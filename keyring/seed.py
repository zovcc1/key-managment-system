"""Seed command (Deliverable, section 8).

Populates a fresh database with:
  - 3 KEKs across states: one active, one deprecated mid-rewrap (a real,
    partially-advanced RewrapJob), one destroyed.
  - ~40 subject keys spanning all 5 lifecycle states.
  - ~15,000 encrypted items.
  - A hash-chained audit log containing one deliberately corrupted entry,
    so `POST /api/audit/verify` has something real to catch.
  - A demo subject with records across 5 tables, left active/untouched, for
    an end-to-end erasure walkthrough performed live against the API.

Run with: ./.venv/bin/python3 -m keyring.seed
(after `alembic upgrade head` against a clean database).
"""
from __future__ import annotations

import hashlib
import os
import random
import uuid
from pathlib import Path

from keyring.config import settings
from keyring.core import blobstore, crypto, runtime
from keyring.core.audit import append as audit_append
from keyring.core.service import DEK_WRAP_INFO, KeyringService
from keyring.db import SessionLocal
from keyring.models.audit import AuditLog
from keyring.models.enums import KeyState
from keyring.models.envelope import Envelope
from keyring.models.file_object import FileObject
from keyring.models.keys import SubjectKey
from keyring.models.session import Operator
from keyring.models.settings_model import SystemSettings

random.seed(1337)

DEMO_SUBJECT_ID = "demo-subject-0001"
DEMO_TABLES = ["users", "addresses", "payment_methods", "support_tickets", "marketing_profiles"]
FILLER_TABLES = ["orders", "invoices", "notes", "documents", "audit_notes"]

OPERATOR_SEEDS = [
    ("Alice", "key-admin", "demo-key-admin-alice-9f2a"),
    ("Bob", "key-admin", "demo-key-admin-bob-7c31"),
    ("Carol", "auditor", "demo-auditor-carol-1e88"),
    ("Dan", "operator", "demo-operator-dan-4b60"),
]


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ensure_provider_files() -> None:
    passphrase_path = Path(settings.root_passphrase_file)
    passphrase_path.parent.mkdir(parents=True, exist_ok=True)
    if not passphrase_path.exists():
        passphrase_path.write_text("correct horse battery staple pass 2026")
    os.chmod(passphrase_path, 0o400)


def _dek_wrap_aad(subject_id: str) -> bytes:
    return DEK_WRAP_INFO + b"|subject:" + subject_id.encode("utf-8")


def seed_operators(db) -> dict[str, Operator]:
    ops: dict[str, Operator] = {}
    for name, role, raw_key in OPERATOR_SEEDS:
        op = Operator(name=name, role=role, api_key_hash=_hash_key(raw_key))
        db.add(op)
        ops[name] = op
    db.flush()
    return ops


def seed_settings(db) -> None:
    db.add(SystemSettings(id=1, rotation_interval_days=90, alert_threshold_days=100, active_provider="file"))


def bulk_encrypt(
    db, provider, sk: SubjectKey, kek_provider_ref: str, table_pool: list[str], count: int, subject_id: str,
) -> int:
    """Populate `count` real, independently-encrypted items for one subject
    key in a single batch: one subject-key unwrap, `count` fresh single-use
    DEKs and AEAD encryptions, one bulk insert. Used for the bulk portion of
    the ~15k seed dataset — the request-path `service.encrypt()` (exercised
    directly for the demo subject and a handful of items per pool) does the
    identical per-item work plus a per-item audit row, which is what real
    traffic produces."""
    subject_raw = bytearray(provider.unwrap(kek_provider_ref, sk.wrapped_key))
    envelopes: list[Envelope] = []
    try:
        for i in range(count):
            table = table_pool[i % len(table_pool)]
            record_id = f"rec-{sk.id[:8]}-{i:05d}"
            plaintext = f"plaintext value {i} for {subject_id}/{table}".encode("utf-8")

            dek = bytearray(crypto.generate_key())
            try:
                dek_wrap = crypto.aead_encrypt(bytes(subject_raw), bytes(dek), _dek_wrap_aad(subject_id))
                aad = crypto.build_aad(table, "value", record_id, subject_id)
                data_result = crypto.aead_encrypt(bytes(dek), plaintext, aad)
            finally:
                crypto.zeroize(dek)

            envelopes.append(
                Envelope(
                    v=crypto.ENVELOPE_VERSION, alg="AES-256-GCM", kek_id=sk.kek_id, subject_key_id=sk.id,
                    wrapped_dek=dek_wrap.ciphertext + dek_wrap.tag, dek_nonce=dek_wrap.nonce,
                    data_nonce=data_result.nonce, ciphertext=data_result.ciphertext, tag=data_result.tag,
                    table_name=table, column_name="value", record_id=record_id, subject_id=subject_id,
                )
            )
    finally:
        crypto.zeroize(subject_raw)

    db.add_all(envelopes)
    sk.record_count += count
    return count


def main() -> None:
    _ensure_provider_files()
    runtime.connect("file")
    provider = runtime.get_connected_provider()

    db = SessionLocal()
    service = KeyringService(db, provider)
    try:
        ops = seed_operators(db)
        seed_settings(db)
        admin_a, admin_b = ops["Alice"].name, ops["Bob"].name

        # --- KEK 1: created, activated, used as the working KEK ------------
        kek1 = service.create_kek(admin_a)
        service.activate_kek(kek1.id, admin_a)
        db.commit()
        print(f"KEK1 (active): {kek1.id}")

        # --- Subject keys + envelopes under KEK1 ---------------------------
        active_kek1_subjects: list[SubjectKey] = []
        for n in range(14):
            subject_id = f"subject-active-a-{n:03d}"
            env = service.encrypt(
                subject_id=subject_id, table=FILLER_TABLES[n % len(FILLER_TABLES)], column="value",
                record_id="rec-0", plaintext=b"seed bootstrap record", actor=admin_a,
            )
            sk = db.get(SubjectKey, env.subject_key_id)
            active_kek1_subjects.append(sk)
        db.commit()

        for sk in active_kek1_subjects:
            n = bulk_encrypt(
                db, provider, sk, kek1.provider_ref, FILLER_TABLES, random.randint(600, 900), sk.subject_id,
            )
            db.commit()
        print(f"Seeded {len(active_kek1_subjects)} active subject keys under KEK1 with bulk envelopes")

        # --- Deprecated (5), revoked (5), destroyed (5) subject keys, ------
        # all wrapped under KEK1 so they become part of KEK1's rewrap
        # workload once KEK1 is rotated below.
        deprecated_subjects: list[SubjectKey] = []
        for n in range(5):
            subject_id = f"subject-deprecated-{n:03d}"
            env = service.encrypt(
                subject_id=subject_id, table=FILLER_TABLES[n % len(FILLER_TABLES)], column="value",
                record_id="rec-0", plaintext=b"seed bootstrap record", actor=admin_a,
            )
            sk = db.get(SubjectKey, env.subject_key_id)
            bulk_encrypt(db, provider, sk, kek1.provider_ref, FILLER_TABLES, random.randint(60, 140), subject_id)
            sk.state = KeyState.DEPRECATED.value  # direct seed data, not a real API transition
            deprecated_subjects.append(sk)
        db.commit()

        revoked_subjects: list[SubjectKey] = []
        for n in range(5):
            subject_id = f"subject-revoked-{n:03d}"
            env = service.encrypt(
                subject_id=subject_id, table=FILLER_TABLES[n % len(FILLER_TABLES)], column="value",
                record_id="rec-0", plaintext=b"seed bootstrap record", actor=admin_a,
            )
            sk = db.get(SubjectKey, env.subject_key_id)
            bulk_encrypt(db, provider, sk, kek1.provider_ref, FILLER_TABLES, random.randint(60, 140), subject_id)
            db.commit()
            service.revoke_key("subject_key", sk.id, admin_a)
            revoked_subjects.append(sk)
        db.commit()

        destroyed_subjects: list[SubjectKey] = []
        for n in range(5):
            subject_id = f"subject-destroyed-{n:03d}"
            env = service.encrypt(
                subject_id=subject_id, table=FILLER_TABLES[n % len(FILLER_TABLES)], column="value",
                record_id="rec-0", plaintext=b"seed bootstrap record", actor=admin_a,
            )
            sk = db.get(SubjectKey, env.subject_key_id)
            bulk_encrypt(db, provider, sk, kek1.provider_ref, FILLER_TABLES, random.randint(60, 140), subject_id)
            db.commit()
            # Forward-only lifecycle: active must pass through revoked
            # before destroyed (FR-4.3).
            service.revoke_key("subject_key", sk.id, admin_a)
            db.commit()
            # Metadata-only tombstone: ciphertext for these subjects stays in
            # place on purpose — that unreadability is the crypto-shredding
            # proof `POST /api/subjects/{id}/verify-unreadable` demonstrates.
            service.destroy_key("subject_key", sk.id, admin_a, approval_id="seed-bootstrap")
            destroyed_subjects.append(sk)
        db.commit()
        print("Seeded 5 deprecated, 5 revoked, 5 destroyed subject keys")

        # --- Pending subject keys (never activated, no envelopes) ----------
        for n in range(5):
            raw = bytearray(crypto.generate_key())
            try:
                wrapped = provider.wrap(kek1.provider_ref, bytes(raw))
            finally:
                crypto.zeroize(raw)
            db.add(
                SubjectKey(
                    subject_id=f"subject-pending-{n:03d}", kek_id=kek1.id, wrapped_key=wrapped,
                    state=KeyState.PENDING.value,
                )
            )
        db.commit()
        print("Seeded 5 pending subject keys")

        # --- Rotate KEK1 -> KEK2, leave the rewrap job partially advanced --
        old_kek, kek2, job = service.rotate_kek(kek1.id, admin_a)
        db.commit()
        print(f"KEK2 (active): {kek2.id}; KEK1 now deprecated with rewrap job {job.id} (total={job.total})")

        # Advance the job partway on purpose — this is the "deprecated KEK
        # mid-rewrap" state the deliverable asks for. The background worker
        # in keyring.main would otherwise run this to completion; we stop
        # early here and leave it "running".
        target_done = max(1, job.total // 3)
        while job.done < target_done:
            job = service.rewrap_step(job.id, batch_size=25)
            db.commit()
        print(f"Rewrap job {job.id} left at {job.done}/{job.total}, state={job.state}")

        # --- Subject keys + envelopes created after rotation (under KEK2) --
        active_kek2_subjects: list[SubjectKey] = []
        for n in range(5):
            subject_id = f"subject-active-b-{n:03d}"
            env = service.encrypt(
                subject_id=subject_id, table=FILLER_TABLES[n % len(FILLER_TABLES)], column="value",
                record_id="rec-0", plaintext=b"seed bootstrap record", actor=admin_a,
            )
            sk = db.get(SubjectKey, env.subject_key_id)
            active_kek2_subjects.append(sk)
        db.commit()

        for sk in active_kek2_subjects:
            bulk_encrypt(db, provider, sk, kek2.provider_ref, FILLER_TABLES, random.randint(400, 600), sk.subject_id)
            db.commit()
        print(f"Seeded {len(active_kek2_subjects)} active subject keys under KEK2 with bulk envelopes")

        # --- KEK 3: created, revoked, destroyed — never activated, so it --
        # has zero dependents and destruction needs no rewrap.
        kek3 = service.create_kek(admin_a)
        db.commit()
        service.revoke_key("kek", kek3.id, admin_a)
        db.commit()
        service.destroy_key("kek", kek3.id, admin_a, approval_id="seed-bootstrap")
        db.commit()
        print(f"KEK3 (destroyed): {kek3.id}")

        # --- Demo subject: active, untouched, spread across 5 tables, for --
        # a live erasure walkthrough performed against the running API.
        for i, table in enumerate(DEMO_TABLES):
            for j in range(20):
                service.encrypt(
                    subject_id=DEMO_SUBJECT_ID, table=table, column="value", record_id=f"rec-{i}-{j:03d}",
                    plaintext=f"demo plaintext {table}/{j}".encode("utf-8"), actor=admin_a,
                )
        db.commit()
        demo_sk = service.get_subject_key_by_subject(DEMO_SUBJECT_ID)
        print(f"Demo subject {DEMO_SUBJECT_ID}: subject key {demo_sk.id}, {demo_sk.record_count} records across {len(DEMO_TABLES)} tables")

        # --- Demo files: two small encrypted files under the demo subject, --
        # so a fresh database shows the Files section already populated for
        # the erasure walkthrough. Skipped if already seeded (idempotent).
        if db.query(FileObject).filter(FileObject.subject_id == DEMO_SUBJECT_ID).count() == 0:
            demo_files = [
                ("welcome.txt", "text/plain", b"Welcome to the Keyring demo subject.\nThis file is encrypted at rest and crypto-shreddable.\n"),
                ("profile.bin", "application/octet-stream", os.urandom(4096)),
            ]
            for filename, content_type, payload in demo_files:
                file_id = str(uuid.uuid4())
                env = service.encrypt_stream(
                    subject_id=DEMO_SUBJECT_ID, table="files", column="content", record_id=file_id,
                    plaintext_chunks=[payload], actor=admin_a, blob_ref=file_id,
                )
                digest = hashlib.sha256()
                with blobstore.open_read(file_id) as fh:
                    digest.update(fh.read())
                db.add(FileObject(
                    id=file_id, filename=filename, content_type=content_type, size_bytes=len(payload),
                    ciphertext_sha256=digest.hexdigest(), envelope_id=env.id, subject_id=DEMO_SUBJECT_ID,
                    uploaded_by=admin_a,
                ))
            db.commit()
            print(f"Seeded {len(demo_files)} demo files under {DEMO_SUBJECT_ID}")

        total_envelopes = db.query(Envelope).count()
        total_subject_keys = db.query(SubjectKey).count()
        print(f"Total envelopes: {total_envelopes}; total subject keys: {total_subject_keys}")

        # --- Corrupt one audit entry on purpose, so POST /api/audit/verify -
        # has a real, findable break instead of always reporting success.
        rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        mid = rows[len(rows) // 2]
        mid.details = dict(mid.details or {})
        mid.details["_seed_tamper"] = "this entry was altered after the fact to demonstrate chain verification"
        db.commit()
        print(f"Deliberately corrupted audit entry id={mid.id} to exercise /api/audit/verify")

        print("\nOperator API keys (for POST /api/session, header X-Api-Key):")
        for name, role, raw_key in OPERATOR_SEEDS:
            print(f"  {name} ({role}): {raw_key}")

    finally:
        db.close()
        runtime.disconnect()


if __name__ == "__main__":
    main()
