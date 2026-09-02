"""KeyringService — the five core operations (FR-10.1) plus everything the
key lifecycle, rewrap, and crypto-shredding requirements need underneath
them. This is the only layer that ever holds raw key material; the API
layer never touches `provider` or a `bytearray` directly.
"""
from __future__ import annotations

import contextlib
import io
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from keyring.core import audit, blobstore, crypto, lifecycle
from keyring.core.errors import (
    ActiveConflictError,
    BlockingDependentsError,
    IllegalTransitionError,
    NoActiveKekError,
    NotFoundError,
    SubjectKeyUnavailableError,
)
from keyring.models.enums import KeyState
from keyring.models.envelope import Envelope
from keyring.models.audit import DecryptFailureLog
from keyring.models.keys import Kek, SubjectKey
from keyring.models.rewrap import RewrapFailure, RewrapJob
from keyring.providers.base import KeyProvider

DEK_WRAP_INFO = b"keyring:v1:dek-wrap"

# FR-2.5: streaming encrypt/decrypt for large payloads — plaintext is never
# fully materialized in memory on the encrypt path (bounded to roughly
# 2x chunk size via one-chunk lookahead); the resulting ciphertext is framed
# as repeated [4-byte length][ciphertext][16-byte tag] records inside the
# existing Envelope.ciphertext column, so no schema change is needed.
STREAM_ALG = "AES-256-GCM-STREAM"
STREAM_CHUNK_SIZE = 1024 * 1024  # 1 MiB
_FRAME_LEN_BYTES = 4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dek_wrap_aad(subject_id: str) -> bytes:
    return DEK_WRAP_INFO + b"|subject:" + subject_id.encode("utf-8")


@contextlib.contextmanager
def _noop_ctx():
    """Stand-in for blobstore.write_stream() when encrypt_stream() is not
    writing to a blob — keeps the `with ... as fh:` shape identical for both
    the inline (fh is None) and blob-backed paths."""
    yield None


class KeyringService:
    def __init__(self, db: DbSession, provider: KeyProvider):
        self.db = db
        self.provider = provider

    # ------------------------------------------------------------------
    # KEK lifecycle (FR-1, FR-4)
    # ------------------------------------------------------------------

    def get_kek(self, kek_id: str) -> Kek:
        kek = self.db.get(Kek, kek_id)
        if kek is None:
            raise NotFoundError(target="kek")
        return kek

    def get_active_kek(self) -> Kek:
        kek = self.db.execute(select(Kek).where(Kek.state == KeyState.ACTIVE.value)).scalar_one_or_none()
        if kek is None:
            raise NoActiveKekError()
        return kek

    def create_kek(self, actor: str) -> Kek:
        ref = str(uuid.uuid4())
        self.provider.create_kek(ref)
        kek = Kek(provider_ref=ref, provider_name=self.provider.name, state=KeyState.PENDING.value)
        self.db.add(kek)
        self.db.flush()
        audit.append(self.db, actor=actor, operation="key_generate", key_id=kek.id, details={"type": "kek"})
        return kek

    def activate_kek(self, kek_id: str, actor: str) -> Kek:
        kek = self.get_kek(kek_id)
        lifecycle.assert_legal(kek.state, KeyState.ACTIVE.value, "kek")
        kek.state = KeyState.ACTIVE.value
        kek.activated_at = _now()
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            raise ActiveConflictError()
        audit.append(self.db, actor=actor, operation="activate_kek", key_id=kek.id)
        return kek

    def rotate_kek(self, kek_id: str, actor: str) -> tuple[Kek, Kek, RewrapJob]:
        """FR-5.1: generate a new KEK and demote the previous one in a
        single atomic transaction. Kicks off a resumable rewrap job for the
        subject keys still wrapped by the demoted KEK (FR-5.3)."""
        current = self.get_kek(kek_id)
        if current.state != KeyState.ACTIVE.value:
            raise IllegalTransitionError(current=current.state, target=KeyState.DEPRECATED.value)

        new_ref = str(uuid.uuid4())
        self.provider.create_kek(new_ref)
        new_kek = Kek(provider_ref=new_ref, provider_name=self.provider.name, state=KeyState.PENDING.value)
        self.db.add(new_kek)
        self.db.flush()

        # Demote the current KEK and flush *before* activating the new one —
        # both updates land in the same transaction, but issuing them as two
        # flushes guarantees the demotion is applied first, so the partial
        # unique index on state='active' never sees two active rows at once
        # regardless of the unit-of-work's internal statement ordering.
        current.state = KeyState.DEPRECATED.value
        current.deprecated_at = _now()
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            raise ActiveConflictError()

        new_kek.state = KeyState.ACTIVE.value
        new_kek.activated_at = _now()
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            raise ActiveConflictError()

        total = self.db.execute(
            select(func.count()).select_from(SubjectKey).where(
                SubjectKey.kek_id == current.id, SubjectKey.state != KeyState.DESTROYED.value
            )
        ).scalar_one()

        job = RewrapJob(from_kek_id=current.id, to_kek_id=new_kek.id, total=total, done=0, state="running")
        self.db.add(job)
        self.db.flush()

        audit.append(
            self.db, actor=actor, operation="rotate_kek", key_id=current.id,
            details={"new_kek_id": new_kek.id, "job_id": job.id, "to_rewrap": total},
        )
        return current, new_kek, job

    def rotate_preview(self, kek_id: str) -> dict:
        kek = self.get_kek(kek_id)
        to_rewrap = self.db.execute(
            select(func.count()).select_from(SubjectKey).where(
                SubjectKey.kek_id == kek.id, SubjectKey.state != KeyState.DESTROYED.value
            )
        ).scalar_one()
        return {"deksToRewrap": to_rewrap, "estimatedSeconds": max(1, round(to_rewrap * 0.004, 2))}

    def revoke_key(self, key_type: str, key_id: str, actor: str):
        row = self._get_key_row(key_type, key_id)
        lifecycle.assert_legal(row.state, KeyState.REVOKED.value, key_type)
        row.state = KeyState.REVOKED.value
        row.revoked_at = _now()
        self.db.flush()
        audit.append(self.db, actor=actor, operation="revoke", key_id=row.id, details={"type": key_type})
        return row

    def emergency_revoke(self, kek_id: str, actor: str) -> Kek:
        """FR-5.6: move the suspect KEK to revoked immediately."""
        return self.revoke_key("kek", kek_id, actor)

    def blocking_dependents(self, key_type: str, key_id: str) -> int:
        if key_type == "kek":
            return self.db.execute(
                select(func.count()).select_from(SubjectKey).where(
                    SubjectKey.kek_id == key_id, SubjectKey.state != KeyState.DESTROYED.value
                )
            ).scalar_one()
        sk = self.db.get(SubjectKey, key_id)
        if sk is None:
            raise NotFoundError(target="subject_key")
        return self.db.execute(
            select(func.count()).select_from(Envelope).where(Envelope.subject_key_id == sk.id)
        ).scalar_one()

    def destroy_key(self, key_type: str, key_id: str, actor: str, approval_id: str):
        row = self._get_key_row(key_type, key_id)
        lifecycle.assert_legal(row.state, KeyState.DESTROYED.value, key_type)
        blocking = self.blocking_dependents(key_type, key_id)
        # FR-4.4's "refuse while dependents exist" applies to KEKs (whose
        # dependents are subject keys that must be rewrapped away first).
        # Subject keys are deliberately exempt: destroying one *while its
        # DEKs are still wrapped* is the crypto-shredding mechanism itself
        # (section 3), not a hazard to guard against.
        if blocking > 0 and key_type == "kek":
            raise BlockingDependentsError(blocking_count=blocking)

        if key_type == "kek":
            self.provider.destroy_kek(row.provider_ref)
            row.state = KeyState.DESTROYED.value
            row.destroyed_at = _now()
        else:
            # Metadata-only tombstone (section 3): the wrapped key row is
            # overwritten; ciphertext elsewhere is deliberately left in
            # place — its unreadability is the proof.
            row.destroyed_record_count = row.record_count
            row.wrapped_key = b"\x00"
            row.state = KeyState.DESTROYED.value
            row.destroyed_at = _now()
            row.destroyed_by = actor
            row.destroyed_approval_id = approval_id

        self.db.flush()
        audit.append(
            self.db, actor=actor, operation="destroy", key_id=row.id,
            details={"type": key_type, "approval_id": approval_id, "blocking_count_at_destroy": blocking},
        )
        return row

    def _get_key_row(self, key_type: str, key_id: str):
        if key_type == "kek":
            return self.get_kek(key_id)
        if key_type == "subject_key":
            sk = self.db.get(SubjectKey, key_id)
            if sk is None:
                raise NotFoundError(target="subject_key")
            return sk
        raise NotFoundError(target=key_type)

    # ------------------------------------------------------------------
    # Rewrap batch job (FR-5.2, FR-5.3, FR-5.4)
    # ------------------------------------------------------------------

    def rewrap_step(self, job_id: str, batch_size: int = 50) -> RewrapJob:
        job = self.db.get(RewrapJob, job_id)
        if job is None:
            raise NotFoundError(target="rewrap_job")
        if job.state != "running":
            return job

        from_kek = self.get_kek(job.from_kek_id)
        to_kek = self.get_kek(job.to_kek_id)

        q = select(SubjectKey).where(SubjectKey.kek_id == from_kek.id)
        if job.cursor:
            q = q.where(SubjectKey.id > job.cursor)
        q = q.order_by(SubjectKey.id.asc()).limit(batch_size)
        batch = self.db.execute(q).scalars().all()

        for sk in batch:
            if sk.state == KeyState.DESTROYED.value:
                job.cursor = sk.id
                job.done += 1
                continue
            try:
                raw = bytearray(self.provider.unwrap(from_kek.provider_ref, sk.wrapped_key))
                try:
                    sk.wrapped_key = self.provider.wrap(to_kek.provider_ref, bytes(raw))
                finally:
                    crypto.zeroize(raw)
                sk.kek_id = to_kek.id
                job.cursor = sk.id
                job.done += 1
            except Exception as exc:  # noqa: BLE001 — batch must not die on one bad item
                self.db.add(
                    RewrapFailure(job_id=job.id, item_id=sk.id, subject_key_id=sk.id, reason=type(exc).__name__)
                )
                job.cursor = sk.id
                job.done += 1
            self.db.flush()

        if not batch or job.done >= job.total:
            job.state = "completed"
        self.db.flush()
        return job

    def rewrap_retry_failure(self, job_id: str, item_id: str) -> RewrapFailure:
        job = self.db.get(RewrapJob, job_id)
        if job is None:
            raise NotFoundError(target="rewrap_job")
        failure = self.db.execute(
            select(RewrapFailure)
            .where(RewrapFailure.job_id == job_id, RewrapFailure.item_id == item_id, RewrapFailure.resolved == False)  # noqa: E712
            .order_by(RewrapFailure.id.desc())
        ).scalars().first()
        if failure is None:
            raise NotFoundError(target="rewrap_failure")

        sk = self.db.get(SubjectKey, item_id)
        from_kek = self.get_kek(job.from_kek_id)
        to_kek = self.get_kek(job.to_kek_id)
        try:
            raw = bytearray(self.provider.unwrap(from_kek.provider_ref if sk.kek_id == from_kek.id else to_kek.provider_ref, sk.wrapped_key))
            try:
                sk.wrapped_key = self.provider.wrap(to_kek.provider_ref, bytes(raw))
            finally:
                crypto.zeroize(raw)
            sk.kek_id = to_kek.id
            failure.resolved = True
            self.db.flush()
        except Exception as exc:  # noqa: BLE001
            failure.attempts += 1
            failure.reason = type(exc).__name__
            self.db.flush()
        return failure

    # ------------------------------------------------------------------
    # Encrypt / Decrypt (FR-2, FR-3, FR-10)
    # ------------------------------------------------------------------

    def _get_or_create_subject_key(self, subject_id: str, actor: str) -> SubjectKey:
        sk = self.db.execute(select(SubjectKey).where(SubjectKey.subject_id == subject_id)).scalar_one_or_none()
        if sk is not None:
            if sk.state in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                raise SubjectKeyUnavailableError(state=sk.state)
            return sk

        active_kek = self.get_active_kek()
        raw = bytearray(crypto.generate_key())
        try:
            wrapped = self.provider.wrap(active_kek.provider_ref, bytes(raw))
        finally:
            crypto.zeroize(raw)

        sk = SubjectKey(
            subject_id=subject_id, kek_id=active_kek.id, wrapped_key=wrapped,
            state=KeyState.ACTIVE.value, activated_at=_now(),
        )
        self.db.add(sk)
        self.db.flush()
        audit.append(self.db, actor=actor, operation="subject_key_create", key_id=sk.id, item_id=subject_id)
        return sk

    def encrypt(self, *, subject_id: str, table: str, column: str, record_id: str, plaintext: bytes, actor: str) -> Envelope:
        sk = self._get_or_create_subject_key(subject_id, actor)
        kek = self.get_kek(sk.kek_id)

        subject_raw = bytearray(self.provider.unwrap(kek.provider_ref, sk.wrapped_key))
        dek = bytearray(crypto.generate_key())
        try:
            dek_wrap = crypto.aead_encrypt(bytes(subject_raw), bytes(dek), _dek_wrap_aad(subject_id))
            aad = crypto.build_aad(table, column, record_id, subject_id)
            data_result = crypto.aead_encrypt(bytes(dek), plaintext, aad)
        finally:
            crypto.zeroize(subject_raw)
            crypto.zeroize(dek)

        env = Envelope(
            v=crypto.ENVELOPE_VERSION, alg="AES-256-GCM", kek_id=kek.id, subject_key_id=sk.id,
            wrapped_dek=dek_wrap.ciphertext + dek_wrap.tag, dek_nonce=dek_wrap.nonce,
            data_nonce=data_result.nonce, ciphertext=data_result.ciphertext, tag=data_result.tag,
            table_name=table, column_name=column, record_id=record_id, subject_id=subject_id,
        )
        self.db.add(env)
        sk.record_count += 1
        self.db.flush()
        audit.append(
            self.db, actor=actor, operation="encrypt", key_id=sk.id, item_id=env.id,
            details={"table": table, "column": column, "subject_id": subject_id},
        )
        return env

    def decrypt(self, envelope_id: str, actor: str) -> bytes:
        env = self.db.get(Envelope, envelope_id)
        try:
            if env is None:
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            sk = self.db.get(SubjectKey, env.subject_key_id)
            if sk is None or sk.state in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            kek = self.db.get(Kek, env.kek_id)
            if kek is None or kek.state in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            subject_raw = bytearray(self.provider.unwrap(kek.provider_ref, sk.wrapped_key))
            try:
                dek_ct, dek_tag = env.wrapped_dek[:-crypto.TAG_LEN], env.wrapped_dek[-crypto.TAG_LEN:]
                dek = bytearray(
                    crypto.aead_decrypt(bytes(subject_raw), env.dek_nonce, dek_ct, dek_tag, _dek_wrap_aad(env.subject_id))
                )
                try:
                    plaintext = crypto.aead_decrypt(bytes(dek), env.data_nonce, env.ciphertext, env.tag, env.aad())
                finally:
                    crypto.zeroize(dek)
            finally:
                crypto.zeroize(subject_raw)
        except Exception:
            # Uniform failure: identical exception, identical audit shape,
            # regardless of *why* decryption failed (FR-3.4).
            self.db.add(DecryptFailureLog(actor=actor, envelope_id=envelope_id, reason_code="attempt_failed"))
            audit.append(self.db, actor=actor, operation="decrypt_failed", item_id=envelope_id, result="failure")
            self.db.flush()
            raise crypto.DecryptFailed()

        sk.last_access_at = _now()
        audit.append(self.db, actor=actor, operation="decrypt", key_id=sk.id, item_id=env.id, result="success")
        self.db.flush()
        return plaintext

    def _decoy_aead_attempt(self) -> None:
        """Perform a throwaway AEAD verification so early-exit branches
        (missing envelope, revoked key) still do comparable cryptographic
        work to the full unwrap+decrypt path. Reduces — does not claim to
        eliminate — timing variance between failure modes."""
        try:
            crypto.aead_decrypt(crypto.generate_key(), crypto.generate_nonce(), b"decoy", crypto.random_bytes(16), b"decoy")
        except crypto.DecryptFailed:
            pass

    # ------------------------------------------------------------------
    # Streaming encrypt / decrypt (FR-2.5)
    # ------------------------------------------------------------------

    def encrypt_stream(
        self, *, subject_id: str, table: str, column: str, record_id: str, plaintext_chunks, actor: str,
        blob_ref: str | None = None,
    ) -> Envelope:
        """Same envelope shape and guarantees as encrypt(), but consumes an
        iterable of plaintext chunks (e.g. a generator reading a file in
        STREAM_CHUNK_SIZE pieces) instead of one in-memory bytes object.
        Uses a one-chunk lookahead so the final chunk's AAD can be bound to
        `final:1` without ever holding the whole plaintext at once.

        When `blob_ref` is given, each frame is written straight to the blob
        store (keyring/core/blobstore.py) as it is produced instead of being
        accumulated in memory, and the envelope's `ciphertext` column is left
        empty (`blob_ref` records where the framed ciphertext actually
        lives). A write failure partway through leaves no blob at `blob_ref`
        (see blobstore.write_stream) and this method raises before adding
        any Envelope row — same all-or-nothing shape as the inline path."""
        sk = self._get_or_create_subject_key(subject_id, actor)
        kek = self.get_kek(sk.kek_id)

        subject_raw = bytearray(self.provider.unwrap(kek.provider_ref, sk.wrapped_key))
        dek = bytearray(crypto.generate_key())
        framed = bytearray() if blob_ref is None else None
        chunk_count = 0
        total_bytes = 0
        try:
            dek_wrap = crypto.aead_encrypt(bytes(subject_raw), bytes(dek), _dek_wrap_aad(subject_id))
            base_aad = crypto.build_aad(table, column, record_id, subject_id)
            nonce_prefix = crypto.stream_nonce_prefix()

            iterator = iter(plaintext_chunks)
            sentinel = object()
            pending = next(iterator, sentinel)
            if pending is sentinel:
                pending = b""  # empty stream still yields exactly one (empty, final) chunk
            index = 0
            blob_handle = blobstore.write_stream(blob_ref) if blob_ref is not None else None
            with blob_handle if blob_handle is not None else _noop_ctx() as fh:
                while True:
                    current = pending
                    pending = next(iterator, sentinel)
                    is_final = pending is sentinel
                    nonce = crypto.chunk_nonce(nonce_prefix, index)
                    aad = crypto.stream_chunk_aad(base_aad, index, is_final)
                    result = crypto.aead_encrypt_with_nonce(bytes(dek), nonce, current, aad)
                    frame = len(result.ciphertext).to_bytes(_FRAME_LEN_BYTES, "big") + result.ciphertext + result.tag
                    if fh is not None:
                        fh.write(frame)
                    else:
                        framed += frame
                    total_bytes += len(current)
                    chunk_count += 1
                    index += 1
                    if is_final:
                        break
        finally:
            crypto.zeroize(subject_raw)
            crypto.zeroize(dek)

        env = Envelope(
            v=crypto.ENVELOPE_VERSION, alg=STREAM_ALG, kek_id=kek.id, subject_key_id=sk.id,
            wrapped_dek=dek_wrap.ciphertext + dek_wrap.tag, dek_nonce=dek_wrap.nonce,
            data_nonce=nonce_prefix, ciphertext=(bytes(framed) if framed is not None else b""), tag=b"",
            blob_ref=blob_ref,
            table_name=table, column_name=column, record_id=record_id, subject_id=subject_id,
        )
        self.db.add(env)
        sk.record_count += 1
        self.db.flush()
        audit.append(
            self.db, actor=actor, operation="encrypt_stream", key_id=sk.id, item_id=env.id,
            details={"table": table, "column": column, "subject_id": subject_id, "chunks": chunk_count, "bytes": total_bytes},
        )
        return env

    def decrypt_stream(self, envelope_id: str, actor: str):
        """Validates the envelope and unwraps its DEK eagerly (so a bad
        envelope_id fails immediately, like decrypt()), then returns a
        generator yielding plaintext chunks one at a time.

        For inline envelopes the whole ciphertext blob is loaded once from
        the DB row; for blob-backed envelopes (`env.blob_ref` set) frames are
        read incrementally from the blob store instead, so plaintext memory
        stays bounded to one chunk at a time either way (see STREAM_ALG
        comment above). A missing blob is checked eagerly, alongside the
        other envelope/key validity checks, and fails exactly like every
        other decrypt failure (FR-3.4) — never a distinguishable error."""
        env = self.db.get(Envelope, envelope_id)
        try:
            if env is None or env.alg != STREAM_ALG:
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            sk = self.db.get(SubjectKey, env.subject_key_id)
            if sk is None or sk.state in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            kek = self.db.get(Kek, env.kek_id)
            if kek is None or kek.state in (KeyState.REVOKED.value, KeyState.DESTROYED.value):
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            if env.blob_ref is not None and not blobstore.exists(env.blob_ref):
                self._decoy_aead_attempt()
                raise crypto.DecryptFailed()

            subject_raw = bytearray(self.provider.unwrap(kek.provider_ref, sk.wrapped_key))
            try:
                dek_ct, dek_tag = env.wrapped_dek[:-crypto.TAG_LEN], env.wrapped_dek[-crypto.TAG_LEN:]
                dek = bytearray(
                    crypto.aead_decrypt(bytes(subject_raw), env.dek_nonce, dek_ct, dek_tag, _dek_wrap_aad(env.subject_id))
                )
            finally:
                crypto.zeroize(subject_raw)
        except Exception:
            self.db.add(DecryptFailureLog(actor=actor, envelope_id=envelope_id, reason_code="attempt_failed"))
            audit.append(self.db, actor=actor, operation="decrypt_failed", item_id=envelope_id, result="failure")
            self.db.flush()
            raise crypto.DecryptFailed()

        sk.last_access_at = _now()
        audit.append(self.db, actor=actor, operation="decrypt_stream", key_id=sk.id, item_id=env.id, result="success")
        self.db.flush()

        base_aad = env.aad()
        nonce_prefix = env.data_nonce
        blob_ref = env.blob_ref
        inline_ciphertext = env.ciphertext
        db = self.db

        def _chunks():
            try:
                if blob_ref is not None:
                    source: io.IOBase = blobstore.open_read(blob_ref)
                    total = blobstore.size(blob_ref)
                else:
                    source = io.BytesIO(inline_ciphertext)
                    total = len(inline_ciphertext)
                try:
                    offset = 0
                    index = 0
                    while offset < total:
                        length = int.from_bytes(source.read(_FRAME_LEN_BYTES), "big")
                        offset += _FRAME_LEN_BYTES
                        ct = source.read(length)
                        offset += length
                        frame_tag = source.read(crypto.TAG_LEN)
                        offset += crypto.TAG_LEN
                        is_final = offset >= total
                        nonce = crypto.chunk_nonce(nonce_prefix, index)
                        aad = crypto.stream_chunk_aad(base_aad, index, is_final)
                        try:
                            yield crypto.aead_decrypt(bytes(dek), nonce, ct, frame_tag, aad)
                        except crypto.DecryptFailed:
                            db.add(DecryptFailureLog(actor=actor, envelope_id=envelope_id, reason_code="attempt_failed"))
                            audit.append(db, actor=actor, operation="decrypt_failed", item_id=envelope_id, result="failure")
                            db.flush()
                            raise
                        index += 1
                finally:
                    if blob_ref is not None:
                        source.close()
            finally:
                crypto.zeroize(dek)

        return _chunks()

    # ------------------------------------------------------------------
    # Crypto-shredding / erasure (section 3)
    # ------------------------------------------------------------------

    def get_subject_key_by_subject(self, subject_id: str) -> SubjectKey:
        sk = self.db.execute(select(SubjectKey).where(SubjectKey.subject_id == subject_id)).scalar_one_or_none()
        if sk is None:
            raise NotFoundError(target="subject")
        return sk

    def subject_tables(self, subject_key_id: str) -> list[str]:
        rows = self.db.execute(
            select(Envelope.table_name).where(Envelope.subject_key_id == subject_key_id).distinct()
        ).scalars().all()
        return sorted(rows)

    def erase_subject(self, subject_id: str, actor: str, approval_id: str) -> dict:
        sk = self.get_subject_key_by_subject(subject_id)
        tables = self.subject_tables(sk.id)
        records = sk.record_count

        self.destroy_key("subject_key", sk.id, actor, approval_id)

        audit.append(
            self.db, actor=actor, operation="erasure", key_id=sk.id, item_id=subject_id,
            details={"records_unreadable": records, "tables": tables, "approval_id": approval_id},
        )
        return {"subject_key_id": sk.id, "records_unreadable": records, "tables_affected": tables}

    def verify_unreadable(self, subject_id: str, sample_size: int = 10) -> dict:
        sk = self.get_subject_key_by_subject(subject_id)
        envs = self.db.execute(
            select(Envelope).where(Envelope.subject_key_id == sk.id).limit(sample_size)
        ).scalars().all()

        results = []
        all_failed = True
        for env in envs:
            try:
                self.decrypt(env.id, actor="system:verify-unreadable")
                all_failed = False
                results.append({"envelopeId": env.id, "decryptFailed": False})
            except crypto.DecryptFailed:
                results.append({"envelopeId": env.id, "decryptFailed": True})

        return {"subjectId": subject_id, "sampled": len(envs), "allDecryptFailed": all_failed, "results": results}

    # ------------------------------------------------------------------
    # Blast radius (key map)
    # ------------------------------------------------------------------

    def blast_radius(self, key_id: str) -> dict:
        kek = self.db.get(Kek, key_id)
        if kek is not None:
            sk_ids = self.db.execute(select(SubjectKey.id).where(SubjectKey.kek_id == kek.id)).scalars().all()
            record_count = self.db.execute(
                select(func.count()).select_from(Envelope).where(Envelope.subject_key_id.in_(sk_ids))
            ).scalar_one() if sk_ids else 0
            tables = self.db.execute(
                select(Envelope.table_name).where(Envelope.subject_key_id.in_(sk_ids)).distinct()
            ).scalars().all() if sk_ids else []
            return {"recordCount": record_count, "tables": sorted(tables), "downstreamKeyCount": len(sk_ids)}

        sk = self.db.get(SubjectKey, key_id)
        if sk is None:
            raise NotFoundError(target="key")
        record_count = self.db.execute(
            select(func.count()).select_from(Envelope).where(Envelope.subject_key_id == sk.id)
        ).scalar_one()
        tables = self.db.execute(
            select(Envelope.table_name).where(Envelope.subject_key_id == sk.id).distinct()
        ).scalars().all()
        return {"recordCount": record_count, "tables": sorted(tables), "downstreamKeyCount": 0}

    # ------------------------------------------------------------------
    # File key tree (Files section)
    # ------------------------------------------------------------------

    def file_key_tree(self, file_object) -> dict:
        """Full ancestry for one uploaded file: provider (root secret,
        never displayed) -> KEK -> subject key -> this file's single-use DEK
        -> envelope, each annotated with its live state. Mirrors the same
        legality checks decrypt_stream() enforces, without ever attempting a
        decrypt, so it is safe for `file_read`-scoped callers (e.g. an
        auditor) who must never see plaintext."""
        env = self.db.get(Envelope, file_object.envelope_id)
        if env is None:
            raise NotFoundError(target="envelope")
        sk = self.db.get(SubjectKey, env.subject_key_id)
        kek = self.db.get(Kek, env.kek_id)

        nodes: list[dict] = [
            {"level": 0, "kind": "root_secret", "id": None, "state": "active", "algorithm": self.provider.name, "usable": True},
        ]
        broken_at: int | None = None

        kek_usable = kek is not None and kek.state not in (KeyState.REVOKED.value, KeyState.DESTROYED.value)
        nodes.append({
            "level": 1, "kind": "kek", "id": kek.id if kek else None,
            "state": kek.state if kek else "missing", "algorithm": kek.algorithm if kek else None,
            "usable": kek_usable,
        })
        if not kek_usable and broken_at is None:
            broken_at = 1

        sk_usable = kek_usable and sk is not None and sk.state not in (KeyState.REVOKED.value, KeyState.DESTROYED.value)
        nodes.append({
            "level": 2, "kind": "subject_key", "id": sk.id if sk else None,
            "state": sk.state if sk else "missing", "algorithm": sk.algorithm if sk else None,
            "usable": sk_usable,
        })
        if not sk_usable and broken_at is None:
            broken_at = 2

        nodes.append({"level": 3, "kind": "dek", "id": None, "state": "single-use", "algorithm": "AES-256-GCM", "usable": sk_usable})
        if not sk_usable and broken_at is None:
            broken_at = 3

        blob_present = env.blob_ref is None or blobstore.exists(env.blob_ref)
        env_usable = sk_usable and blob_present
        nodes.append({"level": 4, "kind": "envelope", "id": env.id, "state": env.alg, "algorithm": env.alg, "usable": env_usable})
        if not env_usable and broken_at is None:
            broken_at = 4

        return {
            "fileId": file_object.id,
            "nodes": nodes,
            "readable": broken_at is None,
            "brokenAtLevel": broken_at,
            "blobPresent": blob_present,
        }
