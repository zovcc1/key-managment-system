"""Hash-chained audit log tests (FR-8.3, FR-8.4)."""
from __future__ import annotations

from keyring.core import audit as audit_core


def test_fresh_chain_verifies_ok(db_session):
    audit_core.append(db_session, actor="alice", operation="session_open")
    audit_core.append(db_session, actor="alice", operation="encrypt", key_id="k1")
    audit_core.append(db_session, actor="alice", operation="decrypt", key_id="k1")
    db_session.commit()

    assert audit_core.verify_chain(db_session) is None


def test_tamper_detection_reports_the_exact_broken_entry(db_session):
    rows = [audit_core.append(db_session, actor="alice", operation=f"op-{i}") for i in range(6)]
    db_session.commit()

    tampered = rows[3]
    tampered.details = {"tampered": True}
    db_session.commit()

    break_info = audit_core.verify_chain(db_session)
    assert break_info is not None
    assert break_info.entry_id == tampered.id


def test_tamper_detection_flags_first_break_even_with_later_valid_looking_entries(db_session):
    rows = [audit_core.append(db_session, actor="alice", operation=f"op-{i}") for i in range(10)]
    db_session.commit()

    # Corrupt an early entry; every entry after it inherits a broken chain,
    # but verify_chain must report the *first* break, not the last.
    rows[2].details = {"tampered": True}
    db_session.commit()
    audit_core.append(db_session, actor="alice", operation="legitimate-after-tamper")
    db_session.commit()

    break_info = audit_core.verify_chain(db_session)
    assert break_info.entry_id == rows[2].id


def test_digest_chain_links_prev_digest(db_session):
    first = audit_core.append(db_session, actor="alice", operation="a")
    second = audit_core.append(db_session, actor="alice", operation="b")
    db_session.commit()

    assert second.prev_digest == first.digest
    assert first.prev_digest == "0" * 64


def test_erasure_and_destroy_audit_entries_never_contain_key_material(service):
    """Audit `details` blobs are metadata (record counts, table names,
    approval ids) — never raw key bytes, wrapped keys, or hex-encoded
    secrets."""
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    for i in range(3):
        service.encrypt(
            subject_id="subj-audit", table="users", column="email", record_id=f"rec-{i}",
            plaintext=b"secret value", actor="alice",
        )
    service.erase_subject("subj-audit", actor="alice", approval_id="approval-1")
    service.db.commit()

    from keyring.models.audit import AuditLog

    rows = service.db.query(AuditLog).all()
    assert rows, "expected audit rows to have been written"

    forbidden_keys = {"raw_key", "wrapped_key", "dek", "root_secret", "provider_ref", "key_bytes"}
    for row in rows:
        details = row.details or {}
        assert forbidden_keys.isdisjoint(details.keys()), f"row {row.id} details leaked key material key: {details}"
        for value in details.values():
            if isinstance(value, str):
                # A 64-hex-char string is exactly what a 256-bit key would
                # look like hex-encoded; digests live in their own dedicated
                # `digest`/`prev_digest` columns, never inside `details`.
                is_hex64 = len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())
                assert not is_hex64, f"row {row.id} details contains a suspicious 64-hex-char value: {value}"
            assert not isinstance(value, bytes)
