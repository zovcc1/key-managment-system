"""Service-level encrypt/decrypt correctness and negative tests (FR-2, FR-3).

Every test in this file runs once per KeyProvider implementation via the
`service` fixture (parametrized in conftest.py).
"""
from __future__ import annotations

import pytest

from keyring.core import crypto
from keyring.core.errors import SubjectKeyUnavailableError
from keyring.models.audit import DecryptFailureLog
from keyring.models.keys import SubjectKey


def _make_kek(service, actor="alice"):
    kek = service.create_kek(actor)
    service.activate_kek(kek.id, actor)
    return kek


def test_encrypt_decrypt_round_trip(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-1", table="users", column="email", record_id="rec-1",
        plaintext=b"alice@example.com", actor="alice",
    )
    plaintext = service.decrypt(env.id, actor="alice")
    assert plaintext == b"alice@example.com"


def test_encrypt_decrypt_many_records_same_subject(service):
    _make_kek(service)
    for i in range(25):
        env = service.encrypt(
            subject_id="subj-multi", table="notes", column="body", record_id=f"rec-{i}",
            plaintext=f"note {i}".encode(), actor="alice",
        )
        assert service.decrypt(env.id, actor="alice") == f"note {i}".encode()


def test_envelope_version_field_does_not_gate_decrypt(service):
    """The `v` field is informational; decrypt must not depend on its
    value, so envelopes minted under an older schema version stay
    decryptable forever (FR-2 forward-compat)."""
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-legacy", table="users", column="email", record_id="rec-1",
        plaintext=b"legacy value", actor="alice",
    )
    env.v = 0  # simulate an envelope minted under an earlier envelope version
    service.db.flush()
    assert service.decrypt(env.id, actor="alice") == b"legacy value"


def test_decrypt_missing_envelope_fails_uniformly(service):
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt("does-not-exist", actor="alice")
    row = service.db.query(DecryptFailureLog).filter_by(envelope_id="does-not-exist").one()
    assert row.reason_code == "attempt_failed"


def test_decrypt_tampered_ciphertext_fails_uniformly(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-2", table="users", column="email", record_id="rec-1",
        plaintext=b"secret", actor="alice",
    )
    env.ciphertext = bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:]
    service.db.flush()
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")


def test_decrypt_tampered_tag_fails_uniformly(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-3", table="users", column="email", record_id="rec-1",
        plaintext=b"secret", actor="alice",
    )
    env.tag = bytes([env.tag[0] ^ 1]) + env.tag[1:]
    service.db.flush()
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")


def test_decrypt_mismatched_aad_fails_uniformly(service):
    """Relocating a ciphertext to a different logical location (table/
    record/subject) must break decryption even though the raw ciphertext
    bytes are untouched (FR-3.2)."""
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-4", table="users", column="email", record_id="rec-1",
        plaintext=b"secret", actor="alice",
    )
    env.record_id = "rec-2"  # AAD is derived from table/column/record/subject
    service.db.flush()
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")


def test_decrypt_revoked_subject_key_fails_uniformly(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-5", table="users", column="email", record_id="rec-1",
        plaintext=b"secret", actor="alice",
    )
    sk = service.db.get(SubjectKey, env.subject_key_id)
    service.revoke_key("subject_key", sk.id, "alice")
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")


def test_decrypt_destroyed_subject_key_fails_uniformly(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-6", table="users", column="email", record_id="rec-1",
        plaintext=b"secret", actor="alice",
    )
    sk = service.db.get(SubjectKey, env.subject_key_id)
    service.destroy_key("subject_key", sk.id, "alice", approval_id="approval-1")
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")


def test_encrypt_without_active_kek_raises_no_active_kek(service):
    from keyring.core.errors import NoActiveKekError

    with pytest.raises(NoActiveKekError):
        service.encrypt(
            subject_id="subj-7", table="users", column="email", record_id="rec-1",
            plaintext=b"secret", actor="alice",
        )


def test_encrypt_reuses_existing_subject_key(service):
    _make_kek(service)
    env1 = service.encrypt(
        subject_id="subj-reuse", table="users", column="email", record_id="rec-1",
        plaintext=b"a", actor="alice",
    )
    env2 = service.encrypt(
        subject_id="subj-reuse", table="users", column="phone", record_id="rec-2",
        plaintext=b"b", actor="alice",
    )
    assert env1.subject_key_id == env2.subject_key_id


def test_encrypt_refuses_new_records_for_revoked_subject(service):
    _make_kek(service)
    service.encrypt(
        subject_id="subj-8", table="users", column="email", record_id="rec-1",
        plaintext=b"a", actor="alice",
    )
    sk = service.get_subject_key_by_subject("subj-8")
    service.revoke_key("subject_key", sk.id, "alice")
    with pytest.raises(SubjectKeyUnavailableError):
        service.encrypt(
            subject_id="subj-8", table="users", column="email", record_id="rec-2",
            plaintext=b"b", actor="alice",
        )
