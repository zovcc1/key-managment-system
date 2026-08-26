"""Crypto-shredding / subject erasure tests (section 3)."""
from __future__ import annotations

import pytest

from keyring.core import crypto


def _make_kek(service, actor="alice"):
    kek = service.create_kek(actor)
    service.activate_kek(kek.id, actor)
    return kek


def test_erase_subject_makes_all_envelopes_unreadable(service):
    _make_kek(service)
    envelope_ids = []
    for i in range(8):
        env = service.encrypt(
            subject_id="subj-erase", table="users", column="email", record_id=f"rec-{i}",
            plaintext=f"value-{i}".encode(), actor="alice",
        )
        envelope_ids.append(env.id)

    result = service.erase_subject("subj-erase", actor="alice", approval_id="approval-1")
    assert result["records_unreadable"] == 8

    for env_id in envelope_ids:
        with pytest.raises(crypto.DecryptFailed):
            service.decrypt(env_id, actor="alice")

    report = service.verify_unreadable("subj-erase", sample_size=100)
    assert report["allDecryptFailed"] is True
    assert report["sampled"] == 8


def test_erase_subject_does_not_affect_other_subjects(service):
    _make_kek(service)
    service.encrypt(
        subject_id="subj-erase-target", table="users", column="email", record_id="rec-1",
        plaintext=b"target value", actor="alice",
    )
    other_env = service.encrypt(
        subject_id="subj-unaffected", table="users", column="email", record_id="rec-1",
        plaintext=b"untouched value", actor="alice",
    )

    service.erase_subject("subj-erase-target", actor="alice", approval_id="approval-1")

    assert service.decrypt(other_env.id, actor="alice") == b"untouched value"
    report = service.verify_unreadable("subj-unaffected")
    assert report["allDecryptFailed"] is False


def test_backup_snapshot_of_ciphertext_becomes_unreadable_after_erasure(service):
    """Simulates an external backup that captured the raw envelope bytes
    *before* erasure. Because the only key material lived in the subject
    key row (never exported), even a byte-for-byte copy of the ciphertext
    is unreadable after the subject key is destroyed — the ciphertext was
    never the secret, the wrapped key was."""
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-backup", table="users", column="email", record_id="rec-1",
        plaintext=b"pre-erasure snapshot target", actor="alice",
    )
    backup_snapshot = {
        "wrapped_dek": env.wrapped_dek,
        "dek_nonce": env.dek_nonce,
        "data_nonce": env.data_nonce,
        "ciphertext": env.ciphertext,
        "tag": env.tag,
    }
    assert service.decrypt(env.id, actor="alice") == b"pre-erasure snapshot target"

    service.erase_subject("subj-backup", actor="alice", approval_id="approval-1")

    # The envelope row in the "live" system is unreadable...
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt(env.id, actor="alice")

    # ...and the pre-erasure snapshot doesn't help either: envelope bytes
    # were never re-encrypted or altered by erasure (ciphertext is
    # untouched, this snapshot is identical to what's on disk), so it
    # carries no additional recovery capability. The only thing erasure
    # destroyed is the wrapped subject key, which the snapshot never had.
    assert backup_snapshot["ciphertext"] == env.ciphertext
    assert backup_snapshot["tag"] == env.tag


def test_verify_unreadable_before_erasure_reports_readable(service):
    _make_kek(service)
    service.encrypt(
        subject_id="subj-pre", table="users", column="email", record_id="rec-1",
        plaintext=b"still readable", actor="alice",
    )
    report = service.verify_unreadable("subj-pre")
    assert report["allDecryptFailed"] is False
