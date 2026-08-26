"""Destroy-blocked-by-dependents tests (FR-4.4) and its deliberate subject-
key exemption (section 3)."""
from __future__ import annotations

import pytest

from keyring.core.errors import BlockingDependentsError


def test_kek_destroy_blocked_by_live_subject_keys(service):
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    service.encrypt(
        subject_id="subj-blocking", table="users", column="email", record_id="rec-1",
        plaintext=b"x", actor="alice",
    )
    service.revoke_key("kek", kek.id, "alice")
    with pytest.raises(BlockingDependentsError):
        service.destroy_key("kek", kek.id, "alice", approval_id="approval-1")


def test_kek_destroy_succeeds_once_dependents_destroyed(service):
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    service.encrypt(
        subject_id="subj-clearing", table="users", column="email", record_id="rec-1",
        plaintext=b"x", actor="alice",
    )
    sk = service.get_subject_key_by_subject("subj-clearing")
    service.destroy_key("subject_key", sk.id, "alice", approval_id="approval-1")

    service.revoke_key("kek", kek.id, "alice")
    row = service.destroy_key("kek", kek.id, "alice", approval_id="approval-2")
    assert row.state == "destroyed"


def test_subject_key_destroy_not_blocked_by_dependent_envelopes(service):
    """Deliberate exemption: a subject key's dependents are its own
    envelopes, and destroying it while they still exist *is* the
    crypto-shredding mechanism — not a hazard to block."""
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    for i in range(5):
        service.encrypt(
            subject_id="subj-exempt", table="users", column="email", record_id=f"rec-{i}",
            plaintext=b"x", actor="alice",
        )
    sk = service.get_subject_key_by_subject("subj-exempt")
    assert service.blocking_dependents("subject_key", sk.id) == 5

    row = service.destroy_key("subject_key", sk.id, "alice", approval_id="approval-1")
    assert row.state == "destroyed"


def test_kek_blocking_dependents_excludes_already_destroyed_subject_keys(service):
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    service.encrypt(
        subject_id="subj-excluded", table="users", column="email", record_id="rec-1",
        plaintext=b"x", actor="alice",
    )
    sk = service.get_subject_key_by_subject("subj-excluded")
    service.destroy_key("subject_key", sk.id, "alice", approval_id="approval-1")

    assert service.blocking_dependents("kek", kek.id) == 0
