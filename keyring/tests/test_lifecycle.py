"""Lifecycle state-machine tests (FR-4): per-entity-type legal-transition
graphs, illegal-transition rejection, and the DB-enforced single-active-KEK
invariant under both sequential and truly concurrent activation attempts.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy.orm import sessionmaker

from keyring.core import lifecycle
from keyring.core.errors import ActiveConflictError
from keyring.core.lifecycle import IllegalTransition
from keyring.core.service import KeyringService


def test_kek_and_subject_key_graphs_differ_on_active_to_destroyed():
    """The one deliberate divergence between the two graphs: a subject key
    may go straight from active to destroyed (crypto-shredding); a KEK may
    not (it must be deprecated/revoked first)."""
    assert "destroyed" not in lifecycle.legal_transitions("active", "kek")
    assert "destroyed" in lifecycle.legal_transitions("active", "subject_key")


def test_kek_active_to_destroyed_is_illegal():
    with pytest.raises(IllegalTransition):
        lifecycle.assert_legal("active", "destroyed", "kek")


def test_subject_key_active_to_destroyed_is_legal():
    lifecycle.assert_legal("active", "destroyed", "subject_key")  # must not raise


def test_destroyed_and_revoked_are_terminal_for_both_types():
    for key_type in ("kek", "subject_key"):
        assert lifecycle.legal_transitions("destroyed", key_type) == []
        assert lifecycle.legal_transitions("revoked", key_type) == ["destroyed"]


def test_service_destroy_kek_directly_from_active_is_rejected(service):
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    with pytest.raises(IllegalTransition):
        service.destroy_key("kek", kek.id, "alice", approval_id="approval-1")


def test_service_destroy_subject_key_directly_from_active_succeeds(service):
    kek = service.create_kek("alice")
    service.activate_kek(kek.id, "alice")
    service.encrypt(
        subject_id="subj-lifecycle", table="users", column="email", record_id="rec-1",
        plaintext=b"x", actor="alice",
    )
    sk = service.get_subject_key_by_subject("subj-lifecycle")
    row = service.destroy_key("subject_key", sk.id, "alice", approval_id="approval-1")
    assert row.state == "destroyed"


def test_activate_second_kek_while_one_active_raises_active_conflict(service):
    kek1 = service.create_kek("alice")
    service.activate_kek(kek1.id, "alice")

    kek2 = service.create_kek("alice")
    with pytest.raises(ActiveConflictError):
        service.activate_kek(kek2.id, "alice")


def test_concurrent_activation_only_one_wins(session_factory, provider):
    """True two-thread race against the same SQLite file: only one
    activation may commit, the loser must observe ActiveConflictError, and
    exactly one KEK ends up active (the partial unique index is the sole
    arbiter, not application-level locking)."""
    setup_db = session_factory()
    setup_service = KeyringService(setup_db, provider)
    kek_a = setup_service.create_kek("alice")
    kek_b = setup_service.create_kek("alice")
    setup_db.commit()
    kek_a_id, kek_b_id = kek_a.id, kek_b.id
    setup_db.close()

    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def _activate(name: str, kek_id: str):
        db = session_factory()
        svc = KeyringService(db, provider)
        try:
            barrier.wait(timeout=5)
            svc.activate_kek(kek_id, "alice")
            db.commit()
            outcomes[name] = "ok"
        except ActiveConflictError:
            outcomes[name] = "conflict"
        finally:
            db.close()

    t1 = threading.Thread(target=_activate, args=("a", kek_a_id))
    t2 = threading.Thread(target=_activate, args=("b", kek_b_id))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    results = sorted(outcomes.values())
    assert results == ["conflict", "ok"], outcomes

    verify_db = session_factory()
    try:
        from keyring.models.keys import Kek

        active = verify_db.query(Kek).filter_by(state="active").all()
        assert len(active) == 1
    finally:
        verify_db.close()
