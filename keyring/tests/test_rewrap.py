"""Resumable KEK rotation / rewrap tests (FR-5)."""
from __future__ import annotations

from keyring.models.keys import SubjectKey


def _seed_subjects(service, count, prefix="subj-rw"):
    subject_ids = []
    for i in range(count):
        subject_id = f"{prefix}-{i:03d}"
        service.encrypt(
            subject_id=subject_id, table="users", column="email", record_id="rec-0",
            plaintext=f"value-{i}".encode(), actor="alice",
        )
        subject_ids.append(subject_id)
    return subject_ids


def test_rotate_kek_does_not_immediately_rewrap(service):
    """FR-5.1: rotation demotes the old KEK and activates a new one in one
    transaction, but the actual rewrap of existing subject keys is a
    separate, resumable batch job — it must not happen inline."""
    kek1 = service.create_kek("alice")
    service.activate_kek(kek1.id, "alice")
    _seed_subjects(service, 5)

    old_kek, new_kek, job = service.rotate_kek(kek1.id, "alice")
    assert old_kek.state == "deprecated"
    assert new_kek.state == "active"
    assert job.total == 5
    assert job.done == 0

    still_wrapped_under_old = service.db.query(SubjectKey).filter_by(kek_id=old_kek.id).count()
    assert still_wrapped_under_old == 5


def test_rewrap_resumes_with_no_gap_and_no_duplicate(service):
    kek1 = service.create_kek("alice")
    service.activate_kek(kek1.id, "alice")
    subject_ids = _seed_subjects(service, 23)

    old_kek, new_kek, job = service.rotate_kek(kek1.id, "alice")

    seen_cursors = []
    # Simulate a worker that gets killed and resumed repeatedly, one small
    # batch at a time, rather than a single call to completion.
    while job.state == "running":
        before_cursor = job.cursor
        job = service.rewrap_step(job.id, batch_size=3)
        seen_cursors.append((before_cursor, job.cursor, job.done))

    assert job.state == "completed"
    assert job.done == job.total == 23

    for sid in subject_ids:
        sk = service.get_subject_key_by_subject(sid)
        assert sk.kek_id == new_kek.id

    # No duplicate processing: cursor strictly increases in id order across
    # every resumed batch (subject key ids are ordered strings compared
    # lexicographically, matching the query's ORDER BY id ASC).
    non_none_cursors = [c for _, c, _ in seen_cursors if c is not None]
    assert non_none_cursors == sorted(non_none_cursors)
    assert len(set(non_none_cursors)) == len(non_none_cursors)


def test_rewrap_step_is_a_noop_once_job_completed(service):
    kek1 = service.create_kek("alice")
    service.activate_kek(kek1.id, "alice")
    _seed_subjects(service, 2)
    _, _, job = service.rotate_kek(kek1.id, "alice")

    job = service.rewrap_step(job.id, batch_size=50)
    assert job.state == "completed"
    done_before = job.done

    job = service.rewrap_step(job.id, batch_size=50)
    assert job.done == done_before


def test_encrypt_and_decrypt_available_mid_rewrap(service):
    """Both the not-yet-rewrapped and already-rewrapped subject keys must
    remain fully encrypt/decrypt-able throughout the batch job (FR-5.4)."""
    kek1 = service.create_kek("alice")
    service.activate_kek(kek1.id, "alice")
    subject_ids = _seed_subjects(service, 10)

    _, new_kek, job = service.rotate_kek(kek1.id, "alice")
    # Advance only partway — some subject keys stay under the old KEK.
    job = service.rewrap_step(job.id, batch_size=4)
    assert job.state == "running"
    assert 0 < job.done < job.total

    rewrapped_ids = [
        sid for sid in subject_ids if service.get_subject_key_by_subject(sid).kek_id == new_kek.id
    ]
    not_yet_ids = [
        sid for sid in subject_ids if service.get_subject_key_by_subject(sid).kek_id != new_kek.id
    ]
    assert rewrapped_ids and not_yet_ids

    for sid in rewrapped_ids + not_yet_ids:
        env = service.encrypt(
            subject_id=sid, table="users", column="phone", record_id="rec-mid-rewrap",
            plaintext=b"mid-rewrap-value", actor="alice",
        )
        assert service.decrypt(env.id, actor="alice") == b"mid-rewrap-value"

    # New subject keys created while the job is still running must land on
    # the newly-active KEK, not the deprecated one.
    env = service.encrypt(
        subject_id="subj-brand-new", table="users", column="email", record_id="rec-0",
        plaintext=b"brand new", actor="alice",
    )
    fresh_sk = service.get_subject_key_by_subject("subj-brand-new")
    assert fresh_sk.kek_id == new_kek.id
    assert service.decrypt(env.id, actor="alice") == b"brand new"
