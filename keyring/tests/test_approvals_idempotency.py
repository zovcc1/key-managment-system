"""Two-party approval and idempotency-key tests (FR-9.3, destructive-op
conventions), exercised at the HTTP layer via TestClient."""
from __future__ import annotations

import uuid

from keyring.core.service import KeyringService
from keyring.models.audit import AuditLog
from keyring.providers.file_provider import FileKeyProvider

ALICE_KEY = "test-key-admin-alice"
BOB_KEY = "test-key-admin-bob"
DAN_KEY = "test-operator-dan"


def _bootstrap(client) -> dict:
    """Create an active KEK and one active subject key directly through the
    service layer (there is no HTTP endpoint to mint the very first KEK —
    that's a seed/bootstrap-time operation, not part of the ongoing HTTP
    lifecycle contract)."""
    provider = FileKeyProvider()
    provider.connect()
    db = client.session_factory()
    try:
        service = KeyringService(db, provider)
        kek = service.create_kek("bootstrap")
        service.activate_kek(kek.id, "bootstrap")
        env = service.encrypt(
            subject_id=f"subj-{uuid.uuid4()}", table="users", column="email", record_id="rec-1",
            plaintext=b"value", actor="bootstrap",
        )
        db.commit()
        return {"kek_id": kek.id, "subject_key_id": env.subject_key_id}
    finally:
        db.close()
        provider.disconnect()


def _seed_two_admins_and_operator(client):
    client.seed_operator("Alice", "key-admin", ALICE_KEY)
    client.seed_operator("Bob", "key-admin", BOB_KEY)
    client.seed_operator("Dan", "operator", DAN_KEY)


def test_self_approval_is_rejected(client):
    _seed_two_admins_and_operator(client)
    alice = client.open_session(ALICE_KEY)

    resp = client.http.post(
        "/api/approvals", json={"operation": "destroy", "targetId": "some-key-id", "recordCount": 0},
        headers=client.auth(alice["token"]),
    )
    assert resp.status_code == 200
    approval_id = resp.json()["id"]

    resp = client.http.post(f"/api/approvals/{approval_id}/approve", headers=client.auth(alice["token"]))
    assert resp.status_code == 403
    assert resp.json()["code"] == "SELF_APPROVAL_FORBIDDEN"


def test_missing_idempotency_key_is_rejected(client):
    _seed_two_admins_and_operator(client)
    bootstrap = _bootstrap(client)
    alice = client.open_session(ALICE_KEY)

    resp = client.http.post(
        f"/api/keys/{bootstrap['subject_key_id']}/destroy",
        json={"typedConfirmation": bootstrap["subject_key_id"], "approvalId": "irrelevant"},
        headers=client.auth(alice["token"]),
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "IDEMPOTENCY_KEY_REQUIRED"


def test_idempotency_replay_returns_identical_result_without_reexecuting(client):
    _seed_two_admins_and_operator(client)
    bootstrap = _bootstrap(client)
    alice = client.open_session(ALICE_KEY)
    bob = client.open_session(BOB_KEY)

    resp = client.http.post(
        "/api/approvals",
        json={"operation": "destroy", "targetId": bootstrap["subject_key_id"], "recordCount": 1},
        headers=client.auth(alice["token"]),
    )
    approval_id = resp.json()["id"]
    resp = client.http.post(f"/api/approvals/{approval_id}/approve", headers=client.auth(bob["token"]))
    assert resp.status_code == 200

    idem_key = str(uuid.uuid4())
    body = {"typedConfirmation": bootstrap["subject_key_id"], "approvalId": approval_id}

    first = client.http.post(
        f"/api/keys/{bootstrap['subject_key_id']}/destroy", json=body,
        headers={**client.auth(alice["token"]), "Idempotency-Key": idem_key},
    )
    assert first.status_code == 200
    assert first.json()["state"] == "destroyed"

    second = client.http.post(
        f"/api/keys/{bootstrap['subject_key_id']}/destroy", json=body,
        headers={**client.auth(alice["token"]), "Idempotency-Key": idem_key},
    )
    assert second.status_code == first.status_code
    assert second.json() == first.json()

    db = client.session_factory()
    try:
        destroy_entries = (
            db.query(AuditLog)
            .filter_by(operation="destroy", key_id=bootstrap["subject_key_id"])
            .count()
        )
        assert destroy_entries == 1, "replay must not re-execute the operation"
    finally:
        db.close()


def test_consumed_approval_cannot_be_reused_for_a_second_destroy(client):
    _seed_two_admins_and_operator(client)
    bootstrap = _bootstrap(client)
    alice = client.open_session(ALICE_KEY)
    bob = client.open_session(BOB_KEY)

    resp = client.http.post(
        "/api/approvals",
        json={"operation": "destroy", "targetId": bootstrap["subject_key_id"], "recordCount": 1},
        headers=client.auth(alice["token"]),
    )
    approval_id = resp.json()["id"]
    client.http.post(f"/api/approvals/{approval_id}/approve", headers=client.auth(bob["token"]))

    body = {"typedConfirmation": bootstrap["subject_key_id"], "approvalId": approval_id}
    first = client.http.post(
        f"/api/keys/{bootstrap['subject_key_id']}/destroy", json=body,
        headers={**client.auth(alice["token"]), "Idempotency-Key": str(uuid.uuid4())},
    )
    assert first.status_code == 200

    # Same approval, brand new idempotency key — must be rejected since the
    # approval was already consumed by the first (different) destroy call.
    retry = client.http.post(
        f"/api/keys/{bootstrap['subject_key_id']}/destroy", json=body,
        headers={**client.auth(alice["token"]), "Idempotency-Key": str(uuid.uuid4())},
    )
    assert retry.status_code == 409
    assert retry.json()["code"] == "APPROVAL_REQUIRED"
