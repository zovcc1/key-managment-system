"""HTTP-level streaming encrypt/decrypt tests (FR-2.5) via TestClient."""
from __future__ import annotations

import uuid

from keyring.core.service import KeyringService
from keyring.providers.file_provider import FileKeyProvider

ALICE_KEY = "test-operator-alice-stream"


def _bootstrap_kek(client) -> None:
    provider = FileKeyProvider()
    provider.connect()
    db = client.session_factory()
    try:
        service = KeyringService(db, provider)
        kek = service.create_kek("bootstrap")
        service.activate_kek(kek.id, "bootstrap")
        db.commit()
    finally:
        db.close()
        provider.disconnect()


def test_encrypt_stream_then_decrypt_stream_round_trip(client):
    client.seed_operator("Alice", "operator", ALICE_KEY)
    _bootstrap_kek(client)
    alice = client.open_session(ALICE_KEY)

    payload = bytes(range(256)) * 500  # 128000 bytes
    subject_id = f"subj-{uuid.uuid4()}"

    resp = client.http.post(
        "/api/encrypt-stream",
        params={"subjectId": subject_id, "table": "files", "column": "blob", "recordId": "rec-1"},
        content=payload,
        headers={**client.auth(alice["token"]), "Content-Type": "application/octet-stream"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["alg"] == "AES-256-GCM-STREAM"
    envelope_id = body["id"]

    resp = client.http.get(f"/api/decrypt-stream/{envelope_id}", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    assert resp.content == payload


def test_decrypt_stream_missing_envelope_returns_decrypt_failed(client):
    client.seed_operator("Alice", "operator", ALICE_KEY)
    _bootstrap_kek(client)
    alice = client.open_session(ALICE_KEY)

    resp = client.http.get("/api/decrypt-stream/does-not-exist", headers=client.auth(alice["token"]))
    assert resp.status_code == 400
    assert resp.json()["code"] == "DECRYPT_FAILED"
