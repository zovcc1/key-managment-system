"""Encrypted Files section: upload/download round trip via the blob store,
the per-file key tree, and RBAC. Service-level tests mirror
test_streaming.py; HTTP-level tests mirror test_streaming_http.py."""
from __future__ import annotations

import hashlib
import os
import uuid

import pytest

from keyring.config import settings
from keyring.core import blobstore, crypto
from keyring.core.service import KeyringService
from keyring.models.file_object import FileObject
from keyring.providers.file_provider import FileKeyProvider


@pytest.fixture(autouse=True)
def _isolate_blob_store(tmp_path, monkeypatch):
    """Every test in this module gets its own blob directory — same pattern
    as the `provider` fixture isolating the KEK store per test."""
    monkeypatch.setattr(settings, "blob_store_path", str(tmp_path / "blobs"))


def _chunks(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _make_kek(service, actor="alice"):
    kek = service.create_kek(actor)
    service.activate_kek(kek.id, actor)
    return kek


def _upload(service, payload: bytes, subject_id="subj-file", chunk_size=4096, actor="alice") -> FileObject:
    file_id = str(uuid.uuid4())
    env = service.encrypt_stream(
        subject_id=subject_id, table="files", column="content", record_id=file_id,
        plaintext_chunks=_chunks(payload, chunk_size), actor=actor, blob_ref=file_id,
    )
    with blobstore.open_read(file_id) as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    fo = FileObject(
        id=file_id, filename="test.bin", content_type="application/octet-stream",
        size_bytes=len(payload), ciphertext_sha256=digest, envelope_id=env.id,
        subject_id=subject_id, uploaded_by=actor,
    )
    service.db.add(fo)
    service.db.commit()
    return fo


# --- 1. round trip -------------------------------------------------------

def test_upload_download_round_trip_multi_frame(service):
    _make_kek(service)
    payload = os.urandom(1024 * 1024 + 137)  # >1 MiB, spans multiple frames
    fo = _upload(service, payload, chunk_size=64 * 1024)

    out = b"".join(service.decrypt_stream(fo.envelope_id, actor="alice"))
    assert out == payload


def test_upload_download_round_trip_empty_file(service):
    _make_kek(service)
    fo = _upload(service, b"")

    out = b"".join(service.decrypt_stream(fo.envelope_id, actor="alice"))
    assert out == b""


# --- 2. envelope/blob shape ------------------------------------------------

def test_envelope_uses_blob_ref_not_inline_ciphertext(service):
    _make_kek(service)
    payload = b"hello file world" * 10
    fo = _upload(service, payload)

    from keyring.models.envelope import Envelope
    env = service.db.get(Envelope, fo.envelope_id)

    assert env.blob_ref == fo.id
    assert env.ciphertext == b""
    assert blobstore.exists(env.blob_ref)
    with blobstore.open_read(env.blob_ref) as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == fo.ciphertext_sha256


# --- 3. tamper -------------------------------------------------------------

def test_tampered_blob_byte_raises_decrypt_failed(service):
    _make_kek(service)
    payload = b"y" * 500
    fo = _upload(service, payload, chunk_size=100)

    path = blobstore._resolve(fo.id)  # test-only reach-in to corrupt the file on disk
    data = bytearray(path.read_bytes())
    data[20] ^= 0xFF
    path.write_bytes(bytes(data))

    with pytest.raises(crypto.DecryptFailed):
        list(service.decrypt_stream(fo.envelope_id, actor="alice"))


# --- 4. missing blob ---------------------------------------------------

def test_missing_blob_raises_decrypt_failed_and_key_tree_reports_it(service):
    _make_kek(service)
    fo = _upload(service, b"gone soon")

    blobstore.delete(fo.id)

    with pytest.raises(crypto.DecryptFailed):
        list(service.decrypt_stream(fo.envelope_id, actor="alice"))

    tree = service.file_key_tree(fo)
    assert tree["blobPresent"] is False
    assert tree["readable"] is False
    assert tree["brokenAtLevel"] == 4


# --- 5. healthy key tree -------------------------------------------------

def test_key_tree_healthy_file_has_five_levels_and_is_readable(service):
    _make_kek(service)
    fo = _upload(service, b"tree me")

    tree = service.file_key_tree(fo)
    assert [n["level"] for n in tree["nodes"]] == [0, 1, 2, 3, 4]
    assert [n["kind"] for n in tree["nodes"]] == ["root_secret", "kek", "subject_key", "dek", "envelope"]
    assert tree["readable"] is True
    assert tree["brokenAtLevel"] is None
    assert tree["blobPresent"] is True
    assert all(n["usable"] for n in tree["nodes"])


# --- 6. crypto-shredding ---------------------------------------------------

def test_erasure_breaks_key_tree_at_subject_key_and_blocks_download(service):
    _make_kek(service)
    fo = _upload(service, b"shred me", subject_id="subj-erase")

    service.erase_subject("subj-erase", actor="alice", approval_id="approval-1")

    tree = service.file_key_tree(fo)
    assert tree["readable"] is False
    assert tree["brokenAtLevel"] == 2  # subject_key
    assert tree["blobPresent"] is True  # ciphertext left in place — the proof

    with pytest.raises(crypto.DecryptFailed):
        list(service.decrypt_stream(fo.envelope_id, actor="alice"))


# --- 7. rotation doesn't break existing files -------------------------

def test_kek_rotation_leaves_existing_file_downloadable(service):
    kek = _make_kek(service)
    fo = _upload(service, b"still here after rotation")

    service.rotate_kek(kek.id, "alice")  # deprecates old KEK, does not rewrap inline

    out = b"".join(service.decrypt_stream(fo.envelope_id, actor="alice"))
    assert out == b"still here after rotation"

    tree = service.file_key_tree(fo)
    assert tree["readable"] is True


# --- 9. path traversal guard -----------------------------------------------

def test_blob_ref_rejects_path_traversal():
    with pytest.raises(blobstore.InvalidBlobRef):
        blobstore._resolve("../../etc/passwd")
    with pytest.raises(blobstore.InvalidBlobRef):
        blobstore._resolve("not-a-uuid")
    assert blobstore.exists("../../etc/passwd") is False


# --- 8. RBAC (HTTP level) ------------------------------------------------

ALICE_KEY = "test-key-admin-alice-files"
CAROL_KEY = "test-auditor-carol-files"
DAN_KEY = "test-operator-dan-files"


def _seed_all(client) -> None:
    client.seed_operator("Alice", "key-admin", ALICE_KEY)
    client.seed_operator("Carol", "auditor", CAROL_KEY)
    client.seed_operator("Dan", "operator", DAN_KEY)


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


def test_key_admin_forbidden_from_upload_and_list(client):
    _seed_all(client)
    _bootstrap_kek(client)
    alice = client.open_session(ALICE_KEY)

    resp = client.http.post(
        "/api/files", data={"subjectId": "subj-rbac"},
        files={"file": ("a.txt", b"hi", "text/plain")}, headers=client.auth(alice["token"]),
    )
    assert resp.status_code == 403

    resp = client.http.get("/api/files", headers=client.auth(alice["token"]))
    assert resp.status_code == 403


def test_auditor_can_read_key_tree_but_not_download(client):
    _seed_all(client)
    _bootstrap_kek(client)
    dan = client.open_session(DAN_KEY)

    resp = client.http.post(
        "/api/files", data={"subjectId": "subj-rbac-2"},
        files={"file": ("a.txt", b"auditable bytes", "text/plain")}, headers=client.auth(dan["token"]),
    )
    assert resp.status_code == 200, resp.text
    file_id = resp.json()["id"]

    carol = client.open_session(CAROL_KEY)

    resp = client.http.get(f"/api/files/{file_id}/key-tree", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    assert resp.json()["readable"] is True

    resp = client.http.get(f"/api/files/{file_id}/download", headers=client.auth(carol["token"]))
    assert resp.status_code == 403


def test_upload_then_download_round_trip_over_http(client):
    _seed_all(client)
    _bootstrap_kek(client)
    dan = client.open_session(DAN_KEY)

    payload = os.urandom(50_000)
    resp = client.http.post(
        "/api/files", data={"subjectId": "subj-rbac-3"},
        files={"file": ("payload.bin", payload, "application/octet-stream")}, headers=client.auth(dan["token"]),
    )
    assert resp.status_code == 200, resp.text
    file_id = resp.json()["id"]

    resp = client.http.get(f"/api/files/{file_id}/download", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    assert resp.content == payload
    assert "payload.bin" in resp.headers["content-disposition"]
