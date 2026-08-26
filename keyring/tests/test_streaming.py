"""Streaming encrypt/decrypt tests (FR-2.5): chunked round trip, per-chunk
tamper detection, and eager envelope validation on the decrypt path."""
from __future__ import annotations

import pytest

from keyring.core import crypto
from keyring.core.service import STREAM_ALG


def _chunks(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _make_kek(service, actor="alice"):
    kek = service.create_kek(actor)
    service.activate_kek(kek.id, actor)
    return kek


def test_stream_round_trip_multiple_chunks(service):
    _make_kek(service)
    payload = bytes(range(256)) * 50  # 12800 bytes, several small chunks
    env = service.encrypt_stream(
        subject_id="subj-stream", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(payload, 1000), actor="alice",
    )
    assert env.alg == STREAM_ALG

    out = bytearray()
    for chunk in service.decrypt_stream(env.id, actor="alice"):
        out.extend(chunk)
    assert bytes(out) == payload


def test_stream_round_trip_single_chunk_smaller_than_buffer(service):
    _make_kek(service)
    payload = b"small payload fits in one chunk"
    env = service.encrypt_stream(
        subject_id="subj-stream-one", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(payload, 4096), actor="alice",
    )
    out = b"".join(service.decrypt_stream(env.id, actor="alice"))
    assert out == payload


def test_stream_round_trip_empty_payload(service):
    _make_kek(service)
    env = service.encrypt_stream(
        subject_id="subj-stream-empty", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(b"", 4096), actor="alice",
    )
    out = b"".join(service.decrypt_stream(env.id, actor="alice"))
    assert out == b""


def test_stream_ciphertext_is_framed_multi_chunk_when_input_has_multiple_chunks(service):
    _make_kek(service)
    payload = b"x" * 30
    env = service.encrypt_stream(
        subject_id="subj-stream-frames", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(payload, 10), actor="alice",
    )
    # 3 frames of 10 bytes each: [4-byte len][10-byte ct][16-byte tag] * 3
    assert len(env.ciphertext) == 3 * (4 + 10 + 16)


def test_stream_tampered_frame_byte_raises_decrypt_failed_uniformly(service):
    _make_kek(service)
    payload = b"y" * 30
    env = service.encrypt_stream(
        subject_id="subj-stream-tamper", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(payload, 10), actor="alice",
    )
    tampered = bytearray(env.ciphertext)
    tampered[10] ^= 0xFF  # flip a byte inside the first frame's ciphertext
    env.ciphertext = bytes(tampered)
    service.db.flush()

    with pytest.raises(crypto.DecryptFailed):
        list(service.decrypt_stream(env.id, actor="alice"))


def test_decrypt_stream_missing_envelope_fails_eagerly(service):
    _make_kek(service)
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt_stream("does-not-exist", actor="alice")


def test_decrypt_stream_rejects_non_stream_envelope(service):
    _make_kek(service)
    env = service.encrypt(
        subject_id="subj-not-stream", table="users", column="email", record_id="rec-1",
        plaintext=b"regular envelope", actor="alice",
    )
    with pytest.raises(crypto.DecryptFailed):
        service.decrypt_stream(env.id, actor="alice")


def test_stream_erasure_makes_all_chunks_unreadable(service):
    _make_kek(service)
    payload = b"z" * 5000
    env = service.encrypt_stream(
        subject_id="subj-stream-erase", table="files", column="blob", record_id="rec-1",
        plaintext_chunks=_chunks(payload, 512), actor="alice",
    )
    service.erase_subject("subj-stream-erase", actor="alice", approval_id="approval-1")

    with pytest.raises(crypto.DecryptFailed):
        list(service.decrypt_stream(env.id, actor="alice"))
