"""Primitive-level tests (FR-1, FR-3.4) — no DB, no provider."""
from __future__ import annotations

import pytest

from keyring.core import crypto


def test_aead_round_trip():
    key = crypto.generate_key()
    result = crypto.aead_encrypt(key, b"hello world", b"aad-1")
    plaintext = crypto.aead_decrypt(key, result.nonce, result.ciphertext, result.tag, b"aad-1")
    assert plaintext == b"hello world"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda k, n, c, t, a: (k, n, c, t[:-1] + bytes([t[-1] ^ 1]), a),  # tampered tag
        lambda k, n, c, t, a: (k, n, c[:-1] + bytes([c[-1] ^ 1]) if c else b"\x00", t, a),  # tampered ciphertext
        lambda k, n, c, t, a: (k, bytes([n[0] ^ 1]) + n[1:], c, t, a),  # tampered nonce
        lambda k, n, c, t, a: (k, n, c, t, a + b"x"),  # mismatched aad
        lambda k, n, c, t, a: (crypto.generate_key(), n, c, t, a),  # wrong key
        lambda k, n, c, t, a: (k, n[:-1], c, t, a),  # truncated nonce
    ],
)
def test_aead_decrypt_uniform_failure(mutate):
    """Every distinct failure mode must raise the exact same exception —
    never a different type or message (FR-3.4)."""
    key = crypto.generate_key()
    result = crypto.aead_encrypt(key, b"some plaintext", b"aad")
    bad_key, bad_nonce, bad_ct, bad_tag, bad_aad = mutate(
        key, result.nonce, result.ciphertext, result.tag, b"aad"
    )
    with pytest.raises(crypto.DecryptFailed) as exc_info:
        crypto.aead_decrypt(bad_key, bad_nonce, bad_ct, bad_tag, bad_aad)
    assert str(exc_info.value) == "DECRYPT_FAILED"
    assert exc_info.value.CODE == "DECRYPT_FAILED"


def test_hkdf_distinct_info_no_collision():
    ikm = crypto.generate_key()
    a = crypto.hkdf_derive(ikm, b"context-a")
    b = crypto.hkdf_derive(ikm, b"context-b")
    assert a != b


def test_hkdf_deterministic():
    ikm = crypto.generate_key()
    assert crypto.hkdf_derive(ikm, b"ctx") == crypto.hkdf_derive(ikm, b"ctx")


def test_argon2id_rejects_short_salt():
    with pytest.raises(ValueError):
        crypto.argon2id_derive(b"passphrase", salt=b"short")


def test_argon2id_deterministic_for_same_salt():
    salt = crypto.random_bytes(16)
    a = crypto.argon2id_derive(b"passphrase", salt)
    b = crypto.argon2id_derive(b"passphrase", salt)
    assert a == b
    assert len(a) == crypto.KEY_LEN


def test_build_aad_binds_logical_location():
    a = crypto.build_aad("users", "email", "rec-1", "subject-1")
    b = crypto.build_aad("users", "email", "rec-2", "subject-1")
    assert a != b


def test_constant_time_eq():
    assert crypto.constant_time_eq(b"abc", b"abc")
    assert not crypto.constant_time_eq(b"abc", b"abd")


def test_assert_csprng_available_does_not_raise():
    crypto.assert_csprng_available()


def test_generate_key_and_nonce_lengths():
    assert len(crypto.generate_key()) == crypto.KEY_LEN
    assert len(crypto.generate_nonce()) == crypto.NONCE_LEN
