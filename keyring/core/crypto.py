"""Cryptographic primitives.

Every primitive below is a thin wrapper around `cryptography` / `argon2-cffi`.
No primitive (AES, KDF, MAC, constant-time compare) is implemented by hand,
per the build spec. This module is the only place in the codebase allowed
to touch raw key material directly.
"""
from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from keyring.config import settings

NONCE_LEN = 12  # 96-bit, per spec
KEY_LEN = 32  # 256-bit
TAG_LEN = 16
ENVELOPE_VERSION = 1

# HKDF info strings — distinct per derivation context so no two derivations
# can ever collide even if fed the same input key material.
HKDF_INFO_ROOT_WRAP = b"keyring:v1:root-wrap"
HKDF_INFO_CERT_SIGNING = b"keyring:v1:cert-signing"


class DecryptFailed(Exception):
    """Single, undifferentiated decryption failure.

    Deliberately carries no detail about *why* decryption failed (wrong key,
    tampered ciphertext, mismatched AAD, truncated envelope). See FR-3.4.
    """

    CODE = "DECRYPT_FAILED"

    def __init__(self) -> None:
        super().__init__("DECRYPT_FAILED")


class CSPRNGUnavailable(RuntimeError):
    pass


def assert_csprng_available() -> None:
    """FR-1.4: fail loudly and refuse to start if the OS CSPRNG is unavailable."""
    try:
        sample = os.urandom(32)
        if len(sample) != 32:
            raise CSPRNGUnavailable("os.urandom returned short output")
    except NotImplementedError as exc:  # pragma: no cover - platform without CSPRNG
        raise CSPRNGUnavailable("OS CSPRNG not available on this platform") from exc


def random_bytes(n: int) -> bytes:
    """CSPRNG-backed random bytes. The only source of randomness in this codebase."""
    return secrets.token_bytes(n)


def generate_key() -> bytes:
    """256-bit key from the OS CSPRNG."""
    return random_bytes(KEY_LEN)


def generate_nonce() -> bytes:
    """96-bit random nonce."""
    return random_bytes(NONCE_LEN)


def zeroize(buf: bytearray) -> None:
    """Best-effort overwrite of key material in memory.

    CPython gives no hard guarantee this is not copied elsewhere (interning,
    GC, swap) — this reduces the exposure window, it does not eliminate it.
    """
    for i in range(len(buf)):
        buf[i] = 0


class _NonceGuard:
    """Defensive, structural (key_id, nonce) reuse detector.

    Every DEK is single-use by construction, so (key, nonce) reuse should be
    structurally impossible. This asserts that invariant rather than trusting
    it implicitly, per spec. Bounded so it cannot grow unbounded in a
    long-lived process; a bound miss only weakens the *defensive* check, the
    structural guarantee (fresh DEK per item) is unaffected.
    """

    _MAX = 200_000

    def __init__(self) -> None:
        self._seen: set[tuple[bytes, bytes]] = set()

    def check_and_record(self, key_fingerprint: bytes, nonce: bytes) -> None:
        pair = (key_fingerprint, nonce)
        if pair in self._seen:
            raise AssertionError("nonce reuse detected for the same key — refusing to encrypt")
        if len(self._seen) >= self._MAX:
            self._seen.clear()
        self._seen.add(pair)


_nonce_guard = _NonceGuard()


def _fingerprint(key: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(key).digest()


@dataclass(frozen=True)
class AeadResult:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> AeadResult:
    """AES-256-GCM encrypt with a fresh random nonce. Fixed algorithm — not
    a caller-selectable parameter anywhere in the public surface (FR-10.2)."""
    nonce = generate_nonce()
    _nonce_guard.check_and_record(_fingerprint(key), nonce)
    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-TAG_LEN], combined[-TAG_LEN:]
    return AeadResult(nonce=nonce, ciphertext=ciphertext, tag=tag)


STREAM_NONCE_PREFIX_LEN = 8  # random, once per envelope
STREAM_CHUNK_INDEX_LEN = 4  # big-endian counter; 8 + 4 = NONCE_LEN


def stream_nonce_prefix() -> bytes:
    """One random prefix per streamed envelope; combined with a per-chunk
    counter (chunk_nonce) this yields a unique 12-byte nonce per chunk
    without needing a fresh CSPRNG call for every chunk."""
    return random_bytes(STREAM_NONCE_PREFIX_LEN)


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    """8-byte per-envelope random prefix + 4-byte big-endian chunk index =
    a nonce that is unique per chunk as long as index never repeats within
    one envelope (guaranteed — it is an in-process counter)."""
    if len(prefix) != STREAM_NONCE_PREFIX_LEN:
        raise ValueError("stream nonce prefix must be 8 bytes")
    return prefix + index.to_bytes(STREAM_CHUNK_INDEX_LEN, "big")


def stream_chunk_aad(base_aad: bytes, index: int, is_final: bool) -> bytes:
    """Binds each chunk's AAD to its position and to whether it is the last
    chunk, so truncating, reordering, or duplicating chunks breaks AEAD
    verification instead of silently producing corrupted plaintext."""
    return base_aad + f"|chunk:{index}|final:{int(is_final)}".encode("utf-8")


def aead_encrypt_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> AeadResult:
    """AES-256-GCM encrypt with a caller-supplied nonce. Used only for
    per-chunk streaming encryption, where the nonce is derived from a
    per-envelope random prefix plus a chunk counter rather than drawn fresh
    from the CSPRNG per chunk. Still runs through the same nonce-reuse
    guard as aead_encrypt."""
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be NONCE_LEN bytes")
    _nonce_guard.check_and_record(_fingerprint(key), nonce)
    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-TAG_LEN], combined[-TAG_LEN:]
    return AeadResult(nonce=nonce, ciphertext=ciphertext, tag=tag)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises DecryptFailed uniformly for every failure
    mode: bad tag, tampered ciphertext, wrong key, mismatched AAD, malformed
    input. Never distinguishes them (FR-3.4)."""
    try:
        if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN or len(key) != KEY_LEN:
            raise DecryptFailed()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)
    except (InvalidTag, ValueError, DecryptFailed):
        raise DecryptFailed()


def hkdf_derive(input_key_material: bytes, info: bytes, salt: Optional[bytes] = None, length: int = KEY_LEN) -> bytes:
    """HKDF-SHA256. `info` must be distinct per derivation context — never
    reuse an info string across two different logical derivations."""
    hkdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(input_key_material)


def argon2id_derive(passphrase: bytes, salt: bytes, length: int = KEY_LEN) -> bytes:
    """Argon2id, minimum params per spec: 64 MiB memory, 3 iterations, 4 lanes."""
    if len(salt) < 16:
        raise ValueError("Argon2id salt must be at least 16 bytes")
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost_kib,
        parallelism=settings.argon2_parallelism,
        hash_len=length,
        type=Type.ID,
    )


def build_aad(table: str, column: str, record_id: str, subject_id: str) -> bytes:
    """Bind every ciphertext to its logical location. Without this an
    attacker with write access can relocate an encrypted field between
    records without breaking confidentiality but corrupting meaning."""
    return f"table:{table}|col:{column}|id:{record_id}|subject:{subject_id}".encode("utf-8")


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
