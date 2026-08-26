from __future__ import annotations

import os

from keyring.config import settings
from keyring.core import crypto
from keyring.core.keystore import LocalEncryptedKeyStore
from keyring.providers.base import KeyProvider, ProviderUnavailable

_SUBJECT_WRAP_AAD = b"keyring:v1:subject-key-wrap"


class EnvKeyProvider(KeyProvider):
    """Root secret = a hex-encoded, high-entropy value in an environment
    variable (already CSPRNG-generated at provisioning time, so it goes
    through HKDF rather than the password-stretching Argon2id path)."""

    name = "env"

    def __init__(self) -> None:
        self._root_wrapping_key: bytearray | None = None
        self._store = LocalEncryptedKeyStore(settings.kek_store_path)

    def _read_secret(self) -> bytes:
        raw = os.environ.get(settings.root_secret_env_var)
        if not raw:
            raise ProviderUnavailable(f"{settings.root_secret_env_var} is not set")
        try:
            return bytes.fromhex(raw.strip())
        except ValueError as exc:
            raise ProviderUnavailable(f"{settings.root_secret_env_var} must be hex-encoded") from exc

    def is_available(self) -> bool:
        try:
            self._read_secret()
            return True
        except ProviderUnavailable:
            return False

    def connect(self) -> None:
        secret = self._read_secret()
        self._root_wrapping_key = bytearray(crypto.hkdf_derive(secret, crypto.HKDF_INFO_ROOT_WRAP))

    def disconnect(self) -> None:
        if self._root_wrapping_key is not None:
            crypto.zeroize(self._root_wrapping_key)
            self._root_wrapping_key = None

    def _key(self) -> bytearray:
        if self._root_wrapping_key is None:
            raise ProviderUnavailable("env provider not connected")
        return self._root_wrapping_key

    def create_kek(self, kek_ref: str) -> None:
        raw = bytearray(crypto.generate_key())
        try:
            self._store.put(kek_ref, bytes(raw), bytes(self._key()))
        finally:
            crypto.zeroize(raw)

    def wrap(self, kek_ref: str, plaintext: bytes) -> bytes:
        raw = bytearray(self._store.get(kek_ref, bytes(self._key())))
        try:
            result = crypto.aead_encrypt(bytes(raw), plaintext, _SUBJECT_WRAP_AAD)
        finally:
            crypto.zeroize(raw)
        return result.nonce + result.ciphertext + result.tag

    def unwrap(self, kek_ref: str, blob: bytes) -> bytes:
        nonce, ciphertext, tag = blob[: crypto.NONCE_LEN], blob[crypto.NONCE_LEN : -crypto.TAG_LEN], blob[-crypto.TAG_LEN :]
        raw = bytearray(self._store.get(kek_ref, bytes(self._key())))
        try:
            return crypto.aead_decrypt(bytes(raw), nonce, ciphertext, tag, _SUBJECT_WRAP_AAD)
        finally:
            crypto.zeroize(raw)

    def destroy_kek(self, kek_ref: str) -> None:
        self._store.delete(kek_ref)
