from __future__ import annotations

import os
from pathlib import Path

from keyring.config import settings
from keyring.core import crypto
from keyring.core.keystore import LocalEncryptedKeyStore
from keyring.providers.base import KeyProvider, ProviderUnavailable

_SUBJECT_WRAP_AAD = b"keyring:v1:subject-key-wrap"


def _require_0400(path: Path, what: str) -> None:
    if not path.exists():
        raise ProviderUnavailable(f"{what} not found at {path}")
    if os.name == "nt":
        # NTFS has no POSIX mode bits: os.stat reports 0o444 when the
        # read-only attribute is set and 0o666 otherwise, and os.chmod(p, 0o400)
        # can only ever produce 0o444 — so the exact-0400 check below can never
        # pass on Windows. Enforce the closest real equivalent: not writable.
        if os.stat(path).st_mode & 0o200:
            raise ProviderUnavailable(
                f"{what} at {path} is writable, expected read-only — refusing to start"
            )
        return
    mode = os.stat(path).st_mode & 0o777
    if mode != 0o400:
        raise ProviderUnavailable(
            f"{what} at {path} has permissions {oct(mode)}, expected 0400 — refusing to start"
        )


class FileKeyProvider(KeyProvider):
    """Root secret = a passphrase read from a file at mode 0400, stretched
    with Argon2id (FR-1.3). KEK material is stored in a local
    AES-256-GCM-wrapped JSON file outside the application database."""

    name = "file"

    def __init__(self) -> None:
        self._root_wrapping_key: bytearray | None = None
        self._store = LocalEncryptedKeyStore(settings.kek_store_path)

    def is_available(self) -> bool:
        try:
            _require_0400(Path(settings.root_passphrase_file), "root passphrase file")
            return True
        except ProviderUnavailable:
            return False

    def connect(self) -> None:
        passphrase_path = Path(settings.root_passphrase_file)
        _require_0400(passphrase_path, "root passphrase file")

        salt_path = Path(settings.root_salt_file)
        if not salt_path.exists():
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            salt_path.write_bytes(crypto.random_bytes(16))
            os.chmod(salt_path, 0o400)
        _require_0400(salt_path, "root salt file")

        passphrase = passphrase_path.read_bytes().strip()
        salt = salt_path.read_bytes()
        self._root_wrapping_key = bytearray(crypto.argon2id_derive(passphrase, salt))

    def disconnect(self) -> None:
        if self._root_wrapping_key is not None:
            crypto.zeroize(self._root_wrapping_key)
            self._root_wrapping_key = None

    def _key(self) -> bytearray:
        if self._root_wrapping_key is None:
            raise ProviderUnavailable("file provider not connected")
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
