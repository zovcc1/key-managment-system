"""Local encrypted KEK material store.

Backs the File and Env providers. Each KEK's raw 256-bit key is stored on
disk wrapped (AES-256-GCM) under a root wrapping key derived from that
provider's root secret. This file lives outside the application database
(FR-6.1) — the app DB only ever sees `provider_ref` handles.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from keyring.core import crypto

_AAD = b"keyring:v1:kek-store"


class LocalEncryptedKeyStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)

    def _load_raw(self) -> dict:
        if not self._path.exists():
            return {}
        return json.loads(self._path.read_text())

    def _save_raw(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data))
        os.chmod(self._path, 0o400)

    def put(self, ref: str, plaintext_key: bytes, root_wrapping_key: bytes) -> None:
        result = crypto.aead_encrypt(root_wrapping_key, plaintext_key, _AAD)
        data = self._load_raw()
        # Existing store file may be 0400 (read-only) from a prior write.
        if self._path.exists():
            os.chmod(self._path, 0o600)
        data[ref] = {
            "nonce": result.nonce.hex(),
            "ciphertext": result.ciphertext.hex(),
            "tag": result.tag.hex(),
        }
        self._save_raw(data)

    def get(self, ref: str, root_wrapping_key: bytes) -> bytes:
        data = self._load_raw()
        entry = data.get(ref)
        if entry is None:
            raise KeyError(ref)
        return crypto.aead_decrypt(
            root_wrapping_key,
            bytes.fromhex(entry["nonce"]),
            bytes.fromhex(entry["ciphertext"]),
            bytes.fromhex(entry["tag"]),
            _AAD,
        )

    def delete(self, ref: str) -> None:
        data = self._load_raw()
        if ref in data:
            if self._path.exists():
                os.chmod(self._path, 0o600)
            del data[ref]
            self._save_raw(data)

    def exists(self, ref: str) -> bool:
        return ref in self._load_raw()
