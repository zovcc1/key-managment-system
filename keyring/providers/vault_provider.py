from __future__ import annotations

import base64
import os

import httpx

from keyring.config import settings
from keyring.core.crypto import DecryptFailed
from keyring.providers.base import KeyProvider, ProviderUnavailable


class VaultKeyProvider(KeyProvider):
    """HashiCorp Vault Transit engine. KEK material never leaves Vault —
    wrap/unwrap are performed server-side by Vault's `encrypt`/`decrypt`
    transit endpoints. `wrap()` returns Vault's own ciphertext string
    (`vault:v1:...`) encoded as bytes; there is no local nonce/tag to
    manage because Vault owns that entirely."""

    name = "vault"

    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    def _token(self) -> str:
        token = os.environ.get(settings.vault_token_env_var)
        if not token:
            raise ProviderUnavailable(f"{settings.vault_token_env_var} is not set")
        return token

    def is_available(self) -> bool:
        try:
            client = httpx.Client(base_url=settings.vault_addr, timeout=2.0)
            resp = client.get("/v1/sys/health")
            return resp.status_code in (200, 429, 472, 473)
        except httpx.HTTPError:
            return False

    def connect(self) -> None:
        token = self._token()
        self._client = httpx.Client(
            base_url=settings.vault_addr,
            headers={"X-Vault-Token": token},
            timeout=5.0,
        )
        try:
            resp = self._client.get("/v1/sys/health")
            if resp.status_code not in (200, 429, 472, 473):
                raise ProviderUnavailable(f"vault health check failed: {resp.status_code}")
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"cannot reach vault at {settings.vault_addr}") from exc

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _c(self) -> httpx.Client:
        if self._client is None:
            raise ProviderUnavailable("vault provider not connected")
        return self._client

    def create_kek(self, kek_ref: str) -> None:
        resp = self._c().post(f"/v1/{settings.vault_mount}/keys/{kek_ref}", json={"type": "aes256-gcm96"})
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"vault key creation failed: {resp.text}")

    def wrap(self, kek_ref: str, plaintext: bytes) -> bytes:
        b64 = base64.b64encode(plaintext).decode()
        resp = self._c().post(f"/v1/{settings.vault_mount}/encrypt/{kek_ref}", json={"plaintext": b64})
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"vault encrypt failed: {resp.text}")
        return resp.json()["data"]["ciphertext"].encode()

    def unwrap(self, kek_ref: str, blob: bytes) -> bytes:
        ciphertext = blob.decode()
        resp = self._c().post(f"/v1/{settings.vault_mount}/decrypt/{kek_ref}", json={"ciphertext": ciphertext})
        if resp.status_code >= 400:
            raise DecryptFailed()
        return base64.b64decode(resp.json()["data"]["plaintext"])

    def destroy_kek(self, kek_ref: str) -> None:
        self._c().post(f"/v1/{settings.vault_mount}/keys/{kek_ref}/config", json={"deletion_allowed": True})
        self._c().delete(f"/v1/{settings.vault_mount}/keys/{kek_ref}")
