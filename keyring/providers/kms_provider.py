from __future__ import annotations

import base64
import os

import httpx

from keyring.config import settings
from keyring.core.crypto import DecryptFailed
from keyring.providers.base import KeyProvider, ProviderUnavailable


class KMSKeyProvider(KeyProvider):
    """Generic cloud-KMS envelope-encryption adapter. Speaks a minimal JSON
    HTTP contract (`POST /keys`, `POST /encrypt`, `POST /decrypt`,
    `DELETE /keys/{id}`) so the same code path works behind any KMS that a
    thin sidecar or the vendor SDK exposes this way. Wiring a specific cloud
    KMS in production means pointing `kms_endpoint` at that adapter — no
    changes to encryption logic (FR-6.3)."""

    name = "kms"

    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    def _token(self) -> str:
        token = os.environ.get(settings.kms_token_env_var)
        if not token:
            raise ProviderUnavailable(f"{settings.kms_token_env_var} is not set")
        return token

    def is_available(self) -> bool:
        try:
            client = httpx.Client(base_url=settings.kms_endpoint, timeout=2.0)
            resp = client.get("/healthz")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def connect(self) -> None:
        token = self._token()
        self._client = httpx.Client(
            base_url=settings.kms_endpoint,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        try:
            resp = self._client.get("/healthz")
            if resp.status_code != 200:
                raise ProviderUnavailable(f"kms health check failed: {resp.status_code}")
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"cannot reach kms at {settings.kms_endpoint}") from exc

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _c(self) -> httpx.Client:
        if self._client is None:
            raise ProviderUnavailable("kms provider not connected")
        return self._client

    def create_kek(self, kek_ref: str) -> None:
        resp = self._c().post("/keys", json={"key_id": kek_ref})
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"kms key creation failed: {resp.text}")

    def wrap(self, kek_ref: str, plaintext: bytes) -> bytes:
        resp = self._c().post("/encrypt", json={"key_id": kek_ref, "plaintext": base64.b64encode(plaintext).decode()})
        if resp.status_code >= 400:
            raise ProviderUnavailable(f"kms encrypt failed: {resp.text}")
        return resp.json()["ciphertext"].encode()

    def unwrap(self, kek_ref: str, blob: bytes) -> bytes:
        resp = self._c().post("/decrypt", json={"key_id": kek_ref, "ciphertext": blob.decode()})
        if resp.status_code >= 400:
            raise DecryptFailed()
        return base64.b64decode(resp.json()["plaintext"])

    def destroy_kek(self, kek_ref: str) -> None:
        self._c().delete(f"/keys/{kek_ref}")
