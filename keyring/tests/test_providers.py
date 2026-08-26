"""FR-6.3: the KeyProvider contract shared by all four implementations —
wrap/unwrap round trip, unwrap under the wrong ref fails uniformly, and
is_available/connect/disconnect behave sanely. Vault and KMS run against a
mocked HTTP transport (httpx.MockTransport); no live backend is needed."""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

from keyring.config import settings
from keyring.core.crypto import DecryptFailed
from keyring.providers import kms_provider as kms_module
from keyring.providers import vault_provider as vault_module
from keyring.providers.base import ProviderUnavailable
from keyring.providers.env_provider import EnvKeyProvider
from keyring.providers.file_provider import FileKeyProvider
from keyring.providers.kms_provider import KMSKeyProvider
from keyring.providers.vault_provider import VaultKeyProvider


class _FakeHttpxModule:
    """Drop-in replacement for the `httpx` name inside a provider module: a
    real httpx.Client wired to a MockTransport, so no real socket is ever
    opened, plus the real exception types the provider's except clauses
    reference."""

    HTTPError = httpx.HTTPError

    def __init__(self, handler):
        self._handler = handler

    def Client(self, **kwargs):
        kwargs.pop("timeout", None)
        return httpx.Client(transport=httpx.MockTransport(self._handler), **kwargs)


def _vault_handler(created_keys: set[str]):
    prefix = f"/v1/{settings.vault_mount}/"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/sys/health":
            return httpx.Response(200, json={"initialized": True, "sealed": False})
        if path.startswith(prefix + "keys/") and path.endswith("/config"):
            return httpx.Response(200, json={})
        if path.startswith(prefix + "keys/"):
            ref = path[len(prefix + "keys/"):]
            if request.method == "POST":
                created_keys.add(ref)
                return httpx.Response(200, json={"data": {}})
            if request.method == "DELETE":
                created_keys.discard(ref)
                return httpx.Response(204)
        if path.startswith(prefix + "encrypt/"):
            ref = path[len(prefix + "encrypt/"):]
            if ref not in created_keys:
                return httpx.Response(400, json={"errors": ["no such key"]})
            body = json.loads(request.content)
            ct = f"vault:v1:{ref}:{body['plaintext']}"
            return httpx.Response(200, json={"data": {"ciphertext": ct}})
        if path.startswith(prefix + "decrypt/"):
            ref = path[len(prefix + "decrypt/"):]
            if ref not in created_keys:
                return httpx.Response(400, json={"errors": ["no such key"]})
            body = json.loads(request.content)
            parts = body["ciphertext"].split(":", 3)
            if len(parts) != 4 or parts[2] != ref:
                return httpx.Response(400, json={"errors": ["ciphertext does not match key"]})
            return httpx.Response(200, json={"data": {"plaintext": parts[3]}})
        return httpx.Response(404, json={"errors": ["not found"]})

    return handler


def _kms_handler(created_keys: set[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/keys" and request.method == "POST":
            body = json.loads(request.content)
            created_keys.add(body["key_id"])
            return httpx.Response(200, json={})
        if path == "/encrypt":
            body = json.loads(request.content)
            if body["key_id"] not in created_keys:
                return httpx.Response(400, json={"error": "no such key"})
            ct = f"kms:{body['key_id']}:{body['plaintext']}"
            return httpx.Response(200, json={"ciphertext": ct})
        if path == "/decrypt":
            body = json.loads(request.content)
            if body["key_id"] not in created_keys:
                return httpx.Response(400, json={"error": "no such key"})
            parts = body["ciphertext"].split(":", 2)
            if len(parts) != 3 or parts[1] != body["key_id"]:
                return httpx.Response(400, json={"error": "wrong key"})
            return httpx.Response(200, json={"plaintext": parts[2]})
        if path.startswith("/keys/") and request.method == "DELETE":
            created_keys.discard(path.removeprefix("/keys/"))
            return httpx.Response(204)
        return httpx.Response(404, json={"error": "not found"})

    return handler


@pytest.fixture(params=["file", "env", "vault", "kms"])
def contract_provider(request, tmp_path, monkeypatch):
    kind = request.param

    if kind == "file":
        monkeypatch.setattr(settings, "root_passphrase_file", str(tmp_path / "root.passphrase"))
        monkeypatch.setattr(settings, "root_salt_file", str(tmp_path / "root.salt"))
        monkeypatch.setattr(settings, "kek_store_path", str(tmp_path / "kek_store.enc.json"))
        Path(settings.root_passphrase_file).write_text("contract test root passphrase")
        os.chmod(settings.root_passphrase_file, 0o400)
        p = FileKeyProvider()

    elif kind == "env":
        monkeypatch.setattr(settings, "kek_store_path", str(tmp_path / "kek_store_env.enc.json"))
        monkeypatch.setenv(settings.root_secret_env_var, os.urandom(32).hex())
        p = EnvKeyProvider()

    elif kind == "vault":
        monkeypatch.setenv(settings.vault_token_env_var, "unit-test-vault-token")
        monkeypatch.setattr(vault_module, "httpx", _FakeHttpxModule(_vault_handler(set())))
        p = VaultKeyProvider()

    else:  # kms
        monkeypatch.setenv(settings.kms_token_env_var, "unit-test-kms-token")
        monkeypatch.setattr(kms_module, "httpx", _FakeHttpxModule(_kms_handler(set())))
        p = KMSKeyProvider()

    p.connect()
    yield p
    p.disconnect()


def test_is_available_true_once_prerequisites_are_met(contract_provider):
    assert contract_provider.is_available() is True


def test_create_wrap_unwrap_round_trip(contract_provider):
    contract_provider.create_kek("kek-a")
    plaintext = os.urandom(32)
    blob = contract_provider.wrap("kek-a", plaintext)
    assert contract_provider.unwrap("kek-a", blob) == plaintext


def test_wrap_output_differs_from_plaintext(contract_provider):
    contract_provider.create_kek("kek-a")
    plaintext = b"a" * 32
    blob = contract_provider.wrap("kek-a", plaintext)
    assert blob != plaintext


def test_unwrap_under_wrong_ref_fails(contract_provider):
    """Wrapping under one KEK and unwrapping under a *different* existing
    KEK must fail — never silently return the wrong plaintext, never
    silently succeed."""
    contract_provider.create_kek("kek-a")
    contract_provider.create_kek("kek-b")
    blob = contract_provider.wrap("kek-a", b"secret payload")
    with pytest.raises(Exception):
        contract_provider.unwrap("kek-b", blob)


def test_destroy_kek_removes_key_material(contract_provider):
    contract_provider.create_kek("kek-a")
    blob = contract_provider.wrap("kek-a", b"secret payload")
    contract_provider.destroy_kek("kek-a")
    with pytest.raises(Exception):
        contract_provider.unwrap("kek-a", blob)


def test_disconnect_then_wrap_raises_provider_unavailable(contract_provider):
    contract_provider.create_kek("kek-a")
    blob = contract_provider.wrap("kek-a", b"secret payload")
    contract_provider.disconnect()
    with pytest.raises(ProviderUnavailable):
        contract_provider.wrap("kek-a", b"more data")
    with pytest.raises(ProviderUnavailable):
        contract_provider.unwrap("kek-a", blob)


# --- vault/kms-specific: unwrap under wrong ref surfaces DecryptFailed -----

def test_vault_unwrap_wrong_ref_raises_decrypt_failed(monkeypatch):
    monkeypatch.setenv(settings.vault_token_env_var, "unit-test-vault-token")
    monkeypatch.setattr(vault_module, "httpx", _FakeHttpxModule(_vault_handler(set())))
    p = VaultKeyProvider()
    p.connect()
    try:
        p.create_kek("kek-a")
        p.create_kek("kek-b")
        blob = p.wrap("kek-a", b"secret payload")
        with pytest.raises(DecryptFailed):
            p.unwrap("kek-b", blob)
    finally:
        p.disconnect()


def test_kms_unwrap_wrong_ref_raises_decrypt_failed(monkeypatch):
    monkeypatch.setenv(settings.kms_token_env_var, "unit-test-kms-token")
    monkeypatch.setattr(kms_module, "httpx", _FakeHttpxModule(_kms_handler(set())))
    p = KMSKeyProvider()
    p.connect()
    try:
        p.create_kek("kek-a")
        p.create_kek("kek-b")
        blob = p.wrap("kek-a", b"secret payload")
        with pytest.raises(DecryptFailed):
            p.unwrap("kek-b", blob)
    finally:
        p.disconnect()


# --- connect() prerequisites missing ---------------------------------------

def test_file_provider_connect_fails_without_passphrase_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "root_passphrase_file", str(tmp_path / "missing.passphrase"))
    monkeypatch.setattr(settings, "root_salt_file", str(tmp_path / "root.salt"))
    p = FileKeyProvider()
    with pytest.raises(ProviderUnavailable):
        p.connect()
    assert p.is_available() is False


def test_env_provider_connect_fails_without_env_var(monkeypatch):
    monkeypatch.delenv(settings.root_secret_env_var, raising=False)
    p = EnvKeyProvider()
    with pytest.raises(ProviderUnavailable):
        p.connect()
    assert p.is_available() is False


def test_vault_provider_connect_fails_without_token_env_var(monkeypatch):
    monkeypatch.delenv(settings.vault_token_env_var, raising=False)
    monkeypatch.setattr(vault_module, "httpx", _FakeHttpxModule(_vault_handler(set())))
    p = VaultKeyProvider()
    with pytest.raises(ProviderUnavailable):
        p.connect()


def test_kms_provider_connect_fails_without_token_env_var(monkeypatch):
    monkeypatch.delenv(settings.kms_token_env_var, raising=False)
    monkeypatch.setattr(kms_module, "httpx", _FakeHttpxModule(_kms_handler(set())))
    p = KMSKeyProvider()
    with pytest.raises(ProviderUnavailable):
        p.connect()


def test_vault_is_available_false_when_health_check_unreachable(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(vault_module, "httpx", _FakeHttpxModule(handler))
    p = VaultKeyProvider()
    assert p.is_available() is False


def test_kms_is_available_false_when_health_check_unreachable(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(kms_module, "httpx", _FakeHttpxModule(handler))
    p = KMSKeyProvider()
    assert p.is_available() is False
