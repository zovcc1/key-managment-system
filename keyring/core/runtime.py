"""Process-wide runtime state: which KeyProvider is currently connected.

There is exactly one live provider connection per process — analogous to a
hardware token being inserted or removed — shared by all operator sessions.
Locking (`DELETE /api/session`) disconnects it for everyone, which is the
intended behaviour for a service guarding a single root secret.
"""
from __future__ import annotations

from keyring.providers import get_provider
from keyring.providers.base import KeyProvider, ProviderUnavailable

_provider: KeyProvider | None = None
_provider_name: str = "file"


def active_provider_name() -> str:
    return _provider_name


def set_active_provider_name(name: str) -> None:
    global _provider_name
    _provider_name = name


def is_connected() -> bool:
    return _provider is not None


def connect(name: str | None = None) -> KeyProvider:
    global _provider, _provider_name
    target = name or _provider_name
    provider = get_provider(target)
    provider.connect()
    _provider = provider
    _provider_name = target
    return provider


def disconnect() -> None:
    global _provider
    if _provider is not None:
        _provider.disconnect()
        _provider = None


def get_connected_provider() -> KeyProvider:
    if _provider is None:
        raise ProviderUnavailable("no provider connected — open a session first")
    return _provider
