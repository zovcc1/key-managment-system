from keyring.providers.base import KeyProvider, ProviderUnavailable
from keyring.providers.env_provider import EnvKeyProvider
from keyring.providers.file_provider import FileKeyProvider
from keyring.providers.kms_provider import KMSKeyProvider
from keyring.providers.vault_provider import VaultKeyProvider

PROVIDERS: dict[str, type[KeyProvider]] = {
    "file": FileKeyProvider,
    "env": EnvKeyProvider,
    "vault": VaultKeyProvider,
    "kms": KMSKeyProvider,
}


def get_provider(name: str) -> KeyProvider:
    try:
        cls = PROVIDERS[name]
    except KeyError as exc:
        raise ProviderUnavailable(f"unknown provider '{name}'") from exc
    return cls()


__all__ = ["KeyProvider", "ProviderUnavailable", "PROVIDERS", "get_provider"]
