"""KeyProvider interface (FR-6.3).

Every KEK operation the rest of the codebase needs goes through this
interface: create, wrap, unwrap, destroy. Encryption logic (envelope
building, AAD, DEK handling) never touches provider internals, so any
implementation is swappable without touching any encryption logic. The
test suite runs unmodified against at least two implementations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class ProviderUnavailable(RuntimeError):
    pass


class KeyProvider(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True if the provider can be reached/unlocked right now."""

    @abstractmethod
    def connect(self) -> None:
        """Open the provider connection (unlock root secret, open handle)."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the provider handle and zero any in-memory root material."""

    @abstractmethod
    def create_kek(self, kek_ref: str) -> None:
        """Generate a fresh 256-bit KEK and store it under `kek_ref`."""

    @abstractmethod
    def wrap(self, kek_ref: str, plaintext: bytes) -> bytes:
        """Wrap `plaintext` (a subject key) under the KEK at `kek_ref`.
        Returns an opaque blob (nonce || ciphertext || tag)."""

    @abstractmethod
    def unwrap(self, kek_ref: str, blob: bytes) -> bytes:
        """Reverse of `wrap`. Raises DecryptFailed on any failure."""

    @abstractmethod
    def destroy_kek(self, kek_ref: str) -> None:
        """Best-effort removal of the KEK material. Callers must have
        already verified there are no remaining dependents."""
