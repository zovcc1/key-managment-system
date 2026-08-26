"""Root-secret backup verification (FR-7.3). Reads the root secret the same
way the active file/env provider would, entirely server-side — the secret
itself never crosses the HTTP boundary, only a boolean does."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from keyring.config import settings
from keyring.core import crypto, runtime, shamir
from keyring.providers.base import ProviderUnavailable

_jobs: dict[str, dict] = {}


def _read_root_secret() -> bytes:
    """Shamir shares are split over the 256-bit *root wrapping key*, not
    the raw passphrase/env value — SLIP-39 requires a fixed-length secret,
    and recovery only needs to reconstruct the wrapping capability, not the
    literal human passphrase."""
    name = runtime.active_provider_name()
    if name == "file":
        passphrase = Path(settings.root_passphrase_file).read_bytes().strip()
        salt = Path(settings.root_salt_file).read_bytes()
        return crypto.argon2id_derive(passphrase, salt)
    if name == "env":
        raw = os.environ.get(settings.root_secret_env_var)
        if not raw:
            raise ProviderUnavailable(f"{settings.root_secret_env_var} is not set")
        secret = bytes.fromhex(raw.strip())
        return crypto.hkdf_derive(secret, crypto.HKDF_INFO_ROOT_WRAP)
    raise ProviderUnavailable(f"backup verification is not defined for provider '{name}'")


def start_verify_job() -> str:
    job_id = str(uuid.uuid4())
    try:
        secret = _read_root_secret()
        ok = shamir.verify_recoverable(secret)
        _jobs[job_id] = {"status": "completed", "ok": ok}
    except Exception as exc:  # noqa: BLE001
        _jobs[job_id] = {"status": "failed", "ok": False, "error": type(exc).__name__}
    return job_id


def get_job(job_id: str) -> dict | None:
    return _jobs.get(job_id)
