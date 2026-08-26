from __future__ import annotations

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Populate the process environment from .env too, so raw os.environ reads
# elsewhere (e.g. the certificate signing key) see the same values as the
# pydantic-parsed Settings fields below, from one file.
load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KEYRING_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./keyring.db"

    # Active key provider: file | env | vault | kms
    provider: str = "file"

    # File provider
    root_passphrase_file: str = "./data/root.passphrase"
    root_salt_file: str = "./data/root.salt"

    # Env provider
    root_secret_env_var: str = "KEYRING_ROOT_SECRET"

    # Local encrypted KEK material store (used by file/env providers).
    # This lives outside the application database, per FR-6.1.
    kek_store_path: str = "./data/kek_store.enc.json"

    # Vault provider
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token_env_var: str = "KEYRING_VAULT_TOKEN"
    vault_mount: str = "transit"

    # KMS provider (generic envelope-encryption HTTP endpoint)
    kms_endpoint: str = "http://127.0.0.1:9000"
    kms_token_env_var: str = "KEYRING_KMS_TOKEN"

    # Argon2id parameters (FR-1.3) — do not lower without a security review.
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 64 * 1024  # 64 MiB
    argon2_parallelism: int = 4

    rotation_interval_days: int = 90
    alert_threshold_days: int = 100

    signing_key_env_var: str = "KEYRING_CERT_SIGNING_KEY"

    session_ttl_seconds: int = 3600


settings = Settings()
