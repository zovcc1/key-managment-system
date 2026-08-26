"""FR-7 recovery drill: Shamir split/recombine over the root secret, plus
the backup-verification job that proves recoverability without ever
returning the secret itself across the boundary."""
from __future__ import annotations

import os

import pytest

from keyring.config import settings
from keyring.core import backup, crypto, shamir
from keyring.providers.base import ProviderUnavailable


def test_split_produces_five_shares():
    secret = crypto.random_bytes(32)
    shares = shamir.split_root(secret)
    assert len(shares) == shamir.SHARES == 5


def test_recombine_from_exactly_threshold_shares_recovers_secret():
    secret = crypto.random_bytes(32)
    shares = shamir.split_root(secret)
    recovered = shamir.recombine_root(shares[: shamir.THRESHOLD])
    assert recovered == secret


def test_recombine_from_any_three_of_five_shares_recovers_secret():
    secret = crypto.random_bytes(32)
    shares = shamir.split_root(secret)
    # A different subset than the first-N one, to prove any 3-of-5 works.
    subset = [shares[0], shares[2], shares[4]]
    assert shamir.recombine_root(subset) == secret


def test_recombine_rejects_fewer_than_threshold_shares():
    secret = crypto.random_bytes(32)
    shares = shamir.split_root(secret)
    with pytest.raises(shamir.ShamirError):
        shamir.recombine_root(shares[:2])


def test_recombine_rejects_zero_shares():
    with pytest.raises(shamir.ShamirError):
        shamir.recombine_root([])


def test_recombine_rejects_tampered_share():
    secret = crypto.random_bytes(32)
    shares = shamir.split_root(secret)
    chosen = list(shares[: shamir.THRESHOLD])
    words = chosen[0].split(" ")
    # Corrupt a word in the middle of the mnemonic — SLIP-39 has its own
    # checksum, so this must be rejected rather than silently recombining
    # into garbage.
    words[len(words) // 2] = "abandon" if words[len(words) // 2] != "abandon" else "ability"
    chosen[0] = " ".join(words)
    with pytest.raises(shamir.ShamirError):
        shamir.recombine_root(chosen)


def test_recombine_rejects_shares_from_two_different_secrets():
    secret_a = crypto.random_bytes(32)
    secret_b = crypto.random_bytes(32)
    shares_a = shamir.split_root(secret_a)
    shares_b = shamir.split_root(secret_b)
    mixed = [shares_a[0], shares_a[1], shares_b[2]]
    with pytest.raises(shamir.ShamirError):
        shamir.recombine_root(mixed)


def test_verify_recoverable_returns_true_for_a_freshly_split_secret():
    secret = crypto.random_bytes(32)
    assert shamir.verify_recoverable(secret) is True


def test_verify_recoverable_only_returns_a_bool_never_the_secret():
    secret = crypto.random_bytes(32)
    result = shamir.verify_recoverable(secret)
    assert isinstance(result, bool)


# --- backup.start_verify_job / get_job, both providers ---------------------

def test_backup_verify_job_ok_for_file_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "root_passphrase_file", str(tmp_path / "root.passphrase"))
    monkeypatch.setattr(settings, "root_salt_file", str(tmp_path / "root.salt"))
    from pathlib import Path

    Path(settings.root_passphrase_file).write_text("backup drill passphrase")
    os.chmod(settings.root_passphrase_file, 0o400)

    from keyring.core import runtime
    runtime.connect("file")
    try:
        job_id = backup.start_verify_job()
        job = backup.get_job(job_id)
        assert job["status"] == "completed"
        assert job["ok"] is True
    finally:
        runtime.disconnect()


def test_backup_verify_job_ok_for_env_provider(monkeypatch):
    monkeypatch.setenv(settings.root_secret_env_var, os.urandom(32).hex())

    from keyring.core import runtime
    runtime.connect("env")
    try:
        job_id = backup.start_verify_job()
        job = backup.get_job(job_id)
        assert job["status"] == "completed"
        assert job["ok"] is True
    finally:
        runtime.disconnect()


def test_backup_verify_job_fails_gracefully_when_env_secret_missing(monkeypatch):
    monkeypatch.delenv(settings.root_secret_env_var, raising=False)

    from keyring.core import runtime
    # _read_root_secret dispatches on the active provider *name*, not on
    # whether a provider is actually connected — set it directly so the
    # env-provider code path runs with the env var deliberately absent.
    monkeypatch.setattr(runtime, "_provider_name", "env")

    job_id = backup.start_verify_job()
    job = backup.get_job(job_id)
    assert job["status"] == "failed"
    assert job["ok"] is False


def test_get_job_returns_none_for_unknown_job_id():
    assert backup.get_job("does-not-exist") is None
