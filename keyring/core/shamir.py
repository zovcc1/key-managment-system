"""Shamir secret sharing over the root secret (FR-7). Backed by the
`shamir-mnemonic` library (SLIP-39) — not a hand-rolled GF(256) split."""
from __future__ import annotations

from shamir_mnemonic import combine_mnemonics, generate_mnemonics
from shamir_mnemonic.utils import MnemonicError

from keyring.core.crypto import constant_time_eq

THRESHOLD = 3
SHARES = 5


class ShamirError(Exception):
    pass


def split_root(master_secret: bytes) -> list[str]:
    """5 shares, threshold 3, single group."""
    groups = generate_mnemonics(
        group_threshold=1,
        groups=[(THRESHOLD, SHARES)],
        master_secret=master_secret,
    )
    return groups[0]


def recombine_root(shares: list[str]) -> bytes:
    """Recombine from any 3 valid shares; reject short or tampered
    combinations by propagating the library's own integrity checks."""
    if len(shares) < THRESHOLD:
        raise ShamirError(f"at least {THRESHOLD} shares are required, got {len(shares)}")
    try:
        return combine_mnemonics(shares)
    except MnemonicError as exc:
        raise ShamirError(str(exc)) from exc


def verify_recoverable(master_secret: bytes) -> bool:
    """FR-7.3: proves recoverability without revealing the root secret to
    the caller — only a boolean crosses this function's return boundary."""
    shares = split_root(master_secret)
    recovered = recombine_root(shares[:THRESHOLD])
    return constant_time_eq(recovered, master_secret)
