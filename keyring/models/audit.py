from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


GENESIS_DIGEST = "0" * 64


class AuditLog(Base):
    """Append-only, hash-chained audit log (FR-8.3). Each row's `digest`
    covers its own fields plus the previous row's digest, so tampering with
    any historical entry is detectable by `verify_chain`."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    operation: Mapped[str] = mapped_column(String(32), index=True)
    key_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    item_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[str] = mapped_column(String(16))  # success | failure
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    prev_digest: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64), index=True)


class DecryptFailureLog(Base):
    """Failed decryption attempts, logged distinctly and queryable per
    FR-8.5 — for auditor review only. The requester-facing API response
    (DECRYPT_FAILED) never varies based on this data."""

    __tablename__ = "decrypt_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    envelope_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    reason_code: Mapped[str] = mapped_column(String(32))
