from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class IdempotencyRecord(Base):
    """Replay protection for destructive calls (destroy, erasure). Keyed on
    the client-supplied Idempotency-Key header; a replay returns the
    original response body and status without re-executing anything."""

    __tablename__ = "idempotency_records"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    status_code: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
