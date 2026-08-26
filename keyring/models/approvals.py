from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base
from keyring.models.enums import ApprovalStatus


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Approval(Base):
    """Two-party approval record (FR-9.3). `requested_by` and
    `approved_by` must differ — enforced by comparing actor identity in the
    service layer, never by client-side omission."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    operation: Mapped[str] = mapped_column(String(32), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)

    requested_by: Mapped[str] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[str] = mapped_column(String(16), default=ApprovalStatus.PENDING.value, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
