from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RewrapJob(Base):
    """Resumable batch rewrap of subject keys from one KEK to another
    (FR-5.3). `cursor` is the last subject_key.id processed, ordered by id,
    so a killed job resumes with no gap and no duplicate (subject keys are
    processed in strictly increasing id order and each rewrap is itself
    idempotent per subject key)."""

    __tablename__ = "rewrap_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    from_kek_id: Mapped[str] = mapped_column(String(36), ForeignKey("keks.id"))
    to_kek_id: Mapped[str] = mapped_column(String(36), ForeignKey("keks.id"))

    state: Mapped[str] = mapped_column(String(16), default="running", index=True)  # running|paused|completed|failed
    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)
    cursor: Mapped[str | None] = mapped_column(String(36), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class RewrapFailure(Base):
    __tablename__ = "rewrap_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(36), ForeignKey("rewrap_jobs.id"), index=True)
    item_id: Mapped[str] = mapped_column(String(36))  # subject_key id
    subject_key_id: Mapped[str] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(String(256))
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
