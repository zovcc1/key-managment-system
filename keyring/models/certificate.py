from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ErasureCertificate(Base):
    """Signed deletion certificate produced by a subject erasure (section
    3). `payload` is the exact canonical JSON that `signature` covers."""

    __tablename__ = "erasure_certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    subject_id: Mapped[str] = mapped_column(String(128), index=True)
    subject_key_id: Mapped[str] = mapped_column(String(36))
    records_unreadable: Mapped[int] = mapped_column(Integer)
    tables_affected: Mapped[list] = mapped_column(JSON)
    operator: Mapped[str] = mapped_column(String(128))
    approval_chain: Mapped[list] = mapped_column(JSON)
    payload: Mapped[dict] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
