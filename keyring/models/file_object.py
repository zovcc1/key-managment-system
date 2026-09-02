from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class FileObject(Base):
    """Metadata for one uploaded file. The plaintext never lands here or in
    any other database row — only what is needed to list/inspect the file
    and to locate its envelope and blob. `id` is generated up front and
    reused as the envelope's `record_id` and the blob's ref, binding all
    three to the same file identity."""

    __tablename__ = "file_objects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)

    # SHA-256 of the ciphertext blob (not the plaintext) — at-rest integrity
    # check without creating a plaintext-guessing oracle that would survive
    # crypto-shredding.
    ciphertext_sha256: Mapped[str] = mapped_column(String(64))

    envelope_id: Mapped[str] = mapped_column(String(36), ForeignKey("envelopes.id"), unique=True, index=True)
    subject_id: Mapped[str] = mapped_column(String(128), index=True)

    uploaded_by: Mapped[str] = mapped_column(String(128))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
