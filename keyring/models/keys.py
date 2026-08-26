from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keyring.db import Base
from keyring.models.enums import KeyState


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Kek(Base):
    __tablename__ = "keks"
    __table_args__ = (
        # FR-4.2: exactly one active KEK, enforced at the database level —
        # not application logic alone. A partial unique index on `state`
        # can only ever contain one row whose value is 'active'.
        Index(
            "ux_keks_single_active",
            "state",
            unique=True,
            sqlite_where=text("state = 'active'"),
            postgresql_where=text("state = 'active'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    state: Mapped[str] = mapped_column(String(16), default=KeyState.PENDING.value, index=True)
    # Opaque handle the active KeyProvider uses to locate this KEK's raw
    # material. Raw KEK bytes never live in this database (FR-6.1).
    provider_ref: Mapped[str] = mapped_column(String(128))
    provider_name: Mapped[str] = mapped_column(String(16))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subject_keys: Mapped[list["SubjectKey"]] = relationship(back_populates="kek", foreign_keys="SubjectKey.kek_id")


class SubjectKey(Base):
    __tablename__ = "subject_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    subject_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    kek_id: Mapped[str] = mapped_column(String(36), ForeignKey("keks.id"), index=True)
    algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    state: Mapped[str] = mapped_column(String(16), default=KeyState.PENDING.value, index=True)

    # Ciphertext blob (nonce || ciphertext || tag) produced by the active
    # KeyProvider wrapping the raw 256-bit subject key under the KEK.
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)

    record_count: Mapped[int] = mapped_column(Integer, default=0)
    last_access_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Destruction tombstone (crypto-shredding proof, section 3). The wrapped
    # key row is overwritten with these fields; ciphertext elsewhere in the
    # system is deliberately left in place.
    destroyed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    destroyed_approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    destroyed_record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    kek: Mapped["Kek"] = relationship(back_populates="subject_keys", foreign_keys=[kek_id])
