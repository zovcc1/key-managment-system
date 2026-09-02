from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from keyring.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Envelope(Base):
    """One encrypted item. Mirrors the versioned envelope shape from the
    spec exactly: v, alg, kek_id, subject_key_id, wrapped_dek, dek_nonce,
    data_nonce, ciphertext, tag, aad, created_at — plus the logical-location
    columns needed to reconstruct the AAD and to query/count records."""

    __tablename__ = "envelopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    v: Mapped[int] = mapped_column(Integer, default=1)
    alg: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")

    kek_id: Mapped[str] = mapped_column(String(36), ForeignKey("keks.id"))
    subject_key_id: Mapped[str] = mapped_column(String(36), ForeignKey("subject_keys.id"), index=True)

    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary)

    data_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    tag: Mapped[bytes] = mapped_column(LargeBinary)

    # Set only for streamed envelopes whose framed ciphertext lives on disk
    # (see keyring/core/blobstore.py) instead of in `ciphertext`, which is
    # then b"". Every other envelope leaves this null.
    blob_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Logical location — the exact inputs used to build the AAD at
    # encryption time. table/col/id/subject must match at decrypt time or
    # the AEAD tag verification fails (FR-3.2).
    table_name: Mapped[str] = mapped_column(String(128), index=True)
    column_name: Mapped[str] = mapped_column(String(128))
    record_id: Mapped[str] = mapped_column(String(128), index=True)
    subject_id: Mapped[str] = mapped_column(String(128), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    def aad(self) -> bytes:
        from keyring.core.crypto import build_aad

        return build_aad(self.table_name, self.column_name, self.record_id, self.subject_id)
