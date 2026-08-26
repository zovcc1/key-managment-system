from __future__ import annotations

from typing import Callable

from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session as DbSession

from keyring.core.errors import IdempotencyKeyMissingError
from keyring.models.idempotency import IdempotencyRecord


def run_idempotent(db: DbSession, *, scope: str, idempotency_key: str | None, fn: Callable[[], tuple[int, dict]]) -> tuple[int, dict]:
    """Destructive operations require an Idempotency-Key header (FR-10
    conventions). Replaying the same key returns the original result
    without re-executing."""
    if not idempotency_key:
        raise IdempotencyKeyMissingError()

    composite_key = f"{scope}:{idempotency_key}"
    existing = db.get(IdempotencyRecord, composite_key)
    if existing is not None:
        return existing.status_code, existing.response_body

    status_code, body = fn()
    record = IdempotencyRecord(key=composite_key, status_code=status_code, response_body=jsonable_encoder(body))
    db.add(record)
    db.commit()
    return status_code, record.response_body
