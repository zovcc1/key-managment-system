"""Append-only, hash-chained audit log (FR-8.3, FR-8.4)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.core.timeutil import aware
from keyring.models.audit import GENESIS_DIGEST, AuditLog


def _canonical_fields(entry_id: int, timestamp_iso: str, actor: str, operation: str,
                       key_id: str | None, item_id: str | None, result: str, details: dict) -> dict:
    return {
        "id": entry_id,
        "timestamp": timestamp_iso,
        "actor": actor,
        "operation": operation,
        "key_id": key_id,
        "item_id": item_id,
        "result": result,
        "details": details,
    }


def compute_digest(fields: dict, prev_digest: str) -> str:
    payload = dict(fields)
    payload["prev_digest"] = prev_digest
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def append(
    db: DbSession,
    *,
    actor: str,
    operation: str,
    result: str = "success",
    key_id: str | None = None,
    item_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    last = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    prev_digest = last.digest if last is not None else GENESIS_DIGEST

    row = AuditLog(
        actor=actor,
        operation=operation,
        key_id=key_id,
        item_id=item_id,
        result=result,
        details=details or {},
        prev_digest=prev_digest,
        digest="",  # filled below, after id is assigned by flush
    )
    db.add(row)
    db.flush()  # assigns row.id, row.timestamp default

    fields = _canonical_fields(
        row.id, aware(row.timestamp).isoformat(), row.actor, row.operation, row.key_id, row.item_id, row.result, row.details
    )
    row.digest = compute_digest(fields, prev_digest)
    db.flush()
    return row


@dataclass
class ChainBreak:
    entry_id: int
    expected_digest: str
    stored_digest: str


def verify_chain(db: DbSession) -> Optional[ChainBreak]:
    """Returns None if the chain is intact, or the first broken entry."""
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    running_prev = GENESIS_DIGEST
    for row in rows:
        if row.prev_digest != running_prev:
            return ChainBreak(entry_id=row.id, expected_digest=running_prev, stored_digest=row.prev_digest)
        fields = _canonical_fields(
            row.id, aware(row.timestamp).isoformat(), row.actor, row.operation, row.key_id, row.item_id, row.result, row.details
        )
        expected = compute_digest(fields, running_prev)
        if expected != row.digest:
            return ChainBreak(entry_id=row.id, expected_digest=expected, stored_digest=row.digest)
        running_prev = row.digest
    return None
