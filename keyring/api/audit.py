from __future__ import annotations

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_db, get_locale, require_scope
from keyring.core import audit as audit_core
from keyring.core.timeutil import aware
from keyring.i18n import t
from keyring.models.audit import AuditLog

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _row_public(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "timestamp": aware(row.timestamp).isoformat(),
        "actor": row.actor,
        "operation": row.operation,
        "keyId": row.key_id,
        "itemId": row.item_id,
        "result": row.result,
        "details": row.details,
    }


@router.get("")
def list_audit(
    actor: str | None = None,
    operation: str | None = None,
    keyId: str | None = None,
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = None,
    cursor: int | None = None,
    limit: int = 50,
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(require_scope("audit_read")),
):
    q = select(AuditLog).order_by(AuditLog.id.asc())
    if actor:
        q = q.where(AuditLog.actor == actor)
    if operation:
        q = q.where(AuditLog.operation == operation)
    if keyId:
        q = q.where(AuditLog.key_id == keyId)
    if from_:
        q = q.where(AuditLog.timestamp >= datetime.fromisoformat(from_))
    if to:
        q = q.where(AuditLog.timestamp <= datetime.fromisoformat(to))
    if cursor:
        q = q.where(AuditLog.id > cursor)
    q = q.limit(limit)

    rows = db.execute(q).scalars().all()
    next_cursor = rows[-1].id if rows else None
    return {"items": [_row_public(r) for r in rows], "nextCursor": next_cursor}


@router.post("/verify")
def verify(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("audit_read"))):
    result = audit_core.verify_chain(db)
    if result is None:
        return {"ok": True}
    return {"ok": False, "firstBrokenEntry": result.entry_id, "expectedDigest": result.expected_digest, "storedDigest": result.stored_digest}


@router.get("/export.csv")
def export_csv(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("audit_read")), locale: str = Depends(get_locale)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([t("csv.actor", locale), t("csv.operation", locale), t("csv.key_id", locale), t("csv.item_id", locale), t("csv.result", locale), t("csv.timestamp", locale)])
    for r in rows:
        writer.writerow([r.actor, r.operation, r.key_id or "", r.item_id or "", r.result, aware(r.timestamp).isoformat()])
    return Response(content=buf.getvalue(), media_type="text/csv", headers={"Content-Language": locale})


@router.get("/actors")
def actors(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("audit_read"))):
    rows = db.execute(select(AuditLog.actor).distinct()).scalars().all()
    return {"actors": sorted(rows)}


@router.get("/operations")
def operations(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("audit_read"))):
    rows = db.execute(select(AuditLog.operation).distinct()).scalars().all()
    return {"operations": sorted(rows)}
