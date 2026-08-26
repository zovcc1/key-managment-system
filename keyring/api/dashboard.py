from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db
from keyring.api.serializers import kek_age_days
from keyring.core import runtime
from keyring.core.audit import verify_chain
from keyring.core.errors import NotFoundError
from keyring.models.audit import DecryptFailureLog
from keyring.models.enums import KeyState
from keyring.models.keys import Kek, SubjectKey
from keyring.models.envelope import Envelope
from keyring.models.approvals import Approval
from keyring.models.enums import ApprovalStatus
from keyring.models.settings_model import Alert, SystemSettings

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    active_kek = db.execute(select(Kek).where(Kek.state == KeyState.ACTIVE.value)).scalar_one_or_none()
    settings_row = db.get(SystemSettings, 1)
    rotation_deadline_days = settings_row.rotation_interval_days if settings_row else 90

    active_kek_public = None
    if active_kek is not None:
        age = kek_age_days(active_kek)
        active_kek_public = {
            "id": active_kek.id,
            "algorithm": active_kek.algorithm,
            "ageDays": age,
            "rotationDeadlineDays": max(rotation_deadline_days - age, 0),
        }

    tile_counts = {
        "keks": db.execute(select(func.count()).select_from(Kek)).scalar_one(),
        "subjectKeys": db.execute(select(func.count()).select_from(SubjectKey)).scalar_one(),
        "encryptedItems": db.execute(select(func.count()).select_from(Envelope)).scalar_one(),
        "pendingApprovals": db.execute(
            select(func.count()).select_from(Approval).where(Approval.status == ApprovalStatus.PENDING.value)
        ).scalar_one(),
    }

    chain_break = verify_chain(db)
    health_strip = [
        {"label": "provider_connected", "status": "ok" if runtime.is_connected() else "down"},
        {"label": "audit_chain", "status": "ok" if chain_break is None else "broken"},
        {"label": "active_kek", "status": "ok" if active_kek is not None else "missing"},
    ]

    return {"activeKek": active_kek_public, "tileCounts": tile_counts, "healthStrip": health_strip}


@router.get("/metrics/decrypt-failures")
def decrypt_failures(window: str = Query(default="24h"), db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    hours = int(window.rstrip("h")) if window.endswith("h") else 24
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(select(DecryptFailureLog).where(DecryptFailureLog.timestamp >= since)).scalars().all()

    buckets: dict[str, int] = {}
    for row in rows:
        bucket = row.timestamp.strftime("%Y-%m-%dT%H:00:00")
        buckets[bucket] = buckets.get(bucket, 0) + 1

    return {"window": window, "buckets": [{"hour": h, "count": c} for h, c in sorted(buckets.items())]}


@router.post("/alerts/{alert_id}/ack")
def ack_alert(alert_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise NotFoundError(target="alert")
    alert.acknowledged = True
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = current.operator.name
    db.commit()
    return {"id": alert.id, "acknowledged": True}
