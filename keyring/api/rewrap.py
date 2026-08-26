from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_db, require_scope
from keyring.core.errors import NotFoundError
from keyring.core.service import KeyringService
from keyring.api.deps import get_service
from keyring.core.timeutil import aware
from keyring.models.rewrap import RewrapFailure, RewrapJob

router = APIRouter(prefix="/api/rewrap", tags=["rewrap"])


def _job_public(job: RewrapJob) -> dict:
    elapsed = max((datetime.now(timezone.utc) - aware(job.created_at)).total_seconds(), 0.001)
    rate = job.done / elapsed
    remaining = max(job.total - job.done, 0)
    eta_seconds = round(remaining / rate, 1) if rate > 0 else None
    return {
        "jobId": job.id,
        "from": job.from_kek_id,
        "to": job.to_kek_id,
        "done": job.done,
        "total": job.total,
        "state": job.state,
        "rate": round(rate, 2),
        "eta": eta_seconds,
    }


@router.get("/jobs/current")
def current_job(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("rewrap_manage"))):
    job = db.execute(select(RewrapJob).order_by(RewrapJob.created_at.desc()).limit(1)).scalar_one_or_none()
    if job is None:
        raise NotFoundError(target="rewrap_job")
    return _job_public(job)


@router.post("/jobs/{job_id}/pause")
def pause(job_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("rewrap_manage"))):
    job = db.get(RewrapJob, job_id)
    if job is None:
        raise NotFoundError(target="rewrap_job")
    job.state = "paused"
    db.commit()
    return _job_public(job)


@router.post("/jobs/{job_id}/resume")
def resume(job_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("rewrap_manage"))):
    job = db.get(RewrapJob, job_id)
    if job is None:
        raise NotFoundError(target="rewrap_job")
    job.state = "running"
    db.commit()
    return _job_public(job)


@router.get("/jobs/{job_id}/failures")
def failures(
    job_id: str, page: int = 1, page_size: int = Query(default=20, alias="pageSize"),
    db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("rewrap_manage")),
):
    q = select(RewrapFailure).where(RewrapFailure.job_id == job_id).order_by(RewrapFailure.id.asc())
    rows = db.execute(q).scalars().all()
    start = (page - 1) * page_size
    page_rows = rows[start : start + page_size]
    return {
        "items": [
            {"itemId": r.item_id, "subjectKeyId": r.subject_key_id, "reason": r.reason, "attempts": r.attempts, "resolved": r.resolved}
            for r in page_rows
        ],
        "page": page,
        "pageSize": page_size,
        "total": len(rows),
    }


@router.post("/jobs/{job_id}/failures/{item_id}/retry")
def retry_failure(job_id: str, item_id: str, service: KeyringService = Depends(get_service), current: CurrentSession = Depends(require_scope("rewrap_manage"))):
    failure = service.rewrap_retry_failure(job_id, item_id)
    service.db.commit()
    return {"itemId": failure.item_id, "resolved": failure.resolved, "attempts": failure.attempts, "reason": failure.reason}
