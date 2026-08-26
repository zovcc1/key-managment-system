from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_db, get_locale, require_scope
from keyring.api.schemas import SettingsPatchBody
from keyring.core import backup, runtime
from keyring.core.errors import NotFoundError
from keyring.core.threat_model import render as render_threat_model
from keyring.models.settings_model import SystemSettings
from keyring.providers import PROVIDERS

router = APIRouter(prefix="/api", tags=["settings"])


def _get_settings(db: DbSession) -> SystemSettings:
    row = db.get(SystemSettings, 1)
    if row is None:
        row = SystemSettings(id=1)
        db.add(row)
        db.commit()
    return row


@router.get("/settings")
def get_settings(db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("settings_write"))):
    row = _get_settings(db)
    return {"rotationIntervalDays": row.rotation_interval_days, "alertThreshold": row.alert_threshold_days, "activeProvider": row.active_provider}


@router.patch("/settings")
def patch_settings(body: SettingsPatchBody, db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("settings_write"))):
    row = _get_settings(db)
    if body.rotationIntervalDays is not None:
        row.rotation_interval_days = body.rotationIntervalDays
    if body.alertThreshold is not None:
        row.alert_threshold_days = body.alertThreshold
    db.commit()
    return {"rotationIntervalDays": row.rotation_interval_days, "alertThreshold": row.alert_threshold_days, "activeProvider": row.active_provider}


@router.get("/providers")
def list_providers(current: CurrentSession = Depends(require_scope("settings_write"))):
    items = []
    for name, cls in PROVIDERS.items():
        try:
            available = cls().is_available()
        except Exception:  # noqa: BLE001
            available = False
        items.append({"id": name, "available": available, "active": name == runtime.active_provider_name() and runtime.is_connected()})
    return {"items": items}


@router.post("/providers/{provider_id}/activate")
def activate_provider(provider_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("provider_activate"))):
    if provider_id not in PROVIDERS:
        raise NotFoundError(target="provider")
    runtime.disconnect()
    runtime.connect(provider_id)
    row = _get_settings(db)
    row.active_provider = provider_id
    db.commit()
    return {"active": provider_id}


@router.post("/backup/verify")
def backup_verify(current: CurrentSession = Depends(require_scope("settings_write"))):
    job_id = backup.start_verify_job()
    return {"jobId": job_id}


@router.get("/backup/verify/{job_id}")
def backup_verify_status(job_id: str, current: CurrentSession = Depends(require_scope("settings_write"))):
    job = backup.get_job(job_id)
    if job is None:
        raise NotFoundError(target="backup_job")
    return job


@router.get("/threat-model")
def threat_model(locale: str = Depends(get_locale)):
    return render_threat_model(locale)
