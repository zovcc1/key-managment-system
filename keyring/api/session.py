from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db, get_locale
from keyring.api.schemas import SessionOpenBody
from keyring.config import settings
from keyring.core import rbac, runtime
from keyring.core.audit import append as audit_append
from keyring.core.errors import UnauthorizedError
from keyring.core.timeutil import aware
from keyring.models.session import Operator, Session

router = APIRouter(prefix="/api/session", tags=["session"])


@router.post("")
def open_session(body: SessionOpenBody, db: DbSession = Depends(get_db), x_api_key: str | None = Header(default=None)):
    if not x_api_key:
        raise UnauthorizedError()
    key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
    operator = db.execute(select(Operator).where(Operator.api_key_hash == key_hash)).scalar_one_or_none()
    if operator is None:
        raise UnauthorizedError()

    if not runtime.is_connected():
        runtime.connect(body.provider)

    session = Session(
        id=str(uuid.uuid4()),
        operator_id=operator.id,
        provider_name=runtime.active_provider_name(),
        provider_connected=True,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.session_ttl_seconds),
    )
    db.add(session)
    audit_append(db, actor=operator.name, operation="session_open", details={"provider": runtime.active_provider_name()})
    db.commit()

    return {
        "token": session.id,
        "operator": operator.name,
        "role": operator.role,
        "scopes": rbac.scopes_for(operator.role),
        "provider": runtime.active_provider_name(),
        "locked": False,
        "expiresAt": aware(session.expires_at).isoformat(),
    }


@router.delete("")
def lock_session(db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    current.session.locked = True
    current.session.locked_at = datetime.now(timezone.utc)
    runtime.disconnect()
    audit_append(db, actor=current.operator.name, operation="session_lock")
    db.commit()
    return {"locked": True}


@router.get("")
def session_status(current: CurrentSession = Depends(get_current_session)):
    return {
        "operator": current.operator.name,
        "role": current.operator.role,
        "locked": current.session.locked,
        "providerConnected": runtime.is_connected(),
        "provider": runtime.active_provider_name(),
        "expiresAt": aware(current.session.expires_at).isoformat(),
    }
