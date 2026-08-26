from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.core import rbac, runtime
from keyring.core.errors import ForbiddenError, LockedSessionError, UnauthorizedError
from keyring.core.service import KeyringService
from keyring.core.timeutil import aware
from keyring.db import get_db
from keyring.models.session import Operator, Session

__all__ = ["get_db", "get_locale", "CurrentSession", "get_current_session", "require_scope", "get_service"]


def get_locale(request: Request) -> str:
    return request.state.locale


@dataclass
class CurrentSession:
    session: Session
    operator: Operator


def get_current_session(
    authorization: str | None = Header(default=None),
    db: DbSession = Depends(get_db),
) -> CurrentSession:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError()
    token = authorization.split(" ", 1)[1].strip()

    session = db.get(Session, token)
    if session is None:
        raise UnauthorizedError()
    if session.locked:
        raise LockedSessionError()
    if aware(session.expires_at) < datetime.now(timezone.utc):
        raise UnauthorizedError()

    operator = db.get(Operator, session.operator_id)
    if operator is None:
        raise UnauthorizedError()
    return CurrentSession(session=session, operator=operator)


def require_scope(scope: str):
    def _dep(current: CurrentSession = Depends(get_current_session)) -> CurrentSession:
        if not rbac.has_scope(current.operator.role, scope):
            raise ForbiddenError(role=current.operator.role, scope=scope)
        return current

    return _dep


def get_service(
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(get_current_session),
) -> KeyringService:
    provider = runtime.get_connected_provider()
    return KeyringService(db, provider)
