from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db, get_service, require_scope
from keyring.api.idempotency import run_idempotent
from keyring.api.schemas import DestroyBody, RevokeBody
from keyring.api.serializers import kek_detail, kek_summary, subject_key_detail, subject_key_summary
from keyring.core.errors import ConfirmationMismatchError, NotFoundError
from keyring.core.service import KeyringService
from keyring.models.approvals import Approval
from keyring.models.enums import ApprovalStatus
from keyring.models.keys import Kek, SubjectKey

router = APIRouter(prefix="/api", tags=["keys"])


def _resolve(db: DbSession, key_id: str):
    kek = db.get(Kek, key_id)
    if kek is not None:
        return "kek", kek
    sk = db.get(SubjectKey, key_id)
    if sk is not None:
        return "subject_key", sk
    raise NotFoundError(target="key")


@router.get("/keys")
def list_keys(
    type: str | None = None,
    state: str | None = None,
    q: str | None = None,
    sort: str = "createdAt",
    dir: str = "desc",
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(get_current_session),
):
    items: list[dict] = []
    if type in (None, "kek"):
        keks = db.execute(select(Kek)).scalars().all()
        for kek in keks:
            if state and kek.state != state:
                continue
            if q and q.lower() not in kek.id.lower():
                continue
            items.append(kek_summary(kek, db))
    if type in (None, "subject_key"):
        sks = db.execute(select(SubjectKey)).scalars().all()
        for sk in sks:
            if state and sk.state != state:
                continue
            if q and q.lower() not in sk.id.lower() and q.lower() not in sk.subject_id.lower():
                continue
            items.append(subject_key_summary(sk, db))

    items.sort(key=lambda i: i.get(sort, i["createdAt"]), reverse=(dir == "desc"))
    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]
    return {"items": page_items, "page": page, "pageSize": page_size, "total": total}


@router.get("/keys/{key_id}")
def get_key(key_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    kind, row = _resolve(db, key_id)
    return kek_detail(row, db) if kind == "kek" else subject_key_detail(row, db)


@router.get("/keys/{key_id}/blast-radius")
def blast_radius(key_id: str, service: KeyringService = Depends(get_service)):
    return service.blast_radius(key_id)


@router.post("/keks/{key_id}/rotate/preview")
def rotate_preview(key_id: str, service: KeyringService = Depends(get_service), current: CurrentSession = Depends(require_scope("rotate"))):
    return service.rotate_preview(key_id)


@router.post("/keks/{key_id}/rotate")
def rotate(key_id: str, service: KeyringService = Depends(get_service), current: CurrentSession = Depends(require_scope("rotate"))):
    current_kek, new_kek, job = service.rotate_kek(key_id, actor=current.operator.name)
    service.db.commit()
    return {"newKekId": new_kek.id, "jobId": job.id}


@router.post("/keys/{key_id}/revoke")
def revoke(key_id: str, body: RevokeBody, service: KeyringService = Depends(get_service), current: CurrentSession = Depends(require_scope("revoke"))):
    kind, _ = _resolve(service.db, key_id)
    row = service.revoke_key(kind, key_id, actor=current.operator.name)
    service.db.commit()
    return kek_detail(row, service.db) if kind == "kek" else subject_key_detail(row, service.db)


@router.post("/keys/{key_id}/destroy")
def destroy(
    key_id: str,
    body: DestroyBody,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("destroy")),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    if body.typedConfirmation != key_id:
        raise ConfirmationMismatchError()

    def _do() -> tuple[int, dict]:
        kind, _ = _resolve(service.db, key_id)
        approval = service.db.get(Approval, body.approvalId)
        if approval is None or approval.status != ApprovalStatus.APPROVED.value or approval.operation != "destroy" or approval.target_id != key_id:
            from keyring.core.errors import ApprovalRequiredError

            raise ApprovalRequiredError()
        row = service.destroy_key(kind, key_id, actor=current.operator.name, approval_id=approval.id)
        approval.status = ApprovalStatus.CONSUMED.value
        service.db.commit()
        result = kek_detail(row, service.db) if kind == "kek" else subject_key_detail(row, service.db)
        return 200, result

    status_code, body_out = run_idempotent(service.db, scope="destroy", idempotency_key=idempotency_key, fn=_do)
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content=body_out)
