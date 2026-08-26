from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db, require_scope
from keyring.api.schemas import ApprovalCreateBody
from keyring.core.audit import append as audit_append
from keyring.core.errors import NotFoundError, SelfApprovalError
from keyring.core.timeutil import aware
from keyring.models.approvals import Approval
from keyring.models.enums import ApprovalStatus, Role
from keyring.models.session import Operator

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


def _required_approvers(db: DbSession, exclude_operator_id: str) -> list[str]:
    rows = db.execute(
        select(Operator).where(Operator.role == Role.KEY_ADMIN.value, Operator.id != exclude_operator_id)
    ).scalars().all()
    return [o.name for o in rows]


def _public(approval: Approval, db: DbSession) -> dict:
    return {
        "id": approval.id,
        "operation": approval.operation,
        "targetId": approval.target_id,
        "recordCount": approval.record_count,
        "status": approval.status,
        "requestedBy": approval.requested_by,
        "approvedBy": approval.approved_by,
        "createdAt": aware(approval.created_at).isoformat(),
        "decidedAt": aware(approval.decided_at).isoformat() if approval.decided_at else None,
        "requiredApprovers": _required_approvers(db, approval.requested_by) if approval.status == ApprovalStatus.PENDING.value else [],
    }


@router.post("")
def create_approval(
    body: ApprovalCreateBody,
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(require_scope("request_approval")),
):
    approval = Approval(
        operation=body.operation,
        target_id=body.targetId,
        record_count=body.recordCount,
        requested_by=current.operator.id,
        status=ApprovalStatus.PENDING.value,
    )
    db.add(approval)
    db.flush()
    audit_append(
        db, actor=current.operator.name, operation="approval_request", item_id=approval.target_id,
        details={"approval_id": approval.id, "operation": body.operation},
    )
    db.commit()
    return _public(approval, db)


@router.get("/{approval_id}")
def get_approval(approval_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise NotFoundError(target="approval")
    return _public(approval, db)


@router.post("/{approval_id}/approve")
def approve(
    approval_id: str,
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(require_scope("approve")),
):
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise NotFoundError(target="approval")
    if approval.requested_by == current.operator.id:
        raise SelfApprovalError()

    from datetime import datetime, timezone

    approval.status = ApprovalStatus.APPROVED.value
    approval.approved_by = current.operator.id
    approval.decided_at = datetime.now(timezone.utc)
    db.flush()
    audit_append(
        db, actor=current.operator.name, operation="approve", item_id=approval.target_id,
        details={"approval_id": approval.id},
    )
    db.commit()
    return _public(approval, db)
