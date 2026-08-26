from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db, get_locale, get_service, require_scope
from keyring.api.idempotency import run_idempotent
from keyring.api.schemas import ErasureBody
from keyring.core import certificate as cert_module
from keyring.core.audit import append as audit_append
from keyring.core.crypto import DecryptFailed
from keyring.core.errors import ApprovalRequiredError, ConfirmationMismatchError, NotFoundError
from keyring.core.service import KeyringService
from keyring.core.timeutil import aware
from keyring.i18n import t
from keyring.models.approvals import Approval
from keyring.models.enums import ApprovalStatus
from keyring.models.certificate import ErasureCertificate
from keyring.models.envelope import Envelope

router = APIRouter(prefix="/api", tags=["subjects"])


@router.get("/subjects/{subject_id}")
def get_subject(subject_id: str, service: KeyringService = Depends(get_service)):
    sk = service.get_subject_key_by_subject(subject_id)
    return {
        "subjectId": subject_id,
        "subjectKeyId": sk.id,
        "state": sk.state,
        "recordCount": sk.record_count,
        "tables": service.subject_tables(sk.id),
        "lastAccessAt": aware(sk.last_access_at).isoformat() if sk.last_access_at else None,
    }


@router.get("/subjects/{subject_id}/fields/{table}/digest")
def field_digest(
    subject_id: str, table: str,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("decrypt")),
    locale: str = Depends(get_locale),
):
    sk = service.get_subject_key_by_subject(subject_id)
    env = service.db.execute(
        select(Envelope).where(Envelope.subject_key_id == sk.id, Envelope.table_name == table).limit(1)
    ).scalar_one_or_none()
    if env is None:
        raise NotFoundError(target="field")

    try:
        plaintext = service.decrypt(env.id, actor=current.operator.name)
    except DecryptFailed:
        service.db.commit()
        return {"code": "DECRYPT_FAILED", "message": t("error.decrypt_failed", locale)}

    text = plaintext.decode("utf-8", errors="replace")
    masked = ("*" * max(len(text) - 4, 0)) + text[-4:] if len(text) > 4 else "*" * len(text)
    audit_append(
        service.db, actor=current.operator.name, operation="field_digest_reveal",
        key_id=sk.id, item_id=env.id, details={"table": table},
    )
    service.db.commit()
    return {"table": table, "column": env.column_name, "recordId": env.record_id, "maskedValue": masked}


@router.post("/subjects/{subject_id}/erasure")
def erasure(
    subject_id: str,
    body: ErasureBody,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("destroy")),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    if body.typedConfirmation != subject_id:
        raise ConfirmationMismatchError()

    def _do() -> tuple[int, dict]:
        approval = service.db.get(Approval, body.approvalId)
        if (
            approval is None
            or approval.status != ApprovalStatus.APPROVED.value
            or approval.operation != "erasure"
            or approval.target_id != subject_id
        ):
            raise ApprovalRequiredError()

        result = service.erase_subject(subject_id, actor=current.operator.name, approval_id=approval.id)
        approval.status = ApprovalStatus.CONSUMED.value

        payload = cert_module.build_payload(
            subject_id=subject_id,
            subject_key_id=result["subject_key_id"],
            records_unreadable=result["records_unreadable"],
            tables_affected=result["tables_affected"],
            operator=current.operator.name,
            approval_chain=[
                {"role": "requester", "operatorId": approval.requested_by},
                {"role": "approver", "operatorId": approval.approved_by},
            ],
        )
        signature = cert_module.sign_payload(payload)
        cert = ErasureCertificate(
            id=str(uuid.uuid4()),
            subject_id=subject_id,
            subject_key_id=result["subject_key_id"],
            records_unreadable=result["records_unreadable"],
            tables_affected=result["tables_affected"],
            operator=current.operator.name,
            approval_chain=payload["approvalChain"],
            payload=payload,
            signature=signature,
        )
        service.db.add(cert)
        service.db.commit()
        return 200, {"certificateId": cert.id, "recordsUnreadable": result["records_unreadable"]}

    status_code, out = run_idempotent(service.db, scope="erasure", idempotency_key=idempotency_key, fn=_do)
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content=out)


@router.post("/subjects/{subject_id}/verify-unreadable")
def verify_unreadable(subject_id: str, service: KeyringService = Depends(get_service)):
    # No decrypt scope required: only pass/fail booleans cross this
    # boundary, never plaintext — this is the auditor's proof artifact.
    result = service.verify_unreadable(subject_id)
    service.db.commit()
    return result


@router.get("/certificates/{certificate_id}")
def get_certificate(certificate_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    cert = db.get(ErasureCertificate, certificate_id)
    if cert is None:
        raise NotFoundError(target="certificate")
    return {"id": cert.id, "payload": cert.payload, "signature": cert.signature}


@router.get("/certificates/{certificate_id}/export")
def export_certificate(
    certificate_id: str, format: str = Query(default="json"),
    db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session),
    locale: str = Depends(get_locale),
):
    cert = db.get(ErasureCertificate, certificate_id)
    if cert is None:
        raise NotFoundError(target="certificate")

    if format == "pdf":
        content = cert_module.export_pdf(cert, locale)
        return Response(content=content, media_type="application/pdf")

    content = cert_module.export_json(cert)
    return Response(content=content, media_type="application/json")
