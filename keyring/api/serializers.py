from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.config import settings
from keyring.core.lifecycle import legal_transitions
from keyring.core.timeutil import aware
from keyring.models.envelope import Envelope
from keyring.models.file_object import FileObject
from keyring.models.keys import Kek, SubjectKey


def kek_summary(kek: Kek, db: DbSession) -> dict:
    dependent_count = db.execute(
        select(SubjectKey.id).where(SubjectKey.kek_id == kek.id)
    ).scalars().all()
    return {
        "id": kek.id,
        "type": "kek",
        "state": kek.state,
        "algorithm": kek.algorithm,
        "createdAt": aware(kek.created_at).isoformat(),
        "lastRotatedAt": aware(kek.deprecated_at).isoformat() if kek.deprecated_at else None,
        "dependentCount": len(dependent_count),
    }


def kek_detail(kek: Kek, db: DbSession) -> dict:
    d = kek_summary(kek, db)
    d["parentId"] = None
    d["legalTransitions"] = legal_transitions(kek.state, "kek")
    return d


def subject_key_summary(sk: SubjectKey, db: DbSession) -> dict:
    return {
        "id": sk.id,
        "type": "subject_key",
        "state": sk.state,
        "algorithm": sk.algorithm,
        "createdAt": aware(sk.created_at).isoformat(),
        "lastRotatedAt": None,
        "dependentCount": sk.record_count,
    }


def subject_key_detail(sk: SubjectKey, db: DbSession) -> dict:
    d = subject_key_summary(sk, db)
    d["parentId"] = sk.kek_id
    d["legalTransitions"] = legal_transitions(sk.state, "subject_key")
    return d


def envelope_public(env: Envelope) -> dict:
    return {
        "id": env.id,
        "v": env.v,
        "alg": env.alg,
        "kekId": env.kek_id,
        "subjectKeyId": env.subject_key_id,
        "wrappedDek": env.wrapped_dek.hex(),
        "dekNonce": env.dek_nonce.hex(),
        "dataNonce": env.data_nonce.hex(),
        "ciphertext": env.ciphertext.hex(),
        "tag": env.tag.hex(),
        "aad": env.aad().decode("utf-8"),
        "createdAt": aware(env.created_at).isoformat(),
        "table": env.table_name,
        "column": env.column_name,
        "recordId": env.record_id,
        "subjectId": env.subject_id,
    }


def kek_age_days(kek: Kek) -> int:
    reference = aware(kek.activated_at or kek.created_at)
    return (datetime.now(timezone.utc) - reference).days


def file_summary(fo: FileObject) -> dict:
    return {
        "id": fo.id,
        "filename": fo.filename,
        "contentType": fo.content_type,
        "sizeBytes": fo.size_bytes,
        "subjectId": fo.subject_id,
        "uploadedBy": fo.uploaded_by,
        "uploadedAt": aware(fo.uploaded_at).isoformat(),
        "envelopeId": fo.envelope_id,
    }


def file_detail(fo: FileObject, env: Envelope) -> dict:
    d = file_summary(fo)
    d["ciphertextSha256"] = fo.ciphertext_sha256
    d["algorithm"] = env.alg
    d["table"] = env.table_name
    d["column"] = env.column_name
    return d
