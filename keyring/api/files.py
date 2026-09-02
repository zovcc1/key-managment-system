"""Files section: upload, list, inspect, and download encrypted files.

Reuses the streaming primitives in keyring.core.service unchanged — a file
is exactly one streamed envelope (table="files", column="content",
record_id=<file uuid>) whose framed ciphertext is written to the blob store
instead of the envelope row (see keyring/core/blobstore.py). Metadata lives
in FileObject; the plaintext never lands in the database or the audit log.
"""
from __future__ import annotations

import hashlib
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.concurrency import run_in_threadpool

from keyring.api.deps import CurrentSession, get_db, get_locale, get_service, require_scope
from keyring.api.serializers import file_detail, file_summary
from keyring.core import blobstore
from keyring.core.audit import append as audit_append
from keyring.core.crypto import DecryptFailed
from keyring.core.errors import NotFoundError
from keyring.core.service import STREAM_CHUNK_SIZE, KeyringService
from keyring.i18n import t
from keyring.models.envelope import Envelope
from keyring.models.file_object import FileObject

router = APIRouter(prefix="/api/files", tags=["files"])

_MAX_FILENAME_LEN = 255
_STREAM_END = object()


def _sanitize_filename(name: str) -> str:
    """Strip any path component a client might send and cap length — this is
    display metadata only, never used to build a filesystem path. The blob
    store addresses files purely by UUID ref (see blobstore._resolve), so a
    hostile filename can at worst render oddly in the UI, not escape a
    directory."""
    name = (name or "upload").replace("\\", "/").rsplit("/", 1)[-1].strip()
    return (name or "upload")[:_MAX_FILENAME_LEN]


def _get_file(db: DbSession, file_id: str) -> FileObject:
    fo = db.get(FileObject, file_id)
    if fo is None:
        raise NotFoundError(target="file")
    return fo


def _get_envelope(db: DbSession, fo: FileObject) -> Envelope:
    env = db.get(Envelope, fo.envelope_id)
    if env is None:
        raise NotFoundError(target="envelope")
    return env


def _hash_blob(ref: str) -> str:
    digest = hashlib.sha256()
    with blobstore.open_read(ref) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


@router.post("")
def upload_file(
    file: UploadFile = File(...),
    subjectId: str = Form(...),
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("file_write")),
):
    file_id = str(uuid.uuid4())
    filename = _sanitize_filename(file.filename or "upload")
    content_type = (file.content_type or "application/octet-stream")[:255]
    counted = {"bytes": 0}

    def _chunks():
        while True:
            chunk = file.file.read(STREAM_CHUNK_SIZE)
            if not chunk:
                return
            counted["bytes"] += len(chunk)
            yield chunk

    try:
        env = service.encrypt_stream(
            subject_id=subjectId, table="files", column="content", record_id=file_id,
            plaintext_chunks=_chunks(), actor=current.operator.name, blob_ref=file_id,
        )
        # Hash the ciphertext, not the plaintext — a plaintext digest would
        # survive crypto-shredding and act as a confirmation oracle against
        # a guessed file.
        ciphertext_sha256 = _hash_blob(file_id)

        fo = FileObject(
            id=file_id, filename=filename, content_type=content_type, size_bytes=counted["bytes"],
            ciphertext_sha256=ciphertext_sha256, envelope_id=env.id, subject_id=subjectId,
            uploaded_by=current.operator.name,
        )
        service.db.add(fo)
        audit_append(
            service.db, actor=current.operator.name, operation="file_upload",
            key_id=env.subject_key_id, item_id=file_id,
            details={"filename": filename, "sizeBytes": counted["bytes"], "contentType": content_type},
        )
        service.db.commit()
    except Exception:
        # Idempotent cleanup: covers both "blob never finished writing"
        # (blobstore.write_stream already removed its own temp file) and
        # "blob finished but the DB write after it failed" (the file exists
        # on disk with no FileObject row pointing at it).
        blobstore.delete(file_id)
        raise
    return file_summary(fo)


@router.get("")
def list_files(
    subjectId: str | None = None,
    q: str | None = None,
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(require_scope("file_read")),
):
    rows = db.execute(select(FileObject).order_by(FileObject.uploaded_at.desc())).scalars().all()
    items = []
    for fo in rows:
        if subjectId and fo.subject_id != subjectId:
            continue
        if q and q.lower() not in fo.filename.lower():
            continue
        items.append(file_summary(fo))

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start:start + page_size]
    return {"items": page_items, "page": page, "pageSize": page_size, "total": total}


@router.get("/{file_id}")
def get_file(
    file_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(require_scope("file_read")),
):
    fo = _get_file(db, file_id)
    env = _get_envelope(db, fo)
    return file_detail(fo, env)


@router.get("/{file_id}/key-tree")
def file_key_tree(
    file_id: str, service: KeyringService = Depends(get_service), current: CurrentSession = Depends(require_scope("file_read")),
):
    fo = _get_file(service.db, file_id)
    return service.file_key_tree(fo)


@router.get("/{file_id}/ciphertext-preview")
def ciphertext_preview(
    file_id: str,
    preview_bytes: int = Query(default=256, ge=1, le=4096, alias="bytes"),
    db: DbSession = Depends(get_db),
    current: CurrentSession = Depends(require_scope("file_read")),
):
    """First `bytes` of the framed ciphertext, as hex — literally what "the
    encrypted file" looks like at rest. Never touches plaintext or the DEK,
    so it needs only `file_read`."""
    fo = _get_file(db, file_id)
    env = _get_envelope(db, fo)

    if env.blob_ref is not None:
        if not blobstore.exists(env.blob_ref):
            return {"hex": "", "previewBytes": 0, "totalBytes": 0, "blobPresent": False}
        total = blobstore.size(env.blob_ref)
        with blobstore.open_read(env.blob_ref) as fh:
            chunk = fh.read(preview_bytes)
    else:
        total = len(env.ciphertext)
        chunk = env.ciphertext[:preview_bytes]

    return {"hex": chunk.hex(), "previewBytes": len(chunk), "totalBytes": total, "blobPresent": True}


@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("decrypt")),
    locale: str = Depends(get_locale),
):
    """Gated on `decrypt`, not `file_read` — an auditor can inspect a file's
    key tree without ever holding plaintext (FR-9 separation of duty)."""
    fo = _get_file(service.db, file_id)
    try:
        chunks = await run_in_threadpool(service.decrypt_stream, fo.envelope_id, current.operator.name)
    except DecryptFailed:
        service.db.commit()
        return JSONResponse(status_code=400, content={"code": "DECRYPT_FAILED", "message": t("error.decrypt_failed", locale)})

    audit_append(
        service.db, actor=current.operator.name, operation="file_download", item_id=file_id,
        details={"filename": fo.filename},
    )
    service.db.commit()

    async def _body():
        try:
            iterator = iter(chunks)
            while True:
                chunk = await run_in_threadpool(next, iterator, _STREAM_END)
                if chunk is _STREAM_END:
                    break
                yield chunk
        finally:
            service.db.commit()

    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fo.filename)}"}
    return StreamingResponse(_body(), media_type=fo.content_type or "application/octet-stream", headers=headers)
