from __future__ import annotations

import asyncio
import queue

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from keyring.api.deps import CurrentSession, get_locale, get_service, require_scope
from keyring.api.schemas import DecryptBody, EncryptBody
from keyring.api.serializers import envelope_public
from keyring.core.crypto import DecryptFailed
from keyring.core.service import KeyringService
from keyring.i18n import t

router = APIRouter(prefix="/api", tags=["core-ops"])

_QUEUE_MAXSIZE = 4  # bounds in-flight chunks; the whole point of streaming
_STREAM_END = object()


@router.post("/encrypt")
def encrypt(
    body: EncryptBody,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("encrypt")),
):
    env = service.encrypt(
        subject_id=body.subjectId, table=body.table, column=body.column, record_id=body.recordId,
        plaintext=body.plaintext.encode("utf-8"), actor=current.operator.name,
    )
    service.db.commit()
    return envelope_public(env)


@router.post("/decrypt")
def decrypt(
    body: DecryptBody,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("decrypt")),
    locale: str = Depends(get_locale),
):
    try:
        plaintext = service.decrypt(body.envelopeId, actor=current.operator.name)
    except DecryptFailed:
        service.db.commit()
        return JSONResponse(status_code=400, content={"code": "DECRYPT_FAILED", "message": t("error.decrypt_failed", locale)})
    service.db.commit()
    return {"plaintext": plaintext.decode("utf-8", errors="replace")}


@router.post("/encrypt-stream")
async def encrypt_stream(
    request: Request,
    subjectId: str,
    table: str,
    column: str,
    recordId: str,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("encrypt")),
):
    """FR-2.5: request body is the raw plaintext (Content-Type:
    application/octet-stream), streamed from the client without ever
    buffering the full body in memory. Metadata travels as query params
    since the body itself is not JSON.

    Bridges the async ASGI receive stream to the sync KeyringService (which
    owns a sync DB session, like every other service method) via a small
    bounded queue: the event loop pushes chunks as they arrive, the
    threadpool worker running encrypt_stream() blocks on the queue between
    chunks. maxsize bounds how many chunks may be in flight at once."""
    chunk_queue: "queue.Queue[object]" = queue.Queue(maxsize=_QUEUE_MAXSIZE)

    def _chunk_iterable():
        while True:
            item = chunk_queue.get()
            if item is _STREAM_END:
                return
            yield item

    async def _pump():
        async for chunk in request.stream():
            if chunk:
                chunk_queue.put(chunk)
        chunk_queue.put(_STREAM_END)

    pump_task = asyncio.create_task(_pump())
    try:
        env = await run_in_threadpool(
            service.encrypt_stream,
            subject_id=subjectId, table=table, column=column, record_id=recordId,
            plaintext_chunks=_chunk_iterable(), actor=current.operator.name,
        )
    finally:
        await pump_task
    service.db.commit()
    return envelope_public(env)


@router.get("/decrypt-stream/{envelope_id}")
async def decrypt_stream(
    envelope_id: str,
    service: KeyringService = Depends(get_service),
    current: CurrentSession = Depends(require_scope("decrypt")),
    locale: str = Depends(get_locale),
):
    """Eager validation (bad envelope id, wrong alg, revoked/destroyed key)
    fails before any bytes are streamed, so the uniform DECRYPT_FAILED shape
    still applies to those cases. A tampered chunk discovered mid-stream
    (rare — most tamper is caught by the eager checks) can only truncate
    the response, since HTTP status/headers are already committed by then;
    that is an inherent limit of streaming over HTTP, not a gap in the
    underlying uniform-failure guarantee at the service layer."""
    try:
        chunks = await run_in_threadpool(service.decrypt_stream, envelope_id, current.operator.name)
    except DecryptFailed:
        service.db.commit()
        return JSONResponse(status_code=400, content={"code": "DECRYPT_FAILED", "message": t("error.decrypt_failed", locale)})

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

    return StreamingResponse(_body(), media_type="application/octet-stream")
