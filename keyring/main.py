from __future__ import annotations

import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from keyring import models  # noqa: F401 — registers all mappers
from keyring.api import approvals, audit, core_ops, dashboard, graph, keys, rewrap, session, settings as settings_api, subjects
from keyring.core.crypto import DecryptFailed, assert_csprng_available
from keyring.core.errors import KeyringError
from keyring.core.lifecycle import IllegalTransition
from keyring.db import SessionLocal
from keyring.i18n import negotiate_locale, t
from keyring.models.rewrap import RewrapJob

_rewrap_worker_stop = threading.Event()


def _rewrap_worker_loop() -> None:
    from keyring.core import runtime
    from keyring.core.service import KeyringService

    while not _rewrap_worker_stop.is_set():
        try:
            if runtime.is_connected():
                db = SessionLocal()
                try:
                    job = db.execute(
                        select(RewrapJob).where(RewrapJob.state == "running").limit(1)
                    ).scalar_one_or_none()
                    if job is not None:
                        service = KeyringService(db, runtime.get_connected_provider())
                        service.rewrap_step(job.id, batch_size=25)
                        db.commit()
                finally:
                    db.close()
        except Exception:  # noqa: BLE001 — worker must never crash the loop
            pass
        _rewrap_worker_stop.wait(0.3)


@asynccontextmanager
async def lifespan(app: FastAPI):
    assert_csprng_available()
    # Schema is owned by Alembic migrations (run `alembic upgrade head`
    # before starting the server) — the app does not create tables itself.
    worker = threading.Thread(target=_rewrap_worker_loop, daemon=True)
    worker.start()
    yield
    _rewrap_worker_stop.set()


app = FastAPI(title="Keyring", version="1.0.0", lifespan=lifespan)

# The console (web/) talks to this API from the Vite dev server's own origin
# during development — production serves it from this same process (see the
# static mount at the bottom of this file), where no CORS is needed at all.
# Content-Language must be exposed explicitly: browsers hide response headers
# from JS by default unless listed in Access-Control-Expose-Headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Language"],
)


@app.middleware("http")
async def locale_middleware(request: Request, call_next):
    locale = negotiate_locale(request.headers.get("accept-language"))
    request.state.locale = locale
    response = await call_next(request)
    response.headers["Content-Language"] = locale
    return response


@app.exception_handler(KeyringError)
async def keyring_error_handler(request: Request, exc: KeyringError):
    locale = getattr(request.state, "locale", "en")
    message = t(exc.message_key, locale, **{k: v for k, v in exc.details.items() if isinstance(v, (str, int, float))})
    return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "message": message, **exc.details})


@app.exception_handler(IllegalTransition)
async def illegal_transition_handler(request: Request, exc: IllegalTransition):
    locale = getattr(request.state, "locale", "en")
    return JSONResponse(
        status_code=409,
        content={"code": "ILLEGAL_TRANSITION", "message": t("error.illegal_transition", locale), "current": exc.current, "target": exc.target},
    )


@app.exception_handler(DecryptFailed)
async def decrypt_failed_handler(request: Request, exc: DecryptFailed):
    locale = getattr(request.state, "locale", "en")
    return JSONResponse(status_code=400, content={"code": DecryptFailed.CODE, "message": t("error.decrypt_failed", locale)})


app.include_router(session.router)
app.include_router(dashboard.router)
app.include_router(keys.router)
app.include_router(graph.router)
app.include_router(approvals.router)
app.include_router(rewrap.router)
app.include_router(subjects.router)
app.include_router(audit.router)
app.include_router(settings_api.router)
app.include_router(core_ops.router)

# Production static mount: serves the built console from this same process
# (`npm run build` in web/, output at web/dist). Mounted last and at "/" so
# every /api/* route above still matches first — Starlette resolves routes
# in registration order, and a Mount only catches what nothing earlier did.
# The console uses HashRouter (see web/src/App.tsx), so client-side routes
# live after "#" and never reach the server — html=True's index.html
# fallback exists only for the bare "/" request, not for deep-link routing.
_web_dist = Path(__file__).resolve().parent.parent / "web" / "dist"
if _web_dist.is_dir():
    app.mount("/", StaticFiles(directory=_web_dist, html=True), name="console")
