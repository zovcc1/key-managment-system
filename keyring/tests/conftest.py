from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from keyring import models  # noqa: F401 — registers all mappers on Base.metadata
from keyring.config import settings
from keyring.core import runtime
from keyring.core.service import KeyringService
from keyring.db import Base
from keyring.models.session import Operator
from keyring.providers.env_provider import EnvKeyProvider
from keyring.providers.file_provider import FileKeyProvider


def make_engine(db_path: Path):
    return create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 5}, future=True
    )


@pytest.fixture
def db_engine(tmp_path):
    engine = make_engine(tmp_path / "unit.db")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False, future=True)


@pytest.fixture
def db_session(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture(params=["file", "env"])
def provider(request, tmp_path, monkeypatch):
    """Parametrized over both KeyProvider implementations — any test that
    depends on this fixture (directly or via `service`) automatically runs
    once per provider, per FR-6.3's "swappable, test suite runs unmodified"
    requirement."""
    if request.param == "file":
        monkeypatch.setattr(settings, "root_passphrase_file", str(tmp_path / "root.passphrase"))
        monkeypatch.setattr(settings, "root_salt_file", str(tmp_path / "root.salt"))
        monkeypatch.setattr(settings, "kek_store_path", str(tmp_path / "kek_store.enc.json"))
        Path(settings.root_passphrase_file).write_text("unit test root passphrase")
        os.chmod(settings.root_passphrase_file, 0o400)
        p = FileKeyProvider()
    else:
        monkeypatch.setattr(settings, "kek_store_path", str(tmp_path / "kek_store_env.enc.json"))
        monkeypatch.setenv(settings.root_secret_env_var, os.urandom(32).hex())
        p = EnvKeyProvider()
    p.connect()
    yield p
    p.disconnect()


@pytest.fixture
def service(db_session, provider):
    return KeyringService(db_session, provider)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class ClientCtx:
    http: "TestClient"
    session_factory: sessionmaker

    def seed_operator(self, name: str, role: str, raw_key: str) -> None:
        db = self.session_factory()
        try:
            db.add(Operator(name=name, role=role, api_key_hash=hash_key(raw_key)))
            db.commit()
        finally:
            db.close()

    def open_session(self, raw_key: str, provider: str = "file") -> dict:
        resp = self.http.post("/api/session", json={"provider": provider}, headers={"X-Api-Key": raw_key})
        assert resp.status_code == 200, resp.text
        return resp.json()

    def auth(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import keyring.db as db_module
    import keyring.main as main_module

    engine = make_engine(tmp_path / "http.db")
    Base.metadata.create_all(engine)
    test_session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    # `get_db` (used by every route) reads `keyring.db.SessionLocal` as a
    # module global at call time, so patching the attribute is enough. The
    # background rewrap-worker thread in main.py imported the name directly
    # (`from keyring.db import SessionLocal`), which binds it into main's own
    # namespace at import time — that binding needs patching separately or
    # the worker thread would touch the real dev database.
    monkeypatch.setattr(db_module, "SessionLocal", test_session_local)
    monkeypatch.setattr(main_module, "SessionLocal", test_session_local)

    monkeypatch.setattr(settings, "root_passphrase_file", str(tmp_path / "root.passphrase"))
    monkeypatch.setattr(settings, "root_salt_file", str(tmp_path / "root.salt"))
    monkeypatch.setattr(settings, "kek_store_path", str(tmp_path / "kek_store.enc.json"))
    Path(settings.root_passphrase_file).write_text("http test root passphrase")
    os.chmod(settings.root_passphrase_file, 0o400)
    monkeypatch.setenv(settings.root_secret_env_var, os.urandom(32).hex())

    with TestClient(main_module.app) as http:
        yield ClientCtx(http=http, session_factory=test_session_local)

    runtime.disconnect()
    engine.dispose()
