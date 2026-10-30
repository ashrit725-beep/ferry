"""Helpers for tests of the assembled server application (ferry.gateway.app).

`app_env` builds settings for a temporary data directory (health loop off), a
migrated database, a console admin (alice) and an auditor (audrey), and a
TestClient on http://127.0.0.1:8750. That is a loopback origin, so with
`cookie_secure = "auto"` the session cookie is not Secure and the test client
sends it back. Requests that change state must carry the CSRF header, so the
`post`/`patch`/`delete` helpers add it; tests that check CSRF use the client
directly.
"""

from __future__ import annotations

import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import httpx
from fastapi.testclient import TestClient

from ferry import audit, auth
from ferry.config import GatewaySettings, ImportSettings, ServerSettings, Settings
from ferry.db import Database
from ferry.gateway.app import create_app

from helpers_bundle import Workspace, make_workspace

BASE_URL = "http://127.0.0.1:8750"
ORIGIN = BASE_URL
CSRF = {"X-Ferry-CSRF": "1"}
ADMIN_USER, ADMIN_PASSWORD = "alice", "alice-password-1234"
AUDITOR_USER, AUDITOR_PASSWORD = "audrey", "audrey-password-1234"
CLI = {"actor_type": "cli", "actor_id": "pytest"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def app_settings(data_dir: Path, *, server: ServerSettings | None = None, imports: ImportSettings | None = None,
                 **gateway: Any) -> Settings:
    values = {"health_interval_s": 0.0, "queue_timeout_s": 2.0, "connect_timeout_s": 2.0, **gateway}
    return Settings(data_dir=data_dir, server=server or ServerSettings(), gateway=GatewaySettings(**values),
                    imports=imports or ImportSettings())


def init_database(settings: Settings) -> Database:
    database = Database(settings.db_path)
    database.init()
    return database


def add_console_user(database: Database, username: str, password: str, role: str) -> dict[str, Any]:
    with database.session() as conn:
        return auth.create_admin_user(conn, username, password, role, **CLI)


def login(client: TestClient, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD) -> httpx.Response:
    client.cookies.clear()
    response = client.post("/api/auth/login", json={"username": username, "password": password}, headers=CSRF)
    assert response.status_code == 200, response.text
    return response


def events(conn: sqlite3.Connection, action: str | None = None) -> list[dict[str, Any]]:
    """Audit events (optionally of one action), oldest first."""
    return list(reversed(audit.query_events(conn, action=action, limit=500)))


@dataclass
class AppEnv:
    settings: Settings
    database: Database
    client: TestClient

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        with self.database.session() as c:
            yield c

    def events(self, action: str | None = None) -> list[dict[str, Any]]:
        with self.conn() as c:
            return events(c, action)

    def as_admin(self) -> None:
        login(self.client, ADMIN_USER, ADMIN_PASSWORD)

    def as_auditor(self) -> None:
        login(self.client, AUDITOR_USER, AUDITOR_PASSWORD)

    def logout_locally(self) -> None:
        self.client.cookies.clear()

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.client.get(path, **kw)

    def post(self, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        headers = {**CSRF, **kw.pop("headers", {})}
        return self.client.post(path, json=json, headers=headers, **kw)

    def patch(self, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        headers = {**CSRF, **kw.pop("headers", {})}
        return self.client.patch(path, json=json, headers=headers, **kw)

    def delete(self, path: str, **kw: Any) -> httpx.Response:
        headers = {**CSRF, **kw.pop("headers", {})}
        return self.client.delete(path, headers=headers, **kw)


@contextmanager
def app_env(data_dir: Path, *, users: bool = True, login_as: str | None = "admin", static_dir: Path | None = None,
            base_url: str = BASE_URL, settings: Settings | None = None, **settings_kw: Any) -> Iterator[AppEnv]:
    settings = settings or app_settings(data_dir, **settings_kw)
    database = init_database(settings)
    if users:
        add_console_user(database, ADMIN_USER, ADMIN_PASSWORD, "admin")
        add_console_user(database, AUDITOR_USER, AUDITOR_PASSWORD, "auditor")
    with TestClient(create_app(settings, static_dir=static_dir), base_url=base_url) as client:
        env = AppEnv(settings=settings, database=database, client=client)
        if users and login_as == "admin":
            env.as_admin()
        elif users and login_as == "auditor":
            env.as_auditor()
        yield env


def wait_for_job(client: TestClient, job_id: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["state"] in ("succeeded", "failed"):
            return job
        if time.monotonic() > deadline:
            raise AssertionError(f"job {job_id} did not finish: {job}")
        time.sleep(0.02)


@dataclass
class BundleSetup:
    workspace: Workspace
    bundle: Path
    """The packed tar (outside the inbox)."""
    inbox: Path
    imports: ImportSettings


def bundle_setup(tmp_path: Path, *, version: str = "1.0.0") -> BundleSetup:
    """A packed, publisher-signed tiny GGUF bundle, an empty inbox, and import
    settings that trust the workspace's keys."""
    workspace = make_workspace(tmp_path)
    packed = workspace.pack(version=version)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    imports = ImportSettings(trust_dir=str(workspace.trust_dir), inbox_dir=str(inbox))
    return BundleSetup(workspace=workspace, bundle=packed.bundle_path, inbox=inbox, imports=imports)


def copy_into(directory: Path, source: Path, name: str | None = None) -> Path:
    target = directory / (name or source.name)
    shutil.copyfile(source, target)
    return target
