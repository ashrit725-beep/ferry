"""Restart tests: everything except in-flight job status survives a new
create_app on the same data directory, migrations are idempotent, and a
database from a newer Ferry is refused instead of being modified.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ferry import audit
from ferry.db import LATEST_VERSION, Database
from ferry.gateway.app import create_app

from helpers_app import (BASE_URL, CSRF, ADMIN_PASSWORD, ADMIN_USER, AUDITOR_PASSWORD, AUDITOR_USER,
                         add_console_user, app_settings, bundle_setup, copy_into, init_database, login, wait_for_job)
from helpers_gateway import bearer, chat_body, store_artifact, store_path, write_token
from helpers_upstream import FakeUpstream


def _tables(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return [(r["type"], r["name"]) for r in conn.execute(
        "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")]


def test_state_survives_a_restart(tmp_path: Path) -> None:
    setup = bundle_setup(tmp_path)
    settings = app_settings(tmp_path / "data", imports=setup.imports)
    database = init_database(settings)
    add_console_user(database, ADMIN_USER, ADMIN_PASSWORD, "admin")
    add_console_user(database, AUDITOR_USER, AUDITOR_PASSWORD, "auditor")
    name = copy_into(setup.inbox, setup.bundle).name
    with FakeUpstream() as upstream:
        with TestClient(create_app(settings), base_url=BASE_URL) as first:
            login(first)
            cookie = first.cookies.get("ferry_session")
            app_id = first.post("/api/apps", json={"name": "survivor", "environment": "pilot"}, headers=CSRF).json()["id"]
            key = first.post(f"/api/apps/{app_id}/keys", json={}, headers=CSRF).json()["api_key"]
            with database.session() as conn:
                digest = store_artifact(settings, conn, b"GGUF bytes that must survive a restart")
            upstream.model_path = store_path(settings, digest)
            token = write_token(settings, "llama", upstream.token)
            backend = first.post("/api/backends", json={"name": "llama", "kind": "llamacpp",
                                                         "base_url": upstream.base_url, "auth_token_file": str(token)},
                                 headers=CSRF).json()
            assert first.post(f"/api/backends/{backend['id']}/check", headers=CSRF).json()["status"]["state"] == "up"
            route = first.post("/api/routes", json={"model": "m1", "backend_id": backend["id"],
                                                    "artifact_digest": digest}, headers=CSRF)
            assert route.status_code == 201 and route.json()["available"] is True
            policy_doc = {"schema": "ferry.dev/access-policy/v1", "rules": [
                {"id": "survivor-m1", "effect": "allow", "principals": ["app:survivor"],
                 "actions": ["chat.completions"], "models": ["m1"]}]}
            assert first.post("/api/policy/activate", json={"document": policy_doc}, headers=CSRF).status_code == 201
            job_id = first.post("/api/inbox/import", json={"name": name}, headers=CSRF).json()["job_id"]
            imported = wait_for_job(first, job_id)
            assert imported["result"]["verdict"] == "accepted"
            assert first.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key)).status_code == 200

        with TestClient(create_app(settings), base_url=BASE_URL) as second:
            second.cookies.set("ferry_session", cookie)
            assert second.get("/api/auth/me").json()["user"] == {"username": ADMIN_USER, "role": "admin"}, \
                "sessions are stored in the database, so they survive a restart"
            apps = second.get("/api/apps").json()["items"]
            assert [(a["name"], a["environment"], len(a["keys"])) for a in apps] == [("survivor", "pilot", 1)]
            assert second.get("/api/policy").json()["active"]["version"] == 1
            routes = second.get("/api/routes").json()["items"]
            assert [(r["model"], r["provenance"]["state"], r["available"]) for r in routes] == [("m1", "verified", True)]
            models = second.get("/v1/models", headers=bearer(key)).json()["data"]
            assert [m["id"] for m in models] == ["m1"]
            assert second.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key)).status_code == 200
            assert second.get(f"/api/jobs/{job_id}").status_code == 404, "job status is in memory only"
            history = second.get("/api/verifications").json()["items"]
            assert [(v["mode"], v["verdict"]) for v in history] == [("import", "accepted")], \
                "the job's outcome was persisted by the importer"
            assert len(second.get("/api/bundles").json()["items"]) == 2
            login(second, AUDITOR_USER, AUDITOR_PASSWORD)
            assert second.post("/api/audit/verify", headers=CSRF).json()["ok"] is True

    with database.session() as conn:
        starts = audit.query_events(conn, action="system.start")
        assert len(starts) == 2 and all(e["actor_type"] == "system" for e in starts)
        assert audit.verify_chain(conn)["ok"] is True
        assert len(audit.query_events(conn, action="gateway.chat.completions")) == 2


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = Database(settings.db_path)
    assert database.init() == LATEST_VERSION
    with database.session() as conn:
        before = _tables(conn)
    assert database.init() == LATEST_VERSION
    for _ in range(2):
        with TestClient(create_app(settings), base_url=BASE_URL):
            pass
    with database.session() as conn:
        assert _tables(conn) == before
        versions = [r["version"] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert versions == list(range(1, LATEST_VERSION + 1))
    assert oct(settings.db_path.stat().st_mode & 0o777) == "0o600"


def test_a_database_from_a_newer_ferry_is_refused(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = init_database(settings)
    with database.session() as conn:
        conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                     (LATEST_VERSION + 1, "2030-01-01T00:00:00.000Z"))
        before = audit.head(conn)
    with pytest.raises(RuntimeError, match="newer than this Ferry build"):
        with TestClient(create_app(settings), base_url=BASE_URL):
            pass
    with database.session() as conn:
        assert audit.head(conn) == before, "nothing was written to a database this build does not understand"
