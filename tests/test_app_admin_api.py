"""Admin API tests (spec section 9): every endpoint's happy path, authentication
(401), roles (auditor 403 on admin-only endpoints), CSRF (missing header,
cross-origin Origin), validation (422), the inbox name rules, background jobs,
one-time API key display, and overview numbers checked against audit events.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from ferry import audit, auth, backends, policy
from ferry.bundle import importer
from ferry.errors import FerryError
from ferry.gateway import admin_api
from ferry.gateway.security import ApiError
from ferry.trust import add_key

from helpers_app import ADMIN_USER, CSRF, AppEnv, app_env, bundle_setup, copy_into, wait_for_job
from helpers_bundle import make_signer
from helpers_gateway import (ACTOR, activate, add_app, add_backend, allow, bearer, chat_body, store_artifact,
                             store_path, write_token)
from helpers_upstream import FakeUpstream

POLICY_DOC = {"schema": policy.SCHEMA, "description": "test", "rules": [
    {"id": "one", "effect": "allow", "principals": ["app:app-one"], "actions": ["chat.completions"], "models": ["m1"]}]}
NO_JOB = "0" * 32
NO_BUNDLE = "sha256:" + "0" * 64

READ_ENDPOINTS = [
    "/api/auth/me", "/api/overview", "/api/inbox", f"/api/jobs/{NO_JOB}", "/api/verifications", "/api/verifications/1",
    "/api/bundles", f"/api/bundles/{NO_BUNDLE}", "/api/trust", "/api/models", "/api/backends", "/api/routes",
    "/api/apps", "/api/policy", "/api/policy/1", "/api/audit", "/api/audit/facets", "/api/audit/1",
    "/api/audit/export", "/api/evidence", "/api/evidence.md", "/api/system",
]
AUDITOR_POSTS = [
    ("POST", "/api/audit/verify", {}),
    ("POST", "/api/policy/validate", {"document": POLICY_DOC}),
    ("POST", "/api/policy/explain", {"app": "app-one", "model": "m1"}),
]
ADMIN_ONLY = [
    ("POST", "/api/inbox/verify", {"name": "x.ferry.tar"}),
    ("POST", "/api/inbox/import", {"name": "x.ferry.tar"}),
    ("POST", "/api/backends", {"name": "b", "kind": "llamacpp", "base_url": "http://127.0.0.1:9"}),
    ("PATCH", "/api/backends/1", {"enabled": False}),
    ("DELETE", "/api/backends/1", None),
    ("POST", "/api/backends/1/check", None),
    ("POST", "/api/routes", {"model": "m1", "backend_id": 1, "require_verified": False}),
    ("PATCH", "/api/routes/1", {"enabled": False}),
    ("DELETE", "/api/routes/1", None),
    ("POST", "/api/apps", {"name": "new-app", "environment": "test"}),
    ("PATCH", "/api/apps/1", {"description": "x"}),
    ("POST", "/api/apps/1/keys", {}),
    ("POST", "/api/keys/aaaaaaaaaaaa/revoke", {}),
    ("POST", "/api/policy/activate", {"document": POLICY_DOC, "comment": "x"}),
]
STATE_CHANGING = [*AUDITOR_POSTS, *ADMIN_ONLY, ("POST", "/api/auth/logout", None),
                  ("POST", "/api/auth/login", {"username": ADMIN_USER, "password": "alice-password-1234"})]


def _call(env: AppEnv, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None) -> Any:
    kwargs: dict[str, Any] = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return env.client.request(method, path, **kwargs)


def _ids(cases: list[tuple[str, str, Any]]) -> list[str]:
    return [f"{m} {p}" for m, p, _ in cases]


@pytest.fixture(scope="module")
def shared(tmp_path_factory: pytest.TempPathFactory):
    """One server for the authentication/role/CSRF matrix, which changes nothing
    that later cases depend on."""
    with app_env(tmp_path_factory.mktemp("shared") / "data") as env:
        yield env


# --- authentication, roles, CSRF -------------------------------------------------------------


@pytest.mark.parametrize("path", READ_ENDPOINTS)
def test_reads_without_a_session_are_401(shared: AppEnv, path: str) -> None:
    shared.logout_locally()
    response = shared.get(path)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("method, path, body", [*AUDITOR_POSTS, *ADMIN_ONLY, ("POST", "/api/auth/logout", None)],
                         ids=_ids([*AUDITOR_POSTS, *ADMIN_ONLY, ("POST", "/api/auth/logout", None)]))
def test_writes_without_a_session_are_401(shared: AppEnv, method: str, path: str, body: Any) -> None:
    shared.logout_locally()
    response = _call(shared, method, path, body, CSRF)
    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "not_authenticated"


def test_a_forged_session_cookie_is_401(shared: AppEnv) -> None:
    shared.logout_locally()
    shared.client.cookies.set("ferry_session", "A" * 43)
    assert shared.get("/api/auth/me").status_code == 401
    shared.client.cookies.set("ferry_session", "not a token")
    assert shared.get("/api/overview").status_code == 401


@pytest.mark.parametrize("method, path, body", ADMIN_ONLY, ids=_ids(ADMIN_ONLY))
def test_auditor_is_refused_admin_only_endpoints(shared: AppEnv, method: str, path: str, body: Any) -> None:
    shared.as_auditor()
    with shared.conn() as c:
        before = audit.head(c)["seq"]
    response = _call(shared, method, path, body, CSRF)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "forbidden"
    with shared.conn() as c:
        assert audit.head(c)["seq"] == before, "a refused request must not change anything"


@pytest.mark.parametrize("method, path, body", AUDITOR_POSTS, ids=_ids(AUDITOR_POSTS))
def test_auditor_may_run_the_read_only_posts(shared: AppEnv, method: str, path: str, body: Any) -> None:
    shared.as_auditor()
    response = _call(shared, method, path, body, CSRF)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("path", READ_ENDPOINTS)
def test_auditor_may_read_everything(shared: AppEnv, path: str) -> None:
    shared.as_auditor()
    response = shared.get(path)
    assert response.status_code in (200, 404), response.text
    if response.status_code == 404:
        assert path.rsplit("/", 1)[-1] in ("1", NO_JOB, NO_BUNDLE)


@pytest.mark.parametrize("method, path, body", STATE_CHANGING, ids=_ids(STATE_CHANGING))
def test_state_changing_requests_without_the_csrf_header_are_403(shared: AppEnv, method: str, path: str,
                                                                 body: Any) -> None:
    shared.as_admin()
    with shared.conn() as c:
        before = audit.head(c)["seq"]
    for headers in ({}, {"X-Ferry-CSRF": "0"}, {"X-Ferry-CSRF": "true"}):
        response = _call(shared, method, path, body, headers)
        assert response.status_code == 403, (headers, response.text)
        assert response.json()["error"]["code"] == "csrf_failed"
    with shared.conn() as c:
        assert audit.head(c)["seq"] == before


@pytest.mark.parametrize("method, path, body", STATE_CHANGING, ids=_ids(STATE_CHANGING))
def test_cross_origin_state_changing_requests_are_403(shared: AppEnv, method: str, path: str, body: Any) -> None:
    shared.as_admin()
    for origin in ("http://evil.example", "http://127.0.0.1:9999", "https://127.0.0.1:8750", "null",
                   "http://localhost:8750"):
        response = _call(shared, method, path, body, {**CSRF, "Origin": origin})
        assert response.status_code == 403, (origin, response.text)
        assert response.json()["error"]["code"] == "csrf_failed"


def test_same_origin_requests_with_the_header_pass(shared: AppEnv) -> None:
    shared.as_admin()
    response = shared.post("/api/audit/verify", {}, headers={"Origin": "http://127.0.0.1:8750"})
    assert response.status_code == 200
    assert response.json()["ok"] is True


# --- auth -----------------------------------------------------------------------------------------


def test_login_me_logout(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        response = env.post("/api/auth/login", {"username": "Alice", "password": "alice-password-1234"})
        assert response.status_code == 200
        assert response.json() == {"user": {"username": "alice", "role": "admin"}}
        me = env.get("/api/auth/me").json()
        assert me["user"] == {"username": "alice", "role": "admin"}
        out = env.post("/api/auth/logout")
        assert out.status_code == 204
        assert "Max-Age=0" in out.headers["set-cookie"]
        assert env.get("/api/auth/me").status_code == 401
        actions = [(e["action"], e["outcome"], e["actor_id"]) for e in env.events() if e["action"].startswith("auth.")]
        assert actions == [("auth.login", "success", "alice"), ("auth.logout", "success", "alice")]


def test_logout_ends_the_session_on_the_server(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        token = env.client.cookies.get("ferry_session")
        assert token and len(token) == 43
        assert env.post("/api/auth/logout").status_code == 204
        env.client.cookies.set("ferry_session", token)
        assert env.get("/api/auth/me").status_code == 401, "a copied cookie must not outlive logout"


def test_wrong_password_is_401_without_detail_and_audited(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        wrong = env.post("/api/auth/login", {"username": "alice", "password": "not-the-password"})
        unknown = env.post("/api/auth/login", {"username": "mallory", "password": "not-the-password"})
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json() == unknown.json(), "callers must not learn whether the user exists"
        failures = [e for e in env.events("auth.login") if e["outcome"] == "failure"]
        assert [(e["actor_id"], e["details"]["reason"]) for e in failures] == [("alice", "bad_password"),
                                                                               ("unknown", "unknown_user")]
        assert "not-the-password" not in json.dumps(env.events())


@pytest.mark.parametrize("body", [
    {"username": "alice"}, {"password": "x" * 12}, {"username": "alice", "password": 123456789012345},
    {"username": ["alice"], "password": "alice-password-1234"},
    {"username": "alice", "password": "alice-password-1234", "remember": True}, [1, 2],
])
def test_login_validation_is_422_and_never_echoes_values(tmp_path: Path, body: Any) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        response = env.post("/api/auth/login", body)
        assert response.status_code == 422, response.text
        assert "123456789012345" not in response.text and "alice-password-1234" not in response.text
        assert env.client.cookies.get("ferry_session") is None


def test_non_json_body_is_422(shared: AppEnv) -> None:
    shared.as_admin()
    response = shared.client.post("/api/apps", content=b"name=x", headers={**CSRF, "Content-Type": "text/plain"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_json"


BODY_ENDPOINTS = [
    ("POST", "/api/auth/login"), ("POST", "/api/inbox/verify"), ("POST", "/api/inbox/import"),
    ("POST", "/api/backends"), ("PATCH", "/api/backends/1"), ("POST", "/api/routes"), ("PATCH", "/api/routes/1"),
    ("POST", "/api/apps"), ("PATCH", "/api/apps/1"), ("POST", "/api/apps/1/keys"),
    ("POST", "/api/keys/aaaaaaaaaaaa/revoke"), ("POST", "/api/policy/validate"), ("POST", "/api/policy/activate"),
    ("POST", "/api/policy/explain"), ("POST", "/api/audit/verify"),
]


@pytest.mark.parametrize("method, path", BODY_ENDPOINTS, ids=[f"{m} {p}" for m, p in BODY_ENDPOINTS])
def test_every_body_endpoint_validates_its_body(shared: AppEnv, method: str, path: str) -> None:
    shared.as_admin()
    with shared.conn() as c:
        before = audit.head(c)["seq"]
    unknown = shared.client.request(method, path, json={"surprise": 1}, headers=CSRF)
    assert unknown.status_code == 422, unknown.text
    assert unknown.json()["error"]["code"] == "validation_failed" and "surprise" in unknown.json()["error"]["message"]
    for raw in (b'{"name": "a", "name": "b"}', b"[1, 2]", b'{"x": NaN}', b"\xff\xfe", b"{" * 5000):
        bad = shared.client.request(method, path, content=raw, headers={**CSRF, "Content-Type": "application/json"})
        assert bad.status_code in (413, 422), (raw[:20], bad.text)
        if bad.status_code == 422:
            assert bad.json()["error"]["code"] == "invalid_json"
    with shared.conn() as c:
        assert audit.head(c)["seq"] == before, "an invalid body changes nothing"


# --- backends and routes ------------------------------------------------------------------------------


def test_backend_and_route_lifecycle(tmp_path: Path) -> None:
    with FakeUpstream() as upstream, app_env(tmp_path / "data") as env:
        token_file = write_token(env.settings, "llama", upstream.token)
        created = env.post("/api/backends", {"name": "llama", "kind": "llamacpp", "base_url": upstream.base_url + "/",
                                             "auth_token_file": str(token_file), "timeout_s": 30, "max_concurrency": 2})
        assert created.status_code == 201, created.text
        backend = created.json()
        assert backend["has_token"] is True and backend["base_url"] == upstream.base_url
        assert "auth_token_file" not in backend and upstream.token not in created.text
        assert [b["name"] for b in env.get("/api/backends").json()["items"]] == ["llama"]

        with env.conn() as c:
            digest = store_artifact(env.settings, c, b"GGUF bytes of the admin api test")
        upstream.model_path = store_path(env.settings, digest)
        check = env.post(f"/api/backends/{backend['id']}/check")
        assert check.status_code == 200, check.text
        assert check.json()["status"]["state"] == "up"
        assert check.json()["status"]["served"][0]["digest"] == digest
        assert check.json()["checked_at"] == check.json()["status"]["checked_at"]

        route = env.post("/api/routes", {"model": "m1", "backend_id": backend["id"], "upstream_model": "alias",
                                         "artifact_digest": "sha256:" + digest})
        assert route.status_code == 201, route.text
        route_id = route.json()["id"]
        assert route.json()["provenance"]["state"] == "verified" and route.json()["available"] is True
        listed = env.get("/api/routes").json()["items"]
        assert [(r["model"], r["backend_name"], r["provenance"]["state"]) for r in listed] == [("m1", "llama", "verified")]

        patched = env.patch(f"/api/routes/{route_id}", {"enabled": False})
        assert patched.status_code == 200 and patched.json()["available"] is False
        renamed = env.patch(f"/api/backends/{backend['id']}", {"name": "llama-2", "enabled": True})
        assert renamed.status_code == 200 and renamed.json()["name"] == "llama-2"

        blocked = env.delete(f"/api/backends/{backend['id']}")
        assert blocked.status_code == 409
        assert blocked.json()["error"]["details"]["routes"] == ["m1"]
        assert env.delete(f"/api/routes/{route_id}").status_code == 204
        assert env.delete(f"/api/backends/{backend['id']}").status_code == 204
        assert env.get("/api/backends").json()["items"] == []

        mine = Counter(e["action"] for e in env.events() if e["actor_id"] == ADMIN_USER and e["actor_type"] == "admin")
        assert mine["backend.create"] == mine["backend.update"] == mine["backend.delete"] == 1
        assert mine["route.create"] == mine["route.update"] == mine["route.delete"] == 1
        assert mine["backend.health"] == 1
        assert upstream.token not in json.dumps(env.events())


@pytest.mark.parametrize("body, code", [
    ({"name": "b", "kind": "tgi", "base_url": "http://127.0.0.1:9"}, "validation_failed"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://8.8.8.8:80"}, "egress_denied"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://169.254.169.254"}, "egress_denied"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://127.0.0.1:9/v1"}, "validation_failed"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://u:p@127.0.0.1:9"}, "validation_failed"),
    ({"name": "b", "kind": "llamacpp"}, "validation_failed"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://127.0.0.1:9", "verify_tls": False}, "validation_failed"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://127.0.0.1:9", "auth_token_file": "/etc/hosts"},
     "validation_failed"),
    ({"name": "b", "kind": "llamacpp", "base_url": "http://127.0.0.1:9", "timeout_s": "fast"}, "validation_failed"),
])
def test_backend_validation_is_422(shared: AppEnv, body: dict[str, Any], code: str) -> None:
    shared.as_admin()
    response = shared.post("/api/backends", body)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == code


def test_backend_and_route_errors(shared: AppEnv) -> None:
    shared.as_admin()
    assert shared.patch("/api/backends/999", {"enabled": False}).status_code == 404
    assert shared.patch("/api/backends/abc", {"enabled": False}).status_code == 422
    assert shared.patch("/api/backends/999", {"colour": "red"}).status_code == 422
    assert shared.post("/api/backends/999/check").status_code == 404
    assert shared.delete("/api/routes/999").status_code == 404
    pinless = shared.post("/api/routes", {"model": "m9", "backend_id": 999})
    assert pinless.status_code in (404, 422)
    missing_pin = shared.post("/api/routes", {"model": "m9", "backend_id": 1, "artifact_digest": "f" * 64,
                                              "require_verified": True})
    assert missing_pin.status_code in (404, 422)


# --- apps and keys ---------------------------------------------------------------------------------------


def test_app_and_key_lifecycle(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        created = env.post("/api/apps", {"name": "report-bot", "environment": "pilot", "description": "reports"})
        assert created.status_code == 201, created.text
        app = created.json()
        assert app["environment"] == "pilot" and app["keys"] == [] and app["disabled"] is False
        patched = env.patch(f"/api/apps/{app['id']}", {"description": "nightly reports", "environment": "production"})
        assert patched.status_code == 200 and patched.json()["environment"] == "production"

        issued = env.post(f"/api/apps/{app['id']}/keys", {"expires_in_days": 30})
        assert issued.status_code == 201, issued.text
        key = issued.json()
        assert key["api_key"].startswith(f"fyk_{key['key_id']}_") and key["expires_at"]
        assert env.get("/v1/models", headers=bearer(key["api_key"])).status_code == 200

        revoked = env.post(f"/api/keys/{key['key_id']}/revoke")
        assert revoked.status_code == 200 and revoked.json()["revoked_at"]
        assert env.post(f"/api/keys/{key['key_id']}/revoke").status_code == 409
        assert env.get("/v1/models", headers=bearer(key["api_key"])).status_code == 401
        assert env.post("/api/keys/not-a-key-id/revoke").status_code == 422
        assert env.post("/api/keys/bbbbbbbbbbbb/revoke").status_code == 404

        disabled = env.patch(f"/api/apps/{app['id']}", {"disabled": True})
        assert disabled.status_code == 200 and disabled.json()["disabled"] is True
        assert env.post(f"/api/apps/{app['id']}/keys", {}).status_code == 409
        listed = env.get("/api/apps").json()["items"]
        assert [(a["name"], len(a["keys"])) for a in listed] == [("report-bot", 1)]
        actions = [e["action"] for e in env.events() if e["actor_type"] == "admin" and e["action"] != "auth.login"]
        assert actions == ["principal.create", "principal.update", "api_key.create", "api_key.revoke",
                           "principal.update"]


def test_api_key_secret_is_shown_once_and_never_stored(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        app_id = env.post("/api/apps", {"name": "one-time", "environment": "test"}).json()["id"]
        issued = env.post(f"/api/apps/{app_id}/keys", {}).json()
        secret = issued["api_key"].split("_", 2)[2]
        assert len(secret) == 43
        assert env.get("/v1/models", headers=bearer(issued["api_key"])).status_code == 200
        for path in ("/api/apps", "/api/audit?limit=500", "/api/audit/export", "/api/evidence", "/api/overview"):
            text = env.get(path).text
            assert secret not in text and issued["api_key"] not in text, path
        assert "api_key" not in json.dumps(env.get("/api/apps").json())
        with env.conn() as c:
            tables = [r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            for table in tables:
                for row in c.execute(f"SELECT * FROM {table}"):
                    for value in tuple(row):
                        assert secret not in str(value), f"secret found in table {table}"
        for path in (env.settings.db_path, env.settings.db_path.with_name("ferry.db-wal")):
            if path.exists():
                assert secret.encode() not in path.read_bytes(), path


@pytest.mark.parametrize("body", [
    {"name": "Bad Name", "environment": "test"}, {"name": "ok-name", "environment": "staging"},
    {"name": "ok-name"}, {"name": "ok-name", "environment": "test", "owner": "x"},
    {"name": "ok-name", "environment": "test", "description": 5},
])
def test_app_validation_is_422(shared: AppEnv, body: dict[str, Any]) -> None:
    shared.as_admin()
    assert shared.post("/api/apps", body).status_code == 422


def test_duplicate_app_is_409_and_bad_key_expiry_is_422(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        app_id = env.post("/api/apps", {"name": "dup", "environment": "test"}).json()["id"]
        assert env.post("/api/apps", {"name": "dup", "environment": "test"}).status_code == 409
        for days in (0, -1, 10_000, "7", True):
            assert env.post(f"/api/apps/{app_id}/keys", {"expires_in_days": days}).status_code == 422
        assert env.post("/api/apps/999/keys", {}).status_code == 404
        assert env.patch(f"/api/apps/{app_id}", {}).status_code == 422


# --- policy -------------------------------------------------------------------------------------------------


def test_policy_validate_activate_explain_and_history(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        assert env.get("/api/policy").json() == {"active": None, "history": []}
        invalid = {"schema": policy.SCHEMA, "rules": [{"id": "Bad Id", "effect": "maybe"}]}
        checked = env.post("/api/policy/validate", {"document": invalid}).json()
        assert checked["valid"] is False and checked["errors"]
        good = env.post("/api/policy/validate", {"document": POLICY_DOC}).json()
        assert good["valid"] is True
        assert any("does not exist" in w["message"] for w in good["warnings"])

        refused = env.post("/api/policy/activate", {"document": invalid, "comment": "nope"})
        assert refused.status_code == 422
        assert refused.json()["validation"]["valid"] is False
        assert refused.json()["error"]["details"]["validation"]["errors"]
        assert env.get("/api/policy").json()["active"] is None

        env.post("/api/apps", {"name": "app-one", "environment": "test"})
        first = env.post("/api/policy/activate", {"document": POLICY_DOC, "comment": "first"})
        assert first.status_code == 201, first.text
        assert first.json()["version"] == 1 and len(first.json()["sha256"]) == 64
        state = env.get("/api/policy").json()
        assert state["active"]["version"] == 1 and state["active"]["activated_by"] == "admin:alice"
        assert state["active"]["document"] == POLICY_DOC
        assert env.get("/api/policy/1").json()["document"] == POLICY_DOC
        assert env.get("/api/policy/7").status_code == 404

        allowed = env.post("/api/policy/explain", {"app": "app-one", "model": "m1"}).json()
        assert allowed["allowed"] is True and allowed["decisive_rule"] == "one" and allowed["principal"] == "app:app-one"
        denied = env.post("/api/policy/explain", {"app": "app-one", "model": "m2", "action": "chat.completions"}).json()
        assert denied["allowed"] is False and denied["reason"] == "no rule allows"
        assert env.post("/api/policy/explain", {"app": "Not Valid", "model": "m1"}).status_code == 422
        assert env.post("/api/policy/explain", {"app": "app-one"}).status_code == 422

        rollback = env.post("/api/policy/activate", {"document": policy.default_policy_document()})
        assert rollback.status_code == 201 and rollback.json()["version"] == 2
        history = env.get("/api/policy").json()["history"]
        assert [(h["version"], h["active"]) for h in history] == [(2, True), (1, False)]
        assert [e["details"]["version"] for e in env.events("policy.activate")] == [1, 2]


# --- audit ----------------------------------------------------------------------------------------------------


def test_audit_query_filters_and_pagination(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        for i in range(5):
            env.post("/api/apps", {"name": f"app-{i}", "environment": "test"})
        page = env.get("/api/audit", params={"action": "principal.create", "limit": 2}).json()
        assert [e["resource"] for e in page["items"]] == ["app:app-4", "app:app-3"]
        assert page["next_before_seq"] == page["items"][-1]["seq"]
        rest = env.get("/api/audit", params={"action": "principal.create", "limit": 10,
                                             "before_seq": page["next_before_seq"]}).json()
        assert [e["resource"] for e in rest["items"]] == ["app:app-2", "app:app-1", "app:app-0"]
        assert rest["next_before_seq"] is None
        assert len(env.get("/api/audit", params={"action": "principal.", "actor_id": "alice"}).json()["items"]) == 5
        assert len(env.get("/api/audit", params={"q": "app-3"}).json()["items"]) == 1
        assert env.get("/api/audit", params={"since": "2999-01-01T00:00:00Z"}).json()["items"] == []
        recent = env.get("/api/audit", params={"since": "2000-01-01T00:00:00+02:00", "outcome": "success"}).json()
        assert len(recent["items"]) >= 6
        for bad in ({"since": "yesterday"}, {"until": "2026-10-28"}, {"limit": 0}, {"limit": 501}, {"limit": "x"},
                    {"before_seq": -1}, {"q": "x" * 600}):
            assert env.get("/api/audit", params=bad).status_code == 422, bad
        event = env.get(f"/api/audit/{page['items'][0]['seq']}").json()
        assert event["action"] == "principal.create" and len(event["hash"]) == 64 and len(event["prev_hash"]) == 64
        assert env.get("/api/audit/99999").status_code == 404
        facets = env.get("/api/audit/facets").json()
        assert "principal.create" in facets["actions"] and "admin" in facets["actor_types"]


def test_audit_verify_records_the_check_and_detects_tampering(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        result = env.post("/api/audit/verify").json()
        assert result["ok"] is True and result["first_bad_seq"] is None
        recorded = env.events("audit.verify")
        assert len(recorded) == 1 and recorded[0]["details"]["ok"] is True
        assert env.get("/api/overview").json()["audit"]["last_verify"]["ok"] is True
        with env.conn() as c:
            c.execute("UPDATE audit_events SET details = ? WHERE seq = 2", ('{"tampered":true}',))
        broken = env.post("/api/audit/verify").json()
        assert broken["ok"] is False and broken["first_bad_seq"] == 2
        overview = env.get("/api/overview").json()
        assert overview["audit"]["last_verify"]["ok"] is False
        assert overview["attention"][0]["severity"] == "error" and "audit chain" in overview["attention"][0]["message"]


def test_overview_last_verify_names_the_covered_head(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        result = env.post("/api/audit/verify").json()
        last = env.get("/api/overview").json()["audit"]["last_verify"]
        recorded = env.events("audit.verify")[0]
        assert last["head_seq"] == result["head_seq"] and last["seq"] == recorded["seq"]
        assert last["seq"] == last["head_seq"] + 1
        assert env.post("/api/apps", json={"name": "after-check", "environment": "test"}).status_code in (200, 201)
        later = env.get("/api/overview").json()["audit"]
        assert later["last_verify"]["head_seq"] == result["head_seq"]
        assert later["head_seq"] > later["last_verify"]["seq"]
        with env.conn() as c:
            c.execute("UPDATE audit_events SET details = ? WHERE seq = ?", ('{"ok": true}', recorded["seq"]))
        assert env.get("/api/overview").json()["audit"]["last_verify"]["head_seq"] is None


def test_audit_export_is_ndjson_and_recorded(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        env.post("/api/apps", {"name": "exported", "environment": "test"})
        with env.conn() as c:
            head = audit.head(c)["seq"]
        response = env.get("/api/audit/export")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        assert response.headers["content-disposition"].startswith('attachment; filename="ferry-audit-')
        lines = response.text.splitlines()
        assert len(lines) == head
        assert [json.loads(line)["seq"] for line in lines] == list(range(1, head + 1))
        exported = env.events("audit.export")
        assert len(exported) == 1 and exported[0]["details"]["events"] == head


# --- inbox and jobs ----------------------------------------------------------------------------------------------


@pytest.fixture
def bundle_env(tmp_path: Path):
    setup = bundle_setup(tmp_path)
    with app_env(tmp_path / "data", imports=setup.imports) as env:
        yield env, setup


def test_inbox_lists_bundle_candidates_only(bundle_env, tmp_path: Path) -> None:
    env, setup = bundle_env
    copy_into(setup.inbox, setup.bundle)
    (setup.inbox / (setup.bundle.name + ".sha256")).write_text("x")
    (setup.inbox / "notes.review.md").write_text("x")
    (setup.inbox / ".hidden.ferry.tar").write_bytes(b"x")
    (setup.inbox / "with space.tar").write_bytes(b"x")
    (setup.inbox / "extracted").mkdir()
    (setup.inbox / "extracted" / "manifest.json").write_text("{}")
    outside = tmp_path / "outside.tar"
    outside.write_bytes(b"secret outside the inbox")
    os.symlink(outside, setup.inbox / "escape.tar")
    os.symlink(setup.inbox / setup.bundle.name, setup.inbox / "alias.tar")
    listing = env.get("/api/inbox").json()
    assert listing["inbox_dir"] == str(setup.inbox)
    items = {i["name"]: i for i in listing["items"]}
    assert sorted(items) == ["alias.tar", "extracted", setup.bundle.name]
    assert items[setup.bundle.name]["type"] == "tar" and items[setup.bundle.name]["size"] == setup.bundle.stat().st_size
    assert items["extracted"]["type"] == "dir" and items["extracted"]["size"] == 2
    assert items[setup.bundle.name]["last_verification"] is None and items[setup.bundle.name]["modified_at"]
    assert env.get("/api/overview").json()["inbox_pending"] == 3


@pytest.mark.parametrize("name", [
    "../x.tar", "sub/x.tar", "..", ".", ".hidden.tar", "x\\y.tar", "", "/etc/passwd", "x\x00.tar", "a" * 300,
    "%2e%2e", "x..tar", "..\\..\\x.tar", " x.tar", 123, None, ["x.tar"], {"name": "x.tar"},
])
def test_inbox_names_that_are_not_plain_entries_are_422(bundle_env, name: Any) -> None:
    env, _ = bundle_env
    for endpoint in ("/api/inbox/verify", "/api/inbox/import"):
        response = env.post(endpoint, {"name": name})
        assert response.status_code == 422, (name, response.text)
        assert response.json()["error"]["code"] == "invalid_name"


def test_inbox_symlinks_must_stay_inside_the_inbox(bundle_env, tmp_path: Path) -> None:
    env, setup = bundle_env
    outside = copy_into(tmp_path, setup.bundle, "outside.ferry.tar")
    os.symlink(outside, setup.inbox / "escape.ferry.tar")
    os.symlink("/etc", setup.inbox / "etc")
    os.symlink(setup.inbox / "nowhere.tar", setup.inbox / "dangling.tar")
    for name, code in (("escape.ferry.tar", "symlink_outside_inbox"), ("etc", "symlink_outside_inbox"),
                       ("dangling.tar", "broken_symlink")):
        response = env.post("/api/inbox/verify", {"name": name})
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == code
    sub = setup.inbox / "releases"
    sub.mkdir()
    copy_into(sub, setup.bundle)
    os.symlink(sub / setup.bundle.name, setup.inbox / "current.ferry.tar")
    accepted = env.post("/api/inbox/verify", {"name": "current.ferry.tar"})
    assert accepted.status_code == 202, accepted.text
    job = wait_for_job(env.client, accepted.json()["job_id"])
    assert job["state"] == "succeeded" and job["result"]["verdict"] == "accepted"
    assert job["source_name"] == "current.ferry.tar"


def test_missing_inbox_entries_and_unknown_jobs_are_404(bundle_env) -> None:
    env, _ = bundle_env
    assert env.post("/api/inbox/import", {"name": "absent.ferry.tar"}).status_code == 404
    assert env.post("/api/inbox/import", {"name": "x.tar", "force": True}).status_code == 422
    assert env.get(f"/api/jobs/{'a' * 32}").status_code == 404
    assert env.get("/api/jobs/../../etc").status_code == 404


def test_verify_and_import_jobs_record_their_results(bundle_env) -> None:
    env, setup = bundle_env
    name = copy_into(setup.inbox, setup.bundle).name
    verify = env.post("/api/inbox/verify", {"name": name})
    assert verify.status_code == 202
    job = wait_for_job(env.client, verify.json()["job_id"])
    assert job["kind"] == "verify" and job["state"] == "succeeded" and job["error"] is None
    assert job["result"]["verdict"] == "accepted" and job["result"]["already_imported"] is False
    assert job["result"]["report"]["report_version"] == 1
    assert job["progress"]["bytes_total"] > 0 and job["progress"]["bytes_done"] == job["progress"]["bytes_total"]
    assert job["started_at"] and job["finished_at"] and job["actor"] == "admin:alice"

    imported = wait_for_job(env.client, env.post("/api/inbox/import", {"name": name}).json()["job_id"])
    assert imported["result"]["verdict"] == "accepted" and imported["result"]["already_imported"] is False
    bundle_id = imported["result"]["bundle_id"]
    again = wait_for_job(env.client, env.post("/api/inbox/import", {"name": name}).json()["job_id"])
    assert again["result"]["already_imported"] is True

    bundles = env.get("/api/bundles").json()["items"]
    assert [b["bundle_id"] for b in bundles] == [bundle_id]
    assert bundles[0]["artifact_count"] == 3 and bundles[0]["signers"][0]["roles"] == ["publisher"]
    assert bundles[0]["imported_by"] == "admin:alice" and bundles[0]["source_name"] == name
    detail = env.get(f"/api/bundles/{bundle_id}").json()
    assert detail["manifest"]["bundle"]["name"] == "tiny-model"
    assert detail["report"]["verdict"] == "accepted"
    assert {a["path"] for a in detail["artifacts"]} == {"artifacts/models/tiny.gguf", "artifacts/docs/LICENSE",
                                                        "artifacts/tokenizer/tokenizer.json"}
    assert env.get(f"/api/bundles/{bundle_id.removeprefix('sha256:')}").status_code == 200
    assert env.get("/api/bundles/not-an-id").status_code == 404
    assert env.get(f"/api/bundles/sha256:{'1' * 64}").status_code == 404

    models = env.get("/api/models").json()["items"]
    assert len(models) == 1 and models[0]["model_name"] == "tiny-model" and models[0]["license"] == "Apache-2.0"
    assert models[0]["format"] == "gguf" and models[0]["in_store"] is True and models[0]["routes"] == []
    assert models[0]["metadata"]["gguf"]["architecture"] == "llama"

    history = env.get("/api/verifications", params={"limit": 10}).json()["items"]
    assert [(v["mode"], v["verdict"]) for v in history] == [("import", "accepted"), ("import", "accepted"),
                                                            ("verify", "accepted")]
    assert all(v["error_count"] == 0 and v["actor"] == "admin:alice" for v in history)
    one = env.get(f"/api/verifications/{history[-1]['id']}").json()
    assert one["report"]["bundle_id"] == bundle_id and one["mode"] == "verify"
    assert env.get("/api/verifications/999").status_code == 404
    assert env.get("/api/verifications", params={"limit": 0}).status_code == 422

    item = env.get("/api/inbox").json()["items"][0]
    assert item["imported"] is True and item["last_verification"]["verdict"] == "accepted"
    assert env.get("/api/overview").json()["inbox_pending"] == 0
    assert [e["outcome"] for e in env.events("bundle.verify")] == ["accepted"]
    assert [e["outcome"] for e in env.events("bundle.import")] == ["success", "success"]


def test_a_rejected_import_is_reported_and_records_nothing_in_the_store(bundle_env, tmp_path: Path) -> None:
    env, setup = bundle_env
    data = bytearray(setup.bundle.read_bytes())
    index = data.rfind(b"Apache License")
    data[index] ^= 0x01
    (setup.inbox / "tampered.ferry.tar").write_bytes(bytes(data))
    job = wait_for_job(env.client, env.post("/api/inbox/import", {"name": "tampered.ferry.tar"}).json()["job_id"])
    assert job["state"] == "succeeded" and job["result"]["verdict"] == "rejected"
    failed = [c["id"] for c in job["result"]["report"]["checks"] if c["status"] == "fail"]
    assert failed == ["artifact.digest"]
    assert env.get("/api/bundles").json()["items"] == []
    assert list((env.settings.store_dir / "sha256").iterdir()) == []
    item = env.get("/api/inbox").json()["items"][0]
    assert item["imported"] is False and item["last_verification"]["verdict"] == "rejected"
    overview = env.get("/api/overview").json()
    assert any("rejected" in a["message"] for a in overview["attention"])


def test_job_lifecycle_queued_running_succeeded_with_progress(bundle_env, monkeypatch: pytest.MonkeyPatch,
                                                              tmp_path: Path) -> None:
    env, setup = bundle_env
    names = [copy_into(setup.inbox, setup.bundle, f"b{i}.ferry.tar").name for i in range(3)]
    gate = threading.Event()
    started: list[str] = []
    lock = threading.Lock()

    def gated(real):
        def run(settings, database, source, *, actor_type, actor_id, progress=None, **kw):
            def report(done: int, total: int) -> None:
                progress(done, total)
                with lock:
                    first = source.name not in started
                    if first:
                        started.append(source.name)
                if first:
                    assert gate.wait(20)
            return real(settings, database, source, actor_type=actor_type, actor_id=actor_id, progress=report, **kw)
        return run

    monkeypatch.setattr(importer, "import_bundle", gated(importer.import_bundle))
    monkeypatch.setattr(importer, "verify_only", gated(importer.verify_only))
    first = env.post("/api/inbox/import", {"name": names[0]}).json()["job_id"]
    second = env.post("/api/inbox/verify", {"name": names[1]}).json()["job_id"]
    third = env.post("/api/inbox/verify", {"name": names[2]}).json()["job_id"]
    assert env.post("/api/inbox/import", {"name": names[0]}).json()["job_id"] == first, "identical job reused"
    deadline = time.monotonic() + 20
    while len(started) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    states = {j: env.get(f"/api/jobs/{j}").json() for j in (first, second, third)}
    assert states[first]["state"] == states[second]["state"] == "running"
    assert states[third]["state"] == "queued" and states[third]["started_at"] is None
    assert states[first]["progress"]["bytes_total"] > 0
    assert states[first]["progress"]["bytes_done"] <= states[first]["progress"]["bytes_total"]
    assert states[third]["result"] is None
    gate.set()
    done = [wait_for_job(env.client, j) for j in (first, second, third)]
    assert [d["state"] for d in done] == ["succeeded"] * 3
    assert [d["result"]["verdict"] for d in done] == ["accepted"] * 3
    assert all(d["progress"]["bytes_done"] == d["progress"]["bytes_total"] for d in done)


def test_a_job_that_raises_is_failed_with_its_message(bundle_env, monkeypatch: pytest.MonkeyPatch) -> None:
    env, setup = bundle_env
    name = copy_into(setup.inbox, setup.bundle).name

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise FerryError("the inbox disk went away")

    monkeypatch.setattr(importer, "verify_only", broken)
    job = wait_for_job(env.client, env.post("/api/inbox/verify", {"name": name}).json()["job_id"])
    assert job["state"] == "failed" and job["error"] == "the inbox disk went away" and job["result"] is None
    assert [e["outcome"] for e in env.events("bundle.verify")] == ["error"]


# --- trust, evidence, system ---------------------------------------------------------------------------------------------


def test_trust_listing_shows_entries_and_problems(bundle_env) -> None:
    env, setup = bundle_env
    (setup.workspace.trust_dir / "junk.txt").write_text("x")
    revoked = make_signer("old")
    add_key(setup.workspace.trust_dir, revoked.pem, name="Old key", roles=["reviewer"],
            not_after="2020-01-01T00:00:00Z")
    trust = env.get("/api/trust").json()
    assert trust["trust_dir"] == str(setup.workspace.trust_dir)
    assert trust["required_roles"] == ["publisher"] and trust["distinct_signers"] is True
    statuses = {i["name"]: i["status"] for i in trust["items"]}
    assert statuses == {"Acme build": "active", "Acme review": "active", "Old key": "expired"}
    assert all("public_key_pem" not in i for i in trust["items"])
    assert any("junk.txt" in p for p in trust["problems"])
    assert env.get("/api/overview").json()["counts"]["trusted_keys"] == 2


def test_evidence_json_and_markdown_downloads(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        report = env.get("/api/evidence").json()
        assert "not a compliance certification" in report["statement"]
        assert report["audit"]["ok"] is True and report["ferry_version"]
        markdown = env.get("/api/evidence.md")
        assert markdown.status_code == 200
        assert markdown.headers["content-type"].startswith("text/markdown")
        assert markdown.headers["content-disposition"].startswith('attachment; filename="ferry-evidence-')
        assert markdown.text.startswith("# Ferry evidence report")


def test_system_endpoint(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        system = env.get("/api/system").json()
        assert system["version"] and system["python"] and system["platform"]
        assert system["config"]["data_dir"] == str(env.settings.data_dir)
        names = {d["name"].lower() for d in system["dependencies"]}
        assert {"fastapi", "uvicorn", "httpx", "cryptography", "pydantic", "starlette"} <= names
        assert system["network_inventory"][0]["direction"] == "inbound"


def test_healthz_needs_no_session_and_says_nothing_else(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        response = env.get("/healthz")
        assert response.status_code == 200 and response.json() == {"status": "ok"}


def test_unknown_api_paths_are_json_404(shared: AppEnv) -> None:
    shared.as_admin()
    for method in ("GET", "POST", "DELETE"):
        response = shared.client.request(method, "/api/does/not/exist", headers=CSRF)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


# --- overview -------------------------------------------------------------------------------------------------------------


def test_overview_numbers_come_from_rows_and_audit_events(tmp_path: Path) -> None:
    with FakeUpstream() as upstream, app_env(tmp_path / "data") as env:
        with env.conn() as c:
            _, key_one = add_app(c, "app-one", environment="test")
            _, key_two = add_app(c, "app-two", environment="pilot")
            digest = store_artifact(env.settings, c, b"GGUF bytes for the overview test")
            upstream.model_path = store_path(env.settings, digest)
            backend_id = add_backend(c, env.settings, upstream.base_url, token=upstream.token)
            backends.create_route(c, model="m1", backend_id=backend_id, upstream_model="alias", artifact_digest=digest,
                                  require_verified=True, **ACTOR)
            activate(c, allow("one", ["app:app-one"], ["m1"]))
        assert env.post(f"/api/backends/{backend_id}/check").json()["status"]["state"] == "up"
        statuses = [
            env.client.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key_one)).status_code,
            env.client.post("/v1/chat/completions", json=chat_body("m1", stream=True),
                            headers=bearer(key_one)).status_code,
            env.client.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key_two)).status_code,
            env.client.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer("fyk_nope")).status_code,
            env.client.post("/v1/chat/completions", json={"model": "m1"}, headers=bearer(key_one)).status_code,
            env.client.post("/v1/chat/completions", json=chat_body("m2"), headers=bearer(key_two)).status_code,
        ]
        assert statuses == [200, 200, 403, 401, 400, 403]
        overview = env.get("/api/overview").json()
        chats = env.events("gateway.chat.completions")
        assert len(chats) == 6
        by_outcome = Counter(e["outcome"] for e in chats)
        traffic = overview["traffic_24h"]
        assert traffic["total"] == len(chats)
        for outcome in ("success", "denied", "error", "unavailable", "rejected", "unauthenticated"):
            assert traffic[outcome] == by_outcome.get(outcome, 0), outcome
        assert (traffic["success"], traffic["denied"], traffic["unauthenticated"], traffic["rejected"]) == (2, 2, 1, 1)
        latencies = sorted(e["details"]["latency_ms"] for e in chats if e["outcome"] == "success")
        assert traffic["p50_ms"] == latencies[math.ceil(0.5 * len(latencies)) - 1]
        assert traffic["p95_ms"] == latencies[math.ceil(0.95 * len(latencies)) - 1]
        by_env = Counter(e["details"]["environment"] for e in chats if e["details"].get("environment"))
        assert overview["traffic_by_environment_24h"] == {"test": by_env["test"], "pilot": by_env["pilot"],
                                                          "production": 0}
        assert overview["traffic_by_environment_24h"] == {"test": 3, "pilot": 2, "production": 0}
        assert overview["counts"] == {"apps": 2, "active_keys": 2, "backends": 1, "routes": 1, "bundles": 1,
                                      "model_artifacts": 1, "trusted_keys": 0}
        assert overview["policy"]["version"] == 1 and overview["policy"]["rule_count"] == 1
        assert overview["backends"] == [{"id": backend_id, "name": "llama", "kind": "llamacpp", "enabled": True,
                                         "state": "up", "checked_at": overview["backends"][0]["checked_at"]}]
        assert overview["routes"] == [{"model": "m1", "backend": "llama", "provenance": "verified", "available": True,
                                       "reason": None}]
        with env.conn() as c:
            head = audit.head(c)
        assert overview["audit"]["head_seq"] == head["seq"] and overview["audit"]["head_hash"] == head["hash"]
        assert overview["audit"]["last_verify"] is None
        assert overview["started_at"] and overview["version"]
        messages = [a["message"] for a in overview["attention"]]
        assert any("No trusted signing keys" in m for m in messages)
        assert not any("No access policy" in m for m in messages)
        assert len(upstream.chat_requests()) == 2, "denied, invalid and unauthenticated requests never reach the backend"


# --- login throttle under concurrency (GWS-1) -------------------------------------------------


def test_login_throttle_holds_under_concurrency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The sign-in endpoint runs in the thread pool, so a burst of guesses must not
    all pass the throttle check before any of them is counted. Password checks are
    held open until the burst has been answered, which is the worst interleaving."""
    with app_env(tmp_path / "data", login_as=None) as env:
        state = env.client.app.state.ferry
        throttle = env.client.app.state.ferry_admin.throttle
        release = threading.Event()
        original = auth.authenticate_admin

        def held(conn: Any, username: object, password: object) -> Any:
            release.wait(10)
            return original(conn, username, password)

        monkeypatch.setattr(auth, "authenticate_admin", held)
        burst = 20
        barrier = threading.Barrier(burst)
        results: list[Any] = []
        lock = threading.Lock()

        def attempt(i: int) -> None:
            barrier.wait()
            try:
                outcome: Any = admin_api._login(state, throttle, "alice", f"wrong-guess-{i:04d}",
                                                f"10.0.{i}.1", f"rid{i}")
            except ApiError as exc:
                outcome = exc.status
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(burst)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with lock:
                if len(results) >= burst - 5:
                    break
            time.sleep(0.01)
        # The right password, sent while the guesses are still being checked, is refused too.
        try:
            right: Any = admin_api._login(state, throttle, "alice", "alice-password-1234", "10.9.9.9", "rid-right")
        except ApiError as exc:
            right = exc.status
        release.set()
        for t in threads:
            t.join(15)
        assert Counter(results) == {401: 5, 429: burst - 5}
        assert right == 429, "a burst must not get more than five password checks for one account"
        with pytest.raises(ApiError) as locked:
            admin_api._login(state, throttle, "alice", "alice-password-1234", "10.9.9.9", "rid-after")
        assert locked.value.status == 429
        assert "Try again in" in locked.value.message


def test_throttle_begin_and_finish_count_in_flight_attempts() -> None:
    throttle = auth.LoginThrottle(clock=lambda: 1000.0)
    for _ in range(5):
        assert throttle.begin("alice", "10.0.0.1") is None
    refusal = throttle.begin("alice", "10.0.0.2")
    assert refusal is not None and refusal.busy and refusal.retry_after_s == throttle.busy_retry_s
    for _ in range(4):
        assert throttle.finish("alice", "10.0.0.1", ok=False) is None
    assert throttle.finish("alice", "10.0.0.1", ok=False) == 900
    refusal = throttle.begin("alice", "10.0.0.3")
    assert refusal is not None and not refusal.busy and refusal.retry_after_s == 900
    # A success clears the name; the address keeps its count, and successes never count against it.
    assert throttle.begin("bob", "10.0.0.4") is None
    assert throttle.finish("bob", "10.0.0.4", ok=True) is None
    for _ in range(30):
        assert throttle.begin("carol", "10.0.0.5") is None
        throttle.finish("carol", "10.0.0.5", ok=True)


def test_concurrent_password_checks_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each scrypt check holds 32 MiB, so a burst across many names and addresses
    must not run more than SCRYPT_CONCURRENCY of them at once."""
    stored = auth.hash_password("alice-password-1234")
    real = auth.hashlib.scrypt
    active, peak = [0], [0]
    lock = threading.Lock()

    def counting(*args: Any, **kwargs: Any) -> bytes:
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            time.sleep(0.05)
            return real(*args, **kwargs)
        finally:
            with lock:
                active[0] -= 1

    monkeypatch.setattr(auth.hashlib, "scrypt", counting)
    barrier = threading.Barrier(16)
    outcomes: list[bool] = []

    def check() -> None:
        barrier.wait()
        outcomes.append(auth.verify_password("wrong-password-xx", stored))

    threads = [threading.Thread(target=check) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert outcomes == [False] * 16
    assert peak[0] <= auth.SCRYPT_CONCURRENCY
