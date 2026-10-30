"""Security properties of the assembled server application (spec sections 6 and 9):
security headers and the exact CSP on every response, docs/OpenAPI routes off,
session cookie flags, the login throttle, CSRF origin matching, CORS scope,
session expiry, error hygiene (no stack traces, no echoed input), and the
console fallback when it was not built.
"""

from __future__ import annotations

import datetime as _dt
import http.cookies
import json
from pathlib import Path

import pytest

from ferry.config import ServerSettings
from ferry.gateway import admin_api
from ferry.gateway.app import STATIC_DIR
from ferry.util import rfc3339, utc_now

from helpers_app import (ADMIN_PASSWORD, ADMIN_USER, AUDITOR_PASSWORD, AUDITOR_USER, CSP, CSRF, app_env)
from helpers_gateway import add_app, bearer

SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


def assert_security_headers(response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, f"{name} on {response.request.method} {response.request.url}"
    assert len(response.headers.get_list("content-security-policy")) == 1


def _asset(suffix: str) -> str:
    return next(p.name for p in sorted((STATIC_DIR / "assets").iterdir()) if p.suffix == suffix)


def test_every_kind_of_response_carries_the_security_headers(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        with env.conn() as c:
            _, key = add_app(c, "header-app")
        signed_in = [env.get("/"), env.get(f"/assets/{_asset('.js')}"), env.get(f"/assets/{_asset('.css')}"),
                     env.get(f"/assets/{_asset('.woff2')}"), env.get("/healthz"), env.get("/api/overview"),
                     env.get("/api/evidence.md"), env.get("/api/audit/export"), env.get("/v1/models", headers=bearer(key)),
                     env.get("/docs"), env.get("/openapi.json"), env.get("/no/such/page"), env.get("/assets/missing.js"),
                     env.get("/api/no/such/endpoint"), env.post("/api/apps", {"name": "Bad Name", "environment": "x"}),
                     env.client.post("/api/apps", json={}), env.client.put("/healthz"),
                     env.client.post("/v1/chat/completions", content=b"x" * (2 * 1024 * 1024),
                                     headers={**bearer(key), "Content-Type": "application/json"}),
                     env.client.post("/api/policy/validate", content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
                                     headers={**CSRF, "Content-Type": "application/json"})]
        env.logout_locally()
        signed_out = [env.get("/api/overview"), env.get("/v1/models"), env.client.post("/v1/chat/completions", json={}),
                      env.get("/v1/unknown"), env.post("/api/auth/login", {"username": "x", "password": "y" * 12})]
        statuses = [r.status_code for r in signed_in + signed_out]
        assert statuses == [200, 200, 200, 200, 200, 200, 200, 200, 200, 404, 404, 404, 404, 404, 422, 403, 405, 413,
                            413, 401, 401, 401, 404, 401]
        for response in signed_in + signed_out:
            assert_security_headers(response)
            path = response.request.url.path
            if path.startswith(("/api/", "/healthz")):
                assert response.headers["cache-control"] == "no-store", path
            if path.startswith(("/api/", "/v1/")):
                assert response.headers.get("x-request-id"), path


def test_console_files_are_served_with_their_types(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        index = env.get("/")
        assert index.headers["content-type"].startswith("text/html")
        assert index.headers["cache-control"] == "no-cache"
        assert '<div id="root">' in index.text
        assert env.get(f"/assets/{_asset('.js')}").headers["content-type"].startswith("text/javascript")
        assert env.get(f"/assets/{_asset('.css')}").headers["content-type"].startswith("text/css")
        assert env.get(f"/assets/{_asset('.woff2')}").headers["content-type"] == "font/woff2"
        assert env.get("/assets/../ferry.db").status_code == 404
        assert env.get("/assets/%2e%2e/%2e%2e/config.py").status_code == 404


def test_a_console_that_was_not_built_gets_a_plain_notice(tmp_path: Path) -> None:
    empty = tmp_path / "static"
    empty.mkdir()
    with app_env(tmp_path / "data", static_dir=empty, login_as=None) as env:
        response = env.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "has not been built" in response.text
        assert_security_headers(response)
        assert env.get("/assets/index.js").status_code == 404
        assert env.get("/healthz").status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/api/openapi.json",
                                  "/api/docs"])
def test_interactive_docs_and_the_openapi_schema_are_not_served(tmp_path: Path, path: str) -> None:
    with app_env(tmp_path / "data", users=False) as env:
        response = env.get(path)
        assert response.status_code == 404
        assert "swagger" not in response.text.lower() and "openapi" not in response.text.lower()


@pytest.mark.parametrize("mode, base_url, secure", [
    ("auto", "http://127.0.0.1:8750", False),
    ("auto", "http://localhost:8750", False),
    ("auto", "http://[::1]:8750", False),
    ("auto", "http://ferry.internal:8750", True),
    ("auto", "http://10.0.0.5:8750", True),
    ("auto", "https://ferry.internal", True),
    ("auto", "https://127.0.0.1:8750", True),
    ("true", "http://127.0.0.1:8750", True),
    ("false", "https://ferry.internal", False),
])
def test_session_cookie_flags(tmp_path: Path, mode: str, base_url: str, secure: bool) -> None:
    with app_env(tmp_path / "data", login_as=None, base_url=base_url,
                 server=ServerSettings(cookie_secure=mode)) as env:
        response = env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD})
        assert response.status_code == 200, response.text
        headers = response.headers.get_list("set-cookie")
        assert len(headers) == 1
        raw = headers[0]
        cookie = http.cookies.SimpleCookie()
        cookie.load(raw)
        morsel = cookie["ferry_session"]
        assert len(morsel.value) == 43
        assert morsel["httponly"] is True
        assert morsel["path"] == "/"
        assert "SameSite=Strict" in raw
        assert bool(morsel["secure"]) is secure, raw
        assert not morsel["max-age"] and not morsel["expires"], "a browser-session cookie; the server enforces expiry"
        assert not morsel["domain"]


def test_login_throttle_per_username(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        for _ in range(5):
            assert env.post("/api/auth/login", {"username": ADMIN_USER, "password": "wrong-password!"}).status_code == 401
        locked = env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD})
        assert locked.status_code == 429, locked.text
        body = locked.json()
        assert 0 < body["retry_after_s"] <= 900
        assert body["error"]["code"] == "too_many_attempts"
        assert body["error"]["details"]["retry_after_s"] == body["retry_after_s"]
        assert int(locked.headers["retry-after"]) == body["retry_after_s"]
        assert env.client.cookies.get("ferry_session") is None
        other = env.post("/api/auth/login", {"username": AUDITOR_USER, "password": AUDITOR_PASSWORD})
        assert other.status_code == 200, "one user's lock does not lock out the others"
        logins = env.events("auth.login")
        assert [e["outcome"] for e in logins] == ["failure"] * 5 + ["denied", "success"]
        assert all(e["details"]["reason"] == "bad_password" and e["actor_id"] == ADMIN_USER for e in logins[:5])
        assert logins[5]["details"]["reason"] == "throttled" and logins[5]["details"]["throttled"] is True
        assert logins[6]["actor_id"] == AUDITOR_USER
        assert "wrong-password!" not in json.dumps(logins)


def test_login_throttle_per_client_address(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        for i in range(20):
            response = env.post("/api/auth/login", {"username": f"guess{i}", "password": "wrong-password!"})
            assert response.status_code == 401
        locked = env.post("/api/auth/login", {"username": AUDITOR_USER, "password": AUDITOR_PASSWORD})
        assert locked.status_code == 429
        assert locked.json()["retry_after_s"] > 0


def test_origin_comparison_normalizes_default_ports_and_case(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None, base_url="http://ferry.internal") as env:
        for origin in ("http://ferry.internal", "http://ferry.internal:80", "http://FERRY.internal"):
            response = env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD},
                                headers={"Origin": origin})
            assert response.status_code == 200, (origin, response.text)
        for origin in ("http://ferry.internal:8080", "https://ferry.internal", "http://ferry.internal.evil.example",
                       "http://ferry.internal/path", "file://", "ferry.internal"):
            response = env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD},
                                headers={"Origin": origin})
            assert response.status_code == 403, origin


def test_cors_is_off_unless_configured(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", login_as=None) as env:
        preflight = env.client.options("/v1/chat/completions", headers={
            "Origin": "http://apps.internal:3000", "Access-Control-Request-Method": "POST"})
        assert "access-control-allow-origin" not in preflight.headers
        simple = env.get("/v1/models", headers={"Origin": "http://apps.internal:3000"})
        assert "access-control-allow-origin" not in simple.headers


def test_configured_cors_covers_the_inference_api_only_and_never_credentials(tmp_path: Path) -> None:
    allowed = "http://apps.internal:3000"
    with app_env(tmp_path / "data", login_as=None, server=ServerSettings(cors_origins=(allowed,))) as env:
        request = {"Origin": allowed, "Access-Control-Request-Method": "POST",
                   "Access-Control-Request-Headers": "authorization, content-type"}
        preflight = env.client.options("/v1/chat/completions", headers=request)
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == allowed
        assert "access-control-allow-credentials" not in preflight.headers
        assert_security_headers(preflight)
        other = env.client.options("/v1/chat/completions", headers={**request, "Origin": "http://evil.example"})
        assert other.headers.get("access-control-allow-origin") != "http://evil.example"
        admin = env.client.options("/api/apps", headers=request)
        assert "access-control-allow-origin" not in admin.headers
        login = env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD},
                         headers={"Origin": allowed})
        assert login.status_code == 403, "a CORS origin is still cross-origin for the admin API"


def test_idle_and_absolute_session_limits_are_enforced(tmp_path: Path) -> None:
    with app_env(tmp_path / "data", server=ServerSettings(session_idle_minutes=5, session_max_hours=8)) as env:
        assert env.get("/api/auth/me").status_code == 200
        stale = rfc3339(utc_now() - _dt.timedelta(minutes=6))
        with env.conn() as c:
            c.execute("UPDATE sessions SET last_seen_at = ?", (stale,))
        assert env.get("/api/auth/me").status_code == 401
        with env.conn() as c:
            assert c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        env.as_admin()
        old = rfc3339(utc_now() - _dt.timedelta(hours=9))
        with env.conn() as c:
            c.execute("UPDATE sessions SET created_at = ?", (old,))
        assert env.get("/api/overview").status_code == 401


def test_a_disabled_console_user_loses_access_at_once(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        assert env.get("/api/auth/me").status_code == 200
        with env.conn() as c:
            c.execute("UPDATE admin_users SET disabled = 1 WHERE username = ?", (ADMIN_USER,))
        assert env.get("/api/auth/me").status_code == 401
        assert env.post("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD}).status_code == 401


def test_api_keys_and_sessions_do_not_cross_over(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        with env.conn() as c:
            _, key = add_app(c, "crossover")
        assert env.get("/v1/models").status_code == 401, "a console session is not an API key"
        cookie = env.client.cookies.get("ferry_session")
        env.logout_locally()
        assert env.get("/api/overview", headers=bearer(key)).status_code == 401, "an API key is not a console session"
        assert env.get("/api/overview", headers={"Authorization": f"Bearer {cookie}"}).status_code == 401


def test_unhandled_errors_are_a_generic_500_with_headers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("internal detail fyk_123456789abc_should-never-leak")

    monkeypatch.setattr(admin_api, "build_overview", explode)
    with app_env(tmp_path / "data") as env:
        response = env.get("/api/overview", headers={"X-Request-ID": "trace-me-123"})
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "internal_error"
        assert "trace-me-123" in response.json()["error"]["message"]
        assert "should-never-leak" not in response.text and "Traceback" not in response.text
        assert response.headers["x-request-id"] == "trace-me-123"
        assert response.headers["cache-control"] == "no-store"
        assert_security_headers(response)


def test_validation_errors_never_echo_submitted_values(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        marker = "SECRET-MARKER-9f8e7d"
        checks = [
            env.post("/api/apps", {"name": f"{marker} x", "environment": "test"}),
            env.post("/api/apps", {"name": "fine", "environment": marker}),
            env.patch(f"/api/backends/{marker}", {"enabled": False}),
            env.get("/api/verifications", params={"limit": marker}),
            env.get("/api/audit", params={"since": marker}),
            env.post("/api/backends", {"name": "b", "kind": marker, "base_url": "http://127.0.0.1:9"}),
            env.post("/api/policy/explain", {"app": marker, "model": "m"}),
        ]
        for response in checks:
            assert response.status_code == 422, response.text
            assert marker not in response.text, response.request.url


def test_request_ids_are_echoed_only_when_safe(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        assert env.get("/api/auth/me", headers={"X-Request-ID": "abc.DEF-123_x"}).headers["x-request-id"] == "abc.DEF-123_x"
        for unsafe in ("bad id with spaces", "x" * 65, "semi;colon", "<script>"):
            generated = env.get("/api/auth/me", headers={"X-Request-ID": unsafe}).headers["x-request-id"]
            assert generated != unsafe and len(generated) == 32 and generated.isalnum()


def test_host_only_operations_have_no_web_endpoint(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        for method, path in (("POST", "/api/trust"), ("POST", "/api/trust/add"), ("POST", "/api/admin/users"),
                             ("POST", "/api/users"), ("PATCH", "/api/config"), ("PUT", "/api/system"),
                             ("DELETE", "/api/audit/1"), ("PATCH", "/api/audit/1")):
            response = env.client.request(method, path, headers=CSRF, json={})
            assert response.status_code in (404, 405), (method, path)
        with env.conn() as c:
            assert [r[0] for r in c.execute("SELECT username FROM admin_users ORDER BY username")] == [
                ADMIN_USER, AUDITOR_USER]
            assert c.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'trust.add'").fetchone()[0] == 0


def test_error_bodies_use_the_ferry_shape(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        assert env.post("/api/apps", {"name": "dup", "environment": "test"}).status_code == 201
        for response in (env.post("/api/apps", {"name": "x"}), env.get("/api/verifications/999"),
                         env.post("/api/apps", {"name": "dup", "environment": "test"})):
            assert response.headers["content-type"].startswith("application/json")
            error = response.json()["error"]
            assert set(error) <= {"code", "message", "details"} and error["code"] and error["message"]
        assert env.post("/api/apps", {"name": "dup", "environment": "test"}).status_code == 409
        assert json.loads(env.post("/api/apps", {"name": "dup", "environment": "test"}).text)["error"]["code"] == "conflict"
