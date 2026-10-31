"""Console security: sessions, roles, CSRF, cookie flags and response headers.

Everything here is enforced on the server for every request; the console's own
role checks only decide which controls it shows.

- Sessions: the `ferry_session` cookie carries a random token; the database
  keeps its SHA-256 (ferry.auth). `current_user` resolves it per request and
  answers 401 when it is missing, unknown or expired.
- Roles: `admin` may do everything, `auditor` may read and run the three
  read-only POSTs (audit verify, policy validate, policy explain). Any other
  role value is treated as no access.
- CSRF: every request under /api/ whose method is not GET, HEAD or OPTIONS
  (login included) must carry `X-Ferry-CSRF: 1`, and an `Origin` header, when
  present, must equal the request's own origin. A browser cannot add the custom
  header to a cross-site request without a CORS preflight, which Ferry never
  grants for /api. Checked in middleware, before routing, so no endpoint can
  forget it.
- Cookie flags: HttpOnly, SameSite=Strict, Path=/, and Secure according to
  `server.cookie_secure` ("auto" = Secure unless the request is plain HTTP to a
  loopback host).
- Headers: a fixed Content-Security-Policy and friends on every response,
  `Cache-Control: no-store` on /api and /healthz. An unhandled exception
  becomes a generic 500 that still carries these headers and no exception text.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from fastapi import Depends, Request
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from .. import auth
from ..config import Settings
from ..errors import operator_detail, operator_traceback
from .limits import ASGIApp, Message, Receive, Scope, Send, request_id_for

log = logging.getLogger("ferry.gateway.security")

SESSION_COOKIE = auth.SESSION_COOKIE
CSRF_HEADER = "X-Ferry-CSRF"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ADMIN = "admin"
AUDITOR = "auditor"
KNOWN_ROLES = (ADMIN, AUDITOR)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode("ascii")),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
)
_REPLACED = frozenset(name for name, _ in SECURITY_HEADERS)
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


# --- errors ------------------------------------------------------------------


class ApiError(Exception):
    """An admin API error answer: `{"error": {"code", "message", "details"?}}`.

    `message` is shown to the console user, so it never contains secrets.
    `extra` adds top-level keys next to `error` (used for 429 retry_after_s and
    the policy activation 422 `validation`)."""

    def __init__(self, status: int, code: str, message: str, *, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}
        self.extra = extra or {}

    def body(self) -> dict[str, Any]:
        return error_body(self.code, self.message, self.details, self.extra)


def error_body(code: str, message: str, details: dict[str, Any] | None = None,
               extra: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return {"error": error, **(extra or {})}


def is_api_path(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


async def send_api_error(send: Send, scope: Scope, status: int, code: str, message: str) -> None:
    """Answer from inside middleware, before any route runs."""
    data = json.dumps(error_body(code, message), separators=(",", ":")).encode("utf-8")
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(data)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-request-id", request_id_for(scope).encode("ascii")),
    ]})
    await send({"type": "http.response.body", "body": data, "more_body": False})


# --- sessions and roles ------------------------------------------------------


@dataclass(frozen=True)
class SessionUser:
    """The console user behind the current request."""

    user_id: int
    username: str
    role: str
    expires_at: str
    token: str = field(repr=False)
    """The raw cookie value; needed only to end the session at logout."""

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN


def _gateway_state(request: Request) -> Any:
    state = getattr(request.app.state, "ferry", None)
    if state is None:
        raise RuntimeError("app.state.ferry is not set; create the app with ferry.gateway.app.create_app")
    return state


def current_user(request: Request) -> SessionUser:
    """Dependency: the signed-in console user, or 401. Synchronous on purpose:
    FastAPI runs it in the thread pool, so the database lookup never blocks the loop."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise ApiError(401, "not_authenticated", "Sign in to use the console API.")
    state = _gateway_state(request)
    with state.db.session() as conn:
        session = auth.resolve_session(conn, token, state.settings)
    if session is None or session.get("role") not in KNOWN_ROLES:
        raise ApiError(401, "not_authenticated", "Your session has ended or is not valid. Sign in again.")
    return SessionUser(user_id=int(session["user_id"]), username=str(session["username"]), role=str(session["role"]),
                       expires_at=str(session["expires_at"]), token=token)


def require_roles(*roles: str) -> Callable[..., SessionUser]:
    """Dependency factory: the signed-in user if their role is one of `roles`, else 403."""
    allowed = frozenset(roles)
    label = " or ".join(sorted(allowed))

    def dependency(user: SessionUser = Depends(current_user)) -> SessionUser:
        if user.role not in allowed:
            raise ApiError(403, "forbidden", f"This action needs the {label} role; you are signed in as "
                                             f"{user.role}.")
        return user

    return dependency


# Every v1 role may read; admin-only endpoints say so explicitly.
any_role = require_roles(ADMIN, AUDITOR)
admin_only = require_roles(ADMIN)
admin_or_auditor = require_roles(ADMIN, AUDITOR)


# --- origins, loopback and cookies ----------------------------------------------


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _host_port(authority: str) -> tuple[str, int | None] | None:
    """Split a Host header value into (lowercase host, port or None)."""
    try:
        parts = urllib.parse.urlsplit("//" + authority)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or parts.username is not None or parts.path or parts.query or parts.fragment:
        return None
    return host.lower(), port


def _origin(scheme: str, host: str, port: int | None) -> str:
    default = 443 if scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}" + (f":{port}" if port is not None and port != default else "")


def normalize_origin(value: str) -> str | None:
    """`scheme://host[:port]` with the default port dropped, or None if `value`
    is not an http(s) origin (an `Origin: null` header, for example)."""
    try:
        parts = urllib.parse.urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname or parts.username is not None:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    return _origin(scheme, parts.hostname.lower(), port)


def request_origin(scope: Scope) -> str | None:
    """The request's own origin: its scheme plus the Host it was addressed to."""
    scheme = str(scope.get("scheme") or "http").lower()
    host = _header(scope, b"host")
    if host:
        split = _host_port(host)
        if split is None:
            return None
        return _origin(scheme, *split)
    server = scope.get("server")
    if server and server[0]:
        return _origin(scheme, str(server[0]).lower(), int(server[1]) if server[1] else None)
    return None


def csrf_problem(scope: Scope) -> str | None:
    """Why a state-changing /api request fails the CSRF rule, or None if it passes."""
    if _header(scope, CSRF_HEADER.lower().encode("ascii")) != "1":
        return f"Missing CSRF header: state-changing requests must send '{CSRF_HEADER}: 1'."
    origin = _header(scope, b"origin")
    if origin is not None:
        own = request_origin(scope)
        if own is None or normalize_origin(origin) != own:
            return "Cross-origin request refused: the Origin header does not match this server."
    return None


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    name = host.strip().lower().rstrip(".")
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if name in _LOOPBACK_NAMES or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def cookie_secure(settings: Settings, scope: Scope) -> bool:
    """Whether the session cookie gets the Secure flag (server.cookie_secure)."""
    mode = settings.server.cookie_secure
    if mode == "true":
        return True
    if mode == "false":
        return False
    if str(scope.get("scheme") or "http").lower() == "https":
        return True
    host = _header(scope, b"host")
    if host is not None:
        split = _host_port(host)
        name = split[0] if split else None  # a malformed Host counts as not loopback: Secure
    else:
        name = str(scope["server"][0]) if scope.get("server") else None
    return not is_loopback_host(name)


def set_session_cookie(response: Response, token: str, *, secure: bool) -> None:
    # No Max-Age: the cookie ends with the browser session; the server enforces
    # the idle and absolute limits whatever the browser keeps.
    response.set_cookie(SESSION_COOKIE, token, path="/", secure=secure, httponly=True, samesite="Strict")  # type: ignore[arg-type]


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="Strict")  # type: ignore[arg-type]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# --- middleware --------------------------------------------------------------


class CSRFMiddleware:
    """Pure ASGI: refuses state-changing /api requests that fail `csrf_problem` with 403."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] == "http" and is_api_path(scope.get("path", ""))
                and str(scope.get("method", "GET")).upper() not in SAFE_METHODS):
            problem = csrf_problem(scope)
            if problem is not None:
                await send_api_error(send, scope, 403, "csrf_failed", problem)
                return
        await self.app(scope, receive, send)


def _no_store(path: str) -> bool:
    return is_api_path(path) or path == "/healthz"


class SecurityHeadersMiddleware:
    """Pure ASGI, outermost: the security headers on every response, no-store on
    /api and /healthz, and a header-carrying 500 for unhandled exceptions."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        no_store = _no_store(path)
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": with_security_headers(message.get("headers") or (), no_store)}
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception as exc:
            if started:
                raise
            rid = request_id_for(scope)
            # The exception text can carry request data, so it is logged only for the
            # kinds whose text is fixed by the system; the stack is logged without it.
            log.error("unhandled %s for %s %s (request id %s)\n%s", operator_detail(exc), scope.get("method"),
                      path, rid, operator_traceback(exc))
            await _internal_error(send, path, rid)


def with_security_headers(headers: Iterable[tuple[bytes, bytes]], no_store: bool) -> list[tuple[bytes, bytes]]:
    drop = _REPLACED | ({b"cache-control", b"pragma"} if no_store else frozenset())
    out = [(k, v) for k, v in headers if k.lower() not in drop]
    out.extend(SECURITY_HEADERS)
    if no_store:
        out.append((b"cache-control", b"no-store"))
    return out


async def _internal_error(send: Send, path: str, rid: str) -> None:
    if path.startswith("/v1/"):
        body: dict[str, Any] = {"error": {"message": f"Internal error (request id {rid}).", "type": "internal_error",
                                          "code": "internal_error", "param": None}}
    else:
        body = error_body("internal_error", f"Internal error (request id {rid}). The server log has the details.")
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = with_security_headers([
        (b"content-type", b"application/json"),
        (b"content-length", str(len(data)).encode("ascii")),
        (b"x-request-id", rid.encode("ascii")),
    ], True)
    await send({"type": "http.response.start", "status": 500, "headers": headers})
    await send({"type": "http.response.body", "body": data, "more_body": False})


class InferenceCORSMiddleware:
    """CORS for the OpenAI-compatible API only, and only when server.cors_origins
    is set. Credentials are never allowed, so a configured origin can call /v1
    with an API key but can never use a console session; /api never gets CORS."""

    def __init__(self, app: ASGIApp, origins: Iterable[str]) -> None:
        self.app = app
        self.cors = CORSMiddleware(
            app, allow_origins=list(origins), allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"], allow_credentials=False,
            expose_headers=["X-Request-ID", "X-Ferry-Max-Tokens", "Retry-After"], max_age=600,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and str(scope.get("path", "")).startswith("/v1/"):
            await self.cors(scope, receive, send)
        else:
            await self.app(scope, receive, send)
