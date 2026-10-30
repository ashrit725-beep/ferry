"""The Ferry server application: gateway, admin API and console in one process.

`create_app(settings)` assembles:

- the OpenAI-compatible API (ferry.gateway.openai_api, /v1) and the admin API
  (ferry.gateway.admin_api, /api), plus GET /healthz;
- the built console from ferry/static (index.html at /, files under /assets);
  if it was not built, / says so in plain text;
- middleware, outermost first: security headers (and a header-carrying 500),
  request ids, CORS for /v1 only when server.cors_origins is set, the CSRF
  check for /api, and the body size limit;
- a lifespan that opens and migrates the database, builds the GatewayState,
  records a `system.start` audit event, starts the backend health loop and the
  job pool, and closes everything on shutdown.

FastAPI's interactive docs and OpenAPI schema are disabled (/docs loads its
assets from a CDN), and so is FastAPI's built-in OpenTelemetry instrumentation,
including its environment-driven exporter setup.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import platform
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.staticfiles import StaticFiles

from .. import __version__, audit, auth, backends, db
from ..config import Settings
from ..errors import ConfigError, Conflict, CryptoError, FerryError, NotFound, PermissionDenied, ValidationFailed
from ..policy import PolicyIntegrityError
from . import admin_api, openai_api
from .admin_api import AdminContext
from .jobs import JobRegistry
from .limits import BodySizeLimitMiddleware, RequestIDMiddleware, openai_error
from .security import (ApiError, CSRFMiddleware, InferenceCORSMiddleware, SecurityHeadersMiddleware, error_body,
                       is_api_path)
from .state import GatewayState, build_state, close_state

log = logging.getLogger("ferry.gateway.app")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
CONSOLE_NOT_BUILT = (
    "Ferry is running, but the web console has not been built: ferry/static/index.html is missing.\n"
    "Build it on a connected machine with `npm ci && npm run build` in web/, or use the ferry command line.\n"
    "The OpenAI-compatible API (/v1) and the admin API (/api) work without it.\n"
)
TELEMETRY_OFF: dict[str, Any] = {"tracing": False, "metrics": False, "logs": False, "operation_spans": False,
                                 "auto_configure": False}
_FERRY_STATUS: tuple[tuple[type[FerryError], int], ...] = (
    (PolicyIntegrityError, 500), (NotFound, 404), (Conflict, 409), (PermissionDenied, 403),
    (ValidationFailed, 422), (CryptoError, 422), (ConfigError, 500),
)


def _fastapi(**kwargs: Any) -> FastAPI:
    # FastAPI >= 0.160 instruments every app with OpenTelemetry (and can add OTLP
    # exporters from environment variables); older versions have no such option.
    if "telemetry" in inspect.signature(FastAPI.__init__).parameters:
        kwargs["telemetry"] = dict(TELEMETRY_OFF)
    return FastAPI(**kwargs)


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _api_json(status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store", **(headers or {})})


async def _on_api_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ApiError)
    return _api_json(exc.status, _json_safe(exc.body()), exc.headers)


async def _on_ferry_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, FerryError)
    status = next((code for cls, code in _FERRY_STATUS if isinstance(exc, cls)), 400)
    if status >= 500:
        log.error("%s on %s %s: %s", type(exc).__name__, request.method, request.url.path, exc.message)
    if request.url.path.startswith("/v1/"):
        return _api_json(status, openai_error(exc.message, "invalid_request_error" if status < 500 else "internal_error",
                                              exc.code))
    return _api_json(status, _json_safe(error_body(exc.code, exc.message, exc.details or None)))


async def _on_validation_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, RequestValidationError)
    # Only where and what: pydantic's error entries also carry the submitted
    # input, which must never be echoed (it may be a password).
    errors = []
    for err in list(exc.errors())[:20]:
        loc = [str(part) for part in err.get("loc", ()) if part != "body"]
        errors.append({"path": ".".join(loc), "message": str(err.get("msg", "invalid value"))[:200]})
    summary = "; ".join(f"{e['path'] or 'request'}: {e['message']}" for e in errors[:3])
    return _api_json(422, error_body("validation_failed", f"The request is not valid: {summary}", {"errors": errors}))


async def _on_http_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, StarletteHTTPException)
    path = request.url.path
    headers = dict(exc.headers or {})
    message = str(exc.detail) if exc.detail else "Request failed"
    if is_api_path(path):
        code = "not_found" if exc.status_code == 404 else f"http_{exc.status_code}"
        return _api_json(exc.status_code, error_body(code, message), headers)
    if path.startswith("/v1/"):
        return _api_json(exc.status_code, openai_error(message, "invalid_request_error"), headers)
    return PlainTextResponse(message, status_code=exc.status_code, headers=headers)


def _record_start(state: GatewayState) -> None:
    s = state.settings
    with state.db.session() as conn:
        schema = db.current_version(conn)
        audit.append_event(
            conn, actor_type="system", actor_id="ferry", action="system.start", resource="system", outcome="success",
            details={"version": __version__, "python": platform.python_version(), "platform": platform.platform(),
                     "pid": os.getpid(), "host": s.server.host, "port": s.server.port,
                     "tls": bool(s.server.tls_cert_file and s.server.tls_key_file), "data_dir": str(s.data_dir),
                     "config_path": str(s.config_path) if s.config_path else None, "schema_version": schema,
                     "health_interval_s": s.gateway.health_interval_s},
        )


def create_app(settings: Settings, *, static_dir: Path | None = None) -> FastAPI:
    """The complete Ferry server application for `settings` (spec sections 8 and 9).
    `static_dir` overrides the console build directory (tests)."""
    static = Path(static_dir) if static_dir is not None else STATIC_DIR

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = build_state(settings)
        app.state.ferry = state
        admin = AdminContext(jobs=JobRegistry(settings, state.db), throttle=auth.LoginThrottle())
        app.state.ferry_admin = admin
        try:
            # Fail closed: a server that cannot write its audit log does not start.
            await run_in_threadpool(_record_start, state)
            state.health_task = asyncio.create_task(backends.health_loop(state), name="ferry-health-loop")
            yield
        finally:
            admin.jobs.shutdown()
            await close_state(state)

    app = _fastapi(title="Ferry", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                   swagger_ui_oauth2_redirect_url=None, redirect_slashes=False, lifespan=lifespan)
    app.add_exception_handler(ApiError, _on_api_error)
    app.add_exception_handler(FerryError, _on_ferry_error)
    app.add_exception_handler(RequestValidationError, _on_validation_error)
    app.add_exception_handler(StarletteHTTPException, _on_http_error)

    app.include_router(openai_api.router)
    app.include_router(admin_api.router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    index = static / "index.html"

    @app.get("/", include_in_schema=False)
    async def console() -> Response:
        if index.is_file():
            return FileResponse(index, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-cache"})
        return PlainTextResponse(CONSOLE_NOT_BUILT)

    assets = static / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    # add_middleware wraps: the last one added is the outermost.
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.server.max_body_bytes)
    app.add_middleware(CSRFMiddleware)
    if settings.server.cors_origins:
        app.add_middleware(InferenceCORSMiddleware, origins=settings.server.cors_origins)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    return app
