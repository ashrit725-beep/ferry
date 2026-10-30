"""Helpers for gateway tests: a minimal app around the OpenAI router, plus data setup.

The real application (ferry/gateway/app.py) adds the admin API, the console,
security headers and the health loop. These tests need only the inference path,
so `make_app` mounts the router, the request-id and body-size middleware and a
GatewayState, and nothing else.

Bundle rows are written directly by `store_artifact`: the importer belongs to
another module, and the gateway only needs a store file plus its registry rows.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ferry import audit, auth, backends, policy
from ferry.config import GatewaySettings, ServerSettings, Settings
from ferry.db import Database, write_tx
from ferry.gateway import openai_api
from ferry.gateway.limits import BodySizeLimitMiddleware, RequestIDMiddleware
from ferry.gateway.state import GatewayState, build_state, close_state
from ferry.util import canonical_json, rfc3339, sha256_hex

from helpers_upstream import FakeUpstream

ACTOR = {"actor_type": "cli", "actor_id": "pytest"}
APP = "report-assistant"
MODEL = "qwen-test"
UPSTREAM_MODEL = "qwen2.5-0.5b-instruct-q4_k_m"


def gateway_settings(data_dir: Path, *, server: ServerSettings | None = None, **gateway: Any) -> Settings:
    """Settings for gateway tests. The health loop is off: tests run checks explicitly."""
    values = {"health_interval_s": 0.0, "queue_timeout_s": 2.0, "connect_timeout_s": 2.0, **gateway}
    return Settings(data_dir=data_dir, gateway=GatewaySettings(**values), server=server or ServerSettings())


def make_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = build_state(settings)
        app.state.ferry = state
        try:
            yield
        finally:
            await close_state(state)

    app = FastAPI(lifespan=lifespan)
    app.include_router(openai_api.router)
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.server.max_body_bytes)
    # Added last, so it is outermost: even the middleware's own 413 carries the id.
    app.add_middleware(RequestIDMiddleware)
    return app


@contextmanager
def live_server(app: FastAPI) -> Iterator[str]:
    """Serve `app` with uvicorn on 127.0.0.1 (random port) in a thread; yields the base URL.
    For behaviour TestClient cannot show, such as a client hanging up mid-stream."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name="uvicorn-test", daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(10)


def add_app(conn: sqlite3.Connection, name: str = APP, *, environment: str = "test") -> tuple[int, str]:
    principal = auth.create_principal(conn, name, environment=environment, **ACTOR)
    return principal["id"], auth.issue_api_key(conn, principal["id"], **ACTOR)["api_key"]


def allow(rule_id: str, principals: list[str], models: list[str], **limits: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {"id": rule_id, "effect": "allow", "principals": principals,
                            "actions": ["chat.completions"], "models": models}
    if limits:
        rule["limits"] = limits
    return rule


def deny(rule_id: str, principals: list[str], models: list[str]) -> dict[str, Any]:
    return {"id": rule_id, "effect": "deny", "principals": principals, "actions": ["*"], "models": models}


def activate(conn: sqlite3.Connection, *rules: dict[str, Any]) -> dict[str, Any]:
    doc = {"schema": policy.SCHEMA, "description": "test policy", "rules": list(rules)}
    return policy.activate_policy(conn, doc, **ACTOR)


def write_token(settings: Settings, name: str, token: str, mode: int = 0o600) -> Path:
    settings.secrets_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(settings.secrets_dir, 0o700)
    path = settings.secrets_dir / f"{name}.token"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    os.chmod(path, mode)
    return path


def add_backend(conn: sqlite3.Connection, settings: Settings, base_url: str, *, name: str = "llama",
                kind: str = "llamacpp", token: str | None = None, **kw: Any) -> int:
    token_file = str(write_token(settings, name, token)) if token else None
    row = backends.create_backend(conn, settings, name=name, kind=kind, base_url=base_url,
                                  auth_token_file=token_file, **kw, **ACTOR)
    return int(row["id"])


def store_artifact(settings: Settings, conn: sqlite3.Connection, content: bytes, *,
                   model_name: str = "test-model", kind: str = "model") -> str:
    """Place `content` in the content-addressed store and register it as imported."""
    digest = sha256_hex(content)
    store = settings.store_dir / "sha256"
    store.mkdir(parents=True, exist_ok=True)
    path = store / digest
    if not path.exists():
        path.write_bytes(content)
        path.chmod(0o444)
    bundle_id = "sha256:" + sha256_hex(b"bundle:" + content)
    with write_tx(conn):
        conn.execute("INSERT OR IGNORE INTO bundles (bundle_id, name, version, manifest, signers, report, imported_at,"
                     " imported_by, source_name) VALUES (?, ?, '1.0.0', '{}', '[]', '{}', ?, 'cli:pytest', 'test.tar')",
                     (bundle_id, model_name, rfc3339()))
        conn.execute("INSERT OR IGNORE INTO artifacts (digest, size, kind, format, model_name, metadata,"
                     " first_bundle_id, imported_at) VALUES (?, ?, ?, 'gguf', ?, '{}', ?, ?)",
                     (digest, len(content), kind, model_name, bundle_id, rfc3339()))
    return digest


def store_path(settings: Settings, digest: str) -> str:
    return str(settings.store_dir / "sha256" / digest)


def run_health(settings: Settings, backend_id: int) -> dict[str, Any]:
    """A real health check and record, on a throwaway state and event loop."""
    async def go() -> dict[str, Any]:
        state = build_state(settings)
        try:
            return await backends.refresh_backend(state, backend_id)
        finally:
            await close_state(state)

    return asyncio.run(go())


def set_status(conn: sqlite3.Connection, backend_id: int, state: str = "up", **extra: Any) -> None:
    """Write a backend status directly, for situations a health check cannot set up."""
    status = {"state": state, "checked_at": rfc3339(), "latency_ms": 1, "http_status": 200 if state == "up" else None,
              "version": None, "models": [], "served": [], "error": None, **extra}
    with write_tx(conn):
        conn.execute("UPDATE backends SET last_status = ?, last_checked_at = ? WHERE id = ?",
                     (canonical_json(status).decode("ascii"), status["checked_at"], backend_id))


def chat_body(model: str = MODEL, prompt: str = "Say hello.", **extra: Any) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": prompt}], **extra}


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def events(conn: sqlite3.Connection, action: str = "gateway.chat.completions") -> list[dict[str, Any]]:
    """Audit events for `action`, oldest first."""
    return list(reversed(audit.query_events(conn, action=action, limit=500)))


@dataclass
class GatewayEnv:
    settings: Settings
    database: Database
    upstream: FakeUpstream
    client: TestClient
    api_key: str
    principal_id: int
    backend_id: int
    route_id: int
    digest: str
    model: str = MODEL

    @property
    def state(self) -> GatewayState:
        return self.client.app.state.ferry  # type: ignore[attr-defined, no-any-return]

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        with self.database.session() as c:
            yield c

    def chat(self, body: dict[str, Any] | None = None, *, key: str | None = None,
             headers: dict[str, str] | None = None, **kw: Any) -> Any:
        merged = {**bearer(key or self.api_key), **(headers or {})}
        return self.client.post("/v1/chat/completions", json=body if body is not None else chat_body(self.model),
                                headers=merged, **kw)

    def events(self, action: str = "gateway.chat.completions") -> list[dict[str, Any]]:
        with self.conn() as c:
            return events(c, action)


@contextmanager
def gateway_env(data_dir: Path, upstream: FakeUpstream, *, rules: list[dict[str, Any]] | None = None,
                pinned: bool = True, require_verified: bool = True, check_health: bool = True,
                backend_kw: dict[str, Any] | None = None, server: ServerSettings | None = None,
                **gateway: Any) -> Iterator[GatewayEnv]:
    """A wired-up gateway: one app with a key, a policy, a llama.cpp backend (the
    test double) and a route, pinned to a store artifact that the double reports
    serving. The double's request log is cleared before the client starts."""
    settings = gateway_settings(data_dir, server=server, **gateway)
    database = Database(settings.db_path)
    database.init()
    with database.session() as conn:
        principal_id, api_key = add_app(conn)
        activate(conn, *(rules if rules is not None else [allow("report-chat", [f"app:{APP}"], [MODEL],
                                                                max_tokens=512, allow_stream=True)]))
        digest = store_artifact(settings, conn, b"GGUF fake model bytes for " + data_dir.name.encode())
        upstream.model_path = store_path(settings, digest)
        backend_id = add_backend(conn, settings, upstream.base_url, token=upstream.token, **(backend_kw or {}))
        route = backends.create_route(conn, model=MODEL, backend_id=backend_id, upstream_model=UPSTREAM_MODEL,
                                      artifact_digest=digest if pinned else None,
                                      require_verified=require_verified, **ACTOR)
    if check_health:
        run_health(settings, backend_id)
    upstream.clear()
    with TestClient(make_app(settings)) as client:
        yield GatewayEnv(settings=settings, database=database, upstream=upstream, client=client, api_key=api_key,
                         principal_id=principal_id, backend_id=backend_id, route_id=int(route["id"]), digest=digest)
