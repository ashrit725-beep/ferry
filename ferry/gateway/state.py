"""Process-wide gateway state, stored at `app.state.ferry`.

There is exactly one outbound HTTP client. It ignores proxy environment
variables (`trust_env=False`) and never follows redirects, so the only hosts the
gateway talks to are the backends an admin configured and the egress guard
allowed.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.cookiejar
import sqlite3
import threading
from dataclasses import dataclass

import httpx

from .. import __version__, policy
from ..backends import EgressGuard
from ..config import Settings
from ..db import Database
from ..util import rfc3339
from .limits import ConcurrencyLimiter


class PolicyCache:
    """The compiled active policy, recompiled only when `active_policy.version`
    changes. Every lookup reads the version, so an activation takes effect on the
    next request in every worker; a stored document that no longer matches its
    digest raises policy.PolicyIntegrityError and the caller must deny."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._version: int | None = None
        self._compiled: policy.CompiledPolicy | None = None

    def get(self, conn: sqlite3.Connection) -> policy.CompiledPolicy | None:
        row = conn.execute("SELECT version FROM active_policy WHERE id = 1").fetchone()
        if row is None:
            self.invalidate()
            return None
        version = int(row["version"])
        with self._lock:
            if self._compiled is not None and self._version == version:
                return self._compiled
        compiled = policy.load_compiled(conn, version)
        with self._lock:
            self._version, self._compiled = version, compiled
        return compiled

    def invalidate(self) -> None:
        with self._lock:
            self._version, self._compiled = None, None


@dataclass
class GatewayState:
    settings: Settings
    db: Database
    http: httpx.AsyncClient
    limiter: ConcurrencyLimiter
    policy: PolicyCache
    egress: EgressGuard
    started_at: str
    health_task: asyncio.Task[None] | None = None
    """Set by the app lifespan when it starts backends.health_loop; close_state cancels it."""


def build_state(settings: Settings) -> GatewayState:
    """Open (and migrate) the database and create the shared clients. Call from the
    app lifespan, inside the event loop that will serve requests."""
    db = Database(settings.db_path)
    db.init()
    g = settings.gateway
    client = httpx.AsyncClient(
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(g.read_timeout_s, connect=g.connect_timeout_s),
        limits=httpx.Limits(max_connections=g.max_concurrency + 16, max_keepalive_connections=g.max_concurrency),
        headers={"User-Agent": f"ferry/{__version__}"},
        # One client serves every app, so it must not carry cookies a backend sets
        # from one request to the next.
        cookies=http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[])),
    )
    return GatewayState(
        settings=settings,
        db=db,
        http=client,
        limiter=ConcurrencyLimiter(g.max_concurrency, g.queue_timeout_s),
        policy=PolicyCache(),
        egress=EgressGuard(g.allow_public_backends),
        started_at=rfc3339(),
    )


async def close_state(state: GatewayState) -> None:
    task, state.health_task = state.health_task, None
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    await state.http.aclose()
