"""Request limits for the gateway: request ids, body size, concurrency.

These run before any authentication or parsing, so they must be cheap and must
not trust the client: the body limit checks the declared Content-Length and
also counts the bytes actually received (a chunked body declares nothing).
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import uuid
from typing import Any, Awaitable, Callable, Iterable, MutableMapping

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SCOPE_KEY = "ferry.request_id"


def openai_error(message: str, kind: str, code: str | None = None) -> dict[str, Any]:
    """The OpenAI error shape. `param` is always null: Ferry does not point at fields."""
    return {"error": {"message": message, "type": kind, "code": code or kind, "param": None}}


def _pick_request_id(headers: Iterable[tuple[bytes, bytes]]) -> str:
    for key, value in headers:
        if key.lower() == b"x-request-id":
            try:
                candidate = value.decode("ascii")
            except UnicodeDecodeError:
                break
            if REQUEST_ID_PATTERN.fullmatch(candidate):
                return candidate
            break
    return uuid.uuid4().hex


def request_id_for(scope: Scope) -> str:
    """The request id for this request: the caller's X-Request-ID if it is a safe
    token, otherwise a new one. Stable for the lifetime of the request."""
    rid = scope.get(_SCOPE_KEY)
    if not isinstance(rid, str):
        rid = _pick_request_id(scope.get("headers") or ())
        scope[_SCOPE_KEY] = rid
    return rid


def _with_header(message: Message, name: bytes, value: bytes) -> Message:
    headers = list(message.get("headers") or [])
    if not any(k.lower() == name for k, _ in headers):
        headers.append((name, value))
    return {**message, "headers": headers}


async def send_json(send: Send, status: int, body: dict[str, Any], scope: Scope,
                    extra_headers: Iterable[tuple[bytes, bytes]] = ()) -> None:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(data)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-request-id", request_id_for(scope).encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data, "more_body": False})


class RequestIDMiddleware:
    """Pure ASGI: fixes the request id before anything else runs and adds the
    X-Request-ID header to every response that does not already carry one."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = request_id_for(scope).encode("ascii")

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = _with_header(message, b"x-request-id", rid)
            await send(message)

        await self.app(scope, receive, send_with_id)


class BodyTooLarge(Exception):
    """Raised from the wrapped `receive` once a body passes the limit. Handlers that
    read the body themselves may catch it; otherwise the middleware answers 413."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"request body is larger than {limit} bytes")
        self.limit = limit


def too_large_body(limit: int) -> dict[str, Any]:
    return openai_error(f"Request body is larger than the {limit}-byte limit.", "request_too_large")


class BodySizeLimitMiddleware:
    """Pure ASGI body limit. A declared Content-Length over the limit is refused
    without reading anything; otherwise received bytes are counted and the request
    fails as soon as it passes the limit, so a chunked upload cannot exhaust memory."""

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.max_body_bytes
        declared = [v for k, v in scope.get("headers") or () if k.lower() == b"content-length"]
        if declared:
            if len(declared) != 1 or not declared[0].isdigit():
                await send_json(send, 400, openai_error("Invalid Content-Length header.", "invalid_request_error"), scope)
                return
            if int(declared[0]) > limit:
                await send_json(send, 413, too_large_body(limit), scope)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if started:
                raise
            await send_json(send, 413, too_large_body(limit), scope)


class QueueTimeout(Exception):
    """No concurrency slot became free within the queue timeout."""

    def __init__(self, scope: str, retry_after_s: int) -> None:
        super().__init__(f"no free {scope} slot")
        self.scope = scope
        self.retry_after_s = retry_after_s


class Lease:
    """Slots held by one request. `release` is idempotent, so cleanup paths can call
    it without tracking whether another path already did."""

    def __init__(self, semaphores: list[asyncio.Semaphore]) -> None:
        self._semaphores = semaphores
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        for sem in reversed(self._semaphores):
            sem.release()


class ConcurrencyLimiter:
    """A global cap (`gateway.max_concurrency`) and a cap per backend
    (`backends.max_concurrency`). A request waits at most `queue_timeout_s` in total.

    The backend slot is taken first, so requests queued for one saturated backend
    do not hold global slots that requests for other backends could use.
    """

    def __init__(self, global_limit: int, queue_timeout_s: float) -> None:
        if global_limit < 1:
            raise ValueError("global_limit must be at least 1")
        self.global_limit = global_limit
        self.queue_timeout_s = float(queue_timeout_s)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._global: asyncio.Semaphore | None = None
        self._backends: dict[int, tuple[int, asyncio.Semaphore]] = {}

    @property
    def retry_after_s(self) -> int:
        return max(1, min(60, math.ceil(self.queue_timeout_s)))

    def _bind(self) -> asyncio.Semaphore:
        # asyncio primitives belong to one event loop; a limiter reused under a new
        # loop (a restarted server, a test client) starts with fresh semaphores.
        loop = asyncio.get_running_loop()
        if self._loop is not loop or self._global is None:
            self._loop = loop
            self._global = asyncio.Semaphore(self.global_limit)
            self._backends = {}
        return self._global

    def _backend_semaphore(self, backend_id: int, limit: int) -> asyncio.Semaphore:
        limit = max(1, int(limit))
        current = self._backends.get(backend_id)
        if current is None or current[0] != limit:
            # A changed limit gets a new semaphore; requests holding the old one
            # release into the old one, which is then dropped.
            current = (limit, asyncio.Semaphore(limit))
            self._backends[backend_id] = current
        return current[1]

    async def acquire(self, backend_id: int, backend_limit: int) -> Lease:
        global_sem = self._bind()
        backend_sem = self._backend_semaphore(backend_id, backend_limit)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.queue_timeout_s
        if not await _acquire_before(backend_sem, deadline):
            raise QueueTimeout("backend", self.retry_after_s)
        try:
            got_global = await _acquire_before(global_sem, deadline)
        except BaseException:  # cancelled while queued: the backend slot is ours to give back
            backend_sem.release()
            raise
        if not got_global:
            backend_sem.release()
            raise QueueTimeout("gateway", self.retry_after_s)
        return Lease([backend_sem, global_sem])


async def _acquire_before(sem: asyncio.Semaphore, deadline: float) -> bool:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        if sem.locked():
            return False
        await sem.acquire()
        return True
    try:
        await asyncio.wait_for(sem.acquire(), remaining)
    except TimeoutError:
        return False
    return True
