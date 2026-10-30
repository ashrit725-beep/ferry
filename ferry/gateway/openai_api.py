"""OpenAI-compatible inference API: GET /v1/models and POST /v1/chat/completions.

A completion request passes fixed stages in this order: request id, body size
limit, authentication, validation, authorization, route and provenance, a
concurrency slot, then the upstream call. Denied, invalid and unauthenticated
requests never reach a backend; llama-server answers with whatever model it has
loaded whatever the request names, so this is the only place a decision can be
made.

Each request produces exactly one audit event. Prompts and completions are never
stored or logged: only the token counts from the backend's usage report are kept.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import anyio
import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.types import Receive, Scope, Send

from .. import audit, auth, backends, policy
from ..errors import FerryError
from ..util import parse_rfc3339
from .limits import BodyTooLarge, Lease, QueueTimeout, openai_error, request_id_for, too_large_body
from .state import GatewayState

log = logging.getLogger("ferry.gateway")
router = APIRouter()

ACTION = "chat.completions"
MAX_MESSAGES = 512
MESSAGE_ROLES = ("system", "user", "assistant", "tool")
MAX_STOP = 4
MAX_TOOLS = 128
MAX_REQUEST_TOKENS = 1_000_000
MAX_UPSTREAM_BODY = 32 * 1024**2
MAX_UPSTREAM_ERROR_BODY = 64 * 1024
MAX_SSE_LINE = 4 * 1024**2
UPSTREAM_MESSAGE_CHARS = 300
AUTH_MESSAGE = "Missing or invalid API key. Send the key as 'Authorization: Bearer <key>'."


class _ApiError(Exception):
    """An error answer. `message` goes to the caller; only `audit_detail` (set for
    fixed, value-free messages) and `error_type` go to the audit log."""

    def __init__(self, status: int, kind: str, message: str, *, outcome: str, error_type: str | None = None,
                 headers: dict[str, str] | None = None, audit_detail: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message
        self.outcome = outcome
        self.error_type = error_type or kind
        self.headers = headers or {}
        self.audit_detail = audit_detail


def _invalid(message: str) -> _ApiError:
    # Validation messages name fields but never echo values, so they are safe to audit.
    return _ApiError(400, "invalid_request_error", message, outcome="rejected", audit_detail=message)


# --- audit record ------------------------------------------------------------


@dataclass
class _Record:
    """The single audit event a request produces, filled in as it progresses."""

    action: str
    request_id: str
    details: dict[str, Any]
    resource: str = "model:-"
    actor_id: str = "anonymous"
    policy_version: int | None = None
    outcome: str = "error"
    started: float = field(default_factory=time.monotonic)
    written: bool = False

    def finish(self, outcome: str, status_code: int, error_type: str | None) -> None:
        self.outcome = outcome
        self.details["status_code"] = status_code
        self.details["error_type"] = error_type
        self.details["latency_ms"] = int((time.monotonic() - self.started) * 1000)


def _chat_record(request_id: str) -> _Record:
    return _Record(action="gateway.chat.completions", request_id=request_id, details={
        "status_code": None, "decision": None, "decisive_rule": None, "model": None, "backend": None,
        "route_id": None, "artifact_digest": None, "provenance": None, "stream": False,
        "max_tokens_requested": None, "max_tokens_effective": None, "prompt_tokens": None,
        "completion_tokens": None, "latency_ms": None, "error_type": None, "key_id": None, "environment": None,
    })


def _write_record(state: GatewayState, rec: _Record) -> None:
    """Blocking (it may wait up to busy_timeout for the database lock): run it in a worker
    thread, never on the event loop, where it would stall every other request."""
    if rec.written:
        return
    rec.written = True
    with state.db.session() as conn:
        audit.append_event(conn, actor_type="app", actor_id=rec.actor_id, action=rec.action, resource=rec.resource,
                           outcome=rec.outcome, correlation_id=rec.request_id, policy_version=rec.policy_version,
                           details=rec.details)


def _record_usage(rec: _Record, usage: Any) -> None:
    if not isinstance(usage, dict):
        return
    for key in ("prompt_tokens", "completion_tokens"):
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            rec.details[key] = value


# --- responses ---------------------------------------------------------------


def _dump_relayed(obj: Any, *, allow_nan: bool) -> bytes:
    """Compact UTF-8 JSON for content a backend sent. Text holding an escaped lone
    surrogate (half of a split emoji, say) has no UTF-8 form, so it stays \\u-escaped."""
    try:
        return json.dumps(obj, ensure_ascii=False, allow_nan=allow_nan, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(obj, allow_nan=allow_nan, separators=(",", ":")).encode("ascii")


class _JSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return _dump_relayed(content, allow_nan=False)


def _json(status: int, body: dict[str, Any], request_id: str, headers: dict[str, str] | None = None) -> JSONResponse:
    merged = {"X-Request-ID": request_id, "Cache-Control": "no-store"}
    if headers:
        merged.update(headers)
    return _JSONResponse(body, status_code=status, headers=merged)


def _state(request: Request) -> GatewayState:
    state = getattr(request.app.state, "ferry", None)
    if not isinstance(state, GatewayState):
        raise RuntimeError("app.state.ferry must be a GatewayState (see ferry.gateway.state.build_state)")
    return state


# --- request validation ------------------------------------------------------


@dataclass(frozen=True)
class ChatRequest:
    model: str
    stream: bool
    max_tokens: int | None
    """What the caller asked for (the smaller of max_tokens and max_completion_tokens)."""
    payload: dict[str, Any]
    """Accepted fields only; model, max_tokens and stream are set when forwarding."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def decode_json_object(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body.decode("utf-8"), parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _invalid("The request body must be valid JSON (UTF-8).") from None
    if not isinstance(data, dict):
        raise _invalid("The request body must be a JSON object.")
    return data


def _optional_bool(data: dict[str, Any], key: str) -> bool | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise _invalid(f"'{key}' must be true or false.")
    return value


def _optional_int(data: dict[str, Any], key: str, lo: int, hi: int, what: str | None = None) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise _invalid(f"'{key}' must be {what or f'a whole number from {lo} to {hi}'}.")
    return value


def _optional_number(data: dict[str, Any], key: str, lo: float, hi: float) -> float | int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
        raise _invalid(f"'{key}' must be a number from {lo:g} to {hi:g}.")
    return value


def _content(value: Any, where: str) -> str | list[dict[str, str]]:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        parts = []
        for j, part in enumerate(value):
            if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
                raise _invalid(f"{where}.content[{j}] must be {{\"type\": \"text\", \"text\": ...}}; "
                               "only text content is supported.")
            parts.append({"type": "text", "text": part["text"]})
        return parts
    raise _invalid(f"{where}.content must be a string or a non-empty list of text parts.")


def _messages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MESSAGES:
        raise _invalid(f"'messages' is required: a list of 1 to {MAX_MESSAGES} messages.")
    out = []
    for i, message in enumerate(value):
        where = f"messages[{i}]"
        if not isinstance(message, dict):
            raise _invalid(f"{where} must be an object.")
        role = message.get("role")
        if role not in MESSAGE_ROLES:
            raise _invalid(f"{where}.role must be one of: {', '.join(MESSAGE_ROLES)}.")
        clean: dict[str, Any] = {"role": role}
        tool_calls = message.get("tool_calls")
        if tool_calls is not None:
            if role != "assistant":
                raise _invalid(f"{where}.tool_calls is only allowed on assistant messages.")
            if (not isinstance(tool_calls, list) or not tool_calls or len(tool_calls) > MAX_TOOLS
                    or not all(isinstance(t, dict) for t in tool_calls)):
                raise _invalid(f"{where}.tool_calls must be a list of 1 to {MAX_TOOLS} objects.")
            clean["tool_calls"] = tool_calls
        content = message.get("content")
        if content is None:
            if "tool_calls" not in clean:
                raise _invalid(f"{where}.content is required.")
            clean["content"] = None
        else:
            clean["content"] = _content(content, where)
        name = message.get("name")
        if name is not None:
            if not isinstance(name, str) or not 1 <= len(name) <= 64:
                raise _invalid(f"{where}.name must be a string of 1 to 64 characters.")
            clean["name"] = name
        if role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not 1 <= len(call_id) <= 256:
                raise _invalid(f"{where}.tool_call_id is required for tool messages.")
            clean["tool_call_id"] = call_id
        out.append(clean)
    return out


def validate_chat_request(data: dict[str, Any]) -> ChatRequest:
    """Accept only the documented fields; anything else is dropped, never forwarded."""
    model = data.get("model")
    if not isinstance(model, str) or not policy.MODEL_NAME.fullmatch(model):
        raise _invalid("'model' is required and must be a model name (letters, digits, '.', '_', ':' or '-').")
    payload: dict[str, Any] = {"messages": _messages(data.get("messages"))}
    stream = bool(_optional_bool(data, "stream"))
    for key, lo, hi in (("temperature", 0, 2), ("top_p", 0, 1), ("presence_penalty", -2, 2),
                        ("frequency_penalty", -2, 2)):
        number = _optional_number(data, key, lo, hi)
        if number is not None:
            payload[key] = number
    seed = _optional_int(data, "seed", -(2**63), 2**64 - 1, "a 64-bit whole number")
    if seed is not None:
        payload["seed"] = seed
    if data.get("n") is not None:
        if _optional_int(data, "n", 1, 1, "1 (the gateway returns one choice per request)") != 1:
            raise _invalid("'n' must be 1.")
        payload["n"] = 1
    stop = data.get("stop")
    if stop is not None:
        if isinstance(stop, str):
            payload["stop"] = stop
        elif isinstance(stop, list) and len(stop) <= MAX_STOP and all(isinstance(s, str) for s in stop):
            payload["stop"] = list(stop)
        else:
            raise _invalid(f"'stop' must be a string or a list of at most {MAX_STOP} strings.")
    response_format = data.get("response_format")
    if response_format is not None:
        if not isinstance(response_format, dict) or not isinstance(response_format.get("type"), str):
            raise _invalid("'response_format' must be an object with a 'type'.")
        payload["response_format"] = response_format
    tools = data.get("tools")
    if tools is not None:
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS or not all(isinstance(t, dict) for t in tools):
            raise _invalid(f"'tools' must be a list of at most {MAX_TOOLS} objects.")
        payload["tools"] = tools
    tool_choice = data.get("tool_choice")
    if tool_choice is not None:
        if not (tool_choice in ("none", "auto", "required") or isinstance(tool_choice, dict)):
            raise _invalid("'tool_choice' must be \"none\", \"auto\", \"required\" or an object.")
        payload["tool_choice"] = tool_choice
    user = data.get("user")
    if user is not None:
        if not isinstance(user, str) or len(user) > 256:
            raise _invalid("'user' must be a string of at most 256 characters.")
        payload["user"] = user
    asked = [v for v in (_optional_int(data, "max_tokens", 1, MAX_REQUEST_TOKENS),
                         _optional_int(data, "max_completion_tokens", 1, MAX_REQUEST_TOKENS)) if v is not None]
    _check_forwardable(payload)
    return ChatRequest(model=model, stream=stream, max_tokens=min(asked) if asked else None, payload=payload)


def _check_forwardable(payload: dict[str, Any]) -> None:
    """json.loads accepts two things the upstream request cannot carry: an escaped lone
    surrogate such as "\\ud800" (it has no UTF-8 form) and objects nested deeper than
    json.dumps can encode. Both are the caller's error, so validation refuses them."""
    try:
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except UnicodeEncodeError:
        raise _invalid("Strings must be valid Unicode: unpaired surrogate escapes such as \\ud800 are not "
                       "accepted.") from None
    except RecursionError:
        raise _invalid("The request is nested too deeply.") from None


# --- authentication, authorization, routing ----------------------------------


async def _authenticate(state: GatewayState, request: Request, rec: _Record) -> auth.AppIdentity:
    header = request.headers.get("authorization")
    presented = auth.parse_bearer(header)

    def check() -> auth.ApiKeyResult:
        with state.db.session() as conn:
            return auth.authenticate_api_key(conn, presented)

    result = await run_in_threadpool(check)
    rec.details["key_id"] = result.key_id
    if not result.ok or result.identity is None:
        rec.details["auth_failure"] = "missing" if not header else result.reason
        raise _ApiError(401, "authentication_error", AUTH_MESSAGE, outcome="unauthenticated",
                        headers={"WWW-Authenticate": "Bearer"})
    rec.actor_id = result.identity.name
    rec.details["environment"] = result.identity.environment
    return result.identity


def _load_policy(state: GatewayState, conn: Any, rec: _Record) -> policy.CompiledPolicy | None:
    try:
        return state.policy.get(conn)
    except FerryError as exc:
        log.error("the active policy could not be loaded: %s", exc.message)
        rec.details["decision"] = "deny"
        raise _ApiError(403, "permission_denied", "Access denied: the active access policy could not be loaded, so "
                        "every request is denied. An administrator must check the policy.", outcome="denied",
                        error_type="policy_unavailable") from None


@dataclass(frozen=True)
class _Plan:
    identity: auth.AppIdentity
    chat: ChatRequest
    route: dict[str, Any]
    max_tokens: int
    clamped: bool


def _authorize_and_route(state: GatewayState, identity: auth.AppIdentity, chat: ChatRequest, rec: _Record) -> _Plan:
    with state.db.session() as conn:
        compiled = _load_policy(state, conn, rec)
        decision = policy.evaluate(compiled, principal=identity.principal, action=ACTION, model=chat.model)
        rec.policy_version = decision.policy_version
        rec.details["decision"] = "allow" if decision.allowed else "deny"
        rec.details["decisive_rule"] = decision.decisive_rule
        if not decision.allowed:
            raise _ApiError(403, "permission_denied",
                            f"Access denied for app '{identity.name}' to model '{chat.model}': {decision.reason}.",
                            outcome="denied", error_type="policy_denied")
        if chat.stream and not decision.allow_stream:
            rec.details["decision"] = "deny"
            raise _ApiError(403, "permission_denied",
                            f"Streaming is not allowed for app '{identity.name}' and model '{chat.model}' "
                            f"(rule '{decision.decisive_rule}'); send the request with \"stream\": false.",
                            outcome="denied", error_type="stream_not_allowed")
        route = backends.route_for_model(conn, chat.model)
    if route is None:
        raise _ApiError(404, "model_not_found", f"The model '{chat.model}' does not exist or has no route.",
                        outcome="rejected", error_type="model_not_found")
    rec.details.update(route_id=route["id"], backend=route["backend_name"], artifact_digest=route["artifact_digest"])
    availability = backends.route_availability(
        route, {"enabled": route["backend_enabled"], "last_status": route["last_status"]})
    rec.details["provenance"] = availability.provenance["state"]
    if not availability.available:
        raise _ApiError(503, "backend_unavailable", f"The model '{chat.model}' is unavailable: {availability.reason}.",
                        outcome="unavailable", error_type=availability.code)
    caps = [c for c in (chat.max_tokens, decision.max_tokens, state.settings.gateway.max_tokens_ceiling) if c is not None]
    effective = min(caps)
    rec.details["max_tokens_effective"] = effective
    return _Plan(identity=identity, chat=chat, route=route, max_tokens=effective,
                 clamped=chat.max_tokens is None or effective < chat.max_tokens)


@dataclass(frozen=True)
class _Target:
    base_url: str
    token: str | None


async def _resolve_target(state: GatewayState, plan: _Plan, rec: _Record) -> _Target:
    """Re-run the egress guard (resolutions cached 30 s) and read the backend token now."""
    try:
        checked = await state.egress.acheck(plan.route["base_url"])
    except FerryError as exc:
        rec.details["error"] = exc.message
        raise _ApiError(503, "backend_unavailable", f"The model '{plan.chat.model}' is unavailable: its backend "
                        "address is not allowed by the egress rules.", outcome="unavailable",
                        error_type="egress_denied") from None
    token = None
    if plan.route["auth_token_file"]:
        try:
            token = await run_in_threadpool(backends.read_token_file, plan.route["auth_token_file"])
        except FerryError as exc:
            rec.details["error"] = exc.message
            raise _ApiError(503, "backend_unavailable", f"The model '{plan.chat.model}' is unavailable: the backend "
                            "credentials could not be read.", outcome="unavailable",
                            error_type="backend_credentials") from None
    return _Target(base_url=checked.base_url, token=token)


async def _acquire(state: GatewayState, plan: _Plan) -> Lease:
    try:
        return await state.limiter.acquire(plan.route["backend_id"], plan.route["max_concurrency"])
    except QueueTimeout as exc:
        raise _ApiError(429, "rate_limit_error", f"Too many requests are in flight for this {exc.scope}; retry after "
                        f"{exc.retry_after_s} s.", outcome="unavailable", error_type=f"queue_timeout_{exc.scope}",
                        headers={"Retry-After": str(exc.retry_after_s)}) from None


# --- upstream ----------------------------------------------------------------


def _upstream_request(state: GatewayState, plan: _Plan, target: _Target, request_id: str) -> httpx.Request:
    payload = dict(plan.chat.payload)
    payload["model"] = plan.route["upstream_model"]
    payload["max_tokens"] = plan.max_tokens
    payload["stream"] = plan.chat.stream
    if plan.chat.stream:
        payload["stream_options"] = {"include_usage": True}
    # Built from scratch: the caller's headers (including its API key) are never forwarded.
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if plan.chat.stream else "application/json",
        "Accept-Encoding": "identity",
        "X-Request-ID": request_id,
    }
    if target.token:
        headers["Authorization"] = f"Bearer {target.token}"
    timeout = httpx.Timeout(float(plan.route["timeout_s"]), connect=state.settings.gateway.connect_timeout_s)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return state.http.build_request("POST", target.base_url + "/v1/chat/completions", content=body,
                                    headers=headers, timeout=timeout)


def _gateway_timeout() -> _ApiError:
    return _ApiError(504, "timeout", "The backend did not respond in time.", outcome="error", error_type="timeout")


def _backend_failed(error_type: str = "backend_error", message: str = "The connection to the backend failed.") -> _ApiError:
    return _ApiError(502, "backend_error", message, outcome="error", error_type=error_type)


async def _send(state: GatewayState, request: httpx.Request) -> httpx.Response:
    try:
        return await state.http.send(request, stream=True)
    except httpx.ConnectTimeout:
        raise _ApiError(503, "backend_unavailable", "The backend could not be reached (connect timeout).",
                        outcome="unavailable", error_type="connect_timeout") from None
    except httpx.ConnectError:
        raise _ApiError(503, "backend_unavailable", "The backend could not be reached (connection refused or failed).",
                        outcome="unavailable", error_type="connect_error") from None
    except httpx.TimeoutException:
        raise _gateway_timeout() from None
    except httpx.HTTPError:
        raise _backend_failed() from None


def _check_identity_encoding(response: httpx.Response) -> None:
    if response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
        raise _backend_failed("invalid_response", "The backend sent a compressed response, which is not accepted.")


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    _check_identity_encoding(response)
    buf = bytearray()
    try:
        async for chunk in response.aiter_raw():
            buf += chunk
            if len(buf) > limit:
                raise _backend_failed("response_too_large", "The backend response is too large.")
    except httpx.TimeoutException:
        raise _gateway_timeout() from None
    except httpx.HTTPError:
        raise _backend_failed() from None
    return bytes(buf)


def _upstream_message(raw: bytes) -> str | None:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    message: Any = None
    if isinstance(data, dict):
        error = data.get("error")
        message = error.get("message") if isinstance(error, dict) else error
        if message is None:
            message = data.get("message") or data.get("detail")
    if not isinstance(message, str):
        return None
    clean = "".join(ch if ch.isprintable() else " " for ch in message).strip()
    return clean[:UPSTREAM_MESSAGE_CHARS] or None


def _upstream_status_error(status: int, raw: bytes) -> _ApiError:
    """Map a backend error status. The backend's message is passed to the caller
    (it concerns the caller's own request) but never to the audit log."""
    if status in (400, 413, 422):
        detail = _upstream_message(raw)
        return _ApiError(400, "invalid_request_error",
                         f"The backend rejected the request (HTTP {status})" + (f": {detail}" if detail else "."),
                         outcome="rejected", error_type=f"upstream_{status}")
    if status in (429, 503):
        return _ApiError(503, "backend_unavailable", f"The backend is busy or still loading (HTTP {status}); retry later.",
                         outcome="unavailable", error_type=f"upstream_{status}")
    return _backend_failed(f"upstream_{status}", f"The backend returned HTTP {status}.")


def _limit_headers(plan: _Plan) -> dict[str, str]:
    return {"X-Ferry-Max-Tokens": str(plan.max_tokens)} if plan.clamped else {}


async def _complete(state: GatewayState, plan: _Plan, request: httpx.Request, rec: _Record) -> Response:
    upstream = await _send(state, request)
    try:
        if upstream.status_code >= 300:
            raise _upstream_status_error(upstream.status_code, await _read_limited(upstream, MAX_UPSTREAM_ERROR_BODY))
        raw = await _read_limited(upstream, MAX_UPSTREAM_BODY)
    finally:
        await upstream.aclose()
    try:
        data = json.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        raise _backend_failed("invalid_response", "The backend returned a response that is not valid JSON.") from None
    if not isinstance(data, dict):
        raise _backend_failed("invalid_response", "The backend returned an unexpected response.")
    data["model"] = plan.chat.model
    _record_usage(rec, data.get("usage"))
    rec.finish("success", 200, None)
    return _json(200, data, rec.request_id, _limit_headers(plan))


class _StreamFailed(Exception):
    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.message = message


def _sse_error(kind: str, message: str) -> bytes:
    return b"data: " + json.dumps(openai_error(message, kind), separators=(",", ":")).encode("utf-8") + b"\n\n"


class _StreamRelay:
    """Copies the backend's server-sent events to the caller line by line,
    rewriting `model` in every JSON chunk and reading the usage report. It owns
    the concurrency slot and the upstream response until `close`."""

    def __init__(self, state: GatewayState, upstream: httpx.Response, lease: Lease, rec: _Record,
                 public_model: str) -> None:
        self.state = state
        self.upstream = upstream
        self.lease = lease
        self.rec = rec
        self.public_model = public_model
        self._buffer = bytearray()
        self._done = False
        self._usage: Any = None
        self._failure: _StreamFailed | None = None
        self._closed = False

    def _line(self, line: bytes) -> bytes:
        text = line[:-1] if line.endswith(b"\r") else line
        if not text.startswith(b"data:"):
            return text
        payload = text[5:].strip()
        if payload == b"[DONE]":
            self._done = True
            return b"data: [DONE]"
        try:
            obj = json.loads(payload)
        except (ValueError, RecursionError):
            return text
        if not isinstance(obj, dict):
            return text
        if "model" in obj:
            obj["model"] = self.public_model
        if isinstance(obj.get("usage"), dict):
            self._usage = obj["usage"]
        if "error" in obj and self._failure is None:
            self._failure = _StreamFailed("backend_error", "the backend reported an error during the stream")
        return b"data: " + _dump_relayed(obj, allow_nan=True)

    def _feed(self, chunk: bytes) -> bytes:
        self._buffer += chunk
        if b"\n" not in chunk:
            if len(self._buffer) > MAX_SSE_LINE:
                raise _StreamFailed("stream_line_too_long", "The backend sent an oversized event.")
            return b""
        *lines, rest = bytes(self._buffer).split(b"\n")
        self._buffer = bytearray(rest)
        if len(self._buffer) > MAX_SSE_LINE:
            raise _StreamFailed("stream_line_too_long", "The backend sent an oversized event.")
        return b"".join(self._line(line) + b"\n" for line in lines)

    async def events(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self.upstream.aiter_raw():
                out = self._feed(chunk)
                if out:
                    yield out
            if self._buffer:
                yield self._line(bytes(self._buffer)) + b"\n\n"
                self._buffer.clear()
            if not self._done:
                raise _StreamFailed("stream_incomplete", "The backend ended the stream before it was complete.")
        except _StreamFailed as exc:
            self._failure = exc
            yield _sse_error("backend_error", exc.message)
        except httpx.TimeoutException:
            self._failure = _StreamFailed("timeout", "The backend stopped sending data in time.")
            yield _sse_error("timeout", self._failure.message)
        except httpx.HTTPError:
            self._failure = _StreamFailed("backend_error", "The connection to the backend failed during the stream.")
            yield _sse_error("backend_error", self._failure.message)
        except Exception as exc:  # the relay's fault, not the client's: close() must not record a disconnect
            log.error("stream relay for %s failed: %s", self.rec.request_id, type(exc).__name__)
            self._failure = _StreamFailed("internal_error", f"Internal error (request id {self.rec.request_id}).")
            yield _sse_error("internal_error", self._failure.message)
        finally:
            await self.close()

    async def close(self) -> None:
        """Release the slot, close the upstream response and write the audit event, once."""
        if self._closed:
            return
        self._closed = True
        self.lease.release()
        with anyio.CancelScope(shield=True):
            try:
                await self.upstream.aclose()
            except Exception:  # closing a broken connection may fail; nothing to do about it
                pass
        if self._failure is not None:
            outcome, error_type = "error", self._failure.error_type
        elif self._done:
            outcome, error_type = "success", None
        else:
            outcome, error_type = "error", "client_disconnected"
        _record_usage(self.rec, self._usage)
        self.rec.finish(outcome, 200, error_type)
        # Shielded, so a stream cut short by cancellation still records its event; in a worker
        # thread, so a write waiting for the database lock does not stall the event loop.
        with anyio.CancelScope(shield=True):
            try:
                await run_in_threadpool(_write_record, self.state, self.rec)
            except Exception as exc:
                log.error("audit write for streamed request %s failed: %s", self.rec.request_id, type(exc).__name__)


class _RelayResponse(StreamingResponse):
    """A streamed completion whose cleanup also runs when the client goes away
    before the first chunk (an async generator that never started has no finally)."""

    def __init__(self, relay: _StreamRelay, headers: dict[str, str]) -> None:
        super().__init__(relay.events(), media_type="text/event-stream", headers=headers)
        self.relay = relay

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.relay.close()


async def _open_stream(state: GatewayState, plan: _Plan, request: httpx.Request, rec: _Record,
                       lease: Lease) -> _RelayResponse:
    upstream = await _send(state, request)
    try:
        if upstream.status_code >= 300:
            raise _upstream_status_error(upstream.status_code, await _read_limited(upstream, MAX_UPSTREAM_ERROR_BODY))
        if "text/event-stream" not in upstream.headers.get("content-type", "").lower():
            raise _backend_failed("invalid_response", "The backend did not answer with an event stream.")
        _check_identity_encoding(upstream)
    except BaseException:
        with anyio.CancelScope(shield=True):
            await upstream.aclose()
        raise
    relay = _StreamRelay(state, upstream, lease, rec, plan.chat.model)
    headers = {"X-Request-ID": rec.request_id, "Cache-Control": "no-store", "X-Accel-Buffering": "no",
               **_limit_headers(plan)}
    return _RelayResponse(relay, headers)


# --- endpoints ---------------------------------------------------------------


async def _read_body(request: Request, limit: int) -> bytes:
    """The body, refusing more than `limit` bytes. BodySizeLimitMiddleware normally
    stops large bodies first; this keeps the router safe if it is mounted without it."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge(limit)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise BodyTooLarge(limit)
    return bytes(body)


async def _chat(request: Request, state: GatewayState, rec: _Record) -> Response:
    body = await _read_body(request, state.settings.server.max_body_bytes)
    identity = await _authenticate(state, request, rec)
    data = decode_json_object(body)
    named = data.get("model")
    if isinstance(named, str) and policy.MODEL_NAME.fullmatch(named):
        rec.details["model"] = named
        rec.resource = f"model:{named}"
    chat = validate_chat_request(data)
    rec.details["stream"] = chat.stream
    rec.details["max_tokens_requested"] = chat.max_tokens
    plan = await run_in_threadpool(_authorize_and_route, state, identity, chat, rec)
    target = await _resolve_target(state, plan, rec)
    lease = await _acquire(state, plan)
    handed_off = False
    try:
        upstream_request = _upstream_request(state, plan, target, rec.request_id)
        if chat.stream:
            response = await _open_stream(state, plan, upstream_request, rec, lease)
            handed_off = True  # the stream owns the slot now and releases it when it ends
            return response
        return await _complete(state, plan, upstream_request, rec)
    finally:
        if not handed_off:
            lease.release()


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    state = _state(request)
    rid = request_id_for(request.scope)
    rec = _chat_record(rid)
    response: Response
    try:
        response = await _chat(request, state, rec)
    except BodyTooLarge as exc:
        # Refused before authentication, like the middleware's own 413: not audited.
        return _json(413, too_large_body(exc.limit), rid)
    except ClientDisconnect:
        return Response(status_code=400, headers={"X-Request-ID": rid})
    except _ApiError as exc:
        rec.finish(exc.outcome, exc.status, exc.error_type)
        if exc.audit_detail:
            rec.details["error"] = exc.audit_detail
        response = _json(exc.status, openai_error(exc.message, exc.kind), rid, exc.headers)
    except Exception as exc:
        log.error("chat completion %s failed: %s", rid, type(exc).__name__)
        rec.finish("error", 500, "internal_error")
        response = _json(500, openai_error(f"Internal error (request id {rid}).", "internal_error"), rid)
    if isinstance(response, _RelayResponse):
        return response  # the stream writes its audit event when it ends
    try:
        await run_in_threadpool(_write_record, state, rec)
    except Exception as exc:
        log.error("audit write for %s failed: %s", rid, type(exc).__name__)
        if response.status_code < 400:
            # Fail closed: a completion that cannot be recorded is not delivered.
            return _json(500, openai_error("The request could not be recorded in the audit log, so the response "
                                           f"was withheld (request id {rid}).", "internal_error"), rid)
    return response


def _unix(stamp: str) -> int:
    try:
        return int(parse_rfc3339(stamp).timestamp())
    except (ValueError, TypeError):
        return 0


def _visible_models(state: GatewayState, identity: auth.AppIdentity, rec: _Record) -> list[dict[str, Any]]:
    """Routed models this app may use under the active policy, in OpenAI list form."""
    with state.db.session() as conn:
        compiled = _load_policy(state, conn, rec)
        routes = conn.execute("SELECT model, created_at FROM routes WHERE enabled = 1 ORDER BY model").fetchall()
    rec.policy_version = compiled.version if compiled else None
    return [{"id": r["model"], "object": "model", "created": _unix(r["created_at"]), "owned_by": "ferry"}
            for r in routes
            if policy.evaluate(compiled, principal=identity.principal, action=ACTION, model=r["model"]).allowed]


@router.get("/v1/models")
async def list_models(request: Request) -> Response:
    state = _state(request)
    rid = request_id_for(request.scope)
    rec = _Record(action="gateway.models.list", request_id=rid, resource="models",
                  details={"status_code": None, "count": None, "key_id": None, "environment": None,
                           "latency_ms": None, "error_type": None})
    response: Response
    try:
        identity = await _authenticate(state, request, rec)
        models = await run_in_threadpool(_visible_models, state, identity, rec)
        rec.details["count"] = len(models)
        rec.finish("success", 200, None)
        response = _json(200, {"object": "list", "data": models}, rid)
    except _ApiError as exc:
        rec.finish(exc.outcome, exc.status, exc.error_type)
        response = _json(exc.status, openai_error(exc.message, exc.kind), rid, exc.headers)
    except Exception as exc:
        log.error("model listing %s failed: %s", rid, type(exc).__name__)
        rec.finish("error", 500, "internal_error")
        response = _json(500, openai_error(f"Internal error (request id {rid}).", "internal_error"), rid)
    try:
        await run_in_threadpool(_write_record, state, rec)
    except Exception as exc:
        log.error("audit write for %s failed: %s", rid, type(exc).__name__)
        if response.status_code < 400:
            return _json(500, openai_error("The request could not be recorded in the audit log, so the response "
                                           f"was withheld (request id {rid}).", "internal_error"), rid)
    return response


@router.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def unknown_endpoint(request: Request, path: str) -> Response:
    return _json(404, openai_error("Unknown endpoint. This gateway serves GET /v1/models and "
                                   "POST /v1/chat/completions.", "invalid_request_error", "unknown_endpoint"),
                 request_id_for(request.scope))
