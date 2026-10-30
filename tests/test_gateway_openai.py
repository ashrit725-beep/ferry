"""Tests for the OpenAI-compatible gateway API (ferry/gateway/openai_api.py).

The backend is a TEST DOUBLE (tests/helpers_upstream.py) on 127.0.0.1. Most
negative tests assert that the double received zero requests: denied, invalid
and unauthenticated requests must never reach a backend.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import socket
import time
import uuid
from contextlib import ExitStack
from typing import Any, Callable, Iterator

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ferry import auth, backends
from ferry.config import ServerSettings
from ferry.db import write_tx
from ferry.gateway import openai_api
from ferry.gateway.limits import REQUEST_ID_PATTERN, BodySizeLimitMiddleware
from ferry.util import rfc3339

from helpers_gateway import (
    ACTOR, APP, MODEL, UPSTREAM_MODEL, GatewayEnv, activate, add_app, add_backend, allow, bearer, chat_body, deny,
    gateway_env, live_server, make_app, run_health, set_status, store_artifact, store_path,
)
from helpers_upstream import FakeUpstream


@pytest.fixture
def upstream() -> Iterator[FakeUpstream]:
    with FakeUpstream() as up:
        yield up


@pytest.fixture
def make_env(data_dir, upstream) -> Iterator[Callable[..., GatewayEnv]]:
    with ExitStack() as stack:
        yield lambda **kw: stack.enter_context(gateway_env(data_dir, upstream, **kw))


@pytest.fixture
def env(make_env) -> GatewayEnv:
    return make_env()


def _error(response: httpx.Response) -> dict[str, Any]:
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"message", "type", "code", "param"}
    assert body["error"]["param"] is None
    return body["error"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# --- success paths ------------------------------------------------------------


def test_non_stream_success_rewrites_model_forwards_backend_token_and_audits_usage(env: GatewayEnv) -> None:
    r = env.chat(chat_body(MODEL, max_tokens=50))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == MODEL  # the double answers as "fake-alias"
    assert body["choices"][0]["message"]["content"] == env.upstream.completion_text
    assert "x-ferry-max-tokens" not in r.headers  # 50 is under every cap
    assert REQUEST_ID_PATTERN.fullmatch(r.headers["x-request-id"])

    [sent] = env.upstream.chat_requests()
    payload = sent.json()
    assert payload["model"] == UPSTREAM_MODEL
    assert payload["max_tokens"] == 50
    assert payload["stream"] is False
    assert sent.headers["authorization"] == f"Bearer {env.upstream.token}"
    assert all(env.api_key not in v for v in sent.headers.values()), "the app's key must never reach the backend"
    assert sent.headers["x-request-id"] == r.headers["x-request-id"]

    [event] = env.events()
    assert event["outcome"] == "success"
    assert event["actor_type"] == "app" and event["actor_id"] == APP
    assert event["resource"] == f"model:{MODEL}"
    assert event["correlation_id"] == r.headers["x-request-id"]
    assert event["policy_version"] == 1
    d = event["details"]
    assert d["status_code"] == 200
    assert d["decision"] == "allow" and d["decisive_rule"] == "report-chat"
    assert d["backend"] == "llama" and d["route_id"] == env.route_id
    assert d["artifact_digest"] == env.digest and d["provenance"] == "verified"
    assert d["stream"] is False
    assert d["max_tokens_requested"] == 50 and d["max_tokens_effective"] == 50
    assert d["prompt_tokens"] == env.upstream.prompt_tokens
    assert d["completion_tokens"] == len(env.upstream.pieces())
    assert isinstance(d["latency_ms"], int) and d["error_type"] is None
    assert d["environment"] == "test" and len(d["key_id"]) == 12


def test_stream_success_rewrites_every_chunk_and_audits_usage(env: GatewayEnv) -> None:
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        lines = [line for line in r.iter_lines() if line]
    assert lines[-1] == "data: [DONE]"
    chunks = [json.loads(line[len("data: "):]) for line in lines[:-1]]
    assert chunks and all(c["model"] == MODEL for c in chunks)
    text = "".join((c["choices"][0]["delta"].get("content") or "") for c in chunks if c["choices"])
    assert text == env.upstream.completion_text
    assert chunks[-1]["choices"] == [] and chunks[-1]["usage"]["completion_tokens"] == len(env.upstream.pieces())

    [sent] = env.upstream.chat_requests()
    assert sent.json()["stream"] is True
    assert sent.json()["stream_options"] == {"include_usage": True}

    [event] = env.events()
    assert event["outcome"] == "success"
    assert event["details"]["stream"] is True
    assert event["details"]["prompt_tokens"] == env.upstream.prompt_tokens
    assert event["details"]["completion_tokens"] == len(env.upstream.pieces())
    assert event["details"]["status_code"] == 200


def test_stream_slot_is_released_after_stream(make_env) -> None:
    env = make_env(backend_kw={"max_concurrency": 1}, queue_timeout_s=0.2)
    for _ in range(3):
        with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                               headers=bearer(env.api_key)) as r:
            assert r.status_code == 200
            list(r.iter_lines())
    assert env.chat().status_code == 200


# --- authentication -----------------------------------------------------------


def _revoke(env: GatewayEnv) -> str:
    with env.conn() as c:
        auth.revoke_api_key(c, auth.parse_api_key(env.api_key)[0], **ACTOR)  # type: ignore[index]
    return env.api_key


def _disable(env: GatewayEnv) -> str:
    with env.conn() as c:
        auth.update_principal(c, env.principal_id, disabled=True, **ACTOR)
    return env.api_key


def _expired(env: GatewayEnv) -> str:
    with env.conn() as c:
        key = auth.issue_api_key(c, env.principal_id, expires_in_days=1, **ACTOR)
        with write_tx(c):
            c.execute("UPDATE api_keys SET expires_at = ? WHERE key_id = ?",
                      (rfc3339(dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)), key["key_id"]))
    return key["api_key"]


def _wrong_secret(env: GatewayEnv) -> str:
    key_id, secret = auth.parse_api_key(env.api_key)  # type: ignore[misc]
    other = ("A" if secret[0] != "A" else "B") + secret[1:]
    return f"fyk_{key_id}_{other}"


@pytest.mark.parametrize("make_header, reason", [
    (lambda env: None, "missing"),
    (lambda env: "Bearer not-a-ferry-key", "malformed"),
    (lambda env: f"Basic {env.api_key}", "malformed"),
    (lambda env: "Bearer fyk_000000000000_" + "x" * 43, "unknown_key"),
    (lambda env: f"Bearer {_wrong_secret(env)}", "bad_secret"),
    (lambda env: f"Bearer {_revoke(env)}", "revoked"),
    (lambda env: f"Bearer {_expired(env)}", "expired"),
    (lambda env: f"Bearer {_disable(env)}", "principal_disabled"),
])
def test_unauthenticated_requests_get_401_and_never_reach_backend(env: GatewayEnv, make_header, reason: str) -> None:
    header = make_header(env)
    headers = {"Authorization": header} if header else {}
    r = env.client.post("/v1/chat/completions", json=chat_body(MODEL), headers=headers)
    assert r.status_code == 401
    err = _error(r)
    assert err["type"] == "authentication_error"
    assert reason not in err["message"]  # the precise reason is for the audit log only
    assert r.headers["www-authenticate"] == "Bearer"
    assert env.upstream.requests == []
    [event] = env.events()
    assert event["outcome"] == "unauthenticated"
    assert event["details"]["auth_failure"] == reason
    assert event["details"]["status_code"] == 401


def test_every_auth_failure_gets_the_same_answer(env: GatewayEnv) -> None:
    answers = {env.client.post("/v1/chat/completions", json=chat_body(MODEL), headers=h).json()["error"]["message"]
               for h in ({}, bearer("junk"), bearer(_wrong_secret(env)), bearer("fyk_000000000000_" + "x" * 43))}
    assert len(answers) == 1


# --- validation ----------------------------------------------------------------


@pytest.mark.parametrize("content", [
    b"{not json",
    b"[]",
    b'"a string"',
    b"",
    b'{"model": "qwen-test", "messages": [{"role": "user", "content": "hi"}], "temperature": NaN}',
    b'{"model": "qwen-test", "messages": [{"role": "user", "content": "hi"}], "temperature": 1e999}',
    b"\xff\xfe not utf-8",
])
def test_malformed_body_is_400(env: GatewayEnv, content: bytes) -> None:
    r = env.client.post("/v1/chat/completions", content=content,
                        headers={**bearer(env.api_key), "Content-Type": "application/json"})
    assert r.status_code == 400
    assert _error(r)["type"] == "invalid_request_error"
    assert env.upstream.requests == []
    assert env.events()[-1]["outcome"] == "rejected"


@pytest.mark.parametrize("body", [
    {"messages": [{"role": "user", "content": "hi"}]},
    {"model": "", "messages": [{"role": "user", "content": "hi"}]},
    {"model": "qwen-*", "messages": [{"role": "user", "content": "hi"}]},
    {"model": MODEL, "messages": []},
    {"model": MODEL, "messages": "hi"},
    {"model": MODEL, "messages": [{"role": "user", "content": "hi"}] * 513},
    {"model": MODEL, "messages": [{"role": "wizard", "content": "hi"}]},
    {"model": MODEL, "messages": [{"role": "user"}]},
    {"model": MODEL, "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]},
    {"model": MODEL, "messages": [{"role": "tool", "content": "result"}]},
    {"model": MODEL, "messages": [{"role": "user", "content": "hi", "tool_calls": [{}]}]},
    chat_body(temperature=2.5),
    chat_body(top_p=-0.1),
    chat_body(presence_penalty=3),
    chat_body(frequency_penalty="high"),
    chat_body(n=2),
    chat_body(max_tokens=0),
    chat_body(max_tokens="10"),
    chat_body(max_tokens=True),
    chat_body(max_completion_tokens=2_000_000),
    chat_body(stream="yes"),
    chat_body(stop=["a", "b", "c", "d", "e"]),
    chat_body(stop=7),
    chat_body(response_format="json"),
    chat_body(tools={"type": "function"}),
    chat_body(tool_choice="sometimes"),
    chat_body(seed=1.5),
    chat_body(user=7),
])
def test_invalid_fields_are_400_and_never_reach_backend(env: GatewayEnv, body: dict[str, Any]) -> None:
    r = env.chat(body)
    assert r.status_code == 400, r.text
    assert _error(r)["type"] == "invalid_request_error"
    assert env.upstream.requests == []
    [event] = env.events()
    assert event["outcome"] == "rejected"
    assert event["details"]["error_type"] == "invalid_request_error"


def test_validation_errors_do_not_echo_request_values(env: GatewayEnv) -> None:
    marker = "LEAK-" + uuid.uuid4().hex
    r = env.chat({"model": MODEL, "messages": [{"role": marker, "content": marker}]})
    assert r.status_code == 400
    assert marker not in r.text
    assert marker not in json.dumps(env.events())


def test_unknown_fields_are_dropped_not_forwarded(env: GatewayEnv) -> None:
    body = chat_body(MODEL, temperature=0.2, top_p=0.9, seed=7, stop=["\n\n"], user="u-1", n=1,
                     logit_bias={"50256": -100}, logprobs=True, evil_field={"x": 1},
                     stream_options={"include_usage": False}, max_completion_tokens=40)
    body["messages"] = [{"role": "system", "content": "be brief", "cache_control": {"type": "x"}},
                        {"role": "user", "content": [{"type": "text", "text": "hi", "extra": 1}]}]
    r = env.chat(body)
    assert r.status_code == 200, r.text
    payload = env.upstream.chat_requests()[0].json()
    assert set(payload) == {"model", "messages", "temperature", "top_p", "seed", "stop", "user", "n", "max_tokens",
                            "stream"}
    assert payload["max_tokens"] == 40 and payload["model"] == UPSTREAM_MODEL
    assert payload["messages"] == [{"role": "system", "content": "be brief"},
                                   {"role": "user", "content": [{"type": "text", "text": "hi"}]}]


def test_tool_messages_are_accepted(env: GatewayEnv) -> None:
    body = chat_body(MODEL, tools=[{"type": "function", "function": {"name": "f", "parameters": {}}}],
                     tool_choice="auto")
    body["messages"] += [
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "42"},
    ]
    assert env.chat(body).status_code == 200
    sent = env.upstream.chat_requests()[0].json()
    assert sent["messages"][2] == {"role": "tool", "content": "42", "tool_call_id": "c1"}
    assert sent["tool_choice"] == "auto"


def test_request_nested_too_deeply_to_forward_is_400(env: GatewayEnv) -> None:
    # json.loads accepts deeper nesting than json.dumps can encode; such a request used to be a 500.
    depth = 17_000
    tool = '{"a":' * depth + "1" + "}" * depth
    try:
        json.dumps(json.loads(tool))
    except RecursionError:
        pass
    else:
        pytest.skip("this interpreter's JSON encoder handles the nesting")
    raw = ('{"model": "%s", "messages": [{"role": "user", "content": "hi"}], "tools": [%s]}' % (MODEL, tool)).encode()
    r = env.client.post("/v1/chat/completions", content=raw,
                        headers={**bearer(env.api_key), "Content-Type": "application/json"})
    assert r.status_code == 400, r.text
    assert _error(r)["type"] == "invalid_request_error"
    assert env.upstream.requests == []
    [event] = env.events()
    assert event["outcome"] == "rejected" and event["details"]["decision"] is None  # refused before authorization


# --- body size -------------------------------------------------------------------


def test_body_over_limit_is_413_by_content_length(make_env) -> None:
    env = make_env(server=ServerSettings(max_body_bytes=2048))
    big = chat_body(MODEL, prompt="x" * 4096)
    r = env.chat(big, headers={"X-Request-ID": "big-1"})
    assert r.status_code == 413
    assert _error(r)["type"] == "request_too_large"
    assert r.headers["x-request-id"] == "big-1"
    assert env.upstream.requests == []
    assert env.chat(chat_body(MODEL)).status_code == 200


def test_body_over_limit_is_413_when_chunked(make_env) -> None:
    env = make_env(server=ServerSettings(max_body_bytes=2048))
    payload = json.dumps(chat_body(MODEL, prompt="y" * 5000)).encode()

    def chunks() -> Iterator[bytes]:
        for i in range(0, len(payload), 512):
            yield payload[i:i + 512]

    r = env.client.post("/v1/chat/completions", content=chunks(),
                        headers={**bearer(env.api_key), "Content-Type": "application/json"})
    assert "content-length" not in r.request.headers
    assert r.status_code == 413
    assert _error(r)["type"] == "request_too_large"
    assert REQUEST_ID_PATTERN.fullmatch(r.headers["x-request-id"])
    assert env.upstream.requests == []


def test_router_enforces_the_body_limit_even_without_the_middleware(data_dir, upstream) -> None:
    with gateway_env(data_dir, upstream, server=ServerSettings(max_body_bytes=2048)) as env:
        bare = FastAPI(lifespan=env.client.app.router.lifespan_context)  # type: ignore[attr-defined]
        bare.include_router(openai_api.router)
        with TestClient(bare) as client:
            big = json.dumps(chat_body(MODEL, prompt="z" * 4096)).encode()
            for content in (big, iter([big[:1500], big[1500:]])):
                r = client.post("/v1/chat/completions", content=content,
                                headers={**bearer(env.api_key), "Content-Type": "application/json"})
                assert r.status_code == 413 and _error(r)["type"] == "request_too_large"
            assert client.post("/v1/chat/completions", json=chat_body(MODEL),
                               headers=bearer(env.api_key)).status_code == 200
        assert len(env.upstream.chat_requests()) == 1


@pytest.mark.parametrize("values", [[b"10", b"20000"], [b"-1"], [b"12abc"], [b""]])
def test_malformed_content_length_is_400_before_the_app(values: list[bytes]) -> None:
    # ASGI directly: HTTP clients refuse to send these headers.
    sent: list[dict[str, Any]] = []

    async def app(scope, receive, send):
        raise AssertionError("the request must be stopped before the app")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "headers": [(b"content-length", v) for v in values]}
    asyncio.run(BodySizeLimitMiddleware(app, 1024)(scope, receive, send))
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"])["error"]["type"] == "invalid_request_error"


# --- authorization --------------------------------------------------------------


def test_deny_rule_is_403_with_rule_id_and_never_reaches_backend(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL]), deny("block-qwen", ["*"], ["qwen-*"])])
    r = env.chat(chat_body(MODEL))
    assert r.status_code == 403
    err = _error(r)
    assert err["type"] == "permission_denied"
    assert "block-qwen" in err["message"]
    assert env.upstream.requests == []
    [event] = env.events()
    assert event["outcome"] == "denied"
    assert event["details"]["decision"] == "deny" and event["details"]["decisive_rule"] == "block-qwen"
    assert event["policy_version"] == 1


def test_no_matching_rule_is_403_no_rule_allows(make_env) -> None:
    env = make_env(rules=[allow("other-chat", ["app:other-app"], [MODEL])])
    r = env.chat(chat_body(MODEL))
    assert r.status_code == 403
    assert "no rule allows" in _error(r)["message"]
    assert env.upstream.requests == []


def test_no_active_policy_denies_everything(data_dir, upstream) -> None:
    with gateway_env(data_dir, upstream) as env:
        with env.conn() as c, write_tx(c):
            c.execute("DELETE FROM active_policy")
        r = env.chat()
        assert r.status_code == 403
        assert "no active policy" in _error(r)["message"]
        assert env.upstream.requests == []


def test_app_cannot_use_a_model_allowed_only_to_another_app(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL]),
                          allow("hr-only", ["app:hr-bot"], ["hr-model"])])
    with env.conn() as c:
        _, hr_key = add_app(c, "hr-bot")
        backends.create_route(c, model="hr-model", backend_id=env.backend_id, require_verified=False, **ACTOR)
    r = env.chat(chat_body("hr-model"))
    assert r.status_code == 403 and "no rule allows" in _error(r)["message"]
    assert env.upstream.requests == []
    assert env.chat(chat_body("hr-model"), key=hr_key).status_code == 200
    assert env.chat(chat_body(MODEL), key=hr_key).status_code == 403


def test_policy_activation_takes_effect_on_next_request(env: GatewayEnv) -> None:
    assert env.chat().status_code == 200
    with env.conn() as c:
        activate(c, deny("lockdown", ["*"], ["*"]))
    r = env.chat()
    assert r.status_code == 403 and "lockdown" in _error(r)["message"]
    assert len(env.upstream.chat_requests()) == 1


def test_tampered_stored_policy_fails_closed(env: GatewayEnv) -> None:
    with env.conn() as c, write_tx(c):
        c.execute("UPDATE policies SET document = replace(document, 'report-chat', 'evil-chat')")
    env.state.policy.invalidate()
    r = env.chat()
    assert r.status_code == 403
    assert "could not be loaded" in _error(r)["message"]
    assert env.upstream.requests == []


def test_streaming_disallowed_by_policy_is_403(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL], allow_stream=False)])
    r = env.chat(chat_body(MODEL, stream=True))
    assert r.status_code == 403
    assert "Streaming is not allowed" in _error(r)["message"]
    assert env.upstream.requests == []
    assert env.events()[-1]["details"]["error_type"] == "stream_not_allowed"
    assert env.chat(chat_body(MODEL)).status_code == 200


# --- max_tokens --------------------------------------------------------------------


def test_max_tokens_clamped_to_policy_cap(env: GatewayEnv) -> None:
    r = env.chat(chat_body(MODEL, max_tokens=5000))
    assert r.status_code == 200
    assert r.headers["x-ferry-max-tokens"] == "512"
    assert env.upstream.chat_requests()[0].json()["max_tokens"] == 512
    d = env.events()[-1]["details"]
    assert d["max_tokens_requested"] == 5000 and d["max_tokens_effective"] == 512


def test_max_tokens_clamped_to_ceiling_when_policy_has_no_cap(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL])], max_tokens_ceiling=100)
    r = env.chat(chat_body(MODEL))
    assert r.headers["x-ferry-max-tokens"] == "100"
    r = env.chat(chat_body(MODEL, max_tokens=50))
    assert "x-ferry-max-tokens" not in r.headers
    r = env.chat(chat_body(MODEL, max_tokens=60, max_completion_tokens=30))
    assert "x-ferry-max-tokens" not in r.headers
    assert [s.json()["max_tokens"] for s in env.upstream.chat_requests()] == [100, 50, 30]


# --- routing, availability, provenance -----------------------------------------------


def test_no_route_is_404(make_env) -> None:
    env = make_env(rules=[allow("everything", [f"app:{APP}"], ["*"])])
    r = env.chat(chat_body("unrouted-model"))
    assert r.status_code == 404
    assert _error(r)["type"] == "model_not_found"
    assert env.upstream.requests == []
    assert env.events()[-1]["outcome"] == "rejected"


@pytest.mark.parametrize("state", ["down", "loading"])
def test_backend_not_up_is_503(env: GatewayEnv, state: str) -> None:
    with env.conn() as c:
        set_status(c, env.backend_id, state)
    r = env.chat()
    assert r.status_code == 503
    assert _error(r)["type"] == "backend_unavailable"
    assert env.upstream.requests == []
    assert env.events()[-1]["outcome"] == "unavailable"


def test_disabled_route_and_backend_are_503(env: GatewayEnv) -> None:
    with env.conn() as c:
        backends.update_route(c, env.route_id, {"enabled": False}, **ACTOR)
    assert env.chat().status_code == 503
    with env.conn() as c:
        backends.update_route(c, env.route_id, {"enabled": True}, **ACTOR)
        backends.update_backend(c, env.settings, env.backend_id, {"enabled": False}, **ACTOR)
    r = env.chat()
    assert r.status_code == 503 and "disabled" in _error(r)["message"]
    assert env.upstream.requests == []


def test_backend_url_change_requires_a_new_health_check(env: GatewayEnv) -> None:
    with env.conn() as c:
        backends.update_backend(c, env.settings, env.backend_id, {"base_url": f"http://127.0.0.1:{_free_port()}"},
                                **ACTOR)
    r = env.chat()
    assert r.status_code == 503 and "health-checked" in _error(r)["message"]


def test_connection_refused_is_503(make_env) -> None:
    env = make_env(rules=[allow("everything", [f"app:{APP}"], ["*"])])
    with env.conn() as c:
        dead = add_backend(c, env.settings, f"http://127.0.0.1:{_free_port()}", name="dead", kind="openai")
        backends.create_route(c, model="dead-model", backend_id=dead, require_verified=False, **ACTOR)
        set_status(c, dead, "up")
    r = env.chat(chat_body("dead-model"))
    assert r.status_code == 503
    assert _error(r)["type"] == "backend_unavailable"
    assert env.events()[-1]["details"]["error_type"] == "connect_error"


def test_slow_upstream_is_504(make_env) -> None:
    env = make_env(backend_kw={"timeout_s": 0.3})
    env.upstream.delay_s = 1.5
    r = env.chat()
    assert r.status_code == 504
    assert _error(r)["type"] == "timeout"
    event = env.events()[-1]
    assert event["outcome"] == "error" and event["details"]["error_type"] == "timeout"


@pytest.mark.parametrize("upstream_status, status, kind", [
    (500, 502, "backend_error"),
    (404, 502, "backend_error"),
    (401, 502, "backend_error"),
    (503, 503, "backend_unavailable"),
    (400, 400, "invalid_request_error"),
])
def test_upstream_error_statuses_are_mapped(env: GatewayEnv, upstream_status: int, status: int, kind: str) -> None:
    env.upstream.chat_status = upstream_status
    env.upstream.chat_error_message = "context length exceeded"
    r = env.chat()
    assert r.status_code == status
    assert _error(r)["type"] == kind
    event = env.events()[-1]
    assert event["details"]["error_type"] == f"upstream_{upstream_status}"
    assert "context length exceeded" not in json.dumps(event)
    if upstream_status == 400:
        assert "context length exceeded" in _error(r)["message"]


def test_provenance_mismatch_with_require_verified_is_503(env: GatewayEnv) -> None:
    with env.conn() as c:
        other = store_artifact(env.settings, c, b"a different model file")
    env.upstream.model_path = store_path(env.settings, other)
    run_health(env.settings, env.backend_id)
    with env.conn() as c:
        [route] = backends.list_routes(c)
    assert route["provenance"]["state"] == "mismatch" and route["provenance"]["served_digest"] == other
    assert route["available"] is False
    env.upstream.clear()
    r = env.chat()
    assert r.status_code == 503
    assert "mismatch" in _error(r)["message"]
    assert env.upstream.requests == []
    assert env.events()[-1]["details"]["provenance"] == "mismatch"


def test_unverified_file_outside_store_is_503_when_required(env: GatewayEnv, tmp_path) -> None:
    outside = tmp_path / "loose.gguf"
    outside.write_bytes(b"GGUF fake model bytes")
    env.upstream.model_path = str(outside)
    run_health(env.settings, env.backend_id)
    env.upstream.clear()
    r = env.chat()
    assert r.status_code == 503 and "unverified" in _error(r)["message"]
    assert env.upstream.requests == []


def test_mismatch_is_served_but_recorded_when_not_required(make_env) -> None:
    env = make_env(require_verified=False)
    with env.conn() as c:
        other = store_artifact(env.settings, c, b"another file again")
    env.upstream.model_path = store_path(env.settings, other)
    run_health(env.settings, env.backend_id)
    assert env.chat().status_code == 200
    assert env.events()[-1]["details"]["provenance"] == "mismatch"


def test_egress_guard_is_rechecked_per_request(env: GatewayEnv) -> None:
    with env.conn() as c, write_tx(c):
        # Simulates a database edited behind the API's back.
        c.execute("UPDATE backends SET base_url = 'http://8.8.8.8:8080' WHERE id = ?", (env.backend_id,))
    r = env.chat()
    assert r.status_code == 503
    event = env.events()[-1]
    assert event["details"]["error_type"] == "egress_denied"
    assert "8.8.8.8" in event["details"]["error"]


def test_unreadable_token_file_is_503(env: GatewayEnv) -> None:
    with env.conn() as c:
        path = c.execute("SELECT auth_token_file FROM backends WHERE id = ?", (env.backend_id,)).fetchone()[0]
    os.chmod(path, 0o644)
    r = env.chat()
    assert r.status_code == 503
    assert path not in r.text  # host paths are for the audit log, not for apps
    assert env.events()[-1]["details"]["error_type"] == "backend_credentials"
    assert env.upstream.requests == []


# --- concurrency ------------------------------------------------------------------


def test_backend_concurrency_exhaustion_is_429_with_retry_after(make_env) -> None:
    env = make_env(backend_kw={"max_concurrency": 1}, queue_timeout_s=0.2)
    portal = env.client.portal
    assert portal is not None
    lease = portal.call(env.state.limiter.acquire, env.backend_id, 1)
    try:
        r = env.chat()
        assert r.status_code == 429
        assert _error(r)["type"] == "rate_limit_error"
        assert r.headers["retry-after"] == "1"
        assert env.upstream.requests == []
        assert env.events()[-1]["details"]["error_type"] == "queue_timeout_backend"
    finally:
        portal.call(lease.release)
    assert env.chat().status_code == 200


def test_global_concurrency_exhaustion_is_429(make_env) -> None:
    env = make_env(max_concurrency=1, queue_timeout_s=0.2)
    portal = env.client.portal
    assert portal is not None
    lease = portal.call(env.state.limiter.acquire, 999_999, 1)  # another backend holds the only global slot
    try:
        r = env.chat()
        assert r.status_code == 429
        assert env.events()[-1]["details"]["error_type"] == "queue_timeout_gateway"
    finally:
        portal.call(lease.release)
    assert env.chat().status_code == 200


# --- streams that go wrong --------------------------------------------------------------


def test_stream_dropped_mid_way_ends_with_error_event_and_is_audited(env: GatewayEnv) -> None:
    env.upstream.drop_mid_stream = True
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as r:
        assert r.status_code == 200
        lines = [line for line in r.iter_lines() if line]
    assert "[DONE]" not in lines[-1]
    assert json.loads(lines[-1][len("data: "):])["error"]["type"] == "backend_error"
    event = env.events()[-1]
    assert event["outcome"] == "error" and event["details"]["error_type"] == "backend_error"


def test_client_hanging_up_mid_stream_is_audited_and_frees_the_slot(data_dir, upstream) -> None:
    upstream.completion_text = " ".join(f"w{i}" for i in range(40))
    with gateway_env(data_dir, upstream, backend_kw={"max_concurrency": 1}, queue_timeout_s=0.5) as env:
        upstream.chunk_delay_s = 0.1
        with live_server(make_app(env.settings)) as base, httpx.Client(trust_env=False, timeout=10) as client:
            with client.stream("POST", base + "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                               headers=bearer(env.api_key)) as r:
                assert r.status_code == 200
                next(r.iter_lines())
            # Leaving the block closes the connection while the backend is still streaming.
            deadline = time.monotonic() + 5
            while not env.events() and time.monotonic() < deadline:
                time.sleep(0.05)
            [event] = env.events()
            assert event["outcome"] == "error" and event["details"]["error_type"] == "client_disconnected"
            assert event["details"]["stream"] is True
            upstream.chunk_delay_s = 0
            # max_concurrency is 1: this only succeeds if the abandoned stream gave its slot back.
            again = client.post(base + "/v1/chat/completions", json=chat_body(MODEL), headers=bearer(env.api_key))
            assert again.status_code == 200


def test_stream_without_done_is_reported_incomplete(env: GatewayEnv) -> None:
    env.upstream.send_done = False
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as r:
        lines = [line for line in r.iter_lines() if line]
    assert "error" in json.loads(lines[-1][len("data: "):])
    assert env.events()[-1]["details"]["error_type"] == "stream_incomplete"


def test_lone_surrogate_from_the_backend_is_relayed_escaped(env: GatewayEnv) -> None:
    # Half of a split emoji has no UTF-8 form; re-encoding it used to fail with a 500 or a cut stream.
    env.upstream.completion_text = "split emoji \ud83d here"
    r = env.chat()
    assert r.status_code == 200, r.text
    assert b"split emoji \\ud83d here" in r.content
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as s:
        lines = [line for line in s.iter_lines() if line]
    assert lines[-1] == "data: [DONE]"
    assert any("\\ud83d" in line for line in lines)
    assert [e["outcome"] for e in env.events()] == ["success", "success"]


def test_unexpected_relay_failure_is_not_filed_as_a_client_disconnect(make_env, monkeypatch) -> None:
    env = make_env(backend_kw={"max_concurrency": 1}, queue_timeout_s=0.5)

    def broken(self: Any, line: bytes) -> bytes:
        raise RuntimeError("simulated relay bug")

    monkeypatch.setattr(openai_api._StreamRelay, "_line", broken)
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as r:
        lines = [line for line in r.iter_lines() if line]
    assert json.loads(lines[-1][len("data: "):])["error"]["type"] == "internal_error"
    [event] = env.events()
    assert event["outcome"] == "error" and event["details"]["error_type"] == "internal_error"
    monkeypatch.undo()
    assert env.chat().status_code == 200  # the slot was given back


# --- request ids, privacy, network hygiene ------------------------------------------------


def test_request_id_is_echoed_or_generated(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL]), deny("no-other", ["*"], ["other"])])
    ok = env.chat(headers={"X-Request-ID": "trace.abc-123_X"})
    assert ok.headers["x-request-id"] == "trace.abc-123_X"
    denied = env.chat(chat_body("other"), headers={"X-Request-ID": "trace-2"})
    assert denied.status_code == 403 and denied.headers["x-request-id"] == "trace-2"
    unauth = env.client.post("/v1/chat/completions", json=chat_body(), headers={"X-Request-ID": "trace-3"})
    assert unauth.headers["x-request-id"] == "trace-3"
    for bad in ("has space", "x" * 65, "semi;colon", "ünïcode"):
        r = env.chat(headers={"X-Request-ID": bad.encode("utf-8")})  # type: ignore[dict-item]
        assert r.headers["x-request-id"] != bad and REQUEST_ID_PATTERN.fullmatch(r.headers["x-request-id"])
    generated = env.chat()
    assert REQUEST_ID_PATTERN.fullmatch(generated.headers["x-request-id"])
    assert [e["correlation_id"] for e in env.events()[:3]] == ["trace.abc-123_X", "trace-2", "trace-3"]


def test_prompt_and_completion_never_reach_the_database(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL], allow_stream=True),
                          deny("no-secret-model", ["*"], ["secret-model"])])
    prompt = "PROMPT-" + uuid.uuid4().hex
    completion = "COMPLETION-" + uuid.uuid4().hex
    env.upstream.completion_text = f"{completion} and more words"
    assert env.chat(chat_body(MODEL, prompt=prompt)).status_code == 200
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, prompt=prompt, stream=True),
                           headers=bearer(env.api_key)) as r:
        assert completion in "".join(r.iter_lines())
    assert env.chat(chat_body("secret-model", prompt=prompt)).status_code == 403
    assert env.chat({"model": MODEL, "messages": [{"role": prompt, "content": prompt}]}).status_code == 400
    env.upstream.chat_status = 400
    env.upstream.chat_error_message = f"cannot handle {prompt}"
    assert env.chat(chat_body(MODEL, prompt=prompt)).status_code == 400
    assert len(env.events()) == 5
    raw = b"".join(p.read_bytes() for p in env.settings.data_dir.glob("ferry.db*"))
    assert raw, "expected the database files to exist"
    for secret in (prompt, completion, env.api_key, auth.parse_api_key(env.api_key)[1]):  # type: ignore[index]
        assert secret.encode() not in raw


def test_proxy_environment_is_ignored(data_dir, upstream, monkeypatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{_free_port()}")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    # Control: a client that honours the environment cannot reach the double.
    with pytest.raises(httpx.HTTPError):
        httpx.get(upstream.base_url + "/health", trust_env=True, timeout=2)
    upstream.clear()
    with gateway_env(data_dir, upstream) as env:
        assert env.state.http.trust_env is False
        r = env.chat()
        assert r.status_code == 200, r.text
        assert len(env.upstream.chat_requests()) == 1


def test_shared_client_never_follows_redirects_or_keeps_cookies(env: GatewayEnv) -> None:
    assert env.state.http.follow_redirects is False
    assert env.state.http.trust_env is False
    env.upstream.set_cookie = "upstream-session=abc123; Path=/"
    assert env.chat().status_code == 200
    assert env.chat().status_code == 200
    assert len(env.state.http.cookies.jar) == 0
    assert all("cookie" not in r.headers for r in env.upstream.chat_requests())


# --- /v1/models ---------------------------------------------------------------------


def test_models_list_is_filtered_by_policy(make_env) -> None:
    env = make_env(rules=[allow("report-chat", [f"app:{APP}"], [MODEL]),
                          allow("hr-only", ["app:hr-bot"], ["hr-model"])])
    with env.conn() as c:
        backends.create_route(c, model="hr-model", backend_id=env.backend_id, require_verified=False, **ACTOR)
        _, hr_key = add_app(c, "hr-bot")
    r = env.client.get("/v1/models", headers=bearer(env.api_key))
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "list"
    assert [m["id"] for m in body["data"]] == [MODEL]
    assert body["data"][0]["object"] == "model" and body["data"][0]["created"] > 0
    assert [m["id"] for m in env.client.get("/v1/models", headers=bearer(hr_key)).json()["data"]] == ["hr-model"]
    unauth = env.client.get("/v1/models")
    assert unauth.status_code == 401 and _error(unauth)["type"] == "authentication_error"
    listed = env.events("gateway.models.list")
    assert [e["outcome"] for e in listed] == ["success", "success", "unauthenticated"]
    assert listed[0]["details"]["count"] == 1 and listed[0]["actor_id"] == APP
    assert env.upstream.requests == []


def test_unknown_v1_endpoint_is_an_openai_shaped_404(env: GatewayEnv) -> None:
    r = env.client.post("/v1/embeddings", json={"input": "x"}, headers=bearer(env.api_key))
    assert r.status_code == 404
    assert _error(r)["code"] == "unknown_endpoint"
    assert REQUEST_ID_PATTERN.fullmatch(r.headers["x-request-id"])
    assert env.upstream.requests == []
