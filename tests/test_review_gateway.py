"""Adversarial review of the gateway area: ferry/gateway/openai_api.py, limits.py,
state.py, ferry/backends.py and ferry/audit.py (review of 2026-10-28).

Each test pins one defect found in the review and fails against the code as
reviewed; none is marked xfail. The backend is the TEST DOUBLE in
tests/helpers_upstream.py on 127.0.0.1. No test connects to any other address:
the egress tests only call the guard (literals, or a monkeypatched resolver).
"""

from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import threading
import time
from typing import Any, Iterator

import httpx
import pytest

from ferry import audit, backends
from ferry.db import write_tx
from ferry.gateway.limits import ConcurrencyLimiter, QueueTimeout

from helpers_gateway import MODEL, GatewayEnv, bearer, chat_body, gateway_env, live_server, make_app
from helpers_upstream import FakeUpstream


@pytest.fixture
def upstream() -> Iterator[FakeUpstream]:
    with FakeUpstream() as up:
        yield up


@pytest.fixture
def env(data_dir, upstream) -> Iterator[GatewayEnv]:
    with gateway_env(data_dir, upstream) as e:
        yield e


# --- egress guard: IPv6 transition addresses that reach public IPv4 hosts --------------------

TUNNEL_URLS = [
    # 6to4 (RFC 3056): 2002:AABB:CCDD::/48 is relayed over the public IPv4 internet to AA.BB.CC.DD.
    "http://[2002:808:808::1]:8080",  # -> 8.8.8.8
    "https://[2002:5db8:d822::1]",  # -> 93.184.216.34
    # Teredo (RFC 4380): 2001:0::/32 is relayed over UDP/IPv4. This is the RFC's own example address.
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]:8080",
]


@pytest.mark.parametrize("url", TUNNEL_URLS)
def test_egress_guard_refuses_6to4_and_teredo_literals(url: str) -> None:
    # ipaddress marks 2002::/16 and 2001::/23 is_private=True ("not globally reachable"
    # in the IANA registry), so address_problem() accepts them like RFC 1918 or ULA
    # space although allow_public_backends is false.
    with pytest.raises(backends.EgressDenied):
        backends.check_backend_url(url)


def test_egress_guard_refuses_a_name_that_resolves_to_a_6to4_address(monkeypatch) -> None:
    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        assert host == "gpu-box.internal", host
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2002:808:808::1", port, 0, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(backends.EgressDenied):
        backends.EgressGuard(False, ttl_s=0).check("http://gpu-box.internal:8080")


def test_console_admin_cannot_register_a_6to4_backend(conn, settings) -> None:
    # Console admins may not weaken egress settings (threat model TB5), yet this succeeds.
    with pytest.raises(backends.EgressDenied):
        backends.create_backend(conn, settings, name="tunnel", kind="openai", base_url=TUNNEL_URLS[0],
                                actor_type="admin", actor_id="alice")


# --- availability: a streamed request's audit write blocks the event loop ---------------------


def test_stream_audit_write_does_not_freeze_the_event_loop(data_dir, upstream) -> None:
    """_StreamRelay.close() calls _write_record synchronously on the event loop. While
    another connection holds the SQLite write lock (busy_timeout is 30 s), every other
    request on the server, even one that never touches the database, waits for it."""
    hold_s = 3.0
    with gateway_env(data_dir, upstream) as env, live_server(make_app(env.settings)) as base, \
            httpx.Client(trust_env=False, timeout=30) as client:
        # Warm-up: records last_used_at, so the streamed request needs no write before its audit event.
        assert client.post(base + "/v1/chat/completions", json=chat_body(MODEL),
                           headers=bearer(env.api_key)).status_code == 200
        holder = sqlite3.connect(str(env.settings.db_path), isolation_level=None, timeout=30,
                                 check_same_thread=False)
        holder.execute("BEGIN IMMEDIATE")  # a CLI write, a backup tool or an operator's sqlite3 session

        def unlock() -> None:
            holder.execute("ROLLBACK")
            holder.close()

        release = threading.Timer(hold_s, unlock)
        release.start()
        saw_done = threading.Event()
        failures: list[BaseException] = []

        def stream() -> None:
            try:
                with httpx.Client(trust_env=False, timeout=30) as c2, c2.stream(
                        "POST", base + "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                        headers=bearer(env.api_key)) as r:
                    for line in r.iter_lines():
                        if line == "data: [DONE]":
                            saw_done.set()
            except BaseException as exc:  # reported by the assertions below
                failures.append(exc)

        worker = threading.Thread(target=stream)
        worker.start()
        try:
            assert saw_done.wait(10), "the streamed completion did not arrive"
            time.sleep(0.3)  # the relay is now in close(), waiting for the lock
            started = time.monotonic()
            r = client.get(base + "/v1/no-such-endpoint")  # answered without any database access
            waited = time.monotonic() - started
        finally:
            release.join()
            worker.join(10)
        assert r.status_code == 404
        assert not failures, failures
        assert waited < 1.0, f"an unrelated request waited {waited:.2f}s behind another request's audit write"
        streamed = env.events()[-1]
        assert streamed["details"]["stream"] is True and streamed["outcome"] == "success"


# --- audit: verify_chain must report tampering, not crash on it -------------------------------


def _three_events(conn: sqlite3.Connection) -> None:
    for i in range(3):
        audit.append_event(conn, actor_type="app", actor_id="report-assistant", action="gateway.chat.completions",
                           resource=f"model:{MODEL}", outcome="success", details={"i": i, "model": MODEL})


@pytest.mark.parametrize("column, value", [
    ("details", '{"i":1,"model":NaN}'),  # json.loads accepts NaN, canonical_json refuses it: ValueError
    ("details", "[" * 100_000 + "]" * 100_000),  # RecursionError is not a ValueError
    ("ts", b"\x00\xff"),  # a BLOB in a TEXT column comes back as bytes: TypeError while hashing
    ("policy_version", b"\x01"),
])
def test_verify_chain_reports_a_tampered_row_instead_of_raising(conn, column: str, value: Any) -> None:
    # Today verify_chain raises, so `ferry doctor`, the evidence report, POST /api/audit/verify
    # and `ferry audit verify` all crash instead of naming the modified event (and the
    # failed verification is never itself audited).
    _three_events(conn)
    with write_tx(conn):
        conn.execute(f"UPDATE audit_events SET {column} = ? WHERE seq = 2", (value,))
    result = audit.verify_chain(conn)
    assert result["ok"] is False
    assert result["first_bad_seq"] == 2


def test_verify_chain_detects_details_rewritten_to_parse_to_the_same_value(conn) -> None:
    """The hash covers canonical_json(json.loads(details)), not the stored text, so any
    rewrite that parses to the same object verifies. A duplicate key lets the stored
    text carry arbitrary words: the console's audit search (q=) runs LIKE over the
    stored text and finds them in an event that verify_chain calls intact."""
    _three_events(conn)
    forged = '{"i":1,"model":"exfil-to-evil-host","model":"%s"}' % MODEL
    with write_tx(conn):
        conn.execute("UPDATE audit_events SET details = ? WHERE seq = 2", (forged,))
    assert audit.get_event(conn, 2)["details"] == {"i": 1, "model": MODEL}  # what the console shows
    assert [e["seq"] for e in audit.query_events(conn, q="exfil-to-evil-host")] == [2]  # what search finds
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 2


# --- streams: a chunk the relay cannot re-encode ------------------------------------------------


def test_stream_chunk_with_a_lone_surrogate_is_not_filed_as_a_client_disconnect(env: GatewayEnv) -> None:
    """The double JSON-encodes its pieces with ensure_ascii, so a lone surrogate arrives
    as the escape \\ud83d. _StreamRelay._line re-encodes with ensure_ascii=False and
    .encode('utf-8') raises UnicodeEncodeError, which no handler in events() catches:
    the stream is cut with no error event and close() records 'client_disconnected'."""
    env.upstream.completion_text = "split emoji \ud83d here"
    with env.client.stream("POST", "/v1/chat/completions", json=chat_body(MODEL, stream=True),
                           headers=bearer(env.api_key)) as r:
        assert r.status_code == 200
        lines = [line for line in r.iter_lines() if line]  # TestClient re-raises the server's exception here
    last = lines[-1]
    assert last == "data: [DONE]" or "error" in json.loads(last[len("data: "):])
    [event] = env.events()
    assert event["details"]["error_type"] != "client_disconnected"


# --- request validation: a body that decodes but cannot be forwarded ----------------------------


def test_lone_surrogate_in_a_request_is_not_an_internal_error(env: GatewayEnv) -> None:
    """json.loads accepts the escape \\ud800; _upstream_request then serializes with
    ensure_ascii=False and .encode('utf-8') raises. Any key holder gets a 500, an
    'internal_error' audit event and an error log line for an invalid request."""
    raw = ('{"model": "%s", "messages": [{"role": "user", "content": "hi \\ud800"}]}' % MODEL).encode()
    r = env.client.post("/v1/chat/completions", content=raw,
                        headers={**bearer(env.api_key), "Content-Type": "application/json"})
    assert r.status_code < 500, r.text
    [event] = env.events()
    assert event["details"]["error_type"] != "internal_error"


# --- concurrency: a request cancelled while it queues for the global slot ----------------------


def test_cancelled_acquire_gives_back_the_backend_slot() -> None:
    """ConcurrencyLimiter.acquire takes the backend slot, then waits for a global one. If
    that wait is cancelled (an ASGI server that cancels handlers on disconnect, a forced
    shutdown, any future request deadline), the backend slot is never released: with
    max_concurrency = 1 the backend answers 429 until the process restarts."""
    async def scenario() -> bool:
        limiter = ConcurrencyLimiter(global_limit=1, queue_timeout_s=5.0)
        busy = await limiter.acquire(99, 1)  # another backend holds the only global slot
        waiting = asyncio.create_task(limiter.acquire(7, 1))
        await asyncio.sleep(0.05)  # backend 7's slot is taken; the task now queues for the global slot
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        busy.release()
        limiter.queue_timeout_s = 0.2
        try:
            lease = await limiter.acquire(7, 1)
        except QueueTimeout:
            return False
        lease.release()
        return True

    assert asyncio.run(scenario()), "the cancelled request leaked backend 7's only slot"
