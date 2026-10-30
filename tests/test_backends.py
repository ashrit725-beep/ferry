"""Tests for ferry.backends: egress guard, token files, CRUD, health checks, provenance.

Health checks run against the TEST DOUBLE in tests/helpers_upstream.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from dataclasses import replace
from typing import Any, Iterator

import pytest

from ferry import audit, backends
from ferry.config import GatewaySettings
from ferry.db import write_tx
from ferry.errors import ConfigError, Conflict, NotFound, ValidationFailed
from ferry.gateway.state import build_state, close_state

from helpers_gateway import ACTOR, run_health, set_status, store_artifact, store_path, write_token
from helpers_upstream import FAKE_BUILD_INFO, FakeUpstream


@pytest.fixture
def upstream() -> Iterator[FakeUpstream]:
    with FakeUpstream() as up:
        yield up


def fake_dns(monkeypatch, mapping: dict[str, list[str]]) -> list[str]:
    """Answer getaddrinfo for the given names; returns the list of names looked up."""
    real = socket.getaddrinfo
    lookups: list[str] = []

    def fake(host, port, *args, **kwargs):
        lookups.append(host)
        if host in mapping:
            out = []
            for addr in mapping[host]:
                if ":" in addr:
                    out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (addr, port, 0, 0)))
                else:
                    out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port)))
            return out
        if str(host).endswith(".invalid"):
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided, or not known")
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return lookups


# --- egress guard ---------------------------------------------------------------


@pytest.mark.parametrize("url, normalized", [
    ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
    ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
    ("HTTP://LOCALHOST:8080", "http://localhost:8080"),
    ("http://[::1]:8080", "http://[::1]:8080"),
    ("https://10.1.2.3", "https://10.1.2.3"),
    ("http://172.16.5.4:11434", "http://172.16.5.4:11434"),
    ("http://192.168.0.10:8000", "http://192.168.0.10:8000"),
    ("http://[fd12:3456::1]:9000", "http://[fd12:3456::1]:9000"),
    ("http://[::ffff:10.0.0.7]:80", "http://[::ffff:10.0.0.7]:80"),
])
def test_loopback_and_private_backends_are_allowed(url: str, normalized: str) -> None:
    checked = backends.check_backend_url(url)
    assert checked.base_url == normalized
    assert checked.addresses


@pytest.mark.parametrize("url, problem", [
    ("http://8.8.8.8:80", "public address"),
    ("http://169.254.169.254", "metadata"),
    ("http://169.254.10.10", "link-local"),
    ("http://[fe80::1]:80", "link-local"),
    ("http://224.0.0.1", "multicast"),
    ("http://[ff02::1]:80", "multicast"),
    ("http://0.0.0.0:8080", "unspecified"),
    ("http://0.1.2.3:8080", "unspecified"),
    ("http://[::]:8080", "unspecified"),
    ("http://240.0.0.1", "reserved"),
    ("http://255.255.255.255", "reserved"),
    ("http://[::ffff:169.254.169.254]", "metadata"),
    ("http://[::ffff:8.8.8.8]", "public address"),
    ("http://100.64.0.1", "public address"),
    ("http://[fd00:ec2::254]", "metadata"),
    ("http://100.100.100.200", "metadata"),
    ("http://[2001:4860:4860::8888]", "public address"),
])
def test_dangerous_and_public_addresses_are_refused(url: str, problem: str) -> None:
    with pytest.raises(backends.EgressDenied, match=problem):
        backends.check_backend_url(url)


@pytest.mark.parametrize("url", ["http://169.254.169.254", "http://[fe80::1]", "http://224.0.0.1",
                                 "http://0.0.0.0", "http://240.0.0.1", "http://[fd00:ec2::254]"])
def test_allow_public_never_opens_link_local_metadata_or_special_ranges(url: str) -> None:
    with pytest.raises(backends.EgressDenied):
        backends.check_backend_url(url, allow_public=True)


def test_allow_public_permits_public_addresses(monkeypatch) -> None:
    fake_dns(monkeypatch, {"inference.example.com": ["93.184.216.34"]})
    assert backends.check_backend_url("https://8.8.8.8", allow_public=True).addresses == ("8.8.8.8",)
    assert backends.check_backend_url("https://inference.example.com", allow_public=True).host == "inference.example.com"


def test_names_are_resolved_and_every_address_must_pass(monkeypatch) -> None:
    fake_dns(monkeypatch, {
        "gpu-box.internal": ["10.0.0.5"],
        "public-name.example": ["93.184.216.34"],
        "split.example": ["10.0.0.5", "93.184.216.34"],
        "metadata.example": ["169.254.169.254"],
        "dual.internal": ["10.0.0.5", "fd00::5"],
    })
    assert backends.check_backend_url("http://gpu-box.internal:8080").addresses == ("10.0.0.5",)
    assert backends.check_backend_url("http://dual.internal:8080").addresses == ("10.0.0.5", "fd00::5")
    with pytest.raises(backends.EgressDenied, match="93.184.216.34"):
        backends.check_backend_url("http://public-name.example")
    with pytest.raises(backends.EgressDenied, match="93.184.216.34"):
        backends.check_backend_url("http://split.example")
    with pytest.raises(backends.EgressDenied, match="metadata"):
        backends.check_backend_url("http://metadata.example", allow_public=True)
    with pytest.raises(backends.EgressDenied, match="cannot resolve"):
        backends.check_backend_url("http://nowhere.invalid")


@pytest.mark.parametrize("url", [
    "http://user:pass@127.0.0.1:8080",
    "http://token@127.0.0.1:8080",
    "http://127.0.0.1:8080/?model=x",
    "http://127.0.0.1:8080?",
    "http://127.0.0.1:8080/#frag",
    "http://127.0.0.1:8080/v1",
    "http://127.0.0.1:8080//",
    "ftp://127.0.0.1",
    "file:///etc/passwd",
    "127.0.0.1:8080",
    "http://",
    "http://:8080",
    "http://127.0.0.1:99999",
    "http://127.0.0.1:0",
    "http://127.0.0.1:port",
    "http://127.0.0.1 :8080",
    "http://127.0.0.1:8080\n",
    "http:\\\\127.0.0.1",
    "http://[fe80::1%25en0]:8080",
    "http://exa mple.com",
    "http://" + "a" * 2050,
    "",
    None,
    42,
])
def test_malformed_backend_urls_are_rejected(url: Any) -> None:
    with pytest.raises(ValidationFailed):
        backends.check_backend_url(url)


def test_egress_guard_caches_resolutions_but_reapplies_rules(monkeypatch) -> None:
    lookups = fake_dns(monkeypatch, {"model-host.internal": ["10.0.0.8"]})
    now = [100.0]
    guard = backends.EgressGuard(False, ttl_s=30, clock=lambda: now[0])
    guard.check("http://model-host.internal:8080")
    guard.check("http://model-host.internal:8080")
    assert lookups.count("model-host.internal") == 1
    now[0] += 31
    guard.check("http://model-host.internal:8080")
    assert lookups.count("model-host.internal") == 2
    assert asyncio.run(guard.acheck("http://model-host.internal:8080")).addresses == ("10.0.0.8",)
    assert lookups.count("model-host.internal") == 2

    fake_dns(monkeypatch, {"model-host.internal": ["93.184.216.34"]})
    now[0] += 31  # DNS now points outside: the next check after the TTL refuses it
    with pytest.raises(backends.EgressDenied):
        guard.check("http://model-host.internal:8080")
    strict = backends.EgressGuard(False)
    with pytest.raises(backends.EgressDenied):
        asyncio.run(strict.acheck("http://model-host.internal:8080"))


# --- token files ------------------------------------------------------------------


def _token_file(tmp_path, content: bytes, mode: int = 0o600):
    path = tmp_path / "backend.token"
    path.write_bytes(content)
    os.chmod(path, mode)
    return path


def test_token_file_first_line_is_the_token(tmp_path) -> None:
    path = _token_file(tmp_path, b"  s3cr3t-token_value.123  \nsecond line ignored\n")
    assert backends.read_token_file(path) == "s3cr3t-token_value.123"
    assert backends.read_token_file(str(path)) == "s3cr3t-token_value.123"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602, 0o660, 0o666])
def test_token_files_accessible_to_others_are_refused(tmp_path, mode: int) -> None:
    path = _token_file(tmp_path, b"supersecret\n", mode)
    with pytest.raises(ConfigError) as excinfo:
        backends.read_token_file(path)
    assert "chmod 600" in excinfo.value.message
    assert "supersecret" not in excinfo.value.message


@pytest.mark.parametrize("content", [b"", b"\n", b"   \nsecond", b"two words\n", b"t\x00k", "tökén".encode(),
                                     b"x" * 9000, b"\xff\xfe"])
def test_bad_token_content_is_refused_without_echoing_it(tmp_path, content: bytes) -> None:
    path = _token_file(tmp_path, content)
    with pytest.raises(ConfigError) as excinfo:
        backends.read_token_file(path)
    if len(content) > 2:
        assert content.decode("latin-1") not in excinfo.value.message


def test_symlinks_directories_missing_and_relative_paths_are_refused(tmp_path) -> None:
    target = _token_file(tmp_path, b"supersecret\n")
    link = tmp_path / "link.token"
    link.symlink_to(target)
    for bad in (link, tmp_path, tmp_path / "missing.token", "relative/backend.token"):
        with pytest.raises(ConfigError):
            backends.read_token_file(bad)


# --- backend CRUD -------------------------------------------------------------------


def test_create_backend_audits_and_hides_the_token(conn, settings, upstream) -> None:
    token_file = write_token(settings, "llama", "hidden-token-value")
    created = backends.create_backend(conn, settings, name="llama", kind="llamacpp", base_url=upstream.base_url + "/",
                                      auth_token_file=str(token_file), timeout_s=30, max_concurrency=2, **ACTOR)
    assert created["base_url"] == upstream.base_url and created["has_token"] is True
    assert created["timeout_s"] == 30.0 and created["max_concurrency"] == 2 and created["enabled"] is True
    assert "auth_token_file" not in created and created["last_status"] is None
    [event] = audit.query_events(conn, action="backend.create")
    assert event["resource"] == "backend:llama" and event["details"]["token_configured"] is True
    assert "hidden-token-value" not in json.dumps(event) and str(token_file) not in json.dumps(event)
    assert backends.list_backends(conn) == [created]
    assert backends.get_backend_by_name(conn, "llama")["id"] == created["id"]
    with pytest.raises(Conflict):
        backends.create_backend(conn, settings, name="llama", kind="openai", base_url=upstream.base_url, **ACTOR)


@pytest.mark.parametrize("kwargs", [
    {"name": "bad name"}, {"name": ""}, {"kind": "vllm"}, {"timeout_s": 0}, {"timeout_s": 3601}, {"timeout_s": "5"},
    {"max_concurrency": 0}, {"max_concurrency": 2000}, {"max_concurrency": 1.5}, {"enabled": "yes"},
    {"base_url": "http://8.8.8.8"}, {"base_url": "http://127.0.0.1:8080/v1"},
    {"auth_token_file": "relative.token"},
])
def test_create_backend_validation(conn, settings, kwargs) -> None:
    base = {"name": "b", "kind": "openai", "base_url": "http://127.0.0.1:8080"}
    with pytest.raises(ValidationFailed):
        backends.create_backend(conn, settings, **{**base, **kwargs}, **ACTOR)
    assert backends.list_backends(conn) == []


def test_public_backends_need_the_host_setting(conn, settings) -> None:
    with pytest.raises(backends.EgressDenied, match="allow_public_backends"):
        backends.create_backend(conn, settings, name="b", kind="openai", base_url="http://8.8.8.8", **ACTOR)
    open_settings = replace(settings, gateway=GatewaySettings(allow_public_backends=True))
    assert backends.create_backend(conn, open_settings, name="b", kind="openai", base_url="http://8.8.8.8",
                                   **ACTOR)["base_url"] == "http://8.8.8.8"


def test_console_admins_may_only_use_token_files_in_the_secrets_dir(conn, settings, tmp_path) -> None:
    outside = _token_file(tmp_path, b"elsewhere\n")
    with pytest.raises(ValidationFailed, match="inside"):
        backends.create_backend(conn, settings, name="b", kind="openai", base_url="http://127.0.0.1:1",
                                auth_token_file=str(outside), actor_type="admin", actor_id="alice")
    inside = write_token(settings, "b", "inside")
    assert backends.create_backend(conn, settings, name="b", kind="openai", base_url="http://127.0.0.1:1",
                                   auth_token_file=str(inside), actor_type="admin", actor_id="alice")["has_token"]
    # The host CLI may point anywhere it can read.
    assert backends.create_backend(conn, settings, name="c", kind="openai", base_url="http://127.0.0.1:1",
                                   auth_token_file=str(outside), **ACTOR)["has_token"]
    insecure = write_token(settings, "d", "readable", mode=0o644)
    with pytest.raises(ValidationFailed, match="chmod 600"):
        backends.create_backend(conn, settings, name="d", kind="openai", base_url="http://127.0.0.1:1",
                                auth_token_file=str(insecure), actor_type="admin", actor_id="alice")


def test_update_backend(conn, settings, upstream) -> None:
    created = backends.create_backend(conn, settings, name="b", kind="llamacpp", base_url=upstream.base_url, **ACTOR)
    set_status(conn, created["id"], "up")
    same = backends.update_backend(conn, settings, created["id"], {"timeout_s": 120.0}, **ACTOR)
    assert same["last_status"]["state"] == "up"
    updated = backends.update_backend(conn, settings, created["id"], {"max_concurrency": 9, "enabled": False}, **ACTOR)
    assert updated["max_concurrency"] == 9 and updated["enabled"] is False
    assert updated["last_status"]["state"] == "up"  # these do not change which server it is
    moved = backends.update_backend(conn, settings, created["id"], {"base_url": "http://127.0.0.1:9"}, **ACTOR)
    assert moved["last_status"] is None and moved["last_checked_at"] is None
    events = list(reversed(audit.query_events(conn, action="backend.update")))
    assert [e["details"]["changed"] for e in events] == [["enabled", "max_concurrency"], ["base_url"]]
    assert [e["details"]["status_reset"] for e in events] == [False, True]
    with pytest.raises(ValidationFailed):
        backends.update_backend(conn, settings, created["id"], {"auth_token": "x"}, **ACTOR)
    with pytest.raises(ValidationFailed):
        backends.update_backend(conn, settings, created["id"], {}, **ACTOR)
    with pytest.raises(backends.EgressDenied):
        backends.update_backend(conn, settings, created["id"], {"base_url": "http://169.254.169.254"}, **ACTOR)
    with pytest.raises(NotFound):
        backends.update_backend(conn, settings, 999, {"enabled": True}, **ACTOR)
    backends.create_backend(conn, settings, name="other", kind="openai", base_url="http://127.0.0.1:2", **ACTOR)
    with pytest.raises(Conflict):
        backends.update_backend(conn, settings, created["id"], {"name": "other"}, **ACTOR)
    token = write_token(settings, "b", "t0k3n")
    assert backends.update_backend(conn, settings, created["id"], {"auth_token_file": str(token)}, **ACTOR)["has_token"]
    assert not backends.update_backend(conn, settings, created["id"], {"auth_token_file": None}, **ACTOR)["has_token"]


def test_delete_backend_refuses_while_routes_use_it(conn, settings) -> None:
    b = backends.create_backend(conn, settings, name="b", kind="openai", base_url="http://127.0.0.1:1", **ACTOR)
    route = backends.create_route(conn, model="m", backend_id=b["id"], require_verified=False, **ACTOR)
    with pytest.raises(Conflict, match="m") as excinfo:
        backends.delete_backend(conn, b["id"], **ACTOR)
    assert excinfo.value.details == {"routes": ["m"]}
    backends.delete_route(conn, route["id"], **ACTOR)
    backends.delete_backend(conn, b["id"], **ACTOR)
    assert backends.list_backends(conn) == []
    with pytest.raises(NotFound):
        backends.delete_backend(conn, b["id"], **ACTOR)
    assert [e["action"] for e in reversed(audit.query_events(conn, action="route."))] == ["route.create",
                                                                                        "route.delete"]
    assert len(audit.query_events(conn, action="backend.delete")) == 1


# --- route CRUD -----------------------------------------------------------------------


@pytest.fixture
def backend_id(conn, settings) -> int:
    return int(backends.create_backend(conn, settings, name="b", kind="llamacpp", base_url="http://127.0.0.1:1",
                                       **ACTOR)["id"])


def test_create_route_and_pin(conn, settings, backend_id) -> None:
    digest = store_artifact(settings, conn, b"model bytes")
    route = backends.create_route(conn, model="qwen", backend_id=backend_id, artifact_digest=f"sha256:{digest.upper()}",
                                  **ACTOR)
    assert route["artifact_digest"] == digest and route["upstream_model"] == "qwen"
    assert route["require_verified"] is True and route["enabled"] is True
    assert route["backend_name"] == "b"
    assert route["provenance"]["state"] == "unknown" and route["available"] is False
    [event] = audit.query_events(conn, action="route.create")
    assert event["resource"] == "model:qwen" and event["details"]["artifact_digest"] == digest
    with pytest.raises(Conflict):
        backends.create_route(conn, model="qwen", backend_id=backend_id, require_verified=False, **ACTOR)


def test_create_route_validation(conn, settings, backend_id) -> None:
    license_digest = store_artifact(settings, conn, b"Apache License", kind="document")
    cases = [
        ({"model": "bad model"}, ValidationFailed),
        ({"model": "qwen-*"}, ValidationFailed),
        ({"backend_id": 999}, NotFound),
        ({"backend_id": "1"}, ValidationFailed),
        ({}, ValidationFailed),  # require_verified (the default) without a pin
        ({"artifact_digest": "f" * 64}, ValidationFailed),  # not imported
        ({"artifact_digest": "xyz"}, ValidationFailed),
        ({"artifact_digest": license_digest}, ValidationFailed),  # not a model
        ({"upstream_model": "has space", "require_verified": False}, ValidationFailed),
        ({"require_verified": "no"}, ValidationFailed),
    ]
    for overrides, error in cases:
        kw = {"model": "qwen", "backend_id": backend_id, **overrides}
        with pytest.raises(error):
            backends.create_route(conn, **kw, **ACTOR)
    assert backends.list_routes(conn) == []
    ok = backends.create_route(conn, model="Qwen2.5:0.5b", backend_id=backend_id, upstream_model="Qwen/Qwen2.5-0.5B",
                               require_verified=False, **ACTOR)
    assert ok["provenance"]["state"] == "not_pinned"


def test_update_route(conn, settings, backend_id) -> None:
    digest = store_artifact(settings, conn, b"model bytes")
    route = backends.create_route(conn, model="qwen", backend_id=backend_id, artifact_digest=digest, **ACTOR)
    with pytest.raises(ValidationFailed, match="require_verified"):
        backends.update_route(conn, route["id"], {"artifact_digest": None}, **ACTOR)
    updated = backends.update_route(conn, route["id"], {"require_verified": False, "artifact_digest": None}, **ACTOR)
    assert updated["artifact_digest"] is None and updated["require_verified"] is False
    assert backends.update_route(conn, route["id"], {"enabled": False}, **ACTOR)["enabled"] is False
    with pytest.raises(ValidationFailed):
        backends.update_route(conn, route["id"], {"colour": "red"}, **ACTOR)
    with pytest.raises(NotFound):
        backends.update_route(conn, 999, {"enabled": True}, **ACTOR)
    with pytest.raises(NotFound):
        backends.update_route(conn, route["id"], {"backend_id": 999}, **ACTOR)
    backends.create_route(conn, model="other", backend_id=backend_id, require_verified=False, **ACTOR)
    with pytest.raises(Conflict):
        backends.update_route(conn, route["id"], {"model": "other"}, **ACTOR)
    changed = [e["details"]["changed"] for e in reversed(audit.query_events(conn, action="route.update"))]
    assert changed == [["artifact_digest", "require_verified"], ["enabled"]]


# --- health checks against the test double -------------------------------------------------


def _backend(conn, settings, upstream, *, kind: str = "llamacpp", token: str | None = "upstream-test-token",
             name: str = "llama") -> int:
    token_file = str(write_token(settings, name, token)) if token else None
    return int(backends.create_backend(conn, settings, name=name, kind=kind, base_url=upstream.base_url,
                                       auth_token_file=token_file, **ACTOR)["id"])


def test_llamacpp_health_reports_build_models_and_served_file(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    status = run_health(settings, bid)
    assert status["state"] == "up" and status["http_status"] == 200 and status["error"] is None
    assert status["version"] == FAKE_BUILD_INFO
    assert status["models"] == ["fake-alias"]
    assert status["served"] == [{"model_id": "fake-alias", "path": upstream.model_path, "digest": None}]
    assert isinstance(status["latency_ms"], int)
    assert [r.path for r in upstream.requests] == ["/health", "/v1/models", "/props"]
    assert all(r.headers.get("authorization") == "Bearer upstream-test-token" for r in upstream.requests)
    stored = backends.get_backend(conn, bid)
    assert stored["last_status"] == status and stored["last_checked_at"] == status["checked_at"]


def test_health_state_changes_are_audited_once(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    run_health(settings, bid)
    run_health(settings, bid)
    upstream.health_status = 503
    assert run_health(settings, bid)["state"] == "loading"
    run_health(settings, bid)
    upstream.health_status = 200
    run_health(settings, bid)
    upstream.stop()
    down = run_health(settings, bid)
    assert down["state"] == "down" and "connection failed" in down["error"]
    events = list(reversed(audit.query_events(conn, action="backend.health")))
    assert [(e["details"]["previous_state"], e["details"]["state"]) for e in events] == [
        (None, "up"), ("up", "loading"), ("loading", "up"), ("up", "down")]
    assert [e["outcome"] for e in events] == ["success", "unavailable", "success", "failure"]
    assert all(e["actor_type"] == "system" and e["resource"] == "backend:llama" for e in events)


def test_wrong_backend_token_is_down_and_never_leaks(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream, token="not-the-right-token")
    status = run_health(settings, bid)
    assert status["state"] == "down" and status["http_status"] == 401
    assert "credentials" in status["error"]
    assert "not-the-right-token" not in json.dumps(status)
    assert "not-the-right-token" not in json.dumps(audit.query_events(conn, action="backend."))


def test_props_failure_leaves_backend_up_but_unproven(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    upstream.props_status = 500
    status = run_health(settings, bid)
    assert status["state"] == "up" and status["served"] == [] and "/props" in status["error"]
    assert backends.evaluate_provenance("a" * 64, status)["state"] == "unverified"


def test_openai_and_ollama_kinds(conn, settings, upstream) -> None:
    openai_id = _backend(conn, settings, upstream, kind="openai", name="vllm")
    status = run_health(settings, openai_id)
    assert status["state"] == "up" and status["models"] == ["fake-alias"] and status["served"] == []
    assert [r.path for r in upstream.requests] == ["/v1/models"]
    ollama_id = _backend(conn, settings, upstream, kind="ollama", name="ollama", token=None)
    status = run_health(settings, ollama_id)
    assert status["state"] == "up" and status["version"] == upstream.ollama_version
    assert status["models"] == ["fake-alias"]


def test_unreadable_token_or_refused_address_marks_backend_down(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    with write_tx(conn):
        path = conn.execute("SELECT auth_token_file FROM backends WHERE id = ?", (bid,)).fetchone()[0]
    os.chmod(path, 0o644)
    status = run_health(settings, bid)
    assert status["state"] == "down" and "chmod 600" in status["error"]
    os.chmod(path, 0o600)
    with write_tx(conn):
        conn.execute("UPDATE backends SET base_url = 'http://169.254.169.254' WHERE id = ?", (bid,))
    upstream.clear()
    status = run_health(settings, bid)
    assert status["state"] == "down" and "metadata" in status["error"]
    assert upstream.requests == []


def test_stale_health_results_are_dropped(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    row = backends.backend_for_check(conn, bid)
    status = {"state": "up", "checked_at": "2026-10-28T00:00:00.000Z", "latency_ms": 1, "http_status": 200,
              "version": None, "models": [], "served": [], "error": None}
    backends.update_backend(conn, settings, bid, {"max_concurrency": 3}, **ACTOR)
    assert backends.record_health(conn, bid, status, checked=row) is True  # same server, still valid
    backends.update_backend(conn, settings, bid, {"base_url": "http://127.0.0.1:2"}, **ACTOR)
    assert backends.record_health(conn, bid, {**status, "state": "down"}, checked=row) is False
    assert backends.get_backend(conn, bid)["last_status"] is None
    with pytest.raises(ValueError):
        backends.record_health(conn, bid, {**status, "state": "great"})


def test_health_loop_checks_enabled_backends_and_stops_on_cancel(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    disabled = _backend(conn, settings, upstream, name="spare")
    backends.update_backend(conn, settings, disabled, {"enabled": False}, **ACTOR)
    fast = replace(settings, gateway=GatewaySettings(health_interval_s=0.05))

    async def run() -> None:
        state = build_state(fast)
        try:
            task = asyncio.create_task(backends.health_loop(state))
            for _ in range(100):
                await asyncio.sleep(0.02)
                if backends.get_backend(conn, bid)["last_status"]:
                    break
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            await close_state(state)

    asyncio.run(run())
    assert backends.get_backend(conn, bid)["last_status"]["state"] == "up"
    assert backends.get_backend(conn, disabled)["last_status"] is None

    async def disabled_loop() -> None:
        state = build_state(replace(settings, gateway=GatewaySettings(health_interval_s=0)))
        try:
            await asyncio.wait_for(backends.health_loop(state), 1)  # returns at once when disabled
        finally:
            await close_state(state)

    asyncio.run(disabled_loop())


# --- provenance ---------------------------------------------------------------------


def _pinned_route(conn, settings, upstream, content: bytes = b"GGUF pinned") -> tuple[int, int, str]:
    digest = store_artifact(settings, conn, content)
    bid = _backend(conn, settings, upstream)
    route = backends.create_route(conn, model="qwen", backend_id=bid, artifact_digest=digest, **ACTOR)
    return bid, int(route["id"]), digest


def test_provenance_verified_when_backend_serves_the_pinned_store_file(conn, settings, upstream) -> None:
    bid, route_id, digest = _pinned_route(conn, settings, upstream)
    upstream.model_path = store_path(settings, digest)
    assert run_health(settings, bid)["served"][0]["digest"] == digest
    route = backends.get_route(conn, route_id)
    assert route["provenance"] == {"state": "verified", "detail": "backend serves the pinned file from the store",
                                   "served_digest": digest}
    assert route["available"] is True and route["reason"] == ""


def test_provenance_mismatch_for_another_store_file(conn, settings, upstream) -> None:
    bid, route_id, digest = _pinned_route(conn, settings, upstream)
    other = store_artifact(settings, conn, b"GGUF other model")
    upstream.model_path = store_path(settings, other)
    run_health(settings, bid)
    route = backends.get_route(conn, route_id)
    assert route["provenance"]["state"] == "mismatch" and route["provenance"]["served_digest"] == other
    assert route["available"] is False and "mismatch" in route["reason"]


def test_provenance_unverified_outside_the_store(conn, settings, upstream, tmp_path) -> None:
    bid, route_id, digest = _pinned_route(conn, settings, upstream)
    copy = tmp_path / digest  # same name and bytes, but not in the store
    copy.write_bytes(b"GGUF pinned")
    sneaky = settings.store_dir / "sha256" / ("0" * 64)
    sneaky.symlink_to(copy)  # a store-looking name that resolves outside the store
    for path in (str(copy), str(sneaky), digest, f"sha256/{digest}", str(settings.store_dir / "sha256" / ("e" * 64))):
        upstream.model_path = path
        run_health(settings, bid)
        route = backends.get_route(conn, route_id)
        assert route["provenance"]["state"] == "unverified", path
        assert route["available"] is False


def test_provenance_follows_a_symlink_into_the_store(conn, settings, upstream, tmp_path) -> None:
    bid, route_id, digest = _pinned_route(conn, settings, upstream)
    link = tmp_path / "model.gguf"
    link.symlink_to(store_path(settings, digest))
    upstream.model_path = str(link)
    run_health(settings, bid)
    assert backends.get_route(conn, route_id)["provenance"]["state"] == "verified"


def test_provenance_not_pinned_and_unknown(conn, settings, upstream) -> None:
    bid = _backend(conn, settings, upstream)
    route = backends.create_route(conn, model="loose", backend_id=bid, require_verified=False, **ACTOR)
    assert route["provenance"]["state"] == "not_pinned"
    run_health(settings, bid)
    route = backends.get_route(conn, int(route["id"]))
    assert route["provenance"]["state"] == "not_pinned" and route["available"] is True
    digest = store_artifact(settings, conn, b"GGUF pinned")
    pinned = backends.create_route(conn, model="pinned", backend_id=bid, artifact_digest=digest, **ACTOR)
    upstream.stop()
    run_health(settings, bid)
    pinned = backends.get_route(conn, int(pinned["id"]))
    assert pinned["provenance"]["state"] == "unknown" and pinned["provenance"]["detail"] == "backend is down"


def test_evaluate_provenance_unit_cases() -> None:
    pin = "a" * 64
    up = {"state": "up", "served": [{"model_id": "m", "path": "/x", "digest": pin}]}
    assert backends.evaluate_provenance(pin, up)["state"] == "verified"
    assert backends.evaluate_provenance("b" * 64, up)["state"] == "mismatch"
    assert backends.evaluate_provenance(pin, {"state": "up", "served": [{"path": "/x", "digest": None}]})["state"] == "unverified"
    assert backends.evaluate_provenance(pin, {"state": "up", "served": []})["state"] == "unverified"
    assert backends.evaluate_provenance(pin, {"state": "up", "served": "garbage"})["state"] == "unverified"
    assert backends.evaluate_provenance(pin, {"state": "loading"})["state"] == "unknown"
    assert backends.evaluate_provenance(pin, None)["state"] == "unknown"
    assert backends.evaluate_provenance(None, up)["state"] == "not_pinned"


@pytest.mark.parametrize("route, backend, code", [
    ({"enabled": 0, "require_verified": 0}, {"enabled": 1, "last_status": {"state": "up"}}, "route_disabled"),
    ({"enabled": 1, "require_verified": 0}, {"enabled": 0, "last_status": {"state": "up"}}, "backend_disabled"),
    ({"enabled": 1, "require_verified": 0}, {"enabled": 1, "last_status": None}, "backend_unchecked"),
    ({"enabled": 1, "require_verified": 0}, {"enabled": 1, "last_status": '{"state": "down"}'}, "backend_down"),
    ({"enabled": 1, "require_verified": 0}, {"enabled": 1, "last_status": {"state": "loading"}}, "backend_loading"),
    ({"enabled": 1, "require_verified": 1, "artifact_digest": "a" * 64},
     {"enabled": 1, "last_status": {"state": "up", "served": []}}, "provenance"),
    ({"enabled": 1, "require_verified": 0, "artifact_digest": "a" * 64},
     {"enabled": 1, "last_status": {"state": "up", "served": []}}, "ok"),
    ({"enabled": 1, "require_verified": 1, "artifact_digest": "a" * 64},
     {"enabled": 1, "last_status": {"state": "up", "served": [{"digest": "a" * 64}]}}, "ok"),
])
def test_route_availability(route, backend, code: str) -> None:
    result = backends.route_availability(route, backend)
    assert result.code == code and result.available is (code == "ok")


def test_store_digest_for_path(settings, conn, tmp_path) -> None:
    assert backends.store_digest_for_path(settings, "/nonexistent") is None
    digest = store_artifact(settings, conn, b"bytes")
    assert backends.store_digest_for_path(settings, store_path(settings, digest)) == digest
    for bad in (None, "", 5, "relative/path", "/x\x00y", str(settings.store_dir), str(tmp_path)):
        assert backends.store_digest_for_path(settings, bad) is None
