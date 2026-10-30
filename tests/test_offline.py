"""Offline guarantees (spec section 2: no network access except the inbound
listener and admin-configured backends).

1. During app startup and a full request flow (console API, backend health
   check, chat completions through the TestClient and through a real uvicorn
   server), socket connects, UDP sends and name lookups to anything but
   loopback raise, and the test asserts that nothing even tried.
2. The console build references nothing a browser would fetch from another
   origin.
3. No module in ferry/ hard-codes a public URL or public IP address, except
   documentation strings and an explicit allowlist with reasons.
"""

from __future__ import annotations

import ast
import errno
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest

import ferry
from ferry import backends, doctor
from ferry.evidence import build_evidence
from ferry.gateway.app import STATIC_DIR, create_app

from helpers_app import CSRF, app_env, app_settings
from helpers_gateway import bearer, chat_body, live_server, store_artifact, store_path, write_token
from helpers_upstream import FakeUpstream

FERRY_DIR = Path(ferry.__file__).resolve().parent


# --- 1. nothing connects out -------------------------------------------------------------------


@dataclass
class NetworkLog:
    connects: list[tuple[str, int]] = field(default_factory=list)
    lookups: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


def _is_loopback(host: str) -> bool:
    name = host.split("%", 1)[0].strip("[]").lower()
    if name in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


@pytest.fixture
def egress_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[NetworkLog]:
    """Every outbound socket operation goes through here; non-loopback ones fail."""
    log = NetworkLog()
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex
    real_sendto, real_getaddrinfo = socket.socket.sendto, socket.getaddrinfo

    def check(sock: socket.socket, address: Any, what: str) -> None:
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(address, tuple):
            return
        host, port = str(address[0]), int(address[1])
        log.connects.append((host, port))
        if not _is_loopback(host):
            log.blocked.append(f"{what} {host}:{port}")
            raise OSError(errno.ENETUNREACH, f"outbound {what} to {host}:{port} blocked by the offline test")

    def connect(self: socket.socket, address: Any) -> Any:
        check(self, address, "connect")
        return real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        check(self, address, "connect")
        return real_connect_ex(self, address)

    def sendto(self: socket.socket, data: bytes, *args: Any) -> Any:
        check(self, args[-1], "sendto")
        return real_sendto(self, data, *args)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None:
            name = host.decode("idna") if isinstance(host, bytes) else str(host)
            try:
                ipaddress.ip_address(name.split("%", 1)[0].strip("[]"))
                literal = True  # numeric: no DNS query; a connect to it is checked above
            except ValueError:
                literal = False
            if not literal:
                log.lookups.append(name)
                if not _is_loopback(name):
                    log.blocked.append(f"lookup {name}")
                    raise socket.gaierror(socket.EAI_NONAME, f"name lookup of {name} blocked by the offline test")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    yield log


def test_the_guard_really_blocks(egress_guard: NetworkLog) -> None:
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(httpx.ConnectError):
        httpx.get("http://192.0.2.1:9/", timeout=1, trust_env=False)
    assert egress_guard.blocked[:2] == ["connect 192.0.2.1:443", "lookup example.com"]


def test_startup_and_a_full_request_flow_make_no_outbound_connections(egress_guard: NetworkLog,
                                                                      tmp_path: Path) -> None:
    with FakeUpstream() as upstream:
        with app_env(tmp_path / "data") as env:
            app_id = env.post("/api/apps", {"name": "offline-app", "environment": "test"}).json()["id"]
            key = env.post(f"/api/apps/{app_id}/keys", {}).json()["api_key"]
            with env.conn() as conn:
                digest = store_artifact(env.settings, conn, b"GGUF bytes for the offline test")
            upstream.model_path = store_path(env.settings, digest)
            token = write_token(env.settings, "llama", upstream.token)
            backend = env.post("/api/backends", {"name": "llama", "kind": "llamacpp", "base_url": upstream.base_url,
                                                 "auth_token_file": str(token)}).json()
            assert env.post(f"/api/backends/{backend['id']}/check").json()["status"]["state"] == "up"
            assert env.post("/api/routes", {"model": "m1", "backend_id": backend["id"],
                                            "artifact_digest": digest}).status_code == 201
            doc = {"schema": "ferry.dev/access-policy/v1", "rules": [
                {"id": "allow-m1", "effect": "allow", "principals": ["app:offline-app"],
                 "actions": ["chat.completions"], "models": ["m1"]}]}
            assert env.post("/api/policy/activate", {"document": doc}).status_code == 201
            assert env.client.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key)).status_code == 200
            stream = env.client.post("/v1/chat/completions", json=chat_body("m1", stream=True), headers=bearer(key))
            assert stream.status_code == 200 and "[DONE]" in stream.text
            for path in ("/", "/api/overview", "/api/evidence", "/api/evidence.md", "/api/system", "/api/models",
                         "/api/audit/export"):
                assert env.get(path).status_code == 200, path
            assert env.post("/api/audit/verify").json()["ok"] is True
            with env.conn() as conn:
                checks = doctor.run_checks(env.settings, conn)
                build_evidence(env.settings, conn)
            assert "network.isolation" not in {c["id"] for c in checks}

            # The same installation behind a real uvicorn listener on 127.0.0.1.
            with live_server(create_app(env.settings)) as base, httpx.Client(base_url=base, trust_env=False) as http:
                assert http.get("/healthz").json() == {"status": "ok"}
                answer = http.post("/v1/chat/completions", json=chat_body("m1"), headers=bearer(key))
                assert answer.status_code == 200
                login = http.post("/api/auth/login", json={"username": "alice", "password": "alice-password-1234"},
                                  headers=CSRF)
                assert login.status_code == 200
    assert egress_guard.blocked == [], egress_guard.blocked
    assert egress_guard.connects, "the flow must have opened loopback connections, or the guard was not active"
    assert all(_is_loopback(host) for host, _ in egress_guard.connects)
    assert all(_is_loopback(name) for name in egress_guard.lookups)
    assert len(upstream.chat_requests()) == 3


def test_backend_registration_refuses_names_it_cannot_resolve_locally(egress_guard: NetworkLog, tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    with app_env(tmp_path / "data", settings=settings) as env:
        response = env.post("/api/backends", {"name": "remote", "kind": "openai", "base_url": "http://api.example.com"})
        assert response.status_code == 422 and response.json()["error"]["code"] == "egress_denied"
    assert egress_guard.blocked == ["lookup api.example.com"], "the only attempt is the egress check's own lookup"


def test_the_app_ships_no_docs_routes_and_no_telemetry(tmp_path: Path) -> None:
    app = create_app(app_settings(tmp_path / "data"))
    paths = {getattr(route, "path", "") for route in app.routes}
    assert not paths & {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}
    telemetry = getattr(app, "_telemetry", None)
    if telemetry is not None:  # FastAPI >= 0.160 has built-in OpenTelemetry
        assert telemetry["tracing"] is False and telemetry["metrics"] is False and telemetry["logs"] is False
        assert telemetry["auto_configure"] is False


def test_http_clients_ignore_proxies_and_redirects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    from ferry.gateway.state import build_state

    state = build_state(app_settings(tmp_path / "data"))
    assert state.http.trust_env is False and state.http.follow_redirects is False
    assert isinstance(state.egress, backends.EgressGuard) and state.egress.allow_public is False


# --- 2. the console references nothing off-origin ------------------------------------------------------------

TEXT_SUFFIXES = {".html", ".js", ".mjs", ".css", ".json", ".svg", ".txt", ".map", ".webmanifest", ".xml"}
SCHEME = re.compile(rb"(?i)\b(?:https?|wss?|ftp)://")


def _static_files() -> list[Path]:
    return sorted(p for p in STATIC_DIR.rglob("*") if p.is_file())


def test_console_build_has_no_external_urls() -> None:
    files = _static_files()
    assert STATIC_DIR / "index.html" in files, "the console build is missing"
    offenders = [p.relative_to(STATIC_DIR).as_posix() for p in files
                 if p.suffix in TEXT_SUFFIXES and SCHEME.search(p.read_bytes())]
    assert offenders == []


def test_console_html_and_css_reference_only_bundled_files() -> None:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r"""\b(?:src|href)\s*=\s*["']([^"']*)["']""", html)
    assert refs, "expected script and stylesheet references"
    for ref in refs:
        if ref == "data:,":
            continue  # the empty favicon, allowed by img-src data:
        assert ref.startswith("/assets/") and not ref.startswith("//"), ref
        assert (STATIC_DIR / ref.lstrip("/")).is_file(), ref
    for css in STATIC_DIR.rglob("*.css"):
        text = css.read_text(encoding="utf-8")
        assert "@import" not in text
        for ref in re.findall(r"""url\(\s*["']?([^"')\s]+)""", text):
            if ref.startswith("data:image/"):
                continue
            assert not re.match(r"^[a-z][a-z0-9+.-]*:|^//", ref, re.IGNORECASE), f"{css.name}: {ref}"
            assert (css.parent / ref).resolve().is_file() or (STATIC_DIR / ref.lstrip("/")).is_file(), ref


# --- 3. no hard-coded public URLs or addresses in ferry/ ----------------------------------------------------------

# A scheme followed by a host; "starts with http:// or https://" in a message is not a URL.
URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[A-Za-z0-9\[][^\s'\"<>)`]*")
LOOPBACK_URL = re.compile(r"(?i)^(?:https?|wss?)://(?:127\.0\.0\.1|localhost|\[::1\])(?:[:/]|$)")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
ALLOWED_URLS = {
    ("offline_rules.py", "https://huggingface"):
        "offline rule base: a regular expression matching the error text huggingface_hub prints when it cannot "
        "reach the Hub; Ferry never connects to it",
}
ALLOWED_PUBLIC_ADDRESSES = {
    ("doctor.py", "1.1.1.1"): "target of the opt-in `ferry doctor --probe-network` isolation probe",
    ("doctor.py", "9.9.9.9"): "second target of the opt-in isolation probe",
}


def _code_strings(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """String constants that are not docstrings (f-string parts included)."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.lineno, node.value


def _findings() -> tuple[list[str], set[tuple[str, str]]]:
    problems: list[str] = []
    used: set[tuple[str, str]] = set()
    for path in sorted(FERRY_DIR.rglob("*.py")):
        rel = path.relative_to(FERRY_DIR).as_posix()
        for lineno, text in _code_strings(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            for url in URL.findall(text):
                if LOOPBACK_URL.match(url):
                    continue
                match = next((k for k in ALLOWED_URLS if k[0] == rel and url.startswith(k[1])), None)
                if match:
                    used.add(match)
                else:
                    problems.append(f"{rel}:{lineno}: URL {url}")
            for candidate in IPV4.findall(text):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if not address.is_global:
                    continue
                if (rel, candidate) in ALLOWED_PUBLIC_ADDRESSES:
                    used.add((rel, candidate))
                else:
                    problems.append(f"{rel}:{lineno}: public address {candidate}")
    return problems, used


def test_no_module_hard_codes_public_urls_or_addresses() -> None:
    problems, used = _findings()
    assert problems == [], "\n".join(problems)
    stale = (set(ALLOWED_URLS) | set(ALLOWED_PUBLIC_ADDRESSES)) - used
    assert not stale, f"allowlist entries no longer needed: {sorted(stale)}"


def test_the_scanner_catches_a_planted_url(tmp_path: Path) -> None:
    tree = ast.parse('"""Docs may say https://example.org."""\nTARGET = "https://telemetry.example.net/v1"\nIP = "8.8.4.4"\n')
    strings = [s for _, s in _code_strings(tree)]
    assert strings == ["https://telemetry.example.net/v1", "8.8.4.4"]
    assert URL.findall(strings[0]) and ipaddress.ip_address(IPV4.findall(strings[1])[0]).is_global
