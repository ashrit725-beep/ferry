"""Tests for ferry.sandbox and ferry.rehearse_runner.

The runtime used here is a TEST DOUBLE: a tiny HTTP server that mimics the
llama-server endpoints the runner calls. The real-runtime test is opt-in
(FERRY_TEST_LLAMACPP_MODEL).
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from ferry import sandbox

FAKE_COMPLETION = "SECRET-COMPLETION-TEXT-7f3a"

FAKE_RUNTIME = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
argv = sys.argv[1:]
opt = lambda name: argv[argv.index(name) + 1]
if "--crash" in open(opt("--api-key-file")).read():
    sys.exit(3)
token = open(opt("--api-key-file")).read().strip()
alias, port, model = opt("--alias"), int(opt("--port")), opt("-m")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def authed(self):
        return self.headers.get("Authorization") == f"Bearer {token}"
    def do_GET(self):
        if self.path == "/health":
            return self.send(200, {"status": "ok"})
        if self.path == "/props":
            if not self.authed():
                return self.send(401, {"error": {"message": "Invalid API Key"}})
            return self.send(200, {"model_path": model, "model_alias": alias, "build_info": "b99999-testdouble"})
        self.send(404, {})
    def do_POST(self):
        if not self.authed():
            return self.send(401, {"error": {"message": "Invalid API Key"}})
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send(200, {"model": alias, "choices": [{"index": 0, "message": {"role": "assistant", "content": "%s"}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}})

HTTPServer(("127.0.0.1", port), H).serve_forever()
''' % FAKE_COMPLETION


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fake_binary(tmp_path: Path) -> Path:
    script = tmp_path / "fake_llama_server.py"
    script.write_text(FAKE_RUNTIME)
    wrapper = tmp_path / "fake-llama-server"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


def _run_runner(tmp_path: Path, binary: str, model_path: str, token: str, isolate: bool) -> dict:
    token_file = tmp_path / "token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    args = {
        "binary": binary, "token_file": str(token_file), "log_dir": str(tmp_path),
        "prompt": "say ready", "max_tokens": 4, "ctx_size": 512, "load_timeout_s": 60,
        "models": [{"name": "m1", "digest": "ab" * 32, "port": _free_port(), "path": model_path}],
    }
    cmd = [sys.executable, "-I", "-m", "ferry.rehearse_runner", json.dumps(args)]
    if isolate:
        cmd = sandbox.detect_isolation().wrap(cmd)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr
    assert FAKE_COMPLETION not in proc.stdout, "completion text must never leave the runner"
    return json.loads(proc.stdout)


class _FakeSocket:
    def __init__(self, exc: BaseException | None):
        self.exc = exc

    def settimeout(self, _t):
        pass

    def connect(self, _addr):
        if self.exc:
            raise self.exc

    def close(self):
        pass


@pytest.mark.parametrize(
    "exc, blocked, result",
    [
        (PermissionError(errno.EPERM, "Operation not permitted"), True, "denied"),
        (OSError(errno.ENETUNREACH, "Network is unreachable"), True, "unreachable"),
        (TimeoutError(), False, "timeout"),
        (OSError(errno.ECONNRESET, "reset"), False, "error"),
        (None, False, "connected"),
    ],
)
def test_tcp_probe_classification(monkeypatch, exc, blocked, result):
    monkeypatch.setattr(sandbox.socket, "socket", lambda *a, **k: _FakeSocket(exc))
    probe = sandbox._probe_tcp(0.1)
    assert (probe["blocked"], probe["result"]) == (blocked, result)


def test_dns_probe_classification(monkeypatch):
    def fail(*_a, **_k):
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(sandbox.socket, "getaddrinfo", fail)
    assert sandbox._probe_dns()["blocked"] is True
    monkeypatch.setattr(sandbox.socket, "getaddrinfo", lambda *_a, **_k: [("ok",)])
    assert sandbox._probe_dns()["blocked"] is False


def test_overall_probe_requires_both_blocked(monkeypatch):
    monkeypatch.setattr(sandbox, "_probe_tcp", lambda _t: {"blocked": True})
    monkeypatch.setattr(sandbox, "_probe_dns", lambda: {"blocked": False})
    assert sandbox.probe_egress()["blocked"] is False


def test_commands_get_no_proxy_variables():
    env = {"HTTP_PROXY": "http://127.0.0.1:3128", "https_proxy": "http://user:pw@proxy.corp.example:8080",
           "All_Proxy": "socks5h://localhost:1080", "PIP_PROXY": "[::1]:3128", "NO_PROXY": "internal", "PATH": "/bin"}
    clean = sandbox.without_proxies(env)
    assert clean == {"PATH": "/bin", "NO_PROXY": "*", "no_proxy": "*"}
    assert sandbox.local_proxies(env) == ["All_Proxy", "HTTP_PROXY", "PIP_PROXY"]


def test_no_isolation_is_explicit(monkeypatch):
    monkeypatch.setattr(sandbox.sys, "platform", "sunos5")
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "none" and not iso.available and iso.wrap(["x"]) == ["x"]


@pytest.mark.skipif(not sandbox.detect_isolation().available, reason="no network isolation tool on this host")
def test_isolation_actually_blocks_egress():
    code = "import json; from ferry.sandbox import probe_egress; print(json.dumps(probe_egress(2)))"
    proc = subprocess.run(sandbox.detect_isolation().wrap([sys.executable, "-I", "-c", code]),
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    probe = json.loads(proc.stdout)
    assert probe["blocked"] is True, probe
    assert probe["tcp"]["result"] in ("denied", "unreachable")


@pytest.mark.parametrize("isolate", [False, pytest.param(True, marks=pytest.mark.skipif(
    not sandbox.detect_isolation().available, reason="no network isolation tool on this host"))])
def test_runner_against_fake_runtime(tmp_path, isolate):
    result = _run_runner(tmp_path, str(_fake_binary(tmp_path)), "/models/m1.gguf", "tok-123", isolate)
    model = result["models"][0]
    assert model["ok"] is True, model
    assert model["completion_tokens"] == 2 and model["prompt_tokens"] == 5
    assert model["build_info"] == "b99999-testdouble"
    assert model["served_model_path"] == "/models/m1.gguf"
    if isolate:
        assert result["probe"]["blocked"] is True


def test_runner_reports_runtime_crash(tmp_path):
    result = _run_runner(tmp_path, str(_fake_binary(tmp_path)), "/models/m1.gguf", "--crash", isolate=False)
    model = result["models"][0]
    assert model["ok"] is False
    assert "exited with code 3" in model["error"]


@pytest.mark.llamacpp
@pytest.mark.skipif(not os.environ.get("FERRY_TEST_LLAMACPP_MODEL") or not shutil.which("llama-server"),
                    reason="set FERRY_TEST_LLAMACPP_MODEL to a GGUF file and install llama-server")
def test_runner_real_llamacpp_in_sandbox(tmp_path):
    isolate = sandbox.detect_isolation().available
    result = _run_runner(tmp_path, shutil.which("llama-server"), os.environ["FERRY_TEST_LLAMACPP_MODEL"],
                         "tok-real", isolate)
    model = result["models"][0]
    assert model["ok"] is True, model
    assert model["build_info"]
