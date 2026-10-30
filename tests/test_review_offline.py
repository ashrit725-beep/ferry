"""Adversarial review of the offline area (preflight, sandbox, rehearse, runtime, reports).

Each test reproduces one defect found in review and fails until it is fixed.
Applications and runtimes here are TEST DOUBLES written to tmp_path. Hidden
calls target RFC 5737 TEST-NET addresses and reserved names (.invalid,
.example), and anything that could leave the host runs inside the OS sandbox,
so nothing can reach a real third party. The "proxy" is a loopback test double
that never connects anywhere.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ferry import cli, runtime
from ferry.bundle.importer import import_bundle
from ferry.config import Settings
from ferry.db import Database
from ferry.errors import FerryError
from ferry.preflight import parse_strace_connects, preflight, render_markdown
from ferry.rehearse import rehearse
from ferry.rehearse import render_markdown as render_rehearsal
from ferry.sandbox import Isolation, detect_isolation
from tests.helpers_bundle import make_workspace

ISO = detect_isolation()
needs_isolation = pytest.mark.skipif(not ISO.available, reason="no network isolation tool on this host")
needs_sandbox_exec = pytest.mark.skipif(ISO.mechanism != "sandbox-exec",
                                        reason="exercises the macOS kernel-log evidence path")
NO_ISOLATION_TEXT = "no supported isolation tool found; ran with the host's normal network access"

# --- test doubles ---------------------------------------------------------------------------------------------

FAKE_RUNTIME = r'''
# TEST DOUBLE for llama-server: --version, /health, /props and /v1/chat/completions.
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
argv = sys.argv[1:]
if "--version" in argv:
    print("version: 0.0.0 (build 99999, commit testdouble)")
    sys.exit(0)
%(preamble)s
opt = lambda n: argv[argv.index(n) + 1]
token = open(opt("--api-key-file")).read().strip()
alias, port, model = opt("--alias"), int(opt("--port")), opt("-m")
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def authed(self):
        return self.headers.get("Authorization") == f"Bearer {token}"
    def do_GET(self):
        if self.path == "/health":
            return self.send(200, {"status": "ok"})
        if self.path == "/props" and self.authed():
            return self.send(200, {"model_path": model, "model_alias": alias, "build_info": "b99999-testdouble"})
        self.send(401, {})
    def do_POST(self):
        if not self.authed():
            return self.send(401, {})
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send(200, {"choices": [{"message": {"role": "assistant", "content": "ready"}}], "usage": {"prompt_tokens": 4, "completion_tokens": 1}})
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''

# Runs only in server mode, i.e. inside the rehearsal sandbox (never for --version, which runs unsandboxed).
RUNTIME_THAT_PHONES_HOME = '''
import socket
try:
    socket.create_connection(("192.0.2.1", 443), timeout=2)  # RFC 5737 TEST-NET-1, like a usage-stats upload
except OSError as exc:
    print(f"usage stats: connect() failed: {exc}", flush=True)
'''


def _fake_runtime(tmp_path: Path, preamble: str = "") -> str:
    script = tmp_path / "fake_llama_server.py"
    script.write_text(FAKE_RUNTIME % {"preamble": preamble})
    wrapper = tmp_path / "llama-server-fake"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(0o755)
    return str(wrapper)


class _LoopbackProxy:
    """TEST DOUBLE for a forward proxy on loopback (cntlm, Px, mitmproxy, `ssh -D`, a corporate agent).
    It never connects anywhere: it records the absolute URL it was asked to fetch and answers 200."""

    def __init__(self) -> None:
        seen = self.seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append(self.path)
                body = b'{"sha": "relayed-by-the-loopback-proxy"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _app(tmp_path: Path, code: str) -> list[str]:
    script = tmp_path / "app.py"
    script.write_text(code)
    return [sys.executable, str(script)]


def _installation(tmp_path: Path) -> tuple[Settings, Database]:
    """A receiving-side data dir with the workspace's tiny GGUF bundle imported (model 'tiny-model')."""
    ws = make_workspace(tmp_path)
    bundle = ws.pack().bundle_path
    (tmp_path / "data").mkdir()
    settings = Settings(data_dir=tmp_path / "data", imports=ws.policy())
    database = Database(settings.db_path)
    database.init()
    assert import_bundle(settings, database, bundle, actor_type="cli", actor_id="review").accepted
    return settings, database


def _alive(pid: int) -> bool:
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


# --- preflight: false PASS ---------------------------------------------------------------------------------------

PROXY_AWARE_CLIENT = '''
# TEST DOUBLE: a hub client checking a model revision with urllib, which (like requests, httpx, curl and pip)
# honours HTTP_PROXY from the environment.
import json, urllib.request
with urllib.request.urlopen("http://huggingface.co/api/models/Qwen/Qwen2.5-0.5B-Instruct", timeout=10) as r:
    print("revision", json.loads(r.read())["sha"], flush=True)
'''


@needs_isolation
def test_a_loopback_proxy_from_the_environment_does_not_carry_hidden_calls_past_a_pass(tmp_path, monkeypatch):
    proxy = _LoopbackProxy()
    try:
        for name in ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("HTTP_PROXY", proxy.url)  # inherited from the operator's shell, as on many corporate hosts
        monkeypatch.setenv("http_proxy", proxy.url)
        report = preflight(_app(tmp_path, PROXY_AWARE_CLIENT), log_path=tmp_path / "out.log", timeout_s=60,
                           strict=True)
    finally:
        proxy.close()
    assert not proxy.seen or report["verdict"] == "fail", (
        f"the command fetched {proxy.seen} through the loopback proxy in HTTP_PROXY, yet the preflight reported "
        f"{report['verdict'].upper()} with egress_blocked={report['isolation']['egress_blocked']}")


NUMERIC_THEN_NATIVE_LOOKUP = '''
# TEST DOUBLE: Python code calls a local service by IP (each call resolves the numeric string, which never
# reaches the resolver), then native code (ctypes stands in for a C or Rust extension) resolves a remote name.
import ctypes, socket
for _ in range(%d):
    socket.getaddrinfo("127.0.0.1", 8080)
res = ctypes.c_void_p()
ctypes.CDLL(None).getaddrinfo(b"telemetry.example", b"443", None, ctypes.byref(res))
'''


@needs_sandbox_exec
def test_strict_preflight_is_not_fooled_by_numeric_loopback_lookups(tmp_path):
    (tmp_path / "control").mkdir()
    control = preflight(_app(tmp_path / "control", NUMERIC_THEN_NATIVE_LOOKUP % 0),
                        log_path=tmp_path / "control" / "out.log", timeout_s=60, strict=True)
    if control["verdict"] != "fail":
        pytest.skip("the macOS log did not show the native lookup's resolver denial, so nothing can be compared")
    report = preflight(_app(tmp_path, NUMERIC_THEN_NATIVE_LOOKUP % 5), log_path=tmp_path / "out.log", timeout_s=60,
                       strict=True)
    assert report["verdict"] == "fail", (
        "numeric getaddrinfo('127.0.0.1') calls never reach the resolver but were used to explain away the native "
        f"remote lookup's denial: {report['network_attempts']}")


DOTTED_127_NAME = '''
# TEST DOUBLE: a library resolving a DNS name that merely starts with "127." (like the public wildcard name
# 127.0.0.1.nip.io). Resolving it needs a DNS server; a reserved .invalid name is used here.
import socket
try:
    socket.getaddrinfo("127.0.0.1.telemetry.invalid", 443)
except OSError:
    pass
'''


@needs_isolation
def test_a_remote_name_that_starts_with_127_is_reported_as_a_network_call(tmp_path):
    report = preflight(_app(tmp_path, DOTTED_127_NAME), log_path=tmp_path / "out.log", timeout_s=60)
    assert any(c["host"] == "127.0.0.1.telemetry.invalid" for c in report["python_network_calls"]), (
        "the Python hook classified the DNS name as loopback, so the lookup was hidden: "
        f"{report['network_attempts']}")
    assert report["verdict"] == "fail"


def test_strace_evidence_keeps_dns_queries_sent_to_a_loopback_stub_resolver():
    # Ubuntu's resolv.conf names systemd-resolved's stub, 127.0.0.53. Inside the network namespace that is the
    # namespace's own loopback, so a native process's lookup of a remote name leaves only this connect() behind
    # (strace output format of `strace -f -e trace=connect -o FILE`).
    line = '4242  connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0'
    assert parse_strace_connects(line), (
        "a DNS query to the stub resolver is discarded as loopback traffic, so on Linux even --strict cannot see "
        "native DNS lookups (macOS reports the same lookups as resolver denials)")


# --- preflight: argument handling, files and processes ----------------------------------------------------------

@needs_isolation
def test_a_smoke_request_without_a_ready_url_is_not_silently_skipped(tmp_path, capsys):
    code = cli.main(["preflight", "--request-url", "http://127.0.0.1:9/v1/chat/completions",
                     "--log", str(tmp_path / "out.log"), "--", sys.executable, "-c", "pass"])
    capsys.readouterr()
    assert code != 0, "--request-url was ignored (no request was sent) and the preflight still exited 0"


def test_preflight_does_not_write_through_a_symlink_planted_next_to_the_log(tmp_path):
    shared = tmp_path / "shared"  # stands in for a directory other local users can write, e.g. /tmp
    shared.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    (shared / "python-net.jsonl").symlink_to(victim)
    false = shutil.which("false")
    assert false
    # TEST DOUBLE isolation whose wrapper exits at once, so nothing runs and nothing touches the network.
    stops_at_once = Isolation("sandbox-exec", (false,), "test double: exits before running the command")
    try:
        preflight([sys.executable, "-c", "pass"], isolation=stops_at_once, log_path=shared / "preflight.log")
    except (OSError, FerryError):
        pass  # refusing the planted path is fine
    assert victim.read_text() == "keep me\n", "the preflight truncated the symlink target python-net.jsonl points to"


def test_preflight_runner_leaves_no_process_of_the_command_behind(tmp_path, monkeypatch):
    import ferry.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "probe_egress", lambda: {"tcp": None, "dns": None, "blocked": True})
    marker = tmp_path / "helper.pid"
    script = tmp_path / "launcher.py"
    script.write_text(f'''
# TEST DOUBLE: a launcher whose helper stays in its process group and ignores SIGTERM.
import os, signal, time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open({str(marker)!r}, "w") as fh:
        fh.write(str(os.getpid()))
    time.sleep(120)
    os._exit(0)
time.sleep(0.5)
''')
    preflight_module._runner({"command": [sys.executable, str(script)], "env": {}, "log_path": str(tmp_path / "out.log"),
                              "timeout_s": 60})
    for _ in range(50):
        if marker.exists() and marker.read_text():
            break
        time.sleep(0.1)
    pid = int(marker.read_text())
    try:
        time.sleep(0.5)
        alive = _alive(pid)
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert not alive, f"pid {pid} of the command's process group was still running after the preflight finished"


@needs_isolation
def test_preflight_report_without_isolation_does_not_claim_egress_was_blocked(tmp_path):
    # Reported as "none", which is what --allow-no-isolation gives on a host without a sandbox tool. It still
    # runs inside the real sandbox so that this test cannot reach the network.
    unisolated = Isolation("none", ISO.prefix, NO_ISOLATION_TEXT)
    report = preflight([sys.executable, "-c", "pass"], isolation=unisolated, require_isolation=False,
                       log_path=tmp_path / "out.log", timeout_s=60)
    assert report["isolation"]["mechanism"] == "none" and report["verdict"] == "pass"
    md = render_markdown(report)
    assert "with outbound network access blocked" not in md, md


# --- rehearse --------------------------------------------------------------------------------------------------

def test_rehearse_applies_the_import_policy_given_as_a_global_config_option(tmp_path, capsys):
    ws = make_workspace(tmp_path)
    bundle = ws.pack().bundle_path  # signed by the publisher only: the site policy below needs a reviewer too
    data = tmp_path / "data"
    data.mkdir()
    config = tmp_path / "ferry.toml"
    config.write_text(f'data_dir = {json.dumps(str(data))}\n\n[import]\nrequired_roles = ["publisher", "reviewer"]\n')
    rest = [str(bundle), "--trust-dir", str(ws.trust_dir), "--binary", str(tmp_path / "no-such-llama-server"), "--json"]

    cli.main(["rehearse", *rest, "--config", str(config)])
    after = json.loads(capsys.readouterr().out)
    assert after["verification_verdict"] == "rejected"  # control: --config after the command name is honoured

    cli.main(["--config", str(config), "rehearse", *rest])
    before = json.loads(capsys.readouterr().out)
    assert before["verification_verdict"] == "rejected", (
        "the global --config (documented in ferry/cli.py) was dropped, so the rehearsal verified under the default "
        "policy and accepted a bundle the site's policy rejects")


@needs_isolation
def test_rehearse_fails_when_the_runtime_attempts_outbound_connections(tmp_path):
    ws = make_workspace(tmp_path)
    bundle = ws.pack().bundle_path
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=_fake_runtime(tmp_path, RUNTIME_THAT_PHONES_HOME),
                      min_build=None)
    assert report["isolation"]["egress_blocked"] is True
    assert report["verdict"] == "fail", (
        "the runtime tried to connect to 192.0.2.1:443 inside the sandbox (behind an enclave firewall that drops "
        "packets this hangs), but the rehearsal passed without recording the attempt")


@needs_isolation
def test_rehearsal_report_without_isolation_does_not_claim_egress_was_blocked(tmp_path, monkeypatch):
    unisolated = Isolation("none", ISO.prefix, NO_ISOLATION_TEXT)  # labelled "none", still sandboxed (see above)
    monkeypatch.setattr("ferry.rehearse.detect_isolation", lambda: unisolated)
    ws = make_workspace(tmp_path)
    bundle = ws.pack().bundle_path
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=_fake_runtime(tmp_path), min_build=None,
                      require_isolation=False)
    assert report["isolation"]["mechanism"] == "none" and report["verdict"] == "pass", report["failures"]
    md = render_rehearsal(report)
    assert "while outbound network access was blocked" not in md, md


# --- runtime ---------------------------------------------------------------------------------------------------

def test_runtime_never_starts_llama_server_with_an_empty_api_key_file(tmp_path):
    settings, database = _installation(tmp_path)
    with database.session() as conn:
        runtime.ensure_llamacpp_registration(settings, conn, "tiny-model", 18080, actor_id="review")
    token = runtime.token_path(settings, "tiny-model")
    token.write_bytes(b"")  # emptied (failed write, truncation by a tool); still a private regular file
    assert token.stat().st_mode & 0o777 == 0o600
    try:
        with database.session() as conn:
            runtime.ensure_llamacpp_registration(settings, conn, "tiny-model", 18080, actor_id="review")
            command = runtime.llamacpp_command(settings, conn, "tiny-model", 18080)
    except FerryError:
        return  # refusing to build the command is a correct outcome
    key_file = Path(command[command.index("--api-key-file") + 1])
    assert key_file.read_text().strip(), (
        "llama-server would be started with an empty --api-key-file, which switches its API-key check off "
        "(llama.cpp b11669 then answers /props and /v1/chat/completions without a token)")
