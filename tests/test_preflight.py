"""Tests for ferry.preflight, ferry.offline_rules and the Python preflight hook.

The applications under test are TEST DOUBLES written to tmp_path: tiny servers
that do or do not make hidden network calls. Hidden calls target names and
RFC 5737 TEST-NET addresses only, so nothing can reach a real third party even
if isolation fails.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from ferry import offline_rules
from ferry.preflight import parse_macos_denials, parse_strace_connects, preflight, read_netlog, render_markdown, scan_output
from ferry.sandbox import detect_isolation

ISOLATED = detect_isolation().available
needs_isolation = pytest.mark.skipif(not ISOLATED, reason="no network isolation tool on this host")
HOOK_DIR = Path(__file__).resolve().parents[1] / "ferry" / "preflight_hook"

LEAKY_LIB = '''
# TEST DOUBLE: behaves like a model-hub client that checks for updates.
import socket
def check_for_updates():
    try:
        socket.getaddrinfo("huggingface.co", 443)
    except OSError as exc:
        print(f"We couldn't connect to 'https://huggingface.co' to load this file: {exc}", flush=True)
'''

APP = '''
# TEST DOUBLE: a tiny model server. With "leaky" it calls a hub client and a
# direct IP (RFC 5737 TEST-NET-2) at startup, like many Python AI stacks do.
import socket, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, mode = int(sys.argv[1]), sys.argv[2]
if mode == "leaky":
    import fake_hub_client
    fake_hub_client.check_for_updates()
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(("198.51.100.7", 443))
    except OSError as exc:
        print("telemetry upload failed:", exc, flush=True)
    finally:
        s.close()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b'{"choices":[{"message":{"content":"never stored"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}'
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def app(tmp_path: Path) -> dict:
    (tmp_path / "site" / "fake_hub_client").mkdir(parents=True)
    (tmp_path / "site" / "fake_hub_client" / "__init__.py").write_text(LEAKY_LIB)
    (tmp_path / "app.py").write_text(APP)
    return {"script": str(tmp_path / "app.py"), "env": {"PYTHONPATH": str(tmp_path / "site")}, "dir": tmp_path}


# --- parsers and rules ----------------------------------------------------------------

def test_parse_macos_denials_aggregates_and_labels_dns():
    text = "\n".join([
        "2026-10-28 02:57:34.104 E  kernel[0:1f3a353] (Sandbox) Sandbox: Python(55970) deny(1) network-outbound remote:*:443",
        "2026-10-28 02:57:36.672 E  kernel[0:1f22559] (Sandbox) 3 duplicate reports for Sandbox: Python(55970) deny(1) network-outbound remote:*:443",
        "2026-10-28 02:57:36.700 E  kernel[0:1f22559] (Sandbox) Sandbox: Python(55970) deny(1) network-outbound /private/var/run/mDNSResponder",
        "unrelated line",
    ])
    denials = {(d["destination"], d["kind"]): d["count"] for d in parse_macos_denials(text)}
    assert denials == {("remote:*:443", "connect"): 4, ("/private/var/run/mDNSResponder", "dns"): 1}


def test_parse_strace_connects_ignores_loopback_and_unix():
    text = "\n".join([
        '412 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        '412 connect(5, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        '413 connect(6, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH',
        '414 connect(7, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 42) = -1 ENOENT',
    ])
    dests = sorted(a["destination"] for a in parse_strace_connects(text))
    assert dests == ["1.1.1.1:443", "[2606:4700::1111]:443"]


def test_scan_output_extracts_hosts(tmp_path):
    log = tmp_path / "out.log"
    log.write_text(
        "loading model\n"
        "urllib3 HTTPSConnectionPool(host='huggingface.co', port=443): Max retries exceeded\n"
        "curl: (6) Could not resolve host: raw.githubusercontent.com\n"
        "ready on http://127.0.0.1:8080\n"
    )
    lines, hosts = scan_output(log)
    assert len(lines) == 2
    assert hosts == ["huggingface.co", "raw.githubusercontent.com"]


def test_rules_match_by_host_package_and_output():
    found = {f["rule"]: f["matched_on"] for f in offline_rules.match(
        hosts={"cdn-lfs.huggingface.co", "stats.vllm.ai"}, packages={"huggingface_hub", "tiktoken", "open_webui"},
        lines=["fetching model_prices_and_context_window.json failed"])}
    assert found["huggingface-hub"] == ["host", "package"]
    assert found["vllm-usage-stats"] == ["host"]
    assert found["litellm-cost-map"] == ["output"]
    # A rule with known hosts does not fire on the package name alone...
    assert "tiktoken-vocab" not in found and "hf-cli-update-check" not in found
    # ...but a rule without hosts can.
    assert found["open-webui-aux-models"] == ["package"]
    assert offline_rules.match(hosts={"example.internal"}) == []


def test_rule_wildcards_do_not_overmatch():
    assert offline_rules._host_matches("huggingface.co", "*.huggingface.co")
    assert offline_rules._host_matches("cdn-lfs.huggingface.co", "*.huggingface.co")
    assert not offline_rules._host_matches("evilhuggingface.co", "*.huggingface.co")


def test_read_netlog_aggregates(tmp_path):
    log = tmp_path / "net.jsonl"
    rec = {"event": "getaddrinfo", "host": "huggingface.co", "port": 443, "module": "huggingface_hub.file_download",
           "location": "x.py:1", "pid": 7}
    log.write_text(json.dumps(rec) + "\n" + json.dumps({**rec, "pid": 8}) + "\nnot json\n")
    calls = read_netlog(log)
    assert len(calls) == 1 and calls[0]["count"] == 2 and calls[0]["package"] == "huggingface_hub"
    assert calls[0]["pids"] == [7, 8]


def test_dns_denials_are_explained_only_by_resolver_lookups_of_the_same_process(tmp_path):
    from ferry.preflight import _explain_dns_denials

    log = tmp_path / "net.jsonl"
    rec = {"event": "gethostbyaddr", "host": "127.0.0.1", "port": None, "module": "http.server", "local": True}
    numeric = {"event": "getaddrinfo", "host": "127.0.0.1", "port": 8080, "module": "__main__", "local": True}
    log.write_text("\n".join(json.dumps(r) for r in [{**rec, "pid": 1}] + [{**rec, "pid": 2}] * 9
                             + [{**numeric, "pid": 1}] * 5) + "\n")
    records = read_netlog(log)
    attempts = [{"pid": 1, "kind": "dns", "count": 2}, {"pid": 2, "kind": "dns", "count": 9}]
    _explain_dns_denials(attempts, records)
    # pid 1 made one reverse lookup; its five numeric lookups never reached the resolver.
    assert [a["explained_by"] for a in attempts] == [None, "local name lookup"]
    attempts = [{"pid": 2, "kind": "dns", "count": 1}]
    _explain_dns_denials(attempts, records, count_local_lookups=False)  # Linux: /etc/hosts answers local names
    assert attempts[0]["explained_by"] is None


def test_a_symlinked_log_path_is_refused(tmp_path):
    from ferry.errors import FerryError
    from ferry.sandbox import Isolation

    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    (tmp_path / "out.log").symlink_to(victim)
    with pytest.raises(FerryError):
        preflight(["true"], isolation=Isolation("none", (), "test"), log_path=tmp_path / "out.log")
    assert victim.read_text() == "keep me\n"


def test_hook_never_breaks_the_application(tmp_path):
    code = "import socket\ntry:\n    socket.getaddrinfo('huggingface.co', 443)\nexcept OSError:\n    pass\nprint('still alive')"
    env = {**os.environ, "PYTHONPATH": str(HOOK_DIR), "FERRY_PREFLIGHT_NETLOG": str(tmp_path / "missing-dir" / "x.jsonl")}
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and "still alive" in proc.stdout


def test_hook_records_caller_module(tmp_path):
    (tmp_path / "pkg_under_test").mkdir()
    (tmp_path / "pkg_under_test" / "__init__.py").write_text(
        "import socket\ndef go():\n    try:\n        socket.getaddrinfo('telemetry.invalid', 443)\n    except OSError:\n        pass\n")
    netlog = tmp_path / "net.jsonl"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(HOOK_DIR), str(tmp_path)]), "FERRY_PREFLIGHT_NETLOG": str(netlog)}
    subprocess.run([sys.executable, "-c", "import pkg_under_test; pkg_under_test.go()"], env=env, check=True, timeout=60)
    calls = read_netlog(netlog)
    assert [(c["host"], c["package"]) for c in calls] == [("telemetry.invalid", "pkg_under_test")]


# --- end to end inside the sandbox ------------------------------------------------------

@needs_isolation
def test_leaky_app_fails_with_attribution_and_fix(app):
    port = _free_port()
    report = preflight([sys.executable, app["script"], str(port), "leaky"], ready_url=f"http://127.0.0.1:{port}/health",
                       env=app["env"], log_path=app["dir"] / "out.log", ready_timeout_s=60)
    assert report["verdict"] == "fail"
    assert report["isolation"]["egress_blocked"] is True
    calls = {(c["host"], c["package"]) for c in report["python_network_calls"]}
    assert ("huggingface.co", "fake_hub_client") in calls
    assert ("198.51.100.7", "__main__") in calls
    assert "huggingface-hub" in {f["rule"] for f in report["findings"]}
    if detect_isolation().mechanism == "sandbox-exec":
        assert report["network_attempts"], "kernel sandbox denials should be attributed to the app"
    md = render_markdown(report)
    assert "Likely causes and fixes" in md and "HF_HUB_OFFLINE=1" in md


@needs_isolation
def test_clean_app_passes_and_smoke_request_never_stores_text(app):
    port = _free_port()
    report = preflight(
        [sys.executable, app["script"], str(port), "clean"], ready_url=f"http://127.0.0.1:{port}/health",
        request={"url": f"http://127.0.0.1:{port}/v1/chat/completions", "body": {"messages": []}},
        env=app["env"], log_path=app["dir"] / "out.log", ready_timeout_s=60)
    assert report["verdict"] == "pass", report["failures"]
    assert report["process"]["request"]["usage"] == {"prompt_tokens": 3, "completion_tokens": 1}
    assert report["python_network_calls"] == []
    # http.server reverse-resolves 127.0.0.1 when it binds; that lookup is listed but explained, not counted.
    assert all(a["kind"] == "dns" and a.get("explained_by") == "local name lookup" for a in report["network_attempts"])
    assert "never stored" not in json.dumps(report)


@needs_isolation
def test_allow_attempts_downgrades_to_warnings(app):
    port = _free_port()
    report = preflight([sys.executable, app["script"], str(port), "leaky"], ready_url=f"http://127.0.0.1:{port}/health",
                       env=app["env"], log_path=app["dir"] / "out.log", ready_timeout_s=60, allow_attempts=True)
    assert report["verdict"] == "pass" and report["warnings"]


@needs_isolation
def test_oneshot_exit_code_is_reported(tmp_path):
    report = preflight([sys.executable, "-c", "import sys; sys.exit(3)"], log_path=tmp_path / "out.log", timeout_s=60)
    assert report["verdict"] == "fail"
    assert any("exited with code 3" in f for f in report["failures"])


def test_missing_isolation_fails_closed(tmp_path, monkeypatch):
    from ferry.sandbox import Isolation
    report = preflight(["true"], isolation=Isolation("none", (), "test"), log_path=tmp_path / "out.log")
    assert report["verdict"] == "fail" and "no network isolation" in report["failures"][0]


@pytest.mark.llamacpp
@needs_isolation
@pytest.mark.skipif(not os.environ.get("FERRY_TEST_LLAMACPP_MODEL") or not shutil.which("llama-server"),
                    reason="set FERRY_TEST_LLAMACPP_MODEL to a GGUF file and install llama-server")
def test_real_llama_server_offline_passes(tmp_path):
    port = _free_port()
    report = preflight(
        [shutil.which("llama-server"), "-m", os.environ["FERRY_TEST_LLAMACPP_MODEL"], "--host", "127.0.0.1",
         "--port", str(port), "--offline", "--no-webui", "-c", "1024"],
        ready_url=f"http://127.0.0.1:{port}/health",
        request={"url": f"http://127.0.0.1:{port}/v1/chat/completions",
                 "body": {"messages": [{"role": "user", "content": "Say ready"}], "max_tokens": 4}},
        log_path=tmp_path / "out.log", ready_timeout_s=120)
    assert report["verdict"] == "pass", report["failures"]
    assert report["process"]["request"]["usage"]["completion_tokens"] >= 1


# --- CLI: report paths, --request-json, Markdown command -----------------------------------------------------

def _fake_report(verdict: str = "pass") -> dict:
    return {"verdict": verdict, "command": ["true"], "isolation": {"mechanism": "none"}, "process": {"exit_code": 0},
            "evidence_sources": [], "log_file": "out.log"}


def test_a_missing_out_directory_fails_before_the_run(tmp_path, monkeypatch, capsys):
    import ferry.preflight as preflight_module
    from ferry import cli

    def must_not_run(*a, **k):
        raise AssertionError("preflight() ran although --out cannot be written")

    monkeypatch.setattr(preflight_module, "preflight", must_not_run)
    out = tmp_path / "missing" / "r.json"
    assert cli.main(["preflight", "--out", str(out), "--", "true"]) == 2
    err = capsys.readouterr().err
    assert "ferry preflight: --out" in err and "does not exist" in err and str(tmp_path / "missing") in err
    assert cli.main(["preflight", "--md", str(tmp_path), "--", "true"]) == 2
    assert "is a directory" in capsys.readouterr().err


def test_a_valid_out_is_written_after_the_verdict_is_printed(tmp_path, monkeypatch, capsys):
    import ferry.preflight as preflight_module
    from ferry import cli

    monkeypatch.setattr(preflight_module, "preflight", lambda *a, **k: _fake_report("fail"))
    out, md = tmp_path / "r.json", tmp_path / "r.md"
    assert cli.main(["preflight", "--out", str(out), "--md", str(md), "--", "true"]) == 1
    assert json.loads(out.read_text())["verdict"] == "fail"
    assert md.read_text().startswith("# Offline preflight (FAIL)")
    assert "Offline preflight: FAIL" in capsys.readouterr().out


def test_a_late_write_error_still_shows_the_verdict(tmp_path, monkeypatch, capsys):
    import ferry.preflight as preflight_module
    from ferry import cli

    out = tmp_path / "gone" / "r.json"
    out.parent.mkdir()

    def run_then_remove(*a, **k):
        out.parent.rmdir()  # the directory disappears while the command runs
        return _fake_report("pass")

    monkeypatch.setattr(preflight_module, "preflight", run_then_remove)
    assert cli.main(["preflight", "--json", "--out", str(out), "--", "true"]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["verdict"] == "pass"
    assert "could not write --out" in captured.err and "(pass) stands" in captured.err


def test_an_invalid_request_json_is_a_usage_error(tmp_path, monkeypatch, capsys):
    import ferry.preflight as preflight_module
    from ferry import cli

    monkeypatch.setattr(preflight_module, "preflight", lambda *a, **k: pytest.fail("preflight() ran"))
    bad = tmp_path / "bad.json"
    bad.write_text("{bad")
    code = cli.main(["preflight", "--ready-url", "http://127.0.0.1:9/", "--request-url", "http://127.0.0.1:9/x",
                     "--request-json", str(bad), "--", "true"])
    err = capsys.readouterr().err
    assert code == 2
    assert "--request-json" in err and "not valid JSON" in err and str(bad) in err
    assert "internal error" not in err


def test_markdown_command_is_the_exact_argv(tmp_path):
    import shlex

    for argv in (["/bin/sh", "-c", 'echo "a b"'], ["python", "-c", "print(`x`)", "a ``` b", "it's"]):
        md = render_markdown({"verdict": "pass", "command": argv, "isolation": {}, "process": {}})
        if argv[0] == "/bin/sh":
            assert "/bin/sh -c 'echo \"a b\"'" in md
        lines = md.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("```") and line.endswith("sh"))
        fence = lines[start][:-2]
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == fence)
        assert shlex.split("\n".join(lines[start + 1:end])) == argv


def test_markdown_table_cells_survive_pipes_and_newlines():
    report = {"verdict": "fail", "command": ["x"], "isolation": {"mechanism": "m", "description": "a|b\nc"},
              "process": {}, "network_attempts": [{"process": "p|q", "pid": 1, "destination": "h\n| x", "count": 1}]}
    md = render_markdown(report)
    assert "| Isolation | m: a\\|b c |" in md
    assert "| p\\|q | 1 | h \\| x | 1 |" in md
