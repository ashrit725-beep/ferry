"""Tests for ferry.rehearse (offline rehearsal of a bundle on the connected side).

The runtime here is a TEST DOUBLE that mimics llama-server's `--version`,
`/health`, `/props` and `/v1/chat/completions`. The real-runtime test is opt-in
(FERRY_TEST_LLAMACPP_MODEL).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from ferry.bundle.pack import sign_bundle
from ferry.rehearse import rehearse, render_markdown
from ferry.sandbox import detect_isolation
from tests.helpers_bundle import make_signer, make_workspace

needs_isolation = pytest.mark.skipif(not detect_isolation().available, reason="no network isolation tool on this host")

FAKE = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
BUILD, SERVED = %(build)d, %(served)r
argv = sys.argv[1:]
if "--version" in argv:
    print(f"version: 0.0.0 (build {BUILD}, commit testdouble)")
    sys.exit(0)
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
            return self.send(200, {"model_path": SERVED or model, "model_alias": alias, "build_info": f"b{BUILD}-testdouble"})
        self.send(401, {})
    def do_POST(self):
        if not self.authed():
            return self.send(401, {})
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send(200, {"choices": [{"message": {"role": "assistant", "content": "ready"}}], "usage": {"prompt_tokens": 4, "completion_tokens": 1}})
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def _fake_runtime(tmp_path: Path, *, build: int = 99999, served: str = "") -> str:
    script = tmp_path / "fake_llama.py"
    script.write_text(FAKE % {"build": build, "served": served})
    wrapper = tmp_path / "llama-server-fake"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(0o755)
    return str(wrapper)


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


@pytest.fixture
def bundle(ws):
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    return res.bundle_path


@needs_isolation
def test_trusted_bundle_rehearses_and_serves_the_imported_file(ws, bundle, tmp_path):
    report = rehearse(bundle, trust_dir=ws.trust_dir, import_settings=ws.policy(required_roles=("publisher", "reviewer")),
                      binary=_fake_runtime(tmp_path), min_build=8146)
    assert report["verdict"] == "pass", report["failures"]
    assert report["verification_verdict"] == "accepted"
    assert report["isolation"]["egress_blocked"] is True
    (model,) = report["models"]
    assert model["ok"] and model["served_file_matches_import"] and model["completion_tokens"] == 1
    assert report["runtime"]["build"] == 99999
    md = render_markdown(report)
    assert "(PASS)" in md and "What this shows" in md


def test_untrusted_bundle_never_starts_a_runtime(ws, bundle, tmp_path):
    stranger = make_workspace(tmp_path / "other")  # a trust store that does not hold our signers
    report = rehearse(bundle, trust_dir=stranger.trust_dir, binary=_fake_runtime(tmp_path))
    assert report["verdict"] == "fail"
    assert report["verification_verdict"] == "rejected" and report["runtime"] is None and report["models"] == []


def test_runtime_older_than_minimum_build_is_refused(ws, bundle, tmp_path):
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=_fake_runtime(tmp_path, build=8000), min_build=8146)
    assert report["verdict"] == "fail"
    assert any("older than the minimum b8146" in f for f in report["failures"])
    assert report["models"] == []


@needs_isolation
def test_runtime_serving_a_different_file_fails(ws, bundle, tmp_path):
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=_fake_runtime(tmp_path, served="/elsewhere/other.gguf"),
                      min_build=None)
    assert report["verdict"] == "fail"
    assert any("not the imported file" in f for f in report["failures"])


def test_missing_runtime_is_reported(ws, bundle, tmp_path):
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=None if shutil.which("llama-server") is None else "/nonexistent/llama-server")
    assert report["verdict"] == "fail"


@pytest.mark.llamacpp
@needs_isolation
@pytest.mark.skipif(not os.environ.get("FERRY_TEST_LLAMACPP_MODEL") or not shutil.which("llama-server"),
                    reason="set FERRY_TEST_LLAMACPP_MODEL to a GGUF file and install llama-server")
def test_real_model_bundle_rehearses(tmp_path):
    from ferry.bundle.pack import pack_bundle
    from ferry.trust import add_key

    model = Path(os.environ["FERRY_TEST_LLAMACPP_MODEL"])
    spec = tmp_path / "bundle.toml"
    spec.write_text(
        '[bundle]\nname = "real-model"\nversion = "1.0.0"\n\n'
        f'[[artifacts]]\nsource = "{model}"\npath = "models/{model.name}"\nkind = "model"\n'
        '[artifacts.model]\nname = "real-model"\nlicense = "Apache-2.0"\n'
    )
    signer = make_signer("publisher")
    add_key(tmp_path / "trust", signer.pem, name="publisher", roles=["publisher"])
    res = pack_bundle(spec, signer.key, tmp_path / "out")
    report = rehearse(res.bundle_path, trust_dir=tmp_path / "trust", max_tokens=4, ctx_size=1024)
    assert report["verdict"] == "pass", report["failures"]
    assert report["models"][0]["served_file_matches_import"]


# --- CLI: ferry rehearse options -----------------------------------------------------------------------------


def _capture_rehearse(monkeypatch) -> list[dict]:
    """Replace the rehearsal itself and return the keyword arguments of each call."""
    import ferry.rehearse as rehearse_mod

    calls: list[dict] = []

    def fake(bundle, **kwargs):
        calls.append(kwargs)
        return {"verdict": "pass", "bundle": Path(bundle).name, "failures": [], "notes": [], "models": [],
                "verification_errors": []}

    monkeypatch.setattr(rehearse_mod, "rehearse", fake)
    return calls


def test_rehearse_accepts_data_dir_after_the_command_name():
    from ferry.cli import build_parser

    args = build_parser().parse_args(["rehearse", "b.tar", "--trust-dir", "t", "--data-dir", "d"])
    assert args.data_dir == "d"


def test_rehearse_keeps_a_global_data_dir_given_before_the_command_name():
    from ferry.cli import build_parser

    args = build_parser().parse_args(["--data-dir", "g", "rehearse", "b.tar", "--trust-dir", "t"])
    assert args.data_dir == "g"


@pytest.mark.parametrize("flag", ["--data-dir", "--config-data-dir"])
def test_rehearse_data_dir_selects_the_import_policy(monkeypatch, tmp_path, flag):
    import ferry.config as config_mod
    from ferry.cli import main

    calls = _capture_rehearse(monkeypatch)
    seen: list[tuple] = []
    policy = config_mod.ImportSettings(required_roles=("publisher", "reviewer"))

    def fake_load(config_path=None, data_dir=None):
        seen.append((config_path, data_dir))
        return config_mod.Settings(data_dir=Path(data_dir), imports=policy)

    monkeypatch.setattr(config_mod, "load_settings", fake_load)
    code = main(["rehearse", str(tmp_path / "b.tar"), "--trust-dir", str(tmp_path), flag, str(tmp_path / "d"),
                 "--json"])
    assert code == 0
    assert seen == [(None, str(tmp_path / "d"))]
    assert calls[0]["import_settings"].required_roles == ("publisher", "reviewer")


def test_rehearse_unknown_role_is_a_usage_error_before_any_import(monkeypatch, tmp_path, capsys):
    from ferry.cli import main

    calls = _capture_rehearse(monkeypatch)
    code = main(["rehearse", str(tmp_path / "b.tar"), "--trust-dir", str(tmp_path), "--require-role", "publsher"])
    assert code == 2
    err = capsys.readouterr().err
    assert "publsher" in err and "roles are: publisher, reviewer" in err
    assert calls == []


def test_rehearse_repeated_role_is_required_once(monkeypatch, tmp_path):
    from ferry.cli import main

    calls = _capture_rehearse(monkeypatch)
    code = main(["rehearse", str(tmp_path / "b.tar"), "--trust-dir", str(tmp_path), "--require-role", "reviewer",
                 "--require-role", "reviewer", "--json"])
    assert code == 0
    assert calls[0]["import_settings"].required_roles == ("reviewer",)


# --- the runner's outer timeout ------------------------------------------------------------------------------

# A runtime that never becomes ready and ignores SIGTERM, recording its process group.
STUCK = r'''
import os, signal, sys, time
if "--version" in sys.argv:
    print("version: 0.0.0 (build 99999, commit testdouble)")
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(%(pgid_file)r, "w") as f:
    f.write(str(os.getpgid(0)))
while True:
    time.sleep(1)
'''


def _stuck_runtime(tmp_path: Path) -> tuple[str, Path]:
    pgid_file = tmp_path / "runtime.pgid"
    script = tmp_path / "stuck_llama.py"
    script.write_text(STUCK % {"pgid_file": str(pgid_file)})
    wrapper = tmp_path / "llama-server-stuck"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(0o755)
    return str(wrapper), pgid_file


def _group_gone(pgid: int, within_s: float = 5.0) -> bool:
    import time

    deadline = time.monotonic() + within_s
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize("runner_obeys_sigterm", [True, False], ids=["runner-stops-runtime", "runner-killed"])
def test_runner_timeout_leaves_no_runtime_running(ws, bundle, tmp_path, monkeypatch, runner_obeys_sigterm):
    import ferry.rehearse as rehearse_mod

    binary, pgid_file = _stuck_runtime(tmp_path)
    # The outer limit fires while the runner is still inside its load timeout (60 s).
    monkeypatch.setattr(rehearse_mod, "runner_budget_s", lambda n_models, load_timeout_s: 4.0)
    if runner_obeys_sigterm:
        monkeypatch.setattr(rehearse_mod, "STOP_GRACE_S", 0.5)
    else:
        # The runner's own stop is still waiting when it is killed, so only the parent's sweep of the announced
        # process group can stop the runtime.
        monkeypatch.setattr(rehearse_mod, "STOP_GRACE_S", 60.0)
        monkeypatch.setattr(rehearse_mod, "RUNNER_GRACE_S", 0.5)
    report = rehearse(bundle, trust_dir=ws.trust_dir, binary=binary, min_build=None, require_isolation=False,
                      load_timeout_s=60)
    assert report["verdict"] == "fail"
    assert any("did not finish within 4 s" in f for f in report["failures"]), report["failures"]
    pgid = int(pgid_file.read_text())
    assert _group_gone(pgid), f"runtime process group {pgid} is still running"


def test_runner_budget_covers_every_inner_limit():
    import ferry.rehearse as rehearse_mod

    for n in (1, 2, 5):
        inner = n * (600 + rehearse_mod.PROPS_TIMEOUT_S + rehearse_mod.REQUEST_TIMEOUT_S + rehearse_mod.STOP_GRACE_S + 5)
        assert rehearse_mod.runner_budget_s(n, 600) > inner
