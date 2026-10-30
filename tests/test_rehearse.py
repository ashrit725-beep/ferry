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
