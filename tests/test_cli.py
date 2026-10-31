"""CLI tests (spec section 10): commands run as real subprocesses (`python -m
ferry.cli`, plus the installed `ferry` console script) against temporary data
directories. Exit codes: 0 success/accepted, 1 rejected/failed, 2 usage, I/O or
configuration error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers_app import CSP, bundle_setup
from helpers_bundle import PICKLE_PROTO4, make_workspace
from helpers_gateway import write_token
from helpers_upstream import FakeUpstream

from ferry.cli import build_parser
from ferry.config import load_settings
from ferry.doctor import PROXY_VARIABLES

PY = sys.executable
FERRY_SCRIPT = Path(sys.executable).parent / "ferry"
CREATED_AT = "2026-10-28T02:00:00Z"
SPEC_COMMANDS = ["version", "init", "keygen", "pack", "sign", "inspect", "verify", "import", "trust", "admin", "app",
                 "backend", "route", "policy", "runtime", "audit", "store", "evidence", "doctor", "serve",
                 "preflight", "rehearse"]
COMMAND_PATHS = [["version"], ["init"], ["keygen"], ["pack"], ["sign"], ["inspect"], ["verify"], ["import"],
                 ["trust", "add"], ["trust", "list"], ["trust", "revoke"], ["admin", "create-user"], ["app", "create"],
                 ["app", "list"], ["app", "key"], ["app", "revoke-key"], ["backend", "add"], ["backend", "list"],
                 ["backend", "check"], ["route", "add"], ["route", "list"], ["policy", "validate"],
                 ["policy", "activate"], ["policy", "show"], ["policy", "explain"], ["runtime", "llamacpp"],
                 ["audit", "verify"], ["audit", "export"], ["audit", "checkpoint"], ["store", "verify"], ["evidence"],
                 ["doctor"], ["serve"], ["preflight"], ["rehearse"]]


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("FERRY_") and k.upper() not in PROXY_VARIABLES}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra or {})
    return env


def ferry(*args: Any, input: str | None = None, env: dict[str, str] | None = None, cwd: Path | None = None,
          timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run([PY, "-m", "ferry.cli", *map(str, args)], input=input, capture_output=True, text=True,
                          env=_env(env), cwd=cwd, timeout=timeout, stdin=None if input is not None else subprocess.DEVNULL,
                          check=False)


def ok(proc: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    assert proc.returncode == 0, f"exit {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return proc


def code(proc: subprocess.CompletedProcess[str], expected: int) -> subprocess.CompletedProcess[str]:
    assert proc.returncode == expected, f"exit {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return proc


def _events(data: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(data / "ferry.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
    finally:
        conn.close()


def _tamper(bundle: Path, target: Path) -> Path:
    data = bytearray(bundle.read_bytes())
    data[data.rfind(b"Apache License")] ^= 0x01
    target.write_bytes(bytes(data))
    return target


# --- parser and entry point -------------------------------------------------------------------


def test_the_console_script_entry_point_works() -> None:
    assert FERRY_SCRIPT.is_file(), "pyproject's [project.scripts] ferry = ferry.cli:main is not installed"
    help_text = subprocess.run([str(FERRY_SCRIPT), "--help"], capture_output=True, text=True, env=_env(),
                               timeout=60, stdin=subprocess.DEVNULL, check=False)
    assert help_text.returncode == 0, help_text.stderr
    for name in SPEC_COMMANDS:
        assert re.search(rf"^\s+{name}\s", help_text.stdout, re.MULTILINE), name
    version = subprocess.run([str(FERRY_SCRIPT), "version"], capture_output=True, text=True, env=_env(), timeout=60,
                             stdin=subprocess.DEVNULL, check=False)
    assert version.returncode == 0 and version.stdout.strip() == "ferry 0.1.0"


@pytest.mark.parametrize("path", COMMAND_PATHS, ids=[" ".join(p) for p in COMMAND_PATHS])
def test_every_command_has_help(path: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args([*path, "--help"])
    assert exit_info.value.code == 0
    assert f"usage: ferry {' '.join(path)}" in capsys.readouterr().out


def _option_strings(parser: argparse.ArgumentParser) -> set[str]:
    found: set[str] = set()
    for action in parser._actions:
        found.update(action.option_strings)
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                found |= _option_strings(sub)
    return found


def test_secrets_are_never_command_line_arguments() -> None:
    options = _option_strings(build_parser())
    secretish = {o for o in options if re.search(r"pass|secret|api-?key", o)
                 or (re.search(r"token", o) and o != "--max-tokens")}
    assert secretish == {"--passphrase-file", "--no-passphrase", "--password-stdin", "--token-file"}


def test_global_options_work_before_and_after_the_command(tmp_path: Path) -> None:
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    assert "ID" in ok(ferry("--data-dir", data, "app", "list")).stdout
    assert "ID" in ok(ferry("app", "list", "--data-dir", data)).stdout
    assert "ID" in ok(ferry("app", "list", env={"FERRY_DATA_DIR": str(data)})).stdout
    assert "ID" in ok(ferry("--config", data / "ferry.toml", "app", "list")).stdout


def test_usage_and_configuration_errors_exit_2(tmp_path: Path) -> None:
    assert ferry().returncode == 2
    assert "no data directory" in code(ferry("import", tmp_path / "x.tar"), 2).stderr
    assert "no Ferry database" in code(ferry("--data-dir", tmp_path / "missing", "app", "list"), 2).stderr
    assert "does not exist" in code(ferry("verify", tmp_path / "missing.tar"), 2).stderr
    assert "needs a passphrase" in code(ferry("keygen", "k", "--out-dir", tmp_path), 2).stderr
    assert "needs --data-dir" in code(ferry("init"), 2).stderr
    bad = tmp_path / "bad.toml"
    bad.write_text('data_dir = "d"\n[gateway]\nallow_public_backend = true\n')
    assert "unknown setting" in code(ferry("--config", bad, "app", "list"), 2).stderr
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    assert "--password-stdin" in code(ferry("--data-dir", data, "admin", "create-user", "bob", "--role", "admin"), 2).stderr
    short = ferry("--data-dir", data, "admin", "create-user", "bob", "--role", "admin", "--password-stdin", input="short\n")
    assert "at least 12" in code(short, 2).stderr
    assert code(ferry("--data-dir", data, "admin", "create-user", "bob", "--role", "root", "--password-stdin",
                      input="long-enough-password\n"), 2).returncode == 2
    assert "invalid choice" in code(ferry("--data-dir", data, "app", "create", "x", "--environment", "nowhere"), 2).stderr


def test_init_creates_a_private_installation_and_is_repeatable(tmp_path: Path) -> None:
    data = tmp_path / "data"
    first = ok(ferry("init", "--data-dir", data))
    assert "(created)" in first.stdout
    assert oct((data / "ferry.toml").stat().st_mode & 0o777) == "0o600"
    assert oct(data.stat().st_mode & 0o777) == "0o700"
    assert oct((data / "ferry.db").stat().st_mode & 0o777) == "0o600"
    assert oct((data / "secrets").stat().st_mode & 0o777) == "0o700"
    assert oct((data / "trust").stat().st_mode & 0o777) == "0o755"
    for sub in ("inbox", "store/sha256", "store/tmp"):
        assert (data / sub).is_dir(), sub
    (data / "ferry.toml").write_text((data / "ferry.toml").read_text().replace("port = 8750", "port = 8751"))
    assert "(kept)" in ok(ferry("init", "--data-dir", data)).stdout
    assert load_settings(data_dir=data).server.port == 8751, "init never overwrites an existing configuration"


# --- connected side -----------------------------------------------------------------------------------


def test_keygen_pack_inspect_sign_and_standalone_verify(tmp_path: Path) -> None:
    ws = make_workspace(tmp_path)
    keys, out, trust = tmp_path / "keys", tmp_path / "out", tmp_path / "trust"
    pass_file = tmp_path / "publisher.pass"
    pass_file.write_text("publisher passphrase\n")
    os.chmod(pass_file, 0o600)
    created = ok(ferry("keygen", "publisher", "--out-dir", keys, "--passphrase-file", pass_file))
    publisher_id = re.search(r"Key id\s+([0-9a-f]{64})", created.stdout).group(1)
    ok(ferry("keygen", "reviewer", "--out-dir", keys, env={"FERRY_KEY_PASSPHRASE": "reviewer passphrase"}))
    assert "ENCRYPTED PRIVATE KEY" in (keys / "publisher.key").read_text()
    assert oct((keys / "publisher.key").stat().st_mode & 0o777) == "0o600"
    assert "refusing to overwrite" in code(ferry("keygen", "publisher", "--out-dir", keys, "--no-passphrase"), 2).stderr

    spec = ws.spec()
    assert "encrypted" in code(ferry("pack", spec, "--key", keys / "publisher.key", "--out", out), 2).stderr
    packed = json.loads(ok(ferry("pack", spec, "--key", keys / "publisher.key", "--passphrase-file", pass_file,
                                 "--out", out, "--created-at", CREATED_AT, "--json")).stdout)
    bundle = Path(packed["bundle_path"])
    assert bundle.name == "tiny-model-1.0.0.ferry.tar" and packed["key_id"] == publisher_id
    assert (out / "tiny-model-1.0.0.ferry.tar.sha256").is_file() and (out / "tiny-model-1.0.0.review.md").is_file()

    inspected = ok(ferry("inspect", bundle))
    assert packed["bundle_id"] in inspected.stdout and "Nothing was verified" in inspected.stdout
    info = json.loads(ok(ferry("inspect", bundle, "--json")).stdout)
    assert info["verified"] is False and info["signatures"] == [publisher_id]
    assert info["manifest"]["bundle"]["name"] == "tiny-model"

    untrusted = code(ferry("verify", bundle), 1)
    assert "no trust store given" in untrusted.stderr and untrusted.stdout.startswith("REJECTED")
    ok(ferry("trust", "add", keys / "publisher.pub.pem", "--name", "Publisher", "--role", "publisher",
             "--trust-dir", trust, "--expect-fingerprint", publisher_id[:16]))
    accepted = ok(ferry("verify", bundle, "--trust-dir", trust))
    assert accepted.stdout.startswith("ACCEPTED") and "Not recorded" in accepted.stdout
    two_person = code(ferry("verify", bundle, "--trust-dir", trust, "--require-role", "publisher",
                            "--require-role", "reviewer"), 1)
    assert "signatures.roles" in two_person.stdout

    reviewer_env = {"FERRY_KEY_PASSPHRASE": "reviewer passphrase"}
    signed = ok(ferry("sign", bundle, "--key", keys / "reviewer.key", env=reviewer_env))
    assert packed["bundle_id"] in signed.stdout and "sidecar updated" in signed.stdout
    assert "already signed" in code(ferry("sign", bundle, "--key", keys / "reviewer.key", env=reviewer_env), 2).stderr
    ok(ferry("trust", "add", keys / "reviewer.pub.pem", "--name", "Reviewer", "--role", "reviewer", "--trust-dir", trust))
    report = json.loads(ok(ferry("verify", bundle, "--trust-dir", trust, "--require-role", "publisher",
                                 "--require-role", "reviewer", "--json")).stdout)
    assert report["verdict"] == "accepted" and len(report["signatures"]) == 2

    tampered = code(ferry("verify", _tamper(bundle, tmp_path / "tampered.ferry.tar"), "--trust-dir", trust), 1)
    assert "artifact.digest" in tampered.stdout and "SHA-256" in tampered.stdout
    refusal = code(ferry("sign", tmp_path / "tampered.ferry.tar", "--key", keys / "reviewer.key", env=reviewer_env), 1)
    assert "refusing to countersign" in refusal.stderr

    ws.add_source("weights.pkl", PICKLE_PROTO4)
    pickled = ws.spec([{"source": "src/weights.pkl", "path": "models/weights.pkl", "kind": "model",
                        "model": {"name": "pickled", "license": "MIT"}}], spec_name="pickled.toml")
    refused = code(ferry("pack", pickled, "--key", keys / "publisher.key", "--passphrase-file", pass_file,
                         "--out", tmp_path / "out2"), 2)
    assert "refusing to pack" in refused.stderr


# --- disconnected side ----------------------------------------------------------------------------------


@pytest.fixture
def host(tmp_path: Path):
    """An initialised installation that trusts the test workspace's publisher, with the bundle imported."""
    setup = bundle_setup(tmp_path)
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    pem = tmp_path / "publisher.pub.pem"
    pem.write_bytes(setup.workspace.publisher.pem)
    ok(ferry("--data-dir", data, "trust", "add", pem, "--name", "Acme build", "--role", "publisher"))
    imported = json.loads(ok(ferry("--data-dir", data, "import", setup.bundle, "--json")).stdout)
    digest = next(a["actual_sha256"] for a in imported["report"]["artifacts"] if a["kind"] == "model")
    return {"setup": setup, "data": data, "D": ["--data-dir", data], "digest": digest, "bundle_id": imported["bundle_id"]}


def test_trust_admin_import_and_apps(host: dict[str, Any], tmp_path: Path) -> None:
    D, setup = host["D"], host["setup"]
    trust = json.loads(ok(ferry(*D, "trust", "list", "--json")).stdout)
    assert [(i["name"], i["status"]) for i in trust["items"]] == [("Acme build", "active")]
    assert "Acme build" in ok(ferry(*D, "trust", "list")).stdout

    ok(ferry(*D, "admin", "create-user", "alice", "--role", "admin", "--password-stdin", input="alice-password-1234\n"))
    assert "already exists" in code(ferry(*D, "admin", "create-user", "alice", "--role", "auditor", "--password-stdin",
                                          input="another-password-1\n"), 2).stderr

    again = ok(ferry(*D, "import", setup.bundle))
    assert again.stdout.startswith("ACCEPTED") and "Already imported" in again.stdout
    rejected = code(ferry(*D, "import", _tamper(setup.bundle, tmp_path / "bad.ferry.tar")), 1)
    assert "artifact.digest" in rejected.stdout and "Nothing was imported" in rejected.stdout
    recorded = ok(ferry(*D, "verify", setup.bundle))
    assert "Recorded in the verification history" in recorded.stdout

    ok(ferry(*D, "app", "create", "bot", "--environment", "pilot", "--description", "test bot"))
    issued = ok(ferry(*D, "app", "key", "bot"))
    key = issued.stdout.strip()
    assert re.fullmatch(r"fyk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", key) and "only time" in issued.stderr
    listed = json.loads(ok(ferry(*D, "app", "list", "--json")).stdout)["items"]
    assert [(a["name"], a["environment"], len(a["keys"])) for a in listed] == [("bot", "pilot", 1)]
    key_id = key.split("_")[1]
    assert "Revoked API key" in ok(ferry(*D, "app", "revoke-key", key_id)).stdout
    assert "already revoked" in code(ferry(*D, "app", "revoke-key", key_id), 2).stderr

    revoked = ok(ferry(*D, "trust", "revoke", setup.workspace.publisher.key_id[:12], "--reason", "rotated"))
    assert "Revoked key" in revoked.stdout
    assert code(ferry(*D, "verify", setup.bundle), 1).stdout.startswith("REJECTED"), "a revoked key no longer counts"

    user = getpass.getuser()
    by_action = {}
    for event in _events(host["data"]):
        by_action.setdefault(event["action"], []).append(event)
    for action in ("trust.add", "trust.revoke", "admin.user_create", "bundle.import", "bundle.verify",
                   "principal.create", "api_key.create", "api_key.revoke"):
        assert by_action.get(action), action
        assert all(e["actor_type"] == "cli" and e["actor_id"] == user for e in by_action[action]), action
    assert key.split("_", 2)[2] not in json.dumps([dict(e) for e in _events(host["data"])])


def test_backends_routes_and_policy(host: dict[str, Any], tmp_path: Path) -> None:
    D, data, digest = host["D"], host["data"], host["digest"]
    settings = load_settings(data_dir=data)
    with FakeUpstream() as upstream:
        upstream.model_path = str(settings.store_dir / "sha256" / digest)
        token = write_token(settings, "llama", upstream.token)
        added = ok(ferry(*D, "backend", "add", "llama", "--kind", "llamacpp", "--url", upstream.base_url,
                         "--token-file", token))
        assert "with a bearer token" in added.stdout and upstream.token not in added.stdout
        checked = ok(ferry(*D, "backend", "check", "llama"))
        assert "Backend llama: up" in checked.stdout and f"store file sha256:{digest}" in checked.stdout
        assert "up" in ok(ferry(*D, "backend", "list")).stdout
        route = ok(ferry(*D, "route", "add", "tiny", "--backend", "llama", "--upstream-model", "fake-alias",
                         "--artifact", digest))
        assert "provenance verified" in route.stdout
        routes = json.loads(ok(ferry(*D, "route", "list", "--json")).stdout)["items"]
        assert [(r["model"], r["provenance"]["state"], r["available"]) for r in routes] == [("tiny", "verified", True)]
        upstream.health_status = 503
        assert "loading" in code(ferry(*D, "backend", "check", "llama"), 1).stdout
    assert "public address" in code(ferry(*D, "backend", "add", "pub", "--kind", "openai", "--url", "http://8.8.8.8"),
                                    2).stderr

    ok(ferry(*D, "app", "create", "bot"))
    good = tmp_path / "policy.json"
    good.write_text(json.dumps({"schema": "ferry.dev/access-policy/v1", "description": "bot may chat with tiny",
                                "rules": [{"id": "bot-tiny", "effect": "allow", "principals": ["app:bot"],
                                           "actions": ["chat.completions"], "models": ["tiny"]}]}))
    bad = tmp_path / "bad-policy.json"
    bad.write_text(json.dumps({"schema": "ferry.dev/access-policy/v1", "rules": [{"id": "x", "effect": "allow"}]}))
    assert ok(ferry(*D, "policy", "validate", good)).stdout.strip().endswith("valid")
    assert "invalid" in code(ferry(*D, "policy", "validate", bad), 1).stdout
    assert "nothing was activated" in code(ferry(*D, "policy", "activate", bad), 1).stderr
    assert "Activated policy version 1" in ok(ferry(*D, "policy", "activate", good, "--comment", "pilot")).stdout
    shown = json.loads(ok(ferry(*D, "policy", "show", "--json")).stdout)
    assert shown["active"]["version"] == 1 and shown["active"]["comment"] == "pilot"
    assert ok(ferry(*D, "policy", "explain", "--app", "bot", "--model", "tiny")).stdout.startswith("ALLOW")
    assert code(ferry(*D, "policy", "explain", "--app", "bot", "--model", "other"), 1).stdout.startswith("DENY")
    assert "no rule allows" in ferry(*D, "policy", "explain", "--app", "bot", "--model", "other").stdout
    nan = tmp_path / "nan.json"
    nan.write_text('{"schema": NaN}')
    assert "not valid JSON" in code(ferry(*D, "policy", "validate", nan), 2).stderr


def test_runtime_llamacpp_registers_and_prints_an_offline_command(host: dict[str, Any]) -> None:
    D, data, digest = host["D"], host["data"], host["digest"]
    settings = load_settings(data_dir=data)
    result = ok(ferry(*D, "runtime", "llamacpp", "tiny-model", "--port", "18080", "--ctx-size", "2048", "--print-only"))
    token = settings.secrets_dir / "llamacpp-tiny-model.token"
    store_file = settings.store_dir / "sha256" / digest
    assert shlex.split(result.stdout.strip()) == [
        "llama-server", "-m", str(store_file), "--alias", "tiny-model", "--host", "127.0.0.1", "--port", "18080",
        "--api-key-file", str(token), "--offline", "--no-webui", "-c", "2048"]
    assert oct(token.stat().st_mode & 0o777) == "0o600"
    secret = token.read_text().strip()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", secret) and secret not in result.stdout + result.stderr
    assert "created: token file, backend, route" in result.stderr
    again = ok(ferry(*D, "runtime", "llamacpp", "tiny-model", "--port", "18080", "--print-only"))
    assert "already registered" in again.stderr and token.read_text().strip() == secret
    backends = json.loads(ok(ferry(*D, "backend", "list", "--json")).stdout)["items"]
    assert [(b["name"], b["kind"], b["base_url"], b["has_token"]) for b in backends] == [
        ("llamacpp-tiny-model", "llamacpp", "http://127.0.0.1:18080", True)]
    routes = json.loads(ok(ferry(*D, "route", "list", "--json")).stdout)["items"]
    assert [(r["model"], r["artifact_digest"], r["require_verified"]) for r in routes] == [("tiny-model", digest, True)]
    moved = ok(ferry(*D, "runtime", "llamacpp", "tiny-model", "--port", "18081", "--print-only"))
    assert "--port 18081" in moved.stdout
    assert json.loads(ok(ferry(*D, "backend", "list", "--json")).stdout)["items"][0]["base_url"] == "http://127.0.0.1:18081"
    missing = code(ferry(*D, "runtime", "llamacpp", "tiny-model", "--binary", "definitely-not-installed-llama"), 2)
    assert "not found on PATH" in missing.stderr
    assert "no imported model" in code(ferry(*D, "runtime", "llamacpp", "nope", "--print-only"), 2).stderr
    actions = [(e["action"], e["actor_type"]) for e in _events(data) if e["action"].startswith(("backend.", "route."))]
    assert actions == [("backend.create", "cli"), ("route.create", "cli"), ("backend.update", "cli")]


def test_audit_store_evidence_and_doctor(host: dict[str, Any], tmp_path: Path) -> None:
    D, data, digest = host["D"], host["data"], host["digest"]
    assert "Audit chain intact" in ok(ferry(*D, "audit", "verify")).stdout
    ok(ferry("keygen", "site", "--out-dir", tmp_path / "site", "--no-passphrase"))
    checkpoint = tmp_path / "checkpoint.json"
    ok(ferry(*D, "audit", "checkpoint", "--sign-key", tmp_path / "site" / "site.key", "--out", checkpoint))
    cp = json.loads(checkpoint.read_text())
    assert cp["schema"] == "ferry.dev/audit-checkpoint/v1" and cp["signature"]["alg"] == "ed25519"
    confirmed = ok(ferry(*D, "audit", "verify", "--checkpoint", checkpoint, "--checkpoint-key",
                         tmp_path / "site" / "site.pub.pem"))
    assert "checkpoint confirmed" in confirmed.stdout and "Checkpoint signature: valid" in confirmed.stdout
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps({**cp, "hash": "0" * 64}))
    assert "BROKEN" in code(ferry(*D, "audit", "verify", "--checkpoint", forged), 1).stdout

    export = tmp_path / "audit.ndjson"
    exported = ok(ferry(*D, "audit", "export", "--out", export))
    lines = [json.loads(line) for line in export.read_text().splitlines()]
    assert [e["seq"] for e in lines] == list(range(1, len(lines) + 1)) and "exported" in exported.stderr
    streamed = ok(ferry(*D, "audit", "export")).stdout.splitlines()
    assert len(streamed) == len(lines) + 1, "the first export is itself recorded"

    assert "OK" in ok(ferry(*D, "store", "verify")).stdout
    store_file = data / "store" / "sha256" / digest
    os.chmod(store_file, 0o644)
    with open(store_file, "r+b") as fh:
        fh.seek(10)
        fh.write(b"\x00\x01")
    broken = code(ferry(*D, "store", "verify"), 1)
    assert f"mismatch  {digest}" in broken.stdout

    evidence_file = tmp_path / "evidence.json"
    ok(ferry(*D, "evidence", "--format", "json", "--out", evidence_file))
    evidence = json.loads(evidence_file.read_text())
    assert evidence["bundles"][0]["bundle_id"] == host["bundle_id"] and "not a compliance" in evidence["statement"]
    assert ok(ferry(*D, "evidence")).stdout.startswith("# Ferry evidence report")

    doctor = ok(ferry(*D, "doctor"))
    assert "[PASS] permissions.data_dir" in doctor.stdout and "Network inventory:" in doctor.stdout
    report = json.loads(ok(ferry(*D, "doctor", "--json")).stdout)
    assert {c["id"] for c in report["checks"]} >= {"tls", "console.assets", "telemetry.packages", "audit.chain"}
    assert report["network_inventory"][0]["component"] == "gateway listener (ferry serve)"
    leaky = write_token(load_settings(data_dir=data), "leaky", "not-so-secret", mode=0o644)
    failing = code(ferry(*D, "doctor"), 1)
    assert "[FAIL] permissions.secrets" in failing.stdout and "not-so-secret" not in failing.stdout
    os.chmod(leaky, 0o600)

    user = getpass.getuser()
    actions = [(e["action"], e["outcome"], e["actor_id"]) for e in _events(data)
               if e["action"].startswith(("audit.", "store."))]
    assert actions[:4] == [("audit.verify", "success", user), ("audit.checkpoint", "success", user),
                           ("audit.verify", "success", user), ("audit.verify", "failure", user)]
    assert ("store.verify", "failure", user) in actions


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_serve_starts_answers_and_stops(tmp_path: Path) -> None:
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    port = _free_port()
    proc = subprocess.Popen([PY, "-m", "ferry.cli", "--data-dir", str(data), "serve", "--port", str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env(),
                            stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        response = None
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=2) as client:
            while time.monotonic() < deadline and proc.poll() is None:
                try:
                    response = client.get("/healthz")
                    break
                except httpx.TransportError:
                    time.sleep(0.1)
            assert response is not None and response.status_code == 200, proc.stderr.read() if proc.poll() else ""
            assert response.json() == {"status": "ok"}
            assert response.headers["content-security-policy"] == CSP
            assert "server" not in response.headers, "the server does not advertise itself"
            assert client.get("/").headers["content-type"].startswith("text/html")
            assert client.get("/api/auth/me").status_code == 401
            assert client.get("/docs").status_code == 404
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    log = proc.stderr.read()
    # uvicorn shuts down gracefully, then re-raises the SIGTERM it caught so the parent sees it.
    assert proc.returncode in (0, -signal.SIGTERM), log
    assert "Application shutdown complete" in log
    starts = [e for e in _events(data) if e["action"] == "system.start"]
    assert len(starts) == 1 and json.loads(starts[0]["details"])["port"] == port


def test_preflight_and_rehearse_are_wired_in() -> None:
    from ferry import cli_offline

    parser = build_parser()
    assert parser.parse_args(["rehearse", "b.ferry.tar", "--trust-dir", "t"]).func is cli_offline.cmd_rehearse
    assert parser.parse_args(["preflight", "--", "true"]).func is cli_offline.cmd_preflight
    missing = ferry("preflight")
    assert missing.returncode == 2 and "give the launch command after --" in missing.stderr


# --- quality pass: serve proxy headers, checkpoint ordering, exit codes, progress, demo, verify overrides -------


def _captured_serve_config(monkeypatch: pytest.MonkeyPatch, data: Path) -> Any:
    """Run `ferry serve` in-process with uvicorn's Server.run stubbed out; return the uvicorn Config it built."""
    import uvicorn

    from ferry import cli

    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, *a, **k: captured.setdefault("config", self.config))
    cli.main(["--data-dir", str(data), "serve"])
    return captured["config"]


def _failed_logins_from_loopback(config: Any, count: int) -> list[int]:
    from helpers_app import CSRF as CSRF_HEADERS
    from starlette.testclient import TestClient

    config.load()  # what uvicorn does before serving: wraps the app in ProxyHeadersMiddleware when enabled
    statuses = []
    with TestClient(config.loaded_app, client=("127.0.0.1", 50000)) as client:
        for i in range(count):
            response = client.post("/api/auth/login", json={"username": f"spray{i}", "password": "wrong-password-1"},
                                   headers={**CSRF_HEADERS, "X-Forwarded-For": f"203.0.113.{i + 1}",
                                            "X-Forwarded-Proto": "https"})
            statuses.append(response.status_code)
    return statuses


def _login_client_ips(data: Path) -> set[Any]:
    return {json.loads(e["details"]).get("client_ip") for e in _events(data) if e["action"] == "auth.login"}


def test_serve_ignores_forwarded_headers_unless_a_proxy_is_trusted(tmp_path: Path,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    config = _captured_serve_config(monkeypatch, data)
    assert config.proxy_headers is False and config.forwarded_allow_ips == []
    statuses = _failed_logins_from_loopback(config, 25)
    assert 429 in statuses, f"a new X-Forwarded-For per request must not dodge the per-address limit: {statuses}"
    assert _login_client_ips(data) == {"127.0.0.1"}, "the audited client_ip is the TCP peer, not a client header"

    # An explicitly trusted proxy (here: one on the same host) is believed.
    proxied = tmp_path / "proxied"
    ok(ferry("init", "--data-dir", proxied))
    toml = proxied / "ferry.toml"
    toml.write_text(toml.read_text().replace("trusted_proxies = []", 'trusted_proxies = ["127.0.0.1", "10.0.0.0/8"]'))
    config = _captured_serve_config(monkeypatch, proxied)
    assert config.proxy_headers is True and config.forwarded_allow_ips == ["127.0.0.1", "10.0.0.0/8"]
    _failed_logins_from_loopback(config, 1)
    assert _login_client_ips(proxied) == {"203.0.113.1"}

    toml.write_text(toml.read_text().replace('["127.0.0.1", "10.0.0.0/8"]', '["proxy.local"]'))
    refused = code(ferry("--data-dir", proxied, "serve"), 2)
    assert "trusted_proxies" in refused.stderr and "proxy.local" in refused.stderr


def test_a_checkpoint_that_cannot_be_written_is_not_recorded(tmp_path: Path) -> None:
    from ferry.db import Database
    from ferry.evidence import build_evidence

    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    readonly = tmp_path / "ro"
    readonly.mkdir()
    os.chmod(readonly, 0o500)
    try:
        failed = code(ferry("--data-dir", data, "audit", "checkpoint", "--out", readonly / "cp.json"), 2)
    finally:
        os.chmod(readonly, 0o700)
    assert not (readonly / "cp.json").exists() and "ferry: error" in failed.stderr
    assert not [e for e in _events(data) if e["action"] == "audit.checkpoint"]
    settings = load_settings(data_dir=data)
    with Database(settings.db_path).session() as conn:
        assert build_evidence(settings, conn)["audit"]["last_checkpoint"] is None

    streamed = json.loads(ok(ferry("--data-dir", data, "audit", "checkpoint")).stdout)
    recorded = [json.loads(e["details"]) for e in _events(data) if e["action"] == "audit.checkpoint"]
    assert [(d["seq"], d["out"]) for d in recorded] == [(streamed["seq"], "stdout")]


def _flip_member_byte(archive: Path, name: str, target: Path) -> Path:
    import tarfile

    data = bytearray(archive.read_bytes())
    with tarfile.open(archive) as tf:
        member = tf.getmember(name)
    data[member.offset_data + member.size // 2] ^= 0x01
    target.write_bytes(bytes(data))
    return target


def test_integrity_refusals_exit_1_and_io_errors_exit_2(tmp_path: Path) -> None:
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    backup = tmp_path / "backup.tar"
    ok(ferry("--data-dir", data, "backup", "--out", backup))
    tampered = _flip_member_byte(backup, "ferry.db", tmp_path / "tampered.tar")
    refused = code(ferry("restore", tampered, "--data-dir", tmp_path / "r2"), 1)
    assert "ferry.db" in refused.stderr and "does not match the manifest" in refused.stderr
    assert "does not exist" in code(ferry("restore", tmp_path / "missing.tar", "--data-dir", tmp_path / "r3"), 2).stderr
    ok(ferry("restore", backup, "--data-dir", tmp_path / "r4"))

    ok(ferry("keygen", "signer", "--out-dir", tmp_path / "keys", "--no-passphrase"))
    mismatch = code(ferry("trust", "add", tmp_path / "keys" / "signer.pub.pem", "--name", "S", "--role", "publisher",
                          "--trust-dir", tmp_path / "trust", "--expect-fingerprint", "0" * 16), 1)
    assert "fingerprint mismatch" in mismatch.stderr
    short = code(ferry("trust", "add", tmp_path / "keys" / "signer.pub.pem", "--name", "S", "--role", "publisher",
                       "--trust-dir", tmp_path / "trust", "--expect-fingerprint", "0" * 4), 2)
    assert "at least" in short.stderr


@pytest.fixture
def standalone_bundle(tmp_path: Path) -> tuple[Path, Path]:
    from ferry.trust import add_key

    setup = bundle_setup(tmp_path)
    trust = tmp_path / "other-trust"
    add_key(trust, setup.workspace.publisher.pem, name="Vendor", roles=["publisher"])
    return setup.bundle, trust


def test_verify_shows_hashing_progress_only_on_a_terminal(standalone_bundle: tuple[Path, Path],
                                                          capsys: pytest.CaptureFixture[str],
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from ferry import cli

    bundle, trust = standalone_bundle
    assert cli.main(["verify", str(bundle), "--trust-dir", str(trust)]) == 0
    plain = capsys.readouterr()
    assert plain.err == ""

    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert cli.main(["verify", str(bundle), "--trust-dir", str(trust)]) == 0
    tty = capsys.readouterr()
    assert tty.out == plain.out, "progress never changes stdout"
    assert re.search(r"\rhashing \d+\.\d / \d+\.\d GiB \(100%\)\n", tty.err), repr(tty.err)

    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert cli.main(["verify", str(bundle), "--trust-dir", str(trust), "--json"]) == 0
    assert capsys.readouterr().err == "", "--json output stays machine-readable"


def test_progress_meter_throttles_and_ends_its_line() -> None:
    import io

    from ferry.cli import _ProgressMeter

    stream = io.StringIO()
    meter = _ProgressMeter("hashing", stream)
    meter(0, 0)
    assert stream.getvalue() == "", "nothing to hash, nothing shown"
    for done in range(0, 2**30, 2**20):
        meter(done, 2**30)
    assert stream.getvalue().count("\r") == 1, "at most one update per interval"
    meter(2**30, 2**30)
    assert stream.getvalue().endswith("\rhashing 1.0 / 1.0 GiB (100%)\n")
    meter.close()
    assert stream.getvalue().count("\n") == 1


DEMO = Path(__file__).resolve().parent.parent / "demo" / "run-demo.sh"


def test_demo_expect_fail_accepts_only_a_rejection() -> None:
    func = re.search(r"^expect_fail\(\) \{\n.*?^\}\n", DEMO.read_text(), re.MULTILINE | re.DOTALL)
    assert func, "expect_fail not found in demo/run-demo.sh"

    def run(inner: str) -> subprocess.CompletedProcess[str]:
        script = f"set -euo pipefail\n{func.group(0)}expect_fail sh -c '{inner}'\necho after\n"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, check=False)

    rejected = run("exit 1")
    assert rejected.returncode == 0 and "(rejected as expected)" in rejected.stdout and "after" in rejected.stdout
    for inner, rc in (("exit 2", 2), ("exit 0", 0)):
        result = run(inner)
        assert result.returncode != 0 and f"UNEXPECTED: exit {rc}" in result.stdout, inner


def test_demo_two_signer_edit_matches_the_default_config(tmp_path: Path) -> None:
    from ferry.config import default_config_toml

    assert 'required_roles = ["publisher"]' in default_config_toml(tmp_path)
    edit = re.search(r'"\$PY" - "\$DATA/ferry.toml" <<\'PYEOF\'\n(.*?)^PYEOF$', DEMO.read_text(),
                     re.MULTILINE | re.DOTALL)
    assert edit, "the step-8 config edit was not found in demo/run-demo.sh"
    script = tmp_path / "edit.py"
    script.write_text(edit.group(1))
    data = tmp_path / "data"
    ok(ferry("init", "--data-dir", data))
    subprocess.run([PY, str(script), str(data / "ferry.toml")], check=True, timeout=60, env=_env())
    assert load_settings(data_dir=data).imports.required_roles == ("publisher", "reviewer")
    changed = tmp_path / "changed.toml"
    changed.write_text(default_config_toml(data).replace('required_roles = ["publisher"]',
                                                         'required_roles = [ "publisher" ]'))
    failed = subprocess.run([PY, str(script), str(changed)], capture_output=True, text=True, timeout=60, env=_env(),
                            check=False)
    assert failed.returncode != 0 and "could not set required_roles" in failed.stderr


def _verification_rows(data: Path) -> int:
    conn = sqlite3.connect(data / "ferry.db")
    try:
        return int(conn.execute("SELECT COUNT(*) FROM verifications").fetchone()[0])
    finally:
        conn.close()


def test_verify_overrides_on_a_host_are_not_recorded_as_the_host_verdict(
        standalone_bundle: tuple[Path, Path], tmp_path: Path) -> None:
    bundle, other = standalone_bundle
    data = tmp_path / "host"
    ok(ferry("init", "--data-dir", data))  # the host trusts nobody yet

    accepted = ok(ferry("--data-dir", data, "verify", bundle, "--trust-dir", other))
    assert accepted.stdout.startswith("ACCEPTED")
    assert "Not recorded in the verification history: --trust-dir replaced the host's import policy" in accepted.stdout
    assert _verification_rows(data) == 0, "an overridden verdict must not reach the inbox or the evidence report"
    events = [e for e in _events(data) if e["action"] == "bundle.verify"]
    assert len(events) == 1 and events[0]["outcome"] == "accepted"
    details = json.loads(events[0]["details"])
    assert details["overrides"] == ["trust_dir"] and details["trust_dir"] == str(other.resolve())
    assert details["host_verdict"] is False

    roles = json.loads(ok(ferry("--data-dir", data, "verify", bundle, "--trust-dir", other,
                                "--require-role", "publisher", "--json")).stdout)
    assert roles["verdict"] == "accepted" and _verification_rows(data) == 0
    last = json.loads([e for e in _events(data) if e["action"] == "bundle.verify"][-1]["details"])
    assert last["overrides"] == ["required_roles", "trust_dir"] and last["required_roles"] == ["publisher"]

    host = code(ferry("--data-dir", data, "verify", bundle), 1)
    assert host.stdout.startswith("REJECTED") and "Recorded in the verification history" in host.stdout
    assert _verification_rows(data) == 1, "without overrides the host's own verdict is recorded"
