"""Tests for the production-hardening changes of 2026-10-29: resilient audit
readers, capped policy warnings, the safetensors header-less pickle scan,
preflight URL validation, and Linux isolation fallbacks (simulated: there is no
Linux host in this environment, so these exercise the selection logic only).
"""

from __future__ import annotations

import io
import json
import struct
from types import SimpleNamespace

import pytest

from ferry import audit, policy, sandbox
from ferry.cli_offline import main as offline_main
from ferry.formats import detect_format
from tests.helpers_bundle import default_st_tensors, safetensors_bytes


# --- audit readers ------------------------------------------------------------------


def _append(conn, n: int = 3) -> None:
    for i in range(n):
        audit.append_event(conn, actor_type="cli", actor_id="t", action="test.event", resource=f"r{i}",
                           outcome="success", details={"n": i})


def test_readers_survive_tampered_details_and_the_chain_still_reports_it(conn):
    _append(conn)
    conn.execute("UPDATE audit_events SET details = 'not json' WHERE seq = 2")
    events = audit.query_events(conn, limit=10)
    bad = next(e for e in events if e["seq"] == 2)
    assert bad["integrity"] == "details_unparseable"
    assert bad["details"] == {"_unreadable": True, "raw": "not json"}
    assert "integrity" not in next(e for e in events if e["seq"] == 1)
    assert audit.get_event(conn, 2)["integrity"] == "details_unparseable"
    out = io.StringIO()
    assert audit.export_jsonl(conn, out) == 3
    exported = [json.loads(line) for line in out.getvalue().splitlines()]
    assert exported[1]["integrity"] == "details_unparseable"
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 2


def test_lenient_reader_bounds_the_raw_text(conn):
    _append(conn, 1)
    conn.execute("UPDATE audit_events SET details = ? WHERE seq = 1", ("x" * 5000,))
    assert len(audit.get_event(conn, 1)["details"]["raw"]) == 1024


# --- policy warnings ----------------------------------------------------------------


def test_policy_warnings_are_capped():
    rules = [{"id": f"r{i}", "effect": "allow", "principals": [f"app:ghost{i}"], "actions": ["chat.completions"],
              "models": [f"m{i}"]} for i in range(policy.MAX_WARNINGS // 2 + 50)]
    doc = {"schema": "ferry.dev/access-policy/v1", "rules": rules}
    result = policy.validate_policy(doc, known_apps=[], known_models=[])
    assert result["valid"] is True
    assert len(result["warnings"]) == policy.MAX_WARNINGS + 1
    assert "more warning(s) not shown" in result["warnings"][-1]["message"]
    assert result["warnings"][-1]["rule_id"] is None


def test_policy_warnings_below_the_cap_are_untouched():
    doc = {"schema": "ferry.dev/access-policy/v1",
           "rules": [{"id": "a", "effect": "allow", "principals": ["app:x"], "actions": ["*"], "models": ["m"]}]}
    result = policy.validate_policy(doc, known_apps=[], known_models=[])
    assert len(result["warnings"]) == 2 and all(w["rule_id"] == "a" for w in result["warnings"])


# --- bounded list endpoints ---------------------------------------------------------------


def test_list_endpoints_honour_limit(data_dir):
    from ferry import auth
    from tests.helpers_app import app_env

    with app_env(data_dir) as env:
        with env.conn() as c:
            for i in range(3):
                auth.create_principal(c, f"app{i}", environment="test", actor_type="cli", actor_id="t")
        assert len(env.get("/api/apps?limit=2").json()["items"]) == 2
        assert len(env.get("/api/apps").json()["items"]) == 3
        assert env.get("/api/apps?limit=0").status_code == 422
        assert env.get("/api/bundles?limit=5001").status_code == 422
        assert env.get("/api/bundles?limit=1").status_code == 200
        assert env.get("/api/models?limit=1").status_code == 200


# --- safetensors header-less pickle scan -------------------------------------------------


def test_safetensors_branch_runs_the_headerless_pickle_scan(monkeypatch):
    data = safetensors_bytes()
    info = detect_format(io.BytesIO(data), len(data), "model.safetensors")
    assert info.format == "safetensors" and info.ok
    monkeypatch.setattr("ferry.formats._headerless_pickle", lambda fh, size: True)
    info = detect_format(io.BytesIO(data), len(data), "model.safetensors")
    assert info.format == "pickle" and info.metadata["polyglot"] == "safetensors"


@pytest.mark.parametrize("header_len", [
    0x2E4E,  # bytes 'N' '.' form a complete tiny pickle (None, STOP) before the zero byte
    0x5454,  # byte 'T' is BINSTRING: its 4-byte length skips into the JSON header
    0x2828,  # two MARK opcodes, then 0x00
    4096,
])
def test_well_formed_safetensors_are_not_flagged_whatever_their_header_length(header_len):
    # A well-formed file whose JSON header is padded with spaces (allowed by the
    # format) to exactly `header_len` bytes, so the 8-byte length prefix takes the
    # interesting values.
    raw, header = b"", {}
    for name, (dtype, shape, blob) in default_st_tensors().items():
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [len(raw), len(raw) + len(blob)]}
        raw += blob
    text = json.dumps(header)
    assert len(text) <= header_len
    data = safetensors_bytes(header=text + " " * (header_len - len(text)), data=raw, pad=False)
    assert struct.unpack("<Q", data[:8])[0] == header_len
    info = detect_format(io.BytesIO(data), len(data), "model.safetensors")
    assert info.format == "safetensors" and info.ok, info.problems


# --- preflight URL validation -----------------------------------------------------------


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://127.0.0.1/x", "http://", "127.0.0.1:8080/health"])
def test_preflight_rejects_urls_that_are_not_http(capsys, url):
    code = offline_main(["preflight", "--ready-url", url, "--", "true"])
    assert code == 2
    assert "http:// or https://" in capsys.readouterr().err


# --- Linux isolation fallbacks (simulated) -------------------------------------------------


def _fake_run(failing: set[str]):
    """subprocess.run double: `failing` names candidates whose self-test must fail."""
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        if argv[0] == "unshare":
            key = "unshare-netns" if "--map-root-user" in argv else "unshare-netns-root"
        else:
            key = argv[0]
        rc = 1 if key in failing else 0
        err = "unshare: unshare failed: Operation not permitted\n" if rc else ""
        return SimpleNamespace(returncode=rc, stdout="", stderr=err)

    return run, calls


def _linux(monkeypatch, *, euid: int, tools: set[str]):
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: euid)
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: f"/usr/bin/{name}" if name in tools else None)


def test_blocked_user_namespaces_fall_back_to_bubblewrap(monkeypatch):
    _linux(monkeypatch, euid=1000, tools={"unshare", "ip", "bwrap"})
    run, calls = _fake_run({"unshare-netns"})
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "bwrap" and iso.available and iso.linux_namespace
    assert iso.tried == ("unshare-netns (exit 1: unshare: unshare failed: Operation not permitted)",)
    assert iso.wrap(["cmd", "arg"]) == ["bwrap", "--unshare-net", "--dev-bind", "/", "/", "--", "cmd", "arg"]
    assert [c[0] for c in calls] == ["unshare", "bwrap"]


def test_root_prefers_a_plain_network_namespace(monkeypatch):
    _linux(monkeypatch, euid=0, tools={"unshare", "ip", "bwrap"})
    run, calls = _fake_run(set())
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "unshare-netns-root" and "--map-root-user" not in iso.prefix
    assert iso.wrap(["x"])[:3] == ["unshare", "--net", "sh"]
    assert len(calls) == 1


def test_no_working_mechanism_fails_closed_and_names_what_was_tried(monkeypatch):
    _linux(monkeypatch, euid=1000, tools={"unshare", "ip", "bwrap"})
    run, _ = _fake_run({"unshare-netns", "bwrap"})
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "none" and not iso.available and not iso.linux_namespace
    assert iso.wrap(["x"]) == ["x"]
    assert "unshare-netns (" in iso.description and "bwrap (" in iso.description
    assert len(iso.tried) == 2


def test_self_test_exception_is_a_failure_not_a_crash(monkeypatch):
    _linux(monkeypatch, euid=1000, tools={"unshare", "ip"})

    def run(argv, **_kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(sandbox.subprocess, "run", run)
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "none" and "OSError" in iso.description


def test_macos_sandbox_exec_is_self_tested_too(monkeypatch):
    monkeypatch.setattr(sandbox.sys, "platform", "darwin")
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/sandbox-exec")
    run, calls = _fake_run({"sandbox-exec"})
    monkeypatch.setattr(sandbox.subprocess, "run", run)
    iso = sandbox.detect_isolation()
    assert iso.mechanism == "none" and iso.tried[0].startswith("sandbox-exec (exit 1")
    assert calls[0][:3] == ["sandbox-exec", "-p", sandbox.MACOS_PROFILE]
