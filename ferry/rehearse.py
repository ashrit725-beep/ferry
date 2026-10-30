"""Offline rehearsal on the connected side (`ferry rehearse`).

The best-documented failure when moving open-weight models into a disconnected
network is a bundle that is incomplete or still reaches for the network, found
only after a transfer that cost a full review cycle (docs/research/06). A
rehearsal catches that before the bundle is written to media:

1. import the bundle into a throwaway data directory with the same verification
   code the disconnected side runs;
2. start llama-server on each imported GGUF file inside a network sandbox
   (ferry.sandbox) and send one prompt (ferry.rehearse_runner);
3. produce a report that can travel with the transfer request.

The runtime's outbound connection attempts (macOS sandbox log, strace on Linux)
and network-failure lines in its output fail the rehearsal, as in `ferry
preflight`: in the sandbox such a call fails at once, behind an enclave firewall
that drops packets it can hang. Blocked DNS lookups carry no name and are noted.

A pass shows that this bundle, on this runtime build, served a completion with
egress blocked on this machine. It does not prove the same for other hardware,
another runtime build or another operating system.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import getpass
import json
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .config import ImportSettings, Settings
from .db import Database
from .preflight import collect_macos_denials, describe_attempts, egress_label
from .sandbox import detect_isolation
from .util import rfc3339

REPORT_VERSION = 1
DEFAULT_PROMPT = "Reply with one word: ready"
# llama.cpp fixed CVE-2026-27940, a GGUF loader overflow, in build b8146 (docs/research/03).
MIN_LLAMACPP_BUILD = 8146
_BUILD = re.compile(r"build\s+(\d+)")


def _as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return dict(vars(obj))


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no user database entry, e.g. in a minimal container
        return "unknown"


def llamacpp_build(binary: str) -> tuple[int | None, str]:
    """(build number, version line) from `llama-server --version`."""
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"could not run {binary} --version: {exc}"
    lines = (proc.stdout + "\n" + proc.stderr).splitlines()
    line = next((ln.strip() for ln in lines if "build" in ln and "version" in ln), "")
    match = _BUILD.search(line)
    return (int(match.group(1)) if match else None), line


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _imported_models(settings: Settings, database: Database, bundle_id: str) -> list[dict[str, Any]]:
    from .bundle import store

    with database.session() as conn:
        rows = conn.execute(
            "SELECT a.digest, a.model_name, a.format FROM bundle_artifacts ba"
            " JOIN artifacts a ON a.digest = ba.digest WHERE ba.bundle_id = ? AND a.kind = 'model'"
            " ORDER BY a.model_name",
            (bundle_id,),
        ).fetchall()
    return [
        {"name": r["model_name"], "digest": r["digest"], "format": r["format"],
         "path": str(store.path_for(settings, r["digest"]))}
        for r in rows
    ]


def rehearse(
    bundle: Path,
    *,
    trust_dir: Path,
    import_settings: ImportSettings | None = None,
    binary: str | None = None,
    prompt: str = DEFAULT_PROMPT,
    ctx_size: int = 2048,
    max_tokens: int = 16,
    min_build: int | None = MIN_LLAMACPP_BUILD,
    require_isolation: bool = True,
    load_timeout_s: float = 180.0,
) -> dict[str, Any]:
    """Run the rehearsal and return the report (see docs/design/v1-additions.md, A2)."""
    from .bundle.importer import import_bundle

    report: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "tool_version": __version__,
        "verdict": "fail",
        "bundle": Path(bundle).name,
        "bundle_id": None,
        "verification_verdict": None,
        "verification_errors": [],
        "isolation": None,
        "runtime": None,
        "models": [],
        "evidence_sources": [],
        "started_at": rfc3339(),
        "finished_at": None,
        "failures": [],
        "notes": [],
    }

    def finish() -> dict[str, Any]:
        report["finished_at"] = rfc3339()
        report["verdict"] = "fail" if report["failures"] else "pass"
        return report

    with tempfile.TemporaryDirectory(prefix="ferry-rehearse-") as tmp:
        tmpdir = Path(tmp)
        imports = dataclasses.replace(import_settings or ImportSettings(),
                                      trust_dir=str(Path(trust_dir).resolve()), inbox_dir=str(tmpdir / "inbox"))
        settings = Settings(data_dir=tmpdir / "data", imports=imports)
        database = Database(settings.db_path)
        database.init()

        # 1. Same verification and import path as the disconnected side.
        result = _as_dict(import_bundle(settings, database, Path(bundle), actor_type="cli", actor_id=_actor()))
        verification = _as_dict(result.get("report", result))
        report["bundle_id"] = verification.get("bundle_id")
        report["verification_verdict"] = verification.get("verdict")
        report["verification_errors"] = list(verification.get("errors") or [])
        if verification.get("verdict") != "accepted":
            report["failures"].append("the bundle failed verification, so no runtime was started")
            return finish()

        models = _imported_models(settings, database, report["bundle_id"])
        for m in models:
            if m["format"] != "gguf":
                report["notes"].append(f"{m['name']}: {m['format']} models are not rehearsed with llama-server")
        models = [m for m in models if m["format"] == "gguf"]
        if not models:
            report["failures"].append("the bundle contains no GGUF model that llama-server can rehearse")
            return finish()

        # 2. Runtime: present, and not a build with known GGUF loader vulnerabilities.
        binary = binary or shutil.which("llama-server")
        if not binary:
            report["failures"].append("llama-server was not found on PATH; install llama.cpp or pass --binary")
            return finish()
        build, version_line = llamacpp_build(binary)
        report["runtime"] = {"binary": binary, "build": build, "version": version_line, "build_info": None}
        if min_build is not None and (build is None or build < min_build):
            report["failures"].append(
                f"llama-server build {build if build is not None else 'unknown'} is older than the minimum b{min_build}"
            )
            return finish()

        # 3. Isolation.
        isolation = detect_isolation()
        report["isolation"] = {"mechanism": isolation.mechanism, "description": isolation.description,
                               "egress_blocked": None, "probe": None}
        if not isolation.available:
            message = "no network isolation is available on this host, so the rehearsal cannot show offline operation"
            if require_isolation:
                report["failures"].append(message)
                return finish()
            report["notes"].append(message)

        token_file = tmpdir / "runtime.token"
        token_file.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
        token_file.chmod(0o600)
        log_dir = tmpdir / "logs"
        log_dir.mkdir()
        strace = isolation.mechanism == "unshare-netns" and shutil.which("strace") is not None
        runner_args = {
            "binary": binary, "token_file": str(token_file), "log_dir": str(log_dir), "prompt": prompt,
            "max_tokens": max_tokens, "ctx_size": ctx_size, "load_timeout_s": load_timeout_s,
            "models": [{**m, "port": _free_port()} for m in models], "strace": strace,
        }
        command = isolation.wrap([sys.executable, "-I", "-m", "ferry.rehearse_runner", json.dumps(runner_args)])
        # Local time with one second of slack: `log show --start` takes local time.
        log_start = (_dt.datetime.now() - _dt.timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=load_timeout_s * len(models) + 300)
        except subprocess.TimeoutExpired:
            report["failures"].append("the rehearsal runner timed out")
            return finish()
        if proc.returncode != 0:
            report["failures"].append(f"the rehearsal runner failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
            return finish()
        out = json.loads(proc.stdout)

        probe = out.get("probe") or {}
        report["isolation"]["probe"] = probe
        report["isolation"]["egress_blocked"] = bool(probe.get("blocked"))
        if isolation.available and not probe.get("blocked"):
            report["failures"].append("egress was not blocked inside the sandbox, so the result does not show offline operation")

        # Evidence of the runtime's own network attempts, as in `ferry preflight`.
        denials: list[dict[str, Any]] | None = None
        if isolation.mechanism == "sandbox-exec":
            report["evidence_sources"].append("macos-sandbox-log")
            runner_pid = int(out.get("runner_pid") or -1)
            denials = collect_macos_denials(log_start, runner_pid)
            if not any(d["pid"] == runner_pid for d in denials):
                report["notes"].append("the probe's own denial did not appear in the macOS log, so the absence of"
                                       " the runtime's denials is not conclusive")
        elif strace:
            report["evidence_sources"].append("strace")
        elif isolation.mechanism == "unshare-netns":
            report["notes"].append("strace is not installed, so the runtime's blocked connection attempts are"
                                   " inferred from its output only")
        report["evidence_sources"].append("output-scan")

        for ran, expected in zip(out.get("models", []), models):
            pids = set(ran.pop("pids", None) or [])
            if denials is not None:
                ran["network_attempts"] = [d for d in denials if d["pid"] in pids]
            _check_network_use(report, ran)
            served = ran.get("served_model_path")
            same_file = bool(served) and Path(served).resolve() == Path(expected["path"]).resolve()
            ran["served_file_matches_import"] = same_file
            if report["runtime"]["build_info"] is None:
                report["runtime"]["build_info"] = ran.get("build_info")
            if not ran.get("ok"):
                report["failures"].append(f"{ran['name']}: {ran.get('error') or 'no completion'}")
            if not same_file:
                report["failures"].append(f"{ran['name']}: the runtime reported serving {served!r}, not the imported file")
        report["models"] = out.get("models", [])
    return finish()


def _check_network_use(report: dict[str, Any], ran: dict[str, Any]) -> None:
    """Fail on the runtime's blocked connection attempts and network-failure output lines; note its blocked
    DNS lookups, which carry no name (a harmless reverse lookup of 127.0.0.1 looks the same)."""
    name = ran.get("name")
    attempts = ran.get("network_attempts")
    if attempts is None:
        report["notes"].append(f"{name}: strace output was not written, so connection attempts are inferred from"
                               " the runtime's output only")
        attempts = ran["network_attempts"] = []
    connects = [a for a in attempts if a.get("kind") != "dns"]
    if connects:
        total = sum(a["count"] for a in connects)
        report["failures"].append(f"{name}: the runtime attempted {total} outbound connection(s), blocked by the"
                                  f" sandbox: {describe_attempts(connects)}")
    lines = ran.get("output_indicators") or []
    if lines:
        hosts = ran.get("hosts_mentioned") or []
        suffix = f" mentioning {', '.join(hosts[:5])}" if hosts else ""
        report["failures"].append(f"{name}: the runtime's output has {len(lines)} network failure line(s){suffix}")
    lookups = sum(a["count"] for a in attempts if a.get("kind") == "dns")
    if lookups:
        report["notes"].append(f"{name}: {lookups} DNS lookup(s) by the runtime were blocked; the OS-level evidence"
                               " does not show which name was looked up")


def _what_this_shows(report: dict[str, Any]) -> str:
    iso = report.get("isolation") or {}
    if report.get("verdict") != "pass":
        return ("The rehearsal failed (see Failures), so it does not show that this bundle serves offline. It is not"
                " a security assessment of the model.")
    if iso.get("mechanism", "none") == "none":
        return ("The bundle passed the same verification the disconnected side runs, and each model above served a"
                " completion through llama-server. No network sandbox was used, so Ferry blocked nothing and this"
                " rehearsal does not show that the bundle serves offline. It is not a security assessment of the"
                " model.")
    return ("The bundle passed the same verification the disconnected side runs, and each model above served a"
            " completion through llama-server while outbound network access was blocked on the machine that ran this"
            " rehearsal. It does not show the same result on different hardware, another llama.cpp build or another"
            " operating system, and it is not a security assessment of the model.")


def render_markdown(report: dict[str, Any]) -> str:
    """A readable version of the report to attach to a transfer request."""
    iso = report.get("isolation") or {}
    probe = iso.get("probe") or {}
    runtime = report.get("runtime") or {}
    yes_no = {True: "yes", False: "no", None: "not measured"}
    lines = [
        f"# Offline rehearsal: {report.get('bundle')} ({report.get('verdict', 'fail').upper()})",
        "",
        "| | |",
        "|---|---|",
        f"| Bundle id | `{report.get('bundle_id')}` |",
        f"| Verification | {report.get('verification_verdict')} |",
        f"| Isolation | {iso.get('mechanism', 'none')}: {iso.get('description', '')} |",
        f"| {egress_label(iso)} | {yes_no.get(iso.get('egress_blocked'))}"
        f" (TCP: {(probe.get('tcp') or {}).get('result', 'n/a')}, DNS: {(probe.get('dns') or {}).get('result', 'n/a')}) |",
        f"| Runtime | {runtime.get('version') or 'n/a'} |",
        f"| Started | {report.get('started_at')} |",
        f"| Finished | {report.get('finished_at')} |",
        f"| Ferry | {report.get('tool_version')} |",
        "",
    ]
    if report.get("models"):
        lines += [
            "## Models",
            "",
            "| Model | Digest | Load (s) | Latency (ms) | Tokens (prompt / completion) | Served file is the imported file | Result |",
            "|---|---|---|---|---|---|---|",
        ]
        for m in report["models"]:
            result = "ok" if m.get("ok") else f"failed: {m.get('error')}"
            lines.append(
                f"| {m.get('name')} | `{str(m.get('digest'))[:16]}` | {m.get('load_seconds')} | {m.get('latency_ms')} |"
                f" {m.get('prompt_tokens')} / {m.get('completion_tokens')} | {yes_no.get(m.get('served_file_matches_import'))} | {result} |"
            )
        lines.append("")
    for title, key in (("Failures", "failures"), ("Verification errors", "verification_errors"), ("Notes", "notes")):
        if report.get(key):
            lines += [f"## {title}", ""] + [f"- {item}" for item in report[key]] + [""]
    lines += ["## What this shows", "", _what_this_shows(report), ""]
    return "\n".join(lines)
