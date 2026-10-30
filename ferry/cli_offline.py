"""`ferry preflight` and `ferry rehearse`: the connected-side offline-readiness commands.

Kept separate from the main CLI so it can be registered with one call:
`cli_offline.register(subparsers)`. Exit codes: 0 pass, 1 fail, 2 usage or setup error.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from .errors import FerryError


def _write_reports(report: dict[str, Any], render, json_out: str | None, md_out: str | None) -> None:
    if json_out:
        Path(json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if md_out:
        Path(md_out).write_text(render(report), encoding="utf-8")


def _print_lines(title: str, items: list[str]) -> None:
    if items:
        print(f"{title}:")
        for item in items:
            print(f"  - {item}")


def _isolation_text(iso: dict[str, Any]) -> str:
    if iso.get("mechanism") in (None, "none"):
        return "none (no sandbox was used, so Ferry blocked nothing)"
    blocked = {True: "yes", False: "NO", None: "not measured"}[iso.get("egress_blocked")]
    return f"{iso['mechanism']} (egress blocked inside the sandbox: {blocked})"


def _print_preflight(report: dict[str, Any]) -> None:
    iso = report["isolation"]
    process = report.get("process") or {}
    ready = process.get("ready") or {}
    print(f"Offline preflight: {report['verdict'].upper()}")
    print(f"  isolation  {_isolation_text(iso)}")
    if report.get("ready_url"):
        print(f"  ready      {'yes after ' + str(ready.get('seconds')) + ' s' if ready.get('ok') else 'no'}")
    elif process:
        print(f"  exit code  {process.get('exit_code')}")
    print(f"  evidence   {', '.join(report.get('evidence_sources') or []) or 'none'}")
    calls = report.get("python_network_calls") or []
    attempts = [a for a in report.get("network_attempts") or [] if a.get("kind") != "dns" or not a.get("explained_by")]
    if calls or attempts:
        print("Network access attempted:")
        for c in calls:
            print(f"  python  {c.get('package') or '?':<18} {c['event']} {c['host']}:{c['port']}  x{c['count']}  ({c.get('location')})")
        for a in attempts:
            what = "DNS lookup (resolver socket)" if a.get("kind") == "dns" else a["destination"]
            print(f"  kernel  {a.get('process') or 'pid'}({a['pid']})  {what}  x{a['count']}")
    if report.get("findings"):
        print("Likely causes and fixes:")
        for f in report["findings"]:
            print(f"  {f['library']} [{f['confidence']}]: {f['issue']}")
            print(f"    fix: {f['fix']}")
    _print_lines("Failures", report.get("failures") or [])
    _print_lines("Warnings", report.get("warnings") or [])
    print(f"Command output: {report.get('log_file')}")


def _print_rehearsal(report: dict[str, Any]) -> None:
    iso = report.get("isolation") or {}
    runtime = report.get("runtime") or {}
    print(f"Offline rehearsal: {report['verdict'].upper()}  ({report.get('bundle')})")
    print(f"  bundle      {report.get('bundle_id')}  verification: {report.get('verification_verdict')}")
    if iso:
        print(f"  isolation   {_isolation_text(iso)}")
    if runtime:
        print(f"  runtime     {runtime.get('version') or runtime.get('binary')}")
    for m in report.get("models") or []:
        state = "ok" if m.get("ok") else f"FAILED: {m.get('error')}"
        print(f"  model       {m['name']}  load {m.get('load_seconds')} s, first completion {m.get('latency_ms')} ms,"
              f" served file is the imported file: {'yes' if m.get('served_file_matches_import') else 'no'}  [{state}]")
    _print_lines("Failures", report.get("failures") or [])
    _print_lines("Verification errors", report.get("verification_errors") or [])
    _print_lines("Notes", report.get("notes") or [])


def _kv(values: list[str], what: str) -> dict[str, str]:
    out = {}
    for item in values or []:
        sep = "=" if what == "env" else ":"
        if sep not in item:
            raise FerryError(f"--{what} expects {'KEY=VALUE' if what == 'env' else 'Name: value'}, got {item!r}")
        k, v = item.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def _is_http_url(value: str) -> bool:
    """Only http(s) URLs with a host: the readiness and smoke requests go to a server the
    command started, never to a file or another scheme urllib would happily open."""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def cmd_preflight(args: argparse.Namespace) -> int:
    from .preflight import preflight, render_markdown

    command = list(args.cmd or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("ferry preflight: give the launch command after --, e.g. ferry preflight --ready-url URL -- llama-server ...",
              file=sys.stderr)
        return 2
    if (args.request_url or args.request_json or args.header) and not args.ready_url:
        print("ferry preflight: --request-url, --request-json and --header need --ready-url: the smoke request is sent"
              " once the server is ready", file=sys.stderr)
        return 2
    if (args.request_json or args.header) and not args.request_url:
        print("ferry preflight: --request-json and --header need --request-url", file=sys.stderr)
        return 2
    for flag, value in (("--ready-url", args.ready_url), ("--request-url", args.request_url)):
        if value and not _is_http_url(value):
            print(f"ferry preflight: {flag} must be an http:// or https:// URL with a host", file=sys.stderr)
            return 2
    request = None
    if args.request_url:
        body = json.loads(Path(args.request_json).read_text(encoding="utf-8")) if args.request_json else None
        request = {"url": args.request_url, "body": body, "headers": _kv(args.header, "header")}
    report = preflight(
        command, ready_url=args.ready_url, request=request, env=_kv(args.env, "env"), cwd=args.cwd,
        ready_timeout_s=args.ready_timeout, timeout_s=args.timeout, require_isolation=not args.allow_no_isolation,
        allow_attempts=args.allow_attempts, strict=args.strict, python_hook=not args.no_python_hook,
        log_path=Path(args.log) if args.log else None,
    )
    _write_reports(report, render_markdown, args.out, args.md)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_preflight(report)
    return 0 if report["verdict"] == "pass" else 1


def cmd_rehearse(args: argparse.Namespace) -> int:
    from .config import ImportSettings, load_settings
    from .rehearse import MIN_LLAMACPP_BUILD, rehearse, render_markdown

    # The import policy comes from the same places as for the other commands: --config (before or after the
    # command name), the global --data-dir, FERRY_CONFIG or FERRY_DATA_DIR. The rehearsal itself still imports
    # into a throwaway data directory.
    config = getattr(args, "config", None)
    data_dir = getattr(args, "config_data_dir", None) or getattr(args, "data_dir", None)
    configured = config or data_dir or os.environ.get("FERRY_CONFIG") or os.environ.get("FERRY_DATA_DIR")
    imports = load_settings(config_path=config, data_dir=data_dir).imports if configured else ImportSettings()
    if args.require_role:
        imports = dataclasses.replace(imports, required_roles=tuple(args.require_role))
    report = rehearse(
        Path(args.bundle), trust_dir=Path(args.trust_dir), import_settings=imports, binary=args.binary,
        prompt=args.prompt, ctx_size=args.ctx_size, max_tokens=args.max_tokens,
        min_build=None if args.min_build == 0 else (args.min_build or MIN_LLAMACPP_BUILD),
        require_isolation=not args.allow_no_isolation,
    )
    _write_reports(report, render_markdown, args.out, args.md)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_rehearsal(report)
    return 0 if report["verdict"] == "pass" else 1


def register(subparsers: Any) -> None:
    p = subparsers.add_parser(
        "preflight", help="run a launch command with egress blocked and report hidden network calls",
        description="Run the exact launch command of an AI stack inside an OS network sandbox and report every "
                    "network access attempt, the library that made it and the documented fix. "
                    "Example: ferry preflight --ready-url http://127.0.0.1:8080/health -- llama-server -m model.gguf --port 8080 --offline")
    p.add_argument("--ready-url", help="poll this URL until HTTP 200 (server mode); without it the command must exit 0")
    p.add_argument("--request-url", help="after ready, send one request here (POST if --request-json is given)")
    p.add_argument("--request-json", help="file with the JSON body for --request-url")
    p.add_argument("--header", action="append", default=[], help="request header 'Name: value' (repeatable)")
    p.add_argument("--env", action="append", default=[], help="KEY=VALUE added to the command's environment (repeatable)")
    p.add_argument("--cwd", help="working directory for the command")
    p.add_argument("--ready-timeout", type=float, default=120.0, help="seconds to wait for --ready-url (default 120)")
    p.add_argument("--timeout", type=float, default=300.0, help="seconds a one-shot command may run (default 300)")
    p.add_argument("--allow-attempts", action="store_true", help="report network attempts as warnings instead of failing")
    p.add_argument("--strict", action="store_true", help="also fail on DNS lookups that cannot be attributed (macOS resolver denials, "
                        "Linux queries to a loopback stub resolver)")
    p.add_argument("--no-python-hook", action="store_true", help="do not load the Python attribution hook")
    p.add_argument("--allow-no-isolation", action="store_true", help="run even if no OS network sandbox is available")
    p.add_argument("--log", help="write the command's output here (default: a temp directory)")
    p.add_argument("--out", help="write the JSON report to this file")
    p.add_argument("--md", help="write the Markdown report to this file")
    p.add_argument("--json", action="store_true", help="print the JSON report instead of the summary")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- followed by the launch command")
    p.set_defaults(func=cmd_preflight)

    r = subparsers.add_parser(
        "rehearse", help="import a bundle into a throwaway store and serve it with llama-server, egress blocked",
        description="Verify and import a Ferry bundle with the same checks the disconnected side runs, start "
                    "llama-server on each GGUF model inside an OS network sandbox, send one prompt, and report.")
    r.add_argument("bundle", help="path to a .ferry.tar or an extracted bundle directory")
    r.add_argument("--trust-dir", required=True, help="trust store with the signers' public keys")
    r.add_argument("--require-role", action="append", help="required signer role (repeatable; default from config or 'publisher')")
    # SUPPRESS: a missing option must not overwrite the global `ferry --config FILE rehearse ...`.
    r.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS,
                   help="ferry.toml whose [import] policy to apply (default: FERRY_CONFIG, or <data dir>/ferry.toml)")
    r.add_argument("--config-data-dir", help=argparse.SUPPRESS)
    r.add_argument("--binary", help="llama-server binary (default: llama-server on PATH)")
    r.add_argument("--prompt", default="Reply with one word: ready", help="smoke-test prompt (never stored)")
    r.add_argument("--ctx-size", type=int, default=2048)
    r.add_argument("--max-tokens", type=int, default=16)
    r.add_argument("--min-build", type=int, default=None,
                   help="minimum llama.cpp build number (default 8146, which fixes CVE-2026-27940; 0 disables)")
    r.add_argument("--allow-no-isolation", action="store_true", help="run even if no OS network sandbox is available")
    r.add_argument("--out", help="write the JSON report to this file")
    r.add_argument("--md", help="write the Markdown report to this file")
    r.add_argument("--json", action="store_true", help="print the JSON report instead of the summary")
    r.set_defaults(func=cmd_rehearse)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ferry")
    register(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FerryError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
