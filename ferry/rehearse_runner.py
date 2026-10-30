"""The part of `ferry rehearse` that runs inside the network sandbox.

`ferry.rehearse` starts this as `python -I -m ferry.rehearse_runner <json>` under
the isolation from `ferry.sandbox`. It probes egress from inside the sandbox,
starts llama-server on each imported model file, sends one prompt, and prints a
single JSON object on stdout. The completion text is never printed or stored.

For the evidence of network attempts it reports, per model, the runtime's
process ids (matched against the macOS sandbox log by `ferry.rehearse`), the
connects strace saw (Linux, when asked) and network-failure lines in the
runtime's output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .preflight import parse_strace_connects, process_group_members, scan_output, stop_process_group
from .sandbox import probe_egress, without_proxies

# Proxy environment variables must not redirect loopback traffic.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(url: str, token: str, body: dict[str, Any] | None = None, timeout: float = 30.0) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET")
    req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _tail(path: Path, lines: int = 30) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def _run_model(args: dict[str, Any], model: dict[str, Any], token: str) -> dict[str, Any]:
    base = f"http://127.0.0.1:{model['port']}"
    log_path = Path(args["log_dir"]) / f"{model['name']}.log"
    strace_out = Path(args["log_dir"]) / f"{model['name']}.strace.txt" if args.get("strace") else None
    out: dict[str, Any] = {
        "name": model["name"], "digest": model["digest"], "ok": False, "error": None,
        "load_seconds": None, "latency_ms": None, "prompt_tokens": None, "completion_tokens": None,
        "build_info": None, "served_model_path": None, "exit_code": None,
        "network_attempts": [], "output_indicators": [], "hosts_mentioned": [],
    }
    cmd = [
        args["binary"], "-m", model["path"], "--alias", model["name"],
        "--host", "127.0.0.1", "--port", str(model["port"]),
        "--api-key-file", args["token_file"], "--offline", "--no-webui",
        "-c", str(args.get("ctx_size", 2048)),
    ]
    if strace_out is not None:
        cmd = ["strace", "-f", "-qq", "-e", "trace=connect", "-o", str(strace_out), *cmd]
    started = time.monotonic()
    pids: set[int] = set()
    with open(log_path, "wb") as log:
        # Own process group, so that helpers are tracked and stopped with it; no proxy variables (loopback
        # stays reachable in the macOS sandbox, see ferry.sandbox).
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                env=without_proxies(os.environ), start_new_session=True)
        pids.add(proc.pid)
        try:
            deadline = started + float(args.get("load_timeout_s", 120))
            last_track = 0.0
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(f"llama-server exited with code {proc.returncode} before becoming ready")
                if time.monotonic() > deadline:
                    raise RuntimeError("llama-server did not become ready before the load timeout")
                if time.monotonic() - last_track > 1:
                    pids |= process_group_members(proc.pid)
                    last_track = time.monotonic()
                try:
                    status, _ = _request(f"{base}/health", token, timeout=2)
                    if status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.25)
            out["load_seconds"] = round(time.monotonic() - started, 2)
            status, props = _request(f"{base}/props", token)
            if status == 200 and isinstance(props, dict):
                out["build_info"] = props.get("build_info")
                out["served_model_path"] = props.get("model_path")
            t0 = time.monotonic()
            status, body = _request(f"{base}/v1/chat/completions", token, {
                "model": model["name"],
                "messages": [{"role": "user", "content": args["prompt"]}],
                "max_tokens": int(args.get("max_tokens", 16)),
                "temperature": 0,
            }, timeout=float(args.get("request_timeout_s", 120)))
            out["latency_ms"] = round((time.monotonic() - t0) * 1000)
            if status != 200 or not isinstance(body, dict):
                raise RuntimeError(f"chat completion returned HTTP {status}")
            usage = body.get("usage") or {}
            out["prompt_tokens"] = usage.get("prompt_tokens")
            out["completion_tokens"] = usage.get("completion_tokens")
            choices = body.get("choices") or []
            out["ok"] = bool(choices) and bool(out["completion_tokens"])
            if not out["ok"]:
                out["error"] = "the runtime answered but produced no completion tokens"
        except Exception as exc:  # reported in the rehearsal, never raised past here
            out["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            pids |= process_group_members(proc.pid)
            stop_process_group(proc)
            out["exit_code"] = proc.returncode
    out["pids"] = sorted(pids)
    out["output_indicators"], out["hosts_mentioned"] = scan_output(log_path)
    if strace_out is not None:
        try:
            out["network_attempts"] = parse_strace_connects(strace_out.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            out["network_attempts"] = None  # strace wrote nothing: no evidence either way
    out["log_tail"] = _tail(log_path)
    return out


def main(argv: list[str] | None = None) -> int:
    args = json.loads((argv or sys.argv[1:])[0])
    token = Path(args["token_file"]).read_text(encoding="utf-8").strip()
    result = {"probe": probe_egress(), "runner_pid": os.getpid(),
              "models": [_run_model(args, m, token) for m in args["models"]]}
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
