"""Preflight any launch command with outbound networking denied (`ferry preflight`).

Hidden network calls are the best-documented way an "offline" AI stack fails
after it has been carried into a disconnected network (docs/research/06): a
library checks for updates, fetches a tokenizer or phones home, and the failure
only shows up inside the enclave. A preflight runs the exact launch command on
the connected side with egress blocked and reports every outbound attempt it can
see, before anything is written to transfer media.

Evidence, from strongest to weakest:
- an egress probe from inside the sandbox (ferry.sandbox.probe_egress);
- macOS: kernel sandbox denials read back from the unified log (process, pid
  and port; macOS redacts the destination address; DNS lookups show up as
  denied connections to the mDNSResponder socket);
- Linux: `strace -f -e trace=connect` when strace is installed (address and
  port; a DNS query to a loopback stub resolver such as 127.0.0.53 counts as a
  lookup);
- Python processes: an audit hook (preflight_hook/sitecustomize.py) that names
  the host and the library behind each lookup and connect;
- the command's exit status, readiness URL and an optional smoke request;
- lines in the command's output that look like network failures, and the host
  names they mention.

Any attempted outbound connection fails the preflight by default, even when the
application recovered: in the sandbox the attempt fails at once, but behind an
enclave firewall that silently drops packets the same call can hang until it
times out. Processes that leave the command's process group (daemons calling
setsid) are not attributed to it. Loopback and Unix sockets are not blocked, so
the command runs without proxy variables (ferry.sandbox.without_proxies).
"""

from __future__ import annotations

import datetime as _dt
import errno
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__, offline_rules
from .errors import ValidationFailed
from .sandbox import Isolation, detect_isolation, is_proxy_variable, local_proxies, probe_egress, without_proxies
from .util import rfc3339

REPORT_VERSION = 1
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_INDICATOR = re.compile(
    r"Failed to resolve|NameResolutionError|nodename nor servname|Name or service not known"
    r"|Temporary failure in name resolution|No address associated with hostname|Could not resolve host"
    r"|getaddrinfo failed|Network is unreachable|No route to host|Max retries exceeded"
    r"|ConnectTimeout|ConnectionError|OfflineModeIsEnabled|couldn't connect to|ProxyError"
    r"|connect\(\) failed|Operation not permitted.{0,40}connect",
    re.IGNORECASE,
)
_HOSTS = (
    re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"),
    re.compile(r"Failed to resolve '([A-Za-z0-9.-]+)'"),
    re.compile(r"Could not resolve host:?\s*([A-Za-z0-9.-]+)"),
    re.compile(r"host='([A-Za-z0-9.-]+)'"),
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_MACOS_DENY = re.compile(
    r"(?:(?P<dup>\d+) duplicate reports? for )?Sandbox: (?P<proc>.+?)\((?P<pid>\d+)\) deny\(\d+\) network-outbound (?P<target>\S+)"
)
_STRACE_CONNECT = re.compile(
    r"^(?P<pid>\d+)\s+connect\(\d+, \{sa_family=AF_INET6?, (?:sin6?_port=htons\((?P<port>\d+)\)).*?"
    r"(?:inet_addr\(\"(?P<ip4>[^\"]+)\"\)|inet_pton\(AF_INET6, \"(?P<ip6>[^\"]+)\")[^=]*=\s*(?P<result>.*)$"
)


# ---------------------------------------------------------------------------
# Runner: executes inside the sandbox.

def _http(url: str, method: str = "GET", body: Any = None, headers: dict[str, str] | None = None,
          timeout: float = 5.0) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw) if raw else None
            except ValueError:
                return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None


def _signal_group(pgid: int, sig: int) -> bool:
    """Send `sig` to a process group; False once no process is left in it."""
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def stop_process_group(proc: subprocess.Popen, grace_s: float = 10.0) -> None:
    """SIGTERM to the command's process group, then SIGKILL to whatever is left of the group after the grace
    period. The leader exiting is not enough: a helper in its group may ignore SIGTERM."""
    deadline = time.monotonic() + grace_s
    _signal_group(proc.pid, signal.SIGTERM)
    while time.monotonic() < deadline:
        if proc.poll() is not None and not _signal_group(proc.pid, 0):
            break
        time.sleep(0.05)
    _signal_group(proc.pid, signal.SIGKILL)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def process_group_members(pgid: int) -> set[int]:
    """Processes in process group `pgid`, i.e. descendants that stayed in the command's group."""
    try:
        ps = subprocess.run(["ps", "-A", "-o", "pid=,pgid="], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return set()
    members = set()
    for line in ps.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == str(pgid) and parts[0].isdigit():
            members.add(int(parts[0]))
    return members


def _open_output(path: str | Path, extra_flags: int = 0) -> int:
    """Open the file the command's output goes to: created 0600 if missing. A symbolic link, a file that is
    hard-linked elsewhere or anything but a regular file is refused, since another user may have planted it."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK | extra_flags
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENXIO):
            raise ValidationFailed(f"{path} is a symbolic link or not a regular file; the log is not written there") from None
        raise
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise ValidationFailed(f"{path} is not a regular file with a single link; the log is not written there")
    os.set_blocking(fd, True)
    return fd


def _empty_output(path: Path) -> None:
    fd = _open_output(path)
    try:
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)


def _runner(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"probe": probe_egress(), "runner_pid": os.getpid(), "pids": [], "exit_code": None,
                           "timed_out": False, "ready": None, "request": None, "error": None, "duration_s": None}
    command = list(args["command"])
    if args.get("strace_out"):
        command = ["strace", "-f", "-qq", "-e", "trace=connect", "-o", args["strace_out"], *command]
    env = without_proxies({**os.environ, **(args.get("env") or {})})
    started = time.monotonic()
    log = os.fdopen(_open_output(args["log_path"], os.O_APPEND), "ab")
    try:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                cwd=args.get("cwd") or None, env=env, start_new_session=True)
    except OSError as exc:
        log.close()
        out["error"] = f"could not start the command: {exc}"
        return out

    pids = {proc.pid}

    def track() -> None:
        pids.update(process_group_members(proc.pid))

    try:
        if args.get("ready_url"):
            deadline = started + float(args.get("ready_timeout_s", 120))
            ready: dict[str, Any] = {"ok": False, "seconds": None, "error": None}
            last_track = 0.0
            while True:
                if proc.poll() is not None:
                    ready["error"] = f"the command exited with code {proc.returncode} before it became ready"
                    break
                if time.monotonic() > deadline:
                    ready["error"] = f"not ready after {args.get('ready_timeout_s', 120)} s"
                    break
                if time.monotonic() - last_track > 1:
                    track()
                    last_track = time.monotonic()
                try:
                    status, _ = _http(args["ready_url"], timeout=2)
                    if status == 200:
                        ready.update(ok=True, seconds=round(time.monotonic() - started, 2))
                        break
                except OSError:
                    pass
                time.sleep(0.25)
            out["ready"] = ready
            request = args.get("request")
            if ready["ok"] and request:
                t0 = time.monotonic()
                try:
                    status, body = _http(request["url"], request.get("method") or ("POST" if request.get("body") is not None else "GET"),
                                         request.get("body"), request.get("headers"), float(request.get("timeout_s", 120)))
                    usage = body.get("usage") if isinstance(body, dict) else None
                    out["request"] = {"ok": 200 <= status < 300, "status": status,
                                      "latency_ms": round((time.monotonic() - t0) * 1000), "usage": usage}
                except OSError as exc:
                    out["request"] = {"ok": False, "status": None, "latency_ms": None, "usage": None,
                                      "error": f"{type(exc).__name__}: {exc}"}
                track()
        else:
            deadline = started + float(args.get("timeout_s", 300))
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    out["timed_out"] = True
                    break
                track()
                time.sleep(0.25)
    finally:
        stop_process_group(proc)
        out["exit_code"] = proc.returncode
        log.close()
    out["pids"] = sorted(pids)
    out["duration_s"] = round(time.monotonic() - started, 2)
    return out


# ---------------------------------------------------------------------------
# Evidence parsers (outside the sandbox).

def parse_macos_denials(text: str) -> list[dict[str, Any]]:
    """Aggregate kernel sandbox network-outbound denials by (pid, process, target)."""
    counts: dict[tuple[int, str, str], int] = {}
    for line in text.splitlines():
        m = _MACOS_DENY.search(line)
        if not m:
            continue
        key = (int(m.group("pid")), m.group("proc"), m.group("target"))
        counts[key] = counts.get(key, 0) + (int(m.group("dup")) if m.group("dup") else 1)
    return [{"pid": pid, "process": proc, "destination": target,
             "kind": "dns" if "mDNSResponder" in target else "connect", "count": n}
            for (pid, proc, target), n in sorted(counts.items())]


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def parse_strace_connects(text: str) -> list[dict[str, Any]]:
    """connect() calls from `strace -f -e trace=connect` output: non-loopback ones, and DNS queries to a
    resolver on loopback (kind "dns"). Inside the network namespace a lookup through a stub resolver such as
    systemd-resolved's 127.0.0.53 leaves only that connect behind."""
    counts: dict[tuple[int, str], dict[str, Any]] = {}
    for line in text.splitlines():
        m = _STRACE_CONNECT.match(line.strip())
        if not m:
            continue
        ip = m.group("ip4") or m.group("ip6")
        kind = "connect"
        if _is_loopback(ip):
            if m.group("port") != "53":
                continue
            kind = "dns"
        dest = f"{ip}:{m.group('port')}" if m.group("ip4") else f"[{ip}]:{m.group('port')}"
        entry = counts.setdefault((int(m.group("pid")), dest), {"pid": int(m.group("pid")), "process": None,
                                                                 "destination": dest, "kind": kind, "count": 0,
                                                                 "result": ""})
        entry["count"] += 1
        entry["result"] = m.group("result").strip()[:120]
    return list(counts.values())


def scan_output(path: Path, max_lines: int = 25) -> tuple[list[str], list[str]]:
    """Lines that look like network failures, and the non-local hosts they mention."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 4 * 1024 * 1024))
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return [], []
    lines: list[str] = []
    hosts: list[str] = []
    for line in text.splitlines():
        if not _INDICATOR.search(line):
            continue
        if len(lines) < max_lines:
            lines.append(line.strip()[:300])
        for pattern in _HOSTS:
            for host in pattern.findall(line):
                if host.lower() not in _LOCAL_HOSTS and host not in hosts:
                    hosts.append(host)
    return lines, hosts


def _macos_log(start: str) -> str:
    try:
        proc = subprocess.run(
            ["/usr/bin/log", "show", "--start", start, "--style", "compact", "--predicate",
             'eventMessage CONTAINS "deny" AND eventMessage CONTAINS "network-outbound"'],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout


def collect_macos_denials(start: str, runner_pid: int) -> list[dict[str, Any]]:
    # The kernel flushes these entries asynchronously. The probe's own denial
    # (runner pid) marks the log as caught up; take one more read after it.
    denials: list[dict[str, Any]] = []
    seen_probe = False
    for _ in range(8):
        denials = parse_macos_denials(_macos_log(start))
        if any(d["pid"] == runner_pid for d in denials):
            if seen_probe:
                break
            seen_probe = True
        time.sleep(1)
    return denials


# ---------------------------------------------------------------------------
# Orchestrator.

def preflight(
    command: list[str],
    *,
    ready_url: str | None = None,
    request: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    ready_timeout_s: float = 120.0,
    timeout_s: float = 300.0,
    require_isolation: bool = True,
    allow_attempts: bool = False,
    strict: bool = False,
    python_hook: bool = True,
    log_path: Path | None = None,
    isolation: Isolation | None = None,
) -> dict[str, Any]:
    """Run `command` with egress blocked and return the preflight report."""
    isolation = isolation or detect_isolation()
    keep_work = log_path is None
    if log_path is not None:
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        _empty_output(log_path)
    # Evidence files go to a private directory (0700), where no other user can plant a symbolic link or read
    # and rewrite them during the run; the log goes there too unless the caller names one.
    work = Path(tempfile.mkdtemp(prefix="ferry-preflight-"))
    if log_path is None:
        log_path = work / "output.log"
        _empty_output(log_path)

    report: dict[str, Any] = {
        "report_version": REPORT_VERSION, "kind": "preflight", "tool_version": __version__, "verdict": "fail",
        "command": list(command), "cwd": cwd, "ready_url": ready_url,
        "isolation": {"mechanism": isolation.mechanism, "description": isolation.description,
                      "egress_blocked": None, "probe": None},
        "process": None, "network_attempts": [], "python_network_calls": [], "findings": [],
        "evidence_sources": [], "output_indicators": [], "hosts_mentioned": [],
        "failures": [], "warnings": [], "notes": [],
        "log_file": str(log_path), "started_at": rfc3339(), "finished_at": None,
    }

    def finish() -> dict[str, Any]:
        report["finished_at"] = rfc3339()
        report["verdict"] = "fail" if report["failures"] else "pass"
        if not keep_work:  # the evidence has been read into the report
            shutil.rmtree(work, ignore_errors=True)
        return report

    if not command:
        report["failures"].append("no command given")
        return finish()
    if request and not ready_url:
        report["failures"].append("a smoke request needs a ready URL (server mode), so it could not be sent")
        return finish()
    if not isolation.available:
        message = "no network isolation is available on this host, so the preflight cannot show offline operation"
        if require_isolation:
            report["failures"].append(message)
            return finish()
        report["warnings"].append(message)

    strace_out = None
    if isolation.mechanism == "unshare-netns":
        if shutil.which("strace"):
            strace_out = str(work / "strace.txt")
        else:
            report["notes"].append("strace is not installed, so blocked connection attempts are inferred from output only")

    run_env = dict(env or {})
    netlog: Path | None = None
    if python_hook:
        # Python processes of the command load preflight_hook/sitecustomize.py at startup.
        netlog = work / "python-net.jsonl"
        netlog.write_bytes(b"")
        hook_dir = str(Path(__file__).resolve().parent / "preflight_hook")
        existing = run_env.get("PYTHONPATH", os.environ.get("PYTHONPATH", ""))
        run_env["PYTHONPATH"] = hook_dir + (os.pathsep + existing if existing else "")
        run_env["FERRY_PREFLIGHT_NETLOG"] = str(netlog)

    # The runner drops proxy variables (sandbox.without_proxies): loopback stays reachable in the macOS sandbox,
    # so a proxy there would relay the command's traffic without a blocked attempt. Names only: values can
    # carry credentials.
    command_env = {**os.environ, **run_env}
    removed = sorted(name for name in command_env if is_proxy_variable(name))
    if removed:
        report["notes"].append("proxy variables were removed from the command's environment and NO_PROXY=* was set: "
                               + ", ".join(removed))
    on_this_host = local_proxies(command_env)
    if on_this_host and isolation.mechanism == "sandbox-exec":
        report["warnings"].append(
            f"{', '.join(on_this_host)} named a proxy on this host. Loopback stays reachable inside the macOS sandbox,"
            " so a command that takes its proxy from elsewhere (its own configuration files, the system proxy"
            " settings) can reach the network through that proxy without any blocked attempt being seen")

    runner_args = {"command": command, "env": run_env, "cwd": cwd, "log_path": str(log_path),
                   "ready_url": ready_url, "ready_timeout_s": ready_timeout_s, "request": request,
                   "timeout_s": timeout_s, "strace_out": strace_out}
    # Local time with one second of slack: `log show --start` takes local time.
    log_start = (_dt.datetime.now() - _dt.timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
    runner = isolation.wrap([sys.executable, "-I", "-m", "ferry.preflight", "--runner", json.dumps(runner_args)])
    try:
        proc = subprocess.run(runner, capture_output=True, text=True, timeout=max(ready_timeout_s, timeout_s) + 120)
    except subprocess.TimeoutExpired:
        report["failures"].append("the preflight runner timed out")
        return finish()
    if proc.returncode != 0:
        report["failures"].append(f"the preflight runner failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
        return finish()
    out = json.loads(proc.stdout)

    probe = out.get("probe") or {}
    report["isolation"]["probe"] = probe
    report["isolation"]["egress_blocked"] = bool(probe.get("blocked"))
    report["process"] = {k: out.get(k) for k in ("exit_code", "timed_out", "ready", "request", "duration_s", "error")}
    # In server mode the preflight itself stops the command once the checks are done.
    report["process"]["stopped_by_preflight"] = bool(ready_url) and (out.get("exit_code") or 0) < 0
    if isolation.available and not probe.get("blocked"):
        report["failures"].append("egress was not blocked inside the sandbox, so the result does not show offline operation")
    if out.get("error"):
        report["failures"].append(out["error"])
    if ready_url:
        ready = out.get("ready") or {}
        if not ready.get("ok"):
            report["failures"].append(ready.get("error") or "the command never became ready")
        if request:
            req = out.get("request") or {}
            if not req.get("ok"):
                report["failures"].append(f"the smoke request failed (HTTP {req.get('status')}) {req.get('error', '')}".strip())
    elif out.get("timed_out"):
        report["failures"].append(f"the command did not finish within {timeout_s} s")
    elif out.get("exit_code") not in (0, None):
        report["failures"].append(f"the command exited with code {out.get('exit_code')}")

    attempts: list[dict[str, Any]] = []
    command_pids = set(out.get("pids") or [])
    if isolation.mechanism == "sandbox-exec":
        report["evidence_sources"].append("macos-sandbox-log")
        denials = collect_macos_denials(log_start, int(out.get("runner_pid") or -1))
        attempts = [d for d in denials if d["pid"] in command_pids]
        if not any(d["pid"] == out.get("runner_pid") for d in denials):
            report["notes"].append("the probe's own denial did not appear in the macOS log, so the absence of other denials is not conclusive")
        report["notes"].append("macOS redacts destination addresses in sandbox log entries; ports are shown")
    elif strace_out:
        report["evidence_sources"].append("strace")
        try:
            attempts = parse_strace_connects(Path(strace_out).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            report["notes"].append("strace output was not written")
    report["evidence_sources"].append("output-scan")
    lines, hosts = scan_output(log_path)
    hook_records = read_netlog(netlog) if netlog else []
    if netlog:
        report["evidence_sources"].append("python-audit-hook")
    python_calls = [c for c in hook_records if not c.get("local")]
    # On Linux, local names are answered from /etc/hosts without a DNS query, so they explain no strace lookup.
    _explain_dns_denials(attempts, hook_records, count_local_lookups=isolation.mechanism == "sandbox-exec")
    report["network_attempts"] = attempts
    report["python_network_calls"] = python_calls
    report["output_indicators"] = lines
    report["hosts_mentioned"] = hosts
    report["findings"] = offline_rules.match(
        set(hosts) | {c["host"] for c in python_calls},
        {c["package"] for c in python_calls if c.get("package")},
        lines,
    )

    bucket = report["warnings"] if allow_attempts else report["failures"]
    connects = [a for a in attempts if a.get("kind") != "dns"]
    unexplained_dns = [a for a in attempts if a.get("kind") == "dns" and not a.get("explained_by")]
    if connects:
        total = sum(a["count"] for a in connects)
        bucket.append(f"{total} outbound connection attempt(s) were blocked: {describe_attempts(connects)}")
    if unexplained_dns:
        total = sum(a["count"] for a in unexplained_dns)
        message = (f"{total} DNS lookup(s) were blocked that the Python hook cannot explain as local names"
                   " (the OS-level evidence does not show which name was looked up)")
        (report["failures"] if strict and not allow_attempts else report["warnings"]).append(message)
    if any(a.get("explained_by") == "local name lookup" for a in attempts):
        report["notes"].append("some blocked DNS lookups were for local names (for example a reverse lookup of 127.0.0.1)"
                               " recorded by the Python hook; they are not counted as attempts")
    if python_calls:
        total = sum(c["count"] for c in python_calls)
        detail = "; ".join(f"{c.get('package') or '?'} -> {c['host']}:{c['port']}" for c in python_calls[:5])
        bucket.append(f"{total} network call(s) from Python code: {detail}")
    if lines:
        suffix = f" mentioning {', '.join(hosts[:5])}" if hosts else ""
        bucket.append(f"the command's output has {len(lines)} network failure line(s){suffix}")
    return finish()


def describe_attempts(attempts: list[dict[str, Any]], limit: int = 5) -> str:
    return "; ".join(f"{a.get('process') or 'pid'}({a['pid']}) to {a['destination']} x{a['count']}"
                     for a in attempts[:limit])


_LOOKUP_EVENTS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"}


def _asks_resolver(rec: dict[str, Any]) -> bool:
    """Whether a lookup the hook recorded reaches the system resolver. A forward lookup of an IP literal, which
    every connect to an address makes (getaddrinfo('127.0.0.1', port)), is answered without it; a reverse
    lookup (gethostbyaddr) is not."""
    if rec.get("event") not in _LOOKUP_EVENTS:
        return False
    if rec.get("event") == "gethostbyaddr":
        return True
    host = str(rec.get("host") or "")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(host)
    return False


def _explain_dns_denials(attempts: list[dict[str, Any]], hook_records: list[dict[str, Any]], *,
                         count_local_lookups: bool = True) -> None:
    """Explain blocked DNS lookups that carry no host name (macOS resolver-socket denials, queries to a
    loopback stub resolver under strace) with the lookups the Python hook recorded in the same process that
    reach the resolver: local names first, then attributed remote lookups (already reported as Python
    calls). Each recorded lookup explains at most one blocked lookup of its own process."""
    budgets: dict[str, dict[int, int]] = {"local name lookup": {}, "attributed Python lookup": {}}
    for rec in hook_records:
        if not _asks_resolver(rec) or (rec.get("local") and not count_local_lookups):
            continue
        budget = budgets["local name lookup" if rec.get("local") else "attributed Python lookup"]
        for pid, n in (rec.get("pid_counts") or {}).items():
            budget[pid] = budget.get(pid, 0) + n
    for a in attempts:
        if a.get("kind") != "dns":
            continue
        a["explained_by"] = None
        remaining = a["count"]
        for reason, budget in budgets.items():
            used = min(remaining, budget.get(a["pid"], 0))
            budget[a["pid"]] = budget.get(a["pid"], 0) - used
            remaining -= used
            if used and a["explained_by"] is None:
                a["explained_by"] = reason
        if remaining:
            a["explained_by"] = None


def read_netlog(path: Path) -> list[dict[str, Any]]:
    """Aggregate the Python hook's JSON lines by (event, host, port, module, local)."""
    calls: dict[tuple[Any, ...], dict[str, Any]] = {}
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in raw:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        module = rec.get("module") or None
        local = bool(rec.get("local"))
        key = (rec.get("event"), rec.get("host"), rec.get("port"), module, local)
        entry = calls.setdefault(key, {
            "event": rec.get("event"), "host": rec.get("host"), "port": rec.get("port"), "module": module,
            "package": module.split(".")[0] if module else None, "location": rec.get("location"),
            "local": local, "pids": [], "pid_counts": {}, "count": 0,
        })
        entry["count"] += 1
        pid = rec.get("pid")
        if pid not in entry["pids"]:
            entry["pids"].append(pid)
        if isinstance(pid, int):  # exact per-process counts: they explain blocked lookups of that process only
            entry["pid_counts"][pid] = entry["pid_counts"].get(pid, 0) + 1
    return list(calls.values())


def render_markdown(report: dict[str, Any]) -> str:
    iso = report.get("isolation") or {}
    probe = iso.get("probe") or {}
    process = report.get("process") or {}
    ready = process.get("ready") or {}
    request = process.get("request") or {}
    yes_no = {True: "yes", False: "no", None: "not measured"}
    if not report.get("ready_url"):
        ready_text = "n/a"
    elif ready.get("ok"):
        ready_text = f"yes, after {ready.get('seconds')} s"
    else:
        ready_text = "no"
    lines = [
        f"# Offline preflight ({report.get('verdict', 'fail').upper()})",
        "",
        f"Command: `{' '.join(report.get('command') or [])}`",
        "",
        "| | |",
        "|---|---|",
        f"| Isolation | {iso.get('mechanism')}: {iso.get('description')} |",
        f"| {egress_label(iso)} | {yes_no.get(iso.get('egress_blocked'))}"
        f" (TCP: {(probe.get('tcp') or {}).get('result', 'n/a')}, DNS: {(probe.get('dns') or {}).get('result', 'n/a')}) |",
        f"| Ready | {ready_text} |",
        f"| Smoke request | {('HTTP ' + str(request.get('status'))) if request else 'n/a'} |",
        f"| Exit code | {'stopped by the preflight after its checks' if process.get('stopped_by_preflight') else process.get('exit_code')} |",
        f"| Evidence sources | {', '.join(report.get('evidence_sources') or [])} |",
        f"| Started / finished | {report.get('started_at')} / {report.get('finished_at')} |",
        "",
    ]
    if report.get("network_attempts"):
        lines += ["## Blocked connection attempts", "", "| Process | PID | Destination | Count |", "|---|---|---|---|"]
        lines += [f"| {a.get('process') or ''} | {a['pid']} | {a['destination']} | {a['count']} |" for a in report["network_attempts"]]
        lines.append("")
    if report.get("python_network_calls"):
        lines += ["## Network calls from Python code", "", "| Call | Host | Port | Module | Where | Count |", "|---|---|---|---|---|---|"]
        lines += [f"| {c['event']} | {c['host']} | {c['port']} | {c.get('module') or ''} | {c.get('location') or ''} | {c['count']} |"
                  for c in report["python_network_calls"]]
        lines.append("")
    if report.get("findings"):
        lines += ["## Likely causes and fixes", ""]
        for f in report["findings"]:
            lines += [f"- **{f['library']}** ({f['confidence']}; matched on {', '.join(f['matched_on'])}): {f['issue']}",
                      f"  Fix: {f['fix']}", f"  Source: {f['source']}"]
        lines.append("")
    if report.get("output_indicators"):
        lines += ["## Network failures in the command's output", ""]
        if report.get("hosts_mentioned"):
            lines += [f"Hosts mentioned: {', '.join(report['hosts_mentioned'])}", ""]
        lines += ["```"] + report["output_indicators"] + ["```", ""]
    for title, key in (("Failures", "failures"), ("Warnings", "warnings"), ("Notes", "notes")):
        if report.get(key):
            lines += [f"## {title}", ""] + [f"- {item}" for item in report[key]] + [""]
    lines += ["## What this shows", "", _what_this_shows(iso), ""]
    return "\n".join(lines)


def egress_label(iso: dict[str, Any]) -> str:
    if iso.get("mechanism") in (None, "none"):
        return "Egress blocked on this host (no sandbox was used)"
    return "Egress blocked inside the sandbox"


def _what_this_shows(iso: dict[str, Any]) -> str:
    if iso.get("mechanism") in (None, "none"):
        return ("No network sandbox was used: the command ran with this host's normal network access, so Ferry blocked"
                " nothing and this report does not show offline operation. It lists only what the command's output"
                " and the Python hook revealed.")
    if iso.get("egress_blocked") is not True:
        return ("The command ran in a network sandbox, but the egress probe inside it was not blocked, so this report"
                " does not show offline operation.")
    return ("The command ran on this machine with outbound network access blocked, and the report lists every"
            " outbound attempt the sandbox and the command's output revealed. A pass means none were seen; it does not"
            " prove the same on another host, and a process that detached from the command's process group is not"
            " attributed to it. Loopback and Unix-socket connections are not blocked, so traffic that a local service"
            " (a proxy, a model server, the Docker daemon) relays for the command is not seen.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--runner":
        sys.stdout.write(json.dumps(_runner(json.loads(sys.argv[2]))))
        raise SystemExit(0)
    raise SystemExit("usage: python -m ferry.preflight --runner <json>  (use `ferry preflight` instead)")
