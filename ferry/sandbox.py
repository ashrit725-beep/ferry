"""Run a command with outbound networking denied, where the OS supports it.

`ferry rehearse` uses this on the connected side to show that a bundle's model
serves with egress blocked, before anyone writes the bundle to transfer media.

- macOS: `sandbox-exec` with a profile that denies non-loopback network access
  and the system DNS resolver service (macOS resolves names through
  mDNSResponder, which a plain network deny does not cover). Apple marks
  `sandbox-exec` deprecated, but it ships with macOS; it is detected at runtime.
- Linux: a new network namespace holding only a loopback interface. Candidates in
  order: `unshare --net` as root, unprivileged `unshare --net --map-root-user`
  (hardened hosts often disable unprivileged user namespaces), and bubblewrap
  (`bwrap --unshare-net`). Each candidate runs a trivial command first; the first
  one that works is used, and the report names the ones that failed.
- Anything else: no isolation, and the report says so.

This is a test harness, not a containment boundary: it shows that the runtime
did not need the network, it is not designed to hold a hostile process.

Loopback connections (on macOS, to this host's own services) and Unix sockets
stay allowed, so a local service that fetches on the command's behalf (a proxy
on 127.0.0.1, a local Ollama, the Docker daemon) is not blocked. Commands run
here therefore get an environment without proxy variables (`without_proxies`).
"""

from __future__ import annotations

import dataclasses
import errno
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping

MACOS_PROFILE = """(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:*"))
(deny mach-lookup (global-name "com.apple.mDNSResponder") (global-name "com.apple.mDNSResponderHelper") (global-name "com.apple.dnssd.service"))
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")) (remote unix-socket (path-literal "/var/run/mDNSResponder")))
"""

# RFC 5737 TEST-NET-1 is never routed on the public internet, so the probe cannot
# reach a real third party even if isolation silently fails.
PROBE_ADDRESS = ("192.0.2.1", 443)
# RFC 2606 reserved name; only resolution is attempted, nothing connects to it.
PROBE_HOSTNAME = "example.com"


LINUX_NAMESPACE_MECHANISMS = ("unshare-netns-root", "unshare-netns", "bwrap")
_LO_UP = 'ip link set lo up && exec "$0" "$@"'


@dataclass(frozen=True)
class Isolation:
    mechanism: str  # "sandbox-exec", one of LINUX_NAMESPACE_MECHANISMS, or "none"
    prefix: tuple[str, ...]  # argv prefix that runs a command inside the sandbox
    description: str
    tried: tuple[str, ...] = ()  # candidates that failed their self-test, for the report

    @property
    def available(self) -> bool:
        return self.mechanism != "none"

    @property
    def linux_namespace(self) -> bool:
        return self.mechanism in LINUX_NAMESPACE_MECHANISMS

    def wrap(self, argv: list[str]) -> list[str]:
        return [*self.prefix, *argv]


def _candidates() -> list[Isolation]:
    """Isolation mechanisms this host may support, most preferred first."""
    if sys.platform == "darwin":
        if shutil.which("sandbox-exec"):
            return [Isolation("sandbox-exec", ("sandbox-exec", "-p", MACOS_PROFILE),
                              "macOS sandbox profile denying non-loopback network and the DNS resolver service")]
        return []
    if not sys.platform.startswith("linux"):
        return []
    out: list[Isolation] = []
    if shutil.which("unshare") and shutil.which("ip"):
        if os.geteuid() == 0:
            out.append(Isolation("unshare-netns-root", ("unshare", "--net", "sh", "-c", _LO_UP),
                                 "Linux network namespace (created as root) containing only a loopback interface"))
        out.append(Isolation("unshare-netns", ("unshare", "--net", "--map-root-user", "sh", "-c", _LO_UP),
                             "Linux network namespace (unprivileged user namespace) containing only a loopback"
                             " interface"))
    if shutil.which("bwrap"):
        out.append(Isolation("bwrap", ("bwrap", "--unshare-net", "--dev-bind", "/", "/", "--"),
                             "bubblewrap sandbox with its own network namespace (loopback only)"))
    return out


def _self_test(candidate: Isolation) -> str | None:
    """Run a trivial command inside the candidate sandbox. None on success, else a
    short reason. Hardened Linux hosts often disable unprivileged user namespaces,
    which only shows when unshare actually runs."""
    try:
        proc = subprocess.run(candidate.wrap(["true"]), capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{type(exc).__name__}: {exc}"[:200]
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        return f"exit {proc.returncode}: {lines[-1] if lines else 'no output'}"[:200]
    return None


def detect_isolation() -> Isolation:
    """The first isolation mechanism that passes its self-test on this host.

    The self-test shows that the mechanism runs here, not that it blocks egress:
    the in-sandbox probe (`probe_egress`) shows that, and a preflight or
    rehearsal fails when the probe reports open egress. Each call runs the short
    self-test again, so a changed environment is picked up.
    """
    tried: list[str] = []
    for candidate in _candidates():
        problem = _self_test(candidate)
        if problem is None:
            return dataclasses.replace(candidate, tried=tuple(tried))
        tried.append(f"{candidate.mechanism} ({problem})")
    if tried:
        return Isolation("none", (), "no working network isolation: tried " + "; ".join(tried), tuple(tried))
    return Isolation("none", (), "no supported isolation tool found; ran with the host's normal network access")


def is_proxy_variable(name: str) -> bool:
    """urllib, requests, httpx, pip and curl take proxies from <scheme>_proxy in any letter case
    (HTTP_PROXY, https_proxy, ALL_PROXY, ...)."""
    return name.lower().endswith("_proxy")


def without_proxies(env: Mapping[str, str]) -> dict[str, str]:
    """The environment for a command run in the sandbox: no proxy variables, and NO_PROXY=* (which also stops
    urllib's lookup of the macOS system proxy settings). A proxy listening on loopback would otherwise carry
    the command's traffic out of the macOS sandbox without any blocked attempt."""
    clean = {k: v for k, v in env.items() if not is_proxy_variable(k)}
    clean["NO_PROXY"] = clean["no_proxy"] = "*"
    return clean


def local_proxies(env: Mapping[str, str]) -> list[str]:
    """Names of the proxy variables in `env` that name a proxy on this host (localhost or a loopback address)."""
    found = []
    for name, value in env.items():
        if not is_proxy_variable(name) or name.lower() == "no_proxy" or not value.strip():
            continue
        text = value.strip()
        try:
            host = urllib.parse.urlsplit(text if "://" in text else "http://" + text).hostname or ""
        except ValueError:
            continue
        if host == "localhost" or host.endswith(".localhost"):
            found.append(name)
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified:
            found.append(name)
    return sorted(found)


def _errno_name(exc: OSError) -> str | None:
    return errno.errorcode.get(exc.errno) if exc.errno else None


def _probe_tcp(timeout: float) -> dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(PROBE_ADDRESS)
    except TimeoutError:
        # Packets may have left the host; isolation is not proven.
        return {"blocked": False, "result": "timeout", "errno": None}
    except PermissionError as exc:
        return {"blocked": True, "result": "denied", "errno": _errno_name(exc)}
    except OSError as exc:
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL):
            return {"blocked": True, "result": "unreachable", "errno": _errno_name(exc)}
        return {"blocked": False, "result": "error", "errno": _errno_name(exc)}
    else:
        return {"blocked": False, "result": "connected", "errno": None}
    finally:
        s.close()


def _probe_dns() -> dict[str, Any]:
    try:
        socket.getaddrinfo(PROBE_HOSTNAME, 443)
    except socket.gaierror as exc:
        # gaierror carries EAI_* resolver codes, not errno values.
        return {"blocked": True, "result": "resolution failed", "errno": None, "detail": str(exc)}
    except OSError as exc:
        return {"blocked": True, "result": "resolution failed", "errno": _errno_name(exc)}
    return {"blocked": False, "result": "resolved", "errno": None}


def probe_egress(timeout: float = 3.0) -> dict[str, Any]:
    """One TCP connect to TEST-NET-1 and one DNS lookup, each classified.

    Inside working isolation both fail at once (EPERM, no route, or no resolver).
    """
    tcp, dns = _probe_tcp(timeout), _probe_dns()
    return {"tcp": tcp, "dns": dns, "blocked": bool(tcp["blocked"] and dns["blocked"])}
