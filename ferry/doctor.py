"""Host checks and the network inventory (`ferry doctor`, evidence, GET /api/system).

`network_inventory` lists every network interaction of this installation: the
listener, each configured backend (and DNS for backend host names), and static
facts about what Ferry never does. `run_checks` looks for the configuration
mistakes that matter on a disconnected host: permissive data directory or
secret permissions, trust store problems, backends on non-private addresses,
missing TLS on a non-loopback listener, proxy variables, external URLs in the
console build, telemetry-capable packages, a weakened import policy, a broken
audit chain.

Nothing here touches the network, except `probe_network=True` (opt-in only):
one 2 s TCP connection attempt to each of two public anycast addresses, which
tells whether the host can actually reach the internet. Resolving the host
names of configured backends uses the system resolver, as the gateway does.
"""

from __future__ import annotations

import importlib.metadata
import ipaddress
import os
import re
import socket
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable, Mapping

from . import audit, backends
from .config import Settings
from .errors import FerryError, ValidationFailed
from .trust import load_trust_store

STATIC_DIR = Path(__file__).resolve().parent / "static"
DIRECT_DEPENDENCIES = ("fastapi", "uvicorn", "httpx", "cryptography", "pydantic")
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "SOCKS_PROXY", "SOCKS5_PROXY")
# Packages that can send data off the host when something configures them.
TELEMETRY_PACKAGES = {
    "opentelemetry-sdk": "OpenTelemetry SDK, exports traces, metrics and logs when configured",
    "opentelemetry-distro": "OpenTelemetry auto-instrumentation",
    "sentry-sdk": "Sentry error reporting",
    "ddtrace": "Datadog tracing",
    "datadog": "Datadog client",
    "newrelic": "New Relic agent",
    "elastic-apm": "Elastic APM agent",
    "scout-apm": "Scout APM agent",
    "logfire": "Pydantic Logfire",
    "posthog": "PostHog analytics",
    "segment-analytics-python": "Segment analytics",
    "analytics-python": "Segment analytics",
    "mixpanel": "Mixpanel analytics",
    "bugsnag": "Bugsnag error reporting",
    "rollbar": "Rollbar error reporting",
    "honeybadger": "Honeybadger error reporting",
    "applicationinsights": "Azure Application Insights",
    "azure-monitor-opentelemetry": "Azure Monitor exporter",
}
TELEMETRY_PREFIXES = ("opentelemetry-exporter-",)
# Public anycast resolvers: reachable from almost any connected network, so a
# failed connection is good evidence of isolation. Used only by the opt-in probe.
PROBE_TARGETS: tuple[tuple[str, int], ...] = (("1.1.1.1", 443), ("9.9.9.9", 443))
PROBE_TIMEOUT_S = 2.0
_URL = re.compile(rb"https?://", re.IGNORECASE)
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

Check = dict[str, str]


# --- small helpers -------------------------------------------------------------


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def is_loopback_host(host: str) -> bool:
    name = host.strip().lower().strip("[]").rstrip(".")
    if name in _LOOPBACK_NAMES or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _host_text(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


# --- dependencies --------------------------------------------------------------


def installed_distributions() -> dict[str, str]:
    """Normalized name -> version of every installed distribution."""
    out: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        try:
            name = dist.metadata["Name"]
        except (KeyError, TypeError):
            continue
        if name:
            out.setdefault(_normalize(name), dist.version)
    return out


def _requirement_names(requires: list[str] | None) -> list[tuple[str, bool]]:
    """(name, has_marker) for each requirement that is not tied to an extra."""
    out = []
    for req in requires or []:
        spec, _, marker = req.partition(";")
        if "extra" in marker:
            continue
        m = _REQ_NAME.match(spec)
        if m:
            out.append((m.group(1), bool(marker.strip())))
    return out


def dependencies() -> list[dict[str, str]]:
    """Ferry's runtime dependency closure with the installed versions (for evidence)."""
    try:
        roots = _requirement_names(importlib.metadata.distribution("ferry-airgap").requires)
    except importlib.metadata.PackageNotFoundError:
        roots = [(name, False) for name in DIRECT_DEPENDENCIES]
    seen: dict[str, dict[str, str]] = {}
    queue = list(roots)
    while queue:
        name, conditional = queue.pop(0)
        key = _normalize(name)
        if key in seen:
            continue
        try:
            dist = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            if not conditional:  # a requirement with a marker may simply not apply here
                seen[key] = {"name": name, "version": "not installed"}
            continue
        try:
            shown = dist.metadata["Name"] or name
        except (KeyError, TypeError):
            shown = name
        seen[key] = {"name": shown, "version": dist.version}
        queue.extend(_requirement_names(dist.requires))
    return sorted(seen.values(), key=lambda d: d["name"].lower())


# --- network inventory -------------------------------------------------------------


def _backend_address_note(host: str, allow_public: bool) -> str:
    ip = _ip_literal(host)
    if ip is None:
        rule = "every address it resolves to must be loopback or private" if not allow_public else \
            "public addresses are allowed by gateway.allow_public_backends"
        return f"host name, resolved when used ({rule})"
    problem = backends.address_problem(ip, allow_public)
    return f"address {ip} is {problem}" if problem else f"address {ip} is loopback or private"


def network_inventory(settings: Settings, conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every network interaction of this installation: [{component, direction,
    destination, purpose, configurable, notes}]."""
    server = settings.server
    tls = bool(server.tls_cert_file and server.tls_key_file)
    listener_notes = [f"TLS (certificate {server.tls_cert_file})" if tls else "plain HTTP",
                      "loopback only" if is_loopback_host(server.host) else "reachable from other hosts",
                      "CORS for /v1 from " + ", ".join(server.cors_origins) if server.cors_origins else "CORS off"]
    items: list[dict[str, Any]] = [{
        "component": "gateway listener (ferry serve)",
        "direction": "inbound",
        "destination": f"{_host_text(server.host)}:{server.port}",
        "purpose": "OpenAI-compatible API (/v1), admin API (/api) and the web console (/)",
        "configurable": True,
        "notes": "; ".join(listener_notes),
    }]
    models: dict[int, list[str]] = {}
    for row in conn.execute("SELECT backend_id, model FROM routes ORDER BY model"):
        models.setdefault(int(row["backend_id"]), []).append(row["model"])
    allow_public = settings.gateway.allow_public_backends
    host_names: set[str] = set()
    for row in conn.execute("SELECT id, name, kind, base_url, enabled, auth_token_file FROM backends ORDER BY name"):
        try:
            host = backends.parse_backend_url(row["base_url"]).host
        except ValidationFailed:
            host = ""
        if host and _ip_literal(host) is None:
            host_names.add(host)
        routed = models.get(int(row["id"]), [])
        notes = ["enabled" if row["enabled"] else "disabled",
                 "bearer token configured" if row["auth_token_file"] else "no backend token",
                 _backend_address_note(host, allow_public) if host else "invalid base_url",
                 "proxy variables ignored, redirects not followed"]
        items.append({
            "component": f"backend {row['name']} ({row['kind']})",
            "direction": "outbound",
            "destination": row["base_url"],
            "purpose": "inference requests and health checks" + (f" for {', '.join(routed)}" if routed else
                                                                  " (no routes use it yet)"),
            "configurable": True,
            "notes": "; ".join(notes),
        })
    if host_names:
        items.append({
            "component": "backend name resolution",
            "direction": "outbound (DNS)",
            "destination": "the host's configured resolver",
            "purpose": "resolve " + ", ".join(sorted(host_names)) + " for the egress check (cached 30 s) and the connection",
            "configurable": True,
            "notes": "use IP literals in base_url to avoid DNS lookups",
        })
    items += [
        {"component": "telemetry, crash reporting, update and licence checks", "direction": "none",
         "destination": "none", "purpose": "not implemented in Ferry", "configurable": False,
         "notes": "FastAPI's built-in OpenTelemetry hooks are switched off when the app is created; "
                  "ferry doctor warns about telemetry-capable packages"},
        {"component": "web console assets", "direction": "none", "destination": "none",
         "purpose": "served by the gateway itself from the installed package (ferry/static)", "configurable": False,
         "notes": "no CDN, remote fonts or analytics; ferry doctor checks the files for external URLs"},
        {"component": "local commands (init, verify, import, trust, app, policy, audit, store verify, evidence)",
         "direction": "none", "destination": "none", "purpose": "work on local files and the database only",
         "configurable": False, "notes": "backend check and doctor --probe-network are the only CLI commands "
                                         "that open connections"},
        {"component": "ferry runtime llamacpp", "direction": "loopback", "destination": "127.0.0.1:<port>",
         "purpose": "llama-server on an imported store file with --offline --no-webui and an API key file",
         "configurable": True, "notes": "registered as a backend; reachable only from this host"},
        {"component": "ferry doctor --probe-network", "direction": "outbound (opt-in)",
         "destination": ", ".join(f"{h}:{p}" for h, p in PROBE_TARGETS),
         "purpose": "isolation check: one TCP connection attempt to each, nothing is sent", "configurable": True,
         "notes": "only when --probe-network is given"},
        {"component": "ferry preflight / ferry rehearse (connected side)", "direction": "loopback, plus probes",
         "destination": "127.0.0.1; 192.0.2.1:443 and a DNS lookup of example.com from inside the sandbox",
         "purpose": "prove that a launch command runs with egress blocked", "configurable": False,
         "notes": "the probes are expected to fail; that failure is the evidence that egress was blocked"},
    ]
    return items


# --- checks --------------------------------------------------------------------------


def _check_permissions(settings: Settings, add: Callable[[str, str, str], None]) -> None:
    data = settings.data_dir
    mode = _mode(data)
    if mode is None:
        add("permissions.data_dir", "fail", f"data directory {data} does not exist; run: ferry init --data-dir {data}")
    elif mode & 0o022:
        add("permissions.data_dir", "fail", f"data directory {data} is writable by group or others (mode {mode:04o}); "
                                            f"run: chmod 700 {data}")
    elif mode & 0o077:
        add("permissions.data_dir", "warn", f"data directory {data} is readable by group or others (mode {mode:04o}); "
                                            "expected 0700")
    else:
        add("permissions.data_dir", "pass", f"data directory {data} is private (mode {mode:04o})")

    db_mode = _mode(settings.db_path)
    if db_mode is None:
        add("permissions.database", "warn", f"no database at {settings.db_path}; run ferry init")
    elif db_mode & 0o022:
        add("permissions.database", "fail", f"database {settings.db_path} is writable by group or others "
                                            f"(mode {db_mode:04o}); run: chmod 600 {settings.db_path}")
    elif db_mode & 0o077:
        add("permissions.database", "warn", f"database {settings.db_path} is readable by group or others "
                                            f"(mode {db_mode:04o}); expected 0600")
    else:
        add("permissions.database", "pass", f"database is private (mode {db_mode:04o})")

    secrets_dir = settings.secrets_dir
    sec_mode = _mode(secrets_dir)
    if sec_mode is None:
        add("permissions.secrets", "pass", "no secrets directory (no backend token files are stored by Ferry)")
        return
    problems = []
    if sec_mode & 0o077:
        problems.append(f"{secrets_dir} is accessible by group or others (mode {sec_mode:04o})")
    files = 0
    try:
        entries = sorted(os.scandir(secrets_dir), key=lambda e: e.name)
    except OSError as exc:
        add("permissions.secrets", "fail", f"cannot list {secrets_dir}: {exc.strerror}")
        return
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        files += 1
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            problems.append(f"{entry.name} is not a regular file")
        elif stat.S_IMODE(st.st_mode) & 0o077:
            problems.append(f"{entry.name} is accessible by group or others (mode {stat.S_IMODE(st.st_mode):04o})")
    if problems:
        add("permissions.secrets", "fail", "secret files are not private: " + "; ".join(problems[:10])
            + f"; run: chmod 700 {secrets_dir} && chmod 600 {secrets_dir}/*")
    else:
        add("permissions.secrets", "pass", f"{files} secret file(s) in {secrets_dir}, all private")


def _check_trust(settings: Settings, add: Callable[[str, str, str], None]) -> None:
    store = load_trust_store(settings.trust_dir)
    active = [e for e in store.entries if e.status() == "active"]
    if store.problems:
        shown = "; ".join(store.problems[:5]) + (f" (and {len(store.problems) - 5} more)" if len(store.problems) > 5 else "")
        add("trust.store", "warn", f"{len(store.problems)} trust store problem(s): {shown}")
    elif not active:
        add("trust.store", "warn", f"no active trusted keys in {settings.trust_dir}: every bundle is rejected until "
                                   "keys are added with: ferry trust add PEM --name N --role R")
    else:
        add("trust.store", "pass", f"{len(active)} active trusted key(s) in {settings.trust_dir}")


def _check_backends(settings: Settings, conn: sqlite3.Connection, add: Callable[[str, str, str], None]) -> None:
    rows = conn.execute("SELECT name, base_url FROM backends ORDER BY name").fetchall()
    if not rows:
        add("backends.addresses", "pass", "no backends are configured")
        return
    failures, warnings = [], []
    for row in rows:
        try:
            parsed = backends.parse_backend_url(row["base_url"])
            addresses = backends.resolve_host(parsed.host, parsed.port)
        except FerryError as exc:
            warnings.append(f"{row['name']}: {exc.message}")
            continue
        for text in addresses:
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                failures.append(f"{row['name']}: resolves to something that is not an IP address")
                continue
            strict = backends.address_problem(ip, False)
            if strict is None:
                continue
            if backends.address_problem(ip, True) is None and settings.gateway.allow_public_backends:
                warnings.append(f"{row['name']} resolves to public address {ip} (allowed by gateway.allow_public_backends)")
            else:
                failures.append(f"{row['name']} resolves to {ip}, {strict}")
    if failures:
        add("backends.addresses", "fail", "backends on addresses the egress rules refuse: " + "; ".join(failures))
    elif warnings:
        add("backends.addresses", "warn", "; ".join(warnings))
    else:
        add("backends.addresses", "pass", f"all {len(rows)} backend(s) resolve to loopback or private addresses")


def _check_tls(settings: Settings, add: Callable[[str, str, str], None]) -> None:
    server = settings.server
    if server.tls_cert_file and server.tls_key_file:
        problems = [f"{f} is not a readable file" for f in (server.tls_cert_file, server.tls_key_file)
                    if not (os.path.isfile(f) and os.access(f, os.R_OK))]
        if problems:
            add("tls", "fail", "TLS is configured but " + "; ".join(problems))
            return
        key_mode = _mode(Path(server.tls_key_file))
        if key_mode is not None and key_mode & 0o077:
            add("tls", "warn", f"TLS key {server.tls_key_file} is accessible by group or others (mode {key_mode:04o}); "
                               f"run: chmod 600 {server.tls_key_file}")
            return
        add("tls", "pass", f"TLS is configured (certificate {server.tls_cert_file})")
    elif is_loopback_host(server.host):
        add("tls", "pass", f"plain HTTP on loopback only ({server.host}); configure tls_cert_file and tls_key_file "
                           "before listening on other interfaces")
    else:
        add("tls", "warn", f"the gateway listens on {server.host} without TLS: API keys, console sessions, prompts and "
                           "completions would cross the network unencrypted; set [server] tls_cert_file and tls_key_file")


def _check_proxy(environ: Mapping[str, str], add: Callable[[str, str, str], None]) -> None:
    # Only the names are reported: proxy URLs can carry credentials.
    present = sorted({name for name in environ if name.upper() in PROXY_VARIABLES})
    if present:
        add("proxy.environment", "warn", f"proxy variable(s) set: {', '.join(present)}. Ferry ignores them (its HTTP "
                                         "client uses trust_env=False), but other tools on this host may not")
    else:
        add("proxy.environment", "pass", "no proxy environment variables are set")


def scan_static(static_dir: Path) -> list[str]:
    """Console build files that contain an http:// or https:// reference."""
    offenders = []
    for path in sorted(p for p in static_dir.rglob("*") if p.is_file()):
        try:
            if _URL.search(path.read_bytes()):
                offenders.append(path.relative_to(static_dir).as_posix())
        except OSError:
            offenders.append(f"{path.relative_to(static_dir).as_posix()} (unreadable)")
    return offenders


def _check_static(static_dir: Path, add: Callable[[str, str, str], None]) -> None:
    if not (static_dir / "index.html").is_file():
        add("console.assets", "warn", f"the web console is not built ({static_dir}/index.html is missing); the API and "
                                      "the command line still work")
        return
    offenders = scan_static(static_dir)
    count = sum(1 for p in static_dir.rglob("*") if p.is_file())
    if offenders:
        add("console.assets", "fail", "console files reference external URLs (a browser would try to fetch them): "
            + ", ".join(offenders[:10]))
    else:
        add("console.assets", "pass", f"{count} console file(s), no http:// or https:// references")


def _check_telemetry(add: Callable[[str, str, str], None]) -> None:
    names = installed_distributions()
    found = [f"{name} ({TELEMETRY_PACKAGES.get(name, 'OpenTelemetry exporter')})" for name in sorted(names)
             if name in TELEMETRY_PACKAGES or name.startswith(TELEMETRY_PREFIXES)]
    if found:
        add("telemetry.packages", "warn", "telemetry-capable package(s) installed: " + ", ".join(found)
            + ". Ferry does not use them and switches FastAPI's telemetry hooks off; remove them from this "
              "environment or make sure nothing configures them")
        return
    note = (" (opentelemetry-api is present: it is the API only, required by FastAPI, and records and sends nothing "
            "without an SDK)") if "opentelemetry-api" in names else ""
    add("telemetry.packages", "pass", "no telemetry-capable packages are installed" + note)


def _check_import_policy(settings: Settings, add: Callable[[str, str, str], None]) -> None:
    i = settings.imports
    warnings = []
    if i.allow_pickle:
        warnings.append("allow_pickle is true: pickle-based weights can run code when they are loaded")
    if i.allow_executables:
        warnings.append("allow_executables is true")
    if "file" in i.allowed_kinds:
        warnings.append("kind 'file' is allowed, which admits nested archives")
    if settings.gateway.allow_public_backends:
        warnings.append("gateway.allow_public_backends is true: backends may be on public addresses")
    if warnings:
        add("config.policy", "warn", "weakened settings in ferry.toml: " + "; ".join(warnings))
    else:
        add("config.policy", "pass", f"import requires signer role(s) {', '.join(i.required_roles)}"
                                     f"{' from distinct keys' if i.distinct_signers else ''}; pickle, executables and "
                                     "public backends are refused")


def _check_admins(conn: sqlite3.Connection, add: Callable[[str, str, str], None]) -> None:
    count = conn.execute("SELECT COUNT(*) AS n FROM admin_users WHERE role = 'admin' AND disabled = 0").fetchone()["n"]
    if count:
        add("console.admins", "pass", f"{count} console admin user(s)")
    else:
        add("console.admins", "warn", "no console admin user; create one on the host with: "
                                      "ferry admin create-user NAME --role admin --password-stdin")


def _check_audit(conn: sqlite3.Connection, add: Callable[[str, str, str], None]) -> None:
    result = audit.verify_chain(conn)
    if result["ok"]:
        add("audit.chain", "pass", f"audit chain intact: {result['events_checked']} event(s), head #{result['head_seq']}")
    else:
        add("audit.chain", "fail", f"audit chain broken at event #{result['first_bad_seq']}: {result['problem']}")


def tcp_connect(address: tuple[str, int], timeout: float) -> str | None:
    """None if a TCP connection to `address` succeeded, else why it failed."""
    try:
        with socket.create_connection(address, timeout=timeout):
            return None
    except TimeoutError:
        return "timed out"
    except OSError as exc:
        return exc.strerror or type(exc).__name__


def _check_isolation(add: Callable[[str, str, str], None]) -> None:
    results = [(f"{host}:{port}", tcp_connect((host, port), PROBE_TIMEOUT_S)) for host, port in PROBE_TARGETS]
    reached = [target for target, error in results if error is None]
    if reached:
        add("network.isolation", "fail", f"this host is NOT isolated: a TCP connection to {reached[0]} succeeded")
    else:
        add("network.isolation", "pass", "no public address was reachable ("
            + "; ".join(f"{target}: {error}" for target, error in results) + ")")


def run_checks(settings: Settings, conn: sqlite3.Connection, probe_network: bool = False, *,
               static_dir: Path | None = None, environ: Mapping[str, str] | None = None) -> list[Check]:
    """[{id, status: pass|warn|fail, message}] for this host and configuration."""
    checks: list[Check] = []

    def add(check_id: str, status: str, message: str) -> None:
        checks.append({"id": check_id, "status": status, "message": message})

    _check_permissions(settings, add)
    _check_trust(settings, add)
    _check_backends(settings, conn, add)
    _check_tls(settings, add)
    _check_proxy(os.environ if environ is None else environ, add)
    _check_static(static_dir or STATIC_DIR, add)
    _check_telemetry(add)
    _check_import_policy(settings, add)
    _check_admins(conn, add)
    _check_audit(conn, add)
    if probe_network:
        _check_isolation(add)
    return checks
