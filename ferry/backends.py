"""Inference backends and model routes: egress guard, credentials, health, provenance.

A backend is an inference server (llama.cpp, Ollama, or anything that speaks the
OpenAI API) on a loopback or private address. A route maps a public model name
to one backend and can pin the digest of an imported model artifact. For
llama.cpp the health check reads /props to learn which file the server loaded;
a file in Ferry's content-addressed store is named by its digest, so the gateway
can tell whether the backend serves exactly the pinned file.

That check catches misconfiguration (wrong file, wrong server), not a hostile
backend, which can report anything. llama-server ignores the "model" field of a
request and answers with whatever it has loaded, so routing and authorization
are decided before a request is forwarded.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import stat
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

import httpx

from . import audit
from .config import Settings
from .db import write_tx
from .errors import ConfigError, Conflict, FerryError, NotFound, ValidationFailed
from .policy import MODEL_NAME
from .util import canonical_json, parse_rfc3339, rfc3339, utc_now

if TYPE_CHECKING:
    from .gateway.state import GatewayState

log = logging.getLogger("ferry.backends")

KINDS = ("llamacpp", "ollama", "openai")
BACKEND_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
UPSTREAM_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DNS_CACHE_TTL_S = 30.0
MAX_URL_CHARS = 2048
MAX_TOKEN_FILE_BYTES = 8192
_TOKEN_CHARS = re.compile(r"^[\x21-\x7e]{1,4096}$")
HEALTH_TIMEOUT_S = 15.0
HEALTH_DEADLINE_FACTOR = 2
"""A whole check (every probe of one backend) must finish within this many
HEALTH_TIMEOUT_S; the read timeout alone cannot stop a server that trickles bytes."""
STALE_STATUS_FACTOR = 3
"""While health checks run, a status older than this many health intervals no
longer counts: the route is treated as unchecked rather than served on old news."""
HEALTH_BODY_LIMIT = 1024 * 1024
MAX_LISTED_MODELS = 200
DEFAULT_MAX_CONCURRENCY = 4
HEALTH_STATES = ("up", "down", "loading")
_HEALTH_OUTCOME = {"up": "success", "loading": "unavailable", "down": "failure"}
_HOST_NAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$")
# Cloud metadata endpoints. Two of them sit in ranges that are otherwise private
# or public, so they are refused by address whatever allow_public_backends says.
_METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"))
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class EgressDenied(ValidationFailed):
    """A backend address that the egress rules do not allow."""

    code = "egress_denied"


# --- egress guard ------------------------------------------------------------


@dataclass(frozen=True)
class BackendURL:
    scheme: str
    host: str
    """Lowercase host name or IP address (IPv6 without brackets)."""
    port: int
    base_url: str
    """Normalized: scheme://host[:port], no trailing slash."""


@dataclass(frozen=True)
class CheckedURL:
    base_url: str
    host: str
    port: int
    addresses: tuple[str, ...]


def parse_backend_url(url: object) -> BackendURL:
    """Syntax rules for base_url: http(s), a host, no credentials, query, fragment or path."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise ValidationFailed(f"base_url must be a URL of at most {MAX_URL_CHARS} characters",
                               details={"field": "base_url"})
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url) or "\\" in url:
        raise ValidationFailed("base_url must not contain spaces, control characters or backslashes",
                               details={"field": "base_url"})
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValidationFailed("base_url is not a valid URL (check the host and port)",
                               details={"field": "base_url"}) from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValidationFailed("base_url must start with http:// or https://", details={"field": "base_url"})
    if "@" in parts.netloc:
        raise ValidationFailed("base_url must not contain a user name or password; put the backend token in "
                               "auth_token_file", details={"field": "base_url"})
    if "?" in url or parts.query:
        raise ValidationFailed("base_url must not have a query string", details={"field": "base_url"})
    if "#" in url or parts.fragment:
        raise ValidationFailed("base_url must not have a fragment", details={"field": "base_url"})
    if parts.path not in ("", "/"):
        raise ValidationFailed("base_url must be the server root, e.g. http://127.0.0.1:8080 (no path such as /v1)",
                               details={"field": "base_url"})
    host = parts.hostname
    if not host:
        raise ValidationFailed("base_url needs a host", details={"field": "base_url"})
    if port == 0:
        raise ValidationFailed("base_url has an invalid port", details={"field": "base_url"})
    if "[" in parts.netloc:
        if "%" in host:
            raise ValidationFailed("base_url: IPv6 zone ids are not supported", details={"field": "base_url"})
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            raise ValidationFailed("base_url has an invalid IPv6 address", details={"field": "base_url"}) from None
        host = ip6.compressed
        host_text = f"[{host}]"
    else:
        if not _HOST_NAME.fullmatch(host):
            raise ValidationFailed("base_url has an invalid host name", details={"field": "base_url"})
        host_text = host
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    base = f"{scheme}://{host_text}" + (f":{port}" if port is not None else "")
    return BackendURL(scheme=scheme, host=host, port=effective_port, base_url=base)


def address_problem(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_public: bool) -> str | None:
    """Why an address may not be a backend, or None if it may.

    Loopback and private addresses are allowed. Link-local (which includes the
    169.254.169.254 metadata service), multicast, unspecified, reserved and
    metadata addresses never are. Anything else counts as public and needs
    gateway.allow_public_backends = true. So do 6to4 (2002::/16) and Teredo
    (2001::/32): ipaddress calls them private, but they are relayed over the
    public IPv4 internet."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in _METADATA_ADDRESSES:
        return "a cloud metadata service address"
    if ip.is_unspecified or (ip.version == 4 and ip in _THIS_NETWORK):
        return "an unspecified address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_loopback:
        return None
    if ip.is_reserved:
        return "a reserved address"
    if isinstance(ip, ipaddress.IPv6Address) and (ip.sixtofour is not None or ip.teredo is not None):
        if allow_public:
            return None
        return ("a 6to4 or Teredo address, relayed over the public internet (set gateway.allow_public_backends = "
                "true in ferry.toml on the host to allow it)")
    if ip.is_private:
        return None
    if allow_public:
        return None
    return "a public address (set gateway.allow_public_backends = true in ferry.toml on the host to allow it)"


def resolve_host(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
        raise EgressDenied(f"cannot resolve backend host '{host}': {detail}", details={"field": "base_url"}) from None
    addresses = sorted({str(info[4][0]).split("%", 1)[0] for info in infos})
    if not addresses:
        raise EgressDenied(f"backend host '{host}' did not resolve to any address", details={"field": "base_url"})
    return tuple(addresses)


def _check_addresses(parsed: BackendURL, addresses: tuple[str, ...], allow_public: bool) -> CheckedURL:
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            raise EgressDenied(f"backend host '{parsed.host}' resolved to something that is not an IP address",
                               details={"field": "base_url"}) from None
        problem = address_problem(ip, allow_public)
        if problem:
            # Every address must pass: a name with one private and one public
            # address could otherwise send traffic out of the enclave.
            raise EgressDenied(f"backend host '{parsed.host}' resolves to {ip}, {problem}",
                               details={"field": "base_url", "address": str(ip)})
    return CheckedURL(base_url=parsed.base_url, host=parsed.host, port=parsed.port, addresses=addresses)


def check_backend_url(url: object, allow_public: bool = False) -> CheckedURL:
    """Egress guard: validate `url` and resolve its host now; every address must be allowed."""
    parsed = parse_backend_url(url)
    return _check_addresses(parsed, resolve_host(parsed.host, parsed.port), allow_public)


class EgressGuard:
    """check_backend_url with resolutions cached for `ttl_s`, for the per-request
    re-check. Only resolutions are cached; the address rules run every time."""

    def __init__(self, allow_public: bool, *, ttl_s: float = DNS_CACHE_TTL_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.allow_public = allow_public
        self.ttl_s = ttl_s
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, int], tuple[float, tuple[str, ...]]] = {}

    def _cached(self, host: str, port: int) -> tuple[str, ...] | None:
        with self._lock:
            hit = self._cache.get((host, port))
            if hit is not None and hit[0] > self._clock():
                return hit[1]
        return None

    def _store(self, host: str, port: int, addresses: tuple[str, ...]) -> None:
        with self._lock:
            if len(self._cache) > 1024:
                self._cache.clear()
            self._cache[(host, port)] = (self._clock() + self.ttl_s, addresses)

    def check(self, url: object) -> CheckedURL:
        parsed = parse_backend_url(url)
        addresses = self._cached(parsed.host, parsed.port)
        if addresses is None:
            addresses = resolve_host(parsed.host, parsed.port)
            self._store(parsed.host, parsed.port, addresses)
        return _check_addresses(parsed, addresses, self.allow_public)

    async def acheck(self, url: object) -> CheckedURL:
        """Like check(), but resolves in a worker thread so DNS never blocks the event loop."""
        parsed = parse_backend_url(url)
        addresses = self._cached(parsed.host, parsed.port)
        if addresses is None:
            addresses = await asyncio.to_thread(resolve_host, parsed.host, parsed.port)
            self._store(parsed.host, parsed.port, addresses)
        return _check_addresses(parsed, addresses, self.allow_public)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# --- credentials -------------------------------------------------------------


def read_token_file(path: str | os.PathLike[str]) -> str:
    """The bearer token on the first line of `path`. Read at use time, so a rotated
    token takes effect without a restart. Refuses symlinks, non-regular files and
    files that group or other users can access. Errors never include file content."""
    p = Path(path)
    if not p.is_absolute():
        raise ConfigError(f"token file path must be absolute: {p}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(p, flags)
    except FileNotFoundError:
        raise ConfigError(f"token file {p} does not exist") from None
    except OSError as exc:
        raise ConfigError(f"cannot open token file {p}: {exc.strerror or type(exc).__name__} "
                          "(symlinks are not followed)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"token file {p} is not a regular file")
        if st.st_mode & 0o077:
            raise ConfigError(f"token file {p} is accessible by group or other users "
                              f"(mode {stat.S_IMODE(st.st_mode):04o}); run: chmod 600 {p}")
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_TOKEN_FILE_BYTES:
            chunk = os.read(fd, MAX_TOKEN_FILE_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_TOKEN_FILE_BYTES:
        raise ConfigError(f"token file {p} is larger than {MAX_TOKEN_FILE_BYTES} bytes")
    first = data.split(b"\n", 1)[0].strip()
    try:
        token = first.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError(f"token file {p}: the first line must be an ASCII token") from None
    if not _TOKEN_CHARS.fullmatch(token):
        raise ConfigError(f"token file {p}: the first line must be a non-empty token without spaces")
    return token


def _check_token_path(settings: Settings, value: object, actor_type: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ValidationFailed("auth_token_file must be an absolute file path", details={"field": "auth_token_file"})
    path = Path(value)
    if not path.is_absolute():
        raise ValidationFailed("auth_token_file must be an absolute file path", details={"field": "auth_token_file"})
    if actor_type == "admin":
        # Console admins may only point at token files under the data directory's
        # secrets folder: otherwise a console user could make the gateway send the
        # first line of any file it can read to a server of their choosing.
        secrets_dir = settings.secrets_dir.resolve()
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError):
            resolved = path
        if secrets_dir not in resolved.parents:
            raise ValidationFailed(f"auth_token_file must be inside {secrets_dir} when set from the console; "
                                   "use the CLI on the host for other locations", details={"field": "auth_token_file"})
    try:
        read_token_file(path)
    except ConfigError as exc:
        raise ValidationFailed(exc.message, details={"field": "auth_token_file"}) from None
    return str(path)


# --- backends ----------------------------------------------------------------


def _json_or_none(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _backend_public(row: sqlite3.Row) -> dict[str, Any]:
    """What APIs may show: the token file path and token are never included."""
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "base_url": row["base_url"],
        "has_token": bool(row["auth_token_file"]),
        "timeout_s": row["timeout_s"],
        "max_concurrency": row["max_concurrency"],
        "enabled": bool(row["enabled"]),
        "last_status": _json_or_none(row["last_status"]),
        "last_checked_at": row["last_checked_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _backend_row(conn: sqlite3.Connection, backend_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)).fetchone()
    if row is None:
        raise NotFound(f"backend {backend_id} does not exist")
    return row


def get_backend(conn: sqlite3.Connection, backend_id: int) -> dict[str, Any]:
    return _backend_public(_backend_row(conn, backend_id))


def get_backend_by_name(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM backends WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise NotFound(f"backend '{name}' does not exist")
    return _backend_public(row)


def backend_for_check(conn: sqlite3.Connection, backend_id: int) -> dict[str, Any]:
    """Internal view for health checks and the gateway (includes the token file path)."""
    return dict(_backend_row(conn, backend_id))


def list_backends(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [_backend_public(r) for r in conn.execute("SELECT * FROM backends ORDER BY name")]


def _check_kind(kind: object) -> str:
    if kind not in KINDS:
        raise ValidationFailed(f"kind must be one of: {', '.join(KINDS)}", details={"field": "kind"})
    return str(kind)


def _check_backend_name(name: object) -> str:
    if not isinstance(name, str) or not BACKEND_NAME.fullmatch(name):
        raise ValidationFailed("backend name must be 1-160 characters: letters, digits, '.', '_', ':' or '-'",
                               details={"field": "name"})
    return name


def _check_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 3600:
        raise ValidationFailed("timeout_s must be a number of seconds greater than 0 and at most 3600",
                               details={"field": "timeout_s"})
    return float(value)


def _check_concurrency(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1024:
        raise ValidationFailed("max_concurrency must be a whole number from 1 to 1024",
                               details={"field": "max_concurrency"})
    return value


def _check_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationFailed(f"{name} must be true or false", details={"field": name})
    return value


def _check_backend_id(value: object) -> int:
    # Ids are SQLite INTEGERs (signed 64-bit): a value outside that range names no
    # backend and would fail to bind (OverflowError, a 500) instead of a clean error.
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**63) <= value < 2**63:
        raise ValidationFailed("backend_id must be a backend id", details={"field": "backend_id"})
    return value


def _backend_audit(row: sqlite3.Row) -> dict[str, Any]:
    # "token_configured", not "has_token": audit.sanitize redacts any key ending in "_token".
    return {"backend_id": row["id"], "name": row["name"], "kind": row["kind"], "base_url": row["base_url"],
            "token_configured": bool(row["auth_token_file"]), "timeout_s": row["timeout_s"],
            "max_concurrency": row["max_concurrency"], "enabled": bool(row["enabled"])}


def create_backend(conn: sqlite3.Connection, settings: Settings, *, name: str, kind: str, base_url: str,
                   auth_token_file: str | None = None, timeout_s: float | None = None,
                   max_concurrency: int | None = None, enabled: bool = True,
                   actor_type: str, actor_id: str) -> dict[str, Any]:
    """Register a backend. The URL must pass the egress guard now (it is checked
    again before every request) and a token file must already be readable."""
    name = _check_backend_name(name)
    kind = _check_kind(kind)
    url = check_backend_url(base_url, settings.gateway.allow_public_backends).base_url
    token_file = _check_token_path(settings, auth_token_file, actor_type) if auth_token_file else None
    timeout = _check_timeout(timeout_s if timeout_s is not None else settings.gateway.read_timeout_s)
    concurrency = _check_concurrency(max_concurrency if max_concurrency is not None else DEFAULT_MAX_CONCURRENCY)
    enabled = _check_bool(enabled, "enabled")
    now = rfc3339()
    with write_tx(conn):
        if conn.execute("SELECT 1 FROM backends WHERE name = ?", (name,)).fetchone():
            raise Conflict(f"a backend named '{name}' already exists")
        cur = conn.execute(
            "INSERT INTO backends (name, kind, base_url, auth_token_file, timeout_s, max_concurrency, enabled,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, kind, url, token_file, timeout, concurrency, int(enabled), now, now),
        )
        row = _backend_row(conn, int(cur.lastrowid or 0))
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backend.create",
                           resource=f"backend:{name}", outcome="success", details=_backend_audit(row))
    return _backend_public(row)


_BACKEND_FIELDS = frozenset({"name", "kind", "base_url", "auth_token_file", "timeout_s", "max_concurrency", "enabled"})
# Changing any of these makes the last health status describe a different server.
_RESETS_STATUS = frozenset({"kind", "base_url", "auth_token_file"})


def update_backend(conn: sqlite3.Connection, settings: Settings, backend_id: int, changes: Mapping[str, Any], *,
                   actor_type: str, actor_id: str) -> dict[str, Any]:
    """PATCH semantics: only the given fields change; auth_token_file None or "" removes the token."""
    unknown = sorted(set(changes) - _BACKEND_FIELDS)
    if unknown:
        raise ValidationFailed(f"unknown backend field(s): {', '.join(unknown)}")
    if not changes:
        raise ValidationFailed("nothing to change")
    values: dict[str, Any] = {}
    if "name" in changes:
        values["name"] = _check_backend_name(changes["name"])
    if "kind" in changes:
        values["kind"] = _check_kind(changes["kind"])
    if "base_url" in changes:
        values["base_url"] = check_backend_url(changes["base_url"], settings.gateway.allow_public_backends).base_url
    if "auth_token_file" in changes:
        token = changes["auth_token_file"]
        values["auth_token_file"] = _check_token_path(settings, token, actor_type) if token else None
    if "timeout_s" in changes:
        values["timeout_s"] = _check_timeout(changes["timeout_s"])
    if "max_concurrency" in changes:
        values["max_concurrency"] = _check_concurrency(changes["max_concurrency"])
    if "enabled" in changes:
        values["enabled"] = int(_check_bool(changes["enabled"], "enabled"))
    with write_tx(conn):
        row = _backend_row(conn, backend_id)
        changed = sorted(k for k, v in values.items() if row[k] != v)
        if "name" in changed and conn.execute("SELECT 1 FROM backends WHERE name = ? AND id != ?",
                                              (values["name"], backend_id)).fetchone():
            raise Conflict(f"a backend named '{values['name']}' already exists")
        if changed:
            sets = [f"{k} = ?" for k in changed] + ["updated_at = ?"]
            params: list[Any] = [values[k] for k in changed] + [rfc3339()]
            if _RESETS_STATUS & set(changed):
                sets += ["last_status = NULL", "last_checked_at = NULL"]
            # Column names come from _BACKEND_FIELDS, never from the caller.
            conn.execute(f"UPDATE backends SET {', '.join(sets)} WHERE id = ?", (*params, backend_id))
            updated = _backend_row(conn, backend_id)
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backend.update",
                               resource=f"backend:{updated['name']}", outcome="success",
                               details={**_backend_audit(updated), "changed": changed,
                                        "status_reset": bool(_RESETS_STATUS & set(changed))})
            row = updated
    return _backend_public(row)


def delete_backend(conn: sqlite3.Connection, backend_id: int, *, actor_type: str, actor_id: str) -> None:
    with write_tx(conn):
        row = _backend_row(conn, backend_id)
        users = [r["model"] for r in conn.execute("SELECT model FROM routes WHERE backend_id = ? ORDER BY model",
                                                  (backend_id,))]
        if users:
            raise Conflict(f"backend '{row['name']}' is used by route(s): {', '.join(users)}; delete or move them first",
                           details={"routes": users})
        conn.execute("DELETE FROM backends WHERE id = ?", (backend_id,))
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backend.delete",
                           resource=f"backend:{row['name']}", outcome="success", details=_backend_audit(row))


# --- provenance and availability --------------------------------------------


def store_digest_for_path(settings: Settings, path: object) -> str | None:
    """The digest of `path` if it resolves to a file in this host's store
    (<store_dir>/sha256/<digest>), else None. Relative paths prove nothing."""
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > 4096:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        store = (settings.store_dir / "sha256").resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if resolved.parent != store or not DIGEST.fullmatch(resolved.name) or not resolved.is_file():
        return None
    return resolved.name


def normalize_digest(value: object) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    if text.startswith("sha256:"):
        text = text[len("sha256:"):]
    if not DIGEST.fullmatch(text):
        raise ValidationFailed("artifact_digest must be a SHA-256 digest (64 hex characters, optionally 'sha256:')",
                               details={"field": "artifact_digest"})
    return text


def evaluate_provenance(artifact_digest: str | None, status: Mapping[str, Any] | None) -> dict[str, Any]:
    """{state, detail, served_digest} for a route pin against a backend's last status.

    verified: the backend serves a store file whose digest is the pin. mismatch:
    it serves a different store file. unverified: it cannot say, or serves a file
    outside the store. not_pinned: the route has no pin. unknown: the backend is
    not up (or was never checked), so there is nothing to compare."""
    if not artifact_digest:
        return {"state": "not_pinned", "detail": "the route is not pinned to an imported artifact",
                "served_digest": None}
    if not status or status.get("state") != "up":
        state = status.get("state") if status else None
        return {"state": "unknown", "detail": f"backend is {state}" if state else "backend has not been checked yet",
                "served_digest": None}
    served = [s for s in status.get("served") or [] if isinstance(s, Mapping)]
    digests = [s.get("digest") for s in served if isinstance(s.get("digest"), str)]
    if artifact_digest in digests:
        return {"state": "verified", "detail": "backend serves the pinned file from the store",
                "served_digest": artifact_digest}
    if digests:
        return {"state": "mismatch",
                "detail": f"backend serves sha256:{digests[0][:16]}…, the route is pinned to sha256:{artifact_digest[:16]}…",
                "served_digest": digests[0]}
    if served:
        return {"state": "unverified", "detail": "backend serves a file that is not in the Ferry store",
                "served_digest": None}
    return {"state": "unverified", "detail": "backend does not report which model file it serves",
            "served_digest": None}


@dataclass(frozen=True)
class Availability:
    available: bool
    code: str
    """ok, route_disabled, backend_disabled, backend_unchecked, backend_down, backend_loading or provenance."""
    reason: str
    provenance: dict[str, Any]


def status_max_age_s(settings: Settings) -> float | None:
    """How old a stored backend status may be before routes stop trusting it:
    STALE_STATUS_FACTOR health intervals, or None when health checks are disabled
    (then statuses only change on a manual check and never go stale)."""
    interval = settings.gateway.health_interval_s
    return interval * STALE_STATUS_FACTOR if interval > 0 else None


def _status_age_s(status: Mapping[str, Any]) -> float | None:
    checked_at = status.get("checked_at")
    if not isinstance(checked_at, str):
        return None
    try:
        return (utc_now() - parse_rfc3339(checked_at)).total_seconds()
    except (ValueError, IndexError):
        return None


def route_availability(route: Mapping[str, Any], backend: Mapping[str, Any], *,
                       max_age_s: float | None = None) -> Availability:
    """`available` = route enabled, backend enabled and up, and (require_verified
    false or provenance verified). With `max_age_s` (see status_max_age_s), a
    status checked longer ago than that, or with no readable check time, counts
    as unchecked: the health loop has stalled and the backend may have changed."""
    raw = backend.get("last_status")
    status = _json_or_none(raw) if isinstance(raw, str) else raw
    age = _status_age_s(status) if status and max_age_s is not None else None
    stale = bool(status) and max_age_s is not None and (age is None or age > max_age_s)
    provenance = evaluate_provenance(route.get("artifact_digest"), None if stale else status)

    def no(code: str, reason: str) -> Availability:
        return Availability(False, code, reason, provenance)

    if not route.get("enabled"):
        return no("route_disabled", "the route is disabled")
    if not backend.get("enabled"):
        return no("backend_disabled", "the backend is disabled")
    if not status:
        return no("backend_unchecked", "the backend has not been health-checked yet")
    if stale:
        when = "at an unknown time" if age is None else f"{int(age)} s ago"
        return no("backend_unchecked",
                  f"the backend was last health-checked {when}, more than the {max_age_s:g} s allowed; "
                  "check the gateway log for a stuck health check, or run a check from the console")
    if status.get("state") == "loading":
        return no("backend_loading", "the backend is still loading the model")
    if status.get("state") != "up":
        return no("backend_down", "the backend is down")
    if route.get("require_verified") and provenance["state"] != "verified":
        return no("provenance", f"provenance is {provenance['state']}: {provenance['detail']}")
    return Availability(True, "ok", "", provenance)


# --- routes ------------------------------------------------------------------


_ROUTE_SELECT = (
    "SELECT r.*, b.name AS backend_name, b.kind AS backend_kind, b.base_url AS base_url,"
    " b.auth_token_file AS auth_token_file, b.timeout_s AS timeout_s, b.max_concurrency AS max_concurrency,"
    " b.enabled AS backend_enabled, b.last_status AS last_status"
    " FROM routes r JOIN backends b ON b.id = r.backend_id"
)


def _route_view(row: sqlite3.Row, max_age_s: float | None = None) -> dict[str, Any]:
    backend = {"enabled": row["backend_enabled"], "last_status": row["last_status"]}
    avail = route_availability(dict(row), backend, max_age_s=max_age_s)
    return {
        "id": row["id"],
        "model": row["model"],
        "backend_id": row["backend_id"],
        "backend_name": row["backend_name"],
        "upstream_model": row["upstream_model"],
        "artifact_digest": row["artifact_digest"],
        "require_verified": bool(row["require_verified"]),
        "enabled": bool(row["enabled"]),
        "provenance": avail.provenance,
        "available": avail.available,
        "reason": avail.reason,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_routes(conn: sqlite3.Connection, *, max_age_s: float | None = None) -> list[dict[str, Any]]:
    """`max_age_s`: see route_availability; the running gateway passes it so the
    console shows what serving would do."""
    return [_route_view(r, max_age_s) for r in conn.execute(_ROUTE_SELECT + " ORDER BY r.model")]


def get_route(conn: sqlite3.Connection, route_id: int, *, max_age_s: float | None = None) -> dict[str, Any]:
    row = conn.execute(_ROUTE_SELECT + " WHERE r.id = ?", (route_id,)).fetchone()
    if row is None:
        raise NotFound(f"route {route_id} does not exist")
    return _route_view(row, max_age_s)


def route_for_model(conn: sqlite3.Connection, model: str) -> dict[str, Any] | None:
    """Internal view for the gateway: route joined with everything needed to call
    its backend (including the token file path). None if the model has no route."""
    row = conn.execute(_ROUTE_SELECT + " WHERE r.model = ?", (model,)).fetchone()
    return dict(row) if row is not None else None


def _check_model(value: object) -> str:
    if not isinstance(value, str) or not MODEL_NAME.fullmatch(value):
        raise ValidationFailed("model must be 1-128 characters: letters, digits, '.', '_', ':' or '-'",
                               details={"field": "model"})
    return value


def _check_upstream_model(value: object) -> str:
    if not isinstance(value, str) or not UPSTREAM_MODEL.fullmatch(value):
        raise ValidationFailed("upstream_model must be 1-256 characters: letters, digits and . _ : / @ + -",
                               details={"field": "upstream_model"})
    return value


def _check_pin(conn: sqlite3.Connection, value: object) -> str:
    digest = normalize_digest(value)
    row = conn.execute("SELECT kind FROM artifacts WHERE digest = ?", (digest,)).fetchone()
    if row is None:
        raise ValidationFailed(f"artifact sha256:{digest} has not been imported", details={"field": "artifact_digest"})
    if row["kind"] != "model":
        raise ValidationFailed(f"artifact sha256:{digest} is a {row['kind']}, not a model",
                               details={"field": "artifact_digest"})
    return digest


def _route_audit(row: sqlite3.Row) -> dict[str, Any]:
    return {"route_id": row["id"], "model": row["model"], "backend_id": row["backend_id"],
            "upstream_model": row["upstream_model"], "artifact_digest": row["artifact_digest"],
            "require_verified": bool(row["require_verified"]), "enabled": bool(row["enabled"])}


def _require_pin(require_verified: bool, digest: str | None) -> None:
    if require_verified and not digest:
        raise ValidationFailed("require_verified needs artifact_digest: pin the route to an imported model, "
                               "or set require_verified to false", details={"field": "require_verified"})


def create_route(conn: sqlite3.Connection, *, model: str, backend_id: int, upstream_model: str | None = None,
                 artifact_digest: str | None = None, require_verified: bool = True, enabled: bool = True,
                 actor_type: str, actor_id: str) -> dict[str, Any]:
    model = _check_model(model)
    upstream = _check_upstream_model(upstream_model if upstream_model is not None else model)
    require_verified = _check_bool(require_verified, "require_verified")
    enabled = _check_bool(enabled, "enabled")
    backend_id = _check_backend_id(backend_id)
    now = rfc3339()
    with write_tx(conn):
        _backend_row(conn, backend_id)
        digest = _check_pin(conn, artifact_digest) if artifact_digest else None
        _require_pin(require_verified, digest)
        if conn.execute("SELECT 1 FROM routes WHERE model = ?", (model,)).fetchone():
            raise Conflict(f"model '{model}' already has a route")
        cur = conn.execute(
            "INSERT INTO routes (model, backend_id, upstream_model, artifact_digest, require_verified, enabled,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (model, backend_id, upstream, digest, int(require_verified), int(enabled), now, now),
        )
        route_id = int(cur.lastrowid or 0)
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (route_id,)).fetchone()
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="route.create",
                           resource=f"model:{model}", outcome="success", details=_route_audit(row))
    return get_route(conn, route_id)


_ROUTE_FIELDS = frozenset({"model", "backend_id", "upstream_model", "artifact_digest", "require_verified", "enabled"})


def update_route(conn: sqlite3.Connection, route_id: int, changes: Mapping[str, Any], *,
                 actor_type: str, actor_id: str) -> dict[str, Any]:
    """PATCH semantics; artifact_digest None or "" removes the pin."""
    unknown = sorted(set(changes) - _ROUTE_FIELDS)
    if unknown:
        raise ValidationFailed(f"unknown route field(s): {', '.join(unknown)}")
    if not changes:
        raise ValidationFailed("nothing to change")
    values: dict[str, Any] = {}
    if "model" in changes:
        values["model"] = _check_model(changes["model"])
    if "upstream_model" in changes:
        values["upstream_model"] = _check_upstream_model(changes["upstream_model"])
    if "require_verified" in changes:
        values["require_verified"] = int(_check_bool(changes["require_verified"], "require_verified"))
    if "enabled" in changes:
        values["enabled"] = int(_check_bool(changes["enabled"], "enabled"))
    if "backend_id" in changes:
        values["backend_id"] = _check_backend_id(changes["backend_id"])
    with write_tx(conn):
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (route_id,)).fetchone()
        if row is None:
            raise NotFound(f"route {route_id} does not exist")
        if "backend_id" in values:
            _backend_row(conn, values["backend_id"])
        if "artifact_digest" in changes:
            pin = changes["artifact_digest"]
            values["artifact_digest"] = _check_pin(conn, pin) if pin else None
        merged = {**dict(row), **values}
        _require_pin(bool(merged["require_verified"]), merged["artifact_digest"])
        changed = sorted(k for k, v in values.items() if row[k] != v)
        if "model" in changed and conn.execute("SELECT 1 FROM routes WHERE model = ? AND id != ?",
                                               (values["model"], route_id)).fetchone():
            raise Conflict(f"model '{values['model']}' already has a route")
        if changed:
            sets = ", ".join(f"{k} = ?" for k in changed)
            conn.execute(f"UPDATE routes SET {sets}, updated_at = ? WHERE id = ?",
                         (*[values[k] for k in changed], rfc3339(), route_id))
            updated = conn.execute("SELECT * FROM routes WHERE id = ?", (route_id,)).fetchone()
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="route.update",
                               resource=f"model:{updated['model']}", outcome="success",
                               details={**_route_audit(updated), "changed": changed})
    return get_route(conn, route_id)


def delete_route(conn: sqlite3.Connection, route_id: int, *, actor_type: str, actor_id: str) -> None:
    with write_tx(conn):
        row = conn.execute("SELECT * FROM routes WHERE id = ?", (route_id,)).fetchone()
        if row is None:
            raise NotFound(f"route {route_id} does not exist")
        conn.execute("DELETE FROM routes WHERE id = ?", (route_id,))
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="route.delete",
                           resource=f"model:{row['model']}", outcome="success", details=_route_audit(row))


# --- health ------------------------------------------------------------------


class _ProbeFailed(Exception):
    def __init__(self, state: str, http_status: int | None, message: str) -> None:
        super().__init__(message)
        self.state = state
        self.http_status = http_status
        self.message = message


class _Prober:
    def __init__(self, client: httpx.AsyncClient, base_url: str, headers: dict[str, str], timeout: httpx.Timeout):
        self.client = client
        self.base_url = base_url
        self.headers = headers
        self.timeout = timeout

    async def get(self, path: str) -> tuple[int, Any]:
        async with self.client.stream("GET", self.base_url + path, headers=self.headers, timeout=self.timeout) as resp:
            if resp.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                raise _ProbeFailed("down", resp.status_code, f"GET {path}: compressed responses are not accepted")
            body = bytearray()
            async for chunk in resp.aiter_raw():
                body += chunk
                if len(body) > HEALTH_BODY_LIMIT:
                    raise _ProbeFailed("down", resp.status_code, f"GET {path}: response larger than {HEALTH_BODY_LIMIT} bytes")
        try:
            data = json.loads(bytes(body))
        except (ValueError, RecursionError):
            data = None
        return resp.status_code, data


def _short(value: object, limit: int = 256) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _model_ids(listing: Any, key: str = "data", field_name: str = "id") -> list[str]:
    items = listing.get(key) if isinstance(listing, dict) else None
    if not isinstance(items, list):
        return []
    ids = [_short(item.get(field_name)) for item in items[:MAX_LISTED_MODELS] if isinstance(item, dict)]
    return [i for i in ids if i]


def _token_rejected(path: str, code: int) -> _ProbeFailed:
    return _ProbeFailed("down", code, f"backend rejected the gateway's credentials (GET {path} returned HTTP {code}); "
                                      "check auth_token_file")


async def _check_llamacpp(probe: _Prober, settings: Settings, status: dict[str, Any]) -> None:
    code, _ = await probe.get("/health")
    status["http_status"] = code
    if code == 503:
        raise _ProbeFailed("loading", code, "backend is loading the model")
    if code != 200:
        raise _ProbeFailed("down", code, f"GET /health returned HTTP {code}")
    code, listing = await probe.get("/v1/models")
    if code in (401, 403):
        raise _token_rejected("/v1/models", code)
    if code != 200:
        raise _ProbeFailed("down", code, f"GET /v1/models returned HTTP {code}")
    status["models"] = _model_ids(listing)
    code, props = await probe.get("/props")
    status["state"] = "up"
    if code != 200 or not isinstance(props, dict):
        status["error"] = f"GET /props returned HTTP {code}; cannot tell which model file is served"
        return
    status["version"] = _short(props.get("build_info"), 128)
    model_path = _short(props.get("model_path"), 4096)
    if model_path:
        alias = _short(props.get("model_alias")) or (status["models"][0] if status["models"] else None)
        status["served"] = [{"model_id": alias, "path": model_path,
                             "digest": store_digest_for_path(settings, model_path)}]


async def _check_ollama(probe: _Prober, status: dict[str, Any]) -> None:
    code, version = await probe.get("/api/version")
    status["http_status"] = code
    if code != 200:
        raise _ProbeFailed("down", code, f"GET /api/version returned HTTP {code}")
    status["version"] = _short(version.get("version"), 128) if isinstance(version, dict) else None
    code, tags = await probe.get("/api/tags")
    if code != 200:
        raise _ProbeFailed("down", code, f"GET /api/tags returned HTTP {code}")
    status["models"] = _model_ids(tags, key="models", field_name="name")
    status["state"] = "up"


async def _check_openai(probe: _Prober, status: dict[str, Any]) -> None:
    code, listing = await probe.get("/v1/models")
    status["http_status"] = code
    if code in (401, 403):
        raise _token_rejected("/v1/models", code)
    if code != 200:
        raise _ProbeFailed("down", code, f"GET /v1/models returned HTTP {code}")
    status["models"] = _model_ids(listing)
    status["state"] = "up"


def _describe_http_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.ConnectError):
        return "connection failed (is the backend running?)"
    return f"request failed ({type(exc).__name__})"


async def check_backend(backend: Mapping[str, Any], client: httpx.AsyncClient, settings: Settings, *,
                        egress: EgressGuard | None = None) -> dict[str, Any]:
    """Probe one backend and return its status:
    {state: up|down|loading, checked_at, latency_ms, http_status, version, models, served, error}.
    Never raises for backend problems; they become state "down" with an error.
    The whole check is bounded by HEALTH_DEADLINE_FACTOR * HEALTH_TIMEOUT_S, so a
    backend that answers slowly but steadily cannot hold up a health pass."""
    started = time.monotonic()
    status: dict[str, Any] = {"state": "down", "checked_at": rfc3339(), "latency_ms": 0, "http_status": None,
                              "version": None, "models": [], "served": [], "error": None}
    deadline = HEALTH_TIMEOUT_S * HEALTH_DEADLINE_FACTOR
    try:
        await asyncio.wait_for(_probe_backend(backend, client, settings, egress, status), deadline)
    except TimeoutError:
        status = {**status, "state": "down", "http_status": None, "version": None, "models": [], "served": [],
                  "error": f"health check exceeded {deadline:g} s; the backend accepted the connection but did not "
                           "finish answering (is it wedged, or behind a slow proxy?)"}
    status["latency_ms"] = int((time.monotonic() - started) * 1000)
    return status


async def _probe_backend(backend: Mapping[str, Any], client: httpx.AsyncClient, settings: Settings,
                         egress: EgressGuard | None, status: dict[str, Any]) -> None:
    try:
        guard = egress or EgressGuard(settings.gateway.allow_public_backends, ttl_s=0)
        target = await guard.acheck(backend["base_url"])
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if backend.get("auth_token_file"):
            token = await asyncio.to_thread(read_token_file, backend["auth_token_file"])
            headers["Authorization"] = f"Bearer {token}"
        timeout = httpx.Timeout(min(float(backend["timeout_s"]), HEALTH_TIMEOUT_S),
                                connect=settings.gateway.connect_timeout_s)
        probe = _Prober(client, target.base_url, headers, timeout)
        kind = backend["kind"]
        if kind == "llamacpp":
            await _check_llamacpp(probe, settings, status)
        elif kind == "ollama":
            await _check_ollama(probe, status)
        elif kind == "openai":
            await _check_openai(probe, status)
        else:
            status["error"] = f"unknown backend kind '{kind}'"
    except _ProbeFailed as exc:
        status.update(state=exc.state, http_status=exc.http_status, error=exc.message)
    except FerryError as exc:
        status.update(state="down", error=exc.message)
    except httpx.HTTPError as exc:
        status.update(state="down", error=_describe_http_error(exc))


def record_health(conn: sqlite3.Connection, backend_id: int, status: Mapping[str, Any], *,
                  checked: Mapping[str, Any] | None = None, actor_type: str = "system",
                  actor_id: str = "health-check") -> bool:
    """Store a status; audit `backend.health` only when the state changed. Returns
    whether it changed. `checked` is the backend row the check ran against: if its
    kind, URL or token file has been changed since, the result describes a server
    that is no longer configured and is dropped."""
    if status.get("state") not in HEALTH_STATES:
        raise ValueError(f"invalid health state {status.get('state')!r}")
    with write_tx(conn):
        row = conn.execute("SELECT name, kind, base_url, auth_token_file, last_status FROM backends WHERE id = ?",
                           (backend_id,)).fetchone()
        if row is None or (checked is not None and any(row[k] != checked.get(k) for k in _RESETS_STATUS)):
            return False
        previous = _json_or_none(row["last_status"])
        previous_state = previous.get("state") if isinstance(previous, dict) else None
        conn.execute("UPDATE backends SET last_status = ?, last_checked_at = ? WHERE id = ?",
                     (canonical_json(dict(status)).decode("ascii"), status["checked_at"], backend_id))
        if previous_state == status["state"]:
            return False
        audit.append_event(
            conn, actor_type=actor_type, actor_id=actor_id, action="backend.health", resource=f"backend:{row['name']}",
            outcome=_HEALTH_OUTCOME[status["state"]],
            details={"backend_id": backend_id, "kind": row["kind"], "previous_state": previous_state,
                     "state": status["state"], "http_status": status.get("http_status"), "error": status.get("error"),
                     "version": status.get("version"),
                     "served": [{"model_id": s.get("model_id"), "digest": s.get("digest")}
                                for s in status.get("served") or [] if isinstance(s, Mapping)]},
        )
    return True


async def refresh_backend(state: GatewayState, backend_id: int, *, actor_type: str = "system",
                          actor_id: str = "health-check") -> dict[str, Any]:
    """Check one backend now and store the result (POST /api/backends/{id}/check)."""
    def load() -> dict[str, Any]:
        with state.db.session() as conn:
            return backend_for_check(conn, backend_id)

    backend = await asyncio.to_thread(load)
    status = await check_backend(backend, state.http, state.settings, egress=state.egress)

    def store() -> None:
        with state.db.session() as conn:
            record_health(conn, backend_id, status, checked=backend, actor_type=actor_type, actor_id=actor_id)

    await asyncio.to_thread(store)
    return status


async def check_all_backends(state: GatewayState, *, parallel: int = 8) -> dict[int, dict[str, Any]]:
    """One pass over every enabled backend, a few at a time."""
    def load() -> list[int]:
        with state.db.session() as conn:
            return [r["id"] for r in conn.execute("SELECT id FROM backends WHERE enabled = 1 ORDER BY id")]

    ids = await asyncio.to_thread(load)
    gate = asyncio.Semaphore(parallel)
    results: dict[int, dict[str, Any]] = {}

    async def one(backend_id: int) -> None:
        async with gate:
            try:
                results[backend_id] = await refresh_backend(state, backend_id)
            except NotFound:
                pass  # deleted while the pass was running
            except Exception as exc:  # one broken backend or write must not stop the others
                log.warning("health check of backend %s failed: %s", backend_id, type(exc).__name__)

    await asyncio.gather(*(one(i) for i in ids))
    return results


async def health_loop(state: GatewayState) -> None:
    """Background task for the app lifespan: check now, then every
    gateway.health_interval_s seconds (0 disables). Cancel it to stop."""
    interval = state.settings.gateway.health_interval_s
    if interval <= 0:
        return
    while True:
        try:
            await check_all_backends(state)
        except Exception as exc:  # the loop must survive any single bad pass
            log.warning("backend health pass failed: %s", type(exc).__name__)
        await asyncio.sleep(interval)
