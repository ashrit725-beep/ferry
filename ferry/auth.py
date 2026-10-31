"""Identity: app principals and their API keys, console admins, sessions, login throttling.

API keys look like fyk_<key id>_<secret>. The key id is not secret (the console
and the audit log show it); only sha256(secret) is stored, so a copy of the
database holds no usable keys. Authentication failures carry a precise reason
for the audit log, while callers only ever get a generic answer, so a client
cannot tell an unknown key from a revoked one.

Admin passwords are hashed with scrypt. Session tokens are random and stored as
SHA-256 hashes. Admin users are created on the host (CLI), never through the web
API.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import math
import re
import secrets
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from . import audit
from .config import Settings
from .db import write_tx
from .errors import Conflict, NotFound, ValidationFailed
from .policy import APP_NAME
from .util import parse_rfc3339, rfc3339, sha256_hex, utc_now

API_KEY_PREFIX = "fyk_"
API_KEY_PATTERN = re.compile(r"^fyk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$")
API_KEY_LENGTH = 60
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
ENVIRONMENTS = ("test", "pilot", "production")
AUTH_FAILURES = ("malformed", "unknown_key", "bad_secret", "revoked", "expired", "principal_disabled")
MAX_KEY_LIFETIME_DAYS = 3650
MAX_DESCRIPTION_CHARS = 1000
LAST_USED_RESOLUTION = _dt.timedelta(minutes=1)

ADMIN_ROLES = ("admin", "auditor")
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MIN_PASSWORD_CHARS = 12
MAX_PASSWORD_CHARS = 1024
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024**2

SESSION_COOKIE = "ferry_session"
_SESSION_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


# --- API keys ----------------------------------------------------------------


def generate_api_key() -> tuple[str, str, str]:
    """Return (key_id, secret, full key). The secret is 32 random bytes, base64url, unpadded."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    return key_id, secret, f"{API_KEY_PREFIX}{key_id}_{secret}"


def parse_api_key(value: object) -> tuple[str, str] | None:
    """(key_id, secret) for a well-formed key, else None. The secret may itself
    contain '_' and '-', so the format is matched as a whole, never split."""
    if not isinstance(value, str) or len(value) != API_KEY_LENGTH:
        return None
    m = API_KEY_PATTERN.fullmatch(value)
    return (m.group(1), m.group(2)) if m else None


def parse_bearer(header: str | None) -> str | None:
    """The credentials of an `Authorization: Bearer <token>` header, else None."""
    if not header:
        return None
    scheme, _, credentials = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    return credentials.strip() or None


def hash_secret(secret: str) -> str:
    return sha256_hex(secret.encode("ascii"))


@dataclass(frozen=True)
class AppIdentity:
    principal_id: int
    name: str
    environment: str
    key_id: str

    @property
    def principal(self) -> str:
        """The policy principal, e.g. "app:report-assistant"."""
        return f"app:{self.name}"


@dataclass(frozen=True)
class ApiKeyResult:
    ok: bool
    reason: str | None = None
    """One of AUTH_FAILURES; for the audit log only, never for the caller."""
    key_id: str | None = None
    identity: AppIdentity | None = None


# Compared against when the key id is unknown, so both paths do the same work.
_UNKNOWN_KEY_HASH = sha256_hex(b"ferry: no such key")


def authenticate_api_key(conn: sqlite3.Connection, presented: str | None, *,
                         now: _dt.datetime | None = None) -> ApiKeyResult:
    """Check a presented API key. Records `last_used_at` at most once a minute per key."""
    now = now or utc_now()
    parsed = parse_api_key(presented)
    if parsed is None:
        return ApiKeyResult(False, "malformed")
    key_id, secret = parsed
    row = conn.execute(
        "SELECT k.key_id, k.secret_hash, k.expires_at, k.revoked_at, k.last_used_at, k.principal_id,"
        " p.name, p.environment, p.disabled FROM api_keys k JOIN principals p ON p.id = k.principal_id"
        " WHERE k.key_id = ?",
        (key_id,),
    ).fetchone()
    digest = hash_secret(secret)
    if row is None:
        hmac.compare_digest(digest, _UNKNOWN_KEY_HASH)
        return ApiKeyResult(False, "unknown_key", key_id)
    # The secret is checked first: whoever lacks it learns nothing about the key's state.
    if not hmac.compare_digest(digest, row["secret_hash"]):
        return ApiKeyResult(False, "bad_secret", key_id)
    if row["revoked_at"]:
        return ApiKeyResult(False, "revoked", key_id)
    if row["expires_at"] and _expired(row["expires_at"], now):
        return ApiKeyResult(False, "expired", key_id)
    if row["disabled"]:
        return ApiKeyResult(False, "principal_disabled", key_id)
    _touch_last_used(conn, key_id, now, row["last_used_at"])
    identity = AppIdentity(principal_id=row["principal_id"], name=row["name"], environment=row["environment"],
                           key_id=key_id)
    return ApiKeyResult(True, None, key_id, identity)


def _expired(stamp: str, now: _dt.datetime) -> bool:
    try:
        return parse_rfc3339(stamp) <= now
    except ValueError:
        return True  # an unreadable expiry fails closed


def _touch_last_used(conn: sqlite3.Connection, key_id: str, now: _dt.datetime, last_used: str | None) -> None:
    cutoff = rfc3339(now - LAST_USED_RESOLUTION)
    if last_used is not None and last_used > cutoff:
        return
    _write(conn, "UPDATE api_keys SET last_used_at = ? WHERE key_id = ? AND (last_used_at IS NULL OR last_used_at <= ?)",
           (rfc3339(now), key_id, cutoff))


# --- principals --------------------------------------------------------------


def _check_name(name: object) -> str:
    if not isinstance(name, str) or not APP_NAME.fullmatch(name):
        raise ValidationFailed("app name must be 1-64 characters: lowercase letters, digits, '-' or '_', "
                               "starting with a letter or digit", details={"field": "name"})
    return name


def _check_environment(environment: object) -> str:
    if environment not in ENVIRONMENTS:
        raise ValidationFailed(f"environment must be one of: {', '.join(ENVIRONMENTS)}",
                               details={"field": "environment"})
    return str(environment)


def _check_description(description: object) -> str:
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS:
        raise ValidationFailed(f"description must be a string of at most {MAX_DESCRIPTION_CHARS} characters",
                               details={"field": "description"})
    return description


def _key_status(row: sqlite3.Row, now: _dt.datetime) -> str:
    if row["revoked_at"]:
        return "revoked"
    if row["expires_at"] and _expired(row["expires_at"], now):
        return "expired"
    return "active"


def _key_dict(row: sqlite3.Row, now: _dt.datetime) -> dict[str, Any]:
    return {
        "key_id": row["key_id"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
        "last_used_at": row["last_used_at"],
        "status": _key_status(row, now),
    }


def _principal_dict(row: sqlite3.Row, keys: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "environment": row["environment"],
        "description": row["description"],
        "disabled": bool(row["disabled"]),
        "created_at": row["created_at"],
        "keys": keys,
    }


def _keys_for(conn: sqlite3.Connection, principal_id: int, now: _dt.datetime) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM api_keys WHERE principal_id = ? ORDER BY created_at, key_id",
                        (principal_id,)).fetchall()
    return [_key_dict(r, now) for r in rows]


def get_principal(conn: sqlite3.Connection, principal_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM principals WHERE id = ?", (principal_id,)).fetchone()
    if row is None:
        raise NotFound(f"app {principal_id} does not exist")
    return _principal_dict(row, _keys_for(conn, row["id"], utc_now()))


def get_principal_by_name(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM principals WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise NotFound(f"app '{name}' does not exist")
    return _principal_dict(row, _keys_for(conn, row["id"], utc_now()))


def list_principals(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    now = utc_now()
    keys: dict[int, list[dict[str, Any]]] = {}
    for r in conn.execute("SELECT * FROM api_keys ORDER BY created_at, key_id"):
        keys.setdefault(r["principal_id"], []).append(_key_dict(r, now))
    return [_principal_dict(r, keys.get(r["id"], [])) for r in conn.execute("SELECT * FROM principals ORDER BY name")]


def create_principal(conn: sqlite3.Connection, name: str, *, environment: str = "test", description: str = "",
                     actor_type: str, actor_id: str) -> dict[str, Any]:
    name = _check_name(name)
    environment = _check_environment(environment)
    description = _check_description(description)
    with write_tx(conn):
        if conn.execute("SELECT 1 FROM principals WHERE name = ?", (name,)).fetchone():
            raise Conflict(f"an app named '{name}' already exists")
        cur = conn.execute(
            "INSERT INTO principals (name, kind, environment, description, disabled, created_at)"
            " VALUES (?, 'app', ?, ?, 0, ?)",
            (name, environment, description, rfc3339()),
        )
        principal_id = int(cur.lastrowid or 0)
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="principal.create",
                           resource=f"app:{name}", outcome="success",
                           details={"principal_id": principal_id, "name": name, "environment": environment})
    return get_principal(conn, principal_id)


def update_principal(conn: sqlite3.Connection, principal_id: int, *, disabled: bool | None = None,
                     description: str | None = None, environment: str | None = None,
                     actor_type: str, actor_id: str) -> dict[str, Any]:
    """Change an app. Disabling it rejects all of its keys immediately; nothing is
    deleted, so re-enabling restores the same keys."""
    wanted: dict[str, Any] = {}
    if disabled is not None:
        if not isinstance(disabled, bool):
            raise ValidationFailed("disabled must be true or false", details={"field": "disabled"})
        wanted["disabled"] = int(disabled)
    if description is not None:
        wanted["description"] = _check_description(description)
    if environment is not None:
        wanted["environment"] = _check_environment(environment)
    if not wanted:
        raise ValidationFailed("nothing to change: give disabled, description or environment")
    with write_tx(conn):
        row = conn.execute("SELECT * FROM principals WHERE id = ?", (principal_id,)).fetchone()
        if row is None:
            raise NotFound(f"app {principal_id} does not exist")
        changes = {k: {"from": row[k], "to": v} for k, v in wanted.items() if row[k] != v}
        if changes:
            # Column names come from the fixed set above, never from the caller.
            assignments = ", ".join(f"{k} = ?" for k in changes)
            conn.execute(f"UPDATE principals SET {assignments} WHERE id = ?",
                         (*[c["to"] for c in changes.values()], principal_id))
            if "disabled" in changes:
                changes["disabled"] = {"from": bool(row["disabled"]), "to": bool(wanted["disabled"])}
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="principal.update",
                               resource=f"app:{row['name']}", outcome="success",
                               details={"principal_id": principal_id, "name": row["name"], "changes": changes})
    return get_principal(conn, principal_id)


def issue_api_key(conn: sqlite3.Connection, principal_id: int, *, expires_in_days: int | None = None,
                  actor_type: str, actor_id: str, now: _dt.datetime | None = None) -> dict[str, Any]:
    """Create a key and return it. The returned `api_key` is the only copy of the
    secret: it is not stored and cannot be shown again."""
    if expires_in_days is not None and (isinstance(expires_in_days, bool) or not isinstance(expires_in_days, int)
                                        or not 1 <= expires_in_days <= MAX_KEY_LIFETIME_DAYS):
        raise ValidationFailed(f"expires_in_days must be a whole number from 1 to {MAX_KEY_LIFETIME_DAYS}",
                               details={"field": "expires_in_days"})
    now = now or utc_now()
    created_at = rfc3339(now)
    expires_at = rfc3339(now + _dt.timedelta(days=expires_in_days)) if expires_in_days else None
    with write_tx(conn):
        row = conn.execute("SELECT id, name, disabled FROM principals WHERE id = ?", (principal_id,)).fetchone()
        if row is None:
            raise NotFound(f"app {principal_id} does not exist")
        if row["disabled"]:
            raise Conflict(f"app '{row['name']}' is disabled; enable it before issuing keys")
        for _ in range(8):
            key_id, secret, api_key = generate_api_key()
            if conn.execute("SELECT 1 FROM api_keys WHERE key_id = ?", (key_id,)).fetchone() is None:
                break
        else:
            raise RuntimeError("could not allocate an unused API key id")
        conn.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key_id, principal_id, hash_secret(secret), created_at, expires_at),
        )
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="api_key.create",
                           resource=f"app:{row['name']}", outcome="success",
                           details={"key_id": key_id, "principal_id": principal_id, "expires_at": expires_at})
    return {"key_id": key_id, "api_key": api_key, "created_at": created_at, "expires_at": expires_at,
            "principal_id": principal_id, "app": row["name"]}


def revoke_api_key(conn: sqlite3.Connection, key_id: str, *, actor_type: str, actor_id: str,
                   now: _dt.datetime | None = None) -> dict[str, Any]:
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise ValidationFailed("key id must be 12 lowercase hex characters (the part after 'fyk_')",
                               details={"field": "key_id"})
    now = now or utc_now()
    with write_tx(conn):
        row = conn.execute("SELECT k.*, p.name FROM api_keys k JOIN principals p ON p.id = k.principal_id"
                           " WHERE k.key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise NotFound(f"API key {key_id} does not exist")
        if row["revoked_at"]:
            raise Conflict(f"API key {key_id} was already revoked at {row['revoked_at']}")
        conn.execute("UPDATE api_keys SET revoked_at = ? WHERE key_id = ?", (rfc3339(now), key_id))
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="api_key.revoke",
                           resource=f"app:{row['name']}", outcome="success",
                           details={"key_id": key_id, "principal_id": row["principal_id"]})
        updated = conn.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
    return {**_key_dict(updated, now), "principal_id": row["principal_id"], "app": row["name"]}


# --- admin users -------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def check_password_policy(password: object) -> str:
    if not isinstance(password, str):
        raise ValidationFailed("password must be a string")
    if len(password) < MIN_PASSWORD_CHARS:
        raise ValidationFailed(f"password must be at least {MIN_PASSWORD_CHARS} characters")
    if len(password) > MAX_PASSWORD_CHARS:
        raise ValidationFailed(f"password must be at most {MAX_PASSWORD_CHARS} characters")
    return password


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """scrypt$N$r$p$<b64 salt>$<b64 hash> with N=2**15, r=8, p=1 and a 16-byte salt."""
    check_password_policy(password)
    if salt is None:
        salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    if len(salt) != SCRYPT_SALT_BYTES:
        raise ValueError(f"salt must be {SCRYPT_SALT_BYTES} bytes")
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=SCRYPT_MAXMEM, dklen=SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


# Each scrypt check allocates 128*r*N bytes (32 MiB at the defaults). A burst of
# sign-in requests runs in the server's thread pool, so without a bound it could
# hold the pool size times that at once; extra checks wait their turn instead.
SCRYPT_CONCURRENCY = 4
_SCRYPT_SLOTS = threading.BoundedSemaphore(SCRYPT_CONCURRENCY)


def verify_password(password: object, stored: object) -> bool:
    """Constant-time check against a stored scrypt string. Malformed strings and
    parameters outside safe bounds (which could exhaust memory) verify as False."""
    if not isinstance(password, str) or not isinstance(stored, str) or len(password) > MAX_PASSWORD_CHARS:
        return False
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt" or not all(p.isdigit() for p in parts[1:4]):
        return False
    n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
    if not (2 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
        return False
    if 128 * r * (n + p + 2) > SCRYPT_MAXMEM:
        return False
    try:
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
    except (ValueError, binascii.Error):
        return False
    if not 8 <= len(salt) <= 64 or not 16 <= len(expected) <= 64:
        return False
    try:
        with _SCRYPT_SLOTS:
            actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM,
                                    dklen=len(expected))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


@lru_cache(maxsize=1)
def _decoy_hash() -> str:
    """Verified against when the username is unknown, so a login for a missing user
    costs the same scrypt work as one for a real user."""
    return hash_password(secrets.token_urlsafe(24))


def normalize_username(username: object) -> str | None:
    if not isinstance(username, str):
        return None
    name = username.strip().lower()
    return name if USERNAME_PATTERN.fullmatch(name) else None


def _admin_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "username": row["username"], "role": row["role"], "disabled": bool(row["disabled"]),
            "created_at": row["created_at"], "last_login_at": row["last_login_at"]}


def create_admin_user(conn: sqlite3.Connection, username: str, password: str, role: str, *,
                      actor_type: str = "cli", actor_id: str) -> dict[str, Any]:
    """Host-only (CLI). The web API has no way to create users."""
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValidationFailed("username must be 1-64 characters: lowercase letters, digits, '.', '-' or '_'",
                               details={"field": "username"})
    if role not in ADMIN_ROLES:
        raise ValidationFailed(f"role must be one of: {', '.join(ADMIN_ROLES)}", details={"field": "role"})
    stored = hash_password(password)
    with write_tx(conn):
        if conn.execute("SELECT 1 FROM admin_users WHERE username = ?", (username,)).fetchone():
            raise Conflict(f"a console user named '{username}' already exists")
        cur = conn.execute(
            "INSERT INTO admin_users (username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, 0, ?)",
            (username, stored, role, rfc3339()),
        )
        user_id = int(cur.lastrowid or 0)
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="admin.user_create",
                           resource=f"admin:{username}", outcome="success",
                           details={"user_id": user_id, "username": username, "role": role})
        row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    return _admin_dict(row)


def get_admin_user(conn: sqlite3.Connection, user_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    return _admin_dict(row) if row else None


@dataclass(frozen=True)
class AdminAuthResult:
    ok: bool
    reason: str | None = None
    """unknown_user, bad_password, disabled or malformed; for the audit log only."""
    user: dict[str, Any] | None = None


def authenticate_admin(conn: sqlite3.Connection, username: object, password: object) -> AdminAuthResult:
    """Check console credentials. Does not write anything: on success call
    create_session, on failure record_login_failure (and the throttle)."""
    name = normalize_username(username)
    row = conn.execute("SELECT * FROM admin_users WHERE username = ?", (name,)).fetchone() if name else None
    good = verify_password(password, row["password_hash"] if row is not None else _decoy_hash())
    if row is None:
        return AdminAuthResult(False, "unknown_user" if name else "malformed")
    if not good:
        return AdminAuthResult(False, "bad_password")
    if row["disabled"]:
        return AdminAuthResult(False, "disabled")
    return AdminAuthResult(True, None, _admin_dict(row))


def record_login_failure(conn: sqlite3.Connection, username: object, reason: str, *, client_ip: str | None = None,
                         correlation_id: str | None = None, throttled: bool = False) -> None:
    """Audit a failed login. The attempted name is recorded only when it belongs to
    an existing user: people do type passwords into the username field."""
    name = normalize_username(username)
    known = bool(name) and conn.execute("SELECT 1 FROM admin_users WHERE username = ?", (name,)).fetchone() is not None
    who = name if known and name else "unknown"
    audit.append_event(conn, actor_type="admin", actor_id=who, action="auth.login", resource=f"admin:{who}",
                       outcome="denied" if throttled else "failure", correlation_id=correlation_id,
                       details={"reason": reason, "client_ip": client_ip, "throttled": throttled})


# --- sessions ----------------------------------------------------------------


def _session_touch_interval(idle: _dt.timedelta) -> _dt.timedelta:
    # last_seen_at is refreshed at most this often, which bounds writes per
    # session while keeping idle expiry accurate to a small fraction of the timeout.
    return min(_dt.timedelta(seconds=30), idle / 20)


def create_session(conn: sqlite3.Connection, user_id: int, settings: Settings, *, now: _dt.datetime | None = None,
                   client_ip: str | None = None, correlation_id: str | None = None) -> tuple[str, dict[str, Any]]:
    """Start a console session and audit the login. Returns (token, session); the
    token goes only into the cookie, the database keeps its SHA-256."""
    now = now or utc_now()
    token = secrets.token_urlsafe(32)
    stamp = rfc3339(now)
    expires_at = rfc3339(now + _dt.timedelta(hours=settings.server.session_max_hours))
    with write_tx(conn):
        row = conn.execute("SELECT * FROM admin_users WHERE id = ?", (user_id,)).fetchone()
        if row is None or row["disabled"]:
            raise NotFound("console user does not exist or is disabled")
        # Housekeeping in the same write: sessions whose browser never came back
        # are otherwise kept forever (resolve_session only deletes a presented token).
        _purge_expired(conn, settings, now)
        conn.execute("INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)"
                     " VALUES (?, ?, ?, ?, ?)", (sha256_hex(token.encode("ascii")), user_id, stamp, stamp, expires_at))
        conn.execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (stamp, user_id))
        audit.append_event(conn, actor_type="admin", actor_id=row["username"], action="auth.login",
                           resource=f"admin:{row['username']}", outcome="success", correlation_id=correlation_id,
                           details={"role": row["role"], "client_ip": client_ip, "expires_at": expires_at})
    return token, {"user_id": user_id, "username": row["username"], "role": row["role"], "created_at": stamp,
                   "expires_at": expires_at}


def _write(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> None:
    """One bookkeeping statement: joins the caller's transaction or runs in its own."""
    if conn.in_transaction:
        conn.execute(sql, params)
    else:
        with write_tx(conn):
            conn.execute(sql, params)


def _delete_session_hash(conn: sqlite3.Connection, token_hash: str) -> None:
    _write(conn, "DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def resolve_session(conn: sqlite3.Connection, token: object, settings: Settings, *,
                    now: _dt.datetime | None = None) -> dict[str, Any] | None:
    """The session's user for a valid token, else None. Expired sessions (idle or
    absolute, under the current settings) and sessions of disabled users are deleted."""
    if not isinstance(token, str) or not _SESSION_TOKEN.fullmatch(token):
        return None
    now = now or utc_now()
    token_hash = sha256_hex(token.encode("ascii"))
    row = conn.execute(
        "SELECT s.user_id, s.created_at, s.last_seen_at, s.expires_at, u.username, u.role, u.disabled"
        " FROM sessions s JOIN admin_users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (token_hash,),
    ).fetchone()
    if row is None:
        return None
    idle = _dt.timedelta(minutes=settings.server.session_idle_minutes)
    try:
        created = parse_rfc3339(row["created_at"])
        last_seen = parse_rfc3339(row["last_seen_at"])
        deadline = min(parse_rfc3339(row["expires_at"]),
                       created + _dt.timedelta(hours=settings.server.session_max_hours))
    except ValueError:
        _delete_session_hash(conn, token_hash)
        return None
    if row["disabled"] or now >= deadline or now - last_seen >= idle:
        _delete_session_hash(conn, token_hash)
        return None
    if now - last_seen >= _session_touch_interval(idle):
        _write(conn, "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (rfc3339(now), token_hash))
    return {"user_id": row["user_id"], "username": row["username"], "role": row["role"],
            "created_at": row["created_at"], "expires_at": rfc3339(deadline)}


def delete_session(conn: sqlite3.Connection, token: object, *, client_ip: str | None = None,
                   correlation_id: str | None = None) -> bool:
    """Log out: delete the session and audit it. False if there was no such session."""
    if not isinstance(token, str) or not _SESSION_TOKEN.fullmatch(token):
        return False
    token_hash = sha256_hex(token.encode("ascii"))
    with write_tx(conn):
        row = conn.execute("SELECT u.username FROM sessions s JOIN admin_users u ON u.id = s.user_id"
                           " WHERE s.token_hash = ?", (token_hash,)).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        audit.append_event(conn, actor_type="admin", actor_id=row["username"], action="auth.logout",
                           resource=f"admin:{row['username']}", outcome="success", correlation_id=correlation_id,
                           details={"client_ip": client_ip})
    return True


def purge_expired_sessions(conn: sqlite3.Connection, settings: Settings, *, now: _dt.datetime | None = None) -> int:
    """Delete sessions past their absolute or idle limit. Housekeeping, not audited."""
    now = now or utc_now()
    with write_tx(conn):
        return _purge_expired(conn, settings, now)


def _purge_expired(conn: sqlite3.Connection, settings: Settings, now: _dt.datetime) -> int:
    # The same limits resolve_session applies: the stored absolute expiry, the
    # absolute limit under the current settings, and the idle limit. Stamps are
    # fixed-width UTC RFC 3339, so string order is time order.
    idle_cutoff = rfc3339(now - _dt.timedelta(minutes=settings.server.session_idle_minutes))
    created_cutoff = rfc3339(now - _dt.timedelta(hours=settings.server.session_max_hours))
    cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ? OR created_at <= ?",
                       (rfc3339(now), idle_cutoff, created_cutoff))
    return cur.rowcount


# --- login throttle ----------------------------------------------------------


@dataclass
class _Bucket:
    failures: deque[float] = field(default_factory=deque)
    locked_until: float = 0.0
    in_flight: int = 0
    """Attempts admitted by begin() whose password check has not finished yet."""


@dataclass(frozen=True)
class ThrottleRefusal:
    """Why begin() refused an attempt: `busy` when the limit is taken up by
    attempts still being checked rather than by a lock."""

    retry_after_s: int
    busy: bool = False


class LoginThrottle:
    """In-memory brake on password guessing: too many failures for one username
    (5) or from one client address (20) within the window lock further attempts
    for `lock_s`. State is per process and resets on restart.

    Callers admit an attempt with begin() before checking the password and report
    the outcome with finish(). Admission and the count are one step under the
    lock, and attempts still in flight count toward the limit, so a concurrent
    burst cannot get more password checks than the limit allows."""

    def __init__(self, *, max_user_failures: int = 5, max_ip_failures: int = 20, window_s: float = 900.0,
                 lock_s: float = 900.0, clock: Callable[[], float] = time.monotonic, max_entries: int = 10_000,
                 busy_retry_s: int = 2):
        self.max_user_failures = max_user_failures
        self.max_ip_failures = max_ip_failures
        self.window_s = window_s
        self.lock_s = lock_s
        self.max_entries = max_entries
        self.busy_retry_s = busy_retry_s
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], _Bucket] = {}

    @staticmethod
    def _keys(username: object, client_ip: str | None) -> list[tuple[str, str]]:
        keys = [("user", str(username).strip().lower()[:128])]
        if client_ip:
            keys.append(("ip", str(client_ip)[:64]))
        return keys

    def _limit(self, key: tuple[str, str]) -> int:
        return self.max_user_failures if key[0] == "user" else self.max_ip_failures

    def _expire(self, bucket: _Bucket, now: float) -> None:
        while bucket.failures and bucket.failures[0] <= now - self.window_s:
            bucket.failures.popleft()

    def retry_after(self, username: object, client_ip: str | None = None) -> int | None:
        """Seconds until a locked username or address may try again, or None."""
        now = self._clock()
        with self._lock:
            waits = [b.locked_until - now for key in self._keys(username, client_ip)
                     if (b := self._buckets.get(key)) is not None and b.locked_until > now]
        return math.ceil(max(waits)) if waits else None

    def begin(self, username: object, client_ip: str | None = None) -> ThrottleRefusal | None:
        """Admit one password check, or refuse it. Refused when the username or
        address is locked, or when its failures plus the checks already in flight
        have reached the limit. An admitted attempt must be closed with finish()."""
        now = self._clock()
        keys = self._keys(username, client_ip)
        with self._lock:
            waits = [b.locked_until - now for key in keys
                     if (b := self._buckets.get(key)) is not None and b.locked_until > now]
            if waits:
                return ThrottleRefusal(math.ceil(max(waits)))
            for key in keys:
                bucket = self._buckets.get(key)
                if bucket is None:
                    continue
                self._expire(bucket, now)
                if len(bucket.failures) + bucket.in_flight >= self._limit(key):
                    return ThrottleRefusal(self.busy_retry_s, busy=True)
            for key in keys:
                self._buckets.setdefault(key, _Bucket()).in_flight += 1
            if len(self._buckets) > self.max_entries:
                self._prune(now)
        return None

    def finish(self, username: object, client_ip: str | None = None, *, ok: bool) -> int | None:
        """Close an attempt admitted by begin(): a failure is counted (returning the
        lock duration if it caused or met a lock); a success clears the username."""
        now = self._clock()
        with self._lock:
            for key in self._keys(username, client_ip):
                bucket = self._buckets.get(key)
                if bucket is not None and bucket.in_flight > 0:
                    bucket.in_flight -= 1
            if ok:
                self._clear_user(username)
                return None
            return self._count_failure(username, client_ip, now)

    def record_failure(self, username: object, client_ip: str | None = None) -> int | None:
        """Count a failure; returns the lock duration if this failure caused (or met) a lock."""
        now = self._clock()
        with self._lock:
            return self._count_failure(username, client_ip, now)

    def record_success(self, username: object, client_ip: str | None = None) -> None:
        """A successful login clears the username's failures (not the address's)."""
        with self._lock:
            self._clear_user(username)

    def _clear_user(self, username: object) -> None:
        key = self._keys(username, None)[0]
        bucket = self._buckets.get(key)
        if bucket is None:
            return
        if bucket.in_flight:  # other checks for this name are still running
            bucket.failures.clear()
            bucket.locked_until = 0.0
        else:
            del self._buckets[key]

    def _count_failure(self, username: object, client_ip: str | None, now: float) -> int | None:
        waits: list[float] = []
        for key in self._keys(username, client_ip):
            bucket = self._buckets.setdefault(key, _Bucket())
            if bucket.locked_until > now:
                waits.append(bucket.locked_until - now)
                continue
            self._expire(bucket, now)
            bucket.failures.append(now)
            if len(bucket.failures) >= self._limit(key):
                bucket.locked_until = now + self.lock_s
                bucket.failures.clear()
                waits.append(self.lock_s)
        if len(self._buckets) > self.max_entries:
            self._prune(now)
        return math.ceil(max(waits)) if waits else None

    def _prune(self, now: float) -> None:
        # Only idle entries are dropped, so flooding the table with fresh names
        # cannot evict an active lock.
        stale = [k for k, b in self._buckets.items()
                 if b.locked_until <= now and not b.in_flight
                 and (not b.failures or b.failures[-1] <= now - self.window_s)]
        for key in stale:
            del self._buckets[key]
