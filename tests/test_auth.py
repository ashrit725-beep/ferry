"""Tests for ferry.auth: API keys, principals, admin passwords, sessions, login throttle."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from dataclasses import replace

import pytest

from ferry import audit, auth
from ferry.config import ServerSettings
from ferry.errors import Conflict, NotFound, ValidationFailed
from ferry.util import sha256_hex

ACTOR = {"actor_type": "cli", "actor_id": "pytest"}
NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.timezone.utc)
PASSWORD = "correct horse battery"


@pytest.fixture
def app(conn):
    return auth.create_principal(conn, "report-assistant", environment="pilot", description="Reports", **ACTOR)


@pytest.fixture
def key(conn, app):
    return auth.issue_api_key(conn, app["id"], now=NOW, **ACTOR)


def _db_bytes(settings) -> bytes:
    return b"".join(p.read_bytes() for p in settings.data_dir.glob("ferry.db*"))


# --- API key format ---------------------------------------------------------------


def test_generated_keys_have_the_documented_format() -> None:
    seen = set()
    for _ in range(50):
        key_id, secret, full = auth.generate_api_key()
        assert re.fullmatch(r"fyk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", full)
        assert full == f"fyk_{key_id}_{secret}" and len(full) == auth.API_KEY_LENGTH
        assert len(base64.urlsafe_b64decode(secret + "=")) == 32
        assert auth.parse_api_key(full) == (key_id, secret)
        seen.add(full)
    assert len(seen) == 50


def test_parse_handles_secrets_containing_separators() -> None:
    secret = "_" * 20 + "-" * 23
    assert auth.parse_api_key(f"fyk_0123456789ab_{secret}") == ("0123456789ab", secret)


@pytest.mark.parametrize("value", [
    None, 42, "", "fyk_", "fyk_0123456789ab", "FYK_0123456789ab_" + "a" * 43, "fyx_0123456789ab_" + "a" * 43,
    "fyk_0123456789AB_" + "a" * 43, "fyk_0123456789a_" + "a" * 44, "fyk_0123456789abc_" + "a" * 42,
    "fyk_0123456789ab_" + "a" * 42, "fyk_0123456789ab_" + "a" * 44, "fyk_0123456789ab-" + "a" * 43,
    "fyk_0123456789ab_" + "a" * 42 + "=", "fyk_0123456789ab_" + "a" * 42 + "/", " fyk_0123456789ab_" + "a" * 42,
    "fyk_0123456789ab_" + "a" * 43 + "\n", "fyk_0123456789ab_" + "ä" * 43,
])
def test_parse_rejects_malformed_keys(value) -> None:
    assert auth.parse_api_key(value) is None


@pytest.mark.parametrize("header, expected", [
    ("Bearer abc", "abc"), ("bearer abc", "abc"), ("BEARER   abc  ", "abc"), ("Bearer", None), ("Bearer   ", None),
    ("Basic abc", None), ("abc", None), ("", None), (None, None), ("Token abc", None),
])
def test_parse_bearer(header, expected) -> None:
    assert auth.parse_bearer(header) == expected


# --- authentication --------------------------------------------------------------------


def test_valid_key_authenticates(conn, app, key) -> None:
    result = auth.authenticate_api_key(conn, key["api_key"], now=NOW)
    assert result.ok is True and result.reason is None and result.key_id == key["key_id"]
    assert result.identity == auth.AppIdentity(principal_id=app["id"], name="report-assistant", environment="pilot",
                                               key_id=key["key_id"])
    assert result.identity.principal == "app:report-assistant"  # type: ignore[union-attr]


def test_failure_reasons(conn, app, key) -> None:
    def reason(value, now=NOW):
        result = auth.authenticate_api_key(conn, value, now=now)
        assert result.ok is False and result.identity is None
        return result.reason

    key_id, secret = auth.parse_api_key(key["api_key"])  # type: ignore[misc]
    assert reason(None) == "malformed"
    assert reason("not a key") == "malformed"
    assert reason(f"fyk_{'0' * 12}_{secret}") == "unknown_key"
    assert reason(f"fyk_{key_id}_{'A' * 43}") == "bad_secret"

    expiring = auth.issue_api_key(conn, app["id"], expires_in_days=1, now=NOW, **ACTOR)
    assert auth.authenticate_api_key(conn, expiring["api_key"], now=NOW + dt.timedelta(hours=23)).ok is True
    assert reason(expiring["api_key"], NOW + dt.timedelta(days=1)) == "expired"

    auth.update_principal(conn, app["id"], disabled=True, **ACTOR)
    assert reason(key["api_key"]) == "principal_disabled"
    auth.update_principal(conn, app["id"], disabled=False, **ACTOR)
    assert auth.authenticate_api_key(conn, key["api_key"], now=NOW).ok is True

    auth.revoke_api_key(conn, key_id, **ACTOR)
    assert reason(key["api_key"]) == "revoked"
    # A guess with the right id but the wrong secret is a bad secret, whatever the key's state.
    assert reason(f"fyk_{key_id}_{'A' * 43}") == "bad_secret"
    assert set(auth.AUTH_FAILURES) >= {"malformed", "unknown_key", "bad_secret", "revoked", "expired",
                                       "principal_disabled"}


def test_secret_comparison_uses_compare_digest(conn, key, monkeypatch) -> None:
    calls = []
    real = auth.hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", spy)
    key_id, secret = auth.parse_api_key(key["api_key"])  # type: ignore[misc]
    assert auth.authenticate_api_key(conn, key["api_key"], now=NOW).ok
    assert calls[-1] == (sha256_hex(secret.encode()), sha256_hex(secret.encode()))
    auth.authenticate_api_key(conn, f"fyk_{key_id}_{'B' * 43}", now=NOW)
    auth.authenticate_api_key(conn, f"fyk_{'f' * 12}_{secret}", now=NOW)  # unknown id: same work
    assert len(calls) == 3


def test_last_used_is_written_at_most_once_a_minute(conn, key) -> None:
    def last_used():
        return conn.execute("SELECT last_used_at FROM api_keys WHERE key_id = ?", (key["key_id"],)).fetchone()[0]

    assert last_used() is None
    auth.authenticate_api_key(conn, key["api_key"], now=NOW)
    assert last_used() == "2026-10-28T12:00:00.000Z"
    auth.authenticate_api_key(conn, key["api_key"], now=NOW + dt.timedelta(seconds=59))
    assert last_used() == "2026-10-28T12:00:00.000Z"
    auth.authenticate_api_key(conn, key["api_key"], now=NOW + dt.timedelta(seconds=61))
    assert last_used() == "2026-10-28T12:01:01.000Z"
    # Failed attempts never touch it.
    auth.authenticate_api_key(conn, f"fyk_{key['key_id']}_{'C' * 43}", now=NOW + dt.timedelta(minutes=10))
    assert last_used() == "2026-10-28T12:01:01.000Z"


def test_only_the_secret_hash_is_stored(conn, settings, key) -> None:
    key_id, secret = auth.parse_api_key(key["api_key"])  # type: ignore[misc]
    stored = conn.execute("SELECT secret_hash FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()[0]
    assert stored == hashlib.sha256(secret.encode()).hexdigest()
    raw = _db_bytes(settings)
    assert secret.encode() not in raw and key["api_key"].encode() not in raw
    [event] = audit.query_events(conn, action="api_key.create")
    assert event["details"] == {"key_id": key_id, "principal_id": key["principal_id"], "expires_at": None}
    assert event["resource"] == "app:report-assistant"


# --- key and principal management --------------------------------------------------------


def test_issue_key_validation(conn, app) -> None:
    for days in (0, -1, 3651, True, "5", 1.5):
        with pytest.raises(ValidationFailed):
            auth.issue_api_key(conn, app["id"], expires_in_days=days, **ACTOR)
    with pytest.raises(NotFound):
        auth.issue_api_key(conn, 999, **ACTOR)
    key = auth.issue_api_key(conn, app["id"], expires_in_days=30, now=NOW, **ACTOR)
    assert key["expires_at"] == "2026-11-27T12:00:00.000Z"
    auth.update_principal(conn, app["id"], disabled=True, **ACTOR)
    with pytest.raises(Conflict, match="disabled"):
        auth.issue_api_key(conn, app["id"], **ACTOR)


def test_revoke_key(conn, app, key) -> None:
    revoked = auth.revoke_api_key(conn, key["key_id"], now=NOW, **ACTOR)
    assert revoked["revoked_at"] == "2026-10-28T12:00:00.000Z" and revoked["status"] == "revoked"
    with pytest.raises(Conflict):
        auth.revoke_api_key(conn, key["key_id"], **ACTOR)
    with pytest.raises(NotFound):
        auth.revoke_api_key(conn, "0" * 12, **ACTOR)
    for bad in ("", "ABCDEF012345", key["api_key"], None):
        with pytest.raises(ValidationFailed):
            auth.revoke_api_key(conn, bad, **ACTOR)  # type: ignore[arg-type]
    assert len(audit.query_events(conn, action="api_key.revoke")) == 1


@pytest.mark.parametrize("name", ["", "Report", "-report", "report assistant", "r" * 65, "app:report", "räport", 5])
def test_principal_names_are_validated(conn, name) -> None:
    with pytest.raises(ValidationFailed):
        auth.create_principal(conn, name, **ACTOR)


def test_principal_create_update_list(conn, app) -> None:
    assert app["environment"] == "pilot" and app["disabled"] is False and app["keys"] == []
    with pytest.raises(Conflict):
        auth.create_principal(conn, "report-assistant", **ACTOR)
    for env in ("prod", "", None, "TEST"):
        with pytest.raises(ValidationFailed):
            auth.create_principal(conn, "other", environment=env, **ACTOR)  # type: ignore[arg-type]
    with pytest.raises(ValidationFailed):
        auth.create_principal(conn, "other", description="x" * 1001, **ACTOR)
    with pytest.raises(ValidationFailed):
        auth.update_principal(conn, app["id"], **ACTOR)
    with pytest.raises(ValidationFailed):
        auth.update_principal(conn, app["id"], disabled="yes", **ACTOR)  # type: ignore[arg-type]
    with pytest.raises(NotFound):
        auth.update_principal(conn, 999, disabled=True, **ACTOR)

    updated = auth.update_principal(conn, app["id"], disabled=True, environment="production", **ACTOR)
    assert updated["disabled"] is True and updated["environment"] == "production"
    [event] = audit.query_events(conn, action="principal.update")
    assert event["details"]["changes"] == {"disabled": {"from": False, "to": True},
                                           "environment": {"from": "pilot", "to": "production"}}
    auth.update_principal(conn, app["id"], disabled=True, **ACTOR)  # no change, no event
    assert len(audit.query_events(conn, action="principal.update")) == 1

    auth.create_principal(conn, "batch-job", **ACTOR)
    key = auth.issue_api_key(conn, auth.get_principal_by_name(conn, "batch-job")["id"], **ACTOR)
    listed = {p["name"]: p for p in auth.list_principals(conn)}
    assert set(listed) == {"report-assistant", "batch-job"}
    assert [k["key_id"] for k in listed["batch-job"]["keys"]] == [key["key_id"]]
    assert listed["batch-job"]["keys"][0]["status"] == "active"
    assert "api_key" not in json.dumps(listed) and "secret" not in json.dumps(listed)
    assert [e["action"] for e in reversed(audit.query_events(conn, action="principal."))] == [
        "principal.create", "principal.update", "principal.create"]


# --- passwords -------------------------------------------------------------------------


def test_password_hash_format_and_parameters(monkeypatch) -> None:
    seen = {}
    real = auth.hashlib.scrypt

    def spy(password, **kw):
        seen.update(kw)
        return real(password, **kw)

    monkeypatch.setattr(auth.hashlib, "scrypt", spy)
    stored = auth.hash_password(PASSWORD)
    assert seen["n"] == 2**15 and seen["r"] == 8 and seen["p"] == 1 and seen["maxmem"] == 64 * 1024**2
    scheme, n, r, p, salt, digest = stored.split("$")
    assert (scheme, n, r, p) == ("scrypt", "32768", "8", "1")
    assert len(base64.b64decode(salt)) == 16 and len(base64.b64decode(digest)) == 32
    assert auth.verify_password(PASSWORD, stored) is True
    assert auth.verify_password(PASSWORD + "!", stored) is False
    assert auth.hash_password(PASSWORD) != stored  # fresh salt every time


def test_password_policy() -> None:
    with pytest.raises(ValidationFailed, match="at least 12"):
        auth.hash_password("short-pass1")
    with pytest.raises(ValidationFailed):
        auth.hash_password("x" * 1025)
    with pytest.raises(ValidationFailed):
        auth.hash_password(None)  # type: ignore[arg-type]
    assert auth.verify_password("x" * 12, auth.hash_password("x" * 12))


@pytest.mark.parametrize("stored", [
    "", "plain", "scrypt$32768$8$1$c2FsdA==", "bcrypt$32768$8$1$AAAA$AAAA", "scrypt$abc$8$1$AAAA$AAAA",
    "scrypt$32768$8$1$!!!$AAAA", "scrypt$32767$8$1$" + "A" * 24 + "$" + "A" * 44,
    "scrypt$1073741824$8$1$" + "A" * 24 + "$" + "A" * 44, "scrypt$32768$999$1$" + "A" * 24 + "$" + "A" * 44,
    "scrypt$32768$8$1$$" + "A" * 44, None,
])
def test_malformed_or_dangerous_hashes_never_verify(stored) -> None:
    assert auth.verify_password(PASSWORD, stored) is False


def test_admin_user_creation_and_login(conn, settings) -> None:
    user = auth.create_admin_user(conn, "alice", PASSWORD, "admin", actor_id="root")
    assert user["role"] == "admin" and user["username"] == "alice"
    with pytest.raises(Conflict):
        auth.create_admin_user(conn, "alice", PASSWORD, "auditor", actor_id="root")
    for name in ("Alice", "", "a b", "x" * 65):
        with pytest.raises(ValidationFailed):
            auth.create_admin_user(conn, name, PASSWORD, "admin", actor_id="root")
    with pytest.raises(ValidationFailed):
        auth.create_admin_user(conn, "bob", PASSWORD, "superuser", actor_id="root")
    with pytest.raises(ValidationFailed):
        auth.create_admin_user(conn, "bob", "too-short", "admin", actor_id="root")

    ok = auth.authenticate_admin(conn, " ALICE ", PASSWORD)
    assert ok.ok is True and ok.user["username"] == "alice"  # type: ignore[index]
    assert auth.authenticate_admin(conn, "alice", "wrong password!!").reason == "bad_password"
    assert auth.authenticate_admin(conn, "mallory", PASSWORD).reason == "unknown_user"
    assert auth.authenticate_admin(conn, "bad name!", PASSWORD).reason == "malformed"
    assert auth.authenticate_admin(conn, "alice", None).ok is False

    [event] = audit.query_events(conn, action="admin.user_create")
    assert event["details"] == {"user_id": user["id"], "username": "alice", "role": "admin"}
    assert PASSWORD.encode() not in _db_bytes(settings)


def test_unknown_users_cost_the_same_scrypt_work(conn, monkeypatch) -> None:
    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda pw, stored: calls.append(stored) or real(pw, stored))
    auth.authenticate_admin(conn, "nobody", PASSWORD)
    assert len(calls) == 1 and calls[0].startswith("scrypt$32768$8$1$")


def test_disabled_admin_cannot_log_in(conn) -> None:
    user = auth.create_admin_user(conn, "carol", PASSWORD, "auditor", actor_id="root")
    conn.execute("UPDATE admin_users SET disabled = 1 WHERE id = ?", (user["id"],))
    assert auth.authenticate_admin(conn, "carol", PASSWORD).reason == "disabled"


def test_login_failures_never_record_unknown_usernames(conn) -> None:
    auth.create_admin_user(conn, "alice", PASSWORD, "admin", actor_id="root")
    typed_password = "hunter2hunter2"  # someone typed a password into the username field
    auth.record_login_failure(conn, typed_password, "unknown_user", client_ip="10.0.0.5", correlation_id="r1")
    auth.record_login_failure(conn, "alice", "bad_password", client_ip="10.0.0.5")
    auth.record_login_failure(conn, "alice", "throttled", throttled=True)
    events = list(reversed(audit.query_events(conn, action="auth.login")))
    assert [e["actor_id"] for e in events] == ["unknown", "alice", "alice"]
    assert [e["outcome"] for e in events] == ["failure", "failure", "denied"]
    assert typed_password not in json.dumps(events)


# --- sessions ----------------------------------------------------------------------------


@pytest.fixture
def admin(conn):
    return auth.create_admin_user(conn, "alice", PASSWORD, "admin", actor_id="root")


def test_session_lifecycle(conn, settings, admin) -> None:
    token, session = auth.create_session(conn, admin["id"], settings, now=NOW, client_ip="127.0.0.1",
                                         correlation_id="req-1")
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    assert session["role"] == "admin" and session["expires_at"] == "2026-10-28T20:00:00.000Z"
    stored = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored == sha256_hex(token.encode()) and token.encode() not in _db_bytes(settings)
    resolved = auth.resolve_session(conn, token, settings, now=NOW + dt.timedelta(minutes=5))
    assert resolved["username"] == "alice" and resolved["role"] == "admin"  # type: ignore[index]
    login = audit.query_events(conn, action="auth.login")[0]
    assert login["outcome"] == "success" and login["actor_id"] == "alice" and login["correlation_id"] == "req-1"
    assert conn.execute("SELECT last_login_at FROM admin_users").fetchone()[0] == "2026-10-28T12:00:00.000Z"

    assert auth.delete_session(conn, token, client_ip="127.0.0.1") is True
    assert auth.resolve_session(conn, token, settings, now=NOW) is None
    assert auth.delete_session(conn, token) is False
    assert [e["outcome"] for e in audit.query_events(conn, action="auth.logout")] == ["success"]


@pytest.mark.parametrize("token", [None, "", "short", "x" * 44, "!" * 43, 12345])
def test_malformed_session_tokens_resolve_to_nothing(conn, settings, token) -> None:
    assert auth.resolve_session(conn, token, settings) is None
    assert auth.delete_session(conn, token) is False


def test_idle_timeout(conn, settings, admin) -> None:
    token, _ = auth.create_session(conn, admin["id"], settings, now=NOW)
    idle = dt.timedelta(minutes=settings.server.session_idle_minutes)
    t = NOW
    for _ in range(5):  # activity keeps the session alive
        t += idle - dt.timedelta(minutes=1)
        assert auth.resolve_session(conn, token, settings, now=t) is not None
    assert auth.resolve_session(conn, token, settings, now=t + idle) is None
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_absolute_timeout_despite_activity(conn, settings, admin) -> None:
    token, _ = auth.create_session(conn, admin["id"], settings, now=NOW)
    t = NOW
    while t < NOW + dt.timedelta(hours=settings.server.session_max_hours) - dt.timedelta(minutes=10):
        t += dt.timedelta(minutes=10)
        assert auth.resolve_session(conn, token, settings, now=t) is not None
    assert auth.resolve_session(conn, token, settings, now=NOW + dt.timedelta(hours=8)) is None


def test_shortened_limits_apply_to_existing_sessions(conn, settings, admin) -> None:
    token, _ = auth.create_session(conn, admin["id"], settings, now=NOW)
    stricter = replace(settings, server=ServerSettings(session_max_hours=1, session_idle_minutes=120))
    assert auth.resolve_session(conn, token, stricter, now=NOW + dt.timedelta(minutes=50)) is not None
    assert auth.resolve_session(conn, token, stricter, now=NOW + dt.timedelta(minutes=61)) is None


def test_sessions_of_disabled_users_end(conn, settings, admin) -> None:
    token, _ = auth.create_session(conn, admin["id"], settings, now=NOW)
    conn.execute("UPDATE admin_users SET disabled = 1 WHERE id = ?", (admin["id"],))
    assert auth.resolve_session(conn, token, settings, now=NOW) is None
    with pytest.raises(NotFound):
        auth.create_session(conn, admin["id"], settings)


def test_last_seen_is_refreshed_sparingly(conn, settings, admin) -> None:
    token, _ = auth.create_session(conn, admin["id"], settings, now=NOW)

    def last_seen():
        return conn.execute("SELECT last_seen_at FROM sessions").fetchone()[0]

    auth.resolve_session(conn, token, settings, now=NOW + dt.timedelta(seconds=10))
    assert last_seen() == "2026-10-28T12:00:00.000Z"
    auth.resolve_session(conn, token, settings, now=NOW + dt.timedelta(seconds=31))
    assert last_seen() == "2026-10-28T12:00:31.000Z"


def test_purge_expired_sessions(conn, settings, admin) -> None:
    auth.create_session(conn, admin["id"], settings, now=NOW - dt.timedelta(hours=9))
    live, _ = auth.create_session(conn, admin["id"], settings, now=NOW)
    assert auth.purge_expired_sessions(conn, settings, now=NOW + dt.timedelta(minutes=1)) == 1
    assert auth.resolve_session(conn, live, settings, now=NOW + dt.timedelta(minutes=2)) is not None


# --- login throttle -------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_throttle_locks_a_username_after_five_failures_and_recovers() -> None:
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock)
    for _ in range(4):
        assert throttle.record_failure("alice", "10.0.0.1") is None
        assert throttle.retry_after("alice", "10.0.0.1") is None
    assert throttle.record_failure("alice", "10.0.0.1") == 900
    assert throttle.retry_after("alice", "10.0.0.9") == 900  # locked from any address
    assert throttle.retry_after("ALICE ") == 900
    assert throttle.retry_after("bob", "10.0.0.2") is None
    clock.t += 600
    assert throttle.retry_after("alice") == 300
    clock.t += 300
    assert throttle.retry_after("alice") is None
    assert throttle.record_failure("alice") is None  # counting starts again


def test_throttle_locks_a_client_address_after_twenty_failures() -> None:
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock)
    for i in range(19):
        assert throttle.record_failure(f"user{i}", "192.168.1.50") is None
    assert throttle.record_failure("user19", "192.168.1.50") == 900
    assert throttle.retry_after("someone-new", "192.168.1.50") == 900
    assert throttle.retry_after("someone-new", "192.168.1.51") is None


def test_throttle_failures_outside_the_window_expire() -> None:
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock)
    for _ in range(4):
        throttle.record_failure("alice")
    clock.t += 901
    assert throttle.record_failure("alice") is None
    assert throttle.retry_after("alice") is None


def test_successful_login_clears_username_failures_only() -> None:
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock, max_ip_failures=6)
    for _ in range(4):
        throttle.record_failure("alice", "10.0.0.1")
    throttle.record_success("alice", "10.0.0.1")
    assert throttle.record_failure("alice", "10.0.0.1") is None
    assert throttle.record_failure("bob", "10.0.0.1") == 900  # the address kept its count


def test_throttle_pruning_never_drops_an_active_lock() -> None:
    clock = Clock()
    throttle = auth.LoginThrottle(clock=clock, max_entries=10)
    for _ in range(5):
        throttle.record_failure("victim")
    for i in range(50):
        clock.t += 1
        throttle.record_failure(f"noise{i}")
    assert throttle.retry_after("victim") is not None
