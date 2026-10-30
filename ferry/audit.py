"""Append-only, hash-chained audit log.

Every event stores the SHA-256 of its predecessor (`prev_hash`) and of its own
canonical form (`hash`), so editing or deleting an event in the middle of the
log breaks the chain and `verify_chain` names the first broken sequence number.

What this does NOT guarantee: someone who can write the database file can
delete the newest events (tail truncation) or rebuild the chain from some point
onward. Checkpoints (seq + hash, optionally signed with a site key) kept outside
the database are what make those changes detectable. Nothing here makes the log
tamper-proof.

Prompts, completions and credentials are never recorded: `sanitize` replaces
values under sensitive keys with "[redacted]" before anything is hashed or stored.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from typing import IO, Any

from . import crypto
from .db import write_tx
from .util import canonical_json, new_event_id, rfc3339, sha256_hex

GENESIS_HASH = "0" * 64
HASHED_FIELDS = (
    "seq", "event_id", "ts", "actor_type", "actor_id", "action", "resource",
    "outcome", "correlation_id", "policy_version", "details", "prev_hash",
)
ACTOR_TYPES = ("admin", "app", "cli", "system")
OUTCOMES = ("success", "failure", "denied", "error", "unavailable", "rejected", "unauthenticated", "accepted")
CHECKPOINT_SCHEMA = "ferry.dev/audit-checkpoint/v1"
_ACTION = re.compile(r"^[a-z][a-z0-9_.]{1,63}$")

_REDACT_EXACT = frozenset({
    "authorization", "cookie", "set_cookie", "password", "passphrase", "secret", "token",
    "api_key", "apikey", "access_token", "refresh_token", "session", "private_key",
    "prompt", "prompts", "messages", "content", "completion", "completions", "choices",
    "input", "inputs", "output", "outputs", "text",
})
_REDACT_SUFFIXES = ("_secret", "_password", "_passphrase", "_token", "_cookie")
# Matched against the key with separators removed, so camelCase and run-together
# spellings ("accessToken", "clientSecret", "x-api-key") are caught too.
_REDACT_COMPACT_SUFFIXES = ("secret", "password", "passphrase", "token", "cookie", "apikey", "privatekey")
_MAX_STRING = 1024
_MAX_ITEMS = 100
_MAX_DEPTH = 6


def _sensitive(key: str) -> bool:
    k = key.strip().lower().replace("-", "_")
    return k in _REDACT_EXACT or k.endswith(_REDACT_SUFFIXES) or k.replace("_", "").endswith(_REDACT_COMPACT_SUFFIXES)


def sanitize(value: Any, _depth: int = 0) -> Any:
    """Copy `value` with sensitive keys redacted and sizes bounded."""
    if _depth > _MAX_DEPTH:
        return "[depth limit]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                out["_truncated_keys"] = len(value) - _MAX_ITEMS
                break
            key = str(k)
            out[key] = "[redacted]" if _sensitive(key) else sanitize(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [sanitize(v, _depth + 1) for v in list(value)[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            items.append(f"[{len(value) - _MAX_ITEMS} more items]")
        return items
    if isinstance(value, str):
        return value if len(value) <= _MAX_STRING else value[:_MAX_STRING] + "…[truncated]"
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    text = str(value)
    return text if len(text) <= _MAX_STRING else text[:_MAX_STRING] + "…[truncated]"


def compute_hash(event: dict[str, Any]) -> str:
    return sha256_hex(canonical_json({k: event[k] for k in HASHED_FIELDS}))


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    event = {k: row[k] for k in HASHED_FIELDS if k != "details"}
    event["details"] = json.loads(row["details"])
    event["hash"] = row["hash"]
    return event


def _row_to_event_lenient(row: sqlite3.Row) -> dict[str, Any]:
    """For readers and exports. A row whose details were tampered into invalid
    JSON comes back with a marker instead of raising, so the console and the
    export keep working and show the damage. verify_chain uses the strict reader."""
    try:
        return _row_to_event(row)
    except (ValueError, TypeError, RecursionError):
        event = {k: row[k] for k in HASHED_FIELDS if k != "details"}
        raw = row["details"]
        text = raw if isinstance(raw, str) else repr(raw)
        event["details"] = {"_unreadable": True, "raw": text[:1024]}
        event["hash"] = row["hash"]
        event["integrity"] = "details_unparseable"
        return event


def append_event(
    conn: sqlite3.Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    resource: str,
    outcome: str,
    correlation_id: str | None = None,
    policy_version: int | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one event and return it. Joins the caller's transaction if one is open
    (it must have been opened with db.write_tx), otherwise runs in its own."""
    if actor_type not in ACTOR_TYPES:
        raise ValueError(f"unknown actor_type {actor_type!r}")
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome {outcome!r}")
    if not _ACTION.fullmatch(action):
        raise ValueError(f"invalid action name {action!r}")
    clean = sanitize(details or {})

    def insert(c: sqlite3.Connection) -> dict[str, Any]:
        last = c.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        event: dict[str, Any] = {
            "seq": (last["seq"] + 1) if last else 1,
            "event_id": new_event_id(),
            "ts": rfc3339(),
            "actor_type": actor_type,
            "actor_id": str(actor_id)[:256],
            "action": action,
            "resource": str(resource)[:512],
            "outcome": outcome,
            "correlation_id": str(correlation_id)[:128] if correlation_id else None,
            "policy_version": policy_version,
            "details": clean,
            "prev_hash": last["hash"] if last else GENESIS_HASH,
        }
        event["hash"] = compute_hash(event)
        c.execute(
            "INSERT INTO audit_events (seq, event_id, ts, actor_type, actor_id, action, resource, outcome,"
            " correlation_id, policy_version, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["seq"], event["event_id"], event["ts"], event["actor_type"], event["actor_id"],
                event["action"], event["resource"], event["outcome"], event["correlation_id"],
                event["policy_version"], canonical_json(clean).decode("ascii"), event["prev_hash"], event["hash"],
            ),
        )
        return event

    if conn.in_transaction:
        return insert(conn)
    with write_tx(conn):
        return insert(conn)


def head(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("SELECT seq, hash, ts FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    if row is None:
        return {"seq": 0, "hash": GENESIS_HASH, "ts": None}
    return {"seq": row["seq"], "hash": row["hash"], "ts": row["ts"]}


def verify_chain(conn: sqlite3.Connection, checkpoint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recompute the whole chain. If `checkpoint` ({seq, hash}) is given, also
    confirm the log still contains that exact event."""
    expected, prev, checked = 1, GENESIS_HASH, 0
    # A checkpoint of an empty log (seq 0) names no event; it holds if it carries the genesis hash.
    checkpoint_seen = checkpoint is None or (checkpoint.get("seq") == 0 and checkpoint.get("hash") == GENESIS_HASH)

    def result(ok: bool, problem: str | None = None, bad: int | None = None) -> dict[str, Any]:
        return {
            "ok": ok,
            "events_checked": checked,
            "head_seq": expected - 1,
            "head_hash": prev,
            "first_bad_seq": bad,
            "problem": problem,
            "checkpoint_verified": bool(checkpoint) and ok,
            "verified_at": rfc3339(),
        }

    cur = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC")
    while True:
        rows = cur.fetchmany(1000)
        if not rows:
            break
        for row in rows:
            try:
                event = _row_to_event(row)
            except (ValueError, TypeError, RecursionError):
                return result(False, "event details are not valid JSON (modified)", row["seq"])
            if event["seq"] != expected:
                return result(False, f"sequence gap: expected {expected}, found {event['seq']} (events deleted)", expected)
            if event["prev_hash"] != prev:
                return result(False, "prev_hash does not match the preceding event", event["seq"])
            try:
                hashed = compute_hash(event)
                # append_event stores details in canonical form, so any other text that parses
                # to the same value (a duplicate key, say) was written by someone else.
                canonical = row["details"] == canonical_json(event["details"]).decode("ascii")
            except (ValueError, TypeError, RecursionError):  # NaN, a BLOB, nesting too deep to encode
                return result(False, "event content cannot be hashed (modified)", event["seq"])
            if hashed != event["hash"]:
                return result(False, "event content does not match its hash (modified)", event["seq"])
            if not canonical:
                return result(False, "event details are not in canonical form (modified)", event["seq"])
            if checkpoint is not None and event["seq"] == checkpoint.get("seq"):
                if event["hash"] != checkpoint.get("hash"):
                    return result(False, "event at checkpoint seq has a different hash than the checkpoint", event["seq"])
                checkpoint_seen = True
            prev = event["hash"]
            expected += 1
            checked += 1
    if not checkpoint_seen:
        assert checkpoint is not None
        return result(False, f"checkpoint seq {checkpoint.get('seq')} is beyond the end of the log (events removed)",
                      checkpoint.get("seq"))
    return result(True)


def make_checkpoint(conn: sqlite3.Connection, signing_key: Any | None = None) -> dict[str, Any]:
    """Describe the current head. Store the result outside the database."""
    h = head(conn)
    cp: dict[str, Any] = {
        "schema": CHECKPOINT_SCHEMA,
        "seq": h["seq"],
        "hash": h["hash"],
        "event_ts": h["ts"],
        "created_at": rfc3339(),
    }
    if signing_key is not None:
        sig = crypto.sign(signing_key, canonical_json(cp))
        cp["signature"] = {
            "key_id": crypto.key_id(signing_key.public_key()),
            "alg": "ed25519",
            "sig": base64.b64encode(sig).decode("ascii"),
        }
    return cp


def verify_checkpoint_signature(checkpoint: dict[str, Any], public_key: Any) -> bool:
    sig = checkpoint.get("signature")
    if not isinstance(sig, dict) or sig.get("key_id") != crypto.key_id(public_key):
        return False
    body = {k: v for k, v in checkpoint.items() if k != "signature"}
    try:
        raw = base64.b64decode(sig.get("sig", ""), validate=True)
        signed = canonical_json(body)
    except (ValueError, TypeError):
        return False
    return crypto.verify(public_key, raw, signed)


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def query_events(
    conn: sqlite3.Connection,
    *,
    action: str | None = None,
    outcome: str | None = None,
    actor_id: str | None = None,
    actor_type: str | None = None,
    resource: str | None = None,
    correlation_id: str | None = None,
    q: str | None = None,
    since: str | None = None,
    until: str | None = None,
    before_seq: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Newest first. `action` ending in '.' or '*' matches a prefix (e.g. 'bundle.')."""
    where, params = [], []
    if action:
        if action.endswith((".", "*")):
            where.append("action LIKE ? ESCAPE '\\'")
            params.append(_like(action.rstrip("*"))[1:])
        else:
            where.append("action = ?")
            params.append(action)
    for column, value in (("outcome", outcome), ("actor_id", actor_id), ("actor_type", actor_type),
                          ("resource", resource), ("correlation_id", correlation_id)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if since:
        where.append("ts >= ?")
        params.append(since)
    if until:
        where.append("ts <= ?")
        params.append(until)
    if before_seq is not None:
        where.append("seq < ?")
        params.append(int(before_seq))
    if q:
        pattern = _like(q)
        where.append("(action LIKE ? ESCAPE '\\' OR resource LIKE ? ESCAPE '\\' OR actor_id LIKE ? ESCAPE '\\'"
                     " OR correlation_id LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\')")
        params.extend([pattern] * 5)
    sql = "SELECT * FROM audit_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY seq DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    return [_row_to_event_lenient(r) for r in conn.execute(sql, params).fetchall()]


def get_event(conn: sqlite3.Connection, seq: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM audit_events WHERE seq = ?", (seq,)).fetchone()
    return _row_to_event_lenient(row) if row else None


def facets(conn: sqlite3.Connection) -> dict[str, list[str]]:
    def distinct(column: str) -> list[str]:
        return [r[0] for r in conn.execute(f"SELECT DISTINCT {column} FROM audit_events ORDER BY {column}")]

    return {"actions": distinct("action"), "outcomes": distinct("outcome"), "actor_types": distinct("actor_type")}


def export_jsonl(conn: sqlite3.Connection, fh: IO[str]) -> int:
    """Write every event, oldest first, one canonical JSON object per line."""
    count = 0
    cur = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC")
    while True:
        rows = cur.fetchmany(1000)
        if not rows:
            break
        for row in rows:
            fh.write(canonical_json(_row_to_event_lenient(row)).decode("ascii") + "\n")
            count += 1
    return count
