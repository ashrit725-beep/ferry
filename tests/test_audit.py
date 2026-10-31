"""Tests for ferry.audit: the hash chain, checkpoints, sanitizing, queries, export."""

from __future__ import annotations

import io
import json
import math
import sqlite3
from pathlib import Path

import pytest

from ferry import audit, cli, crypto, db
from ferry.db import Database, write_tx
from ferry.gateway import admin_api
from ferry.util import canonical_json


def _append(conn, n: int = 1, **overrides):
    out = []
    for i in range(n):
        kw = {"actor_type": "cli", "actor_id": "alice", "action": "bundle.import", "resource": f"bundle:{i}",
              "outcome": "success", "details": {"i": i}}
        kw.update(overrides)
        out.append(audit.append_event(conn, **kw))
    return out


def _sql(conn, sql: str, params=()) -> None:
    with write_tx(conn):
        conn.execute(sql, params)


# --- chain --------------------------------------------------------------------


def test_append_links_events_into_a_chain(conn) -> None:
    first, second, third = _append(conn, 3)
    assert first["seq"] == 1 and first["prev_hash"] == audit.GENESIS_HASH
    assert second["prev_hash"] == first["hash"] and third["prev_hash"] == second["hash"]
    assert first["hash"] == audit.compute_hash(first)
    assert audit.head(conn) == {"seq": 3, "hash": third["hash"], "ts": third["ts"]}
    result = audit.verify_chain(conn)
    assert result["ok"] is True and result["events_checked"] == 3 and result["head_seq"] == 3
    assert result["head_hash"] == third["hash"] and result["first_bad_seq"] is None


def test_empty_log_verifies(conn) -> None:
    result = audit.verify_chain(conn)
    assert result["ok"] is True and result["events_checked"] == 0
    assert audit.head(conn) == {"seq": 0, "hash": audit.GENESIS_HASH, "ts": None}


def test_append_joins_an_open_write_transaction_and_rolls_back_with_it(conn) -> None:
    with pytest.raises(RuntimeError):
        with write_tx(conn):
            audit.append_event(conn, actor_type="cli", actor_id="a", action="trust.add", resource="k",
                               outcome="success")
            raise RuntimeError("operation failed after auditing")
    assert audit.head(conn)["seq"] == 0


@pytest.mark.parametrize("bad", [
    {"actor_type": "root"},
    {"outcome": "maybe"},
    {"action": "Bad Action"},
    {"action": "x"},
])
def test_append_rejects_unknown_vocabulary(conn, bad) -> None:
    kw = {"actor_type": "cli", "actor_id": "a", "action": "policy.activate", "resource": "r", "outcome": "success",
          **bad}
    with pytest.raises(ValueError):
        audit.append_event(conn, **kw)


def test_modified_event_is_detected(conn) -> None:
    _append(conn, 3)
    _sql(conn, "UPDATE audit_events SET details = ? WHERE seq = 2", ('{"i":99}',))
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 2
    assert "modified" in result["problem"]


@pytest.mark.parametrize("column, value", [("outcome", "denied"), ("actor_id", "mallory"), ("ts", "2020-01-01T00:00:00.000Z")])
def test_modified_column_is_detected(conn, column: str, value: str) -> None:
    _append(conn, 3)
    _sql(conn, f"UPDATE audit_events SET {column} = ? WHERE seq = 3", (value,))
    assert audit.verify_chain(conn)["first_bad_seq"] == 3


def test_details_replaced_with_invalid_json_is_reported_not_raised(conn) -> None:
    _append(conn, 2)
    _sql(conn, "UPDATE audit_events SET details = 'not json' WHERE seq = 1")
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 1


def test_rehashed_modification_is_still_detected_by_the_next_event(conn) -> None:
    events = _append(conn, 3)
    forged = dict(events[1], details={"i": 99})
    forged["hash"] = audit.compute_hash(forged)
    _sql(conn, "UPDATE audit_events SET details = ?, hash = ? WHERE seq = 2",
         (canonical_json(forged["details"]).decode(), forged["hash"]))
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 3
    assert "prev_hash" in result["problem"]


def test_deleted_event_is_detected(conn) -> None:
    _append(conn, 4)
    _sql(conn, "DELETE FROM audit_events WHERE seq = 2")
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 2
    assert "gap" in result["problem"]


def test_inserted_event_is_detected(conn) -> None:
    events = _append(conn, 3)
    # Make room after seq 1 and insert a well-formed event that links to seq 1.
    for seq in (3, 2):
        _sql(conn, "UPDATE audit_events SET seq = seq + 1 WHERE seq = ?", (seq,))
    fake = {"seq": 2, "event_id": "f" * 32, "ts": events[0]["ts"], "actor_type": "cli", "actor_id": "mallory",
            "action": "policy.activate", "resource": "policy:9", "outcome": "success", "correlation_id": None,
            "policy_version": None, "details": {}, "prev_hash": events[0]["hash"]}
    fake["hash"] = audit.compute_hash(fake)
    _sql(conn, "INSERT INTO audit_events (seq, event_id, ts, actor_type, actor_id, action, resource, outcome,"
               " correlation_id, policy_version, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (2, fake["event_id"], fake["ts"], "cli", "mallory", "policy.activate", "policy:9", "success", None, None, "{}",
          fake["prev_hash"], fake["hash"]))
    result = audit.verify_chain(conn)
    assert result["ok"] is False and result["first_bad_seq"] == 3


def test_tail_truncation_needs_a_checkpoint_to_be_detected(conn) -> None:
    _append(conn, 5)
    checkpoint = audit.make_checkpoint(conn)
    assert checkpoint["schema"] == audit.CHECKPOINT_SCHEMA and checkpoint["seq"] == 5
    assert audit.verify_chain(conn, checkpoint)["checkpoint_verified"] is True
    _sql(conn, "DELETE FROM audit_events WHERE seq >= 4")
    # Without the checkpoint, a truncated log is internally consistent.
    assert audit.verify_chain(conn)["ok"] is True
    result = audit.verify_chain(conn, checkpoint)
    assert result["ok"] is False and result["checkpoint_verified"] is False
    assert "beyond the end" in result["problem"]


def test_rebuilt_chain_is_detected_by_checkpoint(conn) -> None:
    _append(conn, 3)
    checkpoint = audit.make_checkpoint(conn)
    _sql(conn, "DELETE FROM audit_events")
    _append(conn, 3, actor_id="mallory")
    assert audit.verify_chain(conn)["ok"] is True
    result = audit.verify_chain(conn, checkpoint)
    assert result["ok"] is False and result["first_bad_seq"] == 3


def test_checkpoint_of_an_empty_log_stays_valid(conn) -> None:
    checkpoint = audit.make_checkpoint(conn)
    assert checkpoint["seq"] == 0 and checkpoint["hash"] == audit.GENESIS_HASH
    assert audit.verify_chain(conn, checkpoint)["ok"] is True
    _append(conn, 2)
    assert audit.verify_chain(conn, checkpoint)["ok"] is True
    assert audit.verify_chain(conn, {"seq": 0, "hash": "1" * 64})["ok"] is False


def test_checkpoint_mid_log_still_verifies_after_more_events(conn) -> None:
    _append(conn, 2)
    checkpoint = audit.make_checkpoint(conn)
    _append(conn, 3)
    assert audit.verify_chain(conn, checkpoint)["ok"] is True


# --- signed checkpoints ----------------------------------------------------------


def test_signed_checkpoint_verifies_and_forgeries_do_not(conn) -> None:
    _append(conn, 2)
    key = crypto.generate_private_key()
    checkpoint = audit.make_checkpoint(conn, key)
    assert checkpoint["signature"]["alg"] == "ed25519"
    assert checkpoint["signature"]["key_id"] == crypto.key_id(key.public_key())
    assert audit.verify_checkpoint_signature(checkpoint, key.public_key()) is True
    # A file round trip keeps it valid.
    assert audit.verify_checkpoint_signature(json.loads(json.dumps(checkpoint)), key.public_key()) is True

    other = crypto.generate_private_key()
    assert audit.verify_checkpoint_signature(checkpoint, other.public_key()) is False
    forged = {**checkpoint, "seq": checkpoint["seq"] + 1}
    assert audit.verify_checkpoint_signature(forged, key.public_key()) is False
    resigned_by_other = audit.make_checkpoint(conn, other)
    resigned_by_other["signature"]["key_id"] = checkpoint["signature"]["key_id"]
    assert audit.verify_checkpoint_signature(resigned_by_other, key.public_key()) is False
    unsigned = {k: v for k, v in checkpoint.items() if k != "signature"}
    assert audit.verify_checkpoint_signature(unsigned, key.public_key()) is False
    for sig in ("not base64!!", "", "AAAA", 12345, None):
        bad = {**checkpoint, "signature": {**checkpoint["signature"], "sig": sig}}
        assert audit.verify_checkpoint_signature(bad, key.public_key()) is False
    weird = {**checkpoint, "seq": math.nan}
    assert audit.verify_checkpoint_signature(weird, key.public_key()) is False


# --- sanitize ------------------------------------------------------------------


def test_sanitize_redacts_prompt_content_and_credentials() -> None:
    raw = {
        "prompt": "secret prompt", "messages": [{"role": "user", "content": "hi"}], "content": "x",
        "api_key": "fyk_abc", "Authorization": "Bearer abc", "password": "hunter2", "token": "t",
        "nested": {"access_token": "a", "X-Auth-Token": "b", "db_password": "c", "keep": "visible",
                   "list": [{"completion": "words"}, {"choices": [1]}]},
        "prompt_tokens": 11, "completion_tokens": 5, "max_tokens": 64, "key_id": "abcdef012345",
    }
    clean = audit.sanitize(raw)
    for key in ("prompt", "messages", "content", "api_key", "Authorization", "password", "token"):
        assert clean[key] == "[redacted]", key
    assert clean["nested"]["access_token"] == "[redacted]"
    assert clean["nested"]["X-Auth-Token"] == "[redacted]"
    assert clean["nested"]["db_password"] == "[redacted]"
    assert clean["nested"]["keep"] == "visible"
    assert clean["nested"]["list"] == [{"completion": "[redacted]"}, {"choices": "[redacted]"}]
    # Counters and identifiers that merely contain those words stay readable.
    assert clean["prompt_tokens"] == 11 and clean["completion_tokens"] == 5 and clean["max_tokens"] == 64
    assert clean["key_id"] == "abcdef012345"
    assert raw["password"] == "hunter2", "sanitize must not modify its input"


@pytest.mark.parametrize("key", ["accessToken", "authToken", "clientSecret", "userPassword", "x-api-key",
                                 "privateKey", "sessionCookie", "API_KEY", " Token "])
def test_sanitize_redacts_camel_case_and_run_together_names(key: str) -> None:
    assert audit.sanitize({key: "s3cr3t"})[key] == "[redacted]"


def test_sanitize_bounds_size_depth_and_odd_values() -> None:
    clean = audit.sanitize({"long": "x" * 5000, "many": list(range(150)), "deep": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}},
                            "nan": math.nan, "inf": math.inf, "set": {1}, "tuple": (1, 2)})
    assert len(clean["long"]) < 1100 and clean["long"].endswith("[truncated]")
    assert len(clean["many"]) == 101 and clean["many"][-1] == "[50 more items]"
    assert "[depth limit]" in json.dumps(clean["deep"])
    assert clean["nan"] == "nan" and clean["inf"] == "inf"
    assert clean["tuple"] == [1, 2] and isinstance(clean["set"], str)
    wide = audit.sanitize({f"k{i}": i for i in range(150)})
    assert wide["_truncated_keys"] == 50


def test_details_are_sanitized_before_hashing_and_storage(conn) -> None:
    event = audit.append_event(conn, actor_type="app", actor_id="a", action="gateway.chat.completions",
                               resource="model:m", outcome="success",
                               details={"messages": [{"content": "TOP-SECRET-PROMPT"}], "api_key": "fyk_x"})
    assert event["details"] == {"messages": "[redacted]", "api_key": "[redacted]"}
    stored = conn.execute("SELECT details FROM audit_events WHERE seq = ?", (event["seq"],)).fetchone()[0]
    assert "TOP-SECRET-PROMPT" not in stored and "fyk_x" not in stored
    assert audit.verify_chain(conn)["ok"] is True


# --- queries, facets, export ----------------------------------------------------------


@pytest.fixture
def populated(conn):
    audit.append_event(conn, actor_type="cli", actor_id="alice", action="bundle.import", resource="bundle:a",
                       outcome="success", correlation_id="job-1", details={"note": "50% done"})
    audit.append_event(conn, actor_type="cli", actor_id="alice", action="bundle.verify", resource="bundle:b",
                       outcome="rejected", details={"note": "a_b"})
    audit.append_event(conn, actor_type="admin", actor_id="bob", action="policy.activate", resource="policy:1",
                       outcome="success", policy_version=1, details={"note": "plain"})
    audit.append_event(conn, actor_type="app", actor_id="report", action="gateway.chat.completions",
                       resource="model:m", outcome="denied", details={"note": "axb"})
    return conn


def test_query_filters(populated) -> None:
    conn = populated
    assert [e["seq"] for e in audit.query_events(conn)] == [4, 3, 2, 1]  # newest first
    assert [e["seq"] for e in audit.query_events(conn, action="bundle.")] == [2, 1]
    assert [e["seq"] for e in audit.query_events(conn, action="bundle*")] == [2, 1]
    assert [e["seq"] for e in audit.query_events(conn, action="bundle")] == []  # exact match only
    assert [e["seq"] for e in audit.query_events(conn, outcome="denied")] == [4]
    assert [e["seq"] for e in audit.query_events(conn, actor_id="alice", outcome="rejected")] == [2]
    assert [e["seq"] for e in audit.query_events(conn, actor_type="admin")] == [3]
    assert [e["seq"] for e in audit.query_events(conn, resource="model:m")] == [4]
    assert [e["seq"] for e in audit.query_events(conn, correlation_id="job-1")] == [1]
    assert [e["seq"] for e in audit.query_events(conn, before_seq=3)] == [2, 1]
    assert [e["seq"] for e in audit.query_events(conn, limit=2)] == [4, 3]
    assert len(audit.query_events(conn, limit=0)) == 1 and len(audit.query_events(conn, limit=10_000)) == 4
    ts = audit.get_event(conn, 2)["ts"]  # type: ignore[index]
    assert all(e["ts"] >= ts for e in audit.query_events(conn, since=ts))
    assert all(e["ts"] <= ts for e in audit.query_events(conn, until=ts))


def test_query_text_search_escapes_like_wildcards(populated) -> None:
    conn = populated
    assert [e["seq"] for e in audit.query_events(conn, q="50%")] == [1]
    assert [e["seq"] for e in audit.query_events(conn, q="a_b")] == [2]  # "_" must not match "axb"
    assert [e["seq"] for e in audit.query_events(conn, q="%")] == [1]
    assert audit.query_events(conn, q="\\") == []
    assert [e["seq"] for e in audit.query_events(conn, q="report")] == [4]
    assert [e["seq"] for e in audit.query_events(conn, action="bundle_")] == []


def test_query_prefix_does_not_treat_underscore_as_wildcard(conn) -> None:
    audit.append_event(conn, actor_type="cli", actor_id="a", action="ab.c", resource="r", outcome="success")
    audit.append_event(conn, actor_type="cli", actor_id="a", action="a_.c", resource="r", outcome="success")
    assert [e["action"] for e in audit.query_events(conn, action="a_.")] == ["a_.c"]


def test_get_event_and_facets(populated) -> None:
    assert audit.get_event(populated, 3)["action"] == "policy.activate"  # type: ignore[index]
    assert audit.get_event(populated, 99) is None
    f = audit.facets(populated)
    assert f["actions"] == ["bundle.import", "bundle.verify", "gateway.chat.completions", "policy.activate"]
    assert f["outcomes"] == ["denied", "rejected", "success"]
    assert f["actor_types"] == ["admin", "app", "cli"]


def test_export_jsonl_writes_every_event_oldest_first(populated) -> None:
    buf = io.StringIO()
    assert audit.export_jsonl(populated, buf) == 4
    lines = buf.getvalue().splitlines()
    events = [json.loads(line) for line in lines]
    assert [e["seq"] for e in events] == [1, 2, 3, 4]
    assert all(line == canonical_json(e).decode() for line, e in zip(lines, events))
    assert all(audit.compute_hash(e) == e["hash"] for e in events)
    assert events[1]["prev_hash"] == events[0]["hash"]


def test_facets_list_every_value_present_including_off_vocabulary_ones(populated) -> None:
    _sql(populated, "UPDATE audit_events SET outcome = 'tampered' WHERE seq = 2")
    f = audit.facets(populated)
    assert f["outcomes"] == ["denied", "success", "tampered"]
    assert f["actions"] == ["bundle.import", "bundle.verify", "gateway.chat.completions", "policy.activate"]
    assert f["actor_types"] == ["admin", "app", "cli"]


def test_facets_of_an_empty_log(conn) -> None:
    assert audit.facets(conn) == {"actions": [], "outcomes": [], "actor_types": []}


def test_export_reports_the_head_of_what_it_wrote(populated) -> None:
    buf = io.StringIO()
    written = audit.export(populated, buf)
    last = json.loads(buf.getvalue().splitlines()[-1])
    assert written == {"events": 4, "head_seq": last["seq"], "head_hash": last["hash"]}


def test_export_of_an_empty_log_reports_the_genesis_head(conn) -> None:
    assert audit.export(conn, io.StringIO()) == {"events": 0, "head_seq": 0, "head_hash": audit.GENESIS_HASH}


# --- the audit.export record vouches for the exported file (SF-8) -----------------


def _append_after_export(monkeypatch, database: Database) -> None:
    """Make audit.export append one event from another connection right after it writes,
    as a gateway request audited between the export and its own record would."""
    original = audit.export

    def racing(conn, fh):
        result = original(conn, fh)
        with database.session() as other:
            audit.append_event(other, actor_type="system", actor_id="health", action="backend.health",
                               resource="backend:b", outcome="success")
        return result

    monkeypatch.setattr(audit, "export", racing)


def _assert_record_matches_last_line(conn: sqlite3.Connection, lines: list[str]) -> None:
    last = json.loads(lines[-1])
    record = audit.query_events(conn, action="audit.export", limit=1)[0]["details"]
    assert record["events"] == len(lines)
    assert (record["head_seq"], record["head_hash"]) == (last["seq"], last["hash"])
    assert audit.head(conn)["seq"] == last["seq"] + 2, "the racing event and the export record follow the file"


def test_api_export_record_names_the_last_exported_event(tmp_path: Path, monkeypatch) -> None:
    from helpers_app import app_env

    with app_env(tmp_path / "data") as env:
        env.post("/api/apps", {"name": "exported", "environment": "test"})
        _append_after_export(monkeypatch, env.database)
        response = env.get("/api/audit/export")
        assert response.status_code == 200
        with env.conn() as c:
            _assert_record_matches_last_line(c, response.text.splitlines())


def test_cli_export_record_names_the_last_exported_event(settings, conn, tmp_path: Path, monkeypatch) -> None:
    _append(conn, 3)
    _append_after_export(monkeypatch, Database(settings.db_path))
    out = tmp_path / "audit.ndjson"
    assert cli.main(["--data-dir", str(settings.data_dir), "audit", "export", "--out", str(out)]) == 0
    _assert_record_matches_last_line(conn, out.read_text().splitlines())


# --- query plans and the v2 migration (perf-2, perf-3) -----------------------------


def _plans(conn: sqlite3.Connection, run) -> list[str]:
    """EXPLAIN QUERY PLAN of every audit_events statement `run` executes."""
    statements: list[str] = []
    conn.set_trace_callback(statements.append)
    try:
        run()
    finally:
        conn.set_trace_callback(None)
    plans = []
    for sql in statements:
        if "audit_events" in sql and sql.lstrip().upper().startswith("SELECT"):
            plans.append(" | ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql)))
    assert plans, "nothing was traced"
    return plans


def test_traffic_summary_searches_the_action_ts_index(populated) -> None:
    plans = _plans(populated, lambda: admin_api.traffic_summary(populated, "2000-01-01T00:00:00.000Z"))
    assert all("action=? AND ts>?" in p for p in plans), plans


def test_facets_and_filtered_pages_do_not_scan_the_log(populated) -> None:
    for run in (lambda: audit.facets(populated),
                lambda: audit.query_events(populated, resource="bundle:missing"),
                lambda: audit.query_events(populated, actor_type="system"),
                lambda: audit.query_events(populated, action="gateway.chat.completions"),
                lambda: audit.query_events(populated, outcome="denied")):
        for plan in _plans(populated, run):
            assert "SCAN audit_events" not in plan and "TEMP B-TREE" not in plan, plan


def _chat(conn: sqlite3.Connection, outcome: str, env: str, ms: int) -> None:
    audit.append_event(conn, actor_type="app", actor_id="app-1", action=admin_api.CHAT_ACTION, resource="model:m",
                       outcome=outcome, details={"environment": env, "latency_ms": ms})


def _indexes(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'"
                                       " AND tbl_name = 'audit_events'")}


def test_a_v1_database_is_upgraded_to_v2_with_the_same_traffic_summary(tmp_path: Path) -> None:
    path = tmp_path / "v1" / "ferry.db"
    path.parent.mkdir()
    c = db.connect(path)
    try:
        db.current_version(c)
        with write_tx(c):
            for statement in db._statements(db.SCHEMA_V1):
                c.execute(statement)
            c.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-01-01T00:00:00.000Z')")
        for i, (outcome, env) in enumerate([("success", "test"), ("success", "pilot"), ("denied", "production"),
                                            ("error", "test"), ("success", "production")]):
            _chat(c, outcome, env, 10 * (i + 1))
        audit.append_event(c, actor_type="cli", actor_id="a", action="bundle.import", resource="bundle:x",
                           outcome="success")
        assert "idx_audit_action_ts" not in _indexes(c)
        before = admin_api.traffic_summary(c, "2000-01-01T00:00:00.000Z")
    finally:
        c.close()

    assert Database(path).init() == db.LATEST_VERSION == 2
    with Database(path).session() as c:
        assert {"idx_audit_action_ts", "idx_audit_resource_seq", "idx_audit_actor_type_seq",
                "idx_audit_action"} <= _indexes(c)
        assert admin_api.traffic_summary(c, "2000-01-01T00:00:00.000Z") == before
        assert before[0]["total"] == 5 and before[0]["success"] == 3 and before[1]["production"] == 2
        assert audit.verify_chain(c)["ok"] is True
