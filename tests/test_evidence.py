"""Evidence report tests (spec section 10): every section is present and built
from real records, the report says what it is and is not, nothing secret is in
it, the Markdown rendering escapes table-breaking text, and a broken audit
chain or a missing policy is reported plainly.
"""

from __future__ import annotations

import importlib.metadata
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from helpers_app import app_env, app_settings, bundle_setup, init_database
from helpers_bundle import make_signer
from helpers_gateway import (
    ACTOR,
    activate,
    add_app,
    add_backend,
    allow,
    set_status,
    store_path,
)

from ferry import audit, backends
from ferry.bundle.importer import import_bundle, verify_only
from ferry.config import Settings
from ferry.db import Database, write_tx
from ferry.evidence import STATEMENT, build_evidence, render_markdown
from ferry.trust import add_key

SECTIONS = {"report", "statement", "generated_at", "ferry_version", "host", "config", "import_policy", "trust_anchors",
            "trust_problems", "bundles", "verifications", "routes", "active_policy", "policy_history", "audit",
            "network_inventory", "dependencies"}


@dataclass
class Populated:
    settings: Settings
    database: Database
    bundle_id: str
    digest: str
    api_key: str
    backend_token: str


@pytest.fixture
def populated(tmp_path: Path) -> Populated:
    setup = bundle_setup(tmp_path)
    settings = app_settings(tmp_path / "data", imports=setup.imports)
    database = init_database(settings)
    result = import_bundle(settings, database, setup.bundle, actor_type="cli", actor_id="pytest")
    assert result.accepted
    data = bytearray(setup.bundle.read_bytes())
    data[data.rfind(b"Apache License")] ^= 0x01
    tampered = tmp_path / "tampered.ferry.tar"
    tampered.write_bytes(bytes(data))
    assert not verify_only(settings, database, tampered, actor_type="cli", actor_id="pytest").accepted
    digest = next(a["actual_sha256"] for a in result.report.artifacts if a["kind"] == "model")
    with database.session() as conn:
        backend_id = add_backend(conn, settings, "http://127.0.0.1:9", token="backend-secret-token-value")
        backends.create_route(conn, model="tiny", backend_id=backend_id, upstream_model="tiny", artifact_digest=digest,
                              require_verified=True, **ACTOR)
        set_status(conn, backend_id, "up", served=[{"model_id": "tiny", "path": store_path(settings, digest),
                                                    "digest": digest}])
        _, key = add_app(conn, "evidence-app")
        activate(conn, allow("tiny-chat", ["app:evidence-app"], ["tiny"], max_tokens=256))
    return Populated(settings, database, str(result.bundle_id), digest, key, "backend-secret-token-value")


def test_evidence_has_every_section_built_from_records(populated: Populated) -> None:
    with populated.database.session() as conn:
        evidence = build_evidence(populated.settings, conn)
    json.dumps(evidence)  # must be JSON-serializable as is
    assert set(evidence) == SECTIONS
    assert evidence["statement"] == STATEMENT
    assert "configuration and event evidence" in STATEMENT and "not a compliance certification" in STATEMENT
    assert evidence["host"]["platform"] and evidence["host"]["python"]
    assert evidence["config"]["data_dir"] == str(populated.settings.data_dir)
    assert evidence["import_policy"]["required_roles"] == ["publisher"]
    assert evidence["import_policy"]["trust_dir"] == str(populated.settings.trust_dir)

    anchors = {a["name"]: a for a in evidence["trust_anchors"]}
    assert set(anchors) == {"Acme build", "Acme review"}
    assert anchors["Acme build"]["status"] == "active" and anchors["Acme build"]["roles"] == ["publisher"]
    assert anchors["Acme build"]["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")

    [bundle] = evidence["bundles"]
    assert bundle["bundle_id"] == populated.bundle_id and bundle["name"] == "tiny-model"
    assert [s["roles"] for s in bundle["signers"]] == [["publisher"]]
    model = next(a for a in bundle["artifacts"] if a["kind"] == "model")
    assert model["sha256"] == populated.digest and model["license"] == "Apache-2.0" and model["format"] == "gguf"
    assert model["source_uri"] == "https://example.invalid/tiny-model"

    verifications = evidence["verifications"]
    assert verifications["total"] == 2 and verifications["accepted"] == 1 and verifications["rejected"] == 1
    assert verifications["by_mode"]["import"] == {"accepted": 1, "rejected": 0}
    assert verifications["by_mode"]["verify"] == {"accepted": 0, "rejected": 1}
    [rejection] = verifications["recent_rejections"]
    assert rejection["source_name"] == "tampered.ferry.tar" and rejection["failed_checks"] == ["artifact.digest"]

    [route] = evidence["routes"]
    assert route["model"] == "tiny" and route["pin"] == populated.digest and route["backend"] == "llama"
    assert route["provenance"]["state"] == "verified" and route["available"] is True

    active = evidence["active_policy"]
    assert active["version"] == 1 and len(active["sha256"]) == 64 and active["rule_count"] == 1
    assert active["activated_by"] == "cli:pytest" and active["document"]["rules"][0]["id"] == "tiny-chat"
    assert [h["version"] for h in evidence["policy_history"]] == [1]

    assert evidence["audit"]["ok"] is True and evidence["audit"]["events_checked"] > 0
    assert evidence["audit"]["last_checkpoint"] is None
    assert any(item["destination"] == "http://127.0.0.1:9" for item in evidence["network_inventory"])
    versions = {d["name"].lower(): d["version"] for d in evidence["dependencies"]}
    assert versions["fastapi"] == importlib.metadata.version("fastapi")
    assert versions["cryptography"] == importlib.metadata.version("cryptography")


def test_evidence_contains_no_secrets(populated: Populated) -> None:
    with populated.database.session() as conn:
        evidence = build_evidence(populated.settings, conn)
    text = json.dumps(evidence) + render_markdown(evidence)
    assert populated.api_key not in text and populated.api_key.split("_", 2)[2] not in text
    assert populated.backend_token not in text
    assert "secret_hash" not in text and "password_hash" not in text and "auth_token_file" not in text


def test_markdown_report_has_the_sections_and_the_facts(populated: Populated) -> None:
    with populated.database.session() as conn:
        markdown = render_markdown(build_evidence(populated.settings, conn))
    assert markdown.startswith("# Ferry evidence report\n")
    for heading in ("## Audit chain", "## Trust anchors", "## Import policy", "## Imported bundles",
                    "## Verification history", "## Routes and model provenance", "## Access policy",
                    "## Network inventory", "## Dependencies", "## Effective configuration"):
        assert f"\n{heading}\n" in markdown, heading
    assert "not a compliance certification" in markdown
    assert "**Intact.**" in markdown
    assert f"`{populated.bundle_id}`" in markdown and f"`{populated.digest}`" in markdown
    assert "verified: backend serves the pinned file from the store" in markdown
    assert "| Active version | 1 |" in markdown
    assert "tampered.ferry.tar" in markdown and "artifact.digest" in markdown


def test_markdown_escapes_text_that_would_break_tables(populated: Populated) -> None:
    odd = make_signer("odd")
    add_key(populated.settings.trust_dir, odd.pem, name="Acme | build `x` <b>bold</b>", roles=["reviewer"])
    with populated.database.session() as conn:
        markdown = render_markdown(build_evidence(populated.settings, conn))
    row = next(line for line in markdown.splitlines() if odd.key_id in line)
    unescaped = row.replace("\\|", "")
    assert unescaped.count("|") == 8, row  # seven columns
    assert "<b>" not in row and "\\<b\\>" in row
    assert "\\`x\\`" in row


def test_a_broken_chain_and_a_missing_policy_are_stated_plainly(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = init_database(settings)
    with database.session() as conn:
        add_app(conn, "a")
        add_app(conn, "b")
        conn.execute("UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 2")
        evidence = build_evidence(settings, conn)
    assert evidence["audit"]["ok"] is False and evidence["audit"]["first_bad_seq"] == 2
    assert evidence["active_policy"] is None and evidence["bundles"] == [] and evidence["routes"] == []
    markdown = render_markdown(evidence)
    assert "**BROKEN at event #2:**" in markdown
    assert "**No active policy: every gateway request is denied.**" in markdown
    assert "No bundles have been imported." in markdown and "No trusted keys" in markdown


def test_the_last_checkpoint_is_reported(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = init_database(settings)
    with database.session() as conn:
        add_app(conn, "c")
        checkpoint = audit.make_checkpoint(conn)
        audit.append_event(conn, actor_type="cli", actor_id="pytest", action="audit.checkpoint", resource="audit",
                           outcome="success", details={"seq": checkpoint["seq"], "hash": checkpoint["hash"],
                                                       "signed": False, "key_id": None})
        evidence = build_evidence(settings, conn)
    assert evidence["audit"]["last_checkpoint"]["seq"] == checkpoint["seq"]
    assert evidence["audit"]["last_checkpoint"]["hash"] == checkpoint["hash"]
    assert f"Last recorded checkpoint: event #{checkpoint['seq']}" in render_markdown(evidence)


# --- the report builds on the last full verification instead of re-reading the log ---------------


def _append(conn, count: int, start: int = 0) -> None:
    with write_tx(conn):
        for i in range(start, start + count):
            audit.append_event(conn, actor_type="app", actor_id="load", action="gateway.request",
                               resource="model:tiny", outcome="success", details={"n": i, "note": "é \u2603"})


def _counting_hash(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    real = audit.compute_hash

    def counting(*args, **kwargs):
        calls[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(audit, "compute_hash", counting)
    return calls


def test_evidence_checks_only_events_after_the_last_full_verification(tmp_path: Path,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    with app_env(tmp_path / "data") as env:
        with env.conn() as c:
            _append(c, 3000)
        full = env.post("/api/audit/verify").json()
        assert full["ok"] is True and full["events_checked"] > 3000
        with env.conn() as c:
            _append(c, 50, start=3000)
        calls = _counting_hash(monkeypatch)
        with env.conn() as c:
            evidence = build_evidence(env.settings, c)
        chain = evidence["audit"]
        # 50 new events plus the audit.verify event itself; not the 3,000 already verified.
        assert calls[0] <= 51
        assert chain["ok"] is True and chain["method"] == "incremental" and chain["events_checked"] == 51
        last = chain["last_full_verification"]
        assert last["head_seq"] == full["head_seq"] and last["head_hash"] == full["head_hash"]
        assert last["actor"] == "admin:alice" and last["via"] == "api" and last["ok"] is True
        assert chain["head_seq"] == full["head_seq"] + 51
        markdown = render_markdown(evidence)
        assert "**Intact.** The full verification recorded" in markdown and "admin:alice" in markdown
        assert f"through #{full['head_seq']} intact" in markdown
        assert "(since the last full verification)" in markdown
        assert env.get("/api/evidence").json()["audit"]["method"] == "incremental"

        # An edit before the verified head is the incremental check's blind spot; the
        # explicit full verification still finds it, and the report then says so
        # without re-reading the log.
        with env.conn() as c:
            c.execute("UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 10")
        broken = env.post("/api/audit/verify").json()
        assert broken["ok"] is False and broken["first_bad_seq"] == 10
        calls[0] = 0
        with env.conn() as c:
            evidence = build_evidence(env.settings, c)
        assert calls[0] == 0
        assert evidence["audit"]["ok"] is False and evidence["audit"]["first_bad_seq"] == 10
        assert evidence["audit"]["method"] == "recorded"
        markdown = render_markdown(evidence)
        assert "**BROKEN at event #10:**" in markdown and "run `ferry audit verify` to check again" in markdown


def test_evidence_catches_changes_at_and_after_the_verified_head(tmp_path: Path) -> None:
    with app_env(tmp_path / "data") as env:
        with env.conn() as c:
            _append(c, 20)
        head = env.post("/api/audit/verify").json()["head_seq"]
        with env.conn() as c:
            _append(c, 5, start=20)
            c.execute("UPDATE audit_events SET outcome = 'failure' WHERE seq = ?", (head + 3,))
            chain = build_evidence(env.settings, c)["audit"]
            assert chain["ok"] is False and chain["first_bad_seq"] == head + 3 and chain["method"] == "incremental"
            c.execute("UPDATE audit_events SET outcome = 'success' WHERE seq = ?", (head + 3,))
            assert build_evidence(env.settings, c)["audit"]["ok"] is True
            c.execute("UPDATE audit_events SET hash = ? WHERE seq = ?", ("f" * 64, head))
            chain = build_evidence(env.settings, c)["audit"]
            assert chain["ok"] is False and chain["first_bad_seq"] == head and "no longer carries" in chain["problem"]


def test_verify_chain_from_a_start_point(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = init_database(settings)
    with database.session() as conn:
        _append(conn, 10)
        full = audit.verify_chain(conn)
        mid = conn.execute("SELECT seq, hash FROM audit_events WHERE seq = 6").fetchone()
        result = audit.verify_chain(conn, start=(mid["seq"], mid["hash"]))
        assert result["ok"] is True and result["events_checked"] == full["head_seq"] - 6
        assert result["head_seq"] == full["head_seq"] and result["head_hash"] == full["head_hash"]
        assert audit.verify_chain(conn, start=(0, audit.GENESIS_HASH))["events_checked"] == full["events_checked"]
        assert audit.verify_chain(conn, start=(0, "1" * 64))["ok"] is False
        assert audit.verify_chain(conn, start=(6, "1" * 64))["first_bad_seq"] == 6
        with pytest.raises(ValueError):
            audit.verify_chain(conn, {"seq": 1, "hash": "0" * 64}, start=(6, mid["hash"]))
        conn.execute("DELETE FROM audit_events WHERE seq = 7")
        gap = audit.verify_chain(conn, start=(6, mid["hash"]))
        assert gap["ok"] is False and gap["first_bad_seq"] == 7 and "gap" in gap["problem"]
        conn.execute("DELETE FROM audit_events WHERE seq >= 6")
        gone = audit.verify_chain(conn, start=(6, mid["hash"]))
        assert gone["ok"] is False and gone["first_bad_seq"] == 6 and "missing" in gone["problem"]


def test_compute_hash_with_preencoded_details_matches_the_plain_form() -> None:
    from ferry.util import canonical_json
    event = {"seq": 7, "event_id": "e" * 32, "ts": "2026-01-01T00:00:00Z", "actor_type": "app", "actor_id": 'a"b\\',
             "action": "gateway.request", "resource": "model:x", "outcome": "success", "correlation_id": None,
             "policy_version": 3, "details": {"z": [1, {"y": "\u2603"}], "a": None, "details": "x"},
             "prev_hash": "0" * 64}
    assert audit.compute_hash(event, canonical_json(event["details"])) == audit.compute_hash(event)
    for details in ({}, [], "text", None, {"nested": {"deep": [True, False, 1.5]}}):
        event["details"] = details
        assert audit.compute_hash(event, canonical_json(details)) == audit.compute_hash(event)


def test_a_failed_verification_without_a_broken_event_falls_back_to_a_full_pass(tmp_path: Path) -> None:
    settings = app_settings(tmp_path / "data")
    database = init_database(settings)
    with database.session() as conn:
        _append(conn, 5)
        h = audit.head(conn)
        audit.append_event(conn, actor_type="cli", actor_id="pytest", action="audit.verify", resource="audit",
                           outcome="failure", details={"ok": False, "events_checked": h["seq"], "head_seq": h["seq"],
                                                       "head_hash": h["hash"], "first_bad_seq": None,
                                                       "problem": "the checkpoint's signature does not verify"})
        chain = build_evidence(settings, conn)["audit"]
    assert chain["ok"] is True and chain["method"] == "full" and chain["events_checked"] == h["seq"] + 1
    assert chain["last_full_verification"]["ok"] is False
