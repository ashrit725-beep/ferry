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

from ferry import audit, backends
from ferry.bundle.importer import import_bundle, verify_only
from ferry.config import Settings
from ferry.db import Database
from ferry.evidence import STATEMENT, build_evidence, render_markdown
from ferry.trust import add_key

from helpers_app import app_settings, bundle_setup, init_database
from helpers_bundle import make_signer
from helpers_gateway import ACTOR, activate, add_app, add_backend, allow, set_status, store_path

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
