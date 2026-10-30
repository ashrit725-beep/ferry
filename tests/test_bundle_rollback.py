"""Import-history checks: rollback and version-reuse protection (v1-additions A1)."""

from __future__ import annotations

import pytest

from ferry import audit
from ferry.bundle.importer import import_bundle, verify_only, version_key
from ferry.bundle.pack import sign_bundle
from ferry.config import Settings
from ferry.db import Database
from tests.helpers_bundle import make_workspace

ACTOR = {"actor_type": "cli", "actor_id": "tester"}


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


@pytest.fixture
def env(ws, data_dir):
    settings = Settings(data_dir=data_dir, imports=ws.policy(required_roles=("publisher", "reviewer")))
    database = Database(settings.db_path)
    database.init()
    return settings, database


def _bundle(ws, version: str, *, description: str = "Tiny test model"):
    res = ws.pack(version=version, description=description, out=ws.root / f"out-{version}-{len(description)}")
    sign_bundle(res.bundle_path, ws.reviewer.key)
    return res.bundle_path


def _check(result, check_id):
    return next(c for c in result.report.checks if c["id"] == check_id)


@pytest.mark.parametrize("older, newer", [
    ("1.0.0", "1.0.1"), ("1.2.0", "1.10.0"), ("1.0.0-rc1", "1.0.0"), ("1.0.0-rc.2", "1.0.0-rc.10"),
    ("1.0", "1.0.1"), ("2.0.0+build.9", "2.0.1"), ("0.9.9", "1.0.0"),
])
def test_version_order(older, newer):
    assert version_key(older) < version_key(newer)


def test_build_metadata_is_ignored_for_order():
    assert version_key("1.0.0+a") == version_key("1.0.0+b")


def test_upgrade_is_accepted_and_both_checks_pass(ws, env):
    settings, database = env
    assert import_bundle(settings, database, _bundle(ws, "1.0.0"), **ACTOR).accepted
    result = import_bundle(settings, database, _bundle(ws, "1.1.0"), **ACTOR)
    assert result.accepted
    assert _check(result, "policy.rollback")["status"] == "pass"
    assert _check(result, "policy.version_reuse")["status"] == "pass"


def test_older_version_is_rejected_as_rollback_and_nothing_is_registered(ws, env):
    settings, database = env
    assert import_bundle(settings, database, _bundle(ws, "1.2.0"), **ACTOR).accepted
    result = import_bundle(settings, database, _bundle(ws, "1.1.0"), **ACTOR)
    assert result.verdict == "rejected"
    assert _check(result, "policy.rollback")["status"] == "fail"
    assert "1.2.0" in result.report.errors[-1]
    with database.session() as conn:
        versions = [r[0] for r in conn.execute("SELECT version FROM bundles ORDER BY version")]
        last = audit.query_events(conn, action="bundle.import", limit=1)[0]
        assert audit.verify_chain(conn)["ok"]
    assert versions == ["1.2.0"]
    assert last["outcome"] == "rejected" and "policy.rollback" in last["details"]["failed_checks"]


def test_allow_downgrade_is_explicit_and_audited(ws, env):
    settings, database = env
    import_bundle(settings, database, _bundle(ws, "1.2.0"), **ACTOR)
    result = import_bundle(settings, database, _bundle(ws, "1.1.0"), allow_downgrade=True, **ACTOR)
    assert result.accepted
    with database.session() as conn:
        last = audit.query_events(conn, action="bundle.import", limit=1)[0]
    assert last["outcome"] == "success" and last["details"]["allow_downgrade"] is True


def test_same_version_with_different_content_is_never_accepted(ws, env):
    settings, database = env
    import_bundle(settings, database, _bundle(ws, "1.0.0"), **ACTOR)
    reused = _bundle(ws, "1.0.0", description="Same version, different content")
    for kwargs in ({}, {"allow_downgrade": True}):
        result = import_bundle(settings, database, reused, **ACTOR, **kwargs)
        assert result.verdict == "rejected"
        assert _check(result, "policy.version_reuse")["status"] == "fail"


def test_reimporting_the_same_bundle_stays_idempotent(ws, env):
    settings, database = env
    path = _bundle(ws, "1.0.0")
    import_bundle(settings, database, path, **ACTOR)
    again = import_bundle(settings, database, path, **ACTOR)
    assert again.accepted and again.already_imported


def test_verify_with_a_data_dir_reports_rollback(ws, env):
    settings, database = env
    import_bundle(settings, database, _bundle(ws, "2.0.0"), **ACTOR)
    result = verify_only(settings, database, _bundle(ws, "1.9.0"), **ACTOR)
    assert result.report.verdict == "rejected"
    assert _check(result, "policy.rollback")["status"] == "fail"
