"""Import-history checks: rollback and version-reuse protection (v1-additions A1)."""

from __future__ import annotations

import pytest

from ferry import audit
from ferry.bundle import importer, pack
from ferry.bundle.importer import (
    UnorderableVersion,
    import_bundle,
    verify_only,
    version_key,
)
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
    ("v9.0.0", "v10.0.0"), ("1.0.0rc1", "1.0.0"), ("1.0.0rc1", "1.0.1"), ("v1.0.0", "2.0.0"),
    ("1.0.0a1", "1.0.0b1"), ("1.0.0rc9", "1.0.0rc10"), ("1.0.0-rc.9", "1.0.0-rc.10"), ("1.0.0-1", "1.0.0-alpha"),
])
def test_version_order(older, newer):
    assert version_key(older) < version_key(newer)


def test_build_metadata_is_ignored_for_order():
    assert version_key("1.0.0+a") == version_key("1.0.0+b")


@pytest.mark.parametrize("same, other", [("v1.0.0", "1.0.0"), ("1.0", "1.0.0.0"), ("1.0.0rc1", "1.0.0-rc1")])
def test_spellings_of_one_release_share_a_key(same, other):
    assert version_key(same) == version_key(other)


@pytest.mark.parametrize("version", ["latest", "v", "1.x", "1.0.post1", "1rc1.0", "release-1.0.0", "1_0"])
def test_a_version_without_a_numeric_core_cannot_be_ordered(version):
    with pytest.raises(UnorderableVersion, match="MAJOR.MINOR.PATCH"):
        version_key(version)


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


def test_v10_is_newer_than_v9_so_a_replayed_v9_is_a_rollback(ws, env):
    settings, database = env
    assert import_bundle(settings, database, _bundle(ws, "v10.0.0"), **ACTOR).accepted
    result = import_bundle(settings, database, _bundle(ws, "v9.0.0"), **ACTOR)
    assert result.verdict == "rejected"
    assert _check(result, "policy.rollback")["status"] == "fail"
    assert "v10.0.0" in result.report.errors[-1]


def test_the_final_release_after_its_release_candidate_is_an_upgrade(ws, env):
    settings, database = env
    assert import_bundle(settings, database, _bundle(ws, "1.0.0rc1"), **ACTOR).accepted
    assert import_bundle(settings, database, _bundle(ws, "1.0.0"), **ACTOR).accepted
    late = import_bundle(settings, database, _bundle(ws, "1.0.0rc2"), **ACTOR)
    assert late.verdict == "rejected" and _check(late, "policy.rollback")["status"] == "fail"


def test_an_unorderable_version_is_refused_even_with_allow_downgrade(ws, env, monkeypatch):
    settings, database = env
    # `ferry pack` refuses such a version now; pack it the way an older Ferry (or a
    # hand-made bundle) could, because the receiving host must still refuse it.
    monkeypatch.setattr(pack, "version_key", lambda version: ())
    source = _bundle(ws, "latest")
    monkeypatch.undo()
    for kwargs in ({}, {"allow_downgrade": True}):
        result = import_bundle(settings, database, source, **ACTOR, **kwargs)
        assert result.verdict == "rejected"
        check = _check(result, "policy.rollback")
        assert check["status"] == "fail" and "MAJOR.MINOR.PATCH" in check["message"]
    with database.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM bundles").fetchone()[0] == 0


def _race(monkeypatch, settings, database, nested_source):
    """Run a second import while the first sits between its history check and its
    registration, as two inbox workers or the console and the CLI can."""
    original, results, started = importer._place, [], []

    def place(*args, **kwargs):
        if not started:
            started.append(True)
            results.append(import_bundle(settings, database, nested_source, **ACTOR))
        return original(*args, **kwargs)

    monkeypatch.setattr(importer, "_place", place)
    return results


def test_concurrent_imports_of_one_version_register_only_one(ws, env, monkeypatch):
    settings, database = env
    first = _bundle(ws, "1.0.0")
    second = _bundle(ws, "1.0.0", description="Same version, different content")
    results = _race(monkeypatch, settings, database, second)
    outer = import_bundle(settings, database, first, **ACTOR)
    inner = results[0]
    assert inner.accepted and outer.verdict == "rejected"
    assert _check(outer, "policy.version_reuse")["status"] == "fail"
    assert sum(1 for c in outer.report.checks if c["id"] == "policy.version_reuse") == 1
    with database.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM bundles WHERE name = ? AND version = ?",
                            ("tiny-model", "1.0.0")).fetchone()[0] == 1
        verdict = conn.execute("SELECT verdict FROM verifications WHERE id = ?",
                               (outer.verification_id,)).fetchone()[0]
        last = audit.query_events(conn, action="bundle.import", limit=1)[0]
        assert audit.verify_chain(conn)["ok"]
    assert verdict == "rejected"
    assert last["outcome"] == "rejected" and "policy.version_reuse" in last["details"]["failed_checks"]


def test_a_concurrent_newer_import_makes_the_older_one_a_rollback(ws, env, monkeypatch):
    settings, database = env
    older, newer = _bundle(ws, "1.0.0"), _bundle(ws, "2.0.0")
    results = _race(monkeypatch, settings, database, newer)
    outer = import_bundle(settings, database, older, **ACTOR)
    assert results[0].accepted and outer.verdict == "rejected"
    assert _check(outer, "policy.rollback")["status"] == "fail"
    with database.session() as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM bundles")] == ["2.0.0"]
