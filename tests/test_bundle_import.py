"""Import into the content-addressed store and registry: rows, audit chain,
idempotency, cleanup on every failure path, verify_only, and store verification."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections import namedtuple

import pytest

from ferry import audit
from ferry.bundle import import_bundle, sign_bundle, store, verify_only
from ferry.bundle import importer as importer_module
from ferry.config import Settings
from ferry.db import Database
from ferry.errors import FerryError

from helpers_bundle import (
    LICENSE_TEXT, MODEL, crafted_bundle, gguf_bytes, make_workspace, replace_member, rewrite_tar,
)

ACTOR = {"actor_type": "cli", "actor_id": "tester"}
_Usage = namedtuple("_Usage", "free")


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


@pytest.fixture
def env(ws, data_dir):
    settings = Settings(data_dir=data_dir, imports=ws.policy(required_roles=("publisher", "reviewer")))
    database = Database(settings.db_path)
    database.init()
    return settings, database


@pytest.fixture
def bundle(ws):
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    return res


def rows(database: Database, sql: str, params=()) -> list[dict]:
    with database.session() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def count(database: Database, table: str) -> int:
    return rows(database, f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]


def store_names(settings: Settings) -> list[str]:
    root = store.objects_dir(settings)
    return sorted(os.listdir(root)) if root.exists() else []


def staging_names(settings: Settings) -> list[str]:
    tmp = store.staging_dir(settings)
    return sorted(os.listdir(tmp)) if tmp.exists() else []


def events(database: Database, action: str) -> list[dict]:
    with database.session() as conn:
        return audit.query_events(conn, action=action, limit=500)


def chain_ok(database: Database) -> bool:
    with database.session() as conn:
        return audit.verify_chain(conn)["ok"]


def test_import_stores_registers_and_audits(ws, env, bundle):
    settings, database = env
    result = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert result.accepted and not result.already_imported and result.verification_id
    assert result.bundle_id == bundle.bundle_id
    shas = sorted(a["sha256"] for a in bundle.manifest["artifacts"])
    assert sorted(result.stored) == shas == store_names(settings)
    assert staging_names(settings) == []
    for digest in shas:
        path = store.path_for(settings, digest)
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert stat.S_IMODE(store.objects_dir(settings).stat().st_mode) == 0o700

    (b,) = rows(database, "SELECT * FROM bundles")
    assert (b["bundle_id"], b["name"], b["version"]) == (bundle.bundle_id, "tiny-model", "1.0.0")
    assert b["imported_by"] == "cli:tester" and b["source_name"] == bundle.bundle_path.name
    assert json.loads(b["manifest"]) == bundle.manifest
    assert {s["key_id"] for s in json.loads(b["signers"])} == {ws.publisher.key_id, ws.reviewer.key_id}
    assert json.loads(b["report"])["verdict"] == "accepted"

    arts = {r["digest"]: r for r in rows(database, "SELECT * FROM artifacts")}
    assert sorted(arts) == shas
    model_sha = next(a["sha256"] for a in bundle.manifest["artifacts"] if a["kind"] == "model")
    model = arts[model_sha]
    assert (model["kind"], model["format"], model["model_name"]) == ("model", "gguf", "tiny-model")
    meta = json.loads(model["metadata"])
    assert meta["gguf"]["architecture"] == "llama" and meta["model"]["license"] == "Apache-2.0"
    assert model["first_bundle_id"] == bundle.bundle_id
    links = rows(database, "SELECT bundle_id, digest, path FROM bundle_artifacts")
    assert {(r["bundle_id"], r["digest"], r["path"]) for r in links} == {
        (bundle.bundle_id, a["sha256"], a["path"]) for a in bundle.manifest["artifacts"]}
    assert len(links) == 3

    (v,) = rows(database, "SELECT * FROM verifications")
    assert (v["mode"], v["verdict"], v["actor"], v["bundle_id"]) == ("import", "accepted", "cli:tester", bundle.bundle_id)
    assert v["id"] == result.verification_id

    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "success" and event["resource"] == f"bundle:{bundle.bundle_id}"
    details = event["details"]
    assert details["bundle_id"] == bundle.bundle_id and details["already_imported"] is False
    assert set(details["signers"]) == {ws.publisher.key_id, ws.reviewer.key_id}
    assert sorted(a["sha256"] for a in details["artifacts"]) == shas
    assert chain_ok(database)
    json.dumps(result.to_dict())


def test_import_is_idempotent(ws, env, bundle):
    settings, database = env
    first = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    second = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert first.accepted and second.accepted
    assert second.already_imported and second.stored == [] and second.to_dict()["already_imported"] is True
    assert (count(database, "bundles"), count(database, "artifacts"), count(database, "bundle_artifacts")) == (1, 3, 3)
    assert count(database, "verifications") == 2
    outcomes = [(e["outcome"], e["details"]["already_imported"]) for e in events(database, "bundle.import")]
    assert outcomes == [("success", True), ("success", False)]
    assert len(store_names(settings)) == 3 and staging_names(settings) == []
    assert chain_ok(database)


def test_rejected_import_records_the_rejection_and_stores_nothing(ws, env, bundle):
    settings, database = env
    tampered = ws.root / "tampered.ferry.tar"
    rewrite_tar(bundle.bundle_path, tampered,
                lambda ms: replace_member(ms, "artifacts/docs/LICENSE", LICENSE_TEXT.replace(b"2.0", b"2.1")))
    result = import_bundle(settings, database, tampered, **ACTOR)
    assert result.verdict == "rejected" and not result.already_imported
    assert store_names(settings) == [] and staging_names(settings) == []
    assert count(database, "bundles") == 0 and count(database, "artifacts") == 0
    (v,) = rows(database, "SELECT * FROM verifications")
    assert (v["mode"], v["verdict"]) == ("import", "rejected")
    assert json.loads(v["report"])["verdict"] == "rejected"
    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "rejected"
    assert event["details"]["failed_checks"] == ["artifact.digest"]
    assert any("SHA-256" in e for e in event["details"]["errors"])
    assert chain_ok(database)


def test_untrusted_bundle_is_rejected_without_touching_the_store(ws, env, bundle):
    settings, database = env
    settings = Settings(data_dir=settings.data_dir, imports=ws.policy(trust_dir=str(ws.root / "empty-trust")))
    result = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert result.verdict == "rejected" and store_names(settings) == [] and staging_names(settings) == []


def test_failure_during_verification_leaves_no_files_and_is_audited(ws, env, bundle):
    settings, database = env
    calls = []

    def explode(done, total):
        calls.append(done)
        if done > 0:
            raise RuntimeError("operator cancelled")

    with pytest.raises(RuntimeError, match="operator cancelled"):
        import_bundle(settings, database, bundle.bundle_path, progress=explode, **ACTOR)
    assert calls and staging_names(settings) == [] and store_names(settings) == []
    assert count(database, "bundles") == 0 and count(database, "verifications") == 0
    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "error" and "operator cancelled" in event["details"]["error"]
    assert chain_ok(database)


def test_staging_write_failure_leaves_no_files(ws, env, bundle, monkeypatch):
    settings, database = env
    real = importer_module._Staging.__call__

    class DiskFull:
        def __init__(self, fh):
            self._fh = fh

        def write(self, data):
            raise OSError(28, "No space left on device")

        def __getattr__(self, name):
            return getattr(self._fh, name)

    monkeypatch.setattr(importer_module._Staging, "__call__", lambda self, path: DiskFull(real(self, path)))
    with pytest.raises(OSError, match="No space left"):
        import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert staging_names(settings) == [] and store_names(settings) == []
    assert count(database, "verifications") == 0


def test_database_failure_rolls_back_and_leaves_no_staging_files(ws, env, bundle, monkeypatch):
    settings, database = env
    real = audit.append_event

    def failing(conn, **kwargs):
        if kwargs.get("action") == "bundle.import" and kwargs.get("outcome") == "success":
            raise RuntimeError("database is locked")
        return real(conn, **kwargs)

    monkeypatch.setattr(importer_module.audit, "append_event", failing)
    with pytest.raises(RuntimeError, match="database is locked"):
        import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert staging_names(settings) == []
    assert (count(database, "bundles"), count(database, "artifacts"), count(database, "verifications")) == (0, 0, 0)
    monkeypatch.setattr(importer_module.audit, "append_event", real)
    retry = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert retry.accepted and not retry.already_imported and count(database, "bundles") == 1
    assert chain_ok(database)


def test_identical_content_at_two_paths_is_stored_once(ws, env):
    settings, database = env
    settings = Settings(data_dir=settings.data_dir, imports=ws.policy())
    path = ws.root / "dup.ferry.tar"
    crafted_bundle(path, [ws.publisher], [
        ("artifacts/models/tiny.gguf", gguf_bytes(), {"kind": "model", "fmt": "gguf", "model": MODEL}),
        ("artifacts/docs/LICENSE", LICENSE_TEXT, {"kind": "document", "fmt": "text"}),
        ("artifacts/docs/COPYING", LICENSE_TEXT, {"kind": "document", "fmt": "text"}),
    ])
    result = import_bundle(settings, database, path, **ACTOR)
    assert result.accepted, result.report.errors
    assert len(store_names(settings)) == 2 and staging_names(settings) == []
    assert count(database, "artifacts") == 2 and count(database, "bundle_artifacts") == 3


def test_existing_store_file_is_kept_and_a_damaged_one_is_replaced(ws, env, bundle):
    settings, database = env
    store.ensure_store(settings)
    licence_sha = hashlib.sha256(LICENSE_TEXT).hexdigest()
    model_sha = hashlib.sha256((ws.src / "model.gguf").read_bytes()).hexdigest()
    kept = store.path_for(settings, licence_sha)
    kept.write_bytes(LICENSE_TEXT)
    kept.chmod(0o444)
    inode = kept.stat().st_ino
    damaged = store.path_for(settings, model_sha)
    damaged.write_bytes(b"truncated")
    result = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert result.accepted
    assert kept.stat().st_ino == inode and licence_sha not in result.stored
    assert result.repaired == [model_sha]
    assert hashlib.sha256(damaged.read_bytes()).hexdigest() == model_sha
    assert staging_names(settings) == []


def test_verify_only_records_but_stores_nothing(ws, env, bundle):
    settings, database = env
    ok = verify_only(settings, database, bundle.bundle_path, **ACTOR)
    assert ok.accepted and ok.verification_id and store_names(settings) == []
    tampered = ws.root / "tampered.ferry.tar"
    rewrite_tar(bundle.bundle_path, tampered,
                lambda ms: replace_member(ms, "artifacts/docs/LICENSE", LICENSE_TEXT.replace(b"2.0", b"2.1")))
    bad = verify_only(settings, database, tampered, **ACTOR)
    assert bad.verdict == "rejected"
    assert [(r["mode"], r["verdict"]) for r in rows(database, "SELECT * FROM verifications ORDER BY id")] == [
        ("verify", "accepted"), ("verify", "rejected")]
    assert [e["outcome"] for e in events(database, "bundle.verify")] == ["rejected", "accepted"]
    assert count(database, "bundles") == 0 and staging_names(settings) == []
    assert ok.to_dict()["verdict"] == "accepted" and chain_ok(database)


# --------------------------------------------------------------------------- store


def test_verify_store_detects_corruption(ws, env, bundle):
    settings, database = env
    import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    clean = store.verify_store(settings, database=database, actor_id="tester")
    assert clean["ok"] and clean["checked"] == 3 and clean["mismatches"] == [] and clean["recorded"]

    licence_sha = hashlib.sha256(LICENSE_TEXT).hexdigest()
    victim = store.path_for(settings, licence_sha)
    victim.chmod(0o644)
    victim.write_bytes(LICENSE_TEXT.replace(b"2.0", b"6.6"))
    victim.chmod(0o444)
    report = store.verify_store(settings, database=database, actor_id="tester")
    assert not report["ok"]
    assert [m["digest"] for m in report["mismatches"]] == [licence_sha]
    assert report["mismatches"][0]["actual_sha256"] == hashlib.sha256(victim.read_bytes()).hexdigest()
    outcomes = [e["outcome"] for e in events(database, "store.verify")]
    assert outcomes == ["failure", "success"]
    assert events(database, "store.verify")[0]["details"]["mismatched_digests"] == [licence_sha]
    assert chain_ok(database)


def test_verify_store_reports_missing_untracked_and_unexpected_entries(ws, env, bundle):
    settings, database = env
    import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    model_sha = next(a["sha256"] for a in bundle.manifest["artifacts"] if a["kind"] == "model")
    store.path_for(settings, model_sha).unlink()
    stray = b"not registered"
    store.path_for(settings, hashlib.sha256(stray).hexdigest()).write_bytes(stray)
    (store.objects_dir(settings) / "notes.txt").write_text("hello")
    report = store.verify_store(settings, database=database, actor_id="tester")
    assert report["missing"] == [model_sha]
    assert report["untracked"] == [hashlib.sha256(stray).hexdigest()]
    assert any("notes.txt" in p for p in report["problems"])
    assert any("writable" in w for w in report["warnings"])
    assert not report["ok"]


def test_verify_store_without_a_database_still_hashes(ws, tmp_path):
    settings = Settings(data_dir=tmp_path / "nodb")
    store.ensure_store(settings)
    data = b"content"
    store.path_for(settings, hashlib.sha256(data).hexdigest()).write_bytes(data)
    report = store.verify_store(settings)
    assert report["ok"] and report["checked"] == 1 and report["recorded"] is False


def test_path_for_and_digest_for_path(ws, env, bundle, tmp_path):
    settings, database = env
    import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    digest = hashlib.sha256(LICENSE_TEXT).hexdigest()
    path = store.path_for(settings, digest)
    for spelling in ("sha256:" + digest, digest.upper(), f" {digest}\n", "SHA256:" + digest):
        assert store.path_for(settings, spelling) == path
    for bad in ("abc", "sha512:" + digest, "../" + digest[3:], digest + "0", digest[:-1] + "g", ""):
        with pytest.raises(ValueError):
            store.path_for(settings, bad)
    assert store.digest_for_path(settings, path) == digest
    assert store.digest_for_path(settings, str(path)) == digest
    link = tmp_path / "model-link"
    link.symlink_to(path)
    assert store.digest_for_path(settings, link) == digest
    outside = tmp_path / digest
    outside.write_bytes(LICENSE_TEXT)
    assert store.digest_for_path(settings, outside) is None
    assert store.digest_for_path(settings, os.path.relpath(path)) is None
    assert store.digest_for_path(settings, store.objects_dir(settings) / ("0" * 64)) is None
    assert store.digest_for_path(settings, store.objects_dir(settings)) is None
    assert store.digest_for_path(settings, str(path) + "\x00") is None


# --------------------------------------------------------------------------- quality pass: bundle_import


def simple_env(ws, env):
    settings, database = env
    return Settings(data_dir=settings.data_dir, imports=ws.policy()), database


def text_bundle(ws, name: str, data: bytes, *, bundle: str = "app", version: str = "1.0.0"):
    return crafted_bundle(ws.root / name, [ws.publisher], [
        ("artifacts/docs/README", data, {"kind": "document", "fmt": "text"})], name=bundle, version=version)


def test_concurrent_same_version_import_is_rejected(ws, env, monkeypatch):
    """VI-3: the history check is repeated under the write lock that registers the bundle."""
    settings, database = simple_env(ws, env)
    first = text_bundle(ws, "a.ferry.tar", b"payload A\n")
    second = text_bundle(ws, "b.ferry.tar", b"payload B, different\n")
    real = importer_module._place
    inner: dict[str, object] = {}

    def racing(*args, **kwargs):
        if "result" not in inner:
            inner["result"] = None
            inner["result"] = import_bundle(settings, database, second, **ACTOR)
        return real(*args, **kwargs)

    monkeypatch.setattr(importer_module, "_place", racing)
    outer = import_bundle(settings, database, first, **ACTOR)
    racer = inner["result"]
    assert racer.accepted and not outer.accepted
    reuse = [c for c in outer.report.checks if c["id"] == "policy.version_reuse"]
    assert [c["status"] for c in reuse] == ["fail"]
    assert rows(database, "SELECT COUNT(*) AS n FROM bundles WHERE name = 'app'")[0]["n"] == 1
    # The loser's placed object is removed again; the winner's stays.
    assert store_names(settings) == [hashlib.sha256(b"payload B, different\n").hexdigest()]
    assert outer.stored == [] and staging_names(settings) == []
    assert [e["outcome"] for e in events(database, "bundle.import")] == ["rejected", "success"]
    (v,) = rows(database, "SELECT * FROM verifications WHERE verdict = 'rejected'")
    assert v["bundle_id"] == outer.bundle_id and json.loads(v["report"])["verdict"] == "rejected"
    assert chain_ok(database)


def test_same_size_damaged_store_file_is_repaired(ws, env, bundle):
    """VI-4: a same-size file under the digest's name is re-hashed, not trusted."""
    settings, database = env
    store.ensure_store(settings)
    model_bytes = (ws.src / "model.gguf").read_bytes()
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    path = store.path_for(settings, model_sha)
    path.write_bytes(b"\x00" * len(model_bytes))
    path.chmod(0o444)
    result = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert result.accepted and result.repaired == [model_sha]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == model_sha
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    (event,) = events(database, "bundle.import")
    assert event["details"]["repaired_digests"] == [model_sha]


def test_reimport_repairs_bit_rot_and_a_writable_store_file(ws, env, bundle):
    """SF-3 / integrity-1: re-importing is the documented way to rebuild the store."""
    settings, database = env
    import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    licence_sha = hashlib.sha256(LICENSE_TEXT).hexdigest()
    model_sha = next(a["sha256"] for a in bundle.manifest["artifacts"] if a["kind"] == "model")
    rotten = store.path_for(settings, licence_sha)
    rotten.chmod(0o644)
    rotten.write_bytes(LICENSE_TEXT[:-1] + bytes([LICENSE_TEXT[-1] ^ 1]))
    rotten.chmod(0o444)
    store.path_for(settings, model_sha).chmod(0o644)  # right bytes, but writable
    assert [m["digest"] for m in store.verify_store(settings, database=database, actor_id="t")["mismatches"]] == [
        licence_sha]

    again = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert again.accepted and again.already_imported
    assert sorted(again.repaired) == sorted([licence_sha, model_sha]) == sorted(again.stored)
    for digest in (licence_sha, model_sha):
        path = store.path_for(settings, digest)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    report = store.verify_store(settings, database=database, actor_id="t")
    assert report["ok"] and report["mismatches"] == [] and report["warnings"] == []
    # An intact store is left alone: nothing is rewritten on a third import.
    third = import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert third.stored == [] and third.repaired == []


def _gguf_bundle(ws, name: str, version: str, *, kind: str = "model", model: dict | None = None):
    return crafted_bundle(ws.root / f"{name}-{version}.ferry.tar", [ws.publisher], [
        ("artifacts/models/m.gguf", gguf_bytes(), {"kind": kind, "fmt": "gguf", "model": model})],
        name=name, version=version)


def test_same_bytes_declared_differently_in_two_bundles(ws, env):
    """VI-6: a later bundle's signed model declaration for the same bytes is not dropped."""
    from ferry import evidence, runtime

    settings, database = simple_env(ws, env)
    old = import_bundle(settings, database, _gguf_bundle(ws, "app", "1.0.0",
                                                         model={"name": "qwen-0.5b", "license": "MIT"}), **ACTOR)
    new = import_bundle(settings, database, _gguf_bundle(
        ws, "app", "2.0.0", model={"name": "qwen2.5-0.5b-instruct", "license": "Apache-2.0"}), **ACTOR)
    assert old.accepted and new.accepted
    digest = hashlib.sha256(gguf_bytes()).hexdigest()
    with database.session() as conn:
        served = runtime.resolve_model(settings, conn, "qwen2.5-0.5b-instruct")
        assert served.digest == digest and served.model_name == "qwen2.5-0.5b-instruct"
        by_bundle = {b["version"]: b["artifacts"] for b in evidence._bundles(conn)}
    assert [(a["model_name"], a["license"]) for a in by_bundle["1.0.0"]] == [("qwen-0.5b", "MIT")]
    assert [(a["model_name"], a["license"]) for a in by_bundle["2.0.0"]] == [("qwen2.5-0.5b-instruct", "Apache-2.0")]
    assert count(database, "artifacts") == 1


def test_bytes_first_shipped_as_a_document_can_later_be_a_model(ws, env):
    from ferry import evidence, runtime

    settings, database = simple_env(ws, env)
    assert import_bundle(settings, database, _gguf_bundle(ws, "app", "1.0.0", kind="document"), **ACTOR).accepted
    assert import_bundle(settings, database, _gguf_bundle(ws, "app", "2.0.0", model=MODEL), **ACTOR).accepted
    with database.session() as conn:
        assert runtime.resolve_model(settings, conn, MODEL["name"]).model_name == MODEL["name"]
        kinds = {b["version"]: b["artifacts"][0]["kind"] for b in evidence._bundles(conn)}
    assert kinds == {"1.0.0": "document", "2.0.0": "model"}
    # A later bundle that ships the model's bytes as a document does not unmake the model.
    assert import_bundle(settings, database, _gguf_bundle(ws, "app", "3.0.0", kind="document"), **ACTOR).accepted
    assert rows(database, "SELECT kind, model_name FROM artifacts") == [{"kind": "model", "model_name": MODEL["name"]}]


def test_registration_failure_is_audited(ws, env, bundle, monkeypatch):
    """VI-9: a failure after verification is audited and leaves no unregistered objects."""
    settings, database = env
    real = audit.append_event

    def locked(conn, **kwargs):
        if kwargs.get("action") == "bundle.import" and kwargs.get("outcome") == "success":
            raise sqlite3.OperationalError("database is locked")
        return real(conn, **kwargs)

    monkeypatch.setattr(importer_module.audit, "append_event", locked)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "error" and event["resource"] == f"bundle:{bundle.bundle_id}"
    details = event["details"]
    assert details["step"] == "register" and details["bundle_id"] == bundle.bundle_id
    assert "database is locked" in details["error"] and len(details["removed_digests"]) == 3
    assert store_names(settings) == [] and staging_names(settings) == []
    assert count(database, "bundles") == 0 and count(database, "verifications") == 0
    assert chain_ok(database)


def test_store_failure_is_audited_and_undone(ws, env, bundle, monkeypatch):
    settings, database = env
    licence_sha = hashlib.sha256(LICENSE_TEXT).hexdigest()
    kept = store.path_for(settings, licence_sha)
    store.ensure_store(settings)
    kept.write_bytes(LICENSE_TEXT)
    kept.chmod(0o444)
    real = importer_module._store_staged
    calls = []

    def flaky(staged, dest):
        calls.append(dest.name)
        if len(calls) == 2:
            raise OSError(5, "Input/output error")
        return real(staged, dest)

    monkeypatch.setattr(importer_module, "_store_staged", flaky)
    with pytest.raises(OSError, match="Input/output error"):
        import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "error" and event["details"]["step"] == "store"
    assert event["details"]["removed_digests"] == calls[:1]
    # The pre-existing, intact file was not this import's to remove.
    assert store_names(settings) == [licence_sha] and staging_names(settings) == []


def test_leftover_staging_files_are_swept_and_reported(ws, env, bundle):
    """SF-6: a killed import's staging files are reported, then removed by the next import."""
    settings, database = env
    store.ensure_store(settings)
    leftover = store.staging_dir(settings) / "stage-abc"
    leftover.write_bytes(b"x" * 1000)
    report = store.verify_store(settings, database=database, actor_id="t")
    assert report["leftover_staging"] == 1 and report["leftover_staging_bytes"] == 1000
    assert any("interrupted import" in w and "1,000 bytes" in w for w in report["warnings"])

    # While another import holds the lock, its staging files are never touched.
    with store.import_lock(settings) as swept:
        assert swept == ["stage-abc"]
    with store.import_lock(settings):
        leftover.write_bytes(b"busy")  # as if the import holding the lock were staging it
        assert import_bundle(settings, database, bundle.bundle_path, **ACTOR).accepted
        assert leftover.exists()
        busy = store.verify_store(settings, database=database, actor_id="t")
        assert any("import is in progress" in w for w in busy["warnings"])
    second = ws.pack(version="1.0.1", out=ws.root / "out2")
    sign_bundle(second.bundle_path, ws.reviewer.key)
    assert import_bundle(settings, database, second.bundle_path, **ACTOR).accepted
    assert not leftover.exists() and staging_names(settings) == []


def test_verify_store_warns_about_untracked_files(ws, env, bundle):
    settings, database = env
    import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    stray = b"not registered"
    path = store.path_for(settings, hashlib.sha256(stray).hexdigest())
    path.write_bytes(stray)
    path.chmod(0o444)
    report = store.verify_store(settings, database=database, actor_id="t")
    assert report["ok"] and any(path.name in w and "not part of any imported bundle" in w for w in report["warnings"])


def test_rejected_bundle_stops_staging(ws, env, monkeypatch):
    """perf-5: once a digest is wrong, later artifacts are hashed but not staged."""
    settings, database = simple_env(ws, env)
    first, second = b"first artifact\n", b"second artifact\n"
    path = crafted_bundle(ws.root / "bad.ferry.tar", [ws.publisher], [
        ("artifacts/docs/A", first, {"kind": "document", "fmt": "text", "sha256": "0" * 64}),
        ("artifacts/docs/B", second, {"kind": "document", "fmt": "text"}),
    ])
    staged = []
    real = importer_module._Staging.__call__

    def recording(self, artifact_path):
        staged.append(artifact_path)
        return real(self, artifact_path)

    monkeypatch.setattr(importer_module._Staging, "__call__", recording)
    result = import_bundle(settings, database, path, **ACTOR)
    assert result.verdict == "rejected" and staged == ["artifacts/docs/A"]
    actual = {a["path"]: a["actual_sha256"] for a in result.report.artifacts}
    assert actual == {"artifacts/docs/A": hashlib.sha256(first).hexdigest(),
                      "artifacts/docs/B": hashlib.sha256(second).hexdigest()}
    assert result.report.artifacts[1]["detected_format"] == "text"
    assert staging_names(settings) == [] and store_names(settings) == []


def test_insufficient_space_fails_before_staging(ws, env, bundle, monkeypatch):
    settings, database = env
    staged = []
    real = importer_module._Staging.__call__
    monkeypatch.setattr(importer_module._Staging, "__call__",
                        lambda self, p: staged.append(p) or real(self, p))
    monkeypatch.setattr(importer_module.shutil, "disk_usage", lambda path: _Usage(1 << 20))
    with pytest.raises(FerryError) as info:
        import_bundle(settings, database, bundle.bundle_path, **ACTOR)
    assert info.value.code == "insufficient_space" and "free up space" in info.value.message
    assert staged == [] and staging_names(settings) == [] and store_names(settings) == []
    (event,) = events(database, "bundle.import")
    assert event["outcome"] == "error" and event["details"]["code"] == "insufficient_space"
