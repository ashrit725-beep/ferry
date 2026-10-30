"""Backup and restore of a data directory (ferry.backup)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from ferry import audit
from ferry.backup import MANIFEST_NAME, create_backup, restore_backup
from ferry.bundle.importer import import_bundle
from ferry.bundle.pack import sign_bundle
from ferry.config import ImportSettings, Settings, default_config_toml
from ferry.db import Database
from ferry.errors import ValidationFailed
from ferry.trust import add_key
from tests.helpers_bundle import make_workspace

ACTOR = {"actor_type": "cli", "actor_id": "tester"}


@pytest.fixture
def installation(tmp_path):
    """A data directory with config, two trusted keys, one imported bundle (store files),
    a runtime token file and a few audit events."""
    ws = make_workspace(tmp_path)
    data = tmp_path / "data"
    settings = Settings(data_dir=data, imports=ImportSettings(required_roles=("publisher", "reviewer")))
    database = Database(settings.db_path)
    database.init()
    (data / "ferry.toml").write_text(default_config_toml(data))
    add_key(settings.trust_dir, ws.publisher.pem, name="Acme build", roles=["publisher"])
    add_key(settings.trust_dir, ws.reviewer.pem, name="Acme review", roles=["reviewer"])
    settings.secrets_dir.mkdir(mode=0o700)
    (settings.secrets_dir / "llamacpp-tiny.token").write_text("tok-123\n")
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    assert import_bundle(settings, database, res.bundle_path, **ACTOR).accepted
    return settings, database


def _chain_ok(data_dir: Path) -> bool:
    db = Database(data_dir / "ferry.db")
    with db.session() as conn:
        return audit.verify_chain(conn)["ok"]


def _actions(data_dir: Path) -> list[str]:
    db = Database(data_dir / "ferry.db")
    with db.session() as conn:
        return [e["action"] for e in audit.query_events(conn, limit=100)]


def _members(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:") as tf:
        return tf.getnames()


def test_round_trip_without_store(installation, tmp_path):
    settings, database = installation
    out = tmp_path / "backups" / "ferry.tar"
    summary = create_backup(settings, database, out, **ACTOR)
    assert out.is_file() and stat.S_IMODE(out.stat().st_mode) == 0o600
    names = _members(out)
    assert names[0] == MANIFEST_NAME and "ferry.db" in names and "ferry.toml" in names
    assert sum(n.startswith("trust/") for n in names) == 2 and "secrets/llamacpp-tiny.token" in names
    assert not any(n.startswith("store/") for n in names) and summary["members"] == len(names) - 1

    target = tmp_path / "restored"
    result = restore_backup(out, target, **ACTOR)
    assert result["audit_chain_ok"] is True and result["members"] == len(names) - 1
    assert (target / "ferry.toml").is_file() and (target / "secrets" / "llamacpp-tiny.token").read_text() == "tok-123\n"
    assert stat.S_IMODE((target / "secrets" / "llamacpp-tiny.token").stat().st_mode) == 0o600
    assert stat.S_IMODE((target / "ferry.db").stat().st_mode) == 0o600
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert len(list((target / "trust").glob("*.json"))) == 2
    assert not any((target / "store" / "sha256").iterdir())
    actions = _actions(target)
    assert actions[0] == "backup.restore" and "backup.create" in actions and "bundle.import" in actions
    assert _chain_ok(target)


def test_round_trip_with_store_restores_verifiable_files(installation, tmp_path):
    settings, database = installation
    out = tmp_path / "full.tar"
    create_backup(settings, database, out, include_store=True, **ACTOR)
    assert any(n.startswith("store/sha256/") for n in _members(out))
    target = tmp_path / "restored"
    restore_backup(out, target, **ACTOR)
    files = list((target / "store" / "sha256").iterdir())
    assert len(files) == 3
    for f in files:
        assert hashlib.sha256(f.read_bytes()).hexdigest() == f.name
        assert stat.S_IMODE(f.stat().st_mode) == 0o444


def test_backup_refuses_to_overwrite(installation, tmp_path):
    settings, database = installation
    out = tmp_path / "b.tar"
    out.write_bytes(b"existing")
    with pytest.raises(ValidationFailed, match="already exists"):
        create_backup(settings, database, out, **ACTOR)


def test_restore_refuses_a_non_empty_target_unless_forced(installation, tmp_path):
    settings, database = installation
    out = tmp_path / "b.tar"
    create_backup(settings, database, out, **ACTOR)
    target = tmp_path / "busy"
    target.mkdir()
    (target / "keep.txt").write_text("old")
    with pytest.raises(ValidationFailed, match="not empty"):
        restore_backup(out, target, **ACTOR)
    assert (target / "keep.txt").read_text() == "old"
    result = restore_backup(out, target, force=True, **ACTOR)
    assert result["replaced"] and Path(result["replaced"]).joinpath("keep.txt").read_text() == "old"
    assert (target / "ferry.db").is_file()


def _rewrite(src: Path, dst: Path, mutate) -> None:
    """Copy a tar, letting `mutate(name, data) -> data` change member contents."""
    with tarfile.open(src, "r:") as tin, tarfile.open(dst, "w", format=tarfile.PAX_FORMAT) as tout:
        for member in tin:
            data = tin.extractfile(member).read()
            data = mutate(member.name, data)
            member.size = len(data)
            tout.addfile(member, io.BytesIO(data))


def _no_leftovers(parent: Path) -> bool:
    return not any(p.name.startswith(".ferry-restore-") for p in parent.iterdir())


def test_tampered_member_is_refused_and_leaves_nothing(installation, tmp_path):
    settings, database = installation
    good, bad = tmp_path / "good.tar", tmp_path / "bad.tar"
    create_backup(settings, database, good, **ACTOR)
    _rewrite(good, bad, lambda name, data: data[:-1] + bytes([data[-1] ^ 1]) if name == "ferry.toml" else data)
    target = tmp_path / "restored"
    with pytest.raises(ValidationFailed, match="does not match the manifest"):
        restore_backup(bad, target, **ACTOR)
    assert not target.exists() and _no_leftovers(tmp_path)


def test_manifest_edits_are_refused(installation, tmp_path):
    settings, database = installation
    good, bad = tmp_path / "good.tar", tmp_path / "bad.tar"
    create_backup(settings, database, good, **ACTOR)

    def mutate(name, data):
        if name != MANIFEST_NAME:
            return data
        doc = json.loads(data)
        doc["members"]["ferry.toml"]["sha256"] = "0" * 64
        return json.dumps(doc).encode()

    _rewrite(good, bad, mutate)
    with pytest.raises(ValidationFailed, match="does not match the manifest"):
        restore_backup(bad, tmp_path / "restored", **ACTOR)


def test_unlisted_symlink_and_misplaced_members_are_refused(installation, tmp_path):
    settings, database = installation
    good = tmp_path / "good.tar"
    create_backup(settings, database, good, **ACTOR)

    def with_extra(path: Path, info: tarfile.TarInfo, data: bytes | None) -> Path:
        with tarfile.open(good, "r:") as tin, tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tout:
            for member in tin:
                tout.addfile(member, io.BytesIO(tin.extractfile(member).read()))
            tout.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    extra = tarfile.TarInfo("secrets/extra.token")
    extra.size = 3
    with pytest.raises(ValidationFailed, match="not listed"):
        restore_backup(with_extra(tmp_path / "extra.tar", extra, b"abc"), tmp_path / "r1", **ACTOR)

    link = tarfile.TarInfo("trust/evil.json")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    with pytest.raises(ValidationFailed):
        restore_backup(with_extra(tmp_path / "link.tar", link, None), tmp_path / "r2", **ACTOR)

    def mutate(name, data):
        if name != MANIFEST_NAME:
            return data
        doc = json.loads(data)
        doc["members"]["../escape"] = {"size": 0, "sha256": "0" * 64}
        return json.dumps(doc).encode()

    bad = tmp_path / "escape.tar"
    _rewrite(good, bad, mutate)
    with pytest.raises(ValidationFailed, match="unexpected location"):
        restore_backup(bad, tmp_path / "r3", **ACTOR)
    assert _no_leftovers(tmp_path)


def test_manifest_must_come_first(installation, tmp_path):
    settings, database = installation
    good, bad = tmp_path / "good.tar", tmp_path / "bad.tar"
    create_backup(settings, database, good, **ACTOR)
    with tarfile.open(good, "r:") as tin, tarfile.open(bad, "w", format=tarfile.PAX_FORMAT) as tout:
        members = list(tin)
        for member in members[1:] + members[:1]:
            tout.addfile(member, io.BytesIO(tin.extractfile(member).read()))
    with pytest.raises(ValidationFailed, match="first member"):
        restore_backup(bad, tmp_path / "restored", **ACTOR)


def _ferry(*argv: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    exe = Path(sys.executable).with_name("ferry")
    return subprocess.run([str(exe), *argv], capture_output=True, text=True, timeout=timeout)


def test_cli_round_trip_then_audit_and_store_verify(installation, tmp_path):
    settings, _database = installation
    out = tmp_path / "cli-backup.tar"
    r = _ferry("--data-dir", str(settings.data_dir), "backup", "--out", str(out), "--include-store", "--json")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["include_store"] is True
    r = _ferry("--data-dir", str(settings.data_dir), "backup", "--out", str(out))
    assert r.returncode == 2 and "already exists" in r.stderr

    target = tmp_path / "cli-restored"
    r = _ferry("--data-dir", str(target), "restore", str(out))
    assert r.returncode == 0, r.stderr
    assert "Audit chain     intact" in r.stdout
    assert _ferry("--data-dir", str(target), "audit", "verify").returncode == 0
    assert _ferry("--data-dir", str(target), "store", "verify").returncode == 0
    r = _ferry("--data-dir", str(target), "restore", str(out))
    assert r.returncode == 2 and "not empty" in r.stderr


def test_not_a_tar_is_refused(tmp_path):
    junk = tmp_path / "junk.tar"
    junk.write_bytes(os.urandom(2048))
    with pytest.raises(ValidationFailed, match="not a readable"):
        restore_backup(junk, tmp_path / "restored", **ACTOR)
