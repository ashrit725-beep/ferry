"""Backup and restore of a Ferry data directory.

A backup is a plain tar holding the irreplaceable state of an installation: the
SQLite database (snapshotted with SQLite's online backup API, so a running
gateway need not stop), ferry.toml, the trust store and the secrets directory.
The artifact store is optional (`include_store`): it can be rebuilt by
re-importing the bundles and may be far larger than everything else.

BACKUP-MANIFEST.json is the first member and lists every other member with its
size and SHA-256. Restore reads the manifest first, accepts only regular-file
members at the expected paths, streams each one into a staging directory while
hashing it, and moves the staging directory into place only after every member
has verified. A backup that was modified, truncated or padded is refused as a
whole, and nothing from it is left behind.

Restore writes the default layout (trust/, secrets/, store/ inside the data
directory) and points the restored ferry.toml's top-level data_dir at the restore
target (or warns when it cannot). An installation whose ferry.toml points trust_dir or inbox_dir
elsewhere must have those settings reconciled by the operator afterwards.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from typing import IO, Any

from . import __version__, audit
from .config import Settings, _toml_str
from .db import Database
from .errors import ValidationFailed

# Error code for a backup that fails an integrity check (the CLI exits 1, not 2).
REJECTED = "backup_rejected"

SCHEMA = "ferry.dev/backup/v1"
MANIFEST_NAME = "BACKUP-MANIFEST.json"
CHUNK = 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 1_000_000
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
# Member name prefixes restore accepts, with the file mode each gets.
_MODES = {"ferry.db": 0o600, "ferry.toml": 0o600, "trust/": 0o644, "secrets/": 0o600, "store/sha256/": 0o444}


def _mode_for(name: str) -> int:
    for prefix, mode in _MODES.items():
        if name == prefix or (prefix.endswith("/") and name.startswith(prefix)):
            return mode
    raise ValidationFailed(f"{name}: unexpected location for a backup member")


def _check_name(name: str) -> None:
    """A member name is one of the two files, or one plain file name under trust/,
    secrets/ or store/sha256/. Everything else, including any '..' or nested path,
    is refused before it is used as a path."""
    if name in ("ferry.db", "ferry.toml"):
        return
    for prefix in ("trust/", "secrets/", "store/sha256/"):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            if prefix == "store/sha256/":
                if _DIGEST.fullmatch(rest):
                    return
            elif _NAME.fullmatch(rest):
                return
            raise ValidationFailed(f"{name}: not a plain file name under {prefix}")
    raise ValidationFailed(f"{name}: unexpected location for a backup member")


def _hash_file(path: Path) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _copy_hashing(src: Path, dest: Path) -> tuple[int, str]:
    """Copy `src` to `dest` (mode 0600) and hash the bytes in the same read, so the
    manifest entry describes exactly the bytes that go into the archive even if the
    source is changed while the backup runs."""
    h, n = hashlib.sha256(), 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
        for chunk in iter(lambda: fin.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
            fout.write(chunk)
    return n, h.hexdigest()


class _HashingReader:
    """What tarfile copies out of a source is hashed on the way through."""

    def __init__(self, fh: IO[bytes]):
        self._fh = fh
        self._digest = hashlib.sha256()
        self.count = 0

    def read(self, n: int = -1) -> bytes:
        data = self._fh.read(n)
        self._digest.update(data)
        self.count += len(data)
        return data

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _collect(settings: Settings, include_store: bool) -> list[tuple[str, Path]]:
    """(archive name, source path) for every file to back up except the database.
    Symlinks and oddly named files are skipped: restore would refuse them anyway."""
    members: list[tuple[str, Path]] = []
    toml = settings.data_dir / "ferry.toml"
    if toml.is_file() and not toml.is_symlink():
        members.append(("ferry.toml", toml))
    for name, directory in (("trust", settings.trust_dir), ("secrets", settings.secrets_dir)):
        if directory.is_dir():
            for p in sorted(directory.iterdir()):
                if p.is_file() and not p.is_symlink() and _NAME.fullmatch(p.name):
                    members.append((f"{name}/{p.name}", p))
    if include_store:
        objects = settings.store_dir / "sha256"
        if objects.is_dir():
            for p in sorted(objects.iterdir()):
                if p.is_file() and not p.is_symlink() and _DIGEST.fullmatch(p.name):
                    members.append((f"store/sha256/{p.name}", p))
    return members


def _snapshot_database(database: Database, dest: Path) -> None:
    src = database.connect()
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    os.chmod(dest, 0o600)


def _store_corrupt(digest: str) -> ValidationFailed:
    return ValidationFailed(f"store file {digest} is corrupt (its content no longer hashes to its name); no backup"
                            " was written. Run ferry store verify, re-import the bundle that holds it, then back up"
                            " again", code="store_corrupt")


def _write_tar(tmp_tar: Path, raw: bytes, entries: list[tuple[str, Path]], listed: dict[str, dict[str, Any]]) -> None:
    """Write the manifest, then each member, hashing every member as tarfile copies it and
    checking it against its manifest entry. The file is fsynced before it is closed."""
    now = int(time.time())
    fd = os.open(tmp_tar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        with tarfile.open(fileobj=fh, mode="w", format=tarfile.PAX_FORMAT) as tf:
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size, info.mode, info.mtime = len(raw), 0o600, now
            tf.addfile(info, io.BytesIO(raw))
            for name, path in entries:
                spec = listed[name]
                with open(path, "rb") as src:
                    st = os.fstat(src.fileno())
                    if st.st_size != spec["size"]:
                        if name.startswith("store/sha256/"):
                            raise _store_corrupt(name.rsplit("/", 1)[1])
                        raise ValidationFailed(f"{name} changed while it was being backed up; no backup was written."
                                               " Run ferry backup again", code="source_changed")
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = spec["size"], _mode_for(name), int(st.st_mtime)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    reader = _HashingReader(src)
                    tf.addfile(info, reader)  # type: ignore[arg-type]
                if reader.count != spec["size"] or reader.hexdigest() != spec["sha256"]:
                    if name.startswith("store/sha256/"):
                        raise _store_corrupt(name.rsplit("/", 1)[1])
                    raise ValidationFailed(f"{name} changed while it was being backed up; no backup was written."
                                           " Run ferry backup again", code="source_changed")
        fh.flush()
        os.fsync(fh.fileno())


def _check_archive(tmp_tar: Path, listed: dict[str, dict[str, Any]]) -> None:
    """Read back what was written and check it is the archive restore expects: the manifest
    first, then exactly the listed members, each a regular file of the listed size. Member
    contents were hashed as they were written; the small (non-store) members are hashed
    again here, the store members are not read a second time."""
    try:
        with tarfile.open(tmp_tar, "r:") as tf:
            first = tf.next()
            if first is None or first.name != MANIFEST_NAME:
                raise ValueError(f"the first member is not {MANIFEST_NAME}")
            seen: set[str] = set()
            while (member := tf.next()) is not None:
                spec = listed.get(member.name)
                if spec is None or member.name in seen or not member.isreg() or member.size != spec["size"]:
                    raise ValueError(f"member {member.name} does not match the manifest")
                seen.add(member.name)
                if not member.name.startswith("store/sha256/"):
                    src = tf.extractfile(member)
                    h = hashlib.sha256()
                    while src is not None and (chunk := src.read(CHUNK)):
                        h.update(chunk)
                    if h.hexdigest() != spec["sha256"]:
                        raise ValueError(f"member {member.name} does not match the manifest")
            if seen != set(listed):
                raise ValueError("members are missing")
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise ValidationFailed(f"the backup archive did not verify after writing ({exc}); no backup was written."
                               " Check the destination disk, then run ferry backup again",
                               code="backup_unverified") from None


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)


def create_backup(settings: Settings, database: Database, out_path: str | Path, *, include_store: bool = False,
                  actor_type: str = "cli", actor_id: str = "unknown") -> dict[str, Any]:
    """Write a backup archive to `out_path` (which must not exist) and return a summary.

    The audit log gets a backup.create event with outcome "accepted" before the database
    snapshot (so the backup itself records that it was taken), then a second backup.create
    event once the archive is in place ("success") or the attempt failed ("failure")."""
    out = Path(out_path)
    if out.exists() or out.is_symlink():
        raise ValidationFailed(f"{out} already exists; refusing to overwrite a backup")
    out.parent.mkdir(parents=True, exist_ok=True)
    # Created first: an unwritable destination fails here, before anything is recorded.
    tmpdir = Path(tempfile.mkdtemp(prefix=".ferry-backup-", dir=out.parent))
    resource = f"backup:{out.name}"
    started = False
    try:
        os.chmod(tmpdir, 0o700)
        members = _collect(settings, include_store)
        with database.session() as conn:
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backup.create",
                               resource=resource, outcome="accepted",
                               details={"include_store": include_store, "members": len(members) + 1})
        started = True
        snapshot = tmpdir / "ferry.db"
        _snapshot_database(database, snapshot)
        listed: dict[str, dict[str, Any]] = {}
        size, digest = _hash_file(snapshot)
        listed["ferry.db"] = {"size": size, "sha256": digest}
        entries: list[tuple[str, Path]] = [("ferry.db", snapshot)]
        copies = tmpdir / "files"
        for name, path in members:
            if name.startswith("store/sha256/"):
                # Store files are immutable and named by their digest: the name is the expected
                # hash, checked as the file streams into the archive (one read per file).
                listed[name] = {"size": path.stat().st_size, "sha256": name.rsplit("/", 1)[1]}
                entries.append((name, path))
            else:
                # Small, mutable files are copied first and the copy is archived, so a change
                # made during the backup cannot split the manifest entry from the archived bytes.
                copy = copies / name
                size, digest = _copy_hashing(path, copy)
                listed[name] = {"size": size, "sha256": digest}
                entries.append((name, copy))
        manifest = {"schema": SCHEMA, "created_at": _now(), "ferry_version": __version__,
                    "include_store": include_store, "members": listed}
        raw = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        tmp_tar = tmpdir / "backup.tar"
        _write_tar(tmp_tar, raw, entries, listed)
        _check_archive(tmp_tar, listed)
        os.replace(tmp_tar, out)
        _fsync_dir(out.parent)
    except BaseException as exc:
        if started:
            # The original error is the one to report; a database that cannot take the event must not hide it.
            with contextlib.suppress(Exception), database.session() as conn:
                audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backup.create",
                                   resource=resource, outcome="failure",
                                   details={"include_store": include_store, "error": type(exc).__name__})
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    total = sum(m["size"] for m in listed.values())
    with database.session() as conn:
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backup.create",
                           resource=resource, outcome="success",
                           details={"include_store": include_store, "members": len(entries), "total_bytes": total,
                                    "created_at": manifest["created_at"]})
    return {"path": str(out), "members": len(entries), "total_bytes": total,
            "include_store": include_store, "created_at": manifest["created_at"]}


def _now() -> str:
    from .util import rfc3339

    return rfc3339()


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationFailed(f"{MANIFEST_NAME} is not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ValidationFailed(f"{MANIFEST_NAME}: not a {SCHEMA} manifest")
    members = doc.get("members")
    if not isinstance(members, dict) or not members or len(members) > MAX_MEMBERS:
        raise ValidationFailed(f"{MANIFEST_NAME}: 'members' must be a non-empty object")
    if "ferry.db" not in members:
        raise ValidationFailed(f"{MANIFEST_NAME}: the backup holds no database")
    for name, spec in members.items():
        if not isinstance(name, str):
            raise ValidationFailed(f"{MANIFEST_NAME}: member names must be strings")
        _check_name(name)
        if (not isinstance(spec, dict) or isinstance(spec.get("size"), bool) or not isinstance(spec.get("size"), int)
                or spec["size"] < 0 or not isinstance(spec.get("sha256"), str) or not _DIGEST.fullmatch(spec["sha256"])):
            raise ValidationFailed(f"{MANIFEST_NAME}: member {name!r} needs an integer size and a hex sha256")
    return doc


def _restore_member(tf: tarfile.TarFile, member: tarfile.TarInfo, spec: dict[str, Any], staging: Path) -> None:
    if member.islnk() or member.issym() or not member.isreg():
        raise ValidationFailed(f"{member.name}: only regular files are allowed in a backup", code=REJECTED)
    if member.size != spec["size"]:
        raise ValidationFailed(f"{member.name}: size {member.size:,} differs from the manifest ({spec['size']:,})",
                               code=REJECTED)
    src = tf.extractfile(member)
    if src is None:
        raise ValidationFailed(f"{member.name}: unreadable member")
    dest = staging / member.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    h, n = hashlib.sha256(), 0
    with src, open(dest, "wb") as out:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
            out.write(chunk)
    if n != spec["size"] or h.hexdigest() != spec["sha256"]:
        raise ValidationFailed(f"{member.name}: content does not match the manifest (modified or corrupt backup)",
                               code=REJECTED)
    os.chmod(dest, _mode_for(member.name))


_DATA_DIR_LINE = re.compile(r'^data_dir[ \t]*=[ \t]*"(?:[^"\\\n]|\\.)*"[ \t]*(#[^\n]*)?$', re.MULTILINE)
_TABLE_HEADER = re.compile(r"^[ \t]*\[", re.MULTILINE)


def _retarget_config(toml_path: Path, data_dir: Path) -> list[str]:
    """Point the top-level data_dir of a restored ferry.toml at the restore target, so
    `--config <target>/ferry.toml` operates on the restored copy and not on the installation
    the backup was taken from. Returns warnings when the file cannot be rewritten safely."""
    if not toml_path.is_file():
        return []
    target = data_dir.resolve()
    try:
        text = toml_path.read_text(encoding="utf-8")
        raw = tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return [(f"{target / 'ferry.toml'} could not be read as TOML, so its data_dir was not updated; check it,"
                 f" or always pass --data-dir {target}")]
    current = raw.get("data_dir")
    if current is None:
        return []  # no data_dir: --config alone fails loudly rather than reaching another installation
    if isinstance(current, str) and Path(current) == target:
        return []
    header = _TABLE_HEADER.search(text)
    head_end = header.start() if header else len(text)
    line = _DATA_DIR_LINE.search(text, 0, head_end)
    warning = (f"ferry.toml sets data_dir to {current!r}, not the restored directory; edit it to"
               f" {str(target)!r} or always pass --data-dir {target}")
    if line is None:
        return [warning]
    new_text = text[:line.start()] + f'data_dir = "{_toml_str(target)}"' + text[line.end():]
    try:
        reparsed = tomllib.loads(new_text)
    except tomllib.TOMLDecodeError:
        return [warning]
    if reparsed.get("data_dir") != str(target) or {**reparsed, "data_dir": None} != {**raw, "data_dir": None}:
        return [warning]
    toml_path.write_text(new_text, encoding="utf-8")
    os.chmod(toml_path, 0o600)
    return []


def restore_backup(archive: str | Path, data_dir: str | Path, *, force: bool = False,
                   actor_type: str = "cli", actor_id: str = "unknown") -> dict[str, Any]:
    """Restore `archive` into `data_dir`, which must be absent or empty unless `force`
    (then the current contents are moved aside, never deleted). Verifies every member
    before anything is put in place, then checks the restored audit chain."""
    archive, data_dir = Path(archive), Path(data_dir)
    if data_dir.exists() and any(data_dir.iterdir()) and not force:
        raise ValidationFailed(f"{data_dir} is not empty; pass --force to replace it"
                               " (the current contents are moved aside, not deleted)")
    try:
        tf = tarfile.open(archive, "r:")  # noqa: SIM115 - closed by the `with tf:` below
    except (tarfile.TarError, OSError) as exc:
        raise ValidationFailed(f"{archive} is not a readable uncompressed tar: {exc}") from None
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".ferry-restore-", dir=data_dir.parent))
    restored: list[str] = []
    replaced: Path | None = None
    try:
        os.chmod(staging, 0o700)
        with tf:
            first = tf.next()
            if first is None or first.name != MANIFEST_NAME or not first.isreg():
                raise ValidationFailed(f"{archive.name}: the first member must be {MANIFEST_NAME}")
            if first.size > MAX_MANIFEST_BYTES:
                raise ValidationFailed(f"{archive.name}: {MANIFEST_NAME} is too large")
            src = tf.extractfile(first)
            manifest = _parse_manifest(src.read() if src else b"")
            expected: dict[str, dict[str, Any]] = manifest["members"]
            seen: set[str] = set()
            while True:
                member = tf.next()
                if member is None:
                    break
                if member.name not in expected:
                    raise ValidationFailed(f"{member.name}: not listed in the backup manifest", code=REJECTED)
                if member.name in seen:
                    raise ValidationFailed(f"{member.name}: appears twice in the backup", code=REJECTED)
                _restore_member(tf, member, expected[member.name], staging)
                seen.add(member.name)
                restored.append(member.name)
            missing = sorted(set(expected) - seen)
            if missing:
                raise ValidationFailed(f"incomplete backup: {len(missing)} listed member(s) are absent, e.g. {missing[0]}",
                                       code=REJECTED)
        for sub, mode in (("trust", 0o755), ("secrets", 0o700), ("store", 0o700), ("store/sha256", 0o700),
                          ("store/tmp", 0o700), ("inbox", 0o700)):
            p = staging / sub
            p.mkdir(parents=True, exist_ok=True)
            os.chmod(p, mode)
        warnings = _retarget_config(staging / "ferry.toml", data_dir)
        if data_dir.exists():
            if any(data_dir.iterdir()):
                replaced = data_dir.with_name(f"{data_dir.name}.replaced-{time.strftime('%Y%m%d-%H%M%S')}")
                os.rename(data_dir, replaced)
            else:
                data_dir.rmdir()
        os.rename(staging, data_dir)
        os.chmod(data_dir, 0o700)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    database = Database(data_dir / "ferry.db")
    database.init()
    with database.session() as conn:
        chain = audit.verify_chain(conn)
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="backup.restore",
                           resource=f"backup:{archive.name}", outcome="success" if chain["ok"] else "failure",
                           details={"members": len(restored), "replaced": str(replaced) if replaced else None,
                                    "audit_chain_ok": chain["ok"], "audit_problem": chain["problem"],
                                    "backup_created_at": manifest["created_at"]})
    return {"data_dir": str(data_dir), "members": len(restored), "replaced": str(replaced) if replaced else None,
            "audit_chain_ok": chain["ok"], "audit_problem": chain["problem"],
            "backup_created_at": manifest["created_at"], "include_store": bool(manifest.get("include_store")),
            "warnings": warnings}
