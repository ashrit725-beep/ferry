"""Import a verified bundle into the content-addressed store and the registry.

`import_bundle` verifies with a staging sink: each artifact is written to a
private staging file in the same pass that hashes it, and format detection
reads that copy, so what lands in the store is exactly what was hashed and
classified. Staging files never outlive the call, whatever fails. Importing a
bundle id that is already registered is idempotent: nothing is duplicated, a
verification row and a `bundle.import` audit event still record the attempt,
and the result says `already_imported: true`.

`verify_only` is the recorded form of `verify_bundle`: one `verifications` row
and one `bundle.verify` audit event, nothing stored.

`artifacts.metadata` holds the metadata detected at import, keyed by format
(e.g. `{"gguf": {...}}`), plus the signed `model` declaration (name, licence,
source) for model artifacts.

Both functions also check the bundle against import history (docs/design/
v1-additions.md, A1): an older version of an already imported bundle name is a
rollback and is refused unless the host passes `allow_downgrade`; the same name
and version with different content is never accepted. `import_bundle` repeats
that check inside the transaction that registers the bundle, so two imports
running at once cannot both register one name and version.

A store file is kept on re-import only when it is a 0444 regular file that
re-hashes to its name; anything else is replaced by the verified staged copy
and reported in `repaired`. A failure after verification (store or database) is
audited as a `bundle.import` error, and the store files that call newly placed
are removed again unless another bundle has registered them.

When the same bytes arrive in a second bundle with a model declaration, the
`artifacts` row takes that newer declaration (kind, model name, licence), so
the newest import names the model; each bundle's own declaration stays in its
signed manifest (`bundles.manifest`).
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

# Re-exported here: rollback protection orders versions with them, and callers import them from this module.
from ..manifest import UnorderableVersion, version_key
from .. import audit
from ..config import Settings
from ..db import Database, write_tx
from ..errors import FerryError, operator_detail
from ..trust import load_trust_store
from ..util import canonical_json, rfc3339
from .store import (
    STAGING_PREFIX,
    ensure_store,
    hash_file,
    import_lock,
    objects_dir,
    staging_dir,
)
from .verify import Progress, VerificationReport, verify_bundle

log = logging.getLogger("ferry.bundle.importer")

MAX_AUDITED_ERRORS = 20
STAGING_HEADROOM = 64 * 1024 * 1024
"""Free space required on the store volume beyond the staged artifacts themselves."""


@dataclass
class ImportResult:
    report: VerificationReport
    already_imported: bool = False
    verification_id: int | None = None
    stored: list[str] = field(default_factory=list)
    repaired: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.report.accepted

    @property
    def verdict(self) -> str:
        return self.report.verdict

    @property
    def bundle_id(self) -> str | None:
        return self.report.bundle_id

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "bundle_id": self.bundle_id, "already_imported": self.already_imported,
                "verification_id": self.verification_id, "stored": list(self.stored),
                "repaired": list(self.repaired), "report": self.report.to_dict()}


@dataclass
class VerifyResult:
    report: VerificationReport
    verification_id: int | None = None

    @property
    def accepted(self) -> bool:
        return self.report.accepted

    @property
    def verdict(self) -> str:
        return self.report.verdict

    @property
    def bundle_id(self) -> str | None:
        return self.report.bundle_id

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "bundle_id": self.bundle_id, "already_imported": False,
                "verification_id": self.verification_id, "report": self.report.to_dict()}


class _Staging:
    """The verifier's sink: one private temp file per artifact in store/tmp."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.paths: dict[str, Path] = {}

    def __call__(self, artifact_path: str) -> IO[bytes]:
        if artifact_path in self.paths:
            raise RuntimeError(f"artifact {artifact_path} staged twice")
        fd, name = tempfile.mkstemp(prefix=STAGING_PREFIX, dir=self.directory)
        self.paths[artifact_path] = Path(name)
        return os.fdopen(fd, "w+b")

    def reserve(self, total: int) -> None:
        """Called by the verifier before the first artifact is staged."""
        free = shutil.disk_usage(self.directory).free
        if free < total + STAGING_HEADROOM:
            raise FerryError(
                f"not enough free space to import: staging the artifacts needs {total:,} bytes plus"
                f" {STAGING_HEADROOM:,} bytes of headroom in {self.directory}, and that volume has {free:,} bytes"
                " free; free up space there, or move the Ferry data directory to a larger volume, then import again",
                code="insufficient_space", details={"needed_bytes": total + STAGING_HEADROOM, "free_bytes": free})

    def discard(self) -> None:
        for path in self.paths.values():
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _fsync_path(path: Path, directory: bool = False) -> None:
    fd = os.open(path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if directory else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _intact(dest: Path, digest: str, size: int) -> bool | None:
    """None when nothing is at `dest`; True only for a 0444 regular file of the right
    size whose bytes hash to `digest`. A same-size file with flipped bytes, or one
    made writable, is not kept: it would go on being served under a digest it lacks."""
    try:
        st = os.lstat(dest)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size != size or stat.S_IMODE(st.st_mode) != 0o444:
        return False
    try:
        return hash_file(dest) == digest
    except OSError:
        return False


def _store_staged(staged: Path, dest: Path) -> None:
    _fsync_path(staged)
    os.chmod(staged, 0o444)
    os.replace(staged, dest)


def _place(settings: Settings, report: VerificationReport, staging: _Staging, stored: list[str],
           repaired: list[str]) -> None:
    """Move staged artifacts into the store, appending to `stored` as each one lands
    (so a failure part-way still knows what this call placed). An intact existing
    file is kept; anything else under that name is replaced and also listed in
    `repaired`."""
    root = objects_dir(settings)
    seen: set[str] = set()
    for record in report.artifacts:
        digest = record["actual_sha256"]
        if digest in seen:
            continue
        seen.add(digest)
        dest = root / digest
        state = _intact(dest, digest, record["size"])
        if state:
            continue
        _store_staged(staging.paths[record["path"]], dest)
        stored.append(digest)
        if state is False:
            repaired.append(digest)
    if stored:
        _fsync_path(root, directory=True)


def _restore_missing(settings: Settings, report: VerificationReport, staging: _Staging, stored: list[str]) -> None:
    """Under the registration lock: put back any kept store file that has gone since
    `_place` (a concurrent import that failed may have removed what it had placed)."""
    root = objects_dir(settings)
    for record in report.artifacts:
        digest, staged = record["actual_sha256"], staging.paths[record["path"]]
        if not os.path.lexists(root / digest) and staged.exists():
            _store_staged(staged, root / digest)
            stored.append(digest)
            _fsync_path(root, directory=True)


def _remove_unregistered(conn: sqlite3.Connection, settings: Settings, digests: list[str]) -> list[str]:
    """Delete store files this import placed that no registered artifact uses. Call
    inside a write transaction, so no other import can register one meanwhile."""
    removed = []
    for digest in dict.fromkeys(digests):
        if conn.execute("SELECT 1 FROM artifacts WHERE digest = ?", (digest,)).fetchone() is not None:
            continue
        try:
            os.unlink(objects_dir(settings) / digest)
            removed.append(digest)
        except FileNotFoundError:
            pass
    return removed


def _artifact_metadata(record: dict[str, Any], model: dict[str, Any] | None) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if record["metadata"]:
        meta[record["detected_format"]] = record["metadata"]
    if model is not None:
        meta["model"] = model
    return meta


def _insert_verification(conn: sqlite3.Connection, report: VerificationReport, source: Path, mode: str,
                         actor: str) -> int:
    bundle = report.bundle or {}
    cur = conn.execute(
        "INSERT INTO verifications (source_name, bundle_id, bundle_name, bundle_version, verdict, mode, report,"
        " created_at, actor) VALUES (?,?,?,?,?,?,?,?,?)",
        (source.name, report.bundle_id, bundle.get("name"), bundle.get("version"), report.verdict, mode,
         canonical_json(report.to_dict()).decode("ascii"), rfc3339(), actor),
    )
    return int(cur.lastrowid or 0)


def _resource(report: VerificationReport, source: Path) -> str:
    return f"bundle:{report.bundle_id}" if report.bundle_id else f"source:{source.name}"


def _rejection_details(report: VerificationReport, source: Path, verification_id: int) -> dict[str, Any]:
    bundle = report.bundle or {}
    return {"bundle_id": report.bundle_id, "name": bundle.get("name"), "version": bundle.get("version"),
            "source_name": source.name, "verdict": report.verdict, "verification_id": verification_id,
            "failed_checks": [c["id"] for c in report.checks if c["status"] == "fail"],
            "errors": report.errors[:MAX_AUDITED_ERRORS]}


def _audit_failure(database: Database, source: Path, actor_type: str, actor_id: str, exc: BaseException, *,
                   bundle_id: str | None = None, step: str = "verify", removed: list[str] | None = None) -> None:
    message = exc.message if isinstance(exc, FerryError) else f"{type(exc).__name__}: {exc}"
    details: dict[str, Any] = {"source_name": source.name, "error": message[:500], "step": step}
    if isinstance(exc, FerryError):
        details["code"] = exc.code
    if bundle_id is not None:
        details["bundle_id"] = bundle_id
    if removed is not None:
        details["removed_digests"] = removed
    try:
        with database.session() as conn:
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="bundle.import",
                               resource=f"bundle:{bundle_id}" if bundle_id else f"source:{source.name}",
                               outcome="error", details=details)
    except Exception as audit_exc:  # the original error is what the caller needs to see
        log.error("could not audit the failed %s of %s (%s): %s", step, source.name, type(exc).__name__,
                  operator_detail(audit_exc))


def _stored_key(version: str) -> tuple[Any, ...] | None:
    try:
        return version_key(version)
    except UnorderableVersion:
        return None  # recorded before versions had to be orderable


def history_problem(conn: sqlite3.Connection, name: str, version: str, bundle_id: str, *,
                    allow_downgrade: bool = False) -> tuple[str, str] | None:
    """(check id, message) if importing this bundle would roll back or reuse a version."""
    rows = conn.execute("SELECT bundle_id, version FROM bundles WHERE name = ?", (name,)).fetchall()
    if any(r["bundle_id"] == bundle_id for r in rows):
        return None  # the same bundle again: idempotent
    try:
        key = version_key(version)
    except UnorderableVersion as exc:
        # Refused even with --allow-downgrade: a version that cannot be ordered
        # would also defeat the check for every later import of this name.
        return ("policy.rollback", f"{name}: {exc}")
    # Reuse is judged by the same key that orders versions: "1.0", "1.0.0" and
    # "1.0.0+build" are one release, so a second payload under any of them is reuse.
    stored = [(r, _stored_key(r["version"])) for r in rows]
    for r, stored_key in stored:
        if stored_key == key:
            same = "" if r["version"] == version else f" (as {r['version']})"
            return ("policy.version_reuse",
                    (f"{name} {version} was already imported{same} with different content ({r['bundle_id']});"
                     " publish a new version instead of reusing one"))
    newer = [r["version"] for r, k in sorted(((r, k) for r, k in stored if k is not None and k > key),
                                             key=lambda item: item[1])]
    if newer and not allow_downgrade:
        return ("policy.rollback",
                (f"{name} {newer[-1]} is already imported; refusing to import older {version}"
                 " (a host administrator can override with --allow-downgrade)"))
    return None


def _record_history(report: VerificationReport, problem: tuple[str, str] | None) -> bool:
    """Record the history checks on the report, replacing earlier results for the
    same checks. Returns False if the bundle must be rejected."""
    for check_id in ("policy.version_reuse", "policy.rollback"):
        if problem and problem[0] == check_id:
            check = {"id": check_id, "status": "fail", "message": problem[1]}
            report.errors.append(problem[1])
        else:
            check = {"id": check_id, "status": "pass", "message": "no conflict with previously imported versions"}
        index = next((i for i, c in enumerate(report.checks) if c["id"] == check_id), None)
        if index is None:
            report.checks.append(check)
        else:
            report.checks[index] = check
    if problem:
        report.verdict = "rejected"
        return False
    return True


def _apply_history(conn: sqlite3.Connection, report: VerificationReport, *, allow_downgrade: bool) -> bool:
    """Check the bundle against import history. Returns False if it must be rejected."""
    manifest = report.manifest
    assert manifest is not None and report.bundle_id is not None
    return _record_history(report, history_problem(conn, manifest.name, manifest.version, report.bundle_id,
                                                   allow_downgrade=allow_downgrade))


def _record_rejection(conn: sqlite3.Connection, report: VerificationReport, source: Path, *, actor_type: str,
                      actor_id: str) -> ImportResult:
    vid = _insert_verification(conn, report, source, "import", f"{actor_type}:{actor_id}")
    audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="bundle.import",
                       resource=_resource(report, source), outcome="rejected",
                       details=_rejection_details(report, source, vid))
    return ImportResult(report, verification_id=vid)


def import_bundle(settings: Settings, database: Database, source: str | Path, *, actor_type: str, actor_id: str,
                  progress: Progress | None = None, now: _dt.datetime | None = None,
                  allow_downgrade: bool = False) -> ImportResult:
    """Verify `source` against the host's trust store and import policy, then store and register it."""
    source = Path(source)
    trust = load_trust_store(settings.trust_dir)
    ensure_store(settings)
    with import_lock(settings):
        return _import_locked(settings, database, source, trust, actor_type=actor_type, actor_id=actor_id,
                              progress=progress, now=now, allow_downgrade=allow_downgrade)


def _import_locked(settings: Settings, database: Database, source: Path, trust: Any, *, actor_type: str,
                   actor_id: str, progress: Progress | None, now: _dt.datetime | None,
                   allow_downgrade: bool) -> ImportResult:
    staging = _Staging(staging_dir(settings))
    stored: list[str] = []
    repaired: list[str] = []
    try:
        try:
            report = verify_bundle(source, settings.imports, trust, now=now, progress=progress, sink=staging)
        except BaseException as exc:
            _audit_failure(database, source, actor_type, actor_id, exc)
            raise
        step = "history"
        try:
            if report.accepted:
                with database.session() as conn:
                    _apply_history(conn, report, allow_downgrade=allow_downgrade)
            if not report.accepted:
                step = "record"
                with database.session() as conn, write_tx(conn):
                    return _record_rejection(conn, report, source, actor_type=actor_type, actor_id=actor_id)

            manifest = report.manifest
            assert manifest is not None and report.bundle_id is not None
            step = "store"
            _place(settings, report, staging, stored, repaired)
            step = "register"
            result = _register(settings, database, source, report, staging, stored, repaired, actor_type=actor_type,
                               actor_id=actor_id, allow_downgrade=allow_downgrade)
        except BaseException as exc:
            removed = _cleanup_after_failure(database, settings, stored, repaired)
            _audit_failure(database, source, actor_type, actor_id, exc, bundle_id=report.bundle_id, step=step,
                           removed=removed)
            raise
        return result
    finally:
        staging.discard()


def _cleanup_after_failure(database: Database, settings: Settings, stored: list[str],
                           repaired: list[str]) -> list[str] | None:
    """Remove what a failed import newly placed. None when that could not be done."""
    new = [d for d in stored if d not in repaired]
    if not new:
        return []
    try:
        with database.session() as conn, write_tx(conn):
            return _remove_unregistered(conn, settings, new)
    except (sqlite3.Error, OSError):  # e.g. the database is locked: leave them; store verify lists them
        return None


def _register(settings: Settings, database: Database, source: Path, report: VerificationReport, staging: _Staging,
              stored: list[str], repaired: list[str], *, actor_type: str, actor_id: str,
              allow_downgrade: bool) -> ImportResult:
    manifest = report.manifest
    assert manifest is not None and report.bundle_id is not None
    actor = f"{actor_type}:{actor_id}"
    signers = report.valid_signers
    with database.session() as conn, write_tx(conn):
        exists = conn.execute("SELECT 1 FROM bundles WHERE bundle_id = ?", (report.bundle_id,)).fetchone()
        if exists is None:
            # Again, under the write lock: the check above ran before it, so a
            # concurrent import of the same name may have registered since.
            problem = history_problem(conn, manifest.name, manifest.version, report.bundle_id,
                                      allow_downgrade=allow_downgrade)
            if not _record_history(report, problem):
                result = _record_rejection(conn, report, source, actor_type=actor_type, actor_id=actor_id)
                _remove_unregistered(conn, settings, [d for d in stored if d not in repaired])
                stored.clear()
                repaired.clear()
                return result
        _restore_missing(settings, report, staging, stored)
        now_text = rfc3339()
        if exists is None:
            conn.execute(
                "INSERT INTO bundles (bundle_id, name, version, manifest, signers, report, imported_at,"
                " imported_by, source_name) VALUES (?,?,?,?,?,?,?,?,?)",
                (report.bundle_id, manifest.name, manifest.version,
                 canonical_json(manifest.to_dict()).decode("ascii"), canonical_json(signers).decode("ascii"),
                 canonical_json(report.to_dict()).decode("ascii"), now_text, actor, source.name),
            )
        for entry, record in zip(manifest.artifacts, report.artifacts, strict=True):
            model = entry.model.to_dict() if entry.model else None
            metadata = canonical_json(_artifact_metadata(record, model)).decode("ascii")
            cur = conn.execute(
                "INSERT OR IGNORE INTO artifacts (digest, size, kind, format, model_name, metadata,"
                " first_bundle_id, imported_at) VALUES (?,?,?,?,?,?,?,?)",
                (entry.sha256, entry.size, entry.kind, record["detected_format"],
                 entry.model.name if entry.model else None, metadata, report.bundle_id, now_text),
            )
            if cur.rowcount == 0 and exists is None and entry.model is not None:
                # The same bytes, already imported, now declared as a model by a newer
                # bundle: that declaration names the model from now on. A model is never
                # turned back into a non-model by a later bundle that ships it as a file.
                conn.execute("UPDATE artifacts SET kind = 'model', model_name = ?, metadata = ? WHERE digest = ?",
                             (entry.model.name, metadata, entry.sha256))
            conn.execute("INSERT OR IGNORE INTO bundle_artifacts (bundle_id, digest, path) VALUES (?,?,?)",
                         (report.bundle_id, entry.sha256, entry.path))
        vid = _insert_verification(conn, report, source, "import", actor)
        audit.append_event(
            conn, actor_type=actor_type, actor_id=actor_id, action="bundle.import",
            resource=_resource(report, source), outcome="success",
            details={"bundle_id": report.bundle_id, "name": manifest.name, "version": manifest.version,
                     "source_name": source.name, "signers": [s["key_id"] for s in signers],
                     "artifacts": [{"path": a.path, "sha256": a.sha256} for a in manifest.artifacts],
                     "already_imported": exists is not None, "verification_id": vid,
                     "stored_digests": stored, "repaired_digests": repaired,
                     "allow_downgrade": allow_downgrade},
        )
    return ImportResult(report, already_imported=exists is not None, verification_id=vid,
                        stored=list(stored), repaired=list(repaired))


def verify_only(settings: Settings, database: Database, source: str | Path, *, actor_type: str, actor_id: str,
                progress: Progress | None = None, now: _dt.datetime | None = None, full: bool = False) -> VerifyResult:
    """Verify without importing; records a `verifications` row and a `bundle.verify` audit event."""
    source = Path(source)
    trust = load_trust_store(settings.trust_dir)
    report = verify_bundle(source, settings.imports, trust, now=now, full=full, progress=progress)
    if report.accepted:
        with database.session() as conn:
            _apply_history(conn, report, allow_downgrade=False)
    with database.session() as conn, write_tx(conn):
        vid = _insert_verification(conn, report, source, "verify", f"{actor_type}:{actor_id}")
        details = _rejection_details(report, source, vid)
        if report.accepted:
            details = {k: v for k, v in details.items() if k not in ("errors", "failed_checks")}
            details["signers"] = [s["key_id"] for s in report.valid_signers]
        audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="bundle.verify",
                           resource=_resource(report, source), outcome=report.verdict, details=details)
    return VerifyResult(report, vid)
