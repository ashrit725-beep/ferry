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
and version with different content is never accepted.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sqlite3
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from .. import audit
from ..config import Settings
from ..db import Database, write_tx
from ..errors import FerryError
from ..trust import load_trust_store
from ..util import canonical_json, rfc3339
from .store import ensure_store, objects_dir, staging_dir
from .verify import Progress, VerificationReport, verify_bundle

MAX_AUDITED_ERRORS = 20


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
        fd, name = tempfile.mkstemp(prefix="stage-", dir=self.directory)
        self.paths[artifact_path] = Path(name)
        return os.fdopen(fd, "w+b")

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


def _place(settings: Settings, report: VerificationReport, staging: _Staging) -> tuple[list[str], list[str]]:
    """Move staged artifacts into the store. An existing regular file of the right
    size is kept; anything else under that name is replaced by the verified bytes."""
    root = objects_dir(settings)
    stored: list[str] = []
    repaired: list[str] = []
    for record in report.artifacts:
        digest = record["actual_sha256"]
        staged = staging.paths[record["path"]]
        dest = root / digest
        try:
            st: os.stat_result | None = os.lstat(dest)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISREG(st.st_mode) and st.st_size == record["size"]:
            continue
        _fsync_path(staged)
        os.chmod(staged, 0o444)
        os.replace(staged, dest)
        stored.append(digest)
        if st is not None:
            repaired.append(digest)
    if stored:
        _fsync_path(root, directory=True)
    return stored, repaired


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


def _audit_failure(database: Database, source: Path, actor_type: str, actor_id: str, exc: BaseException) -> None:
    message = exc.message if isinstance(exc, FerryError) else f"{type(exc).__name__}: {exc}"
    try:
        with database.session() as conn:
            audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="bundle.import",
                               resource=f"source:{source.name}", outcome="error",
                               details={"source_name": source.name, "error": message[:500]})
    except Exception:  # the original error is what the caller needs to see
        pass


def version_key(version: str) -> tuple[Any, ...]:
    """Order bundle versions semver-style: numeric parts numerically, a pre-release
    below its release, build metadata (after '+') ignored."""
    def ident(part: str) -> tuple[int, int, str]:
        return (0, int(part), "") if part.isdigit() else (1, 0, part)

    main = version.split("+", 1)[0]
    core, dash, pre = main.partition("-")
    core_key = [ident(p) for p in core.split(".")]
    core_key += [(0, 0, "")] * max(0, 3 - len(core_key))
    pre_key: tuple[Any, ...] = (0, *[ident(p) for p in re.split(r"[.]", pre)]) if dash else (1,)
    return (tuple(core_key), pre_key)


def history_problem(conn: sqlite3.Connection, name: str, version: str, bundle_id: str, *,
                    allow_downgrade: bool = False) -> tuple[str, str] | None:
    """(check id, message) if importing this bundle would roll back or reuse a version."""
    rows = conn.execute("SELECT bundle_id, version FROM bundles WHERE name = ?", (name,)).fetchall()
    if any(r["bundle_id"] == bundle_id for r in rows):
        return None  # the same bundle again: idempotent
    # Reuse is judged by the same key that orders versions: "1.0", "1.0.0" and
    # "1.0.0+build" are one release, so a second payload under any of them is reuse.
    key = version_key(version)
    for r in rows:
        if version_key(r["version"]) == key:
            same = "" if r["version"] == version else f" (as {r['version']})"
            return ("policy.version_reuse",
                    f"{name} {version} was already imported{same} with different content ({r['bundle_id']});"
                    " publish a new version instead of reusing one")
    newer = sorted((r["version"] for r in rows if version_key(r["version"]) > version_key(version)), key=version_key)
    if newer and not allow_downgrade:
        return ("policy.rollback",
                f"{name} {newer[-1]} is already imported; refusing to import older {version}"
                " (a host administrator can override with --allow-downgrade)")
    return None


def _apply_history(conn: sqlite3.Connection, report: VerificationReport, *, allow_downgrade: bool) -> bool:
    """Record the history checks on the report. Returns False if the bundle must be rejected."""
    manifest = report.manifest
    assert manifest is not None and report.bundle_id is not None
    problem = history_problem(conn, manifest.name, manifest.version, report.bundle_id, allow_downgrade=allow_downgrade)
    for check_id in ("policy.version_reuse", "policy.rollback"):
        if problem and problem[0] == check_id:
            report.checks.append({"id": check_id, "status": "fail", "message": problem[1]})
            report.errors.append(problem[1])
        else:
            report.checks.append({"id": check_id, "status": "pass",
                                  "message": "no conflict with previously imported versions"})
    if problem:
        report.verdict = "rejected"
        return False
    return True


def import_bundle(settings: Settings, database: Database, source: str | Path, *, actor_type: str, actor_id: str,
                  progress: Progress | None = None, now: _dt.datetime | None = None,
                  allow_downgrade: bool = False) -> ImportResult:
    """Verify `source` against the host's trust store and import policy, then store and register it."""
    source = Path(source)
    trust = load_trust_store(settings.trust_dir)
    ensure_store(settings)
    staging = _Staging(staging_dir(settings))
    actor = f"{actor_type}:{actor_id}"
    try:
        try:
            report = verify_bundle(source, settings.imports, trust, now=now, progress=progress, sink=staging)
        except BaseException as exc:
            _audit_failure(database, source, actor_type, actor_id, exc)
            raise
        if report.accepted:
            with database.session() as conn:
                _apply_history(conn, report, allow_downgrade=allow_downgrade)
        if not report.accepted:
            with database.session() as conn, write_tx(conn):
                vid = _insert_verification(conn, report, source, "import", actor)
                audit.append_event(conn, actor_type=actor_type, actor_id=actor_id, action="bundle.import",
                                   resource=_resource(report, source), outcome="rejected",
                                   details=_rejection_details(report, source, vid))
            return ImportResult(report, verification_id=vid)

        manifest = report.manifest
        assert manifest is not None and report.bundle_id is not None
        stored, repaired = _place(settings, report, staging)
        signers = report.valid_signers
        with database.session() as conn, write_tx(conn):
            exists = conn.execute("SELECT 1 FROM bundles WHERE bundle_id = ?", (report.bundle_id,)).fetchone()
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
                conn.execute(
                    "INSERT OR IGNORE INTO artifacts (digest, size, kind, format, model_name, metadata,"
                    " first_bundle_id, imported_at) VALUES (?,?,?,?,?,?,?,?)",
                    (entry.sha256, entry.size, entry.kind, record["detected_format"],
                     entry.model.name if entry.model else None,
                     canonical_json(_artifact_metadata(record, model)).decode("ascii"), report.bundle_id, now_text),
                )
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
                            stored=stored, repaired=repaired)
    finally:
        staging.discard()


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
