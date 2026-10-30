"""Verify a bundle: structure, signatures, schema, inventory, digests, formats, policy.

The order is fixed (docs/design/v1-spec.md section 4). Structure is checked
before any member is read. Signatures over the exact manifest bytes are checked
before the manifest JSON is parsed. Nothing the manifest says about an
artifact's content (format, metadata) is believed without recomputing it from
the bytes. Artifacts stream through in 1 MiB chunks; with a sink (the
importer's staging files) each chunk goes to the sink in the same pass as the
hash, and format detection then reads the sink's copy, so the bytes that were
classified, and later stored, are exactly the bytes that were hashed.

Member names are never turned into filesystem paths here: readers open members
by their position in the listing.

The verdict fails closed: a bundle is accepted only when every required check
ran and passed, not merely when no check failed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import tarfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Callable

from .. import __version__, crypto
from ..config import ImportSettings, Settings
from ..formats import FormatInfo, detect_format, quote_untrusted
from ..manifest import (ARTIFACT_PATH, MAX_PATH_CHARS, Manifest, ManifestError, bundle_id_for,
                        ferry_version_satisfied, parse_manifest)
from ..trust import TrustEntry, TrustStore
from ..util import rfc3339, utc_now
from .reader import DIR, FILE, TYPE_LABELS, BundleReader, BundleReadError, Member, open_bundle

REPORT_VERSION = 1
CHUNK_SIZE = 1024 * 1024
MAX_REASONS = 50
MAX_WARNINGS = 200
EXTRA_MEMBERS = 64

CHECK_IDS = (
    "archive.readable", "archive.members", "archive.paths", "archive.duplicates", "archive.limits",
    "manifest.present", "signatures.valid", "signatures.roles", "manifest.schema", "compat.ferry_version",
    "inventory.missing", "inventory.extra", "artifact.size", "artifact.digest", "artifact.format",
    "policy.kinds", "policy.formats", "policy.pickle", "policy.executables", "policy.archives",
    "policy.licenses", "compat.memory",
)
_STRUCTURE = CHECK_IDS[1:6]
_SIGNATURES = ("signatures.valid", "signatures.roles")
_POLICY = tuple(c for c in CHECK_IDS if c.startswith("policy."))

SIGNATURE_MEMBER = re.compile(r"signatures/([0-9a-f]{64})\.sig")
_ARTIFACT_DIR = re.compile(r"artifacts(/[A-Za-z0-9][A-Za-z0-9._-]*)*")

Sink = Callable[[str], IO[bytes]]
"""Called with an artifact's manifest path; returns a new binary file opened
"w+b". The verifier writes the artifact's bytes to it while hashing, reads it
back for format detection, and closes it."""
Progress = Callable[[int, int], None]


@dataclass
class VerificationReport:
    verdict: str
    bundle_id: str | None
    bundle: dict[str, Any] | None
    source: dict[str, Any]
    verified_at: str
    tool_version: str
    policy: dict[str, Any]
    signatures: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    errors: list[str]
    warnings: list[str]
    manifest: Manifest | None = field(default=None, repr=False, compare=False)

    @property
    def accepted(self) -> bool:
        return self.verdict == "accepted"

    def check(self, check_id: str) -> dict[str, Any]:
        return next(c for c in self.checks if c["id"] == check_id)

    @property
    def valid_signers(self) -> list[dict[str, Any]]:
        return [{"key_id": s["key_id"], "name": s["name"], "roles": list(s["roles"])}
                for s in self.signatures if s["status"] == "valid"]

    def to_dict(self) -> dict[str, Any]:
        """The report as JSON-serializable data (spec section 4, report_version 1)."""
        return {
            "report_version": REPORT_VERSION,
            "verdict": self.verdict,
            "bundle_id": self.bundle_id,
            "bundle": dict(self.bundle) if self.bundle else None,
            "source": dict(self.source),
            "verified_at": self.verified_at,
            "tool_version": self.tool_version,
            "policy": dict(self.policy),
            "signatures": [dict(s, roles=list(s["roles"])) for s in self.signatures],
            "artifacts": [dict(a, metadata=dict(a["metadata"])) for a in self.artifacts],
            "checks": [dict(c) for c in self.checks],
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def policy_dict(policy: ImportSettings) -> dict[str, Any]:
    """The effective import policy as it appears in reports."""
    return {
        "required_roles": list(policy.required_roles), "distinct_signers": policy.distinct_signers,
        "allowed_kinds": list(policy.allowed_kinds), "allowed_model_formats": list(policy.allowed_model_formats),
        "allow_pickle": policy.allow_pickle, "allow_executables": policy.allow_executables,
        "allowed_licenses": list(policy.allowed_licenses), "max_bundle_bytes": policy.max_bundle_bytes,
        "max_artifact_bytes": policy.max_artifact_bytes, "max_artifacts": policy.max_artifacts,
        "max_manifest_bytes": policy.max_manifest_bytes,
    }


def host_memory_bytes() -> int | None:
    try:
        pages, page_size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None
    return pages * page_size if pages > 0 and page_size > 0 else None


def _path_problem(member: Member) -> str | None:
    name = member.name
    shown = quote_untrusted(name)
    if not name:
        return "a member has an empty name"
    if "\x00" in name:
        return f"member {shown} contains a NUL character"
    if "\\" in name:
        return f"member {shown} contains a backslash"
    if name.startswith("/"):
        return f"member {shown} is an absolute path"
    parts = name.split("/")
    if ".." in parts:
        return f"member {shown} contains a '..' component"
    if "" in parts:
        return f"member {shown} has an empty path component"
    if "." in parts:
        return f"member {shown} contains a '.' component"
    if len(name) > MAX_PATH_CHARS:
        return f"member {shown} is longer than {MAX_PATH_CHARS} characters"
    if member.type == DIR:
        if name == "signatures" or _ARTIFACT_DIR.fullmatch(name):
            return None
        return f"directory {shown} is not part of the bundle layout (signatures/, artifacts/...)"
    if name == "manifest.json" or SIGNATURE_MEMBER.fullmatch(name) or ARTIFACT_PATH.fullmatch(name):
        return None
    if name.startswith("signatures/"):
        return f"member {shown} is not named signatures/<64 lowercase hex key id>.sig"
    if name.startswith("artifacts/"):
        return (f"member {shown} is not a valid artifact path (components of letters, digits, '.', '_' "
                "and '-', each starting with a letter or digit)")
    return f"member {shown} is outside the bundle layout (manifest.json, signatures/<key id>.sig, artifacts/...)"


def _status_detail(entry: TrustEntry, status: str) -> str:
    if status == "revoked":
        return f"key was revoked at {entry.revoked_at}: {entry.revocation_reason or 'no reason recorded'}"
    if status == "expired":
        return f"key expired at {entry.not_after}"
    return f"key is not valid before {entry.not_before}"


def _assign_roles(required: list[str], signers: list[tuple[str, set[str]]], distinct: bool) -> dict[str, str | None]:
    """Role -> signing key id. With `distinct`, a maximum bipartite matching so one key
    never satisfies two roles."""
    if not distinct:
        return {role: next((kid for kid, roles in signers if role in roles), None) for role in required}
    holder: dict[str, str] = {}

    def augment(role: str, seen: set[str]) -> bool:
        for kid, roles in signers:
            if role in roles and kid not in seen:
                seen.add(kid)
                if kid not in holder or augment(holder[kid], seen):
                    holder[kid] = role
                    return True
        return False

    for role in required:
        augment(role, set())
    by_role = {role: kid for kid, role in holder.items()}
    return {role: by_role.get(role) for role in required}


def _short(kid: str) -> str:
    return crypto.short_id(kid) + "…"


class _Run:
    def __init__(self, source: Path, policy: ImportSettings, trust: TrustStore | None, *, now: _dt.datetime | None,
                 full: bool, progress: Progress | None, sink: Sink | None, integrity_only: bool):
        self.source, self.policy = source, policy
        self.trust = trust if trust is not None else TrustStore.empty()
        self.now = now or utc_now()
        self.full, self.progress, self.sink, self.integrity_only = full, progress, sink, integrity_only
        self.checks = {cid: {"id": cid, "status": "skip", "message": "not run"} for cid in CHECK_IDS}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.signatures: list[dict[str, Any]] = []
        self.artifacts: list[dict[str, Any]] = []
        self.files: dict[str, Member] = {}
        self.duplicated: set[str] = set()
        self.raw_manifest: bytes | None = None
        self.manifest: Manifest | None = None
        self.bundle: dict[str, Any] | None = None
        self.source_info: dict[str, Any] = {"name": source.name, "type": None, "size": None}
        self.done = self.total = 0

    # ------------------------------------------------------------------ bookkeeping

    def set(self, cid: str, status: str, message: str, reasons: list[str] | None = None) -> None:
        self.checks[cid] = {"id": cid, "status": status, "message": message}
        target = self.errors if status == "fail" else self.warnings if status == "warn" else None
        if target is not None:
            shown = reasons or [message]
            target.extend(shown[:MAX_REASONS])
            if len(shown) > MAX_REASONS:
                target.append(f"... and {len(shown) - MAX_REASONS} more ({cid})")

    def verdict_for(self, reasons: list[str], cid: str, ok: str, bad: str, *, soft: bool = False) -> None:
        if reasons:
            self.set(cid, "warn" if soft else "fail", bad, reasons)
        else:
            self.set(cid, "pass", ok)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)

    def failed(self, ids: tuple[str, ...]) -> bool:
        return any(self.checks[c]["status"] == "fail" for c in ids)

    # ------------------------------------------------------------------ pipeline

    def run(self) -> VerificationReport:
        if not self.integrity_only:
            for problem in self.trust.problems:
                self.warn(f"trust store: {problem}")
        try:
            reader = open_bundle(self.source, max_members=self.policy.max_artifacts + EXTRA_MEMBERS)
        except BundleReadError as exc:
            self._describe_unreadable()
            self.set("archive.readable", "fail", exc.message)
            return self.finish()
        with reader:
            self.source_info.update(type=reader.source_type, size=reader.size)
            noun = "tar archive" if reader.source_type == "tar" else "directory"
            self.set("archive.readable", "pass", f"{noun} with {len(reader.members)} members")
            self.structure(reader)
            if self.raw_manifest is None or (self.failed(_STRUCTURE) and not self.full):
                return self.finish()
            self.check_signatures(reader)
            if self.failed(_SIGNATURES) and not self.full:
                return self.finish()
            self.schema()
            if self.manifest is None:
                return self.finish()
            self.compat_version()
            self.inventory()
            self.content(reader)
            self.policy_checks()
            self.memory()
        return self.finish()

    def _describe_unreadable(self) -> None:
        try:
            st = os.lstat(self.source)
        except OSError:
            return
        if os.path.isdir(self.source) and not os.path.islink(self.source):
            self.source_info["type"] = "dir"
        elif not os.path.islink(self.source):
            self.source_info.update(type="tar", size=st.st_size)

    def structure(self, reader: BundleReader) -> None:
        pol, members = self.policy, reader.members
        limit = pol.max_artifacts + EXTRA_MEMBERS

        bad = []
        for m in members:
            if m.type not in (FILE, DIR):
                bad.append(f"member {quote_untrusted(m.name)} is a {TYPE_LABELS.get(m.type, m.type)}; "
                           "only regular files and directories are allowed")
            elif m.mode & 0o7000:
                bad.append(f"member {quote_untrusted(m.name)} has setuid, setgid or sticky bits (mode {m.mode:o})")
        if not reader.listing_complete:
            bad.append(f"the bundle has more than {limit:,} members (max_artifacts + {EXTRA_MEMBERS})")
        self.verdict_for(bad, "archive.members", f"{len(members)} members, all regular files or directories",
                         "the bundle contains members that are not regular files or directories")

        path_problems = {m.index: p for m in members if (p := _path_problem(m))}
        self.verdict_for(list(path_problems.values()), "archive.paths", "all member names are inside the bundle layout",
                         "member names outside the bundle layout")

        exact = Counter(m.name for m in members)
        folded: dict[str, set[str]] = {}
        for m in members:
            folded.setdefault(m.name.lower(), set()).add(m.name)
        dups = [f"member {quote_untrusted(n)} appears {c} times" for n, c in sorted(exact.items()) if c > 1]
        for variants in folded.values():
            if len(variants) > 1:
                dups.append("members " + ", ".join(quote_untrusted(v) for v in sorted(variants))
                            + " differ only in letter case")
                self.duplicated.update(variants)
        self.duplicated.update(n for n, c in exact.items() if c > 1)
        self.verdict_for(dups, "archive.duplicates", "no duplicate member names", "duplicate member names")

        limits = []
        files = [m for m in members if m.type == FILE]
        total = sum(m.size for m in files)
        if reader.size > pol.max_bundle_bytes:
            limits.append(f"the bundle is {reader.size:,} bytes; the limit is {pol.max_bundle_bytes:,}")
        elif total > pol.max_bundle_bytes:
            limits.append(f"the members add up to {total:,} bytes; the limit is {pol.max_bundle_bytes:,}")
        for m in files:
            if m.size > pol.max_artifact_bytes:
                limits.append(f"member {quote_untrusted(m.name)} is {m.size:,} bytes; the limit is {pol.max_artifact_bytes:,}")
        self.verdict_for(limits, "archive.limits", f"{total:,} bytes in {len(files)} files, within limits",
                         "the bundle exceeds size limits")

        self.files = {m.name: m for m in files if m.index not in path_problems and m.name not in self.duplicated}
        manifest = self.files.get("manifest.json")
        if manifest is None:
            if any(m.name.lower() == "manifest.json" for m in members):
                self.set("manifest.present", "fail", "manifest.json is not a single regular file at the top of the bundle")
            else:
                self.set("manifest.present", "fail", "the bundle has no manifest.json")
            return
        if manifest.size > pol.max_manifest_bytes:
            self.set("manifest.present", "fail",
                     f"manifest.json is {manifest.size:,} bytes; the limit is {pol.max_manifest_bytes:,}")
            return
        try:
            with reader.open(manifest) as fh:
                raw = fh.read(manifest.size + 1)
        except (BundleReadError, OSError, tarfile.TarError) as exc:
            self.set("manifest.present", "fail", f"manifest.json could not be read: {exc}")
            return
        if len(raw) != manifest.size:
            self.set("manifest.present", "fail", "manifest.json is shorter or longer than its header says")
            return
        self.raw_manifest = raw
        self.set("manifest.present", "pass", f"manifest.json, {len(raw):,} bytes")

    def check_signatures(self, reader: BundleReader) -> None:
        assert self.raw_manifest is not None
        found = sorted((match.group(1), m) for name, m in self.files.items()
                       if (match := SIGNATURE_MEMBER.fullmatch(name)))
        failures: list[str] = []
        for kid, member in found:
            entry = None if self.integrity_only else self.trust.get(kid)
            record: dict[str, Any] = {"key_id": kid, "name": entry.name if entry else "",
                                      "roles": list(entry.roles) if entry else [], "status": "", "detail": ""}
            self.signatures.append(record)
            if member.size != crypto.SIGNATURE_BYTES:
                record.update(status="malformed",
                              detail=f"signature file is {member.size} bytes; an Ed25519 signature is 64 bytes")
                failures.append(f"{member.name}: {record['detail']}")
                continue
            if self.integrity_only:
                record.update(status="untrusted", detail="not checked against a trust store (integrity check only)")
                continue
            if entry is None:
                why = self.trust.ignored.get(kid)
                record.update(status="untrusted", detail=f"a trust entry for this key exists but is ignored: {why}"
                              if why else "key is not in the trust store")
                continue
            status = entry.status(self.now)
            if status != "active":
                record.update(status=status, detail=_status_detail(entry, status))
                continue
            try:
                with reader.open(member) as fh:
                    signature = fh.read(crypto.SIGNATURE_BYTES + 1)
            except (BundleReadError, OSError, tarfile.TarError) as exc:
                record.update(status="malformed", detail=f"signature could not be read: {exc}")
                failures.append(f"{member.name}: {record['detail']}")
                continue
            if crypto.verify(entry.public_key, signature, self.raw_manifest):  # type: ignore[arg-type]
                record["status"] = "valid"
            else:
                record.update(status="invalid", detail="signature does not match manifest.json")
                failures.append(f"signature from trusted key {_short(kid)} ({entry.name}) does not verify: "
                                "manifest.json or the signature was altered after signing")

        counts = Counter(r["status"] for r in self.signatures)
        summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) or "no signatures"
        if failures:
            self.set("signatures.valid", "fail", f"bad signatures ({summary})", failures)
        else:
            self.set("signatures.valid", "pass", summary)
        if self.integrity_only:
            self.set("signatures.roles", "skip", "trust and roles are not checked in an integrity-only check")
            return
        for r in self.signatures:
            if r["status"] in ("untrusted", "revoked", "expired", "not_yet_valid"):
                self.warn(f"signature from key {_short(r['key_id'])} does not count: {r['detail']}")
        self.check_roles()

    def check_roles(self) -> None:
        required = list(dict.fromkeys(self.policy.required_roles))
        signers = [(r["key_id"], set(r["roles"])) for r in self.signatures if r["status"] == "valid"]
        assignment = _assign_roles(required, signers, self.policy.distinct_signers)
        reasons = []
        for role in required:
            if assignment.get(role) is not None:
                continue
            holders = [kid for kid, roles in signers if role in roles]
            if not holders:
                reasons.append(f"required role {role!r} is not satisfied: no valid signature from an active trusted "
                               "key holding that role")
            else:
                reasons.append(f"required role {role!r} is not satisfied by a distinct signer: key(s) "
                               + ", ".join(_short(k) for k in holders)
                               + " already satisfy another required role and distinct_signers is on")
        if reasons:
            self.set("signatures.roles", "fail", "required signer roles are not satisfied", reasons)
            return
        names = {r["key_id"]: r["name"] for r in self.signatures}
        self.set("signatures.roles", "pass", "; ".join(
            f"{role}: {_short(kid)} ({names.get(kid, '')})" for role, kid in assignment.items() if kid))

    def schema(self) -> None:
        assert self.raw_manifest is not None
        try:
            self.manifest = parse_manifest(self.raw_manifest, self.policy)
        except ManifestError as exc:
            self.set("manifest.schema", "fail", f"manifest.json is not a valid v1 manifest ({len(exc.errors)} problems)",
                     exc.errors)
            return
        m = self.manifest
        self.bundle = {"name": m.name, "version": m.version, "created_at": m.created_at}
        self.set("manifest.schema", "pass", f"{m.name} {m.version}, {len(m.artifacts)} artifacts")
        self.artifacts = [{
            "path": a.path, "kind": a.kind, "declared_format": a.format, "detected_format": None, "size": a.size,
            "expected_sha256": a.sha256, "actual_sha256": None, "status": "skipped", "detail": "", "metadata": {},
        } for a in m.artifacts]

    def compat_version(self) -> None:
        assert self.manifest is not None
        need = self.manifest.ferry_min_version
        if ferry_version_satisfied(need):
            self.set("compat.ferry_version", "pass", f"needs Ferry {need} or newer; this is {__version__}")
        else:
            self.set("compat.ferry_version", "fail", f"the bundle needs Ferry {need} or newer; this is Ferry {__version__}")

    def inventory(self) -> None:
        assert self.manifest is not None
        listed = {a.path for a in self.manifest.artifacts}
        missing = []
        for a, record in zip(self.manifest.artifacts, self.artifacts):
            if a.path in self.files:
                continue
            if a.path in self.duplicated:
                detail = "appears more than once in the bundle"
            elif a.path.lower() in {n.lower() for n in self.files}:
                detail = "is present only under a different letter case"
            else:
                detail = "is not in the bundle as a regular file"
            record.update(status="missing", detail=detail)
            missing.append(f"{a.path} {detail}")
        self.verdict_for(missing, "inventory.missing", f"all {len(listed)} listed artifacts are present",
                         "listed artifacts are missing")
        extra = sorted(n for n in self.files if n.startswith("artifacts/") and n not in listed)
        self.verdict_for([f"member {quote_untrusted(n)} is not listed in the manifest" for n in extra],
                         "inventory.extra", "no unlisted artifacts", "the bundle contains unlisted artifacts")

    def content(self, reader: BundleReader) -> None:
        assert self.manifest is not None
        size_problems, digest_problems, format_problems = [], [], []
        to_read = []
        for a, record in zip(self.manifest.artifacts, self.artifacts):
            member = self.files.get(a.path)
            if member is None:
                continue
            if member.size != a.size:
                record.update(status="mismatch", detail=f"member is {member.size:,} bytes; the manifest says {a.size:,}")
                size_problems.append(f"{a.path}: {record['detail']}")
                continue
            to_read.append((a, record, member))
        self.verdict_for(size_problems, "artifact.size", "every artifact has its declared size",
                         "artifact sizes do not match the manifest")

        self.total = sum(a.size for a, _, _ in to_read)
        self._report_progress()
        for a, record, member in to_read:
            out = self.sink(a.path) if self.sink is not None else None
            try:
                digest, error = self._hash(reader, member, a.size, out)
                if error is not None:
                    record.update(status="mismatch", detail=error)
                    digest_problems.append(f"{a.path}: {error}")
                    continue
                record["actual_sha256"] = digest
                if digest != a.sha256:
                    record.update(status="mismatch", detail="SHA-256 does not match the manifest")
                    digest_problems.append(f"{a.path}: SHA-256 is {digest}; the manifest says {a.sha256}")
                    continue
                info = self._detect(reader, member, a.path, a.size, out)
            finally:
                if out is not None:
                    out.close()
            record.update(detected_format=info.format, metadata=info.metadata)
            for warning in info.warnings:
                self.warn(f"{a.path}: {warning}")
            problems = list(info.problems)
            if info.format != a.format:
                problems.insert(0, f"declared as {a.format} but the content is {info.format}")
            if problems:
                record.update(status="malformed", detail="; ".join(problems))
                format_problems.append(f"{a.path}: {record['detail']}")
            else:
                record["status"] = "ok"
        if self.total == 0 or self.done != self.total:
            self._report_progress()
        self.verdict_for(digest_problems, "artifact.digest", f"{len(to_read)} artifacts, {self.total:,} bytes hashed",
                         "artifact digests do not match the manifest")
        self.verdict_for(format_problems, "artifact.format", "detected formats match the declared formats",
                         "artifact formats are wrong or malformed")

    def _report_progress(self) -> None:
        if self.progress is not None:
            self.progress(self.done, self.total)

    def _hash(self, reader: BundleReader, member: Member, size: int, out: IO[bytes] | None) -> tuple[str, str | None]:
        digest = hashlib.sha256()
        buf = bytearray(CHUNK_SIZE)
        view = memoryview(buf)
        remaining = size
        try:
            src = reader.open(member)
        except BundleReadError as exc:
            return "", exc.message
        with src:
            while remaining:
                try:
                    n = src.readinto(view[:min(CHUNK_SIZE, remaining)])  # type: ignore[attr-defined]
                except (OSError, tarfile.TarError, BundleReadError) as exc:
                    return "", f"read failed after {size - remaining:,} bytes ({exc})"
                if not n:
                    return "", f"member ended after {size - remaining:,} of {size:,} bytes"
                chunk = view[:n]
                digest.update(chunk)
                if out is not None:
                    out.write(chunk)
                remaining -= n
                self.done += n
                self._report_progress()
        return digest.hexdigest(), None

    def _detect(self, reader: BundleReader, member: Member, path: str, size: int, out: IO[bytes] | None) -> FormatInfo:
        if out is not None and out.readable() and out.seekable():
            out.flush()  # a local write failure is an error, not a verdict on the bundle
            try:
                return detect_format(out, size, path)
            except OSError as exc:
                return FormatInfo("binary", {}, [f"could not be read back for format detection ({exc})"])
        try:
            with reader.open(member) as fh:
                return detect_format(fh, size, path)
        except (OSError, tarfile.TarError, BundleReadError) as exc:
            return FormatInfo("binary", {}, [f"could not be read for format detection ({exc})"])

    def policy_checks(self) -> None:
        assert self.manifest is not None
        pol = self.policy
        soft = self.integrity_only
        licenses = {lic.casefold() for lic in pol.allowed_licenses}
        file_ok = "file" in pol.allowed_kinds
        found: dict[str, list[str]] = {cid: [] for cid in _POLICY}
        for a, record in zip(self.manifest.artifacts, self.artifacts):
            detected = record["detected_format"]
            formats = {a.format} | ({detected} if detected else set())
            reasons = []
            if a.kind not in pol.allowed_kinds:
                reasons.append(("policy.kinds", f"kind {a.kind!r} is not allowed (allowed: {', '.join(pol.allowed_kinds)})"))
            if a.kind == "model":
                fmt = detected or a.format
                if fmt not in pol.allowed_model_formats:
                    reasons.append(("policy.formats", f"model format {fmt!r} is not allowed "
                                    f"(allowed: {', '.join(pol.allowed_model_formats)})"))
                license_id = a.model.license if a.model else ""
                if license_id.casefold() not in licenses:
                    reasons.append(("policy.licenses", f"licence {license_id!r} is not allowed "
                                    f"(allowed: {', '.join(pol.allowed_licenses)})"))
                embedded = record["metadata"].get("license") if detected == "gguf" else None
                if isinstance(embedded, str) and embedded.casefold() != license_id.casefold():
                    self.warn(f"{a.path}: the GGUF file names its licence {quote_untrusted(embedded)} but the "
                              f"manifest declares {license_id}")
            if "pickle" in formats and not pol.allow_pickle:
                reasons.append(("policy.pickle", "pickle content can run code when loaded and allow_pickle is false"))
            if "executable" in formats and not pol.allow_executables:
                reasons.append(("policy.executables", "executable content and allow_executables is false"))
            if "archive" in formats and not (a.kind == "file" and file_ok):
                reasons.append(("policy.archives", "nested archives are only allowed as kind 'file' when that kind "
                                "is allowed"))
            for cid, reason in reasons:
                found[cid].append(f"{a.path}: {reason}")
            if reasons and not soft and record["status"] in ("ok", "skipped"):
                record.update(status="rejected", detail=reasons[0][1])
        prefix = "the default import policy would reject this: " if soft else ""
        labels = {
            "policy.kinds": ("all artifact kinds are allowed", "artifact kinds not allowed by policy"),
            "policy.formats": ("all model formats are allowed", "model formats not allowed by policy"),
            "policy.pickle": ("no pickle content", "pickle content"),
            "policy.executables": ("no executable content", "executable content"),
            "policy.archives": ("no nested archives", "nested archives"),
            "policy.licenses": ("all model licences are allowed", "model licences not allowed by policy"),
        }
        for cid in _POLICY:
            ok, bad = labels[cid]
            self.verdict_for([prefix + r for r in found[cid]], cid, ok, prefix + bad, soft=soft)

    def memory(self) -> None:
        assert self.manifest is not None
        need = self.manifest.min_memory_bytes
        if need is None:
            self.set("compat.memory", "pass", "no memory requirement declared")
            return
        have = host_memory_bytes()
        if have is None:
            self.set("compat.memory", "skip", "host memory could not be determined")
        elif have < need:
            self.set("compat.memory", "warn", f"the bundle asks for {need:,} bytes of memory; this host has {have:,}")
        else:
            self.set("compat.memory", "pass", f"needs {need:,} bytes of memory; this host has {have:,}")

    def finish(self) -> VerificationReport:
        required = [c for c in CHECK_IDS if c != "compat.memory"]
        if self.integrity_only:
            required = [c for c in required if c != "signatures.roles" and c not in _POLICY]
        accepted = (all(self.checks[c]["status"] == "pass" for c in required)
                    and not any(c["status"] == "fail" for c in self.checks.values()))
        return VerificationReport(
            verdict="accepted" if accepted else "rejected",
            bundle_id=bundle_id_for(self.raw_manifest) if self.raw_manifest is not None else None,
            bundle=self.bundle,
            source=self.source_info,
            verified_at=rfc3339(self.now),
            tool_version=__version__,
            policy=policy_dict(self.policy),
            signatures=self.signatures,
            artifacts=self.artifacts,
            checks=[self.checks[c] for c in CHECK_IDS],
            errors=self.errors,
            warnings=self.warnings,
            manifest=self.manifest,
        )


def verify_bundle(source: str | Path, settings: Settings | ImportSettings, trust: TrustStore | None, *,
                  now: _dt.datetime | None = None, full: bool = False, progress: Progress | None = None,
                  sink: Sink | None = None) -> VerificationReport:
    """Verify a tar or directory bundle against `settings` (import policy) and `trust`.

    `full=True` keeps going after structural or signature failures, for a
    complete diagnosis; the verdict is the same. `trust=None` trusts nothing.
    """
    policy = settings.imports if isinstance(settings, Settings) else settings
    return _Run(Path(source), policy, trust, now=now, full=full, progress=progress, sink=sink,
                integrity_only=False).run()


def integrity_check(source: str | Path, settings: Settings | ImportSettings | None = None, *,
                    progress: Progress | None = None) -> VerificationReport:
    """Structure, schema, inventory, digests and formats, without trust or role checks.

    Used before countersigning. Policy checks are reported as warnings against
    the default import policy instead of failing.
    """
    policy = settings.imports if isinstance(settings, Settings) else (settings or ImportSettings())
    return _Run(Path(source), policy, None, now=None, full=False, progress=progress, sink=None,
                integrity_only=True).run()
