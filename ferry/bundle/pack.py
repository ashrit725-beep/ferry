"""Pack a bundle on the connected side, and countersign one (`ferry pack`, `ferry sign`).

Packing is deterministic: the same spec, source bytes, key and `created_at`
give a byte-identical tar (members in a fixed order, mode 0644, uid/gid 0,
empty owner names, mtime = created_at). Every source is hashed and classified
before the manifest is written, then hashed again while it is copied into the
tar; if the two digests differ the source changed during packing and no
bundle is written.

Pack refuses content the default import policy rejects (pickle, executables,
nested archives) unless `allow_unsafe` is set, and always refuses malformed
GGUF or safetensors. Next to the tar it writes `<bundle>.ferry.tar.sha256`
(sha256sum format) and `<bundle>.review.md`, a review sheet whose commands
check the signature and every digest with tar, OpenSSL and sha256sum/shasum,
independently of Ferry.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import os
import re
import secrets
import stat
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import __version__, crypto
from ..config import MODEL_FORMATS, ImportSettings
from ..errors import Conflict, CryptoError, FerryError, ValidationFailed
from ..formats import FormatInfo, detect_format
from ..manifest import (RFC3339, Manifest, build_manifest, dump_manifest, parse_manifest, validate_manifest)
from ..util import atomic_write, parse_rfc3339, rfc3339, utc_now
from .verify import CHUNK_SIZE, Progress, integrity_check

_SPEC_TOP, _SPEC_TOP_REQUIRED = {"bundle", "requires", "artifacts"}, {"bundle", "artifacts"}
_SPEC_BUNDLE, _SPEC_BUNDLE_REQUIRED = {"name", "version", "description"}, {"name", "version"}
_SPEC_REQUIRES = {"ferry_min_version", "runtime", "runtime_min_version", "min_memory_bytes"}
_SPEC_ARTIFACT, _SPEC_ARTIFACT_REQUIRED = {"source", "path", "kind", "model"}, {"source", "path", "kind"}
_SPEC_MODEL, _SPEC_MODEL_REQUIRED = {"name", "license", "source_uri", "source_revision", "upstream_sha256"}, {"name", "license"}
_FLAG_FORMATS = (("pickle", "Pickle content"), ("executable", "Executables"), ("archive", "Nested archives"))


@dataclass(frozen=True)
class SpecArtifact:
    source: Path
    path: str
    kind: str
    model: dict[str, Any] | None


@dataclass(frozen=True)
class PackSpec:
    path: Path
    name: str
    version: str
    description: str
    requires: dict[str, Any]
    artifacts: tuple[SpecArtifact, ...]


@dataclass(frozen=True)
class PackResult:
    bundle_path: Path
    sha256_path: Path
    review_path: Path
    bundle_id: str
    tar_sha256: str
    tar_size: int
    key_id: str
    manifest: dict[str, Any]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"bundle_path": str(self.bundle_path), "sha256_path": str(self.sha256_path),
                "review_path": str(self.review_path), "bundle_id": self.bundle_id, "tar_sha256": self.tar_sha256,
                "tar_size": self.tar_size, "key_id": self.key_id, "manifest": self.manifest,
                "warnings": list(self.warnings)}


@dataclass(frozen=True)
class SignResult:
    bundle_path: Path
    bundle_id: str
    key_id: str
    signature_member: str
    tar_sha256: str | None
    sidecar_updated: bool
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"bundle_path": str(self.bundle_path), "bundle_id": self.bundle_id, "key_id": self.key_id,
                "signature_member": self.signature_member, "tar_sha256": self.tar_sha256,
                "sidecar_updated": self.sidecar_updated, "warnings": list(self.warnings)}


# --------------------------------------------------------------------------- spec


def _table_keys(errors: list[str], where: str, table: Any, allowed: set[str], required: set[str]) -> bool:
    if not isinstance(table, dict):
        errors.append(f"{where or 'spec'} must be a table")
        return False
    for key in sorted(required - set(table)):
        errors.append(f"{where + '.' if where else ''}{key} is required")
    for key in sorted(set(table) - allowed):
        errors.append(f"unknown key {where + '.' if where else ''}{key}")
    return True


def load_pack_spec(spec_path: str | Path) -> PackSpec:
    """Read and validate a pack spec (TOML). Unknown keys are errors."""
    spec_path = Path(spec_path)
    try:
        raw = tomllib.loads(spec_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValidationFailed(f"pack spec not found: {spec_path}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValidationFailed(f"{spec_path}: invalid TOML: {exc}") from None
    errors: list[str] = []
    _table_keys(errors, "", raw, _SPEC_TOP, _SPEC_TOP_REQUIRED)
    bundle = raw.get("bundle", {})
    requires = raw.get("requires", {})
    artifacts = raw.get("artifacts", [])
    _table_keys(errors, "bundle", bundle, _SPEC_BUNDLE, _SPEC_BUNDLE_REQUIRED)
    _table_keys(errors, "requires", requires, _SPEC_REQUIRES, set())
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("at least one [[artifacts]] entry is required")
        artifacts = []
    entries: list[SpecArtifact] = []
    for i, art in enumerate(artifacts):
        where = f"artifacts[{i}]"
        if not _table_keys(errors, where, art, _SPEC_ARTIFACT, _SPEC_ARTIFACT_REQUIRED):
            continue
        source, path, kind = art.get("source"), art.get("path"), art.get("kind")
        model = art.get("model")
        if not isinstance(source, str) or not source:
            errors.append(f"{where}.source must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            errors.append(f"{where}.path must be a non-empty string")
            continue
        if not isinstance(kind, str):
            errors.append(f"{where}.kind must be a string")
            continue
        if model is not None and _table_keys(errors, f"{where}.model", model, _SPEC_MODEL, _SPEC_MODEL_REQUIRED):
            model = dict(model)
            if isinstance(model.get("upstream_sha256"), str):
                model["upstream_sha256"] = model["upstream_sha256"].strip().lower()
        src = Path(source)
        entries.append(SpecArtifact(src if src.is_absolute() else spec_path.parent / src,
                                    "artifacts/" + path, kind, model if isinstance(model, dict) else None))
    if errors:
        raise ValidationFailed(f"{spec_path}: invalid pack spec: " + "; ".join(errors), details={"errors": errors})

    spec = PackSpec(spec_path, bundle.get("name"), bundle.get("version"), bundle.get("description", ""),
                    dict(requires), tuple(entries))
    # Validate names, paths, kinds and model fields now, before hours of hashing.
    probe = _manifest_doc(spec, "1970-01-01T00:00:00.000Z",
                          [{"size": 0, "sha256": "0" * 64, "format": "binary", "metadata": {}} for _ in entries])
    problems = validate_manifest(probe)
    if problems:
        raise ValidationFailed(f"{spec_path}: invalid pack spec: " + "; ".join(problems), details={"errors": problems})
    return spec


def _manifest_doc(spec: PackSpec, created_at: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    return build_manifest(
        name=spec.name, version=spec.version, created_at=created_at, description=spec.description,
        requires=spec.requires,
        artifacts=[{"path": a.path, "kind": a.kind, "model": a.model, **f} for a, f in zip(spec.artifacts, facts)],
    )


def _created_at(value: str | _dt.datetime | None) -> tuple[str, int]:
    if value is None:
        ts = utc_now()
    elif isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise ValidationFailed("created_at needs a timezone")
        ts = value
    elif isinstance(value, str) and RFC3339.fullmatch(value.strip()):
        try:
            ts = parse_rfc3339(value.strip())
        except ValueError:
            raise ValidationFailed(f"created_at {value!r} is not a valid date and time") from None
    else:
        raise ValidationFailed("created_at must be an RFC 3339 timestamp such as 2026-10-28T02:00:00Z")
    text = rfc3339(ts)
    mtime = int(parse_rfc3339(text).timestamp())
    if mtime < 0:
        raise ValidationFailed("created_at must not be earlier than 1970-01-01")
    return text, mtime


# --------------------------------------------------------------------------- tar writing


class _HashingReader:
    """What tarfile copies out of a source is hashed on the way through."""

    def __init__(self, fh: IO[bytes], advance: Callable[[int], None]):
        self._fh, self._advance = fh, advance
        self._digest = hashlib.sha256()
        self.count = 0

    def read(self, n: int = -1) -> bytes:
        data = self._fh.read(n)
        self._digest.update(data)
        self.count += len(data)
        self._advance(len(data))
        return data

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


class _HashingWriter:
    """The output tar is hashed as it is written (tarfile writes sequentially in "w" mode)."""

    def __init__(self, fh: IO[bytes]):
        self._fh = fh
        self._digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self._fh.write(data)
        self._digest.update(data)
        self.size += len(data)
        return len(data)

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        self._fh.flush()

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def member_info(name: str, size: int, mtime: int) -> tarfile.TarInfo:
    """A normalized regular-file member: 0644, uid/gid 0, no owner names."""
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime, info.type = size, 0o644, mtime, tarfile.REGTYPE
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def _write_tar(path: Path, manifest_raw: bytes, signatures: dict[str, bytes],
               artifacts: list[tuple[str, Path, int, str]], mtime: int, advance: Callable[[int], None]) -> tuple[str, int]:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            out = _HashingWriter(fh)
            with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8") as tf:  # type: ignore[call-overload]
                tf.copybufsize = CHUNK_SIZE
                tf.addfile(member_info("manifest.json", len(manifest_raw), mtime), io.BytesIO(manifest_raw))
                for kid in sorted(signatures):
                    tf.addfile(member_info(f"signatures/{kid}.sig", len(signatures[kid]), mtime),
                               io.BytesIO(signatures[kid]))
                for name, source, size, digest in sorted(artifacts):
                    with _open_source(source) as src:
                        reader = _HashingReader(src, advance)
                        tf.addfile(member_info(name, size, mtime), reader)  # type: ignore[arg-type]
                    if reader.count != size or reader.hexdigest() != digest:
                        raise FerryError(f"{source} changed while it was being packed; no bundle was written",
                                         code="source_changed")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return out.hexdigest(), out.size


def _open_source(source: Path) -> IO[bytes]:
    """Open a source file (symlinks followed, as in Hugging Face caches) without
    blocking on a FIFO or device, and insist on a regular file."""
    try:
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ValidationFailed(f"cannot read source {source}: {exc.strerror}") from None
    fh = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        fh.close()
        raise ValidationFailed(f"source {source} is not a regular file")
    return fh


def _hash_and_detect(source: Path, name: str, advance: Callable[[int], None]) -> tuple[int, str, FormatInfo]:
    with _open_source(source) as fh:
        st = os.fstat(fh.fileno())
        digest = hashlib.sha256()
        buf = bytearray(CHUNK_SIZE)
        view = memoryview(buf)
        size = 0
        while n := fh.readinto(view):
            digest.update(view[:n])
            size += n
            advance(n)
        if size != st.st_size:
            raise FerryError(f"{source} changed while it was being hashed", code="source_changed")
        return size, digest.hexdigest(), detect_format(fh, size, name)


# --------------------------------------------------------------------------- pack


def pack_bundle(spec_path: str | Path, signing_key: Ed25519PrivateKey, out_dir: str | Path, *,
                created_at: str | _dt.datetime | None = None, progress: Progress | None = None,
                allow_unsafe: bool = False) -> PackResult:
    """Build, sign and write `<name>-<version>.ferry.tar` plus its .sha256 and .review.md sidecars."""
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise CryptoError("the signing key must be an Ed25519 private key")
    spec = load_pack_spec(spec_path)
    created_text, mtime = _created_at(created_at)
    out = Path(out_dir)
    base = f"{spec.name}-{spec.version}"
    tar_path, sha_path, review_path = out / f"{base}.ferry.tar", out / f"{base}.ferry.tar.sha256", out / f"{base}.review.md"
    for p in (tar_path, sha_path, review_path):
        if os.path.lexists(p):
            raise Conflict(f"{p} already exists; refusing to overwrite a bundle (remove it or choose another output directory)")

    sizes = []
    for art in spec.artifacts:
        try:
            sizes.append(os.stat(art.source).st_size)
        except OSError as exc:
            raise ValidationFailed(f"cannot read source {art.source}: {exc.strerror}") from None
    total, done = 2 * sum(sizes), 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress is not None:
            progress(done, total)

    if progress is not None:
        progress(0, total)
    default = ImportSettings()
    licenses = {lic.casefold() for lic in default.allowed_licenses}
    errors: list[str] = []
    warnings: list[str] = []
    facts: list[dict[str, Any]] = []
    for art in spec.artifacts:
        size, digest, info = _hash_and_detect(art.source, art.path, advance)
        fmt = info.format
        facts.append({"size": size, "sha256": digest, "format": fmt,
                      "metadata": {fmt: info.metadata} if info.metadata else {}})
        errors.extend(f"{art.path}: {p}" for p in info.problems)
        warnings.extend(f"{art.path}: {w}" for w in info.warnings)
        unsafe = []
        if fmt == "pickle":
            unsafe.append("pickle content, which can run code when loaded")
        if fmt == "executable":
            unsafe.append("executable content")
        if fmt == "archive" and art.kind != "file":
            unsafe.append("a nested archive (only kind 'file' may be an archive)")
        if unsafe and allow_unsafe:
            warnings.append(f"UNSAFE: {art.path} is {' and '.join(unsafe)}. It was packed only because unsafe "
                            "packing was requested; the default import policy rejects this bundle.")
        elif unsafe:
            errors.append(f"{art.path}: {' and '.join(unsafe)}; the default import policy rejects it "
                          "(pass --allow-unsafe to pack it anyway)")
        if art.kind == "model" and fmt not in MODEL_FORMATS:
            errors.append(f"{art.path}: a model artifact must be GGUF or safetensors, but the content is {fmt}")
        if art.kind not in default.allowed_kinds:
            warnings.append(f"{art.path}: kind {art.kind!r} is not allowed by the default import policy")
        if art.model is not None:
            if str(art.model.get("license", "")).casefold() not in licenses:
                warnings.append(f"{art.path}: licence {art.model.get('license')!r} is not in the default import "
                                "policy's allowed licences")
            expected = art.model.get("upstream_sha256")
            if expected and expected != digest:
                errors.append(f"{art.path}: the SHA-256 of {art.source} is {digest}, but upstream_sha256 in the spec "
                              f"is {expected}; this is not the upstream file")
    if errors:
        raise ValidationFailed("refusing to pack: " + "; ".join(errors), details={"errors": errors})

    manifest_raw = dump_manifest(_manifest_doc(spec, created_text, facts))
    manifest = parse_manifest(manifest_raw)
    public_key = signing_key.public_key()
    kid = crypto.key_id(public_key)
    signature = crypto.sign(signing_key, manifest_raw)
    if not crypto.verify(public_key, signature, manifest_raw):
        raise CryptoError("the signing key produced a signature that does not verify")

    out.mkdir(parents=True, exist_ok=True)
    members = [(art.path, art.source, f["size"], f["sha256"]) for art, f in zip(spec.artifacts, facts)]
    tar_digest, tar_size = _write_tar(tar_path, manifest_raw, {kid: signature}, members, mtime, advance)
    try:
        atomic_write(sha_path, f"{tar_digest}  {tar_path.name}\n".encode("utf-8"), mode=0o644)
        review = render_review_sheet(manifest, bundle_file=tar_path.name, tar_sha256=tar_digest, tar_size=tar_size,
                                     signer_key_ids=[kid], warnings=warnings)
        atomic_write(review_path, review.encode("utf-8"), mode=0o644)
    except BaseException:
        for p in (tar_path, sha_path, review_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        raise
    return PackResult(tar_path, sha_path, review_path, manifest.bundle_id, tar_digest, tar_size, kid,
                      manifest.to_dict(), tuple(warnings))


# --------------------------------------------------------------------------- countersign


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        buf = bytearray(CHUNK_SIZE)
        view = memoryview(buf)
        while n := fh.readinto(view):
            digest.update(view[:n])
    return digest.hexdigest()


def _open_locked(path: Path) -> IO[bytes]:
    """The bundle opened read-write under an exclusive advisory lock, so two
    countersigners cannot interleave between the integrity check and the append."""
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise FerryError(f"cannot open {path} for writing: {exc.strerror}", code="bundle_unwritable") from None
    fh = os.fdopen(fd, "r+b")
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:
        pass
    except OSError:
        fh.close()
        raise Conflict(f"{path} is being modified by another process") from None
    return fh


def _append_tar_signature(fh: IO[bytes], kid: str, signature: bytes, mtime: int) -> None:
    """Append signatures/<kid>.sig in place; on any failure the original end of archive is restored."""
    original_size = os.fstat(fh.fileno()).st_size
    fh.seek(0)
    tf = tarfile.TarFile(fileobj=fh, mode="a", format=tarfile.PAX_FORMAT, encoding="utf-8")
    end = tf.offset
    fh.seek(end)
    tail = fh.read(original_size - end)
    fh.seek(end)
    try:
        tf.addfile(member_info(f"signatures/{kid}.sig", len(signature), mtime), io.BytesIO(signature))
        tf.close()
        fh.flush()
        os.fsync(fh.fileno())
    except BaseException:
        fh.seek(end)
        fh.write(tail)
        fh.truncate(original_size)
        fh.flush()
        os.fsync(fh.fileno())
        raise


def _write_dir_signature(root: Path, kid: str, signature: bytes) -> None:
    """Create signatures/<kid>.sig in a directory bundle without following symlinks or replacing a file."""
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, dir_flags)
    try:
        try:
            os.mkdir("signatures", 0o755, dir_fd=root_fd)
        except FileExistsError:
            pass
        sig_fd = os.open("signatures", dir_flags, dir_fd=root_fd)
        try:
            tmp = f".{kid}.sig.{secrets.token_hex(4)}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644, dir_fd=sig_fd)
            try:
                os.fchmod(fd, 0o644)
                os.write(fd, signature)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, f"{kid}.sig", src_dir_fd=sig_fd, dst_dir_fd=sig_fd)
            except FileExistsError:
                raise Conflict(f"key {kid} has already signed this bundle") from None
            finally:
                os.unlink(tmp, dir_fd=sig_fd)
            os.fsync(sig_fd)
        finally:
            os.close(sig_fd)
    finally:
        os.close(root_fd)


def sign_bundle(bundle_path: str | Path, signing_key: Ed25519PrivateKey, *,
                progress: Progress | None = None) -> SignResult:
    """Countersign: run the integrity pipeline (no trust or role checks), refuse on any
    failure or if this key already signed, then add signatures/<key_id>.sig."""
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise CryptoError("the signing key must be an Ed25519 private key")
    path = Path(bundle_path)
    locked = _open_locked(path) if path.is_file() and not path.is_symlink() else None
    try:
        return _countersign(path, signing_key, locked, progress)
    finally:
        if locked is not None:
            locked.close()


def _countersign(path: Path, signing_key: Ed25519PrivateKey, locked: IO[bytes] | None,
                 progress: Progress | None) -> SignResult:
    report = integrity_check(path, progress=progress)
    if not report.accepted or report.manifest is None:
        raise ValidationFailed("refusing to countersign: the bundle fails its integrity check: "
                               + "; ".join(report.errors[:5] or ["see the report"]), details={"report": report.to_dict()})
    manifest: Manifest = report.manifest
    public_key = signing_key.public_key()
    kid = crypto.key_id(public_key)
    if any(s["key_id"] == kid for s in report.signatures):
        raise Conflict(f"key {kid} has already signed this bundle")
    signature = crypto.sign(signing_key, manifest.raw)
    if not crypto.verify(public_key, signature, manifest.raw):
        raise CryptoError("the signing key produced a signature that does not verify")
    member = f"signatures/{kid}.sig"
    if report.source.get("type") == "dir":
        _write_dir_signature(path, kid, signature)
        return SignResult(path, manifest.bundle_id, kid, member, None, False, tuple(report.warnings))
    held = os.fstat(locked.fileno()) if locked is not None else None
    try:
        current = os.lstat(path)
    except OSError:
        current = None
    if held is None or current is None or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
        raise Conflict(f"{path} was replaced while it was being checked; nothing was signed")
    mtime = max(0, int(parse_rfc3339(manifest.created_at).timestamp()))
    _append_tar_signature(locked, kid, signature, mtime)
    tar_digest = _file_sha256(path)
    sidecar = path.with_name(path.name + ".sha256")
    updated = False
    if sidecar.exists():
        atomic_write(sidecar, f"{tar_digest}  {path.name}\n".encode("utf-8"), mode=0o644)
        updated = True
    return SignResult(path, manifest.bundle_id, kid, member, tar_digest, updated, tuple(report.warnings))


# --------------------------------------------------------------------------- review sheet


def _code(text: str) -> str:
    """A Markdown code span that survives backticks and table pipes in `text`."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    escaped = text.replace("|", "\\|")
    return f"{fence}{pad}{escaped}{pad}{fence}"


def _fenced(text: str, info: str = "") -> list[str]:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + info, *text.splitlines(), fence]


def render_review_sheet(manifest: Manifest, *, bundle_file: str, tar_sha256: str, tar_size: int,
                        signer_key_ids: list[str], warnings: list[str] | tuple[str, ...] = ()) -> str:
    """The Markdown review sheet for the person who approves the transfer."""
    m = manifest
    manifest_hex = m.bundle_id.removeprefix("sha256:")
    requires = [f"Ferry >= {m.ferry_min_version}"]
    if m.runtime:
        requires.append(f"runtime {m.runtime}" + (f" >= {m.runtime_min_version}" if m.runtime_min_version else ""))
    if m.min_memory_bytes is not None:
        requires.append(f"memory >= {m.min_memory_bytes:,} bytes")
    lines = [
        f"# Transfer review: {m.name} {m.version}",
        "",
        f"Written by Ferry {__version__} when this bundle was packed. The checks in the last section use only "
        "standard tools (tar, sha256sum or shasum, OpenSSL), so they can be done without Ferry.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Bundle file | {_code(bundle_file)} |",
        f"| Bundle file SHA-256 (as packed) | {_code(tar_sha256)} |",
        f"| Bundle file size | {tar_size:,} bytes |",
        f"| Bundle id (SHA-256 of manifest.json) | {_code(m.bundle_id)} |",
        f"| Created at | {m.created_at} |",
        f"| Requires | {_code(', '.join(requires))} |",
        "",
    ]
    if m.description:
        lines += ["Description (as declared by the packer):", "", *_fenced(m.description, "text"), ""]
    lines += ["## Signatures", "", "| Key id | Signed |", "|---|---|"]
    lines += [f"| {_code(kid)} | when packed |" for kid in signer_key_ids]
    lines += ["", "A reviewer countersigns with `ferry sign`, which appends `signatures/<key id>.sig`. That changes "
              "the bundle file's SHA-256 (and rewrites the `.sha256` file) but never the bundle id.", ""]
    lines += ["## Artifacts", "", "| Path | Kind | Format | Size (bytes) | SHA-256 | Licence | Source |",
              "|---|---|---|---|---|---|---|"]
    for a in m.artifacts:
        licence = a.model.license if a.model else "-"
        source = "-"
        if a.model and a.model.source_uri:
            source = a.model.source_uri + (f" @ {a.model.source_revision}" if a.model.source_revision else "")
        lines.append(f"| {_code(a.path)} | {a.kind} | {a.format} | {a.size:,} | {_code(a.sha256)} | "
                     f"{_code(licence)} | {_code(source)} |")
    lines += ["", "## Flags", ""]
    for fmt, label in _FLAG_FORMATS:
        hits = [a.path for a in m.artifacts if a.format == fmt]
        lines.append(f"- {label}: " + ("none" if not hits else "YES: " + ", ".join(_code(h) for h in hits)))
    if warnings:
        lines += ["", "## Warnings from packing", ""]
        lines += [f"- {_code(w)}" for w in warnings]
    sums = [f"{a.sha256}  {a.path}" for a in m.artifacts]
    lines += [
        "", "## Check it yourself", "",
        "You need `tar`, `sha256sum` (Linux) or `shasum` (macOS), and OpenSSL 3.0 or newer (the `-rawin` option "
        "used below arrived in 3.0; RHEL 9 and Ubuntu 22.04+ ship it, RHEL 8's 1.1.1 does not). The `openssl` that "
        "ships with macOS is LibreSSL, which cannot load Ed25519 keys at all; use an OpenSSL 3 build from a package "
        "manager. `<pub.pem>` is the signer's public key, obtained out of band, never from inside the bundle.", "",
        "**1. The file you have is the file that was packed.**", "",
        "```sh", f"sha256sum {bundle_file}        # macOS: shasum -a 256 {bundle_file}", "```", "",
        f"Expected: `{tar_sha256}`. After a countersignature is appended, compare with the `.sha256` file that "
        "travels with the bundle instead.", "",
        "**2. List the members, then extract them into an empty directory.** Expect only regular files "
        "(`-rw-r--r--`, owner 0/0): `manifest.json`, `signatures/*.sig` and the artifacts above. (Ferry itself "
        "never extracts bundles; it reads the members in place.)", "",
        "```sh", f"tar -tvf {bundle_file}", f"mkdir review && tar -xf {bundle_file} -C review && cd review", "```", "",
        "**3. The bundle id is the SHA-256 of `manifest.json`.**", "",
        "```sh", "sha256sum manifest.json        # macOS: shasum -a 256 manifest.json", "```", "",
        f"Expected: `{manifest_hex}`", "",
        "**4. The signature over `manifest.json`.** For each key id listed under Signatures:", "",
        "```sh",
    ]
    lines += [f"openssl pkeyutl -verify -pubin -inkey <pub.pem> -rawin -in manifest.json -sigfile signatures/{kid}.sig"
              for kid in signer_key_ids]
    lines += [
        "```", "",
        "Expected: `Signature Verified Successfully`. Then confirm `<pub.pem>` is the key with that id (the key id is "
        "the SHA-256 of the raw 32-byte public key):", "",
        "```sh",
        "openssl pkey -pubin -in <pub.pem> -outform DER | tail -c 32 | sha256sum    # macOS: ... | shasum -a 256",
        "```", "",
        "Expected: the key id, " + " or ".join(f"`{kid}`" for kid in signer_key_ids) + ".", "",
        "**5. Every artifact digest**, from inside the `review` directory:", "",
        "```sh", "sha256sum -c <<'EOF'", *sums, "EOF", "```", "",
        "On macOS:", "",
        "```sh", "shasum -a 256 -c <<'EOF'", *sums, "EOF", "```", "",
        "Expected: one `OK` line per artifact.", "",
    ]
    return "\n".join(lines)
