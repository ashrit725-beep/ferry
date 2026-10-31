"""Content-addressed artifact store: `<data_dir>/store/sha256/<64 hex>`, files 0444.

A store file's name is its SHA-256, so a file is identified by what it
contains. `verify_store` re-hashes every file to catch corruption or tampering
at rest. `digest_for_path` maps a path a backend reports (llama-server's
`model_path`) back to a digest only when that path really is a store file.

Artifact digests are bare lowercase hex, here and in the database
(`artifacts.digest`); `path_for` also accepts a `sha256:` prefix.

Imports stage artifacts in `<data_dir>/store/tmp` as `stage-*` files. An import
that is killed (OOM killer, power loss) leaves its staging files behind;
`import_lock` removes them at the start of the next import that finds no other
import running, and `verify_store` reports any it finds.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .. import audit
from ..config import Settings
from ..db import Database, write_tx
from ..formats import quote_untrusted
from ..util import ensure_private_dir, rfc3339

try:
    import fcntl
except ImportError:  # pragma: no cover - not POSIX
    fcntl = None  # type: ignore[assignment]

DIGEST = re.compile(r"[0-9a-f]{64}")
CHUNK_SIZE = 1024 * 1024
STAGING_PREFIX = "stage-"
IMPORT_LOCK = "import.lock"
"""In `<data_dir>/store`, beside sha256/ and tmp/."""
_O_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def objects_dir(settings: Settings) -> Path:
    return settings.store_dir / "sha256"


def staging_dir(settings: Settings) -> Path:
    return settings.store_dir / "tmp"


def ensure_store(settings: Settings) -> None:
    ensure_private_dir(objects_dir(settings))
    ensure_private_dir(staging_dir(settings))


def _staging_files(settings: Settings) -> list[tuple[Path, int]]:
    found: list[tuple[Path, int]] = []
    try:
        entries = list(os.scandir(staging_dir(settings)))
    except OSError:
        return found
    for entry in entries:
        if not entry.name.startswith(STAGING_PREFIX):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        found.append((Path(entry.path), st.st_size if stat.S_ISREG(st.st_mode) else 0))
    return found


def _try_lock(fd: int, flags: int) -> bool:
    try:
        fcntl.flock(fd, flags)
    except BlockingIOError:
        return False
    return True


def _open_lock(settings: Settings) -> int | None:
    """The import lock file (store/import.lock), or None where flock is unavailable."""
    if fcntl is None:
        return None
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    return os.open(settings.store_dir / IMPORT_LOCK, flags, 0o600)


@contextmanager
def import_lock(settings: Settings) -> Iterator[list[str]]:
    """Held (shared) for the whole of an import. On entry, if no other import holds
    it, staging files left by an import that was killed are removed first; the
    context value lists them. Where flock does not work (no fcntl, or a file
    system without locks) nothing is swept and imports run unlocked."""
    ensure_store(settings)
    fd = _open_lock(settings)
    swept: list[str] = []
    try:
        if fd is not None:
            try:
                if _try_lock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB):
                    for path, _ in _staging_files(settings):
                        try:
                            os.unlink(path)
                            swept.append(path.name)
                        except FileNotFoundError:
                            pass
                fcntl.flock(fd, fcntl.LOCK_SH)
            except OSError:
                pass  # ENOLCK/EOPNOTSUPP: no locking on this file system; nothing was swept
        yield swept
    finally:
        if fd is not None:
            os.close(fd)


def _import_running(settings: Settings) -> bool:
    try:
        fd = _open_lock(settings)
    except OSError:
        return False
    if fd is None:
        return False
    try:
        return not _try_lock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    finally:
        os.close(fd)


def normalize_digest(digest: str) -> str:
    """Bare lowercase hex; accepts surrounding whitespace, upper case and a 'sha256:' prefix."""
    value = digest.strip().lower().removeprefix("sha256:")
    if not DIGEST.fullmatch(value):
        raise ValueError("an artifact digest is 64 lowercase hex characters, optionally prefixed with 'sha256:'")
    return value


def path_for(settings: Settings, digest: str) -> Path:
    return objects_dir(settings) / normalize_digest(digest)


def digest_for_path(settings: Settings, path: str | Path) -> str | None:
    """The digest when `path` resolves to a regular file directly inside the store, else None.

    Relative paths are refused: a path a backend reports relative to its own
    working directory proves nothing about which file it opened.
    """
    text = str(path) if isinstance(path, (str, Path)) else ""
    if not text or "\x00" in text or len(text) > 4096 or not os.path.isabs(text):
        return None
    try:
        resolved = Path(text).resolve(strict=True)
        root = objects_dir(settings).resolve(strict=True)
        st = os.stat(resolved)
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved.parent != root or not DIGEST.fullmatch(resolved.name) or not stat.S_ISREG(st.st_mode):
        return None
    return resolved.name


def hash_file(path: Path, progress: Callable[[int], None] | None = None) -> str:
    """SHA-256 of a regular file, read without following symlinks."""
    fd = os.open(path, _O_READ)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        digest = hashlib.sha256()
        buf = bytearray(CHUNK_SIZE)
        view = memoryview(buf)
        while n := fh.readinto(view):
            digest.update(view[:n])
            if progress is not None:
                progress(n)
    return digest.hexdigest()


def verify_store(settings: Settings, *, database: Database | None = None, actor_type: str = "cli",
                 actor_id: str | None = None, progress: Callable[[int, int], None] | None = None,
                 record: bool = True) -> dict[str, Any]:
    """Re-hash every store file and compare it with its name.

    With a database (passed, or `<data_dir>/ferry.db` when it exists) the
    result is cross-checked against the `artifacts` table and recorded as one
    `store.verify` audit event.
    """
    root = objects_dir(settings)
    result: dict[str, Any] = {
        "ok": True, "store_dir": str(root), "checked": 0, "bytes_checked": 0, "mismatches": [], "missing": [],
        "untracked": [], "problems": [], "warnings": [], "leftover_staging": 0, "leftover_staging_bytes": 0, "verified_at": rfc3339(),
        "recorded": False,
    }
    files: list[tuple[str, int]] = []
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except FileNotFoundError:
        entries = []
    except OSError as exc:
        result["problems"].append(f"cannot list the store: {exc.strerror}")
        entries = []
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError as exc:
            result["problems"].append(f"store entry {quote_untrusted(entry.name)} could not be examined: {exc.strerror}")
            continue
        if not DIGEST.fullmatch(entry.name):
            result["problems"].append(f"unexpected entry {quote_untrusted(entry.name)} in the store")
        elif not stat.S_ISREG(st.st_mode):
            result["problems"].append(f"store entry {entry.name} is not a regular file")
        else:
            files.append((entry.name, st.st_size))
            if st.st_mode & 0o222:
                result["warnings"].append(f"store file {entry.name} is writable (expected mode 0444)")
    leftover = _staging_files(settings)
    result["leftover_staging"] = len(leftover)
    result["leftover_staging_bytes"] = sum(size for _, size in leftover)
    if leftover:
        if _import_running(settings):
            result["warnings"].append(f"an import is in progress: {len(leftover)} staging file(s) in"
                                      f" {staging_dir(settings)} belong to it")
        else:
            result["warnings"].append(
                f"{len(leftover)} staging file(s) ({result['leftover_staging_bytes']:,} bytes) in"
                f" {staging_dir(settings)} were left by an interrupted import; the next import removes them")

    total = sum(size for _, size in files)
    done = 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress is not None:
            progress(done, total)

    if progress is not None:
        progress(0, total)
    for name, size in files:
        try:
            actual = hash_file(root / name, advance)
        except OSError as exc:
            result["problems"].append(f"store file {name} could not be read: {exc}")
            continue
        result["checked"] += 1
        result["bytes_checked"] += size
        if actual != name:
            result["mismatches"].append({"digest": name, "actual_sha256": actual, "size": size})

    if database is None and record and settings.db_path.exists():
        database = Database(settings.db_path)
    if database is not None:
        present = {name for name, _ in files}
        with database.session() as conn:
            known = {row["digest"] for row in conn.execute("SELECT digest FROM artifacts")}
            result["missing"] = sorted(known - present)
            result["untracked"] = sorted(present - known)
            for digest in result["untracked"]:
                result["warnings"].append(f"store file {digest} is not part of any imported bundle: an import"
                                          " that failed left it, or one still running has not registered it yet")
            result["ok"] = not (result["mismatches"] or result["missing"] or result["problems"])
            if record:
                with write_tx(conn):
                    audit.append_event(
                        conn, actor_type=actor_type, actor_id=actor_id or getpass.getuser(), action="store.verify",
                        resource="store", outcome="success" if result["ok"] else "failure",
                        details={"checked": result["checked"], "bytes_checked": result["bytes_checked"],
                                 "mismatched_digests": [m["digest"] for m in result["mismatches"]],
                                 "missing_digests": result["missing"], "problem_count": len(result["problems"])},
                    )
                result["recorded"] = True
    result["ok"] = not (result["mismatches"] or result["missing"] or result["problems"])
    return result
