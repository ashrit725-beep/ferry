"""Small helpers shared across Ferry: time, hashing, canonical JSON, files."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def rfc3339(ts: _dt.datetime | None = None) -> str:
    """Format as UTC RFC 3339 with millisecond precision, e.g. 2026-10-28T01:53:00.000Z."""
    ts = ts or utc_now()
    if ts.tzinfo is None:
        raise ValueError("naive datetime; attach a timezone")
    return ts.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_rfc3339(value: str) -> _dt.datetime:
    """Parse an RFC 3339 timestamp; a timezone is required."""
    v = value.strip()
    if v[-1:] in ("Z", "z"):
        v = v[:-1] + "+00:00"
    ts = _dt.datetime.fromisoformat(v)
    if ts.tzinfo is None:
        raise ValueError(f"timestamp without timezone: {value!r}")
    return ts.astimezone(_dt.timezone.utc)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, ASCII only, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_event_id() -> str:
    return uuid.uuid4().hex


def ensure_private_dir(path: Path) -> Path:
    """Create a directory (and parents) readable only by the owner."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory, fsync, then rename into place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
