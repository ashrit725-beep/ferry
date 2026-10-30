"""Trust store: which public keys may sign bundles, in which roles, and when.

A directory of `<key_id>.json` files on the receiving host. Changes are
host-only (CLI); the web API may list the store but never changes it, and the
caller (CLI) records the `trust.add` / `trust.revoke` audit events.

Loading fails closed. An entry is ignored, and reported in `problems`, when its
file name, its `key_id` and the id computed from its PEM disagree, when it does
not parse or has unknown keys, when it is a symlink or not a regular file, or
when it (or the directory) is writable by group or others, since anyone who
can write the store can make Ferry trust any key.

Key status at a time `now`: revoked > not_yet_valid > expired > active. A
revoked key's signatures never count, whatever time they claim: a manifest's
`created_at` is chosen by the signer and proves nothing about when it signed.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto
from .config import SIGNER_ROLES
from .errors import Conflict, CryptoError, FerryError, NotFound, ValidationFailed
from .formats import has_unsafe_text, quote_untrusted, strict_json_loads
from .manifest import RFC3339
from .util import atomic_write, parse_rfc3339, rfc3339, utc_now

STATUSES = ("active", "revoked", "expired", "not_yet_valid")
MAX_ENTRY_BYTES = 64 * 1024
MIN_FINGERPRINT_HEX = 16
MIN_PREFIX_HEX = 8
MAX_NAME_CHARS = 128
MAX_COMMENT_CHARS = 1000
MAX_REASON_CHARS = 500

_REQUIRED = frozenset({"key_id", "name", "roles", "public_key_pem"})
_OPTIONAL = frozenset({"not_before", "not_after", "revoked_at", "revocation_reason", "added_at", "comment"})
_O_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


@dataclass(frozen=True)
class TrustEntry:
    key_id: str
    name: str
    roles: tuple[str, ...]
    public_key_pem: str
    not_before: str | None = None
    not_after: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    added_at: str | None = None
    comment: str = ""
    public_key: Ed25519PublicKey | None = field(default=None, repr=False, compare=False)

    def status(self, now: _dt.datetime | None = None) -> str:
        now = now or utc_now()
        if self.revoked_at is not None:
            return "revoked"
        if self.not_before is not None and now < parse_rfc3339(self.not_before):
            return "not_yet_valid"
        if self.not_after is not None and now > parse_rfc3339(self.not_after):
            return "expired"
        return "active"

    def file_dict(self) -> dict[str, Any]:
        """The on-disk form."""
        return {
            "key_id": self.key_id, "name": self.name, "roles": list(self.roles),
            "public_key_pem": self.public_key_pem, "not_before": self.not_before, "not_after": self.not_after,
            "revoked_at": self.revoked_at, "revocation_reason": self.revocation_reason,
            "added_at": self.added_at, "comment": self.comment,
        }

    def to_dict(self, now: _dt.datetime | None = None) -> dict[str, Any]:
        out = self.file_dict()
        out["status"] = self.status(now)
        return out


@dataclass
class TrustStore:
    path: Path | None
    entries: list[TrustEntry]
    problems: list[str]
    # key id (from the file name) -> why its entry is not trusted
    ignored: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.entries = sorted(self.entries, key=lambda e: (e.name.lower(), e.key_id))
        self._by_id = {e.key_id: e for e in self.entries}

    @classmethod
    def empty(cls) -> TrustStore:
        return cls(None, [], [])

    def get(self, key_id: str) -> TrustEntry | None:
        return self._by_id.get(key_id)

    def find(self, key_id_or_prefix: str) -> TrustEntry:
        """Exact key id, or a unique prefix of at least 8 hex characters."""
        wanted = key_id_or_prefix.strip().lower()
        if crypto.KEY_ID.fullmatch(wanted):
            entry = self.get(wanted)
            if entry is None:
                raise NotFound(f"no trusted key has id {wanted}", details={"problems": self.problems})
            return entry
        if not re.fullmatch(rf"[0-9a-f]{{{MIN_PREFIX_HEX},63}}", wanted):
            raise ValidationFailed(f"a key id prefix must be {MIN_PREFIX_HEX} to 64 lowercase hex characters")
        matches = [e for e in self.entries if e.key_id.startswith(wanted)]
        if not matches:
            raise NotFound(f"no trusted key id starts with {wanted}", details={"problems": self.problems})
        if len(matches) > 1:
            raise Conflict(f"key id prefix {wanted} is ambiguous; it matches "
                           + ", ".join(crypto.short_id(e.key_id) for e in matches))
        return matches[0]

    def to_dict(self, now: _dt.datetime | None = None) -> dict[str, Any]:
        return {"trust_dir": str(self.path) if self.path else None,
                "items": [e.to_dict(now) for e in self.entries], "problems": list(self.problems)}


class _Skip(Exception):
    """Why one trust entry is ignored."""


def _optional_timestamp(doc: dict[str, Any], key: str) -> str | None:
    value = doc.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        raise _Skip(f"{key} must be an RFC 3339 timestamp or null")
    try:
        parse_rfc3339(value)
    except ValueError:
        raise _Skip(f"{key} is not a valid date and time") from None
    return value


def _entry_from_doc(stem: str, doc: Any) -> TrustEntry:
    if not isinstance(doc, dict):
        raise _Skip("not a JSON object")
    unknown = sorted(set(doc) - _REQUIRED - _OPTIONAL)
    if unknown:
        raise _Skip(f"unknown key(s) {', '.join(quote_untrusted(k) for k in unknown)}")
    missing = sorted(_REQUIRED - set(doc))
    if missing:
        raise _Skip(f"missing {', '.join(missing)}")
    pem = doc["public_key_pem"]
    if not isinstance(pem, str):
        raise _Skip("public_key_pem must be a string")
    try:
        public_key = crypto.load_public_key_pem(pem.encode("utf-8"))
    except CryptoError:
        raise _Skip("public_key_pem is not an Ed25519 public key") from None
    computed = crypto.key_id(public_key)
    declared = doc["key_id"]
    if declared != computed or stem != computed:
        shown = crypto.short_id(declared) if isinstance(declared, str) else "?"
        raise _Skip(f"file name ({crypto.short_id(stem)}…), key_id ({shown}…) and the id computed from "
                    f"public_key_pem ({crypto.short_id(computed)}…) do not all agree")
    name = doc["name"]
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_CHARS or has_unsafe_text(name):
        raise _Skip(f"name must be 1 to {MAX_NAME_CHARS} printable characters")
    roles = doc["roles"]
    if (not isinstance(roles, list) or not roles or len(set(map(str, roles))) != len(roles)
            or not all(isinstance(r, str) and r in SIGNER_ROLES for r in roles)):
        raise _Skip(f"roles must be a non-empty list of distinct roles from: {', '.join(SIGNER_ROLES)}")
    reason = doc.get("revocation_reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > MAX_REASON_CHARS or has_unsafe_text(reason)):
        raise _Skip("revocation_reason must be printable text or null")
    comment = doc.get("comment", "")
    if comment is None:
        comment = ""
    if not isinstance(comment, str) or len(comment) > MAX_COMMENT_CHARS or has_unsafe_text(comment, multiline=True):
        raise _Skip("comment must be printable text")
    return TrustEntry(
        key_id=computed, name=name, roles=tuple(roles), public_key_pem=pem,
        not_before=_optional_timestamp(doc, "not_before"), not_after=_optional_timestamp(doc, "not_after"),
        revoked_at=_optional_timestamp(doc, "revoked_at"), revocation_reason=reason,
        added_at=_optional_timestamp(doc, "added_at"), comment=comment, public_key=public_key,
    )


def _read_entry(directory: Path, name: str) -> TrustEntry:
    stem = name[: -len(".json")]
    if not crypto.KEY_ID.fullmatch(stem):
        raise _Skip("file name is not <64 lowercase hex key id>.json")
    try:
        fd = os.open(directory / name, _O_READ)
    except OSError as exc:
        raise _Skip(f"cannot be opened ({exc.strerror}); symbolic links are not followed") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Skip("not a regular file")
        if st.st_mode & 0o022:
            raise _Skip("writable by group or others")
        if st.st_size > MAX_ENTRY_BYTES:
            raise _Skip("larger than 64 KiB")
        data = os.read(fd, MAX_ENTRY_BYTES + 1)
    finally:
        os.close(fd)
    try:
        doc = strict_json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Skip("not valid JSON") from None
    return _entry_from_doc(stem, doc)


def load_trust_store(directory: str | Path) -> TrustStore:
    """Load every valid entry; everything else is reported in `problems` and not trusted."""
    path = Path(directory)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return TrustStore(path, [], [f"trust directory {path} does not exist; no keys are trusted"])
    except OSError as exc:
        return TrustStore(path, [], [f"cannot read trust directory {path}: {exc.strerror}; no keys are trusted"])
    if not stat.S_ISDIR(st.st_mode):
        return TrustStore(path, [], [f"trust directory {path} is not a directory (symbolic links are not followed); "
                                     "no keys are trusted"])
    if st.st_mode & 0o022:
        return TrustStore(path, [], [f"trust directory {path} is writable by group or others; no keys are trusted "
                                     f"until that is fixed (chmod go-w {path})"])
    entries: list[TrustEntry] = []
    problems: list[str] = []
    ignored: dict[str, str] = {}
    try:
        names = sorted(e.name for e in os.scandir(path))
    except OSError as exc:
        return TrustStore(path, [], [f"cannot list trust directory {path}: {exc.strerror}; no keys are trusted"])
    for name in names:
        if name.startswith("."):
            continue
        if not name.endswith(".json"):
            problems.append(f"unexpected file {quote_untrusted(name)} in the trust directory (ignored)")
            continue
        try:
            entries.append(_read_entry(path, name))
        except _Skip as exc:
            problems.append(f"trust entry {quote_untrusted(name)} ignored: {exc}")
            stem = name[: -len(".json")]
            if crypto.KEY_ID.fullmatch(stem):
                ignored[stem] = str(exc)
    return TrustStore(path, entries, problems, ignored)


def _timestamp_arg(value: str | _dt.datetime | None, what: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise ValidationFailed(f"{what} needs a timezone")
        return rfc3339(value)
    if isinstance(value, str) and RFC3339.fullmatch(value.strip()):
        try:
            return rfc3339(parse_rfc3339(value.strip()))
        except ValueError:
            pass
    raise ValidationFailed(f"{what} must be an RFC 3339 timestamp such as 2027-10-28T00:00:00Z")


def _write_entry(directory: Path, entry: TrustEntry) -> None:
    data = (json.dumps(entry.file_dict(), indent=2, ensure_ascii=True) + "\n").encode("ascii")
    atomic_write(directory / f"{entry.key_id}.json", data, mode=0o644)


def add_key(directory: str | Path, pem_bytes: bytes, *, name: str, roles: list[str] | tuple[str, ...],
            not_before: str | _dt.datetime | None = None, not_after: str | _dt.datetime | None = None,
            comment: str = "", expect_fingerprint: str | None = None) -> TrustEntry:
    """Trust a public key in the given roles. Refuses duplicates (including revoked or
    ignored entries for the same key). `expect_fingerprint`, when given, must be a
    prefix of at least 16 hex characters of the key id, as read out of band."""
    path = Path(directory)
    public_key = crypto.load_public_key_pem(bytes(pem_bytes))
    kid = crypto.key_id(public_key)
    if expect_fingerprint is not None:
        fingerprint = re.sub(r"[\s:]", "", expect_fingerprint).lower().removeprefix("sha256")
        if not re.fullmatch(rf"[0-9a-f]{{{MIN_FINGERPRINT_HEX},64}}", fingerprint):
            raise ValidationFailed(f"the expected fingerprint must be at least {MIN_FINGERPRINT_HEX} hex characters of the key id")
        if not kid.startswith(fingerprint):
            raise CryptoError(f"fingerprint mismatch: this key's id is {kid}, which does not start with {fingerprint}; "
                              "refusing to trust it", code="fingerprint_mismatch")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_CHARS or has_unsafe_text(name):
        raise ValidationFailed(f"name must be 1 to {MAX_NAME_CHARS} printable characters")
    role_list = list(roles)
    if not role_list or len(set(role_list)) != len(role_list) or not all(r in SIGNER_ROLES for r in role_list):
        raise ValidationFailed(f"roles must be one or more distinct roles from: {', '.join(SIGNER_ROLES)}")
    start, end = _timestamp_arg(not_before, "not_before"), _timestamp_arg(not_after, "not_after")
    if start and end and parse_rfc3339(start) >= parse_rfc3339(end):
        raise ValidationFailed("not_before must be earlier than not_after")
    if not isinstance(comment, str) or len(comment) > MAX_COMMENT_CHARS or has_unsafe_text(comment, multiline=True):
        raise ValidationFailed(f"comment must be printable text of at most {MAX_COMMENT_CHARS} characters")

    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir():
            raise FerryError(f"trust directory {path} is not a directory", code="trust_dir_invalid")
    else:
        path.mkdir(parents=True)
        os.chmod(path, 0o755)
    target = path / f"{kid}.json"
    if os.path.lexists(target):
        raise Conflict(f"key {kid} is already in the trust store; refusing to add it again "
                       "(a revoked key cannot be re-added)")
    entry = TrustEntry(
        key_id=kid, name=name.strip(), roles=tuple(role_list),
        public_key_pem=crypto.public_key_to_pem(public_key).decode("ascii"),
        not_before=start, not_after=end, added_at=rfc3339(), comment=comment, public_key=public_key,
    )
    _write_entry(path, entry)
    return entry


def revoke_key(directory: str | Path, key_id_or_prefix: str, reason: str,
               *, now: _dt.datetime | None = None) -> TrustEntry:
    """Mark a trusted key revoked. Its signatures stop counting immediately."""
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON_CHARS or has_unsafe_text(reason):
        raise ValidationFailed(f"a revocation reason of 1 to {MAX_REASON_CHARS} printable characters is required")
    path = Path(directory)
    store = load_trust_store(path)
    entry = store.find(key_id_or_prefix)
    if entry.revoked_at is not None:
        raise Conflict(f"key {entry.key_id} was already revoked at {entry.revoked_at}")
    revoked = dataclasses.replace(entry, revoked_at=rfc3339(now), revocation_reason=reason.strip())
    _write_entry(path, revoked)
    return revoked
