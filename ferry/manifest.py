"""Bundle manifest v1 (`ferry.dev/bundle-manifest/v1`): strict parsing, validation, construction.

The manifest is the document signers attest to, so parsing is strict enough
that two readers can never interpret the same signed bytes differently:
duplicate JSON keys, NaN, a byte order mark, unknown keys and non-UTF-8 input
are errors. Free-text fields may not contain control, zero-width or bidi
characters, so a manifest cannot carry terminal escape sequences or reordered
text into the review sheet, the console or CLI output.

Artifact `metadata` is informational only. The verifier recomputes it from
the file content and never uses the declared values for a decision.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .config import ARTIFACT_KINDS, ImportSettings
from .errors import ValidationFailed
from .formats import FORMATS, has_unsafe_text, quote_untrusted, strict_json_loads
from .util import parse_rfc3339, sha256_hex

SCHEMA = "ferry.dev/bundle-manifest/v1"
MIN_FERRY_VERSION = "0.1.0"

# All patterns are used with fullmatch (a "$" anchor would accept a trailing newline).
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
ARTIFACT_PATH = re.compile(r"artifacts/[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*")
MAX_PATH_CHARS = 255
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}")  # the grammar config.py uses for allowed_licenses
FERRY_VERSION = re.compile(r"[0-9]+(\.[0-9]+){0,2}")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")
MAX_DESCRIPTION_CHARS = 2000
MAX_ERRORS = 50

_TOP = {"schema", "bundle", "producer", "requires", "artifacts"}
_BUNDLE_REQUIRED, _BUNDLE_OPTIONAL = {"name", "version", "created_at"}, {"description"}
_PRODUCER = {"tool", "tool_version"}
_REQUIRES_REQUIRED = {"ferry_min_version"}
_REQUIRES_OPTIONAL = {"runtime", "runtime_min_version", "min_memory_bytes"}
_ARTIFACT_REQUIRED, _ARTIFACT_OPTIONAL = {"path", "size", "sha256", "kind", "format"}, {"model", "metadata"}
_MODEL_REQUIRED = {"name", "license"}
_MODEL_OPTIONAL = {"source_uri", "source_revision", "upstream_sha256"}


class ManifestError(ValidationFailed):
    code = "manifest_invalid"

    def __init__(self, errors: list[str]):
        shown = "; ".join(errors[:5]) + (f" (and {len(errors) - 5} more)" if len(errors) > 5 else "")
        super().__init__(f"invalid manifest: {shown}", details={"errors": list(errors)})
        self.errors = list(errors)


@dataclass(frozen=True)
class ModelInfo:
    name: str
    license: str
    source_uri: str | None = None
    source_revision: str | None = None
    upstream_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "license": self.license, "source_uri": self.source_uri,
                "source_revision": self.source_revision, "upstream_sha256": self.upstream_sha256}


@dataclass(frozen=True)
class ArtifactEntry:
    path: str
    size: int
    sha256: str
    kind: str
    format: str
    model: ModelInfo | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path, "size": self.size, "sha256": self.sha256,
                               "kind": self.kind, "format": self.format}
        if self.model is not None:
            out["model"] = self.model.to_dict()
        out["metadata"] = self.metadata
        return out


@dataclass(frozen=True)
class Manifest:
    """A validated manifest plus the exact bytes it was parsed from (what was signed)."""

    raw: bytes = field(repr=False)
    doc: dict[str, Any] = field(repr=False)
    name: str
    version: str
    created_at: str
    description: str
    ferry_min_version: str
    runtime: str | None
    runtime_min_version: str | None
    min_memory_bytes: int | None
    artifacts: tuple[ArtifactEntry, ...]

    @property
    def bundle_id(self) -> str:
        return bundle_id_for(self.raw)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.doc))


def bundle_id_for(raw: bytes) -> str:
    """Bundle identity: SHA-256 of the exact manifest.json bytes (unchanged by countersigning)."""
    return "sha256:" + sha256_hex(raw)


def parse_ferry_version(value: str) -> tuple[int, int, int]:
    """Leading dotted-numeric part of a version, padded to three parts ('0.2' -> (0, 2, 0))."""
    parts: list[int] = []
    for piece in value.split(".")[:3]:
        digits = re.match(r"[0-9]+", piece)
        if not digits:
            break
        parts.append(int(digits.group()))
        if digits.end() != len(piece):
            break
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def ferry_version_satisfied(required: str, installed: str = __version__) -> bool:
    return parse_ferry_version(installed) >= parse_ferry_version(required)


def decode_manifest_json(raw: bytes) -> Any:
    """Strict JSON decoding of manifest bytes; raises ManifestError."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ManifestError(["manifest.json is not valid UTF-8"]) from None
    if text.startswith("﻿"):
        raise ManifestError(["manifest.json starts with a byte order mark"])
    try:
        return strict_json_loads(text)
    except RecursionError:
        raise ManifestError(["manifest.json is nested too deeply"]) from None
    except ValueError as exc:
        raise ManifestError([f"manifest.json is not valid JSON: {exc}"]) from None


class _Errors:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, message: str) -> None:
        if len(self.items) < MAX_ERRORS:
            self.items.append(f"{path}: {message}" if path else message)

    def keys(self, path: str, obj: Any, required: set[str], optional: frozenset[str] | set[str] = frozenset()) -> bool:
        if not isinstance(obj, dict):
            self.add(path, "must be an object")
            return False
        for key in sorted(required - set(obj)):
            self.add(path, f"missing required key {key!r}")
        for key in sorted(set(obj) - required - optional):
            self.add(path, f"unknown key {quote_untrusted(key)}")
        return True

    def text(self, path: str, value: Any, max_chars: int, *, nullable: bool = False, multiline: bool = False) -> None:
        if value is None and nullable:
            return
        if not isinstance(value, str):
            self.add(path, "must be a string" + (" or null" if nullable else ""))
        elif len(value) > max_chars:
            self.add(path, f"must be at most {max_chars} characters")
        elif has_unsafe_text(value, multiline=multiline):
            self.add(path, "contains control, zero-width or bidirectional-override characters")

    def pattern(self, path: str, value: Any, regex: re.Pattern[str], what: str, *, nullable: bool = False) -> bool:
        if value is None and nullable:
            return True
        if isinstance(value, str) and regex.fullmatch(value):
            return True
        shown = quote_untrusted(value) if isinstance(value, str) else type(value).__name__
        self.add(path, f"{shown} is not {what}")
        return False

    def integer(self, path: str, value: Any, low: int, high: int | None, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if not isinstance(value, int) or isinstance(value, bool):
            self.add(path, "must be an integer" + (" or null" if nullable else ""))
        elif value < low or (high is not None and value > high):
            self.add(path, f"must be between {low} and {high}" if high is not None else f"must be at least {low}")


def _check_timestamp(v: _Errors, path: str, value: Any) -> None:
    if not v.pattern(path, value, RFC3339, "an RFC 3339 timestamp with a timezone"):
        return
    try:
        parse_rfc3339(value)
    except ValueError:
        v.add(path, f"{quote_untrusted(value)} is not a valid date and time")


def validate_manifest(doc: Any, limits: ImportSettings | None = None) -> list[str]:
    """All schema errors in `doc` (empty list = valid). Limits default to the default import policy."""
    limits = limits or ImportSettings()
    v = _Errors()
    if not v.keys("", doc, _TOP):
        return v.items
    if "schema" in doc and doc["schema"] != SCHEMA:
        v.add("schema", f"must be {SCHEMA!r}")

    bundle = doc.get("bundle")
    if "bundle" in doc and v.keys("bundle", bundle, _BUNDLE_REQUIRED, _BUNDLE_OPTIONAL):
        if "name" in bundle:
            v.pattern("bundle.name", bundle["name"], NAME, "a valid bundle name (lowercase letters, digits, '.', '_', '-'; max 64)")
        if "version" in bundle:
            v.pattern("bundle.version", bundle["version"], VERSION, "a valid version (letters, digits, '.', '+', '_', '-'; max 64)")
        if "created_at" in bundle:
            _check_timestamp(v, "bundle.created_at", bundle["created_at"])
        if "description" in bundle:
            v.text("bundle.description", bundle["description"], MAX_DESCRIPTION_CHARS, multiline=True)

    producer = doc.get("producer")
    if "producer" in doc and v.keys("producer", producer, _PRODUCER):
        for key in sorted(_PRODUCER & set(producer)):
            v.text(f"producer.{key}", producer[key], 64)

    requires = doc.get("requires")
    if "requires" in doc and v.keys("requires", requires, _REQUIRES_REQUIRED, _REQUIRES_OPTIONAL):
        if "ferry_min_version" in requires:
            v.pattern("requires.ferry_min_version", requires["ferry_min_version"], FERRY_VERSION,
                      "a dotted numeric version such as 0.1.0")
        for key in ("runtime", "runtime_min_version"):
            if key in requires:
                v.text(f"requires.{key}", requires[key], 64, nullable=True)
        if "min_memory_bytes" in requires:
            v.integer("requires.min_memory_bytes", requires["min_memory_bytes"], 0, None, nullable=True)

    if "artifacts" in doc:
        _validate_artifacts(v, doc["artifacts"], limits)
    return v.items


def _validate_artifacts(v: _Errors, artifacts: Any, limits: ImportSettings) -> None:
    if not isinstance(artifacts, list):
        v.add("artifacts", "must be a list")
        return
    if not 1 <= len(artifacts) <= limits.max_artifacts:
        v.add("artifacts", f"must list between 1 and {limits.max_artifacts} artifacts (found {len(artifacts)})")
        if len(artifacts) > limits.max_artifacts:
            return
    seen: dict[str, int] = {}
    folded: dict[str, int] = {}
    for i, art in enumerate(artifacts):
        where = f"artifacts[{i}]"
        if not v.keys(where, art, _ARTIFACT_REQUIRED, _ARTIFACT_OPTIONAL):
            continue
        path = art.get("path")
        if "path" in art and v.pattern(f"{where}.path", path, ARTIFACT_PATH, "a valid artifact path under artifacts/"):
            if len(path) > MAX_PATH_CHARS:
                v.add(f"{where}.path", f"must be at most {MAX_PATH_CHARS} characters")
            if path in seen:
                v.add(f"{where}.path", f"duplicates artifacts[{seen[path]}].path")
            elif path.lower() in folded:
                v.add(f"{where}.path", f"differs only in letter case from artifacts[{folded[path.lower()]}].path")
            seen.setdefault(path, i)
            folded.setdefault(path.lower(), i)
        if "size" in art:
            v.integer(f"{where}.size", art["size"], 0, limits.max_artifact_bytes)
        if "sha256" in art:
            v.pattern(f"{where}.sha256", art["sha256"], SHA256_HEX, "64 lowercase hex characters")
        kind = art.get("kind")
        if "kind" in art and kind not in ARTIFACT_KINDS:
            v.add(f"{where}.kind", f"must be one of {', '.join(ARTIFACT_KINDS)}")
        if "format" in art and art["format"] not in FORMATS:
            v.add(f"{where}.format", f"must be one of {', '.join(FORMATS)}")
        if kind == "model" and "model" not in art:
            v.add(where, "a model artifact needs a 'model' object")
        elif kind in ARTIFACT_KINDS and kind != "model" and "model" in art:
            v.add(f"{where}.model", "is only allowed when kind is 'model'")
        if "model" in art and kind == "model":
            _validate_model(v, f"{where}.model", art["model"])
        if "metadata" in art and not isinstance(art["metadata"], dict):
            v.add(f"{where}.metadata", "must be an object")


def _validate_model(v: _Errors, where: str, model: Any) -> None:
    if not v.keys(where, model, _MODEL_REQUIRED, _MODEL_OPTIONAL):
        return
    if "name" in model:
        v.pattern(f"{where}.name", model["name"], MODEL_NAME, "a valid model name")
    if "license" in model:
        v.pattern(f"{where}.license", model["license"], LICENSE_ID, "an SPDX-style licence identifier")
    if "source_uri" in model:
        v.text(f"{where}.source_uri", model["source_uri"], 2048, nullable=True)
    if "source_revision" in model:
        v.text(f"{where}.source_revision", model["source_revision"], 128, nullable=True)
    if "upstream_sha256" in model:
        v.pattern(f"{where}.upstream_sha256", model["upstream_sha256"], SHA256_HEX,
                  "64 lowercase hex characters", nullable=True)


def _manifest_from_doc(raw: bytes, doc: dict[str, Any]) -> Manifest:
    entries = []
    for art in doc["artifacts"]:
        model = art.get("model")
        entries.append(ArtifactEntry(
            path=art["path"], size=art["size"], sha256=art["sha256"], kind=art["kind"], format=art["format"],
            model=None if model is None else ModelInfo(
                name=model["name"], license=model["license"], source_uri=model.get("source_uri"),
                source_revision=model.get("source_revision"), upstream_sha256=model.get("upstream_sha256")),
            metadata=dict(art.get("metadata") or {}),
        ))
    bundle, requires = doc["bundle"], doc["requires"]
    return Manifest(
        raw=raw, doc=doc, name=bundle["name"], version=bundle["version"], created_at=bundle["created_at"],
        description=bundle.get("description", ""), ferry_min_version=requires["ferry_min_version"],
        runtime=requires.get("runtime"), runtime_min_version=requires.get("runtime_min_version"),
        min_memory_bytes=requires.get("min_memory_bytes"), artifacts=tuple(entries),
    )


def parse_manifest(raw: bytes, limits: ImportSettings | None = None) -> Manifest:
    """Decode and validate manifest bytes. Raises ManifestError listing every problem found."""
    doc = decode_manifest_json(raw)
    errors = validate_manifest(doc, limits)
    if errors:
        raise ManifestError(errors)
    return _manifest_from_doc(raw, doc)


def build_manifest(*, name: str, version: str, created_at: str, description: str = "",
                   requires: dict[str, Any] | None = None, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble a manifest document in canonical key order. Validate it with dump_manifest."""
    requires = requires or {}
    entries = []
    for art in artifacts:
        entry: dict[str, Any] = {"path": art["path"], "size": art["size"], "sha256": art["sha256"],
                                 "kind": art["kind"], "format": art["format"]}
        model = art.get("model")
        if model is not None:
            entry["model"] = {"name": model["name"], "license": model["license"],
                              "source_uri": model.get("source_uri"), "source_revision": model.get("source_revision"),
                              "upstream_sha256": model.get("upstream_sha256")}
        entry["metadata"] = art.get("metadata") or {}
        entries.append(entry)
    return {
        "schema": SCHEMA,
        "bundle": {"name": name, "version": version, "created_at": created_at, "description": description},
        "producer": {"tool": "ferry", "tool_version": __version__},
        "requires": {
            "ferry_min_version": requires.get("ferry_min_version", MIN_FERRY_VERSION),
            "runtime": requires.get("runtime"),
            "runtime_min_version": requires.get("runtime_min_version"),
            "min_memory_bytes": requires.get("min_memory_bytes"),
        },
        "artifacts": entries,
    }


def dump_manifest(doc: dict[str, Any], limits: ImportSettings | None = None) -> bytes:
    """Validated, deterministic manifest bytes: two-space indented ASCII JSON plus a newline."""
    errors = validate_manifest(doc, limits)
    if errors:
        raise ManifestError(errors)
    return (json.dumps(doc, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
