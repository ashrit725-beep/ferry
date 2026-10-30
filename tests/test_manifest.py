"""Manifest v1: strict decoding, validation of every field rule, deterministic dumping."""

from __future__ import annotations

import copy
import json
from typing import Any, Callable

import pytest

from ferry.config import ImportSettings
from ferry.manifest import (
    SCHEMA, ManifestError, build_manifest, bundle_id_for, decode_manifest_json, dump_manifest,
    ferry_version_satisfied, parse_ferry_version, parse_manifest, validate_manifest,
)
from ferry.util import sha256_hex

GGUF_SHA = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"


def spec_example() -> dict[str, Any]:
    """The example from docs/design/v1-spec.md section 4, with real values in place of '...'."""
    return {
        "schema": SCHEMA,
        "bundle": {"name": "qwen2.5-0.5b-instruct", "version": "1.0.0", "created_at": "2026-10-28T02:00:00.000Z",
                   "description": "Qwen2.5 0.5B Instruct, Q4_K_M GGUF, for llama.cpp"},
        "producer": {"tool": "ferry", "tool_version": "0.1.0"},
        "requires": {"ferry_min_version": "0.1.0", "runtime": "llama.cpp", "runtime_min_version": None,
                     "min_memory_bytes": 1073741824},
        "artifacts": [
            {"path": "artifacts/models/qwen2.5-0.5b-instruct-q4_k_m.gguf", "size": 491400032, "sha256": GGUF_SHA,
             "kind": "model", "format": "gguf",
             "model": {"name": "qwen2.5-0.5b-instruct", "license": "Apache-2.0",
                       "source_uri": "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF",
                       "source_revision": "9217f5db79a29953eb74d5343926648285ec7e67", "upstream_sha256": GGUF_SHA},
             "metadata": {"gguf": {"version": 3, "architecture": "qwen2"}}},
            {"path": "artifacts/docs/LICENSE", "size": 11343, "sha256": "ab" * 32, "kind": "document",
             "format": "text", "metadata": {}},
        ],
    }


def raw(doc: Any) -> bytes:
    return json.dumps(doc).encode("utf-8")


def test_spec_example_is_valid():
    manifest = parse_manifest(raw(spec_example()))
    assert manifest.name == "qwen2.5-0.5b-instruct" and manifest.version == "1.0.0"
    assert manifest.min_memory_bytes == 1073741824 and manifest.runtime == "llama.cpp"
    model = manifest.artifacts[0]
    assert model.kind == "model" and model.model is not None and model.model.license == "Apache-2.0"
    assert manifest.artifacts[1].model is None


def test_bundle_id_is_sha256_of_the_exact_bytes():
    data = raw(spec_example())
    assert parse_manifest(data).bundle_id == "sha256:" + sha256_hex(data)
    assert bundle_id_for(data + b" ") != bundle_id_for(data)


def test_build_and_dump_are_deterministic_and_round_trip():
    kwargs = dict(name="tiny", version="1.0.0", created_at="2026-10-28T02:00:00.000Z", description="d",
                  requires={"runtime": "llama.cpp"},
                  artifacts=[{"path": "artifacts/a.txt", "size": 3, "sha256": "00" * 32, "kind": "document",
                              "format": "text"}])
    first = dump_manifest(build_manifest(**kwargs))
    assert first == dump_manifest(build_manifest(**kwargs))
    assert first.endswith(b"\n") and first.isascii()
    doc = parse_manifest(first).to_dict()
    assert doc["requires"] == {"ferry_min_version": "0.1.0", "runtime": "llama.cpp", "runtime_min_version": None,
                               "min_memory_bytes": None}
    assert doc["producer"]["tool"] == "ferry"


def test_dump_refuses_an_invalid_document():
    doc = spec_example()
    doc["bundle"]["name"] = "Not Valid"
    with pytest.raises(ManifestError):
        dump_manifest(doc)


def mutate(fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    doc = copy.deepcopy(spec_example())
    fn(doc)
    return doc


def _set(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def apply(doc: dict[str, Any]) -> None:
        node: Any = doc
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[int(part)] if part.isdigit() else node[part]
        last = parts[-1]
        if value is _DELETE:
            del node[int(last) if last.isdigit() else last]
        else:
            node[int(last) if last.isdigit() else last] = value
    return apply


_DELETE = object()


@pytest.mark.parametrize("change, expected", [
    (_set("extra", 1), "unknown key \"extra\""),
    (_set("bundle.extra", 1), "bundle: unknown key"),
    (_set("producer.extra", 1), "producer: unknown key"),
    (_set("requires.extra", 1), "requires: unknown key"),
    (_set("artifacts.0.extra", 1), "artifacts[0]: unknown key"),
    (_set("artifacts.0.model.extra", 1), "artifacts[0].model: unknown key"),
    (_set("schema", _DELETE), "missing required key 'schema'"),
    (_set("schema", "ferry.dev/bundle-manifest/v2"), "schema: must be"),
    (_set("producer", _DELETE), "missing required key 'producer'"),
    (_set("bundle.name", "Qwen"), "bundle.name"),
    (_set("bundle.name", ".hidden"), "bundle.name"),
    (_set("bundle.name", "a" * 65), "bundle.name"),
    (_set("bundle.name", "tiny\n"), "bundle.name"),
    (_set("bundle.version", "1.0 beta"), "bundle.version"),
    (_set("bundle.version", "-1"), "bundle.version"),
    (_set("bundle.created_at", "2026-10-28T02:00:00"), "bundle.created_at"),
    (_set("bundle.created_at", "20261028T020000Z"), "bundle.created_at"),
    (_set("bundle.created_at", "2026-13-01T00:00:00Z"), "not a valid date and time"),
    (_set("bundle.created_at", 1793239200), "bundle.created_at"),
    (_set("bundle.description", "x" * 2001), "at most 2000 characters"),
    (_set("bundle.description", "evil \x1b[31m red"), "control, zero-width or bidirectional"),
    (_set("bundle.description", "reversed ‮ txt"), "control, zero-width or bidirectional"),
    (_set("producer.tool", 7), "producer.tool: must be a string"),
    (_set("requires.ferry_min_version", "1.2.3.4"), "requires.ferry_min_version"),
    (_set("requires.ferry_min_version", "v1"), "requires.ferry_min_version"),
    (_set("requires.ferry_min_version", "١.0"), "requires.ferry_min_version"),
    (_set("requires.ferry_min_version", _DELETE), "missing required key 'ferry_min_version'"),
    (_set("requires.runtime", 3), "requires.runtime"),
    (_set("requires.runtime", "x" * 65), "requires.runtime"),
    (_set("requires.min_memory_bytes", -1), "requires.min_memory_bytes"),
    (_set("requires.min_memory_bytes", True), "requires.min_memory_bytes"),
    (_set("artifacts", []), "between 1 and"),
    (_set("artifacts", {}), "artifacts: must be a list"),
    (_set("artifacts.0.path", "models/x.gguf"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/../x"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/.hidden"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/a//b"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/a\\b"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/a b"), "artifacts[0].path"),
    (_set("artifacts.0.path", "/artifacts/a"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/x\n"), "artifacts[0].path"),
    (_set("artifacts.0.path", "artifacts/" + "a" * 246), "at most 255 characters"),
    (_set("artifacts.1.path", "artifacts/models/qwen2.5-0.5b-instruct-q4_k_m.gguf"), "duplicates artifacts[0].path"),
    (_set("artifacts.1.path", "artifacts/models/QWEN2.5-0.5b-instruct-q4_k_m.gguf"), "differs only in letter case"),
    (_set("artifacts.0.size", -1), "artifacts[0].size"),
    (_set("artifacts.0.size", True), "artifacts[0].size: must be an integer"),
    (_set("artifacts.0.size", 1.5), "artifacts[0].size: must be an integer"),
    (_set("artifacts.0.sha256", GGUF_SHA.upper()), "artifacts[0].sha256"),
    (_set("artifacts.0.sha256", "abc"), "artifacts[0].sha256"),
    (_set("artifacts.0.kind", "weights"), "artifacts[0].kind"),
    (_set("artifacts.0.format", "onnx"), "artifacts[0].format"),
    (_set("artifacts.0.model", _DELETE), "a model artifact needs a 'model' object"),
    (_set("artifacts.1.model", {"name": "x", "license": "MIT"}), "only allowed when kind is 'model'"),
    (_set("artifacts.0.model.name", "has space"), "artifacts[0].model.name"),
    (_set("artifacts.0.model.license", "Apache 2.0"), "artifacts[0].model.license"),
    (_set("artifacts.0.model.license", _DELETE), "missing required key 'license'"),
    (_set("artifacts.0.model.upstream_sha256", "xyz"), "artifacts[0].model.upstream_sha256"),
    (_set("artifacts.0.model.source_uri", "u" * 2049), "artifacts[0].model.source_uri"),
    (_set("artifacts.0.model.source_revision", "r" * 129), "artifacts[0].model.source_revision"),
    (_set("artifacts.0.metadata", []), "artifacts[0].metadata: must be an object"),
])
def test_invalid_manifests(change, expected):
    errors = validate_manifest(mutate(change))
    assert any(expected in e for e in errors), errors
    with pytest.raises(ManifestError) as info:
        parse_manifest(raw(mutate(change)))
    assert info.value.errors == errors


@pytest.mark.parametrize("change", [
    _set("bundle.description", "two\nlines\tand tabs"),
    _set("bundle.description", _DELETE),
    _set("bundle.created_at", "2026-10-28T02:00:00+02:00"),
    _set("bundle.created_at", "2026-10-28T02:00:00.123456789Z"),
    _set("requires.runtime", None),
    _set("requires.min_memory_bytes", None),
    _set("requires.ferry_min_version", "1"),
    _set("artifacts.0.metadata", _DELETE),
    _set("artifacts.0.model.source_uri", None),
    _set("artifacts.0.model.upstream_sha256", None),
])
def test_valid_variations(change):
    assert validate_manifest(mutate(change)) == []


def test_artifact_limits_come_from_the_import_policy():
    doc = spec_example()
    assert any("between 1 and 1" in e for e in validate_manifest(doc, ImportSettings(max_artifacts=1)))
    assert any("artifacts[0].size: must be between 0 and 1000" in e
               for e in validate_manifest(doc, ImportSettings(max_artifact_bytes=1000)))


def test_errors_quote_untrusted_values():
    errors = validate_manifest(mutate(_set("bundle.name", "\x1b[2J")))
    assert errors and "\x1b" not in " ".join(errors)


@pytest.mark.parametrize("data, expected", [
    (b'{"a": 1, "a": 2}', 'duplicate key "a"'),
    (b'{"a": NaN}', "not valid JSON"),
    (b'{"a": Infinity}', "not valid JSON"),
    (b"\xef\xbb\xbf{}", "byte order mark"),
    (b'{"a": "\xff"}', "not valid UTF-8"),
    (b"[" * 200_000 + b"]" * 200_000, "nested too deeply"),
    (b"{", "not valid JSON"),
])
def test_strict_decoding(data, expected):
    with pytest.raises(ManifestError) as info:
        decode_manifest_json(data)
    assert expected in info.value.errors[0]


def test_non_object_manifest():
    assert validate_manifest([1, 2]) == ["must be an object"]
    with pytest.raises(ManifestError):
        parse_manifest(b"[]")


def test_manifest_error_lists_problems():
    exc = ManifestError([f"e{i}" for i in range(8)])
    assert exc.code == "manifest_invalid" and exc.details["errors"][7] == "e7"
    assert "(and 3 more)" in exc.message


@pytest.mark.parametrize("required, installed, ok", [
    ("0.1.0", "0.1.0", True), ("0.1", "0.1.0", True), ("0", "0.1.0", True), ("0.2.0", "0.1.0", False),
    ("0.10.0", "0.9.9", False), ("0.9.0", "0.10.0", True), ("1", "0.99.99", False), ("0.1.1", "0.1.1.dev3", True),
])
def test_ferry_version_comparison_is_numeric(required, installed, ok):
    assert ferry_version_satisfied(required, installed) is ok


def test_parse_ferry_version():
    assert parse_ferry_version("2") == (2, 0, 0)
    assert parse_ferry_version("0.1.0rc1") == (0, 1, 0)
