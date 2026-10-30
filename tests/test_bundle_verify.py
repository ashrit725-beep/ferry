"""Verification: every check in the table failing for its own reason, archive tricks,
signature and role policy, directory bundles, streaming, and the report contract."""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from ferry import crypto
from ferry.bundle import CHECK_IDS, sign_bundle, verify_bundle
from ferry.bundle import verify as verify_module
from ferry.config import ImportSettings, Settings
from ferry.trust import add_key, revoke_key

from helpers_bundle import (
    ELF_BYTES, LICENSE_TEXT, MODEL, PICKLE_PROTO4, SHEBANG_BYTES, artifact_entry, crafted_bundle, failed,
    gguf_bytes, make_signer, make_workspace, manifest_bytes, replace_member, rewrite_tar,
    safetensors_bytes, signed_tar, statuses, tar_member, torch_zip_bytes, write_tar, zip_bytes,
)

UTC = dt.timezone.utc
MiB = 1024 * 1024


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


def base_files(*extra: tuple[str, bytes, dict[str, Any]]) -> list[tuple[str, bytes, dict[str, Any]]]:
    return [("artifacts/models/tiny.gguf", gguf_bytes(), {"kind": "model", "fmt": "gguf", "model": MODEL}),
            ("artifacts/docs/LICENSE", LICENSE_TEXT, {"kind": "document", "fmt": "text"}), *extra]


def craft(ws, files=None, *, signers=None, name: str = "crafted.ferry.tar", **kw: Any) -> Path:
    return crafted_bundle(ws.root / name, [ws.publisher] if signers is None else signers,
                          base_files() if files is None else files, **kw)


def run(ws, source: Path, policy: ImportSettings | None = None, **kw: Any):
    return verify_bundle(source, policy or ws.policy(), ws.trust_store(), **kw)


def check(report, cid: str) -> dict[str, Any]:
    return report.check(cid)


# --------------------------------------------------------------------------- happy path and report contract


def test_pack_countersign_verify_happy_path(ws):
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    report = run(ws, res.bundle_path, ws.policy(required_roles=("publisher", "reviewer")))
    assert report.accepted, report.errors
    assert report.errors == [] and all(c["status"] == "pass" for c in report.checks)
    assert report.bundle_id == res.bundle_id
    assert report.bundle == {"name": "tiny-model", "version": "1.0.0", "created_at": "2026-10-28T02:00:00.000Z"}
    assert {s["key_id"]: (s["status"], s["roles"]) for s in report.signatures} == {
        ws.publisher.key_id: ("valid", ["publisher"]), ws.reviewer.key_id: ("valid", ["reviewer"])}
    model = next(a for a in report.artifacts if a["kind"] == "model")
    assert model["status"] == "ok" and model["detected_format"] == "gguf"
    assert model["expected_sha256"] == model["actual_sha256"]
    assert model["metadata"]["architecture"] == "llama"


def test_report_has_exactly_the_spec_shape(ws):
    report = run(ws, ws.pack().bundle_path).to_dict()
    json.dumps(report)
    assert list(report) == ["report_version", "verdict", "bundle_id", "bundle", "source", "verified_at",
                            "tool_version", "policy", "signatures", "artifacts", "checks", "errors", "warnings"]
    assert report["report_version"] == 1 and report["verdict"] == "accepted"
    assert set(report["source"]) == {"name", "type", "size"} and report["source"]["type"] == "tar"
    assert report["policy"]["required_roles"] == ["publisher"]
    assert set(report["signatures"][0]) == {"key_id", "name", "roles", "status", "detail"}
    assert set(report["artifacts"][0]) == {"path", "kind", "declared_format", "detected_format", "size",
                                           "expected_sha256", "actual_sha256", "status", "detail", "metadata"}
    assert [c["id"] for c in report["checks"]] == list(CHECK_IDS)
    assert all(set(c) == {"id", "status", "message"} for c in report["checks"])


def test_settings_object_is_accepted_and_trust_none_trusts_nothing(ws):
    res = ws.pack()
    assert verify_bundle(res.bundle_path, Settings(data_dir=ws.root, imports=ws.policy()), ws.trust_store()).accepted
    report = verify_bundle(res.bundle_path, ws.policy(), None)
    assert not report.accepted and report.signatures[0]["status"] == "untrusted"


def test_metadata_in_the_report_is_recomputed_not_copied_from_the_manifest(ws):
    path = ws.root / "lying.ferry.tar"
    entries = [artifact_entry("artifacts/models/tiny.gguf", gguf_bytes(), kind="model", fmt="gguf", model=MODEL)]
    entries[0]["metadata"] = {"gguf": {"architecture": "trusted-arch", "parameter_count": 1}}
    signed_tar(path, manifest_bytes(entries), [ws.publisher], [("artifacts/models/tiny.gguf", gguf_bytes())])
    report = run(ws, path)
    assert report.accepted
    assert report.artifacts[0]["metadata"]["architecture"] == "llama"
    assert report.artifacts[0]["metadata"]["parameter_count"] == 12


# --------------------------------------------------------------------------- every check fails for its own reason


def _not_a_tar(ws):
    p = ws.root / "random.ferry.tar"
    p.write_bytes(b"This is not a tar file.\n" * 200)
    return p, None


def _symlink_member(ws):
    return craft(ws, extra=[tar_member("artifacts/link", type=tarfile.SYMTYPE, linkname="/etc/passwd")]), None


def _member_outside_layout(ws):
    return craft(ws, extra=[tar_member("README.txt", b"hello")]), None


def _duplicate_member(ws):
    return craft(ws, extra=[tar_member("artifacts/docs/LICENSE", b"second copy")]), None


def _member_too_large(ws):
    return craft(ws), ws.policy(max_artifact_bytes=200)


def _no_manifest(ws):
    p = ws.root / "nomanifest.ferry.tar"
    write_tar(p, [tar_member("artifacts/docs/LICENSE", LICENSE_TEXT)])
    return p, None


def _manifest_tampered(ws):
    entries = [artifact_entry(p, d, **kw) for p, d, kw in base_files()]
    original = manifest_bytes(entries)
    tampered = original.replace(b"crafted for a test", b"crafted for a TEST")
    p = ws.root / "tampered.ferry.tar"
    signed_tar(p, tampered, [ws.publisher], [(p_, d) for p_, d, _ in base_files()], signed_bytes=original)
    return p, None


def _untrusted_signer(ws):
    return craft(ws, signers=[make_signer("stranger")]), None


def _schema_invalid(ws):
    return craft(ws, mutate=lambda doc: doc.update(extra_field=1), validate=False), None


def _future_ferry(ws):
    return craft(ws, requires={"ferry_min_version": "99.0"}), None


def _missing_artifact(ws):
    entries = [artifact_entry(p, d, **kw) for p, d, kw in base_files()]
    entries.append(artifact_entry("artifacts/docs/NOTICE", b"notice\n"))
    p = ws.root / "missing.ferry.tar"
    signed_tar(p, manifest_bytes(entries), [ws.publisher], [(p_, d) for p_, d, _ in base_files()])
    return p, None


def _extra_artifact(ws):
    return craft(ws, extra=[tar_member("artifacts/docs/EXTRA", b"smuggled\n")]), None


def _size_mismatch(ws):
    files = base_files()
    entries = [artifact_entry(p, d, **kw) for p, d, kw in files]
    entries[1]["size"] += 1
    p = ws.root / "size.ferry.tar"
    signed_tar(p, manifest_bytes(entries), [ws.publisher], [(p_, d) for p_, d, _ in files])
    return p, None


def _byte_flipped(ws):
    src = craft(ws)
    p = ws.root / "flipped.ferry.tar"
    rewrite_tar(src, p, lambda ms: replace_member(ms, "artifacts/docs/LICENSE", LICENSE_TEXT.replace(b"2.0", b"2.1")))
    return p, None


def _wrong_format(ws):
    return craft(ws, base_files()[:1] + [("artifacts/docs/LICENSE", LICENSE_TEXT, {"kind": "document", "fmt": "json"})]), None


def _kind_file(ws):
    return craft(ws, base_files(("artifacts/misc/notes.txt", b"notes\n", {"kind": "file", "fmt": "text"}))), None


def _model_format(ws):
    files = [("artifacts/models/tiny.safetensors", safetensors_bytes(),
              {"kind": "model", "fmt": "safetensors", "model": MODEL})]
    return craft(ws, files), ws.policy(allowed_model_formats=("gguf",))


def _pickle(ws):
    return craft(ws, base_files(("artifacts/misc/state.bin", PICKLE_PROTO4, {"kind": "document", "fmt": "pickle"}))), None


def _executable(ws):
    return craft(ws, base_files(("artifacts/tools/run", ELF_BYTES, {"kind": "document", "fmt": "executable"}))), None


def _archive(ws):
    gz = gzip.compress(b"nested")
    return craft(ws, base_files(("artifacts/misc/data.gz", gz, {"kind": "document", "fmt": "archive"}))), None


def _licence(ws):
    model = {**MODEL, "license": "GPL-3.0-only"}
    return craft(ws, [("artifacts/models/tiny.gguf", gguf_bytes(), {"kind": "model", "fmt": "gguf", "model": model})]), None


def _memory(ws):
    return craft(ws, requires={"min_memory_bytes": 2**62}), None


CASES: list[tuple[str, Callable[[Any], tuple[Path, ImportSettings | None]], set[str], str]] = [
    ("archive.readable", _not_a_tar, {"archive.readable"}, "not a readable tar archive"),
    ("archive.members", _symlink_member, {"archive.members"}, "is a symbolic link"),
    ("archive.paths", _member_outside_layout, {"archive.paths"}, "outside the bundle layout"),
    ("archive.duplicates", _duplicate_member, {"archive.duplicates"}, "appears 2 times"),
    ("archive.limits", _member_too_large, {"archive.limits"}, "the limit is 200"),
    ("manifest.present", _no_manifest, {"manifest.present"}, "no manifest.json"),
    ("signatures.valid", _manifest_tampered, {"signatures.valid", "signatures.roles"}, "altered after signing"),
    ("signatures.roles", _untrusted_signer, {"signatures.roles"}, "required role 'publisher' is not satisfied"),
    ("manifest.schema", _schema_invalid, {"manifest.schema"}, "unknown key \"extra_field\""),
    ("compat.ferry_version", _future_ferry, {"compat.ferry_version"}, "needs Ferry 99.0 or newer"),
    ("inventory.missing", _missing_artifact, {"inventory.missing"}, "artifacts/docs/NOTICE is not in the bundle"),
    ("inventory.extra", _extra_artifact, {"inventory.extra"}, "artifacts/docs/EXTRA\" is not listed"),
    ("artifact.size", _size_mismatch, {"artifact.size"}, "the manifest says"),
    ("artifact.digest", _byte_flipped, {"artifact.digest"}, "SHA-256 is"),
    ("artifact.format", _wrong_format, {"artifact.format"}, "declared as json but the content is text"),
    ("policy.kinds", _kind_file, {"policy.kinds"}, "kind 'file' is not allowed"),
    ("policy.formats", _model_format, {"policy.formats"}, "model format 'safetensors' is not allowed"),
    ("policy.pickle", _pickle, {"policy.pickle"}, "allow_pickle is false"),
    ("policy.executables", _executable, {"policy.executables"}, "allow_executables is false"),
    ("policy.archives", _archive, {"policy.archives"}, "nested archives"),
    ("policy.licenses", _licence, {"policy.licenses"}, "licence 'GPL-3.0-only' is not allowed"),
]


@pytest.mark.parametrize("cid, build, expected_failures, reason", CASES, ids=[c[0] for c in CASES])
def test_each_check_fails_for_its_own_reason(ws, cid, build, expected_failures, reason):
    source, policy = build(ws)
    report = run(ws, source, policy)
    assert report.verdict == "rejected"
    assert set(failed(report)) == expected_failures, (failed(report), report.errors)
    assert check(report, cid)["status"] == "fail"
    assert any(reason in e for e in report.errors), report.errors


def test_every_check_id_has_a_failure_case():
    assert {c[0] for c in CASES} | {"compat.memory"} == set(CHECK_IDS)


def test_memory_is_a_warning_only(ws):
    source, _ = _memory(ws)
    report = run(ws, source)
    assert report.accepted and check(report, "compat.memory")["status"] == "warn"
    assert any("bytes of memory" in w for w in report.warnings)


def test_structural_failure_stops_before_signatures(ws):
    report = run(ws, _symlink_member(ws)[0])
    after = CHECK_IDS[CHECK_IDS.index("manifest.present") + 1:]
    assert all(statuses(report)[c] == "skip" for c in after)
    assert report.signatures == [] and report.bundle is None


def test_full_mode_keeps_going_after_a_structural_failure(ws):
    report = run(ws, _member_outside_layout(ws)[0], full=True)
    assert not report.accepted and failed(report) == ["archive.paths"]
    assert check(report, "signatures.roles")["status"] == "pass"
    assert check(report, "artifact.digest")["status"] == "pass"
    assert report.bundle is not None


# --------------------------------------------------------------------------- signatures before parsing


def test_signatures_are_checked_before_the_manifest_is_parsed(ws, monkeypatch):
    calls = []
    real = verify_module.parse_manifest

    def spy(raw, limits=None):
        calls.append(raw)
        return real(raw, limits)

    monkeypatch.setattr(verify_module, "parse_manifest", spy)
    report = run(ws, _untrusted_signer(ws)[0])
    assert not report.accepted and calls == [] and report.bundle is None
    assert check(report, "manifest.schema")["status"] == "skip"
    run(ws, craft(ws, name="ok.ferry.tar"))
    assert len(calls) == 1


def test_garbage_manifest_with_no_trusted_signature_is_never_parsed(ws):
    path = ws.root / "garbage.ferry.tar"
    signed_tar(path, b"\x00not json at all{{{", [make_signer("stranger")])
    report = run(ws, path)
    assert failed(report) == ["signatures.roles"] and check(report, "manifest.schema")["status"] == "skip"
    assert report.bundle_id is not None


def test_garbage_manifest_signed_by_a_trusted_key_fails_schema(ws):
    path = ws.root / "garbage.ferry.tar"
    signed_tar(path, b'{"schema": "ferry.dev/bundle-manifest/v1", "schema": "twice"}', [ws.publisher])
    report = run(ws, path)
    assert failed(report) == ["manifest.schema"] and any("duplicate key" in e for e in report.errors)


# --------------------------------------------------------------------------- signature statuses and roles


def test_signature_statuses(ws, tmp_path):
    revoked, expired, future, stranger = (make_signer(n) for n in ("revoked", "expired", "future", "stranger"))
    add_key(ws.trust_dir, revoked.pem, name="Revoked", roles=["reviewer"])
    revoke_key(ws.trust_dir, revoked.key_id, "laptop stolen")
    add_key(ws.trust_dir, expired.pem, name="Expired", roles=["reviewer"], not_after="2026-01-01T00:00:00Z")
    add_key(ws.trust_dir, future.pem, name="Future", roles=["reviewer"], not_before="2027-01-01T00:00:00Z")
    source = craft(ws, signers=[ws.publisher, revoked, expired, future, stranger])
    now = dt.datetime(2026, 10, 28, tzinfo=UTC)
    report = run(ws, source, ws.policy(required_roles=("publisher", "reviewer")), now=now)
    by_id = {s["key_id"]: s for s in report.signatures}
    assert by_id[ws.publisher.key_id]["status"] == "valid"
    assert by_id[revoked.key_id]["status"] == "revoked" and "laptop stolen" in by_id[revoked.key_id]["detail"]
    assert by_id[expired.key_id]["status"] == "expired"
    assert by_id[future.key_id]["status"] == "not_yet_valid"
    assert by_id[stranger.key_id]["status"] == "untrusted" and by_id[stranger.key_id]["roles"] == []
    assert check(report, "signatures.valid")["status"] == "pass"
    assert failed(report) == ["signatures.roles"]
    assert any("'reviewer' is not satisfied" in e for e in report.errors)
    assert sum("does not count" in w for w in report.warnings) == 4
    # The same bundle is fine once the reviewer key's window opens and only that key is needed.
    later = run(ws, source, ws.policy(required_roles=("reviewer",)), now=dt.datetime(2027, 6, 1, tzinfo=UTC))
    assert later.accepted, later.errors


def test_bad_signature_from_an_inactive_key_is_not_tampering(ws):
    revoked = make_signer("revoked")
    add_key(ws.trust_dir, revoked.pem, name="Revoked", roles=["reviewer"])
    revoke_key(ws.trust_dir, revoked.key_id, "rotated")
    entries = [artifact_entry(p, d, **kw) for p, d, kw in base_files()]
    raw = manifest_bytes(entries)
    path = ws.root / "b.ferry.tar"
    signed_tar(path, raw, [ws.publisher], [(p, d) for p, d, _ in base_files()],
               extra=[tar_member(f"signatures/{revoked.key_id}.sig", b"\x01" * 64)])
    report = run(ws, path)
    assert report.accepted, report.errors


def test_malformed_signature_file(ws):
    entries = [artifact_entry(p, d, **kw) for p, d, kw in base_files()]
    raw = manifest_bytes(entries)
    path = ws.root / "b.ferry.tar"
    short = ws.publisher.sign(raw)[:63]
    write_tar(path, [tar_member("manifest.json", raw), tar_member(f"signatures/{ws.publisher.key_id}.sig", short),
                     *(tar_member(p, d) for p, d, _ in base_files())])
    report = run(ws, path)
    assert check(report, "signatures.valid")["status"] == "fail"
    assert report.signatures[0]["status"] == "malformed" and "63 bytes" in report.signatures[0]["detail"]


def test_signature_from_an_ignored_trust_entry_says_why(ws):
    impostor = make_signer("impostor")
    entry = ws.trust_dir / f"{ws.publisher.key_id}.json"
    doc = json.loads(entry.read_text())
    doc["public_key_pem"] = impostor.pem.decode()
    entry.chmod(0o644)
    entry.write_text(json.dumps(doc))
    report = run(ws, craft(ws))
    assert not report.accepted
    assert "exists but is ignored" in report.signatures[0]["detail"]
    assert any(w.startswith("trust store:") and "do not all agree" in w for w in report.warnings)


def test_two_keys_satisfy_publisher_and_reviewer(ws):
    report = run(ws, craft(ws, signers=[ws.publisher, ws.reviewer]), ws.policy(required_roles=("publisher", "reviewer")))
    assert report.accepted
    message = check(report, "signatures.roles")["message"]
    assert "publisher: " + crypto.short_id(ws.publisher.key_id) in message
    assert "reviewer: " + crypto.short_id(ws.reviewer.key_id) in message


def test_one_key_holding_both_roles_is_not_two_signers(ws):
    both = make_signer("both")
    add_key(ws.trust_dir, both.pem, name="Both roles", roles=["publisher", "reviewer"])
    source = craft(ws, signers=[both])
    distinct = run(ws, source, ws.policy(required_roles=("publisher", "reviewer"), distinct_signers=True))
    assert failed(distinct) == ["signatures.roles"]
    assert any("not satisfied by a distinct signer" in e for e in distinct.errors)
    relaxed = run(ws, source, ws.policy(required_roles=("publisher", "reviewer"), distinct_signers=False))
    assert relaxed.accepted, relaxed.errors


def test_role_assignment_finds_a_matching_when_one_exists(ws):
    both = make_signer("both")
    add_key(ws.trust_dir, both.pem, name="Both roles", roles=["publisher", "reviewer"])
    # "both" could take either role; it must take publisher so the reviewer key fills reviewer, or vice versa.
    report = run(ws, craft(ws, signers=[both, ws.reviewer]), ws.policy(required_roles=("reviewer", "publisher")))
    assert report.accepted, report.errors


def test_publisher_key_cannot_stand_in_for_the_reviewer(ws):
    report = run(ws, ws.pack().bundle_path, ws.policy(required_roles=("publisher", "reviewer")))
    assert failed(report) == ["signatures.roles"]
    assert any("'reviewer' is not satisfied" in e for e in report.errors)


# --------------------------------------------------------------------------- archive tricks


@pytest.mark.parametrize("member, label", [
    (tar_member("artifacts/link", type=tarfile.SYMTYPE, linkname="../../etc/passwd"), "symbolic link"),
    (tar_member("artifacts/hard", type=tarfile.LNKTYPE, linkname="artifacts/docs/LICENSE"), "hard link"),
    (tar_member("artifacts/tty", type=tarfile.CHRTYPE), "character device"),
    (tar_member("artifacts/disk", type=tarfile.BLKTYPE), "block device"),
    (tar_member("artifacts/pipe", type=tarfile.FIFOTYPE), "FIFO"),
    (tar_member("artifacts/cont", b"x", type=tarfile.CONTTYPE), "contiguous file"),
])
def test_special_members_are_rejected(ws, member, label):
    report = run(ws, craft(ws, extra=[member]))
    assert failed(report) == ["archive.members"]
    assert any(label in e for e in report.errors)


def test_sparse_member_is_rejected(ws):
    info, data = tar_member("artifacts/docs/sparse", b"x")
    info.pax_headers = {"GNU.sparse.map": "0,1"}
    report = run(ws, craft(ws, extra=[(info, data)]))
    assert failed(report) == ["archive.members"] and any("sparse file" in e for e in report.errors)


def test_gnu_format_tar_with_a_long_artifact_path_is_readable(ws):
    long_path = "artifacts/" + "/".join(["deeply-nested-directory"] * 6) + "/LICENSE"
    entries = [artifact_entry(long_path, LICENSE_TEXT)]
    raw = manifest_bytes(entries)
    path = ws.root / "gnu.ferry.tar"
    write_tar(path, [tar_member("manifest.json", raw), tar_member(f"signatures/{ws.publisher.key_id}.sig",
                                                                  ws.publisher.sign(raw)),
                     tar_member(long_path, LICENSE_TEXT)], format=tarfile.GNU_FORMAT)
    assert len(long_path) > 100
    report = run(ws, path)
    assert report.accepted, report.errors


def test_symlink_replacing_a_listed_artifact_is_rejected(ws):
    entries = [artifact_entry(p, d, **kw) for p, d, kw in base_files()]
    path = ws.root / "b.ferry.tar"
    signed_tar(path, manifest_bytes(entries), [ws.publisher], [("artifacts/models/tiny.gguf", gguf_bytes())],
               extra=[tar_member("artifacts/docs/LICENSE", type=tarfile.SYMTYPE, linkname="/etc/passwd")])
    report = run(ws, path, full=True)
    assert "archive.members" in failed(report) and "inventory.missing" in failed(report)


def test_setuid_member_is_rejected(ws):
    report = run(ws, craft(ws, extra=[tar_member("artifacts/docs/README", b"x", mode=0o4755)]), full=True)
    assert "archive.members" in failed(report) and any("setuid" in e for e in report.errors)


@pytest.mark.parametrize("name, reason", [
    ("../outside", "'..' component"),
    ("artifacts/../../etc/passwd", "'..' component"),
    ("/etc/passwd", "absolute path"),
    ("/artifacts/docs/x", "absolute path"),
    ("artifacts\\docs\\x", "backslash"),
    ("artifacts/./x", "'.' component"),
    ("./manifest.json", "'.' component"),
    ("artifacts//x", "empty path component"),
    ("artifacts/.hidden", "not a valid artifact path"),
    ("signatures/ABC.sig", "is not named signatures/"),
    ("signatures/" + "a" * 64 + ".txt", "is not named signatures/"),
    ("Manifest.json", "outside the bundle layout"),
    ("artifacts/" + "a" * 250, "longer than 255"),
])
def test_bad_member_names(ws, name, reason):
    report = run(ws, craft(ws, extra=[tar_member(name, b"x")]))
    assert "archive.paths" in failed(report)
    assert any(reason in e for e in report.errors), report.errors


def test_nul_in_a_pax_path_is_rejected(ws):
    info, data = tar_member("artifacts/placeholder", b"x")
    info.pax_headers = {"path": "artifacts/a\x00b"}
    report = run(ws, craft(ws, extra=[(info, data)]))
    assert "archive.paths" in failed(report)


def test_case_insensitive_duplicates(ws):
    report = run(ws, craft(ws, extra=[tar_member("artifacts/docs/license", b"other")]))
    assert failed(report) == ["archive.duplicates"]
    assert any("differ only in letter case" in e for e in report.errors)


def test_duplicate_manifest(ws):
    report = run(ws, craft(ws, extra=[tar_member("manifest.json", b"{}")]))
    assert set(failed(report)) == {"archive.duplicates", "manifest.present"}


def test_directory_members_inside_the_layout_are_allowed(ws):
    dirs = [tar_member(n, type=tarfile.DIRTYPE, mode=0o755) for n in ("signatures", "artifacts", "artifacts/docs")]
    assert run(ws, craft(ws, extra=dirs)).accepted
    report = run(ws, craft(ws, extra=[tar_member("other", type=tarfile.DIRTYPE, mode=0o755)], name="b.tar"))
    assert failed(report) == ["archive.paths"]


def test_too_many_members(ws):
    extra = [tar_member(f"artifacts/x/{i}", b"x") for i in range(70)]
    report = run(ws, craft(ws, extra=extra), ws.policy(max_artifacts=2))
    assert "archive.members" in failed(report)
    assert any("more than 66 members" in e for e in report.errors)


def test_total_size_limit(ws):
    report = run(ws, craft(ws), ws.policy(max_bundle_bytes=1000))
    assert failed(report) == ["archive.limits"]


def test_manifest_size_limit(ws):
    report = run(ws, craft(ws), ws.policy(max_manifest_bytes=100))
    assert failed(report) == ["manifest.present"]


def test_gzip_compressed_tar_is_rejected(ws):
    source = craft(ws)
    gz = ws.root / "b.ferry.tar.gz"
    gz.write_bytes(gzip.compress(source.read_bytes()))
    report = run(ws, gz)
    assert failed(report) == ["archive.readable"] and "gzip-compressed" in report.errors[0]


@pytest.mark.parametrize("cut", ["mid-member", "no-end-marker", "mid-header"])
def test_truncated_tar(ws, cut):
    source = craft(ws)
    data = source.read_bytes()
    with tarfile.open(source) as tf:
        members = tf.getmembers()
        end = tf.offset
    model = next(m for m in members if m.name.endswith(".gguf"))
    length = {"mid-member": model.offset_data + 100, "no-end-marker": end, "mid-header": members[1].offset + 200}[cut]
    truncated = ws.root / "truncated.ferry.tar"
    truncated.write_bytes(data[:length])
    report = run(ws, truncated)
    assert failed(report) == ["archive.readable"]
    assert "truncated" in report.errors[0] or "corrupt" in report.errors[0], report.errors


def test_corrupt_header_in_the_middle(ws):
    source = craft(ws)
    data = bytearray(source.read_bytes())
    with tarfile.open(source) as tf:
        offset = tf.getmembers()[2].offset
    data[offset + 148] ^= 0x01  # checksum field
    bad = ws.root / "corrupt.ferry.tar"
    bad.write_bytes(bytes(data))
    report = run(ws, bad)
    assert failed(report) == ["archive.readable"] and "invalid member header" in report.errors[0]


def test_data_after_the_end_of_the_archive(ws):
    source = craft(ws)
    polyglot = ws.root / "polyglot.ferry.tar"
    polyglot.write_bytes(source.read_bytes() + zip_bytes({"evil.pkl": b"x"}))
    report = run(ws, polyglot)
    assert failed(report) == ["archive.readable"] and "after the end of the archive" in report.errors[0]


def test_pax_header_larger_than_the_cap(ws):
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = tarfile.XHDTYPE
    info.size = 100 * MiB
    hostile = ws.root / "pax.ferry.tar"
    hostile.write_bytes(info.tobuf(tarfile.USTAR_FORMAT) + b"\x00" * 2048)
    report = run(ws, hostile)
    assert failed(report) == ["archive.readable"] and "MiB limit" in report.errors[0]


@pytest.mark.parametrize("content, expected", [
    (b"", "archive.readable"),
    (b"hello world", "archive.readable"),
    (b"\x00" * 1024, "manifest.present"),  # a valid, empty tar: only the end-of-archive marker
])
def test_empty_or_tiny_files(ws, content, expected):
    p = ws.root / "small.ferry.tar"
    p.write_bytes(content)
    assert failed(run(ws, p)) == [expected]


def test_bundle_path_that_is_a_symlink_is_rejected(ws):
    link = ws.root / "link.ferry.tar"
    link.symlink_to(craft(ws))
    report = run(ws, link)
    assert failed(report) == ["archive.readable"] and "symbolic link" in report.errors[0]


def test_missing_bundle(ws):
    report = run(ws, ws.root / "nope.ferry.tar")
    assert failed(report) == ["archive.readable"] and report.source["type"] is None


# --------------------------------------------------------------------------- content


def test_malformed_gguf_inside_a_bundle(ws):
    files = [("artifacts/models/tiny.gguf", gguf_bytes(tensors=[])[:40], {"kind": "model", "fmt": "gguf", "model": MODEL})]
    report = run(ws, craft(ws, files))
    assert failed(report) == ["artifact.format"]
    assert report.artifacts[0]["status"] == "malformed" and "malformed GGUF" in report.artifacts[0]["detail"]


def test_malformed_safetensors_inside_a_bundle(ws):
    bad = safetensors_bytes(header={"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 8]}}, data=b"\x00" * 8)
    files = [("artifacts/models/w.safetensors", bad, {"kind": "model", "fmt": "safetensors", "model": MODEL})]
    report = run(ws, craft(ws, files))
    assert failed(report) == ["artifact.format"] and "needs 16" in report.artifacts[0]["detail"]


def test_pickle_declared_as_safetensors(ws):
    files = [("artifacts/models/model.safetensors", torch_zip_bytes(), {"kind": "model", "fmt": "safetensors",
                                                                        "model": MODEL})]
    report = run(ws, craft(ws, files))
    assert set(failed(report)) == {"artifact.format", "policy.formats", "policy.pickle"}
    assert report.artifacts[0]["detected_format"] == "pickle"


def test_raw_pickle_and_torch_zip_are_rejected_even_when_declared_honestly(ws):
    files = base_files(("artifacts/misc/a.bin", PICKLE_PROTO4, {"kind": "document", "fmt": "pickle"}),
                       ("artifacts/misc/b.bin", torch_zip_bytes(), {"kind": "document", "fmt": "pickle"}))
    report = run(ws, craft(ws, files))
    assert failed(report) == ["policy.pickle"]
    assert sum("allow_pickle is false" in e for e in report.errors) == 2
    allowed = run(ws, craft(ws, files, name="b.tar"), ws.policy(allow_pickle=True))
    assert allowed.accepted, allowed.errors


def test_elf_and_shebang_executables_are_rejected(ws):
    files = base_files(("artifacts/tools/elf", ELF_BYTES, {"kind": "document", "fmt": "executable"}),
                       ("artifacts/tools/run", SHEBANG_BYTES, {"kind": "document", "fmt": "executable"}))
    report = run(ws, craft(ws, files))
    assert failed(report) == ["policy.executables"]
    assert sum("allow_executables is false" in e for e in report.errors) == 2
    assert {a["detected_format"] for a in report.artifacts[2:]} == {"executable"}


def test_nested_archive_is_allowed_only_as_kind_file(ws):
    files = base_files(("artifacts/misc/data.zip", zip_bytes({"a.txt": b"a"}), {"kind": "file", "fmt": "archive"}))
    blocked = run(ws, craft(ws, files))
    assert set(failed(blocked)) == {"policy.kinds", "policy.archives"}
    allowed = run(ws, craft(ws, files, name="b.tar"),
                  ws.policy(allowed_kinds=("model", "tokenizer", "config", "document", "file")))
    assert allowed.accepted, allowed.errors
    as_document = base_files(("artifacts/misc/data.zip", zip_bytes({"a.txt": b"a"}), {"kind": "document", "fmt": "archive"}))
    assert failed(run(ws, craft(ws, as_document, name="c.tar"))) == ["policy.archives"]


def test_licences_compare_case_insensitively(ws):
    model = {**MODEL, "license": "apache-2.0"}
    files = [("artifacts/models/tiny.gguf", gguf_bytes(), {"kind": "model", "fmt": "gguf", "model": model})]
    assert run(ws, craft(ws, files)).accepted


def test_gguf_licence_that_disagrees_with_the_manifest_is_a_warning(ws):
    model = {**MODEL, "license": "MIT"}
    files = [("artifacts/models/tiny.gguf", gguf_bytes(), {"kind": "model", "fmt": "gguf", "model": model})]
    report = run(ws, craft(ws, files))
    assert report.accepted and any("names its licence" in w for w in report.warnings)


# --------------------------------------------------------------------------- directory bundles


def extract_with_tar(tar_path: Path, dest: Path) -> Path:
    dest.mkdir()
    subprocess.run(["tar", "-xf", str(tar_path), "-C", str(dest)], check=True)
    return dest


needs_tar = pytest.mark.skipif(shutil.which("tar") is None, reason="needs a tar binary")


@needs_tar
def test_directory_bundle_is_accepted(ws, tmp_path):
    bundle = extract_with_tar(ws.pack().bundle_path, tmp_path / "bundle")
    report = run(ws, bundle)
    assert report.accepted, report.errors
    assert report.source == {"name": "bundle", "type": "dir", "size": report.source["size"]}
    assert report.source["size"] > 0


@needs_tar
@pytest.mark.parametrize("plant, expected_check, label", [
    (lambda d: (d / "artifacts/docs/link").symlink_to("/etc/passwd"), "archive.members", "symbolic link"),
    (lambda d: os.mkfifo(d / "artifacts/docs/pipe"), "archive.members", "FIFO"),
    (lambda d: os.link(d / "artifacts/docs/LICENSE", d / "artifacts/docs/LICENSE2"), "archive.members", "hard link"),
    (lambda d: (d / ".DS_Store").write_bytes(b"\x00"), "archive.paths", "outside the bundle layout"),
    (lambda d: (d / "artifacts/docs/NOTES").write_bytes(b"extra"), "inventory.extra", "is not listed"),
])
def test_directory_bundle_tricks(ws, tmp_path, plant, expected_check, label):
    bundle = extract_with_tar(ws.pack().bundle_path, tmp_path / "bundle")
    plant(bundle)
    report = run(ws, bundle)
    assert failed(report) == [expected_check], report.errors
    assert any(label in e for e in report.errors), report.errors


@needs_tar
def test_directory_bundle_with_a_symlinked_artifact_directory(ws, tmp_path):
    bundle = extract_with_tar(ws.pack().bundle_path, tmp_path / "bundle")
    real = tmp_path / "elsewhere"
    (bundle / "artifacts/docs").rename(real)
    (bundle / "artifacts/docs").symlink_to(real, target_is_directory=True)
    report = run(ws, bundle, full=True)
    assert "archive.members" in failed(report) and "inventory.missing" in failed(report)


@needs_tar
def test_directory_bundle_that_is_a_symlink(ws, tmp_path):
    bundle = extract_with_tar(ws.pack().bundle_path, tmp_path / "bundle")
    link = tmp_path / "link"
    link.symlink_to(bundle, target_is_directory=True)
    assert failed(run(ws, link)) == ["archive.readable"]


@needs_tar
def test_directory_file_swapped_during_verification_is_refused(ws, tmp_path, monkeypatch):
    bundle = extract_with_tar(ws.pack().bundle_path, tmp_path / "bundle")
    real_hash = verify_module._Run._hash
    swapped = []

    def swap_then_hash(self, reader, member, size, out):
        if member.name == "artifacts/docs/LICENSE" and not swapped:
            target = bundle / member.name
            target.unlink()
            target.symlink_to("/etc/hosts")
            swapped.append(member.name)
        return real_hash(self, reader, member, size, out)

    monkeypatch.setattr(verify_module._Run, "_hash", swap_then_hash)
    report = run(ws, bundle)
    assert swapped and failed(report) == ["artifact.digest"]
    assert any("cannot open" in e or "changed" in e for e in report.errors), report.errors


# --------------------------------------------------------------------------- streaming, progress, sink


def test_progress_and_sink_see_every_byte_in_1_mib_chunks(ws):
    big = bytes(range(256)) * (3 * MiB // 256 + 17)
    files = base_files(("artifacts/misc/big.bin", big, {"kind": "document", "fmt": "binary"}))
    source = craft(ws, files)
    seen: list[tuple[int, int]] = []
    sinks: dict[str, io.BytesIO] = {}

    class Keep(io.BytesIO):
        def close(self) -> None:
            pass

    def sink(path: str):
        sinks[path] = Keep()
        return sinks[path]

    report = run(ws, source, progress=lambda done, total: seen.append((done, total)), sink=sink)
    assert report.accepted, report.errors
    total = sum(len(d) for _, d, _ in files)
    assert seen[0] == (0, total) and seen[-1] == (total, total)
    steps = [b - a for (a, _), (b, _) in zip(seen, seen[1:])]
    assert max(steps) <= MiB and len(seen) >= 5
    assert {p: s.getvalue() for p, s in sinks.items()} == {p: d for p, d, _ in files}


def test_sink_files_are_what_format_detection_reads(ws, tmp_path, monkeypatch):
    source = craft(ws)
    opened: list[Path] = []

    def sink(path: str):
        target = tmp_path / f"stage-{len(opened)}"
        opened.append(target)
        return open(target, "w+b")

    real = verify_module.detect_format
    detected_from: list[str] = []

    def spy(fileobj, size, name=""):
        detected_from.append(getattr(fileobj, "name", "?"))
        return real(fileobj, size, name)

    monkeypatch.setattr(verify_module, "detect_format", spy)
    report = run(ws, source, sink=sink)
    assert report.accepted
    assert detected_from == [str(p) for p in opened]


@pytest.mark.skipif(not os.environ.get("FERRY_TEST_PERF"), reason="set FERRY_TEST_PERF=1 for the 512 MiB timing test")
def test_half_a_gigabyte_verifies_in_seconds(ws):
    size = 512 * MiB
    header = {"w": {"dtype": "U8", "shape": [size], "data_offsets": [0, size]}}
    head = safetensors_bytes(header=header, data=b"")
    src = ws.src / "big.safetensors"
    with open(src, "wb") as fh:
        fh.write(head)
        fh.truncate(len(head) + size)
    arts = [{"source": "src/big.safetensors", "path": "models/big.safetensors", "kind": "model", "model": MODEL}]
    res = ws.pack(arts)
    started = time.monotonic()
    report = run(ws, res.bundle_path)
    elapsed = time.monotonic() - started
    print(f"verified {size / MiB:.0f} MiB in {elapsed:.2f} s")
    assert report.accepted, report.errors
    assert elapsed < 10
