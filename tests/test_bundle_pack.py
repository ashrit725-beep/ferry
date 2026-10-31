"""Packing (normalization, determinism, sidecars, refusals), the review sheet checked
with real OpenSSL and sha256sum/shasum, and countersigning."""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from ferry import crypto
from ferry.bundle import load_pack_spec, pack_bundle, sign_bundle, verify_bundle
from ferry.bundle import pack as pack_module
from ferry.errors import Conflict, CryptoError, ValidationFailed

from helpers_bundle import (
    ELF_BYTES, LICENSE_TEXT, MTIME, PICKLE_PROTO4, SHEBANG_BYTES, gguf_bytes, make_signer, make_workspace, read_tar,
    replace_member, rewrite_tar, torch_zip_bytes, write_spec,
)


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def both_roles(ws, **kw):
    return ws.policy(required_roles=("publisher", "reviewer"), **kw)


# --------------------------------------------------------------------------- pack


def test_pack_writes_a_normalized_tar_and_sidecars(ws):
    res = ws.pack()
    assert res.bundle_path.name == "tiny-model-1.0.0.ferry.tar"
    assert res.sha256_path.name == "tiny-model-1.0.0.ferry.tar.sha256"
    assert res.review_path.name == "tiny-model-1.0.0.review.md"
    for p in (res.bundle_path, res.sha256_path, res.review_path):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644
    assert res.sha256_path.read_text() == f"{sha256_file(res.bundle_path)}  tiny-model-1.0.0.ferry.tar\n"
    assert res.tar_sha256 == sha256_file(res.bundle_path) and res.tar_size == res.bundle_path.stat().st_size
    assert res.bundle_path.read_bytes()[:2] != b"\x1f\x8b"

    members = read_tar(res.bundle_path)
    names = [info.name for info, _ in members]
    assert names == ["manifest.json", f"signatures/{ws.publisher.key_id}.sig", "artifacts/docs/LICENSE",
                     "artifacts/models/tiny.gguf", "artifacts/tokenizer/tokenizer.json"]
    for info, _ in members:
        assert info.isreg() and info.mode == 0o644 and info.uid == 0 and info.gid == 0
        assert info.uname == "" and info.gname == "" and info.mtime == MTIME

    manifest_raw = members[0][1]
    signature = members[1][1]
    assert res.bundle_id == "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    assert crypto.verify(ws.publisher.key.public_key(), signature, manifest_raw)
    arts = {a["path"]: a for a in res.manifest["artifacts"]}
    model = arts["artifacts/models/tiny.gguf"]
    assert model["format"] == "gguf" and model["metadata"]["gguf"]["architecture"] == "llama"
    assert model["sha256"] == sha256_file(ws.src / "model.gguf")
    assert arts["artifacts/tokenizer/tokenizer.json"]["format"] == "json"
    assert arts["artifacts/docs/LICENSE"]["format"] == "text"
    assert res.manifest["bundle"]["created_at"] == "2026-10-28T02:00:00.000Z"
    assert res.key_id == ws.publisher.key_id and res.warnings == ()


def test_pack_is_deterministic(ws):
    a = ws.pack(out=ws.root / "a")
    b = ws.pack(out=ws.root / "b")
    assert a.bundle_path.read_bytes() == b.bundle_path.read_bytes()
    assert a.sha256_path.read_text() == b.sha256_path.read_text()
    assert a.review_path.read_text() == b.review_path.read_text()
    c = ws.pack(out=ws.root / "c", created_at="2026-10-29T00:00:00Z")
    assert c.bundle_path.read_bytes() != a.bundle_path.read_bytes() and c.bundle_id != a.bundle_id


def test_pack_accepts_a_datetime_and_normalizes_it(ws):
    res = ws.pack(created_at=dt.datetime(2026, 10, 28, 4, 0, 0, 123456, tzinfo=dt.timezone(dt.timedelta(hours=2))))
    assert res.manifest["bundle"]["created_at"] == "2026-10-28T02:00:00.123Z"
    assert all(info.mtime == MTIME for info, _ in read_tar(res.bundle_path))


@pytest.mark.parametrize("created_at", ["yesterday", "2026-10-28 02:00:00", "1969-12-31T23:59:59Z",
                                        dt.datetime(2026, 10, 28)])
def test_pack_rejects_bad_created_at(ws, created_at):
    with pytest.raises(ValidationFailed):
        ws.pack(created_at=created_at)


def test_pack_refuses_to_overwrite(ws):
    ws.pack()
    with pytest.raises(Conflict):
        ws.pack()


def test_pack_upstream_sha256_mismatch(ws):
    arts = ws.default_artifacts()
    arts[0]["model"]["upstream_sha256"] = "00" * 32
    with pytest.raises(ValidationFailed) as info:
        ws.pack(arts)
    assert "upstream_sha256" in info.value.message and "not the upstream file" in info.value.message
    assert not (ws.root / "out").exists()


def test_pack_upstream_sha256_match_is_case_insensitive_in_the_spec(ws):
    arts = ws.default_artifacts()
    arts[0]["model"]["upstream_sha256"] = sha256_file(ws.src / "model.gguf").upper()
    res = ws.pack(arts)
    assert res.manifest["artifacts"][0]["model"]["upstream_sha256"] == sha256_file(ws.src / "model.gguf")


@pytest.mark.parametrize("data, kind, expected", [
    (PICKLE_PROTO4, "model", "pickle content"),
    (torch_zip_bytes(), "model", "pickle content"),
    (ELF_BYTES, "document", "executable content"),
    (SHEBANG_BYTES, "document", "executable content"),
    (gzip.compress(b"nested"), "document", "nested archive"),
])
def test_pack_refuses_content_the_default_policy_rejects(ws, data, kind, expected):
    src = ws.add_source("unsafe.bin", data)
    art = {"source": src, "path": "files/unsafe.bin", "kind": kind}
    if kind == "model":
        art["model"] = {"name": "unsafe", "license": "MIT"}
    with pytest.raises(ValidationFailed) as info:
        ws.pack([art])
    assert expected in info.value.message and "--allow-unsafe" in info.value.message


def test_pack_allow_unsafe_packs_with_a_loud_warning(ws):
    src = ws.add_source("weights.pkl", PICKLE_PROTO4)
    res = ws.pack([*ws.default_artifacts(), {"source": src, "path": "extra/weights.pkl", "kind": "document"}],
                  allow_unsafe=True)
    assert any(w.startswith("UNSAFE: artifacts/extra/weights.pkl") for w in res.warnings)
    review = res.review_path.read_text()
    assert "- Pickle content: YES: `artifacts/extra/weights.pkl`" in review
    assert "Warnings from packing" in review


def test_pack_never_packs_malformed_gguf(ws):
    src = ws.add_source("broken.gguf", gguf_bytes(version=1))
    art = {"source": src, "path": "models/broken.gguf", "kind": "model", "model": {"name": "x", "license": "MIT"}}
    for allow_unsafe in (False, True):
        with pytest.raises(ValidationFailed) as info:
            ws.pack([art], allow_unsafe=allow_unsafe)
        assert "malformed GGUF" in info.value.message


def test_pack_model_must_be_a_model_format(ws):
    src = ws.add_source("model.txt", b"not weights\n")
    art = {"source": src, "path": "models/model.txt", "kind": "model", "model": {"name": "x", "license": "MIT"}}
    with pytest.raises(ValidationFailed) as info:
        ws.pack([art], allow_unsafe=True)
    assert "must be GGUF or safetensors" in info.value.message


def test_pack_warns_where_the_default_import_policy_would_reject(ws):
    arts = ws.default_artifacts()
    arts[0]["model"]["license"] = "GPL-3.0-only"
    arts.append({"source": "src/LICENSE", "path": "misc/LICENSE.copy", "kind": "file"})
    res = ws.pack(arts)
    assert any("licence 'GPL-3.0-only'" in w for w in res.warnings)
    assert any("kind 'file' is not allowed" in w for w in res.warnings)


def test_pack_follows_symlinked_sources(ws):
    # Hugging Face caches keep model files as symlinks to blobs.
    (ws.src / "blob").write_bytes(gguf_bytes())
    (ws.src / "linked.gguf").symlink_to(ws.src / "blob")
    arts = ws.default_artifacts()
    arts[0]["source"] = "src/linked.gguf"
    assert ws.pack(arts).manifest["artifacts"][0]["format"] == "gguf"


@pytest.mark.parametrize("bundle, artifacts, extra, expected", [
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "[other]\nk = 1\n",
     "unknown key other"),
    ({"name": "x", "version": "1", "colour": "red"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "",
     "unknown key bundle.colour"),
    ({"name": "X Y", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "", "bundle.name"),
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "../escape", "kind": "document"}], "",
     "artifacts[0].path"),
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "weights"}], "", "artifacts[0].kind"),
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "model"}], "", "needs a 'model'"),
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "document",
                                      "model": {"name": "m", "license": "MIT"}}], "", "only allowed when kind is 'model'"),
    ({"name": "x", "version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "document", "format": "text"}],
     "", "unknown key artifacts[0].format"),
    ({"name": "x", "version": "1"}, [], "", "at least one [[artifacts]]"),
    ({"version": "1"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "", "bundle.name is required"),
    # Refused on the connected side: the receiving host's rollback check could not order them.
    ({"name": "x", "version": "latest"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "",
     "bundle.version: version 'latest' cannot be ordered for rollback protection"),
    ({"name": "x", "version": "1.x"}, [{"source": "src/LICENSE", "path": "a", "kind": "document"}], "",
     "publish versions as MAJOR.MINOR.PATCH"),
])
def test_pack_spec_errors(ws, bundle, artifacts, extra, expected):
    spec = write_spec(ws.root / "bad.toml", bundle=bundle, artifacts=artifacts, extra=extra)
    with pytest.raises(ValidationFailed) as info:
        load_pack_spec(spec)
    assert expected in info.value.message


@pytest.mark.parametrize("version", ["1", "1.2.0", "v1.2.0", "1.2.0-rc.1", "1.2.0rc1", "2.0.0+build.7"])
def test_pack_spec_accepts_versions_rollback_protection_can_order(ws, version):
    spec = write_spec(ws.root / "ok.toml", bundle={"name": "x", "version": version},
                      artifacts=[{"source": "src/LICENSE", "path": "a", "kind": "document"}])
    assert load_pack_spec(spec).version == version


def test_pack_spec_not_toml_and_missing_source(ws):
    bad = ws.root / "bad.toml"
    bad.write_text("[bundle\n")
    with pytest.raises(ValidationFailed, match="invalid TOML"):
        load_pack_spec(bad)
    with pytest.raises(ValidationFailed, match="cannot read source"):
        ws.pack([{"source": "src/missing.bin", "path": "a", "kind": "document"}])


def test_pack_reports_progress(ws):
    seen: list[tuple[int, int]] = []
    pack_bundle(ws.spec(), ws.publisher.key, ws.root / "out", created_at="2026-10-28T02:00:00Z",
                progress=lambda done, total: seen.append((done, total)))
    sizes = sum((ws.src / n).stat().st_size for n in ("model.gguf", "tokenizer.json", "LICENSE"))
    assert seen[0] == (0, 2 * sizes) and seen[-1] == (2 * sizes, 2 * sizes)
    assert [d for d, _ in seen] == sorted(d for d, _ in seen)


def test_pack_detects_a_source_that_changes_while_packing(ws, monkeypatch):
    real = pack_module._write_tar

    def tamper_then_write(*args, **kwargs):
        (ws.src / "LICENSE").write_bytes(LICENSE_TEXT.replace(b"2.0", b"9.9"))  # same size, new bytes
        return real(*args, **kwargs)

    monkeypatch.setattr(pack_module, "_write_tar", tamper_then_write)
    with pytest.raises(Exception, match="changed while it was being packed"):
        ws.pack()
    assert not list((ws.root / "out").glob("*"))


def test_pack_refuses_a_fifo_source_without_blocking(ws):
    os.mkfifo(ws.src / "pipe")
    with pytest.raises(ValidationFailed, match="not a regular file"):
        ws.pack([{"source": "src/pipe", "path": "docs/pipe", "kind": "document"}])


def test_pack_and_sign_need_an_ed25519_private_key(ws):
    with pytest.raises(CryptoError):
        pack_bundle(ws.spec(), "not a key", ws.root / "out")  # type: ignore[arg-type]
    res = ws.pack()
    with pytest.raises(CryptoError):
        sign_bundle(res.bundle_path, ws.reviewer.pem)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- review sheet


def test_review_sheet_contents(ws):
    res = ws.pack()
    text = res.review_path.read_text()
    manifest_hex = res.bundle_id.removeprefix("sha256:")
    for needle in [res.bundle_id, res.tar_sha256, ws.publisher.key_id, manifest_hex,
                   "`https://example.invalid/tiny-model @ abc123`", "`Apache-2.0`",
                   "- Pickle content: none", "- Executables: none", "- Nested archives: none",
                   f"openssl pkeyutl -verify -pubin -inkey <pub.pem> -rawin -in manifest.json -sigfile "
                   f"signatures/{ws.publisher.key_id}.sig",
                   "sha256sum -c <<'EOF'", "shasum -a 256 -c <<'EOF'", "tar -tvf tiny-model-1.0.0.ferry.tar"]:
        assert needle in text, needle
    for art in res.manifest["artifacts"]:
        assert f"{art['sha256']}  {art['path']}" in text


def test_review_sheet_neutralizes_markdown_in_the_description(ws):
    res = ws.pack(description="![beacon](http://tracker.invalid/p.png)\n```\nbreak out")
    text = res.review_path.read_text()
    lines = text.splitlines()
    start = lines.index("````text")
    assert lines[start + 1].startswith("![beacon]") and lines[start + 4] == "````"


def openssl_binary() -> str | None:
    """An OpenSSL (not LibreSSL) binary, which is what Ed25519 `-rawin` verification needs."""
    for candidate in (shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/local/opt/openssl/bin/openssl",
                      "/usr/local/bin/openssl", "/usr/bin/openssl"):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            version = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=10).stdout
        except OSError:
            continue
        if version.startswith("OpenSSL"):
            return candidate
    return None


def sha256_check_command() -> list[str]:
    return ["sha256sum", "-c", "-"] if shutil.which("sha256sum") else ["shasum", "-a", "256", "-c", "-"]


def heredoc(text: str, opener: str) -> str:
    lines = text.splitlines()
    start = lines.index(opener) + 1
    return "\n".join(lines[start:lines.index("EOF", start)]) + "\n"


@pytest.mark.skipif(shutil.which("tar") is None, reason="needs a tar binary")
def test_review_sheet_commands_verify_the_bundle_without_ferry(ws, tmp_path):
    openssl = openssl_binary()
    if openssl is None:
        pytest.skip("no OpenSSL binary found (LibreSSL cannot verify Ed25519)")
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    text = res.review_path.read_text()
    review = tmp_path / "review"
    review.mkdir()
    listing = subprocess.run(["tar", "-tvf", str(res.bundle_path)], capture_output=True, text=True, check=True).stdout
    assert all(line.startswith("-rw-r--r--") for line in listing.splitlines())
    subprocess.run(["tar", "-xf", str(res.bundle_path), "-C", str(review)], check=True)

    keys = {}
    for signer in (ws.publisher, ws.reviewer):
        pem = tmp_path / f"{signer.name}.pub.pem"
        pem.write_bytes(signer.pem)
        keys[signer.key_id] = pem
    command = next(line for line in text.splitlines() if line.startswith("openssl pkeyutl -verify"))
    for kid, pem in keys.items():
        argv = shlex.split(command.replace("<pub.pem>", str(pem)).replace(ws.publisher.key_id, kid))
        argv[0] = openssl
        ok = subprocess.run(argv, cwd=review, capture_output=True, text=True)
        assert ok.returncode == 0 and "Signature Verified Successfully" in ok.stdout, ok.stdout + ok.stderr
        digest = " ".join(map(shlex.quote, sha256_check_command()[:-2]))
        keyid = subprocess.run(["bash", "-c", f"{shlex.quote(openssl)} pkey -pubin -in {shlex.quote(str(pem))} "
                                f"-outform DER | tail -c 32 | {digest}"], capture_output=True, text=True, check=True)
        assert keyid.stdout.split()[0] == kid

    sums = heredoc(text, "sha256sum -c <<'EOF'")
    assert sums == heredoc(text, "shasum -a 256 -c <<'EOF'")
    check = subprocess.run(sha256_check_command(), input=sums, cwd=review, capture_output=True, text=True)
    assert check.returncode == 0 and check.stdout.count(": OK") == 3, check.stdout + check.stderr
    manifest_digest = hashlib.sha256((review / "manifest.json").read_bytes()).hexdigest()
    assert f"Expected: `{manifest_digest}`" in text

    # The same independent checks catch tampering.
    with open(review / "artifacts/docs/LICENSE", "ab") as fh:
        fh.write(b"!")
    assert subprocess.run(sha256_check_command(), input=sums, cwd=review, capture_output=True,
                          text=True).returncode != 0
    (review / "manifest.json").write_bytes((review / "manifest.json").read_bytes().replace(b"Tiny", b"Tinz"))
    argv = shlex.split(command.replace("<pub.pem>", str(keys[ws.publisher.key_id])))
    argv[0] = openssl
    assert subprocess.run(argv, cwd=review, capture_output=True).returncode != 0


# --------------------------------------------------------------------------- countersign


def test_countersign_appends_a_normalized_signature(ws):
    res = ws.pack()
    before = res.bundle_path.read_bytes()
    signed = sign_bundle(res.bundle_path, ws.reviewer.key)
    after = res.bundle_path.read_bytes()
    assert signed.bundle_id == res.bundle_id and signed.key_id == ws.reviewer.key_id
    assert signed.signature_member == f"signatures/{ws.reviewer.key_id}.sig"
    assert signed.sidecar_updated and res.sha256_path.read_text() == f"{sha256_file(res.bundle_path)}  {res.bundle_path.name}\n"
    assert signed.tar_sha256 == sha256_file(res.bundle_path) != res.tar_sha256
    with tarfile.open(fileobj=io.BytesIO(before)) as tf:
        tf.getmembers()
        end_of_members = tf.offset
    assert after[:end_of_members] == before[:end_of_members]
    members = read_tar(res.bundle_path)
    info, sig = members[-1]
    assert info.name == f"signatures/{ws.reviewer.key_id}.sig" and info.mode == 0o644 and info.mtime == MTIME
    assert info.uid == 0 and info.uname == ""
    assert crypto.verify(ws.reviewer.key.public_key(), sig, members[0][1])
    report = verify_bundle(res.bundle_path, both_roles(ws), ws.trust_store())
    assert report.accepted, report.errors


def test_countersign_is_deterministic(ws):
    a, b = ws.pack(out=ws.root / "a"), ws.pack(out=ws.root / "b")
    sign_bundle(a.bundle_path, ws.reviewer.key)
    sign_bundle(b.bundle_path, ws.reviewer.key)
    assert a.bundle_path.read_bytes() == b.bundle_path.read_bytes()


def test_countersign_refuses_double_signing(ws):
    res = ws.pack()
    sign_bundle(res.bundle_path, ws.reviewer.key)
    snapshot = res.bundle_path.read_bytes()
    for key in (ws.reviewer.key, ws.publisher.key):
        with pytest.raises(Conflict, match="already signed"):
            sign_bundle(res.bundle_path, key)
    assert res.bundle_path.read_bytes() == snapshot


def test_countersign_refuses_a_tampered_bundle(ws):
    res = ws.pack()
    tampered = ws.root / "tampered.ferry.tar"
    rewrite_tar(res.bundle_path, tampered,
                lambda ms: replace_member(ms, "artifacts/docs/LICENSE", LICENSE_TEXT.replace(b"2.0", b"2.1")))
    snapshot = tampered.read_bytes()
    with pytest.raises(ValidationFailed) as info:
        sign_bundle(tampered, ws.reviewer.key)
    assert "integrity check" in info.value.message and "SHA-256" in info.value.message
    assert info.value.details["report"]["verdict"] == "rejected"
    assert tampered.read_bytes() == snapshot


def test_countersign_restores_the_tar_if_appending_fails(ws, monkeypatch):
    res = ws.pack()
    snapshot = res.bundle_path.read_bytes()
    real = pack_module.member_info
    monkeypatch.setattr(pack_module, "member_info", lambda name, size, mtime: real(name, size + 1, mtime))
    with pytest.raises(OSError):
        sign_bundle(res.bundle_path, ws.reviewer.key)
    assert res.bundle_path.read_bytes() == snapshot


def test_countersign_refuses_while_another_process_holds_the_bundle(ws):
    import fcntl

    res = ws.pack()
    snapshot = res.bundle_path.read_bytes()
    with open(res.bundle_path, "rb") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX)
        with pytest.raises(Conflict, match="another process"):
            sign_bundle(res.bundle_path, ws.reviewer.key)
    assert res.bundle_path.read_bytes() == snapshot


@pytest.mark.skipif(shutil.which("tar") is None, reason="needs a tar binary")
def test_countersign_a_directory_bundle(ws, tmp_path):
    res = ws.pack()
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    subprocess.run(["tar", "-xf", str(res.bundle_path), "-C", str(extracted)], check=True)
    signed = sign_bundle(extracted, ws.reviewer.key)
    sig = extracted / "signatures" / f"{ws.reviewer.key_id}.sig"
    assert signed.tar_sha256 is None and sig.stat().st_size == 64
    assert stat.S_IMODE(sig.stat().st_mode) == 0o644
    assert sorted(p.name for p in (extracted / "signatures").iterdir()) == sorted(
        [f"{ws.publisher.key_id}.sig", f"{ws.reviewer.key_id}.sig"])
    report = verify_bundle(extracted, both_roles(ws), ws.trust_store())
    assert report.accepted and report.source["type"] == "dir", report.errors
    with pytest.raises(Conflict):
        sign_bundle(extracted, ws.reviewer.key)


def test_countersign_with_an_unrelated_key_still_needs_trust_at_import(ws):
    res = ws.pack()
    stranger = make_signer("stranger")
    sign_bundle(res.bundle_path, stranger.key)
    report = verify_bundle(res.bundle_path, both_roles(ws), ws.trust_store())
    assert not report.accepted
    assert {s["key_id"]: s["status"] for s in report.signatures}[stranger.key_id] == "untrusted"


def test_pack_output_is_rejected_when_bytes_are_flipped(ws):
    res = ws.pack()
    data = bytearray(res.bundle_path.read_bytes())
    offset = data.index(b"Apache License")
    data[offset] ^= 0x20
    res.bundle_path.write_bytes(bytes(data))
    report = verify_bundle(res.bundle_path, ws.policy(), ws.trust_store())
    assert not report.accepted and any(re.search("SHA-256 is [0-9a-f]{64}", e) for e in report.errors)
