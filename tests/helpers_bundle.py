"""Builders for bundle tests: tiny valid GGUF and safetensors files, signers, pack
specs, and hand-made tar files (malicious ones included) signed with real keys.

Malicious tars are built member by member with tarfile.TarInfo, so each test
introduces exactly one defect while everything else stays valid; that is how
the tests show that each check fails for its own reason. Pickle test data is
written as raw opcode bytes by hand; nothing here pickles or imports anything.
"""

from __future__ import annotations

import io
import json
import struct
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ferry import crypto
from ferry.bundle import PackResult, VerificationReport, pack_bundle
from ferry.config import ImportSettings
from ferry.manifest import build_manifest, dump_manifest
from ferry.trust import TrustStore, add_key, load_trust_store
from ferry.util import parse_rfc3339, sha256_hex

CREATED_AT = "2026-10-28T02:00:00.000Z"
MTIME = int(parse_rfc3339(CREATED_AT).timestamp())
MODEL = {"name": "tiny-model", "license": "Apache-2.0"}

# --------------------------------------------------------------------------- GGUF

T_U8, T_I8, T_U16, T_I16, T_U32, T_I32, T_F32, T_BOOL, T_STR, T_ARR, T_U64, T_I64, T_F64 = range(13)
_SCALAR = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<B", 10: "<Q", 11: "<q", 12: "<d"}


def f32(*values: float) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


def gguf_str(value: str | bytes) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return struct.pack("<Q", len(raw)) + raw


def gguf_value(vtype: int, value: Any) -> bytes:
    if vtype in _SCALAR:
        return struct.pack(_SCALAR[vtype], value)
    if vtype == T_STR:
        return gguf_str(value)
    if vtype == T_ARR:
        etype, items = value
        return struct.pack("<IQ", etype, len(items)) + b"".join(gguf_value(etype, v) for v in items)
    raise ValueError(vtype)


def gguf_kv(key: str | bytes, vtype: int, value: Any) -> bytes:
    return gguf_str(key) + struct.pack("<I", vtype) + gguf_value(vtype, value)


@dataclass
class GTensor:
    name: str | bytes
    dims: list[int]
    ggml_type: int = 0
    data: bytes = b""
    offset: int | None = None  # None: laid out after the previous tensor


def default_kvs() -> list[tuple[str, int, Any]]:
    return [
        ("general.architecture", T_STR, "llama"),
        ("general.name", T_STR, "tiny-test"),
        ("general.file_type", T_U32, 0),
        ("general.alignment", T_U32, 32),
        ("general.license", T_STR, "apache-2.0"),
        ("llama.context_length", T_U32, 2048),
        ("tokenizer.ggml.tokens", T_ARR, (T_STR, ["<s>", "</s>", "hello"])),
        ("tokenizer.ggml.scores", T_ARR, (T_F32, [0.0, 0.0, -1.5])),
    ]


def default_tensors() -> list[GTensor]:
    return [GTensor("token_embd.weight", [4, 2], 0, f32(*range(8))),
            GTensor("output_norm.weight", [4], 0, f32(1, 1, 1, 1))]


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def gguf_bytes(*, version: int = 3, kvs: list[tuple[str, int, Any]] | None = None,
               tensors: list[GTensor] | None = None, alignment: int = 32, magic: bytes = b"GGUF",
               tensor_count: int | None = None, kv_count: int | None = None, raw_kv: bytes | None = None) -> bytes:
    """A GGUF file. Defaults: v3, a few metadata KVs, two small F32 tensors, 32-byte alignment."""
    kvs = default_kvs() if kvs is None else kvs
    tensors = default_tensors() if tensors is None else tensors
    head = magic + struct.pack("<I", version) + struct.pack(
        "<QQ", len(tensors) if tensor_count is None else tensor_count, len(kvs) if kv_count is None else kv_count)
    body = raw_kv if raw_kv is not None else b"".join(gguf_kv(k, t, v) for k, t, v in kvs)
    offsets, cursor, region = [], 0, 0
    for t in tensors:
        off = cursor if t.offset is None else t.offset
        offsets.append(off)
        if t.offset is None:
            cursor = _align(off + len(t.data), alignment)
            region = max(region, cursor)
    infos = b"".join(gguf_str(t.name) + struct.pack("<I", len(t.dims)) + b"".join(struct.pack("<Q", d) for d in t.dims)
                     + struct.pack("<IQ", t.ggml_type, off) for t, off in zip(tensors, offsets))
    header = head + body + infos
    data = bytearray(region)
    for t, off in zip(tensors, offsets):
        if off + len(t.data) <= region:
            data[off:off + len(t.data)] = t.data
    return header + b"\x00" * (_align(len(header), alignment) - len(header)) + bytes(data)


# --------------------------------------------------------------------------- safetensors


def default_st_tensors() -> dict[str, tuple[str, list[int], bytes]]:
    return {"weight": ("F32", [2, 3], f32(*range(6))), "bias": ("F32", [3], f32(0, 0, 0))}


def safetensors_bytes(tensors: dict[str, tuple[str, list[int], bytes]] | None = None, *,
                      metadata: dict[str, Any] | None = None, header: Any = None, data: bytes | None = None,
                      header_len: int | None = None, pad: bool = True) -> bytes:
    """A safetensors file; `header` (dict/str/bytes) and `data` override the computed parts."""
    blob = b""
    if header is None:
        header = {}
        if metadata is not None:
            header["__metadata__"] = metadata
        for name, (dtype, shape, raw) in (default_st_tensors() if tensors is None else tensors).items():
            header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [len(blob), len(blob) + len(raw)]}
            blob += raw
    text = header if isinstance(header, (str, bytes)) else json.dumps(header)
    raw_header = text.encode("utf-8") if isinstance(text, str) else text
    if pad:
        raw_header += b" " * (-len(raw_header) % 8)
    n = len(raw_header) if header_len is None else header_len
    return struct.pack("<Q", n) + raw_header + (blob if data is None else data)


# --------------------------------------------------------------------------- other content

# Hand-written opcode bytes: PROTO 4, FRAME, SHORT_BINUNICODE "hello", MEMOIZE, STOP.
PICKLE_PROTO4 = b"\x80\x04\x95\x09\x00\x00\x00\x00\x00\x00\x00\x8c\x05hello\x94."
# PROTO 2, BININT1 1, STOP.
PICKLE_PROTO2 = b"\x80\x02K\x01."
ELF_BYTES = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
SHEBANG_BYTES = b"#!/bin/sh\necho hello\n"
TOKENIZER_JSON = b'{"version": "1.0", "model": {"type": "BPE", "vocab": {"a": 0, "b": 1}}}\n'
LICENSE_TEXT = b"Apache License\nVersion 2.0, January 2004\n"


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def torch_zip_bytes() -> bytes:
    """The layout of a torch.save() archive, with a harmless hand-written pickle."""
    return zip_bytes({"archive/data.pkl": PICKLE_PROTO2, "archive/version": b"3\n"})


def tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --------------------------------------------------------------------------- signers and trust


@dataclass
class Signer:
    name: str
    key: Ed25519PrivateKey

    @property
    def pem(self) -> bytes:
        return crypto.public_key_to_pem(self.key.public_key())

    @property
    def key_id(self) -> str:
        return crypto.key_id(self.key.public_key())

    def sign(self, data: bytes) -> bytes:
        return crypto.sign(self.key, data)


def make_signer(name: str) -> Signer:
    return Signer(name, crypto.generate_private_key())


# --------------------------------------------------------------------------- pack specs


def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    raise TypeError(type(value))


def write_spec(path: Path, *, bundle: dict[str, Any], artifacts: list[dict[str, Any]],
               requires: dict[str, Any] | None = None, extra: str = "") -> Path:
    lines = ["[bundle]", *(f"{k} = {_toml(v)}" for k, v in bundle.items())]
    if requires:
        lines += ["", "[requires]", *(f"{k} = {_toml(v)}" for k, v in requires.items())]
    for art in artifacts:
        lines += ["", "[[artifacts]]", *(f"{k} = {_toml(v)}" for k, v in art.items() if k != "model")]
        if art.get("model") is not None:
            lines += ["[artifacts.model]", *(f"{k} = {_toml(v)}" for k, v in art["model"].items())]
    path.write_text("\n".join(lines) + "\n" + extra, encoding="utf-8")
    return path


@dataclass
class Workspace:
    root: Path
    src: Path
    publisher: Signer
    reviewer: Signer
    trust_dir: Path

    def default_artifacts(self) -> list[dict[str, Any]]:
        return [
            {"source": "src/model.gguf", "path": "models/tiny.gguf", "kind": "model",
             "model": {**MODEL, "source_uri": "https://example.invalid/tiny-model", "source_revision": "abc123"}},
            {"source": "src/tokenizer.json", "path": "tokenizer/tokenizer.json", "kind": "tokenizer"},
            {"source": "src/LICENSE", "path": "docs/LICENSE", "kind": "document"},
        ]

    def add_source(self, name: str, data: bytes) -> str:
        (self.src / name).write_bytes(data)
        return f"src/{name}"

    def spec(self, artifacts: list[dict[str, Any]] | None = None, *, name: str = "tiny-model",
             version: str = "1.0.0", description: str = "Tiny test model",
             requires: dict[str, Any] | None = None, spec_name: str = "bundle.toml") -> Path:
        return write_spec(self.root / spec_name, bundle={"name": name, "version": version, "description": description},
                          artifacts=self.default_artifacts() if artifacts is None else artifacts,
                          requires=requires if requires is not None else {"ferry_min_version": "0.1.0",
                                                                          "runtime": "llama.cpp"})

    def pack(self, artifacts: list[dict[str, Any]] | None = None, *, out: Path | None = None,
             signer: Signer | None = None, allow_unsafe: bool = False, created_at: str = CREATED_AT,
             **spec_kw: Any) -> PackResult:
        spec = self.spec(artifacts, **spec_kw)
        return pack_bundle(spec, (signer or self.publisher).key, out or self.root / "out", created_at=created_at,
                           allow_unsafe=allow_unsafe)

    def trust_store(self) -> TrustStore:
        return load_trust_store(self.trust_dir)

    def policy(self, **overrides: Any) -> ImportSettings:
        return ImportSettings(**{"trust_dir": str(self.trust_dir), **overrides})


def make_workspace(base: Path) -> Workspace:
    """Sources (GGUF model, tokenizer JSON, licence), a publisher and a reviewer key,
    and a trust store holding each with its role."""
    root = base / "ws"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "model.gguf").write_bytes(gguf_bytes())
    (src / "tokenizer.json").write_bytes(TOKENIZER_JSON)
    (src / "LICENSE").write_bytes(LICENSE_TEXT)
    publisher, reviewer = make_signer("publisher"), make_signer("reviewer")
    trust_dir = root / "trust"
    add_key(trust_dir, publisher.pem, name="Acme build", roles=["publisher"])
    add_key(trust_dir, reviewer.pem, name="Acme review", roles=["reviewer"])
    return Workspace(root, src, publisher, reviewer, trust_dir)


# --------------------------------------------------------------------------- hand-made tars

TarEntry = tuple[tarfile.TarInfo, "bytes | None"]


def tar_member(name: str, data: bytes = b"", *, type: bytes = tarfile.REGTYPE, mode: int = 0o644,
               linkname: str = "", mtime: int = MTIME) -> TarEntry:
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.mtime = type, mode, mtime
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    if type in (tarfile.REGTYPE, tarfile.AREGTYPE):
        info.size = len(data)
        return info, data
    info.linkname = linkname
    info.size = 0
    return info, None


def write_tar(path: Path, members: Iterable[TarEntry], *, format: int = tarfile.PAX_FORMAT) -> Path:
    with tarfile.open(path, "w", format=format) as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def read_tar(path: Path) -> list[TarEntry]:
    """Members and bytes of a test tar (reads members; never extracts)."""
    out: list[TarEntry] = []
    with tarfile.open(path, "r:") as tf:
        for info in tf.getmembers():
            fh = tf.extractfile(info) if info.isreg() else None
            out.append((info, fh.read() if fh else None))
    return out


def rewrite_tar(src: Path, dst: Path, transform: Callable[[list[TarEntry]], list[TarEntry]]) -> Path:
    return write_tar(dst, transform(read_tar(src)))


def replace_member(members: list[TarEntry], name: str, data: bytes) -> list[TarEntry]:
    out: list[TarEntry] = []
    for info, old in members:
        if info.name == name:
            info.size = len(data)
            out.append((info, data))
        else:
            out.append((info, old))
    return out


def artifact_entry(path: str, data: bytes, *, kind: str = "document", fmt: str = "text",
                   model: dict[str, Any] | None = None, size: int | None = None, sha256: str | None = None) -> dict[str, Any]:
    return {"path": path, "size": len(data) if size is None else size, "sha256": sha256 or sha256_hex(data),
            "kind": kind, "format": fmt, "model": model, "metadata": {}}


def manifest_bytes(entries: list[dict[str, Any]], *, name: str = "crafted", version: str = "1.0.0",
                   requires: dict[str, Any] | None = None, mutate: Callable[[dict[str, Any]], None] | None = None,
                   validate: bool = True) -> bytes:
    doc = build_manifest(name=name, version=version, created_at=CREATED_AT, description="crafted for a test",
                         requires=requires or {}, artifacts=entries)
    if mutate is not None:
        mutate(doc)
    if validate:
        return dump_manifest(doc, ImportSettings(max_artifacts=100_000))
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def signed_tar(path: Path, manifest: bytes, signers: Iterable[Signer], files: Iterable[tuple[str, bytes]] = (),
               *, extra: Iterable[TarEntry] = (), signed_bytes: bytes | None = None) -> Path:
    members = [tar_member("manifest.json", manifest)]
    members += [tar_member(f"signatures/{s.key_id}.sig", s.sign(signed_bytes or manifest)) for s in signers]
    members += [tar_member(name, data) for name, data in files]
    members += list(extra)
    return write_tar(path, members)


def crafted_bundle(path: Path, signers: Iterable[Signer], files: list[tuple[str, bytes, dict[str, Any]]], *,
                   extra: Iterable[TarEntry] = (), **manifest_kw: Any) -> Path:
    """A signed tar whose manifest lists `files` [(path, data, artifact_entry kwargs)]."""
    entries = [artifact_entry(p, d, **kw) for p, d, kw in files]
    raw = manifest_bytes(entries, **manifest_kw)
    return signed_tar(path, raw, signers, [(p, d) for p, d, _ in files], extra=extra)


def statuses(report: VerificationReport) -> dict[str, str]:
    return {c["id"]: c["status"] for c in report.checks}


def failed(report: VerificationReport) -> list[str]:
    return [c["id"] for c in report.checks if c["status"] == "fail"]
