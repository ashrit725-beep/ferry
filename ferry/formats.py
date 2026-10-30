"""Content-based file format detection with bounded GGUF and safetensors validation.

A format is decided from the bytes, never from a file name or from what a
manifest declares: a pickle renamed to `.bin` is still pickle (the
CVE-2025-10155 class of scanner bypass). Names are only ever used to be *more*
suspicious: a `.py` file is an executable, and a `.pt` file that is neither
GGUF nor safetensors is treated as pickle.

The GGUF and safetensors parsers are written for hostile input (GGUF parsers
in inference runtimes had overflow bugs in 2024, 2025 and 2026). Every count
and length is checked against a fixed bound and against the bytes actually
present before anything is skipped, nothing is allocated from an untrusted
count, and headers are read through a 1 MiB window. Nothing here imports,
unpickles or executes file content: ZIP members are only listed by name, and
the one pickle check is a static opcode scan (`pickletools.genops`), which
decodes opcodes without building objects.
"""

from __future__ import annotations

import codecs
import io
import json
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import IO, Any

FORMATS = ("gguf", "safetensors", "pickle", "json", "text", "binary", "executable", "archive")

MiB = 1024 * 1024
_HEAD_BYTES = 4096
_WINDOW = MiB

GGUF_MAGIC = b"GGUF"
GGUF_VERSIONS = (2, 3)
GGUF_MAX_KV = 65_536
GGUF_MAX_TENSORS = 1_000_000
GGUF_MAX_STRING = 16 * MiB
GGUF_MAX_KEY = 65_535
GGUF_MAX_ARRAY = 16_000_000
GGUF_MAX_ARRAY_DEPTH = 2
GGUF_MAX_DIMS = 4
GGUF_MAX_GGML_TYPE = 64
GGUF_MAX_TENSOR_NAME = 64
GGUF_MAX_HEADER = 256 * MiB
GGUF_DEFAULT_ALIGNMENT = 32
GGUF_MAX_ALIGNMENT = MiB

SAFETENSORS_MIN_HEADER = 8
SAFETENSORS_MAX_HEADER = 100 * MiB
SAFETENSORS_MAX_DIMS = 64
SAFETENSORS_DTYPES: dict[str, int] = {
    "F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "I16": 2, "I8": 1,
    "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1, "U16": 2, "U32": 4, "U64": 8,
}

JSON_MAX_BYTES = 64 * MiB
TEXT_SNIFF_BYTES = MiB
ZIP_MAX_DIRECTORY = 16 * MiB

PICKLE_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib")
EXECUTABLE_EXTENSIONS = (".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".so", ".dylib")

# llama.cpp `llama_ftype` values, as stored in general.file_type.
LLAMA_FTYPES: dict[int, str] = {
    0: "ALL_F32", 1: "MOSTLY_F16", 2: "MOSTLY_Q4_0", 3: "MOSTLY_Q4_1", 4: "MOSTLY_Q4_1_SOME_F16",
    5: "MOSTLY_Q4_2", 6: "MOSTLY_Q4_3", 7: "MOSTLY_Q8_0", 8: "MOSTLY_Q5_0", 9: "MOSTLY_Q5_1",
    10: "MOSTLY_Q2_K", 11: "MOSTLY_Q3_K_S", 12: "MOSTLY_Q3_K_M", 13: "MOSTLY_Q3_K_L",
    14: "MOSTLY_Q4_K_S", 15: "MOSTLY_Q4_K_M", 16: "MOSTLY_Q5_K_S", 17: "MOSTLY_Q5_K_M",
    18: "MOSTLY_Q6_K", 19: "MOSTLY_IQ2_XXS", 20: "MOSTLY_IQ2_XS", 21: "MOSTLY_Q2_K_S",
    22: "MOSTLY_IQ3_XS", 23: "MOSTLY_IQ3_XXS", 24: "MOSTLY_IQ1_S", 25: "MOSTLY_IQ4_NL",
    26: "MOSTLY_IQ3_S", 27: "MOSTLY_IQ3_M", 28: "MOSTLY_IQ2_S", 29: "MOSTLY_IQ2_M",
    30: "MOSTLY_IQ4_XS", 31: "MOSTLY_IQ1_M", 32: "MOSTLY_BF16", 33: "MOSTLY_Q4_0_4_4",
    34: "MOSTLY_Q4_0_4_8", 35: "MOSTLY_Q4_0_8_8", 36: "MOSTLY_TQ1_0", 37: "MOSTLY_TQ2_0",
    38: "MOSTLY_MXFP4_MOE",
}

# ggml tensor types: id -> (name, elements per block, bytes per block). Ids that
# ggml removed (4, 5, 31-33, 36-38) are absent on purpose: their sizes are not
# checked and the parser reports a warning instead (docs/design/v1-additions.md A3).
GGML_TYPES: dict[int, tuple[str, int, int]] = {
    0: ("F32", 1, 4), 1: ("F16", 1, 2), 2: ("Q4_0", 32, 18), 3: ("Q4_1", 32, 20),
    6: ("Q5_0", 32, 22), 7: ("Q5_1", 32, 24), 8: ("Q8_0", 32, 34), 9: ("Q8_1", 32, 36),
    10: ("Q2_K", 256, 84), 11: ("Q3_K", 256, 110), 12: ("Q4_K", 256, 144), 13: ("Q5_K", 256, 176),
    14: ("Q6_K", 256, 210), 15: ("Q8_K", 256, 292), 16: ("IQ2_XXS", 256, 66), 17: ("IQ2_XS", 256, 74),
    18: ("IQ3_XXS", 256, 98), 19: ("IQ1_S", 256, 50), 20: ("IQ4_NL", 32, 18), 21: ("IQ3_S", 256, 110),
    22: ("IQ2_S", 256, 82), 23: ("IQ4_XS", 256, 136), 24: ("I8", 1, 1), 25: ("I16", 1, 2),
    26: ("I32", 1, 4), 27: ("I64", 1, 8), 28: ("F64", 1, 8), 29: ("IQ1_M", 256, 56),
    30: ("BF16", 1, 2), 34: ("TQ1_0", 256, 54), 35: ("TQ2_0", 256, 66), 39: ("MXFP4", 32, 17),
}

_T_STRING, _T_ARRAY = 8, 9
_GGUF_SCALARS: dict[int, tuple[str, int]] = {
    0: ("<B", 1), 1: ("<b", 1), 2: ("<H", 2), 3: ("<h", 2), 4: ("<I", 4), 5: ("<i", 4),
    6: ("<f", 4), 7: ("<B", 1), 10: ("<Q", 8), 11: ("<q", 8), 12: ("<d", 8),
}
_GGUF_INTEGERS = frozenset({0, 1, 2, 3, 4, 5, 10, 11})
_GGUF_KEPT = frozenset({"general.architecture", "general.name", "general.file_type",
                        "general.alignment", "general.license"})
_ARCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

# Opcodes through which a pickle reaches importable code. Without one of
# these nothing callable can reach the unpickler's stack.
_PICKLE_IMPORT_OPS = frozenset({"GLOBAL", "STACK_GLOBAL", "INST", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID"})

_DISPLAY_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")
_MULTILINE_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")


def has_unsafe_text(value: str, multiline: bool = False) -> bool:
    """True if `value` contains control, zero-width or bidi-override characters
    (tab and newline are allowed when `multiline`)."""
    return bool((_MULTILINE_UNSAFE if multiline else _DISPLAY_UNSAFE).search(value))


def strict_json_loads(text: str) -> Any:
    """json.loads that also rejects duplicate keys and NaN/Infinity (ValueError).
    Deep nesting raises RecursionError."""
    return json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)


def clean_text(value: str, limit: int = 256) -> str:
    """An untrusted string made safe to print: control and bidi characters replaced, length bounded."""
    text = _DISPLAY_UNSAFE.sub("�", value)
    return text if len(text) <= limit else text[:limit] + "…"


def quote_untrusted(value: str, limit: int = 120) -> str:
    """A quoted, fully escaped rendering of an untrusted name for error messages.

    Member names and keys come from the bundle; escaping keeps terminal control
    sequences and bidi overrides out of CLI output and logs.
    """
    clipped = value if len(value) <= limit else value[:limit]
    return json.dumps(clipped, ensure_ascii=True) + ("…" if clipped is not value else "")


@dataclass
class FormatInfo:
    """What a file is. Non-empty `problems` means the content is (or claims to be)
    a structured format but is malformed; such a file is never acceptable."""

    format: str
    metadata: dict[str, Any] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {"format": self.format, "metadata": dict(self.metadata),
                "problems": list(self.problems), "warnings": list(self.warnings)}


class _Malformed(Exception):
    """Raised inside a parser; the message becomes a FormatInfo problem."""


def _read_at(fh: IO[bytes], offset: int, n: int) -> bytes:
    fh.seek(offset)
    parts: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = fh.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class _Window:
    """Forward reads over the start of a file through a bounded buffer.

    Each read is checked against the file size and the header budget before
    any bytes are requested, so a hostile length can make parsing fail but
    never makes it allocate or read past the budget.
    """

    def __init__(self, fh: IO[bytes], size: int, budget: int):
        self._fh = fh
        self._size = size
        self._budget = budget
        self._end = min(size, budget)
        self._buf = b""
        self._base = 0
        self._off = 0

    @property
    def pos(self) -> int:
        return self._base + self._off

    def _check(self, n: int, what: str) -> None:
        end = self.pos + n
        if end > self._size:
            raise _Malformed(f"truncated: {what} at offset {self.pos} needs {n:,} bytes but the file is {self._size:,} bytes")
        if end > self._budget:
            raise _Malformed(f"header is larger than the {self._budget // MiB} MiB limit")

    def _fill(self, n: int) -> None:
        start = self.pos
        tail = self._buf[self._off:]
        want = min(max(n - len(tail), _WINDOW), self._end - start - len(tail))
        data = _read_at(self._fh, start + len(tail), want)
        if len(data) != want:
            raise _Malformed(f"file ended early at offset {start + len(tail) + len(data):,}")
        self._buf = tail + data
        self._base = start
        self._off = 0

    def take(self, n: int, what: str) -> bytes:
        if self._off + n > len(self._buf):
            self._check(n, what)
            self._fill(n)
        data = self._buf[self._off:self._off + n]
        self._off += n
        return data

    def skip(self, n: int, what: str) -> None:
        if self._off + n <= len(self._buf):
            self._off += n
            return
        self._check(n, what)
        self._base = self.pos + n
        self._buf = b""
        self._off = 0

    def unpack(self, fmt: str, width: int, what: str) -> Any:
        if self._off + width > len(self._buf):
            self._check(width, what)
            self._fill(width)
        (value,) = struct.unpack_from(fmt, self._buf, self._off)
        self._off += width
        return value


# --------------------------------------------------------------------------- GGUF


def parse_gguf(fh: IO[bytes], size: int) -> FormatInfo:
    """Validate a GGUF header (v2/v3, little-endian) and extract its metadata."""
    meta: dict[str, Any] = {}
    warnings: list[str] = []
    try:
        _parse_gguf(fh, size, meta, warnings)
    except _Malformed as exc:
        return FormatInfo("gguf", meta, [f"malformed GGUF: {exc}"], warnings)
    return FormatInfo("gguf", meta, [], warnings)


def _parse_gguf(fh: IO[bytes], size: int, meta: dict[str, Any], warnings: list[str]) -> None:
    r = _Window(fh, size, GGUF_MAX_HEADER)
    if r.take(4, "magic") != GGUF_MAGIC:
        raise _Malformed("missing GGUF magic")
    version = r.unpack("<I", 4, "version")
    if version not in GGUF_VERSIONS:
        if version == 1:
            raise _Malformed("GGUF version 1 is not supported (versions 2 and 3 are)")
        if version in (0x02000000, 0x03000000):
            raise _Malformed("big-endian GGUF files are not supported")
        raise _Malformed(f"unsupported GGUF version {version}")
    meta["version"] = version
    n_tensors = r.unpack("<Q", 8, "tensor count")
    n_kv = r.unpack("<Q", 8, "metadata count")
    if n_tensors > GGUF_MAX_TENSORS:
        raise _Malformed(f"tensor count {n_tensors:,} exceeds the limit of {GGUF_MAX_TENSORS:,}")
    if n_kv > GGUF_MAX_KV:
        raise _Malformed(f"metadata count {n_kv:,} exceeds the limit of {GGUF_MAX_KV:,}")

    kept: dict[str, tuple[int, Any]] = {}
    seen: set[str] = set()
    for index in range(n_kv):
        key = _gguf_key(r, index)
        if key in seen:
            raise _Malformed(f"duplicate metadata key {quote_untrusted(key)}")
        seen.add(key)
        vtype = r.unpack("<I", 4, f"value type of {key}")
        keep = key in _GGUF_KEPT or key.endswith(".context_length")
        value = _gguf_value(r, vtype, key, keep, 0)
        if keep:
            kept[key] = (vtype, value)

    alignment = GGUF_DEFAULT_ALIGNMENT
    if "general.alignment" in kept:
        vtype, value = kept["general.alignment"]
        if vtype != 4:
            raise _Malformed("general.alignment must be a uint32")
        if value == 0 or value & (value - 1) or value > GGUF_MAX_ALIGNMENT:
            raise _Malformed(f"general.alignment {value} is not a power of two between 1 and {GGUF_MAX_ALIGNMENT}")
        alignment = value

    arch = _gguf_text(kept, "general.architecture")
    if arch is None:
        raise _Malformed("general.architecture is missing")
    if not _ARCH.fullmatch(arch):
        raise _Malformed(f"general.architecture {quote_untrusted(arch)} is not a valid architecture name")
    name = _gguf_text(kept, "general.name")
    license_id = _gguf_text(kept, "general.license")
    file_type = _gguf_int(kept, "general.file_type")
    context_length = _gguf_int(kept, f"{arch}.context_length")

    names: set[str] = set()
    tensors: list[tuple[int, int, int, str, int]] = []
    parameters = 0
    for index in range(n_tensors):
        n = r.unpack("<Q", 8, f"name length of tensor {index}")
        if n == 0:
            raise _Malformed(f"tensor {index} has an empty name")
        if n > GGUF_MAX_TENSOR_NAME:
            raise _Malformed(f"tensor {index} name is {n:,} bytes; the limit is {GGUF_MAX_TENSOR_NAME}")
        try:
            tname = r.take(n, f"name of tensor {index}").decode("utf-8")
        except UnicodeDecodeError:
            raise _Malformed(f"tensor {index} name is not valid UTF-8") from None
        if tname in names:
            raise _Malformed(f"duplicate tensor name {quote_untrusted(tname)}")
        names.add(tname)
        n_dims = r.unpack("<I", 4, f"dimension count of tensor {index}")
        if not 1 <= n_dims <= GGUF_MAX_DIMS:
            raise _Malformed(f"tensor {quote_untrusted(tname)} has {n_dims} dimensions; 1 to {GGUF_MAX_DIMS} are allowed")
        elements = 1
        first_dim = 0
        for d in range(n_dims):
            dim = r.unpack("<Q", 8, f"dimensions of tensor {index}")
            if dim < 1:
                raise _Malformed(f"tensor {quote_untrusted(tname)} has a zero dimension")
            if d == 0:
                first_dim = dim
            elements *= dim
        if elements >= 2**63:
            raise _Malformed(f"tensor {quote_untrusted(tname)} has more than 2^63 elements")
        ggml_type = r.unpack("<I", 4, f"type of tensor {index}")
        if ggml_type >= GGUF_MAX_GGML_TYPE:
            raise _Malformed(f"tensor {quote_untrusted(tname)} has invalid ggml type {ggml_type}")
        offset = r.unpack("<Q", 8, f"offset of tensor {index}")
        tensors.append((offset, ggml_type, elements, tname, first_dim))
        parameters += elements

    data_start = _align(r.pos, alignment)
    if n_tensors and data_start > size:
        raise _Malformed("tensor data would start past the end of the file")
    _check_tensor_data(tensors, alignment, max(size - data_start, 0), warnings)

    meta.update({
        "architecture": arch,
        "name": name,
        "file_type": None if file_type is None else LLAMA_FTYPES.get(file_type, f"type_{file_type}"),
        "context_length": context_length,
        "tensor_count": n_tensors,
        "parameter_count": parameters,
    })
    if license_id is not None:
        meta["license"] = license_id


def _gguf_key(r: _Window, index: int) -> str:
    n = r.unpack("<Q", 8, f"length of metadata key {index}")
    if n == 0:
        raise _Malformed(f"metadata key {index} is empty")
    if n > GGUF_MAX_KEY:
        raise _Malformed(f"metadata key {index} is {n:,} bytes; the limit is {GGUF_MAX_KEY:,}")
    try:
        return r.take(n, f"metadata key {index}").decode("utf-8")
    except UnicodeDecodeError:
        raise _Malformed(f"metadata key {index} is not valid UTF-8") from None


def _gguf_value(r: _Window, vtype: int, key: str, keep: bool, depth: int) -> Any:
    scalar = _GGUF_SCALARS.get(vtype)
    if scalar is not None:
        if keep:
            return r.unpack(scalar[0], scalar[1], key)
        r.skip(scalar[1], key)
        return None
    if vtype == _T_STRING:
        n = r.unpack("<Q", 8, f"string length of {key}")
        if n > GGUF_MAX_STRING:
            raise _Malformed(f"string value of {quote_untrusted(key)} is {n:,} bytes; the limit is 16 MiB")
        if keep:
            return r.take(n, key)
        r.skip(n, key)
        return None
    if vtype == _T_ARRAY:
        if depth >= GGUF_MAX_ARRAY_DEPTH:
            raise _Malformed(f"{quote_untrusted(key)}: arrays are nested more than {GGUF_MAX_ARRAY_DEPTH} deep")
        etype = r.unpack("<I", 4, f"array type of {key}")
        count = r.unpack("<Q", 8, f"array length of {key}")
        if count > GGUF_MAX_ARRAY:
            raise _Malformed(f"array {quote_untrusted(key)} has {count:,} elements; the limit is {GGUF_MAX_ARRAY:,}")
        element = _GGUF_SCALARS.get(etype)
        if element is not None:
            r.skip(count * element[1], key)
        elif etype == _T_STRING:
            for _ in range(count):
                n = r.unpack("<Q", 8, key)
                if n > GGUF_MAX_STRING:
                    raise _Malformed(f"a string in {quote_untrusted(key)} is {n:,} bytes; the limit is 16 MiB")
                r.skip(n, key)
        elif etype == _T_ARRAY:
            for _ in range(count):
                _gguf_value(r, _T_ARRAY, key, False, depth + 1)
        else:
            raise _Malformed(f"array {quote_untrusted(key)} has unknown element type {etype}")
        return ("array", etype, count)
    raise _Malformed(f"{quote_untrusted(key)} has unknown value type {vtype}")


def _gguf_text(kept: dict[str, tuple[int, Any]], key: str) -> str | None:
    if key not in kept:
        return None
    vtype, value = kept[key]
    if vtype != _T_STRING:
        raise _Malformed(f"{key} must be a string")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise _Malformed(f"{key} is not valid UTF-8") from None
    return text if key == "general.architecture" else clean_text(text)


def _gguf_int(kept: dict[str, tuple[int, Any]], key: str) -> int | None:
    if key not in kept:
        return None
    vtype, value = kept[key]
    if vtype not in _GGUF_INTEGERS:
        raise _Malformed(f"{quote_untrusted(key)} must be an integer")
    return int(value)


def _check_tensor_data(tensors: list[tuple[int, int, int, str, int]], alignment: int, data_size: int,
                       warnings: list[str]) -> None:
    """Offsets aligned and inside the data region; for known ggml types, byte
    sizes computed with exact integer arithmetic must fit and must not overlap."""
    spans: list[tuple[int, int, str]] = []
    unknown: set[int] = set()
    for offset, ggml_type, elements, tname, first_dim in tensors:
        if offset % alignment:
            raise _Malformed(f"tensor {quote_untrusted(tname)} offset {offset:,} is not a multiple of the alignment {alignment}")
        if offset >= data_size:
            raise _Malformed(f"tensor {quote_untrusted(tname)} offset {offset:,} is beyond the end of the file "
                             f"(tensor data region is {data_size:,} bytes)")
        layout = GGML_TYPES.get(ggml_type)
        if layout is None:
            unknown.add(ggml_type)
            continue
        type_name, block, block_bytes = layout
        if first_dim % block:
            raise _Malformed(f"tensor {quote_untrusted(tname)} of type {type_name} has {first_dim:,} elements per row, "
                             f"not a multiple of the block size {block}")
        nbytes = elements // block * block_bytes
        if offset + nbytes > data_size:
            raise _Malformed(f"tensor {quote_untrusted(tname)} needs {nbytes:,} bytes at offset {offset:,}, "
                             f"past the end of the file")
        spans.append((offset, offset + nbytes, tname))
    spans.sort()
    for (_, end, first), (start, _, second) in zip(spans, spans[1:]):
        if start < end:
            raise _Malformed(f"tensors {quote_untrusted(first)} and {quote_untrusted(second)} overlap")
    if unknown:
        ids = ", ".join(str(t) for t in sorted(unknown))
        warnings.append(f"ggml type(s) {ids} are not known to Ferry; the byte sizes of those tensors were not checked")
        return
    unused, cursor = 0, 0
    for start, end, _ in spans:
        unused += max(start - _align(cursor, alignment), 0)
        cursor = end
    unused += max(data_size - _align(cursor, alignment), 0)
    if unused:
        warnings.append(f"{unused:,} bytes of the tensor data region are not used by any tensor")


# --------------------------------------------------------------------------- safetensors


def parse_safetensors(fh: IO[bytes], size: int) -> FormatInfo:
    """Validate a safetensors file: bounded header, strict JSON, known dtypes,
    sizes that match shapes, and tensors that cover the data region exactly."""
    meta: dict[str, Any] = {}
    try:
        _parse_safetensors(fh, size, meta)
    except _Malformed as exc:
        return FormatInfo("safetensors", meta, [f"malformed safetensors: {exc}"])
    return FormatInfo("safetensors", meta)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {quote_untrusted(key)}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _safetensors_header_length(fh: IO[bytes], size: int) -> int:
    if size < 8:
        raise _Malformed("file is shorter than the 8-byte header length")
    (n,) = struct.unpack("<Q", _read_at(fh, 0, 8))
    if n < SAFETENSORS_MIN_HEADER:
        raise _Malformed(f"header length {n} is below the minimum of {SAFETENSORS_MIN_HEADER}")
    if n > SAFETENSORS_MAX_HEADER:
        raise _Malformed(f"header length {n:,} bytes exceeds the 100 MiB limit")
    if n + 8 > size:
        raise _Malformed(f"header length {n:,} runs past the end of the {size:,}-byte file")
    return n


def _parse_safetensors(fh: IO[bytes], size: int, meta: dict[str, Any]) -> None:
    n = _safetensors_header_length(fh, size)
    raw = _read_at(fh, 8, n)
    if len(raw) != n:
        raise _Malformed("file ended inside the header")
    if raw[:1] != b"{":
        raise _Malformed("header does not start with '{'")
    try:
        doc = strict_json_loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise _Malformed("header is not valid UTF-8") from None
    except RecursionError:
        raise _Malformed("header JSON is nested too deeply") from None
    except ValueError as exc:
        raise _Malformed(f"header is not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise _Malformed("header is not a JSON object")

    data_len = size - 8 - n
    spans: list[tuple[int, int, str]] = []
    dtypes: set[str] = set()
    parameters = 0
    for name, entry in doc.items():
        if name == "__metadata__":
            if not isinstance(entry, dict) or not all(isinstance(v, str) for v in entry.values()):
                raise _Malformed("__metadata__ must map strings to strings")
            continue
        where = f"tensor {quote_untrusted(name)}"
        if not isinstance(entry, dict):
            raise _Malformed(f"{where} is not an object")
        fields_ = set(entry)
        if fields_ != {"dtype", "shape", "data_offsets"}:
            extra = sorted(fields_ - {"dtype", "shape", "data_offsets"})
            missing = sorted({"dtype", "shape", "data_offsets"} - fields_)
            detail = f"unknown field(s) {', '.join(map(quote_untrusted, extra))}" if extra else f"missing {', '.join(missing)}"
            raise _Malformed(f"{where}: {detail}")
        dtype, shape, offsets = entry["dtype"], entry["shape"], entry["data_offsets"]
        if not isinstance(dtype, str) or dtype not in SAFETENSORS_DTYPES:
            raise _Malformed(f"{where} has unknown dtype {quote_untrusted(str(dtype))}")
        if (not isinstance(shape, list) or len(shape) > SAFETENSORS_MAX_DIMS
                or not all(_is_int(d) and d >= 0 for d in shape)):
            raise _Malformed(f"{where} has an invalid shape")
        if not (isinstance(offsets, list) and len(offsets) == 2 and all(_is_int(o) for o in offsets)):
            raise _Malformed(f"{where} has invalid data_offsets")
        begin, end = offsets
        if not 0 <= begin <= end:
            raise _Malformed(f"{where} has data_offsets [{begin}, {end}]; begin must not exceed end")
        if end > data_len:
            raise _Malformed(f"{where} data_offsets [{begin}, {end}] lie outside the {data_len:,}-byte data region")
        elements = 1
        for d in shape:
            elements *= d
        expected = elements * SAFETENSORS_DTYPES[dtype]
        if end - begin != expected:
            raise _Malformed(f"{where} occupies {end - begin:,} bytes but a {dtype} tensor of shape "
                             f"{str(shape)[:80]} needs {expected:,}")
        spans.append((begin, end, name))
        dtypes.add(dtype)
        parameters += elements

    spans.sort()
    cursor = 0
    for begin, end, name in spans:
        if begin < cursor:
            raise _Malformed(f"tensor {quote_untrusted(name)} overlaps the preceding tensor")
        if begin > cursor:
            raise _Malformed(f"{begin - cursor:,} bytes before tensor {quote_untrusted(name)} are not covered by any tensor")
        cursor = end
    if cursor != data_len:
        raise _Malformed(f"the last {data_len - cursor:,} bytes of the data region are not covered by any tensor")
    meta.update({"tensor_count": len(spans), "parameter_count": parameters, "dtypes": sorted(dtypes)})


def _safetensors_shaped(head: bytes) -> bool:
    # A small little-endian header length followed by '{'.
    return len(head) >= 9 and head[8:9] == b"{" and head[5:8] == b"\x00\x00\x00"


# --------------------------------------------------------------------------- containers and magic numbers


def _executable_magic(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "mach-o"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return "mach-o-fat"
    if head[:2] == b"MZ":
        return "pe"
    if head[:2] == b"#!":
        return "script"
    return None


def _raw_pickle(head: bytes) -> bool:
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _archive_magic(head: bytes) -> str | None:
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[257:262] == b"ustar":
        return "tar"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[3:4] != b"0" and head[4:10] in (b"1AY&SY", b"\x17rE8P\x90"):
        return "bzip2"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if head[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    return None


class _ReadLimit(OSError):
    pass


class _CappedView:
    """Seekable read-only view for zipfile that refuses any single read above
    `cap` bytes, so a hostile central-directory size cannot make it allocate."""

    def __init__(self, fh: IO[bytes], size: int, cap: int):
        self._fh, self._size, self._cap, self._pos = fh, size, cap, 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self._pos, 2: self._size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def read(self, n: int | None = -1) -> bytes:
        remaining = max(self._size - self._pos, 0)
        n = remaining if n is None or n < 0 else min(n, remaining)
        if n > self._cap:
            raise _ReadLimit(f"refusing a {n:,}-byte read")
        data = _read_at(self._fh, self._pos, n)
        self._pos += len(data)
        return data


@dataclass
class _ZipProbe:
    is_zip: bool
    names: list[str]
    error: str | None


def _probe_zip(fh: IO[bytes], size: int, head: bytes) -> _ZipProbe:
    magic = head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    view = _CappedView(fh, size, ZIP_MAX_DIRECTORY)
    try:
        has_directory = zipfile.is_zipfile(view)  # type: ignore[arg-type]
    except Exception:
        has_directory = False
    if not has_directory:
        return _ZipProbe(magic, [], "no end of central directory record" if magic else None)
    try:
        with zipfile.ZipFile(view) as zf:  # type: ignore[arg-type]
            names = zf.namelist()
    except Exception as exc:  # any parser failure on hostile input
        if magic:
            return _ZipProbe(True, [], f"central directory could not be read ({type(exc).__name__})")
        return _ZipProbe(False, [], None)
    return _ZipProbe(True, names, None)


def _pickle_members(names: list[str]) -> list[str]:
    return [n for n in names if n.lower().endswith((".pkl", ".pickle"))]


def _zip_format(probe: _ZipProbe, polyglot: str | None = None) -> FormatInfo:
    meta: dict[str, Any] = {"container": "zip"}
    if polyglot:
        meta["polyglot"] = polyglot
    if probe.error:
        return FormatInfo("archive", meta, [f"ZIP archive could not be listed: {probe.error}"])
    meta["member_count"] = len(probe.names)
    pickles = _pickle_members(probe.names)
    if pickles:
        meta["pickle_members"] = [clean_text(n, 128) for n in pickles[:10]]
        return FormatInfo("pickle", meta)
    return FormatInfo("archive", meta)


def _pickle_polyglot(prefix: bytes) -> bool:
    """True if `prefix`, read as a pickle stream, reaches an importing opcode or
    runs off its end. Static disassembly only: no object is ever built."""
    import pickletools

    stream = io.BytesIO(prefix)
    try:
        for opcode, _arg, _pos in pickletools.genops(stream):
            if opcode.name in _PICKLE_IMPORT_OPS:
                return True
            if opcode.name == "STOP":
                return False
    except Exception:
        # Undecodable bytes stop a real unpickler at the same place; running out
        # of bytes means the stream would continue past the header.
        return stream.tell() >= len(prefix)
    return True


def _headerless_pickle(fh: IO[bytes], size: int) -> bool:
    """True if the file, read by an unpickler from its first byte, reaches GLOBAL,
    INST or STACK_GLOBAL although it has no PROTO header (pickle protocols 0 and 1,
    which start with ordinary bytes). Static disassembly of the first MiB only.

    Stack and MARK depth are tracked so that text and binary files, on which an
    unpickler fails within a few bytes, are not flagged; everything else errs
    towards pickle: STOP starts another scan (loaders may read several pickles
    in a row) and running out of window while the file goes on counts as pickle.
    """
    import pickletools
    import warnings

    data = _read_at(fh, 0, min(size, _WINDOW))
    stream = io.BytesIO(data)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # pickletools warns on backslashes in text lines
            return _scan_headerless(pickletools, stream, data, size)
    except Exception:
        # Undecodable bytes stop an unpickler at the same place; running out of
        # window while the file goes on means the stream may continue.
        return stream.tell() >= len(data) and size > len(data)


def _scan_headerless(pickletools: Any, stream: io.BytesIO, data: bytes, size: int) -> bool:
    puts = ("PUT", "BINPUT", "LONG_BINPUT")
    while stream.tell() < len(data):
        depth, marks = 0, []  # objects above the topmost MARK; depths saved by MARKs
        for opcode, arg, _pos in pickletools.genops(stream):
            name, before = opcode.name, opcode.stack_before
            after = 1 if name in puts else len(opcode.stack_after)
            if name in ("GLOBAL", "INST"):
                module = str(arg).split(" ", 1)[0]
                if all(part.isidentifier() for part in module.split(".")):
                    return True
                return False  # nothing by that name can be imported: the unpickler stops
            if name == "STACK_GLOBAL" and depth >= 2:
                return True
            if pickletools.markobject in before:
                at = before.index(pickletools.markobject)
                if not marks or depth < len(before) - at - 2:
                    return False
                depth = marks.pop()
                before = before[:at]
            elif name == "POP" and depth == 0:
                if not marks:
                    return False
                depth = marks.pop()
                continue
            elif name in puts:
                before = [pickletools.anyobject]  # stores the top of the stack, which must exist
            if depth < len(before):
                return False  # stack underflow: the unpickler fails at this opcode
            depth -= len(before)
            if pickletools.markobject in opcode.stack_after:
                marks.append(depth)
                depth = 0
            else:
                depth += after
        # STOP: loaders may read another pickle from what follows
    return size > len(data)


def _pe_header(fh: IO[bytes], size: int) -> bool:
    if size < 64:
        return False
    (e_lfanew,) = struct.unpack("<I", _read_at(fh, 0x3C, 4))
    return e_lfanew + 4 <= size and _read_at(fh, e_lfanew, 4) == b"PE\x00\x00"


def _is_json(fh: IO[bytes], size: int) -> bool:
    if size > JSON_MAX_BYTES:
        return False
    try:
        json.loads(_read_at(fh, 0, size).decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    return True


def _is_text(fh: IO[bytes], size: int) -> bool:
    data = _read_at(fh, 0, min(size, TEXT_SNIFF_BYTES))
    if b"\x00" in data:
        return False
    try:
        codecs.getincrementaldecoder("utf-8")().decode(data, final=size <= TEXT_SNIFF_BYTES)
    except UnicodeDecodeError:
        return False
    return True


def _with_polyglot_checks(info: FormatInfo, probe: _ZipProbe) -> FormatInfo:
    # A GGUF or safetensors file that is also a listable ZIP could be opened as
    # a torch archive by another tool; classify it by its most dangerous reading.
    if probe.is_zip and not probe.error:
        return _zip_format(probe, polyglot=info.format)
    return info


def detect_format(fileobj: IO[bytes], size: int, name: str = "") -> FormatInfo:
    """Decide what `fileobj` (seekable, `size` bytes) contains, from its bytes.

    `name` is only used to be stricter: a `.safetensors` name makes malformed
    content a safetensors problem rather than "binary", and pickle or
    executable extensions classify content that is not GGUF or safetensors.
    """
    head = _read_at(fileobj, 0, min(size, _HEAD_BYTES))
    if len(head) != min(size, _HEAD_BYTES):
        return FormatInfo("binary", {}, [f"file is shorter than its stated size of {size:,} bytes"])
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    probe = _probe_zip(fileobj, size, head)

    if head[:4] == GGUF_MAGIC:
        return _with_polyglot_checks(parse_gguf(fileobj, size), probe)

    safetensors: FormatInfo | None = None
    if _safetensors_shaped(head) or base.endswith(".safetensors"):
        safetensors = parse_safetensors(fileobj, size)
        if safetensors.ok:
            if _raw_pickle(head):
                header_end = 8 + struct.unpack("<Q", head[:8])[0]
                if _pickle_polyglot(_read_at(fileobj, 0, header_end)):
                    return FormatInfo("pickle", {"container": "raw", "polyglot": "safetensors"})
            if head[:2] == b"MZ" and _pe_header(fileobj, size):
                return FormatInfo("executable", {"kind": "pe", "polyglot": "safetensors"})
            return _with_polyglot_checks(safetensors, probe)

    kind = _executable_magic(head)
    if kind:
        return FormatInfo("executable", {"kind": kind})
    if _raw_pickle(head):
        return FormatInfo("pickle", {"container": "raw", "protocol": head[1]})
    if _headerless_pickle(fileobj, size):
        return FormatInfo("pickle", {"container": "raw", "header": "none"})
    if probe.is_zip:
        return _zip_format(probe)
    container = _archive_magic(head)
    if container:
        return FormatInfo("archive", {"container": container})
    if base.endswith(PICKLE_EXTENSIONS):
        return FormatInfo("pickle", {"container": "unknown", "reason": "file extension"})
    if base.endswith(EXECUTABLE_EXTENSIONS):
        return FormatInfo("executable", {"kind": "file extension"})
    if safetensors is not None:
        return safetensors
    if _is_json(fileobj, size):
        return FormatInfo("json")
    if _is_text(fileobj, size):
        return FormatInfo("text")
    return FormatInfo("binary")
