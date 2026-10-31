"""Content-based format detection and the bounded GGUF / safetensors parsers."""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import pickle
import struct
import tarfile
from pathlib import Path

import pytest

from ferry import formats
from ferry.bundle import verify_bundle
from ferry.formats import FormatInfo, detect_format, parse_gguf, parse_safetensors, quote_untrusted, clean_text

from helpers_bundle import (
    MODEL, crafted_bundle, failed, make_workspace,
    ELF_BYTES, LICENSE_TEXT, PICKLE_PROTO2, PICKLE_PROTO4, SHEBANG_BYTES, T_ARR, T_F32, T_STR, T_U8, T_U32, T_U64,
    TOKENIZER_JSON, GTensor, default_kvs, f32, gguf_bytes, gguf_kv, gguf_str, safetensors_bytes, tar_bytes,
    torch_zip_bytes, zip_bytes,
)

MiB = 1024 * 1024


def detect(data: bytes, name: str = "file") -> FormatInfo:
    return detect_format(io.BytesIO(data), len(data), name)


def gguf_problem(data: bytes) -> str:
    info = parse_gguf(io.BytesIO(data), len(data))
    assert info.format == "gguf"
    assert len(info.problems) == 1, info
    return info.problems[0]


def st_problem(data: bytes) -> str:
    info = parse_safetensors(io.BytesIO(data), len(data))
    assert info.format == "safetensors"
    assert len(info.problems) == 1, info
    return info.problems[0]


def kvs_without(*keys: str) -> list:
    return [kv for kv in default_kvs() if kv[0] not in keys]


# --------------------------------------------------------------------------- GGUF: valid files


def test_tiny_gguf_is_detected_with_metadata():
    info = detect(gguf_bytes(), "models/tiny.gguf")
    assert info.format == "gguf" and info.ok and not info.warnings
    assert info.metadata == {
        "version": 3, "architecture": "llama", "name": "tiny-test", "file_type": "ALL_F32",
        "context_length": 2048, "tensor_count": 2, "parameter_count": 12, "license": "apache-2.0",
    }


def test_gguf_detection_ignores_the_name():
    assert detect(gguf_bytes(), "weights.bin").format == "gguf"
    assert detect(gguf_bytes(), "notes.txt").format == "gguf"


def test_gguf_version_2_is_accepted():
    info = detect(gguf_bytes(version=2))
    assert info.ok and info.metadata["version"] == 2


@pytest.mark.parametrize("file_type, name", [(15, "MOSTLY_Q4_K_M"), (7, "MOSTLY_Q8_0"), (4242, "type_4242")])
def test_gguf_file_type_names(file_type, name):
    kvs = [(k, t, file_type if k == "general.file_type" else v) for k, t, v in default_kvs()]
    assert detect(gguf_bytes(kvs=kvs)).metadata["file_type"] == name


def test_gguf_optional_keys_may_be_absent_and_alignment_defaults_to_32():
    kvs = kvs_without("general.name", "general.file_type", "general.alignment", "general.license", "llama.context_length")
    info = detect(gguf_bytes(kvs=kvs))
    assert info.ok
    assert info.metadata["name"] is None and info.metadata["context_length"] is None
    assert "license" not in info.metadata


def test_gguf_with_no_tensors_is_valid():
    info = detect(gguf_bytes(tensors=[]))
    assert info.ok and info.metadata["tensor_count"] == 0 and info.metadata["parameter_count"] == 0


def test_gguf_arrays_nested_two_deep_are_accepted():
    kvs = default_kvs() + [("test.nested", T_ARR, (T_ARR, [(T_U8, [1, 2]), (T_U8, [3])]))]
    assert detect(gguf_bytes(kvs=kvs)).ok


def test_gguf_strings_are_cleaned_for_display():
    kvs = [(k, t, "evil\x1b[31mname‮" if k == "general.name" else v) for k, t, v in default_kvs()]
    name = detect(gguf_bytes(kvs=kvs)).metadata["name"]
    assert "\x1b" not in name and "‮" not in name and name.startswith("evil")


def test_gguf_unknown_ggml_type_is_a_warning_not_a_problem():
    tensors = [GTensor("a", [4], 0, f32(1, 2, 3, 4)), GTensor("b", [4], 4, f32(1, 2, 3, 4))]  # 4 was Q4_2, removed
    info = detect(gguf_bytes(tensors=tensors))
    assert info.ok
    assert any("not known to Ferry" in w for w in info.warnings)


def test_gguf_unused_trailing_bytes_are_a_warning():
    info = detect(gguf_bytes() + b"\x00" * 4096)
    assert info.ok
    assert any("not used by any tensor" in w for w in info.warnings)


def test_gguf_quantized_block_sizes_are_accounted_exactly():
    # Q4_0 (type 2): blocks of 32 elements in 18 bytes.
    tensors = [GTensor("q", [64, 2], 2, b"\x01" * (4 * 18))]
    info = detect(gguf_bytes(tensors=tensors))
    assert info.ok and not info.warnings


# --------------------------------------------------------------------------- GGUF: malformed files


def test_gguf_bad_magic_is_not_gguf():
    data = gguf_bytes(magic=b"GGUX")
    assert detect(data, "model.gguf").format == "binary"
    assert "missing GGUF magic" in gguf_problem(data)


@pytest.mark.parametrize("version, expected", [
    (1, "version 1 is not supported"),
    (0x03000000, "big-endian"),
    (4, "unsupported GGUF version 4"),
])
def test_gguf_versions(version, expected):
    assert expected in gguf_problem(gguf_bytes(version=version))


def test_gguf_absurd_tensor_count():
    assert "tensor count 1,099,511,627,776 exceeds the limit of 1,000,000" in gguf_problem(gguf_bytes(tensor_count=2**40))


def test_gguf_absurd_kv_count():
    assert "metadata count 65,537 exceeds" in gguf_problem(gguf_bytes(kv_count=65_537))


def test_gguf_counts_larger_than_the_file_fail_as_truncated():
    assert "truncated" in gguf_problem(b"GGUF" + struct.pack("<IQQ", 3, 0, 60_000))
    arch = gguf_kv("general.architecture", T_STR, "llama")
    assert "truncated" in gguf_problem(b"GGUF" + struct.pack("<IQQ", 3, 900_000, 1) + arch)
    # Inflated counts over real content fail on the first impossible field, never by allocating.
    assert "malformed GGUF" in gguf_problem(gguf_bytes(kv_count=60_000))


@pytest.mark.parametrize("cut", [10, 30, 60, 200])
def test_gguf_truncated_header(cut):
    data = gguf_bytes()[:cut]
    problem = gguf_problem(data)
    assert "truncated" in problem
    assert detect(data, "x.gguf").problems


@pytest.mark.parametrize("dims, expected", [
    ([1, 1, 1, 1, 1], "has 5 dimensions; 1 to 4 are allowed"),
    ([], "has 0 dimensions"),
    ([4, 0], "has a zero dimension"),
    ([2**32, 2**31], "more than 2^63 elements"),
])
def test_gguf_bad_dimensions(dims, expected):
    assert expected in gguf_problem(gguf_bytes(tensors=[GTensor("t", dims, 0, f32(1, 2, 3, 4))]))


def test_gguf_offset_beyond_file():
    tensors = [GTensor("a", [4], 0, f32(1, 2, 3, 4)), GTensor("b", [4], 0, b"", offset=4096)]
    assert "offset 4,096 is beyond the end of the file" in gguf_problem(gguf_bytes(tensors=tensors))


def test_gguf_misaligned_offset():
    tensors = [GTensor("a", [2], 0, f32(1, 2)), GTensor("b", [2], 0, f32(1, 2), offset=8)]
    assert "offset 8 is not a multiple of the alignment 32" in gguf_problem(gguf_bytes(tensors=tensors))


@pytest.mark.parametrize("alignment, expected", [
    ((T_U32, 48), "is not a power of two"),
    ((T_U32, 0), "is not a power of two"),
    ((T_U32, 2**21), "is not a power of two"),
    ((T_U64, 32), "must be a uint32"),
])
def test_gguf_bad_alignment_key(alignment, expected):
    vtype, value = alignment
    kvs = kvs_without("general.alignment") + [("general.alignment", vtype, value)]
    assert expected in gguf_problem(gguf_bytes(kvs=kvs))


def test_gguf_custom_alignment_is_honoured():
    kvs = kvs_without("general.alignment") + [("general.alignment", T_U32, 64)]
    tensors = [GTensor("a", [4], 0, f32(1, 2, 3, 4)), GTensor("b", [4], 0, f32(1, 2, 3, 4))]
    assert detect(gguf_bytes(kvs=kvs, tensors=tensors, alignment=64)).ok
    tensors[1].offset = 32
    assert "not a multiple of the alignment 64" in gguf_problem(gguf_bytes(kvs=kvs, tensors=tensors, alignment=64))


def test_gguf_tensor_data_past_end_of_file():
    tensors = [GTensor("big", [64], 0, f32(1, 2, 3, 4))]  # 256 bytes declared, 32 present
    assert "needs 256 bytes at offset 0, past the end of the file" in gguf_problem(gguf_bytes(tensors=tensors))


def test_gguf_overlapping_tensors():
    tensors = [GTensor("a", [4], 0, f32(1, 2, 3, 4)), GTensor("b", [4], 0, b"", offset=0)]
    assert "overlap" in gguf_problem(gguf_bytes(tensors=tensors))


def test_gguf_row_not_a_multiple_of_the_block_size():
    tensors = [GTensor("q", [16], 2, b"\x00" * 18)]  # Q4_0 rows hold multiples of 32 elements
    assert "not a multiple of the block size 32" in gguf_problem(gguf_bytes(tensors=tensors))


def test_gguf_invalid_ggml_type():
    assert "invalid ggml type 64" in gguf_problem(gguf_bytes(tensors=[GTensor("t", [4], 64, f32(1, 2, 3, 4))]))


def test_gguf_duplicate_key():
    kvs = default_kvs() + [("general.name", T_STR, "again")]
    assert 'duplicate metadata key "general.name"' in gguf_problem(gguf_bytes(kvs=kvs))


def test_gguf_duplicate_tensor_name():
    tensors = [GTensor("a", [4], 0, f32(1, 2, 3, 4)), GTensor("a", [4], 0, f32(1, 2, 3, 4))]
    assert 'duplicate tensor name "a"' in gguf_problem(gguf_bytes(tensors=tensors))


def test_gguf_tensor_name_length_limit():
    # llama.cpp's GGML_MAX_NAME (64) counts the terminating NUL, so 63 bytes is the longest name it loads.
    assert detect(gguf_bytes(tensors=[GTensor("n" * 63, [4], 0, f32(1, 2, 3, 4))])).ok
    assert "name is 64 bytes; the limit is 63" in gguf_problem(gguf_bytes(tensors=[GTensor("n" * 64, [4], 0, f32(1, 2, 3, 4))]))


def test_gguf_key_longer_than_limit():
    raw = struct.pack("<Q", 70_000) + b"k" * 70_000
    assert "metadata key 0 is 70,000 bytes; the limit is 65,535" in gguf_problem(gguf_bytes(raw_kv=raw, kv_count=1))


def test_gguf_empty_and_non_utf8_keys():
    assert "metadata key 0 is empty" in gguf_problem(gguf_bytes(raw_kv=gguf_kv(b"", T_U8, 1), kv_count=1))
    assert "not valid UTF-8" in gguf_problem(gguf_bytes(raw_kv=gguf_kv(b"\xff\xfe", T_U8, 1), kv_count=1))


def test_gguf_string_longer_than_limit_is_rejected_before_reading():
    raw = gguf_str("general.name") + struct.pack("<I", T_STR) + struct.pack("<Q", 17 * MiB)
    assert "17,825,792 bytes; the limit is 16 MiB" in gguf_problem(gguf_bytes(raw_kv=raw, kv_count=1))


def test_gguf_array_count_limit():
    raw = gguf_str("big") + struct.pack("<I", T_ARR) + struct.pack("<IQ", T_U8, 16_000_001)
    assert "16,000,001 elements; the limit is 16,000,000" in gguf_problem(gguf_bytes(raw_kv=raw, kv_count=1))


def test_gguf_array_larger_than_file_is_truncated_not_allocated():
    raw = gguf_str("big") + struct.pack("<I", T_ARR) + struct.pack("<IQ", T_U64, 15_000_000)
    assert "truncated" in gguf_problem(gguf_bytes(raw_kv=raw, kv_count=1))


def test_gguf_arrays_nested_three_deep_are_rejected():
    kvs = default_kvs() + [("test.deep", T_ARR, (T_ARR, [(T_ARR, [(T_U8, [1])])]))]
    assert "nested more than 2 deep" in gguf_problem(gguf_bytes(kvs=kvs))


@pytest.mark.parametrize("raw, expected", [
    (gguf_str("x") + struct.pack("<I", 13), "unknown value type 13"),
    (gguf_str("x") + struct.pack("<I", T_ARR) + struct.pack("<IQ", 13, 1), "unknown element type 13"),
])
def test_gguf_unknown_types(raw, expected):
    assert expected in gguf_problem(gguf_bytes(raw_kv=raw, kv_count=1))


def test_gguf_architecture_rules():
    assert "general.architecture is missing" in gguf_problem(gguf_bytes(kvs=kvs_without("general.architecture")))
    wrong_type = kvs_without("general.architecture") + [("general.architecture", T_U32, 7)]
    assert "general.architecture must be a string" in gguf_problem(gguf_bytes(kvs=wrong_type))
    spaced = kvs_without("general.architecture") + [("general.architecture", T_STR, "my arch")]
    assert "not a valid architecture name" in gguf_problem(gguf_bytes(kvs=spaced))


def test_gguf_context_length_must_be_an_integer():
    kvs = kvs_without("llama.context_length") + [("llama.context_length", T_F32, 2048.0)]
    assert "must be an integer" in gguf_problem(gguf_bytes(kvs=kvs))


def test_gguf_header_budget(monkeypatch):
    monkeypatch.setattr(formats, "GGUF_MAX_HEADER", 64)
    assert "header is larger than" in gguf_problem(gguf_bytes())


def test_gguf_zip_polyglot_is_classified_by_its_dangerous_reading():
    info = detect(gguf_bytes() + torch_zip_bytes(), "model.gguf")
    assert info.format == "pickle"
    assert info.metadata["polyglot"] == "gguf"


@pytest.mark.skipif(not os.environ.get("FERRY_TEST_REAL_GGUF"), reason="set FERRY_TEST_REAL_GGUF to a real GGUF file")
def test_real_gguf_header():
    path = Path(os.environ["FERRY_TEST_REAL_GGUF"])
    with open(path, "rb") as fh:
        info = detect_format(fh, os.fstat(fh.fileno()).st_size, path.name)
    print(json.dumps(info.to_dict(), indent=2))
    assert info.format == "gguf" and info.ok, info.problems
    assert info.metadata["architecture"] == "qwen2"
    assert info.metadata["tensor_count"] > 0 and info.metadata["parameter_count"] > 0


# --------------------------------------------------------------------------- safetensors


def test_tiny_safetensors_is_detected_with_metadata():
    info = detect(safetensors_bytes(metadata={"format": "pt"}), "model.safetensors")
    assert info.format == "safetensors" and info.ok
    assert info.metadata == {"tensor_count": 2, "parameter_count": 9, "dtypes": ["F32"]}


def test_safetensors_detection_ignores_the_name():
    assert detect(safetensors_bytes(), "weights.bin").format == "safetensors"
    assert detect(safetensors_bytes(), "weights.pt").format == "safetensors"


def test_safetensors_zero_sized_tensors_and_mixed_dtypes():
    tensors = {"empty": ("F16", [0, 4], b""), "ids": ("I64", [2], b"\x00" * 16), "mask": ("BOOL", [3], b"\x01\x00\x01")}
    info = detect(safetensors_bytes(tensors), "x.safetensors")
    assert info.ok and info.metadata["dtypes"] == ["BOOL", "F16", "I64"]


def test_safetensors_header_too_large():
    data = struct.pack("<Q", 200 * MiB) + b'{"a": {}}' + b"\x00" * 64
    assert "exceeds the 100 MiB limit" in st_problem(data)
    info = detect(data, "weights.bin")
    assert info.format == "safetensors" and not info.ok


@pytest.mark.parametrize("data, expected", [
    (b"\x01\x02", "shorter than the 8-byte header length"),
    (struct.pack("<Q", 4) + b"{}  ", "below the minimum of 8"),
    (struct.pack("<Q", 64) + b"{}      ", "runs past the end"),
    (safetensors_bytes(header=b"[1, 2, 3]"), "does not start with '{'"),
    (safetensors_bytes(header=b"{not json}"), "not valid JSON"),
    (safetensors_bytes(header='{"a": NaN}'), "not valid JSON"),
    (safetensors_bytes(header=b'{"\xff": 1}'), "not valid UTF-8"),
    (safetensors_bytes(header='{"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}, '
                              '"w": {"dtype": "F32", "shape": [1], "data_offsets": [4, 8]}}', data=b"\x00" * 8),
     'duplicate key "w"'),
])
def test_safetensors_malformed_headers(data, expected):
    assert expected in st_problem(data)


def entry(dtype: str, shape: list, begin: int, end: int) -> dict:
    return {"dtype": dtype, "shape": shape, "data_offsets": [begin, end]}


@pytest.mark.parametrize("header, data_len, expected", [
    ({"a": entry("F32", [6], 0, 24), "b": entry("F32", [6], 12, 36)}, 36, 'tensor "b" overlaps the preceding tensor'),
    ({"a": entry("F32", [6], 0, 24), "b": entry("F32", [6], 32, 56)}, 56, '8 bytes before tensor "b" are not covered'),
    ({"a": entry("F32", [6], 0, 24)}, 40, "the last 16 bytes of the data region are not covered"),
    ({"a": entry("F32", [2, 3], 0, 20)}, 20, "occupies 20 bytes but a F32 tensor of shape [2, 3] needs 24"),
    ({"a": entry("F128", [2], 0, 32)}, 32, 'unknown dtype "F128"'),
    ({"a": entry("F32", [-1], 0, 0)}, 0, "invalid shape"),
    ({"a": entry("F32", [True], 0, 4)}, 4, "invalid shape"),
    ({"a": entry("F32", [1] * 65, 0, 4)}, 4, "invalid shape"),
    ({"a": entry("F32", [2], 8, 0)}, 8, "begin must not exceed end"),
    ({"a": entry("F32", [2], 0, 8)}, 4, "lie outside the 4-byte data region"),
    ({"a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4], "extra": 1}}, 4, 'unknown field(s) "extra"'),
    ({"a": {"dtype": "F32", "shape": [1]}}, 0, "missing data_offsets"),
    ({"a": [1, 2]}, 0, 'tensor "a" is not an object'),
    ({"__metadata__": {"k": 1}}, 0, "__metadata__ must map strings to strings"),
])
def test_safetensors_malformed_entries(header, data_len, expected):
    assert expected in st_problem(safetensors_bytes(header=header, data=b"\x00" * data_len))


def test_safetensors_header_length_that_looks_like_a_pickle_header_is_still_safetensors():
    # A 640-byte header starts the file with 0x80 0x02: the pickle PROTO 2 opcode.
    header = {"__metadata__": {"pad": ""}, "w": entry("F32", [2], 0, 8)}
    header["__metadata__"]["pad"] = "x" * (640 - len(json.dumps(header)))
    data = safetensors_bytes(header=header, data=b"\x00" * 8, pad=False)
    assert data[:2] == b"\x80\x02"
    info = detect(data, "model.safetensors")
    assert info.format == "safetensors" and info.ok


def test_safetensors_whose_header_bytes_also_run_as_a_pickle_stream_is_pickle():
    # Header length 0x560280: bytes 80 02 56 = PROTO 2 then UNICODE, which reads up to
    # a newline the JSON never contains, so an unpickler would keep going into the data.
    n = 0x560280
    header = {"__metadata__": {"pad": ""}, "w": entry("F32", [2], 0, 8)}
    header["__metadata__"]["pad"] = "x" * (n - len(json.dumps(header)))
    data = safetensors_bytes(header=header, data=b"\x00" * 8, pad=False)
    assert data[:3] == b"\x80\x02V"
    info = detect(data, "model.safetensors")
    assert info.format == "pickle" and info.metadata["polyglot"] == "safetensors"


def test_pickle_polyglot_scan_is_static():
    assert formats._pickle_polyglot(b"\x80\x02c__ferry_no_such_module__\nnothing\n.")
    assert not formats._pickle_polyglot(b"\x80\x02\x00\x00\x00\x00\x00\x00{}")
    assert not formats._pickle_polyglot(b"\x80\x02K\x01.trailing")


# --------------------------------------------------------------------------- pickle


@pytest.mark.parametrize("data", [PICKLE_PROTO4, PICKLE_PROTO2, b"\x80\x03K\x01.", b"\x80\x05K\x01."])
@pytest.mark.parametrize("name", ["model.bin", "model.safetensors", "weights", "model.gguf"])
def test_raw_pickle_is_detected_by_content(data, name):
    info = detect(data, name)
    assert info.format == "pickle"


def test_torch_zip_with_data_pkl_is_pickle():
    info = detect(torch_zip_bytes(), "pytorch_model.bin")
    assert info.format == "pickle"
    assert info.metadata["pickle_members"] == ["archive/data.pkl"]


def test_zip_with_any_pkl_member_is_pickle():
    assert detect(zip_bytes({"nested/state.pkl": b"x", "readme.txt": b"hi"}), "x.zip").format == "pickle"
    assert detect(zip_bytes({"STATE.PICKLE": b"x"}), "x.zip").format == "pickle"


@pytest.mark.parametrize("ext", [".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib"])
def test_pickle_extensions_with_unremarkable_content_are_pickle(ext):
    assert detect(b"\x01\x02\x03 random bytes", f"model{ext}").format == "pickle"
    assert detect(b"plain text", f"MODEL{ext.upper()}").format == "pickle"


def test_protocol_0_pickle_without_imports_is_only_caught_by_extension():
    # A header-less (protocol 0/1) pickle that can import nothing is just data: text by content.
    proto0 = b"(lp0\nI1\na."
    assert detect(proto0, "data.txt").format == "text"
    assert detect(proto0, "data.pkl").format == "pickle"


@pytest.mark.parametrize("data", [
    b"c__ferry_no_such_module__\nnothing\n.",                 # protocol 0: GLOBAL first
    b"(lp0\nI1\na.c__ferry_no_such_module__\nnothing\n.",     # a second pickle after STOP
    b"N0" * (formats.MiB // 2 + 1),                          # still a valid stream past the window
])
def test_headerless_pickle_that_can_import_is_pickle_by_content(data):
    assert detect(data, "notes.txt").format == "pickle"


# --------------------------------------------------------------------------- executables and archives


@pytest.mark.parametrize("data, kind", [
    (ELF_BYTES, "elf"),
    (b"\xfe\xed\xfa\xce" + b"\x00" * 60, "mach-o"),
    (b"\xfe\xed\xfa\xcf" + b"\x00" * 60, "mach-o"),
    (b"\xce\xfa\xed\xfe" + b"\x00" * 60, "mach-o"),
    (b"\xcf\xfa\xed\xfe" + b"\x00" * 60, "mach-o"),
    (b"\xca\xfe\xba\xbe" + b"\x00" * 60, "mach-o-fat"),
    (b"MZ" + b"\x00" * 62, "pe"),
    (SHEBANG_BYTES, "script"),
])
def test_executables_by_magic(data, kind):
    info = detect(data, "harmless.txt")
    assert info.format == "executable" and info.metadata["kind"] == kind


@pytest.mark.parametrize("name", ["setup.py", "run.sh", "x.bash", "x.ps1", "x.bat", "x.cmd", "tool.exe",
                                  "lib.dll", "libfoo.so", "libfoo.dylib", "app.bin.exe", "artifacts/code/X.PY"])
def test_executables_by_extension(name):
    assert detect(b"print('hello')\n", name).format == "executable"


@pytest.mark.parametrize("data, container", [
    (gzip.compress(b"hello"), "gzip"),
    (tar_bytes({"a.txt": b"hi"}), "tar"),
    (lzma.compress(b"hello"), "xz"),
    (bz2.compress(b"hello"), "bzip2"),
    (b"\x28\xb5\x2f\xfd" + b"\x00" * 20, "zstd"),
    (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20, "7z"),
    (b"Rar!\x1a\x07\x01\x00" + b"\x00" * 20, "rar"),
    (b"\x04\x22\x4d\x18" + b"\x00" * 20, "lz4"),
    (zip_bytes({"readme.txt": b"hello"}), "zip"),
])
def test_archives(data, container):
    info = detect(data, "data.bin")
    assert info.format == "archive" and info.metadata["container"] == container


def test_zip_with_data_prepended_is_still_found():
    info = detect(b"#junk " * 50 + zip_bytes({"a.txt": b"hi"}), "notes.txt")
    assert info.format == "archive"


def test_zip_magic_without_a_central_directory_is_a_malformed_archive():
    info = detect(b"PK\x03\x04" + b"\x00" * 100, "x.zip")
    assert info.format == "archive" and not info.ok


# --------------------------------------------------------------------------- json, text, binary


def test_json_text_binary():
    assert detect(TOKENIZER_JSON, "tokenizer.json").format == "json"
    assert detect(LICENSE_TEXT, "LICENSE").format == "text"
    assert detect(b"", "empty").format == "text"
    assert detect(b"\x00\x01\x02\x03", "blob").format == "binary"
    assert detect(b"caf\xe9", "latin1.txt").format == "binary"
    assert detect(b"text with a \x00 NUL", "x.txt").format == "binary"


def test_json_rules():
    assert detect(b'{"a": NaN}', "x.json").format == "text"
    assert detect(b"[" * 100_000 + b"]" * 100_000, "deep.json").format == "text"
    assert detect(b"\xef\xbb\xbf{}", "bom.json").format == "text"


def test_text_check_tolerates_a_multibyte_character_split_at_the_sniff_boundary():
    data = b"a" * (MiB - 1) + "é".encode("utf-8") + b"tail"
    assert detect(data, "big.txt").format == "text"


def test_short_file_is_a_problem():
    info = detect_format(io.BytesIO(b"abc"), 10, "x")
    assert not info.ok


def test_display_helpers_escape_untrusted_text():
    assert quote_untrusted("a\x1b[2Jb‮") == '"a\\u001b[2Jb\\u202e"'
    assert quote_untrusted("x" * 500).endswith("…")
    assert clean_text("ok\x07⁦") == "ok��"


# --------------------------------------------------------------------------- quality pass: GGUF strictness, polyglots, archives


@pytest.fixture
def ws(tmp_path):
    return make_workspace(tmp_path)


def _verify_with(ws, extra: tuple[str, bytes, dict]) -> list[str]:
    files = [("artifacts/docs/LICENSE", LICENSE_TEXT, {"kind": "document", "fmt": "text"}), extra]
    report = verify_bundle(crafted_bundle(ws.root / "crafted.ferry.tar", [ws.publisher], files),
                           ws.policy(), ws.trust_store())
    return failed(report)


_POLYGLOT_KEY = b"cos\nsystem\n(S'echo pwned'\ntR."


def gguf_pickle_polyglot() -> bytes:
    """A valid GGUF whose bytes, read by an unpickler from byte 0, run os.system.

    'G' (BINFLOAT) swallows bytes 1-8; tensor count 0x025400 puts 'T' (BINSTRING,
    length 2) at byte 9; metadata count and the first key's length (0x0643) each
    start with 'C' (SHORT_BINBYTES, length 6), which lands on the first key's bytes:
    a protocol-0 GLOBAL. 152,576 one-byte I8 tensors at alignment 1 keep it valid."""
    n_tensors, n_kv = 0x025400, 0x0643
    def kv_u8(key: bytes) -> bytes:
        return struct.pack("<Q", len(key)) + key + struct.pack("<I", 0) + b"\x00"
    parts = [b"GGUF", struct.pack("<IQQ", 3, n_tensors, n_kv), kv_u8(_POLYGLOT_KEY.ljust(n_kv, b" ")),
             gguf_kv("general.architecture", T_STR, "llama"), gguf_kv("general.alignment", T_U32, 1)]
    parts += [kv_u8(b"filler.%04d" % i) for i in range(n_kv - 3)]
    tail = struct.pack("<IQI", 1, 1, 24)  # one dimension of 1 element, type I8
    parts += [struct.pack("<Q", 6) + b"%06x" % i + tail + struct.pack("<Q", i) for i in range(n_tensors)]
    parts.append(b"\x00" * n_tensors)
    return b"".join(parts)


@pytest.fixture(scope="module")
def polyglot_gguf() -> bytes:
    return gguf_pickle_polyglot()


class _Imported(Exception):
    pass


class _RecordingUnpickler(pickle.Unpickler):
    def find_class(self, module, name):  # never imports: proves what a loader would import
        raise _Imported(f"{module}.{name}")


def test_gguf_headerless_pickle_polyglot_is_pickle(polyglot_gguf):
    with pytest.raises(_Imported, match="os.system"):
        _RecordingUnpickler(io.BytesIO(polyglot_gguf)).load()
    assert parse_gguf(io.BytesIO(polyglot_gguf), len(polyglot_gguf)).ok  # a valid GGUF on its own
    info = detect(polyglot_gguf, "model.gguf")
    assert info.format == "pickle"
    assert info.metadata["polyglot"] == "gguf" and info.metadata["header"] == "none"
    normal = detect(gguf_bytes(), "model.gguf")
    assert normal.format == "gguf" and normal.ok


def test_gguf_headerless_pickle_polyglot_in_a_bundle_is_rejected_on_pickle_policy(ws, polyglot_gguf):
    extra = ("artifacts/models/tiny.gguf", polyglot_gguf, {"kind": "model", "fmt": "gguf", "model": MODEL})
    assert "policy.pickle" in _verify_with(ws, extra)


def _gguf_with_padding(tensors: list[GTensor], pad: int) -> bytes:
    return gguf_bytes(tensors=tensors) + b"\x00" * pad


@pytest.mark.parametrize("data, expected", [
    (gguf_bytes(tensors=[GTensor("n" * 64, [4], 0, f32(1, 2, 3, 4))]), "name is 64 bytes; the limit is 63"),
    (_gguf_with_padding([GTensor("t0", [8], 0, f32(*range(8)), offset=0),
                         GTensor("t1", [8], 0, f32(*range(8)), offset=64)], 96),
     "tensor \"t1\" is at offset 64, but the tensors declared before it end at 32"),
    (_gguf_with_padding([GTensor("t0", [8], 0, f32(*range(8)), offset=32),
                         GTensor("t1", [8], 0, f32(*range(8)), offset=0)], 64),
     "tensor \"t0\" is at offset 32, but the tensors declared before it end at 0"),
], ids=["64-byte-name", "gap-between-tensors", "out-of-order"])
def test_gguf_layouts_llama_cpp_refuses_are_problems(data, expected):
    info = detect(data, "model.gguf")
    assert info.format == "gguf" and info.problems
    assert expected in info.problems[0]
    assert "re-export the model" in info.problems[0]


def test_gguf_contiguous_tensors_have_no_problems():
    tensors = [GTensor("t0", [8], 0, f32(*range(8))), GTensor("t1", [4], 0, f32(1, 2, 3, 4)),
               GTensor("q", [64, 2], 2, b"\x01" * (4 * 18))]
    info = detect(gguf_bytes(tensors=tensors), "ok.gguf")
    assert info.ok and not info.warnings


def _ar_bytes() -> bytes:
    body = b"#!/bin/sh\necho pwned\n"
    header = b"run.sh/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100755".ljust(8)
    return b"!<arch>\n" + header + str(len(body)).encode().ljust(10) + b"`\n" + body


def _cpio_newc_bytes() -> bytes:
    def entry(name: bytes, data: bytes, mode: int) -> bytes:
        fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        head = b"070701" + b"".join(b"%08X" % f for f in fields) + name + b"\x00"
        head += b"\x00" * (-len(head) % 4)
        return head + data + b"\x00" * (-len(data) % 4)
    return entry(b"run.sh", b"#!/bin/sh\necho pwned\n", 0o100755) + entry(b"TRAILER!!!", b"", 0)


def _v7_tar_bytes() -> bytes:
    # A plain ustar member with its magic and version stripped and the checksum recomputed.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("run.sh")
        payload = b"#!/bin/sh\necho pwned\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    raw = bytearray(buf.getvalue())
    raw[257:265] = b"\x00" * 8
    raw[148:156] = b" " * 8
    raw[148:156] = b"%06o\x00 " % sum(raw[:512])
    return bytes(raw)


@pytest.mark.parametrize("data, container", [
    (_ar_bytes(), "ar"),
    (_cpio_newc_bytes(), "cpio"),
    (b"\xc7\x71" + b"\x00" * 40, "cpio"),
    (_v7_tar_bytes(), "tar"),
    (b"\x1f\x9d\x90" + b"#!/bin/sh\n", "compress"),
    (b"LZIP\x01\x0c" + b"run.sh", "lzip"),
    (b"MSCF\x00\x00\x00\x00" + b"\x00" * 32, "cab"),
    (b"xar!\x00\x1c\x00\x01" + b"\x00" * 32, "xar"),
], ids=["ar", "cpio-newc", "cpio-binary", "v7-tar", "compress", "lzip", "cab", "xar"])
def test_more_archive_containers(data, container):
    info = detect(data, "notes.txt")
    assert info.format == "archive" and info.metadata["container"] == container


def test_v7_tar_sample_is_a_real_tar():
    with tarfile.open(fileobj=io.BytesIO(_v7_tar_bytes())) as tf:
        assert tf.getnames() == ["run.sh"]
    assert formats._tar_checksum_ok(_v7_tar_bytes())
    corrupted = bytearray(_v7_tar_bytes())
    corrupted[0] ^= 1
    assert not formats._tar_checksum_ok(bytes(corrupted))
    assert not formats._tar_checksum_ok(b"\x00" * 512)
    assert detect(b"hello " * 200, "notes.txt").format == "text"


def test_ar_archive_declared_as_document_is_rejected_on_archive_policy(ws):
    extra = ("artifacts/docs/readme.txt", _ar_bytes(), {"kind": "document", "fmt": "archive"})
    assert _verify_with(ws, extra) == ["policy.archives"]
