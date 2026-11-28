"""Model-weight metadata reader: GGUF, safetensors and other quant containers.

Model files are usually multi-gigabyte LFS blobs, but their metadata header sits at
the front. This module parses that header from a byte prefix so a scan never
downloads the weights.

- GGUF: magic "GGUF", version u32, tensor_count u64, metadata_kv_count u64, then
  metadata entries (key string, value type u32, value). Strings are u64 length plus
  bytes; arrays carry an element type u32 and count u64. `tokenizer.chat_template`
  is the security-relevant key.
- safetensors: u64 little-endian header length followed by a JSON header (tensor
  names, dtypes, shapes, offsets and a free-form `__metadata__` map).
- Other weight containers: bounded header samples for format identification; nothing
  is decoded as source text.
"""
import json
import os
import re
import struct
from pathlib import Path
from typing import Any

GGUF_MAGIC = b"GGUF"

# Weight containers whose header is worth sampling without the weights. `.bin` is
# already a binary finding; `.pt`/`.pth` are torch zip/pickle containers, `.onnx`
# is protobuf, `.h5`/`.keras` HDF5, and `.plan`/`.engine` are opaque TensorRT.
WEIGHT_EXT = frozenset({".gguf", ".safetensors", ".onnx", ".ggml", ".pt", ".pth", ".h5",
                         ".keras", ".tflite", ".mlmodel", ".ckpt", ".ot", ".npz", ".plan", ".engine"})

_MODEL_HEADER_MAX = int(os.environ.get("BEAGLE_MODEL_HEADER_MAX_BYTES")
                         or os.environ.get("BEAGLE_GGUF_MAX_BYTES") or 0) or 32 * 1024 * 1024

# Metadata is normally < 16 MiB; a cap keeps a corrupt/hostile header from driving
# the range request and the parse. The chat template in a typical GGUF sits after
# the tokenizer arrays, around 12-20 MiB in.
GGUF_MAX_BYTES = _MODEL_HEADER_MAX

# value type -> fixed byte width (8 string and 9 array are variable)
_SCALAR_WIDTH = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_MAX_KEY = 1 << 20
_MAX_KV = 1_000_000
_MAX_ARRAY = 100_000_000

LFS_OID_RE = re.compile(rb"oid sha256:([0-9a-f]{64})")
LFS_SIZE_RE = re.compile(rb"(?m)^size (\d+)\s*$")


def lfs_pointer(data):
    """(oid, size) when `data` is a Git LFS pointer text, else None."""
    head = data[:1024]
    if not head.startswith(b"version https://git-lfs.github.com/spec/v1"):
        return None
    oid = LFS_OID_RE.search(head)
    size = LFS_SIZE_RE.search(head)
    if not (oid and size):
        return None
    return oid.group(1).decode(), int(size.group(1))


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _skip_string(buf, off, limit):
    """(new_offset, value_or_None, complete). Incomplete means the prefix ends inside it."""
    if off + 8 > len(buf):
        return off, None, False
    n = _u64(buf, off)
    if n > limit:
        raise ValueError(f"string length {n} exceeds {limit} bytes")
    if off + 8 + n > len(buf):
        return off, None, False
    raw = buf[off + 8: off + 8 + n]
    return off + 8 + n, raw, True


def _skip_value(buf, off, vtype, limit, depth=0):
    """(new_offset, stored_value, complete). Raises ValueError on an impossible header."""
    if depth > 4:
        raise ValueError("array nesting deeper than 4")
    if vtype in _SCALAR_WIDTH:
        width = _SCALAR_WIDTH[vtype]
        if off + width > len(buf):
            return off, None, False
        raw = buf[off:off + width]
        if vtype == 6:
            value = struct.unpack("<f", raw)[0]
        elif vtype == 12:
            value = struct.unpack("<d", raw)[0]
        elif vtype == 7:
            value = bool(raw[0])
        else:
            value = int.from_bytes(raw, "little", signed=vtype in (1, 3, 5, 11))
        return off + width, value, True
    if vtype == 8:
        noff, raw, complete = _skip_string(buf, off, limit)
        return noff, (raw.decode("utf-8", "replace") if complete else None), complete
    if vtype == 9:
        if off + 12 > len(buf):
            return off, None, False
        atype = _u32(buf, off)
        count = _u64(buf, off + 4)
        if count > _MAX_ARRAY:
            raise ValueError(f"array count {count} exceeds {_MAX_ARRAY}")
        off += 12
        if atype in _SCALAR_WIDTH:
            total = count * _SCALAR_WIDTH[atype]
            if total > limit:
                raise ValueError(f"array of {count} x {_SCALAR_WIDTH[atype]} bytes exceeds {limit}")
            if off + total > len(buf):
                return off, None, False
            return off + total, None, True
        if atype == 8:
            for _ in range(count):
                off, _, complete = _skip_string(buf, off, limit)
                if not complete:
                    return off, None, False
            return off, None, True
        if atype == 9:
            for _ in range(count):
                off, _, complete = _skip_value(buf, off, 9, limit, depth + 1)
                if not complete:
                    return off, None, False
            return off, None, True
        raise ValueError(f"unknown array element type {atype}")
    raise ValueError(f"unknown metadata value type {vtype}")


def parse_header(buf, limit=GGUF_MAX_BYTES):
    """Parse a GGUF metadata prefix.

    Returns `(metadata, consumed, complete, error)`: only scalar/string values are kept,
    `consumed` is the byte offset where the metadata section ends, and `complete` is False
    when `buf` ends inside an entry (fetch more) or `error` explains an invalid header.
    """
    if len(buf) < 4:
        return {}, 0, False, None
    if buf[:4] != GGUF_MAGIC:
        return {}, 0, False, "not a GGUF file"
    if len(buf) < 24:
        return {}, 0, False, None
    try:
        version = _u32(buf, 4)
        if version < 1 or version > 3:
            return {}, 8, False, f"unsupported GGUF version {version}"
        tensor_count = _u64(buf, 8)
        kv_count = _u64(buf, 16)
        if kv_count > _MAX_KV:
            return {}, 24, False, f"{kv_count} metadata entries exceeds {_MAX_KV}"
        off = 24
        metadata: dict[str, Any] = {}
        for _ in range(kv_count):
            if off + 8 > len(buf):
                return metadata, off, False, None
            klen = _u64(buf, off)
            if klen > _MAX_KEY:
                return metadata, off, False, f"metadata key length {klen} exceeds {_MAX_KEY}"
            if off + 8 + klen + 4 > len(buf):
                return metadata, off, False, None
            key = buf[off + 8: off + 8 + klen].decode("utf-8", "replace")
            off += 8 + klen
            vtype = _u32(buf, off)
            off += 4
            off, value, complete = _skip_value(buf, off, vtype, limit)
            if not complete:
                return metadata, off, False, None
            metadata[key] = value
        return metadata, off, True, None
    except (struct.error, ValueError) as ex:
        return {}, 0, False, str(ex)


def read_header(p, limit=GGUF_MAX_BYTES):
    """(metadata, info) for a local .gguf file, reading only the metadata prefix.

    info: {size, read, consumed, complete, error, lfs}. `lfs` is set when the file is a
    Git LFS pointer that was not materialized (metadata unavailable).
    """
    p = Path(p)
    try:
        size = p.stat().st_size
    except OSError as ex:
        return None, {"size": 0, "read": 0, "consumed": 0, "complete": False,
                      "error": f"{type(ex).__name__}: {ex}", "lfs": None}
    try:
        with open(p, "rb") as fh:
            buf = fh.read(min(size, limit))
    except OSError as ex:
        return None, {"size": size, "read": 0, "consumed": 0, "complete": False,
                      "error": f"{type(ex).__name__}: {ex}", "lfs": None}
    pointer = lfs_pointer(buf)
    info = {"size": size, "read": len(buf), "consumed": 0, "complete": False, "error": None, "lfs": pointer}
    if pointer:
        return None, info
    metadata, consumed, complete, error = parse_header(buf, limit)
    info.update({"consumed": consumed, "complete": complete, "error": error})
    if error:
        return None, info
    return metadata, info


def parse_safetensors(buf, limit=GGUF_MAX_BYTES):
    """(header, consumed, complete, error) for a safetensors prefix.

    The header is a JSON object keyed by tensor name plus an optional `__metadata__`
    map. Only the JSON is parsed; tensor payloads are never read.
    """
    if len(buf) < 8:
        return {}, 0, False, None
    n = int.from_bytes(buf[:8], "little")
    if n == 0:
        return {}, 8, False, "empty safetensors header"
    if n > limit:
        return {}, 8, False, f"safetensors header length {n} exceeds {limit} bytes"
    if len(buf) < 8 + n:
        return {}, 8, False, None
    try:
        header = json.loads(buf[8:8 + n].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as ex:
        return {}, 8 + n, False, f"invalid safetensors JSON header: {ex}"
    if not isinstance(header, dict):
        return {}, 8 + n, False, "safetensors header is not a JSON object"
    return header, 8 + n, True, None


def read_safetensors(p, limit=GGUF_MAX_BYTES):
    """(header, info) for a local safetensors file, reading only the JSON header."""
    p = Path(p)
    try:
        size = p.stat().st_size
    except OSError as ex:
        return None, {"size": 0, "read": 0, "consumed": 0, "complete": False,
                      "error": f"{type(ex).__name__}: {ex}", "lfs": None}
    try:
        with open(p, "rb") as fh:
            head = fh.read(8)
            n = int.from_bytes(head, "little") if len(head) == 8 else 0
            buf = head + fh.read(min(n, limit))
    except OSError as ex:
        return None, {"size": size, "read": 0, "consumed": 0, "complete": False,
                      "error": f"{type(ex).__name__}: {ex}", "lfs": None}
    pointer = lfs_pointer(buf)
    info = {"size": size, "read": len(buf), "consumed": 0, "complete": False, "error": None, "lfs": pointer}
    if pointer:
        return None, info
    header, consumed, complete, error = parse_safetensors(buf, limit)
    info.update({"consumed": consumed, "complete": complete, "error": error})
    if error:
        return None, info
    return header, info


_ONNX_HEADER_FIELDS = {2: "producer_name", 3: "producer_version", 4: "domain", 6: "doc_string"}
_ONNX_HEADER_INTS = {1: "ir_version", 5: "model_version"}


def onnx_prefix_info(buf, max_string=4096):
    """Top-level ONNX ModelProto fields before the graph blob: producer, domain, doc_string.

    A minimal protobuf wire-format walker. Graph field 7 is length-delimited; its length is
    enough to stop (the graph bytes carry the weights and are not in the header sample).
    """
    out: dict[str, Any] = {}
    off = 0
    try:
        while off < len(buf):
            key = 0
            shift = 0
            while True:
                if off >= len(buf) or shift > 63:
                    return out
                b = buf[off]; off += 1
                key |= (b & 0x7f) << shift
                shift += 7
                if not b & 0x80:
                    break
            field, wire = key >> 3, key & 7
            if wire == 0:
                value = 0; shift = 0
                while True:
                    if off >= len(buf) or shift > 63:
                        return out
                    b = buf[off]; off += 1
                    value |= (b & 0x7f) << shift
                    shift += 7
                    if not b & 0x80:
                        break
                if field in _ONNX_HEADER_INTS:
                    out[_ONNX_HEADER_INTS[field]] = value
            elif wire == 2:
                n = 0; shift = 0
                while True:
                    if off >= len(buf) or shift > 63:
                        return out
                    b = buf[off]; off += 1
                    n |= (b & 0x7f) << shift
                    shift += 7
                    if not b & 0x80:
                        break
                name = _ONNX_HEADER_FIELDS.get(field)
                if name and off + n <= len(buf) and n <= max_string:
                    out[name] = buf[off:off + n].decode("utf-8", "replace")
                if off + n > len(buf):
                    return out
                off += n
            elif wire == 5:
                if off + 4 > len(buf):
                    return out
                off += 4
            elif wire == 1:
                if off + 8 > len(buf):
                    return out
                off += 8
            else:
                return out
            if field == 7:      # graph: the remaining bytes are weights
                return out
    except (IndexError, ValueError):
        pass
    return out


