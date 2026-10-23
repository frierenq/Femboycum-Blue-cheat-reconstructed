"""Deterministic authored-only B/C/X inputs for the unrun VM leaf harness."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
import hashlib
import json
import math
import struct
from collections import Counter
from pathlib import Path

def _fc_output_root():
    value = os.environ.get("FC_RESEARCH_OUTPUT_DIR")
    if not value or not Path(value).is_absolute():
        raise RuntimeError("set FC_RESEARCH_OUTPUT_DIR to an absolute scratch directory")
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("FC_RESEARCH_OUTPUT_DIR must be an existing directory")
    public_tree = Path(__file__).resolve().parents[4]
    if root == public_tree or root.is_relative_to(public_tree):
        raise RuntimeError("research output cannot be inside the source candidate/public tools tree")
    if public_tree.name == "research-tools" and root.is_relative_to(public_tree.parent):
        raise RuntimeError("research output cannot be inside the public release tree")
    return root


def _fc_output(name):
    root = _fc_output_root()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        raise RuntimeError("research output path escapes scratch directory")
    return target


def _fc_checked_output(path):
    target = Path(path).resolve()
    if not target.is_relative_to(_fc_output_root()):
        raise RuntimeError("explicit output must be inside FC_RESEARCH_OUTPUT_DIR")
    return target


OUT_DIR = _fc_output_root()
OUT = OUT_DIR / "actions.txt"
REPORT = OUT_DIR / "coverage.json"
MAX_ACTIONS = 10000
MAX_BYTES = 1024 * 1024

def digest20(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()[:20]

def float_bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]

def number(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits))[0]

def max_value(count: int) -> int:
    return (1 << count) - 1

lines: list[str] = []
counts = Counter()

def add_bits(cursor: int, count: int, value: int, data: bytes, family: str) -> None:
    assert 0 <= cursor <= 160 and 1 <= count <= 32
    assert 0 <= value <= max_value(count) and len(data) == 20
    lines.append(f"B {cursor} {count} 0x{value:08x} {data.hex()}")
    counts[family] += 1
    counts["B.success" if cursor + count <= 160 else "B.clamp"] += 1
    if (cursor & 31) + count > 32 and cursor + count <= 160:
        counts["B.crossing_success"] += 1
    if cursor + count == 160: counts["B.exact_capacity"] += 1

def add_coord(cursor: int, bits: int, data: bytes, family: str) -> None:
    value = number(bits)
    assert 0 <= cursor <= 160 and math.isfinite(value) and abs(value) < 16385.0
    assert len(data) == 20
    lines.append(f"C {cursor} 0x{bits:08x} {data.hex()}")
    counts[family] += 1
    if cursor == 160: counts["C.initial_overflow"] += 1
    if cursor >= 145: counts["C.near_capacity"] += 1

def add_xor(data: bytes, key: bytes, family: str) -> None:
    assert len(data) == len(key) == 20
    lines.append(f"X {data.hex()} {key.hex()}")
    counts[family] += 1

# A full cursor × count grid. Rotate through zero, all-ones, and fitting
# nontrivial pattern values; use a distinct nonzero prefill for each case.
for cursor in range(161):
    for count in range(1, 33):
        mode = (cursor + count) % 3
        pattern = int.from_bytes(hashlib.sha256(
            f"B-value:{cursor}:{count}".encode("ascii")).digest()[:4], "little")
        value = 0 if mode == 0 else max_value(count) if mode == 1 else pattern & max_value(count)
        add_bits(cursor, count, value, digest20(f"B-prefill:{cursor}:{count}"), "B.grid")

# Pin deliberate all-zero/all-one/pattern prefill and value combinations at
# word, byte, capacity, and one-bit-edge cursors.
edge_cursors = [0,1,7,8,15,16,31,32,33,63,64,95,96,127,128,129,159,160]
edge_counts = [1,2,5,14,19,28,31,32]
for cursor in edge_cursors:
    for count in edge_counts:
        for mode in range(3):
            data = (b"\x00"*20 if mode == 0 else b"\xff"*20 if mode == 1
                    else digest20(f"B-edge-data:{cursor}:{count}"))
            pattern = int.from_bytes(digest20(f"B-edge-value:{cursor}:{count}")[:4],"little")
            value = 0 if mode == 0 else max_value(count) if mode == 1 else pattern & max_value(count)
            add_bits(cursor,count,value,data,"B.edge")

# Exact binary32 boundary words. Adjacent representables test sign threshold,
# truncation and scaled-fraction branches without decimal parsing ambiguity.
base_float_bits = {
    0x00000000, 0x80000000,  # signed zero
    0x00000001, 0x80000001,  # minimum subnormal
    0x007fffff, 0x807fffff,  # maximum subnormal
    0x00800000, 0x80800000,  # minimum normal
    float_bits(1.0/32.0)-1, float_bits(1.0/32.0), float_bits(1.0/32.0)+1,
    0x80000000 | (float_bits(1.0/32.0)-1),
    0x80000000 | float_bits(1.0/32.0),
    0x80000000 | (float_bits(1.0/32.0)+1),
    float_bits(1.0)-1, float_bits(1.0), float_bits(1.0)+1,
    0x80000000 | (float_bits(1.0)-1),
    0x80000000 | float_bits(1.0),
    0x80000000 | (float_bits(1.0)+1),
    float_bits(1.5), float_bits(-1.5),
    float_bits(16384.0), float_bits(-16384.0),
    float_bits(16384.5), float_bits(-16384.5),
    float_bits(16385.0)-1, 0x80000000 | (float_bits(16385.0)-1),
}
coord_bits = sorted(base_float_bits)
assert len(coord_bits) >= 25
assert all(math.isfinite(number(b)) and abs(number(b)) < 16385.0 for b in coord_bits)
coord_cursors = [0,1,2,3,7,8,31,32,63,64,95,96,127,128,129,
                 140,141,142,143,144,145,146,147,148,149,150,151,
                 152,153,154,155,156,157,158,159,160]
for cursor in coord_cursors:
    for bits in coord_bits:
        add_coord(cursor,bits,digest20(f"C-prefill:{cursor}:{bits:08x}"),"C.grid")

# The raw XOR leaf is exactly 20 bytes. These keys include zero, FF, ramp,
# alternating, equal-data, inverse-data, all byte values, and digests.
special_data = [b"\x00"*20,b"\xff"*20,bytes(range(20)),
                bytes((0x55 if i&1 else 0xaa) for i in range(20))]
special_keys = [b"\x00"*20,b"\xff"*20,bytes(range(20)),
                bytes((0xaa if i&1 else 0x55) for i in range(20))]
for i,(data,key) in enumerate(zip(special_data,special_keys)):
    add_xor(data,key,"X.special")
for i in range(16):
    key=bytes((20*i+j)&255 for j in range(20))
    add_xor(digest20(f"X-data-sweep:{i}"),key,"X.byte_sweep")
for i in range(20):
    data=digest20(f"X-random-data:{i}")
    key=data if i%4==0 else bytes(x^0xff for x in data) if i%4==1 \
        else digest20(f"X-random-key:{i}")
    add_xor(data,key,"X.digest")

assert len(lines) <= MAX_ACTIONS
payload=("# Authored-only deterministic B/C/X fixture set; no original code executed.\n"
         + "\n".join(lines) + "\n").encode("ascii")
assert len(payload) <= MAX_BYTES
OUT.write_bytes(payload)
report = {
    "evidence_class": "authored deterministic fixture generator",
    "actions": len(lines),
    "action_file_bytes": len(payload),
    "action_file_sha256": hashlib.sha256(payload).hexdigest(),
    "counts": dict(sorted(counts.items())),
    "coord_binary32_words": [f"0x{v:08x}" for v in coord_bits],
    "cursor_grid": "0..160 inclusive for every B count 1..32",
    "native_or_harness_executed": False,
}
REPORT.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(f"{len(lines)} B/C/X actions, {len(payload)} ASCII bytes")
