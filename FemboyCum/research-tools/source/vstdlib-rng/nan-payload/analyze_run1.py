"""Read-only classification of archived VM run-1 exponent NaN observations."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
from collections import Counter, defaultdict
from pathlib import Path

def _fc_output_root():
    value = os.environ.get("FC_RESEARCH_OUTPUT_DIR")
    if not value or not Path(value).is_absolute():
        raise RuntimeError("set FC_RESEARCH_OUTPUT_DIR to an absolute scratch directory")
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("FC_RESEARCH_OUTPUT_DIR must be an existing directory")
    public_tree = Path(__file__).resolve().parents[3]
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

import hashlib
import json

if not __debug__:
    raise SystemExit("run the case analyzer without Python -O")

RUN = Path(__file__).resolve().parent.parent / "native-reference-run-1"
EXPECTED_SHA = "0ccf2c5696625ceb9c72f41ca03b0c2bc1ca572b312122f5d45e7b9e0046d36a"
NATIVE_SHA = "b49c831374343a633b39a3776556e71d410b8b6cbf84e0e2631519466dc51f73"


def word(value: str) -> int:
    assert isinstance(value, str) and value.startswith("0x") and len(value) == 10
    return int(value, 16)


def nan(value: int) -> bool:
    return value & 0x7F800000 == 0x7F800000 and bool(value & 0x007FFFFF)


def kind(value: int) -> str:
    if nan(value):
        return ("-" if value >> 31 else "+") + ("qNaN" if value & 0x400000 else "sNaN")
    if value & 0x7FFFFFFF == 0x7F800000:
        return ("-" if value >> 31 else "+") + "inf"
    if value & 0x7FFFFFFF == 0:
        return ("-" if value >> 31 else "+") + "zero"
    return "finite"


def main() -> None:
    expected_bytes = (RUN / "source-expected.json").read_bytes()
    native_bytes = (RUN / "guest-capture/native.jsonl").read_bytes()
    assert hashlib.sha256(expected_bytes).hexdigest() == EXPECTED_SHA
    assert hashlib.sha256(native_bytes).hexdigest() == NATIVE_SHA
    expected = json.loads(expected_bytes)
    native = [json.loads(line) for line in native_bytes.splitlines()]
    assert len(expected) == len(native) == 6274
    classes = Counter()
    by_exponent = defaultdict(Counter)
    examples = []
    mismatch = 0
    for source, guest in zip(expected, native):
        assert source["sequence"] == guest["sequence"]
        if guest["action"] != "E":
            continue
        low, high, exponent = map(word, guest["input_bits"])
        source_result = word(source["value_bits"])
        guest_result = word(guest["value_bits"])
        assert nan(source_result) == nan(guest_result)
        if not nan(guest_result):
            assert source_result == guest_result
            continue
        classes[(kind(low), kind(high), kind(exponent), source_result == guest_result)] += 1
        by_exponent[f"0x{exponent:08x}"][f"0x{guest_result:08x}"] += 1
        if source_result != guest_result:
            assert not nan(low) and not nan(high)
            assert not (low & 0x7FFFFFFF == 0x7F800000 and
                        high & 0x7FFFFFFF == 0x7F800000 and
                        (low >> 31) == (high >> 31))
            assert exponent in (0x7FC12345, 0x7FA12345)
            assert guest_result == (exponent | 0x00400000)
            mismatch += 1
            examples.append({"sequence": guest["sequence"], "low": f"0x{low:08x}",
                             "high": f"0x{high:08x}", "exponent": f"0x{exponent:08x}",
                             "source": f"0x{source_result:08x}",
                             "guest": f"0x{guest_result:08x}"})
    assert mismatch == 244
    result = {"run1_nan_exponent_class_counts": [
        {"low": a, "high": b, "exponent": c, "bit_equal": d, "count": n}
        for (a, b, c, d), n in sorted(classes.items())],
        "guest_nan_result_by_exponent": {key: dict(value) for key, value in sorted(by_exponent.items())},
        "bit_mismatch_count": mismatch, "bit_mismatch_first_20": examples[:20],
        "all_mismatch_deltas_non_nan": True,
        "all_mismatch_guest_bits_equal_quieted_exponent": True,
        "mismatch_exponents": dict(Counter(item["exponent"] for item in examples)),
        "mismatch_endpoint_classes": dict(Counter(
            f"{kind(word(item['low']))}/{kind(word(item['high']))}" for item in examples))}
    (_fc_output("analyze_run1.json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"mismatch_exponents": result["mismatch_exponents"],
                      "mismatch_endpoint_classes": result["mismatch_endpoint_classes"]}, indent=2))


if __name__ == "__main__":
    main()
