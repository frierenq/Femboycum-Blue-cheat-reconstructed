"""Run only the newly authored source probe and compare archived run-1 text."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
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

import argparse
import collections
import hashlib
import json
import subprocess

if not __debug__:
    raise SystemExit("run the source replay without Python -O")

RUN = Path(os.environ["FC_RESEARCH_INPUT_DIR"])


def word(text: str) -> int:
    assert text.startswith("0x") and len(text) == 10
    return int(text, 16)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_probe_exe", type=Path,
                        help="new source-owned fc_uniform_random_tests.exe only")
    args = parser.parse_args()
    executable = args.source_probe_exe.resolve(strict=True)
    assert executable.name == "fc_uniform_random_tests.exe"
    actions = (RUN / "actions.txt").read_text(encoding="ascii")
    native_bytes = (RUN / "guest-capture/native.jsonl").read_bytes()
    assert hashlib.sha256(native_bytes).hexdigest() == \
        "b49c831374343a633b39a3776556e71d410b8b6cbf84e0e2631519466dc51f73"
    native = [json.loads(line) for line in native_bytes.splitlines()]
    result = subprocess.run([str(executable), "--probe"], input=actions,
                            text=True, encoding="ascii", capture_output=True, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(native) == 6274
    counts = collections.Counter()
    mismatches = []
    for index, (line, guest) in enumerate(zip(lines, native)):
        fields = line.split()
        kind = fields.pop(0)
        assert guest["sequence"] == index and kind == guest["action"]
        values = list(map(int, fields))
        output = None if kind == "S" else values.pop(0) & 0xFFFFFFFF
        assert len(values) == 35
        seed, draw, _generation_count, *table = values
        source_state = [value & 0xFFFFFFFF for value in (seed, draw, *table)]
        guest_state = [word(guest["default_state_seed"]),
                       word(guest["default_state_output"]),
                       *map(word, guest["default_state_table"])]
        assert len(source_state) == len(guest_state) == 34
        if source_state != guest_state:
            mismatches.append({"sequence": index, "kind": kind, "type": "state"})
        if kind not in ("M", "S"):
            native_value = word(guest["value_bits"])
            if output != native_value:
                mismatches.append({"sequence": index, "kind": kind, "type": "value",
                                   "source": f"0x{output:08x}",
                                   "guest": f"0x{native_value:08x}"})
            counts[f"{kind}_value_bit_matches" if output == native_value else
                   f"{kind}_value_bit_mismatches"] += 1
        counts[f"actions_{kind}"] += 1
    report = {"evidence_class": "newly authored source probe vs archived guest text",
              "source_probe_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
              "source_probe_path": str(executable), "native_jsonl_sha256": hashlib.sha256(native_bytes).hexdigest(),
              "actions": len(native), "counts": dict(counts), "mismatches": mismatches,
              "original_dll_executed": False}
    _fc_output("source-run1-compare.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("mismatches", "source_probe_path")}, indent=2))
    assert not mismatches, mismatches[:10]


if __name__ == "__main__":
    main()
