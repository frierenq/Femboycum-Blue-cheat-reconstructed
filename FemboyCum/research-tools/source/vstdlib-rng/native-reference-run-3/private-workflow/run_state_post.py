"""Archive a fresh authored post-fix value/full-state probe replay."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import hashlib
import json
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

import subprocess

import run_owned_post as owned

if not __debug__:
    raise RuntimeError("optimized Python disables evidence checks")

HERE = Path(__file__).resolve().parent
EXE = Path(os.environ["FC_RESEARCH_STATE_PROBE_EXE"])
EXE_SHA = "2bef1ee41aaca0cfa954aea84bc82666d2deab527265ba8818429d88b1c7023a"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_output(raw: bytes, module=None) -> int:
    module = module or owned.baseline_module()
    action_lines, actions, expected, _ = module.load_prepared()
    lines = module.strict_lines(raw, "post-fix source-state stdout", 2 * 1024 * 1024)
    module.require(len(lines) == len(actions) == 1692,
                   "post-fix source-state row count")
    for index, (line, (kind, _), source) in enumerate(zip(lines, actions, expected)):
        parts = line.split()
        module.require(parts and parts[0] == kind and
                       len(parts) == (36 if kind == "S" else 37),
                       f"post-fix source-state row {index}: format/action")
        try:
            numbers = [int(word, 10) for word in parts[1:]]
        except ValueError as error:
            raise module.EvidenceError(f"post-fix source-state {index}: decimal") from error
        result = None if kind == "S" else numbers.pop(0)
        module.require(len(numbers) == 35 and
                       all(-(1 << 31) <= word <= 0xffffffff for word in numbers),
                       f"post-fix source-state {index}: word bounds")
        observed_state = [numbers[0] & 0xffffffff, numbers[1] & 0xffffffff]
        observed_state.extend(word & 0xffffffff for word in numbers[3:])
        want_state = [int(word, 16) for word in source["state_words"]]
        module.require(observed_state == want_state and
                       numbers[2] == source["authored_generation_count"],
                       f"post-fix source-state {index}: full state/generation")
        if kind in ("I", "F", "E"):
            module.require((result & 0xffffffff) == int(source["value_bits"], 16),
                           f"post-fix source-state {index}: result bits")
        elif kind == "M":
            module.require(result & ~0x3f == 0x1f80,
                           f"post-fix source-state {index}: selected mode")
    return len(lines)


def main() -> None:
    owned.validate_pins()
    if sha(EXE.read_bytes()) != EXE_SHA:
        raise RuntimeError("post-fix unit/probe executable changed")
    source_actions = (owned.PREP / "actions.txt").read_bytes()
    result = subprocess.run([str(EXE), "--probe"], input=source_actions,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=True)
    if result.stderr:
        raise RuntimeError("post-fix source-state probe emitted stderr")
    rows = validate_output(result.stdout)
    _fc_output("source-state-post.txt").write_bytes(result.stdout)
    receipt = {"authored_only": True, "original_native_executed": False,
               "vm_operated": False, "rows": rows,
               "actions_sha256": owned.PINS[owned.PREP / "actions.txt"],
               "exe_sha256": EXE_SHA, "stdout_sha256": sha(result.stdout),
               "full_state_34_words_and_result_bits_match_sealed_source_expected": True}
    _fc_output("source-state-post-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"rows": rows, "stdout_sha256": sha(result.stdout)}))


if __name__ == "__main__":
    main()
