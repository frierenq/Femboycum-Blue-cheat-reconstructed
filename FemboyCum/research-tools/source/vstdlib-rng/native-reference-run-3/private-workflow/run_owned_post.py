"""Reproduce only the authored post-fix Win32 per-action RNG probe."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
from collections import Counter
import hashlib
import importlib.util
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

if not __debug__:
    raise RuntimeError("optimized Python disables evidence checks")

HERE = Path(__file__).resolve().parent
PREP = Path(os.environ["FC_RESEARCH_PREP_DIR"])
SOURCE = Path(os.environ["FC_RESEARCH_SOURCE_ROOT"])
EXE = Path(os.environ["FC_RESEARCH_OWNED_PROBE_EXE"])
PINS = {
    EXE: "17ec2b835c7a3efd51aa9e795f40b3e0c2030eda04cec4a70ec8744777e167da",
    PREP / "actions.txt": "243ce91969fa47d6b9ddaecacab1fabfa22da7ea8f7b0bce0874983dea6e0911",
    PREP / "compare_run3.py": "0623eae7027f884ea3760d2b70e1b4f53b89aba971dbd43b15625ce6c01a15a2",
    PREP / "CMakeLists.txt": "b21983602795b543a35a684ff3db160bc6494728aa64c7fa1c2f5cbdc71381a3",
    PREP / "owned_per_action_fp_probe.cpp": "305724e0a2ebbb50dfb3c750468d30ec74ac4175a6806b37915a0cc11cff64da",
    SOURCE / "src/uniform_random.cpp": "8a19e3d19fdc0259baa3b03199b0d22ba60a794e3bf40e3620069df6440569f7",
    SOURCE / "src/uniform_random_exp.cpp": "f7147f19c8d7edc0b888c2f1eb3d7c92fe852c9630d73f09a713634aa922abdb",
    SOURCE / "src/uniform_random_exp_tables.inc": "cda810a1dd1ae40a0b3158bf5ffc393a24012cbef96e7475ee5afd5583550926",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_pins() -> None:
    for path, expected in PINS.items():
        if sha(path.read_bytes()) != expected:
            raise RuntimeError(f"pinned authored input changed: {path}")


def baseline_module():
    spec = importlib.util.spec_from_file_location("sealed_run3_comparer",
                                                  PREP / "compare_run3.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load sealed run-3 comparer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_output(raw: bytes, module=None) -> tuple[list[dict], dict]:
    module = module or baseline_module()
    action_lines, actions, expected, _ = module.load_prepared()
    module.require(raw.count(b"\r\n") == 1692 and raw.count(b"\n") == 1692 and
                   raw.count(b"\r") == 1692,
                   "post-fix owned probe changed its CRLF row framing")
    lines = module.strict_lines(raw, "post-fix owned FP stdout", 1024 * 1024)
    module.require(len(lines) == len(action_lines) == 1692,
                   "post-fix row count")
    fp_rows = []
    counts = Counter()
    for index, (line, (kind, values), source) in enumerate(zip(lines, actions, expected)):
        words = line.split()
        module.require(len(words) == 13 and words[0].isdigit() and
                       words[1] == kind and words[2].isdigit() and
                       int(words[0]) == index and int(words[2]) == len(values),
                       f"post-fix row {index}: identity/arity")
        module.require(all(module.HEX8.fullmatch(word) for word in words[3:8]) and
                       all(module.HEX4.fullmatch(words[slot]) for slot in (8, 9, 11, 12)) and
                       module.HEX8.fullmatch(words[10]) is not None,
                       f"post-fix row {index}: word shape")
        args = [int(word, 16) for word in words[3:6]]
        module.require(args == values + [0] * (3 - len(values)),
                       f"post-fix row {index}: input echo")
        want_value = (int(source["value_bits"], 16)
                      if kind in ("I", "F", "E") else 0)
        module.require(int(words[6], 16) == want_value,
                       f"post-fix row {index}: source value mismatch")
        pre_mx, pre_cw, pre_sw = (int(words[slot], 16) for slot in (7, 8, 9))
        post_mx, post_cw, post_sw = (int(words[slot], 16) for slot in (10, 11, 12))
        module.require(pre_mx == 0x1f80 and pre_cw == 0x027f and
                       pre_sw & 0xff == 0 and post_mx & ~0x3f == 0x1f80 and
                       post_cw == 0x027f,
                       f"post-fix row {index}: FP reset/controls")
        fp_rows.append({"pre_mxcsr": pre_mx, "pre_x87_control": pre_cw,
                        "pre_x87_status": pre_sw, "post_mxcsr": post_mx,
                        "post_x87_control": post_cw, "post_x87_status": post_sw})
        counts[f"0x{post_mx & 0x3f:02x}"] += 1
    return fp_rows, dict(sorted(counts.items()))


def main() -> None:
    validate_pins()
    source_actions = (PREP / "actions.txt").read_bytes()
    result = subprocess.run([str(EXE)], input=source_actions,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=True)
    if result.stderr:
        raise RuntimeError("authored probe emitted stderr")
    fp_rows, status_counts = validate_output(result.stdout)
    output = _fc_output("owned-per-action-post.txt")
    output.write_bytes(result.stdout)
    receipt = {"authored_only": True, "original_native_executed": False,
               "vm_operated": False, "rows": len(fp_rows),
               "actions_sha256": PINS[PREP / "actions.txt"],
               "exe_sha256": PINS[EXE],
               "source_input_sha256": {path.name: digest for path, digest in PINS.items()},
               "stdout_sha256": sha(result.stdout),
               "mxcsr_exception_mask_counts": status_counts,
               "scope": "authored source replay only; compare separately with sealed VM capture"}
    _fc_output("owned-post-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(fp_rows), "stdout_sha256": sha(result.stdout),
                      "status_counts": status_counts}))


if __name__ == "__main__":
    main()
