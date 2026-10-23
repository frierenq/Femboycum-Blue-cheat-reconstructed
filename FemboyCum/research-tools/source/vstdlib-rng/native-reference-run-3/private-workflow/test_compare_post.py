"""In-memory negative controls for the authored post-fix run-3 comparator."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
from copy import deepcopy
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


import compare_post
import run_owned_post as owned

HERE = Path(os.environ["FC_RESEARCH_INPUT_DIR"])
base = owned.baseline_module()
_, actions, expected, _ = base.load_prepared()
rows, _ = base.load_capture(Path(os.environ["FC_RESEARCH_RUN3_DIR"]) / "guest-capture")
raw = compare_post.require_hash(HERE / "owned-per-action-post.txt",
                                compare_post.POST_STDOUT_SHA)
fp, _ = owned.validate_output(raw, base)

checks = {}
normal = base.compare_rows(rows, actions, expected, fp)
checks["exact"] = normal["passed"] and all(
    count == 0 for count in normal["mismatch_counts"].values())

status_corrupt = deepcopy(fp)
status_corrupt[2]["post_mxcsr"] ^= 0x04
status_result = base.compare_rows(rows, actions, expected, status_corrupt)
checks["mxcsr_difference_detected"] = (
    status_result["mismatch_counts"] ==
    {"value": 0, "state": 0, "mode": 0, "fp_status": 1})

x87_corrupt = deepcopy(fp)
x87_corrupt[2]["post_x87_status"] ^= 0x0100
x87_result = base.compare_rows(rows, actions, expected, x87_corrupt)
checks["full_x87_status_difference_detected"] = (
    x87_result["mismatch_counts"] ==
    {"value": 0, "state": 0, "mode": 0, "fp_status": 1})

altered = raw.replace(b"bf800000", b"bf800001", 1)
try:
    owned.validate_output(altered, base)
except base.EvidenceError:
    checks["authored_input_echo_corruption_rejected"] = True
else:
    checks["authored_input_echo_corruption_rejected"] = False

try:
    compare_post.require_hash(HERE / "owned-per-action-post.txt", "0" * 64)
except ValueError:
    checks["wrong_stdout_digest_rejected"] = True
else:
    checks["wrong_stdout_digest_rejected"] = False

if not all(checks.values()):
    raise RuntimeError(f"post-fix comparator negative controls failed: {checks}")
_fc_output("synthetic-controls.json").write_text(
    json.dumps({"authored_in_memory_only": True, "checks": checks}, indent=2) + "\n",
    encoding="utf-8")
print(json.dumps({"passed": True, "checks": checks}))
