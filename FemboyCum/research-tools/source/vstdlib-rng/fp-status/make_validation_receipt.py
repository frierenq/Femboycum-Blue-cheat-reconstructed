"""Pin source, owned build, archived stdout, and immutable text-capture hashes."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import argparse
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


from compare_status import RUNS, compare

HERE = Path(os.environ["FC_RESEARCH_INPUT_DIR"])
SOURCE = Path(os.environ["FC_RESEARCH_SOURCE_ROOT"])


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    sources = {
        name: sha(SOURCE / name) for name in (
            "include/fc/uniform_random.hpp", "src/uniform_random.cpp",
            "src/uniform_random_exp.cpp",
            "tests/uniform_random_tests.cpp",
            "research/vstdlib-rng/fp-status/CMakeLists.txt",
            "research/vstdlib-rng/fp-status/owned_status_probe.cpp",
            "research/vstdlib-rng/fp-status/compare_status.py",
            "research/vstdlib-rng/fp-status/run_owned_probe.py",
            "research/vstdlib-rng/fp-status/make_validation_receipt.py",
            "research/vstdlib-rng/fp-status/static_status.py",
        )
    }
    runs = {}
    for label, directory in (("run1", "vm-rng-inputs"), ("run2", "vm-rng-run2")):
        comparison = json.loads((HERE / f"comparison-{label}.json").read_text())
        pre = json.loads((HERE / f"comparison-{label}-pre-fix.json").read_text())
        actions = work / directory / "actions.txt"
        native = work / directory / "guest-capture/native.jsonl"
        post_stdout = HERE / f"owned-{label}-post.txt"
        pre_stdout = HERE / f"owned-{label}-pre-fix.txt"
        if comparison != compare(label, actions, native, post_stdout):
            raise ValueError(f"stale post-fix comparison for {label}")
        if pre != compare(label, actions, native, pre_stdout, "legacy6"):
            raise ValueError(f"stale pre-fix comparison for {label}")
        if comparison["mismatch_count"] != 0 or pre["mismatch_count"] != (93 if label == "run1" else 0):
            raise ValueError("unexpected comparison count")
        if comparison["actions_sha256"] != RUNS[label]["actions_sha256"] or comparison["native_sha256"] != RUNS[label]["native_sha256"]:
            raise ValueError("unexpected pinned inputs")
        runs[label] = {
            "actions_sha256": sha(actions),
            "native_capture_sha256": sha(native),
            "owned_post_stdout_sha256": sha(post_stdout),
            "owned_pre_fix_stdout_sha256": sha(pre_stdout),
            "post_comparison_sha256": sha(HERE / f"comparison-{label}.json"),
            "pre_fix_comparison_sha256": sha(HERE / f"comparison-{label}-pre-fix.json"),
            "rows": comparison["rows"],
            "post_mismatches": comparison["mismatch_count"],
            "pre_fix_mismatches": pre["mismatch_count"],
        }
    receipt = {
        "evidence_class": "authored Win32 source probe, static installed-PE decode, immutable guest text; no original native execution on host",
        "source_sha256": sources,
        "post_owned_exe_sha256": sha(work / "fp-status-build/Release/owned_rng_fp_status.exe"),
        "post_core_object_sha256": sha(work / "fp-status-rootbuild/fc_core.dir/Release/uniform_random_exp.obj"),
        "pre_fix_owned_exe_sha256": "21231eb44b2390e62438a74b3c6427e73725d84e5a827559710ec05e46446fa7",
        "compiler": "MSVC 19.51.36260.0, Win32, /W4 /WX /permissive- /EHsc /fp:strict /arch:SSE2",
        "static_status_receipt_sha256": sha(HERE / "static-status.json"),
        "runs": runs,
        "limits": ["sticky observations are cumulative after one reset",
                   "post-saturation per-call exceptions cannot be distinguished",
                   "pre-fix stdout is legacy six-field text with SHA-pinned source probe"],
    }
    _fc_output("validation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(_fc_output("validation-receipt.json"))


if __name__ == "__main__":
    main()
