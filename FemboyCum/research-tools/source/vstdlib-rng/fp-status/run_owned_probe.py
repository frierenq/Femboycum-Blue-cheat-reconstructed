"""Replay pinned actions through the authored-only FP-status executable."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import argparse
import hashlib
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

import subprocess

RUNS = {
    "run1": {
        "actions": "f6cb6a50b130a47612df37bc1cdfe9c5be5fb3ab67125c7418ddcac3efa4e73d",
        "stdout": "d6994741fde9c3ed7d044395b01ec9fb7ca1fb59625aac9dfda18be940427414",
        "rows": 6274,
    },
    "run2": {
        "actions": "fc9546a2c0949b9e5d1c74e087c4509869a0726ff2903021798a0b4135714a9a",
        "stdout": "c90e5aa70a485107a96b019b43ab5e8a4da44730a03a62b03f14fa1a04fbb1fa",
        "rows": 6738,
    },
}
OWNED_EXE_SHA = "6ece531c10b114a102267e8ef649f3cc164a7bcb4d441bc3b63514a3594313fb"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", choices=sorted(RUNS), required=True)
    parser.add_argument("--actions", type=Path, required=True)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    actions = args.actions.read_bytes()
    if sha(actions) != RUNS[args.run]["actions"]:
        raise SystemExit("wrong action-file SHA-256")
    if args.exe.name.lower() != "owned_rng_fp_status.exe" or sha(args.exe.read_bytes()) != OWNED_EXE_SHA:
        raise SystemExit("not the pinned authored FP-status executable")
    result = subprocess.run([str(args.exe.resolve())], input=actions, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True)
    if result.stderr:
        raise SystemExit("authored probe emitted stderr")
    if sha(result.stdout) != RUNS[args.run]["stdout"] or len(result.stdout.splitlines()) != RUNS[args.run]["rows"]:
        raise SystemExit("authored probe stdout differs from the archived post-fix replay")
    _fc_checked_output(args.out).write_bytes(result.stdout)
    print(f"owned stdout sha256={sha(result.stdout)} rows={len(result.stdout.splitlines())}")


if __name__ == "__main__":
    main()
