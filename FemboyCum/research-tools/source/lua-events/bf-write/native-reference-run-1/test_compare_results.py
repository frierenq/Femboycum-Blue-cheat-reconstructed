"""Synthetic text-only controls for compare_results.py. No native execution."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import hashlib
import json
import subprocess
import sys
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


from compare_results import GUEST_OUTPUT_DIR, GUEST_UUID

HERE = Path(__file__).resolve().parent
SCRATCH = _fc_output("comparison-negative-controls")
SCRATCH.mkdir(parents=True, exist_ok=True)
EXPECTED = Path(os.environ["FC_RESEARCH_INPUT_DIR"]) / "expectations.jsonl"
ACTION = Path(os.environ["FC_RESEARCH_INPUT_DIR"]) / "actions.txt"
COVERAGE = Path(os.environ["FC_RESEARCH_INPUT_DIR"]) / "coverage.json"
PROBE = Path(os.environ["FC_RESEARCH_INPUT_DIR"]) / "probe-receipt.json"
COMPARATOR = HERE / "compare_results.py"

def need(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)

def payload(rows: list[dict]) -> bytes:
    return b"".join((json.dumps(row,separators=(",",":"))+"\n").encode("ascii")
                    for row in rows)

authored = [json.loads(line) for line in EXPECTED.read_text(encoding="utf-8").splitlines()]
guest = []
for row in authored:
    new = {key:value for key,value in row.items() if key != "evidence_class"}
    new.update(source_key_after=row["key"], source_key_unchanged=True,
               immutable_header_unchanged=True, buffer_canaries_unchanged=True,
               mxcsr="0x00001f80")
    guest.append(new)

def run_case(name: str, rows: list[dict], exit_data: bytes = b"0 \r\n",
             missing_exit: bool = False, truncate: bool = False,
             tamper_capture: bool = False,
             capture_directory: str = GUEST_OUTPUT_DIR) -> subprocess.CompletedProcess:
    result_path = SCRATCH / "native.jsonl"
    exit_path = SCRATCH / "exit-code.txt"
    capture_path = SCRATCH / "capture.json"
    raw = payload(rows)
    if truncate:
        raw = raw[:-5]
    result_path.write_bytes(raw)
    exit_path.write_bytes(exit_data)
    record = lambda filename, data: {
        "guest_path": capture_directory + "/" + filename,
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    capture = {
        "vm_state": "poweroff",
        "guest_uuid": GUEST_UUID,
        "mounted": False, "guest_code_executed_by_reader": False,
        "all_requested_data_initialized": True,
        "only_authored_result_files_extracted": True,
        "disk_size_mtime_unchanged": True,
        "guest_files_read": [record("exit-code.txt",exit_data),
                             record("native.jsonl",raw)],
    }
    if tamper_capture:
        capture["guest_files_read"][1]["sha256"] = "0" * 64
    capture_path.write_text(json.dumps(capture),encoding="utf-8")
    missing_path = SCRATCH/"missing-exit-code.txt"
    need(not missing_path.exists(), "reserved missing-exit path unexpectedly exists")
    command = [sys.executable, "-O", str(COMPARATOR), str(EXPECTED),
               str(result_path), "--actions", str(ACTION),
               "--coverage", str(COVERAGE), "--probe-receipt", str(PROBE),
               "--capture", str(capture_path), "--exit-code",
               str(missing_path if missing_exit else exit_path)]
    process = subprocess.run(command,capture_output=True,text=True)
    print(f"{name}: exit {process.returncode}")
    return process

need(run_case("synthetic-control",guest).returncode == 0,
     "complete synthetic control was refused")
need(run_case("truncated-row",guest,truncate=True).returncode == 2,
     "truncated guest row was accepted")
need(run_case("missing-row",guest[:-1]).returncode == 2,
     "missing guest row was accepted")
changed = [dict(row) for row in guest]
changed[0]["value_bits"] = "0xdeadbeef"
need(run_case("changed-input-row",changed).returncode == 2,
     "changed source identity was accepted")
missing_field = [dict(row) for row in guest]
del missing_field[0]["source_key_after"]
need(run_case("missing-key-field",missing_field).returncode == 2,
     "missing invariant field was accepted")
need(run_case("missing-exit-file",guest,missing_exit=True).returncode == 2,
     "missing exit-code file was accepted")
need(run_case("nonzero-exit-file",guest,exit_data=b"1 \r\n").returncode == 2,
     "nonzero exit-code file was accepted")
bad_mxcsr = [dict(row) for row in guest]
bad_mxcsr[0]["mxcsr"] = "0x00001fc0"
need(run_case("changed-mxcsr-control",bad_mxcsr).returncode == 2,
     "changed MXCSR control was accepted")
bad_key = [dict(row) for row in guest]
bad_key[0]["source_key_after"] = "ff" * 20
need(run_case("changed-source-key",bad_key).returncode == 2,
     "changed source key was accepted")
bad_header = [dict(row) for row in guest]
bad_header[0]["immutable_header_unchanged"] = False
need(run_case("changed-header-flag",bad_header).returncode == 2,
     "false header invariant was accepted")
bad_canary = [dict(row) for row in guest]
bad_canary[0]["buffer_canaries_unchanged"] = False
need(run_case("false-canary-flag",bad_canary).returncode == 2,
     "false canary invariant was accepted")
missing_canary = [dict(row) for row in guest]
del missing_canary[0]["buffer_canaries_unchanged"]
need(run_case("missing-canary-flag",missing_canary).returncode == 2,
     "missing canary invariant was accepted")
wrong_type_canary = [dict(row) for row in guest]
wrong_type_canary[0]["buffer_canaries_unchanged"] = 1
need(run_case("wrong-type-canary-flag",wrong_type_canary).returncode == 2,
     "non-boolean canary invariant was accepted")
need(run_case("capture-sha-mismatch",guest,tamper_capture=True).returncode == 2,
     "bad reader receipt hash was accepted")
need(run_case("same-basename-wrong-directory",guest,
              capture_directory="/SYNTHETIC-TEXT-ONLY").returncode == 2,
     "same-basename files from another guest directory were accepted")
changed_effect = [dict(row) for row in guest]
changed_effect[0]["output_data"] = "ff" * 20
need(run_case("effect-disagreement",changed_effect).returncode == 1,
     "effect mismatch did not produce a comparison failure")
print("all synthetic text-only controls passed under Python -O")
