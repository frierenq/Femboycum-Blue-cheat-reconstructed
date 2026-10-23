"""Fail-closed, text-only comparison of authored and offline guest results.

All checks are explicit exceptions, so Python -O cannot disable them.
This script never launches the native harness, original core, or VM.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import argparse
import hashlib
import json
import posixpath
import re
import sys
from pathlib import Path

ACTION_SHA = "14a6af6741ed92f51f087ed83fc6a9b725a87cdadbb917f76a5ba5976aec03fd"
EXPECTED_SHA = "4273b3d7ce83de9dd7ba5f41570f371b3436ed57cba3eb37c07cf1bb1fc758e6"
ACTION_BYTES, EXPECTED_BYTES, COUNT = 396481, 2202241, 6632
SOURCE_SHA = "af425660ed8102a31912e24856c709bb8f04753a0e3a0cec22e78cad7ebd1b3f"
PROBE_SHA = "f91721362c1b6f00483fea5c74a3df6005c75184eae6bc81b68eb64ec3717dee"
GUEST_UUID = os.environ["FC_RESEARCH_GUEST_UUID"]
GUEST_OUTPUT_DIR = os.environ["FC_RESEARCH_GUEST_OUTPUT_DIR"]
WORD = re.compile(r"0x[0-9a-f]{8}\Z")
BYTES20 = re.compile(r"[0-9a-f]{40}\Z")

def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def file_bytes(path: Path, limit: int) -> bytes:
    raw = path.read_bytes()
    need(len(raw) <= limit, f"{path.name}: oversized")
    return raw

def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        need(key not in result, f"duplicate JSON key {key!r}")
        result[key] = value
    return result

def bad_constant(value: str):
    raise ValueError(f"invalid JSON numeric constant {value}")

def parse_json(raw: bytes, label: str):
    try:
        return json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=unique_keys, parse_constant=bad_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}: invalid UTF-8/JSON: {exc}") from exc

def jsonl(raw: bytes, label: str) -> list[dict]:
    need(raw.endswith(b"\n"), f"{label}: missing final newline")
    parts = raw.split(b"\n")[:-1]
    need(bool(parts) and all(parts), f"{label}: empty row")
    output = []
    for index, part in enumerate(parts):
        row = parse_json(part, f"{label} row {index}")
        need(type(row) is dict, f"{label} row {index}: expected object")
        output.append(row)
    return output

def word(value: str, line: int) -> int:
    need(WORD.fullmatch(value) is not None, f"action line {line}: bad word")
    return int(value[2:], 16)

def bytes20(value: str, line: int) -> str:
    need(BYTES20.fullmatch(value) is not None, f"action line {line}: bad 20-byte field")
    return value

def decimal(value: str, line: int) -> int:
    need(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None,
         f"action line {line}: bad decimal")
    number = int(value)
    need(number <= 0xffffffff, f"action line {line}: decimal overflow")
    return number

def fixture_identities(raw: bytes) -> list[dict]:
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("action file is not ASCII") from exc
    result = []
    for line_number, line in enumerate(lines, 1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        kind = fields[0]
        if kind == "B":
            need(len(fields) == 5, f"action line {line_number}: B arity")
            cursor, count = decimal(fields[1], line_number), decimal(fields[2], line_number)
            value, data = word(fields[3], line_number), bytes20(fields[4], line_number)
            key = "00" * 20
            need(cursor <= 160 and 1 <= count <= 32 and
                 (count == 32 or value >> count == 0),
                 f"action line {line_number}: B domain")
        elif kind == "C":
            need(len(fields) == 4, f"action line {line_number}: C arity")
            cursor, value = decimal(fields[1], line_number), word(fields[2], line_number)
            data, count, key = bytes20(fields[3], line_number), 0, "00" * 20
            need(cursor <= 160, f"action line {line_number}: C cursor")
        elif kind == "X":
            need(len(fields) == 3, f"action line {line_number}: X arity")
            cursor, count, value = 0, 0, 0
            data, key = bytes20(fields[1], line_number), bytes20(fields[2], line_number)
        else:
            raise ValueError(f"action line {line_number}: unknown kind")
        result.append({"index": len(result), "line": line_number, "kind": kind,
                       "value_bits": f"0x{value:08x}", "count": count,
                       "input_data": data, "key": key, "cursor_before": cursor})
    need(len(result) == COUNT, "action file count differs from pinned fixture")
    return result

def captured_file(capture: dict, name: str, raw: bytes) -> None:
    entries = capture.get("guest_files_read")
    need(type(entries) is list, "capture: missing guest_files_read")
    expected_path = GUEST_OUTPUT_DIR + "/" + name
    found = [row for row in entries if type(row) is dict and
             type(row.get("guest_path")) is str and
             row["guest_path"].replace("\\", "/") == expected_path and
             posixpath.normpath(row["guest_path"].replace("\\", "/")) == expected_path]
    need(len(found) == 1, f"capture: need exact normalized {expected_path} entry")
    row = found[0]
    need(type(row.get("bytes")) is int and row["bytes"] == len(raw),
         f"capture: {name} byte count mismatch")
    need(type(row.get("sha256")) is str and row["sha256"] == digest(raw),
         f"capture: {name} SHA-256 mismatch")

def number_field(row: dict, name: str, label: str, low: int, high: int) -> int:
    value = row.get(name)
    need(type(value) is int and low <= value <= high, f"{label}: bad {name}")
    return value

def string_field(row: dict, name: str, label: str, pattern: re.Pattern[str]) -> str:
    value = row.get(name)
    need(type(value) is str and pattern.fullmatch(value) is not None,
         f"{label}: bad {name}")
    return value

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("expectations", type=Path)
    ap.add_argument("guest_jsonl", type=Path)
    for flag in ("actions", "coverage", "probe-receipt", "capture", "exit-code"):
        ap.add_argument("--" + flag, type=Path, required=True)
    args = ap.parse_args()
    actions_raw = file_bytes(args.actions, 1024 * 1024)
    expected_raw = file_bytes(args.expectations, 8 * 1024 * 1024)
    guest_raw = file_bytes(args.guest_jsonl, 16 * 1024 * 1024)
    exit_raw = file_bytes(args.exit_code, 64)
    coverage = parse_json(file_bytes(args.coverage, 65536), "coverage")
    probe = parse_json(file_bytes(args.probe_receipt, 65536), "probe receipt")
    capture = parse_json(file_bytes(args.capture, 1024 * 1024), "capture receipt")
    need(type(coverage) is dict and type(probe) is dict and type(capture) is dict,
         "coverage/probe/capture must be JSON objects")

    need(len(actions_raw) == ACTION_BYTES and digest(actions_raw) == ACTION_SHA,
         "action file differs from pinned fixture")
    need(len(expected_raw) == EXPECTED_BYTES and digest(expected_raw) == EXPECTED_SHA,
         "expectations differ from pinned authored probe output")
    need(coverage.get("actions") == COUNT and
         coverage.get("action_file_bytes") == ACTION_BYTES and
         coverage.get("action_file_sha256") == ACTION_SHA,
         "coverage receipt/action pin mismatch")
    need(probe.get("evidence_class") == "authored-owned-bit-writer" and
         probe.get("actions") == COUNT and
         probe.get("action_file_bytes") == ACTION_BYTES and
         probe.get("action_file_sha256") == ACTION_SHA and
         probe.get("expectations_bytes") == EXPECTED_BYTES and
         probe.get("expectations_sha256") == EXPECTED_SHA and
         probe.get("source_bit_writer_cpp_sha256") == SOURCE_SHA and
         probe.get("owned_probe_cpp_sha256") == PROBE_SHA and
         probe.get("mxcsr_controls") == "0x1f80" and
         probe.get("original_code_executed") is False and
         probe.get("native_harness_executed") is False,
         "probe receipt/pin mismatch")
    try:
        exit_text = exit_raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("exit-code file is not ASCII") from exc
    need(re.fullmatch(r"0[ \t]*(?:\r?\n)?", exit_text) is not None,
         "guest exit-code file is missing/nonzero/malformed")
    need(capture.get("vm_state") == "poweroff" and
         capture.get("guest_uuid") == GUEST_UUID and
         capture.get("mounted") is False and
         capture.get("guest_code_executed_by_reader") is False and
         capture.get("all_requested_data_initialized") is True and
         capture.get("only_authored_result_files_extracted") is True and
         capture.get("disk_size_mtime_unchanged") is True,
         "offline capture receipt state mismatch")
    captured_file(capture, "exit-code.txt", exit_raw)
    captured_file(capture, "native.jsonl", guest_raw)

    source = fixture_identities(actions_raw)
    expected, guest = jsonl(expected_raw, "authored"), jsonl(guest_raw, "guest")
    need(len(source) == len(expected) == len(guest) == COUNT,
         "action/authored/guest row count mismatch")
    mismatches = []
    for index, (fixture, want, got) in enumerate(zip(source, expected, guest)):
        for label, row in (("authored", want), ("guest", got)):
            need(number_field(row, "index", label, 0, COUNT-1) == index,
                 f"{label} row {index}: noncontiguous index")
            for field, value in fixture.items():
                need(type(row.get(field)) is type(value) and row[field] == value,
                     f"{label} row {index}: source fixture identity mismatch at {field}")
            string_field(row, "output_data", label, BYTES20)
            number_field(row, "cursor_after", label, 0, 160)
            number_field(row, "overflow", label, 0, 1)
        need(string_field(got, "source_key_after", "guest", BYTES20) == fixture["key"],
             f"guest row {index}: source key changed")
        need(got.get("source_key_unchanged") is True and
             got.get("immutable_header_unchanged") is True and
             got.get("buffer_canaries_unchanged") is True,
             f"guest row {index}: source/header/canary invariant absent or false")
        mxcsr = string_field(got, "mxcsr", "guest", WORD)
        need((int(mxcsr, 16) & ~0x3f) == 0x1f80,
             f"guest row {index}: MXCSR controls differ from 0x1f80")
        effects = {field: [want[field], got[field]]
                   for field in ("output_data", "cursor_after", "overflow")
                   if want[field] != got[field]}
        if effects:
            mismatches.append({"index": index, "kind": fixture["kind"], "effects": effects})
    print(json.dumps({"compared": COUNT, "mismatches": len(mismatches),
                      "first_25": mismatches[:25]}, indent=2))
    return 1 if mismatches else 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"comparison refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
