"""Strict text comparison for a future offline-captured VM-only RNG run 3.

This script only reads archived files. It never boots the VM or loads vendor DLLs.
Exit 0: exact value/state/mode/FP status; 1: well-formed differences;
2: malformed data or broken preparation/capture provenance.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import argparse
from collections import Counter
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

import re
import sys

if not __debug__:
    raise RuntimeError("optimized Python disables evidence checks")

HERE = Path(os.environ["FC_RESEARCH_INPUT_DIR"])
RUN = Path(os.environ["FC_RESEARCH_RUN3_DIR"])
GUEST_DIR = os.environ["FC_RESEARCH_GUEST_OUTPUT_DIR"]
GUEST_UUID = os.environ["FC_RESEARCH_GUEST_UUID"]
COUNT = 1692
EXPECTED_HASHES = {
    "actions.txt": "243ce91969fa47d6b9ddaecacab1fabfa22da7ea8f7b0bce0874983dea6e0911",
    "fixture-manifest.json": "4c8cb1b84fac105197b2b1dbc6131b07e80389ae97b2adef212eab013f5c6b77",
    "media-preparation.json": "28205e6f61074380781ac863276fb75e3e42b4c2d89b264a8fd4a483eef17566",
    "authored-preparation.json": "e7d0defd88051cd32e9b833a7997ba01da72686c0fbac9a144c830e02cb9a809",
    "owned-per-action-receipt.json": "922fb282d32e1b4583487afcbe6a7b79851575c438439a84e4da8bff0bc4fe09",
    "source-expected.json": "fb6fe9d79570b197ddbe347e5e43dd02261bd5d17f731fe98db53f4c6fbb832d",
    "authored-probe.txt": "4a0b72f0ed8859439d391962b494acbb8b21410a87906b822553407382c61c0e",
    "owned-per-action.txt": "de63dfdc2ce06a506dd86cf1959f2fa4324cd8589b8faf08e44e42fa6feaf535",
    "femboycum-rng-run3-per-action-unrun.iso": "a46905d1d324702514fefad89706d99980d7ce58fe4881ce98793e2150a2dd62",
    "native_rng_per_action_reference.cpp": "c494279e9eefa2d1c5dfc5f97346ed9f3c761571341b4e215a09a3db5c51c299",
    "CMakeLists.txt": "b21983602795b543a35a684ff3db160bc6494728aa64c7fa1c2f5cbdc71381a3",
    "run.cmd": "7da91263e0bcfb379dfc7be17dc1ee12d4cefeb8b3a94bf9931296ce2f71737e",
}
HEX_WORD = re.compile(r"0x[0-9a-f]{8}\Z")
HEX8 = re.compile(r"[0-9a-f]{8}\Z")
HEX4 = re.compile(r"[0-9a-f]{4}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
FLOAT = re.compile(r"0x[0-9a-f]{8}\Z")
DLL_PATH = re.compile(r"[A-Za-z]:\\RNG3\\(vstdlib|tier0)\.dll\Z", re.I)
ARITY = {"S": 1, "I": 2, "F": 2, "E": 3, "M": 0}
ROW_KEYS = {
    "sequence", "line", "action", "input_bits", "value_kind", "value_bits",
    "fp_reset_per_action", "mxcsr_pre_action", "mxcsr_post_action",
    "mxcsr_before_setup", "x87_control_pre_action", "x87_status_pre_action",
    "x87_control_post_action", "x87_status_post_action",
    "x87_control_before_setup", "x87_status_before_setup", "vstdlib_path",
    "tier0_path", "dispatch_pointer", "default_vtable", "selected_default",
    "expected_vtable", "default_state_seed", "default_state_output",
    "default_state_table",
}


class EvidenceError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise EvidenceError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_int(value: object, name: str, low: int = 0, high: int = 0xffffffff) -> int:
    require(type(value) is int and low <= value <= high, f"{name}: invalid integer")
    return value


def exact_bool(value: object, name: str) -> bool:
    require(type(value) is bool, f"{name}: invalid boolean")
    return value


def hex_word(value: object, name: str) -> int:
    require(type(value) is str and HEX_WORD.fullmatch(value) is not None,
            f"{name}: expected lowercase 0x plus eight hex digits")
    return int(value, 16)


def pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(value: str):
    raise EvidenceError(f"non-JSON numeric constant {value}")


def decode_json(raw: bytes, label: str):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_no_duplicates,
                          parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label}: malformed UTF-8/JSON: {error}") from error


def strict_lines(raw: bytes, label: str, maximum: int, *, ascii_only: bool = True,
                 lf_only: bool = False) -> list[str]:
    require(0 < len(raw) <= maximum and raw.endswith(b"\n"),
            f"{label}: empty/oversized or missing final newline")
    if lf_only:
        require(b"\r" not in raw, f"{label}: expected LF-only records")
    try:
        text = raw.decode("ascii" if ascii_only else "utf-8")
    except UnicodeError as error:
        raise EvidenceError(f"{label}: invalid text encoding") from error
    lines = text.splitlines()
    require(len(lines) == COUNT and all(lines),
            f"{label}: expected exactly {COUNT} nonempty records")
    return lines


def read_pinned(name: str) -> bytes:
    raw = (HERE / name).read_bytes()
    require(sha(raw) == EXPECTED_HASHES[name], f"prepared file hash changed: {name}")
    return raw


def parse_actions(lines: list[str]) -> list[tuple[str, list[int]]]:
    actions = []
    counts = Counter()
    for index, line in enumerate(lines):
        tokens = line.split(" ")
        require(tokens and tokens[0] in ARITY and len(tokens) == ARITY[tokens[0]] + 1
                and all(tokens), f"action {index}: syntax/arity")
        kind = tokens[0]
        values = []
        for token in tokens[1:]:
            if kind in ("S", "I"):
                require(re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token) is not None,
                        f"action {index}: signed decimal syntax")
                number = int(token)
                require(-(1 << 31) <= number < (1 << 31),
                        f"action {index}: signed int32 range")
                values.append(number & 0xffffffff)
            else:
                require(FLOAT.fullmatch(token) is not None,
                        f"action {index}: raw float bit syntax")
                values.append(int(token, 16))
        counts[kind] += 1
        actions.append((kind, values))
    require(dict(counts) == {"E": 760, "F": 72, "I": 20, "M": 2, "S": 838},
            "action-kind counts changed")
    return actions


def load_prepared() -> tuple[list[str], list[tuple[str, list[int]]], list[dict], list[dict]]:
    blobs = {name: read_pinned(name) for name in EXPECTED_HASHES}
    manifest = decode_json(blobs["fixture-manifest.json"], "fixture manifest")
    media = decode_json(blobs["media-preparation.json"], "media preparation")
    authored = decode_json(blobs["authored-preparation.json"], "authored preparation")
    owned = decode_json(blobs["owned-per-action-receipt.json"], "owned preparation")
    require(type(manifest) is dict and type(media) is dict and
            type(authored) is dict and type(owned) is dict, "receipt object shape")
    require(exact_bool(manifest.get("prepared_only"), "manifest prepared_only") and
            exact_bool(media.get("prepared_only"), "media prepared_only") and
            not exact_bool(manifest.get("native_reference_executed"), "manifest native execution") and
            not exact_bool(media.get("native_reference_executed"), "media native execution") and
            not exact_bool(media.get("vm_operated"), "media VM operation"),
            "prepared receipts do not describe unrun media")
    require(exact_int(manifest.get("action_count"), "manifest action count") == COUNT and
            exact_int(manifest.get("action_bytes"), "manifest action bytes") == len(blobs["actions.txt"]) and
            manifest.get("actions_sha256") == EXPECTED_HASHES["actions.txt"] and
            media.get("guest_uuid") == GUEST_UUID and
            media.get("manual_guest_output_dir") == GUEST_DIR and
            media.get("iso_sha256") == EXPECTED_HASHES["femboycum-rng-run3-per-action-unrun.iso"] and
            media.get("source_harness_sha256") == EXPECTED_HASHES["native_rng_per_action_reference.cpp"] and
            media.get("source_cmake_sha256") == EXPECTED_HASHES["CMakeLists.txt"] and
            media.get("fixture_manifest_sha256") == EXPECTED_HASHES["fixture-manifest.json"] and
            media.get("authored_preparation_sha256") == EXPECTED_HASHES["authored-preparation.json"],
            "fixture/media receipt join changed")
    for name, receipt in (("authored", authored), ("owned", owned)):
        require(exact_bool(receipt.get("authored_only"), f"{name} authored_only") and
                not exact_bool(receipt.get("native_reference_executed"), f"{name} native execution") and
                receipt.get("actions_sha256") == EXPECTED_HASHES["actions.txt"] and
                exact_int(receipt.get("rows"), f"{name} rows") == COUNT,
                f"{name} receipt join changed")
    require(authored.get("probe_stdout_sha256") == EXPECTED_HASHES["authored-probe.txt"] and
            authored.get("probe_exe_sha256") ==
            "4c82f2b3fce5d432c485d1f66e0b903e7584b28a0788bfd2eb3ad24329a696a7" and
            authored.get("source_expected_sha256") == EXPECTED_HASHES["source-expected.json"] and
            owned.get("stdout_sha256") == EXPECTED_HASHES["owned-per-action.txt"] and
            owned.get("exe_sha256") ==
            "7408d41685314b47e989f863d4a846d13deaac35ba90d291aa461440fbf49877",
            "authored output receipt join changed")
    iso_files = media.get("files")
    require(type(iso_files) is list, "media file manifest missing")
    iso_by_path = {entry.get("joliet_path"): entry for entry in iso_files
                   if type(entry) is dict}
    require(len(iso_by_path) == len(iso_files) and
            iso_by_path.get("/run.cmd", {}).get("sha256") == EXPECTED_HASHES["run.cmd"] and
            iso_by_path.get("/RNG3/actions.txt", {}).get("sha256") == EXPECTED_HASHES["actions.txt"] and
            iso_by_path.get("/RNG3/native_rng_per_action_reference.exe", {}).get("sha256") ==
            "0e9382a9dc24dad0eaac5753041588d8c1c6b85efc71ea6ed5b6a31da77df22f" and
            iso_by_path.get("/RNG3/vstdlib.dll", {}).get("sha256") ==
            "25af287294687ca41eb276732bb01dade88d15daccb2e8658b00775ce989538f" and
            iso_by_path.get("/RNG3/tier0.dll", {}).get("sha256") ==
            "c74788938d265fdc0172b299ee1fd42e622b15586977093b1ac4aa2c09925312",
            "media contents identity changed")
    action_lines = strict_lines(blobs["actions.txt"], "actions", 1024 * 1024,
                                lf_only=True)
    actions = parse_actions(action_lines)
    expected = decode_json(blobs["source-expected.json"], "source expected")
    require(type(expected) is list and len(expected) == COUNT,
            "source expected row count")
    probe_lines = strict_lines(blobs["authored-probe.txt"], "authored probe", 2 * 1024 * 1024)
    owned_lines = strict_lines(blobs["owned-per-action.txt"], "owned FP probe", 1024 * 1024)
    fp_rows = []
    for index, (action_line, (kind, values), row, probe_line, fp_line) in enumerate(
            zip(action_lines, actions, expected, probe_lines, owned_lines)):
        require(type(row) is dict, f"source row {index}: object")
        keys = {"sequence", "line", "action", "value_bits", "state_words",
                "authored_generation_count"}
        if kind == "M":
            keys.add("authored_probe_mxcsr")
        require(set(row) == keys and
                exact_int(row["sequence"], f"source {index} sequence") == index and
                exact_int(row["line"], f"source {index} line") == index + 1
                and row["action"] == action_line, f"source row {index}: echo/schema")
        require(type(row["state_words"]) is list and len(row["state_words"]) == 34,
                f"source row {index}: 34-word state")
        state = [hex_word(value, f"source {index} state") for value in row["state_words"]]
        generation = exact_int(row["authored_generation_count"], f"source {index} generation")
        p = probe_line.split()
        require(p and p[0] == kind and len(p) == (37 if kind != "S" else 36)
                and all(re.fullmatch(r"-?(?:0|[1-9][0-9]*)", x) for x in p[1:]),
                f"source probe {index}: decimal row shape")
        numbers = [int(x, 10) for x in p[1:]]
        raw_value = None if kind == "S" else numbers.pop(0)
        require(len(numbers) == 35 and all(-(1 << 31) <= v <= 0xffffffff for v in numbers),
                f"source probe {index}: word domain")
        require((numbers[0] & 0xffffffff) == state[0] and
                (numbers[1] & 0xffffffff) == state[1] and
                numbers[2] == generation and
                [n & 0xffffffff for n in numbers[3:]] == state[2:],
                f"source probe {index}: state/generation echo")
        if kind == "M":
            require(row["value_bits"] is None and raw_value & ~0x3f == 0x1f80 and
                    hex_word(row["authored_probe_mxcsr"], f"source {index} M") == raw_value,
                    f"source probe {index}: M observation")
        elif kind == "S":
            require(row["value_bits"] is None, f"source {index}: seed has value")
        else:
            require(hex_word(row["value_bits"], f"source {index} value") ==
                    (raw_value & 0xffffffff),
                    f"source probe {index}: value echo")
        f = fp_line.split()
        require(len(f) == 13 and re.fullmatch(r"[0-9]+", f[0]) is not None and
                re.fullmatch(r"[0-9]+", f[2]) is not None and
                exact_int(int(f[0]), f"owned {index} sequence") == index and
                f[1] == kind and int(f[2]) == len(values),
                f"owned probe {index}: identity/arity")
        require(all(HEX8.fullmatch(x) for x in f[3:8]),
                f"owned probe {index}: value/input/pre-MXCSR word format")
        require(HEX4.fullmatch(f[8]) is not None and HEX4.fullmatch(f[9]) is not None and
                HEX8.fullmatch(f[10]) is not None and HEX4.fullmatch(f[11]) is not None and
                HEX4.fullmatch(f[12]) is not None,
                f"owned probe {index}: FP word format")
        fp_input = [int(x, 16) for x in f[3:6]]
        require(fp_input == values + [0] * (3 - len(values)),
                f"owned probe {index}: action input echo")
        fp_value = int(f[6], 16)
        require(fp_value == ((raw_value & 0xffffffff)
                             if kind in ("I", "F", "E") else 0),
                f"owned probe {index}: source value echo")
        pre_mx, pre_cw, pre_sw = int(f[7], 16), int(f[8], 16), int(f[9], 16)
        post_mx, post_cw, post_sw = int(f[10], 16), int(f[11], 16), int(f[12], 16)
        require(pre_mx == 0x1f80 and pre_cw == 0x027f and pre_sw & 0xff == 0 and
                post_mx & ~0x3f == 0x1f80 and post_cw == 0x027f,
                f"owned probe {index}: FP reset/control")
        fp_rows.append({"pre_mxcsr": pre_mx, "pre_x87_control": pre_cw,
                        "pre_x87_status": pre_sw, "post_mxcsr": post_mx,
                        "post_x87_control": post_cw, "post_x87_status": post_sw})
    return action_lines, actions, expected, fp_rows


def load_capture(capture_dir: Path, *, synthetic: bool = False) -> tuple[list[dict], dict]:
    expected_dir = (RUN / "guest-capture").resolve()
    if synthetic:
        synthetic_root = _fc_output("synthetic-controls")
        require(capture_dir.resolve().is_relative_to(synthetic_root),
                "synthetic capture must stay under synthetic-controls")
    else:
        require(capture_dir.resolve() == expected_dir,
                "native capture must be the exact run3 guest-capture directory")
    manifest_path = capture_dir / "capture.json"
    raw_manifest = manifest_path.read_bytes()
    require(len(raw_manifest) < 1024 * 1024 and raw_manifest.endswith(b"\n"),
            "offline capture manifest size/newline")
    manifest = decode_json(raw_manifest, "offline capture")
    require(type(manifest) is dict, "offline capture must be object")
    require(manifest.get("synthetic", False) is synthetic,
            "synthetic/real capture marker mismatch")
    require(manifest.get("vm_state") == "poweroff" and
            manifest.get("guest_uuid") == GUEST_UUID and
            exact_bool(manifest.get("mounted"), "capture mounted") is False and
            exact_bool(manifest.get("guest_code_executed_by_reader"),
                       "capture reader execution") is False and
            exact_bool(manifest.get("all_requested_data_initialized"),
                       "capture initialized") is True and
            exact_bool(manifest.get("only_authored_result_files_extracted"),
                       "capture file scope") is True and
            exact_bool(manifest.get("disk_size_mtime_unchanged"),
                       "capture disk unchanged") is True,
            "offline capture VM/read-only proof fields")
    images = manifest.get("images")
    require(type(images) is list and images and all(type(item) is dict and
            exact_bool(item.get("size_mtime_unchanged"), "image unchanged")
            for item in images), "offline capture image read-only receipts")
    for hash_field in ("mft_sha256",):
        value = manifest.get(hash_field)
        require(type(value) is str and HASH.fullmatch(value) is not None,
                f"offline capture {hash_field}")
    guest_files = manifest.get("guest_files_read")
    require(type(guest_files) is list and guest_files, "offline guest file list")
    by_name = {}
    for entry in guest_files:
        require(type(entry) is dict, "offline guest file entry")
        path = entry.get("guest_path")
        require(type(path) is str and
                path in {f"{GUEST_DIR}/native.jsonl", f"{GUEST_DIR}/exit-code.txt",
                         f"{GUEST_DIR}/run.log"},
                "offline guest file exact output path")
        name = path.rsplit("/", 1)[-1]
        require(name not in by_name, "duplicate offline guest file entry")
        size = exact_int(entry.get("bytes"), f"offline {name} bytes", high=32 * 1024 * 1024)
        digest = entry.get("sha256")
        require(type(digest) is str and HASH.fullmatch(digest) is not None,
                f"offline {name} digest")
        raw = (capture_dir / name).read_bytes()
        require(len(raw) == size and sha(raw) == digest,
                f"offline {name} size/hash differs from disk reader receipt")
        by_name[name] = raw
    require({"native.jsonl", "exit-code.txt"} <= set(by_name),
            "offline capture lacks native output or exit code")
    require(by_name["exit-code.txt"] == b"0 \r\n",
            "guest run.cmd exit code must be exact zero echo")
    native_lines = strict_lines(by_name["native.jsonl"], "native JSONL",
                                32 * 1024 * 1024, lf_only=True)
    rows = [decode_json(line.encode("ascii"), f"native row {index}")
            for index, line in enumerate(native_lines)]
    return rows, {
        "capture_manifest_sha256": sha(raw_manifest),
        "native_jsonl_sha256": sha(by_name["native.jsonl"]),
        "exit_code_sha256": sha(by_name["exit-code.txt"]),
        "guest_uuid": GUEST_UUID, "guest_output_dir": GUEST_DIR,
        "capture_dir": str(capture_dir.resolve()), "synthetic": synthetic,
    }


def inspect_native_row(index: int, row: dict, action: tuple[str, list[int]],
                       expected: dict) -> dict:
    kind, inputs = action
    require(type(row) is dict and set(row) == ROW_KEYS,
            f"native row {index}: exact JSON object schema")
    require(exact_int(row["sequence"], f"native {index} sequence") == index and
            exact_int(row["line"], f"native {index} line") == index + 1 and
            row["action"] == kind and type(row["action"]) is str,
            f"native row {index}: sequence/line/kind echo")
    require(type(row["input_bits"]) is list and len(row["input_bits"]) == len(inputs)
            and [hex_word(value, f"native {index} input") for value in row["input_bits"]]
            == inputs, f"native row {index}: input echo")
    require(exact_bool(row["fp_reset_per_action"], f"native {index} reset"),
            f"native row {index}: per-action reset marker false")
    require(exact_bool(row["selected_default"], f"native {index} default") and
            exact_bool(row["expected_vtable"], f"native {index} vtable"),
            f"native row {index}: wrong stream identity")
    dispatch = hex_word(row["dispatch_pointer"], f"native {index} dispatch")
    vtable = hex_word(row["default_vtable"], f"native {index} vtable")
    require((dispatch - vtable) & 0xffffffff == (0x3aa20 - 0x2e778),
            f"native row {index}: dispatch/vtable offset join")
    vstdlib_path = row["vstdlib_path"]
    tier0_path = row["tier0_path"]
    require(type(vstdlib_path) is str and type(tier0_path) is str and
            DLL_PATH.fullmatch(vstdlib_path) is not None and
            DLL_PATH.fullmatch(tier0_path) is not None and
            vstdlib_path.lower().endswith("\\rng3\\vstdlib.dll") and
            tier0_path.lower().endswith("\\rng3\\tier0.dll") and
            vstdlib_path[:2].casefold() == tier0_path[:2].casefold(),
            f"native row {index}: restricted ISO DLL path echo")
    want_kind = "i32" if kind == "I" else ("f32" if kind in ("F", "E") else "none")
    require(row["value_kind"] == want_kind and type(row["value_kind"]) is str,
            f"native row {index}: result kind")
    if want_kind == "none":
        require(row["value_bits"] is None and expected["value_bits"] is None,
                f"native row {index}: no-call result shape")
        result = None
    else:
        result = hex_word(row["value_bits"], f"native {index} value")
    state_table = row["default_state_table"]
    require(type(state_table) is list and len(state_table) == 32,
            f"native row {index}: table width")
    state = [hex_word(row["default_state_seed"], f"native {index} seed"),
             hex_word(row["default_state_output"], f"native {index} output")]
    state.extend(hex_word(value, f"native {index} table") for value in state_table)
    fp = {field: hex_word(row[field], f"native {index} {field}") for field in (
        "mxcsr_pre_action", "mxcsr_post_action", "mxcsr_before_setup",
        "x87_control_pre_action", "x87_status_pre_action",
        "x87_control_post_action", "x87_status_post_action",
        "x87_control_before_setup", "x87_status_before_setup")}
    require(all(fp[field] <= 0xffff for field in fp if field.startswith("x87_")),
            f"native row {index}: x87 register width")
    require(fp["mxcsr_pre_action"] == 0x1f80 and
            fp["x87_control_pre_action"] == 0x027f and
            fp["x87_status_pre_action"] & 0xff == 0,
            f"native row {index}: unclean/incorrect pre-action FP reset")
    return {"result": result, "state": state, "fp": fp,
            "dispatch": dispatch, "vtable": vtable,
            "vstdlib_path": vstdlib_path, "tier0_path": tier0_path}


def compare_rows(rows: list[dict], actions: list[tuple[str, list[int]]],
                 expected: list[dict], fp_expected: list[dict]) -> dict:
    require(len(rows) == len(actions) == len(expected) == len(fp_expected) == COUNT,
            "comparison row cardinality")
    counts = Counter()
    differences = {"value": [], "state": [], "mode": [], "fp_status": []}
    capture_identity = None
    for index, (row, action, source, owned) in enumerate(
            zip(rows, actions, expected, fp_expected)):
        observed = inspect_native_row(index, row, action, source)
        identity = (observed["dispatch"], observed["vtable"],
                    observed["vstdlib_path"], observed["tier0_path"],
                    observed["fp"]["mxcsr_before_setup"],
                    observed["fp"]["x87_control_before_setup"],
                    observed["fp"]["x87_status_before_setup"])
        if capture_identity is None:
            capture_identity = identity
        require(identity == capture_identity,
                f"native row {index}: process/module/initial-FP identity changed")
        kind = action[0]
        counts[f"actions_{kind}"] += 1
        want_value = None if source["value_bits"] is None else int(source["value_bits"], 16)
        if observed["result"] != want_value:
            differences["value"].append({"sequence": index, "action": kind,
                                         "source": source["value_bits"],
                                         "native": row["value_bits"]})
        else:
            counts["exact_value_bits_or_no_result"] += 1
        want_state = [int(word, 16) for word in source["state_words"]]
        state_delta = [{"word": slot, "source": f"0x{want:08x}",
                        "native": f"0x{got:08x}"}
                       for slot, (want, got) in enumerate(zip(want_state, observed["state"]))
                       if want != got]
        if state_delta:
            differences["state"].append({"sequence": index, "action": kind,
                                         "words": state_delta})
        else:
            counts["exact_34_word_states"] += 1
        fp = observed["fp"]
        mode_delta = {}
        if fp["mxcsr_post_action"] & ~0x3f != 0x1f80:
            mode_delta["mxcsr_post_controls"] = f"0x{fp['mxcsr_post_action'] & ~0x3f:08x}"
        if fp["x87_control_post_action"] != 0x027f:
            mode_delta["x87_post_control"] = f"0x{fp['x87_control_post_action']:08x}"
        if mode_delta:
            differences["mode"].append({"sequence": index, "action": kind,
                                        "differences": mode_delta})
        else:
            counts["exact_post_control_modes"] += 1
        status_delta = {}
        for native_name, owned_name, mask in (
                ("mxcsr_post_action", "post_mxcsr", 0x3f),
                ("x87_status_pre_action", "pre_x87_status", 0xffff),
                ("x87_status_post_action", "post_x87_status", 0xffff)):
            got = fp[native_name] & mask
            want = owned[owned_name] & mask
            if got != want:
                status_delta[native_name] = {"source": f"0x{want:04x}",
                                             "native": f"0x{got:04x}"}
        if status_delta:
            differences["fp_status"].append({"sequence": index, "action": kind,
                                             "differences": status_delta})
        else:
            counts["exact_full_fp_status"] += 1
    mismatch_counts = {name: len(items) for name, items in differences.items()}
    return {"passed": all(count == 0 for count in mismatch_counts.values()),
            "actions_compared": COUNT, "counts": dict(counts),
            "mismatch_counts": mismatch_counts, "differences": differences,
            "all_result_bits_including_nan_required": True,
            "all_34_state_words_required": True,
            "native_generation_counter_claimed": False,
            "fp_status_scope": "MXCSR exception bits 0..5; full x87 pre/post status word; per-action authored source comparator",
            "mode_scope": "post-action MXCSR controls and x87 control word; pre-action reset/control required structurally"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-source-only", action="store_true")
    parser.add_argument("--synthetic-capture-dir", type=Path,
                        help="tests only: path under preparation/synthetic-controls")
    parser.add_argument("--synthetic-output", type=Path,
                        help="tests only: comparison JSON under preparation/synthetic-controls")
    args = parser.parse_args()
    try:
        _, actions, expected, fp_expected = load_prepared()
        if args.verify_source_only:
            require(args.synthetic_capture_dir is None and args.synthetic_output is None,
                    "source-only mode takes no capture arguments")
            print(json.dumps({"prepared_source_echo_verified": True, "actions": COUNT,
                              "native_reference_executed": False}))
            return 0
        synthetic = args.synthetic_capture_dir is not None
        require((args.synthetic_output is not None) == synthetic,
                "synthetic capture and output must be specified together")
        capture_dir = args.synthetic_capture_dir if synthetic else RUN / "guest-capture"
        output = _fc_checked_output(args.synthetic_output) if synthetic else _fc_output("comparison.json")
        if synthetic:
            require(output.resolve().is_relative_to(_fc_output("synthetic-controls")),
                    "synthetic output must stay under synthetic-controls")
        rows, provenance = load_capture(capture_dir, synthetic=synthetic)
        result = compare_rows(rows, actions, expected, fp_expected)
        result.update({"capture": provenance,
                       "prepared_input_sha256": dict(EXPECTED_HASHES),
                       "scope": "installed hash-pinned vstdlib default RNG stream in exact isolated VM; not historical core/game parity",
                       "native_reference_executed_by_comparer": False})
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"passed": result["passed"],
                          "mismatch_counts": result["mismatch_counts"],
                          "comparison": str(output), "synthetic": synthetic}))
        return 0 if result["passed"] else 1
    except (EvidenceError, OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"provenance/structure failure: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
