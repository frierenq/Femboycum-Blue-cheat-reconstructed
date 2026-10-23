"""Strict text-only FP comparison; never loads or executes a native DLL.

Exit 0: full match. Exit 1: well-formed value/status difference.
Exit 2: malformed text, wrong fixture/capture hash, or broken run contract.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

if not __debug__:
    print("Python -O is not accepted for this evidence checker", file=sys.stderr)
    raise SystemExit(2)

RUNS = {
    "run1": {
        "actions_sha256": "f6cb6a50b130a47612df37bc1cdfe9c5be5fb3ab67125c7418ddcac3efa4e73d",
        "native_sha256": "b49c831374343a633b39a3776556e71d410b8b6cbf84e0e2631519466dc51f73",
        "pre_owned_sha256": "3f09e7891b2e50709a507d8befc2d88db38a616da8371e6780470d575670df73",
        "rows": 6274,
    },
    "run2": {
        "actions_sha256": "fc9546a2c0949b9e5d1c74e087c4509869a0726ff2903021798a0b4135714a9a",
        "native_sha256": "1a5b8dbd8683d103d111f98935d2fdb6ab69b2732005ec49591929ea87c5b740",
        "pre_owned_sha256": "92dd256cb21cad968973164ef5407f32170bf713be7d58d59e2672c3fc542db0",
        "rows": 6738,
    },
}
HEX32 = re.compile(r"0x[0-9a-fA-F]{8}\Z")
OWNED32 = re.compile(r"[0-9a-fA-F]{8}\Z")
OWNED16 = re.compile(r"[0-9a-fA-F]{4}\Z")
DECIMAL = re.compile(r"-?[0-9]+\Z")


class InvalidEvidence(ValueError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidEvidence(message)


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise InvalidEvidence(f"non-JSON numeric constant {value}")


def parse_hex32(value: object, name: str) -> int:
    require(type(value) is str and HEX32.fullmatch(value) is not None,
            f"{name} must be a 0x-prefixed 8-digit hex word")
    return int(value, 16)


def parse_actions(path: Path) -> list[tuple[int, str, tuple[int, ...]]]:
    result = []
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeError as exc:
        raise InvalidEvidence("actions are not ASCII") from exc
    arities = {"M": 0, "S": 1, "I": 2, "F": 2, "E": 3}
    for line_number, line in enumerate(lines, 1):
        words = line.split()
        require(words, f"empty action line {line_number}")
        kind = words[0]
        require(kind in arities, f"unknown action at line {line_number}")
        require(len(words) == arities[kind] + 1, f"arity at line {line_number}")
        args = []
        for token in words[1:]:
            if kind in ("S", "I"):
                require(DECIMAL.fullmatch(token) is not None, f"signed integer line {line_number}")
                value = int(token, 10)
                require(-(1 << 31) <= value < (1 << 31), f"integer range line {line_number}")
                args.append(value & 0xFFFFFFFF)
            else:
                args.append(parse_hex32(token, f"action line {line_number}"))
        result.append((line_number, kind, tuple(args)))
    return result


def parse_owned(line: str, index: int) -> tuple[str, tuple[int, ...], int, tuple[int, int, int]]:
    words = line.split()
    require(len(words) == 10, f"owned field count at {index}")
    require(DECIMAL.fullmatch(words[0]) is not None and int(words[0]) == index,
            f"owned sequence at {index}")
    kind = words[1]
    require(kind in ("M", "S", "I", "F", "E"), f"owned action kind at {index}")
    require(DECIMAL.fullmatch(words[2]) is not None, f"owned arity at {index}")
    arity = int(words[2])
    require(arity in (0, 1, 2, 3), f"owned arity range at {index}")
    for pos in range(3, 8):
        require(OWNED32.fullmatch(words[pos]) is not None, f"owned hex32 field {pos} at {index}")
    for pos in (8, 9):
        require(OWNED16.fullmatch(words[pos]) is not None, f"owned hex16 field {pos} at {index}")
    args = tuple(int(word, 16) for word in words[3:3 + arity])
    require(all(int(word, 16) == 0 for word in words[3 + arity:6]),
            f"owned unused argument must be zero at {index}")
    status = (int(words[7], 16), int(words[8], 16), int(words[9], 16))
    return kind, args, int(words[6], 16), status


def parse_legacy_owned(line: str, index: int,
                       expected_args: tuple[int, ...]) -> tuple[str, tuple[int, ...], int,
                                                                 tuple[int, int, int]]:
    """Archived pre-fix stdout had no input echo; its exact hash is mandatory."""
    words = line.split()
    require(len(words) == 6, f"legacy owned field count at {index}")
    require(DECIMAL.fullmatch(words[0]) is not None and int(words[0]) == index,
            f"legacy owned sequence at {index}")
    require(words[1] in ("M", "S", "I", "F", "E"), f"legacy action at {index}")
    for pos in (2, 3):
        require(OWNED32.fullmatch(words[pos]) is not None,
                f"legacy hex32 field {pos} at {index}")
    for pos in (4, 5):
        require(OWNED16.fullmatch(words[pos]) is not None,
                f"legacy hex16 field {pos} at {index}")
    return words[1], expected_args, int(words[2], 16), (
        int(words[3], 16), int(words[4], 16), int(words[5], 16))


def compare(run: str, actions_path: Path, native_path: Path,
            owned_path: Path, owned_format: str = "echo10") -> dict:
    pin = RUNS[run]
    actions_sha, native_sha, owned_sha = (digest(path) for path in
                                         (actions_path, native_path, owned_path))
    require(actions_sha == pin["actions_sha256"], "wrong action-file SHA-256")
    require(native_sha == pin["native_sha256"], "wrong native-capture SHA-256")
    if owned_format == "legacy6":
        require(owned_sha == pin["pre_owned_sha256"], "wrong archived pre-fix stdout SHA-256")
    actions = parse_actions(actions_path)
    native_lines = native_path.read_text(encoding="utf-8").splitlines()
    owned_lines = owned_path.read_text(encoding="ascii").splitlines()
    require(len(actions) == len(native_lines) == len(owned_lines) == pin["rows"],
            "action/native/owned row count differs from pinned fixture")
    mismatches = []
    native_transitions = []
    owned_transitions = []
    old_native = old_owned = None
    kinds = Counter()
    for index, ((line_number, kind, args), native_line, owned_line) in enumerate(
            zip(actions, native_lines, owned_lines)):
        try:
            n = json.loads(native_line, object_pairs_hook=unique_pairs,
                           parse_constant=reject_constant)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise InvalidEvidence(f"malformed native JSON at {index}") from exc
        require(type(n) is dict, f"native row type at {index}")
        require(type(n.get("sequence")) is int and n["sequence"] == index,
                f"native sequence at {index}")
        require(type(n.get("line")) is int and n["line"] == line_number,
                f"native source line at {index}")
        require(type(n.get("action")) is str and n["action"] == kind,
                f"native action at {index}")
        raw_args = n.get("input_bits")
        require(type(raw_args) is list and len(raw_args) == len(args),
                f"native input arity at {index}")
        require(tuple(parse_hex32(value, f"native input at {index}") for value in raw_args) == args,
                f"native input words at {index}")
        o_kind, o_args, o_value, os = (parse_owned(owned_line, index)
            if owned_format == "echo10" else parse_legacy_owned(owned_line, index, args))
        require(o_kind == kind and o_args == args, f"owned input echo at {index}")
        expected_value_kind = "none" if kind in ("M", "S") else "i32" if kind == "I" else "f32"
        require(type(n.get("value_kind")) is str and n["value_kind"] == expected_value_kind,
                f"native value kind at {index}")
        native_value = n.get("value_bits")
        if expected_value_kind == "none":
            require(native_value is None and o_value == 0, f"no-value row at {index}")
        else:
            native_value = parse_hex32(native_value, f"native value at {index}")
        ns = (parse_hex32(n.get("mxcsr"), f"native mxcsr at {index}"),
              parse_hex32(n.get("x87_control"), f"native x87 control at {index}"),
              parse_hex32(n.get("x87_status"), f"native x87 status at {index}"))
        require((ns[0] & ~0x3F) == (os[0] & ~0x3F) == 0x1F80,
                f"SSE controls at {index}")
        require(ns[1] == os[1] == 0x027F, f"x87 controls at {index}")
        if old_native is not None:
            require(not ((old_native[0] & 0x3F) & ~(ns[0] & 0x3F)),
                    f"native SSE sticky bits cleared at {index}")
            require(not ((old_owned[0] & 0x3F) & ~(os[0] & 0x3F)),
                    f"owned SSE sticky bits cleared at {index}")
        if ns != old_native:
            native_transitions.append({"sequence": index, "action": kind,
                                       "input_bits": raw_args,
                                       "mxcsr": f"0x{ns[0]:08x}", "x87": f"0x{ns[2]:04x}"})
        if os != old_owned:
            owned_transitions.append({"sequence": index, "action": kind,
                                      "input_bits": raw_args,
                                      "mxcsr": f"0x{os[0]:08x}", "x87": f"0x{os[2]:04x}"})
        if ns != os or (native_value is not None and native_value != o_value):
            mismatches.append({"sequence": index, "action": kind, "input_bits": raw_args,
                               "native_value": None if native_value is None else f"0x{native_value:08x}",
                               "owned_value": None if native_value is None else f"0x{o_value:08x}",
                               "native_mxcsr": f"0x{ns[0]:08x}",
                               "owned_mxcsr": f"0x{os[0]:08x}",
                               "native_x87": f"0x{ns[2]:04x}",
                               "owned_x87": f"0x{os[2]:04x}"})
        kinds[kind] += 1
        old_native, old_owned = ns, os
    return {"run": run, "owned_format": owned_format, "actions_sha256": actions_sha,
            "native_sha256": native_sha, "owned_sha256": owned_sha,
            "rows": len(actions), "kinds": dict(kinds),
            "native_transitions": native_transitions,
            "owned_transitions": owned_transitions,
            "mismatch_count": len(mismatches), "first_mismatches": mismatches[:20]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", choices=sorted(RUNS), required=True)
    parser.add_argument("--actions", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--owned", type=Path, required=True)
    parser.add_argument("--owned-format", choices=("echo10", "legacy6"), default="echo10")
    args = parser.parse_args()
    try:
        result = compare(args.run, args.actions, args.native, args.owned, args.owned_format)
    except (InvalidEvidence, OSError, UnicodeError, ValueError) as exc:
        print(f"invalid FP-status evidence: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["mismatch_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
