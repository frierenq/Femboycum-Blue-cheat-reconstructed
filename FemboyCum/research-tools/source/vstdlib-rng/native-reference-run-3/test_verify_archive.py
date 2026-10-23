"""Read-only synthetic negative controls for the portable archived-text verifier."""
from __future__ import annotations

import copy
import json
import sys

sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")
import verify_archive as v


def rejected(label: str, operation) -> str:
    try:
        operation()
    except v.EvidenceError as error:
        return f"{label}: {error}"
    raise RuntimeError(f"negative control was accepted: {label}")


def main() -> None:
    v.verify_manifest()
    old, new, rows, old_fp, actions, expected = v.replay()
    assert old["mismatch_counts"]["fp_status"] == 121
    assert new["mismatch_counts"] == {"value": 0, "state": 0,
                                       "mode": 0, "fp_status": 0}
    controls = []

    def bad_input():
        row = copy.deepcopy(rows[1])
        row["input_bits"][0] = f"0x{(int(row['input_bits'][0], 16) ^ 1):08x}"
        v.inspect_native_row(1, row, actions[1], expected[1])
    controls.append(rejected("native input echo", bad_input))

    def bad_state():
        changed = copy.deepcopy(rows)
        seed = int(changed[1]["default_state_seed"], 16)
        changed[1]["default_state_seed"] = f"0x{(seed ^ 1):08x}"
        result = v.compare_rows(changed, actions, expected, old_fp)
        v.require(result["mismatch_counts"]["state"] == 0,
                  "synthetic native state mismatch")
    controls.append(rejected("native state", bad_state))

    def bad_post_status():
        changed = copy.deepcopy(rows)
        status = int(changed[1]["mxcsr_post_action"], 16)
        changed[1]["mxcsr_post_action"] = f"0x{(status ^ 1):08x}"
        result = v.compare_rows(changed, actions, expected,
                                v.load_post_fp(actions, expected))
        v.require(result["mismatch_counts"]["fp_status"] == 0,
                  "synthetic post-FP mismatch")
    controls.append(rejected("native post-FP status", bad_post_status))

    def bad_authored_fp_echo():
        raw = v.read_pinned("owned-per-action-post.txt")
        lines = raw.split(b"\r\n")
        words = lines[1].split()
        words[3] = f"{(int(words[3], 16) ^ 1):08x}".encode("ascii")
        lines[1] = b" ".join(words)
        v.load_post_fp(actions, expected, b"\r\n".join(lines))
    controls.append(rejected("authored FP input echo", bad_authored_fp_echo))

    def bad_authored_state():
        raw = v.read_pinned("source-state-post.txt")
        lines = raw.splitlines(keepends=True)
        words = lines[1].split()
        words[-1] = str(int(words[-1]) ^ 1).encode("ascii")
        lines[1] = b" ".join(words) + b"\n"
        v.check_post_state(expected, b"".join(lines))
    controls.append(rejected("authored 34-word state", bad_authored_state))

    controls.append(rejected("duplicate JSON key",
                             lambda: v.decode_json(b'{"a":1,"a":2}', "synthetic")))
    print(json.dumps({"positive_replay": True,
                      "negative_controls_rejected": len(controls),
                      "controls": controls}, indent=2))


if __name__ == "__main__":
    main()
