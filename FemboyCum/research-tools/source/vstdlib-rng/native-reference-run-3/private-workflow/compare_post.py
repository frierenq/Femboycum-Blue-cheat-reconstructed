"""Strictly compare pinned authored post-fix FP stdout with sealed run-3 capture."""
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

import sys

if not __debug__:
    raise RuntimeError("optimized Python disables evidence checks")

import run_owned_post as owned
import run_state_post as state

HERE = Path(os.environ["FC_RESEARCH_INPUT_DIR"])
PREP = Path(os.environ["FC_RESEARCH_PREP_DIR"])
RUN = Path(os.environ["FC_RESEARCH_RUN3_DIR"])
POST_STDOUT_SHA = "e9559405ac3287d56df0770196e45528b5b9d7187b41da4285c5d3d975375ce4"
POST_RECEIPT_SHA = "26dbda2d4d919ef98e20c84c91d94d16db1f6f7a57ac39bc96557a8090f02ee7"
RUNNER_SHA = "e1685ade59882d16bd59308b9cfa41600d8849e84ce9e6035672742716cf98e1"
STATE_STDOUT_SHA = "8277af049c3d8d6002b1e3808b21d28e5d31ff889b4315ad0fc73b8f6b93090c"
STATE_RECEIPT_SHA = "31ee46b4d2799dab6ce2eb509420e6a3f980cf18299a34a100116cd13cfb483b"
STATE_RUNNER_SHA = "e938cee7d7af704c0d1c0bada00ed40e26a90d4fee5ce6912cedbcd39c07e043"
OLD_COMPARISON_SHA = "626ca9d03c8073ca0a40f6101b478457c620fe882bdd61ede91f4fe3dbd1a2c0"
NATIVE_SHA = "5d731f17e7e18f3d995397e3e94c4ea26b42b8383e845b89186e7a57c8d6c1d1"
CAPTURE_SHA = "748bca1f4b1380439660777e7297c3cb1ca4c5190abca6295c00c6993f7ff1bb"


def require_hash(path: Path, digest: str) -> bytes:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"pinned file changed: {path}")
    return raw


def main() -> int:
    try:
        owned.validate_pins()
        module = owned.baseline_module()
        require_hash(HERE / "run_owned_post.py", RUNNER_SHA)
        require_hash(HERE / "run_state_post.py", STATE_RUNNER_SHA)
        require_hash(RUN / "comparison.json", OLD_COMPARISON_SHA)
        require_hash(RUN / "guest-capture/native.jsonl", NATIVE_SHA)
        require_hash(RUN / "guest-capture/capture.json", CAPTURE_SHA)
        receipt_raw = require_hash(HERE / "owned-post-receipt.json", POST_RECEIPT_SHA)
        receipt = module.decode_json(receipt_raw, "post-fix owned receipt")
        module.require(type(receipt) is dict and
                       receipt.get("authored_only") is True and
                       receipt.get("original_native_executed") is False and
                       receipt.get("vm_operated") is False and
                       receipt.get("rows") == 1692 and
                       receipt.get("exe_sha256") == owned.PINS[owned.EXE] and
                       receipt.get("actions_sha256") ==
                           owned.PINS[PREP / "actions.txt"] and
                       receipt.get("stdout_sha256") == POST_STDOUT_SHA and
                       receipt.get("source_input_sha256") ==
                           {path.name: digest for path, digest in owned.PINS.items()},
                       "post-fix owned receipt content mismatch")
        stdout = require_hash(HERE / "owned-per-action-post.txt", POST_STDOUT_SHA)
        fp_rows, counts = owned.validate_output(stdout, module)
        module.require(counts == receipt["mxcsr_exception_mask_counts"],
                       "post-fix authored FP counts disagree with receipt")
        state_receipt_raw = require_hash(HERE / "source-state-post-receipt.json",
                                         STATE_RECEIPT_SHA)
        state_receipt = module.decode_json(state_receipt_raw,
                                           "post-fix source-state receipt")
        module.require(type(state_receipt) is dict and
                       state_receipt.get("authored_only") is True and
                       state_receipt.get("original_native_executed") is False and
                       state_receipt.get("vm_operated") is False and
                       state_receipt.get("rows") == 1692 and
                       state_receipt.get("exe_sha256") == state.EXE_SHA and
                       state_receipt.get("actions_sha256") ==
                           owned.PINS[PREP / "actions.txt"] and
                       state_receipt.get("stdout_sha256") == STATE_STDOUT_SHA and
                       state_receipt.get(
                           "full_state_34_words_and_result_bits_match_sealed_source_expected") is True,
                       "post-fix source-state receipt content mismatch")
        state_stdout = require_hash(HERE / "source-state-post.txt", STATE_STDOUT_SHA)
        module.require(state.validate_output(state_stdout, module) == 1692,
                       "post-fix source-state replay row count")
        _, actions, expected, _ = module.load_prepared()
        rows, provenance = module.load_capture(RUN / "guest-capture")
        result = module.compare_rows(rows, actions, expected, fp_rows)
        result.update({"capture": provenance,
                       "owned_post_stdout_sha256": POST_STDOUT_SHA,
                       "owned_post_receipt_sha256": POST_RECEIPT_SHA,
                       "owned_post_full_state_stdout_sha256": STATE_STDOUT_SHA,
                       "owned_post_full_state_receipt_sha256": STATE_RECEIPT_SHA,
                       "original_pre_fix_comparison_sha256": OLD_COMPARISON_SHA,
                       "native_reference_executed_by_comparer": False,
                       "scope": "installed default RNG per-action run-3 sample only"})
        _fc_output("comparison-post.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"passed": result["passed"],
                          "mismatch_counts": result["mismatch_counts"],
                          "comparison": str(_fc_output("comparison-post.json"))}))
        return 0 if result["passed"] else 1
    except (module.EvidenceError if "module" in locals() else ValueError,
            OSError, UnicodeError, ValueError, TypeError, KeyError,
            RuntimeError) as error:
        print(f"provenance/structure failure: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
