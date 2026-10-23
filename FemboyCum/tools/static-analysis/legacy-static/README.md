# Optional legacy static verifiers

These 30 source-only scripts preserve distinct bounded analysis checks from an earlier native-recovery checkpoint. They are development tools, not components of the default CMake build. Their private reference image, original exports, semantic fixture JSON, deployed-build comparison files, and generated disassembly are **not** included. No target code was executed while preparing this source candidate, and these scripts have not been revalidated against an independently assembled public fixture corpus.

Each script requires both environment variables before execution:

- `FC_RESEARCH_ROOT`: a **writable private analysis directory** with the historical `ui-controls/nl.core.bin` layout and any selected evidence files the script reads. Keep it outside the public repository.
- `FC_WORKSPACE_ROOT`: the root of the separately held historical workspace for scripts that verify source/deployed-file hashes. Keep it outside the public repository.

`verify_config_name_joins.py` additionally requires `FC_SOURCE_ARCHIVE`, an explicit path to the historical source archive. Python and the `capstone` package are required. The three literal-evaluator clients use the sibling public `literal_evaluator.py` in the parent tools directory. These scripts may write JSON or instruction summaries inside `FC_RESEARCH_ROOT`; use a disposable private analysis copy if output preservation matters. Do not run them against live processes or use generated leads as whole-control-flow proof.

`SOURCE_DECISIONS.json` lists every one of the 34 top-level historical scripts, its original and candidate source hashes, and a filename-specific inclusion or omission reason. The four omitted scripts are historical Ghidra launcher duplicates or protected-core preparation/guard-assumption utilities. Only the 30 `.py` analyzers, `legacy_env.py`, this README, and the decision manifest are candidate source files; no private evidence or original binary is copied.

This source candidate has no assigned public license. Its availability here does not resolve distribution rights for copied analyst models or historical upstream material.
