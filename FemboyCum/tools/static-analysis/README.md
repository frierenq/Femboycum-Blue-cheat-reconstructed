# Optional static-analysis utilities

These are source-only development utilities adapted from the local native-recovery research. They do not contain a reference image, game assets, decompiled output, or an executable target. They are **not** part of the default CMake build and do not make the experimental reconstruction compatible with the historical product. No project license or redistribution grant is asserted here.

- `TargetedFunctions.java` is a Ghidra script that disassembles and decompiles caller-selected addresses in the open analysis program into a caller-selected output directory.
- `AssumedFunctions.java` is a Ghidra script for *conditional analysis copies*: it verifies expected bytes, changes the analysis program in memory, then exports selected functions. Use a disposable Ghidra project; it changes Ghidra's program state.
- `literal_evaluator.py` collects bounded linear x86 literal/call leads from caller-supplied image bytes. Import it and call `analyze(start, data=..., base=..., cs=...)` with a detailed Capstone x86-32 disassembler. Its result is a lead index, not a path-feasible reconstruction.
- `overlap_cfg.py` collects bounded direct-branch leads from a caller-supplied flat image. It requires Python and Capstone, and takes `--input`, `--base`, `--output-dir`, optional `--sha256`, and one or more `0xSTART:0xEND` regions. It does not follow calls or indirect jumps.

The original versions live in the private historical research tree. The four utilities above remove private workspace layout assumptions, make binary inputs explicit, and fix the Ghidra override warning. Protected-module extraction scripts and historical Ghidra launcher duplicates are omitted. The original provenance record contains an authorship statement but no public license grant; release requires a rights decision.

`legacy-static/` separately contains 30 source-only historical verifiers whose private input roots are explicit environment variables. Their reference data and generated outputs are absent; see its README and per-file decision manifest. These are optional development tools and have not been run against the excluded historical inputs for this release preparation.
