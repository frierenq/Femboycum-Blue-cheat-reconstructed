# Optional research utilities

This optional source subtree accompanies the experimental reconstruction. `source/` contains 44 independently authored research utilities. `TRANSFORMATIONS.json` records the source-relative path, original SHA-256, disposition, reason, transformed path, transformed SHA-256, and each portability change for all 171 research Python/C++ source files reviewed. No generated result, original PE/core, guest capture, VM disk, ISO, PDB, executable, object file, or downloaded Python wheel is included.

The utilities fall into four groups: static scanners of caller-supplied private byte files; read-only offline VDI/NTFS/hive readers; text-only evidence comparers and synthetic controls; and authored-only C++ probes. They do not confer permission to redistribute their private inputs. Some tools remain case-specific and will fail cleanly without archived input text. A hash in source is an evidence identifier, not a recheck of absent original bytes. Do not treat the presence of a utility as clearance to publish its output.

## Input configuration

Set only the variables needed by a chosen tool. Generated files require `FC_RESEARCH_OUTPUT_DIR` to name an existing, absolute scratch directory **outside the public source tree**; the staged writers reject missing configuration and paths inside `research-tools` or its public parent. Use a distinct scratch directory for each utility to avoid filename collisions. Required variables intentionally have no personal-machine default:

| Variable | Purpose |
| --- | --- |
| `FC_RESEARCH_CORE`, `FC_VSTDLIB_DLL` | Caller-supplied private byte input for static scanning only. |
| `FC_RESEARCH_WRAPPER_PE`, `FC_RESEARCH_AUX_INPUT_DIR`, `FC_RESEARCH_SUPPLIED_SOURCE_DIR` | Caller-supplied wrapper bytes, auxiliary decoded text, or supplied source tree for static indexing. |
| `FC_RESEARCH_ROOT`, `FC_RESEARCH_WORKSPACE_ROOT`, `FC_RESEARCH_SOURCE_ROOT` | Private research root, original workspace root, or authored source root where a case-specific tool needs one. |
| `FC_RESEARCH_PYTHON_LIBS` | Installed optional Python dependencies (`pefile`, `capstone`, or `python-registry`), separately acquired. |
| `FC_RESEARCH_INPUT_DIR`, `FC_RESEARCH_PREP_DIR`, `FC_RESEARCH_RUN3_DIR`, `FC_RESEARCH_ARCHIVE_ROOT`, `FC_RESEARCH_WORK_DIR` | Caller-supplied archived text/input directories. The archive contents are omitted here. |
| `FC_RESEARCH_OUTPUT_DIR` | Required external scratch directory for any generated result, receipt, negative-control fixture, or downloaded optional package. Create it before running a writer. |
| `FC_RESEARCH_GUEST_UUID`, `FC_RESEARCH_GUEST_OUTPUT_DIR`, `FC_GUEST_VSTDLIB_PATH`, `FC_GUEST_TIER0_PATH`, `FC_GUEST_NTUSER_PATH`, `FC_VM_BASELINE_SNAPSHOT_UUID`, `FC_RNG_DISPATCH_DELTA` | Private case identity, guest paths, snapshot, and observed dispatch delta, supplied by the person who has those inputs. No actual VM UUID or account path is embedded here. |
| `FC_VM_OFFLINE_VBOX`, `FC_VM_OFFLINE_WORK`, `FC_NTFS_SAMPLE_TERMS` | Explicit powered-off VDI-chain input, scratch receipts, and optional metadata filter. Do not inspect a running VM disk. |
| `FC_RESEARCH_OWNED_PROBE_EXE`, `FC_RESEARCH_STATE_PROBE_EXE` | Paths to locally built *authored* probes only. No original DLL or core execution is part of these tools. |

The offline hive reader uses `vm_offline_vdi.py`, `vm_offline_ntfs.py`, and an optional `python-registry` package. `fetch_registry_reader.py` can download one checksum-pinned upstream wheel into an explicit external scratch directory; it does not include that dependency or its license in this candidate. Review the upstream license before distributing any downloaded copy. Some static scanners also require `pefile`, `capstone`, or `z3-solver`; install these separately and record their versions. All staged Python sources pass syntax parsing. The readers and evidence checkers refuse Python `-O` where assertions carry checks. Local Python imports disable `__pycache__` writes.

## Authored probe build notes

The bit-writer probe (`source/lua-events/bf-write/native-reference-run-1/tools/owned-probe/owned_probe.cpp`) can be built from the public `include/fc/bit_writer.hpp` and `src/bit_writer.cpp` with C++20 MSVC in a Win32 developer prompt. The voice-message probe (`source/lua-events/voice-message-projection/oracle_probe.cpp`) analogously needs `include/fc/voice_message.hpp` and `src/voice_message.cpp`. These two authored components are independent of the withheld RNG table. The bit-writer probe requires `FC_RESEARCH_OUTPUT_DIR` and accepts an expectations output file only inside that scratch directory. Suggested commands, with `ROOT` set to the public source root and `OUT` to external scratch:

```bat
cl /nologo /std:c++20 /EHsc /W4 /WX /I "%ROOT%\include" "%ROOT%\src\bit_writer.cpp" "%ROOT%\research-tools\source\lua-events\bf-write\native-reference-run-1\tools\owned-probe\owned_probe.cpp" /Fe:"%OUT%\owned_bit_writer_probe.exe"
cl /nologo /std:c++20 /EHsc /W4 /WX /I "%ROOT%\include" "%ROOT%\src\voice_message.cpp" "%ROOT%\research-tools\source\lua-events\voice-message-projection\oracle_probe.cpp" /Fe:"%OUT%\owned_voice_message_probe.exe"
```

The two distinct authored RNG probe sources are preserved under `source/vstdlib-rng/`. Their build requires `fc/uniform_random.hpp`, `src/uniform_random.cpp`, `src/uniform_random_exp.cpp`, and the withheld `src/uniform_random_exp_tables.inc`; the candidate does **not** supply a substitute table or imply those probes currently build. An archived byte-identical copy of `owned_status_probe.cpp` is intentionally represented once; both source paths and hashes remain in `TRANSFORMATIONS.json`.

The DIA query tools read a caller-supplied PDB through a caller-supplied DIA provider path. Their `LoadLibraryExW` call **executes that provider DLL**; use only an installed Microsoft DIA provider, never original game/core binaries or an untrusted DLL. Their case-specific symbol queries may be useful for private verification, but no PDB or provider binary is included.

## Held source

The manifest records individual reasons. In particular, selected original instruction/operand proof scripts, numerical tables copied from a proprietary PE, VM-only original-code loaders, and raw mapping closures are not staged. Several bootstrap trace analyzers are text-only yet embed sampled original register/cell values and target addresses; those remain held until the case constants are separated from reusable parsing code. The table required by full RNG/Core is absent, so this candidate must not be presented as a successful full Core/DLL build.

Keep private inputs, generated reports, downloaded dependencies, and executable outputs outside the public tree. Project and dependency rights still require owner review; this subtree grants no license to excluded original material.
