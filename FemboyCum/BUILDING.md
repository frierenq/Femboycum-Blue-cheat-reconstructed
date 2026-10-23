# Building FemboyCum

## Prerequisites

- Windows with MSVC x86 C++ desktop tools and a Windows SDK.
- CMake 3.24 or newer, with support for the installed Visual Studio generator. Visual Studio 2026 requires a newer CMake release than the minimum.
- Python 3 for `tools/check_source_boundary.py` and optional development utilities.
- No original core, game module, launcher payload or prebuilt project library is a supported build input.

The development environment used Visual Studio 2026, MSVC 19.51.36260 and Windows SDK 10.0.26100.0. This is a tested environment record, not a requirement for a particular personal installation path. Older toolchains need independent validation.

## Full build: currently blocked by an excluded dependency

Run from the repository root in PowerShell with CMake on `PATH`:

```powershell
cmake -S . -B build/full -G "Visual Studio 18 2026" -A Win32 -DBUILD_TESTING=ON
cmake --build build/full --config Release --parallel 3
ctest --test-dir build/full -C Release --output-on-failure
```

For Visual Studio 2022, use `-G "Visual Studio 17 2022"` with an appropriate CMake installation. The existing convenience script accepts `-Generator` and `-BuildDirectory`:

```powershell
.\build.ps1 -Generator 'Visual Studio 18 2026' -BuildDirectory .\build\full
```

Configuration can succeed while compilation fails: `src/uniform_random_exp.cpp` includes the intentionally excluded `src/uniform_random_exp_tables.inc`. That file contains exact proprietary-module data whose redistribution rights remain unresolved. Consequently `fc_core`, `femboycum_experimental.dll`, the mock application and dependent full-suite tests are not standalone buildable in this candidate. Supplying a private file to make them compile would not validate the public source closure. No approximation or replacement implementation has been inserted.

## Build the existing independent targets

These targets do not use the withheld table. They are the project's existing libraries and fixtures:

```powershell
cmake -S . -B build/independent -G "Visual Studio 18 2026" -A Win32 -DBUILD_TESTING=ON
cmake --build build/independent --config Release --parallel 3 --target fc_bit_writer_tests fc_hook_transactions_tests fc_hook_publication_tests fc_voice_message_tests
cmake --build build/independent --config Release --parallel 3 --target recovered_api_overloads_tests recovered_bruteforce_state_tests recovered_desync_math_tests recovered_hidden_overrides_tests recovered_inverter_decision_tests recovered_inverter_request_tests recovered_localization_key_tests recovered_rotation_math_tests recovered_turn16_quantization_tests recovered_button_pulse_tests recovered_choice_state_tests recovered_property_lookup_tests recovered_sequence_cache_builder_tests recovered_sequence_selector_tests recovered_text_setting_tests recovered_vector_values_tests
ctest --test-dir build/independent -C Release --output-on-failure -R '^(research\.(bit_writer|hook_transactions|hook_publication|voice_message)|recovered_.*)$'
python tools/check_source_boundary.py --build build/independent
```

Model fixtures can be inspected and built locally, but their public redistribution grant is unresolved. Passing these selected tests does not constitute a successful full DLL build or historical compatibility test.

## Optional source-built candidates

`-DFC_ENABLE_LUAJIT_CANDIDATE=ON` enables the pinned LuaJIT source runtime and owned scripting adapter. Its Core dependency means the complete lane is also blocked by the withheld table. Its source is included for transparent development; it is not an identified exact historical runtime.

`-DFC_ENABLE_DETOURS_CANDIDATE=ON` enables the pinned Detours source and authored local-function tests. These three tests can be built independently of Core:

```powershell
cmake -S . -B build/detours -G "Visual Studio 18 2026" -A Win32 -DBUILD_TESTING=ON -DFC_ENABLE_DETOURS_CANDIDATE=ON
cmake --build build/detours --config Release --parallel 3 --target fc_detours_candidate_tests fc_detours_hook_backend_tests fc_detours_hook_publication_tests
ctest --test-dir build/detours -C Release --output-on-failure -R '^research\.detours_'
```

All Detours execution in these tests uses authored targets. It is separate from original-module runtime experiments. Source pins are verified at configure/build time; generated binaries stay in the build directory.

## Validation records and CI

See [VALIDATION.md](VALIDATION.md) for the clean prepared-copy results. Raw build logs and personal paths are kept outside the candidate. No hosted CI result or badge is claimed. A full-build GitHub workflow is deferred until the source closure and licensing blockers are resolved; publishing a workflow that predictably fails on the missing table would not establish reliable CI.
