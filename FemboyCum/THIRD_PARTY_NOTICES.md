# Third-party notices

## LuaJIT candidate

Source subset at `third_party/luajit-candidate`, pinned to upstream commit `1c279127050e86e99970100e9c42e0f09cd54ab7`. `SOURCE_MANIFEST.json` records the archive identity and 209 source/notice files. Its complete unmodified [COPYRIGHT](third_party/luajit-candidate/COPYRIGHT) is retained, including Mike Pall's LuaJIT notice, the Lua.org/PUC-Rio notice and the dlmalloc statement. Individual source headers and DynASM notices are also retained. The applicable notices grant MIT terms to the covered sources; no exact historical-runtime identification is asserted.

## Microsoft Detours candidate

Source subset at `third_party/detours-candidate`, pinned to official v4.0.1 commit `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`. `SOURCE_MANIFEST.json` pins 16 unmodified source/notice files. Microsoft Corporation's original [MIT licence](third_party/detours-candidate/LICENSE.md), README and source copyright headers are retained.

## Project and unresolved components

These third-party grants cover their respective sources. No root project licence or grant for the 33-file recovered-model subtree is inferred. The extracted proprietary exponent table, historical binaries/payloads and historical wrapper/launcher/service/assets are excluded. See [PROVENANCE.md](PROVENANCE.md) for the resulting build and release limitations.

MSVC, the Microsoft C++ runtime, Windows SDK, CMake and Python are external build/runtime prerequisites; their installations and binaries are not redistributed in this source candidate.
