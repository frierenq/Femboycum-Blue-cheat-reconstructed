# FemboyCum

FemboyCum is an experimental, independently developed CS:GO native-software research and reconstruction project. It contains the active C++20 source tree, experimental interfaces, semantic models, tests, build integration and selected development utilities.

**Release status: NEEDS REVIEW.** This local release candidate is incomplete and is not ready to publish. A proprietary data table has been withheld, model redistribution rights need confirmation, and no project-wide open-source licence has been selected. See [PROVENANCE.md](PROVENANCE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The experimental DLL has a new ABI and mock engine/render adapters. It is not a compatible replacement for the historical Neverlose DLL. Complete source recovery, historical configuration compatibility, game integration and full startup have not been established. Keep experiments separate from any installed software and user data.

## Current components

| System | Current implementation |
| --- | --- |
| Core and configuration | Source for lifecycle management, callback dispatch and transactional `FCFG/1` configuration. Historical configuration parsing is incomplete. |
| Experimental DLL | Source for a length-based C ABI and owned adapters. Full build currently needs the withheld exponent table. |
| Settings and models | Text setting projection, overrides and 16 authored semantic model suites. These are bounded reconstructions; their redistribution rights remain unresolved. |
| Selected state and cleanup | Explicit owned hurt/feedback/reset and round/death record replays. Full event eligibility and native ownership are unresolved. |
| Random streams | Integer, ordinary-float and exponent-float source projections. The exponent helper's extracted data table is excluded. Live engine stream selection is unresolved. |
| Bit writer and voice helpers | Owned 20-byte writer and protobuf body/frame helpers. Native message delivery is incomplete. |
| Lua candidate | Optional source-built LuaJIT, protected callbacks, an Event namespace candidate and writer/helper bindings. Exact historical runtime compatibility is unproved. |
| Hook research | Transaction/publication libraries and optional Detours tests against authored local functions. Game hook integration and arbitrary caller retirement are incomplete. |
| UI and rendering | Recording renderer and mock text presentation. Historical menu, D3D9 device handling and input are incomplete. |
| Launcher and service | Historical sources depend on excluded payloads and have unresolved provenance or licence metadata. They are not included in this candidate. |

## Build requirements and instructions

Use Windows, a Visual Studio C++ desktop workload with x86 tools and Windows SDK, CMake 3.24 or newer, and Python 3 for inspection utilities. Visual Studio generator support depends on the installed CMake version. The development build has been exercised with Visual Studio 2026, MSVC 19.51 and Windows SDK 10.0.26100.

The prepared copy configures, but its default full build cannot complete because `src/uniform_random_exp_tables.inc` is intentionally absent. It is an exact data extraction from a proprietary `vstdlib.dll` interval with unresolved redistribution rights. No substitute table or approximation is supplied. The standard build script preserves the existing build graph and will report the missing dependency.

See [BUILDING.md](BUILDING.md) for exact full-build and independent-target commands, prerequisites and validation limits. The optional LuaJIT and Detours sources are vendored with their original notices and hash manifests; those lanes do not download prebuilt libraries.

## Repository layout

```text
include/fc/       Experimental C ABI and C++ interfaces
src/              Active implementation sources
recovered/        Authored semantic projections and fixtures, with provenance pins
tests/            Independent implementation tests
tools/            Build/source checks and selected development utilities
cmake/            Optional source dependency build integration
third_party/      Pinned LuaJIT and Microsoft Detours sources and notices
research-tools/   Selected authored portable analysis utilities and dispositions
```

Private images, raw disassembly/decompiler outputs, machine-specific captures, protected loaders, compiled artifacts, personal configuration and unrelated research are excluded. The detailed local omission inventory is kept outside this directory.

No screenshot of a functional in-game reconstruction is available for this candidate. Test fixtures and mock adapters do not establish that result.

## Evidence limits

Development comparisons have matched 14,704 sampled RNG actions and 6,632 sampled writer actions under specific isolated reference profiles. These are bounded observations, not a feature-completion percentage. The reference binaries and machine-specific receipts are not part of this public candidate, so its standalone build does not reproduce those native comparisons.

A guarded bootstrap observation reached a first-call return and restored the raw header page. Table insertion, TLS execution, the protected entry, complete wrapper startup and game startup remain unproved. The project has not passed 100 actual game spawn/round transitions or a one-hour offline game soak. Mock lifecycle tests are a separate result.

## Roadmap and contributions

Resolve source/data redistribution rights and choose a project licence before publication. Then restore a documented distributable exponent-table dependency, validate the complete public build, and enable suitable CI. Continue recovering observable contracts, replace incomplete adapters with verified implementations, and expand isolated compatibility evidence before considering game acceptance tests.

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should preserve readable source and distinguish authored tests, static evidence and native observations. Do not include proprietary binaries, copied implementation, credentials, protected payloads or personal machine data.

## Legal and licensing notices

No root `LICENSE` is supplied because a project grant and the rights of the model subtree have not been established. The included third-party sources retain their own licences and attribution. This candidate does not grant rights to excluded software, assets or data. Product names identify the research subject and imply no affiliation or endorsement.
