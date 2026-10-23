# FemboyCum

**An open-source-oriented CS:GO reverse-engineering and software reconstruction project.**

FemboyCum explores the architecture and behavior of historical CS:GO native software through C++20 development, independent implementations, controlled experiments, and technical research.

The project focuses on understanding and rebuilding individual software components, with an emphasis on readable source code, reproducible testing, and documented limitations.

> **Development status:** Experimental. The public release candidate is incomplete, does not currently build in full, and requires licensing and redistribution review before publication.

## Features and research areas

- **Native C++ architecture:** Experimental DLL interfaces, lifecycle management, and callback dispatch.
- **Configuration system:** Transactional configuration management and setting models.
- **Lua integration:** Experimental LuaJIT bindings and callback handling.
- **Rendering and UI:** Recording renderer, text presentation, and mock adapters.
- **State management:** Event handling, resource ownership, and lifecycle experiments.
- **Serialization:** Bit-writing and protobuf-related research utilities.
- **Testing:** Independently authored unit tests and bounded behavioral comparisons.

## Current development status

FemboyCum is an ongoing reconstruction project, not a complete replacement for the original Neverlose CS:GO software.

Several components have independently implemented source code and tests. Other systems remain partially understood, incomplete, or dependent on unavailable material.

**Known limitations:**

- The full project currently cannot build because a required proprietary data table is excluded.
- Native game integration and complete startup have not been established.
- Historical configuration compatibility remains incomplete.
- In-game functionality has not been independently validated.
- Certain reconstructed models require redistribution-rights review.

See [BUILDING.md](BUILDING.md) for current build instructions and limitations.

## Technologies

- C++20
- CMake
- Microsoft Visual C++
- Windows SDK
- LuaJIT
- Microsoft Detours
- Python

## Project structure

```text
include/         Public interfaces and headers
src/             Native implementation
recovered/       Experimental semantic models
tests/           Independent tests
tools/           Development utilities
cmake/           Build integration
third_party/     Third-party dependencies and notices
research-tools/  Selected research utilities
```

## Development roadmap

The long-term goal is to improve the completeness, reliability, and reproducibility of the independently implemented components.

Current priorities include resolving redistribution rights, restoring a fully buildable public configuration, improving compatibility testing, and documenting unresolved behavior.

## Contributing

Contributions, bug reports, documentation improvements, and independently authored implementations are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md).

Do not submit proprietary binaries, protected payloads, copied commercial source code, credentials, or material you do not have permission to distribute.

## Legal and licensing

This project is an independent research effort and is not affiliated with, endorsed by, or maintained by Neverlose.

Third-party components retain their respective licenses.

**A project-wide open-source license has not yet been established.** Until the licensing review is complete, do not assume that the entire repository is available for unrestricted reuse or redistribution.

See [PROVENANCE.md](PROVENANCE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
