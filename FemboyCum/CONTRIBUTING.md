# Contributing

This is a local release candidate with unresolved source/data rights and no project-wide licence. Resolve those issues before public distribution or accepting public contributions under a new grant.

Use the existing CMake architecture and explicit experimental interfaces. Keep sources readable. Preserve vendored sources and their original notices; update their hash manifests only after reviewing an intentional upstream revision change.

For implementation changes, describe the observable behavior, support boundaries and relevant tests. Distinguish independent fixtures, decoded static evidence and isolated native observations. Do not infer full compatibility from a sampled comparison, mock lifecycle test or successful compilation.

Use disposable configuration files and authored test targets. Do not overwrite installed software or user data. Research utilities should take explicit input paths and write only to a chosen output directory. No original binary is a default build or test dependency.

Do not contribute proprietary binaries, decompiled/copied proprietary implementation, protected payloads, restricted assets, credentials, personal machine identifiers or unrelated research. Record uncertain provenance before admitting a new component.

Follow [BUILDING.md](BUILDING.md), run the tests appropriate to the changed component, and describe any checks that could not run. A full build is currently blocked by an excluded exponent table; preserve that limitation in reports until resolved.
