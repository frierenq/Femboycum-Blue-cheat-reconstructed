# Prepared-copy validation

The prepared copy was validated on 2026-10-23 with MSVC 19.51.36260, a Win32 Visual Studio 2026 generator and Windows SDK 10.0.26100.0. Clean build directories and raw logs were kept outside this repository.

| Check | Result |
| --- | --- |
| Default configure | Passed. The missing proprietary table is explicitly diagnosed. |
| Default complete build | **Failed** with C1083 for `uniform_random_exp_tables.inc`, as documented. No complete public DLL build is claimed. |
| Existing independent target build | Passed for bit writer, hook transactions/publication, voice helpers and all 16 model suites. |
| Independent CTests | **20/20 passed**: four research library suites and 16 semantic model suites. |
| Optional configure with LuaJIT and Detours enabled | Passed, including vendor source-pin verification. |
| Independent Detours targets and CTests | Build passed; **3/3 tests passed** against authored local functions. |
| Vendored LuaJIT runtime | Built from source. A smoke check passed for version 20100, FFI loading and four-byte pointers. This does not validate the blocked Core/Lua host integration. |
| Source boundary checks | Passed: 33 model source hashes and 225 pinned upstream source/notice hashes. Build read logs were checked for original research inputs. |
| Selected authored development probes | The admitted writer/voice probe sources built with MSVC Win32 `/W4 /WX`. The writer replayed 6,632 generated authored cases; the voice probe matched the existing fixed64 zero-payload golden fixture. These add no native parity comparisons. |
| Tool output portability | Generated research outputs require explicit external scratch directories. Missing and in-source output paths were rejected in authored controls; selected generator/probe/comparer controls passed with private scratch. |

The 23 selected CTests are independently runnable existing targets. Their success does not constitute a full build, public redistribution permission, historical hook/message compatibility or game integration. The Core, DLL, complete default suite and Lua host integration remain blocked in this copy by the excluded table. The active private development tree's full-suite results are a separate record.

No original native module, protected payload or historical observer is executed by these checks. No hosted CI run or game acceptance result is claimed.
