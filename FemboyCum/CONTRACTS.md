# Experimental implementation contracts

These contracts describe the included authored source. They do not establish complete historical product compatibility. The missing exponent table prevents a full public Core/DLL build; source-level behavior below remains subject to that build limitation.

## Core, configuration and ABI

Core has one owning thread. Caller-owned adapters outlive Core. Initialization validates the complete configuration before starting adapters and committing active state; failed or cancelled initialization cleans up. Shutdown is idempotent, detaches active state before external callbacks, and cannot destroy a Core during one of its member calls. Reentrant dispatch and reinitialization during initialization, dispatch or teardown are rejected.

The engine adapter is metadata and the default adapter is a mock. The renderer records text/reset presentation; it does not create a D3D9 device or native menu. The default script host is a mock. The optional source-built Lua host is a candidate with a new bridge, not a validated historical ABI.

Dispatch snapshots retain callable objects, skip cancelled subscriptions and defer additions. Shutdown stops remaining subscribers. Callback exceptions stop the current dispatch and release its guard; later events may proceed. Teardown callbacks are noexcept. Arbitrary stale handles and concurrent access are outside the contract.

`FCFG/1` stores bounded, length-prefixed key/value bytes, preserving unknown fields and embedded NUL/newline bytes. Keys are nonempty and unique; serialization uses lexical key order and a 1 MiB document budget. Malformed, duplicate, truncated or oversized documents are rejected before initialization. Stored text and owner-scoped presentation overrides are distinct. Historical configuration/history formats are not supported.

The experimental C ABI uses explicit byte lengths, DLL-owned handles, status/error results and queryable output sizes including the trailing NUL. Short output buffers remain untouched. Handles must be live and released by the same DLL. No borrowed C++ objects cross the ABI. These exports have no historical launcher, service or injection compatibility claim.

## Selected state, records and random streams

Owned reference/selected state banks have 65 unsigned words. Explicit hurt/feedback/reset methods replay selected transformations with validated owned indices. Hurt re-acquires published context around observed writes and RNG calls. Feedback preserves selected scalar comparison/transition behavior. Reset clears both banks; no native reset event eligibility is inferred. State is transient and not invented as persistent historical settings.

Record projections represent reviewed fields and release-intent tokens. Tokens are not native pointers to free. Round/death replays preserve selected write/release ordering and separately supplied indices. An unsupported native branch can retain earlier effects and is reported explicitly. Record cleanup does not imply Anti Bruteforce array reset or complete resource ownership.

The owned RNG has one transient state per initialized Core lifetime. Seed, integer, ordinary-float, exponent-float and explicit hurt-profile operations share that state. Floating operation ordering and sampled NaN/status handling have bounded private reference evidence. Other profiles, unsampled inputs, traps, interleaving and live engine stream selection remain unresolved. The exponent implementation requires the withheld proprietary-data table; no standalone build claim is made for it.

## Writer, voice and optional Lua

The bit writer owns 20 bytes and tracks cursor/overflow state. Safe-domain argument rejections are explicit support boundaries. The voice helpers serialize that owned payload into a protobuf body or byte-aligned frame. They do not construct historical engine objects or send a network message.

The Lua host places allocation-capable operations inside protected Lua calls. Lua nonlocal exits must not cross live C++ objects with destructors. Callback registration/dispatch, chunk cleanup, stack recovery and allocation-failure handling are authored lifecycle policies. Event userdata own names and share callback collections by length-aware signed-byte hashing. Dispatch snapshots skip cancelled entries and defer additions; this stability policy does not assert deterministic native mutation behavior. Selected manual-call guards and an unsupported special path remain explicit candidate boundaries.

`fc_research.new_bit_writer20`, `voice_message_body` and `voice_message_frame` expose owned objects/helpers only. Lua host finalization, full engine events, error contexts, coroutine/environment ownership and exact runtime revision remain incomplete.

## Hook transaction and publication research

Stable backend-owned target slots outlive deferred transaction writes. Begin outcomes distinguish Ready, Rejected and Uncertain state. Trampoline publication occurs before Commit. Cooperative caller leases close a gate before draining callbacks and detaching. Callers that bypass the gate, arbitrary module unload and native game retirement remain unresolved. Optional Detours tests use authored local functions and do not integrate hooks into Core, the DLL or a game.

## Evidence and acceptance

Implementation fixtures, static analysis and native observations are separate evidence classes. Historical private comparisons are not bundled standalone public tests. Mock lifecycle cycles do not establish game spawn/round transitions. Full startup, D3D9/input/device behavior, historical scripting/configuration compatibility, crash reproduction, 100 actual game cycles and the one-hour offline soak remain outstanding. See README.md and VALIDATION.md for the current prepared-copy scope and results.
