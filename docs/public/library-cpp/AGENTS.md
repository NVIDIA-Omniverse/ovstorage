# Agent routing — library-cpp persona

You're working on behalf of a C++20 application that uses `ovstorage.hpp`
over the `ovstorage-capi` cdylib. Use this file to route quickly; the
[README](README.md) carries the user-facing narrative.

## What's where

- **C++ wrapper:** `ovstorage-core/crates/ovstorage-capi/include/ovstorage.hpp`
  (header-only, ships alongside the cbindgen-generated `ovstorage.h`).
- **C ABI it sits on:** `ovstorage-core/crates/ovstorage-capi/` —
  `src/ffi/`, headers in `include/ovstorage.h`. Wrapper surface is
  mirrored from the C ABI; any new C++ method needs a corresponding C
  entry point.
- **Working example:** `ovstorage-core/examples/cpp-async/`
  (CMakeLists.txt + `test_driver.cpp`). Read-only for this persona's
  docs work.
- **Authoritative surface doc:** [README.md](README.md) — § *Surface
  inventory*, § *Coroutine internals*, and § *STL mismatch posture*
  are the canonical references.

## Build / link recipe

The example uses CMake and resolves the workspace target tree at
configure time:

```sh
# From repo root, after `cargo build` in ovstorage-core/:
cmake -S ovstorage-core/examples/cpp-async -B /tmp/cpp-async-build
cmake --build /tmp/cpp-async-build
ctest --test-dir /tmp/cpp-async-build --output-on-failure
```

Override `OVSTORAGE_LIB_DIR` to point at `target/release` for a
release build. The variable is consumed only by the example's
`CMakeLists.txt` at `ovstorage-core/examples/cpp-async/CMakeLists.txt`
(see the `if(NOT DEFINED OVSTORAGE_LIB_DIR)` block, the
`find_library` lookup, and the `BUILD_RPATH` wiring); your own CMake
project can mirror that pattern or hard-code the cdylib path. The
example's CMake also sets `BUILD_RPATH` to the cdylib directory and
wires `OVSTORAGE_PLUGIN_DIR` into the `add_test` environment so plugins
are discoverable at runtime.

For ad-hoc projects: add `ovstorage-core/crates/ovstorage-capi/include`
to the include path, `#include "ovstorage.hpp"`, link `ovstorage`.
There is no separate Cargo crate for the C++ wrapper, no `.cpp`
translation unit, and no pkg-config / CMake package files.

## Compiler floor

C++20 with `<coroutine>`, `<span>`, `<concepts>`. Targets:

- GCC 13+
- Clang 17+
- MSVC 19.40+ (Visual Studio 2022 17.10+)

Native compiler-matrix CI is **not configured**; `examples/cpp-async/`
is the smoke target. C++ application authors should test their app on
at least their target compiler before shipping; running `examples/
cpp-async/` against your toolchain confirms the wrapper compiles cleanly
on that compiler / STL combination.

## Common routing decisions

| Question | Route to |
|---|---|
| Is method X exposed in C++? | Search `ovstorage.hpp` for `task<...> X(`; if absent, check `ovstorage.h` first (C ABI gap, not just C++ gap). |
| Does this need a new C ABI entry point? | Yes if the method isn't in `ovstorage.h`. Wrapper is header-only and thin. |
| Streaming reads — per-chunk? | Not provided; aggregates to `std::vector<std::byte>`. Punt to C ABI multi-fire callback. |
| Cancellation across multiple ops? | One `CancelToken` shared by reference; see README § *Cancellation*. |
| STL mismatch concern? | Route to [README.md § STL mismatch posture](README.md#stl-mismatch-posture) — already-decided posture. |
| Plugin author wants to use C++ internally? | `-static-libstdc++` (GCC) or `-stdlib=libc++ -lc++abi --whole-archive` (Clang); manifest types stay POD C. |

## Hard rules

- **No exceptions across the library boundary.** Wrapper itself never
  throws; errors come back as `ovstorage::Result<T>`. Plugins that
  use C++ internally must catch internally and translate to the C
  error shape before returning.
- **Move-only handles.** Every wrapper type is move-only; a moved-from
  handle is null and methods on it return failed `Result` rather than
  hanging.
- **Don't add STL types to plugin manifests.** POD C only.
  `plugin_manifest_pod_check` enforces it.
- **Don't drain `Body::Stream` to `Vec<u8>` at the host or plugin.**
  True-streaming applies to the broker REST gateway too. The C++
  wrapper's vector aggregation for `read_stream` is a known gap, not a
  sanctioned pattern to extend.

## What's not configured

- Compiler-matrix CI (GCC/Clang/MSVC × libstdc++/libc++/MSVC STL).
- ASan/UBSan jobs.
- Symbol versioning, pkg-config, generated CMake package files.
- Per-chunk `AsyncStream<Bytes>` C++ surface.
