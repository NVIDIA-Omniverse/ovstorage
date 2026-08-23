# Agent routing — library-cpp persona

You're working on behalf of a C++20 application that uses `ovstorage.hpp`
over the C sources it ships beside. Use this file to route quickly; the
[README](README.md) carries the user-facing narrative.

## What's where

Everything is in one tree, `ovstorage-c-source/`. There is no
`ovstorage-capi` crate and no precompiled cdylib; the C/C++ surface ships as
source.

- **C++ wrapper:** `include/ovstorage.hpp` — header-only, hand-written,
  async-only.
- **C API it sits on:** `include/ovstorage.h`, implemented by `src/*.c`.
  The wrapper surface mirrors the C API, so any new C++ method needs a
  corresponding C entry point. Both are hand-maintained and edited
  together.
- **Plugin ABI:** `include/ovstorage_plugin.h` — this one IS generated,
  from the `ovstorage-plugin` crate, and byte-copied here. Do not edit it.
- **Working example:** `examples/cpp20_roundtrip.cpp`, plus
  `Makefile.example` and `CMakeLists.txt.example`.
- **Authoritative surface doc:** [README.md](README.md) — § *Surface
  inventory*, § *Coroutine internals*, and § *STL mismatch posture*
  are the canonical references.

## Build / link recipe

There is nothing to link. Compile the C sources into your own build and
include the header:

```sh
cd ovstorage-c-source
make -f Makefile.example check    # builds and runs both examples
```

For ad-hoc projects: add `ovstorage-c-source/src/*.c` to the build as
C99, put `ovstorage-c-source/include` on the include path, and
`#include "ovstorage.hpp"`. On POSIX the sources need
`_POSIX_C_SOURCE=200809L`, `_XOPEN_SOURCE=700`, `_FILE_OFFSET_BITS=64`,
and `-lpthread -ldl`; both example build files show the full set.

There is no cdylib, no separate Cargo crate for the C++ wrapper, no `.cpp`
translation unit, and no pkg-config / CMake package files.

## Compiler floor

C++20 with `<coroutine>`, `<span>`, `<concepts>`. Targets:

- GCC 13+
- Clang 17+
- MSVC 19.40+ (Visual Studio 2022 17.10+)

GCC 15.x is *within* the floor version range but has a known compiler defect
that causes a ThreadSanitizer data race on coroutine frames resumed on another
thread before the ramp returns (callback-driven awaiters); see
[Known toolchain defects](README.md#known-toolchain-defects) in the README.

Both example build files probe the floor by compiling `ovstorage.hpp`
itself and report it if the compiler cannot — a narrower coroutine probe
is not equivalent, since it passes on compilers that then reject the
header. Below the floor the CMake example omits the C++ target and still
generates the C99 ones.

Native compiler-matrix CI is **not configured**; the shipped examples are
the smoke target. C++ application authors should test on at least their
target compiler before shipping; building `examples/cpp20_roundtrip.cpp`
against your toolchain confirms the wrapper compiles cleanly on that
compiler / STL combination.

## Common routing decisions

| Question | Route to |
|---|---|
| Is method X exposed in C++? | Search `ovstorage.hpp` for `task<...> X(`; if absent, check `ovstorage.h` first (C API gap, not just C++ gap). |
| Does this need a new C API entry point? | Yes if the method isn't in `ovstorage.h`. Adding one means declaring it there AND implementing it in `src/`; the link-completeness gate fails otherwise. |
| Does a string argument need a NUL check? | No — `detail::embedded_nul` is the single chokepoint every entry point routes through. Add the guard line, don't write a new check. |
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
