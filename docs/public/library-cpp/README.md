<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Persona: C++20 application using `ovstorage.hpp`

The header-only C++ wrapper composes ABI-v2 Layers with
`ovstorage::Registry` and `ovstorage::Stack`. A successful build returns an
immutable `ovstorage::LayerHandle`; object, introspection, and connection calls
run through that handle.

> **"ABI-v2" is the plugin ABI family, not an ovstorage release.** The plugin
> ABI carries its own version number (13 in ovstorage 0.2.1, within the v2
> family whose floor is 5). Nothing on this page named `v2` refers to the
> package version.

## Build and link

ovstorage ships its C/C++ surface as source. There is no library to link:
add `ovstorage-c-source/src/*.c` to your build, put
`ovstorage-c-source/include` on the header search path, and
`#include "ovstorage.hpp"` from your C++ translation units. The `.c` files
stay compiled as C99; only your own code is compiled as C++.

The wrapper is header-only and needs C++20 coroutines, `<span>` and
`<concepts>`. The C sources need only C99, so a toolchain below the C++ floor
can still build and use the C API.

`ovstorage-c-source/` carries two worked build files and a round-trip example
that exercises the wrapper end to end:

```sh
cd ovstorage-c-source
make -f Makefile.example check          # builds and runs all examples
```

or, with CMake:

```sh
cp CMakeLists.txt.example CMakeLists.txt
cmake -S . -B /tmp/ovstorage-build
cmake --build /tmp/ovstorage-build
ctest --test-dir /tmp/ovstorage-build --output-on-failure
```

Both are examples of the integration model rather than a supported ovstorage
build system. Copy the pattern into your own build.

## Build a Stack

`Registry` starts with exactly one built-in Layer factory: the `file` backend.
Load trusted ABI-v2 plugins with `Plugin::load`, keep each `Plugin` alive, and
add it to the registry. `Stack` records named layers and graph edges; `build()`
is a coroutine that resolves to the root `LayerHandle` and consumes the Stack
on success.

```cpp
#include "ovstorage.hpp"

ovstorage::Registry registry;
ovstorage::Stack stack;

auto added = stack.add_layer(registry, "files", "file");
auto rooted = stack.set_root("files");

ovstorage::ConnectionRequest request("file");
request.set_persist(false);
request.add_config(
    "root", ovstorage::ConfigValue::string_("file:///srv/assets/"));
auto connected = stack.add_connection("files", std::move(request));

auto built = ovstorage::sync_wait(stack.build());
if (!built.has_value()) {
    // built.error() is an ovstorage::Error
}
ovstorage::LayerHandle handle = std::move(built).value();
```

`build()` returns `task<LayerHandle>` and drives the non-blocking async build.
Coroutine-native code writes `auto built = co_await stack.build();`; the
`sync_wait` above drives it to completion for synchronous callers. The Stack
must outlive the await — keep it (and every recorded request) alive until the
task resolves. Pass `build(options, &cancel)` to build under a `CancelToken`.

Wrappers use `set_inner`; routers use `set_children`.
`add_layer_config(instance, key, ConfigValue)` supplies factory-time Layer
configuration. Backend connection configuration and credentials remain
separate in `ConnectionRequest`.

There is no directory-scan plugin loader on this surface: enumerate the
cdylibs yourself and call `ovstorage_load_plugin` (or `Plugin::load`) on each.

Plugin loading executes platform loader hooks. Only load trusted paths.
`Plugin::inspect` is for discovery UI and permanently pins the inspected cdylib
for process lifetime, so inspect a path once rather than polling it.

For a complete progression from the one-file Stack through routing, HTTP,
caching, and a native C++ wrapper, follow the
[numbered C++20 examples](https://github.com/NVIDIA-Omniverse/ovstorage/tree/main/ovstorage-c-source/examples/tutorial).

## Native C++ Layers

`LayerHandle::export_handle()` mints an owned
`OvStoragePlugin_LayerHandle`. A native C++ Layer can wrap that handle using
the same operational vtable a plugin implements, then pass its own handle to
`LayerHandle::import_handle()`. The imported result is the new driveable root;
Layers above it do not need to know that the implementation is C++ rather than
plugin-provided.

Start wrapper implementations from `OVSTORAGE_PASSTHROUGH_VTABLE` in
`ovstorage_defaults.h`, replace the slots they decorate, and preserve its state
layout rule: the owned inner handle is the first state member. A wrapper with
additional state must replace `drop`. The default `drop` also calls `free()`
on the state block, so a wrapper allocated with `new` must replace it even
when the inner handle is its only state. The native logging example
`examples/tutorial/06_native_layer.cpp` decorates every asynchronous request
slot and demonstrates the complete ownership transfer.

## Surface inventory

Owning wrapper types are move-only and destroy their C handle:

- `Registry`: kind-to-factory registry seeded with the built-in `file`
  backend;
- `Plugin`: one loaded ABI-v2 plugin and its advertised factories;
- `Stack`: mutable composition accumulator, consumed by successful build;
- `LayerHandle`: immutable built root and operational handle;
- `ConnectionRequest`, `ConfigValue`, and credential builders;
- result payload wrappers such as `Info`, `Bytes`, `LocalDelegate`,
  `WriteRedirectBatch`, and lists;
- value types for streamed writes, redirect results, watch events, read
  ranges, and connection-attribute patches;
- `CancelToken`: shareable cooperative cancellation.

`LayerHandle` exposes coroutine operations for object I/O, listing,
materialization, metadata and directory operations, connection lifecycle,
authentication events, and Layer introspection. Consult `ovstorage.hpp` for
the exact overload and option shape; it is hand-written and tested against the
C sources it ships beside.

The object-I/O surface includes producer-driven `write_stream`, the
`write_redirect` / `continue_write` handshake, `get_latest_version`, and
multi-fire `watch_directory`. Connection management includes borrowed-builder
`probe` and `update_connection_attributes`.

`read_bytes`, `read_stream`, `read_local_file`, and `get_latest_version` each
accept an optional `ReadOptions` carrying a byte range. A start on its own
reads to the end of the object; a start with an inclusive end reads that
window. An end with no start is refused with `InvalidArgument`, since the C
struct beneath gates both endpoints behind one flag and cannot express it.
An end that precedes its start is refused for the same status but a
different reason: the C struct can carry it, and the C layer would answer with
one catch-all string naming neither endpoint. Whether a range is honored at
all is a backend property: `read_local_file` materializes, and the `file://`
backend refuses a window rather than staging one. `RootInfo::range_read_strategy`
reports what a range costs on a given root — `MaterializeOnly` means a small
window pulls the whole object.

`write`, `write_stream` and `write_redirect` each accept an optional
`WriteOptions` carrying `no_overwrite`, `if_match_etag` and `size_hint`. The
two preconditions are mutually exclusive — `no_overwrite` fails if anything is
at the destination, `if_match_etag` fails unless what is there carries exactly
that etag — and setting both is refused with `InvalidArgument` rather than
given a precedence. An empty etag is refused too, so propagating an absent
`Info::etag()` as `""` is an error rather than a silent unconditional
overwrite. `Capabilities::supports_if_match_write` reports whether a backend evaluates
the precondition; the host forwards it either way rather than pre-screening on
that bit, since capabilities are reported per root.

`Capabilities` exposes every field of the C struct through a typed accessor,
with the two optional fields — `version_list_order` and
`watch_directory_max_lag_nanos` — returning `std::optional`. Verb availability
(`supports_write`, `supports_delete`, `supports_create_directory`, …) is
distinct from mechanism (`supports_server_side_copy`, `supports_atomic_rename`):
the first says a verb can be attempted, the second says how it runs.

`Info` carries `modified_by`, `checksums` and `effective_permissions`
alongside the metadata maps. `Connection` exposes the auth-state payloads —
credential expiry under `Authenticated`, the `AuthReason` under
`AwaitingAuth`, and an error code under `AuthFailed` — each returning
`std::nullopt` for a variant other than the one `auth_state_kind()` names.
Every connection operation takes a `target` parameter naming the owning Layer
instance; `RootInfo::owning_target` is that instance name, which is not
derivable from the root URL.

`OvStorage_AuthEvent` is a union. Check the discriminant before reading a
variant; reading the wrong one is undefined behaviour.
`OvStorage_InteractiveAuthCapability` encodes `0 = None`, `1 = Headless`,
`2 = Browser`, so a stored or serialized numeric value must be read against
that order. `ovstorage_init_auth_substrate` takes an options struct that, when
non-NULL, *must* name a directory; pass `options = NULL` to request the
default directory.

The options structs are plain C structs with no `struct_size` member, so `{0}`
selects defaults for every one of them. Do not initialize one with
`= { sizeof o }`: that sets the leading member — `no_overwrite` on a write —
rather than any size field.

The runtime thread count defaults to available parallelism clamped to
[2, 32]. It is process-global: the first `stack_build` wins, and a later build
requesting a different count warns rather than taking effect.

`WatchDirectoryOptions` carries `has_since` alongside `since`. A backend may
mint a zero-length cursor, and emptiness alone cannot distinguish that from
having no cursor at all, so resuming from one without the flag replays the
whole change history. A non-empty `since` resumes either way.

`sync_wait` blocks the calling thread and must not be called from a runtime
worker thread, the same constraint `ovstorage_stack_build` carries: the
process-global runtime's workers run tasks to completion, so nested blocking
calls exhaust the pool. Use `co_await` inside a callback the library invoked.

Every async operation returns `task<T>`. Awaiting the task yields
`Result<T>`; the wrapper does not throw for ovstorage failures.

```cpp
auto outcome = ovstorage::sync_wait(handle.read_bytes("file:///srv/a.usd"));
if (!outcome.has_value()) {
    std::fprintf(stderr, "%s\n", outcome.error().message().c_str());
}
```

Streaming reads are aggregated into `Bytes` by the C++ wrapper. Use
the C ABI's multi-fire callback surface when per-chunk delivery is required.

## Coroutine internals

Each method creates an awaiter state shared with its C callback. The tasks are
**eager**: calling a method submits its operation immediately, and awaiting
only collects the result — a task you construct and never await has still
performed its operation. Completion stores a `Result<T>` and the callback
resumes the continuation. Completion may race suspension; the bridge uses a
commit protocol so either ordering resumes exactly once.

`sync_wait` is a convenience for synchronous callers. Coroutine-native code
should `co_await` tasks directly. Callbacks run on runtime worker threads, so
do not assume thread affinity.

Completion is not guaranteed to be asynchronous. Argument rejections in the C
ABI's prologue, and Layers that answer synchronously, complete inline on the
calling thread. The awaiters handle both orderings, so this is not something
callers have to reason about — but do not build on an assumption that the
callback lands on another thread.

`CancelToken` can be shared across operations. Destroying the C++ token does
not invalidate copies already held by in-flight work. Cancellation is
cooperative and returns through the normal `Result` path.

## Ownership and errors

All owning types are move-only. Moved-from/default handles are null; operations
on a null `LayerHandle` return `InvalidArgument`. `Stack::build` consumes the
Stack when the build succeeds; a build that fails or is cancelled does not
consume it, so it can always be inspected or destroyed safely.

The C snapshot types behind `Info`, `Connection`, `AuthEvent`, `RootInfo`, and
their lists have visible read-only fields. The C++ wrappers preserve null and
variant guards around those fields. `List::info(i)` and
`VersionList::info(i)` return a borrowed `InfoView`; call `.clone()` only when
the item must outlive its list. The clone is an owning `Info` and performs a
deep copy of strings and metadata.

A failed build is generally **not** retryable in place. Any path that reaches
the build epilogue zeroes recorded credentials for secret hygiene, after which
a retry is rejected with `InvalidArgument` for every connection that carried
secrets. Connections without credentials retry unchanged, and a prologue
rejection leaves the builder untouched. Recover by destroying the Stack and
rebuilding it with fresh credentials rather than re-awaiting `build()`. This
applies equally to `ovstorage_stack_build` and `ovstorage_stack_build_async`.

No exception crosses the C boundary. `ovstorage::Result<T>` carries either a
value or an `ovstorage::Error` with the stable status code and message. Plugin
authors using C++ internally must catch exceptions before returning through a
C vtable. `OvStorage_Error` carries `code`, `message` and `code_name`.

`OvStorage_Status` runs 0–16 plus `Internal = 255`, where
`IncompatibleType = 13`, `ResourceExhausted = 14`, `PartialCompletion = 15`
and `PluginRejected = 16`. Route retry decisions through
`ovstorage_status_is_retryable` rather than a hand-rolled list: neither
blanket policy is safe, since treating an unrecognized status as fatal
abandons `ResourceExhausted`, which is retryable, while treating it as
retryable retries `PartialCompletion`, which the header warns is destructive.

Every string argument crosses the C ABI as a `const char*`, which ends at its
first NUL. A `std::string` carrying an embedded NUL would therefore arrive
truncated — a different address, a different config key — so the wrapper
rejects it with `InvalidArgument` instead of letting it through. This applies
to every entry point that takes a string, not just addresses.

### Mixing header and implementation versions

Building from source, as ovstorage distributes it, removes most of this
hazard: the header and the implementation come from one tree and are compiled
together, so they cannot disagree.

The hazard appears if you package these sources into a shared library of your
own and then link older application objects against a newer build of it. That
puts back a binary boundary the source distribution does not have, and every
caller-allocated struct in `ovstorage.h` is where it bites. `OvStorage_Error`,
the options structs, and `OvStorage_Capabilities` are all plain structs
callers may stack-allocate, with no `struct_size` field, no reserved padding
and no version macro, so a layout change is a **silent** break rather than a
detected one — a caller compiled against a stale layout has the newer library
write past the end of its object.

This is deliberate rather than an oversight. In the source-distribution model
there is no boundary for that machinery to guard, and paying for it everywhere
so that a repackager need not think about versioning would be the wrong trade.
The `ovstorage-c-source/README.md` section "C ABI stability at 1.0" carries the
full rationale.

There is no runtime guard. If you own that packaging, rebuild everything from
one source tree rather than mixing a stale translation unit with a newer
build. This differs from the plugin ABI, where a version mismatch is refused
at load with `IncompatibleType` — the application C API has no equivalent
gate, because in the source-distribution model it does not need one.

## STL mismatch posture

The public plugin and host ABI is POD C. Do not put `std::string`, containers,
exceptions, RTTI objects, or C++ allocators in plugin manifests or vtables.
This keeps a plugin built with a different standard library from exchanging
STL ownership with the host.

The header-only application wrapper does use the application's STL. That is
safe because its STL objects are consumed within the application translation
unit and converted to C ABI buffers/handles at the boundary. A plugin that
uses C++ internally remains responsible for keeping its C++ runtime and object
ownership on its side of the ABI.

## Current toolchain posture

Documented compiler floors are GCC 13+, Clang 17+, and MSVC 19.40+. Both
shipped example build files enforce that with a capability probe: they compile
`ovstorage.hpp` itself and report the floor if the compiler cannot, rather
than emitting template diagnostics from inside the wrapper. Probing the header
is deliberate — a narrower coroutine probe passes on compilers that then
reject it. Below the floor, the CMake example omits the C++ target and keeps
generating the C99 ones.

A full compiler/STL/sanitizer matrix is not currently provided. Symbol
versioning, pkg-config files, and generated CMake package files are also not
yet shipped.

### Known toolchain defects

**GCC 15.x — non-atomic coroutine frame refcount (affects coroutines resumed on another thread before the ramp returns)**

GCC 15 adds a 16-bit `_Coro_frame_refcount` field to every coroutine frame
and manipulates it with plain (non-atomic) read-modify-write instructions.
The ramp function increments the refcount before entering the coroutine actor
and decrements it after the actor returns; the actor does the same pair around
its body. When a coroutine handle is published to another thread from inside
`await_suspend` — the only conforming place for a callback-driven awaiter —
that thread's decrement races the ramp's decrement. The result is UB and can
leak the coroutine frame (both sides read 2, both write 1, neither frees).

Single-threaded coroutines and coroutines whose handles are published only
after the ramp has returned are not affected — there is no concurrent refcount
operation in those cases.

This is a compiler defect, not an ovstorage defect. `ovstorage.hpp`'s
synchronization is correct; the race is in the code GCC 15 generates for any
coroutine whose handle is published to another thread inside `await_suspend`,
independent of the library. ThreadSanitizer reports a 2-byte data
race on the coroutine frame heap block and exits non-zero. That output can look
like a `sync_wait` failure even when the condvar-destruction check itself passes.

This repository's test suite detects the defect and attributes it. On an
affected compiler `cpp20_toolchain_coroutine_frames_are_race_free` fails and
names it; that test's driver includes no ovstorage header, so its verdict is
about the compiler alone. `cpp20_sync_wait_does_not_destroy_a_condvar_in_use`
then builds without ThreadSanitizer and says so loudly, because a TSan build
would halt on the frame race and never reach the condvar race it exists to
pin — so on GCC 15 that leg catches a wrong outcome or a hang, but contributes
no condvar-race coverage. This is a property of the compiler in use, not of
the ovstorage version: the same test gives full coverage on GCC 13, GCC 14 and
Clang 17+.

**Workaround:** build the C++ wrapper with GCC 13, GCC 14, or Clang 17+ until
this is fixed upstream. No upstream GCC bug number is cited here because none
could be verified at the time of writing; consult the GCC bug tracker before
upgrading to GCC 15 for C++20 coroutine workloads.

See [configuration](../configuration.md) and the
[glossary](../GLOSSARY.md). `ovstorage.h` remains the exact C API reference; it
is hand-maintained alongside the implementation it declares, and the two are
edited together.
