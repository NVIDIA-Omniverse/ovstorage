# Persona: C++ application using `ovstorage.hpp`

> "I'm writing a C++20 application that needs object I/O across multiple
> backends and want native coroutines, RAII handle management, and
> `Result<T>` error handling without exceptions across the library
> boundary."

You're reaching for ovstorage from a C++ host (a desktop tool, a
service, a render-farm worker) and you want the binding to feel native:
`co_await` on every long-running call, RAII for every handle, and
errors that come back as values rather than exceptions thrown across
the FFI seam.

## What you link against

`ovstorage.hpp` is the **header-only** C++20 wrapper that ships from
`ovstorage-capi`'s include directory alongside the cbindgen-generated
`ovstorage.h`. No separate Cargo crate, no `.cpp` translation unit —
add the include directory to your project, link `ovstorage-capi`'s
cdylib, and `#include "ovstorage.hpp"`. Compiler floor: C++20 with
`<coroutine>`, `<span>`, and `<concepts>` — GCC 13+, Clang 17+, MSVC
19.40+.

**Build recipe.** From a checkout of this repo:

```sh
# 1. Build the cdylib + cbindgen-regenerated ovstorage.h.
cd ovstorage-core
cargo build --release -p ovstorage-capi

# 2. Build at least one plugin so the runtime has a backend to dispatch to.
#    (If you already ran `make dist` from the repo root, dist/plugins/ has
#    every plugin built — skip this step and use that path in step 4.)
cargo build --release -p ovstorage-plugin-file

# 3. Point your build at the headers + cdylib.
#    Headers:  ovstorage-core/crates/ovstorage-capi/include/
#              (carries both ovstorage.h and ovstorage.hpp)
#    Library:  ovstorage-core/target/release/libovstorage.{so,dylib,dll}
#    RPATH or LD_LIBRARY_PATH must reach that target/release directory.
#
# 4. At runtime, set OVSTORAGE_PLUGIN_DIR to the directory holding
#    libovstorage_plugin_*.so, then call load_plugins_from_dir().
export OVSTORAGE_PLUGIN_DIR="$(pwd)/target/release"
```

`ovstorage-core/examples/cpp-async/` is a working reference; its
`CMakeLists.txt` parameterizes the cdylib path on
`OVSTORAGE_LIB_DIR` (default `target/debug`) and wires
`OVSTORAGE_PLUGIN_DIR` into `ctest`.

## Surface inventory

Owning handle types — `ovstorage::Library`, `ovstorage::Info`,
`ovstorage::Bytes`, `ovstorage::LocalDelegate`, `ovstorage::List`,
`ovstorage::VersionList`, `ovstorage::UpdateMetadataOptions`,
`ovstorage::AccessDecision`, `ovstorage::CancelToken`, plus
`Capabilities`, `ConfigValue`, `SecretValue`, `SecretBundle`,
`ConnectionRequest`, `Connection`, `ConnectionList`, `AuthEvent`,
`AliasRequest`, `Alias`, `AliasList`, `AddressVisibilityOverride` (+
list), `AddressRootList`, `BackendKindDescriptorList` — wrap the
corresponding C handles and call the appropriate `_destroy` / `_clear`
functions in their destructors. All move-only, no copy.

Methods mirror the C surface: `stat`, `read_bytes`, `read_stream`,
`read_local_file`, `write`, `delete_object`, `list`, `list_versions`,
`copy`, `rename`, `create_directory`, `delete_directory`,
`update_metadata`, `check_access`, plus the connection / alias /
discovery group (`add_connection`, `list_connections`,
`remove_connection`, `update_connection_credentials`,
`authenticate_connection`, `add_alias`, `remove_alias`, `list_aliases`,
`set_address_visibility`, `list_address_visibility_overrides`,
`list_address_roots`, `watch_address_roots`, `list_backend_kinds`,
`capabilities_for`).

`ovstorage::Bytes` exposes `std::span<const std::byte>` over the
underlying buffer and frees it on destruction; conversion to
`std::string`, `std::vector<std::byte>`, or any contiguous range is one
move-or-copy. Writes accept `std::span<const std::byte>` directly;
there is no intermediate `ByteSink` type.

`ovstorage::Error` is a value type that copies the error fields out of
the C `OvStorage_Error` before the library releases the message.
`.code()` returns `OvStorage_Status`; `.message()` returns `const
std::string&`.

## Coroutine internals

`task<T>::initial_suspend()` is `std::suspend_never` — the coroutine
body starts immediately on the call expression so any caller-borrowed
inputs (`std::span` write buffers, `ConnectionRequest&&` builders,
`const UpdateMetadataOptions&`) are snapshotted into the awaiter frame
before the call expression's temporaries die. Defer the await safely:
`auto t = lib.write(addr, std::span(temp_buffer)); co_await std::move(t);`
is sound.

Eager start admits two cross-thread orderings — body completion via the
tokio worker may fire before, during, or after the consumer's
`co_await`. The `task<T>::promise_type` carries an atomic `state` that
the `final_awaiter` and `task::await_suspend` exchange against (the
same canonical 0/1/2 pattern used by the per-callback awaiter bases):
whichever party arrives second observes the other's value and either
resumes the consumer's continuation directly or short-circuits the
suspend.

**Drop-while-suspended.** A consumer is also allowed to drop the task
without ever co_awaiting it (e.g., the surrounding scope unwinds via
exception). The promise's atomic state has a fourth value `3`
("consumer abandoned") that `~task()` writes if the body is still
suspended at an in-flight C callback; in that case `~task()` does
**not** call `handle.destroy()`. The body's eventual
`final_awaiter::await_suspend` observes `state == 3` and destroys the
frame itself, so the in-flight callback can safely write into the
per-awaiter heap-allocated state (held alive by a leaked
`std::shared_ptr` ref count that the static `on_complete` thunk
reclaims) and resume the body's continuation. This shared-ownership of
awaiter state closes a drop-before-await use-after-free: stack-allocated
awaiter sub-objects in the coroutine frame would be destroyed by
`handle.destroy()` while the C callback still held a `this` pointer;
the heap-allocated state outlives both the awaiter and (when abandoned)
the entire frame. The await-race coordination is exercised by
`cpp20_task_deferred_await_race`; the abandon path by
`cpp20_task_drop_before_await_no_uaf` (compiled with `-fsanitize=address`
when ASan is available).

## Picking up connections saved by the CLI

If you've already used `ovstorage connect` and `ovstorage write-config`
to set up a backend interactively, your C++ app can pick those
connections up automatically:

```cpp
auto opened = ovstorage::Library::init();
if (!opened.has_value()) co_return /* propagate opened.error() */;
ovstorage::Library library = std::move(opened.value());
co_await library.load_plugins_from_dir(std::nullopt);  // OVSTORAGE_PLUGIN_DIR
co_await library.load_config(std::nullopt);            // default search path
```

`load_config(std::nullopt)` searches `./ovstorage.toml` then
`$XDG_CONFIG_HOME/ovstorage/ovstorage.toml` (matching the CLI) and
registers every `[[connections]]` entry on the live library —
credential refs (env / keyring) resolve through the same keyring
namespace the CLI used, so a CLI `write-config --secrets keyring` flow
Just Works. Returns an empty `ConnectionList` when no config file
exists. Pass an explicit path string instead of `std::nullopt` to
load a non-default config. Per-route overrides and `[state]` are
init-time concerns; pass them through `LibraryInitOptions` if needed.

## How calls return

Every long-running method on `ovstorage::Library` returns
`ovstorage::task<T>` — a C++20 coroutine type whose final result is
`ovstorage::Result<T>` (a small `std::expected`-shaped value with
`ovstorage::Error` on the failure side).

- **Inside another coroutine,** `co_await` the call directly:
  `auto info = co_await lib.stat(addr);`.
- **From a top-level caller** (your `main`, a non-coroutine method,
  a thread that doesn't have its own coroutine context),
  `ovstorage::sync_wait(task<T>)` drives the task to completion on
  the calling thread.

The per-method awaiter parks the coroutine; the C ABI's `on_complete`
callback resumes the continuation from a tokio worker thread. You
never see threads in your code — the bridge is in the header.

## ConfigValue factory naming (`string_`, `int_`, `bool_`)

The `ovstorage::ConfigValue` factory methods carry a trailing
underscore (`string_`, `int_`, `bool_`) to avoid collision with C++'s
own `string` (the `<string>` header types) and with the `int` / `bool`
keywords. The `_` is part of the name; not a typo. The fourth
factory, `toml(...)`, is unambiguous and unsuffixed.

## RAII for every handle

Every owning C handle has a C++ wrapper whose destructor calls the
matching `_destroy`: `Library`, `Info`, `Bytes`, `LocalDelegate`,
`List`, `VersionList`, `Connection`, `ConnectionList`,
`ConnectionRequest`, `AliasRequest`, `SecretBundle`, `ConfigValue`,
`SecretValue`, `CancelToken`, plus the rest of the surface listed in
§ *Surface inventory* above. All wrappers are **move-only**, no copy.
A moved-from
handle is null; calling a method on a null `Library` returns a failed
`Result` with `InvalidArgument` rather than hanging the coroutine.

## Multi-fire callbacks aggregate

`read_stream`, `authenticate_connection`, and `watch_address_roots` are
the multi-fire callback shapes in the C ABI (one fire per chunk / event
/ snapshot, plus a final `done = true`). The C++ wrapper aggregates
read chunks and auth events into `std::vector<…>`; address-root watch
uses a snapshot callback:

- `read_stream(addr) -> task<std::vector<std::byte>>`
- `authenticate_connection(conn_id) -> task<std::vector<AuthEvent>>`
- `watch_address_roots(on_snapshot) -> task<void>`

A per-chunk awaiter / `AsyncStream<Bytes>` shape is **not provided**.
For multi-gigabyte reads where in-process aggregation is unacceptable,
use the C ABI directly with your own callback that streams chunks to
disk or downstream — the C++ wrapper does not yet have a streaming
seam for that path.

## Cancellation

`ovstorage::CancelToken` wraps an `Arc<CancellationToken>`. Construct
one, pass it into multiple in-flight ops, and call `.cancel()` to
signal group-cancel:

```cpp
ovstorage::CancelToken token;
auto a = lib.stat(addr_a, false, &token);
auto b = lib.read_bytes(addr_b, ovstorage::ReadOptions{}, &token);
// later, from another thread or signal handler:
token.cancel();
auto outcome_a = co_await std::move(a);
auto outcome_b = co_await std::move(b);
```

A pre-canceled token does not hang the bridge — the call resolves with
a `Cancelled`-class status.

## ETags, preconditions, and races

Reads, writes, lists, and `stat` return an `ObjectInfo` that carries
the backend-native `etag` (plus descriptive `version` / `size` /
`mtime` when the backend reports them). The etag asserts *which
version of the bytes* you observed; pass it back on the next mutation
so you don't accidentally clobber a concurrent writer.

The 0.1 C++ wrapper (`ovstorage.hpp`) exposes `write(address, body,
no_overwrite)` — a single boolean toggling unconditional clobber vs.
refuse-if-exists. The full SPI shape (`if_match` etag on
read / delete / update-metadata, `IfDestExists` on write / copy /
rename, separate `if_source` on copy / rename) is not yet surfaced
through the C++ headers; reach for the REST gateway
(`If-Match` / `If-None-Match: *` / `X-OV-If-Source-Match`) when
etag-bound mutation is required from C++. Header expansion is a
tracked follow-up.

Version selection, when a backend supports it, lives in
version-pinned addresses returned by `list_versions` or
`get_latest_version`. Preconditions carry only opaque etag strings,
and a backend that lacks etag-bound writes advertises that through its
capability matrix. Issuing an etag-bound write against such a backend
yields a typed error rather than silent data loss. Multi-writer
correctness is the caller's contract; the plugin can't paper over it.

## STL mismatch posture

`ovstorage-capi` itself is C ABI — no STL types cross the binding
seam. Your application's STL choice (libstdc++, libc++, MSVC's STL)
is invisible to the library and to plugins.

The risk this posture closes: a C++ application linked against
`libstdc++` loads an ovstorage plugin compiled against `libc++` (or
vice versa). The two STLs have incompatible `std::string` and
`std::vector` layouts; passing one through a function boundary
corrupts memory and crashes — typically at the most confusing possible
moment, far from the actual mismatch.

The C ABI is the *only* cross-toolchain stable interface ovstorage
exposes. The C++ binding is header-only and always inherits the host
application's STL, so there is no way for an STL mismatch to cross a
binary boundary that the project owns. Plugin authors who need C++
inside their plugin link the C++ STL statically (a one-line CMake
flag), the same posture LLVM, Boost, and every cross-vendor C++
ecosystem ships in production. The project never claims to provide a
stable C++ ABI; that claim has bitten Qt and Apple's C++ libraries
repeatedly and is widely understood as a non-goal.

**Alternatives considered and rejected.**

- **Stable C++ ABI surface.** No serious project ships one across
  compilers and STLs; the maintenance cost is the single biggest
  reason cross-platform C++ libraries default to header-only.
- **Force libc++ everywhere.** Excludes Linux distros where
  `libstdc++` is the system default; not portable.
- **Static-link `libstdc++` into the library.** Doubles binary size,
  increases load time, and creates the diamond-dependency problem
  when the host application also static-links.

**What this posture does NOT cover.**

- Two plugins compiled against different STLs in the same process:
  each plugin is a separate `.so` and a separate dynamic-link unit;
  if both happen to use STL types in their public manifests, mismatch
  is theoretically possible. Mitigation: plugin manifests are POD C
  structs only; no STL types cross plugin boundaries.
- C++ exception propagation across the FFI: not supported; plugins
  must catch all C++ exceptions internally and translate to the C
  error code shape.

**Plugin-author checklist.**

- The C++ binding ships as a single header (`ovstorage.hpp` from
  `ovstorage-capi/include/`) with no `.cpp` translation unit and no
  separate Cargo crate; CMake `INTERFACE` library only.
- If you ship a plugin that uses C++ internally, **link the C++
  runtime statically**: `-static-libstdc++ -static-libgcc` (GCC), or
  `-stdlib=libc++ -lc++abi` plus `--whole-archive` (Clang). This
  keeps the plugin's STL from escaping into the host process.
- Plugin manifest types are POD C structs — never `std::vector`,
  `std::string`, or any other STL type. The
  `plugin_manifest_pod_check` header-side conformance check is a pair
  of `static_assert`s (`is_standard_layout_v` and
  `is_trivially_copyable_v`) emitted per manifest type by the C ABI
  build, so a manifest with an STL field fails to compile.
- A multi-STL CI matrix (libstdc++ and libc++ on Linux, MSVC's STL on
  Windows) is not configured.

## Working example

`ovstorage-core/examples/cpp-async/` is a CMake project that builds
against the workspace `target/{debug,release}/` tree, resolves the
headers from `ovstorage-core/crates/ovstorage-capi/include/`, links
`libovstorage.so`, and wires `OVSTORAGE_PLUGIN_DIR` into the
`add_test` environment so plugins are discoverable at runtime. The
driver in `ovstorage-core/examples/cpp-async/test_driver.cpp` shows the
full shape —
`Library::init`, building a `ConnectionRequest`, `add_connection`,
then write/read/stat:

```cpp
// ConfigValue is move-only. `string_(root)` returns a temporary that
// lives long enough for `add_config` to consume it; the temporary
// dies at the semicolon.
ovstorage::ConnectionRequest request("file");
request.add_config("root", ovstorage::ConfigValue::string_(root));
// Equivalent two-step form — make the move explicit:
//     auto value = ovstorage::ConfigValue::string_(root);
//     request.add_config("root", std::move(value));
//     // value is now in the moved-from null state; do not reuse.
auto registered = co_await lib.add_connection(std::move(request));
if (!registered.has_value()) co_return /* propagate registered.error() */;

std::span<const std::byte> payload_span(
    reinterpret_cast<const std::byte*>(payload.data()), payload.size());
auto write_outcome = co_await lib.write(addr, payload_span);
if (!write_outcome.has_value()) co_return /* propagate */;

auto read_outcome = co_await lib.read_bytes(addr);
if (!read_outcome.has_value()) co_return /* propagate */;
auto& [bytes, info] = read_outcome.value();
auto bytes_span = bytes.span(); // std::span<const std::byte>
```

`Library::init(LibraryInitOptions opts = {})` is the static
constructor (returns `Result<Library>`); it calls the C ABI's
`ovstorage_library_init`, which spins up the per-`Library` tokio runtime
without loading plugins or routes. Call `load_plugins_from_dir` or
`load_plugin` explicitly before adding connections that depend on
backend kinds those plugins provide. The full signature lives in
`ovstorage.hpp` under `class Library`.

The example also exercises `list_connections`,
`authenticate_connection` (multi-event drain),
`capabilities_for`, `list_backend_kinds`, `watch_address_roots`, and
`remove_connection` against the in-tree plugin-test backend — read it
as the canonical reference for the surface.

## What's not supported

- **Exceptions across the library boundary.** The C ABI is the only
  cross-toolchain stable interface, and exception ABIs aren't
  interoperable across compilers / STLs. Errors come back as
  `ovstorage::Result<T>`; the wrapper itself never throws. Plugins
  that use C++ internally must catch all C++ exceptions and translate
  to the C error shape before the call returns.
- **Per-chunk `read_stream`.** The C++ wrapper aggregates chunks into
  `std::vector<std::byte>`. A chunk-by-chunk awaiter is a follow-up;
  for now, callers that can't tolerate aggregation use the C ABI's
  multi-fire callback directly.
- **STL types in plugin manifests.** Manifest types are POD C only —
  no `std::vector`, `std::string`, or any STL type. The
  `plugin_manifest_pod_check` header-side conformance check is a pair
  of `static_assert`s (`is_standard_layout_v` and
  `is_trivially_copyable_v`) emitted per manifest type by the C ABI
  build, so a manifest with an STL field fails to compile.
