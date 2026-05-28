# ovstorage-capi (`ovstorage.h` + `ovstorage.hpp`)

> The canonical user-facing reference for the C++ wrapper lives in
> [`docs/public/library-cpp/README.md`](../../../docs/public/library-cpp/README.md).
> This file is the crate-internal contributor surface (C ABI design,
> generation, plugin loading, threat model, conformance gates).

## Purpose

`ovstorage-capi` generates `ovstorage.h` via cbindgen and ships the C-ABI symbols (committed in-tree for ABI-drift detection). It also ships the header-only C++ RAII wrapper as `crates/ovstorage-capi/include/ovstorage.hpp` alongside the C header. The C ABI is the foreign interface for **C and C++** — those bindings sit on it directly. The Python wheel ([ovstorage-python](../ovstorage-python/README.md)) is a separate PyO3 binding that links the Rust `ovstorage` library directly and **bypasses** this C ABI; future bindings may sit on the C ABI or use a native FFI path of their own.

The C++ wrapper is consumed at the C/C++ build level, not as a Cargo dep — pull `ovstorage.hpp` + `ovstorage.h` from `ovstorage-capi`'s include dir and link `ovstorage-capi`'s cdylib. The crate links [ovstorage](../ovstorage/README.md) directly and reaches into [ovstorage-plugin](../ovstorage-plugin/README.md) only through types `ovstorage` re-exports.

The C ABI is also the loader interface for dynamically-linked plugins ([ovstorage-plugin](../ovstorage-plugin/README.md)), which is why ABI stability matters more here than in any other language.

For the Python binding see [ovstorage-python](../ovstorage-python/README.md).

## Design audience

The C ABI is the project's **ABI stability contract** — the surface that
third-party consumers link against and that survives across library
versions. Direct hand-authored C against this surface is supported but
is **not** the primary audience. Humans reach for one of three wrappers
instead:

- **Rust** — the `ovstorage::Library` rlib in
  [`crates/ovstorage`](../ovstorage/README.md).
- **C++** — `ovstorage.hpp` in this crate's `include/` directory, which
  layers RAII handles, `task<T>` coroutines, and `Result<T>` over the
  raw C surface.
- **Python** — [`ovstorage-python`](../ovstorage-python/README.md),
  which links the Rust library directly through PyO3 and **bypasses**
  the C ABI entirely.

The wrappers absorb the ergonomic cost of the C surface (opaque-handle
accessor functions, owned-buffer destroy calls, callback-shaped async
methods) so design decisions here optimize for **ABI stability and
correctness**, not hand-written-C ergonomics. Specifically:

- Default to opaque-handle-with-accessors whenever a type has
  variable-length data, owned strings with a defined lifetime, or
  expected ABI growth that won't fit under `struct_size` reserved
  padding.
- Reserve flat `#[repr(C)]` structs (with `struct_size` versioning +
  `has_*` companions for optionals) for cases where all fields are
  by-value primitives — `Capabilities`, `access_decision_t`, the
  options structs.
- Verbose accessor lists (≈10 functions for one `Info` type) are fine
  — they cost typing in the wrapper layer once, not at every call
  site.

## Implementation shape

The implementation is async-first. Every long-running C ABI call is callback-shaped: the function returns `void`, the synchronous prologue validates inputs, and the work plus its `on_complete` callback are dispatched on a per-`Library` tokio runtime so the callback always fires from a worker thread (the "always-async" invariant). The C++ wrapper layers C++20 coroutines (`ovstorage::task<T>`) and `Result<T>` on top via per-method awaiters. Cancellation is plumbed through an opaque `OvStorage_CancelToken` (an `Arc<CancellationToken>`) that the caller can share across in-flight ops for group-cancel; `read_stream`, `authenticate_connection`, and `watch_address_roots` are the multi-fire callback shapes (one fire per chunk/event plus a final `done = true`).

The surface includes the object I/O group plus connection management, alias management, and discovery (see "Public surface" below). `Storage` itself remains async-`Result<T>` in Rust; the Rust `read_stream` returns an async `futures::Stream<Item = Result<Bytes>>` (`type ReadStream = Pin<Box<dyn Stream + Send>>`), and the C ABI exposes it as a multi-fire callback that fires once per chunk plus a final `done = true`. The C++ wrapper aggregates read chunks into a `std::vector<std::byte>` and exposes address-root watch snapshots through a caller callback.

## Public surface

### `ovstorage-capi` — `ovstorage.h`

**Surface.** cbindgen rewrites Rust type names with the `OvStorage_` prefix, so handles appear as `OvStorage_Library*`, `OvStorage_Info*`, `OvStorage_LocalDelegate*`, `OvStorage_List*`, `OvStorage_VersionList*`, `OvStorage_UpdateMetadataOptions*`, plus the connection/auth/alias/discovery handles (`OvStorage_Connection*`, `OvStorage_ConnectionList*`, `OvStorage_AuthEvent*`, `OvStorage_Alias*`, `OvStorage_AliasList*`, `OvStorage_AddressVisibilityOverride*` (+ list), `OvStorage_AddressRoot*` (+ list), `OvStorage_BackendKindDescriptor*` (+ list), `OvStorage_CancelToken*`, plus builder handles `OvStorage_ConfigValue*`, `OvStorage_SecretValue*`, `OvStorage_SecretBundle*`, `OvStorage_ConnectionRequest*`, `OvStorage_AliasRequest*`). Function names stay snake_case (cbindgen does not rename `#[no_mangle]` exports), so callers see `ovstorage_stat`, `ovstorage_library_init`, etc. Object I/O symbols cover `ovstorage_stat`, `ovstorage_read_bytes`, `ovstorage_read_stream`, `ovstorage_read_local_file`, `ovstorage_write`, `ovstorage_delete`, `ovstorage_list`, `ovstorage_list_versions`, `ovstorage_copy`, `ovstorage_rename`, `ovstorage_create_directory`, `ovstorage_delete_directory`, `ovstorage_update_metadata`, and `ovstorage_check_access`. Connection management adds `ovstorage_library_add_connection`, `ovstorage_library_list_connections`, `ovstorage_library_remove_connection`, `ovstorage_library_update_connection_credentials`, and `ovstorage_library_authenticate_connection` (multi-fire). Aliases add `ovstorage_library_add_alias`, `ovstorage_library_remove_alias`, and `ovstorage_library_list_aliases`. Discovery adds `ovstorage_library_set_address_visibility`, `ovstorage_library_list_address_visibility_overrides`, `ovstorage_library_list_address_roots`, `ovstorage_library_watch_address_roots` (multi-fire snapshots), `ovstorage_library_list_backend_kinds`, and `ovstorage_library_capabilities_for`. Each function that acts on a handle takes `OvStorage_Library*` as its first argument.

Options structs are versioned (`OvStorage_ReadOptionsV1`, `OvStorage_StatOptionsV1`, `OvStorage_WriteOptionsV1`, `OvStorage_ListOptionsV1`, `OvStorage_ListVersionsOptionsV1`, `OvStorage_CreateDirectoryOptionsV1`, `OvStorage_DeleteDirectoryOptionsV1`, `OvStorage_LibraryInitOptionsV1`); each carries a leading `size_t struct_size` field validated against the library's known minimum, so newer callers stay forward-compatible. Older callers passing a smaller `struct_size` are rejected with `InvalidArgument`; callers must pass at least the size the library was built against. `OvStorage_DeleteDirectoryOptionsV1` carries no behavioural fields beyond `struct_size` plus reserved padding (the SPI's `DeleteDirectoryOptions` is a unit struct); subtree delete is host-side composition, not a flag on the options struct.

**Async model.** C ABI long-running calls return `void` and take an `on_complete` callback plus a `void* user_data`. The synchronous prologue validates inputs (null pointers, UTF-8, struct_size); even prologue failures are dispatched onto the runtime so the callback always fires from a worker thread, never inline from the caller's thread. The single documented exception is a null `library` handle: with no runtime to dispatch on, a supplied callback fires inline with `InvalidArgument` so callers do not hang forever. `ovstorage_read_stream`, `ovstorage_library_authenticate_connection`, and `ovstorage_library_watch_address_roots` are multi-fire — the callback fires once per chunk/event/snapshot, then once more with `done = true`; a null `library` completes these shapes inline with an error and `done = true`. The synchronous trivial-input builders (`ovstorage_update_metadata_options_*`, `ovstorage_library_init`, `ovstorage_library_shutdown`, the cancel-token lifecycle, accessor getters, and the destroy/clear functions) use the classic blocking shape and return `OvStorage_Status` plus an optional `OvStorage_Error*`.

`OvStorage_Status::Cancelled` carries discriminant `12`; the C++ status mapping handles it explicitly. `ErrorCode` mapping lives in `lib.rs::status_from_error`. `extern "C" fn` callbacks cannot capture state, so each op has a dedicated `fire_*` helper per callback shape (eight: status, info, read_bytes, read_local_file, list, list_versions, check_access, plus `fire_stream_error` for the per-chunk `ovstorage_read_stream_callback_t`). The wrappers are mechanical and easier to read in stack traces.

**Targeted file-connection helper.** `ovstorage_library_register_file_connection(library, root_path, cancel, on_complete, user_data)` is a thunk in `ops.rs` with a status-only callback. It hardcodes `backend_kind = "file"` and `config = { "root": Path }`, defaulting credentials, persist, and display_name. The C++ wrapper exposes it as `Library::register_file_connection(root_path, cancel) -> task<void>`. The cpp-async test driver does an end-to-end round-trip (register → write → read_bytes → stat) against a temp-dir file backend.

**Errors.** Async thunks deliver errors via the callback's `const OvStorage_Error*` parameter — the message is owned by the library and freed after the callback returns. Synchronous calls take a caller-allocated `OvStorage_Error*`; on failure the library fills the status code and a heap-owned message that the caller releases with `ovstorage_error_clear`. Passing `NULL` for `out_error` is allowed when the caller only cares about the status code. All C entry points wrap Rust execution in `catch_unwind` and convert panics to `Internal`.

**Buffers and ownership.** `OvStorage_Bytes { const uint8_t* data; size_t len; void* free_ctx; }` lets the library hand back owned bytes without copying them into caller-provided storage. The caller passes the struct to `ovstorage_bytes_destroy` when done. Streaming reads (`ovstorage_read_stream`) deliver the same shape one chunk at a time through the callback. `OvStorage_LocalDelegate` mirrors the Rust struct: a UTF-8 path plus a populated `OvStorage_Info*` reachable via `ovstorage_local_delegate_path` and `ovstorage_local_delegate_info`.

**Safety.** Every entry point wraps Rust execution in `std::panic::catch_unwind` and converts an escaped panic to `OvStorage_Status_Internal`. The workspace also sets `panic = "abort"` for both `[profile.dev]` and `[profile.release]` so an escaped panic in a plugin or host callback terminates rather than rolling up the C frame stack; the `catch_unwind` walls remain as defense in depth against foreign-built plugins compiled with `panic = "unwind"`. All inputs are validated at the boundary; invalid pointers return `InvalidArgument` (or the documented safe default for accessor getters such as `OvStorage_ConfigValue`'s `_kind` / `_as_*`) rather than crashing.

**Nullable callback fields.** `OvStorage_OvCredentialCallback.resolve` and `.free_userdata` are emitted as nullable C function pointers (`Option<unsafe extern "C" fn(...)>` on the Rust side). `resolve` may be `NULL` only when `has_credential_callback = false`; setting `has_credential_callback = true` with `resolve = NULL` is rejected with `InvalidArgument`. `free_userdata` is unconditionally optional — the host calls it only when non-null.

**`OvResolvedCredentialV1` consumption.** The `bundle` handle is consumed by the host only on success. All fallible non-owning validation (`struct_size`, `bundle != NULL`, `source_name != NULL`, UTF-8 decode of `source_name`) runs before the host takes ownership of the bundle, so on `InvalidArgument` the caller still owns the bundle and must `ovstorage_resolved_credential_bundle_destroy` it.

**Header smoke tests.** The crate's test suite exercises `cc -std=c99 -fsyntax-only ovstorage.h` and `g++ -std=c++20 -fsyntax-only ovstorage.hpp` against the committed headers; these tests are skipped (with a stderr note) when the toolchain is unavailable so the suite still runs in minimal sandboxes.

**Generation and distribution.** Headers are generated by `cbindgen` (configured via `cbindgen.toml`, `prefix = "OvStorage_"`, `style = "type"`, `cpp_compat = true`) from the Rust crate's `pub extern "C"` surface; the `build.rs` rewrites `crates/ovstorage-capi/include/ovstorage.h` in-place when bytes change. The header is committed in-tree for ABI-drift detection and IDE consumption. Set `OVSTORAGE_CAPI_SKIP_CBINDGEN=1` to short-circuit generation in sandboxes. The local package bundles the C header, plugin header, C++ header, Python stubs, and built shared libraries. Symbol versioning, pkg-config, CMake package files, and sanitizer matrix jobs are not provided.

### C++ wrapper — `ovstorage.hpp`

> The canonical reference for the **C++ wrapper — `ovstorage.hpp`** lives in [`docs/public/library-cpp/README.md` § Surface inventory](../../../docs/public/library-cpp/README.md#surface-inventory) and § [Coroutine internals](../../../docs/public/library-cpp/README.md#coroutine-internals).

## Internals

### Shared lifecycle

The bindings share one async `Library` implementation. The C ABI links [ovstorage](../ovstorage/README.md) directly; the C++ header calls the C ABI. Each binding owns a tokio runtime: the C ABI's `Library` carries an `Arc<tokio::Runtime>` sized by `LibraryInitOptionsV1.runtime_threads` (default 2). This matters because:

- A C application that opens two `OvStorage_Library*` handles gets two Rust `Library`s and two tokio runtimes; in-flight ops on each handle are independent.
- A C++ application gets `task<T>` coroutines; top-level callers drive them with `sync_wait`, while inside another coroutine they `co_await` directly.

### Type marshaling

The bindings are deliberately thin. Type marshaling is the bulk of each binding's code:

- **Address values.** C calls accept UTF-8 address strings directly; there is no public `OvStorage_Address` handle. C++ accepts strings and lets Rust `address::parse` validate them at the boundary.
- **`OvStorage_Info`.** Mirrors `ObjectInfo`. Field accessors expose address, size, mtime (as Unix nanoseconds), etag, version, system metadata, and user metadata. C++ `Info` reads through those accessors.
- **`OvStorage_LocalDelegate`.** Wraps a `LocalDelegate`. `ovstorage_local_delegate_path(const OvStorage_LocalDelegate*)` returns a borrowed UTF-8 path; `ovstorage_local_delegate_info` returns a borrowed `OvStorage_Info*`; `ovstorage_local_delegate_destroy` drops the delegate. C++ `LocalDelegate`'s destructor calls `_destroy`.
- **`OvStorage_List` / `OvStorage_VersionList`.** Own paged list results. Item accessors return newly-owned `OvStorage_Info*` handles; each item's canonical address is `OvStorage_Info.address`.
- **Builder types.** `OvStorage_ConnectionRequest`, `OvStorage_AliasRequest`, `OvStorage_SecretBundle`, `OvStorage_ConfigValue`, and `OvStorage_SecretValue` are constructor-style: callers `_create`, append fields with setters, then move-consume them on submission. The Rust side stores them in a `Mutex<Option<…>>` so a double-submit returns `InvalidArgument` rather than crashing.

Options marshaling is field-for-field with `ovstorage-plugin`. Bindings must not reinterpret absent metadata fields as wildcard strings or sentinel numbers: an omitted ETag/version/size/mtime remains `None`. `delete_directory` removes only the directory representation; subtree deletion is host-side composition (callers walk + bulk-delete themselves) and is not exposed as a flag on the options struct.

### Plugin loading from C

[ovstorage-plugin](../ovstorage-plugin/README.md) owns plugin loading: the loader opens `.so` / `.dylib` / `.dll` files, locates `ovstorage_plugin_manifest_v1` and `ovstorage_plugin_init_v1`, validates the ABI version and vtable size, and returns a `LoadedPlugin`. The application C ABI's `ovstorage_library_init` returns an empty library: no plugins are loaded and no routes are bound. Callers must explicitly load trusted plugin cdylibs with `ovstorage_library_load_plugin` or `ovstorage_library_load_plugins_from_dir` before adding connections for plugin backend kinds. `ovstorage_library_load_plugins_from_dir(NULL)` resolves `OVSTORAGE_PLUGIN_DIR` (or `<exe_dir>/plugins/` as a fallback); if no plugin is loaded, `add_connection` with `backend_kind = "file"` returns `NoBackend`. After plugin loading, `ovstorage_library_list_backend_kinds` reports which backend kinds are available. Callers reach the file backend by adding a connection with `backend_kind = "file"` through `ovstorage_library_add_connection`; there is no dedicated `ovstorage_library_open_file` shortcut. Config-driven preset connections (declarative TOML routing for the binding) are not implemented.

Storage plugins and authz plugins are distinguished by which manifest symbol they export — storage plugins export `ovstorage_plugin_manifest_v1` plus `ovstorage_plugin_init_v1`, authz plugins export `ovstorage_authz_plugin_manifest_v1` plus `ovstorage_authz_plugin_init_v1`. Each domain's loader resolves its own symbol; there is **no `plugin_kind` field** on the storage `PluginManifestV1` struct (the only fields are `struct_size`, `abi_version`, `name`, `version`, and `test_only`). Broker authn is implemented in broker core; broker authz uses the separate `ovstorage-authz-plugin` SPI rather than the C/C++ binding ABI.

Sharing one plugin across multiple language hosts in the same process is safe by design: explicit plugin loading is idempotent for already-loaded plugin shared objects, and `dlopen` deduplicates at the OS level, so a Python application and a C++ application that share a plugin search path and load the same plugin observe the same plugin instance through the loader's symbol table. The manifest-validation pass keys off the loader-returned handle rather than re-parsing fresh per `Library`.

## Dependencies

In-workspace:

- **`ovstorage-capi`** depends on [ovstorage](../ovstorage/README.md), `tokio` (`rt-multi-thread`), and `futures`. Its `cdylib` artifact ships as `libovstorage.so` / `libovstorage.dylib` / `ovstorage.dll` (via `[lib] name = "ovstorage"`); the cargo package name `ovstorage-capi` is workspace metadata only. The crate does not export an rlib — integration tests dlopen the cdylib via `libloading`.
- **`ovstorage.hpp`** has no separate Cargo crate (it ships from `ovstorage-capi/include/`); it consumes `ovstorage-capi`'s generated header and `cdylib` at the C++ build level. `examples/cpp-async/` exercises the linkage via CMake.

External (notable):

- `ovstorage-capi` — `cbindgen` (build-dep for header generation).
- `ovstorage.hpp` — none at the Rust level. At the C++ level: depends on the host application's standard library (libstdc++, libc++, MSVC STL) and a C++20 toolchain (coroutines).

## Threat model

The bindings inherit [ovstorage](../ovstorage/README.md)'s redaction guarantee: every error that crosses the binding boundary has already been redacted at the [ovstorage-plugin](../ovstorage-plugin/README.md) error-mapping layer; the bindings don't add their own logging or tracing that could leak token material. Tracing is configured via the underlying library — applications that want OTLP / stdout-JSON spans set the env vars or call the library's `init_tracing` once at startup, regardless of which binding they're using.

**Plugin loading happens in the host process.** A malicious plugin loaded by a C or C++ application has the same privileges the application has — there is no sandbox at the C ABI. This is by design: in-process plugins are documented as trusted code in [ovstorage-plugin § Threat model](../ovstorage-plugin/README.md#threat-model). Operators who need plugin isolation deploy a per-host broker over UDS and route the relevant prefix through `broker-client`.

**Panic discipline.** Every C entry point wraps Rust execution in `std::panic::catch_unwind`; an escaped panic is reported as `OvStorage_Status_Internal` with a generic redacted message. The workspace also sets `panic = "abort"` for both `[profile.dev]` and `[profile.release]` so any panic in workspace-built plugins or host callbacks terminates the process rather than risking undefined behavior across the C frame; the `catch_unwind` walls remain as defense in depth against foreign-built plugins shipped with `panic = "unwind"`. Application authors who need stronger isolation should run their `ovstorage_library_init` calls in a child process they can restart.

## Conformance tests

Local source-level gates: the C ABI symbols are covered by Rust tests in `ovstorage-capi`, and the C++ wrapper is checked as a packaged header. The broader compiler and sanitizer matrix below describes additional gates that are not configured.

**ABI**
- C ABI smoke: every documented `ovstorage_*` symbol is callable from a C99 program against the committed `ovstorage.h` and produces the documented behavior on a `file:` round trip.
- ABI-drift: a CI gate that regenerates the header via `cbindgen` and fails the build on any diff against the committed `ovstorage.h` is not configured.
- Versioned options: a `_v1_` options struct compiled against version N runs unchanged against the library at version N+1; new fields are zero-initialized on the older client and ignored by the newer library.
- API parity: every public `Storage` method has a documented C symbol or an explicit binding-level omission approved before 1.0; object I/O, control, management, and auth groups are checked separately so the data plane cannot accidentally hide management drift.
- Version listing parity: `list_versions` returns `ObjectInfo` values with caller-facing, version-pinned addresses exactly the same way as Rust; C and C++ expose finite paged results.
- Directory-delete shape: `ovstorage_delete_directory_options_v1_t` is empty beyond `struct_size` and reserved padding; the SPI's `delete_directory` removes only the directory representation, and a caller that wants to delete children walks + bulk-deletes them itself.
- ASan / UBSan: the C-ABI test suite is expected to run clean under AddressSanitizer and UndefinedBehaviorSanitizer; sanitizer CI is not configured.
- Symbol versioning: `libovstorage.so.1` exports exactly the documented symbols when platform packaging adds versioned shared-library metadata; an unversioned binary linking against `.so.1` resolves correctly. Versioned shared-library metadata is not configured.

**C++**
- RAII: every documented `ovstorage::*` handle calls the corresponding `_destroy` exactly once on destruction; double-free / leak detection is part of every test under ASan.
- Result usage: no exceptions cross the C++/library boundary; every awaited error path returns `ovstorage::Result<T>` containing `ovstorage::Error`.
- Coroutine parity: `co_await Library::*` and `sync_wait(Library::*)` produce byte-identical `Result<T>` for every documented method.
- Directory-delete parity: `co_await library.delete_directory(addr)` invokes the same single library path as Rust; subtree delete in C++ is host-side composition (caller walks + bulk-deletes), matching the SPI shape.
- Compiler matrix: GCC 13, Clang 17, MSVC 19.40 each compile the header-only library with `-Wall -Wextra -Werror` (or MSVC equivalent) and run the test suite green; native compiler CI is not configured. The `examples/cpp-async/` CMake project is the smoke target.

## Risks

### C ABI stability at 1.0

**Status:** defensive-depth

**Concern.** The cbindgen-generated `ovstorage.h` is the wire across every non-Rust caller (C, C++, Python, future bindings). At 1.0, every struct layout, function signature, and enum value is a forever commitment — breakage requires a 2.0, with the corresponding ecosystem disruption.

**Why this mitigation is sound (target).** Five layered defenses, all textbook for projects that have done this successfully (zlib, libcurl, SQLite). Conservative struct layout puts a `size_t struct_size` field first on every options struct so the library can reject ABI-mismatched callers at runtime; reserved padding (8 `void*` slots at the end of every public struct) absorbs additive growth; ASan / UBSan jobs and an ABI-drift gate (cbindgen diff vs. the committed `ovstorage.h`) catch layout bugs that escape review; 0.x is the explicit burn-in window where breakage is expected and called out in release notes. **Current state:** struct-versioning + reserved-padding ship in code; ASan/UBSan jobs and the ABI-drift CI gate are *not* configured (no workspace CI exists today — see `Conformance tests` and `Implementation gaps` below).

**Alternatives considered and rejected.**

- **No struct-versioning, rely on never breaking layouts.** zlib's history says this works only for trivially-small structs; ovstorage's options structs grow over time, so explicit versioning is necessary.
- **Opaque handles only (no public structs).** Ergonomically painful for C/C++ callers who want to inspect `ObjectInfo` fields directly; the project chose value-shaped public types and lives with the discipline cost.
- **Major-version bumps for every additive field.** Breaks zero-cost extensibility — the entire point of `struct_size` plus reserved padding is that callers built against version N transparently work against library N+M for any additive M.

**What this mitigation does NOT cover.**

- Compiler-version mismatches in `_Atomic` semantics (C11 vs C17): we do not expose atomics in the public ABI; internal use only.
- Caller misuse of `struct_size` (passing the wrong size deliberately to access reserved padding): the library rejects mismatched sizes with `InvalidArgument`; deliberate misuse is the caller's bug.

**Implementor checklist.**

- Every public options struct has `size_t struct_size` as its first field; the library checks `struct_size >= sizeof(known_minimum)` at every entry point. (`usize_is_size_t = true` in `cbindgen.toml`.)
- **Vtable reserved slots:** `BackendVTableV1` and `BackendFactoryVTableV1` end with 16 zero-initialized `Option<VTableReservedFn>` slots so a NEWER host running against an OLDER plugin sees `None` for an unimplemented call rather than reading past the plugin's vtable. New SPI methods consume the next free reserved slot in tree order, never reorder existing fields.
- **Options reserved padding:** every public V1 options struct in `ovstorage-capi` ends with `_reserved: ReservedOptionsPadding` (8 zero-initialized `void*` slots) so additive growth doesn't break layout for older callers. Use `RESERVED_OPTIONS_PADDING_ZERO` to zero-initialize.
- **`panic = abort` workspace profile:** both `[profile.release]` and `[profile.dev]` set `panic = "abort"`, so an escaped panic in a plugin or host callback terminates rather than crossing the C frame stack. `catch_unwind` walls at each FFI entry point are defense in depth.
- `cbindgen.toml` pins `header` content; the `build.rs` regenerates `include/ovstorage.h` in-place. An `abi-drift-check` CI step that runs `cbindgen --crate ovstorage-capi` and `diff -u` against the committed header is not configured.
- ASan + UBSan jobs in CI are not configured.
- Every public function pre-calls `catch_unwind`; the workspace also sets `panic = "abort"` for `[profile.dev]` and `[profile.release]` so an escaped panic terminates rather than crossing the FFI.
- Release-note template includes "ABI-affecting changes" section; pre-1.0 releases call out every breakage.

**Verification.**

- Conformance test `c_abi_struct_size_rejection` (not implemented): a caller passing a `struct_size` smaller than the library's known minimum (including `struct_size == 0`) gets `InvalidArgument`; passing the size of a future known version succeeds (forward compat). The `struct_size == 0` case is rejected because the plugin SPI's `*_options_from_ffi` converters read tail fields unconditionally; accepting `0` would force them to read uninitialised memory. Top-level C-API entry points (`ovstorage_*`) may still synthesise defaults from a zero-prefix because they construct fully-initialised options structs before handing them down to the SPI; the rejection only applies at the SPI boundary itself (see `validate_struct_size` in `ovstorage-plugin/src/ffi/options.rs`).
- Conformance test `c_abi_padding_growth` (not implemented): a synthetic struct-extension scenario validating that adding a field within reserved padding doesn't change the layout for old callers.
- CI gate `abi-drift-check`: not configured (no `.github/`, GitLab CI, or workspace CI config exists); required check on every PR touching `ovstorage-capi` or its dependencies.
- The C ABI surface ships from 0.1; the ABI-drift gate is required from 0.1 forward — currently *not enforced*.

### C++ standard library mismatch

> The canonical reference for **C++ standard library mismatch** lives in [`docs/public/library-cpp/README.md` § STL mismatch posture](../../../docs/public/library-cpp/README.md#stl-mismatch-posture).
>
> Crate-internal verification gates retained here:
>
> - Conformance test `cpp_binding_libstdcxx_libcxx_parity`: the same C++ test program built against libstdc++ and libc++ produces byte-identical output for every public API call.
> - Conformance test `plugin_manifest_pod_check`: every type appearing in a plugin manifest passes `std::is_standard_layout_v && std::is_trivially_copyable_v`.
> - General plugin-author docs are in [plugin-development](../../../docs/public/plugin-development/README.md) and [plugin-storage](../../../docs/public/plugin-storage/README.md). A dedicated *C++ plugin*-author guide (covering libstdc++/libc++ static-link options for plugins authored in C++) is not provided.

## Implementation gaps

These items are referenced ("see Implementation gaps") elsewhere in the doc; centralized here so reviewers can audit the full list in one place. None block the surface from working.

**ABI stability scaffolding (referenced from "Risks · C ABI stability at 1.0", "Conformance tests").**
- No CI is configured in the workspace (no `.github/`, no GitLab CI, no workspace CI scripts under `tools/` or `scripts/` for binding gates). The `abi-drift-check`, ASan, UBSan, and compiler-matrix gates listed under "Conformance tests" are not configured.

**Examples and packaging.**
- `examples/cpp-async/` ships and its `CMakeLists.txt` resolves the cdylib + headers from the workspace `target/` tree. There is no `examples/c-async/` smoke binary.
- The `build.rs` doc-comment refers to "`src/lib.rs` and `src/ops.rs`" but the FFI lives in `src/ffi/{mod.rs, ops.rs, builders.rs, …}`. The `cbindgen::with_crate(&crate_dir)` call still works (it walks the whole crate tree), but the comment is stale.

**Configuration surface follow-ups.**
- Schema accessors on `BackendKindDescriptor` (config_schema / credential_schema field walks) are not exposed at the C ABI. UI-tooling concern; needs its own design pass before landing.
- `watch_address_roots` is continuous and delivers full `AddressRootList` snapshots; the C++ wrapper surfaces those snapshots through `AddressRootSnapshotHandler`.
- `read_stream` in the C++ wrapper accumulates chunks into a `std::vector<std::byte>` (drain-to-vector). A chunk-by-chunk `AsyncStream<Bytes>` surface is a follow-up.

### Out of scope

- **Push-callback streaming and Arrow C Stream Interface integration.** The C ABI exposes the chunk-iterator surface only; no Arrow-stream bridge is provided.
- **Poll + waker C ABI for async.** Foreign callers drive async operations through the existing callback / completion handles; a poll/waker-shaped C surface is not part of the ABI.
- **Plugin sandboxing / seccomp.** Plugins loaded via the C ABI run in-process with the host's privileges. Operators who need plugin isolation deploy a per-host broker over UDS and route the relevant prefix through `broker-client`.

## See also

- [ovstorage-python](../ovstorage-python/README.md) — the Python binding (PyO3-based wheel).
