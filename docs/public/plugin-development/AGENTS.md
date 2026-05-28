# Plugin development — agent routing

Terse routing for an LLM agent given a plugin task. Read the
companion [README.md](README.md) for prose; this file is invariants
and pointers.

## Where the SPI lives

- **Storage SPI** (Rust traits, manifest, C-ABI handshake, type
  vocabulary) → [README § Plugin SPI](README.md#plugin-spi) and
  [README § Type vocabulary](README.md#type-vocabulary).
- **Author shortcut macro** (`ovstorage_plugin!`) →
  [README § Plugin macros](README.md#plugin-macros).
- **C ABI surface** (`ovstorage.h` / `ovstorage.hpp`,
  `OvStorage_*` types, vtable layout) →
  [README § C-ABI surface](README.md#c-abi-surface) and
  [library-cpp](../library-cpp/README.md) for the C-side header
  surface.
- **Conformance harness** (the in-tree controllable plugin every
  host conformance suite drives ABI shapes through) →
  [README § Conformance harness](README.md#conformance-harness).
- **Minimum viable Rust plugin scaffold** lives inline in
  [README § Build and load](README.md#build-and-load); copy that
  Cargo.toml + `src/lib.rs` block as a starting point.
- **Authz SPI** is separate from storage and is not part of the active
  in-repo plugin surface.

## Read-this-first by plugin kind

- **Storage plugin** (backend that serves objects via routes): start
  at `plugin-storage/README.md`, then [README § Plugin SPI](README.md#plugin-spi).
- **Authz plugin** (broker authorization decisions): not part of the
  active in-repo plugin surface.

## Hard invariants

- **Project rules apply.** Run `make verify` before opening a PR
  (header regeneration, format, license/advisory/clippy, skill frontmatter,
  `cargo test`). Don't paper over a missed cancel plumb-through with a
  leading underscore.
- **Streaming-seam tests are mandatory.** If your change adds a seam
  through which a `Body::Stream` flows — a new plugin, a new
  transport, a new cross-process boundary — add a
  `streaming_invariant` test for it. See
  [README § Streaming seams](README.md#streaming-seams).
  Draining a stream into a `Vec<u8>` at any seam is a memory-DoS
  vector on the public REST gateway and will fail review.
- **Don't hand-write the C ABI.** Use the
  `ovstorage_plugin!(MyFactory::default)` macro
  ([README § Plugin macros](README.md#plugin-macros)). The macro
  emits `ovstorage_plugin_manifest_v1` and
  `ovstorage_plugin_init_v1` with the correct `struct_size`,
  ABI-version band, and `panic = "abort"`-aware init thunk. Adding
  a trailing `, test_only` flag flips the manifest's `test_only`
  bit; any other tail token is a compile error.
- **Cancellation = `tokio::sync::CancellationToken`.** Async SPI
  methods take `Option<&CancellationToken>` (or, for methods still
  shaped synchronously, no token at all). Don't invent a new
  cancellation primitive, don't wrap the token in your own type,
  don't hand back a cancel-handle. The C ABI surfaces this as
  `OvStorage_CancelToken*` (an `Arc<CancellationToken>`) for foreign
  callers; the Rust SPI passes the token directly.
- **Panic discipline.** The workspace pins `panic = "abort"` for
  both `dev` and `release` profiles; an escaped panic terminates
  the process rather than unwinding across the FFI. Plugins must
  not override the profile to `panic = "unwind"`. The
  `catch_unwind` walls in `ovstorage-plugin::thunks` are defense in
  depth, not the primary contract.
- **`test_only` plugins are gated by the host, not by packaging.** A
  plugin with `test_only = true` in its manifest only loads against a
  host that has called `LibraryBuilder::allow_test_plugins(true)`.
  `Library::load_plugin` (direct, by-path) returns
  `ErrorCode::PluginRejected` for an opted-out host;
  `Library::load_plugins_from_dir` (the bulk scan used by the broker
  and REST gateway) skips the cdylib at debug-log level so a default-
  posture deployment can sweep a `plugins/` directory containing a
  bundled test cdylib without failing startup. The conformance plugin
  sets the flag and ships in the release archive's `plugins/` for
  downstream host authors to opt in to; first-party storage plugins
  do not set the flag.
- **`spawn_blocking` is not a runtime escape.**
  `tokio::task::spawn_blocking` workers inherit the calling tokio
  runtime's context. Any closure that internally drives a tokio
  runtime — host FFI callbacks that re-enter tokio,
  `reqwest::blocking::Client::builder().build()` (which builds and
  drops a runtime), nested `Runtime::new() + block_on()` — will
  deadlock or panic. Use vanilla `std::thread::spawn` plus
  `tokio::sync::oneshot` to route results back. Backend code that
  bridges synchronous host callbacks into async streams should use
  `std::thread::spawn` to sever the runtime context.

## Where things are NOT

- The C ABI is not a hand-authoring target. If you find yourself
  hand-writing `extern "C"` symbols for a new storage plugin, stop
  and use `ovstorage_plugin!`. Authz plugins follow the authz SPI's
  own conventions — see that workspace.
- `Storage` (the public application API) and the plugin SPI are not
  the same surface. The plugin SPI is what plugins implement; the
  `Storage` trait is what applications call. Some `Storage` methods
  collapse multiple SPI calls; some SPI calls exist only for routing
  / lifecycle. See [README § Surface boundary](README.md#surface-boundary--host-apis-vs-plugin-spi).
- Conformance scenarios are not free-form scripts. They live in the
  `ScenarioRegistry`. Adding a new behavior means a new registry
  entry, not new test-only config keys. See
  [README § Registry entry shape](README.md#registry-entry-shape).
