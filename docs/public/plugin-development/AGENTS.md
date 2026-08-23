# Plugin development — agent routing

Terse routing for an LLM agent given a plugin task. Read the
companion [README.md](README.md) for prose; this file is invariants
and pointers.

## Where the Layer contract lives

- **Layer contract** (Rust traits, manifest, C-ABI handshake, type
  vocabulary) → [README § Plugin Layer contract](README.md#plugin-layer-contract) and
  [README § Type vocabulary](README.md#type-vocabulary).
- **Author shortcut macro** (`ovstorage_layer_plugin!`) →
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

## Read-this-first by plugin kind

- **Storage plugin** (backend that serves objects via routes): start
  at `plugin-storage/README.md`, then [README § Plugin Layer contract](README.md#plugin-layer-contract).

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
- **Don't hand-write the C ABI.** Use the single-factory
  `ovstorage_layer_plugin!(backend, MyFactory::default)` form or the bundled
  `ovstorage_layer_plugin!(((backend, BackendFactory::default), (wrapper,
  WrapperFactory::default)))` form
  ([README § Plugin macros](README.md#plugin-macros)). The macro
  emits `ovstorage_plugin_manifest_v1` and
  `ovstorage_plugin_init_v1` with the correct `struct_size`,
  ABI version, and a panic-hard-fail init thunk (a constructor
  panic aborts rather than unwinding across the C ABI). Adding
  a trailing `, test_only` flag flips the whole manifest's `test_only`
  bit; bundled kind names must be unique, two discovered plugins cannot
  advertise the same kind, and any other tail token is a compile error.
- **Cancellation = `tokio::sync::CancellationToken`.** Async Layer
  methods take `Option<&CancellationToken>`. The synchronously shaped
  slots take no token: `descriptor`, `list_kinds`, `inner_layer`,
  `owned_targets`, `supports_buffered_write_capture` and
  `invalidate_cached_subtree`. Every operational and runtime-state slot
  is async and cancellable. Don't invent a new
  cancellation primitive, don't wrap the token in your own type,
  don't hand back a cancel-handle. The C ABI surfaces this as
  `OvStorage_CancelToken*` (an `Arc<CancellationToken>`) for foreign
  callers; the Rust Layer trait passes the token directly.
- **Panic discipline.** The `catch_unwind` walls in
  `ovstorage-plugin::thunks_v2` and `ovstorage-plugin::ffi_runtime` convert an escaped panic to
  `ErrorCode::Internal` before it can unwind across the FFI — that
  is the primary contract. The workspace keeps the default
  `panic = "unwind"` so those walls can catch; a panic in a plugin
  constructor (the un-wrapped `extern "C"` init fn) is force-aborted
  by rustc rather than crossing the C ABI.
- **`test_only` plugins are gated by the host, not by packaging.** A
  plugin with `test_only = true` in its manifest only loads against a
  host whose configuration enables `allow_test_plugins`.
  Direct loading returns `ErrorCode::PluginRejected` for an opted-out
  host; directory discovery (the bulk scan used by the broker and REST
  gateway) skips the cdylib at debug-log level so a default-
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
  hand-writing `extern "C"` symbols for a new plugin, stop and use
  `ovstorage_layer_plugin!`.
- `LayerExt` (application conveniences) and the plugin Layer ABI are not the
  same surface. Some application helpers compose multiple Layer calls, while
  some Layer calls exist only for routing or lifecycle. See
  [README § Surface boundary](README.md#surface-boundary--host-apis-vs-plugin-layer).
- Conformance scenarios are not free-form scripts. They live in the
  `ScenarioRegistry`. Adding a new behavior means a new registry
  entry, not new test-only config keys. See
  [README § Registry entry shape](README.md#registry-entry-shape).
