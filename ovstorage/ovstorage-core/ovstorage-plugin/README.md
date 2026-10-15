# ovstorage-plugin

## Purpose

`ovstorage-plugin` is the Rust SDK and C-ABI contract for dynamically loaded
ovstorage Layer plugins. A plugin supplies one or more backend, wrapper, or
router kinds, constructs `Layer` instances for Stack entries, and serves every
operational call through the uniform Layer surface.

Rust authors implement `Layer` plus one of `BackendFactory`, `WrapperFactory`,
or `RouterFactory`, then export the cdylib with
`ovstorage_layer_plugin!`. Rust and host binaries still cross a C ABI because
Rust has no stable dynamic-library ABI.

The canonical author guide is
[`docs/public/plugin-development`](../../docs/public/plugin-development/README.md).
The method-level storage contract is
[`plugin-storage/CONFORMANCE.md`](../../docs/public/plugin-storage/CONFORMANCE.md).

## Public surface

The crate re-exports the operational types from `ovstorage-layer`, including:

- `Layer`, `LayerHandle`, `BackendFactory`, `WrapperFactory`, and
  `RouterFactory`;
- `Request<T>`, `Extensions`, cancellation tokens, and every operation request;
- `LayerKindDescriptor`, `RootInfo`, `Capabilities`, connection/auth types, and
  update streams;
- `ReadResult`, `WriteResult`, `WriteStep`, redirect envelopes, object metadata,
  and error types;
- `ovstorage_layer_plugin!`, the Rust cdylib export macro.

`marshal` converts shared FFI value types and exposes host callbacks. It is not
a plugin SPI: plugins implement `Layer`, not traits under `marshal`.

### Surface boundary: host APIs vs plugin SPI

Applications call a `Stack` or one of the language/service bindings. Plugins
receive already-routed Layer requests. Routing, aliases, retry, caches,
redirect execution, cross-root transfer, policy, and public result projection
belong to host Layers. A backend plugin implements its backend semantics; a
wrapper delegates through `inner_layer()` and intercepts only its policy; a
router owns and dispatches to its children.

### Type vocabulary

The canonical type reference lives in
[`plugin-development` § Type vocabulary](../../docs/public/plugin-development/README.md#type-vocabulary).
Important scope rules:

- `LayerKindDescriptor` is kind-scoped and immutable.
- `Connection` describes configured connection state.
- `RootInfo` is URL/root-scoped and carries effective capabilities.
- `Extensions` contains request facts, never instructions.
- `SecretBytes` must not be logged or converted to an unredacted debug value.

### Error model

Use the shared `ErrorCode` taxonomy documented in
[`GLOSSARY.md` § Error model](../../docs/public/GLOSSARY.md#error-model).
Return `Unsupported` for an unimplemented optional operation and typed
argument/auth/precondition errors for supported operations. Do not encode
provider failures in message strings when a shared code exists.

### URL canonicalization

The host canonicalizes scheme, host, default port and query encoding, and
normalizes the path: escapes are decoded, runs of `/` collapsed, dot segments
resolved, the fragment dropped, and the result re-encoded once. Those arrive
already done, so a plugin neither has to nor can preserve the other spellings.

Everything else in a key stays opaque. Plugins must not strip trailing
punctuation or normalize Unicode; two keys differing only in those bytes are two
objects.

**The trailing slash is never added or removed**, in either direction.
Directory-facing operations receive the target spelled as the caller wrote it,
so they must derive their own directory form rather than assume one.

Mutation operations whose provider cannot honor a version-pinned target must
return `InvalidArgument`; use `url_helpers::reject_pinned_for_mutation`.

### `ReadResult`: the current read shapes

`Layer::read` returns one of four shapes:

- `Bytes { bytes, info }` for a bounded in-memory result;
- `Stream { stream, info }` for chunked async bytes;
- `LocalDelegate` for a leased host-local path;
- `Redirect` for a short-lived request the host redirect Layer executes.

Keep memory bounded by chunk size. Do not collect a streaming provider response
solely to return `Bytes`.

### Plugin SPI

`Layer` contains synchronous identity/introspection and asynchronous object and
connection operations. Async calls accept `Request<T>` plus an optional
`CancellationToken`. Wrapper defaults delegate to `inner_layer()`; leaves
default unsupported operations to `Unsupported`.

Factories describe a kind and create one composition shape:

- `BackendFactory::create_backend(name, config, cancel)`;
- `WrapperFactory::create_wrapper(name, config, inner, cancel)`;
- `RouterFactory::create_router(name, config, children, cancel)`.

The factory returns `LayerHandle` (`Arc<dyn Layer>`). Connection management is
part of `Layer`, so it passes through wrapper and router composition like object
operations.

### C-ABI surface

Every plugin exports two stable symbol names:

- `ovstorage_plugin_manifest_v1`: `PluginManifestV1` with struct size, exact
  Layer ABI version, package name/version, and `test_only`;
- `ovstorage_plugin_init_v1`: receives `HostCallbacks` and returns
  `PluginInitResultV1`.

The frozen symbol suffix is independent of the manifest's ABI value. The
manifest's `abi_version` is `OVSTORAGE_PLUGIN_ABI_V2_VERSION`, and the host
requires an exact match.

`PluginInitResultV1` owns plugin-scoped state, a `PluginVTableV1`, and borrowed
kind descriptors. The plugin vtable exposes `create_backend`, `create_wrapper`,
and `create_router`. Each created `LayerHandle` carries one `LayerVTableV1`
covering identity, introspection, object operations, and connection lifecycle.

Async vtable callbacks fire exactly once. `status == FFI_STATUS_OK` is reserved
for success; the authoritative outcome is pointer presence (`error == NULL`
means success). Reserved trailing slots are zero-initialized.

### Ownership and lifetime invariants

- Manifest memory is static for the cdylib lifetime.
- Kind descriptor arrays are borrowed until plugin state is dropped.
- The host drops each owned `LayerHandle` exactly once through its vtable.
- A plugin must not retain borrowed request pointers past the synchronous ABI
  prologue; thunks convert them to owned Rust values before spawning work.
- Callback-delivered heap values use their matching exported free function.
  Caller-owned out slots are cleared in place and never freed as outer storage.
- Stream items and errors transfer ownership one item at a time.

### Capability vocabulary

Capabilities are root-scoped and returned through `root_info_for` and
`list_address_roots`. Advertise only operations the Layer can honor for that
root. The full vocabulary is documented in
[`plugin-development` § Capability vocabulary](../../docs/public/plugin-development/README.md#capability-vocabulary).

## Dependencies

Notable dependencies are `ovstorage-layer` for the native contract, `tokio` and
`tokio-util` for async/cancellation, `cbindgen` for the checked-in C header, and
`zeroize` for secret storage. The proc macro lives in the sibling
`ovstorage-plugin-macros` crate.

## Threat model

Plugins are trusted in-process native code. The ABI prevents accidental layout,
ownership, and unwind mistakes; it is not a sandbox. Package provenance and
binary signing belong to the deployment system. Hosts restart to load new
plugin binaries; hot replacement is unsupported.

`test_only` is a host policy. Direct loading rejects a test plugin unless the
host enables it; directory discovery skips it at debug level.

## Conformance tests

The workspace verifies:

- native and dynamically loaded Layer behavior;
- backend, wrapper, and router factory creation;
- Layer vtable slot order against the Rust trait;
- descriptor and request-envelope conversion;
- pointer ownership, exact-once callbacks, panic conversion, and cancellation;
- streaming invariants through `ovstorage-plugin-test`;
- generated-header naming and C compilation.

## Implementation notes

### Async model

`thunks_v2` converts owned Rust values to and from the Layer ABI.
`ffi_runtime` owns the per-plugin Tokio runtime, callback guards, cancellation
bridges, and stream thunks. Plugin methods are async-native; blocking SDK work
must be isolated by the plugin.

### Cancellation propagation

The host passes a nullable `CancelTokenFFI`. Plugin thunks retain the token for
the spawned future, bridge it to a local `CancellationToken`, and release it
after completion. Plugin methods should use `race_cancel` or equivalent selects
around provider calls and streams. Cancellation is cooperative; plugins should
also enforce provider deadlines.

### Panic safety

ABI thunks catch panics and complete with `ErrorCode::Internal`; no unwind may
cross C. A panic in the generated `extern "C"` init function aborts according to
Rust's C-unwind rules, so constructors should be small and infallible.

## Risks

### Plugin C ABI vtable stability at 1.0

At 1.0, layouts, slot order, callbacks, and ownership become compatibility
commitments. Top-level structs carry `struct_size`; vtables reserve trailing
slots; the host checks the exact ABI version before reading the init result.
Rust authors use `ovstorage_layer_plugin!` so ABI wiring remains generated.

### Async substrate risks

The main risks are missed completion, cancellation races, use-after-free across
callbacks, and buffering a nominally streaming body. Exact-once guards,
owned-value conversion, focused FFI tests, and conformance streaming checks
cover these boundaries.
