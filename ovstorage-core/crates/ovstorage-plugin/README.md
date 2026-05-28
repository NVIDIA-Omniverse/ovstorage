# ovstorage-plugin

## Purpose

`ovstorage-plugin` declares the Rust-side traits and the C-shaped loader handshake every ovstorage storage plugin implements: `shim::Backend`, `shim::Factory`, the `Capabilities` bitset, `ReadResult` / `WriteStep`, backend list/version/watch item shapes, the manifest format, and the C-ABI symbols (`ovstorage_plugin_manifest_v1`, `ovstorage_plugin_init_v1`, `BackendFactoryVTableV1`, `BackendVTableV1`) the host loader expects. It is the contract between [ovstorage](../ovstorage/README.md) and every storage plugin — first-party and otherwise.

Broker authentication is implemented in `ovstorage-broker` core. Broker authorization uses the separate `ovstorage-authz-plugin` SPI and the first-party `ovstorage-authz-toml` plugin. Authz plugins are deliberately separate from the storage-backend contract described here.

The crate ships the Rust traits, the `ovstorage_plugin!` function-like macro (in the sibling `ovstorage-plugin-macros` crate) that emits the 0.x manifest/init symbols for Rust authors, and the public C header `ovstorage_plugin.h` that C / C++ authors compile against. The library does not know — and does not need to know — what language the plugin was written in: the binary the loader sees is the same shape. There is no separate "Rust plugin" loader path; the Rust ABI is unstable, so even an all-Rust deployment crosses the C ABI between library and plugin.

The C vtable carries the populated factory + backend method tables (`drop` + 17 async I/O slots on the backend, plus `drop` / `descriptor` / `probe` / `instantiate` / `update_credentials` / `authenticate` on the factory). Async I/O slots are callback-shaped — the host calls the vtable method, the thunk validates inputs synchronously, spawns the work on the plugin's tokio runtime, and fires `on_complete` exactly once when the spawned future settles. The remaining ABI work before 1.0 is hardening, ABI-drift CI, and the conformance harness.

The plugin C ABI **freezes at 1.0**; once shipped, breakage is a 2.0. Mitigations: conservative vtable design, an explicit `OVSTORAGE_PLUGIN_ABI_VERSION` constant the host checks against the manifest, and the function-like `ovstorage_plugin!(MyFactory::default)` macro insulating Rust authors from the C surface. Reserved trailing-slot padding and a multi-revision handshake are still on the burn-in todo list (see [Risks](#plugin-c-abi-vtable-stability-at-10)). 0.x is the burn-in.

## Public surface

### Surface boundary: host APIs vs plugin SPI

> The canonical reference for **Surface boundary: host APIs vs plugin SPI**
> lives in [`docs/public/plugin-development/README.md` § Surface boundary](../../../docs/public/plugin-development/README.md#surface-boundary--host-apis-vs-plugin-spi).

### Type vocabulary

> The canonical reference for **Type vocabulary** (core types, options structs, version-pinned addresses, connection / alias / auth types, `LocalDelegate`, and `SecretBytes`) lives in [`docs/public/plugin-development/README.md` § Type vocabulary](../../../docs/public/plugin-development/README.md#type-vocabulary).

### Error model

> The canonical reference for the `ErrorCode` taxonomy lives in
> [`docs/public/GLOSSARY.md` § Error model](../../../docs/public/GLOSSARY.md#error-model).

### URL canonicalization

The library canonicalizes URLs at parse time, but only on the parts of the URL that name *where* the request goes — scheme, host, port, and query encoding. **Object key segments are preserved byte-for-byte.** Object stores commonly accept keys with literal `..`, `.`, double-slashes, trailing dots, control characters, and unicode-normalization-sensitive sequences, and the library doesn't rewrite any of them.

The transformations the library *does* apply:

- Lowercase the scheme.
- Lowercase the host, where the scheme treats host as case-insensitive.
- Strip default ports (e.g. `:443` for `https`).
- Encode query parameters canonically, without reordering them.
- Apply IDN punycode normalization to the host.

`ovstorage-plugin` does not recognize provider-native HTTPS URLs. To the plugin ABI, `https://bucket.s3.us-west-2.amazonaws.com/key`, `https://storage.googleapis.com/bucket/key`, and `https://account.blob.core.windows.net/container/key` are just HTTPS addresses. Any provider-specific interpretation of the host or path belongs to the plugin for the route that explicitly matched that prefix.

Keys at the providers we target are opaque byte strings. In one S3 bucket, `foo/bar`, `foo//bar`, and `foo/../foo/bar` are three different objects that can coexist, and a `list` returns each one verbatim. GCS and Azure flat-blob behave the same way.

The providers do enforce a few narrow server-side rules. S3 rejects PUTs whose cumulative `..` count parsed left-to-right exceeds the non-relative segments seen so far — `videos/../../v.wmv` is rejected, but `videos/2014/../../v.wmv` is accepted and stored as the literal string. GCS rejects an object name that is *exactly* `.` or `..`. ADLS Gen2 with hierarchical namespace, being a real filesystem, rejects `//` and trailing `.`, `/`, or `\` outright. Whatever the provider accepts is stored exactly as written.

The library leaves those rules to the provider and never silently rewrites a key segment. Rewriting would either resolve to a different object than the caller asked for — collapsing `foo//bar` to `foo/bar` when both exist — or produce a key the provider rejects, like stripping a trailing dot the caller deliberately included. Some client SDKs in the wild do normalize URI paths before signing (AWS Go SDK v1's `DisableRestProtocolURICleaning = false` default, rclone's path collapsing); ovstorage's HTTP machinery sends the caller's bytes through to the wire unchanged.

The exception is not URL canonicalization but operation semantics: directory-facing methods canonicalize their argument to directory form by appending a trailing slash before query or fragment. This is scoped to `create_directory`, `delete_directory`, and `list`. `stat` is input-guided: no trailing slash probes the exact object first and then the directory on `NotFound`; a trailing slash probes only the directory. Byte-addressed object operations never apply this rewrite.

Mutating ops whose backend wire format cannot carry a version pin must reject any caller-supplied version-pinned address with `InvalidArgument` rather than silently dropping the pin and writing to head. The shared helper `ovstorage_plugin::url_helpers::reject_pinned_for_mutation` takes the resolved URL and a list of pin keys (`versionId`, `generation`, `versionid`, `version`, `checkpoint`, …) and returns the typed error so each plugin's mutating-op surface stays consistent.

### `ReadResult`: the current read shapes

Every plugin's `read` SPI call returns one of four shapes. The library's typed helpers (`read_bytes`, `read_stream`, `materialize`) consume the enum and present the appropriate result to the caller; applications never branch on the variant directly.

```text
pub enum ReadResult {
    Bytes { bytes: Vec<u8>, info: ObjectInfo },
    Stream { stream: ReadStream, info: ObjectInfo },
    LocalDelegate(LocalDelegate),
    Redirect(ReadRedirect),
}
```

- **`LocalDelegate`** ([Type vocabulary § `LocalDelegate`](#localdelegate)) — bytes are already on local disk under a leased path. Returned from cache hits and from the `file` plugin. The library hands it back unchanged; `read_stream` opens the file and emits 64 KiB chunks.
- **`Bytes`** — the plugin returns an in-memory byte buffer plus `ObjectInfo`. Used for small responses (under the per-plugin small-response threshold) and for ranged reads where the caller already bounded the slice. `read_stream` wraps it as a single iterator chunk.
- **`Stream { stream, info }`** — async chunk-stream (`ReadStream = Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>`) for whole-object reads above the small-response threshold. Returned by every cloud plugin's whole-object path (HTTP, GCS user-cred, OpenDAL, broker-client streamed-Read response). `read_stream` returns the stream as-is; `read_bytes` and `materialize` drain it on the runtime via `.next().await` (no `spawn_blocking` — the SPI is async-native). Peak host memory is bounded by the stream's chunk size, never by object size — this is the substrate that prevents the "redirect a 10 GiB read and OOM the host" pattern. The REST gateway feeds the stream straight into `axum::body::Body::from_stream` with no per-chunk runtime hop.
- **`Redirect`** — the plugin returns a short-lived HTTP request envelope plus response-parsing hints. The host follows the request through the shared redirect follower; the streaming follower handed to `read_stream` pulls chunks from `reqwest::Response::bytes_stream()` so even multi-GiB redirected reads stay bounded.

The `Stream` variant is the read-side counterpart to `Body::Stream` on the write side. Plugins MAY keep `Bytes` as a fallback for small responses (per-plugin threshold, e.g., 1 MiB); the dispatcher accepts both shapes uniformly. The conformance harness asserts that streaming reads from a multi-GiB fixture peak at chunk-size memory rather than object-size memory; plugins that rebuild buffers internally fail this assertion even if they advertise streaming.

### Plugin SPI

> The canonical reference for **Plugin SPI** (the `shim::Backend` and `shim::Factory` async traits, the full method-by-method contract, `list` shape rules, `WriteStep` / redirect vocabulary, `watch_directory` events, and the differential return shapes) lives in [`docs/public/plugin-development/README.md` § Plugin SPI](../../../docs/public/plugin-development/README.md#plugin-spi).

### C-ABI surface

From the library's perspective there is one plugin transport: a dynamically loaded shared library (`.so` / `.dylib` / `.dll`) opened through `libloading`. Every plugin binary exports two C-ABI symbols (the factory vtable lives inside the plugin as a static, but its address is returned from `init` rather than resolved as a separate symbol):

- `ovstorage_plugin_manifest_v1` — a `static PluginManifestV1` describing the plugin (`struct_size: usize`, `abi_version: u32`, NUL-terminated `name` and `version` pointers, `test_only: bool`). There is no `plugin_kind` field on the manifest; storage vs. authz is disambiguated by cdylib filename prefix and by which symbols the loader resolves. Read first; if the manifest is missing or its ABI version isn't compatible, the library refuses to load the binary.
- `ovstorage_plugin_init_v1` — the binary init function. It receives a `*const HostCallbacks` (the host's keyring and OAuth-refresh-lock callbacks) and returns `BackendPluginInitResultV1 { struct_size, abi_version, min_supported_abi_version, max_supported_abi_version, plugin_state, factory_vtable }`. The `factory_vtable` field points at the populated factory-level vtable inside the plugin's binary; the host borrows the pointer for the cdylib's lifetime.

The factory-level vtable shape is `BackendFactoryVTableV1`: `drop`, `descriptor`, `probe`, `instantiate`, `update_credentials`, `authenticate`. `instantiate` hands back a `BackendInstance` carrying the route's `Capabilities` as a value field; the `backend.vtable` points at `BackendVTableV1` (`drop`, `stat`, `read`, `write`, `write_stream`, `write_redirect`, `continue_write`, `delete`, `list`, `list_versions`, `get_latest_version`, `watch_directory`, `create_directory`, `delete_directory`, `copy`, `rename`, `update_metadata`, `check_access`). `watch_address_roots` is exposed on the Rust SPI trait (`shim::Backend::watch_address_roots`) but is **not** wired through `BackendVTableV1` — plugins loaded through the C ABI cannot serve dynamic address-root subscriptions; the static `address_roots()` SPI is the only callable surface. Plugins that advertise `Capabilities::address_roots_are_dynamic = true` while loaded as a cdylib are accepted by the host (the dispatcher will spawn a watcher) but the watcher's `watch_address_roots` call surfaces `Unsupported` immediately because no C-ABI slot exists; the host logs and the watcher exits.

Rust authors get all required symbols emitted by `ovstorage_plugin!(MyFactory::default)` (a function-like macro that takes any `fn() -> impl Factory` constructor expression); C and C++ authors export them by hand against `ovstorage_plugin.h`. The library does not know — and does not need to know — what language the plugin was written in: the binary the loader sees is the same shape. There is no separate "Rust plugin" loader path; the Rust ABI is unstable, so even an all-Rust deployment crosses the C ABI between library and plugin.

**Async callback `status` convention.** Every async vtable method's `on_complete` callback receives `(status: i32, result, error, user_data)`. `status == FFI_STATUS_OK` (`0`) is reserved exclusively for success; every error path returns `FFI_STATUS_ERR` (`-1`). The real `ErrorCode` lives on the heap-allocated `*mut Error` pointer the callback receives, never in the integer status word — `ErrorCode::NotFound` happens to be discriminant `0` and a status-only consumer would otherwise mishandle it as `Ok`. Outcome dispatch is pointer-presence based: `error == NULL` is success; `error != NULL` is failure.

**`*_free` ownership.** The C ABI exposes two distinct allocation patterns and each `ovstorage_plugin_*_free` export honours exactly one of them — calling the wrong one is undefined behaviour:

1. **Callback-delivered (heap)** — the plugin's thunk `Box::into_raw(Box::new(...))`'s the value and the host receives a `*mut T` that *owns* a `Layout::new::<T>` allocation. The matching `_free` reclaims it via `Box::from_raw`, releasing both nested fields and the outer `Box`. Affected exports: `ovstorage_plugin_error_free`, `ovstorage_plugin_write_result_free`, `ovstorage_plugin_read_result_free`, `ovstorage_plugin_write_step_free`, `ovstorage_plugin_access_decision_free`, `ovstorage_plugin_object_info_free` (the `stat` callback path), `ovstorage_plugin_backend_instance_free`, `ovstorage_plugin_auth_event_stream_free`, `ovstorage_plugin_backend_change_stream_free`. Calling these on caller-owned storage (a stack slot, a borrowed field, an `out: *mut T` argument) is UB.
2. **Caller-owned (in-place clear)** — the value lives in storage the caller already owns: a sync `out: *mut T` slot, a `*const T` input parameter, an `out_item: *mut T` written by a stream's `next_fn`, or a field embedded in a larger value. The matching `_free` does `std::ptr::drop_in_place(value)` so nested allocations are released without trying to free the outer slot. Affected exports: `ovstorage_plugin_str_free`, `ovstorage_plugin_bytes_free`, `ovstorage_plugin_body_free`, `ovstorage_plugin_body_stream_free`, `ovstorage_plugin_backend_id_free`, `ovstorage_plugin_resolved_target_free`, `ovstorage_plugin_object_identity_free`, `ovstorage_plugin_backend_change_event_free`, `ovstorage_plugin_auth_event_free`, `ovstorage_plugin_storage_backend_kind_descriptor_free`, `ovstorage_plugin_connection_request_free`, `ovstorage_plugin_connection_free`. Calling these on a `Box::into_raw` pointer leaks the outer allocation but is otherwise sound; calling them on the same pointee twice is UB. Each export's Rust doc comment names which production path produced the pointer.

Plugin and manifest live in the same binary by construction; there is no separate file to drift, lose, or forge.

The manifest declares:

- the **plugin name** (used in route configuration to refer to this plugin instance type), and the **schemes** the plugin understands (e.g. `s3`, `s3+minio`; or `file`; or, for `broker-client`, no schemes — it works against any prefix the operator routes through it);
- plugin version, minimum library version, publisher, and build id.

Manifests do **not** declare URL prefixes — prefixes are an operator decision made at route-configuration time, not a property of the plugin. `broker-client` in particular has no idea what prefix it serves; it forwards whatever the operator routes through it. Conflict detection (two routes claiming overlapping prefixes) lives in the route loader, not the plugin loader.

Manifests are descriptive metadata, not a runtime trust gate. The loader logs each loaded plugin's manifest at INFO; supply-chain trust comes from whatever installed the `.so` (`apt`, `cargo`, an internal CI pipeline). Cryptographic signing of the binary, if an organization wants it, lives in that package manager. The trust model treats in-process plugins as fully trusted code (see "Plugin trust" below).

**The `Host` context.** The same plugin binary loads into the library (in-process) and the broker (long-running process). At load time the plugin receives a `Host` reference covering the small set of behaviors that legitimately differ between the two: where to read OAuth refresh tokens from, and whether the plugin's own configuration is admissible. A plugin can refuse to load when its config and host disagree: for example, the `file` plugin requires a `root_path` distinct from `/` when `host.is_broker == true` and returns a typed init error otherwise; the broker surfaces the plugin's own error message rather than carrying schema knowledge of every plugin. Plugins that need none of this never look at `Host`. Everything else — the `StorageBackend` SPI, capabilities, manifest, the redirect / stream return shapes — is identical in both hosts. A plugin returns `ReadResult::LocalDelegate` whenever bytes are on the host's local disk; in Brokered mode the broker silently promotes that to `ReadResult::Stream` at its own boundary by opening the file and streaming, since the path is meaningful only on the broker host. So each backend has one implementation, one conformance suite, and no `is_broker` branches in its `read` / `write` paths.

### Ownership and lifetime invariants

The ABI is designed so ownership is obvious even to a C plugin author:

- Manifest memory is static and immutable for the lifetime of the loaded binary. The host never frees it.
- Plugin, factory, backend, stream, future, `LocalDelegate`, and error handles are opaque. Whoever creates an owned handle also exports the destructor for that handle; the host calls the matching destructor exactly once. Borrowed handles are explicitly documented as borrowed and never survive the call that received them.
- No borrowed pointer, slice, string, header map, options struct, or callback reference may be retained after the vtable call returns unless the ABI field is explicitly an owned handle. Async methods therefore copy or retain owned handles before returning pending work to the host runtime.
- `StorageBackend` methods take `&self` semantically and may be called concurrently by the host. Plugins must protect non-thread-safe SDK clients, refresh-token state, multipart upload maps, and native handles internally. A plugin cannot rely on the host serializing calls except where an individual continuation token states that a sequence is single-use.
- `Capabilities` are immutable for the lifetime of a `StorageBackend` instance. If a backend's true behavior differs by bucket, namespace feature, principal, or route policy, the plugin reports the intersection for that instance and operators model the difference with separate backend instances / routes.
- `WriteStep::Redirects.state` is an opaque, plugin-owned continuation blob. The host echoes it byte-for-byte to `continue_write`, may persist it only for the lifetime of the in-flight operation, and must not inspect or log it. Plugins keep it bounded and non-secret; if a secret is needed to continue a write, the plugin keeps it in backend state and puts only an identifier in `state`.
- A `RedirectResponse` is owned by the host until passed into `continue_write`; after the call, the plugin owns any copied data it needs. Captured response bodies are bounded by `ResultCapture.body_max_bytes` before the plugin sees them.
- A `LocalDelegate` path is meaningful only on the host that received it from the plugin or cache. In Direct mode the library may expose it to `materialize`; in Brokered mode the broker consumes the path and streams bytes over the broker protocol. The plugin must not delete or mutate the delegated file while the lease is alive.
- Plugin unload is reverse-topology: all in-flight calls and returned streams/delegates must be dropped before backend destruction; all backends before factories; all factories before plugin-state destruction; plugin-state destruction before the shared library is closed.

### Failure semantics

Plugins translate backend failures into the shared error taxonomy and return promptly. Retry, backoff, circuit breaking, cache fallback, and user-visible policy are host responsibilities unless a backend protocol has an indivisible internal retry that is required for a single operation to complete safely. The observable contract is:

- Manifest / ABI mismatch fails before `ovstorage_plugin_init_v1`. No plugin code beyond manifest access is trusted after an incompatible ABI is detected.
- `ovstorage_plugin_init_v1` failures are plugin-load failures. `StorageBackendFactory::instantiate` failures are backend-instance / connection failures. `StorageBackendFactory::probe` failures mean the configured backend exists but is not currently usable with the supplied config or credentials. Hosts surface these at different API boundaries and should not collapse them into one generic "open failed" bucket.
- Unsupported operations return `Unsupported` and should be predictable from `Capabilities`. A host path that checked capabilities first should avoid calling unsupported SPI methods; conformance uses recorder assertions for this. A plugin may still return `Unsupported` defensively if called directly or if backend reality changed under it.
- Invalid caller input returns `InvalidArgument` before side effects. Object-operation authorization failures return the core `PermissionDenied` code; connection/probe failures that happen before an object operation also use `PermissionDenied` (when the IdP rejects credentials), `CredentialUnavailable` (when no credentials reach the plugin), `AuthRequired` (when interactive auth is needed), or `Internal` (when the plugin's own setup fails). `NotFound`, `AlreadyExists`, `ObjectModified`, `DirectoryNotEmpty`, `IncompatibleType`, `Locked`, `ContentChecksumMismatch`, `Transient`, and `Internal` retain their usual meanings from the [Error model](#error-model); plugins should prefer the narrowest typed error that preserves recovery semantics.

#### Publish-before-durable

`Ok(WriteResult { ... })` is a host-observable promise that the write is durable: a follow-up `stat` or `read` against the same address will see the new bytes, and the cache layer above will key on the returned address plus etag/version metadata. Plugins must therefore commit the durable side-effect before returning `Ok`. See [plugin-storage § Publish-before-durable](../../../docs/public/plugin-storage/README.md#publish-before-durable) for the patterns to watch for and the reference `write_atomic` shape.

#### Connection lifecycle errors

> The canonical reference for **Connection lifecycle errors** (the lifecycle-stage to `ErrorCode` mapping table) lives in [`docs/public/plugin-development/README.md` § Connection lifecycle errors](../../../docs/public/plugin-development/README.md#connection-lifecycle-errors).

### Address projection

For SPI calls that return object addresses, plugins return full
`ObjectInfo.address` values in the resolved backend namespace they
received. The library, which is the only component that knows about
routes, projects those addresses into the caller-facing namespace by
replacing the requested resolved prefix with the caller's prefix. A
`list("corp-prod://team/sub/")` can therefore return
`corp-prod://team/sub/foo`, `corp-prod://team/sub/bar/baz`, etc.,
regardless of how the plugin's config rewrites the prefix internally.

- **`list`** - each returned `ObjectInfo` carries the child address
  and metadata directly. The address must stay inside the requested
  resolved prefix; anything outside the scope is an `Internal`
  backend contract violation.
- **List-backed `stat`** - when a route sets
  `wants_list_backed_stat` and the host uses `StorageBackend::list`
  to satisfy an object `stat`, it reuses only returned `ObjectInfo`
  values whose `kind.is_file()`. Directory entries are not treated as
  cached folder stats because flat backends can create parent folders
  implicitly from child objects. Plugin notification handlers should
  dirty the whole parent listing for any child `Created`, `Modified`,
  `Deleted`, or `MetadataChanged` event instead of trying to patch the
  single cached item.
- **`list_versions`** - each returned `ObjectInfo.address` is the
  full backend-native version-pinned address for that version. The
  library projects the route prefix but does not synthesize or merge a
  separate version field. A `list_versions("corp-prod://team/sub/foo")`
  returns `corp-prod://team/sub/foo?versionId=abc`,
  `...?versionId=def`, and so on in caller space; if the caller's
  base address has other query parameters, the plugin's version-pinned
  address carries whatever complete query form the backend will serve.

  `list_versions` returns the object's full version history. The
  caller's base address selects the object whose history is
  enumerated; any version pin in the URL identifies an object, not a
  list filter. Callers probing a specific version use
  `stat(versioned_url)`; callers asking for the head use
  `get_latest_version`.
- **`watch_directory`** — each `BackendChangeEvent::Object` carries a
  full backend address under the watched resolved prefix. The library
  projects it to produce `ChangeEvent::Object.address`. `Lapsed`
  events have no address; they apply to the whole watch_directory
  stream.

`address_roots` and `watch_address_roots` are **not** differential. They return absolute `ObjectAddress`es, not route-prefix-relative fragments. This is the deliberate architectural exception: `list` is differential because the route's prefix is structurally part of the answer (the listing is *under* the route), but `address_roots` reports what the backend serves, which the backend already knows in absolute terms from its config. Plugins return whole URLs; the library never composes. The trivial case (most plugins, most of the time) is one address derived directly from the connection's config — an `s3` connection configured for `acme-prod` in `us-west-2` returns `[{ address: "s3://acme-prod/", ... }]`. The multi-address case is what makes the SPI worth having: an SFTP connection returns one entry per home directory the principal can see; an SCM connection returns one entry per accessible repo; **`broker-client` is the load-bearing case**, implementing `address_roots` by issuing `ListAddressRoots` upstream. Every address the broker decides to publish for the principal flows into the library's routing table through this SPI. In Brokered mode, `ctx.principal` carries the calling principal so plugins that gate this themselves (SFTP, SCM) answer per-principal; in Direct mode `ctx.principal` is `None`.

For I/O, the plugin receives the resolved URL (the route has already translated the caller's prefix into the plugin's URL space). Any version pin the caller put in the URL — whether they typed it themselves ([URL canonicalization](#url-canonicalization)) or got it back from `list_versions` — survives the route translation byte-for-byte: the library only rewrites the prefix, never the query string. The plugin parses the version pin out of the URL exactly the way it would parse a caller-typed versioned URL.

For cache keying, the plugin surfaces a `ResolvedTarget`: the canonical backend identity that lets two callers using different aliases for the same physical object share a cache entry. `ResolvedTarget` is internal and never reaches the application; address projection is how *application-visible* addresses make the round trip.

### Capability vocabulary

> The canonical reference for **Capability vocabulary** (the full bit list grouped by concurrency, metadata, write, naming, listing, address roots, versions, permissions, watches, redirect dispatch, and kind-level descriptor flags) lives in [`docs/public/plugin-development/README.md` § Capability vocabulary](../../../docs/public/plugin-development/README.md#capability-vocabulary).

### Object information from the backend

**The dividing line: ovstorage understands a value, or it doesn't.** Values ovstorage parses, validates, or compares against semantics live in typed fields on `ObjectInfo`. Values ovstorage merely shuttles between backend and application live in `SystemMetadata`, an opaque `String → String` map whose keys are plugin-chosen and whose semantics are entirely the backend's. Pushing "understood" values through a stringly-typed map would force every consumer to reimplement the parser; pushing "shuttled" values through typed fields would force an SPI struct change for every new vendor concept. The split keeps each kind on the side where its evolution is cheap.

**Typed fields on `ObjectInfo`** (in addition to `address`, `kind`, `etag`, `version`, `size`, and `mtime`):

- **`checksums: ChecksumSet`** — backend-supplied content hashes. The plugin populates one entry per algorithm the backend actually returned (S3 `sha256`, GCS `crc32c` and `md5`, Azure `md5`, `crc64nvme`, provider-specific tokens, and so on); an algorithm that's absent means "the backend didn't tell us." The algorithm tag is a normalized `ChecksumAlgorithm` string token, so plugins can add provider-native algorithms without an SPI enum bump, while callers still receive parsed bytes instead of reparsing base16/base64 strings on every read.

- **`effective_permissions: Option<EffectivePermissions>`** — what the calling principal is allowed to do against this specific object, when the backend can answer for free. `EffectivePermissions` is a `bitflags`-style set with `READ`, `WRITE`, `DELETE`, `UPDATE_METADATA`. **`None` and `Some(EffectivePermissions::empty())` mean different things:** `None` means the backend didn't tell us; `Some(empty)` means the backend told us this principal cannot perform any of these operations. Capability `populates_effective_permissions_on_stat` advertises whether the field is ever `Some` on this route.

  Operations excluded from the set are excluded for structural reasons. `stat` is excluded — a successful response to `stat` already proves the permission. `list` is excluded — it operates on a prefix, not on the object. `copy` / `rename` are excluded — they're two-address operations whose authorization can't be answered from a single `ObjectInfo`. `create_directory` / `delete_directory` are excluded for the same reason as `list`: directory operations are answered against the directory address, not an object inside it.

  Plugins populate the field when answering is free: the broker's policy engine already has the answer for the principal that just authorized this `stat`; the `file` plugin uses its filesystem-readonly approximation (`READ` for readonly entries, the full set for writable entries) and can grow richer POSIX / Windows ACL mapping behind the same field. Plugins that would have to make a separate authorization call to answer (S3 / GCS / Azure flat, where `HeadObject` doesn't tell you whether `DeleteObject` would be allowed) leave the field `None` rather than guessing or paying for an extra round trip.

  The field is read-only — it never appears in `update_metadata` or any precondition — and never participates in the etag. Pinning a read on "what I was allowed to do at the time" is not a coherent operation, and the type system enforces that by carrying the value outside the validator fields.

  *Forward compatibility:* `EffectivePermissions` is a `u32` bitset newtype; new flag bits may be added in later versions. Consumers ignore bits they don't recognize and treat them as "operation I don't know about, allowed" — never as "denied," because an old consumer doesn't know enough about a new operation to make any claim about it. The bitset is a hand-rolled `u32` newtype with `from_bits_truncate`; it is not marked `#[non_exhaustive]`. Adding a flag is a minor-version SPI change; reorganizing the type is a major-version one.

**Opaque values in `SystemMetadata`.** Everything backend-owned that ovstorage does not understand. Keys are plugin-chosen; ovstorage neither parses nor normalizes them. Two patterns dominate:

- **Vendor headers under their raw name** — `x-amz-server-side-encryption-aws-kms-key-id`, `x-ms-lease-state`, `x-goog-stored-content-encoding`, `x-amz-storage-class`. Each cloud picked its own prefix precisely so headers wouldn't collide, so no further normalization is needed. The prefix tells the caller at a glance that the value is opaque pass-through.
- **Vendor categorization facilities** — S3 Object Tags, Azure Blob Index Tags. Plugins surface these under whatever key shape the backend uses (e.g., `x-amz-tag-<name>`); read-only; writing tags through ovstorage is out of scope.

What's deliberately *not* in `SystemMetadata`: anything ovstorage parses (checksums) or compares against semantics (permissions), and anything that already has a typed home (size, mtime, etag, version). If ovstorage starts understanding a previously opaque concept — e.g., promoting `storage-class` to a typed `StorageClass` field — that key migrates from `SystemMetadata` to a typed field with a major-version SPI bump.

## Dependencies

In-workspace: none. `ovstorage-plugin` is the root of the workspace dependency graph and the canonical home for the Rust type vocabulary (`ObjectAddress`, `ObjectInfo`, `ObjectKind`, `IfDestExists`, `ResolvedTarget`, `Capabilities`, `SecretBytes`, the error taxonomy, options structs, connection / alias / auth types). [ovstorage](../ovstorage/README.md) re-exports those types so callers do not need to depend on this crate directly.

External (notable): `libloading` for dynamic-library probing, `cbindgen` (build-dep) for the C header, `tokio` / `tokio-util` for the cancellation token, `zeroize` for `SecretBytes`. The function-like macro `ovstorage_plugin!` lives in the sibling `ovstorage-plugin-macros` crate so the consumer dependency stays small. The C plugin header `ovstorage_plugin.h` is committed in-tree at `crates/ovstorage-plugin/include/ovstorage_plugin.h` and regenerated by `build.rs` on every build.

## Layering lint

The workspace ships a small CI lint at `tools/check-plugin-deps/` that walks every `crates/ovstorage-plugin-*/Cargo.toml` (excluding the ABI crates themselves — `ovstorage-plugin` and `ovstorage-plugin-macros`) and rejects any `ovstorage-`-prefixed key in `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, or any `[target.<cfg>.<table>]` permutation that is not in the matching allowlist. The lint binary at `tools/check-plugin-deps/src/main.rs` is also wired in as an integration test (`tools/check-plugin-deps/tests/workspace_lint.rs`) so `cargo test --workspace` catches layering regressions on every change.

Coverage is root-configured: `tools/check-plugin-deps/roots.toml` enumerates active first-party `crates/` directories using paths relative to the tool's `CARGO_MANIFEST_DIR`. The active root is the `ovstorage-core` crates directory. Each root entry may extend the base allowlist via `extra_dependencies`, `extra_dev_dependencies`, and `extra_build_dependencies` arrays, so a sibling workspace that legitimately needs an additional `ovstorage-*` key does not widen the core allowlist. The integration test asserts every root's visit set is non-empty, closing the silent-empty-scan gap that would otherwise let an accidentally narrowed scan pass green.

The base allowlist starts permissive enough to admit the existing workspace and tightens as plugins migrate. Final policy: `[dependencies]` may name `ovstorage-plugin` and any non-`ovstorage-*` crate, no other `ovstorage-*` crate may be a direct dependency, `[dev-dependencies]` may additionally name `ovstorage` for tests that drive the dispatcher, and `[build-dependencies]` admits no `ovstorage-*` keys at all unless a `roots.toml` entry grants them.

## Threat model

The plugin ABI is the trust seam between the host (library or broker) and the dynamically loaded `.so`. The host extends full process trust to whatever it loads — plugins can read credentials, follow OAuth flows, sign requests, and emit network traffic on the host's behalf. This is the same trust posture as a Rust crate dependency; it is not weakened by the C-ABI boundary, and it is not strengthened by the manifest. **Operators treat in-process plugins as trusted code, equivalent to their own application.**

Manifests are descriptive metadata, not a runtime trust gate. Supply-chain validation of the `.so` itself is the operator's package-manager problem (`apt`, `cargo`, an internal CI pipeline). Cryptographic signing of the binary, if an organization wants it, lives in that package manager — not in the plugin loader.

`SecretBytes` carries a "redacted in `Debug`" guarantee, descriptors flag every credential field with a `secret = true` marker, and the public API never returns plaintext secrets after `add_connection`. Applications that render `StorageBackendKindDescriptor` fields generically can rely on the `secret` marker to suppress display.

Panics across FFI are an integrity hazard. The workspace builds with `panic = "abort"` for both `dev` and `release`; that abort profile is the load-bearing FFI panic-safety mechanism — a panic terminates the process before any unwind reaches the C frame stack. The `catch_unwind` walls in `ovstorage_plugin::thunks` around per-method async dispatch are defense in depth for consumers that ever override the workspace profile to `panic = "unwind"`. The macro-generated `ovstorage_plugin_init_v1` export is intentionally not `catch_unwind`-wrapped — under the abort profile a constructor panic is a deliberate hard abort, and `catch_unwind` cannot intercept aborts. ASan / UBSan run in CI on the conformance harness.

## Conformance tests

The conformance surface the plugin ABI is responsible for:

**Capabilities**
- The conformance suite skips a test only if the relevant capability is absent; every skip cites the capability.
- Capability values are per backend instance and immutable for that instance's lifetime. Tests that need different capability sets create different backend instances.
- Host paths that can check capabilities before dispatch must do so; unsupported-call scenarios assert through the recorder that the plugin was not called.

**Surface boundary**
- Public `Storage` helper methods map onto the plugin SPI without changing the plugin ABI. For example, `read_bytes`, `read_stream`, and `materialize` all consume `StorageBackend::read` plus `ReadResult`; they are not separate plugin methods.
- `StorageBackendFactory` methods are management/configuration SPI and are tested separately from object I/O methods.
- `address_roots` / `watch_address_roots` are route-introspection SPI, not public listing methods.

**ABI and lifetimes**
- Manifest compatibility, vtable revision handshake, `struct_size` validation, opaque-handle destructor pairing, panic/exception containment, and borrowed-vs-owned buffer rules are tested against both a Rust macro-generated plugin and the hand-written C example.
- Concurrent `&self` calls into one backend instance are tested with overlapping `read`, `write`, `stat`, and `watch_directory` calls to catch accidental host-side serialization assumptions.
- Stream cancellation, dropped futures, dropped `LocalDelegate`s, and backend/plugin unload are tested so plugin state outlives all handles that can still call back into it.

**Permissions**
- `effective_permissions` field semantics: a plugin emitting `READ | WRITE | DELETE | UPDATE_METADATA`, just `READ`, or `EffectivePermissions::empty()` produces decisions consistent with set semantics; unknown bits set by a future-version plugin are tolerated; `None` and `Some(empty)` are distinct.
- `check_access` returns exactly the subset of requested ops the principal is allowed to perform; ops the caller didn't ask about don't appear; `Unsupported` from plugins without `supports_access_check` propagates without the library substituting a synthesized answer.

**Plugin kind isolation**
- The storage `StorageBackend` plugin ABI is what this crate exposes. Broker authn is broker-core configuration, and host authz uses the separate `ovstorage-authz` SPI shared between broker and REST. Authn conformance lives with the broker; authz conformance lives with the authz crate.

**Differentials**
- Listing differential: `list("corp-prod://team/sub/")` returns `corp-prod://team/sub/foo` regardless of the plugin's internal prefix rewrites; verified with a route whose `rewrite_to` differs from the caller-facing prefix.
- Versions differential: `list_versions(...?response-content-type=...)` returns URLs with `versionId` appended, preserving the existing query string byte-for-byte. The base URL identifies the object whose full version history is enumerated.
- `address_roots` is *not* differential: plugins return absolute `ObjectAddress`es; the library never composes.

**Connection management** (relevant to factory / descriptor surface)
- Schema round-trip: for every loaded factory, the library can render the descriptor, accept a config blob whose keys exactly match `config_schema`, and instantiate the backend. Mismatched keys (missing required fields or unknown keys) produce `InvalidArgument` with a message naming the offending key — the `ErrorCode` enum has no separate `MissingConfigField` / `InvalidConfig` variants.
- Probe success / failure: `probe` round-trips against working / unreachable / wrong-credential / nonexistent targets, surfacing the [Connection lifecycle errors](#connection-lifecycle-errors) `ErrorCode` mapping above.
- Credential rotation: a plugin returning `ReinstantiateRequired` from `update_credentials` triggers a transparent rebuild that preserves the `ConnectionId`.
- Secret hygiene: a test that `Debug`-formats a `Connection` or any RPC payload containing one finds `<redacted>` in place of every credential byte.
- Host-mode admissibility: a plugin can reject a configuration when `Host::is_broker` makes it unsafe or meaningless, and the host surfaces the plugin's typed error without learning plugin-specific schema.

**Watches** (gap-signaling contract the SPI imposes on every plugin)
- Gap signaling: a test plugin that drops events MUST emit `Lapsed` before resuming normal events. The harness drops events in-band and verifies the signal.
- Resume: for plugins with `watch_directory_resumable: true`, a `watch_directory` opened with `since: <recent cursor>` MUST replay events from that cursor and not start from "now."
- Polling fallback: when enabled, the plugin emits `Lapsed` if the previous polling cycle was longer ago than `watch_directory_max_lag * 2`, and otherwise emits one event per detected `Created` / `Modified` / `Deleted` since the previous cycle.

## Implementation notes

- The Rust `shim::Backend` and `shim::Factory` traits are the executable async SPI for first-party backends. Every I/O method takes `cancel: Option<CancellationToken>`.
- The C loader validates `ovstorage_plugin_manifest_v1` and `ovstorage_plugin_init_v1`; `BackendFactoryVTableV1` and `BackendVTableV1` carry their populated method slots and dispatch through the plugin tokio runtime via callback-shaped async slots.
- The `ovstorage_plugin!` macro emits the manifest/init symbols and threads the host's `HostCallbacks` into `shim::register_host` for the rest of the plugin's lifetime.
- ABI-drift CI between the Rust trait shape and the cbindgen-generated C header is a remaining burndown item; manual divergence should fail CI.
- Redirect types stay provider-neutral. `S3Multipart*` or cloud-specific branches do not appear in the host.

### Out of scope

- **Plugin hot-reload.** Loaded plugins live for the host process's lifetime. Replacing a plugin binary requires restarting the host (library, broker, or REST gateway).
- **Plugin sandboxing / seccomp.** In-process plugins run with the host's privileges. Operators who need plugin isolation deploy a per-host broker over UDS and route the relevant prefix through `broker-client` — the broker is the IPC + credential boundary in one.

## Async model

Async runs all the way down. `Library::init`/`shutdown` and trivial getters stay sync; every other I/O method on the public `Storage` API, the plugin SPI, and the C-ABI vtable is async with end-to-end cancellation where the path accepts a token. SPI cancellation is threaded through every method whose Rust trait signature carries `cancel: Option<CancellationToken>` — that's every `Backend` I/O method and every `Factory` lifecycle method on the storage SPI. Per-plugin cancellation gaps (e.g. nucleus's `subscribe_list` background pump that does not observe the host token) are documented in each plugin's README. Authz plugins receive cancellation only on `configure`; `authorize` / `filter_list_batch` use the host's outer RPC timeout instead because the Rust `AuthzPlugin` trait methods take no token.

### Foundations

- `tokio = { version = "1", features = ["fs", "io-util", "macros", "net", "rt-multi-thread", "signal", "sync", "time"] }` is pinned in workspace `Cargo.toml` across all four workspaces; every lockfile resolves the same `tokio = "1"` (currently 1.52.1). `cargo tree -d` surfaces drift if a transitive dep starts pulling a divergent line.
- `async-trait`, `tokio-util` (for `CancellationToken`, feature `rt`), `futures` (for the `Stream` trait), and `pin-project-lite` are workspace deps.
- All four workspaces use `edition = "2024"`. Three concrete payoffs: RPIT lifetime capture (async fns returning futures borrowing from `&self` or `&CancellationToken` work without ad-hoc `Captures<'_>` workarounds), tail-expression drop scope (catches the Mutex-across-await footgun mechanically — a `mutex.lock().await` guard accidentally held across a later `.await` because it was a tail expression compiles silently in 2021 but is rejected in 2024), and `unsafe extern` blocks (vtable `unsafe extern "C" fn` and `#[no_mangle]` exports must live in `unsafe extern { ... }` blocks with `unsafe(no_mangle)`, baking in safety hygiene).

### Plugin runtime substrate

Each plugin cdylib has one process-wide `OnceLock<Runtime>` in `ovstorage-plugin/src/thunks.rs::runtime()`, built with `Builder::new_multi_thread().worker_threads(1).enable_all()`. FFI thunks call `runtime().spawn(...)` and fire `on_complete` from the spawned task. Plugins do **not** build per-`Backend` runtimes.

`multi_thread(1)` is load-bearing. A `current_thread` Runtime restricts `block_on` to a single calling thread at a time and would deadlock under concurrent FFI calls from different host threads. `multi_thread` with one worker thread keeps the same one-thread budget while allowing concurrent `block_on` from multiple host threads (work serializes internally on the worker; host threads just block waiting). Each cdylib statically links its own copy of tokio, so each cdylib gets its own `multi_thread(1)` Runtime; the runtimes coexist and are isolated.

For a typical deployment with five cdylib plugins loaded (file, http, s3, gcs, broker-client):

| Component | Threads |
|---|---|
| C-API / `Library` runtime (`multi_thread`, 2 workers default) | 2 |
| Plugin: file (`multi_thread(1)`) | 1 |
| Plugin: http (`multi_thread(1)`) | 1 |
| Plugin: s3 (`multi_thread(1)`) | 1 |
| Plugin: gcs (`multi_thread(1)`) | 1 |
| Plugin: broker-client (`multi_thread(1)`) | 1 |
| tokio `spawn_blocking` pool (lazy, on-demand) | 0–N |
| **Total (idle)** | **~7** |

`library_init` accepts a `runtime_threads` field (default 2) so the host runtime is configurable. If a single plugin needs to drive heavy concurrent CPU work, it can `spawn_blocking` (uses tokio's shared blocking pool).

### Cancellation propagation

`CancellationToken` is a separate parameter on every I/O method, never a field on options. Re-exported from `tokio_util::sync::CancellationToken` via `ovstorage_plugin::CancellationToken`. Most callsites pass `None`.

The shared cancel-race helper is `ovstorage_plugin::race_cancel(cancel.as_ref(), fut)`, defined in `ovstorage-plugin/src/cancel.rs` and re-exported at the crate root. Plugins that observe cancellation explicitly call `race_cancel(cancel.as_ref(), inner_fut).await` on long ops to surface cancellation as `ErrorCode::Cancelled`. Use this instead of hand-rolling `tokio::select!`. `reqwest`'s async future-drop does most of the work transitively, so plugins that rely on connection teardown alone (azure, nucleus) work without explicit `race_cancel` wrapping — at the cost of cancellation latency on the cooperative-cancel path.

The FFI shape is `CancelTokenFFI`, a refcounted handle around `AtomicCancelState` (atomic flag + atomic refcount + mutex-protected callback list). Host-side, `cancel_token_to_ffi() -> CancelTokenHandle` spawns an auxiliary task that bridges `host_token.cancelled().await` into `state.cancel()`; the handle aborts the bridge on `Drop`. Plugin-side, `cancel_token_from_ffi() -> CancelTokenLocal` registers an FFI callback that wakes a fresh `CancellationToken` when the host signals; a `Drop` guard unregisters the callback and frees the `WakerData`. Both wrappers carry explicit `unsafe impl Send + Sync` because the `*const AtomicCancelState` raw pointer is `!Send` by default; the underlying state is fully thread-safe.

The bridge task in `cancel_token_to_ffi` owns its refcount via an RAII guard (`BridgeStateGuard(*const AtomicCancelState)` with `unsafe impl Send` and a `Drop` that calls `ffi_drop`) so refcount accounting balances under cancellation.

### Async core traits

Both `shim::Backend` and `shim::Factory` are `#[async_trait]` and every I/O method takes `cancel: Option<CancellationToken>`. The dynamic C ABI populates a heterogeneous vtable: synchronous slots (`drop` on the backend, `drop` + `descriptor` on the factory) return through out-pointers; every async I/O slot is callback-shaped — the host calls the vtable method, the thunk converts inputs synchronously, spawns the work on the plugin's tokio runtime, and fires `on_complete` exactly once when the spawned future settles. Capabilities ride on the `BackendInstance` value `Factory::instantiate` returns; there is no per-backend `capabilities` vtable slot.

The vtable shape (each I/O method follows this pattern):

```rust,ignore
pub struct BackendVTableV1 {
    pub struct_size: usize,
    pub drop: unsafe extern "C" fn(*mut OpaqueBackend),
    pub read: unsafe extern "C" fn(
        backend: *mut OpaqueBackend,
        target: *const ResolvedTargetFFI,
        opts: *const ReadOptionsFFI,
        cancel: *const CancelTokenFFI,                          // nullable
        on_complete: extern "C" fn(
            status: i32,
            result: *mut ReadResultFFI,    // null on error
            error: *mut ErrorFFI,          // null on success
            user_data: *mut c_void,
        ),
        user_data: *mut c_void,
    ),
    // ... write, stat, etc. follow the same shape
}
```

Host-side, each method has a per-method `oneshot::channel` plus a per-method `extern "C" fn` trampoline that boxes the sender as `user_data`, decodes status/result/error, and sends through. Memory rules: ownership transfers via callback (input pointers borrowed for the synchronous prologue only; output `result` and `error` pointers are `Box::into_raw`'d by the plugin and `Box::from_raw`'d by the trampoline).

Plugin thunks call `runtime().spawn(...)` and fire `on_complete` from the spawned task. `AssertUnwindSafe + catch_unwind` converts plugin panics to `ErrorCode::Internal` — defense in depth on top of the workspace's `panic = "abort"` profile.

`Factory` state is `Box<Arc<dyn Factory>>` so spawned tasks can take shared ownership while the outer `Box` keeps the canonical handle alive.

### Pointer-as-primary-signal protocol

`decode_async_result` branches on `error`/`result` pointer presence rather than the `status` integer. `ErrorCode::NotFound` has discriminant `0`, which collides with a naive "0 = success" convention. The `status` int remains for the C-API surface but is informational on the Rust side: `error == NULL` is success, `error != NULL` is failure.

Cancel/panic test coverage:

- Three cancel tests in `ovstorage-core/crates/ovstorage/tests/host_plugin_behaviors.rs` exercise the rlib path (cooperative cancel via plugin-test's `read_delay_ms` + `panic_on_read_key` knobs).
- One panic test in `ovstorage-core/crates/ovstorage-plugin-test/tests/loaded.rs` exercises the dlopen path and verifies the FFI thunk's `catch_unwind` actually fires.

Panic-surface-as-Internal only kicks in via FFI. The rlib-style `register_backend_factory(Arc<TestFactory>)` dispatches through `Arc<dyn Backend>` directly without going through the FFI thunk's `catch_unwind`; a panic in an rlib-registered backend propagates up the await chain and crashes the test thread. The dlopen path catches because the panic happens inside the cdylib's `runtime().spawn(...)` task.

### Plugin-by-plugin async shape

- **plugin-test** — synthetic in-memory plugin; async fn natively. `read` has a cancel-able delay knob raced against `cancel.cancelled()`.
- **plugin-file** — `tokio::fs::*` throughout; backend impl + helpers async; `write_atomic` takes a `WriteFill` enum; recursive list walk is iterative-async with an explicit `Vec<PathBuf>` stack (converting recursive walks to async would force `Box::pin` at every recursion edge or a dep on the `async-recursion` macro); watch-stream surface stays sync; cancel races on long ops via `race_cancel`.
- **plugin-http** — async `reqwest::Client` (process-wide `OnceLock`, 10 s timeout, connection pooling); cancel race on `stat`/`read` via `race_cancel`; retry backoff is `tokio::time::sleep`.
- **plugin-s3** — async `reqwest::Client`; `signed_request`, `head_object`, `put_object_inline`, `create_multipart_upload`, `complete_multipart_upload`, `upload_part_streamed`, `abort_multipart_upload`, `stream_write` all async. `stream_write` is implemented as an associated `async fn commit_streaming_part`. Cancel races on every `Backend` method that issues HTTP.
- **plugin-gcs** — async `reqwest::Client`; the `Authenticator` and the lib helpers (`send`, `decode_json`, `decode_object`, `ensure_success`, `bearer_token`, `fetch_object`, `download_bytes`, `write_inline_media`, `update_metadata_after_inline`, `initiate_resumable_redirect`, `stream_resumable_upload`, `put_marker`, `delete_subtree`, `rewrite_object`) are all async; cancel races on every `Backend` method that hits HTTP.
- **plugin-azure** — async `reqwest::Client`. Explicit `race_cancel` wrapping is a known gap — `reqwest` future-drop already tears down in-flight requests; per-method cancellation observation is the missing piece.
- **plugin-opendal** — runs entirely on `thunks::runtime()`; `Operator` futures are `.await`'d directly. `open_operator` and `preflight_write` are async fns.
- **plugin-nucleus** — async-native. No `block_on` outside the sync-stream `WatchIter` bridge. The bridge keeps a dedicated `std::thread` plus a fresh `Runtime::new` because `tokio::spawn` deadlocks single-thread test runtimes (consumer blocks the only worker; rationale documented inline).
- **plugin-broker-client** — `TonicBrokerClient` has no `Runtime` field; the only remaining `block_on` is inside the watch-stream bridge, the deferred sync-`Iterator` FFI surface. Same trade-off as plugin-nucleus.

Watch-stream producers stay on `std::thread::spawn` plus a dedicated `Runtime::new` until the watch surface goes async. `tokio::spawn` for watch-stream producers deadlocks single-thread test runtimes: the consumer thread blocks on `mpsc::Recv`, but the producer needs a runtime worker to make progress, and a `current_thread` test runtime has only one. The rule applies even though "the plugin is already on `thunks::runtime()`," because the test path uses the test's runtime, not the plugin's.

### Streaming-FFI status

`Body::Stream` (writes) and `BackendChangeStream` / `BackendAddressRootsStream` / `AuthEventStream` (reads, watches, auth) remain sync `Iterator`s, returned from inside `async fn`. Converting them to `futures::Stream` requires a callback-shaped FFI vtable for chunk pull and is a deferred follow-up; per-chunk callbacks risk allocation explosion across FFI and the design needs care. Per-chunk cancellation observation works today by polling the originating `CancelTokenFFI`'s `is_canceled` between chunks.

The host's bridge from sync iterator to async stream is `redirect.rs::body_stream_to_async`: it offloads each chunk pull to `tokio::task::spawn_blocking` and emits a `futures::Stream<Item = std::io::Result<Vec<u8>>>` that `reqwest::Body::wrap_stream` accepts. This is the canonical sync-iterator → async-stream pattern; reuse it if the watch surface ever needs a similar bridge. Splitting iterator state across `spawn_blocking` calls needs `(state, value)` returns: `spawn_blocking(move || (iter.next(), iter)).await` returns `(Option<Item>, Iter)`; rebind the iter and loop. Used in `read_n_from_stream` and `execute_file_streaming_request`. Single-shot consumption (drain everything inside one task) doesn't need this — only resumable pull-loops do.

### Read-bridge thread model

`shim/payload.rs::read_result_from_ffi` (Stream variant) spawns one
`std::thread::spawn` per active streaming read to drain the sync FFI
iterator and forward chunks into an async channel. The thread lives
for the duration of the stream.

The choice of `std::thread::spawn` over `spawn_blocking` is forced:
the FFI `on_read` callback is invoked by whichever thread the plugin
chose to fire it on (a broker-client gRPC response handler running on
its own pool is one real example), and that thread carries no tokio
runtime context. `spawn_blocking` panics from a non-tokio thread.

One thread per active stream is bounded by traffic, not by code
structure — the "N subsystems × M thread pools" antipattern doesn't
apply because there's a single purpose and the count equals concurrent
streams. Bridge threads spend ≥99% of wall time blocked on the FFI
iterator, so they cost almost nothing in CPU. The streaming *write*
path used to have a similar bridge thread; that one was eliminated by
switching to `async_channel` (the producer is async and the plugin's
existing worker thread serves as the natural sync consumer).

A bounded thread pool would cap concurrent streams at the pool size,
which is strictly worse than the unbounded case for a storage gateway
whose primary workload is streaming. The long-term fix, if production
load makes thread count load-bearing, is a push-model FFI SPI where
the plugin pushes chunks into a host-supplied `ChunkSender` instead of
the host pulling. That's an SPI-wide change touching every backend
plus careful cancellation semantics; defer until real numbers demand
it, and add a bridge-thread-count metric first.

### Plugin-author rules

Constraints worth memorizing before writing or modifying plugin code:

- **`tokio::task::spawn_blocking` is not a runtime-context escape hatch.** Its worker threads inherit the calling runtime context. Two patterns break specifically because of this: (1) `reqwest::blocking::Client::builder().build()` builds and drops a temporary `Runtime` synchronously, so the drop trips on any active tokio context — panicking with "Cannot drop a runtime in a context where blocking is not allowed"; (2) the plugin FFI thunks in `ovstorage-plugin/src/thunks.rs` drive the async `Backend` trait through a process-wide `runtime().block_on(...)`, and a nested `block_on` from a host that's already inside a tokio context panics with "Cannot start a runtime from within a runtime." When you need that escape, use `std::thread::spawn` plus `tokio::sync::oneshot` (see `run_ffi` in `crates/ovstorage/src/loaded_backend.rs` for the canonical pattern). The same applies inside host-side FFI callbacks (`on_read`, `on_write` in `loaded_backend.rs`): there is no contract that the plugin's invoking thread carries a tokio context, so `spawn_blocking` panics with "no current Runtime" there too. `spawn_blocking` remains fine for plain CPU/IO work that doesn't touch tokio internals.
- **`tracing::info_span!(...).entered()` makes async fns `!Send`.** The returned `Entered<'_>` guard contains a `*mut ()` thread-local pointer. Re-introduce instrumentation via `Instrument::instrument(span)` on the future or `#[tracing::instrument]` on the fn — never `.entered()` across an `.await`.
- **`parking_lot` guards are `!Send`.** Snapshot data inside the lock scope, drop the guard, then await. parking_lot locks also never poison; `lock_routes()` etc. return the guard directly with no `Result`.
- **`&Body` cannot live across an `.await`.** `Body::Stream(BodyStream)` wraps `Box<dyn Iterator<Item = Result<Vec<u8>>> + Send>` — no `Sync`. So `&Body` is `!Send`, and any async fn that takes `&Body` and `.await`s in its body produces a `!Send` future. Inline the small bit of logic that needs the body kind, taking ownership of just what crosses the await.
- **Cache stampede protection downgrades cleanly across `.await`.** The library's previous `cache.with_herd_lock(key, || backend.read(...))` pattern held an in-process `Mutex<()>` plus a file lock across the closure; the closure becoming a future means the lock would span `.await`. The current shape is lookup → await → insert; multiple concurrent reads of the same key may race to the backend, but cache inserts are idempotent, so the race is acceptable. Proper async stampede protection (likely `tokio::sync::Mutex` keyed inside `ovstorage-cache`) is a known gap.
- **Iterative directory walks beat async recursion.** An explicit `Vec<PathBuf>` work-stack avoids the `Box::pin` + `async-recursion` overhead at every recursion edge and is equivalent in practice.
- **`std::env::set_var` is unsafe in 2024.** The only call site is `ovstorage-broker-protocol/build.rs` (build-script context, single-threaded, safe to mutate process env); wrap it in `unsafe { ... }`.
- **Narrow `unsafe { }` blocks.** `unsafe fn` bodies are not wrapped wholesale in `{ unsafe { ... } }`; that would defeat the `unsafe_op_in_unsafe_fn` lint. Wrap individual unsafe operations (deref, FFI calls, `Box::from_raw`), not the whole body.
- **Plugin SPI substrate is process-global.** Call `ovstorage::init_auth_substrate(Some(&auth_dir))` once per process before any `Library::builder().open()`; it registers `SecretStore` + `AuthRefreshLock` into a once-per-process slot. A second init call with a different substrate fails with `Unsupported`. In-process tests share one `Library` via `OnceLock`; tests that need their own substrate live in `tests/<name>.rs` integration binaries.

## Risks

### Plugin C ABI vtable stability at 1.0

**Status:** defensive-depth

**Concern.** Every plugin in the ecosystem links against the `BackendVTableV1` / `BackendFactoryVTableV1` vtables (returned via `BackendPluginInitResultV1.factory_vtable`). Once 1.0 ships, every function-pointer slot, every callback signature, and every options struct on every method is a forever commitment — a breaking change orphans every existing plugin and forces the entire ecosystem to a 2.0 binary boundary.

**Why this mitigation is sound.** The vtable is conservative by construction: top-level shapes (`PluginManifestV1`, `BackendPluginInitResultV1`, `BackendVTableV1`, `BackendFactoryVTableV1`, `HostCallbacks`) all carry a `struct_size: usize` prefix and the host validates `>= expected` so additive growth is layout-safe ([ovstorage-capi § C ABI stability](../ovstorage-capi/README.md#c-abi-stability-at-10)); `ovstorage_plugin_manifest_v1` exports the same `OVSTORAGE_PLUGIN_ABI_VERSION` constant the host expects, and the host refuses to load on mismatch. The function-like `ovstorage_plugin!` macro insulates Rust plugin authors from the C-level details by emitting the manifest, init function, and vtable wiring at compile time from a Rust `Factory` constructor — Rust authors write idiomatic Rust, the macro generates the `extern "C"` shims, and the macro itself is the unit of versioning that absorbs breaking changes when the project bumps a Rust-side type. 0.x burn-in lets the project cycle through real plugin authors before the freeze.

**In place today.** `BackendVTableV1` and `BackendFactoryVTableV1` both end with `_reserved: [Option<unsafe extern "C" fn(*mut c_void) -> *mut Error>; 16]` zero-initialized slots, and `BackendPluginInitResultV1` carries the banded handshake fields (`abi_version`, `min_supported_abi_version`, `max_supported_abi_version`) which the loader checks via `validate_init_result_header_banded`. Both defenses ship in 0.x.

**Not yet in place** (see Implementor checklist below): the ABI-drift CI gate that diffs the cbindgen-emitted header against a checked-in golden file, the loaded-plugin conformance scenario for `abi-struct-size-rejection`, and the ASan/UBSan jobs running the conformance suite against `examples/plugin-c/`. These are tracked work items, not properties the current 0.x implementation claims.

**Alternatives considered and rejected.**

- **Single-version vtable, no negotiation.** Forces every host-plugin pair to be exactly compatible; breaks rolling deployments where a host upgrade and plugin upgrade ship at different cadences.
- **Trait-object ABI (Rust-only).** Locks out C/C++/Zig/Go plugins; the project explicitly supports cross-language plugins.
- **Per-method dynamic dispatch (no vtable, lookup by name).** Adds 50–100ns per call (string hash + lookup); the project's hot-path latency budget is too tight for that on every SPI invocation.

**What this mitigation does NOT cover.**

- A plugin author who manually authors the vtable in C and gets the layout wrong: the version handshake catches mismatched `vtable_revision`, but a plugin that lies about its revision is undetectable. Mitigation: the project recommends the proc macro for Rust and conformance-test-validates C plugins via the example in `examples/plugin-c/`.
- Removing or weakening a method's contract within a single revision: the vtable layout is preserved but semantics aren't; a 0.x→0.x release that tightens a precondition can break plugins. Mitigation: 0.x release notes call out semantic changes; 1.0 freeze forbids them.

**Implementor checklist.**

- `BackendVTableV1` and `BackendFactoryVTableV1` defined in `crates/ovstorage-plugin/src/ffi/host_vtable.rs`; cbindgen emits them into `ovstorage_plugin.h` on build. Layout reviewed by at least two maintainers before any change to slot order or signature.
- Both vtables end with `_reserved: [Option<VTableReservedFn>; 16]` (16 zero-initialized fn-pointer slots). New SPI methods consume the next free reserved slot; never reorder existing fields, never change signatures.
- The manifest's banded-handshake fields (`abi_version` + `min_supported_abi_version` + `max_supported_abi_version`) let the host load plugins from any ABI version in the advertised band; pre-1.0 plugins set `min == max == OVSTORAGE_PLUGIN_ABI_VERSION` (see "Verification" below).
- `ovstorage_plugin!` function-like macro lives in `ovstorage-plugin-macros`; emits the manifest static, the init `extern "C"` function, and the FACTORY_VTABLE wiring. Rust plugin authors never see the C surface. (An attribute-macro form `#[ovstorage_plugin]` does not exist; the function-like form is the only spelling.)
- Every per-method options struct in `ffi/options.rs` (12 of them — `StatOptions`, `ReadOptions`, `WriteOptions`, `DeleteOptions`, `ListOptions`, `ListVersionsOptions`, `CreateDirectoryOptions`, `DeleteDirectoryOptions`, `CopyOptions`, `RenameOptions`, `UpdateMetadataOptions`, `WatchDirectoryOptions`) carries a leading `struct_size: usize` prefix matching the top-level vtables. New fields append before any growth tail; never reorder.
- ASan + UBSan jobs run the conformance suite against `examples/plugin-c/` (the manually-authored C plugin). Panic safety is rooted in the workspace's `panic = "abort"` profile (see `ovstorage-core/Cargo.toml`); the `catch_unwind` walls inside `ovstorage_plugin::thunks` are defense-in-depth for callers that override the profile, and the macro-generated `ovstorage_plugin_init_v1` is intentionally NOT `catch_unwind`-wrapped (a panic in init aborts the loading process under the abort profile, which is the desired failure mode).

**Verification.**

- `header_verification.rs` (in `crates/ovstorage-plugin/tests/`) parses `ovstorage_plugin.h`, asserts the `OvStoragePlugin_` / `ovstorage_plugin_` naming contract, and (when `cc` is on PATH) compiles `examples/plugin-c/example_plugin.c` against the generated header. `macro_plugin.rs` drives the `ovstorage_plugin!` macro end-to-end in-process: validates the manifest static, runs `ovstorage_plugin_init_v1`, and dispatches `descriptor` + `probe` through the factory vtable.
- **Banded ABI handshake.** `BackendPluginInitResultV1` carries `abi_version`, `min_supported_abi_version`, and `max_supported_abi_version`. The host validates `min <= host.abi_version <= max` via `validate_init_result_header_banded`; out-of-band plugins are rejected with `IncompatibleType` plus a diagnostic that names both the band and the host's `OVSTORAGE_PLUGIN_ABI_VERSION`. Plugins that pre-date the banded fields (zero-init `min` / `max`) fall back to single-version equality on `abi_version`.
- `ffi::validate_struct_size::<T>(declared, label)` rejects an undersized options struct with `InvalidArgument` before any tail field is read. The check is applied uniformly across **every** `*_options_from_ffi` converter — including `stat_options_from_ffi` and `create_directory_options_from_ffi`. `struct_size == 0` is **also rejected** because the converters read tail fields unconditionally; accepting `0` would force them to read uninitialised memory (the "use library defaults" contract is honoured only at the higher-level C-API entry points, which materialise a fully-initialised options struct before crossing the SPI). Unit tests in `ovstorage-plugin/src/ffi/options.rs` and `ovstorage-plugin/src/shim/tests.rs` pin the contract. The matching loaded-plugin conformance scenario (`abi-struct-size-rejection`) is not yet in place; the in-process shim is the only path that exercises the rejection assertion.
- The CI gate `plugin-abi-drift-check` (required check on every PR touching `ovstorage-plugin`; diff of `ovstorage_plugin.h` against a checked-in golden file) is not yet in place.
- The SPI is marked unstable; `examples/plugin-rust/` and `examples/plugin-c/` are the reference plugins. The 1.0 freeze burns the surface in.

### Async substrate risks

**Status:** defensive-depth

These are async-shaped risks the substrate has to keep watch on:

- **Cancellation under race.** `cancel_token_cancel` while a callback is mid-flight must be safe. Today's design uses an `Arc<OpState>` refcounted between trampoline and submitter; the trampoline drops its handle in the callback, the bridge task in `cancel_token_to_ffi` owns its refcount via `BridgeStateGuard`, and `CancelTokenLocal::Drop` unregisters the FFI callback before freeing `WakerData`. Cancel/panic test coverage is described above under "Async core traits."
- **Cross-FFI streaming complexity.** `Body::Stream` async pull across FFI is the trickiest piece left. The current shape keeps the stream handle as a sync `Iterator` and bridges with `spawn_blocking`; a callback-shaped async pull (`ovstorage_read_stream_next(stream_handle, callback, ...)`) is one alternative model that gives tighter control but risks per-chunk allocation. The design has not been picked.
- **tokio version drift across cdylibs.** The workspace pin must stay tight. If a plugin pulls a different tokio via a transitive dep, runtime types diverge silently — `cargo tree -d` is the surfacing tool.
