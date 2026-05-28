# library-rust — agent routing

Terse map for agents working on Rust callers of `ovstorage::Library`.
For prose, see [README.md](README.md).

## Entry points

- `Library::builder() -> LibraryBuilder` — chained builder.
- `ovstorage::init_auth_substrate(Some(auth_dir))` — optional explicit
  pin for the process-global auth substrate before the first
  `Library::builder().open()` / `Library::open(None)`. `open()` with no
  prior init auto-initializes a default substrate.
- `Library::load_plugin(path)` / `load_plugins_from_dir(dir)` — both
  `unsafe`; load only trusted cdylibs after opening the library.
- `ovstorage::default_plugin_dir() -> Option<PathBuf>` —
  `$OVSTORAGE_PLUGIN_DIR` if set, else `<exe-dir>/plugins/`. Use this in
  examples and starter code; there is no `Library::open_default()` today.
- `LibraryBuilder::open() -> Result<Arc<Library>>` — ownership boundary;
  validates routes, sorts longest-prefix-first, initializes the default
  auth substrate if needed, and returns the dispatcher.
- After open, register backends with
  `Storage::add_connection(ConnectionRequest, cancel)`.

## Important traits

- `ovstorage::Storage` — the address-routed operation surface. `#[async_trait]`;
  byte-moving methods take a final `cancel: Option<&CancellationToken>`.
  Implemented by `Library`. Test doubles can implement it directly.
- `ovstorage::OAuthFlow` (re-exported from `ovstorage::auth`) — the host-side
  PKCE / device-code driver. Plugins request a flow; the host runs it. Most
  application code does not touch this; UIs that surface auth events do.

## Routing

- The dispatcher routes by `ObjectAddress` (`url::Url` under the hood) using
  longest-prefix-first match against the merged routing table (static
  rows + connection-contributed rows + alias rows). "Longest-prefix-first"
  means among all routes whose prefix matches the request, the one with
  the most-specific (longest) prefix wins — so a route at
  `s3://bucket/team/` always shadows a route at `s3://bucket/`. All
  address handling uses `ovstorage_plugin::address::*` helpers (`parse`,
  `key`, `join_relative`, `to_directory`, …); the library never composes
  URLs. See [README § Routing-table types](README.md#routing-table-types).

## Streaming reads

- `read_bytes` for objects you know fit in memory.
- `read_stream` for large objects — returns
  `(impl Stream<Item = Result<bytes::Bytes>>, ObjectInfo)`. Drive it with
  `StreamExt::next().await`; peak memory is chunk-size × producer mpsc
  capacity, never object size.
- `materialize` returns a `LocalDelegate` whose lifetime pins the
  cached file against GC.
- `read_raw` returns the unfollowed `ReadResult` (`Bytes` / `Stream` /
  `LocalDelegate` / `Redirect`) without consulting the byte cache. The
  REST gateway uses it to forward the variant verbatim to HTTP clients;
  application code rarely needs it.

## Streaming writes

- `Body::Bytes(Vec<u8>)`, `Body::LocalFile(PathBuf)`, `Body::Stream(BodyStream)`.
- `Body::Stream` propagates chunk-by-chunk through the dispatcher,
  redirect follower, and plugin SPI. Do **not** drain a stream to
  `Vec<u8>` at any seam — it is a memory-DoS antipattern on the public
  REST gateway. Stream-bodied writes are limited to single-stage
  multipart flows; a second redirect round on a consumed stream surfaces
  `Unsupported`.

## Cancellation

- Every byte-moving `Storage` method takes a final
  `cancel: Option<&CancellationToken>`. `tokio_util::sync::CancellationToken`
  is the type; the dispatcher threads it down through the `StorageBackend`
  SPI.
- Pass `None` only when the caller really wants no cancellation handle. In
  any non-trivial path (servers, GUIs, long-running tasks), thread one
  through and call `token.cancel()` on shutdown.
- Group-cancel ("abort everything for principal X") requires a broker and
  is not available in Direct mode.

## Errors and etags

- `ovstorage_plugin::Error` carries an `ErrorCode` from a closed taxonomy
  (`NotFound`, `PreconditionFailed`, `Unsupported`, `PermissionDenied`,
  `Transient`, `BrokerUnavailable`, `ResourceExhausted`, …). Match on
  `error.code()`.
- Idempotent calls plus HTTP redirects retry on `Transient`,
  `BrokerUnavailable`, `ResourceExhausted` per `LibraryBuilder::with_retry`
  / per-route TOML knobs. Defaults (`RetryConfig::default()` in
  `ovstorage-core/crates/ovstorage/src/retry.rs`): `initial_delay_ms =
  100`, `max_delay_ms = 30_000`, `max_attempts = 5`. The curve is
  exponential — each delay doubles the previous one, capped at
  `max_delay_ms`. Full jitter (uniform-random in `[0, computed_delay)`)
  is applied so concurrent retriers desynchronize. HTTP-shaped retries
  (`with_http_retry_async`) honor a server-supplied `Retry-After` over
  the calculated delay. `RetryConfig::NONE` disables retry
  (`max_attempts = 1`).
- For consistent read/modify/write, capture `ObjectInfo.etag` and
  pass it back as `if_match` / `if_source` / `if_dest` on the next
  call. Version selection lives in version-pinned addresses, not in
  precondition fields.

## What lives elsewhere

- Plugin-author SPI (`StorageBackend`, `StorageBackendFactory`,
  `Capabilities`, `ReadResult`, `WriteStep`, the C-ABI handshake) is in
  [plugin-development README](../plugin-development/README.md). If
  you're writing a plugin, you're a different persona — see
  [plugin-storage README](../plugin-storage/README.md) instead.
- Broker operator concerns (TOML, authn, authz, lifecycle) are out of
  scope for this repo. Direct-mode callers don't configure those.
