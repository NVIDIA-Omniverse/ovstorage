# Plugin author: storage backend

> "I'm building a storage plugin for ovstorage — I implement
> `Factory` + `Backend` (the Rust traits in `ovstorage_plugin::shim`,
> sometimes referred to in prose as `StorageBackendFactory` /
> `StorageBackend`), wire them through `ovstorage_plugin!`, ship a
> cdylib, and the host loads me at runtime."

You're writing a new backend. The in-repo storage references are
`file`, `http`, `omniverse-storage-service`, `s3`, `gcs`,
`azure`, `opendal`, `nucleus`, `broker` (broker-client), and the
test-only conformance plugin.
This page covers the storage-specific surface; the shared substrate
(C ABI, Rust shim, conformance harness, build-and-test loop, ABI
stability, full SPI vocabulary) lives in
[`../plugin-development/README.md`](../plugin-development/README.md).
Read that first.

## Storage SPI shape

Two `#[async_trait]` traits in `ovstorage_plugin::shim`, both with
`cancel: Option<CancellationToken>` on every I/O method. The Rust
trait names are `Factory` and `Backend`; persona docs and review
material occasionally call them `StorageBackendFactory` and
`StorageBackend` to disambiguate from the broader "factory" /
"backend" prose — those longer names are documentation-only
synonyms, not separate types.

- **`Factory`** — one per backend *kind*. Owns the descriptor;
  instantiates a backend; accepts credential rotation; drives
  interactive auth events. `Factory::instantiate` returns a
  `BackendInstance { backend_id, backend: Arc<dyn Backend>,
  address_roots, display_name, auth_state }` — the
  `address_roots` carry per-root capabilities the host stamps onto
  matching routes.
- **`Backend`** — one per configured connection. Owns clients and
  per-instance config. Object I/O the host dispatches after routing:
  `stat`, `read`, `write` / `write_stream` / `write_redirect` /
  `continue_write`, `delete`, `list`, `list_versions`,
  `watch_directory`, directory ops, `copy`, `rename`,
  `update_metadata`, `check_access`, `address_roots` /
  `watch_address_roots`.

Source of truth for method list, signatures, `list`
recursive-vs-one-level shape, redirect dispatch state machine, and
the `watch_directory` `Lapsed` contract:
[`../plugin-development/README.md` § Plugin SPI](../plugin-development/README.md#plugin-spi).

A method you don't implement returns `Unsupported` (the trait
defaults already do that). Pair every "I implement this" with the
matching capability bit so the host never dispatches a call the
plugin can't honor.

## Capabilities: get this right

`Capabilities` is the host's contract with the *caller* about what
the route can do. Callers gate UX on these bits; mis-advertising
them produces errors that look like backend bugs. Full vocabulary +
method-to-bit correspondence in
[`../plugin-development/README.md` § Capability vocabulary](../plugin-development/README.md#capability-vocabulary).
The bit name a plugin sets to advertise versioning is
`Capabilities::supports_if_match_write`. High-leverage groups:
**concurrency** (`supports_if_match_write`,
`supports_no_overwrite_write`), **write** (`writes_are_atomic`,
`supports_server_side_copy`, `redirect_size_threshold`),
**naming** (`supports_server_side_rename`,
`supports_atomic_rename`, `has_real_directories`), **listing**
(`supports_list`, `supports_recursive_list`,
`wants_list_backed_stat`, `populates_subdirectory_metadata`),
**address roots** (`address_roots_are_dynamic`), **versions**
(`supports_version_listing`, `version_list_order`), **permissions**
(`populates_effective_permissions_on_stat`, `supports_access_check`),
**watches** (`supports_watch_directory`, `watch_directory_kinds`,
`watch_directory_resumable`, `watch_directory_max_lag`).

`StorageBackendKindDescriptor.capabilities` (returned by
`Factory::descriptor()`) is the kind-wide declaration the host
renders into Add Connection forms. `BackendInstance.capabilities`
(returned by `Factory::instantiate(...)`) is the per-connection
authoritative value the host snapshots and gates dispatch on.
Per-instance capabilities can downgrade from the descriptor's
defaults (for example, a backend instance may reflect a configured
driver's caps), but must remain immutable for the instance's
lifetime.

## Manifest, descriptor, and connection lifecycle

- **Manifest** — cdylib-level `PluginManifestV1`:
  `struct_size: usize`, `abi_version: u32`, `name` and `version`
  (NUL-terminated, fed from `CARGO_PKG_NAME` / `CARGO_PKG_VERSION`
  by the `ovstorage_plugin!` macro), `test_only: bool` (production
  hosts refuse to load `test_only` plugins). The manifest does
  **not** carry a `plugin_kind` field; storage vs. authz is
  disambiguated by cdylib filename prefix
  (`libovstorage_plugin_*` vs `libovstorage_authz_*`) and by the
  symbols the loader resolves.
- **`StorageBackendKindDescriptor`** — returned synchronously by
  `Factory::descriptor()`. Carries `kind` (the URL scheme prefix),
  `display_name`, `description`, `config_schema: Vec<ConfigField>`,
  `credential_schema: Vec<CredentialField>`, `capabilities`,
  optional `icon`, and `supports_runtime_add`. Generic UIs render
  the descriptor to build "Add Connection" forms; the host
  validates incoming config / credential blobs against it. (No
  `name` / `schemes` / `plugin_kind` fields — those names appear in
  informal prose only, not in the struct.)

Required `ConfigField`s ship with defaults; descriptors evolve
additively by convention. The per-kind descriptor-version handshake
is the `struct_size` validation on `StorageBackendKindDescriptor`
plus the `abi_version` band carried in
`BackendPluginInitResultV1`: an undersized descriptor is rejected
with `InvalidArgument` before any field past the known minimum is
read, and an out-of-band `abi_version` is rejected with
`IncompatibleType` at load time. Adding a non-defaulted required
field is a breaking change and a 2.0.

Every credential field is flagged `secret = true`; `SecretBytes` is
"redacted in `Debug`"; the public API never returns plaintext
secrets after `add_connection`. A descriptor-driven UI that
respects the `secret` marker has nothing to leak; one that doesn't
can render the schema but receives only redacted values from the
runtime.

Connection lifecycle errors map onto the typed `ErrorCode` set in
[`../plugin-development/README.md` § Connection lifecycle errors](../plugin-development/README.md#connection-lifecycle-errors).
Don't invent new variants.

## Streaming reads and writes: forward, don't drain

`Body::Stream` (writes) and the read stream shape both flow
chunk-by-chunk. **Never** drain into a `Vec<u8>` and ship the buffer
— that's a memory-DoS vector at the public REST gateway and the
single most common plugin bug. Wire each chunk into the backend
transport as it arrives: HTTP-shaped backends use
`reqwest::Body::wrap_stream` (mirror the host's
`redirect.rs::body_stream_to_async` bridge); native-SDK backends use
the SDK's chunked-upload entry point. Don't fall back to
"buffer then upload" — opt out of `write_stream` by leaving the
trait default (returns `Unsupported`) and the host routes to
`write` (small, in-memory) or `write_redirect` (out-of-band)
instead.

Add a `streaming_invariant` test at
`<your-plugin-crate>/tests/streaming_invariant.rs` using
`ovstorage_plugin_test::streaming::assert_streaming_invariants`
(drives ≥3 chunks totaling ≥64 MiB at 4 MiB; asserts bounded
in-flight bytes, preserved chunk count, in-order arrival). Seam
inventory:
[`../plugin-development/README.md` § Streaming seams](../plugin-development/README.md#streaming-seams).

## Publish-before-durable

When a write succeeds, **the durable side-effect (object on disk,
blob in S3, row in your store) must commit before any in-memory or
cached state advances**. The host treats `Ok(WriteResult { ... })`
as "persistent and visible to subsequent reads" — if your plugin
returns `Ok` with the bytes still in flight to the backend, a
follow-up `stat`/`read` against the same address will see stale or
missing data and the cache layer above will key on a not-yet-durable
etag/version.

Watch for these patterns:
- Acquiring a per-target lock and immediately calling `.send()` /
  `tokio::fs::write` / a network upload, then releasing the lock
  before the upload's async completion is awaited.
- An existence check (`try_exists`, `SELECT 1`) gating a non-atomic
  mutation (`tokio::fs::write` to the final path).
- A backend SDK that returns from `upload()` before the underlying
  PUT has been acknowledged by the remote; await the explicit
  durability handle (e.g. multipart `complete`, `flush`, `fsync`).

Restructure so the durable step runs first and gates the in-memory
advance. The reference pattern is
`ovstorage-plugin-file::write_atomic`: write to a tempfile,
`sync_all`, then `rename(2)` into place. If you genuinely cannot
order the steps that way, document the rationale in the
function-level rustdoc and surface the window as a known caveat.

## Working example

A skeleton Rust storage plugin is two files. The `Cargo.toml`:

```toml
[package]
name    = "my-backend-plugin"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
ovstorage-plugin = "0.1"
async-trait      = "0.1"
tokio-util       = { version = "0.7", default-features = false }
```

And `src/lib.rs`, which implements `shim::Factory` and invokes
`ovstorage_plugin!(MyFactory::default)` at module scope. The macro
emits the two cdylib symbols (`ovstorage_plugin_manifest_v1` and
`ovstorage_plugin_init_v1`) and pulls `name` / `version` from
`CARGO_PKG_*`. The factory vtable (`BackendFactoryVTableV1`) is a
static inside `ovstorage_plugin::thunks` whose pointer the init
function hands back to the host in
`BackendPluginInitResultV1.factory_vtable` — there is no third
`ovstorage_plugin_vtable_v1` symbol. The factory shape:

```rust
#[derive(Default)]
struct ExampleFactory;

#[async_trait::async_trait]
impl Factory for ExampleFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "example-rust".into(),
            display_name: "Example Rust Plugin".into(),
            description: Some("Reference Rust plugin for ovstorage_plugin! macro".into()),
            config_schema: vec![],
            credential_schema: vec![],
            capabilities: Capabilities::empty(),
            icon: None,
            supports_runtime_add: false,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        _cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::shim::BackendInstance, Error> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "example-rust factory does not instantiate a backend",
        ))
    }
}

ovstorage_plugin!(ExampleFactory::default);
```

This skeleton returns `Unsupported` from `instantiate`, so it loads
but cannot serve objects. A real plugin returns a populated
`BackendInstance` carrying an `Arc<dyn Backend>` and a list of
`AddressRoot`s, then implements the `shim::Backend` methods matching
the capabilities it advertises.

## Worked references

The in-repo storage plugins — implementations against which the
conformance suite runs, and reference material for plugin authors.
Each plugin lives on its own page, and the cross-cutting behavioral
contract every backend implements lives in
[`CONFORMANCE.md`](CONFORMANCE.md) — the Storage SPI behavioral
contract that complements the per-backend pages below. Read
`CONFORMANCE.md` first when implementing a new backend; the
per-backend pages illustrate one valid branch each.

- [`file`](plugin-file.md) — reference implementation of the `Backend`
  SPI against the local filesystem. Atomic publish via temp + fsync +
  rename.
- [`http`](plugin-http.md) — read-only plugin for anonymous HTTP/HTTPS
  URLs.
- [`omniverse-storage-service`](plugin-services-client.md) —
  Omniverse Storage Service client over Storage API gRPC + OIDC.
- [`s3`](plugin-s3.md) — AWS S3 and S3-compatible object stores (MinIO,
  Cloudflare R2, Backblaze B2, custom). SigV4 signing, native multipart,
  presigned-URL redirects.
- [`gcs`](plugin-gcs.md) — Google Cloud Storage. V4 query-signing for
  service accounts, OAuth bearer tokens, resumable uploads.
- [`azure`](plugin-azure.md) — Azure Blob Storage and ADLS Gen2
  (HNS-aware). Shared-key/SAS/Entra OAuth2 auth paths.
- [`opendal`](plugin-opendal.md) — long-tail backends fronted by Apache
  OpenDAL (`fs`, `s3`, `webdav` services).
- [`nucleus`](plugin-nucleus.md) — NVIDIA Omniverse Nucleus
  content-collaboration server. `omniverse://` URL scheme, omni1
  protocol over SOWS/ConnLib WebSocket plus an LFT HTTP side-channel
  for bulk bytes; checkpoint versioning and ACL-aware permissions.
- [`broker`](plugin-broker.md) — `broker-client` cdylib. Forwards
  every `StorageBackend` SPI call across the library <-> broker
  gRPC protocol to an upstream `ovstorage-broker` daemon. No scheme
  of its own — address roots come from the broker's
  `ListAddressRoots` snapshot.
- [`ovstorage-plugin-test`](plugin-test.md) — the in-tree test plugin
  (`test_only = true`; production hosts refuse to load it).

## What's not supported

- **Plugin hot-reload.** Plugins load at process start (or via
  `add_connection` for `supports_runtime_add` factories) and stay
  loaded for the host's lifetime. Operators restart the host to
  pick up a new `.so`.
- **Plugin sandboxing.** Plugins run in-process at full host trust
  — same threat posture as a Rust crate dependency. Manifests are
  descriptive metadata, not a runtime gate. Supply-chain validation
  of the `.so` is the operator's package-manager problem.
- **Disk-spool half-measures for streaming writes.** If your
  backend can't stream, return `Unsupported` from `write_stream`
  and let the host route to `write` or `write_redirect`. Spooling
  to disk to fake streaming reintroduces the memory-DoS shape one
  indirection deeper. Add a streaming-invariant test when you
  introduce a true streaming seam.
- **Second redirect rounds against a streamed body.** When a plugin
  emits a `WriteStep::Redirects` whose `continue_write` returns
  another `WriteStep::Redirects`, the host can run that second
  round only against a buffered body (`Body::Bytes` or
  `Body::LocalFile`). A `Body::Stream` is consumed during the first
  round; a second round surfaces `Unsupported` ("the stream was
  consumed in the first redirect round"). S3 multipart fits in one
  round (one `WriteRedirect` per part, all in the first batch), so
  this is a forward-compat guard rather than a current limit. A
  backend that needs more than one round on a streamed body should
  drive the loop inside `write_stream` instead.
