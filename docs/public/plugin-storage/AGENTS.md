# Agent routing: plugin-storage

Persona: plugin author writing a new storage backend. The in-repo
reference backends are `file`, `http`, `omniverse-storage-service`,
`s3`, `gcs`, `azure`, `opendal`, `nucleus`, `broker`
(broker-client), and the test-only `ovstorage-plugin-test`
conformance plugin.
Foundation lives in
[`../plugin-development/AGENTS.md`](../plugin-development/AGENTS.md);
read it first for shared substrate (C ABI, Rust marshalling, conformance,
build, ABI stability). This page is the storage-specific routing.

## Where to start

- The minimum-viable scaffold lives inline in the
  [plugin-storage README § Build and export](README.md#build-and-export):
  `Cargo.toml` with `crate-type = ["cdylib"]`, one `src/lib.rs`
  implementing `BackendFactory`, and
  `ovstorage_layer_plugin!(backend, MyFactory::default)` at module
  scope.
- Macro: `ovstorage_layer_plugin!(tag, constructor)` — function-like,
  not attribute. `tag` is the layer type (`backend` / `wrapper` /
  `router`); the constructor is an `fn() -> impl BackendFactory` (or
  the matching wrapper/router factory trait). The macro emits the two
  cdylib symbols (`ovstorage_plugin_manifest_v1` and
  `ovstorage_plugin_init_v1` — the symbol names are frozen; the manifest
  they emit selects the Layer ABI version, 13 in ovstorage 0.2.1) and
  pulls `name` / `version` from `CARGO_PKG_*`. Use
  `ovstorage_layer_plugin!(((backend, BackendFactory::default), (wrapper,
  WrapperFactory::default)))` to export multiple factories from one cdylib.
  Kind names in a bundle must be unique, `file` is reserved for the built-in
  backend, and a trailing `test_only` flag applies to the whole plugin.

## Two traits to implement

- `BackendFactory` — `descriptor` (sync, the `LayerKindDescriptor`)
  and `create_backend(name, config, cancel)`, which returns your
  `Arc`'d `Layer` bound to the instance config.
- `Layer` — the operational vtable slots: object I/O (`stat`, `read`,
  the write family, `list`, …) plus connection lifecycle
  (`add_connection`, `authenticate_connection`,
  `update_connection_credentials`, `list_connections`) and
  introspection (`root_info_for`, `list_address_roots`). Slots you
  don't implement default to `Unsupported`. Behavioral source of
  truth: [`CONFORMANCE.md`](CONFORMANCE.md).

## Capability matrix is mandatory

Advertise via `Capabilities` exactly what you implement; the host
gates dispatch on these bits and callers gate UX on them.
Mis-advertising produces errors that look like backend bugs.
Vocabulary:
[`../plugin-development/README.md` § Capability vocabulary](../plugin-development/README.md#capability-vocabulary).
Capability values are advertised per root (`RootInfo.capabilities`)
and immutable for the owning connection's lifetime.

## Conformance harness

The host's conformance tests run against your plugin (loaded as a
real cdylib). They use the trusted in-tree test plugin (the
`ovstorage-plugin-test` harness, exported as the
`ovstorage-plugin-test-abi` cdylib) to drive scenarios the host needs
to observe; you don't write a separate "plugin TCK" — you make the
host's tests pass against your plugin. Skipped tests cite the
missing capability; if your plugin advertises a capability, the
corresponding tests run. Read
[`../plugin-development/README.md` § Conformance harness](../plugin-development/README.md#conformance-harness)
when implementing or reviewing a backend; it describes the rules
the host tests exercise.

## Streaming-invariant test

Mandatory for any new plugin that exposes a `Body::Stream` seam
(writes) or chunked read seam. Location:
`<your-plugin-crate>/tests/streaming_invariant.rs`. Helper:
`ovstorage_plugin_test::streaming::assert_streaming_invariants`
(drives ≥3 chunks ≥64 MiB at 4 MiB; asserts bounded in-flight
bytes, preserved chunk count, in-order arrival). Inventory +
recorder shapes:
[`../plugin-development/README.md` § Streaming seams](../plugin-development/README.md#streaming-seams).
A plugin that can't stream returns `Unsupported` from
`write_stream` — do NOT disk-spool as a half-measure.

## Manifest, descriptor, errors

- Manifest fields the macro emits in `ovstorage_plugin_manifest_v1`:
  `struct_size: usize`, `abi_version: u32`, `name` and `version`
  pointers (NUL-terminated, fed from `CARGO_PKG_NAME` /
  `CARGO_PKG_VERSION`), and `test_only: bool` (false for vendor
  plugins). There is **no** `plugin_kind` field on the manifest;
  every dynamically loaded plugin implements the storage Layer ABI.
- `LayerKindDescriptor` — what `BackendFactory::descriptor` returns —
  carries `kind` (URL scheme prefix), `layer_type`, `display_name`,
  `description`, `config_schema`, `credential_schema`,
  `credential_methods`, optional `icon`, `accepts_connections`, and
  `supports_user_metadata` (whether the kind accepts the host's
  attribution stamp in a write's `user_metadata`; a host composes its
  attribution layer only over a branch that declares `true`).
  Capabilities are **not** on the descriptor; they are advertised per
  root through `RootInfo.capabilities` (see § Capability matrix above).
- New required `ConfigField` without a default = breaking change =
  a **plugin C ABI 2.0**, not an ovstorage 2.0 release. The ABI freezes
  at 1.0 and a break after that is what forces the ABI major bump; the
  ovstorage package version moves independently. Evolve descriptors
  additively; the per-kind version handshake fails fast on mis-binding.
- Credential fields are flagged `secret = true`; `SecretBytes`
  redacts in `Debug`; the public API never returns plaintext after
  `add_connection`.
- Map connection lifecycle errors to the typed `ErrorCode` set in
  [`../plugin-development/README.md` § Connection lifecycle errors](../plugin-development/README.md#connection-lifecycle-errors).
  Don't invent new variants.

## Worked references

The cross-cutting behavioral contract every backend implements lives
in [CONFORMANCE.md](CONFORMANCE.md) — the storage Layer behavioral
contract that complements the per-backend pages below. Read it first
when implementing a new backend; each per-backend page illustrates one
valid branch of the contracts spelled out there.

1. [plugin-file](plugin-file.md) — the built-in `file` backend: the
   library's native local-filesystem implementation, served in-Stack
   with no cdylib to build or load. Atomic publish via temp + fsync +
   rename.
2. [plugin-http](plugin-http.md) — read-only plugin for HTTP/HTTPS
   URLs, anonymous or authenticated (bearer / basic).
3. [plugin-services-client](plugin-services-client.md) —
   `omniverse-storage-service` client over Storage API gRPC + OIDC.
4. [plugin-s3](plugin-s3.md) — AWS S3 and S3-compatible object stores
   (MinIO, Cloudflare R2, Backblaze B2, custom). SigV4 signing, native
   multipart, presigned-URL redirects.
5. [plugin-gcs](plugin-gcs.md) — Google Cloud Storage. V4
   query-signing for service accounts, OAuth bearer tokens, resumable
   uploads.
6. [plugin-azure](plugin-azure.md) — Azure Blob Storage and ADLS Gen2
   (HNS-aware). Shared-key/SAS/Entra OAuth2 auth paths.
7. [plugin-opendal](plugin-opendal.md) — long-tail backends fronted by
   Apache OpenDAL (`fs`, `s3`, `webdav` services).
8. [plugin-nucleus](plugin-nucleus.md) — NVIDIA Omniverse Nucleus
   content-collaboration server. `omniverse://` URL scheme, omni1
   protocol over SOWS/ConnLib WebSocket + LFT HTTP side-channel,
   checkpoint versioning, ACL-aware permissions.
9. [plugin-broker](plugin-broker.md) — `broker-client` cdylib for
   the brokered topology. No scheme of its own; address roots come
   from the upstream `ovstorage-broker` daemon via
   `ListAddressRoots`. Forwards every Layer call across the library
   <-> broker gRPC protocol with `if_match` (etag),
   `if_source` (etag), and `if_dest` (`IfDestExists`)
   pass-through.
10. [plugin-test](plugin-test.md) — the in-tree test plugin
    (`test_only = true`; production hosts refuse to load it),
    controllable test backend used by host conformance scenarios.

## Don't

- Don't drain `Body::Stream` to a `Vec<u8>` at the plugin boundary.
  Ever.
- Don't author the C vtable by hand for a Rust plugin — use the
  macro.
- Don't author non-Rust storage plugins. The C ABI is the stability
  layer, not a hand-authoring target. Bindings for C++ / Python
  that let those languages **call** ovstorage exist; first-party
  hand-written-C plugin authoring is out of scope. Authors writing
  in C++ or other languages route through `plugin-development` for
  the shared-substrate questions before designing a non-Rust plugin.
- Don't expect plugin hot-reload or sandboxing. Plugins are full
  in-process trust; operators restart the host to pick up a new
  `.so`.
- Don't advertise a capability you don't implement (or vice versa).
