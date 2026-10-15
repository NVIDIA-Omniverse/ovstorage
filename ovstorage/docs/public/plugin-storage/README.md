# Storage plugin guide

> "I'm implementing or reviewing an ovstorage storage Layer."

Start with [CONFORMANCE.md](CONFORMANCE.md). It is the method-level behavioral
contract. Use [plugin-development](../plugin-development/README.md) for the ABI,
type vocabulary, ownership, build, and loading rules.

## Architecture

A storage plugin is an ABI-v2 Layer plugin — "v2" is the plugin ABI *family*,
whose version number is 19 in the current source tree and 15 in ovstorage
0.2.1, with a family floor of 5. It is unrelated to the ovstorage package
version.

It implements:

- `BackendFactory`, whose synchronous `descriptor` identifies the kind and whose
  asynchronous `create_backend` constructs a configured `LayerHandle`;
- `Layer`, the uniform operational surface for object I/O, connection lifecycle,
  and root/kind/connection introspection;
- `ovstorage_layer_plugin!(backend, Constructor)` to emit the manifest and init
  symbols for a Rust cdylib.

Object and connection operations take a typed `Request<T>` envelope plus an
optional cancellation token. `Request::extensions` carries host facts such as
the caller principal. It is not a policy instruction channel.

The host builds a `Stack` from backends, wrappers, and a router. Storage plugins
do not implement routing, aliases, retries, caches, redirect execution, or
copy/rename fallback unless the plugin itself is a wrapper/router kind dedicated
to that responsibility.

## Descriptor and runtime state

`LayerKindDescriptor` contains kind-wide facts:

- `kind`, `layer_type`, display name, description, and icon;
- configuration and credential schemas;
- supported credential methods;
- `accepts_connections`.

It must not contain connection- or URL-specific capabilities. A Layer returns
those through `root_info_for` and `list_address_roots`. `RootInfo.capabilities`
is the effective capability set for that root and must remain truthful for the
connection lifetime.

`LayerConfig` is the Stack-entry configuration supplied to the factory. Runtime
connections are managed through the Layer connection slots:
`add_connection`, `remove_connection`, `authenticate_connection`,
`update_connection_credentials`, and `list_connections`.

## Object operations

The backend Layer implements the supported subset of:

- `stat`, `read`, `write`, `write_stream`, `write_redirect`, and
  `continue_write`;
- `delete`, `copy`, `rename`, `list`, `list_versions`, and
  `get_latest_version`;
- `create_directory`, `delete_directory`, `update_metadata`, and
  `check_access`;
- `watch_directory`.

Unimplemented optional slots return `Unsupported`. Advertise the corresponding
capability only when the implementation honors the complete contract in
[CONFORMANCE.md](CONFORMANCE.md).

That list is exhaustive for a backend Layer. The vtable carries one further
object slot, `materialize`, which a backend leaves at its trait default: local
availability is produced by the host wrapper Layers composed above the backend
— the redirect follower stages a `read` into a local file, and the byte cache
serves and pins under a lease one it already holds, delegating downward on a
miss — so it is a property of the composed Stack rather than of a backend, and
there is no capability bit for it. [OWNERSHIP.md](OWNERSHIP.md) is the registry
of which Layer owns which concern.

## Streaming

Large reads return `ReadResult::Stream`; streaming writes consume
`Body::Stream`. Do not drain either side into one object-sized buffer. Plugins
with a streaming seam add `tests/streaming_invariant.rs` using
`ovstorage_plugin_test::streaming::assert_streaming_invariants`.

`ReadResult::LocalDelegate` is valid only for a leased path local to the current
host. A broker converts it to bytes/streaming at the service boundary. Redirect
results carry short-lived scoped requests for the host redirect Layer to
execute.

## Addresses and versions

An address names a **node**, and the host hands you one canonical spelling of
it. Separators, dot segments, empty segments and the fragment are normalized at
construction, so `a//b` and `a/./b` both arrive as `a/b` and a plugin never sees
— and must not try to preserve — the other spellings. Trailing punctuation,
percent encoding and Unicode bytes inside a segment are yours: they survive
untouched, and two keys differing only in those bytes stay two keys.

**The trailing slash is never added or removed.** `docs` and `docs/` name one
node, and every host-side comparison knows that, but on a flat store they may be
two objects — so the caller's spelling reaches you unchanged and the choice
stays yours. A directory-facing slot (`list`, `watch_directory`,
`create_directory`, `delete_directory`) must therefore **derive its own
directory key** rather than assume a trailing slash is present. See
[CONFORMANCE.md § Trailing slash conventions](CONFORMANCE.md).

Returned object addresses stay inside the resolved request prefix. The host
projects them back into the caller namespace. Version-aware plugins return
version-pinned addresses and never silently drop a caller-supplied pin on a
mutation. Under the `versioned_address` cost flag they also report each
object's pin as `ObjectInfo.versioned_address`; the per-backend table in
[CONFORMANCE.md](CONFORMANCE.md) states what that costs on each store.

An address that no connection serves is `NoRoute` — unless the operator granted
the **anonymous fallback** for the address's scheme, with
`anonymous_fallback = ["s3"]` (or `["gs"]`, `["azure"]`) on that kind's layer
table, or `anonymous_fallback_schemes` on a broker or REST gateway, which
stamps the same key. A granted backend publishes one hidden scheme root
(`s3:///`, `gs:///`, `azure:///`); the shared route table consults it only
after every prefix has missed and only for an address whose query carries no
credential; and the backend attempts the address anonymously and read-only,
refusing a cloud instance-metadata host before any socket opens. The placement
follows the ownership registry's information test: the backend owns reaching
the node anonymously — the scheme root, the per-bucket client, the read-only
refusal and the instance-metadata refusal — and the host owns whether that is
permitted, which is why the grant is layer configuration and authorization is
evaluated before routing. The `anonymous_fallback` section of
[configuration.md](../configuration.md) has the keys and the host rules; the
`Router` routing row and the owning-backend row for the per-scheme anonymous
fallback in [OWNERSHIP.md](OWNERSHIP.md) record the placement; and each cloud
plugin's own **Anonymous fallback** section ([S3](plugin-s3.md),
[GCS](plugin-gcs.md), [Azure](plugin-azure.md)) states what its fallback
reaches and refuses.

## Credentials and secrets

Declare credential fields in the descriptor and mark secrets with
`secret = true`. Use `SecretBytes`; never log or persist plaintext outside the
host credential substrate. Authentication is driven through
`authenticate_connection`, which returns an auth-event stream appropriate to
the host's interactive capability — or `Unsupported`, when the backend has no
interactive flow at all, in which case nothing ran and the connection's state
is unchanged.

Connection errors use the shared `ErrorCode` mapping. In particular,
authentication-required, invalid credentials, denied access, missing
configuration, and unsupported flows must remain distinguishable.

The first-party cloud plugins intentionally expose narrower credential sources
than their provider SDKs. The
[credential-provider matrix and host-bridge recipes](credential-providers.md)
state which S3, GCS, and Azure ambient identities are accepted, bridgeable, or
not representable by the current bundle.

## Build and export

Rust plugins build as `cdylib` and invoke:

```rust,ignore
ovstorage_plugin::ovstorage_layer_plugin!(backend, MyLayerFactory::default);
```

The loader requires an exact match on the host's Layer ABI version rather than
a compatible range. The current source tree expects 19; ovstorage 0.2.1
expects 15. A cdylib declaring anything else is refused at load with
`IncompatibleType`. `test_only` is available only for controlled conformance
fixtures:

```rust,ignore
ovstorage_plugin::ovstorage_layer_plugin!(backend, TestLayerFactory::default, test_only);
```

## Verification

Before review:

1. Run the plugin's unit/integration tests and its streaming invariant when
   applicable.
2. Load the release cdylib through the real host loader.
3. Run the capability-selected contracts in [CONFORMANCE.md](CONFORMANCE.md).
4. Run repository `make verify` and the affected workspace tests.
5. Confirm cancellation and provider deadlines on every blocking/network path.

New plugins add `tests/conformance_scenarios.rs`: a registry-as-spec sweep
that iterates `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and
drives every scenario the plugin's advertised capabilities support against
scripted local fixtures (`ScriptedHttpServer` for HTTP-shaped backends), so
no test touches a real network. Scenarios gated out by `required_profile` /
`required_capabilities` are reported as explicit skips naming the missing
capability, never silently omitted, and the driven-name set is pinned so
lost coverage fails loudly. Each first-party provider crate's
`tests/conformance_scenarios.rs` is a working example. The sweep runs under
`make test` automatically via `cargo test --workspace`.

The in-tree `ovstorage-plugin-test` crate is a deterministic host-boundary
fixture, not a vendor-plugin template. Its export crate marks the cdylib
`test_only = true`.

## Backend references

- [file](plugin-file.md) — built-in local filesystem Layer.
- [HTTP](plugin-http.md) — HTTP/HTTPS reads, anonymous or authenticated, with
  broker-scoped upstream OAuth.
- [services client](plugin-services-client.md) — Omniverse Storage Service.
- [S3](plugin-s3.md) — AWS S3 and compatible services.
- [GCS](plugin-gcs.md) — Google Cloud Storage.
- [Azure](plugin-azure.md) — Azure Blob Storage and ADLS Gen2.
- [Hugging Face Hub](plugin-huggingface.md) — Hugging Face Hub repositories
  (read-only).
- [OpenDAL](plugin-opendal.md) — OpenDAL-backed services.
- [Nucleus](plugin-nucleus.md) — Omniverse Nucleus.
- [test plugin](plugin-test.md) — deterministic conformance fixture.

## Review rules

- Keep capability declarations exact.
- Preserve error codes across SDK/provider mappings.
- Enforce write preconditions before publishing bytes.
- A write creates its path: create missing ancestors on real-directory
  backends; never make the caller do it.
- Keep streams bounded and cancellation-aware.
- Never hand-author the C vtable for a Rust plugin.
- Treat plugins as trusted in-process code; there is no sandbox or hot reload.
