# ovstorage-plugin-broker

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-broker.md`](../../../docs/public/plugin-storage/plugin-broker.md).

Cdylib `Backend` plugin for the `broker` kind: forwards every
`StorageBackend` SPI call across the library <-> broker gRPC
protocol to a configured upstream `ovstorage-broker` daemon. Loads
through the C ABI declared by `ovstorage-plugin`; sits on top of
[`ovstorage-broker-protocol`](../ovstorage-broker-protocol/README.md)
for the wire contract.

## Internal architecture

- **`src/lib.rs`** — module wiring, `ovstorage_plugin!` macro
  invocation, `BrokerClientBackendFactory`,
  `BrokerClientBackend`, the `impl shim::Backend` block, and
  the `TonicBrokerClient` `BrokerClientTransport` implementation
  (two-layer channel cache via `tokio::sync::OnceCell`).
- **`src/auth.rs`** — discovery state machine,
  `AuthorizationInterceptor`, OIDC client-credentials grant,
  refresh-token grant, interactive PKCE login bridge
  (`std::sync::mpsc` + per-bridge thread + dedicated
  `tokio::Runtime` to surface `AuthEvent`s into the host's sync
  iterator), per-user upstream-OAuth `Auth` /
  `RegisterCredential` round-trip plumbing.

`Capabilities::empty()` is advertised kind-wide; the
authoritative per-route capability profile is forwarded from the
broker's `ListAddressRoots` response into each
`BackendInstance.address_roots[i].capabilities` (the proto's
`pb::AddressRoot.capabilities` mirrors the upstream plugin's
profile field-by-field).

## Test layout

- `src/*::tests` — unit tests per module: descriptor +
  URL / endpoint parsing; discovery status-classification matrix;
  services-document parser; cross-scheme redirect-policy decision
  and loopback-host detection; channel-cache cell behavior;
  capability mirroring round-trips; auth interceptor +
  refresh-token grant; `update_credentials` hot-rotation; slot
  keying isolation across two same-display-name connections.
- `tests/precondition.rs` — boundary-sanity integration tests:
  inverted-range refusal, `if_match` etag pass-through for
  read / delete / update_metadata, `if_source` + `if_dest`
  (`IfDestExists`) pass-through for write / copy / rename,
  `list_versions` page-token pass-through, `list` recursive
  pass-through, `write_redirect` with `size_hint = None`
  pass-through (the broker daemon accepts unknown-size writes).

## Conformance test gaps

End-to-end discovery + bootstrap scenarios (anonymous-first
connect, auth-required connect, multi-service,
adjacent-services-discarded / current-introspection absence,
channel-lifecycle, token-generation reauth, proactive refresh,
capability bootstrap, bootstrap-failure distinction,
cache-survives-restart, stale-row reads, cache-prune,
cache-deleted) and integration coverage of the mpsc-bridged auth
flows + streaming-write source-error capture are tracked work,
not implemented today.

## `_test_support` feature

`BrokerClientBackend::new_for_tests(discovery_url, transport)` is a
`#[doc(hidden)]`, `#[cfg(feature = "_test_support")]` constructor
that injects a pre-built transport for `tests/precondition.rs`.
The crate self-references with this feature enabled in
`[dev-dependencies]`, so integration tests pick it up
automatically. Not part of the public API; production builds
exclude it entirely.
