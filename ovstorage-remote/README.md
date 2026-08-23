# ovstorage-remote

Remote-host components: the optional `ovstorage-broker` daemon, the
`ovstorage-rest` gateway, and the built-in authorization Layer plus its
TOML-driven policy engine. Direct-mode `ovstorage` does not need anything from this
workspace; deployments that want centralized credential isolation,
fleet-shared metadata caching, or REST-as-an-edge run a broker (and
optionally a REST gateway in front of it).

The `ovstorage-rest` gateway is a thin REST projection over an
in-process `ovstorage::Stack`. To chain REST → broker → cloud, the
operator configures one or more `[[connections]] backend_kind =
"broker-client"` entries in the gateway's `ovstorage.toml`; the
`broker-client` plugin forwards every routed call over gRPC to the
configured upstream broker. Without a `broker-client` connection, REST
runs purely against directly-loaded backend plugins in its own
process. There is no implicit chain — the binding is the operator's
`[[connections]]` choice.

See the [repo-root README](../README.md) for the cross-workspace layout
and dependency graph.

## Crates

- [`ovstorage-broker`](ovstorage-broker/README.md) — the broker daemon: gRPC server, listener authn (four implemented modes plus reserved `mtls` that returns `Unsupported` at startup), broker-side metadata + byte caching, redirect issuance, audit-safe diagnostics, route + backend lifecycle.
- [`ovstorage-broker-protocol`](ovstorage-broker-protocol/README.md) — the wire protocol: `.proto` definitions, tonic-generated types, error-detail framing, streaming-write framing.
- [`ovstorage-plugin-broker`](ovstorage-plugin-broker/README.md) — the library-side plugin that talks to a broker. Loaded as a cdylib like any other backend plugin.
- [`ovstorage-rest`](ovstorage-rest/README.md) — the public REST gateway: Hyper-based HTTP server fronting an `ovstorage::Stack`. Streaming-write enforcement, bearer-token authn, public-facing object I/O surface.
- [`ovstorage-authz`](ovstorage-authz/README.md) — shared `Principal` and attribution types.
- [`ovstorage-authz-context`](ovstorage-authz-context/src/lib.rs) — request identity and transport context shared by hosts and Layers.
- [`ovstorage-authz-policy`](ovstorage-authz-policy/src/lib.rs) — pure TOML policy parser and evaluator.
- [`ovstorage-authz-layer`](ovstorage-authz-layer/src/lib.rs) — built-in authentication and authorization Layer.

Operators running a broker should start at the
`broker-operator` persona.
Authorization policy operators should start at the
[`authz-policy`](../docs/public/authz-policy/README.md) guide. Contributors
changing the implementation should use the
[`ovstorage-contributor-modify-authz-layer`](../skills/ovstorage-contributor-modify-authz-layer/SKILL.md)
skill.

## Why REST and broker are separate crates

`ovstorage-rest` and `ovstorage-broker` are independent binaries that each
construct a Stack. They share nothing in source — just the
workspace. The un-merge holds for two reasons:

- **API surfaces diverge.** REST exposes connection management, alias
  management, visibility overrides, and an authenticate-flow SSE
  endpoint. gRPC/broker doesn't — those are local host state and
  don't fit the broker-multiplexer model the gRPC API is shaped for.
  REST projects a Stack over HTTP; gRPC is a deliberately curated
  subset for daemon-to-daemon multiplexing. They're different products,
  not protocol twins.
- **Authn is fundamentally a transport concern, not shared substrate.**
  "Who is the caller?" depends on the wire shape — `PeerCred` only
  makes sense over UDS, bearer JWT over TCP, etc. Each transport
  produces a `Principal` (defined in `ovstorage-authz` because
  `Principal` is what authz consumes), but the production mechanism
  is per-transport. The JWT-validation code in `-broker`
  (`GrpcAuthn::JwtVerify`) and `-rest` (`JwtAuthenticator` in
  `ovstorage-rest/src/jwt.rs`) duplicates ~150 lines of
  `jsonwebtoken` usage; that is the price of keeping the abstraction
  honest. A small `ovstorage-jwt` *utility* (just `JwksCache` +
  `validate_signed_jwt`) is fine if a future caller appears, but
  authz architecture stays per-transport.

The workspace directory is `ovstorage-remote/` (not `ovstorage-broker/`)
because the workspace holds REST + authz + broker bits. Don't re-rename
to `-broker`. Don't create an `ovstorage-authn` crate. New auth modes
added to one transport don't automatically come to the other —
extraction is wire-format-specific.

## Deferred polish

The workspace is functional; these items are tracked but not blocking:

- Share `OidcConfig` between REST's `[server.oidc]` and broker's
  `BrokerListenerAuthnConfig` — both carry identical
  `issuer` / `audience` / `jwks_url` fields. A shared struct in
  `ovstorage-authz` (or a small `ovstorage-listener-config`) drops the
  duplication.
- REST authn-mode parity with broker. The broker has five modes
  (`DevCurrentUser`, `JwtVerify`, `TrustedUnsignedJwt`,
  `TrustedForwardedHeaders`, `PeerCred`); REST has two (`none`,
  `JwtVerify`). `TrustedForwardedHeaders` is the most-wanted addition
  (REST sitting behind nginx/Envoy that already did OIDC) but lands
  when a real deployment needs it, not preemptively.
- REST CLI integration in `ovstorage-cli`. The CLI talks to brokers
  via `broker-client`; it doesn't know how to talk to REST yet.
- Single shared test plugin fixture. Today broker's `build.rs` builds
  `file + test + broker-client` and REST's `build.rs` builds
  `file + test`, so `file` and `test` each compile twice. Cosmetic;
  cargo caches absorb the cost.
