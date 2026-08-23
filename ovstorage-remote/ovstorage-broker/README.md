# ovstorage-broker

> Canonical user-facing reference for the broker daemon lives in
> [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md).

`ovstorage-broker` is the gRPC daemon binary. It embeds the
`ovstorage` Rust crate, dispatches through a **per-listener built-in
auth Layer** composed over a shared, auth-free inner `Stack`, and
forwards to backend plugins through the same Stack API direct callers
use. Single-tenant by design — one broker, one credential boundary.

The auth Layer (`ovstorage-authz-layer`, `BuiltinAuthLayer`, kind
`builtin-auth`) does authentication **and** authorization. The daemon
gathers the caller's opaque transport credential material (bearer
token + transport peer creds) and stamps it DOWN as
`ext::AUTH_CREDENTIAL` on a fresh extensions bag; the auth Layer
decodes it, resolves a principal, evaluates policy, and on allow
stamps `ext::PRINCIPAL_ID` DOWN to the inner. The daemon itself
performs no authn, authz, or principal resolution.

Internal architecture and dev notes follow.

## Module map

- `src/main.rs` — binary entry point. CLI argument parsing
  (`--config PATH`, `--listen HOST:PORT`), TOML load, validation
  pipeline, listener bind, lifecycle controller setup.
- `src/lib.rs` — library wrapper: registers backend factories,
  resolves the `[listener].auth` block via
  `ovstorage_authz_layer::resolve_listener_auth`, gathers the
  caller's `AuthCredential`, exposes the `Broker` API.
- `src/stack.rs` — `BrokerStackBuilder`: composes the shared
  auth-free inner Stack, then `attach`es the per-listener
  `BuiltinAuthLayer` over it (the daemon dispatches through this auth
  Stack). Both hosts are single-listener today, so this is the N=1
  case: one shared auth Layer, no fan-out.
- `src/config.rs` — TOML config types (`BrokerConfig`,
  `BrokerListenerConfig` — carries the opaque `auth` value —
  `BrokerListenerTlsConfig`, `BrokerTransport`,
  `AttributionStrategyConfig`).
- `src/broker.rs` — `Broker` core: gathers credential material onto
  a fresh extensions bag (`principal_cx` / `principal_req`) and
  dispatches `read` / `write` / `stat` / `list` / `write_redirect` /
  `continue_write` through the auth Stack.
- `src/grpc.rs` — tonic service implementations, including the
  server-streaming `Auth` relay and unary `RegisterCredential` path;
  the transport-branched credential-gathering seam
  (`gather_credential` → `AuthCredential`); error-context helpers;
  HTTP/2 keepalive policy.
- `src/discovery.rs` — `/api/v1/services` and `/api/v1/auth-config`
  HTTP discovery axum app.
- `src/lifecycle.rs` — `LifecycleController`: SIGHUP-driven
  atomic reload, drain-first shutdown, `ArcSwap<Broker>` swap.
- `src/observability.rs` — Prometheus `/metrics` listener and the
  metric families (including `ovstorage_auth_decisions_total`,
  emitted by the auth Layer).
- `src/oauth_providers.rs` — `[oauth_providers.<name>]` registry and
  route bindings used by the per-principal upstream-OAuth wrapper.
- `src/upstream_credential.rs` — broker-owned credential boundary that
  resolves and persists OAuth tokens in the authenticated principal's slot.
- `src/policy.rs` — per-route policy overlay
  (`cache.max_object_bytes`) and the daemon-wide `follow_cap`
  derivation (`BrokerRoutePolicies::daemon_follow_cap`).
- `src/trace.rs` — tracing span setup (`broker.<method>` spans;
  `RedactedUrl` for `object.address`).
- `src/watch.rs` — broker watch-RPC shutdown state; concurrent-subscription
  coalescing is a backend concern (SDK `WatchCoalescer`).
- `src/client_transport.rs` — broker-as-client transport plumbing
  for chained brokers.
- `src/test_utils.rs` — fixture builders for the test suite.

The built-in auth Layer itself (authn front-end + policy engine) lives
in the `ovstorage-authz-layer` crate, not here.

## Test layout

- `src/*::tests` — unit tests per module (config parsing, credential
  gathering, JWKS caching, lifecycle controller, etc.).
- `tests/` — integration suite. Notable scenarios: lifecycle
  reload + drain; auth directional decomposition; metadata-cache key
  isolation across principals; fan-out / queue-depth limits.

## Conformance test gaps

Crash-injection coverage (mid-redirect-issuance, mid-write
truncation), per-principal quota mapping to `ResourceExhausted`,
durable audit sinks, mTLS certificate validation, certificate
hot-reload, and an end-to-end SIGHUP-driven reload test via real
signal injection are tracked in the broker's `Implementation
gaps` section in the public operator doc.
