# ovstorage-broker

> Canonical user-facing reference for the broker daemon lives in
> [`docs/public/broker-operator/README.md`](../../../docs/public/broker-operator/README.md).

`ovstorage-broker` is the gRPC daemon binary. It embeds the
`ovstorage` Rust crate, runs every RPC through a configured
`AuthzPlugin` before dispatch, and forwards to backend plugins
through the same `Storage` API direct callers use. Single-tenant by
design — one broker, one credential boundary.

Internal architecture and dev notes follow.

## Module map

- `src/main.rs` — binary entry point. CLI argument parsing
  (`--config PATH`, `--listen HOST:PORT`), TOML load, validation
  pipeline, listener bind, lifecycle controller setup.
- `src/lib.rs` — library wrapper; embeds `ovstorage::Library`,
  registers backend factories, exposes `Broker` API.
- `src/config.rs` — TOML config types (`BrokerConfig`,
  `BrokerListenerConfig`, `BrokerListenerAuthnConfig`,
  `BrokerListenerTlsConfig`, `BrokerTransport`, `BrokerAuthnMode`,
  `AttributionStrategyConfig`, `AuthzPluginConfig`).
- `src/authn.rs` — listener authn modes (`dev_current_user`,
  `jwt_verify`, `trusted_unsigned_jwt`,
  `trusted_forwarded_headers`, `peer_cred`; reserved `mtls`).
  JWKS cache + unknown-`kid` refetch path.
- `src/authz_plugins.rs` — authz plugin loader plumbing.
- `src/broker.rs` — `Broker` core: `read` / `write` / `stat` /
  `list` / `write_redirect` / `continue_write` dispatch including
  the cache + authz gates.
- `src/grpc.rs` — tonic service implementations
  (`BrokerService` + `Auth` + `RegisterCredential`); error-context
  helpers (`ctx_status`, `ctx_status_addr`); HTTP/2 keepalive
  policy.
- `src/discovery.rs` — `/api/v1/services` and `/api/v1/auth-config`
  HTTP discovery axum app.
- `src/lifecycle.rs` — `LifecycleController`: SIGHUP-driven
  atomic reload, drain-first shutdown, `ArcSwap<Broker>` swap.
- `src/observability.rs` — Prometheus `/metrics` listener and the
  11 metric families.
- `src/oauth_providers.rs` — `[oauth_providers.<name>]` registry
  plus the per-user upstream-OAuth `Auth` /
  `RegisterCredential` round-trip plumbing.
- `src/policy.rs` — per-route policy overlay
  (`cache.max_object_bytes`, `redirect.ttl_seconds` /
  `read_endpoint` / `write_endpoint`).
- `src/redirect_fetch.rs` — broker-side
  `follow_read_redirect` plus the bounded fetch + cache-put path.
- `src/trace.rs` — tracing span setup (`broker.<method>` spans;
  `RedactedUrl` for `object.address`).
- `src/watch.rs` — `WatchDirectoryHub` per-key `OnceCell`
  coalescing + 256-watcher fan-out cap +
  `DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH = 256` bounded mpsc per
  watcher.
- `src/client_transport.rs` — broker-as-client transport plumbing
  for chained brokers.
- `src/test_utils.rs` — fixture builders for the test suite.

## Test layout

- `src/*::tests` — unit tests per module (config parsing, authn
  mode selection, JWKS caching, lifecycle controller, policy-epoch
  state machine, etc.).
- `tests/` — integration suite. Notable scenarios: lifecycle
  reload + drain; multi-listener wiring; authz directional
  decomposition; metadata-cache key isolation across principals;
  fan-out / queue-depth limits.

## Conformance test gaps

Crash-injection coverage (mid-redirect-issuance, mid-write
truncation), per-principal quota mapping to `ResourceExhausted`,
durable audit sinks, mTLS certificate validation, certificate
hot-reload, and an end-to-end SIGHUP-driven reload test via real
signal injection are tracked in the broker's `Implementation
gaps` section in the public operator doc.
