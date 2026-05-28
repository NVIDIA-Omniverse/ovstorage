# ovstorage-rest

> Canonical user-facing reference lives in
> [`docs/public/library-web/README.md`](../../../docs/public/library-web/README.md).

Standalone binary that links the `ovstorage` Rust crate and
exposes the `Library` API over HTTP at versioned `/v1/` paths.
Peer of [`ovstorage-broker`](../ovstorage-broker/README.md): same
library underneath, different front end (REST vs gRPC).

Right fit for callers in languages without an ovstorage binding
(Go, Java, browser JS, ad-hoc shell scripts), polyglot
environments, and anything that already speaks HTTP. CORS, rate
limiting, TLS termination, and request-size caps are deferred to a
reverse proxy by design.

## Internal architecture

- **`src/main.rs`** — binary entry point. Parses CLI args
  (`--config PATH`, `--listen HOST:PORT`), resolves the TOML
  config, builds the `Library`, loads the authz cdylib (when
  `[authz]` is present), instantiates the router, binds the axum
  listener.
- **`src/lib.rs`** — router assembly via `utoipa-axum`'s
  `OpenApiRouter`; the OpenAPI doc at
  `/v1/openapi.{json,yaml}` is generated from the same router
  that serves traffic.
- **`src/objects.rs`** — `/v1/objects` data-plane handlers
  (read / stat / write / delete / list / list_versions /
  get_latest_version / copy / rename / update_metadata /
  check_access / watch_directory SSE). `PUT /v1/objects`
  propagates the request body as `Body::Stream` through a 16-slot
  bounded mpsc.
- **`src/management.rs`** — `/v1/connections`, `/v1/aliases`,
  `/v1/address-visibility`, and
  `/v1/connections:authenticate` (SSE) handlers.
- **`src/helpers.rs`** — query-parameter parsing helpers (strict
  bool / int parsing returning `400 InvalidArgument` on bad
  input).
- **`src/authn.rs`** — `JwtAuthenticator` (the OIDC bearer JWT
  validator). JWKS-cache 10-minute TTL + unknown-`kid` refetch
  path.
- **`src/jwt.rs`** — `jsonwebtoken` integration; `JwtClaims`
  struct.
- **`src/schema.rs`** — `utoipa` JSON schemas for the REST
  request / response shapes.
- **`src/metrics_layer.rs`** — request-counter / latency-tracking
  tower layer.
- **`src/trace.rs`** — tracing span setup (request span with
  `http.path` and the validated `Principal`).
- **`src/test_utils.rs`** — fixture builders (test JWKS, test
  routes, fake-OIDC issuer) for the conformance kit.
- **`src/tests.rs`** — inline unit tests for handler shapes.

## Test layout

- `src/*::tests` — unit tests per module.
- `tests/rest_conformance.rs` — end-to-end gateway scenarios:
  `307 Temporary Redirect` for `ReadResult::Redirect`, streaming
  reads / writes, `If-Match` quoted and bare-etag round-trip,
  `If-None-Match: *` no-overwrite, authz directional
  decomposition (`Copy` -> `Read+Write`; `AddAlias` -> `AddAlias +
  Read`), per-item list filtering via `filter_list_batch`,
  OIDC bearer authentication matrix,
  `streaming_write_does_not_drain_body` (asserts a 16 MiB body in
  64 KiB chunks round-trips with bytes intact).

## Conformance test gaps

Chained REST -> broker audit attribution (the topology doesn't
exist in this codebase — REST runs the library in-process), body-
size limits, CORS layer, rate-limiting layer, audit-record
threading, REST reload story / `policy_epoch` advance via
SIGHUP, crash-injection coverage, redaction-fuzz harness, and
performance benchmarks vs an in-process `Library` are tracked in
the public doc's *Implementation gaps* section.
