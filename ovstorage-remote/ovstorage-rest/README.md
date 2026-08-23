# ovstorage-rest

> Canonical user-facing reference lives in
> [`docs/public/library-web/README.md`](../../docs/public/library-web/README.md).

Standalone binary that links the `ovstorage` Rust crate and
exposes the storage API over HTTP at versioned `/v1/` paths.
Peer of [`ovstorage-broker`](../ovstorage-broker/README.md): same
Stack underneath, different front end (REST vs gRPC).

Like the broker, the gateway dispatches through a **built-in auth
Layer** (`ovstorage-authz-layer`, `BuiltinAuthLayer`, kind
`builtin-auth`) composed over a shared, auth-free inner `Stack`. Each
handler gathers the caller's credential through the `CallCx` seam —
the undecoded bearer from the HTTP `Authorization` header plus the
`Tcp` transport — and stamps it DOWN as `ext::AUTH_CREDENTIAL` on a
fresh extensions bag; the auth Layer resolves the principal,
authorizes, and stamps `ext::PRINCIPAL_ID` DOWN. REST is a
single-listener host (the degenerate N=1 case: one auth Layer, no
fan-out). The gateway performs no authn, authz, or principal
resolution itself.

Right fit for callers in languages without an ovstorage binding
(Go, Java, browser JS, ad-hoc shell scripts), polyglot
environments, and anything that already speaks HTTP. CORS, rate
limiting, TLS termination, and request-size caps are deferred to a
reverse proxy by design.

## Internal architecture

- **`src/main.rs`** — binary entry point. Parses CLI args
  (`--config PATH`, `--listen HOST:PORT`), resolves the TOML
  config, resolves the `[server].auth` block via
  `ovstorage_authz_layer::resolve_listener_auth` (fail-closed —
  absent `auth` errors before binding), builds the gateway Stack,
  instantiates the router, binds the axum listener.
- **`src/stack.rs`** — `GatewayStackBuilder`: composes the shared
  auth-free inner Stack, then `attach`es the per-listener
  `BuiltinAuthLayer` over it. REST is single-listener (N=1): one
  auth Layer, no fan-out.
- **`src/lib.rs`** — router assembly via `utoipa-axum`'s
  `OpenApiRouter`; the `CallCx` credential-gathering seam (bearer
  from the `Authorization` header → `ext::AUTH_CREDENTIAL` on a
  fresh extensions bag); the OpenAPI doc at
  `/v1/openapi.{json,yaml}` is generated from the same router
  that serves traffic.
- **`src/objects.rs`** — `/v1/objects` data-plane handlers
  (read / stat / write / delete / list / list_versions /
  get_latest_version / copy / rename / update_metadata /
  check_access / watch_directory SSE). `PUT /v1/objects`
  propagates the request body as `Body::Stream` through a 16-slot
  bounded mpsc. A `ReadResult::Redirect` surfaces as an HTTP
  `307 Temporary Redirect` unchanged.
- **`src/helpers.rs`** — query-parameter parsing helpers (strict
  bool / int parsing returning `400 InvalidArgument` on bad
  input).
- **`src/schema.rs`** — `utoipa` JSON schemas for the REST
  request / response shapes.
- **`src/metrics_layer.rs`** — request-counter / latency-tracking
  tower layer.
- **`src/trace.rs`** — tracing span setup (request span with
  `http.path` and the resolved principal).
- **`src/test_utils.rs`** — fixture builders (test JWKS, test
  routes, fake-OIDC issuer) for the conformance kit.
- **`src/tests.rs`** — inline unit tests for handler shapes.

Runtime connection-management (`POST`/`DELETE /v1/connections`,
`/v1/aliases`, `/v1/address-visibility`, `:authenticate`) is not a
REST surface: connections/aliases/visibility are operator config,
applied on the shared inner at build/reload time (the router returns
`404` for those paths). JWT validation and claim→principal mapping
live in the built-in auth Layer (`ovstorage-authz-layer`), not in the
gateway.

## Test layout

- `src/*::tests` — unit tests per module.
- `tests/rest_conformance.rs` — end-to-end gateway scenarios:
  `307 Temporary Redirect` for `ReadResult::Redirect`, streaming
  reads / writes, `If-Match` quoted and bare-etag round-trip,
  `If-None-Match: *` no-overwrite, authz directional
  decomposition (`Copy` -> `Read+Write`), per-item list filtering,
  OIDC bearer authentication matrix,
  `streaming_write_does_not_drain_body` (asserts a 16 MiB body in
  64 KiB chunks round-trips with bytes intact).

## Conformance test gaps

Chained REST -> broker audit attribution (the topology doesn't
exist in this codebase — REST runs the Stack in-process), body-
size limits, CORS layer, rate-limiting layer, audit-record
threading, crash-injection coverage, redaction-fuzz harness, and
performance benchmarks vs an in-process Stack are tracked in
the public doc's *Implementation gaps* section.
