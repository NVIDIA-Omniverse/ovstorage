# library-web persona

> *I'm calling ovstorage over HTTP — from Go, Java, Node, browser JS, a
> shell pipeline, or anything else that speaks HTTP. I don't link an
> ovstorage SDK; I want a JSON-shaped REST surface with bearer-token
> auth.*

This persona lands you at `ovstorage-rest`, the standalone HTTP gateway
binary that links the `ovstorage` Rust crate and exposes the `Library`
API over a versioned `/v1/` REST surface. The gateway is a peer of
[`ovstorage-broker`](../broker-operator/README.md): same library
underneath, different front end. The broker speaks gRPC to library
processes; the gateway speaks REST to anything that speaks HTTP. It is
the right fit for services and tools written in languages without an
ovstorage binding (Go, Java, browser JS, ad-hoc shell scripts),
polyglot environments, and anything that already speaks HTTP.

```text
browser JS / curl / Go / Java / shell -> ovstorage-rest -> ovstorage
                                                          -> Direct mode plugins
                                                          -> broker-client -> ovstorage-broker
```

## When to use REST vs the gRPC broker

Pick `ovstorage-rest` when:

- Your caller is in a language without an ovstorage binding.
- Your caller is a browser, an HTTP-only CI runner, or a polyglot
  pipeline that already speaks HTTP.
- You want to put a reverse proxy (CORS, rate limit, TLS, IP allow-list,
  non-OIDC auth) in front of ovstorage.

Pick the gRPC broker (`ovstorage-broker`) directly when:

- Your caller is in Rust / Python / C / C++ and can link the
  `broker-client` plugin against the native library.
- You want server-streaming RPCs (`Read`, `WatchDirectory`,
  `WatchAddressRoots`, `Auth`) with native chunked transport instead of
  Server-Sent Events.
- You're chaining brokers (one broker fronting another) — the broker
  speaks broker-protocol gRPC, not REST.

The canonical chain is `ovstorage-rest` -> `ovstorage-broker` -> cloud:
the gateway speaks REST to humans and tools and gRPC upstream to the
broker, and the broker holds the credentials. Each component has one
responsibility and scales independently. An operator who wants one
process can run both binaries on the same host; their threat surfaces
differ, but their composition is clean.

## Endpoint catalog

Every endpoint is under `/v1/`. The gateway publishes its own OpenAPI 3
document at `/v1/openapi.json` and `/v1/openapi.yaml` — generated from
the same router that serves traffic, so the doc and the routes agree
by construction.

### Object I/O

| Method + path | `Library` method | Notes |
|---|---|---|
| `GET /v1/objects?address=...` | `read_raw` | `200` with body for `Bytes` / `Stream` / `LocalDelegate`; `307 Temporary Redirect` with `Location` + `X-OV-Audit-Id` for `Redirect`. Range reads via `Range:` header. |
| `GET /v1/objects:stat?address=...&full_metadata=true` | `stat` | Input-guided directory handling: `.../foo` stats exact object first, then `.../foo/` on `NotFound`; `.../foo/` stats only the directory spelling. |
| `PUT /v1/objects?dest=...` | `write` | Request body propagates as `Body::Stream` chunk-by-chunk (no host-side `Vec<u8>` drain) through a 16-slot bounded mpsc. |
| `DELETE /v1/objects?address=...` | `delete` | |
| `GET /v1/objects:list?prefix=...&recursive=true&full_metadata=true` | `list` | Per-item authz filtering via `filter_list_batch`. |
| `GET /v1/objects:versions?address=...` | `list_versions` | |
| `GET /v1/objects:latest-version?address=...` | `get_latest_version` | |
| `POST /v1/objects:copy` | `copy` | Decomposes server-side into `Read(src) + Write(dst)` for authz. |
| `POST /v1/objects:rename` | `rename` | Decomposes server-side into `Read(src) + Delete(src) + Write(dst)`. |
| `PUT /v1/directories?address=...` | `create_directory` | |
| `DELETE /v1/directories?address=...` | `delete_directory` | |
| `PATCH /v1/objects:metadata?address=...` | `update_metadata` | |
| `POST /v1/objects:check-access` | `check_access` | |
| `GET /v1/objects:watch-directory?prefix=...` | `watch_directory` | Server-Sent Events. `poll_interval_ms` enforces a 100 ms floor. Per-event authz drops are silent (no `Lapsed` synthesis). |

### Routing introspection and management

| Method + path | `Library` method |
|---|---|
| `GET /v1/capabilities?prefix=...` | `capabilities_for(prefix)` |
| `GET /v1/address-roots` | `list_address_roots` |
| `GET /v1/backend-kinds` | `list_backend_kinds` |
| `POST /v1/connections` | `add_connection` |
| `GET /v1/connections` | `list_connections` |
| `DELETE /v1/connections/{id}` | `remove_connection` |
| `POST /v1/connections:authenticate?id=...` | `authenticate_connection` (Server-Sent Events) |
| `POST /v1/aliases` | `add_alias` |
| `GET /v1/aliases` | `list_aliases` |
| `DELETE /v1/aliases/{id}` | `remove_alias` |
| `PUT /v1/address-visibility` | `set_address_visibility` |
| `GET /v1/address-visibility` | `list_address_visibility_overrides` |

### OpenAPI

| Method + path | Content |
|---|---|
| `GET /v1/openapi.json` | OpenAPI 3 (JSON), generated from the live router. |
| `GET /v1/openapi.yaml` | Same document as YAML. |

`ObjectInfo`, `Capabilities`, `WriteResult`, page envelopes, and error
envelopes are JSON. `list`, `list_versions`, and
`get_latest_version` surface `ObjectInfo` values directly; version
history items carry version-pinned addresses in `ObjectInfo.address`.
Object bodies are raw bytes with chunked
transfer encoding when the upstream `ReadResult` is `Stream` or
`LocalDelegate`. Query parameters are parsed strictly: booleans accept
exactly `true`/`false`/`1`/`0`; integers reject non-integer values
with `400 InvalidArgument`.

## Authentication

OIDC bearer tokens only. The gateway validates JWTs against a
configured JWKS using its built-in `JwtAuthenticator`. Configure
through `[server.oidc]` in `ovstorage.toml`:

```toml
[server.oidc]
issuer    = "https://login.example.com"
audience  = "ovstorage"
jwks_url  = "https://login.example.com/.well-known/jwks.json"
```

Or matching `OVSTORAGE_REST_OIDC_*` env vars (env wins). All three
must resolve, or none — partial config is a startup error. With no
OIDC config the gateway runs in **dev mode** and skips bearer
validation; do not expose dev mode on a public interface.

The JWKS document is fetched through a long-lived `reqwest::Client`
with a 10 s connect/read timeout and cached behind a 10-minute TTL. A
token presenting an unknown `kid` triggers a one-shot refetch before
being rejected, so routine IdP key rotation is absorbed without a
gateway restart.

API keys, Basic auth, mTLS, and other schemes are out of scope.
Deployments that need them put a reverse proxy in front. The gateway
doesn't accept mTLS because the typical caller is a human at an HTTP
client without a client cert.

### Precondition headers

Optimistic concurrency uses different headers depending on how many
precondition operands a route has.

**Single-operand routes** — read, delete, update-metadata, and
write — use the standard RFC 7232 headers directly. The target is
the only operand, so `If-Match` is unambiguous:

- `If-Match: "<etag>"` — the target's etag must match. Both the
  quoted form (`"<etag>"`) and a bare etag are accepted; a leading
  `W/` weak-etag prefix is tolerated.
- `If-None-Match: *` (write only) — the target must not exist. Only
  the literal `*` is accepted; any other value returns
  `400 InvalidArgument`. Mutually exclusive with `If-Match` on the
  same write request.

```http
DELETE /v1/objects?address=s3://bucket/file.txt
If-Match: "etag-from-the-last-write"
```

**Two-operand routes** — copy and rename — carry both a source and
a destination. RFC 7232's `If-Match` defines only one operand per
request, so a bare `If-Match` on these routes is ambiguous and
returns `400 InvalidArgument` pointing the caller at the explicit
per-operand headers:

- `X-OV-If-Source-Match: "<etag>"` — the source's etag must match
  (custom header, mirrors AWS S3's `x-amz-copy-source-if-match`).
- `X-OV-If-Dest-Match: "<etag>"` — the destination's etag must match.
- `If-None-Match: *` — the destination must not exist (no source-side
  analog: "destination must not exist" is unambiguous).

`X-OV-If-Dest-Match` and `If-None-Match` both target the destination
and are mutually exclusive on the same request. Sending both
`X-OV-If-Source-Match` and `X-OV-If-Dest-Match` is supported — the
two-sided "exactly-this-source onto exactly-that-destination" case
the services-client plugin wires through end-to-end. Etag values
accept the quoted or bare form on both custom headers; the `W/`
weak-etag prefix is tolerated.

```http
POST /v1/objects:copy
X-OV-If-Source-Match: "src-etag"
X-OV-If-Dest-Match: "dst-etag"
```

```http
POST /v1/objects:rename
X-OV-If-Source-Match: "src-etag"
If-None-Match: *
```

A request with no precondition headers runs unconditionally. The
backend's capability bits (`supports_if_match_write`,
`supports_no_overwrite_write`) decide whether the precondition is
honored or refused — read `GET /v1/capabilities?prefix=...` first when
in doubt.

## Connection, alias, and visibility management

Routing state changes through REST:

```http
POST /v1/connections HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{
  "backend_kind": "s3",
  "config": { "bucket": "my-bucket", "region": "us-east-1" },
  "credentials": { "fields": { "aws_access_key_id": "...", "aws_secret_access_key": "..." } },
  "persist": true,
  "display_name": "prod"
}
```

The response carries the new `Connection { id, current_addresses, ... }`.
`POST /v1/connections:authenticate?id=...` returns Server-Sent Events
for the auth flow (`OpenBrowser`, `DeviceCode`, `Progress`, `Succeeded`,
`Failed`, `Cancelled`); surface those events directly to the caller.

Aliases (`POST /v1/aliases`) and visibility overrides
(`PUT /v1/address-visibility`) operate on caller-facing `ObjectAddress`
values; authz checks `AddAlias(from)` plus `Read(to)` for alias
creation.

## Authenticate-flow SSE endpoint

`POST /v1/connections:authenticate?id=<connection-id>` returns
`text/event-stream`. Each `event:` line is one of:

- `OpenBrowser` — `data: { "url": "..." }`. The caller opens the URL.
- `DeviceCode` — `data: { "user_code": "ABCD-1234", "verification_url":
  "..." }`. The caller surfaces the code + URL.
- `Progress` — `data: { "message": "..." }`. Informational.
- `Succeeded` — terminal; the connection is now authenticated.
- `Failed` — terminal; the connection failed to authenticate.
- `Cancelled` — terminal; the caller cancelled.

Stop reading on any terminal event. Re-issue the request to retry.

## Configuration TOML shape

```toml
# ovstorage.toml — gateway-side

[server]
bind = "127.0.0.1:8443"

[server.oidc]
issuer    = "https://login.example.com"
audience  = "ovstorage"
jwks_url  = "https://login.example.com/.well-known/jwks.json"

# Optional: per-call authz (shared with the broker).
[authz]
plugin = "ovstorage-authz-toml"

[[authz.policy]]
id        = "team-read"
effect    = "allow"
principal = "team-*"
operations = ["read", "stat", "list"]
prefix    = "s3://corp-prod/team/"

# Routes flow through the embedded `Library`. Define backend
# connections inline or load them from XDG config; the shape is the
# same the CLI uses.
[[connections]]
backend_kind = "broker"
display_name = "corp"
config       = { address = "https://broker.corp.example.com" }

[[connections]]
backend_kind = "file"
display_name = "scratch"
config       = { root = "/var/lib/ovstorage/scratch" }
```

Resolution order: env vars (`OVSTORAGE_REST_OIDC_*`) override the TOML.
Partial OIDC config (any one of `issuer` / `audience` / `jwks_url`
present without the others) is a startup error. No `[authz]` section
runs in dev mode (allow-all); production deployments must configure
`[authz]` explicitly or place an authorization layer in front of REST.

## Streaming reads

`GET /v1/objects` honors all four `ReadResult` variants:

- **`Bytes`** — `200 OK` with the bytes in the body.
- **`Stream`** — `200 OK` with chunked transfer encoding; the plugin's
  `futures::Stream` forwards into `axum::body::Body::from_stream`
  with per-chunk errors mapping to `std::io::Error` at the body
  boundary. Peak gateway memory stays bounded by the plugin's chunk
  size times in-flight chunks.
- **`LocalDelegate`** — `200 OK` with chunked transfer; the file is
  opened with `tokio::fs::File` and wrapped in
  `tokio_util::io::ReaderStream`. Used by plugins that can only
  deliver bytes through the local filesystem (`file`, on-disk caches).
- **`Redirect`** — `307 Temporary Redirect` with the pre-signed URL in
  `Location` and an audit-correlatable `X-OV-Audit-Id` header. The
  caller's HTTP client follows the redirect and bytes flow cloud ->
  caller directly. The gateway's value here is amortized credential
  resolution and warm connections, not proxying bytes.

`Range:` headers are honored when the upstream backend's
`Capabilities` permits; inverted ranges
(`start > end_inclusive`) return `400 InvalidArgument`.

## Streaming writes

`PUT /v1/objects` propagates the request body chunk-by-chunk through a
16-slot bounded `tokio::sync::mpsc` and into the plugin's `write` as
`Body::Stream`. The whole pipeline is true-streaming: peak host
buffering is bounded by channel capacity (16 times chunk size)
regardless of total length. Plugins that do not implement
`write_stream` return `Unsupported` rather than collecting the stream
into a buffer.

**Why true-streaming is mandatory at this boundary.** REST is the
unauthenticated-input edge; any allowed client can send a multi-GB
body. A drain-to-`Vec<u8>` implementation would let one request force
the gateway to hold the whole body in memory — a trivial DoS. The
constraint propagates inward: every plugin's `write` impl must consume
`Body::Stream` chunk-by-chunk; no host-side hop may collect into a
single buffer.

## Error envelopes

Errors return JSON:

```json
{
  "ok": false,
  "code": "NotFound",
  "message": "object not found: s3://my-bucket/missing.txt",
  "audit_id": "..."
}
```

`code` is one of the stable `ErrorCode` taxonomy
(`NotFound`, `PreconditionFailed`, `Unsupported`, `PermissionDenied`,
`Transient`, `BrokerUnavailable`, `ResourceExhausted`, …). Match on
`code` rather than parsing `message`. Retry on `Transient`,
`BrokerUnavailable`, and `ResourceExhausted` with exponential backoff;
honor any `Retry-After` header.

## What's not in the REST surface

- **CORS.** No `tower_http::cors::CorsLayer` is layered; cross-origin
  access depends on a reverse proxy.
- **Rate limiting.** Deferred to a reverse proxy by policy.
- **TLS termination.** Deferred to a reverse proxy by policy.
- **Body-size limit.** No `DefaultBodyLimit` is configured today; the
  streaming-write pipeline bounds peak per-request memory, but a
  request-size cap is sensible defence-in-depth at the proxy.
- **Audit attribution.** `ovstorage` has no audit subsystem; only the
  `X-OV-Audit-Id` correlation header on `307` responses is observable.
- **S3-compatible REST surface.** The native REST surface at `/v1/` is
  the only HTTP surface ovstorage owns. Deployments that need
  S3-API tooling against ovstorage targets put an existing S3-gateway
  product in front of `ovstorage-rest`.
- **Server-side caching of read bytes.** REST reads go through
  `Library::read_raw`, which bypasses the byte cache by design — the
  gateway can hand `Redirect`, `Stream`, and `LocalDelegate` results
  back to the caller untouched. In-process Rust callers and the broker
  still see the cache.

For policy management, listener authn modes, observability, and the
broker's role in the brokered topology, see
[`docs/public/broker-operator/README.md`](../broker-operator/README.md).
