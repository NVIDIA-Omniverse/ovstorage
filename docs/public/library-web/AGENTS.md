# library-web — agent routing

Terse map for agents working on REST callers of `ovstorage-rest`. For
prose, see [README.md](README.md).

## Where to start

- **Endpoint catalog**: [README.md § Endpoint catalog](README.md#endpoint-catalog).
- **OpenAPI**: the gateway publishes its own document at
  `/v1/openapi.json` and `/v1/openapi.yaml`. Generate clients from
  there.
- **When to use REST vs gRPC broker**:
  [README.md § When to use REST vs the gRPC broker](README.md#when-to-use-rest-vs-the-grpc-broker).
  Short version: REST for HTTP-only callers (browser JS, Go, Java,
  shell); gRPC broker when you can link the `broker-client` plugin.

## Authentication

- Auth is fail-closed: the server `auth` field is required. `auth =
  "anonymous"` is the explicit unauthenticated allow-all opt-in.
- `[server.auth]` accepts `kind = "builtin-auth"` or a loaded wrapper
  kind whose descriptor declares `auth_capable = true`. Missing, unknown,
  non-wrapper, and non-auth-capable kinds fail startup.
- The built-in signed-JWT form reads `authn_mode = "jwt_verify"` plus
  `jwt_issuer`, `jwt_audience`, and `jwt_jwks_url` from
  `[server.auth.config]`. REST does not expose mTLS client certificates,
  trusted-proxy peers, or forwarded identity headers to built-in authn.
- A plugin auth factory receives `[server.auth.config]` verbatim and owns
  its schema and credential decoding. The gateway supplies the undecoded
  bearer from `Authorization` plus the TCP peer address.
- The REST process has no live auth-policy reload surface. Restart it to
  reconstruct either auth wrapper after changing its config.

## Precondition headers

Optimistic concurrency rides on different headers depending on how
many precondition operands the route has.

**Single-operand routes** — read, delete, update-metadata, write
(the target is the only operand) — use the standard RFC 7232
headers directly:

- `If-Match: "<etag>"` — the target's etag must match. Both the
  quoted form and a bare etag are accepted; a leading `W/`
  weak-etag prefix is tolerated.
- `If-None-Match: *` (write only) — the target must not exist. Only
  the literal `*` is accepted; any other value returns
  `400 InvalidArgument`. Mutually exclusive with `If-Match` on the
  same write request.

**Two-operand routes** — copy and rename (source + destination) —
use dedicated headers, one per operand. RFC 7232's `If-Match` has
no operand binding, so a bare `If-Match` on copy / rename returns
`400 InvalidArgument` pointing the caller at the explicit headers:

- `X-OV-If-Source-Match: "<etag>"` — the source's etag must match.
- `X-OV-If-Dest-Match: "<etag>"` — the destination's etag must match.
- `If-None-Match: *` — the destination must not exist (no source-side
  analog: destination-must-not-exist is unambiguous).

`X-OV-If-Dest-Match` and `If-None-Match` both target the destination
and are mutually exclusive on the same request. Sending both
`X-OV-If-Source-Match` and `X-OV-If-Dest-Match` is supported — that
is the two-sided "exactly-this-source onto exactly-that-destination"
case the services-client plugin wires through end-to-end. Etag values
accept the quoted (`"<etag>"`) or bare form on both headers; the
`W/` weak-etag prefix is tolerated.

Examples (copy / rename):

```http
POST /v1/objects:copy
X-OV-If-Source-Match: "src-etag-abc"
X-OV-If-Dest-Match: "dst-etag-xyz"
```

```http
POST /v1/objects:rename
X-OV-If-Source-Match: "src-etag-abc"
If-None-Match: *
```

No precondition header = unconditional. Backend capability bits
(`supports_no_overwrite_write`, `supports_if_match_write`) decide
whether each precondition is honored; check
`GET /v1/capabilities?prefix=...` in doubt.

## Streaming

- **Reads**: `GET /v1/objects` honors `ReadResult::Bytes` /
  `Stream` / `LocalDelegate` (all `200` with appropriate transfer
  encoding) and `Redirect` (`307` with `Location` + `X-OV-Audit-Id`).
  `Range:` honored where the backend supports it.
- **Writes**: `PUT /v1/objects` propagates the request body
  chunk-by-chunk through a 16-slot bounded mpsc. Never drains to
  `Vec<u8>`. Plugins that can't stream return `Unsupported`.
- **Watches**: `GET /v1/objects:watch-directory` is Server-Sent
  Events. Per-event authz drops are silent (no `Lapsed` synthesis);
  upstream `Lapsed` events pass through.

## Errors and etags

- JSON envelope `{ ok: false, code: "...", message: "...", audit_id: "..." }`.
- Match on `code` (stable `ErrorCode` taxonomy), not `message`.
- Retry on `Transient`, `BrokerUnavailable`, `ResourceExhausted`,
  `DeadlineExceeded`, `CacheLockContention`, and
  `AuthorizationLeaseExpired` with exponential backoff; honor
  `Retry-After`.
- Capture the response's `etag` and pass it back as
  `If-Match: "<etag>"` on the next read / delete / write (or
  `X-OV-If-Source-Match: "<etag>"` / `X-OV-If-Dest-Match: "<etag>"`
  on the next copy / rename) for optimistic concurrency.

## Deployment notes (for callers)

- CORS, rate limiting, TLS, body-size caps, IP allow-lists: not in
  the gateway. Put a reverse proxy in front.
- The gateway is the unauthenticated-input edge; the broker is the
  credential boundary in Brokered mode. Sensitive cloud credentials
  never reach the host that calls REST in the canonical
  REST -> broker -> cloud chain.

## What lives elsewhere

- Plugin author concerns (writing a backend) are in
  [plugin-storage AGENTS](../plugin-storage/AGENTS.md) and
  [plugin-development AGENTS](../plugin-development/AGENTS.md).
- Broker operator concerns (deployment, listener authn modes, policy,
  TLS, observability) are in
  [broker-operator README](../broker-operator/README.md).
- Authorization policy concerns are in the
  [authorization policy guide](../authz-policy/README.md).
