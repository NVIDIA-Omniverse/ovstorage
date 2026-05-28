# Anonymous HTTP plugin (`http`)

Read-only plugin for anonymous HTTP / HTTPS URLs. Writes return
`Unsupported`. HTTP and HTTPS share a single plugin because the
on-the-wire protocol differences (TLS, default port) are immaterial
to object-retrieval semantics; whether to permit unencrypted
fetches is expressed by which prefixes the operator routes to the
plugin.

**Public surface**

- **Schemes**: `http://` and `https://`.
- **Descriptor**: `kind = "http"`, `display_name = "Anonymous HTTP"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `root_url` (**required**, URL string): HTTP URL prefix served
    by this connection.
  - `prefix` (optional, URL string): caller-facing route prefix;
    defaults to `root_url`.
  - `default_headers` (optional, comma-separated `Name=Value` pairs)
    for caller-pinned non-secret headers such as a corporate
    `User-Agent`. `Authorization`, `Cookie`, and
    `Proxy-Authorization` are rejected at `instantiate`
    (case-insensitive); authenticated HTTP belongs behind a broker
    or reverse proxy.
  - `redirect_policy` (optional enum, default `same_origin`):
    `none`, `same_origin`, or `allow_list`.
  - `redirect_allow_hosts` (optional, comma-separated host list,
    consulted when `redirect_policy = "allow_list"`).
  - `allow_range_stat_fallback` (optional bool, default `false`)
    lets `stat` fall back from `HEAD` to `GET Range: bytes=0-0` when
    the origin returns 405.
- **Credential keys**: none. The plugin is anonymous-only;
  authenticated HTTP retrieval is the broker's job or an operator's
  reverse-proxy concern.

Operators control which URLs the plugin handles entirely through
routing. A route at `https://` matches every HTTPS URL; a route at
`https://datasets.example.com/` matches only that host; with no
route bound to the plugin, no URL reaches it and the library
returns `NoRoute`.

```toml
# A connection picks the plugin and supplies its required config.
[[connections]]
display_name = "anonymous-https"
backend_kind = "http"

[connections.config]
root_url = "https://"

# Routes bind a caller-facing prefix to a connection. The route
# table uses [[routes]] (plural).
[[routes]]
prefix     = "https://"
connection = "anonymous-https"

# Per-host route + per-host connection (operators that want a tight
# allow-list per origin can use one connection per origin):
[[connections]]
display_name = "datasets-example"
backend_kind = "http"

[connections.config]
root_url = "https://datasets.example.com/"

[[routes]]
prefix     = "https://datasets.example.com/"
connection = "datasets-example"
```

**Internals — URL handling**

The plugin treats the full canonicalized HTTP(S) URL as the object
address. Scheme and host are canonicalized by `address::parse`;
path bytes and query parameters are preserved. Fragment identifiers
are rejected with `InvalidArgument` at `instantiate` time via the
shared `validate_route_url` helper applied to `root_url` and
`prefix`; fragments are client-side document selectors and never
sent to an HTTP server. Query strings may contain signed-URL
credentials even though the plugin has no credential fields, so
logs, errors, and conformance traces should use the shared
redaction rule (request-line without query, no `Authorization`-shaped
headers).

When `prefix` differs from `root_url`, the backend stores both.
Each `stat`/`read` call rewrites the dispatcher's caller-facing
`resolved_address` via `address::replace_prefix(&resolved_address, &prefix, &root_url)`
before issuing the HTTP request, so the wire request hits
`root_url` even when the operator has chosen a different
caller-facing scheme/host. `ObjectInfo.address` continues to carry
the caller-facing URL.

Provider-native cloud HTTPS addresses are not interpreted here. If
an operator wants `https://bucket.s3.amazonaws.com/key` to behave
like S3, they route that prefix to `plugin-s3`; if they route it to
`plugin-http`, it is an anonymous HTTP object with only HTTP
metadata and no S3 versioning, tags, or precondition semantics.

**HTTP status codes surface as typed errors, not as body bytes.**
The plugin translates: `404 → NotFound`, `401 → AuthRequired` (with
`ErrorContext::Auth { reason: "http_unauthorized" }`),
`403 → PermissionDenied` (final, no retry),
`429 → ResourceExhausted`, `5xx → Transient`, `2xx → body`. A call
to `read_bytes` on a URL that returns a 403 page produces a
`PermissionDenied` error, not a successful read of the error page.

Whole-object reads (no `range`) return `ReadResult::Stream`,
bridging `reqwest::Response::bytes_stream()` directly into the
host's chunk iterator without an intermediate `Vec<u8>`. The stream
is wrapped in a `CancelableStream` adapter that, on each
`poll_next`, races the upstream chunk against the host's
`CancellationToken`; on cancellation the wrapper yields one
`Err(ErrorCode::Cancelled)` and then ends. Range reads buffer, but
the buffered body is bounded by the requested range length —
an origin that ignores `Range` and returns a giant `200 OK` cannot
force an unbounded allocation. HTTP 3xx redirects are ordinary
transport behaviour controlled by `redirect_policy`, not ovstorage
redirect results. `same_origin` follows only redirects that
preserve scheme, host, and effective port; `allow_list` follows
redirects to hosts in `redirect_allow_hosts`; `none` disables
redirect following entirely (3xx surfaces as `Unsupported`).

`stat` uses `HEAD`. When the origin returns 405 and
`allow_range_stat_fallback = true`, the plugin retries with
`GET Range: bytes=0-0` capped at a 2-byte budget; if the origin
returns `200 OK` (i.e., ignores the Range), the fallback returns
`Unsupported` rather than buffering the full body. Range reads
(`ReadOptions.range`) translate to `Range:` headers; a
`206 Partial Content` response is returned as-is.

`ObjectInfo` fields populate from HTTP validators directly:
`ObjectInfo.etag` carries the response `ETag` header value exactly as
returned (including a `W/` weak-marker prefix); `Last-Modified` is
parsed into `mtime` when present. `size` is populated from
`Content-Range`'s total when present, then from `Content-Length`,
then from the observed buffered length. Streaming responses without
`Content-Length` (chunked transfer) leave `size = None`. Weak ETags
(`W/"…"`) are surfaced for diagnostics but never satisfy an exact
`ReadOptions::if_match`. The SPI etag string maps to the wire
`If-Match` header verbatim. `If-None-Match: *` is unsupported because
the plugin is read-only.

No user-metadata facility — reads return an empty `UserMetadata`
map and `update_metadata` returns `Unsupported`. `watch_directory`
likewise returns `Unsupported`; HTTP has no native change feed.
Response headers from the wire are surfaced as `system_metadata`
(lower-cased keys) on `stat` and `read`.

Capability bits are correspondingly sparse: no write, delete, list,
version listing, metadata patch, access check, directory, or
watch_directory capabilities are advertised. `supports_recursive_list`
and `supports_list` are false for this plugin; the URL identifies a
single resource, not a browsable collection.

Status-code mapping (full table): `401 → AuthRequired`,
`403 → PermissionDenied`, `404 → NotFound`, `405 → Unsupported`,
`408 → Transient`, `412 → ObjectModified` (with
`ErrorContext::Identity { new_etag }` populated from the response's
`etag` when present),
`429 → ResourceExhausted`, `5xx → Transient`, anything else →
`Unsupported`, plus `reqwest::Error::is_redirect → Unsupported` so
a redirect-policy block surfaces cleanly. Idempotent retry is
owned by the host library per the workspace
`no_retry_on_transient_pinned` invariant; the plugin does not run
an in-plugin retry loop.

**Threat model**

The plugin is anonymous-only; it never accepts caller-supplied
credentials and never reads ambient ones. Operators concerned about
exfiltration to arbitrary hosts route only the prefixes they trust
to the plugin; with no route bound, the plugin sees no traffic.
There is no caller-side mTLS; deployments that need it route
through a reverse proxy that adds the client cert.
