# HTTP plugin (`http`)

Read-only plugin for HTTP / HTTPS URLs, anonymous or authenticated. The
broker can additionally supply a per-principal OAuth bearer through its
internal request-credential boundary. Writes
return `Unsupported`. HTTP and HTTPS share a single plugin because the
on-the-wire protocol differences (TLS, default port) are immaterial
to object-retrieval semantics; whether to permit unencrypted
fetches is expressed by which prefixes the operator routes to the
plugin.

`http` is an **ABI-v2 Layer plugin**: its backend is exported via
the `ovstorage_layer_plugin!` macro and loaded onto the internal v2
Stack. The `ovstorage-plugin-http` crate contains the reusable Rust
implementation; the `ovstorage-plugin-http-abi` package builds the shipped
`libovstorage_plugin_http.so` cdylib so fixed-name ABI exports never enter an
in-process Rust dependency.

**Public surface**

- **Schemes**: `http://` and `https://`.
- **Descriptor**: `kind = "http"`, `display_name = "HTTP"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `root_url` (**required**, URL string): HTTP URL prefix served
    by this connection.
  - `prefix` (optional, URL string): caller-facing route prefix;
    defaults to `root_url` with its userinfo removed. An explicitly
    configured prefix is taken as written, except that one embedding
    userinfo is refused. A malformed `prefix` is a load error instead
    of silently falling back to `root_url`.
  - **Neither `root_url` nor `prefix` may carry a query or a
    fragment.** Both are addresses, and an address names a node:
    requests are routed on scheme, authority and path alone, and a
    fragment never reaches a server at all. A config value carrying
    either is a load error naming the component. A signature that needs to
    ride on every request belongs in the `signed_query` credential; see
    [Signed roots are declared credentials](#signed-roots-are-declared-credentials).
  - `default_headers` (optional, comma-separated `Name=Value` pairs)
    for caller-pinned non-secret headers such as a corporate
    `User-Agent`. `Authorization`, `Cookie`, and
    `Proxy-Authorization` are rejected at `instantiate`
    (case-insensitive); use the credential keys below instead. Nothing
    stops another header name carrying a secret, so treat this field as
    the non-secret surface it is documented to be: the HTTP client's
    redirect-stripping list is fixed at those three names plus
    `WWW-Authenticate`, so any other header **is forwarded across an
    `allow_list` redirect to another host**. A connection with pinned
    headers is refused a cleartext downgrade for the same reason.
  - `redirect_policy` (optional enum, default `same_origin`):
    `none`, `same_origin`, or `allow_list`.
  - `redirect_allow_hosts` (optional, comma-separated host list,
    consulted when `redirect_policy = "allow_list"`).
  - `allow_range_stat_fallback` (optional bool, default `false`)
    lets `stat` fall back from `HEAD` to `GET Range: bytes=0-0` when
    the origin returns 405.
  - `signed_query_scope` (required when `signed_query` is supplied):
    `prefix` declares that one token covers every object under `root_url`;
    `object` is refused as `Unsupported` because a connection cannot safely
    hold a per-object signature.
- **Credential keys** (named literally, because the Python
  `BackendKindDescriptor` does not expose `credential_schema`):
  - `bearer_token` — sent as `Authorization: Bearer <token>` (RFC 6750).
  - `username` + `password` — sent as `Authorization: Basic <base64>`
    (RFC 7617). Both keys are required together; supplying one and
    omitting the other is `InvalidArgument`. Either *value* may be
    empty, which RFC 7617 permits and services do issue — an API key as
    the user-id with no password is the common spelling. Both empty is
    `InvalidArgument`: it authenticates as nobody.
  - `signed_query` — a pre-issued query string appended byte-for-byte to
    every request (an optional leading `?` is removed). It requires
    `signed_query_scope = "prefix"`. Recognized per-object families such as
    SigV4 presigns, Azure blob SAS tokens, and CloudFront canned policies are
    refused. A CloudFront custom policy must contain one trailing-wildcard
    Resource that covers `root_url`.
  - `secret_headers` — one `Name: Value` per line. Values may contain commas,
    repeated names are preserved, and all values are marked sensitive.
    Authority, framing, hop-by-hop, `Range`, and `If-Match` headers are
    refused. `Authorization` is allowed only when Basic, Bearer, and
    `root_url` userinfo do not already write it.
- **Credential methods**: `bearer`, `basic`, `signed_query`, and
  `secret_headers`. Distinct channels combine; competing Authorization
  writers do not. Values are never rewritten: a trailing newline in a
  single-value credential is reported rather than trimmed, and signed-query
  bytes are validated after URL construction. Only raw-bytes secrets are
  accepted; the plugin has no token-refresh path, so the host rotates an
  expiring secret through `update_connection_credentials`.
- **Broker-attached OAuth**: when the plugin runs inside `ovstorage-broker`,
  the broker-owned `upstream_credential` layer may attach a non-secret keyring
  reference for the authenticated principal. The plugin consumes that
  reference for one request and loads the access token through host callbacks;
  token bytes do not enter the request extension bag. HTTP is the only shipped
  first-party backend with this read-side consumer registration; bindings for
  other backend kinds fail closed unless a trusted host integration registers
  and implements the same capability.
- **Credentials require TLS.** A connection that authenticates over
  `http://` is rejected unless the host is loopback (`127.0.0.0/8`,
  `::1`, `::ffff:127.0.0.0/104`, `localhost`). This covers every declared
  channel, because a credential is whatever this connection sends that
  the caller did not: all credential fields above, and userinfo embedded
  in `root_url`, which the HTTP client turns into the same Basic header.
  The loopback exemption also disables proxying for that connection,
  because the client honours `HTTP_PROXY` by default and a proxied
  cleartext request would carry the credential to a host that is not
  loopback at all. Every secret-bearing connection also refuses an `https` → `http`
  redirect hop: `Authorization` is dropped by the transport only when
  the host or port changes, so a same-host downgrade would otherwise
  carry it in clear — and a header pinned through `default_headers` is
  dropped on no hop at all, so the refusal is the only thing between it
  and cleartext. The follow set itself is still whatever
  `redirect_policy` says, which is `same_origin` unless configured
  wider. And no `Referer` is sent on any redirect hop — the transport's
  default sends the previous URL and strips only userinfo and the
  fragment, so a **caller's** query, which is where a presigned URL
  carries its signature, would otherwise travel to the next host in a
  header no redirect policy short of `none` inspects.
- **`root_url` must be `http://` or `https://`.** It is the physical
  origin every request is rewritten onto, so an unusable scheme is
  rejected at connect rather than failing every read. `prefix` is
  caller-facing and may use another scheme.
- **`Authenticated` requires positive evidence.** The connect-time probe
  reports it only when a `HEAD` on `root_url` answered `2xx`. A `401` is
  a refusal and reports `AuthFailed`. **Everything else establishes
  nothing** — a redirect the policy did not follow, `403`, `404`, `405`,
  `429`, `5xx` — and the connection registers saying exactly that, with
  the observed status named in the note so the operator can tell which
  of them arrived.
  `403` in particular is not treated as acceptance: a rejected token and
  a valid one with a restricted policy are indistinguishable from the
  status alone, and a `HEAD` carries no body to discriminate with.
  **This is reporting only — the connection is registered and serves
  reads in every one of these cases.** An origin whose root has no index,
  or that refuses `HEAD` (the case `allow_range_stat_fallback` exists
  for), therefore reports an unconfirmed credential while working
  normally. The check is black-box, so it also cannot detect an origin
  that ignores `Authorization` altogether.

  `ovstorage connect` reports an `AuthFailed` through its **exit status**:
  it prints `Registered, but not authenticated` rather than `Connected`
  and exits non-zero, because a script can read a status and cannot read
  a warning on stderr. An unproven state is not a failure and still exits
  0, but it does not say `Connected` either — the headline is
  `Registered, credential unconfirmed`. So `Connected` means the identity
  is settled, and nothing else.

  It does **not** delete the connection. The probe is a `HEAD` on the
  root, and an origin that challenges its root while serving the objects
  beneath it is an ordinary shape, so the registration and its routes
  survive and reads may well work. A declared
  `[[ovstorage.connections]]` entry is unaffected either way, because a
  host must be able to start with an expired secret in its config.

  A route prefix a connection *added* through the graph is exclusive (see
  below), so a mistyped credential keeps the prefix for the rest of an
  interactive `ovstorage` session. Two commands clear it: re-running `connect` on the same
  origin with the corrected credential replaces the refused one in place, and
  `disconnect` removes the connection outright. Rotation needs the corrected
  value in the credential *bundle* — `--auth basic`, `--auth bearer` — because
  that is what `update_connection_credentials` replaces; a credential carried
  as userinfo on `root_url` is not in one, so that spelling answers
  `RouteConflict` instead of rotating.

  Which command is the way back then depends on where the connection came
  from, and userinfo on `root_url` is spelled both ways:

  - **From `connect`, or from an `[[ovstorage.connections]]` entry** —
    `disconnect` removes it, and a fresh `connect` takes the prefix back.
  - **From a layer's own `[ovstorage.layers.<name>]` block** — neither command
    finishes the job, and both say so rather than pretending. `disconnect`
    refuses with `Unsupported`, because the seed is not an
    `[[ovstorage.connections]]` entry for it to drop and `write-config` would
    re-serialize the layer block and rebuild the connection on the next start.
    `connect` has no way in either: re-spelling the credential as userinfo
    leaves the bundle empty, so there is nothing to rotate and the
    `RouteConflict` stands, and supplying it as `--auth basic` instead is
    refused with `InvalidArgument` — the connection keeps the `root_url` it was
    built with, userinfo and all, and a bundle beside it would write
    `Authorization` twice. **Correct the credential in the layer block and
    restart** — that is the change that lasts, and it is what `disconnect`'s own
    refusal tells you.

  Nothing is persisted on its own — `connect` registers with
  `persist: false`, so a one-shot invocation takes the registration with
  it when the process exits. The exception is deliberate: `write-config`
  serializes the session's connections, so a refused one written that way
  is persisted with everything else and outlives the restart. Declared
  connections and the broker are unaffected.

  Two separate mechanisms produce the collision. Publishing the
  userinfo-*stripped* address gives two spellings of one origin the same
  prefix. And a second connection on a root another
  already serves anywhere in the graph is *refused* rather than
  silently shadowed — so a mistyped `bearer_token`
  or `password`, which submits an identical `root_url` both times and is
  unaffected by userinfo at all, hits the same wall.

- **Two connections ADDED to one composed graph cannot publish the same root.**
  The HTTP layer refuses a duplicate held by the same layer instance, and a
  router refuses a same-node root from a sibling child at the aggregation
  boundary, then removes the newcomer from that child. **The router's half
  covers connections that arrive through it** — `[[ovstorage.connections]]`
  entries, which the host applies with `add_connection`, and `ovstorage
  connect` — and not one a backend builds from its own
  `[ovstorage.layers.<name>]` block, which is installed inside the layer before
  the router exists to be asked. See the layer-instance case below. The comparison is node equality,
  not containment — connections may publish `https://h/` and
  `https://h/sub/` at once, including from sibling layers, and both are
  routable because lookup is longest-prefix-wins. The router's refusal applies
  when *every* root a connection publishes is already served; a connection that
  also serves roots of its own keeps them, and only the contested root is
  shadowed — on the newcomer's side, so the connection already serving an
  address keeps serving it no matter which child of the router each sits on.
  An HTTP connection publishes exactly one root, so for this backend
  any collision is total and the refusal always applies — the distinction
  matters for the discovery-rooted backends, which publish many. A runtime
  `add_connection` is rejected with `RouteConflict` — the same code
  `nucleus` uses for a duplicate server root, and deliberately not the
  vaguer `AlreadyExists`, which other layers use for a duplicate
  connection *id*. The message names only the origin, because a route
  prefix can carry a secret in its userinfo, its query or its path, and
  the origin is the part that structurally cannot. Accepting a duplicate
  would leave one connection registered, unroutable, and its credential
  silently unused. A **declared** `[[ovstorage.connections]]` duplicate is
  reported on the tracing channel and skipped instead: the graph already
  serves that exact root, so the addresses the newcomer would answer for
  resolve to the incumbent whatever the host does. It could not be routed
  however the host reacted, so refusing to start would buy that connection
  nothing and cost every unrelated backend in the graph — and a host that
  auto-restarts would loop. Because the default prefix strips userinfo,
  two connections to one origin that differ only in their userinfo
  collapse onto one prefix; the incumbent owns it. Use distinct explicit
  `prefix` values when two connections need separate address spaces.
- **Header-credential scope is the origin, not the path.** `root_url` is a URL
  *prefix*, but the only header scope enforced on a redirect is the origin:
  with `root_url = https://host/private/` and the default
  `redirect_policy = "same_origin"`, a redirect to
  `https://host/collector` is followed and still carries the credential.
  Do not point a credential-bearing connection at an origin you do not
  fully trust. A held query has its own explicit `signed_query_scope`; a
  recognized per-object signature is not accepted on a connection. The
  connect-time
  probe follows the **configured redirect policy intersected with
  same-origin** — a same-origin hop under `same_origin` or a matching
  `allow_list`, and nothing at all under `redirect_policy = "none"` — and
  stops at an origin change. So a connection whose root redirects off its
  origin, and one whose policy forbids the hop, both report that nothing
  was established rather than claiming either outcome. A `2xx` reached
  after a hop is evidence only when it landed on `root_url` itself
  (trailing-slash normalization aside): an origin that bounces an
  unaccepted credential to a sign-in page answers `2xx` from that page
  exactly as an accepted credential would.
- **An authorized redirect hop receives the connection credentials.** The
  plugin builds every hop itself and re-applies Basic/Bearer authorization,
  signed-query parameters, and secret headers. `same_origin` is the safe
  default. With `allow_list`, listing a host explicitly authorizes sending the
  connection's credentials to that host; the host match intentionally permits
  any port. Userinfo injected by `Location` is stripped, and the root's own
  userinfo is retained only on same-origin hops.
- **Refreshing values uses `Layer::update_connection_credentials`.** The
  plugin resolves and probes a replacement while the old immutable snapshot
  continues serving, then swaps it atomically. Rotation preserves the exact
  shape: Authorization method, signed-query presence, and secret-header names
  and multiplicity. Remove and re-add the connection to change that shape or
  its `signed_query_scope`. A refused replacement leaves the old credential
  untouched.
- **Declared credential fields only reach the plugin through a
  connection.** The `[ovstorage.layers.http]` static-layer shape supplies
  an empty bundle, so `bearer_token` / `username` / `password` /
  `signed_query` / `secret_headers` must come
  from `add_connection` — `ovstorage connect`, or an
  `[[ovstorage.connections]]` entry. Userinfo is the exception: a
  statically configured
  `root_url = "https://user:pass@host/"` authenticates, is held to the
  same TLS rule, and is probed the same way. Either half may be empty,
  as for the declared fields; a wholly empty `://:@` is normalized away
  by URL parsing and is simply an anonymous connection.

Operators control which URLs the plugin handles entirely through
routing. Each connection declares a concrete HTTP(S) origin or narrower URL
prefix such as `https://datasets.example.com/`; with no route bound to the
plugin, no URL reaches it and the library returns `NoRoute`, unless the host
grants an anonymous `http`/`https` fallback — the top-level
`anonymous_http_fallback` key on the broker and the REST gateway, whose default
`"refuse"` keeps that answer and whose `"allow"` is refused at startup in this
release, because the per-origin tier that would honour it is not available and
a grant that did nothing would be worse than one that fails loud. It is a
separate switch from the cloud schemes' `anonymous_fallback_schemes` because it
means something different: an http fallback is not a public bucket but an
arbitrary origin, fetched from the host's own network position. See the
`anonymous_fallback` section of [`../configuration.md`](../configuration.md).

The plugin is wired into an `[ovstorage]` Stack: a `router` layer with an
`http` backend-layer child, plus one connection per origin. A connection's
`root_url` (or its optional `prefix`) is the caller-facing route it
serves; the router dispatches each URL to the child whose connection
serves a matching prefix. There is no separate route table — see
[`../configuration.md`](../configuration.md) for the full schema.

```toml
[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["http"]

# The `http` backend layer; its `kind` defaults to the layer name.
[ovstorage.layers.http]

# A connection picks the plugin, supplies its config, and serves one concrete
# origin or narrower URL prefix. Its `target` defaults to `backend_kind`, so it
# attaches to the `http` layer above.
[[ovstorage.connections]]
display_name = "datasets-example"
backend_kind = "http"
config = { root_url = "https://datasets.example.com/" }
```

**Internals — URL handling**

The plugin treats the full canonicalized HTTP(S) URL as the object
address. Scheme, host and path are canonicalized by `address::parse`.

**A request address keeps its query and loses its fragment.** A caller
pins a version or presents a presigned URL through the query, so it is
carried onto the wire; a fragment is a client-side document selector
that never reaches a server, so `https://origin/doc#section` requests
`https://origin/doc`.

**A configuration address may carry neither**, and that asymmetry is the
whole rule: `root_url` and `prefix` are refused a query or a fragment at
load, because a value the system would drop or route on differently from
how it reads must not be accepted in silence. Query
strings may contain signed-URL credentials, so logs, errors, and
conformance traces should use the shared redaction rule (request-line
without query, no `Authorization`-shaped headers). Errors raised from the HTTP client drop
the request URL entirely rather than relying on the shared query-key
allowlist, which covers only known provider parameters.

> **One path pipeline applies to every scheme, `http:` and `https:`
> included, and that is a decision rather than an oversight.** For every other
> backend the address is used to *derive a key*; here the address **is the
> wire URL**, so decoding percent-escapes and collapsing runs of `/` changes
> which resource is fetched:
>
> | written | fetched |
> |---|---|
> | `https://h/a//b` | `https://h/a/b` |
> | `https://h/pkg%2Fv1.tgz` | `https://h/pkg/v1.tgz` |
> | `https://h/x%3Bj=1` | `https://h/x;j=1` |
>
> There is no escape hatch and no opt-out.
>
> **Why it is the same rule here.** An encoded slash inside a path segment is
> a well-known source of authorization bypasses: two spellings reach one
> resource, and any check that compares them as strings can be made to
> disagree with the server that resolves them. A system that cannot express
> the distinction cannot be tricked by it, and `https://h/pkg%2Fv1.tgz`
> fetching `/pkg/v1.tgz` is what most readers expect the URL to mean anyway.
> The uniform rule is preferred to a scheme-specific exception on those
> grounds, not merely accepted for uniformity's sake.
>
> **What it costs, stated as a boundary rather than as a defect.** An origin
> where an encoded slash inside one segment is load-bearing — Artifactory- and
> GitLab-style package paths — **is not addressable through this plugin**, and
> there is no spelling that works: double-encoding is not an escape hatch,
> since `https://h/a%252Fb` is left alone and puts a literal `%252F` on the
> wire. The same goes for a doubled separator that the origin treats as
> significant, and for a raw `;` that Tomcat or Jetty reads as a path
> parameter. If that describes your origin, this plugin is not the way to
> reach it; that is a scope statement, not a limitation awaiting a fix.

**Userinfo in `root_url`** (`https://user:pass@host/`) authenticates —
the HTTP client turns it into a Basic header — but it is not published.
`prefix` defaults to a *userinfo-stripped* copy of `root_url`, so
`BackendId`, `RootInfo` and `ObjectInfo.address` carry no password. An
object served by `root_url = "https://user:pass@host/"` is therefore
addressed as `https://host/x`. Publishing the userinfo-bearing spelling
alongside it would re-publish the secret, so only the stripped one is
registered.

A caller's address that carries userinfo — `https://user:pass@host/x` — still
**routes**, because userinfo is
not part of what an address names — routing compares scheme, host, port and
path. What it does
not do is travel: the credentials on a caller's address are dropped before
the request is built, so they never become an `Authorization` header and
the origin sees the same request either spelling produced. A caller cannot
choose the credentials the connection authenticates with; only `root_url`
and the declared credential fields do that. Userinfo in an
explicitly configured `prefix` is rejected. Userinfo combined with another
Authorization writer — Bearer, declared Basic, or an `Authorization` entry in
`secret_headers` — is rejected because the client would emit two values with
no rule for which the origin honours. A signed query or a non-Authorization
secret header is a distinct channel and may coexist with userinfo.

When `prefix` differs from `root_url`, the backend stores both.
Each `stat`/`read` call rewrites the dispatcher's caller-facing
`resolved_address` via `address::replace_prefix(&resolved_address, &prefix, &root_url)`
before issuing the HTTP request, so the wire request hits
`root_url` even when the operator has chosen a different
caller-facing scheme/host. `ObjectInfo.address` continues to carry
the caller-facing URL.

**Two connections cannot publish one address space.** Only one connection can
own a caller-facing prefix, so a second `root_url` (or explicit `prefix`) that
resolves to the same published address is refused with `RouteConflict` naming
the origin. The HTTP layer enforces that within one instance, and a router
enforces it between sibling children — for every connection **added** through
the graph, which is what an `[[ovstorage.connections]]` entry and `ovstorage
connect` both are. Registering both would leave one permanently unroutable
while every read under the prefix went out over the incumbent connection, with
nothing in the response naming the substitution.

> **A connection seeded by a layer's own config is not covered.** A non-empty
> `[ovstorage.layers.<name>]` block makes this backend build one connection from
> it at startup, inside the layer, before any router exists to be asked — so
> nothing refuses a collision between two such layers. **If you configure two
> backend layers of the same kind against one origin, give their connections
> distinct `prefix` values.** Two `http` layers whose `root_url`s differ only in
> userinfo publish one prefix twice: both register, both probe with their own
> credential, `list-routes` prints the prefix twice, and every read is served by
> whichever the router aggregated first while the other credential is silently
> unused. Nothing refuses it and nothing stops startup, but it is reported
> rather than left to be discovered: `ovstorage doctor` lists it under
> **Contested address roots**, naming the origin and how many layers publish it,
> and the router logs it once per distinct collision when the graph aggregates
> the roots — at construction and on any later rebuild, since neither path has
> an add to refuse. `list-routes` printing one prefix twice and
> `list-connections` showing the shadowed side with an empty `target` are the
> same fact seen from two other angles.

The comparison is by **node**, not by spelling, so `https://origin/c` and
`https://origin/c/` collide too — the router treats them as one address space,
and a refusal that keyed on the exact bytes would let both connections install
and then serve all their traffic from whichever arrived first. The same holds
for two explicitly configured prefixes differing only in a trailing slash.

Give each connection an explicit `prefix` instead, so the two address spaces
stay distinct:

```toml
[[ovstorage.connections]]
backend_kind = "http"
config = { root_url = "https://origin-a/c/", prefix = "https://tenant-a/c/" }

[[ovstorage.connections]]
backend_kind = "http"
config = { root_url = "https://origin-b/c/", prefix = "https://tenant-b/c/" }
```

A host that declares both without explicit prefixes logs the refusal and
starts with the second connection absent, rather than refusing to start.

**Nothing from the route address is added to the query.** `root_url` and
`prefix` may not carry one. The caller's query survives projection unchanged;
when the connection holds `signed_query`, its exact bytes are appended after
the caller's parameters (`&` when a query is already present, otherwise `?`).

Provider-native cloud HTTPS addresses are not interpreted here. If
an operator wants `https://bucket.s3.amazonaws.com/key` to behave
like S3, they route that prefix to `plugin-s3`; if they route it to
`plugin-http`, it is a plain HTTP object with only HTTP
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
redirect following entirely (3xx surfaces as `Unsupported`). The plugin
applies the connection's credentials to each authorized hop, so an
allow-listed host is a deliberate credential recipient. The complete redirect
chain shares one 30-second deadline rather than restarting the timeout at each
hop.

**One destination is refused under every policy.** A redirect whose `Location`
resolves to a cloud instance-metadata endpoint — any IPv4 address in
`169.254.0.0/16`, `100.100.100.200`, `168.63.129.16`, any IPv6 address in
`fe80::/10`, `fd00:ec2::254`, an IPv6 address embedding a refused IPv4
address, or the exact names `metadata.google.internal`, `metadata.goog` and
`metadata`, never a suffix — answers `PermissionDenied` (`refusing to contact
<origin>: it is a cloud instance-metadata endpoint, and ovstorage never
fetches from one on a caller's behalf`) under `none`, under `same_origin`, and
under `allow_list` with that very host listed in `redirect_allow_hosts`. The
destination is judged before the follow policy is consulted, which is why the
answer under `none` is this typed error rather than the `Unsupported` an
unfollowed 3xx otherwise earns: the payoff of that one fetch is the process's
own cloud credentials rather than data, no operator setting makes it
acceptable, and a refusal folded into the policy check would be
indistinguishable from a hop the policy merely declined. The message names the
origin only, because the path and query of
such a URL are the server's and not worth echoing. The same predicate guards
the host's redirect follower: a `ReadResult::Redirect` or `WriteStep::Redirects`
that any backend mints — S3, GCS, Azure, Hugging Face, Nucleus — is judged
before a socket opens on the first attempt, on every re-mint after expiry or a
`403`, and on every mid-stream resume, for every connection of every kind.
What the check does not catch is a name that resolves to a link-local address;
only a connector that checks the resolved address before dialing would close
that. A configured `root_url` at such a host is the operator's own choice
rather than a server's, so `instantiate` honours it and logs one `warn`
(`configured root_url names a cloud instance-metadata endpoint; every request
on this connection reaches it from this process's network position`).

`stat` uses `HEAD`. When the origin returns 405 and
`allow_range_stat_fallback = true`, the plugin retries with
`GET Range: bytes=0-0` capped at a 2-byte budget; if the origin
returns `200 OK` (i.e., ignores the Range), the fallback returns
`Unsupported` rather than buffering the full body. Range reads
(`ReadOptions.range`) translate to `Range:` headers; a
`206 Partial Content` response is returned as-is.

`ObjectInfo` fields populate from HTTP validators directly. The plugin
normalizes the response `ETag` into an opaque token by removing surrounding
quotes and any `W/` marker, and records the evidence separately in
`ObjectInfo.etag_strength`: a conformant nonempty quoted entity-tag is
`Strong`, an explicit `W/` value is `Weak`, and a bare or malformed unmarked
value is `Unspecified`. `Last-Modified` is parsed into `mtime` when present. A
configured `etag_header` with any other name remains an
opaque token and carries the explicit `ResponseParsing.etag_strength`
declaration supplied by the redirect producer. The follower carries that
custom-header value verbatim, including surrounding quotes or a literal `W/`
prefix, and callers use that exact spelling for later preconditions. Its
zero-value default is `Unspecified`, because the header name alone does not
promise byte identity; only a producer that knows the backend contract may
declare it `Strong` or `Weak`. A failed response stream resumes when this
projected validator is nonempty and the resumed response repeats the same
configured header value. Validator strength does not gate this textual resume
check. A standard HTTP `ETag`, when present, is captured independently and sent
as the resume request's `If-Match`. `size` is populated from
`Content-Range`'s total when present, then from `Content-Length`,
then from the observed buffered length. Streaming responses without
`Content-Length` (chunked transfer) leave `size = None`. `versioned_address`
is always `None`; the plugin serves no pinned reads.

`ReadOptions::if_match` accepts that normalized token for both strong and weak
origins. The plugin does not send a wire `If-Match`, because HTTP forbids a weak
validator from satisfying that strong comparison. It performs the GET, then
normalizes and compares the response validator before returning bytes; a
mismatch is `ObjectModified`. This post-response check fully supports weak
origins without manufacturing a strong precondition that can never succeed.
`If-None-Match: *` is unsupported because the plugin is read-only.

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

The plugin accepts caller-supplied credentials (`bearer_token`, `username` +
`password`, `signed_query`, and `secret_headers`) and never reads ambient ones — there is no
environment-variable default, because no convention exists for "the
token for arbitrary HTTP origin X" and the plugin can be pointed at any
host. Operators concerned about exfiltration route only the prefixes
they trust to the plugin; with no route bound, the plugin sees no
traffic.

A broker-loaded plugin additionally accepts a broker-minted OAuth reference:
it requires a stamped principal and reads the named access token from the
broker host's keyring callbacks. Bearer-carrying requests require HTTPS,
except literal `127.0.0.1` HTTP for local development; they restrict redirect
following to same-origin even when anonymous traffic has a broader
allow-list, and they bypass system proxies.

A header credential is scoped to the origin of `root_url`, not its path (see
the public surface above), so an operator must trust the whole origin. A
signed query must declare prefix scope, and recognized object-scoped families
are refused.
It is refused over cleartext unless the host is loopback, and a
redirect that would downgrade `https` to `http` is refused, because the
HTTP client drops `Authorization` only when the host or port changes and
would otherwise carry it over the downgrade. Redirect chains are capped
at 10 hops, and a hop to a cloud instance-metadata endpoint is refused under
every `redirect_policy`, an allow-listed host included, because the payoff of
that fetch is the process's own cloud identity.

Credentials never enter an error, a log or a published address. The
credential is held as a sensitive header value (`set_sensitive`), so it
prints redacted and is never HPACK-indexed; it is attached per request
rather than as a client-wide default header; and it appears in no
`BackendId`, `RootInfo` or `ObjectInfo`. A `default_headers` entry that
is rejected is identified by its position and byte length and never by
its text, because the natural `Authorization: Basic <base64>` mistyping
puts the credential on either side of the `=` the parser splits on.

**What the origin sends back is filtered too.** An authenticated exchange
can return material that belongs to the connection rather than the
object — `Set-Cookie`, `WWW-Authenticate`, `Authentication-Info`,
`Proxy-Authenticate` — and `ObjectInfo.system_metadata` crosses the
broker and REST boundaries to callers who may be less privileged than
the credential. Those headers are dropped; everything else, including
vendor and `x-` headers, is published unchanged.

Two residuals are **not** closed. Userinfo in `root_url` is connection
*config*, so `write-config` persists it verbatim without the
plaintext-secret policy that `--secrets` applies to declared credential
fields — prefer the `username`/`password` fields, which do go through it.
And the CLI holds prompted secrets in ordinary strings for the lifetime
of the session; the zeroizing carriers described here begin at the
plugin boundary.

There is no caller-side mTLS or OAuth refresh flow; deployments that need
either use a host-side rotation source or a reverse proxy. Custom credential
headers use `secret_headers`. They follow the configured redirect policy, so
keep the default `same_origin` unless every host named by `allow_list` is an
intended credential recipient.

## Signed roots are declared credentials

A signature that covers the whole root is a credential, not part of the
address. A connection holds it in the raw-bytes `signed_query` credential and
declares its family with `signed_query_scope`; `root_url` and `prefix` are
refused a query outright. This keeps the value out of route identity and lets
the host rotate it without rebuilding the connection.

Two reasons, and neither is about the spelling:

1. **Baking a signature into a config address is the wrong shape for it.** A
   signature is a credential, so it belongs in an explicit field routed
   through the credential system — where the plaintext-secret policy, the
   transport rules and the auth-state reporting already apply — rather than in
   the URL the operator writes and `write-config` persists verbatim.
2. **A held query is only correct for half of the signatures operators
   present.** Splicing a fixed query onto every request works for a
   *prefix-scoped* token — an Azure container SAS, a CloudFront
   custom-policy signed URL. For a **per-object** signature such as an AWS
   SigV4 presign it manufactures a URL that authenticates nothing, and the
   two are indistinguishable unless the connection is made to declare which
   it holds. `signed_query_scope` is that declaration.

Only prefix-scoped grants belong in the connection. Per-object presigns remain
request addresses: an AWS SigV4 presign, Azure blob SAS, or CloudFront canned
policy signs one object and is refused when presented as a held credential.
Unknown schemes rely on the operator's `prefix` declaration; recognized
families are checked as a backstop. The query is appended textually and then
checked against the parsed URL so percent escapes and parameter order cannot
change silently.
