# Configuration (`ovstorage.toml`)

`ovstorage` reads its configuration from a TOML file. A deployment
describes its **Stack as data**: a named graph of layers plus the
credential bindings that connect backends. The CLI, the MCP server, and
the REST gateway all load this same `[ovstorage]` schema; a host adds
only its own sections on top (the REST gateway adds `[server]`, the broker
adds `[listener]`, and each carries its own `auth` block inside).

A file that declares no `[ovstorage]` table is not an error: the loader
returns an **empty stack**, and no config struct rejects unknown keys, so
foreign tables are read past in silence. Only a syntactically invalid file is
an error (`InvalidArgument`), and a missing file is a `NotFound`. See
[§ The empty stack](#the-empty-stack) for what an empty stack answers.

The CLI, the MCP server, the REST gateway, the broker, and direct library
hosts all read the `[ovstorage]` schema described on this page.

## Outbound HTTP proxy

Outbound HTTP proxy policy is process-wide rather than part of the Stack
graph. Set the standard environment variables before starting an ovstorage
host; every loaded plugin sees the same process environment:

| Variable | Meaning |
|---|---|
| `HTTP_PROXY` / `http_proxy` | Proxy for HTTP destinations. |
| `HTTPS_PROXY` / `https_proxy` | Proxy for HTTPS destinations, normally using HTTP CONNECT. |
| `ALL_PROXY` / `all_proxy` | Fallback proxy when the protocol-specific variable is absent. |
| `NO_PROXY` / `no_proxy` | Comma-separated hosts, domains, IP addresses, or CIDR ranges that connect directly. |

Protocol-specific variables take precedence over `ALL_PROXY`. Uppercase takes
precedence when both cases are present. The clients snapshot these values when
their connection pools are built, so changing them in a running process does
not reconfigure existing connections; restart the host to apply a new proxy
policy.

The S3/SQS connector honors these variables like every other client. A host
that exports `HTTP_PROXY` or `HTTPS_PROXY` for unrelated reasons therefore
routes S3 traffic through that proxy, with no configuration of its own.
Add private or on-prem S3 endpoints — MinIO, Ceph, and other in-cluster object
stores a corporate egress proxy cannot reach — to the `NO_PROXY` list
to keep them direct.

`NO_PROXY` matches an entry against a host in one form only. `*` and domain
suffixes apply to named hosts; an endpoint written as an IP literal such as
`http://10.20.30.40:9000` is matched only by that address or by a CIDR range
that contains it. `NO_PROXY=*` therefore does **not** bypass an IP-literal
endpoint — list the address or a range like `10.0.0.0/8` alongside it.

Two conditions disable proxying altogether, both from the underlying HTTP
clients rather than from ovstorage:

- Setting `REQUEST_METHOD` marks the process as a CGI script and causes every
  proxy variable to be ignored. This is the standard httpoxy mitigation, and it
  applies whatever the variable's value is.
- A proxy variable naming a scheme the transport cannot use is not ignored —
  requests fail instead. `ALL_PROXY=socks5h://…` makes S3, SQS, and the
  reqwest-backed backends fail with an unsupported-scheme dispatch error rather
  than connecting directly. A host that exports a SOCKS proxy for other tools
  must therefore bypass ovstorage's destinations through `NO_PROXY`, or unset
  the variable for the ovstorage process.

```sh
export HTTPS_PROXY="http://proxy.example.com:8080"
export NO_PROXY="localhost,127.0.0.1,::1,.corp.example.com"
ovstorage --config ./ovstorage.toml stat s3://assets/scene.usd
```

The policy covers ordinary outbound HTTP(S) used by the HTTP, S3/SQS, GCS,
Azure, and OpenDAL backends; redirect following; OAuth/OIDC and JWKS calls;
service and broker discovery; Nucleus large-file transfer; and HTTP telemetry
export. It does not change inbound REST or broker listeners, gRPC channels, or
Nucleus WebSocket transports.

Proxy endpoints use `http://` or `https://`. An HTTPS destination can still use
an `http://` proxy: the client establishes a CONNECT tunnel before negotiating
TLS with the destination. SOCKS, PAC/WPAD, and NTLM/Kerberos/Negotiate proxy
authentication are not supported — and for SOCKS specifically, "not supported"
means requests fail rather than fall back to a direct connection, as described
above.

For a Basic-authenticated proxy, percent-encode the credentials as URL userinfo
and inject the complete value through the process's secret manager or service
environment:

```sh
export HTTPS_PROXY="http://proxy-user:${PROXY_PASSWORD}@proxy.example.com:8080"
```

Do not commit proxy credentials to `ovstorage.toml` or place
`Proxy-Authorization` in an HTTP connection's `default_headers`. Error messages
redact URL userinfo, but environment access and process inspection remain part
of the host operator's trust boundary.

Native desktop proxy settings are not an ovstorage configuration source.
Windows and macOS expose transport-specific proxy stores, while Linux has no
single system proxy registry, and the AWS and reqwest transports do not consume
those stores uniformly. Environment variables therefore provide the portable,
predictable policy for the whole process.

## The `[ovstorage]` table

Everything ovstorage owns lives under one top-level table. Foreign
top-level tables (a host's own `[server]`, `[listener]`, …) are ignored
by the stack parser, so one file can feed every consumer.

```toml
[ovstorage]
root = "alias"                     # the name of the root layer
# [ovstorage.layers.<name>] ...    # one table per layer
# [[ovstorage.connections]] ...    # credential bindings (a distinct list)
```

### `root`

`root` is the **name** of the layer every operation enters through — the
top of the graph. It must name a layer defined under
`[ovstorage.layers]`. A stack that declares layers but sets no `root` is
a configuration error.

### `[ovstorage.layers.<name>]` — one table per layer

Each layer in the graph is a `[ovstorage.layers.<name>]` table, keyed by
a name you choose. A layer table has exactly three **structural** keys,
all optional:

| Key | Meaning |
|---|---|
| `kind` | The layer's implementation kind. **Defaults to the layer name.** Set it only when a layer's name differs from its kind — e.g. two backends of the same kind, `[ovstorage.layers.prod]` and `[ovstorage.layers.scratch]` both with `kind = "file"`. |
| `inner` | A wrapper's single inner child layer (the name of the layer it wraps). |
| `children` | A router's child layer names (an array). |

**Every other key in the table is flat layer config** passed to that
layer's implementation. For a backend layer these are the backend's
config keys (see the per-backend plugin docs); for a wrapper they are
that wrapper's tunables (e.g. `byte_cache`'s `max_object_bytes`).

```toml
# A layer whose name equals its kind — `kind` defaults to "file".
[ovstorage.layers.file]
# (backend config for `file` is supplied via a connection, below)

# Two backends of the same kind need explicit `kind`.
[ovstorage.layers.prod]
kind = "file"

[ovstorage.layers.scratch]
kind = "file"
```

### `[[ovstorage.connections]]` — credential bindings

Connections are a **distinct list**, not layer config. Each connection
attaches a backend instance (its config + credentials) to a backend
layer in the graph.

| Key | Required | Meaning |
|---|---|---|
| `backend_kind` | yes | The backend kind to instantiate (`"file"`, `"s3"`, `"http"`, …). |
| `target` | no | The **backend layer name** to attach to. **Defaults to `backend_kind`.** Set it when the layer's name differs from its kind. |
| `display_name` | no | A human-readable label for the connection. |
| `config` | no | Backend-specific config table (e.g. `{ root = "/data" }`). |
| `credentials` | no | A table of credential fields. `${NAME}` values are substituted from the process environment when the connection is built. |

```toml
[[ovstorage.connections]]
backend_kind = "s3"
display_name = "prod"
config = { bucket = "corp-prod", region = "us-east-1" }
credentials = { access_key_id = "${AWS_ACCESS_KEY_ID}", secret_access_key = "${AWS_SECRET_ACCESS_KEY}" }
```

A credential string that does not match the strict POSIX form
`${[A-Za-z_][A-Za-z0-9_]*}` passes through literally.

## The empty stack

**No `[ovstorage.layers]` means an empty stack.** There is no code-side
default graph: a host with no configured layers answers every object and
connection operation with `Unsupported`, including `capabilities`. You either
declare the stack yourself or start from a shipped default config (below).
This is intentional — the stack shape is always the deployment's own data.

Listing is the exception, and it succeeds rather than failing: listing
kinds, connections, and address roots against an empty stack returns an empty
result. So `ovstorage doctor` and the MCP `ovstorage_doctor`,
`ovstorage_connections_list`, and `ovstorage_address_roots_list` tools all work
before anything is configured — an empty report is the answer, not an error.

An empty stack therefore reports **no backend kinds** to the in-process
listings (`ovstorage list-backends`, `ovstorage doctor`, the MCP
`ovstorage_doctor` tool, the Rust `LayerExt::list_backend_kinds`): those
enumerate the backend layers the stack was built with, so a kind is absent
until this config declares a layer for it. That holds for the built-in `file`
backend as much as for a plugin-provided one. `ovstorage connect` reads the
same listing, which is why it fails with `NotConfigured: "no backend kinds are
registered"` against an empty stack.

## Canonical default (the `file` backend)

This is the smallest complete, copyable config. It serves the local filesystem
directly through the built-in `file` backend and does not require any plugins:

```toml
[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"
config = { root = "/data" }
```

The connection attaches to the `file` layer (its `target` defaults to
`backend_kind = "file"`). Load plugins before building the stack when its graph
uses any other kind.

> **Watch coalescing.** Watch coalescing lives in the backends, not in a host
> layer. A competing-consumer backend (S3, GCS) self-coalesces overlapping
> subscriptions onto one physical consumer via the SDK `WatchCoalescer`, proven
> by the `watch-concurrent-cross-prefix-no-split` conformance scenario. There is
> no `watch_coalescing` stack layer to configure. Non-competing-consumer
> backends (Azure change-feed, services-client, nucleus, file, broker-relay)
> open one physical watch per overlapping subscription; correctness is
> unaffected because those transports broadcast every event to every reader.

## Standard layer kinds

Only `file` is built in. Every other public backend or wrapper is supplied by a
plugin, so Rust, C/C++, and Python hosts all discover the same layer
implementations through the plugin ABI. See
[`plugin-storage/README.md`](plugin-storage/README.md) for loading and
configuration guidance.

| Kind | Provider | Role | Structural key |
|---|---|---|---|
| `file` | Built in | Local-filesystem backend | — |
| `router` | Core plugin | Dispatches an address to the child backend that serves its prefix | `children` |
| `alias` | Core plugin | Address translation / visibility (outermost) | `inner` |
| `copy_rename_fallback` | Core plugin | Copy/rename fallback (emulates when the layer below declines) | `inner` |
| `retry` | Core plugin | Retries transient backend failures | `inner` |
| `redirect_follower` | HTTP plugin | Follows backend redirect pointers | `inner` |
| `byte_cache` | Cache plugin | Caches object bytes (config: `max_object_bytes`, …) | `inner` |
| `metadata_cache` | Cache plugin | Caches stat/list metadata | `inner` |

Every wrapper in that table is behavior you place in the graph yourself: a
stack that does not declare `retry` or `redirect_follower` has neither
behavior. Per-prefix routing is the `router` layer's `children` plus the
address roots each connection serves.

The `redirect_follower` declares four config keys of its own — `follow_reads`
(default `true`), `follow_reads_max_bytes` (default unset — unbounded),
`replay_spool_threshold_bytes`, and `disclose_redirect_credentials` (see
below) — and also accepts the shared `retry` tunables. With
`follow_reads = true` (or unset) and no cap, the follower fetches redirect
targets of any size.

**Whether that costs memory depends on what the caller asks for, so do not
treat it as bounded.** The follower hands back a lazy stream, and a consumer
that forwards it chunk by chunk — the REST gateway's read handler does — holds
only the chunks in flight. But `read_bytes` buffers a stream whole, and a
`byte_cache` above the follower buffers the whole object on a `read_bytes` it
means to cache, so an uncapped redirect target read that way is resident in
host memory in full. Cache disk is unbounded on the same path, and the
connection and bandwidth are held for the length of the transfer either way.
This is the memory/disk DoS vector to size `follow_reads_max_bytes` against —
**but that key gates following only for redirects that are *delegable*.** A
redirect the disclosure policy will not let cross the host boundary is followed
locally whatever its size, in both arms: with `follow_reads = true` the size
gate hands an over-cap non-delegable redirect back as a stream rather than
surfacing it, and with `follow_reads = false` a cap is refused at startup
altogether. So for Azure under Entra OAuth or a supplied `sas_token`, Nucleus
LFT and the Omniverse Storage Service client, `follow_reads_max_bytes` bounds
nothing. Bound the *buffering* with `ReadOptions.max_bytes`, and the cache with
`byte_cache.max_object_bytes` plus a `max_bytes` size budget; server-side
streaming bounds memory only, never bandwidth or connection occupancy.

The shipped server templates pin this safely: the REST gateway sets
`follow_reads = false` (surfacing redirects as HTTP 307), and the
broker sets `follow_reads_max_bytes` to its cache cap. Running `follow_reads =
true` uncapped beside a `byte_cache` in a hand-written graph is a deliberate,
explicit choice.

`follow_reads = false` suppresses read-following, it does not make
credential-bearing backends unreadable. A redirect whose credential authorizes
more than the redirected request may not be surfaced to the caller, so the
follower fetches it locally and returns the bytes as a stream instead.
Redirects whose credential is scoped to the redirected request — a presigned
URL, a single-object signature — surface unfollowed as usual.

**What decides that is the minting backend's declaration, not an inspection of
the redirect.** A signature an operator minted for a whole account and one
scoped to a single object are the same shape on the wire, so no header or URL
matching recovers the difference; only the code that built the credential knows
what it authorizes. Header inspection survives as a one-way demotion: a
backend that declares a request-scoped credential and then attaches a header
this host cannot account for as inert is treated as connection-scoped, so a
declaration mistake costs a proxied transfer rather than a disclosure.

Whether the follower may hand over a redirect it judges broader is decided by
`disclose_redirect_credentials` on the layer, which defaults to refusing.
**On the broker and the REST gateway an operator does not set it here.** Those
hosts stamp it onto every follower in the graph from their own top-level
`redirect_credential_disclosure`, and a graph that declares the layer key by
hand is **refused at startup** with `InvalidArgument` naming the layer —
refusing beats silently overriding, because two spellings of one policy that
disagree is a state an operator cannot debug from the outside. A bespoke
library host composing its own `StackConfig` sets the layer key directly, and
does so legitimately, as do the CLI and MCP hosts, which declare a
`redirect_follower` and do no stamping — for them the layer key is the
setting.

This layer is where the check can be applied *gracefully*, by holding the
connection and fetching the bytes itself, which makes it security-relevant
rather than merely an optimization. It is not the only place the rule is
applied: the broker and the REST gateway apply it again at their own out-edges,
which no graph can compose away. So a bespoke graph that serves a backend
emitting broader-than-request redirects — Azure under Entra OAuth or an
operator-supplied `sas_token`, Nucleus LFT, the Omniverse Storage Service
client — and omits `redirect_follower` loses the local-fetch fallback, and
those reads fail rather than being proxied. A library host with no out-edge
guard of its own forwards them to its caller verbatim. Graphs handing
redirects to remote callers should keep the layer.

Both cache kinds accept `watch_invalidation = true` (default `false`). When
enabled, the cache discovers address roots from its inner layer, opens one
shared background drain per watch-capable root, and tracks root additions,
removals, and capability changes. Watch events invalidate matching addresses
across every principal's metadata entries; byte-cache entries are already
address-scoped rather than principal-scoped. The bounded root drains therefore
do not multiply with the number of principals.

`watch_invalidation` is the only key that turns watch-driven invalidation on,
and cache layers ignore unknown keys, so a misspelled or unrecognized key next
to it is silently dropped rather than rejected.

An advertised watch that returns `Unsupported` at runtime falls back to
TTL-only invalidation for that root. Enable this only when the deployment
accepts the backend cost of maintaining watches; the root capability says
whether a watch is available, not whether it is economical.

#### When the root watch is refused

A stack that authorizes per address may allow a principal to read objects under
a root and not allow it to watch the root — `watch_directory` is authorized
separately from `read` and `list`. The root watch then fails with
`PermissionDenied`, and a single root-wide watch cannot be had at all.

Rather than falling to TTL-only for everything under that root, the cache
starts watching the **directories it has produced entries for**: the parent of
each cached object, and the prefix of each cached listing. Each of those is a
separate `watch_directory` call the same authorization decides on its own — the
cache infers no permission from a successful read and gains none it was not
granted. A directory whose watch is also refused is TTL-only, and so is
everything under a root where no narrower watch is granted.

This fallback is bounded rather than configurable, and the bounds are
deliberately small:

- **Four concurrent directory watches per cache layer.** A watch is not a cheap
  subscription end to end: over the broker client each one costs a dedicated OS
  thread and its own async runtime, and inside the cache each one holds a
  blocking thread for as long as it is open. A directory covered by a watch
  above it does not take a second slot, and reading under a directory counts as
  use of that directory, so a project directory whose subtree is busy keeps its
  watch while only its children are being addressed.

  **The watch set follows the working set.** The cache remembers many more
  directories than it can watch and picks the most recently read of them, so a
  workload that moves to different directories moves its watches with it. A
  watch is given up only once its own directory has gone unread for a minute:
  tearing one down invalidates everything cached beneath it, and without that
  floor a working set one directory larger than the budget would discard a
  subtree on every read.

  **One extra watch can be open while a broader one is starting.** When a
  directory above several watched ones is read, its watch is opened alongside
  them rather than in place of one — it cannot replace them until it is actually
  open, and until then tearing them down would leave their subtrees reported by
  nothing. The others close as soon as it opens. At most one such extra watch
  exists at a time, so the steady-state ceiling is five rather than four.

  **When the watch set rotates, both sets are briefly open.** A watch that has
  been given up is replaced in the same pass that gives it up, and the one being
  replaced is not closed until the backend actually releases its stream — which
  a backend that does not act on cancellation may not do promptly, or ever.
  Nothing bounds how long that takes. So a rotation of the whole set holds both,
  and the peak to size a connection pool against is **at least** twice the
  steady-state figure — exactly twice if the backend releases promptly, and
  higher on one that does not, since each later rotation can still add the one
  extra watch a broader directory is granted.

  **Against a backend that never releases, the figure to size against is not a
  multiple of four at all.** The bound above is on *live* watches, and a
  cancelled stream that is never released is not a live watch — it is a parked
  thread. The number of those grows by up to four per rotation, for as long as
  the working set keeps moving, and nothing reclaims them: a watch stream is
  driven on a blocking thread, and a blocking task cannot be cancelled, which is
  why the cache does not abort them. That pool is shared with the cache's own
  maintenance work, so once it is exhausted the cache's directory-watch
  management stops making progress and other cache work queues behind it.

  This is a property of the backend, not a tuning knob: a backend that returns
  from a cancelled watch releases everything promptly and none of this applies.
  If yours does not, the cache logs a warning naming the count once the stuck
  set reaches four rotations' worth, and the options are to size the runtime's
  blocking pool for the deployment's rotation rate, or to turn
  `watch_invalidation` off and rely on TTL.

  The alternative — refusing to open the replacements until the old streams are
  released — would leave the directories now being read with no watch at all
  until they are, having just invalidated what was cached under the ones
  released. The transient is taken deliberately in preference to that.
- **A refused directory is remembered for five minutes** before it is tried
  again, so a reloaded policy that grants the right is picked up without a
  restart while a standing refusal is not re-asked on every read.
- **A root whose narrower watches fail eight times in a row, with none granted
  in between, stops being probed for five minutes.** The per-directory limits
  above bound how often any one directory is asked about; they cannot bound a
  workload that keeps walking into fresh directories, each worth one refused
  call. This is where "this deployment grants no watch at any prefix" is
  noticed.

Two consequences worth planning for:

- Entries under a directory with no watch — over the cap, refused, or an object
  directly at the top of the root, which has no narrower directory than the root
  itself — are invalidated by TTL alone. What that means differs by layer, and
  the difference is what to plan for: a metadata entry always expires, on
  `ttl_seconds`, which defaults to 30 seconds when unset rather than to no
  expiry. A **byte** cache entry has no TTL at all — there is no `ttl_seconds`
  for bodies — so for cached object data a watch is the only thing that
  invalidates. Lower `ttl_seconds` if you want the metadata half to converge
  faster; for the byte half, plan on the watch.
- A root the authorization layer does not show the principal in the first place
  never reaches this path, and the cache is then TTL-only with no watch even
  attempted. Two separate grants stand between a principal and a visible root:
  the address-free `list_address_roots` operation, without which discovery is
  refused outright, and then `read` **or** `list` on the root address itself,
  which is the filter each advertised root passes. Policy rules match by
  prefix, so a rule scoped to a subtree does not satisfy the second: a policy
  granting only `read` on `some://server/projects/` advertises no root at all.
  Granting `watch_directory` on the root address, in addition, is what makes a
  single root-wide watch possible and skips this fallback entirely.

The internal drain has no caller `PRINCIPAL_ID` and opens its own logical
subscription on the backend, independent of any authenticated caller's watch. On
competing-consumer transports (where each notification is delivered to exactly
one reader), a backend must self-coalesce so that overlapping subscriptions
on one connection collapse onto a single physical upstream and each still
receive every event — the in-tree S3 and GCS backends do this via the SDK
`WatchCoalescer`. Enable `watch_invalidation` against such a backend only when it
self-coalesces; otherwise use TTL invalidation.

### `byte_cache` availability fallback

Beside the cached bytes, the `byte_cache` keeps a per-address **last-known
validator** — the validator of the newest body it filled for that address. A
read keys strictly on the validator the inner `stat` reports, so while the
backend answers the index is never consulted. What a *failing* `stat` does
depends on the error's shape:

| `stat` outcome | Effect on the read |
|---|---|
| Succeeds with an `etag` | Keys the cache on that validator; the index is not consulted |
| Succeeds without an `etag` | Bypass — unversioned content is never served from cache |
| `Transient`, `DeadlineExceeded`, `ResourceExhausted`, `Internal`, `BrokerUnavailable`, `NetworkFilesystemRefused`, `StateRootUnavailable`, `RedirectExpired` | **Outage** — the index answers, and the last content proved for the address is served |
| `NotFound` | Bypass by default; **outage** when `lost_backing_fallback = true` |
| `Unsupported` | Bypass — a backend that cannot `stat` gets no validation, so it is never served from the index |
| `Cancelled` | Propagates; the read fails rather than falling back |
| Anything else (`PermissionDenied`, `InvalidArgument`, the auth/credential family) | Bypass — an answer rather than an outage |

"Bypass" means the read proceeds to the inner layer as if nothing were cached;
it does not mean the read succeeds. A principal the backend refuses is never
served partition-shared content from the index.

`lost_backing_fallback = true` (default `false`) is therefore a single move in
that table: it reclassifies `NotFound` from an answer to an outage, so an
object the backend reports as absent is served from the last known validator —
the broker's survive-backing-loss contract. The availability-shaped row above
it is **not** gated on this key: any composition with a persistent `byte_cache`
serves last-known content during a transient stat failure.

> **Bound: an unclean exit can leave a superseded validator.** A mutation
> commits at the backend and then clears the address's last-known validator.
> Those are two stores with no shared transaction, so if the process dies
> between them — SIGKILL, OOM kill, container eviction, power loss — the
> address retains a validator the backend has superseded, with that
> validator's bytes still in the cache. The window is the interval between the
> two operations, but its consequence has no expiry: nothing is served wrongly
> while the backend answers stats, and the first stat outage after the crash
> serves the pre-mutation body as current. Under `lost_backing_fallback` that
> includes a *deleted* object, which keeps being served.
>
> Four things clear the row, and none of them runs on a schedule. **A
> mutation** to the address clears it, and is the only certain repair. **A
> read** clears it only if it *misses* — a read that finds the content row
> returns from the cache before the fill path runs, so read traffic against an
> address whose bytes are already cached leaves the row alone. **Eviction**
> drops it, but only above the `max_bytes` cap, and only in
> least-recently-accessed order. **Watch invalidation** drops it on a change
> event, but `watch_invalidation` defaults to `false` and the cache's watch
> opens without a cursor, so events that predate the process start are not
> replayed — it covers later out-of-band changes, not the one that was
> in flight.
>
> **Only wiping the cache bounds this.** Stop the process, remove
> `cache_root`, and restart: deleting it while no process is using the root is
> supported, and the next open drops every index row whose bytes are gone.
> That is the one mitigation that ends the exposure outright.
>
> The other two knobs narrow the odds and are worth setting, but neither is a
> bound, and it is worth being precise about why:
>
> - **`max_bytes`** caps the cache's total size, not the age of any row.
>   Eviction fires only when the cache is over the cap, so a cache that stays
>   under it never evicts anything. When it does fire it takes the
>   least-recently-accessed rows first — and a fallback read refreshes the
>   access time of both the stale validator row and the body it names. An
>   address that keeps being read through an outage therefore sits at the
>   recent end of that order and survives while colder rows are reclaimed
>   around it. `max_bytes` shortens the life of a *cold* stale row; it puts no
>   bound on a hot one.
> - **`watch_invalidation`** repairs an address when the backend reports a
>   change to it, which covers out-of-band writes from then on. It cannot
>   repair the row the crash left, because the drain starts from the moment it
>   opens.
>
> Accepting the bound is also a defensible position: `lost_backing_fallback`
> is already an explicit decision to serve content the backend cannot confirm.

### `alias` rules and visibility

An `alias` layer's rewrite rules and visibility overrides are authored as
ordinary nested TOML under the layer table — an array of tables per key:

```toml
[ovstorage.layers.alias]
inner = "router"

# Rewrite a virtual prefix onto its physical target (longest-prefix, chained).
[[ovstorage.layers.alias.aliases]]
from = "ov:///public/"
to   = "file:///srv/data/"

# Override how a prefix is advertised: "visible" (default), "hidden", or
# "suppressed" (alias-only; rejected as a caller-supplied address).
[[ovstorage.layers.alias.visibility]]
address    = "file:///srv/data/"
visibility = "suppressed"
```

Each rule prefix is a URL and is normalized like an incoming address, with one
difference: it may not carry a **query** or a **fragment**. An address names a
node, matching reads scheme, authority and path alone, and a fragment never
reaches a backend — so either component in a rule is a load error naming it.
A caller's *request* address may still carry a query.

A `suppressed` prefix is never advertised by `list_address_roots` and cannot be
addressed directly; it is reachable only as an alias target.

## Server auth kinds

The broker's `[listener.auth]` and REST gateway's `[server.auth]` select an auth
wrapper composed above the shared inner Stack. The block is fail-closed: it
must be `"anonymous"`, `kind = "builtin-auth"`, or the kind of a loaded plugin
wrapper whose descriptor declares `auth_capable = true`. A missing block, an
unknown kind, a backend or router kind, or a wrapper without that marker makes
the server refuse startup; naming an ordinary wrapper can never silently create
an unauthenticated listener.

For a plugin auth kind, the host passes `[listener.auth.config]` or
`[server.auth.config]` to the selected factory verbatim. The plugin owns that
schema. The auth wrapper consumes the request's `AUTH_CREDENTIAL`, enforces its
authorization contract, and on allow stamps the resolved `PRINCIPAL_ID` DOWN on
the request it delegates to the inner Stack. The principal must be non-empty
UTF-8. A host-owned opaque boundary below the wrapper strips `AUTH_CREDENTIAL`
from every delegation and fails the request closed when the wrapper delegates
without a stamped, valid principal. Raw bearer material therefore cannot reach
the storage graph, and a wrapper cannot silently admit an unattributed request.
For a streaming write, the broker supplies a pull-driven body;
the wrapper must complete authentication before it polls that body or delegates
the request so a denied caller cannot make the listener drain upload data. In
the broker, an allowed empty or sub-threshold upload is then delegated as
replayable bytes, while an over-threshold upload remains a bounded stream.
Backend-kind discovery uses the synchronous `list_kinds` authorization gate.
The host does not inject listener identity or trusted-proxy fields into
plugin config.

The built-in `authn_mode`, `jwt_*`, and `peer_dev_current_user` behavior belongs
only to `builtin-auth`. For the broker, host-owned `trusted_proxy` and
`trusted_peers` gate forwarded metadata before either auth form runs. A plugin
may select the metadata allowlist with `forwarded_identity_header` (default
`x-forwarded-user`) and `forwarded_claim_headers` in its own config; the broker
preserves duplicate values and input order and passes those config fields to
the factory unchanged. The built-in layer supports its typed policy reload
operation. Plugin auth kinds do not: a server lifecycle reload reconstructs
the plugin layer from config instead of hot-reloading its policy in place.

## Environment overrides

Each host loads the env overlay under **its own prefix**, and the prefix
selects which host honors it. Nested keys use `__` as the separator:

| Host | Prefix | Example |
|---|---|---|
| CLI / MCP server | `OVSTORAGE__` | `OVSTORAGE__ROOT` → `ovstorage.root` |
| broker | `OVSTORAGE_BROKER__` | `OVSTORAGE_BROKER__OVSTORAGE__ROOT` → `ovstorage.root` |
| REST gateway | `OVSTORAGE_REST__` | `OVSTORAGE_REST__OVSTORAGE__ROOT` → `ovstorage.root` |

The CLI/MCP `OVSTORAGE__` prefix maps directly into the `[ovstorage]`
table, so `OVSTORAGE__LAYERS__BYTE_CACHE__MAX_OBJECT_BYTES` sets
`ovstorage.layers.byte_cache.max_object_bytes`. The broker and REST
gateway load their own top-level config (`[listener]` / `[server]`, auth,
attribution) and read the stack as a nested `ovstorage` field, so their
prefixes carry the extra `OVSTORAGE__` (i.e. `..._BROKER__OVSTORAGE__…`)
to reach a stack key. A bare `OVSTORAGE__…` variable is honored only by
the CLI/MCP path — the servers ignore it.

Environment values override the file. (For the CLI/MCP path this overlay
applies when a config file is loaded from a path; it is intentionally
skipped when a config is parsed from an in-memory string in tests.)

## Config file locations

The CLI resolves its startup config in this order, stopping at the first
that applies:

1. `--no-config` — start from an empty stack, ignoring every file and env
   var below.
2. `--config <PATH>` — parse exactly this file (`--config` and
   `--no-config` are mutually exclusive).
3. `$OVSTORAGE_CONFIG` — parse the file this env var points at.
4. `./ovstorage.toml` (current directory).
5. `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`
   (default `~/.config/ovstorage/ovstorage.toml`).
6. None of the above found → the stack is empty.

The MCP server uses the same resolution without the CLI flags:
`$OVSTORAGE_CONFIG`, then the `./ovstorage.toml` → XDG search path, then
the empty stack. (Set `OVSTORAGE_MCP_NO_CONFIG` to force the empty stack.)

## Portability: `ovstorage write-config`

`ovstorage write-config <PATH>` serializes your live stack as a
self-contained `[ovstorage]` document — every layer and every connection —
that runs verbatim under any host. Move the same file between the CLI, the
MCP server, and the REST gateway; each host layers only its own sections
(`[server]` or `[listener]`, each with its own `auth` block) on top of the
shared `[ovstorage]` stack.
