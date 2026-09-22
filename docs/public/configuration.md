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

Do not put literal secrets in the TOML. A reusable parsed configuration keeps
literal credential bytes for its lifetime. The native C/C++ loader clears its
file, overlay, and parser storage when that storage is released, but the bytes
still remain resident until `StackConfig` is destroyed. `${NAME}` keeps only
the placeholder in the parsed document and resolves the secret when a
connection is built.

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
registered"` against an empty stack. `ovstorage init` writes the canonical
minimal `file` layer graph and loads it into the live session, which makes the
built-in backend kind available to `connect`. It returns `AlreadyExists` when
the session already has a configured stack, even with `--force`, or when the
destination file exists and `--force` is absent.

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

`ovstorage init` emits the layer half of this graph: `[ovstorage]` with
`root = "file"` and `[ovstorage.layers.file]`, but no
`[[ovstorage.connections]]` entry. In the live session, `connect file <dir>`
supplies the connection and `write-config ovstorage.toml --force` writes the
complete configuration back to the initialized file.

> **Watch coalescing.** Watch coalescing lives in the backends, not in a host
> layer. A competing-consumer backend (S3, GCS) self-coalesces overlapping
> subscriptions onto one physical consumer via the SDK `WatchCoalescer`, proven
> by the `watch-concurrent-cross-prefix-no-split` conformance scenario. There is
> no `watch_coalescing` stack layer to configure. Non-competing-consumer
> backends (Azure change-feed, services-client, nucleus, file) can open one
> physical watch per overlapping subscription because those transports
> broadcast every event to every reader. The broker-client is a transport
> adapter exception: within one connection credential-identity generation it
> coalesces non-resumable watches sharing a resolved prefix onto one gRPC
> stream. An identity-changing credential update replaces the registry. A
> route advertising
> `watch_directory_resumable = true` bypasses coalescing so its cursor and
> options reach a dedicated stream unchanged. Separately, the broker daemon
> injects its broker-native `watch_limit` Layer at the root of its shared inner
> Stack, centrally bounding admitted watches per principal (default 256) and
> process-wide (default 4096); this is admission control, not coalescing.

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
| `hub_cache` | Hub Cache plugin | **Experimental.** Caches object bytes in a local Omniverse Hub (usd-workstation-cache); configuration keys and behavior may change between releases (config: `endpoint`, `key_scheme`, `max_object_bytes`, …) | `inner` |

Every wrapper in that table is behavior you place in the graph yourself: a
stack that does not declare `retry` or `redirect_follower` has neither
behavior.

The `metadata_cache` keeps one row per address and records the cost flags —
`full_metadata`, `versioned_address` — that row was fetched under. A `stat`
whose set flags the row covers is served from it, so a default `stat` may
come back with the richer fields an earlier flagged call paid for; a request
the row does not cover goes upstream once with the union of the stored and
requested flags and replaces the row. A `full_metadata = true` result is
cached like any other. Rows a `list` fills vouch only for the
`versioned_address` flag the listing was asked to carry, so a `full_metadata`
stat always reaches the backend.

`hub_cache` places the local hub daemon inside the stack's trust domain:
the hub accepts writes from any local process with no authentication, so a
served entry is only as trustworthy as the workstation's local processes.
Entries under `omni-client-compat` digest keys are proven against their
bytes before they are served (repeat serves of a file state reuse the
proof, with the state pinned by identifiers a non-root local process
cannot restore; where no such identifier exists, every serve re-proves);
entries under the default `ovstorage` scheme carry no provable content
identity, so a local process that derives the key can plant bytes the
layer will serve. Enable the layer only where every local process is
already trusted with the objects being cached.

Per-prefix routing is the `router` layer's `children` plus the address
roots each connection serves.

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
setting. The anonymous fallback grant follows the same rule — a top-level
key on those two hosts, stamped onto the backend layer that reads it, and a
hand-set layer key refused; see [Anonymous fallback for `s3`, `gs` and
`azure`](#anonymous-fallback-for-s3-gs-and-azure).

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
| Succeeds with a nonempty `Strong` `etag` | Keys the cache on that validator; the index is not consulted |
| Succeeds without an `etag` | Bypasses the lookup; a later Strong read result may still fill content and publish the availability row |
| Succeeds with an empty, `Weak`, or `Unspecified` `etag` | Bypasses the lookup, clears any live fallback, and suppresses availability publication for this read |
| `Transient`, `DeadlineExceeded`, `ResourceExhausted`, `Internal`, `BrokerUnavailable`, `NetworkFilesystemRefused`, `StateRootUnavailable`, `RedirectExpired` | **Outage** — the index answers, and the last content proved for the address is served |
| `NotFound` | Bypass by default; **outage** when `lost_backing_fallback = true` |
| `Unsupported` | Bypass — a backend that cannot `stat` gets no validation, so it is never served from the index |
| `Cancelled` | Propagates; the read fails rather than falling back |
| Anything else (`PermissionDenied`, `InvalidArgument`, the auth/credential family) | Bypass — an answer rather than an outage |

"Bypass" means the read proceeds to the inner layer as if nothing were cached;
it does not mean the read succeeds. A principal the backend refuses is never
served partition-shared content from the index.

The successful-stat distinction also governs fills. A present untrusted
validator suppresses the read-start availability fence, so even if the read's
own result declares a nonempty validator `Strong`, that result can populate
only the strict validator-keyed content row. It does not publish the
last-known-validator row used during an outage. This keeps a backend whose
ordinary stats are weak or unspecified from staging and fsyncing a tombstone
on every read. An absent stat validator is different: it makes no strength
claim, so the cache takes the fence and can publish a Strong validator learned
from a redirected or otherwise enriched read result.

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

# Override root visibility locally and across broker/REST boundaries:
# "visible" (default) is listed, addressable, and carried as visible;
# "hidden" is unlisted but addressable and carried marked as hidden;
# "suppressed" is omitted from advertisements and rejected as a caller address.
# A rule can only narrow an incoming root's visibility, never widen it: a
# "visible" rule does not re-list a root the broker already marked hidden.
[[ovstorage.layers.alias.visibility]]
address    = "file:///srv/data/"
visibility = "suppressed"
```

Each rule prefix is a URL and is normalized like an incoming address, with one
difference: it may not carry a **query** or a **fragment**. An address names a
node, matching reads scheme, authority and path alone, and a fragment never
reaches a backend — so either component in a rule is a load error naming it.
A caller's *request* address may still carry a query.

Locally, `visible` roots appear in route listings and remain directly
addressable. `hidden` roots are omitted from listings but remain directly
addressable. Broker and REST root advertisements carry both kinds with their
true visibility, so a broker client installs a hidden root for routing without
showing it in ordinary route listings. A `suppressed` prefix is omitted from
every root advertisement and a caller addressing it receives `NoRoute`; it is
reachable only as an alias target.

### Generated aliases for `s3`, `azure` and `huggingface` connections

When an `s3`, `azure` or `huggingface` connection registers below an
`alias` layer, the layer generates **hidden** alias rules for the ordinary
URLs of the same data automatically — a user pasting a URL they already
hold does not translate it first. An S3 connection on the AWS profile accepts
its six public URL shapes in the commercial partition (virtual-hosted and
path-style, each in the regional, global, and legacy `s3-<region>`
spelling) — four outside it, since the region-less global shapes name the
commercial partition only and bucket names are unique just within a
partition; China also swaps in the `.amazonaws.com.cn` suffix — three shapes, path-style only,
for a bucket whose name contains a dot, since its virtual-hosted HTTPS
host never fetches; a connection with an explicit endpoint (MinIO, B2,
R2, custom) accepts exactly the one shape its endpoint configuration
describes. An Azure connection accepts its blob-endpoint URL
(`https://<account>.blob.<suffix>/<container>/`, or the configured
`blob_endpoint`, including path-style Azurite), plus the `dfs` twin when
`hierarchical_namespace` is set. A `huggingface` connection accepts the
Hub's own repository URL on `https://huggingface.co`,
`http://huggingface.co`, their `www.` twins, and the short domain `hf.co`
over either scheme — prefixed `datasets/` or `spaces/` for those
repository types — so `https://huggingface.co/acme/demo/`
rewrites onto `hf://models/acme/demo/`; a loopback `endpoint` accepts
exactly its own shape. The exact shapes are listed in each plugin's
document.

Generated rules are `hidden` — addressable, never advertised, so listings
keep showing the canonical `s3://` / `azure://` / `hf://` form only. They
are never persisted: they regenerate from whatever registers the connection
(config replay at startup, a runtime add) and are withdrawn when it is
removed. In `list_connections` output they carry the
`org.omniverse.ovstorage/alias-derived-from` metadata key naming the
connection they came from. An explicit alias rule you author on the same
prefix wins — it evicts the generated rule rather than being refused as a
duplicate. The eviction lasts until the backend connection re-registers
(config replay at startup, or removing and re-adding it): removing your
explicit rule later does *not* bring the generated one back by itself. To
turn a single generated spelling off reversibly instead, use an ordinary
`suppressed` visibility override on its prefix — removing the override
restores the spelling. A stack without an `alias` layer above the backend
simply gets no generated rules.

Generation fails closed. If the layer cannot determine what an inner
`alias` layer already owns — its connection scan errors or times out — the
registration still succeeds but **no** rules are generated for it, rather
than generating them as though nothing were owned. An absent answer is not
evidence that a scope is free, and treating it as one would let a
transient fault re-derive a spelling an inner layer owns, including one
suppressed there. Re-register the connection once the inner layer answers
to generate them.

A generated spelling names exactly the address its canonical form names.
The address boundary normalizes every request the same way whatever
spelling it arrived under — including collapsing repeated `/` in the
path, which is why a key containing `//` is not addressable through
ovstorage under any spelling (see the plugin storage contract). Adding a
generated alias adds a way to *write* an address, never a different rule
for which object it selects.

**A generated rule stands aside for a credential-bearing URL.** An S3
presigned URL or an Azure SAS URL authenticates itself with its query and
grants exactly what it was signed for. Rewritten onto the canonical
`s3://` / `azure://` form those parameters stop meaning anything, and the
connection's own configured credentials would authenticate instead — so an
expired, revoked, or deliberately narrow URL would be served as a full
privileged read. A generated rule therefore declines any query it does not
recognize, and the address falls through to whatever else routes it (an
HTTP layer that honours the signature, or no route at all). The version
selectors the backends read — `versionId`, `versionid`, `generation`,
`revision` — are carried through, because they name a version of the same
object; a backend that does not read one of them ignores or refuses it on
its own terms. An alias rule you author yourself is unaffected: writing one
states that this prefix means that target, and only the default applied on
your behalf stands aside.

**An endpoint path prefix is never published as a generated spelling.**
Generated spellings appear in `list_connections` and `list_address_roots`
output, which a principal holding only the addressless introspection
operation can read — a weaker grant than reading the data. An endpoint
path can be a capability token, and connection configuration is otherwise
never returned, so a connection whose endpoint carries a path generates
no spelling for it: `s3` keeps only `host[:port]` from an endpoint, and
`azure` withholds a path-bearing endpoint entirely unless it is loopback
(which is what keeps path-style Azurite working); `huggingface` admits no
endpoint but the default and a loopback one, so the same carve-out covers
every endpoint it can be given. Author the alias rule
by hand if you want that prefix accepted — publishing it is then your
decision rather than a default.

Adding an explicit alias rule on a scope an inner `alias` layer holds a
generated rule for fails if that generated rule is found and cannot be
removed. The takeover runs before the rule is published, so the rule is
never announced on the connection or root update streams in a state where
a generated copy still shadows it, and a failed takeover publishes nothing
at all. The rule is withdrawn again rather than left installed, because
a surviving generated copy covers the same scope and would keep routing
past it: the add either takes effect with `explicit beats derived`
holding, or does not take effect. Retry once the inner layer accepts the
removal. If the *scan* for such copies cannot run at all — an inner layer
that is unreachable, in a stack that may well have no inner `alias` layer
to begin with — the add still succeeds and logs a warning naming the
scope, so an unrelated inner fault does not refuse a purely local address
rewrite.

A `suppressed` override on a *broader* prefix covers the generated
spellings under it too: a generated rule never re-opens a subtree you
denied above it. An override you place on the generated prefix itself
still decides that prefix, so `suppressed` at
`https://s3.us-west-2.amazonaws.com/` with `visible` at
`https://s3.us-west-2.amazonaws.com/bucket/` is a working combination.

**One case leaves a generated row behind.** Withdrawing a connection's
generated rules is refused when the remaining rule set would be invalid,
which is reachable only when a generated rule currently shields an
otherwise-cyclic set of rules you authored. The removal of the backend
connection still succeeds; its generated rows stay listed, marked
`alias-derived-from` a connection that is gone, and advertise as
`dangling`. Read that as a report that the authored rules the row shields
contain a cycle. The rows are ordinary alias connections, so
`remove_connection` on the row's own id deletes one directly once the
cycle is corrected.

**Authorization is deliberately untouched.** Authorization evaluates the
caller-supplied address *before* alias resolution, and policy is deny-all
when absent — so a grant on `azure://account/container` does **not** cover
`https://account.blob.core.windows.net/container`, a grant on
`hf://models/acme/demo/` does not cover `https://huggingface.co/acme/demo/`,
and no matching grant is ever generated (that would silently widen a
deny-by-default policy). In a brokered or gateway deployment the generated
aliases therefore do nothing until you grant their URL space, exactly as for
an alias you author by hand; a direct library host has no authz layer and
gets the benefit immediately.

### Anonymous fallback for `s3`, `gs` and `azure`

An `s3://`, `gs://` or `azure://` address that no configured connection
serves answers `NoRoute`, and nothing is attempted. A backend layer of the
`s3`, `gcs` or `azure` kind can instead be **granted** a fallback for its
scheme: an unrouted address on that scheme routes to the layer, which
attempts it **anonymously** and **read-only**. The grant is the layer key
`anonymous_fallback`, a TOML array of the schemes the layer serves. Absent
or empty is off, which is the default everywhere; a value that is not an
array of scheme strings, a scheme outside the closed set, or a scheme the
layer's kind does not serve (`["gs"]` on an `s3` layer) is refused at
startup with `InvalidArgument`. The keys beside it tune the fallback and are
read whether or not the grant is present, so a misspelt or mistyped one
fails at startup instead of sitting inert until the grant is added:

```toml
[ovstorage.layers.s3]
anonymous_fallback = ["s3"]
# Default us-east-1: where the region probe is sent, and the region a bucket
# is assumed in when the answer names none.
anonymous_fallback_region = "us-east-1"
# Optional. Skips the region probe (one endpoint serves every bucket) and
# defaults the profile to "custom". MinIO, emulators, sovereign endpoints.
# anonymous_fallback_endpoint = "http://minio:9000"
# Optional: aws | minio | r2 | b2 | custom.
# anonymous_fallback_compatibility_profile = "minio"
# Default false. A bucket whose name contains "." is path-style regardless.
anonymous_fallback_force_path_style = false
anonymous_fallback_max_backends = 64        # default; 1 to 100000
anonymous_fallback_mints_per_minute = 120   # default; 1 to 1000000

[ovstorage.layers.gcs]
anonymous_fallback = ["gs"]
# Optional; the default is the public endpoint. Emulators set theirs.
# anonymous_fallback_endpoint = "https://storage.googleapis.com"
anonymous_fallback_max_backends = 64        # default; 1 to 1000000
anonymous_fallback_mints_per_minute = 120   # default; 1 to 1000000

[ovstorage.layers.azure]
anonymous_fallback = ["azure"]
# Default core.windows.net; a sovereign cloud sets its own suffix.
anonymous_fallback_endpoint_suffix = "core.windows.net"
anonymous_fallback_max_backends = 64        # default; at least 1
anonymous_fallback_mints_per_minute = 120   # default; at least 1
```

A connection request — a runtime `add_connection` or a probe — that carries
any `anonymous_fallback*` key is refused with `InvalidArgument` naming the
key as a layer key: set on a connection it would otherwise be ignored while
the operator believed it took effect.

With the grant in place the host behaves as though a scheme-level anonymous
connection existed, without one existing. `list_address_roots` publishes one
extra root per granted scheme — `s3:///`, `gs:///`, `azure:///` — with
`hidden` visibility, no connection id, and the metadata key
`org.omniverse.ovstorage/scheme-fallback` valued `anonymous`; `ovstorage
doctor` lists it among the roots with that marker. The router consults the
root only after every configured prefix misses, so a connection for a bucket
always outranks the fallback for that bucket, and adding one evicts the
anonymous client the fallback built for it. `root_info_for` on an address
reached this way answers the scheme root itself, never a synthesized
per-bucket root; `list_connections` is unchanged; `ovstorage connect` on
such a bucket sees no incumbent; and nothing is persisted — the root is
config, regenerated at every start from the grant and gone when the grant
is.

The fallback is anonymous **by construction**. Its client is built with no
credential source of any kind — not the environment (`AWS_*`,
`GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_*`), not a credentials file, not an
instance-metadata service — so the process's ambient identity is never
spent on an address the operator did not configure, and every request that
leaves the process is unsigned. A bucket that refuses anonymous access
answers `PermissionDenied`, as it does through a configured anonymous
connection; a bucket that does not exist answers `NotFound`.

It is read-only **by construction** too. Every mutation — `write`,
`write_stream`, `write_redirect`, `continue_write`, `delete`, `copy`,
`rename`, `create_directory`, `delete_directory`, `update_metadata` — and
`watch_directory` answer `Unsupported` before any request is sent (`this
address is reached through the anonymous s3:// fallback, which is
read-only`), with a next action naming the bucket root a connection would
be added for and never the caller's path. A `copy` or `rename` is refused
when either end is reached through the fallback. The scheme root advertises
read-side capability bits only, so a host that gates on capabilities never
reaches the slot in the first place; its ranged-read strategy is the
`Native` one the kind's connection roots advertise, so `root_info_for`
answers the same strategy for a fallback-served address as for a configured
one on the same store. The bare scheme root itself, and any address with an
empty authority (`s3:///key`), is `InvalidArgument`: it names no bucket, or
on `azure` no storage account.

**A presigned S3 URL or an Azure SAS URL falls through to `NoRoute`.** Any
query other than the `versionId` / `versionid` / `generation` / `revision`
version selectors keeps an address out of the fallback, for the reason a
generated alias rule stands aside: the query is the authority the caller
presented, and an anonymous attempt against the canonical address would
silently discard it.

S3 learns a bucket's region once, from one unsigned `HeadBucket` per bucket
sent to `anonymous_fallback_region`. The `x-amz-bucket-region` header on the
answer names the region whatever the status; a `2xx` or `4xx` naming none
means the configured region; and a `404` is `NotFound` and is not
remembered. The region is then cached per bucket for the life of the
process. A probe the store did not judge — a `3xx` naming no region, a
`429` or `5xx`, a transport failure — teaches no region and is remembered
for one minute, during which the bucket answers `ResourceExhausted` naming
the wait (`the region probe for this bucket failed recently; it is not sent
again for another N s`) before any client is built or charged. A built
client whose own request answers `301` naming a valid region other than the
one it was built for takes that region and is rebuilt on the next touch of
that bucket, once and without a probe; any other `301` — one naming the
built region, or none — leaves the client in place, evicts and charges
nothing, and reaches the caller as `InvalidArgument`. A configured
`anonymous_fallback_endpoint` skips the probe and the heal alike: no region
changes the client it pins, so a `301` met there surfaces as
`InvalidArgument` and nothing is rebuilt. The S3 endpoint must be a bare
`http` or `https` origin — scheme, host and port; one that embeds
credentials or carries a path, query or fragment is refused at startup with
`InvalidArgument` naming the key and the layer, never the value. GCS
needs none: the bucket is the address's authority and one public endpoint
serves every bucket; a GCS `anonymous_fallback_endpoint` is kept as scheme,
host, port and path only, and one that embeds credentials, carries a query
or a fragment, uses a scheme other than `http` or `https`, or names no host
is refused at startup with `InvalidArgument` naming the key and the layer,
never the value. Azure takes the account and container from the address
(`azure://account/container/` is the node a client is built for), assumes a
flat namespace, and derives the blob host from
`anonymous_fallback_endpoint_suffix`.

The fallback is bounded. At most `anonymous_fallback_max_backends`
anonymous clients stay resident (default 64; the least recently used is
evicted), and at most `anonymous_fallback_mints_per_minute` new ones are
built per sliding minute (default 120). A first touch beyond the budget
answers `ResourceExhausted` (`anonymous fallback mint budget exhausted;
retry later`), which is retryable, while an address whose client is resident
is still served; every build attempt counts, including one that fails, a
refusal answered from S3's region negative cache builds nothing and is not
charged, and concurrent first touches of one bucket build once. Every kind
refuses `0` for either bound at startup. Each build logs one `INFO` line at
the `ovstorage.fallback` target naming the scheme and the bucket's origin,
never the key.

**Cloud instance-metadata endpoints are refused before any connection is
opened, whatever the grant says and whatever an authorization rule allows.**
Any host in `169.254.0.0/16` or `fe80::/10`, `100.100.100.200`,
`168.63.129.16`, `fd00:ec2::254`, an IPv6 address embedding a refused IPv4
address, and the exact names `metadata.google.internal`, `metadata.goog`
and `metadata` — matched exactly, never by suffix — answer `PermissionDenied`
naming the origin only (`refusing to contact <origin>: it is a cloud
instance-metadata endpoint, and ovstorage never fetches from one on a
caller's behalf`). The refusal applies to the host the fallback derives from
an address, to a configured `anonymous_fallback_endpoint` at startup
(granted or not), and to every redirect destination the http plugin and the
redirect follower are handed, under every `redirect_policy`. A process that
can be pointed at such an endpoint on a caller's behalf hands the caller the
instance's role credentials — the server-side request forgery this surface
exists not to become. A DNS name that resolves to a link-local address is not
caught: the predicate judges the host as written. An endpoint an operator
configures on an ordinary connection (`endpoint`, `blob_endpoint`,
`root_url`) that matches is honoured with one `WARN`, not refused.

**On the broker and the REST gateway an operator does not set the layer
key.** Those hosts carry the grant as two top-level keys beside
`redirect_credential_disclosure` — `anonymous_fallback_schemes = []`, a list
of `"s3"`, `"gs"` and `"azure"`, and `anonymous_http_fallback = "refuse"` —
and stamp `anonymous_fallback` onto the one layer of each granted scheme's
kind. The carrier is resolved against the routed graph — the layers `root`
reaches through `inner` and `children`, which is exactly the set the Stack
builder instantiates — so a backend reached only through a wrapper chain,
or one that is itself the root, carries the grant as well as a router child
does. A graph that sets the layer key by hand on an `s3`, `gcs`, `azure` or
`http` layer is **refused at startup** with `InvalidArgument` naming the
layer and both top-level keys, even when nothing is granted — refusing
beats silently overriding, for the reason the disclosure key gives. The
grant is also refused when the graph declares no layer of a granted
scheme's kind (declare `[ovstorage.layers.gcs]` and add it to the router's
`children` first; a grant that sits inert is the failure an operator never
notices); when its only layers of that kind are declared but not reachable
from `root`, refused by name (`` `anonymous_fallback_schemes` grants `gs`,
but layer `gcs` of kind `gcs` is declared and not reachable from the
graph's root, so the grant would sit inert: add it to the router's
`children` (or make it the root, or a wrapper's `inner`) ``); and when
`root` reaches more than one. Only routed layers are counted, so a
declared-but-unrouted duplicate does not trip the two-layer refusal.
`anonymous_http_fallback = "allow"` parses and is refused at startup: no
http tier exists to honour it, and a grant that did nothing would be worse
than one that fails loud, so an unrouted `http://` or `https://` address
answers `NoRoute`. The grant lives at the top level because it is a
property of the deployment rather than of any connection: a brokered fetch
runs from the broker's network position and reaches whatever that position
reaches, and only the operator of that position can say whether its
clients may point it at buckets it was not configured for. A bespoke
library host composing its own `StackConfig` sets the layer key directly,
as do the CLI and MCP hosts — for them the layer key is the setting.

A brokered client honours a scheme fallback root the broker advertises only
when its own `broker` layer table grants the scheme:

```toml
[ovstorage.layers.broker]
anonymous_fallback = ["s3"]
```

Without the local grant the advertised root is dropped at ingestion and the
address is `NoRoute` on the client, whatever the broker granted; with it,
the client forwards the address verbatim and the broker's own router and
backend do the rest. The ingested root is read-only on the client whatever
capability bits the wire asserted — every write, delete, copy, rename,
directory-mutation, metadata-patch and watch bit is false; list,
list_stream, recursive list, version listing and access check are kept —
and every mutation and `watch_directory` on an address it answers is
refused on the client, before any request reaches the broker, with the
same `Unsupported` message; the next action names the address's origin
(`add a connection for s3://public-bucket/ with credentials to modify it`),
because the client knows no scheme's node shape. A `copy` or `rename` is
refused when either end is fallback-routed. The client publishes no
fallback root of its own: the key is an admission filter, not a licence to
attempt anything from the client's position.

One layer per kind carries the grant. Two layers of one kind both
publishing `s3:///` publish one node twice: the router keeps the root it
aggregated earliest, logs the collision as an overlapping address root, and
the second grant is inert. The stamped hosts refuse such a graph outright;
a library host that composes one gets the log line and earliest-wins.

The fallback does not re-open what an `alias` layer closed. A `suppressed`
visibility override on a prefix still refuses a caller addressing it with
`NoRoute` before routing runs, granted or not, and the scheme root passes
through `alias` as `hidden` rather than being dropped. The fallback also
covers the canonical `s3://` / `gs://` / `azure://` spellings only: no
generated alias exists for a bucket without a connection, so its ordinary
cloud URL — `https://public-bucket.s3.amazonaws.com/key`, say — is
`NoRoute`.

**Authorization is deliberately untouched.** Policy sees the caller's
address before routing and is deny-all when absent, so a caller no rule
covers is denied before the fallback is consulted and can never cause an
outbound request. A grant on `s3://public-bucket/` covers that bucket and
nothing beside it — not a sibling bucket, not `s3:///` — and no grant is
ever generated for the fallback, exactly as none is for a generated alias.
The hidden scheme root is listed only to a principal whose rule covers the
bare scheme (`prefix = "s3://"`), and that rule grants nothing on any
bucket; a brokered client needs it to see the root at all. `root_info_for`
on an address the policy does not cover answers `NoRoute`, indistinguishable
from an address nothing routes — deliberately, so the error code never
reports what a grant could switch on. **A fallback grants routability, never
authority.**

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
| CLI / MCP server / file-backed Python `Stack.from_config` / native C/C++ path loader | `OVSTORAGE__` | `OVSTORAGE__ROOT` → `ovstorage.root` |
| broker | `OVSTORAGE_BROKER__` | `OVSTORAGE_BROKER__OVSTORAGE__ROOT` → `ovstorage.root` |
| REST gateway | `OVSTORAGE_REST__` | `OVSTORAGE_REST__OVSTORAGE__ROOT` → `ovstorage.root` |

For the CLI, MCP server, file-backed Python `Stack.from_config`, and native
C/C++ `StackConfig::from_toml_path`, the `OVSTORAGE__` prefix maps directly
into the `[ovstorage]` table, so
`OVSTORAGE__LAYERS__BYTE_CACHE__MAX_OBJECT_BYTES` sets
`ovstorage.layers.byte_cache.max_object_bytes`. The broker and REST gateway
load their own top-level config (`[listener]` / `[server]`, auth, attribution)
and read the stack as a nested `ovstorage` field, so their prefixes carry the
extra `OVSTORAGE__` (i.e. `..._BROKER__OVSTORAGE__…`) to reach a stack key. A
bare `OVSTORAGE__…` variable is honored by the CLI, MCP, Python, and native
C/C++ path loaders. The servers ignore it.

Environment values override the file. This overlay applies when the CLI, MCP,
Python `Stack.from_config`, or native C/C++ path loader loads configuration from
a file. Python's `toml=` and native C/C++ `StackConfig::from_toml_str` parse an
in-memory document and intentionally skip the overlay.

For the shared `OVSTORAGE__` stack loader used by the CLI, MCP, Python, and
native C/C++ surfaces, prefix and key matching is ASCII case-insensitive and
key paths after the prefix must contain only ASCII characters. Values must be
valid Unicode (`UTF-8` at the C boundary). Variables that target different
fields under the same table coalesce, so a table-valued override and a nested
override can be used together. Do not define multiple spellings that
canonicalize to the same key; the later process-environment entry wins, and
that enumeration order is not a portable configuration mechanism. On the
native C/C++ loader, inferred integers are limited to the TOML signed 64-bit
range; larger decimal values remain strings.

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
Python's `Stack.from_config(path=None)` uses the same MCP-style resolution:
`$OVSTORAGE_CONFIG`, then the default search path, then an empty stack.

Native C/C++ `StackConfig::from_default_path` mirrors the core library helper:
it tries `./ovstorage.toml`, then the XDG user config path, and returns no
config when neither exists. It does not inspect `$OVSTORAGE_CONFIG`; a native
host that supports that selection variable resolves it before calling the
explicit path loader.

## Portability: `ovstorage write-config`

`ovstorage write-config <PATH>` serializes your live stack as a
self-contained `[ovstorage]` document — every layer and every connection —
that runs verbatim under any host. Move the same file between the CLI, the
MCP server, and the REST gateway; each host layers only its own sections
(`[server]` or `[listener]`, each with its own `auth` block) on top of the
shared `[ovstorage]` stack.
