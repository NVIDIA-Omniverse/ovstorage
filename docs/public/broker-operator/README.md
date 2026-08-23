# broker-operator persona

> **Not recommended for new deployments.** `ovstorage-broker` ships in the
> release archive and it runs, but it has not had enough validation for us to
> recommend building on it yet, and this document is not linked from the docs
> index for that reason. It is maintained for deployments that already exist.
> Interfaces described here may change.

> *I run `ovstorage-broker` — the gRPC daemon that holds long-lived
> cloud credentials, enforces per-call authorization, and dispatches
> through the embedded `ovstorage` Stack to backend plugins. I write
> its TOML, configure its listener and auth layer,
> consume its tracing fields, and debug what it does at runtime.*

This persona lands you at the `ovstorage-broker` binary in
`ovstorage-remote/ovstorage-broker/`. The daemon embeds the
`ovstorage` Rust crate so the dispatcher, routing table, plugin
loader, and `ovstorage-cache` substrate are all the same code clients
run in Direct mode; what's broker-specific is the gRPC accept loop,
the per-listener auth layer it dispatches through, broker-side
caching, and broker-side ownership of credentials and state.

Authentication and authorization are an auth wrapper composed over the shared
inner Stack, not host-side middleware. The shipped `builtin-auth` wrapper and
loaded plugin wrappers marked `auth_capable` may fill that role. The daemon
gathers the caller's opaque transport credential material and hands it to the
selected auth layer, which resolves the principal and enforces its authorization
contract. See [§ Auth layer](#auth-layer).

The broker is **single-tenant by design**: one broker, one credential
boundary. Separate trust scopes are separate broker deployments —
prod versus dev, two cloud accounts, mutually untrusted teams all run
separate brokers.

## Deployment

The broker ships as a single binary:

```sh
ovstorage-broker --config /etc/ovstorage/broker.toml
```

`--config PATH` is recommended. With no `--config`, the binary falls
back to `./ovstorage.toml` in the current working directory; if
neither resolves, it hard-fails before binding any socket.

Optional flags:

- `--listen HOST:PORT` — override the listener bind value for quick
  local runs. Per-listener TLS and the `auth` block still come from the
  config file.

`make dist` from the repo root assembles the daemon, the REST
gateway, the CLI, and every cdylib plugin into `dist/bin/` and
`dist/plugins/`. systemd, Docker, Kubernetes, and Helm packaging are
**not** provided; operators run the binary with their existing
process-management tooling and ship `OVSTORAGE_PLUGIN_DIR` into the
unit so the loader picks up the right backend cdylibs.

A minimal systemd unit (illustrative, not provided in-tree):

```ini
[Unit]
Description=ovstorage broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ovstorage-broker --config /etc/ovstorage/broker.toml
Environment=OVSTORAGE_PLUGIN_DIR=/usr/local/lib/ovstorage/plugins
User=ovstorage
Group=ovstorage
StateDirectory=ovstorage
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Configure SIGHUP to reload, SIGTERM to drain — both are wired through
the broker's `LifecycleController`.

## Configuration shape

The broker builds its shared inner data-plane Stack directly from the
`[ovstorage]` table — the layer graph, the byte/metadata cache roots, and
the follower's follow policy are all **layer config**, not broker
concerns; the broker guarantees its per-branch attribution and
per-principal upstream-credential security boundary around that graph.
The full `[ovstorage]` schema (layer tables, connections,
built-in kinds, env overrides) lives in
[`../configuration.md`](../configuration.md); this section shows only how a
broker wires it together with its listener, auth, and attribution
sections. The shipped default at
`ovstorage-remote/ovstorage-broker/ovstorage-broker.toml` is the canonical
starting point.

```toml
# /etc/ovstorage/broker.toml

# Trust-boundary attribution for `modified_by`: `user_metadata` (default)
# stamps the authenticated principal; `passthrough` forwards an upstream
# broker's stamp. Top-level key read by `BrokerConfig`, NOT `[listener]` —
# keep it above the first table header so TOML does not nest it.
attribution_strategy = "user_metadata"

# May a redirect carrying a credential broader than the redirected request be
# handed to the client that asked for it? Top-level key, same placement rule as
# `attribution_strategy`. Governs the read and the write path together.
#   "refuse" (default) — the broker moves the bytes itself instead.
#   "allow"            — these clients are inside the trust boundary.
# See "What a forwarded redirect discloses" below before setting "allow".
redirect_credential_disclosure = "refuse"

# ---- Listener ----
[listener]
bind = "0.0.0.0:8787"
trusted_proxy = false                   # set true only when behind a trusted proxy
# trusted_peers = ["10.0.0.0/8"]        # required when trusted_proxy = true on TCP

[listener.tls]
cert_path = "/etc/ovstorage/broker.crt"
key_path  = "/etc/ovstorage/broker.key"
# client_ca_path = "/etc/ovstorage/client-ca.crt" # required for mTLS authn

# Per-listener auth is fail-closed: the `auth` block is REQUIRED.
# `auth = "anonymous"` is the explicit unauthenticated allow-all opt-in.
[listener.auth]
kind = "builtin-auth"                    # or a loaded auth-capable wrapper kind

[listener.auth.config]
# OIDC bearer-JWT authn for a TCP listener (all three required together;
# omit all three for a peer-cred-only / anonymous-fallthrough listener):
authn_mode  = "jwt_verify"
jwt_issuer   = "https://login.example.com"
jwt_audience = "ovstorage"
jwt_jwks_url = "https://login.example.com/.well-known/jwks.json"
# peer_dev_current_user = true           # dev only: UDS/npipe caller = current OS user

# The policy rule set (`plugin` optional; defaults to ovstorage-authz-toml):
[listener.auth.config.policy]

[[listener.auth.config.policy.policy]]
id        = "team-read"
effect    = "allow"
principal = "team-*"
operations = ["read", "stat", "list"]
prefix    = "s3://corp-prod/team/"

[[listener.auth.config.policy.policy]]
id        = "team-upstream-auth"
effect    = "allow"
principal = "team-*"
# Both interactive Auth and proactive RegisterCredential use this operation.
operations = ["update_connection_credentials"]
prefix    = "https://assets.example.com/team/"

# ---- Discovery (optional) ----
[discovery]
bind = "0.0.0.0:443"                    # serves /api/v1/services + /api/v1/auth-config
name = "Acme Production"

[[discovery.services]]
type     = "ovstorage-broker"
endpoint = "grpc+tls://broker.example.com:8787"

[[discovery.services]]
type     = "ovstorage-rest"
endpoint = "https://rest.example.com/v1"

[discovery.auth_config]
openid_configuration = "https://login.example.com/.well-known/openid-configuration"

[discovery.auth_config.clients.default]
client_id = "ovstorage-cli"
scope     = "openid email ovstorage:read ovstorage:write"

# ---- Observability ----
[observability]
prometheus_bind = "127.0.0.1:9090"      # opt-in /metrics endpoint
# otlp_endpoint = "..."                 # reserved; surfaces Unsupported today

# ---- The shared inner data-plane Stack ----
# upstream_credential → alias → copy_rename_fallback → byte_cache →
# metadata_cache → redirect_follower → retry → router → attribution_s3 → s3
[ovstorage]
root = "upstream_credential"

# Per-principal broker-side upstream OAuth credential handling. The broker
# also inserts this security boundary when an operator graph omits it.
[ovstorage.layers.upstream_credential]
inner = "alias"

[ovstorage.layers.alias]
inner = "copy_rename_fallback"

[ovstorage.layers.copy_rename_fallback]
inner = "byte_cache"

# Broker-side byte cache. `max_object_bytes` gates and caps warm fills
# (0 = off).
[ovstorage.layers.byte_cache]
inner            = "metadata_cache"
cache_root       = "/var/lib/ovstorage/broker/cache"
state_root       = "/var/lib/ovstorage/broker/state"
max_object_bytes = 1048576

[ovstorage.layers.metadata_cache]
inner       = "redirect_follower"
max_entries = 4096
ttl_seconds = 30

# Where the broker keeps the credentials it uses to reach backends:
# `auth.sqlite`, its advisory refresh locks, and the credential bytes.
# Optional — omitted, it resolves the per-user platform default.
[auth]
state_root = "/var/lib/ovstorage/broker/auth"

# Follow small read redirects into the byte cache; cap matches the cache.
# An oversize read surfaces the redirect when the disclosure policy permits it,
# and is served as a stream — fetched here — when it does not. The size cap
# decides what is worth caching, not what is readable.
[ovstorage.layers.redirect_follower]
inner                  = "retry"
follow_reads           = true
follow_reads_max_bytes = 1048576

[ovstorage.layers.retry]
inner = "router"

# One branch per connected kind. A branch is the backend layer (`target`
# defaults to the kind) or an attribution wrapper over it — see
# "Where attribution sits" below.
[ovstorage.layers.router]
children = ["attribution_s3"]

# Broker-attested `modified_by` overlay for the `s3` branch (strategy from the
# top-level `attribution_strategy`).
[ovstorage.layers.attribution_s3]
kind  = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"

# ---- Backend connections ----
[[ovstorage.connections]]
backend_kind = "s3"
display_name = "prod-assets"
config       = { bucket = "prod-assets", region = "us-east-1" }
credentials  = { access_key_id = "${AWS_ACCESS_KEY_ID}", secret_access_key = "${AWS_SECRET_ACCESS_KEY}" }
```

### Upstream OAuth endpoint transport

The shipped broker-resolved upstream OAuth scope supports only
`backend_kind = "http"` as a first-party production read-side consumer. The
broker propagates the resolved principal's keyring reference on `stat`, `read`,
and `materialize`. The HTTP backend consumes it on `stat` and `read`; canonical
`materialize` reaches that authenticated read path when the leaf cannot stage
directly. The bearer is
sent only to HTTPS origins (literal `127.0.0.1` HTTP remains available for
local development). Provider parsing is backend-agnostic, but final broker
Stack composition rejects a provider kind for which the trusted host has not
registered the `UpstreamOAuthConsumerCapability::ReadSide` capability; this
prevents an authentication flow from reporting success for a backend that
ignores the credential on supported read-side slots. A custom read-side backend
integration registers that backend-kind/capability pair through
`OAuthProviderRegistry::with_consumer_capability` when composing the broker
rather than requiring another backend-kind branch in broker orchestration.
This capability does not promise
propagation through list, mutation, or multi-address operations; those operation
families are unsupported until the host registers an explicit capability and
the backend consumes the corresponding reference. Every
binding must still resolve to a route owned by its configured backend kind.
Durable OAuth metadata has one slot per `(backend_kind, principal)`, so
configure at most one named OAuth provider for a backend kind; duplicate
providers are rejected at startup instead of overwriting each other's active
keyring handle. Broker-built keyring handles also include a hashed namespace
derived from the canonical auth state root. Two broker deployments under one OS
account therefore use separate keyring entries when they use separate state
roots. The durable row's recorded handle remains authoritative during a state
root relocation; the next successful refresh or explicit registration records
the namespace for the root at its new location.

When the registered HTTP consumer rejects a stamped access token with `401`,
the broker conditionally invalidates only the credential epoch used by that
request, resolves the retained refresh token, and retries the operation once.
The epoch check prevents a delayed rejection from invalidating a credential
that another registration committed concurrently. A second `401` is returned
as `AuthRequired`; the broker does not loop or apply this recovery to unrelated
backend errors.

Each `[oauth_providers.<name>]` entry requires HTTPS authorization and token
endpoints. Literal `http://127.0.0.1/...` and `http://[::1]/...` endpoints are
accepted only for local development and hermetic test IdPs. A deployment whose
private IdP serves non-loopback HTTP must provision TLS before using this
configuration validation.

Daemon-issued device-authorization, token-exchange, and refresh requests do not
follow HTTP redirects or system proxy settings, and each request has a bounded
connect and total lifetime. Configure each endpoint as the final HTTPS URL; a
3xx response fails the authentication attempt without forwarding authorization
codes, PKCE verifiers, device codes, or refresh tokens to the redirect target.

The production broker-client's automatic remote TCP tier-3 path supports
device-capable providers. A remote caller that requests browser interaction is
served with device flow because its browser cannot reach the daemon's loopback
PKCE listener. A PKCE-only provider returns `Unsupported`; client-side PKCE is
outside the broker-client's automatic flow. Separate client tooling completes
PKCE locally and invokes the authenticated `RegisterCredential` RPC explicitly.
Local UDS and named-pipe callers can use the daemon-owned loopback PKCE flow
directly.

The `[ovstorage]` stack is the same schema the CLI and REST gateway read,
so one `ovstorage.toml` can feed broker + CLI + REST (each host layers
only its own top-level sections — `[listener]`/`[server]`, auth,
attribution — on top). `[[ovstorage.connections]]` registers backends at
startup on the composed Stack.

`make verify` from the repo root validates this config shape against
`cargo run -p ovstorage-cli -- list-routes` (which loads the same TOML, resolves
credentials, and exits non-zero on bad routes / unresolvable secret
refs without binding any sockets). Use it before deploying a config
change.

### Where credentials are stored

Three names in this file are close enough to be worth separating, and only one of them is this:

- **`[auth] state_root`** — the auth directory. `auth.sqlite`, the advisory refresh locks, and the credential bytes the broker uses to authenticate *to backends*. It must not be deleted casually: deleting it signs every connection out.
- **`[ovstorage.layers.byte_cache] state_root`** — byte-cache index state. Layer config, a different setting that happens to share a name, and safe to delete while the broker is stopped.
- **`[listener] auth`** — the per-listener authentication policy, which decides who may talk *to* the broker. Nothing to do with credential storage.

Resolution order for the auth directory is `[auth] state_root`, then `OVSTORAGE_AUTH_DIR`, then the platform per-user data directory (`$XDG_DATA_HOME/ovstorage/auth`, `~/Library/Application Support/ovstorage/auth`, `%LOCALAPPDATA%\ovstorage\auth`). The config key sits ahead of the environment variable deliberately: a broker running as its own service user is configured by a file you own, and an inherited environment variable should not silently redirect where its credentials land.

The directory is created `0700` and the database `0600`, with an owner-only DACL on Windows, and both are corrected on every start rather than only on the one that creates them — so a directory left permissive by an earlier release is tightened before any credential is written into it. That permission is the whole of the protection: it stops another OS user on the host reading the credentials, and it stops them landing in a backup or disk image readable by someone else. It does not stop a process running as the same user, and nothing here claims otherwise.

**Two processes running as one OS user share these credentials.** That is intended — it is what lets a broker and a CLI session reach the same connection without signing in twice. A broker running as its own service user therefore gets its own directory and shares nothing, which is usually what you want for a daemon; set `state_root` explicitly when you want to be sure, or when two brokers on one host must stay isolated from each other.

## Where attribution sits

The attribution overlay stamps the authenticated principal into the
reserved `user_metadata` key `ovstorage-modified-by` on every mutating
call **that carries caller metadata** — `write`, `write_stream`,
`write_redirect` and `update_metadata` — and harvests it back into the
typed `modified_by` on read. It sits **below the router, one instance
per branch** — not at the root of the graph — and only on branches whose
backend can carry that key.

`continue_write` — the call a client makes to finalize a redirect write —
carries no caller metadata to stamp, and what its commit applies or reports
travelled out to the client inside the plugin's continuation or came back as
a captured response. So under `user_metadata` the overlay stamps the principal
on the result itself, and asserts it on the request for the plugin to use in
place of whatever came back when the plugin is the one writing it.

The two halves of that sit in different places. What the finalize call
**reports** is asserted by the overlay itself, so it is right for every branch
that carries the overlay, including `broker` branches and backends this build
has never heard of. What the backend **persists** can only be asserted by the
plugin, because only the plugin can decode its own continuation — so that is
the one obligation a backend carries, and a backend that binds its metadata
when the redirect is minted does not even carry that.

`write_redirect` and `continue_write` are separately authenticated calls, and
nothing binds them to one principal. Where a different principal finalizes an
upload, **which value carries that principal depends on when the backend wrote
it**: on Azure's staged commit the object itself
records the finalizer, and through the storage-service's metadata service it
does too as far as a best-effort update after the write can carry it; on S3 and
GCS the object was bound when the upload was created and keeps the minter, with
only the finalize call's own response naming the finalizer. Azure's inline
redirect is neither — the client's own PUT bound the object and Azure signs no
headers, so there the object holds whatever the client sent and only the
response is asserted.
The per-branch table below says which each backend does.

Two things follow from that placement, and both are why it is there.

**An emulated copy or rename is attributed.** The `copy_rename_fallback`
wrapper serves a backend that declines a copy by fabricating a write and
issuing it through its own `inner`. Only a layer *below* that wrapper is
in the fabricated write's path, so a branch-level instance stamps the
destination of an emulated copy and an instance at the graph root does
not.

**The broker does not manufacture metadata that a backend has declared it
cannot keep.** A backend with no caller-owned user-metadata facet is
required to reject a non-empty `user_metadata` rather than silently drop
it (see the plugin CONFORMANCE guide, *Write options* and
*`update_metadata`*). A broker that stamps every write from the root
therefore makes every write to such a backend fail, for objects nobody
asked to carry metadata. Omitting the layer on that branch is what fixes
it. A client that supplies `user_metadata` of its own still reaches that
backend and is still refused — correctly, because that request did ask.

**Each backend kind answers this for itself.** A plugin declares
`supports_user_metadata` on its kind descriptor, and the broker composes
the attribution layer only over a branch whose backend declares that it
accepts the host's stamp. A kind that declares nothing gets no layer, so a
third-party plugin is not handed a reserved key it would have to refuse.
The table below records what each shipped backend kind declares and why.

**That omission has a second effect, and it is not protective.** The
attribution layer is also the only thing on the path that strips inbound
`ovstorage-*` keys, so a branch without it does no sanitizing: a client's
own value for the reserved `ovstorage-modified-by` key reaches the backend
unaltered. Whether it is stored is that backend's business, and the
declaration does not settle it — declining says the kind will not take the
host's stamp, not that it refuses metadata a caller supplies. Read
[What a branch without the layer gives up](#what-a-branch-without-the-layer-gives-up)
before you put a broker in front of a host with declining branches; the
consequence lands on the outer broker, not on the branch itself.

Two limits are worth stating. The declaration is per **kind**, not per
root, so a kind serving roots that disagree has to pick one answer for
all of them. Declaring support means the stamp reaches roots that cannot
store the key, and what such a root does with it is that backend's own
behaviour: conformance asks it to refuse the write rather than drop the
key, and the `omniverse-storage-service` row below records a deliberate
deviation from that rule. Declining
means no branch of that kind is stamped even where the root could have
kept the key, which is what `opendal` chooses. And **declaring a branch
without the layer does not help**: the guarantee fills an empty position, so the
layer comes back on a branch whose backend declares support.

If you run a backend that declines and your graph explicitly declares an
`attribution_<kind>` layer over it, the broker **refuses to start** with
`misplaced attribution layer ... sits over '<backend>', whose kind declares no
user-metadata support (supports_user_metadata = false); that branch takes no
attribution layer at all`.
Delete that layer's table **and** re-point whatever named it — a router's
`children` entry, another layer's `inner`, or `root` where the graph forks
nowhere — at the backend layer directly. Deleting the table alone leaves a
dangling reference and a second startup failure reading `layer '<name>' is
referenced but not declared`.

If you need a branch that declares support to stop being stamped, the
only lever is process-wide:

**`attribution_strategy = "passthrough"`, and it costs more than it
looks.** Every stamp function returns early under
`passthrough`, and the inbound sanitizer has no other caller — so the
flag disables the stamp, the harvest **and** the inbound `ovstorage-*`
sanitizing for every branch in the process, not just the one with the
problem. Clients on your `file`, `s3`, `gcs` and `azure` branches can
then plant reserved keys of their own. Reaching for it to fix an
availability problem on one branch trades a much larger guarantee for it.
The branch with the problem need not be a third-party one: the declaration
is per backend kind, so a kind whose roots disagree declares one answer for
all of them, and `omniverse-storage-service` is a shipped kind that declares
support and can still meet a root that cannot store the key.

### How a copy is attributed

`copy`, `rename` and `create_directory` are the exceptions, and they
are structural: neither `CopyOptions` nor `RenameOptions` has a
`user_metadata` field, so there is nothing for the overlay to stamp. It
harvests the results of `copy` and `create_directory`; `rename` returns
nothing to harvest and simply passes through.

That leaves the destination of a transfer attributed differently
depending on whether the backend performed it. A transfer the backend
**declines** is emulated by `copy_rename_fallback` as a read plus a
fabricated write, and that write goes through the branch instance — so
its destination is attributed to whoever asked for the copy. A transfer
the backend performs **natively** carries whatever that backend's own
copy carries, which is not uniform:

- `file` copies its metadata sidecar, and `s3` and `azure` use their
  services' default copy semantics, so the destination keeps the
  *source's* stamp and reads as written by whoever wrote the source.
- `gcs` is the odd one. Its rewrite normally preserves source metadata,
  but when the operation carries a `message` the plugin sends a body
  containing only that message — and the service treats a supplied
  metadata object as the destination's complete metadata. A GCS copy
  with a message therefore lands with **no** stamp at all, neither the
  source's nor the caller's.
- `omniverse-storage-service` records user metadata through a separate
  metadata service after the write. Its copy calls that service only for
  the operation's `message` and never for the source's other keys, so the
  plugin contributes no stamp to the destination. That is an inference
  from the plugin; the backing service's own copy semantics are not
  observable from here.

Attributing a native transfer to the caller would need a
`user_metadata` field on `CopyOptions`, which the plugin SPI does not
have.

### Which branches carry it

| Branch kind | Carries attribution | Why |
| --- | --- | --- |
| `file` | yes | Persists user metadata in a sidecar and returns it on `stat` and `list`. |
| `s3` | yes | `x-amz-meta-*` on `PutObject`, on multipart, and signed into the presigned URL. What a multipart redirect write persists is bound when the upload is created and a single-PUT redirect's is bound by the presign signature, so the client never holds either, and this branch owes nothing at the finalize. For the multipart shape the `ObjectInfo` the finalize call reports is rebuilt from the continuation the client echoed back, and the overlay stamps it with the principal the broker authenticated on that call; the single-PUT shape reports no user metadata at all. Where one principal drives the whole upload those are the same value; where a different principal finalizes, the report names the finalizer and the object keeps the minter. |
| `gcs` | yes | Object `metadata` on upload and on the resumable-session initiation behind a redirect write, so what a redirect write persists is committed before the client uploads at all and the client never holds it. The `ObjectInfo` the finalize call reports is parsed from the response body the client captured and handed back, and the overlay stamps it with the principal the broker authenticated on that call. Where one principal drives the whole upload those are the same value; where a different principal finalizes, the report names the finalizer and the object keeps the minter. |
| `azure` | yes | `x-ms-meta-*` on Put Blob, on the presigned PUT, and at Put Block List. A **staged** redirect write commits through the broker's own `Put Block List`. Under `user_metadata` that commit stamps the principal the broker authenticated on the finalize call, so the metadata the client held cannot decide it; under `passthrough` — including on the deeper brokers of a chain, which this page tells you to set that way — nothing is stamped there and the metadata the client held is what lands. **Caveat, on the inline redirect only:** those headers accompany the presigned request, Azure's SAS signs no headers, and the client's own PUT is the commit — there is no later call of the broker's to write with, so a client taking that redirect can rewrite or drop the stamp on the object. Under `user_metadata` the `modified_by` the finalize call reports for such a write is stamped by the overlay, so a report cannot name a writer that broker did not authenticate even though the object can; under `passthrough` nothing is stamped there either. S3 signs its metadata into the presigned URL and GCS commits it server-side at session start; Azure does neither. This is a property of the plugin's presign, not of where the layer sits. |
| `omniverse-storage-service` | yes | Records it through the metadata service after the write, including after a redirect finalizes, where under `user_metadata` it stamps the principal the broker authenticated on the finalize call rather than the copy the client held — and under `passthrough`, including on the deeper brokers of a chain, the copy the client held is what lands. Best-effort **for the reserved keys**: where every key that failed is one of the host's own, a metadata-service failure there is logged and discarded, so the object write still succeeds and the key keeps whatever value the object carried before (a caller's own key failing still fails the write, where "own" means outside the reserved namespace — the split is made by `is_reserved_metadata_key`, so a caller-supplied reserved key is exempted too) — while the finalize call's own response still reports the principal this broker authenticated, so a failed stash shows up as that response disagreeing with a later `stat` of the same object. Discarding it is a deviation from the multi-stage durability rule, which asks for a failure of a later durability stage to be surfaced to the caller; the plugin's own page records that. |
| `broker` | yes | Forwards `WriteOptions` verbatim to the upstream. This is what preserves the original principal across a `user_metadata → passthrough` broker chain: a `broker` branch without the layer hands the upstream nothing to forward, and a `passthrough` upstream stamps nothing of its own, so the object lands with no attribution at all. |
| `nucleus` | **no** | Rejects a non-empty `user_metadata` with `Unsupported` on `write`, `write_stream` and `write_redirect`. It also never returns user metadata, so the branch gives up no harvest. |
| `opendal` | **no** | Rejects a non-empty `user_metadata` on presigned writes outright, so a stamped branch loses the redirect path for every OpenDAL connection whose driver presigns at all — silently, because the follower catches `Unsupported` and falls back to an ordinary write, pulling every byte through the broker. On the buffered and streaming slots it keeps the key when the connection's driver supports it and **refuses the write otherwise**, per the reject-rather-than-drop rule cited above. Whether a stamp survives is therefore a per-connection fact one branch cannot settle: stamping costs a metadata-capable driver its presigned path and fails every write to a driver without metadata support. |
| `http` | **no** | Read-only: every mutating verb is unsupported, and `stat` reports an empty user-metadata map. |
| anything else | whatever it declares | A kind that declares nothing carries no attribution layer. |

For a **chained broker** — this broker fronting another one — the branch
carrying attribution is only half the answer; the other half is
`attribution_strategy`. Leave it `user_metadata` on the broker your
users authenticate to, and set `passthrough` on the brokers behind it,
so the first broker's stamp survives to the backend instead of each hop
re-stamping with the previous hop's service account. Two
`user_metadata` brokers in a chain lose the original principal at the
deeper one.

`opendal` and `broker` are the honest hard cases: one branch fronts many
connections whose behaviour differs, so neither answer is right for all
of them. `opendal` comes off, which costs a connection whose driver
*can* store user metadata its stamp and its harvest. `broker` stays on,
which costs a connection whose upstream ultimately lands on a
metadata-less backend the write itself — `Unsupported`, the same failure
a direct `nucleus` branch would have raised.

### What a branch without the layer gives up

The layer is the only sanitizer and the only harvester on the path. A
branch that omits it gives up both:

- **Harvest.** A reserved `ovstorage-*` key already stored on one of that
  branch's objects is surfaced to clients verbatim inside
  `user_metadata`, instead of being promoted to the typed `modified_by`
  and hidden.
- **Inbound sanitizing.** A client's own value for the reserved key
  reaches that backend unaltered. On that branch it stays a raw
  `user_metadata` entry, and `modified_by` reports whatever the backend
  natively knows, if anything.

**That second consequence does not stay on the branch, and it is the one
to weigh.** A `broker` branch carries the layer — deliberately, so an
upstream stamp survives a chain — and harvests whatever the host beneath
it returned. So a value planted on an unsanitized branch of broker B is
promoted to the attested `modified_by` when read through a broker A that
fronts B, and a client of A cannot tell it from a real one.
**`modified_by` from a chained broker is only as trustworthy as the
sanitizing on every branch beneath it.** No policy decision reads
`modified_by`, so the impact is on display and audit integrity rather
than access control — but it is a narrowing of what the field means.

The raw keys that surface are also worth naming: they are principal ids,
often email-like, moving out of a hidden reserved namespace into the
generic `user_metadata` channel that ordinary clients read.

**Which branches this reaches is not a fixed list.** Of the shipped kinds,
`nucleus` and `http` are safe on their own behaviour rather than on the
declaration: neither stores nor returns user metadata, so neither can
happen there. On `opendal` over a driver that persists metadata, both can.
But the set is whatever declares `false` or leaves the field unset, so it
extends to any third-party kind a deployment loads — including one that
stores `user_metadata` perfectly well and declines only the host's stamp,
which is what `opendal` itself does, and one whose author never set the
field at all. **Audit the declining branches of every host you front**,
rather than reading this as a property of three known kinds. Closing it in
the host rather than per deployment needs a sanitize-only mode of the
attribution layer, composed over declining branches, which this release
does not have.

### Two properties of the mechanism worth knowing

**The strategy is process-wide.** `attribution_strategy` is injected into
the one factory that builds every instance, so a graph varies
attribution's *placement* per branch but never its *behaviour*.
`passthrough` on one branch and `user_metadata` on another is not
expressible; a branch that must not stamp omits the layer.

**The placement is canonical, and the broker enforces it.** An attribution
layer belongs directly above a backend that can carry the key. The
broker adds one wherever that position is empty, and **refuses to start**
if the graph declares one anywhere else — over the router, or part-way up
a branch — naming the layer and where it belongs.

One exception, in the safe direction: a layer nothing routes through
stamps nothing, so an attribution layer unreachable from the graph root
is logged at `WARN` rather than refused. Refusing there would take a
broker down over a leftover table with no effect on anything, on an
ordinary restart.

Refusing rather than quietly relocating is deliberate. The only change
the broker makes to a declared graph is to add an attribution layer to a
branch that has none, re-pointing the one edge that must now point at
it. It never removes, reorders or reconfigures anything you wrote, so a
configuration the stack builder would have rejected can never be turned
into a working host that behaves differently from what you declared.

A single `attribution` table declared at the root, over the router, is
one such refusal: it would stamp the very branches this layout exempts,
so a `nucleus` branch would refuse every write.

**Correcting it is two edits, not one.** Delete the
`[ovstorage.layers.attribution]` table, **and** re-point whatever named
it at the layer it wrapped — for the shipped graph that means
`root = "alias"` in place of `root = "attribution"`. Deleting the table
on its own leaves `root` naming a layer that does not exist, and you get
a second startup failure on the same restart, about a missing root, with
no mention of attribution. With both edits done, an instance is placed
on every branch that can carry the key, which is what you want.
Declaring them yourself works too, one directly above each capable
backend.

A branch whose kind cannot carry the key is left with nothing above it,
which is why a broker connected only to such backends ends up with no
attribution layer at all. That is the design, not an oversight.

## Authn front-end

For `kind = "builtin-auth"`, authentication branches on
the listener transport, which is
auto-detected from the `bind` value: absolute path (`/tmp/sock`) ->
Unix domain socket; `pipe:NAME` -> Windows named pipe; `host:port` ->
TCP. Authenticated TCP listeners select an `authn_mode` in
`[listener.auth.config]`. Omitting it means signed JWT when all three
`jwt_*` settings are present, and anonymous TCP when none are present.
TCP listeners can run with TLS by setting `[listener.tls]`.
Plaintext TCP is valid for loopback / local deterministic use; a
non-loopback plaintext TCP bind is accepted only when `trusted_proxy =
true` and `trusted_peers = [...]` records the expected proxy peers.
The CIDR list is enforced by the auth layer before it consumes trusted
forwarded headers or an unsigned JWT; use a firewall or proxy ACL to
enforce the same boundary for other authn modes.

The daemon gathers the caller's credential material (transport tag +
peer creds + any bearer token) and hands it to the auth layer, which
resolves the principal per transport:

| Transport | Authn | Configured by |
|---|---|---|
| TCP | Signed bearer JWT: validate issuer, audience, lifetime, and signature against JWKS; claims become principal attributes. | `authn_mode = "jwt_verify"` plus `jwt_issuer`, `jwt_audience`, and `jwt_jwks_url`. The mode may be omitted when the complete OIDC triplet is present. |
| TCP behind a trusted proxy | Unsigned bearer JWT already validated by the proxy. The layer requires a subject, validates `exp` / `nbf` when present, and compares `iss` / `aud` against `jwt_issuer` / `jwt_audience` when those are set. It verifies no signature. | `authn_mode = "trusted_unsigned_jwt"`, `trusted_proxy = true`, and non-empty `trusted_peers`. Optionally `jwt_issuer` and `jwt_audience`; `jwt_jwks_url` is rejected. |
| TCP behind a trusted proxy | Identity and selected attributes from forwarded gRPC metadata. Duplicate identity or configured claim headers fail authentication. | `authn_mode = "trusted_forwarded_headers"`, optional `forwarded_identity_header` (default `x-forwarded-user`) and `[listener.auth.config.forwarded_claim_headers]`, plus the trusted-proxy settings above. |
| TCP with mutual TLS | SHA-256 fingerprint of the verified leaf certificate, as `mtls:sha256:<lowercase hex>`. | `authn_mode = "mtls"`, server cert/key, and `client_ca_path` in `[listener.tls]`. |
| UDS / named pipe | OS peer-credential identity (`uid:{uid}` / `sid:{sid}`). | Automatic for UDS / npipe binds. |
| UDS / named pipe (dev) | The host's current OS user, instead of the peer's credentials. Local-development convenience. | `peer_dev_current_user = true` in `[listener.auth.config]`. Avoid in production. |

For example, a proxy-authenticated listener can map metadata into policy
attributes as follows:

```toml
[listener]
bind = "0.0.0.0:8787"
trusted_proxy = true
trusted_peers = ["10.20.0.0/16"]

[listener.auth]
kind = "builtin-auth"

[listener.auth.config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "x-authenticated-user"

[listener.auth.config.forwarded_claim_headers]
team = "x-authenticated-team"
```

### What `trusted_unsigned_jwt` does and does not enforce

In this mode the fronting proxy holds the signing keys, so the broker
performs **no signature verification**. The auth layer enforces only:
the CIDR peer allowlist, a well-formed three-segment token with a named
`alg`, a non-empty `sub`, `exp` / `nbf` bounds when the claims are
present, and `iss` / `aud` string equality **when `jwt_issuer` /
`jwt_audience` are configured**. An `aud` array must consist entirely of
strings and contain the configured value; an array holding any
non-string member is rejected rather than searched. A configured check
requires the claim to be present: a token omitting `aud` is rejected once
`jwt_audience` is set.

Leaving `jwt_issuer` / `jwt_audience` unset means those claims are **not
enforced by the broker at all**. In that configuration the upstream
verifier MUST enforce the audience itself. A proxy that verifies
signatures but not `aud` — a common oauth2-proxy / envoy setup — lets any
token the same IdP minted for a different relying party authenticate as
an ovstorage principal. Set both settings unless the proxy is known to
enforce them.

When this mode is selected and either setting is unset, the auth layer
logs one `WARN` as the listener builds, naming the listener's `bind` and
the unset settings:

```text
WARN ovstorage.auth: listener leaves trusted_unsigned_jwt claim checks
unenforced ... listener=0.0.0.0:8787 unenforced=jwt_issuer, jwt_audience
```

It is a warning, not a startup failure, because a proxy that does enforce
these claims is a valid deployment. The default log filter
(`warn,ovstorage=info`) shows it without any `OVSTORAGE_LOG` override.

`jwt_jwks_url` is rejected in this mode: a JWKS would sit unused, and
accepting it would imply signatures are checked here. Use
`authn_mode = "jwt_verify"` for signature verification.

```toml
[listener.auth.config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://login.example.com/"
jwt_audience = "ovstorage-broker"
```

A resolved principal carries an id, an optional display name, and
attributes (JWT claims). On allow the auth layer stamps
`ext::PRINCIPAL_ID` (and the display name) downstream; downstream cache
scoping and attribution read it.

`trusted_proxy = true` is rejected at startup for UDS / npipe
transports because they carry no peer IP for `trusted_peers` to
constrain. Startup validates each IPv4/IPv6 CIDR, and the auth layer
rejects trusted forwarded-header or unsigned-JWT credentials unless the
captured connection peer is in that allowlist. Keep a network-layer
firewall or proxy ACL as defense in depth.

## TLS

For TCP listeners, set `[listener.tls]` to a cert / key pair the
broker reads at startup. For mutual TLS, also set `client_ca_path` to a
PEM CA bundle; tonic requires and verifies the client certificate before
the auth layer receives its DER leaf certificate.

Certificate hot-reload is not implemented. A cert rotation requires a
process restart; SIGHUP rejects changed listener TLS material rather than
reporting a reload that the bound listener did not apply.

For UDS / npipe listeners, TLS is not used; trust is OS-level (file
permissions for UDS, ACLs for named pipes).

## Auth layer

Authentication and authorization are one auth wrapper the broker composes over
its shared inner Stack and dispatches every request through. It is configured
per listener under `[listener.auth]`:

- `auth = "anonymous"` — the explicit unauthenticated allow-all opt-in
  (every principal, every operation, every address). Use it only for a
  trusted-local listener where the transport is the trust boundary.
- `[listener.auth]` with `kind = "builtin-auth"` and a
  `[listener.auth.config]` table — the authenticated form. The config
  table carries the policy rule set (`policy`), TCP `authn_mode`
  settings, optional OIDC `jwt_*` params, and the optional
  `peer_dev_current_user` flag.
- `[listener.auth]` with the kind of a loaded plugin wrapper whose descriptor
  declares `auth_capable = true` — a plugin-provided auth form. The broker
  passes `[listener.auth.config]` verbatim to that wrapper's factory.

For `builtin-auth`, the policy rule set is the TOML shape the first-party
`ovstorage-authz-toml` engine reads (`[[policy]]` rules with `id` / `effect` /
`principal` / `operations` / `prefix`). Its `authn_mode`, `jwt_*`,
and `peer_dev_current_user` settings are built-in-only. A plugin kind owns its
config schema and its credential-decoding and authorization behavior; plugin
auth uses the ordinary storage Layer ABI, and there is no separate authz
cdylib and no separate authz ABI.

For either auth form, forwarded metadata is available only on a TCP listener
with `trusted_proxy = true` and a non-empty, valid `trusted_peers` CIDR list.
The broker rejects an unallowlisted connection before dispatch. A plugin auth
config may set `forwarded_identity_header` (default `x-forwarded-user`) and a
`forwarded_claim_headers` string map; the host captures only those names,
preserves duplicates and input order, and passes the fields unchanged to the
plugin factory with the rest of its config.

**Fail-closed.** A listener with no `auth` block **refuses to start**
(`listener <name> has no auth configured`) — "no auth" is never a
silent default; it is the explicit `auth = "anonymous"` choice. An unknown
kind, a backend or router kind, or a wrapper without `auth_capable = true` also
refuses startup, so naming an ordinary wrapper cannot create an unauthenticated
listener.

The built-in layer provides the broker's synchronous write preflight. The
plugin ABI has no separate write-specific preflight slot, so a plugin-auth
listener dispatches the authoritative `write` through its auth Stack with a
pull-driven body: the broker does not read the request body until the
authenticated inner path pulls its first chunk. A conforming plugin auth
wrapper authenticates before delegating, so either auth form rejects an
unauthorized streaming write before its body is drained. After an allow, the
broker coalesces an empty or sub-threshold upload into replayable bytes and
keeps an over-threshold upload streaming, matching the built-in-auth body
selection and backend capability behavior. Size limits continue to bound the
allowed streaming path.

`copy` and `rename` decompose into their primitive `Read` / `Write` /
`Delete` checks; `list` and `watch_directory` post-filter entries /
events by per-item visibility. Auth decisions emit
`ovstorage_auth_decisions_total` (`outcome = allow|deny|error`).

Interactive `authenticate_connection` and proactive
`update_connection_credentials` are both authorized as the policy operation
`update_connection_credentials`, against the upstream address when the request
carries one. JWT or peer-authenticated listeners therefore need an explicit
allow rule for that operation and address prefix before users can run brokered
upstream authentication or register an externally completed credential. A
data-only rule such as `operations = ["read", "stat", "list"]` denies both
credential slots by default.

## Rule prefixes

Every rule that selects addresses — an authz policy `prefix`, an alias
`from`, a visibility address, a `broker_oauth_routes` route key, an
OpenDAL connection `prefix`, a Nucleus connection `server`, an HTTP
connection `prefix` — is matched on scheme, host, port and path,
comparing decoded path components. Nothing in that comparison reads a
query, a fragment, a username or a password. A configuration value the
system would drop, or read differently from how it spells, is a load
error rather than a silent surprise, and the startup message names the
offending rule and the field.

### Percent-escapes decode

Matching decodes path escapes, so `%25` means `%` and `%20` means a
space: `deny s3://b/100%25` protects the key `100%`, and `s3://b/pub x`
— which the URL parser serializes as `s3://b/pub%20x` — protects the key
`pub x`. Every spelling of one key resolves together, so there is no
escape-free rewrite that names the encoded form instead; point the rule
at the key you mean to protect. A key that literally contains `%25`
is named by escaping the escape: `s3://b/100%2525` protects the key
`100%25`, which is a different object from the `100%` above. A prefix
whose **serialized** form carries a percent-escape does not load until
the decoding is acknowledged once at the top of the policy document:

```toml
prefix_escapes_are_decoded = true
```

The load error lists every affected rule with the scope it resolves to,
so the review is a comparison rather than a guess. A bare `%` is not
affected: `s3://b/100%` is not encoded by the parser and names `100%`.

### Four spellings that are refused

Each of these reads like something other than what it matches, so the
broker refuses to start and the message names the rule.

**Two rules whose prefixes resolve to the same scope.** Authorization
ranks a rule by how many path segments its prefix pins, so two spellings
of one scope tie and the winner falls through to declaration order.
Writing one prefix *twice* is how a later rule deliberately supersedes
an earlier one, but two prefixes that merely *resolve* the same are
refused, because which one applied would be decided silently. The
spellings that collapse:

| written as | what the URL parser removes |
|---|---|
| `s3://b/private/` and `s3://b/%70rivate/` | the percent-escape decodes |
| `s3://b` and `s3://b/` | an empty path becomes `/` |
| `https://h:443/team/` and `https://h/team/` | the default port |
| `https://H/team/` and `https://h/team/` | the host's case |
| `HTTPS://h/team/` and `https://h/team/` | the scheme's case |
| `https://bücher.example/t/` and `https://xn--bcher-kva.example/t/` | IDNA |
| `http://[::1]/x/` and `http://[0:0:0:0:0:0:0:1]/x/` | the IPv6 form |
| `s3://b/pub x/` and `s3://b/pub%20x/` | the space encodes |

Delete one, give them genuinely different scopes, or — if you meant the
later rule to win — write both prefixes **identically**.

**A prefix using `\` as a path separator**, on `file:`, `http:`,
`https:`, `ws:`, `wss:` or `ftp:`. The URL parser folds `\` into `/`
for exactly those schemes, in the host as well as the path, so
`https://h/data\..\` would scope the whole host and `https://h\evil/data`
would scope a path the rule never named. Write it with `/`. On a storage
scheme (`s3:`, `gs:`, `omniverse:`) a backslash is an ordinary character
in a key and loads.

**A prefix with leading or trailing whitespace, or containing a tab,
newline or carriage return.** The parser strips those before it reads
the scheme or the path, so the rule would be checked as one string and
applied as another — `s3://b/team/.⇥.` (with a tab) would scope the
whole bucket. A space *inside* a key is fine and loads; it encodes as
`%20`.

**A prefix whose authority is not separated from its path by `/`**, such
as `s3://corp:\secret`. The parser ends the authority at the `\` and
moves the rest into the path, so `s3://corp:\secret%2F..%2F..` would
scope the whole bucket while reading as scoped to `secret`.

### A query or a fragment in a rule prefix

**A load error, on every field: an authz policy prefix, an alias `from`,
an alias `to`, and a visibility address.** An address names a node, and
neither a query nor a fragment is part of what names it — matching
compares scheme, host, port and path, and a fragment never reaches a
backend at all. An alias `from` of `logical://h/public` loads;
`logical://h/public#note` is refused for its fragment, and a visibility
address of `https://h/private?v=1` is refused for its query. Write the
prefix without it. Escape it as `%23` if the key really contains a `#` —
`%23` is an ordinary key byte and is untouched, as is `%3F` for `?`.

An alias `to` is covered by the same rule. The projection takes the
query from the caller's address when it has one and from the `to`
otherwise, so a query there would reach only the callers who supplied
none.

**The same rule reaches every other configuration address**, not only
rule prefixes: `plugin-http`'s `root_url` and `prefix`, the OpenDAL
connection `prefix`, a `broker_oauth_routes` route key, the `file`
connection's `root` and `prefix`, the Nucleus connection `server`, and
the services-client `service_address`. A **request** address is
unaffected and carries its query, which is where a caller pins a version
or presents a presigned URL.

### A rule prefix that carries credentials

**Credentials in a URL are not part of the scope a rule names.** Nothing
in the comparison reads the username or the password, so a rule written
with them covers its path for **every** credential, not for the one it
spells. The spellings whose reading is permissive are refused at load:

| written as | why it is refused |
|---|---|
| `allow` policy prefix, e.g. `allow s3://reader:token@b/reports/` | grants the path under any credential |
| alias `from`, e.g. `from = "https://reader:token@h/reports/"` | rewrites anonymous addresses under that path too |
| `visible` visibility prefix, e.g. `https://reader:token@h/team/` | advertises the path under any credential |
| `broker_oauth_routes` key, e.g. `"https://reader:token@h/uploads/" = "corp-idp"` | selects that provider for the path under any credential, including none |
| OpenDAL connection `prefix`, e.g. `prefix = "opendal://tenant:secret@fs/private/"` | publishes that address space under any credential, including none |
| Nucleus connection `server`, e.g. `server = "reader:token@prod"` | is published as the root `omniverse://reader:token@prod/`, selected under any credential — and the credential does not reach the wire |
| HTTP connection `prefix`, e.g. `prefix = "https://reader:token@h/team/"` | publishes that route under any credential, including none. Its `root_url` is a credential channel and still accepts userinfo; only an explicitly written `prefix` is refused. With no `prefix` the published route is derived from `root_url` with the userinfo stripped, so it publishes `https://h/team/` — a route you did not write |

**Write the prefix without the credentials.** They authenticate nothing,
so the rule means what it reads as meaning. Narrow it by path or by
principal if the credential was meant to be doing the narrowing.

The rules that widen the other way load: a `deny` policy prefix, and a
`hidden` or `suppressed` visibility prefix, hide or refuse more rather
than less. It is the same authoring mistake and it does change what the
deployment does — a path that answers for anonymous callers may stop
answering — so a credential-bearing visibility prefix logs a warning at
load whichever direction it takes. Only the direction that publishes is
worth refusing to start over.

Making such a rule visible later is refused too, not only at load: a
`hidden` rule with credentials in its prefix cannot be patched to
`visible` through `update_connection_attributes`, since that reaches the
same state by another door.

An alias `to` is not affected, because it is not a rule that selects
addresses — it is the address the rewrite produces, and nothing compares
it against a caller's address, so there is no scope to widen. What a
backend does with userinfo on the address it is handed is that backend's
own rule; the HTTP one authenticates from `root_url` and the declared
credential fields, and puts no address userinfo on the wire.

## Broker-side byte cache

Broker-side caching is the `byte_cache` layer in the `[ovstorage]` graph,
not a per-route knob. `max_object_bytes` gates and caps what the cache
stores:

```toml
[ovstorage.layers.byte_cache]
inner            = "metadata_cache"
cache_root       = "/var/lib/ovstorage/broker/cache"
state_root       = "/var/lib/ovstorage/broker/state"
max_object_bytes = 1048576              # cache threshold; 0 disables
```

Requests carrying broker-resolved OAuth credentials bypass byte-cache lookup
and fill because that cache is principal-agnostic. Their `stat` requests also
bypass metadata-cache lookup and fill: principal-scoped keys do not encode
credential revocation or replacement within one principal's slot. The
metadata-cache wrapper applies the same guard to a credential-bearing `list`
request as forward-looking defence, but the broker currently propagates the
credential reference only through `stat`, `read`, and `materialize`; brokered
OAuth does not currently promise authenticated `list`. Ordinary metadata
requests remain cached under the authenticated principal.

The broker uses `max_object_bytes` to gate the byte cache (default `0`
when the layer is present but the key is omitted — off). Raising the
threshold is an explicit decision: small same-datacenter fleets gain
round-trip savings (one warm broker connection instead of N cold cloud
connections) plus caching for objects under the threshold. To run
forward-only with no caching, drop the `byte_cache` (and
`metadata_cache`) layer from the graph and relink its neighbour's
`inner`.

The broker never mints redirects itself. It holds the backend
credentials and the backend plugin does the minting with them (S3
multipart, GCS resumable, Azure Service SAS, …); the broker forwards
what comes back through the Stack. Their lifetime is the backend's:
there is no broker-configured redirect TTL, and `expires_at` on the
envelope is the backend saying when it wants the redirect re-minted.
The lever over the exfiltration window is
`redirect_credential_disclosure`, which decides whether a redirect
broader than the request reaches the client at all.

### What a forwarded redirect discloses

Forwarding a redirect hands the calling host whatever credential the
backend put in it, and that is not uniform across backends. Whether
that is acceptable is a property of your deployment, not of the
credential, which is why `redirect_credential_disclosure` is yours to
set: a broker is not always a credential boundary. Sometimes it is a
central configuration point for clients that are already inside the
trust boundary — a pod of render agents in one datacenter behind one
broker — and handing those clients a credential discloses nothing they
were not already entitled to, while refusing costs them the redirect
path entirely.

The broker cannot answer that question by looking at a redirect. An
account-wide signature and one scoped to a single blob are the same
shape on the wire, so no amount of header or URL inspection recovers
the difference. Each backend therefore **declares** what its
redirect's credential authorizes, and this setting decides what the
broker does with that declaration:

| Declared | Means | Under `refuse` | Under `allow` |
|---|---|---|---|
| `none` | No credential; the URL alone fetches the target. | Handed over | Handed over |
| `request` | Authorizes this one request, and expires with the redirect. | Handed over | Handed over |
| `connection` | Authorizes the connection at large: other objects, and time beyond this redirect's expiry. | Withheld | Handed over |
| `unspecified` | The backend forwards a credential it did not mint and cannot classify. | Withheld | Handed over |

`unspecified` is fail-safe rather than neutral: a backend that cannot
say what a credential covers is treated exactly as `connection`.

The declaration is a one-way claim. If a backend declares `request`
and then attaches a header this broker cannot account for as
addressing or conditioning the request, the redirect is demoted to
`connection` — a declaration mistake costs a proxied transfer rather
than a disclosure. Inspection can lower a declaration, never raise
one.

#### What each backend declares

| Backend | Mode | Declares | What the client would hold |
|---|---|---|---|
| S3 | anonymous (public bucket) | `none` | A plain unsigned object URL. |
| S3 | credentialed read, and every write redirect | `request` | A SigV4 query presign over one key, one method, one 5-minute TTL. Carries the access-key id, never the secret. |
| GCS | anonymous / public bucket | `none` | A plain unsigned object URL. |
| GCS | service-account read | `request` | A V4 signature over one object and one method, 5 minutes. |
| GCS | write | `request` | A per-object resumable session URL: narrow, but comparatively long-lived. |
| Azure | `Anonymous` | `none` | Nothing; writes refuse this mode before a redirect is minted. |
| Azure | Shared Key | `request` | A freshly minted Service SAS scoped to the single blob, with only the permissions that operation needs and a five-minute expiry. |
| Azure | operator-supplied `sas_token` | `connection` | Exactly the token you minted, forwarded verbatim — the plugin holds no account key and a SAS cannot be attenuated without one, so it can neither read its scope nor narrow it. |
| Azure | Entra OAuth (client secret or federated) | `connection` | **The storage-account bearer.** Account-scoped rather than object-scoped, and it outlives the request. |
| Nucleus | LFT read and write | `connection` | The connection's own auth headers, which name no object, range or operation. |
| OpenDAL | every presigning driver | `unspecified` | A header set OpenDAL's driver returned, which this plugin did not mint and cannot classify. |
| Omniverse Storage Service | read and write | `unspecified` | Headers copied verbatim out of the service's response, whose scope is not this plugin's to state. |

Two entries deserve a second read before you set `allow`. **Azure
under Entra OAuth hands over an account-scoped bearer** — a completely
different exposure from a narrow, short-lived signed URL, and the one
worth checking your trust boundary against. **Nucleus LFT** is the
same shape: its credentials ride in `Authorization-Token`,
`Connection-Token`/`Connection-Signature` and, when the deployment
populates an access token, a literal `Authorization: Bearer`.

If you run Azure behind a broker and can choose the mode, **Shared Key
is the mode to run**: it is the only Azure mode whose redirects are
scoped to the object being transferred, so it keeps the redirect path
under the default policy. If you must run an operator-supplied
`sas_token`, mint the narrowest token the workload needs, with only
the permissions it uses and the shortest lifetime you can operate. A
*service* SAS can be backed by a container stored access policy, which
makes it revocable without rotating the account key; an account SAS or
a user delegation SAS cannot.

#### Where the policy is enforced, and what it costs

Two places, answering different questions.

The `redirect_follower` layer applies it first, and that is where a
refusal is cheap: the layer can fetch the bytes itself. A read of a
withheld redirect comes back as a stream, at whatever size — the
`follow_reads_max_bytes` cap decides what is worth putting in the byte
cache, not what is readable.

The broker applies it again at its own out-edge, on `read`,
`write_redirect` and `continue_write`. The layer graph above is
operator config: you may rename the follower, or omit it. A policy that
lived only in the layer would silently vanish from such a deployment,
and the broker would forward whatever the graph left it. There are no
bytes in reach at the out-edge, so that check refuses rather than
degrading. In a stock composition it never fires.

The cost lands on **writes**. A refused write redirect comes back as
`Unsupported`, which the client-side follower turns into a body write
through the broker — so the write still completes, proxied. That
proxied body is capped at 64 MiB, on cumulative length, streaming
included. Above that the write fails; there is no size at which it
recovers.

So on a connection whose redirects are declared `connection` or
`unspecified` — Azure under Entra OAuth or an operator `sas_token`,
Nucleus LFT, every OpenDAL presigning driver, the storage-service
client — brokered writes over 64 MiB
do not work under the default. Your options are to move that
connection to a mode whose redirects are request-scoped, to keep those
writes under 64 MiB, or to set
`redirect_credential_disclosure = "allow"` if the clients are inside
your trust boundary.

**That failure does not name the setting.** The refusal itself is
invisible: the client asks for a write redirect, the broker answers
`Unsupported`, and the client-side follower quietly retries as a body
write through the broker. What you see is that body write hitting the
cap —

```
ResourceExhausted: write body exceeded broker buffer cap of 67108864 bytes
```

— which reads like a broker sizing limit, because that is the layer it
came from. So the symptom to match on is `ResourceExhausted` with that
message, on a write above 64 MiB, on a connection in the list above.
Reads on the same connections are unaffected, which is a useful way to
tell this apart from a credential or connectivity problem.

**One limitation of `allow` on the REST gateway specifically.** A `307`
carries the redirect URL and nothing else — the gateway does not
forward the redirect's request headers, because HTTP has no way to
tell a client "and send these headers". So a redirect whose target
*requires* a header to succeed is surfaced under `allow` in a form the
client cannot execute, and the client sees the origin's rejection
rather than a gateway error. That covers the header-bearing backends in
the table above whose *reads* are redirected — Azure under Entra OAuth,
Nucleus LFT and the storage-service client. (OpenDAL is in that table
for its presigned writes; it mints no read redirect, and REST surfaces
no write redirect, so it never reaches this projection.) The default
`refuse` does not have this problem for those three, because it
withholds those redirects and serves the bytes instead.

**S3's requester-pays reads are the case the default does not save you
from.** `x-amz-request-payer` is on the inert list, which decides only
that the header does not narrow the redirect's declared credential
scope — the redirect stays request-scoped and is therefore delegated
under `refuse` as much as under `allow`. But S3 honours that value as a
request header and ignores it as a query parameter, so a gateway client
handed only the `Location` URL reaches S3 without it and gets a `403`
against a requester-pays bucket. Neither setting changes that, because
the policy is not what is failing — the projection is.

The only gateway configuration that serves such a bucket at every size
is `follow_reads = true` with **no** `follow_reads_max_bytes`, so the
gateway always fetches the bytes itself and never projects a `307`.
Setting a cap is not a partial fix in the way it looks: with a cap, an
object larger than it — **and any object whose size the origin does not
declare** — takes the unfollowed-redirect arm and `403`s exactly as
before, so the failure becomes size-dependent rather than going away.

Two things to weigh before setting it. The follower is a single global
layer, so `follow_reads = true` removes `307` surfacing for **every**
backend on that gateway, not only the requester-pays one. And the cost
of running uncapped is connection and bandwidth occupancy, not memory:
the follower returns a lazy stream and the REST read handler forwards
it chunk by chunk without ever collecting it, so peak memory stays
bounded by the chunk size times the in-flight chunks.

This is a property of the `307` projection rather than of the policy,
and it is the reason `allow` on a gateway is a narrower proposition
than `allow` on a broker.

**A refused write leaves the backend's upload state behind.** The
refusal happens at the broker's out-edge, which is *after* the backend
plugin has already minted the batch — and minting is not free for every
backend. Nucleus allocates an LFT content id, and the Omniverse Storage
Service opens a multipart upload, before either returns the redirects
the broker then declines to forward. The client falls back to a proxied
body write, `continue_write` is never called, and that allocation is
never finalized or aborted.

So on those two backends, under the default policy, every brokered
write above the size threshold that triggers redirects leaves one
orphaned upload. The same state is orphaned whenever a client crashes
between rounds; what the default policy adds is that it happens on the
ordinary path rather than exceptionally. Where the
backend has lifecycle rules for incomplete multipart uploads, configure
them; Nucleus has no abort call for an unfinalized LFT content id, so
its ids accumulate until the deployment reclaims them by other means.

Setting `redirect_credential_disclosure = "allow"` avoids this entirely
on connections where the clients are inside your trust boundary, since
nothing is refused and the upload completes through the redirect.

There is one further sharp edge on multi-round uploads. If a later
`continue_write` round returns a batch declaring a broader credential
than the first, it is refused and the upload fails, with any parts
already uploaded orphaned until the bucket's lifecycle rules collect
them. No in-tree backend does this — for all of them the declaration
is a property of the connection's auth mode, so a batch that starts
delegable stays delegable — but a plugin that changes mechanism
mid-upload would hit it.

The per-mode detail is on each plugin page, under "Redirect credential
scope" — for example the
[Azure plugin page](../plugin-storage/plugin-azure.md#redirect-credential-scope).

### Serving through a backing-store outage

The shipped `ovstorage-broker.toml` sets `lost_backing_fallback = true`
on this layer. That is the survive-backing-loss contract: when the
backend cannot answer a validating `stat`, the broker serves the last
content it proved for the address rather than failing the read, and
with this key set that includes a `stat` answering `NotFound`. See
[`configuration.md`](../configuration.md#byte_cache-availability-fallback)
for the full error-shape breakdown.

One bound is worth an operator's attention. A backend mutation and the
cache invalidation that follows it are two stores with no shared
transaction, so a broker killed between them (SIGKILL, OOM kill,
container eviction, power loss) leaves the address holding a validator
the backend has superseded. Nothing is served wrongly while the backend
answers stats; the first backing-store outage after such a restart can
serve the pre-mutation body — or a deleted object — as current, and
that state persists until the address is written again.

**The operational answer is to wipe the cache after an unclean
shutdown.** Remove `cache_root` before the broker restarts: deletion is
supported while no process holds the root, and the next open drops
every index row whose bytes are gone. This is the only step that ends
the exposure rather than narrowing it.

The automatic repairs are weaker than they look, and the shipped config
enables none of them. A read repairs an address only if it misses the
cache. Eviction fires only above `max_bytes` and takes the
least-recently-accessed rows first, while a fallback read refreshes the
access time on both the stale validator row and the body it names — so
a hot address survives eviction that reclaims colder rows around it,
and `max_bytes` bounds total cache size rather than the life of any
row. `watch_invalidation` covers out-of-band changes reported after the
drain opens, so it cannot repair the row the crash left. Both are
worth setting for their own sake; neither substitutes for the wipe.

Setting `max_bytes` needs a **process restart**, not a SIGHUP. The
`Cache` is interned in a process-global map keyed by `cache_root` and
reused for the life of the process — the same interning that keeps the
tee-resurrection guard intact across a reload — so a reload that
changes `max_bytes` while keeping `cache_root` runs on the original
cap. Nothing removes an entry from that map, so every cache-lifecycle
change — the cap, the roots, the wipe above — is restart-only.

## Policy management

The built-in auth layer evaluates the **fresh** policy on every request — there
is no policy-epoch counter, no per-request epoch stamp, and no cache
freshness mode. Revocation is automatic: the next request a revoked
principal makes is evaluated against the current policy and denied.
(`PolicyEpochStale` exists only as a wire error code; the broker never
raises it.)

On Unix the daemon installs a SIGHUP signal handler that re-reads +
re-validates the config, builds a fresh `Broker` — which reconstructs
the auth layer from the fresh `auth` config — and atomically swaps the
live broker pointer. New RPCs see the swapped broker immediately;
in-flight RPCs continue against the snapshot `Arc<Broker>` they
captured at dispatch (so the old broker is dropped only after its last
in-flight RPC completes). A failed reload logs and leaves the old
broker live. Listener bind, TLS material, and forwarded-header capture
changes require a process restart and are rejected by the reload guard.

Plugin auth kinds do not implement the built-in layer's in-place policy
hot-reload operation. SIGHUP reconstructs the plugin auth layer from its
verbatim config as part of the fresh `Broker`; operators must not expect a
plugin-specific policy document to mutate an existing plugin instance.

A live stream (`watch_directory`) opened before a revocation keeps
delivering change *notifications* for its already-authorized prefix
until the client disconnects; each emitted event is re-checked for
`Read` visibility, and any non-stream operation reflects the
revocation immediately.

Pre-deploy config validation: run
`cargo run -p ovstorage-cli -- list-routes --config <broker-config>` against
the broker TOML to load the same shared `[ovstorage]` stack the broker
builds, resolve credentials, and exit non-zero on bad routes
or unresolvable secret refs without binding any sockets. (`ovstorage-cli
--config <broker-config> list-routes` is the same surface from the
CLI binary.)

## Windows behavior

Windows has no SIGHUP. The broker on Windows installs CTRL_C /
CTRL_BREAK handlers that trigger drain-first shutdown (see below),
but it does not install a SIGHUP-equivalent reload path. Config
changes on Windows require a process restart.

## Observability

### Metrics

Prometheus `/metrics` is opt-in via `[observability] prometheus_bind =
"HOST:PORT"`; when set, the broker spawns an axum listener and serves
`text/plain; version=0.0.4` exposition.

Ten metric families register at startup:

- `broker_rpc_seconds` (histogram, label `op`) — RPC latency. Dormant
  (no observation sites in the current broker).
- `broker_cache_metadata_hits_total` — metadata-cache hits.
- `broker_cache_object_hits_total` — object-byte-cache hits.
- `broker_cache_object_fills_total` — object-byte-cache fills.
- `broker_cache_evictions_total` — dormant.
- `ovstorage_auth_decisions_total` (label `outcome` in
  `allow|deny|error`) — emitted by the built-in auth layer.
- `broker_watch_fanout` (gauge) — dormant.
- `broker_redirect_emissions_total` (label `kind` in `read|write`) —
  increments at every fixture-driven and plugin-driven redirect.
- `broker_lifecycle_events_total` (label `event` in
  `reload_ok|reload_failed|drain_start|drain_complete`).
- `broker_uptime_seconds`.

OTLP push is reserved (`otlp_endpoint` field surfaces `Unsupported` if
set). Operators wanting OTLP can layer `opentelemetry_otlp` onto the
existing `init_tracing_from_env` subscriber path.

### Health

Standard `grpc.health.v1` on the same gRPC endpoint as the rest of the
broker API. `Health/Check` reports `Serving` whenever structural backend-kind
introspection on the active auth-free inner Stack succeeds. The health
protocol carries no caller credential, so readiness does not invoke the
listener auth wrapper. Readiness is not flipped during drain (the gRPC server
stops accepting new connections via `serve_with_incoming_shutdown` but
`Health/Check` keeps the last reported state until the server thread exits) or
failed reload (the controller logs and keeps the old broker live).

### Tracing

In-broker calls flow through the same OpenTelemetry subscriber the
library uses. Broker spans add the following audit-safe attributes on
top of the library's set so traces carry the same fields an audit
sink would consume:

- `principal.id` — every object-IO span (`broker.stat`, `broker.read`,
  `broker.write`, `broker.list`, `broker.list_versions`,
  `broker.list_address_roots`).
- `object.address` — redacted via `RedactedUrl` (scheme + host + port
  + path only, no query / fragment / userinfo; an address with no
  authority, where every byte after the scheme is one opaque string,
  prints as its scheme alone) — on every object-IO span that has an
  address.
- `audit_id` — on `ReadRedirect` and `WriteRedirect` envelopes and on
  every `pb::ErrorDetail`. Freshly minted when `RequestContext.audit_id`
  is `None`.
- `cache.hit` and `redirect.kind` where applicable.
- `outcome` (`allow|deny|error`) on the `ovstorage_auth_decisions_total`
  counter.

`route.id` and `backend.id` are **not** stamped on per-RPC tracing
spans today: the broker does not stamp routes and does not expose the
dispatch's resolved backend without leaking. Closing the gap is a
tracked work item.

### Audit log shape

Durable audit sinks are **not** provided. The diagnostic fields land
in tracing spans, `pb::ErrorDetail` envelopes, and redirect envelopes
only. Operators that need an audit log point a log aggregator at the
broker's tracing output and filter on `audit_id` + `principal.id`.

Any sink that consumes these fields must redact physical URLs before
logging query strings or signed headers. The pipeline must never log
raw bearer tokens, credential bytes, or usable signed URLs.

## Debug runbook

### "The broker won't start"

1. Run
   `cargo run -p ovstorage-cli -- list-routes --config /etc/ovstorage/broker.toml`
   to validate the config without binding sockets. Bad routes,
   unresolvable secret refs, and invalid listener config all
   fail here before the broker accepts traffic.
2. Check the journal: the broker fails closed on a **missing `auth`
   block** (`listener <name> has no auth configured`), an invalid auth
   config (bad policy TOML, a partial `jwt_*` set, an unknown auth
   kind), a missing backend plugin, bad route binding, unavailable
   state root, unavailable cache root, or listener bind failure. The
   error is typed and names the offending field.
3. Confirm the cdylibs are where the loader expects them
   (`OVSTORAGE_PLUGIN_DIR`). A configured plugin auth kind must be present as a
   wrapper descriptor with `auth_capable = true`; `builtin-auth` needs no
   separate cdylib.

### "The broker accepts the call but every request fails authz"

1. Look at the tracing output for `ovstorage_auth_decisions_total
   {outcome="deny"}`. The deny path threads the policy's `reason` into
   the gRPC `PermissionDenied` message.
2. Confirm the principal's `id` matches an allow rule in the
   `[listener.auth.config.policy]` rule set. Look at the `principal.id`
   field on the failing span. A recent SIGHUP reload rebuilds the auth
   layer from the fresh config, so a policy edit takes effect on the
   next request; there is no epoch to advance or refresh.

### "The broker is up but no routes are visible"

1. Run `cargo run -p ovstorage-cli -- list-routes --config <broker-config>`
   from the broker host to load the same TOML the broker loads. If
   the routes are missing here, the config is missing them.
2. Check `[[ovstorage.connections]]` blocks — backends register at startup, and
   a missing or misnamed plugin manifest fails startup.
3. Confirm the embedded Stack publishes the expected address roots through the
   broker's `ListAddressRoots` RPC.

### "Streaming writes are slow / corrupted / aborted"

1. The broker server distinguishes graceful EOF (`Ok(None)` from the
   inbound stream) from RST_STREAM(CANCEL) (`Err(status)` with
   `status.code() == Cancelled`). Look for `broker.write` spans
   ending in `Status::cancelled` — that's the client-side abort path.
2. Inline upload size is bounded by `WRITE_BODY_BYTE_CAP` (64 MiB)
   after authz. Larger writes must use the redirect branch (S3
   multipart, GCS resumable, etc.); the plugin must mint redirects
   via `WriteStep::Redirects`.
3. Check `broker_redirect_emissions_total{kind="write"}` — a missing
   redirect emission means the plugin can't mint redirects for that
   route, and the broker is falling back to inline upload.

### "Lifecycle: reload didn't pick up my change"

1. `broker_lifecycle_events_total{event="reload_failed"}` increments
   when a SIGHUP reload fails validation. Check the journal for the
   typed validation error.
2. `broker_lifecycle_events_total{event="reload_ok"}` increments on a
   successful reload; the rebuilt broker's auth layer serves the fresh
   policy on the next request.
3. Windows hosts: no SIGHUP. Use a process restart.

### "Drain: shutdown hangs"

The broker drains on SIGTERM / SIGINT (Unix) and CTRL_C / CTRL_BREAK
(Windows) up to the configurable `drain_timeout` (default
`DEFAULT_DRAIN_TIMEOUT`). `serve_with_incoming_shutdown` stops
accepting new connections and runs in-flight RPCs to completion
within the timeout. If a worker RPC is wedged in a plugin (most
commonly a wedged upstream backend), the drain deadline expires and
the process exits with in-flight RPCs truncated. Tune `drain_timeout`
to the longest legitimate request your workload tolerates.

## Implementation gaps

- **Per-principal connection / RPC / watch limits.** A competing-consumer
  backend's SDK `WatchCoalescer` bounds each subscriber's queue depth (overflow
  injects a `Lapsed`) but enforces **no** per-principal watcher limit — a
  per-principal limit belongs at a central chokepoint (the broker or a limit
  layer), not in each backend's coalescer (where it would be
  per-principal-per-backend). There is no global per-watch-key fan-out cap
  either. Broader per-principal
  connection and RPC quotas mapped to `ResourceExhausted` are not implemented.
- **Durable audit sinks.** No `AuditRecord` / `AuditEvent` type,
  durable sink, or operator-facing `explain-decision` tool is
  provided. Diagnostic fields land in tracing spans, error details,
  and redirect envelopes only.
- **OTLP push.** Field reserved; surfaces `Unsupported` if set.
- **Certificate hot-reload.** Cert rotation requires a process restart;
  SIGHUP rejects listener TLS changes.
- **Crash-injection conformance.** Tests that crash the broker
  mid-redirect-issuance or mid-write are not implemented;
  partial-publish hardening rides on the `ovstorage-cache`
  substrate's atomic put.
- **Operator packaging assets.** systemd, Docker, Kubernetes, and Helm
  assets are not provided.

## Related

- [plugin-storage README](../plugin-storage/README.md) — backend
  plugin author concerns.
- [plugin-storage plugin-broker page](../plugin-storage/plugin-broker.md)
  — the `broker-client` cdylib that calls this daemon from
  library-side processes.
- [library-web README](../library-web/README.md) — the REST gateway
  in front of the broker.
