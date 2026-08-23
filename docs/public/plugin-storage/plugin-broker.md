# Broker storage plugin (kind `broker`)

> **Not recommended for new deployments.** This plugin is only useful against an
> `ovstorage-broker` daemon, which has not had enough validation for us to
> recommend building on it yet. This document is not linked from the backend
> index for that reason. It is maintained for deployments that already exist.

The `broker` plugin: a first-party `Backend` implementation that forwards
every Layer ABI call across the host ↔ broker gRPC
protocol to a configured upstream `ovstorage-broker` daemon. Lives in
`ovstorage-remote/ovstorage-plugin-broker/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
broker hop adds per-call authorization, broker-side metadata + byte
caching, and a credential boundary that keeps long-lived cloud secrets
off the calling host — subject to what the upstream backend puts in a
redirect, which the Threat model below sets out. From the Layer's
perspective `broker` is an ordinary plugin that happens to talk gRPC
to a broker instead of HTTPS
to a cloud — the same `.so` is loaded by the library (the canonical
Brokered topology) or by `ovstorage-broker` itself (chained brokers).

Operators who don't run a broker simply don't install the plugin;
everything is gated by which `.so` files are present in the plugin
directory.

## Public surface

- **Schemes**: none of its own. The plugin advertises no scheme prefix.
  Stack address roots come from the broker-published root snapshot
  (`ListAddressRoots`) through `Layer::list_address_roots` and its
  server-streaming `WatchAddressRoots` subscription; operators wire
  whatever route prefixes the broker publishes (typically `s3://`,
  `gs://`, `azure://`, `omniverse://`, `file://`, … depending on the
  upstream broker's configured routes).
- **Descriptor**: `kind = "broker"`, `display_name = "ovstorage broker"`,
  `supports_runtime_add = true`. Kind-wide `Capabilities::empty()` — the
  authoritative capability profile lives per-`AddressRoot` returned by
  the broker (`pb::AddressRoot.capabilities` mirrors the upstream
  plugin's per-route profile field-by-field, so the library advertises
  accurate `supports_recursive_list`, `supports_version_listing`,
  `supports_watch_directory`, `version_list_order`,
  `watch_directory_kinds`, `redirect_size_threshold`, etc. for each
  brokered route).
- **Config keys** (see the `BackendFactory::descriptor()` block in
  `src/lib.rs`):
  - `address` (**required**, `Text`): broker discovery / gRPC address.
    Accepts: an absolute path (Unix domain socket); `pipe:NAME`
    (Windows named pipe); `https://host` (HTTPS discovery — fetches
    `/api/v1/services`); `http://host` (plaintext-HTTP discovery for
    local dev — only honored against `localhost`, IP literals, and
    `.local` hosts); `grpc+tls://host:port` / `grpc+tcp://host:port`
    (direct gRPC, skipping discovery); or bare `host[:port]` (auto
    `http`/`https` based on locality). Endpoint aliases: `http://` →
    `grpc+tcp://`; `https://` → `grpc+tls://`. UDS / npipe channels
    are platform-gated to OSes that support them.
  - `oidc_client_name` (optional, default `"default"`): selects an
    entry from the broker's published `auth-config.clients.<name>`.
    Deployments that publish auth-config under a non-default key set
    this to match.
  - `persistence_id` (optional): durable account discriminator for the
    connection's stored credential. Set it when two connections point
    at one broker address and OIDC client but are meant for different
    accounts; give each its own value (`alice-work`, `ci-runner`). It
    is a durable key, not a label — choose it once and leave it, since
    changing it moves the connection to a fresh credential and requires
    signing in again. It is deliberately separate from `display_name`,
    so renaming a connection never disturbs its credential.
- **Credential methods** (see `BackendFactory::descriptor().credential_methods`):
  - **`client_credentials`** (advanced) — OIDC client credentials.
    Binds `client_id` and `client_secret`. Only valid against a
    discovery address (not direct gRPC endpoints): the plugin fetches
    `/api/v1/auth-config`, follows the `openid_configuration` URL, and
    drives a non-interactive client-credentials grant against the
    discovered IdP. Suited for service accounts and headless
    deployments.

  Interactive flows are requested through `Layer::authenticate_connection`.
  The host signals which mode is
  available through the `x-ov-iauth: browser|headless|none` gRPC
  metadata header attached by the broker-client SDK on every RPC. The
  broker reads this on its streaming `Auth` RPC, threads the parsed
  `InteractiveAuthCapability` into `RequestContext`, and forwards to
  `OAuthCredentialProvider::build_flow(backend, capability)`. The production
  broker-client's automatic remote TCP tier-3 path supports
  device-capable providers. A remote `Browser` request is downgraded to RFC 8628
  device flow when the bound provider supports it, because the client's browser
  cannot reach a PKCE listener on the daemon's loopback interface. A PKCE-only
  provider requires external client tooling to complete PKCE and invoke
  `RegisterCredential` explicitly with the resulting token. An explicit
  `Headless` request against that provider returns `Unsupported`
  rather than treating its authorization endpoint as a device endpoint.
  Absent or malformed values default to `Browser`; `None` causes the broker
  to emit a terminal `Failed { AuthRequired }` envelope without ever
  opening a browser tab or device prompt (the fail-fast shape render
  workers and CI hosts need). For daemon-driven device flow, the daemon
  persists the upstream access and refresh tokens before emitting success;
  token bytes never cross the `Auth` response stream.

## Discovery and auth

Connection setup is two-stage. The plugin first fetches
`<address>/api/v1/services` over HTTPS (or normalized HTTP for
loopback / IP-literal / `.local`) without an `Authorization` header.
The services document looks like:

```json
{
  "name": "Acme Production",
  "services": [
    { "type": "ovstorage-broker", "endpoint": "grpc+tls://broker.acme:8443" },
    { "type": "ovstorage-rest",   "endpoint": "https://rest.acme/v1" }
  ]
}
```

The plugin selects the first `ovstorage-broker` entry and connects to
its `endpoint`. Adjacent service types (`ovstorage-rest`, `ovlive`,
`ovthumbnails`, `ovuserinfo`) are discarded after validation — they
exist for embedding applications that want to consume the REST gateway
or adjacent services directly, but `broker-client` itself only talks
to the broker. A services document missing `name`, with an empty
`services[]`, or with no `ovstorage-broker` entry fails `instantiate`
with `NotConfigured`.

If `/api/v1/services` returns `401`, the plugin fetches
`<address>/api/v1/auth-config`, follows the published
`openid_configuration` URL to the standard OIDC discovery doc, reads
`authorization_endpoint` / `token_endpoint` /
`device_authorization_endpoint`, and drives whichever flow the host's
`InteractiveAuthCapability` allows. `403` from the services endpoint is
final and surfaces as `PermissionDenied` without re-auth. `404` / `410`
surface as `NotConfigured`; `408` / `429` / `5xx` and other non-2xx
status codes surface as `BrokerUnavailable`. JSON parse failures and
schema-class violations surface as `NotConfigured`.

Direct-endpoint addresses (`grpc+tcp://`, `grpc+tls://`, `unix:/...`,
`npipe:/...`) skip discovery — the channel opens against the address
directly without fetching either discovery document.

HTTPS-initial chains stay on HTTPS; loopback-HTTP-initial chains stay
on loopback HTTP; the redirect chain is capped at 5 hops. A cross-scheme
downgrade (HTTPS-initial discovery following a non-HTTPS hop, or
loopback-HTTP-initial following a non-loopback HTTP hop) fails as
`Unreachable`. Certificate validation goes through the system trust
store; there is no certificate pinning by design (modern CAs rotate
frequently; pinning creates operational burden without commensurate
security gain when TLS is already authenticated against system roots).

Once authenticated, the cached `tonic::transport::Channel` carries
`Authorization: Bearer <access_token>` on every RPC via an
`AuthorizationInterceptor` reading from the live `DiscoveryState`.
Token rotation (refresh, re-login, hot rotation via
`update_credentials`) reaches the live channel without rebuilding it.
That bearer authenticates the plugin to the broker and nothing else: it
is **never** forwarded to a redirect target. A redirect target carries
whatever authentication the upstream backend put on it, which for most
backends is a signature in the URL query. Azure's OAuth mode is the
exception and puts a storage-account bearer in the redirect's request
headers — see [the Azure plugin's redirect credential
scope](plugin-azure.md#redirect-credential-scope).

## Precondition shape

The broker wire forwards each precondition field verbatim to the
upstream backend:

- `ReadOptions::if_match` / `DeleteOptions::if_match` /
  `UpdateMetadataOptions::if_match` — opaque etag string.
- `WriteOptions::if_dest` — the `IfDestExists` tagged union
  (`Overwrite` / `Fail` / `MatchEtag(etag)`).
- `CopyOptions` / `RenameOptions` — `if_source: Option<String>`
  (source-side etag) and `if_dest: IfDestExists`
  (destination-side precondition).

The plugin does no precondition validation of its own. A caller
talking to a brokered `s3://corp-prod/` route sees the same
`IfDestExists::MatchEtag` etag semantics it would see in Direct mode —
the broker daemon dispatches into the same in-process `s3` plugin,
and any backend-specific refusal surfaces back through the wire with
the original message preserved.

## Layer-to-RPC mapping

| Layer method | Broker RPC |
|---|---|
| `list_address_roots` (snapshot) | `ListAddressRoots` — unary; populates `RootInfo.capabilities` |
| `list_address_roots` (updates) | `WatchAddressRoots` — server-streaming `Snapshot` / `Added` / `Removed` (broker emits one initial `Snapshot` from its current route table; ongoing delta emission requires a runtime-mutable broker route table, which the daemon does not implement today) |
| `stat` | `Stat` — unary |
| `read` (inline / stream) | `Read` — server-streaming. Wire shapes: `info, body, body, ...` (byte branch) or standalone `redirect` (`ReadResult::Redirect` for the host to follow). The `info, redirect` bridging shape is allowed by proto for forward compat; `broker-client` tolerates it but the broker does not emit it |
| `write` / `write_stream` | `Write` — bidirectional-streaming. First frame `WriteOpen` (dest, `size_hint?`, user metadata, `if_dest`); subsequent `chunk` frames. The proto can carry a `WriteRedirectBatch` on this stream, but the daemon does not emit one: `Broker::write` drives the redirect loop through its own in-stack follower and returns a terminal `WriteResult` on every success path. Client-driven redirects arrive on the `WriteRedirect` RPC below instead |
| `write_redirect` (body-less) | `WriteRedirect` — unary entry point that returns the first `WriteRedirectBatch` without opening a bidi stream. Plugin forwards `size_hint = None` faithfully — `Broker::write_redirect` applies no size policy of its own and passes the request down its stack, leaving the accept-or-refuse decision to the upstream plugin; contrasts with `nucleus` which refuses `None` because LFT multipart needs total length |
| `continue_write` | `ContinueWrite` — unary; carries each subsequent `WriteRedirectBatch` / `RedirectResultBatch` exchange for multipart uploads (S3 Initiate / Parts / Complete) |
| `delete` | `Delete` — unary |
| `list` | `List` — unary; `recursive` and `page_token` forwarded faithfully (no plugin-side refusal) |
| `list_versions` | `ListVersions` — unary; `page_token` forwarded |
| `get_latest_version` | `GetLatestVersion` — unary |
| `create_directory` | `CreateDirectory` — unary |
| `delete_directory` | `DeleteDirectory` — unary |
| `copy` | `Copy` — unary; `if_source` (etag) and `if_dest` (IfDestExists) forwarded |
| `rename` | `Rename` — unary; `if_source` (etag) and `if_dest` (IfDestExists) forwarded |
| `update_metadata` | `UpdateMetadata` — unary |
| `check_access` | `CheckAccess` — unary; broker intersects backend permission with broker authz decisions for requested ops |
| `watch_directory` | `WatchDirectory` — server-streaming `ChangeEvent { Object \| Lapsed }` |

`Auth` (server-streaming) and `RegisterCredential` (unary) handle the
broker's per-user upstream-OAuth flow. The daemon drives device flow and
persists its resolved token in the principal's `secret_tokens` row +
`SecretStore` before `Auth` emits success. `RegisterCredential` is the
explicit external-registration surface for a remote PKCE-only provider; it is
outside the production broker-client's automatic authentication flow. Client
tooling performs PKCE where its browser can reach the loopback callback, then
calls the authenticated RPC once with the resulting token. Neither RPC returns
upstream credential bytes.

## Streaming guarantees

The host dispatcher owns the redirect follower and the cache population
path. When the broker returns `ReadResult::Redirect`, the host's
in-process HTTPS client executes that request directly and bytes flow
cloud ↔ host without re-entering the broker. The request is usually
pre-signed; for a backend that authenticates through a header instead
it is that header the follower replays. When the broker returns
`ReadResult::Stream`, the gRPC server-stream wire
forwards each `body` chunk through the plugin and into the dispatcher
without an intermediate `Vec<u8>` drain.

`Write` streams are propagated chunk-by-chunk through the bidi RPC.
The `broker-client` plugin's `StreamingChunkRequests` records a
chunk-pull error into a shared `Arc<Mutex<Option<Error>>>` and fires a
oneshot `cancel_tx` before parking on `pending()`; the transport's
`write` races the bidi future against `cancel_rx` in a
`tokio::select!`, drops the in-flight RPC future on signal, which
propagates RST_STREAM(CANCEL) through tonic's HTTP/2 layer. The broker
server distinguishes that from a graceful EOF (`stream.message().await
-> Ok(None)` commits; `Err(status)` with `status.code() == Cancelled`
aborts), so a backend-side chunk-pull error aborts the upload at the
broker rather than committing a truncated body.

Range reads on `Read` are forwarded faithfully: `ReadOptions::range` is
not refused at the plugin boundary. Inverted ranges
(`start > end_inclusive`) are caught at the Layer boundary before any
wire call and return `InvalidArgument` (see Enforcement below).

## ACL semantics

The broker daemon owns authorization. Its outermost `builtin-auth` Layer
evaluates each request against the configured TOML policy before dispatching
to a backend. Policy is written over the *incoming caller-facing address* —
not the resolved physical target — so aliases remain explicit policy
boundaries and the policy language stays human-readable.

The `broker-client` plugin never runs policy checks of its own. It
forwards every Layer call faithfully and surfaces the broker daemon's
authz decisions back to the host as typed errors:

- `Allow` → call proceeds; the response carries the broker's
  `audit_id` and `policy_epoch` in the redirect envelope (when one is
  emitted) or in the response's tracing fields.
- `Deny` → `PermissionDenied` with the policy rule id folded into the
  error message as a stable, audit-safe explanation.
- Policy error → typed error per `ErrorCode`; broker fails closed and
  the backend is not called.

`list` and `watch_directory` apply per-item / per-event filtering in the auth
Layer; filtered-out entries and events are simply omitted, with no `Lapsed`
synthesis for authorization drops.

`check_access` intersects backend permission with broker authz
decisions for the requested ops — a backend-permitted op the broker
denies surfaces as denied in the union; a backend-denied op the broker
would allow surfaces as denied.

## Capability bits

The kind-wide descriptor advertises `Capabilities::empty()`. The
authoritative per-route capability profile comes from the broker on
`ListAddressRoots` (and `WatchAddressRoots` updates), mirroring the
upstream plugin's profile field-by-field. Routes whose prefix isn't in
the published roots default to `Capabilities::empty()` (conservative —
the host treats unknown brokered routes as supporting nothing until
the broker publishes them explicitly).

Per-route fields the broker forwards intact:
`supports_if_match_write`, `supports_no_overwrite_write`,
`writes_are_atomic`, `supports_copy`, `supports_rename`,
`supports_server_side_copy`, `supports_server_side_rename`,
`supports_atomic_rename`,
`has_real_directories`, `supports_list`, `supports_recursive_list`,
`wants_list_backed_stat`, `populates_subdirectory_metadata`,
`address_roots_are_dynamic`, `supports_version_listing`,
`version_list_order`, `populates_effective_permissions_on_stat`,
`supports_access_check`, `supports_watch_directory`,
`watch_directory_kinds`, `watch_directory_resumable`,
`watch_directory_max_lag`, `redirect_size_threshold`,
`supports_native_metadata_patch`, `supports_metadata_rewrite_emulation`.

## Enforcement

- **Inverted byte ranges refused.** `ReadOptions::range` with
  `end_inclusive < start` returns `InvalidArgument` at the plugin
  boundary before any wire call. The broker daemon would reject this
  too (the gateway-side range follower can't satisfy `end < start`),
  but catching at the plugin boundary saves a round-trip and gives a
  precise diagnostic rather than a downstream `Internal` from
  whichever upstream backend the broker dispatches to.
- **`write_redirect` with `size_hint = None` forwarded faithfully.**
  `Broker::write_redirect` accepts `Option<u64>` and forwards the
  unknown-size request through the Stack to the upstream backend, which
  emits the redirect batch (the broker holds the backend credentials but
  never mints a redirect itself — the plugin does, in the broker
  process); an emitted `WriteRedirect` can carry the body via
  `body_source` rather than a known `Content-Length`. Refusing here
  would deny a path the wire fully supports. (Contrasts with
  `nucleus`'s `write_redirect` refusal, which is grounded in LFT
  multipart needing total length to compute part offsets — the broker
  wire is not multipart.)
- **Precondition fields forwarded faithfully.** `if_match` etag,
  `if_source` etag, and `if_dest` (`Overwrite` / `Fail` /
  `MatchEtag(etag)`) cross the wire intact; the upstream plugin
  applies any backend-specific refusal.
- **`list` `recursive` / `page_token` forwarded faithfully.** The
  upstream plugin (or the broker's daemon-side dispatcher) decides
  whether to honor them; plugin-broker does not narrow.
- **No `filter_map(Result::ok)`.** Stream-path error propagation is
  explicit; chunk errors surface through `Body::Stream` end-of-stream
  errors, not silent drops.
- **Auth delegated to broker daemon.** plugin-broker holds no
  background credential-refresh task of its own. Streaming `Auth` carries
  daemon-driven prompts and terminal state; unary `RegisterCredential`
  accepts a client-completed PKCE result — that round-trip is the only
  credential surface the plugin participates in. OAuth refresh, secret-store
  persistence, and policy enforcement live broker-side.

## Threat model

In Brokered mode the library holds redirects forwarded by the broker
plus its own bearer token to the broker. **A compromised library
process can exfiltrate those redirects for as long as the credential
inside them keeps working.**

How long that is depends on the upstream backend and its auth mode, and
the broker does not bound it: there is no broker-side redirect TTL, and
`expires_at` on the redirect envelope is the backend's own statement of
when it wants the redirect re-minted, not a lifetime the broker
enforces. There is no policy key that caps the window; the control
operators have is the redirect-disclosure control described below,
which bounds who receives a redirect rather than how long it lives.
When the backend
scoped a fresh signature into the URL — S3's
presigned requests, GCS's V4-signed reads, Azure under Shared Key, all
of which default to five minutes — the exfiltrated capability is one
object for that window, and the sentence above is the whole story. GCS
resumable session URLs are equally narrow but live longer.

When the backend put a broader credential in the redirect instead,
neither the narrowness nor the short window holds.
**Azure is the case to know about**: under an operator-supplied SAS the
redirect carries that SAS verbatim, and under Entra OAuth a write
redirect carries the storage-account bearer. See
[the Azure plugin's redirect credential
scope](plugin-azure.md#redirect-credential-scope) for what each mode
discloses and how to configure around it.

The host redirect follower will not let a *read* redirect whose
credential authorizes more than the redirected request leave the process
that minted it. It follows such a redirect locally and returns a stream
instead — including where the redirect is larger than
`follow_reads_max_bytes`, since that cap decides what is worth following
into a cache, not what is readable. The reference broker configuration
sets the cap to 1 MiB, and a broker pointed at an Entra OAuth Azure
connection serves reads of any size, proxying them rather than handing
over the storage-account bearer.

What decides "authorizes more than the redirected request" is the
minting backend's declaration, not an inspection. An operator-minted
account-scoped SAS and a per-object signature are the same shape on the
wire, so nothing in the redirect distinguishes them. Header inspection
is used only as a one-way demotion: a backend declaring a request-scoped
credential that also attaches a header this host cannot account for as
inert is treated as connection-scoped, so the failure direction is a
proxied transfer rather than a disclosure.

Two things about the shape of that protection are worth knowing. The
graceful half lives in the `redirect_follower` layer, so a hand-written
broker graph that omits the layer does not get the local-fetch fallback
— but the guarantee itself is applied again at the broker's own
out-edge, which no graph can compose away. And **the write path is
governed too**, by the same operator key with the same value: a refused
write redirect returns `Unsupported` and the client proxies the body
through the broker, which is capped at 64 MiB.

Per-byte broker-side enforcement is intentionally not a feature
— there is no provider-portable way to make an already-issued S3 /
STS / SAS / GCS credential refuse the (N+1)-th read by itself.
Deployments that need per-byte enforcement run a forward proxy in
front of the cloud.

The bearer token the plugin carries to the broker is a short-lived
OIDC access token; refresh tokens (when the OIDC server issues them)
are persisted to the secret store through the shared
`ovstorage_plugin::oauth_secret_store` helper, which writes them with the
host's `secret_put` callback. The Rust host backs that callback with
`SecretStore`; a host that supplies its own callbacks decides where the
bytes land, so secret-store persistence is a property of the host, not of
this plugin.

A stored refresh token is keyed on the broker address, the OIDC client,
and `persistence_id`, and it carries a record of the identity — issuer,
client, principal — the provider minted it for. Warm continuation adopts
it only after the sign-in it drives authenticates as that same identity;
a session that comes back as somebody else is refused and the connection
prompts for interactive sign-in.

Where two connections without distinct `persistence_id` values are live
at once **in one process**, neither can attribute the shared entry: both
sign in interactively, neither writes it — including the write an
interactive sign-in itself performs — and a warning names the key. A
connection that has shared its key stays in that state for as long as it
is live, even after the sibling goes away — including a connection
created onto a key another one already holds, which removing the older
connection does not promote. Give the connections distinct
`persistence_id` values and reconnect to clear it.
That detection is process-local — two applications running as one OS
user each see themselves as the sole claimant, and the stored identity
record cannot separate them either, since the second process
warm-continues on the stored lineage and so authenticates as its owner.
Set `persistence_id` whenever one broker address and OIDC client serve
more than one account; it is the only discriminator that holds across
processes.

Connections are restored one at a time, so the first of a same-key pair
is genuinely the sole claimant at the moment it loads: it adopts the
stored credential and begins serving on it before the second exists. When
the second is restored and claims the key, that adoption is retracted —
the first connection is refused at its next credential operation and
signs in again, which binds it to whoever actually signs in.

The bound on that: the first connection keeps serving on the adopted
credential from its adoption until its **next credential operation**,
which with a valid access token is typically up to that token's lifetime.
It is not invalidated the instant the sibling appears. Setting
`persistence_id` prevents the window entirely, because the two
connections never derive the same key in the first place.

Worth stating plainly, because it bounds what any amount of machinery can
do here: without `persistence_id` the system has **no information**
distinguishing the two connections. Detecting the collision when the
sibling appears and forcing both to re-authenticate is the best available
answer, not a way-station to a better one.


A stored entry that names no identity at all is refused, and never
written. An entry is written and bound in place after the connection's
first interactive sign-in.

A refused write has a consequence beyond the entry it declined to touch.
Refresh tokens rotate: the provider spends the old token at the moment it
issues the successor. When the successor cannot be stored — because the
key is contended, because the binding names no identity, or because the
secret store is sealed or unavailable — the connection keeps working on the
successor in memory, and the plugin declines to present the stored token
to the provider while it knows the stored token to be behind. Replaying a
spent refresh token is what a provider's reuse detection looks for, and
providers that implement it may revoke the whole token family rather than
reject the one token.

**That knowledge is held in memory, and does not survive the process.** A
restart warm-continues on the stored token, which by then is the spent
predecessor. Two lines on the `ovstorage.connection` target mark it:

- `secret persist failed after all retries` (WARN) — the write was
  declined; the connection is serving on a credential the store does not
  hold.
- `connection torn down with outstanding credential persist-debt` (WARN)
  — the connection went away still in that state, with its stored token
  preserved. Whatever starts next warm-continues on a spent token. A
  purging connection removal prints this too unless its delete actually
  ran and succeeded: the delete is skipped when another live connection
  shares the stable id, and a failed delete is not retried.

What clears it depends on why the write was declined, and the two cases
differ sharply:

- **A transient store failure** — a busy or briefly unavailable secret
  store — is retired by the next durable write that succeeds, which for
  a rotating connection is its next token refresh. Note what that does
  *not* say: nothing retries the failed write on its own. The state is
  cleared as a side effect of the next write the connection would have
  made anyway, so it persists until then. A connection whose credentials
  carry **no expiry** schedules no background refresh at all, and may
  therefore make no further durable write for the life of the process —
  treat the warning as requiring action rather than waiting for it to
  clear.
- **A shared persistence key does not clear on its own, and removing the
  duplicate connection does not fix it.** A persistence key that has ever
  been claimed by two live connections stays ambiguous for the rest of
  those connections' lives, deliberately: that a sibling has gone away is
  not evidence of whose the stored lineage was. Give the connections
  distinct `persistence_id` values and reconnect — and expect to **sign in
  again**, because reconnecting builds a new connection with no memory of
  the token the old one was serving on.

In both cases, if a teardown warning was printed for a connection whose
stored token was preserved, sign in again for it before the next start
rather than letting that start warm-continue.

Both markers are log lines, and a hard crash prints neither: teardown is
the last point at which process-local state can be reported at all. A
durable record that survives a crash is tracked separately.

A `Redirect` carries whatever authentication the upstream backend put
on it — usually a signature in the URL query, but a header for Azure
under Entra OAuth and for Nucleus LFT. The plugin never forwards the
broker bearer token to those targets.

The plugin does not pin certificates and does not accept operator
overrides for the gRPC endpoint, OIDC issuer, or client ID —
drift between an operator override and the broker's advertised state is
a class of bug the no-overrides commitment refuses by construction.
Operators with stricter trust postures deploy custom CAs into the
system trust store.

TLS termination, mTLS client-cert validation, and listener authn
(peer credentials, signed or trusted-proxy JWT, forwarded headers, and
mTLS) all live on the broker daemon; plugin-broker is
the client side and authenticates with whatever the broker's listener
mode requires. Broker operator concerns — listener authn mode
selection, TLS cert provisioning, policy management, observability —
are owned by the [broker-operator persona](../broker-operator/README.md).

## Cancellation contract

This plugin's Layer methods accept `cancel: Option<CancellationToken>`.
The Layer ABI propagates the host token across the cdylib boundary,
but this plugin does **not** yet select on it inside gRPC client
futures, discovery fetches, or the mpsc-backed streaming bridges;
cancellation there relies on dropping futures and closing streams.
Plugins SHOULD also bound work with an internal deadline. Brokered
routes inherit this property — a
`Layer::read` call against a wedged upstream backend pins the
caller's outer timeout rather than the host's `CancellationToken`.
