# Broker storage plugin (kind `broker`)

The `broker` plugin: a first-party `Backend` implementation that forwards
every `StorageBackend` SPI call across the library ↔ broker gRPC
protocol to a configured upstream `ovstorage-broker` daemon. Lives in
`ovstorage-remote/crates/ovstorage-plugin-broker/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
broker hop adds per-call authorization, broker-side metadata + byte
caching, and a credential boundary that keeps long-lived cloud secrets
off the calling host. From the SPI's perspective `broker` is an
ordinary plugin that happens to talk gRPC to a broker instead of HTTPS
to a cloud — the same `.so` is loaded by the library (the canonical
Brokered topology) or by `ovstorage-broker` itself (chained brokers).

Operators who don't run a broker simply don't install the plugin;
everything is gated by which `.so` files are present in the plugin
directory.

## Public surface

- **Schemes**: none of its own. The plugin advertises no scheme prefix.
  Library address roots come from the broker-published root snapshot
  (`ListAddressRoots`) during `Factory::instantiate` and through the
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
- **Config keys** (see the `Factory::descriptor()` block in
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
- **Credential methods** (see `Factory::descriptor().credential_methods`):
  - **`client_credentials`** (advanced) — OIDC client credentials.
    Binds `client_id` and `client_secret`. Only valid against a
    discovery address (not direct gRPC endpoints): the plugin fetches
    `/api/v1/auth-config`, follows the `openid_configuration` URL, and
    drives a non-interactive client-credentials grant against the
    discovered IdP. Suited for service accounts and headless
    deployments.

  Interactive flows (PKCE loopback for `Browser`, RFC 8628 device flow
  for `Headless`) are driven by `Factory::authenticate` against the
  same broker-published `auth-config`. The host signals which mode is
  available through the `x-ov-iauth: browser|headless|none` gRPC
  metadata header attached by the broker-client SDK on every RPC. The
  broker reads this on its streaming `Auth` RPC, threads the parsed
  `InteractiveAuthCapability` into `RequestContext`, and forwards to
  `OAuthCredentialProvider::build_flow(backend, capability)`. Absent
  or malformed values default to `Browser`; `None` causes the broker
  to emit a terminal `Failed { AuthRequired }` envelope without ever
  opening a browser tab or device prompt (the fail-fast shape render
  workers and CI hosts need). Successful interactive auth lands a
  refresh token on the broker side via `RegisterCredential`; the host
  process holds only the short-lived broker bearer.

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
Pre-signed redirect targets carry their own authentication in query
parameters; the bearer token is **never** forwarded to redirect URLs.

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

## SPI-to-RPC mapping

| SPI method | Broker RPC |
|---|---|
| `address_roots` (initial) | `ListAddressRoots` — unary; populates per-route capabilities on `BackendInstance.address_roots[i].capabilities` |
| `watch_address_roots` | `WatchAddressRoots` — server-streaming `Snapshot` / `Added` / `Removed` (broker emits one initial `Snapshot` from its current route table; ongoing delta emission requires a runtime-mutable broker route table, which the daemon does not implement today) |
| `stat` | `Stat` — unary |
| `read` (inline / stream) | `Read` — server-streaming. Wire shapes: `info, body, body, ...` (byte branch) or standalone `redirect` (`ReadResult::Redirect` for the host to follow). The `info, redirect` bridging shape is allowed by proto for forward compat; `broker-client` tolerates it but the broker does not emit it |
| `write` / `write_stream` | `Write` — bidirectional-streaming. First frame `WriteOpen` (dest, `size_hint?`, user metadata, `if_dest`); subsequent `chunk` frames; broker emits `WriteRedirectBatch` or terminal `WriteResult` |
| `write_redirect` (body-less) | `WriteRedirect` — unary entry point that returns the first `WriteRedirectBatch` without opening a bidi stream. Plugin forwards `size_hint = None` faithfully (the broker daemon's `BrokerRoutePolicy::should_redirect_write` accepts unknown sizes); contrasts with `nucleus` which refuses `None` because LFT multipart needs total length |
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
broker's per-user upstream-OAuth flow: when an upstream backend
demands re-auth, the broker emits `AuthEvent`s through `Auth`; the
broker-client SDK relays them to the host UI; the host drives the
interactive PKCE / device step; the resolved token rides back via
`RegisterCredential` and lands in the broker's `secret_tokens` row +
`SecretStore`. The host process never holds the upstream credential
bytes — only the broker does.

## Streaming guarantees

The host dispatcher owns the redirect follower and the cache population
path. When the broker returns `ReadResult::Redirect`, the host's
in-process HTTPS client executes the pre-signed request directly and
bytes flow cloud ↔ host without re-entering the broker. When the
broker returns `ReadResult::Stream`, the gRPC server-stream wire
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
(`start > end_inclusive`) are caught at the SPI boundary before any
wire call and return `InvalidArgument` (see Enforcement below).

## ACL semantics

The broker daemon owns authorization. Before dispatching any RPC to a
backend plugin, the daemon evaluates the request against its configured
`AuthzPlugin` (typically the in-tree `ovstorage-authz-toml`, but any
plugin built against the `ovstorage-authz` SPI). Policy is written
over the *incoming caller-facing address* — not the resolved physical
target — so aliases act as compatibility gates and the policy
language stays human-readable.

The `broker-client` plugin never runs policy checks of its own. It
forwards every SPI call faithfully and surfaces the broker daemon's
authz decisions back to the host as typed errors:

- `Allow` → call proceeds; the response carries the broker's
  `audit_id` and `policy_epoch` in the redirect envelope (when one is
  emitted) or in the response's tracing fields.
- `Deny` → `PermissionDenied` with the plugin's `reason` /
  `explanation` folded into the error message (the explanation is a
  stable, audit-safe handle such as a TOML rule id).
- Plugin error → typed error per `ErrorCode`; broker fails closed and
  the backend is not called.

`list` and `watch_directory` apply per-item / per-event filtering
broker-side via `AuthzPlugin::filter_list_batch`; filtered-out entries
and events are simply omitted, with no `Lapsed` synthesis for authz
drops.

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
`writes_are_atomic`, `supports_server_side_copy`,
`supports_server_side_rename`, `supports_atomic_rename`,
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
  The broker daemon's `Broker::write_redirect` and its
  `BrokerRoutePolicy::should_redirect_write` both accept
  `Option<u64>` and route unknown-size writes to the configured
  `write_redirect_endpoint` independently of plugin caps; the single
  emitted `WriteRedirect` carries the body via `body_source` rather
  than a known `Content-Length`. Refusing here would deny a path the
  wire fully supports. (Contrasts with `nucleus`'s `write_redirect`
  refusal, which is grounded in LFT multipart needing total length to
  compute part offsets — the broker wire is not multipart.)
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
  background credential-refresh task of its own. The streaming `Auth`
  + unary `RegisterCredential` round-trip is the only credential
  surface the plugin participates in; OAuth refresh, keyring
  persistence, and policy enforcement live broker-side.

## Threat model

In Brokered mode the library never holds long-lived provider secrets —
`broker-client` only holds time-bounded redirects issued by the broker
plus its own bearer token to the broker. **A compromised library
process can exfiltrate redirects for the rest of their lifetime.** The
exposure window is the redirect TTL, set on the broker side (default
300 seconds, max 3600 seconds, min 30 seconds; clamped at config
load). Per-byte broker-side enforcement is intentionally not a feature
— there is no provider-portable way to make an already-issued S3 /
STS / SAS / GCS credential refuse the (N+1)-th read by itself.
Deployments that need per-byte enforcement run a forward proxy in
front of the cloud.

The bearer token the plugin carries to the broker is a short-lived
OIDC access token; refresh tokens (when the OIDC server issues them)
are persisted via the OS keyring per the
`ovstorage-cache::OsKeyringSecretStorage` path. Pre-signed origin URLs
returned in `Redirect`s carry their own authentication in query
parameters; the plugin never forwards the broker bearer token to those
targets.

The plugin does not pin certificates and does not accept operator
overrides for the gRPC endpoint, OIDC issuer, or client ID — drift
between an operator override and the broker's advertised state is a
class of bug the no-overrides commitment refuses by construction.
Operators with stricter trust postures deploy custom CAs into the
system trust store.

TLS termination, mTLS client-cert validation, and listener authn
(JWT verify, trusted forwarded headers, trusted unsigned JWT, peer
cred, reserved mTLS) all live on the broker daemon; plugin-broker is
the client side and authenticates with whatever the broker's listener
mode requires. Broker operator concerns — listener authn mode
selection, TLS cert provisioning, policy management, observability —
are owned by the [broker-operator persona](../broker-operator/README.md).

## Cancellation contract

This plugin's SPI methods accept `cancel: Option<CancellationToken>`,
but the plugin does **not** thread cancellation through the gRPC
client futures, discovery fetches, or the mpsc-backed streaming
bridges; cancellation today relies on dropping futures and closing
streams. Per the cross-workspace cancellation contract, plugins
SHOULD bound their own work with an internal deadline; the host
does not propagate cancellation across the cdylib FFI today. Brokered routes inherit this property — a
`StorageBackend::read` call against a wedged upstream backend pins the
caller's outer timeout rather than the host's `CancellationToken`.
