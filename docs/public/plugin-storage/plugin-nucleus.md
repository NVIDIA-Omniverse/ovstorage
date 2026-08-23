# Nucleus plugin (`nucleus`)

The `nucleus` plugin: a first-party `Backend` implementation against
NVIDIA Omniverse Nucleus, the content-collaboration server for the
Omniverse platform. Lives in
`ovstorage-nucleus/ovstorage-plugin-nucleus/` and compiles as
a cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
plugin speaks Nucleus's native `omni1` protocol directly — there is
no third-party Nucleus SDK in the stack. Discovery and auth flow
over Nucleus's short-lived **SOWS** WebSocket transport; the
long-lived storage `Connection` socket uses **ConnLib** framing.
Bulk-bytes payloads ride a separate **LFT** (Large File Transfer)
HTTP side-channel rather than the WebSocket control channel. The
`omni1` IDL at `ovstorage-nucleus/nucleus-client/omni1.idl.ts`
is the source of truth for wire shapes; the
`nucleus-{auth,client,codegen,discovery,transport}` support crates
compile the IDL into typed Rust clients.

## Public surface

- **Schemes**: `omniverse://server[:port]/path`. The path is
  canonicalized like every other scheme's — escapes decoded, dot
  segments resolved, runs of `/` collapsed — so the server never sees a
  spelling ovstorage would resolve differently.
- **Descriptor**: `kind = "nucleus"`,
  `display_name = "Nucleus"`,
  `supports_runtime_add = true`.
- **Config keys** (see `nucleus_config_schema()` in `src/config.rs`):
  - `server` (**required**, `Text`, `host[:port]`): the Nucleus
    server. Validated by the plugin and lowercased into the
    canonical root.
  - `endpoint` (optional, `Url`): SOWS discovery override for
    production session establishment.
  - `prefix` (optional, `Text`, default `/`): Nucleus path prefix
    scoping which paths this backend instance serves. Write the path
    literally: it is a bare, decoded path rather than a URL, so `%`, a
    space, `?` and `#` are ordinary bytes in a folder name and a prefix
    containing them loads. It is
    compared against the path a request resolves to, so a spelling
    that normalizes to a different path — a doubled separator, a dot
    segment — names a scope no request can reach; such a prefix is
    refused at connection creation with the path it resolves to in the
    message, rather than accepted into a connection that answers
    `NoRoute` for everything beneath it.
  - `use_lft` (optional, `Bool`, default `true`): gates the LFT
    redirect path and the `LftClient`-backed bulk-bytes branches.
  - `persistence_id` (optional, `Text`): durable account
    discriminator. Set it when two connections point at one server
    but are meant for different accounts, and give each its own
    value (`alice-work`, `ci-runner`). It is a durable key, not a
    label — choose it once and leave it, since changing it moves the
    connection to a fresh credential and requires signing in again.
  The full non-secret config plus `display_name` forms the stable
  connection identity used for refresh-token persistence, and
  `persistence_id` is the discriminator to reach for when separating
  same-server SSO connections.

  Note the Nucleus-specific caveat: because the stable identity hashes
  the whole config map *and* `display_name`, any change to either
  moves this connection to a fresh secret-store entry and orphans the old
  one — renaming a connection, adding `persistence_id` to an existing
  connection, or setting `persistence_id = ""` on a connection whose
  config omitted the key all cost one interactive sign-in. (The
  `omniverse-storage-service` and `broker` plugins key only on the
  endpoint, OIDC client, and `persistence_id`, so a rename is free
  there.) Choose these values when the connection is created.
- **Credential methods.** Nucleus's auth shape predates the unified
  OAuth model used by the Omniverse Storage Service and the
  cloud backends; the descriptor exposes three user-selectable
  credential methods (see `nucleus_credential_methods()` and
  `nucleus_credential_schema()` in `src/config.rs`):
  - **`sso`** — Single sign-on (browser). Recommended. Binds no
    credential fields; the user authenticates by opening a URL in
    their browser and nothing secret is stored in connection
    config. See the Discovery and auth section below for the
    nonce-subscription mechanics.
  - **`userpass`** — Username and password. Binds the `username`
    and `password` credential fields; drives the omni1
    `Credentials::auth` flow. For service accounts and headless
    deployments.
  - **`api_token`** — API token. Binds a single `api_token`
    credential field; drives `Tokens::auth_with_api_token`. Takes
    precedence over `username` / `password` and is the recommended
    automation path. The `Auth` envelope's `username` field is
    recorded as the authenticated principal.

  Successful authentication via `sso` yields a refresh token the
  plugin offers to the host's `secret_put` callback. Whether it is
  stored at all turns on the session having an identifiable account
  and on no sibling connection sharing this connection's derived
  key; whether a later connect finds it turns additionally on that
  derived key being unchanged (see the caveat above), on what the
  host backs the callback with, and on how long that store keeps an
  entry.

  SSO (`SSO::*`) and DeviceFlow (`DeviceFlow::*`) are declared as
  target / deferred flows in the experiment surface; they are not
  wired today.

## Discovery and auth

Connection setup is two-stage. The plugin first opens a short-lived
SOWS transport against the configured `server` (or the `endpoint`
override) and queries Nucleus's discovery surface
(`DiscoverySearch::find`) for the three interfaces it speaks: the
auth-side `Credentials` and `Tokens`, plus the storage-side
`Connection` interface that hosts the path / asset / object /
versioning / mount methods (the `omni1.idl.ts` shape). Each query
returns a transport descriptor; the plugin opens one transport
connection per interface. `Profiles`, `SSO`, `DeviceFlow`, and
`ServerFeatures` are not queried today — those flows are not wired.

The auth handshake (`handshake::{establish_api_token,
establish_username_password, establish_interactive_auth}`) returns
an `Auth` envelope
`{ status, access_token, refresh_token, username, profile, nonce }`.
The plugin then opens the long-lived storage `Connection` socket
over ConnLib framing and calls
`Connection::authorize_token(token, version, client_capabilities)`.
The response (`Auth`) carries a `connection_id` (echoed on every
LFT request as `X-OV-Connection-ID`), an optional
`connection_id_signature` (sent as `Connection-Token` /
`Connection-Signature`), a ConnLib session token (sent as
`Authorization-Token` on LFT), `lft_address`, `lft_threshold`,
`multipart_chunk_size`, `max_chunk_size`, `max_in_flight_requests`,
and `super_user`. The plugin captures these for the connection's
lifetime.

Cold-start interactive auth (`establish_interactive_auth`, used by
the `sso` credential method) registers a one-shot login intent via
`Tokens::subscribe`, receives a server-generated `nonce`, and
surfaces `AuthEvent::OpenBrowser` with the Nucleus login URL
annotated `?nonce=<nonce>` so the host UI can open it. The second
response on the same subscription carries the authentication
result. `Progress`, `Succeeded`, `Failed`, and `Cancelled` ride the
same `AuthEvent` stream the host already consumes. The plugin
never touches raw passwords or 2FA challenges on this path.
At connection registration, `ConnectionSet` loads an identity-scoped
`refresh_token` from the secret store together with the record of the
principal it was issued for. Warm continuation adopts it only after the
handshake it drives comes back as that same principal; a handshake that
authenticates as somebody else is refused and the connection prompts for
an interactive sign-in. Warm continuation rediscovers
`tokens_url` from scratch and defers to `refresh_session` for the
refresh-token grant. The set serializes load, one-time-token rotation,
and successor persistence under the stable identity's cross-process
lock; the per-shared token-generation epoch additionally collapses
concurrent in-process recovery calls.

## URL handling

Nucleus URLs follow `omniverse://<server>[:<port>]/<path>`. The
configured `server` is authoritative; the connection-registration
path rejects a route whose URL authority contradicts it. Literal
`..`, `.` and doubled slashes never reach the server: canonicalization
resolves them before the plugin is called, so such a path names the
node it resolves to rather than reaching the server to be judged
there. A path whose
bytes are not valid UTF-8 has no omni1 wire spelling and is rejected
with `InvalidArgument`.

An address written with a fragment names the node without it. The
plugin does not reject one: canonicalization strips the fragment
before the plugin is called, so any such check could not fire.

Checkpoint pins use Nucleus's native query form
`?<branch>&<checkpoint>`. Branch support never shipped in practice,
so the common spelling is an empty branch plus checkpoint — for
example `foo.usd?&3` parses into
`PathAtVersion { path: "foo.usd", branch: None, checkpoint: Some(3) }`.
The pin is preserved byte-for-byte through route translation,
whether the caller typed it or got it back from `list_versions`.

Mutating ops — `write`, `write_stream`, `write_redirect`, `delete`,
`copy(destination)`, `rename(both endpoints)`, `update_metadata`,
`create_directory`, and `delete_directory` — refuse any URL that
pins a checkpoint with `InvalidArgument` rather than silently
dropping the pin and writing to head. Read-side ops (`stat`, `read`,
`list_versions`) honour the checkpoint pin on the wire.

## Precondition shape

The only mutating omni1 method that carries a per-path conditional
is `update_asset`, whose conditional field is an **etag** — not a
checkpoint number. The other mutating IDL structs (`delete2`,
`copy2`, `rename2`, `update_metadata`'s wire shape) carry no
per-path conditional at all.

The plugin maps the Layer precondition fields onto the wire:

- `WriteOptions::if_dest = IfDestExists::MatchEtag(etag)` →
  `update_asset`'s etag conditional. The etag value is opaque to
  the Layer — Nucleus uses its own ETag string format.
- `WriteOptions::if_dest = IfDestExists::Fail` → create-only
  semantics (`create_asset` rather than `update_asset`).
- `ReadOptions::if_match` (etag) → honored via the read-asset path
  where supported; otherwise host-driven post-read comparison.
- `DeleteOptions::if_match`, `UpdateMetadataOptions::if_match`,
  `CopyOptions::{if_source,if_dest}`,
  `RenameOptions::{if_source,if_dest}` → `Unsupported` (the
  underlying omni1 RPCs carry no conditional fields).

A purged or older checkpoint surfaces as `NotFound`. A stale etag
on `update_asset` returns Nucleus's `InvalidETag`, which the plugin
maps to `PreconditionFailed`; `ObjectModified` remains reserved for
the host-driven etag-comparison post-read fallback. The read-side
checkpoint pin is part of the resolved address, not `if_match` — it
is preserved through the URL.

## Layer-to-omni1 mapping

| Layer method | omni1 RPC |
|---|---|
| `instantiate` | (no remote call; validates the connection config, deferred auth/authorize to first data-path call) |
| `stat` | `Connection::stat2(PathAtVersion)` → `Stat2Result` (`size`, `etag`, `transaction_id`, `hash_*`, `acl`, lock state, checkpoint flag) |
| `read` (asset, inline) | `Connection::read_asset_version(PathAtVersion, etag?)` — inline `content` for sub-threshold payloads |
| `read` (asset, LFT) | `Connection::read_asset_version` returns `uri_redirection` → `ReadResult::Redirect` carrying the LFT URL plus `LftClient::auth_headers()` |
| `write` / `write_stream` (asset, inline) | `Connection::create_asset` / `update_asset(PathAtBranch, content?, content_id?, ...)` with bytes inline |
| `write_redirect` + `continue_write` | LFT presigned-PUT: `LftClient::generate_upload` mints one `WriteRedirect` per call; `continue_write` finalises via `create_asset` / `update_asset` with `content_id` set |
| `delete` | `Connection::delete2(PathAtVersion[])` — batched on the wire, single-path through the Layer; non-recursive |
| `list` | `Connection::list2(path, branches?, path_types?, show_hidden?)` → `List2Response.entries[]`; one-level only |
| `list_versions` | `Connection::get_checkpoints(PathAtBranch)` → `Checkpoint[]` (`checkpoint_id: uint64`, `message`); newest-first |
| `get_latest_version` | `get_checkpoints` filtered to the requested checkpoint, or the most recent; `Unsupported` when no checkpoints |
| `create_directory` | `Connection::create_directory(PathAtBranch)` (does not synthesise missing parents) |
| `delete_directory` | `Connection::delete2` of an empty directory; non-recursive (recursive returns `Unsupported`; the host walks) |
| `copy` | `Connection::copy2(PathsToCopy[])` — single-pair |
| `rename` | `Connection::rename2(PathsToRename[])` — single-pair, atomic per pair |
| `update_metadata` | `Unsupported` — omni1 has no caller-owned key/value metadata surface |
| `check_access` | `Connection::get_acl_resolved` filtered to the authenticated principal captured from `Connection::authorize_token` |
| `watch_directory` | `Connection::subscribe_list(PathAtBranch)` — one-level; iterator pumped on a dedicated OS thread |
| `address_roots` | static `vec![config.root]` (no `get_mount_info` integration) |

The plugin uses the v2 / asset / object methods exclusively, never
the deprecated single-arg variants. Single-address watches
(`subscribe_read_asset` / `subscribe_read_object`), omni-object
reads/writes (`create_object` / `update_object`), content-addressed
write fast-paths (`*_with_hash`), and `get_mount_info`-driven
dynamic address roots are not wired today.

The directory verbs — `create_directory`, `delete_directory`, `list`
and `watch_directory` — append a trailing `/` to the resolved path
before it goes on the wire, because `x` and `x/` name one node to the
Layer but not to omni1. Without it,
`delete_directory("omniverse://srv/docs")` would target the **file**
`/docs` rather than the folder `/docs/`, and a slashless `list` could
return a sibling named `docsx` among its entries.

## Streaming guarantees

`write_redirect` emits one `WriteRedirect` per LFT part, all of them
against the single upload URL minted by `LftClient::generate_upload`.
The part count is `ceil(size / part_size)`, so a body no larger than
one part collapses to a single redirect and a zero-length body still
emits one. The part size is the server-advertised
`multipart_chunk_size` from the `Auth` envelope (5 MiB when the
server omits it), clamped down to 20 MiB when a deployment advertises
more, since the LFT server's per-PUT cap is 24 MiB. Each part carries
its own `Content-Start`, from which the server derives
`part_number = Content-Start / Multipart-Chunk-Size + 1`.
`continue_write` collects the captured responses and commits via
`create_asset` / `update_asset`.
Above-threshold true streaming via `write_stream` returns
`ErrorCode::Unsupported`, pointing the host at `write_redirect`;
the host materialises the body to memory or local file before
issuing the redirect. The non-LFT path drains the stream into memory,
bounded by
`clamp(the server's LFT threshold or 16 MiB, at most 64 MiB)`; a body
over that bound is refused rather than allocated in full.
True streaming PUTs through the LFT client
require `Body::Stream` propagation through `reqwest::Body`, which is
target work.

Range reads are not wired yet. The omni1 read methods themselves
have no range parameter, and this plugin currently rejects
`ReadOptions::range` with `Unsupported` before issuing the read.
Range-aware LFT downloads are target work once the redirect follower
can reliably carry `Range:` through that path.

LFT URLs and headers are bearer credentials for the redirect's
lifetime. The plugin marks their expiry, redacts URLs and auth
headers in errors / tracing, and never copies them into
`ObjectInfo`, cache metadata, or durable route state.

## Redirect credential scope

Both LFT redirect paths — the `read` that follows `uri_redirection`
and every part of a `write_redirect` batch — declare
`RedirectScope.credential = connection`. That is the honest reading of
what they carry: an LFT redirect is authorized by the connection's own
headers, not by a signature over the object being transferred.
`LftClient::auth_headers` puts on each of them

- `X-OV-Connection-ID` — the Nucleus `connection_id`;
- `Authorization-Token` — the ConnLib session token;
- `Connection-Token` / `Connection-Signature` — when the server issued a
  `connection_id_signature`;
- `Authorization: Bearer <access token>` — the account's Nucleus access
  token;
- `X-OV-Username` — the authenticated principal.

Write parts add `Content-ID`, `Content-Start`, `Multipart-Chunk-Size`
and `X-OV-URI` on top, which describe the transfer rather than
authorizing it.

A party that receives such a redirect therefore holds the connection's
authentication, not a capability over one asset. That credential names
no path, so it is not confined to the object the redirect points at (the
`X-OV-URI` on a write part addresses the transfer, it does not bound
what the headers authorize); it does not expire
with the redirect, whose 5-minute `expires_at` bounds the URL rather
than the credential; and it lasts as long as the session token and the
access token do. The `connection_id` binding is a real constraint — a
token replayed outside its bound connection context is not directly
usable — but it is a constraint on *where* the credential works, not on
*what* it reaches.

So under a host running the default
`redirect_credential_disclosure = "refuse"`, a Nucleus LFT redirect is
never handed to a caller outside the host process, so a caller that
consumes `write_redirect` results directly is refused unless the host
sets the key to `allow`. On the read path the
host follows the redirect itself and returns the bytes as a stream, so
the read still succeeds; on the write path `write_redirect` is refused
and the body goes through the host instead. Setting the key to `allow`
hands the redirect over with those headers on it, which is appropriate
only where every client permitted to write is as trusted as the Nucleus
account itself.

## ACL semantics

The Nucleus ACL is owned by the server. The plugin maps the
caller-effective ACL into the read-only
`ObjectInfo.effective_permissions` field and uses
`get_acl_resolved` to implement `check_access` when the
authenticated principal is known.

`Stat2Result.acl` carries the calling principal's `PathPermission`
set (`read` / `write` / `admin`). The plugin maps these onto
`EffectivePermissions`:

| `PathPermission` | `EffectivePermissions` |
|---|---|
| `read` | `READ` |
| `write` | READ, WRITE, DELETE, UPDATE_METADATA |
| `admin` | `EffectivePermissions::all()` |

Nucleus's `write` ACL bit grants mutate, delete, and metadata-update
on the object — there is no separate ACL split. When the
authenticated principal cannot be determined, `check_access`
denies all requested ops with `reason = "nucleus principal unknown"`
rather than over-granting via union. Group-based ACL entries are
not folded in because local group membership is not tracked;
superuser routing via `service_resolve_acl` is not wired.
`set_acl_v2` is not exposed through `update_metadata`.

## Capability bits

The backend advertises (true): `supports_if_match_write`,
`supports_no_overwrite_write`, `writes_are_atomic`,
`supports_copy`, `supports_rename`, `supports_server_side_copy`,
`supports_server_side_rename`,
`has_real_directories`, `supports_list`, `wants_list_backed_stat`,
`populates_subdirectory_metadata`, `supports_version_listing`
(with `version_list_order = Some(Newest)`),
`populates_effective_permissions_on_stat`, `supports_access_check`,
`supports_watch_directory`. The `watch_directory_kinds` set covers
`created`, `modified`, `deleted`, and `metadata_changed`.

Notably **not** advertised (false): `supports_atomic_rename`
(single-pair copy/rename only, no batch atomicity),
`supports_recursive_list` (omni1 `list2` is one-level only),
`supports_native_metadata_patch` (no caller-owned user-metadata
patch on the wire), `supports_metadata_rewrite_emulation`,
`watch_directory_resumable` (subscribe_list streams reset on
reconnect; `Lapsed` signals the gap).

`redirect_size_threshold` advertises `DEFAULT_LFT_THRESHOLD_BYTES`
(16 MiB), matching the omni1 buffered-PUT upper bound for typical
deployments; the auth flow does not rewire it from the
server-advertised `lft_threshold` today.

## Enforcement

- **Compound `if_match` refused.** `if_match` is `etag`-only on the
  ops where it applies (`write`, `write_stream`, `write_redirect`,
  `update_metadata`, `copy`, `rename`, `delete`). Compound with
  `size` / `mtime` / `version` returns `Unsupported` at the Layer
  boundary via `require_etag_only_if_match`. `delete` / `copy` /
  `rename` only carry the helper because the omni1 IDL structs
  themselves have no per-path conditional — calling them with any
  `if_match` field populated is also `Unsupported`.
- **Range validation.** Inverted byte ranges
  (`start > end_inclusive`) return `InvalidArgument` at the Layer
  boundary before any wire I/O.
- **`write_redirect` requires a size hint.** A `write_redirect`
  call without a known `size_hint` returns `Unsupported`; the host
  falls back to `write_stream` (which itself returns `Unsupported`
  above the LFT threshold, forcing the host to materialise).
- **`list` refuses `recursive = true`.** The capability is
  advertised as false; the Layer entry point refuses the option with
  `Unsupported` rather than performing a host-side walk under the
  plugin.
- **`list` rejects `page_token`.** Nucleus's `list2` has no
  continuation cursor; `ListOptions::page_token` is refused with
  `Unsupported`. `max_results` is honoured by truncation.
- **Read range refused.** `ReadOptions::range` is refused with
  `Unsupported`; range-aware LFT downloads are target work.
- **Copy/rename conditionals refused.** `copy2` and `rename2` have
  no source-side etag slot, so any populated `if_match` is refused
  rather than silently weakened.
- **Token refresh coalesced.** In-process OmniAuth refresh
  coalescing rides on the per-shared
  `refresh_lock: tokio::sync::Mutex<()>` + `cred_epoch: AtomicU64`
  on `NucleusShared`. Concurrent callers observing the same stale
  epoch collapse onto a single `Tokens::refresh` round-trip.
  Background-spawned refresh is **not** used — refresh runs on
  demand under the per-shared mutex when a Layer call returns
  `Expired` / `InvalidToken`.
- **One connection per server, per layer instance.** The published
  root is `omniverse://{server}/` whatever the `prefix`, so a second
  connection naming a server the instance already serves is refused
  with `RouteConflict`, so a config declaring two fails to bring the
  second up.
- **A transport failure during a mutation surfaces as
  `CommitAmbiguous`.** A dropped socket cannot tell the plugin whether
  the server committed, so the mutating verbs report the ambiguity
  instead of an error the caller would read as a clean failure. Callers
  must handle it: re-`stat` the target before deciding to replay.
  Read-side transport failures map to retryable codes.
- **Writes are not auto-retried.** `ConnectionSet::with_recovery`
  drives refresh-and-retry-once for `delete`, `copy`, `rename`,
  `create_directory`, `delete_directory` and the reads, but `write` and
  `write_stream` bypass it: a write consumes its body, so there is
  nothing to replay. An expired credential under a write therefore
  surfaces at the caller rather than being refreshed transparently.

## Threat model

The plugin holds the Nucleus `access_token` in process memory for
the lifetime of the connection. The `refresh_token` lives in the
secret store, keyed by `(backend_kind = "nucleus", connection_id =
<stable-request-identity>, field = "refresh_token")`. The stable
identity is a SHA-256 hash of a length-prefixed encoding of backend kind,
sorted non-secret config, and `display_name`; it is not the host-minted
`ConnectionId` (which is process-local). `ConnectionSet` alone calls the driver's
persist/load/delete hooks, so a rotating grant publishes its successor
under the same cross-process lock that serialized consumption.

The plugin deliberately does not fall back to an entry keyed by server
hostname alone: once two identities have collided on such an entry, no
safe rule can assign its final token. The first identity-scoped persist
or purge best-effort deletes an orphaned hostname-keyed entry, after
which identities remain isolated.

Alongside the token, the entry carries an identity record naming the
server and the principal the credential was issued for. A stored
credential without that record cannot be attributed to an account and
is not adopted: the affected connection prompts for one interactive
sign-in, after which the entry is rebound in place and warm
continuation resumes. The secret is left where it is rather than
deleted, so no credential that cannot be re-minted is lost. A record
naming no principal at all is refused the same way, and never written.

Where two connections without distinct `persistence_id` values are live
**in one process**, neither can claim the shared entry: both sign in
interactively, neither writes it — including the write an interactive
sign-in itself performs — and a warning names the key. A connection that
has shared its key stays in that state for as long as it is live, even
after the sibling goes away — including a connection created onto a key
another one already holds, which removing the older connection does not
promote. Give the connections distinct `persistence_id` values and
reconnect to clear it. That
detection is process-local — two applications running as one OS user
each believe they are the sole claimant, and the stored lineage's own
principal cannot separate them either, since the second process
warm-continues on that lineage and so authenticates as its owner. Set
`persistence_id` whenever one server serves more than one account; it is
the only discriminator that holds across processes.

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


LFT side-channel HTTP traffic carries the ConnLib session token
bound to the Nucleus `connection_id` via the
`X-OV-Connection-ID` / `Connection-Token` / `Connection-Signature`
headers, so a leaked token outside its bound `connection_id`
context is not directly usable. The plugin marks LFT redirect
expiry, redacts URLs and auth headers in errors and tracing, and
never copies them into `ObjectInfo`, cache metadata, or durable
route state.

In Brokered mode the broker holds the credentials, but an LFT redirect
is not a narrower thing than they are: its headers are the connection's
own authentication, the `Authorization: Bearer <access token>` among
them (see [Redirect credential scope](#redirect-credential-scope)).
`LftClient::auth_headers` emits that header whenever the client holds an
access token, and the plugin's session setup refuses to complete without
one — `complete_session` fails with `AuthRequired` if the Tokens
interface returned no `access_token` — so on every shipped auth path
(`sso`, `userpass`, `api_token`) the bearer is there. What keeps those
bytes inside the broker is the host's
`redirect_credential_disclosure` default of `refuse`, which declines to
delegate a redirect declared `connection`. Nucleus
wire-protocol drift is a known risk; the design target is a
per-interface version-range pin that fails connection
establishment with a clear diagnostic when the server is out of
range, plus a conformance suite pinned against a Nucleus reference
deployment in CI. Neither is wired today.

## TLS stack

Both the WebSocket transport (`tokio-tungstenite`) and the LFT
HTTP side-channel (`reqwest`) are built against `rustls` with the
platform's native root certificate store
(`rustls-tls-native-roots` for tungstenite, `rustls-tls` plus the
process's `webpki-roots` / native roots for reqwest). The plugin
does not link `native-tls` / OpenSSL / Secure Transport / SChannel.
Deployments that rely on a private CA chain must install the CA
into the OS trust store the same way they would for any
`rustls`-backed client; per-process CA injection is not exposed
today.
