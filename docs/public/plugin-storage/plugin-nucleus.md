# Nucleus plugin (`nucleus`)

The `nucleus` plugin: a first-party `Backend` implementation against
NVIDIA Omniverse Nucleus, the content-collaboration server for the
Omniverse platform. Lives in
`ovstorage-nucleus/crates/ovstorage-plugin-nucleus/` and compiles as
a cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
plugin speaks Nucleus's native `omni1` protocol directly — there is
no third-party Nucleus SDK in the stack. Discovery and auth flow
over Nucleus's short-lived **SOWS** WebSocket transport; the
long-lived storage `Connection` socket uses **ConnLib** framing.
Bulk-bytes payloads ride a separate **LFT** (Large File Transfer)
HTTP side-channel rather than the WebSocket control channel. The
`omni1` IDL at `ovstorage-nucleus/crates/nucleus-client/omni1.idl.ts`
is the source of truth for wire shapes; the
`nucleus-{auth,client,codegen,discovery,transport}` support crates
compile the IDL into typed Rust clients.

## Public surface

- **Schemes**: `omniverse://server[:port]/path`. URL canonicalization
  is host-and-scheme only — the Nucleus path segment is provider-owned
  and is not normalised by ovstorage.
- **Descriptor**: `kind = "nucleus"`,
  `display_name = "Omniverse Nucleus"`,
  `supports_runtime_add = true`.
- **Config keys** (see `nucleus_config_schema()` in `src/config.rs`):
  - `server` (**required**, `Text`, `host[:port]`): the Nucleus
    server. Validated by the plugin and lowercased into the
    canonical root.
  - `endpoint` (optional, `Url`): SOWS discovery override for
    production session establishment.
  - `prefix` (optional, `Text`, default `/`): Nucleus path prefix
    scoping which paths this backend instance serves.
  - `use_lft` (optional, `Bool`, default `true`): gates the LFT
    redirect path and the `LftClient`-backed bulk-bytes branches.
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

  Successful authentication via `sso` produces a refresh token
  that is stored in the OS keyring and reused on subsequent
  connects without re-prompting.

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
Warm-continuation reads `refresh_token` from the OS keyring,
rediscovers `tokens_url` from scratch, and defers to
`refresh_session` for the refresh-token grant; concurrent callers
share a single `Tokens::refresh` round-trip under a per-shared
mutex keyed by token-generation epoch. `AuthRequired` /
`AuthExpired` / `PermissionDenied` clear the keyring entry;
`Transient` preserves it for retry.

## URL handling

Nucleus URLs follow `omniverse://<server>[:<port>]/<path>`. The
configured `server` is authoritative; the connection-registration
path rejects a route whose URL authority contradicts it. Literal
`..`, `.`, and doubled slashes are handed to Nucleus as written;
the server rejects them with `InvalidPath`, which the plugin maps
to `InvalidArgument`.

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

The plugin maps the SPI precondition fields onto the wire:

- `WriteOptions::if_dest = IfDestExists::MatchEtag(etag)` →
  `update_asset`'s etag conditional. The etag value is opaque to
  the SPI — Nucleus uses its own ETag string format.
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

## SPI-to-omni1 mapping

| SPI method | omni1 RPC |
|---|---|
| `instantiate` | (no remote call; validates the connection config, deferred auth/authorize to first data-path call) |
| `stat` | `Connection::stat2(PathAtVersion)` → `Stat2Result` (`size`, `etag`, `transaction_id`, `hash_*`, `acl`, lock state, checkpoint flag) |
| `read` (asset, inline) | `Connection::read_asset_version(PathAtVersion, etag?)` — inline `content` for sub-threshold payloads |
| `read` (asset, LFT) | `Connection::read_asset_version` returns `uri_redirection` → `ReadResult::Redirect` carrying the LFT URL plus `LftClient::auth_headers()` |
| `write` / `write_stream` (asset, inline) | `Connection::create_asset` / `update_asset(PathAtBranch, content?, content_id?, ...)` with bytes inline |
| `write_redirect` + `continue_write` | LFT presigned-PUT: `LftClient::generate_upload` mints one `WriteRedirect` per call; `continue_write` finalises via `create_asset` / `update_asset` with `content_id` set |
| `delete` | `Connection::delete2(PathAtVersion[])` — batched on the wire, single-path through the SPI; non-recursive |
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

## Streaming guarantees

`write_redirect` emits exactly one `WriteRedirect` per call: a
single LFT presigned-PUT against the URL minted by
`LftClient::generate_upload`. `continue_write` collects the
captured response and commits via `create_asset` / `update_asset`.
Above-threshold true streaming via `write_stream` returns
`ErrorCode::Unsupported`, pointing the host at `write_redirect`;
the host materialises the body to memory or local file before
issuing the redirect. Multi-part LFT batches chunked at
`multipart_chunk_size` are captured from the `Auth` envelope but
not consumed; true streaming PUTs through the LFT client require
`Body::Stream` propagation through `reqwest::Body`, which is
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
`supports_server_side_copy`, `supports_server_side_rename`,
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
  `size` / `mtime` / `version` returns `Unsupported` at the SPI
  boundary via `require_etag_only_if_match`. `delete` / `copy` /
  `rename` only carry the helper because the omni1 IDL structs
  themselves have no per-path conditional — calling them with any
  `if_match` field populated is also `Unsupported`.
- **Range validation.** Inverted byte ranges
  (`start > end_inclusive`) return `InvalidArgument` at the SPI
  boundary before any wire I/O.
- **`write_redirect` requires a size hint.** A `write_redirect`
  call without a known `size_hint` returns `Unsupported`; the host
  falls back to `write_stream` (which itself returns `Unsupported`
  above the LFT threshold, forcing the host to materialise).
- **`list` refuses `recursive = true`.** The capability is
  advertised as false; the SPI entry point refuses the option with
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
  demand under the per-shared mutex when an SPI call returns
  `Expired` / `InvalidToken`.

## Threat model

The plugin holds the Nucleus `access_token` in process memory for
the lifetime of the connection. The `refresh_token` lives in the
OS keyring, keyed by `(backend_kind = "nucleus", connection_id =
<server-hostname>, field = "refresh_token")`. The keyring
`connection_id` is the *server* hostname, not the host-minted
`ConnectionId` (which is `pid + nanos` and unstable across runs).
`install_handshake_output` writes the refresh token after every
successful handshake (initial or refresh-rotation);
`update_credentials` clears the entry because new credentials may
belong to a different identity.

LFT side-channel HTTP traffic carries the ConnLib session token
bound to the Nucleus `connection_id` via the
`X-OV-Connection-ID` / `Connection-Token` / `Connection-Signature`
headers, so a leaked token outside its bound `connection_id`
context is not directly usable. The plugin marks LFT redirect
expiry, redacts URLs and auth headers in errors and tracing, and
never copies them into `ObjectInfo`, cache metadata, or durable
route state.

In Brokered mode the broker holds the credentials; the library
sees only the LFT redirects, never the access-token bytes. Nucleus
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
