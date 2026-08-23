# GCS plugin (`gcs`)

The `gcs` plugin: a first-party `Backend` implementation against
Google Cloud Storage. Lives in
`ovstorage-cloud/ovstorage-plugin-gcs/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
plugin hand-rolls the GCS REST client, V4 RSA signed-URL minting,
ADC discovery, and OAuth2 token exchange against the async
`reqwest::Client` — no `google-cloud-storage` / `google-cloud-auth`
dependency. Mints `ReadResult::Redirect` against V4-signed URLs and
drives `write_redirect` through GCS resumable-upload sessions so
bytes flow directly between GCS and the host. The plugin owns GCS's
vendor response-header vocabulary (`x-goog-generation`,
`x-goog-metageneration`, `x-goog-hash`, `x-goog-storage-class`, ...)
so the host stays generic.

## Public surface

- **Schemes**: `gs://`, plus GCS-region-native HTTPS prefixes
  (`https://storage.googleapis.com/...`) routed at the operator's
  discretion. The core library treats HTTPS prefixes as ordinary
  `https://` addresses until an explicit route selects this plugin.
- **Descriptor**: `kind = "gcs"`,
  `display_name = "Google Cloud Storage"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `bucket` (**required**).
  - `project_id` (optional; surfaced for operator clarity, not used in
    the data path).
  - `service_account` (optional; named in the GCS credential chain).
  - `endpoint` (optional; for GCS-compatible deployments).
  - `pubsub_subscription` (optional;
    `projects/{project}/subscriptions/{subscription}` — enables
    `watch_directory`).
  - `pubsub_pull_max` (optional; default `100`, max Pub/Sub messages
    per pull).
- **Credential keys**: `service_account_key` (the JSON blob shipped by
  Google's IAM console, supplied inline) and `file_path` (path to a
  gcloud ADC JSON file on disk). The `file_path` field's descriptor
  default is the literal string
  `~/.config/gcloud/application_default_credentials.json`, so when no
  inline `service_account_key` is provided the plugin reads ADC from
  that path (after `HOME` / `USERPROFILE` tilde expansion). The plugin
  itself does **not** consult `GOOGLE_APPLICATION_CREDENTIALS` or any
  other environment variable when selecting a credential — if a host's
  bundle-resolution layer wishes to expand env vars into bundle fields
  before passing them to the plugin, that is a separate concern.
  Resolved auth is cached on the backend; OAuth2 bearer tokens refresh
  through an in-process `Mutex` 5 minutes before expiry.

## Auth

Two credential JSON `type` values are accepted: `service_account`
(RSA-key bearing) and `authorized_user` (refresh-token bearing).
GCE/GKE metadata server, workload-identity federation
(`external_account`), and service-account impersonation
(`impersonated_service_account`) flows from `google-cloud-auth`'s
ADC chain are intentionally **not** implemented in-process; an
unsupported `type` surfaces `CredentialUnavailable` with a message
naming the type. Operators that need the unsupported flows materialise
a supported JSON blob into the `SecretBundle` (either inline as
`service_account_key` or on disk and referenced by `file_path`).

Resolution order (inside the plugin):

1. Explicit `service_account_key` from `SecretBundle`
   (`type: service_account`) → JWT bearer-assertion exchange.
2. Explicit `service_account_key` from `SecretBundle`
   (`type: authorized_user`) → OAuth2 refresh-token exchange.
3. ADC file located at the bundle's `file_path` (defaults to
   `~/.config/gcloud/application_default_credentials.json`, with
   `~` expanded against `HOME` on Unix and
   `USERPROFILE` / `HOMEDRIVE` + `HOMEPATH` on Windows).

The plugin does not read `GOOGLE_APPLICATION_CREDENTIALS` or any
other environment variable when selecting a credential. A host's
bundle-resolution layer is free to expand env vars into `file_path`
or `service_account_key` before handing the bundle to the plugin;
that resolution happens above the plugin boundary.

The cross-plugin
[credential-provider matrix](credential-providers.md)
includes the supported file-path bridge and identifies metadata,
workload-identity, and impersonation credentials that have no
representable bundle shape.

For service-account credentials the plugin builds a self-issued JWT
(`alg = RS256`, `iss = client_email`, `aud = token_uri`,
`scope = devstorage.full_control pubsub`, lifetime 3600 s), signs it
with the service account's RSA private key
(`jsonwebtoken::EncodingKey::from_rsa_pem`), and POSTs it to
`token_uri` as the documented `urn:ietf:params:oauth:grant-type:jwt-bearer`
assertion. Authorized-user credentials POST a `refresh_token` grant
against `https://oauth2.googleapis.com/token`; those credentials must
already have been issued with `pubsub` or `cloud-platform` scope to
use watches.

Resolution failures surface as `ErrorCode::CredentialUnavailable`.
Token-exchange failures surface as `ErrorCode::AuthRequired`.

Cross-process token-refresh coalescing through a shared `auth.sqlite`
substrate is not wired in here; the in-process `Mutex` keeps two
callers in the same process from racing, but two processes targeting
the same connection can each mint a fresh bearer.

## URL handling and version-pinned addresses

Native addresses use `gs://<bucket>/<object>`. The configured `bucket`
is authoritative; per-call address parsing rejects a target whose URL
bucket disagrees with `ErrorCode::NoRoute`. `stat` against an empty
object name (`gs://bucket/`) returns `InvalidArgument`; bucket-root
metadata is not exposed.

**The object name is the decoded path.** `gs://bucket/pub%20x` names
the object `pub x`, and a name containing a literal `%` is spelled
`%25`. Trailing dots and other escaped bytes round-trip. A name
containing a dot segment or a doubled separator cannot be named by an
address: it is omitted from listings with a `warn!` rather than handed
out as an address that resolves to a different object. A name whose
bytes are not valid UTF-8 has no GCS wire spelling and is rejected with
`InvalidArgument`, as is an address carrying a port.

Versioned URLs use `?generation=<N>`. `list_versions` returns
`ObjectInfo` values whose addresses carry the corresponding
generation pin.
Mutating ops whose wire format cannot carry a generation pin —
`write`, `write_stream`, `write_redirect`, `copy(destination)`,
`rename(both endpoints)`, `update_metadata` — reject any pinned
`?generation=` with `InvalidArgument`. `delete` honours a pinned
`?generation=` on the wire so the deletion targets that specific
historical version.

## V4 signing and presigned reads

The V4 signer implements the GCS variant of AWS-style V4: algorithm
`GOOG4-RSA-SHA256`, credential service component `storage`,
request-type token `goog4_request`, host pinned to
`storage.googleapis.com`, signed headers fixed to `host`. Canonical
URI percent-encoding uses uppercase hex digits. Default expiry is
5 minutes. Signatures are produced by `RSA-SHA256` over the V4
string-to-sign using the service account's RSA private key, so
authorized-user ADC credentials **cannot** mint signed URLs.

Reads with a service-account credential return `ReadResult::Redirect`
carrying the V4-signed GET URL plus `ResponseParsing` pinning `etag`,
`x-goog-generation`, `content-length`, `last-modified`, and the GCS
vendor `system_metadata_headers` set (`x-goog-metageneration`,
`x-goog-storage-class`, `x-goog-stored-content-encoding`,
`x-goog-hash`). Reads with an authorized-user credential cannot
V4-sign and instead pull bytes through the JSON download endpoint
(`alt=media`) under the cached bearer token: whole-object reads
return `ReadResult::Stream` (chunk-by-chunk, no `to_vec()` copy);
ranged reads return `ReadResult::Bytes` because the caller already
requested a bounded slice.

`ReadOptions.range` is wired into a `Range:` request header on the
redirect (GCS V4 signs only `host`; `Range` passes through unsigned)
and onto the `alt=media` GET. `ReadOptions.if_match` is an etag-only
precondition; generation selection belongs in the address as
`?generation=<N>`. When the wire cannot apply the etag directly, the
host compares the returned `ObjectInfo.etag` after the read.

The signed URL respects the connection's `endpoint` override: when
set, both the URL host and the V4 `host:` canonical header resolve to
that endpoint (port preserved). The signing scope
(`storage` / `goog4_request`) stays host-independent.

## Redirect credential scope

Every redirect this plugin mints declares what its credential authorizes,
on `RedirectScope.credential`. A host reads that declaration to decide
whether the redirect may be handed to a caller outside its own process;
inspection cannot answer the question, since a signature over one object
and one over a whole bucket are the same shape on the wire.

| Mode | Declares | What the party executing the redirect holds |
|---|---|---|
| Anonymous read (public bucket) | `none` | The unsigned public download URL, plus the `generation` / `ifGenerationMatch` pins the caller asked for. No credential rides on it. |
| Service-account read | `request` | A `GOOG4-RSA-SHA256` signature over this bucket, this object, `GET` and the pinned query, valid for the 5-minute default expiry. `Range` is supplied by the follower and is not signed (GCS V4 here signs only `host`), so the signature binds the object and the window, not the slice. |
| Authorized-user read | — | Nothing. An authorized-user credential cannot V4-sign, and the plugin does not fall back to a broader credential: it pulls the bytes itself and answers `ReadResult::Stream` (whole object) or `ReadResult::Bytes` (range). |
| `write_redirect` (every credential mode) | `request` | The resumable session URL GCS returned in `Location`. The session names one object and accepts uploads to that session alone; the redirect's own request carries only `content-type`, never the connection's bearer, which is spent on the plugin's `uploadType=resumable` POST and not passed on. The declared expiry on that scope is seven days. |

So nothing this plugin hands out reaches an object the redirect does not
name, and the write session is the longest-lived of them. Under a host
running the default `redirect_credential_disclosure = "refuse"`, every
GCS redirect is delegated on both paths — the credential is never
broader than the redirected request, so the policy has nothing to
withhold. The session URL is a bearer credential for its lifetime all
the same: whoever holds it can upload to that object until the session
is finished or expires.

## Layer-to-API mapping

| Layer method | GCS API |
|---|---|
| `add_connection` | Validates the connection config, builds the `reqwest` client, and constructs the `Authenticator` from the `SecretBundle`. Bearer-token acquisition is deferred to the first data-path call. Capabilities are returned through `RootInfo`. |
| `stat` | `GET /b/{bucket}/o/{name}` (or `?generation=N` for a version-pinned target). Parses `etag`, `generation`, `metageneration`, `size`, `updated`, `crc32c`, `md5Hash`, `storageClass`, `contentType`, `contentEncoding`, `metadata`. |
| `read` | V4-signed presigned GET (service-account creds) or `alt=media` JSON-API streaming GET (authorized-user creds). |
| `write` (Body::Bytes) | Single-shot upload through the JSON API (preconditions inline). |
| `write_redirect` (known size) | Initiates a resumable session (`uploadType=resumable` with `X-Upload-Content-Length`), returns a single `WriteRedirect` (PUT against the session URL with `RedirectBodySource::UserBytes { offset: 0, len }`). |
| `write_redirect` (unknown size) | Returns `Unsupported`; the dispatcher falls through to `write_stream`. |
| `continue_write` | Parses the captured `Object` JSON; rejects 308 Resume Incomplete on the single-PUT path (partial commit must not be reported as success). Compares the session URL and the recorded target address from the continuation blob, and re-checks the committed object's `name` against the target — all three are defence in depth, not the control. A resumable session names the object by itself, so it cannot be re-derived from the request address; on the broker's client-driven route both sides of either continuation comparison come from the same caller, and the `name` re-check reads a response body that caller also supplied. The `name` re-check is in any case detection after the commit rather than prevention. |
| `write_stream` | Initiates a resumable session itself, PUTs exactly-8 MiB chunks (`Content-Range: bytes <s>-<e>/*`, 308 = continue), finalises with `Content-Range: bytes <s>-<e>/<total>`. Memory stays bounded by one ~8 MiB chunk regardless of object size. |
| `delete` | `DELETE /b/{bucket}/o/{name}` with `ifGenerationMatch` parsed from `DeleteOptions.if_match` (etag string; GCS uses the generation number as the etag) or address `?generation`. |
| `list` | `GET /b/{bucket}/o?prefix=&delimiter=&pageToken=&maxResults=`. Real objects return `ObjectInfo` with `ObjectKind::File`; zero-byte marker objects ending in `/` return `ObjectInfo` with `ObjectKind::DirectoryMarker`; common prefixes return `ObjectInfo` with `ObjectKind::DirectoryInferred`. If GCS reports the same address as both a marker object and a prefix, the marker wins and only one item is emitted. |
| `list_versions` | Adds `versions=true` to the same endpoint, filters by exact object name, and returns one `ObjectInfo` per generation with `?generation=…` in the address. Newest-first order. |
| `get_latest_version` | Stat on the pinned generation, or the head's current generation, returning a version-pinned `ObjectInfo.address`. Buckets without versioning return `Unsupported`. |
| `copy` | `POST /b/{src}/o/{src}/rewriteTo/b/{dst}/o/{dst}`, looping on `rewriteToken` until `done = true`. `CopyOptions::if_source` → `ifSourceGenerationMatch`; `CopyOptions::if_dest = IfDestExists::MatchEtag(etag)` → `ifGenerationMatch`; `IfDestExists::Fail` → `ifGenerationMatch=0`. |
| `rename` | Copy-then-delete with best-effort delete-on-failure rollback. |
| `update_metadata` | `PATCH /b/{bucket}/o/{name}` with `metadata` map (set → string values, remove → JSON `null`). `if_match` (etag) → `ifGenerationMatch`. **Native** patch — does not rewrite the object's bytes. |
| `check_access` | `GET /b/{bucket}/iam/testIamPermissions?permissions=…` for the requested ops. |
| `watch_directory` | Pub/Sub `:pull` against `pubsub_subscription`; one coalesced consumer per connection, ack after fan-out. |

## Streaming guarantees

`write` with `Body::Bytes` (zero-byte payloads included) PUTs through
the JSON API in one round-trip, skipping the resumable-session
redirect. Known-size `write_redirect` emits a single resumable-session
redirect the host follower drives end-to-end. Unknown-size writes go
through `write_stream`'s chunk-aligned 8 MiB loop — memory bounded by
one chunk regardless of object size. Range reads buffer only the
requested byte slice.

## Capability bits

The plugin advertises (true):
`writes_are_atomic`, `supports_no_overwrite_write` (via
`ifGenerationMatch=0`), `supports_if_match_write` (via
`ifGenerationMatch=<N>`), `supports_server_side_copy`, `supports_copy`,
`supports_rename` (availability: `rename` is offered, implemented as
copy-plus-delete with rollback, so `supports_server_side_rename` and
`supports_atomic_rename` are both false), `supports_recursive_list`,
`supports_list`, `wants_list_backed_stat`, `supports_version_listing`
(with `version_list_order = Some(Newest)`),
`supports_native_metadata_patch`, `supports_access_check`,
`supports_watch_directory` (only when `pubsub_subscription` is
configured; `watch_directory_resumable = false`, advertised kinds:
created / deleted / metadata-changed,
`watch_directory_max_lag = 30s`).

Not advertised (false):
`supports_atomic_rename`, `has_real_directories`,
`populates_subdirectory_metadata`,
`supports_metadata_rewrite_emulation` (GCS has native patch — no
emulation needed). `effective_permissions` is left `None`; answering
would require an extra IAM `testIamPermissions` call beyond
`check_access`.

**Enforcement**

- `if_match` (read / delete / update_metadata), `if_source` (copy /
  rename), and `IfDestExists::MatchEtag` (write / copy / rename)
  accept an opaque etag string. GCS uses the object generation
  number as the etag, mapped onto `ifGenerationMatch` /
  `ifSourceGenerationMatch` on the wire. `IfDestExists::Fail` maps
  to `ifGenerationMatch=0`.
- Background OAuth refresh runs at ~90% of the access token's TTL with a
  30s retry floor on failure. The refresh task holds a weak reference to
  the auth state, so it stops naturally when the connection is dropped.
- Inverted byte ranges return `InvalidArgument` at the Layer boundary.

## Subscriptions and watch

`watch_directory` uses a configured Cloud Pub/Sub pull subscription
that receives Cloud Storage object-change notifications for the
bucket. The plugin does not create subscriptions or notification
configurations; configure those out-of-band and set
`pubsub_subscription` on the connection.

When the shared consumer opens it reads the subscription resource once
and caches `ackDeadlineSeconds` (`0` normalised to Pub/Sub's 10 second
default) and `enableExactlyOnceDelivery`. Pull uses
`POST /v1/{subscription}:pull`; acknowledgements use
`POST /v1/{subscription}:acknowledge` through the same
bearer-authenticated `reqwest` client.

Acknowledgement is at-least-once and happens **after fan-out**: once a
derived ovstorage event has been dispatched to every matching watcher,
its ack is queued to the Pub/Sub ack pump (off the fan-out path, so a
slow network ack never stalls delivery). Each Pub/Sub message carries
one refcount and is acked **exactly once**, after every one of its
events has been dispatched and acked. Malformed notification bodies
yield `Lapsed` and are acked the same way; a notification outside the
watched prefix or bucket carries no event for that watcher but is still
acked. A synchronous ack-dispatch failure (the bounded pump is full or
closed) and a fatal asynchronous provider failure (a Pub/Sub
`:acknowledge` error the pump classifies as fatal) each surface as a
terminal error on the watch stream — never a silently dropped ack —
tearing the shared consumer down so the next watch reopens it. A
transient `:acknowledge` failure is logged and retried on redelivery,
not terminal.

### One consumer per connection

Concurrent `watch_directory` calls on a single connection — any prefix,
any principal — **self-coalesce onto one physical Pub/Sub pull
consumer** per connection. Events are fanned out in-process,
prefix-filtered per watcher, so watches on different prefixes never
cannibalize each other's notifications (Pub/Sub pull is a
competing-consumer transport: each message is delivered to one puller).
The coalescer is principal-blind: it keys solely on the Pub/Sub
subscription resource, never on the caller.

A `since` request coalesces like any other watch: the stream is prefixed
with one `Lapsed` (GCS keeps no resume history) and then delivers live
events off the shared consumer — no dedicated puller.

**Operational rule — one notification resource per consumer.**
Coalescing is in-process, per connection: each `GcsBackend` owns its own
coalescer. It cannot stop two backend connections, two broker replicas,
or two application processes from each attaching an independent puller to
the **same** Pub/Sub subscription and splitting its notifications. So
each live connection that consumes a subscription must have **its own**
subscription (or use a fan-out delivery model), or the pullers
cannibalize each other.

Event mapping:
`OBJECT_FINALIZE` → `Created`;
`OBJECT_METADATA_UPDATE` → `MetadataChanged`;
`OBJECT_DELETE` / `OBJECT_ARCHIVE` → `Deleted` unless
`overwrittenByGeneration` is present (in which case the old-generation
removal is suppressed because the paired finalize event represents
the logical object change). Cloud Storage notification attributes are
the primary source for bucket, object, generation, event type, and
event time; if the optional `JSON_API_V1` payload is present the
plugin enriches the event with `etag`, `size`, and `updated`.

Pub/Sub error mapping: 401 → `AuthRequired`; 403 with Google error
reason `ACCESS_TOKEN_SCOPE_INSUFFICIENT` → `AuthRequired` with a
scope hint; other 403s → `PermissionDenied`. For exactly-once
subscriptions, a 400 `INVALID_ARGUMENT` ack response after the ack
deadline plus skew is treated as expected stale ack ID; before that
deadline, or on non-exactly-once subscriptions, it is fatal.

## Threat model

The plugin holds the resolved GCS service-account JSON (or refresh
token) in process memory for the lifetime of the connection. In
Brokered mode the broker holds the credentials; the library sees only
short-lived signed redirects. Bearer tokens are cached on the backend
instance behind a `Mutex` and rotated 5 minutes before expiry. Signed
URLs and resumable session URLs are bearer credentials until expiry
and are redacted everywhere the core redacts presigned redirects.

Storage and Pub/Sub error response bodies are never interpolated into
error text. Only an allowlisted error-code token survives into
`error.message` — JSON `error.status`, else the first
`errors[].reason`, else the first `<Code>` element that is a direct
child of the root `<Error>` element of the XML-API error shape, within
the first 8 KiB of the body — and the rest of the body is discarded. A body from
which no code can be recovered is reported by its length alone and
nothing else. So a failed request cannot disclose its response text
through a logged exception.

The same holds when a *successful* response fails to deserialize —
a resumable-write object, a Pub/Sub subscription lookup, a pull
response. A serde type error renders the offending value, so every
one of those paths reports the decode failure by classification,
position and body length instead of by its `Display`. The pull
response matters most of the three: it is the one carrying
notification payloads and attributes.

The OAuth token endpoint is not covered by that guarantee: a failed
token exchange reports the response text, which carries an
OAuth error code and description rather than the service-account
private key.

## Deferred capabilities

- GCE / GKE metadata server as an ADC source.
- Workload identity federation (`external_account` JSON) and
  service-account impersonation.
- Cross-process bearer-token coalescing — the in-process `Mutex` only
  coalesces refreshes within a single process.
- HMAC-key-signed URL flow (the XML-API HMAC signing path); this
  plugin signs with the service account's RSA key.
- gRPC-only fields exposed by the Cloud Storage gRPC API; this plugin
  uses JSON over HTTP exclusively.
