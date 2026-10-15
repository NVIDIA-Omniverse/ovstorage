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
- **Anonymous-fallback layer keys** (set on `[ovstorage.layers.<name>]`,
  never on a connection; see [Anonymous fallback](#anonymous-fallback)).
  None of them appears in the kind descriptor's `config_schema`, so
  `ovstorage connect` never prompts for one:
  - `anonymous_fallback` (TOML array of scheme strings; the only scheme
    this kind serves is `"gs"`; absent or `[]` is off, which is the
    default).
  - `anonymous_fallback_endpoint` (optional `http` or `https` URL; the
    JSON API endpoint every fallback bucket talks to; default
    `https://storage.googleapis.com`. An emulator or a loopback fixture
    is what it exists for. It is kept as scheme, host, port and path
    only: one that embeds credentials, carries a query or a fragment,
    uses another scheme, or names no host is refused at layer build.)
  - `anonymous_fallback_max_backends` (optional int, default `64`,
    between 1 and 1000000; how many per-bucket anonymous clients stay
    resident).
  - `anonymous_fallback_mints_per_minute` (optional int, default `120`,
    between 1 and 1000000; how many clients may be built per sliding
    minute).

### Anonymous fallback

A `gs://<bucket>/<object>` address that no connection serves has
nowhere to go: the route scan misses and the caller sees `NoRoute`. The
`anonymous_fallback` layer key is the opt-in answer, off by default:

```toml
[ovstorage.layers.gcs]
anonymous_fallback = ["gs"]
```

A granted layer publishes one extra address root beside its connection
roots: the bare scheme `gs:///`, `Hidden`, with no connection id,
read-only capabilities, the `Native` ranged-read strategy its connection
roots advertise, and the marker
`org.omniverse.ovstorage/scheme-fallback = "anonymous"` in its
`user_metadata`. The shared route table consults that root only after
every prefix has missed, so a configured bucket always outranks it for
its own authority, and only for an address whose query carries no
credential. On a hit the layer reads the bucket from the address,
synthesizes the same per-bucket config a connection would carry, and
builds a `GcsBackend` from a literal empty `SecretBundle` — see
[Auth](#auth). GCS is the simplest of the cloud tiers: one fixed public
endpoint, no region to learn, no project to name, so building a
bucket's client costs no request at all. Nothing is registered as a
`Connection`: `list_connections` never lists the fallback, `ovstorage
connect gs://public-bucket/` sees no incumbent, and adding a connection
for a bucket the fallback has been serving is not a `RouteConflict`.
The connection outranks the fallback the moment it installs, the cached
anonymous client for that bucket is dropped, and removing the
connection hands the bucket back to the fallback. `root_info_for` on a
fallback-served address returns the `gs:///` root verbatim; `ovstorage
list-routes` omits hidden roots, so the grant is visible through
`ovstorage doctor`, which lists the root with its marker, and through
the one `INFO` line the first build for a bucket logs at target
`ovstorage.fallback`, naming the bucket origin and never an object.

The grant is layer configuration. A library, CLI or MCP host sets the
key directly; the broker and the REST gateway set it from their
top-level `anonymous_fallback_schemes` and refuse a hand-set layer key,
so the deployment-wide policy has one spelling — see the
`anonymous_fallback` section of
[`../configuration.md`](../configuration.md) and the
[broker operator guide](../broker-operator/README.md). Every
`anonymous_fallback*` key is validated at `create_backend` whether or
not the grant is on, so a mistake is refused where the operator wrote
it rather than on the day the grant is added: an unknown key answers
`InvalidArgument` (`` `anonymous_fallback_region` on layer `gcs` is not
an anonymous fallback key; the accepted keys are anonymous_fallback,
anonymous_fallback_endpoint, anonymous_fallback_max_backends,
anonymous_fallback_mints_per_minute ``), a grant naming a scheme this
kind does not serve answers `InvalidArgument` (`` `anonymous_fallback`
on layer `gcs` (kind gcs) names scheme `s3`, which this kind does not
serve; it serves gs ``), a fallback endpoint that is not a bare
addressable origin answers `InvalidArgument` naming the key and the
layer and never the value — `` `anonymous_fallback_endpoint` on layer
`gcs` must not embed credentials in the URL ``, `... must not carry a
query`, `... must not carry a fragment`, `... must use http or https`,
`... must name a host`, `... must be an absolute URL: <parse error>` —
because reqwest turns URL userinfo into an `Authorization` header on
every request and a `read` redirect would hand it to the caller, while a
stray `?` or `#` would push the appended API path into the query, and a
fallback endpoint on a cloud instance-metadata host answers
`PermissionDenied`. A connection request
— `ovstorage connect`, an `[[ovstorage.connections]]` entry, or a probe
— carrying any of these keys is refused with
`` `anonymous_fallback_endpoint` is a layer key, not connection config;
set it on [ovstorage.layers.gcs] ``, because a fallback key on a
connection would otherwise be ignored silently while the operator
believed it took effect.

**A fallback grants routability, never authority.** Policy sees the
caller's address, before routing and before alias resolution, so a
caller the [authorization policy](../authz-policy/README.md) does not
cover is denied before the fallback is consulted and no request leaves
the process on their behalf. No grant is ever generated for the
fallback — that would be automatic widening of a deny-by-default policy
— and a bucket-scoped rule does not cover `gs:///`: a rule on the bare
scheme (`prefix = "gs://"`) lists the hidden root and grants nothing on
any bucket.

## Auth

Four credential JSON `type` values are accepted: `service_account`
(RSA-key bearing), `authorized_user` (refresh-token bearing),
`external_account` (workload identity federation), and
`impersonated_service_account` (a source credential spent on an
`iamcredentials.googleapis.com` … `:generateAccessToken` hop). The
GCE/GKE metadata server as an ADC source is intentionally **not**
implemented in-process; an unsupported `type` surfaces
`InvalidArgument` with a message naming the type. All four accepted
shapes arrive the same two ways: inline as `service_account_key` or
on disk and referenced by `file_path`.

`external_account` specifics: the subject token comes from a
`credential_source` naming a `file` or a `url` (with optional
`headers` and a `text` / `json` `format`); the AWS and `executable`
source flavors are rejected at parse time, as are workforce
(user-identity) federation configs — a `/workforcePools/` audience or
a `workforce_pool_user_project` field — whose STS exchange needs an
`options` parameter this client does not send. The endpoints the JSON
names are validated at parse time: `token_url` and
`service_account_impersonation_url` must be https
`*.googleapis.com` (or loopback, for tests and emulators), because an
`external_account` file is treated as shareable configuration in the
wider Google ecosystem and `token_url` is where the locally-read
subject token gets POSTed; `credential_source.url` must be https or
loopback, which keeps the plain-http link-local GCE metadata server
unreachable through a credential file. A present-but-malformed
optional field (a null or non-string `service_account_impersonation_url`,
say) is `InvalidArgument`, never silently treated as absent. The
subject token is re-fetched on **every** exchange — federation
platforms rotate it out from under a running process (a projected
volume on GKE, a per-request endpoint on GitHub Actions), and keeping
it fresh is the host platform's responsibility. The STS exchange
posts to `token_url` (defaulting to
`https://sts.googleapis.com/v1/token`); with a
`service_account_impersonation_url` present the federated token is
requested with `cloud-platform` scope and spent on the impersonation
hop, whose token carries the storage scopes; without one the
federated token itself is the bearer and is requested with the
storage scopes directly.

Impersonation-hop failures carry their own reason tags
(`impersonation_http_{status}` / `impersonation_empty`): 400, 401,
and an empty grant are definitive refusals (they latch and park),
while the `iamcredentials` 403 — a missing principal-to-service-account
binding, or IAM propagation lag — parks connection verification
without latching a promotion veto. A subject-token source the
platform fails to serve (`CredentialUnavailable`) also parks at
verify time: it is the same deterministic local misconfiguration an
unreadable ADC `file_path` parks at resolution time, discovered at
token time because external-account sources are read per exchange.

`impersonated_service_account` specifics: `source_credentials` is
parsed recursively (any accepted type except another impersonation),
its bearer is minted first, and `delegates` ride along on the
`generateAccessToken` call.

Resolution order (inside the plugin):

1. Explicit `service_account_key` from `SecretBundle`
   (`type: service_account`) → JWT bearer-assertion exchange.
2. Explicit `service_account_key` from `SecretBundle`
   (`type: authorized_user`) → OAuth2 refresh-token exchange.
3. Explicit `service_account_key` from `SecretBundle`
   (`type: external_account` / `impersonated_service_account`) →
   the exchanges above.
4. ADC file located at the bundle's `file_path` (defaults to
   `~/.config/gcloud/application_default_credentials.json`, with
   `~` expanded against `HOME` on Unix and
   `USERPROFILE` / `HOMEDRIVE` + `HOMEPATH` on Windows), any of the
   four types.

The plugin does not read `GOOGLE_APPLICATION_CREDENTIALS` or any
other environment variable when selecting a credential. A host's
bundle-resolution layer is free to expand env vars into `file_path`
or `service_account_key` before handing the bundle to the plugin;
that resolution happens above the plugin boundary.

A bucket reached through the [anonymous fallback](#anonymous-fallback)
is served with the anonymous credential source, and nothing above can
reach it. The resolution order runs on a connection's `SecretBundle`;
the fallback builds its `Authenticator` from a literal empty bundle,
which resolves to the anonymous source and runs no discovery chain — no
ADC file, no `file_path` default, no metadata server — so
`GOOGLE_APPLICATION_CREDENTIALS` cannot reach it even through a host
that expands environment variables into bundle fields, because there is
no bundle to expand into. One anonymous authenticator and one HTTP
client are shared by every bucket the fallback builds. `read` mints the
unsigned public download URL `<endpoint>/<bucket>/<object>` as a
redirect declared `none`; `stat`, `list`, `list_stream`,
`list_versions`, `get_latest_version` and `check_access` run in-process
with no `Authorization` header, and succeed exactly as far as the
bucket's public-access controls allow.

Read-only takes two shapes here, and they differ on purpose. A
configured connection that resolves to anonymous keeps every capability
bit a credentialed one advertises, because `gcs_capabilities` is
auth-agnostic and it is GCS that refuses a write the bucket does not
grant. The fallback's `gs:///` root instead withholds every write,
delete, copy, rename, directory-mutation, metadata-patch and watch bit,
and the layer refuses those slots before any request is built:
`Unsupported`, `this address is reached through the anonymous gs://
fallback, which is read-only`, with a `next_action` naming the bucket
root (`add a connection for gs://public-bucket/ with credentials to
modify it`) and never the object. `copy` and `rename` check both ends
and refuse when either is fallback-served, naming that end. An
anonymous mutation is not something to attempt on an operator's behalf
against a bucket the operator did not configure, whatever the bucket
would accept.

The cross-plugin
[credential-provider matrix](credential-providers.md)
includes the supported file-path bridge and identifies the metadata
server as the remaining credential source with no representable
bundle shape.

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

Resolution failures name their cause: malformed or unsupported
credentials JSON surfaces `ErrorCode::InvalidArgument`, an unreadable
`file_path` ADC file surfaces `ErrorCode::NotConfigured`, a non-empty
bundle carrying neither field surfaces `ErrorCode::AuthRequired`, and
a subject-token source the platform fails to serve surfaces
`ErrorCode::CredentialUnavailable`. Token-exchange failures surface
as `ErrorCode::AuthRequired`.

Cross-process token-refresh coalescing through a shared `auth.sqlite`
substrate is not wired in here; the in-process `Mutex` keeps two
callers in the same process from racing, but two processes targeting
the same connection can each mint a fresh bearer.

## URL handling and version-pinned addresses

Native addresses use `gs://<bucket>/<object>`. The configured `bucket`
is authoritative: a connection serves only the bucket it pins, and an
address naming any other bucket misses the layer's route table and
answers `ErrorCode::NoRoute` — unless the layer grants the
[anonymous fallback](#anonymous-fallback), in which case the address
routes to the fallback, which reads the bucket from the address and
applies every rule below unchanged. `stat` against an empty object name
(`gs://bucket/`) returns `InvalidArgument`; bucket-root metadata is not
exposed.

**The object name is the decoded path.** `gs://bucket/pub%20x` names
the object `pub x`, and a name containing a literal `%` is spelled
`%25`. Trailing dots and other escaped bytes round-trip. A name
containing a dot segment or a doubled separator cannot be named by an
address: it is omitted from listings with a `warn!` rather than handed
out as an address that resolves to a different object. A name whose
bytes are not valid UTF-8 has no GCS wire spelling and is rejected with
`InvalidArgument`, as is an address carrying a port.

What the fallback does not extend to is deliberate. The scheme root and
any hostless address — `gs:///`, `gs:///key` — name no bucket and
answer `InvalidArgument` (`a gs:// address names no bucket`). An
address whose query carries anything outside the shared carried-query
allowlist — the version selectors `versionId`, `versionid`,
`generation` and `revision` — never reaches the fallback and answers the
byte-identical `NoRoute` an ungranted layer gives: a signed URL such as
`gs://public-bucket/key?X-Goog-Signature=abc` authenticates itself, and
re-serving it anonymously would silently discard the authority the
caller presented. A generation pin is a version selector, so
`gs://public-bucket/key?generation=123` routes through the fallback and
the pin rides the unsigned public download URL. The HTTPS spelling of
the same object, `https://storage.googleapis.com/public-bucket/key`, is
an ordinary HTTPS address to the host and is not routed to this plugin
by the fallback, which serves `gs://` alone.

Versioned URLs use `?generation=<N>`. `list_versions` returns
`ObjectInfo` values whose addresses carry the corresponding
generation pin. Every object `stat` and every `File` list entry also
carries `ObjectInfo.versioned_address =
gs://<bucket>/<object>?generation=<n>`: the generation is on every
object resource, so the pin is populated whether or not
`StatOptions::versioned_address` / `ListOptions::versioned_address` is
set. Directory kinds carry `None`.
Mutating ops whose wire format cannot carry a generation pin —
`write`, `write_stream`, `write_redirect`, `copy(destination)`,
`rename(both endpoints)`, `update_metadata` — reject any pinned
`?generation=` with `InvalidArgument`, and a `versioned_address` this
plugin returns is refused the same way. `delete` honours a pinned
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
authorized-user, external-account, and impersonated credentials
**cannot** mint signed URLs.

Reads with a service-account credential return `ReadResult::Redirect`
carrying the V4-signed GET URL plus `ResponseParsing` selecting
`x-goog-generation` as both etag and version, declaring that generation
`Strong`, and pinning `content-length`, `last-modified`, and the GCS
vendor `system_metadata_headers` set (`x-goog-metageneration`,
`x-goog-storage-class`, `x-goog-stored-content-encoding`,
`x-goog-hash`). Reads with an authorized-user, external-account, or
impersonated credential cannot
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
| Keyless read (authorized-user, external-account, impersonated) | — | Nothing. These credentials hold no RSA key to V4-sign with, and the plugin does not fall back to a broader credential: it pulls the bytes itself and answers `ReadResult::Stream` (whole object) or `ReadResult::Bytes` (range). |
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
| `stat` | `GET /b/{bucket}/o/{name}` (or `?generation=N` for a version-pinned target). Parses `etag`, `generation`, `metageneration`, `size`, `updated`, `crc32c`, `md5Hash`, `storageClass`, `contentType`, `contentEncoding`, `metadata`. Populates `versioned_address` from `generation`, flag or not; directory kinds carry `None`. |
| `read` | V4-signed presigned GET (service-account creds) or `alt=media` JSON-API streaming GET (authorized-user, external-account, and impersonated creds). |
| `write` (Body::Bytes) | Single-shot upload through the JSON API (preconditions inline). |
| `write_redirect` (known size) | Initiates a resumable session (`uploadType=resumable` with `X-Upload-Content-Length`), returns a single `WriteRedirect` (PUT against the session URL with `RedirectBodySource::UserBytes { offset: 0, len }`). |
| `write_redirect` (unknown size) | Returns `Unsupported`; the dispatcher falls through to `write_stream`. |
| `continue_write` | Parses the captured `Object` JSON; rejects 308 Resume Incomplete on the single-PUT path (partial commit must not be reported as success). Compares the session URL and the recorded target address from the continuation blob, and re-checks the committed object's `name` against the target — all three are defence in depth, not the control. A resumable session names the object by itself, so it cannot be re-derived from the request address. A direct SPI caller or an unsealed host supplies both sides of either continuation comparison. The broker's client-driven route instead verifies an address-bound HMAC seal before this plugin runs, so continuation modification is refused there; the `name` re-check still reads a response body the caller supplied. That response check is in any case detection after the commit rather than prevention. |
| `write_stream` | Initiates a resumable session itself, PUTs exactly-8 MiB chunks (`Content-Range: bytes <s>-<e>/*`, 308 = continue), finalises with `Content-Range: bytes <s>-<e>/<total>`. Memory stays bounded by one ~8 MiB chunk regardless of object size. |
| `delete` | `DELETE /b/{bucket}/o/{name}` with `ifGenerationMatch` parsed from `DeleteOptions.if_match` (etag string; GCS uses the generation number as the etag) or address `?generation`. |
| `list` | `GET /b/{bucket}/o?prefix=&delimiter=&pageToken=&maxResults=`. Real objects return `ObjectInfo` with `ObjectKind::File`; zero-byte marker objects ending in `/` return `ObjectInfo` with `ObjectKind::DirectoryMarker`; common prefixes return `ObjectInfo` with `ObjectKind::DirectoryInferred`. If GCS reports the same address as both a marker object and a prefix, the marker wins and only one item is emitted. Each `File` item carries `versioned_address` from the listing's own `generation`, flag or not; markers and prefixes are `None`. |
| `list_versions` | Adds `versions=true` to the same endpoint, filters by exact object name, and returns one `ObjectInfo` per generation with `?generation=…` in the address and `versioned_address` equal to it. Newest-first order. |
| `get_latest_version` | Stat on the pinned generation, or the head's current generation, returning a version-pinned `ObjectInfo.address` and `versioned_address` equal to it. Buckets without versioning return `Unsupported`. |
| `copy` | `POST /b/{src}/o/{src}/rewriteTo/b/{dst}/o/{dst}`, looping on `rewriteToken` until `done = true`. `CopyOptions::if_source` → `ifSourceGenerationMatch`; `CopyOptions::if_dest = IfDestExists::MatchEtag(etag)` → `ifGenerationMatch`; `IfDestExists::Fail` → `ifGenerationMatch=0`. |
| `rename` | Copy-then-delete with best-effort delete-on-failure rollback. |
| `update_metadata` | `PATCH /b/{bucket}/o/{name}` with `metadata` map (set → string values, remove → JSON `null`). `if_match` (etag) → `ifGenerationMatch`. **Native** patch — does not rewrite the object's bytes. |
| `check_access` | `GET /b/{bucket}/iam/testPermissions?permissions=…` for the requested ops (the method is named `testIamPermissions`, but its URL path segment is `iam/testPermissions`). |
| `watch_directory` | Pub/Sub `:pull` against `pubsub_subscription`; one coalesced consumer per connection, ack after fan-out. |

### Metadata keys

The plugin writes `user_metadata` verbatim into the JSON API's
`metadata` map on upload and on `PATCH`, and reads it back from the
same map. GCS preserves key case and stores case variants of one name
— `Author` and `author` — as two distinct keys, so a caller that mixes
spellings gets two entries back rather than one; which characters the
service accepts beyond the portable subset is the service's rule, not
the plugin's. Names inside the portable subset of
[User-metadata keys](CONFORMANCE.md#user-metadata-keys) have one
spelling by construction; the reserved `ovstorage_` names sit inside
it. The per-operation `message` lands in the same map under
`x_ov_message`, beside the caller's keys, on every upload path and on
`PATCH`. On the rewrite behind `copy` and `rename` a non-empty body
replaces the destination's editable metadata wholesale, where an empty
body makes GCS copy the source's, so the plugin reads the source object
first and sends its content type, encoding, language, disposition, cache
control, custom time, storage class and user metadata together with the
annotation, and pins the rewrite to the generation that read returned
unless the caller pinned one, so a source overwritten between the two
calls cannot have its new bytes stamped with the old metadata. ACLs,
holds and retention are outside an empty body's copy and stay out of an
annotated one as well.

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
- A present numeric generation is declared `Strong` in object metadata.
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

The OAuth token endpoints (including STS and the impersonation hop)
follow the same rule: a failed exchange reports only the top-level
provider error code, because the rest of the body
(`error_description`, an IAM `message`) echoes the rejected assertion
or the caller's request. A body with no recoverable code is reported
by byte length alone.

One trust note the credential shapes imply: `external_account` JSON
names the endpoints the plugin will call — `token_url`,
`credential_source.url` (with verbatim headers), and the
impersonation URL. Parse-time validation pins the token and
impersonation endpoints to https `*.googleapis.com` (or loopback) and
the subject-token URL to https-or-loopback, so a hostile config
cannot exfiltrate a locally-read file or reach the metadata server —
but the credentials JSON remains part of the `SecretBundle` trust
boundary all the same: a host must source it from configuration it
trusts, exactly as it must the `service_account` private key.

The [anonymous fallback](#anonymous-fallback) reaches buckets a
**caller** chose, from this process's network position, which is the
shape of a server-side request forgery; what keeps it narrow is that
the host it contacts is not the caller's to choose. Every fallback
bucket talks to one endpoint — `https://storage.googleapis.com`, or
`anonymous_fallback_endpoint` — and that endpoint is judged before any
client is built: a cloud instance-metadata endpoint (`169.254.0.0/16`,
`100.100.100.200`, `168.63.129.16`, `fe80::/10`, `fd00:ec2::254`, an
IPv6 address embedding a refused IPv4 address, or the exact names
`metadata.google.internal`, `metadata.goog` and `metadata`) is refused
with `PermissionDenied` (`refusing to contact <origin>: it is a cloud
instance-metadata endpoint, and ovstorage never fetches from one on a
caller's behalf`) at `create_backend`, granted or not, and again on
each build. A configured connection's `endpoint` is the operator's own
choice carrying the operator's own credential, so it is warned about
(`configured GCS endpoint is a cloud instance-metadata host`) rather
than refused. The predicate judges the host as written: a DNS name that
resolves to a link-local address is not caught.

The fallback's cost is bounded because bucket names are the caller's to
invent: at most `anonymous_fallback_max_backends` clients stay
resident, the least recently used evicted first; at most
`anonymous_fallback_mints_per_minute` may be built per sliding minute,
every attempt charged; and past the budget a cold bucket answers
`ResourceExhausted` (`anonymous fallback mint budget exhausted; retry
later`, retryable) while resident buckets keep answering. A build is
single-flight per bucket. The fallback holds no credential at all — no
service-account JSON, no refresh token, no bearer to cache or rotate —
so its `read` redirects are plain unsigned URLs declared `none`, every
mutation is refused before the wire, and a signed URL for an
unconfigured bucket is never re-served anonymously: it falls through to
`NoRoute` rather than reaching the fallback.

## Deferred capabilities

- GCE / GKE metadata server as an ADC source.
- The AWS and `executable` `credential_source` flavors of
  `external_account` (file- and url-sourced subject tokens are
  supported).
- Workforce (user-identity) federation — `external_account` configs
  with a `/workforcePools/` audience; only workload identity pools
  are supported.
- IAM `signBlob` as a V4 signer for keyless credentials —
  external-account and impersonated reads stay plugin-proxied.
- Cross-process bearer-token coalescing — the in-process `Mutex` only
  coalesces refreshes within a single process.
- HMAC-key-signed URL flow (the XML-API HMAC signing path); this
  plugin signs with the service account's RSA key.
- gRPC-only fields exposed by the Cloud Storage gRPC API; this plugin
  uses JSON over HTTP exclusively.
- The HTTPS spellings of an unconfigured bucket reaching the anonymous
  fallback; the fallback serves `gs://` alone.
- A credentialed fallback tier — one that spends a configured identity
  on a bucket nobody configured. The anonymous tier is the only one.
- Refusing a configured `endpoint` at a cloud instance-metadata host;
  the plugin warns instead. The unconditional refusal covers the
  fallback's endpoint and every redirect destination the http plugin
  and the redirect follower are handed; the redirects this plugin's own
  HTTP client follows are not judged.
