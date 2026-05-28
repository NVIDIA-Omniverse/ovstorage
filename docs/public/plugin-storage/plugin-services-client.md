# Omniverse Storage Service plugin (kind `omniverse-storage-service`)

The `omniverse-storage-service` plugin: the reference implementation
of the `Backend` SPI against the Omniverse Storage Service over Storage API
gRPC + OIDC. Lives in
`ovstorage-services-client/crates/ovstorage-plugin-services-client/`
and compiles against the canonical contracts at
`ovstorage-services/apis/storage-api/proto/` (v1alpha) and
`ovstorage-services/apis/notifications-api/consumer/protos/`
(v1beta).

**Public surface**

- **Schemes**: not URL-scheme based. Addresses are resolved through
  the configured service's discovery endpoint, not a per-scheme
  prefix.
- **Descriptor**: `kind = "omniverse-storage-service"`,
  `display_name = "Omniverse Storage"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `discovery_url` (**required**, URL): HTTP root that serves
    `/api/v1/services` (returns the gRPC endpoint) and
    `/api/v1/auth-config` (returns OIDC client configuration). HTTPS
    by default; the plugin infers `http` only for `localhost`, `.local`
    hostnames, or IP literals.
  - `oidc_client_name` (optional, string, default `"default"`):
    selects which entry from `auth-config.clients` drives the OIDC
    flow.
- **Credential methods.** The descriptor offers two
  `CredentialMethod`s; the UI picks one per connection:
  - **`interactive`** (default; PKCE for browsers, device flow for
    headless). Uses the `oauth` secret bundle (an `OAuthToken` with
    access token, optional refresh token, and expiry). Cold-start
    flows are driven by
    `Factory::authenticate(InteractiveAuthCapability::Browser | Headless)`;
    the resulting refresh token is stored to the OS keyring so
    follow-up processes warm-continue without re-prompting.
  - **`client_credentials`** (machine-to-machine for service
    identities). Uses the `client_id` and `client_secret` credential
    fields and authenticates to the IDP directly, with no user sign-in.

**Discovery and auth**

Connection setup is two-stage. The plugin fetches
`{discovery_url}/api/v1/services` to learn the gRPC endpoint, then
`{discovery_url}/api/v1/auth-config` to learn which OIDC issuer and
client to authenticate against. The issuer's OIDC discovery document
(`/.well-known/openid-configuration`) supplies the auth/token/device
endpoints. A bearer-token interceptor wraps every outgoing gRPC call
with the current access token; expiry triggers an automatic
refresh-token grant against the discovered token endpoint.

The `grpc` value in the discovery response is interpreted per the
standard gRPC name-resolution scheme: `grpc://host:port` for
plaintext, `grpcs://host:port` for TLS. The plugin rewrites these to
tonic's native `http://` / `https://` internally and accepts those
schemes as direct equivalents. A bare `host:port` (no scheme)
defaults to plaintext for local addresses (`localhost`, `*.local`,
loopback / private IPs) and TLS for everything else, so a public
domain typed without a scheme isn't silently downgraded. The
deployment guides in the vendored `ovstorage-services/` subtree
may use older wording around `http://` vs. `grpc://`; the rules
above are what this client actually applies.

Cold-start interactive auth (no `oauth` credential bundle on file)
runs through the plugin's `authenticate(...)` entry point. The host
chooses `InteractiveAuthCapability::Browser` (PKCE with a loopback
redirect) or `Headless` (RFC 8628 device flow). Both surface
`AuthEvent` updates the host can render to the user. The result is
an `OAuthToken` the host installs as the connection's credentials.

**Precondition shape**

The Storage API wire carries opaque `ResourceIdentity` values as
precondition tokens. In this plugin, `encoded_identity` is an etag:
it validates the resource the caller already observed, and it is not
a version address. The plugin maps the SPI precondition fields onto
the wire directly; it does not pre-`Stat` just to compare the current
head when the caller already supplied the etag/identity token:

- `ReadOptions::if_match` — `Option<String>` etag, forwarded as
  `ReadRequest.resource_identity.encoded_identity`.
- `DeleteOptions::if_match` — `Option<String>` etag, forwarded as
  `DeleteRequest.previous_version.encoded_identity`.
- `UpdateMetadataOptions::if_match` — returns `Unsupported`; the Storage API
  metadata service preconditions individual metadata keys rather than
  the whole object identity.
- `WriteOptions::if_dest = IfDestExists::MatchEtag(etag)` — forwarded
  to the Storage API write request's destination identity.
- `WriteOptions::if_dest = IfDestExists::Fail` — returns `Unsupported`
  at the SPI boundary; the Storage API wire has no destination-must-not-exist
  predicate (`supports_no_overwrite_write = false`).
- `CopyOptions::if_source` — `Option<String>` etag, forwarded as
  `CopyRequest.source_resource_identity`. When absent, the plugin
  must `Stat` the source because the Storage API `Copy` RPC requires a
  source identity even for an unconditional copy.
- `CopyOptions::if_dest = IfDestExists::MatchEtag(etag)` — forwarded
  as `CopyRequest.previous_version`. Despite the generic field name,
  the Storage API defines this as the destination's expected current identity;
  the source identity is `CopyRequest.source_resource_identity`.
- `RenameOptions::if_source` — forwarded as
  `MoveRequest.source_previous_version` as an etag precondition.
- `RenameOptions::if_dest = IfDestExists::MatchEtag(etag)` —
  forwarded as `MoveRequest.destination_previous_version` as an etag
  precondition. The Omniverse Storage Service exposes real two-sided
  preconditions on move.

The etag is opaque to the SPI and is used only for optimistic
concurrency. Version selection and version listing use addresses:
Storage API `VersionInfo.resource_address` is the version-pinned address the
plugin returns as `ObjectInfo.address`. If the Omniverse Storage Service rejects or can no
longer read a supplied identity, the plugin maps that failure to
`ObjectModified`; it does not reinterpret `ResourceIdentity` as an
address query parameter.

**Version address shape**

`list_versions` calls `VersioningService.EnumerateVersions` with the
resolved `resource_address`. That field is required for the
address-first API; the plugin does not synthesize a version request
from `ResourceIdentity.encoded_identity`, does not fall back to an
encoded-identity token when the address is missing, and does not parse
or rewrite a backend-specific version selector out of the returned
URL. Each streamed version becomes an `ObjectInfo` whose address is
the returned version-pinned `resource_address`, projected back into
caller space by the host.

`get_latest_version` first calls `VersioningService.EnumerateVersions`
and chooses the latest item according to `versions_order`:
`NEWEST_FIRST` selects the first item, `OLDEST_FIRST` selects the last
item, `BY_KEY` selects the item with the greatest `sorting_key`, and
`UNSPECIFIED` returns `Unsupported`. If the service rejects the input
as an invalid version-enumeration address, the plugin treats it as an
already version-pinned resource address, stats that exact address, and
returns it unchanged.

**SPI-to-RPC mapping**

| SPI method | gRPC RPC |
|------------|----------|
| `instantiate` | `CapabilitiesService.ListTopLevelAddresses` (after HTTP service discovery) |
| `stat` | `FileObjectService.Stat` |
| `read` | `FileObjectService.ReadFromAddress` (server-stream); chunks → `ReadResult::Stream`, `Redirect` → `ReadResult::Redirect` |
| `write` / `write_stream` | `FileObjectService.Write` (bidi); inline body, single `ResourceInfo` response |
| `write_redirect` + `continue_write` | `FileObjectService.Write` returning `WriteRedirect` (single PUT) or `MultipartUpload` (parts), finalized via `CompleteRedirectUpload` / `CompleteMultipartUpload`; aborts via `AbortMultipartUpload` |
| `delete` | `FileObjectService.Delete` |
| `list` | `FileFolderService.ListStat` (server-stream) |
| `list_versions` | `VersioningService.EnumerateVersions` (server-stream; requires `resource_address`) |
| `get_latest_version` | `VersioningService.EnumerateVersions` with `versions_order` selection; `FileObjectService.Stat` fallback when the service rejects an already version-pinned address |
| `create_directory` / `delete_directory` | `FileFolderService.CreateFolder` / `DeleteFolder` |
| `copy` / `rename` | `FileObjectService.Copy` / `Move` |
| `update_metadata` | `MetadataService.UpdateMetadata` (one RPC per key) |
| `check_access` | `MetadataService.GetMetadata` for the `acl` user-metadata key (list of `read` / `write` / `admin` strings) |
| `watch_directory` | `EventConsumerService.ConsumeNonDurableEvents` (bidi stream, filter on `omni.storage.{,dir_}{created,deleted}`) |
| `watch_address_roots` | `CapabilitiesService.ListTopLevelAddresses`, single `Snapshot` (no delta feed today) |

**Streaming guarantees**

`write_stream` is true-streaming: the host's `BodyStream` chunks
reach the gRPC seam one-by-one through a bounded async channel,
never buffered. `Body::LocalFile` reads via async I/O — no
`spawn_blocking` on the I/O path. The streaming-invariant test
drives ≥3 chunks totaling ≥64 MiB at 4 MiB through the bidi seam
and asserts bounded in-flight bytes, preserved chunk count, and
in-order arrival.

Range reads buffer the requested byte range only; the gRPC server's
stream interleaves the body bytes and `Redirect` envelopes, and the
client surfaces `Redirect` as `ReadResult::Redirect` for the host's
in-process redirect follower.

Multipart uploads return `WriteStep::Redirects` whose
`continue_write` points at part endpoints; finalize with
`CompleteMultipartUpload`. Aborts (cancel, error) explicitly call
`AbortMultipartUpload` so the server doesn't accumulate orphaned
parts.

**ACL semantics**

The `acl` user-metadata key is a `ListValue` of permission tokens.
Mapping:

| Token | SPI ops granted |
|---|---|
| `read` | `read` |
| `write` | `write` + `update_metadata` |
| `admin` | `delete` |

Absent `acl` key or `MetadataService` returning `Unimplemented` →
grant all ops. An `acl` value that is not a list grants nothing;
unknown or non-string entries inside a list are ignored. The actual
RPC returns `PermissionDenied` if the storage server refuses;
`check_access` is a hint, not an authoritative gate.

**Capability bits**

The backend starts from static support for `writes_are_atomic`,
`supports_server_side_copy`, `supports_server_side_rename`,
`supports_atomic_rename`, `supports_write`, `supports_write_stream`,
`supports_write_redirect`, `supports_delete`, `supports_list`,
`supports_native_metadata_patch`, `supports_version_listing`,
`supports_access_check`, and `supports_watch_directory`. Per
top-level address, it probes `GetFolderMode` to set directory
capabilities and `GetOptimisticLockingSupport` to set
`supports_if_match_write`; if those probes are unimplemented or fail,
the plugin keeps the descriptor defaults. The
`watch_directory_kinds` set is `{created, deleted}` — the Omniverse
Storage Service emits no `modified` or `metadata_changed` events for
non-durable subscriptions, so the backend declares those off to avoid
host dispatch surprise.

Notably **not** advertised (false): `supports_no_overwrite_write`,
`supports_recursive_list`, `wants_list_backed_stat`,
`populates_subdirectory_metadata`,
`populates_effective_permissions_on_stat`,
`supports_metadata_rewrite_emulation`. The recursive-list gap means
the host falls back to repeated one-level listings for subtree
traversal.

**Threat model**

Credentials live in `SecretBundle::oauth` and are redacted in
`Debug` output. The bearer-token interceptor is the only place the
plaintext access token is read; it's installed into the
`tonic::transport::Channel`'s request layer and not exposed elsewhere
in the plugin's API. Operators who route private prefixes to this
backend must trust the Omniverse Storage Service's TLS configuration and the
OIDC issuer; the plugin does not pin server certificates beyond the
default rustls root-cert store.
