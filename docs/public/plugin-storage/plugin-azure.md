# Azure plugin (`azure`)

The `azure` plugin: a first-party `Backend` implementation against
Azure Blob Storage, with first-class support for Hierarchical
Namespace (HNS) accounts — Azure Data Lake Storage Gen2. Lives in
`ovstorage-cloud/crates/ovstorage-plugin-azure/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
Azure REST client, Shared Key signing, Service SAS minting, and
Entra OAuth2 client-credentials flow are all hand-rolled against
`reqwest` (rustls-tls) — no `azure_storage` / `azure_identity`
dependency. Mints `ReadResult::Redirect` against Service SAS so bytes
flow directly between Azure and the host; staged block-list writes
emit one redirect per block and commit atomically at
`Put Block List`. The plugin owns Azure's vendor response-header
vocabulary (`x-ms-version-id`, `x-ms-meta-*`, `x-ms-blob-content-md5`,
`x-ms-lease-state`, ...) so the host stays generic.

## Public surface

- **Schemes**: `azure://`, plus Azure-region-native HTTPS prefixes
  (`https://*.blob.core.windows.net/...`,
  `https://*.dfs.core.windows.net/...` for HNS) routed at the
  operator's discretion. The core library treats HTTPS prefixes as
  ordinary `https://` addresses until an explicit route selects this
  plugin.
- **Descriptor**: `kind = "azure"`,
  `display_name = "Azure Blob Storage"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `account` (**required**).
  - `container` (**required**).
  - `endpoint_suffix` (optional; for sovereign clouds; default
    `core.windows.net`).
  - `hierarchical_namespace` (optional bool; when `true`, the plugin
    uses the ADLS Gen2 `dfs` endpoint for path operations and reports
    `has_real_directories = true`). `instantiate` validates the
    configured flag against the account's actual mode and returns
    `InvalidArgument` on mismatch.
  - `change_feed_enabled` (optional bool, default `false` — enables
    `watch_directory` through Azure Blob Change Feed on flat Blob
    accounts).
  - `change_feed_segment_lag_seconds` (optional int, default `60` —
    delays segment reads to avoid open-segment races).
  - `change_feed_poll_interval_seconds` (optional int, default `15`).
- **Credential keys**: `account_key` (Shared Key signing material);
  `sas_token` (pre-issued SAS appended verbatim);
  `client_id` / `client_secret` / `tenant_id` (Entra OAuth2
  client-credentials);
  `federated_token_file` (workload-identity assertion file). Each of
  these credential fields ships with a descriptor default that is a
  placeholder string referencing the conventional `AZURE_*`
  environment variable — for example `account_key`'s default is the
  literal string `${AZURE_STORAGE_ACCOUNT_KEY}`, `sas_token`'s default
  is `${AZURE_STORAGE_SAS_TOKEN}`, and so on through
  `${AZURE_TENANT_ID}` / `${AZURE_CLIENT_ID}` /
  `${AZURE_CLIENT_SECRET}` / `${AZURE_FEDERATED_TOKEN_FILE}`. These
  placeholders are expanded by the host's bundle-resolution layer
  before the resolved `SecretBundle` is passed to the plugin; the
  plugin itself never reads `AZURE_*` environment variables at
  runtime. Resolved auth is cached on the backend; OAuth bearer
  tokens refresh through an in-process `Mutex` 60 seconds before
  expiry.

## Auth

Resolution order (inside the plugin, against the resolved
`SecretBundle`):

1. `account_key` present → Shared Key signing.
2. `sas_token` present → token appended to URLs as-is.
3. (`tenant_id`, `client_id`, `federated_token_file`) present →
   Entra OAuth2 federated workload-identity flow.
4. (`tenant_id`, `client_id`, `client_secret`) present → Entra
   OAuth2 client-credentials flow against
   `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
   with scope `https://storage.azure.com/.default`.

The `AZURE_STORAGE_ACCOUNT_KEY`, `AZURE_STORAGE_SAS_TOKEN`,
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and
`AZURE_FEDERATED_TOKEN_FILE` environment variables are referenced
only through the descriptor's `${...}` placeholder defaults on those
credential fields. The host's bundle-resolution layer is responsible
for expanding the placeholders against the process environment
before passing the resolved bundle in. From the plugin's point of
view there is no fallback step — it sees only the four populated
field combinations above.

The IMDS Managed Identity, Azure CLI (`az login`), VS Code, and
PowerShell credential sources from the SDK's
`DefaultAzureCredential` chain are intentionally **not** implemented
in-process. Operators that need them configure credentials explicitly
via `SecretBundle` (or via the host's `AZURE_*` env-var expansion
into those same bundle fields).

Resolution failures surface as `ErrorCode::AuthRequired`. Anonymous
fallback works only against public containers; signed operations on a
connection that resolved to anonymous return `AuthRequired` from the
data path.

The Shared Key signer hand-rolls the canonical string-to-sign
documented at Microsoft's Authorize-with-Shared-Key page: lowercased,
alphabetically-sorted `x-ms-*` headers; canonicalized resource as
`/{account}{path}\n{name:value1,value2}` per query parameter;
HMAC-SHA256 with the base64-decoded account key;
`Authorization: SharedKey <account>:<signature>`. The Service SAS
minter uses the matching string-to-sign for `signedResource = b` and
emits `sv` / `sr` / `se` / `sp` / `spr` / `sig` query parameters with
a default 5-minute expiry.

## URL handling and version-pinned addresses

Native addresses use `azure://<account>/<container>/<blob-or-path>`.
The configured (account, container) is authoritative; per-call
address parsing rejects any `ResolvedTarget` whose URL contradicts
that pair with `InvalidArgument`.

Path bytes are decoded via `ovstorage_plugin::address::key` before
storing the backend key, then re-encoded once at the HTTP boundary.
Blob names with spaces, `?`, `%`, or Unicode therefore reach Azure
with the correct single-encoded form (no double-encoding). HNS
accounts have filesystem-like path rules and may reject names that
flat Blob would accept; the plugin reports the provider's rejection
as `InvalidArgument` rather than silently normalising.

Versioned URLs use Azure's opaque `versionid` pin (lowercased to
match Azure's wire form, also accepted as `versionId`). `stat`,
`read`, `delete`, and `copy(source)` append `versionid=<id>` to both
the HTTP URL and the Shared Key canonical query. Mutating ops whose
wire format cannot carry a version pin — `write`, `write_stream`,
`write_redirect`, `rename(both endpoints)`, `update_metadata` —
reject any pinned `?versionid=` with `InvalidArgument` (Azure's
`Put Blob`, `Put Block List`, `Set Blob Metadata`, and the HNS rename
surfaces all target the current version). `x-ms-version-id` from
responses copies into `ObjectInfo.version`.

## SPI-to-API mapping

| SPI method | Azure API |
|---|---|
| `instantiate` | (no remote call; parses the `ConnectionRequest` config, resolves `AzureAuth` from the `SecretBundle`, builds the `reqwest` (rustls) client, and returns the `BackendInstance` with per-mode `Capabilities`. Bearer-token acquisition and the `hierarchical_namespace` round-trip check happen on the first data-path call.) |
| `stat` (flat) | `HEAD Blob`. |
| `stat` (HNS) | `HEAD ?action=getStatus` against the dfs endpoint. |
| `read` | Service SAS-signed GET URL (Shared Key auth), caller's SAS appended verbatim (SAS auth), or bearer-authenticated GET (OAuth). Returns `ReadResult::Redirect` with `ResponseParsing` pinning `etag`, `x-ms-version-id`, `content-length`, `last-modified`, plus the Azure system-metadata header set. |
| `write` (Body::Bytes) | Direct `Put Blob` through the signed client (zero-byte payloads included). Preconditions inline. |
| `write_redirect` (≤ 256 MiB) | Single SAS-signed `Put Blob` redirect with `RedirectBodySource::UserBytes { offset: 0, len }` and an empty `block_ids` continuation; `continue_write` rebuilds `ObjectInfo` from captured response headers (no second hop). |
| `write_redirect` (> 256 MiB) | Partitions into 4 MiB blocks (capped at Azure's 50 000-block limit; oversize bodies surface `Unsupported`). Emits one SAS-signed `?comp=block&blockid=<id>` redirect per block. Block IDs are deterministic: `base64(sha256(blob_key)[..12] \|\| u32::to_be_bytes(seq))`, uniformly 24 chars. |
| `continue_write` | Single `Put Block List` against `build_block_list_xml(block_ids)`. Re-applies `if_dest` (`If-Match: <etag>` for `MatchEtag`, `If-None-Match: *` for `Fail`) at commit time, not on each block. Non-2xx redirect outcomes route through `map_status_to_error` (401 → `AuthRequired`, 403 → `PermissionDenied`, 412 → `PreconditionFailed`, 409 → `AlreadyExists`, only 408/429/503/504 → `Transient`). |
| `delete` | `DELETE Blob`; honours `?versionid=…`. |
| `list` (flat) | `List Blobs` (`?restype=container&comp=list`) with `prefix`, optional `delimiter=/`, `marker`, `maxresults`. Loops on `NextMarker`. Zero-byte slash blobs return `DirectoryMarker`; `BlobPrefixes` return `DirectoryInferred`; an exact marker/prefix duplicate emits only the marker. |
| `list` (HNS) | `Filesystem - List Paths` (`?resource=filesystem&recursive=<bool>&directory=<prefix>`) on the `dfs` endpoint; pages on `x-ms-continuation`. Directory paths return `Directory`. |
| `list_versions` | `List Blobs` with `include=versions` constrained to the target blob's prefix; same `NextMarker` paging. Each version returns an `ObjectInfo` whose address carries `?versionid=…`. Oldest-first order (`version_list_order = Some(Oldest)`). |
| `get_latest_version` | Stat on the pinned version, or the head's current version, returning a version-pinned `ObjectInfo.address`. Unversioned containers return `Unsupported`. |
| `create_directory` (HNS) | `PUT ?resource=directory`. |
| `create_directory` (flat) | Zero-length marker blob at `<key>/`. |
| `delete_directory` (HNS) | `DELETE` against an empty directory; non-empty surfaces `DirectoryNotEmpty`. |
| `delete_directory` (flat) | Removes the marker only (host walks for recursive). |
| `copy` | `Copy Blob` (`x-ms-copy-source`). The source URL is a 5-minute read-only Service SAS under Shared Key auth; the caller's SAS verbatim under SAS auth; the bare URL under OAuth/Anonymous. Cross-account / cross-container `copy` is not implemented. May return `202 Accepted` with `x-ms-copy-status: pending`; the plugin polls every 500 ms with a 30-minute deadline. |
| `rename` (HNS) | Native `PUT ?resource=file` with `x-ms-rename-source`. Atomic. |
| `rename` (flat) | Copy-plus-delete (`supports_server_side_rename = false` for flat). |
| `update_metadata` | Read-modify-write atop `Set Blob Metadata` (replace-only on the wire). Plugin HEADs first to capture existing `x-ms-meta-*` and ETag, applies `user_metadata_remove` then `user_metadata_set`, PUTs the full merged map with `If-Match: <captured-etag>`. Rejected on version-pinned URLs (metadata patching is current-version-only). |
| `check_access` | `Get Blob Properties`; 200 → `read` allowed, 401/403 → denied. Fine-grained inference requires Entra-only RBAC APIs and is out of scope. |
| `watch_directory` | Reads Azure Blob Change Feed (`$blobchangefeed/meta/Segments.json`, segment manifests, chunk directories, Avro object-container chunks) with the storage-account credentials. HNS accounts are excluded (Change Feed does not support HNS). |

Every backend method body is wrapped in
`ovstorage_plugin::race_cancel(cancel.as_ref(), async move { ... })`
so a `CancellationToken` cancelled before or during an in-flight HTTP
exchange surfaces as `ErrorCode::Cancelled` rather than racing to
completion.

## Streaming guarantees

`write` with `Body::Bytes` PUTs directly. The staged-blocks write
path commits atomically at `Put Block List` — if the host follower
fails on any block, the commit never happens and Azure garbage-collects
the uncommitted blocks within a week.

`update_metadata` is read-modify-write; concurrent updates surface as
`PreconditionFailed` (412) for the host's retry policy to handle.

`Copy Blob` polling on cross-region or large copies bounds at 30
minutes; the plugin surfaces `failed` / `aborted` (with
`x-ms-copy-status-description`) as `Internal`.

## Capability bits

Common across both modes: `supports_no_overwrite_write` (via
`If-None-Match: *`), `supports_if_match_write` (via
`If-Match: <etag>`), `supports_native_metadata_patch` (via
`Set Blob Metadata`), `supports_server_side_copy` (via
`x-ms-copy-source`), `supports_version_listing` (with
`version_list_order = Some(Oldest)`), `wants_list_backed_stat`,
`supports_recursive_list`, `supports_list`, `writes_are_atomic`.

Mode-specific:

- Flat (non-HNS): `has_real_directories = false`,
  `supports_server_side_rename = false`,
  `supports_atomic_rename = false`.
- HNS (ADLS Gen2): `has_real_directories = true`,
  `supports_server_side_rename = true`,
  `supports_atomic_rename = true`,
  `populates_subdirectory_metadata = true`.

`supports_watch_directory = true` only when
`change_feed_enabled = true` and `hierarchical_namespace = false`.
Advertised kinds: created, deleted, metadata-changed (no `modified` —
in-place overwrite arrives as `BlobCreated`).
`watch_directory_resumable = false`, `watch_directory_max_lag = 120s`.

**Enforcement**

- `if_match` (read / delete / update_metadata), `if_source` (copy /
  rename), and `IfDestExists::MatchEtag` (write / copy / rename) all
  accept an opaque etag string. Azure's wire carries it as
  `If-Match` / `x-ms-source-if-match`; `IfDestExists::Fail` maps to
  `If-None-Match: *`.
- Background OAuth refresh runs at ~90% of the access token's TTL with a
  30s retry floor on failure (Entra OAuth2 connections only; SharedKey
  and SAS connections don't refresh).
- Streaming writes with unknown size route through `write_stream`. The
  plugin refuses `write_redirect` with `opts.size_hint = None` (returns
  `Unsupported`).
- Inverted byte ranges return `InvalidArgument` at the SPI boundary.
- Copy and rename emit the source-side conditional
  (`x-ms-source-if-match` from `CopyOptions::if_source`) in addition
  to the destination-side conditional from `if_dest`.

## Subscriptions and watch

Initial watches start from a live window ending at
`lastConsumable - change_feed_segment_lag_seconds`; they do not
replay the account's retained change-feed history. If a running
watcher falls behind that live window — or more than twice its
effective poll interval elapses between successful polls — it emits
`Lapsed` and continues from the current window.

The Avro reader is intentionally narrow: it supports the
object-container format, `null` and raw-`deflate` codecs, block
sync-marker verification, the change-feed primitive fields,
`map<string,string>` metadata, and primitive unknown-field skipping.
Unsupported codecs or complex unknown schema additions surface as
chunk-level `Lapsed` events rather than panics. Chunks are marked
consumed only after records decode and map successfully, or after an
intentional terminal skip (missing / corrupt / unsupported chunk).

## Threat model

The plugin holds resolved Azure credentials in process memory for
the lifetime of the connection. In Brokered mode the broker holds
the credentials; the library sees only short-lived SAS-bearing
redirects. Service SAS strings expire 5 minutes after issuance by
default and are redacted under the same rules as every other
presigned redirect. OAuth bearer tokens cached in
`tokio::sync::Mutex<Option<CachedToken>>` — followers re-check the
cache after acquiring the lock so a concurrent burst on an expired
token yields exactly one refresh request.

## Deferred capabilities

- Managed Identity (IMDS), Azure CLI (`az login`), VS Code, and
  PowerShell credential sources from `DefaultAzureCredential`.
- Event Grid push subscriptions for `watch_directory`.
- Entra-only RBAC inference for fine-grained `EffectivePermissions`.
