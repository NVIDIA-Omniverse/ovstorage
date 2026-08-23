# Azure plugin (`azure`)

The `azure` plugin: a first-party `Backend` implementation against
Azure Blob Storage, with first-class support for Hierarchical
Namespace (HNS) accounts — Azure Data Lake Storage Gen2. Lives in
`ovstorage-cloud/ovstorage-plugin-azure/` and compiles as a
cdylib loaded through the C ABI declared by `ovstorage-plugin`. The
Azure REST client, Shared Key signing, Service SAS minting, and
Entra OAuth2 client-credentials flow are all hand-rolled against
`reqwest` (rustls-tls) — no `azure_storage` / `azure_identity`
dependency. Mints `ReadResult::Redirect` so bytes flow directly between
Azure and the host — against a Service SAS under Shared Key, and
against the connection's own credential under the other auth modes
(see [Redirect credential scope](#redirect-credential-scope)); staged
block-list writes
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
  - `blob_endpoint` (optional; a full service URL — scheme, host,
    optional port, optional path prefix — for the blob tier. When set
    it overrides `endpoint_suffix` for that tier; `endpoint_suffix`
    still addresses the tier that has no explicit endpoint). The URL
    carries addressing only: config parsing rejects a query string, a
    fragment or URL-embedded credentials with `InvalidArgument`, and
    rejects them on presence — a bare trailing `?`, `#` or `@` counts.
    There is no loopback or credential restriction, so an emulator on a
    container hostname (`http://azurite:10000`) is accepted; see
    [Plain-HTTP endpoints](#plain-http-endpoints) for what a cleartext
    endpoint puts on the wire.
  - `dfs_endpoint` (optional; the same full-URL form for the ADLS
    Gen2 `dfs` tier). The two tiers resolve independently, so this may
    be set on its own — routing DFS through a private gateway while
    the blob tier keeps resolving from `endpoint_suffix` is a
    supported shape. The one combination config parsing rejects with
    `InvalidArgument` is the reverse: on a `hierarchical_namespace`
    connection a custom `blob_endpoint` must be paired with a
    `dfs_endpoint`, because otherwise data operations move off the
    public cloud while HNS path operations keep addressing the public
    `dfs` suffix, splitting the connection across two accounts.
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

The cross-plugin
[credential-provider matrix](credential-providers.md)
distinguishes the supported federated-token-file flow from Managed
Identity and cached developer credentials, which have no representable
bundle shape.

Resolution failures surface as `ErrorCode::AuthRequired`.

A connection that resolves to anonymous signs nothing and sends every
request as it is, so what succeeds is decided by the container's
public-access level rather than by the plugin:

- **blob** — an anonymous `read` of a blob is permitted; enumeration is
  not, so `list` is refused by the service;
- **container** — anonymous `read` and `list` both work
  (`GET ?restype=container&comp=list`).

Everything the level does not cover is refused by Azure, carrying its
`x-ms-error-code` in the message. `write_redirect` is the operation
refused locally, because delegating a write needs a SAS to mint — so
`supports_write_redirect` is false on an anonymous connection, and the
refusal is `ErrorCode::Unsupported`. `continue_write` refuses with it,
for the same reason and with the same code: it has no bit of its own and
is gated implicitly by that one, so it self-gates rather than running
behind a bit that is false. That refusal precedes the continuation being
decoded, because the single-`Put Blob` arm builds its answer from the
caller's own captured headers and contacts no store. Every other capability bit is
identical to a credentialed connection's, because every other operation
is genuinely attempted and it is the service that decides.

Read the code, not the status, when diagnosing an anonymous refusal.
Azure declines to disclose that a container exists to a principal not
permitted to enumerate it, so an anonymous `list` against a *blob*-level
container can arrive as `404` and reach the caller as
`ErrorCode::NotFound` — indistinguishable on the status line from a
container that is genuinely absent. The `x-ms-error-code` carried in the
message is what separates them.

The Shared Key signer hand-rolls the canonical string-to-sign
documented at Microsoft's Authorize-with-Shared-Key page: lowercased,
alphabetically-sorted `x-ms-*` headers; canonicalized resource as
`/{account}{endpoint-path-prefix}{path}\n{name:value1,value2}` per
query parameter — the prefix is empty for host-style endpoints and
carries the endpoint's path segments (for example `/devstoreaccount1`)
under path-style account addressing, so the signed resource always
matches the request URI;
HMAC-SHA256 with the base64-decoded account key;
`Authorization: SharedKey <account>:<signature>`. The Service SAS
minter uses the matching string-to-sign for `signedResource = b` and
emits `sv` / `sr` / `se` / `sp` / `spr` / `sig` query parameters with
a default 5-minute expiry.

**Object keys are signed percent-encoded.** Azure's rule is that any
part of the canonicalized resource derived from the request URI is
"encoded exactly as it is in the URI" — only query parameter names and
values are decoded — which is why the .NET signer reads
`Uri.AbsolutePath` and the Go one `EscapedPath()`. The canonical path
therefore runs the blob key through the same encoder the request URL
uses, and is byte-identical to the URL's path component.

Signing the raw key while the request URL carried the encoded one would
produce an unexplained 403 for any key containing a space, a `+`, a `%`,
most punctuation or a non-ASCII byte; signing the encoded form is what
makes those keys work.

## Redirect credential scope

`read` and `write_redirect` hand back an `HttpRequest` the caller is
expected to execute against Azure itself. **What credential rides in
that request depends on the auth mode**, and the four modes are not
equivalent. This matters when the party executing the redirect is
remote, because that party keeps whatever the request carried. Where a
host does hand the redirect over — see the disclosure policy below — a
broker client receives the whole `HttpRequest`, headers included. A REST
client receives less: the gateway's 307 carries only `Location` and
`X-OV-Audit-Id`, so a credential in the URL crosses to it and a
credential in a header does not.

| Auth mode | Declares | Credential in the redirect | Scope of what the executor gains |
|---|---|---|---|
| Shared Key | `request` | A freshly minted Service SAS in the URL query, `sr=b` over the single blob path, `sp=r` for reads and `sp=cw` for writes, `spr=https` (widened to `spr=https,http` only when the configured endpoint is itself cleartext — see [Plain-HTTP endpoints](#plain-http-endpoints)), 5-minute expiry | That one blob, those permissions, five minutes |
| Operator-supplied SAS | `connection` | The configured `sas_token`, appended verbatim | Exactly what the operator minted — the plugin neither narrows nor inspects it, so it may authorize one blob or the whole account and must be assumed connection-wide |
| Entra OAuth (client secret or federated) | `connection` | `Authorization: Bearer <token>` in the request headers — the connection's own storage-account token | Everything the service principal is entitled to, account-wide rather than blob-scoped, for the remaining lifetime of the token (whatever Entra declared in `expires_in`; the plugin assumes one hour only when Entra omits it) |
| Anonymous | `none` | None. `read` emits the bare URL; `write_redirect` refuses with `Unsupported`, and `supports_write_redirect` is not advertised for this connection shape (an absent `size_hint` is also refused as `Unsupported`, on either shape) | Nothing the caller did not already have |

The cloud siblings behave differently, and the contrast is the point.
S3 presigns every credentialed redirect, and a SigV4 presigned URL
carries the access-key id but no secret; its anonymous mode emits a
plain unsigned URL, which discloses nothing. GCS V4-signs the URL from a
service-account key and, when the credential is an authorized-user
credential that cannot sign, **declines to redirect and streams the
bytes itself** rather than falling back to a broader credential; its
write redirects are per-object resumable session URLs. So GCS's
redirect behaviour also varies by credential type — but it varies
between "narrow" and "no redirect", never into a wide one. Neither S3
nor GCS emits an `Authorization` header on a redirect under any
configuration.

Azure is not the only in-tree backend that puts a credential in
redirect headers. Nucleus LFT redirects carry the connection's auth
headers on both the read and the write path, and the services client
copies the headers its service returns onto the redirect verbatim. What
follows is about Azure, but the host-side mechanics it describes are
not Azure-specific.

`RedirectScope`'s addressing fields narrow none of this. They constrain
the URL (`physical_url_prefix`, which for Azure is the whole container)
and the verb (`AccessOps`), and the host's own redirect follower checks
them immediately before it dials the URL. They are not constraints that
travel with the redirect and bind a remote executor. What governs
disclosure is a separate field on the same struct,
`RedirectScope.credential`, carrying the declaration in the table
above.

### What the host does about it

The mode's answer is a declaration the plugin stamps on every redirect
it mints, and a host decides from that declaration rather than from
inspecting the redirect. Inspection cannot decide it: an account SAS and
a single-blob SAS are byte-identical on the wire, and a bearer is one
more opaque string. Only the code that built the credential knows what
it authorizes.

Hosts — the broker and the REST gateway — take a top-level
`redirect_credential_disclosure`, whose default is `"refuse"`. Under
`refuse`, a redirect declared `connection` does not cross the host
boundary, on either path:

- **Read.** The host's redirect follower fetches the object itself and
  returns `ReadResult::Stream`. The bytes stay reachable; what the
  caller does not receive is the credential. This is independent of the
  follower's `follow_reads` and `follow_reads_max_bytes` settings — a
  size cap decides whether an object is worth caching, not whether a
  connection is readable — so an Entra OAuth read of any size succeeds
  under the shipped broker configuration and under the REST gateway's
  `follow_reads = false`. Where no follower sits on the path at all, a
  hand-written graph included, the broker has no bytes in reach and
  refuses the redirect with `PermissionDenied`.
- **Write.** `write_redirect` is refused with `Unsupported`, and the
  caller — in the canonical Brokered topology, the library's own
  redirect follower above the `broker` plugin — sends the body through
  the broker instead. A later round of a redirected write already in
  flight is refused with `PermissionDenied`.

Under `allow`, any valid redirect is handed to the client, headers
included. That is the setting for clients already inside the trust
boundary; on an Entra OAuth connection it means every client permitted
to write receives the storage-account bearer.

Shared Key and Anonymous redirects are delegated under **both**
settings. They are the reason redirects exist: a Service SAS naming one
blob for five minutes discloses nothing beyond the transfer it
authorizes.

The declaration can be lowered but never raised. A host that finds a
header it cannot account for on a redirect declared `request` treats
that redirect as connection-scoped, so a declaration mistake costs a
proxied transfer rather than a disclosure.

### Choosing a mode

- **Shared Key is the mode to run a broker on.** It is the only one
  that mints a per-operation, per-blob, short-lived credential for
  every redirect, and it is what the redirect design assumes. It is also
  the only mode whose redirects a host will delegate under the default
  policy, so it is the one that keeps the redirect path — bytes moving
  client-to-Azure — rather than routing every transfer through the
  broker.
- **Entra OAuth is the mode for a direct client-to-Azure
  configuration**, where the party following the redirect is the
  application itself, in the same trust domain, and nothing crosses a
  boundary. Under a broker on the default policy it works and discloses
  nothing, at the cost of the broker moving every byte: reads are
  streamed through the broker and writes go through it as bodies rather
  than as redirects. Setting `redirect_credential_disclosure = "allow"`
  buys the redirect path back by handing the storage-account bearer to
  every client permitted to read or write, which is a defensible trade
  only where those clients are already as trusted as the service
  principal. Run a broker on Shared Key to have both.
- **An operator-supplied SAS cannot be narrowed by the plugin.** A SAS
  is an HMAC over a fixed field set; re-signing a narrower one requires
  the account key, which this mode does not hold, and Azure offers no
  attenuation primitive. That is why its redirects are declared
  connection-wide and withheld by default: the plugin appends a token it
  did not mint, cannot read, and cannot bound. Obtaining a user
  delegation key instead would require an OAuth credential, which this
  mode does not hold either. So the control is at mint time. Mint the narrowest token the workload
  actually needs — a single blob where that is possible, otherwise the
  smallest container or directory scope the SAS form supports — with
  only the permissions it uses and the shortest lifetime you can
  operate. If it is a **service** SAS, back it with a container
  **stored access policy**, which makes it revocable without rotating
  the account key; an account SAS or a user delegation SAS cannot be
  backed by one, and for those the only revocation is rotating the
  account key or the delegation key respectively.

Minting a *user delegation SAS* on the OAuth path — narrow, like Shared
Key, but signed from a key obtained with the bearer rather than from
the account key — is what would let an OAuth connection declare
`request` and keep its redirects under the default policy, without
changing deployment shape. It is not implemented. It needs a
new `?restype=service&comp=userdelegationkey` call and its own key
cache, a second string-to-sign variant (a user delegation SAS
interposes `skoid`/`sktid`/`skt`/`ske`/`sks`/`skv` into the canonical
string and emits them as extra query parameters, so the Service SAS
signer cannot be reused), and a decision about principals that lack the
`generateUserDelegationKey` action.

## URL handling and version-pinned addresses

Native addresses use `azure://<account>/<container>/<blob-or-path>`.
The configured (account, container) is authoritative; per-call
address parsing rejects any `ResolvedTarget` whose URL contradicts
that pair with `InvalidArgument`.

Path bytes are decoded via `ovstorage_plugin::address::key_utf8` before
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

### Emulator and custom endpoints

`blob_endpoint` / `dfs_endpoint` take a full service URL, so an
emulator, a private-link name, or a sovereign endpoint that
`endpoint_suffix` cannot express is representable directly. Azurite's
default blob service is:

```toml
[[ovstorage.connections]]
display_name = "azurite"
backend_kind = "azure"
config = { account = "devstoreaccount1", container = "mycontainer", blob_endpoint = "http://127.0.0.1:10000/devstoreaccount1" }
```

The URL's scheme, host, and port replace the derived
`https://{account}.blob.{endpoint_suffix}` base for that tier. A
non-empty path is a **path prefix**: it means the endpoint uses
path-style account addressing (the account sits in the path rather
than the hostname), and the plugin folds it into every Shared Key
canonicalized resource as `/{account}{prefix}/{container}/{blob}` —
matching the request URI, which is what keeps signed requests off a
403. The blob prefix also applies to the change feed, since
`$blobchangefeed` is a blob-tier container. Query strings, fragments,
and userinfo are rejected, and a non-`http`/`https` scheme is
rejected; the keys carry no loopback restriction, so a container
hostname such as `http://azurite:10000` is accepted — see
[Plain-HTTP endpoints](#plain-http-endpoints) for what a cleartext one
puts on the wire.

The accepted URL is normalized before anything is built from it:
scheme and host case-fold, a port that is the scheme default and a
trailing `/` drop. Normalization is what the request URLs, the Shared
Key prefix, and the signed-protocol decision all read, so
`HTTPS://Host` is treated as TLS-only exactly like `https://host`.

Service SAS is unaffected by the prefix — its string-to-sign
canonicalizes as `/blob/{account}/{container}/{blob}` from the
configured account, not from the URL. Only the signed protocol
follows the endpoint: a plain-HTTP endpoint mints `spr=https,http`
(Azure accepts only those two values), and everything else mints
`spr=https`.

### Plain-HTTP endpoints

A plain-`http://` endpoint is accepted with every credential mode and
carries no loopback restriction — an emulator reached by container
hostname is exactly the shape these keys exist for, and refusing it
would refuse the feature:

```toml
config = { account = "devstoreaccount1", container = "mycontainer", blob_endpoint = "http://azurite:10000/devstoreaccount1" }
```

What the plugin does instead is **warn**. When an endpoint it will
actually address is plain HTTP on a non-loopback host, the connection
logs a `warn` naming the endpoint, the credential mode and the exposure
that mode implies, so an operator who set it once and forgot still has
a trace.

The check runs after credential resolution at backend construction, so
it covers every way a connection is built, and it reads the *resolved*
auth source rather than which credential fields happen to be present.
Every tier that carries the credential is scanned, each only when
something will address it: the blob tier always, the DFS tier under
`hierarchical_namespace`, and the change feed under
`change_feed_enabled` — that last one resolves through its own chain,
so a loopback data-path override does not make it clean. A loopback
literal (`127.0.0.1`, `[::1]`) is never warned about — nothing leaves
the host — but a hostname is never treated as loopback even when it
resolves there today, because DNS cannot promise that tomorrow.

**Use `https://` for anything that is not an emulator**, because a
cleartext endpoint puts the following on the wire where anyone on the
path can read and replay it:

| credential | on the wire over `http://` |
| --- | --- |
| anonymous | no credential, but object bytes, listings and metadata all cross the link in the clear — readable by anyone on the path, and modifiable in transit. |
| Shared Key (`account_key`) | a per-request HMAC over the verb, headers and canonicalized resource. The key itself is never sent, and a captured signature authorizes only the one request it covers — but the redirect paths below mint a bearer SAS. |
| `sas_token` | the caller's SAS, appended to the request URL verbatim and readable in the request line — replayable until it expires. |
| OAuth (`client_id` + `client_secret` + `tenant_id`, or `federated_token_file`) | the access token, as `Authorization: Bearer …` — replayable until it expires. |

There is one exposure the plugin creates itself rather than passing
through: under Shared Key the redirect-following read and write paths
mint a **Service SAS** and hand that URL to the caller, and on a
plain-HTTP endpoint it carries `spr=https,http` (a SAS pinned to
`https` is rejected by an HTTP emulator, which is why the protocol
follows the endpoint). Each is scoped to a single blob with read or
write only and expires in five minutes, but within that window it is
observable on the wire and replayable.

The `127.0.0.1` Azurite example is safe because it is loopback plus the
emulator's well-known account key: nothing replayable leaves the host.
The `http://azurite:10000` form is the same emulator over a container
network — supported, and warned about, because the bytes do leave the
host even when that network is trusted.

## Layer-to-API mapping

| Layer method | Azure API |
|---|---|
| `add_connection` | Parses the connection config, resolves `AzureAuth` from the `SecretBundle`, and builds the `reqwest` (rustls) client. Bearer-token acquisition and the `hierarchical_namespace` round-trip check happen on the first data-path call. Capabilities are returned through `RootInfo`. |
| `stat` (flat) | `HEAD Blob`. |
| `stat` (HNS) | `HEAD ?action=getStatus` against the dfs endpoint. |
| `read` | Service SAS-signed GET URL (Shared Key auth), caller's SAS appended verbatim (SAS auth), or bearer-authenticated GET (OAuth). Returns `ReadResult::Redirect` with `ResponseParsing` pinning `etag`, `x-ms-version-id`, `content-length`, `last-modified`, plus the Azure system-metadata header set. On `hierarchical_namespace` connections — the only shape advertising `has_real_directories` — one `HEAD ?action=getStatus` precedes the signing: an `x-ms-resource-type: directory` verdict refuses the read with `InvalidArgument` and `list()` guidance, as `Layer::read` requires. Any other outcome (including a refused or failed probe) signs as usual, and flat namespaces issue no probe at all. |
| `write` (Body::Bytes) | Direct `Put Blob` through the signed client (zero-byte payloads included). Preconditions inline. |
| `write_redirect` (≤ 256 MiB) | Single `Put Blob` redirect with `RedirectBodySource::UserBytes { offset: 0, len }` and an empty `block_ids` continuation; `continue_write` rebuilds `ObjectInfo` from captured response headers (no second hop). Authorized per [Redirect credential scope](#redirect-credential-scope): a minted Service SAS under Shared Key, the caller's SAS verbatim under SAS auth, a bearer header under OAuth; refused under Anonymous. |
| `write_redirect` (> 256 MiB) | Partitions into 4 MiB blocks (capped at Azure's 50 000-block limit; oversize bodies surface `Unsupported`). Emits one `?comp=block&blockid=<id>` redirect per block, authorized the same way as the single-shot form. Block IDs are deterministic: `base64(sha256(blob_key)[..12] \|\| u32::to_be_bytes(seq))`, uniformly 24 chars. |
| `continue_write` | Refused with `Unsupported` on an anonymous connection, before the continuation is decoded — it is gated implicitly by `supports_write_redirect`, which that connection shape withholds. Otherwise a single `Put Block List` against `build_block_list_xml(block_ids)`. Re-applies `if_dest` (`If-Match: <etag>` for `MatchEtag`, `If-None-Match: *` for `Fail`) at commit time, not on each block. Non-2xx redirect outcomes route through `map_status_to_error` (401 → `AuthRequired`, 403 → `PermissionDenied`, 412 → `PreconditionFailed`, 409 → `AlreadyExists`, only 408/429/503/504 → `Transient`). |
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
`x-ms-copy-source`), `supports_copy`, `supports_rename` (availability:
`rename` is offered on both namespace shapes; only the mechanism
differs, see below), `supports_version_listing` (with
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
- Inverted byte ranges return `InvalidArgument` at the Layer boundary.
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
them, and what a calling library sees instead depends on the auth mode
and on the operator's disclosure policy — see
[Redirect credential scope](#redirect-credential-scope). Under Shared
Key it is a per-blob Service SAS that expires 5 minutes after issuance.
Under the other credentialed modes the redirect is declared
connection-scoped, so under the default policy the caller sees bytes the
broker moved rather than a credential, and under
`redirect_credential_disclosure = "allow"` it sees the operator's SAS or
the storage-account bearer.
Service SAS strings are redacted under the same rules as every other
presigned redirect. OAuth bearer tokens cached in
`tokio::sync::Mutex<Option<CachedToken>>` — followers re-check the
cache after acquiring the lock so a concurrent burst on an expired
token yields exactly one refresh request.

Storage-endpoint error bodies are never interpolated into error text.
When a Blob or ADLS Gen2 request fails, only the allowlisted
error-code token — the `x-ms-error-code` response header, which is
the only source on a HEAD (a `stat`, which has no body), else
`<Code>` from the Blob XML error shape or `error.code` from the ADLS
Gen2 JSON shape — and the
`x-ms-request-id` correlation header survive into `error.message`;
the rest of the body is discarded. A body from which no code can be
recovered is reported by its length alone and nothing else. So an
`AuthenticationFailed` response cannot disclose the request MAC or
the canonical string-to-sign through a logged exception.

The Entra token endpoint is not covered by that guarantee: a failed
token request reports the identity provider's response text.
Those bodies carry AADSTS codes and correlation IDs rather than the
client secret or the signing key, so the residual exposure is low —
but it is response text, and operators who forward `error.message` to
a shared log sink should know it is there.

## Deferred capabilities

- Managed Identity (IMDS), Azure CLI (`az login`), VS Code, and
  PowerShell credential sources from `DefaultAzureCredential`.
- Event Grid push subscriptions for `watch_directory`.
- Entra-only RBAC inference for fine-grained `EffectivePermissions`.
