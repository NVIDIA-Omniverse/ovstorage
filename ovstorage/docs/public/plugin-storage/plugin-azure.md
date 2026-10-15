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
- **Anonymous-fallback layer keys** (set on `[ovstorage.layers.<name>]`,
  never on a connection; see [Anonymous fallback](#anonymous-fallback)).
  None of them appears in the kind descriptor's `config_schema`, so
  `ovstorage connect` never prompts for one:
  - `anonymous_fallback` (TOML array of scheme strings; the only scheme
    this kind serves is `"azure"`; absent or `[]` is off, which is the
    default).
  - `anonymous_fallback_endpoint_suffix` (optional; default
    `core.windows.net`; validated as a DNS suffix. The fallback derives
    `<account>.blob.<suffix>` from it, so a sovereign cloud is one key
    away.)
  - `anonymous_fallback_max_backends` (optional int, default `64`; how
    many per-container anonymous clients stay resident. Must be `1` or
    more: `0` is refused at `create_backend`, as it is on `s3` and
    `gcs`, and a value that does not fit is refused as too large.)
  - `anonymous_fallback_mints_per_minute` (optional int, default `120`;
    how many clients may be built per sliding minute. Must be `1` or
    more: `0` is refused at `create_backend` rather than read as no
    budget, and a value that does not fit is refused as too large.)

### Anonymous fallback

An `azure://<account>/<container>/<blob>` address that no connection
serves has nowhere to go: the route scan misses and the caller sees
`NoRoute`. The `anonymous_fallback` layer key is the opt-in answer, off
by default:

```toml
[ovstorage.layers.azure]
anonymous_fallback = ["azure"]
```

A granted layer publishes one extra address root beside its connection
roots: the bare scheme `azure:///`, `Hidden`, with no connection id,
read-only capabilities, the `Native` ranged-read strategy its connection
roots advertise, and the marker
`org.omniverse.ovstorage/scheme-fallback = "anonymous"` in its
`user_metadata`. The shared route table consults that root only after
every prefix has missed, so a configured container always outranks it
for its own node, and only for an address whose query carries no
credential. On a hit the layer reads the account and the container from
the address, synthesizes the same per-container config a connection
would carry — a flat namespace, no change feed, the blob tier at
`<account>.blob.<anonymous_fallback_endpoint_suffix>` — and builds an
`AzureBackend` from a literal empty `SecretBundle`; see [Auth](#auth).
Building costs no request. Nothing is registered as a `Connection`:
`list_connections` never lists the fallback, `ovstorage connect
azure://account/container/` sees no incumbent, and adding a connection
for a node the fallback has been serving is not a `RouteConflict`. The
connection outranks the fallback the moment it installs, the cached
anonymous client for that node is dropped, and removing the connection
hands the node back to the fallback. `root_info_for` on a
fallback-served address returns the `azure:///` root verbatim;
`ovstorage list-routes` omits hidden roots, so the grant is visible
through `ovstorage doctor`, which lists the root with its marker, and
through the one `INFO` line the first build for a node logs at target
`ovstorage.fallback`, naming the account origin and never a container or
blob.

The grant is layer configuration. A library, CLI or MCP host sets the
key directly; the broker and the REST gateway set it from their
top-level `anonymous_fallback_schemes` and refuse a hand-set layer key,
so the deployment-wide policy has one spelling — see the
`anonymous_fallback` section of
[`../configuration.md`](../configuration.md) and the
[broker operator guide](../broker-operator/README.md). Every
`anonymous_fallback*` key is validated at `create_backend` whether or
not the grant is on, so a mistake is refused where the operator wrote
it rather than on the day the grant is added: a key this kind does not
read answers `InvalidArgument` (`` unknown Azure layer key
`anonymous_fallback_endpoint`; the anonymous fallback accepts
anonymous_fallback, anonymous_fallback_endpoint_suffix,
anonymous_fallback_max_backends, anonymous_fallback_mints_per_minute
``), and a grant naming a scheme this kind does not serve answers
`InvalidArgument` (`` `anonymous_fallback` on layer `azure` (kind
azure) names scheme `s3`, which this kind does not serve; it serves
azure ``). A connection request — `ovstorage connect`, an
`[[ovstorage.connections]]` entry, or a probe — carrying any of these
keys is refused with `` `anonymous_fallback` is a layer key, not
connection config; set it on [ovstorage.layers.azure] ``, because a
fallback key on a connection would otherwise be reported as an unknown
field and send the operator to the wrong document.

**A fallback grants routability, never authority.** Policy sees the
caller's address, before routing and before alias resolution, so a
caller the [authorization policy](../authz-policy/README.md) does not
cover is denied before the fallback is consulted and no request leaves
the process on their behalf. No grant is ever generated for the
fallback — that would be automatic widening of a deny-by-default policy
— and a container-scoped rule does not cover `azure:///`: a rule on the
bare scheme (`prefix = "azure://"`) lists the hidden root and grants
nothing on any account.

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

A container reached through the [anonymous fallback](#anonymous-fallback)
is served exactly as an anonymous connection is, and its anonymity is
structural. The resolution order above runs on a connection's resolved
`SecretBundle`, after the host has expanded the `${AZURE_*}`
placeholders on that connection's credential fields; the fallback has no
connection and no credential fields, and it resolves its auth source
from a literal empty bundle. The resolver reads only the bundle, so it
resolves to anonymous by construction rather than by the absence of an
environment: no `AZURE_STORAGE_ACCOUNT_KEY`, no `AZURE_STORAGE_SAS_TOKEN`
and no Entra secret can reach a fallback request however the process is
configured. It signs nothing and appends nothing: `read` emits the bare
blob URL as a redirect declared `none`, and `stat`, `list`,
`list_stream`, `list_versions`, `get_latest_version` and `check_access`
go to the store as they are, succeeding exactly as far as the
container's public-access level allows — the same **blob** versus
**container** distinction as above, with the same `404` for an
enumeration the level does not permit.

Read-only takes two shapes here, and they differ on purpose. A
configured connection that resolves to anonymous keeps every capability
bit a credentialed one advertises except `supports_write_redirect`,
because every other operation is genuinely attempted and it is the
service that decides. The fallback's `azure:///` root instead withholds
every write, delete, copy, rename, directory-mutation, metadata-patch
and watch bit, and the layer refuses those slots before any request is
built: `Unsupported`, `this address is reached through the anonymous
azure:// fallback, which is read-only`, with a `next_action` naming the
node root (`add a connection for azure://account/container/ with
credentials to modify it`) and never the blob. `copy` and `rename`
check both ends and refuse when either is fallback-served, naming that
end, so the refusal is the fallback's rather than the cross-connection
`Unsupported`. `watch_directory` is refused the same way: the change
feed is a standing registration the fallback has no identity to hold.
An anonymous mutation is not something to attempt on an operator's
behalf against a container the operator did not configure, whatever
the container would accept.

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

With `anonymous_fallback = ["azure"]` on the layer, an address naming
an (account, container) pair that no connection pins is routed to the
[fallback](#anonymous-fallback) rather than left at `NoRoute`. The
account and the container come from the address, validated exactly as
a connection's `account` and `container` are; the endpoint suffix comes
from `anonymous_fallback_endpoint_suffix`; and the namespace is taken to
be flat — there is no HNS probe an anonymous caller could run, so the
`dfs` tier is never addressed and `has_real_directories` is false on the
`azure:///` root. One client is built per (account, container), so
`azure://account/alpha/one.usd` and `azure://account/beta/two.usd` are
two nodes and two clients under one account. What the fallback does not
extend to is deliberate. The scheme root and any hostless address —
`azure:///`, `azure:///container/key` — name no account and answer
`InvalidArgument` (`an azure:// address names no storage account`) on
every slot, mutations included; `azure://account/` names no container
and answers `InvalidArgument` (`azure address must include an account
and container`). An address whose query carries anything outside the
shared carried-query allowlist — the version selectors `versionid`,
`versionId`, `generation` and `revision` — never reaches the fallback and
answers the byte-identical `NoRoute` an ungranted layer gives: a SAS URL
such as `azure://account/container/key?sig=abc` — or a `sv`, or a
`snapshot` selector — authenticates itself, and re-serving it anonymously
would silently discard the authority the caller presented, while
`azure://account/container/key?versionid=7` (or `?versionId=7`) routes
and is honoured on the wire; `generation` and `revision` route as well,
and this plugin ignores them.

### Generated URL spellings

`azure://<account>/<container>/…` is the connection's only canonical
address form; the ordinary HTTPS spellings of the same data are the
**alias layer's** job. So that an operator does not have to author them,
each connection advertises the URL prefixes it accepts as alternate
spellings of its root (`org.omniverse.ovstorage/accepted-url-spellings` on
its connection row), and an alias layer composed above installs one
**hidden** alias rule per spelling at registration — addressable, never
advertised, withdrawn with the connection. See "Generated aliases" in
`docs/public/configuration.md` for the alias-layer and authorization
semantics — including that a generated rule declines a SAS URL rather than
re-serving it with this connection's credentials.

The spellings are a property of a connection, so the
[anonymous fallback](#anonymous-fallback) generates none:
`https://account.blob.core.windows.net/container/key` for a container no
connection pins is an ordinary HTTPS address and stays `NoRoute` under a
granted layer, while `azure://account/container/key` routes.

The set is derived from the same effective-endpoint resolution the request
signer uses — never a host template — so every configured shape comes out
right by construction:

- the blob tier, always: `https://<account>.blob.<endpoint_suffix>/<container>/`
  for a natural host (sovereign suffixes included), or the configured
  `blob_endpoint` — including path-style Azurite,
  `http://127.0.0.1:10000/devstoreaccount1/<container>/`, and privatelink
  or custom hosts;
- the DFS tier, exactly when `hierarchical_namespace` is set:
  `https://<account>.dfs.<endpoint_suffix>/<container>/` (or the configured
  `dfs_endpoint`). Under HNS the account answers on both hosts for the same
  data; a flat-namespace connection never addresses the DFS tier, so no DFS
  spelling is generated for it.

**An endpoint carrying a path prefix generates no spelling unless it is
loopback.** These prefixes are published in connection metadata, which
`list_connections` and `list_address_roots` return to a principal holding
only the addressless introspection operation — a weaker grant than reading
the data — while connection configuration is otherwise never returned. An
endpoint path can be a capability token
(`https://gateway.example/<token>`), so a remote path-bearing
`blob_endpoint` or `dfs_endpoint` is withheld rather than published; the
two tiers are filtered independently, so a clean blob endpoint still
generates while a path-bearing DFS endpoint does not. The loopback
carve-out is what keeps path-style Azurite working: its path is the
well-known `devstoreaccount1`, on an address that never leaves the host.
Author the alias rule by hand to accept such a prefix — publishing it is
then a decision rather than a default.

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

It is also spelled into `ObjectInfo.versioned_address` as
`azure://<account>/<container>/<blob>?versionid=<id>`: `stat` reports it
for free from the `Get Blob Properties` response, echoing a caller's own
`?versionid=` pin; `list` reports it only under
`ListOptions::versioned_address`. HNS (`dfs`) stats and listings carry no
version id and answer `None`, as do directory kinds and a container
without versioning. Writing through a returned pin is refused exactly as
above.

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

### Instance-metadata endpoints

A second advisory runs in the same spirit. A connection whose blob base
— or, under `hierarchical_namespace`, its `dfs` base, or, under
`change_feed_enabled`, its change-feed base — resolves to a cloud
instance-metadata endpoint (`169.254.0.0/16`, `100.100.100.200`,
`168.63.129.16`, `fe80::/10`, `fd00:ec2::254`, an IPv6 address
embedding a refused IPv4 address, or the exact names
`metadata.google.internal`, `metadata.goog` and `metadata`) is
honoured, and logs one `warn` at construction: `Azure connection
endpoint is a cloud instance-metadata host; it is honoured because an
operator configured it, but every request this connection signs goes
to that host`. An operator who wrote that endpoint chose it, and the
request carries that operator's own credential.

The [anonymous fallback](#anonymous-fallback) is the other case, and it
is refused rather than warned about. Its blob host is derived from an
account name a **caller** wrote, which is exactly the shape a
server-side request forgery takes, so the derived host is judged by the
same predicate before any client is built and an instance-metadata
endpoint answers `PermissionDenied` (`refusing to contact <origin>: it
is a cloud instance-metadata endpoint, and ovstorage never fetches from
one on a caller's behalf`). In practice `<account>.blob.<suffix>` cannot
spell one of those names, so the check is defence in depth on this
plugin; it is the same predicate the http plugin applies to every
redirect destination, where the destination is a server's choice. The
predicate judges the host as written: a DNS name that resolves to a
link-local address is not caught.

## Layer-to-API mapping

| Layer method | Azure API |
|---|---|
| `add_connection` | Parses the connection config, resolves `AzureAuth` from the `SecretBundle`, and builds the `reqwest` (rustls) client. Bearer-token acquisition and the `hierarchical_namespace` round-trip check happen on the first data-path call. Capabilities are returned through `RootInfo`. |
| `stat` (flat) | `HEAD Blob`. A present `x-ms-version-id` is also spelled into `versioned_address` as `?versionid=…`, whatever `StatOptions::versioned_address` says; a caller's own pin is echoed; directory kinds and unversioned containers carry `None`. |
| `stat` (HNS) | `HEAD ?action=getStatus` against the dfs endpoint. `getStatus` reports no version id, so `versioned_address` is `None`. |
| `read` | Service SAS-signed GET URL (Shared Key auth), caller's SAS appended verbatim (SAS auth), or bearer-authenticated GET (OAuth). Returns `ReadResult::Redirect` with `ResponseParsing` pinning `etag`, `x-ms-version-id`, `content-length`, `last-modified`, plus the Azure system-metadata header set. On `hierarchical_namespace` connections — the only shape advertising `has_real_directories` — one `HEAD ?action=getStatus` precedes the signing: an `x-ms-resource-type: directory` verdict refuses the read with `InvalidArgument` and `list()` guidance, as `Layer::read` requires. Any other outcome (including a refused or failed probe) signs as usual, and flat namespaces issue no probe at all. |
| `write` (Body::Bytes) | Direct `Put Blob` through the signed client (zero-byte payloads included). Preconditions inline. |
| `write_redirect` (≤ 256 MiB) | Single `Put Blob` redirect with `RedirectBodySource::UserBytes { offset: 0, len }` and an empty `block_ids` continuation; `continue_write` rebuilds `ObjectInfo` from captured response headers (no second hop). Authorized per [Redirect credential scope](#redirect-credential-scope): a minted Service SAS under Shared Key, the caller's SAS verbatim under SAS auth, a bearer header under OAuth; refused under Anonymous. |
| `write_redirect` (> 256 MiB) | Partitions into 4 MiB blocks (capped at Azure's 50 000-block limit; oversize bodies surface `Unsupported`). Emits one `?comp=block&blockid=<id>` redirect per block, authorized the same way as the single-shot form. Block IDs are deterministic: `base64(sha256(blob_key)[..12] \|\| u32::to_be_bytes(seq))`, uniformly 24 chars. |
| `continue_write` | Refused with `Unsupported` on an anonymous connection, before the continuation is decoded — it is gated implicitly by `supports_write_redirect`, which that connection shape withholds. Otherwise a single `Put Block List` against `build_block_list_xml(block_ids)`. Re-applies `if_dest` (`If-Match: <etag>` for `MatchEtag`, `If-None-Match: *` for `Fail`) at commit time, not on each block. Non-2xx redirect outcomes route through `map_status_to_error` (401 → `AuthRequired`, 403 → `PermissionDenied`, 412 → `PreconditionFailed`, 409 → `AlreadyExists`, only 408/429/503/504 → `Transient`). |
| `delete` | `DELETE Blob`; honours `?versionid=…`. |
| `list` (flat) | `List Blobs` (`?restype=container&comp=list`) with `prefix`, optional `delimiter=/`, `marker`, `maxresults`. Loops on `NextMarker`. Zero-byte slash blobs return `DirectoryMarker`; `BlobPrefixes` return `DirectoryInferred`; an exact marker/prefix duplicate emits only the marker. With `ListOptions::versioned_address` set, a recursive listing adds `include=versions` and keeps only entries whose `IsCurrentVersion` is not `false`, pinning each `File` with `?versionid=…` (every version of every blob under the prefix travels in the response, so a page carries fewer items than `maxresults`); a non-recursive listing keeps its `delimiter` — the service refuses `include=versions` together with one — and issues one `Get Blob Properties` call per blob, whose answer supplies the pin from `x-ms-version-id` and replaces the listed entry's etag, size, mtime and metadata so they describe the version the pin names. `BlobPrefixes` and markers stay `None`. With the flag clear, `versioned_address` is `None`. |
| `list` (HNS) | `Filesystem - List Paths` (`?resource=filesystem&recursive=<bool>&directory=<prefix>`) on the `dfs` endpoint; pages on `x-ms-continuation`. Directory paths return `Directory`. `List Paths` carries no version id, so `versioned_address` is `None`. |
| `list_versions` | `List Blobs` with `include=versions` constrained to the target blob's prefix; same `NextMarker` paging. Each version returns an `ObjectInfo` whose address carries `?versionid=…`, and `versioned_address` equal to that address. Oldest-first order (`version_list_order = Some(Oldest)`). |
| `get_latest_version` | Stat on the pinned version, or the head's current version, returning a version-pinned `ObjectInfo.address` and `versioned_address` equal to it. Unversioned containers return `Unsupported`. |
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

### Metadata keys

The plugin formats every `user_metadata` key verbatim into an
`x-ms-meta-<key>` header — on `Put Blob`, on the presigned PUT, at
`Put Block List` and on `Set Blob Metadata` — and validates nothing
before the wire. Azure requires a metadata name to be a C# identifier
(a letter or underscore first, then letters, digits and underscores)
and refuses any other name, a hyphen included, with
`400 InvalidMetadata`, which fails the write. The service compares names
case-insensitively, and the plugin reads them back from lowercased
response headers, so a key round-trips in lowercase whatever case it
was written in. The portable subset in
[User-metadata keys](CONFORMANCE.md#user-metadata-keys) is the
lowercase form of this rule, and the reserved `ovstorage_` names sit
inside it. The per-operation `message` is stashed into the same map
under `x_ov_message`, a name inside this rule, so a write or metadata
patch that carries one stores the annotation beside the caller's keys;
a message that is not a legal header value, one carrying a line break
for instance, is dropped and the call proceeds without it.
`copy` and `rename` issue Copy Blob without metadata headers, so the
destination carries the source's metadata verbatim, annotation
included, and the message they carry is not recorded.

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
- Raw HTTP `ETag` headers are normalized into opaque tokens with
  `normalize_wire_etag`. A conformant nonempty quoted etag is declared
  `Strong`; an explicit `W/` marker is preserved out of band as `Weak`; and a
  bare or malformed unmarked header value is `Unspecified`. Azure serializes
  the typed etag members in List Blobs XML and List Paths JSON without those
  HTTP quotes; a nonempty bare value in either list payload is declared
  `Strong` from the provider contract rather than inferred from its spelling,
  while an explicit `W/` remains `Weak`.
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

The [anonymous fallback](#anonymous-fallback) holds no credential at
all — no account key, no SAS, no bearer to cache — so there is nothing
of its own in process memory to protect and nothing a redirect could
carry: its `read` redirects are bare blob URLs declared `none`, and
every mutation and `watch_directory` is refused before the wire. Its
outbound host is judged by the instance-metadata predicate before any
client is built (see [Instance-metadata
endpoints](#instance-metadata-endpoints)). Its cost is bounded because
account and container names are the caller's to invent: at most
`anonymous_fallback_max_backends` clients stay resident, the least
recently used evicted first; at most `anonymous_fallback_mints_per_minute`
may be built per sliding minute, every attempt charged; and past the
budget a cold node answers `ResourceExhausted` (`anonymous fallback mint
budget exhausted; retry later`, retryable) while resident nodes keep
answering. A build is single-flight per node. A SAS URL for an
unconfigured container is never re-served anonymously: it falls through
to `NoRoute` rather than reaching the fallback.

## Deferred capabilities

- Managed Identity (IMDS), Azure CLI (`az login`), VS Code, and
  PowerShell credential sources from `DefaultAzureCredential`.
- Event Grid push subscriptions for `watch_directory`.
- Entra-only RBAC inference for fine-grained `EffectivePermissions`.
- The HTTPS spellings of an unconfigured container reaching the
  anonymous fallback; the fallback serves `azure://` alone.
- Hierarchical-namespace accounts through the anonymous fallback; the
  fallback assumes a flat namespace and never addresses the `dfs` tier.
- A credentialed fallback tier — one that spends a configured identity
  on a container nobody configured. The anonymous tier is the only one.
- Refusing a configured `blob_endpoint` or `dfs_endpoint` at a cloud
  instance-metadata host; the plugin warns instead. The unconditional
  refusal covers the host the fallback derives and every redirect
  destination the http plugin and the redirect follower are handed;
  the redirects this plugin's own HTTP client follows are not judged.
