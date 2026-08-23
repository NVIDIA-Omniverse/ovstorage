# Omniverse Storage Service plugin (kind `omniverse-storage-service`)

The `omniverse-storage-service` plugin: the reference implementation
of the `Backend` Layer contract against the Omniverse Storage Service over Storage API
gRPC + OIDC. Lives in
`ovstorage-services-client/ovstorage-plugin-services-client/`
and compiles against the canonical contracts at
`ovstorage-services/apis/storage-api/proto/` (v1alpha) and
`ovstorage-services/apis/notifications-api/consumer/protos/`
(v1beta).

**Public surface**

- **Schemes**: not URL-scheme based. Object addresses are resolved
  through the configured service, not a per-scheme prefix. (The
  *connection's own* URL does use its scheme to say whether it names a
  discovery service or a gRPC endpoint — see below.)
- **Descriptor**: `kind = "omniverse-storage-service"`,
  `display_name = "Omniverse Storage"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `address` (**required**, URL): where the service is. It
    takes either of two forms, told apart by the scheme:
    - **A discovery root** — `https://host`, `http://host`, or a bare
      `host[:port]`. The HTTP root that serves `/api/v1/services`
      (returns the gRPC endpoint) and `/api/v1/auth-config` (returns
      OIDC client configuration). HTTPS by default; the plugin infers
      `http` only for `localhost`, `.local` hostnames, or IP literals.
    - **A direct gRPC endpoint** — `grpcs://host[:port]` (TLS) or
      `grpc://host[:port]` (plaintext, local hosts only). The storage
      service is dialed at exactly that address and no discovery service
      is contacted. See
      [Connecting straight to a gRPC endpoint](#connecting-straight-to-a-grpc-endpoint).

    A bare `host:port` is always a discovery root, even when the host
    is literally named `grpc` — the direct form requires the `://`
    separator.
  - `oidc_client_name` (optional, string, default `"default"`):
    selects which entry from `auth-config.clients` drives the OIDC
    flow.
  - `allow_plaintext_credentials` (optional, bool, default `false`):
    permits a bearer token to be sent over a `grpc://` endpoint that is
    not loopback. See
    [Credentials over a cleartext link](#credentials-over-a-cleartext-link).
  - `persistence_id` (optional, string): durable account
    discriminator. See
    [Stored credentials belong to one account](#stored-credentials-belong-to-one-account).
- **Credential methods.** The descriptor offers two
  `CredentialMethod`s; the UI picks one per connection:
  - **`interactive`** (default; PKCE for browsers, device flow for
    headless). Uses the `oauth` secret bundle (an `OAuthToken` with
    access token, optional refresh token, and expiry). Cold-start
    flows are driven by
    `Layer::authenticate_connection` with a Browser or Headless capability;
    the resulting refresh token is offered to the host's
    `secret_put` callback. Whether it is stored at all turns on the
    session having an identifiable account and on no sibling
    connection sharing the derived key; whether a follow-up process
    can warm-continue from it turns additionally on that process
    re-deriving the same key from the discovery URL, the OIDC client
    and `persistence_id`, on what the host backs the callback with, and
    on how long that store keeps an entry.
  - **`client_credentials`** (machine-to-machine for service
    identities). Uses the `client_id` and `client_secret` credential
    fields and authenticates to the IDP directly, with no user sign-in.

    Both methods need the OIDC endpoints that only a discovery root
    publishes, so **neither applies to a direct gRPC endpoint**. Such a
    connection takes an access token the host supplies in the `oauth`
    field and attaches it, whitespace-trimmed and otherwise unaltered;
    there is no method entry for that,
    because there is no flow to drive — see
    [A host-supplied bearer](#a-host-supplied-bearer-and-how-to-rotate-it).

### Connecting straight to a gRPC endpoint

A deployment that knows its storage gRPC address and runs no discovery
service sets `address` to that address with a `grpc://` or
`grpcs://` scheme:

```toml
address = "grpcs://storage.internal:50051"   # TLS
address = "grpc://localhost:50051"           # plaintext
```

It is also the shortest way to point the plugin at a service running
locally, which is what makes it convenient for a test or CI setup that
brings up a storage service without a discovery service beside it.

Discovery supplies two things — the service endpoints *and* the OIDC
client configuration — and a direct endpoint replaces only the first.
So such a connection can talk to no identity provider, and it says so
rather than pretending otherwise:

- there is no interactive sign-in. `authenticate_connection` answers
  `Unsupported` — the code that means "this backend has no
  authentication flow", as distinct from `AuthRequired`, which means a
  flow exists and could not be driven. It is the same answer the cloud
  backends give.
- there is no `client_credentials` grant and no plugin-driven token
  refresh, for the same reason: both need the OIDC endpoints that only
  `/api/v1/auth-config` names.
- **no credential is stored or read.** Such a connection takes no part
  in the credential store, so it cannot disturb the stored credential
  of a connection that does. That is a consequence rather than a
  policy: the secret store holds OAuth *refresh tokens*, and this mode has
  nowhere to redeem one.
- `watch_directory` is **not advertised**. Directory watching runs over
  the `notification-consumer` service, and only `/api/v1/services` can
  name that endpoint. Asking the transport for it returns
  `NotConfigured` naming the missing service. Every other capability is
  served by the `storage` endpoint and is unaffected.

To use OIDC sign-in against such a deployment, configure a discovery
URL instead — the two forms are alternatives, not a pair.

### A host-supplied bearer, and how to rotate it

What a direct endpoint *can* do is carry an access token the host
already holds. Supply it in the `oauth` credential field and gRPC calls
go out with `authorization: Bearer <token>`. Supply nothing and the
connection is anonymous.

It can be written straight into configuration:

```toml
[connections.config]
address = "grpcs://storage.internal:50051"

[connections.credentials]
oauth = "${OVS_STORAGE_TOKEN}"
```

or handed over programmatically as an OAuth token bundle, in which case
the refresh token is ignored — see below.

An `${...}` reference is resolved when the host reads its configuration,
and an **unset** variable fails that read — which is a startup failure,
not a connection failure, exactly as it is for every other credential in
the file. A variable that is set but **empty** is a different case: it is
treated as a credential that was supplied and cannot be used, so the
connection is refused rather than quietly becoming anonymous.

**What the token itself may contain.** Surrounding whitespace is
removed, so a token read out of a file or a Kubernetes secret works with
the trailing newline it arrives with — a bearer token's alphabet
(RFC 6750 `b64token`) contains no whitespace, so nothing can be lost by
trimming. A token holding a **control character anywhere inside it** is
refused when the credential is accepted, naming the problem, because no
HTTP header value can carry one and the request would fail on every
call. The check runs where the credential is taken, so a malformed token
parks that one connection instead of failing the host at startup. Bytes
outside ASCII are *not* refused: an HTTP header value may carry them.

Because the plugin cannot mint a successor, **rotation is the host's
job**, and the standard credential-update call is how it is done:
`update_connection_credentials` with a fresh `oauth` bundle replaces
the bearer on a **live** connection — no teardown, no re-add, and the
same call re-publishes the connection's routes when the deployment
answers. A host that refreshes its own token on a timer simply calls it
again each time.

To drop the credential, call the same update with a bundle that names no
credential — an **empty** one, or one carrying only blank values under
keys this plugin does not model. The connection becomes anonymous and
stops sending an `authorization` header: it is a removal, not just a
change of reported state.

**Naming a credential field this plugin models is an offer whatever it
carries**, so a bundle carrying a blank `oauth`, or a blank
`client_id` / `client_secret` pair, is refused rather than treated as a
removal. Those are the three fields the credential schema publishes, and
that is the one place this reads presence rather than content. It is
deliberate: the way a blank arrives is an environment reference that
resolved to nothing, or a form submitted with the boxes empty, and
deleting a working bearer because a secret failed to populate is not a
recoverable kind of helpful. The accident belongs to the reference, not
to the field it sits under, which is why the rule covers all three
rather than `oauth` alone.

Anything else that carries something but no usable access token — a
refresh token, a `client_id` / `client_secret` pair, or a populated field
this plugin does not recognise — is a **failed** credential operation and
is refused with `Unsupported` and a message naming what to supply. The
distinction matters because a removal *deletes a working bearer*: if
"nothing I can use" and "nothing at all" were the same case, a mistyped
update would silently drop a live connection's credential and report
success.

A refused update does **not** disturb the bearer already in use: the
refusal happens before anything is cleared, so requests keep working. The
connection is parked to record that the rotation did not take, and it
recovers on the next accepted update — or on its own next bring-up, which
re-uses the credential it still holds.

"All blank" is judged on the shapes a secret can take — a text value, a
token bundle, a file path, a certificate pair — and only for keys outside
the credential schema, since a schema field is an offer by name. A credential that
carries no bytes but still expresses an intent — asking for the host's
ambient system identity, for instance — is a credential this endpoint
cannot use, not an absent one, and is refused rather than treated as a
removal.

Four consequences worth stating, because all four are visible:

- The connection reports **no expiry**, on the connection view and on a
  *Test connection* probe alike. That field's job in ovstorage is to
  schedule a background refresh, and there is no refresh to schedule;
  the party that knows when the token expires is the host that minted
  it.
- A refresh token or a `client_credentials` pair supplied *alongside* a
  usable access token is **not used** — both need the missing token
  endpoint. The token is served from and the rest dropped, with a warning
  once per connection, rather than the whole bundle being refused.
- If the server **rejects** a new bearer, the update reports failure and
  the connection parks. The token it was already serving stays
  installed, because nothing replaces the live one until a candidate has
  been proven — so requests keep working while the rotation is reported
  as having failed. Supplying a token the deployment accepts, through
  the same call, recovers it. There is no other route: this connection
  has no grant to refresh with and no sign-in flow.
- Over `grpc://`, sending the bearer **requires
  `allow_plaintext_credentials = true`** on the connection unless the
  endpoint is loopback. Without it the credential is refused and the
  connection parks, naming the key in the error. See
  [Credentials over a cleartext link](#credentials-over-a-cleartext-link)
  below.

If the server rejects the bearer on an ordinary request, the failure is
surfaced to the caller rather than retried: there is no grant that could
recover it, and the remedy is a fresh token from the host.

### Credentials over a cleartext link

**Scope: this is about a DIRECT endpoint**, one whose `address` is a
`grpc://` value. A discovery connection is not covered — see the note at
the end of this section.

`grpc://` is plaintext. On a direct endpoint, sending a bearer token over
one is **off by default**, and the operator turns it on per connection:

```toml
[[ovstorage.connections]]
backend_kind = "omniverse-storage-service"

[ovstorage.connections.config]
address = "grpc://storage:50051"
allow_plaintext_credentials = true          # required to send the token

[ovstorage.connections.credentials]
oauth = "${OVS_STORAGE_TOKEN}"
```

(The shorter `[connections.config]` fragments elsewhere on this page show
only the config table; the block above is a whole connection entry, so it
carries the `ovstorage.` prefix a stack file needs.)

Without the key, `obtain` refuses the credential and the connection parks
with a message naming the key. The connection itself is still allowed —
this gates the *credential*, not the address — so an anonymous `grpc://`
connection is unaffected.

With the key, the connection logs one `WARN` naming itself the first time
it sends a token over the cleartext link. It is latched, so an unchanging
configuration is not restated on every operation, and it is not emitted
for a loopback endpoint — the audience is the operator who accepted the
disclosure, not every local development connection.

**Loopback needs no opt-in**, because the packets reach no network.
Loopback here means an IP literal in a loopback range — `127.0.0.0/8`,
`::1`, and the IPv4-mapped form `[::ffff:127.0.0.1]` — or the name
**`localhost` exactly**, with an optional trailing dot.

That name test is deliberately literal, and narrower than "a name that
resolves to loopback". `localhost.localdomain`, a `*.localhost`
subdomain, or a hosts-file entry pointing at `127.0.0.1` all still
require the opt-in: what resolves to loopback on the machine writing the
config is not something this plugin can verify, and the failure direction
is to ask rather than to assume.

**Why this is not covered by the plaintext address rules.** Plaintext
addresses are accepted for private, in-cluster and single-label hosts
(below), on the grounds that such a host cannot be on the public
internet. That reasoning covers the *object bytes*, which are exposed on
the one link they cross. It does not cover an access token: the IDP that
minted it chose its audience, so anyone who can read the link — a
compromised sidecar, a node-level capture agent, a mirrored port — can
replay it anywhere else that audience is accepted. The data is exposed
on one link; the credential is exposed everywhere it is honoured.

Two limits on the loopback exemption, stated because they are the ways it
can be wrong. Loopback traffic crosses no network, but it is still visible
to a process on the same machine holding `CAP_NET_RAW` — a sidecar with
host networking, a shared CI runner. And the exemption for the *name*
`localhost` trusts local resolution: a hosts file or resolver that points
`localhost` somewhere other than 127.0.0.1 sends the token there with no
opt-in, because what a name resolves to is not something this plugin can
check.

**A discovery connection is not gated by this key.** Where discovery
publishes a `grpc://` storage endpoint, the OIDC-minted access token rides
that cleartext channel with neither this refusal nor a warning: the
channel's scheme is not known until the endpoints are fetched, which is
after the credential decision is made. That is a real gap and it is not
closed here — the same reasoning about replay applies to it. Prefer a
discovery service that publishes `grpcs://`.

Prefer `grpcs://` wherever the deployment can terminate TLS. Use
`allow_plaintext_credentials` where the link is trusted end to end by
something outside this plugin — a service mesh with mTLS, or an encrypted
underlay — and where you accept that the token is readable by whatever
sits between.

`grpc://` means **plaintext** and `grpcs://` means **TLS**, following the
standard gRPC name-resolution convention. Because a cleartext link to a
host on the public internet is not a mistake that can be taken back,
**`grpc://` is refused for any host that could be one.** Plaintext is
accepted for:

- `localhost`, and loopback / private / link-local addresses;
- `.local` and `.internal` names;
- **any single-label name** — `storage`, `ovstorage-svc` — which is how
  a service is addressed inside a Docker network or from within a
  Kubernetes namespace. Such a name resolves through a local search
  domain or the container runtime's DNS rather than the public
  hierarchy. (Dotless names are prohibited for new top-level domains
  and refused by mainstream clients, so this is a judgement that the
  in-cluster reading is the intended one — not a guarantee that no such
  public name can exist. If your deployment is an exception, spell the
  address `grpcs://`.);
- names ending in `.internal` (reserved for private use) or `.svc`
  (undelegated). Matched as suffixes only — `evil.svc.example.com` is a
  public host and is refused. The Kubernetes long form
  `svc.namespace.svc.cluster.local` qualifies via `.local`;
- shared address space `100.64.0.0/10` (carrier-grade NAT, and the
  overlay networks built on it such as cluster CNIs and Tailscale);
- IPv4-mapped IPv6 spellings of loopback and private addresses, such as
  `[::ffff:127.0.0.1]`.

A name written with a trailing dot is a root-relative FQDN and is
resolved only through the public root, so it never qualifies under the
single-label rule — `grpc://ai.` is refused. `localhost.` and
`broker.local.` still work, because they qualify on their own terms.

A single label that is all digits, or a `0x`-prefixed hex number, is
refused too: the system resolver reads those as addresses rather than
names, so `grpc://134744072` would reach 8.8.8.8 in cleartext through
the rule meant for `storage`.

Anything else needs `grpcs://`, and the refusal says so.

This matters because the same string means the opposite in the broker
client, which reads `grpc://remote-host` as TLS. Refusing here is what
stops one spelling silently meaning two different things across two
plugins. For the same reason the broker's own `grpc+tls://` and
`grpc+tcp://` spellings are **refused by name** rather than being read
as a discovery URL, which is what they would otherwise become.

A port is optional — the default for the HTTP scheme the value is
rewritten to applies — but give one explicitly: a gRPC service rarely
listens on the HTTP defaults, and the broker plugin requires a port for
its own direct endpoints.

A direct endpoint is an **address and nothing else**. A path, query
string or fragment is refused rather than carried, because the value
becomes the connection's identity and is written to the log — a token
pasted into a query string would otherwise be persisted and printed.
Userinfo (`grpc://user:pw@host`) is refused for the same reason. The
host must be ASCII: supply an internationalized name in its punycode
form (`xn--...`), which is what the gRPC client requires, rather than
having the connection accepted and then fail when the channel is
built.

**This applies to the direct arm only.** A discovery `address` still
takes userinfo, a path, a query and a fragment — it is fetched, not
dialed — so the shared config-address rule that other backends apply to
their route URLs is not applied here. Accepting those components is not
an invitation to authenticate with them: put no secret in a discovery
address, in userinfo or in a query token. Authentication belongs in the
declared credential fields, which are the only ones this plugin treats
as secret.

**Discovery and auth**

Connection setup is two-stage when `address` names a discovery root.
The plugin fetches `{address}/api/v1/auth-config` to learn which OIDC
issuer and client to authenticate against, then `{address}/api/v1/services`
to learn the gRPC endpoint. The services fetch is deferred to the first
RPC rather than run while the connection is being assembled, but that
first RPC still happens during connection setup — `instantiate`
discovers the address roots. The issuer's OIDC discovery document
(`/.well-known/openid-configuration`) supplies the auth/token/device
endpoints. A bearer-token interceptor wraps every outgoing gRPC call
with the current access token; expiry triggers an automatic
refresh-token grant against the discovered token endpoint.

The `grpc` value in the discovery response is interpreted per the
standard gRPC name-resolution scheme: `grpc://host:port` for
plaintext, `grpcs://host:port` for TLS. The plugin rewrites these to
tonic's native `http://` / `https://` internally and accepts those
schemes as direct equivalents. That applies to the values *inside a
discovery response*; an `http(s)` value in `address` itself always
names a discovery service, never a gRPC endpoint. A bare `host:port` (no scheme)
defaults to plaintext for local addresses (`localhost`, `*.local`,
loopback / private IPs) and TLS for everything else, so a public
domain typed without a scheme isn't silently downgraded. The
deployment guides in the vendored `ovstorage-services/` subtree
may use older wording around `http://` vs. `grpc://`; the rules
above are what this client actually applies.

### Stored credentials belong to one account

A stored refresh token is keyed on the discovery URL, the OIDC client,
and the connection's `persistence_id`, and it carries a record of the
identity — issuer, client, principal — the provider minted it for.
Warm continuation adopts a stored credential only after the sign-in it
drives authenticates as that same identity; a session that comes back
as somebody else is refused and the connection prompts for an
interactive sign-in.

Set `persistence_id` when two connections point at one discovery URL
and OIDC client but are meant for different accounts — for example a
personal and a service account on one deployment. Give each connection
its own value (`alice-work`, `ci-runner`). It is a durable key, not a
label: choose it once and leave it. Changing it moves the connection to
a fresh credential and requires signing in again, and it is deliberately
separate from `display_name` so renaming a connection never disturbs its
credential.

Where two connections without distinct `persistence_id` values are live
at once **in one process**, neither can tell which of them a stored
credential belongs to. Both then sign in interactively and neither
writes to the shared entry — including the write an interactive sign-in
itself performs — with a warning naming the key.

A connection that has shared its key with a sibling stays in that state
for as long as it is live, even after the sibling goes away: nothing it
does afterwards establishes whose the stored lineage was while both
existed. That holds for the newcomer too — a connection created onto a
key another one already holds is ambiguous from birth, and removing the
older connection does not promote it. Give the connections distinct
`persistence_id` values **and reconnect** to clear it.

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


That detection is process-local, and it is the only mechanism that
covers a missing `persistence_id`. Two applications running as one OS
user each see themselves as the sole claimant of a shared key, and the
stored identity record cannot separate them either: the second process
warm-continues on the stored lineage, so it authenticates as that
lineage's owner and verification passes. **Set `persistence_id` whenever
one discovery URL and OIDC client serve more than one account** — it is
the only discriminator that holds across processes.

A stored refresh token is keyed on the discovery URL, the OIDC client
and `persistence_id`, and the entry carries the identity record above.
An entry that cannot be attributed to an account is not adoptable: the
connection prompts for one interactive sign-in, after which the entry
is written and bound in place and warm continuation resumes. A record
naming
no identity at all is refused the same way, and never written: if a
deployment's provider issues opaque access tokens *and* its
`oidc_client_name` is empty, nothing about the account can be recorded,
so no credential is persisted and each start signs in again. Set
`oidc_client_name` to give the entry a durable lineage. A `persistence_id`
does not substitute here: it separates the keys, but the record stored
under each still has to name the account it belongs to.

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
a version address. The plugin maps the Layer precondition fields onto
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
  at the Layer boundary; the Storage API wire has no destination-must-not-exist
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

The etag is opaque to the Layer and is used only for optimistic
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
or rewrite version-pinning query parameters out of the returned URL.
The returned address is used whole, but it is not opaque: the host
canonicalizes it like any other address, so a server that returns a
non-canonical spelling is normalized rather than routed as a distinct
node. Two consequences for a caller: an address that survives may be
spelled differently from what the server sent, so comparing it byte-wise
against a server-side value breaks; and an entry the host cannot
canonicalize is omitted from a listing rather than failing the page it
appeared on. Each streamed version
becomes an `ObjectInfo` whose address is the returned version-pinned
`resource_address`, projected back into caller space by the host.

`get_latest_version` first calls `VersioningService.EnumerateVersions`
and chooses the latest item according to `versions_order`:
`NEWEST_FIRST` selects the first item, `OLDEST_FIRST` selects the last
item, `BY_KEY` selects the item with the greatest `sorting_key`, and
`UNSPECIFIED` returns `Unsupported`. If the service rejects the input
as an invalid version-enumeration address, the plugin treats it as an
already version-pinned resource address, stats that exact address, and
returns it unchanged.

**Layer-to-RPC mapping**

| Layer method | gRPC RPC |
|------------|----------|
| `instantiate` | `CapabilitiesService.ListTopLevelAddresses` (after HTTP service discovery, or directly against a configured gRPC endpoint) |
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
| `check_access` | `FileObjectService.Stat` to resolve the object, then `MetadataService.GetMetadata` for the `acl` user-metadata key (list of `read` / `write` / `admin` strings) |
| `watch_directory` | `EventConsumerService.ConsumeNonDurableEvents` (bidi stream, filter on `omni.storage.{,dir_}{created,deleted}`) |
| `watch_address_roots` | `CapabilitiesService.ListTopLevelAddresses`, single `Snapshot` (no delta feed today) |

**`user_metadata` on a write lands in a second stage, and the object
commits first.** The service's write RPC carries no metadata, so the
plugin writes the object, then issues one
`MetadataService.UpdateMetadata` per key — the same path
`WriteOptions.message` takes under the reserved `x-ov-message` key.

**A caller key that does not land fails the write with
`PartialCompletion`.** The error carries `ErrorContext::Partial` naming
`completed: ObjectData`, `failed: UserMetadata`, the failure's outcome,
and `rollback: RollbackEffect::DestroysRequestedWork` — undoing the
committed stage would destroy the very object the caller asked for — plus
a next-action string describing the remedy. It covers every way the
stage can fail: a metadata service that is unreachable or answers
`Unimplemented`, which takes all the keys with it, and any individual
key's refusal.

The object bytes are durable and correct at that point, so this is **not
retryable and a retry Layer must not replay the write**. What repairs it
depends on why the stage failed, and the outcome in `ErrorContext::Partial`
names which case you are in. A service that was unreachable, or an
individual key it refused, is worth re-applying with `update_metadata`.
An `Unimplemented` answer is not: the deployment does not serve that RPC,
so the same call fails the same way every time. There the choice is to
accept the object without those keys or to route to a deployment whose
metadata service exists — retrying is a loop.

Re-apply the keys with `update_metadata` where that applies, or re-read
them with a
full-metadata `stat` (the ordinary stat conversion leaves
`user_metadata` unset) to see which landed.

Two failures are deliberately not surfaced to the caller. A failure
confined to the reserved `ovstorage-` namespace — `ovstorage-modified-by`
and its neighbours — returns `Ok`, because those keys are the host's, not
the caller's. And a `WriteOptions.message` stash failure is discarded
entirely, because that field is droppable by contract. Both cases still
emit the operator warning, which carries the failed and attempted counts
over the whole map, a sample key, and a flag for whether attribution
itself failed.

Code that treats a non-`Ok` write as "the bytes did not land"
mis-handles `PartialCompletion` — under that code the bytes did land.

This matches the multi-stage durability rule, which requires a plugin
whose durability lands in stages to surface a final-stage failure even
though the earlier stage has committed. The built-in `file` backend
reports its own second stage the same way: its user-metadata sidecar is
staged and published after the bytes commit, and a publish failure
surfaces as `PartialCompletion` too.

It is a separate question from the capability-driven silent drop the
plugin contract forbids: this backend *does* support user metadata, and
a plugin whose backend cannot store it must refuse a non-empty map
rather than write without it.

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

**Redirect credential scope**

Both redirect paths — the `Redirect` frame the read stream interleaves,
and the `WriteRedirect` / `MultipartUpload` the write stream returns —
declare `RedirectScope.credential = unspecified`. Hosts treat that
exactly as `connection`: the redirect is not handed to a caller outside
the host process unless the operator has set
`redirect_credential_disclosure` to `allow`.

That is honest coverage rather than a gap this plugin is expected to
close. The redirect's URL and its `additional_headers` are copied
verbatim out of what the Omniverse Storage Service sent. The service
minted them against whichever cloud it federates to, and the wire says
nothing about their scope — a signature over the one object and an
`Authorization` header carrying the service's own credential arrive in
the same field. Declaring `request` would be a guess, and a wrong guess
in that direction hands out a credential; declaring `unspecified` costs
a proxied transfer instead, which is the failure worth having.

What it means in practice: under the default, a redirect-backed read
still returns its bytes — the host follows the redirect itself and
answers with a stream — while `write_redirect` is refused with
`Unsupported` so the body goes through the host, and a later round of an
already-started redirected write is refused with `PermissionDenied`.
Under `allow`, both are handed to the client with the service's headers
on them.

**ACL semantics**

The `acl` user-metadata key is a `ListValue` of permission tokens.
Mapping:

| Token | Layer ops granted |
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
the plugin keeps the descriptor defaults.

A connection configured with a direct gRPC endpoint does not advertise
`supports_watch_directory` at all, since the service that serves it
cannot be located without discovery.

For a discovery connection the `watch_directory_kinds` set is
`{created, deleted}` — the Omniverse
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

The statically-advertised bits describe what the **protocol** offers,
not what the connected deployment implements. A service that has not
implemented `FileObjectService.Copy` answers `Unsupported` even though
`supports_server_side_copy` is `true`, and only the two probed bits
above are negotiated per root. This is the general capability rule
(see [Capability vocabulary](../plugin-development/README.md#capability-vocabulary)),
not a defect specific to this plugin: `true` is not a guarantee, so
callers handle `Unsupported` from any advertised operation.

**Threat model**

Credentials live in `SecretBundle::oauth` and are redacted in
`Debug` output. The bearer-token interceptor is the only place the
plaintext access token is read *on the request path*; it's installed
into the `tonic::transport::Channel`'s request layer and not exposed
elsewhere in the plugin's API. The connection driver also decodes the
token during a grant, to check the identity a session authenticates as
against the one the stored credential is bound to. Operators who route private prefixes to this
backend must trust the Omniverse Storage Service's TLS configuration and the
OIDC issuer; the plugin does not pin server certificates beyond the
default rustls root-cert store.
