# S3 plugin (`s3`)

The `s3` plugin: a first-party `Backend` implementation against AWS S3
and S3-compatible object stores (MinIO, Cloudflare R2, Backblaze B2,
custom endpoints). Lives in
`ovstorage-cloud/ovstorage-plugin-s3/` and compiles as a cdylib
loaded through the C ABI declared by `ovstorage-plugin`. The plugin
uses the official AWS SDK for Rust (`aws-sdk-s3` / `aws-sdk-sqs`) for
SigV4 signing, endpoint resolution, and wire handling, and owns the
vendor response-header vocabulary so the host stays generic. Mints
`ReadResult::Redirect` and `WriteStep::Redirects` via SDK SigV4
presigning so bytes flow directly between S3 and the host; multipart
uploads use the native `CreateMultipartUpload` / `UploadPart` /
`CompleteMultipartUpload` flow.

> The SDK is configured with a rustls + ring HTTP client (the SDK's
> default `aws-lc` crypto is not pulled), static credentials only (no
> `aws-config` provider chain), SDK retries disabled (the host owns
> retry), and default request/response checksums off for
> S3-compatible-store compatibility. The shared S3/SQS connector reads the
> process-wide `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`
> environment when its connection pool is built; see
> [`../configuration.md`](../configuration.md#outbound-http-proxy).

## Public surface

- **Schemes**: `s3://<bucket>/<key>` is the canonical address shape.
  `parse_s3_address` also accepts `s3+minio://` for operators that
  routed that scheme, but the descriptor advertises only
  `kind = "s3"`. Provider-native HTTPS prefixes
  (`https://*.s3.amazonaws.com/`,
  `https://s3.<region>.amazonaws.com/...`) are not owned by this
  plugin; route them through `s3` only via explicit operator routing.
- **Descriptor**: `kind = "s3"`,
  `display_name = "S3-compatible object store"`,
  `supports_runtime_add = true`.
- **Config keys**:
  - `bucket` (**required**).
  - `region` (**required**).
  - `endpoint` (optional; required for `minio` and `b2` profiles, and
    for `custom`).
  - `compatibility_profile` (optional enum: `aws`, `minio`, `r2`,
    `b2`, `custom`; default `aws` unless `endpoint` is set — then
    `custom`). Picks the default addressing style and signing region
    per the matrix below.
  - `profile` (optional; named profile in the AWS shared credentials
    file).
  - `force_path_style` (optional bool, default `false`).
  - `force_request_payer` (optional bool, default `false`; threads
    `x-amz-request-payer: requester` through the SigV4 signed-headers
    set on direct calls, and returns it among the **request headers**
    of a `Read` redirect for the follower to re-send. On the anonymous
    public-bucket arm the plugin attaches the header itself, and S3
    honours it only as a header — a query placement is ignored and
    `403`s against a requester-pays bucket. So a consumer that takes
    only the redirect URL and drops the headers, such as a REST `307`,
    will `403`).
  - `sqs_queue_url` (optional; enables `watch_directory` when set).
  - `sqs_max_messages`, `sqs_wait_seconds`,
    `sqs_visibility_timeout` (SQS poll-loop tuning).
- **Credential keys**: `aws_access_key_id`, `aws_secret_access_key`,
  `aws_session_token`. All optional — absent fields fall through to
  the credential chain (env vars, shared credentials file).
- **Anonymous-fallback layer keys** (set on `[ovstorage.layers.<name>]`,
  never on a connection; see [Anonymous fallback](#anonymous-fallback)).
  None of them appears in the kind descriptor's `config_schema`, so
  `ovstorage connect` never prompts for one:
  - `anonymous_fallback` (TOML array of scheme strings; the only scheme
    this kind serves is `"s3"`; absent or `[]` is off, which is the
    default).
  - `anonymous_fallback_region` (optional; default `us-east-1`. The
    region a cold bucket's probe is sent to, and the region a bucket is
    taken to live in when no probe runs. It must have the shape of a
    region identifier — `[a-z0-9-]{1,32}` — because it becomes part of
    a hostname.)
  - `anonymous_fallback_endpoint` (optional URL; an explicit
    S3-compatible endpoint for every fallback bucket. Setting it skips
    the region probe, because the endpoint pins the host. It must be a
    bare `http` or `https` origin — scheme, host and port; one that
    embeds credentials or carries a path, query or fragment is refused
    at startup with `InvalidArgument` naming the key and the layer,
    never the value.)
  - `anonymous_fallback_compatibility_profile` (optional enum with the
    same five values as `compatibility_profile`; default `aws`, or
    `custom` once `anonymous_fallback_endpoint` is set).
  - `anonymous_fallback_force_path_style` (optional bool, default
    `false`; a bucket whose name contains a dot is addressed path-style
    regardless).
  - `anonymous_fallback_max_backends` (optional int, default `64`,
    between 1 and 100000; how many per-bucket anonymous clients stay
    resident).
  - `anonymous_fallback_mints_per_minute` (optional int, default `120`,
    between 1 and 1000000; how many clients may be built per sliding
    minute).

### Compatibility profiles

| Profile  | Addressing style       | Signing region        | Endpoint required |
| -------- | ---------------------- | --------------------- | ----------------- |
| `aws`    | virtual-hosted         | configured `region`   | no                |
| `minio`  | path                   | configured `region`   | yes               |
| `r2`     | virtual-hosted         | `auto`                | no                |
| `b2`     | path                   | `auto`                | yes               |
| `custom` | path (when configured) | configured `region`   | yes               |

`force_path_style = true` switches any profile to path style.

Presigned write redirects are replayed verbatim by the host follower:
every header named in `X-Amz-SignedHeaders` is echoed into the outgoing
request, and `Host` is derived from the redirect URL's authority
(host + port). Strict origins such as MinIO recompute the canonical
request from the wire and reject any deviation — including a missing
port — with 403 `SignatureDoesNotMatch`.

### Anonymous fallback

An `s3://<bucket>/<key>` address that no connection serves has nowhere
to go: the route scan misses and the caller sees `NoRoute`. The
`anonymous_fallback` layer key is the opt-in answer, off by default:

```toml
[ovstorage.layers.s3]
anonymous_fallback = ["s3"]
```

A granted layer publishes one extra address root beside its connection
roots: the bare scheme `s3:///`, `Hidden`, with no connection id,
read-only capabilities, the `Native` ranged-read strategy its connection
roots advertise, and the marker
`org.omniverse.ovstorage/scheme-fallback = "anonymous"` in its
`user_metadata`. The shared route table consults that root only after
every prefix has missed, so a configured bucket always outranks it for
its own authority, and only for an address whose query carries no
credential. On a hit the layer reads the bucket from the address,
synthesizes the same per-bucket config a connection would carry, and
builds an `S3Backend` with **no credentials provider** — see
[Auth](#auth) — keeping one client per bucket. Nothing is registered as
a `Connection`: `list_connections` never lists the fallback,
`ovstorage connect s3://public-bucket/` sees no incumbent, and adding a
connection for a bucket the fallback has been serving is not a
`RouteConflict`. The connection outranks the fallback the moment it
installs, the cached anonymous client for that bucket is dropped, and
removing the connection hands the bucket back to the fallback.
`root_info_for` on a fallback-served address returns the `s3:///` root
verbatim; `ovstorage list-routes` omits hidden roots, so the grant is
visible through `ovstorage doctor`, which lists the root with its
marker, and through the one `INFO` line the first build for a bucket
logs at target `ovstorage.fallback`, naming the bucket origin and its
region and never a key.

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
`InvalidArgument` naming the six accepted keys, a grant naming a scheme
this kind does not serve answers `InvalidArgument`
(`` `anonymous_fallback` on layer `s3` (kind s3) names scheme `gs`,
which this kind does not serve; it serves s3 ``), and a fallback
endpoint on a cloud instance-metadata host answers `PermissionDenied`.
A connection request — `ovstorage connect`, an
`[[ovstorage.connections]]` entry, or a probe — carrying any of these
keys is refused with `` `anonymous_fallback_region` is a layer key,
not connection config; set it on [ovstorage.layers.s3] ``, because a
fallback key on a connection would otherwise be ignored silently while
the operator believed it took effect.

**A fallback grants routability, never authority.** Policy sees the
caller's address, before routing and before alias resolution, so a
caller the [authorization policy](../authz-policy/README.md) does not
cover is denied before the fallback is consulted and no request leaves
the process on their behalf. No grant is ever generated for the
fallback — that would be automatic widening of a deny-by-default policy
— and a bucket-scoped rule does not cover `s3:///`: a rule on the bare
scheme (`prefix = "s3://"`) lists the hidden root and grants nothing on
any bucket.

## Auth

The plugin signs requests with the AWS SDK (SigV4 header signing for
direct calls, query/presign signing for redirect URLs). Credentials
are static keys only, resolved in order:

1. Explicit `SecretBundle` fields (`aws_access_key_id` +
   `aws_secret_access_key`, optional `aws_session_token`). The pair
   is required together; surfacing only the access key ID returns
   `AuthRequired`.
2. Environment variables: `AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`. The
   connection's own `region` config wins inside the signer regardless
   of `AWS_REGION`. `AWS_PROFILE` and `AWS_SHARED_CREDENTIALS_FILE`
   set defaults for the file step.
3. Shared credentials file. Default `~/.aws/credentials` (OS home
   variants), overridable via `AWS_SHARED_CREDENTIALS_FILE`. Profile
   resolution: connection's `profile` config field, then
   `AWS_PROFILE`, then `default`. Both `[profile name]` and `[name]`
   section headers are tolerated.

Resolution failures surface as `ErrorCode::AuthRequired`. There is no
interactive flow to drive, so `authenticate_connection` answers
`ErrorCode::Unsupported` rather than an auth-event stream: credentials
arrive with the connection or through `update_connection_credentials`.
Secret bytes are never logged.
IMDS, AWS SSO, web-identity tokens, and STS role assumption are
**not** implemented in-process — operators run `aws sso login` (or
their session helper) to materialise a static-key profile.

The cross-plugin
[credential-provider matrix](credential-providers.md)
distinguishes direct shared-credentials-file support from ambient chains that
a host resolves into the temporary access-key / secret / session-token bundle
this plugin accepts.

With no credentials resolved from any source, the connection is
**anonymous** (public-bucket access). S3 evaluates an unsigned request as
the anonymous principal, and this plugin issues these read-side
operations that way:

- `read` emits a plain, unsigned redirect URL;
- `list`, `stat`, `list_versions`, `get_latest_version` and `check_access`
  go to the store unsigned and succeed exactly as far as the bucket's
  public-access controls allow — typically `s3:GetObject` and `s3:ListBucket` granted
  to `*`. `list_versions`, and `list` with `ListOptions::versioned_address`
  set, need `s3:ListBucketVersions`, which is a separate grant and rarely
  public; a flagged `list` on such a connection answers the wire's denial
  rather than a listing.

A bucket reached through the [anonymous fallback](#anonymous-fallback)
is served exactly as an anonymous connection is, and its anonymity is
structural rather than circumstantial. The three resolution steps above
run for a connection — an `[[ovstorage.connections]]` entry, `ovstorage
connect`, or a layer table that seeds one — and the fallback never runs
them: its client is built from a literal empty bundle with no
credentials provider registered, so the environment variables, the
shared credentials file, IMDS, and any `${ENV}` placeholder a host
expands into a connection's credential fields are unreachable by
construction, however the process is configured. `read` emits the same
unsigned redirect declared `none`; `list`, `stat`, `list_versions`,
`get_latest_version` and `check_access` go to the store unsigned; a
store that refuses answers `PermissionDenied` naming the unsigned
request; and the remedy is a connection for that bucket with
credentials, which takes the bucket over from the fallback as soon as
it installs.

`list` follows `NextContinuationToken` to the end of the prefix, so a
listing is the whole prefix rather than its first 1000 keys. A direct
`S3Backend` caller that supplies `max_results` gets exactly one request
instead — a bound, not a cursor: `list` returns no continuation token, so
there is no way to ask it for the next page. Through the Layer nobody
takes that branch, because `S3Layer::list` asks the backend for the full
set and paginates host-side over its own token space.

**An unbounded listing is capped at 100,000 entries and 1000 responses.** The whole listing is
assembled in memory before the first entry is returned — budget roughly
half a kilobyte per entry and one sequential round trip per up to 1000
entries (the service page size, which counts `CommonPrefixes` too) — so
`list` with `recursive: true` on a bucket root asks for every object
beneath it. Past either budget — 100,000 entries is roughly 50 MB — the call answers
`Internal` naming the one that was hit.

The budgets are checked on the edge that would fetch **another** page, so a
listing the store has already declared complete is returned rather than
discarded for finishing one page over. What that does not do is make a
large prefix listable: a store with more to send is still offering a
continuation token when the check runs. And completeness is not unlimited
licence — a single response that carries the total past 101,000 entries
(the budget plus one full page) is refused whatever it claims, because a
store ignoring the requested `max-keys` is exactly the store the budgets
exist for and the Layer would re-allocate that set twice more. That
ceiling applies to a direct `S3Backend` call with `max_results` as well:
the bound is on the request, and only the store decides how large a
response actually is.

It never truncates. A short listing that reads as complete is what turns a
present object into a missing one through the metadata cache, so the cap
refuses rather than shortens.

**The code is `Internal`, and the deciding fact is the retry.**
`ResourceExhausted` is the accurate name — a resource this backend bounds
was exhausted — but retryability here is exactly bucket membership, that
bucket is retryable, and the shipped broker graph composes the retry Layer
above the router at five attempts. A budget is a fixed local bound: the
same request reaches it every time, so retrying re-walks the whole prefix
to fail identically, and a ~150,000-object bucket would cost roughly 500
`ListObjectsV2` requests and ~250 MB rather than ~100 and ~50 MB. There is
no code that both names exhaustion and stays out of the retryable buckets,
so this reports the backend giving up: `Internal`, which the error-code
table in [CONFORMANCE](CONFORMANCE.md) names for a plugin's own hard bound
as well as for a plugin bug, and which the CLI's and MCP's identical
100,000-entry caps also use. Over HTTP that is `500` and the `ovstorage`
CLI exits `1`.

There is no parameter for the caller to correct either: `S3Layer::list`
hard-sets `max_results` to `None`, so a caller's own `max_results` slices
the answer without bounding the walk; what a caller has is the remedy
below rather than an argument.

**Doing the work and discarding it is the defect underneath this**, and the
cap is a stopgap rather than the answer: 100 requests and 50 MB are spent
before the refusal, and the caller gets nothing. `list` returning what it
has with a continuation token, or streaming, is what removes that — both
change the Layer/backend pagination contract, so neither is
implemented.

The default `ListOptions` is
non-recursive, which bounds a listing by one directory's fan-out and stays
far below the cap; a caller that hits it should narrow the prefix or walk
directories, or use a direct `S3Backend` call with `max_results` when a
bound matters more than a single answer.

**The case with no remedy is a single directory level holding more than
101,000 direct children** — the budget plus the one page of overshoot a
completed walk is allowed, so a level of exactly 101,000 still lists.
Narrowing is not available above that, since there is nothing narrower
than one level, `S3Layer::list` sends no `max_results`, and the budget is
a constant rather than a config key, so an operator cannot raise it
either. Serving the shape properly needs two things: `S3Backend::list`
returning a native continuation cursor — which `S3Layer::list`'s own
comment records as a deferred behaviour change — and the Layer not
folding directory markers over the whole set before it paginates, which
is the reason it asks for the whole set. Neither is implemented.

The 1000-response budget is the second half of the same guard: a store
that answers empty pages with a fresh continuation token grows no entries,
so an entry budget alone would never end the walk. Ten times the ~100
responses a full entry budget needs, so genuinely sparse pages are not
refused for being sparse.

`list_versions` reads one native page, and above the Layer a caller
cannot page it at all: `S3Layer::list_versions` always returns
`next_page_token: None`. Neither behaviour is a property of anonymity —
both are identical on a credentialed connection.

Every mutation — `write`, `write_stream`, `write_redirect`,
`continue_write`, `delete`, `copy`, `rename`, `create_directory`,
`delete_directory`, `update_metadata` — answers `Unsupported` without
reaching the wire. That is a deliberate refusal rather than a protocol
limit: S3 would accept an unsigned `PutObject` against a bucket that
grants it publicly, ovstorage does not issue one, and such a bucket is a
misconfiguration to repair. `watch_directory` is `Unsupported` for the
same kind of reason rather than a protocol one — an SQS queue policy can
grant `sqs:ReceiveMessage` to `*` just as a bucket policy can grant
`s3:GetObject` — but the anonymous constructor builds no SQS client for
the watch to poll with.

Through the fallback the same refusal carries its own message —
`this address is reached through the anonymous s3:// fallback, which is
read-only` — and a `next_action` naming the bucket root the operator
would configure a connection for (`add a connection for
s3://public-bucket/ with credentials to modify it`), never the caller's
key. `copy` and `rename` check both ends and refuse when either is
fallback-served, naming that end, so a copy from a configured bucket
into a public one is refused before the source is read. The `s3:///`
root advertises the refusal honestly: its capabilities are the
anonymous set lowered to its read side — every write, delete, copy,
rename, directory-mutation, metadata-patch and watch bit false;
`supports_list`, `supports_list_stream`, `supports_recursive_list`,
`supports_version_listing` and `supports_access_check` true. An
anonymous connection you configured keeps the bits described in this
section; the fallback is the one shape that withholds them, because it
serves buckets nobody configured.

`supports_access_check` **is** advertised, as it is for a credentialed
connection. An anonymous connection advertises whatever a credentialed
one does, minus what it genuinely cannot do. That is a policy rather than
a contract requirement: the Layer's self-gate rule constrains the pair, so
withholding the bit and refusing the slot locally conforms equally — the
Azure plugin does that with `supports_access_check`, though for every
connection rather than only anonymous ones. Only the half-measure, a false
bit in front of a slot that still runs, is forbidden. `check_access`
is in fact more accurate here than on a credentialed connection — it
reports the mutating operations denied, because they are refused before
the wire — but on both shapes the decision comes from a single probe
rather than from each requested permission separately.

A bucket that grants anonymous `s3:GetObject` but not `s3:ListBucket` is
an ordinary configuration, and there `read` works while `list` is refused
by S3 itself. That surfaces as `PermissionDenied` naming the unsigned
request rather than as `AuthRequired`, because an anonymous connection has
no credential to be wrong. (The one anonymous path that can still produce
`AuthRequired` is `read`: it hands the host an unsigned URL to follow, and
a `401` on that request is mapped by the redirect follower, not here.) Its
`next_action` says to **remove and re-add the
connection** with credentials, or to grant the action to anonymous
callers in the public-access controls covering the bucket: attaching
credentials to a connection that was added without them is refused, since
the backend was built with no signing client.

## Redirect credential scope

Every redirect this plugin mints declares what its credential authorizes,
on `RedirectScope.credential`. A host reads that declaration to decide
whether the redirect may be handed to a caller outside its own process:
it cannot recover the answer by inspecting the redirect, because a
signature scoped to one object and one scoped to an account look
identical on the wire.

| Mode | Declares | What the party executing the redirect holds |
|---|---|---|
| Anonymous read (public bucket) | `none` | A plain, unsigned object URL. It carries no credential, so handing it over discloses nothing the holder of the address did not already have. |
| Credentialed read | `request` | A SigV4 query presign over this bucket, this key, `GET`, and whatever the caller pinned (`versionId`, `If-Match`, request-payer). It carries the access-key id and never the secret, and it stops working when the 5-minute presign window (`DEFAULT_PRESIGN_TTL_SECS`) closes. |
| `write_redirect`, single presigned `PutObject` | `request` | A SigV4 query presign over this key and `PUT`, expiring on the same 5-minute window. |
| `write_redirect`, presigned `UploadPart` per part | `request` | One presign per part, each naming this key, this upload id and one part number, expiring on the same window. |

No arm of this plugin puts the connection's own credential on a
redirect: everything it hands out names the object it is redirecting to
and dies with the presign. So under a host running the default
`redirect_credential_disclosure = "refuse"`, S3 redirects are delegated
to the client on both the read and the write path — there is
nothing broader for the policy to withhold.

The demotion rule costs a redirect rather than disclosing anything. A
host lowers a request-scoped declaration to connection-scoped when the
redirect carries a header it does not recognise as inert to the
transfer, so a wrong declaration proxies bytes instead of leaking a
credential.

Everything this plugin's redirects carry is inert, so its `request`
declarations survive that check and the redirects stay delegable. The
headers are whatever the AWS SDK signed and echoed back for the follower
to re-send verbatim — `host`, the conditional headers, `x-amz-meta-*`
when the write carries `user_metadata`, `x-amz-checksum-*` when it
carries a checksum, and `x-amz-request-payer` on requester-pays buckets.
The two families with open-ended suffixes are matched by prefix, because
their last segment is a caller's metadata key or an algorithm name
rather than something a host can enumerate.

## URL handling and version-pinned addresses

Native addresses are `s3://<bucket>/<key>`. The configured `bucket`
pins the bucket; addresses whose URL bucket disagrees are rejected
with `InvalidArgument` before any signing happens.

**The key is the decoded path.** `s3://bucket/pub%20x` names the key
`pub x`, and a key containing a literal `%` is spelled `%25`, so
`s3://bucket/100%25` names `100%`. Trailing dots and other escaped bytes
round-trip. A key containing a dot segment or a doubled separator cannot
be named by an address at all: it is omitted from listings with a
`warn!` rather than handed out as an address that resolves to a
different object. A key whose bytes are not valid UTF-8 has no S3 wire
spelling and is rejected with `InvalidArgument`.

An address carrying a port is rejected: the matcher ranks
`s3://bucket:443/x` and `s3://bucket/x` as two scopes, so the backend
must not resolve them to one bucket.

With `anonymous_fallback = ["s3"]` on the layer, an address naming a
bucket that no connection pins is routed to the
[fallback](#anonymous-fallback) rather than left at `NoRoute`. The
fallback reads the bucket from the address exactly as `parse_s3_address`
does, so every key rule above applies unchanged. What it does not extend
to is deliberate. `s3+minio://` is a different scheme and the scheme
root is scheme-exact, so `s3+minio://public-bucket/key` stays
`NoRoute`. The scheme root itself and any hostless address — `s3:///`,
`s3:///key` — name no bucket and answer `InvalidArgument` (`an s3://
address names no bucket`) on every slot, mutations included. An address
whose query carries anything outside the shared carried-query allowlist
— the version selectors `versionId`, `versionid`, `generation` and
`revision` — never reaches the fallback and answers the byte-identical
`NoRoute` an ungranted layer gives: a presigned URL (an `X-Amz-Signature`,
an `X-Amz-Credential`) authenticates itself, and re-serving it anonymously
would silently discard the authority the caller presented, while
`s3://public-bucket/key?versionId=7` routes and is honoured on the wire
(the other selectors route as well; S3 reads only `versionId`).
A bucket whose name contains a dot is addressed path-style
whatever `anonymous_fallback_force_path_style` says, for the reason the
next section gives: its virtual-hosted name falls outside AWS's wildcard
certificate.

### Generated URL spellings

`s3://<bucket>/…` is the connection's only canonical address form; the
ordinary HTTPS spellings of the same data are the **alias layer's** job. So
that an operator does not have to author them, each connection advertises
the URL prefixes it accepts as alternate spellings of its root
(`org.omniverse.ovstorage/accepted-url-spellings` on its connection row),
and an alias layer composed above installs one **hidden** alias rule per
spelling at registration — addressable, never advertised, withdrawn with
the connection. See "Generated aliases" in `docs/public/configuration.md`
for the alias-layer and authorization semantics — including that a
generated rule declines a presigned URL rather than re-serving it with this
connection's credentials.

The spellings are a property of a connection, so the
[anonymous fallback](#anonymous-fallback) generates none:
`https://public-bucket.s3.amazonaws.com/key` for a bucket no connection
pins is an ordinary HTTPS address and stays `NoRoute` under a granted
layer, while `s3://public-bucket/key` routes.

For the `aws` profile with no explicit endpoint in the **commercial**
partition, the set is the six public shapes (`<sfx>` is `amazonaws.com`):

- `https://<bucket>.s3.<region>.<sfx>/` — virtual-hosted, regional
- `https://<bucket>.s3.<sfx>/` — virtual-hosted, global
- `https://<bucket>.s3-<region>.<sfx>/` — virtual-hosted, legacy dashed
- `https://s3.<region>.<sfx>/<bucket>/` — path-style, regional
- `https://s3.<sfx>/<bucket>/` — path-style, global
- `https://s3-<region>.<sfx>/<bucket>/` — path-style, legacy dashed

Outside the commercial partition the two **global** (region-less) shapes are
withheld, leaving four: China (`<sfx>` becomes `amazonaws.com.cn`),
GovCloud, and the isolated partitions get the regional and legacy-dashed
forms only. `s3.amazonaws.com` is a commercial endpoint that does not route
into those partitions, and S3 bucket names are unique only *within* a
partition — so accepting the global form there would alias a URL naming a
different bucket, quite possibly someone else's, onto this connection, and
would stretch an HTTPS-prefix authorization grant written for the
commercial bucket over this one's data.

The legacy dashed form is deliberate — AWS no longer issues it, but it is
still in wide circulation (including NVIDIA's own published content URLs) —
and it is generated in every partition because it is region-scoped: where
it was never issued it is a rule no request can match, which is dead rather
than wrong, and that is precisely what the global form is not. It matches
`s3-<configured region>` **exactly**, never a wildcard, so
`s3-website-…`, `s3-accesspoint-…`, `s3-fips-…` and whatever AWS introduces
next can never be captured. A bucket whose name contains a dot gets only
the three path-style shapes: its virtual-hosted host is multi-label and
falls outside AWS's wildcard certificate, so the HTTPS spelling never
fetches and is not a URL a user could be holding. Explicit-endpoint
profiles (MinIO, B2, custom, or any profile with `endpoint` set) generate
exactly the one shape the endpoint configuration describes —
`<scheme>://<host>/<bucket>/` under path-style addressing,
`<scheme>://<bucket>.<host>/` otherwise — and R2 generates that shape on
its fixed `r2.cloudflarestorage.com` suffix. An endpoint's **path** never
reaches a spelling: the derivation keeps `host[:port]` and nothing else,
so a capability token carried as an endpoint path prefix is not published
in the connection metadata an introspection-only caller can read.

A generated spelling names exactly the address its canonical `s3://` form
names. Every request is normalized the same way at the address boundary
whatever spelling it arrived under, so the key rules above apply
unchanged: `https://<bucket>.s3.<region>.<sfx>/a//b` reaches the same
object `s3://bucket/a//b` does, which is the key `a/b` — a key containing
a doubled separator is not nameable under any spelling, and is dropped
from listings with a `warn!` rather than handed out. Generating a spelling
adds a way to write an address, never a different rule for which object it
selects.

Deliberately excluded: transport variants (dualstack, FIPS, transfer
acceleration — nothing in this repository constructs such an endpoint, and
they are not universally valid), and different resources rather than other
spellings (access points, multi-region access points, S3 Express directory
buckets, VPC endpoints, Outposts). The membership test for any future shape
is *"what URL could a user plausibly be holding?"*, not "what can the SDK
emit".

`?versionId=...` is the only recognised version pin. `read`,
`stat`, `delete`, `copy(source)`, `update_metadata(source HEAD)`,
`get_latest_version` and `check_access` honour it on the wire so the
request reaches the pinned historical version. `list_versions` does
**not**: it enumerates versions of a prefix, and the only pin-bearing
input it reads is its own `page_token`, which it splits into S3's
`key-marker` / `version-id-marker` pair. Mutating ops whose wire format cannot
carry a version pin — `write`, `write_stream`, `write_redirect`,
`continue_write`, `copy(destination)`, `rename(both endpoints)`,
`update_metadata(destination)` — reject any pinned `?versionId=` with
`InvalidArgument` rather than silently writing to head.

`ObjectInfo.versioned_address` is this pin as the plugin spells it:
`s3://<bucket>/<key>?versionId=<id>` whenever S3 reports an
`x-amz-version-id`. `stat` reports it for free from the `HeadObject`
response, echoing a caller's own `?versionId=` pin; `list` reports it only
under `ListOptions::versioned_address`. The literal `null` id of an
unversioned or suspended bucket is not a pin, and directory kinds carry
`None`. Writing through a returned pin is refused exactly as above.

## Region discovery for fallback buckets

A connection carries its `region`; a fallback bucket carries nothing but
its name, and S3 serves a bucket only from the region it lives in. So a
cold bucket costs one unsigned `HeadBucket`, sent to
`anonymous_fallback_region` (default `us-east-1`). S3 stamps
`x-amz-bucket-region` on the answer — on a `200`, on the `301` it gives
a request that reached the wrong region, on a `400`, and on the `403` a
bucket that grants the anonymous principal no `HeadBucket` returns — and
the fallback reads the header off whatever status came back. The value
is admitted only when it has the shape of a region identifier
(`[a-z0-9-]{1,32}`), because it becomes part of a hostname; a malformed
value is treated as absent, and no header on a `2xx` or `4xx` means the
bucket is taken to live in the default region, because the store judged
the bucket from there. A `3xx` naming no region is a failed probe, not a
verdict: a redirect says the bucket is served from somewhere else, which
is the opposite of the default, so it teaches nothing (AWS always names
the region on its `301`; a compatible store that does not has said only
that it does not know). The learned region is cached per bucket for
the life of the layer and survives eviction of the bucket's client: a
region is a fact about the bucket, not about who serves it, so a bucket
handed back to the fallback after a connection is removed is rebuilt
without another probe. When the probe's region is the answer, the
probe's own client is kept, so a bucket in the default region pays for
one client rather than two. A region can still be learned wrongly — the
probe was answered without one and the default taken, or the bucket
moved — and the store's own data-path `301` is the correction, applied
only when it can change what is built: when the `301` names a valid
region other than the one the backend was built for, and no endpoint is
pinned, the learned region is replaced by the named one and the next
touch of that bucket rebuilds it for that region, once, without another
probe. Any other `301` leaves the cached backend in place and reaches
the caller as the `InvalidArgument` described below. One naming the
region already built for contradicts itself; one naming no region says
only "not here", so it drops the learned region — a later miss probes
afresh — without a rebuild, because a probe that already answered
without a region would teach the same default again. Nothing is evicted
or charged on those paths: the mint budget is layer-wide, the verdict
on a backend is permanent, and an eviction that rebuilt the same
backend would recur on every touch of the bucket for the life of the
layer.

A `404` is `NotFound` — the bucket does not exist — and is **not**
cached, because the bucket may be created later and each retry is
bounded by the mint budget anyway. A probe the store did not judge — a
timeout or connection failure, a `429` or `5xx` that shed the request,
a `3xx` naming no region — is negative-cached for 60 seconds and teaches
no region; until the window passes the bucket answers
`ResourceExhausted` (`the region probe for this bucket failed recently;
it is not sent again for another N s`) with the `next_action` `retry
after ~N s, or add an explicit connection for the bucket`. That refusal
is answered before the mint cache is entered, so it sends nothing and
charges nothing, and a retry wrapper that replays it burns neither
budget nor wire. With `anonymous_fallback_endpoint` set no probe runs:
the endpoint pins the host, the region reaches the wire only through a
SigV4 scope an unsigned request has none of, and every fallback bucket
is built for `anonymous_fallback_region`; a `301` met there surfaces as
`InvalidArgument` and nothing is rebuilt, because no region the answer
could name would change the client. Every build attempt, including one
that fails or is cancelled, is charged against
`anonymous_fallback_mints_per_minute`; a negatively-cached refusal is
not a build attempt and is not charged.

The region mapping is the same for every connection, and it is where a
wrong `region` surfaces. **A `301 PermanentRedirect` on any S3
connection is `InvalidArgument`** — `S3 answered HTTP 301
(PermanentRedirect): the bucket is not served from the configured
region` — carrying a `next_action` whenever the response names the
region in `x-amz-bucket-region`, and it is not retried: every replay
reaches the same endpoint and earns the same `301`, so a `Transient`
here would have the retry Layer replay a configuration mistake. The
`next_action` names the setting the operator can reach: `set region =
"<region>" on this connection` on a connection backend, and on a
fallback backend, which has no connection to set it on, `set
anonymous_fallback_region = "<region>" on the layer, or add a connection
for s3://<bucket>/ with region = "<region>"` — the layer key moves every
cold bucket's probe, the fix when one endpoint has one region, while a
connection pins this bucket alone and outranks the fallback the moment
it installs. A `400` carrying the modeled code
`AuthorizationHeaderMalformed` is the SigV4 spelling of the same
mistake and maps the same way. A `307 TemporaryRedirect` is
`Transient`: S3 answers it for a bucket in the minutes after its
creation, while the bucket's DNS name still resolves elsewhere, and it
clears on its own.

## Layer-to-API mapping

| Layer method | S3 API |
|---|---|
| `instantiate` | (no remote call; AWS SDK client setup) |
| `stat` | `HeadObject` (forwards `?versionId=…` pin; parses `ETag`, `Content-Length`, `Last-Modified`, `x-amz-version-id`, `x-amz-checksum-*`, `x-amz-meta-*`, system `x-amz-*` headers). A present `x-amz-version-id` other than the literal `null` is also spelled into `versioned_address` as `?versionId=…`, whatever `StatOptions::versioned_address` says; a caller's own pin is echoed; directory kinds carry `None`. |
| `read` | Presigned `GetObject` (SigV4 query auth, 5-min TTL). `ReadOptions.if_match` (etag) is folded into the SigV4 signed-headers set, so a holder of the URL cannot drop or alter it without invalidating the URL. `ReadOptions.range` is deliberately **not** signed: the plugin validates the requested range and then discards it, because the host injects `Range:` itself before following and a signed duplicate would break the SigV4 header set (403 `SignatureDoesNotMatch`). An unsigned `Range` on a presigned GET is honored by S3, so the "cannot drop or alter" guarantee covers `if_match` and does not cover `Range` — a holder of the URL chooses its own slice. Returns `ReadResult::Redirect` with `ResponseParsing` for ETag, version, size, mtime, and S3 system metadata. |
| `write` (Body::Bytes) | Direct `PutObject` through the plugin's signed client. `WriteOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`); `Overwrite` sends neither. |
| `write_redirect` | Known-size `size_hint >= 100 MiB` → `CreateMultipartUpload` + one presigned `UploadPart` redirect per part. Planning targets 32 MiB parts, then clamps to S3's 10 000 parts / 5 GiB-per-part / 5 TiB-per-object limits; otherwise a single presigned `PutObject` redirect. `If-Match: <etag>` (from `IfDestExists::MatchEtag`), `If-None-Match: *` (from `IfDestExists::Fail`), and `x-amz-meta-*` are signed into the request. |
| `continue_write` | `CompleteMultipartUpload` (or no-op for the single-PUT path). On any failure (terminal CMU failure, missing per-part ETag) the plugin issues a best-effort `AbortMultipartUpload` so failed commits don't leak staged parts. |
| `write_stream` | Chunk-by-chunk direct signed `UploadPart` calls (8 MiB parts, no `Vec<u8>` materialisation). Used for unknown-size `Body::Stream` writes. |
| `delete` | `DeleteObject`; `DeleteOptions.if_match` (etag) → `If-Match`; `?versionId=…` propagated as a query parameter. |
| `list` | `ListObjectsV2` with `prefix`, optional `delimiter=/`, `max-keys`, `continuation-token`, repeated until `NextContinuationToken` is absent (a `max_results` request is a single page instead). Real objects return `ObjectInfo` with `ObjectKind::File`; zero-byte keys ending in `/` return `ObjectInfo` with `ObjectKind::DirectoryMarker`; `CommonPrefixes` become `ObjectInfo` values with `ObjectKind::DirectoryInferred`. If S3 reports the same address as both a marker object and a common prefix, the marker wins and only one item is emitted. With `ListOptions::versioned_address` set, the walk uses `ListObjectVersions` with the same `prefix` / `delimiter`, keeps only `IsLatest` versions (a key whose newest entry is a delete marker has none and is omitted, exactly as `ListObjectsV2` omits it) and pins every `File` item with `?versionId=…`; `CommonPrefixes` and markers stay `None`. Each `CommonPrefixes` entry is verified with one `ListObjectsV2` probe (`max-keys=1`, no delimiter) and dropped when no current object lives under it, so the flagged and unflagged listings agree on which directories exist. `MaxKeys` counts every version and delete marker, so a page can carry fewer items than requested and the 1000-response budget is reached sooner on heavily versioned prefixes; a delimited page costs one request plus one probe per common prefix. The grants are `s3:ListBucketVersions` for the walk and `s3:ListBucket` for the probes, and a connection without them answers the wire's denial rather than falling back. With the flag clear, `versioned_address` is `None`. |
| `list_versions` | One `ListObjectVersions` request, resuming from `key-marker` / `version-id-marker` when the backend is handed a page token. It does **not** walk to the end on its own, so a call returns one native page. The Layer above it always answers `next_page_token: None`, so a caller cannot obtain a token to resume with; the `<key-marker>\|<version-id-marker>` encoding is the backend-level form. Each version returns an `ObjectInfo` whose address carries `?versionId=…`, and `versioned_address` equal to that address; the literal `null` version of an unversioned bucket selects mutable content, so its entry carries `None`. Newest-first order; delete markers are not surfaced as version items. |
| `get_latest_version` | `HeadObject` (returns `ObjectInfo` for the head with its current `?versionId=…` address, or for the pinned `?versionId=…` address; `versioned_address` equals that address, or `None` when the id is the literal `null`). Unversioned buckets return `Unsupported`. |
| `create_directory` / `delete_directory` | Zero-byte marker object at `<key>/`; `delete_directory` removes only the marker (recursive directory delete is host-side composition). |
| `copy` | `CopyObject` with `x-amz-copy-source: /<bucket>/<percent-encoded-key>[?versionId=…]`. `CopyOptions::if_source` (etag) maps to `x-amz-copy-source-if-match`; `CopyOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`). |
| `rename` | Copy-then-delete. **No rollback** of the destination on delete failure; surfaces `CommitAmbiguous` reporting that the destination committed but the source delete failed. |
| `update_metadata` | Self-copy with `x-amz-metadata-directive: REPLACE`. The plugin HEADs first (honouring `?versionId=…`), merges existing `user_metadata` with `user_metadata_remove` / `user_metadata_set`, and emits the merged set. Gated on `UpdateMetadataOptions.allow_rewrite_emulation = true`. |
| `check_access` | `HeadObject` for an object target. For a bucket target: `GET ?policyStatus=` on a credentialed connection, a bounded `ListObjectsV2` on an anonymous one (essentially no anonymous caller holds `s3:GetBucketPolicyStatus`, so probing with it would report a fully public bucket unreadable). `200` → `allowed: true`, except that an anonymous connection reports any requested `write` / `delete` / `update_metadata` in `denied_ops` — and `allowed` is then `false`, since not everything asked for is permitted — because those are refused before the wire. `401`/`403` → `allowed: false` with every requested op denied, returned as a successful decision rather than an error. `404` → `NotFound`. The object probe resolves the address's own shape first: a `?versionId=` address pins the `HeadObject` to that version, and a `key/` address whose marker object is absent falls back to the same bounded prefix probe `stat` uses, so a `DirectoryInferred` address this backend's own `list` returned is not reported missing (a refused fallback answers `allowed: false` rather than `NotFound`). The decision comes from one probe rather than from each requested permission separately. |
| `watch_directory` | `ReceiveMessage` / `DeleteMessageBatch` via `aws-sdk-sqs` against `sqs_queue_url`. Resumable cursor is intentionally empty. |

### Metadata keys

S3 stores `user_metadata` as `x-amz-meta-<key>` headers, so any HTTP
header token is a valid name, hyphens included. The plugin lowercases
every key before it sends a `PutObject`, a `CreateMultipartUpload` or
a presigned redirect, and S3 returns names lowercased on `HeadObject`
regardless, so `Author` and `author` are one key on this backend and a
mixed-case name comes back in lowercase. Names inside the portable
subset of [User-metadata keys](CONFORMANCE.md#user-metadata-keys) are
lowercase by construction and round-trip unchanged; the reserved
`ovstorage_` names sit inside it. The per-operation `message` on a
buffered, streaming or presigned write and on `update_metadata` is
stored in the same headers under `x_ov_message`, beside the caller's
keys; a message that is not a legal header value, one carrying a line
break for instance, is dropped and the call proceeds without it. `copy`
and `rename` go through `CopyObject` with the source's
metadata copied verbatim, annotation included, and do not record the
message they carry.

## Streaming guarantees

`write` with `Body::Bytes` PUTs directly (zero-byte payloads
included), skipping the redirect round-trip. `Body::Stream` writes go
through `write_stream`'s chunk-by-chunk `UploadPart` loop — the host's
chunks reach the signed client one-by-one through a bounded path; no
full-body buffering happens at the plugin boundary. Range reads are
served by the presigned URL itself, with `Range:` supplied unsigned by
whoever follows the redirect: the SigV4 binding covers the object, the
method and the expiry, not the slice, so a follower or proxy can widen
the range without invalidating the URL.

Multipart finalisation parses the `CompleteMultipartUpload` response
defensively: S3 can return HTTP 200 with an embedded `<Error>` body,
so the plugin checks for that envelope first and maps known codes:
`InternalError` / `ServiceUnavailable` / `SlowDown` / `RequestTimeout` /
`OperationAborted` → `Transient`; `PreconditionFailed` →
`PreconditionFailed`; `InvalidPart` / `InvalidPartOrder` /
`EntityTooSmall` → `ObjectModified`, these being terminal commit failures
rather than retryable ones; any other modeled code → `Internal`, since a
modeled code on a 2xx status must not fall through to the status
mapping and be reported as `Transient`.

## Capability bits

The plugin advertises (true):
`writes_are_atomic` (single PUT atomicity; multipart commits atomically
at `CompleteMultipartUpload`), `supports_no_overwrite_write` (via
`If-None-Match: *`), `supports_if_match_write` (via `If-Match`),
`supports_server_side_copy`, `supports_copy`, `supports_rename`
(availability: the plugin owns the copy-then-delete dance, so
`supports_server_side_rename` and `supports_atomic_rename` are both
false — there is no S3-side rename primitive),
`supports_recursive_list`, `supports_list` (delimiter `/`),
`wants_list_backed_stat`, `supports_version_listing` (with
`version_list_order = Some(Newest)`),
`supports_metadata_rewrite_emulation`, `supports_access_check`,
`supports_watch_directory` (only when `sqs_queue_url` is configured;
`watch_directory_resumable = false`, all four change kinds advertised,
`watch_directory_max_lag = 60s`).

Not advertised (false):
`supports_atomic_rename`, `has_real_directories`,
`populates_subdirectory_metadata`, `supports_native_metadata_patch`
(S3's `PUT ?metadata` does not exist; metadata patches are
self-copy emulations).

Per-bucket capability downgrades (versioning disabled, conditional
writes denied by IAM, etc.) are not probed; operators who need that
fidelity split mixed buckets into separate connections.

**Enforcement**

- `if_match` (read / delete / update_metadata), `if_source` (copy /
  rename), and `IfDestExists::MatchEtag` (write / copy / rename) all
  accept an opaque etag string. S3's wire carries it as `If-Match` /
  `x-amz-copy-source-if-match`.
- S3 object etags are normalized into opaque tokens with
  `normalize_wire_etag`. A conformant nonempty quoted etag is declared
  `Strong`; an explicit `W/` marker is preserved out of band as `Weak`; and a
  bare or malformed unmarked value is `Unspecified`.
- Streaming writes with unknown size route through `write_stream`. The plugin
  refuses `write_redirect` with `opts.size_hint = None` (returns `Unsupported`)
  because presigned-PUT and multipart-upload both need a known body length.
- Inverted byte ranges (`start > end_inclusive`) return `InvalidArgument`
  at the Layer boundary; the request never reaches S3.
- Known-size multipart redirects target 32 MiB parts (clamped to AWS's
  [5 MiB, 5 GiB, ≤10 000 parts] window), with a balanced base/remainder
  split so every part is within one byte of every other.
- Unknown-size streaming writes use bounded 8 MiB `UploadPart` buffers.
  They keep the same 10 000-part guard; exceeding it returns
  `Unsupported` with the message `S3 streaming write exceeded the
  10000-part limit`.

## Subscriptions and watch

`watch_directory` consumes S3 notifications from an operator-managed
SQS queue. The plugin does not create bucket notification rules,
EventBridge rules, or queues; configure either direct S3 bucket
notifications to SQS or EventBridge S3 object events delivered to
SQS, then set `sqs_queue_url` on the connection. The same AWS
credentials drive SQS `ReceiveMessage` and `DeleteMessageBatch`
through `aws-sdk-sqs`.

Acknowledgement is at-least-once and happens **after fan-out**: once a
derived ovstorage event has been dispatched to every matching watcher,
its delete is queued to the SQS ack pump (off the fan-out path, so a
slow network ack never stalls delivery). A source SQS message that
parses into several events carries one refcount and is deleted
**exactly once**, after every one of its events has been dispatched and
acked. Malformed notification bodies yield `Lapsed` and are deleted the
same way; a notification record outside the connection's bucket carries
no event and is deleted directly. A synchronous ack-dispatch failure
(the bounded pump is full or closed) and an asynchronous provider
failure (an SQS `DeleteMessageBatch` error) each surface as a terminal
error on the watch stream — never a silently dropped ack — tearing the
shared consumer down so the next watch reopens it.

### One consumer per connection

Concurrent `watch_directory` calls on a single connection — any prefix,
any principal — **self-coalesce onto one physical SQS consumer** per
connection. Events are fanned out in-process, prefix-filtered per
watcher, so watches on different prefixes never cannibalize each other's
notifications (a competing-consumer queue delivers each message to one
reader). The coalescer is principal-blind: it keys solely on the queue
resource, never on the caller.

A `since` request coalesces like any other watch: the stream is prefixed
with one `Lapsed` (S3 keeps no resume history) and then delivers live
events off the shared consumer — no dedicated reader.

**Operational rule — one notification resource per consumer.**
Coalescing is in-process, per connection. It cannot stop two backend
connections, two broker replicas, or two application processes from each
attaching an independent consumer to the **same** SQS queue and
splitting its notifications. So each live connection that consumes a
competing-consumer queue must have **its own** queue, or the resource
must be broadcast (fan-out) rather than competing-consumer.

## Threat model

Resolved AWS credentials live in process memory for the lifetime of
the backend instance. In Brokered mode the broker holds the
credentials and the library sees only short-lived presigned redirects.
The presigned-URL TTL is a private const
(`DEFAULT_PRESIGN_TTL_SECS = 300`) — there is no runtime config knob;
operators that need a different TTL change the const and
rebuild.

The factory's per-process backend instance map is keyed by a SHA-256
fingerprint over every security-relevant config value
(bucket, region, endpoint, profile, compatibility, `force_path_style`,
`force_request_payer`) and stable credential identity bits from the
supplied `SecretBundle` (`aws_access_key_id`, `aws_session_token`),
plus a per-factory monotonic instance counter. Two connections that
share a bucket but differ in any other field — config-shape *or*
principal — collide neither in the cache nor in `update_credentials`,
so one principal cannot use another principal's cached presigned URLs.

S3-compatible stores reached via `endpoint` inherit the operator's
network trust posture. There is no plugin-side cert pinning — the
system trust store handles HTTPS; operators wanting tighter posture
run a reverse proxy that pins for them.

The [anonymous fallback](#anonymous-fallback) reaches hosts a **caller**
chose — the bucket name in the address decides the virtual-hosted name,
the learned region decides the suffix — from this process's network
position, which is the shape of a server-side request forgery. So the
host every probe and every client would actually contact is judged
before a socket opens, and a cloud instance-metadata endpoint is
refused with `PermissionDenied` (`refusing to contact <origin>: it is a
cloud instance-metadata endpoint, and ovstorage never fetches from one
on a caller's behalf`): every IPv4 address in `169.254.0.0/16`,
`100.100.100.200`, `168.63.129.16`, every IPv6 address in `fe80::/10`,
`fd00:ec2::254`, an IPv6 address embedding a refused IPv4 address, and
the exact names `metadata.google.internal`, `metadata.goog` and
`metadata` — never by suffix, so `metadata.google.internal.evil.test`
is somebody else's host and is not refused on that ground.
`anonymous_fallback_endpoint` is judged the same way at
`create_backend`, granted or not. The predicate judges the host as
written: a DNS name that resolves to a link-local address is not
caught, and only a connector that checks the resolved address before
dialing would close that. A configured connection's `endpoint` is the
operator's own choice carrying the operator's own credential, so it is
warned about (`the configured S3 endpoint is a cloud instance-metadata
host`) rather than refused.

The fallback's cost is bounded because bucket names are the caller's to
invent: at most `anonymous_fallback_max_backends` clients stay resident,
the least recently used evicted first; at most
`anonymous_fallback_mints_per_minute` may be built per sliding minute,
every attempt charged, failures included, though a refusal answered
from the region negative cache builds nothing and is not charged; and
past the budget a cold bucket answers `ResourceExhausted` (`anonymous
fallback mint budget exhausted; retry later`, retryable) while resident
buckets keep answering. A build is single-flight per bucket, so a burst
of callers on one cold bucket costs one probe and one client. The
fallback holds no credential at all, so there is nothing of its own in
process memory to protect, nothing of its own in the instance-map
fingerprint above, and nothing a redirect could carry: its `read`
redirects are plain unsigned URLs declared `none`. Every mutation is
refused before the wire. A presigned URL for an unconfigured bucket is
never re-served anonymously; it falls through to `NoRoute` rather than
reaching the fallback.

S3 and SQS error response bodies are never interpolated into error
text. Only an allowlisted error-code token survives into
`error.message` — the first `<Code>` element that is a direct child of
the root `<Error>` element, within the first 8 KiB of the body, or the
modeled service error code when the SDK supplies one — and the rest of
the body is dropped. So a `SignatureDoesNotMatch`
response cannot disclose its `StringToSign`, `CanonicalRequest`, or
`AWSAccessKeyId` through a logged exception.

How a body with no recoverable code is reported depends on which
path produced it. A response this plugin captured itself — a
redirect result — is reported by its length alone, and an empty one
adds nothing to the message at all. An error raised by the AWS SDK
carries only the operation label: the SDK does not hand back a body
length independent of the response it already parsed, so there is
nothing to report there. Either way no byte of the body is quoted.

One path is not covered by that guarantee: a failed
`DeleteMessageBatch` entry reports the provider's free-form batch
failure message next to its code, because that message is the only
per-entry diagnostic SQS returns.

## Deferred / out of scope

- IMDS, AWS SSO, web-identity tokens, STS role assumption. The
  credential chain stops at the shared credentials file.
- Automatic EventBridge, bucket-notification, queue, or IAM
  provisioning for `watch_directory`.
- Persistent `SecretStore`-backed credential storage when
  `ConnectionRequest.persist = true`. Field validation runs in
  `update_credentials` either way.
- Provider-native HTTPS scheme routing (the host treats
  `https://…amazonaws.com` URLs as ordinary HTTPS until an explicit
  route selects this plugin).
- Per-bucket capability probing — `Capabilities` is connection-level
  only.
- `s3+minio://` through the anonymous fallback; the scheme root is
  scheme-exact and only `s3://` is served.
- The HTTPS spellings of an unconfigured bucket reaching the anonymous
  fallback; generated aliases exist per connection, and the fallback
  has none.
- A credentialed fallback tier — one that spends a configured identity
  on a bucket nobody configured. The anonymous tier is the only one.
- Refusing a configured `endpoint` at a cloud instance-metadata host;
  the plugin warns instead. The unconditional refusal covers the hosts
  the fallback derives and every redirect destination.
- Resolve-then-check pinning of fallback and redirect hosts, so a DNS
  name resolving to a link-local address is caught.
