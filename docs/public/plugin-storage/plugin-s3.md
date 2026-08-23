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
  to `*`. `list_versions` needs `s3:ListBucketVersions`, which is a
  separate grant and rarely public.

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

## Layer-to-API mapping

| Layer method | S3 API |
|---|---|
| `instantiate` | (no remote call; AWS SDK client setup) |
| `stat` | `HeadObject` (forwards `?versionId=…` pin; parses `ETag`, `Content-Length`, `Last-Modified`, `x-amz-version-id`, `x-amz-checksum-*`, `x-amz-meta-*`, system `x-amz-*` headers) |
| `read` | Presigned `GetObject` (SigV4 query auth, 5-min TTL). `ReadOptions.if_match` (etag) is folded into the SigV4 signed-headers set, so a holder of the URL cannot drop or alter it without invalidating the URL. `ReadOptions.range` is deliberately **not** signed: the plugin validates the requested range and then discards it, because the host injects `Range:` itself before following and a signed duplicate would break the SigV4 header set (403 `SignatureDoesNotMatch`). An unsigned `Range` on a presigned GET is honored by S3, so the "cannot drop or alter" guarantee covers `if_match` and does not cover `Range` — a holder of the URL chooses its own slice. Returns `ReadResult::Redirect` with `ResponseParsing` for ETag, version, size, mtime, and S3 system metadata. |
| `write` (Body::Bytes) | Direct `PutObject` through the plugin's signed client. `WriteOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`); `Overwrite` sends neither. |
| `write_redirect` | Known-size `size_hint >= 100 MiB` → `CreateMultipartUpload` + one presigned `UploadPart` redirect per part. Planning targets 32 MiB parts, then clamps to S3's 10 000 parts / 5 GiB-per-part / 5 TiB-per-object limits; otherwise a single presigned `PutObject` redirect. `If-Match: <etag>` (from `IfDestExists::MatchEtag`), `If-None-Match: *` (from `IfDestExists::Fail`), and `x-amz-meta-*` are signed into the request. |
| `continue_write` | `CompleteMultipartUpload` (or no-op for the single-PUT path). On any failure (terminal CMU failure, missing per-part ETag) the plugin issues a best-effort `AbortMultipartUpload` so failed commits don't leak staged parts. |
| `write_stream` | Chunk-by-chunk direct signed `UploadPart` calls (8 MiB parts, no `Vec<u8>` materialisation). Used for unknown-size `Body::Stream` writes. |
| `delete` | `DeleteObject`; `DeleteOptions.if_match` (etag) → `If-Match`; `?versionId=…` propagated as a query parameter. |
| `list` | `ListObjectsV2` with `prefix`, optional `delimiter=/`, `max-keys`, `continuation-token`, repeated until `NextContinuationToken` is absent (a `max_results` request is a single page instead). Real objects return `ObjectInfo` with `ObjectKind::File`; zero-byte keys ending in `/` return `ObjectInfo` with `ObjectKind::DirectoryMarker`; `CommonPrefixes` become `ObjectInfo` values with `ObjectKind::DirectoryInferred`. If S3 reports the same address as both a marker object and a common prefix, the marker wins and only one item is emitted. |
| `list_versions` | One `ListObjectVersions` request, resuming from `key-marker` / `version-id-marker` when the backend is handed a page token. It does **not** walk to the end on its own, so a call returns one native page. The Layer above it always answers `next_page_token: None`, so a caller cannot obtain a token to resume with; the `<key-marker>\|<version-id-marker>` encoding is the backend-level form. Each version returns an `ObjectInfo` whose address carries `?versionId=…`. Newest-first order; delete markers are not surfaced as version items. |
| `get_latest_version` | `HeadObject` (returns `ObjectInfo` for the head with its current `?versionId=…` address, or for the pinned `?versionId=…` address). Unversioned buckets return `Unsupported`. |
| `create_directory` / `delete_directory` | Zero-byte marker object at `<key>/`; `delete_directory` removes only the marker (recursive directory delete is host-side composition). |
| `copy` | `CopyObject` with `x-amz-copy-source: /<bucket>/<percent-encoded-key>[?versionId=…]`. `CopyOptions::if_source` (etag) maps to `x-amz-copy-source-if-match`; `CopyOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`). |
| `rename` | Copy-then-delete. **No rollback** of the destination on delete failure; surfaces `CommitAmbiguous` reporting that the destination committed but the source delete failed. |
| `update_metadata` | Self-copy with `x-amz-metadata-directive: REPLACE`. The plugin HEADs first (honouring `?versionId=…`), merges existing `user_metadata` with `user_metadata_remove` / `user_metadata_set`, and emits the merged set. Gated on `UpdateMetadataOptions.allow_rewrite_emulation = true`. |
| `check_access` | `HeadObject` for an object target. For a bucket target: `GET ?policyStatus=` on a credentialed connection, a bounded `ListObjectsV2` on an anonymous one (essentially no anonymous caller holds `s3:GetBucketPolicyStatus`, so probing with it would report a fully public bucket unreadable). `200` → `allowed: true`, except that an anonymous connection reports any requested `write` / `delete` / `update_metadata` in `denied_ops` — and `allowed` is then `false`, since not everything asked for is permitted — because those are refused before the wire. `401`/`403` → `allowed: false` with every requested op denied, returned as a successful decision rather than an error. `404` → `NotFound`. The object probe resolves the address's own shape first: a `?versionId=` address pins the `HeadObject` to that version, and a `key/` address whose marker object is absent falls back to the same bounded prefix probe `stat` uses, so a `DirectoryInferred` address this backend's own `list` returned is not reported missing (a refused fallback answers `allowed: false` rather than `NotFound`). The decision comes from one probe rather than from each requested permission separately. |
| `watch_directory` | `ReceiveMessage` / `DeleteMessageBatch` via `aws-sdk-sqs` against `sqs_queue_url`. Resumable cursor is intentionally empty. |

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
