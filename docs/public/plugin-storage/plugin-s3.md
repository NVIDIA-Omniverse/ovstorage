# S3 plugin (`s3`)

The `s3` plugin: a first-party `Backend` implementation against AWS S3
and S3-compatible object stores (MinIO, Cloudflare R2, Backblaze B2,
custom endpoints). Lives in
`ovstorage-cloud/crates/ovstorage-plugin-s3/` and compiles as a cdylib
loaded through the C ABI declared by `ovstorage-plugin`. The plugin
hand-rolls AWS Signature Version 4 over an async `reqwest::Client`
(no `aws-sdk-*` dependency) and owns the vendor response-header
vocabulary so the host stays generic. Mints `ReadResult::Redirect`
and `WriteStep::Redirects` against SigV4 presigning so bytes flow
directly between S3 and the host; multipart uploads use the native
`CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload`
state machine.

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
    set on direct calls and as a signed query parameter on presigned
    `Read` URLs).
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

## Auth

The plugin uses hand-rolled SigV4 (canonical request, string-to-sign,
derived signing key, HMAC-SHA256 header or query signing). The
credential chain, in order:

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

Resolution failures surface as `ErrorCode::AuthRequired`. The
factory's `authenticate` returns `AuthEvent::Succeeded` on resolution
and `AuthEvent::Failed` otherwise; secret bytes are never logged.
IMDS, AWS SSO, web-identity tokens, and STS role assumption are
**not** implemented in-process — operators run `aws sso login` (or
their session helper) to materialise a static-key profile.

## URL handling and version-pinned addresses

Native addresses are `s3://<bucket>/<key>`. The configured `bucket`
pins the bucket; addresses whose URL bucket disagrees are rejected
with `InvalidArgument` before any signing happens. Object keys are
byte-preserving: literal `..`, `.`, double slashes, trailing dots,
and percent-encoded sequences round-trip through both routing and
signing.

`?versionId=...` is the only recognised version pin. `read`,
`stat`, `delete`, `copy(source)`, `update_metadata(source HEAD)`,
and `list_versions` honour it on the wire so the request reaches the
pinned historical version. Mutating ops whose wire format cannot
carry a version pin — `write`, `write_stream`, `write_redirect`,
`copy(destination)`, `rename(both endpoints)`,
`update_metadata(destination)` — reject any pinned `?versionId=` with
`InvalidArgument` rather than silently writing to head.

## SPI-to-API mapping

| SPI method | S3 API |
|---|---|
| `instantiate` | (no remote call; SigV4 client setup) |
| `stat` | `HeadObject` (forwards `?versionId=…` pin; parses `ETag`, `Content-Length`, `Last-Modified`, `x-amz-version-id`, `x-amz-checksum-*`, `x-amz-meta-*`, system `x-amz-*` headers) |
| `read` | Presigned `GetObject` (SigV4 query auth, 5-min TTL). `ReadOptions.range` / `if_match` (etag) are folded into the SigV4 signed-headers set so a holder of the URL cannot drop or alter those headers without invalidating the URL. Returns `ReadResult::Redirect` with `ResponseParsing` for ETag, version, size, mtime, and S3 system metadata. |
| `write` (Body::Bytes) | Direct `PutObject` through the plugin's signed client. `WriteOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`); `Overwrite` sends neither. |
| `write_redirect` | Known-size `size_hint >= 100 MiB` → `CreateMultipartUpload` + one presigned `UploadPart` redirect per part. Planning targets 32 MiB parts, then clamps to S3's 10 000 parts / 5 GiB-per-part / 5 TiB-per-object limits; otherwise a single presigned `PutObject` redirect. `If-Match: <etag>` (from `IfDestExists::MatchEtag`), `If-None-Match: *` (from `IfDestExists::Fail`), and `x-amz-meta-*` are signed into the request. |
| `continue_write` | `CompleteMultipartUpload` (or no-op for the single-PUT path). On any failure (terminal CMU failure, missing per-part ETag) the plugin issues a best-effort `AbortMultipartUpload` so failed commits don't leak staged parts. |
| `write_stream` | Chunk-by-chunk direct signed `UploadPart` calls (8 MiB parts, no `Vec<u8>` materialisation). Used for unknown-size `Body::Stream` writes. |
| `delete` | `DeleteObject`; `DeleteOptions.if_match` (etag) → `If-Match`; `?versionId=…` propagated as a query parameter. |
| `list` | `ListObjectsV2` with `prefix`, optional `delimiter=/`, `max-keys`, `continuation-token`. Real objects return `ObjectInfo` with `ObjectKind::File`; zero-byte keys ending in `/` return `ObjectInfo` with `ObjectKind::DirectoryMarker`; `CommonPrefixes` become `ObjectInfo` values with `ObjectKind::DirectoryInferred`. If S3 reports the same address as both a marker object and a common prefix, the marker wins and only one item is emitted. |
| `list_versions` | `ListObjectVersions`, paging through `key-marker` / `version-id-marker`. Each version returns an `ObjectInfo` whose address carries `?versionId=…`. Page token encoded as `<key-marker>\|<version-id-marker>`. Newest-first order; delete markers are not surfaced as version items. |
| `get_latest_version` | `HeadObject` (returns `ObjectInfo` for the head with its current `?versionId=…` address, or for the pinned `?versionId=…` address). Unversioned buckets return `Unsupported`. |
| `create_directory` / `delete_directory` | Zero-byte marker object at `<key>/`; `delete_directory` removes only the marker (recursive directory delete is host-side composition). |
| `copy` | `CopyObject` with `x-amz-copy-source: /<bucket>/<percent-encoded-key>[?versionId=…]`. `CopyOptions::if_source` (etag) maps to `x-amz-copy-source-if-match`; `CopyOptions::if_dest` maps to `If-Match: <etag>` (for `MatchEtag`) or `If-None-Match: *` (for `Fail`). |
| `rename` | Copy-then-delete. **No rollback** of the destination on delete failure; surfaces `Internal` reporting that the destination committed but the source delete failed. |
| `update_metadata` | Self-copy with `x-amz-metadata-directive: REPLACE`. The plugin HEADs first (honouring `?versionId=…`), merges existing `user_metadata` with `user_metadata_remove` / `user_metadata_set`, and emits the merged set. Gated on `UpdateMetadataOptions.allow_rewrite_emulation = true`. |
| `check_access` | `HeadObject` for an object target; `GET ?policyStatus=` for a bucket target. `200` → `allowed: true`; `401`/`403` → `allowed: false`; `404` → `NotFound`. |
| `watch_directory` | SQS `ReceiveMessage` / `DeleteMessageBatch` against `sqs_queue_url` (SigV4 service `sqs`). Resumable cursor is intentionally empty. |

## Streaming guarantees

`write` with `Body::Bytes` PUTs directly (zero-byte payloads
included), skipping the redirect round-trip. `Body::Stream` writes go
through `write_stream`'s chunk-by-chunk `UploadPart` loop — the host's
chunks reach the signed client one-by-one through a bounded path; no
full-body buffering happens at the plugin boundary. Range reads are
served by the presigned URL itself; the SigV4 binding of the `range`
header prevents a follower or proxy from silently widening the slice.

Multipart finalisation parses the `CompleteMultipartUpload` response
defensively: S3 can return HTTP 200 with an embedded `<Error>` body,
so the plugin checks for that envelope first and maps known codes
(`InternalError` / `SlowDown` / `ServiceUnavailable` → `Transient`,
precondition codes → `ObjectModified`, others → `Internal`).

## Capability bits

The plugin advertises (true):
`writes_are_atomic` (single PUT atomicity; multipart commits atomically
at `CompleteMultipartUpload`), `supports_no_overwrite_write` (via
`If-None-Match: *`), `supports_if_match_write` (via `If-Match`),
`supports_server_side_copy`, `supports_server_side_rename` (plugin
owns the copy-then-delete dance — **not** an atomic S3-side rename),
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
  at the SPI boundary; the request never reaches S3.
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
credentials sign SQS `ReceiveMessage` and `DeleteMessageBatch` with
SigV4 service `sqs`.

Acknowledgement is at-least-once and one event delayed: a source SQS
message is deleted only after every derived ovstorage event has been
yielded and the caller asks the iterator for the next item.
Malformed notification bodies yield `Lapsed` and are deleted after
that `Lapsed` is drained. Dropping the iterator before the next pull
leaves the most recently yielded message unacked so SQS can redeliver
it after the visibility timeout.

## Threat model

Resolved AWS credentials live in process memory for the lifetime of
the backend instance. In Brokered mode the broker holds the
credentials and the library sees only short-lived presigned redirects.
The presigned-URL TTL is a private const
(`DEFAULT_PRESIGN_TTL_SECS = 300`) — there is no runtime config knob
today; operators that need a different TTL change the const and
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
