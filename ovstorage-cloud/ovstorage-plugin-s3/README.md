# ovstorage-plugin-s3

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-s3.md`](../../docs/public/plugin-storage/plugin-s3.md).

Cdylib `Backend` plugin for AWS S3 and S3-compatible services
(MinIO, Cloudflare R2, Backblaze B2, custom). Loads through the C ABI
declared by `ovstorage-plugin`; sits behind the same `Factory` /
`Backend` SPI as the other first-party storage plugins.

## Internal architecture

The plugin runs on the official **AWS SDK for Rust** (`aws-sdk-s3` +
`aws-sdk-sqs`).

- **SDK clients**: `src/client.rs` builds the per-connection
  `aws_sdk_s3::Client` (and an `aws_sdk_sqs::Client` when
  `watch_directory` is configured) on a shared rustls + **ring** HTTP
  client. The SDK's default `aws-lc` crypto is deliberately not pulled
  (`aws-smithy-http-client` with `default-features = false` +
  `rustls-ring`), reusing the rustls/ring stack already in the tree;
  `cargo tree -i aws-lc-sys` stays empty. Credentials are static-only:
  a `ProvideCredentials` cell reads the backend's live credentials with
  the identity cache disabled, so a host-driven refresh after a `401`
  is picked up without rebuilding the client. SDK retries are disabled
  (the host owns retry) and default request/response checksums are off
  to match S3-compatible stores.
- **Backend dispatcher**: `src/backend.rs` is the per-connection SPI
  dispatcher. It calls the SDK's typed operations (`HeadObject`,
  presigned `GetObject` / `PutObject` / `UploadPart`, `ListObjectsV2`,
  `ListObjectVersions`, `CopyObject`, multipart, …) and owns directory
  marker key derivation, range serialisation, checksum / version-id
  extraction, and the presigned-redirect orchestration.
- **Multipart**: `src/multipart.rs` implements the state machine for
  S3's `CreateMultipartUpload` → per-part `UploadPart` →
  `CompleteMultipartUpload` (or `AbortMultipartUpload` on error).
  State serializes into the `continue_write` continuation token.
  The 100 MiB redirect-vs-stream threshold
  (`MULTIPART_REDIRECT_THRESHOLD_BYTES`) is a private const here.
- **Errors**: `src/errors.rs` maps the SDK's `SdkError` (and raw HTTP
  status) onto the plugin's `ErrorCode` taxonomy, preserving the
  `401 → AuthRequired` reauth contract the host keys on, and the
  `CompleteMultipartUpload` HTTP-200-with-`<Error>` case via the
  modeled error code.
- **Config**: `src/config.rs` parses the connection config, resolves
  the compatibility-profile endpoint / region / path-style, and owns
  the S3 URL canonicalisation helpers.
- **Credentials**: `src/credentials.rs` owns the explicit → env →
  shared-credentials-file chain (static keys only).
- **Subscriptions**: `src/subscription.rs` drives `watch_directory`
  through `aws-sdk-sqs` (`ReceiveMessage` / `DeleteMessageBatch`),
  parsing the direct-S3 and EventBridge notification records carried in
  each message body and classifying receipt-handle staleness.

The AWS SDK is a larger dependency tree than a hand-rolled
`reqwest` + SigV4 + `quick-xml` stack; this binary-size cost is an
accepted trade for SDK-maintained signing, endpoint resolution, and
wire-protocol handling.

## Test layout

- `src/*::tests` — unit tests:
  - `config.rs`: virtual-hosted vs path addressing per profile,
    endpoint requirement enforcement, signing-region overrides.
  - `credentials.rs`: chain priority, incomplete-bundle rejection,
    missing-credentials mapping to `AuthRequired`.
  - `errors.rs`: HTTP-status → `ErrorCode` mapping (notably
    `401 → AuthRequired` with the reauth `Auth` context).
  - `multipart.rs`: continuation round-trip, foreign-tag rejection,
    part-plan threshold.
  - `backend.rs`: marker keys, range-header serialisation, ETag
    quoting, checksum mapping, version-id extraction.
  - `subscription.rs`: S3 / EventBridge notification parsing,
    metadata / recursion filters, receipt-handle stale classification.
- `tests/precondition.rs`, `tests/multipart_state_machine.rs` —
  integration tests driving the SDK against an in-process HTTP server
  (the backend's `endpoint` points at `127.0.0.1`): precondition /
  redirect shapes and the multipart `WriteStep::Redirects` +
  `continue_write` ETag flow.
- `tests/sqs_watch_subscription.rs` — drives `watch_directory` against
  an in-process **awsJson1.0** SQS fixture (receive / delete, ack
  ordering, long-poll cancellation, batch-failure classification).
