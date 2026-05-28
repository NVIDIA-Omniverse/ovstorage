# ovstorage-plugin-s3

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-s3.md`](../../../docs/public/plugin-storage/plugin-s3.md).

Cdylib `Backend` plugin for AWS S3 and S3-compatible services
(MinIO, Cloudflare R2, Backblaze B2, custom). Loads through the C ABI
declared by `ovstorage-plugin`; sits behind the same `Factory` /
`Backend` SPI as the other first-party storage plugins.

## Internal architecture

- **SigV4 signer**: `src/sigv4.rs` owns the hand-rolled AWS SigV4
  signing path (canonical request → string-to-sign → derived signing
  key → HMAC-SHA256). No `aws-sdk-rust` dependency to keep the
  binary small and the surface auditable.
- **Multipart**: `src/multipart.rs` implements the state machine for
  S3's `CreateMultipartUpload` → per-part `UploadPart` →
  `CompleteMultipartUpload` (or `AbortMultipartUpload` on error).
  State serializes into the `continue_write` continuation token.
  The 100 MiB redirect-vs-stream threshold
  (`MULTIPART_REDIRECT_THRESHOLD_BYTES`) is a private const here.
- **HTTP**: `src/http.rs` builds and dispatches the per-request
  `reqwest::Client` calls. Retries are owned by the host; the plugin
  does not run an in-plugin retry loop.
- **XML**: `src/xml.rs` parses the AWS XML error/response shapes via
  `quick-xml` (ETag stripping, `ListObjectsV2` `CommonPrefixes`
  folding, `ListObjectVersions` paging through `key-marker` /
  `version-id-marker`).
- **Backend dispatcher**: `src/backend.rs` is the per-connection SPI
  dispatcher (directory marker key derivation, range-header
  serialisation, checksum extraction, version-id query extraction).
- **Credentials**: `src/credentials.rs` owns the explicit → env →
  shared-credentials-file chain.
- **Subscriptions**: `src/subscription.rs` parses direct S3 and
  EventBridge notification records, SQS XML responses, and classifies
  receipt-handle staleness.

## Test layout

- `src/*::tests` — unit tests:
  - `sigv4.rs`: AWS-published reference vectors (`get-vanilla`,
    `get-utf8`, `post-vanilla-query`), plus presigned-query shape.
  - `config.rs`: virtual-hosted vs path addressing per profile,
    endpoint requirement enforcement, signing-region overrides.
  - `credentials.rs`: chain priority, incomplete-bundle rejection,
    missing-credentials mapping to `AuthRequired`.
  - `xml.rs`: list / version / multipart-initiate-and-complete
    parsing, `CompleteMultipartUpload` body serialisation.
  - `multipart.rs`: continuation round-trip, foreign-tag rejection,
    part-plan threshold.
  - `backend.rs`: marker keys, range-header serialisation, ETag
    quoting, checksum extraction, version-id extraction.
  - `subscription.rs`: S3 / EventBridge parsing, SQS XML parsing,
    metadata / recursion filters, receipt-handle stale classification.
- `tests/multipart_state_machine.rs` — integration test driving
  `write` against an in-process HTTP server that serves
  `InitiateMultipartUpload` and `CompleteMultipartUpload`; asserts
  the `WriteStep::Redirects` shape and the final ETag from
  `continue_write(results)`.
