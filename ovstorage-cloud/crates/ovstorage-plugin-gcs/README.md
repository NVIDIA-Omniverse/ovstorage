# ovstorage-plugin-gcs

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-gcs.md`](../../../docs/public/plugin-storage/plugin-gcs.md).

Cdylib `Backend` plugin for Google Cloud Storage. Loads through the
C ABI declared by `ovstorage-plugin`; sits behind the same `Factory`
/ `Backend` SPI as the other first-party storage plugins. Hand-rolled
HTTP / V4 signing / OAuth2 against `reqwest` — no
`google-cloud-storage` / `google-cloud-auth` dependency.

## Internal architecture

- **Auth**: `src/auth.rs` handles service-account JSON parsing,
  OAuth2 token exchange (JWT-bearer grant for service accounts,
  refresh-token grant for authorized-user creds), and access-token
  caching behind a `Mutex` with refresh 5 minutes before expiry.
- **Signing**: `src/sign.rs` builds GCS V4 query-string signatures
  (`GOOG4-RSA-SHA256` / `auto / storage / goog4_request`, uppercase
  hex percent-encoding, `host` as the only signed header) for
  presigned-URL redirects. Signs with the service account's RSA
  private key via `jsonwebtoken::EncodingKey::from_rsa_pem`.
- **Parsing**: `src/parse.rs` parses GCS's JSON object metadata and
  the `x-goog-*` response header family into the SPI's `ObjectInfo`
  shape (flat `etag` / `version` / `size` / `mtime`). Handles the
  `x-goog-hash` composite header for both `crc32c=` and `md5=` entries.
- **Subscriptions**: `src/subscription.rs` translates Cloud Pub/Sub
  pull responses (Cloud Storage object-change notifications) into
  `WatchEvent`s; handles exactly-once delivery ack classification.
- **Factory / backend / dispatcher**: `src/lib.rs` owns the factory
  registration, the per-connection backend dispatcher, the resumable
  upload state machine (known-size redirect + unknown-size 8 MiB
  streaming), and the SPI method bodies.

## Test layout

- `src/*::tests` — unit tests for JWT generation (using
  `tests/synthetic_rsa_pkcs8.pem`), V4 signing fixtures, JSON
  parsing, and error mapping.
- A conformance fixture suite under `tests/fixtures/gcs/` is
  documented but not yet wired up; integration tests against a GCS
  fake (`fake-gcs-server`) are deferred.
