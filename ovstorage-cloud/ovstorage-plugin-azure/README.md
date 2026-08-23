# ovstorage-plugin-azure

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-azure.md`](../../docs/public/plugin-storage/plugin-azure.md).

Cdylib `Backend` plugin for Azure Blob Storage and Azure Data Lake
Storage Gen2 (HNS-aware). Loads through the C ABI declared by
`ovstorage-plugin`; sits behind the same `Factory` / `Backend` SPI
as the other first-party storage plugins. Hand-rolled HTTP / Shared
Key signing / Service SAS / Entra OAuth2 against
`reqwest` (rustls-tls) — no `azure_storage` / `azure_identity`
dependency.

## Internal architecture

- **Auth**: `src/auth.rs` handles all five credential paths (Shared
  Key, SAS, federated OAuth2, client-credentials OAuth2, env-var
  fallbacks). Bearer-token cache lives in
  `tokio::sync::Mutex<Option<CachedToken>>` with refresh 60 seconds
  before expiry.
- **Signing**: `src/signing.rs` builds the Shared Key HMAC-SHA256
  signature over the canonical string (lowercased / sorted
  `x-ms-*` headers, canonicalised resource), and mints Service SAS
  query strings (`sv` / `sr` / `se` / `sp` / `spr` / `sig`).
- **Client**: `src/client.rs` wraps the per-request HTTP dispatch
  with vendor-specific headers and the response-status → typed
  `ErrorCode` mapping.
- **Backend**: `src/backend.rs` is the per-connection SPI dispatcher.
  Owns the staged-blocks write state machine
  (`build_block_list_xml`, `WriteContinuation` JSON encoding, the
  deterministic 24-char block-id derivation) and the flat / HNS
  branching across `stat` / `list` / `rename` / directory ops.
- **Avro changefeed**: `src/avro_changefeed.rs` parses Azure's
  object-container Avro records (`null` and raw-`deflate` codecs,
  block sync-marker verification, primitive unknown-field skipping).
- **Parsing**: `src/parse.rs` translates the `x-ms-*` header family,
  Azure's XML enumeration responses, and HNS path-list JSON into
  `ObjectInfo` / `UserMetadata`. Pinned-header sets live in
  `SYSTEM_METADATA_HEADERS` and `HNS_SYSTEM_METADATA_HEADERS`.
- **Subscriptions**: `src/subscription.rs` drives the change-feed
  polling loop (segment lag, poll-interval gating, `Lapsed` emission
  on backlog or missing segments).
- **Config**: `src/config.rs` validates the descriptor's config
  schema and pins HNS-vs-flat at instantiate time.

## Test layout

- `src/*::tests` — unit tests:
  - `signing.rs`: `shared_key_string_to_sign_matches_microsoft_list_blobs_example`
    (reproduces Microsoft's documented `List Containers` example
    byte-for-byte); `shared_key_signature_is_stable_for_pinned_inputs`
    and `service_sas_query_signs_a_pinned_blob_request` pin the
    HMAC-SHA256 outputs and SAS query-parameter ordering.
  - `auth.rs`: `entra_client_secret_token_body_shape_is_pinned`,
    `entra_federated_token_body_replaces_secret_with_assertion`.
  - `parse.rs`: `parse_blob_list_xml_handles_prefixes_and_blobs`,
    `parse_dfs_path_list_handles_directories_and_files`,
    `parse_object_info_packs_etag_size_and_user_metadata`.
  - `backend.rs`: `stage_block_sequence_emits_redirects_then_done`,
    `block_id_is_deterministic_and_uniform_length`,
    `write_redirect_below_threshold_keeps_single_putblob`,
    `block_list_xml_round_trips_in_order`,
    `write_continuation_round_trips_through_json`,
    `capabilities_track_hns_flag`.
  - `tests::instantiate_reports_flat_vs_hns_capabilities`.
- Live Azure / Azurite integration tests live in the workspace
  conformance suite, gated by environment variables.
