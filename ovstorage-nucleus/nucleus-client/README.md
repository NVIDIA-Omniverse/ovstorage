# nucleus-client (`nucleus-client`)

## Purpose

Wraps the Nucleus *omni1* surface — the storage / namespace / asset traits Nucleus speaks over its ConnLib WebSocket transport — for plugin-side consumers. Houses the codegen output for the `omni1.idl.ts` IDL, plus a hand-authored `deprecated_methods` escape hatch and a hand-authored `LftClient` for the Large File Transfer side channel.

The crate sits between [nucleus-codegen](../nucleus-codegen/README.md) (build-time IDL→Rust generator) and [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) (the host-facing storage plugin). The plugin uses this crate's `Connection` and `ServerFeatures` traits over its main ConnLib transport, then mints LFT redirects through `LftClient` when a write exceeds the configured size threshold.

## Public surface

- `pub mod types` — re-exports the codegen-generated types from `omni1.idl.ts`: `PathAtVersion`, `PathAtBranch`, `PathType`, `PathPermission`, `PathEvent`, `Stat2Result`, `List2Response`, `List2ResponsePathEntry`, `Auth`, `Copy2Response`, `CreateAssetResult`, `CreateDirectoryResult`, `Delete2Response`, `GetACLResolvedResponses`, `GetCheckpointsResponse`, `MoveResponse`, `PathsToCopy`, `PathsToRename`, `ReadAssetVersionResult`, `StatusType`, `SubscribeListResponse`, `UpdateAssetResult`, `UploadResult`, `DeletedPath`, plus omni-object/with-hash variants the plugin does not wire.
- `pub mod generated` — the codegen `include!` output, defining the `Connection` and `ServerFeatures` traits over `Transport`. Each trait has one impl per `Transport` implementor (so `ConnLibTransport` implements both).
- `pub mod deprecated_methods` — hand-authored bypass for IDL methods the codegen filters out. See "Deprecated-method escape hatch" below.
- `pub mod lft` — the Large File Transfer side-channel client. See "LFT client" below.
- `pub type NucleusClient = nucleus_transport::ConnLibTransport;` — the conventional transport choice for the `omni1` endpoint (always ConnLib, never SOWS — the OmniAuth surface is the SOWS one and lives in [nucleus-auth](../nucleus-auth/README.md)).
- `pub use generated::{Connection, ServerFeatures};`
- `pub use lft::{LftClient, LftUploadInfo};`
- `pub use nucleus_transport::{self, Transport};`

## Deprecated-method escape hatch

`nucleus-codegen`'s `active_methods()` filter removes deprecated IDL methods from the generated `Connection` trait. Four operations have no non-deprecated replacement on the Nucleus server, so this crate hand-rolls them by calling `Transport::send` directly with the raw `interface.method` strings and JSON parameters:

- `create` with `type = Channel` — `create_asset` / `create_object` / `create_directory` are each pinned to one `PathType`; none accept `PathTypeCode::Channel` (3). Only the deprecated `create` mints Channel paths.
- `read` for channel subscriptions — `subscribe_read_asset` / `subscribe_read_object` / etc. dispatch to type-specific server handlers by method name. The Nucleus channel protocol is only handled by the `read` code path; calling `subscribe_read_asset` on a channel path hits the wrong handler.
- `update` for channel message sending — `update_object`'s mandatory `object_id` parameter doesn't exist for channels, so the deprecated `update` is the only path that publishes to a channel.
- `delete` for recursive deletion — `delete2` only works on empty folders. The deprecated `delete` handles recursive removal in one call. The helper returns `Ok` only after observing `StatusType::Done`; any subscription/transport/JSON error before `Done` is surfaced as `Err` carrying the URI and the count of paths already reported, so a connection drop mid-recursive-delete cannot masquerade as a clean termination.

The return types (`UploadResult`, `ReadResult`, `DeletedPath`, …) are still produced by codegen, because type generation is not filtered by deprecation. The escape hatch only bypasses the *trait dispatch* layer.

**Hard contract**: this module must be hand-edited on every `omni1.idl.ts` revision that touches one of those four methods or the types they exchange. The tests under `nucleus-client/src/deprecated_methods.rs` are not enough to catch every drift case; downstream tests in plugin-nucleus exercise the live wire shapes.

## LFT client

`LftClient` mints redirects against the Large File Transfer service (a sibling of the Nucleus `omni1` server that handles raw byte uploads). Plugin-nucleus's `write_redirect` consults `LftClient::should_use_lft(size)` and, when `true`, builds a `WriteRedirect` whose URL + headers come from `LftClient::generate_upload`.

- `pub fn new(lft_address, threshold, connection_id, connection_id_signature, connlib_token, access_token, username) -> Self` — constructor; all optional fields are `Option<String>` and the auth-header set adapts to whichever ones are populated. Builds an internal `reqwest::Client` with a 10s connect timeout and a 30s request timeout. Panics with a clear message if the TLS-rooted `reqwest::Client::builder().build()` fails (per `reqwest`'s "effectively infallible" contract on platforms with a usable rustls root store).
- `pub fn with_client(lft_address, threshold, connection_id, connection_id_signature, connlib_token, access_token, username, http: reqwest::Client) -> Self` — alternate constructor that injects a caller-provided `reqwest::Client`. Used by tests and by callers wanting custom deadlines.
- `pub fn should_use_lft(&self, size: u64) -> bool` — returns `true` only when `self.threshold > 0 && size > self.threshold`. The inequality is **strict**: a write whose `size_hint` equals the threshold goes through the in-band omni1 path, not LFT. A zero `threshold` disables LFT entirely (returns `false` for any size).
- `pub fn auth_headers(&self) -> Vec<(String, String)>` — emits the canonical LFT redirect header set:
  - `X-OV-Connection-ID` — always present.
  - `Authorization-Token: {connlib_token}` — when the ConnLib session token is present.
  - `Authorization: Bearer {access_token}` — when the JWT access token is present.
  - `Connection-Token: {connection_id}` and `Connection-Signature: {sig}` — both, when `connection_id_signature` is `Some`.
  - `X-OV-Username: {username}` — when the username is populated.
- `pub async fn generate_upload(&self, path: &str) -> Result<LftUploadInfo>` — POSTs `{"path": path}` to `{lft_address}/content/` with the auth headers above, parses the response to extract `(content_id_numeric, content_id_string)`, and returns the upload URL + the additional `Content-ID` / `Content-Start: 0` / `X-OV-URI` / `Content-ID-Numeric` headers the redirect's PUT must carry. On non-2xx responses the error body is read into memory bounded to 4 KiB (`LFT_ERROR_BODY_MAX_BYTES`); the truncation marker `(body truncated to N bytes of M)` is included in the returned error when truncation actually fired, and the `tracing::warn!` line carries `body_bytes` (count) + `truncated` (flag) instead of the raw body. When `content_id_numeric` is missing, `content_id` is parsed strictly from the string field via `parse::<u64>()` and surfaces an error rather than silently committing as ID `0`.
- `pub struct LftUploadInfo { content_id, content_id_str, upload_url, headers }` — drives plugin-nucleus's `WriteRedirectProperties`.

The HTTP client is built via `reqwest::Client::builder()` (async, rustls-tls) with explicit connect / request timeouts in `LftClient::new`. Tests and advanced callers may inject a fully-configured client through `LftClient::with_client`.

## Build-time codegen

`build.rs` invokes `nucleus_codegen::generate_from_file("../omni1.idl.ts")` and writes the Rust output to `OUT_DIR/generated.rs`, which `pub mod generated` includes verbatim. Drift between the IDL and `mod types` surfaces at build time. See [nucleus-codegen](../nucleus-codegen/README.md) for the IDL subset accepted and the deprecated-method filter.

## Cross-links

- [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) — the storage plugin that consumes this crate. Its "LFT side channel" section's auth-header set is authoritatively defined in `lft::LftClient::auth_headers` here.
- [nucleus-transport](../nucleus-transport/README.md) — defines the `Transport` trait the generated traits dispatch over.
- [nucleus-codegen](../nucleus-codegen/README.md) — generates `mod generated` and applies the `active_methods` filter.

## Implementation gaps

- The IDL types for omni-object and with-hash variants are generated but the storage plugin does not wire them. This crate's surface is complete on that axis; the plugin-side wiring is the gap.
- `LftClient` issues each `generate_upload` request through a freshly-`reqwest::Client::new()`-constructed instance per `LftClient`. Reusing a shared `reqwest::Client` has no observed cost.
