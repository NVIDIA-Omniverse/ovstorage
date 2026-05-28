# plugin-http (`ovstorage-plugin-http`)

> The canonical reference for the `http` / `https` backend's public
> surface, URL handling, status-code mapping, redirect policy, and
> capability bits lives in
> [`docs/public/plugin-storage/plugin-http.md`](../../../docs/public/plugin-storage/plugin-http.md).

## Purpose (crate-local)

Read-only plugin for anonymous HTTP / HTTPS URLs. Writes return
`Unsupported`. HTTP and HTTPS share a single plugin because the
on-the-wire protocol differences (TLS, default port) are immaterial
to object-retrieval semantics; whether to permit unencrypted
fetches is expressed by which prefixes the operator routes to the
plugin.

## Contributor notes

This README covers contributor-internal details only. Plugin
authors and operators should read the public reference linked above
for the schemes, descriptor, config keys, URL handling, capability
matrix, status-code mapping, and threat model.

### Dependencies

In-workspace: `ovstorage-plugin`.

External (notable): `reqwest`, `tokio` (with `time`), `async-trait`,
`httpdate`. Dev-only: `ovstorage` (for `Library`-level integration
tests), `futures`. The plugin's `reqwest::Client` lives on each
`HttpBackend` instance (per-route redirect policy + default headers);
the redirect follower in the library owns its own client. The two
clients are not shared because they differ in redirect-policy
intent and per-instance default-header configuration.

### Conformance tests

The plugin's conformance surface. Unless flagged **(pending)**, each
item is a target the plugin's tests should cover at maturity; only
items flagged **(covered)** have an actual `#[tokio::test]` checked
into `src/lib.rs`.

**HTTP/HTTPS routing**
- Route at `https://` matches every HTTPS URL; route at `http://`
  matches every HTTP URL.
- Route at `https://datasets.example.com/` matches that prefix only;
  other URLs return `NoRoute`. **(routing-side test in `ovstorage`)**
- No route bound to the `http` plugin: every HTTP/HTTPS URL returns
  `NoRoute`. **(routing-side test in `ovstorage`)**
- Non-2xx responses surface as typed errors (`NotFound`,
  `PermissionDenied`, `Transient`, …), not as body bytes. **(412 →
  `ObjectModified` and 503 → library retry covered in-tree; broader
  status-mapping coverage lives in conformance.)**
- Redirect policy is enforced: same-origin redirects succeed,
  cross-origin redirects fail unless the host is allow-listed.
  **(`build_redirect_policy_accepts_three_modes` and
  `build_redirect_policy_rejects_unknown` cover policy parsing;
  cross-host integration test deferred.)**
- Weak ETags never satisfy an exact `if_match` by themselves; strong
  ETags are sent as `If-Match` and mismatches surface as
  `ObjectModified`.
  **(`weak_etag_in_check_identity_is_not_comparable` plus
  `http_read_forwards_strong_etag_precondition_and_maps_412`.)**
- Default-header banlist rejects `Authorization`, `Cookie`,
  `Proxy-Authorization`.
  **(`parse_default_headers_rejects_credential_headers`,
  `parse_default_headers_accepts_safe_headers`.)**
- Fragment in route prefix is rejected at `instantiate`.
  **(`fragment_in_prefix_is_invalid_argument`.)**

The `tests` module in `src/lib.rs` covers anonymous HEAD + GET
(`anonymous_http_read_and_stat`), the strong-ETag `If-Match` wire
shape and 412 → `ObjectModified` mapping
(`http_read_forwards_strong_etag_precondition_and_maps_412`),
library-driven retry on retryable statuses
(`http_read_retries_retryable_status_via_library`), weak-ETag
suppression (`weak_etag_in_check_identity_is_not_comparable`),
default-header banlist
(`parse_default_headers_rejects_credential_headers` /
`_accepts_safe_headers`), fragment rejection at both factory entry
points (`fragment_in_prefix_is_invalid_argument`,
`fragment_in_prefix_is_invalid_argument_at_instantiate`),
redirect-policy builder (`build_redirect_policy_rejects_unknown` /
`_accepts_three_modes`), the `map_status` identity-context wiring
(`map_status_412_with_headers_carries_identity_context`,
`map_status_412_without_headers_omits_context`,
`map_status_401_is_auth_required_with_context`,
`map_status_403_is_permission_denied_no_context`,
`check_identity_mismatch_carries_identity_context`),
`instantiated_backend_uses_root_url_for_requests` (prefix →
root_url rewrite hits the configured origin path),
`ranged_read_uses_content_range_total_for_size` (`stat` then ranged
read with matching `if_match` round-trips a `Content-Range`-derived
total), `streaming_read_without_content_length_leaves_size_unknown`
(chunked 200 leaves `size = None`),
`stat_fallback_rejects_200_when_range_is_ignored` (`Unsupported`
rather than buffered full body), `streaming_read_cancels_mid_body`
(cancellation after first chunk surfaces as `ErrorCode::Cancelled`),
`default_client_blocks_cross_origin_redirect` (`HttpBackend::new()`
refuses a 302 to a different origin), and direct-unit coverage of
the `Content-Range` parser
(`parse_content_range_total_handles_well_formed_header`,
`parse_content_range_total_returns_none_for_unknown_total`).
