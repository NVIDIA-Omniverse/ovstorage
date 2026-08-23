# plugin-http (`ovstorage-plugin-http`)

> The canonical reference for the `http` / `https` backend's public
> surface, URL handling, status-code mapping, redirect policy, and
> capability bits lives in
> [`docs/public/plugin-storage/plugin-http.md`](../../docs/public/plugin-storage/plugin-http.md).

## Purpose (crate-local)

Read-only Layer implementation for HTTP / HTTPS URLs, anonymous or
authenticated (Bearer, Basic, a prefix-scoped signed query, and/or explicit
secret headers). A broker host may additionally attach its per-principal OAuth
bearer through the broker-minted request-credential reference. The sibling
`ovstorage-plugin-http-abi` package exports the shipped
`libovstorage_plugin_http` ABI-v2 cdylib. Writes return `Unsupported`. HTTP and
HTTPS share a single plugin because the
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
`httpdate`, `base64`, `serde_json`, `zeroize`. Dev-only: `ovstorage` (for `Stack` integration
tests), `futures`. Anonymous and bearer-credentialed `reqwest::Client`s live on each
`HttpBackend` instance (per-route redirect policy + default headers);
the credentialed client always restricts redirects to the same origin and
disables system proxies. The bearer itself is loaded through broker host
keyring callbacks for each request; the redirect follower in the library owns
its own client. The two
client groups are not shared because they differ in redirect-policy
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
- Declared credentials reach both request builders — the whole-object
  read and `stat` — and the connect-time probe.
  **(`a_credential_reaches_both_request_builders_and_the_probe`.)**
- Signed-query bytes are preserved, a real prefix-scoped SAS authorizes
  multiple objects, and a real per-object SigV4 presign is refused as a
  connection-held shape. Secret headers reach the wire and rotate without
  changing the connection's exact channel shape.
  **(`signed_query_credentials`, `secret_headers_are_sensitive_and_shape_is_exact`,
  `userinfo_coexists_with_non_authorization_secrets_and_guards_rotation`.)**
- A malformed credential bundle fails the connection: unknown key, half
  a basic pair, an empty bearer token, a basic pair with both halves
  empty, both shapes at once, a non-bytes secret, a control character.
  One empty half of a basic pair is *valid* (RFC 7617). `root_url`
  userinfo spells the same credential, except that a wholly empty
  `://:@` is normalized away by URL parsing and is simply anonymous.
  **(`instantiate_rejects_a_malformed_credential_bundle`, plus the
  `credentials` module's own tests.)**
- Credentials are refused over cleartext unless the host is loopback —
  for userinfo in `root_url` as well as the declared fields — and a
  loopback connection ignores an ambient proxy.
  **(`credentials_are_refused_over_cleartext_except_on_loopback`,
  `userinfo_over_cleartext_is_refused_like_any_other_credential`,
  `a_credentialed_loopback_connection_ignores_an_ambient_proxy`.)**
- A `root_url` scheme the transport cannot serve is refused at connect,
  while a caller-facing `prefix` may use another scheme.
  **(`a_root_url_scheme_the_transport_cannot_serve_is_refused`.)**
- A cancelled probe fails the connection rather than inventing a state.
  **(`a_cancelled_probe_fails_the_connection`.)**
- The configured redirect policy is really installed, not merely
  correct in isolation.
  **(`the_configured_redirect_policy_is_actually_installed`.)**
- Two connections cannot share one caller-facing prefix, and the
  refusal carries no query secret.
  **(`two_connections_on_one_prefix_fail_the_build_with_the_prefix_named`,
  `the_duplicate_prefix_error_carries_no_query_secret`.)**
- The connect-time probe records what it learned and never refuses the
  add: 401 is `AuthFailed`, an unreachable origin is `AwaitingAuth`, and
  a declared connection cannot stop the host starting.
  **(`the_probe_records_what_it_learned`,
  `a_refused_credential_in_config_still_starts_the_host`.)** `probe`
  itself surfaces both as errors.
  **(`probe_reports_credential_and_reachability_failures_as_errors`.)**
- `Authenticated` needs positive evidence — a `2xx` — and every other
  answer, `403` included, claims nothing; the credential survives a
  same-origin hop, which is the premise that makes a redirected verdict
  attributable.
  **(`the_probe_claims_authentication_only_on_positive_evidence`.)**
- The probe never follows a hop the configured data path would refuse,
  nor a cross-origin hop where its authentication verdict would no longer
  describe the configured root.
  **(`the_probe_never_follows_a_hop_the_data_path_would_refuse`,
  `the_probe_does_not_cross_an_origin_the_data_path_is_allowed_to`.)**
- Loopback covers the spellings of the local interface, and only those.
  **(`loopback_covers_the_spellings_of_the_local_interface`.)**
- A redirect chain is capped and shares one total deadline, and an
  authenticated redirect may not downgrade to cleartext.
  **(`a_redirect_chain_is_capped`,
  `redirect_hops_share_one_total_timeout`,
  `an_authenticated_redirect_may_not_downgrade_to_cleartext`.)**
- `root_url` userinfo authenticates but is not published, an explicit
  prefix must be usable and credential-free, and a duplicate
  caller-facing prefix is refused.
  **(`userinfo_is_stripped_from_the_caller_facing_route`,
  `an_explicit_prefix_must_be_usable_and_credential_free`,
  `a_duplicate_caller_facing_prefix_is_refused`.)**
- Errors carry neither a credential nor a request URL.
  **(`malformed_default_headers_entry_does_not_echo_a_credential`,
  `reqwest_error_message_carries_no_request_url`.)**
- A fragment in a configured route URL is rejected because it never reaches
  the origin and cannot participate honestly in routing.
  **(`a_config_address_may_not_carry_a_query_or_a_fragment`.)**

The `tests` module in `src/lib.rs` covers anonymous HEAD + GET
(`anonymous_http_read_and_stat`), the strong-ETag `If-Match` wire
shape and 412 → `ObjectModified` mapping
(`http_read_forwards_strong_etag_precondition_and_maps_412`),
library-driven retry on retryable statuses
(`http_read_retries_retryable_status_via_library`), weak-ETag
suppression (`weak_etag_in_check_identity_is_not_comparable`),
default-header banlist
(`parse_default_headers_rejects_credential_headers` /
`_accepts_safe_headers`), fragment stripping in a route URL
(`fragment_in_root_url_is_stripped_rather_than_rejected`),
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
