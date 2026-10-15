// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP discovery against `/api/v1/services` to learn the Omniverse Storage Service gRPC
//! endpoint a client should connect to. Mirrors what the C++
//! `provider_omnistorage` does at first contact.

use ovstorage_plugin::{Error, ErrorCode, Result};
use serde::Deserialize;

use crate::auth::DiscoveryState;

/// One entry in the `/api/v1/services` response. The Omniverse Storage Service publishes
/// `{type, name, id, grpc, rest}`; we route via the `type` ("storage"
/// is the gRPC backend we dial) and the `grpc` field carries the full
/// URL (`https://host[:port]/`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ServiceEndpoint {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub grpc: Option<String>,
    #[serde(default)]
    pub rest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct ServicesResponse {
    #[serde(default)]
    services: Vec<ServiceEndpoint>,
}

/// Fetch and parse the `/api/v1/services` document. Returns the list of
/// service endpoints the discovery layer publishes. Stamps `Authorization:
/// Bearer …` from `auth_state` when a token is present — the Omniverse Storage Service
/// gates services discovery behind OIDC on auth-required deployments.
pub async fn fetch_service_endpoints(
    client: &reqwest::Client,
    discovery_url: &str,
    auth_state: &DiscoveryState,
) -> Result<Vec<ServiceEndpoint>> {
    let trimmed = discovery_url.trim_end_matches('/');
    let url = format!("{trimmed}/api/v1/services");
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.discovery",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: fetching service endpoints",
    );
    let mut request = client.get(&url);
    if let Some(token) = auth_state.access_token().await {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: services discovery fetch failed for {url}: {err}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::Transient,
            format!(
                "omniverse-storage-service: services discovery returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: services discovery body read failed: {err}"),
        )
    })?;
    let parsed: ServicesResponse = serde_json::from_slice(&body).map_err(|err| {
        // Preview the body so operators can spot schema drift without
        // adding ad-hoc traces.
        tracing::warn!(
            target: "ovstorage.omniverse_storage_service.discovery",
            plugin = "omniverse-storage-service",
            error = %err,
            body_preview = %String::from_utf8_lossy(&body[..body.len().min(512)]),
            "omniverse-storage-service: services discovery JSON parse failed",
        );
        Error::new(
            ErrorCode::InvalidArgument,
            format!("omniverse-storage-service: services discovery JSON parse failed: {err}"),
        )
    })?;
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.discovery",
        plugin = "omniverse-storage-service",
        endpoint_count = parsed.services.len(),
        "omniverse-storage-service: service endpoints fetched",
    );
    tracing::trace!(
        target: "ovstorage.omniverse_storage_service.discovery",
        plugin = "omniverse-storage-service",
        url = %url,
        services = ?parsed.services,
        "omniverse-storage-service: /api/v1/services response body",
    );
    Ok(parsed.services)
}

/// Find the gRPC endpoint URI for the named service kind (e.g.
/// `"storage"`, `"notification-consumer"`). Returns `(uri, plaintext)`.
pub fn find_grpc_endpoint_for_kind(
    endpoints: &[ServiceEndpoint],
    kind: &str,
) -> Result<(String, bool)> {
    if endpoints.is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: discovery returned no service endpoints",
        ));
    }
    let pick = endpoints
        .iter()
        .find(|s| s.kind == kind && s.grpc.is_some())
        .ok_or_else(|| {
            let kinds = endpoints
                .iter()
                .map(|s| s.kind.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: discovery returned no '{kind}' endpoint with a grpc URL (kinds seen: [{kinds}])"
                ),
            )
        })?;
    let url = pick.grpc.as_deref().expect("filtered for grpc.is_some");
    let uri = normalize_grpc_uri(url);
    let plaintext = uri.starts_with("http://");
    tracing::info!(
        target: "ovstorage.omniverse_storage_service.discovery",
        plugin = "omniverse-storage-service",
        kind,
        grpc_uri = %uri,
        "omniverse-storage-service: gRPC endpoint resolved",
    );
    Ok((uri, plaintext))
}

/// Normalize a gRPC endpoint spelling to a tonic-dialable URI. Shared by
/// discovery-published `grpc` values and by an operator-configured direct
/// endpoint, so one address has one meaning however it arrives.
pub(crate) fn normalize_grpc_uri(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    // gRPC name-resolution convention: `grpc://` = plaintext (≈ http),
    // `grpcs://` = TLS (≈ https). Tonic doesn't recognise either, so
    // rewrite. Case-insensitive guard against real-world payloads
    // that uppercase the scheme.
    if let Some(rest) = strip_scheme_ci(trimmed, "grpcs://") {
        return format!("https://{rest}");
    }
    if let Some(rest) = strip_scheme_ci(trimmed, "grpc://") {
        return format!("http://{rest}");
    }
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    // Bare host:port — pick scheme by host class. Local addresses
    // (localhost, *.local, loopback / private / link-local IPs)
    // typically run plaintext; everything else defaults to TLS so
    // we don't quietly downgrade a public domain.
    let host = extract_host(trimmed);
    if ovstorage::net::is_local_cleartext_host(host) {
        format!("http://{trimmed}")
    } else {
        format!("https://{trimmed}")
    }
}

/// Compared over BYTES, not over a `str` slice. `s[..prefix_len]` panics when
/// byte `prefix_len` lands inside a multi-byte character — which it does for
/// any internationalized host, since the two schemes differ in length:
/// matching `"grpcs://"` (8 bytes) against `grpc://<non-ASCII>` (7 bytes of
/// scheme) cuts the first host character in half. The prefix is ASCII, so a
/// byte-wise match implies `prefix_len` is a character boundary and the slice
/// below is safe by construction.
pub(crate) fn strip_scheme_ci<'a>(s: &'a str, scheme_lower: &str) -> Option<&'a str> {
    let prefix_len = scheme_lower.len();
    let head = s.as_bytes().get(..prefix_len)?;
    if head.eq_ignore_ascii_case(scheme_lower.as_bytes()) {
        Some(&s[prefix_len..])
    } else {
        None
    }
}

/// Best-effort host extraction from an authority-like `host[:port]`
/// or bracketed `[ipv6]:port`. Used only by `normalize_grpc_uri` to
/// route into `is_local_cleartext_host`; if the input is ambiguous
/// (e.g., unbracketed IPv6), returns the whole string and lets the
/// classifier decide — falling back to TLS on no-match is the
/// safer default.
fn extract_host(authority: &str) -> &str {
    if let Some(after_open) = authority.strip_prefix('[')
        && let Some((host, _)) = after_open.split_once(']')
    {
        return host;
    }
    if authority.matches(':').count() == 1 {
        return authority
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority);
    }
    authority
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(kind: &str, grpc: Option<&str>) -> ServiceEndpoint {
        ServiceEndpoint {
            kind: kind.into(),
            name: format!("{kind} service"),
            id: format!("{kind}-01"),
            grpc: grpc.map(str::to_string),
            rest: None,
        }
    }

    /// A `grpc://` value cannot serve as a discovery root: services discovery
    /// is an HTTP GET, and the HTTP client speaks only `http`/`https`. This is
    /// what makes the `grpc://` spelling free to mean "dial this endpoint
    /// directly" — it names no configuration that resolves today.
    ///
    /// The control is the point. An unreachable port fails with the same
    /// message, so "it returned an error" would prove nothing about the
    /// scheme. This drives a LIVE server and asserts the `http://` spelling of
    /// the very same authority SUCCEEDS, then that only the scheme differs in
    /// the failing cases. `grpcs://` is covered too: it is the TLS spelling and
    /// would otherwise be the one plausibly mistaken for `https`.
    #[tokio::test]
    async fn services_discovery_refuses_a_grpc_scheme_root() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/services"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"services":[]}"#),
            )
            .mount(&server)
            .await;
        let authority = server.uri().strip_prefix("http://").unwrap().to_string();

        let http = reqwest::Client::new();
        let state = crate::auth::DiscoveryState::new("default");

        // Control: the same authority over `http://` is a working discovery
        // root. Without this the failures below could be a dead port.
        fetch_service_endpoints(&http, &format!("http://{authority}"), &state)
            .await
            .expect("the http:// spelling of this authority is a live discovery root");

        for scheme in ["grpc", "grpcs"] {
            let root = format!("{scheme}://{authority}");
            let err = fetch_service_endpoints(&http, &root, &state)
                .await
                .expect_err("a grpc:// root is not a discovery URL");
            assert!(
                err.message().contains("services discovery fetch failed"),
                "expected the request itself to be refused for {root}, got: {}",
                err.message(),
            );
        }
        assert_eq!(
            server.received_requests().await.map(|r| r.len()),
            Some(1),
            "only the http:// control may reach the server; a grpc:// root must \
             not produce a request at all",
        );
    }

    #[test]
    fn find_picks_matching_kind() {
        let endpoints = vec![
            endpoint("storage", Some("https://grpc.storage.example/")),
            endpoint(
                "notification-consumer",
                Some("https://grpc.events.example/"),
            ),
        ];
        let (uri, _) = find_grpc_endpoint_for_kind(&endpoints, "storage").unwrap();
        assert_eq!(uri, "https://grpc.storage.example");
        let (uri, _) = find_grpc_endpoint_for_kind(&endpoints, "notification-consumer").unwrap();
        assert_eq!(uri, "https://grpc.events.example");
    }

    #[test]
    fn find_rejects_when_kind_missing() {
        let endpoints = vec![endpoint("storage", Some("https://grpc.storage.example/"))];
        let err = find_grpc_endpoint_for_kind(&endpoints, "notification-consumer").unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("notification-consumer"));
        assert!(err.message().contains("storage")); // lists kinds seen
    }

    #[test]
    fn find_errors_when_empty() {
        let err = find_grpc_endpoint_for_kind(&[], "storage").unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn find_errors_when_kind_has_no_grpc_url() {
        let endpoints = vec![endpoint("storage", None)];
        let err = find_grpc_endpoint_for_kind(&endpoints, "storage").unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    /// `grpc://` is the canonical scheme for plaintext gRPC in the
    /// gRPC name-resolution standard (mirrors `http://`). Tonic
    /// doesn't recognise the scheme; rewrite to `http://` and route
    /// to the plaintext channel.
    #[test]
    fn find_normalizes_grpc_scheme_to_http_plaintext() {
        let eps = vec![endpoint("storage", Some("grpc://host:1"))];
        let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
        assert_eq!(uri, "http://host:1");
        assert!(plaintext);
    }

    /// `grpcs://` is the TLS counterpart (mirrors `https://`).
    #[test]
    fn find_normalizes_grpcs_scheme_to_https_tls() {
        let eps = vec![endpoint("storage", Some("grpcs://host:1"))];
        let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
        assert_eq!(uri, "https://host:1");
        assert!(!plaintext);
    }

    #[test]
    fn find_preserves_http_scheme_as_plaintext() {
        let eps = vec![endpoint("storage", Some("http://host:1"))];
        let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
        assert_eq!(uri, "http://host:1");
        assert!(plaintext);
    }

    #[test]
    fn find_preserves_https_scheme_as_tls() {
        let eps = vec![endpoint("storage", Some("https://host:1"))];
        let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
        assert_eq!(uri, "https://host:1");
        assert!(!plaintext);
    }

    /// Case-insensitive scheme match — discovery payloads from
    /// real-world deployments occasionally uppercase the scheme.
    #[test]
    fn find_normalizes_uppercase_grpc_scheme() {
        let eps = vec![endpoint("storage", Some("GRPC://host:1"))];
        let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
        assert_eq!(uri, "http://host:1");
        assert!(plaintext);
    }

    /// Bare authority with a local host class → plaintext. Today's
    /// "always http" default would also produce plaintext here; the
    /// test guards against the smart-detection variant breaking it.
    #[test]
    fn find_routes_bare_local_host_to_plaintext() {
        for raw in [
            "localhost:1",
            "127.0.0.1:1",
            "[::1]:1",
            "broker.local:1",
            "192.168.1.5:1",
        ] {
            let eps = vec![endpoint("storage", Some(raw))];
            let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
            assert!(plaintext, "expected plaintext for {raw}, got uri={uri}");
            assert!(
                uri.starts_with("http://"),
                "expected http:// for {raw}, got {uri}",
            );
        }
    }

    /// Bare authority with a public host class → TLS. An
    /// "always http" default would silently downgrade a public
    /// domain.
    #[test]
    fn find_routes_bare_public_host_to_tls() {
        for raw in ["example.com:1", "broker.example.com:1", "8.8.8.8:1"] {
            let eps = vec![endpoint("storage", Some(raw))];
            let (uri, plaintext) = find_grpc_endpoint_for_kind(&eps, "storage").unwrap();
            assert!(!plaintext, "expected TLS for {raw}, got uri={uri}");
            assert!(
                uri.starts_with("https://"),
                "expected https:// for {raw}, got {uri}",
            );
        }
    }
}
