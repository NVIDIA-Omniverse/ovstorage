// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-config parsing and `azure://` address parsing.
//!
//! Pulled out of `lib.rs` so the live backend, the auth resolver, and the
//! signing layer can share one canonical `AzureConnectionConfig` shape without
//! re-exporting validation helpers from the factory module.

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, ConnectionRequest, CredentialField,
    CredentialMethod, Error, ErrorCode, Result, SecretBundle, Url, address,
};

pub(crate) const BACKEND_KIND: &str = "azure";
pub(crate) const DEFAULT_ENDPOINT_SUFFIX: &str = "core.windows.net";
pub(crate) const CONFIG_KEYS: &[&str] = &[
    "account",
    "container",
    "endpoint_suffix",
    "blob_endpoint",
    "dfs_endpoint",
    "hierarchical_namespace",
    "change_feed_enabled",
    "change_feed_segment_lag_seconds",
    "change_feed_poll_interval_seconds",
];
pub(crate) const DEFAULT_CHANGE_FEED_SEGMENT_LAG_SECONDS: u64 = 60;
pub(crate) const DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS: u64 = 15;
pub(crate) const CREDENTIAL_KEYS: &[&str] = &[
    "account_key",
    "sas_token",
    "client_id",
    "client_secret",
    "tenant_id",
    "federated_token_file",
];

/// A fully specified service endpoint: the normalized
/// `scheme://host[:port][/path]` base with no trailing slash, plus the
/// URL path that precedes `/{container}` in a request URI.
///
/// `path_prefix` is `""` for host-style addressing
/// (`https://acct.blob.core.windows.net`) and `/seg[/seg]` for path-style
/// addressing (`http://127.0.0.1:10000/devstoreaccount1`), where it also
/// belongs in the Shared Key canonicalized resource.
///
/// The fields are private and derived in exactly one place
/// ([`AzureEndpoint::parse`]) so that no call site re-derives URL structure
/// from raw configuration text. That matters twice over: `base` is rebuilt
/// from the parsed URL, so a stray `?`, `#` or `@` cannot survive into the
/// string that request URLs are concatenated onto, and `https` records the
/// parser's case-folded scheme rather than a `starts_with` on that string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AzureEndpoint {
    base: String,
    path_prefix: String,
    authority: String,
    https: bool,
}

impl AzureEndpoint {
    /// Normalizes a full service URL. The only fallible constructor, and the
    /// only place the `base` / `path_prefix` / `authority` / `https`
    /// invariant is established.
    ///
    /// Only the addressing parts are accepted: a query, fragment, or
    /// URL-embedded credentials are rejected rather than silently dropped,
    /// because they would not survive into the signed request and the caller
    /// would see an endpoint that behaves differently from what it
    /// configured. What is rejected is *presence*, not non-emptiness — a
    /// bare trailing `?` or `#` is just as fatal, because request URLs are
    /// built by concatenating `/{container}/{key}` onto `base` and a
    /// delimiter left there would push the whole path into the query
    /// component while the Shared Key signature still covers the path.
    pub(crate) fn parse(raw: &str, key: &str) -> Result<Self> {
        let value = clean_text(raw, key)?;
        let parsed = Url::parse(&value).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must be an absolute URL: {err}"),
            )
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must use http or https"),
            ));
        }
        let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must include a host"),
            ));
        };
        if parsed.query().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must not include a query string"),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must not include a fragment"),
            ));
        }
        // `Url` drops syntactically-empty userinfo (`https://@host` parses
        // with an empty username and no password), so the raw authority is
        // the only place a caller's stray `@` is still visible.
        if raw_authority(&value).contains('@') {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure config field '{key}' must not embed credentials in the URL"),
            ));
        }
        // The SERIALIZED path, i.e. percent-encoded, and deliberately so on
        // both sides of its use.
        //
        // Azure's rule for the canonicalized resource is that any portion
        // derived from the request URI is "encoded exactly as it is in the
        // URI" — only query parameter names and values are decoded. That is
        // why the .NET signer takes `Uri.AbsolutePath` and the Go one
        // `EscapedPath()`. So one encoded string serves the request URL and
        // the signature, and `base` ending with `path_prefix` is a property
        // rather than a coincidence.
        //
        // The blob-key half follows the same rule: `canonical_path_for_blob`
        // runs the key through the same `url_encode_path` that `blob_url`
        // uses. Mixing the two conventions in one canonical string is what
        // produces an unexplained 403.
        let path_prefix = match parsed.path().trim_end_matches('/') {
            "" => String::new(),
            path => path.to_string(),
        };
        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        Ok(Self {
            base: format!("{}://{authority}{path_prefix}", parsed.scheme()),
            path_prefix,
            authority,
            https: parsed.scheme() == "https",
        })
    }

    /// The natural `https://{account}.{tier}.{endpoint_suffix}` endpoint.
    /// Infallible by construction: the host is assembled from an already
    /// validated account name and endpoint suffix, and host-style addressing
    /// carries no path prefix.
    fn host_style(host: &str) -> Self {
        Self {
            base: format!("https://{host}"),
            path_prefix: String::new(),
            authority: host.to_string(),
            https: true,
        }
    }

    /// `scheme://host[:port][/prefix]`, never with a trailing `/`.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The URL path preceding `/{container}`: `""` or `/seg[/seg]`, percent-
    /// ENCODED, so it is byte-identical in the request URI and the signature.
    pub(crate) fn path_prefix(&self) -> &str {
        &self.path_prefix
    }

    /// `host[:port]`, with the port elided when it is the scheme default.
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    /// Whether the host is a loopback IP literal (`127.0.0.1`, `[::1]`).
    ///
    /// Only an IP literal counts. A name that merely resolves to loopback
    /// today (`localhost`, a container alias) can resolve elsewhere
    /// tomorrow, and the point of this check is that nothing leaves the
    /// host — a property DNS cannot promise.
    pub(crate) fn is_loopback(&self) -> bool {
        // `authority` is already `host[:port]`, so only the port and any
        // IPv6 brackets have to come off. A bracketed literal keeps its own
        // colons, hence the all-digits test on the tail.
        let host = match self.authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            _ => self.authority.as_str(),
        };
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
    }

    /// Whether the normalized scheme is `https`. Read off the parser, so
    /// `HTTPS://host` counts as TLS-only the same as `https://host`.
    pub(crate) fn is_https(&self) -> bool {
        self.https
    }
}

/// The authority substring of a raw endpoint URL — `[userinfo@]host[:port]`.
/// Used only to spot userinfo the URL parser normalizes away.
fn raw_authority(raw: &str) -> &str {
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

/// Parsed connection config. Public so the `__test_only_*` hooks in
/// `lib.rs` can hand instances back to integration tests; the inner
/// fields stay `pub(crate)` to keep the runtime surface narrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureConnectionConfig {
    pub(crate) account: String,
    pub(crate) container: String,
    pub(crate) endpoint_suffix: String,
    /// Supported public analog of `test_endpoint_override` for the
    /// blob tier: a full service URL that replaces the
    /// `https://<account>.blob.<endpoint_suffix>` construction, so
    /// emulators (Azurite) and custom or sovereign endpoints are
    /// representable. Unlike the test-only hook it is not restricted to
    /// loopback hosts or to Shared Key credentials.
    pub(crate) blob_endpoint: Option<AzureEndpoint>,
    /// Blob-tier `blob_endpoint`'s DFS counterpart, used for ADLS Gen2
    /// requests when `hierarchical_namespace` is set.
    pub(crate) dfs_endpoint: Option<AzureEndpoint>,
    pub(crate) hierarchical_namespace: bool,
    pub(crate) change_feed_enabled: bool,
    pub(crate) change_feed_segment_lag_seconds: u64,
    pub(crate) change_feed_poll_interval_seconds: u64,
    pub(crate) test_change_feed_endpoint: Option<AzureEndpoint>,
    /// Test-only override for the data-path base URL (e.g.
    /// `http://127.0.0.1:NNNN`). When set, `blob_url_base()` /
    /// `dfs_url_base()` skip the natural `https://<account>.blob.<suffix>`
    /// construction and route at the override instead, so integration
    /// tests in `tests/precondition.rs` can point the backend at a
    /// capture-style fake server without needing TLS.
    pub(crate) test_endpoint_override: Option<AzureEndpoint>,
    pub(crate) address_root: Url,
}

impl AzureConnectionConfig {
    pub fn from_request(request: &ConnectionRequest) -> Result<Self> {
        if request.backend_kind != BACKEND_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "azure factory requires backend_kind 'azure'",
            ));
        }
        reject_unknown_config_keys(&request.config)?;
        validate_credential_keys(&request.credentials)?;

        let account = required_text(&request.config, "account")?;
        validate_account_name(&account)?;
        let container = required_text(&request.config, "container")?;
        validate_container_name(&container)?;
        let endpoint_suffix =
            optional_text(&request.config, "endpoint_suffix", DEFAULT_ENDPOINT_SUFFIX)?;
        validate_endpoint_suffix(&endpoint_suffix)?;
        let blob_endpoint = optional_endpoint(&request.config, "blob_endpoint")?;
        let dfs_endpoint = optional_endpoint(&request.config, "dfs_endpoint")?;
        let hierarchical_namespace = optional_bool(&request.config, "hierarchical_namespace")?;
        // One-directional on purpose. The two tiers resolve independently
        // (see `effective_blob_endpoint` / `effective_dfs_endpoint`), so a
        // lone `dfs_endpoint` is a supported shape: an operator may route the
        // DFS tier through a private gateway while the blob tier keeps
        // resolving from `endpoint_suffix`. What is refused is the one
        // combination that cannot mean what it says — moving the blob tier
        // off the public cloud while HNS path operations keep addressing the
        // public `dfs` suffix, which splits the connection across two
        // accounts.
        if hierarchical_namespace && blob_endpoint.is_some() && dfs_endpoint.is_none() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Azure connections with hierarchical_namespace and a custom \
                 'blob_endpoint' must also set 'dfs_endpoint'; otherwise DFS \
                 requests fall back to the public cloud host",
            ));
        }
        let change_feed_enabled = optional_bool(&request.config, "change_feed_enabled")?;
        let change_feed_segment_lag_seconds = optional_u64(
            &request.config,
            "change_feed_segment_lag_seconds",
            DEFAULT_CHANGE_FEED_SEGMENT_LAG_SECONDS,
        )?;
        let change_feed_poll_interval_seconds = optional_u64(
            &request.config,
            "change_feed_poll_interval_seconds",
            DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS,
        )?;
        let test_change_feed_endpoint = optional_test_endpoint(
            &request.config,
            &request.credentials,
            "__test_change_feed_endpoint",
        )?;
        let test_endpoint_override =
            optional_test_data_endpoint(&request.config, &request.credentials, "__test_endpoint")?;
        let address_root = azure_address_root(&account, &container)?;

        Ok(Self {
            account,
            container,
            endpoint_suffix,
            blob_endpoint,
            dfs_endpoint,
            hierarchical_namespace,
            change_feed_enabled,
            change_feed_segment_lag_seconds,
            change_feed_poll_interval_seconds,
            test_change_feed_endpoint,
            test_endpoint_override,
            address_root,
        })
    }

    pub(crate) fn blob_host(&self) -> String {
        format!("{}.blob.{}", self.account, self.endpoint_suffix)
    }

    pub(crate) fn dfs_host(&self) -> String {
        format!("{}.dfs.{}", self.account, self.endpoint_suffix)
    }

    /// The one resolution point for blob-tier addressing, in precedence
    /// order `test_endpoint_override` → `blob_endpoint` → the natural
    /// `https://<account>.blob.<endpoint_suffix>`.
    ///
    /// Returning the whole [`AzureEndpoint`] — rather than a base string the
    /// caller re-inspects — is what keeps base, canonical prefix and scheme
    /// from ever being resolved through different chains.
    fn effective_blob_endpoint(&self) -> AzureEndpoint {
        self.test_endpoint_override
            .clone()
            .or_else(|| self.blob_endpoint.clone())
            .unwrap_or_else(|| AzureEndpoint::host_style(&self.blob_host()))
    }

    /// [`Self::effective_blob_endpoint`]'s DFS-tier twin, resolving
    /// `test_endpoint_override` → `dfs_endpoint` → the natural
    /// `https://<account>.dfs.<endpoint_suffix>`.
    fn effective_dfs_endpoint(&self) -> AzureEndpoint {
        self.test_endpoint_override
            .clone()
            .or_else(|| self.dfs_endpoint.clone())
            .unwrap_or_else(|| AzureEndpoint::host_style(&self.dfs_host()))
    }

    /// The change feed lives in the blob tier's `$blobchangefeed` container,
    /// so it follows `blob_endpoint` — but the test-only change-feed hook
    /// redirects it independently of the data path, which is why it resolves
    /// through its own chain: `test_change_feed_endpoint` → `blob_endpoint` →
    /// the natural blob host. It deliberately ignores
    /// `test_endpoint_override`, whose scope is the data path.
    fn effective_change_feed_endpoint(&self) -> AzureEndpoint {
        self.test_change_feed_endpoint
            .clone()
            .or_else(|| self.blob_endpoint.clone())
            .unwrap_or_else(|| AzureEndpoint::host_style(&self.blob_host()))
    }

    /// Base `scheme://host[:port][/prefix]` for blob-tier requests. Honors
    /// the configured `blob_endpoint` and the `test_endpoint_override`
    /// hook, so emulators and capture-style fake servers are reachable
    /// over plain HTTP without the SAS-signing layer needing TLS.
    pub(crate) fn blob_url_base(&self) -> String {
        self.effective_blob_endpoint().base().to_string()
    }

    /// Same shape as `blob_url_base()`, for DFS-tier HNS requests.
    pub(crate) fn dfs_url_base(&self) -> String {
        self.effective_dfs_endpoint().base().to_string()
    }

    /// URL path that precedes `/{container}` in blob-tier request URIs, and
    /// therefore in the Shared Key canonicalized resource.
    ///
    /// Azure canonicalizes as `/{account}` followed by the request URI
    /// path, so a path-style emulator endpoint
    /// (`http://127.0.0.1:10000/devstoreaccount1`) signs as
    /// `/{account}/{account}/{container}/{key}`. Host-style addressing
    /// yields `""` and the familiar `/{account}/{container}/{key}`.
    // Resolved here so one place owns endpoint precedence; the request
    // builders in `backend.rs`/`subscription.rs` fold it into their
    // canonical paths.
    pub(crate) fn blob_canonical_prefix(&self) -> String {
        self.effective_blob_endpoint().path_prefix().to_string()
    }

    /// [`Self::blob_canonical_prefix`]'s DFS-tier twin. The same rule
    /// applies: the canonicalized resource is `/{account}` plus the request
    /// URI path, so a path-style DFS endpoint contributes its own prefix.
    pub(crate) fn dfs_canonical_prefix(&self) -> String {
        self.effective_dfs_endpoint().path_prefix().to_string()
    }

    /// Base URL for `$blobchangefeed` requests.
    pub(crate) fn change_feed_base_url(&self) -> String {
        self.effective_change_feed_endpoint().base().to_string()
    }

    /// [`Self::change_feed_base_url`]'s canonical-path counterpart. Paired
    /// with it through [`Self::effective_change_feed_endpoint`] so the URI a
    /// change-feed request is sent to and the resource it is signed against
    /// can never come from different endpoints — a mismatch Azure answers
    /// with a bare 403 rather than a routing error.
    pub(crate) fn change_feed_canonical_prefix(&self) -> String {
        self.effective_change_feed_endpoint()
            .path_prefix()
            .to_string()
    }

    /// Value for a Service SAS `spr` (signed protocol) field. Azure accepts
    /// only `https` or `https,http`; an HTTP emulator rejects a SAS pinned
    /// to `https`, so a plain-HTTP effective endpoint widens it. Widening is
    /// a real loosening of the signed URL, so the scheme comes from the URL
    /// parser and never from a prefix match on configuration text.
    // Consumed by the `spr` field of every Service SAS built in
    // `backend.rs`.
    pub(crate) fn sas_protocol(&self) -> &'static str {
        if self.effective_blob_endpoint().is_https() {
            "https"
        } else {
            "https,http"
        }
    }

    /// Whichever tier this connection will actually address resolves to a
    /// plain-HTTP endpoint that is not a loopback literal — the configuration
    /// that puts credentials and minted SAS URLs on a cleartext wire someone
    /// else can be on.
    ///
    /// Every tier that carries the credential is scanned, and each is included
    /// only when something will address it, so an inert endpoint cannot raise
    /// a warning about traffic that never happens:
    ///
    /// - blob, always;
    /// - DFS, under `hierarchical_namespace` — a flat namespace never issues
    ///   an ADLS Gen2 path operation;
    /// - the change feed, under `change_feed_enabled`. It resolves through its
    ///   OWN chain (`test_change_feed_endpoint` → `blob_endpoint` → the
    ///   natural host), so a loopback `__test_endpoint` on the data path does
    ///   not make it clean: `ChangeFeedClient` still follows `blob_endpoint`
    ///   and signs over that link.
    pub(crate) fn cleartext_offhost_endpoint(&self) -> Option<AzureEndpoint> {
        [
            Some(self.effective_blob_endpoint()),
            self.hierarchical_namespace
                .then(|| self.effective_dfs_endpoint()),
            self.change_feed_enabled
                .then(|| self.effective_change_feed_endpoint()),
        ]
        .into_iter()
        .flatten()
        .find(|endpoint| !endpoint.is_https() && !endpoint.is_loopback())
    }

    /// Short label identifying where this connection points, for
    /// diagnostics: the effective blob endpoint's `host[:port]` when an
    /// endpoint is configured, else the DNS `endpoint_suffix` that the
    /// natural host is derived from.
    pub(crate) fn endpoint_label(&self) -> String {
        if self.test_endpoint_override.is_none() && self.blob_endpoint.is_none() {
            return self.endpoint_suffix.clone();
        }
        self.effective_blob_endpoint().authority().to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AzureAddress {
    pub(crate) account: String,
    pub(crate) container: String,
    pub(crate) key: String,
    pub(crate) version_id: Option<String>,
}

impl AzureAddress {
    pub(crate) fn parse(addr: &Url) -> Result<Self> {
        if addr.scheme() != "azure" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "azure backend requires azure:// addresses",
            ));
        }
        let Some(account) = addr.host_str() else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "azure address must include an account and container",
            ));
        };
        // `key_utf8`, not `key`: the container and blob name reach an HTTP
        // URL path and the HMAC-signed SharedKey canonical string, both of
        // which are `&str`. A key those cannot spell is refused rather than
        // converted lossily, which would make the backend fetch one blob for
        // two distinct addresses.
        let full_key = address::key_utf8(addr)?;
        let Some((container, key)) = full_key.split_once('/') else {
            if full_key.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "azure address must include an account and container",
                ));
            }
            validate_account_name(account)?;
            validate_container_name(&full_key)?;
            return Ok(Self {
                account: account.to_string(),
                container: full_key,
                key: String::new(),
                version_id: extract_version_id(addr),
            });
        };
        validate_account_name(account)?;
        validate_container_name(container)?;
        Ok(Self {
            account: account.to_string(),
            container: container.to_string(),
            key: key.to_string(),
            version_id: extract_version_id(addr),
        })
    }
}

fn extract_version_id(addr: &Url) -> Option<String> {
    for (k, v) in addr.query_pairs() {
        if k.eq_ignore_ascii_case("versionid") || k == "versionId" {
            return Some(v.into_owned());
        }
    }
    None
}

pub(crate) fn azure_config_schema() -> Vec<ConfigField> {
    vec![
        text_field("account", "Account", true, Some("examplestorage"), false),
        text_field("container", "Container", true, Some("assets"), false),
        ConfigField {
            key: "endpoint_suffix".into(),
            display_name: "Endpoint suffix".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String(DEFAULT_ENDPOINT_SUFFIX.into())),
            help: Some("Azure DNS suffix for public or sovereign clouds".into()),
            example: Some(DEFAULT_ENDPOINT_SUFFIX.into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "blob_endpoint".into(),
            display_name: "Blob endpoint".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: None,
            help: Some(
                "Full blob service URL (scheme, host, optional port and path prefix) that \
                 overrides endpoint_suffix for the blob tier"
                    .into(),
            ),
            example: Some("http://127.0.0.1:10000/devstoreaccount1".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "dfs_endpoint".into(),
            display_name: "DFS endpoint".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: None,
            help: Some(
                "Full ADLS Gen2 (DFS) service URL (scheme, host, optional port and path prefix) \
                 that overrides endpoint_suffix for the DFS tier"
                    .into(),
            ),
            example: Some("http://127.0.0.1:10000/devstoreaccount1".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "hierarchical_namespace".into(),
            display_name: "Hierarchical namespace".into(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(false)),
            help: Some(
                "When true, the connection is treated as an ADLS Gen2/HNS filesystem".into(),
            ),
            example: None,
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "change_feed_enabled".into(),
            display_name: "Change feed enabled".into(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(false)),
            help: Some("Enable watch_directory via Azure Blob Change Feed".into()),
            example: None,
            group: Some("watch".into()),
            advanced: true,
        },
        watch_int_field(
            "change_feed_segment_lag_seconds",
            "Change feed segment lag seconds",
            DEFAULT_CHANGE_FEED_SEGMENT_LAG_SECONDS as i64,
            "Delay segment reads to avoid provider-side open-segment races",
            Some("60"),
        ),
        watch_int_field(
            "change_feed_poll_interval_seconds",
            "Change feed poll interval seconds",
            DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS as i64,
            "Polling interval for Blob Change Feed discovery",
            Some("15"),
        ),
    ]
}

pub(crate) fn azure_credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "account_key".into(),
            display_name: "Account key".into(),
            fields: vec!["account_key".into()],
            help: Some("Long-lived storage account key for Shared Key signing.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "sas_token".into(),
            display_name: "SAS token".into(),
            fields: vec!["sas_token".into()],
            help: Some("Pre-issued shared-access signature appended to request URLs.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "service_principal".into(),
            display_name: "Service principal (client secret)".into(),
            fields: vec![
                "client_id".into(),
                "client_secret".into(),
                "tenant_id".into(),
            ],
            help: Some("Entra ID service principal authenticating with a client secret.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "workload_identity".into(),
            display_name: "Workload identity".into(),
            fields: vec![
                "federated_token_file".into(),
                "client_id".into(),
                "tenant_id".into(),
            ],
            help: Some(
                "Federated workload identity using a token file (replaces client secret).".into(),
            ),
            advanced: false,
        },
    ]
}

pub(crate) fn azure_credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "account_key".into(),
            display_name: "Account key".into(),
            default: Some("${AZURE_STORAGE_ACCOUNT_KEY}".into()),
            help: Some("Optional storage account key used for Shared Key signing".into()),
            advanced: false,
        },
        CredentialField {
            key: "sas_token".into(),
            display_name: "SAS token".into(),
            default: Some("${AZURE_STORAGE_SAS_TOKEN}".into()),
            help: Some("Optional pre-issued SAS token appended to request URLs".into()),
            advanced: false,
        },
        CredentialField {
            key: "client_id".into(),
            display_name: "Client ID".into(),
            default: Some("${AZURE_CLIENT_ID}".into()),
            help: Some("Entra ID service-principal client ID for OAuth2 client_credentials".into()),
            advanced: false,
        },
        CredentialField {
            key: "client_secret".into(),
            display_name: "Client secret".into(),
            default: Some("${AZURE_CLIENT_SECRET}".into()),
            help: Some("Entra ID service-principal secret".into()),
            advanced: false,
        },
        CredentialField {
            key: "tenant_id".into(),
            display_name: "Tenant ID".into(),
            default: Some("${AZURE_TENANT_ID}".into()),
            help: Some("Entra ID tenant containing the service principal".into()),
            advanced: false,
        },
        CredentialField {
            key: "federated_token_file".into(),
            display_name: "Federated token file".into(),
            default: Some("${AZURE_FEDERATED_TOKEN_FILE}".into()),
            help: Some(
                "Path to a workload-identity federated assertion token file (replaces client_secret)".into(),
            ),
            advanced: false,
        },
    ]
}

fn text_field(
    key: &str,
    display_name: &str,
    required: bool,
    example: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required,
        default: None,
        help: None,
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

pub(crate) fn reject_unknown_config_keys(config: &HashMap<String, ConfigValue>) -> Result<()> {
    let mut unknown = config
        .keys()
        .filter(|key| {
            !CONFIG_KEYS.contains(&key.as_str())
                && key.as_str() != "__test_change_feed_endpoint"
                && key.as_str() != "__test_endpoint"
        })
        .cloned()
        .collect::<Vec<_>>();
    unknown.sort();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown Azure config field(s): {}", unknown.join(", ")),
        ))
    }
}

pub(crate) fn validate_credential_keys(credentials: &SecretBundle) -> Result<()> {
    let mut unknown = credentials
        .fields
        .keys()
        .filter(|key| !CREDENTIAL_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unknown.sort();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown Azure credential field(s): {}", unknown.join(", ")),
        ))
    }
}

fn required_text(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => clean_text(value, key),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be text"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required Azure config field '{key}'"),
        )),
    }
}

fn optional_text(
    config: &HashMap<String, ConfigValue>,
    key: &str,
    default: &str,
) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => clean_text(value, key),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be text"),
        )),
        None => Ok(default.into()),
    }
}

fn optional_endpoint(
    config: &HashMap<String, ConfigValue>,
    key: &str,
) -> Result<Option<AzureEndpoint>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => AzureEndpoint::parse(value, key).map(Some),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be text"),
        )),
        None => Ok(None),
    }
}

fn clean_text(value: &str, key: &str) -> Result<String> {
    if value.is_empty() || value != value.trim() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must not be empty or padded"),
        ));
    }
    Ok(value.to_string())
}

fn optional_bool(config: &HashMap<String, ConfigValue>, key: &str) -> Result<bool> {
    match config.get(key) {
        Some(ConfigValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be bool"),
        )),
        None => Ok(false),
    }
}

fn optional_u64(config: &HashMap<String, ConfigValue>, key: &str, default: u64) -> Result<u64> {
    match config.get(key) {
        Some(ConfigValue::Int(value)) if *value >= 0 => Ok(*value as u64),
        Some(ConfigValue::Int(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be non-negative"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be integer"),
        )),
        None => Ok(default),
    }
}

fn optional_test_endpoint(
    config: &HashMap<String, ConfigValue>,
    credentials: &SecretBundle,
    key: &str,
) -> Result<Option<AzureEndpoint>> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    if !credentials.fields.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' is only supported for anonymous loopback tests"),
        ));
    }
    let ConfigValue::String(value) = value else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be text"),
        ));
    };
    require_loopback_endpoint(value, key)
}

/// Loopback-only data-path override for the connection-lifecycle
/// integration tests (the analog of `__test_change_feed_endpoint` for the
/// blob/DFS data path). Unlike the change-feed override it admits
/// credentials, but ONLY the `account_key` shape: Shared Key signing sends an
/// HMAC signature over the wire, never the secret itself, while SAS tokens
/// and OAuth secrets are bearer-style and would travel to the endpoint
/// verbatim — those stay refused.
fn optional_test_data_endpoint(
    config: &HashMap<String, ConfigValue>,
    credentials: &SecretBundle,
    key: &str,
) -> Result<Option<AzureEndpoint>> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    if credentials
        .fields
        .keys()
        .any(|field| field != "account_key")
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "Azure config field '{key}' is only supported for anonymous or \
                 Shared Key loopback tests (bearer-style credentials would be \
                 sent to the test endpoint)"
            ),
        ));
    }
    let ConfigValue::String(value) = value else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be text"),
        ));
    };
    require_loopback_endpoint(value, key)
}

/// Shared tail of both `__test_*` endpoint hooks: normalize through the same
/// [`AzureEndpoint::parse`] the public keys use — so a test hook can never
/// carry a shape the supported keys refuse — then hold it to loopback.
fn require_loopback_endpoint(raw: &str, key: &str) -> Result<Option<AzureEndpoint>> {
    let endpoint = AzureEndpoint::parse(raw, key)?;
    // One implementation of loopback classification, shared with the
    // cleartext-endpoint warning — two would be free to drift on authority
    // or IPv6 handling and then disagree about what counts as local.
    if !endpoint.is_loopback() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' is only supported for loopback test endpoints"),
        ));
    }
    Ok(Some(endpoint))
}

fn watch_int_field(
    key: &str,
    display_name: &str,
    default: i64,
    help: &str,
    example: Option<&str>,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Integer,
        required: false,
        default: Some(ConfigValue::Int(default)),
        help: Some(help.into()),
        example: example.map(str::to_string),
        group: Some("watch".into()),
        advanced: true,
    }
}

pub(crate) fn validate_account_name(value: &str) -> Result<()> {
    if (3..=24).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "Azure account must be 3-24 lowercase letters or digits",
        ))
    }
}

pub(crate) fn validate_container_name(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let valid_len = (3..=63).contains(&bytes.len());
    let valid_chars = bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    let valid_edges = bytes
        .first()
        .zip(bytes.last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    let no_double_hyphen = !value.contains("--");
    if valid_len && valid_chars && valid_edges && no_double_hyphen {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "Azure container must be 3-63 lowercase letters, digits, or single hyphens",
        ))
    }
}

pub(crate) fn validate_endpoint_suffix(value: &str) -> Result<()> {
    let has_bad_syntax = value.contains("://")
        || value.contains(['/', '\\', '?', '#', ':'])
        || value.starts_with('.')
        || value.ends_with('.');
    let valid_labels = value.split('.').all(valid_dns_label);
    if !has_bad_syntax && valid_labels {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "Azure endpoint_suffix must be a DNS suffix without scheme or path",
        ))
    }
}

fn valid_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && bytes
            .first()
            .zip(bytes.last())
            .is_some_and(|(first, last)| {
                first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
            })
}

pub(crate) fn azure_address_root(account: &str, container: &str) -> Result<Url> {
    address::parse(&format!("azure://{account}/{container}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(pairs: &[(&str, ConfigValue)]) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("account".into(), ConfigValue::String("acct123".into()));
        config.insert("container".into(), ConfigValue::String("assets".into()));
        for (key, value) in pairs {
            config.insert((*key).into(), value.clone());
        }
        ConnectionRequest {
            backend_kind: BACKEND_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    fn parse_blob_endpoint(raw: &str) -> Result<Option<AzureEndpoint>> {
        AzureConnectionConfig::from_request(&request_with(&[(
            "blob_endpoint",
            ConfigValue::String(raw.into()),
        )]))
        .map(|config| config.blob_endpoint)
    }

    fn expect_rejected(raw: &str) -> Error {
        let err = parse_blob_endpoint(raw)
            .expect_err(&format!("expected blob_endpoint '{raw}' to be rejected"));
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "input: {raw}");
        assert!(
            err.message().contains("blob_endpoint"),
            "message should name the key, got: {}",
            err.message()
        );
        err
    }

    #[test]
    fn azurite_url_splits_into_base_and_path_prefix() {
        let endpoint = parse_blob_endpoint("http://127.0.0.1:10000/devstoreaccount1")
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.base(), "http://127.0.0.1:10000/devstoreaccount1");
        assert_eq!(endpoint.path_prefix(), "/devstoreaccount1");
        assert_eq!(endpoint.authority(), "127.0.0.1:10000");
        assert!(!endpoint.is_https());
    }

    #[test]
    fn bare_host_has_no_path_prefix() {
        let endpoint = parse_blob_endpoint("https://blob.example.com")
            .unwrap()
            .unwrap();
        assert_eq!(endpoint.base(), "https://blob.example.com");
        assert_eq!(endpoint.path_prefix(), "");
        assert!(endpoint.is_https());
    }

    #[test]
    fn trailing_slash_is_trimmed_from_base_and_prefix() {
        let rooted = parse_blob_endpoint("https://blob.example.com/")
            .unwrap()
            .unwrap();
        assert_eq!(rooted.base(), "https://blob.example.com");
        assert_eq!(rooted.path_prefix(), "");

        let prefixed = parse_blob_endpoint("http://azurite:10000/devstoreaccount1/")
            .unwrap()
            .unwrap();
        assert_eq!(prefixed.base(), "http://azurite:10000/devstoreaccount1");
        assert_eq!(prefixed.path_prefix(), "/devstoreaccount1");
    }

    /// `base` is rebuilt from the parsed URL, not echoed from the caller's
    /// text, so scheme and host case-fold and a redundant default port
    /// disappears. `is_https` reads the same parsed scheme — a widened SAS
    /// `spr` on a TLS-only endpoint would be a real loosening of the signed
    /// URL, so it must not hinge on how the operator capitalized things.
    #[test]
    fn base_is_normalized_from_the_parsed_url() {
        let mixed = parse_blob_endpoint("HTTPS://Blob.Example.COM/Prefix")
            .unwrap()
            .unwrap();
        assert_eq!(mixed.base(), "https://blob.example.com/Prefix");
        assert_eq!(mixed.path_prefix(), "/Prefix");
        assert!(mixed.is_https());

        let default_port = parse_blob_endpoint("https://blob.example.com:443")
            .unwrap()
            .unwrap();
        assert_eq!(default_port.base(), "https://blob.example.com");
        assert_eq!(default_port.authority(), "blob.example.com");

        let ipv6 = parse_blob_endpoint("http://[::1]:10000/devstoreaccount1")
            .unwrap()
            .unwrap();
        assert_eq!(ipv6.base(), "http://[::1]:10000/devstoreaccount1");
        assert_eq!(ipv6.authority(), "[::1]:10000");
    }

    #[test]
    fn absent_endpoints_stay_none() {
        let config = AzureConnectionConfig::from_request(&request_with(&[])).unwrap();
        assert_eq!(config.blob_endpoint, None);
        assert_eq!(config.dfs_endpoint, None);
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        for raw in [
            "ftp://host/path",
            "not-a-url",
            "https://h/p?x=1",
            "https://h/p#f",
            "https://user:pw@h",
            "",
            " https://h ",
            // Empty delimiters are rejected on presence, not on content:
            // request URLs are built by concatenating `/{container}/{key}`
            // onto the base, so a surviving `?` or `#` would move the whole
            // path out of the path component while Shared Key still signs
            // it as a path, and a surviving `@` would reinterpret the host.
            "https://h/p?",
            "https://h/p#",
            "https://@h",
            "https://:@h",
        ] {
            expect_rejected(raw);
        }
    }

    #[test]
    fn non_text_endpoint_is_rejected() {
        let err = AzureConnectionConfig::from_request(&request_with(&[(
            "blob_endpoint",
            ConfigValue::Bool(true),
        )]))
        .expect_err("bool blob_endpoint must be rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("blob_endpoint"));
    }

    #[test]
    fn hns_with_blob_endpoint_requires_dfs_endpoint() {
        let err = AzureConnectionConfig::from_request(&request_with(&[
            ("hierarchical_namespace", ConfigValue::Bool(true)),
            (
                "blob_endpoint",
                ConfigValue::String("http://127.0.0.1:10000/devstoreaccount1".into()),
            ),
        ]))
        .expect_err("HNS with only blob_endpoint must be rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("dfs_endpoint"),
            "message should name the missing key, got: {}",
            err.message()
        );

        let config = AzureConnectionConfig::from_request(&request_with(&[
            ("hierarchical_namespace", ConfigValue::Bool(true)),
            (
                "blob_endpoint",
                ConfigValue::String("http://127.0.0.1:10000/devstoreaccount1".into()),
            ),
            (
                "dfs_endpoint",
                ConfigValue::String("http://127.0.0.1:10001/devstoreaccount1".into()),
            ),
        ]))
        .unwrap();
        assert_eq!(
            config.dfs_endpoint.unwrap().base(),
            "http://127.0.0.1:10001/devstoreaccount1"
        );
    }

    /// The guard is one-directional, and this is the direction it does NOT
    /// refuse: a deployment whose DFS tier sits behind a private gateway
    /// while the blob tier is correctly addressed by `endpoint_suffix` is a
    /// real shape, and the tiers resolve independently precisely so it is
    /// expressible without an undocumented incantation.
    #[test]
    fn hns_with_only_a_dfs_endpoint_is_supported() {
        let config = AzureConnectionConfig::from_request(&request_with(&[
            ("hierarchical_namespace", ConfigValue::Bool(true)),
            (
                "dfs_endpoint",
                ConfigValue::String("https://private.dfs.example.com".into()),
            ),
        ]))
        .expect("a DFS-only override is a supported HNS shape");
        // The DFS tier moves; the blob tier stays where `endpoint_suffix`
        // puts it, which is the whole point of accepting this.
        assert_eq!(config.dfs_url_base(), "https://private.dfs.example.com");
        assert_eq!(
            config.blob_url_base(),
            "https://acct123.blob.core.windows.net"
        );

        // Without HNS the blob tier is the only tier, so a lone
        // `dfs_endpoint` is inert rather than wrong.
        AzureConnectionConfig::from_request(&request_with(&[(
            "dfs_endpoint",
            ConfigValue::String("http://azurite:10001/devstoreaccount1".into()),
        )]))
        .expect("flat namespace does not require a paired blob_endpoint");
    }

    /// A prefix needing percent-escaping is the only case that can tell the
    /// request URL and the signed prefix apart — every other prefix in these
    /// tests is encoding-invariant, which is why a mismatch could survive.
    ///
    /// Both carry the ENCODED path: Azure canonicalizes URI-derived parts of
    /// the resource exactly as the URI spells them, so `base` ends with
    /// `path_prefix` and the signature reproduces what was addressed.
    #[test]
    fn a_path_prefix_needing_escapes_is_encoded_in_both_the_url_and_the_signature() {
        // A literal space: the WHATWG parser percent-encodes it into the
        // serialized path, so this is the spelling an operator writes.
        let endpoint = parse_blob_endpoint("http://host:10000/dev store")
            .unwrap()
            .unwrap();
        assert_eq!(
            endpoint.base(),
            "http://host:10000/dev%20store",
            "the request URL must carry the encoded path"
        );
        assert_eq!(
            endpoint.path_prefix(),
            "/dev%20store",
            "the signed prefix must be the SAME bytes the URL carries"
        );
        assert!(
            endpoint.base().ends_with(endpoint.path_prefix()),
            "base and path_prefix are one string, so they cannot diverge"
        );

        // The same when the caller pre-encodes it, and for a non-ASCII
        // segment.
        assert_eq!(
            parse_blob_endpoint("http://host:10000/dev%20store")
                .unwrap()
                .unwrap(),
            endpoint,
            "both spellings normalize alike"
        );
        let unicode = parse_blob_endpoint("http://host:10000/vår-lagring")
            .unwrap()
            .unwrap();
        assert_eq!(unicode.path_prefix(), "/v%C3%A5r-lagring");
        assert!(unicode.base().ends_with(unicode.path_prefix()));

        // Signing the path as-is means an escape this plugin cannot decode
        // is not this plugin's problem: it passes through untouched, exactly
        // as the URI carries it.
        let odd = parse_blob_endpoint("http://host:10000/bad%FFsegment")
            .expect("a non-UTF-8 escape is not a config error")
            .unwrap();
        assert_eq!(odd.path_prefix(), "/bad%FFsegment");
        assert!(odd.base().ends_with(odd.path_prefix()));
    }

    fn config_with(pairs: &[(&str, ConfigValue)]) -> AzureConnectionConfig {
        AzureConnectionConfig::from_request(&request_with(pairs)).unwrap()
    }

    #[test]
    fn natural_hosts_are_the_default_bases() {
        let config = config_with(&[]);
        assert_eq!(
            config.blob_url_base(),
            "https://acct123.blob.core.windows.net"
        );
        assert_eq!(
            config.dfs_url_base(),
            "https://acct123.dfs.core.windows.net"
        );
        assert_eq!(config.blob_canonical_prefix(), "");
        assert_eq!(config.dfs_canonical_prefix(), "");
        assert_eq!(config.endpoint_label(), "core.windows.net");
    }

    #[test]
    fn blob_endpoint_overrides_base_and_supplies_prefix() {
        let config = config_with(&[(
            "blob_endpoint",
            ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
        )]);
        assert_eq!(
            config.blob_url_base(),
            "http://azurite:10000/devstoreaccount1"
        );
        assert_eq!(config.blob_canonical_prefix(), "/devstoreaccount1");
        assert_eq!(config.endpoint_label(), "azurite:10000");
    }

    #[test]
    fn dfs_endpoint_is_independent_of_blob_endpoint() {
        let config = config_with(&[(
            "blob_endpoint",
            ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
        )]);
        // Blob-only config leaves the DFS tier on its natural host.
        assert_eq!(
            config.dfs_url_base(),
            "https://acct123.dfs.core.windows.net"
        );
        assert_eq!(config.dfs_canonical_prefix(), "");

        let config = config_with(&[
            (
                "blob_endpoint",
                ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
            ),
            (
                "dfs_endpoint",
                ConfigValue::String("http://azurite:10001/devstoreaccount1".into()),
            ),
        ]);
        assert_eq!(
            config.blob_url_base(),
            "http://azurite:10000/devstoreaccount1"
        );
        assert_eq!(
            config.dfs_url_base(),
            "http://azurite:10001/devstoreaccount1"
        );
        assert_eq!(config.dfs_canonical_prefix(), "/devstoreaccount1");
    }

    #[test]
    fn test_endpoint_override_still_wins_over_blob_endpoint() {
        let config = config_with(&[
            (
                "blob_endpoint",
                ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
            ),
            (
                "__test_endpoint",
                ConfigValue::String("http://127.0.0.1:9999/emulated".into()),
            ),
        ]);
        assert_eq!(config.blob_url_base(), "http://127.0.0.1:9999/emulated");
        assert_eq!(config.dfs_url_base(), "http://127.0.0.1:9999/emulated");
        // The bare override string still yields a signable prefix.
        assert_eq!(config.blob_canonical_prefix(), "/emulated");
        assert_eq!(config.dfs_canonical_prefix(), "/emulated");
        assert_eq!(config.endpoint_label(), "127.0.0.1:9999");
    }

    #[test]
    fn change_feed_follows_blob_endpoint_unless_overridden() {
        let config = config_with(&[]);
        assert_eq!(
            config.change_feed_base_url(),
            "https://acct123.blob.core.windows.net"
        );

        let config = config_with(&[(
            "blob_endpoint",
            ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
        )]);
        assert_eq!(
            config.change_feed_base_url(),
            "http://azurite:10000/devstoreaccount1"
        );

        let config = config_with(&[
            (
                "blob_endpoint",
                ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
            ),
            (
                "__test_change_feed_endpoint",
                ConfigValue::String("http://127.0.0.1:9998".into()),
            ),
        ]);
        assert_eq!(config.change_feed_base_url(), "http://127.0.0.1:9998");
    }

    /// The change-feed base URL and the prefix it is signed against resolve
    /// through one endpoint, so no combination of hooks can send a request
    /// to one host while canonicalizing it against another's prefix.
    #[test]
    fn change_feed_base_and_prefix_resolve_together() {
        let config = config_with(&[(
            "blob_endpoint",
            ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
        )]);
        assert_eq!(
            config.change_feed_base_url(),
            "http://azurite:10000/devstoreaccount1"
        );
        assert_eq!(config.change_feed_canonical_prefix(), "/devstoreaccount1");

        // The change-feed hook takes the whole endpoint with it — base and
        // prefix both — rather than leaving the blob endpoint's prefix
        // signed against a different host.
        let config = config_with(&[
            (
                "blob_endpoint",
                ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
            ),
            (
                "__test_change_feed_endpoint",
                ConfigValue::String("http://127.0.0.1:9998".into()),
            ),
        ]);
        assert_eq!(config.change_feed_base_url(), "http://127.0.0.1:9998");
        assert_eq!(config.change_feed_canonical_prefix(), "");

        // The data-path hook has no say over the change feed, so it must
        // not leak its prefix into the change-feed signature either.
        let config = config_with(&[(
            "__test_endpoint",
            ConfigValue::String("http://127.0.0.1:9999/emulated".into()),
        )]);
        assert_eq!(
            config.change_feed_base_url(),
            "https://acct123.blob.core.windows.net"
        );
        assert_eq!(config.change_feed_canonical_prefix(), "");
    }

    #[test]
    fn sas_protocol_widens_only_for_http_endpoints() {
        assert_eq!(config_with(&[]).sas_protocol(), "https");
        assert_eq!(
            config_with(&[(
                "blob_endpoint",
                ConfigValue::String("https://blob.example.com".into()),
            )])
            .sas_protocol(),
            "https"
        );
        // URL schemes are case-insensitive; a mixed-case one is still
        // TLS-only and must not widen `spr` to `https,http`.
        assert_eq!(
            config_with(&[(
                "blob_endpoint",
                ConfigValue::String("HTTPS://myaccount.privatelink.blob.core.windows.net".into()),
            )])
            .sas_protocol(),
            "https"
        );
        assert_eq!(
            config_with(&[(
                "blob_endpoint",
                ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
            )])
            .sas_protocol(),
            "https,http"
        );
    }

    #[test]
    fn endpoint_keys_are_accepted_and_published() {
        assert!(CONFIG_KEYS.contains(&"blob_endpoint"));
        assert!(CONFIG_KEYS.contains(&"dfs_endpoint"));
        let keys = azure_config_schema()
            .iter()
            .map(|field| field.key.clone())
            .collect::<Vec<_>>();
        let suffix = keys
            .iter()
            .position(|key| key == "endpoint_suffix")
            .expect("endpoint_suffix is in the schema");
        assert_eq!(keys[suffix + 1], "blob_endpoint");
        assert_eq!(keys[suffix + 2], "dfs_endpoint");
    }
}
