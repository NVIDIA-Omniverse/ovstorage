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

/// Parsed connection config. Public so the `__test_only_*` hooks in
/// `lib.rs` can hand instances back to integration tests; the inner
/// fields stay `pub(crate)` to keep the runtime surface narrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureConnectionConfig {
    pub(crate) account: String,
    pub(crate) container: String,
    pub(crate) endpoint_suffix: String,
    pub(crate) hierarchical_namespace: bool,
    pub(crate) change_feed_enabled: bool,
    pub(crate) change_feed_segment_lag_seconds: u64,
    pub(crate) change_feed_poll_interval_seconds: u64,
    pub(crate) test_change_feed_endpoint: Option<String>,
    /// Test-only override for the data-path base URL (e.g.
    /// `http://127.0.0.1:NNNN`). When set, `blob_url_base()` /
    /// `dfs_url_base()` skip the natural `https://<account>.blob.<suffix>`
    /// construction and route at the override instead, so integration
    /// tests in `tests/precondition.rs` can point the backend at a
    /// capture-style fake server without needing TLS.
    pub(crate) test_endpoint_override: Option<String>,
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
        let hierarchical_namespace = optional_bool(&request.config, "hierarchical_namespace")?;
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
        let address_root = azure_address_root(&account, &container)?;

        Ok(Self {
            account,
            container,
            endpoint_suffix,
            hierarchical_namespace,
            change_feed_enabled,
            change_feed_segment_lag_seconds,
            change_feed_poll_interval_seconds,
            test_change_feed_endpoint,
            test_endpoint_override: None,
            address_root,
        })
    }

    pub(crate) fn blob_host(&self) -> String {
        format!("{}.blob.{}", self.account, self.endpoint_suffix)
    }

    pub(crate) fn dfs_host(&self) -> String {
        format!("{}.dfs.{}", self.account, self.endpoint_suffix)
    }

    /// Base `scheme://host[:port]` for blob-tier requests. Honors
    /// the `test_endpoint_override` hook so integration tests can
    /// route at a capture-style fake server over plain HTTP without
    /// the SAS-signing layer needing TLS.
    pub(crate) fn blob_url_base(&self) -> String {
        match self.test_endpoint_override.as_deref() {
            Some(base) => base.trim_end_matches('/').to_string(),
            None => format!("https://{}", self.blob_host()),
        }
    }

    /// Same shape as `blob_url_base()`, for DFS-tier HNS requests.
    pub(crate) fn dfs_url_base(&self) -> String {
        match self.test_endpoint_override.as_deref() {
            Some(base) => base.trim_end_matches('/').to_string(),
            None => format!("https://{}", self.dfs_host()),
        }
    }

    pub(crate) fn change_feed_base_url(&self) -> String {
        self.test_change_feed_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{}", self.blob_host()))
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
        let full_key = address::key(addr);
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
            !CONFIG_KEYS.contains(&key.as_str()) && key.as_str() != "__test_change_feed_endpoint"
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
) -> Result<Option<String>> {
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
    let value = clean_text(value, key)?;
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
    if !url_host_is_loopback(&parsed) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' is only supported for loopback test endpoints"),
        ));
    }
    Ok(Some(value.trim_end_matches('/').to_string()))
}

fn url_host_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.parse::<std::net::IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
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
