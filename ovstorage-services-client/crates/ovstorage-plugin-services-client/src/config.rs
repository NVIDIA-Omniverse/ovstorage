// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, CredentialField, CredentialMethod, Error, ErrorCode,
    Result,
};

pub const KIND: &str = "omniverse-storage-service";

pub fn config_schema() -> Vec<ConfigField> {
    vec![
        ConfigField {
            key: "discovery_url".into(),
            display_name: "Discovery URL".into(),
            kind: ConfigFieldKind::Url,
            required: true,
            default: None,
            help: Some(
                "Omniverse Storage Service discovery URL serving /api/v1/services and /api/v1/auth-config"
                    .into(),
            ),
            example: Some("https://omniverse-storage-service.example.com".into()),
            group: Some("server".into()),
            advanced: false,
        },
        ConfigField {
            key: "oidc_client_name".into(),
            display_name: "OIDC client name".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String("default".into())),
            help: Some("Selects which client entry from /api/v1/auth-config to drive".into()),
            example: None,
            group: Some("auth".into()),
            advanced: true,
        },
    ]
}

pub fn credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "oauth".into(),
            display_name: "OIDC token bundle".into(),
            default: None,
            help: Some(
                "Access + refresh token returned by the upstream IDP after PKCE / device flow"
                    .into(),
            ),
            advanced: false,
        },
        CredentialField {
            key: "client_id".into(),
            display_name: "Client ID".into(),
            default: None,
            help: Some("OIDC client identifier for client-credentials grants".into()),
            advanced: false,
        },
        CredentialField {
            key: "client_secret".into(),
            display_name: "Client secret".into(),
            default: None,
            help: Some("OIDC client secret paired with `client_id`".into()),
            advanced: false,
        },
    ]
}

pub fn credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "interactive".into(),
            display_name: "OIDC sign-in (browser / device flow)".into(),
            fields: vec!["oauth".into()],
            help: Some(
                "Recommended. Opens an OIDC sign-in flow in your browser or returns a device code."
                    .into(),
            ),
            advanced: false,
        },
        CredentialMethod {
            key: "client_credentials".into(),
            display_name: "OIDC client credentials (machine-to-machine)".into(),
            fields: vec!["client_id".into(), "client_secret".into()],
            help: Some(
                "For service identities: authenticates to the IDP with a client ID and secret \
                 instead of a user sign-in."
                    .into(),
            ),
            advanced: false,
        },
    ]
}

pub fn discovery_url(config: &HashMap<String, ConfigValue>) -> Result<String> {
    let raw = match config.get("discovery_url") {
        Some(ConfigValue::String(value)) => value.trim(),
        Some(_) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Discovery URL must be text",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Discovery URL is required",
            ));
        }
    };
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Discovery URL cannot be empty",
        ));
    }
    if trimmed.contains("://") {
        url::Url::parse(trimmed).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("Discovery URL is not a valid URL: {err}"),
            )
        })?;
        return Ok(trimmed.to_string());
    }
    let scheme = if should_infer_http(trimmed) {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{trimmed}"))
}

pub fn oidc_client_name(config: &HashMap<String, ConfigValue>) -> String {
    config
        .get("oidc_client_name")
        .and_then(|v| match v {
            ConfigValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "default".to_string())
}

fn should_infer_http(host_part: &str) -> bool {
    let host = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split(':')
        .next()
        .unwrap_or(host_part);
    if host == "localhost" {
        return true;
    }
    if host.ends_with(".local") {
        return true;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(value: &str) -> HashMap<String, ConfigValue> {
        let mut map = HashMap::new();
        map.insert("discovery_url".into(), ConfigValue::String(value.into()));
        map
    }

    #[test]
    fn infers_https_for_remote_host() {
        let url = discovery_url(&cfg("storage.example.com")).unwrap();
        assert_eq!(url, "https://storage.example.com");
    }

    #[test]
    fn infers_http_for_localhost() {
        let url = discovery_url(&cfg("localhost:8080")).unwrap();
        assert_eq!(url, "http://localhost:8080");
    }

    #[test]
    fn preserves_explicit_scheme() {
        let url = discovery_url(&cfg("https://storage.example.com:443/")).unwrap();
        assert_eq!(url, "https://storage.example.com:443");
    }

    #[test]
    fn rejects_empty() {
        let err = discovery_url(&cfg("   ")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
