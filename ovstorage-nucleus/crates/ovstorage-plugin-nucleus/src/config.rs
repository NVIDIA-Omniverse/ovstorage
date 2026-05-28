// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, ConnectionRequest, CredentialField,
    CredentialMethod, Error, ErrorCode, Result, Url, address,
};

use crate::address::{NUCLEUS_KIND, NUCLEUS_SCHEME, canonical_server_from_root};

#[derive(Clone, Debug)]
pub(crate) struct NucleusConfig {
    pub server: String,
    /// Optional SOWS discovery override.
    #[allow(dead_code)]
    pub endpoint: Option<String>,
    pub prefix: String,
    pub root: Url,
    /// When false, LFT redirects are disabled even if the server advertises an LFT endpoint.
    pub use_lft: bool,
}

impl NucleusConfig {
    pub fn from_request(request: &ConnectionRequest) -> Result<Self> {
        if request.backend_kind != NUCLEUS_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "connection request backend kind is not nucleus",
            ));
        }
        let server = config_string(&request.config, "server")?;
        validate_server(&server)?;
        // `url::Url` preserves host casing for non-special schemes like `omniverse`, so lowercase explicitly.
        let server = server.to_ascii_lowercase();
        let endpoint = optional_config_string(&request.config, "endpoint")?;
        let prefix = optional_config_string(&request.config, "prefix")?
            .map(|value| normalize_prefix(&value))
            .transpose()?
            .unwrap_or_else(|| "/".into());
        let root = address::parse(&format!("{NUCLEUS_SCHEME}://{server}/"))?;
        let use_lft = optional_config_bool(&request.config, "use_lft")?.unwrap_or(true);
        Ok(Self {
            server: canonical_server_from_root(&root)?,
            endpoint,
            prefix,
            root,
            use_lft,
        })
    }
}

fn optional_config_bool(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<bool>> {
    match config.get(key) {
        Some(ConfigValue::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be true or false"),
        )),
    }
}

pub(crate) fn nucleus_config_schema() -> Vec<ConfigField> {
    vec![
        ConfigField {
            key: "server".into(),
            display_name: "Server".into(),
            kind: ConfigFieldKind::Text,
            required: true,
            default: None,
            help: Some("Nucleus host[:port] used for omniverse:// address roots".into()),
            example: Some("localhost".into()),
            group: Some("provider".into()),
            advanced: false,
        },
        ConfigField {
            key: "endpoint".into(),
            display_name: "Discovery endpoint".into(),
            kind: ConfigFieldKind::Url,
            required: false,
            default: None,
            help: Some(
                "Optional SOWS discovery endpoint override (https://host[:port]); object addresses still use omniverse://server/"
                    .into(),
            ),
            example: Some("https://localhost:3019/".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "prefix".into(),
            display_name: "Provider path prefix".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String("/".into())),
            help: Some("Optional Nucleus path prefix that scopes which omni1 paths this backend will serve".into()),
            example: Some("/Projects".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "use_lft".into(),
            display_name: "Use LFT".into(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(true)),
            help: Some(
                "Hint for native large-file-transfer uploads above the server-advertised threshold".into(),
            ),
            example: None,
            group: Some("provider".into()),
            advanced: true,
        },
    ]
}

pub(crate) fn nucleus_credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "sso".into(),
            display_name: "Single sign-on (browser)".into(),
            fields: Vec::new(),
            help: Some(
                "Recommended. Authenticate by opening a URL in your browser; \
                 no credentials are stored locally."
                    .into(),
            ),
            advanced: false,
        },
        CredentialMethod {
            key: "userpass".into(),
            display_name: "Username and password".into(),
            fields: vec!["username".into(), "password".into()],
            help: Some("OmniAuth username and password.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "api_token".into(),
            display_name: "API token".into(),
            fields: vec!["api_token".into()],
            help: Some("OmniAuth API token; takes precedence over username/password.".into()),
            advanced: false,
        },
    ]
}

pub(crate) fn nucleus_credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "username".into(),
            display_name: "Username".into(),
            default: None,
            help: Some("OmniAuth username paired with `password`".into()),
            advanced: false,
        },
        CredentialField {
            key: "password".into(),
            display_name: "Password".into(),
            default: None,
            help: Some("OmniAuth password paired with `username`".into()),
            advanced: false,
        },
        CredentialField {
            key: "api_token".into(),
            display_name: "API token".into(),
            default: None,
            help: Some("OmniAuth API token; takes precedence over username/password".into()),
            advanced: false,
        },
    ]
}

fn config_string(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => Ok(value.trim().into()),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} cannot be empty"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} is required"),
        )),
    }
}

fn optional_config_string(
    config: &HashMap<String, ConfigValue>,
    key: &str,
) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().into()))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be text"),
        )),
    }
}

fn validate_server(server: &str) -> Result<()> {
    if server.contains("://")
        || server.contains('/')
        || server.contains('?')
        || server.contains('#')
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "server must be host[:port], not a URL",
        ));
    }
    if server.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "server is required"));
    }
    Ok(())
}

fn normalize_prefix(prefix: &str) -> Result<String> {
    if prefix.contains('?') || prefix.contains('#') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "prefix must not contain a query or fragment",
        ));
    }
    let mut normalized = if prefix.starts_with('/') {
        prefix.to_string()
    } else {
        format!("/{prefix}")
    };
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}
