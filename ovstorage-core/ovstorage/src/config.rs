// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Config types deserialized from `ovstorage.toml`. Lives in
//! `ovstorage` (not `ovstorage-plugin`) because the Layer 0 plugin ABI
//! avoids `serde`. Plugins consume already-resolved
//! [`SecretBundle`]s via `ConnectionRequest`.

use std::collections::HashMap;
use std::path::PathBuf;

use ovstorage_plugin::{
    ConfigValue, ConnectionRequest, Error, ErrorCode, Result, SecretBundle, SecretBytes,
    SecretValue, resolve_env_refs,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<PathBuf>,
}

/// Credentials are stored as UTF-8 strings. `${NAME}` references are
/// substituted from the process environment at `to_connection_request`
/// time via [`resolve_env_refs`]. Any string not matching the strict
/// POSIX form `${[A-Za-z_][A-Za-z0-9_]*}` (e.g. `${env:NAME}`,
/// `${VAR:-default}`) passes through literally with no error.
/// Plugins that take binary keys must declare them as base64-encoded
/// strings in their descriptor.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConnectionConfig {
    pub backend_kind: String,
    /// Name of the layer this connection attaches to. Resolved to a
    /// concrete target (default: `backend_kind`) when a Stack is built;
    /// stored here only so an explicit choice round-trips through TOML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, toml::Value>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub credentials: HashMap<String, String>,
}

impl ConnectionConfig {
    /// Project a live [`ConnectionRequest`] to declarative connection config.
    ///
    /// The request's live credential bundle and its `persist` flag are dropped:
    /// a `ConnectionConfig` carries only `${ENV}`-style credential *references*,
    /// never consumed secrets. Each flat `config` value marshals back to its TOML
    /// value; `target` is left unset (it defaults to `backend_kind` at build time).
    pub fn from_request(request: ConnectionRequest) -> Self {
        Self {
            backend_kind: request.backend_kind,
            target: None,
            display_name: request.display_name,
            config: request
                .config
                .iter()
                .map(|(key, value)| (key.clone(), config_value_to_toml(value)))
                .collect(),
            credentials: HashMap::new(),
        }
    }
}
/// Candidate paths in resolution order.
pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("./ovstorage.toml")];
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    if let Some(base) = xdg {
        paths.push(base.join("ovstorage").join("ovstorage.toml"));
    }
    paths
}

impl ConnectionConfig {
    /// Substitutes `${NAME}` references in credential values against
    /// the process environment.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NotConfigured`] — a credential value references an
    ///   environment variable that is not set.
    pub fn to_connection_request(&self) -> Result<ConnectionRequest> {
        let mut config = HashMap::with_capacity(self.config.len());
        for (key, value) in &self.config {
            config.insert(key.clone(), config_value_from_toml(key, value)?);
        }

        let mut credentials = SecretBundle::default();
        for (key, raw) in &self.credentials {
            let resolved = resolve_env_refs(raw).map_err(|err| {
                Error::new(
                    err.code(),
                    format!("credential '{key}': {message}", message = err.message()),
                )
            })?;
            credentials.fields.insert(
                key.clone(),
                SecretValue::Bytes(SecretBytes(resolved.into_bytes())),
            );
        }

        Ok(ConnectionRequest {
            backend_kind: self.backend_kind.clone(),
            config,
            credentials,
            persist: false,
            display_name: self.display_name.clone(),
        })
    }
}

/// Inverse of [`config_value_from_toml`]. `ConfigValue::Toml`
/// payloads reparse into their original nested shape; parse failure
/// falls back to a plain string so the round-trip never panics.
pub fn config_value_to_toml(value: &ConfigValue) -> toml::Value {
    match value {
        ConfigValue::String(s) => toml::Value::String(s.clone()),
        ConfigValue::Int(i) => toml::Value::Integer(*i),
        ConfigValue::Bool(b) => toml::Value::Boolean(*b),
        ConfigValue::Toml(s) => s
            .parse::<toml::Value>()
            .unwrap_or_else(|_| toml::Value::String(s.clone())),
    }
}

/// Hybrid model: top-level scalars map to matching `ConfigValue`
/// variants; tables and arrays reserialize to `ConfigValue::Toml` (the
/// plugin parses on receipt). No path-named-key heuristic — the host
/// doesn't know which keys are paths.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the TOML value is a float or datetime
///   (not supported), or serialization of nested structures fails.
pub fn config_value_from_toml(key: &str, value: &toml::Value) -> Result<ConfigValue> {
    match value {
        toml::Value::String(value) => Ok(ConfigValue::String(value.clone())),
        toml::Value::Integer(value) => Ok(ConfigValue::Int(*value)),
        toml::Value::Boolean(value) => Ok(ConfigValue::Bool(*value)),
        toml::Value::Table(_) | toml::Value::Array(_) => {
            // Wrap under the field key so arrays-of-tables round-trip
            // as `[[<key>]]` (toml::to_string needs a top-level table).
            let mut wrapper = toml::value::Table::new();
            wrapper.insert(key.to_string(), value.clone());
            let toml_string = toml::to_string(&toml::Value::Table(wrapper)).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("config field '{key}' is nested and could not be reserialized: {err}"),
                )
            })?;
            Ok(ConfigValue::Toml(toml_string))
        }
        toml::Value::Float(_) | toml::Value::Datetime(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "config field '{key}' has an unsupported type \
                 (only string, integer, boolean, table, and array are accepted)"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_to_request_substitutes_env_vars() {
        let var = "OVSTORAGE_TEST_CONNCONFIG_TOREQUEST";
        // SAFETY: single-threaded test; var name is unique.
        unsafe { std::env::set_var(var, "env-secret") };

        let mut creds = HashMap::new();
        creds.insert("token".to_string(), format!("${{{var}}}"));
        creds.insert("api_key".to_string(), "inline-secret".to_string());
        let mut config = HashMap::new();
        config.insert("bucket".into(), toml::Value::String("b".into()));
        config.insert("port".into(), toml::Value::Integer(443));
        config.insert("verify_tls".into(), toml::Value::Boolean(true));
        config.insert("root".into(), toml::Value::String("/tmp/x".into()));

        let cfg = ConnectionConfig {
            backend_kind: "test".into(),
            target: None,
            display_name: Some("dev".into()),
            config,
            credentials: creds,
        };
        let req = cfg.to_connection_request().unwrap();

        assert_eq!(req.backend_kind, "test");
        assert_eq!(req.display_name.as_deref(), Some("dev"));
        assert!(matches!(req.config.get("bucket"), Some(ConfigValue::String(s)) if s == "b"));
        assert!(matches!(
            req.config.get("port"),
            Some(ConfigValue::Int(443))
        ));
        assert!(matches!(
            req.config.get("verify_tls"),
            Some(ConfigValue::Bool(true))
        ));
        assert!(matches!(req.config.get("root"), Some(ConfigValue::String(s)) if s == "/tmp/x"));

        let token = req.credentials.fields.get("token").unwrap();
        let SecretValue::Bytes(SecretBytes(bytes)) = token else {
            panic!("expected Bytes");
        };
        assert_eq!(bytes, b"env-secret");

        let api_key = req.credentials.fields.get("api_key").unwrap();
        let SecretValue::Bytes(SecretBytes(bytes)) = api_key else {
            panic!("expected Bytes");
        };
        assert_eq!(bytes, b"inline-secret");

        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn connection_config_credential_resolution_failure_includes_field_name() {
        let mut creds = HashMap::new();
        creds.insert(
            "missing_secret".to_string(),
            "${OVSTORAGE_TEST_DEFINITELY_UNSET_kkk}".to_string(),
        );
        let cfg = ConnectionConfig {
            backend_kind: "test".into(),
            target: None,
            display_name: None,
            config: HashMap::new(),
            credentials: creds,
        };
        let err = cfg.to_connection_request().unwrap_err();
        assert!(
            err.message().contains("missing_secret"),
            "message: {}",
            err.message()
        );
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn config_value_marshal_top_level_scalars_and_nested() {
        assert!(matches!(
            config_value_from_toml("root", &toml::Value::String("/x".into())).unwrap(),
            ConfigValue::String(_)
        ));
        assert!(matches!(
            config_value_from_toml("port", &toml::Value::Integer(8080)).unwrap(),
            ConfigValue::Int(8080)
        ));
        assert!(matches!(
            config_value_from_toml("verify", &toml::Value::Boolean(true)).unwrap(),
            ConfigValue::Bool(true)
        ));
        let arr = toml::Value::Array(vec![]);
        assert!(matches!(
            config_value_from_toml("policy", &arr).unwrap(),
            ConfigValue::Toml(_)
        ));
        let bad = toml::Value::Float(1.5);
        assert_eq!(
            config_value_from_toml("rate", &bad).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}
