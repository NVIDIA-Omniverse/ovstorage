// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Config types deserialized from `ovstorage.toml`. Lives in
//! `ovstorage` (not `ovstorage-plugin`) because the Layer 0 plugin ABI
//! avoids `serde`. Plugins consume already-resolved
//! [`SecretBundle`]s via `ConnectionRequest`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ovstorage_plugin::{
    ConfigValue, ConnectionRequest, Error, ErrorCode, Result, SecretBundle, SecretBytes,
    SecretValue, resolve_env_refs,
};
use serde::{Deserialize, Serialize};

/// Top-level `ovstorage.toml` shape. Apps embed via `#[serde(flatten)]`
/// in their own config struct so one TOML feeds every consumer.
///
/// Scoped to deployment-shared concerns:
/// - `state` — where on disk to put the cache + state DB.
/// - `routes` — per-prefix policy overrides (cache, redirect, retry).
/// - `connections` — backend connections persisted by `ovstorage write-config`.
/// - `metadata_cache` — sizing + TTL + notification-driven invalidations.
///
/// Library-wide retry policy and interactive auth capability live on
/// `LibraryBuilder` only — those are application context (a daemon knows
/// it's headless, a desktop CLI knows it can show a browser), not
/// deployment config.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct LibraryConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<ConnectionConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_cache: Option<crate::MetadataCacheConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<RouteCacheConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RouteRedirectConfig>,
    /// Overrides [`LibraryBuilder::with_retry`](crate::LibraryBuilder::with_retry) for this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<crate::retry::RetryConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RouteCacheConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_object_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RouteRedirectConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, toml::Value>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub credentials: HashMap<String, String>,
}

impl LibraryConfig {
    /// Unknown top-level sections are ignored (so flattening hosts
    /// can carry their own).
    pub fn from_toml_str(s: &str) -> Result<Self> {
        use figment::{
            Figment,
            providers::{Format, Toml},
        };
        // Test/programmatic path: parse a TOML string. Env-var overlay
        // is intentionally skipped here so unit tests with explicit
        // configs don't pick up developer environments. Operator-facing
        // parsing goes through `from_toml_path`.
        Figment::new()
            .merge(Toml::string(s))
            .extract()
            .map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ovstorage config: {err}"),
                )
            })
    }

    pub fn from_toml_path(path: &Path) -> Result<Self> {
        use figment::{
            Figment,
            providers::{Env, Format, Toml},
        };
        if !path.is_file() {
            return Err(Error::new(
                ErrorCode::NotFound,
                format!("could not read {}: file does not exist", path.display()),
            ));
        }
        let env = Env::prefixed("OVSTORAGE__")
            .map(|key| {
                let lowered: String = key.as_str().to_lowercase().replace("__", ".");
                lowered.into()
            })
            .split(".");
        Figment::new()
            .merge(Toml::file(path))
            .merge(env)
            .extract()
            .map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ovstorage config '{}': {err}", path.display()),
                )
            })
    }

    /// Try `./ovstorage.toml`, then
    /// `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`
    /// (default `~/.config/ovstorage/ovstorage.toml`). `Ok(None)` when
    /// neither exists.
    pub fn from_default_path() -> Result<Option<Self>> {
        for candidate in default_config_paths() {
            if candidate.is_file() {
                return Self::from_toml_path(&candidate).map(Some);
            }
        }
        Ok(None)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to serialize ovstorage config: {err}"),
            )
        })
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
    fn library_config_round_trips_through_toml() {
        let mut creds = HashMap::new();
        creds.insert(
            "aws_access_key_id".to_string(),
            "${AWS_ACCESS_KEY_ID}".to_string(),
        );
        creds.insert(
            "aws_secret_access_key".to_string(),
            "literal-value".to_string(),
        );
        let mut config = HashMap::new();
        config.insert(
            "bucket".to_string(),
            toml::Value::String("my-bucket".into()),
        );
        config.insert(
            "region".to_string(),
            toml::Value::String("us-east-1".into()),
        );

        let original = LibraryConfig {
            state: Some(StateConfig {
                state_root: Some(PathBuf::from("/var/lib/ovstorage")),
                cache_root: None,
            }),
            routes: vec![RouteConfig {
                prefix: "s3:my-bucket/".into(),
                cache: Some(RouteCacheConfig {
                    max_object_bytes: Some(1024 * 1024),
                }),
                redirect: None,
                retry: None,
            }],
            connections: vec![ConnectionConfig {
                backend_kind: "s3".into(),
                display_name: Some("prod".into()),
                config,
                credentials: creds,
            }],
            metadata_cache: None,
        };

        let toml_str = original.to_toml_string().unwrap();
        let parsed = LibraryConfig::from_toml_str(&toml_str).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn library_config_ignores_unknown_top_level_sections() {
        let toml_str = r#"
            [unknown_section]
            value = 42

            [[connections]]
            backend_kind = "file"
        "#;
        let cfg = LibraryConfig::from_toml_str(toml_str).unwrap();
        assert_eq!(cfg.connections.len(), 1);
        assert_eq!(cfg.connections[0].backend_kind, "file");
    }

    #[test]
    fn library_config_invalid_toml_returns_error() {
        let err = LibraryConfig::from_toml_str("not = [valid").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn from_toml_path_missing_file_is_not_found() {
        let err =
            LibraryConfig::from_toml_path(Path::new("/nonexistent/ovstorage.toml")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

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

    #[test]
    fn library_config_silently_drops_removed_fields() {
        let toml_str = r#"
            interactive_auth_capability = "headless"

            [retry]
            min_delay_ms = 100
            max_delay_ms = 30000
            max_attempts = 5
        "#;
        let cfg = LibraryConfig::from_toml_str(toml_str).unwrap();
        assert!(cfg.connections.is_empty());
        assert!(cfg.routes.is_empty());
        assert!(cfg.state.is_none());
    }
}
