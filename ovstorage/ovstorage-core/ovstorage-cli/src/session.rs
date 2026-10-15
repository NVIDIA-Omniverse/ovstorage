// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory state shared across one CLI invocation (especially relevant in the interactive shell).
//!
//! Each credential field is a UTF-8 string sourced from TOML or the TTY.
//! Literal values pass through as-is; values containing `${NAME}` get
//! env-substituted at `to_connection_request` time. Plugins that take binary
//! keys must declare them as base64-encoded strings in their descriptor.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::{
    ConnectionRequest, SecretBundle, SecretBytes, SecretValue, Stack, StackConfig, Url,
    config_value_from_toml, resolve_env_refs,
};

pub struct SessionConnection {
    pub backend_kind: String,
    /// Name of the layer this connection attaches to, when it differs from
    /// (or was explicitly pinned alongside) `backend_kind`. Carried so
    /// `write-config` can round-trip a connection attached to a backend layer
    /// named differently from its kind (e.g. layer `prod` of kind `s3`).
    pub target: Option<String>,
    pub display_name: Option<String>,
    pub config: HashMap<String, toml::Value>,
    pub credentials: HashMap<String, String>,
}

pub struct SessionState {
    pub stack: Arc<Stack>,
    pub connections: Vec<SessionConnection>,
    /// Current working address: relative paths typed by the user are resolved
    /// against this. `None` means there's no current directory and addresses
    /// must be absolute.
    pub pwd: Option<Url>,
    /// True only inside the interactive shell loop. The `cd` command refuses
    /// to do anything when this is `false`, since a one-shot invocation can't
    /// use the new pwd before the process exits.
    pub interactive: bool,
}

impl SessionState {
    /// Record the config's connections into session state so `write-config`
    /// can round-trip them. The connections were already applied to the Stack
    /// by [`ovstorage::host::build_stack`], so this does NOT re-apply them;
    /// credential values pass through to the session verbatim.
    pub async fn build(stack: Arc<Stack>, config: StackConfig) -> ovstorage::Result<Self> {
        let connections = config
            .connections
            .into_iter()
            .map(|conn| SessionConnection {
                backend_kind: conn.backend_kind,
                target: conn.target,
                display_name: conn.display_name,
                config: conn.config,
                credentials: conn.credentials,
            })
            .collect();
        Ok(Self {
            stack,
            connections,
            pwd: None,
            interactive: false,
        })
    }
}

impl SessionConnection {
    /// Build a runtime `ConnectionRequest` from this session connection,
    /// substituting `${NAME}` in credential values from the process env.
    pub fn to_connection_request(&self) -> ovstorage::Result<ConnectionRequest> {
        let mut config = HashMap::with_capacity(self.config.len());
        for (key, value) in &self.config {
            config.insert(key.clone(), config_value_from_toml(key, value)?);
        }
        let mut credentials = SecretBundle::default();
        for (key, raw) in &self.credentials {
            let resolved = resolve_env_refs(raw).map_err(|err| {
                ovstorage::Error::new(
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
