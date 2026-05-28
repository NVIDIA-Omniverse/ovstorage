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
    ConnectionRequest, Library, LibraryConfig, RouteConfig, SecretBundle, SecretBytes, SecretValue,
    StateConfig, Storage, Url, config_value_from_toml, resolve_env_refs,
};

pub struct SessionConnection {
    pub backend_kind: String,
    pub display_name: Option<String>,
    pub config: HashMap<String, toml::Value>,
    pub credentials: HashMap<String, String>,
}

pub struct SessionState {
    pub library: Arc<Library>,
    pub connections: Vec<SessionConnection>,
    pub routes: Vec<RouteConfig>,
    pub state_config: Option<StateConfig>,
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
    /// Convert the parsed startup config into session state, registering each
    /// loaded connection with the live library. Credential values pass through
    /// to the session verbatim so `write-config` round-trips them.
    pub async fn build(library: Arc<Library>, loaded: LibraryConfig) -> ovstorage::Result<Self> {
        let mut connections = Vec::with_capacity(loaded.connections.len());
        for conn in loaded.connections {
            let request = conn.to_connection_request()?;
            library.add_connection(request, None).await?;
            connections.push(SessionConnection {
                backend_kind: conn.backend_kind,
                display_name: conn.display_name,
                config: conn.config,
                credentials: conn.credentials,
            });
        }
        Ok(Self {
            library,
            connections,
            routes: loaded.routes,
            state_config: loaded.state,
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
