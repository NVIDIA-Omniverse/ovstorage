// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-level OAuth provider registry.
//!
//! Stores `OAuthCredentialProvider` instances by name so the gRPC
//! `Auth` / `RegisterCredential` RPCs can resolve a route's
//! `oauth_provider = "<name>"` at request time. Route bindings live in
//! a broker-local map ([`BrokerOAuthRouteBindings`]) so the
//! cross-workspace `RouteConfig` stays untouched.
//!
//! UDS / named-pipe transports are local-trust-scope; pairing them with
//! any `oauth_provider` config is a startup error.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::auth::flow::OAuthEndpoints;
use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy, SecretStore};
use ovstorage::{Error, ErrorCode};
use serde::Deserialize;

/// `OAuthCredentialProvider`s keyed by their TOML name.
#[derive(Default)]
pub struct OAuthProviderRegistry {
    providers: HashMap<String, Arc<OAuthCredentialProvider>>,
}

impl std::fmt::Debug for OAuthProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderRegistry")
            .field("provider_names", &self.providers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OAuthProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider; replaces any prior registration.
    pub fn with_provider(
        mut self,
        name: impl Into<String>,
        provider: Arc<OAuthCredentialProvider>,
    ) -> Self {
        self.providers.insert(name.into(), provider);
        self
    }

    pub fn lookup(&self, name: &str) -> Option<Arc<OAuthCredentialProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.keys().map(String::as_str)
    }
}

/// Broker-local map from route URL prefix → provider name.
#[derive(Clone, Debug, Default)]
pub struct BrokerOAuthRouteBindings {
    /// Sorted by descending prefix length; longest-prefix wins.
    rules: Vec<(url::Url, String)>,
}

impl BrokerOAuthRouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_route(mut self, prefix: url::Url, provider_name: impl Into<String>) -> Self {
        self.rules.push((prefix, provider_name.into()));
        self.rules
            .sort_by_key(|p| std::cmp::Reverse(p.0.as_str().len()));
        self
    }

    /// Longest-prefix lookup; `None` when no route has a binding.
    pub fn provider_for(&self, address: &url::Url) -> Option<&str> {
        self.rules
            .iter()
            .find(|(prefix, _)| ovstorage::address::is_prefix_of(prefix, address))
            .map(|(_, name)| name.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&url::Url, &str)> {
        self.rules.iter().map(|(p, n)| (p, n.as_str()))
    }
}

/// Shape of one `[oauth_providers.<name>]` block.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct OAuthProviderConfig {
    pub kind: OAuthProviderKind,
    /// Backend kind (matches `BackendId.0`) this provider speaks for.
    pub backend_kind: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// Required for `kind = "pkce"`; ignored for device flow.
    #[serde(default)]
    pub redirect_base: Option<String>,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProviderKind {
    Pkce,
    Device,
}

impl OAuthProviderConfig {
    /// Build an `OAuthCredentialProvider`. The broker daemon never
    /// drives PKCE/device locally — the `Auth` RPC carries flow events
    /// back to the host SDK.
    pub fn build(
        &self,
        name: &str,
        secret_store: Arc<SecretStore>,
        refresh_lock: Arc<AuthRefreshLock>,
    ) -> ovstorage::Result<Arc<OAuthCredentialProvider>> {
        let endpoints = OAuthEndpoints {
            authorization_endpoint: parse_endpoint_url(
                &format!("oauth_providers.{name}.authorization_endpoint"),
                &self.authorization_endpoint,
            )?,
            token_endpoint: parse_endpoint_url(
                &format!("oauth_providers.{name}.token_endpoint"),
                &self.token_endpoint,
            )?,
            client_id: self.client_id.clone(),
            scope: self.scope.clone(),
        };
        let strategy = match self.kind {
            OAuthProviderKind::Pkce => {
                let base = self.redirect_base.as_deref().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("oauth_providers.{name}: kind = \"pkce\" requires redirect_base"),
                    )
                })?;
                OAuthStrategy::Pkce {
                    redirect_base: parse_endpoint_url(
                        &format!("oauth_providers.{name}.redirect_base"),
                        base,
                    )?,
                }
            }
            OAuthProviderKind::Device => OAuthStrategy::Device,
        };
        let provider = OAuthCredentialProvider::new(
            name,
            self.backend_kind.clone(),
            endpoints,
            secret_store,
            refresh_lock,
            strategy,
        );
        Ok(Arc::new(provider))
    }
}

fn parse_endpoint_url(field: &str, value: &str) -> ovstorage::Result<url::Url> {
    url::Url::parse(value).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{field} must be a URL: {err}"),
        )
    })
}

/// Build the registry from parsed `[oauth_providers]` entries.
pub fn build_oauth_provider_registry(
    configs: &HashMap<String, OAuthProviderConfig>,
    secret_store: Arc<SecretStore>,
    refresh_lock: Arc<AuthRefreshLock>,
) -> ovstorage::Result<Arc<OAuthProviderRegistry>> {
    let mut registry = OAuthProviderRegistry::new();
    for (name, cfg) in configs {
        let provider = cfg.build(name, secret_store.clone(), refresh_lock.clone())?;
        registry = registry.with_provider(name, provider);
    }
    Ok(Arc::new(registry))
}
