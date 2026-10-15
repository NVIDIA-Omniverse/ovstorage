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
//!
//! The shipped production consumer scope is the HTTP backend's read-side
//! slots. A provider for another backend kind fails closed until a trusted host
//! integration both consumes the request-scoped reference and registers the
//! matching [`UpstreamOAuthConsumerCapability`]. Provider configuration alone
//! cannot opt a backend into receiving keyring references.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ovstorage::auth::flow::OAuthEndpoints;
use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy, SecretStore};
use ovstorage::{Error, ErrorCode, canonicalize};
use serde::Deserialize;

/// The shipped production backend that consumes a broker-resolved OAuth
/// credential reference on the read-side slots. Registration is host-owned:
/// accepting an untrusted plugin's claim here would allow it to receive a
/// principal's keyring handle. The accepted backend-kind set is intentionally
/// host-gated; extend it only together with a production plugin integration
/// that consumes the reference on every registered slot. No other first-party
/// backend is registered.
const DEFAULT_UPSTREAM_OAUTH_READ_CONSUMER: &str = "http";

/// Data-slot surface on which the broker propagates broker-resolved OAuth
/// credential references to a trusted backend integration.
///
/// Capabilities are explicit because the broker currently stamps the reference
/// only on the named operation family. Registering a backend for one family
/// must not imply that list, mutation, or multi-address operations carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UpstreamOAuthConsumerCapability {
    /// Propagate the reference on `stat`, `read`, and `materialize`; the
    /// backend consumes it for the read-side operations it supports.
    ReadSide,
}

/// `OAuthCredentialProvider`s keyed by their TOML name, plus the trusted
/// backend-kind/capability pairs that consume request-scoped credential
/// references.
pub struct OAuthProviderRegistry {
    providers: HashMap<String, Arc<OAuthCredentialProvider>>,
    consumer_capabilities: HashMap<String, HashSet<UpstreamOAuthConsumerCapability>>,
}

impl Default for OAuthProviderRegistry {
    fn default() -> Self {
        Self {
            providers: HashMap::new(),
            consumer_capabilities: HashMap::from([(
                DEFAULT_UPSTREAM_OAUTH_READ_CONSUMER.to_string(),
                HashSet::from([UpstreamOAuthConsumerCapability::ReadSide]),
            )]),
        }
    }
}

impl std::fmt::Debug for OAuthProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderRegistry")
            .field("provider_names", &self.providers.keys().collect::<Vec<_>>())
            .field("consumer_capabilities", &self.consumer_capabilities)
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

    /// Trust `backend_kind` to consume broker-resolved OAuth credential
    /// references on the supported operations in `capability`'s family. Hosts
    /// call this only for a production backend integration they control.
    /// Credential establishment verifies route ownership up front; the data
    /// path verifies it again before recovering a rejected credential, while
    /// successful dispatch relies on the consumer's backend-kind check.
    pub fn with_consumer_capability(
        mut self,
        backend_kind: impl Into<String>,
        capability: UpstreamOAuthConsumerCapability,
    ) -> Self {
        self.consumer_capabilities
            .entry(backend_kind.into())
            .or_default()
            .insert(capability);
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

    pub(crate) fn has_consumer_capability(
        &self,
        backend_kind: &str,
        capability: UpstreamOAuthConsumerCapability,
    ) -> bool {
        self.consumer_capabilities
            .get(backend_kind)
            .is_some_and(|capabilities| capabilities.contains(&capability))
    }

    /// Validate the durable credential-slot model. OAuth metadata is keyed by
    /// `(backend_kind, principal)`, so two named providers for one backend kind
    /// would overwrite each other's active keyring handle and expiry row.
    pub(crate) fn validate_backend_slots(&self) -> ovstorage::Result<()> {
        let mut by_backend: HashMap<&str, Vec<&str>> = HashMap::new();
        for (name, provider) in &self.providers {
            by_backend
                .entry(provider.backend_kind())
                .or_default()
                .push(name);
        }
        for (backend, names) in &mut by_backend {
            if names.len() > 1 {
                names.sort_unstable();
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "oauth providers {} all target backend kind '{backend}', but durable OAuth state permits only one provider per backend kind",
                        names.join(", "),
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Validate that every provider targets a host-registered production
    /// read-side consumer. Config parsing intentionally stays backend-agnostic;
    /// the composed broker calls this after its trusted capability
    /// registrations are complete and before loading or serving the Stack. A
    /// backend kind belongs in those registrations only when its production
    /// plugin integration consumes the resolved reference on every read-side
    /// slot; configuration alone never expands the trusted set.
    pub(crate) fn validate_registered_read_consumers(&self) -> ovstorage::Result<()> {
        let mut unsupported = self
            .providers
            .iter()
            .filter(|(_, provider)| {
                !self.has_consumer_capability(
                    provider.backend_kind(),
                    UpstreamOAuthConsumerCapability::ReadSide,
                )
            })
            .map(|(name, provider)| (name.as_str(), provider.backend_kind()))
            .collect::<Vec<_>>();
        unsupported.sort_unstable();
        let Some((name, backend_kind)) = unsupported.first() else {
            return Ok(());
        };
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "oauth provider '{name}' targets backend kind '{backend_kind}', which has no registered production read-side consumer for broker-resolved OAuth credentials on stat/read/materialize"
            ),
        ))
    }

    pub(crate) fn validate(&self) -> ovstorage::Result<()> {
        self.validate_backend_slots()?;
        self.validate_registered_read_consumers()
    }
}

/// Why a parsed route prefix cannot be bound.
///
/// One enum over two ingresses — the TOML loader and the programmatic builder —
/// so a rule added to either reaches the other. It is not a style preference:
/// the two had already diverged twice, and each time the builder bound
/// something the loader refuses to start over. The component rule was the
/// first — the builder checked only the query while the loader refused a
/// fragment too — and the scope rule was the second, which is why the rules
/// that can be shared now live in one place instead of three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoutePrefixProblem {
    Opaque,
    Credentials,
    RespelledScope,
}

impl RoutePrefixProblem {
    /// A short tag for a log field. Never the prefix itself, which is
    /// caller-written and may carry a credential.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Credentials => "credentials",
            Self::RespelledScope => "respelled scope",
        }
    }

    /// The operator-facing explanation, completing `prefix '<the url>' …`.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Opaque => {
                "is opaque — everything after the scheme is one payload rather than a \
                 path, so it has no scope to select and canonicalization cannot normalize \
                 it. Write it with an authority"
            }
            Self::Credentials => {
                "must not carry credentials; a route is matched on scheme, authority and \
                 path alone, so this route selects its path under EVERY credential rather \
                 than the one written. Write the prefix without them"
            }
            Self::RespelledScope => {
                "names the same scope as another route; two spellings of one scope select \
                 different credentials depending on which is applied first"
            }
        }
    }
}

/// Every rule that can be asked of a **parsed** route prefix, in one place.
///
/// Three: the prefix must not be opaque, must carry no credentials, and must
/// not respell a scope already bound. The enumeration is the point — a
/// rule of the parsed prefix that lives at only one ingress is how the two
/// diverged twice already, so a new one goes here rather than beside a caller.
///
/// `bound` is the prefixes already accepted, which is what makes the scope rule
/// answerable: `x` and `x/` are one node, so they tie under `node_rank` and a
/// stable sort keeps whichever arrived first — the other is installed and can
/// never be selected. Which of the two the operator meant is unanswerable, so
/// neither ingress guesses.
///
/// **The component rule — a query or a fragment — is deliberately not here.**
/// It can only be asked of the raw string, and the two ingresses hold different
/// ones: `address::parse` has already removed a fragment by the time the config
/// loader holds a `Url`, while `url::Url::parse` keeps one, so the builder can
/// still see it and the loader must ask before it parses. A shared check over
/// the parsed form would be a guard that cannot execute on one of its callers.
pub(crate) fn route_prefix_problem<'a>(
    prefix: &url::Url,
    bound: impl IntoIterator<Item = &'a url::Url>,
) -> Option<RoutePrefixProblem> {
    // First, because the two rules below are meaningless for an opaque URL:
    // `username()` is empty however the payload is spelled, and `node_key`'s
    // path component is that payload rather than a path. `canonicalize` leaves
    // the class alone for the same reason — the path state machine never runs —
    // so this is also what keeps "canonicalized before it is stored" true.
    //
    // **This tests OPAQUE, which is narrower than "has an authority", and the
    // narrow question is the only one it may ask.** `s3:/team/` is base-able
    // with no host — the parser takes the opaque path only when the byte after
    // `:` is not `/` — so it passes here, binds, and then cannot match the
    // `s3://team/...` requests it reads like, because `is_ancestor_or_self`
    // compares `host_str()` first.
    //
    // **That residual is real and is deliberately left open, because neither
    // wider test is sound.** Refusing a missing HOST would break spellings this
    // repository ships and routes: the zero-config broker's own
    // `from = broker:///` alias, `ov:///public/` in the broker stack, and
    // `file:/path` as a published file root all have no host, and they select
    // the hostless addresses beneath them because `None == None` matches.
    // Refusing a missing AUTHORITY would split `broker:/x` from `broker:///x`,
    // which are one node — `node_key` gives both
    // `("broker", None, None, "/x", None)` — so one spelling would bind and the
    // other would not. What is left of the case is scheme-specific: `s3:` and
    // `omniverse:` addresses always carry a host, and this predicate has no
    // business knowing that.
    //
    // The TOML ingress refuses the opaque class one step earlier, inside
    // `address::parse` — whose "address must have an authority" message
    // over-promises in exactly the way this arm's name did before it was
    // corrected.
    if prefix.cannot_be_a_base() {
        return Some(RoutePrefixProblem::Opaque);
    }
    if ovstorage::address::config_prefix_carries_credentials(prefix) {
        return Some(RoutePrefixProblem::Credentials);
    }
    let key = ovstorage::address::node_key_owned(prefix);
    bound
        .into_iter()
        .any(|other| ovstorage::address::node_key_owned(other) == key)
        .then_some(RoutePrefixProblem::RespelledScope)
}

/// Broker-local map from route URL prefix → provider name.
#[derive(Clone, Debug, Default)]
pub struct BrokerOAuthRouteBindings {
    /// Sorted by descending [`ovstorage::address::node_rank`]; the most
    /// specific scope wins. Rank rather than prefix length, because byte length
    /// is spelling-dependent and two spellings of one node must not order
    /// differently — and they cannot both be here anyway, since a respelling is
    /// dropped at the door.
    rules: Vec<(url::Url, String)>,
}

impl BrokerOAuthRouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a route prefix to a provider, dropping one that carries a query, a
    /// fragment or credentials, that is opaque, or that respells a scope
    /// already bound.
    ///
    /// A route prefix is a configuration address and may carry neither — the
    /// TOML ingress refuses both in `build_oauth_providers_from_config`. This
    /// is the programmatic ingress, and it takes a `Url` the caller built
    /// rather than a string this crate parsed, so **both components are still
    /// present here**: `url::Url::parse` retains a fragment, and only
    /// `address::parse` removes one. A binding carrying either matches a scope
    /// the caller did not spell — `provider_for` uses
    /// `address::is_ancestor_or_self`, which ignores a fragment entirely and
    /// requires exact equality of a query.
    ///
    /// **Credentials are dropped for a third reason**, and it is the one the
    /// authz `allow`, the alias `from` and a `visible` visibility prefix
    /// already refuse for: [`Self::provider_for`] compares scheme, host, port
    /// and path and never the userinfo, so a prefix written with credentials
    /// selects its path under every credential rather than the one it spells —
    /// including under none.
    ///
    /// **A second spelling of a scope already bound is dropped for a fourth**,
    /// and that one is a property of this builder rather than of the prefix:
    /// `x` and `x/` are one node, so they tie on rank and a stable sort keeps
    /// whichever arrived first while the other stays installed and unreachable.
    /// **An opaque prefix is dropped for a fifth**, since it spells no path to
    /// select on and canonicalization cannot normalize it.
    ///
    /// Those three live in one crate-internal predicate that the TOML ingress
    /// calls too, so a rule askable of a parsed prefix cannot reach one ingress
    /// and miss the other. The component rule is the exception and stays here,
    /// for the reason above: it can only be asked of the raw string.
    ///
    /// The prefix is **canonicalized** before either rule is asked of it and
    /// before it is stored, which is what makes "same scope" mean the same
    /// thing on both ingresses. A caller-built `Url` is not canonical:
    /// `https://h/team//` is a second spelling of `https://h/team/` that the
    /// scope rule cannot see without it.
    ///
    /// Dropped and logged rather than refused, because this is an infallible
    /// builder in a composition chain and the alternative — installing it —
    /// leaves a binding that answers for the wrong scope and looks installed.
    /// A caller that wants a startup error writes its routes in configuration,
    /// where the same prefix is an `InvalidArgument`.
    #[must_use]
    pub fn with_route(mut self, prefix: url::Url, provider_name: impl Into<String>) -> Self {
        if let Some(component) = ovstorage::address::refused_config_component(prefix.as_str()) {
            // The prefix is not rendered: a route key is caller-written and may
            // carry userinfo, and this line reaches a log.
            tracing::warn!(
                provider = %provider_name.into(),
                component = component.name(),
                "an OAuth route prefix carrying this component names a scope it does not \
                 spell; binding dropped"
            );
            return self;
        }
        // Canonicalized before it is compared or stored, because both of those
        // are only sound on the canonical form and this ingress takes a `Url`
        // the caller built rather than one this crate parsed. `Url::parse`
        // resolves a dot segment but does not collapse a `//`, and `node_path`
        // strips one trailing slash, so `https://h/team//` and `https://h/team/`
        // reach the scope rule as two nodes — while `is_ancestor_or_self`
        // matches BOTH against `https://h/team/x` and ranks them equal, which
        // is the tie this refusal exists to remove. It also makes a rule the
        // request side could never match, `https://h/%74eam/`, into the live
        // rule its author meant instead of an inert one.
        //
        // The TOML ingress is unaffected: `address::parse` has already
        // canonicalized, and `canonicalize` is idempotent
        // (`address::tests::is_idempotent`), so this is the same value it
        // passed in. The component check stays ABOVE it — canonicalization
        // drops the fragment, so asking afterwards is asking a question whose
        // answer has been erased.
        let prefix = canonicalize(prefix);
        if let Some(problem) =
            route_prefix_problem(&prefix, self.rules.iter().map(|(bound, _)| bound))
        {
            // The prefix is not rendered, for the reason above and for one
            // more: a credential-bearing prefix is one of the things this
            // refuses, and this line reaches a log.
            tracing::warn!(
                provider = %provider_name.into(),
                problem = problem.name(),
                reason = problem.reason(),
                "an OAuth route prefix cannot select what it spells; binding dropped"
            );
            return self;
        }
        self.rules.push((prefix, provider_name.into()));
        self.rules
            .sort_by_key(|p| std::cmp::Reverse(ovstorage::address::node_rank(&p.0)));
        self
    }

    /// Longest-prefix lookup; `None` when no route has a binding.
    pub fn provider_for(&self, address: &url::Url) -> Option<&str> {
        self.rules
            .iter()
            .find(|(prefix, _)| ovstorage::address::is_ancestor_or_self(prefix, address))
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
    /// Backend kind (matches `BackendId.0`) this provider speaks for. The
    /// broker host must register the production read-side consumer capability
    /// for this kind before composing the Stack.
    pub backend_kind: String,
    pub client_id: String,
    /// HTTPS authorization endpoint. Literal loopback HTTP is accepted for
    /// local development.
    pub authorization_endpoint: String,
    /// HTTPS token endpoint. Literal loopback HTTP is accepted for local
    /// development. OAuth HTTP clients do not follow redirects.
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
    /// Build the `OAuthCredentialProvider` used by the broker daemon to drive
    /// device flows and local-caller PKCE flows.
    pub fn build(
        &self,
        name: &str,
        secret_store: Arc<dyn SecretStore>,
        refresh_lock: Arc<AuthRefreshLock>,
    ) -> ovstorage::Result<Arc<OAuthCredentialProvider>> {
        // Isolation between co-located brokers is structural: each broker's
        // secrets live in the `auth.sqlite` under its own state root, so no
        // handle namespacing is needed to keep deployments apart.
        let endpoints = OAuthEndpoints {
            authorization_endpoint: parse_oauth_endpoint_url(
                &format!("oauth_providers.{name}.authorization_endpoint"),
                &self.authorization_endpoint,
            )?,
            token_endpoint: parse_oauth_endpoint_url(
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
                    redirect_base: parse_pkce_redirect_base(
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

fn parse_oauth_endpoint_url(field: &str, value: &str) -> ovstorage::Result<url::Url> {
    let url = parse_endpoint_url(field, value)?;
    let loopback_host = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    let literal_loopback_http = url.scheme() == "http" && loopback_host;
    if url.scheme() != "https" && !literal_loopback_http {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{field} must use https (literal loopback http is development-only)"),
        ));
    }
    Ok(url)
}

fn parse_pkce_redirect_base(field: &str, value: &str) -> ovstorage::Result<url::Url> {
    let url = parse_endpoint_url(field, value)?;
    // OAuthFlow binds its callback listener specifically to 127.0.0.1, so the
    // configured public redirect spelling must name that same interface.
    let loopback = matches!(
        url.host(),
        Some(url::Host::Ipv4(address)) if address == std::net::Ipv4Addr::LOCALHOST
    );
    if url.scheme() != "http" || !loopback {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{field} must be an http loopback URL"),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{field} must not contain userinfo or a fragment"),
        ));
    }
    Ok(url)
}

/// Build the registry from parsed `[oauth_providers]` entries.
pub fn build_oauth_provider_registry(
    configs: &HashMap<String, OAuthProviderConfig>,
    secret_store: Arc<dyn SecretStore>,
    refresh_lock: Arc<AuthRefreshLock>,
) -> ovstorage::Result<Arc<OAuthProviderRegistry>> {
    let mut registry = OAuthProviderRegistry::new();
    for (name, cfg) in configs {
        let provider = cfg.build(name, secret_store.clone(), refresh_lock.clone())?;
        registry = registry.with_provider(name, provider);
    }
    registry.validate_backend_slots()?;
    Ok(Arc::new(registry))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthProviderConfig {
        OAuthProviderConfig {
            kind: OAuthProviderKind::Pkce,
            backend_kind: "http".into(),
            client_id: "client".into(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            scope: None,
            redirect_base: Some("http://127.0.0.1/callback".into()),
        }
    }

    #[test]
    fn oauth_provider_config_parsing_is_backend_agnostic() {
        let mut non_http = config();
        non_http.backend_kind = "gcs".into();

        let provider = build(&non_http).unwrap();

        assert_eq!(provider.backend_kind(), "gcs");
    }

    #[test]
    fn provider_registry_requires_a_host_registered_read_consumer() {
        let mut non_http = config();
        non_http.backend_kind = "gcs".into();
        let provider = build(&non_http).unwrap();
        let unsupported =
            OAuthProviderRegistry::new().with_provider("provider", Arc::clone(&provider));

        let error = unsupported
            .validate_registered_read_consumers()
            .unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .message()
                .contains("no registered production read-side consumer")
        );

        OAuthProviderRegistry::new()
            .with_provider("provider", provider)
            .with_consumer_capability("gcs", UpstreamOAuthConsumerCapability::ReadSide)
            .validate()
            .expect("a trusted host registration enables another read-side consumer kind");
    }

    #[test]
    fn oauth_provider_registry_rejects_two_names_for_one_durable_backend_slot() {
        let configs = HashMap::from([
            ("provider-a".to_string(), config()),
            ("provider-b".to_string(), config()),
        ]);
        let state_root = std::env::temp_dir().join(format!(
            "ovstorage-oauth-slot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let error = build_oauth_provider_registry(
            &configs,
            Arc::new(
                ovstorage::auth::SqliteSecretStore::open(&state_root).expect("open sqlite store"),
            ),
            Arc::new(AuthRefreshLock::open(state_root).unwrap()),
        )
        .unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("provider-a, provider-b"));
        assert!(error.message().contains("one provider per backend kind"));
    }

    #[test]
    fn programmatic_registry_uses_the_same_durable_slot_validation() {
        let first = build(&config()).unwrap();
        let second = build(&config()).unwrap();
        let registry = OAuthProviderRegistry::new()
            .with_provider("provider-a", first)
            .with_provider("provider-b", second);

        let error = registry.validate_backend_slots().unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("provider-a, provider-b"));
    }

    fn build(config: &OAuthProviderConfig) -> ovstorage::Result<Arc<OAuthCredentialProvider>> {
        let state_root = std::env::temp_dir().join(format!(
            "ovstorage-oauth-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        config.build(
            "provider",
            Arc::new(
                ovstorage::auth::SqliteSecretStore::open(&state_root).expect("open sqlite store"),
            ),
            Arc::new(AuthRefreshLock::open(state_root).unwrap()),
        )
    }

    #[test]
    fn oauth_provider_config_requires_https_or_literal_loopback_endpoints() {
        let mut insecure_authorization = config();
        insecure_authorization.authorization_endpoint = "http://idp.example/authorize".into();
        assert_eq!(
            build(&insecure_authorization).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        let mut insecure_token = config();
        insecure_token.token_endpoint = "http://idp.example/token".into();
        assert_eq!(
            build(&insecure_token).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        for loopback in ["http://127.0.0.1/token", "http://[::1]/token"] {
            let mut development = config();
            development.token_endpoint = loopback.into();
            assert!(
                build(&development).is_ok(),
                "literal loopback endpoint {loopback} should support local development"
            );
        }
    }

    #[test]
    fn oauth_provider_config_requires_plain_loopback_pkce_redirect() {
        for redirect in [
            "https://127.0.0.1/callback",
            "http://idp.example/callback",
            "http://127.0.0.2/callback",
            "http://[::1]/callback",
            "http://user@127.0.0.1/callback",
            "http://127.0.0.1/callback#fragment",
        ] {
            let mut invalid = config();
            invalid.redirect_base = Some(redirect.into());
            assert_eq!(
                build(&invalid).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "redirect {redirect} must be rejected"
            );
        }

        assert!(build(&config()).is_ok());
    }

    /// The programmatic ingress drops an opaque prefix.
    ///
    /// `s3:a/b` is opaque: everything after the scheme is one payload, so there
    /// is no path to select on and `canonicalize` leaves it alone — the path
    /// state machine never runs — which means it would be stored
    /// un-canonicalized as well.
    ///
    /// **The rule is not "has an authority", and the row below is why.**
    /// `s3:/team/` is base-able with no host, so it is NOT refused here: it
    /// binds, and it can never match `s3://team/...` because
    /// `is_ancestor_or_self` compares `host_str()` first. That residual is
    /// asserted rather than fixed, because both wider tests break something
    /// real — refusing a missing host would refuse `broker:///`, `ov:///public/`
    /// and `file:/path`, which this repository ships and routes, and refusing a
    /// missing authority would split `broker:/x` from `broker:///x`, which are
    /// one node. Closing it needs a scheme-level fact this predicate does not
    /// have.
    ///
    /// Load-bearing line: the `cannot_be_a_base` arm of `route_prefix_problem`.
    #[test]
    fn a_programmatic_route_that_is_opaque_is_not_bound() {
        let bindings =
            BrokerOAuthRouteBindings::new().with_route(url::Url::parse("s3:a/b").unwrap(), "corp");
        assert!(bindings.is_empty(), "an opaque prefix must not bind");

        // The stated residual, pinned so a later reader sees it is known
        // rather than missed: base-able, hostless, binds, and unreachable for
        // any address that carries a host.
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(url::Url::parse("s3:/team/").unwrap(), "corp");
        assert_eq!(bindings.iter().count(), 1, "a hostless prefix still binds");
        assert_eq!(
            bindings.provider_for(&url::Url::parse("s3://team/x").unwrap()),
            None,
            "and cannot select the hosted address it reads like"
        );

        // A hostless prefix is NOT inert in general, which is why the rule
        // above is not "has a host": these are spellings this repository ships.
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(url::Url::parse("broker:///").unwrap(), "corp");
        assert_eq!(
            bindings.provider_for(&url::Url::parse("broker:///x").unwrap()),
            Some("corp"),
            "a hostless prefix selects the hostless addresses beneath it"
        );

        // The control: the same scope written with an authority binds and
        // answers for its subtree.
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(url::Url::parse("s3://a/b/").unwrap(), "corp");
        assert_eq!(
            bindings.provider_for(&url::Url::parse("s3://a/b/x").unwrap()),
            Some("corp")
        );
    }

    /// The programmatic ingress drops a second spelling of a scope it already
    /// binds, in either registration order.
    ///
    /// `x` and `x/` are one node, so they tie under `node_rank` and a stable
    /// sort keeps whichever was registered first — silently, with the other
    /// provider installed and unreachable. Which of the two an operator meant
    /// is unanswerable, so the builder binds the first and drops the second,
    /// exactly as the TOML ingress refuses the pair outright.
    ///
    /// **The assertion is the COUNT, not the winner.** First-registered already
    /// won before this refusal existed — the loser was installed and never
    /// selected — so asserting the winner alone passes with the guard deleted
    /// and proves nothing. Measured: with the `node_key_owned` check removed
    /// both rows install and `iter().count()` is 2, which is what reddens.
    #[test]
    fn a_programmatic_route_that_respells_a_bound_scope_is_not_bound_twice() {
        let url = |raw: &str| url::Url::parse(raw).unwrap();
        for (first, second) in [
            ("https://h/team", "https://h/team/"),
            ("https://h/team/", "https://h/team"),
            // The two rows that pin the CANONICALIZE step, measured: a
            // caller-built `Url` keeps both of these verbatim
            // (`Url::parse("https://h/team//")` is `…/team//` and
            // `…/%74eam/` is `…/%74eam/`), so without canonicalization the
            // first installs a second rule that ties with the first and wins or
            // loses by arrival order, and the second installs one no canonical
            // request address can ever match.
            ("https://h/team/", "https://h/team//"),
            ("https://h/team/", "https://h/%74eam/"),
            // NOT load-bearing for that step, and here to say so: `Url::parse`
            // resolves a dot segment itself, so this pair arrives already
            // collapsed and would be caught with the canonicalize call deleted.
            // It pins the `url` crate's behaviour, which the rows above depend
            // on being narrower than it looks.
            ("https://h/team/", "https://h/a/../team/"),
        ] {
            let bindings = BrokerOAuthRouteBindings::new()
                .with_route(url(first), "tenant-a")
                .with_route(url(second), "tenant-b");
            assert_eq!(
                bindings.iter().count(),
                1,
                "{second} respells the scope {first} already binds"
            );
            assert_eq!(
                bindings.provider_for(&url("https://h/team/x")),
                Some("tenant-a"),
                "the surviving binding must be the one that was registered first"
            );
        }

        // The control: two prefixes that name DIFFERENT scopes both bind and
        // each answers for its own subtree, so the refusal is about the
        // respelling and not about registering a second route at all.
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(url("https://h/team/"), "tenant-a")
            .with_route(url("https://h/other/"), "tenant-b");
        assert_eq!(bindings.iter().count(), 2);
        assert_eq!(
            bindings.provider_for(&url("https://h/team/x")),
            Some("tenant-a")
        );
        assert_eq!(
            bindings.provider_for(&url("https://h/other/x")),
            Some("tenant-b")
        );
    }

    /// The programmatic ingress drops a route prefix carrying credentials, for
    /// the reason the config loader refuses one: `provider_for` compares
    /// scheme, host, port and path, so the binding would answer for its path
    /// under every credential rather than the one it spells.
    ///
    /// Load-bearing line: the `username`/`password` block in `with_route`.
    /// Deleting it installs the binding, so `is_empty` reddens and so does the
    /// anonymous-address assertion — which is the widening itself, stated as an
    /// address the caller never spelled a credential for.
    #[test]
    fn a_programmatic_route_carrying_credentials_is_not_bound() {
        let url = |raw: &str| url::Url::parse(raw).unwrap();
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(url("https://alice:pw@origin.invalid/team/"), "corp");
        assert!(
            bindings.is_empty(),
            "a credential-bearing prefix must not bind"
        );
        assert_eq!(
            bindings.provider_for(&url("https://origin.invalid/team/x")),
            None,
            "and it must not select the anonymous address it never spelled"
        );

        // The good input: the same prefix without the credential binds and
        // answers for its subtree, so the refusal is about the credential and
        // not about the route.
        let bindings =
            BrokerOAuthRouteBindings::new().with_route(url("https://origin.invalid/team/"), "corp");
        assert_eq!(
            bindings.provider_for(&url("https://origin.invalid/team/x")),
            Some("corp")
        );
    }

    /// The programmatic route ingress drops a prefix carrying a query or a
    /// fragment, and binds the one that carries neither.
    ///
    /// This ingress takes a `Url`, so unlike the TOML one it sees a fragment:
    /// `url::Url::parse` keeps one and only `address::parse` removes it. The
    /// first two rows would otherwise install a binding covering a scope the
    /// caller did not spell — `is_ancestor_or_self` ignores a fragment and
    /// requires exact equality of a query.
    ///
    /// Load-bearing line: the `refused_config_component` block in
    /// `with_route`. Deleting it installs both rows, so both `is_empty`
    /// assertions redden. Only the FRAGMENT row's `provider_for` assertion
    /// reddens with it — a query-bearing binding installs but still answers
    /// `None`, because `is_ancestor_or_self` then demands the address carry
    /// the same query. That asymmetry is why the fragment is the dangerous
    /// half: it is the one that silently widens.
    #[test]
    fn a_programmatic_route_carrying_a_query_or_a_fragment_is_not_bound() {
        let url = |raw: &str| url::Url::parse(raw).unwrap();

        // The fragment survives `url::Url::parse`, which is why it has to be
        // checked here rather than assumed away.
        assert_eq!(
            url("https://origin.invalid/team/#note").fragment(),
            Some("note")
        );

        for raw in [
            "https://origin.invalid/team/#note",
            "https://origin.invalid/team/?v=1",
        ] {
            let bindings = BrokerOAuthRouteBindings::new().with_route(url(raw), "corp");
            assert!(bindings.is_empty(), "{raw} must not bind");
            assert_eq!(
                bindings.provider_for(&url("https://origin.invalid/team/x")),
                None,
                "{raw} must not answer for the subtree it does not spell"
            );
        }

        // The good input binds and answers for its subtree, so the refusal is
        // about the component and not about the route.
        let bindings =
            BrokerOAuthRouteBindings::new().with_route(url("https://origin.invalid/team/"), "corp");
        assert!(!bindings.is_empty());
        assert_eq!(
            bindings.provider_for(&url("https://origin.invalid/team/x")),
            Some("corp")
        );
    }
}
