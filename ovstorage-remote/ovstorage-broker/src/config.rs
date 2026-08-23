// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BrokerConfig {
    /// The shared inner data-plane Stack, declared as `[ovstorage]` config
    /// (root + `[ovstorage.layers.*]` + `[[ovstorage.connections]]`). The broker
    /// builds it verbatim through [`ovstorage::host::build_stack`]; the layer
    /// graph, the byte/metadata cache roots, and the follower follow policy are
    /// all layer config here, not host concerns. An empty
    /// `[ovstorage.layers]` is rejected at startup (`require_configured_stack`);
    /// declare a stack or copy the shipped `ovstorage-broker.toml`.
    #[serde(default)]
    pub ovstorage: ovstorage::StackConfig,
    #[serde(default)]
    pub discovery: BrokerDiscoveryConfig,
    /// Single listener per broker process. Multi-transport deployments
    /// run two broker processes sharing backend plugin config.
    #[serde(default)]
    pub listener: Option<BrokerListenerConfig>,
    #[serde(default)]
    pub observability: Option<BrokerObservabilityConfig>,
    /// Trust-boundary attribution strategy for `modified_by`. Default
    /// `user_metadata` stamps the authn'd principal into a reserved
    /// key in object metadata; `passthrough` for intermediate brokers
    /// in a chain that should forward an upstream broker's stamp
    /// unchanged. `external_db` is reserved for v2.
    #[serde(default)]
    pub attribution_strategy: AttributionStrategyConfig,
    /// Whether a redirect carrying a credential broader than the redirected
    /// request may be handed to the client that asked for it.
    ///
    /// This is a property of the deployment, not of the credential, which is
    /// why it is an operator setting rather than a rule. A broker is not always
    /// a credential boundary: it is sometimes a central configuration point for
    /// clients already inside the trust boundary — a pod of render agents in one
    /// datacenter behind one broker — and handing those clients a credential
    /// discloses nothing they were not already entitled to, while refusing costs
    /// them the redirect path entirely.
    ///
    /// Governs the read and the write path identically.
    #[serde(default)]
    pub redirect_credential_disclosure: RedirectDisclosureConfig,
    /// Per-name OAuth provider registry.
    ///
    /// ```toml
    /// [oauth_providers.upstream-idp]
    /// kind = "pkce"
    /// backend_kind = "http"
    /// client_id = "ovstorage-broker"
    /// authorization_endpoint = "https://idp.example/authorize"
    /// token_endpoint = "https://idp.example/token"
    /// scope = "openid profile"
    /// redirect_base = "http://127.0.0.1"
    /// ```
    #[serde(default)]
    pub oauth_providers: HashMap<String, OAuthProviderConfig>,
    /// Route URL prefix → `oauth_providers` name. Broker-local so the
    /// cross-workspace `RouteConfig` stays untouched.
    ///
    /// ```toml
    /// [broker_oauth_routes]
    /// "https://assets.example/" = "upstream-idp"
    /// ```
    #[serde(default)]
    pub broker_oauth_routes: HashMap<String, String>,
    /// Where the credential substrate lives on disk.
    ///
    /// ```toml
    /// [auth]
    /// state_root = "/srv/ovstorage/auth"
    /// ```
    #[serde(default)]
    pub auth: AuthStateConfig,
}

/// Operator control over the auth directory — `auth.sqlite`, its advisory
/// refresh locks, and the credential bytes.
///
/// Two names in this file are close enough to be worth separating. This is
/// not `[listener.auth]`, which selects the per-listener authentication
/// policy and decides who may talk to the broker; this decides where the
/// broker keeps the credentials it uses to talk to *backends*. It is also not
/// a byte-cache `state_root`: those are layer config under
/// `[ovstorage.layers.*]` and hold cache index state, which is safe to delete.
/// This directory is not.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthStateConfig {
    /// Absolute path to the auth directory. Takes precedence over
    /// `OVSTORAGE_AUTH_DIR`, which in turn takes precedence over the platform
    /// per-user data directory.
    ///
    /// Set this when a broker runs as its own service user and must not share
    /// a credential lineage with the operator's interactive sessions, or when
    /// two brokers on one host must stay isolated from each other.
    #[serde(default)]
    pub state_root: Option<PathBuf>,
}

/// Whether redirects may carry a connection-wide credential to the client.
///
/// ```toml
/// redirect_credential_disclosure = "refuse"  # default; the broker moves the bytes
/// # redirect_credential_disclosure = "allow" # clients are inside the trust boundary
/// ```
///
/// Redirects whose credential is scoped to the redirected request — an S3
/// presigned URL, an Azure service SAS the broker minted, a GCS signed URL —
/// are handed to the client under **both** settings. They are the reason
/// redirects exist and disclose nothing beyond the object being transferred.
#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedirectDisclosureConfig {
    /// A redirect carrying a credential broader than the redirected request is
    /// not handed over; this host moves the bytes instead.
    #[default]
    Refuse,
    /// Any valid redirect may be handed to the client.
    Allow,
}

impl RedirectDisclosureConfig {
    pub fn discloses(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Wire form of [`ovstorage_authz::AttributionStrategy`].
///
/// ```toml
/// attribution_strategy = "user_metadata"  # default
/// # attribution_strategy = "passthrough"     # chained intermediate broker
/// # attribution_strategy = "external_db"     # v2; broker refuses to start
/// ```
#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttributionStrategyConfig {
    #[default]
    UserMetadata,
    Passthrough,
    ExternalDb,
}

impl From<AttributionStrategyConfig> for AttributionStrategy {
    fn from(value: AttributionStrategyConfig) -> Self {
        match value {
            AttributionStrategyConfig::UserMetadata => AttributionStrategy::UserMetadata,
            AttributionStrategyConfig::Passthrough => AttributionStrategy::Passthrough,
            AttributionStrategyConfig::ExternalDb => AttributionStrategy::ExternalDb,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BrokerListenerConfig {
    /// Transport is auto-detected from the bind value:
    /// - absolute path (`/tmp/sock`) → Unix domain socket
    /// - `pipe:NAME` → Windows named pipe
    /// - `host:port` → TCP
    pub bind: String,
    #[serde(default)]
    pub tls: Option<BrokerListenerTlsConfig>,
    #[serde(default)]
    pub trusted_proxy: bool,
    #[serde(default)]
    pub trusted_peers: Vec<String>,
    /// Per-listener auth block, resolved by
    /// [`ovstorage_authz_layer::resolve_listener_auth`] into the built-in auth
    /// layer's kind + `LayerConfig`. Fail-closed: absent ⇒ the broker refuses
    /// to build. `auth = "anonymous"` is the explicit unauthenticated allow-all
    /// opt-in; `[listener.auth]` (a `{ kind, config }` table) carries the policy
    /// rule set plus optional OIDC `jwt_*` params and the `peer_dev_current_user`
    /// flag. The value is captured opaquely and handed to the
    /// resolver at build time — the host performs no authn.
    #[serde(default)]
    pub auth: Option<toml::Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BrokerListenerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// PEM trust roots used to verify required client certificates. Setting
    /// this enables client-certificate verification in tonic.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

/// Decoded bind value. The wire form is the `bind` string on
/// `BrokerListenerConfig`; this type is what main.rs and the validator
/// branch on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerTransport {
    Tcp(SocketAddr),
    UnixSocket(PathBuf),
    NamedPipe(String),
}

impl BrokerTransport {
    pub fn parse(bind: &str) -> ovstorage::Result<Self> {
        let bind = bind.trim();
        if bind.is_empty() {
            return Err(invalid_config("listener bind must not be empty"));
        }
        if let Some(name) = bind.strip_prefix("pipe:") {
            let name = name.trim();
            if name.is_empty() {
                return Err(invalid_config(
                    "listener bind 'pipe:' must include a pipe name",
                ));
            }
            return Ok(BrokerTransport::NamedPipe(name.to_string()));
        }
        if bind.starts_with(r"\\.\pipe\") || bind.starts_with(r"\\?\pipe\") {
            return Ok(BrokerTransport::NamedPipe(bind.to_string()));
        }
        if bind.starts_with('/') {
            return Ok(BrokerTransport::UnixSocket(PathBuf::from(bind)));
        }
        if let Ok(addr) = bind.parse::<SocketAddr>() {
            return Ok(BrokerTransport::Tcp(addr));
        }
        Err(invalid_config(format!(
            "listener bind '{bind}' could not be parsed; expected an absolute path \
             (UDS), 'pipe:NAME' (npipe), or 'host:port' (TCP)"
        )))
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::UnixSocket(_) | Self::NamedPipe(_))
    }
}

impl BrokerListenerConfig {
    pub fn transport(&self) -> ovstorage::Result<BrokerTransport> {
        BrokerTransport::parse(&self.bind)
    }
}
