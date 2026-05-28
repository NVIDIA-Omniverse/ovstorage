// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BrokerConfig {
    /// Flattened so a single `ovstorage.toml` feeds broker + CLI/REST.
    #[serde(flatten)]
    pub library: LibraryConfig,
    #[serde(default)]
    pub discovery: BrokerDiscoveryConfig,
    /// Single listener per broker process. Multi-transport deployments
    /// run two broker processes sharing backend plugin config.
    #[serde(default)]
    pub listener: Option<BrokerListenerConfig>,
    #[serde(default)]
    pub authz: Option<AuthzPluginConfig>,
    #[serde(default)]
    pub observability: Option<BrokerObservabilityConfig>,
    /// Trust-boundary attribution strategy for `modified_by`. Default
    /// `user_metadata` stamps the authn'd principal into a reserved
    /// key in object metadata; `passthrough` for intermediate brokers
    /// in a chain that should forward an upstream broker's stamp
    /// unchanged. `external_db` is reserved for v2.
    #[serde(default)]
    pub attribution_strategy: AttributionStrategyConfig,
    /// Per-name OAuth provider registry.
    ///
    /// ```toml
    /// [oauth_providers.upstream-idp]
    /// kind = "pkce"
    /// backend_kind = "nucleus"
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
    /// "nucleus://prod/" = "upstream-idp"
    /// ```
    #[serde(default)]
    pub broker_oauth_routes: HashMap<String, String>,
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

/// `[authz]` shape: `plugin` selects the cdylib by manifest name; the
/// rest of the table is captured opaquely and handed to the plugin's
/// `configure` step.
///
/// ```toml
/// [authz]
/// plugin = "ovstorage-authz-toml"
/// decision_ttl_max_seconds = 60
///
/// [[authz.policy]]
/// id = "allow-team"
/// effect = "allow"
/// principal = "team-*"
/// operations = ["read"]
/// prefix = "file:/root/"
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AuthzPluginConfig {
    pub plugin: String,
    #[serde(flatten)]
    pub config: toml::Table,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
    /// When absent, `mode` is auto-selected from the transport:
    /// `peer_cred` for UDS / named-pipe, `jwt_verify` for TCP.
    #[serde(default)]
    pub authn: Option<BrokerListenerAuthnConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BrokerListenerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
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

    /// Resolve the effective authn config — either the operator's
    /// explicit `[listener.authn]` or the auto-default for the
    /// detected transport.
    pub fn resolved_authn(&self) -> ovstorage::Result<BrokerListenerAuthnConfig> {
        if let Some(authn) = &self.authn {
            return Ok(authn.clone());
        }
        let mode = match self.transport()? {
            BrokerTransport::UnixSocket(_) | BrokerTransport::NamedPipe(_) => {
                BrokerAuthnMode::PeerCred
            }
            BrokerTransport::Tcp(_) => BrokerAuthnMode::JwtVerify,
        };
        Ok(BrokerListenerAuthnConfig {
            mode,
            issuer: None,
            audience: None,
            jwks_url: None,
            identity_header: default_forwarded_identity_header(),
            claim_headers: HashMap::new(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BrokerListenerAuthnConfig {
    #[serde(default)]
    pub mode: BrokerAuthnMode,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default = "default_forwarded_identity_header")]
    pub identity_header: String,
    #[serde(default)]
    pub claim_headers: HashMap<String, String>,
}

impl Default for BrokerListenerAuthnConfig {
    fn default() -> Self {
        Self {
            mode: BrokerAuthnMode::default(),
            issuer: None,
            audience: None,
            jwks_url: None,
            identity_header: default_forwarded_identity_header(),
            claim_headers: HashMap::new(),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrokerAuthnMode {
    #[default]
    JwtVerify,
    TrustedUnsignedJwt,
    TrustedForwardedHeaders,
    PeerCred,
    Mtls,
}
