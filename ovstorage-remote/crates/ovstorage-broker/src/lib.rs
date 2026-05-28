// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![allow(
    clippy::collapsible_if,
    clippy::result_large_err,
    clippy::large_enum_variant,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items
)]

#[cfg(test)]
mod test_utils;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use std::{
    os::windows::io::AsRawHandle,
    task::{Context, Poll},
};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_core::Stream;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage::{
    AccessOps, AddressVisibility, Alias, AliasRequest, Body, ChangeEvent, ChangeStream, Connection,
    ConnectionConfig, ConnectionRequest, Error, ErrorCode, HttpRequest, Library, LibraryBuilder,
    LibraryConfig, ObjectInfo, ObjectKind, ReadRedirect, RedirectBodySource, RedirectResultBatch,
    RedirectScope, RouteConfig, SecretBundle, StatOptions, StateConfig, Storage,
    StorageBackendKindDescriptor, Url, UserMetadata, WatchDirectoryOptions, WriteOptions,
    WriteRedirect, WriteRedirectBatch, WriteResult, address,
};
use ovstorage_authz::{
    AttributionLayer, AttributionStrategy, AuthzDecision, AuthzPlugin, AuthzRequest, Operation,
    Principal, RequestContext,
};
#[cfg(test)]
use ovstorage_authz_toml::{TomlAuthzConfig, TomlAuthzPlugin};
use ovstorage_broker_protocol::{
    self as protocol, BrokerClientTransport, BrokerClientWatchDirectoryStream, health_pb, pb,
};
use ovstorage_cache::{Cache, CacheConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response as GrpcResponse, Status};

mod authn;
mod authz_plugins;
mod broker;
mod client_transport;
mod config;
mod discovery;
mod grpc;
mod lifecycle;
mod oauth_providers;
mod observability;
mod policy;
mod redirect_fetch;
mod trace;
mod watch;

#[allow(unused_imports)]
pub use authn::*;
pub use authz_plugins::*;
pub use broker::*;
pub use config::*;
pub use discovery::*;
pub use grpc::*;
pub use lifecycle::{DEFAULT_DRAIN_TIMEOUT, LifecycleController};
pub use oauth_providers::*;
pub use observability::{
    AuthzOutcome, BrokerObservabilityConfig, MetricsGuard, PrometheusServer, install_recorders,
    prometheus_handle, prometheus_router, spawn_prometheus_listener,
};
pub use ovstorage::{
    AzureEventGridDispatcher, DisabledDispatcher, GcpPubsubDispatcher, Invalidation, MetadataCache,
    MetadataCacheConfig, MetadataCacheKey, MetadataCachePayload, MetadataKind,
    NotificationDispatcher, NotificationSourceConfig, NotificationSourceKind, S3SqsDispatcher,
};
pub use policy::*;
pub use redirect_fetch::{
    NotCacheableReason, RedirectFetchOutcome, broker_byte_cache_info_key, broker_byte_cache_key,
    decode_cached_object_info, encode_cached_object_info, follow_read_redirect,
};
pub use trace::RedactedUrl;
#[allow(unused_imports)]
pub use watch::*;

pub async fn build_default_broker() -> ovstorage::Result<Broker> {
    Ok(Broker::with_authz_plugin_policies_and_epoch_state(
        build_default_library().await?,
        Arc::new(AllowAllAuthzPlugin),
        BrokerRoutePolicies::default(),
        policy_state_from_config_or_env(None)?,
    ))
}

/// Build a fully-defaulted [`BrokerConfig`] for "no args, just works"
/// mode: a local UDS / named-pipe listener with auto-selected
/// `peer_cred`, `file:/` mounted at a sandbox dir under the user's data
/// home, and an allow-all toml authz rule. Creates the sandbox dir.
///
/// Security relies on the local-trust-scope transport: only processes
/// running as the same OS user can connect.
pub fn zero_config_broker_config() -> ovstorage::Result<(BrokerConfig, PathBuf)> {
    let bind = default_zero_config_bind()?;
    let sandbox = default_zero_config_sandbox_dir()?;
    fs::create_dir_all(&sandbox).map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!(
                "failed to create zero-config sandbox dir at {}: {err}",
                sandbox.display()
            ),
        )
    })?;
    let config = build_zero_config_struct(bind, &sandbox);
    Ok((config, sandbox))
}

/// Pure-construct variant — no filesystem side effects. Tests + the
/// public helper share this so callers can inject paths under a tmp
/// dir without requiring `~/.local/share` to be writable.
pub fn build_zero_config_struct(bind: String, sandbox: &Path) -> BrokerConfig {
    let mut rule = toml::value::Table::new();
    rule.insert(
        "id".into(),
        toml::Value::String("zero-config-allow-all".into()),
    );
    rule.insert("effect".into(), toml::Value::String("allow".into()));
    rule.insert("principal".into(), toml::Value::String("*".into()));
    rule.insert(
        "operations".into(),
        toml::Value::Array(vec![toml::Value::String("*".into())]),
    );
    rule.insert("prefix".into(), toml::Value::String("*".into()));
    let mut authz_table = toml::value::Table::new();
    authz_table.insert(
        "policy".into(),
        toml::Value::Array(vec![toml::Value::Table(rule)]),
    );

    let mut file_config = HashMap::new();
    file_config.insert(
        "root".into(),
        toml::Value::String(sandbox.to_string_lossy().into_owned()),
    );

    let library = LibraryConfig {
        connections: vec![ConnectionConfig {
            backend_kind: "file".into(),
            display_name: Some("zero-config sandbox".into()),
            config: file_config,
            credentials: HashMap::new(),
        }],
        ..Default::default()
    };

    BrokerConfig {
        library,
        listener: Some(BrokerListenerConfig {
            bind,
            tls: None,
            trusted_proxy: false,
            trusted_peers: Vec::new(),
            authn: None,
        }),
        authz: Some(AuthzPluginConfig {
            plugin: "ovstorage-authz-toml".into(),
            config: authz_table,
        }),
        ..Default::default()
    }
}

#[cfg(unix)]
fn default_zero_config_bind() -> ovstorage::Result<String> {
    // WSLg points XDG_RUNTIME_DIR at /mnt/wslg/runtime-dir, a 9P mount
    // that returns EROFS on file creation despite `is_dir()` succeeding.
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if runtime.is_dir() && is_dir_writable(&runtime) {
            return Ok(runtime
                .join("ovstorage-broker.sock")
                .to_string_lossy()
                .into_owned());
        }
    }
    Ok(std::env::temp_dir()
        .join(format!("ovstorage-broker-{}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned())
}

#[cfg(unix)]
fn is_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".ovstorage-probe-{}", std::process::id()));
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
fn default_zero_config_bind() -> ovstorage::Result<String> {
    Ok("pipe:ovstorage-broker".into())
}

fn default_zero_config_sandbox_dir() -> ovstorage::Result<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(data).join("ovstorage-broker").join("sandbox"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("ovstorage-broker")
                .join("sandbox"));
        }
        Ok(std::env::temp_dir().join("ovstorage-broker-sandbox"))
    }
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local)
                .join("ovstorage-broker")
                .join("sandbox"));
        }
        Ok(std::env::temp_dir().join("ovstorage-broker-sandbox"))
    }
}

/// Registers `broker:/` and `broker:///` aliases for the zero-config
/// sandbox. Two forms because `broker` is a non-special scheme — the URL
/// parser preserves `broker:/x` and `broker:///x` as distinct strings, and
/// our route table matches by string prefix.
pub fn register_zero_config_alias(broker: &Broker, sandbox: &Path) -> ovstorage::Result<()> {
    let to = Url::from_directory_path(sandbox).map_err(|()| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "zero-config sandbox path is not absolute: {}",
                sandbox.display()
            ),
        )
    })?;
    for from in ["broker:/", "broker:///"] {
        broker.library().add_alias(AliasRequest {
            from: Url::parse(from).expect("static URL"),
            to: to.clone(),
            visibility: AddressVisibility::Visible,
            persist: false,
            display_name: Some("zero-config broker shortcut".into()),
            user_metadata: UserMetadata::new(),
        })?;
    }
    Ok(())
}

pub async fn build_default_library() -> ovstorage::Result<Arc<Library>> {
    let mut builder = builtin_library_builder()?;
    if let Some(cache) = cache_from_env()? {
        builder = builder.with_cache(cache);
    }
    let library = builder.open()?;
    load_default_plugins(&library)?;
    Ok(library)
}

pub async fn build_broker_from_config_file(path: impl AsRef<Path>) -> ovstorage::Result<Broker> {
    let config = load_broker_config_file(path)?;
    build_broker_from_config(&config).await
}

pub async fn build_broker_from_config(config: &BrokerConfig) -> ovstorage::Result<Broker> {
    validate_broker_config_for_startup(config)?;
    let mut broker = Broker::with_authz_plugin_policies_and_epoch_state(
        build_library_from_config(config).await?,
        build_authz_plugin_from_config(config.authz.as_ref()).await?,
        BrokerRoutePolicies::from_config(&config.library.routes)?,
        policy_state_from_config_or_env(config.library.state.as_ref())?,
    )
    .with_attribution_strategy(config.attribution_strategy.into())?;
    if let Some(byte_cache) = cache_from_config_or_env(config.library.state.as_ref())? {
        broker = broker.with_byte_cache(Arc::new(byte_cache));
    }
    let (registry, bindings) = build_oauth_providers_from_config(config)?;
    broker = broker.with_oauth_providers(registry, bindings);
    Ok(broker)
}

pub fn load_broker_config_file(path: impl AsRef<Path>) -> ovstorage::Result<BrokerConfig> {
    use figment::{
        Figment,
        providers::{Env, Format, Toml},
    };

    Figment::new()
        .merge(Toml::file(path.as_ref()))
        .merge(
            Env::prefixed("OVSTORAGE_BROKER__")
                .map(|key| {
                    let lowered: String = key.as_str().to_lowercase().replace("__", ".");
                    lowered.into()
                })
                .split("."),
        )
        .extract()
        .map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid broker config: {error}"),
            )
        })
}

pub async fn build_broker_from_config_str(contents: &str) -> ovstorage::Result<Broker> {
    let config = parse_broker_config(contents)?;
    build_broker_from_config(&config).await
}

/// Build the OAuth provider registry + per-route bindings from the
/// broker's TOML.
pub fn build_oauth_providers_from_config(
    config: &BrokerConfig,
) -> ovstorage::Result<(Arc<OAuthProviderRegistry>, BrokerOAuthRouteBindings)> {
    let (secret_store, refresh_lock) = cached_broker_substrate()?;
    let registry = build_oauth_provider_registry(
        &config.oauth_providers,
        secret_store.clone(),
        refresh_lock.clone(),
    )?;
    let mut bindings = BrokerOAuthRouteBindings::new();
    for (prefix, provider_name) in &config.broker_oauth_routes {
        if !config.oauth_providers.contains_key(provider_name) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: route '{prefix}' references oauth_providers \
                     entry '{provider_name}' which is not defined"
                ),
            ));
        }
        let url = ovstorage::address::parse(prefix).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: prefix '{prefix}' is invalid: {}",
                    err.message()
                ),
            )
        })?;
        bindings = bindings.with_route(url, provider_name.clone());
    }
    Ok((registry, bindings))
}

pub fn parse_broker_config(contents: &str) -> ovstorage::Result<BrokerConfig> {
    use figment::{
        Figment,
        providers::{Format, Toml},
    };

    // Test/programmatic path: parse a TOML string. Env-var overlay is
    // intentionally skipped here so unit tests with explicit configs
    // don't pick up developer environments. Operator-facing parsing
    // goes through `load_broker_config_file`.
    Figment::new()
        .merge(Toml::string(contents))
        .extract()
        .map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid broker config: {error}"),
            )
        })
}

pub fn validate_broker_config_for_startup(config: &BrokerConfig) -> ovstorage::Result<()> {
    if let Some(listener) = &config.listener {
        validate_listener_for_startup(listener)?;
    }
    BrokerRoutePolicies::from_config(&config.library.routes)?;
    // Sync shape-check only; dlopen + configure() happen in the async
    // build path.
    require_authz_section(config.authz.as_ref())?;
    // OAuth relay only valid over network gRPC; UDS / named-pipe are
    // local-trust-scope and a local attacker could route around the
    // network listener's auth.
    validate_oauth_providers_against_listeners(config)?;
    Ok(())
}

/// Refuse startup when a local-trust-scope listener (UDS / named-pipe)
/// coexists with `oauth_providers` config; a local attacker could route
/// around the network listener's auth.
pub fn validate_oauth_providers_against_listeners(config: &BrokerConfig) -> ovstorage::Result<()> {
    let any_local = match &config.listener {
        Some(listener) => listener.transport().map(|t| t.is_local()).unwrap_or(false),
        None => false,
    };
    let any_oauth = !config.oauth_providers.is_empty() || !config.broker_oauth_routes.is_empty();
    if any_local && any_oauth {
        return Err(invalid_config(
            "oauth_provider config is incompatible with local-trust-scope \
             transports (unix-socket / named-pipe); OAuth relay is only valid \
             over grpc+tcp / grpc+tls. Move the broker's OAuth listener onto \
             a network transport, or remove [oauth_providers] / \
             [broker_oauth_routes] from this config",
        ));
    }
    Ok(())
}

fn require_authz_section(config: Option<&AuthzPluginConfig>) -> ovstorage::Result<()> {
    let Some(config) = config else {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "broker config must include [authz] with plugin = \"<authz-plugin-name>\"",
        ));
    };
    if config.plugin.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "[authz] plugin field must not be empty",
        ));
    }
    Ok(())
}

/// Build the authz plugin by dlopening the cdylib matching
/// `config.plugin`.
pub async fn build_authz_plugin_from_config(
    config: Option<&AuthzPluginConfig>,
) -> ovstorage::Result<Arc<dyn AuthzPlugin>> {
    require_authz_section(config)?;
    let config = config.unwrap();

    let dir = ovstorage::default_plugin_dir().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "could not resolve a plugin directory (set OVSTORAGE_PLUGIN_DIR)",
        )
    })?;
    // SAFETY: dlopen runs platform loader hooks; the operator controls
    // OVSTORAGE_PLUGIN_DIR and the cdylibs it contains.
    let plugin =
        unsafe { ovstorage_authz::loaded::load_authz_plugin_for_kind(&dir, &config.plugin) }?;

    // Top-level scalars get the typed ConfigValue variant; nested
    // tables/arrays reserialize to TOML and arrive as ConfigValue::Toml,
    // matching the shape backend plugins receive.
    let mut config_map = HashMap::with_capacity(config.config.len());
    for (key, value) in &config.config {
        let cv = match value {
            toml::Value::String(s) => ovstorage::ConfigValue::String(s.clone()),
            toml::Value::Integer(n) => ovstorage::ConfigValue::Int(*n),
            toml::Value::Boolean(b) => ovstorage::ConfigValue::Bool(*b),
            toml::Value::Table(_) | toml::Value::Array(_) => {
                // toml::to_string needs a top-level table; wrap under the
                // key so `[[<key>]]\n...` round-trips through the plugin's
                // own toml::from_str.
                let mut wrapper = toml::value::Table::new();
                wrapper.insert(key.clone(), value.clone());
                let toml_str = toml::to_string(&toml::Value::Table(wrapper)).map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("[authz] field '{key}' could not be reserialized to TOML: {err}"),
                    )
                })?;
                ovstorage::ConfigValue::Toml(toml_str)
            }
            other => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "[authz] field '{key}' has unsupported type: {}",
                        other.type_str()
                    ),
                ));
            }
        };
        config_map.insert(key.clone(), cv);
    }

    plugin.configure(config_map, None).await?;
    Ok(Arc::new(plugin))
}

pub async fn build_library_from_config(config: &BrokerConfig) -> ovstorage::Result<Arc<Library>> {
    let mut builder = builtin_library_builder()?;
    if let Some(cache) = cache_from_config_or_env(config.library.state.as_ref())? {
        builder = builder.with_cache(cache);
    }
    if let Some(cfg) = config.library.metadata_cache.clone() {
        builder = builder.with_metadata_cache(cfg);
    }
    let library = builder.open()?;
    load_default_plugins(&library)?;
    for connection in &config.library.connections {
        library
            .add_connection(connection.to_connection_request()?, None)
            .await?;
    }
    Ok(library)
}

pub fn default_context() -> RequestContext {
    RequestContext {
        principal: Principal {
            id: current_principal(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "default_context".into(),
        },
        policy_epoch: 0,
        audit_id: None,
    }
}

fn redirect_request(method: &str, endpoint: &str, address: &Url) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        url: endpoint.into(),
        headers: vec![("x-ov-address".into(), address.to_string())],
    }
}

fn redirect_body_source(
    body: &Body,
    options: &WriteOptions,
) -> ovstorage::Result<RedirectBodySource> {
    let len = match options.size_hint {
        Some(len) => len,
        None => body_len(body)?,
    };
    if len == 0 {
        Ok(RedirectBodySource::Empty)
    } else {
        Ok(RedirectBodySource::UserBytes { offset: 0, len })
    }
}

fn body_len(body: &Body) -> ovstorage::Result<u64> {
    match body {
        Body::Bytes(bytes) => Ok(bytes.len() as u64),
        Body::LocalFile(path) => Ok(fs::metadata(path).map_err(map_io)?.len()),
        // Streams must not drain to Vec<u8> (memory-DoS); size-aware
        // routing must use a different path.
        Body::Stream(_) => Err(ovstorage::Error::new(
            ovstorage::ErrorCode::Unsupported,
            "broker: body_len does not support Body::Stream (size unknown until \
             consumed; use the streaming write path)",
        )),
    }
}

fn audit_id_for(context: &RequestContext) -> String {
    context
        .audit_id
        .clone()
        .unwrap_or_else(|| format!("broker-policy-epoch-{}", context.policy_epoch))
}
fn cache_from_env() -> ovstorage::Result<Option<Cache>> {
    cache_from_config_or_env(None)
}

fn policy_state_from_config_or_env(
    config: Option<&StateConfig>,
) -> ovstorage::Result<Arc<BrokerPolicyEpochState>> {
    match state_root_from_config_or_env(config) {
        Some(state_root) => BrokerPolicyEpochState::open(state_root, BrokerPolicyFreshness::Strict),
        None => Ok(BrokerPolicyEpochState::in_memory(
            0,
            BrokerPolicyFreshness::Strict,
        )),
    }
}

fn state_root_from_config_or_env(config: Option<&StateConfig>) -> Option<PathBuf> {
    config
        .and_then(|c| c.state_root.clone())
        .or_else(|| std::env::var_os("OVSTORAGE_BROKER_STATE_ROOT").map(PathBuf::from))
        .or_else(|| std::env::var_os("OVSTORAGE_STATE_ROOT").map(PathBuf::from))
}

fn cache_from_config_or_env(config: Option<&StateConfig>) -> ovstorage::Result<Option<Cache>> {
    let state_root = state_root_from_config_or_env(config);
    let cache_root = config
        .and_then(|c| c.cache_root.clone())
        .or_else(|| std::env::var_os("OVSTORAGE_BROKER_CACHE_ROOT").map(PathBuf::from))
        .or_else(|| std::env::var_os("OVSTORAGE_CACHE_ROOT").map(PathBuf::from));
    match (state_root, cache_root) {
        (Some(state_root), Some(cache_root)) => Cache::open(CacheConfig {
            state_root,
            cache_root,
        })
        .map(Some),
        (_, None) => Ok(None),
        (None, Some(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "broker cache_root requires state_root",
        )),
    }
}

/// Process-cached `(SecretStore, AuthRefreshLock)` pair. The host
/// substrate is set-once-per-process at the plugin SPI; every
/// `LibraryBuilder` must reuse the same Arcs or the second
/// `Library::open` returns `Unsupported`.
pub(crate) fn cached_broker_substrate()
-> ovstorage::Result<&'static (Arc<SecretStore>, Arc<AuthRefreshLock>)> {
    static CACHE: std::sync::OnceLock<(Arc<SecretStore>, Arc<AuthRefreshLock>)> =
        std::sync::OnceLock::new();
    static INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    if let Some(s) = CACHE.get() {
        return Ok(s);
    }
    // OnceLock::get_or_init is closure-only; without the mutex two
    // concurrent callers can race two `AuthRefreshLock::open` calls on
    // the same SQLite db ("database is locked"). Serialize the fallible
    // init and double-check inside the lock.
    let _guard = INIT_LOCK.lock().unwrap();
    if let Some(s) = CACHE.get() {
        return Ok(s);
    }
    let auth_root = broker_auth_state_root()?;
    let secret_store = Arc::new(SecretStore::new());
    let refresh_lock = Arc::new(AuthRefreshLock::open(&auth_root)?);
    Ok(CACHE.get_or_init(|| (secret_store, refresh_lock)))
}

fn builtin_library_builder() -> ovstorage::Result<LibraryBuilder> {
    let (secret_store, refresh_lock) = cached_broker_substrate()?;

    // Set `OVSTORAGE_ALLOW_TEST_PLUGINS=1` to make the bulk loader
    // actually accept `test_only = true` cdylibs in
    // `OVSTORAGE_PLUGIN_DIR`. With the env unset, those cdylibs are
    // silently skipped (debug-log level) and the rest of the
    // discovery scan continues — production deployments don't need
    // to touch the env even if the directory happens to contain a
    // test plugin (e.g. shipped in the release archive for
    // consumer-side testing).
    let allow_test_plugins =
        std::env::var_os("OVSTORAGE_ALLOW_TEST_PLUGINS").is_some_and(|v| v == "1");

    Ok(Library::builder()
        .with_credential_persistence(secret_store.clone(), refresh_lock.clone())
        .allow_test_plugins(allow_test_plugins))
}

fn load_default_plugins(library: &Library) -> ovstorage::Result<()> {
    let plugin_dir = ovstorage::default_plugin_dir().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "could not resolve a default plugin directory; set OVSTORAGE_PLUGIN_DIR",
        )
    })?;
    // SAFETY: dlopen runs platform loader hooks; the operator
    // controls `OVSTORAGE_PLUGIN_DIR` and the binary's install dir.
    unsafe { library.load_plugins_from_dir(Some(&plugin_dir)) }
}

fn broker_auth_state_root() -> ovstorage::Result<PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-broker-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        Error::new(
            ErrorCode::StateRootUnavailable,
            format!("failed to create broker auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}

fn validate_listener_for_startup(listener: &BrokerListenerConfig) -> ovstorage::Result<()> {
    let label = "listener";
    let transport = listener.transport()?;
    if listener.trusted_proxy && listener.trusted_peers.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} sets trusted_proxy = true but does not configure trusted peer constraints"
            ),
        ));
    }
    if listener.trusted_proxy && transport.is_local() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} trusted_proxy = true is only valid on tcp listeners; \
                 unix-socket / named-pipe transports carry no peer IP and \
                 trusted_peers cannot be enforced"
            ),
        ));
    }
    parse_trusted_peers(&listener.trusted_peers)?;
    if let BrokerTransport::Tcp(addr) = &transport {
        if listener.tls.is_none() && !addr.ip().is_loopback() {
            if !listener.trusted_proxy || listener.trusted_peers.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{label} plaintext TCP on a non-loopback bind requires trusted_proxy = true and trusted peer constraints"
                    ),
                ));
            }
        }
    }

    let authn = listener.resolved_authn()?;
    match authn.mode {
        BrokerAuthnMode::JwtVerify => {
            require_nonempty_option(label, "authn.issuer", authn.issuer.as_deref())?;
            require_nonempty_option(label, "authn.audience", authn.audience.as_deref())?;
            require_nonempty_option(label, "authn.jwks_url", authn.jwks_url.as_deref())?;
            validate_url(
                &format!("{label} authn.jwks_url"),
                authn.jwks_url.as_deref().unwrap_or_default(),
            )
        }
        BrokerAuthnMode::TrustedUnsignedJwt => {
            require_trusted_proxy_listener(label, listener)?;
            Ok(())
        }
        BrokerAuthnMode::TrustedForwardedHeaders => {
            require_trusted_proxy_listener(label, listener)?;
            if authn.identity_header.trim().is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("{label} authn.identity_header must not be empty"),
                ));
            }
            Ok(())
        }
        BrokerAuthnMode::PeerCred => {
            if matches!(transport, BrokerTransport::Tcp(_)) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("{label} authn.mode = \"peer_cred\" is only valid on local transports"),
                ));
            }
            Ok(())
        }
        BrokerAuthnMode::Mtls => Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "{label} authn.mode = \"mtls\" is reserved in 0.4; full mTLS certificate validation and principal mapping ship in 0.5"
            ),
        )),
    }
}

fn require_trusted_proxy_listener(
    label: &str,
    listener: &BrokerListenerConfig,
) -> ovstorage::Result<()> {
    let mode = listener.authn.as_ref().map(|a| a.mode).unwrap_or_default();
    if !listener.trusted_proxy {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} authn.mode = \"{}\" requires trusted_proxy = true",
                authn_mode_name(mode)
            ),
        ));
    }
    if listener.trusted_peers.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} authn.mode = \"{}\" requires trusted peer constraints",
                authn_mode_name(mode)
            ),
        ));
    }
    Ok(())
}

fn require_nonempty_option(label: &str, field: &str, value: Option<&str>) -> ovstorage::Result<()> {
    if value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!("{label} {field} must be configured"),
    ))
}

fn authn_mode_name(mode: BrokerAuthnMode) -> &'static str {
    match mode {
        BrokerAuthnMode::JwtVerify => "jwt_verify",
        BrokerAuthnMode::TrustedUnsignedJwt => "trusted_unsigned_jwt",
        BrokerAuthnMode::TrustedForwardedHeaders => "trusted_forwarded_headers",
        BrokerAuthnMode::PeerCred => "peer_cred",
        BrokerAuthnMode::Mtls => "mtls",
    }
}

fn default_forwarded_identity_header() -> String {
    "x-forwarded-user".into()
}

fn default_discovery_name() -> String {
    "ovstorage broker".into()
}

fn validate_url(field: &str, value: &str) -> ovstorage::Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_config(format!("{field} must not be empty")));
    }
    url::Url::parse(trimmed).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{field} must be a URL: {error}"),
        )
    })?;
    Ok(())
}

fn invalid_config(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn http_error_response(error: Error) -> Response {
    (
        status_for_error(error.code()),
        Json(json!({
            "error": {
                "code": format!("{:?}", error.code()),
                "message": error.message(),
            }
        })),
    )
        .into_response()
}

fn status_for_error(code: ErrorCode) -> StatusCode {
    // Exhaustive match: a wildcard would silently collapse new
    // variants to 500 and lose retryability information for clients.
    match code {
        ErrorCode::NotConfigured | ErrorCode::NotFound | ErrorCode::NoRoute => {
            StatusCode::NOT_FOUND
        }
        ErrorCode::PermissionDenied | ErrorCode::PluginRejected => StatusCode::FORBIDDEN,
        ErrorCode::AuthRequired
        | ErrorCode::AuthExpired
        | ErrorCode::AuthCancelled
        | ErrorCode::CredentialExpired
        | ErrorCode::CredentialUnavailable
        | ErrorCode::AuthorizationLeaseExpired => StatusCode::UNAUTHORIZED,
        ErrorCode::InvalidArgument | ErrorCode::AliasChainTooLong => StatusCode::BAD_REQUEST,
        ErrorCode::AlreadyExists
        | ErrorCode::Conflict
        | ErrorCode::DirectoryNotEmpty
        | ErrorCode::IncompatibleType
        | ErrorCode::RouteConflict
        | ErrorCode::PolicyEpochStale => StatusCode::CONFLICT,
        ErrorCode::Locked => StatusCode::LOCKED,
        ErrorCode::PreconditionFailed | ErrorCode::ObjectModified => {
            StatusCode::PRECONDITION_FAILED
        }
        ErrorCode::IntegrityFailure
        | ErrorCode::ContentMismatch
        | ErrorCode::ContentChecksumMismatch => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::RedirectExpired | ErrorCode::StagingExpired => StatusCode::GONE,
        ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
        ErrorCode::ResourceExhausted | ErrorCode::CacheLockContention => {
            StatusCode::TOO_MANY_REQUESTS
        }
        ErrorCode::Cancelled | ErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        ErrorCode::Transient | ErrorCode::BrokerUnavailable => StatusCode::BAD_GATEWAY,
        ErrorCode::BrokerRequired
        | ErrorCode::StateRootUnavailable
        | ErrorCode::NetworkFilesystemRefused => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Internal | ErrorCode::CacheCorrupt | ErrorCode::CommitAmbiguous => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        // Defensive: future ErrorCode variants surface as 500 until
        // they get an explicit arm. `ErrorCode` is `#[non_exhaustive]`.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_io(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

fn current_principal() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "local".into())
}

#[cfg(test)]
mod tests;
