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
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
use futures_core::Stream;
use ovstorage::auth::{AuthRefreshLock, SecretStore, SqliteSecretStore};
use ovstorage::{
    AccessOps, Body, ChangeStream, CheckAccessRequest, Connection, ConnectionConfig,
    ContinueWriteRequest, CopyRequest, CreateDirectoryRequest, DeleteDirectoryRequest,
    DeleteRequest, Error, ErrorCode, Layer, ListRequest, ListVersionsRequest, ObjectInfo,
    ReadRedirect, ReadRequest, ReadResult, RedirectResultBatch, RenameRequest, Stack, StatOptions,
    StatRequest, StorageBackendKindDescriptor, UpdateMetadataRequest, Url, WatchDirectoryOptions,
    WatchDirectoryRequest, WriteOptions, WriteRedirectBatch, WriteRequest, WriteResult, address,
    canonicalize,
};
// Names consumed only by the in-crate test modules via `use super::*`
// (production dispatch does not reference them directly).
#[cfg(test)]
use ovstorage::{ConnectionRequest, SecretBundle};
// The broker keeps `ovstorage-authz` for the attribution overlay (the in-stack
// `AttributionWrapper` Layer + strategy). Authentication + authorization are the
// selected per-listener auth layer (`ovstorage-authz-layer`); the broker gathers
// only the caller's `AuthCredential` (transport + bearer) for it.
use ovstorage_authz::{AttributionStrategy, UserMetadataKinds};
use ovstorage_authz_context::{AuthCredential, ForwardedHeaders, Transport};
use ovstorage_authz_layer::{
    ListenerAuth, ListenerAuthBuildPlan, ListenerWriteAdmission, resolve_listener_auth,
};
use ovstorage_broker_protocol::{
    self as protocol, BrokerClientTransport, BrokerClientWatchDirectoryStream, health_pb, pb,
};
use ovstorage_plugin_cache::{ByteCacheGenerations, ByteCacheWrapperFactory};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response as GrpcResponse, Status};

mod broker;
mod client_transport;
mod config;
mod discovery;
mod grpc;
mod lifecycle;
mod oauth_providers;
mod observability;
mod stack;
mod trace;
mod upstream_credential;
mod watch;
mod write_body;

pub use broker::*;
pub use config::*;
pub use discovery::*;
pub use grpc::*;
pub use lifecycle::{DEFAULT_DRAIN_TIMEOUT, LifecycleController};
pub use oauth_providers::*;
pub use observability::{
    BrokerObservabilityConfig, MetricsGuard, PrometheusServer, install_recorders,
    prometheus_handle, prometheus_router, spawn_prometheus_listener,
};
pub use ovstorage::{
    DisabledDispatcher, Invalidation, MetadataCache, MetadataCacheConfig, MetadataCacheKey,
    MetadataCachePayload, MetadataKind, NotificationDispatcher,
};
pub(crate) use stack::{BrokerGraphOptions, broker_stack_config, with_alias_rules};
pub use stack::{BrokerJwtParams, BrokerStack, BrokerStackBuilder};
pub use trace::RedactedUrl;
pub use upstream_credential::*;
#[allow(unused_imports)]
pub use watch::*;

pub async fn build_default_broker() -> ovstorage::Result<Broker> {
    // The zero-arg default is the broker's forward graph with no connections and
    // no caches (caches are `[ovstorage.layers]` config now).
    let stack_config = broker_stack_config(
        Vec::new(),
        BrokerGraphOptions::default(),
        &UserMetadataKinds::from_factories(&[]),
    );
    // The zero-arg default opts explicitly into the anonymous allow-all auth
    // layer (the sanctioned route to allow-all — never a silent fallback;
    // fail-closed).
    let (_kind, auth_config) = resolve_listener_auth(
        Some(toml::Value::String(
            ovstorage_authz_layer::ANONYMOUS_AUTH_KIND.to_string(),
        )),
        "broker",
        std::iter::empty::<&str>(),
    )?;
    let builder = broker_stack_builder()?
        .stack_config(stack_config)
        .auth_config(auth_config);
    // SAFETY: dlopen runs platform loader hooks; the operator controls
    // `OVSTORAGE_PLUGIN_DIR` and the binary's install dir.
    let broker_stack = unsafe { builder.build().await? };
    Ok(Broker::from_composed(broker_stack))
}

/// Base [`BrokerStackBuilder`] wired with the `test_only`-plugin gate. The auth
/// substrate is left to `init_auth_substrate`'s default resolution
/// (`OVSTORAGE_AUTH_DIR` or a per-pid tmp): passing an explicit dir would make
/// the process-global init reject a second broker built under a different dir
/// (e.g. SIGHUP rebuild, or a test process that builds several brokers), which
/// the `None` path tolerates. Callers layer on connections / caches before
/// `build`.
fn broker_stack_builder() -> ovstorage::Result<BrokerStackBuilder> {
    #[cfg(test)]
    crate::test_utils::ensure_test_plugin_env();
    let allow_test_plugins =
        std::env::var_os("OVSTORAGE_ALLOW_TEST_PLUGINS").is_some_and(|v| v == "1");
    Ok(BrokerStackBuilder::new().allow_test_plugins(allow_test_plugins))
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
    let mut file_config = HashMap::new();
    file_config.insert(
        "root".into(),
        toml::Value::String(sandbox.to_string_lossy().into_owned()),
    );

    // Zero-config declares an EXPLICIT forward graph — the same
    // `alias → … → router → attribution_file → file` chain the
    // shipped `ovstorage-broker.toml`
    // declares — via the shared `broker_stack_config` builder, so it survives the
    // empty-stack refusal like any operator stack (the `broker:///` sandbox
    // aliases are folded in at build time). Forward-only: no caches. This is an
    // opt-in dev convenience, not a silent operator-file default.
    let ovstorage = broker_stack_config(
        vec![ConnectionConfig {
            backend_kind: "file".into(),
            target: None,
            display_name: Some("zero-config sandbox".into()),
            config: file_config,
            credentials: HashMap::new(),
        }],
        BrokerGraphOptions::default(),
        &UserMetadataKinds::from_factories(&[]),
    );

    BrokerConfig {
        ovstorage,
        listener: Some(BrokerListenerConfig {
            bind,
            tls: None,
            trusted_proxy: false,
            trusted_peers: Vec::new(),
            // Zero-config is a local dev sandbox: opt the listener into the
            // explicit unauthenticated allow-all (fail-closed).
            auth: Some(toml::Value::String(
                ovstorage_authz_layer::ANONYMOUS_AUTH_KIND.to_string(),
            )),
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

/// The `broker:///` → sandbox alias for zero-config mode.
///
/// **One rule, and it serves both spellings a caller may write.** `broker:/x`
/// and `broker:///x` are distinct strings that the URL parser preserves, but
/// they name one node: `node_key` reads an absent authority and an empty one
/// alike, so both are `("broker", None, None, "/", None)`. Alias matching is
/// node-aware, so a single `from = broker:///` is an ancestor of both, and
/// `replace_prefix` projects both onto the same sandbox object — measured, for
/// `x`, `a/b` and the root itself.
///
/// Emitting both spellings is therefore not belt-and-braces, it is two rules
/// for one scope, which `validate_alias_rules` refuses as a duplicate `from`.
/// Because the Stack is built eagerly, that refusal is a **startup failure**:
/// the zero-config broker does not come up at all.
///
/// `broker:///` is the spelling kept because it is the one a caller writes.
/// The other direction is not symmetric: with `from = broker:/`, a
/// `broker:///x` request yields the relative suffix `//x` rather than `x`, and
/// only the empty-segment collapse downstream rescues it — a rule that depends
/// on a later normalization to name the right object is a rule that stops
/// working when that normalization moves.
///
/// Composed into the Stack at build time (the Stack is immutable, so aliases
/// cannot be added post-construction).
pub fn zero_config_aliases(sandbox: &Path) -> ovstorage::Result<Vec<(Url, Url)>> {
    let to = Url::from_directory_path(sandbox).map_err(|()| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "zero-config sandbox path is not absolute: {}",
                sandbox.display()
            ),
        )
    })?;
    Ok(vec![(Url::parse("broker:///").expect("static URL"), to)])
}

pub async fn build_broker_from_config_file(path: impl AsRef<Path>) -> ovstorage::Result<Broker> {
    let config = load_broker_config_file(path)?;
    build_broker_from_config(&config).await
}

pub async fn build_broker_from_config(config: &BrokerConfig) -> ovstorage::Result<Broker> {
    build_broker_from_config_with_aliases(config, &[]).await
}

/// Zero-config entry: composes `config`'s Stack plus the `broker:///` sandbox
/// aliases (the immutable Stack bakes aliases at build time).
pub async fn build_zero_config_broker(
    config: &BrokerConfig,
    sandbox: &Path,
) -> ovstorage::Result<Broker> {
    let aliases = zero_config_aliases(sandbox)?;
    build_broker_from_config_with_aliases(config, &aliases).await
}

async fn build_broker_from_config_with_aliases(
    config: &BrokerConfig,
    aliases: &[(Url, Url)],
) -> ovstorage::Result<Broker> {
    validate_broker_config_for_startup(config)?;

    // Built-in/anonymous auth is fully known before dlopen, so preserve the
    // original early empty-stack error. Plugin-shaped auth waits for the
    // builder to validate its kind against loaded factories first.
    if matches!(
        broker_listener_auth_preflight(config.listener.as_ref())?,
        BrokerListenerAuthPreflight::ResolvedBuiltin(_)
    ) {
        ovstorage::host::require_configured_stack(&config.ovstorage)?;
    }

    // The shared inner graph is `[ovstorage]` config, built verbatim; caches +
    // follow policy are the operator's layer config, not host concerns.
    let stack_config = with_alias_rules(config.ovstorage.clone(), aliases.to_vec(), Vec::new())?;
    // Stamp the operator's disclosure policy onto every follower in the graph.
    // The operator sets one top-level key; the follower is where a read refusal
    // can still fetch the bytes, so the value has to reach it. An operator who
    // also writes the layer key by hand gets a startup error naming the
    // top-level key rather than one of the two silently winning.
    let stack_config = ovstorage::host::stamp_redirect_disclosure(
        stack_config,
        config.redirect_credential_disclosure.discloses(),
    )?;
    let (registry, bindings) = build_oauth_providers_from_config(config)?;
    let listener = config.listener.as_ref();
    let listener_name = listener
        .map(|listener| listener.bind.clone())
        .unwrap_or_else(|| "broker".to_string());
    let mut builder = broker_stack_builder()?
        .stack_config(stack_config)
        .require_configured_stack()
        .attribution_strategy(config.attribution_strategy.into())
        .listener_auth(
            listener.and_then(|listener| listener.auth.clone()),
            listener_name,
            listener.is_some_and(|listener| listener.trusted_proxy),
            listener
                .map(|listener| listener.trusted_peers.clone())
                .unwrap_or_default(),
        )
        .oauth(registry, bindings)
        // The same root `build_oauth_providers_from_config` resolved above.
        // Without this the process-global substrate behind the plugin
        // `secret_*` callbacks initialises on the per-user default while the
        // broker's own OAuth providers use the configured directory, so the
        // two halves of one broker's credentials land in different databases.
        .auth_dir(broker_auth_state_root(config.auth.state_root.as_deref()));
    if let Some(factory) = shared_byte_cache_factory(&config.ovstorage)? {
        builder = builder.extra_factory(factory);
    }
    // SAFETY: dlopen runs platform loader hooks; the operator controls the
    // plugin directory and the cdylibs it contains.
    let broker_stack = unsafe { builder.build().await? };

    // The Broker's OAuth registry + route bindings come from the composed
    // BrokerStack: the exact Arcs shared with the immutable
    // `upstream_credential` wrapper, so the control-plane and the in-stack
    // wrapper can never disagree.
    Ok(Broker::from_composed(broker_stack)
        .with_redirect_disclosure(config.redirect_credential_disclosure.discloses()))
}

#[derive(Clone, Debug)]
pub(crate) enum BrokerListenerAuthPreflight {
    ResolvedBuiltin(ovstorage::LayerConfig),
    NeedsPluginFactories,
}

/// Host-owned metadata capture for a trusted-proxy listener.
///
/// Header names are an explicit allowlist and values are copied only when the
/// transport peer matches `trusted_peers`. Keeping the peer gate beside the
/// capture prevents a plugin auth wrapper from ever receiving spoofed
/// forwarded identity metadata from a direct client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokerForwardedHeaderConfig {
    headers: ovstorage_authz_layer::ForwardedHeaderConfig,
    trusted_peers: Vec<String>,
}

impl BrokerForwardedHeaderConfig {
    pub(crate) fn headers(&self) -> &ovstorage_authz_layer::ForwardedHeaderConfig {
        &self.headers
    }

    pub(crate) fn trusts_peer(&self, peer_addr: &str) -> bool {
        ovstorage_authz_layer::is_trusted_peer(peer_addr, &self.trusted_peers).unwrap_or(false)
    }
}

impl BrokerListenerAuthPreflight {
    #[cfg(test)]
    pub(crate) fn into_builtin_config(self) -> ovstorage::Result<ovstorage::LayerConfig> {
        match self {
            Self::ResolvedBuiltin(config) => Ok(config),
            Self::NeedsPluginFactories => Err(Error::new(
                ErrorCode::Unsupported,
                "plugin listener auth config resolves only after plugin factories are loaded",
            )),
        }
    }
}

pub(crate) fn broker_listener_auth_preflight(
    listener: Option<&BrokerListenerConfig>,
) -> ovstorage::Result<BrokerListenerAuthPreflight> {
    let listener_name = listener
        .map(|listener| listener.bind.as_str())
        .unwrap_or("broker");
    let raw_auth = listener.and_then(|listener| listener.auth.clone());
    let plan = ListenerAuthBuildPlan::listener(raw_auth, listener_name);
    let Some(mut resolved) = plan.preflight()? else {
        return Ok(BrokerListenerAuthPreflight::NeedsPluginFactories);
    };
    debug_assert!(resolved.is_builtin());
    // Name this listener for the auth layer's diagnostics, so a layer-level
    // warning (a permissive `trusted_unsigned_jwt` posture) identifies which
    // listener it is about rather than being unattributable.
    ovstorage_authz_layer::configure_listener_id(resolved.config_mut(), listener_name);
    if let Some(listener) = listener {
        ovstorage_authz_layer::configure_trusted_proxy(
            resolved.config_mut(),
            listener.trusted_proxy,
            &listener.trusted_peers,
        )?;
    }
    Ok(BrokerListenerAuthPreflight::ResolvedBuiltin(
        resolved.config().clone(),
    ))
}

/// Resolve the host-side forwarded-header capture for one listener.
///
/// Built-in auth declares its selected identity/claim headers in its typed
/// config. A plugin-auth listener behind an explicitly trusted proxy uses the
/// same standard config fields to select its metadata allowlist (defaulting to
/// `x-forwarded-user`); the plugin still owns decoding and authorization, while
/// the host owns the transport peer allowlist. Every capture remains
/// peer-gated and name-allowlisted.
pub(crate) fn broker_listener_forwarded_header_config(
    listener: Option<&BrokerListenerConfig>,
) -> ovstorage::Result<Option<BrokerForwardedHeaderConfig>> {
    match broker_listener_auth_preflight(listener)? {
        BrokerListenerAuthPreflight::ResolvedBuiltin(config) => {
            ovstorage_authz_layer::forwarded_header_config(&config)?
                .map(|headers| {
                    let listener = listener.expect("resolved listener auth has a listener config");
                    Ok(BrokerForwardedHeaderConfig {
                        headers,
                        trusted_peers: listener.trusted_peers.clone(),
                    })
                })
                .transpose()
        }
        BrokerListenerAuthPreflight::NeedsPluginFactories => {
            let listener = listener.expect("plugin listener auth has a listener config");
            if !listener.trusted_proxy {
                return Ok(None);
            }
            if listener.trusted_peers.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "plugin auth forwarded-header capture requires a non-empty trusted_peers list",
                ));
            }
            ovstorage_authz_layer::validate_trusted_peers(&listener.trusted_peers)?;
            let raw_auth = listener
                .auth
                .as_ref()
                .and_then(toml::Value::as_table)
                .expect("plugin auth preflight accepts only an auth table");
            let kind = raw_auth
                .get("kind")
                .and_then(toml::Value::as_str)
                .expect("plugin auth preflight accepts only a string kind");
            let (_, plugin_config) = resolve_listener_auth(
                listener.auth.clone(),
                &listener.bind,
                std::iter::once(kind),
            )?;
            Ok(Some(BrokerForwardedHeaderConfig {
                headers: ovstorage_authz_layer::plugin_forwarded_header_config(&plugin_config)?,
                trusted_peers: listener.trusted_peers.clone(),
            }))
        }
    }
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
    let (secret_store, refresh_lock) = cached_broker_substrate(config.auth.state_root.as_deref())?;
    let registry = build_oauth_provider_registry(
        &config.oauth_providers,
        secret_store.clone(),
        refresh_lock.clone(),
    )?;
    let mut bindings = BrokerOAuthRouteBindings::new();
    // Two bindings whose prefixes differ only in spelling scope the same
    // addresses, so whichever is applied first silently decides which
    // credential a request is signed with — and `broker_oauth_routes` is a
    // `HashMap`, so that is not even the order the operator wrote. Refuse at
    // load and make them say which one they meant.
    for (prefix, provider_name) in &config.broker_oauth_routes {
        // The first two refusals in this loop are the only ones that cannot
        // render the route through `RedactedUrl`: neither has a parsed URL to
        // render — one runs before the parse and the other IS the parse
        // failing — and there is no way to tell a password from a path in
        // `svc:s3cr3t,pw@host/`. Both therefore name the route by its byte
        // length alone. A route key is operator-written and may carry userinfo
        // or a signed query, and `Error`'s redactor is not a backstop for
        // either.
        //
        // The first is the shared configuration-address rule: a route key may
        // carry neither a query nor a fragment. The raw string is the only view
        // in which the fragment still exists — `address::parse` strips one — so
        // a route key carrying a fragment would match a scope the operator did
        // not spell and nothing after the parse could see it.
        if let Some(component) = ovstorage::address::refused_config_component(prefix) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: a prefix of {} bytes carries a {}; a route is \
                     matched on scheme, authority and path alone",
                    prefix.len(),
                    component.name()
                ),
            ));
        }
        // The second: the parse itself. Every refusal BELOW this point has a
        // `Url` and renders it through `RedactedUrl`, which is why the parse
        // comes before them. `err.message()` already
        // identifies the rule that refused it and names the scheme where there
        // is one — the same trade `address::parse` itself makes for this class.
        let url = ovstorage::address::parse(prefix).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: an invalid prefix of {} bytes: {}",
                    prefix.len(),
                    err.message()
                ),
            )
        })?;
        // Rendered redacted, like the duplicate-scope refusal below it. This
        // one is the EASIER of the two to reach — no collision is needed, just
        // a mistyped provider name — and the route is operator-written, so it
        // may carry userinfo or a signed query.
        if !config.oauth_providers.contains_key(provider_name) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: route '{}' references oauth_providers \
                     entry '{provider_name}' which is not defined",
                    RedactedUrl(&url)
                ),
            ));
        }
        // Every rule that can be asked of the PARSED prefix, asked once,
        // through the predicate `BrokerOAuthRouteBindings::with_route` also
        // calls — so a rule added to either ingress reaches both. They had
        // already diverged twice, once per rule, and each time the programmatic
        // path bound something this loop refuses to start over.
        //
        // A route prefix that SELECTS addresses is matched on scheme, host,
        // port and path, so nothing here consults the userinfo:
        // `https://tenant-a@origin/team/` selects `https://origin/team/x` and
        // `https://tenant-b@origin/team/x` as well, minting tenant-a's provider
        // for a request written under another credential. And two spellings of
        // one scope tie under `node_rank`, so which of the two applies is
        // decided by iteration order over a `HashMap`.
        //
        // The set of already-accepted prefixes is `bindings` itself rather than
        // a second collection beside it: this loop returns on every problem, so
        // nothing unaccepted is ever in there, and one source cannot drift from
        // the other.
        //
        // Rendered through `RedactedUrl`, never the raw written prefix.
        // `Error`'s own redactor is not a backstop — it recognizes only known
        // provider query names, and its URL scan ends at punctuation, so a
        // password containing a comma survives it verbatim.
        if let Some(problem) = route_prefix_problem(&url, bindings.iter().map(|(bound, _)| bound)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker_oauth_routes: prefix '{}' {}",
                    RedactedUrl(&url),
                    problem.reason()
                ),
            ));
        }
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
    validate_auth_state_root(config.auth.state_root.as_deref())?;
    if let Some(listener) = &config.listener {
        validate_listener_for_startup(listener)?;
    }
    // Built-in auth and generic plugin config shape are checked synchronously;
    // the async build resolves plugin kinds again against the loaded,
    // auth-capable wrapper factory set before composition.
    // OAuth relay only valid over network gRPC; UDS / named-pipe are
    // local-trust-scope and a local attacker could route around the
    // network listener's auth.
    validate_oauth_providers_against_listeners(config)?;
    Ok(())
}

/// Guard a `--listen` override against silently exposing the zero-config
/// listener over TCP. In zero-config mode the generated listener is a local
/// socket (UDS / named-pipe) serving anonymous allow-all; retargeting it to a
/// TCP bind would expose that allow-all surface to every process that can reach
/// the port. Refuse a transport-changing (local → TCP) override — an operator
/// who wants a TCP listener must supply an explicit `--config` with a
/// `[listener]` `auth` block (fail-closed).
///
/// `zero_config` is true when no config file was resolved. `current_bind` is the
/// bind the broker was built with; `override_bind` is the `--listen` value. A
/// non-zero-config override is always allowed here (its config carries auth and
/// is re-validated by [`validate_broker_config_for_startup`]).
pub fn check_listen_override(
    zero_config: bool,
    current_bind: Option<&str>,
    override_bind: &str,
) -> ovstorage::Result<()> {
    if !zero_config {
        return Ok(());
    }
    let new_transport = BrokerTransport::parse(override_bind)?;
    let current_local = current_bind
        .and_then(|bind| BrokerTransport::parse(bind).ok())
        .map(|transport| transport.is_local())
        .unwrap_or(false);
    if current_local && matches!(new_transport, BrokerTransport::Tcp(_)) {
        return Err(invalid_config(
            "zero-config mode refuses a --listen override that changes the transport to \
             TCP: the zero-config listener serves anonymous allow-all and must stay on a \
             local socket. Provide a --config with an explicit [listener] auth to serve \
             over TCP.",
        ));
    }
    Ok(())
}

/// Apply a `--listen` CLI override to `config`'s listener: overwrite the bind of
/// an existing `[listener]`, or synthesize a spawn-only listener when the config
/// file declares none (the `--listen`-supplies-the-listener mode). Shared by
/// startup and SIGHUP reload so the effective listener the reload guard compares
/// against is reconstructed identically on both paths.
pub fn apply_listen_override(config: &mut BrokerConfig, bind: String) {
    match config.listener.as_mut() {
        Some(listener) => listener.bind = bind,
        None => {
            config.listener = Some(BrokerListenerConfig {
                bind,
                tls: None,
                trusted_proxy: false,
                trusted_peers: Vec::new(),
                // The broker is composed with its resolved `auth` config, so this
                // spawn-only listener carries no auth of its own.
                auth: None,
            });
        }
    }
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

/// The anonymous default context: no gathered credential, so the per-listener
/// auth layer resolves the caller as anonymous. Identity now flows only through
/// `ext::AUTH_CREDENTIAL` (the credential-gathering seam), never a host-resolved
/// principal.
pub fn default_context() -> RequestContext {
    RequestContext::default()
}

/// Process-cached `(SecretStore, AuthRefreshLock)` pair. The host
/// substrate is set-once-per-process at the plugin SPI, so every broker Stack
/// reuses the same Arcs.
pub(crate) fn cached_broker_substrate(
    configured_root: Option<&Path>,
) -> ovstorage::Result<&'static (Arc<dyn SecretStore>, Arc<AuthRefreshLock>)> {
    static CACHE: std::sync::OnceLock<(Arc<dyn SecretStore>, Arc<AuthRefreshLock>)> =
        std::sync::OnceLock::new();
    static CACHED_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    static INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    if let Some(s) = CACHE.get() {
        // The substrate is process-global and already open. Handing it back
        // for a *different* configured root would report success while every
        // credential kept going to the first one — which is what a SIGHUP
        // rebuild with a changed `auth.state_root` looks like.
        check_cached_root(&CACHED_ROOT, configured_root)?;
        return Ok(s);
    }
    // OnceLock::get_or_init is closure-only; without the mutex two
    // concurrent callers can race two `AuthRefreshLock::open` calls on
    // the same SQLite db ("database is locked"). Serialize the fallible
    // init and double-check inside the lock.
    let _guard = INIT_LOCK.lock().unwrap();
    if let Some(s) = CACHE.get() {
        check_cached_root(&CACHED_ROOT, configured_root)?;
        return Ok(s);
    }
    let auth_root = broker_auth_state_root(configured_root);
    let _ = CACHED_ROOT.set(auth_root.clone());
    let secret_store: Arc<dyn SecretStore> = Arc::new(SqliteSecretStore::open(&auth_root)?);
    let refresh_lock = Arc::new(AuthRefreshLock::open(&auth_root)?);
    Ok(CACHE.get_or_init(|| (secret_store, refresh_lock)))
}

/// Refuse an auth root that is empty or relative.
///
/// It is checked before anything opens or chmods the path, because both of
/// those are destructive against the wrong directory: a relative root is
/// resolved against the service's working directory, so `state_root = "."`
/// would take the broker's own working directory, narrow it to `0700` and
/// create `auth.sqlite` inside it — and would silently move the credentials
/// the next time the service started somewhere else.
pub fn validate_auth_state_root(state_root: Option<&Path>) -> ovstorage::Result<()> {
    let Some(root) = state_root else {
        return Ok(());
    };
    if root.as_os_str().is_empty() || !root.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`auth.state_root` must be an absolute path, got {root:?}. A relative \
                 auth directory is resolved against the working directory, so it moves \
                 with wherever the service happens to be started",
            ),
        ));
    }
    Ok(())
}

/// Refuse a configured root that disagrees with the one already open.
///
/// Only an *explicit* root is checked. A caller naming none is asking for
/// whatever the process already resolved, which is the zero-config and
/// test-harness path and has to keep working.
fn check_cached_root(
    cached: &std::sync::OnceLock<PathBuf>,
    configured_root: Option<&Path>,
) -> ovstorage::Result<()> {
    let (Some(cached), Some(requested)) = (cached.get(), configured_root) else {
        return Ok(());
    };
    if cached == requested {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::Unsupported,
        format!(
            "the auth substrate is already open at {cached:?} and cannot be reopened \
             at {requested:?}. It is process-global, so changing `auth.state_root` \
             needs a restart rather than a reload",
        ),
    ))
}

/// `[auth] state_root` when the operator set one, else the shared resolver.
///
/// The config key sits ahead of `OVSTORAGE_AUTH_DIR` deliberately: a broker
/// running as its own service user is configured by a file an operator owns,
/// and an inherited environment variable should not silently redirect where
/// its credentials land.
fn broker_auth_state_root(configured_root: Option<&Path>) -> PathBuf {
    match configured_root {
        Some(path) => path.to_path_buf(),
        None => ovstorage::auth::default_state_root(),
    }
}

type ByteCacheEntry = (Arc<ovstorage_cache::Cache>, ByteCacheGenerations);

static BYTE_CACHES: std::sync::OnceLock<Mutex<HashMap<PathBuf, ByteCacheEntry>>> =
    std::sync::OnceLock::new();

fn byte_cache_intern_map() -> &'static Mutex<HashMap<PathBuf, ByteCacheEntry>> {
    BYTE_CACHES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(crate) fn byte_cache_is_interned(cache_root: &Path) -> bool {
    byte_cache_intern_map()
        .lock()
        .unwrap()
        .contains_key(cache_root)
}

fn process_byte_cache(
    cache_root: &Path,
    state_root: &Path,
    max_bytes: Option<u64>,
) -> ovstorage::Result<ByteCacheEntry> {
    let mut caches = byte_cache_intern_map().lock().unwrap();
    if let Some(entry) = caches.get(cache_root) {
        return Ok(entry.clone());
    }
    let cache = Arc::new(ovstorage_cache::Cache::open_with_options(
        ovstorage_cache::CacheConfig {
            state_root: state_root.to_path_buf(),
            cache_root: cache_root.to_path_buf(),
        },
        ovstorage_cache::CacheOptions {
            max_bytes,
            ..Default::default()
        },
    )?);
    let entry = (cache, ByteCacheGenerations::new());
    caches.insert(cache_root.to_path_buf(), entry.clone());
    Ok(entry)
}

fn byte_cache_layer_config(
    config: &ovstorage::StackConfig,
) -> ovstorage::Result<Option<&HashMap<String, toml::Value>>> {
    let mut matches = config
        .layers
        .iter()
        .filter(|(name, table)| {
            table.kind.as_deref().unwrap_or(name.as_str())
                == ovstorage_plugin_cache::BYTE_CACHE_KIND
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.0.cmp(right.0));
    match matches.as_slice() {
        [] => Ok(None),
        [(_, table)] => Ok(Some(&table.config)),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "multiple `{}`-kind layers declared ({}); the broker cannot choose one \
                 process-shared byte cache",
                ovstorage_plugin_cache::BYTE_CACHE_KIND,
                matches
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

fn shared_byte_cache_factory(
    config: &ovstorage::StackConfig,
) -> ovstorage::Result<Option<ovstorage::LoadedLayerFactory>> {
    let Some(layer) = byte_cache_layer_config(config)? else {
        return Ok(None);
    };
    let (Some(toml::Value::String(cache_root)), Some(toml::Value::String(state_root))) =
        (layer.get("cache_root"), layer.get("state_root"))
    else {
        return Ok(None);
    };
    let max_bytes = match layer.get("max_bytes") {
        None => None,
        Some(toml::Value::Integer(value)) if *value >= 0 => Some(*value as u64),
        Some(_) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "byte_cache layer config `max_bytes` must be a non-negative integer",
            ));
        }
    };
    let (cache, generations) =
        process_byte_cache(Path::new(cache_root), Path::new(state_root), max_bytes)?;
    Ok(Some(ovstorage::LoadedLayerFactory::Wrapper(Arc::new(
        ByteCacheWrapperFactory::with_cache_and_generations(cache, generations),
    ))))
}

fn validate_listener_for_startup(listener: &BrokerListenerConfig) -> ovstorage::Result<()> {
    let label = "listener";
    let transport = listener.transport()?;
    let authn_mode = match broker_listener_auth_preflight(Some(listener))? {
        BrokerListenerAuthPreflight::ResolvedBuiltin(config) => {
            ovstorage_authz_layer::configured_authn_mode(&config)?
        }
        BrokerListenerAuthPreflight::NeedsPluginFactories => None,
    };
    let trusted_authn = matches!(
        authn_mode,
        Some(
            ovstorage_authz_layer::AuthnMode::TrustedUnsignedJwt
                | ovstorage_authz_layer::AuthnMode::TrustedForwardedHeaders
        )
    );
    if trusted_authn && !listener.trusted_proxy {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} authn_mode = \"{}\" requires trusted_proxy = true",
                authn_mode.map(|mode| mode.as_str()).unwrap_or_default()
            ),
        ));
    }
    // A permissive `trusted_unsigned_jwt` posture (no `jwt_audience`/`jwt_issuer`
    // to compare) is warned about by the auth layer when it builds, naming this
    // listener via the injected identity. This function is a pure predicate and
    // runs more than once per startup, so it deliberately logs nothing.
    if authn_mode == Some(ovstorage_authz_layer::AuthnMode::Mtls) {
        if !matches!(transport, BrokerTransport::Tcp(_)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{label} authn_mode = \"mtls\" requires a TCP listener"),
            ));
        }
        if listener
            .tls
            .as_ref()
            .and_then(|tls| tls.client_ca_path.as_ref())
            .is_none()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{label} authn_mode = \"mtls\" requires listener.tls.client_ca_path"),
            ));
        }
    }
    if listener.trusted_proxy && listener.trusted_peers.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{label} sets trusted_proxy = true but leaves trusted_peers empty; a \
                 trusted_proxy listener must record its peer-IP allowlist"
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
    ovstorage_authz_layer::validate_trusted_peers(&listener.trusted_peers)?;
    if let BrokerTransport::Tcp(addr) = &transport {
        if listener.tls.is_none() && !addr.ip().is_loopback() {
            if !listener.trusted_proxy || listener.trusted_peers.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{label} plaintext TCP on a non-loopback bind requires trusted_proxy = \
                         true and a non-empty trusted_peers list. trusted_proxy asserts an \
                         external TLS-terminating proxy fronts the listener; trusted_peers is \
                         enforced against the connection peer before trusted identity is used"
                    ),
                ));
            }
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests;
