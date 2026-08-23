// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Composition of the broker daemon's shared inner [`Stack`].
//!
//! The broker builds its shared, auth-free inner Stack from declared
//! `[ovstorage]` config through [`ovstorage::host::build_stack`]: the layer
//! graph, byte/metadata cache roots, and follower follow policy are all caller
//! data (config), not a hard-coded chain. [`BrokerStackBuilder`] loads the
//! plugin directory, adds the broker's bespoke wrapper factories (the
//! `attribution` overlay and the `upstream_credential` handler) to the
//! plugin-provided factory set, normalizes the mandatory upstream-credential
//! boundary, discovers the connectable backend kinds, and hands `build_stack`
//! the [`StackConfig`]. It then attaches the selected per-listener auth layer
//! over that inner. The
//! immutable Stack advertises only its *connected* kinds via `list_kinds`, so
//! discovery reads the captured set instead.
//!
//! The canonical broker graph (shipped `ovstorage-broker.toml`, and
//! [`broker_stack_config`]'s programmatic twin) is `upstream_credential →
//! alias → copy_rename_fallback → [byte_cache] → [metadata_cache] →
//! redirect_follower → retry → router → [attribution_<kind> →]
//! backend-per-kind`. The attribution overlay sits per-branch below the
//! router, on the branches whose backend can carry the reserved
//! `user_metadata` key. The
//! follower carries a daemon-wide follow policy from its layer config: a byte
//! cache with a `max_object_bytes` cap ⇒ `follow_reads = true` with that cap, so
//! small reads are followed and teed into the byte cache while oversize reads
//! surface the `Redirect` unfollowed; otherwise `follow_reads = false`.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use ovstorage::{
    AddressVisibility, ConnectionConfig, LayerConfig, LayerTable, LoadedLayerFactory, Stack,
    StackConfig, StorageBackendKindDescriptor, Url,
};
use ovstorage_authz::{
    AttributionStrategy, UserMetadataKinds, attributed_router_layers, prepare_listener_inner_stack,
};
use ovstorage_authz_layer::{AUTH_LAYER_NAME, ListenerAuth, ListenerAuthBuildPlan};

use crate::{
    BrokerOAuthRouteBindings, OAuthProviderRegistry, UPSTREAM_CREDENTIAL_KIND,
    UpstreamCredentialWrapperFactory,
};

/// Broker-owned wrappers in their fixed outer-to-inner order.
///
/// This is the single source for both operator graph normalization and the
/// programmatic default graph. Adding or reordering a broker security boundary
/// changes this chain rather than adding another special-case graph scan.
/// (Attribution is not part of this top-of-stack boundary: it sits per-branch
/// below the router, guaranteed by the attribution normalization inside
/// [`prepare_listener_inner_stack`].)
const BROKER_OWNED_BOUNDARY: &[&str] = &[UPSTREAM_CREDENTIAL_KIND];

/// Compose the broker-owned security boundary around an operator data graph.
///
/// Missing wrappers are injected in [`BROKER_OWNED_BOUNDARY`] order. Explicit
/// declarations remain accepted for configuration compatibility, but each kind
/// must occur exactly once and at its prescribed boundary position. A misplaced
/// declaration is rejected instead of trusted because an operator wrapper above
/// it could intercept a credential-establishing slot without delegation.
fn compose_broker_owned_boundary(mut config: StackConfig) -> ovstorage::Result<StackConfig> {
    let Some(mut current) = config.root.clone() else {
        return Ok(config);
    };
    let mut parent: Option<String> = None;

    for &required_kind in BROKER_OWNED_BOUNDARY {
        let declared = config
            .layers
            .iter()
            .filter_map(|(name, table)| {
                (table.kind.as_deref().unwrap_or(name.as_str()) == required_kind)
                    .then_some(name.as_str())
            })
            .collect::<Vec<_>>();
        if declared.len() > 1 {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!("broker stack must contain exactly one {required_kind} layer"),
            ));
        }

        let current_kind = config
            .layers
            .get(&current)
            .map(|table| table.kind.as_deref().unwrap_or(current.as_str()));
        if current_kind == Some(required_kind) {
            let inner = config
                .layers
                .get(&current)
                .and_then(|table| table.inner.clone())
                .ok_or_else(|| {
                    ovstorage::Error::new(
                        ovstorage::ErrorCode::InvalidArgument,
                        format!("broker {required_kind} boundary must wrap an inner layer"),
                    )
                })?;
            parent = Some(current);
            current = inner;
            continue;
        }

        if let Some(declared) = declared.first() {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!(
                    "broker {required_kind} layer '{declared}' is outside the required broker-owned boundary"
                ),
            ));
        }

        let mut name = required_kind.to_string();
        let mut suffix = 1;
        while config.layers.contains_key(&name) {
            name = format!("{required_kind}_{suffix}");
            suffix += 1;
        }
        config.layers.insert(
            name.clone(),
            ovstorage::host::wrapper_layer(required_kind, &current),
        );
        if let Some(parent) = &parent {
            config
                .layers
                .get_mut(parent)
                .expect("broker boundary parent was inserted or resolved above")
                .inner = Some(name.clone());
        } else {
            config.root = Some(name.clone());
        }
        parent = Some(name);
    }

    Ok(config)
}

/// OIDC bearer-JWT parameters for the built-in auth layer's `Tcp` authn front
/// end. All three are required together. The host wiring assembles these into
/// the auth layer's [`LayerConfig`] via
/// [`ovstorage_authz_layer::resolve_listener_auth`]; test fixtures use this
/// struct to configure a `Tcp` JWT listener directly.
pub type BrokerJwtParams = ovstorage_authz_layer::JwtParams;

/// The composed broker Stack plus the backend kinds a caller may connect.
#[derive(Clone)]
pub struct BrokerStack {
    /// The selected per-listener auth layer `attach`ed over the shared
    /// auth-free inner.
    pub stack: Arc<Stack>,
    /// The auth-free inner Stack used only for structural health/readiness
    /// probes. Health is intentionally outside listener authentication: an
    /// auth-capable plugin may reject an empty request context while still
    /// being fully able to serve authenticated callers.
    pub(crate) health_stack: Arc<Stack>,
    /// Opaque listener-auth handle exposing policy reload, discovery gating,
    /// and write-admission behavior without leaking implementation handles.
    pub auth_layer: ListenerAuth,
    /// Backend kinds discovered from the loaded plugin factories, for the
    /// discovery endpoint.
    pub backend_kinds: Vec<StorageBackendKindDescriptor>,
    /// The exact registry shared with the immutable `upstream_credential`
    /// wrapper composed into `stack`.
    pub(crate) oauth_providers: Arc<OAuthProviderRegistry>,
    /// The exact route bindings shared with the immutable
    /// `upstream_credential` wrapper composed into `stack`.
    pub(crate) oauth_bindings: Arc<BrokerOAuthRouteBindings>,
}

/// Builder for the broker daemon's [`BrokerStack`]. Loads plugins from a
/// directory, adds the broker's bespoke wrapper factories (`attribution` +
/// `upstream_credential`) to the plugin-provided factory set, and builds the
/// shared inner [`Stack`] from the declared [`StackConfig`] via
/// [`ovstorage::host::build_stack`] — then attaches the selected per-listener
/// auth layer over it. The graph, cache roots, and follow
/// policy are all `[ovstorage]` config; the builder carries only the host
/// concerns the config cannot (the attribution strategy, the auth-layer config,
/// and any override/plugin factories).
pub struct BrokerStackBuilder {
    plugin_dir: Option<PathBuf>,
    auth_dir: Option<PathBuf>,
    allow_test_plugins: bool,
    require_configured_stack: bool,
    /// The shared inner data-plane graph + its connections, declared as
    /// `[ovstorage]` config. Broker-owned security wrappers are normalized
    /// before it is handed to `build_stack`: the upstream-credential boundary
    /// is injected at the root when missing, and the attribution guarantee may
    /// add an instance to a branch that declares none, re-pointing the one
    /// edge that must then point at it. Normalization removes, reorders and
    /// reconfigures nothing, and refuses the graph rather than moving a
    /// misplaced instance.
    stack_config: StackConfig,
    auth: ListenerAuthBuildPlan,
    auth_host_config: Option<BrokerAuthHostConfig>,
    /// Attribution strategy for the in-stack (shared-inner) `attribution` wrapper
    /// — injected into the factory, not read from layer config (the broker owns
    /// this config).
    attribution_strategy: AttributionStrategy,
    /// OAuth providers and route bindings injected into the broker-owned
    /// `upstream_credential` wrapper factory at compose time.
    oauth_providers: Arc<OAuthProviderRegistry>,
    oauth_bindings: Arc<BrokerOAuthRouteBindings>,
    /// Extra in-process Layer factories registered after the plugins. This is
    /// used by private broker Layers and test fixtures.
    extra_factories: Vec<LoadedLayerFactory>,
}

struct BrokerAuthHostConfig {
    listener_name: String,
    trusted_proxy: bool,
    trusted_peers: Vec<String>,
}

impl Default for BrokerStackBuilder {
    fn default() -> Self {
        Self {
            plugin_dir: None,
            auth_dir: None,
            allow_test_plugins: false,
            require_configured_stack: false,
            stack_config: StackConfig::default(),
            auth: ListenerAuthBuildPlan::resolved_builtin(LayerConfig::new()),
            auth_host_config: None,
            attribution_strategy: AttributionStrategy::default(),
            oauth_providers: Arc::new(OAuthProviderRegistry::new()),
            oauth_bindings: Arc::new(BrokerOAuthRouteBindings::new()),
            extra_factories: Vec::new(),
        }
    }
}

impl BrokerStackBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Directory to scan for plugin cdylibs. `None` resolves to
    /// [`ovstorage::default_plugin_dir`].
    pub fn plugin_dir(mut self, dir: PathBuf) -> Self {
        self.plugin_dir = Some(dir);
        self
    }

    /// Directory pinning the process-global auth substrate. `None` uses the
    /// default (`$OVSTORAGE_AUTH_DIR` or a per-pid tempdir).
    pub fn auth_dir(mut self, dir: PathBuf) -> Self {
        self.auth_dir = Some(dir);
        self
    }

    /// Accept `test_only`-manifest plugins (test fixtures). Off by default.
    pub fn allow_test_plugins(mut self, allow: bool) -> Self {
        self.allow_test_plugins = allow;
        self
    }

    /// The declared inner Stack graph + connections (`[ovstorage]` config). An
    /// empty graph builds a one-layer `EmptyLayer` Stack (`build_stack`'s
    /// contract); the broker's config path refuses an empty stack up front
    /// (`require_configured_stack`) rather than substituting a default graph,
    /// while the zero-config path supplies its own via `broker_stack_config`.
    pub fn stack_config(mut self, config: StackConfig) -> Self {
        self.stack_config = config;
        self
    }

    /// Require an explicitly configured inner Stack after listener-auth kind
    /// resolution. Production config paths enable this; programmatic builders
    /// may intentionally use the core empty-Stack behavior.
    pub fn require_configured_stack(mut self) -> Self {
        self.require_configured_stack = true;
        self
    }

    /// Supply a pre-resolved built-in auth config. This programmatic route is
    /// retained for embedding hosts and tests; operator config should use
    /// [`BrokerStackBuilder::listener_auth`]. An empty config is deny-all.
    pub fn auth_config(mut self, config: LayerConfig) -> Self {
        self.auth = ListenerAuthBuildPlan::resolved_builtin(config);
        self.auth_host_config = None;
        self
    }

    /// Supply an operator listener-auth value for resolution after plugins are
    /// loaded. Trusted-proxy settings are host-owned built-in authn machinery;
    /// plugin auth factories receive only their operator config, verbatim.
    pub fn listener_auth(
        mut self,
        raw: Option<toml::Value>,
        listener_name: impl Into<String>,
        trusted_proxy: bool,
        trusted_peers: Vec<String>,
    ) -> Self {
        let listener_name = listener_name.into();
        self.auth = ListenerAuthBuildPlan::listener(raw, listener_name.clone());
        self.auth_host_config = Some(BrokerAuthHostConfig {
            listener_name,
            trusted_proxy,
            trusted_peers,
        });
        self
    }

    /// Attribution strategy for the shared inner's attribution wrapper.
    pub fn attribution_strategy(mut self, strategy: AttributionStrategy) -> Self {
        self.attribution_strategy = strategy;
        self
    }

    /// OAuth providers and route bindings for the shared inner's
    /// `upstream_credential` wrapper.
    pub fn oauth(
        mut self,
        registry: Arc<OAuthProviderRegistry>,
        bindings: impl Into<Arc<BrokerOAuthRouteBindings>>,
    ) -> Self {
        self.oauth_providers = registry;
        self.oauth_bindings = bindings.into();
        self
    }

    /// Register an in-process Layer factory (in addition to the plugins loaded
    /// from the directory). Registered after the plugins, so an override
    /// (such as a host-shared cache instance) wins over the plugin factory of
    /// the same kind.
    pub fn extra_factory(mut self, factory: LoadedLayerFactory) -> Self {
        self.extra_factories.push(factory);
        self
    }

    /// Build the shared inner Stack from the declared config and attach the
    /// per-listener auth layer over it.
    ///
    /// Loads the plugin directory, appends the broker's `attribution` +
    /// `upstream_credential` wrapper factories (and any extra factories, which
    /// override plugin-provided factories), guarantees the per-principal
    /// upstream-credential boundary, builds the inner via
    /// [`ovstorage::host::build_stack`], then composes the selected auth layer as
    /// the single child of a thin auth `Stack` the daemon dispatches through —
    /// the degenerate N=1 case of the per-listener-auth-over-shared-inner design.
    ///
    /// # Safety
    ///
    /// Loading plugins `dlopen`s cdylibs from the plugin directory; trust its
    /// contents.
    pub async unsafe fn build(self) -> ovstorage::Result<BrokerStack> {
        // Provider parsing is backend-agnostic. This final host-owned
        // composition gate runs after trusted read-side consumer-capability
        // registration and before plugin loading, so unsupported provider
        // kinds fail startup.
        self.oauth_providers.validate()?;
        let auth_preflight = self.auth.preflight()?;
        ovstorage::init_auth_substrate(self.auth_dir.as_deref())?;
        let auth_plan = self.auth;
        let auth_host_config = self.auth_host_config;
        let require_configured_stack = self.require_configured_stack;
        let stack_config = self.stack_config;
        let plugin_dir = match self.plugin_dir {
            Some(dir) => Some(dir),
            None => ovstorage::default_plugin_dir(),
        };
        let factories = match plugin_dir {
            // SAFETY: forwarded from this fn's own safety contract.
            Some(dir) => unsafe {
                ovstorage::load_layer_plugins_from_dir_with_host_kind(
                    &dir,
                    self.allow_test_plugins,
                    ovstorage::ffi::HostKindV1::Broker,
                )?
            },
            None => Vec::new(),
        };
        let stack_config = compose_broker_owned_boundary(stack_config)?;
        let (stack_config, mut factories) = prepare_listener_inner_stack(
            stack_config,
            factories,
            self.attribution_strategy,
            self.extra_factories,
        )?;
        let oauth_providers = self.oauth_providers;
        let oauth_bindings = self.oauth_bindings;
        factories.push(LoadedLayerFactory::Wrapper(Arc::new(
            UpstreamCredentialWrapperFactory::new(
                Arc::clone(&oauth_providers),
                Arc::clone(&oauth_bindings),
            ),
        )));

        let mut resolved_auth = match auth_preflight {
            Some(resolved) => resolved,
            None => auth_plan.resolve(&factories)?,
        };
        if let Some(host_config) = &auth_host_config
            && host_config.trusted_proxy
        {
            if host_config.trusted_peers.is_empty() {
                return Err(ovstorage::Error::new(
                    ovstorage::ErrorCode::InvalidArgument,
                    "trusted_proxy = true requires a non-empty trusted_peers list",
                ));
            }
            ovstorage_authz_layer::validate_trusted_peers(&host_config.trusted_peers)?;
        }
        if resolved_auth.is_builtin()
            && let Some(host_config) = &auth_host_config
        {
            // Listener identity and the built-in layer's internal CIDR key are
            // injected only for built-in auth. Plugin kinds receive their
            // operator-owned config without host-added keys; the gRPC listener
            // enforces the same validated peer list before dispatching them.
            ovstorage_authz_layer::configure_listener_id(
                resolved_auth.config_mut(),
                &host_config.listener_name,
            );
            ovstorage_authz_layer::configure_trusted_proxy(
                resolved_auth.config_mut(),
                host_config.trusted_proxy,
                &host_config.trusted_peers,
            )?;
        }

        // Resolve plugin auth first so an unknown/typo'd auth kind wins over
        // the independent empty-stack validation, preserving fail-closed error
        // ordering while still validating against the actually loaded set.
        if require_configured_stack {
            ovstorage::host::require_configured_stack(&stack_config)?;
        }

        // Runtime-addable kinds are the backend kinds the graph declares a Layer
        // for (the Router's children) — NOT the startup connection set. An
        // operator may predeclare and route a backend with no initial connection
        // so a connection can be added later; the immutable Stack still owns that
        // target.
        let routed_kinds = ovstorage::host::graph_backend_kinds(&stack_config, &factories);
        let backend_kinds = ovstorage::host::discover_backend_kinds(&factories, &routed_kinds);

        // Compose the shared, auth-free inner from declared config.
        let inner = ovstorage::host::build_stack(&stack_config, factories.clone()).await?;
        let health_stack = inner.clone();
        // Plugin auth must receive the request before a pull-driven gRPC source
        // is consumed. Its transparent inner layer applies the shared body
        // accumulator only after authentication delegates. Built-in auth uses
        // the same accumulator in the gRPC handler after its typed preflight.
        let auth_inner = if resolved_auth.is_builtin() {
            inner
        } else {
            crate::write_body::normalize_listener_auth_writes(inner)
        };

        // Host-injected listener/trusted-proxy config was applied only on the
        // built-in route above. Plugin factories receive operator config
        // verbatim; the host enforces their peer CIDRs at the listener seam.
        let composed = resolved_auth
            .compose(AUTH_LAYER_NAME, auth_inner, &factories, None)
            .await?;
        Ok(BrokerStack {
            stack: composed.stack,
            health_stack,
            auth_layer: composed.auth_layer,
            backend_kinds,
            oauth_providers,
            oauth_bindings,
        })
    }
}

/// Optional layers + follow policy for [`broker_stack_config`]. Named fields so
/// call sites self-document instead of trailing adjacent bare booleans.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BrokerGraphOptions {
    /// Insert a `byte_cache` layer (the concrete cache is injected as an
    /// override factory).
    pub byte_cache: bool,
    /// Insert a `metadata_cache` layer.
    pub metadata_cache: bool,
    /// Per-object follow/tee cap; with `byte_cache` it drives both the byte
    /// cache's `max_object_bytes` and the follower's `follow_reads_max_bytes`.
    pub follow_cap: Option<u64>,
}

/// Add host-generated alias and visibility rules to the declared `alias`
/// layer's plugin configuration.
pub(crate) fn with_alias_rules(
    mut config: StackConfig,
    aliases: Vec<(Url, Url)>,
    visibility: Vec<(Url, AddressVisibility)>,
) -> ovstorage::Result<StackConfig> {
    if aliases.is_empty() && visibility.is_empty() {
        return Ok(config);
    }
    let mut alias_layers = config
        .layers
        .iter()
        .filter(|(name, table)| {
            table.kind.as_deref().unwrap_or(name.as_str()) == ovstorage_plugin_core::ALIAS_KIND
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    alias_layers.sort();
    let alias_name = match alias_layers.as_slice() {
        [] => {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::NotConfigured,
                "host-generated alias rules require an `alias`-kind layer",
            ));
        }
        [name] => name,
        names => {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!(
                    "host-generated alias rules require exactly one `alias`-kind layer; found {}",
                    names.join(", ")
                ),
            ));
        }
    };
    let alias = config
        .layers
        .get_mut(alias_name)
        .expect("alias layer name came from this map");
    if !aliases.is_empty() {
        if alias.config.contains_key("aliases") {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!(
                    "host-generated alias rules conflict with operator-declared `aliases` in \
                     layer `{alias_name}`"
                ),
            ));
        }
        alias.config.insert(
            "aliases".into(),
            toml::Value::Array(
                aliases
                    .into_iter()
                    .map(|(from, to)| {
                        toml::Value::Table(toml::Table::from_iter([
                            ("from".into(), toml::Value::String(from.to_string())),
                            ("to".into(), toml::Value::String(to.to_string())),
                        ]))
                    })
                    .collect(),
            ),
        );
    }
    if !visibility.is_empty() {
        if alias.config.contains_key("visibility") {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!(
                    "host-generated visibility rules conflict with operator-declared \
                     `visibility` in layer `{alias_name}`"
                ),
            ));
        }
        alias.config.insert(
            "visibility".into(),
            toml::Value::Array(
                visibility
                    .into_iter()
                    .map(|(address, visibility)| {
                        let visibility = match visibility {
                            AddressVisibility::Visible => "visible",
                            AddressVisibility::Hidden => "hidden",
                            AddressVisibility::Suppressed => "suppressed",
                        };
                        toml::Value::Table(toml::Table::from_iter([
                            ("address".into(), toml::Value::String(address.to_string())),
                            ("visibility".into(), toml::Value::String(visibility.into())),
                        ]))
                    })
                    .collect(),
            ),
        );
    }
    Ok(config)
}

/// The broker's default forward Stack graph as declarative [`StackConfig`] data
/// — the programmatic twin of the shipped `ovstorage-broker.toml`, used where
/// the graph is assembled in code rather than read from an operator TOML: the
/// zero-config path and the test fixtures. (The operator-config path does not
/// fall back to this graph — an empty `[ovstorage.layers]` is refused.)
///
/// Chain (top→bottom), rooted at `upstream_credential`: `upstream_credential →
/// alias → copy_rename_fallback →
/// [byte_cache →] [metadata_cache →] redirect_follower → retry → router →
/// [attribution_<kind> →] <kind>*`. The
/// optional byte/metadata cache layers are present only when requested. Alias and
/// visibility rules are encoded in the alias Layer's config before the Stack
/// is built. `follow_cap` drives both the byte cache's `max_object_bytes` and
/// the follower's follow policy: a byte cache AND a cap ⇒ `follow_reads = true`
/// with that cap; otherwise `follow_reads = false`.
///
/// Attribution sits **below** the router, one instance per branch, and only on
/// branches whose backend kind `declared` says can carry the reserved key
/// ([`UserMetadataKinds::carries_attribution`]). `declared` need only be a
/// subset of the truth: this emits a graph before any plugin is loaded, and
/// `ensure_branch_attribution` runs afterwards with the loaded plugins' own
/// declarations, splicing a wrapper onto a capable branch that has none and
/// refusing a graph that puts one where it does not belong. That placement is
/// what puts the
/// `copy_rename_fallback` wrapper's fabricated write — issued downward, below
/// that wrapper — inside attribution's path, and what keeps a stamp off the
/// branches that would reject or discard it.
pub(crate) fn broker_stack_config(
    connections: Vec<ConnectionConfig>,
    options: BrokerGraphOptions,
    declared: &UserMetadataKinds,
) -> StackConfig {
    let BrokerGraphOptions {
        byte_cache,
        metadata_cache,
        follow_cap,
    } = options;
    let mut layers: HashMap<String, LayerTable> = HashMap::new();

    layers.insert(
        "alias".into(),
        ovstorage::host::wrapper_layer("alias", "copy_rename_fallback"),
    );

    // copy_rename_fallback links to the first present layer below it.
    let after_cross = if byte_cache {
        "byte_cache"
    } else if metadata_cache {
        "metadata_cache"
    } else {
        "redirect_follower"
    };
    layers.insert(
        "copy_rename_fallback".into(),
        ovstorage::host::wrapper_layer("copy_rename_fallback", after_cross),
    );

    if byte_cache {
        let inner = if metadata_cache {
            "metadata_cache"
        } else {
            "redirect_follower"
        };
        let mut byte_cache_layer = ovstorage::host::wrapper_layer("byte_cache", inner);
        // The broker is the sanctioned survive-backing-loss + warm-delegates
        // opt-in; the concrete `Arc<Cache>` is injected as an override factory,
        // so no `cache_root`/`state_root` here.
        byte_cache_layer
            .config
            .insert("partition".into(), toml::Value::String("local".into()));
        byte_cache_layer
            .config
            .insert("lost_backing_fallback".into(), toml::Value::Boolean(true));
        byte_cache_layer
            .config
            .insert("warm_delegates".into(), toml::Value::Boolean(true));
        if let Some(cap) = follow_cap {
            byte_cache_layer
                .config
                .insert("max_object_bytes".into(), toml::Value::Integer(cap as i64));
        }
        layers.insert("byte_cache".into(), byte_cache_layer);
    }

    if metadata_cache {
        layers.insert(
            "metadata_cache".into(),
            ovstorage::host::wrapper_layer("metadata_cache", "redirect_follower"),
        );
    }

    let mut follower = ovstorage::host::wrapper_layer("redirect_follower", "retry");
    match (byte_cache, follow_cap) {
        (true, Some(cap)) => {
            follower
                .config
                .insert("follow_reads".into(), toml::Value::Boolean(true));
            follower.config.insert(
                "follow_reads_max_bytes".into(),
                toml::Value::Integer(cap as i64),
            );
        }
        _ => {
            follower
                .config
                .insert("follow_reads".into(), toml::Value::Boolean(false));
        }
    }
    layers.insert("redirect_follower".into(), follower);

    layers.insert(
        "retry".into(),
        ovstorage::host::wrapper_layer("retry", "router"),
    );

    // One backend Layer per distinct connected kind (`target = kind`), the
    // router forking to exactly those branches, and a per-branch attribution
    // wrapper wherever the backend can carry the reserved key.
    let kinds: BTreeSet<String> = connections.iter().map(|c| c.backend_kind.clone()).collect();
    layers.extend(attributed_router_layers(&kinds, declared));

    compose_broker_owned_boundary(StackConfig {
        root: Some("alias".into()),
        layers,
        connections,
    })
    .expect("the canonical broker graph has a valid broker-owned boundary")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy};
    use ovstorage::wrappers::ext;
    use ovstorage::{
        AuthEvent, AuthenticateRequest, CancellationToken, ConfigValue, ConnectionId,
        ConnectionKey, ErrorCode, InteractiveAuthCapability, Layer, LayerHandle,
        LayerKindDescriptor, LayerType, Request, Result, WrapperFactory,
    };
    use ovstorage_authz::{ATTRIBUTION_KIND, attribution_branch_name};
    use ovstorage_plugin_core::{
        AliasWrapperFactory, CopyRenameFallbackWrapperFactory, RetryWrapperFactory,
        RouterFactoryImpl,
    };
    use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

    use super::*;

    #[tokio::test]
    async fn final_stack_composition_rejects_an_unregistered_oauth_read_consumer() {
        let state_root = std::env::temp_dir().join(format!(
            "ovstorage-unregistered-oauth-read-consumer-{}",
            std::process::id()
        ));
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "gcs",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "test".into(),
                scope: None,
            },
            Arc::new(
                ovstorage::auth::SqliteSecretStore::open(&state_root).expect("open sqlite store"),
            ),
            Arc::new(AuthRefreshLock::open(&state_root).unwrap()),
            OAuthStrategy::Device,
        ));
        let registry =
            Arc::new(OAuthProviderRegistry::new().with_provider("upstream-idp", provider));

        let result = unsafe {
            BrokerStackBuilder::new()
                .oauth(registry, BrokerOAuthRouteBindings::new())
                .build()
                .await
        };
        let error = match result {
            Ok(_) => panic!("an unregistered provider read consumer must fail startup"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .message()
                .contains("no registered production read-side consumer")
        );
        let _ = std::fs::remove_dir_all(state_root);
    }

    #[test]
    fn rejects_an_upstream_credential_layer_below_the_security_boundary() {
        let mut layers = HashMap::new();
        layers.insert(
            "alias".into(),
            ovstorage::host::wrapper_layer("alias", UPSTREAM_CREDENTIAL_KIND),
        );
        layers.insert(
            UPSTREAM_CREDENTIAL_KIND.into(),
            ovstorage::host::wrapper_layer(UPSTREAM_CREDENTIAL_KIND, "file"),
        );
        layers.insert(
            "file".into(),
            LayerTable {
                kind: Some("file".into()),
                ..Default::default()
            },
        );
        let config = StackConfig {
            root: Some("alias".into()),
            layers,
            connections: Vec::new(),
        };

        let error = compose_broker_owned_boundary(config).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("required broker-owned boundary"));
    }

    #[tokio::test]
    async fn composed_custom_graph_injects_upstream_wrapper_with_oauth_bindings() {
        crate::test_utils::ensure_test_plugin_env();
        let address = Url::parse("nucleus://prod/object").unwrap();
        let bindings = Arc::new(
            BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("nucleus://prod/").unwrap(), "missing-provider"),
        );
        let registry = Arc::new(OAuthProviderRegistry::new());
        let (_, auth_config) = ovstorage_authz_layer::resolve_listener_auth(
            Some(toml::Value::String(
                ovstorage_authz_layer::ANONYMOUS_AUTH_KIND.to_string(),
            )),
            "test",
            std::iter::empty::<&str>(),
        )
        .unwrap();
        // Drop the upstream_credential boundary the canonical graph carries, as
        // an operator graph that never declared it: the builder must inject it.
        let mut stack_config = broker_stack_config(
            Vec::new(),
            BrokerGraphOptions::default(),
            &UserMetadataKinds::default(),
        );
        stack_config.layers.remove(UPSTREAM_CREDENTIAL_KIND);
        stack_config.root = Some("alias".into());

        let composed = unsafe {
            BrokerStackBuilder::new()
                .allow_test_plugins(true)
                .stack_config(stack_config)
                .auth_config(auth_config)
                .oauth(Arc::clone(&registry), Arc::clone(&bindings))
                .extra_factory(LoadedLayerFactory::Router(Arc::new(RouterFactoryImpl)))
                .extra_factory(LoadedLayerFactory::Wrapper(Arc::new(
                    AliasWrapperFactory::default(),
                )))
                .extra_factory(LoadedLayerFactory::Wrapper(Arc::new(
                    CopyRenameFallbackWrapperFactory,
                )))
                .extra_factory(LoadedLayerFactory::Wrapper(Arc::new(
                    RedirectFollowerWrapperFactory,
                )))
                .extra_factory(LoadedLayerFactory::Wrapper(Arc::new(RetryWrapperFactory)))
                .build()
                .await
                .unwrap()
        };
        assert!(Arc::ptr_eq(&composed.oauth_providers, &registry));
        assert!(Arc::ptr_eq(&composed.oauth_bindings, &bindings));
        assert_eq!(
            composed.oauth_bindings.provider_for(&address),
            bindings.provider_for(&address)
        );

        // The listener Stack attaches its auth layer as an opaque root, so its
        // StackSpec intentionally contains only that attachment. Walk the live
        // inner chain to verify the graph built beneath the auth boundary.
        // The listener-auth handle is opaque; the auth-free health stack is
        // the same shared inner, so walk the graph beneath it instead.
        let upstream = composed
            .health_stack
            .inner_layer()
            .expect("shared inner stack roots at upstream_credential");
        assert_eq!(upstream.name(), UPSTREAM_CREDENTIAL_KIND);
        let alias = upstream
            .inner_layer()
            .expect("upstream_credential wraps alias");
        assert_eq!(alias.name(), "alias");

        let mut request = Request::new(AuthenticateRequest {
            key: ConnectionKey {
                target: "router".into(),
                id: ConnectionId("test".into()),
            },
            capability: InteractiveAuthCapability::Browser,
            auto_open_browser: false,
        });
        ext::insert_upstream_auth_address(&mut request.extensions, &address);
        let mut events = composed
            .stack
            .authenticate_connection(request, None)
            .await
            .unwrap();
        match events.next().expect("terminal auth event").unwrap() {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
                assert!(error.message().contains("missing-provider"));
            }
            event => panic!("expected failed auth event, got {event:?}"),
        }
    }

    fn connection(kind: &str) -> ConnectionConfig {
        ConnectionConfig::from_request(ovstorage::ConnectionRequest {
            backend_kind: kind.into(),
            config: HashMap::new(),
            credentials: ovstorage::SecretBundle::default(),
            persist: false,
            display_name: None,
        })
    }

    /// The graph's whole point, asserted structurally: a branch whose backend can
    /// carry the reserved key is fronted by its own attribution wrapper, and a
    /// branch whose backend rejects it is wired to the router directly. The
    /// router's child is the wrapper in the first case and the backend in the
    /// second; nothing above the router stamps either.
    #[test]
    fn attribution_fronts_the_branches_that_can_carry_it_and_no_others() {
        let config = broker_stack_config(
            vec![
                connection("s3"),
                connection("broker"),
                connection("nucleus"),
                connection("opendal"),
                connection("http"),
            ],
            BrokerGraphOptions::default(),
            &UserMetadataKinds::default()
                .with("s3", true)
                .with("broker", true)
                .with("nucleus", false)
                .with("opendal", false)
                .with("http", false),
        );

        assert_eq!(config.root.as_deref(), Some(UPSTREAM_CREDENTIAL_KIND));
        assert_eq!(
            config.layers[UPSTREAM_CREDENTIAL_KIND].inner.as_deref(),
            Some("alias"),
            "the broker-owned boundary wraps the operator graph's alias root"
        );
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.inner.as_deref() == Some("router")
                    && table.kind.as_deref() == Some(ATTRIBUTION_KIND)),
            "nothing above the router may stamp"
        );

        let mut children = config.layers["router"].children.clone();
        children.sort();
        assert_eq!(
            children,
            vec![
                // Wrapped: these persist what they are handed, or forward it.
                "attribution_broker".to_string(),
                "attribution_s3".to_string(),
                // Bare: these reject it, drop it, or cannot be written at all.
                "http".to_string(),
                "nucleus".to_string(),
                "opendal".to_string(),
            ],
        );
        for kind in ["s3", "broker"] {
            assert_eq!(
                config.layers[&attribution_branch_name(kind)]
                    .inner
                    .as_deref(),
                Some(kind),
                "{kind}'s wrapper must wrap {kind} itself"
            );
        }
        for kind in ["nucleus", "opendal", "http"] {
            assert!(
                !config.layers.contains_key(&attribution_branch_name(kind)),
                "{kind} must have no attribution wrapper"
            );
            assert!(config.layers.contains_key(kind));
        }
    }

    #[test]
    fn host_alias_rules_target_effective_kind_not_layer_name() {
        let mut config = StackConfig::default();
        config.layers.insert(
            "mounts".into(),
            LayerTable {
                kind: Some(ovstorage_plugin_core::ALIAS_KIND.into()),
                ..Default::default()
            },
        );
        config.layers.insert(
            "alias".into(),
            LayerTable {
                kind: Some("retry".into()),
                ..Default::default()
            },
        );

        let config = with_alias_rules(
            config,
            vec![(
                Url::parse("ov:///public/").unwrap(),
                Url::parse("file:///data/").unwrap(),
            )],
            Vec::new(),
        )
        .unwrap();

        assert!(config.layers["mounts"].config.contains_key("aliases"));
        assert!(!config.layers["alias"].config.contains_key("aliases"));
    }

    #[test]
    fn host_alias_rules_reject_operator_rule_replacement() {
        let mut config = StackConfig::default();
        let mut alias = LayerTable {
            kind: Some(ovstorage_plugin_core::ALIAS_KIND.into()),
            ..Default::default()
        };
        alias
            .config
            .insert("aliases".into(), toml::Value::Array(Vec::new()));
        config.layers.insert("mounts".into(), alias);

        let error = with_alias_rules(
            config,
            vec![(
                Url::parse("ov:///public/").unwrap(),
                Url::parse("file:///data/").unwrap(),
            )],
            Vec::new(),
        )
        .unwrap_err();

        assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(error.message().contains("operator-declared"));
    }

    const TEST_AUTH_KIND: &str = "host-wiring-test-auth";

    struct RecordingAuthFactory {
        seen_config: Arc<Mutex<Option<LayerConfig>>>,
    }

    #[async_trait]
    impl WrapperFactory for RecordingAuthFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                display_name: TEST_AUTH_KIND.to_string(),
                kind: TEST_AUTH_KIND.to_string(),
                layer_type: LayerType::Wrapper,
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                supports_user_metadata: false,
                auth_capable: true,
            }
        }

        async fn create_wrapper(
            &self,
            name: &str,
            config: &LayerConfig,
            inner: LayerHandle,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            *self.seen_config.lock().unwrap() = Some(config.clone());
            Ok(Arc::new(TestAuthLayer {
                name: name.to_string(),
                descriptor: self.descriptor(),
                inner,
            }))
        }
    }

    struct TestAuthLayer {
        name: String,
        descriptor: LayerKindDescriptor,
        inner: LayerHandle,
    }

    #[async_trait]
    impl Layer for TestAuthLayer {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            self.descriptor.clone()
        }

        fn inner_layer(&self) -> Option<&LayerHandle> {
            Some(&self.inner)
        }
    }

    #[tokio::test]
    async fn registered_plugin_auth_composes_verbatim_and_reload_is_unsupported() {
        let plugin_dir = tempfile::tempdir().unwrap();
        let seen_config = Arc::new(Mutex::new(None));
        let factory = LoadedLayerFactory::Wrapper(Arc::new(RecordingAuthFactory {
            seen_config: seen_config.clone(),
        }));
        let raw = toml::Value::Table(toml::Table::from_iter([
            (
                "kind".to_string(),
                toml::Value::String(TEST_AUTH_KIND.to_string()),
            ),
            (
                "config".to_string(),
                toml::Value::Table(toml::Table::from_iter([(
                    "operator_value".to_string(),
                    toml::Value::String("kept".to_string()),
                )])),
            ),
        ]));

        // Trusted-proxy configuration remains host-owned and is validated,
        // while the plugin sees only its operator-owned config.
        let composed = unsafe {
            BrokerStackBuilder::new()
                .plugin_dir(plugin_dir.path().to_path_buf())
                .extra_factory(factory)
                .listener_auth(Some(raw), "test-listener", true, vec!["127.0.0.0/8".into()])
                .build()
                .await
                .unwrap()
        };
        assert_eq!(composed.auth_layer.kind(), TEST_AUTH_KIND);
        assert_eq!(
            seen_config.lock().unwrap().as_ref().unwrap(),
            &LayerConfig::from_iter([(
                "operator_value".to_string(),
                ConfigValue::String("kept".to_string()),
            )])
        );

        let broker = crate::Broker::from_composed(composed);
        let error = broker.reload_auth_policy("").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(error.message().contains(TEST_AUTH_KIND));
    }

    #[tokio::test]
    async fn plugin_auth_direct_builder_rejects_invalid_trusted_peer_cidr() {
        let plugin_dir = tempfile::tempdir().unwrap();
        let seen_config = Arc::new(Mutex::new(None));
        let factory = LoadedLayerFactory::Wrapper(Arc::new(RecordingAuthFactory { seen_config }));
        let raw = toml::Value::Table(toml::Table::from_iter([(
            "kind".to_string(),
            toml::Value::String(TEST_AUTH_KIND.to_string()),
        )]));

        let error = unsafe {
            BrokerStackBuilder::new()
                .plugin_dir(plugin_dir.path().to_path_buf())
                .extra_factory(factory)
                .listener_auth(Some(raw), "test-listener", true, vec!["not-a-cidr".into()])
                .build()
                .await
                .err()
                .expect("invalid plugin trusted-proxy CIDR must fail startup")
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("not-a-cidr"));
    }
}
