// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Composition of the REST gateway's shared inner [`Stack`].
//!
//! The gateway builds its shared, auth-free inner Stack from declared
//! `[ovstorage]` config through [`ovstorage::host::build_stack`]: the layer graph
//! is caller data (config), not a hard-coded chain. [`GatewayStackBuilder`] loads
//! the plugin directory, adds the gateway's one bespoke wrapper factory (the
//! `attribution` overlay), discovers
//! the connectable backend kinds, and hands `build_stack` the [`StackConfig`]. It then
//! attaches the selected per-listener auth layer over that inner. The immutable
//! Stack advertises only its *connected* kinds via `list_kinds`, so the discovery
//! endpoint reads the captured set.
//!
//! REST is a single-listener host: the degenerate `N=1` case of the
//! per-listener-auth-over-shared-inner design. One auth stack, no
//! fan-out. Authentication, authorization, and principal resolution all live in
//! the auth layer; the host performs none.
//!
//! The canonical gateway graph (shipped `ovstorage-rest.toml`, and
//! [`rest_stack_config`]'s programmatic twin) is `alias →
//! copy_rename_fallback → redirect_follower(follow_reads=false) → router →
//! [attribution_<kind> →] backend-per-kind` — no caches, no retry (clients retry).
//! `follow_reads = false` surfaces a backend read `Redirect` up unfollowed for
//! the handler to return as HTTP 307; body-bearing writes still follow
//! server-side, and `copy_rename_fallback` keeps cross-root copy/rename working.
//! The attribution overlay sits per-branch below the router, on the branches
//! whose backend can carry the reserved `user_metadata` key.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use ovstorage::{
    ConnectionConfig, LayerConfig, LayerTable, LoadedLayerFactory, Stack, StackConfig,
    StorageBackendKindDescriptor,
};
use ovstorage_authz::{
    AttributionStrategy, UserMetadataKinds, attributed_router_layers, prepare_listener_inner_stack,
};
use ovstorage_authz_layer::{AUTH_LAYER_NAME, ListenerAuth, ListenerAuthBuildPlan};

/// OIDC bearer-JWT parameters for the built-in auth layer's `Tcp` authn front
/// end. All three are required together. The host wiring assembles these into
/// the auth layer's [`LayerConfig`] via
/// [`ovstorage_authz_layer::resolve_listener_auth`]; test fixtures use this
/// struct to configure a `Tcp` JWT listener directly.
pub type RestJwtParams = ovstorage_authz_layer::JwtParams;

/// The composed gateway Stack plus the concrete auth-layer handle and the
/// backend kinds a caller may connect.
#[derive(Clone)]
pub struct GatewayStack {
    /// The selected per-listener auth layer `attach`ed over the shared
    /// auth-free inner.
    pub stack: Arc<Stack>,
    /// Opaque listener-auth handle used for backend-kind discovery gating.
    pub auth_layer: ListenerAuth,
    /// Backend kinds discovered from the loaded plugin factories, for
    /// `GET /v1/backend-kinds`.
    pub backend_kinds: Vec<StorageBackendKindDescriptor>,
    /// Whether a redirect carrying a credential broader than the redirected
    /// request may be handed to the client, from the operator's
    /// `redirect_credential_disclosure`.
    ///
    /// The follower in the graph carries the same setting and applies it first,
    /// where it can still fetch the bytes itself. The handler carries this copy
    /// because the layer graph is operator config and may rename or omit the
    /// follower entirely; a policy living only there would silently vanish from
    /// such a deployment and the `307` arm would forward whatever the graph left
    /// it.
    pub disclose_redirect_credentials: bool,
}

/// Builder for the REST gateway's [`GatewayStack`]. Loads plugins from a
/// directory, adds the gateway's one bespoke wrapper factory (`attribution`) to
/// the plugin-provided factory set, and builds the
/// shared inner [`Stack`] from the declared [`StackConfig`] via
/// [`ovstorage::host::build_stack`] — then attaches the selected per-listener
/// auth layer over it. The graph is `[ovstorage]` config; the
/// builder carries only the host concerns the config cannot (the attribution
/// strategy, the auth-layer config, and any override/plugin factories).
pub struct GatewayStackBuilder {
    plugin_dir: Option<PathBuf>,
    auth_dir: Option<PathBuf>,
    allow_test_plugins: bool,
    require_configured_stack: bool,
    /// The shared inner data-plane graph + its connections, declared as
    /// `[ovstorage]` config. Handed to `build_stack` as written, except that the
    /// attribution guarantee may add an instance to a branch that declares none,
    /// re-pointing the one edge that must then point at it. It removes, reorders
    /// and reconfigures nothing, and refuses the graph rather than moving a
    /// misplaced instance.
    stack_config: StackConfig,
    auth: ListenerAuthBuildPlan,
    /// Attribution strategy for the shared inner's `attribution` wrapper —
    /// injected into the factory, not read from layer config (the host owns it).
    attribution_strategy: AttributionStrategy,
    /// The operator's redirect credential disclosure policy. Stamped onto every
    /// follower in the declared graph at build time, and retained on the built
    /// [`GatewayStack`] for the handler's out-edge check. Defaults to refusing,
    /// so a gateway built without operator config discloses no more than one
    /// built with it.
    disclose_redirect_credentials: bool,
    /// Extra in-process Layer factories registered after the plugins, so an
    /// override (a test backend, an embedding host's bespoke layer) wins over the
    /// plugin-provided factory of the same kind.
    extra_factories: Vec<LoadedLayerFactory>,
}

fn validate_builtin_auth_transport(config: &LayerConfig) -> ovstorage::Result<()> {
    match ovstorage_authz_layer::configured_authn_mode(config)? {
        Some(ovstorage_authz_layer::AuthnMode::Mtls) => Err(ovstorage::Error::new(
            ovstorage::ErrorCode::InvalidArgument,
            "REST does not expose a verified TLS client certificate to authn_mode = \"mtls\"",
        )),
        Some(
            mode @ (ovstorage_authz_layer::AuthnMode::TrustedUnsignedJwt
            | ovstorage_authz_layer::AuthnMode::TrustedForwardedHeaders),
        ) => Err(ovstorage::Error::new(
            ovstorage::ErrorCode::InvalidArgument,
            format!(
                "REST does not expose trusted-proxy peer or forwarded-header credentials to authn_mode = \"{}\"",
                mode.as_str()
            ),
        )),
        None | Some(ovstorage_authz_layer::AuthnMode::JwtVerify) => Ok(()),
    }
}

impl Default for GatewayStackBuilder {
    fn default() -> Self {
        Self {
            plugin_dir: None,
            auth_dir: None,
            allow_test_plugins: false,
            require_configured_stack: false,
            stack_config: StackConfig::default(),
            auth: ListenerAuthBuildPlan::resolved_builtin(LayerConfig::new()),
            attribution_strategy: AttributionStrategy::default(),
            disclose_redirect_credentials: false,
            extra_factories: Vec::new(),
        }
    }
}

impl GatewayStackBuilder {
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
    /// contract); the gateway's config path refuses an empty stack up front
    /// (`require_configured_stack` in `main`) rather than substituting a default
    /// graph. [`rest_stack_config`] is the programmatic twin used only by test
    /// fixtures and embedding hosts that compose from connections in code.
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

    /// Register an in-process Layer factory (in addition to the plugins loaded
    /// from the directory) — e.g. a compat-wrapped in-process backend for a
    /// test, or an embedding host's bespoke layer. Registered after the plugins,
    /// so an override wins over a plugin-provided factory of the same kind.
    pub fn extra_factory(mut self, factory: LoadedLayerFactory) -> Self {
        self.extra_factories.push(factory);
        self
    }

    /// Supply a pre-resolved built-in auth config. This programmatic route is
    /// retained for embedding hosts and tests; operator config should use
    /// [`GatewayStackBuilder::listener_auth`]. An empty config is deny-all.
    pub fn auth_config(mut self, config: LayerConfig) -> Self {
        self.auth = ListenerAuthBuildPlan::resolved_builtin(config);
        self
    }

    /// Supply an operator listener-auth value for resolution after plugins are
    /// loaded, when their auth-capable wrapper kinds are known.
    pub fn listener_auth(
        mut self,
        raw: Option<toml::Value>,
        listener_name: impl Into<String>,
    ) -> Self {
        self.auth = ListenerAuthBuildPlan::listener(raw, listener_name);
        self
    }

    /// Attribution strategy for the shared inner's `attribution` wrapper.
    /// `Passthrough` is the right choice for an intermediate REST gateway that
    /// fronts another broker — the upstream broker's `ovstorage-modified-by`
    /// stamp survives end-to-end.
    pub fn attribution_strategy(mut self, strategy: AttributionStrategy) -> Self {
        self.attribution_strategy = strategy;
        self
    }

    /// The operator's redirect credential disclosure policy
    /// (`redirect_credential_disclosure`): whether a redirect carrying a
    /// credential broader than the redirected request may be handed to the
    /// client that asked for it.
    ///
    /// This is a property of the deployment, not of the credential. A gateway is
    /// not always a credential boundary — it is sometimes a central
    /// configuration point for clients already inside the trust boundary — and
    /// only the operator can say which. It governs the read and the write path
    /// identically.
    pub fn redirect_disclosure(mut self, disclose: bool) -> Self {
        self.disclose_redirect_credentials = disclose;
        self
    }

    /// Build the shared inner Stack from the declared config and attach the
    /// per-listener auth layer over it.
    ///
    /// Loads the plugin directory, appends the gateway's `attribution`
    /// wrapper factory (and any extra factories, which
    /// override plugin-provided factories), builds the inner via
    /// [`ovstorage::host::build_stack`], then composes the selected auth layer as
    /// the single child of a thin auth `Stack` the handlers dispatch through — the
    /// degenerate N=1 case of the per-listener-auth-over-shared-inner design.
    ///
    /// # Safety
    ///
    /// Loading plugins `dlopen`s cdylibs from the plugin directory; trust its
    /// contents.
    pub async unsafe fn build(self) -> ovstorage::Result<GatewayStack> {
        let require_configured_stack = self.require_configured_stack;
        let auth_plan = self.auth;
        let auth_preflight = auth_plan.preflight()?;
        if let Some(resolved) = &auth_preflight {
            debug_assert!(resolved.is_builtin());
            validate_builtin_auth_transport(resolved.config())?;
        }
        ovstorage::init_auth_substrate(self.auth_dir.as_deref())?;
        // Stamp the operator's disclosure policy onto every follower in the
        // declared graph. The operator sets one top-level key; the follower is
        // where a read refusal can still fetch the bytes, so the value has to
        // reach it. An operator who also writes the layer key by hand gets a
        // startup error naming the top-level key rather than one of the two
        // silently winning.
        let stack_config = ovstorage::host::stamp_redirect_disclosure(
            self.stack_config,
            self.disclose_redirect_credentials,
        )?;
        let plugin_dir = match self.plugin_dir {
            Some(dir) => Some(dir),
            None => ovstorage::default_plugin_dir(),
        };
        let factories = match plugin_dir {
            // SAFETY: forwarded from this fn's own safety contract.
            Some(dir) => unsafe {
                ovstorage::load_layer_plugins_from_dir(&dir, self.allow_test_plugins)?
            },
            None => Vec::new(),
        };
        let (stack_config, factories) = prepare_listener_inner_stack(
            stack_config,
            factories,
            self.attribution_strategy,
            self.extra_factories,
        )?;

        let resolved_auth = match auth_preflight {
            Some(resolved) => resolved,
            None => auth_plan.resolve(&factories)?,
        };

        if resolved_auth.is_builtin() {
            validate_builtin_auth_transport(resolved_auth.config())?;
        }

        // Resolve plugin auth first so an unknown/typo'd auth kind wins over
        // the independent empty-stack validation, preserving fail-closed error
        // ordering while still validating against the actually loaded set.
        if require_configured_stack {
            ovstorage::host::require_configured_stack(&stack_config)?;
        }

        // Runtime-addable kinds are the backend kinds the graph declares a Layer
        // for (the router's children) — NOT the startup connection set. An
        // operator may predeclare and route a backend with no initial connection
        // so a connection can be added later; the immutable Stack still owns that
        // target. `discover_backend_kinds` gates `supports_runtime_add` on this
        // set so the discovery endpoint agrees with the composed routes.
        let routed_kinds = ovstorage::host::graph_backend_kinds(&stack_config, &factories);
        let backend_kinds = ovstorage::host::discover_backend_kinds(&factories, &routed_kinds);

        // Compose the shared, auth-free inner from declared config.
        let inner = ovstorage::host::build_stack(&stack_config, factories.clone()).await?;

        // REST has no host-injected auth config. Plugin kinds receive their
        // operator config verbatim; built-in transport checks run only above.
        let composed = resolved_auth
            .compose(AUTH_LAYER_NAME, inner, &factories, None)
            .await?;
        Ok(GatewayStack {
            stack: composed.stack,
            auth_layer: composed.auth_layer,
            backend_kinds,
            disclose_redirect_credentials: self.disclose_redirect_credentials,
        })
    }
}

/// The REST gateway's default forward Stack graph as declarative [`StackConfig`]
/// data — the programmatic twin of the shipped `ovstorage-rest.toml`, used where
/// the graph is assembled in code rather than read from an operator TOML (the
/// test fixtures and embedding hosts that compose from connections directly).
///
/// Chain (top→bottom), rooted at `alias`: `alias → copy_rename_fallback →
/// redirect_follower(follow_reads=false) → router
/// → [attribution_<kind> →] <kind>*`. No caches, no retry (HTTP clients retry).
/// `follow_reads = false` is REST-critical: a backend read `Redirect` flows up
/// unfollowed for the handler to surface as HTTP 307.
///
/// Attribution sits **below** the router, one instance per branch, and only on
/// branches whose backend kind `declared` says can carry the reserved key
/// ([`UserMetadataKinds::carries_attribution`]) — the same placement the broker
/// uses, emitted from the same shared helper.
///
/// `declared` need only be a subset of the truth. This emits a graph before any
/// plugin is loaded, and `ensure_branch_attribution` runs afterwards with the
/// loaded plugins' own declarations: it splices a wrapper onto a capable branch
/// that has none, and refuses a graph that puts one over a branch that cannot
/// carry the key. A caller holding only core's built-in factories passes those.
pub fn rest_stack_config(
    connections: Vec<ConnectionConfig>,
    declared: &UserMetadataKinds,
) -> StackConfig {
    let mut layers: std::collections::HashMap<String, LayerTable> =
        std::collections::HashMap::new();

    // The linear wrapper chain above the follower: each layer's sole `inner` is
    // the next. Data-driven so the verbatim `insert(name, ovstorage::host::wrapper_layer(..))`
    // boilerplate lives once.
    for (name, kind, inner) in [
        ("alias", "alias", "copy_rename_fallback"),
        (
            "copy_rename_fallback",
            "copy_rename_fallback",
            "redirect_follower",
        ),
    ] {
        layers.insert(name.into(), ovstorage::host::wrapper_layer(kind, inner));
    }

    // Single global follower with `follow_reads = false`: read redirects flow up
    // unfollowed so the handler surfaces them as HTTP 307.
    let mut follower = ovstorage::host::wrapper_layer("redirect_follower", "router");
    follower
        .config
        .insert("follow_reads".into(), toml::Value::Boolean(false));
    layers.insert("redirect_follower".into(), follower);

    // One backend Layer per distinct connected kind (`target = kind`), the
    // router forking to exactly those branches, and a per-branch attribution
    // wrapper wherever the backend can carry the reserved key.
    let kinds: BTreeSet<String> = connections.iter().map(|c| c.backend_kind.clone()).collect();
    layers.extend(attributed_router_layers(&kinds, declared));

    StackConfig {
        root: Some("alias".into()),
        layers,
        connections,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The graph wiring that must stay in lockstep between the shipped TOML and
    /// its programmatic twin: `root`, and per layer its resolved `kind`
    /// (`table.kind`, else the layer name), its `inner`, and its `children`
    /// (order-normalized). Connection details and per-layer config are ignored —
    /// they legitimately differ (the shipped file carries connection roots).
    #[allow(clippy::type_complexity)]
    fn wiring(
        config: &StackConfig,
    ) -> (
        Option<String>,
        BTreeMap<String, String>,
        BTreeMap<String, Option<String>>,
        BTreeMap<String, Vec<String>>,
    ) {
        let kinds = config
            .layers
            .iter()
            .map(|(name, table)| {
                (
                    name.clone(),
                    table.kind.clone().unwrap_or_else(|| name.clone()),
                )
            })
            .collect();
        let inners = config
            .layers
            .iter()
            .map(|(name, table)| (name.clone(), table.inner.clone()))
            .collect();
        let children = config
            .layers
            .iter()
            .map(|(name, table)| {
                let mut c = table.children.clone();
                c.sort();
                (name.clone(), c)
            })
            .collect();
        (config.root.clone(), kinds, inners, children)
    }

    /// Structural-equality guard: the shipped `ovstorage-rest.toml` graph and the
    /// programmatic [`rest_stack_config`] twin must declare the same layer wiring.
    /// If someone edits one without the other, this fails — the twin is what test
    /// fixtures and embedding hosts compose from, so silent divergence would ship
    /// a graph that behaves differently from the documented default.
    #[test]
    fn shipped_toml_and_twin_have_identical_graph_wiring() {
        let shipped = include_str!("../ovstorage-rest.toml");
        let parsed = StackConfig::from_toml_str(shipped).expect("shipped rest TOML parses");
        let twin = rest_stack_config(
            parsed.connections.clone(),
            &UserMetadataKinds::from_factories(&[]),
        );
        assert_eq!(
            wiring(&parsed),
            wiring(&twin),
            "shipped ovstorage-rest.toml graph wiring diverged from rest_stack_config; \
             update both in lockstep"
        );
    }

    /// The companion of the broker's test of the same name. The follower's kind
    /// is spelled in `ovstorage::host` rather than imported — a host reaches
    /// plugins through `dlopen`, so the follower crate must not be linked into
    /// production dispatch — and two spellings of one name would make
    /// `stamp_redirect_disclosure` a silent no-op here, finding no layer to
    /// stamp and, correctly for a graph with no follower, saying nothing.
    #[test]
    fn the_shipped_gateway_graph_declares_a_layer_of_the_follower_kind() {
        let shipped = include_str!("../ovstorage-rest.toml");
        let config = StackConfig::from_toml_str(shipped).expect("shipped rest TOML parses");
        assert!(
            config.layers.iter().any(|(name, table)| {
                table.kind.as_deref().unwrap_or(name.as_str())
                    == ovstorage::host::REDIRECT_FOLLOWER_LAYER_KIND
            }),
            "no layer in the shipped gateway graph resolves to kind `{}`, so the \
             operator's `redirect_credential_disclosure` would reach no follower and \
             the policy would hold only at the handler's out-edge",
            ovstorage::host::REDIRECT_FOLLOWER_LAYER_KIND,
        );
    }

    /// The companion of the broker's guard: every layer this twin emits must be a
    /// connected backend kind, the router, or a name `HOST_GRAPH_LAYER_NAMES`
    /// reserves. That list is hand-maintained in another crate, so a host adding a
    /// layer and not updating it would let a connection kind collide with it.
    #[test]
    fn every_layer_the_rest_twin_emits_is_a_backend_kind_or_a_reserved_name() {
        let connections: Vec<ConnectionConfig> = ["file", "s3"]
            .into_iter()
            .map(|kind| {
                ConnectionConfig::from_request(ovstorage::ConnectionRequest {
                    backend_kind: kind.into(),
                    config: std::collections::HashMap::new(),
                    credentials: ovstorage::SecretBundle::default(),
                    persist: false,
                    display_name: None,
                })
            })
            .collect();
        let twin = rest_stack_config(
            connections,
            &UserMetadataKinds::from_factories(&[]).with("s3", true),
        );

        for name in twin.layers.keys() {
            let is_backend_kind = ["file", "s3"].contains(&name.as_str());
            assert!(
                is_backend_kind
                    || name.starts_with("attribution_")
                    || name == "router"
                    || ovstorage_authz::is_reserved_host_layer_name(name),
                "the gateway emits a layer named '{name}' that \
                 `HOST_GRAPH_LAYER_NAMES` does not reserve"
            );
        }
    }

    /// The gateway refuses a graph declaring attribution above its router — the
    /// shape a configuration written for the previous layout has — rather than
    /// starting on a graph whose exempt branches would still be stamped. The
    /// broker has the same test; this one pins that the REST host propagates the
    /// refusal too, since both call the same guarantee but through their own
    /// builders.
    #[tokio::test]
    async fn rest_refuses_an_attribution_layer_above_the_router() {
        let config = StackConfig::from_toml_str(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "router"

[ovstorage.layers.router]
kind = "router"
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#,
        )
        .expect("fixture parses");

        // The auth substrate is process-global and refuses a second `auth_dir`, so
        // use the one every REST fixture in this process uses. Initializing the
        // default here would make every gateway built afterwards in this process
        // fail to build.
        let auth_root =
            std::env::temp_dir().join(format!("ovstorage-rest-test-auth-{}", std::process::id()));
        std::fs::create_dir_all(&auth_root).unwrap();

        // SAFETY: no plugin directory is configured, so nothing is dlopened.
        let error = unsafe {
            GatewayStackBuilder::new()
                .auth_dir(auth_root)
                .stack_config(config)
                .build()
                .await
        }
        .err()
        .expect("a root-declared attribution layer must not start");
        assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("misplaced attribution layer"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains("'attribution'"),
            "{}",
            error.message()
        );
    }

    #[tokio::test]
    async fn rest_rejects_mtls_authn_without_a_client_certificate_transport() {
        let mut auth = LayerConfig::new();
        auth.insert(
            ovstorage_authz_layer::AUTHN_MODE_CONFIG_KEY.to_string(),
            ovstorage::ConfigValue::String("mtls".to_string()),
        );
        // SAFETY: the mTLS transport guard runs before plugin loading.
        let error = unsafe { GatewayStackBuilder::new().auth_config(auth).build().await }
            .err()
            .expect("REST mTLS config must be rejected");
        assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(error.message().contains("verified TLS client certificate"));
    }

    #[tokio::test]
    async fn rest_rejects_trusted_proxy_authn_without_proxy_transport_context() {
        for mode in ["trusted_unsigned_jwt", "trusted_forwarded_headers"] {
            let mut auth = LayerConfig::new();
            auth.insert(
                ovstorage_authz_layer::AUTHN_MODE_CONFIG_KEY.to_string(),
                ovstorage::ConfigValue::String(mode.to_string()),
            );
            // SAFETY: the trusted-proxy transport guard runs before plugin loading.
            let error = unsafe { GatewayStackBuilder::new().auth_config(auth).build().await }
                .err()
                .expect("REST trusted-proxy config must be rejected");
            assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
            assert!(error.message().contains("trusted-proxy peer"));
            assert!(error.message().contains(mode));
        }
    }
}
