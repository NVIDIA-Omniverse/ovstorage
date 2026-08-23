// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only fixture helpers. The build script populates an
//! `OUT_DIR/test-plugins/` dir with the cdylibs broker tests dlopen and
//! exports the path as `OVSTORAGE_BROKER_TEST_PLUGIN_DIR`.

#![cfg(test)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use ovstorage::layers::{
    ALIAS_KIND, BYTE_CACHE_KIND, COPY_RENAME_FALLBACK_KIND, REDIRECT_FOLLOWER_KIND, RETRY_KIND,
    register_default_layer_factories,
};
use ovstorage::{
    AddressVisibility, ConfigValue, ConnectionConfig, ConnectionRequest, LayerConfig,
    LayerConnectionRequest, LayerSpec, LoadedLayerFactory, MetadataCache, SecretBundle, Stack, Url,
};
use ovstorage_authz_layer::{ANONYMOUS_ALLOW_ALL_POLICY, POLICY_CONFIG_KEY};
use ovstorage_cache::Cache;
use ovstorage_plugin_cache::{ByteCacheWrapperFactory, MetadataCacheWrapperFactory};
use ovstorage_plugin_core::{
    AliasRules, AliasWrapperFactory, CopyRenameFallbackWrapperFactory, RetryWrapperFactory,
    RouterFactoryImpl,
};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

use crate::{
    Broker, BrokerGraphOptions, BrokerOAuthRouteBindings, BrokerStack, BrokerStackBuilder,
    OAuthProviderRegistry, broker_stack_config,
};

/// Rewrite a per-branch-attribution graph into the root-declared shape: every
/// router child becomes the backend layer it wraps, the branch wrappers are
/// dropped, and one attribution layer is placed over the current root. What the
/// host does with such a graph — refuse to start — is what the tests using this
/// assert.
fn root_attribution_graph(mut config: ovstorage::StackConfig) -> ovstorage::StackConfig {
    // A configuration written for the previous layout also predates the
    // broker-owned `upstream_credential` boundary: drop the emitted boundary
    // layer so the graph is exactly what such an operator would declare. The
    // builder re-injects the boundary; what must refuse the graph is the
    // attribution placement check.
    if let Some(boundary) = config.layers.remove(crate::UPSTREAM_CREDENTIAL_KIND) {
        let inner = boundary
            .inner
            .expect("the emitted broker boundary always wraps an inner layer");
        if config.root.as_deref() == Some(crate::UPSTREAM_CREDENTIAL_KIND) {
            config.root = Some(inner);
        }
    }
    let branches: Vec<String> = config
        .layers
        .iter()
        .filter(|(_, table)| table.kind.as_deref() == Some(ovstorage_authz::ATTRIBUTION_KIND))
        .map(|(name, _)| name.clone())
        .collect();
    for branch in &branches {
        let inner = config.layers[branch]
            .inner
            .clone()
            .expect("an attribution branch wrapper wraps its backend");
        for table in config.layers.values_mut() {
            for child in table.children.iter_mut() {
                if child == branch {
                    *child = inner.clone();
                }
            }
        }
        config.layers.remove(branch);
    }
    let root = config.root.clone().expect("fixture graph has a root");
    config.layers.insert(
        "attribution".into(),
        ovstorage::host::wrapper_layer(ovstorage_authz::ATTRIBUTION_KIND, &root),
    );
    config.root = Some("attribution".into());
    config
}

pub(crate) fn workspace_plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_BROKER_TEST_PLUGIN_DIR"))
}

/// Build the post-bind broker client Stack used by integration tests.
///
/// The discovery URL is only known after the listener binds, so the broker
/// connection and aliases are declared while composing this Stack rather than
/// added through runtime mutation after construction.
#[derive(Default)]
pub(crate) struct BrokerClientStackOptions {
    pub(crate) aliases: Vec<(Url, Url)>,
    pub(crate) byte_cache: Option<Arc<Cache>>,
    pub(crate) lost_backing_fallback: bool,
}

pub(crate) async fn broker_client_stack(discovery_url: &str) -> Arc<Stack> {
    broker_client_stack_with(discovery_url, BrokerClientStackOptions::default()).await
}

pub(crate) async fn broker_client_stack_with(
    discovery_url: &str,
    options: BrokerClientStackOptions,
) -> Arc<Stack> {
    let BrokerClientStackOptions {
        aliases,
        byte_cache,
        lost_backing_fallback,
    } = options;
    ensure_test_plugin_env();
    let stem = if cfg!(target_os = "windows") {
        "ovstorage_plugin_broker.dll"
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_broker.dylib"
    } else {
        "libovstorage_plugin_broker.so"
    };
    let path = workspace_plugin_dir().join(stem);
    // SAFETY: the broker-client cdylib is built and staged by this crate's
    // integration-test build script.
    let broker_factory = unsafe { ovstorage::load_layer_plugin(&path, true) }
        .expect("load broker-client plugin")
        .into_iter()
        .find_map(|factory| match factory {
            LoadedLayerFactory::Backend(factory) if factory.descriptor().kind == "broker" => {
                Some(factory)
            }
            _ => None,
        })
        .expect("broker-client plugin exposes the broker backend");

    let mut builder = register_default_layer_factories(Stack::builder("alias"))
        .backend_factory(broker_factory)
        .wrapper_factory(Arc::new(AliasWrapperFactory::with_rules(AliasRules {
            aliases,
            visibility: Vec::new(),
        })))
        .wrapper_factory(Arc::new(CopyRenameFallbackWrapperFactory))
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .wrapper_factory(Arc::new(RetryWrapperFactory));
    let retry_inner = if let Some(cache) = byte_cache {
        builder = builder.wrapper_factory(Arc::new(ByteCacheWrapperFactory::with_cache(cache)));
        let mut cache = LayerSpec::wrapper("byte_cache", BYTE_CACHE_KIND, "redirect_follower");
        cache.config.insert(
            "partition".into(),
            ConfigValue::String("broker-client-test".into()),
        );
        if lost_backing_fallback {
            cache
                .config
                .insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
        }
        builder = builder.layer(cache);
        "byte_cache"
    } else {
        "redirect_follower"
    };

    let mut config = HashMap::new();
    config.insert(
        "address".into(),
        ConfigValue::String(discovery_url.to_string()),
    );
    let stack = builder
        .layer(LayerSpec::wrapper(
            "alias",
            ALIAS_KIND,
            "copy_rename_fallback",
        ))
        .layer(LayerSpec::wrapper(
            "copy_rename_fallback",
            COPY_RENAME_FALLBACK_KIND,
            retry_inner,
        ))
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            REDIRECT_FOLLOWER_KIND,
            "retry",
        ))
        .layer(LayerSpec::wrapper("retry", RETRY_KIND, "broker"))
        .layer(LayerSpec::backend("broker", "broker"))
        .connection(LayerConnectionRequest {
            target: "broker".into(),
            connection: ConnectionRequest {
                backend_kind: "broker".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("broker".into()),
            },
        })
        .build()
        .await
        .expect("build broker-client test Stack");
    Arc::new(stack)
}

/// Build a broker [`Stack`] for tests. The
/// single global follower's follow cap comes from the fixture's
/// [`follow_cap`](Self::follow_cap); a byte cache present + a cap ⇒
/// `follow_reads = true`.
#[derive(Default)]
pub(crate) struct BrokerStackFixture {
    connections: Vec<ConnectionRequest>,
    aliases: Vec<(Url, Url)>,
    visibility: Vec<(Url, AddressVisibility)>,
    byte_cache: Option<Arc<Cache>>,
    metadata_cache: Option<Arc<MetadataCache>>,
    extra_factories: Vec<LoadedLayerFactory>,
    /// The daemon-wide follow cap threaded into the emitted graph's `byte_cache`
    /// (`max_object_bytes`) and `redirect_follower` (`follow_reads` +
    /// `follow_reads_max_bytes`). With a byte cache present, `Some(cap)` ⇒
    /// `follow_reads = true`; otherwise the follower forwards redirects unfollowed.
    follow_cap: Option<u64>,
    /// The per-listener built-in auth layer's policy. When set,
    /// `build`/`build_broker` compose the built-in auth layer over the shared
    /// inner with this policy; unset ⇒ allow-all.
    auth_policy: Option<String>,
    /// Attribution strategy for the shared inner's attribution wrapper.
    attribution_strategy: ovstorage_authz::AttributionStrategy,
    /// Emit the graph with ONE attribution wrapper declared at its root, over the
    /// whole chain, as an operator config may still name it.
    ///
    /// The host **refuses** such a graph: `ensure_branch_attribution` accepts an
    /// attribution layer only directly above a backend that can carry the reserved
    /// key. So this builds the shape a configuration written for the previous
    /// layout has, and a test using it asserts that a broker declines to start on
    /// it rather than quietly running something else.
    attribution_at_root: bool,
    /// OIDC bearer-JWT params for the built-in auth layer's `Tcp` authn.
    jwt: Option<crate::BrokerJwtParams>,
    /// Complete auth-layer config for tests of non-JWT TCP modes.
    explicit_auth_config: Option<LayerConfig>,
    /// OAuth providers and route bindings injected into the broker's
    /// `upstream_credential` wrapper.
    oauth_providers: Arc<OAuthProviderRegistry>,
    oauth_bindings: BrokerOAuthRouteBindings,
    /// The operator's `redirect_credential_disclosure`, applied the way
    /// production applies it: stamped onto every follower in the emitted graph
    /// AND carried on the `Broker` for its out-edge check. Both, because they
    /// are two enforcement points and a fixture that set only one would let a
    /// test pass through a path the other guards.
    disclose_redirect_credentials: bool,
    /// Emit the graph without a `redirect_follower`, as an operator's own graph
    /// may. See `without_a_follower`.
    drop_follower: bool,
}

impl BrokerStackFixture {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A `file` backend connection rooted at `root`.
    pub(crate) fn file(mut self, root: &Path) -> Self {
        let mut config = HashMap::new();
        config.insert(
            "root".into(),
            ConfigValue::String(root.to_string_lossy().into_owned()),
        );
        self.connections.push(ConnectionRequest {
            backend_kind: "file".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        });
        self
    }

    /// The `test` fixture backend rooted at `test://demo/`, plus `extra` config.
    pub(crate) fn test_backend(mut self, extra: HashMap<String, ConfigValue>) -> Self {
        let mut config = extra;
        config.insert(
            "test_root".into(),
            ConfigValue::String("test://demo/".into()),
        );
        self.connections.push(ConnectionRequest {
            backend_kind: "test".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        });
        self
    }

    pub(crate) fn connection(mut self, request: ConnectionRequest) -> Self {
        self.connections.push(request);
        self
    }

    pub(crate) fn extra_factory(mut self, factory: LoadedLayerFactory) -> Self {
        self.extra_factories.push(factory);
        self
    }

    pub(crate) fn alias(mut self, from: Url, to: Url) -> Self {
        self.aliases.push((from, to));
        self
    }

    /// Register an address-visibility override, mirroring
    /// [`BrokerStackBuilder::visibility`]. Threaded into the composed Stack's
    /// `alias` wrapper so a `Hidden`/`Suppressed` root is filtered from
    /// `list_address_roots` (only `Visible` roots advertise).
    pub(crate) fn visibility(mut self, address: Url, visibility: AddressVisibility) -> Self {
        self.visibility.push((address, visibility));
        self
    }

    /// Supply the daemon-wide follow cap that drives the single global follower.
    /// `Some(cap)` with a byte cache present ⇒ `follow_reads = true` with that cap
    /// — the follow-and-tee path; `None` ⇒ `follow_reads = false`.
    pub(crate) fn follow_cap(mut self, cap: Option<u64>) -> Self {
        self.follow_cap = cap;
        self
    }

    /// Compose the built-in auth layer over the shared inner with `policy_toml`.
    /// Re-points a test that used `.authz(policy)` onto the per-listener auth
    /// layer path.
    pub(crate) fn authz(mut self, policy_toml: impl Into<String>) -> Self {
        self.auth_policy = Some(policy_toml.into());
        self
    }

    /// Declare a single attribution wrapper at the graph root and none per branch
    /// — the shape a configuration written for the previous layout has. The host
    /// refuses such a graph; see the field's own note.
    pub(crate) fn attribution_at_root(mut self) -> Self {
        self.attribution_at_root = true;
        self
    }

    /// Set the attribution strategy for the shared inner's attribution wrapper.
    pub(crate) fn attribution_strategy(
        mut self,
        strategy: ovstorage_authz::AttributionStrategy,
    ) -> Self {
        self.attribution_strategy = strategy;
        self
    }

    /// Configure OIDC bearer-JWT authn for the built-in auth layer (a TCP
    /// listener's `Tcp` credentials).
    pub(crate) fn jwt(mut self, params: crate::BrokerJwtParams) -> Self {
        self.jwt = Some(params);
        self
    }

    pub(crate) fn auth_config(mut self, config: LayerConfig) -> Self {
        self.explicit_auth_config = Some(config);
        self
    }

    pub(crate) fn oauth(
        mut self,
        registry: Arc<OAuthProviderRegistry>,
        bindings: BrokerOAuthRouteBindings,
    ) -> Self {
        self.oauth_providers = registry;
        self.oauth_bindings = bindings;
        self
    }

    /// The operator's `redirect_credential_disclosure`, `true` meaning `allow`.
    /// Applied to both enforcement points, as production does.
    pub(crate) fn redirect_disclosure(mut self, disclose: bool) -> Self {
        self.disclose_redirect_credentials = disclose;
        self
    }

    /// Emit the graph with **no** `redirect_follower` layer in it, the layer
    /// above it repointed at `retry`.
    ///
    /// The layer graph is operator configuration and may omit the follower;
    /// this builds exactly that. It is the only way to exercise the broker's
    /// own out-edge guard, because in a stock graph the follower reaches every
    /// redirect first and a test over that graph passes as soon as *something*
    /// withholds it — proving nothing about the check that is supposed to be
    /// uncomposable-away.
    pub(crate) fn without_a_follower(mut self) -> Self {
        self.drop_follower = true;
        self
    }

    pub(crate) fn byte_cache(mut self, cache: Arc<Cache>) -> Self {
        self.byte_cache = Some(cache);
        self
    }

    pub(crate) fn metadata_cache(mut self, cache: Arc<MetadataCache>) -> Self {
        self.metadata_cache = Some(cache);
        self
    }

    /// Assemble the built-in auth layer's [`LayerConfig`] the same way the
    /// resolved `auth` block would: an unset policy is the explicit anonymous
    /// allow-all (the single allow-all home in the auth crate), a set policy
    /// gates, and JWT params configure `Tcp` bearer authn.
    fn auth_layer_config(&self) -> LayerConfig {
        if let Some(config) = &self.explicit_auth_config {
            return config.clone();
        }
        let mut config = LayerConfig::new();
        let policy = self
            .auth_policy
            .clone()
            .unwrap_or_else(|| ANONYMOUS_ALLOW_ALL_POLICY.to_string());
        config.insert(POLICY_CONFIG_KEY.to_string(), ConfigValue::Toml(policy));
        if let Some(jwt) = &self.jwt {
            jwt.apply_to(&mut config);
        }
        config
    }

    /// Compose the [`BrokerStack`] (stack + discovered backend kinds), surfacing a
    /// build error — for tests that assert the host refuses a graph.
    pub(crate) async fn try_build(self) -> ovstorage::Result<BrokerStack> {
        ensure_test_plugin_env();
        // Assemble the auth-layer config before moving `self`'s other fields.
        let auth_config = self.auth_layer_config();
        let disclose = self.disclose_redirect_credentials;
        let drop_follower = self.drop_follower;
        // Emit the declarative graph — optional cache layers gated on the shared
        // instances the fixture holds; the concrete `Arc<Cache>` /
        // `Arc<MetadataCache>` are injected as override wrapper factories below,
        // so the emitted cache layers self-provision no roots.
        let connections: Vec<ConnectionConfig> = self
            .connections
            .into_iter()
            .map(ConnectionConfig::from_request)
            .collect();
        let stack_config = broker_stack_config(
            connections,
            BrokerGraphOptions {
                byte_cache: self.byte_cache.is_some(),
                metadata_cache: self.metadata_cache.is_some(),
                follow_cap: self.follow_cap,
            },
            &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
        );
        let stack_config = if self.attribution_at_root {
            root_attribution_graph(stack_config)
        } else {
            stack_config
        };
        let stack_config = crate::with_alias_rules(stack_config, self.aliases, self.visibility)
            .expect("valid broker test alias rules");
        // Stamp the follower the way the operator-config path does, so a
        // fixture exercises the same two-point enforcement production has.
        let stack_config = ovstorage::host::stamp_redirect_disclosure(stack_config, disclose)?;
        let stack_config = if drop_follower {
            drop_follower_layer(stack_config)
        } else {
            stack_config
        };
        // Leave the auth substrate to `init_auth_substrate`'s default (`None`)
        // resolution: pinning a dir would make the process-global init reject a
        // later broker built under a different dir, and this suite builds many.
        let mut builder = BrokerStackBuilder::new()
            .allow_test_plugins(true)
            .stack_config(stack_config)
            .attribution_strategy(self.attribution_strategy)
            .auth_config(auth_config)
            .oauth(self.oauth_providers, self.oauth_bindings)
            // The public utility layers are plugin-provided. Unit tests link
            // their rlib forms and register the same factories explicitly;
            // production loads their cdylibs from the plugin directory.
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
            .extra_factory(LoadedLayerFactory::Wrapper(Arc::new(RetryWrapperFactory)));
        for factory in self.extra_factories {
            builder = builder.extra_factory(factory);
        }
        // Host-shared cache instances override the plugin cache factories by
        // kind, so the Stack shares the test's cache.
        if let Some(cache) = self.byte_cache {
            builder = builder.extra_factory(LoadedLayerFactory::Wrapper(Arc::new(
                ByteCacheWrapperFactory::with_cache(cache),
            )));
        }
        if let Some(cache) = self.metadata_cache {
            builder = builder.extra_factory(LoadedLayerFactory::Wrapper(Arc::new(
                MetadataCacheWrapperFactory::with_cache(cache),
            )));
        }
        // SAFETY: integration test pointing at the workspace plugin dir.
        unsafe { builder.build().await }
    }

    /// Compose the [`BrokerStack`], panicking on a build error — the common case.
    pub(crate) async fn build(self) -> BrokerStack {
        self.try_build().await.expect("broker test stack build")
    }

    /// Compose and return only the `Arc<Stack>` — the common case for
    /// `Broker::new(stack)` and friends.
    pub(crate) async fn build_stack(self) -> Arc<Stack> {
        self.build().await.stack
    }

    /// Compose the Stack and wrap it in a `Broker` carrying the concrete auth
    /// layer handle + discovered backend kinds. Without a
    /// configured policy the auth layer is allow-all.
    pub(crate) async fn build_broker(self) -> Broker {
        let disclose = self.disclose_redirect_credentials;
        Broker::from_composed(self.build().await).with_redirect_disclosure(disclose)
    }
}

/// A forward-class broker [`Stack`] with a single `file` connection at `root`.
pub(crate) async fn file_broker_stack(root: &Path) -> Arc<Stack> {
    BrokerStackFixture::new().file(root).build_stack().await
}

/// A broker [`Stack`] with no connections (plugins loaded, empty router).
pub(crate) async fn empty_broker_stack() -> Arc<Stack> {
    BrokerStackFixture::new().build_stack().await
}

/// Set `OVSTORAGE_PLUGIN_DIR` + auth dir once per test process so
/// production-path builders discover the fixture cdylibs.
pub(crate) fn ensure_test_plugin_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("OVSTORAGE_PLUGIN_DIR", workspace_plugin_dir()) };
        let auth_root =
            std::env::temp_dir().join(format!("ovstorage-broker-test-auth-{}", std::process::id()));
        std::fs::create_dir_all(&auth_root).unwrap();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("OVSTORAGE_AUTH_DIR", &auth_root) };
        unsafe { std::env::set_var("OVSTORAGE_ALLOW_TEST_PLUGINS", "1") };
    });
}

/// Remove the `redirect_follower` layer from a declared graph, repointing
/// whichever layer named it as `inner` at what the follower pointed to.
///
/// The shape an operator's own graph can have. Nothing in the host requires a
/// follower; what requires one is the *graceful* half of the disclosure policy.
fn drop_follower_layer(mut config: ovstorage::StackConfig) -> ovstorage::StackConfig {
    // Panic rather than return the graph unchanged. A silent no-op here would
    // leave the follower in place, and both tests using this fixture would keep
    // passing — the refusal one via the follower, which is precisely the false
    // pass the fixture exists to eliminate.
    let follower = config
        .layers
        .remove("redirect_follower")
        .expect("the broker twin's graph declares a redirect_follower to drop");
    let target = follower
        .inner
        .expect("the broker twin's follower always names an inner");
    for table in config.layers.values_mut() {
        if table.inner.as_deref() == Some("redirect_follower") {
            table.inner = Some(target.clone());
        }
    }
    if config.root.as_deref() == Some("redirect_follower") {
        config.root = Some(target);
    }
    config
}
