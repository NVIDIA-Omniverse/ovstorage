// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

impl LibraryBuilder {
    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = Some(Arc::new(cache));
        self
    }

    pub fn with_metadata_cache(mut self, config: MetadataCacheConfig) -> Self {
        let cache = Arc::new(MetadataCache::new(&config));
        cache.spawn_ttl_sweeper(Duration::from_secs(60));
        for source in &config.notification_sources {
            metadata_cache::spawn_notification_source(&cache, source);
        }
        self.metadata_cache = Some(cache);
        self
    }

    pub fn add_route(
        mut self,
        prefix: Url,
        backend_id: impl Into<String>,
        backend: Arc<dyn shim::Backend>,
        capabilities: Capabilities,
    ) -> Self {
        self.routes.push(Route {
            prefix,
            rewrite_to: None,
            backend_id: BackendId(backend_id.into()),
            backend,
            backend_kind: "static".into(),
            display_name: None,
            connection_id: None,
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            capabilities,
            retry: None,
        });
        self
    }

    /// Static rewrite route resolved via a registered factory.
    /// `backend_kind` + `config` mirror a TOML route entry; the factory
    /// must already be registered (via [`Self::register_backend_factory`]
    /// or via `Library::load_plugin` / `Library::load_plugins_from_dir`
    /// after `open`).
    pub async fn add_rewrite_route(
        mut self,
        prefix: Url,
        rewrite_to: Url,
        backend_kind: impl Into<String>,
        config: HashMap<String, ConfigValue>,
    ) -> Result<Self> {
        let kind = backend_kind.into();
        let factory = self.backend_factories.get(&kind).cloned().ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!("backend kind '{kind}' is not registered"),
            )
        })?;
        let request = ConnectionRequest {
            backend_kind: kind.clone(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let instance = factory.instantiate(&request, None).await?;
        let capabilities = instance
            .address_roots
            .first()
            .map(|root| root.capabilities.clone())
            .unwrap_or_else(Capabilities::empty);
        self.routes.push(Route {
            prefix,
            rewrite_to: Some(rewrite_to),
            backend_id: instance.backend_id,
            backend: instance.backend,
            backend_kind: kind,
            display_name: None,
            connection_id: None,
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            capabilities,
            retry: None,
        });
        Ok(self)
    }

    /// Test-only — wires mock `Backend` impls without a factory.
    /// Production code uses [`Self::add_rewrite_route`].
    pub fn add_rewrite_route_with_backend_handle(
        mut self,
        prefix: Url,
        rewrite_to: Url,
        backend_id: impl Into<String>,
        backend: Arc<dyn shim::Backend>,
        capabilities: Capabilities,
    ) -> Self {
        self.routes.push(Route {
            prefix,
            rewrite_to: Some(rewrite_to),
            backend_id: BackendId(backend_id.into()),
            backend,
            backend_kind: "static".into(),
            display_name: None,
            connection_id: None,
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            capabilities,
            retry: None,
        });
        self
    }

    pub fn register_backend_factory(mut self, factory: Arc<dyn shim::Factory>) -> Self {
        let descriptor = factory.descriptor();
        self.backend_factories.insert(descriptor.kind, factory);
        self
    }

    /// Library-wide default. Per-route values from TOML override.
    pub fn with_retry(mut self, config: retry::RetryConfig) -> Result<Self> {
        config.validate()?;
        self.retry_default = config;
        Ok(self)
    }

    /// Chain consulted by [`Library::resolve_credentials`] in
    /// registration order; first non-`Unavailable` wins,
    /// `Backend(Error)` short-circuits.
    pub fn with_credential_providers(
        mut self,
        providers: Vec<Arc<dyn auth::CredentialProvider>>,
    ) -> Self {
        self.credential_providers = providers;
        self
    }

    /// Defaults: `refresh_skew = 60s`, `static_cred_ttl = 300s`.
    pub fn with_credential_cache_config(mut self, config: auth::CredentialCacheConfig) -> Self {
        self.credential_cache_config = config;
        self
    }

    /// Wire L2 cache durability with OS-keyring blobs.
    /// Storage failures surface as `CredentialError::Backend`.
    pub fn with_credential_persistence(
        mut self,
        secret_store: Arc<auth::SecretStore>,
        refresh_lock: Arc<auth::AuthRefreshLock>,
    ) -> Self {
        let persistence: Arc<dyn auth::CredentialPersistence> = Arc::new(
            auth::AuthDbCredentialPersistence::with_keyring(refresh_lock, secret_store),
        );
        self.credential_persistence = Some(persistence);
        self
    }

    /// Append a closure-driven [`auth::CredentialProvider`] to the
    /// chain. The closure is
    /// `Fn(BackendId, PrincipalView) -> impl Future<Output =
    /// Result<ResolvedCredential, CredentialError>>`.
    pub fn with_credential_callback<F, Fut>(mut self, name: impl Into<String>, callback: F) -> Self
    where
        F: Fn(BackendId, auth::PrincipalView) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<
                Output = std::result::Result<auth::ResolvedCredential, auth::CredentialError>,
            > + Send
            + 'static,
    {
        self.credential_providers
            .push(Arc::new(auth::CallbackCredentialProvider::new(
                name, callback,
            )));
        self
    }

    /// `InMemoryOnly` drops any wired persistence backend — for
    /// ephemeral VMs whose tokens come from an external control-plane.
    pub fn with_credential_cache_durability(
        mut self,
        durability: auth::CredentialCacheDurability,
    ) -> Self {
        self.credential_cache_durability = durability;
        self
    }

    /// Storage-namespace boundary folded into byte-cache keys. Two
    /// libraries on the same `cache_root` with different partitions
    /// never share cached bytes. Default `"local"` (single-tenant);
    /// multi-tenant hosts pass a per-tenant / per-route value.
    pub fn with_policy_partition(mut self, partition: impl Into<String>) -> Self {
        self.policy_partition = partition.into();
        self
    }

    /// Permit cdylib plugins whose manifest reports `test_only`.
    /// Default `false` so production hosts reject test fixtures with
    /// `ErrorCode::PluginRejected`. Older plugins predating the
    /// `test_only` field are treated as `false`.
    pub fn allow_test_plugins(mut self, allow: bool) -> Self {
        self.allow_test_plugins = allow;
        self
    }

    /// Top of the resolution chain: builder > env > smart default.
    /// `None` falls through. Threaded into `Factory::authenticate` (and
    /// broker `x-ov-iauth` metadata) so plugins pick PKCE vs. device
    /// vs. fail-fast.
    ///
    /// Not loaded from `LibraryConfig` — auth capability is per-binary
    /// context (a daemon knows it's headless, a desktop CLI knows it can
    /// show a browser), not deployment-shared TOML.
    pub fn interactive_auth_capability(
        mut self,
        capability: impl Into<Option<InteractiveAuthCapability>>,
    ) -> Self {
        self.interactive_auth_capability = capability.into();
        self
    }

    /// builder > env > smart default. Invalid env values warn + fall through.
    fn resolve_interactive_auth_capability(&self) -> InteractiveAuthCapability {
        let env = auth::StdEnv;
        self.interactive_auth_capability
            .or_else(|| auth::read_env_capability(&env))
            .unwrap_or_else(|| auth::detect_default_capability(&env))
    }

    pub fn open(mut self) -> Result<Arc<Library>> {
        let interactive_auth_capability = self.resolve_interactive_auth_capability();
        self.routes
            .sort_by_key(|r| std::cmp::Reverse(r.prefix.as_str().len()));
        for pair in self.routes.windows(2) {
            if pair[0].prefix == pair[1].prefix {
                return Err(Error::new(
                    ErrorCode::RouteConflict,
                    format!("duplicate route prefix '{}'", pair[0].prefix),
                ));
            }
        }
        // Auto-init the process-global auth substrate with defaults if
        // not yet pinned. Callers wanting a non-default `auth_dir` must
        // call `crate::init_auth_substrate(...)` before `open()`.
        crate::init_auth_substrate(None)?;
        // `InMemoryOnly` overrides any wired persistence backend.
        let persistence = self.credential_persistence.take();
        let credential_cache = match (self.credential_cache_durability, persistence) {
            (auth::CredentialCacheDurability::Persistent, Some(persistence)) => Arc::new(
                auth::CredentialCache::with_persistence(self.credential_cache_config, persistence)
                    .map_err(Error::from)?,
            ),
            (auth::CredentialCacheDurability::Persistent, None)
            | (auth::CredentialCacheDurability::InMemoryOnly, _) => {
                Arc::new(auth::CredentialCache::new(self.credential_cache_config))
            }
        };
        let metadata_cache = self.metadata_cache;
        let library = Arc::new(Library {
            routes: RwLock::new(self.routes),
            cache: self.cache,
            metadata_cache,
            backend_factories: RwLock::new(self.backend_factories),
            connections: Mutex::new(Vec::new()),
            allow_test_plugins: self.allow_test_plugins,
            aliases: RwLock::new(Vec::new()),
            visibility_overrides: RwLock::new(Vec::new()),
            retry_default: self.retry_default,
            credential_providers: self.credential_providers,
            credential_cache,
            policy_partition: self.policy_partition,
            route_epoch: AtomicU64::new(0),
            address_roots_watchers: Mutex::new(HashMap::new()),
            address_root_watch_senders: Mutex::new(Vec::new()),
            connection_requests: Mutex::new(HashMap::new()),
            bringup_locks: Mutex::new(HashMap::new()),
            bringup_cooldowns: Mutex::new(HashMap::new()),
            self_weak: Mutex::new(Weak::new()),
            interactive_auth_capability,
        });
        // Written before any external caller has a handle.
        *library.self_weak.lock() = Arc::downgrade(&library);
        Ok(library)
    }
}
