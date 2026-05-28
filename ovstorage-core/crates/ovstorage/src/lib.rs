// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use ovstorage_cache::Cache;
pub use ovstorage_plugin::address;
pub use ovstorage_plugin::*;

pub mod auth;
pub use auth::{AuthError as OAuthError, OAuthEndpoints, OAuthFlow};
pub mod config;
pub mod net;
pub use net::is_local_cleartext_host;
mod loaded_backend;
mod loaded_factory;
mod loader;
pub use config::{
    ConnectionConfig, LibraryConfig, RouteCacheConfig, RouteConfig, RouteRedirectConfig,
    StateConfig, config_value_from_toml, config_value_to_toml,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// User-facing ovstorage API implemented by [`Library`]. Address-routed
/// methods dispatch to the matching route's plugin; management and
/// introspection methods are library-local. Async I/O methods take
/// `cancel: Option<CancellationToken>`; pure state readers stay sync.
#[async_trait::async_trait]
pub trait Storage {
    fn list_address_roots(&self) -> Result<Vec<AddressRoot>>;
    fn list_backend_kinds(&self) -> Result<Vec<StorageBackendKindDescriptor>>;
    async fn add_connection(
        &self,
        request: ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection>;
    fn remove_connection(&self, id: &ConnectionId) -> Result<()>;
    async fn update_connection_credentials(
        &self,
        id: &ConnectionId,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection>;
    fn list_connections(&self) -> Result<Vec<Connection>>;
    fn watch_connections(&self) -> Result<ConnectionChangeStream>;
    fn add_alias(&self, request: AliasRequest) -> Result<Alias>;
    fn remove_alias(&self, id: &AliasId) -> Result<()>;
    fn list_aliases(&self) -> Result<Vec<Alias>>;
    fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<AddressRootSnapshotStream>;
    fn set_address_visibility(
        &self,
        address: Url,
        visibility: AddressVisibility,
        persist: bool,
    ) -> Result<AddressVisibilityOverride>;
    fn list_address_visibility_overrides(&self) -> Result<Vec<AddressVisibilityOverride>>;
    async fn authenticate_connection(
        &self,
        id: &ConnectionId,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream>;

    fn capabilities_for(&self, prefix: &Url) -> Result<Capabilities>;
    async fn stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;
    async fn read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(Vec<u8>, ObjectInfo)>;
    async fn read_stream(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ReadStream, ObjectInfo)>;
    /// Materialize the object at `addr` as a local file. Returns a
    /// `LocalDelegate` whose `path` field points at an on-disk file
    /// pinned against cache eviction for the lifetime of the delegate.
    /// Drop the delegate to release the pin.
    ///
    /// For local-file backends, returns the file's existing path
    /// directly. For remote backends, fetches the bytes into the cache
    /// and returns the cache row's path with a held lease.
    async fn materialize(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate>;
    /// Raw [`ReadResult`] without following redirects, materializing
    /// local-delegate files, or consulting the byte cache. Used by the
    /// REST gateway to forward `Redirect` as 307 and stream
    /// `LocalDelegate` to the caller.
    async fn read_raw(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult>;
    async fn write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult>;
    /// Body-less redirect-only entry point. Calls the plugin's
    /// `write_redirect` directly — never falls back to `write` /
    /// `write_stream`. Used by the broker daemon's gRPC `WriteRedirect`
    /// handler.
    async fn write_redirect(
        &self,
        dest: Url,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch>;
    /// Continue a write after the host (or an external follower)
    /// executed the plugin's redirects. Returns `WriteStep::Done` with
    /// the final result, or another `Redirects` for multi-stage uploads.
    async fn continue_write(
        &self,
        dest: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep>;
    async fn delete(
        &self,
        addr: Url,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;
    async fn list(
        &self,
        prefix: Url,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>>;
    async fn list_versions(
        &self,
        addr: Url,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>>;
    /// Resolve `addr` to a single [`ObjectInfo`]: the addressed version when
    /// the URL carries the backend's version-modifier query param, else the
    /// current head. Capability-gated on `supports_version_listing`.
    async fn get_latest_version(
        &self,
        addr: Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;
    async fn watch_directory(
        &self,
        prefix: Url,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream>;
    async fn create_directory(
        &self,
        addr: Url,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;
    async fn delete_directory(
        &self,
        addr: Url,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;
    async fn copy(
        &self,
        src: Url,
        dest: Url,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult>;
    async fn rename(
        &self,
        src: Url,
        dest: Url,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;
    async fn update_metadata(
        &self,
        addr: Url,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;
    async fn check_access(
        &self,
        addr: Url,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision>;
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeConfig;

#[derive(Clone, Debug)]
pub struct TracingConfig {
    pub service_name: String,
    pub service_version: String,
    pub otlp_traces: bool,
}

pub struct TracingGuard {
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[derive(Clone)]
struct Route {
    prefix: Url,
    rewrite_to: Option<Url>,
    backend_id: BackendId,
    backend: Arc<dyn shim::Backend>,
    backend_kind: String,
    display_name: Option<String>,
    connection_id: Option<ConnectionId>,
    source: RouteSource,
    capabilities: Capabilities,
    /// Per-route override; `None` falls back to library-wide default.
    retry: Option<retry::RetryConfig>,
}

pub struct Library {
    /// Read-heavy (lookup on every dispatch); `RwLock` lets concurrent
    /// dispatches resolve in parallel.
    routes: RwLock<Vec<Route>>,
    cache: Option<Arc<Cache>>,
    metadata_cache: Option<Arc<MetadataCache>>,
    backend_factories: RwLock<HashMap<String, Arc<dyn shim::Factory>>>,
    connections: Mutex<Vec<Connection>>,
    /// Allow `load_plugin*` to accept plugins whose manifest reports
    /// `test_only`. Threaded through from the builder.
    allow_test_plugins: bool,
    aliases: RwLock<Vec<Alias>>,
    visibility_overrides: RwLock<Vec<AddressVisibilityOverride>>,
    retry_default: retry::RetryConfig,
    credential_providers: Vec<Arc<dyn auth::CredentialProvider>>,
    credential_cache: Arc<auth::CredentialCache>,
    /// Storage-namespace boundary folded into every byte-cache key so
    /// callers in different partitions never share cached bytes for the
    /// same resolved target. See `ovstorage-cache.md` § "Per-key
    /// serialization".
    policy_partition: String,
    /// Monotonic counter bumped on every routing-state mutation
    /// (connection / alias / visibility / dynamic-roots event). Callers
    /// cache routing decisions keyed by this epoch and re-resolve when
    /// it advances.
    route_epoch: AtomicU64,
    address_roots_watchers:
        Mutex<HashMap<ConnectionId, library_helpers::AddressRootsWatcherHandle>>,
    address_root_watch_senders: Mutex<Vec<std::sync::mpsc::Sender<()>>>,
    /// Original `ConnectionRequest` retained for each registered connection
    /// so the lazy bring-up path can re-call `Factory::probe` /
    /// `Factory::instantiate` after a stub install or a credential rotation.
    /// Cleared on `remove_connection`.
    connection_requests: Mutex<HashMap<ConnectionId, Arc<ConnectionRequest>>>,
    /// Per-connection serialization for the lazy bring-up path. Concurrent
    /// requests against an `AwaitingAuth` connection coalesce on this lock
    /// so a single `Factory::authenticate` flow runs even under burst load.
    /// See `Library::bring_up_or_fail`.
    bringup_locks: Mutex<HashMap<ConnectionId, Arc<tokio::sync::Mutex<()>>>>,
    /// Last time `try_live_bringup` was attempted for a connection that
    /// was *not* `Authenticated` afterwards. The `bring_up_or_fail` hook
    /// short-circuits with the cached failure if the cooldown window
    /// hasn't elapsed; `force_bring_up` ignores this map.
    bringup_cooldowns: Mutex<HashMap<ConnectionId, Instant>>,
    /// Self-weak written once during `open()` before any external caller
    /// can observe the `Library`; the dynamic-roots watcher task
    /// upgrades to drive event application and exits cleanly when the
    /// host drops its `Arc`.
    self_weak: Mutex<Weak<Library>>,
    pub(crate) interactive_auth_capability: InteractiveAuthCapability,
}

pub(crate) const BRINGUP_COOLDOWN: Duration = Duration::from_secs(10);
#[cfg(not(test))]
pub(crate) const ADDRESS_ROOTS_REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
pub(crate) const ADDRESS_ROOTS_REFRESH_TIMEOUT: Duration = Duration::from_millis(200);

pub struct LibraryBuilder {
    routes: Vec<Route>,
    cache: Option<Arc<Cache>>,
    metadata_cache: Option<Arc<MetadataCache>>,
    backend_factories: HashMap<String, Arc<dyn shim::Factory>>,
    retry_default: retry::RetryConfig,
    credential_providers: Vec<Arc<dyn auth::CredentialProvider>>,
    credential_cache_config: auth::CredentialCacheConfig,
    pub(crate) credential_persistence: Option<Arc<dyn auth::CredentialPersistence>>,
    credential_cache_durability: auth::CredentialCacheDurability,
    policy_partition: String,
    allow_test_plugins: bool,
    /// `None` falls through to env → smart default.
    interactive_auth_capability: Option<InteractiveAuthCapability>,
}

#[allow(clippy::large_enum_variant)]
enum MetadataStatLookup {
    Found(ObjectInfo),
    NotFound,
    Unavailable,
}

struct CachedSubstrate {
    auth_dir: std::path::PathBuf,
}

static SUBSTRATE_CACHE: std::sync::Mutex<Option<CachedSubstrate>> = std::sync::Mutex::new(None);

/// Initialize the process-global auth substrate.
///
/// The plugin SPI's host callbacks register set-once-per-process — every
/// [`Library`] in one process shares one `(SecretStore, AuthRefreshLock)`
/// pair, pinned to one `auth_dir`. Call this explicitly before the first
/// [`Library::builder()`]`.open()` to pin a non-default `auth_dir`; otherwise
/// `open()` auto-initializes with the default (`$OVSTORAGE_AUTH_DIR` or
/// `<tempdir>/ovstorage-<pid>`).
///
/// Re-calling with `Some(path)` that doesn't match the already-pinned
/// `auth_dir` returns `Err(ErrorCode::Unsupported)`. Re-calling with
/// `None` is always a no-op when the substrate is already initialized
/// (i.e., "ensure substrate exists, defaulting if necessary").
pub fn init_auth_substrate(auth_dir: Option<&std::path::Path>) -> Result<()> {
    let mut guard = SUBSTRATE_CACHE
        .lock()
        .expect("ovstorage substrate cache mutex poisoned");
    if let Some(existing) = guard.as_ref() {
        if let Some(requested) = auth_dir
            && existing.auth_dir != requested
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "ovstorage auth substrate already initialized with auth_dir={:?}; \
                         cannot re-initialize with {:?}. The substrate is process-global; \
                         only one auth_dir per process is supported.",
                    existing.auth_dir, requested,
                ),
            ));
        }
        return Ok(());
    }
    let resolved = match auth_dir {
        Some(path) => path.to_path_buf(),
        None => default_auth_dir()?,
    };
    install_auth_substrate(&mut guard, resolved)
}

/// Ensure the process-global auth substrate exists, using
/// `default_auth_dir` only if this call wins initialization.
///
/// This is for language bindings that have a binding-specific default
/// directory but must not reject a caller's earlier explicit
/// [`init_auth_substrate`] call with a custom directory.
pub fn ensure_auth_substrate_with_default(
    default_auth_dir: impl FnOnce() -> Result<std::path::PathBuf>,
) -> Result<()> {
    let mut guard = SUBSTRATE_CACHE
        .lock()
        .expect("ovstorage substrate cache mutex poisoned");
    if guard.is_some() {
        return Ok(());
    }
    let resolved = default_auth_dir()?;
    install_auth_substrate(&mut guard, resolved)
}

fn install_auth_substrate(
    guard: &mut Option<CachedSubstrate>,
    resolved: std::path::PathBuf,
) -> Result<()> {
    let secret_store = Arc::new(auth::SecretStore::new());
    let refresh_lock = Arc::new(auth::AuthRefreshLock::open(&resolved)?);
    let provider = loader::HostCallbacksProvider::new(secret_store, refresh_lock);
    loader::register_host_substrate(provider)?;
    *guard = Some(CachedSubstrate { auth_dir: resolved });
    Ok(())
}

fn default_auth_dir() -> Result<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(std::path::PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to create default auth dir {tmp:?}: {error}"),
        )
    })?;
    Ok(tmp)
}

impl Default for LibraryBuilder {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            cache: None,
            metadata_cache: None,
            backend_factories: HashMap::new(),
            retry_default: retry::RetryConfig::default(),
            credential_providers: Vec::new(),
            credential_cache_config: auth::CredentialCacheConfig::default(),
            credential_persistence: None,
            credential_cache_durability: auth::CredentialCacheDurability::default(),
            policy_partition: "local".to_string(),
            allow_test_plugins: false,
            interactive_auth_capability: None,
        }
    }
}

impl Library {
    pub fn builder() -> LibraryBuilder {
        LibraryBuilder::default()
    }

    /// Open a `Library` with no plugins, no routes, and no config loaded.
    /// Pins the process-global auth substrate via
    /// [`init_auth_substrate`] (`None` accepts whatever's already
    /// registered or defaults). Most apps follow this immediately with
    /// [`Self::load_plugins_from_dir`] and [`Self::load_config`]. For
    /// advanced builder customization (credential providers, retry,
    /// partition, etc.), use [`Self::builder`] directly.
    pub fn open(auth_dir: Option<&std::path::Path>) -> Result<Arc<Self>> {
        init_auth_substrate(auth_dir)?;
        Self::builder().open()
    }

    /// Load and register a single plugin cdylib at `path`. Idempotent for
    /// already-registered backend kinds (silent re-register replaces the
    /// existing factory entry).
    ///
    /// # Safety
    ///
    /// `dlopen` runs platform loader hooks; load only trusted plugin paths.
    pub unsafe fn load_plugin(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let provider = loader::substrate().ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                "load_plugin requires crate::init_auth_substrate to have been called \
                 (LibraryBuilder::open() auto-initializes it on first call)",
            )
        })?;
        unsafe {
            let plugin = loader::HostPlugin::load(path, provider, self.allow_test_plugins)?;
            let factory = loaded_factory::LoadedFactory::new(plugin)?;
            let descriptor = <loaded_factory::LoadedFactory as shim::Factory>::descriptor(&factory);
            let factory_arc: Arc<dyn shim::Factory> = Arc::new(factory);
            self.backend_factories
                .write()
                .insert(descriptor.kind, factory_arc);
        }
        Ok(())
    }

    /// Scan a directory for `libovstorage_plugin_*.{so,dylib,dll}` and load
    /// each. `dir = None` resolves to [`crate::default_plugin_dir`] (i.e.
    /// `OVSTORAGE_PLUGIN_DIR` or `<exe-dir>/plugins/`). A non-existent
    /// directory is `Ok(())` — empty plugin set is a valid state.
    ///
    /// Bulk discovery is lenient about two error modes that direct
    /// [`Self::load_plugin`] surfaces verbatim:
    /// - **Missing manifest symbol** — an adjacent dylib matches the
    ///   `libovstorage_plugin_*` name pattern but isn't actually a
    ///   plugin (e.g. a proc-macro dylib in a shared target dir).
    ///   Skipped silently.
    /// - **Policy-rejected plugin** ([`ErrorCode::PluginRejected`]) —
    ///   the manifest's `test_only` flag is set but the host did not
    ///   opt in via [`LibraryBuilder::allow_test_plugins`]. Skipped at
    ///   debug-log level. This lets a production host ship the test
    ///   plugin in the same `plugins/` directory the bulk loader
    ///   scans without crashing at startup; downstream consumers that
    ///   want the fixture call [`Self::load_plugin`] directly with
    ///   `allow_test_plugins(true)`.
    ///
    /// Any other load failure (e.g. ABI mismatch, init failure)
    /// aborts the scan with the underlying error.
    ///
    /// # Safety
    ///
    /// Each candidate is `dlopen`'d in-process; trust the directory contents.
    pub unsafe fn load_plugins_from_dir(&self, dir: Option<&std::path::Path>) -> Result<()> {
        let resolved: std::path::PathBuf = match dir {
            Some(p) => p.to_path_buf(),
            None => match crate::default_plugin_dir() {
                Some(p) => p,
                None => return Ok(()),
            },
        };
        if !resolved.exists() {
            return Ok(());
        }
        let entries = std::fs::read_dir(&resolved).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to read plugin directory {}: {error}",
                    resolved.display()
                ),
            )
        })?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("failed to enumerate {}: {error}", resolved.display()),
                )
            })?;
            let path = entry.path();
            if path.is_file() && crate::tracing_init::is_plugin_artifact(&path) {
                paths.push(path);
            }
        }
        paths.sort();
        for path in paths {
            match unsafe { self.load_plugin(&path) } {
                Ok(()) => {}
                // Adjacent workspace dylibs (e.g. proc-macros) match
                // the name pattern but lack the manifest symbol.
                Err(error) if crate::tracing_init::missing_plugin_symbol(&error) => continue,
                // Host policy opted out (today: `test_only` without
                // `allow_test_plugins`). The plugin is well-formed;
                // it just isn't loadable for this host. See the
                // function-level docs for the contract.
                Err(error) if crate::tracing_init::policy_rejected_plugin(&error) => {
                    tracing::debug!(
                        plugin.path = %path.display(),
                        error.message = %error.message(),
                        "skipping policy-rejected plugin during bulk load",
                    );
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Load `ovstorage.toml` and apply its `[[connections]]` and `[[routes]]`
    /// to this live library. `path = None` searches `./ovstorage.toml` then
    /// `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml` (matching the CLI's
    /// search). No file? `Ok(Vec::new())` — empty config is a valid state.
    ///
    /// Connections are registered via [`Storage::add_connection`]; each
    /// `[[connections]].credentials` value is a plain string with
    /// `${NAME}` references substituted from the process environment.
    /// `[[routes]]` rewrite entries register through the appropriate
    /// factory in `backend_factories` — load the backend's plugin (via
    /// [`Self::load_plugin`] / [`Self::load_plugins_from_dir`]) before
    /// `load_config` so the factory exists.
    ///
    /// `retry`, `interactive_auth_capability`, `[state]`, and
    /// `[metadata_cache]` are *builder*-time concerns — set them via
    /// [`LibraryBuilder`] before [`LibraryBuilder::open`] if your TOML
    /// carries them. `load_config` ignores those sections.
    pub async fn load_config(&self, path: Option<&std::path::Path>) -> Result<Vec<Connection>> {
        let cfg = match path {
            Some(p) => Some(config::LibraryConfig::from_toml_path(p)?),
            None => config::LibraryConfig::from_default_path()?,
        };
        let Some(cfg) = cfg else {
            return Ok(Vec::new());
        };

        for route in &cfg.routes {
            let prefix = address::parse(&route.prefix)?;
            self.add_route_from_config(prefix, route).await?;
        }

        let mut registered = Vec::with_capacity(cfg.connections.len());
        for conn in &cfg.connections {
            let request = conn.to_connection_request()?;
            registered.push(self.add_connection_lazy(request, None).await?);
        }
        Ok(registered)
    }

    /// Apply a single TOML `[[routes]]` entry's prefix to the live routing
    /// table. Per-route `cache` / `redirect` / `retry` overrides are tracked
    /// separately and remain unwired — see Implementation gaps.
    async fn add_route_from_config(&self, prefix: Url, _route: &config::RouteConfig) -> Result<()> {
        // Today routes from [[routes]] are parsed and round-tripped through
        // write-config but per-route cache/redirect/retry overrides aren't
        // installed (matches the prior CLI behavior). The prefix entry alone
        // is a no-op until that plumbing lands.
        let _ = prefix;
        Ok(())
    }

    /// Static rewrite route resolved via a registered factory.
    /// `backend_kind` and `config` mirror a TOML route entry; the factory
    /// must already be registered (via [`Self::load_plugin`] /
    /// [`Self::load_plugins_from_dir`] or
    /// [`LibraryBuilder::register_backend_factory`]). Post-open analogue
    /// of [`LibraryBuilder::add_rewrite_route`].
    pub async fn add_rewrite_route(
        &self,
        prefix: Url,
        rewrite_to: Url,
        backend_kind: impl Into<String>,
        config: HashMap<String, ConfigValue>,
    ) -> Result<()> {
        let kind = backend_kind.into();
        let factory = self
            .backend_factories
            .read()
            .get(&kind)
            .cloned()
            .ok_or_else(|| {
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
        let mut routes = self.routes.write();
        routes.push(Route {
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
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.as_str().len()));
        drop(routes);
        self.bump_route_epoch();
        Ok(())
    }

    /// Resolve credentials for `(backend, principal)` against the
    /// configured provider chain. Cached entries within TTL skip the
    /// chain. Empty chain returns [`auth::CredentialError::Unavailable`].
    pub async fn resolve_credentials(
        &self,
        backend: &BackendId,
        principal: &auth::PrincipalView,
    ) -> std::result::Result<auth::ResolvedCredential, auth::CredentialError> {
        self.credential_cache
            .resolve(backend, principal, &self.credential_providers)
            .await
    }

    /// Drop the cached entry for `(backend, principal)`. Persistence
    /// errors are logged and discarded — L1 invalidation has happened
    /// regardless and the retry path must not be blocked.
    pub fn invalidate_credentials(&self, backend: &BackendId, principal: &auth::PrincipalView) {
        if let Err(err) = self.credential_cache.invalidate(backend, principal) {
            tracing::warn!(
                plugin = backend.0.as_str(),
                error.message = %err,
                "credential cache invalidate: persistence error (L1 already cleared)"
            );
        }
    }

    /// Inject a credential into the cache, bypassing the provider chain.
    /// Intended for external token-management (control-plane portals,
    /// proactive refresh push). Bumps `cred_epoch`; commits to L2 when
    /// persistence is wired and durability is `Persistent`.
    ///
    /// Does NOT hot-swap the bearer in active broker connections — use
    /// [`Storage::update_connection_credentials`] for that.
    pub async fn set_credential(
        &self,
        backend: BackendId,
        principal: auth::PrincipalView,
        credential: auth::ResolvedCredential,
    ) -> Result<()> {
        self.credential_cache
            .insert(&backend, &principal, credential)
            .await
            .map_err(Error::from)
    }

    /// Monotonic counter bumped on every successful resolve and
    /// invalidation. See `ovstorage.md` § "Resolved-credential caching".
    pub fn cred_epoch(&self) -> u64 {
        self.credential_cache.cred_epoch()
    }

    pub(crate) fn policy_partition(&self) -> &str {
        &self.policy_partition
    }

    pub fn metadata_cache(&self) -> Option<&Arc<MetadataCache>> {
        self.metadata_cache.as_ref()
    }

    pub fn interactive_auth_capability(&self) -> InteractiveAuthCapability {
        self.interactive_auth_capability
    }

    /// Monotonic counter bumped on every routing-state mutation. Cache
    /// route resolutions keyed on this — re-resolve on mismatch.
    pub fn route_epoch(&self) -> u64 {
        self.route_epoch.load(Ordering::Acquire)
    }

    pub(crate) fn bump_route_epoch(&self) {
        self.route_epoch.fetch_add(1, Ordering::AcqRel);
        self.address_root_watch_senders
            .lock()
            .retain(|tx| tx.send(()).is_ok());
    }
}

mod builder;
mod dispatch;
mod format;
mod library_helpers;
pub mod metadata_cache;
pub mod metrics;
mod redirect;
pub mod retry;
mod routing;
mod stub_backend;
mod tracing_init;

#[allow(unused_imports)]
pub use format::*;
pub use metadata_cache::{
    AzureEventGridDispatcher, DisabledDispatcher, GcpPubsubDispatcher, Invalidation, MetadataCache,
    MetadataCacheConfig, MetadataCacheKey, MetadataCachePayload, MetadataKind,
    NotificationDispatcher, NotificationSourceConfig, NotificationSourceKind, S3SqsDispatcher,
    hash_list_options, hash_list_versions_options, hash_stat_options,
};
#[allow(unused_imports)]
pub use redirect::*;
#[allow(unused_imports)]
pub use routing::*;
#[allow(unused_imports)]
pub use tracing_init::*;

#[cfg(test)]
mod tests;
