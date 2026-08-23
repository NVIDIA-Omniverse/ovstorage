// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![warn(clippy::missing_errors_doc)]

use std::sync::Arc;

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
pub use ovstorage_layer::{
    Extensions, REDACTED_QUERY_KEYS, canonicalize, canonicalize_preserves_node,
    parsing_preserves_node, redact_message, redact_url,
};
pub use ovstorage_plugin::address;
pub use ovstorage_plugin::*;
// The cross-language live-handoff verbs are stable
// `ovstorage` API — re-exported explicitly rather than left as glob fallout.
pub use ovstorage_plugin::{
    LayerExportExt, debug_assert_no_live_exports, export_handle, import_handle, live_export_count,
};

pub mod auth;
pub use auth::{AuthError as OAuthError, OAuthEndpoints, OAuthFlow};
pub mod config;
pub mod net;
mod stack_config;
pub use net::is_local_cleartext_host;
pub use stack_config::*;
mod loaded_v2;
mod loader;
pub use config::{ConnectionConfig, StateConfig, config_value_from_toml, config_value_to_toml};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

/// A Layer factory produced by [`load_layer_plugin`], tagged by the
/// construction shape the host registers it under on a `Stack::builder()`.
///
/// `Clone` is cheap because every variant wraps an `Arc`.
#[derive(Clone)]
pub enum LoadedLayerFactory {
    Backend(Arc<dyn BackendFactory>),
    Wrapper(Arc<dyn WrapperFactory>),
    Router(Arc<dyn RouterFactory>),
}

impl LoadedLayerFactory {
    /// The factory's kind descriptor (kind, `layer_type`, display name, and —
    /// once the manifest carries them — config/credential schemas). Lets a
    /// host index a loaded factory by `kind` and `layer_type` without caring
    /// which construction-shape variant it is.
    pub fn descriptor(&self) -> LayerKindDescriptor {
        match self {
            LoadedLayerFactory::Backend(factory) => factory.descriptor(),
            LoadedLayerFactory::Wrapper(factory) => factory.descriptor(),
            LoadedLayerFactory::Router(factory) => factory.descriptor(),
        }
    }
}

/// Reject a loaded plugin factory whose kind was already advertised by
/// another plugin in the same directory scan.
///
/// Native and language-binding hosts share this accumulator so a plugin
/// directory has the same duplicate-kind behavior on every Rust-backed
/// surface.
///
/// # Errors
///
/// Returns [`ErrorCode::InvalidArgument`] when `loaded` contains a kind
/// already present in `advertised`.
#[doc(hidden)]
pub fn validate_unique_loaded_plugin_kinds(
    advertised: &mut std::collections::HashSet<String>,
    loaded: &[LoadedLayerFactory],
) -> Result<()> {
    for factory in loaded {
        let descriptor = factory.descriptor();
        if !advertised.insert(descriptor.kind.clone()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "more than one plugin advertises Layer kind '{}'",
                    descriptor.kind
                ),
            ));
        }
    }
    Ok(())
}

/// Load an ABI-v2 storage plugin cdylib as one or more Layer factories ready
/// to register on a [`Stack::builder()`]. The loader validates the exact
/// supported Layer ABI and yields one factory per advertised kind.
///
/// Requires [`init_auth_substrate`] to have run.
///
/// # Safety
///
/// `dlopen` runs platform loader hooks; load only trusted plugin paths.
///
/// # Errors
///
/// - [`ErrorCode::NotConfigured`] — [`init_auth_substrate`] has not been
///   called.
/// - [`ErrorCode::InvalidArgument`] — the plugin advertises the reserved
///   built-in `file` kind or repeats a kind within one bundle.
/// - [`ErrorCode::Internal`] — the plugin cdylib cannot be opened,
///   `plugin_init_v1` cannot be called, or the manifest is invalid.
/// - [`ErrorCode::Unsupported`] — the plugin advertises an ABI this host
///   does not support, or `test_only` flag is set with `allow_test_plugins`
///   false.
pub unsafe fn load_layer_plugin(
    path: impl AsRef<std::path::Path>,
    allow_test_plugins: bool,
) -> Result<Vec<LoadedLayerFactory>> {
    unsafe {
        load_layer_plugin_with_host_kind(
            path.as_ref(),
            allow_test_plugins,
            ovstorage_plugin::ffi::HostKindV1::Library,
        )
    }
}

unsafe fn load_layer_plugin_with_host_kind(
    path: &std::path::Path,
    allow_test_plugins: bool,
    host_kind: ovstorage_plugin::ffi::HostKindV1,
) -> Result<Vec<LoadedLayerFactory>> {
    let provider = loader::substrate().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "load_layer_plugin requires crate::init_auth_substrate to have been called",
        )
    })?;

    let plugin =
        unsafe { loaded_v2::load_v2_plugin(path, provider, allow_test_plugins, host_kind)? };
    validate_plugin_kinds(plugin.manifest().name.as_str(), plugin.kinds())?;
    let mut factories = Vec::with_capacity(plugin.kinds().len());
    for kind in plugin.kinds() {
        factories.push(match kind.layer_type {
            LayerType::Backend => LoadedLayerFactory::Backend(Arc::new(
                loaded_v2::LoadedV2BackendFactory::new(plugin.clone(), kind.clone()),
            )),
            LayerType::Wrapper => LoadedLayerFactory::Wrapper(Arc::new(
                loaded_v2::LoadedV2WrapperFactory::new(plugin.clone(), kind.clone()),
            )),
            LayerType::Router => LoadedLayerFactory::Router(Arc::new(
                loaded_v2::LoadedV2RouterFactory::new(plugin.clone(), kind.clone()),
            )),
        });
    }
    Ok(factories)
}

fn validate_plugin_kinds(plugin_name: &str, kinds: &[LayerKindDescriptor]) -> Result<()> {
    let mut advertised = std::collections::HashSet::with_capacity(kinds.len());
    for kind in kinds {
        if kind.kind == crate::layers::FILE_BACKEND_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "plugin '{plugin_name}' advertises reserved built-in Layer kind '{}'",
                    crate::layers::FILE_BACKEND_KIND
                ),
            ));
        }
        if !advertised.insert(kind.kind.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "plugin '{plugin_name}' advertises Layer kind '{}' more than once",
                    kind.kind
                ),
            ));
        }
    }
    Ok(())
}

/// The filename shape [`discover_plugin_libraries`] accepts on this platform,
/// for hosts that report "no plugins found here" to a user.
#[cfg(windows)]
pub const PLUGIN_LIBRARY_FILENAME_PATTERN: &str = "ovstorage_plugin_*.dll";
/// The filename shape [`discover_plugin_libraries`] accepts on this platform,
/// for hosts that report "no plugins found here" to a user.
#[cfg(not(windows))]
pub const PLUGIN_LIBRARY_FILENAME_PATTERN: &str =
    "libovstorage_plugin_*.so / libovstorage_plugin_*.dylib";

/// List the plugin cdylibs in `dir`, sorted by path so repeated scans of one
/// directory yield one registration order.
///
/// This is the single definition of "what a host discovers when it is pointed
/// at a plugin directory", shared by [`load_layer_plugins_from_dir`] and by
/// the Python `PluginRegistry`. The scan is deliberately narrow:
///
/// - **Single level.** Subdirectories are not descended. A plugin directory
///   inside a release tree sits next to unrelated shared objects, and a
///   recursive walk would `dlopen` them.
/// - **Exact filename shape.** `libovstorage_plugin_*.so` /
///   `libovstorage_plugin_*.dylib` on Unix, `ovstorage_plugin_*.dll` on
///   Windows. Versioned suffixes (`libovstorage_plugin_x.so.1`) and any other
///   `.so`/`.dll` in the directory are not candidates: an unrelated library
///   that is `dlopen`'d runs its initializers in this process, so a name that
///   only resembles a plugin is a worse outcome than an unfound plugin.
/// - **Files only.** A directory named like a macOS framework bundle is not a
///   candidate.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `dir` does not exist, is not a
///   directory, or cannot be read or enumerated.
pub fn discover_plugin_libraries(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    if !dir.is_dir() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("plugin directory {} is not a directory", dir.display()),
        ));
    }
    let entries = std::fs::read_dir(dir).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("failed to read plugin directory {}: {error}", dir.display()),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to enumerate {}: {error}", dir.display()),
            )
        })?;
        let path = entry.path();
        if path.is_file() && crate::tracing_init::is_plugin_artifact(&path) {
            paths.push(path);
        }
    }
    // Directory order is filesystem-defined and differs between machines and
    // between runs; sort so a host registers the same kinds in the same order
    // every time.
    paths.sort();
    Ok(paths)
}

/// Whether a [`load_layer_plugin`] failure is one that directory discovery
/// steps over instead of failing on: an adjacent dylib matching the filename
/// pattern but carrying no manifest symbol (e.g. a proc-macro dylib in a
/// shared target dir), a `test_only` plugin refused by host policy, or a
/// cdylib built against an ABI this host does not implement.
///
/// A caller that names one plugin file still receives all three as errors —
/// they asked for that file. Bulk discovery is lenient so one stale or
/// unrelated file cannot hide every valid plugin beside it. Every other
/// failure (a corrupt manifest, a plugin whose init fails) is fatal to the
/// scan.
pub fn is_skippable_discovery_error(error: &Error) -> bool {
    crate::tracing_init::missing_plugin_symbol(error)
        || crate::tracing_init::policy_rejected_plugin(error)
        || crate::tracing_init::incompatible_abi_plugin(error)
}

/// Scan `dir` for plugin cdylibs (`libovstorage_plugin_*.{so,dylib,dll}`) and
/// load each via [`load_layer_plugin`], returning the flattened factory set
/// ready to register on a [`Stack::builder()`]. Bespoke hosts can reuse this
/// directory scan before composing their Stack.
///
/// A non-existent directory yields an empty set. Bulk discovery skips an
/// adjacent dylib that matches the filename pattern but lacks the manifest
/// symbol, a policy-rejected `test_only` plugin when `allow_test_plugins` is
/// false, and a plugin built for an incompatible ABI. Any other load failure
/// aborts the scan.
///
/// Requires [`init_auth_substrate`] to have run.
///
/// # Safety
///
/// Each candidate is `dlopen`'d in-process; trust the directory contents.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the directory cannot be read or
///   enumerated, a plugin advertises the reserved built-in `file` kind, or
///   more than one plugin advertises the same Layer kind.
/// - [`ErrorCode::Internal`] — a plugin cdylib fails to load (excluding
///   missing-manifest, policy-rejected, and ABI-incompatible skips).
pub unsafe fn load_layer_plugins_from_dir(
    dir: &std::path::Path,
    allow_test_plugins: bool,
) -> Result<Vec<LoadedLayerFactory>> {
    unsafe {
        load_layer_plugins_from_dir_with_host_kind(
            dir,
            allow_test_plugins,
            ovstorage_plugin::ffi::HostKindV1::Library,
        )
    }
}

/// Broker-host variant of [`load_layer_plugins_from_dir`]. The host kind is
/// carried in each plugin's callback table, allowing credential-aware plugins
/// to accept broker-minted request context while refusing the same context in
/// a direct library host.
///
/// # Safety
///
/// Each candidate is `dlopen`'d in-process; trust the directory contents.
///
/// # Errors
///
/// Returns the same errors as [`load_layer_plugins_from_dir`].
#[doc(hidden)]
pub unsafe fn load_layer_plugins_from_dir_with_host_kind(
    dir: &std::path::Path,
    allow_test_plugins: bool,
    host_kind: ovstorage_plugin::ffi::HostKindV1,
) -> Result<Vec<LoadedLayerFactory>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let paths = discover_plugin_libraries(dir)?;
    let mut factories = Vec::new();
    let mut kinds = std::collections::HashSet::new();
    for path in paths {
        match unsafe { load_layer_plugin_with_host_kind(&path, allow_test_plugins, host_kind) } {
            Ok(loaded) => {
                validate_unique_loaded_plugin_kinds(&mut kinds, &loaded)?;
                factories.extend(loaded);
            }
            Err(error) if is_skippable_discovery_error(&error) => {
                tracing::debug!(
                    plugin.path = %path.display(),
                    error.message = %error.message(),
                    "skipping non-loadable candidate during bulk load",
                );
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(factories)
}

#[cfg(test)]
mod plugin_kind_validation_tests {
    use super::*;

    fn kind(name: &str) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: name.to_string(),
            layer_type: LayerType::Backend,
            display_name: name.to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: true,
            auth_capable: false,
            supports_user_metadata: true,
        }
    }

    #[test]
    fn bundled_plugin_cannot_advertise_file() {
        let error = validate_plugin_kinds("reserved", &[kind("file")])
            .expect_err("file must remain host-provided");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            error.message(),
            "plugin 'reserved' advertises reserved built-in Layer kind 'file'"
        );
    }

    #[test]
    fn bundled_plugin_cannot_repeat_a_kind() {
        let error = validate_plugin_kinds("duplicate", &[kind("same"), kind("same")])
            .expect_err("duplicate kind must be rejected");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            error.message(),
            "plugin 'duplicate' advertises Layer kind 'same' more than once"
        );
    }
}

/// Inspect the Layer kinds a plugin cdylib advertises, for discovery /
/// configuration UIs (the C `ovstorage_inspect_plugin`) — "what kinds does
/// this plugin provide?" without composing them into a Stack.
///
/// In the current ABI the kind descriptors are carried in
/// `PluginInitResultV1` (not the static manifest), so this performs a full
/// [`load_layer_plugin`] — opening the cdylib and running `plugin_init_v1` —
/// but it never instantiates a Layer (`create_backend`/etc. are not called).
/// The descriptors are identity-only today (kind / `layer_type` /
/// `display_name`); the config/credential schemas are empty until the
/// manifest carries them (a later milestone).
///
/// # Pinning
///
/// Like [`load_layer_plugin`], this **permanently pins** the cdylib for the
/// remaining process lifetime: the loaded plugin's `library` / host
/// callbacks / state are held in `ManuallyDrop`, so the `dlopen` mapping is
/// never unmapped even though inspection discards the factories. Call it
/// once per plugin you intend to inspect — do **not** poll it or re-scan a
/// plugin directory on a refresh loop, as every call leaks one mmap'd
/// cdylib plus its auth substrate, unbounded.
///
/// # Safety
///
/// `dlopen` runs platform loader hooks; load only trusted plugin paths.
///
/// # Errors
///
/// Propagates errors from [`load_layer_plugin`]: [`ErrorCode::NotConfigured`],
/// [`ErrorCode::Internal`], or [`ErrorCode::Unsupported`].
pub unsafe fn inspect_layer_plugin(
    path: impl AsRef<std::path::Path>,
    allow_test_plugins: bool,
) -> Result<Vec<LayerKindDescriptor>> {
    let factories = unsafe { load_layer_plugin(path, allow_test_plugins)? };
    Ok(factories
        .iter()
        .map(LoadedLayerFactory::descriptor)
        .collect())
}

struct CachedSubstrate {
    auth_dir: std::path::PathBuf,
}

static SUBSTRATE_CACHE: std::sync::Mutex<Option<CachedSubstrate>> = std::sync::Mutex::new(None);

/// Initialize the process-global auth substrate.
///
/// The plugin SPI's host callbacks register set-once-per-process, so every
/// plugin loaded in one process shares one `(SecretStore, AuthRefreshLock)`
/// pair pinned to one `auth_dir`. Call this before loading plugins to pin a
/// non-default `auth_dir`; passing `None` selects `$OVSTORAGE_AUTH_DIR` or
/// `<tempdir>/ovstorage-<pid>`.
///
/// Re-calling with `Some(path)` that doesn't match the already-pinned
/// `auth_dir` returns `Err(ErrorCode::Unsupported)`. Re-calling with
/// `None` is always a no-op when the substrate is already initialized
/// (i.e., "ensure substrate exists, defaulting if necessary").
///
/// # Errors
///
/// - [`ErrorCode::Unsupported`] — the substrate is already initialized with
///   a different `auth_dir`.
/// - [`ErrorCode::Internal`] — the default auth directory cannot be created
///   or the auth substrate cannot be registered.
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
        None => default_auth_dir(),
    };
    install_auth_substrate(&mut guard, resolved)
}

/// Ensure the process-global auth substrate exists, using
/// `default_auth_dir` only if this call wins initialization.
///
/// This is for language bindings that have a binding-specific default
/// directory but must not reject a caller's earlier explicit
/// [`init_auth_substrate`] call with a custom directory.
///
/// # Errors
///
/// [`ErrorCode::Internal`] when the auth substrate cannot be registered.
pub fn ensure_auth_substrate_with_default(
    default_auth_dir: impl FnOnce() -> std::path::PathBuf,
) -> Result<()> {
    let mut guard = SUBSTRATE_CACHE
        .lock()
        .expect("ovstorage substrate cache mutex poisoned");
    if guard.is_some() {
        return Ok(());
    }
    let resolved = default_auth_dir();
    install_auth_substrate(&mut guard, resolved)
}

fn install_auth_substrate(
    guard: &mut Option<CachedSubstrate>,
    resolved: std::path::PathBuf,
) -> Result<()> {
    let secret_store: Arc<dyn auth::SecretStore> =
        Arc::new(auth::SqliteSecretStore::open(&resolved)?);
    let refresh_lock = Arc::new(auth::AuthRefreshLock::open(&resolved)?);
    let provider = loader::HostCallbacksProvider::new(secret_store, refresh_lock);
    loader::register_host_substrate(provider)?;
    *guard = Some(CachedSubstrate { auth_dir: resolved });
    Ok(())
}

fn default_auth_dir() -> std::path::PathBuf {
    auth::default_state_root()
}

mod read_helpers;
// `LayerExt` lives in its own public module rather than being re-exported into
// the crate root: a crate-root `LayerExt` binding leaks through the many
// internal `use crate::*` / `use super::*` globs and makes every crate-internal
// typed `self.copy(req, ..)` / `stack.stat(req, ..)` call ambiguous against the
// blanket ergonomic verb of the same name. Namespacing under `ext` keeps the
// wrapper dispatch bodies untouched; callers reach it via
// `ovstorage::ext::LayerExt`.
pub mod ext;
pub(crate) mod file;
mod format;
pub mod host;
pub mod layers;
pub mod metrics;
pub mod retry;
// The host's `routing` is a superset of `ovstorage_plugin::routing` (it adds
// host-only helpers and re-exports the promoted primitives), so it intentionally
// shadows the one pulled in by `pub use ovstorage_plugin::*` above.
#[allow(hidden_glob_reexports)]
mod routing;
mod tracing_init;
pub mod wrappers;

#[allow(unused_imports)]
pub use format::*;
/// The metadata cache lives in the shared `ovstorage-cache` crate. Re-export
/// the module under its historical `metadata_cache` name so paths like
/// `ovstorage::metadata_cache::hash_stat_options` keep resolving.
pub use ovstorage_cache::metadata as metadata_cache;
pub use ovstorage_cache::metadata::{
    DisabledDispatcher, Invalidation, MetadataCache, MetadataCacheConfig, MetadataCacheKey,
    MetadataCachePayload, MetadataKind, NotificationDispatcher, hash_list_options,
    hash_list_versions_options, hash_stat_options,
};
#[allow(unused_imports)]
pub use routing::*;
#[allow(unused_imports)]
pub use tracing_init::*;
