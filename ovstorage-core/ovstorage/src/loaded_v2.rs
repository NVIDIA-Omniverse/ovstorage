// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side loader for an ABI-v2 (Layer) cdylib. [`HostPluginV2`] `dlopen`s
//! the library, validates the manifest/init handshake, and keeps it mapped;
//! the three `LoadedV2*Factory` adapters expose a v2 `PluginVTableV1`'s
//! `create_backend`/`create_wrapper`/`create_router` as the Rust
//! `BackendFactory`/`WrapperFactory`/`RouterFactory` traits, wrapping each
//! produced `LayerHandle` in a plugin-pinned
//! [`ForeignVtableLayer`] —
//! the generic foreign-vtable `Layer` that lives beside the produce-side
//! `thunks_v2` in `ovstorage-plugin`'s `consume_v2`.
//!
//! The borrowed-manifest `clone_*` kind-descriptor decoders below stay here
//! (they copy out of the plugin-owned manifest array without consuming it);
//! the owned-frame FFI→Rust decoders live in `consume_v2`.

use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::Arc;

// The consumer-side ABI-v2 codec — request builders, introspection decoders,
// update-stream bridges, the `on_complete` result decoders, and the generic
// `ForeignVtableLayer` that drives a foreign `LayerHandle`'s vtable — lives in
// `ovstorage-plugin`'s `consume_v2`, next to the produce-side `thunks_v2`. The
// host loader (`HostPluginV2`) and the `LoadedV2*Factory` glue below construct
// `ForeignVtableLayer`s pinned to the loaded plugin.
use crate::*;
use ovstorage_plugin::consume_v2::{ForeignVtableLayer, KindsFallback};

pub(crate) const MANIFEST_ABI_MISMATCH_MESSAGE: &str =
    "manifest abi_version is not the supported Layer ABI";
pub(crate) const INIT_ABI_MISMATCH_MESSAGE: &str =
    "v2 plugin init abi_version is not the supported Layer ABI";
pub(crate) const PLUGIN_VTABLE_ABI_MISMATCH_MESSAGE: &str =
    "v2 plugin PluginVTableV1 abi_version is not the supported Layer ABI";

// =====================================================================
// Loaded v2 plugin handle
// =====================================================================

/// A `dlopen`'d ABI-v2 cdylib: the plugin-scoped state and vtable from
/// `ovstorage_plugin_init_v1`, plus the keep-alive boxes. The host drops
/// `plugin_state` via `plugin_vtable.drop` after every Layer handle the
/// plugin produced has been dropped; the library and host-callback boxes
/// stay pinned for the process lifetime (a plugin may stash the host
/// pointer), preserving the callback context for every exported handle.
pub(crate) struct HostPluginV2 {
    plugin_state: *mut c_void,
    plugin_vtable: *const ffi::PluginVTableV1,
    manifest: PluginManifest,
    #[allow(dead_code)]
    library: std::mem::ManuallyDrop<libloading::Library>,
    #[allow(dead_code)]
    callbacks: std::mem::ManuallyDrop<Box<ffi::HostCallbacks>>,
    #[allow(dead_code)]
    state: std::mem::ManuallyDrop<Box<crate::loader::HostCallbacksState>>,
    /// The kinds this cdylib advertised, decoded from the init result.
    kinds: Vec<LayerKindDescriptor>,
}

// SAFETY: the raw pointers are read-only after init and the contract
// makes them safe to share across threads while `library` stays mapped.
unsafe impl Send for HostPluginV2 {}
unsafe impl Sync for HostPluginV2 {}

impl HostPluginV2 {
    /// Assemble a `HostPluginV2` from the pieces the loader gathered. The
    /// loader owns dlopen + manifest validation + the host-callback
    /// substrate; this just records them and decodes the advertised
    /// kinds.
    pub(crate) fn from_parts(
        library: libloading::Library,
        callbacks: Box<ffi::HostCallbacks>,
        state: Box<crate::loader::HostCallbacksState>,
        manifest: PluginManifest,
        init: ffi::PluginInitResultV1,
    ) -> Result<Arc<Self>> {
        if init.plugin_vtable.is_null() || init.plugin_state.is_null() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "v2 plugin init returned a null plugin_state or plugin_vtable",
            ));
        }
        // SAFETY: checked non-null above; the loader keeps the plugin image
        // mapped for the handle's lifetime.
        let vtable_abi_version = unsafe { read_plugin_vtable_header(init.plugin_vtable) }?;
        if vtable_abi_version != ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION {
            // Init already ran, so `plugin_state` and the kinds array exist
            // and nothing else will reclaim them: this returns before the
            // `HostPluginV2` that would own them is built. The `drop` slot
            // is safe to call even at a mismatched version — `struct_size`
            // is validated above and the stable header (`struct_size`,
            // `abi_version`, `drop`) is fixed across the whole v2 family,
            // which is the same rule a version-mismatched `LayerHandle`
            // import relies on to dispose itself.
            //
            // SAFETY: `struct_size` vouches for the `drop` slot's presence,
            // and `plugin_state` is the non-null value init paired with it.
            unsafe { ((*init.plugin_vtable).drop)(init.plugin_state) };
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                PLUGIN_VTABLE_ABI_MISMATCH_MESSAGE,
            ));
        }
        if init.kind_count > 0 && init.kinds.is_null() {
            // SAFETY: the current plugin vtable was validated above and owns
            // the non-null state returned by this init result.
            unsafe { ((*init.plugin_vtable).drop)(init.plugin_state) };
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "v2 plugin advertised kinds with a null descriptor array",
            ));
        }
        // Decode the borrowed kind descriptors (host copies them out; the
        // plugin frees its own array via plugin_vtable.drop).
        let mut kinds = Vec::with_capacity(init.kind_count);
        for i in 0..init.kind_count {
            let raw = unsafe { &*init.kinds.add(i) };
            let descriptor = match unsafe { layer_kind_descriptor_clone_from_ffi(raw) } {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    // SAFETY: the current plugin vtable was validated above
                    // and owns the non-null state returned by this init result.
                    unsafe { ((*init.plugin_vtable).drop)(init.plugin_state) };
                    return Err(error);
                }
            };
            kinds.push(descriptor);
        }
        if let Err(error) = validate_unique_plugin_kinds(&manifest.name, &kinds) {
            // SAFETY: the current plugin vtable was validated above and owns
            // the non-null state returned by this init result.
            unsafe { ((*init.plugin_vtable).drop)(init.plugin_state) };
            return Err(error);
        }
        Ok(Arc::new(Self {
            plugin_state: init.plugin_state,
            plugin_vtable: init.plugin_vtable,
            manifest,
            library: std::mem::ManuallyDrop::new(library),
            callbacks: std::mem::ManuallyDrop::new(callbacks),
            state: std::mem::ManuallyDrop::new(state),
            kinds,
        }))
    }

    #[allow(dead_code)]
    pub(crate) fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// The kinds this cdylib advertised. The identity fields AND the
    /// credential schema/method lists are cloned out of the borrowed manifest
    /// (`layer_kind_descriptor_clone_from_ffi`) so discovery and connection
    /// management see the plugin's actual authentication contract. Only
    /// `config_schema` remains empty here (available live via
    /// the `descriptor` vtable slot on an instantiated layer).
    pub(crate) fn kinds(&self) -> &[LayerKindDescriptor] {
        &self.kinds
    }

    fn vtable(&self) -> &ffi::PluginVTableV1 {
        // SAFETY: validated non-null in `from_parts`; valid while `library`
        // stays mapped.
        unsafe { &*self.plugin_vtable }
    }
}

fn validate_unique_plugin_kinds(plugin_name: &str, kinds: &[LayerKindDescriptor]) -> Result<()> {
    let mut seen = HashSet::with_capacity(kinds.len());
    for descriptor in kinds {
        if !seen.insert(descriptor.kind.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "v2 plugin '{plugin_name}' advertises Layer kind '{}' more than once",
                    descriptor.kind
                ),
            ));
        }
    }
    Ok(())
}

impl Drop for HostPluginV2 {
    fn drop(&mut self) {
        if !self.plugin_vtable.is_null() && !self.plugin_state.is_null() {
            // The ABI's exclusive-after-drain drop contract holds here without
            // a pin of its own: every `PluginVTableV1` slot other than `drop`
            // is synchronous (`create_backend` / `create_wrapper` /
            // `create_router` return before the host regains control), so no
            // call against `plugin_state` can be outstanding. The Layer slots
            // that ARE callback-shaped run against a Layer's state, and each
            // foreign Layer holds this `Arc` as its `keepalive` for as long as
            // any of its calls is in flight (`consume_v2::ForeignLayerState`),
            // so a plugin whose Layer was abandoned mid-call stays loaded here
            // too.
            // SAFETY: contract guarantees `plugin_vtable->drop` is valid for
            // the lifetime of `plugin_state`; library is still mapped.
            unsafe { ((*self.plugin_vtable).drop)(self.plugin_state) };
            self.plugin_state = std::ptr::null_mut();
            self.plugin_vtable = std::ptr::null();
        }
    }
}

/// `dlopen` an ABI-v2 cdylib, validate its manifest and init handshake, and
/// build a [`HostPluginV2`].
///
/// # Safety
///
/// `dlopen` runs platform loader hooks; load only trusted plugin paths.
pub(crate) unsafe fn load_v2_plugin(
    path: &std::path::Path,
    provider: Arc<crate::loader::HostCallbacksProvider>,
    allow_test_plugins: bool,
    host_kind: ffi::HostKindV1,
) -> Result<Arc<HostPluginV2>> {
    unsafe {
        let library = libloading::Library::new(path).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to load plugin library: {error}"),
            )
        })?;

        let manifest = {
            let manifest_symbol: libloading::Symbol<*const ffi::PluginManifestV1> = library
                .get(b"ovstorage_plugin_manifest_v1\0")
                .map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("plugin manifest symbol is missing: {error}"),
                    )
                })?;
            read_v2_manifest(*manifest_symbol)?
        };

        if manifest.test_only && !allow_test_plugins {
            return Err(Error::new(
                ErrorCode::PluginRejected,
                format!(
                    "plugin '{}' is marked test_only and the host did not opt in via \
                     allow_test_plugins",
                    manifest.name
                ),
            ));
        }

        let (callbacks, state) = crate::loader::build_host_callbacks(provider, host_kind);
        let init: ffi::PluginInitResultV1 = {
            let init_symbol: libloading::Symbol<ffi::PluginInitV1> = library
                .get(b"ovstorage_plugin_init_v1\0")
                .map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("plugin init symbol is missing: {error}"),
                    )
                })?;
            init_symbol(&*callbacks)
        };

        if init.struct_size < std::mem::size_of::<ffi::PluginInitResultV1>() {
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                "v2 plugin PluginInitResultV1 struct_size is too small",
            ));
        }
        // Exact match: this host implements exactly the current V2 Layer
        // ABI, so any other abi_version — a stale earlier one (e.g. v5) or
        // an unknown higher one — must be rejected; there is no `[min,max]`
        // band, so an accepted-but-mismatched ABI would be read with the
        // wrong (current) struct layout. Future hosts widen this to the set
        // of Layer ABIs they know how to validate.
        if init.abi_version != ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION {
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                INIT_ABI_MISMATCH_MESSAGE,
            ));
        }

        HostPluginV2::from_parts(library, callbacks, state, manifest, init)
    }
}

/// Read and validate the factory vtable's stable header, returning its
/// `abi_version`, before any slot is reached through it.
///
/// The `abi_version` here is separate from the manifest's and the init
/// result's, and it is the one governing the `create_*` slots. A plugin
/// assembled from mixed-version components can advertise a current manifest
/// and init result over a stale factory vtable, which the other two gates
/// do not cover: a `create_*` error would then be minted by the stale
/// component's marshalling and released by this host's allocator. The
/// separately gated `LayerVTableV1` on a returned layer comes too late to
/// catch that. The pure-C loader gates the same field (`registry.c`), so
/// both hosts validate alike.
///
/// Takes a raw pointer and never forms a `&PluginVTableV1` spanning more
/// than it has checked. Materializing that reference asserts the whole
/// `size_of::<PluginVTableV1>()` region is live — the very claim a
/// truncated or malformed vtable breaks — so doing it before reading
/// `struct_size` would make this gate unsound against exactly the plugins
/// it exists to reject. Each field is read through its own raw place
/// projection, in the order the header's own size bounds allow.
///
/// # Safety
///
/// `vtable` must be non-null and readable for at least the leading
/// `usize`. That much is irreducible: nothing can report how large the
/// struct is without reading the field that says so.
unsafe fn read_plugin_vtable_header(vtable: *const ffi::PluginVTableV1) -> Result<u32> {
    // Step 1: the leading `usize` only.
    let struct_size = unsafe { std::ptr::addr_of!((*vtable).struct_size).read() };
    if struct_size < std::mem::size_of::<ffi::PluginVTableV1>() {
        return Err(Error::new(
            ErrorCode::IncompatibleType,
            "v2 plugin PluginVTableV1 struct_size is too small",
        ));
    }
    // Step 2: `struct_size` now vouches for the rest of the struct, so
    // reading a later field is in bounds.
    Ok(unsafe { std::ptr::addr_of!((*vtable).abi_version).read() })
}

/// Read and validate a Layer plugin's manifest fields directly.
unsafe fn read_v2_manifest(raw: *const ffi::PluginManifestV1) -> Result<PluginManifest> {
    unsafe {
        if raw.is_null() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "plugin manifest pointer is null",
            ));
        }
        let struct_size = (*raw).struct_size;
        const PREFIX_THROUGH_VERSION: usize = std::mem::size_of::<usize>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<*const std::os::raw::c_char>() * 2;
        if struct_size < PREFIX_THROUGH_VERSION {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "plugin manifest struct_size is too small",
            ));
        }
        let raw = &*raw;
        // Exact match, mirroring the init-result check above (see there).
        if raw.abi_version != ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION {
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                MANIFEST_ABI_MISMATCH_MESSAGE,
            ));
        }
        let read_cstr = |ptr: *const std::os::raw::c_char, field: &str| -> Result<String> {
            if ptr.is_null() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("plugin manifest {field} is null"),
                ));
            }
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .map(str::to_string)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("plugin manifest {field} is not UTF-8"),
                    )
                })
        };
        let name = read_cstr(raw.name, "name")?;
        let version = read_cstr(raw.version, "version")?;
        let test_only = if struct_size >= PREFIX_THROUGH_VERSION + std::mem::size_of::<bool>() {
            raw.test_only
        } else {
            false
        };
        Ok(PluginManifest {
            abi_version: raw.abi_version,
            name,
            version,
            test_only,
        })
    }
}

// =====================================================================
// Wrapping plugin-produced Layer handles
// =====================================================================

/// Wrap a freshly-created plugin `LayerHandle` as a host `Layer`, pinning the
/// loaded [`HostPluginV2`] alive for the layer's lifetime and supplying the
/// plugin's advertised first kind as the `descriptor()` decode-failure
/// fallback (the pre-generalization behavior, pinned by the
/// `loaded_plugin_characterization` suite). The generic [`ForeignVtableLayer`]
/// does the vtable driving.
fn wrap_plugin_layer(
    plugin: Arc<HostPluginV2>,
    handle: ffi::LayerHandle,
) -> Result<Arc<ForeignVtableLayer>> {
    let fallback_plugin = Arc::clone(&plugin);
    let fallback: KindsFallback = Box::new(move || fallback_plugin.kinds().first().cloned());
    let keepalive: Arc<dyn std::any::Any + Send + Sync> = plugin;
    ForeignVtableLayer::from_handle_with_fallback(handle, Some(keepalive), Some(fallback))
}

// =====================================================================
// Borrowed-manifest kind-descriptor clone decoders (host-only): these
// copy out of the plugin-owned `PluginManifestV1.kinds` array without
// consuming it (`plugin_vtable.drop` frees the source), so they stay next
// to [`HostPluginV2`] rather than moving to `consume_v2` with the owned
// (host-frees) introspection decoders.
// =====================================================================

/// Copy a `Str` borrowed inside a caller-owned struct (the manifest the
/// plugin still owns) into an owned `String`, without freeing the source.
unsafe fn clone_str(value: &ffi::Str) -> Result<String> {
    Ok(unsafe { marshal::primitive::str_borrow(value)? }.to_string())
}

/// Borrow-clone an `Optional<Str>` field of a plugin-owned struct.
unsafe fn clone_opt_str(value: &ffi::Optional<ffi::Str>) -> Result<Option<String>> {
    Ok(if value.is_some() {
        Some(unsafe { clone_str(value.value.assume_init_ref())? })
    } else {
        None
    })
}

/// Borrow-clone every element of a plugin-owned `List<T>` without consuming
/// or freeing the source (the plugin still owns the allocation).
unsafe fn clone_list<T, U>(list: &ffi::List<T>, clone: impl Fn(&T) -> Result<U>) -> Result<Vec<U>> {
    unsafe { std::slice::from_raw_parts(list.ptr, list.len) }
        .iter()
        .map(clone)
        .collect()
}

/// Borrow-clone a manifest [`ffi::CredentialField`] the plugin still owns.
unsafe fn credential_field_clone_from_ffi(value: &ffi::CredentialField) -> Result<CredentialField> {
    Ok(CredentialField {
        key: unsafe { clone_str(&value.key)? },
        display_name: unsafe { clone_str(&value.display_name)? },
        default: unsafe { clone_opt_str(&value.default)? },
        help: unsafe { clone_opt_str(&value.help)? },
        advanced: value.advanced,
    })
}

/// Borrow-clone a manifest [`ffi::CredentialMethod`] the plugin still owns.
unsafe fn credential_method_clone_from_ffi(
    value: &ffi::CredentialMethod,
) -> Result<CredentialMethod> {
    Ok(CredentialMethod {
        key: unsafe { clone_str(&value.key)? },
        display_name: unsafe { clone_str(&value.display_name)? },
        fields: unsafe { clone_list(&value.fields, |s| clone_str(s))? },
        help: unsafe { clone_opt_str(&value.help)? },
        advanced: value.advanced,
    })
}

/// **Clone** a kind descriptor that the host only *borrows* — the manifest
/// `kinds` array, owned by the plugin and freed via `plugin_vtable.drop`.
/// Copies the identity fields AND the credential schema/method lists without
/// consuming the source. The credential lists are cloned faithfully so a
/// credentialed plugin is never misreported as anonymous. The
/// `config_schema` is still left empty (live via the `descriptor` slot on an
/// instantiated layer; hydrating it here is the remaining N4 follow-up).
unsafe fn layer_kind_descriptor_clone_from_ffi(
    value: &ffi::LayerKindDescriptor,
) -> Result<LayerKindDescriptor> {
    Ok(LayerKindDescriptor {
        kind: unsafe { clone_str(&value.kind)? },
        layer_type: ovstorage_plugin::thunks_v2::layer_type_from_ffi(value.layer_type),
        display_name: unsafe { clone_str(&value.display_name)? },
        description: if value.description.is_some() {
            Some(unsafe { clone_str(value.description.value.assume_init_ref())? })
        } else {
            None
        },
        config_schema: Vec::new(),
        credential_schema: unsafe {
            clone_list(&value.credential_schema, |f| {
                credential_field_clone_from_ffi(f)
            })?
        },
        credential_methods: unsafe {
            clone_list(&value.credential_methods, |m| {
                credential_method_clone_from_ffi(m)
            })?
        },
        icon: None,
        accepts_connections: value.accepts_connections,
        auth_capable: value.auth_capable,
        supports_user_metadata: value.supports_user_metadata,
    })
}

// =====================================================================
// Factory adapters (v2 PluginVTableV1.create_* -> Rust factory traits)
// =====================================================================

fn create_error_from(err: *mut ffi::Error, status: i32) -> Error {
    if !err.is_null() {
        return unsafe { marshal::error::from_ffi(ffi::abi_alloc::abi_unbox(err)) };
    }
    Error::new(
        ErrorCode::Internal,
        format!("v2 plugin create returned status {status} with no error"),
    )
}

fn config_to_ffi(config: &LayerConfig) -> ffi::List<ffi::ConnectionConfigEntry> {
    let entries: Vec<ffi::ConnectionConfigEntry> = config
        .iter()
        .map(|(key, value)| ffi::ConnectionConfigEntry {
            key: marshal::primitive::str_to_ffi(key.clone()),
            value: marshal::descriptor::config_value_to_ffi(value.clone()),
        })
        .collect();
    marshal::primitive::list_to_ffi(entries, |entry| entry)
}

/// Adapter exposing a v2 plugin's BACKEND kind as a `BackendFactory`.
pub(crate) struct LoadedV2BackendFactory {
    plugin: Arc<HostPluginV2>,
    descriptor: LayerKindDescriptor,
}

impl LoadedV2BackendFactory {
    pub(crate) fn new(plugin: Arc<HostPluginV2>, descriptor: LayerKindDescriptor) -> Self {
        Self { plugin, descriptor }
    }
}

#[async_trait::async_trait]
impl BackendFactory for LoadedV2BackendFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // The C `create_backend` is synchronous and a Rust v2 plugin
        // drives its async factory via `block_on` on the plugin runtime.
        // We are on the host runtime here, so run the FFI call on a
        // blocking thread (no runtime context) to avoid a nested-runtime
        // `block_on` panic. All raw pointers stay inside the closure.
        let plugin = Arc::clone(&self.plugin);
        let kind = self.descriptor.kind.clone();
        let instance_id = name.to_string();
        let config = config.clone();
        tokio::task::spawn_blocking(move || -> Result<LayerHandle> {
            let request = ffi::CreateBackendRequest {
                struct_size: std::mem::size_of::<ffi::CreateBackendRequest>(),
                extensions: std::ptr::null(),
                kind: marshal::primitive::str_to_ffi(kind),
                instance_id: marshal::primitive::str_to_ffi(instance_id),
                config: config_to_ffi(&config),
                _reserved: [std::ptr::null_mut(); 8],
            };
            let mut out = MaybeUninit::<ffi::LayerHandle>::uninit();
            let mut err: *mut ffi::Error = std::ptr::null_mut();
            let status = unsafe {
                (plugin.vtable().create_backend)(
                    plugin.plugin_state,
                    &request,
                    out.as_mut_ptr(),
                    &mut err,
                )
            };
            std::mem::forget(request);
            if status != ffi::FFI_STATUS_OK {
                return Err(create_error_from(err, status));
            }
            let layer = wrap_plugin_layer(Arc::clone(&plugin), unsafe { out.assume_init() })?;
            Ok(layer as LayerHandle)
        })
        .await
        .map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("create_backend task panicked: {e}"),
            )
        })?
    }
}

/// Adapter exposing a v2 plugin's WRAPPER kind as a `WrapperFactory`.
pub(crate) struct LoadedV2WrapperFactory {
    plugin: Arc<HostPluginV2>,
    descriptor: LayerKindDescriptor,
}

impl LoadedV2WrapperFactory {
    pub(crate) fn new(plugin: Arc<HostPluginV2>, descriptor: LayerKindDescriptor) -> Self {
        Self { plugin, descriptor }
    }
}

#[async_trait::async_trait]
impl WrapperFactory for LoadedV2WrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // Cross-binary composition: any child — host-native or
        // itself a loaded layer — crosses behind the host's vtable; the
        // plugin imports it as a foreign child. See `export_child`.
        let inner = export_child(inner);
        let request = ffi::CreateWrapperRequest {
            struct_size: std::mem::size_of::<ffi::CreateWrapperRequest>(),
            extensions: std::ptr::null(),
            inner,
            kind: marshal::primitive::str_to_ffi(self.descriptor.kind.clone()),
            instance_id: marshal::primitive::str_to_ffi(name.to_string()),
            config: config_to_ffi(config),
            _reserved: [std::ptr::null_mut(); 8],
        };
        let mut out = MaybeUninit::<ffi::LayerHandle>::uninit();
        let mut err: *mut ffi::Error = std::ptr::null_mut();
        let status = unsafe {
            (self.plugin.vtable().create_wrapper)(
                self.plugin.plugin_state,
                &request,
                out.as_mut_ptr(),
                &mut err,
            )
        };
        std::mem::forget(request);
        if status != ffi::FFI_STATUS_OK {
            return Err(create_error_from(err, status));
        }
        let layer = wrap_plugin_layer(Arc::clone(&self.plugin), unsafe { out.assume_init() })?;
        Ok(layer as LayerHandle)
    }
}

/// Adapter exposing a v2 plugin's ROUTER kind as a `RouterFactory`.
pub(crate) struct LoadedV2RouterFactory {
    plugin: Arc<HostPluginV2>,
    descriptor: LayerKindDescriptor,
}

impl LoadedV2RouterFactory {
    pub(crate) fn new(plugin: Arc<HostPluginV2>, descriptor: LayerKindDescriptor) -> Self {
        Self { plugin, descriptor }
    }
}

#[async_trait::async_trait]
impl RouterFactory for LoadedV2RouterFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    async fn create_router(
        &self,
        name: &str,
        config: &LayerConfig,
        children: Vec<LayerHandle>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let mut router_children = Vec::with_capacity(children.len());
        for child in children {
            router_children.push(ffi::RouterChild {
                handle: export_child(child),
                _reserved: [std::ptr::null_mut(); 8],
            });
        }
        // The plugin takes ownership of every child handle; the array's
        // backing allocation stays here (the ABI passes a bare pointer,
        // not an owning `List`) and is freed when `router_children` goes
        // out of scope.
        let router_children = marshal::factory::RouterChildArray::new(router_children);
        let request = ffi::CreateRouterRequest {
            struct_size: std::mem::size_of::<ffi::CreateRouterRequest>(),
            extensions: std::ptr::null(),
            kind: marshal::primitive::str_to_ffi(self.descriptor.kind.clone()),
            instance_id: marshal::primitive::str_to_ffi(name.to_string()),
            config: config_to_ffi(config),
            children: router_children.as_ptr(),
            child_count: router_children.len(),
            _reserved: [std::ptr::null_mut(); 8],
        };
        let mut out = MaybeUninit::<ffi::LayerHandle>::uninit();
        let mut err: *mut ffi::Error = std::ptr::null_mut();
        let status = unsafe {
            (self.plugin.vtable().create_router)(
                self.plugin.plugin_state,
                &request,
                out.as_mut_ptr(),
                &mut err,
            )
        };
        std::mem::forget(request);
        if status != ffi::FFI_STATUS_OK {
            return Err(create_error_from(err, status));
        }
        let layer = wrap_plugin_layer(Arc::clone(&self.plugin), unsafe { out.assume_init() })?;
        Ok(layer as LayerHandle)
    }
}

/// Project a host-side child Layer to a C `ffi::LayerHandle` so it can be
/// handed to a v2 plugin's `create_wrapper`/`create_router` as an
/// `inner`/child. `downcast_loaded_v2` cannot project a loaded child (it
/// refuses every loaded child with `Unsupported`), so every child — host-native
/// or itself a loaded `ForeignVtableLayer` — crosses behind the HOST's
/// `LAYER_VTABLE` via `export_handle`; the plugin side imports it as a
/// foreign child and wraps it in its own `ForeignVtableLayer`. A same-plugin
/// child therefore takes one extra bridge hop per boundary (re-export
/// double-bridges); a vtable identity probe to short-circuit that is a
/// possible future optimization, out of scope here.
fn export_child(child: LayerHandle) -> ffi::LayerHandle {
    export_handle(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Consumer-side codec helpers exercised directly by the codec/iterator
    // tests below (they moved to `consume_v2` with the `ForeignVtableLayer`
    // that drives them).
    use ovstorage_plugin::consume_v2::{
        ConnectionChangeIter, RootInfoChangeIter, bridge_update_stream, connection_change_from_ffi,
        layer_kind_descriptor_from_ffi, root_info_change_from_ffi,
    };

    #[test]
    fn manifest_below_the_layer_abi_floor_is_rejected() {
        let manifest = ffi::PluginManifestV1 {
            struct_size: std::mem::size_of::<ffi::PluginManifestV1>(),
            abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_FLOOR - 1,
            name: std::ptr::null(),
            version: std::ptr::null(),
            test_only: false,
        };

        let error = unsafe { read_v2_manifest(&manifest) }
            .expect_err("a pre-Layer ABI manifest must not reach init");
        assert_eq!(error.code(), ErrorCode::IncompatibleType);
    }

    /// Records every `plugin_state` a rejected vtable's `drop` slot
    /// reclaims, so tests can require the reclamation rather than assume it.
    static DROPPED_PLUGIN_STATES: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    unsafe extern "C" fn recording_drop(state: *mut core::ffi::c_void) {
        DROPPED_PLUGIN_STATES
            .lock()
            .expect("dropped plugin states")
            .push(state as usize);
    }

    fn plugin_vtable_at_version(abi_version: u32) -> ffi::PluginVTableV1 {
        let mut vtable = ovstorage_plugin::thunks_v2::plugin_vtable_template_for_test();
        vtable.abi_version = abi_version;
        vtable.drop = recording_drop;
        vtable
    }

    fn test_kind(kind: &str, layer_type: LayerType) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: kind.to_string(),
            layer_type,
            display_name: kind.to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: layer_type == LayerType::Backend,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    #[test]
    fn bundled_plugin_kinds_must_be_unique_even_across_layer_types() {
        let error = validate_unique_plugin_kinds(
            "duplicate-fixture",
            &[
                test_kind("same-kind", LayerType::Backend),
                test_kind("same-kind", LayerType::Wrapper),
            ],
        )
        .expect_err("duplicate advertised kinds must be rejected");

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .message()
                .contains("advertises Layer kind 'same-kind' more than once"),
            "{error}"
        );
    }

    /// A factory vtable from a stale ABI reports its own version, which the
    /// caller then refuses. Its marshalling mints values on a different
    /// allocator than this host releases them with, so calling into it is
    /// the heap-corruption path the ABI heap exists to close.
    #[test]
    fn stale_plugin_vtable_abi_version_is_reported() {
        let vtable = plugin_vtable_at_version(ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION - 1);
        let seen = unsafe { read_plugin_vtable_header(&vtable) }
            .expect("a well-sized header must still be readable");
        assert_ne!(seen, ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION);
    }

    /// The same exact-match rule catches an unknown-higher version rather
    /// than reading it under the current layout.
    #[test]
    fn unknown_higher_plugin_vtable_abi_version_is_reported() {
        let vtable = plugin_vtable_at_version(ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION + 1);
        let seen = unsafe { read_plugin_vtable_header(&vtable) }
            .expect("a well-sized header must still be readable");
        assert_ne!(seen, ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION);
    }

    #[test]
    fn current_plugin_vtable_abi_version_is_accepted() {
        let vtable = plugin_vtable_at_version(ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION);
        let seen = unsafe { read_plugin_vtable_header(&vtable) }
            .expect("the current factory vtable must be accepted");
        assert_eq!(seen, ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION);
    }

    /// A truncated vtable — one whose `struct_size` claims less than the
    /// current layout — must be rejected from its prefix alone, with the
    /// header read never touching a byte past what the producer supplied.
    ///
    /// The mapping puts the readable prefix flush against an unmapped guard
    /// page, so a read past it faults instead of quietly succeeding.
    ///
    /// What this does and does not establish. It catches a header read that
    /// *physically* spans the whole struct — copying the vtable by value,
    /// say — which is the failure that actually touches memory the producer
    /// never supplied. It cannot catch the narrower fault of merely forming
    /// a `&PluginVTableV1` over a short prefix: that is undefined because of
    /// the validity claim the reference makes, not because of a load, and
    /// the optimizer generally narrows the access to the field being used,
    /// so nothing reaches the guard page. Ruling that out needs a tool that
    /// models the abstract machine (Miri); this test is the runtime half.
    #[cfg(unix)]
    #[test]
    fn a_truncated_vtable_is_rejected_without_reading_past_its_prefix() {
        const PREFIX: usize = std::mem::size_of::<usize>();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap the probe region");
        assert_eq!(
            unsafe { libc::mprotect(base.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) },
            0,
            "arm the guard page"
        );

        // Land the prefix in the last `PREFIX` readable bytes, so the struct
        // "continues" into the guard page.
        let vtable = unsafe { base.cast::<u8>().add(page - PREFIX) }.cast::<ffi::PluginVTableV1>();
        // A producer claiming a struct smaller than this host's layout.
        unsafe { std::ptr::addr_of_mut!((*vtable).struct_size).write(PREFIX) };

        let error = unsafe { read_plugin_vtable_header(vtable) }
            .expect_err("a truncated PluginVTableV1 must be rejected");
        assert_eq!(error.code(), ErrorCode::IncompatibleType);
        assert!(error.message().contains("struct_size"), "{error}");

        assert_eq!(unsafe { libc::munmap(base, page * 2) }, 0, "unmap");
    }

    /// The same truncated-vtable rejection, with the prefix on the stack and
    /// no FFI, so it runs under Miri — which is what can actually rule out
    /// the reference-formation half the guard-page test cannot see. Under
    /// Miri, reading through the raw place projection is in bounds, while
    /// forming a `&PluginVTableV1` over this prefix is a hard error.
    #[test]
    fn a_truncated_vtable_prefix_is_read_within_bounds() {
        // Exactly the leading `usize` and nothing more.
        let prefix: usize = std::mem::size_of::<usize>();
        let vtable = (&prefix as *const usize).cast::<ffi::PluginVTableV1>();

        let error = unsafe { read_plugin_vtable_header(vtable) }
            .expect_err("a truncated PluginVTableV1 must be rejected");
        assert_eq!(error.code(), ErrorCode::IncompatibleType);
        assert!(error.message().contains("struct_size"), "{error}");
    }

    /// The mixed-component plugin, assembled end to end: a current manifest
    /// and init result over a stale factory vtable. Drives
    /// `HostPluginV2::from_parts` rather than the validator, so removing the
    /// validator's call site fails here — the tests above pin only that the
    /// rule is correct, not that anything applies it.
    #[cfg(unix)]
    #[test]
    fn assembling_a_plugin_over_a_stale_factory_vtable_is_rejected() {
        let vtable: &'static ffi::PluginVTableV1 = Box::leak(Box::new(plugin_vtable_at_version(
            ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION - 1,
        )));
        // Init already produced this, so the rejection path owes it a
        // `drop` call; the assertion below requires one.
        let plugin_state = Box::into_raw(Box::new(0u8)) as *mut core::ffi::c_void;

        let init = ffi::PluginInitResultV1 {
            struct_size: std::mem::size_of::<ffi::PluginInitResultV1>(),
            // Current, like the manifest below: only the factory vtable lags.
            abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
            plugin_state,
            plugin_vtable: vtable,
            kinds: std::ptr::null(),
            kind_count: 0,
        };
        let manifest = PluginManifest {
            abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
            name: "mixed-component-fixture".into(),
            version: "0.1.0".into(),
            test_only: true,
        };

        let refresh_dir = tempfile::tempdir().expect("refresh-lock dir");
        let provider = crate::loader::HostCallbacksProvider::new(
            Arc::new(
                crate::auth::SqliteSecretStore::open(refresh_dir.path()).expect("secret store"),
            ),
            Arc::new(crate::auth::AuthRefreshLock::open(refresh_dir.path()).expect("refresh lock")),
        );
        let (callbacks, state) =
            crate::loader::build_host_callbacks(provider, ffi::HostKindV1::Library);
        // A handle on this image: `from_parts` takes ownership of a library,
        // and no plugin cdylib is guaranteed present for a unit test.
        let library = libloading::Library::from(libloading::os::unix::Library::this());

        let error = HostPluginV2::from_parts(library, callbacks, state, manifest, init)
            .err()
            .expect("a stale factory vtable must not assemble into a loaded plugin");
        assert_eq!(error.code(), ErrorCode::IncompatibleType);
        assert_eq!(error.message(), PLUGIN_VTABLE_ABI_MISMATCH_MESSAGE);

        // Rejecting mid-load must still hand the plugin its state back:
        // init already allocated it (and the kinds array), and nothing else
        // is left to reclaim them once this returns without a `HostPluginV2`.
        assert!(
            DROPPED_PLUGIN_STATES
                .lock()
                .expect("dropped plugin states")
                .contains(&(plugin_state as usize)),
            "a rejected plugin must be reclaimed through its own drop slot"
        );

        // SAFETY: `recording_drop` only records, so this test still owns the
        // allocation it minted and releases it here.
        drop(unsafe { Box::from_raw(plugin_state as *mut u8) });
    }

    /// A backend kind's `supports_user_metadata` declaration must survive both
    /// ways a host reads a plugin manifest: the borrow-clone the loader takes of
    /// the plugin-owned manifest, and the owned decode. Either one substituting a
    /// constant would strip the attribution layer off every dynamically loaded
    /// backend at once, and the loader would report nothing — the graph builds,
    /// the writes succeed, and no `modified_by` is ever recorded.
    #[test]
    fn manifest_reads_carry_the_user_metadata_declaration() {
        for declared in [true, false] {
            let ffi_descriptor = ffi::LayerKindDescriptor {
                struct_size: std::mem::size_of::<ffi::LayerKindDescriptor>(),
                layer_type: ffi::LayerType::Backend,
                accepts_connections: true,
                auth_capable: false,
                supports_user_metadata: declared,
                kind: marshal::primitive::str_to_ffi("um-kind".to_string()),
                display_name: marshal::primitive::str_to_ffi("Kind".to_string()),
                description: ffi::Optional::none(),
                config_schema: marshal::primitive::list_to_ffi(
                    Vec::new(),
                    marshal::descriptor::config_field_to_ffi,
                ),
                credential_schema: marshal::primitive::list_to_ffi(
                    Vec::new(),
                    marshal::descriptor::credential_field_to_ffi,
                ),
                credential_methods: marshal::primitive::list_to_ffi(
                    Vec::new(),
                    marshal::descriptor::credential_method_to_ffi,
                ),
                icon: ffi::Optional::none(),
                _reserved: [std::ptr::null_mut(); 8],
            };

            let cloned = unsafe { layer_kind_descriptor_clone_from_ffi(&ffi_descriptor).unwrap() };
            assert_eq!(
                cloned.supports_user_metadata, declared,
                "the borrow-clone dropped the plugin's declaration"
            );
            let consumed = unsafe { layer_kind_descriptor_from_ffi(ffi_descriptor).unwrap() };
            assert_eq!(
                consumed.supports_user_metadata, declared,
                "the owned decode dropped the plugin's declaration"
            );
        }
    }

    /// The borrowed-manifest clone must carry the plugin's real credential
    /// schema/method lists rather than silently reporting a credentialed plugin
    /// as anonymous.
    #[test]
    fn manifest_clone_carries_credential_lists() {
        let ffi_descriptor = ffi::LayerKindDescriptor {
            struct_size: std::mem::size_of::<ffi::LayerKindDescriptor>(),
            layer_type: ffi::LayerType::Backend,
            accepts_connections: true,
            supports_user_metadata: true,
            kind: marshal::primitive::str_to_ffi("cred-kind".to_string()),
            display_name: marshal::primitive::str_to_ffi("Credentialed".to_string()),
            description: ffi::Optional::none(),
            config_schema: marshal::primitive::list_to_ffi(
                Vec::new(),
                marshal::descriptor::config_field_to_ffi,
            ),
            credential_schema: marshal::primitive::list_to_ffi(
                vec![CredentialField {
                    key: "token".into(),
                    display_name: "Token".into(),
                    default: None,
                    help: Some("an API token".into()),
                    advanced: false,
                }],
                marshal::descriptor::credential_field_to_ffi,
            ),
            credential_methods: marshal::primitive::list_to_ffi(
                vec![CredentialMethod {
                    key: "api-token".into(),
                    display_name: "API token".into(),
                    fields: vec!["token".into()],
                    help: None,
                    advanced: true,
                }],
                marshal::descriptor::credential_method_to_ffi,
            ),
            icon: ffi::Optional::none(),
            auth_capable: true,
            _reserved: [std::ptr::null_mut(); 8],
        };

        // Borrow-clone (what the loader does with the plugin-owned manifest).
        let cloned = unsafe { layer_kind_descriptor_clone_from_ffi(&ffi_descriptor).unwrap() };
        assert_eq!(cloned.kind, "cred-kind");
        assert!(cloned.auth_capable);
        assert_eq!(cloned.credential_schema.len(), 1);
        assert_eq!(cloned.credential_schema[0].key, "token");
        assert_eq!(
            cloned.credential_schema[0].help.as_deref(),
            Some("an API token")
        );
        assert_eq!(cloned.credential_methods.len(), 1);
        assert_eq!(
            cloned.credential_methods[0].fields,
            vec!["token".to_string()]
        );
        assert!(cloned.credential_methods[0].advanced);

        // The clone did not consume the source: the owned decoder still
        // round-trips the same lists (and frees the allocation).
        let consumed = unsafe { layer_kind_descriptor_from_ffi(ffi_descriptor).unwrap() };
        assert!(consumed.auth_capable);
        assert_eq!(consumed.credential_schema, cloned.credential_schema);
        assert_eq!(consumed.credential_methods, cloned.credential_methods);
    }

    fn sample_root(url: &str) -> RootInfo {
        RootInfo {
            root: Url::parse(url).unwrap(),
            display_name: Some("Sample".into()),
            layer_kind: "mini-v2".into(),
            connection_id: Some(ConnectionId("conn-1".into())),
            owning_target: None,
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::Native,
            source: RouteSource::ConnectionContributed {
                connection_id: ConnectionId("conn-1".into()),
            },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    fn sample_connection(id: &str, url: &str) -> Connection {
        Connection {
            id: ConnectionId(id.into()),
            backend_kind: "mini-v2".into(),
            display_name: "Sample".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: vec![Url::parse(url).unwrap()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    /// Every `RootInfoChange` tag must survive the FFI codec (plugin
    /// `thunks_v2::root_info_change_to_ffi` → host `root_info_change_from_ffi`),
    /// not just the `Added` arm the end-to-end bridge test drives.
    #[test]
    fn root_info_change_codec_round_trips_every_variant() {
        let roots = vec![sample_root("mini://a/"), sample_root("mini://b/")];
        for change in [
            RootInfoChange::Snapshot(roots.clone()),
            RootInfoChange::Added(roots.clone()),
            RootInfoChange::Removed(roots.clone()),
            RootInfoChange::Updated(roots),
        ] {
            let ffi = ovstorage_plugin::thunks_v2::root_info_change_to_ffi_for_test(change.clone());
            let decoded = unsafe { root_info_change_from_ffi(ffi) }.expect("decode root change");
            assert_eq!(decoded, change);
        }
    }

    /// Each `ConnectionChange` tag routes a different FFI field (`connection`
    /// for Added/Updated, `removed_id` for Removed, `connections` for Snapshot),
    /// so exercise every arm — the end-to-end bridge test drives only `Added`.
    #[test]
    fn connection_change_codec_round_trips_every_variant() {
        let conns = vec![
            sample_connection("c1", "mini://a/"),
            sample_connection("c2", "mini://b/"),
        ];
        for change in [
            ConnectionChange::Added(conns[0].clone()),
            ConnectionChange::Updated(conns[1].clone()),
            ConnectionChange::Removed {
                id: ConnectionId("c9".into()),
            },
            ConnectionChange::Snapshot(conns.clone()),
        ] {
            let ffi =
                ovstorage_plugin::thunks_v2::connection_change_to_ffi_for_test(change.clone());
            let decoded =
                unsafe { connection_change_from_ffi(ffi) }.expect("decode connection change");
            assert_eq!(decoded, change);
        }
    }

    unsafe extern "C" fn fake_root_next(
        state: *mut c_void,
        out_item: *mut ffi::RootInfoChange,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        let counter = unsafe { &mut *(state as *mut u32) };
        let step = *counter;
        *counter += 1;
        match step {
            0 => {
                let change = RootInfoChange::Added(vec![sample_root("mini://a/")]);
                unsafe {
                    std::ptr::write(
                        out_item,
                        ovstorage_plugin::thunks_v2::root_info_change_to_ffi_for_test(change),
                    );
                }
                ffi::StreamStep::Yielded
            }
            1 => {
                unsafe {
                    std::ptr::write(
                        out_error,
                        marshal::error::to_ffi(&Error::new(ErrorCode::Internal, "boom")),
                    );
                }
                ffi::StreamStep::Failed
            }
            _ => panic!("iterator polled the FFI stream after a terminal Failed frame"),
        }
    }

    unsafe extern "C" fn fake_root_drop(state: *mut c_void) {
        unsafe { drop(Box::from_raw(state as *mut u32)) };
    }

    /// The decode iterator must surface a `Yielded` frame, then map a `Failed`
    /// frame to `Err`, then latch: once terminal it returns `None` forever
    /// without touching the FFI `next_fn` again (the fake panics if re-polled).
    /// `ConnectionChangeIter` shares this machinery verbatim.
    #[test]
    fn root_info_change_iter_yields_then_latches_after_failed() {
        let counter = Box::into_raw(Box::new(0u32)) as *mut c_void;
        let stream = ffi::RootInfoChangeStream {
            state: counter,
            next_fn: fake_root_next,
            drop_fn: fake_root_drop,
        };
        let mut iter = RootInfoChangeIter {
            stream,
            done: false,
        };
        assert!(matches!(
            iter.next(),
            Some(Ok(RootInfoChange::Added(roots))) if roots.len() == 1
        ));
        assert!(matches!(iter.next(), Some(Err(_))));
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    /// Root update stream emitting `[Ok, TransientError, Ok, Ended]` — a
    /// recoverable error sandwiched between two yielded frames. Panics if
    /// polled past `Ended`.
    unsafe extern "C" fn fake_root_transient_next(
        state: *mut c_void,
        out_item: *mut ffi::RootInfoChange,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        let counter = unsafe { &mut *(state as *mut u32) };
        let step = *counter;
        *counter += 1;
        match step {
            0 | 2 => {
                let url = if step == 0 { "mini://a/" } else { "mini://b/" };
                let change = RootInfoChange::Added(vec![sample_root(url)]);
                unsafe {
                    std::ptr::write(
                        out_item,
                        ovstorage_plugin::thunks_v2::root_info_change_to_ffi_for_test(change),
                    );
                }
                ffi::StreamStep::Yielded
            }
            1 => {
                unsafe {
                    std::ptr::write(
                        out_error,
                        marshal::error::to_ffi(&Error::new(ErrorCode::Internal, "resync")),
                    );
                }
                ffi::StreamStep::TransientError
            }
            3 => ffi::StreamStep::Ended,
            _ => panic!("iterator polled the FFI stream after Ended"),
        }
    }

    /// Connection update stream mirroring [`fake_root_transient_next`].
    unsafe extern "C" fn fake_connection_transient_next(
        state: *mut c_void,
        out_item: *mut ffi::ConnectionChange,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        let counter = unsafe { &mut *(state as *mut u32) };
        let step = *counter;
        *counter += 1;
        match step {
            0 | 2 => {
                let (id, url) = if step == 0 {
                    ("c1", "mini://a/")
                } else {
                    ("c2", "mini://b/")
                };
                let change = ConnectionChange::Added(sample_connection(id, url));
                unsafe {
                    std::ptr::write(
                        out_item,
                        ovstorage_plugin::thunks_v2::connection_change_to_ffi_for_test(change),
                    );
                }
                ffi::StreamStep::Yielded
            }
            1 => {
                unsafe {
                    std::ptr::write(
                        out_error,
                        marshal::error::to_ffi(&Error::new(ErrorCode::Internal, "resync")),
                    );
                }
                ffi::StreamStep::TransientError
            }
            3 => ffi::StreamStep::Ended,
            _ => panic!("iterator polled the FFI stream after Ended"),
        }
    }

    /// A `TransientError` frame must surface as `Some(Err(_))` WITHOUT latching:
    /// the host iterator keeps pulling and yields the item that follows the
    /// error, ending only on `Ended`. This is the S_N1_1 fix — a recoverable
    /// update-stream error must not be mistaken for EOF. Covers both the
    /// root-info and connection change families across the plugin→host codec.
    #[test]
    fn root_info_change_iter_continues_after_transient_error() {
        let counter = Box::into_raw(Box::new(0u32)) as *mut c_void;
        let stream = ffi::RootInfoChangeStream {
            state: counter,
            next_fn: fake_root_transient_next,
            drop_fn: fake_root_drop,
        };
        let mut iter = RootInfoChangeIter {
            stream,
            done: false,
        };
        assert!(matches!(
            iter.next(),
            Some(Ok(RootInfoChange::Added(roots))) if roots[0].root.as_str() == "mini://a/"
        ));
        assert!(matches!(iter.next(), Some(Err(_))));
        // The error did NOT latch: the following item still comes through.
        assert!(matches!(
            iter.next(),
            Some(Ok(RootInfoChange::Added(roots))) if roots[0].root.as_str() == "mini://b/"
        ));
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn connection_change_iter_continues_after_transient_error() {
        let counter = Box::into_raw(Box::new(0u32)) as *mut c_void;
        let stream = ffi::ConnectionChangeStream {
            state: counter,
            next_fn: fake_connection_transient_next,
            drop_fn: fake_root_drop,
        };
        let mut iter = ConnectionChangeIter {
            stream,
            done: false,
        };
        assert!(matches!(
            iter.next(),
            Some(Ok(ConnectionChange::Added(conn))) if conn.id.0 == "c1"
        ));
        assert!(matches!(iter.next(), Some(Err(_))));
        assert!(matches!(
            iter.next(),
            Some(Ok(ConnectionChange::Added(conn))) if conn.id.0 == "c2"
        ));
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    /// A pull-iterator whose `next()` blocks (parks) forever until the test
    /// releases it — the plugin-`next_fn`-parks-until-emission case, without the
    /// FFI machinery (`bridge_update_stream` is generic over any iterator).
    struct ParkingIter {
        unblock: std::sync::mpsc::Receiver<()>,
        parked: std::sync::mpsc::Sender<()>,
        polled: bool,
    }

    impl Iterator for ParkingIter {
        type Item = Result<RootInfoChange>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.polled {
                return None;
            }
            self.polled = true;
            // Announce that we've reached the park point, then block until the
            // test unblocks us (mirrors a plugin `next_fn` parked awaiting the
            // next frame). After release, end the stream cleanly.
            let _ = self.parked.send(());
            let _ = self.unblock.recv();
            None
        }
    }

    /// Dropping a bridge stream whose thread is parked in the pull-iterator's
    /// `next()` must NOT block the dropper — the `JoinHandle` is discarded, so
    /// there is no join-on-drop deadlock. The parked thread is a documented,
    /// bounded leak until the plugin emits/tears down; here we release it after
    /// the drop so it exits cleanly. Regression guard for the parked-drop
    /// semantics (commit 7de1fd11).
    #[tokio::test]
    async fn bridge_stream_drop_while_thread_parked_does_not_hang() {
        use futures::StreamExt as _;
        let (unblock_tx, unblock_rx) = std::sync::mpsc::channel::<()>();
        let (parked_tx, parked_rx) = std::sync::mpsc::channel::<()>();
        let iter = ParkingIter {
            unblock: unblock_rx,
            parked: parked_tx,
            polled: false,
        };
        let mut stream = bridge_update_stream::<RootInfoChange, _>("test-park", iter);

        // First poll spawns the bridge thread, which parks in `next()`; the
        // stream stays Pending, so the bounded poll times out (expected).
        let poll = tokio::time::timeout(std::time::Duration::from_millis(200), stream.next()).await;
        assert!(
            poll.is_err(),
            "stream is Pending while the thread is parked"
        );
        // Confirm the bridge thread actually reached the park point.
        parked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("bridge thread must reach the parked pull");

        // Drop while parked: must return promptly, not join the parked thread.
        let dropped =
            tokio::time::timeout(std::time::Duration::from_secs(2), async { drop(stream) }).await;
        assert!(
            dropped.is_ok(),
            "dropping a parked bridge stream must not block the dropper"
        );

        // Release the parked thread so it unwinds cleanly instead of lingering.
        let _ = unblock_tx.send(());
    }
}
