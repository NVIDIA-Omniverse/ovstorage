// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for the `ovstorage_plugin!` macro.
//!
//! This test file is itself a "plugin": it invokes the macro at module
//! scope, which emits the same `#[no_mangle] pub static
//! ovstorage_plugin_manifest_v1` and `pub extern "C" fn
//! ovstorage_plugin_init_v1` symbols that a real cdylib plugin would.
//! The test then drives those symbols in-process to verify the macro
//! wires everything up correctly: manifest values, init result struct,
//! plugin_state pointer, factory_vtable typed to BackendFactoryVTableV1.
//!
//! The example crate at `examples/plugin-rust/` exercises the same
//! path end-to-end as a real cdylib; this test exists to give the
//! macro fast in-tree CI feedback without depending on a workspace
//! cdylib artifact.

use ovstorage_plugin::shim::Factory;
use ovstorage_plugin::{
    CancellationToken, ConnectionRequest, Error, ErrorCode, OVSTORAGE_PLUGIN_ABI_VERSION,
    StorageBackendKindDescriptor, ffi, ovstorage_plugin, shim,
};

#[derive(Default)]
struct MacroTestFactory;

#[async_trait::async_trait]
impl Factory for MacroTestFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "macro-test".into(),
            display_name: "Macro test factory".into(),
            description: None,
            config_schema: vec![],
            credential_schema: vec![],
            credential_methods: vec![],
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance, Error> {
        let _ = &cancel; // test plugin: synchronous, no work to interrupt.
        Err(Error::new(
            ErrorCode::Unsupported,
            "macro test factory does not instantiate a backend",
        ))
    }
}

ovstorage_plugin!(MacroTestFactory::default);

// The macro emitted `pub static ovstorage_plugin_manifest_v1`,
// `pub static ovstorage_plugin_vtable_v1`, and
// `pub extern "C" fn ovstorage_plugin_init_v1`. Inside this test
// binary we can name them directly without `extern "C"` blocks — they
// live at the test crate's root.

fn read_manifest_string(ptr: *const std::os::raw::c_char) -> String {
    // SAFETY: macro-emitted manifest strings are NUL-terminated and
    // live for the duration of the binary.
    unsafe { std::ffi::CStr::from_ptr(ptr).to_str().unwrap().to_owned() }
}

#[test]
fn macro_emits_valid_manifest_symbol() {
    let manifest = &ovstorage_plugin_manifest_v1;
    assert_eq!(
        manifest.struct_size,
        std::mem::size_of::<ffi::PluginManifestV1>(),
    );
    assert_eq!(manifest.abi_version, OVSTORAGE_PLUGIN_ABI_VERSION);
    // Name comes from CARGO_PKG_NAME of the crate the macro expands
    // in. Here that's `ovstorage-plugin` itself (since this test is
    // part of that crate).
    assert_eq!(read_manifest_string(manifest.name), "ovstorage-plugin");
    assert_eq!(
        read_manifest_string(manifest.version),
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn macro_emits_valid_init_function() {
    let host = Box::new(StubHost::new());
    let cb = stub_callbacks(&host);
    let init = unsafe { ovstorage_plugin_init_v1(&cb) };
    assert_eq!(
        init.struct_size,
        std::mem::size_of::<ffi::BackendPluginInitResultV1>(),
    );
    assert_eq!(init.abi_version, OVSTORAGE_PLUGIN_ABI_VERSION);
    assert!(!init.plugin_state.is_null());
    assert!(!init.factory_vtable.is_null());

    let factory_vtable = unsafe { &*init.factory_vtable };
    assert_eq!(
        factory_vtable.struct_size,
        std::mem::size_of::<ffi::BackendFactoryVTableV1>(),
    );

    // Drive `descriptor` through the vtable to confirm dispatch
    // reaches the user's `MacroTestFactory::descriptor` impl.
    let mut out = std::mem::MaybeUninit::<ffi::StorageBackendKindDescriptor>::uninit();
    let err = unsafe { (factory_vtable.descriptor)(init.plugin_state, out.as_mut_ptr()) };
    assert!(err.is_null(), "descriptor thunk returned an error");
    let ffi_descriptor = unsafe { out.assume_init() };
    let descriptor =
        unsafe { shim::descriptor::storage_backend_kind_descriptor_from_ffi(ffi_descriptor) }
            .unwrap();
    assert_eq!(descriptor.kind, "macro-test");

    // Tear down the factory state.
    unsafe { (factory_vtable.drop)(init.plugin_state) };
}

// Minimal stub host: no-op keyring/refresh callbacks. Used to feed
// `*const ffi::HostCallbacks` into `ovstorage_plugin_init_v1` so the
// plugin's `shim::register_host` stash points at something valid.
struct StubHost;

impl StubHost {
    fn new() -> Self {
        Self
    }
}

unsafe extern "C" fn stub_keyring_get(
    _state: *mut core::ffi::c_void,
    _key: *const ffi::KeyringKey,
    out_value: *mut ffi::Optional<ffi::SecretBytes>,
) -> *mut ffi::Error {
    unsafe {
        std::ptr::write(out_value, ffi::Optional::none());
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn stub_keyring_put(
    _state: *mut core::ffi::c_void,
    _key: *const ffi::KeyringKey,
    _value: *const ffi::SecretBytes,
) -> *mut ffi::Error {
    std::ptr::null_mut()
}

unsafe extern "C" fn stub_keyring_delete(
    _state: *mut core::ffi::c_void,
    _key: *const ffi::KeyringKey,
) -> *mut ffi::Error {
    std::ptr::null_mut()
}

unsafe extern "C" fn stub_auth_refresh(
    _state: *mut core::ffi::c_void,
    _backend_kind: *const ffi::Str,
    _connection_id: *const ffi::ConnectionId,
    _freshness_window_ms: u64,
    refresh_state: *mut core::ffi::c_void,
    refresh_fn: ffi::HostRefreshFn,
) -> *mut ffi::Error {
    unsafe { refresh_fn(refresh_state) }
}

unsafe extern "C" fn stub_log(
    _state: *mut core::ffi::c_void,
    _level: u8,
    _target: *const ffi::Str,
    _message: *const ffi::Str,
) {
}

#[allow(clippy::borrowed_box)]
fn stub_callbacks(host: &Box<StubHost>) -> ffi::HostCallbacks {
    ffi::HostCallbacks {
        struct_size: std::mem::size_of::<ffi::HostCallbacks>(),
        host_state: std::ptr::from_ref::<StubHost>(&**host) as *mut core::ffi::c_void,
        keyring_get: stub_keyring_get,
        keyring_put: stub_keyring_put,
        keyring_delete: stub_keyring_delete,
        auth_refresh_lock_with_refresh: stub_auth_refresh,
        host_kind: ffi::HostKindV1::Library as u32,
        log: stub_log,
    }
}
