// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for `ovstorage_library_init` — exercised in its
//! own process so the in-crate lib-tests (which share a `Library`
//! constructed via `Library::builder()`) don't collide with the
//! once-per-process plugin-SPI substrate registration.
//!
//! The cdylib is loaded via `libloading`; this binary does not link
//! the Rust crate directly.

mod common;

use std::ffi::CString;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{
    ConnectionSlot, Error, InfoSlot, InitAuthSubstrateOptionsV1, LibraryInitOptionsV1, Loader,
    OvCredentialCallback, RESERVED_PADDING_ZERO, Status, StatusSlot,
};

fn workspace_plugin_dir() -> std::path::PathBuf {
    // Honor `CARGO_TARGET_DIR` by deriving the profile dir from the
    // build-script-captured cdylib path (which uses Cargo's active
    // `OUT_DIR`). A hard-coded `CARGO_MANIFEST_DIR/../../target/<profile>`
    // would miss the override and point at a non-existent dir.
    common::workspace_profile_dir()
}

#[test]
fn library_init_round_trip_through_file_plugin() {
    // `add_connection(backend_kind="file")` needs the file plugin's
    // cdylib in `OVSTORAGE_PLUGIN_DIR` (the workspace target dir).
    // Self-bootstrap so a bare `cargo test -p ovstorage-capi --test
    // library_init` from a clean checkout passes.
    common::ensure_cdylibs_built(&["ovstorage-capi", "ovstorage-plugin-file"]);
    let loader = Loader::load();

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ovstorage-capi-init-test-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();

    // SAFETY: cargo runs each integration test in its own process, so
    // env-var mutation here doesn't race other tests.
    unsafe { std::env::set_var("OVSTORAGE_PLUGIN_DIR", workspace_plugin_dir()) };

    unsafe {
        let mut error = Error::default();
        let mut library = ptr::null_mut();
        let init_options = LibraryInitOptionsV1 {
            struct_size: std::mem::size_of::<LibraryInitOptionsV1>(),
            runtime_threads: 0,
            interactive_auth_capability: -1,
            credential_cache_durability: 0,
            has_credential_callback: false,
            credential_callback: OvCredentialCallback::default(),
            credential_callback_name: ptr::null(),
            allow_test_plugins: true,
            _reserved: RESERVED_PADDING_ZERO,
        };
        assert_eq!(
            (loader.ovstorage_library_init)(&init_options, &mut library, &mut error),
            Status::Ok,
            "library_init should succeed"
        );
        assert!(!library.is_null());

        // Plugins are explicit post-init now. Load from the workspace dir
        // pointed at by OVSTORAGE_PLUGIN_DIR (set above).
        let load_slot = StatusSlot::new();
        (loader.ovstorage_library_load_plugins_from_dir)(
            library,
            ptr::null(),
            Some(common::status_cb),
            Arc::as_ptr(&load_slot) as *mut _,
        );
        let load_status = load_slot
            .wait(Duration::from_secs(5))
            .expect("load_plugins_from_dir completes");
        assert_eq!(
            load_status,
            Status::Ok,
            "load_plugins_from_dir should succeed"
        );

        // Register a file connection rooted at our temp dir through the
        // C ABI connection-request builders.
        let backend_kind = CString::new("file").unwrap();
        let request = (loader.ovstorage_connection_request_create)(backend_kind.as_ptr());
        assert!(!request.is_null(), "connection_request_create");

        let root_key = CString::new("root").unwrap();
        let root_value = CString::new(root.to_string_lossy().replace('\\', "/")).unwrap();
        let root_cv = (loader.ovstorage_config_value_create_string)(root_value.as_ptr());
        assert!(!root_cv.is_null(), "config_value_create_string");
        assert!(
            (loader.ovstorage_connection_request_add_config)(request, root_key.as_ptr(), root_cv),
            "add_config(root)"
        );
        (loader.ovstorage_connection_request_set_persist)(request, false);

        let conn_slot = ConnectionSlot::new();
        (loader.ovstorage_library_add_connection)(
            library,
            request,
            ptr::null(),
            Some(common::connection_cb),
            Arc::as_ptr(&conn_slot) as *mut _,
        );
        let conn_outcome = conn_slot
            .wait(Duration::from_secs(5))
            .expect("add_connection completes");
        assert_eq!(
            conn_outcome.status,
            Status::Ok,
            "add_connection should succeed"
        );
        if let Some(conn) = conn_outcome.connection {
            (loader.ovstorage_connection_destroy)(conn);
        }

        // Write + stat a file to prove the library_init-built runtime
        // drives end-to-end I/O.
        let file_address = CString::new(format!(
            "file:{}/probe.txt",
            root.to_string_lossy().replace('\\', "/")
        ))
        .unwrap();
        let payload = b"library_init works";
        let slot = InfoSlot::new();
        (loader.ovstorage_write)(
            library,
            file_address.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            ptr::null(),
            ptr::null(),
            Some(common::info_cb),
            Arc::as_ptr(&slot) as *mut _,
        );
        let outcome = slot.wait(Duration::from_secs(5)).expect("write completes");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "write through library_init runtime should succeed"
        );
        if let Some(info) = outcome.info {
            (loader.ovstorage_info_destroy)(info);
        }

        let slot = InfoSlot::new();
        (loader.ovstorage_stat)(
            library,
            file_address.as_ptr(),
            ptr::null(),
            ptr::null(),
            Some(common::info_cb),
            Arc::as_ptr(&slot) as *mut _,
        );
        let outcome = slot.wait(Duration::from_secs(5)).expect("stat completes");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "stat through library_init runtime should succeed"
        );
        let info = outcome.info.expect("stat info");
        assert_eq!((loader.ovstorage_info_size)(info), payload.len() as u64);
        (loader.ovstorage_info_destroy)(info);

        (loader.ovstorage_library_shutdown)(library);

        // Second init in the same process succeeds against the cached
        // auth substrate, even with different per-Library config. Prior
        // to the substrate cache the loader's `Arc::ptr_eq` check would
        // have rejected this with `Status::Unsupported`.
        let mut library2 = ptr::null_mut();
        let init_options2 = LibraryInitOptionsV1 {
            struct_size: std::mem::size_of::<LibraryInitOptionsV1>(),
            runtime_threads: 0,
            interactive_auth_capability: -1,
            credential_cache_durability: 1, // InMemoryOnly (vs Persistent above)
            has_credential_callback: false,
            credential_callback: OvCredentialCallback::default(),
            credential_callback_name: ptr::null(),
            allow_test_plugins: false, // also differs from the first init
            _reserved: RESERVED_PADDING_ZERO,
        };
        assert_eq!(
            (loader.ovstorage_library_init)(&init_options2, &mut library2, &mut error),
            Status::Ok,
            "second library_init in the same process should succeed"
        );
        assert!(!library2.is_null());
        (loader.ovstorage_library_shutdown)(library2);

        // Explicit init_auth_substrate with NULL options is also a no-op
        // since the substrate was already established by library_init.
        let mut error2 = Error::default();
        assert_eq!(
            (loader.ovstorage_init_auth_substrate)(ptr::null(), &mut error2),
            Status::Ok,
            "init_auth_substrate(NULL) after library_init should be a no-op"
        );

        // But explicit init_auth_substrate with a different auth_dir
        // returns Unsupported with a clear message.
        let other_dir = CString::new("/tmp/ovstorage-capi-init-test-alt").unwrap();
        let alt_options = InitAuthSubstrateOptionsV1 {
            struct_size: std::mem::size_of::<InitAuthSubstrateOptionsV1>(),
            auth_dir: other_dir.as_ptr(),
            _reserved: RESERVED_PADDING_ZERO,
        };
        assert_eq!(
            (loader.ovstorage_init_auth_substrate)(&alt_options, &mut error2),
            Status::Unsupported,
            "init_auth_substrate with a different auth_dir should fail"
        );
        (loader.ovstorage_error_clear)(&mut error2);

        (loader.ovstorage_error_clear)(&mut error);
    }
    std::fs::remove_dir_all(&root).ok();
}
