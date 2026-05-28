// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for callers that pin a custom auth substrate
//! before creating a C ABI library handle. Runs in its own process so
//! the substrate-pin observed here does not race the
//! `library_init_round_trip_through_file_plugin` integration test.

mod common;

use std::ffi::CString;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{
    Error, InitAuthSubstrateOptionsV1, LibraryInitOptionsV1, Loader, OvCredentialCallback,
    RESERVED_PADDING_ZERO, Status,
};

#[test]
fn custom_init_auth_substrate_then_library_init_succeeds() {
    let loader = Loader::load();

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let auth_dir = std::env::temp_dir().join(format!(
        "ovstorage-capi-custom-auth-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&auth_dir).unwrap();
    let auth_dir_c = CString::new(auth_dir.to_string_lossy().into_owned()).unwrap();

    unsafe {
        let mut error = Error::default();
        let auth_options = InitAuthSubstrateOptionsV1 {
            struct_size: std::mem::size_of::<InitAuthSubstrateOptionsV1>(),
            auth_dir: auth_dir_c.as_ptr(),
            _reserved: RESERVED_PADDING_ZERO,
        };
        assert_eq!(
            (loader.ovstorage_init_auth_substrate)(&auth_options, &mut error),
            Status::Ok,
            "explicit custom auth substrate init should succeed"
        );

        let mut library = ptr::null_mut();
        let init_options = LibraryInitOptionsV1 {
            struct_size: std::mem::size_of::<LibraryInitOptionsV1>(),
            runtime_threads: 0,
            interactive_auth_capability: -1,
            credential_cache_durability: 0,
            has_credential_callback: false,
            credential_callback: OvCredentialCallback::default(),
            credential_callback_name: ptr::null(),
            allow_test_plugins: false,
            _reserved: RESERVED_PADDING_ZERO,
        };
        assert_eq!(
            (loader.ovstorage_library_init)(&init_options, &mut library, &mut error),
            Status::Ok,
            "library_init should accept the already-pinned custom auth dir"
        );
        assert!(!library.is_null());
        (loader.ovstorage_library_shutdown)(library);
        (loader.ovstorage_error_clear)(&mut error);
    }

    std::fs::remove_dir_all(auth_dir).ok();
}
