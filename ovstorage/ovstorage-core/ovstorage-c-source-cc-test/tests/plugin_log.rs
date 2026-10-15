// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_int;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn ovstorage_c_source_plugin_log_contract(fixture_path: *const c_char) -> c_int;
}

#[cfg(ovstorage_cpp20)]
unsafe extern "C" {
    fn ovstorage_c_source_plugin_log_cpp20_contract() -> c_int;
}

#[test]
fn plugin_logs_are_filtered_and_routed_by_the_c_host() {
    let fixture = CString::new(env!("OVSTORAGE_C_SOURCE_PLUGIN_LOG_FIXTURE"))
        .expect("the generated plugin log fixture path has no interior NUL");
    // SAFETY: the path remains live for the call. The C driver restores its
    // process environment before returning, and this dedicated binary keeps
    // those mutations isolated from sibling integration-test processes.
    let status = unsafe { ovstorage_c_source_plugin_log_contract(fixture.as_ptr()) };
    assert_eq!(
        status, 0,
        "plugin log filtering and routing contract failed"
    );
    #[cfg(ovstorage_cpp20)]
    {
        // SAFETY: build.rs links this no-argument C++ adapter into this test
        // binary. It owns all state it creates and returns an integer status.
        let status = unsafe { ovstorage_c_source_plugin_log_cpp20_contract() };
        assert_eq!(status, 0, "the C++ plugin-log wrappers failed");
    }
}
