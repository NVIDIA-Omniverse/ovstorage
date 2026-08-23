// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manifest-only cdylib pinned one version below the current Layer ABI.
//!
//! The host must reject this fixture before looking for the init symbol. It is
//! intentionally not a usable plugin. Its whole point is that the version it
//! advertises is the one *immediately* preceding
//! `OVSTORAGE_PLUGIN_ABI_V2_VERSION`, so it proves the exact-match manifest
//! check refuses even the most-recent stale ABI rather than only an ancient
//! one.
//!
//! That relationship is derived, not written down. A hand-maintained number
//! drifts silently on the next bump: the loader test asserts only that the
//! fixture is rejected, which stays true as the gap widens, so the fixture
//! would keep passing while no longer testing the case it is named for.

use std::os::raw::c_char;

#[repr(C)]
struct PluginManifestV1 {
    struct_size: usize,
    abi_version: u32,
    name: *const c_char,
    version: *const c_char,
    test_only: bool,
}

unsafe impl Sync for PluginManifestV1 {}

const RETIRED_LAYER_ABI_VERSION: u32 = ovstorage_plugin::ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION - 1;

// The fixture only means something while the version it advertises is still
// inside the v2 family: below the floor it would be rejected by the family
// check instead of the exact-match check it exists to exercise.
const _: () =
    assert!(RETIRED_LAYER_ABI_VERSION >= ovstorage_plugin::ffi::OVSTORAGE_PLUGIN_ABI_V2_FLOOR);

#[unsafe(no_mangle)]
static ovstorage_plugin_manifest_v1: PluginManifestV1 = PluginManifestV1 {
    struct_size: std::mem::size_of::<PluginManifestV1>(),
    abi_version: RETIRED_LAYER_ABI_VERSION,
    name: c"ovstorage-plugin-test-incompatible-abi".as_ptr(),
    version: c"0.1.0".as_ptr(),
    test_only: true,
};
