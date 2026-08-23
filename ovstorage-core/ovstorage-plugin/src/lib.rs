// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod address;
pub mod cancel;
pub mod connection;
pub mod consume_v2;
pub mod ffi;
mod ffi_runtime;
pub mod log_layer;
pub mod marshal;
pub mod oauth_binding;
pub mod oauth_secret_store;
pub mod provider_error;
pub mod routing;
pub mod subscription;
pub mod thunks_v2;
pub mod trace;
mod types;
pub mod url_helpers;

pub use cancel::{CancelOnDrop, cancel_on_drop, race_cancel};
pub use ovstorage_plugin_macros::ovstorage_layer_plugin;
pub use routing::{RouteTable, fold_markers_and_infer_subdir_kinds, fresh_id, paginate_list_items};
// The cross-language live-handoff verbs are crate-root
// API; `ovstorage` re-exports them onward as its stable surface.
#[cfg(feature = "test-codec")]
pub use thunks_v2::import_handle_force_foreign;
pub use thunks_v2::{
    LayerExportExt, debug_assert_no_live_exports, export_handle, import_handle, live_export_count,
};
pub use trace::RedactedUrl;
pub use types::*;
pub use url_helpers::{extract_pinned_value, reject_pinned_for_mutation};

pub mod redact {
    pub use ovstorage_layer::redact::*;
}

// Migration aid: canonical home for these is `ffi::*`.
pub use ffi::PluginManifestV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginManifest {
    pub abi_version: u32,
    pub name: String,
    pub version: String,
    /// Test fixture marker. Production hosts refuse to load
    /// `test_only = true` plugins unless `allow_test_plugins` is
    /// set; older plugins missing this field default to `false`
    /// via the `struct_size` forward-compatibility check.
    pub test_only: bool,
}
