// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that the host loader can `dlopen` a real cdylib
//! plugin, bind its `BackendFactoryVTableV1`, and route descriptor +
//! probe + instantiate calls through the shim/ffi boundary.
//!
//! The example plugin's path is wired in by `crates/ovstorage/build.rs`
//! via the `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO` env var.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::Library;
use ovstorage::Storage as _;
use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage_plugin::{ConnectionRequest, ErrorCode, SecretBundle};

const PLUGIN_PATH: &str = env!("OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO");

fn auth_substrate() -> (Arc<SecretStore>, Arc<AuthRefreshLock>, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(SecretStore::new());
    let lock = Arc::new(AuthRefreshLock::open(temp.path()).expect("auth refresh lock state root"));
    (store, lock, temp)
}

#[tokio::test]
async fn dlopen_example_plugin_registers_descriptor_and_routes_instantiate() {
    if PLUGIN_PATH == "__skip_docs_rs__" {
        eprintln!("skipping: docs.rs build does not produce a plugin .so");
        return;
    }
    let (_store, _lock, state) = auth_substrate();
    let library = Library::open(Some(state.path())).expect("library open");
    // SAFETY: integration test pointing at our own example plugin.
    unsafe {
        library.load_plugin(PLUGIN_PATH).expect("load_plugin");
    }

    let kinds = library.list_backend_kinds().expect("list_backend_kinds");
    let example = kinds
        .iter()
        .find(|d| d.kind == "example-rust")
        .expect("example-rust factory should be registered");
    assert_eq!(example.display_name, "Example Rust Plugin");
    assert!(!example.supports_runtime_add);

    // The example plugin's `instantiate` returns `Unsupported`. Driving
    // `add_connection` exercises the full descriptor + probe + instantiate
    // round-trip through the FFI vtable, including the `*mut Error`
    // heap-reclamation path (probe runs first and returns a single
    // address; instantiate is the call that actually errors).
    let request = ConnectionRequest {
        backend_kind: "example-rust".into(),
        config: HashMap::new(),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let error = library
        .add_connection(request, None)
        .await
        .expect_err("instantiate is Unsupported");
    assert_eq!(error.code(), ErrorCode::Unsupported);
}
