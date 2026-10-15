// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that the host loader can `dlopen` the example plugin
//! cdylib (`ovstorage-core/examples/plugin-rust/`, the plugin-author
//! reference), route it through the ABI-v2 loader, surface its
//! kind descriptor, and marshal a typed error back across the FFI when
//! the factory refuses to create a backend.
//!
//! The example plugin's path is wired in by `ovstorage/build.rs`
//! via the `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO` env var.

use ovstorage::{ErrorCode, LayerConfig, LayerType, LoadedLayerFactory};

const PLUGIN_PATH: &str = env!("OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO");

#[tokio::test]
async fn dlopen_example_plugin_loads_abi_v2_and_marshals_errors() {
    if PLUGIN_PATH == "__skip_docs_rs__" {
        eprintln!("skipping: docs.rs build does not produce a plugin .so");
        return;
    }
    ovstorage::init_auth_substrate(None).expect("init auth substrate");

    // SAFETY: integration test pointing at our own example plugin.
    let factories = unsafe { ovstorage::load_layer_plugin(PLUGIN_PATH, false) }
        .expect("example plugin must load through the ABI-v2 branch");
    assert_eq!(factories.len(), 1, "example plugin advertises one kind");

    let descriptor = factories[0].descriptor();
    assert_eq!(descriptor.kind, "example-rust");
    assert_eq!(descriptor.layer_type, LayerType::Backend);
    assert_eq!(descriptor.display_name, "Example Rust Plugin");
    assert!(!descriptor.accepts_connections);
    // The example is the copy source for out-of-tree plugins and creates no
    // backend, so it declares no user-metadata support. Pinned here because a
    // host reads this field to decide whether to compose an attribution layer
    // over the kind's branch, and nothing else in the tree reads the example's.
    assert!(!descriptor.supports_user_metadata);

    // Drive `create_backend` across the real FFI vtable: the example
    // factory refuses with a typed `Unsupported`, which must survive the
    // error-marshalling round trip (not degrade to `Internal`).
    let LoadedLayerFactory::Backend(backend) = &factories[0] else {
        panic!("example plugin must expose a backend-layer factory");
    };
    let error = match backend
        .create_backend("example", &LayerConfig::new(), None)
        .await
    {
        Ok(_) => panic!("the example factory must not create a backend"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::Unsupported, "got {error}");
}
