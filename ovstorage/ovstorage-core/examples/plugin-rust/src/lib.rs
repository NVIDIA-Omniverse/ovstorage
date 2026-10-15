// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reference Rust plugin demonstrating the `ovstorage_layer_plugin!` macro.
//!
//! Authors implement a factory trait matching their layer type —
//! [`BackendFactory`] here (plus a `Layer`, omitted for brevity since this
//! example never creates one; see `ovstorage-core/ovstorage-plugin-test-layer`
//! for a minimal working backend Layer) — then invoke the macro at module
//! scope to emit the cdylib symbols the host loader expects:
//! `ovstorage_plugin_manifest_v1` and `ovstorage_plugin_init_v1`. Those frozen
//! symbol names carry the current Layer ABI selected by the manifest's
//! `abi_version`. The plugin's
//! name/version are taken from this crate's `CARGO_PKG_NAME` /
//! `CARGO_PKG_VERSION` at macro-expansion time.

use async_trait::async_trait;
use ovstorage_plugin::{
    BackendFactory, CancellationToken, Error, ErrorCode, LayerConfig, LayerHandle,
    LayerKindDescriptor, LayerType, Result, ovstorage_layer_plugin,
};

/// Trivial factory. `create_backend` always errors with `Unsupported`.
/// Real plugins return an `Arc`'d `Layer` implementation bound to the
/// instance config (root URL, endpoint, credentials schema, …).
#[derive(Default)]
struct ExampleFactory;

#[async_trait]
impl BackendFactory for ExampleFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "example-rust".into(),
            layer_type: LayerType::Backend,
            display_name: "Example Rust Plugin".into(),
            description: Some("Reference Rust plugin for the ovstorage_layer_plugin! macro".into()),
            config_schema: vec![],
            credential_schema: vec![],
            credential_methods: vec![],
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            // This example creates no backend, so no write's `user_metadata`
            // survives it and there is nothing to declare support for. A real
            // plugin answers for its own write paths: declaring support is what
            // lets an attributing host compose its attribution layer over this
            // kind's branch and, under the default `user_metadata` strategy,
            // stamp a reserved key into the writes that reach it.
            supports_user_metadata: false,
        }
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "example-rust factory does not create a backend layer",
        ))
    }
}

ovstorage_layer_plugin!(backend, ExampleFactory::default);
