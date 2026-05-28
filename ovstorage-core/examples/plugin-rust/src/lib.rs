// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reference Rust plugin demonstrating the `ovstorage_plugin!` macro.
//!
//! Authors implement `shim::Factory` (and `shim::Backend`, omitted
//! here for brevity since the example never instantiates a backend),
//! then invoke the macro at module scope to emit the cdylib symbols a
//! host loader expects: `ovstorage_plugin_manifest_v1`,
//! `ovstorage_plugin_vtable_v1`, `ovstorage_plugin_init_v1`. The
//! factory's name/version are taken from this crate's `CARGO_PKG_NAME`
//! / `CARGO_PKG_VERSION` at macro-expansion time.

use ovstorage_plugin::shim::Factory;
use ovstorage_plugin::{
    AuthEventStream, BackendId, CancellationToken, Connection, ConnectionAuthState,
    ConnectionRequest, Error, ErrorCode, InteractiveAuthCapability, SecretBundle,
    StorageBackendKindDescriptor, ovstorage_plugin,
};

/// Trivial factory. `instantiate` always errors with `Unsupported`.
/// Real plugins implement these against a backing service.
#[derive(Default)]
struct ExampleFactory;

#[async_trait::async_trait]
impl Factory for ExampleFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "example-rust".into(),
            display_name: "Example Rust Plugin".into(),
            description: Some("Reference Rust plugin for ovstorage_plugin! macro".into()),
            config_schema: vec![],
            credential_schema: vec![],
            credential_methods: vec![],
            icon: None,
            supports_runtime_add: false,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        _cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::shim::BackendInstance, Error> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "example-rust factory does not instantiate a backend",
        ))
    }

    // `update_credentials`, `authenticate` use the trait's default
    // impls — `Ok(())` and a single-event `AuthEvent::Succeeded` stream
    // respectively. We override `authenticate` here only to silence
    // unused-import warnings for the imports we still want plugin
    // authors to see in the example.
    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream, Error> {
        // Demonstrate the auth event stream shape: emit a single
        // Succeeded event carrying the connection back unchanged.
        Ok(Box::new(std::iter::once(Ok(
            ovstorage_plugin::AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            },
        ))))
    }
}

// Reference all the imports plugin authors typically need so this
// example doubles as a copy/paste starting point. The unused ones
// are silenced via `_` use.
const _: fn() -> Option<BackendId> = || None;
const _: fn() -> Option<ConnectionAuthState> = || None;
const _: fn() -> Option<SecretBundle> = || None;

ovstorage_plugin!(ExampleFactory::default);
