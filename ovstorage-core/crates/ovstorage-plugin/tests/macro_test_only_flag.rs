// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression test for `ovstorage_plugin!`'s `, test_only` flag
//! parsing. The token-tree parser must split the input at the
//! top-level comma between the factory ctor and the trailing
//! `test_only` ident.
//!
//! If this test fails to COMPILE, the parser regressed.

use ovstorage_plugin::shim::Factory;
use ovstorage_plugin::{
    CancellationToken, ConnectionRequest, Error, ErrorCode, SecretBundle,
    StorageBackendKindDescriptor, ovstorage_plugin,
};

#[derive(Default)]
struct TestOnlyFactory;

#[async_trait::async_trait]
impl Factory for TestOnlyFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "macro-test-only".into(),
            display_name: "Macro test-only factory".into(),
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
    ) -> Result<ovstorage_plugin::shim::BackendInstance, Error> {
        let _ = &cancel; // test plugin: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "regression test only"))
    }

    async fn update_credentials(
        &self,
        _connection: &ovstorage_plugin::Connection,
        _credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        let _ = &cancel; // test plugin: synchronous, no work to interrupt.
        Ok(())
    }

    async fn authenticate(
        &self,
        _connection: ovstorage_plugin::Connection,
        _capability: ovstorage_plugin::InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::AuthEventStream, Error> {
        let _ = &cancel; // test plugin: synchronous, no work to interrupt.
        Ok(Box::new(std::iter::empty()))
    }
}

ovstorage_plugin!(TestOnlyFactory::default, test_only);

#[test]
fn macro_accepts_test_only_flag_and_marks_manifest() {
    let manifest = &ovstorage_plugin_manifest_v1;
    assert!(
        manifest.test_only,
        "test_only flag must propagate into the manifest"
    );
}
