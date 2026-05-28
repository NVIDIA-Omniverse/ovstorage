// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression test for `ovstorage_plugin!` parsing of turbofish
//! constructor expressions. The macro splits its input on the first
//! top-level comma to separate the factory ctor from the optional
//! `test_only` flag. A naive `rsplit_once(',')` over the rendered
//! input string would split on the comma INSIDE
//! `Generic::<A, B>::default`, producing nonsense errors. The
//! token-tree-walking parser tracks angle-bracket depth so commas at
//! `angle_depth > 0` aren't candidate separators.
//!
//! If this test fails to COMPILE, the parser regressed.

use ovstorage_plugin::shim::Factory;
use ovstorage_plugin::{
    CancellationToken, ConnectionRequest, Error, ErrorCode, SecretBundle,
    StorageBackendKindDescriptor, ovstorage_plugin,
};

#[derive(Default)]
struct GenericFactory<_A, _B>(std::marker::PhantomData<(_A, _B)>);

#[async_trait::async_trait]
impl<_A: Send + Sync + 'static, _B: Send + Sync + 'static> Factory for GenericFactory<_A, _B> {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "macro-turbofish".into(),
            display_name: "Macro turbofish factory".into(),
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

ovstorage_plugin!(GenericFactory::<u8, u16>::default);

#[test]
fn macro_accepts_turbofish_factory_ctor() {
    let manifest = &ovstorage_plugin_manifest_v1;
    assert_eq!(
        manifest.struct_size,
        std::mem::size_of::<ovstorage_plugin::ffi::PluginManifestV1>(),
    );
}
