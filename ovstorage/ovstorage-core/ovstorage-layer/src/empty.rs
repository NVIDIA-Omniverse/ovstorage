// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use async_trait::async_trait;

use crate::*;

/// The reserved layer kind/name of the [`EmptyLayer`] sentinel.
///
/// One source of truth for the `"empty"` string: `build_stack`'s empty-stack
/// fallback roots a Stack here, `LayerExt::list_backend_kinds` filters it out,
/// and `write-config` refuses to serialize a stack rooted at it. Never use a
/// bare `"empty"` literal for the sentinel — reference this const so the four
/// sites cannot drift.
pub const EMPTY_LAYER_KIND: &str = "empty";

/// Root of an otherwise-empty [`Stack`]: no `[ovstorage.layers]` configured
/// ⇒ every operation returns [`ErrorCode::Unsupported`].
///
/// `EmptyLayer` implements only `name`/`descriptor`; it leaves `inner_layer()`
/// at its `None` default, so every data-plane and connection method falls
/// through to the trait's `Err(unsupported(..))` default. `build_stack` roots a
/// rootless config here so a missing stack yields `Unsupported` uniformly with
/// zero host special-casing.
pub struct EmptyLayer;

#[async_trait]
impl Layer for EmptyLayer {
    fn name(&self) -> &str {
        EMPTY_LAYER_KIND
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: EMPTY_LAYER_KIND.to_string(),
            layer_type: LayerType::Backend,
            display_name: "Empty".to_string(),
            description: Some("no stack configured".to_string()),
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            // A placeholder for "no stack configured": every operation is the
            // trait's `Unsupported` default, so there is no write for a
            // user-metadata key to ride on.
            supports_user_metadata: false,
        }
    }
    // inner_layer() defaults to None -> all ops Unsupported.
}

/// [`BackendFactory`] for [`EmptyLayer`], registered under kind `"empty"`.
///
/// `build_stack` uses this to construct the one-layer empty Stack
/// (`Stack::builder("empty")` + `EmptyLayerFactory` + `LayerSpec::backend`).
pub struct EmptyLayerFactory;

#[async_trait]
impl BackendFactory for EmptyLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        EmptyLayer.descriptor()
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(EmptyLayer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn stat_request() -> Request<StatRequest> {
        Request::new(StatRequest {
            address: Url::parse("test://root/obj").unwrap(),
            options: StatOptions::default(),
        })
    }

    fn connection_request() -> Request<LayerConnectionRequest> {
        Request::new(LayerConnectionRequest {
            target: "empty".into(),
            connection: ConnectionRequest {
                backend_kind: "empty".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
    }

    #[tokio::test]
    async fn empty_layer_stat_is_unsupported() {
        let layer = EmptyLayer;
        assert_eq!(
            layer.stat(stat_request(), None).await.unwrap_err().code(),
            ErrorCode::Unsupported,
        );
    }

    #[tokio::test]
    async fn empty_layer_add_connection_is_unsupported() {
        let layer = EmptyLayer;
        assert_eq!(
            layer
                .add_connection(connection_request(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported,
        );
    }

    #[tokio::test]
    async fn empty_layer_factory_creates_unsupported_backend() {
        let factory = EmptyLayerFactory;
        assert_eq!(factory.descriptor().kind, "empty");
        let handle = factory
            .create_backend("empty", &LayerConfig::new(), None)
            .await
            .unwrap();
        assert_eq!(handle.name(), "empty");
        assert_eq!(
            handle.stat(stat_request(), None).await.unwrap_err().code(),
            ErrorCode::Unsupported,
        );
    }
}
