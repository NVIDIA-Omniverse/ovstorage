// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The host's built-in Layer registry.
//!
//! Every public Layer except `file` is supplied by an ABI-v2 plugin. Keeping
//! this registry intentionally small gives the Rust, Python, and C/C++ hosts
//! the same baseline.

use std::sync::Arc;

use crate::*;

pub use crate::file::FileBackendFactory;

pub const FILE_BACKEND_KIND: &str = "file";
pub const ROUTER_KIND: &str = "router";
pub const COPY_RENAME_FALLBACK_KIND: &str = "copy_rename_fallback";
pub const ALIAS_KIND: &str = "alias";
pub const BROKER_AUTHZ_LAYER_NAME: &str = "authz";
pub const METADATA_CACHE_KIND: &str = "metadata_cache";
pub const BYTE_CACHE_KIND: &str = "byte_cache";
pub const RETRY_KIND: &str = "retry";
pub const REDIRECT_FOLLOWER_KIND: &str = "redirect_follower";

pub const ALIAS_TO_METADATA_KEY: &str = "org.omniverse.ovstorage/alias-to";
pub const ALIAS_VISIBILITY_METADATA_KEY: &str = "org.omniverse.ovstorage/alias-visibility";

/// The factories available without loading a plugin.
pub fn default_layer_factories() -> Vec<LoadedLayerFactory> {
    vec![LoadedLayerFactory::Backend(Arc::new(FileBackendFactory))]
}

/// Register the host's plugin-free factory set.
pub fn register_default_layer_factories(builder: StackBuilder) -> StackBuilder {
    builder.backend_factory(Arc::new(FileBackendFactory))
}

pub(crate) fn descriptor(
    kind: impl Into<String>,
    layer_type: LayerType,
    accepts_connections: bool,
    supports_user_metadata: bool,
) -> LayerKindDescriptor {
    let kind = kind.into();
    LayerKindDescriptor {
        display_name: kind.clone(),
        kind,
        layer_type,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections,
        auth_capable: false,
        supports_user_metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_free_registry_contains_exactly_file() {
        let descriptors = default_layer_factories()
            .into_iter()
            .map(|factory| factory.descriptor())
            .collect::<Vec<_>>();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].kind, FILE_BACKEND_KIND);
        assert_eq!(descriptors[0].layer_type, LayerType::Backend);
    }

    /// The built-in backend's `supports_user_metadata` declaration. A host reads
    /// it to decide whether to compose an attribution layer over the `file`
    /// branch, and this is the only backend in the plugin-free registry, so
    /// nothing else pins it.
    #[test]
    fn the_file_backend_declares_its_user_metadata_support() {
        let descriptor = default_layer_factories()[0].descriptor();
        assert!(
            descriptor.supports_user_metadata,
            "the file backend persists user metadata in a sidecar and returns it \
             on stat, so a host composes its attribution layer over that branch"
        );
    }
}
