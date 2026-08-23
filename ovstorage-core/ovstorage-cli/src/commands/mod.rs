// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod cache;
pub mod connect;
pub mod directory;
pub mod doctor;
pub mod files;
pub mod repl;
pub mod util;
pub mod write_config;

#[cfg(test)]
pub(crate) fn test_layer_factories() -> Vec<ovstorage::LoadedLayerFactory> {
    use std::sync::Arc;

    vec![
        ovstorage::LoadedLayerFactory::Router(Arc::new(ovstorage_plugin_core::RouterFactoryImpl)),
        ovstorage::LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_core::AliasWrapperFactory::default(),
        )),
        ovstorage::LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_cache::ByteCacheWrapperFactory::default(),
        )),
    ]
}
