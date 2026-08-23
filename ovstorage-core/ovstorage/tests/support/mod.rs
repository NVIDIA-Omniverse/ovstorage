// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ovstorage::{LayerTable, LoadedLayerFactory, StackConfig};

/// Build a connection-free linear Stack graph ending at `backend_kind`.
pub(crate) fn linear_stack_config(backend_kind: &str, wrappers: &[&str]) -> StackConfig {
    let names: Vec<&str> = wrappers
        .iter()
        .copied()
        .chain(std::iter::once(backend_kind))
        .collect();
    let layers = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                (*name).to_string(),
                LayerTable {
                    kind: Some((*name).to_string()),
                    inner: names.get(index + 1).map(|inner| (*inner).to_string()),
                    ..LayerTable::default()
                },
            )
        })
        .collect::<HashMap<_, _>>();
    StackConfig {
        root: Some(names[0].to_string()),
        layers,
        connections: Vec::new(),
    }
}

/// Resolve another staged first-party plugin beside `plugin`.
#[allow(dead_code)] // This module is compiled separately for each integration test.
pub(crate) fn sibling_plugin(plugin: &Path, stem: &str) -> PathBuf {
    plugin.with_file_name(format!(
        "{}{stem}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ))
}

/// Load a test's backend plugin together with the plugin-provided wrappers its
/// stack graph names.
#[allow(dead_code)] // This module is compiled separately for each integration test.
pub(crate) fn load_plugins(paths: &[&Path]) -> Vec<LoadedLayerFactory> {
    paths
        .iter()
        .flat_map(|path| {
            // SAFETY: these paths name first-party plugins staged by the test
            // harness in one directory.
            unsafe { ovstorage::load_layer_plugin(path, true) }
                .unwrap_or_else(|error| panic!("load ABI-v2 plugin {}: {error}", path.display()))
        })
        .collect()
}
