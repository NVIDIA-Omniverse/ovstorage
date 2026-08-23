// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guard against doc rot: every `[ovstorage]` config example that appears in
//! `docs/public/**` must parse via [`StackConfig::from_toml_str`], and every
//! complete example composed from the built-in backend and public utility
//! Layer implementations must also survive [`build_stack`].
//!
//! Unlike a hand-copied constant, this test binds to the **actual** markdown:
//! it `include_str!`s the doc files (so the paths are checked at compile time)
//! and extracts their fenced ```toml blocks. Editing a doc example into an
//! invalid form now fails this test instead of silently drifting from a stale
//! inline copy.

use ovstorage::host::build_stack;
use std::sync::Arc;

use ovstorage::{LayerTable, LoadedLayerFactory, StackConfig};

const BUILDABLE_KINDS: &[&str] = &[
    "file",
    "http",
    "router",
    "alias",
    "copy_rename_fallback",
    "retry",
    "redirect_follower",
    "byte_cache",
    "metadata_cache",
];

fn public_layer_factories() -> Vec<LoadedLayerFactory> {
    vec![
        LoadedLayerFactory::Router(Arc::new(ovstorage_plugin_core::RouterFactoryImpl)),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_core::AliasWrapperFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_core::CopyRenameFallbackWrapperFactory,
        )),
        LoadedLayerFactory::Wrapper(Arc::new(ovstorage_plugin_core::RetryWrapperFactory)),
        LoadedLayerFactory::Backend(Arc::new(
            ovstorage_plugin_http::HttpBackendLayerFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_http::RedirectFollowerWrapperFactory,
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_cache::ByteCacheWrapperFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_cache::MetadataCacheWrapperFactory::default(),
        )),
    ]
}

/// Every markdown doc that carries an `[ovstorage]` config example. Bound at
/// compile time so a moved/renamed doc breaks the build rather than silently
/// dropping coverage.
const DOC_SOURCES: &[(&str, &str)] = &[
    (
        "docs/public/configuration.md",
        include_str!("../../../docs/public/configuration.md"),
    ),
    (
        "docs/public/library-web/README.md",
        include_str!("../../../docs/public/library-web/README.md"),
    ),
    (
        "docs/public/plugin-storage/plugin-http.md",
        include_str!("../../../docs/public/plugin-storage/plugin-http.md"),
    ),
    (
        "docs/public/broker-operator/README.md",
        include_str!("../../../docs/public/broker-operator/README.md"),
    ),
];

/// Extract the bodies of every ```toml fenced block in a markdown document.
fn toml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match current {
            None => {
                if line.trim_start().starts_with("```toml") {
                    current = Some(String::new());
                }
            }
            Some(ref mut body) => {
                if line.trim_start().starts_with("```") {
                    blocks.push(current.take().unwrap());
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    blocks
}

/// Is `block` an ovstorage example (as opposed to a host-only `[server.oidc]`
/// snippet)? Keyed on the literal table prefix so a comment mentioning
/// `ovstorage` doesn't count.
fn declares_ovstorage(block: &str) -> bool {
    block.lines().map(str::trim_start).any(|l| {
        l.starts_with("[ovstorage]")
            || l.starts_with("[ovstorage.")
            || l.starts_with("[[ovstorage.")
    })
}

/// A parsed doc example is a complete, file-only stack iff it has a root, at
/// least one layer, and every referenced kind is `file` (so `build_stack` can
/// compose it without any plugin factory).
fn is_buildable_stack(cfg: &StackConfig) -> bool {
    if cfg.root.is_none() || cfg.layers.is_empty() {
        return false;
    }
    let layer_kind =
        |name: &String, table: &LayerTable| table.kind.clone().unwrap_or_else(|| name.clone());
    let layers_ok = cfg
        .layers
        .iter()
        .all(|(name, table)| BUILDABLE_KINDS.contains(&layer_kind(name, table).as_str()));
    let connections_ok = cfg
        .connections
        .iter()
        .all(|conn| BUILDABLE_KINDS.contains(&conn.backend_kind.as_str()));
    layers_ok && connections_ok
}

#[test]
fn all_doc_ovstorage_examples_parse() {
    let mut examined = 0;
    for (file, markdown) in DOC_SOURCES {
        for (i, block) in toml_blocks(markdown).into_iter().enumerate() {
            if !declares_ovstorage(&block) {
                continue;
            }
            examined += 1;
            StackConfig::from_toml_str(&block).unwrap_or_else(|e| {
                panic!("{file} toml block #{i} failed to parse: {e:?}\n{block}")
            });
        }
    }
    assert!(
        examined >= 5,
        "expected to find the documented [ovstorage] examples; found {examined} \
         (did the doc structure or fenced-block extraction change?)"
    );
}

#[tokio::test]
async fn complete_doc_examples_build() {
    let mut built = 0;
    for (file, markdown) in DOC_SOURCES {
        for (i, block) in toml_blocks(markdown).into_iter().enumerate() {
            if !declares_ovstorage(&block) {
                continue;
            }
            let cfg = match StackConfig::from_toml_str(&block) {
                Ok(cfg) => cfg,
                Err(_) => continue, // parse failures are reported by the parse test
            };
            if !is_buildable_stack(&cfg) {
                continue; // fragment or a stack using an unavailable backend
            }
            build_stack(&cfg, public_layer_factories())
                .await
                .unwrap_or_else(|e| {
                    panic!("{file} toml block #{i} failed to build: {e:?}\n{block}")
                });
            built += 1;
        }
    }
    assert!(
        built >= 2,
        "expected both complete public Layer examples to build; built {built}"
    );
}
