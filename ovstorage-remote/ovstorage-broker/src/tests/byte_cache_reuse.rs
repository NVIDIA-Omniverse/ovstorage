// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use crate::test_utils::ensure_test_plugin_env;

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ovstorage-broker-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn process_byte_cache_interns_cache_and_generation_registry() {
    let cache_root = unique_dir("cache");
    let state_root = unique_dir("state");
    let (first_cache, first_generations) =
        super::super::process_byte_cache(&cache_root, &state_root, None).unwrap();
    let (second_cache, second_generations) =
        super::super::process_byte_cache(&cache_root, &state_root, None).unwrap();

    assert!(Arc::ptr_eq(&first_cache, &second_cache));
    assert!(first_generations.shares_registry_with(&second_generations));
}

#[tokio::test]
async fn broker_rebuild_reuses_byte_cache_and_generation_registry() {
    ensure_test_plugin_env();
    let cache_root = unique_dir("reload-cache");
    let state_root = unique_dir("reload-state");
    let data_root = unique_dir("reload-data");
    let config = format!(
        r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "byte_cache"

[ovstorage.layers.byte_cache]
kind = "byte_cache"
inner = "redirect_follower"
cache_root = "{cache_root}"
state_root = "{state_root}"
partition = "local"

[ovstorage.layers.redirect_follower]
kind = "redirect_follower"
inner = "router"
follow_reads = false

[ovstorage.layers.router]
kind = "router"
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{data_root}"
"#,
        cache_root = cache_root.display(),
        state_root = state_root.display(),
        data_root = data_root.display(),
    );

    assert!(!super::super::byte_cache_is_interned(&cache_root));
    let first = super::super::build_broker_from_config_str(&config)
        .await
        .unwrap();
    assert!(first.health().is_ok());
    assert!(super::super::byte_cache_is_interned(&cache_root));
    let (first_cache, first_generations) =
        super::super::process_byte_cache(&cache_root, &state_root, None).unwrap();

    let second = super::super::build_broker_from_config_str(&config)
        .await
        .unwrap();
    assert!(second.health().is_ok());
    let (second_cache, second_generations) =
        super::super::process_byte_cache(&cache_root, &state_root, None).unwrap();

    assert!(Arc::ptr_eq(&first_cache, &second_cache));
    assert!(first_generations.shares_registry_with(&second_generations));
}
