// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! RFC-0066: the shipped `ovstorage-cli.toml` template declares the
//! canonical CLI file-backend stack. It must parse through
//! `StackConfig::from_toml_str` and build a real (non-`EmptyLayer`) Stack from
//! the built-in `file` backend plus the plugin-provided public wrappers.

use ovstorage::StackConfig;

#[tokio::test]
async fn shipped_default_config_builds_nonempty_stack() {
    let cfg = StackConfig::from_toml_str(include_str!("../ovstorage-cli.toml"))
        .expect("shipped ovstorage-cli.toml must parse");
    assert_eq!(cfg.root.as_deref(), Some("alias"));
    assert!(
        !cfg.layers.is_empty(),
        "template must declare a layer graph"
    );

    ovstorage::init_auth_substrate(None).expect("initialize plugin auth substrate");
    let plugin_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-plugins");
    assert!(
        plugin_dir.is_dir(),
        "run `make build-test-plugins` before this test"
    );
    let factories = unsafe { ovstorage::load_layer_plugins_from_dir(&plugin_dir, true) }
        .expect("load the staged public Layer plugins");
    let stack = ovstorage::host::build_stack(&cfg, factories)
        .await
        .expect("shipped ovstorage-cli.toml must build_stack");

    // A real graph, not the `EmptyLayer` fallback (which roots at `empty`).
    assert_eq!(stack.spec().root, "alias");
    assert!(
        stack.spec().layers.len() > 1,
        "expected the full CLI graph, got {} layer(s)",
        stack.spec().layers.len()
    );
}
