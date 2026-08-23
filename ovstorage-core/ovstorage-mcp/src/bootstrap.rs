// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ovstorage::{Stack, StackConfig};

pub async fn bootstrap_stack() -> ovstorage::Result<Arc<Stack>> {
    let config = load_startup_config()?;
    ovstorage::init_auth_substrate(Some(&auth_state_root()))?;

    // SAFETY: dlopen runs platform loader hooks; the user/operator controls
    // `OVSTORAGE_PLUGIN_DIR` and the binary's install dir.
    let factories = match ovstorage::default_plugin_dir() {
        Some(dir) => unsafe { ovstorage::load_layer_plugins_from_dir(&dir, false)? },
        None => Vec::new(),
    };
    ovstorage::host::build_stack(&config, factories).await
}

fn load_startup_config() -> ovstorage::Result<StackConfig> {
    if std::env::var_os("OVSTORAGE_MCP_NO_CONFIG").is_some() {
        return Ok(StackConfig::default());
    }
    if let Some(path) = std::env::var_os("OVSTORAGE_CONFIG") {
        return StackConfig::from_toml_path(Path::new(&path));
    }
    Ok(StackConfig::from_default_path()?.unwrap_or_default())
}

fn auth_state_root() -> PathBuf {
    ovstorage::auth::default_state_root()
}
