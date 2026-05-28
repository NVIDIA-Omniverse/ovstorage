// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ovstorage::{Error, ErrorCode, Library, LibraryConfig, StateConfig, Storage};
use ovstorage_cache::{Cache, CacheConfig};

pub async fn bootstrap_library() -> ovstorage::Result<Arc<Library>> {
    let loaded = load_startup_config()?;
    ovstorage::init_auth_substrate(Some(&auth_state_root()?))?;
    let mut builder = Library::builder();
    if let Some(cache) = cache_from_loaded_or_env(loaded.state.as_ref())? {
        builder = builder.with_cache(cache);
    }
    let library = builder.open()?;
    unsafe {
        library.load_plugins_from_dir(None)?;
    }
    for conn in &loaded.connections {
        library
            .add_connection(conn.to_connection_request()?, None)
            .await?;
    }
    Ok(library)
}

fn load_startup_config() -> ovstorage::Result<LibraryConfig> {
    if std::env::var_os("OVSTORAGE_MCP_NO_CONFIG").is_some() {
        return Ok(LibraryConfig::default());
    }
    if let Some(path) = std::env::var_os("OVSTORAGE_CONFIG") {
        return LibraryConfig::from_toml_path(Path::new(&path));
    }
    Ok(LibraryConfig::from_default_path()?.unwrap_or_default())
}

fn auth_state_root() -> ovstorage::Result<PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-mcp-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        Error::new(
            ErrorCode::StateRootUnavailable,
            format!("failed to create MCP auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}

fn cache_from_loaded_or_env(state: Option<&StateConfig>) -> ovstorage::Result<Option<Cache>> {
    cache_config_resolved(state)?.map(Cache::open).transpose()
}

fn cache_config_resolved(state: Option<&StateConfig>) -> ovstorage::Result<Option<CacheConfig>> {
    let env_state = std::env::var_os("OVSTORAGE_STATE_ROOT").map(PathBuf::from);
    let env_cache = std::env::var_os("OVSTORAGE_CACHE_ROOT").map(PathBuf::from);
    let toml_state = state.and_then(|s| s.state_root.clone());
    let toml_cache = state.and_then(|s| s.cache_root.clone());
    match (env_state.or(toml_state), env_cache.or(toml_cache)) {
        (Some(state_root), Some(cache_root)) => Ok(Some(CacheConfig {
            state_root,
            cache_root,
        })),
        (None, None) => Ok(None),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "state_root and cache_root must be set together",
        )),
    }
}
