// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::commands::util::cache_from_loaded_or_env;
use crate::session::SessionState;

pub(crate) fn cache_status(state: &SessionState) -> ovstorage::Result<()> {
    let Some(cache) = cache_from_loaded_or_env(state.state_config.as_ref())? else {
        println!("cache=disabled");
        return Ok(());
    };
    let status = cache.status()?;
    println!("cache=enabled");
    println!("cache_root={}", status.cache_root.display());
    println!("entries={}", status.entries);
    println!("total_bytes={}", status.total_bytes);
    println!(
        "max_bytes={}",
        status
            .max_bytes
            .map_or("none".into(), |value| value.to_string())
    );
    println!("staging_files={}", status.staging_files);
    Ok(())
}

/// Dry-run the cache crash-recovery sweep and print counts.
pub(crate) fn cache_doctor(state: &SessionState) -> ovstorage::Result<()> {
    let Some(cache) = cache_from_loaded_or_env(state.state_config.as_ref())? else {
        println!("cache=disabled");
        return Ok(());
    };
    let outcome = cache.doctor()?;
    println!("cache=enabled");
    println!("rows_examined={}", outcome.rows_examined);
    println!("rows_reaped={}", outcome.rows_reaped);
    println!("missing_cas_removed={}", outcome.missing_cas_removed);
    println!("quarantined={}", outcome.quarantined);
    Ok(())
}

/// Drive the cache GC pass on demand (the same eviction sweep `put`
/// triggers internally).
pub(crate) fn cache_gc(state: &SessionState) -> ovstorage::Result<()> {
    let Some(cache) = cache_from_loaded_or_env(state.state_config.as_ref())? else {
        println!("cache=disabled");
        return Ok(());
    };
    cache.gc()?;
    let status = cache.status()?;
    println!("cache=enabled");
    println!("entries_after={}", status.entries);
    println!("total_bytes_after={}", status.total_bytes);
    Ok(())
}

/// Detailed cache stats: bytes-by-state, live process leases, max-bytes.
pub(crate) fn cache_stats(state: &SessionState) -> ovstorage::Result<()> {
    let Some(cache) = cache_from_loaded_or_env(state.state_config.as_ref())? else {
        println!("cache=disabled");
        return Ok(());
    };
    let status = cache.status()?;
    println!("cache=enabled");
    println!("cache_root={}", status.cache_root.display());
    println!("state_root={}", status.state_root.display());
    println!("entries={}", status.entries);
    println!("total_bytes={}", status.total_bytes);
    println!(
        "max_bytes={}",
        status
            .max_bytes
            .map_or("unbounded".into(), |value| value.to_string())
    );
    println!("staging_files={}", status.staging_files);
    println!("live_process_leases={}", status.live_process_leases);
    Ok(())
}

pub(crate) fn state_status(state: &SessionState) -> ovstorage::Result<()> {
    let Some(cache) = cache_from_loaded_or_env(state.state_config.as_ref())? else {
        println!("state=disabled");
        return Ok(());
    };
    let status = cache.status()?;
    println!("state=enabled");
    println!("state_root={}", status.state_root.display());
    println!("live_process_leases={}", status.live_process_leases);
    println!("entries={}", status.entries);
    Ok(())
}
