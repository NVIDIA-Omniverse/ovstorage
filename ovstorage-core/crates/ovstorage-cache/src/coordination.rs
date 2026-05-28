// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Coordination modes: HostExclusive (default), SharedSingleWriter
//! (one writer holds `<cache_root>/.writer` via O_EXCL), ReadOnly
//! (writes return Unsupported).

use std::fs::{File, OpenOptions};
use std::path::Path;

use ovstorage_plugin::{Error, ErrorCode, Result};

/// Coordination mode the cache runs under. Pinned at [`crate::Cache::open`] time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CacheCoordination {
    /// One host instance has exclusive ownership. Crash recovery
    /// reclaims aggressively; locks block on contention.
    #[default]
    HostExclusive,
    /// Multiple readers, one writer. The writer holds the
    /// `.writer` rendezvous file under `cache_root`; a second
    /// open-as-writer surfaces `ErrorCode::CacheLockContention`.
    SharedSingleWriter,
    /// All writes return `Unsupported`.
    ReadOnly,
}

/// Acquire the writer rendezvous file for `SharedSingleWriter`
/// mode. Opens with `O_EXCL`; an existing file is a contention error.
/// Drop the returned `File` to release.
pub fn acquire_writer_rendezvous(cache_root: &Path) -> Result<File> {
    let path = cache_root.join(".writer");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| {
            Error::new(
                ErrorCode::CacheLockContention,
                format!(
                    "writer rendezvous already held at {}: {error}",
                    path.display()
                ),
            )
        })
}

/// Release a `.writer` rendezvous file. Idempotent.
pub fn release_writer_rendezvous(cache_root: &Path) {
    let _ = std::fs::remove_file(cache_root.join(".writer"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_first_writer_succeeds_second_fails() {
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path();
        let _first = acquire_writer_rendezvous(cache_root).unwrap();
        let second = acquire_writer_rendezvous(cache_root);
        assert!(second.is_err());
        assert_eq!(second.unwrap_err().code(), ErrorCode::CacheLockContention);
    }

    #[test]
    fn rendezvous_release_lets_next_writer_in() {
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path();
        let first = acquire_writer_rendezvous(cache_root).unwrap();
        drop(first);
        release_writer_rendezvous(cache_root);
        let _second = acquire_writer_rendezvous(cache_root).unwrap();
    }

    #[test]
    fn coordination_default_is_host_exclusive() {
        assert_eq!(
            CacheCoordination::default(),
            CacheCoordination::HostExclusive
        );
    }
}
