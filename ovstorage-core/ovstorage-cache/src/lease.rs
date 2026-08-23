// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! RAII lease + process sentinel. A `Lease` pins CAS bytes against
//! eviction; drop releases. The process-wide sentinel
//! (`<state_root>/processes/<pid>.lock`, flock'd) lets crash-recovery
//! distinguish dead-PID leases from live ones.

use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Process-wide sentinel cloned into every emitted [`Lease`]. When the
/// last `Arc<CacheProcess>` drops, the inner Drop releases the flock
/// and unlinks the on-disk lock file so a re-open by the same PID
/// doesn't see ghost leases.
#[derive(Debug)]
pub struct CacheProcess {
    pub pid: u32,
    pub started_unix_ms: i64,
    sentinel: Mutex<Option<SentinelFile>>,
}

#[derive(Debug)]
struct SentinelFile {
    file: File,
    path: PathBuf,
}

impl CacheProcess {
    pub fn new(pid: u32, started_unix_ms: i64) -> Arc<Self> {
        Arc::new(Self {
            pid,
            started_unix_ms,
            sentinel: Mutex::new(None),
        })
    }

    pub fn with_sentinel(
        pid: u32,
        started_unix_ms: i64,
        sentinel_file: File,
        sentinel_path: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            pid,
            started_unix_ms,
            sentinel: Mutex::new(Some(SentinelFile {
                file: sentinel_file,
                path: sentinel_path,
            })),
        })
    }
}

impl Drop for CacheProcess {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.sentinel.lock()
            && let Some(sentinel) = slot.take()
        {
            let _ = sentinel.file.unlock();
            drop(sentinel.file);
            let _ = std::fs::remove_file(&sentinel.path);
        }
    }
}

/// One CAS-bytes lease held by the running process. Eviction skips
/// rows with `lease_count > 0` whose `CacheProcess` is still alive.
/// Drop runs `cleanup` exactly once to decrement `lease_count` and
/// reclaim the row when both pin and lease counts reach zero.
pub struct Lease {
    pub cas_key: String,
    pub row_id: Option<i64>,
    /// Cloned from the cache so the lease's lifetime extends the
    /// process sentinel for the lease's duration.
    pub process: Arc<CacheProcess>,
    cleanup: Mutex<Option<LeaseCleanup>>,
}

type LeaseCleanup = Box<dyn FnOnce(&Lease) + Send + 'static>;

impl Lease {
    /// Construct a lease. The `cleanup` closure runs exactly once on drop.
    pub fn new(
        cas_key: String,
        row_id: Option<i64>,
        process: Arc<CacheProcess>,
        cleanup: impl FnOnce(&Lease) + Send + 'static,
    ) -> Self {
        Self {
            cas_key,
            row_id,
            process,
            cleanup: Mutex::new(Some(Box::new(cleanup))),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Poisoned mutex skips cleanup rather than risk running it twice.
        if let Ok(mut slot) = self.cleanup.lock()
            && let Some(cleanup) = slot.take()
        {
            cleanup(self);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn lease_drop_runs_cleanup_exactly_once() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_lease = counter.clone();
        let process = CacheProcess::new(1, 0);
        let lease = Lease::new("deadbeef".into(), Some(7), process, move |l| {
            assert_eq!(l.cas_key, "deadbeef");
            assert_eq!(l.row_id, Some(7));
            counter_for_lease.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        drop(lease);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lease_extends_process_lifetime_until_drop() {
        let process = CacheProcess::new(99, 0);
        let weak = Arc::downgrade(&process);
        let lease = Lease::new("aa".into(), None, process, |_| {});
        assert!(weak.upgrade().is_some(), "lease must keep process alive");
        drop(lease);
        assert!(
            weak.upgrade().is_none(),
            "process must drop when lease drops"
        );
    }
}
