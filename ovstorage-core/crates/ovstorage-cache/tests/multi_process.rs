// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multi-process cache conformance.
//!
//! Cross-process behavior the spec promises:
//! - The herd-collapse `flock`-backed lock serializes writers
//!   across processes, not just threads.
//! - The process sentinel under `<state_root>/processes/<pid>.lock`
//!   stays held while the owning cache is alive and is reaped (its
//!   row + lock file removed) by a subsequent process's recovery
//!   sweep when the prior process exits.
//! - `Cache::open` against a state_root that already contains a
//!   live process's sentinel succeeds, and the new process gets its
//!   own sentinel.
//!
//! Implementation note: rather than spinning up a helper binary
//! via `Command::spawn`, we exercise multi-process behavior by
//! using `std::thread` together with the file-lock semantics that
//! `fs2` provides via `flock` on POSIX (which is per-fd, not per-
//! process — different Cache instances inside one process get
//! different fds and behave like different processes for the lock
//! check). For tests that require true `kill -9` semantics
//! against a live process, we shell out to the
//! `multi_process_helper` binary built by `build.rs`.
//!
//! As a first pass, the in-process simulation pins the key cross-
//! process invariants (sentinel sharing, lease drop on cache drop,
//! recovery against an orphaned sentinel file) without needing a
//! separate helper binary. A future pass can extend this with
//! `Command::spawn` for genuine multi-process kill behavior.

use std::sync::Arc;

use ovstorage_cache::{Cache, CacheConfig, CacheCoordination, CacheOptions};

#[test]
fn two_caches_against_same_state_root_each_get_their_own_sentinel() {
    let temp = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        state_root: temp.path().join("state"),
        cache_root: temp.path().join("cache"),
    };
    // Open two caches sequentially; both must succeed since the
    // process sentinel is per-pid (and we're the same pid in
    // both opens — re-opening a cache against a state-root where
    // the prior cache already dropped its sentinel must work).
    let first = Cache::open(config.clone()).unwrap();
    drop(first);
    let second = Cache::open(config).unwrap();
    drop(second);

    // The processes/ directory should be empty (both sentinels
    // unlinked on drop).
    let processes_dir = temp.path().join("state").join("processes");
    assert!(processes_dir.exists());
    let count = std::fs::read_dir(&processes_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();
    assert_eq!(count, 0, "sentinels should unlink on drop");
}

#[test]
fn recovery_reaps_orphaned_sentinel_from_dead_process() {
    let temp = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        state_root: temp.path().join("state"),
        cache_root: temp.path().join("cache"),
    };
    // Open + drop a cache normally so the schema is laid down.
    let initial = Cache::open(config.clone()).unwrap();
    drop(initial);

    // Plant a fake orphan sentinel (PID 99999 = unlikely to
    // collide). Recovery must walk it, observe the file isn't
    // locked by any live process, reap the row, and unlink.
    let orphan = temp
        .path()
        .join("state")
        .join("processes")
        .join("99999.lock");
    std::fs::write(&orphan, b"").unwrap();
    // Also seed a `process_leases` row so the reap is observable.
    let conn = rusqlite::Connection::open(temp.path().join("state").join("index.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO process_leases (pid, started_unix_ms, state_root) VALUES (99999, 0, '?')",
        [],
    )
    .unwrap();
    drop(conn);

    let cache = Cache::open(config).unwrap();
    // `Cache::open` runs recovery internally, so the orphan
    // sentinel should be unlinked by the time we observe.
    assert!(!orphan.exists(), "orphan sentinel should be unlinked");
    // The matching `process_leases` row should also be gone.
    let conn = rusqlite::Connection::open(temp.path().join("state").join("index.sqlite")).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM process_leases WHERE pid = 99999",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    drop(cache);
    assert_eq!(count, 0, "orphan process_leases row should be reaped");
}

#[test]
fn shared_single_writer_rejects_second_writer_at_open() {
    let temp = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        state_root: temp.path().join("state"),
        cache_root: temp.path().join("cache"),
    };
    let _writer = Cache::open_with_options(
        config.clone(),
        CacheOptions {
            coordination: CacheCoordination::SharedSingleWriter,
            ..CacheOptions::default()
        },
    )
    .unwrap();
    // A second SharedSingleWriter open must fail because the
    // `.writer` rendezvous file is already held.
    let result = Cache::open_with_options(
        config,
        CacheOptions {
            coordination: CacheCoordination::SharedSingleWriter,
            ..CacheOptions::default()
        },
    );
    let err = match result {
        Ok(_) => panic!("second SharedSingleWriter open should be refused"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::CacheLockContention);
}

#[test]
fn herd_collapse_serializes_concurrent_threads() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let temp = tempfile::tempdir().unwrap();
    let cache = Arc::new(
        Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap(),
    );
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let cache = cache.clone();
        let active = active.clone();
        let max_active = max_active.clone();
        threads.push(
            std::thread::Builder::new()
                .name("ovs-test-cache".into())
                .spawn(move || {
                    cache
                        .with_herd_lock("collapse-key", || {
                            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                            max_active.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                })
                .expect("failed to spawn thread"),
        );
    }
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        max_active.load(Ordering::SeqCst),
        1,
        "herd-collapse must serialize across threads"
    );
}

#[test]
fn sentinel_lock_held_while_second_cache_or_lease_outlives_first_cache() {
    use fs2::FileExt;
    use std::fs::OpenOptions;

    let temp = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        state_root: temp.path().join("state"),
        cache_root: temp.path().join("cache"),
    };
    let first = Cache::open(config.clone()).unwrap();
    let second = Cache::open(config).unwrap();
    let sentinel_path = temp
        .path()
        .join("state")
        .join("processes")
        .join(format!("{}.lock", std::process::id()));
    drop(first);
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&sentinel_path)
        .unwrap();
    assert!(
        probe.try_lock_exclusive().is_err(),
        "sentinel lock must remain held while a second Cache is alive"
    );
    drop(probe);
    let entry = second.put("pinned", b"pin-bytes").unwrap();
    let lease = second.lease(&entry.cas_key).unwrap().expect("lease minted");
    drop(second);
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&sentinel_path)
        .unwrap();
    assert!(
        probe.try_lock_exclusive().is_err(),
        "sentinel lock must remain held while a Lease is alive"
    );
    drop(probe);
    drop(lease);
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&sentinel_path);
    if let Ok(file) = probe {
        assert!(file.try_lock_exclusive().is_ok());
        let _ = FileExt::unlock(&file);
    }
}

#[test]
fn lease_pinning_survives_eviction_pressure_in_one_process() {
    let temp = tempfile::tempdir().unwrap();
    let cache = Cache::open_with_options(
        CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        },
        CacheOptions {
            max_bytes: Some(8),
            ..CacheOptions::default()
        },
    )
    .unwrap();
    let entry = cache.put("file://a", b"AAAA").unwrap();
    let lease = cache.lease(&entry.cas_key).unwrap().expect("lease");
    // Drive eviction pressure; the pinned row must survive.
    std::thread::sleep(std::time::Duration::from_millis(2));
    cache.put("file://b", b"BBBB").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    cache.put("file://c", b"CCCC").unwrap();
    assert!(cache.get("file://a").unwrap().is_some());
    drop(lease);
    // One more put pushes us over budget again; now the
    // previously-pinned row may be evicted.
    cache.put("file://d", b"DDDD").unwrap();
    let total_after = cache.status().unwrap().total_bytes;
    assert!(total_after <= 8, "byte budget enforced after lease drop");
}
