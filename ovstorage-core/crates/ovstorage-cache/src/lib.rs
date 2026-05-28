// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use ovstorage_plugin::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub mod coordination;
pub mod fs_probe;
mod lease;
mod migrations;
pub mod observer;

pub use coordination::CacheCoordination;
pub use fs_probe::{FsKind, fs_kind};
pub use lease::{CacheProcess, Lease};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use observer::{
    EvictionReason, FillOutcome, LookupOutcome, MetricsObserver, NoopObserver, Observer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    pub state_root: PathBuf,
    pub cache_root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    pub resolved_target: String,
    pub cas_key: String,
    pub size: u64,
    /// On-disk CAS path. **Not pinned against eviction.** Callers
    /// handing this path to a downstream reader must obtain it via
    /// [`Cache::lookup`] and keep the paired [`Lease`] alive — without
    /// one, concurrent eviction or invalidation can unlink the file.
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedObject {
    pub entry: CacheEntry,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct CacheOptions {
    pub max_bytes: Option<u64>,
    pub refuse_network_filesystems: bool,
    pub coordination: CacheCoordination,
    /// Optional metric/tracing hook. `None` short-circuits with no allocations.
    pub observer: Option<Arc<dyn Observer>>,
}

impl std::fmt::Debug for CacheOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheOptions")
            .field("max_bytes", &self.max_bytes)
            .field(
                "refuse_network_filesystems",
                &self.refuse_network_filesystems,
            )
            .field("coordination", &self.coordination)
            .field(
                "observer",
                &self.observer.as_ref().map(|_| "<dyn Observer>"),
            )
            .finish()
    }
}

impl PartialEq for CacheOptions {
    fn eq(&self, other: &Self) -> bool {
        // Observer is a trait object; compare by Arc pointer equality.
        self.max_bytes == other.max_bytes
            && self.refuse_network_filesystems == other.refuse_network_filesystems
            && self.coordination == other.coordination
            && match (&self.observer, &other.observer) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl Eq for CacheOptions {}

/// Typed herd-collapse key. Three flavors hash into disjoint lock
/// spaces so concurrent callers requesting the same logical resource
/// collapse onto the right shared work.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HerdKey {
    /// Newest committed bytes for `prefix`.
    Current { prefix: String },
    /// Bytes whose ETag still matches `etag`. Conditional writes use
    /// this so a stale-cache-hit + write race doesn't surface a
    /// phantom-version entry.
    Guarded { prefix: String, etag: String },
    /// Exactly the named version. Versioned reads/writes collapse on
    /// the (target, version) pair.
    Exact {
        prefix: String,
        version_or_cas: String,
    },
}

impl HerdKey {
    /// Render to the opaque lock-key string. Discriminator prefixes
    /// guarantee disjoint lock spaces across flavors.
    pub fn as_lock_key(&self) -> String {
        match self {
            HerdKey::Current { prefix } => format!("v1:current\0{prefix}"),
            HerdKey::Guarded { prefix, etag } => format!("v1:guarded\0{prefix}\0{etag}"),
            HerdKey::Exact {
                prefix,
                version_or_cas,
            } => format!("v1:exact\0{prefix}\0{version_or_cas}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheStatus {
    pub state_root: PathBuf,
    pub cache_root: PathBuf,
    pub entries: u64,
    pub total_bytes: u64,
    pub live_process_leases: u64,
    pub staging_files: u64,
    pub max_bytes: Option<u64>,
}

pub struct Cache {
    state_root: PathBuf,
    cache_root: PathBuf,
    staging_root: PathBuf,
    locks_root: PathBuf,
    max_bytes: Option<u64>,
    process_started_unix_ms: i64,
    conn: Mutex<Connection>,
    key_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Sentinel cloned into every `Lease` so a live lease keeps the
    /// `<state_root>/processes/<pid>.lock` flock alive.
    process: Arc<CacheProcess>,
    coordination: CacheCoordination,
    /// `Some` only in `SharedSingleWriter`; dropped to release the rendezvous.
    _writer_rendezvous: Option<File>,
    observer: Option<Arc<dyn Observer>>,
}

impl Cache {
    pub fn open(config: CacheConfig) -> Result<Self> {
        Self::open_with_options(config, CacheOptions::default())
    }

    pub fn open_with_options(config: CacheConfig, options: CacheOptions) -> Result<Self> {
        if options.refuse_network_filesystems {
            for root in [&config.state_root, &config.cache_root] {
                refuse_network_with_probe(root)?;
            }
        }
        fs::create_dir_all(&config.state_root).map_err(map_io)?;
        fs::create_dir_all(&config.cache_root).map_err(map_io)?;
        let staging_root = config.cache_root.join("staging");
        let locks_root = config.state_root.join("locks");
        let processes_root = config.state_root.join("processes");
        if staging_root.exists() {
            fs::remove_dir_all(&staging_root).map_err(map_io)?;
        }
        fs::create_dir_all(&staging_root).map_err(map_io)?;
        fs::create_dir_all(&locks_root).map_err(map_io)?;
        fs::create_dir_all(&processes_root).map_err(map_io)?;
        // One-shot in-place rename of legacy `cache.sqlite` to `index.sqlite`.
        let new_db_path = config.state_root.join("index.sqlite");
        let legacy_db_path = config.state_root.join("cache.sqlite");
        if !new_db_path.exists() && legacy_db_path.exists() {
            fs::rename(&legacy_db_path, &new_db_path).map_err(map_io)?;
            // SQLite picks up the WAL/SHM sidecars by filename; rename
            // them alongside. Missing files are normal after clean shutdown.
            for sidecar in ["cache.sqlite-wal", "cache.sqlite-shm"] {
                let from = config.state_root.join(sidecar);
                if from.exists() {
                    let to_name = sidecar.replace("cache.sqlite", "index.sqlite");
                    let to = config.state_root.join(to_name);
                    let _ = fs::rename(&from, &to);
                }
            }
        }
        let conn = Connection::open(&new_db_path).map_err(map_sql)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            ",
        )
        .map_err(map_sql)?;
        migrations::migrate(&conn)?;
        let process_started_unix_ms = unix_ms();
        conn.execute(
            "
            INSERT OR REPLACE INTO process_leases (pid, started_unix_ms, state_root)
            VALUES (?1, ?2, ?3)
            ",
            params![
                std::process::id() as i64,
                process_started_unix_ms,
                config.state_root.to_string_lossy()
            ],
        )
        .map_err(map_sql)?;
        // Two `Cache::open`s against the same canonical state_root in
        // this process must share one `Arc<CacheProcess>` — otherwise
        // a sibling open would race the recovery sweep and reset
        // `lease_count` of the first cache's still-live leases.
        let pid = std::process::id();
        let canonical_state_root = config_state_root_canonical(&processes_root)?;
        let (process, is_first_open_in_process) = process_sentinel(
            &canonical_state_root,
            &processes_root,
            pid,
            process_started_unix_ms,
        )?;

        let writer_rendezvous = match options.coordination {
            CacheCoordination::SharedSingleWriter => {
                Some(coordination::acquire_writer_rendezvous(&config.cache_root)?)
            }
            CacheCoordination::HostExclusive | CacheCoordination::ReadOnly => None,
        };

        let cache = Self {
            state_root: config.state_root,
            cache_root: config.cache_root,
            staging_root,
            locks_root,
            max_bytes: options.max_bytes,
            process_started_unix_ms,
            conn: Mutex::new(conn),
            key_locks: Mutex::new(HashMap::new()),
            process,
            coordination: options.coordination,
            _writer_rendezvous: writer_rendezvous,
            observer: options.observer,
        };
        // Bounded crash recovery before declaring the cache ready.
        // Only the first open in this process for this state_root
        // resets the `lease_count` denormalization — subsequent
        // opens must not race a sibling cache's live leases to zero.
        let recovery_outcome = cache.recover_internal(is_first_open_in_process)?;
        if let Some(observer) = cache.observer.as_ref() {
            observer
                .on_crash_recovery(recovery_outcome.rows_examined, recovery_outcome.rows_reaped);
        }
        cache.evict_to_limit()?;
        tracing::info!(
            max_bytes = cache.max_bytes,
            recovery.rows_examined = recovery_outcome.rows_examined,
            recovery.rows_reaped = recovery_outcome.rows_reaped,
            "cache opened"
        );
        Ok(cache)
    }

    pub fn with_herd_lock<T>(
        &self,
        resolved_target: &str,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let in_process_lock = self.in_process_key_lock(resolved_target)?;
        let _in_process_guard = in_process_lock.lock().map_err(|_| {
            Error::new(ErrorCode::CacheLockContention, "cache key lock is poisoned")
        })?;
        let _lock = self.lock_key(resolved_target)?;
        f()
    }

    /// Typed herd-collapse: like [`Cache::with_herd_lock`] but the
    /// [`HerdKey`] flavors hash into disjoint lock spaces.
    pub fn with_typed_herd_lock<T>(
        &self,
        key: &HerdKey,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let lock_key = key.as_lock_key();
        self.with_herd_lock(&lock_key, f)
    }

    pub fn status(&self) -> Result<CacheStatus> {
        let conn = self.conn()?;
        let (entries, total_bytes): (u64, u64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM entries",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(map_sql)?;
        let live_process_leases = conn
            .query_row("SELECT COUNT(*) FROM process_leases", [], |row| row.get(0))
            .map_err(map_sql)?;
        Ok(CacheStatus {
            state_root: self.state_root.clone(),
            cache_root: self.cache_root.clone(),
            entries,
            total_bytes,
            live_process_leases,
            staging_files: count_files(&self.staging_root)?,
            max_bytes: self.max_bytes,
        })
    }

    pub fn lock_key(&self, resolved_target: &str) -> Result<CacheKeyLock> {
        fs::create_dir_all(&self.locks_root).map_err(map_io)?;
        let path = self
            .locks_root
            .join(format!("{}.lock", sha256_hex(resolved_target.as_bytes())));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(map_io)?;
        file.lock_exclusive().map_err(map_io)?;
        Ok(CacheKeyLock { file })
    }

    pub fn put(&self, resolved_target: &str, bytes: &[u8]) -> Result<CacheEntry> {
        self.ensure_writable()?;
        let started = std::time::Instant::now();
        let _lock = self.lock_key(resolved_target)?;
        let result = self.put_locked(resolved_target, bytes);
        if let Some(observer) = self.observer.as_ref() {
            let outcome = match &result {
                Ok(_) => FillOutcome::Success,
                Err(_) => FillOutcome::Failure,
            };
            observer.on_fill(outcome, bytes.len() as u64, started.elapsed());
        }
        result
    }

    pub fn put_with_existing_key_lock(
        &self,
        resolved_target: &str,
        bytes: &[u8],
    ) -> Result<CacheEntry> {
        self.ensure_writable()?;
        self.put_locked(resolved_target, bytes)
    }

    /// Fill + lease in one call. The paired [`Lease`] pins the CAS
    /// file so the caller can hand `entry.path` to a downstream
    /// reader without racing eviction.
    pub fn put_and_lease(&self, resolved_target: &str, bytes: &[u8]) -> Result<CachePut> {
        let entry = self.put(resolved_target, bytes)?;
        let lease = self.lease(&entry.cas_key)?;
        Ok(CachePut { entry, lease })
    }

    /// Fill from an existing local file + lease in one call. The file
    /// is copied into cache staging while hashing, then published into
    /// CAS without loading the whole body into memory.
    pub fn put_path_and_lease(&self, resolved_target: &str, source: &Path) -> Result<CachePut> {
        self.ensure_writable()?;
        let started = std::time::Instant::now();
        let _lock = self.lock_key(resolved_target)?;
        let result = self.put_path_locked(resolved_target, source);
        if let Some(observer) = self.observer.as_ref() {
            let (outcome, size) = match &result {
                Ok(entry) => (FillOutcome::Success, entry.size),
                Err(_) => (FillOutcome::Failure, 0),
            };
            observer.on_fill(outcome, size, started.elapsed());
        }
        let entry = result?;
        let lease = self.lease(&entry.cas_key)?;
        Ok(CachePut { entry, lease })
    }

    fn put_locked(&self, resolved_target: &str, bytes: &[u8]) -> Result<CacheEntry> {
        self.ensure_writable()?;
        let now = unix_ms();
        let cas_key = sha256_hex(bytes);
        fs::create_dir_all(&self.staging_root).map_err(map_io)?;
        let tmp = self.staging_path(resolved_target, now);
        {
            let mut file = File::create(&tmp).map_err(map_io)?;
            file.write_all(bytes).map_err(map_io)?;
            file.sync_all().map_err(map_io)?;
        }
        let size = bytes.len() as u64;
        self.put_staged_locked(resolved_target, cas_key, size, tmp, now)
    }

    fn put_path_locked(&self, resolved_target: &str, source: &Path) -> Result<CacheEntry> {
        self.ensure_writable()?;
        let now = unix_ms();
        fs::create_dir_all(&self.staging_root).map_err(map_io)?;
        let tmp = self.staging_path(resolved_target, now);
        let (cas_key, size) = copy_path_to_staging_and_hash(source, &tmp)?;
        self.put_staged_locked(resolved_target, cas_key, size, tmp, now)
    }

    fn staging_path(&self, resolved_target: &str, now: i64) -> PathBuf {
        self.staging_root.join(format!(
            "{}-{}-{}.tmp",
            std::process::id(),
            now,
            sha256_hex(resolved_target.as_bytes())
        ))
    }

    fn put_staged_locked(
        &self,
        resolved_target: &str,
        cas_key: String,
        size: u64,
        tmp: PathBuf,
        now: i64,
    ) -> Result<CacheEntry> {
        let result = (|| -> Result<CacheEntry> {
            let path = cas_path(&self.cache_root, &cas_key)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(map_io)?;
            }

            // INSERT before publishing the CAS file. Eviction walks
            // `entries`, so an orphan file (publish-then-INSERT) is
            // invisible to the LRU and leaks forever. INSERT-then-publish
            // can leave an orphan row pointing at a missing file, but the
            // reader (get_entry_inner) treats ENOENT as a miss and
            // eviction's remove_file tolerates it, so the system
            // self-heals on next access.
            let mut conn = self.conn()?;
            let tx_result = (|| -> Result<()> {
                let tx = conn.transaction().map_err(map_sql)?;
                tx.execute(
                    "
                    INSERT INTO entries (
                        resolved_target,
                        cas_key,
                        size,
                        updated_unix_ms,
                        last_access_unix_ms
                    )
                    VALUES (?1, ?2, ?3, ?4, ?4)
                    ON CONFLICT(resolved_target) DO UPDATE SET
                        cas_key = excluded.cas_key,
                        size = excluded.size,
                        updated_unix_ms = excluded.updated_unix_ms,
                        last_access_unix_ms = excluded.last_access_unix_ms
                    ",
                    params![resolved_target, cas_key, size, now],
                )
                .map_err(map_sql)?;
                // ON CONFLICT preserves existing lease/pin counts when
                // the same CAS key is rewritten under a different target.
                tx.execute(
                    "
                    INSERT INTO cache_entries (cas_key, size, verified_at)
                    VALUES (?1, ?2, ?3)
                    ON CONFLICT(cas_key) DO UPDATE SET
                        size = excluded.size,
                        verified_at = excluded.verified_at
                    ",
                    params![cas_key, size, now],
                )
                .map_err(map_sql)?;
                tx.commit().map_err(map_sql)
            })();
            if let Err(error) = tx_result {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
            drop(conn);

            publish_cas(&tmp, &path)?;
            self.evict_to_limit()?;
            Ok(CacheEntry {
                resolved_target: resolved_target.to_string(),
                cas_key,
                size,
                path,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    pub fn get(&self, resolved_target: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.get_entry(resolved_target)?.map(|cached| cached.bytes))
    }

    /// Async wrapper for `get`: runs the blocking read on the tokio
    /// blocking pool so async callers don't park a runtime worker on
    /// `fs::read` + SHA-256 verify.
    pub async fn get_async(self: &Arc<Self>, resolved_target: &str) -> Result<Option<Vec<u8>>> {
        let cache = Arc::clone(self);
        let key = resolved_target.to_string();
        tokio::task::spawn_blocking(move || cache.get(&key))
            .await
            .map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("cache get task panicked: {err}"),
                )
            })?
    }

    /// Async wrapper for `get_entry`: runs the blocking read + verify
    /// on the tokio blocking pool.
    pub async fn get_entry_async(
        self: &Arc<Self>,
        resolved_target: &str,
    ) -> Result<Option<CachedObject>> {
        let cache = Arc::clone(self);
        let key = resolved_target.to_string();
        tokio::task::spawn_blocking(move || cache.get_entry(&key))
            .await
            .map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("cache get_entry task panicked: {err}"),
                )
            })?
    }

    /// Read a cached object. **Does not** mint a [`Lease`]; consumers
    /// that hand `entry.path` to a downstream reader must call
    /// [`Cache::lookup`] instead so a lease pins the CAS file.
    pub fn get_entry(&self, resolved_target: &str) -> Result<Option<CachedObject>> {
        let (result, quarantined) = self.get_entry_inner(resolved_target);
        let hit = matches!(&result, Ok(Some(_)));
        tracing::debug!(cache.hit = hit, "cache lookup");
        if let Some(observer) = self.observer.as_ref() {
            let outcome = match &result {
                Ok(Some(_)) => LookupOutcome::Hit,
                Ok(None) if quarantined => LookupOutcome::CorruptQuarantine,
                Ok(None) => LookupOutcome::Miss,
                Err(_) => LookupOutcome::Miss,
            };
            observer.on_lookup(outcome);
        }
        result
    }

    fn get_entry_inner(&self, resolved_target: &str) -> (Result<Option<CachedObject>>, bool) {
        let entry = match self.entry(resolved_target) {
            Ok(Some(entry)) => entry,
            Ok(None) => return (Ok(None), false),
            Err(error) => return (Err(error), false),
        };
        match fs::read(&entry.path) {
            Ok(bytes) => {
                if bytes.len() as u64 != entry.size || sha256_hex(&bytes) != entry.cas_key {
                    let result = self.quarantine_corrupt(&entry);
                    return match result {
                        Ok(()) => (Ok(None), true),
                        Err(error) => (Err(error), true),
                    };
                }
                match self.touch(resolved_target) {
                    Ok(()) => (Ok(Some(CachedObject { entry, bytes })), false),
                    Err(error) => (Err(error), false),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Ok(None), false),
            Err(error) => (Err(map_io(error)), false),
        }
    }

    fn quarantine_corrupt(&self, entry: &CacheEntry) -> Result<()> {
        let _ = fs::remove_file(&entry.path);
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM entries WHERE cas_key = ?1",
            params![entry.cas_key],
        )
        .map_err(map_sql)?;
        conn.execute(
            "DELETE FROM cache_entries WHERE cas_key = ?1",
            params![entry.cas_key],
        )
        .map_err(map_sql)?;
        drop(conn);
        tracing::warn!(
            cas_key = entry.cas_key.as_str(),
            size_bytes = entry.size,
            "cache row quarantined: CAS verification failed"
        );
        if let Some(observer) = self.observer.as_ref() {
            observer.on_eviction(EvictionReason::Corrupt, entry.size);
        }
        Ok(())
    }

    /// Mint a [`Lease`] for the given CAS key. Eviction skips rows
    /// with `lease_count > 0`. Returns `None` when no row exists.
    pub fn lease(&self, cas_key: &str) -> Result<Option<Lease>> {
        let conn = self.conn()?;
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cache_entries WHERE cas_key = ?1)",
                params![cas_key],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if exists == 0 {
            return Ok(None);
        }
        let path = cas_path(&self.cache_root, cas_key)?;
        if !path.exists() {
            return Ok(None);
        }
        conn.execute(
            "UPDATE cache_entries SET lease_count = lease_count + 1 WHERE cas_key = ?1",
            params![cas_key],
        )
        .map_err(map_sql)?;
        drop(conn);
        if let Some(observer) = self.observer.as_ref() {
            observer.on_lease(1);
        }
        // The cleanup closure must not capture `&self`: a Lease can
        // outlive the Cache. Re-open SQLite by path on drop and no-op
        // if the path is gone (state_root wiped during shutdown).
        let cas_key_owned = cas_key.to_string();
        let state_root = self.state_root.clone();
        let cache_root = self.cache_root.clone();
        let observer = self.observer.clone();
        Ok(Some(Lease::new(
            cas_key_owned.clone(),
            None,
            self.process.clone(),
            move |_lease| {
                let db_path = state_root.join("index.sqlite");
                if !db_path.exists() {
                    return;
                }
                if let Ok(conn) = Connection::open(&db_path) {
                    let _ = conn.execute(
                        "UPDATE cache_entries SET lease_count = MAX(0, lease_count - 1) \
                         WHERE cas_key = ?1",
                        params![cas_key_owned],
                    );
                    // If the entry was invalidated while pinned,
                    // `prune_unreferenced_cas` short-circuited on the
                    // pinned row — reap it here on the last lease drop.
                    let still_referenced: bool = conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM entries WHERE cas_key = ?1)",
                            params![cas_key_owned],
                            |row| row.get(0),
                        )
                        .unwrap_or(true);
                    if !still_referenced {
                        let pinned: i64 = conn
                            .query_row(
                                "SELECT COALESCE(MAX(lease_count + pin_count), 0) FROM cache_entries WHERE cas_key = ?1",
                                params![cas_key_owned],
                                |row| row.get(0),
                            )
                            .unwrap_or(1);
                        if pinned == 0 {
                            let _ = conn.execute(
                                "DELETE FROM cache_entries WHERE cas_key = ?1",
                                params![cas_key_owned],
                            );
                            if let Ok(path) = cas_path(&cache_root, &cas_key_owned) {
                                let _ = fs::remove_file(path);
                            }
                        }
                    }
                }
                if let Some(o) = observer.as_ref() {
                    o.on_lease(-1);
                }
            },
        )))
    }

    /// Lookup that pairs the cached bytes with a [`Lease`] in one
    /// call. The lease is minted **before** the bytes are read so the
    /// CAS file is pinned against eviction for the entire read.
    pub fn lookup(&self, resolved_target: &str) -> Result<Option<CacheLookup>> {
        let Some(entry) = self.entry(resolved_target)? else {
            if let Some(observer) = self.observer.as_ref() {
                observer.on_lookup(LookupOutcome::Miss);
            }
            return Ok(None);
        };
        let Some(lease) = self.lease(&entry.cas_key)? else {
            if let Some(observer) = self.observer.as_ref() {
                observer.on_lookup(LookupOutcome::Miss);
            }
            return Ok(None);
        };
        let (result, quarantined) = self.get_entry_inner(resolved_target);
        if let Some(observer) = self.observer.as_ref() {
            let outcome = match &result {
                Ok(Some(_)) => LookupOutcome::Hit,
                Ok(None) if quarantined => LookupOutcome::CorruptQuarantine,
                Ok(None) => LookupOutcome::Miss,
                Err(_) => LookupOutcome::Miss,
            };
            observer.on_lookup(outcome);
        }
        match result? {
            Some(cached) => Ok(Some(CacheLookup {
                cached,
                lease: Some(lease),
            })),
            None => Ok(None),
        }
    }

    /// Run a GC pass. Currently equivalent to `evict_to_limit`.
    pub fn gc(&self) -> Result<()> {
        self.evict_to_limit()
    }

    /// Dry-run recovery sweep. Returns what `recover` would touch.
    pub fn doctor(&self) -> Result<RecoveryOutcome> {
        self.recover_dry_run()
    }

    pub fn entry(&self, resolved_target: &str) -> Result<Option<CacheEntry>> {
        self.conn()?
            .query_row(
                "SELECT cas_key, size FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
                |row| {
                    let cas_key: String = row.get(0)?;
                    let size: u64 = row.get(1)?;
                    let path = cas_path(&self.cache_root, &cas_key).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(CacheEntry {
                        resolved_target: resolved_target.to_string(),
                        cas_key,
                        size,
                        path,
                    })
                },
            )
            .optional()
            .map_err(map_sql)
    }

    pub fn remove_index(&self, resolved_target: &str) -> Result<()> {
        self.ensure_writable()?;
        let conn = self.conn()?;
        let cas_key: Option<String> = conn
            .query_row(
                "SELECT cas_key FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql)?;
        conn.execute(
            "DELETE FROM entries WHERE resolved_target = ?1",
            params![resolved_target],
        )
        .map_err(map_sql)?;
        if let Some(key) = cas_key {
            self.prune_unreferenced_cas(&conn, &key)?;
        }
        Ok(())
    }

    pub fn remove_prefix(&self, resolved_prefix: &str) -> Result<()> {
        self.ensure_writable()?;
        let conn = self.conn()?;
        let mut statement = conn
            .prepare("SELECT resolved_target, cas_key FROM entries")
            .map_err(map_sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(map_sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        drop(statement);
        let mut affected: Vec<String> = Vec::new();
        for (key, cas_key) in rows {
            if key.starts_with(resolved_prefix) {
                conn.execute(
                    "DELETE FROM entries WHERE resolved_target = ?1",
                    params![key],
                )
                .map_err(map_sql)?;
                affected.push(cas_key);
            }
        }
        for cas_key in affected {
            self.prune_unreferenced_cas(&conn, &cas_key)?;
        }
        Ok(())
    }

    fn prune_unreferenced_cas(
        &self,
        conn: &std::sync::MutexGuard<'_, Connection>,
        cas_key: &str,
    ) -> Result<()> {
        let still_referenced: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE cas_key = ?1)",
                params![cas_key],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if still_referenced {
            return Ok(());
        }
        let pinned: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(lease_count + pin_count), 0) FROM cache_entries WHERE cas_key = ?1",
                params![cas_key],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if pinned > 0 {
            return Ok(());
        }
        conn.execute(
            "DELETE FROM cache_entries WHERE cas_key = ?1",
            params![cas_key],
        )
        .map_err(map_sql)?;
        let path = cas_path(&self.cache_root, cas_key)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
        Ok(())
    }

    fn touch(&self, resolved_target: &str) -> Result<()> {
        self.conn()?
            .execute(
                "UPDATE entries SET last_access_unix_ms = ?2 WHERE resolved_target = ?1",
                params![resolved_target, unix_ms()],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn evict_to_limit(&self) -> Result<()> {
        // Read-only mode never evicts; bytes belong to the writer.
        if matches!(self.coordination, CacheCoordination::ReadOnly) {
            return Ok(());
        }
        let Some(max_bytes) = self.max_bytes else {
            return Ok(());
        };
        let conn = self.conn()?;
        let mut total_bytes: u64 = conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM entries", [], |row| {
                row.get(0)
            })
            .map_err(map_sql)?;
        if total_bytes <= max_bytes {
            return Ok(());
        }
        let victims = {
            let mut statement = conn
                .prepare(
                    "
                    SELECT resolved_target, cas_key, size
                    FROM entries
                    ORDER BY last_access_unix_ms ASC, updated_unix_ms ASC
                    ",
                )
                .map_err(map_sql)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .map_err(map_sql)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_sql)?
        };
        for (resolved_target, cas_key, size) in victims {
            if total_bytes <= max_bytes {
                break;
            }
            // Skip rows with live leases — eviction must not yank
            // bytes a `Lease` holder is still using.
            let pinned: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(lease_count), 0) FROM cache_entries WHERE cas_key = ?1",
                    params![cas_key],
                    |row| row.get(0),
                )
                .map_err(map_sql)?;
            if pinned > 0 {
                continue;
            }
            conn.execute(
                "DELETE FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
            )
            .map_err(map_sql)?;
            total_bytes = total_bytes.saturating_sub(size);
            let still_referenced: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM entries WHERE cas_key = ?1)",
                    params![cas_key],
                    |row| row.get(0),
                )
                .map_err(map_sql)?;
            if !still_referenced {
                let path = cas_path(&self.cache_root, &cas_key)?;
                let _ = conn.execute(
                    "DELETE FROM cache_entries WHERE cas_key = ?1",
                    params![cas_key],
                );
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(map_io(error)),
                }
            }
            tracing::debug!(size_bytes = size, "cache eviction: size pressure");
            if let Some(observer) = self.observer.as_ref() {
                observer.on_eviction(EvictionReason::SizePressure, size);
            }
        }
        Ok(())
    }
}

impl Cache {
    fn ensure_writable(&self) -> Result<()> {
        if matches!(self.coordination, CacheCoordination::ReadOnly) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "cache is opened in read-only coordination mode; mutations are refused",
            ));
        }
        Ok(())
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| {
            Error::new(
                ErrorCode::StateRootUnavailable,
                "cache SQLite connection lock is poisoned",
            )
        })
    }

    fn in_process_key_lock(&self, resolved_target: &str) -> Result<Arc<Mutex<()>>> {
        let mut key_locks = self.key_locks.lock().map_err(|_| {
            Error::new(
                ErrorCode::CacheLockContention,
                "cache key-lock table is poisoned",
            )
        })?;
        Ok(key_locks
            .entry(resolved_target.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "
                DELETE FROM process_leases
                WHERE pid = ?1 AND started_unix_ms = ?2
                ",
                params![std::process::id() as i64, self.process_started_unix_ms],
            );
        }
        if matches!(self.coordination, CacheCoordination::SharedSingleWriter) {
            coordination::release_writer_rendezvous(&self.cache_root);
        }
    }
}

/// Result of [`Cache::lookup`]. The lease pins the cached bytes
/// against eviction for as long as it lives.
pub struct CacheLookup {
    pub cached: CachedObject,
    pub lease: Option<Lease>,
}

/// Result of [`Cache::put_and_lease`]. The lease pins the CAS file
/// against eviction for the lifetime of any downstream read.
pub struct CachePut {
    pub entry: CacheEntry,
    pub lease: Option<Lease>,
}

/// Summary of a recovery / doctor pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub rows_examined: u64,
    /// Rows torn down (orphan staging, dead-pid leases, missing CAS).
    pub rows_reaped: u64,
    /// CAS files whose on-disk SHA-256 didn't match the column.
    pub quarantined: u64,
    /// Entries removed because their CAS file was gone.
    pub missing_cas_removed: u64,
}

impl Cache {
    /// Bounded crash-recovery sweep. Called from `Cache::open`;
    /// surfaced separately so tests can exercise each step.
    pub fn recover(&self) -> Result<RecoveryOutcome> {
        self.recover_internal(false)
    }

    fn recover_internal(&self, reset_lease_count: bool) -> Result<RecoveryOutcome> {
        let mut outcome = RecoveryOutcome::default();
        let mut other_live_processes = false;
        // Lease sweep: a sentinel file we can exclusive-lock has no
        // live owner, so leases attributed to that pid are reaped.
        let processes_dir = self.state_root.join("processes");
        if processes_dir.exists() {
            for entry in fs::read_dir(&processes_dir).map_err(map_io)? {
                let entry = entry.map_err(map_io)?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                    continue;
                }
                outcome.rows_examined += 1;
                let pid_str = path.file_stem().and_then(|s| s.to_str()).unwrap_or("0");
                let dead_pid: i64 = pid_str.parse().unwrap_or(0);
                if dead_pid == std::process::id() as i64 {
                    continue;
                }
                let probe = OpenOptions::new()
                    .create(false)
                    .read(true)
                    .write(true)
                    .open(&path);
                if let Ok(file) = probe {
                    if file.try_lock_exclusive().is_ok() {
                        let conn = self.conn()?;
                        let reaped = conn
                            .execute(
                                "DELETE FROM process_leases WHERE pid = ?1",
                                params![dead_pid],
                            )
                            .map_err(map_sql)?;
                        outcome.rows_reaped += reaped as u64;
                        let _ = file.unlock();
                        let _ = fs::remove_file(&path);
                    } else {
                        other_live_processes = true;
                    }
                }
            }
        }
        // Index repair: remove rows whose CAS file is gone. The
        // denormalized `lease_count` resets only when this is the
        // first open in this process AND no other live process holds
        // leases — otherwise the reset would race a live `Lease`
        // count back to zero.
        {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare("SELECT resolved_target, cas_key FROM entries")
                .map_err(map_sql)?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(map_sql)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_sql)?;
            drop(stmt);
            for (target, cas_key) in &rows {
                let path = cas_path(&self.cache_root, cas_key)?;
                if !path.exists() {
                    conn.execute(
                        "DELETE FROM entries WHERE resolved_target = ?1",
                        params![target],
                    )
                    .map_err(map_sql)?;
                    outcome.missing_cas_removed += 1;
                }
            }
            if reset_lease_count && !other_live_processes {
                let _ = conn.execute("UPDATE cache_entries SET lease_count = 0", []);
            }
            let _ = conn.execute(
                "DELETE FROM cache_entries \
                 WHERE cas_key NOT IN (SELECT cas_key FROM entries)",
                [],
            );
        }
        Ok(outcome)
    }

    /// Dry-run variant of [`Self::recover`]; does not mutate.
    pub fn recover_dry_run(&self) -> Result<RecoveryOutcome> {
        let mut outcome = RecoveryOutcome::default();
        let processes_dir = self.state_root.join("processes");
        if processes_dir.exists() {
            for entry in fs::read_dir(&processes_dir).map_err(map_io)? {
                let entry = entry.map_err(map_io)?;
                if entry.path().extension().and_then(|s| s.to_str()) != Some("lock") {
                    continue;
                }
                outcome.rows_examined += 1;
                let probe = OpenOptions::new().read(true).write(true).open(entry.path());
                if let Ok(file) = probe
                    && file.try_lock_exclusive().is_ok()
                {
                    outcome.rows_reaped += 1;
                    let _ = file.unlock();
                }
            }
        }
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT cas_key FROM entries")
            .map_err(map_sql)?;
        let rows: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        drop(stmt);
        for cas_key in &rows {
            let path = cas_path(&self.cache_root, cas_key)?;
            if !path.exists() {
                outcome.missing_cas_removed += 1;
            }
        }
        Ok(outcome)
    }
}

pub struct CacheKeyLock {
    file: File,
}

impl Drop for CacheKeyLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Race-idempotent CAS publish: hard-link, treat AlreadyExists as
/// success (the on-disk bytes are by definition identical), remove
/// staging file on every branch.
fn publish_cas(tmp: &Path, dest: &Path) -> Result<()> {
    match fs::hard_link(tmp, dest) {
        Ok(()) => {
            fs::remove_file(tmp).map_err(map_io)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(tmp).map_err(map_io)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(tmp);
            Err(map_io(error))
        }
    }
}

fn cas_path(cache_root: &Path, cas_key: &str) -> Result<PathBuf> {
    if cas_key.len() < 4 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "CAS key is too short to map to a path",
        ));
    }
    Ok(cache_root
        .join("sha256")
        .join(&cas_key[..2])
        .join(&cas_key[2..]))
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn refuse_network_root(path: &Path) -> Result<()> {
    let value = path.to_string_lossy();
    if value.starts_with("\\\\") || value.starts_with("//") {
        return Err(Error::new(
            ErrorCode::NetworkFilesystemRefused,
            format!("network filesystem roots are refused by default: {value}"),
        ));
    }
    Ok(())
}

/// Refuse network filesystems via `fs_probe`, falling back to the
/// UNC string check on `Unknown`. `OVSTORAGE_ALLOW_NETWORK_FS=1`
/// bypasses the refusal.
fn refuse_network_with_probe(path: &Path) -> Result<()> {
    if fs_probe::allow_network_fs_override() {
        return Ok(());
    }
    match fs_probe::fs_kind(path) {
        FsKind::Network => Err(Error::new(
            ErrorCode::NetworkFilesystemRefused,
            format!(
                "network filesystem roots are refused by default: {}",
                path.display()
            ),
        )),
        FsKind::Local => Ok(()),
        FsKind::Unknown => refuse_network_root(path),
    }
}

fn count_files(path: &Path) -> Result<u64> {
    let mut count = 0;
    if !path.exists() {
        return Ok(0);
    }
    for entry in fs::read_dir(path).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let metadata = entry.metadata().map_err(map_io)?;
        if metadata.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// Canonicalize so two opens with the same logical root (differing
/// in symlinks or `..`) share one sentinel.
fn config_state_root_canonical(processes_root: &Path) -> Result<PathBuf> {
    let state_root = processes_root.parent().unwrap_or(processes_root);
    state_root.canonicalize().map_err(map_io)
}

/// Process-wide registry keyed by canonical state_root.
fn sentinel_registry() -> &'static Mutex<HashMap<PathBuf, std::sync::Weak<CacheProcess>>> {
    use std::sync::OnceLock;
    static REG: OnceLock<Mutex<HashMap<PathBuf, std::sync::Weak<CacheProcess>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get-or-create the per-(state_root, pid) sentinel. Returns the
/// `Arc<CacheProcess>` plus `true` when this call created it
/// (first open in this process for this state_root). The lock file
/// is unlinked when the last `Arc` drops.
fn process_sentinel(
    canonical_state_root: &Path,
    processes_root: &Path,
    pid: u32,
    started_unix_ms: i64,
) -> Result<(Arc<CacheProcess>, bool)> {
    let mut registry = sentinel_registry()
        .lock()
        .map_err(|_| Error::new(ErrorCode::Internal, "sentinel registry lock poisoned"))?;
    if let Some(weak) = registry.get(canonical_state_root)
        && let Some(arc) = weak.upgrade()
    {
        return Ok((arc, false));
    }
    let process_lock_path = processes_root.join(format!("{pid}.lock"));
    let process_lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&process_lock_path)
        .map_err(map_io)?;
    process_lock_file.lock_exclusive().map_err(map_io)?;
    let process =
        CacheProcess::with_sentinel(pid, started_unix_ms, process_lock_file, process_lock_path);
    registry.insert(canonical_state_root.to_path_buf(), Arc::downgrade(&process));
    Ok((process, true))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn copy_path_to_staging_and_hash(source: &Path, tmp: &Path) -> Result<(String, u64)> {
    let result = (|| -> Result<(String, u64)> {
        let mut input = File::open(source).map_err(map_io)?;
        let mut output = File::create(tmp).map_err(map_io)?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buf = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buf).map_err(map_io)?;
            if read == 0 {
                break;
            }
            output.write_all(&buf[..read]).map_err(map_io)?;
            hasher.update(&buf[..read]);
            size = size.saturating_add(read as u64);
        }
        output.sync_all().map_err(map_io)?;
        let digest = hasher.finalize();
        Ok((hex_bytes(&digest), size))
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn map_io(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

fn map_sql(error: rusqlite::Error) -> Error {
    Error::new(ErrorCode::StateRootUnavailable, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_test_cache<F, T>(f: F) -> std::thread::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        std::thread::Builder::new()
            .name("ovs-test-cache".into())
            .spawn(f)
            .expect("failed to spawn thread")
    }

    #[test]
    fn cache_round_trips_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let cache_root = temp.path().join("cache");
        let config = CacheConfig {
            state_root,
            cache_root,
        };

        let cache = Cache::open(config.clone()).unwrap();
        let entry = cache.put("file:/tmp/object", b"hello cache").unwrap();
        assert!(entry.path.exists());
        assert_eq!(
            cache.get("file:/tmp/object").unwrap(),
            Some(b"hello cache".to_vec())
        );
        drop(cache);

        let reopened = Cache::open(config).unwrap();
        assert_eq!(
            reopened.get("file:/tmp/object").unwrap(),
            Some(b"hello cache".to_vec())
        );
        reopened.remove_index("file:/tmp/object").unwrap();
        assert_eq!(reopened.get("file:/tmp/object").unwrap(), None);
    }

    #[test]
    fn cache_put_path_and_lease_streams_source_file() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let source = temp.path().join("source.bin");
        fs::write(&source, b"source bytes").unwrap();

        let put = cache
            .put_path_and_lease("file:/tmp/source", &source)
            .unwrap();

        assert_eq!(put.entry.size, b"source bytes".len() as u64);
        assert!(put.lease.is_some());
        assert_eq!(
            cache.get("file:/tmp/source").unwrap(),
            Some(b"source bytes".to_vec())
        );
    }

    #[test]
    fn cache_removes_prefix_entries() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        cache.put("file\0file:/root/a.txt", b"a").unwrap();
        cache.put("file\0file:/root/dir/b.txt", b"b").unwrap();
        cache.put("file\0file:/root-other/c.txt", b"c").unwrap();

        cache.remove_prefix("file\0file:/root/").unwrap();
        assert_eq!(cache.get("file\0file:/root/a.txt").unwrap(), None);
        assert_eq!(cache.get("file\0file:/root/dir/b.txt").unwrap(), None);
        assert_eq!(
            cache.get("file\0file:/root-other/c.txt").unwrap(),
            Some(b"c".to_vec())
        );
    }

    #[test]
    fn cache_quarantines_corrupt_bytes_and_self_heals_on_next_read() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file:/tmp/object", b"good").unwrap();
        fs::write(&entry.path, b"bad").unwrap();
        assert_eq!(cache.get("file:/tmp/object").unwrap(), None);
        assert!(!entry.path.exists());
        assert!(cache.entry("file:/tmp/object").unwrap().is_none());
        let conn = cache.conn().unwrap();
        let cache_entries: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cache_entries, 0);
    }

    #[test]
    fn cache_evicts_least_recently_used_entries_to_max_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            },
            CacheOptions {
                max_bytes: Some(5),
                refuse_network_filesystems: false,
                ..CacheOptions::default()
            },
        )
        .unwrap();
        cache.put("a", b"aaaa").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.put("b", b"bbbb").unwrap();

        assert_eq!(cache.get("a").unwrap(), None);
        assert_eq!(cache.get("b").unwrap(), Some(b"bbbb".to_vec()));
        let status = cache.status().unwrap();
        assert_eq!(status.entries, 1);
        assert_eq!(status.total_bytes, 4);
    }

    #[test]
    fn cache_cleans_staging_on_open_and_reports_status() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let cache_root = temp.path().join("cache");
        let staging = cache_root.join("staging");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("orphan.tmp"), b"partial").unwrap();

        let cache = Cache::open(CacheConfig {
            state_root,
            cache_root,
        })
        .unwrap();
        let status = cache.status().unwrap();
        assert_eq!(status.staging_files, 0);
        assert_eq!(status.live_process_leases, 1);
    }

    #[test]
    fn cache_refuses_network_roots_when_requested() {
        let result = Cache::open_with_options(
            CacheConfig {
                state_root: PathBuf::from("\\\\server\\share\\state"),
                cache_root: PathBuf::from("\\\\server\\share\\cache"),
            },
            CacheOptions {
                max_bytes: None,
                refuse_network_filesystems: true,
                ..CacheOptions::default()
            },
        );
        let err = match result {
            Ok(_) => panic!("network roots should be refused"),
            Err(error) => error,
        };
        assert_eq!(err.code(), ErrorCode::NetworkFilesystemRefused);
    }

    #[test]
    fn cache_herd_lock_serializes_threads_in_process() {
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
        for _ in 0..4 {
            let cache = cache.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            threads.push(spawn_test_cache(move || {
                cache
                    .with_herd_lock("same-key", || {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_open_renames_legacy_sqlite_path() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let cache_root = temp.path().join("cache");
        std::fs::create_dir_all(&state_root).unwrap();

        // Seed a legacy `cache.sqlite` mimicking a pre-rename DB.
        let legacy_path = state_root.join("cache.sqlite");
        {
            let conn = rusqlite::Connection::open(&legacy_path).unwrap();
            conn.execute_batch(
                "
                CREATE TABLE entries (
                    resolved_target TEXT PRIMARY KEY NOT NULL,
                    cas_key         TEXT NOT NULL,
                    size            INTEGER NOT NULL,
                    updated_unix_ms INTEGER NOT NULL,
                    last_access_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE process_leases (
                    pid             INTEGER NOT NULL,
                    started_unix_ms INTEGER NOT NULL,
                    state_root      TEXT NOT NULL,
                    PRIMARY KEY (pid, started_unix_ms)
                );
                ",
            )
            .unwrap();
        }
        assert!(legacy_path.exists());
        assert!(!state_root.join("index.sqlite").exists());

        let cache = Cache::open(CacheConfig {
            state_root: state_root.clone(),
            cache_root,
        })
        .unwrap();
        assert!(!legacy_path.exists());
        assert!(state_root.join("index.sqlite").exists());
        let conn = cache.conn().unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'cache_entries'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn herd_key_flavors_hash_into_disjoint_lock_spaces() {
        let prefix = "test://root/key".to_string();
        let current = HerdKey::Current {
            prefix: prefix.clone(),
        };
        let guarded = HerdKey::Guarded {
            prefix: prefix.clone(),
            etag: "abc123".into(),
        };
        let exact = HerdKey::Exact {
            prefix: prefix.clone(),
            version_or_cas: "v1".into(),
        };
        assert_ne!(current.as_lock_key(), guarded.as_lock_key());
        assert_ne!(current.as_lock_key(), exact.as_lock_key());
        assert_ne!(guarded.as_lock_key(), exact.as_lock_key());
        let current_again = HerdKey::Current { prefix };
        assert_eq!(current.as_lock_key(), current_again.as_lock_key());
    }

    #[test]
    fn typed_herd_lock_serializes_same_flavor_different_callers() {
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
        let key = HerdKey::Current {
            prefix: "test://shared/object".into(),
        };
        for _ in 0..4 {
            let cache = cache.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            let key = key.clone();
            threads.push(spawn_test_cache(move || {
                cache
                    .with_typed_herd_lock(&key, || {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_lease_blocks_eviction_until_drop() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            },
            CacheOptions {
                max_bytes: Some(5),
                ..CacheOptions::default()
            },
        )
        .unwrap();
        let entry = cache.put("pinned", b"aaaa").unwrap();
        let lease = cache.lease(&entry.cas_key).unwrap();
        assert!(lease.is_some(), "lease minted on existing CAS key");
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.put("evictable", b"bbbb").unwrap();
        assert!(
            cache.get("pinned").unwrap().is_some(),
            "pinned survives eviction pressure"
        );
        drop(lease);
        cache.put("trigger", b"cccc").unwrap();
        let count = cache.status().unwrap().entries;
        assert!(count <= 2, "eviction kicks in once leases drop: {count}");
    }

    #[test]
    fn cache_lease_returns_none_for_missing_cas_key() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        assert!(cache.lease("does-not-exist").unwrap().is_none());
    }

    #[test]
    fn cache_lookup_returns_cached_object_with_lease() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        cache.put("file://a", b"hello").unwrap();
        let lookup = cache.lookup("file://a").unwrap().unwrap();
        assert_eq!(lookup.cached.bytes, b"hello");
        assert!(lookup.lease.is_some());
    }

    #[test]
    fn cache_doctor_reports_missing_cas_files() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://a", b"hello").unwrap();
        fs::remove_file(&entry.path).unwrap();
        let outcome = cache.doctor().unwrap();
        assert_eq!(outcome.missing_cas_removed, 1);
        // Doctor is dry-run — the row stays.
        assert!(cache.entry("file://a").unwrap().is_some());
        let outcome = cache.recover().unwrap();
        assert_eq!(outcome.missing_cas_removed, 1);
        assert!(cache.entry("file://a").unwrap().is_none());
    }

    #[test]
    fn cache_read_only_mode_refuses_writes() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            },
            CacheOptions {
                coordination: CacheCoordination::ReadOnly,
                ..CacheOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            cache.put("file://a", b"x").unwrap_err().code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            cache
                .put_with_existing_key_lock("file://a", b"x")
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            cache.remove_index("file://a").unwrap_err().code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            cache.remove_prefix("file://").unwrap_err().code(),
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn remove_index_prunes_unreferenced_cas_file_and_row() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://a", b"alpha").unwrap();
        assert!(entry.path.exists());
        cache.remove_index("file://a").unwrap();
        assert!(!entry.path.exists());
        let conn = cache.conn().unwrap();
        let cache_entries: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cache_entries, 0);
    }

    #[test]
    fn remove_index_keeps_cas_file_when_other_target_references_it() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let first = cache.put("file://a", b"shared").unwrap();
        let second = cache.put("file://b", b"shared").unwrap();
        assert_eq!(first.cas_key, second.cas_key);
        cache.remove_index("file://a").unwrap();
        assert!(first.path.exists());
        assert_eq!(cache.get("file://b").unwrap(), Some(b"shared".to_vec()));
    }

    #[test]
    fn remove_prefix_prunes_unreferenced_cas_files() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let a = cache.put("test://root/a", b"aaa").unwrap();
        let b = cache.put("test://root/b", b"bbb").unwrap();
        let c = cache.put("test://other/c", b"ccc").unwrap();
        cache.remove_prefix("test://root/").unwrap();
        assert!(!a.path.exists());
        assert!(!b.path.exists());
        assert!(c.path.exists());
    }

    #[test]
    fn recover_reaps_orphaned_cache_entries_rows() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        {
            let conn = cache.conn().unwrap();
            conn.execute(
                "INSERT INTO cache_entries (cas_key, size, lease_count) VALUES ('orphaned', 4, 0)",
                [],
            )
            .unwrap();
        }
        cache.recover().unwrap();
        let conn = cache.conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = 'orphaned'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn lease_returns_none_when_cas_file_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://x", b"hello").unwrap();
        fs::remove_file(&entry.path).unwrap();
        assert!(cache.lease(&entry.cas_key).unwrap().is_none());
    }

    #[test]
    fn recover_preserves_lease_count_when_sibling_cache_holds_lease() {
        let temp = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        };
        let first = Cache::open(config.clone()).unwrap();
        let entry = first.put("file://pinned", b"pinned-bytes").unwrap();
        let lease = first.lease(&entry.cas_key).unwrap().expect("lease minted");
        let second = Cache::open(config).unwrap();
        let conn = second.conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT lease_count FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);
        assert_eq!(
            count, 1,
            "subsequent open in same process must not reset lease_count of a sibling's live lease",
        );
        drop(lease);
        drop(first);
        drop(second);
    }

    #[test]
    fn lease_drop_reaps_orphaned_cache_entries_after_invalidation() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://t", b"orphan-bytes").unwrap();
        let lease = cache.lease(&entry.cas_key).unwrap().expect("lease minted");
        cache.remove_index("file://t").unwrap();
        assert!(
            entry.path.exists(),
            "pinned CAS file must survive invalidation while a lease is held",
        );
        {
            let conn = cache.conn().unwrap();
            let cache_entries: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                    params![entry.cas_key],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(cache_entries, 1, "cache_entries row deferred to lease drop");
        }
        drop(lease);
        let conn = cache.conn().unwrap();
        let cache_entries: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            cache_entries, 0,
            "lease drop must reap the orphaned cache_entries row",
        );
        assert!(
            !entry.path.exists(),
            "lease drop must unlink the orphaned CAS file",
        );
    }

    #[test]
    fn lookup_pins_local_path_against_eviction_pressure() {
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
        cache.put("file://a", b"AAAA").unwrap();
        let lookup = cache.lookup("file://a").unwrap().expect("hit");
        assert!(lookup.lease.is_some(), "lookup must pair with a lease");
        let pinned_path = lookup.cached.entry.path.clone();
        assert!(pinned_path.exists());
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.put("file://b", b"BBBB").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.put("file://c", b"CCCC").unwrap();
        assert!(
            pinned_path.exists(),
            "lookup-returned path must survive eviction pressure",
        );
        drop(lookup);
        cache.put("file://d", b"DDDD").unwrap();
        let total = cache.status().unwrap().total_bytes;
        assert!(total <= 8, "byte budget enforced after lookup drop");
    }

    #[test]
    fn cas_publish_is_race_idempotent_across_writers() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );
        let bytes: &'static [u8] = b"shared-cas-bytes";
        let mut handles = Vec::new();
        for i in 0..4 {
            let cache = cache.clone();
            let target = format!("test://routes/{i}");
            handles.push(spawn_test_cache(move || cache.put(&target, bytes).unwrap()));
        }
        let entries: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let cas_key = entries[0].cas_key.clone();
        for entry in &entries {
            assert_eq!(entry.cas_key, cas_key);
            assert!(entry.path.exists());
        }
        let on_disk = fs::read(&entries[0].path).unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn cache_observer_receives_hit_miss_fill_eviction_events() {
        use std::sync::Mutex;

        struct Recorder {
            events: Mutex<Vec<&'static str>>,
        }
        impl Observer for Recorder {
            fn on_lookup(&self, outcome: LookupOutcome) {
                self.events.lock().unwrap().push(match outcome {
                    LookupOutcome::Hit => "hit",
                    LookupOutcome::Miss => "miss",
                    _ => "other",
                });
            }
            fn on_fill(&self, _o: FillOutcome, _b: u64, _e: std::time::Duration) {
                self.events.lock().unwrap().push("fill");
            }
            fn on_eviction(&self, _r: EvictionReason, _b: u64) {
                self.events.lock().unwrap().push("eviction");
            }
        }
        let recorder = Arc::new(Recorder {
            events: Mutex::new(Vec::new()),
        });
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            },
            CacheOptions {
                max_bytes: Some(5),
                observer: Some(recorder.clone()),
                ..CacheOptions::default()
            },
        )
        .unwrap();
        let _ = cache.get("missing");
        cache.put("file://a", b"aaaa").unwrap();
        let _ = cache.get("file://a");
        std::thread::sleep(std::time::Duration::from_millis(2));
        cache.put("file://b", b"bbbb").unwrap();
        let events = recorder.events.lock().unwrap();
        assert!(events.contains(&"miss"));
        assert!(events.contains(&"hit"));
        assert!(events.contains(&"fill"));
        assert!(events.contains(&"eviction"));
    }

    #[test]
    fn cache_open_creates_index_sqlite_for_fresh_state_root() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        assert!(temp.path().join("state").join("index.sqlite").exists());
        assert!(!temp.path().join("state").join("cache.sqlite").exists());
        let conn = cache.conn().unwrap();
        let version: i64 = conn
            .query_row(
                "SELECT version FROM schema_version WHERE rowid = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    /// Publish-before-durable regression: a failed `entries` INSERT
    /// must not leave a CAS file the index has no record of —
    /// eviction walks `entries`, so an orphan file would leak forever.
    #[test]
    fn put_does_not_orphan_cas_file_when_index_insert_fails() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let cache_root = temp.path().join("cache");
        let cache = Cache::open(CacheConfig {
            state_root: state_root.clone(),
            cache_root: cache_root.clone(),
        })
        .unwrap();

        // Drop the `entries` table from a side connection so the
        // INSERT in `put_locked` fails. Real production failures
        // (disk-full, schema mismatch, locked DB) take the same path.
        let side = rusqlite::Connection::open(state_root.join("index.sqlite")).unwrap();
        side.execute("DROP TABLE entries", []).unwrap();
        drop(side);

        let bytes: &[u8] = b"orphan-test-bytes";
        let result = cache.put("file:///orphan-key", bytes);
        assert!(
            result.is_err(),
            "put should fail when the INSERT cannot find the entries table"
        );

        let cas_key = sha256_hex(bytes);
        let cas_file = cas_path(&cache_root, &cas_key).unwrap();
        assert!(
            !cas_file.exists(),
            "publish-before-durable: orphan CAS file at {} (eviction would never see this)",
            cas_file.display()
        );

        // The staging tmp is cleaned up on the failure path.
        let staging = state_root.join("staging");
        if staging.exists() {
            let leftovers: Vec<_> = fs::read_dir(&staging)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(
                leftovers.is_empty(),
                "staging tmp file leaked after failed put: {leftovers:?}"
            );
        }
    }
}
