// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use ovstorage_layer::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::coordination::CacheCoordination;
use crate::errors::map_sql;
use crate::fs_probe::{self, FsKind};
use crate::lease::{CacheProcess, Lease};
use crate::migrations;
use crate::observer::{EvictionReason, FillOutcome, LookupOutcome, Observer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    pub state_root: PathBuf,
    pub cache_root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteCacheEntry {
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
pub struct ByteCacheObject {
    pub entry: ByteCacheEntry,
    pub bytes: Vec<u8>,
}

/// Precondition on an index publish: the compare half of a compare-and-swap,
/// evaluated inside the same SQLite transaction as the write half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishGuard<'a> {
    /// Publish unconditionally.
    Always,
    /// Publish only while the row's current `cas_key` equals this value;
    /// `None` requires the row to be absent.
    IfCurrent(Option<&'a str>),
}

#[derive(Clone, Default)]
pub struct CacheOptions {
    pub max_bytes: Option<u64>,
    pub refuse_network_filesystems: bool,
    pub coordination: CacheCoordination,
    /// Optional metric/tracing hook. `None` short-circuits with no allocations.
    pub observer: Option<Arc<dyn Observer>>,
    /// Re-hash every blob on every read to detect bit-rot. Off by default;
    /// the size check alone is sufficient for normal operation and the
    /// SHA-256 over a large file on every lookup is prohibitively expensive.
    pub verify_checksums_on_read: bool,
    /// Max concurrent in-flight streaming fills ([`Cache::begin_streaming_put`])
    /// this cache admits. `None` uses `DEFAULT_MAX_STREAMING_FILLS`. Once the
    /// limit is reached `begin_streaming_put` returns `Err`, which the tee
    /// caller degrades to serving the object uncached — bounding the staging
    /// FDs/bytes N concurrent callers can pin regardless of `max_object_bytes`.
    pub max_streaming_fills: Option<usize>,
    /// Aggregate on-disk staging-byte budget shared across all in-flight
    /// streaming fills. `None` derives it from `max_bytes` (half the cache cap)
    /// or `DEFAULT_STREAMING_STAGING_BYTES` when the cache is uncapped. A
    /// `write_chunk` that would push total in-flight staging past this budget
    /// fails the fill so the tee is abandoned and the object served uncached.
    pub max_streaming_staging_bytes: Option<u64>,
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
            .field("verify_checksums_on_read", &self.verify_checksums_on_read)
            .field("max_streaming_fills", &self.max_streaming_fills)
            .field(
                "max_streaming_staging_bytes",
                &self.max_streaming_staging_bytes,
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
            && self.verify_checksums_on_read == other.verify_checksums_on_read
            && self.max_streaming_fills == other.max_streaming_fills
            && self.max_streaming_staging_bytes == other.max_streaming_staging_bytes
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
pub struct ByteCacheStatus {
    pub state_root: PathBuf,
    pub cache_root: PathBuf,
    pub entries: u64,
    pub total_bytes: u64,
    pub live_process_leases: u64,
    pub staging_files: u64,
    pub max_bytes: Option<u64>,
}

/// Phase reported to a dependent test by [`CompareAndPutSeam`].
#[cfg(any(test, feature = "test-seams"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareAndPutPhase {
    /// The advisory read matched, immediately before the guarded write.
    Observed,
    /// The guarded write and its CAS-file publication completed successfully.
    Published,
}

/// Test-only interposition invoked with the contested key around the guarded
/// write in [`ByteCache::compare_and_put`].
#[cfg(any(test, feature = "test-seams"))]
pub type CompareAndPutSeam = Arc<dyn Fn(&str, CompareAndPutPhase) + Send + Sync>;

/// Test-only interposition invoked after [`ByteCache::remove_index_returning`]
/// commits the row removal and before it returns the removed value.
#[cfg(any(test, feature = "test-seams"))]
pub type RemoveIndexReturningSeam = Arc<dyn Fn(&str) + Send + Sync>;

/// Test-only interposition invoked with the key being reclaimed, at the point
/// inside `reclaim_unreferenced_cas` between the reference check and the
/// unlink. See [`ByteCache::reclaim_seam`].
#[cfg(test)]
type ReclaimSeam = Arc<dyn Fn(&str) + Send + Sync>;

pub struct ByteCache {
    state_root: PathBuf,
    cache_root: PathBuf,
    staging_root: PathBuf,
    locks_root: PathBuf,
    max_bytes: Option<u64>,
    process_started_unix_ms: i64,
    conn: Mutex<Connection>,
    key_locks: Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
    /// Sentinel cloned into every `Lease` so a live lease keeps the
    /// `<state_root>/processes/<pid>.lock` flock alive.
    process: Arc<CacheProcess>,
    coordination: CacheCoordination,
    verify_checksums_on_read: bool,
    /// `Some` only in `SharedSingleWriter`; dropped to release the rendezvous.
    _writer_rendezvous: Option<File>,
    observer: Option<Arc<dyn Observer>>,
    /// Shared in-process budget bounding concurrent streaming fills and their
    /// aggregate on-disk staging bytes (single-process scope).
    streaming_budget: Arc<StreamingBudget>,
    /// Exclusive flock on this instance's staging-dir owner sentinel
    /// (`<staging_root>/.owner`). Held for the cache's lifetime so a sibling
    /// open's `sweep_orphan_staging` treats this instance's dir as live and
    /// never reaps it; released on drop, after which the freed sentinel lets a
    /// later run reclaim the dir regardless of PID.
    _staging_owner_lock: File,
    /// Test-only interposition fired inside [`Self::compare_and_put`] after the
    /// row's current value has been observed and before it is written, so a
    /// test can land a competing mutation in exactly that window.
    #[cfg(any(test, feature = "test-seams"))]
    compare_and_put_seam: Mutex<Option<CompareAndPutSeam>>,
    /// Test-only interposition fired after [`Self::remove_index_returning`]
    /// commits its row removal and before its detached caller can continue
    /// with cleanup derived from the removed value.
    #[cfg(any(test, feature = "test-seams"))]
    remove_index_returning_seam: Mutex<Option<RemoveIndexReturningSeam>>,
    /// Test-only interposition fired inside [`Self::reclaim_unreferenced_cas`]
    /// after the reference check and before the unlink, so a test can land a
    /// competing publication in exactly that window.
    #[cfg(test)]
    reclaim_seam: Mutex<Option<ReclaimSeam>>,
}

pub type Cache = ByteCache;
pub type CacheEntry = ByteCacheEntry;
pub type CacheLookup = ByteCacheLookup;
pub type CachePut = ByteCachePut;
pub type CacheStatus = ByteCacheStatus;
pub type CachedObject = ByteCacheObject;

impl ByteCache {
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
        let staging_parent = config.cache_root.join("staging");
        let locks_root = config.state_root.join("locks");
        let processes_root = config.state_root.join("processes");
        fs::create_dir_all(&staging_parent).map_err(map_io)?;
        fs::create_dir_all(&locks_root).map_err(map_io)?;
        fs::create_dir_all(&processes_root).map_err(map_io)?;
        // Instance-scoped staging dir: a sibling cache opening against the same
        // roots must not wipe this instance's live staging files (an in-flight
        // `StreamingPut`). Sweep only loose legacy orphans and instance dirs
        // owned by a provably-dead process — never a live instance's dir.
        sweep_orphan_staging(&staging_parent, &processes_root)?;
        let staging_root = staging_parent.join(instance_staging_name());
        fs::create_dir_all(&staging_root).map_err(map_io)?;
        // Per-instance ownership sentinel: the flock we hold marks this dir as
        // live so a sibling open's sweep spares it; a crashed run's sentinel is
        // free and reclaimable independent of PID (fixes the fixed-PID leak).
        let staging_owner_lock = acquire_staging_owner_lock(&staging_root)?;
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
            -- Sibling processes share one state_root (a broker and a CLI, say),
            -- and the compare-and-swap below takes the write lock at BEGIN, so
            -- ordinary contention needs a bounded wait rather than an immediate
            -- SQLITE_BUSY to whichever process arrives second.
            PRAGMA busy_timeout = 5000;
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
            CacheCoordination::SharedSingleWriter => Some(
                crate::coordination::acquire_writer_rendezvous(&config.cache_root)?,
            ),
            CacheCoordination::HostExclusive | CacheCoordination::ReadOnly => None,
        };

        // Staging budget: cap concurrent fills and their aggregate staging
        // bytes. The byte budget defaults to half the cache cap (leaving room
        // for the CAS the fills publish into) or a fixed cap when uncapped, so
        // an uncapped cache never implies unbounded staging.
        let streaming_budget = Arc::new(StreamingBudget::new(
            options
                .max_streaming_fills
                .unwrap_or(DEFAULT_MAX_STREAMING_FILLS),
            options
                .max_streaming_staging_bytes
                .unwrap_or_else(|| streaming_staging_budget_default(options.max_bytes)),
        ));

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
            verify_checksums_on_read: options.verify_checksums_on_read,
            _writer_rendezvous: writer_rendezvous,
            observer: options.observer,
            streaming_budget,
            _staging_owner_lock: staging_owner_lock,
            #[cfg(any(test, feature = "test-seams"))]
            compare_and_put_seam: Mutex::new(None),
            #[cfg(any(test, feature = "test-seams"))]
            remove_index_returning_seam: Mutex::new(None),
            #[cfg(test)]
            reclaim_seam: Mutex::new(None),
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

    pub fn status(&self) -> Result<ByteCacheStatus> {
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
        Ok(ByteCacheStatus {
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

    pub fn put(&self, resolved_target: &str, bytes: &[u8]) -> Result<ByteCacheEntry> {
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
    ) -> Result<ByteCacheEntry> {
        self.ensure_writable()?;
        self.put_locked(resolved_target, bytes)
    }

    /// Fill + lease in one call. The paired [`Lease`] pins the CAS
    /// file so the caller can hand `entry.path` to a downstream
    /// reader without racing eviction.
    pub fn put_and_lease(&self, resolved_target: &str, bytes: &[u8]) -> Result<ByteCachePut> {
        let entry = self.put(resolved_target, bytes)?;
        let lease = self.lease(&entry.cas_key)?;
        Ok(ByteCachePut { entry, lease })
    }

    /// Fill from an existing local file + lease in one call. The file
    /// is copied into cache staging while hashing, then published into
    /// CAS without loading the whole body into memory.
    pub fn put_path_and_lease(&self, resolved_target: &str, source: &Path) -> Result<ByteCachePut> {
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
        Ok(ByteCachePut { entry, lease })
    }

    /// Begin a streaming fill for `resolved_target`. Chunks written through the
    /// returned [`StreamingPut`] spool to a cache staging file (hashed
    /// incrementally); the `entries`/CAS row is published only on
    /// [`StreamingPut::commit`]. This is the streaming counterpart of
    /// [`put`](Self::put)/[`put_path_and_lease`](Self::put_path_and_lease) — a
    /// caller can tee an object's read stream into the cache without ever
    /// holding the whole body in memory. `max_bytes` caps the object size: a
    /// write past it fails the fill and the staging file is discarded on drop,
    /// so an over-cap object never allocates a whole-object buffer and never
    /// leaves a half-cached row.
    pub fn begin_streaming_put(
        self: &Arc<Self>,
        resolved_target: &str,
        max_bytes: Option<u64>,
    ) -> Result<StreamingPut> {
        self.ensure_writable()?;
        // Reserve an in-flight fill slot against the shared budget before
        // spooling anything. At the concurrency limit this returns `Err`, which
        // the tee caller degrades to serving uncached — the reservation (and
        // any bytes it later charges) is released on `StreamingPut`/`Drop`.
        let reservation = self.streaming_budget.try_acquire().ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "streaming cache fill concurrency limit reached; serving uncached",
            )
        })?;
        fs::create_dir_all(&self.staging_root).map_err(map_io)?;
        let now = unix_ms();
        let tmp = self.streaming_staging_path(resolved_target, now);
        let file = File::create(&tmp).map_err(map_io)?;
        Ok(StreamingPut {
            cache: Arc::clone(self),
            resolved_target: resolved_target.to_string(),
            tmp,
            file: Some(file),
            hasher: Sha256::new(),
            size: 0,
            max_bytes,
            started: std::time::Instant::now(),
            fill_reported: false,
            reservation,
        })
    }

    fn put_locked(&self, resolved_target: &str, bytes: &[u8]) -> Result<ByteCacheEntry> {
        self.ensure_writable()?;
        let now = unix_ms();
        let cas_key = sha256_hex(bytes);
        fs::create_dir_all(&self.staging_root).map_err(map_io)?;
        let tmp = self.staging_path(resolved_target, now);
        write_staging_file(&tmp, bytes)?;
        let size = bytes.len() as u64;
        self.publish_staged_locked(resolved_target, cas_key, size, tmp, now)
    }

    fn put_path_locked(&self, resolved_target: &str, source: &Path) -> Result<ByteCacheEntry> {
        self.ensure_writable()?;
        let now = unix_ms();
        fs::create_dir_all(&self.staging_root).map_err(map_io)?;
        let tmp = self.staging_path(resolved_target, now);
        let (cas_key, size) = copy_path_to_staging_and_hash(source, &tmp)?;
        self.publish_staged_locked(resolved_target, cas_key, size, tmp, now)
    }

    fn staging_path(&self, resolved_target: &str, now: i64) -> PathBuf {
        self.staging_root.join(format!(
            "{}-{}-{}.tmp",
            std::process::id(),
            now,
            sha256_hex(resolved_target.as_bytes())
        ))
    }

    /// Per-fill-unique staging path for a streaming put. Unlike
    /// [`staging_path`](Self::staging_path) — reused safely by the locked
    /// `put`/`put_path` calls because they hold the key lock across the whole
    /// staging+publish — a streaming fill writes to its staging file *before*
    /// taking the key lock (the tee deliberately holds no stampede lock), so
    /// two concurrent same-key fills landing in the same millisecond would
    /// otherwise share and corrupt one file. A process-wide counter makes each
    /// fill's staging path unique.
    fn streaming_staging_path(&self, resolved_target: &str, now: i64) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        self.staging_root.join(format!(
            "{}-{}-{}-{}.stream.tmp",
            std::process::id(),
            now,
            sha256_hex(resolved_target.as_bytes()),
            seq
        ))
    }

    /// Publish a staged blob unconditionally as an evictable content row.
    fn publish_staged_locked(
        &self,
        resolved_target: &str,
        cas_key: String,
        size: u64,
        tmp: PathBuf,
        now: i64,
    ) -> Result<ByteCacheEntry> {
        self.put_staged_locked(
            resolved_target,
            cas_key,
            size,
            tmp,
            now,
            PublishGuard::Always,
        )?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "cache publish reported a refusal for an unguarded put",
            )
        })
    }

    /// Publish a staged blob under `resolved_target`. `guard` is evaluated
    /// inside the publishing transaction, so a compare-and-swap caller sees the
    /// compare and the write as one step against every other writer on this
    /// connection; `Ok(None)` means the guard refused and nothing was written.
    fn put_staged_locked(
        &self,
        resolved_target: &str,
        cas_key: String,
        size: u64,
        tmp: PathBuf,
        now: i64,
        guard: PublishGuard<'_>,
    ) -> Result<Option<ByteCacheEntry>> {
        let result = (|| -> Result<Option<ByteCacheEntry>> {
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
            let mut displaced: Option<String> = None;
            let tx_result = (|| -> Result<bool> {
                // IMMEDIATE takes the write lock before the guard's read, so
                // the compare and the write cannot be split by a writer on
                // another connection either.
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sql)?;
                if let PublishGuard::IfCurrent(expected) = guard {
                    let current: Option<String> = tx
                        .query_row(
                            "SELECT cas_key FROM entries WHERE resolved_target = ?1",
                            params![resolved_target],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(map_sql)?;
                    if current.as_deref() != expected {
                        // Dropping the transaction rolls back; nothing written.
                        return Ok(false);
                    }
                }
                // The blob this row is about to stop naming. Captured before
                // the upsert overwrites `cas_key`: nothing else ever revisits
                // it, so leaving it behind orphans the file outside both the
                // LRU (which walks `entries`) and the size budget.
                let superseded: Option<String> = tx
                    .query_row(
                        "SELECT cas_key FROM entries WHERE resolved_target = ?1",
                        params![resolved_target],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(map_sql)?;
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
                displaced = superseded.filter(|key| *key != cas_key);
                tx.commit().map_err(map_sql)?;
                Ok(true)
            })();
            let published = match tx_result {
                Ok(published) => published,
                Err(error) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(error);
                }
            };
            if !published {
                drop(conn);
                let _ = fs::remove_file(&tmp);
                return Ok(None);
            }

            // Publish the blob while still holding the connection. That
            // excludes readers on THIS `Cache` instance from the window where
            // the committed row names a file that is not there yet -- such a
            // reader would treat the row as orphaned and delete it, dropping a
            // row this call is about to report as published.
            //
            // It does not exclude another process or another `Cache` over the
            // same roots: `conn` is a process-local mutex, and retaining the
            // connection after COMMIT does not retain the database write lock.
            // Those readers can still observe the window; the outcome is a
            // self-healed miss and an orphaned blob, never wrong bytes.
            publish_cas(&tmp, &path)?;
            // Reclaim the blob this row stopped naming. Done after the commit
            // and while still holding the connection, so the tracking row
            // outlives the unlink and a crash in between leaves something a
            // later pass can find.
            if let Some(displaced) = displaced {
                self.reclaim_best_effort(&conn, &displaced);
            }
            drop(conn);
            self.evict_to_limit()?;
            Ok(Some(ByteCacheEntry {
                resolved_target: resolved_target.to_string(),
                cas_key,
                size,
                path,
            }))
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
    ) -> Result<Option<ByteCacheObject>> {
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
    pub fn get_entry(&self, resolved_target: &str) -> Result<Option<ByteCacheObject>> {
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

    fn get_entry_inner(&self, resolved_target: &str) -> (Result<Option<ByteCacheObject>>, bool) {
        let entry = match self.entry(resolved_target) {
            Ok(Some(entry)) => entry,
            Ok(None) => return (Ok(None), false),
            Err(error) => return (Err(error), false),
        };
        match fs::read(&entry.path) {
            Ok(bytes) => {
                if bytes.len() as u64 != entry.size
                    || (self.verify_checksums_on_read && sha256_hex(&bytes) != entry.cas_key)
                {
                    let result = self.quarantine_corrupt(&entry);
                    return match result {
                        Ok(()) => (Ok(None), true),
                        Err(error) => (Err(error), true),
                    };
                }
                match self.touch(resolved_target) {
                    Ok(()) => (Ok(Some(ByteCacheObject { entry, bytes })), false),
                    Err(error) => (Err(error), false),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Backing file is gone (external deletion, or purged while a
                // sibling target sharing this CAS blob was quarantined). Drop
                // the orphaned row so it stops counting toward cache size and
                // the lookup self-heals to a clean miss rather than lingering
                // forever. Best-effort: a read-only cache can't delete.
                let _ = self.drop_orphan_entry(&entry);
                (Ok(None), false)
            }
            Err(error) => (Err(map_io(error)), false),
        }
    }

    /// Remove an `entries` row whose backing CAS file has vanished.
    fn drop_orphan_entry(&self, entry: &ByteCacheEntry) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM entries WHERE resolved_target = ?1",
            params![entry.resolved_target],
        )
        .map_err(map_sql)?;
        // Deliberately does NOT reclaim the blob. This runs because a reader
        // found the file missing, and "missing" has two causes: already
        // reclaimed, or not linked yet -- publication commits its rows before
        // it links. Dropping `cache_entries` here on the second cause leaves
        // the publisher's blob with no rows at all once it does link:
        // unbudgeted, invisible to recovery's orphan sweep, permanent, and
        // driven by read traffic so it compounds.
        //
        // Leaving the tracking row is safe either way. A genuinely absent blob
        // has its row reclaimed by recovery at next open -- once per process
        // rather than once per read -- and a mid-flight one is superseded by
        // the publisher's own rows.
        Ok(())
    }

    fn quarantine_corrupt(&self, entry: &ByteCacheEntry) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM entries WHERE resolved_target = ?1",
            params![entry.resolved_target],
        )
        .map_err(map_sql)?;
        // A content-hash mismatch means the CAS *file* is bad, so every other
        // `entries` row sharing this cas_key is equally corrupt. Purge the file
        // + cache_entries row regardless of those references (unless an active
        // lease pins it); the siblings then self-heal via the NotFound path on
        // next access instead of each re-detecting the corruption.
        self.purge_corrupt_cas(&conn, &entry.cas_key)?;
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
                    // `reclaim_unreferenced_cas` short-circuited on the
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
                            // Unlink before untracking, as everywhere else:
                            // `cache_entries` is the only record the blob
                            // exists, so dropping it while the file is still
                            // there strands the blob past recovery's orphan
                            // sweep and outside the size budget. Keeping the
                            // row when the unlink fails leaves a later pass
                            // something to retry.
                            let unlinked = match cas_path(&cache_root, &cas_key_owned) {
                                Ok(path) => match fs::remove_file(path) {
                                    Ok(()) => true,
                                    Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                                },
                                Err(_) => false,
                            };
                            if unlinked {
                                let _ = conn.execute(
                                    "DELETE FROM cache_entries WHERE cas_key = ?1",
                                    params![cas_key_owned],
                                );
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
    pub fn lookup(&self, resolved_target: &str) -> Result<Option<ByteCacheLookup>> {
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
            Some(cached) => Ok(Some(ByteCacheLookup {
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

    pub fn entry(&self, resolved_target: &str) -> Result<Option<ByteCacheEntry>> {
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
                    Ok(ByteCacheEntry {
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
            // Best-effort: the row is already gone, which is the whole of the
            // caller's invalidation. A blob that cannot be unlinked keeps its
            // tracking row, so recovery retries it.
            self.reclaim_best_effort(&conn, &key);
        }
        Ok(())
    }

    /// Remove `resolved_target` and return the exact object its row named.
    ///
    /// The row read and delete share one IMMEDIATE transaction, so a sibling
    /// writer cannot replace the row between them. This is the removal
    /// counterpart of [`Self::compare_and_put`] for callers whose cleanup
    /// depends on the value they actually made unreachable rather than on an
    /// earlier observation.
    ///
    /// This operation is intended only for small index values. It reads and
    /// verifies the blob while holding the cache's single SQLite connection
    /// and an IMMEDIATE transaction so neither an in-process operation nor a
    /// sibling process can reclaim or replace the selected value. Do not use
    /// it to return object bodies.
    ///
    /// A missing or unreadable CAS file fails without deleting the row. A
    /// caller that must invalidate even under that corruption can fall back to
    /// [`Self::remove_index`], but cannot safely infer the missing value.
    pub fn remove_index_returning(&self, resolved_target: &str) -> Result<Option<ByteCacheObject>> {
        self.ensure_writable()?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let stored: Option<(String, u64)> = tx
            .query_row(
                "SELECT cas_key, size FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_sql)?;
        let Some((cas_key, size)) = stored else {
            return Ok(None);
        };
        let path = cas_path(&self.cache_root, &cas_key)?;
        let bytes = fs::read(&path).map_err(map_io)?;
        // Unlike an ordinary cache read, these bytes drive a destructive
        // secondary cleanup. A same-length corruption must not be parsed into
        // a key that deletes an unrelated content row, so integrity
        // verification is unconditional here.
        if bytes.len() as u64 != size || sha256_hex(&bytes) != cas_key {
            return Err(Error::new(
                ErrorCode::Internal,
                "cache row selected for removal names corrupt content",
            ));
        }
        tx.execute(
            "DELETE FROM entries WHERE resolved_target = ?1",
            params![resolved_target],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        self.reclaim_best_effort(&conn, &cas_key);
        drop(conn);
        #[cfg(any(test, feature = "test-seams"))]
        self.fire_remove_index_returning_seam(resolved_target);
        Ok(Some(ByteCacheObject {
            entry: ByteCacheEntry {
                resolved_target: resolved_target.to_string(),
                cas_key,
                size,
                path,
            },
            bytes,
        }))
    }

    /// Atomically set (`new = Some`) or remove (`new = None`) the `entries` row
    /// for `resolved_target` **iff its current value equals `expected`**,
    /// returning whether the swap was applied. The stored value is
    /// content-addressed, so the row's `cas_key` (`= sha256(bytes)`) identifies
    /// it exactly — the compare is by hash, no CAS file is read.
    /// `expected = None` means "the row must currently be absent";
    /// `new = None` removes it.
    ///
    /// The compare and the mutation run in one IMMEDIATE SQLite transaction, so
    /// they are indivisible with respect to every other row mutator —
    /// including the ones that take no per-key lock ([`Self::remove_index`],
    /// [`Self::remove_prefix`], size-pressure eviction). A removal landing
    /// between them therefore refuses the swap instead of letting it succeed
    /// against a value that is no longer current, which is what a caller
    /// building a read-modify-write on this (the byte-cache availability
    /// index's fenced publication) depends on.
    pub fn compare_and_put(
        &self,
        resolved_target: &str,
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<bool> {
        self.ensure_writable()?;
        // The key lock keeps two compare-and-swaps on the same key from
        // duplicating each other's staging work; correctness rests on the
        // transaction below, not on this lock.
        let _lock = self.lock_key(resolved_target)?;
        let expected_cas = expected.map(sha256_hex);
        match new {
            Some(bytes) => {
                // Advisory pre-check. Refusal is the common outcome for the
                // fenced publish this exists to serve, and staging costs a
                // create + write + fsync + unlink; a mismatch visible here is
                // one the transaction would refuse anyway. It is advisory
                // only — the in-transaction guard remains authoritative, so a
                // value that changes between the two is still caught.
                if self.current_cas_key(resolved_target)? != expected_cas {
                    return Ok(false);
                }
                // Test seam: the point AFTER the row's value has been observed
                // and BEFORE it is written. A check-then-act implementation
                // acts on the observation made above; this one re-derives it
                // inside the transaction below, so a mutation landing here
                // changes the outcome of exactly one of the two.
                #[cfg(any(test, feature = "test-seams"))]
                self.fire_compare_and_put_seam(resolved_target, CompareAndPutPhase::Observed);
                let now = unix_ms();
                let cas_key = sha256_hex(bytes);
                fs::create_dir_all(&self.staging_root).map_err(map_io)?;
                let tmp = self.staging_path(resolved_target, now);
                write_staging_file(&tmp, bytes)?;
                let published = self.put_staged_locked(
                    resolved_target,
                    cas_key,
                    bytes.len() as u64,
                    tmp,
                    now,
                    PublishGuard::IfCurrent(expected_cas.as_deref()),
                )?;
                #[cfg(any(test, feature = "test-seams"))]
                if published.is_some() {
                    self.fire_compare_and_put_seam(resolved_target, CompareAndPutPhase::Published);
                }
                Ok(published.is_some())
            }
            None => self.compare_and_remove(resolved_target, expected_cas.as_deref()),
        }
    }

    /// Run the registered compare-and-swap seam, if any.
    #[cfg(any(test, feature = "test-seams"))]
    fn fire_compare_and_put_seam(&self, resolved_target: &str, phase: CompareAndPutPhase) {
        let seam = self
            .compare_and_put_seam
            .lock()
            .ok()
            .and_then(|seam| seam.clone());
        if let Some(seam) = seam {
            seam(resolved_target, phase);
        }
    }

    /// Install a hook that runs at deterministic phases of each guarded write.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn set_compare_and_put_seam(&self, seam: CompareAndPutSeam) {
        *self.compare_and_put_seam.lock().expect("seam lock") = Some(seam);
    }

    /// Run the registered remove-and-return seam, if any.
    #[cfg(any(test, feature = "test-seams"))]
    fn fire_remove_index_returning_seam(&self, resolved_target: &str) {
        let seam = self
            .remove_index_returning_seam
            .lock()
            .ok()
            .and_then(|seam| seam.clone());
        if let Some(seam) = seam {
            seam(resolved_target);
        }
    }

    /// Install a hook that runs after an exact row removal commits.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn set_remove_index_returning_seam(&self, seam: RemoveIndexReturningSeam) {
        *self.remove_index_returning_seam.lock().expect("seam lock") = Some(seam);
    }

    /// The `cas_key` of `resolved_target`'s row, or `None` when it is absent.
    fn current_cas_key(&self, resolved_target: &str) -> Result<Option<String>> {
        self.conn()?
            .query_row(
                "SELECT cas_key FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql)
    }

    /// Remove `resolved_target`'s row iff its current `cas_key` equals
    /// `expected_cas`, in one transaction with the compare. The CAS blob is
    /// unlinked after the commit — a file removal cannot participate in the
    /// transaction, and an `entries` row is authoritative over the blob.
    fn compare_and_remove(
        &self,
        resolved_target: &str,
        expected_cas: Option<&str>,
    ) -> Result<bool> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT cas_key FROM entries WHERE resolved_target = ?1",
                params![resolved_target],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql)?;
        if current.as_deref() != expected_cas {
            return Ok(false);
        }
        let Some(cas_key) = current else {
            // The row is absent and the caller expected it absent: the
            // requested end state already holds.
            return Ok(true);
        };
        tx.execute(
            "DELETE FROM entries WHERE resolved_target = ?1",
            params![resolved_target],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        // After the commit: the blob's tracking row survives until its file is
        // gone, and a file removal cannot participate in the transaction. The
        // swap has already been applied, so reclamation cannot fail it.
        self.reclaim_best_effort(&conn, &cas_key);
        drop(conn);
        Ok(true)
    }

    /// Whether any row's key starts with `resolved_prefix`.
    ///
    /// A half-open range on the primary key, for the reason spelled out on
    /// [`Self::remove_prefix`]: a `LIKE` over a concatenation expression cannot
    /// use the index and full-scans `entries`.
    pub fn has_any_with_prefix(&self, resolved_prefix: &str) -> Result<bool> {
        let conn = self.conn()?;
        let upper = prefix_upper_bound(resolved_prefix);
        match &upper {
            // `CAST(?2 AS TEXT)` is load-bearing here too -- see
            // [`Self::remove_prefix`].
            Some(upper) => conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM entries \
                 WHERE resolved_target >= ?1 AND resolved_target < CAST(?2 AS TEXT))",
                params![resolved_prefix, upper],
                |row| row.get(0),
            ),
            None => conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE resolved_target >= ?1)",
                params![resolved_prefix],
                |row| row.get(0),
            ),
        }
        .map_err(map_sql)
    }

    pub fn remove_prefix(&self, resolved_prefix: &str) -> Result<()> {
        self.ensure_writable()?;
        let conn = self.conn()?;
        // A half-open range on the primary key, not `LIKE ?1 || '%'`: SQLite
        // cannot use the index for a LIKE whose pattern is a concatenation
        // expression, so that form full-scans `entries` on every call --
        // including the construction-time sweep of an abandoned namespace,
        // which then rescans a warm cache forever for rows that are already
        // gone. `prefix_upper_bound` is `None` only for a prefix with no
        // successor, which degrades to a scan from the prefix onward.
        let upper = prefix_upper_bound(resolved_prefix);
        let rows = {
            let mut statement = match &upper {
                // CAST(?2 AS TEXT) is load-bearing. The bound is bytes, so
                // rusqlite binds it as a BLOB, and SQLite orders every TEXT
                // before every BLOB -- an uncast comparison is therefore always
                // true and the range degenerates to [prefix, infinity). Column
                // affinity does not rescue it: SQLite's pre-comparison
                // conversions are INTEGER/REAL <-> TEXT only, never BLOB.
                Some(_) => conn.prepare(
                    "SELECT resolved_target, cas_key FROM entries \
                     WHERE resolved_target >= ?1 AND resolved_target < CAST(?2 AS TEXT)",
                ),
                None => conn.prepare(
                    "SELECT resolved_target, cas_key FROM entries \
                     WHERE resolved_target >= ?1",
                ),
            }
            .map_err(map_sql)?;
            let map_row =
                |row: &rusqlite::Row<'_>| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
            match &upper {
                Some(upper) => statement
                    .query_map(params![resolved_prefix, upper], map_row)
                    .map_err(map_sql)?
                    .collect::<std::result::Result<Vec<_>, _>>(),
                None => statement
                    .query_map(params![resolved_prefix], map_row)
                    .map_err(map_sql)?
                    .collect::<std::result::Result<Vec<_>, _>>(),
            }
            .map_err(map_sql)?
        };
        // The range narrows the scan; `starts_with` remains the authoritative
        // filter, since the bound is a byte successor rather than a
        // collation-aware one.
        // Every row is attempted even if one fails, and the rows that did
        // delete are still reclaimed. A caller's mutation has already committed
        // at the backend by the time this runs, so aborting partway leaves the
        // remaining keys naming pre-mutation state, which is the same reason
        // the callers of this sweep run every step before reporting. The first
        // error is reported once the pass is complete.
        let mut affected: Vec<String> = Vec::new();
        let mut outcome: Result<()> = Ok(());
        for (key, cas_key) in rows {
            if !key.starts_with(resolved_prefix) {
                continue;
            }
            match conn
                .execute(
                    "DELETE FROM entries WHERE resolved_target = ?1",
                    params![key],
                )
                .map_err(map_sql)
            {
                Ok(_) => affected.push(cas_key),
                Err(error) => {
                    if outcome.is_ok() {
                        outcome = Err(error);
                    }
                }
            }
        }
        // Best-effort, as in `remove_index`: the rows are already deleted.
        for cas_key in affected {
            self.reclaim_best_effort(&conn, &cas_key);
        }
        outcome
    }

    /// [`Self::reclaim_unreferenced_cas`], for callers whose authoritative
    /// mutation has already landed, so a reclamation failure must not be
    /// reported as a failure of theirs.
    fn reclaim_best_effort(&self, conn: &Connection, cas_key: &str) {
        if let Err(error) = self.reclaim_unreferenced_cas(conn, cas_key) {
            tracing::debug!(
                cas_key,
                error = %error,
                "cache could not reclaim an unreferenced blob; its tracking row is retained for a later pass"
            );
        }
    }

    /// Whether `cas_key`'s blob may be reclaimed: no `entries` row names it and
    /// no lease or pin holds it. A lease is a promise that the path stays
    /// readable for the lease's lifetime, so it outranks reclamation.
    fn cas_is_reclaimable(&self, conn: &Connection, cas_key: &str) -> Result<bool> {
        let still_referenced: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE cas_key = ?1)",
                params![cas_key],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if still_referenced {
            return Ok(false);
        }
        let pinned: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(lease_count + pin_count), 0) FROM cache_entries WHERE cas_key = ?1",
                params![cas_key],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        Ok(pinned == 0)
    }

    /// Reclaim a blob nothing references: **unlink the file, then drop its
    /// tracking row**.
    ///
    /// The order is the point. `cache_entries` is the only record that a blob
    /// exists, so dropping it first and crashing before the unlink leaves a
    /// file with neither an `entries` nor a `cache_entries` row — invisible to
    /// recovery, uncounted by the size budget, and unreclaimable for the life
    /// of the cache. This order can instead leave a row whose file is already
    /// gone, which the next access or recovery pass re-examines and drops.
    ///
    /// # Why the check and the unlink share one IMMEDIATE transaction
    ///
    /// "Nothing references this blob" is only true for as long as nothing can
    /// make it false, and the writer that would is not necessarily in this
    /// process: sibling caches over one pair of roots are explicitly supported,
    /// and the connection mutex does not exclude them. Checked outside a
    /// transaction, a sibling can publish the same content under another
    /// target, commit its `entries` row and take a lease, all between the check
    /// and the unlink — and because [`publish_cas`] accepts an existing file,
    /// its publication is a no-op that leaves the file this call then deletes.
    /// The result is a live row, and possibly a live lease, over a missing
    /// file: at best a self-healed miss, at worst a `LocalDelegate` whose path
    /// vanishes under a reader that was promised it would not.
    ///
    /// IMMEDIATE takes SQLite's write lock at BEGIN, which is cross-process, so
    /// the two orderings are the only two: a publisher that commits first is
    /// seen by the recheck and stops the reclaim, and a publisher that arrives
    /// second waits, then republishes the file from its own staged copy. The
    /// unlink runs inside the transaction because holding the exclusion across
    /// it is the entire point; it is one bounded filesystem call on the
    /// reclamation path only.
    ///
    /// Returns whether the blob was actually reclaimed.
    fn reclaim_unreferenced_cas(&self, conn: &Connection, cas_key: &str) -> Result<bool> {
        // `new_unchecked` because the callers hold the connection through a
        // guard rather than by `&mut`. Dropping the transaction rolls back, so
        // every early exit below leaves the row untouched.
        let tx =
            Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(map_sql)?;
        if !self.cas_is_reclaimable(&tx, cas_key)? {
            return Ok(false);
        }
        // A key that is not a digest names no file this cache ever wrote, and
        // no path may be derived from it -- see `is_valid_cas_key`. Dropping
        // the tracking row is the one safe action: it reclaims the row without
        // a filesystem operation, and it keeps the sweep converging instead of
        // reconsidering an unusable row on every open.
        if !is_valid_cas_key(cas_key) {
            tracing::warn!(
                cas_key,
                "cache dropped a tracking row whose CAS key is not a SHA-256 digest \
                 without touching the filesystem"
            );
            tx.execute(
                "DELETE FROM cache_entries WHERE cas_key = ?1",
                params![cas_key],
            )
            .map_err(map_sql)?;
            tx.commit().map_err(map_sql)?;
            return Ok(true);
        }
        #[cfg(test)]
        self.fire_reclaim_seam(cas_key);
        let path = cas_path(&self.cache_root, cas_key)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
        tx.execute(
            "DELETE FROM cache_entries WHERE cas_key = ?1",
            params![cas_key],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok(true)
    }

    /// Run the registered reclamation seam, if any.
    #[cfg(test)]
    fn fire_reclaim_seam(&self, cas_key: &str) {
        let seam = self.reclaim_seam.lock().ok().and_then(|seam| seam.clone());
        if let Some(seam) = seam {
            seam(cas_key);
        }
    }

    /// Install a reclamation seam. See [`Self::reclaim_seam`].
    #[cfg(test)]
    fn set_reclaim_seam(&self, seam: ReclaimSeam) {
        *self.reclaim_seam.lock().expect("seam lock") = Some(seam);
    }

    /// Remove a CAS blob known to be corrupt. Unlike
    /// [`Self::reclaim_unreferenced_cas`],
    /// this ignores other `entries` rows referencing the key — a content-hash
    /// mismatch means the file is bad for all of them. The only thing that stays
    /// our hand is an active lease/pin: we can't yank a file out from under a
    /// reader mid-stream, so we leave it (new lookups still miss because the
    /// caller already dropped this target's row).
    fn purge_corrupt_cas(
        &self,
        conn: &std::sync::MutexGuard<'_, Connection>,
        cas_key: &str,
    ) -> Result<()> {
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
        // Unlink before untracking, as in `reclaim_unreferenced_cas`: the
        // `cache_entries` row is the only record the blob exists, so dropping
        // it first and failing the unlink strands a known-corrupt file with no
        // row -- past recovery's orphan query, which reads `cache_entries`.
        let path = cas_path(&self.cache_root, cas_key)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
        conn.execute(
            "DELETE FROM cache_entries WHERE cas_key = ?1",
            params![cas_key],
        )
        .map_err(map_sql)?;
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

        // Phase 1: all DB mutations under the mutex; collect paths to unlink.
        let (files_to_remove, evictions) = {
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
            let mut files_to_remove: Vec<(String, PathBuf)> = Vec::new();
            let mut evictions: Vec<u64> = Vec::new();
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
                    // The `cache_entries` row is dropped in phase 3, after the
                    // file is gone: dropping it here and failing the unlink
                    // would strand the blob with no record it exists.
                    let path = cas_path(&self.cache_root, &cas_key)?;
                    files_to_remove.push((cas_key, path));
                }
                evictions.push(size);
            }
            // Every candidate was walked and the cache is still over budget:
            // the remainder is pinned by live leases. Eviction is silent about
            // this otherwise, and a cache stuck over budget re-walks the whole
            // victim list on every fill.
            if total_bytes > max_bytes {
                tracing::warn!(
                    total_bytes,
                    max_bytes,
                    "cache is over its size budget after eviction: the remaining rows are lease-pinned"
                );
            }
            (files_to_remove, evictions)
            // conn (MutexGuard) is dropped here, releasing the mutex before any I/O
        };

        // Phase 2: file removal outside the mutex.
        //
        // One failure does not abandon the pass. The rows are already deleted,
        // so returning here would skip the remaining unlinks, all of phase 3
        // and every eviction callback -- and would fail the caller's `put`,
        // which is itself one of the ways a fill error becomes a stale index.
        // A blob that could not be unlinked keeps its tracking row for a later
        // pass; the first error is reported once the pass is complete.
        let mut untrack: Vec<String> = Vec::new();
        let mut outcome: Result<()> = Ok(());
        for (cas_key, path) in files_to_remove {
            match fs::remove_file(&path) {
                Ok(()) => untrack.push(cas_key),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => untrack.push(cas_key),
                Err(error) => {
                    if outcome.is_ok() {
                        outcome = Err(map_io(error));
                    }
                }
            }
        }
        // Phase 3: drop the tracking rows whose files are now gone.
        //
        // Conditional, because the mutex was released for phase 2: a
        // concurrent `put` of content-identical bytes can have re-referenced
        // this key and re-created the file (its `publish_cas` tolerates an
        // existing link). Deleting unconditionally would leave that live blob
        // with an `entries` row and no `cache_entries` row, so `lease` would
        // report a miss for bytes that are on disk.
        if !untrack.is_empty() {
            let conn = self.conn()?;
            for cas_key in untrack {
                let _ = conn.execute(
                    "DELETE FROM cache_entries WHERE cas_key = ?1 \
                     AND NOT EXISTS(SELECT 1 FROM entries WHERE cas_key = ?1) \
                     AND lease_count + pin_count = 0",
                    params![cas_key],
                );
            }
        }
        for size in evictions {
            tracing::debug!(size_bytes = size, "cache eviction: size pressure");
            if let Some(observer) = self.observer.as_ref() {
                observer.on_eviction(EvictionReason::SizePressure, size);
            }
        }
        outcome
    }
}

impl ByteCache {
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
        if let Some(weak) = key_locks.get(resolved_target)
            && let Some(strong) = weak.upgrade()
        {
            return Ok(strong);
        }
        let strong = Arc::new(Mutex::new(()));
        key_locks.insert(resolved_target.to_string(), Arc::downgrade(&strong));
        // Prune dead entries periodically to bound map memory.
        if key_locks.len() % 256 == 0 {
            key_locks.retain(|_, w| w.strong_count() > 0);
        }
        Ok(strong)
    }
}

impl Drop for ByteCache {
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
            crate::coordination::release_writer_rendezvous(&self.cache_root);
        }
        // Remove this instance's staging dir on clean drop so a fixed-PID
        // container that restarts against a persistent cache root doesn't
        // accrete abandoned instance dirs. The dir is instance-unique and, by
        // the time this runs, every `StreamingPut` that cloned our `Arc` has
        // dropped, so no live fill still spools into it. The still-held
        // `_staging_owner_lock` is unlinked with the dir (harmless on unix).
        let _ = fs::remove_dir_all(&self.staging_root);
    }
}

/// Result of [`Cache::lookup`]. The lease pins the cached bytes
/// against eviction for as long as it lives.
pub struct ByteCacheLookup {
    pub cached: ByteCacheObject,
    pub lease: Option<Lease>,
}

/// Result of [`Cache::put_and_lease`]. The lease pins the CAS file
/// against eviction for the lifetime of any downstream read.
pub struct ByteCachePut {
    pub entry: ByteCacheEntry,
    pub lease: Option<Lease>,
}

/// An in-progress streaming fill from [`Cache::begin_streaming_put`]. Chunks
/// appended via [`write_chunk`](Self::write_chunk) spool to a disk staging file
/// and are hashed as they arrive; the cache row is published only on
/// [`commit`](Self::commit). Dropping the handle without committing discards the
/// staging file, so a cancelled or truncated fill leaves no half-cached row.
pub struct StreamingPut {
    cache: Arc<ByteCache>,
    resolved_target: String,
    tmp: PathBuf,
    /// `Some` until the handle is finalized (committed or aborted); `None`
    /// tells `Drop` the staging file is already gone.
    file: Option<File>,
    hasher: Sha256,
    size: u64,
    max_bytes: Option<u64>,
    /// Fill start, for the terminal `on_fill` observer callback.
    started: std::time::Instant,
    /// Guards `on_fill` to exactly one emission across commit / error / drop.
    fill_reported: bool,
    /// Slot + staging-byte reservation against the cache's shared budget.
    /// Bytes are charged as chunks are written; the slot and all charged bytes
    /// are released exactly once when this handle drops (commit or abandon).
    reservation: StreamingReservation,
}

impl StreamingPut {
    /// Emit the single terminal `on_fill` for this streaming fill. Idempotent:
    /// commit, a commit error, and an un-committed drop all funnel here, but
    /// only the first call reports.
    fn report_fill(&mut self, outcome: FillOutcome, size: u64) {
        if self.fill_reported {
            return;
        }
        self.fill_reported = true;
        if let Some(observer) = self.cache.observer.as_ref() {
            observer.on_fill(outcome, size, self.started.elapsed());
        }
    }

    /// Append `chunk` to the staging file, enforcing the optional size cap. A
    /// cap breach or staging I/O error returns an error and leaves the staging
    /// file for [`Drop`] to remove; the caller stops teeing but its own stream
    /// is unaffected. Never buffers more than the current chunk in memory.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        if self.file.is_none() {
            return Err(Error::new(
                ErrorCode::Internal,
                "streaming cache fill already finalized",
            ));
        }
        let delta = chunk.len() as u64;
        let projected = self.size.saturating_add(delta);
        if let Some(cap) = self.max_bytes
            && projected > cap
        {
            return Err(streaming_put_cap_error(cap));
        }
        // Charge the chunk against the shared aggregate staging budget before
        // writing. A breach returns `Err` (leaving nothing written) so the tee
        // is abandoned; the staging file is discarded and the reservation
        // released on `Drop`.
        self.reservation.charge(delta)?;
        let file = self
            .file
            .as_mut()
            .expect("file presence checked above under &mut self");
        file.write_all(chunk).map_err(map_io)?;
        self.hasher.update(chunk);
        self.size = projected;
        Ok(())
    }

    /// Bytes spooled so far.
    pub fn staged_len(&self) -> u64 {
        self.size
    }

    /// Publish the staged bytes into the CAS under the fill's key and return the
    /// committed entry. Consumes the handle; because the row is written only
    /// here, an un-committed handle (dropped) leaves the cache untouched.
    pub fn commit(mut self) -> Result<ByteCacheEntry> {
        self.commit_inner()
    }

    /// Publish the staged bytes under `resolved_target` instead of the key the
    /// fill began with — the streamed-**write**-through counterpart of
    /// [`commit`](Self::commit). A streamed write learns its object's validator
    /// only from the write *result*, so its tee spools under a provisional key
    /// and retargets to the post-write validator key here. The staging file and
    /// content hash are unaffected (the target names only the `entries` index
    /// row and the key lock); otherwise identical to [`commit`](Self::commit).
    pub fn commit_to(mut self, resolved_target: &str) -> Result<ByteCacheEntry> {
        resolved_target.clone_into(&mut self.resolved_target);
        self.commit_inner()
    }

    fn commit_inner(&mut self) -> Result<ByteCacheEntry> {
        let file = self.file.take().ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "streaming cache fill already finalized",
            )
        })?;
        // Clean up the staging file if `sync_all` fails: `Drop` now sees
        // `file == None` and would otherwise leave the blob orphaned on disk.
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&self.tmp);
            self.report_fill(FillOutcome::Failure, 0);
            return Err(map_io(error));
        }
        drop(file);
        let cas_key = hex_bytes(&std::mem::take(&mut self.hasher).finalize());
        let tmp = std::mem::take(&mut self.tmp);
        // Stamp the committed row with a fresh timestamp: a multi-second stream
        // drain would otherwise commit a row already aged by the fill's
        // begin-time timestamp.
        let now = unix_ms();
        // Publish under the key lock, matching `put_path_and_lease`. On error
        // `put_staged_locked` removes the staging file itself; a lock failure
        // before it runs is cleaned up here.
        let lock = match self.cache.lock_key(&self.resolved_target) {
            Ok(lock) => lock,
            Err(error) => {
                let _ = fs::remove_file(&tmp);
                self.report_fill(FillOutcome::Failure, 0);
                return Err(error);
            }
        };
        let entry =
            self.cache
                .publish_staged_locked(&self.resolved_target, cas_key, self.size, tmp, now);
        drop(lock);
        match &entry {
            Ok(_) => self.report_fill(FillOutcome::Success, self.size),
            Err(_) => self.report_fill(FillOutcome::Failure, 0),
        }
        entry
    }
}

impl Drop for StreamingPut {
    fn drop(&mut self) {
        // Un-committed: discard the staging file so a cancelled/truncated tee
        // never leaves an orphaned blob behind.
        if self.file.is_some() {
            let _ = fs::remove_file(&self.tmp);
        }
        // A fill that was never committed (cancelled/truncated tee) still emits
        // exactly one terminal `on_fill`.
        if !self.fill_reported {
            self.report_fill(FillOutcome::Failure, 0);
        }
    }
}

fn streaming_put_cap_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("streaming cache fill exceeded the {cap}-byte object cap"),
    )
}

fn streaming_budget_exhausted_error(budget: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("streaming cache staging budget ({budget} bytes) is exhausted; serving uncached"),
    )
}

/// Default cap on concurrent in-flight streaming fills when the caller doesn't
/// set [`CacheOptions::max_streaming_fills`]. Bounds staging FDs and, with the
/// byte budget, staging bytes N concurrent callers can pin.
const DEFAULT_MAX_STREAMING_FILLS: usize = 64;

/// Default aggregate staging-byte budget for an uncapped cache
/// (`max_bytes = None`). 1 GiB is generous for legitimate concurrent
/// warms yet a hard ceiling against the unbounded-staging DoS.
const DEFAULT_STREAMING_STAGING_BYTES: u64 = 1 << 30;

/// Derive the aggregate streaming staging-byte budget from the cache cap: half
/// the cap (leaving room for the CAS the fills publish into), or the fixed
/// default when the cache is uncapped.
fn streaming_staging_budget_default(max_bytes: Option<u64>) -> u64 {
    match max_bytes {
        Some(cap) => (cap / 2).max(1),
        None => DEFAULT_STREAMING_STAGING_BYTES,
    }
}

/// Process-local budget shared by every in-flight streaming fill on a cache. It
/// bounds both the count of concurrent fills and their aggregate on-disk
/// staging bytes. **Single-process scope only** — cross-process staging
/// accounting (multiple host processes sharing one cache root) is
/// unimplemented; one process cannot see another's in-flight reservations.
struct StreamingBudget {
    max_fills: usize,
    in_flight: AtomicUsize,
    max_bytes: u64,
    reserved_bytes: AtomicU64,
}

impl StreamingBudget {
    fn new(max_fills: usize, max_bytes: u64) -> Self {
        Self {
            max_fills,
            in_flight: AtomicUsize::new(0),
            max_bytes,
            reserved_bytes: AtomicU64::new(0),
        }
    }

    /// Reserve one in-flight fill slot, or `None` when the cache is already at
    /// its concurrency limit. The returned guard releases the slot — and any
    /// bytes later charged against it — exactly once on drop.
    fn try_acquire(self: &Arc<Self>) -> Option<StreamingReservation> {
        let prev = self.in_flight.fetch_add(1, Ordering::SeqCst);
        if prev >= self.max_fills {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(StreamingReservation {
            budget: Arc::clone(self),
            bytes_charged: 0,
        })
    }
}

/// RAII reservation for one in-flight streaming fill. Holds a slot in the
/// cache's [`StreamingBudget`] and tracks the staging bytes charged so far;
/// drop releases the slot and all charged bytes exactly once, whether the fill
/// committed or was abandoned.
struct StreamingReservation {
    budget: Arc<StreamingBudget>,
    bytes_charged: u64,
}

impl StreamingReservation {
    /// Charge `delta` more staging bytes against the shared budget. Returns an
    /// error (leaving this reservation's charge unchanged) when the charge would
    /// push aggregate in-flight staging past the budget, so the caller abandons
    /// the fill and serves uncached.
    fn charge(&mut self, delta: u64) -> Result<()> {
        let prev = self
            .budget
            .reserved_bytes
            .fetch_add(delta, Ordering::SeqCst);
        if prev.saturating_add(delta) > self.budget.max_bytes {
            self.budget
                .reserved_bytes
                .fetch_sub(delta, Ordering::SeqCst);
            return Err(streaming_budget_exhausted_error(self.budget.max_bytes));
        }
        self.bytes_charged = self.bytes_charged.saturating_add(delta);
        Ok(())
    }
}

impl Drop for StreamingReservation {
    fn drop(&mut self) {
        self.budget
            .reserved_bytes
            .fetch_sub(self.bytes_charged, Ordering::SeqCst);
        self.budget.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
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

impl ByteCache {
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
            // Orphaned blobs: tracked, but named by no `entries` row.
            //
            // A live lease or pin outranks reclamation — a lease promises the
            // path stays readable for its lifetime, and a blob can be leased
            // while its logical entry has been invalidated. Ordinary pruning
            // and eviction both honour that; recovery must too, or a sibling
            // cache opening the same roots unlinks a file a `LocalDelegate`
            // holder is about to read.
            let orphans: Vec<String> = {
                let mut statement = conn
                    .prepare(
                        "SELECT cas_key FROM cache_entries \
                         WHERE cas_key NOT IN (SELECT cas_key FROM entries) \
                           AND lease_count + pin_count = 0",
                    )
                    .map_err(map_sql)?;
                statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(map_sql)?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(map_sql)?
            };
            // `orphans` is a snapshot, and a sibling cache over these same
            // roots can publish, reference and lease any of those blobs before
            // this loop reaches them. So each candidate is re-examined under
            // the write lock rather than trusted from the query: the shared
            // reclaim path rechecks references and leases, unlinks and untracks
            // inside one IMMEDIATE transaction, and reports whether it acted.
            // Recovery holds no exclusion the ordinary pruning paths lack --
            // the process lock above covers dead processes' staging files, not
            // live siblings' blobs.
            for cas_key in orphans {
                match self.reclaim_unreferenced_cas(&conn, &cas_key) {
                    Ok(true) => outcome.rows_reaped += 1,
                    // Re-referenced since the snapshot, or its file could not
                    // be unlinked: either way the tracking row stays, so the
                    // next pass reconsiders it.
                    Ok(false) => {}
                    Err(error) => tracing::debug!(
                        cas_key,
                        error = %error,
                        "cache recovery could not reclaim an orphaned blob; \
                         its tracking row is retained for a later pass"
                    ),
                }
            }
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
/// Publish a staged blob into the CAS.
///
/// # Why the staging file is fsynced and this directory is not
///
/// These look like two halves of one durability decision and are not. The
/// staging `sync_all` before this call protects **content**: without it a
/// crash can leave a CAS file whose bytes are torn while the index row says it
/// is complete, and readers verify size rather than hash by default, so torn
/// bytes would be served as valid. That is a wrong-answer failure.
///
/// Syncing this directory would protect the **name**. Losing it leaves a row
/// pointing at a file that is not there, which `get_entry_inner` treats as a
/// miss, drops via `drop_orphan_entry`, and re-fetches. That is a re-fetch, on
/// a cache, after a power loss.
///
/// So the asymmetry is deliberate: one prevents serving wrong bytes, the other
/// prevents one self-healing miss, and the second would cost an fsync on every
/// fill — including every availability-row write, the hottest path here. Note
/// also that `synchronous = NORMAL` already declines full power-loss
/// durability at the SQLite layer, so the row this name pairs with is not
/// durable either.
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

/// The least string greater than every string starting with `prefix`, under
/// SQLite's BINARY collation. `None` when the prefix has no successor (empty,
/// or every trailing byte already maximal), which leaves the caller an
/// unbounded-above range.
fn prefix_upper_bound(prefix: &str) -> Option<Vec<u8>> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.pop() {
        if last < 0xFF {
            bytes.push(last + 1);
            return Some(bytes);
        }
    }
    None
}

/// Width of a SHA-256 digest in lowercase hex -- the only shape a `cas_key`
/// may take.
const CAS_KEY_LEN: usize = 64;

/// Whether `cas_key` is exactly what [`sha256_hex`] produces: 64 lowercase
/// ASCII hex characters.
///
/// This is a **security boundary**, not a tidiness check. Everything below
/// derives a filesystem path from this string and then unlinks, reads or
/// hard-links it, while `cache_entries.cas_key` is TEXT with no constraint the
/// database enforces. Two shapes escape the cache root outright: an absolute
/// `rest` makes `Path::join` discard everything to its left, and `..`
/// components walk upward. The sibling-cache model puts that across a privilege
/// boundary -- a lower-privileged writer over a shared `state_root` injects the
/// row, and the next higher-privileged process to open the cache performs the
/// deletion.
///
/// Rejecting the whole shape rather than filtering separators is the point:
/// a rule that admits only `[0-9a-f]{64}` cannot express a separator, a `..`,
/// a drive prefix, a NUL, or a non-ASCII byte, so it needs no list of the
/// things it is defending against.
fn is_valid_cas_key(cas_key: &str) -> bool {
    cas_key.len() == CAS_KEY_LEN
        && cas_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The on-disk path for `cas_key`, or an error if the key is not a digest.
///
/// Validation lives HERE, at the one place every filesystem operation on cached
/// content passes through, so no call site can forget it: the four unlink sites
/// (reclaim, corrupt purge, eviction, the lease self-heal), the path handed to
/// callers by `entry` (which is opened, read and mmapped, so an escape reads as
/// well as deletes), and the existence probes in recovery.
fn cas_path(cache_root: &Path, cas_key: &str) -> Result<PathBuf> {
    if !is_valid_cas_key(cas_key) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "CAS key is not a SHA-256 digest",
        ));
    }
    // Indexing is safe now: the key is 64 ASCII bytes, so byte 2 is a character
    // boundary. It is still done with `get` because this is reachable from
    // `Drop`, where robustness on the abnormal path is the whole reason the
    // call sits there.
    let (shard, rest) = match (cas_key.get(..2), cas_key.get(2..)) {
        (Some(shard), Some(rest)) => (shard, rest),
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "CAS key does not split on a character boundary",
            ));
        }
    };
    Ok(cache_root.join("sha256").join(shard).join(rest))
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
        // The instance owner sentinel is bookkeeping, not a staging file.
        if entry.file_name().to_str() == Some(INSTANCE_OWNER_LOCK) {
            continue;
        }
        let metadata = entry.metadata().map_err(map_io)?;
        if metadata.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// Per-process-instance staging subdirectory name: `<pid>-<unix_ms>-<seq>`.
/// The leading pid lets [`sweep_orphan_staging`] attribute a leftover dir to a
/// process and reclaim it only once that process is proven dead.
fn instance_staging_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", std::process::id(), unix_ms(), seq)
}

/// Filename of the per-instance ownership sentinel inside each staging dir. The
/// live cache holds an exclusive flock on it; a free (or absent) sentinel means
/// the owning run is dead and the dir is reclaimable, independent of PID.
const INSTANCE_OWNER_LOCK: &str = ".owner";

/// Acquire and hold the exclusive owner lock for this instance's staging dir.
fn acquire_staging_owner_lock(staging_root: &Path) -> Result<File> {
    let path = staging_root.join(INSTANCE_OWNER_LOCK);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(map_io)?;
    file.lock_exclusive().map_err(map_io)?;
    Ok(file)
}

/// Reclaim staging left by crashed runs without touching a live instance's dir.
/// Loose files directly under `staging_parent` are legacy single-dir orphans
/// (pre-instance-scoping) and are always removed. Subdirectories are instance
/// dirs; one is removed only when [`instance_dir_is_orphan`] proves no live
/// cache still owns it — via the per-instance owner sentinel, independent of
/// numeric PID, so a fixed-PID container restarting as the same PID still
/// reclaims a crashed run's staging.
fn sweep_orphan_staging(staging_parent: &Path, processes_root: &Path) -> Result<()> {
    let entries = match fs::read_dir(staging_parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(map_io(error)),
    };
    let self_pid = std::process::id() as i64;
    for entry in entries {
        let entry = entry.map_err(map_io)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(map_io)?;
        if file_type.is_dir() {
            if instance_dir_is_orphan(&path, processes_root, self_pid) {
                let _ = fs::remove_dir_all(&path);
            }
        } else {
            // Legacy loose staging file from the pre-instance-scoping layout.
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

/// An instance staging dir is an orphan (safe to reap) when no live cache holds
/// its owner sentinel. The per-instance owner lock (`<dir>/.owner`) is the
/// authority: if it can be exclusively acquired, the instance has no live
/// holder and is reaped — regardless of whether its PID prefix matches this
/// process, so a fixed-PID container that restarts as the same PID still
/// reclaims a crashed run's staging. A legacy dir predating the sentinel (no
/// `.owner`) falls back to the per-PID liveness probe and keeps the
/// conservative same-PID skip, sparing a live same-PID sibling.
fn instance_dir_is_orphan(dir: &Path, processes_root: &Path, self_pid: i64) -> bool {
    let owner_lock = dir.join(INSTANCE_OWNER_LOCK);
    match OpenOptions::new().read(true).write(true).open(&owner_lock) {
        Ok(file) => file.try_lock_exclusive().is_ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match instance_dir_pid(dir) {
            Some(pid) if pid != self_pid => staging_owner_is_dead(processes_root, pid),
            _ => false,
        },
        Err(_) => false,
    }
}

/// Parse the leading PID from a legacy instance-dir name (`<pid>-<ms>-<seq>`).
fn instance_dir_pid(dir: &Path) -> Option<i64> {
    dir.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split('-').next())
        .and_then(|pid| pid.parse::<i64>().ok())
}

/// A staging instance dir's owner is dead when its process lock is absent or
/// can be exclusively acquired (no live holder) — the same liveness probe the
/// process-lease recovery sweep uses. Fallback for legacy dirs without a
/// per-instance sentinel.
fn staging_owner_is_dead(processes_root: &Path, pid: i64) -> bool {
    let lock_path = processes_root.join(format!("{pid}.lock"));
    match OpenOptions::new().read(true).write(true).open(&lock_path) {
        Ok(file) => file.try_lock_exclusive().is_ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
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

/// Write `bytes` to `tmp`, removing the partial file if any step fails.
///
/// The cleanup is the point. Both callers hand `tmp` to
/// `publish_staged_locked`, which removes it on every failure of its own — but
/// a `?` before that call never reaches it, and the partial file is then
/// invisible to `SUM(size)` and unreachable by eviction. Under ENOSPC that is
/// every buffered `put` and every availability-row swap leaving one behind.
/// The sibling stager, `copy_path_to_staging_and_hash`, has always had this;
/// the asymmetry was an oversight.
fn write_staging_file(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let result = (|| -> Result<()> {
        let mut file = File::create(tmp).map_err(map_io)?;
        file.write_all(bytes).map_err(map_io)?;
        file.sync_all().map_err(map_io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
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
        _ if is_storage_full(&error) => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

#[cfg(unix)]
fn is_storage_full(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ENOSPC)
}

#[cfg(not(unix))]
fn is_storage_full(_error: &std::io::Error) -> bool {
    false
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
    fn byte_cache_name_opens_same_cache_surface() {
        let temp = tempfile::tempdir().unwrap();
        let cache = ByteCache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        cache.put("file:/tmp/object", b"bytes").unwrap();
        assert_eq!(
            cache.get("file:/tmp/object").unwrap(),
            Some(b"bytes".to_vec())
        );
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
    fn streaming_put_commits_on_completion() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );

        let mut put = cache.begin_streaming_put("file:/tmp/obj", None).unwrap();
        put.write_chunk(b"hello ").unwrap();
        put.write_chunk(b"world").unwrap();
        let entry = put.commit().unwrap();

        assert_eq!(entry.size, b"hello world".len() as u64);
        assert_eq!(
            cache.get("file:/tmp/obj").unwrap(),
            Some(b"hello world".to_vec())
        );
    }

    #[test]
    fn streaming_put_drop_without_commit_leaves_no_row_or_staging() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );
        let staging_root = cache.staging_root.clone();

        {
            let mut put = cache.begin_streaming_put("file:/tmp/obj", None).unwrap();
            put.write_chunk(b"partial").unwrap();
            // Dropped without commit: models a cancelled/truncated tee.
        }

        assert_eq!(cache.get("file:/tmp/obj").unwrap(), None);
        let staged: Vec<_> = fs::read_dir(&staging_root)
            .map(|it| {
                it.flatten()
                    // The instance owner sentinel is bookkeeping, not staging.
                    .filter(|e| e.file_name().to_str() != Some(INSTANCE_OWNER_LOCK))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            staged.is_empty(),
            "staging file must be discarded on drop: {staged:?}"
        );
    }

    #[test]
    fn streaming_put_cap_breach_aborts_without_row() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );

        let mut put = cache.begin_streaming_put("file:/tmp/obj", Some(8)).unwrap();
        put.write_chunk(b"12345").unwrap();
        let err = put.write_chunk(b"678901").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
        drop(put);

        assert_eq!(cache.get("file:/tmp/obj").unwrap(), None);
    }

    #[test]
    fn concurrent_streaming_puts_same_key_do_not_share_staging() {
        // Two in-flight streaming fills of the SAME key, interleaved chunk for
        // chunk. Each fill must spool to its own staging file so the committed
        // CAS blobs are not a corrupt interleave. Path distinctness at a fixed
        // timestamp is covered by `streaming_staging_path_differs_by_seq_at_fixed_timestamp`.
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );

        let a = vec![b'a'; 4096];
        let b = vec![b'b'; 4096];
        let mut p1 = cache.begin_streaming_put("file:/tmp/obj", None).unwrap();
        let mut p2 = cache.begin_streaming_put("file:/tmp/obj", None).unwrap();
        for (chunk_a, chunk_b) in a.chunks(512).zip(b.chunks(512)) {
            p1.write_chunk(chunk_a).unwrap();
            p2.write_chunk(chunk_b).unwrap();
        }

        let entry1 = p1.commit().unwrap();
        assert_eq!(cache.get("file:/tmp/obj").unwrap(), Some(a.clone()));
        let entry2 = p2.commit().unwrap();
        assert_eq!(cache.get("file:/tmp/obj").unwrap(), Some(b.clone()));
        // Distinct bodies hash to distinct CAS rows — neither fill overwrote
        // the other's staging bytes.
        assert_ne!(entry1.cas_key, entry2.cas_key);
    }

    #[test]
    fn streaming_staging_path_differs_by_seq_at_fixed_timestamp() {
        // Regression for the same-millisecond collision: hold the timestamp
        // fixed so the paths can only differ by the `seq` counter component.
        // With a real clock the timestamps could drift and mask a missing seq.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let now = 1_700_000_000_000_i64;
        let first = cache.streaming_staging_path("file:/tmp/obj", now);
        let second = cache.streaming_staging_path("file:/tmp/obj", now);
        assert_ne!(
            first, second,
            "same key + same timestamp must still yield distinct staging paths via the seq counter",
        );
    }

    #[test]
    fn sibling_cache_open_preserves_active_streaming_put() {
        // A second cache opening against the same roots must not wipe a live
        // instance's staging file: the in-flight `StreamingPut` below must
        // still commit after the sibling open (pre-fix: `open` unconditionally
        // `remove_dir_all`'d the shared staging root, unlinking the stage).
        let temp = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        };
        let cache_a = Arc::new(Cache::open(config.clone()).unwrap());
        let mut put = cache_a.begin_streaming_put("file:/tmp/obj", None).unwrap();
        put.write_chunk(b"hello ").unwrap();
        // Sibling open in the same process while the fill is live.
        let cache_b = Arc::new(Cache::open(config).unwrap());
        put.write_chunk(b"world").unwrap();
        put.commit().expect("live staging survives a sibling open");
        assert_eq!(
            cache_a.get("file:/tmp/obj").unwrap(),
            Some(b"hello world".to_vec())
        );
        drop(cache_b);
    }

    #[test]
    fn streaming_fill_budget_refuses_over_limit_and_releases_on_drop() {
        // The staging budget bounds concurrent fills so N callers
        // can't each pin an unbounded staging file. With a limit of 2, the
        // third concurrent `begin_streaming_put` is refused (tee serves
        // uncached); dropping a live fill frees the slot for a later one.
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open_with_options(
                CacheConfig {
                    state_root: temp.path().join("state"),
                    cache_root: temp.path().join("cache"),
                },
                CacheOptions {
                    max_streaming_fills: Some(2),
                    ..CacheOptions::default()
                },
            )
            .unwrap(),
        );

        let p1 = cache.begin_streaming_put("file:/tmp/a", None).unwrap();
        let p2 = cache.begin_streaming_put("file:/tmp/b", None).unwrap();
        // `StreamingPut` isn't `Debug`, so inspect the error via `match`.
        match cache.begin_streaming_put("file:/tmp/c", None) {
            Ok(_) => panic!("the (N+1)th concurrent fill must be refused"),
            Err(err) => assert_eq!(err.code(), ErrorCode::ResourceExhausted),
        }

        // Releasing a slot frees budget: a later fill now succeeds.
        drop(p1);
        let p3 = cache
            .begin_streaming_put("file:/tmp/c", None)
            .expect("a freed slot admits a new fill");
        drop(p2);
        drop(p3);
        // Budget fully released: the limit is available again.
        let p4 = cache
            .begin_streaming_put("file:/tmp/d", None)
            .expect("all slots released after drop");
        drop(p4);
    }

    #[test]
    fn streaming_fill_aggregate_staging_byte_budget_enforced() {
        // `write_chunk` charges actual bytes against the shared
        // aggregate staging budget, and a breach fails the fill (rolled back,
        // nothing written) so it is abandoned rather than pinning the bytes.
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open_with_options(
                CacheConfig {
                    state_root: temp.path().join("state"),
                    cache_root: temp.path().join("cache"),
                },
                CacheOptions {
                    max_streaming_staging_bytes: Some(16),
                    ..CacheOptions::default()
                },
            )
            .unwrap(),
        );

        let mut p1 = cache.begin_streaming_put("file:/tmp/a", None).unwrap();
        let mut p2 = cache.begin_streaming_put("file:/tmp/b", None).unwrap();
        p1.write_chunk(&[0u8; 10]).unwrap(); // 10 of 16 aggregate bytes charged
        let err = p2.write_chunk(&[0u8; 10]).unwrap_err(); // would reach 20 > 16
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);

        // Dropping p1 releases its 10 bytes; p2's charge now fits.
        drop(p1);
        p2.write_chunk(&[0u8; 10]).unwrap();
        drop(p2);
    }

    #[test]
    fn sweep_reaps_free_sentinel_instance_dir_even_same_pid() {
        // A stranded instance dir whose owner sentinel is free must
        // be reaped even when its PID prefix equals this process's PID — the
        // fixed-PID-container restart case, where a PID-equality skip would
        // leak the dir.
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        let staging_parent = cache_root.join("staging");
        fs::create_dir_all(&staging_parent).unwrap();

        let self_pid = std::process::id();
        let stranded = staging_parent.join(format!("{self_pid}-1700000000000-0"));
        fs::create_dir_all(&stranded).unwrap();
        // A sentinel present but unlocked: the crashed owner released its flock.
        fs::write(stranded.join(INSTANCE_OWNER_LOCK), b"").unwrap();
        fs::write(stranded.join("leftover.stream.tmp"), b"orphan").unwrap();

        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root,
        })
        .unwrap();
        assert!(
            !stranded.exists(),
            "a same-PID instance dir with a free sentinel must be reaped"
        );
        drop(cache);
    }

    #[test]
    fn sweep_spares_instance_dir_with_held_sentinel() {
        // A live instance's held sentinel keeps its dir even across a same-PID
        // open — the safety the reap must not violate.
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        let staging_parent = cache_root.join("staging");
        fs::create_dir_all(&staging_parent).unwrap();

        let self_pid = std::process::id();
        let live = staging_parent.join(format!("{self_pid}-1700000000001-0"));
        fs::create_dir_all(&live).unwrap();
        // Hold the sentinel exclusively, mimicking a live sibling instance.
        let held = acquire_staging_owner_lock(&live).unwrap();

        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root,
        })
        .unwrap();
        assert!(
            live.exists(),
            "a dir whose owner sentinel is held must be spared"
        );
        drop(held);
        drop(cache);
    }

    #[test]
    fn clean_drop_removes_instance_staging_dir() {
        // A clean `ByteCache` drop removes its own instance dir so a
        // fixed-PID container doesn't accrete dirs across restarts.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let staging_root = cache.staging_root.clone();
        assert!(staging_root.exists());
        drop(cache);
        assert!(
            !staging_root.exists(),
            "clean drop must remove the instance staging dir"
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
            cache.remove_index_returning("file://a").unwrap_err().code(),
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
    fn remove_index_returning_reports_the_exact_object_it_removed() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://a", b"alpha").unwrap();

        let removed = cache
            .remove_index_returning("file://a")
            .unwrap()
            .expect("the stored row is removed");

        assert_eq!(removed.entry, entry);
        assert_eq!(removed.bytes, b"alpha");
        assert!(cache.entry("file://a").unwrap().is_none());
        assert!(!removed.entry.path.exists());
        assert!(
            cache.remove_index_returning("file://a").unwrap().is_none(),
            "an absent row reports no removed object"
        );
    }

    #[test]
    fn remove_index_returning_rejects_same_length_corruption_before_removal() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let entry = cache.put("file://a", b"alpha").unwrap();
        fs::write(&entry.path, b"bravo").unwrap();

        let error = cache.remove_index_returning("file://a").unwrap_err();

        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(
            cache.entry("file://a").unwrap(),
            Some(entry),
            "integrity failure must leave the row in place so its value is never \
             used for destructive secondary cleanup"
        );
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
    fn quarantine_purges_shared_corrupt_blob_and_siblings_self_heal() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let first = cache.put("file://a", b"shared").unwrap();
        let second = cache.put("file://b", b"shared").unwrap();
        assert_eq!(first.cas_key, second.cas_key);

        // Corrupt the shared CAS file on disk.
        std::fs::write(&first.path, b"tampered").unwrap();

        // Reading A detects the hash mismatch and quarantines. Because the file
        // itself is bad, it is purged even though B still references the key.
        assert_eq!(cache.get("file://a").unwrap(), None);
        assert!(
            !first.path.exists(),
            "corrupt CAS file purged despite a sibling reference"
        );

        // B self-heals to a clean miss via the NotFound path, and its dangling
        // row is dropped rather than lingering forever.
        assert_eq!(cache.get("file://b").unwrap(), None);
        let conn = cache.conn().unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE cas_key = ?1",
                params![first.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "dangling entries rows are cleaned up");
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
            // Not a digest, so no path is ever derived from it -- the row is
            // still reaped, by the row-only branch that touches no file.
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
    fn overwriting_a_row_reclaims_the_blob_it_stopped_naming() {
        // An `entries` row names exactly one blob. Overwriting it is the only
        // mutation that drops a reference without deleting a row, so nothing
        // else ever revisits the displaced blob: left behind it is invisible to
        // the LRU (which walks `entries`) and uncounted by the size budget.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let key = "idx://overwritten";

        let first = cache.put(key, b"first-body").unwrap();
        assert!(first.path.exists(), "the first blob is published");
        let second = cache.put(key, b"second-body").unwrap();

        assert!(
            !first.path.exists(),
            "the displaced blob must be unlinked, not orphaned outside the LRU"
        );
        assert!(second.path.exists(), "the current blob stays");
        let tracked: i64 = cache
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![first.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tracked, 0, "and its tracking row goes with it");
    }

    #[test]
    fn prefix_upper_bound_is_the_successor_of_the_prefix() {
        assert_eq!(prefix_upper_bound("p\u{1}"), Some(b"p\x02".to_vec()));
        assert_eq!(prefix_upper_bound("ab"), Some(b"ac".to_vec()));
        // The bound is a byte successor, not a character one: 0xFF never
        // appears in UTF-8, so the carry loop never runs past the last byte and
        // the empty prefix is the only input without a successor.
        assert_eq!(prefix_upper_bound("a\u{ff}"), Some(vec![b'a', 0xC3, 0xC0]));
        assert_eq!(
            prefix_upper_bound(""),
            None,
            "no successor for an empty prefix"
        );
    }

    #[test]
    fn prefix_range_bound_must_be_compared_as_text() {
        // The bound is bytes, so rusqlite binds it as a BLOB, and SQLite orders
        // every TEXT before every BLOB -- `resolved_target < ?2` is then always
        // true and the range degenerates to [prefix, infinity). `remove_prefix`
        // stays correct either way because `starts_with` is the authoritative
        // filter, so this pins the comparison itself: dropping the CAST from
        // the query silently widens every prefix sweep to a scan of the whole
        // key space from the prefix onward.
        let conn = Connection::open_in_memory().unwrap();
        let bound = prefix_upper_bound("p\u{1}").unwrap();
        let adjacent = "p\u{2}live-row";

        let uncast: bool = conn
            .query_row("SELECT ?1 < ?2", params![adjacent, bound], |row| row.get(0))
            .unwrap();
        assert!(
            uncast,
            "a blob-bound comparison is vacuous: the next namespace sorts inside the range"
        );

        let cast: bool = conn
            .query_row(
                "SELECT ?1 < CAST(?2 AS TEXT)",
                params![adjacent, bound],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !cast,
            "cast to TEXT, the bound excludes the next namespace as intended"
        );
    }

    #[test]
    fn remove_prefix_sweeps_every_other_row_when_one_delete_fails() {
        // A subtree invalidation runs after its backend mutation has already
        // committed, so aborting partway leaves the remaining children naming
        // pre-delete validators with their bodies still cached. One row failing
        // must not cost the rest of the sweep.
        //
        // A BEFORE DELETE trigger fails exactly one row, standing in for the
        // SQLITE_BUSY-past-timeout or SQLITE_IOERR that reach the same arm.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        let keys = ["p\u{2}a", "p\u{2}b", "p\u{2}c", "p\u{2}d"];
        let mut blobs = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            blobs.push(cache.put(key, format!("body-{index}").as_bytes()).unwrap());
        }

        cache
            .conn()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER block_one BEFORE DELETE ON entries \
                 WHEN OLD.resolved_target = 'p' || char(2) || 'b' \
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
            )
            .unwrap();

        let swept = cache.remove_prefix("p\u{2}");
        assert!(swept.is_err(), "the failing row is reported");

        for (index, key) in keys.iter().enumerate() {
            let present = cache.get_entry(key).unwrap().is_some();
            if *key == "p\u{2}b" {
                assert!(present, "the blocked row survives");
            } else {
                assert!(
                    !present,
                    "row {key:?} must be swept even though another row failed"
                );
                assert!(
                    !blobs[index].path.exists(),
                    "and its blob must be reclaimed, not stranded"
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn lease_drop_keeps_the_tracking_row_when_the_unlink_fails() {
        // `cache_entries` is the only record that a blob exists: recovery's
        // orphan sweep reads it, and the size budget is derived from rows. Drop
        // it before the file is actually gone and a failed unlink strands the
        // blob with no row at all -- unreachable and unreclaimable for the life
        // of the cache. Every other reclaim site unlinks first; this one is the
        // last that did not.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        let entry = cache.put("file://leased", b"leased-body").unwrap();
        let lease = cache.lease(&entry.cas_key).unwrap().expect("lease minted");
        // Invalidate the logical entry; the blob survives because it is leased.
        cache.remove_index("file://leased").unwrap();

        // Make the unlink fail: a directory at the blob path refuses
        // `remove_file`, standing in for a permission or I/O error.
        std::fs::remove_file(&entry.path).unwrap();
        std::fs::create_dir(&entry.path).unwrap();

        drop(lease);

        let tracked: i64 = cache
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            tracked, 1,
            "a blob whose unlink failed must keep its tracking row so a later pass can retry"
        );
    }

    #[test]
    fn cas_path_admits_only_a_sha256_digest() {
        // The key is read straight out of SQLite, which constrains it to TEXT,
        // and every filesystem operation on cached content derives its path
        // from it. Two shapes leave the cache root entirely, and both are
        // rejected here rather than at each call site.
        let root = std::path::Path::new("/tmp/cache");
        let digest = "a".repeat(64);
        assert!(cas_path(root, &digest).is_ok(), "a digest maps to a path");

        assert!(
            cas_path(root, &format!("aa{}", "/etc/victim")).is_err(),
            "an absolute rest would make `join` discard the cache root"
        );
        assert!(
            cas_path(root, "aa../../../victim").is_err(),
            "`..` components would walk out of the cache root"
        );
        assert!(
            cas_path(root, "\u{20ac}ab").is_err(),
            "3-byte lead character"
        );
        assert!(cas_path(root, "ab").is_err(), "too short");
        assert!(cas_path(root, "abcd").is_err(), "short of a digest");
        assert!(
            cas_path(root, &"A".repeat(64)).is_err(),
            "uppercase is not what `sha256_hex` emits"
        );
        assert!(
            cas_path(root, &"g".repeat(64)).is_err(),
            "non-hex characters"
        );
        assert!(
            cas_path(root, &format!("{}\0", "a".repeat(63))).is_err(),
            "an interior NUL truncates the path a syscall sees"
        );
    }

    #[test]
    #[cfg(unix)]
    fn recovery_keeps_the_tracking_row_when_the_orphan_unlink_fails() {
        // Recovery is the pass that reclaims blobs no `entries` row names. It
        // is also the last pass that can: `cache_entries` is the only record
        // the blob exists. Dropping that row when the unlink failed strands the
        // file with neither row -- invisible to the next recovery pass, which
        // reads `cache_entries` to find orphans in the first place.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        let entry = cache.put("file://orphaned", b"orphan-body").unwrap();
        // Orphan the blob: drop the naming row directly, leaving `cache_entries`.
        cache
            .conn()
            .unwrap()
            .execute(
                "DELETE FROM entries WHERE resolved_target = ?1",
                params!["file://orphaned"],
            )
            .unwrap();

        // Make the unlink fail: a directory at the blob path refuses
        // `remove_file`, standing in for a permission or I/O error.
        std::fs::remove_file(&entry.path).unwrap();
        std::fs::create_dir(&entry.path).unwrap();

        cache.recover().unwrap();

        let tracked: i64 = cache
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            tracked, 1,
            "an orphan whose unlink failed must keep its tracking row for the next pass"
        );
    }

    #[test]
    fn a_missing_blob_self_heal_keeps_the_tracking_row() {
        // Publication commits the rows and then links the file, so between
        // those a reader on another instance sees a row whose file is absent.
        // Self-healing that read by dropping the `entries` row is right; also
        // dropping `cache_entries` is not -- it treats "file not there yet" as
        // "file already reclaimed", and once the publisher links the blob it
        // has no rows at all: outside the budget, past recovery's orphan sweep,
        // and permanent. Driven by read traffic, so it compounds.
        //
        // Keeping the tracking row is safe either way. If the blob really is
        // gone, recovery reclaims the row at next open; if it is mid-flight,
        // the publisher's own rows take over.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        let entry = cache.put("file://vanishing", b"body").unwrap();
        // Stand in for the publication window: the row exists, the file does not.
        std::fs::remove_file(&entry.path).unwrap();

        assert!(
            cache.get_entry("file://vanishing").unwrap().is_none(),
            "the read self-heals to a clean miss"
        );

        let tracked: i64 = cache
            .conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = ?1",
                params![entry.cas_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            tracked, 1,
            "the blob's tracking row must survive a reader's self-heal"
        );
    }

    #[test]
    fn compare_and_put_swaps_only_on_matching_expected() {
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let key = "idx://addr";

        // Absent row: a swap succeeds only when `expected` is also absent.
        assert!(
            !cache.compare_and_put(key, Some(b"x"), Some(b"a")).unwrap(),
            "a non-absent expected against an absent row must not swap"
        );
        assert!(cache.get_entry(key).unwrap().is_none());
        assert!(
            cache.compare_and_put(key, None, Some(b"a")).unwrap(),
            "expected-absent set must succeed"
        );
        assert_eq!(cache.get_entry(key).unwrap().unwrap().bytes, b"a");

        // Present row: swap only when `expected` equals the current value.
        assert!(
            !cache
                .compare_and_put(key, Some(b"WRONG"), Some(b"b"))
                .unwrap(),
            "a stale expected must not swap"
        );
        assert_eq!(cache.get_entry(key).unwrap().unwrap().bytes, b"a");
        assert!(
            cache.compare_and_put(key, Some(b"a"), Some(b"b")).unwrap(),
            "a matching expected must swap"
        );
        assert_eq!(cache.get_entry(key).unwrap().unwrap().bytes, b"b");

        // Remove via `new = None`, gated the same way.
        assert!(
            !cache.compare_and_put(key, Some(b"a"), None).unwrap(),
            "a stale expected must not remove"
        );
        assert!(
            cache.compare_and_put(key, Some(b"b"), None).unwrap(),
            "a matching expected must remove"
        );
        assert!(cache.get_entry(key).unwrap().is_none());
    }

    #[test]
    fn compare_and_put_survives_real_contention_with_an_unlocked_remover() {
        // A liveness and consistency guard under genuine cross-thread
        // contention with a mutator that takes no per-key lock: no deadlock, no
        // error, and a successful swap never leaves anything but `b` behind.
        //
        // This does NOT discriminate a check-then-act implementation --
        // `compare_and_put_refuses_a_mutation_inside_its_compare_window` is the
        // test that does. Two same-key swaps serialize on the key lock, so
        // "exactly one of two swaps wins" holds either way; and a lost removal
        // is unobservable from outside, because the next round re-seeds `a`
        // and paints over the resurrected row.
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );
        let key = "idx://contested";
        const ROUNDS: usize = 300;

        let gate = Arc::new(std::sync::Barrier::new(2));
        let remover_cache = Arc::clone(&cache);
        let remover_gate = Arc::clone(&gate);
        let remover = std::thread::spawn(move || {
            remover_gate.wait();
            for _ in 0..ROUNDS {
                remover_cache.remove_index(key).unwrap();
            }
        });

        let swapper_cache = Arc::clone(&cache);
        let swapper_gate = Arc::clone(&gate);
        let swapper = std::thread::spawn(move || {
            swapper_gate.wait();
            let mut succeeded = 0usize;
            for _ in 0..ROUNDS {
                // Re-seed so the swap has a value to contend for.
                swapper_cache.put(key, b"a").unwrap();
                if swapper_cache
                    .compare_and_put(key, Some(b"a"), Some(b"b"))
                    .unwrap()
                {
                    succeeded += 1;
                    // A successful swap claims the row held `a` when it wrote.
                    // The remover may drop it immediately afterwards, but it
                    // must never be observable as anything but `b`.
                    if let Some(object) = swapper_cache.get_entry(key).unwrap() {
                        assert_eq!(
                            object.bytes, b"b",
                            "a swap reported success but the row does not hold the swapped-in value"
                        );
                    }
                }
            }
            succeeded
        });

        remover.join().unwrap();
        let succeeded = swapper.join().unwrap();
        assert!(
            succeeded > 0,
            "the contention test never exercised a successful swap"
        );
    }

    #[test]
    fn compare_and_put_refuses_a_mutation_inside_its_compare_window() {
        // The discriminating case for atomicity. A removal lands after the row
        // has been observed and before it is written -- the window a
        // check-then-act implementation leaves open, and the one `remove_index`
        // / `remove_prefix` / size-pressure eviction can enter because none of
        // them take the per-key lock. Acting on the stale observation resurrects
        // the row the remover dropped, silently undoing a subtree invalidation.
        let temp = tempfile::tempdir().unwrap();
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: temp.path().join("state"),
                cache_root: temp.path().join("cache"),
            })
            .unwrap(),
        );
        let key = "idx://window";
        cache.put(key, b"a").unwrap();

        let contender = Arc::clone(&cache);
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_seam = Arc::clone(&fired);
        cache.set_compare_and_put_seam(Arc::new(move |target: &str, phase| {
            if phase == CompareAndPutPhase::Observed
                && fired_seam.fetch_add(1, Ordering::SeqCst) == 0
            {
                contender.remove_index(target).unwrap();
            }
        }));

        let swapped = cache.compare_and_put(key, Some(b"a"), Some(b"b")).unwrap();
        assert_eq!(fired.load(Ordering::SeqCst), 1, "the window was contested");
        assert!(
            !swapped,
            "a swap whose expected value was removed inside its window must refuse"
        );
        assert!(
            cache.get_entry(key).unwrap().is_none(),
            "the contending removal must stand, not be undone by the swap"
        );
    }

    #[test]
    fn compare_and_put_refuses_after_a_removal_it_did_not_observe() {
        // The deterministic half of the invariant above: a removal landing
        // before the swap's compare makes the swap refuse, so the removal is
        // never silently undone.
        let temp = tempfile::tempdir().unwrap();
        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();
        let key = "idx://removed";
        cache.put(key, b"a").unwrap();
        cache.remove_index(key).unwrap();

        assert!(
            !cache.compare_and_put(key, Some(b"a"), Some(b"b")).unwrap(),
            "a swap against a removed row must refuse"
        );
        assert!(
            cache.get_entry(key).unwrap().is_none(),
            "the removal must stand"
        );
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
        assert_eq!(version, crate::CURRENT_SCHEMA_VERSION);
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

    /// Drive a reclamation whose reference check is raced by a sibling cache
    /// publishing the same content under `sibling_target`.
    ///
    /// The sibling runs on its own thread and its own connection, so it is a
    /// stand-in for the separate process the cross-instance contract allows.
    /// The seam waits only for that thread to START -- with the reclaim holding
    /// the write lock the sibling's publication blocks, so waiting for it to
    /// finish would wait on this very call -- and then sleeps long enough for
    /// it to reach the write it is going to be blocked on.
    fn race_reclaim_against_sibling_publish(
        cache: &Cache,
        sibling: Arc<Cache>,
        sibling_target: &'static str,
        body: &'static [u8],
    ) -> Arc<Mutex<Option<std::thread::JoinHandle<()>>>> {
        let handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
        let seam_handle = Arc::clone(&handle);
        cache.set_reclaim_seam(Arc::new(move |_key| {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let sibling = Arc::clone(&sibling);
            let spawned = std::thread::spawn(move || {
                started_tx.send(()).expect("seam receiver");
                sibling.put(sibling_target, body).expect("sibling publish");
            });
            started_rx.recv().expect("sibling thread start");
            std::thread::sleep(std::time::Duration::from_millis(250));
            *seam_handle.lock().expect("seam handle") = Some(spawned);
        }));
        handle
    }

    #[test]
    fn reclaim_does_not_unlink_a_blob_a_sibling_re_referenced() {
        // The reference check and the unlink must be one step against every
        // writer, including a sibling cache on another connection. Checked
        // outside a transaction, the sibling commits its `entries` row in the
        // window and `publish_cas` accepts the file that is already there --
        // so the unlink that follows deletes a live entry's only copy.
        let temp = tempfile::tempdir().unwrap();
        let config = || CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        };
        let cache = Cache::open(config()).unwrap();
        let sibling = Arc::new(Cache::open(config()).unwrap());

        let entry = cache.put("file://a", b"shared bytes").unwrap();
        assert!(entry.path.exists());

        let handle = race_reclaim_against_sibling_publish(
            &cache,
            Arc::clone(&sibling),
            "file://b",
            b"shared bytes",
        );
        // Drops the only reference, so the reclaim runs -- into the seam.
        cache.remove_index("file://a").unwrap();
        if let Some(spawned) = handle.lock().unwrap().take() {
            spawned.join().expect("sibling thread");
        }

        assert_eq!(
            sibling.get("file://b").unwrap().as_deref(),
            Some(&b"shared bytes"[..]),
            "a blob re-referenced during the reclaim must survive it"
        );
    }

    #[test]
    fn recovery_does_not_unlink_a_blob_a_sibling_re_referenced() {
        // Recovery's orphan list is a snapshot, and it holds no exclusion the
        // pruning paths lack: the same race, reached through the pass that
        // sweeps blobs no `entries` row names.
        let temp = tempfile::tempdir().unwrap();
        let config = || CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        };
        let cache = Cache::open(config()).unwrap();
        let sibling = Arc::new(Cache::open(config()).unwrap());

        // An orphan: tracked by `cache_entries`, named by no `entries` row.
        let entry = cache.put("file://a", b"orphan bytes").unwrap();
        {
            let conn = cache.conn().unwrap();
            conn.execute(
                "DELETE FROM entries WHERE resolved_target = ?1",
                params!["file://a"],
            )
            .unwrap();
        }
        assert!(entry.path.exists());

        let handle = race_reclaim_against_sibling_publish(
            &cache,
            Arc::clone(&sibling),
            "file://b",
            b"orphan bytes",
        );
        cache.recover().unwrap();
        if let Some(spawned) = handle.lock().unwrap().take() {
            spawned.join().expect("sibling thread");
        }

        assert_eq!(
            sibling.get("file://b").unwrap().as_deref(),
            Some(&b"orphan bytes"[..]),
            "a blob re-referenced during recovery must survive it"
        );
    }

    /// Insert an orphaned `cache_entries` row: tracked, named by no `entries`
    /// row, unleased -- exactly what recovery's orphan sweep reclaims.
    fn track_orphan(cache: &Cache, cas_key: &str) {
        let conn = cache.conn().unwrap();
        conn.execute(
            "INSERT INTO cache_entries (cas_key, size, verified_at) VALUES (?1, 0, 0)",
            params![cas_key],
        )
        .unwrap();
    }

    #[test]
    fn recovery_never_unlinks_outside_the_cache_root() {
        // `cache_entries.cas_key` is TEXT with no hash constraint, and recovery
        // unlinks a path derived from it. `Path::join` with an absolute
        // component DISCARDS everything to its left, and `..` components walk
        // out of the root, so a crafted key names any file the process can
        // delete. The sibling-cache model makes that reachable across a
        // privilege boundary: a lower-privileged writer over the shared
        // `state_root` injects the row, and the next higher-privileged open
        // performs the deletion.
        let temp = tempfile::tempdir().unwrap();
        let outside_absolute = temp.path().join("sentinel-absolute.txt");
        let outside_relative = temp.path().join("sentinel-relative.txt");
        fs::write(&outside_absolute, b"must survive").unwrap();
        fs::write(&outside_relative, b"must survive").unwrap();

        let cache = Cache::open(CacheConfig {
            state_root: temp.path().join("state"),
            cache_root: temp.path().join("cache"),
        })
        .unwrap();

        // `rest` is absolute, so the cache root is discarded outright.
        track_orphan(&cache, &format!("aa{}", outside_absolute.to_string_lossy()));
        // `rest` walks up out of `<cache_root>/sha256/aa/`.
        track_orphan(&cache, "aa../../../sentinel-relative.txt");

        cache.recover().unwrap();

        assert!(
            outside_absolute.exists(),
            "an absolute CAS key must not delete a file outside the cache root"
        );
        assert!(
            outside_relative.exists(),
            "a traversing CAS key must not delete a file outside the cache root"
        );
    }
}
