// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An in-process hub that implements the cache-aside semantics.
//!
//! [`FakeHub`] listens on a loopback port, speaks the same length-prefixed
//! protobuf framing as the real hub, and backs its entries with real files in
//! a caller-supplied directory. It is not a script of canned answers: it
//! implements write-once keys, pending-write visibility, refcounted read
//! leases, and the disconnect cleanup a real hub performs, so a layer tested
//! against it exercises the behaviour it will meet in production.
//!
//! # On-disk naming
//!
//! An entry is identified by its key alone. Its file is
//! `<cache_dir>/<encoded key>.<extension>`, or `<cache_dir>/<encoded key>`
//! when the extension is empty. The encoding keeps `A-Z`, `a-z`, `0-9`, `_`
//! and `-` verbatim and writes every other byte as `%XX` with uppercase hex,
//! which is injective: two distinct keys never name the same file, and a key
//! containing a dot cannot collide with another key's extension.
//!
//! # The extension trap
//!
//! The extension names the file, not the entry. Opening a committed entry
//! with an extension other than the one it was written with therefore
//! succeeds and hands back a path that does not exist. The fake reproduces
//! this faithfully, because a layer that trusts the path without checking it
//! is the defect the fake exists to catch.
//!
//! # Fidelity limits
//!
//! Requests on one connection are answered in arrival order rather than out
//! of order, and the store's file I/O runs on the async worker rather than a
//! blocking pool. Neither is observable through the client API at fixture
//! scale.
//!
//! ```no_run
//! # use ovstorage_hub_client::fake::FakeHub;
//! # async fn example(dir: std::path::PathBuf) {
//! let hub = FakeHub::start(dir).await;
//! let endpoint = hub.endpoint();
//! // Point a HubCacheClient at `endpoint`, drive it, then assert on the hub.
//! assert_eq!(hub.open_handles(), 0);
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::proto;
use crate::proto::ResultCode;
use crate::proto::request_params::Params as WireParams;
use crate::proto::response_result::Result as WireResult;
use crate::wire::{read_frame, write_frame};

/// How long [`FakeHub::wait_for`] polls before it gives up.
const WAIT_LIMIT: Duration = Duration::from_secs(5);

/// How often [`FakeHub::wait_for`] re-checks its condition.
const WAIT_STEP: Duration = Duration::from_millis(1);

// ---------------------------------------------------------------------------
// Configuration and introspection types
// ---------------------------------------------------------------------------

/// An interface the fake advertises in its version probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HubInterface {
    /// The cache-aside file interface, which the fake implements.
    CacheAside,
    /// The block-cache interface, which the fake advertises but does not
    /// implement. It exists so a test can present a hub whose interface list
    /// lacks cache-aside.
    BlockCache,
}

impl HubInterface {
    fn wire(self) -> i32 {
        match self {
            Self::CacheAside => proto::Interface::CacheAside as i32,
            Self::BlockCache => proto::Interface::BlockCache as i32,
        }
    }
}

/// What a [`FakeHub`] reports about itself and how much it accepts.
#[derive(Clone, Debug)]
pub struct FakeHubConfig {
    /// The interfaces the version probe reports, each at version 1.
    pub interfaces: Vec<HubInterface>,
    /// The `major.minor.patch` the version probe reports as the hub's own
    /// software version.
    pub software_version: (u64, u64, u64),
    /// The largest entry an open-for-write may reserve. `None` accepts any
    /// size; a larger reservation is refused with the hub's too-large code.
    pub max_entry_size: Option<u64>,
}

impl Default for FakeHubConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![HubInterface::CacheAside],
            software_version: (1, 0, 0),
            max_entry_size: None,
        }
    }
}

/// The state of one cache entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryState {
    /// A client holds a write lease on the key. Readers and second writers
    /// alike see the hub's pending-write code.
    PendingWrite,
    /// The entry is published and readable.
    Committed {
        /// The size the file had when the write lease was closed.
        size: u64,
        /// The extension the entry was written with, which names its file.
        extension: String,
    },
}

/// How many cache-aside operations the hub has received.
///
/// The counters record requests, not outcomes: a rejected open still counts.
/// Leases released because a connection ended are not requests and are not
/// counted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HubCounters {
    /// Open-for-read requests received.
    pub opens_for_read: u64,
    /// Open-for-write requests received.
    pub opens_for_write: u64,
    /// Close requests received.
    pub closes: u64,
    /// Remove requests received.
    pub removes: u64,
}

// ---------------------------------------------------------------------------
// The hub
// ---------------------------------------------------------------------------

/// A hub that implements the cache-aside protocol over a real directory.
///
/// The hub serves until it is shut down or dropped. Its store outlives its
/// listener, so [`FakeHub::restart`] resumes serving the same entries on the
/// same address.
pub struct FakeHub {
    state: Arc<HubState>,
    addr: SocketAddr,
    server: Mutex<Option<Server>>,
}

/// The listener side of a running hub, replaced wholesale by a restart.
struct Server {
    stop: watch::Sender<bool>,
    accept: JoinHandle<()>,
}

impl FakeHub {
    /// Starts a hub with the default configuration, storing entries under
    /// `cache_dir`, which is created if it does not exist.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created or the loopback listener
    /// cannot be bound; a fixture that cannot start has nothing to report.
    pub async fn start(cache_dir: impl Into<PathBuf>) -> Self {
        Self::start_with(cache_dir, FakeHubConfig::default()).await
    }

    /// Starts a hub with an explicit configuration.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created or the loopback listener
    /// cannot be bound.
    pub async fn start_with(cache_dir: impl Into<PathBuf>, config: FakeHubConfig) -> Self {
        let cache_dir = cache_dir.into();
        fs::create_dir_all(&cache_dir).expect("the fake hub's cache directory is creatable");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port is available");
        let addr = listener
            .local_addr()
            .expect("a bound listener has a local address");
        let state = Arc::new(HubState::new(cache_dir, config));
        let server = serve_on(listener, state.clone());
        Self {
            state,
            addr,
            server: Mutex::new(Some(server)),
        }
    }

    /// The `127.0.0.1:port` a client dials.
    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    /// The address the hub is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The directory the hub stores entries in.
    pub fn cache_dir(&self) -> &Path {
        &self.state.cache_dir
    }

    /// Stops accepting and drops every live connection, which is what a hub
    /// process dying looks like to a client.
    ///
    /// The store survives: [`FakeHub::restart`] resumes on the same address
    /// with the same entries. A fresh [`FakeHub::start`] on the same
    /// directory is a different hub — it takes a new port and starts with an
    /// empty index, so files the old hub wrote are unreferenced — which is
    /// what a test wants when it means "a hub that lost its cache". Each
    /// connection releases the leases it held as it goes, so pending writes
    /// are discarded exactly as a real hub discards them;
    /// [`FakeHub::wait_for_open_handles`] observes that settling.
    ///
    /// The call returns without waiting for the listener to close; use
    /// [`FakeHub::restart`] when the address has to be free.
    pub fn shutdown(&self) {
        if let Some(server) = self.take_server() {
            server.stop.send_replace(true);
        }
    }

    /// Stops the hub and starts serving the same store on the same address
    /// again.
    ///
    /// # Errors
    ///
    /// Returns the bind error if something else claimed the address while
    /// the hub was down.
    pub async fn restart(&self) -> std::io::Result<()> {
        if let Some(server) = self.take_server() {
            server.stop.send_replace(true);
            // Awaiting the accept task is what frees the address: the
            // listener lives in that task and closes when it returns.
            let _ = server.accept.await;
        }
        let listener = TcpListener::bind(self.addr).await?;
        *lock(&self.server) = Some(serve_on(listener, self.state.clone()));
        Ok(())
    }

    /// The number of leases clients currently hold, across every connection.
    pub fn open_handles(&self) -> usize {
        lock(&self.state.inner).leases.len()
    }

    /// The state of `key`, or `None` if the hub holds no entry for it.
    pub fn entry(&self, key: &str) -> Option<EntryState> {
        lock(&self.state.inner).entries.get(key).map(Entry::state)
    }

    /// The bytes stored for `key`, or `None` if it is not committed or its
    /// file cannot be read.
    pub fn committed_bytes(&self, key: &str) -> Option<Vec<u8>> {
        let path = {
            let inner = lock(&self.state.inner);
            let entry = inner.entries.get(key)?;
            if matches!(entry.phase, Phase::Pending) {
                return None;
            }
            self.state.file_path(&entry.base, &entry.extension)
        };
        fs::read(path).ok()
    }

    /// The operations the hub has received so far.
    pub fn counters(&self) -> HubCounters {
        let counters = &self.state.counters;
        HubCounters {
            opens_for_read: counters.opens_for_read.load(Ordering::Relaxed),
            opens_for_write: counters.opens_for_write.load(Ordering::Relaxed),
            closes: counters.closes.load(Ordering::Relaxed),
            removes: counters.removes.load(Ordering::Relaxed),
        }
    }

    /// Publishes `bytes` under `key` as if a client had filled it, and
    /// returns the file it wrote.
    ///
    /// This is how a test builds a warm cache, or an entry whose extension
    /// differs from the one a reader will ask for, without driving a client
    /// through a fill. Any existing entry for `key` is replaced.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be written.
    pub fn seed_entry(&self, key: &str, extension: &str, bytes: &[u8]) -> PathBuf {
        let mut inner = lock(&self.state.inner);
        if let Some(previous) = inner.entries.remove(key) {
            let _ = fs::remove_file(self.state.file_path(&previous.base, &previous.extension));
        }
        let base = encode_key(key);
        let path = self.state.file_path(&base, extension);
        fs::write(&path, bytes).expect("the seeded entry is writable");
        inner.entries.insert(
            key.to_string(),
            Entry {
                base,
                extension: extension.to_string(),
                phase: Phase::Committed {
                    size: bytes.len() as u64,
                },
                readers: 0,
            },
        );
        path
    }

    /// Arms a one-shot override on `key`: the next `OpenForRead` for it, on
    /// any connection, answers not-found regardless of the entry's actual
    /// state, then the override is consumed and later opens behave normally.
    ///
    /// This is the deterministic reproduction of the cross-process fill
    /// race a real hub can produce: a reader's lookup answers not-cached,
    /// but by the time that reader opens the key for write, another client
    /// has already committed it — so the reader's write collects
    /// `ALREADY_EXISTS` instead of the `Success` its own (stale) read would
    /// have predicted. Arming the override on an already-committed entry
    /// reproduces exactly that ordering without a real race.
    pub fn answer_not_cached_once(&self, key: &str) {
        lock(&self.state.inner)
            .not_cached_once
            .insert(key.to_string());
    }

    /// Arms a one-shot refusal on `key`: the next `Close` of a WRITE lease
    /// for it, on any connection, answers the hub's internal error instead
    /// of committing, then the override is consumed and later closes behave
    /// normally.
    ///
    /// This is the deterministic reproduction of a refused commit with the
    /// real hub's ordering: the handle is consumed before the close is
    /// attempted, so the failure ORPHANS the pending reservation. A
    /// follow-up remove answers handle-not-found, the connection ending has
    /// nothing left to release, and the key stays pending — unreadable and
    /// unfillable — until the hub itself restarts.
    pub fn refuse_next_close(&self, key: &str) {
        lock(&self.state.inner)
            .refuse_close_once
            .insert(key.to_string());
    }

    /// Polls until `ready` holds.
    ///
    /// A client enqueues the releases its dropped handles owe rather than
    /// awaiting them, so an assertion about the hub's state waits for it to
    /// settle instead of assuming it already has.
    ///
    /// # Panics
    ///
    /// Panics naming `what` if the condition does not hold within five
    /// seconds.
    pub async fn wait_for(&self, what: &str, mut ready: impl FnMut(&Self) -> bool) {
        let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
        loop {
            if ready(self) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the fake hub timed out waiting for {what}"
            );
            tokio::time::sleep(WAIT_STEP).await;
        }
    }

    /// Polls until exactly `expected` leases are open.
    ///
    /// # Panics
    ///
    /// Panics if the count does not settle within five seconds.
    pub async fn wait_for_open_handles(&self, expected: usize) {
        self.wait_for("the open handle count to settle", |hub| {
            hub.open_handles() == expected
        })
        .await;
    }

    fn take_server(&self) -> Option<Server> {
        lock(&self.server).take()
    }
}

impl std::fmt::Debug for FakeHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeHub")
            .field("endpoint", &self.addr)
            .field("cache_dir", &self.state.cache_dir)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

/// Spawns the accept loop for `listener` and returns the handle that stops
/// it. Dropping the returned sender stops the hub too, so a dropped
/// [`FakeHub`] leaves no tasks behind.
fn serve_on(listener: TcpListener, state: Arc<HubState>) -> Server {
    let (stop, mut stopped) = watch::channel(false);
    let accept = tokio::spawn(async move {
        loop {
            let socket = tokio::select! {
                biased;
                _ = stopped.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok((socket, _)) => socket,
                    Err(_) => break,
                },
            };
            let connection = state.next_connection();
            tokio::spawn(serve(socket, state.clone(), connection, stopped.clone()));
        }
    });
    Server { stop, accept }
}

/// Answers one connection's requests until it ends, then releases every
/// lease it held.
async fn serve(
    mut socket: TcpStream,
    state: Arc<HubState>,
    connection: u64,
    mut stopped: watch::Receiver<bool>,
) {
    let _ = socket.set_nodelay(true);
    let mut connected = false;
    loop {
        if *stopped.borrow() {
            break;
        }
        let request = tokio::select! {
            biased;
            _ = stopped.changed() => break,
            frame = read_frame::<_, proto::Request>(&mut socket) => match frame {
                Ok(Some(request)) => request,
                // A closed or broken connection ends the conversation; the
                // cleanup below is the same either way.
                Ok(None) | Err(_) => break,
            },
        };
        let response = state.answer(connection, &mut connected, request);
        if write_frame(&mut socket, &response).await.is_err() {
            break;
        }
    }
    state.release_connection(connection);
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Everything a hub owns that outlives its listener.
struct HubState {
    cache_dir: PathBuf,
    config: FakeHubConfig,
    /// Never held across an await point.
    inner: Mutex<Inner>,
    counters: Counters,
}

#[derive(Default)]
struct Counters {
    opens_for_read: AtomicU64,
    opens_for_write: AtomicU64,
    closes: AtomicU64,
    removes: AtomicU64,
    connections: AtomicU64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    leases: HashMap<u64, Lease>,
    next_handle: u64,
    /// Keys armed by [`FakeHub::answer_not_cached_once`]: the next
    /// `OpenForRead` for a key in this set answers not-found regardless of
    /// the entry's real state, then the key is removed from the set.
    not_cached_once: HashSet<String>,
    /// Keys armed by [`FakeHub::refuse_next_close`]: the next `Close` of a
    /// write lease for a key in this set answers the hub's internal error
    /// instead of committing, then the key is removed from the set.
    refuse_close_once: HashSet<String>,
}

/// One cache entry. The extension is recorded because it names the file the
/// entry lives in, while the key alone decides the entry's identity.
struct Entry {
    base: String,
    extension: String,
    phase: Phase,
    readers: usize,
}

impl Entry {
    fn state(&self) -> EntryState {
        match &self.phase {
            Phase::Pending => EntryState::PendingWrite,
            Phase::Committed { size } => EntryState::Committed {
                size: *size,
                extension: self.extension.clone(),
            },
        }
    }
}

enum Phase {
    /// A write lease is filling the entry. The lease itself records which
    /// connection holds it.
    Pending,
    /// The entry is published at `size` bytes.
    Committed { size: u64 },
}

/// A lease a client holds. Handle numbers are unique hub-wide, and the
/// owning connection is recorded so one connection cannot release another's
/// lease.
struct Lease {
    connection: u64,
    key: String,
    write: bool,
}

/// Why a lease is being given up.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Release {
    /// A close request: a write lease publishes, a read lease is given back.
    Close,
    /// A remove request: a write lease discards its entry, a read lease is
    /// given back and collects the entry when it was the last reference.
    Remove,
    /// The connection ended: a write lease discards its entry, a read lease
    /// is given back.
    Disconnect,
}

impl HubState {
    fn new(cache_dir: PathBuf, config: FakeHubConfig) -> Self {
        Self {
            cache_dir,
            config,
            inner: Mutex::new(Inner::default()),
            counters: Counters::default(),
        }
    }

    fn next_connection(&self) -> u64 {
        self.counters.connections.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The file an entry with `base` occupies when it is named with
    /// `extension`.
    fn file_path(&self, base: &str, extension: &str) -> PathBuf {
        if extension.is_empty() {
            self.cache_dir.join(base)
        } else {
            self.cache_dir.join(format!("{base}.{extension}"))
        }
    }

    /// Answers one request. `connected` tracks whether this connection has
    /// completed the mandatory connect handshake.
    fn answer(
        &self,
        connection: u64,
        connected: &mut bool,
        request: proto::Request,
    ) -> proto::Response {
        let params = request.params.and_then(|params| params.params);
        let result = match params {
            None => error_info("the request carries no parameters"),
            Some(WireParams::ClientConnect(_)) => {
                *connected = true;
                WireResult::ClientConnect(proto::ClientConnectResult {})
            }
            Some(_) if !*connected => {
                error_info("the hub requires a client-connect request before any other operation")
            }
            Some(WireParams::HubVersionInfo(_)) => self.version_info(),
            Some(WireParams::CacheAsideVersionInfo(_)) => {
                WireResult::CacheAsideVersionInfo(proto::CacheAsideVersionInfoResult {
                    version: Some(proto::SemVer {
                        major: 1,
                        minor: 0,
                        patch: 0,
                    }),
                })
            }
            Some(WireParams::CacheAsideOpenForRead(params)) => {
                self.open_for_read(connection, &params)
            }
            Some(WireParams::CacheAsideOpenForWrite(params)) => {
                self.open_for_write(connection, &params)
            }
            Some(WireParams::CacheAsideClose(params)) => {
                self.counters.closes.fetch_add(1, Ordering::Relaxed);
                let code = self.release(connection, params.handle, Release::Close);
                WireResult::CacheAsideClose(proto::CacheAsideCloseResult {
                    result_code: code as i32,
                })
            }
            Some(WireParams::CacheAsideRemove(params)) => {
                self.counters.removes.fetch_add(1, Ordering::Relaxed);
                let code = self.release(connection, params.handle, Release::Remove);
                WireResult::CacheAsideRemove(proto::CacheAsideRemoveResult {
                    result_code: code as i32,
                })
            }
            Some(_) => error_info("the fake hub implements only the cache-aside interface"),
        };
        proto::Response {
            request_id: request.request_id,
            result: Some(proto::ResponseResult {
                result: Some(result),
            }),
        }
    }

    fn version_info(&self) -> WireResult {
        let (major, minor, patch) = self.config.software_version;
        WireResult::HubVersionInfo(proto::HubVersionInfoResult {
            version_info: Some(proto::VersionInfo {
                software_version: Some(proto::SemVer {
                    major,
                    minor,
                    patch,
                }),
                interface_versions: self
                    .config
                    .interfaces
                    .iter()
                    .map(|interface| proto::InterfaceVersion {
                        interface: interface.wire(),
                        version: 1,
                    })
                    .collect(),
            }),
        })
    }

    fn open_for_read(
        &self,
        connection: u64,
        params: &proto::CacheAsideOpenForReadParams,
    ) -> WireResult {
        self.counters.opens_for_read.fetch_add(1, Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        if inner.not_cached_once.remove(&params.key) {
            return read_result(ResultCode::ErrorNotFound, None, None);
        }
        let Some(entry) = inner.entries.get(&params.key) else {
            return read_result(ResultCode::ErrorNotFound, None, None);
        };
        if matches!(entry.phase, Phase::Pending) {
            return read_result(ResultCode::ErrorPendingWrite, None, None);
        }
        // The requested extension names the file, so an entry written under
        // a different one resolves to a path that was never created. The
        // open still succeeds: that is the trap callers have to check for.
        let path = self.file_path(&entry.base, &params.extension);
        let handle = inner.open_read(connection, &params.key);
        read_result(ResultCode::Success, Some(path), Some(handle))
    }

    fn open_for_write(
        &self,
        connection: u64,
        params: &proto::CacheAsideOpenForWriteParams,
    ) -> WireResult {
        self.counters
            .opens_for_write
            .fetch_add(1, Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        // Keys are write-once, and the hub distinguishes WHY a key is
        // taken: one that is still being filled answers pending-write (as
        // it does for readers), while a committed one answers
        // already-exists.
        if let Some(entry) = inner.entries.get(&params.key) {
            let code = match entry.phase {
                Phase::Pending => ResultCode::ErrorPendingWrite,
                Phase::Committed { .. } => ResultCode::ErrorAlreadyExists,
            };
            return write_result(code, None, None);
        }
        // The hub refuses a zero-byte reservation outright (its internal
        // invalid-argument error crosses the wire as the internal code), so
        // a zero-byte object can never be cached.
        if params.size == 0 {
            return write_result(ResultCode::ErrorInternal, None, None);
        }
        if self
            .config
            .max_entry_size
            .is_some_and(|max| params.size > max)
        {
            return write_result(ResultCode::ErrorTooLarge, None, None);
        }
        let base = encode_key(&params.key);
        let path = self.file_path(&base, &params.extension);
        if fs::write(&path, b"").is_err() {
            return write_result(ResultCode::ErrorInternal, None, None);
        }
        inner.entries.insert(
            params.key.clone(),
            Entry {
                base,
                extension: params.extension.clone(),
                phase: Phase::Pending,
                readers: 0,
            },
        );
        let handle = inner.open_write(connection, &params.key);
        write_result(ResultCode::Success, Some(path), Some(handle))
    }

    /// Gives up one lease. Returns the result code the request answers with;
    /// a disconnect discards it.
    fn release(&self, connection: u64, handle: u64, why: Release) -> ResultCode {
        let mut inner = lock(&self.inner);
        // A handle belongs to the connection that opened it. Releasing
        // someone else's is not a request the hub can honour.
        let owned = inner
            .leases
            .get(&handle)
            .is_some_and(|lease| lease.connection == connection);
        if !owned {
            return ResultCode::ErrorHandleNotFound;
        }
        let lease = inner.leases.remove(&handle).expect("the lease is present");
        // A refusal armed by `refuse_next_close` mirrors the real hub's
        // ordering: the handle is consumed BEFORE the close is attempted, so
        // a failed close orphans the pending reservation — no handle can
        // reach it again (a follow-up remove answers handle-not-found, and
        // the connection ending has nothing left to release), and the key
        // stays pending until the hub itself is restarted.
        if why == Release::Close && lease.write && inner.refuse_close_once.remove(&lease.key) {
            return ResultCode::ErrorInternal;
        }
        let Some(entry) = inner.entries.get_mut(&lease.key) else {
            return ResultCode::ErrorInternal;
        };
        if lease.write {
            if why == Release::Close {
                // Closing a write lease is the hub's commit: the entry takes
                // the size the client actually wrote.
                let path = self.file_path(&entry.base, &entry.extension);
                let size = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
                entry.phase = Phase::Committed { size };
            } else {
                self.discard(&mut inner, &lease.key);
            }
            return ResultCode::Success;
        }
        entry.readers = entry.readers.saturating_sub(1);
        // A remove collects the entry only when the removing lease was the
        // last reference; with other readers still holding it, the request
        // downgrades to a plain close and the entry stays readable — the
        // hub never evicts an entry a client is holding, and it keeps no
        // mark once the remove is downgraded.
        if why == Release::Remove && entry.readers == 0 {
            self.discard(&mut inner, &lease.key);
        }
        ResultCode::Success
    }

    /// Forgets an entry and deletes its file.
    fn discard(&self, inner: &mut Inner, key: &str) {
        if let Some(entry) = inner.entries.remove(key) {
            let _ = fs::remove_file(self.file_path(&entry.base, &entry.extension));
        }
    }

    /// Releases every lease a connection held when it ends: its read leases
    /// are given back and its pending writes are discarded, so a client that
    /// vanishes mid-fill leaves nothing half-written in the cache.
    fn release_connection(&self, connection: u64) {
        let handles: Vec<u64> = {
            let inner = lock(&self.inner);
            inner
                .leases
                .iter()
                .filter(|(_, lease)| lease.connection == connection)
                .map(|(handle, _)| *handle)
                .collect()
        };
        for handle in handles {
            let _ = self.release(connection, handle, Release::Disconnect);
        }
    }
}

impl Inner {
    fn open_read(&mut self, connection: u64, key: &str) -> u64 {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.readers += 1;
        }
        self.lease(connection, key, false)
    }

    fn open_write(&mut self, connection: u64, key: &str) -> u64 {
        self.lease(connection, key, true)
    }

    fn lease(&mut self, connection: u64, key: &str, write: bool) -> u64 {
        self.next_handle += 1;
        let handle = self.next_handle;
        self.leases.insert(
            handle,
            Lease {
                connection,
                key: key.to_string(),
                write,
            },
        );
        handle
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encodes `key` into a file name stem, escaping every byte outside
/// `[A-Za-z0-9_-]` as `%XX`. Dots are escaped too, so a key that contains one
/// cannot produce the same file name as another key plus an extension.
fn encode_key(key: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(key.len());
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn read_result(code: ResultCode, path: Option<PathBuf>, handle: Option<u64>) -> WireResult {
    WireResult::CacheAsideOpenForRead(proto::CacheAsideOpenForReadResult {
        result_code: code as i32,
        local_file: path.map(|path| path.to_string_lossy().into_owned()),
        handle,
    })
}

fn write_result(code: ResultCode, path: Option<PathBuf>, handle: Option<u64>) -> WireResult {
    WireResult::CacheAsideOpenForWrite(proto::CacheAsideOpenForWriteResult {
        result_code: code as i32,
        local_file: path.map(|path| path.to_string_lossy().into_owned()),
        handle,
    })
}

fn error_info(message: &str) -> WireResult {
    WireResult::ErrorInfo(proto::ErrorInfoResult {
        message: message.to_string(),
    })
}

/// Locks a mutex this module only ever holds for a few statements, treating
/// poisoning as "the previous holder panicked, the data is still ours".
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A client that speaks the wire protocol directly, for the paths the
    /// typed client cannot reach: a request before the handshake, a remove
    /// on a read lease, and a connection that simply disappears.
    struct RawClient {
        socket: TcpStream,
        next_request_id: u64,
    }

    impl RawClient {
        async fn connect(hub: &FakeHub) -> Self {
            let socket = TcpStream::connect(hub.addr()).await.expect("the hub is up");
            Self {
                socket,
                next_request_id: 1,
            }
        }

        /// Connects and completes the mandatory handshake.
        async fn handshaked(hub: &FakeHub) -> Self {
            let mut client = Self::connect(hub).await;
            let result = client
                .call(WireParams::ClientConnect(proto::ClientConnectParams {
                    client_name: "raw".to_string(),
                    client_uuid: "raw-uuid".to_string(),
                }))
                .await;
            assert!(matches!(result, WireResult::ClientConnect(_)));
            client
        }

        async fn call(&mut self, params: WireParams) -> WireResult {
            let request_id = self.next_request_id;
            self.next_request_id += 1;
            let request = proto::Request {
                request_id,
                params: Some(proto::RequestParams {
                    params: Some(params),
                }),
            };
            write_frame(&mut self.socket, &request)
                .await
                .expect("the request is written");
            let response: proto::Response = read_frame(&mut self.socket)
                .await
                .expect("the response is read")
                .expect("the hub answers");
            assert_eq!(response.request_id, request_id);
            response
                .result
                .and_then(|result| result.result)
                .expect("the response carries a result")
        }

        async fn open_for_read(&mut self, key: &str, extension: &str) -> (ResultCode, Option<u64>) {
            let result = self
                .call(WireParams::CacheAsideOpenForRead(
                    proto::CacheAsideOpenForReadParams {
                        key: key.to_string(),
                        provider: "test".to_string(),
                        extension: extension.to_string(),
                    },
                ))
                .await;
            let WireResult::CacheAsideOpenForRead(open) = result else {
                panic!("an open-for-read is answered in kind");
            };
            (code_of(open.result_code), open.handle)
        }

        async fn open_for_write(
            &mut self,
            key: &str,
            extension: &str,
            size: u64,
        ) -> (ResultCode, Option<u64>) {
            let result = self
                .call(WireParams::CacheAsideOpenForWrite(
                    proto::CacheAsideOpenForWriteParams {
                        key: key.to_string(),
                        provider: "test".to_string(),
                        extension: extension.to_string(),
                        size,
                    },
                ))
                .await;
            let WireResult::CacheAsideOpenForWrite(open) = result else {
                panic!("an open-for-write is answered in kind");
            };
            (code_of(open.result_code), open.handle)
        }

        async fn remove(&mut self, handle: u64) -> ResultCode {
            let result = self
                .call(WireParams::CacheAsideRemove(
                    proto::CacheAsideRemoveParams { handle },
                ))
                .await;
            let WireResult::CacheAsideRemove(removed) = result else {
                panic!("a remove is answered in kind");
            };
            code_of(removed.result_code)
        }

        async fn close(&mut self, handle: u64) -> ResultCode {
            let result = self
                .call(WireParams::CacheAsideClose(proto::CacheAsideCloseParams {
                    handle,
                }))
                .await;
            let WireResult::CacheAsideClose(closed) = result else {
                panic!("a close is answered in kind");
            };
            code_of(closed.result_code)
        }
    }

    fn code_of(code: i32) -> ResultCode {
        ResultCode::try_from(code).expect("the fake answers with a defined result code")
    }

    async fn hub() -> (TempDir, FakeHub) {
        let dir = TempDir::new().expect("a temporary directory");
        let hub = FakeHub::start(dir.path()).await;
        (dir, hub)
    }

    #[tokio::test]
    async fn an_operation_before_the_handshake_is_an_error_result() {
        let (_dir, hub) = hub().await;
        let mut client = RawClient::connect(&hub).await;

        let result = client
            .call(WireParams::CacheAsideOpenForRead(
                proto::CacheAsideOpenForReadParams {
                    key: "k".to_string(),
                    provider: "test".to_string(),
                    extension: "bin".to_string(),
                },
            ))
            .await;

        let WireResult::ErrorInfo(error) = result else {
            panic!("an unconnected client gets an error result");
        };
        assert!(error.message.contains("client-connect"), "{error:?}");
    }

    #[tokio::test]
    async fn the_version_probe_reports_the_configured_interfaces() {
        let dir = TempDir::new().expect("a temporary directory");
        let hub = FakeHub::start_with(
            dir.path(),
            FakeHubConfig {
                interfaces: vec![HubInterface::BlockCache],
                software_version: (4, 5, 6),
                ..FakeHubConfig::default()
            },
        )
        .await;
        let mut client = RawClient::handshaked(&hub).await;

        let result = client
            .call(WireParams::HubVersionInfo(proto::HubVersionInfoParams {}))
            .await;

        let WireResult::HubVersionInfo(info) = result else {
            panic!("a version probe is answered in kind");
        };
        let version = info.version_info.expect("the probe carries version info");
        assert_eq!(
            version.software_version,
            Some(proto::SemVer {
                major: 4,
                minor: 5,
                patch: 6
            })
        );
        let interfaces: Vec<i32> = version
            .interface_versions
            .iter()
            .map(|entry| entry.interface)
            .collect();
        assert_eq!(interfaces, vec![proto::Interface::BlockCache as i32]);
    }

    #[tokio::test]
    async fn the_cache_aside_version_is_reported() {
        let (_dir, hub) = hub().await;
        let mut client = RawClient::handshaked(&hub).await;

        let result = client
            .call(WireParams::CacheAsideVersionInfo(
                proto::CacheAsideVersionInfoParams {},
            ))
            .await;

        let WireResult::CacheAsideVersionInfo(info) = result else {
            panic!("a cache-aside version probe is answered in kind");
        };
        assert_eq!(
            info.version,
            Some(proto::SemVer {
                major: 1,
                minor: 0,
                patch: 0
            })
        );
    }

    #[tokio::test]
    async fn a_lost_connection_releases_every_lease_it_held() {
        let (_dir, hub) = hub().await;
        hub.seed_entry("warm", "bin", b"warm bytes");
        let mut client = RawClient::handshaked(&hub).await;
        let (read, _) = client.open_for_read("warm", "bin").await;
        assert_eq!(read, ResultCode::Success);
        let (write, _) = client.open_for_write("cold", "bin", 4).await;
        assert_eq!(write, ResultCode::Success);
        assert_eq!(hub.open_handles(), 2);

        // The connection simply disappears, exactly as a killed process
        // would.
        drop(client);

        hub.wait_for_open_handles(0).await;
        // The pending write is discarded; the read lease's entry survives.
        assert_eq!(hub.entry("cold"), None);
        assert!(matches!(
            hub.entry("warm"),
            Some(EntryState::Committed { .. })
        ));
    }

    #[tokio::test]
    async fn removing_a_shared_read_lease_downgrades_to_a_close() {
        let (_dir, hub) = hub().await;
        let path = hub.seed_entry("k", "bin", b"bytes");
        let mut first = RawClient::handshaked(&hub).await;
        let mut second = RawClient::handshaked(&hub).await;
        let (_, first_handle) = first.open_for_read("k", "bin").await;
        let (_, second_handle) = second.open_for_read("k", "bin").await;

        assert_eq!(
            first.remove(first_handle.expect("a handle")).await,
            ResultCode::Success
        );

        // Another reader still holds the entry, so the remove downgrades to
        // a close and leaves no mark: the entry stays readable even after
        // that reader leaves.
        assert!(matches!(hub.entry("k"), Some(EntryState::Committed { .. })));
        assert!(path.exists());
        assert_eq!(
            second.close(second_handle.expect("a handle")).await,
            ResultCode::Success
        );
        assert!(matches!(hub.entry("k"), Some(EntryState::Committed { .. })));
        assert!(path.exists());
        assert_eq!(hub.open_handles(), 0);

        // A remove by the last (sole) reference collects the entry.
        let (_, third_handle) = first.open_for_read("k", "bin").await;
        assert_eq!(
            first.remove(third_handle.expect("a handle")).await,
            ResultCode::Success
        );
        assert_eq!(hub.entry("k"), None);
        assert!(!path.exists());
        assert_eq!(hub.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_lease_belongs_to_the_connection_that_opened_it() {
        let (_dir, hub) = hub().await;
        hub.seed_entry("k", "bin", b"bytes");
        let mut owner = RawClient::handshaked(&hub).await;
        let mut stranger = RawClient::handshaked(&hub).await;
        let (_, handle) = owner.open_for_read("k", "bin").await;
        let handle = handle.expect("a handle");

        assert_eq!(
            stranger.close(handle).await,
            ResultCode::ErrorHandleNotFound
        );
        assert_eq!(
            stranger.remove(handle).await,
            ResultCode::ErrorHandleNotFound
        );
        assert_eq!(hub.open_handles(), 1);

        assert_eq!(owner.close(handle).await, ResultCode::Success);
        // A handle is released exactly once.
        assert_eq!(owner.close(handle).await, ResultCode::ErrorHandleNotFound);
    }

    #[tokio::test]
    async fn an_unknown_handle_is_not_found() {
        let (_dir, hub) = hub().await;
        let mut client = RawClient::handshaked(&hub).await;

        assert_eq!(client.close(404).await, ResultCode::ErrorHandleNotFound);
        assert_eq!(client.remove(404).await, ResultCode::ErrorHandleNotFound);
    }

    #[tokio::test]
    async fn a_block_cache_request_is_refused() {
        let (_dir, hub) = hub().await;
        let mut client = RawClient::handshaked(&hub).await;

        let result = client
            .call(WireParams::BlockCacheGet(proto::BlockCacheGetParams {
                keys: vec![b"block".to_vec()],
                timeout_us: 0,
            }))
            .await;

        assert!(matches!(result, WireResult::ErrorInfo(_)), "{result:?}");
    }

    #[tokio::test]
    async fn answer_not_cached_once_forces_one_not_found_then_normal_behavior() {
        let (_dir, hub) = hub().await;
        hub.seed_entry("k", "bin", b"bytes");
        hub.answer_not_cached_once("k");
        let mut client = RawClient::handshaked(&hub).await;

        let (code, handle) = client.open_for_read("k", "bin").await;
        assert_eq!(code, ResultCode::ErrorNotFound);
        assert!(handle.is_none());
        // The committed entry itself is untouched by the override.
        assert!(matches!(hub.entry("k"), Some(EntryState::Committed { .. })));

        // The override is consumed: the next open sees the real state.
        let (code, handle) = client.open_for_read("k", "bin").await;
        assert_eq!(code, ResultCode::Success);
        assert!(handle.is_some());
    }

    #[tokio::test]
    async fn refuse_next_close_consumes_the_handle_and_orphans_the_reservation() {
        let (_dir, hub) = hub().await;
        hub.refuse_next_close("k");
        let mut client = RawClient::handshaked(&hub).await;
        let (code, handle) = client.open_for_write("k", "bin", 4).await;
        assert_eq!(code, ResultCode::Success);
        let handle = handle.expect("a handle");

        assert_eq!(client.close(handle).await, ResultCode::ErrorInternal);
        // The real hub consumes the handle before attempting the close, so
        // the failed commit orphans the reservation: still pending, but no
        // handle can reach it.
        assert_eq!(hub.entry("k"), Some(EntryState::PendingWrite));
        assert_eq!(
            hub.open_handles(),
            0,
            "the refused close consumed the handle"
        );
        assert_eq!(client.remove(handle).await, ResultCode::ErrorHandleNotFound);
        assert_eq!(hub.entry("k"), Some(EntryState::PendingWrite));

        // The orphan blocks every later writer and reader of the key.
        let (code, refused) = client.open_for_write("k", "bin", 4).await;
        assert_eq!(code, ResultCode::ErrorPendingWrite);
        assert!(refused.is_none());
        let (code, _) = client.open_for_read("k", "bin").await;
        assert_eq!(code, ResultCode::ErrorPendingWrite);

        // The override was one-shot and per-key: an untouched key commits
        // normally.
        let (code, handle) = client.open_for_write("other", "bin", 4).await;
        assert_eq!(code, ResultCode::Success);
        assert_eq!(
            client.close(handle.expect("a handle")).await,
            ResultCode::Success
        );
        assert!(matches!(
            hub.entry("other"),
            Some(EntryState::Committed { .. })
        ));
    }

    #[test]
    fn the_file_name_escapes_every_byte_outside_the_safe_set() {
        assert_eq!(encode_key("plain-key_1"), "plain-key_1");
        assert_eq!(encode_key("a.b"), "a%2Eb");
        assert_eq!(encode_key("s3://bucket/o"), "s3%3A%2F%2Fbucket%2Fo");
        // Escaping the dot keeps a key that contains one from colliding with
        // another key's extension.
        assert_ne!(encode_key("a.b"), format!("{}.b", encode_key("a")));
    }
}
