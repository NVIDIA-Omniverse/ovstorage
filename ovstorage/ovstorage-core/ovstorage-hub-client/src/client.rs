// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The connect-only hub cache-aside client.
//!
//! One [`HubCacheClient`] owns at most one TCP connection to the hub. The
//! connection is dialled lazily by the first operation, handshaked before it
//! is usable, and then shared by every subsequent operation. A background
//! task owns the socket: callers hand it a request over an unbounded
//! channel and wait on a oneshot for the matching response, because the hub
//! answers out of order and correlates only by `request_id`.
//!
//! Handles returned by the open operations hold hub leases. Every lease is
//! released exactly once: explicitly through
//! [`ReadHandle::close`]/[`WriteHandle::commit`]/[`WriteHandle::abort`], or
//! implicitly by `Drop`, which enqueues a fire-and-forget release. A dropped
//! write handle sends `Remove`, never `Close`, so an uncommitted write is
//! never implicitly committed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::time::Instant;
use tracing::debug;

use crate::proto;
use crate::proto::request_params::Params as WireParams;
use crate::proto::response_result::Result as WireResult;
use crate::types::{HubClientConfig, HubError, HubResultCode, ReadOpen, WriteOpen};
use crate::wire::{read_frame, write_frame};

/// The cache-aside protocol revision this client is written against. The
/// hub's contract keeps the number constant unless the protocol changes, so
/// a hub advertising any other revision fails the handshake.
const SUPPORTED_CACHE_ASIDE_VERSION: u32 = 1;

/// The most unanswered requests one connection may hold before the client
/// presumes the hub wedged and tears the connection down. Far above any
/// healthy in-flight count; a backstop, not a throttle.
const MAX_PENDING_REQUESTS: usize = 4096;

/// A hub client bound to one endpoint.
///
/// Construction performs no I/O. The client is cheap to clone — a clone
/// shares the same connection, the same request-id sequence and the same
/// cooldown state — so callers pass it around by value rather than wrapping
/// it in another `Arc`.
#[derive(Clone)]
pub struct HubCacheClient {
    shared: Arc<Shared>,
}

impl HubCacheClient {
    /// Creates a client for `config` without contacting the hub. The first
    /// operation dials.
    pub fn new(config: HubClientConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                client_uuid: uuid::Uuid::new_v4().to_string(),
                config,
                next_request_id: Arc::new(AtomicU64::new(1)),
                inflight: Arc::new(Inflight::default()),
                slot: Mutex::new(Slot::default()),
                dial: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// The settings this client was built with.
    pub fn config(&self) -> &HubClientConfig {
        &self.shared.config
    }

    /// Opens `key` for reading.
    ///
    /// `provider` is diagnostic only — the hub discards it. `extension`
    /// participates in the cached file's name but not in its identity, so
    /// reading a key with an extension other than the one it was written
    /// with succeeds and yields a path that does not exist; callers check
    /// the path before trusting it.
    pub async fn open_for_read(
        &self,
        key: &str,
        provider: &str,
        extension: &str,
    ) -> Result<ReadOpen, HubError> {
        let conn = self.shared.connection().await?;
        let params = WireParams::CacheAsideOpenForRead(proto::CacheAsideOpenForReadParams {
            key: key.to_string(),
            provider: provider.to_string(),
            extension: extension.to_string(),
        });
        let result = call(
            &conn,
            self.shared.config.timeout,
            params,
            LateRelease::Close,
        )
        .await?;
        let WireResult::CacheAsideOpenForRead(result) = result else {
            return Err(HubError::protocol(format!(
                "open-for-read answered with {}",
                result_name(&result)
            )));
        };
        match HubResultCode::from_wire(result.result_code) {
            HubResultCode::Success => {
                let (path, handle) = opened(&conn, result.local_file, result.handle, false)?;
                Ok(ReadOpen::Opened(ReadHandle {
                    shared: self.shared.clone(),
                    generation: conn.generation,
                    handle,
                    path,
                    released: false,
                }))
            }
            HubResultCode::NotFound => Ok(ReadOpen::NotCached),
            HubResultCode::PendingWrite => Ok(ReadOpen::PendingWrite),
            code => Err(HubError::Hub(code)),
        }
    }

    /// Opens `key` for writing, reserving it at `size` bytes.
    ///
    /// Hub keys are write-once: a key another client already stored comes
    /// back as [`WriteOpen::AlreadyExists`], which is the benign answer to a
    /// redundant fill rather than a failure.
    pub async fn open_for_write(
        &self,
        key: &str,
        provider: &str,
        extension: &str,
        size: u64,
    ) -> Result<WriteOpen, HubError> {
        let conn = self.shared.connection().await?;
        let params = WireParams::CacheAsideOpenForWrite(proto::CacheAsideOpenForWriteParams {
            key: key.to_string(),
            provider: provider.to_string(),
            extension: extension.to_string(),
            size,
        });
        let result = call(
            &conn,
            self.shared.config.timeout,
            params,
            LateRelease::Remove,
        )
        .await?;
        let WireResult::CacheAsideOpenForWrite(result) = result else {
            return Err(HubError::protocol(format!(
                "open-for-write answered with {}",
                result_name(&result)
            )));
        };
        match HubResultCode::from_wire(result.result_code) {
            HubResultCode::Success => {
                let (path, handle) = opened(&conn, result.local_file, result.handle, true)?;
                Ok(WriteOpen::Opened(WriteHandle {
                    shared: self.shared.clone(),
                    generation: conn.generation,
                    handle,
                    path,
                    released: false,
                }))
            }
            HubResultCode::AlreadyExists => Ok(WriteOpen::AlreadyExists),
            HubResultCode::PendingWrite => Ok(WriteOpen::PendingWrite),
            HubResultCode::TooLarge => Ok(WriteOpen::TooLarge),
            code => Err(HubError::Hub(code)),
        }
    }

    /// Whether the client currently knows it cannot serve: no connection is
    /// installed and the last failure's cooldown is still running.
    ///
    /// Costs one mutex acquisition and no I/O. A fresh client — never
    /// dialled — reports available, so the first operation still dials;
    /// during a cooldown, callers can skip work they would only have been
    /// doing for the hub's sake instead of paying for it and then being
    /// told the same thing by the fail-fast dial.
    pub fn unavailable(&self) -> bool {
        let slot = lock(&self.shared.slot);
        slot.conn.is_none()
            && slot
                .cooldown_until
                .is_some_and(|until| Instant::now() < until)
    }

    /// The number of requests this client has submitted and not yet
    /// retired, including releases enqueued by dropped handles.
    ///
    /// Handle-leak accounting reads this: a client with no live handles and
    /// no outstanding calls settles at zero.
    pub fn pending_ops(&self) -> usize {
        self.shared.inflight.count.load(Ordering::Acquire)
    }

    /// Waits until [`HubCacheClient::pending_ops`] reaches zero.
    ///
    /// A handle released by `Drop` is enqueued rather than awaited, so tests
    /// and shutdown paths use this to observe the release before they assert
    /// on the hub's state.
    pub async fn quiesce(&self) {
        loop {
            let notified = self.shared.inflight.idle.notified();
            tokio::pin!(notified);
            // Register before the count check so a release that completes in
            // between still wakes this waiter.
            notified.as_mut().enable();
            if self.pending_ops() == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl std::fmt::Debug for HubCacheClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubCacheClient")
            .field("endpoint", &self.shared.config.endpoint)
            .finish()
    }
}

/// A read lease on a cached entry.
///
/// The hub keeps the entry alive while the lease is held. Dropping the
/// handle enqueues a fire-and-forget `Close`; [`ReadHandle::close`] sends the
/// same release and waits for the hub to acknowledge it.
pub struct ReadHandle {
    shared: Arc<Shared>,
    generation: u64,
    handle: u64,
    path: PathBuf,
    released: bool,
}

impl ReadHandle {
    /// The local file the hub cached this entry in.
    ///
    /// The path is not guaranteed to exist: an entry stored under one
    /// extension and opened under another resolves to a name the hub never
    /// wrote.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Releases the lease and waits for the hub's acknowledgement.
    ///
    /// A handle whose connection has been replaced has nothing to release —
    /// the hub drops a connection's leases when that connection ends — so
    /// that case succeeds without a round trip.
    pub async fn close(mut self) -> Result<(), HubError> {
        self.released = true;
        let Some(conn) = self.shared.connection_for(self.generation) else {
            return Ok(());
        };
        release_call(
            &conn,
            self.shared.config.timeout,
            WireParams::CacheAsideClose(proto::CacheAsideCloseParams {
                handle: self.handle,
            }),
        )
        .await
    }
}

impl Drop for ReadHandle {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.shared.enqueue_release(
            self.generation,
            WireParams::CacheAsideClose(proto::CacheAsideCloseParams {
                handle: self.handle,
            }),
        );
    }
}

impl std::fmt::Debug for ReadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadHandle")
            .field("handle", &self.handle)
            .field("path", &self.path)
            .finish()
    }
}

/// A write lease on a reserved entry.
///
/// The caller writes the bytes into [`WriteHandle::path`] and then commits.
/// `Close` is the hub's "writing complete" signal, so it is sent only by
/// [`WriteHandle::commit`]; [`WriteHandle::abort`] and `Drop` send `Remove`,
/// which keeps a half-written entry out of the cache.
pub struct WriteHandle {
    shared: Arc<Shared>,
    generation: u64,
    handle: u64,
    path: PathBuf,
    released: bool,
}

impl WriteHandle {
    /// The local file to write the entry's bytes into.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publishes the entry and waits for the hub's acknowledgement.
    ///
    /// A handle whose connection has been replaced fails: the hub discarded
    /// the reservation when the connection ended, so the entry is not in the
    /// cache and the caller must not believe it is.
    ///
    /// A commit the hub refuses is followed by a best-effort remove: hub
    /// keys are write-once, so a reservation nothing can publish is only
    /// ever in the way. Against the real hub the remove cannot land — a
    /// close consumes the handle before it is attempted, so a failed close
    /// orphans the reservation hub-side (pending until the hub restarts) and
    /// the remove answers handle-not-found. It is sent anyway because it is
    /// harmless there and reclaims the reservation on any implementation
    /// that keeps the handle alive across a refused close.
    pub async fn commit(mut self) -> Result<(), HubError> {
        self.released = true;
        let Some(conn) = self.shared.connection_for(self.generation) else {
            return Err(HubError::unavailable(
                "the connection that reserved this entry ended before the write was committed",
            ));
        };
        let outcome = release_call(
            &conn,
            self.shared.config.timeout,
            WireParams::CacheAsideClose(proto::CacheAsideCloseParams {
                handle: self.handle,
            }),
        )
        .await;
        if outcome.is_err() {
            conn.submit_release(WireParams::CacheAsideRemove(
                proto::CacheAsideRemoveParams {
                    handle: self.handle,
                },
            ));
        }
        outcome
    }

    /// Discards the entry. Failures are not actionable — the connection
    /// ending discards the entry too — so the outcome is not reported.
    pub async fn abort(mut self) {
        self.released = true;
        let Some(conn) = self.shared.connection_for(self.generation) else {
            return;
        };
        let params = WireParams::CacheAsideRemove(proto::CacheAsideRemoveParams {
            handle: self.handle,
        });
        if let Err(err) = release_call(&conn, self.shared.config.timeout, params).await {
            debug!(handle = self.handle, %err, "aborting a hub write handle failed");
        }
    }
}

impl Drop for WriteHandle {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.shared.enqueue_release(
            self.generation,
            WireParams::CacheAsideRemove(proto::CacheAsideRemoveParams {
                handle: self.handle,
            }),
        );
    }
}

impl std::fmt::Debug for WriteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteHandle")
            .field("handle", &self.handle)
            .field("path", &self.path)
            .finish()
    }
}

/// Validates the local file and handle a successful open must carry.
///
/// A success that carries a handle but no path leaves a lease the caller
/// cannot use, so the lease is released before the protocol violation is
/// reported.
fn opened(
    conn: &Connection,
    local_file: Option<String>,
    handle: Option<u64>,
    write: bool,
) -> Result<(PathBuf, u64), HubError> {
    match (local_file, handle) {
        (Some(path), Some(handle)) => Ok((PathBuf::from(path), handle)),
        (_, handle) => {
            if let Some(handle) = handle {
                conn.submit_release(release_params(handle, write));
            }
            Err(HubError::protocol(
                "the hub answered an open with success but no local file",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Shared client state
// ---------------------------------------------------------------------------

/// State every clone of a [`HubCacheClient`] shares.
struct Shared {
    config: HubClientConfig,
    client_uuid: String,
    /// Request ids are unique across the client's whole lifetime, so a frame
    /// from a previous connection can never collide with a live request.
    next_request_id: Arc<AtomicU64>,
    inflight: Arc<Inflight>,
    /// Never held across an await point.
    slot: Mutex<Slot>,
    /// Serialises dialling so a burst of concurrent first operations opens
    /// one connection rather than one each.
    dial: tokio::sync::Mutex<()>,
}

/// The current connection, or the cooldown that has to expire first.
#[derive(Default)]
struct Slot {
    conn: Option<Arc<Connection>>,
    cooldown_until: Option<Instant>,
    generation: u64,
}

impl Shared {
    /// Returns the live connection, dialling and handshaking one if needed.
    async fn connection(self: &Arc<Self>) -> Result<Arc<Connection>, HubError> {
        if let Some(conn) = self.live_connection()? {
            return Ok(conn);
        }
        let _dialing = self.dial.lock().await;
        if let Some(conn) = self.live_connection()? {
            return Ok(conn);
        }
        match self.dial_and_handshake().await {
            Ok(conn) => Ok(conn),
            Err(err) => {
                self.enter_cooldown();
                Err(err)
            }
        }
    }

    /// The connection if one is up, `None` if a dial is needed, and an error
    /// while the post-failure cooldown is still running.
    fn live_connection(&self) -> Result<Option<Arc<Connection>>, HubError> {
        let mut slot = lock(&self.slot);
        if let Some(conn) = &slot.conn {
            return Ok(Some(conn.clone()));
        }
        if let Some(until) = slot.cooldown_until {
            if Instant::now() < until {
                return Err(HubError::unavailable(format!(
                    "the hub at {} is in its reconnect cooldown",
                    self.config.endpoint
                )));
            }
            slot.cooldown_until = None;
        }
        Ok(None)
    }

    async fn dial_and_handshake(self: &Arc<Self>) -> Result<Arc<Connection>, HubError> {
        let endpoint = self.config.endpoint.clone();
        let mut stream = tokio::time::timeout(self.config.timeout, TcpStream::connect(&endpoint))
            .await
            .map_err(|_| {
                HubError::unavailable(format!("dialling the hub at {endpoint} hit the deadline"))
            })?
            .map_err(|err| {
                HubError::unavailable(format!("dialling the hub at {endpoint}: {err}"))
            })?;
        // The protocol is strictly request/response, so Nagle only adds
        // latency.
        let _ = stream.set_nodelay(true);
        tokio::time::timeout(self.config.timeout, self.handshake(&mut stream))
            .await
            .map_err(|_| {
                HubError::unavailable(format!(
                    "the handshake with the hub at {endpoint} hit the deadline"
                ))
            })??;

        let (tx, rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(None);
        let conn = {
            let mut slot = lock(&self.slot);
            slot.generation += 1;
            let conn = Arc::new(Connection {
                generation: slot.generation,
                tx,
                shutdown: shutdown_tx,
                next_request_id: self.next_request_id.clone(),
                inflight: self.inflight.clone(),
                pending: Mutex::new(Some(HashMap::new())),
            });
            // Published before the connection task exists: teardown retires
            // the slot by generation, so the slot must already name this
            // connection when the task starts, or a hub that disconnects
            // immediately after the handshake would race the insertion —
            // retiring nothing, then leaving a dead connection installed with
            // no cooldown and nothing left to ever retire it.
            slot.conn = Some(conn.clone());
            slot.cooldown_until = None;
            conn
        };
        tokio::spawn(run_connection(
            stream,
            rx,
            shutdown_rx,
            conn.clone(),
            Arc::downgrade(self),
            endpoint,
            self.config.timeout,
        ));
        Ok(conn)
    }

    /// Performs the mandatory connect request and the interface probe that
    /// makes the connection usable.
    async fn handshake(&self, stream: &mut TcpStream) -> Result<(), HubError> {
        let connect = WireParams::ClientConnect(proto::ClientConnectParams {
            client_name: self.config.client_name.clone(),
            client_uuid: self.client_uuid.clone(),
        });
        match self.exchange(stream, connect).await? {
            WireResult::ClientConnect(_) => {}
            other => {
                return Err(HubError::protocol(format!(
                    "the connect request answered with {}",
                    result_name(&other)
                )));
            }
        }

        let probe = WireParams::HubVersionInfo(proto::HubVersionInfoParams {});
        let info = match self.exchange(stream, probe).await? {
            WireResult::HubVersionInfo(info) => info,
            other => {
                return Err(HubError::protocol(format!(
                    "the version probe answered with {}",
                    result_name(&other)
                )));
            }
        };
        let version = info.version_info.ok_or_else(|| {
            HubError::protocol("the hub's version response carries no version info")
        })?;
        let software = version.software_version.unwrap_or_default();
        let interfaces: Vec<(i32, u32)> = version
            .interface_versions
            .iter()
            .map(|entry| (entry.interface, entry.version))
            .collect();
        debug!(
            endpoint = %self.config.endpoint,
            software_version = %format_args!("{}.{}.{}", software.major, software.minor, software.patch),
            ?interfaces,
            "hub handshake complete"
        );
        let cache_aside = proto::Interface::CacheAside as i32;
        let Some((_, advertised)) = interfaces.iter().find(|(id, _)| *id == cache_aside) else {
            return Err(HubError::protocol(format!(
                "the hub at {} does not offer the cache-aside interface",
                self.config.endpoint
            )));
        };
        // The version is enforced, not just reported: the hub's protocol doc
        // says this number changes only when the protocol changes, so a hub
        // speaking a revision this client was not written against must fail
        // the handshake (and pass reads through) rather than exchange frames
        // it may misinterpret.
        if *advertised != SUPPORTED_CACHE_ASIDE_VERSION {
            return Err(HubError::protocol(format!(
                "the hub at {} speaks cache-aside version {advertised}; \
                 this client supports version {SUPPORTED_CACHE_ASIDE_VERSION}",
                self.config.endpoint
            )));
        }
        Ok(())
    }

    /// One request and its response on a socket that no reader task owns
    /// yet. Used only by the handshake, which is strictly sequential.
    async fn exchange(
        &self,
        stream: &mut TcpStream,
        params: WireParams,
    ) -> Result<WireResult, HubError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = proto::Request {
            request_id,
            params: Some(proto::RequestParams {
                params: Some(params),
            }),
        };
        write_frame(stream, &request).await.map_err(|err| {
            HubError::unavailable(format!(
                "writing to the hub at {}: {err}",
                self.config.endpoint
            ))
        })?;
        let response: proto::Response = read_frame(stream)
            .await
            .map_err(|err| {
                HubError::unavailable(format!(
                    "reading from the hub at {}: {err}",
                    self.config.endpoint
                ))
            })?
            .ok_or_else(|| {
                HubError::unavailable(format!(
                    "the hub at {} closed the connection during the handshake",
                    self.config.endpoint
                ))
            })?;
        if response.request_id != request_id {
            return Err(HubError::protocol(format!(
                "the hub answered handshake request {request_id} with request id {}",
                response.request_id
            )));
        }
        match response.result.and_then(|result| result.result) {
            Some(WireResult::ErrorInfo(error)) => Err(HubError::protocol(format!(
                "the hub reported: {}",
                error.message
            ))),
            Some(result) => Ok(result),
            None => Err(HubError::protocol(
                "the hub's handshake response carries no result",
            )),
        }
    }

    /// Stamps the fail-fast window that follows a connection failure.
    fn enter_cooldown(&self) {
        let mut slot = lock(&self.slot);
        slot.conn = None;
        slot.cooldown_until = Some(Instant::now() + self.config.cooldown);
    }

    /// Retires connection `generation` if it is still the current one.
    fn retire(&self, generation: u64) {
        let mut slot = lock(&self.slot);
        if slot
            .conn
            .as_ref()
            .is_some_and(|conn| conn.generation == generation)
        {
            slot.conn = None;
            slot.cooldown_until = Some(Instant::now() + self.config.cooldown);
        }
    }

    /// The current connection, but only if it is the one `generation`
    /// identifies.
    fn connection_for(&self, generation: u64) -> Option<Arc<Connection>> {
        let slot = lock(&self.slot);
        match &slot.conn {
            Some(conn) if conn.generation == generation => Some(conn.clone()),
            _ => None,
        }
    }

    /// Queues a release without waiting for it.
    ///
    /// Handle numbers belong to the connection that issued them, so a
    /// release from a replaced connection is dropped rather than sent: the
    /// hub already released that connection's leases, and the number may now
    /// name someone else's entry.
    fn enqueue_release(&self, generation: u64, params: WireParams) {
        let Some(conn) = self.connection_for(generation) else {
            return;
        };
        conn.submit_release(params);
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Releases queued by the last handles are already in the channel;
        // the connection task writes them and then stops.
        if let Some(conn) = lock(&self.slot).conn.take() {
            conn.signal_shutdown(HubError::unavailable("the hub client was dropped"));
        }
    }
}

/// Sends a release and waits for the hub's acknowledgement.
async fn release_call(
    conn: &Arc<Connection>,
    timeout: Duration,
    params: WireParams,
) -> Result<(), HubError> {
    let result = call(conn, timeout, params, LateRelease::None).await?;
    let code = match &result {
        WireResult::CacheAsideClose(close) => close.result_code,
        WireResult::CacheAsideRemove(remove) => remove.result_code,
        other => {
            return Err(HubError::protocol(format!(
                "a release answered with {}",
                result_name(other)
            )));
        }
    };
    match HubResultCode::from_wire(code) {
        HubResultCode::Success => Ok(()),
        code => Err(HubError::Hub(code)),
    }
}

// ---------------------------------------------------------------------------
// In-flight accounting
// ---------------------------------------------------------------------------

/// Counts submitted-but-unretired requests so callers can wait for the
/// client to settle.
#[derive(Default)]
struct Inflight {
    count: AtomicUsize,
    idle: Notify,
}

impl Inflight {
    fn enter(self: &Arc<Self>) -> InflightGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        InflightGuard(self.clone())
    }
}

/// Retires one in-flight request when it is dropped, which happens whether
/// the request is answered, failed by a teardown, or discarded unsent.
struct InflightGuard(Arc<Inflight>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// What a response that arrives after its caller gave up requires, so a
/// handle the caller never saw is not left pinning an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LateRelease {
    /// The request cannot produce a handle.
    None,
    /// A read lease: release it with `Close`.
    Close,
    /// A write lease: release it with `Remove`, never `Close`.
    Remove,
}

/// The release a lease needs: `Remove` discards a write reservation,
/// `Close` gives back a read lease and commits a write.
fn release_params(handle: u64, remove: bool) -> WireParams {
    if remove {
        WireParams::CacheAsideRemove(proto::CacheAsideRemoveParams { handle })
    } else {
        WireParams::CacheAsideClose(proto::CacheAsideCloseParams { handle })
    }
}

/// A request the connection task has not answered yet.
enum Pending {
    /// A caller is waiting on `reply`.
    Call {
        reply: oneshot::Sender<Delivered>,
        late: LateRelease,
        _guard: InflightGuard,
    },
    /// A fire-and-forget release; its response is consumed silently.
    Release { _guard: InflightGuard },
}

/// A response travelling to its caller, carrying its own release duty.
///
/// A oneshot `send` succeeds as long as the receiver is alive, even when
/// that receiver is about to be dropped without another poll — a caller
/// whose deadline elapsed in the same instant, or whose future was dropped
/// mid-await. A lease-carrying result silently discarded that way would pin
/// its hub entry forever, so the release lives in this guard's `Drop`
/// rather than in any code path that has to observe the hand-off: whoever
/// ends up holding the value — the caller, the failed `send`, or the
/// dropped receiver — releases it exactly once unless it was consumed.
struct Delivered {
    result: Option<Result<WireResult, HubError>>,
    late: LateRelease,
    conn: Weak<Connection>,
}

impl Delivered {
    /// Consumes the response, transferring the release duty to the caller.
    fn take(mut self) -> Result<WireResult, HubError> {
        self.result.take().expect("a delivered response is present")
    }
}

impl Drop for Delivered {
    fn drop(&mut self) {
        let Some(Ok(result)) = self.result.take() else {
            return;
        };
        if let Some(conn) = self.conn.upgrade() {
            conn.release_late(&result, self.late);
        }
    }
}

/// One frame for the task that owns the socket's write half.
struct Frame {
    request_id: u64,
    params: WireParams,
}

/// One live connection to the hub.
struct Connection {
    /// Distinguishes this connection from its replacements. Hub handle
    /// numbers are scoped to the connection that issued them.
    generation: u64,
    tx: mpsc::UnboundedSender<Frame>,
    /// The out-of-band teardown signal. It deliberately does not travel the
    /// frame channel: a queued backlog must never delay a shutdown behind
    /// the writes in front of it, and repeated signals collapse into one
    /// value instead of growing a queue. The first reason wins.
    shutdown: watch::Sender<Option<HubError>>,
    next_request_id: Arc<AtomicU64>,
    inflight: Arc<Inflight>,
    /// `None` once the connection is torn down, which rejects late
    /// submissions instead of leaving them unanswered.
    pending: Mutex<Option<HashMap<u64, Pending>>>,
}

impl Connection {
    /// Registers a correlation entry and queues the frame that fills it.
    fn submit(
        &self,
        params: WireParams,
        late: LateRelease,
    ) -> Result<oneshot::Receiver<Delivered>, HubError> {
        let (reply, receiver) = oneshot::channel();
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let pending = Pending::Call {
            reply,
            late,
            _guard: self.inflight.enter(),
        };
        self.register(request_id, pending)?;
        self.dispatch_frame(request_id, params)?;
        Ok(receiver)
    }

    /// Queues a release nobody waits on. The correlation entry still exists
    /// so the hub's acknowledgement is not mistaken for a stray response.
    fn submit_release(&self, params: WireParams) {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let pending = Pending::Release {
            _guard: self.inflight.enter(),
        };
        if self.register(request_id, pending).is_ok() {
            let _ = self.dispatch_frame(request_id, params);
        }
    }

    fn register(&self, request_id: u64, pending: Pending) -> Result<(), HubError> {
        let mut guard = lock(&self.pending);
        let map = guard
            .as_mut()
            .ok_or_else(|| HubError::unavailable("the hub connection is closed"))?;
        // Correlation entries whose caller gave up are deliberately retained
        // for their late-release duty, so a hub that accepts requests but
        // never answers them accumulates entries. This bound is the
        // backstop: a map this size means the hub is not answering, and
        // presuming the connection wedged reclaims everything through the
        // ordinary teardown.
        if map.len() >= MAX_PENDING_REQUESTS {
            drop(guard);
            let reason =
                HubError::unavailable("the hub has too many unanswered requests; presumed wedged");
            self.signal_shutdown(reason.clone());
            return Err(reason);
        }
        map.insert(request_id, pending);
        Ok(())
    }

    /// Signals the connection task to tear down for `reason`. The first
    /// signal wins; later ones are no-ops.
    fn signal_shutdown(&self, reason: HubError) {
        self.shutdown.send_if_modified(|slot| {
            if slot.is_none() {
                *slot = Some(reason);
                true
            } else {
                false
            }
        });
    }

    fn dispatch_frame(&self, request_id: u64, params: WireParams) -> Result<(), HubError> {
        if self.tx.send(Frame { request_id, params }).is_err() {
            self.take_pending(request_id);
            return Err(HubError::unavailable("the hub connection is closed"));
        }
        Ok(())
    }

    fn take_pending(&self, request_id: u64) -> Option<Pending> {
        lock(&self.pending)
            .as_mut()
            .and_then(|map| map.remove(&request_id))
    }

    /// Routes one response to the request that asked for it.
    fn dispatch(self: &Arc<Self>, response: proto::Response) {
        let request_id = response.request_id;
        let Some(pending) = self.take_pending(request_id) else {
            debug!(request_id, "a hub response matched no pending request");
            return;
        };
        let Some(result) = response.result.and_then(|result| result.result) else {
            if let Pending::Call { reply, late, .. } = pending {
                let _ = reply.send(Delivered {
                    result: Some(Err(HubError::protocol("a hub response carries no result"))),
                    late,
                    conn: Weak::new(),
                });
            }
            return;
        };
        match pending {
            Pending::Release { .. } => {
                let outcome = match &result {
                    WireResult::CacheAsideClose(close) => Some(close.result_code),
                    WireResult::CacheAsideRemove(remove) => Some(remove.result_code),
                    WireResult::ErrorInfo(error) => {
                        debug!(message = %error.message, "the hub rejected a release");
                        None
                    }
                    _ => None,
                };
                if let Some(code) = outcome.map(HubResultCode::from_wire)
                    && code != HubResultCode::Success
                {
                    debug!(%code, "a hub release was not acknowledged");
                }
            }
            Pending::Call { reply, late, .. } => {
                let payload = match result {
                    WireResult::ErrorInfo(error) => Err(HubError::protocol(format!(
                        "the hub reported: {}",
                        error.message
                    ))),
                    other => Ok(other),
                };
                // The guard carries the release duty: a failed send drops
                // the value here, a receiver dropped without polling drops
                // it there, and either drop releases a carried lease.
                let _ = reply.send(Delivered {
                    result: Some(payload),
                    late,
                    conn: Arc::downgrade(self),
                });
            }
        }
    }

    /// Releases a lease carried by a response whose caller already gave up.
    fn release_late(&self, result: &WireResult, late: LateRelease) {
        if late == LateRelease::None {
            return;
        }
        let handle = match result {
            WireResult::CacheAsideOpenForRead(open) => open.handle,
            WireResult::CacheAsideOpenForWrite(open) => open.handle,
            _ => None,
        };
        let Some(handle) = handle else {
            return;
        };
        debug!(
            handle,
            "releasing a hub handle from a response that arrived after its deadline"
        );
        self.submit_release(release_params(handle, late == LateRelease::Remove));
    }

    /// Fails every unanswered request and refuses new ones.
    fn fail_pending(&self, reason: &HubError) {
        let Some(map) = lock(&self.pending).take() else {
            return;
        };
        for pending in map.into_values() {
            if let Pending::Call { reply, late, .. } = pending {
                let _ = reply.send(Delivered {
                    result: Some(Err(reason.clone())),
                    late,
                    conn: Weak::new(),
                });
            }
        }
    }
}

/// Submits `params` and waits for its response under the call deadline.
///
/// A deadline that expires tears the connection down: the hub is a local
/// metadata service, so a call that cannot answer within its budget means
/// the connection is wedged — an open socket to a stopped or deadlocked
/// process — and without the teardown every later call would pay the full
/// deadline forever while the correlation map grew without bound. The
/// teardown fails the other in-flight calls, retires the slot into its
/// cooldown, and ends the connection, which releases every lease the hub
/// still holds for it. A response racing the expiry is covered either way:
/// undelivered, its correlation entry's late disposition releases the
/// lease; delivered into the dropped receiver, [`Delivered`]'s drop does.
///
/// The deadline is owned by a spawned watchdog rather than by this future,
/// so a caller that stops waiting — a cancelled request dropping the future
/// mid-flight — takes nothing with it. The watchdog waits out the same
/// deadline: a late response still has its lease released by
/// [`Delivered`]'s drop, and a hub that never answers is still presumed
/// wedged and torn down. Without that, one abandoned call against a silent
/// hub would sit in the correlation map indefinitely — a single entry never
/// reaches the backstop — while any reservation the hub made for it stayed
/// pinned until something else ended the connection.
async fn call(
    conn: &Arc<Connection>,
    timeout: Duration,
    params: WireParams,
    late: LateRelease,
) -> Result<WireResult, HubError> {
    let receiver = conn.submit(params, late)?;
    let (relay, response) = oneshot::channel();
    let watchdog = conn.clone();
    tokio::spawn(async move {
        let outcome = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(delivered)) => Ok(delivered),
            Ok(Err(_)) => Err(HubError::unavailable(
                "the hub connection closed before the response arrived",
            )),
            Err(_) => {
                let reason = HubError::unavailable(format!(
                    "a hub request exceeded its {}ms deadline; the connection is presumed wedged",
                    timeout.as_millis()
                ));
                watchdog.signal_shutdown(reason.clone());
                Err(reason)
            }
        };
        // A caller that stopped listening drops the outcome right here, and
        // a dropped `Delivered` releases any lease it carries.
        let _ = relay.send(outcome);
    });
    match response.await {
        Ok(Ok(delivered)) => delivered.take(),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(HubError::unavailable(
            "the hub connection closed before the response arrived",
        )),
    }
}

/// Owns one socket for its whole life: writes queued frames, reads
/// responses, and tears the connection down when either side stops.
async fn run_connection(
    stream: TcpStream,
    rx: mpsc::UnboundedReceiver<Frame>,
    shutdown: watch::Receiver<Option<HubError>>,
    conn: Arc<Connection>,
    shared: Weak<Shared>,
    endpoint: String,
    write_timeout: Duration,
) {
    let (read_half, write_half) = stream.into_split();
    let reader = tokio::spawn(read_loop(read_half, conn.clone(), endpoint.clone()));
    let reason = write_loop(write_half, rx, shutdown, &endpoint, write_timeout).await;
    reader.abort();
    let _ = reader.await;
    debug!(endpoint = %endpoint, generation = conn.generation, %reason, "hub connection ended");
    // Retire the connection before failing its requests so a caller that
    // retries immediately sees the cooldown rather than this dead socket.
    if let Some(shared) = shared.upgrade() {
        shared.retire(conn.generation);
    }
    conn.fail_pending(&reason);
}

/// Writes queued frames until the channel closes or a shutdown is
/// signalled.
///
/// The shutdown signal is honoured between AND during writes: it arrives
/// out of band rather than queued behind the frames, so a backlog of
/// pending writes — each individually within its deadline against a
/// slow-reading hub — cannot postpone a teardown by the length of the
/// queue. A write abandoned mid-frame corrupts the stream, which is
/// irrelevant on a connection that is being torn down. Each write also
/// carries its own deadline: a hub that cannot drain one small frame
/// within the call budget is wedged.
async fn write_loop(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Frame>,
    mut shutdown: watch::Receiver<Option<HubError>>,
    endpoint: &str,
    write_timeout: Duration,
) -> HubError {
    loop {
        if let Some(reason) = shutdown.borrow_and_update().clone() {
            return reason;
        }
        let frame = tokio::select! {
            biased;
            _ = shutdown.changed() => continue,
            frame = rx.recv() => match frame {
                Some(frame) => frame,
                None => {
                    return HubError::unavailable("the hub client released its connection");
                }
            },
        };
        let request = proto::Request {
            request_id: frame.request_id,
            params: Some(proto::RequestParams {
                params: Some(frame.params),
            }),
        };
        let write = tokio::time::timeout(write_timeout, write_frame(&mut write_half, &request));
        tokio::pin!(write);
        tokio::select! {
            biased;
            _ = shutdown.changed() => continue,
            result = &mut write => match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return HubError::unavailable(format!(
                        "writing to the hub at {endpoint}: {err}"
                    ));
                }
                Err(_) => {
                    return HubError::unavailable(format!(
                        "a write to the hub at {endpoint} exceeded its deadline; \
                         the connection is presumed wedged"
                    ));
                }
            },
        }
    }
}

/// Reads responses until the socket ends, then tells the writer to stop.
async fn read_loop(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    conn: Arc<Connection>,
    endpoint: String,
) {
    let reason = loop {
        match read_frame::<_, proto::Response>(&mut read_half).await {
            Ok(Some(response)) => conn.dispatch(response),
            Ok(None) => {
                break HubError::unavailable(format!(
                    "the hub at {endpoint} closed the connection"
                ));
            }
            Err(err) => {
                break HubError::unavailable(format!("reading from the hub at {endpoint}: {err}"));
            }
        }
    };
    conn.signal_shutdown(reason);
}

/// Locks a mutex this crate only ever holds for a few statements, treating
/// poisoning as "the previous holder panicked, the data is still ours".
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Names a response variant for diagnostics.
fn result_name(result: &WireResult) -> &'static str {
    match result {
        WireResult::ClientConnect(_) => "a client-connect result",
        WireResult::HubVersionInfo(_) => "a hub-version-info result",
        WireResult::CacheAsideVersionInfo(_) => "a cache-aside-version-info result",
        WireResult::CacheAsideConnect(_) => "a cache-aside-connect result",
        WireResult::CacheAsideOpenForRead(_) => "an open-for-read result",
        WireResult::CacheAsideOpenForWrite(_) => "an open-for-write result",
        WireResult::CacheAsideClose(_) => "a close result",
        WireResult::CacheAsideRemove(_) => "a remove result",
        WireResult::ErrorInfo(_) => "an error result",
        _ => "a block-cache result",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    const CACHE_ASIDE: i32 = proto::Interface::CacheAside as i32;
    const BLOCK_CACHE: i32 = proto::Interface::BlockCache as i32;

    const SUCCESS: i32 = 0;
    const ALREADY_EXISTS: i32 = 2;
    const TOO_LARGE: i32 = 3;
    const INTERNAL: i32 = 5;
    const NOT_FOUND: i32 = 6;
    const PENDING_WRITE: i32 = 7;

    /// What the scripted hub does with a cache-aside open.
    enum Reaction {
        /// Answer immediately.
        Now(WireResult),
        /// Record the request and say nothing; the test answers it by hand
        /// with [`ScriptedHub::respond`].
        Silent,
        /// Hang up mid-conversation.
        Disconnect,
    }

    /// A hub that speaks the real framing and answers from a script.
    ///
    /// It handles the handshake and acknowledges every release, so tests
    /// only script the opens they care about.
    struct ScriptedHub {
        addr: SocketAddr,
        state: Arc<HubState>,
    }

    struct HubState {
        /// `(interface, version)` pairs the version probe advertises.
        interfaces: Vec<(i32, u32)>,
        responder: Box<dyn Fn(&WireParams) -> Reaction + Send + Sync>,
        connections: AtomicUsize,
        requests: Mutex<Vec<proto::Request>>,
        out: Mutex<Option<mpsc::UnboundedSender<proto::Response>>>,
    }

    impl HubState {
        fn react(&self, request: &proto::Request) -> Reaction {
            let Some(params) = request.params.as_ref().and_then(|p| p.params.as_ref()) else {
                return Reaction::Silent;
            };
            match params {
                WireParams::ClientConnect(_) => {
                    Reaction::Now(WireResult::ClientConnect(proto::ClientConnectResult {}))
                }
                WireParams::HubVersionInfo(_) => {
                    Reaction::Now(WireResult::HubVersionInfo(proto::HubVersionInfoResult {
                        version_info: Some(proto::VersionInfo {
                            software_version: Some(proto::SemVer {
                                major: 1,
                                minor: 2,
                                patch: 3,
                            }),
                            interface_versions: self
                                .interfaces
                                .iter()
                                .map(|(interface, version)| proto::InterfaceVersion {
                                    interface: *interface,
                                    version: *version,
                                })
                                .collect(),
                        }),
                    }))
                }
                WireParams::CacheAsideClose(_) => {
                    Reaction::Now(WireResult::CacheAsideClose(proto::CacheAsideCloseResult {
                        result_code: SUCCESS,
                    }))
                }
                WireParams::CacheAsideRemove(_) => Reaction::Now(WireResult::CacheAsideRemove(
                    proto::CacheAsideRemoveResult {
                        result_code: SUCCESS,
                    },
                )),
                other => (self.responder)(other),
            }
        }
    }

    impl ScriptedHub {
        async fn start(
            interfaces: Vec<(i32, u32)>,
            responder: impl Fn(&WireParams) -> Reaction + Send + Sync + 'static,
        ) -> Self {
            let state = Arc::new(HubState {
                interfaces,
                responder: Box::new(responder),
                connections: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                out: Mutex::new(None),
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            let accepting = state.clone();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    accepting.connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(socket, accepting.clone()));
                }
            });
            Self { addr, state }
        }

        /// A hub that offers the cache-aside interface at the supported
        /// version.
        async fn cache_aside(
            responder: impl Fn(&WireParams) -> Reaction + Send + Sync + 'static,
        ) -> Self {
            Self::start(vec![(CACHE_ASIDE, 1)], responder).await
        }

        fn client(&self, timeout: Duration, cooldown: Duration) -> HubCacheClient {
            HubCacheClient::new(HubClientConfig {
                endpoint: self.addr.to_string(),
                client_name: "ovstorage-test".to_string(),
                timeout,
                cooldown,
            })
        }

        /// The default client: deadlines long enough that only a real stall
        /// trips them, and a cooldown long enough that nothing re-dials by
        /// accident.
        fn default_client(&self) -> HubCacheClient {
            self.client(Duration::from_secs(5), Duration::from_secs(60))
        }

        fn connections(&self) -> usize {
            self.state.connections.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<proto::Request> {
            lock(&self.state.requests).clone()
        }

        /// The parameter variants received so far, in arrival order.
        fn request_names(&self) -> Vec<&'static str> {
            self.requests().iter().map(param_name).collect()
        }

        /// `(request_id, key)` for every open of `kind`.
        fn opens(&self, write: bool) -> Vec<(u64, String)> {
            self.requests()
                .iter()
                .filter_map(|request| {
                    match request.params.as_ref().and_then(|p| p.params.as_ref())? {
                        WireParams::CacheAsideOpenForRead(open) if !write => {
                            Some((request.request_id, open.key.clone()))
                        }
                        WireParams::CacheAsideOpenForWrite(open) if write => {
                            Some((request.request_id, open.key.clone()))
                        }
                        _ => None,
                    }
                })
                .collect()
        }

        fn closed(&self) -> Vec<u64> {
            self.released(false)
        }

        fn removed(&self) -> Vec<u64> {
            self.released(true)
        }

        fn released(&self, remove: bool) -> Vec<u64> {
            self.requests()
                .iter()
                .filter_map(|request| {
                    match request.params.as_ref().and_then(|p| p.params.as_ref())? {
                        WireParams::CacheAsideClose(close) if !remove => Some(close.handle),
                        WireParams::CacheAsideRemove(rm) if remove => Some(rm.handle),
                        _ => None,
                    }
                })
                .collect()
        }

        /// Answers a request the script left silent.
        fn respond(&self, request_id: u64, result: WireResult) {
            let out = lock(&self.state.out)
                .as_ref()
                .expect("a live connection")
                .clone();
            out.send(proto::Response {
                request_id,
                result: Some(proto::ResponseResult {
                    result: Some(result),
                }),
            })
            .expect("the connection writer is running");
        }

        async fn wait_for(&self, what: &str, mut ready: impl FnMut(&Self) -> bool) {
            for _ in 0..5_000 {
                if ready(self) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            panic!("timed out waiting for {what}");
        }
    }

    async fn serve(socket: TcpStream, state: Arc<HubState>) {
        let _ = socket.set_nodelay(true);
        let (mut read_half, mut write_half) = socket.into_split();
        let (out, mut outbox) = mpsc::unbounded_channel::<proto::Response>();
        *lock(&state.out) = Some(out.clone());
        let writer = tokio::spawn(async move {
            while let Some(response) = outbox.recv().await {
                if write_frame(&mut write_half, &response).await.is_err() {
                    return;
                }
            }
        });
        while let Ok(Some(request)) = read_frame::<_, proto::Request>(&mut read_half).await {
            lock(&state.requests).push(request.clone());
            match state.react(&request) {
                Reaction::Now(result) => {
                    let _ = out.send(proto::Response {
                        request_id: request.request_id,
                        result: Some(proto::ResponseResult {
                            result: Some(result),
                        }),
                    });
                }
                Reaction::Silent => {}
                Reaction::Disconnect => break,
            }
        }
        writer.abort();
    }

    fn param_name(request: &proto::Request) -> &'static str {
        match request.params.as_ref().and_then(|p| p.params.as_ref()) {
            Some(WireParams::ClientConnect(_)) => "client-connect",
            Some(WireParams::HubVersionInfo(_)) => "hub-version-info",
            Some(WireParams::CacheAsideOpenForRead(_)) => "open-for-read",
            Some(WireParams::CacheAsideOpenForWrite(_)) => "open-for-write",
            Some(WireParams::CacheAsideClose(_)) => "close",
            Some(WireParams::CacheAsideRemove(_)) => "remove",
            _ => "other",
        }
    }

    fn read_result(code: i32, handle: Option<u64>, local_file: Option<&str>) -> WireResult {
        WireResult::CacheAsideOpenForRead(proto::CacheAsideOpenForReadResult {
            result_code: code,
            local_file: local_file.map(str::to_string),
            handle,
        })
    }

    fn write_result(code: i32, handle: Option<u64>, local_file: Option<&str>) -> WireResult {
        WireResult::CacheAsideOpenForWrite(proto::CacheAsideOpenForWriteResult {
            result_code: code,
            local_file: local_file.map(str::to_string),
            handle,
        })
    }

    #[tokio::test]
    async fn the_handshake_precedes_the_first_operation() {
        let hub =
            ScriptedHub::cache_aside(|_| Reaction::Now(read_result(NOT_FOUND, None, None))).await;
        let client = hub.default_client();

        let outcome = client.open_for_read("k", "s3", "bin").await.expect("opens");

        assert!(matches!(outcome, ReadOpen::NotCached));
        assert_eq!(
            hub.request_names(),
            vec!["client-connect", "hub-version-info", "open-for-read"]
        );
    }

    #[tokio::test]
    async fn the_handshake_happens_once_for_many_operations() {
        let hub =
            ScriptedHub::cache_aside(|_| Reaction::Now(read_result(NOT_FOUND, None, None))).await;
        let client = hub.default_client();

        for _ in 0..3 {
            client.open_for_read("k", "s3", "bin").await.expect("opens");
        }

        assert_eq!(hub.connections(), 1);
        assert_eq!(
            hub.request_names(),
            vec![
                "client-connect",
                "hub-version-info",
                "open-for-read",
                "open-for-read",
                "open-for-read"
            ]
        );
    }

    #[tokio::test]
    async fn out_of_order_responses_correlate_by_request_id() {
        let hub = ScriptedHub::cache_aside(|_| Reaction::Silent).await;
        let client = hub.default_client();

        let alpha = {
            let client = client.clone();
            tokio::spawn(async move { client.open_for_read("alpha", "s3", "bin").await })
        };
        let beta = {
            let client = client.clone();
            tokio::spawn(async move { client.open_for_read("beta", "s3", "bin").await })
        };
        hub.wait_for("two opens", |hub| hub.opens(false).len() == 2)
            .await;

        let opens = hub.opens(false);
        // A response nobody is waiting for is dropped, not fatal.
        hub.respond(9_999, read_result(NOT_FOUND, None, None));
        // Answer the second arrival first: correlation, not ordering,
        // decides who gets which answer.
        hub.respond(opens[1].0, read_result(NOT_FOUND, None, None));
        hub.respond(opens[0].0, read_result(SUCCESS, Some(7), Some("/cache/7")));

        let alpha = alpha.await.expect("task").expect("opens");
        let beta = beta.await.expect("task").expect("opens");
        let (first, second) = if opens[0].1 == "alpha" {
            (alpha, beta)
        } else {
            (beta, alpha)
        };
        let ReadOpen::Opened(handle) = first else {
            panic!("the first request asked for the cached entry");
        };
        assert_eq!(handle.path(), Path::new("/cache/7"));
        assert!(matches!(second, ReadOpen::NotCached));
    }

    #[tokio::test]
    async fn a_hub_speaking_an_unsupported_cache_aside_version_is_refused() {
        let hub = ScriptedHub::start(vec![(CACHE_ASIDE, 2)], |_| Reaction::Silent).await;
        let client = hub.default_client();

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the handshake rejects the revision");
        assert!(matches!(err, HubError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("version 2"), "{err}");
    }

    #[tokio::test]
    async fn a_hub_without_the_cache_aside_interface_is_a_protocol_error() {
        let hub = ScriptedHub::start(vec![(BLOCK_CACHE, 1)], |_| Reaction::Silent).await;
        let client = hub.default_client();

        let first = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the handshake rejects the hub");
        assert!(matches!(first, HubError::Protocol(_)), "{first}");
        assert!(!first.is_unavailable());

        // The failed handshake starts a cooldown, so the next call fails
        // fast without a second dial.
        let second = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the cooldown fails fast");
        assert!(second.is_unavailable(), "{second}");
        assert_eq!(hub.connections(), 1);
    }

    #[tokio::test]
    async fn open_for_read_maps_every_expected_result_code() {
        let hub = ScriptedHub::cache_aside(|params| {
            let WireParams::CacheAsideOpenForRead(open) = params else {
                return Reaction::Silent;
            };
            Reaction::Now(match open.key.as_str() {
                "hit" => read_result(SUCCESS, Some(11), Some("/cache/11")),
                "miss" => read_result(NOT_FOUND, None, None),
                "pending" => read_result(PENDING_WRITE, None, None),
                _ => read_result(INTERNAL, None, None),
            })
        })
        .await;
        let client = hub.default_client();

        let hit = client.open_for_read("hit", "s3", "bin").await.expect("hit");
        let ReadOpen::Opened(handle) = hit else {
            panic!("success opens a handle");
        };
        assert_eq!(handle.path(), Path::new("/cache/11"));
        handle.close().await.expect("close succeeds");

        assert!(matches!(
            client
                .open_for_read("miss", "s3", "bin")
                .await
                .expect("miss"),
            ReadOpen::NotCached
        ));
        assert!(matches!(
            client
                .open_for_read("pending", "s3", "bin")
                .await
                .expect("pending"),
            ReadOpen::PendingWrite
        ));
        let unexpected = client
            .open_for_read("boom", "s3", "bin")
            .await
            .expect_err("an internal error is not an outcome");
        assert!(
            matches!(unexpected, HubError::Hub(HubResultCode::Internal)),
            "{unexpected}"
        );
        assert_eq!(hub.closed(), vec![11]);
    }

    #[tokio::test]
    async fn open_for_write_maps_every_expected_result_code() {
        let hub = ScriptedHub::cache_aside(|params| {
            let WireParams::CacheAsideOpenForWrite(open) = params else {
                return Reaction::Silent;
            };
            Reaction::Now(match open.key.as_str() {
                "fresh" => write_result(SUCCESS, Some(21), Some("/cache/21")),
                "present" => write_result(ALREADY_EXISTS, None, None),
                _ => write_result(TOO_LARGE, None, None),
            })
        })
        .await;
        let client = hub.default_client();

        let fresh = client
            .open_for_write("fresh", "s3", "bin", 64)
            .await
            .expect("fresh");
        let WriteOpen::Opened(handle) = fresh else {
            panic!("success opens a handle");
        };
        assert_eq!(handle.path(), Path::new("/cache/21"));
        handle.commit().await.expect("commit succeeds");

        assert!(matches!(
            client
                .open_for_write("present", "s3", "bin", 64)
                .await
                .expect("present"),
            WriteOpen::AlreadyExists
        ));
        assert!(matches!(
            client
                .open_for_write("huge", "s3", "bin", u64::MAX)
                .await
                .expect("huge"),
            WriteOpen::TooLarge
        ));
        // Committing is a Close; the entry is published, never removed.
        assert_eq!(hub.closed(), vec![21]);
        assert!(hub.removed().is_empty());
    }

    #[tokio::test]
    async fn an_error_result_is_a_protocol_error() {
        let hub = ScriptedHub::cache_aside(|_| {
            Reaction::Now(WireResult::ErrorInfo(proto::ErrorInfoResult {
                message: "the cache is wedged".to_string(),
            }))
        })
        .await;
        let client = hub.default_client();

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("an error result fails the call");

        assert!(matches!(err, HubError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("the cache is wedged"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hub_hoarding_unanswered_requests_trips_the_backstop() {
        let hub = ScriptedHub::cache_aside(|_| Reaction::Silent).await;
        // Deadlines long enough that nothing expires while the map fills:
        // the backstop, not the per-call timeout, must be what trips.
        let client = hub.client(Duration::from_secs(600), Duration::from_secs(600));

        let mut hoarded = tokio::task::JoinSet::new();
        for _ in 0..MAX_PENDING_REQUESTS {
            let client = client.clone();
            hoarded.spawn(async move { client.open_for_read("k", "s3", "bin").await });
        }
        while client.pending_ops() < MAX_PENDING_REQUESTS {
            tokio::task::yield_now().await;
        }

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the backstop trips");
        assert!(err.to_string().contains("unanswered"), "{err}");

        // Presuming the connection wedged reclaims everything: the teardown
        // fails every hoarded call and the client settles.
        while let Some(result) = hoarded.join_next().await {
            let outcome = result.expect("the task completes");
            assert!(outcome.expect_err("torn down").is_unavailable());
        }
        client.quiesce().await;
        assert_eq!(client.pending_ops(), 0);
    }

    #[tokio::test]
    async fn a_deadline_expiry_tears_down_the_wedged_connection() {
        let hub = ScriptedHub::cache_aside(|_| Reaction::Silent).await;
        let client = hub.client(Duration::from_millis(60), Duration::from_secs(60));

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the deadline expires");
        assert!(err.is_unavailable(), "{err}");

        // The teardown fails the correlation map: the client settles rather
        // than holding the abandoned entry (and its in-flight guard)
        // forever.
        client.quiesce().await;
        assert_eq!(client.pending_ops(), 0);

        // The slot is in its cooldown: the next call fails fast rather than
        // paying another full deadline against the wedged hub, and no
        // second connection is dialled.
        let second = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the cooldown fails fast");
        assert!(second.is_unavailable(), "{second}");
        assert!(second.to_string().contains("cooldown"), "{second}");
        assert_eq!(hub.connections(), 1);
    }

    #[tokio::test]
    async fn the_failure_cooldown_is_visible_without_dialling() {
        let client = HubCacheClient::new(HubClientConfig {
            // A port in the reserved range nothing listens on: the dial is
            // refused immediately.
            endpoint: "127.0.0.1:1".to_string(),
            client_name: "ovstorage-test".to_string(),
            timeout: Duration::from_millis(500),
            cooldown: Duration::from_secs(60),
        });
        assert!(
            !client.unavailable(),
            "a fresh client has not failed at anything yet"
        );

        client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("nothing listens on the endpoint");
        assert!(
            client.unavailable(),
            "the failed dial's cooldown is observable without I/O"
        );
    }

    #[tokio::test]
    async fn an_abandoned_call_still_enforces_its_deadline_on_a_silent_hub() {
        let hub = ScriptedHub::cache_aside(|_| Reaction::Silent).await;
        let client = hub.client(Duration::from_millis(60), Duration::from_secs(60));

        // The caller stops waiting mid-flight: the open has reached the hub,
        // then its future is dropped. The correlation entry stays behind for
        // its late-release duty.
        let call = {
            let client = client.clone();
            tokio::spawn(async move { client.open_for_read("k", "s3", "bin").await })
        };
        hub.wait_for("the open reaches the hub", |hub| {
            !hub.opens(false).is_empty()
        })
        .await;
        call.abort();
        let _ = call.await;
        assert_eq!(client.pending_ops(), 1);

        // The dropped future did not take the deadline with it: one entry
        // never reaches the backstop, so without the watchdog this silent
        // hub would hold the entry — and any reservation behind it — until
        // something else ended the connection. The watchdog presumes the
        // connection wedged and the teardown reclaims everything.
        tokio::time::timeout(Duration::from_secs(10), client.quiesce())
            .await
            .expect("the abandoned call's deadline tears the connection down");
        assert_eq!(client.pending_ops(), 0);
        let next = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the cooldown fails fast");
        assert!(next.is_unavailable(), "{next}");
        assert_eq!(hub.connections(), 1);
    }

    #[tokio::test]
    async fn a_delivered_response_dropped_unread_releases_its_lease() {
        let hub = ScriptedHub::cache_aside(|_| {
            Reaction::Now(read_result(SUCCESS, Some(51), Some("/cache/51")))
        })
        .await;
        let client = hub.default_client();
        let ReadOpen::Opened(handle) = client.open_for_read("k", "s3", "bin").await.expect("opens")
        else {
            panic!("success opens a handle");
        };
        let conn = lock(&client.shared.slot)
            .conn
            .clone()
            .expect("the open left a live connection");

        // A lease-carrying response that reached a receiver nothing will
        // poll again — a deadline or a dropped caller future — is dropped
        // unread; the guard, not the caller, gives the lease back.
        drop(Delivered {
            result: Some(Ok(read_result(SUCCESS, Some(77), Some("/cache/77")))),
            late: LateRelease::Close,
            conn: Arc::downgrade(&conn),
        });
        hub.wait_for("the unread read lease is closed", |hub| {
            hub.closed() == vec![77]
        })
        .await;

        drop(Delivered {
            result: Some(Ok(write_result(SUCCESS, Some(78), Some("/cache/78")))),
            late: LateRelease::Remove,
            conn: Arc::downgrade(&conn),
        });
        hub.wait_for("the unread write lease is removed", |hub| {
            hub.removed() == vec![78]
        })
        .await;

        drop(handle);
        client.quiesce().await;
        assert_eq!(hub.closed(), vec![77, 51]);
    }

    #[tokio::test]
    async fn a_dropped_read_handle_closes_its_lease() {
        let hub = ScriptedHub::cache_aside(|_| {
            Reaction::Now(read_result(SUCCESS, Some(31), Some("/cache/31")))
        })
        .await;
        let client = hub.default_client();

        let ReadOpen::Opened(handle) = client.open_for_read("k", "s3", "bin").await.expect("opens")
        else {
            panic!("success opens a handle");
        };
        drop(handle);
        client.quiesce().await;

        assert_eq!(hub.closed(), vec![31]);
        assert!(hub.removed().is_empty());
        assert_eq!(client.pending_ops(), 0);
    }

    #[tokio::test]
    async fn a_dropped_write_handle_removes_its_lease() {
        let hub = ScriptedHub::cache_aside(|_| {
            Reaction::Now(write_result(SUCCESS, Some(32), Some("/cache/32")))
        })
        .await;
        let client = hub.default_client();

        let WriteOpen::Opened(handle) = client
            .open_for_write("k", "s3", "bin", 64)
            .await
            .expect("opens")
        else {
            panic!("success opens a handle");
        };
        drop(handle);
        client.quiesce().await;

        // An uncommitted write is never implicitly committed.
        assert_eq!(hub.removed(), vec![32]);
        assert!(hub.closed().is_empty());
    }

    #[tokio::test]
    async fn an_aborted_write_handle_removes_its_lease() {
        let hub = ScriptedHub::cache_aside(|_| {
            Reaction::Now(write_result(SUCCESS, Some(33), Some("/cache/33")))
        })
        .await;
        let client = hub.default_client();

        let WriteOpen::Opened(handle) = client
            .open_for_write("k", "s3", "bin", 64)
            .await
            .expect("opens")
        else {
            panic!("success opens a handle");
        };
        handle.abort().await;

        assert_eq!(hub.removed(), vec![33]);
        assert!(hub.closed().is_empty());
    }

    #[tokio::test]
    async fn a_handle_from_a_replaced_connection_releases_nothing() {
        let hub = ScriptedHub::cache_aside(|params| {
            let WireParams::CacheAsideOpenForRead(open) = params else {
                return Reaction::Silent;
            };
            if open.key == "hangup" {
                return Reaction::Disconnect;
            }
            Reaction::Now(read_result(SUCCESS, Some(5), Some("/cache/5")))
        })
        .await;
        // A zero cooldown lets the next call re-dial immediately.
        let client = hub.client(Duration::from_secs(5), Duration::ZERO);

        let ReadOpen::Opened(stale) = client
            .open_for_read("first", "s3", "bin")
            .await
            .expect("opens")
        else {
            panic!("success opens a handle");
        };
        let err = client
            .open_for_read("hangup", "s3", "bin")
            .await
            .expect_err("the hub hung up");
        assert!(err.is_unavailable(), "{err}");

        let ReadOpen::Opened(live) = client
            .open_for_read("second", "s3", "bin")
            .await
            .expect("re-dials")
        else {
            panic!("success opens a handle");
        };
        assert_eq!(hub.connections(), 2);

        // The stale handle's number belongs to the connection that is gone;
        // sending it now would release someone else's entry.
        drop(stale);
        drop(live);
        client.quiesce().await;

        assert_eq!(hub.closed(), vec![5]);
    }

    #[tokio::test]
    async fn a_connection_failure_fails_fast_for_the_cooldown() {
        let hub = ScriptedHub::cache_aside(|_| Reaction::Disconnect).await;
        let client = hub.client(Duration::from_secs(5), Duration::from_secs(60));

        let first = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the hub hung up");
        assert!(first.is_unavailable(), "{first}");

        let second = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("the cooldown fails fast");
        assert!(second.is_unavailable(), "{second}");
        assert!(second.to_string().contains("cooldown"), "{second}");
        assert_eq!(hub.connections(), 1);
    }

    #[tokio::test]
    async fn a_dead_endpoint_is_unavailable_rather_than_a_hang() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let client = HubCacheClient::new(HubClientConfig {
            endpoint: addr.to_string(),
            timeout: Duration::from_secs(5),
            cooldown: Duration::from_secs(60),
            ..HubClientConfig::default()
        });

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("nothing is listening");

        assert!(err.is_unavailable(), "{err}");
    }

    #[tokio::test]
    async fn a_success_without_a_local_file_is_a_protocol_error() {
        let hub =
            ScriptedHub::cache_aside(|_| Reaction::Now(read_result(SUCCESS, Some(51), None))).await;
        let client = hub.default_client();

        let err = client
            .open_for_read("k", "s3", "bin")
            .await
            .expect_err("success without a path is impossible");

        assert!(matches!(err, HubError::Protocol(_)), "{err}");
        // The unusable lease is released rather than left pinning the entry.
        client.quiesce().await;
        assert_eq!(hub.closed(), vec![51]);
    }

    #[test]
    fn the_default_configuration_targets_the_hub_default_port() {
        let config = HubClientConfig::default();
        assert_eq!(config.endpoint, crate::DEFAULT_HUB_ENDPOINT);
        assert_eq!(config.client_name, "ovstorage");
    }

    #[tokio::test]
    async fn a_client_is_cheap_to_clone_and_shares_one_connection() {
        let hub =
            ScriptedHub::cache_aside(|_| Reaction::Now(read_result(NOT_FOUND, None, None))).await;
        let client = hub.default_client();
        let clone = client.clone();

        client.open_for_read("a", "s3", "bin").await.expect("opens");
        clone.open_for_read("b", "s3", "bin").await.expect("opens");

        assert_eq!(hub.connections(), 1);
    }
}
