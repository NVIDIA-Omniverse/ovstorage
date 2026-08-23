// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::address;
use crate::{
    BackendChangeEvent, BackendChangeStream, ChangeKind, Error, ErrorCode, Result, Url,
    WatchDirectoryCursor, WatchDirectoryOptions,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryId(u64);

#[derive(Debug, Clone, Copy)]
pub enum AckToken {
    Provider(DeliveryId),
    Noop,
}

pub struct SubscriptionEvent {
    pub event: BackendChangeEvent,
    pub ack_token: AckToken,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct PendingEntry<H> {
    handle: H,
    remaining: usize,
    deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingDecrement<H> {
    Pending,
    Ready { handle: H, deadline: Instant },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingDeliveryId {
    pub id: DeliveryId,
}

pub struct Pending<H> {
    map: Mutex<HashMap<DeliveryId, PendingEntry<H>>>,
    next_id: AtomicU64,
}

impl<H> Pending<H> {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    pub fn insert(&self, handle: H, remaining: usize, deadline: Instant) -> DeliveryId {
        assert!(
            remaining > 0,
            "pending delivery must have at least one event"
        );
        let id = DeliveryId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.map.lock().unwrap().insert(
            id,
            PendingEntry {
                handle,
                remaining,
                deadline,
            },
        );
        id
    }

    pub fn decrement(
        &self,
        id: DeliveryId,
    ) -> std::result::Result<PendingDecrement<H>, MissingDeliveryId> {
        let mut m = self.map.lock().unwrap();
        let entry = m.get_mut(&id).ok_or(MissingDeliveryId { id })?;
        entry.remaining -= 1;
        if entry.remaining == 0 {
            let e = m.remove(&id).unwrap();
            Ok(PendingDecrement::Ready {
                handle: e.handle,
                deadline: e.deadline,
            })
        } else {
            Ok(PendingDecrement::Pending)
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<H> Default for Pending<H> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Watch fan-out coalescer.
//
// Turns N overlapping `watch_directory` calls that share a `CoalesceKey` into
// **one** upstream consumer, fanning every event out to all subscribers. This
// is the single-downstream-consumer property a cache self-watch needs: on
// competing-consumer transports (SQS / Pub/Sub) each event is delivered to
// exactly one poller, so two independent watches on the same connection would
// *split* the event flow and silently under-invalidate. Coalescing to one
// upstream restores at-least-once delivery to every subscriber.
//
// The mechanics — a bounded per-subscriber queue, a single dispatcher thread
// per upstream, slow-consumer `Lapsed` injection on overflow, and
// last-unsubscribe teardown — mirror the reviewed host fan-out primitive.
// `BackendChangeStream` is a blocking `Iterator`, so the dispatcher runs on a
// dedicated `std::thread` (`ovs-watch-fan`) rather than the async runtime.
//
// Design (rev 5):
//   * The coalescing key is an adopter-supplied opaque `String` naming the
//     shared notification resource (principal-blind — the adopter decides what
//     shares a feed). Poll cadence and recursion are NOT in the key.
//   * Poll cadence is negotiated over **adopter-normalized `effective_cadence`s**
//     (each adopter applies its own sentinel/floor before calling `subscribe`);
//     the coalescer mins the opening cohort's values and fixes it for the
//     upstream's lifetime.
//   * The upstream is opened recursive+metadata-inclusive at the key's root, and
//     each subscriber is **filtered at the dispatcher, before its bounded
//     queue** — so heavy traffic on one prefix cannot overflow a quiet
//     subscriber watching a disjoint prefix.
//   * The upstream is an `AckingStream` of `(event, AckHandle)`; the dispatcher
//     invokes the nonblocking `AckHandle` after fanning the event out. A
//     synchronous dispatch failure (the handle returns `Err`) is a terminal
//     upstream error — the ack is never silently dropped.
//   * Concurrent first-subscribers of one key single-flight one physical open
//     without holding the registry lock across the network `.await`.
// ---------------------------------------------------------------------------

/// Per-subscriber queue depth; on overflow the coalescer injects a single
/// `BackendChangeEvent::Lapsed` so the subscriber re-lists and resumes from
/// "now".
// Internal tuning constant private to the coalescer, not a C ABI symbol.
/// cbindgen:ignore
const QUEUE_DEPTH: usize = 256;

/// Poll cadence for a cancel-aware `WatcherReceiver::next()`.
// Internal tuning constant private to the coalescer, not a C ABI symbol.
/// cbindgen:ignore
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Adopter-supplied coalescing key: an opaque `String` identifying the shared
/// notification resource. Two `subscribe` calls share one upstream iff their
/// keys are equal — the adopter decides what coalesces (it is
/// **principal-blind**: the coalescer never reads the principal). Poll cadence
/// and recursion are deliberately **not** part of
/// the key: cadence is negotiated at open (min of the opening cohort's
/// adopter-normalized `effective_cadence`s) and recursion/metadata are
/// per-subscriber filters applied at the dispatcher.
pub type CoalesceKey = String;

/// A nonblocking ack for one delivered event. Invoked once by the dispatcher
/// after the event has been fanned out to all matching subscribers. It **must
/// not block** (the dispatcher is a blocking `std::thread` that cannot `.await`)
/// — the adopter dispatches the real SQS-delete / Pub-Sub-acknowledge onto its
/// own async ack pump.
///
/// It returns a [`Result`]: a **synchronous dispatch** failure (a bounded ack
/// channel `try_send` returning `Full`/`Closed`) is reported as `Err`, and the
/// dispatcher treats it as a **terminal upstream error immediately** — an ack is
/// never silently dropped. An **async provider** ack failure still surfaces
/// later as a terminal `Err` on the [`AckingStream`] (the adopter wires its
/// pump's fatal channel back into the upstream). Adopters without per-message
/// ack (broker gRPC, Azure offset) supply a no-op handle returning `Ok(())`.
pub type AckHandle = Box<dyn FnOnce() -> Result<()> + Send>;

/// The single upstream feed for a key: a blocking `Iterator` yielding
/// `(event, ack)` pairs. A terminal `Err` tears the fan-out down and the next
/// subscribe reopens fresh.
pub type AckingStream = Box<dyn Iterator<Item = Result<(BackendChangeEvent, AckHandle)>> + Send>;

/// Opens the single upstream [`AckingStream`] for a key. Called once per key on
/// the first subscriber(s). The coalescer passes a [`CancellationToken`] the
/// opener MUST wire into the underlying `watch_directory` so last-unsubscribe
/// (and `cancel_all`) tears the transport down — the token is a child of the
/// coalescer shutdown, so it also fires when the whole coalescer is cancelled.
/// The `Duration` is the negotiated poll cadence — the min of the opening
/// cohort's adopter-normalized `effective_cadence`s (each adopter applies its
/// own sentinel/floor before calling `subscribe`; the generic coalescer does not
/// normalize raw durations) — fixed for the upstream's lifetime, so a later
/// joiner never renegotiates a live upstream.
pub type UpstreamFactory = Arc<
    dyn Fn(CancellationToken, Duration) -> BoxFuture<'static, Result<AckingStream>> + Send + Sync,
>;

/// Does `event` fall within a subscriber's `(prefix, recursive)` view? Applied
/// by the dispatcher **before** the per-subscriber queue, so a connection-wide
/// feed does not overflow a quiet subscriber with events it would discard.
///
/// `Lapsed` (and terminal errors) bypass this — a gap in the superset is a gap
/// for every narrower view, so those broadcast to all. Recursive accepts any
/// event **under** the prefix at any depth (and rejects events outside it);
/// non-recursive keeps the trailing-slash direct-child boundary;
/// `MetadataChanged` is dropped when `!include_metadata_changes`.
fn watcher_accepts(
    prefix: &Url,
    recursive: bool,
    include_metadata_changes: bool,
    event: &BackendChangeEvent,
) -> bool {
    let BackendChangeEvent::Object { address, kind, .. } = event else {
        return true;
    };
    if *kind == ChangeKind::MetadataChanged && !include_metadata_changes {
        return false;
    }
    if !address::is_ancestor_or_self(prefix, address) {
        // Outside the subscriber's prefix.
        return false;
    }
    // Compare canonical percent-decoded path keys (query and fragment excluded)
    // so an encoded separator (`%2F`) counts as a nested boundary and a slash in
    // the query does not masquerade as one.
    //
    // Bytes, because the backend resolves bytes. A subscriber's prefix is the
    // scope it is authorized for, so a decode that equated two names the
    // backend keeps apart would deliver one object's events to a watcher of
    // the other.
    let prefix_key = address::key(prefix);
    let address_key = address::key(address);
    // Both keys are decoded PATHS, so the query is already out of the picture
    // and the only difference left is the prefix's trailing slash. Dropping it
    // makes the two comparable, and the watched node itself then has an empty
    // relative key rather than falling through to a whole-key fallback that
    // read it as a direct child of its own parent.
    let prefix_key = prefix_key.strip_suffix(b"/").unwrap_or(&prefix_key);
    // The watched node is not beneath itself, and this is checked for BOTH
    // views. Compare the two in NODE form — one trailing `/` dropped from each —
    // because all four spellings of the pair name the watched node: an event
    // about `root` or `root/` is about the directory being watched under either
    // spelling of the prefix, not about something inside it.
    //
    // Deciding this before the `recursive` branch is what keeps `recursive` a
    // question about *depth* rather than a second boundary rule that can
    // disagree with this one. It used to sit below, so a recursive watcher
    // returned on `is_ancestor_or_self` alone — and that predicate compares node
    // paths, so it treats `root` and `root/` as one node and admitted the
    // distinct flat-store object.
    let address_node = address_key.strip_suffix(b"/").unwrap_or(&address_key);
    if address_node == prefix_key {
        return false;
    }
    if recursive {
        // Anything under the prefix, at any depth.
        return true;
    }
    // Non-recursive: only direct children of the prefix directory.
    let Some(relative) = address_key.strip_prefix(prefix_key).and_then(|rest| {
        if prefix_key.is_empty() {
            Some(rest)
        } else {
            rest.strip_prefix(b"/")
        }
    }) else {
        // Containment said yes and the keys disagree. Deliver nothing rather
        // than guess which node the event is about.
        return false;
    };
    let relative = relative.strip_suffix(b"/").unwrap_or(relative);
    !relative.is_empty() && !relative.contains(&b'/')
}

/// One key's in-flight physical open. Concurrent first-subscribers of the same
/// key single-flight this — a detached driver task runs the `UpstreamFactory`
/// while the subscribers await [`Opening::done`], so the registry lock is never
/// held across the network `.await`.
struct Opening {
    /// The physical open's cancel token (a child of the coalescer shutdown).
    /// Fired when **every** waiter has cancelled — so one waiter cancelling
    /// before the open completes does not kill the others' upstream.
    cancel: CancellationToken,
    /// Fired by the driver once `inner.outcome` is set; level-triggered, so a
    /// waiter that starts awaiting after completion still observes it.
    done: CancellationToken,
    inner: Mutex<OpeningInner>,
}

struct OpeningInner {
    /// Live waiters still awaiting this open. Each waiter holds a [`WaiterGuard`]
    /// whose `Drop` decrements this; when it reaches 0 before the open resolves,
    /// the guard fires [`Opening::cancel`] and removes the entry.
    waiters: usize,
    /// Min of the opening cohort's adopter-normalized `effective_cadence`s. Lowered
    /// by joiners only while the cohort is still `Collecting` (`frozen == false`);
    /// once the driver freezes it at the `Collecting -> Opening` transition, later
    /// joiners cannot affect it (their cadence is advisory — the upstream exists).
    min_cadence: Duration,
    /// Cohort phase gate: `false` = `Collecting` (joiners may lower `min_cadence`),
    /// `true` = `Opening` (cadence frozen; the factory has been / is being invoked).
    /// Flipped once by the driver immediately before it reads `min_cadence`.
    frozen: bool,
    outcome: Option<OpenOutcome>,
}

enum OpenOutcome {
    Ready(Arc<WatchDirectoryFanout>),
    Failed(Error),
}

/// A key's registry state: either an in-flight open or a live fan-out.
enum KeyState {
    Opening(Arc<Opening>),
    /// Held as `Weak` so a fan-out is freed once its last subscriber drops
    /// (dispatcher exits, `Arc` released); stale entries are lazily replaced.
    Live(Weak<WatchDirectoryFanout>),
}

/// Keyed coalescer merging overlapping `watch_directory` calls into one upstream
/// consumer per [`CoalesceKey`], fanning events out to all subscribers. One
/// coalescer per owner (e.g. per backend connection); dropping it (or
/// `cancel_all`) cancels every live and future upstream. The coalescer is
/// **principal-blind** and cap-free: it never reads the principal and enforces
/// no per-principal or total subscriber limit (limits live at a central
/// chokepoint, not in each backend's own coalescer instance).
///
/// # Why coalescing lives in the backend, not the host Layer
///
/// The contended resource is the per-connection queue/subscription (an SQS
/// receiver, a Pub/Sub subscription, an Azure change feed), and it spans **all
/// prefixes** of the connection: `root/foo/` and `root/bar/` drain the same
/// queue. On a competing-consumer transport each notification is delivered to
/// exactly one reader and acked, so two watches sharing that queue cannibalize
/// each other's events. Correct coalescing therefore has to happen at the
/// granularity of the contended resource — the connection.
///
/// A host coalescing Layer could not see that granularity: sitting above the
/// router and keying by prefix, watches on different prefixes of one bucket
/// would stay distinct keys and still open N queue readers. Only the backend
/// knows which prefixes share a queue. This is the load-bearing reason
/// coalescing is a backend responsibility rather than a host Layer.
///
/// Consequences reflected in this type's contract:
///
/// - **The adopter supplies the key as an opaque `String`.** Single-queue
///   backends (S3/GCS/Azure) use a connection-constant [`CoalesceKey`] (one
///   upstream total, all prefixes filtered per subscriber); the broker/services
///   client keys by connection id + prefix (one gRPC `Watch` per prefix).
/// - **The coalescer is principal-blind.** It never reads the principal; the
///   upstream stays single regardless of which principal subscribes.
/// - **Competing-consumer backends MUST self-coalesce.** This is enforced by a
///   conformance scenario (concurrent overlapping watches on one connection each
///   receive every event), which replaces the removed host Layer as the safety
///   net.
pub struct WatchCoalescer {
    /// Live fan-outs and in-flight opens by key. A **`std::sync::Mutex`**: the
    /// single-flight rework never holds it across an `.await` (opens run on a
    /// detached driver), so a synchronous [`WaiterGuard::drop`] can decrement a
    /// waiter and tear an opening down atomically under this lock. Lock order is
    /// **registry -> `Opening::inner`** everywhere.
    registry: Mutex<HashMap<CoalesceKey, KeyState>>,
    /// Coalescer-wide shutdown; every upstream cancel is a child of this, so
    /// `cancel_all()` cascades to every live AND future upstream.
    shutdown: CancellationToken,
}

impl WatchCoalescer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            shutdown: CancellationToken::new(),
        })
    }

    /// Subscribe to the coalesced upstream for `key`, opening it via `upstream`
    /// on the first subscriber(s). Returns a [`BackendChangeStream`] (blocking
    /// `Iterator`); dropping the last stream for a key cancels its upstream.
    ///
    /// Concurrent first-subscribers of one key single-flight **one** physical
    /// open and all await it; the registry lock is **not** held across the
    /// opener's `.await`, so one hung key never wedges opens for other keys.
    ///
    /// `effective_cadence` is the adopter's already-normalized poll cadence for
    /// this request (sentinel/floor applied per that backend's semantics — the
    /// generic coalescer does NOT derive cadence from `opts.poll_interval`). The
    /// coalescer mins the opening cohort's `effective_cadence`s and passes that
    /// min to the [`UpstreamFactory`], fixed for the upstream's lifetime.
    ///
    /// `cancel` ends *this* subscriber's stream (poll-bounded) without tearing
    /// down the shared upstream — a caller cancelling its own watch, or a drain
    /// stopping on teardown. `None` blocks in `recv()` until the upstream ends.
    ///
    /// The subscriber's `(prefix, opts.recursive, opts.include_metadata_changes)`
    /// filter is applied at the dispatcher, before this subscriber's queue. When
    /// `opts.since.is_some()`, the returned stream **prepends** one `Lapsed`
    /// before live events, signalling the caller to re-list from its saved
    /// cursor; the watch still coalesces onto the shared upstream (no dedicated
    /// replay stream).
    pub async fn subscribe(
        self: &Arc<Self>,
        key: CoalesceKey,
        prefix: Url,
        opts: WatchDirectoryOptions,
        effective_cadence: Duration,
        cancel: Option<CancellationToken>,
        upstream: UpstreamFactory,
    ) -> Result<BackendChangeStream> {
        let receiver = self
            .subscribe_receiver(key, &prefix, &opts, effective_cadence, cancel, upstream)
            .await?;
        Ok(Box::new(FilteredWatcherReceiver {
            inner: receiver,
            initial_lapsed: opts.since.is_some(),
        }) as BackendChangeStream)
    }

    /// Attach to (or single-flight-open) the fan-out for `key`, returning the raw
    /// receiver. Retries on the corpse race (attaching to a fan-out torn down
    /// out from under us) by reopening.
    async fn subscribe_receiver(
        self: &Arc<Self>,
        key: CoalesceKey,
        prefix: &Url,
        opts: &WatchDirectoryOptions,
        effective_cadence: Duration,
        subscriber_cancel: Option<CancellationToken>,
        upstream: UpstreamFactory,
    ) -> Result<WatcherReceiver> {
        loop {
            // Phase 1 (registry lock, no `.await` across the open): find a live
            // fan-out, join an in-flight open, or start one. `Wait` carries a
            // [`WaiterGuard`] that already owns this call's `waiters` count.
            enum Step {
                Live(Arc<WatchDirectoryFanout>),
                Wait(Arc<Opening>, WaiterGuard),
            }
            let step = {
                let mut registry = lock_registry(&self.registry);
                match registry.get(&key) {
                    Some(KeyState::Live(weak)) => match weak.upgrade() {
                        Some(fanout) => Step::Live(fanout),
                        None => {
                            let opening = self.start_opening(
                                &mut registry,
                                &key,
                                effective_cadence,
                                &upstream,
                            );
                            let guard = self.waiter_guard(&key, &opening);
                            Step::Wait(opening, guard)
                        }
                    },
                    // Join an in-flight open only if it is NOT already doomed
                    // (cancelled by shutdown cascade or the last waiter leaving).
                    // Joining a cancelled opening would surface a spurious
                    // `Cancelled`, so start fresh instead.
                    Some(KeyState::Opening(opening)) if !opening.cancel.is_cancelled() => {
                        let opening = opening.clone();
                        {
                            let mut inner = opening.inner.lock().map_err(|_| {
                                Error::new(
                                    ErrorCode::Internal,
                                    "watch coalescer open lock is poisoned",
                                )
                            })?;
                            inner.waiters += 1;
                            // A later joiner (cohort already frozen) cannot lower
                            // the cadence — the upstream exists or is being opened.
                            if !inner.frozen {
                                inner.min_cadence = inner.min_cadence.min(effective_cadence);
                            }
                        }
                        let guard = self.waiter_guard(&key, &opening);
                        Step::Wait(opening, guard)
                    }
                    _ => {
                        // No entry, or a doomed `Opening` we must not join: start
                        // fresh (replacing any doomed entry) under the lock.
                        let opening =
                            self.start_opening(&mut registry, &key, effective_cadence, &upstream);
                        let guard = self.waiter_guard(&key, &opening);
                        Step::Wait(opening, guard)
                    }
                }
            };

            let fanout = match step {
                Step::Live(fanout) => fanout,
                Step::Wait(opening, guard) => {
                    // The guard is held across the `.await`; if this future is
                    // dropped/aborted here (token never fired), its `Drop` still
                    // decrements the waiter and tears the open down if last.
                    let result = self.await_open(&opening, &subscriber_cancel).await;
                    drop(guard);
                    match result {
                        Ok(fanout) => fanout,
                        Err(err) => return Err(err),
                    }
                }
            };

            match fanout.subscribe(
                prefix.clone(),
                opts.recursive,
                opts.include_metadata_changes,
                subscriber_cancel.clone(),
            ) {
                Ok(receiver) => return Ok(receiver),
                // Corpse race: the fan-out was torn down between our lookup and
                // registering. Drop the dead entry (if still ours) and reopen.
                Err(err) if err.code() == ErrorCode::Cancelled => {
                    let mut registry = lock_registry(&self.registry);
                    if let Some(KeyState::Live(weak)) = registry.get(&key)
                        && weak.upgrade().is_none_or(|cur| Arc::ptr_eq(&cur, &fanout))
                    {
                        registry.remove(&key);
                    }
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Build a [`WaiterGuard`] owning the one `waiters` count this call added to
    /// `opening` (either as the opener with `waiters: 1`, or a joiner's `+= 1`).
    fn waiter_guard(self: &Arc<Self>, key: &CoalesceKey, opening: &Arc<Opening>) -> WaiterGuard {
        WaiterGuard {
            coalescer: Arc::downgrade(self),
            key: key.clone(),
            opening: opening.clone(),
        }
    }

    /// Insert a fresh `Opening` for `key` and spawn the detached driver that runs
    /// the physical open. The registry lock is held by the caller only for the
    /// insert — the driver runs the `.await` on its own.
    fn start_opening(
        self: &Arc<Self>,
        registry: &mut HashMap<CoalesceKey, KeyState>,
        key: &CoalesceKey,
        effective_cadence: Duration,
        upstream: &UpstreamFactory,
    ) -> Arc<Opening> {
        let opening = Arc::new(Opening {
            cancel: self.shutdown.child_token(),
            done: CancellationToken::new(),
            inner: Mutex::new(OpeningInner {
                waiters: 1,
                min_cadence: effective_cadence,
                frozen: false,
                outcome: None,
            }),
        });
        registry.insert(key.clone(), KeyState::Opening(opening.clone()));
        let this = Arc::downgrade(self);
        let key = key.clone();
        let opening_for_task = opening.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            drive_open(this, key, opening_for_task, upstream).await;
        });
        opening
    }

    /// Await the shared open for `opening`, returning the live fan-out or the
    /// open's error. If this subscriber's own cancel fires first, return
    /// `Cancelled`; the caller's [`WaiterGuard`] decrements the waiter (and tears
    /// the open down if it was the last) on drop.
    async fn await_open(
        self: &Arc<Self>,
        opening: &Arc<Opening>,
        subscriber_cancel: &Option<CancellationToken>,
    ) -> Result<Arc<WatchDirectoryFanout>> {
        // A subscriber with no cancel token still leaves when the whole
        // coalescer shuts down, so a parked open never wedges it forever.
        let leave = subscriber_cancel
            .clone()
            .unwrap_or_else(|| self.shutdown.clone());
        loop {
            {
                let inner = opening.inner.lock().map_err(|_| {
                    Error::new(ErrorCode::Internal, "watch coalescer open lock is poisoned")
                })?;
                match &inner.outcome {
                    Some(OpenOutcome::Ready(fanout)) => return Ok(fanout.clone()),
                    Some(OpenOutcome::Failed(err)) => return Err(err.clone()),
                    None => {}
                }
            }
            tokio::select! {
                biased;
                _ = leave.cancelled() => {
                    return Err(Error::new(
                        ErrorCode::Cancelled,
                        "watch_directory cancelled during upstream open",
                    ));
                }
                _ = opening.done.cancelled() => {
                    // Outcome is set; loop to read it.
                }
            }
        }
    }

    /// Cancel every live AND future upstream (owner teardown / Stack rebuild).
    pub fn cancel_all(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for WatchCoalescer {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

/// Lock the registry, recovering from poisoning: a panic under this lock would
/// leave the map intact (no `.await`, no partial mutation that matters), so the
/// coalescer keeps operating rather than propagating the poison.
fn lock_registry(
    registry: &Mutex<HashMap<CoalesceKey, KeyState>>,
) -> std::sync::MutexGuard<'_, HashMap<CoalesceKey, KeyState>> {
    registry.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII handle for one waiter on an in-flight [`Opening`]. Created the instant a
/// `subscribe` call registers as the opener or joins an existing open (owning the
/// `waiters` count it added). Its `Drop` — which runs however the `subscribe`
/// future ends: normal return, an error, a fired cancel token, OR an abort that
/// never fires the token — decrements the count and, if it was the **last**
/// unresolved waiter, cancels the physical open and removes the entry.
///
/// The decrement, the last-waiter decision, the `cancel`, and the registry
/// removal all happen **atomically under the registry lock** (order
/// registry -> `inner`), re-checking `waiters == 0 && outcome.is_none()` and that
/// the registry still holds *this* `Opening`. Joiners (Phase 1) and the
/// driver-flip (`Opening -> Live`) serialize on the same registry lock, so this
/// never (a) tears down an open a late joiner just re-populated, nor (b) cancels
/// an already-`Live` fan-out — its entry is no longer `Opening`, so the guarded
/// `cancel`+remove is skipped and the live upstream survives.
struct WaiterGuard {
    coalescer: Weak<WatchCoalescer>,
    key: CoalesceKey,
    opening: Arc<Opening>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let Some(coalescer) = self.coalescer.upgrade() else {
            // The coalescer is gone: no registry to update, but still decrement
            // and cancel a now-orphaned open so its parked driver exits.
            if let Ok(mut inner) = self.opening.inner.lock() {
                inner.waiters = inner.waiters.saturating_sub(1);
                if inner.waiters == 0 && inner.outcome.is_none() {
                    self.opening.cancel.cancel();
                }
            }
            return;
        };
        // Hold the registry lock across the decrement + teardown decision so
        // joiners and the driver-flip serialize with us (order registry -> inner).
        let mut registry = lock_registry(&coalescer.registry);
        let tear_down = {
            let Ok(mut inner) = self.opening.inner.lock() else {
                return;
            };
            inner.waiters = inner.waiters.saturating_sub(1);
            inner.waiters == 0 && inner.outcome.is_none()
        };
        if tear_down
            && let Some(KeyState::Opening(cur)) = registry.get(&self.key)
            && Arc::ptr_eq(cur, &self.opening)
        {
            self.opening.cancel.cancel();
            registry.remove(&self.key);
        }
    }
}

/// Drive one key's physical open: read the negotiated cadence, run the factory
/// (racing the open's cancel), then publish the fan-out (or the failure) to the
/// `Opening` and wake its waiters. Runs as a detached task so no single
/// subscriber's cancellation can drop the future out from under the others.
async fn drive_open(
    coalescer: Weak<WatchCoalescer>,
    key: CoalesceKey,
    opening: Arc<Opening>,
    upstream: UpstreamFactory,
) {
    // Yield once so concurrent first-waiters that raced in behind the registry
    // insert can lower `min_cadence` before it is frozen for the upstream's
    // lifetime. Later joiners accept the live cadence (see `UpstreamFactory`).
    tokio::task::yield_now().await;

    // Freeze the cohort at the `Collecting -> Opening` transition and read the
    // negotiated cadence in the same critical section. A poisoned cadence lock is
    // **terminal** — a fabricated interval could violate a backend floor and we
    // refuse to open a resource despite the poison (fail with `Internal`).
    let cadence = {
        let Ok(mut inner) = opening.inner.lock() else {
            fail_open_terminal(
                &coalescer,
                &key,
                &opening,
                Error::new(
                    ErrorCode::Internal,
                    "watch coalescer cadence lock is poisoned",
                ),
            );
            return;
        };
        inner.frozen = true;
        inner.min_cadence
    };

    let opened = tokio::select! {
        biased;
        _ = opening.cancel.cancelled() => Err(Error::new(
            ErrorCode::Cancelled,
            "watch_directory upstream open cancelled",
        )),
        result = upstream(opening.cancel.clone(), cadence) => result,
    };

    // Publish the outcome. If the coalescer is gone, there are no waiters to
    // serve; just record the outcome and wake anyone parked so they exit.
    match opened {
        Ok(stream) => {
            let fanout = WatchDirectoryFanout::new(stream, opening.cancel.clone());
            if let Some(coalescer) = coalescer.upgrade() {
                // Publish atomically under the established registry -> inner lock
                // order: the registry `Live` flip and `inner.outcome = Ready`
                // become a single critical section, so a concurrent
                // `WaiterGuard::drop` can never observe `Live` with an unset
                // outcome (the window that leaked an orphaned upstream).
                let mut registry = lock_registry(&coalescer.registry);
                let mut inner = opening.inner.lock().unwrap_or_else(|e| e.into_inner());
                let still_ours = matches!(
                    registry.get(&key),
                    Some(KeyState::Opening(cur)) if Arc::ptr_eq(cur, &opening)
                );
                if !still_ours {
                    // The entry was removed or replaced while we opened: this
                    // fan-out is orphaned. Cancel the physical open; the discarded
                    // fan-out's `Drop` stops the producer as a backstop.
                    opening.cancel.cancel();
                    inner.outcome = Some(OpenOutcome::Failed(Error::new(
                        ErrorCode::Cancelled,
                        "watch_directory upstream open superseded before publication",
                    )));
                } else if inner.waiters == 0 {
                    // The last waiter left in the publish window: nobody wants
                    // this open. Cancel it, drop the now-stale entry, and discard
                    // the fan-out (its `Drop` also stops the producer).
                    opening.cancel.cancel();
                    registry.remove(&key);
                    inner.outcome = Some(OpenOutcome::Failed(Error::new(
                        ErrorCode::Cancelled,
                        "watch_directory upstream open unwanted before publication",
                    )));
                } else {
                    // A waiter is still parked: flip `Live` and set `Ready`
                    // together, before releasing either lock.
                    registry.insert(key.clone(), KeyState::Live(Arc::downgrade(&fanout)));
                    inner.outcome = Some(OpenOutcome::Ready(fanout));
                }
            } else {
                // Coalescer gone: no registry to publish into and no new waiter
                // will attach. Record `Ready` so any parked waiter exits; the
                // fan-out then drops unattached and its `Drop` cancels the
                // upstream.
                let mut inner = opening.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.outcome = Some(OpenOutcome::Ready(fanout));
            }
        }
        Err(err) => {
            // Record the failure and drop the registry entry in one critical
            // section (order registry -> inner), so a concurrent
            // `WaiterGuard::drop` sees a consistent removed-entry/`Failed` pair.
            if let Some(coalescer) = coalescer.upgrade() {
                let mut registry = lock_registry(&coalescer.registry);
                let mut inner = opening.inner.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(KeyState::Opening(cur)) = registry.get(&key)
                    && Arc::ptr_eq(cur, &opening)
                {
                    registry.remove(&key);
                }
                inner.outcome = Some(OpenOutcome::Failed(err));
            } else {
                let mut inner = opening.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.outcome = Some(OpenOutcome::Failed(err));
            }
        }
    }
    opening.done.cancel();
}

/// Terminate an in-flight open with a terminal error without ever opening a
/// backend resource: cancel the physical open, remove the registry entry (if
/// still this `Opening`), record the failure, and wake every parked waiter so
/// they observe the `Err`. Used when the cadence lock is poisoned — we refuse to
/// fabricate a non-normalized interval.
fn fail_open_terminal(
    coalescer: &Weak<WatchCoalescer>,
    key: &CoalesceKey,
    opening: &Arc<Opening>,
    err: Error,
) {
    opening.cancel.cancel();
    if let Some(coalescer) = coalescer.upgrade() {
        let mut registry = lock_registry(&coalescer.registry);
        if let Some(KeyState::Opening(cur)) = registry.get(key)
            && Arc::ptr_eq(cur, opening)
        {
            registry.remove(key);
        }
    }
    // Recover the poisoned lock so waiters read `Failed` rather than blocking on
    // `done` forever; a waiter's own poisoned read would surface `Internal` too.
    let mut inner = opening.inner.lock().unwrap_or_else(|e| e.into_inner());
    inner.outcome = Some(OpenOutcome::Failed(err));
    drop(inner);
    opening.done.cancel();
}

/// Per-subscriber entry. `gap` is shared with the [`WatcherReceiver`]: the
/// dispatcher sets it (and drops the overflowing event) on queue overflow; the
/// receiver delivers it as a synthetic `Lapsed` on the next pull regardless of
/// queue occupancy. This guarantees prompt Lapsed delivery independently of any
/// future upstream activity. `id` lets `WatcherReceiver::drop` remove exactly this entry so the
/// live-subscriber count stays accurate. The `(prefix, recursive,
/// include_metadata_changes)` filter is matched by the dispatcher **before**
/// `try_send`, so an event outside this subscriber's view never touches its
/// queue.
struct WatcherEntry {
    id: u64,
    sender: mpsc::SyncSender<Result<BackendChangeEvent>>,
    gap: Arc<AtomicBool>,
    /// Out-of-band terminal error, shared with the [`WatcherReceiver`]. Set by
    /// [`WatchDirectoryFanout::broadcast_terminal`] so a subscriber whose bounded
    /// queue is **full** still observes the terminal `Err` (an in-band `try_send`
    /// would be dropped on `Full`, and the subscriber would then drain to a clean
    /// EOF — a silent loss). The receiver drains this after its channel empties.
    terminal: Arc<Mutex<Option<Error>>>,
    prefix: Url,
    recursive: bool,
    include_metadata_changes: bool,
}

/// One upstream [`AckingStream`] fanned out to N subscribers.
struct WatchDirectoryFanout {
    watchers: Mutex<Vec<WatcherEntry>>,
    /// Holds the upstream stream between construction and the first
    /// `subscribe()`. The first subscriber takes ownership, registers its entry,
    /// and spawns the dispatcher — atomically w.r.t. the upstream pull, so a
    /// synchronous-emit upstream can't publish event 0 to an empty subscriber
    /// list and lose it. Late subscribers see only post-subscribe events; a
    /// caller wanting a cold-start refresh passes `opts.since`.
    pending_stream: Mutex<Option<AckingStream>>,
    /// Cancels the upstream. Fired by `WatcherReceiver::drop` when the last
    /// subscriber leaves, AND by the dispatcher itself when the upstream
    /// terminates (end or error) — so a racing same-key subscribe observes a
    /// cancelled fan-out and reopens fresh instead of attaching to an exited
    /// dispatcher (the "corpse" race).
    cancel: CancellationToken,
    /// Live [`WatcherReceiver`] count. Last-consumer teardown keys off this
    /// atomic; entries are also removed from `watchers` on drop.
    active_consumers: AtomicUsize,
    /// Monotonic id source for `WatcherEntry`.
    next_id: AtomicU64,
}

impl WatchDirectoryFanout {
    fn new(stream: AckingStream, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            watchers: Mutex::new(Vec::new()),
            pending_stream: Mutex::new(Some(stream)),
            cancel,
            active_consumers: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
        })
    }

    /// Register a subscriber; the first one takes the pending upstream and spawns
    /// the dispatcher thread. Returns `Cancelled` if the fan-out was torn down
    /// before this subscriber attached (the coalescer retries with a fresh
    /// upstream).
    fn subscribe(
        self: &Arc<Self>,
        prefix: Url,
        recursive: bool,
        include_metadata_changes: bool,
        subscriber_cancel: Option<CancellationToken>,
    ) -> Result<WatcherReceiver> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_DEPTH);
        let gap = Arc::new(AtomicBool::new(false));
        let terminal: Arc<Mutex<Option<Error>>> = Arc::new(Mutex::new(None));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let pending_stream = {
            let mut pending_stream = self.pending_stream.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "watch fan-out pending-stream lock is poisoned",
                )
            })?;
            let mut watchers = self
                .watchers
                .lock()
                .map_err(|_| Error::new(ErrorCode::Internal, "watch fan-out lock is poisoned"))?;
            // A fan-out cancelled between the coalescer upgrading its Weak and
            // this lock must not silently attach to a dead upstream — covers both
            // a last-subscriber teardown and a dispatcher end-of-stream.
            if self.cancel.is_cancelled() {
                return Err(Error::new(
                    ErrorCode::Cancelled,
                    "watch fan-out cancelled before subscriber registered",
                ));
            }
            watchers.push(WatcherEntry {
                id,
                sender,
                gap: gap.clone(),
                terminal: terminal.clone(),
                prefix,
                recursive,
                include_metadata_changes,
            });
            // Increment UNDER the watchers lock so a concurrent
            // `WatcherReceiver::drop` can't see the count before we've
            // contributed and fire the cancel as the "last" consumer.
            self.active_consumers.fetch_add(1, Ordering::SeqCst);
            pending_stream.take()
        };
        if let Some(stream) = pending_stream {
            let fanout = self.clone();
            std::thread::Builder::new()
                .name("ovs-watch-fan".into())
                .spawn(move || fanout.run(stream))
                .expect("failed to spawn watch fan-out thread");
        }
        Ok(WatcherReceiver {
            inner: receiver,
            fanout: Arc::downgrade(self),
            cancel: subscriber_cancel,
            id,
            gap,
            terminal,
        })
    }

    fn run(self: Arc<Self>, stream: AckingStream) {
        for item in stream {
            let (event, ack) = match item {
                Ok(pair) => pair,
                // An upstream error is terminal (consistent with each wrapper's
                // `GapSweepStream`, which treats `Err` as a gap): broadcast it to
                // every subscriber, then tear the fan-out down so the next
                // subscribe reopens fresh. A terminal `Err` bypasses the filter.
                Err(err) => {
                    self.broadcast_terminal(err);
                    break;
                }
            };
            let alive_after = self.fan_out(&event);
            // Ack AFTER fan-out: nonblocking dispatch into the adopter's ack
            // pump. A slow network ack runs off this thread, so it never
            // serializes the fan-out. A *synchronous* dispatch failure (the ack
            // channel `try_send` returning Full/Closed) is terminal — same path
            // as a terminal stream `Err` — so an ack is never silently dropped.
            if let Err(err) = ack() {
                self.broadcast_terminal(err);
                break;
            }
            if !alive_after {
                break;
            }
        }
        self.teardown();
    }

    /// Fan one event out to the matching subscribers, filtering `Object` events
    /// per subscriber **before** `try_send`. `Lapsed` bypasses the filter (a gap
    /// in the superset is a gap for every view). Returns whether any subscriber
    /// remains.
    fn fan_out(&self, event: &BackendChangeEvent) -> bool {
        let Ok(mut watchers) = self.watchers.lock() else {
            return false;
        };
        let is_object = matches!(event, BackendChangeEvent::Object { .. });
        watchers.retain_mut(|watcher| {
            if is_object
                && !watcher_accepts(
                    &watcher.prefix,
                    watcher.recursive,
                    watcher.include_metadata_changes,
                    event,
                )
            {
                // Outside this subscriber's view: skip without touching its queue,
                // so unrelated-prefix traffic can't overflow a quiet subscriber.
                return true;
            }
            match watcher.sender.try_send(Ok(event.clone())) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    // Overflow: drop this event and raise the subscriber's gap
                    // flag; the receiver delivers a Lapsed when it drains.
                    tracing::warn!(
                        target: "ovstorage.watch_coalescer",
                        queue_depth = QUEUE_DEPTH,
                        "watch fan-out queue overflow; marking gap (Lapsed on drain)"
                    );
                    watcher.gap.store(true, Ordering::SeqCst);
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
        !watchers.is_empty()
    }

    /// Broadcast a terminal error to every subscriber (bypassing the filter) on
    /// the way to teardown.
    ///
    /// The error is stored **out-of-band** in each subscriber's `terminal` slot
    /// (mirroring the `gap` overflow flag) rather than pushed in-band: a
    /// subscriber whose bounded queue is `Full` would lose an in-band `try_send`
    /// and then drain to a clean EOF — a silent loss of the terminal error. The
    /// receiver drains the slot after its channel empties, so the `Err` always
    /// surfaces. Dropping the senders (via `clear`) disconnects each channel, so
    /// the receiver reaches the drain promptly.
    ///
    /// The `cancel` fires **under the watchers lock**, together with `clear`, so a
    /// `subscribe` racing between this call and teardown either observes the
    /// cancelled fan-out (and reopens fresh) or has already registered — in which
    /// case it, too, gets the terminal slot set here — and can never attach
    /// silently to the dying fan-out.
    fn broadcast_terminal(&self, err: Error) {
        let Ok(mut watchers) = self.watchers.lock() else {
            self.cancel.cancel();
            return;
        };
        for watcher in watchers.iter() {
            if let Ok(mut slot) = watcher.terminal.lock()
                && slot.is_none()
            {
                *slot = Some(err.clone());
            }
        }
        self.cancel.cancel();
        watchers.clear();
    }

    /// Fire the fan-out cancel and drop every sender, UNDER the watchers lock so
    /// a concurrent `subscribe` either observes the cancelled fan-out (and is
    /// rejected → the coalescer reopens fresh) or has already registered (and
    /// sees `Disconnected` on its next pull, not an infinite block). Closes the
    /// end-of-stream corpse race.
    fn teardown(&self) {
        let Ok(mut watchers) = self.watchers.lock() else {
            self.cancel.cancel();
            return;
        };
        self.cancel.cancel();
        watchers.clear();
    }
}

impl Drop for WatchDirectoryFanout {
    /// Backstop: any path that drops a fan-out without an explicit teardown — a
    /// publication that finds no waiter, an orphaned/superseded open, or a
    /// coalescer that shut down mid-open — must still cancel the upstream token
    /// the adopter's producer holds a clone of, or that producer leaks (a
    /// competing SQS/Pub-Sub consumer running with nobody reading it).
    /// `CancellationToken::cancel` is idempotent, so this is a no-op after a
    /// normal `teardown`/`broadcast_terminal` that already cancelled.
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A subscriber's end of a coalesced watch. A blocking `Iterator` over
/// `Result<BackendChangeEvent>`. Dropping it removes its `watchers` entry and,
/// when it was the last one, cancels the shared upstream. Holds a `Weak` so it
/// doesn't keep a torn-down fan-out alive.
struct WatcherReceiver {
    inner: mpsc::Receiver<Result<BackendChangeEvent>>,
    fanout: Weak<WatchDirectoryFanout>,
    /// When set, `next()` polls this token so a parked pull ends promptly on
    /// cancel (a drain's `Drop`, or a caller cancelling its own watch) — without
    /// tearing down the shared upstream other subscribers still use.
    cancel: Option<CancellationToken>,
    id: u64,
    /// Shared overflow flag (see [`WatcherEntry::gap`]); delivered as a synthetic
    /// `Lapsed` on the next pull regardless of queue occupancy.
    gap: Arc<AtomicBool>,
    /// Shared out-of-band terminal error (see [`WatcherEntry::terminal`]); drained
    /// as the final `Err` when the queue empties, after any pending `Lapsed`.
    terminal: Arc<Mutex<Option<Error>>>,
}

impl WatcherReceiver {
    /// Returns `true` if this receiver ended because its own cancel token fired
    /// (an intentional teardown), as opposed to the upstream ending or erroring
    /// (a genuine coverage gap).
    fn cancelled_by_subscriber(&self) -> bool {
        self.cancel.as_ref().is_some_and(|t| t.is_cancelled())
    }

    fn take_gap_lapsed(&self) -> Option<Result<BackendChangeEvent>> {
        if self.gap.swap(false, Ordering::SeqCst) {
            Some(Ok(BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            }))
        } else {
            None
        }
    }

    /// Take the out-of-band terminal error, if one was stored.
    fn take_terminal(&self) -> Option<Error> {
        self.terminal.lock().ok().and_then(|mut slot| slot.take())
    }

    /// The tail delivered once the channel is drained/disconnected: any pending
    /// overflow `Lapsed` first, then the stored terminal `Err` (so a full-queue
    /// subscriber still observes it, never a silent clean EOF), then `None`.
    fn drained_tail(&self) -> Option<Result<BackendChangeEvent>> {
        if let Some(lapsed) = self.take_gap_lapsed() {
            return Some(lapsed);
        }
        if let Some(err) = self.take_terminal() {
            return Some(Err(err));
        }
        None
    }
}

impl Iterator for WatcherReceiver {
    type Item = Result<BackendChangeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Observe cancellation on EVERY pull, ahead of every other outcome —
            // including a pending overflow gap. A cancelled subscriber is going
            // away, so cancel wins over delivering anything more: it returns
            // `None` promptly rather than emitting one last `Lapsed` before the
            // teardown. Checking here (not only in the `Empty` arm) is also what
            // makes cancel observable under sustained flow, where `try_recv`
            // returns `Ok` indefinitely and never reaches `Empty`; a cancel
            // checked only there would never be seen and the subscriber would
            // yield forever (wedging broker shutdown during an event storm).
            if self.cancelled_by_subscriber() {
                return None;
            }
            // Deliver a raised overflow gap before draining more queued events.
            // Under sustained overload `try_recv` returns `Ok` indefinitely and
            // never reports `Empty`, so this top-of-loop check is the only place
            // the marker is guaranteed to land on the next pull. The atomic swap
            // in `take_gap_lapsed` keeps it to exactly one `Lapsed` per gap.
            if let Some(lapsed) = self.take_gap_lapsed() {
                return Some(lapsed);
            }
            match self.inner.try_recv() {
                Ok(item) => return Some(item),
                Err(TryRecvError::Disconnected) => return self.drained_tail(),
                Err(TryRecvError::Empty) => {
                    if self.cancelled_by_subscriber() {
                        return None;
                    }
                    match self.inner.recv_timeout(RECV_POLL_INTERVAL) {
                        Ok(item) => return Some(item),
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return self.drained_tail();
                        }
                    }
                }
            }
        }
    }
}

impl Drop for WatcherReceiver {
    fn drop(&mut self) {
        let Some(fanout) = self.fanout.upgrade() else {
            return;
        };
        // Remove this entry and decide last-consumer teardown UNDER the watchers
        // lock: the removal keeps the live-subscriber count accurate, and
        // serializing with `subscribe`'s register-and-increment prevents a
        // concurrent subscriber that hasn't yet incremented from making us fire
        // the cancel as the "last" consumer.
        // Recover a poisoned lock (matching `lock_registry`) so a panic under
        // the lock does not skip the decrement and leak the shared upstream; the
        // lock still serializes with `subscribe`'s register-and-increment.
        let mut watchers = fanout.watchers.lock().unwrap_or_else(|e| e.into_inner());
        watchers.retain(|w| w.id != self.id);
        if fanout.active_consumers.fetch_sub(1, Ordering::SeqCst) == 1 {
            fanout.cancel.cancel();
        }
    }
}

/// A subscriber-facing wrapper over a [`WatcherReceiver`]. Event filtering lives
/// at the dispatcher (see [`watcher_accepts`]), so this wrapper only prepends one
/// `Lapsed` when the subscribing watch carried `opts.since` (the best "resume"
/// without history — the watch still coalesces onto the shared upstream rather
/// than opening a dedicated replay stream).
struct FilteredWatcherReceiver {
    inner: WatcherReceiver,
    /// When `true`, the next pull yields the prepended `Lapsed` and clears.
    initial_lapsed: bool,
}

impl Iterator for FilteredWatcherReceiver {
    type Item = Result<BackendChangeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.initial_lapsed {
            self.initial_lapsed = false;
            return Some(Ok(BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            }));
        }
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct ManualClock {
        base: Instant,
        offset_nanos: AtomicU64,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_nanos: AtomicU64::new(0),
            }
        }

        fn advance(&self, by: Duration) {
            self.offset_nanos
                .fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.offset_nanos.load(Ordering::Relaxed))
        }
    }

    #[test]
    fn pending_decrement_returns_handle_only_when_remaining_hits_zero() {
        let p: Pending<&str> = Pending::new();
        let deadline = Instant::now();
        let id = p.insert("handle", 2, deadline);
        assert_eq!(p.decrement(id), Ok(PendingDecrement::Pending));
        assert_eq!(
            p.decrement(id),
            Ok(PendingDecrement::Ready {
                handle: "handle",
                deadline
            })
        );
        assert!(p.is_empty());
    }

    #[test]
    fn pending_decrement_reports_missing_delivery_id() {
        let p: Pending<&str> = Pending::new();
        let missing = DeliveryId(42);
        assert_eq!(p.decrement(missing), Err(MissingDeliveryId { id: missing }));
    }

    #[test]
    #[should_panic(expected = "pending delivery must have at least one event")]
    fn pending_insert_rejects_zero_remaining() {
        let p: Pending<&str> = Pending::new();
        p.insert("handle", 0, Instant::now());
    }

    #[test]
    fn pending_delivery_ids_are_unique() {
        let p: Pending<()> = Pending::new();
        let now = Instant::now();
        let a = p.insert((), 1, now);
        let b = p.insert((), 1, now);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clock_advances() {
        let c = ManualClock::new();
        let t0 = c.now();
        c.advance(Duration::from_secs(10));
        let t1 = c.now();
        assert!(t1 >= t0 + Duration::from_secs(10));
    }
}

#[cfg(test)]
mod watch_coalescer_tests {
    use super::*;
    use crate::ChangeKind;
    use std::sync::atomic::AtomicBool;

    fn key(k: &str) -> CoalesceKey {
        k.to_string()
    }

    fn opts() -> WatchDirectoryOptions {
        WatchDirectoryOptions {
            recursive: true,
            include_metadata_changes: true,
            since: None,
            poll_interval: Duration::from_millis(10),
        }
    }

    fn opts_since() -> WatchDirectoryOptions {
        WatchDirectoryOptions {
            since: Some(WatchDirectoryCursor(vec![9])),
            ..opts()
        }
    }

    fn prefix() -> Url {
        Url::parse("test://bucket/a/").unwrap()
    }

    /// A default adopter-normalized cadence for tests that don't exercise
    /// cadence negotiation.
    fn cadence() -> Duration {
        Duration::from_millis(10)
    }

    // Under `prefix()` (`test://bucket/a/`) so the dispatcher-side recursive
    // filter admits it to the subscriber's queue.
    fn object_event(i: usize) -> Result<BackendChangeEvent> {
        object_event_at(&format!("test://bucket/a/o-{i}"), ChangeKind::Created, i)
    }

    fn object_event_at(
        address: &str,
        kind: ChangeKind,
        cursor: usize,
    ) -> Result<BackendChangeEvent> {
        Ok(BackendChangeEvent::Object {
            address: Url::parse(address).unwrap(),
            kind,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            at: std::time::SystemTime::UNIX_EPOCH,
            cursor: WatchDirectoryCursor(vec![(cursor & 0xff) as u8]),
        })
    }

    fn noop_ack() -> AckHandle {
        Box::new(|| Ok(()))
    }

    /// Pair a `Result<BackendChangeEvent>` with a no-op ack for an `AckingStream`.
    fn with_noop_ack(event: Result<BackendChangeEvent>) -> Result<(BackendChangeEvent, AckHandle)> {
        event.map(|e| (e, noop_ack()))
    }

    /// A scripted upstream: yields `events`, then either ends (`keep_alive =
    /// false`, a finite burst) or parks polling its cancel token (`keep_alive =
    /// true`) until torn down. Sets `torn_down` on Drop to prove last-unsubscribe
    /// teardown.
    struct ScriptedStream {
        events: std::vec::IntoIter<Result<BackendChangeEvent>>,
        cancel: CancellationToken,
        keep_alive: bool,
        torn_down: Arc<AtomicBool>,
    }

    impl Iterator for ScriptedStream {
        type Item = Result<(BackendChangeEvent, AckHandle)>;
        fn next(&mut self) -> Option<Self::Item> {
            if let Some(ev) = self.events.next() {
                return Some(with_noop_ack(ev));
            }
            if !self.keep_alive {
                return None;
            }
            loop {
                if self.cancel.is_cancelled() {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl Drop for ScriptedStream {
        fn drop(&mut self) {
            self.torn_down.store(true, Ordering::SeqCst);
        }
    }

    /// Build an upstream opener that counts opens and returns a scripted stream
    /// carrying `event_count` object events.
    fn scripted_upstream(
        opens: Arc<AtomicUsize>,
        torn_down: Arc<AtomicBool>,
        event_count: usize,
        keep_alive: bool,
    ) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, _cadence: Duration| {
            opens.fetch_add(1, Ordering::SeqCst);
            let torn_down = torn_down.clone();
            let events: Vec<Result<BackendChangeEvent>> =
                (0..event_count).map(object_event).collect();
            Box::pin(async move {
                Ok(Box::new(ScriptedStream {
                    events: events.into_iter(),
                    cancel,
                    keep_alive,
                    torn_down,
                }) as AckingStream)
            }) as BoxFuture<'static, Result<AckingStream>>
        })
    }

    /// An upstream that blocks until events are injected (honoring the cancel
    /// token), so a test can register subscribers before any event flows and
    /// drive delivery deterministically.
    #[derive(Default)]
    struct InjectableUpstream {
        queue: std::sync::Mutex<std::collections::VecDeque<Result<BackendChangeEvent>>>,
        ready: std::sync::Condvar,
    }

    impl InjectableUpstream {
        fn inject(&self, event: Result<BackendChangeEvent>) {
            self.queue.lock().unwrap().push_back(event);
            self.ready.notify_all();
        }
    }

    fn injectable_upstream(
        state: Arc<InjectableUpstream>,
        opens: Arc<AtomicUsize>,
    ) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, _cadence: Duration| {
            opens.fetch_add(1, Ordering::SeqCst);
            let state = state.clone();
            Box::pin(async move { Ok(Box::new(InjectableIter { state, cancel }) as AckingStream) })
                as BoxFuture<'static, Result<AckingStream>>
        })
    }

    struct InjectableIter {
        state: Arc<InjectableUpstream>,
        cancel: CancellationToken,
    }

    impl Iterator for InjectableIter {
        type Item = Result<(BackendChangeEvent, AckHandle)>;
        fn next(&mut self) -> Option<Self::Item> {
            let mut queue = self.state.queue.lock().unwrap();
            loop {
                if let Some(event) = queue.pop_front() {
                    return Some(with_noop_ack(event));
                }
                if self.cancel.is_cancelled() {
                    return None;
                }
                let (g, _) = self
                    .state
                    .ready
                    .wait_timeout(queue, Duration::from_millis(20))
                    .unwrap();
                queue = g;
            }
        }
    }

    fn recv_within(
        stream: &mut BackendChangeStream,
        timeout: Duration,
    ) -> Option<Result<BackendChangeEvent>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(item) = stream.next() {
                return Some(item);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
        }
    }

    fn cursor_of(m: &Option<Result<BackendChangeEvent>>) -> Option<Vec<u8>> {
        match m {
            Some(Ok(BackendChangeEvent::Object { cursor, .. })) => Some(cursor.0.clone()),
            _ => None,
        }
    }

    /// Two subscribers on the SAME key share ONE upstream (opener invoked once);
    /// a DIFFERENT key opens a second upstream.
    #[tokio::test]
    async fn coalesces_same_key_and_separates_distinct_keys() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let torn = Arc::new(AtomicBool::new(false));
        let upstream = scripted_upstream(opens.clone(), torn.clone(), 0, true);

        let _r1 = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        let _r2 = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1, "same key must coalesce");

        let _r3 = hub
            .subscribe(
                key("b"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            opens.load(Ordering::SeqCst),
            2,
            "a distinct key must open its own upstream"
        );
    }

    /// Dropping the last subscriber cancels the shared upstream.
    #[tokio::test]
    async fn last_unsubscribe_tears_down_upstream() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let torn = Arc::new(AtomicBool::new(false));
        let upstream = scripted_upstream(opens.clone(), torn.clone(), 0, true);

        let r1 = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        let r2 = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();

        drop(r1);
        assert!(
            !torn.load(Ordering::SeqCst),
            "upstream must stay live while a subscriber remains"
        );
        drop(r2);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !torn.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            torn.load(Ordering::SeqCst),
            "last unsubscribe must tear down the upstream"
        );
    }

    /// A slow subscriber that overflows its queue gets a `Lapsed` (not a
    /// terminal error) and keeps receiving.
    #[tokio::test]
    async fn slow_subscriber_overflow_injects_lapsed() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let torn = Arc::new(AtomicBool::new(false));
        let upstream = scripted_upstream(opens, torn, QUEUE_DEPTH + 20, false);

        let mut receiver = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();

        let handle = std::thread::spawn(move || {
            let mut saw_lapsed = false;
            let mut errors = 0usize;
            let mut received = 0usize;
            for msg in receiver.by_ref() {
                received += 1;
                match msg {
                    Ok(BackendChangeEvent::Lapsed { .. }) => {
                        saw_lapsed = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => errors += 1,
                }
                std::thread::sleep(Duration::from_millis(1));
                if received > QUEUE_DEPTH + 40 {
                    break;
                }
            }
            (saw_lapsed, errors)
        });
        let (saw_lapsed, errors) = handle.join().unwrap();
        assert_eq!(errors, 0, "overflow must not surface a terminal error");
        assert!(saw_lapsed, "overflow must inject a Lapsed marker");
    }

    /// The overflow `Lapsed` marker lands on the VERY NEXT pull even while the
    /// bounded queue is still full — it is not deferred until the queue drains.
    /// Falsifies the pre-fix behavior where `take_gap_lapsed` was checked only in
    /// the `try_recv` `Empty` arm: under sustained overload `try_recv` keeps
    /// returning `Ok`, so the gap `Lapsed` was never delivered while events
    /// remained queued.
    #[test]
    fn overflow_lapsed_delivered_on_next_pull_while_queue_full() {
        let cancel = CancellationToken::new();
        let torn = Arc::new(AtomicBool::new(false));
        let stream = Box::new(ScriptedStream {
            events: Vec::new().into_iter(),
            cancel: cancel.clone(),
            keep_alive: true,
            torn_down: torn,
        }) as AckingStream;
        let fanout = WatchDirectoryFanout::new(stream, cancel);
        let mut rx = fanout.subscribe(prefix(), true, true, None).unwrap();

        // Reach into the registered entry for its sender + gap flag so the test
        // fills the queue to capacity and raises the overflow gap exactly as
        // `fan_out` does — deterministically, without relying on dispatcher
        // timing (the scripted upstream carries no events and stays parked).
        let (sender, gap) = {
            let watchers = fanout.watchers.lock().unwrap();
            let entry = &watchers[0];
            (entry.sender.clone(), entry.gap.clone())
        };

        // Fill the bounded queue to capacity.
        for i in 0..QUEUE_DEPTH {
            sender
                .try_send(object_event(i))
                .expect("queue not yet full");
        }
        // The queue is now full; raise the gap as `fan_out` does on `Full`.
        assert!(
            sender.try_send(object_event(QUEUE_DEPTH)).is_err(),
            "queue must be full to exercise the sustained-overflow path"
        );
        gap.store(true, Ordering::SeqCst);

        // The overflow Lapsed must land on the very next pull, ahead of the
        // still-queued events.
        let first = rx.next();
        assert!(
            matches!(first, Some(Ok(BackendChangeEvent::Lapsed { .. }))),
            "gap Lapsed must be delivered on the next pull while the queue is \
             full, got {first:?}"
        );

        // Exactly one Lapsed per gap: the queued events then follow, all present.
        let mut objects = 0usize;
        for _ in 0..QUEUE_DEPTH {
            match rx.next() {
                Some(Ok(BackendChangeEvent::Object { .. })) => objects += 1,
                other => panic!("expected a queued Object after the Lapsed, got {other:?}"),
            }
        }
        assert_eq!(
            objects, QUEUE_DEPTH,
            "every queued event survives the injected Lapsed"
        );

        drop(rx);
        drop(fanout);
    }

    /// Last-consumer teardown fires the upstream cancel even when the `watchers`
    /// lock is POISONED. Falsifies the pre-fix `if let Ok(watchers.lock())`
    /// guard, which skipped the decrement + cancel on a poisoned lock and leaked
    /// the shared upstream.
    #[test]
    fn poisoned_watchers_lock_still_tears_down_on_last_drop() {
        let cancel = CancellationToken::new();
        let torn = Arc::new(AtomicBool::new(false));
        let stream = Box::new(ScriptedStream {
            events: Vec::new().into_iter(),
            cancel: cancel.clone(),
            keep_alive: true,
            torn_down: torn.clone(),
        }) as AckingStream;
        let fanout = WatchDirectoryFanout::new(stream, cancel);
        let rx = fanout.subscribe(prefix(), true, true, None).unwrap();

        // Poison the watchers lock: panic while holding it, caught so the test
        // process survives. Silence the panic hook so the intentional unwind
        // does not spam test output.
        let poisoner = fanout.clone();
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.watchers.lock().unwrap();
            panic!("intentional poison");
        }));
        std::panic::set_hook(prev_hook);
        assert!(caught.is_err(), "the panic must unwind out of catch_unwind");
        assert!(
            fanout.watchers.is_poisoned(),
            "watchers lock must be poisoned"
        );

        // Dropping the last receiver must still decrement + cancel despite the
        // poison. The fan-out `Arc` stays alive across this assertion, so the
        // `Drop for WatchDirectoryFanout` backstop cannot mask a missed cancel in
        // `WatcherReceiver::drop`.
        drop(rx);

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !torn.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            torn.load(Ordering::SeqCst),
            "poison-safe teardown must cancel the upstream on last drop"
        );
        drop(fanout);
    }

    /// Both subscribers on one key receive the SAME event from ONE upstream
    /// (delivery is a true fan-out, not a competing-consumer round-robin).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_subscribers_receive_same_event_from_one_upstream() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(InjectableUpstream::default());
        let upstream = injectable_upstream(state.clone(), opens.clone());

        let mut r1 = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        let mut r2 = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1, "one upstream for both");

        state.inject(object_event(7));
        let e1 = tokio::task::spawn_blocking(move || {
            let got = recv_within(&mut r1, Duration::from_secs(5));
            (got, r1)
        });
        let e2 = tokio::task::spawn_blocking(move || {
            let got = recv_within(&mut r2, Duration::from_secs(5));
            (got, r2)
        });
        let (g1, _r1) = e1.await.unwrap();
        let (g2, _r2) = e2.await.unwrap();
        assert_eq!(cursor_of(&g1), Some(vec![7]), "r1 must receive the event");
        assert_eq!(
            cursor_of(&g2),
            Some(vec![7]),
            "r2 must receive the same event"
        );
    }

    /// Cancelling one subscriber's token ends only its receiver; the other keeps
    /// receiving and the shared upstream survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn subscriber_cancel_ends_only_that_receiver() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(InjectableUpstream::default());
        let upstream = injectable_upstream(state.clone(), opens.clone());

        let cancel = CancellationToken::new();
        let mut cancellable = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                Some(cancel.clone()),
                upstream.clone(),
            )
            .await
            .unwrap();
        let mut survivor = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1);

        let cancelled = tokio::task::spawn_blocking(move || cancellable.next());
        cancel.cancel();
        assert!(
            cancelled.await.unwrap().is_none(),
            "a cancelled subscriber's receiver must end"
        );

        state.inject(object_event(9));
        let got =
            tokio::task::spawn_blocking(move || recv_within(&mut survivor, Duration::from_secs(5)))
                .await
                .unwrap();
        assert!(
            matches!(got, Some(Ok(BackendChangeEvent::Object { .. }))),
            "the surviving subscriber must keep receiving"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1, "upstream must not reopen");
    }
    /// `opts.since` prepends one `Lapsed` before live events, and the watch still
    /// coalesces onto the shared upstream (opener invoked once).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn since_prepends_initial_lapsed() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(InjectableUpstream::default());
        let upstream = injectable_upstream(state.clone(), opens.clone());

        let _r1 = hub
            .subscribe(
                key("a"),
                prefix(),
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        let mut since = hub
            .subscribe(key("a"), prefix(), opts_since(), cadence(), None, upstream)
            .await
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1, "since watch must coalesce");

        state.inject(object_event(5));
        let (first, second) = tokio::task::spawn_blocking(move || {
            let first = recv_within(&mut since, Duration::from_secs(5));
            let second = recv_within(&mut since, Duration::from_secs(5));
            (first, second)
        })
        .await
        .unwrap();

        assert!(
            matches!(first, Some(Ok(BackendChangeEvent::Lapsed { .. }))),
            "since must prepend a Lapsed, got {first:?}"
        );
        assert_eq!(
            cursor_of(&second),
            Some(vec![5]),
            "the injected live event follows the prepended Lapsed"
        );
    }

    /// A subscriber that opens (or reopens) exactly as the last subscriber drops
    /// must end up on a live fan-out — never attaching to a corpse.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_last_drop_and_subscribe_keeps_new_receiver_live() {
        for cursor in 0..32 {
            let hub = WatchCoalescer::new();
            let opened_states = Arc::new(Mutex::new(Vec::<Arc<InjectableUpstream>>::new()));
            let upstream: UpstreamFactory = {
                let opened_states = opened_states.clone();
                Arc::new(move |cancel, _cadence| {
                    let state = Arc::new(InjectableUpstream::default());
                    opened_states.lock().unwrap().push(state.clone());
                    Box::pin(async move {
                        Ok(Box::new(InjectableIter { state, cancel }) as AckingStream)
                    })
                })
            };
            let old = hub
                .subscribe(
                    key("a"),
                    prefix(),
                    opts(),
                    cadence(),
                    None,
                    upstream.clone(),
                )
                .await
                .unwrap();

            let drop_task = tokio::task::spawn_blocking(move || drop(old));
            let new = hub
                .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
                .await
                .expect("a concurrent subscriber must attach or reopen");
            drop_task.await.unwrap();

            for state in opened_states.lock().unwrap().clone() {
                state.inject(object_event(cursor));
            }
            let received = tokio::task::spawn_blocking(move || new.into_iter().next());
            let item = tokio::time::timeout(Duration::from_secs(1), received)
                .await
                .expect("new receiver must not be dead on arrival")
                .unwrap();
            assert!(
                matches!(item, Some(Ok(BackendChangeEvent::Object { .. }))),
                "new receiver must receive after the last-drop handoff"
            );
            hub.cancel_all();
        }
    }

    /// A first open with NO subscriber cancel token must still be interrupted by
    /// coalescer shutdown — a parked backend open does not wedge forever.
    #[tokio::test]
    async fn hub_shutdown_interrupts_first_open_without_subscriber_cancel() {
        let hub = WatchCoalescer::new();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
        let upstream: UpstreamFactory = Arc::new(move |_cancel, _cadence| {
            if let Some(entered) = entered_tx.lock().unwrap().take() {
                let _ = entered.send(());
            }
            Box::pin(std::future::pending())
        });
        let task = {
            let hub = hub.clone();
            tokio::spawn(async move {
                hub.subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
                    .await
            })
        };

        entered_rx.await.expect("upstream open started");
        hub.cancel_all();
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("hub shutdown must interrupt a parked open")
            .unwrap()
            .err()
            .expect("shutdown must cancel the open");
        assert_eq!(error.code(), ErrorCode::Cancelled);
    }

    #[test]
    fn non_recursive_filter_requires_a_prefix_boundary() {
        let prefix = Url::parse("test://bucket/root").unwrap();
        // A prefix-collision sibling (`rooted/`) is NOT a child of `root`.
        assert!(!watcher_accepts(
            &prefix,
            false,
            true,
            &object_event_at("test://bucket/rooted/child", ChangeKind::Created, 1).unwrap()
        ));
        // A direct child IS accepted.
        assert!(watcher_accepts(
            &prefix,
            false,
            true,
            &object_event_at("test://bucket/root/direct", ChangeKind::Created, 2).unwrap()
        ));
        // A grandchild is not a direct child.
        assert!(!watcher_accepts(
            &prefix,
            false,
            true,
            &object_event_at("test://bucket/root/sub/deep", ChangeKind::Created, 3).unwrap()
        ));
        // Trailing-slash roots retain direct children.
        let root = Url::parse("test://bucket/").unwrap();
        assert!(watcher_accepts(
            &root,
            false,
            true,
            &object_event_at("test://bucket/direct", ChangeKind::Created, 4).unwrap()
        ));
        // An encoded separator (`%2F`) is a nested key `a/b`, not a direct child:
        // ancestry is decided on the percent-decoded path, not the encoded text.
        assert!(!watcher_accepts(
            &prefix,
            false,
            true,
            &object_event_at("test://bucket/root/a%2Fb", ChangeKind::Created, 5).unwrap()
        ));
    }

    /// The watched directory is not a direct child of itself.
    ///
    /// Both spellings of the prefix name one node, so an event about that node
    /// is about the directory being watched. Comparing decoded keys with a
    /// whole-key fallback read the slashless spelling as a single-segment
    /// relative key — a direct child — and delivered the event.
    #[test]
    fn non_recursive_filter_rejects_an_event_about_the_watched_node_itself() {
        for spelled in ["test://bucket/root", "test://bucket/root/"] {
            let prefix = Url::parse(spelled).unwrap();
            for event_address in ["test://bucket/root", "test://bucket/root/"] {
                assert!(
                    !watcher_accepts(
                        &prefix,
                        false,
                        true,
                        &object_event_at(event_address, ChangeKind::Created, 1).unwrap()
                    ),
                    "prefix {spelled} must not accept {event_address} as a direct child of itself"
                );
            }
            // The control: a real direct child is still delivered under either
            // spelling of the prefix.
            assert!(watcher_accepts(
                &prefix,
                false,
                true,
                &object_event_at("test://bucket/root/direct", ChangeKind::Created, 2).unwrap()
            ));
        }
    }

    /// A **recursive** watcher must reject the watched node too.
    ///
    /// `is_ancestor_or_self` compares node paths, which strip one trailing `/`,
    /// so `root` and `root/` are one node to it and an event about `root`
    /// satisfies containment for a watch of `root/`. The recursive branch used
    /// to return on that alone, skipping the self-exclusion the non-recursive
    /// branch performs below it — so a recursive watch of the directory `root/`
    /// delivered events for the *distinct* flat-store object `root`, which is
    /// not beneath the watched prefix. The authz layer's per-event `Read`
    /// re-check does not catch it: the event is genuinely readable, it is simply
    /// out of scope.
    ///
    /// The load-bearing line is the self-exclusion sitting ABOVE the `recursive`
    /// branch; moving it back below reddens this and nothing else.
    #[test]
    fn recursive_filter_rejects_an_event_about_the_watched_node_itself() {
        for spelled in ["test://bucket/root", "test://bucket/root/"] {
            let prefix = Url::parse(spelled).unwrap();
            for event_address in ["test://bucket/root", "test://bucket/root/"] {
                assert!(
                    !watcher_accepts(
                        &prefix,
                        true,
                        true,
                        &object_event_at(event_address, ChangeKind::Created, 1).unwrap()
                    ),
                    "recursive prefix {spelled} must not accept {event_address}, which is \
                     the watched node and not beneath it"
                );
            }
            // The controls: everything genuinely under the prefix still arrives,
            // at any depth, or the exclusion would be filtering the wrong thing.
            for under in [
                "test://bucket/root/direct",
                "test://bucket/root/nested/deep/leaf",
            ] {
                assert!(
                    watcher_accepts(
                        &prefix,
                        true,
                        true,
                        &object_event_at(under, ChangeKind::Created, 2).unwrap()
                    ),
                    "recursive prefix {spelled} must still accept {under}"
                );
            }
            // A sibling that merely shares the prefix's bytes is still out.
            assert!(!watcher_accepts(
                &prefix,
                true,
                true,
                &object_event_at("test://bucket/rootx/y", ChangeKind::Created, 3).unwrap()
            ));
        }
    }

    /// The watched node carrying a modifier is still the watched node.
    ///
    /// Containment ignores a prefix with no query while node identity includes
    /// one, so an event about the watched directory *plus a pin* passed the
    /// gate, missed a guard written in terms of node identity, and was
    /// delivered to a non-recursive watcher as a direct child of itself.
    #[test]
    fn non_recursive_filter_rejects_an_event_about_the_watched_node_with_a_modifier() {
        let prefix = Url::parse("test://bucket/root/").unwrap();
        for event_address in [
            "test://bucket/root?versionId=1",
            "test://bucket/root/?versionId=1",
            "test://bucket/root?a=1&b=2",
        ] {
            assert!(
                !watcher_accepts(
                    &prefix,
                    false,
                    true,
                    &object_event_at(event_address, ChangeKind::Created, 1).unwrap()
                ),
                "{event_address} is the watched node itself, not a child of it"
            );
        }
        // The control: a pinned direct child is still delivered.
        assert!(watcher_accepts(
            &prefix,
            false,
            true,
            &object_event_at("test://bucket/root/a?versionId=1", ChangeKind::Created, 2).unwrap()
        ));
    }

    #[test]
    fn recursive_filter_checks_the_subscriber_prefix() {
        let prefix = Url::parse("test://bucket/foo/").unwrap();
        // Under the prefix at any depth: accepted.
        assert!(watcher_accepts(
            &prefix,
            true,
            true,
            &object_event_at("test://bucket/foo/a/b/c", ChangeKind::Created, 1).unwrap()
        ));
        // Outside the prefix: rejected even though recursive.
        assert!(!watcher_accepts(
            &prefix,
            true,
            true,
            &object_event_at("test://bucket/bar/x", ChangeKind::Created, 2).unwrap()
        ));
        // MetadataChanged dropped when not requested.
        assert!(!watcher_accepts(
            &prefix,
            true,
            false,
            &object_event_at("test://bucket/foo/x", ChangeKind::MetadataChanged, 3).unwrap()
        ));
        assert!(watcher_accepts(
            &prefix,
            true,
            true,
            &object_event_at("test://bucket/foo/x", ChangeKind::MetadataChanged, 4).unwrap()
        ));
    }

    /// Dispatcher-side filtering: flooding one prefix past `QUEUE_DEPTH` must not
    /// overflow a quiet watcher on a disjoint prefix — the quiet watcher gets its
    /// own event and never a synthetic `Lapsed`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn flood_unrelated_prefix_does_not_lapse_quiet_watcher() {
        let hub = WatchCoalescer::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(InjectableUpstream::default());
        let upstream = injectable_upstream(state.clone(), opens.clone());

        let busy_prefix = Url::parse("test://bucket/foo/").unwrap();
        let quiet_prefix = Url::parse("test://bucket/bar/").unwrap();

        // Both share ONE key/upstream but watch disjoint prefixes.
        let _busy = hub
            .subscribe(
                key("shared"),
                busy_prefix,
                opts(),
                cadence(),
                None,
                upstream.clone(),
            )
            .await
            .unwrap();
        let mut quiet = hub
            .subscribe(
                key("shared"),
                quiet_prefix,
                opts(),
                cadence(),
                None,
                upstream,
            )
            .await
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 1, "one upstream for both");

        // Flood the busy prefix far past the queue depth, then one quiet event.
        for i in 0..(QUEUE_DEPTH + 50) {
            state.inject(object_event_at(
                &format!("test://bucket/foo/o-{i}"),
                ChangeKind::Created,
                i,
            ));
        }
        state.inject(object_event_at(
            "test://bucket/bar/only",
            ChangeKind::Created,
            7,
        ));

        // The quiet watcher receives exactly its own event, first, with no
        // Lapsed — its queue never saw the foo flood.
        let got =
            tokio::task::spawn_blocking(move || recv_within(&mut quiet, Duration::from_secs(5)))
                .await
                .unwrap();
        match got {
            Some(Ok(BackendChangeEvent::Object { address, .. })) => {
                assert_eq!(address.as_str(), "test://bucket/bar/only");
            }
            other => panic!("quiet watcher must receive its own event, got {other:?}"),
        }
    }

    /// The dispatcher invokes each delivered event's `AckHandle` exactly once,
    /// after fan-out.
    #[tokio::test]
    async fn ack_invoked_after_fanout() {
        let hub = WatchCoalescer::new();
        let acks = Arc::new(AtomicUsize::new(0));
        const N: usize = 5;

        let upstream: UpstreamFactory = {
            let acks = acks.clone();
            Arc::new(move |_cancel, _cadence| {
                let acks = acks.clone();
                let events: Vec<Result<(BackendChangeEvent, AckHandle)>> = (0..N)
                    .map(|i| {
                        let acks = acks.clone();
                        let ack: AckHandle = Box::new(move || {
                            acks.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        });
                        Ok((object_event(i).unwrap(), ack))
                    })
                    .collect();
                Box::pin(async move { Ok(Box::new(events.into_iter()) as AckingStream) })
            })
        };

        let stream = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();
        // Drain the finite burst.
        let received = tokio::task::spawn_blocking(move || {
            let mut count = 0usize;
            for msg in stream {
                if msg.is_ok() {
                    count += 1;
                }
                if count >= N {
                    break;
                }
            }
            count
        })
        .await
        .unwrap();
        assert_eq!(received, N, "all events must be delivered");

        // Acks fire on the dispatcher thread right after fan-out; give it a beat.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while acks.load(Ordering::SeqCst) < N && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            acks.load(Ordering::SeqCst),
            N,
            "every delivered event's ack must fire exactly once"
        );
    }

    /// Records the cadence the factory was invoked with; returns a keep-alive
    /// empty stream.
    fn cadence_recording_upstream(recorded: Arc<Mutex<Option<Duration>>>) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, cadence: Duration| {
            *recorded.lock().unwrap() = Some(cadence);
            Box::pin(async move { Ok(Box::new(KeepAliveEmpty { cancel }) as AckingStream) })
                as BoxFuture<'static, Result<AckingStream>>
        })
    }

    struct KeepAliveEmpty {
        cancel: CancellationToken,
    }

    impl Iterator for KeepAliveEmpty {
        type Item = Result<(BackendChangeEvent, AckHandle)>;
        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.cancel.is_cancelled() {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    /// The cadence passed to the factory is the min of the opening cohort's
    /// adopter-normalized `effective_cadence`s — NOT derived from
    /// `opts.poll_interval`. Two concurrent subscribers on one key pass 200ms and
    /// 50ms effective cadences (with identical `opts`), and open one upstream at
    /// 50ms.
    #[tokio::test]
    async fn cadence_passed_to_factory_is_min_of_cohort_effective_cadences() {
        let hub = WatchCoalescer::new();
        let recorded = Arc::new(Mutex::new(None));
        let upstream = cadence_recording_upstream(recorded.clone());

        // Both requests carry identical `opts` (same poll_interval); only the
        // adopter-normalized `effective_cadence` differs, proving cadence comes
        // from that argument and not from `opts.poll_interval`.
        let slow_cadence = Duration::from_millis(200);
        let fast_cadence = Duration::from_millis(50);

        // Drive both subscribes concurrently so both register (lowering
        // min_cadence to 50ms) before the detached driver reads it.
        let (a, b) = tokio::join!(
            hub.subscribe(
                key("a"),
                prefix(),
                opts(),
                slow_cadence,
                None,
                upstream.clone()
            ),
            hub.subscribe(
                key("a"),
                prefix(),
                opts(),
                fast_cadence,
                None,
                upstream.clone()
            ),
        );
        let _a = a.unwrap();
        let _b = b.unwrap();

        assert_eq!(
            *recorded.lock().unwrap(),
            Some(Duration::from_millis(50)),
            "cadence must be the min of the cohort's effective_cadences"
        );
        hub.cancel_all();
    }

    /// Records the open's cancel token so a test can observe teardown, and parks.
    fn parking_upstream(
        entered: Arc<AtomicUsize>,
        token_slot: Arc<Mutex<Option<CancellationToken>>>,
    ) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, _cadence: Duration| {
            *token_slot.lock().unwrap() = Some(cancel);
            entered.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        })
    }

    async fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !cond() {
            if std::time::Instant::now() >= deadline {
                panic!("timed out waiting for {what}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Subscriber A cancelling before the shared open completes must NOT kill
    /// subscriber B's upstream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn a_cancels_open_b_survives() {
        let hub = WatchCoalescer::new();
        let entered = Arc::new(AtomicUsize::new(0));
        let token_slot = Arc::new(Mutex::new(None));
        let upstream = parking_upstream(entered.clone(), token_slot.clone());

        let ca = CancellationToken::new();
        let a = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            let ca = ca.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), cadence(), Some(ca), upstream)
                    .await
            })
        };
        let cb = CancellationToken::new();
        let _b = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            let cb = cb.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), cadence(), Some(cb), upstream)
                    .await
            })
        };

        // One shared open enters, with both A and B as waiters.
        wait_until(|| entered.load(Ordering::SeqCst) == 1, "the shared open").await;

        // A cancels before the open completes.
        ca.cancel();
        let a_result = a.await.unwrap();
        assert_eq!(
            a_result.err().map(|e| e.code()),
            Some(ErrorCode::Cancelled),
            "A must return Cancelled"
        );

        // B's upstream must NOT be torn down.
        assert!(
            !token_slot.lock().unwrap().as_ref().unwrap().is_cancelled(),
            "A cancelling must not cancel the shared open B still awaits"
        );

        cb.cancel();
    }

    /// When ALL waiters cancel before the open completes, the physical open is
    /// cancelled and its entry removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn all_waiters_cancel_tears_down_open() {
        let hub = WatchCoalescer::new();
        let entered = Arc::new(AtomicUsize::new(0));
        let token_slot = Arc::new(Mutex::new(None));
        let upstream = parking_upstream(entered.clone(), token_slot.clone());

        let ca = CancellationToken::new();
        let a = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            let ca = ca.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), cadence(), Some(ca), upstream)
                    .await
            })
        };
        let cb = CancellationToken::new();
        let b = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            let cb = cb.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), cadence(), Some(cb), upstream)
                    .await
            })
        };

        wait_until(|| entered.load(Ordering::SeqCst) == 1, "the shared open").await;

        ca.cancel();
        cb.cancel();
        assert_eq!(
            a.await.unwrap().err().map(|e| e.code()),
            Some(ErrorCode::Cancelled)
        );
        assert_eq!(
            b.await.unwrap().err().map(|e| e.code()),
            Some(ErrorCode::Cancelled)
        );

        assert!(
            token_slot.lock().unwrap().as_ref().unwrap().is_cancelled(),
            "all-waiters-cancel must cancel the physical open"
        );
        assert!(
            !hub.registry.lock().unwrap().contains_key(&key("k")),
            "the opening entry must be removed"
        );
    }

    /// Different keys open concurrently — the registry lock is not held across a
    /// hung open, so a parked open on one key does not block the other's open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn different_keys_open_concurrently() {
        let hub = WatchCoalescer::new();
        let entered = Arc::new(AtomicUsize::new(0));
        let token_slot = Arc::new(Mutex::new(None));
        let upstream = parking_upstream(entered.clone(), token_slot.clone());

        let ta = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                hub.subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
                    .await
            })
        };
        let tb = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                hub.subscribe(key("b"), prefix(), opts(), cadence(), None, upstream)
                    .await
            })
        };

        // Both hung opens must enter concurrently; with a lock held across the
        // open, the second would never start.
        wait_until(
            || entered.load(Ordering::SeqCst) == 2,
            "both opens to enter",
        )
        .await;

        hub.cancel_all();
        let _ = ta.await.unwrap();
        let _ = tb.await.unwrap();
    }

    /// A failed upstream open surfaces the error to the subscriber.
    #[tokio::test]
    async fn failed_open_surfaces_error() {
        let hub = WatchCoalescer::new();

        let upstream: UpstreamFactory = Arc::new(|_cancel, _cadence| {
            Box::pin(async { Err(Error::new(ErrorCode::Transient, "upstream open failed")) })
        });

        let err = match hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
        {
            Ok(_) => panic!("a failed open must surface the error"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    /// An upstream that emits one event whose `AckHandle` returns `Err`
    /// (simulating a synchronous ack-dispatch `try_send` → Full/Closed), then
    /// parks until torn down. `torn_down` proves the dispatcher cancelled the
    /// upstream after the terminal ack failure.
    struct FailingAckStream {
        emitted: bool,
        ack_err: Option<Error>,
        cancel: CancellationToken,
        torn_down: Arc<AtomicBool>,
    }

    impl Iterator for FailingAckStream {
        type Item = Result<(BackendChangeEvent, AckHandle)>;
        fn next(&mut self) -> Option<Self::Item> {
            if !self.emitted {
                self.emitted = true;
                let err = self.ack_err.take().unwrap();
                let ack: AckHandle = Box::new(move || Err(err));
                return Some(Ok((object_event(0).unwrap(), ack)));
            }
            loop {
                if self.cancel.is_cancelled() {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl Drop for FailingAckStream {
        fn drop(&mut self) {
            self.torn_down.store(true, Ordering::SeqCst);
        }
    }

    fn failing_ack_upstream(torn_down: Arc<AtomicBool>, ack_err: Error) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, _cadence: Duration| {
            let torn_down = torn_down.clone();
            let ack_err = ack_err.clone();
            Box::pin(async move {
                Ok(Box::new(FailingAckStream {
                    emitted: false,
                    ack_err: Some(ack_err),
                    cancel,
                    torn_down,
                }) as AckingStream)
            }) as BoxFuture<'static, Result<AckingStream>>
        })
    }

    /// A synchronous dispatch failure (the `AckHandle` returns `Err`, simulating
    /// a bounded ack channel `try_send` → Full/Closed) is a terminal upstream
    /// error: the error is broadcast to every subscriber (no silent ack loss) and
    /// the upstream is cancelled.
    async fn ack_error_is_terminal(ack_err: Error) {
        let hub = WatchCoalescer::new();
        let torn = Arc::new(AtomicBool::new(false));
        let upstream = failing_ack_upstream(torn.clone(), ack_err);

        let mut stream = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();

        // The dispatcher delivers the object event, then the failing ack turns
        // terminal: the subscriber sees a trailing `Err`.
        let items = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match stream.next() {
                    Some(item) => {
                        let is_err = item.is_err();
                        out.push(item);
                        if is_err {
                            break;
                        }
                    }
                    None => break,
                }
            }
            out
        })
        .await
        .unwrap();

        assert!(
            matches!(items.last(), Some(Err(_))),
            "a synchronous ack failure must surface a terminal error to the subscriber, got {items:?}"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !torn.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            torn.load(Ordering::SeqCst),
            "a terminal ack failure must cancel/tear down the upstream"
        );
    }

    /// Synchronous ack dispatch returning `Full` is terminal.
    #[tokio::test]
    async fn ack_sync_dispatch_full_is_terminal() {
        ack_error_is_terminal(Error::new(
            ErrorCode::ResourceExhausted,
            "ack channel full (try_send)",
        ))
        .await;
    }

    /// Synchronous ack dispatch returning `Closed` is terminal.
    #[tokio::test]
    async fn ack_sync_dispatch_closed_is_terminal() {
        ack_error_is_terminal(Error::new(
            ErrorCode::Cancelled,
            "ack channel closed (try_send)",
        ))
        .await;
    }
    /// FIX 1 (waiter-lifecycle leak): a waiter whose `subscribe` future is
    /// **aborted without ever firing a cancel token** must still tear the in-flight
    /// open down. Pre-fix the waiter count only decremented in the `select!` leave
    /// arm, so an aborted future leaked its waiter and the open hung forever. The
    /// RAII [`WaiterGuard`] now decrements on drop and tears down as the last
    /// waiter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn aborted_waiter_without_token_tears_down_open() {
        let hub = WatchCoalescer::new();
        let entered = Arc::new(AtomicUsize::new(0));
        let token_slot = Arc::new(Mutex::new(None));
        let upstream = parking_upstream(entered.clone(), token_slot.clone());

        // A single waiter with NO cancel token parks on the shared open.
        let a = {
            let hub = hub.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), cadence(), None, upstream)
                    .await
            })
        };
        wait_until(|| entered.load(Ordering::SeqCst) == 1, "the physical open").await;

        // Abort the task WITHOUT firing any token. The dropped future drops the
        // WaiterGuard, which decrements the last waiter and tears the open down.
        a.abort();

        wait_until(
            || {
                token_slot
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|t| t.is_cancelled())
            },
            "the physical open to be cancelled after the last waiter aborts",
        )
        .await;
        wait_until(
            || !hub.registry.lock().unwrap().contains_key(&key("k")),
            "the opening entry to be removed",
        )
        .await;
    }

    /// FIX 1 (snapshot race / join-a-doomed-open): concurrent first-subscribers of
    /// one key single-flight ONE open and both attach to the live upstream — never
    /// a spurious `Cancelled`, never a silent `None`. Stressed across iterations to
    /// exercise the join-as-the-open-completes window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn concurrent_first_subscribers_join_one_open_without_spurious_cancel() {
        for cursor in 0..32usize {
            let hub = WatchCoalescer::new();
            let opens = Arc::new(AtomicUsize::new(0));
            let state = Arc::new(InjectableUpstream::default());
            let upstream = injectable_upstream(state.clone(), opens.clone());

            let ha = {
                let hub = hub.clone();
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    hub.subscribe(key("k"), prefix(), opts(), cadence(), None, upstream)
                        .await
                })
            };
            let hb = {
                let hub = hub.clone();
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    hub.subscribe(key("k"), prefix(), opts(), cadence(), None, upstream)
                        .await
                })
            };
            let mut ra = ha
                .await
                .unwrap()
                .expect("A must not get a spurious Cancelled");
            let mut rb = hb
                .await
                .unwrap()
                .expect("B must not get a spurious Cancelled");
            assert_eq!(
                opens.load(Ordering::SeqCst),
                1,
                "concurrent first-subscribers must single-flight one open"
            );

            // Both are attached to the SAME live upstream: one injected event
            // reaches both, proving neither silently attached to a corpse (None).
            state.inject(object_event(cursor));
            let t1 =
                tokio::task::spawn_blocking(move || recv_within(&mut ra, Duration::from_secs(2)));
            let t2 =
                tokio::task::spawn_blocking(move || recv_within(&mut rb, Duration::from_secs(2)));
            let g1 = t1.await.unwrap();
            let g2 = t2.await.unwrap();
            assert!(
                matches!(g1, Some(Ok(BackendChangeEvent::Object { .. }))),
                "A must receive the event, not a silent None: {g1:?}"
            );
            assert!(
                matches!(g2, Some(Ok(BackendChangeEvent::Object { .. }))),
                "B must receive the event, not a silent None: {g2:?}"
            );
            hub.cancel_all();
        }
    }

    /// An upstream that fills a subscriber's bounded queue to `QUEUE_DEPTH` with
    /// noop-ack events, then emits ONE more event whose ack fails — turning
    /// terminal while the queue is full. Proves FIX 2: a full-queue subscriber
    /// still observes the trailing `Err`.
    fn fill_then_failing_ack_upstream(ack_err: Error) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, _cadence: Duration| {
            let ack_err = ack_err.clone();
            Box::pin(async move {
                let mut events: Vec<Result<(BackendChangeEvent, AckHandle)>> =
                    Vec::with_capacity(QUEUE_DEPTH + 1);
                for i in 0..QUEUE_DEPTH {
                    events.push(Ok((object_event(i).unwrap(), noop_ack())));
                }
                let failing: AckHandle = Box::new(move || Err(ack_err));
                events.push(Ok((object_event(QUEUE_DEPTH).unwrap(), failing)));
                Ok(Box::new(FillThenPark {
                    events: events.into_iter(),
                    cancel,
                }) as AckingStream)
            }) as BoxFuture<'static, Result<AckingStream>>
        })
    }

    struct FillThenPark {
        events: std::vec::IntoIter<Result<(BackendChangeEvent, AckHandle)>>,
        cancel: CancellationToken,
    }

    impl Iterator for FillThenPark {
        type Item = Result<(BackendChangeEvent, AckHandle)>;
        fn next(&mut self) -> Option<Self::Item> {
            if let Some(ev) = self.events.next() {
                return Some(ev);
            }
            loop {
                if self.cancel.is_cancelled() {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    /// FIX 2 (terminal error lost on a full subscriber queue): a subscriber whose
    /// bounded queue is full must still observe the trailing terminal `Err` after
    /// draining, not a clean `None`. Pre-fix `broadcast_terminal` used `try_send`
    /// and dropped the `Err` on `Full`; the out-of-band `terminal` slot fixes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn full_queue_subscriber_still_observes_terminal_error() {
        let hub = WatchCoalescer::new();
        let upstream = fill_then_failing_ack_upstream(Error::new(
            ErrorCode::ResourceExhausted,
            "ack channel full (try_send)",
        ));

        let stream = hub
            .subscribe(key("a"), prefix(), opts(), cadence(), None, upstream)
            .await
            .unwrap();

        // Do NOT read until the dispatcher has filled the queue and gone terminal,
        // so the terminal `Err` cannot ride an in-band `try_send` (queue is Full).
        let items = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut out = Vec::new();
            for msg in stream {
                let is_err = msg.is_err();
                out.push(msg);
                if is_err {
                    break;
                }
            }
            out
        })
        .await
        .unwrap();

        assert!(
            matches!(items.last(), Some(Err(_))),
            "a full-queue subscriber must still observe the terminal Err after draining, not a clean None"
        );
        let object_count = items
            .iter()
            .filter(|m| matches!(m, Ok(BackendChangeEvent::Object { .. })))
            .count();
        assert_eq!(
            object_count, QUEUE_DEPTH,
            "the subscriber must first drain its full queue of events"
        );
    }

    /// Records the cadence the factory was invoked with, signals `entered` (the
    /// factory runs AFTER the cohort freezes), then parks at `gate` until the test
    /// releases it — so a later joiner can register while the open is held open.
    fn gated_cadence_upstream(
        recorded: Arc<Mutex<Option<Duration>>>,
        entered: CancellationToken,
        gate: CancellationToken,
    ) -> UpstreamFactory {
        Arc::new(move |cancel: CancellationToken, cadence: Duration| {
            let recorded = recorded.clone();
            let entered = entered.clone();
            let gate = gate.clone();
            Box::pin(async move {
                *recorded.lock().unwrap() = Some(cadence);
                entered.cancel();
                gate.cancelled().await;
                Ok(Box::new(KeepAliveEmpty { cancel }) as AckingStream)
            }) as BoxFuture<'static, Result<AckingStream>>
        })
    }

    /// FIX 3 (explicit cohort freeze): a waiter joining AFTER the cohort is frozen
    /// (the driver has read `min_cadence` at the `Collecting -> Opening`
    /// transition) is a later-joiner and cannot lower the cadence. Verified both on
    /// the frozen `OpeningInner` and on the cadence the factory was handed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn later_joiner_after_freeze_does_not_change_cadence() {
        let hub = WatchCoalescer::new();
        let recorded = Arc::new(Mutex::new(None));
        let entered = CancellationToken::new();
        let gate = CancellationToken::new();
        let upstream = gated_cadence_upstream(recorded.clone(), entered.clone(), gate.clone());

        // First subscriber: slow cadence. The driver freezes the cohort at 200ms
        // and invokes the factory, which parks at the gate.
        let slow = Duration::from_millis(200);
        let a = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), slow, None, upstream)
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.cancelled())
            .await
            .expect("the factory must be invoked (cohort frozen)");

        // A later joiner with a much smaller cadence joins AFTER the freeze.
        let fast = Duration::from_millis(1);
        let b = {
            let hub = hub.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                hub.subscribe(key("k"), prefix(), opts(), fast, None, upstream)
                    .await
            })
        };
        // Let the joiner register as a waiter, then inspect the frozen cohort.
        wait_until(
            || {
                let reg = hub.registry.lock().unwrap();
                matches!(reg.get(&key("k")), Some(KeyState::Opening(o))
                    if o.inner.lock().unwrap().waiters == 2)
            },
            "the later joiner to register as the second waiter",
        )
        .await;
        {
            let reg = hub.registry.lock().unwrap();
            let Some(KeyState::Opening(opening)) = reg.get(&key("k")) else {
                panic!("expected an in-flight Opening");
            };
            let inner = opening.inner.lock().unwrap();
            assert!(
                inner.frozen,
                "the cohort must be frozen once the factory is invoked"
            );
            assert_eq!(
                inner.min_cadence, slow,
                "a later joiner must not lower the frozen cadence"
            );
        }

        // Release the open and confirm the factory was handed the frozen cadence.
        gate.cancel();
        let _a = a.await.unwrap().expect("A subscribes");
        let _b = b.await.unwrap().expect("B subscribes");
        assert_eq!(
            *recorded.lock().unwrap(),
            Some(slow),
            "the factory must receive the frozen (pre-join) cadence"
        );
        hub.cancel_all();
    }

    /// Publication race (orphaned-upstream leak): if the final waiter's
    /// `subscribe` future is aborted in the `Opening -> Live` publication window,
    /// no waiter ever attaches and the completed fan-out is dropped unattached.
    /// The `WatchDirectoryFanout` `Drop` backstop must still cancel the physical
    /// upstream token, so the adopter's producer stops instead of leaking a
    /// competing consumer. Asserted deterministically via the observable
    /// guarantee: a completed-but-unwaited fan-out cancels its token on drop.
    #[tokio::test]
    async fn publication_race_aborted_last_waiter_cancels_upstream() {
        let torn = Arc::new(AtomicBool::new(false));
        // The physical upstream cancel token the adopter's producer wires in.
        let upstream_token = CancellationToken::new();
        let stream: AckingStream = Box::new(ScriptedStream {
            events: Vec::new().into_iter(),
            cancel: upstream_token.clone(),
            keep_alive: true,
            torn_down: torn.clone(),
        });
        let fanout = WatchDirectoryFanout::new(stream, upstream_token.clone());
        assert!(
            !upstream_token.is_cancelled(),
            "the upstream token must be live before the fan-out drops"
        );

        // No waiter ever attaches (the last waiter aborted around publication);
        // the fan-out is dropped unwaited.
        drop(fanout);

        assert!(
            upstream_token.is_cancelled(),
            "dropping a completed-but-unwaited fan-out must cancel its upstream token"
        );
        assert!(
            torn.load(Ordering::SeqCst),
            "the discarded upstream stream must be dropped"
        );
    }

    /// A cancelled subscriber must stop even while its queue is saturated. Under
    /// sustained flow the receiver's `try_recv` returns `Ok` on every pull and
    /// never reaches the `Empty` arm, so a cancel observed only in that arm would
    /// never fire and the subscriber would yield forever (a broker shutdown
    /// hanging through an event storm). Fails against the pre-fix code that
    /// checks cancellation only on `Empty`: there the full queue keeps handing
    /// back `Some(item)`.
    #[test]
    fn cancelled_receiver_stops_under_saturated_queue() {
        let (tx, rx) = mpsc::sync_channel::<Result<BackendChangeEvent>>(QUEUE_DEPTH);
        // Saturate the queue so `try_recv` always returns `Ok` (never `Empty`).
        for i in 0..QUEUE_DEPTH {
            tx.try_send(object_event(i))
                .expect("fill the subscriber queue");
        }
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut receiver = WatcherReceiver {
            inner: rx,
            fanout: Weak::<WatchDirectoryFanout>::new(),
            cancel: Some(cancel),
            id: 0,
            gap: Arc::new(AtomicBool::new(false)),
            terminal: Arc::new(Mutex::new(None)),
        };
        // The sender stays alive (channel never disconnects), so the only exit is
        // the top-of-loop cancel check.
        assert!(
            receiver.next().is_none(),
            "a cancelled subscriber must return None even with a full queue"
        );
        drop(tx);
    }

    /// Cancel wins over a pending overflow gap: a cancelled receiver whose gap
    /// flag is raised returns `None` immediately, never one last `Lapsed` before
    /// teardown. Fails against the check-`take_gap_lapsed`-first ordering, which
    /// would surface the gap `Lapsed` ahead of the cancel `None`.
    #[test]
    fn cancelled_receiver_with_pending_gap_returns_none() {
        let (tx, rx) = mpsc::sync_channel::<Result<BackendChangeEvent>>(QUEUE_DEPTH);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut receiver = WatcherReceiver {
            inner: rx,
            fanout: Weak::<WatchDirectoryFanout>::new(),
            cancel: Some(cancel),
            id: 0,
            // A gap is pending: check-lapsed-first would emit a `Lapsed` here.
            gap: Arc::new(AtomicBool::new(true)),
            terminal: Arc::new(Mutex::new(None)),
        };
        assert!(
            receiver.next().is_none(),
            "a cancelled subscriber with a raised gap must return None, not Lapsed"
        );
        drop(tx);
    }
}
