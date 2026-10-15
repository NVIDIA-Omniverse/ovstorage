// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commit-ordered event emission.
//!
//! An event that implies an order — `Added` before `Removed`, a delta against a
//! rule set — is correctly ordered only if it is sent inside the same critical
//! section that commits the state change it describes. Send it after the guard
//! drops and a concurrent committer interleaves, so subscribers observe an order
//! the committed state never had. Worse, a *decision* about what to emit that is
//! read under a different lock from the one ordering the commit is not atomic
//! with the commit either, so two racing mutations can each conclude the other
//! will emit and neither does.
//!
//! Three instances of that shape were found by review, one at a time, and each
//! fix was a convention the next edit could silently break. This module makes
//! the class unwritable instead.
//!
//! ## The shape of the guarantee
//!
//! [`Ordered`] owns the guarded state **and** the channel its commits are
//! reported on, as one value. [`Ordered::commit`] takes the write guard and
//! hands the closure an [`Emit`] — and an `Emit` is not a *token* that some
//! channel then chooses to trust, it is a borrow of *this* `Ordered`'s own
//! sender. There is no channel-selection step to get wrong:
//!
//! - It cannot be constructed outside this module (private field).
//! - It cannot be aimed at a different channel, because it carries the sender
//!   rather than describing one. An earlier design branded the token with a type
//!   tag; two locks sharing a tag then minted interchangeable tokens, so the
//!   guarantee held only as long as nobody reused the tag. Carrying the sender
//!   removes the failure mode instead of documenting it.
//! - It cannot outlive the section, because the closure's return type cannot
//!   capture the higher-ranked borrow it is handed.
//!
//! An emit on an [`Ordered`]'s channel that is not under the ordering guard
//! therefore fails to compile. The deferred line described below relaxes *when*
//! a send may happen, never *what* orders it.
//!
//! ## The deliberate exception
//!
//! Merging two independent producers (`futures::stream::select(local, inner)`)
//! is order-free by construction and must stay that way: no guard can promise
//! cross-source order between producers that never share one. Such a stream is
//! keyed upsert/delete on the consumer side. The exemption is scoped to the
//! merge and not to either half: the local producer's own emissions are still
//! guarded by an [`Ordered`] or a [`Sequenced`], and what nothing on this side
//! can sequence is only the interleave against the other source. State that at
//! the channel, rather than leaving it as a silent exception to an otherwise
//! enforced rule.
//!
//! ## Sending under a lock
//!
//! [`Emit::send`] runs inside a synchronous critical section, so the wrapped
//! sender must never block or await. [`Emitter`] is the contract for that: an
//! implementation must complete without waiting on a consumer. A
//! `tokio::sync::broadcast::Sender` qualifies — it overwrites the oldest queued
//! item and signals lag rather than applying backpressure. An unbounded
//! `mpsc::UnboundedSender` qualifies. A bounded `mpsc::Sender` does not.
//!
//! The same requirement holds on the deferred channel for a different reason:
//! a deferred send runs while its [`Turn`] is held, and a sender that waited on
//! a consumer would hold the line rather than the lock.
//!
//! ## When the report needs an await
//!
//! [`Ordered`] covers the case where the decision and the emission are both
//! synchronous. Everything the event says is already in hand under the guard,
//! so the send happens there and the lock is the whole ordering argument.
//!
//! That argument fails the moment part of what you report must be asked of a
//! layer below. Asking is an `await`, an `await` cannot happen under the guard,
//! so the send cannot happen there either — and the lock stops ordering
//! anything. [`Sequenced`] is for exactly that shape: it keeps the in-guard
//! channel [`Ordered`] already provides and adds a second, deferred one whose
//! order is carried by a ticket stamped under the guard rather than by the
//! guard itself. Reach for it when, and only when, computing what you report
//! requires an await. A producer that never awaits gains nothing from it.
//!
//! `ConnectionSet` is the worked example of the other answer, and it stays on
//! [`Ordered`] deliberately. Its membership decision and the event describing
//! it are both synchronous, so a ticket would be pure cost — the machinery, and
//! the coupling it introduces. A ticket line makes each event wait on every
//! earlier one; its membership events are ordered by the lock alone, and no
//! wedged inner layer can delay them. Putting them behind a turn would hand an
//! inner layer that power in exchange for an ordering it already has.
//!
//! ### What the ticket line guarantees
//!
//! Three invariants carry the deferred half. Each item below is a consequence
//! of one of them rather than a rule of its own.
//!
//! - **Ticket order is commit order.** Stamping happens in [`Commit::defer`],
//!   which exists only inside the write guard. A ticket taken after the guard
//!   released would let two commits line up in the opposite order to the state
//!   changes they describe.
//! - **The retirement obligation transfers exactly once.** A [`Deferred`]
//!   carries it until [`Deferred::take`] moves it to the [`Turn`], and exactly
//!   one of the two discharges it by dropping. Discharging twice runs the
//!   frontier past a predecessor that is still live; discharging never parks
//!   every later ticket for the life of the owner. Publishing consumes the
//!   `Turn`, so a turn that emits discharges at the end of its send — after the
//!   batch is out — and a turn that emits nothing discharges when the caller
//!   drops it. Both are the same one drop.
//! - **The published frontier advances only across a contiguous run of retired
//!   tickets.** It never reaches a retired ticket that still has an unretired
//!   one before it. Advancing to the highest retired ticket instead would
//!   release a waiter while its predecessor is still running, and the two would
//!   then sample concurrently.
//!
//! ### The turn is taken before the sampling
//!
//! Before the sampling, not merely before the sends. Each deferred job samples
//! the lower layer for itself, so ordering the emissions alone leaves the
//! samples racing: ticket 1 can sample, stall, and publish first while ticket 2
//! sampled a newer state — two deltas that no longer telescope. A consumer
//! applying them as upsert/delete without resnapshotting then holds a state the
//! committed one never had, and nothing afterwards corrects it. Holding the
//! [`Turn`] across both the sample and the send makes them one indivisible
//! step; see [`Deferred::take`].
//!
//! The publication at the end of that step is one batch, and the signature says
//! so: [`Turn::send_all`] consumes the turn. A delta split across two sends
//! would take its admission decision twice, so an owner going away between them
//! tears the delta in half — additions published, removals dropped. Consuming
//! the turn is the same move [`Commit::defer`] makes to keep one commit to one
//! position in line.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};

use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::{broadcast, mpsc, watch};

/// Seals [`Emitter`]. An outside implementation could expose or retain the
/// channel it wraps, which would reintroduce an unguarded path to the very
/// sender [`Ordered`] exists to protect. New channel kinds are added here, next
/// to a constructor that creates the channel rather than accepting one.
mod sealed {
    pub trait Sealed {}
    impl<T: Clone> Sealed for tokio::sync::broadcast::Sender<T> {}
    impl<T> Sealed for tokio::sync::mpsc::UnboundedSender<T> {}
}

/// A sender that completes an emission without blocking or awaiting.
///
/// Implement this only for senders that apply no backpressure: [`Emit::send`]
/// runs inside a synchronous critical section, so a sender that waits on a
/// consumer would hold the ordering guard for as long as the slowest subscriber
/// takes to drain. Dropping or lagging an event is the correct behaviour there;
/// waiting is not.
pub trait Emitter: sealed::Sealed {
    /// The event this sender carries.
    type Event;

    /// A handle that names this channel without keeping it open.
    ///
    /// [`Deferred`] carries one across an await. A strong clone would keep the
    /// channel open for as long as a ticket is outstanding, so a consumer
    /// draining to EOF would never finish — the whole point of the module's
    /// "the only sender in existence is the one this value owns" rule.
    ///
    /// `Clone` because [`Deferred`] hands its handle to [`Turn`] during
    /// retirement transfer, and neither type can be destructured by move: both
    /// implement [`Drop`].
    type Weak: Clone;

    /// Emit `event`, discarding the "no subscribers" / "lagged" outcome — a
    /// commit is not conditional on anyone listening.
    fn emit(&self, event: Self::Event);

    /// A handle that names this channel without holding it open.
    fn downgrade(&self) -> Self::Weak;

    /// The sender again, or `None` once every strong sender is gone.
    ///
    /// A successful upgrade is the admission point for a deferred send: see
    /// [`Turn::send`].
    fn upgrade(weak: &Self::Weak) -> Option<Self>
    where
        Self: Sized;
}

/// `broadcast` overwrites its oldest queued item and reports the loss to the
/// receiver as lag, so a send completes without waiting on any subscriber.
impl<T: Clone> Emitter for broadcast::Sender<T> {
    type Event = T;
    type Weak = broadcast::WeakSender<T>;

    fn emit(&self, event: T) {
        let _ = self.send(event);
    }

    fn downgrade(&self) -> Self::Weak {
        broadcast::Sender::downgrade(self)
    }

    fn upgrade(weak: &Self::Weak) -> Option<Self> {
        weak.upgrade()
    }
}

/// An unbounded `mpsc` never applies backpressure, so a send completes without
/// waiting on the receiver.
impl<T> Emitter for mpsc::UnboundedSender<T> {
    type Event = T;
    type Weak = mpsc::WeakUnboundedSender<T>;

    fn emit(&self, event: T) {
        let _ = self.send(event);
    }

    fn downgrade(&self) -> Self::Weak {
        mpsc::UnboundedSender::downgrade(self)
    }

    fn upgrade(weak: &Self::Weak) -> Option<Self> {
        weak.upgrade()
    }
}

/// The capability to emit on one specific channel, valid only inside the commit
/// section that produced it.
///
/// This is a borrow of the owning [`Ordered`]'s sender, not a certificate that a
/// channel validates. That is what makes "emit on the wrong channel"
/// unrepresentable rather than merely discouraged.
pub struct Emit<'commit, S> {
    /// Private: the only source is [`Ordered::commit`], and the only thing that
    /// can be done with one is [`Emit::send`].
    tx: &'commit S,
}

impl<S: Emitter> Emit<'_, S> {
    /// Emit `event` on the channel this capability came from.
    pub fn send(&self, event: S::Event) {
        self.tx.emit(event);
    }
}

/// State guarded by a write lock, together with the channel on which its commits
/// are reported.
///
/// Binding them into one value is the point: the lock that orders the state and
/// the channel that describes it cannot drift apart, and no call site chooses
/// which channel a guard authorises.
///
/// ```
/// use ovstorage_layer::ordered::Ordered;
///
/// let state = Ordered::broadcast(0u32, 8);
/// let mut rx = state.subscribe();
///
/// // The mutation and the event describing it are one critical section.
/// state.commit(|value, emit| {
///     *value += 1;
///     emit.send(*value);
/// });
/// assert_eq!(rx.try_recv().unwrap(), 1);
/// ```
pub struct Ordered<T, S> {
    lock: Arc<RwLock<T>>,
    tx: S,
}

impl<T, S> Ordered<T, S> {
    /// Private on purpose. A public constructor taking a caller-supplied sender
    /// hands the caller a retained handle to the channel, and `tx.send(..)` on
    /// that handle needs no guard at all — the exact spelling this module exists
    /// to remove. Every public constructor below *creates* the channel, so the
    /// only sender in existence is the one this value owns.
    fn new(value: T, tx: S) -> Self {
        Self {
            lock: Arc::new(RwLock::new(value)),
            tx,
        }
    }

    /// Read the guarded state. Reading commits nothing, so it grants no
    /// emission capability.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.lock.read()
    }

    /// A read-only handle to the state, carrying no sender.
    ///
    /// For closures that outlive this value. Cloning the whole `Ordered` would
    /// carry its sender too, so a merged stream built over one would never see
    /// its local half close and a consumer draining to EOF would hang.
    pub fn read_handle(&self) -> ReadHandle<T> {
        ReadHandle {
            lock: Arc::clone(&self.lock),
        }
    }

    /// Take the write guard for a mutation that reports nothing.
    ///
    /// Prefer [`Self::commit`]. This exists for the mutations that genuinely
    /// emit no event; it deliberately hands back no [`Emit`].
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.lock.write()
    }

    /// Take the write guard and run `f` with the guarded state and the
    /// capability to emit on this value's channel.
    ///
    /// `f` must not block, await, or re-enter this lock — `parking_lot` guards
    /// are not reentrant and the guard is held for the whole call.
    ///
    /// The capability cannot escape the section, because `R` is fixed by the
    /// caller and the `Emit` borrow it is handed is higher-ranked:
    ///
    /// ```compile_fail
    /// use ovstorage_layer::ordered::{Emit, Ordered};
    ///
    /// let state = Ordered::broadcast(0u32, 8);
    /// let mut escaped: Option<&Emit<'_, tokio::sync::broadcast::Sender<u32>>> = None;
    /// state.commit(|_value, emit| escaped = Some(emit));
    /// ```
    ///
    /// Nor can one be built from scratch, because the field is private:
    ///
    /// ```compile_fail
    /// use ovstorage_layer::ordered::Emit;
    ///
    /// let (tx, _rx) = tokio::sync::broadcast::channel::<u32>(8);
    /// let forged = Emit { tx: &tx };
    /// forged.send(1);
    /// ```
    ///
    /// And the channel cannot be supplied by the caller, so no retained handle
    /// to it can exist. Constructing an `Ordered` over a sender you keep — and
    /// then emitting on that sender with no guard held — does not compile:
    ///
    /// ```compile_fail
    /// use ovstorage_layer::ordered::Ordered;
    ///
    /// let (tx, _rx) = tokio::sync::broadcast::channel::<u32>(8);
    /// let _state = Ordered::new(0u32, tx.clone());
    /// tx.send(1u32); // unguarded emission on the very channel `_state` orders
    /// ```
    ///
    /// Nor can two `Ordered` values be built over one sender:
    ///
    /// ```compile_fail
    /// use ovstorage_layer::ordered::Ordered;
    ///
    /// let (tx, _rx) = tokio::sync::broadcast::channel::<u32>(8);
    /// let _a = Ordered::new(0u32, tx.clone());
    /// let _b = Ordered::new(0u32, tx.clone());
    /// ```
    pub fn commit<R>(&self, f: impl FnOnce(&mut T, &Emit<'_, S>) -> R) -> R {
        let mut guard = self.lock.write();
        let emit = Emit { tx: &self.tx };
        f(&mut guard, &emit)
    }
}

impl<T, E: Clone> Ordered<T, broadcast::Sender<E>> {
    /// Guard `value`, reporting its commits on a fresh `broadcast` channel of
    /// `capacity`.
    pub fn broadcast(value: T, capacity: usize) -> Self {
        Self::new(value, broadcast::channel(capacity).0)
    }

    /// Subscribe to the commit channel. Subscribing establishes no order.
    pub fn subscribe(&self) -> broadcast::Receiver<E> {
        self.tx.subscribe()
    }
}

impl<T, E> Ordered<T, mpsc::UnboundedSender<E>> {
    /// Guard `value`, reporting its commits on a fresh unbounded `mpsc`.
    ///
    /// The receiver is returned because only the caller can hold it; the sender
    /// stays owned by this value and is never handed out.
    pub fn unbounded(value: T) -> (Self, mpsc::UnboundedReceiver<E>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self::new(value, tx), rx)
    }
}

/// Ordering state for a deferred channel: which ticket runs next, and whether
/// the owner is gone.
///
/// Owns no sender, so a handle may hold this strongly without keeping any
/// channel open. That split is what lets a parked ticket both (a) be woken
/// when the owner drops and (b) still fail to emit, which are different
/// questions with different answers.
struct TicketOrder {
    /// Handed out under the write guard. Tickets are 1-based: the counter
    /// starts at 0 and `stamp` adds one, which keeps the overflow check on the
    /// increment rather than on a counter that has nowhere to report it.
    next: AtomicU64,
    /// The highest ticket that has retired with every earlier ticket already
    /// retired. Starts at 0, so ticket 1 never waits.
    frontier: watch::Sender<u64>,
    /// Tickets retired out of order, waiting for the frontier to reach them.
    pending: Mutex<BTreeSet<u64>>,
    /// Set by `Sequenced::drop`. Published through `frontier` so a ticket
    /// parked behind a still-live predecessor wakes: closing the event channel
    /// alone would leave it blocked forever.
    closed: AtomicBool,
}

impl TicketOrder {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            frontier: watch::channel(0).0,
            pending: Mutex::new(BTreeSet::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// Called only from `Commit::defer`, i.e. only under the write guard, which
    /// is what makes ticket order equal commit order.
    fn stamp(&self) -> u64 {
        // One ticket per mutation cannot exhaust a u64, but a wrapped ticket
        // would park every later notification behind a predecessor that can
        // never arrive, so fail loudly rather than as a silent stall.
        self.next
            .fetch_add(1, AtomicOrdering::Relaxed)
            .checked_add(1)
            .expect("the deferred-ordering ticket counter overflowed a u64")
    }

    /// Release `ticket`, advancing the published frontier across every
    /// contiguously retired ticket.
    ///
    /// Advancing to the maximum retired ticket instead would let a ticket that
    /// retires early — a `Deferred` dropped without ever being awaited — carry
    /// the frontier past a predecessor that is still running, and the ticket
    /// behind it would then sample concurrently with that predecessor.
    fn retire(&self, ticket: u64) {
        let mut pending = self.pending.lock();
        self.frontier.send_if_modified(|frontier| {
            // A ticket at or below the frontier has already been released. It
            // would be inserted into `pending` below and never removed, since
            // absorption only ever probes above the frontier — a silent leak
            // and a broken invariant. The `armed` discipline makes it
            // unreachable; assert rather than let a future caller reintroduce
            // it quietly.
            debug_assert!(
                ticket > *frontier,
                "ticket {ticket} retired at or below the frontier {frontier}: retired twice?"
            );
            if ticket != *frontier + 1 {
                // Out of order: record it, and let the predecessor absorb it.
                pending.insert(ticket);
                return false;
            }
            let mut reached = ticket;
            while pending.remove(&(reached + 1)) {
                reached += 1;
            }
            *frontier = reached;
            true
        });
    }

    /// Wake every parked ticket; grant no further turns once this is observed.
    ///
    /// Not a barrier: a `take` that has already passed its check can still be
    /// granted, and its turn can still publish, because the owner's sender
    /// fields outlive this call. See [`Turn::send`] for why that boundary is
    /// deliberately one-sided.
    fn close(&self) {
        self.closed.store(true, AtomicOrdering::Release);
        // Wake the waiters; the value is irrelevant, `closed` is the signal.
        self.frontier.send_modify(|_| {});
    }

    fn is_closed(&self) -> bool {
        self.closed.load(AtomicOrdering::Acquire)
    }

    /// Resolve once every earlier ticket has retired. `false` if the owner went
    /// away first, in which case no turn is granted.
    async fn wait_for(&self, ticket: u64) -> bool {
        let mut rx = self.frontier.subscribe();
        loop {
            if self.is_closed() {
                return false;
            }
            // `borrow_and_update` marks the current value seen, which is what
            // closes the gap between the check and the wait: with a plain
            // `borrow`, a retirement landing in that gap would leave `changed`
            // waiting for a notification that had already been sent, and this
            // ticket would park behind a predecessor that has already gone.
            if *rx.borrow_and_update() >= ticket - 1 {
                return true;
            }
            // Re-check AFTER consuming the notification. `close` publishes
            // through this same watch, so a close landing between the check
            // above and `borrow_and_update` has its notification consumed
            // here — and the `changed` below would then wait for a wake that
            // has already happened, stranding this ticket for the life of the
            // process.
            if self.is_closed() {
                return false;
            }
            if rx.changed().await.is_err() {
                // The sender lives in this value, which every handle holds
                // strongly, so this is unreachable while a handle exists.
                return false;
            }
        }
    }
}

/// A read-only handle to the guarded state that carries no sender.
///
/// For closures that outlive the owner. A clone of the whole [`Sequenced`]
/// would carry its senders too, so a merged stream built over one would never
/// see its local half close, and a consumer draining to EOF would hang.
pub struct ReadHandle<T> {
    lock: Arc<RwLock<T>>,
}

impl<T> Clone for ReadHandle<T> {
    fn clone(&self) -> Self {
        Self {
            lock: Arc::clone(&self.lock),
        }
    }
}

impl<T> ReadHandle<T> {
    /// Read the guarded state. Reading commits nothing, so it grants no
    /// emission capability.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.lock.read()
    }
}

/// State guarded by one write lock, reported on two channels: one sent inside
/// the guard, one deferred to a ticketed turn.
///
/// [`Ordered`] covers the single-channel case. This exists for the consumer
/// that has to compute part of its notification by asking a layer below —
/// which needs an `await`, which cannot happen under a lock. Such a consumer
/// takes a ticket under the guard, releases the guard, then waits its turn
/// before doing the async work, so ticket order is commit order even though
/// the work is not.
///
/// `P` is the in-guard (primary) channel; `D` is the deferred one.
pub struct Sequenced<T, P, D> {
    /// The lock and the in-guard channel, and the single implementation of
    /// "emission happens under the guard". This type only ADDS the deferred
    /// line; it does not restate that rule.
    inner: Ordered<T, P>,
    deferred: D,
    order: Arc<TicketOrder>,
}

impl<T, P, D> Sequenced<T, P, D> {
    fn new(inner: Ordered<T, P>, deferred: D) -> Self {
        Self {
            inner,
            deferred,
            order: Arc::new(TicketOrder::new()),
        }
    }

    /// Read the guarded state. Reading commits nothing, so it grants no
    /// emission capability.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read()
    }

    /// A read-only handle carrying no sender, for closures that outlive this
    /// value.
    pub fn read_handle(&self) -> ReadHandle<T> {
        self.inner.read_handle()
    }

    /// Take the write guard for a mutation that reports nothing.
    ///
    /// Prefer [`Self::commit`]. This exists for mutations that genuinely emit
    /// no event; it deliberately hands back no capability.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.inner.write()
    }

    /// Mutate the state and report it, under the write guard.
    ///
    /// `f` must not block, await, or re-enter this lock: `parking_lot` guards
    /// are not reentrant and the guard is held for the whole call.
    ///
    /// The [`Commit`] is passed by value because [`Commit::defer`] consumes it,
    /// which is what limits a commit to one ticket. `R` is caller-chosen, so an
    /// owned [`Deferred`] can leave the section while the borrow-carrying
    /// `Commit` cannot.
    pub fn commit<R>(&self, f: impl FnOnce(&mut T, Commit<'_, P, D>) -> R) -> R {
        let deferred = &self.deferred;
        let order = &self.order;
        self.inner.commit(move |value, emit| {
            f(
                value,
                Commit {
                    emit,
                    deferred,
                    order,
                },
            )
        })
    }
}

impl<T, P, D> Drop for Sequenced<T, P, D> {
    fn drop(&mut self) {
        // Closing the event channels happens implicitly when the sender fields
        // drop, but that does not wake a ticket parked behind a live
        // predecessor — its wait is on the frontier, not on the channel.
        self.order.close();
    }
}

impl<T, PE: Clone, DE: Clone> Sequenced<T, broadcast::Sender<PE>, broadcast::Sender<DE>> {
    /// Guard `value`, creating BOTH channels.
    ///
    /// There is no constructor taking a sender: a caller-supplied sender is a
    /// retained handle to the channel, and a send on it needs no guard at all.
    pub fn broadcast(value: T, primary_capacity: usize, deferred_capacity: usize) -> Self {
        Self::new(
            Ordered::broadcast(value, primary_capacity),
            broadcast::channel(deferred_capacity).0,
        )
    }

    /// Subscribe to the in-guard channel. Subscribing establishes no order.
    pub fn subscribe_primary(&self) -> broadcast::Receiver<PE> {
        self.inner.subscribe()
    }

    /// Subscribe to the deferred channel. Subscribing establishes no order.
    pub fn subscribe_deferred(&self) -> broadcast::Receiver<DE> {
        self.deferred.subscribe()
    }
}

impl<T, PE, DE> Sequenced<T, mpsc::UnboundedSender<PE>, mpsc::UnboundedSender<DE>> {
    /// Guard `value`, creating both channels as unbounded `mpsc`.
    ///
    /// The receivers are returned because only the caller can hold them; the
    /// senders stay owned by this value and are never handed out.
    pub fn unbounded(
        value: T,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<PE>,
        mpsc::UnboundedReceiver<DE>,
    ) {
        let (inner, primary_rx) = Ordered::unbounded(value);
        let (deferred_tx, deferred_rx) = mpsc::unbounded_channel();
        (Self::new(inner, deferred_tx), primary_rx, deferred_rx)
    }
}

/// The capability to report a commit. Exists only inside
/// [`Sequenced::commit`], and therefore only under the write guard.
pub struct Commit<'commit, P, D> {
    /// The in-guard capability, from the inner [`Ordered`]. Carrying it rather
    /// than a second borrow of the sender keeps one definition of what an
    /// in-guard send is.
    emit: &'commit Emit<'commit, P>,
    deferred: &'commit D,
    order: &'commit Arc<TicketOrder>,
}

impl<P: Emitter, D: Emitter> Commit<'_, P, D> {
    /// Report on the in-guard channel, ordered by the lock alone.
    pub fn send(&self, event: P::Event) {
        self.emit.send(event);
    }

    /// Stamp this commit's position and return an owned handle to it.
    ///
    /// The only way to mint one, and it consumes the `Commit`, so one commit
    /// takes at most one position in line. Sends may precede it.
    ///
    /// Stamping happens here — under the guard — which is what makes ticket
    /// order equal commit order. A ticket taken after the guard released would
    /// let two commits stamp in the opposite order to the swaps they describe.
    ///
    /// One commit cannot take two positions, because the first `defer` moves
    /// the `Commit`:
    ///
    /// The `E0382` annotation records the error this is *meant* to produce, but
    /// it does not enforce it: on stable rustdoc accepts a `compile_fail` block
    /// that fails for any reason at all, verified here by swapping the code for
    /// a nonexistent `E0999` and watching the test still pass. So this block is
    /// weak evidence on its own — the guarantee is carried by `defer` taking
    /// `self`, and the example below is the half that would break loudly if the
    /// signature stopped allowing send-then-defer.
    ///
    /// ```compile_fail,E0382
    /// use ovstorage_layer::ordered::Sequenced;
    /// use tokio::sync::mpsc::UnboundedSender;
    ///
    /// let (state, _primary, _deferred) =
    ///     Sequenced::<u32, UnboundedSender<u32>, UnboundedSender<u32>>::unbounded(0);
    /// state.commit(|_value, commit| {
    ///     let _first = commit.defer();
    ///     let _second = commit.defer(); // `commit` was moved by the first call
    /// });
    /// ```
    ///
    /// Sending first and then deferring is fine, and is the expected order:
    ///
    /// ```
    /// use ovstorage_layer::ordered::Sequenced;
    /// use tokio::sync::mpsc::UnboundedSender;
    ///
    /// let (state, mut primary, _deferred) =
    ///     Sequenced::<u32, UnboundedSender<u32>, UnboundedSender<u32>>::unbounded(0);
    /// let ticket = state.commit(|value, commit| {
    ///     *value += 1;
    ///     commit.send(7);
    ///     commit.defer()
    /// });
    /// assert_eq!(primary.try_recv(), Ok(7));
    /// assert_eq!(ticket.ticket(), 1);
    /// ```
    pub fn defer(self) -> Deferred<D> {
        Deferred {
            ticket: self.order.stamp(),
            order: Arc::clone(self.order),
            weak: self.deferred.downgrade(),
            armed: true,
        }
    }
}

/// A stamped position in line, waiting to be taken.
///
/// Owned and `'static`, so it can move into a detached task — the real call
/// site cannot hold a borrow of the wrapper across its await.
///
/// Carries the retirement obligation until [`Self::take`] moves it to the
/// [`Turn`]. At most one of the two discharges it: `mem::forget` on either is
/// safe Rust and would stall every later ticket for the life of the owner, so
/// let them drop normally.
pub struct Deferred<D: Emitter> {
    ticket: u64,
    order: Arc<TicketOrder>,
    weak: D::Weak,
    armed: bool,
}

impl<D: Emitter> Deferred<D> {
    /// This commit's position, for diagnostics.
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Wait for every earlier ticket to retire, then take the turn.
    ///
    /// Sampling must happen *after* this resolves, not merely before the sends.
    /// Each deferred job samples the lower layer for itself, so ordering the
    /// emissions alone is not enough: if ticket 1 sampled early and then
    /// stalled, ticket 2 could sample a NEWER state and still be published
    /// second, so the two deltas no longer telescope. The consumer above
    /// applies them as upsert/delete without resnapshotting, and nothing
    /// afterwards corrects it. Holding the turn across the sample is what makes
    /// the sample and the send one indivisible step.
    ///
    /// `None` once the owner is gone. The ticket is retired by dropping `self`
    /// still armed — never by an explicit call here, which would retire again
    /// when `self` drops at the end of this function.
    pub async fn take(mut self) -> Option<Turn<D>> {
        if !self.order.wait_for(self.ticket).await {
            return None;
        }
        // Transfer the obligation. Neither type can be destructured by move, so
        // build the `Turn` from clones first and disarm LAST: if anything
        // between the two could unwind, a disarmed `Deferred` would drop
        // without retiring and stall every later ticket permanently.
        let turn = Turn {
            ticket: self.ticket,
            order: Arc::clone(&self.order),
            weak: self.weak.clone(),
            armed: true,
        };
        self.armed = false;
        Some(turn)
    }
}

impl<D: Emitter> Drop for Deferred<D> {
    fn drop(&mut self) {
        if self.armed {
            self.order.retire(self.ticket);
        }
    }
}

/// The right to run one sample-and-send, held across the whole of it.
///
/// Publishing consumes it, so one turn publishes exactly one batch and a second
/// send from the same turn has no spelling — the same shape as [`Commit::defer`]
/// taking `self` to keep one commit to one position in line. Assemble the whole
/// batch first and hand it to [`Self::send_all`].
///
/// Dropping it lets the next ticket run, so hold it until the sample and the
/// send for this commit are both done. A turn that decides to emit nothing is
/// simply dropped.
pub struct Turn<D: Emitter> {
    ticket: u64,
    order: Arc<TicketOrder>,
    weak: D::Weak,
    armed: bool,
}

impl<D: Emitter> Turn<D> {
    /// This commit's position, for diagnostics.
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Report a single event on the deferred channel, ending this turn.
    ///
    /// The one-element case of [`Self::send_all`], with the same linearity: it
    /// consumes the turn, so a caller that discovers a second event to send has
    /// to go back and build the batch rather than sending again. Keeping it is
    /// what lets a bail-out path — report one thing and return — stay a single
    /// line.
    ///
    /// A successful upgrade is this send's admission point, and that boundary is
    /// deliberately NOT synchronous with the owner's drop.
    ///
    /// Upgrading takes a strong sender for the duration of the call, so it
    /// races the owner's drop rather than excluding it: the upgrade can win,
    /// the owner can then drop, and this event still publishes afterwards.
    /// Making that impossible would need the send and the owner's drop to share
    /// a lock, which would put a lock acquisition on every emission to buy a
    /// guarantee no consumer asks for — a subscriber cannot tell "published
    /// just before the owner went away" from "just after".
    ///
    /// So the guarantee is one-sided, and it is the one that matters: a send
    /// that has *not* upgraded by the time the last strong sender is gone is
    /// dropped rather than published. Do not write this as "owner drop cancels
    /// every not-yet-sent event" — that is a race, not a contract, and a
    /// single-threaded test would pass while observing nothing about it.
    pub fn send(self, event: D::Event) {
        self.send_all(std::iter::once(event));
    }

    /// Report a batch, upgrading once for the whole of it, and end this turn.
    ///
    /// One turn publishes one batch, and the signature is the whole enforcement:
    /// consuming `self` leaves a second emission from the same turn with no
    /// spelling. Emitting a multi-event delta as separate sends would upgrade
    /// per event, so the owner could go away between two events of one delta and
    /// the later ones would be discarded while the earlier ones are already out.
    /// A subscriber that sees a delta's additions without its removals holds a
    /// state the committed one never had, and a consumer that applies deltas as
    /// upsert/delete without resnapshotting has nothing to correct it with.
    ///
    /// Holding the upgraded sender across the batch makes the whole batch share
    /// one admission point: either the turn upgraded before the last strong
    /// sender went away, in which case every event in the batch is published, or
    /// it did not, in which case none is.
    ///
    /// Retirement stays exactly once, and stays after the batch: `self` is not
    /// destructured — [`Turn`] implements [`Drop`] — so it drops at the end of
    /// this call, once every event is out, and its `Drop` retires the ticket
    /// there exactly as it does for a turn that emits nothing. Retiring inside
    /// this method instead would release the next ticket while this one is still
    /// publishing.
    ///
    /// A second batch from one turn does not compile:
    ///
    /// ```compile_fail,E0382
    /// use ovstorage_layer::ordered::Sequenced;
    /// use tokio::sync::mpsc::UnboundedSender;
    ///
    /// let (state, _primary, _deferred) =
    ///     Sequenced::<u32, UnboundedSender<u32>, UnboundedSender<u32>>::unbounded(0);
    /// let ticket = state.commit(|_value, commit| commit.defer());
    /// futures::executor::block_on(async {
    ///     let turn = ticket.take().await.expect("ticket 1 never waits");
    ///     turn.send_all([1, 2]);
    ///     turn.send_all([3]); // `turn` was moved by the first call
    /// });
    /// ```
    ///
    /// What that block proves and what it does not: rustdoc accepts a
    /// `compile_fail` block that fails to build for *any* reason, and the
    /// `E0382` annotation is not enforced on this toolchain — swapping it for a
    /// nonexistent `E0999` leaves the test passing, measured rather than
    /// assumed. So the block is a live check that this call site does not build,
    /// which would also catch it becoming un-buildable for an unrelated reason;
    /// the error code records the intent only. The guarantee itself is carried
    /// by the `self` in the signature, and the passing examples elsewhere in this
    /// module are the half that breaks loudly if a single legitimate send stops
    /// compiling.
    pub fn send_all(self, events: impl IntoIterator<Item = D::Event>) {
        let Some(sender) = D::upgrade(&self.weak) else {
            return;
        };
        for event in events {
            sender.emit(event);
        }
    }
}

impl<D: Emitter> Drop for Turn<D> {
    fn drop(&mut self) {
        if self.armed {
            self.order.retire(self.ticket);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    type Chan = mpsc::UnboundedSender<u32>;

    /// `true` if the channel is closed and drained.
    ///
    /// Bounded on purpose: the mutant these callers exist to catch is "a strong
    /// sender kept the channel open", under which a bare `recv().await` never
    /// returns and wedges the test binary instead of reporting a failure.
    async fn closed(rx: &mut mpsc::UnboundedReceiver<u32>) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await,
            Ok(None)
        )
    }

    type BChan = broadcast::Sender<u32>;

    /// A turn publishes through its weak handle on a `broadcast` channel.
    ///
    /// The alias uses `broadcast` exclusively, and every other test here uses
    /// `mpsc`. Mutant: make `<broadcast::Sender<_> as Emitter>::upgrade`
    /// return `None` unconditionally — every other test stays green while
    /// every deferred event in production silently disappears.
    #[tokio::test]
    async fn a_broadcast_turn_publishes_through_its_weak_handle() {
        let state = Sequenced::<u32, BChan, BChan>::broadcast(0, 8, 8);
        let mut primary = state.subscribe_primary();
        let mut deferred = state.subscribe_deferred();

        let ticket = state.commit(|value, commit| {
            *value += 1;
            commit.send(11);
            commit.defer()
        });
        let turn = ticket.take().await.expect("ticket 1 never waits");
        turn.send(22);

        assert_eq!(primary.try_recv(), Ok(11));
        assert_eq!(deferred.try_recv(), Ok(22), "the weak handle upgraded");
    }

    /// An outstanding `broadcast` ticket does not keep its channel open.
    #[tokio::test]
    async fn a_broadcast_ticket_does_not_keep_the_channel_open() {
        let state = Sequenced::<u32, BChan, BChan>::broadcast(0, 8, 8);
        let mut deferred = state.subscribe_deferred();
        let outstanding = state.commit(|_, c| c.defer());

        drop(state);

        assert!(
            matches!(
                deferred.try_recv(),
                Err(broadcast::error::TryRecvError::Closed)
            ),
            "the deferred channel stayed open behind an outstanding ticket"
        );
        assert!(
            outstanding.take().await.is_none(),
            "no turn is granted once the owner is gone"
        );
    }

    /// A `ReadHandle` outliving the owner still lets both channels close.
    ///
    /// This is the property the whole handle exists for: the alias captures one
    /// into a projection closure that is RETURNED to the caller and routinely
    /// outlives the wrapper. Mutant: give `ReadHandle` a strong sender field.
    /// It compiles, every other test stays green, and a consumer draining the
    /// merged stream to EOF hangs forever.
    #[tokio::test]
    async fn a_read_handle_outliving_the_owner_still_lets_the_channels_close() {
        let (state, mut primary, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        state.commit(|value, _| *value = 7);
        let handle = state.read_handle();

        drop(state);

        assert!(closed(&mut primary).await, "the in-guard channel closed");
        assert!(closed(&mut deferred).await, "the deferred channel closed");
        assert_eq!(*handle.read(), 7, "the state is still readable through it");
    }

    /// A batch shares one admission point: all of it is published, or none.
    ///
    /// Sending the events one at a time upgrades per call, so the owner can go
    /// away mid-batch and a subscriber sees a delta's additions without its
    /// removals — a state the committed one never had.
    #[tokio::test]
    async fn a_batch_is_all_or_nothing() {
        let (state, _p, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let ticket = state.commit(|_, c| c.defer());
        let turn = ticket.take().await.expect("ticket 1 never waits");

        // Publishing consumes the turn, which is also what releases the line
        // before the next position is taken.
        turn.send_all([1, 2, 3]);
        assert_eq!(deferred.try_recv(), Ok(1));
        assert_eq!(deferred.try_recv(), Ok(2));
        assert_eq!(deferred.try_recv(), Ok(3), "the whole batch was admitted");

        // With the owner gone the upgrade fails once, for the batch as a whole.
        let second = state.commit(|_, c| c.defer());
        let later = second.take().await.expect("ticket 2 runs");
        drop(state);
        later.send_all([4, 5, 6]);
        assert!(
            closed(&mut deferred).await,
            "no part of the batch was published after the owner went away"
        );
    }

    /// A ticket that emits nothing still releases the next one.
    ///
    /// This is the alias's dominant path: nothing is emitted when the
    /// projection is unchanged, but the turn must still be taken and retired.
    #[tokio::test]
    async fn a_ticket_that_emits_nothing_still_releases_the_next() {
        let (state, _p, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let quiet = state.commit(|_, c| c.defer());
        let following = state.commit(|_, c| c.defer());

        let turn = quiet.take().await.expect("ticket 1 never waits");
        drop(turn); // emitted nothing

        let next = tokio::time::timeout(Duration::from_secs(5), following.take())
            .await
            .expect("ticket 2 was stranded behind a silent ticket")
            .expect("a turn is granted");
        next.send(1);
        assert_eq!(deferred.try_recv(), Ok(1));
    }

    /// Events reach the subscriber in ticket order, not completion order.
    #[tokio::test]
    async fn turns_publish_in_ticket_order() {
        let (state, _p, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let first = state.commit(|_, c| c.defer());
        let second = state.commit(|_, c| c.defer());

        // Ticket 2 is taken only after ticket 1 has run, which is the order the
        // line enforces; assert the subscriber observes that order.
        let turn_one = first.take().await.expect("ticket 1 never waits");
        turn_one.send(10); // consuming the turn retires ticket 1
        let turn_two = second.take().await.expect("ticket 2 follows");
        turn_two.send(20);

        assert_eq!(deferred.try_recv(), Ok(10));
        assert_eq!(deferred.try_recv(), Ok(20));
    }

    /// A commit may report in-guard AND take a position in line; the deferred
    /// event lands only when the turn runs.
    #[tokio::test]
    async fn one_commit_reports_in_guard_and_takes_a_position() {
        let (seq, mut primary, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);

        let ticket = seq.commit(|value, commit| {
            *value += 1;
            commit.send(10);
            commit.defer()
        });

        assert_eq!(
            primary.try_recv(),
            Ok(10),
            "the in-guard event is immediate"
        );
        assert!(deferred.try_recv().is_err(), "nothing is deferred-sent yet");

        let turn = ticket.take().await.expect("ticket 1 never waits");
        turn.send(20);
        assert_eq!(deferred.try_recv(), Ok(20));
    }

    /// Retirement is ONE obligation that moves to the `Turn`; it is not
    /// discharged when `take` consumes the `Deferred`.
    ///
    /// Mutant: retire unconditionally in `Deferred::drop` (drop the `armed`
    /// check). Ticket 1 then retires the instant `take` returns, ticket 2 runs
    /// while ticket 1 still holds its turn, and the assertion below fires.
    #[tokio::test(start_paused = true)]
    async fn taking_a_turn_does_not_retire_the_ticket() {
        let (seq, _p, _d) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let first = seq.commit(|_, c| c.defer());
        let second = seq.commit(|_, c| c.defer());

        let held = first.take().await.expect("ticket 1 never waits");
        let waiting = tokio::spawn(second.take());
        // Paused time only auto-advances once every task is idle, so this
        // sleep returning IS the proof that `waiting` has been polled and is
        // parked. A wall-clock sleep would leave the assertion below passing
        // whenever the task simply had not been scheduled yet.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "ticket 2 ran while ticket 1's turn was still held"
        );

        drop(held);
        let turn = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("ticket 2 never woke after ticket 1 retired")
            .expect("join")
            .expect("the owner is still alive, so a turn is granted");
        assert_eq!(turn.ticket(), 2);
    }

    /// The frontier advances across a CONTIGUOUS run, so a ticket abandoned out
    /// of order cannot carry it past a predecessor that is still running.
    ///
    /// Mutant: retire with `frontier = max(frontier, ticket)`. Dropping ticket
    /// 2 then publishes 2, ticket 3 starts while ticket 1 is still sampling,
    /// and the assertion below fires. This is the test that distinguishes the
    /// two retirement designs.
    #[tokio::test(start_paused = true)]
    async fn abandoning_a_later_ticket_does_not_release_the_one_behind_it() {
        let (seq, _p, _d) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let first = seq.commit(|_, c| c.defer());
        let second = seq.commit(|_, c| c.defer());
        let third = seq.commit(|_, c| c.defer());

        let held = first.take().await.expect("ticket 1 never waits");
        drop(second); // abandoned out of order, while ticket 1 runs

        let waiting = tokio::spawn(third.take());
        // Parked, not merely unscheduled — see the note in
        // `taking_a_turn_does_not_retire_the_ticket`.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "ticket 3 overtook ticket 1 because an abandoned ticket 2 moved the frontier"
        );

        drop(held);
        let turn = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("ticket 3 never woke")
            .expect("join")
            .expect("a turn is granted");
        assert_eq!(
            turn.ticket(),
            3,
            "ticket 3 runs once 1 and 2 have both gone"
        );
    }

    /// Owner drop wakes a ticket parked behind a still-live predecessor.
    ///
    /// The wait is on the frontier, not on the channel, so closing the channels
    /// alone leaves this ticket blocked forever. Mutant: delete
    /// `TicketOrder::close`'s body and this test times out instead of passing.
    #[tokio::test(start_paused = true)]
    async fn owner_drop_wakes_a_ticket_parked_behind_a_live_predecessor() {
        let (seq, _p, _d) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let first = seq.commit(|_, c| c.defer()); // never awaited, kept alive
        let second = seq.commit(|_, c| c.defer());

        let waiting = tokio::spawn(second.take());
        // The task must reach its wait BEFORE the owner drops, or a
        // non-publishing `close()` would still pass: a task first polled after
        // the drop sees `closed` on its initial check and returns `None`
        // without ever needing the wake this test is about.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "ticket 2 must be parked behind 1");

        drop(seq);

        let outcome = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the parked ticket never woke on owner drop")
            .expect("join");
        assert!(
            outcome.is_none(),
            "no turn is granted once the owner is gone"
        );
        drop(first);
    }

    /// A close landing in the window between the closed-check and the
    /// notification consume still wakes the parked ticket.
    ///
    /// `wait_for` checks `closed`, then `borrow_and_update` — which marks the
    /// watch notification seen. `close` publishes through that same watch, so
    /// a close arriving between the two has its wake consumed by the very call
    /// that is about to decide to sleep. Without the re-check after the
    /// consume, `changed().await` waits for a notification that already fired
    /// and the ticket is stranded for the life of the process.
    ///
    /// This is a SMOKE CHECK, not a gate: the window between the check and the
    /// consume is a few instructions wide, and deleting the re-check in
    /// `wait_for` leaves this test green over 200 thread-races — measured, not
    /// assumed. Closing the window is justified by inspection of `wait_for`
    /// against `watch`'s consume semantics, not by this test. Making it
    /// discriminate would need a seam inside `wait_for` to park the waiter
    /// between the two operations.
    #[tokio::test]
    async fn a_close_racing_the_notification_consume_still_wakes_the_waiter() {
        for _ in 0..200 {
            let (seq, _p, _d) = Sequenced::<u32, Chan, Chan>::unbounded(0);
            let blocker = seq.commit(|_, c| c.defer());
            let parked = seq.commit(|_, c| c.defer());

            // Drop the owner from another thread so the close can land at any
            // point inside `take`, including between the check and the consume.
            let waiting = tokio::spawn(parked.take());
            let closer = std::thread::spawn(move || drop(seq));

            let outcome = tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .expect("a ticket was stranded by a close racing the consume")
                .expect("join");
            assert!(
                outcome.is_none(),
                "no turn is granted once the owner is gone"
            );
            closer.join().expect("closer thread");
            drop(blocker);
        }
    }

    /// An outstanding ticket does not hold either channel open: it carries a
    /// weak handle, so a consumer draining to EOF still finishes.
    #[tokio::test]
    async fn an_outstanding_ticket_does_not_keep_the_channels_open() {
        let (seq, mut primary, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let outstanding = seq.commit(|_, c| c.defer());

        drop(seq);

        assert!(closed(&mut primary).await, "the in-guard channel closed");
        assert!(closed(&mut deferred).await, "the deferred channel closed");
        drop(outstanding);
    }

    /// A turn that has not upgraded by the time the owner is gone drops its
    /// event rather than publishing it.
    #[tokio::test]
    async fn a_turn_cannot_emit_once_the_owner_is_gone() {
        let (seq, _p, mut deferred) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let ticket = seq.commit(|_, c| c.defer());
        let turn = ticket.take().await.expect("ticket 1 never waits");

        drop(seq);
        turn.send(99);

        assert!(
            closed(&mut deferred).await,
            "the event was published after the owner was gone"
        );
    }

    /// A `Deferred` moved into a future that is never polled still retires, so
    /// the ticket behind it is not stranded.
    ///
    /// This is the shutdown case: a task spawned onto a runtime that is going
    /// away never runs, and its ticket must not park everything behind it.
    #[tokio::test]
    async fn a_ticket_whose_task_never_runs_still_retires() {
        let (seq, _p, _d) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let abandoned = seq.commit(|_, c| c.defer());
        let following = seq.commit(|_, c| c.defer());
        assert_eq!(abandoned.ticket(), 1, "the ticket existed before the drop");

        // The future is built and dropped without ever being polled.
        let never_polled = abandoned.take();
        drop(never_polled);

        let turn = tokio::time::timeout(Duration::from_secs(5), following.take())
            .await
            .expect("ticket 2 was stranded behind a ticket that never ran")
            .expect("a turn is granted");
        assert_eq!(turn.ticket(), 2);
    }

    /// Two `Sequenced` values of the same types keep separate channels and
    /// separate lines.
    #[tokio::test]
    async fn separate_instances_do_not_share_a_line() {
        let (a, _ap, _ad) = Sequenced::<u32, Chan, Chan>::unbounded(0);
        let (b, _bp, _bd) = Sequenced::<u32, Chan, Chan>::unbounded(0);

        let a_first = a.commit(|_, c| c.defer());
        let b_first = b.commit(|_, c| c.defer());

        // `a`'s line is blocked, but `b`'s is not.
        let _held = a_first.take().await.expect("a ticket 1");
        let turn = tokio::time::timeout(Duration::from_secs(5), b_first.take())
            .await
            .expect("b's line was blocked by a's outstanding turn")
            .expect("a turn is granted");
        assert_eq!(turn.ticket(), 1);
    }

    /// Two `Ordered` values of the *same types* keep separate channels, and a
    /// commit on one reaches only its own subscribers.
    ///
    /// This is the case the previous, tag-branded design got wrong: two locks
    /// sharing a tag minted interchangeable tokens, so a guard taken on one lock
    /// authorised emission on a channel ordered by the other. Carrying the
    /// sender leaves that miswiring with no spelling at all; what remains
    /// checkable is that same-typed instances really are distinct channels.
    #[test]
    fn commits_reach_only_their_own_channel() {
        let a: Ordered<u32, broadcast::Sender<u32>> = Ordered::broadcast(0, 8);
        let b: Ordered<u32, broadcast::Sender<u32>> = Ordered::broadcast(0, 8);
        let mut rx_a = a.subscribe();
        let mut rx_b = b.subscribe();

        a.commit(|value, emit| {
            *value += 1;
            emit.send(100);
        });
        assert_eq!(rx_a.try_recv().unwrap(), 100, "A's commit reaches A");
        assert!(
            rx_b.try_recv().is_err(),
            "A's commit must not reach B's channel"
        );

        b.commit(|_value, emit| emit.send(200));
        assert_eq!(rx_b.try_recv().unwrap(), 200, "B's commit reaches B");
        assert!(
            rx_a.try_recv().is_err(),
            "B's commit must not reach A's channel"
        );
    }

    /// Holding an unrelated lock grants nothing on this channel: the capability
    /// handed to a closure belongs to the value being committed, whatever else
    /// the caller happens to hold at the time.
    #[test]
    fn holding_another_lock_grants_nothing_on_this_channel() {
        let entries: Ordered<u32, broadcast::Sender<&'static str>> = Ordered::broadcast(0, 8);
        let cooldowns: Ordered<u32, broadcast::Sender<&'static str>> = Ordered::broadcast(0, 8);
        let mut on_entries = entries.subscribe();
        let mut on_cooldowns = cooldowns.subscribe();

        let held = entries.read();
        cooldowns.commit(|_value, emit| emit.send("cooldown event"));
        drop(held);

        // Positive control first: without it this test would pass just as well
        // if `send` did nothing at all.
        assert_eq!(
            on_cooldowns.try_recv().unwrap(),
            "cooldown event",
            "the commit must publish on its own channel"
        );
        assert!(
            on_entries.try_recv().is_err(),
            "a commit on an unrelated lock must not publish on the entries channel"
        );
    }
}
