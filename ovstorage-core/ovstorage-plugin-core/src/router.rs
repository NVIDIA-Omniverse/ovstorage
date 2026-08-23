// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::StreamExt as _;
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use url::Url;

use crate::*;
use ovstorage_plugin::routing::RouteTable;

pub const ROUTER_KIND: &str = "router";

/// How long any Router-driven fan-out over its children's `list_address_roots`
/// may take: the two at construction (the initial table and the post-subscribe
/// re-read), and each connection mutation's route-table catch-up.
///
/// The bound exists for the caller that supplies no cancellation token and so
/// has no other exit: `StackBuilder::build` passes `None`, and every host that
/// composes a Stack without a token of its own — broker startup and its SIGHUP
/// reload, REST, Python — inherits that. Without the bound a wedged backend
/// pins those open indefinitely. It covers construction as well as mutation
/// because the build path is exactly where the token-less callers are.
///
/// It bounds the SLOWEST child, not the sum of all of them: every one of those
/// fan-outs queries the children concurrently, so this is a per-child budget
/// even though it is applied once around the whole fan-out. That distinction
/// decides whether the bound is safe. A sequential scan under one aggregate
/// limit would make a healthy Stack unbuildable — sixteen healthy remote
/// children at two seconds each during cold start exceeds any fixed aggregate,
/// and since the failure repeats on every rebuild the Stack could never be
/// built at all. A per-child budget scales with child count for free.
///
/// A blunt instrument next to a token the host owns. The CLI hands its Ctrl+C
/// token to `host::build_stack_with_cancel` and so exits a wedged startup on
/// the first press; the daemons need a process-scoped shutdown token before
/// they can do the same, which is tracked separately.
const CHILD_ROOT_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct RouterFactoryImpl;

#[async_trait]
impl RouterFactory for RouterFactoryImpl {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor(ROUTER_KIND, LayerType::Router, false)
    }

    async fn create_router(
        &self,
        name: &str,
        _config: &LayerConfig,
        children: Vec<LayerHandle>,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // Thread the factory's build cancel token through initial root
        // discovery so `StackBuilder::build_with_cancel` can abort the fan-out
        // over each child's `list_address_roots` — no executor thread blocks
        // while the routing table is aggregated.
        let router = Arc::new(Router::new(name, children, cancel.clone()).await?);
        // Subscribe to each child's root-change stream so the Router's route
        // table stays current when a backend discovers its roots asynchronously
        // (e.g. after an operator adds a route to a broker backend).
        //
        // Concurrently, for the same reason `RouterState::rebuild` is: this is
        // one `list_address_roots` per child on the cold-start path, so
        // serializing it makes a Stack of healthy remote children cost the sum
        // of them before it is usable.
        //
        // Bounded like every other child fan-out: a token-less build has no
        // other exit from a child that neither answers nor errors. This pass
        // KEEPS the update streams it collects, so its token is cancelled on
        // failure only — never on the success path, where cancelling would tear
        // down the watchers this is subscribing.
        let cx = Extensions::new();
        let subscribe_cancel = match &cancel {
            Some(caller) => caller.child_token(),
            None => CancellationToken::new(),
        };
        let subscriptions = bounded_child_query(
            Some(&subscribe_cancel),
            futures::future::try_join_all(
                router
                    .state
                    .children
                    .iter()
                    .map(|child| child.list_address_roots(&cx, Some(subscribe_cancel.clone()))),
            ),
        )
        .await?;
        for (_, maybe_stream) in subscriptions {
            if let Some(stream) = maybe_stream {
                spawn_root_watcher(Arc::downgrade(&router), stream, router.cancel.clone());
            }
        }
        // Now that the watchers are subscribed, re-read the children once more
        // to capture any change that landed between Router::new's initial
        // rebuild and the subscribe above.
        let generation = router.state.next_generation();
        bounded_child_query(None, router.state.rebuild(generation, cancel)).await?;
        Ok(router)
    }
}

fn spawn_root_watcher(
    router: Weak<Router>,
    mut stream: RootInfoUpdateStream,
    cancel: CancellationToken,
) {
    // A bridged v2-plugin update stream can yield `Err` on *every* poll (an
    // arbitrary, repeatable plugin error), unlike the in-tree Router's own
    // `BroadcastStream`, where `Err` is only a self-limiting `Lagged`. Without a
    // brake a persistently-erroring child would hot-loop the bridge thread and
    // storm `rebuild`. Back off on *consecutive* errors (reset on any
    // successful item), so a genuine one-off `Lagged` still resyncs promptly
    // while a stuck stream is bounded to an occasional rebuild.
    const MAX_ERR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
    const BASE_ERR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);
    tokio::spawn(async move {
        let mut consecutive_errors: u32 = 0;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                next = stream.next() => match next {
                    // Ok = a child root change; Err = "resync" — either a
                    // recoverable `Lagged` (broadcast overflow) or a bridged
                    // plugin error. Both re-read the children and re-emit a full
                    // snapshot. Only `None` (sender dropped → child gone) ends
                    // the watcher; treating a resync as fatal would silently
                    // freeze the route table.
                    Some(item) => {
                        let Some(r) = router.upgrade() else { break };
                        // The rebuild is now async; awaiting it here (never from
                        // a sync context) keeps the fan-out off the executor's
                        // blocking path. Forward the watcher's cancel so a
                        // dropped Router aborts an in-flight rebuild promptly.
                        let generation = r.state.next_generation();
                        let _ = r
                            .state
                            .rebuild(generation, Some(cancel.clone()))
                            .await;
                        if item.is_err() {
                            // Exponential backoff, capped, so a stream stuck
                            // erroring can't spin: 50ms, 100, 200 … ≤ 5s.
                            let shift = consecutive_errors.min(10);
                            let backoff =
                                MAX_ERR_BACKOFF.min(BASE_ERR_BACKOFF.saturating_mul(1u32 << shift));
                            consecutive_errors = consecutive_errors.saturating_add(1);
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => break,
                                _ = tokio::time::sleep(backoff) => {}
                            }
                        } else {
                            consecutive_errors = 0;
                        }
                    }
                    None => break,
                },
            }
        }
    });
}

/// Requires a Tokio runtime: the root watchers and each connection mutation's
/// route-table catch-up are spawned tasks.
struct Router {
    name: String,
    state: Arc<RouterState>,
    cancel: CancellationToken,
}

/// The Router's children and the maps derived from them, behind an `Arc` so a
/// post-commit route-table catch-up can run as an owned background task holding
/// only this — never a borrow of the `Router` or of a caller's future.
struct RouterState {
    children: Vec<LayerHandle>,
    routes: RwLock<RouteTable<LayerHandle>>,
    targets: RwLock<HashMap<String, LayerHandle>>,
    /// Stamped on each rebuild when it is REQUESTED, so the generations order
    /// rebuilds by the state they set out to capture rather than by the order
    /// their fan-outs happen to finish in.
    next_generation: AtomicU64,
    /// The generation whose fan-out produced the maps above. Held across the
    /// swap rather than merely compared before it, so a rebuild's "am I still
    /// the newest?" check and its publication are atomic against a concurrent
    /// rebuild.
    applied_generation: Mutex<u64>,
    /// One permit: at most ONE post-commit catch-up runs at a time.
    ///
    /// A catch-up that times out is cancelled, but a child that ignores
    /// cancellation keeps its task (and this permit) alive. Holding the permit
    /// is what bounds that: later mutations queue for it rather than each
    /// starting another full fan-out against a backend that is not answering.
    ///
    /// The queueing is inside each catch-up's own deadline, so a mutation that
    /// waits here still exits on schedule whether or not the permit ever
    /// reaches it, and whether or not anyone is still waiting on the mutation.
    /// Against a persistently wedged backend a Router therefore holds at most
    /// one in-flight child call, and every catch-up behind it retires by its own
    /// deadline instead of parking until Router drop.
    catch_up_slot: Arc<tokio::sync::Semaphore>,
    root_change_tx: broadcast::Sender<RootInfoChange>,
}

impl Drop for Router {
    fn drop(&mut self) {
        // Stops the per-child root watchers and any in-flight detached
        // route-table catch-up deterministically instead of relying on each
        // child's broadcast sender being dropped.
        self.cancel.cancel();
    }
}

impl Router {
    async fn new(
        name: &str,
        children: Vec<LayerHandle>,
        cancel: Option<CancellationToken>,
    ) -> Result<Self> {
        let (root_change_tx, _) = broadcast::channel(16);
        let router = Self {
            name: name.to_string(),
            state: Arc::new(RouterState {
                children,
                routes: RwLock::new(RouteTable::empty()),
                targets: RwLock::new(HashMap::new()),
                next_generation: AtomicU64::new(0),
                applied_generation: Mutex::new(0),
                catch_up_slot: Arc::new(tokio::sync::Semaphore::new(1)),
                root_change_tx,
            }),
            cancel: CancellationToken::new(),
        };
        let generation = router.state.next_generation();
        bounded_child_query(None, router.state.rebuild(generation, cancel)).await?;
        Ok(router)
    }

    /// Run the post-commit route-table catch-up on its own task and wait for
    /// it, bounded by `cancel` and by [`CHILD_ROOT_QUERY_TIMEOUT`].
    ///
    /// **The invariant this upholds: `Ok` means the mutation committed AND the
    /// route table reflects it.** Every other outcome is an error — the fan-out
    /// failed, the caller's token fired, the wait timed out, or the catch-up
    /// panicked — because a caller told `Ok` immediately routes against the
    /// address it just bound. `StackBuilder::build_with_cancel` applies each
    /// configured connection through this Layer and hands back a Stack expected
    /// to route it, with no reconciliation pass of its own; a child that
    /// advertises no root-update stream (`FileBackend`, any `updates: false`
    /// plugin) has no watcher to repair a table this catch-up failed to
    /// publish. So a swallowed failure here is a permanently unroutable
    /// connection whose caller was told it succeeded.
    ///
    /// EVERY failure here reports [`ErrorCode::CommitAmbiguous`], because every
    /// one of them happens after the mutation committed. That is a contract
    /// about retryability, not a cosmetic relabelling: `CommitAmbiguous` buckets
    /// as `Internal` and so is not retryable, while the child's own error is
    /// routinely [`ErrorCode::Transient`], whose contract says a blind retry is
    /// safe. Propagating a `Transient` root re-query failure verbatim would
    /// invite exactly the retry that re-issues an already-committed mutation and
    /// gets `AlreadyExists` (or `NotFound` for a removal) — the trap this whole
    /// wait exists to avoid. The underlying error is carried in the message
    /// instead, where it diagnoses without steering.
    ///
    /// What the caller's token buys is an EXIT, not a different answer: it
    /// releases this wait without cancelling the catch-up, which keeps running
    /// on its own task, under its own deadline, and still converges the table if
    /// the children answer within it. The mutation reports the same ambiguity
    /// rather than `Err(Cancelled)`, which would claim an operation that already
    /// succeeded did not happen, or `Ok`, which would claim a table that may
    /// still be stale is current.
    ///
    /// The TIMEOUT is not the same exit, and it is not this function's. The
    /// catch-up's deadline belongs to [`Router::spawn_route_catch_up`], on the
    /// task itself, because a deadline held by a waiter is no deadline at all:
    /// a caller that releases its wait — or whose future is simply dropped, an
    /// RPC handler on client disconnect — would leave the task running with
    /// nothing left to bound it, one per abandoned mutation. A catch-up that
    /// misses its own deadline cancels its own token, which is what stops a
    /// foreign child; the task ends, and the two outcomes report different
    /// messages because only one of them converges afterwards.
    ///
    /// OWNERSHIP BEGINS AT COMMIT. The task is spawned before this function
    /// awaits anything, it acquires the catch-up slot itself, and it carries its
    /// own bound. Nothing about a committed mutation's reconcile may depend on
    /// the caller's future surviving: a dropped future is not a cancellation
    /// token firing, so it runs none of the exits above. If the permit were
    /// acquired here instead, a mutation parked behind an in-flight catch-up
    /// would exist only inside the caller's future — drop it and the committed
    /// mutation has no owner left to reconcile it, and an `updates: false` child
    /// has no watcher to repair that later.
    ///
    /// [`RouterState::rebuild`] publishes only on success, so a failed catch-up
    /// leaves the previous table intact rather than emptying it.
    async fn route_catch_up(&self, cancel: Option<CancellationToken>) -> Result<()> {
        // This catch-up's own token: cancelling on timeout must stop THIS
        // catch-up without disturbing the Router's watchers or a sibling
        // mutation's.
        let catch_up_cancel = self.cancel.child_token();
        // Stamp the generation at COMMIT — this is the first thing after the
        // mutation landed, before any await — so the ordering `rebuild`
        // enforces is commit order rather than permit-acquisition order.
        let generation = self.state.next_generation();
        let task = self.spawn_route_catch_up(generation, catch_up_cancel);
        // This wait owns no deadline. The catch-up carries its own, on its own
        // task, so releasing this wait cannot strip it of one — see
        // [`Router::spawn_route_catch_up`].
        let waited = match &cancel {
            // Dropping the `JoinHandle` detaches the task rather than aborting
            // it, so the catch-up survives the released wait. The task is
            // polled FIRST: a catch-up that already finished must be reported
            // as finished even if the caller's token fires in the same wake.
            Some(caller) => tokio::select! {
                biased;
                joined = task => Some(joined),
                _ = caller.cancelled() => None,
            },
            None => Some(task.await),
        };
        match waited {
            Some(Ok(Ok(()))) => Ok(()),
            // The catch-up's own deadline reports itself; every other failure
            // is the children's. Both are abandoned — nothing reschedules them.
            Some(Ok(Err(error))) if error.code() == ErrorCode::DeadlineExceeded => {
                Err(catch_up_abandoned(&format!("{error}")))
            }
            Some(Ok(Err(error))) => Err(catch_up_abandoned(&format!(
                "re-querying the children failed ({error})"
            ))),
            Some(Err(join)) => Err(catch_up_abandoned(&format!("it panicked ({join})"))),
            None => Err(catch_up_detached("the caller's cancellation token fired")),
        }
    }

    /// The catch-up itself, on a task bounded by `cancel` — a child of the
    /// Router's token, so Router drop fires it and its own deadline can fire it
    /// alone.
    ///
    /// The task carries the deadline, spanning permit acquisition AND the
    /// rebuild. That placement is the point: the caller's wait is released by a
    /// fired token and abandoned outright by a dropped future, and neither may
    /// leave a committed mutation's catch-up running unbounded. Every catch-up
    /// therefore ends on its own schedule, however its waiter left.
    ///
    /// Holds a `Weak`, like the sibling [`spawn_root_watcher`]: a catch-up
    /// orphaned by a released wait must not be the thing keeping the Router's
    /// children alive.
    ///
    /// The task acquires the [`RouterState::catch_up_slot`] permit ITSELF and
    /// holds it until it ends, so the slot frees exactly when the task does —
    /// including when it ends because a timeout cancelled it. Acquiring here
    /// rather than in the caller is what keeps a queued catch-up owned: the
    /// wait for the permit belongs to a spawned task, not to a caller's future
    /// that may be dropped.
    fn spawn_route_catch_up(
        &self,
        generation: u64,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let state = Arc::downgrade(&self.state);
        let slot = Arc::clone(&self.state.catch_up_slot);
        tokio::spawn(async move {
            let Some(state) = state.upgrade() else {
                return Err(Error::new(
                    ErrorCode::Cancelled,
                    "the router was dropped before its route-table catch-up ran",
                ));
            };
            // Queue behind any catch-up already in flight, and reconcile once
            // it is this one's turn. The DEADLINE spans both, and lives here on
            // the task rather than on a caller's wait: a caller may release its
            // wait or be dropped outright, and neither may leave this task
            // running unbounded. It fires its own token on expiry, which is
            // what stops a foreign child — dropping the `rebuild` future
            // unwinds the Rust side only.
            let bounded = tokio::time::timeout(CHILD_ROOT_QUERY_TIMEOUT, async {
                let _permit = slot
                    .acquire_owned()
                    .await
                    .expect("the router's catch-up slot is never closed");
                state.rebuild(generation, Some(cancel.clone())).await
            });
            let result = tokio::select! {
                biased;
                bounded = bounded => match bounded {
                    Ok(result) => result,
                    Err(_) => {
                        cancel.cancel();
                        Err(Error::new(
                            ErrorCode::DeadlineExceeded,
                            format!(
                                "it did not complete within {CHILD_ROOT_QUERY_TIMEOUT:?} \
                                 and was cancelled"
                            ),
                        ))
                    }
                },
                _ = cancel.cancelled() => Err(Error::new(
                    ErrorCode::Cancelled,
                    "the route-table catch-up was cancelled: the router was dropped",
                )),
            };
            if let Err(error) = &result {
                // The waiting mutation surfaces this too, but a catch-up whose
                // wait was released has no other voice.
                tracing::warn!(
                    error = %error,
                    "router: route-table catch-up after a connection mutation failed; \
                     retaining the previous table",
                );
            }
            result
        })
    }

    fn route(&self, url: &Url) -> Result<LayerHandle> {
        self.state
            .routes
            .read()
            .lookup(url)
            .map(|(_, child)| child.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    fn route_target(&self, target: &str) -> Result<LayerHandle> {
        self.state
            .targets
            .read()
            .get(target)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "target layer not found"))
    }
}

impl RouterState {
    /// The stamp for a rebuild that is about to be requested. Generations start
    /// at 1, so the initial `applied_generation` of 0 precedes every rebuild.
    fn next_generation(&self) -> u64 {
        // Exhausting a u64 at one stamp per rebuild is unreachable, but the
        // wrap is not harmless enough to leave implicit: `fetch_add` wraps in
        // release builds, and a generation that wrapped past
        // `applied_generation` would make `rebuild` discard every later table
        // while still returning `Ok` — silently breaking the invariant this
        // counter exists to enforce. Fail loudly in every profile instead.
        self.next_generation
            .fetch_add(1, AtomicOrdering::Relaxed)
            .checked_add(1)
            .expect("the router's rebuild generation counter overflowed a u64")
    }

    /// Re-query every child, and — if this rebuild is still the newest — install
    /// the resulting maps and announce them.
    async fn rebuild(&self, generation: u64, cancel: Option<CancellationToken>) -> Result<()> {
        let cx = Extensions::new();
        // The fan-out's own token, cancelled the moment this rebuild stops
        // caring about the answers — first error, timeout, or the whole future
        // being dropped. `try_join_all` drops the outstanding futures on the
        // first error, and dropping a future stops only the RUST half of a
        // child: a `ForeignVtableLayer`'s plugin task and its `user_data` live
        // on until the FFI operation completes. Cancelling is the signal that
        // crosses the ABI. Safe to fire on success too, because this fan-out
        // discards the children's update streams — unlike `create_router`'s
        // subscribe pass, which keeps them and so cancels only on timeout.
        let fan_out = match &cancel {
            Some(caller) => caller.child_token(),
            None => CancellationToken::new(),
        };
        let _stop_fan_out = CancelOnDrop(fan_out.clone());
        // Query the children CONCURRENTLY. They are independent calls that may
        // each reach remote I/O, so serializing them makes the fan-out cost the
        // sum of the children rather than the slowest one — which is what would
        // put a healthy Stack's cold start over `CHILD_ROOT_QUERY_TIMEOUT`.
        // `try_join_all` preserves child order in its results, so the route
        // table is built deterministically. No lock is held across the await.
        let snapshots = futures::future::try_join_all(
            self.children
                .iter()
                .map(|child| child.list_address_roots(&cx, Some(fan_out.clone()))),
        )
        .await?;

        let mut routes = Vec::new();
        let mut targets = HashMap::new();
        for (child, (snapshot, _updates)) in self.children.iter().zip(snapshots) {
            routes.extend(snapshot.roots.into_iter().map(|root| (root, child.clone())));
            for target in child.owned_targets() {
                if targets.insert(target.clone(), child.clone()).is_some() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("target layer '{target}' is owned by multiple router children"),
                    ));
                }
            }
        }

        // Publish under the generation guard. A fan-out that started before one
        // that has already published carries the older view of the children, so
        // installing it would roll the table back — losing a connection whose
        // caller was told `Ok`, with no watcher to repair it for an
        // `updates: false` child. Yielding to the newer generation is safe, not
        // merely convenient: a higher generation was requested after this one,
        // therefore after whatever mutation this one is catching up with, so
        // its fan-out observed that mutation too.
        //
        // The guard spans the broadcast as well as the swap, so what subscribers
        // see is ordered by the same generations the table is. Dropping it after
        // the swap would let an older rebuild collect its roots, get preempted
        // by a newer one that swaps and broadcasts, and then broadcast its own
        // stale snapshot — leaving the Router's table correct but regressing
        // every direct stream consumer (a cache drain has nothing to re-query
        // against). Both are cheap, non-blocking operations: a `broadcast::send`
        // to a bounded channel never waits on a receiver.
        let mut applied = self.applied_generation.lock();
        if *applied >= generation {
            return Ok(());
        }
        *applied = generation;
        *self.routes.write() = RouteTable::build(routes);
        *self.targets.write() = targets;
        let roots = self.routes.read().roots().cloned().collect();
        let _ = self.root_change_tx.send(RootInfoChange::Snapshot(roots));
        Ok(())
    }
}

/// Cancels its token when dropped.
///
/// The reason this type exists rather than a `cancel()` at each exit: dropping
/// a future stops the Rust side of a child call and nothing else. A child that
/// is a `ForeignVtableLayer` keeps its plugin-side task and `user_data`
/// allocation alive until the FFI operation ends on its own, so every place
/// that abandons a child call has to CANCEL, not merely drop — including the
/// paths that abandon it by being dropped themselves.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Bound a Router fan-out over its children by [`CHILD_ROOT_QUERY_TIMEOUT`].
///
/// Used on the CONSTRUCTION fan-outs, where nothing has committed yet, so the
/// timeout is a plain [`ErrorCode::DeadlineExceeded`] rather than the
/// commit-ambiguity the post-commit catch-up reports.
///
/// `on_failure` is the token handed to the children, cancelled on EVERY failure
/// exit — the bound being missed, and equally a sibling erroring. Both abandon
/// the outstanding children the same way: `try_join_all` resolves on the first
/// error and drops the pending futures, and a dropped future is not enough to
/// stop a foreign child (see [`CancelOnDrop`]). Cancelling only the timeout
/// would leave a blackholed foreign sibling running after a failed build, with
/// nothing left to fire the token — it is not a child of the Router's, so the
/// half-built Router's drop does not reach it either.
///
/// `None` is for a `query` that already owns that responsibility —
/// [`RouterState::rebuild`] cancels its own fan-out token from a
/// [`CancelOnDrop`] guard, so being dropped here is enough.
///
/// Success never cancels: `create_router`'s subscribe pass KEEPS the update
/// streams it collects, and cancelling would tear down the watchers it just
/// subscribed.
async fn bounded_child_query<T>(
    on_failure: Option<&CancellationToken>,
    query: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let result = match tokio::time::timeout(CHILD_ROOT_QUERY_TIMEOUT, query).await {
        Ok(result) => result,
        Err(_) => Err(Error::new(
            ErrorCode::DeadlineExceeded,
            format!(
                "the router's children did not answer list_address_roots within \
                 {CHILD_ROOT_QUERY_TIMEOUT:?}"
            ),
        )),
    };
    if result.is_err()
        && let Some(token) = on_failure
    {
        token.cancel();
    }
    result
}

/// The error a connection mutation reports when it committed but its
/// route-table catch-up is still running, having outlived this caller's wait:
/// [`ErrorCode::CommitAmbiguous`], which buckets as `Internal` and so is NOT
/// marked retryable — a blind retry would report `AlreadyExists`/`NotFound` for
/// state that already changed.
fn catch_up_detached(reason: &str) -> Error {
    Error::new(
        ErrorCode::CommitAmbiguous,
        format!(
            "the connection mutation committed on its backend, but the router's route table \
             did not catch up with it here: {reason}. The catch-up continues in the \
             background; re-read the connection list rather than re-issuing the mutation",
        ),
    )
}

/// The same ambiguity, for a catch-up that will NOT converge on its own: it
/// failed, panicked, or timed out and was cancelled.
///
/// Worth distinguishing from [`catch_up_detached`] because the advice differs.
/// A child with no root-update stream (`FileBackend`, any `updates: false`
/// plugin) has no watcher to repair the table, so nothing further will happen
/// until the next mutation or a Stack rebuild — telling that caller to wait for
/// background convergence would be telling it to wait forever.
fn catch_up_abandoned(reason: &str) -> Error {
    Error::new(
        ErrorCode::CommitAmbiguous,
        format!(
            "the connection mutation committed on its backend, but the router's route table \
             did not catch up with it: {reason}. No further catch-up is scheduled, so the \
             table may not route the affected addresses until the next connection mutation \
             or root update; re-read the connection list rather than re-issuing the mutation",
        ),
    )
}

#[async_trait]
impl Layer for Router {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor(ROUTER_KIND, LayerType::Router, false)
    }

    fn owned_targets(&self) -> Vec<String> {
        self.state
            .children
            .iter()
            .flat_map(|child| child.owned_targets())
            .collect()
    }

    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.route(url)?.root_info_for(url, cx, cancel).await
    }

    /// Route by `url` first (the Router has no single inner), then delegate to
    /// the owning child so a renamed backend Layer resolves to its instance
    /// name. `None` when `url` matches no route.
    async fn owning_target_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Option<String> {
        self.route(url)
            .ok()?
            .owning_target_for(url, cx, cancel)
            .await
    }

    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        let mut seen = HashSet::new();
        let mut out = vec![self.descriptor()];
        seen.insert(ROUTER_KIND.to_string());
        for child in &self.state.children {
            for descriptor in child.list_kinds(cx)? {
                if seen.insert(descriptor.kind.clone()) {
                    out.push(descriptor);
                }
            }
        }
        Ok(out)
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        // The cached-snapshot read below is non-blocking, so this returns
        // without ever awaiting or fanning out — the async signature only
        // satisfies the trait. Subscribe before snapshotting so a change
        // between the two is delivered on the stream rather than lost. The
        // route table is kept current by the root watchers, so no rebuild is
        // needed here (avoids a recursive re-fan-out across the child tree on
        // every snapshot).
        let stream: RootInfoUpdateStream = Box::pin(
            BroadcastStream::new(self.state.root_change_tx.subscribe())
                .map(|r| r.map_err(|e| Error::new(ErrorCode::Internal, e.to_string()))),
        );
        let roots = self.state.routes.read().roots().cloned().collect();
        Ok((
            RootInfoSnapshot {
                roots,
                updates: true,
            },
            Some(stream),
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.route(&request.input.address)?
            .stat(request, cancel)
            .await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.route(&request.input.address)?
            .read(request, cancel)
            .await
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.route(&request.input.address)?
            .materialize(request, cancel)
            .await
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.route(&request.input.address)?
            .write(request, cancel)
            .await
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.route(&request.input.address)?
            .write_stream(request, cancel)
            .await
    }

    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        self.route(&request.input.address)?
            .write_redirect(request, cancel)
            .await
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.route(&request.input.address)?
            .continue_write(request, cancel)
            .await
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.route(&request.input.address)?
            .delete(request, cancel)
            .await
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.route(&request.input.prefix)?
            .list(request, cancel)
            .await
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        self.route(&request.input.address)?
            .list_versions(request, cancel)
            .await
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.route(&request.input.address)?
            .get_latest_version(request, cancel)
            .await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        self.route(&request.input.prefix)?
            .watch_directory(request, cancel)
            .await
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.route(&request.input.address)?
            .create_directory(request, cancel)
            .await
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.route(&request.input.address)?
            .delete_directory(request, cancel)
            .await
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let src = self.route(&request.input.source)?;
        let dst = self.route(&request.input.destination)?;
        if !Arc::ptr_eq(&src, &dst) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "cross-root copy requires a copy_rename_fallback layer",
            ));
        }
        dst.copy(request, cancel).await
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let src = self.route(&request.input.source)?;
        let dst = self.route(&request.input.destination)?;
        if !Arc::ptr_eq(&src, &dst) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "cross-root rename requires a copy_rename_fallback layer",
            ));
        }
        dst.rename(request, cancel).await
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.route(&request.input.address)?
            .update_metadata(request, cancel)
            .await
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        self.route(&request.input.address)?
            .check_access(request, cancel)
            .await
    }

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.route_target(&request.input.target)?
            .probe(request, cancel)
            .await
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let child = self.route_target(&request.input.target)?;
        let connection = child.add_connection(request, cancel.clone()).await?;
        // The mutation has COMMITTED on the child. The route-table catch-up
        // that follows is this Layer reconciling with that fact, and it is the
        // only thing that does so for a child publishing no update stream
        // (`FileBackend`, any `updates: false` plugin) — such a child has no
        // watcher to self-heal a table this leaves stale. So the `?` is
        // load-bearing: returning the connection with an unpublished table
        // would tell the caller an address is bound that does not route. See
        // `route_catch_up` for what each failure means and why a cancel here
        // reports `CommitAmbiguous` rather than `Cancelled`.
        self.route_catch_up(cancel).await?;
        Ok(connection)
    }

    async fn list_connections(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        // Fan out over the children sequentially, forwarding cancel to each so
        // a slow child keeps the aggregation cancellable; the Router exposes no
        // live connection-update stream of its own.
        let mut connections = Vec::new();
        for child in &self.state.children {
            connections.extend(
                child
                    .list_connections(cx, cancel.clone())
                    .await?
                    .0
                    .connections,
            );
        }
        Ok((
            ConnectionSnapshot {
                connections,
                updates: false,
            },
            None,
        ))
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.route_target(&key.input.target)?
            .remove_connection(key, cancel.clone())
            .await?;
        // The mutation has COMMITTED on the child; the catch-up that reconciles
        // the table with that fact runs and is waited on exactly as in
        // `add_connection`, under the same `Ok` invariant.
        self.route_catch_up(cancel).await
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.route_target(&request.input.key.target)?
            .update_connection_credentials(request, cancel)
            .await
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let connection = self
            .route_target(&request.input.key.target)?
            .update_connection_attributes(request, cancel.clone())
            .await?;
        // Under the same `Ok` invariant as `add_connection`/`remove_connection`:
        // an attribute patch changes what a root advertises (display name,
        // visibility — an alias flipped to `Suppressed` must stop being
        // routable), and an `updates: false` child has no watcher to publish
        // that. Credential updates are excluded: they change no root.
        self.route_catch_up(cancel).await?;
        Ok(connection)
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        self.route_target(&request.input.key.target)?
            .authenticate_connection(request, cancel)
            .await
    }
}

pub(crate) fn descriptor(
    kind: impl Into<String>,
    layer_type: LayerType,
    accepts_connections: bool,
) -> LayerKindDescriptor {
    let kind = kind.into();
    LayerKindDescriptor {
        display_name: kind.clone(),
        kind,
        layer_type,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections,
        auth_capable: false,
        // Declining is this helper's fixed answer, and the only layer this
        // crate registers through it is the router, which owns no storage. A
        // backend that can carry a write's `user_metadata` declares so on its
        // own descriptor rather than through here.
        supports_user_metadata: false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::Semaphore;

    use super::*;

    /// A router child whose `list_address_roots` can be pinned open on a gate or
    /// made to fail, standing in for a child that commits a connection mutation
    /// and then stalls, or errors on, the re-query the Router uses to catch its
    /// route table up.
    struct GatedChild {
        roots: RwLock<Vec<RootInfo>>,
        /// One-shot: the NEXT re-query stalls, later ones pass through. Set by
        /// the test, cleared by the stalling call.
        stall: AtomicBool,
        /// Latching: EVERY re-query stalls at the gate, standing in for a
        /// backend that is wedged rather than merely slow.
        stall_all: AtomicBool,
        /// Re-queries currently parked at the gate, and the high-water mark of
        /// that count. Together they measure how many catch-up fan-outs a
        /// wedged child is carrying at once.
        in_flight: std::sync::atomic::AtomicUsize,
        peak_in_flight: std::sync::atomic::AtomicUsize,
        /// Makes every re-query fail.
        fail: AtomicBool,
        /// Released by the test to let a stalled re-query complete.
        gate: Semaphore,
        /// Signals that a re-query has reached the gate.
        entered: Semaphore,
        /// Counts `add_connection` calls, so each binds a distinct root.
        adds: std::sync::atomic::AtomicUsize,
    }

    /// Counts a fan-out for as long as it is parked in the child, updating the
    /// high-water mark on entry and decrementing on drop.
    struct InFlight<'a>(&'a GatedChild);

    impl<'a> InFlight<'a> {
        fn enter(child: &'a GatedChild) -> Self {
            let now = child.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            child.peak_in_flight.fetch_max(now, Ordering::SeqCst);
            Self(child)
        }
    }

    impl Drop for InFlight<'_> {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl GatedChild {
        /// A root this child serves from the start, so a test can tell an
        /// unpublished rebuild ("the previous table survived") apart from an
        /// emptied one.
        const STATIC_ROOT: &'static str = "gated:///static/";
        /// The root the FIRST `add_connection` binds. Later adds bind
        /// `gated:///added-{n}/`, so a test can tell one mutation's root from
        /// another's in a published table.
        const ROOT: &'static str = "gated:///added/";

        /// The root the `n`th add binds, counting from the first.
        fn nth_root(n: usize) -> String {
            if n == 0 {
                Self::ROOT.to_string()
            } else {
                format!("gated:///added-{n}/")
            }
        }

        fn next_root(&self) -> String {
            Self::nth_root(self.adds.fetch_add(1, Ordering::SeqCst))
        }

        fn new() -> Arc<Self> {
            Arc::new(Self {
                roots: RwLock::new(vec![Self::root_info(Self::STATIC_ROOT)]),
                stall: AtomicBool::new(false),
                stall_all: AtomicBool::new(false),
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                peak_in_flight: std::sync::atomic::AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                gate: Semaphore::new(0),
                entered: Semaphore::new(0),
                adds: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn root_info(root: &str) -> RootInfo {
            RootInfo {
                root: Url::parse(root).unwrap(),
                display_name: None,
                layer_kind: "gated".to_string(),
                connection_id: None,
                owning_target: Some("gated".to_string()),
                capabilities: Capabilities::empty(),
                range_read_strategy: RangeReadStrategy::default(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: UserMetadata::new(),
            }
        }
    }

    #[async_trait]
    impl Layer for GatedChild {
        fn name(&self) -> &str {
            "gated"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("gated", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            vec!["gated".to_string()]
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::Transient, "root re-query failed"));
            }
            // Sample the roots BEFORE the gate, so a stalled re-query carries
            // the view it had when its fan-out reached this child — which is
            // what makes a delayed rebuild's snapshot older than a later one's.
            let roots = self.roots.read().clone();
            if self.stall.swap(false, Ordering::SeqCst) || self.stall_all.load(Ordering::SeqCst) {
                self.entered.add_permits(1);
                // Counted with a drop guard, so a fan-out whose future is
                // dropped (a cancelled catch-up) stops counting immediately —
                // which is what distinguishes "cancelled and gone" from
                // "abandoned and still holding the child".
                let _counted = InFlight::enter(self);
                let _permit = self.gate.acquire().await.expect("the gate stays open");
            }
            Ok((
                RootInfoSnapshot {
                    roots,
                    updates: false,
                },
                None,
            ))
        }

        async fn add_connection(
            &self,
            _request: Request<LayerConnectionRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            // Commit first, exactly like a child whose mutation lands before
            // its root re-query stalls. Each add binds a DISTINCT root, so a
            // test can tell which mutations a published table reflects.
            let root = Url::parse(&self.next_root()).unwrap();
            self.roots.write().push(Self::root_info(root.as_str()));
            Ok(Connection {
                id: ConnectionId("gated".to_string()),
                backend_kind: "gated".to_string(),
                display_name: "gated".to_string(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: vec![root],
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
            })
        }
    }

    fn gated_connection_request() -> Request<LayerConnectionRequest> {
        Request::new(LayerConnectionRequest {
            target: "gated".to_string(),
            connection: ConnectionRequest {
                backend_kind: "gated".to_string(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
    }

    /// A router child standing in for a FOREIGN one: its `list_address_roots`
    /// never returns, and the only way to stop the work it represents is the
    /// cancellation token. A detached watcher — the analogue of the plugin-side
    /// task that outlives a dropped Rust future — records that the token fired.
    struct ForeignishChild {
        cancelled: Arc<Semaphore>,
        /// Makes this child fail immediately instead, so a test can force the
        /// fan-out to abandon its siblings.
        fail: AtomicBool,
    }

    impl ForeignishChild {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                cancelled: Arc::new(Semaphore::new(0)),
                fail: AtomicBool::new(fail),
            })
        }
    }

    #[async_trait]
    impl Layer for ForeignishChild {
        fn name(&self) -> &str {
            "foreignish"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("foreignish", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            vec![format!("foreignish-{:p}", self)]
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            if self.fail.swap(false, Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::Transient, "foreignish child failed"));
            }
            if let Some(cancel) = cancel {
                let cancelled = Arc::clone(&self.cancelled);
                tokio::spawn(async move {
                    cancel.cancelled().await;
                    cancelled.add_permits(1);
                });
            }
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn abandoning_a_fan_out_cancels_the_children_it_gave_up_on() {
        // `try_join_all` drops the outstanding futures when one child fails.
        // Dropping unwinds the Rust half only: a foreign child's plugin task and
        // its `user_data` allocation live until the FFI call ends on its own, so
        // the fan-out has to cancel the token as well.
        let failing = ForeignishChild::new(true);
        let abandoned = ForeignishChild::new(false);
        let router = Router::new(
            "r",
            vec![
                abandoned.clone() as LayerHandle,
                failing.clone() as LayerHandle,
            ],
            None,
        )
        .await;
        assert!(router.is_err(), "the failing child fails the build");

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            abandoned.cancelled.acquire(),
        )
        .await;
        assert!(
            cancelled.is_ok(),
            "the abandoned child's token must be cancelled, not merely dropped: \
             a foreign child cannot see a dropped future",
        );
    }

    /// A router child that answers the CONSTRUCTION rebuild and then behaves
    /// like [`ForeignishChild`] on every later call — either failing at once or
    /// blackholing. Lets a test reach `create_router`'s SUBSCRIBE pass, which
    /// only runs once `Router::new`'s initial rebuild has succeeded.
    struct SubscribeForeignishChild {
        cancelled: Arc<Semaphore>,
        calls: std::sync::atomic::AtomicUsize,
        /// Fail the subscribe pass instead of blackholing it, so a test can
        /// force that fan-out to abandon its siblings.
        fail_after_first: bool,
        root: Url,
    }

    impl SubscribeForeignishChild {
        fn new(index: usize, fail_after_first: bool) -> Arc<Self> {
            Arc::new(Self {
                cancelled: Arc::new(Semaphore::new(0)),
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail_after_first,
                root: Url::parse(&format!("subscribe:///c{index}/")).unwrap(),
            })
        }
    }

    #[async_trait]
    impl Layer for SubscribeForeignishChild {
        fn name(&self) -> &str {
            "subscribe-foreignish"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("subscribe-foreignish", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            vec![format!("subscribe-foreignish-{:p}", self)]
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok((
                    RootInfoSnapshot {
                        roots: vec![RootInfo {
                            root: self.root.clone(),
                            display_name: None,
                            layer_kind: "subscribe-foreignish".to_string(),
                            connection_id: None,
                            owning_target: None,
                            capabilities: Capabilities::empty(),
                            range_read_strategy: RangeReadStrategy::default(),
                            source: RouteSource::Static {
                                layer: ConfigLayer::Programmatic,
                            },
                            visible: true,
                            visibility: AddressVisibility::Visible,
                            alias_state: None,
                            icon: None,
                            user_metadata: UserMetadata::new(),
                        }],
                        updates: true,
                    },
                    None,
                ));
            }
            if self.fail_after_first {
                return Err(Error::new(
                    ErrorCode::Transient,
                    "subscribe-foreignish child failed",
                ));
            }
            if let Some(cancel) = cancel {
                let cancelled = Arc::clone(&self.cancelled);
                tokio::spawn(async move {
                    cancel.cancelled().await;
                    cancelled.add_permits(1);
                });
            }
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_subscribe_pass_cancels_the_children_it_gave_up_on() {
        // The subscribe pass is a second fan-out, after `Router::new` succeeded.
        // Its token is cancelled when the fan-out MISSES ITS BOUND, but a
        // sibling that ERRORS resolves `try_join_all` early and drops the
        // pending futures just the same — and a dropped future is invisible to
        // a foreign child, whose plugin task and `user_data` live until the FFI
        // call ends by itself. The token is not a child of the Router's either,
        // so dropping the half-built Router does not fire it: nothing else ever
        // will. Repeated failed builds (a broker SIGHUP reload loop) would
        // accumulate one leaked foreign operation each.
        let abandoned = SubscribeForeignishChild::new(0, false);
        let failing = SubscribeForeignishChild::new(1, true);
        let router = RouterFactoryImpl
            .create_router(
                "r",
                &LayerConfig::new(),
                vec![
                    abandoned.clone() as LayerHandle,
                    failing.clone() as LayerHandle,
                ],
                None,
            )
            .await;
        assert!(
            router.is_err(),
            "the failing child must fail the subscribe pass",
        );
        assert_eq!(
            failing.calls.load(Ordering::SeqCst),
            2,
            "the failure must come from the SUBSCRIBE pass, not the initial \
             rebuild — otherwise this test never reaches the path it covers",
        );

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            abandoned.cancelled.acquire(),
        )
        .await;
        assert!(
            cancelled.is_ok(),
            "the abandoned child's token must be cancelled on ANY subscribe \
             failure, not only on the timeout: a foreign child cannot see a \
             dropped future",
        );
    }

    /// A HEALTHY router child whose `list_address_roots` simply takes a while,
    /// as a remote backend does during cold start. Used to assert the SHAPE of
    /// the fan-out: many of these must cost the slowest one, not their sum.
    struct SlowChild {
        name: String,
        root: Url,
        delay: std::time::Duration,
        roots: RwLock<Vec<RootInfo>>,
    }

    impl SlowChild {
        fn new(index: usize, delay: std::time::Duration) -> Arc<Self> {
            let root = Url::parse(&format!("slow:///c{index}/")).unwrap();
            Arc::new(Self {
                name: format!("slow{index}"),
                roots: RwLock::new(vec![Self::root_info(&root, index)]),
                root,
                delay,
            })
        }

        fn added_root(&self) -> Url {
            self.root.join("added/").unwrap()
        }

        fn root_info(root: &Url, index: usize) -> RootInfo {
            RootInfo {
                root: root.clone(),
                display_name: None,
                layer_kind: "slow".to_string(),
                connection_id: None,
                owning_target: Some(format!("slow{index}")),
                capabilities: Capabilities::empty(),
                range_read_strategy: RangeReadStrategy::default(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: UserMetadata::new(),
            }
        }
    }

    #[async_trait]
    impl Layer for SlowChild {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("slow", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            vec![self.name.clone()]
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            tokio::time::sleep(self.delay).await;
            Ok((
                RootInfoSnapshot {
                    roots: self.roots.read().clone(),
                    updates: false,
                },
                None,
            ))
        }

        async fn add_connection(
            &self,
            _request: Request<LayerConnectionRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            let added = self.added_root();
            self.roots.write().push(RootInfo {
                root: added.clone(),
                ..Self::root_info(&self.root, 0)
            });
            Ok(Connection {
                id: ConnectionId(self.name.clone()),
                backend_kind: "slow".to_string(),
                display_name: self.name.clone(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: vec![added],
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
            })
        }
    }

    #[tokio::test]
    async fn router_mutation_exits_a_stalled_catch_up_and_still_converges() {
        // A child that commits `add_connection` and then stalls its root
        // re-query must not pin the mutation open: the caller's token releases
        // the wait. The answer is `CommitAmbiguous` — the mutation committed,
        // the table had not caught up when the caller left — never `Cancelled`
        // (which would deny a commit that happened) and never `Ok` (which would
        // promise a table that is not yet current). The catch-up owns itself,
        // so it still converges the table once the child answers.
        let child = GatedChild::new();
        let router = Arc::new(Router::new("r", vec![child.clone()], None).await.unwrap());
        let mut rx = router.state.root_change_tx.subscribe();
        let added = Url::parse(GatedChild::ROOT).unwrap();
        assert!(router.route(&added).is_err(), "no route before the add");

        child.stall.store(true, Ordering::SeqCst);
        let caller = CancellationToken::new();
        let mutation = tokio::spawn({
            let router = Arc::clone(&router);
            let caller = caller.clone();
            async move {
                router
                    .add_connection(gated_connection_request(), Some(caller))
                    .await
            }
        });

        // Gate on the child actually being inside the stalled re-query, so the
        // cancel below lands in the post-commit window this exercises.
        let _entered =
            tokio::time::timeout(std::time::Duration::from_secs(5), child.entered.acquire())
                .await
                .expect("the catch-up must reach the child's root re-query");
        caller.cancel();

        let error = tokio::time::timeout(std::time::Duration::from_secs(5), mutation)
            .await
            .expect("a stalled child must not hold the committed mutation open")
            .expect("the mutation task must not panic")
            .expect_err("a released wait cannot report `Ok` for a table that may be stale");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert!(
            !error.code().bucket().retryable(),
            "a blind retry would report AlreadyExists for state that already changed",
        );

        // The caller left; the catch-up did not. Releasing the child converges
        // the route table, announced by the rebuild's snapshot broadcast.
        child.gate.add_permits(1);
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("the released catch-up must broadcast its rebuild")
            .expect("the broadcast must not be dropped");
        assert!(
            router.route(&added).is_ok(),
            "the route table must catch up with the committed connection",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn router_catch_up_costs_its_slowest_child_not_the_sum_of_them() {
        // Sixteen entirely HEALTHY children, two seconds each on a cold start.
        // Queried concurrently that fan-out costs two seconds; one after
        // another it costs thirty-two — past `CHILD_ROOT_QUERY_TIMEOUT`, so every
        // rebuild would fail and the Stack would be permanently unbuildable out
        // of working components. Time is paused, so the whole thing is virtual.
        let delay = std::time::Duration::from_secs(2);
        let children: Vec<Arc<SlowChild>> =
            (0..16).map(|index| SlowChild::new(index, delay)).collect();
        let handles: Vec<LayerHandle> = children
            .iter()
            .map(|child| child.clone() as LayerHandle)
            .collect();
        let router = Router::new("r", handles, None).await.unwrap();

        let started = tokio::time::Instant::now();
        router
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: children[0].name.clone(),
                    connection: ConnectionRequest {
                        backend_kind: "slow".to_string(),
                        config: HashMap::new(),
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .expect("a fan-out over healthy children must not time out");
        let elapsed = started.elapsed();

        assert!(
            elapsed < delay * 3,
            "the fan-out must cost its slowest child, not the sum of all of \
             them; took {elapsed:?} across {} children",
            children.len(),
        );
        assert!(router.route(&children[0].added_root()).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn router_mutation_without_a_token_is_bounded_by_the_catch_up_timeout() {
        // A caller with no cancellation token — `StackBuilder::build` and so
        // every host that composes a Stack through it, including the broker's
        // SIGHUP reload — must still have an exit from a wedged child. Time is
        // paused, so the bound is asserted without any real wait.
        let child = GatedChild::new();
        let router = Router::new("r", vec![child.clone()], None).await.unwrap();
        child.stall.store(true, Ordering::SeqCst);

        let error = router
            .add_connection(gated_connection_request(), None)
            .await
            .expect_err("a wedged child must not pin a token-less mutation open");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        child.gate.add_permits(1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wedged_child_accumulates_at_most_one_catch_up() {
        // A timed-out catch-up is cancelled, but a child that ignores
        // cancellation keeps running anyway. If each timed-out mutation simply
        // spawned another one, a persistently wedged backend would grow tasks
        // and in-flight child calls without bound — a leak in place of the hang
        // the timeout removed. At most ONE catch-up may be in flight per Router.
        let child = GatedChild::new();
        let router = Arc::new(Router::new("r", vec![child.clone()], None).await.unwrap());
        child.stall_all.store(true, Ordering::SeqCst);

        // Three mutations in flight at once, all against the wedged child.
        let mutations: Vec<_> = (0..3)
            .map(|_| {
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    router
                        .add_connection(gated_connection_request(), None)
                        .await
                })
            })
            .collect();
        for mutation in mutations {
            let error = mutation
                .await
                .expect("the mutation task must not panic")
                .expect_err("a wedged child cannot let a mutation confirm its table");
            assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        }

        assert_eq!(
            child.peak_in_flight.load(Ordering::SeqCst),
            1,
            "concurrent mutations must queue for the one catch-up slot rather \
             than each starting its own fan-out against a wedged child",
        );
        assert_eq!(
            child.in_flight.load(Ordering::SeqCst),
            0,
            "and every timed-out catch-up must be cancelled, not left running",
        );
        child.gate.add_permits(3);
    }

    /// Live catch-up tasks, counted by the strong `Arc<RouterState>` each one
    /// holds for its whole life. Everything else that reaches `RouterState`
    /// holds a `Weak`, so above the baseline this counts exactly the catch-ups
    /// that have not ended.
    fn live_catch_ups(router: &Router, baseline: usize) -> usize {
        Arc::strong_count(&router.state) - baseline
    }

    /// Park `count` mutations against a wedged child with no caller left to
    /// bound them, by the route the caller chooses to leave: an explicit token,
    /// or a future that is simply dropped.
    async fn abandon_mutations(router: &Arc<Router>, count: usize, by_token: bool) {
        for _ in 0..count {
            if by_token {
                let caller = CancellationToken::new();
                let mutation = tokio::spawn({
                    let router = Arc::clone(router);
                    let caller = caller.clone();
                    async move {
                        router
                            .add_connection(gated_connection_request(), Some(caller))
                            .await
                    }
                });
                // Let the mutation commit and park on its catch-up, then
                // release the wait the way an impatient caller does.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                caller.cancel();
                let error = mutation
                    .await
                    .expect("the mutation task must not panic")
                    .expect_err("a released wait cannot confirm the table");
                assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
            } else {
                // A dropped future runs NONE of the caller-facing exits — no
                // token fires, no arm of the match is reached.
                let pending = router.add_connection(gated_connection_request(), None);
                futures::pin_mut!(pending);
                assert!(
                    futures::poll!(pending.as_mut()).is_pending(),
                    "the mutation must commit and then park on its catch-up",
                );
            }
        }
    }

    /// The catch-up's deadline belongs to the TASK, not to whoever happens to
    /// be waiting on it. Asserted for both ways a caller leaves.
    async fn abandoned_catch_ups_still_retire(by_token: bool) {
        let child = GatedChild::new();
        let router = Arc::new(Router::new("r", vec![child.clone()], None).await.unwrap());
        let baseline = Arc::strong_count(&router.state);
        child.stall_all.store(true, Ordering::SeqCst);

        abandon_mutations(&router, 3, by_token).await;
        // Let every spawned catch-up be polled at least once: a task upgrades
        // its `Weak<RouterState>` on first poll, so until then it is not yet
        // counted by `live_catch_ups`.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            live_catch_ups(&router, baseline),
            3,
            "each committed mutation owns a catch-up task, so three of them are \
             outstanding at this point — the question is whether they end",
        );

        // Well past the budget every one of them was spawned under.
        tokio::time::sleep(CHILD_ROOT_QUERY_TIMEOUT * 4).await;

        let live = live_catch_ups(&router, baseline);
        assert_eq!(
            live, 0,
            "a catch-up whose waiter is gone must still hit its own deadline \
             and cancel itself; {live} are parked on a wedged child with no \
             deadline at all, one per abandoned mutation, until Router drop",
        );
        child.gate.add_permits(3);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_mutations_do_not_accumulate_deadline_less_catch_ups() {
        abandoned_catch_ups_still_retire(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_mutations_do_not_accumulate_deadline_less_catch_ups() {
        abandoned_catch_ups_still_retire(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_caller_future_still_converges_a_committed_mutation() {
        // A dropped future is NOT a fired cancellation token: an RPC handler
        // dropped on client disconnect runs none of the caller-facing exits. So
        // nothing about a committed mutation's reconcile may live only inside
        // the caller's future — including the wait for the catch-up slot. The
        // task is spawned at commit and queues for the permit itself, so the
        // mutation converges even though the caller is gone.
        let child = GatedChild::new();
        let router = Arc::new(Router::new("r", vec![child.clone()], None).await.unwrap());
        let first = Url::parse(&GatedChild::nth_root(0)).unwrap();
        let second = Url::parse(&GatedChild::nth_root(1)).unwrap();

        // Mutation A commits and its catch-up parks in the child, holding the
        // slot. Its fan-out sampled the roots before B commits below.
        child.stall.store(true, Ordering::SeqCst);
        let mutation_a = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(gated_connection_request(), None)
                    .await
            }
        });
        let _entered =
            tokio::time::timeout(std::time::Duration::from_secs(5), child.entered.acquire())
                .await
                .expect("A's catch-up must reach the child");

        // Mutation B commits, then queues for the slot — and its caller future
        // is dropped there, without its token ever firing.
        {
            let pending = router.add_connection(gated_connection_request(), None);
            futures::pin_mut!(pending);
            assert!(
                futures::poll!(pending.as_mut()).is_pending(),
                "B must still be queued behind A's catch-up",
            );
        }

        // Release A. B has no caller left, but its catch-up is Router-owned, so
        // the table must still end up routing what B committed.
        child.gate.add_permits(2);
        mutation_a
            .await
            .expect("A must not panic")
            .expect("A's catch-up completes once released");

        // Poll with a sleep rather than a yield: under a paused clock a yield
        // loop never lets the runtime go idle, so the timeout below could never
        // fire and a regression would hang instead of failing.
        let converged = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while router.route(&second).is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "a committed mutation whose caller future was dropped must still \
             converge: its catch-up is owned by the router, not by the caller",
        );
        assert!(router.route(&first).is_ok(), "and A's root is still routed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_catch_up_says_it_will_not_converge() {
        // The two ambiguous outcomes give opposite advice, so they must not
        // share wording: a released wait leaves the catch-up running, but a
        // timeout cancels it, and an `updates: false` child has no watcher to
        // repair the table afterwards. Telling that caller to await background
        // convergence would be telling it to wait forever.
        let child = GatedChild::new();
        let router = Router::new("r", vec![child.clone()], None).await.unwrap();
        child.stall_all.store(true, Ordering::SeqCst);

        let timed_out = router
            .add_connection(gated_connection_request(), None)
            .await
            .expect_err("the wedged child cannot complete the catch-up");
        assert_eq!(timed_out.code(), ErrorCode::CommitAmbiguous);
        assert!(
            timed_out.to_string().contains("No further catch-up"),
            "a cancelled catch-up must not promise background convergence: {timed_out}",
        );
    }

    #[tokio::test]
    async fn router_mutation_reports_a_failed_catch_up_and_keeps_the_previous_table() {
        // The wait exists to guarantee the table, so a catch-up that FAILS must
        // surface: a child with no root-update stream has no watcher to repair
        // the table later, so an `Ok` here would strand a connection the caller
        // was told is bound. The previous table survives the failure.
        let child = GatedChild::new();
        let router = Router::new("r", vec![child.clone()], None).await.unwrap();
        let static_root = Url::parse(GatedChild::STATIC_ROOT).unwrap();
        let added = Url::parse(GatedChild::ROOT).unwrap();
        assert!(router.route(&static_root).is_ok());

        child.fail.store(true, Ordering::SeqCst);
        let error = router
            .add_connection(gated_connection_request(), None)
            .await
            .expect_err("a failed catch-up must not be reported as success");
        // The child's own error is `Transient`, whose contract invites a blind
        // retry — which here would re-issue a mutation that already committed
        // and get `AlreadyExists`. A post-commit failure must report the
        // ambiguity instead, and carry the cause in its message.
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert!(
            !error.code().bucket().retryable(),
            "a blind retry would report AlreadyExists for state that already changed",
        );
        assert!(
            error.to_string().contains("root re-query failed"),
            "the child's error must survive as diagnosis: {error}",
        );

        assert!(
            router.route(&added).is_err(),
            "the failed rebuild published nothing",
        );
        assert!(
            router.route(&static_root).is_ok(),
            "and left the previous table intact rather than emptying it",
        );
    }

    #[tokio::test]
    async fn router_rebuild_does_not_roll_the_table_back_to_an_older_snapshot() {
        // A catch-up orphaned by a released wait outlives its caller, so it can
        // finish after a later one has already published. Its snapshot is the
        // older one; installing it would drop a connection whose caller was
        // told the table was current, with no watcher to repair it.
        let child = GatedChild::new();
        let router = Router::new("r", vec![child.clone()], None).await.unwrap();
        let added = Url::parse(GatedChild::ROOT).unwrap();

        // Subscribed before anything publishes, so the broadcast can be asserted
        // on as well as the table: a stream consumer has no route table of its
        // own to fall back on, so a stale snapshot reaching it is a regression
        // the table assertions below cannot see.
        let mut rx = router.state.root_change_tx.subscribe();

        // The straggler samples the children (no `added` root yet), then stalls.
        let stale_generation = router.state.next_generation();
        child.stall.store(true, Ordering::SeqCst);
        let straggler = tokio::spawn({
            let state = Arc::clone(&router.state);
            async move { state.rebuild(stale_generation, None).await }
        });
        let _entered =
            tokio::time::timeout(std::time::Duration::from_secs(5), child.entered.acquire())
                .await
                .expect("the straggler must reach the child's root re-query");

        // A later mutation commits and publishes, under a higher generation.
        router
            .add_connection(gated_connection_request(), None)
            .await
            .expect("add_connection");
        assert!(router.route(&added).is_ok());

        // Now let the straggler finish. Its older snapshot must be discarded.
        child.gate.add_permits(1);
        tokio::time::timeout(std::time::Duration::from_secs(5), straggler)
            .await
            .expect("the straggler must finish")
            .expect("the straggler must not panic")
            .expect("a superseded rebuild is not an error, just a no-op");
        assert!(
            router.route(&added).is_ok(),
            "a superseded rebuild must not roll the table back",
        );

        // The mutation's own rebuild broadcast one snapshot, carrying `added`.
        // The straggler must have broadcast NOTHING: its snapshot predates
        // `added`, and a subscriber that received it would be left believing the
        // root is gone with nothing to re-query against.
        let mut snapshots = Vec::new();
        while let Ok(RootInfoChange::Snapshot(roots)) = rx.try_recv() {
            snapshots.push(roots);
        }
        assert_eq!(
            snapshots.len(),
            1,
            "a superseded rebuild must not broadcast its stale snapshot",
        );
        assert!(
            snapshots[0].iter().any(|root| root.root == added),
            "and the one broadcast is the winning generation's: {:?}",
            snapshots[0],
        );
    }

    #[tokio::test]
    async fn router_mutation_catch_up_precedes_a_successful_return() {
        // Characterization of the read-after-write contract every host relies
        // on: a mutation that returns `Ok` has a table that routes what it just
        // bound.
        let child = GatedChild::new();
        let router = Router::new("r", vec![child.clone()], None).await.unwrap();
        let added = Url::parse(GatedChild::ROOT).unwrap();

        router
            .add_connection(gated_connection_request(), None)
            .await
            .expect("add_connection");

        assert!(
            router.route(&added).is_ok(),
            "the route must be live the instant the mutation returns",
        );
    }

    #[tokio::test]
    async fn router_watcher_resyncs_on_stream_error_instead_of_terminating() {
        // A `BroadcastStream` `Lagged` (mapped to an Error) must trigger a
        // resync, not kill the watcher. Feed [Err, Ok]: the watcher must
        // process *past* the error, producing a rebuild broadcast for each
        // item (two), not break on the first error (zero/one).
        let router = Arc::new(Router::new("r", Vec::new(), None).await.unwrap());
        let mut rx = router.state.root_change_tx.subscribe();
        let stream: RootInfoUpdateStream = Box::pin(futures::stream::iter(vec![
            Err(Error::new(ErrorCode::Internal, "lagged")),
            Ok(RootInfoChange::Snapshot(Vec::new())),
        ]));
        spawn_root_watcher(Arc::downgrade(&router), stream, router.cancel.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut count = 0;
            while count < 2 {
                match rx.recv().await {
                    Ok(_) => count += 1,
                    Err(_) => break,
                }
            }
            count
        })
        .await
        .expect("watcher should resync and broadcast, not hang or terminate early");
        assert_eq!(
            received, 2,
            "watcher must resync on the error and keep processing"
        );
    }

    #[tokio::test]
    async fn router_watcher_backs_off_on_consecutive_errors_without_terminating() {
        // A bridged v2-plugin stream can yield `Err` on every poll. The watcher
        // must neither terminate (freezing the route table) nor hot-loop:
        // consecutive errors incur exponential backoff, reset by any `Ok`. Feed
        // [Err×4, Ok] and require (a) all five processed — five rebuild
        // broadcasts, proving non-termination — and (b) the four backoffs
        // (50+100+200+400ms) make the burst take a measurable minimum, so the
        // test fails if the backoff brake is removed (the burst would finish
        // near-instantly). The lower-bound assertion is robust to slow CI: a
        // sleep can only make the burst *longer*.
        let router = Arc::new(Router::new("r", Vec::new(), None).await.unwrap());
        let mut rx = router.state.root_change_tx.subscribe();
        let stream: RootInfoUpdateStream = Box::pin(futures::stream::iter(vec![
            Err(Error::new(ErrorCode::Internal, "e1")),
            Err(Error::new(ErrorCode::Internal, "e2")),
            Err(Error::new(ErrorCode::Internal, "e3")),
            Err(Error::new(ErrorCode::Internal, "e4")),
            Ok(RootInfoChange::Snapshot(Vec::new())),
        ]));
        let start = tokio::time::Instant::now();
        spawn_root_watcher(Arc::downgrade(&router), stream, router.cancel.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut count = 0;
            while count < 5 {
                match rx.recv().await {
                    Ok(_) => count += 1,
                    Err(_) => break,
                }
            }
            count
        })
        .await
        .expect("watcher must process the whole burst, not hang or terminate");
        assert_eq!(
            received, 5,
            "watcher must process every item past the consecutive errors"
        );
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(500),
            "consecutive errors must incur backoff, not hot-loop (elapsed {:?})",
            start.elapsed()
        );
    }
}
