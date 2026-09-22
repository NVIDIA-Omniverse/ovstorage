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
    /// Serializes connection ADDS against each other, held across the child
    /// commit, the exclusivity check, any rollback, and the route-table
    /// catch-up.
    ///
    /// Graph-wide prefix exclusivity is a read-then-act on the route table, and
    /// the `Layer` API asks no caller to serialize mutations. Without this, two
    /// adds on different children both commit, both read the same pre-add table,
    /// both find nothing, and both succeed — leaving exactly the
    /// registered-but-unroutable connection
    /// [`Router::cross_child_conflict`] exists to prevent.
    ///
    /// **It has to span the child commit, not merely the check.** Serializing
    /// only the check-and-catch-up does not work: the first add's catch-up
    /// re-queries every child, so it publishes the second child's
    /// already-committed root too, and the second add's lookup then hits its own
    /// root, reads `Arc::ptr_eq(serving, child)` as same-child, and passes. The
    /// newcomer's root must not exist anywhere until the incumbent's cycle has
    /// finished.
    ///
    /// [`RouterState::catch_up_slot`] cannot do this job: it is acquired inside the
    /// spawned catch-up, long after the check has read the table, and it is
    /// deliberately held by the catch-up rather than by the mutation.
    ///
    /// Removals and attribute updates do not take it. Neither can create a
    /// second claim on a root — a removal only frees one — so neither can
    /// invalidate a check that has already passed, and the catch-ups they queue
    /// are ordered by generation as before.
    ///
    /// **Waiting on it observes the caller's token**, because a queue is exactly
    /// where a caller gives up: a wait that ignored cancellation handed the
    /// child an add its caller had abandoned, and a child may not check either
    /// — `FileBackend::add_connection` does not — so it registered and reported
    /// success. `Router::add_connection` therefore races the token against the
    /// acquisition and re-checks with the guard in hand.
    ///
    /// **Serializing is necessary and not sufficient**, which is what
    /// [`RouterState::claimed_roots`] is for. Holding this across the catch-up
    /// orders the adds; it does not make the table current when the gate is
    /// released, because that wait is detachable by contract — a fired caller
    /// token releases it while the catch-up runs on, and a failed or timed-out
    /// catch-up ends with the table never updated at all. Ordering alone would
    /// therefore hand the next add a table that is stale rather than pre-add.
    add_gate: tokio::sync::Mutex<()>,
    /// Roots a committed add has bound that the route table may not show yet.
    ///
    /// The exclusivity check reads the route table, and the table is only ever
    /// as current as the last catch-up that PUBLISHED. That is not the same as
    /// the last catch-up a caller waited for: [`Router::route_catch_up`] is
    /// detachable on purpose — a fired caller token releases the wait with the
    /// catch-up still running, and a fan-out that fails, times out or panics
    /// ends with nothing published and nothing rescheduled. In every one of
    /// those cases the child has COMMITTED the connection while the table has
    /// never heard of its root, so the next add on a sibling child would read
    /// the pre-add table, find the node free, and bind it too —
    /// [`RouterState::add_gate`] cannot prevent that, because by then the first
    /// add has released it.
    ///
    /// So the claim is recorded from the add itself, immediately after the check
    /// passes and before the catch-up is waited on, and the check consults it
    /// alongside the table. It is the committed fact; the table is a projection
    /// of it that may lag.
    ///
    /// **A claim is released when a rebuild has demonstrably included it**, and
    /// the generation is what demonstrates it: the stamp is taken after the
    /// child commits and before the catch-up is spawned, so any rebuild carrying
    /// a generation at least as high queried the children after that commit and
    /// therefore saw the root (or saw it already gone). Releasing on
    /// `generation <= applied_generation` is that statement, and it is why a
    /// claim needs no explicit removal path: a connection removed while its
    /// claim is outstanding frees the node as soon as the removal's own catch-up
    /// publishes, which stamps a higher generation.
    ///
    /// The set is therefore empty in the ordinary case — a healthy graph
    /// publishes on every add — and bounded by the adds since the last rebuild
    /// that got through when it is not.
    claimed_roots: Mutex<Vec<ClaimedRoot>>,
    /// The cross-child collisions last reported, so a standing misconfiguration
    /// is named once rather than on every rebuild. See
    /// [`RouterState::report_cross_child_collisions`].
    reported_collisions: Mutex<Vec<CrossChildCollision>>,
    /// Connections this Layer refused whose removal it could not confirm.
    ///
    /// A refused add that is still registered on its child is not refused yet:
    /// it holds probed credentials and would begin serving the moment the root
    /// it collided with went away. Until the child confirms it is gone, every
    /// root it publishes is kept out of the table — see
    /// [`Router::roll_back_conflicting_add`], which records the entry before
    /// attempting the removal so a dropped caller cannot lose it.
    quarantined: Mutex<Vec<Quarantined>>,
    root_change_tx: broadcast::Sender<RootInfoChange>,
}

/// One root bound by a committed add, waiting for a rebuild to prove the table
/// knows about it. See [`RouterState::claimed_roots`].
struct ClaimedRoot {
    /// The address as the connection published it; compared by node, exactly as
    /// the table lookup is.
    node: Url,
    /// Which child committed it — the same `Arc::ptr_eq` identity the table
    /// comparison uses, so a claim can be recognised as this child's own and
    /// left to the child's intra-child exclusivity.
    child: LayerHandle,
    /// The catch-up generation stamped for this add.
    generation: u64,
}

impl Drop for Router {
    fn drop(&mut self) {
        // Stops the per-child root watchers and any in-flight detached
        // route-table catch-up deterministically instead of relying on each
        // child's broadcast sender being dropped.
        self.cancel.cancel();
    }
}

/// [`Router::attribute_row`]'s body, over the state rather than the `Router`.
///
/// Free so the `authenticate_connection` stream can carry it: that stream
/// outlives the call that made it, and `AuthEvent::Succeeded` carries a
/// `Connection` that goes through the same rule as the other five paths. A
/// cloned `Arc<RouterState>` is what lets the route lookup stay LIVE there
/// rather than being a snapshot taken when the flow opened.
///
/// `candidate` is the target to offer where the row has none, or to correct to
/// where the row names a sibling's. The five host-side paths derive it from
/// the child's `owned_targets`; the auth path supplies its request key. It is
/// offered, not imposed — a self-report that routes back to this child is left
/// alone.
fn attribute_row_in(
    state: &RouterState,
    child: &LayerHandle,
    candidate: &Option<String>,
    connection: &mut Connection,
) {
    match &connection.owning_target {
        None => connection.owning_target = candidate.clone(),
        Some(target) => {
            let routed = state.targets.read().get(target).cloned();
            if let Some(routed) = routed
                && !Arc::ptr_eq(&routed, child)
            {
                // **Corrected where the truth is knowable, cleared only
                // where it is not.** Clearing alone is not a safe remedy:
                // `None` reads as "never attributed" to every consumer, and
                // one of them — the rotation's listing lookup — takes an
                // unattributed row as a stand-in for whatever key it was
                // given. A row cleared here would then be adopted for the
                // very sibling key it misnamed, which is the outcome this
                // arm exists to prevent.
                //
                // A child declaring EXACTLY ONE owned target has a knowable
                // answer, and it is verified rather than guessed: it comes
                // from the same `owned_targets()` call `state.targets` is
                // built from, so it routes back to this child by
                // construction. Any other count — several targets, or none
                // at all, which is the shape a layer gating `owned_targets`
                // on `supports_runtime_add` presents — has no such answer
                // and falls back to `None`, where the residual risk is the
                // narrow one above.
                match candidate {
                    Some(corrected) => {
                        tracing::warn!(
                            target: "ovstorage.router",
                            layer = %child.name(),
                            connection.target = %target,
                            connection.corrected_target = %corrected,
                            connection.id = %connection.id.0,
                            "router: a child reported a connection owned by a sibling's \
                             target; correcting it to the target that reaches this child"
                        );
                        connection.owning_target = candidate.clone();
                    }
                    None => {
                        tracing::warn!(
                            target: "ovstorage.router",
                            layer = %child.name(),
                            connection.target = %target,
                            connection.id = %connection.id.0,
                            "router: a child declaring no single owned target reported a \
                             connection owned by a sibling's target; clearing it so the \
                             row is not addressed there"
                        );
                        connection.owning_target = None;
                    }
                }
            }
        }
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
                add_gate: tokio::sync::Mutex::new(()),
                claimed_roots: Mutex::new(Vec::new()),
                reported_collisions: Mutex::new(Vec::new()),
                quarantined: Mutex::new(Vec::new()),
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
        // Stamp the generation at COMMIT — this is the first thing after the
        // mutation landed, before any await — so the ordering `rebuild`
        // enforces is commit order rather than permit-acquisition order.
        self.route_catch_up_at(self.state.next_generation(), cancel)
            .await
    }

    /// [`Router::route_catch_up`] on a generation the caller has already
    /// stamped, for `add_connection`, which needs the stamp before this call:
    /// its claim on the roots it just bound is released by generation, so the
    /// claim and the catch-up have to be the same one. Stamping it there also
    /// keeps the stamp where the doc above says it belongs — immediately after
    /// the commit, with no await in between.
    async fn route_catch_up_at(
        &self,
        generation: u64,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // This catch-up's own token: cancelling on timeout must stop THIS
        // catch-up without disturbing the Router's watchers or a sibling
        // mutation's.
        let catch_up_cancel = self.cancel.child_token();
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

    /// The child serving `url`, by the shared [`RouteTable`]'s two tiers: the
    /// longest matching prefix, then — when no prefix matches and the address
    /// carries no credential in its query — the marked scheme fallback root for
    /// `url.scheme()`. The second tier is a property of the table, not of this
    /// Router, so an unrouted address on a granted scheme reaches the child
    /// that published the marked scheme root without any Router-side rule;
    /// with no such root in the table the answer is the byte-identical
    /// `NoRoute` an unrouted address always had.
    fn route(&self, url: &Url) -> Result<LayerHandle> {
        self.state
            .routes
            .read()
            .lookup(url)
            .map(|(_, child)| child.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    /// Attribute one row a `child` produced, by the rule the fan-out applies.
    ///
    /// The rule for **all six** `Connection`-bearing exits: the
    /// `list_connections` fan-out, the four ops that return one (`probe`,
    /// `add_connection`, `update_connection_credentials`,
    /// `update_connection_attributes`), and the `AuthEvent::Succeeded` a
    /// forwarded auth stream carries.
    ///
    /// **No path ever answers with a target another path contradicts.** That is
    /// the invariant, and it is weaker than "one answer everywhere" on purpose:
    /// the paths differ in whether they can answer AT ALL. A caller that reads
    /// a listing and then calls `probe` for the same connection must not see
    /// the field change under it, and does not — those five share a candidate
    /// source. `authenticate_connection` has a source the others do not, so for
    /// one child class it answers where they decline; see below. What is
    /// excluded is two paths naming two DIFFERENT targets for one row, which no
    /// arm of this rule can produce **from one topology**.
    ///
    /// That scope is load-bearing, so it is stated rather than left implied.
    /// Every input here is read live: the fan-out and `attribute_one` take
    /// independent `owned_targets()` reads, and the deference arm re-reads the
    /// target table. So two observations separated by a child changing what it
    /// owns, or by a rebuild, can differ on ANY pair of paths — a child owning
    /// `{T}` when listed and `{U}` when probed answers `T` then `U` with no
    /// auth path in sight. That is the topology moving under the caller, not
    /// two arms of this rule disagreeing, and reading a row twice across a
    /// rebuild is inherently a question about two graphs.
    ///
    /// **A caller that lists a multi-target child's row and then authenticates
    /// it sees `None`, then `Some(key.target)`.** The listing declined because
    /// flattening lost which of that child's targets holds the row; the auth
    /// path answered because the request names it. Declining and then answering
    /// is not the disagreement the deference arm protects against — that one is
    /// about overwriting an answer a child stands behind, and it still holds.
    /// `a_child_owning_several_targets_leaves_its_rows_unattributed` and
    /// `the_auth_path_answers_for_a_composite_child_that_owned_targets_cannot`
    /// pin the two halves on one fixture, deliberately.
    ///
    /// **What the auth answer rests on is the plugin contract, not this rule.**
    /// `route_target` proves the key reaches the child; that the row the child
    /// yields is the one the key named is the child's own obligation — *answer
    /// `NotFound` for a `ConnectionKey` you do not hold* — which the host cannot
    /// verify, and which `docs/public/plugin-development/README.md` already
    /// names as unenforceable. A child that returns some other row of its own
    /// gets that row labelled with the key that was asked for.
    ///
    /// The plugin boundary one level down chose the other way and is worth
    /// contrasting rather than citing: `ForeignVtableLayer` feeds its auth
    /// stream the same `sole_owning_target` as its listing, so it answers
    /// `None` on every path for a composite and the graph is asked instead.
    ///
    /// **What differs between the paths is only where the candidate comes
    /// from**, not what is done with it. The five here derive it from the
    /// child's `owned_targets` — the fan-out hoisting it once per child rather
    /// than once per row — because flattening loses which of a child's targets
    /// holds a given row. `authenticate_connection` supplies the request key
    /// instead, which its `route_target` has already proved reaches the child
    /// and which cannot go stale across an interactive sign-in. Either way the
    /// candidate is offered, not imposed: it fills an unattributed row,
    /// corrects one naming a sibling's target, and leaves a correct
    /// self-report alone.
    ///
    /// The body is [`attribute_row_in`], which takes the state rather than the
    /// `Router` so a `'static` stream closure can hold it.
    fn attribute_row(
        &self,
        child: &LayerHandle,
        candidate: &Option<String>,
        connection: &mut Connection,
    ) {
        attribute_row_in(&self.state, child, candidate, connection);
    }

    /// [`Router::attribute_row`] for a single-row op, which has no fan-out to
    /// hoist the child's sole target out of.
    fn attribute_one(&self, child: &LayerHandle, connection: &mut Connection) {
        let sole_target = ovstorage_layer::sole_owning_target(&child.owned_targets());
        self.attribute_row(child, &sole_target, connection);
    }

    fn route_target(&self, target: &str) -> Result<LayerHandle> {
        self.state
            .targets
            .read()
            .get(target)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "target layer not found"))
    }

    /// Prefix exclusivity across the graph's add path: the refusal a child
    /// cannot raise for itself.
    ///
    /// A connection-owning child enforces exclusivity over **its own** roots —
    /// plugin-http's `install` scans one instance state, nucleus keys on its
    /// own reserved roots — and no child can see a sibling's. So two HTTP
    /// children whose connections differ only in userinfo each accept, each
    /// probe (two distinct credentials reaching the origin), and the route
    /// table keeps both: one routes, the other is registered, unroutable and
    /// silently unused, with every read served by whichever root the
    /// aggregation happened to rank first. **The aggregation boundary is the
    /// only place that collision is visible, so this is where it is refused.**
    ///
    /// **What it reaches is the ADD path, which is not everything.** This has
    /// one call site, [`Router::add_connection`], so it sees connections that
    /// arrive through this Layer: the declared `[[ovstorage.connections]]`
    /// entries the host applies that way, and the CLI's `connect`. A backend
    /// that builds a connection from its own layer config installs it inside
    /// itself before any Router exists — `HttpBackendLayerFactory::create_backend`
    /// does, for a non-empty `[ovstorage.layers.<name>]` block — and this Layer
    /// first meets that root in its construction fan-out, where `RouteTable`
    /// shadows the overlap and warns. Two same-kind layers configured against
    /// one origin therefore still both register, exactly as before this refusal
    /// existed. Extending enforcement there means failing the BUILD, since there
    /// is no add to refuse and no caller to tell, which is a separate decision
    /// with its own compatibility cost; until it is made, the docs say where the
    /// line is (`plugin-http.md`) and
    /// `a_build_time_seed_is_outside_the_add_path_and_is_only_shadowed` pins it.
    ///
    /// Same node, not containment. A sibling root that merely *contains* the
    /// newcomer's — `x://h/a/` against `x://h/a/b/` — is independently routable
    /// under longest-prefix lookup and stays legal; refusing it would also
    /// break the requirement the startup skip arm places on `RouteConflict`
    /// (`ovstorage-layer`'s `StackBuilder::build_with_cancel`), which is sound
    /// only when the newcomer's addresses resolve to the incumbent. Node
    /// equality is what makes that true, and it is the comparison the route
    /// table itself uses, so `assets` and `assets/` are one root here exactly
    /// as they are there.
    ///
    /// A hit served by the SAME child is not a conflict of this Layer's making:
    /// intra-child exclusivity is the child's own contract, and the child has
    /// already applied it (or deliberately allows the overlap, as an alias
    /// layer's synthesized roots do).
    ///
    /// **Only a TOTAL collision is refused.** A connection may publish many
    /// roots — broker and services-client both assign a whole discovered `Vec`
    /// to `current_addresses`, where plugin-http and nucleus publish exactly
    /// one — and the refusal costs the caller the whole connection: this Layer
    /// rolls it off its child, and at startup `StackBuilder::build_with_cancel`
    /// skips the declared connection outright. That is free only when every
    /// address the newcomer would answer for already resolves to an incumbent,
    /// which is precisely the precondition that skip arm states for itself. A
    /// connection with five roots of which one collides has four address spaces
    /// that route perfectly well, and refusing would delete them to prevent a
    /// duplicate on the fifth — behind a `warn` the CLI does not even print
    /// unless `RUST_LOG` is set. So a partial collision is SHADOWED instead,
    /// which is what the route table does with an overlap on its own, and the
    /// connection is kept.
    ///
    /// **The NEWCOMER is the shadowed side**, and that does not fall out of the
    /// route table on its own: it breaks an overlap by aggregation order, which
    /// here is the order the children sit in the graph, so a newcomer on an
    /// earlier child would otherwise take the route a later child's connection
    /// is already serving — an outcome nobody chose and no operator can see.
    /// [`RouterState::incumbents_first`] fixes the direction, and it is what
    /// makes the paragraph above true: the caller keeps every address space it
    /// serves alone and loses only the contested one, which it never served.
    ///
    /// The single-root producers are unaffected by that distinction: for them
    /// any collision is total, so the refusal this exists for still fires.
    ///
    /// **What keeping it leaves behind, stated plainly.** The kept connection
    /// goes on publishing the contested root: it stays in that connection's
    /// `current_addresses` and in the child's `RootInfo` set, so a listing shows
    /// it against an address the incumbent answers for, while reads there are
    /// served by the incumbent. For that one root this is the
    /// registered-but-not-serving state the refusal exists to prevent, and it is
    /// a real cost of the trade above rather than an oversight.
    ///
    /// Refusing the whole connection is not the way out of it. That was the
    /// behaviour once, and it was wrong for the reason the paragraph above
    /// gives: it deletes address spaces nothing else serves in order to prevent
    /// a duplicate on one, and it breaks the requirement the startup skip arm
    /// places on `RouteConflict` — that arm skips a declared connection *because*
    /// its addresses resolve to the incumbent regardless, which is false the
    /// moment the connection also serves roots of its own.
    ///
    /// The way out is the one this Layer does not have: a verb that removes the
    /// contested root from the CHILD's published state, leaving the rest of the
    /// connection intact. `update_connection_attributes` patches a connection's
    /// presentation and visibility, not its root set, and nothing else on the
    /// `Layer` API un-publishes one root of many — so the Router can decline to
    /// route a root, which it does, but cannot make the child stop advertising
    /// it. Adding that is a `Layer`-contract change every connection-owning
    /// backend would have to implement, and it is the thing to build if this
    /// residue needs to go.
    ///
    /// Until then it is reported rather than left to be found:
    /// [`RouterState::report_cross_child_collisions`] names the node and both
    /// layers wherever roots are aggregated, and `ovstorage doctor` lists it
    /// under contested address roots.
    ///
    /// The table read is the pre-add one — this runs before
    /// [`Router::route_catch_up`], so the newcomer's own roots are not in it
    /// yet. That is a read-then-act, and it is only a decision at all because
    /// [`RouterState::add_gate`] holds every other add out of the window
    /// between this read and the catch-up that publishes what it approved. The
    /// `Layer` API asks no caller to serialize mutations, so nothing outside
    /// this Layer establishes that ordering.
    ///
    /// **The table is not the whole answer, and on its own it is not even a
    /// sound one.** A catch-up publishes only when it gets through: a caller's
    /// fired token releases the wait while the catch-up runs on, and a fan-out
    /// that fails or times out ends with nothing published and nothing
    /// rescheduled. Both leave a root committed on a child and absent from the
    /// table, and the gate is released either way — so the next add would read a
    /// table that is stale rather than pre-add and bind the node a second time.
    /// [`RouterState::claimed_roots`] carries those committed-but-unpublished
    /// bindings, and is consulted here on equal terms with the table. Answers
    /// returned: `Ok` names the addresses the caller may claim (every address it
    /// publishes that nothing else holds), and `Err` is the total-collision
    /// refusal.
    ///
    /// One narrower race remains, and it is the child's to lose: a child that
    /// publishes a root-update stream can race a watcher rebuild into the same
    /// window and land its own new root in the table first. The hit is then
    /// same-child, and the collision is missed. Closing it would mean gating
    /// the watchers on the add path, which would let one wedged child stall
    /// every other child's route updates — a worse failure than the duplicate
    /// it would prevent, and one that would bite a healthy graph rather than a
    /// misconfigured one.
    fn cross_child_conflict(
        &self,
        child: &LayerHandle,
        connection: &Connection,
        claimable: &[Url],
    ) -> Result<Vec<Url>> {
        // Snapshotted rather than held across the table read, so the two locks
        // are never held at once and no ordering between them can arise. Safe
        // because claims only ever leave this set after the table already shows
        // the root: a claim missing here is a root the table below has.
        let claimed: Vec<(Url, LayerHandle)> = self
            .state
            .claimed_roots
            .lock()
            .iter()
            .map(|claim| (claim.node.clone(), claim.child.clone()))
            .collect();
        let routes = self.state.routes.read();
        let mut collided: Option<&Url> = None;
        let mut routable = Vec::new();
        for address in claimable {
            // The prefix tier alone. This check asks who serves this exact
            // node, and a scheme fallback root never names a node an incoming
            // connection could collide with: `s3:///` is not the node of
            // `s3://bucket/`, so the `same_node` guard below already discards
            // a second-tier hit. Reading the first tier states the intent
            // instead of relying on the guard to undo an answer to a question
            // this check did not ask.
            let taken = routes
                .lookup_prefix(address)
                .is_some_and(|(root, serving)| {
                    !Arc::ptr_eq(serving, child) && address::same_node(&root.root, address)
                })
                || claimed.iter().any(|(node, owner)| {
                    !Arc::ptr_eq(owner, child) && address::same_node(node, address)
                });
            if taken {
                if collided.is_none() {
                    collided = Some(address);
                }
            } else {
                routable.push(address.clone());
            }
        }
        // No collision at all — and the same arm for a connection publishing no
        // roots yet, which a broker-backed one does while it is parked.
        let Some(collided) = collided else {
            return Ok(routable);
        };
        if !routable.is_empty() {
            // Every address is named only by its origin, here as in the refusal
            // below: the rest of a route prefix — userinfo, a signed-URL query,
            // a capability token in the path — can carry a secret, and the
            // shared redaction pass recognises only some of them.
            tracing::warn!(
                target: "ovstorage.router",
                router = %self.name,
                connection.id = %connection.id.0,
                address = %ovstorage_plugin::redact::origin_only(collided),
                "router: a root this connection publishes is already served by another layer \
                 in this graph. The connection is kept, because refusing it would also discard \
                 the address spaces it serves alone — but it goes on ADVERTISING the contested \
                 root while reads there are served by the incumbent, so a listing will show it \
                 against an address it does not answer for. Give the two connections distinct \
                 prefixes to clear it"
            );
            return Ok(routable);
        }
        Err(Error::new(
            ErrorCode::RouteConflict,
            format!(
                "another layer in this graph already serves an address prefix on '{}'",
                ovstorage_plugin::redact::origin_only(collided)
            ),
        ))
    }

    /// The addresses this connection actually publishes a ROUTE for.
    ///
    /// **`current_addresses` is not that set.** It is what a connection lists,
    /// and a Layer may list an address it does not serve: the in-tree
    /// `AliasWrapper` gives a visibility-override connection the arbitrary
    /// address its rule governs, while `project_advertised_roots` publishes a
    /// root only for a `Visible` one — so a `Hidden` or `Suppressed` override
    /// lists a scope and routes nothing at all. Read as route claims, those
    /// entries made a valid visibility rule collide with whatever sibling
    /// happens to serve the address it governs, and the add was refused and
    /// rolled back for a conflict that did not exist.
    ///
    /// So the child is asked. An address counts only when the child publishes a
    /// root at that node AND that root is this connection's — or carries no
    /// connection id at all, which is a child that does not attribute its roots
    /// rather than one disclaiming them. A root there belonging to a DIFFERENT
    /// connection on the same child is not this one's claim to answer for.
    ///
    /// A query that cannot be answered falls back to `current_addresses`: that
    /// is the pre-existing reading, so exclusivity keeps whatever protection it
    /// had, and the only cost is the false refusal above in a graph already
    /// failing to answer about itself. The alternative — claiming nothing —
    /// would let a genuine duplicate through on any child that stumbles.
    ///
    /// The reviewer's other route to this, extending `add_connection` to return
    /// the roots it bound, would say it more directly but moves the `Layer`
    /// contract and every implementor with it; this needs neither.
    async fn published_claims(&self, child: &LayerHandle, connection: &Connection) -> Vec<Url> {
        let cx = Extensions::new();
        let queried = bounded_child_call(&self.cancel, |token| {
            child.list_address_roots(&cx, Some(token))
        })
        .await;
        let Ok(Ok((snapshot, _updates))) = queried else {
            return connection.current_addresses.clone();
        };
        connection
            .current_addresses
            .iter()
            .filter(|address| {
                snapshot.roots.iter().any(|root| {
                    address::same_node(&root.root, address)
                        && root
                            .connection_id
                            .as_ref()
                            .is_none_or(|id| *id == connection.id)
                })
            })
            .cloned()
            .collect()
    }

    /// Reserve what a child publishes after it reported a committed-but-
    /// unconfirmed add, so exclusivity survives an add this Layer could not
    /// finish.
    ///
    /// **Why there is anything to do.** `add_connection` answering
    /// [`ErrorCode::CommitAmbiguous`] means the mutation landed — a child Router
    /// raises it when its own post-commit catch-up fails, with the connection
    /// registered on ITS child. The parent gets an error and no `Connection`, so
    /// it cannot run the exclusivity check or record a claim, and its route table
    /// does not have the new roots either, because the failure that produced this
    /// code is precisely the reconcile that would have published them. Left
    /// there, the very next add on a sibling child reads a table and a claim set
    /// that have never heard of those roots and binds one of them — two
    /// connections on one node, which is the state this Layer exists to prevent.
    ///
    /// **The recovery is a query, and it runs under the add gate.** Ask the child
    /// what it publishes now and claim all of it. Claiming a root this child
    /// already served is harmless: [`Router::cross_child_conflict`] skips claims
    /// held by the child being added to, so this constrains siblings and not the
    /// child itself — which is the same constraint the route table would impose
    /// once it catches up. The generation stamp makes it self-clearing, exactly
    /// as an ordinary add's claim is: the first rebuild that publishes at or
    /// above it drops these.
    ///
    /// On the Router's own token, because the caller's may be the reason the
    /// child could not confirm in the first place, and a reservation skipped for
    /// that reason would leave the hole this closes. A query that fails anyway
    /// is warned about: nothing else can be reserved from here, and short of the
    /// child carrying its committed roots on the error there is no other way to
    /// learn them.
    async fn reserve_after_ambiguous_commit(&self, child: &LayerHandle) {
        // Stamped before the query, so any rebuild that releases this claim
        // fanned out afterwards and has therefore seen the same roots.
        let generation = self.state.next_generation();
        let cx = Extensions::new();
        let queried = bounded_child_call(&self.cancel, |token| {
            child.list_address_roots(&cx, Some(token))
        })
        .await;
        let roots = match queried {
            Ok(Ok((snapshot, _updates))) => snapshot.roots,
            Ok(Err(error)) => {
                self.warn_unreserved(child, &format!("{error}"));
                return;
            }
            Err(_elapsed) => {
                self.warn_unreserved(
                    child,
                    &format!("it did not answer within {CHILD_ROOT_QUERY_TIMEOUT:?}"),
                );
                return;
            }
        };
        self.state.claim_roots(
            child,
            roots.into_iter().map(|root| root.root).collect(),
            generation,
        );
    }

    /// Say plainly that exclusivity is unguarded for one child until a rebuild
    /// catches up — the residue of [`Router::reserve_after_ambiguous_commit`]
    /// when even the recovery query cannot be answered.
    fn warn_unreserved(&self, child: &LayerHandle, error: &str) {
        tracing::warn!(
            target: "ovstorage.router",
            router = %self.name,
            layer = %child.name(),
            error = %error,
            "router: a child reported a committed add it could not confirm, and then could not \
             say what it publishes; the roots that add bound are unknown to this Layer until a \
             rebuild succeeds, so a sibling add on one of them would not be refused"
        );
    }

    /// Undo an add this Layer refused after the child committed it, and answer
    /// with the error the caller should see.
    ///
    /// **The refusal is only a refusal if the add is gone.** Until the child has
    /// removed it, the connection is committed: registered, holding credentials
    /// it has already probed with, and one rebuild away from serving the moment
    /// the incumbent's root goes away. Reporting `RouteConflict` over that says
    /// nothing happened, which is the one thing that is not true — and it is the
    /// case the `Layer` contract reserves [`ErrorCode::CommitAmbiguous`] for, the
    /// same code [`Router::route_catch_up`] raises when a mutation lands and its
    /// reconcile does not. So the removal's outcome decides the answer:
    /// `RouteConflict` when the child confirms it is gone, `CommitAmbiguous`
    /// naming the target and id when it does not.
    ///
    /// **A `CommitAmbiguous` from the REMOVAL is a removal that happened**, not
    /// one that failed — that is what the code means, and it is what this very
    /// Layer answers when a child lets go and its catch-up does not follow, so a
    /// nested Router hands it back for exactly that. Reading it as a failure
    /// told the caller the ADD had stuck, and the CLI keeps the declaration for
    /// a `CommitAmbiguous` add, so `write-config` persisted an entry for a
    /// connection that had been rolled back and the next startup recreated it.
    /// Membership is treated as removed and the caller gets the plain conflict.
    /// Only the quarantine stays: a child that could not reconcile may go on
    /// publishing that connection's roots, and they must not route to something
    /// that is gone. It retires itself once those roots stop appearing and the
    /// child's own listing confirms the connection is absent.
    ///
    /// **It runs on this Layer's token, not the caller's.** The caller's token
    /// belongs to the operation that was refused; reusing it means a fired token
    /// — a Ctrl+C arriving during the add — cancels the cleanup of a mutation
    /// that already committed, which is precisely when leaving it behind is
    /// worst. The removal is spawned with a child of the Router's own token and
    /// its own deadline, so it survives the caller's cancellation and outlives a
    /// caller whose future is dropped, exactly as the post-commit catch-up does
    /// and for the same reason.
    ///
    /// **What this must NOT change is whether a host starts.** The
    /// declared-connection loop in `ovstorage-layer`'s
    /// `StackBuilder::build_with_cancel` tolerates this code for that reason: a
    /// duplicated `[[ovstorage.connections]]` entry whose rollback fails would
    /// otherwise abort the whole build, taking every unrelated backend in the
    /// graph with it and looping a host that auto-restarts — over a connection
    /// that is registered whatever the host does and, thanks to the quarantine
    /// above, cannot serve. That is not a narrow shape: the in-tree backend that
    /// leaves `remove_connection` to the `Layer` default is `file` (`s3`, `gcs`,
    /// `azure` and `opendal` all implement it), so two `file` layers over one
    /// root — a copy-pasted connection entry — is exactly it.
    ///
    /// The code still travels intact to callers that are not a stack build:
    /// `ovstorage connect` reports it, exits `20`, and says not to retry.
    ///
    /// **The quarantine is recorded BEFORE the removal is attempted**, with no
    /// await in between, so a dropped future cannot lose it. Until the child is
    /// confirmed to have let go, [`RouterState::rebuild`] keeps every root of
    /// this connection out of the table — otherwise a refused connection becomes
    /// routable later, when whatever it collided with is removed, and starts
    /// serving under credentials the operator was told were rejected. The entry
    /// is lifted on a confirmed removal, and pruned by the first rebuild that
    /// sees the child publishing nothing for it.
    async fn roll_back_conflicting_add(
        &self,
        child: &LayerHandle,
        target: &str,
        extensions: Extensions,
        connection: &Connection,
        conflict: Error,
    ) -> Error {
        // The addresses it LISTS, which is the widest set it could publish a
        // root for: withholding a node the refused connection never serves
        // costs nothing (nothing publishes there for it), while missing one it
        // does serve is the refused-connection-starts-serving case this entry
        // exists to stop.
        self.state.quarantine(
            child,
            target,
            connection,
            connection.current_addresses.clone(),
        );
        let key = Request {
            extensions,
            input: ConnectionKey {
                target: target.to_string(),
                id: connection.id.clone(),
            },
        };
        // Owned: the task holds what it needs, so neither a fired caller token
        // nor a dropped caller future can strip the cleanup of its deadline or
        // stop it part way.
        let removal = child.clone();
        let parent = self.cancel.clone();
        let removed = tokio::spawn(async move {
            bounded_child_call(&parent, |token| removal.remove_connection(key, Some(token))).await
        })
        .await;
        // `(what to report, whether the quarantine stays)`. A confirmed removal
        // is the only outcome that retires the entry here; everything else
        // leaves roots that may still be published.
        let (error, hold_quarantine) = match removed {
            Ok(Ok(Ok(()))) => (None, false),
            // **The removal COMMITTED.** That is what this code means — it is
            // what THIS Layer answers from `remove_connection` when the child
            // let go and the route-table catch-up did not follow, so a nested
            // Router hands it back for exactly that. Reading it as a failed
            // removal reported a connection as still registered when it was
            // gone: the caller was told `CommitAmbiguous` from the ADD, and the
            // CLI reads that as "it landed, keep the declaration", so
            // `write-config` persisted an entry for a connection that had been
            // rolled back and the next startup recreated it.
            //
            // So membership is treated as removed and the refusal is the plain
            // one. The quarantine is NOT lifted: the child could not reconcile,
            // so it may go on publishing this connection's roots for a while,
            // and those must not route to something that is gone. It retires
            // itself once those roots stop appearing and the child's own listing
            // confirms the connection is absent — which is what
            // [`RouterState::retire_confirmed_quarantines`] asks.
            Ok(Ok(Err(err))) if err.code() == ErrorCode::CommitAmbiguous => {
                tracing::warn!(
                    target: "ovstorage.router",
                    router = %self.name,
                    layer = %target,
                    connection.id = %connection.id.0,
                    error = %err,
                    "router: a connection refused for a sibling layer's address prefix was \
                     removed, but the child could not confirm its routes; this Layer withholds \
                     that connection's roots until they stop being published, and the refusal \
                     stands as an ordinary route conflict"
                );
                (None, true)
            }
            Ok(Ok(Err(error))) => (Some(format!("{error}")), true),
            Ok(Err(_elapsed)) => (
                Some(format!(
                    "it did not complete within {CHILD_ROOT_QUERY_TIMEOUT:?}"
                )),
                true,
            ),
            Err(join) => (Some(format!("it panicked ({join})")), true),
        };
        let Some(error) = error else {
            if !hold_quarantine {
                self.state.lift_quarantine(child, target, &connection.id);
            }
            return conflict;
        };
        tracing::error!(
            target: "ovstorage.router",
            router = %self.name,
            layer = %target,
            connection.id = %connection.id.0,
            error = %error,
            "router: rolling back a connection refused for an address prefix a sibling layer \
             already serves failed; it stays registered on the child, this Layer keeps its \
             roots out of the route table so it cannot start serving later, and it has to be \
             removed by hand"
        );
        Error::new(
            ErrorCode::CommitAmbiguous,
            format!(
                "the connection was refused for an address prefix another layer already serves, \
                 but removing it from layer '{target}' failed ({error}); it remains registered \
                 as connection '{}' and this graph will not route it — remove it by hand",
                connection.id.0
            ),
        )
        // Says WHICH `CommitAmbiguous` this is: a refusal that could not be
        // undone, whose leftover this Layer withholds from the table, and which
        // therefore never routes. A host reading this may carry on; one reading
        // the other kind — a reconcile that failed over a connection that IS
        // wanted — must not. See [`ovstorage_layer::NEXT_ACTION_REFUSED_LEFTOVER`].
        .with_next_action(ovstorage_layer::NEXT_ACTION_REFUSED_LEFTOVER)
    }
}

/// A connection whose refusal this Layer could not complete, and whose roots
/// must therefore not route. See [`RouterState::quarantined`].
struct Quarantined {
    child: LayerHandle,
    /// The layer the refused add was aimed at. **Identity is `(target, id)`**,
    /// not the id alone: an id is unique only within its owning target, and one
    /// child can own several — a nested Router owns the union of its children's,
    /// and a composite plugin reports its internals — so two connections under
    /// one child can both be `rule`. Keyed by id alone, quarantining one of them
    /// suppressed the other's roots as well, and the healthy one went dark with
    /// nothing to retire the entry, because it stayed in the child's listing.
    target: String,
    connection: ConnectionId,
    /// The nodes the refused connection listed, for the roots that come back
    /// carrying no attribution to match against.
    ///
    /// [`RouterState::withhold_quarantined`] prefers `(child, connection id)`
    /// and needs nothing else when the child answers with one. This is the
    /// fallback, and it exists because the add path already accepts an
    /// unattributed root as the added connection's own — see
    /// [`Router::published_claims`], which treats a missing `connection_id` as
    /// "this child does not attribute its roots" rather than as a disclaimer.
    /// A refusal reached that way must be withholdable the same way, or the
    /// child's reticence quietly undoes it.
    nodes: Vec<Url>,
}

impl Quarantined {
    /// Whether the refused connection listed this node — the node-equality
    /// comparison the route table and the add-path refusal both use.
    fn claims_node(&self, node: &Url) -> bool {
        self.nodes
            .iter()
            .any(|claimed| address::same_node(claimed, node))
    }
}

/// One node published by more than one child, with the layers that publish it.
///
/// Ordered and deduplicated so two rebuilds that see the same misconfiguration
/// compare equal — which is what lets [`RouterState::report_cross_child_collisions`]
/// stay quiet about a standing problem it has already named.
#[derive(Debug, PartialEq, Eq)]
struct CrossChildCollision {
    node: Url,
    layers: Vec<String>,
}

/// Every node in `routes` that two or more DIFFERENT children publish.
///
/// Node equality, matching the route table and the add-path refusal: a sibling
/// root that merely *contains* another is independently routable under
/// longest-prefix lookup and is not a collision. Same-child overlaps are the
/// child's own business and are left alone here exactly as they are there.
///
/// Pure, so the detection is testable without a graph: the reporting around it
/// is a `tracing` call, which is not.
fn cross_child_collisions(routes: &[(RootInfo, LayerHandle)]) -> Vec<CrossChildCollision> {
    let mut collisions: Vec<CrossChildCollision> = Vec::new();
    for (index, (root, child)) in routes.iter().enumerate() {
        for (other_root, other_child) in routes.iter().skip(index + 1) {
            if Arc::ptr_eq(child, other_child) || !address::same_node(&root.root, &other_root.root)
            {
                continue;
            }
            let entry = match collisions
                .iter_mut()
                .find(|found| address::same_node(&found.node, &root.root))
            {
                Some(found) => found,
                None => {
                    collisions.push(CrossChildCollision {
                        node: root.root.clone(),
                        layers: Vec::new(),
                    });
                    collisions.last_mut().expect("just pushed")
                }
            };
            for name in [child.name().to_string(), other_child.name().to_string()] {
                if !entry.layers.contains(&name) {
                    entry.layers.push(name);
                }
            }
        }
    }
    for collision in &mut collisions {
        collision.layers.sort();
    }
    collisions.sort_by(|a, b| a.node.as_str().cmp(b.node.as_str()));
    collisions
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

    /// Record what a committed add has bound, for the window before a rebuild
    /// publishes it. See [`RouterState::claimed_roots`].
    ///
    /// Called with no await between it and the commit it records, so a caller's
    /// future dropped mid-add cannot leave a bound root unclaimed: a dropped
    /// future stops at an await point, and there is none in between.
    ///
    /// **Recorded under `applied_generation`, which is what makes the release
    /// rule total.** A claim leaves this set only through
    /// [`RouterState::release_claims_through`], and that runs during a rebuild;
    /// so a claim inserted into a generation window a rebuild has ALREADY swept
    /// is never looked at again by any release, and no later rebuild lowers
    /// `applied_generation` to reach it. It would sit here reserving a node for
    /// the life of the process, and — because
    /// [`Router::cross_child_conflict`] consults claims before anything
    /// schedules a catch-up — every sibling add on that node would be refused
    /// with `RouteConflict` and none of them would clear it.
    ///
    /// That window is reachable wherever the stamp and the insert are not
    /// adjacent: [`Router::reserve_after_ambiguous_commit`] stamps, then awaits
    /// the child's root snapshot, and a removal (which takes no
    /// [`RouterState::add_gate`]) can allocate a newer generation, publish, and
    /// release through it while that query is outstanding.
    ///
    /// Taking the lock closes it, and dropping the claim is the CORRECT answer
    /// rather than merely the convenient one: `applied >= generation` says a
    /// rebuild stamped at or above this one has published, that rebuild was
    /// allocated after this generation was — generations are handed out in
    /// order — and this generation is itself stamped after the child committed.
    /// So its fan-out queried the children after the commit and the table it
    /// installed already carries these roots, or does not because the
    /// connection has since been removed. Either way the claim has nothing left
    /// to say.
    ///
    /// The lock order is `applied_generation` then `claimed_roots`, matching
    /// [`RouterState::rebuild`], which holds the first across its call to
    /// `release_claims_through`. Neither is held across an await.
    fn claim_roots(&self, child: &LayerHandle, nodes: Vec<Url>, generation: u64) {
        if nodes.is_empty() {
            return;
        }
        let applied = self.applied_generation.lock();
        if *applied >= generation {
            return;
        }
        let mut claimed = self.claimed_roots.lock();
        claimed.extend(nodes.into_iter().map(|node| ClaimedRoot {
            node,
            child: child.clone(),
            generation,
        }));
    }

    /// Drop the claims a published table has caught up with.
    ///
    /// `applied` is a generation whose fan-out ran after those claims' commits,
    /// so the table it installed already carries their roots — or does not,
    /// because the connection was removed in the meantime, which frees the node
    /// just as legitimately. Either way the claim has stopped being the more
    /// current fact and the table can answer alone.
    ///
    /// Called while `applied_generation` is held and only after the new table is
    /// in place, so no reader can observe a moment where neither the claim nor
    /// the table covers the root.
    fn release_claims_through(&self, applied: u64) {
        self.claimed_roots
            .lock()
            .retain(|claim| claim.generation > applied);
    }

    /// Drop one generation's claims by hand, for the add that recorded them and
    /// then did not go through.
    ///
    /// The generation rule releases a claim once a rebuild has demonstrably
    /// included it, which presumes a rebuild is coming. On the refusal path in
    /// [`Router::add_connection`] none is: the newcomer is rolled back off its
    /// child and the catch-up is skipped precisely because the table never saw
    /// it. A provisional claim left there would reserve the node with nothing
    /// to release it — the immortal claim [`RouterState::claim_roots`]
    /// describes, arrived at from the other direction.
    ///
    /// Keyed by generation rather than by node or child, so it removes exactly
    /// the entries one add recorded and cannot disturb a sibling's claim on the
    /// same node: generations are unique per stamp.
    fn discard_claims_at(&self, generation: u64) {
        self.claimed_roots
            .lock()
            .retain(|claim| claim.generation != generation);
    }

    /// Keep a refused-but-still-registered connection out of the table.
    ///
    /// Recorded by [`Router::roll_back_conflicting_add`] before it attempts the
    /// removal, so the entry exists even if that future never resumes.
    fn quarantine(
        &self,
        child: &LayerHandle,
        target: &str,
        connection: &Connection,
        nodes: Vec<Url>,
    ) {
        // A child owning several targets cannot be told apart by id alone, so
        // suppression there leans on `RootInfo::owning_target` — which the host
        // does NOT fill in for a loaded plugin's `list_address_roots` the way it
        // does for `root_info_for`. A root that arrives without it under such a
        // child is unattributable, and this says so once rather than either
        // silently withholding a sibling's roots or silently letting the refused
        // connection's through.
        if child.owned_targets().len() > 1 {
            tracing::warn!(
                target: "ovstorage.router",
                layer = %child.name(),
                connection.target = %target,
                connection.id = %connection.id.0,
                "router: withholding a refused connection's roots on a child that owns several \
                 targets; a root it publishes without an owning target is matched against the \
                 addresses this connection listed instead"
            );
        }
        let mut quarantined = self.quarantined.lock();
        if quarantined.iter().any(|held| {
            Arc::ptr_eq(&held.child, child)
                && held.target == target
                && held.connection == connection.id
        }) {
            return;
        }
        quarantined.push(Quarantined {
            child: child.clone(),
            target: target.to_string(),
            connection: connection.id.clone(),
            nodes,
        });
    }

    /// Drop the entry once the child has confirmed the connection is gone.
    fn lift_quarantine(&self, child: &LayerHandle, target: &str, connection: &ConnectionId) {
        self.quarantined.lock().retain(|held| {
            !(Arc::ptr_eq(&held.child, child)
                && held.target == target
                && held.connection == *connection)
        });
    }

    /// Remove every quarantined connection's roots from a freshly aggregated
    /// set, and answer with the entries nothing published for.
    ///
    /// Matched by `(child, connection id)` wherever the child attributes its
    /// roots: the whole connection was refused, so none of its roots may route,
    /// and a *different* connection later binding that same node on that same
    /// child is not this one and must not be blocked by it.
    ///
    /// **Where attribution is missing, the node decides instead**, and the
    /// direction of that fallback is deliberate. A root arriving with no
    /// `connection_id`, or with an id but no `owning_target` under a child that
    /// owns several, cannot be pinned to a connection — but the add path
    /// already read exactly such a root as the added connection's own (see
    /// [`Router::published_claims`]), which is how a refusal on a child like
    /// that comes about in the first place. Letting it back into the table
    /// because the child will not say whose it is would undo the refusal the
    /// moment the incumbent went away, and the refused connection would begin
    /// serving under the credential it probed with. So the entry keeps the
    /// nodes the refused connection listed and withholds on those.
    ///
    /// It errs toward withholding a root that is somebody else's, which costs a
    /// node that does not route until the entry retires — recoverable, visible
    /// in `ovstorage doctor`, and only reachable on a child that declines to
    /// attribute a root it publishes on a node a refused connection listed.
    ///
    /// **An entry nothing published for is a CANDIDATE for retirement, not a
    /// retirement.** "The child published nothing for it" and "the child no
    /// longer holds it" are different facts, and the first is reachable while
    /// the connection is still registered: a parked connection publishes no
    /// roots (root discovery is skipped for one), and a discovery-backed child
    /// mid-reconnect can answer with an empty set. Retiring on that dropped the
    /// entry while the leftover was still there, and when it published again —
    /// and whatever it collided with was removed — the connection this Layer
    /// REFUSED became the route for that address, serving under the credential
    /// it probed with. So the caller confirms with
    /// [`RouterState::retire_confirmed_quarantines`] before anything is
    /// dropped, and absence of evidence retires nothing.
    fn withhold_quarantined(&self, routes: &mut Vec<(RootInfo, LayerHandle)>) -> Vec<Quarantined> {
        let quarantined = self.quarantined.lock();
        if quarantined.is_empty() {
            return Vec::new();
        }
        let mut matched = vec![false; quarantined.len()];
        // Computed once per entry rather than per root: whether this child owns
        // a single target, in which case an id names one connection inside it
        // and needs no further qualification. That is every ordinary backend,
        // and it is what keeps this working for a loaded plugin, whose
        // `list_address_roots` the host does NOT fill `owning_target` into.
        let id_alone_suffices: Vec<bool> = quarantined
            .iter()
            .map(|held| held.child.owned_targets().len() <= 1)
            .collect();
        routes.retain(|(root, child)| {
            let hit = quarantined.iter().enumerate().position(|(index, held)| {
                if !Arc::ptr_eq(&held.child, child) {
                    return false;
                }
                match root.connection_id.as_ref() {
                    // Attributed to a DIFFERENT connection: that connection's
                    // root, whatever node it sits on, and not this entry's to
                    // withhold.
                    Some(id) if *id != held.connection => false,
                    Some(_) => match root.owning_target.as_deref() {
                        // The root says which target it belongs to: believe it,
                        // and leave a sibling target's identically-named
                        // connection be.
                        Some(owner) => owner == held.target,
                        // Inside a single-target child an id is already
                        // unambiguous.
                        None if id_alone_suffices[index] => true,
                        // A multi-target child, and the root does not say which
                        // target: the id alone cannot tell this entry's row
                        // from a sibling target's namesake. Decided on the
                        // nodes instead, which is what the refusal was about.
                        None => held.claims_node(&root.root),
                    },
                    // **Unattributed, and this is the fail-closed arm.**
                    // `published_claims` accepts a root with no `connection_id`
                    // as the added connection's claim — that is what allows a
                    // refusal on such a child at all — so returning the root to
                    // the table here would let the connection this Layer
                    // reported as REFUSED become the active route once the
                    // incumbent goes away, serving under the credential it
                    // probed with. The two readings have to agree, and the node
                    // is the fact both of them turn on.
                    None => held.claims_node(&root.root),
                }
            });
            match hit {
                Some(index) => {
                    matched[index] = true;
                    false
                }
                None => true,
            }
        });
        quarantined
            .iter()
            .enumerate()
            .filter(|(index, _)| !matched[*index])
            .map(|(_, held)| Quarantined {
                child: held.child.clone(),
                target: held.target.clone(),
                connection: held.connection.clone(),
                nodes: held.nodes.clone(),
            })
            .collect()
    }

    /// Retire the quarantines whose connections the child confirms are gone.
    ///
    /// **Positive evidence only.** The question "does this child still hold that
    /// connection?" has an answer — `list_connections` — and this asks it rather
    /// than inferring one from an empty root snapshot. A child that says the id
    /// is not there has let go, and the entry has nothing left to protect; a
    /// child that still lists it, or that cannot answer at all, keeps its entry,
    /// because the cost of holding one too long is a root that does not route
    /// while the cost of dropping one too early is a refused connection quietly
    /// serving.
    ///
    /// Asked only about candidates — entries that published nothing this
    /// rebuild — so a healthy graph, where the quarantine set is empty and a
    /// quarantined connection goes on publishing, pays nothing for it.
    ///
    /// **What a flattened listing can and cannot decide.** `list_connections`
    /// answers `Connection` rows, which carry an id and no target — the ABI
    /// struct has no field for one — so this reads it for the single fact it
    /// settles exactly: an id that appears NOWHERE in the child cannot be held
    /// under any target of it, `(target, id)` included, so the entry retires.
    /// The other direction does not follow. On a multi-target child — a nested
    /// Router, a composite plugin reporting its internals — a row with this id
    /// may be a namesake under a SIBLING target, and then the id is present
    /// while `(target, id)` is gone. Retirement stays refused there, which is
    /// the safe way to be wrong about one rebuild, but on its own it is
    /// permanent: the namesake never leaves, so the entry never retires, and a
    /// later valid connection re-added at that same `(target, id)` would be
    /// withheld forever despite `add_connection` answering `Ok`.
    ///
    /// So the exact key is decided where this Layer actually holds it, not here:
    /// [`Router::add_connection`] and [`Router::remove_connection`] both act on
    /// a `(target, id)` the caller named, and both lift the entry for exactly
    /// that key when the child accepts. A successful removal is the leftover
    /// confirmed gone; a successful add at the same key is the child saying the
    /// id is free to bind, which it could only be if the leftover no longer
    /// holds it — and withholding past that point would black-hole the
    /// connection the caller was just told it had. Neither depends on reading a
    /// target out of a listing that does not carry one.
    ///
    /// A standing entry for a key nothing holds costs nothing on its own — it
    /// withholds roots no connection publishes. It only bites once something
    /// occupies that key again, and anything doing so through this Router lifts
    /// it on the way past. What is left uncovered is a connection installed at
    /// that key out of band, through a separate handle to the child rather than
    /// through this Router; nothing in-tree does that, because a Router owns its
    /// children and every mutation reaching them comes through it.
    async fn retire_confirmed_quarantines(
        &self,
        candidates: Vec<Quarantined>,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) {
        // A token of this rebuild's own to hang the per-call ones off: the
        // caller's must not be cancelled here — it belongs to the rebuild, not
        // to one confirmation — while a call that stalls still has to be told to
        // stop. Inheriting from it keeps a cancelled rebuild cancelling these
        // too.
        let parent = match &cancel {
            Some(caller) => caller.child_token(),
            None => CancellationToken::new(),
        };
        for candidate in candidates {
            let listed = bounded_child_call(&parent, |token| {
                candidate.child.list_connections(cx, Some(token))
            })
            .await;
            let Ok(Ok((snapshot, _updates))) = listed else {
                // No answer is not an answer. Keep it.
                continue;
            };
            // Absence is the exact half — see the doc above. Presence may be a
            // namesake under a sibling target, so it decides nothing on a
            // multi-target child and the entry is kept.
            if snapshot
                .connections
                .iter()
                .any(|connection| connection.id == candidate.connection)
            {
                continue;
            }
            self.lift_quarantine(&candidate.child, &candidate.target, &candidate.connection);
        }
    }

    /// Name every node two DIFFERENT children both publish, once per distinct
    /// set rather than once per rebuild.
    ///
    /// The route table already logs an overlap, but it logs it per root and
    /// says nothing about layers: an operator reading
    /// `overlapping address root shadowed` cannot tell the benign case — a
    /// sibling serving a broader root, which longest-prefix lookup keeps
    /// routable — from the one where two layers claim the same node and one of
    /// them is dead. This says the second one out loud, names both layers and
    /// the origin, and does it wherever aggregated roots appear: initial
    /// construction, a watcher-driven rebuild, a post-commit catch-up.
    ///
    /// Deduped against the last set reported, because a graph whose children
    /// publish update streams rebuilds on every change and a standing
    /// misconfiguration would otherwise repeat this line forever. The set is
    /// keyed by node and layer names, so a collision that clears and returns is
    /// reported again.
    fn report_cross_child_collisions(&self, routes: &[(RootInfo, LayerHandle)]) {
        let found = cross_child_collisions(routes);
        let mut last = self.reported_collisions.lock();
        if *last == found {
            return;
        }
        for collision in &found {
            // `error!`, not the table's `warn!`: an overlap between siblings is
            // a routing decision, but two layers on ONE node is a configuration
            // that cannot be satisfied — whatever the table does, one of those
            // layers serves nothing.
            tracing::error!(
                target: "ovstorage.router",
                address = %ovstorage_layer::origin_only(&collision.node),
                layers = %collision.layers.join(", "),
                "router: two layers in this graph publish the same address root; only one can \
                 serve it and the other is unreachable, with its credential unused. Give them \
                 distinct prefixes, or remove one."
            );
        }
        *last = found;
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
        // Before anything reads these roots: a connection this Layer refused
        // and could not remove is still publishing, and must not be routed just
        // because whatever it collided with has since gone away.
        let unpublished = self.withhold_quarantined(&mut routes);
        if !unpublished.is_empty() {
            // Confirmed against the child, never inferred from the silence
            // above. Awaited outside the quarantine lock, and only for the
            // entries that went quiet.
            self.retire_confirmed_quarantines(unpublished, &cx, cancel.clone())
                .await;
        }

        // Reported from HERE, not from the add path, because this is the only
        // place every root passes through: a connection a child built from its
        // own layer config was installed before this Router existed, and one a
        // child publishes on its update stream arrives without an add. Neither
        // reaches `cross_child_conflict`, so neither can be refused — see that
        // function for why refusing here is a different decision — but both are
        // visible right here, and an operator who cannot be told is the part of
        // this that is fixable.
        self.report_cross_child_collisions(&routes);

        let mut applied = self.applied_generation.lock();
        if *applied >= generation {
            // Discarded, but not uninformative: a generation at least this high
            // has already published, and it queried the children after every
            // commit stamped at or below it — so those claims are covered by the
            // table that is installed right now.
            self.release_claims_through(*applied);
            return Ok(());
        }
        *applied = generation;
        // Built before the write guard is taken: `incumbents_first` reads the
        // table it is about to replace, and this `RwLock` is not reentrant.
        let table = RouteTable::build(self.incumbents_first(routes));
        *self.routes.write() = table;
        *self.targets.write() = targets;
        // After the swap, never before: until the table carries these roots the
        // claims are the only record that they are bound.
        self.release_claims_through(generation);
        let roots = self.routes.read().roots().cloned().collect();
        let _ = self.root_change_tx.send(RootInfoChange::Snapshot(roots));
        Ok(())
    }

    /// Reorder a rebuild's aggregated roots so a binding this table ALREADY
    /// serves leads the ones that have just arrived.
    ///
    /// [`RouteTable`] breaks a same-node overlap by aggregation order, and this
    /// Layer's aggregation order is `self.children` order. That makes the winner
    /// of an overlap a fact about where a child sits in the graph, which is not
    /// a property anyone chose: a newcomer on an earlier child would take the
    /// route a later child's connection is already serving, moving live traffic
    /// to a different backend behind a `warn` the CLI does not print unless
    /// `RUST_LOG` is set. **Incumbency decides instead**, which is the direction
    /// [`Router::cross_child_conflict`] promises when it keeps a partially
    /// colliding connection and shadows the one root: the connection that was
    /// already serving an address keeps serving it, and the newcomer is the one
    /// shadowed, whichever order the two children happen to be in.
    ///
    /// The incumbent is read from the table being replaced, under the same
    /// `applied_generation` guard as the swap, so two rebuilds cannot each
    /// promote themselves off the other's view.
    ///
    /// It is the RESOLVING binding that is preserved, not every published one:
    /// a node with an overlap has both entries in the table, and treating the
    /// shadowed one as incumbent too would let child order decide again on the
    /// next rebuild — flipping the route back and forth on every mutation.
    /// [`RouteTable::entries`] is in ranked order, so the first entry for a node
    /// is exactly what `lookup` answers with, and `or_insert` keeps it.
    ///
    /// A root nobody served before is unaffected: it falls in the second group
    /// and keeps graph order, so a first build (and every non-overlapping
    /// rebuild) is byte-for-byte what it was. A node whose incumbent has since
    /// gone away has no entry here either, so its route heals to whoever is left
    /// rather than staying vacant.
    fn incumbents_first(
        &self,
        routes: Vec<(RootInfo, LayerHandle)>,
    ) -> Vec<(RootInfo, LayerHandle)> {
        let serving = {
            let published = self.routes.read();
            let mut serving = HashMap::new();
            for (root, child) in published.entries() {
                serving
                    .entry(address::node_key_owned(&root.root))
                    .or_insert_with(|| child.clone());
            }
            serving
        };
        if serving.is_empty() {
            return routes;
        }
        let (incumbent, arrived): (Vec<_>, Vec<_>) =
            routes.into_iter().partition(|(root, child)| {
                serving
                    .get(&address::node_key_owned(&root.root))
                    .is_some_and(|holder| Arc::ptr_eq(holder, child))
            });
        incumbent.into_iter().chain(arrived).collect()
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

/// Run ONE child call bounded by [`CHILD_ROOT_QUERY_TIMEOUT`], on a token this
/// Layer cancels however the call ends.
///
/// **A timeout that only drops the future is not a cancellation.**
/// `tokio::time::timeout` drops the inner future and nothing else, and dropping
/// a child's future unwinds the Rust half alone: a `ForeignVtableLayer`'s plugin
/// task and its `user_data` live until the FFI operation finishes on its own.
/// Cancelling the token is the signal that crosses the ABI. Handing these calls
/// a child of the Router's own token gave them one that fires only at Router
/// drop, so a plugin that stalls a removal or a listing leaked an outstanding
/// task and its allocation per attempt for the life of the process.
///
/// So the token is minted here, handed to the call, and fired by
/// [`CancelOnDrop`] on every exit — the timeout, an error, or this future being
/// dropped out from under it.
///
/// Firing on SUCCESS too is safe for these callers and is the same licence
/// `RouterState::rebuild`'s fan-out takes: each discards any update stream the
/// call hands back, so there is nothing left tied to the token once the answer
/// is in hand. A caller that wanted to KEEP a stream could not use this.
async fn bounded_child_call<T, F>(
    parent: &CancellationToken,
    call: impl FnOnce(CancellationToken) -> F,
) -> std::result::Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    let token = parent.child_token();
    let _cancel_on_exit = CancelOnDrop(token.clone());
    tokio::time::timeout(CHILD_ROOT_QUERY_TIMEOUT, call(token)).await
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

    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        if request.input.options.max_results.is_some() || request.input.options.page_token.is_some()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }

        self.route(&request.input.prefix)?
            .list_stream(request, cancel)
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
        let child = self.route_target(&request.input.target)?;
        let mut connection = child.probe(request, cancel).await?;
        self.attribute_one(&child, &mut connection);
        Ok(connection)
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let child = self.route_target(&request.input.target)?;
        // Taken AFTER the target lookup, so naming a layer that does not exist
        // is answered immediately rather than queued behind a slow add, and
        // released by this guard's drop on every exit — including a caller whose
        // future is dropped mid-add. See [`RouterState::add_gate`] for why it
        // has to span the commit below and not merely the check.
        //
        // **Waiting for it is cancellable, and so is holding it.** A plain
        // `lock().await` is not: a caller queued behind a slow add whose token
        // fires while it waits went on to the child anyway once the gate opened,
        // and a child is under no obligation to notice — the in-tree
        // `FileBackend::add_connection` takes its `cancel` as `_cancel` — so a
        // request the caller had abandoned still registered a connection and
        // answered `Ok`. It also left that caller parked with no exit at all if
        // whoever held the gate wedged. Nothing has committed at this point, so
        // `Cancelled` is the truthful answer here, unlike after the child has
        // been called.
        let _adding = match &cancel {
            Some(token) => {
                tokio::select! {
                    // Biased so an already-fired token wins a gate that happens
                    // to be free: the caller has left, and taking it would be
                    // work nobody is waiting for.
                    biased;
                    () = token.cancelled() => {
                        return Err(Error::new(
                            ErrorCode::Cancelled,
                            "cancelled while waiting for the router's add gate",
                        ));
                    }
                    guard = self.state.add_gate.lock() => guard,
                }
            }
            None => self.state.add_gate.lock().await,
        };
        // And once more with the gate in hand: the token can fire in the window
        // between the wait ending and the child being called, which is the one
        // moment a cancelled add would still commit.
        ovstorage_layer::bail_if_cancelled(&cancel)?;
        // Kept for the rollback below, which has to reach the same child under
        // the same request extensions the add carried — a management op the
        // host gates on those would otherwise be judged differently from the
        // mutation it is undoing.
        let target = request.input.target.clone();
        let extensions = request.extensions.clone();
        let mut connection = match child.add_connection(request, cancel.clone()).await {
            Ok(connection) => connection,
            // The child says the add COMMITTED and it could not confirm the rest
            // — the code its own contract reserves for exactly that, and what a
            // child Router answers when its post-commit catch-up fails. There is
            // no `Connection` to check or claim, so this add cannot be finished;
            // but something under that child is now serving roots this Layer has
            // not seen, and releasing the gate on a bare `?` would let the next
            // add on a SIBLING bind one of them. Reserve first, then propagate.
            Err(err) if err.code() == ErrorCode::CommitAmbiguous => {
                self.reserve_after_ambiguous_commit(&child).await;
                return Err(err);
            }
            // Every other code means the mutation did not take effect, which is
            // what makes this arm safe to leave alone: there is nothing
            // committed to reserve.
            Err(err) => return Err(err),
        };
        // The child bound this exact `(target, id)`, so any quarantine standing
        // against it is spent: the id could only be free to bind if the refused
        // leftover no longer holds it. Lifting here is what keeps a quarantine
        // from outliving its connection on a multi-target child, where the
        // listing `retire_confirmed_quarantines` reads cannot tell this key's
        // row from a sibling target's namesake and so never retires it. Without
        // this the connection just added would be withheld from the table for
        // the life of the process while its caller was told `Ok` — registered,
        // unroutable, and invisible. A refusal below re-records the entry before
        // it attempts the rollback, so a rolled-back add is not let through by
        // this.
        self.state.lift_quarantine(&child, &target, &connection.id);
        // **Claimed provisionally before anything can suspend this future.**
        // The child has COMMITTED, and the exclusivity check below may await
        // `published_claims` to reach its verdict — the one post-commit
        // suspension point on the ordinary path. A caller future dropped there
        // (an RPC client that hangs up on a slow or foreign child) unwinds with
        // the connection registered, no claim, no quarantine, and the add gate
        // released by `_adding`; against an `updates: false` child nothing ever
        // reconciles it, so a sibling add could bind the same node, or removing
        // the incumbent could let this abandoned connection start serving under
        // the credential it probed with.
        //
        // So the widest set it could bind — what it LISTS — is reserved first
        // and narrowed afterwards. Over-reserving costs nothing that lasts: a
        // claim held by this child is skipped by `cross_child_conflict` for
        // this child's own add, it constrains only siblings, and the first
        // rebuild that publishes at or above its generation drops it. Under-
        // reserving is the unroutable duplicate this Layer exists to prevent.
        let provisional = self.state.next_generation();
        self.state
            .claim_roots(&child, connection.current_addresses.clone(), provisional);
        // Graph-wide prefix exclusivity, asked BEFORE the catch-up below so the
        // table it reads is still the pre-add one — see
        // [`Router::cross_child_conflict`]. A refusal rolls the newcomer back
        // off its child and skips the catch-up entirely: the table never saw
        // the newcomer, so there is nothing to reconcile, and no claim was
        // recorded for it either.
        // Checked against what the connection LISTS first, which costs nothing
        // and is right whenever nothing is contested — the overwhelmingly common
        // case. Only a verdict that would drop an address is worth paying a
        // query for: `current_addresses` is not the set of roots a connection
        // routes (see [`Router::published_claims`]), and the difference only
        // matters when an entry is about to be treated as a collision.
        //
        // Asking unconditionally would put a `list_address_roots` on every add,
        // which is exactly the call a wedged child never answers — the add path
        // must not inherit that.
        let listed = connection.current_addresses.clone();
        let mut verdict = self.cross_child_conflict(&child, &connection, &listed);
        if verdict
            .as_ref()
            .map_or(true, |kept| kept.len() != listed.len())
        {
            let claimable = self.published_claims(&child, &connection).await;
            verdict = self.cross_child_conflict(&child, &connection, &claimable);
        }
        let claimed = match verdict {
            Ok(claimed) => claimed,
            Err(conflict) => {
                // The add is being undone and no catch-up will run, so the
                // provisional reservation goes with it — otherwise it outlives
                // the connection it was standing in for and refuses every
                // sibling on that node forever. Dropped BEFORE the rollback,
                // not after: the rollback awaits, and the leftover it may fail
                // to remove is covered by the quarantine
                // `roll_back_conflicting_add` records first, which withholds
                // those roots from the table on its own terms.
                self.state.discard_claims_at(provisional);
                return Err(self
                    .roll_back_conflicting_add(&child, &target, extensions, &connection, conflict)
                    .await);
            }
        };
        // Stamped and claimed with no await in between, so the roots this child
        // has COMMITTED are on record before anything can interrupt this future.
        // The catch-up below is detachable by contract — a fired caller token
        // releases the wait, a failed fan-out publishes nothing — and the gate
        // is released on both paths, so without the claim the next add would
        // read a table that never heard of these roots and bind them again. See
        // [`RouterState::claimed_roots`].
        let generation = self.state.next_generation();
        self.state.claim_roots(&child, claimed, generation);
        // Narrowed, never widened: the exact set is on record above before the
        // provisional one comes off, so no reader sees a moment where neither
        // covers a node this connection binds.
        self.state.discard_claims_at(provisional);
        self.attribute_one(&child, &mut connection);
        // The mutation has COMMITTED on the child. The route-table catch-up
        // that follows is this Layer reconciling with that fact, and it is the
        // only thing that does so for a child publishing no update stream
        // (`FileBackend`, any `updates: false` plugin) — such a child has no
        // watcher to self-heal a table this leaves stale. So the `?` is
        // load-bearing: returning the connection with an unpublished table
        // would tell the caller an address is bound that does not route. See
        // `route_catch_up` for what each failure means and why a cancel here
        // reports `CommitAmbiguous` rather than `Cancelled`.
        self.route_catch_up_at(generation, cancel).await?;
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
        //
        // **The child that answered is recorded, not discarded.** Flattening is
        // the one point where a row and the child that produced it are still
        // together, and this is the only place in the graph that holds both:
        // the rows arrive per child, and `state.targets` — which this must
        // agree with, since it is what `route_target` reads — is built from the
        // same `owned_targets()` call. A row a child already attributed is left
        // alone; the child knows its own interior and this does not.
        //
        // A child owning SEVERAL targets is not attributable from here: an id is
        // unique only within its target, so nothing about the fan-out says which
        // of that child's targets holds the row. It stays `None`, which tells a
        // caller to ask the graph rather than handing back a name that would
        // fail at `route_target`. This is a net under the child's own
        // attribution, not a substitute for it.
        //
        // **A child's answer is trusted about itself, not about a sibling.**
        // Callers address a reported target DIRECTLY — that is the point of the
        // field — so a name that routes to a different child would aim a removal
        // or an interactive flow at that child's connection, and ids collide
        // across targets legally, so a namesake there is a live connection
        // somebody is using. A misreport is an ordinary plugin bug, and the
        // graph is the only place it is visible. [`Router::attribute_row`] is
        // the rule that follows from that, and it is shared with the four ops
        // that return a `Connection`, so one row has one answer whatever
        // produced it. The auth stream reaches the same invariant from its
        // request key instead. A target this Router does not route at all is
        // left alone: a child may own connections on a name it does not publish as
        // routable — the broker-client and services-client layers gate
        // `owned_targets` on `supports_runtime_add` while still answering ops
        // keyed on their own name — and that name reaches the child that
        // reported it, which is the property this is protecting.
        let mut connections = Vec::new();
        for child in &self.state.children {
            let sole_target = ovstorage_layer::sole_owning_target(&child.owned_targets());
            let rows = child
                .list_connections(cx, cancel.clone())
                .await?
                .0
                .connections;
            connections.extend(rows.into_iter().map(|mut connection| {
                self.attribute_row(child, &sole_target, &mut connection);
                connection
            }));
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
        let child = self.route_target(&key.input.target)?;
        let target = key.input.target.clone();
        let id = key.input.id.clone();
        child.remove_connection(key, cancel.clone()).await?;
        // The child confirmed this exact `(target, id)` is gone, which is the
        // one thing a quarantine on it was waiting to hear — and the one thing
        // `retire_confirmed_quarantines` cannot establish from a flattened
        // listing when a sibling target holds a namesake. Ordinary removals go
        // through here, so an operator clearing a refused leftover by hand
        // retires its entry by doing so.
        self.state.lift_quarantine(&child, &target, &id);
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
        let child = self.route_target(&request.input.key.target)?;
        let mut connection = child.update_connection_credentials(request, cancel).await?;
        self.attribute_one(&child, &mut connection);
        Ok(connection)
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let child = self.route_target(&request.input.key.target)?;
        let mut connection = child
            .update_connection_attributes(request, cancel.clone())
            .await?;
        self.attribute_one(&child, &mut connection);
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
        let child = self.route_target(&request.input.key.target)?;
        // **The sixth `Connection`-bearing exit. It takes the same rule, with a
        // better source for the rule's one derived input.**
        //
        // `AuthEvent::Succeeded` carries a `Connection`, so a row leaves the
        // Router here as surely as it does through the listing or the four ops,
        // and forwarding it untouched let a child name a sibling's target on a
        // row a caller then addresses.
        //
        // What differs is where the candidate target comes from. The fan-out
        // must derive one from `owned_targets`, because flattening loses which
        // of a child's targets holds a row. Here the request says: the
        // `route_target` above has proved `key.target` reaches this child, so
        // it is the candidate — and it cannot go stale the way a derived one
        // can. `AuthEventStream` is a blocking iterator the caller pulls at its
        // own pace, so anything read from `owned_targets()` when the flow
        // opened is frozen across an interactive sign-in; a child that became
        // multi-target meanwhile would be handed a guessed single target where
        // the rule's own contract says the answer is unknowable.
        //
        // **What the request does NOT prove is that the row is the one it
        // named.** `route_target` establishes target → child; whether the
        // `Connection` a child yields is the one the key addressed is the
        // child's business. So the candidate is offered to
        // [`attribute_row_in`], not stamped: it fills an unattributed row,
        // corrects one naming a sibling's target, and LEAVES A CORRECT
        // SELF-REPORT ALONE. That last arm is what stamping unconditionally
        // broke, for a child that had attributed its own row correctly under
        // one of its other targets.
        //
        // **This path answers where the fan-out declines, and that is not a
        // contradiction.** For a multi-target child the listing reports `None`
        // — flattening lost which target holds the row — and this reports
        // `Some(key.target)`, because the request names what the listing could
        // not recover. Declining then answering is not two answers; see the
        // invariant on [`Router::attribute_row`] for what is actually excluded,
        // and for the plugin obligation this leans on.
        let candidate = Some(request.input.key.target.clone());
        // A STRONG ref, unlike the `Weak` a detached catch-up takes. The
        // difference is ownership: a catch-up orphaned by a released wait must
        // not keep the Router's children alive, and this stream has a caller
        // holding it. The cost is that `RouterState`'s strong count is no
        // longer a catch-up count while a flow is open — see `live_catch_ups`.
        let state = Arc::clone(&self.state);
        let stream = child.authenticate_connection(request, cancel).await?;
        Ok(Box::new(stream.map(move |event| match event {
            Ok(AuthEvent::Succeeded {
                mut connection,
                credentials,
            }) => {
                attribute_row_in(&state, &child, &candidate, &mut connection);
                Ok(AuthEvent::Succeeded {
                    connection,
                    credentials,
                })
            }
            other => other,
        })))
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
        /// Counts `stat` and `copy` calls, so a test can tell "the Router
        /// routed here" from a refusal the Router produced on its own.
        stats: std::sync::atomic::AtomicUsize,
        copies: std::sync::atomic::AtomicUsize,
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
                stats: std::sync::atomic::AtomicUsize::new(0),
                copies: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        /// Publish `root` from the start, before any Router's construction
        /// fan-out reads this child.
        fn publish(&self, root: RootInfo) {
            self.roots.write().push(root);
        }

        /// The marked `gated:///` root a granted child publishes. Built by hand
        /// because the shared constructor admits only the closed scheme set,
        /// while the predicate the table consults reads the marker and the
        /// shape and not the set — which is what lets a test scheme exercise
        /// the tier. Shaped as the constructor shapes its roots: hidden,
        /// unattributed, and owned by no connection.
        fn marked_scheme_root() -> RootInfo {
            let mut root = Self::root_info("gated:///");
            root.display_name = Some("anonymous gated:// fallback".to_string());
            root.owning_target = None;
            root.visible = false;
            root.visibility = AddressVisibility::Hidden;
            root.user_metadata.insert(
                SCHEME_FALLBACK_METADATA_KEY.to_string(),
                SCHEME_FALLBACK_ANONYMOUS.to_string(),
            );
            assert!(
                is_scheme_fallback_root(&root),
                "the fixture must be what the table's second tier reads"
            );
            root
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

        /// Answers from this child's own published roots through the shared
        /// table, as a backend layer does: the Router routes to the child, and
        /// the child's table — with the same second tier — names the root.
        async fn root_info_for(
            &self,
            url: &Url,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<RootInfo> {
            let table = RouteTable::build(
                self.roots
                    .read()
                    .iter()
                    .cloned()
                    .map(|root| (root, ()))
                    .collect(),
            );
            table
                .lookup(url)
                .map(|(root, ())| root.clone())
                .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
        }

        async fn stat(
            &self,
            request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            self.stats.fetch_add(1, Ordering::SeqCst);
            Ok(ObjectInfo::from((
                request.input.address,
                BackendItemInfo {
                    kind: ObjectKind::File,
                    ..BackendItemInfo::default()
                },
            )))
        }

        /// Answers with this child's OWN code, distinct from the `Unsupported`
        /// the Router produces when a copy's two addresses route to different
        /// children.
        async fn copy(
            &self,
            _request: Request<CopyRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<WriteStep> {
            self.copies.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(
                ErrorCode::NotFound,
                "the gated child has no such source",
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
                owning_target: None,
            })
        }

        async fn remove_connection(
            &self,
            _key: Request<ConnectionKey>,
            _cancel: Option<CancellationToken>,
        ) -> Result<()> {
            // Commits by dropping the root this child serves from the start —
            // the one root a key can name unambiguously here, since every add
            // reports the same `ConnectionId` — and then stalls the Router's
            // re-query exactly as `add_connection` does. This path takes no
            // `RouterState::add_gate`, which is what lets a test park the
            // catch-up slot on a committed mutation while a later ADD still
            // reaches the child.
            self.roots
                .write()
                .retain(|root| root.root.as_str() != Self::STATIC_ROOT);
            Ok(())
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

    /// The key for a removal against [`GatedChild`], which registers every
    /// connection under the same id.
    fn gated_connection_key() -> Request<ConnectionKey> {
        Request::new(ConnectionKey {
            target: "gated".to_string(),
            id: ConnectionId("gated".to_string()),
        })
    }

    // ---- The route table's second tier, seen from the Router -------------
    //
    // The tier lives in the shared `RouteTable`, so the Router gains it with
    // no rule of its own. These pin what that means at the Router's surface:
    // an unrouted address on a granted scheme reaches the child that published
    // the marked scheme root, and everything the Router already did around a
    // route — introspection, the exclusivity check, the same-child copy check,
    // root publication — keeps its shape.

    fn stat_request(address: &str) -> Request<StatRequest> {
        Request::new(StatRequest {
            address: Url::parse(address).unwrap(),
            options: StatOptions::default(),
        })
    }

    fn copy_request(source: &str, destination: &str) -> Request<CopyRequest> {
        Request::new(CopyRequest {
            source: Url::parse(source).unwrap(),
            destination: Url::parse(destination).unwrap(),
            options: CopyOptions::default(),
        })
    }

    /// A child publishing the marked scheme root routes an address on that
    /// scheme which no prefix serves, and introspection names the scheme root
    /// itself — no per-authority root is synthesized and no connection is
    /// named. Without the marker the same address is the byte-identical
    /// `NoRoute` it always was: the hostless `gated:///static/` root is a
    /// prefix root, not a catch-all.
    #[tokio::test]
    async fn a_child_publishing_a_marked_scheme_root_routes_an_unconfigured_authority() {
        let elsewhere = Url::parse("gated://elsewhere/x").unwrap();

        let plain = GatedChild::new();
        let router = Router::new("r", vec![plain.clone()], None).await.unwrap();
        let error = router
            .stat(stat_request(elsewhere.as_str()), None)
            .await
            .expect_err("no prefix serves a hosted address and nothing is granted");
        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert_eq!(error.message(), "no route matches address");
        assert_eq!(
            plain.stats.load(Ordering::SeqCst),
            0,
            "an unrouted address never reaches a child"
        );

        let granted = GatedChild::new();
        granted.publish(GatedChild::marked_scheme_root());
        let router = Router::new("r", vec![granted.clone()], None).await.unwrap();
        router
            .stat(stat_request(elsewhere.as_str()), None)
            .await
            .expect("the marked scheme root routes the unconfigured authority");
        assert_eq!(granted.stats.load(Ordering::SeqCst), 1);
        let serving = router.route(&elsewhere).expect("the address routes");
        assert!(Arc::ptr_eq(&serving, &(granted.clone() as LayerHandle)));

        let root = router
            .root_info_for(&elsewhere, &Extensions::new(), None)
            .await
            .expect("introspection follows the same route");
        assert_eq!(root, GatedChild::marked_scheme_root());
        assert_eq!(root.connection_id, None);
        assert_eq!(root.root.as_str(), "gated:///");
    }

    /// Configuring a real connection for an authority the fallback currently
    /// serves is not a route conflict: the exclusivity check asks who serves
    /// that exact node, and the scheme root names no node. Once added, the
    /// connection's prefix outranks the fallback for its own authority and the
    /// fallback keeps every other.
    ///
    /// The newcomer arrives on a SIBLING child, because a same-child hit is
    /// discarded by the identity check before the node is ever compared — a
    /// cross-child add is the only shape the check can refuse, and so the only
    /// one that pins it.
    #[tokio::test]
    async fn adding_a_connection_for_a_fallback_served_authority_is_not_a_route_conflict() {
        let granted = GatedChild::new();
        granted.publish(GatedChild::marked_scheme_root());
        let tenant = TenantChild::new("tenant");
        let router = Router::new(
            "r",
            vec![
                granted.clone() as LayerHandle,
                tenant.clone() as LayerHandle,
            ],
            None,
        )
        .await
        .unwrap();
        let elsewhere = Url::parse("gated://elsewhere/x").unwrap();
        assert!(
            Arc::ptr_eq(
                &router.route(&elsewhere).expect("the fallback answers"),
                &(granted.clone() as LayerHandle)
            ),
            "premise: the fallback serves the authority before the add"
        );

        router
            .add_connection(tenant_request("tenant", "gated://elsewhere/"), None)
            .await
            .expect("a fallback-served authority is free to configure");
        assert_eq!(tenant.connection_count(), 1, "the add committed and stayed");
        assert!(
            Arc::ptr_eq(
                &router.route(&elsewhere).expect("the address still routes"),
                &(tenant as LayerHandle)
            ),
            "the configured prefix outranks the fallback for its own authority"
        );
        let other = Url::parse("gated://other/x").unwrap();
        assert!(
            Arc::ptr_eq(
                &router.route(&other).expect("the fallback still answers"),
                &(granted as LayerHandle)
            ),
            "every other authority on the scheme still takes the fallback"
        );
    }

    /// A copy whose source and destination are both fallback-served resolves
    /// both to the one child that published the scheme root, so the Router's
    /// same-child check passes and the child sees the copy. The child answers
    /// with its own code; the Router's cross-root `Unsupported` never fires.
    #[tokio::test]
    async fn copy_between_two_fallback_addresses_reaches_one_child() {
        let plain = GatedChild::new();
        let router = Router::new("r", vec![plain.clone()], None).await.unwrap();
        let error = router
            .copy(copy_request("gated://a/x", "gated://b/y"), None)
            .await
            .expect_err("nothing routes either address");
        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert_eq!(plain.copies.load(Ordering::SeqCst), 0);

        let granted = GatedChild::new();
        granted.publish(GatedChild::marked_scheme_root());
        let router = Router::new("r", vec![granted.clone()], None).await.unwrap();
        let error = router
            .copy(copy_request("gated://a/x", "gated://b/y"), None)
            .await
            .expect_err("the child answers with its own refusal");
        assert_eq!(
            error.code(),
            ErrorCode::NotFound,
            "the child's answer, not the Router's cross-root refusal: {error}"
        );
        assert_eq!(
            granted.copies.load(Ordering::SeqCst),
            1,
            "both addresses resolved to the one child and the copy reached it"
        );
    }

    /// `list_address_roots` publishes the marked root exactly as the child
    /// handed it over — hidden, unattributed, marker intact — and a child
    /// without one publishes exactly what it did before the tier existed.
    #[tokio::test]
    async fn list_address_roots_publishes_the_marked_root_verbatim_and_is_unchanged_without_it() {
        let static_root = GatedChild::root_info(GatedChild::STATIC_ROOT);

        let plain = GatedChild::new();
        let router = Router::new("r", vec![plain], None).await.unwrap();
        let (snapshot, _updates) = router
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.roots, vec![static_root.clone()]);

        let granted = GatedChild::new();
        granted.publish(GatedChild::marked_scheme_root());
        let router = Router::new("r", vec![granted], None).await.unwrap();
        let (snapshot, _updates) = router
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap();
        // Ranked order: the deeper static root first, the scheme root last.
        assert_eq!(
            snapshot.roots,
            vec![static_root, GatedChild::marked_scheme_root()]
        );
        let marked = &snapshot.roots[1];
        assert!(is_scheme_fallback_root(marked));
        assert_eq!(marked.visibility, AddressVisibility::Hidden);
        assert!(!marked.visible);
        assert_eq!(marked.connection_id, None);
        assert_eq!(marked.owning_target, None);
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
                owning_target: None,
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
        //
        // Adds now queue on `RouterState::add_gate` as well, so this bound is
        // doubly enforced on THIS path and the assertion below no longer
        // isolates `catch_up_slot`. That slot is still the only bound on the
        // paths that take no add gate — `remove_connection` and
        // `update_connection_attributes` — and it is what stops a mutation
        // whose caller has walked away from starting a second fan-out.
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
    /// holds for its whole life.
    ///
    /// **One other thing now holds a strong ref**, so this is a count of
    /// catch-ups only while no auth flow is open: `authenticate_connection`
    /// clones the `Arc` into the stream it returns, so the state outlives the
    /// call for as long as the caller holds the stream. One open flow and no
    /// catch-ups at all reads as `1` here, and drops back to `0` when the
    /// stream does. A test that combines the two has to account for it rather
    /// than read this as a catch-up count.
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
        //
        // The mutation that occupies the slot is a REMOVAL, not a second add.
        // Adds serialize on `RouterState::add_gate`, which spans the commit and
        // the catch-up both, so a second add would park at the gate and never
        // reach the child — and a mutation that has not committed is not this
        // test's subject. Removals take no add gate, so the dropped add below
        // still commits on the child and queues its own catch-up behind this
        // one, which is the scenario the property is about.
        let child = GatedChild::new();
        let router = Arc::new(Router::new("r", vec![child.clone()], None).await.unwrap());
        let static_root = Url::parse(GatedChild::STATIC_ROOT).unwrap();
        let added = Url::parse(GatedChild::ROOT).unwrap();

        // Mutation A commits — the child no longer serves its static root — and
        // its catch-up parks in the child, holding the slot. Its fan-out
        // sampled the roots BEFORE B commits below, so A's own rebuild cannot
        // publish B's root: only B's Router-owned catch-up can.
        child.stall.store(true, Ordering::SeqCst);
        let mutation_a = tokio::spawn({
            let router = Arc::clone(&router);
            async move { router.remove_connection(gated_connection_key(), None).await }
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
        assert_eq!(
            child.adds.load(Ordering::SeqCst),
            1,
            "B must have COMMITTED on the child before its future was dropped, \
             or this asserts nothing about a committed mutation",
        );

        // Release A. B has no caller left, but its catch-up is Router-owned, so
        // the table must still end up routing what B committed.
        child.gate.add_permits(1);
        mutation_a
            .await
            .expect("A must not panic")
            .expect("A's catch-up completes once released");

        // Poll with a sleep rather than a yield: under a paused clock a yield
        // loop never lets the runtime go idle, so the timeout below could never
        // fire and a regression would hang instead of failing.
        let converged = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while router.route(&added).is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "a committed mutation whose caller future was dropped must still \
             converge: its catch-up is owned by the router, not by the caller",
        );
        assert!(
            router.route(&static_root).is_err(),
            "and A's committed removal is still reflected",
        );
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

    /// A connection-owning child in the shape of plugin-http: every connection
    /// binds one address root, the child publishes its roots unconditionally
    /// (in every auth state), and exclusivity is enforced over **its own**
    /// roots only — it cannot see a sibling's, which is the whole reason the
    /// Router has to enforce the rest.
    struct TenantChild {
        name: String,
        connections: Mutex<Vec<Connection>>,
        /// The target this child stamps on the `Connection` it yields from
        /// `authenticate_connection`. `Some(sibling)` is the misreport the
        /// auth-path test needs; `None` leaves the row unattributed as the
        /// other fixture paths do.
        authenticated_as: Mutex<Option<String>>,
        /// Appended to `owned_targets()`, so a test can make this child
        /// multi-target AFTER a flow has opened. What that exercises is a LIVE
        /// `owned_targets` read at event time, which would find no single
        /// target and clear the row; a hoisted read agrees with the request key
        /// here and is not what the test rules out.
        extra_targets: Mutex<Vec<String>>,
        /// Makes `remove_connection` fail, standing in for a child that cannot
        /// undo the add the Router just refused.
        fail_removals: AtomicBool,
        /// Counts `remove_connection` calls, so a test can tell a rollback that
        /// ran from one that was skipped.
        removals: std::sync::atomic::AtomicUsize,
        /// Parks `add_connection` until the test releases it, so a second add
        /// can be launched while the first is mid-commit. Real backends take
        /// their time here — a probe, a handshake — so this is the ordinary
        /// window, not a contrived one.
        gate: Option<Semaphore>,
        /// Makes the root re-query fail, so a committed add's catch-up ends with
        /// nothing published — the ordinary shape of a backend that answers the
        /// mutation and then goes unreachable.
        fail_root_query: AtomicBool,
        /// Commits the add and THEN answers `CommitAmbiguous`, which is what a
        /// child Router does when its own post-commit catch-up fails: the
        /// connection is registered on its child, and the caller gets an error
        /// with no `Connection` in it.
        ambiguous_adds: AtomicBool,
        /// Never returns from `remove_connection`, standing in for a plugin
        /// that stalls one — and records whether the token it was handed was
        /// ever cancelled, which is the only signal that crosses the ABI.
        stall_removals: AtomicBool,
        removal_cancelled: Arc<Semaphore>,
        /// Addresses a connection LISTS but publishes no root for, so the two
        /// sets differ the way an alias visibility override makes them differ.
        scopes: Mutex<Vec<Url>>,
        /// Removes the connection and THEN answers `CommitAmbiguous` — what a
        /// nested Router returns when its child let go and its own route-table
        /// catch-up did not follow. The membership change happened.
        ambiguous_removals: AtomicBool,
        /// Answers the root query `Ok` with an EMPTY snapshot while keeping
        /// every connection — a parked connection publishes no roots, and a
        /// discovery-backed child mid-reconnect answers the same way. Distinct
        /// from `fail_root_query`, which errors and so fails the whole rebuild
        /// before anything reads the roots.
        publish_nothing: AtomicBool,
        /// Signals that an add has reached the gate.
        entered: Semaphore,
        /// Publishes roots with NO `connection_id` and no `owning_target`,
        /// which is what a loaded plugin's `list_address_roots` looks like: the
        /// host fills those in for `root_info_for` and not for this. A child
        /// that does not attribute its roots is the ordinary case, not a
        /// broken one.
        unattributed_roots: AtomicBool,
        /// Parks `list_address_roots` until [`TenantChild::release_root_query`],
        /// so a test can hold a caller inside the one post-commit await on the
        /// add path and drop it there.
        park_root_query: AtomicBool,
        root_query_gate: Semaphore,
        /// Signals that a root query has reached the gate.
        entered_root_query: Semaphore,
    }

    impl TenantChild {
        fn new(name: &str) -> Arc<Self> {
            Self::build(name, None)
        }

        /// Like [`TenantChild::new`], but every `add_connection` parks until
        /// [`TenantChild::release`] is called.
        fn gated(name: &str) -> Arc<Self> {
            Self::build(name, Some(Semaphore::new(0)))
        }

        fn build(name: &str, gate: Option<Semaphore>) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                connections: Mutex::new(Vec::new()),
                authenticated_as: Mutex::new(None),
                extra_targets: Mutex::new(Vec::new()),
                fail_removals: AtomicBool::new(false),
                removals: std::sync::atomic::AtomicUsize::new(0),
                gate,
                fail_root_query: AtomicBool::new(false),
                ambiguous_adds: AtomicBool::new(false),
                publish_nothing: AtomicBool::new(false),
                ambiguous_removals: AtomicBool::new(false),
                stall_removals: AtomicBool::new(false),
                removal_cancelled: Arc::new(Semaphore::new(0)),
                scopes: Mutex::new(Vec::new()),
                entered: Semaphore::new(0),
                unattributed_roots: AtomicBool::new(false),
                park_root_query: AtomicBool::new(false),
                root_query_gate: Semaphore::new(0),
                entered_root_query: Semaphore::new(0),
            })
        }

        async fn wait_until_adding(&self) {
            self.entered
                .acquire()
                .await
                .expect("the gate stays open")
                .forget();
        }

        fn release(&self) {
            if let Some(gate) = &self.gate {
                gate.add_permits(1);
            }
        }

        async fn wait_until_querying_roots(&self) {
            self.entered_root_query
                .acquire()
                .await
                .expect("the gate stays open")
                .forget();
        }

        fn release_root_query(&self) {
            self.root_query_gate.add_permits(1);
        }

        fn root_info(&self, connection: &Connection, root: &Url) -> RootInfo {
            RootInfo {
                root: root.clone(),
                display_name: None,
                layer_kind: "tenant".to_string(),
                connection_id: if self.unattributed_roots.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(connection.id.clone())
                },
                owning_target: if self.unattributed_roots.load(Ordering::SeqCst) {
                    None
                } else {
                    Some(self.name.clone())
                },
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

        fn connection_count(&self) -> usize {
            self.connections.lock().len()
        }

        /// Install a connection the way a backend factory does for a non-empty
        /// layer config: built by the child itself, before any Router exists to
        /// be asked about it (`HttpBackendLayerFactory::create_backend` calls
        /// `install` directly). No `add_connection`, so no aggregation boundary.
        fn seed(self: &Arc<Self>, root: &str) -> Arc<Self> {
            let connection = Connection {
                id: ConnectionId(format!("{}-seed", self.name)),
                backend_kind: "tenant".to_string(),
                display_name: self.name.clone(),
                source: ConnectionSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                capabilities: Capabilities::empty(),
                current_addresses: vec![Url::parse(root).unwrap()],
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
                owning_target: None,
            };
            self.connections.lock().push(connection);
            Arc::clone(self)
        }
    }

    #[async_trait]
    impl Layer for TenantChild {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("tenant", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            let mut targets = vec![self.name.clone()];
            targets.extend(self.extra_targets.lock().iter().cloned());
            targets
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            if self.park_root_query.load(Ordering::SeqCst) {
                self.entered_root_query.add_permits(1);
                self.root_query_gate
                    .acquire()
                    .await
                    .expect("the gate stays open")
                    .forget();
            }
            if self.fail_root_query.load(Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::Transient, "root re-query failed"));
            }
            if self.publish_nothing.load(Ordering::SeqCst) {
                return Ok((
                    RootInfoSnapshot {
                        roots: Vec::new(),
                        updates: false,
                    },
                    None,
                ));
            }
            let roots = {
                let connections = self.connections.lock();
                connections
                    .iter()
                    .flat_map(|connection| {
                        connection
                            .current_addresses
                            .iter()
                            .filter(|address| {
                                // A listed scope is not a published root.
                                !self
                                    .scopes
                                    .lock()
                                    .iter()
                                    .any(|scope| address::same_node(scope, address))
                            })
                            .map(|address| self.root_info(connection, address))
                    })
                    .collect()
            };
            Ok((
                RootInfoSnapshot {
                    roots,
                    updates: false,
                },
                None,
            ))
        }

        /// Yields one `Succeeded` carrying a `Connection` stamped with
        /// `authenticated_as`, so a test can put a sibling's target on the auth
        /// path and watch the Router correct it -- or leave `None` and watch it
        /// fill from the request key.
        async fn authenticate_connection(
            &self,
            _request: Request<AuthenticateRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<AuthEventStream> {
            let connection = Connection {
                id: ConnectionId(format!("{}-seed", self.name)),
                backend_kind: "tenant".to_string(),
                display_name: self.name.clone(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: Vec::new(),
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
                owning_target: self.authenticated_as.lock().clone(),
            };
            // A bundle rides along so a test can prove the Router's
            // reconstruction of this event does not drop it.
            let mut credentials = SecretBundle::default();
            credentials.fields.insert(
                "token".to_string(),
                SecretValue::Bytes(SecretBytes(b"opaque".to_vec())),
            );
            Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: Some(credentials),
            }))))
        }

        /// Side-effect-free, and -- like [`TenantChild::seed`] -- it reports no
        /// owning target of its own, so what a caller reads back on this path
        /// is whatever the Router filled in.
        async fn probe(
            &self,
            _request: Request<LayerConnectionRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            Ok(Connection {
                id: ConnectionId(format!("{}-probe", self.name)),
                backend_kind: "tenant".to_string(),
                display_name: self.name.clone(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: Vec::new(),
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
                owning_target: None,
            })
        }

        async fn add_connection(
            &self,
            request: Request<LayerConnectionRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            let root = match request.input.connection.config.get("root_url") {
                Some(ConfigValue::String(value)) => Url::parse(value)
                    .map_err(|_| Error::new(ErrorCode::InvalidArgument, "root_url is not a URL"))?,
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "root_url is required",
                    ));
                }
            };
            // An address the connection LISTS but publishes no root for — the
            // shape an alias visibility override takes: `current_addresses`
            // carries the scope its rule governs, and a `Hidden` or
            // `Suppressed` override advertises nothing there.
            let scope =
                match request.input.connection.config.get("scope") {
                    Some(ConfigValue::String(value)) => Some(Url::parse(value).map_err(|_| {
                        Error::new(ErrorCode::InvalidArgument, "scope is not a URL")
                    })?),
                    _ => None,
                };
            // A SECOND root on one connection, the shape broker and
            // services-client take when they assign a whole discovered `Vec` to
            // `current_addresses`. Optional, because the single-root producers
            // (plugin-http, nucleus) are the other half of the contract.
            let extra = match request.input.connection.config.get("extra_root") {
                Some(ConfigValue::String(value)) => Some(Url::parse(value).map_err(|_| {
                    Error::new(ErrorCode::InvalidArgument, "extra_root is not a URL")
                })?),
                _ => None,
            };
            // Parked BEFORE the commit, which is where a real backend's probe
            // or handshake sits.
            if let Some(gate) = &self.gate {
                self.entered.add_permits(1);
                gate.acquire().await.expect("the gate stays open").forget();
            }
            if let Some(scope) = &scope {
                self.scopes.lock().push(scope.clone());
            }
            let mut connections = self.connections.lock();
            // Intra-INSTANCE exclusivity, the contract plugin-http's `install`
            // applies over its own state. It sees nothing outside this child.
            if connections.iter().any(|existing| {
                existing
                    .current_addresses
                    .iter()
                    .any(|held| address::same_node(held, &root))
            }) {
                return Err(Error::new(
                    ErrorCode::RouteConflict,
                    "this layer instance already serves that address prefix",
                ));
            }
            let connection = Connection {
                id: ConnectionId(format!("{}-{}", self.name, connections.len())),
                backend_kind: "tenant".to_string(),
                display_name: self.name.clone(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                // Deduped, because a real backend lists an address once even
                // when a rule's scope is the root it also serves.
                current_addresses: std::iter::once(root)
                    .chain(extra)
                    .chain(scope.clone())
                    .fold(Vec::new(), |mut listed: Vec<Url>, address| {
                        if !listed.iter().any(|held| address::same_node(held, &address)) {
                            listed.push(address);
                        }
                        listed
                    }),
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
                owning_target: None,
            };
            connections.push(connection.clone());
            if self.ambiguous_adds.load(Ordering::SeqCst) {
                // Committed, and unconfirmable — the shape a nested Router takes
                // when its catch-up fails after the grandchild registered.
                return Err(Error::new(
                    ErrorCode::CommitAmbiguous,
                    "the add committed and the route-table catch-up was abandoned",
                ));
            }
            Ok(connection)
        }

        async fn list_connections(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
            let connections = self.connections.lock().clone();
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
            _cancel: Option<CancellationToken>,
        ) -> Result<()> {
            self.removals.fetch_add(1, Ordering::SeqCst);
            if self.fail_removals.load(Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::Transient, "removal failed"));
            }
            if self.stall_removals.load(Ordering::SeqCst) {
                if let Some(cancel) = _cancel {
                    let cancelled = Arc::clone(&self.removal_cancelled);
                    tokio::spawn(async move {
                        cancel.cancelled().await;
                        cancelled.add_permits(1);
                    });
                }
                // A plugin whose FFI call has not come back: the Rust future
                // parks here, and only the token can tell it to stop.
                std::future::pending::<()>().await;
            }
            if self.ambiguous_removals.load(Ordering::SeqCst) {
                // Committed, then unconfirmable: the connection really is gone.
                self.connections
                    .lock()
                    .retain(|connection| connection.id != key.input.id);
                return Err(Error::new(
                    ErrorCode::CommitAmbiguous,
                    "the removal committed and the route-table catch-up was abandoned",
                ));
            }
            let mut connections = self.connections.lock();
            let before = connections.len();
            connections.retain(|connection| connection.id != key.input.id);
            if connections.len() == before {
                return Err(Error::new(ErrorCode::NotFound, "no such connection"));
            }
            Ok(())
        }
    }

    fn tenant_request(target: &str, root: &str) -> Request<LayerConnectionRequest> {
        tenant_request_with(target, root, None)
    }

    /// A request for a connection publishing TWO roots, the shape broker and
    /// services-client take.
    fn multi_root_request(
        target: &str,
        root: &str,
        extra: &str,
    ) -> Request<LayerConnectionRequest> {
        tenant_request_with(target, root, Some(extra))
    }

    /// A child that owns SEVERAL targets and takes caller-supplied connection
    /// ids — a nested Router, or a composite plugin reporting its internals.
    /// Two of its targets can therefore hold connections with one id, which is
    /// the shape `(child, id)` cannot tell apart.
    ///
    /// Publishes `owning_target` on its roots, as a layer that owns more than
    /// one must for anything to attribute them.
    struct CompositeChild {
        /// `(target, connection)`, so one id can appear under two targets.
        connections: Mutex<Vec<(String, Connection)>>,
        fail_removals: AtomicBool,
    }

    impl CompositeChild {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                connections: Mutex::new(Vec::new()),
                fail_removals: AtomicBool::new(false),
            })
        }

        /// Install a connection under one of its internal targets, the way its
        /// own composition would.
        fn seed(self: &Arc<Self>, target: &str, id: &str, root: &str) -> Arc<Self> {
            self.connections.lock().push((
                target.to_string(),
                Connection {
                    id: ConnectionId(id.to_string()),
                    backend_kind: "composite".to_string(),
                    display_name: id.to_string(),
                    source: ConnectionSource::Runtime { persisted: false },
                    capabilities: Capabilities::empty(),
                    current_addresses: vec![Url::parse(root).unwrap()],
                    auth_state: ConnectionAuthState::Anonymous,
                    last_probed: None,
                    user_metadata: UserMetadata::new(),
                    owning_target: None,
                },
            ));
            Arc::clone(self)
        }

        fn holds(&self, target: &str, id: &str) -> bool {
            self.connections
                .lock()
                .iter()
                .any(|(held, connection)| held == target && connection.id.0 == id)
        }
    }

    #[async_trait]
    impl Layer for CompositeChild {
        fn name(&self) -> &str {
            "composite"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("composite", LayerType::Backend, true)
        }

        fn owned_targets(&self) -> Vec<String> {
            vec!["inner-a".to_string(), "inner-b".to_string()]
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            let roots = self
                .connections
                .lock()
                .iter()
                .flat_map(|(target, connection)| {
                    let target = target.clone();
                    connection.current_addresses.iter().map(move |address| {
                        let mut root = root_for(address.as_str());
                        root.connection_id = Some(connection.id.clone());
                        root.owning_target = Some(target.clone());
                        root
                    })
                })
                .collect();
            Ok((
                RootInfoSnapshot {
                    roots,
                    updates: false,
                },
                None,
            ))
        }

        /// Yields the held row unattributed, as its flattened listing does --
        /// this child owns several targets and cannot say which holds a row.
        async fn authenticate_connection(
            &self,
            request: Request<AuthenticateRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<AuthEventStream> {
            let connection = self
                .connections
                .lock()
                .iter()
                .find(|(_, held)| held.id == request.input.key.id)
                .map(|(_, held)| held.clone())
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
            Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }))))
        }

        async fn list_connections(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
            // Flattened, exactly as the real surface is: no target on a row.
            let connections = self
                .connections
                .lock()
                .iter()
                .map(|(_, connection)| connection.clone())
                .collect();
            Ok((
                ConnectionSnapshot {
                    connections,
                    updates: false,
                },
                None,
            ))
        }

        async fn add_connection(
            &self,
            request: Request<LayerConnectionRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            let root = match request.input.connection.config.get("root_url") {
                Some(ConfigValue::String(value)) => Url::parse(value)
                    .map_err(|_| Error::new(ErrorCode::InvalidArgument, "root_url is not a URL"))?,
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "root_url is required",
                    ));
                }
            };
            // Caller-supplied, like the alias layer's — which is what lets two
            // targets hold one id.
            let id = match request.input.connection.config.get("id") {
                Some(ConfigValue::String(value)) => value.clone(),
                _ => "rule".to_string(),
            };
            let connection = Connection {
                id: ConnectionId(id),
                backend_kind: "composite".to_string(),
                display_name: "composite".to_string(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: vec![root],
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
                owning_target: None,
            };
            self.connections
                .lock()
                .push((request.input.target, connection.clone()));
            Ok(connection)
        }

        async fn remove_connection(
            &self,
            key: Request<ConnectionKey>,
            _cancel: Option<CancellationToken>,
        ) -> Result<()> {
            if self.fail_removals.load(Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "layer does not support remove_connection",
                ));
            }
            self.connections.lock().retain(|(target, connection)| {
                !(*target == key.input.target && connection.id == key.input.id)
            });
            Ok(())
        }
    }

    fn composite_request(target: &str, id: &str, root: &str) -> Request<LayerConnectionRequest> {
        Request::new(LayerConnectionRequest {
            target: target.to_string(),
            connection: ConnectionRequest {
                backend_kind: "composite".to_string(),
                config: HashMap::from([
                    (
                        "root_url".to_string(),
                        ConfigValue::String(root.to_string()),
                    ),
                    ("id".to_string(), ConfigValue::String(id.to_string())),
                ]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
    }

    #[tokio::test]
    async fn the_router_attributes_each_row_to_the_child_that_produced_it() {
        // Two children of one kind, each holding a connection, and the flat
        // snapshot is the only place a caller meets them. `backend_kind` says
        // `tenant` for both and neither publishes a distinguishing name, so
        // before the rows carried a target the listing could not say which
        // layer to address -- which is the whole reason `disconnect` had to
        // discover ownership by attempting the removal against each candidate.
        //
        // Neither child stamps its own rows (`TenantChild::seed` leaves them
        // unattributed), so this is the Router's fill and nothing else.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let stage = TenantChild::new("stage").seed("http://stage.example/assets/");
        let router = Arc::new(
            Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
                .await
                .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        let mut owners: Vec<(String, String)> = rows
            .iter()
            .map(|connection| {
                (
                    connection.id.0.clone(),
                    connection
                        .owning_target
                        .clone()
                        .expect("a single-target child's rows are attributable"),
                )
            })
            .collect();
        owners.sort();
        assert_eq!(
            owners,
            vec![
                ("prod-seed".to_string(), "prod".to_string()),
                ("stage-seed".to_string(), "stage".to_string()),
            ],
        );

        // The answer is not merely present, it is the one `route_target` reads
        // -- an attribution that did not round-trip through the target table
        // would be a name no connection op could use.
        for (_, target) in &owners {
            router
                .route_target(target)
                .unwrap_or_else(|_| panic!("`{target}` must be a routable target"));
        }
    }

    #[tokio::test]
    async fn a_child_owning_several_targets_leaves_its_rows_unattributed() {
        // The composite case: the child owns `inner-a` and `inner-b`, and its
        // flattened listing says nothing about which of them holds a row. The
        // Router cannot invent the answer, and must not substitute the child's
        // own `name()` -- that string is not in `state.targets`, so a key built
        // on it would answer `NotFound` against a graph that holds the
        // connection. `None` tells the caller to ask the graph instead.
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].owning_target, None,
            "a composite child's rows are not attributable from the fan-out",
        );
        assert!(
            router.route_target("composite").is_err(),
            "the child's own name is not a routable target, which is why it is \
             not substituted",
        );
    }

    #[tokio::test]
    async fn the_router_never_overwrites_a_child_supplied_target() {
        // A composite child that DOES attribute its own rows knows its interior
        // and the Router does not, so its answer stands. This is the shape a
        // loaded composite plugin takes once it reports the target itself.
        let composite = CompositeChild::new().seed("inner-b", "rule", "http://origin.example/b/");
        composite
            .connections
            .lock()
            .iter_mut()
            .for_each(|(target, connection)| {
                connection.owning_target = Some(target.clone());
            });
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        assert_eq!(rows[0].owning_target.as_deref(), Some("inner-b"));
        router
            .route_target("inner-b")
            .expect("and the child's own answer is a routable target");
    }

    #[tokio::test]
    async fn a_child_reporting_a_siblings_target_has_it_corrected() {
        // A caller addresses a reported target DIRECTLY, so a misreport is not
        // a cosmetic error: ids collide across targets legally, so `stage`'s
        // `rule` is a live connection somebody is using, and a removal aimed
        // there by `prod`'s misreport would take it out. The graph is the only
        // place this is visible -- `prod` cannot see that `stage` exists, and
        // `stage` is never asked.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let stage = TenantChild::new("stage").seed("http://stage.example/assets/");
        prod.connections
            .lock()
            .iter_mut()
            .for_each(|connection| connection.owning_target = Some("stage".to_string()));
        let prod_handle = prod.clone();
        let router = Arc::new(
            Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
                .await
                .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        let misreported = rows
            .iter()
            .find(|row| row.id.0 == "prod-seed")
            .expect("the misreporting child's row still lists");
        // Corrected, not cleared. `None` reads as "never attributed" to every
        // consumer, and the rotation's listing lookup takes an unattributed row
        // as a stand-in for whatever key it was given -- so a cleared row would
        // be adopted for the very `stage` key it misnamed, which is the outcome
        // this arm exists to prevent. The substituted name is verified rather
        // than guessed: it comes from the same `owned_targets()` call the route
        // table is built from, so it routes back to this child by construction.
        assert_eq!(
            misreported.owning_target.as_deref(),
            Some("prod"),
            "a target routing to a sibling is replaced by the one that reaches this child",
        );
        assert!(
            Arc::ptr_eq(
                &router
                    .route_target("prod")
                    .expect("the corrected target routes"),
                &(prod_handle as LayerHandle),
            ),
            "and it routes back to the child that produced the row",
        );
        // The honest sibling is untouched: this corrects a claim, it does not
        // punish the graph.
        assert_eq!(
            rows.iter()
                .find(|row| row.id.0 == "stage-seed")
                .and_then(|row| row.owning_target.as_deref()),
            Some("stage"),
        );
    }

    #[tokio::test]
    async fn the_listing_probe_and_add_paths_agree_on_owning_target() {
        // These three share a candidate source, so for them the strong claim
        // does hold: one connection, one answer, whatever produced the row. A
        // caller that reads `owning_target` from a listing and then calls
        // `probe` or `add` for the same connection must not see the field
        // change under it -- the plugin boundary one level down settled THIS
        // question the same way, hoisting the identical expression for its
        // snapshot and its four single-row ops, and a Router answering only on
        // the listing path would reintroduce the disagreement one level up.
        // (It chose differently for the auth path alone; see
        // [`Router::attribute_row`], which is about all six.) `TenantChild::seed` leaves its rows unattributed, so
        // every value below is the Router's fill.
        //
        // NAMED FOR WHAT IT MEASURES: three of the six `Connection`-bearing
        // exits. `TenantChild` implements neither update op, so both fall to
        // the `Layer` default's `Unsupported` and this fixture cannot reach
        // them; the auth path has its own test below, because it carries a row
        // on a stream rather than returning one.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let stage = TenantChild::new("stage").seed("http://stage.example/assets/");
        let router = Arc::new(
            Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
                .await
                .unwrap(),
        );

        let listed = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        let from_listing = listed
            .iter()
            .find(|row| row.id.0 == "prod-seed")
            .and_then(|row| row.owning_target.clone())
            .expect("the listing attributes it");
        assert_eq!(from_listing, "prod");

        let added = router
            .add_connection(tenant_request("prod", "http://prod.example/added/"), None)
            .await
            .expect("the add commits");
        assert_eq!(
            added.owning_target.as_deref(),
            Some(from_listing.as_str()),
            "add_connection must answer what the listing answers",
        );

        let probed = router
            .probe(tenant_request("prod", "http://prod.example/probed/"), None)
            .await
            .expect("the probe answers");
        assert_eq!(
            probed.owning_target.as_deref(),
            Some(from_listing.as_str()),
            "probe must answer what the listing answers",
        );
    }

    #[tokio::test]
    async fn a_misreported_target_is_corrected_on_the_auth_success_event_too() {
        // `AuthEvent::Succeeded` carries a `Connection`, so it is a sixth exit
        // and takes the same rule. The FILL leg would agree here without any
        // help -- a loaded plugin's row is back-filled below the Router with
        // the same sole target -- so the leg that matters is CORRECTION: a
        // child naming a SIBLING's target, forwarded untouched, would aim an
        // interactive sign-in at that sibling's connection, which is the harm
        // the rule exists to prevent. A correct self-report is left alone
        // instead; `the_auth_path_leaves_a_correct_self_report_alone` pins
        // that half.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let stage = TenantChild::new("stage").seed("http://stage.example/assets/");
        prod.authenticated_as.lock().replace("stage".to_string());
        let router = Arc::new(
            Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
                .await
                .unwrap(),
        );

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "prod".to_string(),
                        id: ConnectionId("prod-seed".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");

        let (succeeded, credentials) = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded {
                    connection,
                    credentials,
                }) => Some((connection, credentials)),
                _ => None,
            })
            .expect("the child yields a success event");
        assert_eq!(
            succeeded.owning_target.as_deref(),
            Some("prod"),
            "a sibling's target on the auth path is replaced by the request key",
        );
        // The Router rebuilds the event to swap the field, so the half it is
        // not changing has to come through untouched. Nothing else asserts it.
        assert!(
            credentials.is_some_and(|bundle| bundle.fields.contains_key("token")),
            "reconstructing the event must not drop the credential bundle",
        );
    }

    #[tokio::test]
    async fn the_auth_path_fills_an_unattributed_row_from_the_request_key() {
        // The fill leg. A child that reports nothing gets the key the caller
        // addressed -- which `route_target` has already proved reaches it, so
        // it is exact rather than derived. Separate from the correction test
        // because a rule that only ever overwrote would pass that one.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let stage = TenantChild::new("stage").seed("http://stage.example/assets/");
        let router = Arc::new(
            Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
                .await
                .unwrap(),
        );

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "stage".to_string(),
                        id: ConnectionId("stage-seed".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");

        let succeeded = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded { connection, .. }) => Some(connection),
                _ => None,
            })
            .expect("the child yields a success event");
        assert_eq!(succeeded.owning_target.as_deref(), Some("stage"));
    }

    #[tokio::test]
    async fn the_auth_path_does_not_go_stale_when_the_child_gains_targets() {
        // The staleness this path is built to avoid. `AuthEventStream` is a
        // blocking iterator the caller pulls at its own pace, so anything read
        // when the flow OPENED is frozen across an interactive sign-in. Here
        // the child becomes multi-target mid-flow -- the state in which
        // `owned_targets` has no single answer -- and the row still names the
        // key the caller addressed, because that key is what this flow is for.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let router = Arc::new(
            Router::new("r", vec![prod.clone() as LayerHandle], None)
                .await
                .unwrap(),
        );

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "prod".to_string(),
                        id: ConnectionId("prod-seed".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");

        // Between opening the flow and pulling the event.
        prod.extra_targets.lock().push("prod-inner-b".to_string());

        let succeeded = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded { connection, .. }) => Some(connection),
                _ => None,
            })
            .expect("the child yields a success event");
        // WHAT THIS RULES OUT, precisely: routing this path through
        // `attribute_row_in` with a LIVE `owned_targets` read, which is the
        // alternative that looks most correct. It would find no single target
        // and clear the row to `None` -- discarding an owner the request key
        // makes knowable. It does NOT rule out a hoisted read, which happens to
        // agree here; the case that separates that one is below.
        assert_eq!(
            succeeded.owning_target.as_deref(),
            Some("prod"),
            "a multi-target child mid-flow must not cost the row its owner",
        );
    }

    #[tokio::test]
    async fn the_auth_path_leaves_a_correct_self_report_alone() {
        // The deference arm, and the one an unconditional stamp destroys. This
        // child owns `inner-a` and `inner-b` and has attributed its own row to
        // `inner-b`, correctly. A caller reads that from the listing, then
        // authenticates by a key naming `inner-a` -- which routes to this same
        // child, so nothing about the request contradicts the row.
        //
        // The request proves target -> CHILD. It does not prove that the row
        // the child yields is the one the key named, so it is a candidate and
        // not a verdict: an unattributed row takes it, a sibling's name is
        // corrected to it, and a self-report the child stands behind is left
        // alone. Stamping it unconditionally gave one connection two answers
        // and made the auth path contradict the listing.
        let composite = CompositeChild::new().seed("inner-b", "rule", "http://origin.example/b/");
        composite
            .connections
            .lock()
            .iter_mut()
            .for_each(|(target, connection)| {
                connection.owning_target = Some(target.clone());
            });
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let from_listing = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections
            .into_iter()
            .find(|row| row.id.0 == "rule")
            .and_then(|row| row.owning_target)
            .expect("the child attributed its own row");
        assert_eq!(from_listing, "inner-b");

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "inner-a".to_string(),
                        id: ConnectionId("rule".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");

        let succeeded = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded { connection, .. }) => Some(connection),
                _ => None,
            })
            .expect("the child yields a success event");
        assert_eq!(
            succeeded.owning_target.as_deref(),
            Some(from_listing.as_str()),
            "the listing and the auth event must agree on one connection's owner",
        );
    }

    #[tokio::test]
    async fn listing_declines_where_the_auth_path_answers_and_that_is_intended() {
        // The divergence, asserted in ONE test on ONE router so it is a
        // decision rather than something two tests happen to imply.
        //
        // For a multi-target child the listing reports `None` -- flattening
        // lost which target holds the row -- and the auth path reports the
        // request key, which names what the listing could not recover. That is
        // declining and then answering, not two answers: no path here names a
        // target another contradicts, which is the invariant on
        // `Router::attribute_row`. A reader who finds this surprising should
        // read that docstring, which says what the auth answer rests on.
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let listed = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections
            .into_iter()
            .find(|row| row.id.0 == "rule")
            .expect("the row lists");
        assert_eq!(
            listed.owning_target, None,
            "the fan-out cannot say which of the child's targets holds this row",
        );

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "inner-a".to_string(),
                        id: ConnectionId("rule".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");
        let succeeded = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded { connection, .. }) => Some(connection),
                _ => None,
            })
            .expect("the child yields a success event");
        assert_eq!(
            succeeded.owning_target.as_deref(),
            Some("inner-a"),
            "the request names the target the listing could not recover",
        );
    }

    #[tokio::test]
    async fn the_auth_path_answers_for_a_composite_child_that_owned_targets_cannot() {
        // The request key is not merely fresher than an `owned_targets` read,
        // it is STRONGER. This child owns two internal targets, so
        // `sole_owning_target` declines however it is read -- live or hoisted,
        // both leave the row unattributed. The key names `inner-a`, and
        // `route_target` has already proved that key reaches this child, so the
        // owner is knowable exactly where the fan-out's rule gives up.
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let mut events = router
            .authenticate_connection(
                Request::new(AuthenticateRequest {
                    key: ConnectionKey {
                        target: "inner-a".to_string(),
                        id: ConnectionId("rule".to_string()),
                    },
                    capability: InteractiveAuthCapability::None,
                    auto_open_browser: false,
                }),
                None,
            )
            .await
            .expect("the flow opens");

        let succeeded = events
            .find_map(|event| match event {
                Ok(AuthEvent::Succeeded { connection, .. }) => Some(connection),
                _ => None,
            })
            .expect("the child yields a success event");
        assert_eq!(
            succeeded.owning_target.as_deref(),
            Some("inner-a"),
            "the key answers where `owned_targets` declines",
        );
    }

    #[tokio::test]
    async fn a_composite_child_misreporting_a_sibling_is_cleared() {
        // No knowable answer to substitute: a child owning several targets has
        // no single name that reaches it, so the misreport is cleared rather
        // than corrected. This is the residual case -- narrower than clearing
        // every misreport, which is what made a cleared row adoptable by the
        // rotation's listing lookup.
        let prod = TenantChild::new("prod").seed("http://prod.example/assets/");
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        composite
            .connections
            .lock()
            .iter_mut()
            .for_each(|(_, connection)| connection.owning_target = Some("prod".to_string()));
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod as LayerHandle, composite as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        assert_eq!(
            rows.iter()
                .find(|row| row.id.0 == "rule")
                .and_then(|row| row.owning_target.clone()),
            None,
            "a composite's misreport has no correct substitute, so it is cleared",
        );
    }

    #[tokio::test]
    async fn a_target_this_router_does_not_route_is_left_alone() {
        // The narrower-`owned_targets` shape: the broker-client and
        // services-client layers gate `owned_targets` on `supports_runtime_add`
        // yet still answer ops keyed on their own name. That name is absent
        // from the route table, and it still reaches the child that reported
        // it -- so it is not a sibling claim and must survive.
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        composite
            .connections
            .lock()
            .iter_mut()
            .for_each(|(_, connection)| {
                connection.owning_target = Some("unpublished".to_string());
            });
        let router = Arc::new(
            Router::new("r", vec![composite as LayerHandle], None)
                .await
                .unwrap(),
        );

        let rows = router
            .list_connections(&Extensions::new(), None)
            .await
            .expect("the fan-out answers")
            .0
            .connections;
        assert!(router.route_target("unpublished").is_err());
        assert_eq!(rows[0].owning_target.as_deref(), Some("unpublished"));
    }

    #[tokio::test]
    async fn quarantining_one_target_leaves_a_namesake_on_another_target_routing() {
        // Identity is `(target, id)`. This child owns two internal targets and
        // both hold `rule` — legal, because an id is unique only within its
        // target, and reachable through a nested Router or a composite plugin.
        // Keyed by id alone, quarantining `inner-b`'s `rule` suppressed
        // `inner-a`'s roots too: a healthy connection went dark, and the entry
        // never retired, because `inner-a`'s `rule` stayed in the child's
        // flattened listing.
        let prod = TenantChild::new("prod");
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        let router = Arc::new(
            Router::new(
                "r",
                vec![
                    prod.clone() as LayerHandle,
                    composite.clone() as LayerHandle,
                ],
                None,
            )
            .await
            .unwrap(),
        );
        let contested = "http://origin.example/shared/";
        router
            .add_connection(tenant_request("prod", contested), None)
            .await
            .expect("the sibling binds the contested root");

        // `inner-b` tries the same node and is refused; its rollback cannot land.
        composite.fail_removals.store(true, Ordering::SeqCst);
        let error = router
            .add_connection(composite_request("inner-b", "rule", contested), None)
            .await
            .expect_err("a sibling child already serves that root");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert!(
            composite.holds("inner-b", "rule"),
            "the refused connection is the leftover this quarantines",
        );

        // The suppression only reaches the table on the NEXT aggregation, so
        // without this the assertions below would read the pre-quarantine table
        // and pass whatever the matcher does.
        router
            .state
            .rebuild(router.state.next_generation(), None)
            .await
            .expect("the rebuild succeeds");

        // The property: `inner-a`'s connection is untouched and still routes.
        assert!(
            composite.holds("inner-a", "rule"),
            "the healthy namesake must still be registered",
        );
        let healthy = Url::parse("http://origin.example/a/").unwrap();
        let serving = router
            .route(&healthy)
            .expect("a sibling target's identically-named connection must keep routing");
        assert!(
            Arc::ptr_eq(&serving, &(composite as LayerHandle)),
            "and it must route to the child that holds it",
        );
    }

    /// Quarantine `inner-b/rule` on a composite child that also holds a
    /// namesake `inner-a/rule`, with the rollback refused so the leftover
    /// stands. Answers `(router, composite)`.
    async fn quarantined_namesake_router() -> (Arc<Router>, Arc<CompositeChild>) {
        let prod = TenantChild::new("prod");
        let composite = CompositeChild::new().seed("inner-a", "rule", "http://origin.example/a/");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod as LayerHandle, Arc::clone(&composite) as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );
        router
            .add_connection(
                tenant_request("prod", "http://origin.example/shared/"),
                None,
            )
            .await
            .expect("the sibling binds the contested root");
        composite.fail_removals.store(true, Ordering::SeqCst);
        let error = router
            .add_connection(
                composite_request("inner-b", "rule", "http://origin.example/shared/"),
                None,
            )
            .await
            .expect_err("a sibling child already serves that root");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert_eq!(
            router.state.quarantined.lock().len(),
            1,
            "the leftover is quarantined",
        );
        (router, composite)
    }

    #[tokio::test]
    async fn a_confirmed_removal_retires_a_quarantine_a_namesake_would_keep_alive() {
        // `retire_confirmed_quarantines` reads a FLATTENED listing: rows carry
        // an id and no target. `inner-a/rule` keeps the id in that listing for
        // the life of the process, so no rebuild can ever retire the entry for
        // `inner-b/rule` — the exact key has to be settled where this Layer
        // holds it, and a removal it performed is that.
        let (router, composite) = quarantined_namesake_router().await;
        composite.fail_removals.store(false, Ordering::SeqCst);
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "inner-b".to_string(),
                    id: ConnectionId("rule".to_string()),
                }),
                None,
            )
            .await
            .expect("the operator clears the leftover by hand");
        assert!(!composite.holds("inner-b", "rule"), "the leftover is gone",);
        assert!(
            composite.holds("inner-a", "rule"),
            "and the namesake that blocks id-based retirement is still there",
        );
        assert!(
            router.state.quarantined.lock().is_empty(),
            "so the entry has to retire on the removal, not on the listing",
        );
    }

    #[tokio::test]
    async fn a_re_added_key_is_not_withheld_by_the_quarantine_it_replaces() {
        // The harm a never-retiring entry does: a valid connection re-added at
        // the same `(target, id)` is answered `Ok`, and then withheld from the
        // route table for the life of the process — registered, probed, and
        // unroutable, with nothing said about it.
        let (router, composite) = quarantined_namesake_router().await;
        // The child let the leftover go on its own — a transient removal
        // failure that cleared, a reconnect that dropped it. Nothing told this
        // Layer, and nothing can: the namesake keeps the id in the listing.
        composite
            .connections
            .lock()
            .retain(|(target, connection)| !(target == "inner-b" && connection.id.0 == "rule"));

        let repaired = "http://origin.example/b/";
        router
            .add_connection(composite_request("inner-b", "rule", repaired), None)
            .await
            .expect("the key is free, so the add lands");
        router
            .state
            .rebuild(router.state.next_generation(), None)
            .await
            .expect("the rebuild succeeds");

        assert!(
            router.state.quarantined.lock().is_empty(),
            "binding the key is the child saying the leftover no longer holds it",
        );
        let serving = router
            .route(&Url::parse(repaired).unwrap())
            .expect("the re-added connection must route");
        assert!(
            Arc::ptr_eq(&serving, &(composite as LayerHandle)),
            "to the child that holds it",
        );
    }

    fn tenant_request_with(
        target: &str,
        root: &str,
        extra: Option<&str>,
    ) -> Request<LayerConnectionRequest> {
        let mut config = HashMap::from([(
            "root_url".to_string(),
            ConfigValue::String(root.to_string()),
        )]);
        if let Some(extra) = extra {
            config.insert(
                "extra_root".to_string(),
                ConfigValue::String(extra.to_string()),
            );
        }
        Request::new(LayerConnectionRequest {
            target: target.to_string(),
            connection: ConnectionRequest {
                backend_kind: "tenant".to_string(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
    }

    /// Two tenant children under one Router, neither holding a connection yet.
    async fn two_tenant_router() -> (Arc<Router>, Arc<TenantChild>, Arc<TenantChild>) {
        let prod = TenantChild::new("prod");
        let stage = TenantChild::new("stage");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );
        (router, prod, stage)
    }

    #[tokio::test]
    async fn a_sibling_child_cannot_bind_a_root_another_child_already_serves() {
        // The cross-child half of prefix exclusivity, on the add path. Two HTTP
        // children whose
        // connections differ only in userinfo name ONE origin node, and neither
        // child can see the other's roots — so without a refusal here both
        // register, both probe, and the loser is registered, unroutable and
        // silently unused.
        let (router, prod, stage) = two_tenant_router().await;
        let root = Url::parse("http://origin.example/assets/").unwrap();

        router
            .add_connection(tenant_request("prod", root.as_str()), None)
            .await
            .expect("the first tenant binds the root");

        // Same NODE, different spelling: no trailing slash, and userinfo the
        // node comparison ignores — the exact shape a corrected credential on
        // an already-served origin takes.
        let error = router
            .add_connection(
                tenant_request("stage", "http://user:secret@origin.example/assets"),
                None,
            )
            .await
            .expect_err("a sibling must not bind a root another child serves");
        assert_eq!(
            error.code(),
            ErrorCode::RouteConflict,
            "the refusal must be a route conflict, not the child's own answer: {error}",
        );

        // The newcomer is rolled back off its child, so it is not left
        // registered-but-unroutable — the state the refusal exists to prevent.
        assert_eq!(
            stage.connection_count(),
            0,
            "the refused connection must be rolled back off the child it committed on",
        );
        assert_eq!(
            prod.connection_count(),
            1,
            "the incumbent must be untouched by a refusal aimed at the newcomer",
        );
        let serving = router.route(&root).expect("the incumbent still routes");
        assert!(
            Arc::ptr_eq(&serving, &(prod as LayerHandle)),
            "the incumbent child must keep the route",
        );
    }

    #[tokio::test]
    async fn an_add_cancelled_while_queued_never_reaches_the_child() {
        // A queue is exactly where a caller gives up. Waiting on the add gate
        // with a plain `lock().await` ignored that: once the gate opened, the
        // abandoned request went on to the child, and a child need not notice
        // either — `FileBackend::add_connection` takes its `cancel` as `_cancel`
        // — so it registered a connection and answered `Ok` for a caller that
        // had left. Nothing has committed while queueing, so `Cancelled` is the
        // truthful answer.
        let prod = TenantChild::gated("prod");
        let stage = TenantChild::new("stage");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );

        // The gate holder: parked inside the child, holding `add_gate`.
        let holder = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(tenant_request("prod", "http://origin.example/held/"), None)
                    .await
            }
        });
        prod.wait_until_adding().await;

        // The queued caller, which then gives up.
        let cancel = CancellationToken::new();
        let queued = tokio::spawn({
            let router = Arc::clone(&router);
            let cancel = cancel.clone();
            async move {
                router
                    .add_connection(
                        tenant_request("stage", "http://origin.example/queued/"),
                        Some(cancel),
                    )
                    .await
            }
        });
        // Let it reach the gate before firing, so this exercises the WAIT rather
        // than the pre-flight check.
        tokio::task::yield_now().await;
        cancel.cancel();

        // Bounded, because the regression this guards does not fail — it
        // HANGS: a plain `lock().await` gives a cancelled caller no exit at
        // all, so the wait below would never return. A test that hangs tells CI
        // nothing; this one says what happened.
        let error = tokio::time::timeout(std::time::Duration::from_secs(10), queued)
            .await
            .expect(
                "the cancelled add never returned — a caller whose token fired must not be left \
                 waiting on the gate",
            )
            .expect("the queued task completes")
            .expect_err("a caller that left must not have its add applied");
        assert_eq!(
            error.code(),
            ErrorCode::Cancelled,
            "nothing committed while queueing, so the answer is the plain one: {error}",
        );
        assert_eq!(
            stage.connection_count(),
            0,
            "the child must never have seen the abandoned add",
        );

        // The holder still finishes on its own terms — a cancelled queuer does
        // not disturb it.
        prod.release();
        holder
            .await
            .expect("the holding task completes")
            .expect("the first add is unaffected");
        assert_eq!(prod.connection_count(), 1);
    }

    #[tokio::test]
    async fn a_build_time_collision_is_named_even_though_it_cannot_be_refused() {
        // The add path never sees these roots, so nothing refuses them — but
        // every root passes through the aggregation, so an operator can at
        // least be told which two layers are fighting over one node. The route
        // table's own warning cannot say that: it fires per root and names no
        // layer, so it reads the same for a benign nested overlap.
        let prod = TenantChild::new("prod").seed("http://origin.example/assets/");
        let stage = TenantChild::new("stage").seed("http://origin.example/assets/");
        let router = Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
            .await
            .expect("the build survives");

        let reported = router.state.reported_collisions.lock();
        assert_eq!(reported.len(), 1, "one contested node: {reported:?}");
        assert_eq!(
            reported[0].layers,
            ["prod", "stage"],
            "both layers must be named, since either could be the one to change",
        );
    }

    #[tokio::test]
    async fn a_collision_is_reported_once_rather_than_on_every_rebuild() {
        // A graph whose children publish update streams rebuilds on every
        // change; a standing misconfiguration must not repeat the line forever.
        let prod = TenantChild::new("prod").seed("http://origin.example/assets/");
        let stage = TenantChild::new("stage").seed("http://origin.example/assets/");
        let router = Router::new("r", vec![prod as LayerHandle, stage as LayerHandle], None)
            .await
            .unwrap();
        let first: Vec<Vec<String>> = router
            .state
            .reported_collisions
            .lock()
            .iter()
            .map(|c| c.layers.clone())
            .collect();

        // A second aggregation over the same roots.
        router
            .state
            .rebuild(router.state.next_generation(), None)
            .await
            .expect("the rebuild succeeds");
        let second: Vec<Vec<String>> = router
            .state
            .reported_collisions
            .lock()
            .iter()
            .map(|c| c.layers.clone())
            .collect();
        assert_eq!(
            second, first,
            "the set is unchanged, so nothing new is said",
        );
        assert_eq!(first.len(), 1, "and it is the collision, not an empty set");
    }

    #[test]
    fn containment_across_children_is_not_a_collision() {
        // Same rule as the add-path refusal: `x://h/a/` and `x://h/a/b/` are
        // independently routable under longest-prefix lookup, so a sibling
        // serving the broader root is not claiming the narrower one's node.
        let prod = TenantChild::new("prod") as LayerHandle;
        let stage = TenantChild::new("stage") as LayerHandle;
        let routes = vec![
            (root_for("http://origin.example/a/"), prod.clone()),
            (root_for("http://origin.example/a/b/"), stage),
            // And the same child publishing one node twice is its own business.
            (root_for("http://origin.example/c/"), prod.clone()),
            (root_for("http://origin.example/c"), prod),
        ];
        assert!(cross_child_collisions(&routes).is_empty());
    }

    #[test]
    fn one_node_under_two_spellings_on_two_children_is_a_collision() {
        // Node equality, not bytes: `assets` and `assets/` are one node, which
        // is the whole reason a corrected credential collides with the mistake
        // it corrects.
        let prod = TenantChild::new("prod") as LayerHandle;
        let stage = TenantChild::new("stage") as LayerHandle;
        let routes = vec![
            (root_for("http://origin.example/assets/"), prod),
            (root_for("http://origin.example/assets"), stage),
        ];
        let found = cross_child_collisions(&routes);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].layers, ["prod", "stage"]);
    }

    /// A published root at `address`, owning no connection — enough for the
    /// collision scan, which reads only the node and the publishing child.
    fn root_for(address: &str) -> RootInfo {
        RootInfo {
            root: Url::parse(address).unwrap(),
            display_name: None,
            layer_kind: "tenant".to_string(),
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
        }
    }

    #[tokio::test]
    async fn a_build_time_seed_is_outside_the_add_path_and_is_only_shadowed() {
        // WHERE THE REFUSAL ENDS. `cross_child_conflict` has one call site,
        // `add_connection`, so it sees connections that arrive through this
        // Layer: `[[ovstorage.connections]]` entries, which the host applies
        // that way, and `ovstorage connect`. A connection a backend factory
        // builds from its own `[ovstorage.layers.<name>]` block never passes
        // through it — the child installs it itself, before this Router exists
        // — and the Router first meets that root in its construction fan-out,
        // where `RouteTable::build` shadows the overlap and warns, exactly as it
        // did before the refusal was added.
        //
        // Pinned rather than left implicit because three docs describe the
        // refusal, and a reader who takes "graph-wide" as covering this case
        // would configure two same-kind layers against one origin and get a
        // silently unused credential. If enforcement is ever extended to the
        // build, this test is the one that should change first.
        let prod = TenantChild::new("prod").seed("http://origin.example/assets/");
        let stage = TenantChild::new("stage").seed("http://origin.example/assets/");
        let router = Router::new(
            "r",
            vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
            None,
        )
        .await
        .expect("a build-time collision does not fail the build");

        assert_eq!(prod.connection_count(), 1);
        assert_eq!(
            stage.connection_count(),
            1,
            "neither seed is rolled back: no add path ran to refuse one",
        );
        let root = Url::parse("http://origin.example/assets/").unwrap();
        let serving = router.route(&root).expect("the node routes");
        assert!(
            Arc::ptr_eq(&serving, &(prod as LayerHandle)),
            "one child wins the node and the other is shadowed, which is the \
             pre-existing route-table behaviour and not a refusal",
        );

        // And the add path still refuses on the very same node, which is what
        // makes the boundary a boundary rather than a gap in the check.
        let error = router
            .add_connection(
                tenant_request("stage", "http://origin.example/assets/"),
                None,
            )
            .await
            .expect_err("an add on a node a sibling already serves is refused");
        assert_eq!(error.code(), ErrorCode::RouteConflict);
    }

    #[tokio::test]
    async fn a_commit_whose_catch_up_published_nothing_still_holds_its_root() {
        // The gate orders the adds; it does not make the table current when it
        // is released. This add COMMITS on `prod` and then its catch-up fails —
        // the fan-out errors, nothing is published, nothing is rescheduled — so
        // the caller is told `CommitAmbiguous` and the gate is released with the
        // table never having heard of the root. Reading the table alone, the
        // next add on a sibling child would find the node free and bind it too:
        // two connections on one node, one of them registered, unroutable and
        // silently unused, which is the exact state this refusal exists to
        // prevent.
        let (router, prod, stage) = two_tenant_router().await;
        let root = Url::parse("http://origin.example/assets/").unwrap();

        prod.fail_root_query.store(true, Ordering::SeqCst);
        let ambiguous = router
            .add_connection(tenant_request("prod", root.as_str()), None)
            .await
            .expect_err("a catch-up that publishes nothing is not an `Ok`");
        assert_eq!(
            ambiguous.code(),
            ErrorCode::CommitAmbiguous,
            "the mutation committed and the table did not follow: {ambiguous}",
        );
        assert_eq!(
            prod.connection_count(),
            1,
            "the connection committed on the child regardless",
        );
        assert!(
            router.route(&root).is_err(),
            "the table cannot have the root — publishing it is what failed",
        );

        // The child is reachable again, so nothing about the SECOND add is
        // impaired: it is refused on the strength of the first add's committed
        // claim, not because the graph is broken.
        prod.fail_root_query.store(false, Ordering::SeqCst);
        let error = router
            .add_connection(tenant_request("stage", root.as_str()), None)
            .await
            .expect_err("a committed root is bound whether or not the table shows it");
        assert_eq!(error.code(), ErrorCode::RouteConflict);
        assert_eq!(
            stage.connection_count(),
            0,
            "the refused newcomer must be rolled back off its child",
        );
    }

    #[tokio::test]
    async fn a_claim_is_released_once_a_rebuild_has_carried_it() {
        // The claim is a stand-in for a table that has not caught up, not a
        // second permanent record: once a rebuild has published the root, the
        // table answers alone. Proven by removing the connection — which frees
        // the node — and binding the same root on the sibling, which a claim
        // left behind would refuse.
        let (router, prod, stage) = two_tenant_router().await;
        let root = Url::parse("http://origin.example/assets/").unwrap();

        let connection = router
            .add_connection(tenant_request("prod", root.as_str()), None)
            .await
            .expect("the first tenant binds the root");
        assert!(
            router.state.claimed_roots.lock().is_empty(),
            "a catch-up that published must leave no claim outstanding",
        );

        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "prod".to_string(),
                    id: connection.id.clone(),
                }),
                None,
            )
            .await
            .expect("the incumbent is removed");
        router
            .add_connection(tenant_request("stage", root.as_str()), None)
            .await
            .expect("a freed node is bindable again");
        assert_eq!(stage.connection_count(), 1);
        assert_eq!(prod.connection_count(), 0);
    }

    #[tokio::test]
    async fn a_removal_frees_a_root_whose_claim_outlived_its_catch_up() {
        // The claim has no explicit removal path, so this is what retires one
        // whose connection is gone: the removal's own catch-up stamps a higher
        // generation, and publishing it releases every claim at or below.
        // Without that a failed add would sterilise the node until the Router
        // was rebuilt.
        let (router, prod, stage) = two_tenant_router().await;
        let root = Url::parse("http://origin.example/assets/").unwrap();

        prod.fail_root_query.store(true, Ordering::SeqCst);
        let connection = {
            router
                .add_connection(tenant_request("prod", root.as_str()), None)
                .await
                .expect_err("the catch-up fails");
            prod.connections.lock()[0].clone()
        };
        assert!(
            !router.state.claimed_roots.lock().is_empty(),
            "the committed root is claimed while the table lags",
        );

        prod.fail_root_query.store(false, Ordering::SeqCst);
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "prod".to_string(),
                    id: connection.id.clone(),
                }),
                None,
            )
            .await
            .expect("the connection is removed and the catch-up publishes");
        assert!(
            router.state.claimed_roots.lock().is_empty(),
            "a published rebuild retires the claim it has caught up with",
        );
        router
            .add_connection(tenant_request("stage", root.as_str()), None)
            .await
            .expect("the node is free again");
        assert_eq!(stage.connection_count(), 1);
    }

    /// A request for a connection whose ONLY address is a management scope: it
    /// lists the address its rule governs and publishes no root anywhere, which
    /// is the shape `AliasWrapper::visibility_connection` builds for a `Hidden`
    /// or `Suppressed` override (`current_addresses: vec![rule.address]`).
    fn scope_only_request(target: &str, scope: &str) -> Request<LayerConnectionRequest> {
        let mut request = tenant_request(target, scope);
        request
            .input
            .connection
            .config
            .insert("scope".to_string(), ConfigValue::String(scope.to_string()));
        request
    }

    #[tokio::test]
    async fn an_address_a_connection_lists_but_does_not_serve_is_not_a_claim() {
        // `current_addresses` is what a connection LISTS, not what it routes.
        // The in-tree `AliasWrapper` gives a visibility-override connection the
        // arbitrary address its rule governs, and a `Hidden` or `Suppressed`
        // override publishes no root for it — so reading those entries as route
        // claims refused a valid visibility rule, and rolled it back, merely
        // because a sibling served the address it governs.
        let (router, prod, stage) = two_tenant_router().await;
        let governed = "http://origin.example/governed/";
        router
            .add_connection(tenant_request("prod", governed), None)
            .await
            .expect("the sibling serves the address the rule will govern");

        router
            .add_connection(scope_only_request("stage", governed), None)
            .await
            .expect("a scope it does not serve must not collide with a sibling that does");
        assert_eq!(stage.connection_count(), 1, "and it is not rolled back");

        // The sibling keeps the address it actually serves.
        let serving = router
            .route(&Url::parse(governed).unwrap())
            .expect("the address still routes");
        assert!(
            Arc::ptr_eq(&serving, &(prod as LayerHandle)),
            "to the child that publishes a root for it",
        );
    }

    #[tokio::test]
    async fn a_partial_collision_shadows_the_one_root_and_keeps_the_connection() {
        // Broker and services-client connections publish a whole discovered set
        // of roots. Refusing the connection because ONE of them collides costs
        // the caller every other address space it serves — and at startup the
        // skip arm drops the declared connection outright, so those spaces
        // vanish behind a warning the CLI does not print by default. Worse than
        // the duplicate it would prevent, and the skip arm's own precondition
        // (every address resolves to the incumbent) is false here.
        let (router, prod, stage) = two_tenant_router().await;
        let shared = "http://origin.example/shared/";
        router
            .add_connection(tenant_request("prod", shared), None)
            .await
            .expect("the first tenant binds the shared root");

        router
            .add_connection(
                multi_root_request("stage", "http://origin.example/stage-only/", shared),
                None,
            )
            .await
            .expect("a connection that also serves roots of its own is kept");

        assert_eq!(
            stage.connection_count(),
            1,
            "a partial collision must not roll the connection back",
        );
        // The residue of keeping it: `stage`'s connection goes on publishing a
        // root it does not serve, so a listing shows it against an address the
        // incumbent answers for. This Layer cannot un-publish a child's root —
        // there is no verb for it — so what it can do is refuse to let that be
        // silent, and the aggregation names the contested node and both layers.
        let reported = router.state.reported_collisions.lock();
        assert_eq!(
            reported.len(),
            1,
            "the contested root must be reported, not merely shadowed: {reported:?}",
        );
        assert_eq!(reported[0].layers, ["prod", "stage"]);
        drop(reported);
        // The root it serves alone routes to it — the whole point of keeping it.
        let own = Url::parse("http://origin.example/stage-only/x").unwrap();
        assert!(
            Arc::ptr_eq(
                &router.route(&own).expect("its own root routes"),
                &(stage as LayerHandle)
            ),
            "the address space it does not share must still be served",
        );
        // And the shared one is shadowed rather than stolen: the connection
        // already serving it keeps it. The sibling case below pins that this is
        // incumbency and not the order the children sit in.
        let contested = Url::parse(shared).unwrap();
        assert!(
            Arc::ptr_eq(
                &router
                    .route(&contested)
                    .expect("the shared root still routes"),
                &(prod as LayerHandle)
            ),
            "the incumbent keeps the root it already served",
        );
    }

    #[tokio::test]
    async fn a_partial_collision_shadows_the_newcomer_from_whichever_child_it_arrives_on() {
        // The same shape with the children the other way round: the incumbent
        // is on `stage`, which this Router aggregates SECOND, and the newcomer
        // arrives on `prod`, aggregated first. `RouteTable` breaks a same-node
        // overlap by aggregation order, so without `incumbents_first` the
        // newcomer would take the route — a working, already-serving connection
        // silently rerouted to another backend behind a `warn` the CLI does not
        // print unless `RUST_LOG` is set. Which child is which must not decide
        // this.
        let (router, prod, stage) = two_tenant_router().await;
        let shared = "http://origin.example/shared/";
        router
            .add_connection(tenant_request("stage", shared), None)
            .await
            .expect("the incumbent binds the shared root on the LATER child");

        router
            .add_connection(
                multi_root_request("prod", "http://origin.example/prod-only/", shared),
                None,
            )
            .await
            .expect("a connection that also serves roots of its own is kept");

        assert_eq!(
            prod.connection_count(),
            1,
            "a partial collision must not roll the connection back",
        );
        let contested = Url::parse(shared).unwrap();
        assert!(
            Arc::ptr_eq(
                &router
                    .route(&contested)
                    .expect("the shared root still routes"),
                &(stage as LayerHandle)
            ),
            "the incumbent keeps the root it already served, from either child",
        );
        // The newcomer still gets everything it does not share, which is the
        // reason it was kept at all.
        let own = Url::parse("http://origin.example/prod-only/x").unwrap();
        assert!(
            Arc::ptr_eq(
                &router.route(&own).expect("its own root routes"),
                &(prod as LayerHandle)
            ),
            "the address space it does not share must still be served",
        );
    }

    #[tokio::test]
    async fn a_shadowed_root_does_not_change_hands_on_a_later_rebuild() {
        // Once the collision exists, BOTH children publish the contested node
        // and every later rebuild re-decides it. Reading incumbency off every
        // published entry rather than the one that RESOLVES would make the
        // shadowed root an incumbent too — and then aggregation order would
        // decide again, flipping the route to the newcomer on whatever mutation
        // came next. The route has to stay where it is until the connection
        // holding it goes away.
        let (router, prod, stage) = two_tenant_router().await;
        let shared = "http://origin.example/shared/";
        router
            .add_connection(tenant_request("stage", shared), None)
            .await
            .expect("the incumbent binds the shared root");
        router
            .add_connection(
                multi_root_request("prod", "http://origin.example/prod-only/", shared),
                None,
            )
            .await
            .expect("the partial collision is kept");

        // Any later mutation rebuilds the table from both children's roots.
        router
            .add_connection(tenant_request("prod", "http://origin.example/later/"), None)
            .await
            .expect("an unrelated add on the newcomer's child succeeds");

        let contested = Url::parse(shared).unwrap();
        assert!(
            Arc::ptr_eq(
                &router
                    .route(&contested)
                    .expect("the shared root still routes"),
                &(stage as LayerHandle)
            ),
            "a rebuild must not hand the contested root to the shadowed side",
        );
        assert_eq!(prod.connection_count(), 2);
    }

    #[tokio::test]
    async fn a_total_collision_is_still_refused_for_a_multi_root_connection() {
        // The distinction is partial-vs-total, not one-root-vs-many: a
        // connection whose every root is already served has nothing left to
        // offer, so the refusal (and the startup skip that follows it) costs
        // nothing.
        let (router, _prod, stage) = two_tenant_router().await;
        let first = "http://origin.example/a/";
        let second = "http://origin.example/b/";
        router
            .add_connection(multi_root_request("prod", first, second), None)
            .await
            .expect("the first tenant binds both roots");

        let error = router
            .add_connection(multi_root_request("stage", first, second), None)
            .await
            .expect_err("every root is already served");
        assert_eq!(error.code(), ErrorCode::RouteConflict);
        assert_eq!(
            stage.connection_count(),
            0,
            "a total collision is rolled back as before",
        );
    }

    #[tokio::test]
    async fn concurrent_adds_cannot_both_claim_one_root() {
        // The exclusivity check is a read-then-act on the route table, and the
        // `Layer` API asks no caller to serialize mutations. Unguarded, both
        // adds commit, both read the same pre-add table, both find nothing, and
        // both succeed — recreating the registered-but-unroutable pair the
        // check exists to prevent.
        //
        // The gate on `prod` is where a real backend's probe or handshake sits,
        // so this is the ordinary window rather than a contrived one.
        let prod = TenantChild::gated("prod");
        let stage = TenantChild::new("stage");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );
        let root = "http://origin.example/assets/";

        let first = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(tenant_request("prod", root), None)
                    .await
            }
        });
        // The first add is now inside its child, past the point of no return
        // and holding the Router's add gate.
        prod.wait_until_adding().await;

        let second = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(tenant_request("stage", root), None)
                    .await
            }
        });
        // Give the second every chance to race ahead. It must be parked on the
        // Router, not on anything its own child does — `stage` has no gate.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            stage.connection_count(),
            0,
            "the second add must not reach its child while the first is mid-cycle",
        );

        prod.release();
        first
            .await
            .expect("the first task must not panic")
            .expect("the first add binds the root");
        let error = second
            .await
            .expect("the second task must not panic")
            .expect_err("one root, one connection");
        assert_eq!(
            error.code(),
            ErrorCode::RouteConflict,
            "the loser of the race must be refused, not silently registered: {error}",
        );
        assert_eq!(
            stage.connection_count(),
            0,
            "the refused newcomer must be rolled back off its child",
        );
        assert_eq!(prod.connection_count(), 1);
    }

    #[tokio::test]
    async fn a_claim_recorded_after_its_generation_published_does_not_reserve_forever() {
        // A claim leaves `claimed_roots` only through `release_claims_through`,
        // which runs during a rebuild and sweeps everything at or below the
        // generation it applied. So a claim INSERTED into a generation window
        // that has already been swept is never looked at again: no later
        // rebuild lowers `applied_generation` to reach it.
        //
        // `reserve_after_ambiguous_commit` is exactly that shape — it stamps,
        // then awaits the child's root snapshot, and a removal (which takes no
        // add gate) can allocate a newer generation, publish, and release
        // through it while that query is outstanding. The claim then reserved
        // the node for the life of the process, and because the exclusivity
        // check consults claims BEFORE anything schedules a catch-up, every
        // sibling add on that node was refused and none of them could clear it.
        let prod = TenantChild::new("prod");
        let stage = TenantChild::new("stage");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );
        let root = "http://origin.example/assets/";

        // Stamped, as a reservation does before it goes and asks the child.
        let stale = router.state.next_generation();
        // A concurrent removal's rebuild allocates a newer generation and
        // publishes, releasing through it.
        router
            .state
            .rebuild(router.state.next_generation(), None)
            .await
            .expect("the rebuild succeeds");
        // The reservation's query now returns and records its claim, late.
        router.state.claim_roots(
            &(prod.clone() as LayerHandle),
            vec![Url::parse(root).unwrap()],
            stale,
        );

        assert!(
            router.state.claimed_roots.lock().is_empty(),
            "a claim whose generation has already been applied is covered by the \
             published table and must not be recorded, or nothing will ever release it",
        );
        // The property that matters to a caller: the node is still bindable.
        router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect("an unclaimed node must still be bindable");
    }

    #[tokio::test]
    async fn a_caller_dropped_mid_check_leaves_its_committed_add_claimed() {
        // The exclusivity check may await `published_claims` to reach its
        // verdict, and that is the one post-commit suspension point on the
        // ordinary path. A caller future dropped there — an RPC client hanging
        // up on a slow child — unwound with the connection COMMITTED on the
        // child, no claim, no quarantine, and the add gate released. Against an
        // `updates: false` child nothing ever reconciled it, so the next
        // sibling add read a table that had never heard of those roots and
        // bound one of them.
        let prod = TenantChild::new("prod");
        let stage = TenantChild::new("stage");
        let extra = TenantChild::new("extra");
        let router = Arc::new(
            Router::new(
                "r",
                vec![
                    prod.clone() as LayerHandle,
                    stage.clone() as LayerHandle,
                    extra.clone() as LayerHandle,
                ],
                None,
            )
            .await
            .unwrap(),
        );
        let contested = "http://origin.example/shared/";
        let uncontested = "http://origin.example/stage-only/";
        router
            .add_connection(tenant_request("prod", contested), None)
            .await
            .expect("the incumbent binds the contested root");

        // `stage` publishes two roots, one of them contested. That partial
        // collision is what makes the check pay for a `published_claims` query
        // rather than answering from `current_addresses` alone.
        stage.park_root_query.store(true, Ordering::SeqCst);
        let add = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(multi_root_request("stage", contested, uncontested), None)
                    .await
            }
        });
        stage.wait_until_querying_roots().await;
        assert_eq!(
            stage.connection_count(),
            1,
            "the child has committed by the time the check queries it",
        );
        // The caller gives up right there.
        add.abort();
        let _ = add.await;
        stage.release_root_query();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        // Nothing published the abandoned connection's roots — the catch-up
        // never ran — so the claim is the only record that they are bound.
        assert_eq!(
            stage.connection_count(),
            1,
            "the abandoned add is still committed on its child",
        );
        let error = router
            .add_connection(tenant_request("extra", uncontested), None)
            .await
            .expect_err("that root is bound by the connection the dropped caller left behind");
        assert_eq!(
            error.code(),
            ErrorCode::RouteConflict,
            "a committed add must constrain siblings even when its caller walked away: {error}",
        );
        assert_eq!(
            extra.connection_count(),
            0,
            "and the refused newcomer must be rolled back off its child",
        );
    }

    #[tokio::test]
    async fn a_refused_connection_stays_withheld_when_its_child_does_not_attribute_roots() {
        // `published_claims` accepts a root carrying no `connection_id` as the
        // added connection's own — a child that does not attribute its roots,
        // not one disclaiming them — which is what lets a refusal happen on
        // such a child at all. Withholding has to read it the same way. When it
        // did not, the refused connection's roots went back into the table the
        // moment the incumbent was removed, and the connection this Layer had
        // REPORTED AS REFUSED became the active route, serving under the
        // credential it had already probed with.
        let prod = TenantChild::new("prod");
        let stage = TenantChild::new("stage");
        let router = Arc::new(
            Router::new(
                "r",
                vec![prod.clone() as LayerHandle, stage.clone() as LayerHandle],
                None,
            )
            .await
            .unwrap(),
        );
        let contested = "http://origin.example/shared/";
        let incumbent = router
            .add_connection(tenant_request("prod", contested), None)
            .await
            .expect("the incumbent binds the contested root");

        // `stage` is refused for that root and cannot be rolled back, so the
        // leftover stands and is quarantined.
        stage.unattributed_roots.store(true, Ordering::SeqCst);
        stage.fail_removals.store(true, Ordering::SeqCst);
        let error = router
            .add_connection(tenant_request("stage", contested), None)
            .await
            .expect_err("a sibling child already serves that root");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert_eq!(
            stage.connection_count(),
            1,
            "the refused connection is the leftover this quarantines",
        );

        // Whatever it collided with goes away. This is the moment the
        // quarantine exists for.
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "prod".to_string(),
                    id: incumbent.id.clone(),
                }),
                None,
            )
            .await
            .expect("the incumbent is removed");

        assert!(
            router.route(&Url::parse(contested).unwrap()).is_err(),
            "a connection this Layer refused must not become the route once the \
             incumbent is gone, whether or not its child says whose root it is",
        );
        assert_eq!(
            router.state.quarantined.lock().len(),
            1,
            "and the entry stands while the leftover is still registered",
        );
    }

    #[tokio::test]
    async fn a_refusal_names_only_the_origin_of_the_colliding_prefix() {
        // Every other part of a route prefix can carry a secret, and the shared
        // redaction pass recognises only some of them. The message must name
        // the origin and nothing else.
        let (router, _prod, _stage) = two_tenant_router().await;
        router
            .add_connection(
                tenant_request("prod", "http://origin.example:8443/assets/"),
                None,
            )
            .await
            .expect("the first tenant binds the root");

        // No query here: the query IS part of the node key, so a pinned root is
        // a DIFFERENT node and would not collide at all. The query's rendering
        // is covered directly, in
        // `a_route_prefix_renders_as_its_origin_alone`.
        let error = router
            .add_connection(
                tenant_request("stage", "http://user:hunter2@origin.example:8443/assets/"),
                None,
            )
            .await
            .expect_err("a sibling must not bind a root another child serves");
        let message = error.to_string();
        assert!(
            message.contains("http://origin.example:8443"),
            "the refusal must name the origin it collides on: {message}",
        );
        for secret in ["hunter2", "user:", "/assets"] {
            assert!(
                !message.contains(secret),
                "the refusal must not render '{secret}': {message}",
            );
        }
    }

    #[tokio::test]
    async fn a_containing_sibling_root_is_still_accepted() {
        // Longest-prefix nesting across children stays legal in BOTH
        // directions: a sibling root that contains the newcomer's, and a
        // newcomer that contains the incumbent's. Only same-node collisions are
        // unroutable, and refusing containment would also break the startup
        // skip arm, which is sound only when the newcomer's addresses resolve
        // to the incumbent.
        let (router, prod, stage) = two_tenant_router().await;
        router
            .add_connection(tenant_request("prod", "http://origin.example/a/"), None)
            .await
            .expect("the first tenant binds the root");

        router
            .add_connection(tenant_request("stage", "http://origin.example/a/b/"), None)
            .await
            .expect("a root CONTAINED by a sibling's is independently routable");
        router
            .add_connection(tenant_request("stage", "http://origin.example/"), None)
            .await
            .expect("a root CONTAINING a sibling's is independently routable");

        assert_eq!(prod.connection_count(), 1);
        assert_eq!(
            stage.connection_count(),
            2,
            "neither nested root may be rolled back",
        );
        let nested = Url::parse("http://origin.example/a/b/c").unwrap();
        let serving = router.route(&nested).expect("the nested root routes");
        assert!(
            Arc::ptr_eq(&serving, &(stage as LayerHandle)),
            "longest prefix still wins across children",
        );
    }

    #[tokio::test]
    async fn an_intra_child_conflict_still_comes_from_the_child() {
        // Exclusivity over a child's own roots is the child's contract, already
        // applied there. The Router must not intercept it, rewrite it, or roll
        // the INCUMBENT back on a duplicate add.
        let (router, prod, _stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first add binds the root");

        let error = router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect_err("the child refuses its own duplicate");
        assert_eq!(error.code(), ErrorCode::RouteConflict);
        assert!(
            error.to_string().contains("this layer instance"),
            "the child's own refusal must reach the caller verbatim: {error}",
        );
        assert_eq!(
            prod.removals.load(Ordering::SeqCst),
            0,
            "a refusal raised INSIDE the child leaves nothing for the Router to roll back",
        );
        assert_eq!(
            prod.connection_count(),
            1,
            "the incumbent must survive a refused duplicate",
        );
    }

    #[tokio::test]
    async fn a_rollback_that_failed_is_reported_as_committed_not_as_a_refusal() {
        // A refusal whose removal did not land is not a refusal: the connection
        // is registered, holding credentials it has already probed with.
        // `RouteConflict` would say nothing happened, which is the one thing
        // that is not true — so it reports the code the contract reserves for a
        // mutation that stuck, and names what to remove by hand.
        let (router, prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first tenant binds the root");
        stage.fail_removals.store(true, Ordering::SeqCst);

        let error = router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("a sibling must not bind a root another child serves");
        assert_eq!(
            error.code(),
            ErrorCode::CommitAmbiguous,
            "the add is still committed, and the caller has to be told: {error}",
        );
        assert!(
            error.message().contains("stage"),
            "the layer to clean up must be named: {error}",
        );
        assert!(
            error.message().contains("stage-0"),
            "and the connection on it: {error}",
        );
        assert_eq!(
            stage.removals.load(Ordering::SeqCst),
            1,
            "the rollback must have been attempted",
        );
        assert_eq!(
            stage.connection_count(),
            1,
            "a rollback that failed leaves the newcomer on the child",
        );

        // The hazard the quarantine closes: the leftover is one rebuild away
        // from serving. Take the incumbent away — nothing contests the node any
        // more — and it must STILL not route, because what this Layer refused it
        // does not serve later by accident.
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "prod".to_string(),
                    id: ConnectionId("prod-0".to_string()),
                }),
                None,
            )
            .await
            .expect("the incumbent is removed");
        assert_eq!(prod.connection_count(), 0);
        assert!(
            router.route(&Url::parse(root).unwrap()).is_err(),
            "a connection this Layer refused must not become routable once the root it \
             collided with is gone",
        );
    }

    #[tokio::test]
    async fn a_childs_committed_but_unconfirmed_add_still_reserves_its_roots() {
        // The nested-graph hole: a child Router whose own catch-up fails answers
        // `CommitAmbiguous` with the connection registered on ITS child. The
        // parent gets an error and no `Connection`, so it can neither check
        // exclusivity nor claim — and its table never learned the roots either,
        // because the failure IS the reconcile that would have published them.
        // Releasing the gate there lets the next sibling add bind the same node.
        let (router, prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        prod.ambiguous_adds.store(true, Ordering::SeqCst);

        let error = router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect_err("the child could not confirm its own commit");
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous);
        assert_eq!(
            prod.connection_count(),
            1,
            "the add committed on the child regardless, which is what the code means",
        );
        assert!(
            router.route(&Url::parse(root).unwrap()).is_err(),
            "and the parent's table has not caught up with it",
        );

        // The property this test exists for: a sibling may not take the node
        // the committed connection is serving, even though nothing about it
        // reached the route table.
        let refused = router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("a sibling must not bind a root a committed add already holds");
        assert_eq!(refused.code(), ErrorCode::RouteConflict);
        assert_eq!(
            stage.connection_count(),
            0,
            "and the refused newcomer is rolled back off its child",
        );
    }

    #[tokio::test]
    async fn a_reservation_that_cannot_be_queried_does_not_block_the_add_path() {
        // The residue: if the child cannot say what it publishes either, there
        // is nothing to reserve and the warning says so. What must NOT happen is
        // the add path failing or hanging because of it.
        let (router, prod, _stage) = two_tenant_router().await;
        prod.ambiguous_adds.store(true, Ordering::SeqCst);
        prod.fail_root_query.store(true, Ordering::SeqCst);

        let error = router
            .add_connection(
                tenant_request("prod", "http://origin.example/assets/"),
                None,
            )
            .await
            .expect_err("the child could not confirm its own commit");
        assert_eq!(
            error.code(),
            ErrorCode::CommitAmbiguous,
            "the caller still gets the child's own answer, not the recovery's: {error}",
        );
        assert!(
            router.state.claimed_roots.lock().is_empty(),
            "nothing could be learned, so nothing is claimed",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_rollback_that_times_out_cancels_the_child_it_gave_up_on() {
        // A timeout that only drops the future is not a cancellation. Dropping
        // a child's future unwinds the Rust half alone — a plugin's task and its
        // `user_data` live until the FFI call ends — so a stalled removal has to
        // be TOLD to stop, or every refused add against a wedged plugin leaks an
        // outstanding task for the life of the process. The token these calls
        // were handed was a child of the Router's own, which fires only at
        // Router drop.
        let (router, _prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first tenant binds the root");
        stage.stall_removals.store(true, Ordering::SeqCst);

        let cancelled = Arc::clone(&stage.removal_cancelled);
        let refused = tokio::spawn({
            let router = Arc::clone(&router);
            async move {
                router
                    .add_connection(tenant_request("stage", root), None)
                    .await
            }
        });

        // The stalled removal is told to stop by its own deadline, not by the
        // Router going away — this test never drops the Router.
        let permit = tokio::time::timeout(
            CHILD_ROOT_QUERY_TIMEOUT + std::time::Duration::from_secs(5),
            cancelled.acquire(),
        )
        .await
        .expect("the stalled removal must be cancelled when its deadline passes");
        permit.expect("the semaphore stays open").forget();

        let error = refused
            .await
            .expect("the add task completes")
            .expect_err("the add is still refused");
        assert_eq!(
            error.code(),
            ErrorCode::CommitAmbiguous,
            "a removal that never answered leaves the connection registered: {error}",
        );
    }

    #[tokio::test]
    async fn a_rollback_the_child_could_not_confirm_is_still_a_rollback() {
        // `CommitAmbiguous` from a REMOVAL means the removal happened — it is
        // what this Layer itself answers when a child let go and the catch-up
        // did not follow, so a nested Router hands it back for exactly that.
        // Reading it as a failure reported the ADD as committed, and the CLI
        // keeps the declaration for that code, so `write-config` persisted an
        // entry for a connection that had been rolled back and the next startup
        // recreated it.
        let (router, _prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first tenant binds the root");
        stage.ambiguous_removals.store(true, Ordering::SeqCst);

        let error = router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("a sibling must not bind a root another child serves");
        assert_eq!(
            error.code(),
            ErrorCode::RouteConflict,
            "the add was refused AND undone, so nothing about it survived: {error}",
        );
        assert_eq!(
            stage.connection_count(),
            0,
            "the removal committed, whatever the child could confirm about its routes",
        );
    }

    #[tokio::test]
    async fn a_confirmed_rollback_reports_the_conflict_and_leaves_no_quarantine() {
        // The ordinary path must not pay for the one above: when the child
        // confirms the removal, the refusal is complete and the caller gets the
        // diagnosis it can act on.
        let (router, _prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first tenant binds the root");

        let error = router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("a sibling must not bind a root another child serves");
        assert_eq!(error.code(), ErrorCode::RouteConflict);
        assert_eq!(stage.connection_count(), 0, "the newcomer is gone");
        assert!(
            router.state.quarantined.lock().is_empty(),
            "a completed refusal holds nothing back",
        );
    }

    #[tokio::test]
    async fn a_quarantine_survives_a_rebuild_the_connection_published_nothing_in() {
        // "Published nothing" is not "is gone". A parked connection publishes no
        // roots — root discovery is skipped for one — and a discovery-backed
        // child mid-reconnect answers the same way, neither of which means the
        // leftover was removed. Retiring on that dropped the entry while the
        // connection was still registered, and when it published again, with
        // whatever it collided with since removed, the connection this Layer
        // REFUSED became the route for that address, serving under the
        // credential it probed with during the add.
        let (router, prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .expect("the first tenant binds the root");
        stage.fail_removals.store(true, Ordering::SeqCst);
        router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("refused, and the rollback cannot land");
        assert_eq!(stage.connection_count(), 1, "the leftover is registered");
        assert_eq!(router.state.quarantined.lock().len(), 1);

        // A rebuild in which the leftover publishes nothing while still holding
        // the connection.
        stage.publish_nothing.store(true, Ordering::SeqCst);
        router
            .state
            .rebuild(router.state.next_generation(), None)
            .await
            .expect("the rebuild succeeds");
        assert_eq!(
            router.state.quarantined.lock().len(),
            1,
            "the child still holds it, so the entry must not be retired on its silence",
        );

        // It comes back, and the root it collided with goes away.
        stage.publish_nothing.store(false, Ordering::SeqCst);
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "prod".to_string(),
                    id: ConnectionId("prod-0".to_string()),
                }),
                None,
            )
            .await
            .expect("the incumbent is removed");
        assert_eq!(prod.connection_count(), 0);
        assert!(
            router.route(&Url::parse(root).unwrap()).is_err(),
            "a refused connection must not become the route once the incumbent is gone",
        );
    }

    #[tokio::test]
    async fn a_quarantine_is_pruned_once_the_child_stops_publishing_it() {
        // The entry lives exactly as long as the leftover does, so a removal
        // that lands later — by hand, or by the child's own housekeeping —
        // clears it rather than blocking that child forever.
        let (router, _prod, stage) = two_tenant_router().await;
        let root = "http://origin.example/assets/";
        router
            .add_connection(tenant_request("prod", root), None)
            .await
            .unwrap();
        stage.fail_removals.store(true, Ordering::SeqCst);
        router
            .add_connection(tenant_request("stage", root), None)
            .await
            .expect_err("refused");
        assert_eq!(router.state.quarantined.lock().len(), 1);

        // The operator clears it by hand, and the next aggregation forgets it.
        stage.fail_removals.store(false, Ordering::SeqCst);
        router
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "stage".to_string(),
                    id: ConnectionId("stage-0".to_string()),
                }),
                None,
            )
            .await
            .expect("the leftover is removed");
        assert!(
            router.state.quarantined.lock().is_empty(),
            "nothing published for it, so nothing is withheld for it",
        );
    }

    #[test]
    fn a_route_prefix_renders_as_its_origin_alone() {
        for (prefix, origin) in [
            ("http://origin.example/assets/", "http://origin.example"),
            (
                "https://user:hunter2@origin.example:8443/a/b?sig=deadbeef",
                "https://origin.example:8443",
            ),
        ] {
            let url = Url::parse(prefix).unwrap();
            assert_eq!(ovstorage_plugin::redact::origin_only(&url), origin);
        }
    }
}

#[cfg(test)]
mod list_stream_tests {
    use futures::StreamExt as _;

    use super::*;

    struct ListingChild {
        root: RootInfo,
        items: Vec<ObjectInfo>,
    }

    #[async_trait]
    impl Layer for ListingChild {
        fn name(&self) -> &str {
            "listing-child"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("listing-child", LayerType::Backend, false)
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            Ok((
                RootInfoSnapshot {
                    roots: vec![self.root.clone()],
                    updates: false,
                },
                None,
            ))
        }

        async fn list(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListPage> {
            Ok(ListPage {
                items: self.items.clone(),
                next_page_token: None,
            })
        }

        async fn list_stream(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListStream> {
            Ok(Box::pin(futures::stream::iter(
                self.items.clone().into_iter().map(Ok),
            )))
        }
    }

    fn item(address: &str) -> ObjectInfo {
        ObjectInfo::from((
            Url::parse(address).unwrap(),
            BackendItemInfo {
                kind: ObjectKind::File,
                ..BackendItemInfo::default()
            },
        ))
    }

    fn root_info(root: &str) -> RootInfo {
        RootInfo {
            root: Url::parse(root).unwrap(),
            display_name: None,
            layer_kind: "listing-child".to_string(),
            connection_id: None,
            owning_target: Some("listing-child".to_string()),
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

    fn request(prefix: &str, options: ListOptions) -> Request<ListRequest> {
        Request::new(ListRequest {
            prefix: Url::parse(prefix).unwrap(),
            options,
        })
    }

    #[tokio::test]
    async fn streaming_uses_the_buffered_route_and_preserves_child_order() {
        let expected = vec![item("route://host/root/z"), item("route://host/root/a")];
        let child = Arc::new(ListingChild {
            root: root_info("route://host/root/"),
            items: expected.clone(),
        });
        let router = Router::new("router", vec![child], None).await.unwrap();

        let buffered = router
            .list(request("route://host/root/", ListOptions::default()), None)
            .await
            .unwrap()
            .items;
        let streamed = router
            .list_stream(request("route://host/root/", ListOptions::default()), None)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(streamed, buffered);
        assert_eq!(streamed, expected);

        let error = match router
            .list_stream(
                request("route://host/missing/", ListOptions::default()),
                None,
            )
            .await
        {
            Ok(_) => panic!("an unrouteable stream must fail to open"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::NoRoute);
    }

    #[tokio::test]
    async fn rejects_page_windows_before_route_selection() {
        let router = Router::new("router", Vec::new(), None).await.unwrap();

        for options in [
            ListOptions {
                max_results: Some(1),
                ..ListOptions::default()
            },
            ListOptions {
                page_token: Some("next".to_string()),
                ..ListOptions::default()
            },
        ] {
            let error = match router
                .list_stream(request("route://host/missing/", options), None)
                .await
            {
                Ok(_) => panic!("a page window must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }
    }
}
