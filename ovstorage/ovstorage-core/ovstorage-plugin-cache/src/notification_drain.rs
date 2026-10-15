// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Notification invalidation and background drain lifecycle for cache Layers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures::StreamExt as _;
use tokio_util::sync::CancellationToken;

use crate::*;

/// Cache-layer config key enabling root-driven watch invalidation.
pub const WATCH_INVALIDATION_KEY: &str = "watch_invalidation";

/// Marks the cache-owned drain, whose reconnect loop owns clean-end coverage.
///
/// Cache wrappers still sweep on events, `Lapsed`, and stream errors. A clean
/// end is not itself a gap: the drain's owner reconnects with bounded backoff
/// rather than wiping the cache inline on every batch. Because a cursorless
/// backend cannot prove gap-free replay across the reconnect, the reconnect
/// loop re-arms a subtree sweep on each successful reopen, at the cost of one
/// subtree invalidation per reconnect.
///
/// That sweep narrows the end-to-reopen window; it does not close it. A
/// request already in flight when the sweep runs stores a response the backend
/// computed before it, so a mutation inside the window can survive in a row
/// written after the sweep. Byte-cache entries are not exposed — they are
/// keyed on the object's validator, so a body under a superseded etag is
/// unreachable — but a metadata row is, until its TTL.
pub(crate) const MANAGED_NOTIFICATION_DRAIN_EXTENSION: &str =
    "ovstorage.managed_notification_drain";

type RootSweep = Arc<dyn Fn(&Url) + Send + Sync>;

/// Shared lifecycle state embedded by both cache wrappers.
/// Records a cacheable commit from a context that has no layer to call.
///
/// Same rule as [`CacheWatchState::note_cached`]: the address passed is one
/// whose commit produced a **cache entry**, not merely a successful read.
#[derive(Clone)]
pub(crate) struct CommitRegistrar(Arc<ScopedWatchState>);

impl CommitRegistrar {
    pub(crate) fn note_cached(&self, address: &Url) {
        self.0.note_cached(address);
    }
}

pub(crate) struct CacheWatchState {
    shutdown: CancellationToken,
    handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    scoped: Arc<ScopedWatchState>,
}

impl CacheWatchState {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            shutdown: CancellationToken::new(),
            handles: Mutex::new(Vec::new()),
            scoped: Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(enabled)))),
        }
    }

    /// Record that a cacheable entry was produced for `address`, so a root in
    /// scoped mode can watch the directory holding it.
    ///
    /// Call sites pass an address whose read produced a **cache entry**, not
    /// merely a successful read: a scope protecting nothing still costs a watch
    /// and evicts one that protects something.
    pub(crate) fn note_cached(&self, address: &Url) {
        self.scoped.note_cached(address);
    }

    /// Whether this layer watches at all, so a forwarding call site can skip
    /// the address clone `note_cached` would need on the default
    /// `watch_invalidation = false` path.
    pub(crate) fn watches(&self) -> bool {
        self.scoped.scopes.enabled
    }

    /// A handle for recording a commit that lands after the call that started
    /// it returned.
    ///
    /// The byte layer's streaming tee is a free function driving a stream that
    /// outlives its `read`, so it cannot reach the layer — and it is one of the
    /// points where a body is actually committed. Cheap to clone, and
    /// recording takes the registry's leaf lock and nothing else.
    pub(crate) fn registrar(&self) -> CommitRegistrar {
        CommitRegistrar(Arc::clone(&self.scoped))
    }

    pub(crate) fn start(
        &self,
        layer: Arc<dyn Layer>,
        inner: LayerHandle,
        enabled: bool,
        sweep: RootSweep,
    ) {
        if !enabled {
            return;
        }
        // Address-root discovery is async and cancellable under ABI v8, so the
        // initial snapshot is acquired inside the spawned task rather than here
        // in this synchronous factory path.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!(
                target: "ovstorage.notification_drain",
                "cache watch invalidation not started because no tokio runtime is active"
            );
            return;
        };
        let weak = Arc::downgrade(&layer);
        let scoped = Arc::clone(&self.scoped);
        let manager = handle.spawn(manage_cache_watch_drains(
            weak.clone(),
            inner,
            self.shutdown.clone(),
            sweep.clone(),
            Arc::clone(&scoped),
        ));
        // A second task, not a per-root one: scope selection needs the whole
        // root set to assign each scope to its longest matching root, and the
        // watch budget is global to this layer. Its cancel token is this
        // layer's own, so a scope drain is never orphaned by the manager or the
        // supervisor being aborted first.
        let supervisor = handle.spawn(supervise_scoped_drains(
            weak,
            self.shutdown.clone(),
            sweep,
            scoped,
        ));
        if let Ok(mut handles) = self.handles.lock() {
            *handles = vec![manager, supervisor];
        }
    }
}

impl Drop for CacheWatchState {
    /// Cancel BEFORE aborting, and the order is load-bearing. Every drain's
    /// cancel token is a child of `shutdown`, and aborting the manager and the
    /// supervisor drops their drain maps without running their own teardown —
    /// so if the abort came first, nothing would ever cancel the drains those
    /// maps held.
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Ok(handles) = self.handles.get_mut() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
    }
}

/// Applies per-event invalidation and at most one terminal gap sweep.
///
/// Ordinary caller streams sweep on an unexpected clean end. Managed cache
/// drains pass `sweep_on_clean_end = false` because their reconnect loop treats
/// finite clean batches as normal; errors remain coverage gaps and always
/// sweep.
pub(crate) struct GapSweepStream<F, G> {
    inner: ChangeStream,
    on_event: F,
    on_gap: Option<G>,
    teardown: Option<CancellationToken>,
    sweep_on_clean_end: bool,
    done: bool,
}

impl<F, G> GapSweepStream<F, G>
where
    F: FnMut(&ChangeEvent) + Send,
    G: FnOnce() + Send,
{
    pub(crate) fn new(
        inner: ChangeStream,
        teardown: Option<CancellationToken>,
        sweep_on_clean_end: bool,
        on_event: F,
        on_gap: G,
    ) -> Self {
        Self {
            inner,
            on_event,
            on_gap: Some(on_gap),
            teardown,
            sweep_on_clean_end,
            done: false,
        }
    }

    fn sweep(&mut self) {
        if let Some(on_gap) = self.on_gap.take() {
            on_gap();
        }
    }

    fn is_intentional_teardown(&self) -> bool {
        self.teardown.as_ref().is_some_and(|t| t.is_cancelled())
    }
}

impl<F, G> Iterator for GapSweepStream<F, G>
where
    F: FnMut(&ChangeEvent) + Send,
    G: FnOnce() + Send,
{
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.inner.next() {
            Some(Ok(event)) => {
                (self.on_event)(&event);
                Some(Ok(event))
            }
            Some(Err(error)) => {
                self.done = true;
                self.sweep();
                Some(Err(error))
            }
            None => {
                self.done = true;
                if self.sweep_on_clean_end && !self.is_intentional_teardown() {
                    self.sweep();
                }
                None
            }
        }
    }
}

pub(crate) fn parse_watch_invalidation(config: &LayerConfig) -> Result<bool> {
    match config.get(WATCH_INVALIDATION_KEY) {
        None => Ok(false),
        Some(ConfigValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "cache config `watch_invalidation` must be a boolean",
        )),
    }
}

const INITIAL_DRAIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_DRAIN_BACKOFF: Duration = Duration::from_secs(60);
const MIN_STABLE_WATCH_UPTIME: Duration = Duration::from_secs(5);
const INITIAL_ROOT_UPDATE_BACKOFF: Duration = Duration::from_millis(50);
const MAX_ROOT_UPDATE_BACKOFF: Duration = Duration::from_secs(5);

/// Cancelled drains still holding a blocking thread before the layer both warns
/// and stops changing the watch set.
///
/// **Two things turn on this number**, so tuning it to make the log quieter also
/// moves the point at which watches stop being opened and retired: the warning
/// in [`supervise_scoped_drains`] and the freeze in [`reconcile_scopes`].
///
/// Four rotations' worth. A rotation of the whole watch set can leave up to
/// [`MAX_WATCH_SCOPES`] handles behind against a backend that does not return
/// from a cancelled `stream.next()`, and one rotation is ordinary.
///
/// Reaching it does not prove the handles are stuck, and the freeze is chosen so
/// it does not have to. A drain parked in a blocking `next()` on a QUIET
/// directory returns only when the backend has something to say, so four
/// rotations over quiet directories reaches this number with every handle
/// destined to complete. That case sees a pause in watch-set changes for as long
/// as the handles take, and the prune at the top of each pass ends it — which is
/// why the freeze holds the set rather than draining it.
const STUCK_RETIREMENT_LIMIT: usize = MAX_WATCH_SCOPES * 4;

/// Consecutive barren stream ends before a root is distrusted.
///
/// One threshold rather than one per reader. Both questions the count is asked
/// — does this end cost probe budget, and does an accepted open still refund it
/// — are the same question about the same evidence, and answering them at
/// different thresholds latches: below the charging threshold a barren end is
/// declared transient and costs nothing, so if the refund stops there instead,
/// a single broker blip silently withdraws every later refund. `Worked` clears
/// the count and is reported only when a stream ENDS, so under a root whose
/// watches stay open there is nothing to clear it before the pause expires.
const BARREN_ENDS_BEFORE_DISTRUST: u32 = 2;

/// Concurrent scoped watches one cache layer may hold, across every root.
///
/// Small because a watch is expensive on both sides of this layer, and the
/// number is set by the more expensive side:
///
/// - here, [`drain_stream`] parks one `spawn_blocking` thread per live watch
///   for as long as it is open, and a `spawn_blocking` task cannot be aborted,
///   so a backend that does not observe watch cancellation holds that thread
///   until its stream ends;
/// - on the broker client — the composition this bound exists for — every
///   `watch_directory` spawns a dedicated OS thread **and its own multi-thread
///   Tokio runtime**, so each watch costs a thread plus a worker pool, not a
///   task.
///
/// Four recursive directory watches is therefore a different order of cost
/// from four subscriptions, and it still covers the shape this feature is for:
/// a recursive watch on a project directory serves its whole subtree, and
/// selection collapses a scope covered by another onto the covering one. The
/// budget can rise once the broker client coalesces its watches onto shared
/// streams; until then this is the number the client's per-watch cost allows.
const MAX_WATCH_SCOPES: usize = 4;

/// How many directories the registry remembers as candidates.
///
/// Deliberately well above [`MAX_WATCH_SCOPES`], and the same reasoning as
/// [`MAX_DENIED_SCOPES`]: a table that has to outlive the budget's churn cannot
/// *be* the budget. Sized at exactly the budget, "is a candidate" and "holds a
/// watch" become one scarce resource — eviction has to protect watched slots or
/// thrash them, and protecting them freezes the table, so the fallback watches
/// whichever directories the cache happened to hold first for the life of the
/// process. Being a candidate costs a `Url`, two clock readings and a flag;
/// only selection spends a watch.
const MAX_CANDIDATE_SCOPES: usize = 32;

/// Scopes whose watch was refused, remembered so a refusal is not re-probed on
/// every reconcile. Larger than [`MAX_WATCH_SCOPES`] on purpose: a refusal must
/// outlive the watch budget's churn, or evicting a candidate would forget its
/// refusal and re-probe it on the next read.
const MAX_DENIED_SCOPES: usize = 256;

/// How long a refusal is remembered — for a denied directory, for a root that
/// has stopped probing, and between one refused root watch and the next.
///
/// Policy is reloadable at runtime, so a refusal is a fact with an expiry
/// rather than a permanent one; without the expiry a reloaded policy that
/// grants the right would be invisible until the process restarted.
const DENIED_SCOPE_RETRY: Duration = Duration::from_secs(300);

/// Failed scope watches in a row under one root, with none granted in between,
/// before that root stops probing for [`DENIED_SCOPE_RETRY`].
///
/// The registry's own limits bound probing *per directory* — a directory is
/// probed at most once per retry interval, and only four are candidates at a
/// time. They do not bound it per *deployment*: a workload walking fresh
/// directories keeps feeding new candidates, each worth one refused round trip,
/// and on the broker client a round trip is a thread and a runtime. "This
/// deployment grants no watch at any prefix" is a property of the deployment,
/// and this is where it is noticed.
const MAX_CONSECUTIVE_SCOPE_FAILURES: u32 = 8;

/// How long a directory must go unread before the watch it holds may be given
/// up for a hotter candidate.
///
/// Tearing a watch down costs a subtree invalidation, so a working set one
/// directory larger than [`MAX_WATCH_SCOPES`] must not rotate through the
/// budget: without this floor it would discard a subtree per read. Stated as
/// idleness rather than tenure, it cannot thrash — a directory still being read
/// keeps its watch no matter how hot a rival gets — while a working set that
/// genuinely moves away releases its slots after one interval.
///
/// This is a rule about *watches*, not about the registry. The registry's own
/// eviction reads one thing about a scope — whether a drain holds it, and only
/// so that admission picks a different victim, since a scope evicted from the
/// registry cannot be selected at all. Recency is what decides everything else
/// there.
const MIN_WATCH_RESIDENCY: Duration = Duration::from_secs(60);

/// How long the scope supervisor sleeps when a deadline is outstanding and
/// nothing else wakes it, so an expiring refusal is re-probed without needing a
/// cache read to arrive first.
const SCOPE_RECONCILE_TICK: Duration = Duration::from_secs(30);

/// The directory a cached entry for `address` lives under, or `None` when the
/// address has no directory the cache could watch.
///
/// A directory-form address (a `list` prefix) is its own scope, with any query
/// or fragment dropped. An object address contributes its parent directory, in
/// the trailing-slash spelling [`address::parent_and_name`] returns — and that
/// helper declines a fragment-bearing object address, which therefore has no
/// watchable scope and stays TTL-only.
///
/// An address carrying URL userinfo is declined the same way. Neither this
/// function nor `parent_and_name` drops userinfo — both preserve the authority —
/// so without this a `scheme://user:password@host/…` request would copy the
/// caller's password into structures that outlive it by design: the registry's
/// `HashMap` keys, the denial memo's keys, and the prefix a `ScopeDrain` holds
/// and re-opens on every reconnect for the life of the process. `redact_url`
/// covers the log lines and nothing covers a map key.
///
/// Declined rather than stripped, and it costs nothing to decline: no in-tree
/// route produces such an address. HTTP is the only backend whose addresses can
/// carry userinfo and it refuses a configured prefix that does, stripping it
/// from the default so it never reaches a `RootInfo` or an `ObjectInfo`. So this
/// guards an address shape the stack does not currently mint, which is the
/// cheapest moment to guard it. Stripping instead would keep a scope that no
/// advertised root matches, occupying one of the thirty-two candidate slots
/// without ever being selected.
///
/// This covers addresses only. A root's own URL does not pass through here, so a
/// backend that advertised a userinfo-bearing ROOT would still put it in the
/// root table — config-supplied rather than caller-supplied, and not a shape any
/// current backend produces.
fn scope_of(address: &Url) -> Option<Url> {
    if !address.username().is_empty() || address.password().is_some() {
        return None;
    }
    if address::is_directory(address) {
        let mut scope = address.clone();
        scope.set_query(None);
        scope.set_fragment(None);
        return Some(scope);
    }
    address::parent_and_name(address).map(|(parent, _)| parent)
}

/// What one scope drain has just learned about its root.
///
/// A bool could not say this. The question the probe budget answers is whether a
/// root grants watches that WORK, and an accepted open is weaker evidence of
/// that than a stream which ran — while a stream accepted and dropped at once is
/// evidence against. Collapsing the three into "failed or not" is what let a
/// backend that accepts every watch and immediately ends it reset the budget on
/// every cycle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScopeOutcome {
    /// The open was accepted. A grant, but not yet a working watch.
    Opened,
    /// The stream ran — long enough or with events — before it ended.
    Worked,
    /// The stream ended at once with nothing to show, cleanly or in error.
    Barren,
    /// The open failed terminally.
    Failed,
    /// The open failed with a RETRYABLE error and this drain had never opened.
    ///
    /// Charged once per drain rather than once per retry, so an ordinary
    /// reconnect costs nothing and a backend that is simply down costs one slot
    /// per directory attempted. Without it the budget bounds only the refusal
    /// and terminal paths: a drain that has never opened is `worth_defending ==
    /// false` and `has_opened == false`, so candidate churn displaces it, and a
    /// cancelled exit returns before anything is charged — leaving a workload
    /// that walks fresh directories attempting watches at an unbounded rate
    /// against an unavailable backend, each a thread and a runtime on the broker
    /// client, with `consecutive_failures` never leaving zero.
    OpenUnavailable,
}

/// How much of a prefix a watch asks to be told about.
///
/// Not a cosmetic option. Authorization in this repository's own policy layer
/// never reads it — the decision is `(principal, operation, prefix)` — but it
/// is not only that layer that can refuse: the file backend walks descendant
/// directories to build a recursive watch's snapshot, so a descendant the
/// filesystem denies makes the recursive form fail where the non-recursive form
/// succeeds; and the Storage Service client maps recursion onto a genuinely
/// different remote filter. On S3, GCS, Azure and Nucleus it is instead a
/// filter over one shared upstream, so there a retry cannot help. The cache
/// cannot tell those apart from here, so it asks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WatchMode {
    /// The whole subtree. What a scope asks for first, and the only mode whose
    /// coverage lets another scope be collapsed onto it.
    Recursive,
    /// The prefix's immediate children only — a strictly smaller ask, and what
    /// a refused recursive watch degrades to before giving up.
    NonRecursive,
}

impl WatchMode {
    fn recursive(self) -> bool {
        matches!(self, WatchMode::Recursive)
    }
}

/// A refusal, and how much of one it was.
struct DeniedScope {
    at: tokio::time::Instant,
    /// Both modes were refused. A recursive-only refusal leaves the scope a
    /// candidate that starts non-recursively instead of withholding it.
    fully: bool,
    /// The root advertisement whose drain issued this refusal.
    ///
    /// A memo is keyed by scope URL, and a scope changes hands: the same URL is
    /// re-advertised on a route rebind, and a nested root takes the subtree
    /// beneath it by longest prefix. Without this the old route's refusal reads
    /// as the new route's, withholding the directory from a backend that never
    /// refused it — for [`DENIED_SCOPE_RETRY`] after a rebind, and until
    /// eviction after a takeover, since `advertise`/`withdraw` do not clear
    /// memos.
    ///
    /// Stamped at the write, checked at the read. Checking at the write instead
    /// is what the guard around `deny` does, and it cannot be sufficient on its
    /// own: the check and the insertion are separate lock acquisitions, so a
    /// takeover between them still lands the memo. Stamping is what makes that
    /// window harmless rather than narrow.
    root: Url,
    generation: u64,
}

/// One candidate directory and when it was last read, on two clocks.
struct ScopeEntry {
    url: Url,
    /// Logical clock reading of the last touch. Orders the table without a wall
    /// clock, which is what eviction and selection compare.
    touched: u64,
    /// Wall reading of the last DIRECT read of this scope — a read whose own
    /// parent directory is this one, not one of a descendant.
    ///
    /// Only one question needs a duration rather than an order: whether a
    /// directory has gone unread for [`MIN_WATCH_RESIDENCY`], which is what
    /// lets its watch be given up. That question must not inherit the ancestor
    /// touch that `touched` does. A watch is defended because tearing it down
    /// loses what it reports, so descendant traffic may only defend an ancestor
    /// that actually reports the descendants — and a scope on its root's own
    /// prefix is always opened `NonRecursive`, while any scope may degrade to
    /// it, so an ancestor being read-through is no evidence at all. Inherited
    /// here, four such ancestors hold the whole budget on traffic none of them
    /// can see, while the directories generating it stay unwatched. The
    /// supervisor re-adds descendant heat for the ancestors that CAN see it —
    /// the ones holding a recursive watch. See
    /// [`WatchScopes::subtree_touched_within`].
    direct_touch: tokio::time::Instant,
    /// Whether a drain currently holds this scope, as the supervisor last saw
    /// it. Read by eviction alone, and only to pick a different victim: a scope
    /// evicted from the registry is absent from `candidates()`, so its drain is
    /// retired and its subtree swept on the next reconcile no matter how
    /// recently it was read. A working set of more distinct directories than
    /// the registry holds would otherwise tear a watch down and rebuild it
    /// every time its entry cycled out — a broker thread and runtime per cycle,
    /// on opens that succeed, so no budget notices.
    ///
    /// This cannot freeze the table the way the old registry did: only a scope
    /// that selection holds a drain for carries it, and selection is bounded by
    /// [`MAX_WATCH_SCOPES`] plus the one cover it may grant above that — five
    /// of [`MAX_CANDIDATE_SCOPES`], so twenty-seven remain plain LRU.
    watched: bool,
}

#[derive(Default)]
struct ScopeTable {
    /// Candidate directories, keyed by `Url::as_str`.
    scopes: HashMap<String, ScopeEntry>,
    /// Directories whose watch was refused, and how much of one.
    denied: HashMap<String, DeniedScope>,
    /// Monotonic touch counter; LRU order without a wall clock.
    clock: u64,
}

/// The directories this cache layer has produced entries for, bounded and
/// LRU-ordered, plus the refusals it has already paid for.
///
/// Written on the cache read path and read by the scope supervisor. The lock is
/// a leaf: nothing is called while it is held, so it can never order against a
/// cache lock or a sweep.
pub(crate) struct WatchScopes {
    enabled: bool,
    table: Mutex<ScopeTable>,
    wake: tokio::sync::Notify,
}

impl WatchScopes {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            table: Mutex::new(ScopeTable::default()),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// Touch the scope holding `address`, and every candidate that already
    /// covers it.
    ///
    /// The ancestor touch is what keeps a project directory from becoming the
    /// least-recently-used entry while its own subtree is the busiest thing in
    /// the cache: a recursive watch on `a/` serves every read under `a/`, so
    /// those reads have to count as use of `a/`.
    fn note_cached(&self, address: &Url) {
        if !self.enabled {
            return;
        }
        let Some(scope) = scope_of(address) else {
            return;
        };
        let mut changed = false;
        {
            let Ok(mut table) = self.table.lock() else {
                return;
            };
            table.clock += 1;
            let now = table.clock;
            let at = tokio::time::Instant::now();
            // `is_ancestor_or_self` is reflexive, so this also touches `scope`'s own
            // entry when it has one.
            // The ancestor touch is for `touched` — the LRU order it was
            // written for — and NOT for `direct_touch`, which decides whether a
            // watch may be given up. See the field.
            for entry in table.scopes.values_mut() {
                if address::is_ancestor_or_self(&entry.url, &scope) {
                    entry.touched = now;
                }
            }
            if let Some(entry) = table.scopes.get_mut(scope.as_str()) {
                entry.direct_touch = at;
            }
            if !table.scopes.contains_key(scope.as_str()) {
                // LRU, with no test for a scope an existing candidate already
                // covers — that would be admission deciding what may be
                // *watched*, which is selection's question and is answered
                // there against the drains. The one thing admission does read
                // is `watched`, and only to choose a different victim; see the
                // field. A newcomer otherwise has to be newer than the coldest
                // of thirty-two, and nothing more.
                if table.scopes.len() >= MAX_CANDIDATE_SCOPES {
                    let coldest = table
                        .scopes
                        .iter()
                        .min_by_key(|(_, entry)| (entry.watched, entry.touched))
                        .map(|(key, _)| key.clone());
                    if let Some(key) = coldest {
                        table.scopes.remove(&key);
                    }
                }
                table.scopes.insert(
                    scope.as_str().to_string(),
                    ScopeEntry {
                        url: scope,
                        touched: now,
                        direct_touch: at,
                        watched: false,
                    },
                );
                changed = true;
            }
        }
        if changed {
            self.wake.notify_one();
        }
    }

    /// Record that `scope`'s watch was refused in `mode`.
    ///
    /// A refusal of [`WatchMode::Recursive`] is not a denial of the scope: the
    /// drain degrades to the smaller ask and tries again, and remembering the
    /// mode is what stops a scope that ends up watched non-recursively paying
    /// for the recursive probe again every time it is re-admitted.
    fn deny(&self, scope: &Url, mode: WatchMode, root: &Url, generation: u64) {
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        if table.denied.len() >= MAX_DENIED_SCOPES && !table.denied.contains_key(scope.as_str()) {
            let oldest = table
                .denied
                .iter()
                .min_by_key(|(_, denied)| denied.at)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                table.denied.remove(&key);
            }
        }
        table.denied.insert(
            scope.as_str().to_string(),
            DeniedScope {
                at: tokio::time::Instant::now(),
                fully: !mode.recursive(),
                root: root.clone(),
                generation,
            },
        );
    }

    /// Test shorthand: refuse `scope` in both modes.
    #[cfg(test)]
    fn deny_both(&self, scope: &Url) {
        let root = Url::parse("mem:///").expect("a valid test root");
        self.deny(scope, WatchMode::NonRecursive, &root, 0);
    }

    /// The mode a fresh drain for `scope` should open with: the smaller ask
    /// when a recursive watch on it was refused inside the retry window.
    fn starting_mode(&self, scope: &Url, owned_by: &dyn Fn(&Url, u64, &Url) -> bool) -> WatchMode {
        let Ok(table) = self.table.lock() else {
            return WatchMode::Recursive;
        };
        let now = tokio::time::Instant::now();
        match table.denied.get(scope.as_str()) {
            // A memo the current owner did not issue says nothing about this
            // route, so it does not narrow this route's first ask.
            Some(denied)
                if now.duration_since(denied.at) < DENIED_SCOPE_RETRY
                    && owned_by(&denied.root, denied.generation, scope) =>
            {
                WatchMode::NonRecursive
            }
            _ => WatchMode::Recursive,
        }
    }

    /// Candidate directories, most recently used first, with refusals that have
    /// not yet expired removed.
    fn candidates(&self, owned_by: &dyn Fn(&Url, u64, &Url) -> bool) -> Vec<Url> {
        let Ok(table) = self.table.lock() else {
            return Vec::new();
        };
        let now = tokio::time::Instant::now();
        let mut live: Vec<(u64, Url)> = table
            .scopes
            .values()
            // A recursive-only refusal keeps the scope a candidate: it opens
            // non-recursively instead. Only a scope refused in BOTH modes is
            // withheld.
            .filter(|entry| match table.denied.get(entry.url.as_str()) {
                // Same rule as `starting_mode`: a full refusal withholds the
                // directory only from the route that earned it. After a rebind
                // or a nested takeover the memo belongs to nobody, and holding
                // the scope back would leave the new backend unwatched for the
                // retry window on a verdict it never gave.
                Some(denied) => {
                    !denied.fully
                        || now.duration_since(denied.at) >= DENIED_SCOPE_RETRY
                        || !owned_by(&denied.root, denied.generation, &entry.url)
                }
                None => true,
            })
            .map(|entry| (entry.touched, entry.url.clone()))
            .collect();
        // Most recent first, then DEEPEST first, then by spelling so the order
        // is TOTAL and the budget cutoff is deterministic. Left to `HashMap`
        // order the dropped member is arbitrary and can flip between
        // reconciles, and each flip retires a drain and sweeps its subtree out
        // of a persistent cache. `root_views` sorts totally for the same reason.
        //
        // Ties are ordinary rather than exotic, and they are always one
        // ancestor chain: `note_cached` bumps `table.clock` once and writes that
        // single value to the scope and to every ancestor already in the table,
        // so reading `mem:///a/b/c/d/e/obj` ties five entries at once against a
        // budget of four, and two unrelated directories never tie at all. So
        // this tie-break decides exactly one thing — which member of a chain
        // keeps the slot — and depth is the answer whenever the chain is still
        // a chain by the time selection truncates.
        //
        // Shallowest-first is right only where an ancestor's RECURSIVE watch
        // covers the rest, and in that case selection never reaches this
        // ordering: the antichain drops the descendants outright, on
        // `can_cover`, whatever order they are in. What survives to the
        // truncation is a chain nothing is collapsing — every ancestor
        // degraded to `NonRecursive`, which is the file-backend and
        // Storage-Service-client case this whole feature exists for. A
        // non-recursive watch on `a/b/` reports its immediate children and says
        // nothing about objects under `a/b/c/`, so ordering it first spends the
        // budget on directories that cannot report the reads while the
        // directory actually being read goes unwatched — with no expiry beneath
        // it, since the byte cache has none.
        //
        // The ancestor touch keeps a busy project directory from being EVICTED
        // from the registry, which is what it was added for. This stops it also
        // outranking its own descendants for a watch.
        //
        // It is a trade rather than a free win, and the losing side is the
        // recursive-capable backend with a chain deeper than the budget. There
        // the shallow order converged in one pass — the top of the chain is
        // selected, opens recursively, and the antichain collapses the rest —
        // whereas this one selects the deepest members first and reaches the
        // same place through the cover slot a pass or two later, paying an open
        // and a retirement, each with its subtree sweep, for the members it
        // passed through. `a_cover_gets_a_slot_rather_than_waiting_to_be_able_to_open`
        // pins that it still converges.
        //
        // Taken because the two sides are not symmetric. The cost above is
        // bounded work on a path that ends correctly; the cost below is the
        // directory a workload is actively reading holding no watch at all, for
        // as long as its ancestors stay refused, over a byte cache with no
        // expiry. What would get both is a second key — prefer the shallow
        // member while it may still open recursively, the deep one once its
        // recursive form has been refused — which `starting_mode` can answer
        // but not from inside this comparator, since it takes the same lock.
        live.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| {
                    ovstorage_layer::node_rank(&b.1).cmp(&ovstorage_layer::node_rank(&a.1))
                })
                .then_with(|| ovstorage_layer::node_key(&a.1).cmp(&ovstorage_layer::node_key(&b.1)))
        });
        live.into_iter().map(|(_, url)| url).collect()
    }

    /// Record which scopes a drain currently holds, so eviction can pick a
    /// victim that is not one of them.
    ///
    /// Keyed on a drain existing rather than on its watch being live: what
    /// eviction would cost is the scope's *selectability*, and a drain between
    /// streams is still selected and still owns the slot.
    fn mark_watched(&self, watched: &[String]) {
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        for (key, entry) in table.scopes.iter_mut() {
            entry.watched = watched.iter().any(|held| held == key);
        }
    }

    /// Whether `scope` has been read within `window`.
    ///
    /// Selection asks this of the scopes whose watch has opened, and only of
    /// those: a watch is not torn down for a hotter newcomer while the
    /// directory it protects is still being read. A scope with no entry answers
    /// no. Eviction is what keeps that from mattering: from the moment
    /// [`Self::mark_watched`] records a drain, that scope is not the victim
    /// admission picks. In the pass that first selects a scope the flag is not
    /// set yet, so a concurrent read can evict it and the next pass retires it
    /// — one wasted open, self-correcting, and the alternative is admission
    /// waiting on the supervisor.
    fn touched_within(&self, scope: &str, window: Duration) -> bool {
        let Ok(table) = self.table.lock() else {
            return false;
        };
        let now = tokio::time::Instant::now();
        table
            .scopes
            .get(scope)
            .is_some_and(|entry| now.duration_since(entry.direct_touch) < window)
    }

    /// Whether any candidate strictly BELOW `prefix` has been read within
    /// `window`.
    ///
    /// The other half of splitting the ancestor touch off `direct_touch`. A
    /// watch is defended because tearing it down loses what it reports, so
    /// descendant traffic defends an ancestor only when the ancestor reports
    /// those descendants.
    ///
    /// `same_route` is the second half of "reports": a recursive
    /// `watch_directory` is dispatched to the route that owns the prefix it
    /// names, so an ancestor on an outer root does not report a descendant a
    /// NESTED root has taken over — reads there dispatch to a different backend
    /// entirely. Without it, traffic under a nested mount would pin the outer
    /// ancestor's watch indefinitely while the directory actually being read
    /// went unwatched, which is the same defect as the mode half in a different
    /// dimension. The supervisor asks this of the drains holding a RECURSIVE
    /// watch, on the same advertisement — so a recursive project-directory watch
    /// keeps its slot while its subtree is busy even if the directory itself is
    /// never listed again, and a degraded or root-prefix watch does not.
    ///
    /// Deliberately not `covers_below`, which is this plus `live`. Whether the
    /// stream is up THIS INSTANT decides what the watch reports; it does not
    /// decide whether the watch is worth keeping, and a cover held up entirely
    /// by traffic below it has a stale `direct_touch` by construction — so
    /// reading `live` here would drop the whole of its defence at every
    /// reconnect. Spanning the reconnect is [`ScopeSignals::working_recently`]'s
    /// job, and it bounds a drain that does not come back.
    fn subtree_touched_within(
        &self,
        prefix: &Url,
        window: Duration,
        same_route: &dyn Fn(&Url) -> bool,
    ) -> bool {
        let Ok(table) = self.table.lock() else {
            return false;
        };
        let now = tokio::time::Instant::now();
        table.scopes.values().any(|entry| {
            entry.url != *prefix
                && address::is_ancestor_or_self(prefix, &entry.url)
                && now.duration_since(entry.direct_touch) < window
                && same_route(&entry.url)
        })
    }

    /// Whether any refusal is still inside its retry window, so the supervisor
    /// knows to wake on a timer rather than only on a cache read.
    fn has_pending_deadline(&self) -> bool {
        let Ok(table) = self.table.lock() else {
            return false;
        };
        let now = tokio::time::Instant::now();
        table
            .denied
            .values()
            .any(|denied| now.duration_since(denied.at) < DENIED_SCOPE_RETRY)
    }
}

/// The roots whose own watch was refused, shared between the root drains that
/// discover that and the scope supervisor that acts on it.
///
/// Probing is bounded on two axes. Per directory: at most [`MAX_WATCH_SCOPES`]
/// watches are open at once, a live watch is given up only for a hotter
/// candidate once its own directory has been unread for
/// [`MIN_WATCH_RESIDENCY`], and a refused directory is not re-probed for
/// [`DENIED_SCOPE_RETRY`]. Per deployment, by
/// [`MAX_CONSECUTIVE_SCOPE_FAILURES`] here — which is the axis the registry
/// cannot see, because a workload walking fresh directories supplies new
/// candidates indefinitely.
pub(crate) struct ScopedWatchState {
    scopes: Arc<WatchScopes>,
    /// Every advertised root — including ones whose backend cannot watch, since
    /// assignment has to mirror the router — not the refused ones alone.
    /// Absence is not a state: a root whose own watch has not answered yet must
    /// neither suppress the scopes below it nor be probed under.
    roots: Mutex<HashMap<String, ScopedRoot>>,
    /// Source of [`ScopedRoot::generation`]. Never reused, so a withdrawal
    /// followed by a re-advertisement of the same URL is a different root.
    next_generation: std::sync::atomic::AtomicU64,
}

/// One advertised address root, and what its own watch has answered.
struct ScopedRoot {
    root: Url,
    watch: RootWatch,
    /// Which advertisement of this URL this record is.
    ///
    /// A URL is not an identity. `reconcile_roots` withdraws and re-advertises
    /// the same URL when its connection or route changes, and a scoped drain
    /// opened under the old advertisement holds a stream bound to the old
    /// connection — mutations on the replacement never reach it, so its subtree
    /// is stale with nothing to expire it: `ttl_seconds` is a metadata-cache
    /// key, and the byte cache has no TTL at all. A new root can also
    /// take over a scope by longest prefix. The generation is what lets
    /// SELECTION notice either, since neither changes the URL, and what the
    /// root's own state transitions match on so a straggling drain cannot speak
    /// for the advertisement that replaced it.
    ///
    /// It does not yet reach the scope drains' write-backs:
    /// `note_scope_outcome` resolves its root by URL and the denial memo is
    /// keyed by scope URL, so a straggler's outcome is still charged to
    /// whatever now owns that URL. That is bounded — at most
    /// [`MAX_WATCH_SCOPES`] outcomes, and only against a root already probing —
    /// and is the remaining half of making this an identity rather than a
    /// field.
    generation: u64,
}

/// What a root's own watch has answered so far.
///
/// The supervisor asks a root two questions whose answers do not follow from
/// each other: *does this root's own watch already report this subtree*, which
/// only [`RootWatch::Live`] answers yes to, and *may a narrower watch be opened
/// under it*, which only [`RootWatch::Refused`] does, and then only while its
/// probe budget holds. Leaving either implicit is how a scope ends up
/// suppressed by a watch that is not open, or probed under a root that already
/// covers it. As the [`RootView`] pair selection reads:
///
/// | state                         | `covers` | `admits_probes` |
/// |-------------------------------|----------|-----------------|
/// | `Pending`                     | false    | false           |
/// | `Live`                        | true     | false           |
/// | `Refused`, budget unspent     | false    | true            |
/// | `Refused`, budget spent       | false    | false           |
///
/// Note the last two rows differ from `Pending` only in `admits_probes`, so a
/// paused root and a root that has not answered are equally silent — and
/// neither suppresses anything.
enum RootWatch {
    /// The drain has started and its watch has not answered. It covers nothing
    /// and admits no probing.
    Pending,
    /// The watch is open, and being recursive it reports the whole subtree.
    Live,
    /// The watch was refused, so the directories the cache holds under this
    /// root are probed individually under a bounded budget.
    Refused {
        consecutive_failures: u32,
        /// Barren stream ends seen in a row under this root, across ALL its
        /// drains.
        ///
        /// Per root because the counter it guards is per root. Held per drain it
        /// was useless: a drain's FIRST open has no barren history, so it
        /// refunded — and a workload walking fresh directories replaces drains
        /// continuously, so an accept-and-drop backend got its budget wiped by
        /// every newcomer and never reached the pause. The evidence that a root
        /// grants watches that work has to outlive the drain that produced it.
        consecutive_barren: u32,
        /// Set when the budget is spent. No *new* probe opens under this root
        /// until it passes, after which the count resets; drains already open
        /// are kept, because a root that granted a watch is not a root that
        /// grants nothing.
        paused_until: Option<tokio::time::Instant>,
    },
    /// The root's own drain ended non-retryably, so nothing under it is being
    /// watched and nothing will be until the root is advertised again.
    ///
    /// Reached from `Refused` as well as from `Pending`: the refusal path keeps
    /// retrying the root every [`DENIED_SCOPE_RETRY`], and any of those retries
    /// can come back `Unsupported`, or `Internal` from a broker hiccup, which
    /// ends the drain. Without this state the root stayed `Refused` with a dead
    /// drain — still admitting probes, so the supervisor kept opening scoped
    /// watches under a backend that had already answered non-retryably,
    /// forever, and with no route back because only the drain that just died
    /// could have cleared it. It covers nothing and admits no probing, so it is
    /// exactly as silent as `Pending`. Recovery is re-advertisement — the same
    /// event that recovers any route change — rather than a retry loop, because
    /// the answer that put the root here was by definition not retryable.
    Unwatchable,
}

/// Everything scope selection needs to know about one advertised root, stated
/// rather than inferred from which map the root appears in.
struct RootView {
    root: Url,
    /// [`ScopedRoot::generation`], carried through selection so a drain can be
    /// matched against the advertisement it was opened under.
    generation: u64,
    /// The root's own watch is open, so it already reports this subtree.
    covers: bool,
    /// The root's watch was refused and its probe budget is not spent, so a new
    /// scoped watch may be opened under it.
    admits_probes: bool,
}

impl ScopedWatchState {
    fn new(scopes: Arc<WatchScopes>) -> Self {
        Self {
            scopes,
            roots: Mutex::new(HashMap::new()),
            next_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record that a watch-capable root is advertised and its drain has
    /// started.
    ///
    /// The entry starts `Pending`, which is the state that says nothing: it
    /// neither covers the scopes beneath it nor admits probing. Only the root's
    /// own watch answering moves it on. A root already known keeps the state it
    /// is in, so this stays an insert-or-nothing even though the drain manager
    /// only reaches it for a root it has no drain for.
    fn advertise(&self, root: &Url) -> u64 {
        let mut inserted = false;
        let generation;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return u64::MAX;
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = roots.entry(root_key(root)) {
                // Only a genuinely new entry takes a generation. A repeat
                // advertisement of a root already known is the same route, so
                // bumping the counter here would burn a number nothing uses,
                // and re-numbering the entry would retire every drain beneath
                // it on a call the drain manager makes routinely.
                generation = self
                    .next_generation
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                slot.insert(ScopedRoot {
                    root: root.clone(),
                    watch: RootWatch::Pending,
                    generation,
                });
                inserted = true;
            } else {
                // Occupied by construction: `Entry::Vacant` failing to match is
                // the only way here. Read through the entry rather than looking
                // the key up twice, and rather than inventing a default that
                // would silently give a drain a generation no root has — which
                // would pin its root `Pending` for the life of the process with
                // nothing to say why.
                let std::collections::hash_map::Entry::Occupied(slot) = roots.entry(root_key(root))
                else {
                    unreachable!("vacant was handled above")
                };
                generation = slot.get().generation;
            }
        }
        // A new root immediately changes scope-to-root assignment, because
        // selection assigns each candidate to its LONGEST matching root: a
        // nested root takes over every scope beneath it, and the drains opened
        // under the ancestor are bound to a route those scopes no longer
        // dispatch to. Nothing else would say so — the supervisor blocks with
        // no timer whenever every candidate is watched — so without this a
        // takeover is invisible until some unrelated event happens to wake it,
        // and until then the cache serves entries fetched from the route the
        // subtree used to point at. `withdraw` notifies for the mirror of this
        // reason.
        if inserted {
            self.scopes.wake.notify_one();
        }
        generation
    }

    /// Forget every root that is no longer advertised.
    ///
    /// The counterpart of [`Self::advertise`], and it has to be, because the
    /// two are driven from different sets. `reconcile_roots` advertises every
    /// discovered root but only keeps DRAINS for the watch-capable ones, so
    /// withdrawing per-drain leaves a root that never had a drain in the map
    /// forever. That is not inert: assignment is by longest prefix, so a
    /// phantom `Pending` root suppresses every scope beneath it for the life of
    /// the process — a watch withheld on a route that no longer exists.
    fn retain_advertised(&self, advertised: &[Url]) {
        let removed;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            let before = roots.len();
            roots.retain(|key, _| advertised.iter().any(|root| root_key(root) == *key));
            removed = roots.len() != before;
        }
        // Same reason [`Self::withdraw`] notifies: the scopes a departed root
        // was assigned to now belong to whatever is above it, and nothing else
        // would say so.
        if removed {
            self.scopes.wake.notify_one();
        }
    }

    /// A root that vanished or rebound is no longer advertised; any scoped
    /// drains under it are retired by the next reconcile.
    fn withdraw(&self, root: &Url) {
        let removed = self
            .roots
            .lock()
            .is_ok_and(|mut roots| roots.remove(&root_key(root)).is_some());
        // On any removal, not only a probing one. Withdrawing a LIVE root
        // changes what covers the scopes beneath it: a candidate that root was
        // suppressing may now fall to a refused root above and need a watch of
        // its own, and nothing else would tell the supervisor.
        if removed {
            self.scopes.wake.notify_one();
        }
    }

    /// A root whose own watch was refused starts probing narrower scopes.
    ///
    /// A root already probing keeps its budget. The root drain re-attempts its
    /// own watch on [`DENIED_SCOPE_RETRY`], so every later refusal calls this
    /// again — replacing the entry here would reset the budget on that same
    /// interval, in exactly the deployment the budget exists for.
    fn enter_scoped_mode(&self, root: &Url, generation: u64) {
        let mut entered = false;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            // `get_mut`, not `entry`: absence means "not advertised", and a
            // drain whose open resolves after its root was withdrawn would
            // otherwise re-create the entry with nothing to remove it again.
            let Some(entry) = roots.get_mut(&root_key(root)) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            if !matches!(entry.watch, RootWatch::Refused { .. }) {
                entry.watch = RootWatch::Refused {
                    consecutive_failures: 0,
                    consecutive_barren: 0,
                    paused_until: None,
                };
                entered = true;
            }
        }
        // Only on a real transition, or the supervisor spins once per refusal
        // interval for a root whose answer has not changed.
        if entered {
            self.scopes.wake.notify_one();
        }
    }

    /// A root whose own watch opened covers its whole subtree recursively, so
    /// nothing under it needs a watch of its own.
    fn leave_scoped_mode(&self, root: &Url, generation: u64) {
        let left;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            // `get_mut`, not `entry`: a root drain's open resolves without a
            // cancellation check, so it can land after `reconcile_roots` has
            // withdrawn the route. Re-creating the entry here would leave a
            // phantom `Live` root that nothing can remove — and a `Live` root
            // suppresses every scope beneath it, silently and for good.
            let Some(entry) = roots.get_mut(&root_key(root)) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            // Any state that is not already `Live`, not `Refused` alone. What
            // selection reads is `covers`, which only `Live` sets — so a
            // `Pending` root becoming `Live` changes exactly as much as a
            // `Refused` one does: every candidate beneath it stops being
            // selectable and every scoped drain under it is redundant. Keying
            // the wake on the arm the author happened to have in mind, rather
            // than on whether the answer selection reads has changed, is what
            // left a granted takeover invisible.
            left = !matches!(entry.watch, RootWatch::Live);
            entry.watch = RootWatch::Live;
        }
        // Only on a real transition into `Live`, which in production is every
        // call: the sole caller is the drain's successful-open arm, and it
        // cannot reach that arm twice without passing `root_watch_ended` in
        // between, which puts the entry back to `Pending`. So a granted root
        // that reconnects wakes the supervisor each time, and should — its
        // subtree really did stop being covered and start again — while the
        // reopen is backoff-bounded. The guard is idempotence for a caller that
        // does not exist yet, kept because `covers` is what selection reads and
        // a wake for an unchanged answer is pure cost.
        if left {
            self.scopes.wake.notify_one();
        }
    }

    /// A root's watch stream ended, so the root no longer reports its subtree.
    ///
    /// `Live` is a statement about a watch that is open *right now*, exactly as
    /// [`ScopeSignals::live`] is for a scope, and this is the root half of that
    /// same rule. The root drain reopens with backoff and a reopen can fail
    /// retryably for a long time — an ordinary broker restart keeps it retrying
    /// indefinitely — and while it does, the root reports nothing. Two things
    /// go wrong if the state says otherwise: [`RootView::covers`] answers yes
    /// for a subtree nothing is watching, so every candidate beneath the root
    /// is dropped from selection, and a scope drain still running under the
    /// root is retired as redundant — sweeping its subtree if its own watch had
    /// opened — and cannot be re-selected. A root whose watch opens and dies
    /// before the supervisor reconciles loses its scoped watches that way and
    /// never gets them back. `Pending` rather than `Refused`: nothing has
    /// refused anything, and a root that has not answered must neither cover
    /// the scopes beneath it nor admit probes under it. A reopen that is
    /// refused calls [`Self::enter_scoped_mode`] and moves it on from there.
    /// `Pending` is therefore absorbing when the reopen ends the drain instead
    /// — `Unsupported`, or any other non-retryable code — because nothing
    /// writes the state again and only a route rebind removes the entry. That
    /// is the intended answer, and the same one a root that never opened gets:
    /// a backend that cannot support this watch will not support a narrower one
    /// either, so the subtree is TTL-only rather than paying the probe budget
    /// to find out. `only_a_refusal_narrows_the_watch` asserts it for the codes
    /// that end a drain. Record that a root's own drain ended non-retryably.
    /// Generation-checked like every other write from a drain that may have
    /// been retired: a dead drain must not silence a route that replaced it.
    /// Waking matters — the supervisor has to stop admitting probes under this
    /// root, and nothing else would tell it.
    fn root_unwatchable(&self, root: &Url, generation: u64) {
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            let Some(entry) = roots.get_mut(&root_key(root)) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.watch = RootWatch::Unwatchable;
        }
        self.scopes.wake.notify_one();
    }

    fn root_watch_ended(&self, root: &Url, generation: u64) {
        let ended;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            // `get_mut` for the same reason as the two transitions above: a
            // withdrawn root must stay withdrawn.
            let Some(entry) = roots.get_mut(&root_key(root)) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            ended = matches!(entry.watch, RootWatch::Live);
            if ended {
                entry.watch = RootWatch::Pending;
            }
        }
        // Only on a real transition, and the transition matters: candidates
        // this root was covering are now selectable, and nothing else would say
        // so.
        if ended {
            self.scopes.wake.notify_one();
        }
    }

    /// Every advertised root, longest prefix first, with the two facts scope
    /// selection needs about each.
    ///
    /// Longest first is what makes assignment mirror the router's
    /// longest-prefix dispatch (`RouteTable::lookup`) — and assignment has to
    /// run over **all** advertised roots, exactly as the router does, or a
    /// scope under a granted inner root matches a refused outer one and takes a
    /// watch the granted root already covers.
    ///
    /// Expiring a spent probe budget is folded in here because this is the one
    /// read that scope *selection* makes, and selection is what acts on it:
    /// resetting in a second place is how the budget ends up refunded twice.
    /// Nothing else reads the budget: the cache read path only registers scopes
    /// through [`Self::note_cached`] and consults no root state at all.
    fn root_views(&self) -> Vec<RootView> {
        let Ok(mut roots) = self.roots.lock() else {
            return Vec::new();
        };
        let now = tokio::time::Instant::now();
        for entry in roots.values_mut() {
            if let RootWatch::Refused {
                consecutive_failures,
                consecutive_barren,
                paused_until,
            } = &mut entry.watch
                && paused_until.is_some_and(|until| now >= until)
            {
                *paused_until = None;
                *consecutive_failures = 0;
                *consecutive_barren = 0;
            }
        }
        let mut views: Vec<RootView> = roots
            .values()
            .map(|entry| RootView {
                root: entry.root.clone(),
                generation: entry.generation,
                covers: matches!(entry.watch, RootWatch::Live),
                admits_probes: matches!(
                    entry.watch,
                    RootWatch::Refused {
                        paused_until: None,
                        ..
                    }
                ),
            })
            .collect();
        // Longest prefix first, then by spelling so the order is total and a
        // reconcile is deterministic. An exact-length overlap is a genuine
        // route collision the router itself shadows.
        views.sort_by(|a, b| {
            ovstorage_layer::node_rank(&b.root)
                .cmp(&ovstorage_layer::node_rank(&a.root))
                .then_with(|| {
                    ovstorage_layer::node_key(&a.root).cmp(&ovstorage_layer::node_key(&b.root))
                })
        });
        views
    }

    /// The generation currently recorded for `root`, so a test can drive a
    /// transition the way the drain does — against the advertisement it belongs
    /// to — without threading the number through every fixture.
    #[cfg(test)]
    fn generation_of(&self, root: &Url) -> u64 {
        self.roots
            .lock()
            .ok()
            .and_then(|roots| roots.get(&root_key(root)).map(|entry| entry.generation))
            .unwrap_or(u64::MAX)
    }

    /// [`Self::enter_scoped_mode`] against `root`'s current advertisement.
    #[cfg(test)]
    fn refuse(&self, root: &Url) {
        self.enter_scoped_mode(root, self.generation_of(root));
    }

    /// [`Self::leave_scoped_mode`] against `root`'s current advertisement.
    #[cfg(test)]
    fn grant(&self, root: &Url) {
        self.leave_scoped_mode(root, self.generation_of(root));
    }

    /// [`Self::root_watch_ended`] against `root`'s current advertisement.
    #[cfg(test)]
    fn end_root_watch(&self, root: &Url) {
        self.root_watch_ended(root, self.generation_of(root));
    }

    /// A probing root's consecutive-failure count, or `None` when the root is
    /// not probing at all.
    #[cfg(test)]
    fn probe_failures(&self, root: &Url) -> Option<u32> {
        let roots = self.roots.lock().ok()?;
        match roots.get(&root_key(root))?.watch {
            RootWatch::Refused {
                consecutive_failures,
                ..
            } => Some(consecutive_failures),
            _ => None,
        }
    }

    /// Root prefixes currently probing narrower scopes, longest first — the
    /// `admits_probes` half of [`Self::root_views`], which is the shape the
    /// registry's own tests assert on.
    #[cfg(test)]
    fn probing_roots(&self) -> Vec<Url> {
        self.root_views()
            .into_iter()
            .filter(|view| view.admits_probes)
            .map(|view| view.root)
            .collect()
    }

    /// Record that a cacheable entry was produced for `address`.
    ///
    /// A directory a live root watch already reports is registered the same as
    /// any other. Its root's watch can be refused later — a policy reload, a
    /// broker restart — and at that moment this table is the only record of
    /// what the cache holds; dropping the read instead would leave the fallback
    /// with nothing to select until traffic happened to re-read every
    /// directory. Registering it costs one of [`MAX_CANDIDATE_SCOPES`] entries
    /// and no watch: selection drops it while the root covers it. Nothing here
    /// reads the root map, so the cache read path takes the registry's leaf
    /// lock and no other.
    fn note_cached(&self, address: &Url) {
        self.scopes.note_cached(address);
    }

    /// Whether a root whose own watch is live already reports `address`.
    ///
    /// The same question [`RootView::covers`] answers for selection, asked of
    /// one address. Longest match wins, as everywhere else, so an inner granted
    /// root answers for its subtree rather than the refused root above it.
    #[cfg(test)]
    fn covers(&self, address: &Url) -> bool {
        let Ok(roots) = self.roots.lock() else {
            return false;
        };
        roots
            .values()
            .filter(|entry| address::is_ancestor_or_self(&entry.root, address))
            .max_by_key(|entry| ovstorage_layer::node_rank(&entry.root))
            .is_some_and(|entry| matches!(entry.watch, RootWatch::Live))
    }

    /// Whether `generation` still names the live advertisement of `root`.
    ///
    /// Kept only as [`Self::still_owns_scope`]'s foil. No production path may
    /// use it:
    /// every write a retired drain makes is about a SCOPE, and this question
    /// cannot see a nested takeover of one. The test that contrasts them asserts
    /// this returns `true` in exactly the case where the verdict must not land,
    /// which is the whole reason the stronger predicate exists.
    #[cfg(test)]
    fn advertisement_is_current(&self, root: &Url, generation: u64) -> bool {
        let Ok(roots) = self.roots.lock() else {
            return false;
        };
        roots
            .get(&root_key(root))
            .is_some_and(|record| record.generation == generation)
    }

    /// A predicate for the memo readers: whether the advertisement that issued
    /// a refusal still owns the scope it is about.
    ///
    /// The same question as the write guard, asked at read time, and it has to
    /// be the same: a memo is a verdict from one route about one directory, so
    /// it applies exactly while that route is the one serving that directory. A
    /// route that has been withdrawn, re-advertised, or had the scope taken from
    /// it by a nested root is no longer speaking for that directory.
    ///
    /// LOCK ORDER. This is called with the scope table already held and takes
    /// the roots lock, so it establishes scopes-then-roots. Nothing in this file
    /// takes them the other way — every root-state writer releases the roots
    /// lock before touching `scopes`, and the notify at the end of each is on a
    /// `Notify` rather than the table — so the order is consistent. It is stated
    /// here because it is the only place both are held at once.
    fn memo_owner_still_owns(&self) -> impl Fn(&Url, u64, &Url) -> bool + '_ {
        move |root: &Url, generation: u64, scope: &Url| {
            self.still_owns_scope(root, generation, scope)
        }
    }

    /// Whether `root`@`generation` is still the route that OWNS `scope`.
    ///
    /// Comparing only the root's own generation is not enough, and the gap is
    /// not a race but a wrong question. (`advertisement_is_current` asks exactly
    /// that narrower question and is kept, test-only, as this one's foil — not
    /// linked here, because a `cfg(test)` item is absent from the doc build.) A nested root taking a subtree over
    /// leaves the outer root advertised and its generation untouched — so the
    /// outer drain's own advertisement is still perfectly current while the
    /// scope beneath it now belongs to somebody else. Asked only about the root,
    /// the guard says yes and the retired drain's verdict lands on the
    /// replacement anyway.
    ///
    /// Ownership is the router's rule: the longest advertised prefix wins, the
    /// same `RouteTable::lookup` uses and the same `select_scopes` assigns by.
    /// Answered under one acquisition of the roots lock, so a takeover cannot
    /// slip between the two questions.
    fn still_owns_scope(&self, root: &Url, generation: u64, scope: &Url) -> bool {
        let Ok(roots) = self.roots.lock() else {
            return false;
        };
        let Some(record) = roots.get(&root_key(root)) else {
            return false;
        };
        if record.generation != generation {
            return false;
        }
        !roots.values().any(|other| {
            !address::same_node(&other.root, root)
                && address::is_ancestor_or_self(&other.root, scope)
                && ovstorage_layer::node_rank(&other.root) > ovstorage_layer::node_rank(root)
        })
    }

    /// The current advertisement's generation for `root`, for tests that are
    /// not modelling a stale drain and should not have to spell one.
    #[cfg(test)]
    fn note_scope_outcome_now(&self, root: &Url, outcome: ScopeOutcome) {
        let generation = {
            let Ok(roots) = self.roots.lock() else {
                return;
            };
            match roots.get(&root_key(root)) {
                Some(record) => record.generation,
                None => return,
            }
        };
        self.note_scope_outcome(root, generation, outcome);
    }

    /// Charge one scope watch's outcome to its root's probe budget.
    ///
    /// [`ScopeOutcome`] rather than a bool because the budget asks whether
    /// probing under this root is producing watches that WORK, and the four
    /// answers are not two: `Failed` covers every terminal end and not refusals
    /// alone, since a run of scopes ending terminally for any reason answers no;
    /// `Barren` is weaker still, an accepted watch that reported nothing;
    /// `Opened` is a grant that has not yet proved itself; and `Worked` is the
    /// only one that settles it.
    fn note_scope_outcome(&self, root: &Url, generation: u64, outcome: ScopeOutcome) {
        let mut paused = false;
        {
            let Ok(mut roots) = self.roots.lock() else {
                return;
            };
            let Some(record) = roots.get_mut(&root_key(root)) else {
                return;
            };
            // A URL is not an identity, and this is a write that outlives its
            // author: the drain reporting the outcome may have been retired
            // while the same URL was re-advertised, or while a nested root took
            // its scope over. Charging the replacement's budget for the old
            // route's refusal pauses probing on a root that has answered
            // nothing.
            if record.generation != generation {
                return;
            }
            let ScopedRoot {
                watch:
                    RootWatch::Refused {
                        consecutive_failures,
                        consecutive_barren,
                        paused_until,
                    },
                ..
            } = record
            else {
                return;
            };
            match outcome {
                // An open succeeded. That is a grant, and a grant resets the
                // budget — UNLESS this root has been handing out watches that
                // end barren, in which case an accepted open is the very thing
                // being distrusted and must not launder the count.
                //
                // The SAME threshold the charge uses, so the refund is withheld
                // exactly when the barren history has actually cost budget. A
                // lower one here would withhold it on a history the charge
                // called transient, and little repairs that inside a run: a
                // stream that ends having worked clears the count, and a root
                // granting healthy watches keeps them open, so what is left is
                // the pause expiry — which first costs the pause.
                ScopeOutcome::Opened => {
                    if *consecutive_barren < BARREN_ENDS_BEFORE_DISTRUST {
                        *consecutive_failures = 0;
                    }
                    return;
                }
                // A stream that ran. The strongest evidence this root grants
                // watches that work, so it clears both counts.
                ScopeOutcome::Worked => {
                    *consecutive_barren = 0;
                    *consecutive_failures = 0;
                    return;
                }
                // Accepted and over at once with nothing to show. One is a
                // transient fault; a run of them is a backend that accepts
                // watches without watching, and only then does it cost budget.
                ScopeOutcome::Barren => {
                    *consecutive_barren += 1;
                    if *consecutive_barren < BARREN_ENDS_BEFORE_DISTRUST {
                        return;
                    }
                }
                ScopeOutcome::Failed | ScopeOutcome::OpenUnavailable => {}
            }
            *consecutive_failures += 1;
            if *consecutive_failures >= MAX_CONSECUTIVE_SCOPE_FAILURES && paused_until.is_none() {
                *paused_until = Some(tokio::time::Instant::now() + DENIED_SCOPE_RETRY);
                paused = true;
            }
        }
        if paused {
            tracing::info!(
                target: "ovstorage.notification_drain",
                root = %redact_url(root),
                "no watch was granted under this address root; pausing directory watch attempts and using TTL-only invalidation"
            );
        }
    }

    /// Whether a root is waiting out a spent probe budget, so the supervisor
    /// wakes on a timer rather than only on a cache read.
    fn has_pending_deadline(&self) -> bool {
        let Ok(roots) = self.roots.lock() else {
            return false;
        };
        roots.values().any(|entry| {
            matches!(
                entry.watch,
                RootWatch::Refused {
                    paused_until: Some(_),
                    ..
                }
            )
        })
    }
}

/// How long to wait before another open attempt after one failed.
///
/// A refused root is not a blip to recover from: it is a policy statement, and
/// the only thing that changes it is a policy reload. It gets a flat, long
/// interval rather than the doubling backoff, whose ceiling
/// ([`MAX_DRAIN_BACKOFF`]) would re-ask the same refused question every minute
/// for the life of the process.
fn backoff_after_open_failure(refused_root: bool, current: Duration) -> Duration {
    if refused_root {
        DENIED_SCOPE_RETRY
    } else {
        (current * 2).min(MAX_DRAIN_BACKOFF)
    }
}

/// What a watch's stream amounted to, classified once for every question that
/// depends on it.
///
/// Two questions do: how long to wait before reopening, and whether the watch
/// counts as having been working. They had a predicate each, neither of which
/// named every [`DrainEnd`], and they disagreed — a stream that opened and
/// errored at once was backed off as a failure by one and stamped as a working
/// watch by the other, which is how a backend whose streams error immediately
/// pinned every slot indefinitely: the stamp refreshed faster than
/// [`ScopeSignals::working_recently`]'s window could age it out.
///
/// The `match` below is wildcard-free over [`DrainEnd`] on purpose: a new
/// variant stops compiling until it is classified here, rather
/// than being silently absorbed by whichever predicate a later reader happens
/// to extend. What "barren" MEANS is one expression, so changing it changes
/// every question at once instead of one of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StreamEnd {
    /// This drain was cancelled. Nothing is recorded for it.
    Cancelled,
    /// It ended at once with nothing to show, cleanly or in error. A backend
    /// that answers every open this way is accepting watches without watching,
    /// and must not look like one that works.
    Barren,
    /// It ran — long enough or with events — and then failed. The watch did
    /// work, so it counts as having worked; the failure only sets the backoff.
    Faulted,
    /// It ran and ended cleanly. The ordinary reconnect.
    Productive,
}

impl StreamEnd {
    fn of(outcome: &DrainOutcome, uptime: Duration) -> Self {
        let barren = outcome.events == 0 && uptime < MIN_STABLE_WATCH_UPTIME;
        match (&outcome.end, barren) {
            (DrainEnd::Cancelled, _) => StreamEnd::Cancelled,
            (DrainEnd::Clean, true) | (DrainEnd::Error, true) => StreamEnd::Barren,
            (DrainEnd::Error, false) => StreamEnd::Faulted,
            (DrainEnd::Clean, false) => StreamEnd::Productive,
        }
    }

    /// Whether this end says the watch was doing its job, which is what
    /// [`ScopeSignals::note_stream_ended`] records. Barren and cancelled ends
    /// do not, so they leave [`ScopeSignals::NEVER_STOPPED`] standing — though
    /// only the barren case reaches the stamp, since a cancelled drain exits
    /// before it.
    fn worked(self) -> bool {
        match self {
            StreamEnd::Faulted | StreamEnd::Productive => true,
            StreamEnd::Barren | StreamEnd::Cancelled => false,
        }
    }
}

fn drain_backoff_after(current: Duration, end: StreamEnd) -> Duration {
    match end {
        StreamEnd::Barren | StreamEnd::Faulted => (current * 2).min(MAX_DRAIN_BACKOFF),
        StreamEnd::Productive | StreamEnd::Cancelled => INITIAL_DRAIN_BACKOFF,
    }
}

/// Routing identity of a root beyond its URL: the connection and route that
/// currently back the URL. A same-URL rebind to a different connection/route
/// changes this, so the drain is cancelled, reopened, and the subtree swept.
#[derive(Clone, PartialEq, Eq)]
struct RootIdentity {
    connection_id: Option<ConnectionId>,
    source: RouteSource,
}

impl RootIdentity {
    fn of(root: &RootInfo) -> Self {
        Self {
            connection_id: root.connection_id.clone(),
            source: root.source.clone(),
        }
    }
}

struct RootDrain {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    identity: RootIdentity,
    prefix: Url,
}

impl RootDrain {
    fn stop(self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// One scoped watch: a directory drain owned by the scope supervisor.
struct ScopeDrain {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
    /// What the drain publishes about itself. Retirement reads `ever_opened`: a
    /// scope whose watch was refused before it ever opened protected nothing,
    /// so there is nothing of its subtree to invalidate — sweeping it anyway
    /// would delete cache entries for no reason, on every refusal, in exactly
    /// the deployment this fallback exists for, and the mode it is asking for.
    signals: Arc<ScopeSignals>,
    /// The root advertisement this drain was opened under, and which
    /// generation of it. Selection matches on both: the drain's stream is bound
    /// to that route, and every outcome it reports is charged to that root.
    root: Url,
    generation: u64,
}

/// What a scope drain publishes about itself, for the supervisor to read
/// between reconciles.
struct ScopeSignals {
    /// Set the first time the watch opens and never cleared. Retirement reads
    /// it: a scope whose watch was refused before it ever opened protected
    /// nothing, so there is nothing of its subtree to invalidate.
    ever_opened: std::sync::atomic::AtomicBool,
    /// Whether the watch is open *right now*. Eviction protection reads this
    /// one: a slot is worth holding while it is doing the job, and a scope
    /// whose stream ended and whose reopen keeps failing is not. The two
    /// questions have different answers, and conflating them is what lets a
    /// dead scope hold a slot for the life of the process.
    live: std::sync::atomic::AtomicBool,
    /// The mode currently being asked for. Selection reads it: a scope that has
    /// degraded to its immediate children reports nothing below them and must
    /// stop being treated as covering the scopes beneath it.
    recursive: std::sync::atomic::AtomicBool,
    /// When this drain was created. The origin for `stopped_at_millis`, which
    /// has to be a number to live in an atomic. The drain stamps and the
    /// supervisor reads, so the two must share a clock: both run on the layer's
    /// runtime today, and moving a drain onto a runtime of its own would break
    /// this rather than the atomics.
    started: tokio::time::Instant,
    /// Milliseconds since `started` at which this watch last stopped reporting,
    /// written by the drain when its stream ends.
    ///
    /// Displacement protection needs "has this watch been working recently",
    /// and neither of the flags above answers it: `live` is false both for a
    /// drain sleeping out a backoff and for one wedged for the life of the
    /// process, and `ever_opened` is never cleared. The drain publishes the
    /// fact rather than the supervisor inferring it from when it last looked —
    /// the supervisor has no tick at all when every candidate is watched, so
    /// an inferred reading ages while a perfectly healthy watch is up, and the
    /// first reconcile after a ten-minute stream reads a one-second reconnect
    /// as a wedge.
    stopped_at_millis: std::sync::atomic::AtomicU64,
}

impl ScopeSignals {
    /// Whether this watch has been reporting recently enough to be worth
    /// defending against a hotter candidate.
    ///
    /// A watch that is open now qualifies; so does one whose stream ended
    /// recently, where recently is twice [`MAX_DRAIN_BACKOFF`] — the longest a
    /// drain sleeps between streams, plus room for the open that follows, which
    /// has no deadline of its own. Beyond that it is wedged rather than
    /// reconnecting, and a directory that could be watched takes the slot.
    ///
    /// A watch that never opened qualifies for neither: it has proved nothing,
    /// and four such directories would otherwise pin every slot for the life of
    /// the process.
    ///
    /// Neither does a watch whose streams have ONLY EVER ended at once with no
    /// events. The drain declines to stamp those ends, so `stopped_at_millis`
    /// keeps [`Self::NEVER_STOPPED`] and this answers no: a backend that
    /// accepts every watch and immediately drops it must not look like a
    /// working one, or four such directories hold every slot while a prefix
    /// whose watch would work is never selected. A watch that ran properly once
    /// and has been failing that way since keeps the grace for two backoffs
    /// after its last real stream, exactly as any other watch does. Only a real
    /// stream end stamps, and the grace is measured from the stamp.
    fn working_recently(&self) -> bool {
        if !self.ever_opened.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        if self.live.load(std::sync::atomic::Ordering::SeqCst) {
            return true;
        }
        let stopped = self
            .stopped_at_millis
            .load(std::sync::atomic::Ordering::SeqCst);
        if stopped == Self::NEVER_STOPPED {
            // Not open, and no stream has ever ended in a way worth stamping:
            // every stream this watch had ended at once with no events. A zero
            // sentinel here would instead read as "stopped at creation" and
            // grant the reconnect grace to exactly the backend the stamp is
            // withheld from.
            return false;
        }
        // Twice the backoff, not once. `MAX_DRAIN_BACKOFF` is the longest a
        // drain SLEEPS between streams; what has to be covered is the sleep
        // plus the open that follows it, and an open has no deadline. At
        // exactly one backoff a healthy watch whose reopen takes a second is
        // read as wedged and swept a moment before its stream comes up.
        self.elapsed_millis().saturating_sub(stopped) <= MAX_DRAIN_BACKOFF.as_millis() as u64 * 2
    }

    /// Milliseconds since this drain was created.
    fn elapsed_millis(&self) -> u64 {
        tokio::time::Instant::now()
            .saturating_duration_since(self.started)
            .as_millis() as u64
    }

    /// The `stopped_at_millis` of a watch that has never had a stream end worth
    /// recording. Distinct from zero, which is a real reading: a stream that
    /// ended in the first millisecond of the drain's life.
    const NEVER_STOPPED: u64 = u64::MAX;

    /// Record that the watch has stopped reporting, as of now.
    fn note_stream_ended(&self) {
        // Stamped before the flag clears, so a supervisor reading them in the
        // other order never sees a scope that is neither live nor recently
        // stopped.
        self.stopped_at_millis
            .store(self.elapsed_millis(), std::sync::atomic::Ordering::SeqCst);
        self.live.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ScopeDrain {
    /// Cancel the drain and hand back its handle, deliberately **without**
    /// aborting.
    ///
    /// Aborting the task would resolve its handle at once while the watch's
    /// synchronous `next()` — running on a blocking thread inside
    /// [`drain_stream`] — kept running, so a backend that does not observe
    /// cancellation would hold a stream and a thread that nothing accounted
    /// for, and [`MAX_WATCH_SCOPES`] would stop bounding live watches. Left
    /// un-aborted, the handle completes exactly when the blocking closure
    /// returns, which is a truthful signal that the resource is free. The
    /// supervisor does not charge it against the watch budget — see that
    /// argument in `reconcile_scopes` — it holds the watch set still once too
    /// many handles are outstanding, at `STUCK_RETIREMENT_LIMIT`.
    fn stop(self) -> tokio::task::JoinHandle<()> {
        self.cancel.cancel();
        self.handle
    }
}

/// Everything selection and retirement need to know about one running scope
/// drain, stated rather than read off an atomic wherever the question is asked.
///
/// The scope half of what [`ScopedWatchState::root_views`] does for roots, and
/// written for the reason that type gives: several questions are asked of a
/// drain, no two of them have the same answer, and each is answered by a
/// different signal. Reading the atomics at the call sites is what lets a
/// question end up on the wrong one.
///
/// | the question                                  | field             | the signals behind it                |
/// |-----------------------------------------------|-------------------|--------------------------------------|
/// | does it report the scopes below it?           | `covers_below`    | open *now*, and recursive            |
/// | is it worth defending against a hotter rival? | `worth_defending` | working recently, and still read     |
/// | has it a watch whose loss must be swept?      | `has_opened`      | it opened at least once              |
///
/// The three differ in exactly the way four rounds of this code got wrong. A
/// drain sleeping out a backoff between streams is not `covers_below` but is
/// `worth_defending`; one wedged for the life of the process is neither, yet is
/// still `has_opened` and so still has a subtree to sweep. No one signal
/// answers two of these questions.
///
/// `root` and `generation` travel with every answer, because each is about a
/// watch on a ROUTE rather than on a URL: a drain whose scope has changed hands
/// is retired in this same pass, and must not be believed in the meantime.
struct ScopeView {
    key: String,
    root: Url,
    generation: u64,
    covers_below: bool,
    worth_defending: bool,
    has_opened: bool,
}

/// Project every running drain into the answers selection asks for.
///
/// One pass, taken immediately before selection runs, so every question is
/// answered from the same instant. The drains write these signals from their
/// own tasks, so separate passes could disagree with each other about one drain
/// — and a selection built from two disagreeing readings is not a selection of
/// anything.
///
/// It is a SNAPSHOT, and selection acts on it: a drain whose first open lands
/// after this pass is selected against as though it had not opened, which under
/// a root that admits no probes costs it its slot until that root answers —
/// a pause expiring, or a watch that has not answered yet doing so. That is why
/// the call sits immediately above `select_scopes`, after the root and
/// candidate reads selection also depends on — and why the retirement reads
/// `ScopeSignals::ever_opened` again rather than reusing `has_opened`. The
/// second read decides only whether to sweep, and a fresher answer there can
/// only add a sweep: cancelling a watch that did open without invalidating what
/// it was protecting is the one outcome with no expiry behind it.
/// The map key for one address ROOT: two spellings of a node give one row.
///
/// `RouteTable` treats `x` and `x/` as one root — it dedups on
/// `ovstorage_layer::node_key` and ranks on `node_rank` — so root bookkeeping
/// keyed on the serialization splits one route into two records, and a removal
/// spelled differently from the insert leaves the other behind.
///
/// This folds the trailing slash, which the metadata cache's own keys
/// deliberately do NOT: there a key names an object, and on a flat store
/// `docs` and `docs/` are two of them. Here a key names a mount that a route
/// publishes, which is the same thing whichever way it is written.
fn root_key(root: &Url) -> String {
    let mut node = root.clone();
    node.set_path(ovstorage_layer::node_path(root));
    ovstorage_layer::node_address(&node)
}

/// The root advertisement a URL would be served by: longest prefix wins, which
/// is what `RouteTable::lookup` does and therefore what decides which backend a
/// watch on it reaches.
fn longest_root<'a>(roots: &'a [RootView], address: &Url) -> Option<&'a Url> {
    roots
        .iter()
        .filter(|view| address::is_ancestor_or_self(&view.root, address))
        .max_by_key(|view| ovstorage_layer::node_rank(&view.root))
        .map(|view| &view.root)
}

fn scope_views(
    drains: &HashMap<String, ScopeDrain>,
    scopes: &WatchScopes,
    roots: &[RootView],
) -> Vec<ScopeView> {
    drains
        .iter()
        .map(|(key, drain)| {
            let recursive = drain
                .signals
                .recursive
                .load(std::sync::atomic::Ordering::SeqCst);
            let covers_below =
                drain.signals.live.load(std::sync::atomic::Ordering::SeqCst) && recursive;
            // Descendant traffic defends this watch only where this watch
            // reports the descendants. `direct_touch` carries reads of the
            // directory itself; the subtree is added back here, and only for a
            // drain whose watch is recursive and on the current advertisement —
            // a narrow watch is not defended by traffic it could never report.
            //
            // `recursive` and not `covers_below`, which is the same test plus
            // `live`. Whether the watch is open THIS INSTANT is the coverage
            // question, and importing it here answers the defensibility one
            // with it: a cover held up entirely by subtree traffic has a stale
            // `direct_touch` by construction, since `note_cached` stamps that
            // only for the directory actually read. So the whole of its defence
            // would fall the moment its stream ended, and once enough rivals
            // outrank it to push it past the truncation, an ordinary reconnect
            // retires and sweeps a working recursive watch. A reconcile lands in
            // that gap routinely: a descendant collapsed onto the cover is an
            // unselected candidate, which keeps the supervisor's tick armed.
            // Spanning the reconnect is what the `working_recently()` conjunct
            // below is for, and it already bounds a drain that never comes back.
            let still_read = scopes.touched_within(key, MIN_WATCH_RESIDENCY)
                || (recursive
                    && Url::parse(key).is_ok_and(|scope| {
                        scopes.subtree_touched_within(&scope, MIN_WATCH_RESIDENCY, &|descendant| {
                            longest_root(roots, descendant) == Some(&drain.root)
                        })
                    }));
            ScopeView {
                key: key.clone(),
                root: drain.root.clone(),
                generation: drain.generation,
                covers_below,
                worth_defending: drain.signals.working_recently() && still_read,
                has_opened: drain
                    .signals
                    .ever_opened
                    .load(std::sync::atomic::Ordering::SeqCst),
            }
        })
        .collect()
}

/// Selects and maintains the scoped watches for every root that is probing.
///
/// One task rather than one per root: assigning a scope to its longest matching
/// root needs the whole root set, and [`MAX_WATCH_SCOPES`] is a budget for the
/// layer rather than for a root.
async fn supervise_scoped_drains(
    layer: Weak<dyn Layer>,
    shutdown: CancellationToken,
    sweep: RootSweep,
    scoped: Arc<ScopedWatchState>,
) {
    let mut drains: HashMap<String, ScopeDrain> = HashMap::new();
    // Cancelled drains whose watch has not yet let go of its BLOCKING-POOL
    // thread — `drain_stream` parks in `stream.next()` there and the
    // cancellation check is only between calls, so a backend that never returns
    // holds one for the life of the process. They are not charged against the
    // watch budget: see the budget's own comment for why charging them ate the
    // watches instead. What bounds the set is the spawn gate in
    // `reconcile_scopes`, which stops opening replacements once it reaches
    // `STUCK_RETIREMENT_LIMIT` — a threshold on the whole set rather
    // than a charge per handle, which is the distinction that comment is about.
    let mut retiring: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut warned_stuck_retirements = false;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        if layer.upgrade().is_none() {
            break;
        }
        let deferred_candidate = reconcile_scopes(
            &mut drains,
            &mut retiring,
            &layer,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        // Names the backend that never returns from a cancelled
        // `stream.next()`, because the freeze in `reconcile_scopes` makes the
        // condition survivable but silent: watches simply stop following the
        // working set. Each such retirement parks a blocking-pool thread for the
        // life of the process, and the pool is shared with the subtree sweeps
        // that loop awaits, which is what the freeze exists to stay clear of.
        //
        // Nothing here can reclaim the thread — a `spawn_blocking` closure
        // cannot be cancelled, which is why `ScopeDrain::stop` hands the handle
        // back rather than aborting it while the drain is retiring. Aborting
        // would drop the task and leave the thread exactly where it is, so a cap
        // that aborts reports progress it has not made.
        //
        // Latched, and re-armed at half the limit rather than at zero, so a
        // backend that releases some and then stalls again is reported again.
        // Against one that releases nothing the set sits at the limit and this
        // stays latched, which is correct: the freeze holds it there, so there
        // is no further growth to report.
        if retiring.len() >= STUCK_RETIREMENT_LIMIT {
            if !warned_stuck_retirements {
                warned_stuck_retirements = true;
                tracing::warn!(
                    target: "ovstorage.notification_drain",
                    stuck = retiring.len(),
                    threshold = STUCK_RETIREMENT_LIMIT,
                    "cache watch streams are not being released after cancellation; \
                     each holds a blocking thread for the life of the process and the \
                     pool is shared with cache maintenance"
                );
            }
        } else if retiring.len() <= STUCK_RETIREMENT_LIMIT / 2 {
            warned_stuck_retirements = false;
        }
        // A refusal expires on a clock, not on an event, so a pending deadline
        // means the supervisor must wake on its own rather than wait for the
        // next cache read to arrive.
        if supervisor_needs_timer(retiring.len(), deferred_candidate, &scoped) {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = scoped.scopes.wake.notified() => {}
                _ = tokio::time::sleep(SCOPE_RECONCILE_TICK) => {}
            }
        } else {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = scoped.scopes.wake.notified() => {}
            }
        }
    }
    for (_, drain) in drains.drain() {
        drain.stop().abort();
    }
}

/// Whether the supervisor must wake on a timer rather than only on a cache
/// read.
///
/// Three kinds of state change happen on a clock rather than on an event. A
/// refusal expires on one. A retiring drain completes silently — `retiring` is
/// drained only inside `reconcile_scopes` — and until it is pruned it holds a
/// blocking-pool thread nothing else reports. And a live watch becomes displaceable by going unread
/// for [`MIN_WATCH_RESIDENCY`], which is the deadline `deferred_candidate`
/// reports. All three share one hazard: `note_cached` notifies only when a
/// *new* scope is registered, so a workload with a stable working set produces
/// no wakes at all and the pending change is never applied.
fn supervisor_needs_timer(
    retiring: usize,
    deferred_candidate: bool,
    scoped: &ScopedWatchState,
) -> bool {
    retiring > 0
        || deferred_candidate
        || scoped.scopes.has_pending_deadline()
        || scoped.has_pending_deadline()
}

/// Choose the scopes to watch and bring the running drains in line with them.
///
/// Selection is the antichain of assigned candidates: a scope covered by
/// another selected scope is dropped, because scoped watches are recursive and
/// the covering watch already reports its subtree. Without that, a `list` of a
/// project directory and reads of its children would each take a slot for the
/// same events.
///
/// Answers whether a candidate was left without a slot, which is a deadline the
/// supervisor has to wake on: see [`supervisor_needs_timer`].
async fn reconcile_scopes(
    drains: &mut HashMap<String, ScopeDrain>,
    retiring: &mut Vec<tokio::task::JoinHandle<()>>,
    layer: &Weak<dyn Layer>,
    shutdown: &CancellationToken,
    sweep: &RootSweep,
    scoped: &Arc<ScopedWatchState>,
) -> bool {
    // Pruned here and nowhere else, which is why `supervisor_needs_timer` arms
    // a tick while any remain. A retiring drain still holds its watch and its
    // thread; what it no longer holds is a slot in the budget.
    retiring.retain(|handle| !handle.is_finished());
    let roots = scoped.root_views();
    let candidates = scoped.scopes.candidates(&scoped.memo_owner_still_owns());
    // Coverage is a property of a watch that is open and recursive, not of a
    // scope that has been selected. A candidate with no drain yet covers
    // nothing: its own watch may take a long time to open — an ordinary broker
    // restart keeps it retrying with backoff — or may open only degraded, and
    // the descendants collapsed onto it would meanwhile hold entries with no
    // watch and nothing to expire them, the byte cache having no TTL at all. The
    // cost of asking for `live` is one reconcile of overlap, which costs a
    // refetch when the cover opens and its own activation sweep runs. A scope
    // on an advertised root's own prefix needs no separate exclusion: its
    // recursive form is precisely the watch that was refused, so it is spawned
    // `NonRecursive` and its `recursive` signal is never set. Carried with the
    // root advertisement the drain was opened under, because coverage is a
    // property of a watch on a ROUTE and not of a URL. A drain whose scope has
    // since changed hands is retired in this same pass, and a watch about to be
    // cancelled reports nothing after it: treating it as covering would
    // collapse a descendant onto a stream that is going away.
    let views = scope_views(drains, &scoped.scopes, &roots);
    let can_cover = |entry: &SelectedScope| {
        views.iter().any(|view| {
            view.covers_below
                && view.key == entry.scope.as_str()
                && view.root == entry.root
                && view.generation == entry.generation
        })
    };
    // The anti-thrash rule, moved off admission and onto the resource it is
    // about. A watch keeps its slot while the directory under it is still being
    // read; once that directory has been unread for `MIN_WATCH_RESIDENCY` the
    // watch set is free to follow the working set that replaced it.
    //
    // Keyed on the watch having been live RECENTLY, which is neither `live` nor
    // `ever_opened` alone. `live` is false for a drain sleeping out a backoff
    // between streams, so a reconcile landing in that window would tear down
    // and sweep a directory read a second ago, on every routine reconnect.
    // `ever_opened` is never cleared, so a scope whose every reopen hangs for
    // the life of the process would hold its slot for as long as its directory
    // is read while reporting nothing at all. `MAX_DRAIN_BACKOFF` is the
    // longest a working drain waits between streams, so beyond it a watch is
    // wedged rather than reconnecting. Carried with its advertisement, like
    // `running`, and for a reason specific to what protection is FOR. The rule
    // exists so that tearing a watch down — which sweeps the subtree it was
    // keeping fresh — is not done for a merely hotter newcomer. A drain whose
    // route has been rebound is retired in this same pass whatever it is doing,
    // and because it had opened (protection requires that) its retirement
    // sweeps. So by the time the scope's new entry could be protected, the
    // subtree protection exists to preserve is already gone: there is nothing
    // left to defend, and the scope is exactly as deserving of a slot as any
    // other directory that is being read. The cost is real and bounded: for one
    // pass after a rebind the scopes under that root compete on recency alone,
    // so a burst of hotter newcomers can take the slots. They re-earn
    // protection as soon as their watches open.
    let protected: Vec<(String, Url, u64)> = views
        .iter()
        .filter(|view| view.worth_defending)
        .map(|view| (view.key.clone(), view.root.clone(), view.generation))
        .collect();
    // Retention is a different question from admission, and the probe budget
    // answers only the second. A drain whose watch has been granted stays:
    // tearing it down would cancel a productive watch and sweep the subtree it
    // was keeping fresh, on the verdict that its root grants nothing — which
    // that grant refutes. It keys on `ever_opened` rather than on the drain
    // merely existing, because a drain still retrying its first open is not
    // evidence of anything and would otherwise hold a slot past an exhausted
    // budget without ever failing terminally enough to be charged for it.
    //
    // Carried with the generation of the advertisement the drain was opened
    // under: a watch bound to a withdrawn route, or to a root a nested one has
    // since taken over, is not the watch retention is arguing for.
    let running: Vec<(String, Url, u64)> = views
        .iter()
        .filter(|view| view.has_opened)
        .map(|view| (view.key.clone(), view.root.clone(), view.generation))
        .collect();
    let selected = select_scopes(
        &roots,
        &candidates,
        // Cancelled drains are NOT charged here. Retention is a different
        // question from admission for `retiring` exactly as it is for the probe
        // budget above, and charging it answered the wrong one: a cancelled
        // drain keeps its slot until its blocking `next()` returns, and
        // `ScopeDrain::stop` deliberately does not abort, so against a backend
        // that never observes cancellation the handle is parked for the life of
        // the process. Subtracting it evicted WORKING watches to pay for a
        // stream nobody can reclaim, and compounded: each eviction retired
        // another drain into the same set, so four stuck handles took the
        // budget to zero, swept every subtree on the way out and left nothing
        // able to re-watch them, with no TTL under them — the byte cache has
        // none — and no path back. So the budget bounds LIVE watches, and a
        // stuck cancelled drain costs a thread rather than a watch. That is the
        // asymmetry the rest of this file is built on — a watch too many costs
        // a thread and can be undone, a watch too few costs entries that expire
        // never — and it removes that eviction cascade at the root rather than
        // flooring it.
        //
        // The thread it costs instead is bounded elsewhere and deliberately not
        // here: past `STUCK_RETIREMENT_LIMIT` the pass above returns without
        // changing the watch set at all. Bounding threads by holding the set
        // still costs nothing that was already working; bounding them by
        // subtracting here evicts watches that were.
        MAX_WATCH_SCOPES,
        &can_cover,
        &|scope: &Url| {
            scoped
                .scopes
                .starting_mode(scope, &scoped.memo_owner_still_owns())
                == WatchMode::Recursive
        },
        &running,
        &protected,
    );
    let selected_count = selected.len();

    // Where the supervisor retires the drains it holds. A drain's TASK can also
    // end on its own, on a terminal open (`scope_drain_task`) — its map entry
    // is still removed here, on the next pass, because the denial takes the
    // scope out of `candidates()`. The supervisor's own exit is what bypasses
    // this block — shutdown, or the layer being dropped out from under it. On
    // the shutdown path `CacheWatchState::drop` cancels and then aborts the
    // supervisor, so what ends the drains is the cancellation hierarchy rather
    // than the loop at the foot of `supervise_scoped_drains`; on the layer-drop
    // path the upgrade fails first and that loop does run.
    //
    // Retirement is one statement with several reasons, and the reasons are
    // four questions. They give four different answers about liveness, which is
    // why no single "may this be retired" predicate over the drain is right:
    //
    // - VALIDITY — is this drain's stream bound to the route that currently
    //   owns the scope? Answered by the root and generation match below, and in
    //   `select_scopes` by a scope having no advertised root at all. The
    //   decision reads no liveness: a stream still reporting a backend the
    //   subtree no longer routes to is precisely the one to end, and the better
    //   it is working the longer it would answer for entries nobody fetches
    //   from there. `ScopeSignals::ever_opened` is read once the decision is
    //   made, to choose whether the retirement has anything to sweep — that is
    //   a consequence, not a condition.
    // - REDUNDANCY — is a watch ABOVE this scope already reporting its events?
    //   Answered by `RootView::covers` for a root's own watch and by `can_cover`
    //   for a peer scope's. Both read the liveness of the COVERING watch;
    //   neither reads this drain's, because a healthy duplicate is still a
    //   duplicate and costs a thread and a runtime on the broker client.
    // - ADMISSION — may a probe be spent under this root at all? `select_scopes`
    //   drops a scope under a root that admits none — a spent probe budget, but
    //   equally a root that has not answered yet — unless it is already
    //   `running`, which is `ScopeView::has_opened`: this drain's own signal,
    //   but "has it ever worked", not "is it working now". A drain still
    //   retrying its first open is ended here, which
    //   `a_paused_root_retains_only_the_drains_whose_watch_was_granted` pins.
    // - SCARCITY — with more candidates than the budget affords, is this the
    //   least valuable watch? `ScopeView::worth_defending`, the only one of the
    //   four that reads how recently this drain was reporting — recently, not
    //   now: a watch stays defensible across a reconnect, because tearing one
    //   down mid-backoff would sweep a directory read a second ago. It does not
    //   save a drain unconditionally either: the cover's extra slot can put one
    //   more scope in `selected` than the budget, so truncation can still reach
    //   a protected scope, and protection earned under a previous advertisement
    //   does not carry to the next one.
    //
    // A fifth reason lives outside both functions: a scope evicted from the
    // registry is absent from `candidates()` and so retires on the next pass
    // however recently it was read. `ScopeEntry::watched` makes eviction PREFER
    // a victim that holds no drain — a tiebreak on drain EXISTENCE, none of the
    // four above — and it is only because at most five of
    // `MAX_CANDIDATE_SCOPES` entries can carry the flag that the preference is
    // as good as a guard. `WatchScopes::touched_within` documents the window
    // where it is not: the pass that first selects a scope has not marked it
    // yet.
    //
    // Validity, redundancy and scarcity are each pinned against a drain whose
    // watch is open at the time, by
    // `a_scope_drain_is_replaced_when_its_root_advertisement_is`,
    // `a_live_scoped_watch_yields_to_its_roots_own_watch` and
    // `a_displaced_watch_sweeps_the_subtree_it_was_protecting` respectively.
    //
    // A drain is kept only where selection asks for the SAME scope under the
    // SAME root advertisement. A URL match is not enough: `reconcile_roots`
    // withdraws and re-advertises a root whose connection or route changed, and
    // a newly advertised nested root takes over the scopes beneath it by
    // longest prefix. In either case the running drain's stream is bound to the
    // old route and its outcomes are charged to a root that no longer owns it,
    // so it is retired here and reopened against the current one — which also
    // re-evaluates the root-prefix rule that forces `NonRecursive`.
    //
    // The circuit breaker on the leak the watch budget cannot see. Every
    // cancelled drain that has not let go holds a BLOCKING-POOL thread, and
    // nothing reclaims it: a `spawn_blocking` closure cannot be cancelled,
    // which is why retirement hands the handle back rather than aborting. The
    // budget bounds LIVE watches, so it does not bound these at all, and the
    // pool they consume is shared — `sweep_off_runtime` is awaited a few lines
    // below, so exhausting it stops this loop from running rather than merely
    // slowing it, and takes the cache's other blocking work with it.
    //
    // It holds RETIREMENT as well as spawning, and that is the whole of why it
    // bounds threads without costing watches. Declining only the spawns would
    // retire and sweep as usual while refusing the replacements, so any pass
    // that changes selection — a root rebind makes every drain stale at once —
    // takes the watch set down by that many with nothing to build it back, and
    // arrives at an empty set on a backend whose new watches would all have
    // worked. Returning before both leaves `drains` untouched: the watch set
    // stops FOLLOWING the working set rather than being torn down, which is a
    // stale watch rather than no watch. See the budget argument in
    // `reconcile_scopes` for why subtracting per handle is the other shape of
    // the same mistake.
    //
    // Keeping a drain whose route has changed is the cost of that. It is the
    // safe direction: every write-back it can still make is generation-guarded
    // and simply misses, and the events it delivers can only over-invalidate,
    // which costs a refetch. A watch it should have kept and lost costs entries
    // the byte cache never expires.
    //
    // `retiring` is pruned at the top of every pass and the supervisor's timer
    // is armed whenever it is non-empty, so this re-opens by itself the moment
    // handles start finishing, with nothing remembering that it fired.
    // Only ever a HOLD on a set this layer still has. The limit is crossed by a
    // retirement, so a pass can start under it, retire the last drain and end
    // over it — and freezing an empty set is not a hold, it is switching the
    // feature off for good, because nothing but a completed handle lowers the
    // count and by hypothesis none of them completes. That is the shape this
    // whole rule exists to avoid, arrived at one pass later, and it would take
    // a deployment whose replacement route is perfectly healthy with it.
    //
    // Letting an empty set rebuild costs one rotation of new handles and cannot
    // repeat: the only thing that empties `drains` is retirement, and from the
    // next pass on this holds it. So the leak settles at the limit plus that
    // rotation instead of growing, which is the bound the warning reports.
    if retiring.len() >= STUCK_RETIREMENT_LIMIT && !drains.is_empty() {
        let held: Vec<String> = drains.keys().cloned().collect();
        scoped.scopes.mark_watched(&held);
        return true;
    }
    let stale: Vec<String> = drains
        .iter()
        .filter(|(key, drain)| {
            !selected.iter().any(|entry| {
                entry.scope.as_str() == key.as_str()
                    && entry.generation == drain.generation
                    && entry.root == drain.root
            })
        })
        .map(|(key, _)| key.clone())
        .collect();
    for key in stale {
        let Some(drain) = drains.remove(&key) else {
            continue;
        };
        // Retirement always sweeps, even when a broader scope has been selected
        // over this one. Selection is not coverage: the covering scope's watch
        // may take a long time to open, or never open — an ordinary broker
        // restart keeps it retrying with backoff indefinitely — and until it
        // does, these entries have no watch and the byte cache has no TTL to
        // fall back on, so they would be stale with no expiry rather than stale
        // until expiry. When the cover does open, its own activation sweep
        // repeats this over a superset, so nothing is lost by being early.
        if drain
            .signals
            .ever_opened
            .load(std::sync::atomic::Ordering::SeqCst)
            && let Ok(prefix) = Url::parse(&key)
        {
            sweep_off_runtime(sweep, &prefix).await;
        }
        retiring.push(drain.stop());
    }

    for SelectedScope {
        root,
        generation,
        scope,
    } in selected
    {
        if drains.contains_key(scope.as_str()) {
            continue;
        }
        let cancel = shutdown.child_token();

        // The root's own prefix only ever opens non-recursively: its recursive
        // form is precisely the watch that was refused. Otherwise start with
        // the mode the memo suggests, so a scope that already degraded once
        // does not pay for the recursive probe again on re-admission.
        let mode = if root.as_str() == scope.as_str() {
            WatchMode::NonRecursive
        } else {
            scoped
                .scopes
                .starting_mode(&scope, &scoped.memo_owner_still_owns())
        };
        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(mode.recursive()),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
        });
        let handle = tokio::spawn(scope_drain_task(
            layer.clone(),
            root.clone(),
            scope.clone(),
            generation,
            cancel.clone(),
            sweep.clone(),
            Arc::clone(scoped),
            Arc::clone(&signals),
        ));
        drains.insert(
            scope.as_str().to_string(),
            ScopeDrain {
                cancel,
                handle,
                signals,
                root,
                generation,
            },
        );
    }

    // Marked after the spawn and retire loops, so the set is the drains that
    // exist rather than the ones about to.
    let held: Vec<String> = drains.keys().cloned().collect();
    scoped.scopes.mark_watched(&held);

    // Not every candidate here lost the budget — some are covered by a live
    // root, some sit under a root that is not probing, some collapsed onto a
    // cover. What they have in common is that whether they get a watch can
    // change without any read arriving: a protected watch reaching
    // `MIN_WATCH_RESIDENCY`, a cover's own watch opening. Both are reached by a
    // clock. This over-arms deliberately — a 30-second tick is the cheap
    // direction, and the expensive one is the supervisor sitting on whichever
    // directories it first selected because no read happened to wake it.
    //
    // The freeze above returns `true` directly rather than falling through to
    // this, because neither term describes it: the frozen pass may hold a full
    // drain set with every candidate selected, and what it is waiting for is a
    // handle to finish rather than a candidate to become selectable.
    // `supervisor_needs_timer` would also arm on `retiring > 0`, but two
    // independent conditions agreeing is not the same as saying it.
    !drains.is_empty() && selected_count < candidates.len()
}

/// Record that `prefix`'s recursive watch was refused, so a later drain for the
/// same scope starts with the smaller ask instead of re-paying for this one.
///
/// Answers whether the memo was actually written, because the caller's retry
/// depends on it: the drain loop re-reads `starting_mode` at the top of every
/// iteration, so a degrade that recorded nothing is re-widened to `Recursive`
/// and refused again. A suppressed write is a silent one, and the caller cannot
/// tell it from a recorded one without being told.
fn state_deny_recursive(role: &DrainRole, prefix: &Url) -> bool {
    let DrainRole::Scope {
        state,
        root,
        generation,
        ..
    } = role
    else {
        return false;
    };
    // The third URL-keyed write a retired drain can land, and the last one.
    // `deny` is keyed by scope, so a recursive refusal recorded after a nested
    // root took this scope over — or after a same-URL rebind — would start the
    // REPLACEMENT's drain `NonRecursive` for the whole `DENIED_SCOPE_RETRY`
    // window and disqualify it from the cover slot, on the strength of a
    // refusal from a route it never watched.
    if !state.still_owns_scope(root, *generation, prefix) {
        return false;
    }
    state
        .scopes
        .deny(prefix, WatchMode::Recursive, root, *generation);
    true
}

/// Wake the scope supervisor, for a change only the drain can observe.
fn notify_supervisor(role: &DrainRole) {
    if let DrainRole::Scope { state, .. } = role {
        state.scopes.wake.notify_one();
    }
}

/// Run a sweep on the blocking pool.
///
/// A sweep is synchronous disk work — for the byte cache a SQLite subtree
/// delete with an fsync — and this crate's rule is that such work does not run
/// on a runtime worker. Awaited, so the caller's ordering still holds.
async fn sweep_off_runtime(sweep: &RootSweep, prefix: &Url) {
    let sweep = Arc::clone(sweep);
    let prefix = prefix.clone();
    let _ = tokio::task::spawn_blocking(move || sweep(&prefix)).await;
}

/// One scope chosen for watching, with the root advertisement it was assigned
/// to. The generation travels with it because a drain has to be matched against
/// the advertisement it was opened under, not merely against a URL.
#[derive(Clone)]
struct SelectedScope {
    root: Url,
    generation: u64,
    scope: Url,
}

/// Scopes chosen for watching, in selection order.
type Assignment = Vec<SelectedScope>;

/// Pick the scopes to watch from `candidates`, given the roots that are
/// probing and how many watches are affordable.
///
/// `roots` is longest-prefix-first and `candidates` most-recently-used first;
/// the result is `(root, scope)` pairs in that same recency order.
///
/// Five rules, in order:
///
/// 1. **One root per scope** — the longest root prefix that matches, over
///    **every** advertised root, which is what the router itself dispatches
///    over (`RouteTable::lookup`). A scope assigned to every overlapping root
///    would be watched once per root, and the budget would not be a budget.
///
///    This holds only because `reconcile_roots` advertises every discovered
///    root rather than the watch-capable ones. A root missing from `roots` does
///    not remove its scopes from selection — it makes them match a watch-capable
///    ANCESTOR, so the watch is opened on a prefix the router sends to the
///    nested backend anyway, and that backend's refusal is charged to the
///    ancestor's probe budget. The rule is about mirroring dispatch, and the set
///    has to mirror it too.
/// 2. **Root status** — a scope under a root whose own watch is live needs no
///    watch: that watch already reports it, and a duplicate costs a thread and
///    a runtime on the broker client and sweeps a subtree the root watch was
///    keeping fresh when it retires. A scope under a root that is not probing
///    is not opened either — but one already running is kept, because the
///    budget bounds new probes and not productive watches.
/// 3. **Antichain** — a scope is dropped when another candidate above it, on
///    the **same root**, can cover it. A recursive watch reports its whole
///    subtree, so without this a `list` of a project directory and reads of its
///    children each take a slot for the same events. Two conditions make that
///    conditional rather than assumed. `can_cover` asks whether the covering
///    watch is open and recursive: a scope watching non-recursively — because
///    its recursive form was refused, or because it is the root prefix whose
///    recursive form was — reports nothing below its immediate children. And
///    the roots must match: a watch is dispatched by `RouteTable::lookup` to
///    the route owning the prefix it names, so an ancestor under an outer root
///    is watched by the outer backend and says nothing about a descendant a
///    nested root routes elsewhere.
/// 4. **Budget** — `protected` scopes keep their slots, then the coldest
///    candidates are dropped last-first. `protected` is the scopes whose watch
///    has been live recently and whose directory is still being read; this is
///    where the anti-thrash rule lives, because this is the only place that can
///    weigh a newcomer's heat against the cost of tearing a working watch down.
/// 5. **One cover above the budget** — a candidate that covers a protected
///    scope subsumes it rather than competing with it, so it is granted a slot
///    beyond `budget` instead of taking one. Deferring it deadlocks (it can
///    only cover by opening and only open by being selected, while the reads
///    keeping its descendants protected keep it the hottest candidate there is)
///    and displacing for it is unrecoverable (an open has no deadline, so a
///    cover that never answers costs a working watch permanently). At most one
///    such slot exists however many covers there are, and which cover gets it
///    is decided by what it subsumes rather than by recency, so it does not
///    move with the last read.
///
/// `running` is the scopes that already hold a drain, paired with the root
/// generation each was opened under. It is an input rather than something
/// selection could infer: the same scope is admissible or not depending on
/// whether opening it is a new probe or keeping an existing watch — and only a
/// drain opened under *this* advertisement is the watch that argument is about.
fn select_scopes(
    roots: &[RootView],
    candidates: &[Url],
    budget: usize,
    can_cover: &dyn Fn(&SelectedScope) -> bool,
    may_open_recursive: &dyn Fn(&Url) -> bool,
    running: &[(String, Url, u64)],
    protected: &[(String, Url, u64)],
) -> Assignment {
    let assigned: Assignment = candidates
        .iter()
        .filter_map(|scope| {
            let view = roots
                .iter()
                .find(|view| address::is_ancestor_or_self(&view.root, scope))?;
            if view.covers {
                return None;
            }
            // A scope equal to its root is not watched at all.
            //
            // It can only open `NonRecursive` — its recursive form is the watch
            // that was refused — so it reports the root's immediate children.
            // But a watch's ACTIVATION SWEEP is unconditionally recursive:
            // `clear_subtree_impl` does a prefix scan with no depth bound. So
            // this one scope discards the entire partition, on activation and
            // again on every reopen, including the subtrees that other live
            // scoped watches are keeping fresh. It buys invalidation for the
            // objects at the top of the root and pays for it with the whole
            // cache, repeatedly.
            //
            // Matching the sweep to the mode is the better fix and is not
            // available here: it needs a depth-bounded removal on the shared
            // `Cache`, which has only `remove_prefix`. Until that exists, not
            // watching this scope is strictly better than watching it — and it
            // is what `docs/public/configuration.md` already promises, that an
            // object "directly at the top of the root, which has no narrower
            // directory than the root itself" is invalidated by TTL alone.
            if view.root.as_str() == scope.as_str() {
                return None;
            }
            // The exemption from a non-probing root is per ADVERTISEMENT rather
            // than per URL, and that covers both ways a scope changes hands.
            //
            // A same-URL re-advertisement is a route rebind: the drain's stream
            // is bound to a connection that is gone. A newly advertised nested
            // root is a route MOUNTED OVER this subtree — reads for it now
            // dispatch to a different backend, while the drain's open stream is
            // still on the old one. Keeping either is how a stream outlives the
            // route it was opened on, reporting a backend nobody is reading
            // from, with nothing to notice: no budget is charged and no sweep
            // runs.
            //
            // Both therefore retire, and retiring sweeps — the entries the old
            // route produced are removed rather than left to answer for a
            // subtree that has moved. What the scope gets until the new root
            // answers is TTL-only invalidation, which is what every root that
            // has not answered yet gives the scopes beneath it.
            //
            // The root travels with each entry but is not compared here, and
            // does not need to be: within one `ScopedWatchState` every
            // generation comes from a counter that only ever increments and is
            // never reassigned (`ScopedWatchState::advertise`), so a generation
            // already names exactly one advertisement of exactly one root.
            // Where both are compared the root comparison is therefore
            // redundant and kept deliberately. Three sites compare the pair —
            // `can_cover`, the `protected` partition and `stale` — and dropping
            // the root from all three at once reddens nothing. It is kept
            // because it costs a comparison and means no site rests on that
            // invariant silently.
            let running_here = running.iter().any(|(key, _, generation)| {
                key == scope.as_str() && *generation == view.generation
            });
            if !view.admits_probes && !running_here {
                return None;
            }
            Some(SelectedScope {
                root: view.root.clone(),
                generation: view.generation,
                scope: scope.clone(),
            })
        })
        .collect();
    // Collapsing is per ROOT as well as per prefix. A recursive
    // `watch_directory` is dispatched by `RouteTable::lookup` to the route that
    // owns the prefix it names, so an ancestor scope assigned to an outer root
    // is watched by the OUTER backend, while a descendant a nested root routes
    // elsewhere is served by a different one. Nested roots are ordinary here —
    // `root_views` is longest-prefix-first precisely because of them — so a
    // URL-only antichain would drop the inner scope's watch and leave its
    // entries invalidated by nothing at all.
    //
    // Stated as a route comparison rather than as a claim about backends,
    // because the cache cannot tell the two apart: two roots may be aliases
    // onto one connection, and there the ancestor's watch genuinely would serve
    // the descendant. Selection cannot prove that, and the direction it cannot
    // undo is the other one — a second watch costs a slot, a missing one costs
    // entries that expire never.
    let antichain: Assignment = assigned
        .iter()
        .filter(|entry| {
            !assigned.iter().any(|other| {
                other.scope != entry.scope
                    && other.root == entry.root
                    && address::is_ancestor_or_self(&other.scope, &entry.scope)
                    && can_cover(other)
            })
        })
        .cloned()
        .collect();
    // A stable partition, so recency still orders within each half. Protected
    // scopes can outnumber the budget — the cover is granted one slot above it,
    // so a cover that becomes protected in its own right makes `selected` one
    // longer than `budget` — and then dropping the coldest of them is the only
    // way to stay inside the watch bound at all. Gating the cover on whether it
    // can open recursively is what keeps that rare rather than routine.
    let (mut selected, rest): (Assignment, Assignment) = antichain.into_iter().partition(|entry| {
        protected.iter().any(|(key, root, generation)| {
            key == entry.scope.as_str() && *root == entry.root && *generation == entry.generation
        })
    });
    // A candidate above a protected scope is a consolidation, not a newcomer:
    // its recursive watch subsumes everything it covers, which retires onto it
    // the moment it opens. Deferring it is not a wait but a deadlock — it can
    // only become covering by opening, it can only open by being selected, and
    // the reads keeping its descendants protected are the same reads that,
    // through the ancestor touch, keep it the hottest candidate of all.
    // Meanwhile the broader directory's OWN entries — the listing that
    // registered it — are watched by nothing, with no TTL under them: the byte
    // cache has none. Per root for the same reason the antichain is: a
    // candidate above a protected scope on a DIFFERENT route subsumes nothing,
    // because the watch it would open is dispatched to its own route and never
    // reports the other. Which cover, when there is more than one, must not
    // depend on recency: two covers of two busy subtrees would otherwise swap
    // the slot every time a read landed under the other, and each swap retires
    // a drain and sweeps its subtree. Most protected scopes subsumed wins, then
    // the lower spelling — both properties of the selected set rather than of
    // the last read, so the answer only changes when the answer should. The
    // root comparison matches the antichain's rather than earning its own case:
    // a candidate above a protected scope on a DIFFERENT route subsumes
    // nothing, because the watch it would open is dispatched to its own route
    // and never reports the other. The WINNER is chosen first and only the
    // winner is taken out of `rest`. Partitioning every cover out and keeping
    // the best of them would disqualify the runners-up from the ordinary budget
    // entirely — they could not win an in-budget slot even with slots free —
    // which relocates onto the runner-up the very deadlock this rule exists to
    // prevent, for as long as the winner's open keeps failing.
    let subsumed = |entry: &SelectedScope| {
        selected
            .iter()
            .filter(|held| {
                held.root == entry.root && address::is_ancestor_or_self(&entry.scope, &held.scope)
            })
            .count()
    };
    // Eligibility is whether the candidate can ATTEMPT a recursive watch, not
    // merely whether it sits above protected scopes. The justification above is
    // that the cover's recursive watch subsumes what it covers and collapses
    // the subtree onto it — so a candidate that cannot open recursively is not
    // a consolidation at all. Two are in that position by construction: a scope
    // equal to its root's own prefix, which `reconcile_scopes` always spawns
    // `NonRecursive`, and one with an unexpired recursive refusal, for which
    // `starting_mode` answers the same. Granted the slot, such a watch opens,
    // covers nothing (`can_cover` needs `live && recursive`), and then becomes
    // protected by its own reads — so the next truncation has more protected
    // scopes than budget and evicts an actively read descendant, sweeping it.
    let winner = rest
        .iter()
        .filter(|entry| {
            subsumed(entry) > 0
                && !roots
                    .iter()
                    .any(|view| view.root.as_str() == entry.scope.as_str())
                && may_open_recursive(&entry.scope)
        })
        .max_by(|a, b| {
            subsumed(a)
                .cmp(&subsumed(b))
                .then_with(|| b.scope.as_str().cmp(a.scope.as_str()))
        })
        .map(|entry| entry.scope.clone());
    let (covers, rest): (Assignment, Assignment) = rest
        .into_iter()
        .partition(|entry| Some(&entry.scope) == winner.as_ref());
    let cover = covers.into_iter().next();
    selected.extend(rest);
    selected.truncate(budget);
    // The cover is granted ONE slot above the budget rather than taking a slot
    // from what it covers. Displacing the coldest scope it subsumes was the
    // first shape of this rule and it is wrong in the direction that cannot be
    // undone: an open has no deadline, so a cover whose watch never answers
    // holds its slot indefinitely — and the descendant it displaced was a
    // working watch, which nothing gives back. Overshooting by one costs one
    // thread and one runtime on the broker client, is capped here at one
    // however many covers appear, and ends the moment the cover opens and its
    // subtree collapses onto it.
    if let Some(cover) = cover
        && !selected.iter().any(|held| held.scope == cover.scope)
    {
        selected.push(cover);
    }
    selected
}

/// Run one scope's watch; a terminal end records the refusal and sweeps what
/// the watch had been protecting.
#[allow(clippy::too_many_arguments)]
async fn scope_drain_task(
    layer: Weak<dyn Layer>,
    root: Url,
    scope: Url,
    generation: u64,
    cancel: CancellationToken,
    sweep: RootSweep,
    scoped: Arc<ScopedWatchState>,
    signals: Arc<ScopeSignals>,
) {
    let exit = cache_watch_drain_loop(
        layer,
        scope.clone(),
        cancel,
        sweep.clone(),
        DrainRole::Scope {
            signals,
            state: Arc::clone(&scoped),
            root: root.clone(),
            generation,
        },
    )
    .await;
    // A cancelled exit records nothing, and does not have to: this drain's own
    // token is the only thing that ends the loop that way, and whoever fired it
    // — `ScopeDrain::stop` on retirement, or the layer's shutdown — has already
    // taken this drain out of the supervisor's map. An error the drain did not
    // ask for keeps retrying instead of exiting, precisely so no path can leave
    // a finished drain behind in that map.
    if matches!(exit.kind, DrainExitKind::Cancelled) {
        return;
    }
    // Any terminal end is a scope with no watch — a refusal, but also
    // `Unsupported` or anything else non-retryable. All go in the same table
    // for the same reason: asking again immediately gets the same answer.
    // Both writes are the retired drain's verdict on a route it may no longer
    // be watching, so both are guarded on the advertisement they were formed
    // under. The denial is keyed by scope URL and would otherwise withhold the
    // directory from the root that took it over for the whole retry window;
    // the outcome would charge that root's probe budget for a refusal it never
    // issued.
    if scoped.still_owns_scope(&root, generation, &scope) {
        scoped
            .scopes
            .deny(&scope, WatchMode::NonRecursive, &root, generation);
        scoped.note_scope_outcome(&root, generation, ScopeOutcome::Failed);
    }
    // A scope that never opened was TTL-only throughout, exactly as it is
    // without this feature, so there is nothing it stopped protecting. One that
    // opened and then died terminally holds entries filled while a watch was
    // live, and the byte cache has no TTL. (The retirement path in
    // `reconcile_scopes` sweeps this drain's prefix again when it removes the
    // dead entry; being early costs a refetch and being late has no expiry.)
    if exit.ever_opened {
        sweep_off_runtime(&sweep, &scope).await;
    }
    scoped.scopes.wake.notify_one();
}

/// Run one root's watch. A refusal is handled inside the loop, which starts the
/// probing and keeps retrying the root; the loop only returns when the root is
/// terminally unwatchable or the drain is cancelled.
async fn root_drain_task(
    layer: Weak<dyn Layer>,
    prefix: Url,
    cancel: CancellationToken,
    sweep: RootSweep,
    scoped: Arc<ScopedWatchState>,
    generation: u64,
) {
    let exit = cache_watch_drain_loop(
        layer,
        prefix.clone(),
        cancel,
        sweep,
        DrainRole::Root {
            state: Arc::clone(&scoped),
            generation,
        },
    )
    .await;
    // ONLY `Unsupported`, and the distinction is the whole point.
    //
    // A root that has refused is being probed scope by scope, and that probing
    // is the feature working. `Unsupported` says the backend does no watches
    // here, so the scopes are futile and stopping them is right. Every other
    // non-retryable code — `Internal` from a broker hiccup on one of the root's
    // five-minute re-probes, say — says nothing about whether
    // `mem:///project/` can be watched, and marking the root unwatchable on one
    // of those would take a deployment with four working scoped watches to zero
    // for the life of the process, with no TTL under the byte cache to catch
    // it. That is a worse outcome than the endless root retry this replaces,
    // and it lands on exactly the deployment this feature exists for. A
    // `Terminal` root drain still stops retrying — it has returned — so the
    // waste that motivated this is gone either way. What it does not do is
    // silence the scopes.
    if matches!(exit.kind, DrainExitKind::Unsupported) {
        scoped.root_unwatchable(&prefix, generation);
    }
}

fn reconcile_roots(
    drains: &mut HashMap<String, RootDrain>,
    layer: &Weak<dyn Layer>,
    roots: Vec<RootInfo>,
    shutdown: &CancellationToken,
    sweep: &RootSweep,
    scoped: &Arc<ScopedWatchState>,
) {
    let advertised: Vec<Url> = roots.iter().map(|root| root.root.clone()).collect();
    let eligible: HashMap<String, RootInfo> = roots
        .into_iter()
        .filter(|root| root.capabilities.supports_watch_directory)
        .map(|root| (root_key(&root.root), root))
        .collect();

    // Drop drains whose root vanished, or whose routing identity changed under
    // an unchanged URL (a connection/route rebind). Sweep the subtree on the
    // way out so stale stat/list entries do not answer past the route's
    // lifetime; the rebind then reopens against the new route below.
    let stale: Vec<String> = drains
        .iter()
        .filter(|(key, drain)| match eligible.get(*key) {
            None => true,
            Some(root) => drain.identity != RootIdentity::of(root),
        })
        .map(|(key, _)| key.clone())
        .collect();
    for key in stale {
        if let Some(drain) = drains.remove(&key) {
            sweep(&drain.prefix);
            // A vanished or rebound root is no longer advertised; the rebind
            // below re-advertises it and re-attempts the root watch from
            // scratch.
            scoped.withdraw(&drain.prefix);
            drain.stop();
        }
    }

    // EVERY discovered root is advertised, not only the watch-capable ones, and
    // after the withdrawals above so a rebind is never transiently absent.
    //
    // Assignment has to mirror `RouteTable::lookup`, which dispatches over
    // every route whatever its capabilities. A root missing from this map does
    // not stop its scopes being watched — it makes them match a watch-capable
    // ANCESTOR, so the watch is opened on a prefix the router hands to the
    // nested backend anyway, that backend refuses it, and the refusal is
    // charged to the ancestor's probe budget until the ancestor stops probing
    // entirely. Recorded, an incapable root answers no to both of selection's
    // questions, exactly as a root that has not spoken yet does, and its scopes
    // stay TTL-only. No separate capability flag is carried:
    // `RootWatch::Pending` already gives that answer, and the generation each
    // transition carries is what keeps a straggling drain from moving a
    // drain-less root off it. `eligible` still decides which roots get a root
    // DRAIN: there is nothing to attempt against a backend that says it cannot
    // watch. `retain_advertised` is the counterpart, and it is driven by the
    // same set: withdrawing per-drain would leave a root that never had a drain
    // in the map for the life of the process, suppressing every scope beneath
    // it by longest prefix. Its key set is disjoint from the advertise loop's —
    // it removes only what is absent, `advertise` touches only what is present
    // — so the two commute and the order here is arbitrary. What renumbers a
    // rebound root is the `withdraw` in the stale loop above, which has already
    // run.
    scoped.retain_advertised(&advertised);
    let mut generations: HashMap<String, u64> = HashMap::new();
    for root in &advertised {
        generations.insert(root_key(root), scoped.advertise(root));
    }

    for (key, root) in eligible {
        if drains.contains_key(&key) {
            continue;
        }
        let prefix = root.root.clone();
        let identity = RootIdentity::of(&root);
        let cancel = shutdown.child_token();
        // `eligible`'s keys are a subset of `advertised`'s, and every one of
        // those was just advertised, so this is present. A default here would
        // hand the drain a generation no root has and silently pin its root
        // `Pending` for the life of the process.
        let generation = generations
            .get(&key)
            .copied()
            .expect("every eligible root was advertised above");
        let handle = tokio::spawn(root_drain_task(
            layer.clone(),
            prefix.clone(),
            cancel.clone(),
            sweep.clone(),
            Arc::clone(scoped),
            generation,
        ));
        drains.insert(
            key,
            RootDrain {
                cancel,
                handle,
                identity,
                prefix,
            },
        );
    }
}

fn roots_by_key(roots: Vec<RootInfo>) -> HashMap<String, RootInfo> {
    roots
        .into_iter()
        .map(|root| (root_key(&root.root), root))
        .collect()
}

/// An empty `Updated` is a resync nudge, not a delta: an upstream that could
/// not compute a precise change (e.g. the alias wrapper on a transient
/// `list_address_roots` failure) asks consumers to re-query rather than pinning
/// a stale root set. Applying it through [`apply_root_change`] would loop zero
/// times — a silent no-op — so the drain manager routes it to a resnapshot
/// instead.
fn is_resync_nudge(change: &RootInfoChange) -> bool {
    matches!(change, RootInfoChange::Updated(roots) if roots.is_empty())
}

fn apply_root_change(roots: &mut HashMap<String, RootInfo>, change: RootInfoChange) {
    match change {
        RootInfoChange::Snapshot(snapshot) => {
            *roots = roots_by_key(snapshot);
        }
        RootInfoChange::Added(added) | RootInfoChange::Updated(added) => {
            for root in added {
                roots.insert(root_key(&root.root), root);
            }
        }
        RootInfoChange::Removed(removed) => {
            for root in removed {
                roots.remove(&root_key(&root.root));
            }
        }
    }
}

/// The live source of address-root topology changes for the drain manager.
enum UpdateSource {
    /// A backend-provided update stream is being polled.
    Live(RootInfoUpdateStream),
    /// The stream ended (clean EOF or error); resnapshot + resubscribe under
    /// bounded backoff. A `Stream` may not be polled after it yields `None`, so
    /// the exhausted stream is dropped rather than re-polled.
    Resubscribe,
    /// The backend advertises no dynamic updates; hold the reconciled drains
    /// until shutdown.
    Frozen,
}

async fn manage_cache_watch_drains(
    layer: Weak<dyn Layer>,
    inner: LayerHandle,
    shutdown: CancellationToken,
    sweep: RootSweep,
    scoped: Arc<ScopedWatchState>,
) {
    let discovery_cx = Extensions::new();
    let mut roots: HashMap<String, RootInfo> = HashMap::new();
    let mut drains: HashMap<String, RootDrain> = HashMap::new();
    let mut root_update_backoff = INITIAL_ROOT_UPDATE_BACKOFF;
    // Whether address-root discovery has ever succeeded. Governs how the
    // resubscribe loop treats a terminal (non-retryable) resnapshot error: a
    // cold start that has never succeeded gives up to TTL-only (the backend
    // cannot support discovery), whereas a backend that was live before keeps
    // retrying across a terminal blip.
    let mut discovered_once = false;
    // Debounces the resubscribe-failure log: the first failure of an episode
    // warns, subsequent identical retries drop to debug so a persistently-down
    // backend does not emit a warn every `MAX_ROOT_UPDATE_BACKOFF`.
    let mut warned_resync_failure = false;
    let initial = tokio::select! {
        _ = shutdown.cancelled() => return,
        result = inner.list_address_roots(&discovery_cx, Some(shutdown.clone())) => result,
    };
    let mut source = match initial {
        Ok((snapshot, updates)) => {
            discovered_once = true;
            roots = roots_by_key(snapshot.roots);
            reconcile_roots(
                &mut drains,
                &layer,
                roots.values().cloned().collect(),
                &shutdown,
                &sweep,
                &scoped,
            );
            updates.map_or(UpdateSource::Frozen, UpdateSource::Live)
        }
        // A `Cancelled` result here is the shutdown token firing mid-call (the
        // `select!` raced), not a discovery failure — return quietly.
        Err(error) if error.code() == ErrorCode::Cancelled => return,
        // A genuinely terminal error has no retry path, so permanent TTL-only
        // invalidation is correct. It is not necessarily an incapable backend:
        // an authorizing stack answers `PermissionDenied` when this identity
        // lacks `ListAddressRoots`, and returns a root set already filtered to
        // the roots it may see at all.
        Err(error) if !error.code().retryable() => {
            tracing::warn!(
                target: "ovstorage.notification_drain",
                %error,
                "cache watch invalidation could not discover address roots; cache stays TTL-only"
            );
            return;
        }
        // A retryable initial failure (backend/broker not ready at startup, a
        // transient network blip) must not permanently degrade to TTL-only.
        // Start with no drains and enter the `Resubscribe` backoff loop — the
        // same bounded-retry path the resnapshot uses — so discovery is retried
        // until it succeeds and drains open once a root becomes watch-capable.
        // Discovery has not yet succeeded, so the loop still gives up if a
        // later cold-start resnapshot returns a terminal error.
        Err(error) => {
            tracing::warn!(
                target: "ovstorage.notification_drain",
                %error,
                "cache watch invalidation could not discover address roots yet; degraded to TTL-only, retrying discovery under backoff"
            );
            warned_resync_failure = true;
            UpdateSource::Resubscribe
        }
    };

    loop {
        match &mut source {
            UpdateSource::Frozen => {
                // No live update stream: the backend advertises a frozen
                // topology. Hold the reconciled drains until shutdown.
                shutdown.cancelled().await;
                break;
            }
            UpdateSource::Resubscribe => {
                let delay = root_update_backoff;
                root_update_backoff = (root_update_backoff * 2).min(MAX_ROOT_UPDATE_BACKOFF);
                let slept = tokio::select! {
                    _ = shutdown.cancelled() => false,
                    _ = tokio::time::sleep(delay) => true,
                };
                if !slept {
                    break;
                }
                match inner
                    .list_address_roots(&Extensions::new(), Some(shutdown.clone()))
                    .await
                {
                    Ok((snapshot, new_updates)) => {
                        discovered_once = true;
                        warned_resync_failure = false;
                        roots = roots_by_key(snapshot.roots);
                        reconcile_roots(
                            &mut drains,
                            &layer,
                            roots.values().cloned().collect(),
                            &shutdown,
                            &sweep,
                            &scoped,
                        );
                        source = new_updates.map_or(UpdateSource::Frozen, UpdateSource::Live);
                    }
                    // `Cancelled` is the shutdown token firing during the
                    // resnapshot; the next backoff select observes it and
                    // breaks — don't log it as a failure.
                    Err(resync_error) if resync_error.code() == ErrorCode::Cancelled => {}
                    // A cold start that has never discovered roots hitting a
                    // terminal error mirrors the initial-call policy: give up
                    // to permanent TTL-only rather than retry a terminal error
                    // forever. The cause is not always an incapable backend — a
                    // `PermissionDenied` here means this identity lacks the
                    // separate `ListAddressRoots` right — but no retry changes
                    // either answer.
                    Err(resync_error) if !discovered_once && !resync_error.code().retryable() => {
                        tracing::warn!(
                            target: "ovstorage.notification_drain",
                            %resync_error,
                            "cache watch invalidation could not discover address roots; cache stays TTL-only"
                        );
                        break;
                    }
                    Err(resync_error) => {
                        // A retryable failure, or any failure after discovery
                        // has succeeded before (a backend that worked should
                        // not give up on a blip): stay in `Resubscribe` and
                        // retry after the next backoff. Warn the first failure
                        // of an episode, then debounce identical retries to
                        // debug to avoid per-backoff spam while the backend
                        // stays down.
                        let message = if discovered_once {
                            "address-root resnapshot failed; retaining current cache drains and retrying"
                        } else {
                            "cache watch invalidation waiting on address-root discovery; backend unavailable, retrying"
                        };
                        if warned_resync_failure {
                            tracing::debug!(
                                target: "ovstorage.notification_drain",
                                %resync_error,
                                "{message}"
                            );
                        } else {
                            tracing::warn!(
                                target: "ovstorage.notification_drain",
                                %resync_error,
                                "{message}"
                            );
                            warned_resync_failure = true;
                        }
                    }
                }
            }
            UpdateSource::Live(stream) => {
                let change = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    change = stream.next() => change,
                };
                match change {
                    Some(Ok(update)) => {
                        root_update_backoff = INITIAL_ROOT_UPDATE_BACKOFF;
                        if is_resync_nudge(&update) {
                            // A resync nudge (empty `Updated`) carries no delta
                            // to apply; treat it like a stream error/EOF and
                            // take the resnapshot+resubscribe recovery path so
                            // the root set re-converges instead of staying
                            // pinned to a stale view. Dropping the still-live
                            // stream is safe: the resnapshot returns a fresh
                            // snapshot and stream.
                            source = UpdateSource::Resubscribe;
                        } else {
                            apply_root_change(&mut roots, update);
                            reconcile_roots(
                                &mut drains,
                                &layer,
                                roots.values().cloned().collect(),
                                &shutdown,
                                &sweep,
                                &scoped,
                            );
                        }
                    }
                    Some(Err(error)) => {
                        tracing::warn!(
                            target: "ovstorage.notification_drain",
                            %error,
                            "address-root update stream reported an error; resnapshotting and resubscribing"
                        );
                        source = UpdateSource::Resubscribe;
                    }
                    None => {
                        tracing::debug!(
                            target: "ovstorage.notification_drain",
                            "address-root update stream ended; resnapshotting and resubscribing"
                        );
                        source = UpdateSource::Resubscribe;
                    }
                }
            }
        }
    }

    for (_, drain) in drains {
        drain.stop();
    }
}

/// Why a drain loop stopped, and whether its watch was ever live.
///
/// A root's refusal is handled inside the loop, which keeps retrying, so a root
/// drain only returns when it is terminally unwatchable or cancelled. A scope
/// drain's caller reads both fields: the kind to decide whether to record a
/// refusal, `ever_opened` to decide whether there is anything to sweep.
struct DrainExit {
    kind: DrainExitKind,
    ever_opened: bool,
}

enum DrainExitKind {
    /// Shutdown fired, or the layer went away.
    Cancelled,
    /// The open was refused with [`ErrorCode::PermissionDenied`].
    Refused,
    /// The backend says it does not do watches here at all
    /// ([`ErrorCode::Unsupported`]).
    ///
    /// Kept apart from `Terminal` because it is the only non-retryable answer
    /// that is a verdict on the BACKEND rather than on this one open. A root
    /// answering `Unsupported` tells you the scopes beneath it are futile too;
    /// a root answering `Internal` tells you a request failed.
    Unsupported,
    /// Any other non-retryable open failure.
    Terminal,
}

/// What a drain loop's prefix is, and so what a refusal and a successful open
/// mean for the rest of the system.
enum DrainRole {
    /// An address root. A refusal starts the root probing narrower scopes and
    /// the loop keeps retrying the root itself; a later success stops the
    /// probing.
    ///
    /// The generation is the advertisement this drain was started for, and
    /// every state transition below carries it. A drain is cancelled without
    /// being aborted, so it can be between its cancellation check and its state
    /// write while the manager withdraws and re-advertises the same URL — and
    /// the entry it would then write to is a different route's. Without the
    /// generation it can mark a re-created, drain-less root `Live`, which
    /// suppresses every scope beneath it with nothing able to clear it.
    Root {
        state: Arc<ScopedWatchState>,
        generation: u64,
    },
    /// A directory being probed under a refused root. The flag is the
    /// supervisor's copy of "this watch was live at some point", which decides
    /// whether retiring the scope has anything to sweep.
    ///
    /// The generation is the root advertisement this drain was started under,
    /// and it guards every write below exactly as the root role's does. A scope
    /// drain is cancelled without being aborted, so it can be between its
    /// cancellation check and its state write while the manager re-advertises
    /// the same URL, or while a nested root takes the scope over. Its late
    /// result would then deny a scope, or charge and pause the probe budget, of
    /// a route it never watched — leaving a newly watchable subtree with no
    /// invalidation and nothing to notice.
    Scope {
        signals: Arc<ScopeSignals>,
        state: Arc<ScopedWatchState>,
        root: Url,
        generation: u64,
    },
}

async fn cache_watch_drain_loop(
    layer: Weak<dyn Layer>,
    prefix: Url,
    shutdown: CancellationToken,
    sweep: RootSweep,
    role: DrainRole,
) -> DrainExit {
    let mut backoff = INITIAL_DRAIN_BACKOFF;
    let mut warned_open_failure = false;
    // Whether this drain has already charged its root for being unable to open.
    let mut charged_unavailable = false;
    let mut warned_quick_empty_end = false;
    let mut ever_opened = false;
    // A scope's drain begins in the mode its `ScopeDrain` published; a root's
    // is always recursive, since narrowing a root means narrowing the prefix.
    let mut mode = match &role {
        DrainRole::Root { .. } => WatchMode::Recursive,
        DrainRole::Scope { signals, .. } => {
            if signals.recursive.load(std::sync::atomic::Ordering::SeqCst) {
                WatchMode::Recursive
            } else {
                WatchMode::NonRecursive
            }
        }
    };
    macro_rules! exit {
        ($kind:expr) => {
            return DrainExit {
                kind: $kind,
                ever_opened,
            }
        };
    }
    loop {
        if shutdown.is_cancelled() {
            exit!(DrainExitKind::Cancelled);
        }
        // Re-ask what mode this scope should open in, rather than carrying the
        // degrade for the drain's lifetime. `starting_mode` already expires a
        // recursive-only refusal after `DENIED_SCOPE_RETRY`, and that expiry is
        // there so a reloaded policy granting the right is picked up without a
        // restart — but only a REPLACEMENT drain used to consult it, and a
        // degraded drain whose narrower watch is healthy is `worth_defending`,
        // so it is never replaced. The recursive grant stayed invisible for the
        // life of the process, and with `recursive` stuck false the scope
        // covered nothing, so every directory beneath it competed separately
        // for one of the four slots.
        //
        // Only the local `mode` is refreshed here. `signals.recursive` is the
        // width of the watch this drain most recently HELD, and it is published
        // where that becomes true — beside `live`, in the arm where an open
        // succeeded — because two selection rules read it as a claim about what
        // the watch reports. Published from the ask instead, it would say
        // "recursive" for a scope whose recursive form has only ever been
        // refused, from the moment the memo expires until the next open
        // resolves: `select_scopes` defends such a watch on traffic under it
        // that it has never reported, and the directory generating that traffic
        // competes undefended.
        //
        // A scope on its root's OWN prefix is excluded: its recursive form is
        // precisely the watch that was refused, and that rule lives in the
        // supervisor rather than in the denial memo, so `starting_mode` would
        // answer `Recursive` and re-widen it on the next reopen forever.
        if let DrainRole::Scope { state, root, .. } = &role
            && root.as_str() != prefix.as_str()
        {
            mode = state
                .scopes
                .starting_mode(&prefix, &state.memo_owner_still_owns());
        }
        let Some(layer) = layer.upgrade() else {
            exit!(DrainExitKind::Cancelled);
        };
        let mut request = Request::new(WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: WatchDirectoryOptions {
                recursive: mode.recursive(),
                include_metadata_changes: true,
                ..Default::default()
            },
        });
        request
            .extensions
            .insert(MANAGED_NOTIFICATION_DRAIN_EXTENSION, Vec::new());
        let opened = layer
            .watch_directory(request, Some(shutdown.child_token()))
            .await;
        drop(layer);
        match opened {
            Ok(stream) => {
                // The same guard the `Err` arm carries, and for the same
                // reason. `ScopeDrain::stop` cancels without aborting, and this
                // whole design is built for backends that do not observe watch
                // cancellation, so the token can fire while the open is in
                // flight and the backend still answer `Ok`. Everything below
                // writes state the supervisor has already stopped believing in:
                // it would refund the root's probe budget from an open that
                // happened after retirement — the mirror of the refusal this
                // arm is guarded against charging — and run a subtree
                // invalidation of a persistent cache for a scope that is no
                // longer selected, including one retired precisely because it
                // never opened, and including on the way down, since
                // `CacheWatchState::drop` cancels the scope drains without
                // aborting them.
                if shutdown.is_cancelled() {
                    // Dropped on the blocking pool, not here. A broker-fronted
                    // stream's `Drop` cancels and then JOINS the thread running
                    // its own Tokio runtime, and across the plugin ABI it is an
                    // arbitrary `drop_fn`. `drain_stream` is the only other
                    // place a stream is disposed of and it does so inside
                    // `spawn_blocking` for the same reason; an unreachable
                    // broker — the deployment this fallback exists for — would
                    // otherwise stall a runtime worker here, and at teardown
                    // every scope drain reaches this line at once.
                    let _ = tokio::task::spawn_blocking(move || drop(stream)).await;
                    exit!(DrainExitKind::Cancelled);
                }
                warned_open_failure = false;
                ever_opened = true;
                match &role {
                    // A root watch that opens ends any scoped probing under it:
                    // one watch covers the whole root, so the supervisor
                    // retires the narrower drains and this loop's own
                    // activation sweep takes over their subtrees. This is also
                    // how a policy reload that grants the root is picked up,
                    // since the loop keeps retrying rather than exiting on a
                    // refusal.
                    DrainRole::Root { state, generation } => {
                        state.leave_scoped_mode(&prefix, *generation)
                    }
                    DrainRole::Scope {
                        signals,
                        state,
                        root,
                        generation,
                    } => {
                        signals
                            .ever_opened
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        // The width this watch actually holds, published where
                        // it becomes true rather than where it was asked for.
                        // Both readers treat it as a claim about what the watch
                        // reports: `covers_below` collapses the subtree onto it,
                        // and the subtree half of `worth_defending` credits it
                        // with that subtree's traffic.
                        signals
                            .recursive
                            .store(mode.recursive(), std::sync::atomic::Ordering::SeqCst);
                        signals
                            .live
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        // Reported as what it is — an open was accepted —
                        // rather than pre-judged here. Whether that refunds the
                        // root's probe budget turns on the ROOT's recent barren
                        // history, which no single drain can see: a drain has no
                        // history on its first open, and drains are replaced
                        // continuously as a workload walks fresh directories.
                        state.note_scope_outcome(root, *generation, ScopeOutcome::Opened);
                        // A watch that just went live is a change only this
                        // drain can observe, and selection reads it: until the
                        // supervisor is told, this scope is not treated as
                        // covering the candidates below it and is not protected
                        // from being displaced by a newcomer.
                        notify_supervisor(&role);
                    }
                }
                // Re-arm the subtree sweep on every reopen: a cursorless
                // backend cannot prove gap-free replay across the end-to-reopen
                // window, so a mutation in that window would otherwise linger
                // until TTL.
                sweep_off_runtime(&sweep, &prefix).await;
                let started = tokio::time::Instant::now();
                let outcome = drain_stream(stream, &shutdown).await;
                if matches!(outcome.end, DrainEnd::Cancelled) || shutdown.is_cancelled() {
                    exit!(DrainExitKind::Cancelled);
                }
                // The end of the stream is the end of the watch, for both
                // roles. Neither reports anything again until its next open
                // succeeds, and the state each publishes has to say so or
                // selection acts on a watch that is not there.
                //
                // Deliberately no wake for a SCOPE, and the reason is a bound
                // rather than an absence of change. A recursive scope going
                // down does un-cover the descendants collapsed onto it —
                // `ScopeView::covers_below` is `live && recursive` — and those
                // hold no drain of their own, so this is a real second answer
                // and not only the protection one `stopped_at_millis` settles.
                //
                // It is bounded and it repairs itself. A collapsed descendant
                // is a candidate that is not selected, so `reconcile_scopes`
                // reports a deferred candidate and `supervisor_needs_timer`
                // arms `SCOPE_RECONCILE_TICK` for as long as one exists: the
                // re-selection is at most a tick away, never indefinite.
                // Whatever is cached inside the gap is then discarded either
                // way, because every reopen re-arms the activation sweep over
                // this whole prefix and retirement sweeps any descendant that
                // had opened. Nothing stale is served on either path.
                //
                // So waking here would buy reporting during the gap and pay a
                // descendant spawn, an activation sweep each, and a retirement
                // each, on EVERY reconnect of every recursive cover — more
                // sweeping of a cache with no expiry, for a window that already
                // ends in a sweep. A ROOT ending its watch is different and does
                // wake, because that changes which backend covers the scopes
                // beneath it rather than how long they wait.
                let uptime = started.elapsed();
                let stream_end = StreamEnd::of(&outcome, uptime);
                let quick_empty_end = stream_end == StreamEnd::Barren;
                // Charged on the SECOND consecutive barren end, whatever ended
                // the stream.
                //
                // Reported for BOTH ways a stream can end barren. A quick
                // empty end is the accept-and-drop shape whether the stream
                // closed cleanly or errored, and a rule that reads `DrainEnd`
                // here charges one of them and lets the other evade.
                //
                // Which of them is a verdict is the root's call, not this
                // drain's: `note_scope_outcome` charges from the second in a
                // row, so an isolated quick end — a reset, a broker blip —
                // costs nothing, while a backend that does nothing else climbs
                // to the budget.
                //
                // The residual bound is worth naming rather than arguing away:
                // a backend that flaps INDEFINITELY under
                // `MIN_STABLE_WATCH_UPTIME` reaches the pause and stops new
                // probes for the whole root, healthy scopes included. A stream
                // that runs clears both counts (`ScopeOutcome::Worked`), so
                // this needs every stream under the root to be flapping, and
                // the pause expires. It is a real bound and not one this
                // threshold removes.
                if quick_empty_end
                    && let DrainRole::Scope {
                        state,
                        root,
                        generation,
                        ..
                    } = &role
                {
                    // A run of these is a backend accepting watches without
                    // watching. One is a transient fault, so the root charges
                    // only from the second in a row — and counts them across
                    // drains, since a replacement drain is not a fresh start
                    // for the backend.
                    state.note_scope_outcome(root, *generation, ScopeOutcome::Barren);
                }
                match &role {
                    DrainRole::Root { state, generation } => {
                        state.root_watch_ended(&prefix, *generation)
                    }
                    // A watch that keeps opening and closing with nothing to
                    // show is not reporting anything, so it does not count as
                    // having worked: restamping on it would let a backend that
                    // accepts every watch and immediately drops it hold a slot
                    // for the life of the process, re-arming a subtree sweep on
                    // every cycle. Whether it dropped the stream cleanly or
                    // with an error makes no difference to that, which is why
                    // `StreamEnd` decides it rather than a test on `DrainEnd`.
                    DrainRole::Scope {
                        signals,
                        state,
                        root,
                        generation,
                    } if stream_end.worked() => {
                        signals.note_stream_ended();
                        // The only place the root learns its watches actually
                        // WORK, as opposed to being accepted. Without it
                        // `consecutive_barren` would never fall once it rose,
                        // so a root that produced two barren ends early would
                        // stop refunding on every later open however healthy
                        // its streams became — TTL-only until the pause expiry
                        // happened to reset it.
                        state.note_scope_outcome(root, *generation, ScopeOutcome::Worked);
                    }
                    DrainRole::Scope { signals, .. } => {
                        signals
                            .live
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                if quick_empty_end {
                    if !warned_quick_empty_end {
                        tracing::warn!(
                            target: "ovstorage.notification_drain",
                            prefix = %redact_url(&prefix),
                            "cache notification watch ended quickly without events; reconnecting with backoff"
                        );
                        warned_quick_empty_end = true;
                    }
                } else {
                    warned_quick_empty_end = false;
                }
                backoff = drain_backoff_after(backoff, stream_end);
            }
            Err(error) => {
                // Cancellation is not a verdict on the prefix. The `Layer`
                // contract has a method taking a `CancellationToken` answer
                // `Cancelled` when that token fires mid-flight, and `Cancelled`
                // is not retryable — so without this guard a cancelled open
                // falls through to `Terminal`, and a SCOPE drain's caller then
                // denies the directory, charges its root's probe budget, and
                // sweeps the subtree. (A root drain's caller discards the exit,
                // so only the log line changes there.)
                //
                // Only THIS drain's token ends the loop. `shutdown` is that
                // token — a child of the layer's, which `ScopeDrain::stop`
                // fires on ordinary retirement and not only at process exit —
                // and it also catches a backend that answers something other
                // than `Cancelled` in the window after the token fires.
                if shutdown.is_cancelled() {
                    exit!(DrainExitKind::Cancelled);
                }
                // A `Cancelled` the drain did not ask for — raised below it by
                // a client whose per-watch runtime is retiring, or an upstream
                // mapping its own cancellation — is not a verdict on the prefix
                // either, but it is also not a reason to stop. It is excluded
                // from the non-retryable arm below and falls to the retry arm,
                // whose doubling backoff is what bounds a condition that may
                // clear. Exiting instead would leave the supervisor to reap the
                // drain and re-select the scope with nothing between attempts,
                // so a backend answering promptly would spin: open, cancel,
                // wake, reap, spawn.
                if error.code() == ErrorCode::Unsupported {
                    tracing::info!(
                        target: "ovstorage.notification_drain",
                        prefix = %redact_url(&prefix),
                        "cache watch invalidation is unsupported for this prefix; using TTL-only invalidation"
                    );
                    exit!(DrainExitKind::Unsupported);
                }
                // Only a refusal narrows. That is a policy choice, not a fact
                // about the error: `Internal` could in principle be
                // prefix-specific too. But authorization is the mechanism that
                // is prefix-scoped by construction, so a refusal is the one
                // code where a narrower prefix has a *reason* to answer
                // differently, and the others would spend the probe budget on a
                // guess. Narrowing is not a retry and not a bypass: each
                // narrower watch is a separate read-only call the same layer
                // authorizes on its own, and its refusal is honoured.
                if error.code() == ErrorCode::PermissionDenied {
                    match &role {
                        // A refused root starts probing the directories the
                        // cache holds, and keeps retrying itself on a long
                        // interval. Exiting here instead would leave a refusal
                        // permanent for the process's life, so a policy reload
                        // granting the root would be invisible until restart —
                        // the same dead-drain shape this narrowing exists to
                        // remove.
                        DrainRole::Root { state, generation } => {
                            if !warned_open_failure {
                                tracing::info!(
                                    target: "ovstorage.notification_drain",
                                    prefix = %redact_url(&prefix),
                                    "watch on this address root was refused; watching the directories the cache holds instead"
                                );
                                warned_open_failure = true;
                            }
                            state.enter_scoped_mode(&prefix, *generation);
                            // Not the doubling backoff below: that clamps to
                            // `MAX_DRAIN_BACKOFF`, so a standing policy refusal
                            // would be re-asked every minute for the life of
                            // the process. This interval exists to notice a
                            // reload, not to recover from a blip.
                            backoff = backoff_after_open_failure(true, backoff);
                        }
                        // A refused recursive scope degrades to the smaller
                        // ask before giving up. That is this PR's own move —
                        // narrow what you ask for rather than treat a refusal
                        // as final — applied to the second axis a watch has. It
                        // is not always available: on S3, GCS, Azure and
                        // Nucleus recursion is a filter over one shared
                        // upstream, so the retry gets the same answer. It is on
                        // the file backend, whose recursive snapshot walks
                        // descendant directories a filesystem can deny, and on
                        // the Storage Service client, where recursion selects a
                        // different remote filter — and through a broker
                        // fronting either. The cache cannot tell which it is
                        // talking to, so it asks once and remembers the answer.
                        DrainRole::Scope { signals, .. }
                            if matches!(mode, WatchMode::Recursive) =>
                        {
                            tracing::debug!(
                                target: "ovstorage.notification_drain",
                                prefix = %redact_url(&prefix),
                                "recursive watch on this cached directory was refused; retrying its immediate children only"
                            );
                            // The immediate retry is skipping the backoff at the
                            // foot of the loop, and that is only sound if the
                            // next iteration really does open narrowly. It
                            // reads `starting_mode` unconditionally, so the
                            // narrowing survives only through the memo — and
                            // the memo is suppressed when this drain no longer
                            // owns the scope. Without this test the loop would
                            // re-widen, be refused again, suppress the write
                            // again and retry again with no sleep and no probe
                            // charge, at whatever rate the backend can refuse:
                            // every attempt an OS thread and its own runtime on
                            // the broker client, bounded only by the
                            // supervisor's next reconcile, which itself awaits a
                            // blocking subtree delete for each retiring drain
                            // that had opened.
                            //
                            // The recorded path still allows one sleepless
                            // retry: `starting_mode` applies the ownership test
                            // again on the read, so a nested root advertised
                            // between the write and that read re-widens once.
                            // The next pass finds the write suppressed and
                            // reaches this backoff, so it does not repeat.
                            if !state_deny_recursive(&role, &prefix) {
                                backoff = backoff_after_open_failure(false, backoff);
                            } else {
                                mode = WatchMode::NonRecursive;
                                signals
                                    .recursive
                                    .store(false, std::sync::atomic::Ordering::SeqCst);
                                // Descendants collapsed onto this scope are no
                                // longer covered by it, so the supervisor has to
                                // re-select them.
                                notify_supervisor(&role);
                                continue;
                            }
                        }
                        DrainRole::Scope { .. } => {
                            tracing::debug!(
                                target: "ovstorage.notification_drain",
                                prefix = %redact_url(&prefix),
                                "watch on this cached directory was refused in both modes; it stays TTL-only"
                            );
                            exit!(DrainExitKind::Refused);
                        }
                    }
                } else if !error.code().retryable() && error.code() != ErrorCode::Cancelled {
                    tracing::warn!(
                        target: "ovstorage.notification_drain",
                        prefix = %redact_url(&prefix),
                        %error,
                        "cache watch invalidation failed terminally for this prefix; using TTL-only invalidation"
                    );
                    exit!(DrainExitKind::Terminal);
                } else {
                    if !warned_open_failure {
                        tracing::warn!(
                            target: "ovstorage.notification_drain",
                            prefix = %redact_url(&prefix),
                            %error,
                            "cache notification watch failed to open; retrying with backoff"
                        );
                        warned_open_failure = true;
                    }
                    // Charged ONCE, on the first retryable failure of a drain
                    // that has never opened, and never for `Cancelled` — a
                    // cancellation raised below the cache is not a statement
                    // about the backend's availability, and
                    // `a_watch_open_cancelled_from_below_is_retried_not_denied`
                    // pins that it costs nothing. Retrying is not free at this layer
                    // — on the broker client every attempt is an OS thread and
                    // its own runtime — and nothing else bounds it: this drain
                    // cannot be defended (`working_recently` needs
                    // `ever_opened`), so churn displaces it, and its cancelled
                    // exit records nothing. Once per drain rather than per retry
                    // keeps an ordinary reconnect free.
                    if !charged_unavailable
                        && !ever_opened
                        && error.code() != ErrorCode::Cancelled
                        && let DrainRole::Scope {
                            state,
                            root,
                            generation,
                            ..
                        } = &role
                    {
                        charged_unavailable = true;
                        state.note_scope_outcome(root, *generation, ScopeOutcome::OpenUnavailable);
                    }
                    backoff = backoff_after_open_failure(false, backoff);
                }
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => exit!(DrainExitKind::Cancelled),
            _ = tokio::time::sleep(backoff) => {}
        }
    }
}

async fn drain_stream(stream: ChangeStream, shutdown: &CancellationToken) -> DrainOutcome {
    let shutdown = shutdown.clone();
    tokio::task::spawn_blocking(move || {
        let mut events = 0usize;
        let mut stream = stream;
        loop {
            if shutdown.is_cancelled() {
                return DrainOutcome {
                    events,
                    end: DrainEnd::Cancelled,
                };
            }
            match stream.next() {
                Some(Ok(_)) => events += 1,
                Some(Err(_)) => {
                    return DrainOutcome {
                        events,
                        end: DrainEnd::Error,
                    };
                }
                None if shutdown.is_cancelled() => {
                    return DrainOutcome {
                        events,
                        end: DrainEnd::Cancelled,
                    };
                }
                None => {
                    return DrainOutcome {
                        events,
                        end: DrainEnd::Clean,
                    };
                }
            }
        }
    })
    .await
    .unwrap_or(DrainOutcome {
        events: 0,
        end: DrainEnd::Error,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainEnd {
    Clean,
    Error,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DrainOutcome {
    events: usize,
    end: DrainEnd,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;

    /// A backend whose initial `list_address_roots` records the cancel token it
    /// receives and then parks forever, ignoring cancellation. It never returns
    /// on its own, so the only way the drain manager can leave the initial
    /// discovery call is its own `select!`-vs-shutdown arm.
    struct ParkingDiscoveryLayer {
        calls: Arc<AtomicUsize>,
        passed_token: Mutex<Option<CancellationToken>>,
    }

    #[async_trait]
    impl Layer for ParkingDiscoveryLayer {
        fn name(&self) -> &str {
            "parking-discovery"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            crate::layers::descriptor("parking-discovery", LayerType::Backend, true)
        }

        async fn list_address_roots(
            &self,
            _cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.passed_token.lock().unwrap() = cancel;
            // Ignore the token and park: only the manager's shutdown `select!`
            // arm can end the wait.
            std::future::pending::<()>().await;
            unreachable!("parked discovery never resolves on its own")
        }
    }

    /// Guards the initial-discovery `select!`-vs-shutdown arm AND the
    /// `Some(shutdown.clone())` cancel token handed to the discovery call. The
    /// backend parks forever ignoring cancellation, so the manager can only
    /// escape via its own shutdown arm — observed through the manager task's
    /// completion, NOT `CacheWatchState::drop`, which aborts the task and would
    /// mask a missing arm. The recorded token proves the shutdown token reaches
    /// the call: dropping the arm hangs the manager here, and passing `None`
    /// leaves the recorded token unset/uncancelled.
    #[tokio::test]
    async fn shutdown_during_initial_discovery_is_prompt_and_passes_the_shutdown_token() {
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(ParkingDiscoveryLayer {
            calls: calls.clone(),
            passed_token: Mutex::new(None),
        });
        let layer: Arc<dyn Layer> = backend.clone();
        let inner: LayerHandle = backend.clone();
        let sweeps = Arc::new(AtomicUsize::new(0));
        let sweeps_seen = sweeps.clone();
        let sweep: RootSweep = Arc::new(move |_: &Url| {
            sweeps_seen.fetch_add(1, Ordering::SeqCst);
        });
        let shutdown = CancellationToken::new();
        let manager = tokio::spawn(manage_cache_watch_drains(
            Arc::downgrade(&layer),
            inner,
            shutdown.clone(),
            sweep,
            Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true)))),
        ));

        // Wait until the initial discovery call is genuinely in flight
        // (parked).
        for _ in 0..500 {
            if calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the manager must call initial discovery exactly once"
        );
        assert!(
            !manager.is_finished(),
            "the manager must stay in the initial discovery call while it is unresolved"
        );
        assert!(
            backend.passed_token.lock().unwrap().is_some(),
            "initial discovery must receive Some(shutdown) cancel token, not None"
        );

        shutdown.cancel();

        // The manager must return promptly on shutdown even though the
        // discovery call never returns on its own. A missing shutdown arm hangs
        // here.
        tokio::time::timeout(Duration::from_secs(2), manager)
            .await
            .expect("manager must return promptly when shutdown races initial discovery")
            .expect("manager task must not panic");

        assert!(
            backend
                .passed_token
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_cancelled(),
            "the token handed to discovery must be the shutdown token (cancelled with it)"
        );
        assert_eq!(
            sweeps.load(Ordering::SeqCst),
            0,
            "no drain opens or sweep runs when shutdown races the initial discovery"
        );
    }

    /// A `can_cover` that permits every candidate to cover, for the tests whose
    /// subject is the selection rules rather than the degraded-cover exception.
    fn covers_all() -> impl Fn(&SelectedScope) -> bool {
        |_: &SelectedScope| true
    }

    /// A minimal advertised root, watch-capable unless the caller says
    /// otherwise.
    fn root_info(prefix: &str) -> RootInfo {
        RootInfo {
            root: url(prefix),
            display_name: None,
            layer_kind: "probe".to_string(),
            connection_id: None,
            owning_target: None,
            capabilities: Capabilities::empty(),
            range_read_strategy: Default::default(),
            source: RouteSource::Static {
                layer: ovstorage_layer::ConfigLayer::Programmatic,
            },
            visible: true,
            visibility: Default::default(),
            alias_state: None,
            icon: None,
            user_metadata: Default::default(),
        }
    }

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    /// Protected scopes as selection takes them: keyed by the advertisement the
    /// protecting drain was opened under, which `probing_views` numbers 0.
    fn protected_under(root: &str, keys: &[String]) -> Vec<(String, Url, u64)> {
        keys.iter()
            .map(|key| (key.clone(), url(root), 0u64))
            .collect()
    }

    fn scope_urls(selected: &[SelectedScope]) -> Vec<String> {
        selected
            .iter()
            .map(|entry| entry.scope.as_str().to_string())
            .collect()
    }

    /// [`select_scopes`] with no scope holding a live watch on a directory that
    /// is still being read — the state every rule other than the budget's
    /// anti-thrash ordering is stated over. Protection is exercised by the
    /// tests that name it.
    fn select_unprotected(
        roots: &[RootView],
        candidates: &[Url],
        budget: usize,
        can_cover: &dyn Fn(&SelectedScope) -> bool,
        running: &[(String, Url, u64)],
    ) -> Assignment {
        select_scopes(
            roots,
            candidates,
            budget,
            can_cover,
            &|_| true,
            running,
            &[],
        )
    }

    /// The live generation for a root, so a test spawning a drain by hand does
    /// not have to spell one and cannot accidentally spell a stale one.
    #[cfg(test)]
    fn current_generation(state: &ScopedWatchState, root: &str) -> u64 {
        state
            .roots
            .lock()
            .ok()
            .and_then(|roots| {
                roots
                    .get(&root_key(&url(root)))
                    .map(|record| record.generation)
            })
            .expect("the root must be advertised before a drain is spawned for it")
    }

    /// The scope unit itself, including the shape that produces none.
    #[test]
    fn a_scope_is_the_directory_holding_the_entry() {
        assert_eq!(
            scope_of(&url("mem:///a/b/obj")).map(|s| s.to_string()),
            Some("mem:///a/b/".to_string())
        );
        // A directory-form address (a `list` prefix) is its own scope.
        assert_eq!(
            scope_of(&url("mem:///a/b/")).map(|s| s.to_string()),
            Some("mem:///a/b/".to_string())
        );
        // An object at the top level of a root derives the root itself. There
        // is no narrower prefix; the design must not pretend otherwise.
        assert_eq!(
            scope_of(&url("mem:///obj")).map(|s| s.to_string()),
            Some("mem:///".to_string())
        );
        // A fragment-bearing OBJECT address has no watchable directory:
        // TTL-only. A directory-form one keeps its scope with the fragment and
        // query dropped, which is the spelling every other scope uses.
        assert_eq!(scope_of(&url("mem:///a/obj#v2")), None);
        assert_eq!(
            scope_of(&url("mem:///a/b/?v=2#f")).map(|s| s.to_string()),
            Some("mem:///a/b/".to_string())
        );
    }

    /// An address carrying credentials names no scope, in either form.
    ///
    /// A scope outlives the request that produced it by design — it is a key in
    /// the registry and in the denial memo, and it is the prefix a drain re-opens
    /// on every reconnect for the life of the process. Neither `scope_of` nor
    /// `address::parent_and_name` drops userinfo, so admitting one of these would
    /// park a caller's password in exactly those structures, none of which is
    /// redacted the way a log line is.
    ///
    /// Both forms, and both halves of the userinfo, because they are separately
    /// reachable: a password-less `user@host` is still a credential, and the
    /// object form derives its scope through a different helper.
    #[test]
    fn an_address_carrying_credentials_names_no_scope() {
        assert_eq!(scope_of(&url("mem://user:secret@host/a/b/")), None);
        assert_eq!(scope_of(&url("mem://user:secret@host/a/b/obj")), None);
        assert_eq!(scope_of(&url("mem://user@host/a/b/")), None);
        assert_eq!(scope_of(&url("mem://user@host/a/b/obj")), None);
        // The control: the same authority without userinfo is watchable, so the
        // rule above is about the credentials and not about the host form.
        assert_eq!(
            scope_of(&url("mem://host/a/b/obj")).map(|s| s.to_string()),
            Some("mem://host/a/b/".to_string())
        );
    }

    /// The registry itself refuses it, not merely the helper.
    ///
    /// `note_cached` is the only way a scope is admitted, and a predicate being
    /// right says nothing about the call site consulting it.
    #[test]
    fn a_credentialed_read_registers_no_candidate() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem://user:secret@host/a/b/obj"));
        scopes.note_cached(&url("mem://user:secret@host/a/b/"));
        assert!(
            scopes.candidates(&any_owner).is_empty(),
            "a credentialed address must leave nothing in the registry, whose \
             keys outlive the request and are not redacted"
        );
        // The control, so this cannot pass by registering nothing at all.
        scopes.note_cached(&url("mem://host/a/b/obj"));
        assert_eq!(
            scopes
                .candidates(&any_owner)
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            vec!["mem://host/a/b/".to_string()]
        );
    }

    /// Advertised roots that were all refused and are all still probing — the
    /// arrangement most of the selection rules are about. A test that needs a
    /// granted or paused root builds its `RootView`s directly.
    /// A drain whose watch is open and recursive on `root` — the state
    /// `covers_below` needs, so `scope_views` will ask the subtree question.
    #[cfg(test)]
    fn covering_drain_for(root: &Url, generation: u64) -> ScopeDrain {
        ScopeDrain {
            cancel: CancellationToken::new(),
            handle: tokio::spawn(std::future::pending::<()>()),
            signals: Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(true),
                live: std::sync::atomic::AtomicBool::new(true),
                recursive: std::sync::atomic::AtomicBool::new(true),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            }),
            root: root.clone(),
            generation,
        }
    }

    /// Memo reads in tests that are not modelling a stale route: every memo is
    /// treated as its owner's.
    fn any_owner(_root: &Url, _generation: u64, _scope: &Url) -> bool {
        true
    }

    /// Longest first, because `root_views` is and `select_scopes` relies on it:
    /// assignment takes the FIRST matching view, which is the router's
    /// longest-prefix dispatch only if the order says so. Unsorted, this
    /// fixture assigned a scope under a nested root to the outer one and no
    /// test could see the difference.
    fn probing_views(roots: &[Url]) -> Vec<RootView> {
        let mut views: Vec<RootView> = roots
            .iter()
            .map(|root| RootView {
                root: root.clone(),
                generation: 0,
                covers: false,
                admits_probes: true,
            })
            .collect();
        views.sort_by(|a, b| {
            ovstorage_layer::node_rank(&b.root)
                .cmp(&ovstorage_layer::node_rank(&a.root))
                .then_with(|| {
                    ovstorage_layer::node_key(&a.root).cmp(&ovstorage_layer::node_key(&b.root))
                })
        });
        views
    }

    /// Collapsing a scope onto a broader one is a claim that the broader watch
    /// reports its events, and across two routes that claim is false.
    ///
    /// `watch_directory` is dispatched by `RouteTable::lookup` on the prefix it
    /// names, so a recursive watch on `mem:///a/` opens against the route that
    /// owns `mem:///a/` — the outer root — while reads of `mem:///a/b/c/x` are
    /// served by the nested root. Dropping the inner scope would leave its
    /// entries invalidated by nothing at all, which is the silent staleness
    /// this whole fallback exists to remove. Both candidates are covering here
    /// (`covers_all`), so only the root comparison can keep the inner one.
    #[test]
    fn a_cover_on_another_route_does_not_collapse_the_scope_below_it() {
        // Longest-prefix-first, as `root_views` supplies them.
        let roots = probing_views(&[url("mem:///a/b/"), url("mem:///")]);
        let candidates = vec![url("mem:///a/"), url("mem:///a/b/c/")];
        let mut got = scope_urls(&select_unprotected(
            &roots,
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        ));
        got.sort();
        assert_eq!(
            got,
            vec!["mem:///a/".to_string(), "mem:///a/b/c/".to_string()],
            "a scope the nested root routes keeps its own watch: the ancestor's \
             watch is open against the outer route and reports nothing about it"
        );

        // The control, and the rule this must not break: with one root, both
        // candidates are on the same route, and there the ancestor's recursive
        // watch really does serve the descendant.
        assert_eq!(
            scope_urls(&select_unprotected(
                &probing_views(&[url("mem:///")]),
                &candidates,
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )),
            vec!["mem:///a/".to_string()],
            "control: on one route the antichain still collapses the subtree"
        );
    }

    /// The extra slot above the budget is a consolidation, so it too is per
    /// root: a candidate above a protected scope on another route subsumes
    /// nothing, and granting it the overshoot spends the layer's one spare
    /// watch on a consolidation that can never happen. Two rules are being
    /// separated here. The cover partition decides WHETHER a candidate is a
    /// cover at all, and `subsumed` decides WHICH cover wins when there is more
    /// than one. Both compare prefixes, and both would otherwise count a
    /// protected scope on a different route.
    #[test]
    fn a_candidate_above_another_route_is_not_a_cover() {
        // A nested root sits strictly between the two candidates, which is what
        // makes them route differently: `mem:///a/b/c/` is assigned to
        // `mem:///a/b/`, and `mem:///a/` — above that root — to `mem:///`.
        let candidates = [url("mem:///a/b/c/"), url("mem:///a/")];
        let protected: Vec<String> = vec!["mem:///a/b/c/".to_string()];
        // No candidate covers anything yet: the cover's own watch has not
        // opened, which is precisely the state the extra slot exists for. So
        // the antichain leaves both, and only the partition decides.
        let never = |_: &SelectedScope| false;
        let selected = select_scopes(
            &probing_views(&[url("mem:///a/b/"), url("mem:///")]),
            &candidates,
            1,
            &never,
            &|_| true,
            &[],
            &protected_under("mem:///a/b/", &protected),
        );
        assert_eq!(
            scope_urls(&selected),
            vec!["mem:///a/b/c/".to_string()],
            "a candidate that routes elsewhere subsumes nothing, so it does not \
             earn the slot above the budget; it competes like any newcomer and \
             the protected scope keeps the one watch on offer"
        );
        // And it lost to the budget rather than never being admissible: with
        // room for two it is selected. Without this the assertion above would
        // also pass if the ancestor had been dropped at assignment.
        let mut affordable = scope_urls(&select_scopes(
            &probing_views(&[url("mem:///a/b/"), url("mem:///")]),
            &candidates,
            2,
            &never,
            &|_| true,
            &[],
            &protected_under("mem:///a/b/", &protected),
        ));
        affordable.sort();
        assert_eq!(
            affordable,
            vec!["mem:///a/".to_string(), "mem:///a/b/c/".to_string()],
            "both are admissible candidates; the one above is simply not a cover"
        );

        // The control: the same two candidates on ONE route, where the ancestor
        // really would consolidate the descendant, do get the extra slot. That
        // is the rule this must not break — deferring a genuine cover
        // deadlocks.
        let mut both = scope_urls(&select_scopes(
            &probing_views(&[url("mem:///")]),
            &candidates,
            1,
            &never,
            &|_| true,
            &[],
            &protected_under("mem:///", &protected),
        ));
        both.sort();
        assert_eq!(
            both,
            vec!["mem:///a/".to_string(), "mem:///a/b/c/".to_string()],
            "control: on one route the cover is granted the slot above the \
             budget rather than displacing what it subsumes"
        );
    }

    /// A generation names one advertisement of one root, which is what lets
    /// `running_here` compare generations without comparing roots.
    ///
    /// Two halves, and they are covered differently. NON-REUSE — a rebind must
    /// not be handed back the number it released — is what the reconcile tests
    /// that withdraw and re-advertise already depend on, and they redden if it
    /// breaks. UNIQUENESS across live roots is what nothing else covers: the
    /// selection fixtures hand every root generation 0, so a scheme that
    /// collided would go unnoticed there. This asserts both, the second as a
    /// two-root sample rather than a proof, which a monotone counter earns.
    #[test]
    fn a_generation_names_one_advertisement_of_one_root() {
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&url("mem:///a/"));
        state.advertise(&url("mem:///b/"));
        let generations: Vec<u64> = state.root_views().iter().map(|v| v.generation).collect();
        assert_eq!(
            generations
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            2,
            "two roots must not share a generation, got {generations:?}"
        );

        // Re-advertising a root that is already known keeps its generation: it
        // is the same route, and bumping it here would retire every drain
        // beneath it on a call the drain manager makes whenever it reconciles.
        let before = state.root_views();
        state.advertise(&url("mem:///a/"));
        let after = state.root_views();
        assert_eq!(
            before.iter().map(|v| v.generation).collect::<Vec<_>>(),
            after.iter().map(|v| v.generation).collect::<Vec<_>>(),
            "a repeated advertisement is not a new advertisement"
        );

        // A withdrawal and a fresh advertisement IS one, and must not reuse the
        // generation it released — that number is what a drain from the old
        // route is matched against.
        let released = after
            .iter()
            .find(|v| v.root.as_str() == "mem:///a/")
            .expect("a/ is advertised")
            .generation;
        state.withdraw(&url("mem:///a/"));
        state.advertise(&url("mem:///a/"));
        let reissued = state
            .root_views()
            .into_iter()
            .find(|v| v.root.as_str() == "mem:///a/")
            .expect("a/ is advertised again")
            .generation;
        assert_ne!(
            reissued, released,
            "a rebind must be distinguishable from the advertisement it replaced"
        );
    }

    /// Protection is a claim about a watch on a ROUTE too: a drain opened under
    /// an advertisement that no longer owns the scope defends nothing.
    ///
    /// Scarcity is the one question that reads the drain's own liveness, which
    /// makes it the easy one to key on a URL and leave there. It cannot be. A
    /// drain on a rebound route is retired in the same pass however well it is
    /// working, so honouring its protection spends the budget defending a scope
    /// whose watch is about to be cancelled — over a scope somewhere else whose
    /// watch is open and staying open. It also feeds the extra slot above the
    /// budget, which is granted for subsuming a protected scope.
    #[test]
    fn protection_does_not_survive_the_advertisement_that_earned_it() {
        let roots = vec![RootView {
            root: url("mem:///"),
            generation: 1,
            covers: false,
            admits_probes: true,
        }];
        // Recency puts the newcomer first, so only protection can save `old`.
        let candidates = [url("mem:///hot/"), url("mem:///old/")];
        let stale = vec![("mem:///old/".to_string(), url("mem:///"), 0u64)];
        assert_eq!(
            scope_urls(&select_scopes(
                &roots,
                &candidates,
                1,
                &covers_all(),
                &|_| true,
                &[],
                &stale
            )),
            vec!["mem:///hot/".to_string()],
            "a watch from the previous advertisement is being retired this pass, \
             so it must not hold the budget against a directory that could be \
             watched"
        );

        // The control: the same protection, earned under the advertisement that
        // currently owns the scope, does keep the slot.
        let current = vec![("mem:///old/".to_string(), url("mem:///"), 1u64)];
        assert_eq!(
            scope_urls(&select_scopes(
                &roots,
                &candidates,
                1,
                &covers_all(),
                &|_| true,
                &[],
                &current
            )),
            vec!["mem:///old/".to_string()],
            "control: a live watch on a directory still being read keeps its \
             slot however hot the newcomer"
        );
    }

    /// Coverage is a claim about a watch on a ROUTE, so a drain opened under an
    /// advertisement that no longer owns the scope covers nothing.
    ///
    /// Such a drain is retired in this same pass — its own root and generation
    /// no longer match what selection asks for — and a watch about to be
    /// cancelled reports nothing after it. Believing it would collapse the
    /// descendants onto a stream that is going away: they would be dropped from
    /// selection, retired, and swept, while the thing they were collapsed onto
    /// was being cancelled alongside them.
    ///
    /// Driven through `reconcile_scopes` rather than `select_scopes`, because
    /// the claim is about how the supervisor DERIVES `can_cover` from the
    /// drains it holds. A hand-written `can_cover` tests the contract and not
    /// the derivation, and the derivation is where the identity comparison
    /// lives.
    #[tokio::test]
    async fn a_cover_opened_under_a_stale_advertisement_covers_nothing() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = one_scope_under_a_refused_root("mem:///a/b/obj");
        scoped.note_cached(&url("mem:///a/"));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(drains.len(), 2, "both directories start with a watch");
        let ancestor = &drains["mem:///a/"].signals;
        ancestor.ever_opened.store(true, Ordering::SeqCst);
        ancestor.live.store(true, Ordering::SeqCst);

        // A route rebind: same URL, new advertisement. Every drain here is now
        // bound to a connection that is gone, including the covering one.
        scoped.withdraw(&url("mem:///"));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let mut held: Vec<&String> = drains.keys().collect();
        held.sort();
        assert_eq!(
            held,
            vec!["mem:///a/", "mem:///a/b/"],
            "the descendant must be reopened against the new advertisement: the \
             only thing that could have covered it was bound to the old one and \
             was cancelled in this same pass"
        );
        assert_eq!(
            *swept.lock().unwrap(),
            vec!["mem:///a/".to_string()],
            "and the watch that WAS open on the old route sweeps what it had \
             been keeping fresh; the descendant never opened, so it has nothing \
             to invalidate"
        );

        // The control: with the advertisement unchanged, the very same live
        // recursive drain does collapse the descendant — so the assertion above
        // is about the rebind and not about coverage never applying.
        drains["mem:///a/"]
            .signals
            .ever_opened
            .store(true, Ordering::SeqCst);
        drains["mem:///a/"]
            .signals
            .live
            .store(true, Ordering::SeqCst);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.keys().collect::<Vec<_>>(),
            vec!["mem:///a/"],
            "control: a cover on the current advertisement collapses the subtree"
        );
        shutdown.cancel();
    }

    /// A root whose backend cannot watch is still advertised to the supervisor,
    /// because ASSIGNMENT has to mirror the router and the router does not
    /// consult capabilities.
    ///
    /// `RouteTable::lookup` dispatches `watch_directory` by longest prefix over
    /// every route, capable or not. Leaving an incapable root out of the map
    /// does not make its scopes unwatched — it makes them match the
    /// watch-capable ancestor, so the watch is opened on a prefix the router
    /// hands to the incapable backend, which refuses it, and the refusal is
    /// charged to the ANCESTOR's probe budget. Eight such directories pause the
    /// ancestor for `DENIED_SCOPE_RETRY`, so directories elsewhere under it
    /// that the deployment would happily watch get nothing; a workload walking
    /// fresh directories under the incapable root re-spends the budget and
    /// re-pauses it indefinitely. Advertised, it answers no to both of
    /// selection's questions — the answer `RootWatch::Pending` already gives,
    /// which is why no capability flag is stored — and its scopes stay
    /// TTL-only. That is what this file already does for the dynamic form of
    /// the same thing: a root whose watch ends `Unsupported` stays
    /// absorbing-`Pending` rather than paying the probe budget to rediscover
    /// it.
    #[tokio::test]
    async fn a_root_that_cannot_watch_is_still_advertised() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();

        let mut capable = root_info("mem:///");
        capable.capabilities.supports_watch_directory = true;
        let mut incapable = root_info("mem:///team/");
        incapable.capabilities.supports_watch_directory = false;

        reconcile_roots(
            &mut drains,
            &weak,
            vec![capable, incapable],
            &shutdown,
            &sweep,
            &scoped,
        );

        assert_eq!(
            drains.keys().collect::<Vec<_>>(),
            vec!["mem:///"],
            "only a watch-capable root gets a drain: there is nothing to attempt \
             against a backend that says it cannot watch"
        );
        let views = scoped.root_views();
        let mut advertised: Vec<&str> = views.iter().map(|v| v.root.as_str()).collect();
        advertised.sort();
        assert_eq!(
            advertised,
            vec!["mem:///", "mem:///team/"],
            "but BOTH are advertised, or a scope the incapable root routes is \
             assigned to the capable one above it"
        );
        let nested = views
            .iter()
            .find(|v| v.root.as_str() == "mem:///team/")
            .expect("advertised above");
        assert!(
            !nested.covers && !nested.admits_probes,
            "and it neither reports its subtree nor accepts a probe"
        );

        // The consequence selection draws: with the outer root probing, a
        // directory the nested root routes is not probed under the outer one.
        scoped.refuse(&url("mem:///"));
        assert!(
            select_unprotected(
                &scoped.root_views(),
                &[url("mem:///team/proj/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )
            .is_empty(),
            "a scope the incapable root routes must not spend the capable \
             root's probe budget"
        );
        // The control: a directory the capable root really does route is.
        assert_eq!(
            scope_urls(&select_unprotected(
                &scoped.root_views(),
                &[url("mem:///other/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )),
            vec!["mem:///other/".to_string()],
            "control: and one it does route still is"
        );
        shutdown.cancel();
    }

    /// A degraded scope re-asks for the recursive watch once the refusal
    /// expires, without needing to be replaced.
    ///
    /// `DENIED_SCOPE_RETRY` exists so a reloaded policy granting the right is
    /// picked up without a restart. Only a REPLACEMENT drain used to consult it,
    /// and a degraded drain whose narrower watch is healthy is `worth_defending`
    /// — so it is never replaced, and the grant stayed invisible for the life of
    /// the process. Worse, `recursive` stayed false, so the scope covered
    /// nothing and every directory beneath it competed separately for one of the
    /// four slots.
    ///
    /// The scope on its root's own prefix is the exception, and it is not in the
    /// memo: that rule lives in the supervisor, so re-reading the memo would
    /// answer `Recursive` and re-widen it on every reopen.
    ///
    /// **This MIRRORS the loop's refresh rather than driving it.** The loop can
    /// only be reached through a real drain against a real backend, and no test
    /// harness here can hold one across a `DENIED_SCOPE_RETRY` boundary. So
    /// this pins the decision and the republished signal; that the loop
    /// performs it at the top of each iteration is not covered.
    #[tokio::test(start_paused = true)]
    async fn a_degraded_scope_re_asks_for_recursion_when_the_refusal_expires() {
        let scopes = Arc::new(WatchScopes::new(true));
        let scoped = Arc::new(ScopedWatchState::new(Arc::clone(&scopes)));
        let scope = url("mem:///a/");
        scopes.deny(&scope, WatchMode::Recursive, &url("mem:///"), 0);
        assert_eq!(
            scopes.starting_mode(&scope, &any_owner),
            WatchMode::NonRecursive
        );

        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(false),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
        });
        let role = DrainRole::Scope {
            signals: Arc::clone(&signals),
            state: Arc::clone(&scoped),
            root: url("mem:///"),
            generation: 0,
        };

        // What the loop does at the top of each iteration, for a scope that is
        // not its root's own prefix.
        let refresh = |role: &DrainRole, prefix: &Url| -> WatchMode {
            if let DrainRole::Scope {
                signals,
                state,
                root,
                ..
            } = role
                && root.as_str() != prefix.as_str()
            {
                let mode = state.scopes.starting_mode(prefix, &any_owner);
                signals.recursive.store(mode.recursive(), Ordering::SeqCst);
                return mode;
            }
            WatchMode::NonRecursive
        };

        assert_eq!(refresh(&role, &scope), WatchMode::NonRecursive);
        assert!(
            !signals.recursive.load(Ordering::SeqCst),
            "inside the retry window it keeps asking for the smaller watch"
        );

        tokio::time::advance(DENIED_SCOPE_RETRY + Duration::from_secs(1)).await;
        assert_eq!(refresh(&role, &scope), WatchMode::Recursive);
        assert!(
            signals.recursive.load(Ordering::SeqCst),
            "and once the refusal expires it re-asks, and publishes that it \
             covers its subtree again"
        );

        // The exception: a scope equal to its root's prefix has no memo, so the
        // memo must not be consulted for it.
        let root_scope = url("mem:///");
        let root_role = DrainRole::Scope {
            generation: 0,
            signals: Arc::clone(&signals),
            state: Arc::clone(&scoped),
            root: root_scope.clone(),
        };
        signals.recursive.store(false, Ordering::SeqCst);
        assert_eq!(refresh(&root_role, &root_scope), WatchMode::NonRecursive);
        assert!(
            !signals.recursive.load(Ordering::SeqCst),
            "the root's own prefix stays narrow: its recursive form is exactly \
             the watch that was refused"
        );
    }

    /// Descendant traffic on a NESTED route does not defend an outer
    /// ancestor's watch.
    ///
    /// The mode half of this rule asks whether the ancestor's watch is
    /// recursive; this is the route half. A recursive `watch_directory` is
    /// dispatched to the route owning the prefix it names, so an ancestor on an
    /// outer root never reports a subtree a nested root has taken over — reads
    /// there reach a different backend. Counting that traffic would pin the
    /// outer watch indefinitely while the directory generating it went
    /// unwatched.
    #[test]
    fn traffic_under_a_nested_route_does_not_defend_the_outer_watch() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///a/obj"));
        scopes.note_cached(&url("mem:///a/inner/obj"));
        {
            let mut table = scopes.table.lock().unwrap();
            table
                .scopes
                .get_mut("mem:///a/")
                .expect("a candidate")
                .direct_touch -= MIN_WATCH_RESIDENCY * 2;
        }

        // One route: the ancestor owns the subtree and is defended by it.
        let outer_only = probing_views(&[url("mem:///")]);
        assert!(
            scopes.subtree_touched_within(&url("mem:///a/"), MIN_WATCH_RESIDENCY, &|d| {
                longest_root(&outer_only, d) == Some(&url("mem:///"))
            }),
            "control: with one route the ancestor does report the subtree"
        );

        // A nested root is advertised over the busy descendant. The outer
        // ancestor's watch no longer reaches it.
        let nested = probing_views(&[url("mem:///"), url("mem:///a/inner/")]);
        assert!(
            !scopes.subtree_touched_within(&url("mem:///a/"), MIN_WATCH_RESIDENCY, &|d| {
                longest_root(&nested, d) == Some(&url("mem:///"))
            }),
            "traffic dispatched to a nested backend must not defend a watch \
             that cannot report it"
        );
    }

    /// The same rule through `scope_views`, because the predicate being right
    /// says nothing about the supervisor supplying it.
    ///
    /// `scope_views` is where `same_route` is actually built; a test that hands
    /// `subtree_touched_within` its own closure stays green if that wiring is
    /// deleted.
    #[tokio::test]
    async fn scope_views_supplies_the_route_filter() {
        let scopes = Arc::new(WatchScopes::new(true));
        scopes.note_cached(&url("mem:///a/obj"));
        scopes.note_cached(&url("mem:///a/inner/obj"));
        {
            let mut table = scopes.table.lock().unwrap();
            table
                .scopes
                .get_mut("mem:///a/")
                .expect("a candidate")
                .direct_touch -= MIN_WATCH_RESIDENCY * 2;
        }
        let mut drains = HashMap::new();
        drains.insert(
            "mem:///a/".to_string(),
            covering_drain_for(&url("mem:///"), 0),
        );

        let outer = probing_views(&[url("mem:///")]);
        assert!(
            scope_views(&drains, &scopes, &outer)
                .iter()
                .any(|view| view.key == "mem:///a/" && view.worth_defending),
            "control: with one route the supervisor lets the subtree defend it"
        );

        let nested = probing_views(&[url("mem:///"), url("mem:///a/inner/")]);
        assert!(
            !scope_views(&drains, &scopes, &nested)
                .iter()
                .any(|view| view.key == "mem:///a/" && view.worth_defending),
            "and once a nested root owns the busy descendant, the supervisor \
             must stop counting it"
        );
    }

    /// A candidate that cannot open recursively is not a cover.
    ///
    /// The extra slot exists for a consolidation — a broader candidate whose
    /// RECURSIVE watch subsumes the scopes beneath it and collapses them onto
    /// it the moment it opens. A scope equal to its root's own prefix is always
    /// spawned `NonRecursive`, so it can never do that: granted the slot it
    /// opens, covers nothing, and then becomes protected by its own reads, so
    /// the next truncation has more protected scopes than budget and evicts a
    /// descendant that is actively read — sweeping it, with no TTL under it —
    /// the byte cache has none and no watch left to invalidate it.
    #[test]
    fn a_scope_that_cannot_go_recursive_does_not_take_the_cover_slot() {
        let never = |_: &SelectedScope| false;
        // The root's own prefix, above two protected descendants, with the
        // budget entirely spent on them.
        let candidates = [url("mem:///a/"), url("mem:///b/"), url("mem:///")];
        let protected = vec!["mem:///a/".to_string(), "mem:///b/".to_string()];
        let selected = select_scopes(
            &probing_views(&[url("mem:///")]),
            &candidates,
            2,
            &never,
            &|_| true,
            &[],
            &protected_under("mem:///", &protected),
        );
        assert!(
            !selected.iter().any(|e| e.scope.as_str() == "mem:///"),
            "the root prefix opens NonRecursive, so it subsumes nothing and \
             must not take the overshoot slot, got {:?}",
            selected
                .iter()
                .map(|e| e.scope.as_str())
                .collect::<Vec<_>>()
        );

        // Same shape, but the ancestor is a normal directory that CAN attempt a
        // recursive watch — the control, and the case the slot exists for.
        let candidates = [url("mem:///p/a/"), url("mem:///p/b/"), url("mem:///p/")];
        let protected = vec!["mem:///p/a/".to_string(), "mem:///p/b/".to_string()];
        let selected = select_scopes(
            &probing_views(&[url("mem:///")]),
            &candidates,
            2,
            &never,
            &|_| true,
            &[],
            &protected_under("mem:///", &protected),
        );
        assert!(
            selected.iter().any(|e| e.scope.as_str() == "mem:///p/"),
            "control: a genuine consolidation still gets the extra slot"
        );

        // And an unexpired RECURSIVE refusal disqualifies the same candidate,
        // because `starting_mode` would open it non-recursively too.
        let selected = select_scopes(
            &probing_views(&[url("mem:///")]),
            &candidates,
            2,
            &never,
            &|scope: &Url| scope.as_str() != "mem:///p/",
            &[],
            &protected_under("mem:///", &protected),
        );
        assert!(
            !selected.iter().any(|e| e.scope.as_str() == "mem:///p/"),
            "a scope with an unexpired recursive refusal cannot consolidate \
             either"
        );
    }

    /// A watch that reports nothing about a subtree is not defended by that
    /// subtree's traffic.
    ///
    /// The scope on its root's own prefix is always opened `NonRecursive`, so
    /// it reports the root's immediate children and nothing else — yet every
    /// cached read anywhere under the root passes through it as an ancestor.
    /// Defending it on that traffic reserves a slot against reads it cannot
    /// see, while the directory generating them goes unwatched with no TTL
    /// under them: the byte cache has none. The control is the same shape with
    /// a recursive watch, which does report the subtree and is defended by it.
    #[tokio::test]
    async fn a_watch_is_defended_only_by_traffic_it_can_report() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        scoped.note_cached(&url("mem:///a/obj"));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let ancestor = &drains.get("mem:///a/").expect("a drain").signals;
        ancestor.ever_opened.store(true, Ordering::SeqCst);
        ancestor.live.store(true, Ordering::SeqCst);
        // Degraded: it reports its immediate children only.
        ancestor.recursive.store(false, Ordering::SeqCst);

        // The directory itself goes unread, while its subtree stays busy.
        {
            let mut table = scoped.scopes.table.lock().unwrap();
            table
                .scopes
                .get_mut("mem:///a/")
                .expect("a candidate")
                .direct_touch -= MIN_WATCH_RESIDENCY * 2;
        }
        scoped.note_cached(&url("mem:///a/deep/obj"));

        let views = scope_views(&drains, &scoped.scopes, &probing_views(&[url("mem:///")]));
        let ancestor_view = views
            .iter()
            .find(|v| v.key == "mem:///a/")
            .expect("a view for the drain");
        assert!(
            !ancestor_view.worth_defending,
            "a degraded watch must not be defended by traffic below it, which \
             it does not report"
        );

        // The control: the same watch, recursive, does report that traffic and
        // is defended by it.
        drains["mem:///a/"]
            .signals
            .recursive
            .store(true, Ordering::SeqCst);
        let views = scope_views(&drains, &scoped.scopes, &probing_views(&[url("mem:///")]));
        assert!(
            views
                .iter()
                .find(|v| v.key == "mem:///a/")
                .expect("a view")
                .worth_defending,
            "control: a recursive watch reports the subtree, so the subtree's \
             reads keep it"
        );

        // The same recursive watch between streams. Defensibility spans the
        // reconnect — that is what `working_recently` is for — and this is the
        // drain class whose defence is ENTIRELY the subtree disjunct: a cover
        // held up by traffic below it has a stale `direct_touch` by
        // construction, because `note_cached` stamps that only for the
        // directory actually read. Testing the subtree half against `live`
        // would drop the whole of that defence at every stream end, so once
        // enough rivals outranked it an ordinary reconnect would retire and
        // sweep a working recursive watch — and a reconcile lands in that gap
        // routinely, since a collapsed descendant keeps the supervisor's tick
        // armed for as long as it is unselected.
        drains["mem:///a/"].signals.note_stream_ended();
        assert!(
            !drains["mem:///a/"].signals.live.load(Ordering::SeqCst),
            "the stream must be down for this arm to be about the reconnect"
        );
        assert!(
            views
                .iter()
                .find(|v| v.key == "mem:///a/")
                .is_some_and(|v| v.covers_below),
            "and it must have been covering before it went down, or this arm \
             measures a watch that was never a cover"
        );
        let views = scope_views(&drains, &scoped.scopes, &probing_views(&[url("mem:///")]));
        let reconnecting = views
            .iter()
            .find(|v| v.key == "mem:///a/")
            .expect("a view for the drain");
        assert!(
            !reconnecting.covers_below,
            "a watch between streams reports nothing, so it covers nothing"
        );
        assert!(
            reconnecting.worth_defending,
            "but it is still the watch for that subtree, and retiring it on a \
             reconnect sweeps a byte cache with no TTL and gives the slot away"
        );
        shutdown.cancel();
    }

    /// Stuck retirements cannot ratchet the watch set to nothing.
    ///
    /// A cancelled drain holds its blocking thread until `next()` returns, and
    /// against a backend that never observes cancellation it never does. The
    /// shape this pins is a budget that SUBTRACTS such a drain: the loss
    /// compounds rather than costing a slot, because each reduction forces
    /// another retirement into the same set, so four of them take the budget to
    /// zero, sweep every subtree on the way out and leave nothing able to
    /// re-watch them — with no path back, since nothing ages a stuck handle out.
    /// The budget bounds LIVE watches instead, and the thread cost is bounded by
    /// holding the watch set still at `STUCK_RETIREMENT_LIMIT`, which is well
    /// above the count used here.
    #[tokio::test]
    async fn stuck_retirements_cannot_ratchet_the_watch_set_to_nothing() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        for i in 0..MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        // Handles that never finish, exactly as a backend ignoring the watch
        // cancel token leaves them. More of them than the whole budget.
        let mut retiring: Vec<tokio::task::JoinHandle<()>> = (0..MAX_WATCH_SCOPES * 2)
            .map(|_| tokio::spawn(std::future::pending::<()>()))
            .collect();

        for pass in 0..4 {
            reconcile_scopes(
                &mut drains,
                &mut retiring,
                &weak,
                &shutdown,
                &sweep,
                &scoped,
            )
            .await;
            assert_eq!(
                drains.len(),
                MAX_WATCH_SCOPES,
                "pass {pass}: cancelled drains must not cost live watches, or \
                 one misbehaving backend switches the feature off for the life \
                 of the process — got {:?}",
                drains.keys().collect::<Vec<_>>()
            );
        }
        for handle in retiring {
            handle.abort();
        }
        shutdown.cancel();
    }

    /// Crossing the limit while retiring must not switch watching off for good.
    ///
    /// The limit is crossed BY a retirement, so a pass can begin under it, retire
    /// its last drain and end over it. Holding on the count alone then holds an
    /// EMPTY set — and nothing lowers the count but a handle completing, which by
    /// hypothesis none of them does. The deployment gets no watches again for the
    /// life of the process, including on a replacement route that is perfectly
    /// healthy, over a byte cache with no expiry. That is the same end state the
    /// hold exists to prevent, reached one pass later.
    #[tokio::test]
    async fn crossing_the_limit_while_retiring_still_lets_a_healthy_route_be_watched() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        for i in 0..MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        // Under the limit by exactly one rotation, so this pass's retirements
        // are what cross it.
        let mut retiring: Vec<tokio::task::JoinHandle<()>> = (0..STUCK_RETIREMENT_LIMIT
            - MAX_WATCH_SCOPES)
            .map(|_| tokio::spawn(std::future::pending::<()>()))
            .collect();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES,
            "the set must be full before the route is withdrawn"
        );

        // The route goes away: every drain is stale at once, and retiring them
        // takes the count to the limit with the set left empty.
        scoped.withdraw(&url("mem:///"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.is_empty(),
            "the withdrawn route must leave no drains, or this measures nothing"
        );
        assert!(
            retiring.len() >= STUCK_RETIREMENT_LIMIT,
            "the retirements must have crossed the limit, or this measures \
             nothing — got {}",
            retiring.len()
        );

        // A healthy replacement route. Holding on the count alone would refuse
        // it for the life of the process.
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        scoped.note_cached(&url("mem:///fresh/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            !drains.is_empty(),
            "an empty set must still be allowed to rebuild, or one stuck backend \
             switches watching off permanently for the next healthy route"
        );
        for (_, drain) in drains.drain() {
            drain.stop().abort();
        }
        shutdown.cancel();
    }

    /// A backend that never releases FREEZES the watch set rather than losing it.
    ///
    /// The budget bounds LIVE watches, so it does not bound cancelled drains
    /// that never let go of their blocking thread. Each rotation of the working
    /// set adds up to [`MAX_WATCH_SCOPES`] more, and the pool they consume is
    /// shared with `sweep_off_runtime`, which `reconcile_scopes` awaits:
    /// exhausting it stops watch management entirely and queues the cache's
    /// other blocking work behind threads that never return.
    ///
    /// Both halves of "freeze" are asserted, and the second is the one that
    /// distinguishes this from bounding threads by admission alone. Holding only
    /// the spawns still retires and sweeps, so a pass that changes selection —
    /// a root rebind makes every drain stale at once — walks the set to zero on
    /// a backend whose new watches would all have worked. So this drives a
    /// rebind while over the limit and asserts the drains are still there.
    ///
    /// `stuck_retirements_cannot_ratchet_the_watch_set_to_nothing` holds the
    /// other side, at `MAX_WATCH_SCOPES * 2` handles: below the limit the set is
    /// untouched and keeps rotating normally.
    #[tokio::test]
    async fn a_backend_that_never_releases_stops_the_supervisor_opening_more() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        for i in 0..MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // A healthy watch set first, built while the retiring set is empty.
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES,
            "the set must be full before the limit is reached, or the freeze \
             below has nothing to hold"
        );
        let held: Vec<String> = {
            let mut keys: Vec<String> = drains.keys().cloned().collect();
            keys.sort();
            keys
        };

        // Now the backend stops releasing, and the route is rebound — which
        // makes every existing drain stale at once, so a rule that held only the
        // spawns would retire all four and replace none.
        retiring.extend(
            (0..STUCK_RETIREMENT_LIMIT).map(|_| tokio::spawn(std::future::pending::<()>())),
        );
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        scoped.note_cached(&url("mem:///newcomer/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let after: Vec<String> = {
            let mut keys: Vec<String> = drains.keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(
            after, held,
            "the watch set must be held exactly as it was: neither torn down \
             nor extended while the blocking pool is not being given back"
        );
        assert_eq!(
            retiring.len(),
            STUCK_RETIREMENT_LIMIT,
            "nothing may be retired into the set while it is over the limit"
        );

        // An emptied set is allowed exactly one rebuild — see
        // `crossing_the_limit_while_retiring_still_lets_a_healthy_route_be_watched`
        // for why holding an empty one switches watching off for good — and the
        // pass after it holds again, which is what makes that allowance a
        // one-off rather than a way back to unbounded growth.
        for (_, drain) in drains.drain() {
            drain.stop().abort();
        }
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES,
            "an emptied set must be allowed to rebuild once"
        );
        let rebuilt: Vec<String> = {
            let mut keys: Vec<String> = drains.keys().cloned().collect();
            keys.sort();
            keys
        };
        scoped.note_cached(&url("mem:///another/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let after_rebuild: Vec<String> = {
            let mut keys: Vec<String> = drains.keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(
            after_rebuild, rebuilt,
            "and the pass after the rebuild must hold it, or the allowance is a \
             way back to unbounded growth"
        );

        // Self-healing, and through the real prune: the handles stay in the
        // vector and `retain` at the top of the next pass is what removes them,
        // so this fails if the prune is what regresses rather than the limit.
        // Aborting is how a test makes a parked handle finish; the drain it
        // models finishes when the backend returns.
        for handle in retiring.iter() {
            handle.abort();
        }
        for _ in 0..1_000 {
            if retiring.iter().all(|handle| handle.is_finished()) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            retiring.len(),
            STUCK_RETIREMENT_LIMIT,
            "the handles must still be IN the set, or `retain` is not what is \
             being measured"
        );
        assert!(
            retiring.iter().all(|handle| handle.is_finished()),
            "the released handles never completed, so this measured nothing"
        );

        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            retiring.len() < STUCK_RETIREMENT_LIMIT,
            "the released handles must be pruned below the limit, or it never \
             re-opens — got {}",
            retiring.len()
        );
        assert!(
            !retiring.iter().any(|handle| handle.is_finished()),
            "every finished handle must be gone; what is left are this pass's \
             own retirements, which have not completed"
        );
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES,
            "once the backend releases, the watch set must follow the working \
             set again on its own"
        );
        for (_, drain) in drains.drain() {
            drain.stop().abort();
        }
        shutdown.cancel();
    }

    /// A root that leaves the route set is forgotten, whether or not it ever
    /// had a drain.
    ///
    /// Advertising every discovered root and withdrawing only the ones that got
    /// a drain is not symmetric, and the asymmetry is not inert: assignment is
    /// by longest prefix, so an entry nothing can remove suppresses every scope
    /// beneath it for the life of the process. A watch withheld on the strength
    /// of a route that no longer exists is the same failure this whole PR is
    /// about, so the withdrawal has to be driven by the same set the
    /// advertisement is.
    #[tokio::test]
    async fn a_root_that_leaves_the_route_set_is_forgotten() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();

        let mut capable = root_info("mem:///");
        capable.capabilities.supports_watch_directory = true;
        let mut incapable = root_info("mem:///team/");
        incapable.capabilities.supports_watch_directory = false;
        reconcile_roots(
            &mut drains,
            &weak,
            vec![capable.clone(), incapable],
            &shutdown,
            &sweep,
            &scoped,
        );
        scoped.refuse(&url("mem:///"));
        assert!(
            select_unprotected(
                &scoped.root_views(),
                &[url("mem:///team/proj/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )
            .is_empty(),
            "while the nested root is advertised its scopes are its own"
        );

        // `Notify` stores a permit when nothing is waiting, and the reconcile
        // above issued several. Consume whatever is outstanding, or the
        // assertion below passes on a wake from the setup.
        while tokio::time::timeout(Duration::from_millis(20), scoped.scopes.wake.notified())
            .await
            .is_ok()
        {}

        // The nested route is removed. It never had a drain, so nothing in the
        // drain map can carry its withdrawal.
        reconcile_roots(
            &mut drains,
            &weak,
            vec![capable],
            &shutdown,
            &sweep,
            &scoped,
        );
        assert_eq!(
            scoped
                .root_views()
                .iter()
                .map(|v| v.root.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["mem:///".to_string()],
            "a departed root must not linger, or it suppresses its subtree forever"
        );
        assert_eq!(
            scope_urls(&select_unprotected(
                &scoped.root_views(),
                &[url("mem:///team/proj/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )),
            vec!["mem:///team/proj/".to_string()],
            "and the scope falls back to the root that now routes it"
        );
        // And the supervisor is told. This root had no drain, so the stale loop
        // never ran for it and `advertise` never inserted — `retain_advertised`
        // is the only thing that can say so, and with no timer in the steady
        // state a change nobody announces is a change nobody applies.
        tokio::time::timeout(Duration::from_secs(1), scoped.scopes.wake.notified())
            .await
            .expect("a departing root reassigns the scopes it owned");
        shutdown.cancel();
    }

    /// A root drain writes its state against the advertisement it was started
    /// for, so a straggler cannot speak for the route that replaced it.
    ///
    /// A drain is cancelled without being aborted, so it can sit between its
    /// cancellation check and its state write while the manager withdraws and
    /// re-advertises the same URL. Writing by URL alone, it would mark the NEW
    /// entry `Live` — and that entry may have no drain at all, so nothing would
    /// ever move it off. A permanently-`Live` root with no watch suppresses its
    /// whole subtree from selection: the phantom the `get_mut` guards were
    /// written to prevent, reached through a re-created entry rather than a
    /// re-created map slot.
    #[test]
    fn a_root_transition_is_ignored_when_its_advertisement_has_moved_on() {
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        let root = url("mem:///");
        let stale = state.advertise(&root);
        state.withdraw(&root);
        let current = state.advertise(&root);
        assert_ne!(stale, current, "a rebind is a new advertisement");

        state.leave_scoped_mode(&root, stale);
        assert!(
            !state.covers(&url("mem:///a/obj")),
            "a drain from the previous advertisement must not mark this one live"
        );
        state.enter_scoped_mode(&root, stale);
        assert!(
            state.probe_failures(&root).is_none(),
            "nor start it probing"
        );
        // And the third transition, which is the one that costs most if it
        // lands: the replacement's watch is up, and a straggler's stream ending
        // must not put the live root back to `Pending` — a state that neither
        // covers nor admits probes, and that nothing would rewrite until the
        // live drain's own stream ends.
        state.leave_scoped_mode(&root, current);
        state.root_watch_ended(&root, stale);
        assert!(
            state.covers(&url("mem:///a/obj")),
            "a straggler's stream ending must not un-cover the route that \
             replaced it"
        );

        // The control: the same transitions against the current advertisement
        // are applied.
        state.root_watch_ended(&root, current);
        assert!(!state.covers(&url("mem:///a/obj")));
        state.leave_scoped_mode(&root, current);
        assert!(state.covers(&url("mem:///a/obj")));
        state.root_watch_ended(&root, current);
        assert!(!state.covers(&url("mem:///a/obj")));
        state.enter_scoped_mode(&root, current);
        assert_eq!(state.probe_failures(&root), Some(0));
    }

    /// Selection assigns each scope to the LONGEST matching root, exactly as
    /// the router dispatches. Assigning to every matching root would open one
    /// watch per overlapping root for the same events.
    #[test]
    fn a_scope_is_assigned_to_its_longest_matching_root_only() {
        // Roots come from `probing_roots`, not hand-sorted here: the ordering
        // production supplies is half of what makes this hold, so a test that
        // pre-sorts them would pass with that ordering removed.
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&url("mem:///"));
        state.refuse(&url("mem:///"));
        state.advertise(&url("mem:///team/"));
        state.refuse(&url("mem:///team/"));
        let roots = probing_views(&state.probing_roots());
        let selected = select_unprotected(
            &roots,
            &[url("mem:///team/proj/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert_eq!(selected.len(), 1, "one scope must yield exactly one watch");
        assert_eq!(selected[0].root.as_str(), "mem:///team/");
    }

    /// A scope with no probing root is not watched at all — the supervisor
    /// must not invent a watch for a root that never refused.
    #[test]
    fn a_scope_under_no_probing_root_is_not_selected() {
        let selected = select_unprotected(
            &[],
            &[url("mem:///a/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert!(selected.is_empty());
        let selected = select_unprotected(
            &probing_views(&[url("other:///")]),
            &[url("mem:///a/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert!(selected.is_empty());
    }

    /// Scoped watches are recursive, so a covering candidate makes the ones
    /// beneath it redundant — in BOTH orders, because the covering scope can be
    /// registered before or after the ones it covers.
    #[test]
    fn a_covered_scope_is_dropped_whichever_order_it_arrived_in() {
        let roots = probing_views(&[url("mem:///")]);
        for candidates in [
            vec![url("mem:///a/"), url("mem:///a/b/"), url("mem:///a/b/c/")],
            vec![url("mem:///a/b/c/"), url("mem:///a/b/"), url("mem:///a/")],
        ] {
            let selected =
                select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &covers_all(), &[]);
            assert_eq!(
                scope_urls(&selected),
                vec!["mem:///a/".to_string()],
                "only the covering scope survives, order notwithstanding"
            );
        }
        // A sibling is not covered and keeps its own watch.
        let selected = select_unprotected(
            &roots,
            &[url("mem:///a/b/"), url("mem:///a/c/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert_eq!(selected.len(), 2);
    }

    /// Segment alignment: `mem:///ab/` is not covered by `mem:///a`.
    #[test]
    fn coverage_is_segment_aligned_not_textual() {
        let selected = select_unprotected(
            &probing_views(&[url("mem:///")]),
            &[url("mem:///a"), url("mem:///ab/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert_eq!(selected.len(), 2, "a textual prefix is not a cover");
    }

    /// The budget drops the coldest candidates, and drops them last-first
    /// because candidates arrive most-recently-used first.
    #[test]
    fn the_budget_drops_the_coldest_candidates() {
        let roots = probing_views(&[url("mem:///")]);
        let candidates: Vec<Url> = (0..MAX_WATCH_SCOPES + 3)
            .map(|i| url(&format!("mem:///d{i}/")))
            .collect();
        let selected =
            select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &covers_all(), &[]);
        assert_eq!(
            scope_urls(&selected),
            (0..MAX_WATCH_SCOPES)
                .map(|i| format!("mem:///d{i}/"))
                .collect::<Vec<_>>(),
            "the retained set is the head of the recency order, not just its size"
        );
        // A budget of zero selects nothing, whatever spent it.
        assert!(select_unprotected(&roots, &candidates, 0, &covers_all(), &[]).is_empty());
    }

    /// A registry that is not enabled records nothing, so the default
    /// composition pays no bookkeeping on its read path.
    #[test]
    fn a_disabled_registry_records_nothing() {
        let scopes = WatchScopes::new(false);
        scopes.note_cached(&url("mem:///a/obj"));
        assert!(scopes.candidates(&any_owner).is_empty());
        // Controlled against the enabled case, so "empty" means "declined to
        // record" rather than "records nothing either way".
        let enabled = WatchScopes::new(true);
        enabled.note_cached(&url("mem:///a/obj"));
        assert_eq!(enabled.candidates(&any_owner).len(), 1);
    }

    /// The directory being read must not lose its slot to its own ancestors.
    ///
    /// `note_cached` writes ONE clock reading to the scope and to every ancestor
    /// already in the table, so a leaf's recency is exactly equal to — never
    /// greater than — each of its ancestors'. With ties broken by ascending
    /// spelling the leaf sorts last of its chain every time, because a directory
    /// URL is a literal string prefix of everything beneath it. Four registered
    /// ancestors then fill the budget and `truncate` drops the leaf on every
    /// reconcile.
    ///
    /// That is correct only while an ancestor's recursive watch actually covers
    /// the chain, and then the antichain has already dropped the descendants on
    /// `can_cover` before ordering matters. This is the other case: no ancestor
    /// is covering, so nothing collapses and a non-recursive watch on `assets/`
    /// reports nothing about objects inside `textures/`. A chain whose ancestors
    /// have degraded stays in that state, which is what this feature is for; a
    /// recursive-capable chain passes through it at cold start and leaves it
    /// through the cover slot, one reconcile later. Nothing else rescues the leaf —
    /// `protected` needs `working_recently()`, which needs a watch it never
    /// gets, and the cover slot needs `subsumed(entry) > 0`, which a leaf never
    /// satisfies.
    #[test]
    fn a_read_directory_is_not_outranked_by_its_own_ancestors() {
        let scopes = WatchScopes::new(true);
        // A browse down the tree, then work in the leaf — four ancestors and
        // the directory the objects are actually read from.
        for prefix in [
            "mem:///projects/",
            "mem:///projects/team/",
            "mem:///projects/team/proj/",
            "mem:///projects/team/proj/assets/",
        ] {
            scopes.note_cached(&url(prefix));
        }
        scopes.note_cached(&url("mem:///projects/team/proj/assets/textures/x.usd"));

        let candidates = scopes.candidates(&any_owner);
        assert_eq!(
            candidates.len(),
            5,
            "the chain must be registered five deep, or this measures nothing"
        );
        // No ancestor is COVERING — `can_cover` is false for all of them —
        // which is the state both cases share: the degraded chain this rule is
        // for, and a recursive-capable chain at cold start, where nothing has
        // opened yet. `select_unprotected` leaves `may_open_recursive` true, so
        // this is the cold-start reading as much as the degraded one, and the
        // ancestor reaches its watch through the cover slot rather than through
        // this ordering.
        let selected = select_unprotected(
            &probing_views(&[url("mem:///")]),
            &candidates,
            MAX_WATCH_SCOPES,
            &|_: &SelectedScope| false,
            &[],
        );
        assert_eq!(
            selected.len(),
            MAX_WATCH_SCOPES,
            "the budget is spent either way; the question is on what"
        );
        assert!(
            scope_urls(&selected)
                .contains(&"mem:///projects/team/proj/assets/textures/".to_string()),
            "the directory the objects are read from must keep a watch when no \
             ancestor can report it, got {:?}",
            scope_urls(&selected)
        );
        // The control, so this cannot pass by preferring depth blindly: give one
        // ancestor a covering recursive watch and the antichain collapses the
        // whole chain onto it, which is the shape the shallow order was for.
        let covered = select_unprotected(
            &probing_views(&[url("mem:///")]),
            &candidates,
            MAX_WATCH_SCOPES,
            &|entry: &SelectedScope| entry.scope.as_str() == "mem:///projects/",
            &[],
        );
        assert_eq!(
            scope_urls(&covered),
            vec!["mem:///projects/".to_string()],
            "a covering ancestor still takes the whole chain onto one watch"
        );
    }

    /// Reading under a directory counts as use of that directory, so a project
    /// scope cannot become the coldest entry while its own subtree is the
    /// busiest thing in the cache.
    #[test]
    fn reading_under_a_scope_keeps_that_scope_warm() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///a/obj"));
        // Twice the registry's capacity of fresh subdirectories: without the
        // ancestor touch `mem:///a/` is evicted long before this loop ends, and
        // with it `mem:///a/` is the most recently used entry throughout.
        for i in 0..MAX_CANDIDATE_SCOPES * 2 {
            scopes.note_cached(&url(&format!("mem:///a/sub{i}/obj")));
        }
        let candidates = scopes.candidates(&any_owner);
        assert_eq!(
            candidates.len(),
            MAX_CANDIDATE_SCOPES,
            "the registry is bounded"
        );
        // The ancestor touch credits each of those reads to `mem:///a/` on the
        // same clock reading as the child it just inserted, so the two share
        // the head of the order. Without it `mem:///a/` is not in the table at
        // all.
        let position = candidates
            .iter()
            .position(|scope| scope.as_str() == "mem:///a/");
        assert!(
            matches!(position, Some(0 | 1)),
            "reading under a directory is use of that directory, so it must be \
             at the head of the recency order, got {:?}",
            candidates.iter().map(Url::as_str).collect::<Vec<_>>()
        );
        // And it is what selection keeps, so the whole subtree costs one watch
        // rather than one per directory.
        let selected = select_unprotected(
            &probing_views(&[url("mem:///")]),
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert_eq!(scope_urls(&selected), vec!["mem:///a/".to_string()]);
    }

    /// A registration that happens while the supervisor is mid-reconcile — not
    /// yet waiting — must still wake it.
    ///
    /// This pins the choice of `Notify::notify_one` over `notify_waiters`:
    /// `notify_waiters` stores no permit, so a notification sent when no waiter
    /// is registered is dropped. There is exactly one waiter and it spends most
    /// of its life not registered, and its only other wake source is a timer
    /// that does not run when no refusal is outstanding — so a dropped
    /// notification is a directory that silently never gets watched.
    #[tokio::test]
    async fn a_registration_wakes_a_supervisor_that_is_not_yet_waiting() {
        let scopes = WatchScopes::new(true);
        // Sent before anyone waits, exactly as it is when the supervisor is
        // inside its reconcile.
        scopes.note_cached(&url("mem:///a/obj"));
        tokio::time::timeout(Duration::from_secs(1), scopes.wake.notified())
            .await
            .expect("a registration made while nothing was waiting must still wake the supervisor");
    }

    /// Every root change selection reads has to wake the supervisor, because
    /// when every candidate is watched there is no timer at all.
    ///
    /// `supervisor_needs_timer` is false with nothing retiring, nothing
    /// deferred, no denial in its window and no paused root — the steady state
    /// of a working fallback — so the supervisor blocks on the notify alone. A
    /// root change that does not wake it is therefore not "applied late", it is
    /// applied never, until something unrelated happens to wake it.
    ///
    /// Both directions here changed what selection sees and neither used to
    /// notify: advertising a nested root reassigns every scope beneath it by
    /// longest prefix, and a `Pending` root going `Live` starts covering them.
    #[tokio::test]
    async fn every_root_change_selection_reads_wakes_the_supervisor() {
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&url("mem:///"));
        tokio::time::timeout(Duration::from_secs(1), state.scopes.wake.notified())
            .await
            .expect("advertising a root reassigns the scopes beneath it");

        // A repeat advertisement of a root already known is the same route and
        // must stay silent, or the drain manager wakes the supervisor on every
        // reconcile of an unchanged root set.
        state.advertise(&url("mem:///"));
        tokio::time::timeout(Duration::from_millis(50), state.scopes.wake.notified())
            .await
            .expect_err("a repeated advertisement is not a change");

        // `Pending` -> `Live`, which is the takeover case: the root never
        // refused anything, so there is no `Refused` state to leave.
        state.grant(&url("mem:///"));
        tokio::time::timeout(Duration::from_secs(1), state.scopes.wake.notified())
            .await
            .expect("a root whose watch opens starts covering every scope beneath it");

        // A second grant with no intervening end is not a change. This is not
        // the reconnect case — a reconnecting drain passes through
        // `root_watch_ended` first, which puts the entry back to `Pending`, so
        // its next grant IS a change and does wake. What this excludes is a
        // repeated advertisement of a root that is already live.
        state.grant(&url("mem:///"));
        tokio::time::timeout(Duration::from_millis(50), state.scopes.wake.notified())
            .await
            .expect_err("a grant of an already-live root changes nothing");

        // And the reconnect really does wake, both halves of it.
        state.end_root_watch(&url("mem:///"));
        tokio::time::timeout(Duration::from_secs(1), state.scopes.wake.notified())
            .await
            .expect("a root whose stream ends stops covering its subtree");
        state.grant(&url("mem:///"));
        tokio::time::timeout(Duration::from_secs(1), state.scopes.wake.notified())
            .await
            .expect("and covers it again when the reopen lands");
    }

    /// A refusal is remembered, so a reconcile does not re-probe it — and it is
    /// remembered per scope, not for the whole registry.
    #[test]
    fn a_denied_scope_is_withheld_but_its_siblings_are_not() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///a/obj"));
        scopes.note_cached(&url("mem:///b/obj"));
        assert_eq!(scopes.candidates(&any_owner).len(), 2);
        scopes.deny_both(&url("mem:///a/"));
        assert_eq!(
            scopes
                .candidates(&any_owner)
                .iter()
                .map(|u| u.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["mem:///b/".to_string()]
        );
        assert!(scopes.has_pending_deadline());

        // And it is withheld until a deadline, not permanently. Policy is
        // reloadable, so a refusal is a fact with an expiry; without that, a
        // reload granting the right would be invisible until the process
        // restarted. Backdating the refusal past its retry interval is the only
        // thing that changes here.
        {
            let mut table = scopes.table.lock().unwrap();
            let denied = table
                .denied
                .get_mut("mem:///a/")
                .expect("the refusal was recorded");
            denied.at -= DENIED_SCOPE_RETRY * 2;
        }
        assert!(
            scopes
                .candidates(&any_owner)
                .iter()
                .any(|scope| scope.as_str() == "mem:///a/"),
            "an expired refusal must let the directory be probed again"
        );
        assert!(
            !scopes.has_pending_deadline(),
            "and the supervisor stops waking on a timer once nothing is pending"
        );
    }

    /// The pause on a root that grants nothing expires too, for the same
    /// reason: it is a rate limit on probing, not a verdict on the deployment.
    #[test]
    fn a_paused_root_is_probed_again_once_its_pause_expires() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES {
            state.note_scope_outcome_now(&root, ScopeOutcome::Failed);
        }
        assert!(state.probing_roots().is_empty());

        {
            let mut roots = state.roots.lock().unwrap();
            let RootWatch::Refused { paused_until, .. } =
                &mut roots.get_mut(&root_key(&root)).expect("the root").watch
            else {
                panic!("a root that spent its budget is refused");
            };
            *paused_until = Some(tokio::time::Instant::now() - Duration::from_secs(1));
        }
        assert_eq!(
            state.probing_roots(),
            vec![root.clone()],
            "an expired pause must let the root probe again"
        );
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "with the budget refunded, or the next failure would re-pause it at once"
        );
        assert!(
            !state.has_pending_deadline(),
            "and the supervisor stops waking on a timer for it"
        );
    }

    /// An object at the top level of a root derives the ROOT as its scope, and
    /// that scope is not watched.
    ///
    /// It could only ever open `NonRecursive`, since its recursive form is the
    /// watch that was refused — but the activation sweep every open performs is
    /// unconditionally recursive, because `clear_subtree_impl` is a prefix scan
    /// with no depth bound. Selecting it therefore discards the whole partition
    /// on activation and on every reopen, taking with it the subtrees that
    /// other live scoped watches are keeping fresh. It would buy invalidation
    /// for the objects at the top of the root and pay for it with the entire
    /// cache. So the top-level object is TTL-only, which is what
    /// `docs/public/configuration.md` already tells operators. Matching the
    /// sweep radius to the watch mode would let this scope back in, and needs a
    /// depth-bounded removal the shared `Cache` does not have.
    #[test]
    fn a_scope_equal_to_its_root_is_not_watched() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///obj"));
        scopes.note_cached(&url("mem:///folder/obj"));
        let candidates = scopes.candidates(&any_owner);
        let roots = probing_views(&[url("mem:///")]);
        assert!(
            candidates.iter().any(|c| c.as_str() == "mem:///"),
            "the registry still REGISTERS it — the exclusion is selection's, so \
             a depth-aware sweep could restore the watch without touching the \
             read path"
        );

        let selected =
            select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &covers_all(), &[]);
        assert_eq!(
            scope_urls(&selected),
            vec!["mem:///folder/".to_string()],
            "the root's own prefix must not be selected, and the directory \
             below it must still be"
        );

        // A nested root makes the same URL an ordinary scope again: `mem:///a/`
        // is watchable under `mem:///`, and unwatchable once it is itself a
        // root. The rule is about the pair, not about the spelling.
        scopes.note_cached(&url("mem:///a/obj"));
        let candidates = scopes.candidates(&any_owner);
        let outer = probing_views(&[url("mem:///")]);
        assert!(
            scope_urls(&select_unprotected(
                &outer,
                &candidates,
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[]
            ))
            .contains(&"mem:///a/".to_string()),
            "control: under the outer root alone it is an ordinary scope"
        );
        let nested = probing_views(&[url("mem:///"), url("mem:///a/")]);
        assert!(
            !scope_urls(&select_unprotected(
                &nested,
                &candidates,
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[]
            ))
            .contains(&"mem:///a/".to_string()),
            "and it drops out once a root is advertised at exactly that URL"
        );
    }

    /// A recursive refusal is not a denial: the scope stays a candidate and the
    /// next drain for it starts with the smaller ask instead of re-paying for
    /// the refused one. Only a refusal in both modes withholds it.
    #[test]
    fn a_recursive_refusal_degrades_the_scope_rather_than_denying_it() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///a/obj"));
        assert_eq!(
            scopes.starting_mode(&url("mem:///a/"), &any_owner),
            WatchMode::Recursive
        );

        scopes.deny(&url("mem:///a/"), WatchMode::Recursive, &url("mem:///"), 0);
        assert_eq!(
            scopes.candidates(&any_owner).len(),
            1,
            "a recursive refusal must not withhold the scope"
        );
        assert_eq!(
            scopes.starting_mode(&url("mem:///a/"), &any_owner),
            WatchMode::NonRecursive,
            "and the next drain must not re-pay for the refused recursive probe"
        );

        scopes.deny(
            &url("mem:///a/"),
            WatchMode::NonRecursive,
            &url("mem:///"),
            0,
        );
        assert!(
            scopes.candidates(&any_owner).is_empty(),
            "a refusal in both modes is what withholds it"
        );
    }

    /// A scope watching non-recursively reports nothing below its immediate
    /// children, so it cannot cover the scopes beneath it — the collapse is
    /// sound only under a watch that is actually recursive.
    #[test]
    fn a_degraded_scope_does_not_cover_the_scopes_beneath_it() {
        let roots = probing_views(&[url("mem:///")]);
        let candidates = vec![url("mem:///a/"), url("mem:///a/b/")];
        let collapsed =
            select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &covers_all(), &[]);
        assert_eq!(
            scope_urls(&collapsed),
            vec!["mem:///a/".to_string()],
            "a recursive cover collapses the scope beneath it"
        );

        let degraded = |entry: &SelectedScope| entry.scope.as_str() != "mem:///a/";
        let expanded = select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &degraded, &[]);
        let mut got = scope_urls(&expanded);
        got.sort();
        assert_eq!(
            got,
            vec!["mem:///a/".to_string(), "mem:///a/b/".to_string()],
            "once the cover degrades, the scope beneath it needs its own watch"
        );
    }

    /// The registry follows the working set. Sized at exactly the watch budget
    /// it could not: four directories holding live watches left nothing
    /// displaceable, so no later directory could be admitted at all and the
    /// fallback watched whichever directories the cache happened to hold first
    /// for the life of the process. Measured on that shape, ten thousand reads
    /// of a fifth directory left it out of the registry entirely.
    #[test]
    fn the_registry_follows_the_working_set() {
        let scopes = WatchScopes::new(true);
        for i in 0..MAX_WATCH_SCOPES {
            scopes.note_cached(&url(&format!("mem:///first{i}/obj")));
        }
        scopes.note_cached(&url("mem:///hot/obj"));
        let candidates = scopes.candidates(&any_owner);
        assert_eq!(
            candidates.first().map(Url::as_str),
            Some("mem:///hot/"),
            "a directory being read now must be the registry's most recent, got {:?}",
            candidates.iter().map(Url::as_str).collect::<Vec<_>>()
        );
        assert!(
            candidates.len() > MAX_WATCH_SCOPES,
            "being a candidate is not holding a watch: the registry is the larger table"
        );
    }

    /// A directory an existing candidate already covers is admitted like any
    /// other. It costs one of [`MAX_CANDIDATE_SCOPES`] entries and no watch —
    /// selection collapses it onto the covering scope — so it cannot crowd out
    /// an unrelated directory that does need one. Saxon's case: a `list` of a
    /// project directory plus reads of three of its subdirectories used to fill
    /// the table, leaving a fourth, unrelated directory unadmittable while
    /// three of the four affordable watches sat idle.
    #[test]
    fn a_subsumed_directory_does_not_crowd_out_one_that_needs_a_watch() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///proj/"));
        for name in ["a", "b", "c"] {
            scopes.note_cached(&url(&format!("mem:///proj/{name}/obj")));
        }
        scopes.note_cached(&url("mem:///other/obj"));
        let candidates = scopes.candidates(&any_owner);
        assert!(
            candidates
                .iter()
                .any(|scope| scope.as_str() == "mem:///other/"),
            "a directory that needs a watch must reach the registry, got {:?}",
            candidates.iter().map(Url::as_str).collect::<Vec<_>>()
        );
        // And it gets one: the three subsumed directories collapse onto the
        // project directory's live recursive watch, so two watches cover all
        // five reads.
        let covering = |entry: &SelectedScope| entry.scope.as_str() == "mem:///proj/";
        let mut selected = scope_urls(&select_unprotected(
            &probing_views(&[url("mem:///")]),
            &candidates,
            MAX_WATCH_SCOPES,
            &covering,
            &[],
        ));
        selected.sort();
        assert_eq!(
            selected,
            vec!["mem:///other/".to_string(), "mem:///proj/".to_string()]
        );
    }

    /// Probing is bounded by the registry and by selection together: a
    /// workload walking hundreds of directories produces at most
    /// [`MAX_CANDIDATE_SCOPES`] candidates and at most [`MAX_WATCH_SCOPES`]
    /// watches, and a refusal is remembered so it is not re-probed. A
    /// deployment that grants no watch at any prefix therefore pays a handful
    /// of refused opens per retry interval rather than one per directory read.
    #[test]
    fn probing_is_bounded_by_the_registry_not_by_directories_read() {
        let scopes = WatchScopes::new(true);
        for i in 0..400 {
            scopes.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let candidates = scopes.candidates(&any_owner);
        assert_eq!(
            candidates.len(),
            MAX_CANDIDATE_SCOPES,
            "400 directories may not become 400 candidates"
        );
        let roots = probing_views(&[url("mem:///")]);
        assert_eq!(
            select_unprotected(&roots, &candidates, MAX_WATCH_SCOPES, &covers_all(), &[]).len(),
            MAX_WATCH_SCOPES,
            "and 32 candidates may not become 32 watches"
        );
        // A refused directory is withheld rather than re-probed, so the probes
        // move on to the next candidates instead of repeating.
        for scope in candidates.iter().take(MAX_WATCH_SCOPES) {
            scopes.deny_both(scope);
        }
        let after = scopes.candidates(&any_owner);
        assert!(
            candidates
                .iter()
                .take(MAX_WATCH_SCOPES)
                .all(|scope| !after.contains(scope)),
            "a refused directory must stay withheld for the retry interval"
        );
    }

    /// A registry eviction is a retirement, so the one thing admission must not
    /// do is evict a scope a drain holds. A scope absent from `candidates()`
    /// cannot be selected at all, so its watch is torn down and its subtree
    /// swept however recently it was read — and a working set of more distinct
    /// directories than the registry holds would cycle every watch out and back
    /// on opens that succeed, which no budget notices.
    #[test]
    fn a_watched_scope_is_not_evicted_by_registry_pressure() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///held/obj"));
        scopes.mark_watched(&["mem:///held/".to_string()]);
        for i in 0..MAX_CANDIDATE_SCOPES * 2 {
            scopes.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        assert!(
            scopes
                .candidates(&any_owner)
                .iter()
                .any(|scope| scope.as_str() == "mem:///held/"),
            "a scope holding a watch must survive pressure from directories it \
             has nothing to do with"
        );
        // Which cannot freeze the table: only the four a drain holds are
        // exempt, and the rest of it churned freely under that same pressure.
        assert!(
            scopes.candidates(&any_owner).iter().any(
                |scope| scope.as_str() == format!("mem:///d{}/", MAX_CANDIDATE_SCOPES * 2 - 1)
            ),
            "the newest directory must still be admitted"
        );

        // The control: the same pressure evicts it once no drain holds it, so
        // the assertion above is about the exemption and not about the entry
        // being unreachable.
        scopes.mark_watched(&[]);
        for i in 0..MAX_CANDIDATE_SCOPES * 2 {
            scopes.note_cached(&url(&format!("mem:///e{i}/obj")));
        }
        assert!(
            !scopes
                .candidates(&any_owner)
                .iter()
                .any(|scope| scope.as_str() == "mem:///held/"),
            "an unheld scope is ordinary LRU"
        );
    }

    /// The anti-thrash rule lives in selection now, and it is stated as
    /// idleness rather than tenure: a live watch on a directory that is still
    /// being read keeps its slot however hot a rival gets. Without it a working
    /// set one directory larger than the budget would discard a subtree per
    /// read.
    #[test]
    fn a_live_watch_is_not_displaced_while_its_directory_is_still_read() {
        let roots = probing_views(&[url("mem:///")]);
        // Recency order puts the newcomers first, so only protection can save
        // the incumbents.
        let hot: Vec<String> = (0..MAX_WATCH_SCOPES)
            .map(|i| format!("mem:///new{i}/"))
            .collect();
        let incumbents: Vec<String> = (0..MAX_WATCH_SCOPES)
            .map(|i| format!("mem:///old{i}/"))
            .collect();
        let candidates: Vec<Url> = hot.iter().chain(&incumbents).map(|s| url(s)).collect();

        let mut kept = scope_urls(&select_scopes(
            &roots,
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &|_| true,
            &[],
            &protected_under("mem:///", &incumbents),
        ));
        kept.sort();
        assert_eq!(
            kept, incumbents,
            "a watch on a directory still being read is not given up"
        );

        // The control: the same recency order with nothing protected hands
        // every slot to the newcomers, so the assertion above is about
        // protection rather than about the order.
        let mut taken = scope_urls(&select_unprotected(
            &roots,
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        ));
        taken.sort();
        assert_eq!(taken, hot);
    }

    /// Protection is idleness, so it expires. A directory that stops being read
    /// releases its watch to the working set that replaced it — which is the
    /// recency escape a table capped at the watch budget could not have.
    #[test]
    fn a_watch_becomes_displaceable_once_its_directory_goes_unread() {
        let scopes = WatchScopes::new(true);
        scopes.note_cached(&url("mem:///a/obj"));
        assert!(scopes.touched_within("mem:///a/", MIN_WATCH_RESIDENCY));
        {
            let mut table = scopes.table.lock().unwrap();
            for entry in table.scopes.values_mut() {
                entry.direct_touch -= MIN_WATCH_RESIDENCY * 2;
            }
        }
        assert!(
            !scopes.touched_within("mem:///a/", MIN_WATCH_RESIDENCY),
            "an idle directory's watch must become displaceable"
        );
        // A read UNDER it does not, by itself, count as a read of it. Residency
        // defends a watch because tearing it down loses what it reports, and an
        // ancestor opened `NonRecursive` — the root's own prefix always is, and
        // any scope may degrade to it — reports nothing about this traffic.
        // Inherited here, such an ancestor would hold a slot on reads it cannot
        // see while the directory generating them stays unwatched.
        scopes.note_cached(&url("mem:///a/b/obj"));
        assert!(
            !scopes.touched_within("mem:///a/", MIN_WATCH_RESIDENCY),
            "descendant traffic alone must not defend an ancestor's watch"
        );

        // The route back for an ancestor that CAN see it: the supervisor asks
        // this of exactly the drains whose watch is open, recursive and on the
        // current advertisement, which is what keeps a project directory's
        // recursive watch while only its children are addressed.
        assert!(
            scopes.subtree_touched_within(&url("mem:///a/"), MIN_WATCH_RESIDENCY, &|_| true),
            "but a watch that reports the subtree is kept by the subtree's reads"
        );
        assert!(
            !scopes.subtree_touched_within(&url("mem:///a/b/"), MIN_WATCH_RESIDENCY, &|_| true),
            "and it is STRICTLY below: a scope's own read is not its subtree's"
        );

        assert!(
            !scopes.touched_within("mem:///gone/", MIN_WATCH_RESIDENCY),
            "a scope the registry has evicted is displaceable by definition"
        );
    }

    /// The registry bounds probing per directory; it cannot bound it per
    /// deployment, because a workload walking fresh directories supplies new
    /// candidates indefinitely. That is what the root's probe budget is for.
    #[test]
    fn a_root_that_grants_nothing_stops_being_probed() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES - 1 {
            state.note_scope_outcome_now(&root, ScopeOutcome::Failed);
        }
        assert_eq!(
            state.probing_roots().len(),
            1,
            "one failure short of the budget still probes"
        );
        assert!(!state.has_pending_deadline());

        state.note_scope_outcome_now(&root, ScopeOutcome::Failed);
        assert!(
            state.probing_roots().is_empty(),
            "a root that has granted nothing must stop being probed"
        );
        assert!(
            state.has_pending_deadline(),
            "and it must be a pause on a clock, not a permanent stop — policy is \
             reloadable, so a grant has to become visible without a restart"
        );
    }

    /// One granted watch says this is not a deployment that grants nothing, so
    /// the budget must not accumulate across successes.
    #[test]
    fn a_granted_scope_clears_the_probe_budget() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES * 4 {
            for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES - 1 {
                state.note_scope_outcome_now(&root, ScopeOutcome::Failed);
            }
            state.note_scope_outcome_now(&root, ScopeOutcome::Worked);
        }
        assert_eq!(state.probing_roots().len(), 1);
        assert!(!state.has_pending_deadline());
    }

    /// A refused root is re-asked on the refusal interval, not on the ordinary
    /// reconnect backoff — whose ceiling would re-ask a standing policy refusal
    /// every minute for the life of the process.
    #[test]
    fn a_refused_root_waits_the_refusal_interval_not_the_reconnect_ceiling() {
        assert_eq!(
            backoff_after_open_failure(true, INITIAL_DRAIN_BACKOFF),
            DENIED_SCOPE_RETRY
        );
        assert!(
            backoff_after_open_failure(true, MAX_DRAIN_BACKOFF) > MAX_DRAIN_BACKOFF,
            "the refusal interval must not be clamped to the reconnect ceiling"
        );
        // An ordinary retryable failure keeps the doubling backoff and its cap.
        assert_eq!(
            backoff_after_open_failure(false, INITIAL_DRAIN_BACKOFF),
            INITIAL_DRAIN_BACKOFF * 2
        );
        assert_eq!(
            backoff_after_open_failure(false, MAX_DRAIN_BACKOFF),
            MAX_DRAIN_BACKOFF
        );
    }

    /// A root that vanishes or rebinds stops probing; its replacement drain
    /// re-attempts the root watch from scratch.
    #[test]
    fn leaving_scoped_mode_stops_probing_that_root() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        state.grant(&root);
        assert!(state.probing_roots().is_empty());
    }

    /// A deeper root outranks a shallower one that merely spells more bytes.
    ///
    /// `mem:///a?v=1` is twelve bytes and `mem:///a/b` is ten, so a byte-length
    /// rank puts the pinned parent above the deeper child and assigns
    /// `mem:///a/b/c/` to it — the wrong route for that address.
    /// `node_rank` is depth first, then whether the root pins a query, so the
    /// child wins on depth while a pinned root still outranks its own unpinned
    /// parent. This is the disagreement that survives the keying fix.
    #[test]
    fn a_deeper_root_outranks_a_pinned_shallower_one() {
        let views = probing_views(&[url("mem:///a?v=1"), url("mem:///a/b")]);
        assert_eq!(
            views
                .iter()
                .map(|v| v.root.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["mem:///a/b".to_string(), "mem:///a?v=1".to_string()],
            "the deeper root must rank first"
        );
        assert_eq!(
            longest_root(&views, &url("mem:///a/b/c/")).map(Url::as_str),
            Some("mem:///a/b"),
            "the deeper root must serve an address beneath it"
        );
    }

    /// Two spellings of one root are ONE root, exactly as `RouteTable` treats
    /// them, through advertise / withdraw / re-advertise.
    ///
    /// The router dedups on `node_key` and ranks on `node_rank`, so `x` and
    /// `x/` name one route there. Keyed on the serialization instead, they are
    /// two records here: a withdraw spelled the other way leaves the first
    /// behind, and a stale `Live` root suppresses the scoped watch belonging to
    /// the route that actually serves the subtree — over a byte cache with no
    /// expiry, so the entries never refresh.
    ///
    /// This pins the KEYING half only. Once one node is one record, the two
    /// spellings cannot both be present, so no ranking rule can tell them
    /// apart — the ranking half is pinned by
    /// [`a_deeper_root_outranks_a_pinned_shallower_one`] instead.
    #[test]
    fn two_spellings_of_one_root_are_one_root() {
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));

        // Advertise slashless, refuse through the slashed spelling: one record,
        // reached by either name.
        state.advertise(&url("mem:///team"));
        state.refuse(&url("mem:///team/"));
        assert_eq!(
            state.probing_roots().len(),
            1,
            "one node must not advertise as two roots: {:?}",
            state.probing_roots()
        );
        assert_eq!(
            state.generation_of(&url("mem:///team")),
            state.generation_of(&url("mem:///team/")),
            "both spellings must name one advertisement"
        );

        // Neither spelling outranks the other, so the root still owns a scope
        // beneath it: `x/` must not appear to have taken it over from `x`.
        let generation = state.generation_of(&url("mem:///team"));
        assert!(
            state.still_owns_scope(&url("mem:///team"), generation, &url("mem:///team/proj/")),
            "one node took its own scope over from itself"
        );

        // A withdraw spelled the other way really removes it.
        state.withdraw(&url("mem:///team/"));
        assert!(
            state.probing_roots().is_empty(),
            "a withdraw spelled the other way left the root behind: {:?}",
            state.probing_roots()
        );
    }

    /// Roots are offered to selection longest-first, which is what makes the
    /// longest-prefix assignment above hold.
    #[test]
    fn probing_roots_are_ordered_longest_prefix_first() {
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&url("mem:///"));
        state.refuse(&url("mem:///"));
        state.advertise(&url("mem:///team/sub/"));
        state.refuse(&url("mem:///team/sub/"));
        state.advertise(&url("mem:///team/"));
        state.refuse(&url("mem:///team/"));
        assert_eq!(
            state
                .probing_roots()
                .iter()
                .map(|r| r.as_str().to_string())
                .collect::<Vec<_>>(),
            vec![
                "mem:///team/sub/".to_string(),
                "mem:///team/".to_string(),
                "mem:///".to_string()
            ]
        );
    }

    #[test]
    fn watch_invalidation_defaults_false_and_requires_bool() {
        assert!(!parse_watch_invalidation(&LayerConfig::new()).unwrap());
        let mut config = LayerConfig::new();
        config.insert(WATCH_INVALIDATION_KEY.to_string(), ConfigValue::Bool(true));
        assert!(parse_watch_invalidation(&config).unwrap());

        let mut bad = LayerConfig::new();
        bad.insert(
            WATCH_INVALIDATION_KEY.to_string(),
            ConfigValue::String("mock://bucket/".into()),
        );
        assert_eq!(
            parse_watch_invalidation(&bad).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    /// Every `StreamEnd`, in both directions: what it is classified as, and
    /// what the backoff does with it.
    ///
    /// Walks all four so the classification cannot be extended by adding an arm
    /// nothing exercises, and asserts the two properties that used to be
    /// answered by separate predicates that disagreed — the backoff, and
    /// whether the end counts as the watch having worked.
    #[test]
    fn reconnect_backoff_distinguishes_quick_empty_ends_from_stable_streams() {
        let end = |events, end, uptime| StreamEnd::of(&DrainOutcome { events, end }, uptime);
        let brief = Duration::from_millis(1);

        // Barren: nothing to show, however the stream ended. An error here is
        // the same signature as a clean drop and must be treated the same — it
        // was not, and a backend erroring on every open held its slots forever.
        for kind in [DrainEnd::Clean, DrainEnd::Error] {
            assert_eq!(end(0, kind, brief), StreamEnd::Barren);
        }
        // Ran: either because it carried events, or because it stayed up.
        assert_eq!(end(1, DrainEnd::Clean, brief), StreamEnd::Productive);
        assert_eq!(
            end(0, DrainEnd::Clean, MIN_STABLE_WATCH_UPTIME),
            StreamEnd::Productive
        );
        assert_eq!(end(1, DrainEnd::Error, brief), StreamEnd::Faulted);
        assert_eq!(
            end(0, DrainEnd::Error, MIN_STABLE_WATCH_UPTIME),
            StreamEnd::Faulted
        );
        assert_eq!(end(0, DrainEnd::Cancelled, brief), StreamEnd::Cancelled);

        // A stream that ran counts as having worked; one that showed nothing
        // does not, and neither does a cancellation.
        assert!(StreamEnd::Productive.worked());
        assert!(StreamEnd::Faulted.worked());
        assert!(!StreamEnd::Barren.worked());
        assert!(!StreamEnd::Cancelled.worked());

        // The backoff doubles on anything that did not end cleanly after
        // running, and resets otherwise.
        assert_eq!(
            drain_backoff_after(INITIAL_DRAIN_BACKOFF, StreamEnd::Barren),
            Duration::from_secs(1)
        );
        assert_eq!(
            drain_backoff_after(Duration::from_secs(8), StreamEnd::Faulted),
            Duration::from_secs(16)
        );
        assert_eq!(
            drain_backoff_after(Duration::from_secs(8), StreamEnd::Productive),
            INITIAL_DRAIN_BACKOFF
        );
        assert_eq!(
            drain_backoff_after(Duration::from_secs(8), StreamEnd::Cancelled),
            INITIAL_DRAIN_BACKOFF
        );
        assert_eq!(
            drain_backoff_after(MAX_DRAIN_BACKOFF, StreamEnd::Barren),
            MAX_DRAIN_BACKOFF,
            "and it is clamped"
        );
    }

    #[test]
    fn intentional_teardown_and_managed_clean_end_do_not_sweep() {
        for (cancelled, sweep_on_clean_end) in [(true, true), (false, false)] {
            let cancel = CancellationToken::new();
            if cancelled {
                cancel.cancel();
            }
            let swept = Arc::new(AtomicBool::new(false));
            let swept_on_gap = swept.clone();
            let mut stream = GapSweepStream::new(
                Box::new(std::iter::empty()),
                Some(cancel),
                sweep_on_clean_end,
                |_| {},
                move || swept_on_gap.store(true, Ordering::SeqCst),
            );
            assert!(stream.next().is_none());
            assert!(!swept.load(Ordering::SeqCst));
        }
    }

    /// A retiring drain holds a watch and a blocking-pool thread until its
    /// handle completes, and nothing notifies on that completion — so the
    /// supervisor has to look. `retiring` is pruned only inside
    /// `reconcile_scopes`, and without the timer a stable working set produces
    /// no wakes at all, so against a backend that DOES release its stream the
    /// entry would sit in the vector unreclaimed and the supervisor would keep
    /// believing a watch is winding down that finished long ago.
    #[test]
    fn a_retiring_drain_arms_the_supervisor_timer() {
        let scoped = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        assert!(
            !supervisor_needs_timer(0, false, &scoped),
            "with nothing outstanding the supervisor waits on reads alone"
        );
        assert!(
            supervisor_needs_timer(1, false, &scoped),
            "a retiring drain is a deadline: its completion is not an event"
        );
        assert!(
            supervisor_needs_timer(0, true, &scoped),
            "so is a candidate waiting for a live watch to go idle: idleness is \
             reached by a clock and produces no wake of its own"
        );
        // The two pre-existing deadlines still arm it, so the new clauses are
        // additions rather than replacements.
        let denied = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        denied.scopes.deny_both(&url("mem:///a/"));
        assert!(supervisor_needs_timer(0, false, &denied));
        let paused = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        paused.advertise(&url("mem:///"));
        paused.refuse(&url("mem:///"));
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES {
            paused.note_scope_outcome_now(&url("mem:///"), ScopeOutcome::Failed);
        }
        assert!(supervisor_needs_timer(0, false, &paused));
    }

    /// `Live` is a watch that is open now, for a root exactly as for a scope.
    /// A root whose stream ends stops reporting its subtree; leaving the record
    /// `Live` makes `covers` answer yes for a subtree nothing is watching, and
    /// makes selection retire the scoped drains under it as redundant. The
    /// reopen is not a state: it may fail retryably for a long time.
    #[test]
    fn a_root_stops_covering_when_its_watch_stream_ends() {
        let root = url("mem:///team/");
        let under = url("mem:///team/proj/obj");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.grant(&root);
        assert!(state.covers(&under), "the open watch reports its subtree");

        state.end_root_watch(&root);
        assert!(
            !state.covers(&under),
            "a watch whose stream ended reports nothing"
        );
        assert!(
            state.probing_roots().is_empty(),
            "and it has refused nothing, so nothing may be probed under it yet"
        );

        // The reopen answering is what moves it on, in either direction.
        state.grant(&root);
        assert!(state.covers(&under), "a successful reopen covers again");
        state.end_root_watch(&root);
        state.refuse(&root);
        assert_eq!(
            state.probing_roots(),
            vec![root],
            "a refused reopen starts probing the directories the cache holds"
        );
    }

    /// A root drain's open resolves with no cancellation check, so it can
    /// answer after `reconcile_roots` has withdrawn the route. Neither answer
    /// may re-create the record: a phantom `Live` root suppresses every scope
    /// beneath it and nothing can ever remove it, so the subtree would be
    /// TTL-only for the life of the process with no log line; a phantom
    /// `Refused` one holds scoped watches under a root that no longer routes.
    #[test]
    fn a_withdrawn_root_is_not_resurrected_by_a_late_answer() {
        let root = url("mem:///team/");
        let under = url("mem:///team/proj/obj");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.withdraw(&root);

        state.grant(&root);
        assert!(
            !state.covers(&under),
            "a withdrawn root must not come back as a live one"
        );
        state.refuse(&root);
        assert!(
            state.probing_roots().is_empty(),
            "a withdrawn root must not come back as a probing one"
        );

        // The control: while the root IS advertised both answers land, so the
        // assertions above are about withdrawal and not about the answers being
        // ignored.
        state.advertise(&root);
        state.refuse(&root);
        assert_eq!(state.probing_roots().len(), 1);
        state.grant(&root);
        assert!(state.covers(&under));
    }

    /// A cancellation the drain did not ask for is not a verdict on the prefix,
    /// and it is also not a reason to stop. The drain retries it with the
    /// ordinary doubling backoff.
    ///
    /// Exiting on it instead — which is what treating every `Cancelled` alike
    /// produces — leaves a finished drain in the supervisor's map with nothing
    /// recorded against its scope, so it is neither reaped nor re-spawned; and
    /// reaping it to fix that spins, because the scope is still a candidate and
    /// there is no backoff between a reap and the next spawn.
    ///
    /// Three affirmative readings: the backend is asked more than once, the
    /// directory is still a candidate, and the root's budget is unspent.
    #[tokio::test]
    async fn a_watch_open_cancelled_from_below_is_retried_not_denied() {
        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(CancellingWatchLayer {
            opens: opens.clone(),
        });
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = one_scope_under_a_refused_root("mem:///a/obj");
        let cancel = CancellationToken::new();

        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            url("mem:///"),
            url("mem:///a/"),
            current_generation(&scoped, "mem:///"),
            cancel.clone(),
            sweep,
            Arc::clone(&scoped),
            Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(false),
                live: std::sync::atomic::AtomicBool::new(false),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
                recursive: std::sync::atomic::AtomicBool::new(true),
            }),
        ));
        // INITIAL_DRAIN_BACKOFF is 500ms and doubles, so a second open proves a
        // retry rather than a spin, and a spin would be visible as a count far
        // above two.
        for _ in 0..600 {
            if opens.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            opens.load(Ordering::SeqCst) >= 2,
            "the open must be retried, got {} attempts",
            opens.load(Ordering::SeqCst)
        );
        assert!(
            !task.is_finished(),
            "a cancellation raised below the drain must not end it, or it is \
             left in the supervisor's map with nothing recorded against it"
        );
        assert!(
            scoped
                .scopes
                .candidates(&any_owner)
                .iter()
                .any(|scope| scope.as_str() == "mem:///a/"),
            "the directory must not be withheld for the denial window"
        );
        assert_eq!(
            scoped.probe_failures(&url("mem:///")),
            Some(0),
            "and the root's probe budget must not be charged"
        );

        // The drain's OWN token still ends it, which is what keeps the retry
        // from being a leak.
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the drain's own cancellation must still end it")
            .unwrap();
    }

    /// Retention past a spent probe budget is earned by a watch that was
    /// granted, not by a drain that exists. A drain still retrying its first
    /// open records no denial and is never charged to the budget, so retaining
    /// it on existence alone would let it hold a slot indefinitely under a root
    /// that has stopped probing — and the budget could never learn it was
    /// worthless.
    #[tokio::test]
    async fn a_paused_root_retains_only_the_drains_whose_watch_was_granted() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = one_scope_under_a_refused_root("mem:///a/obj");
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();

        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(drains.len(), 1, "the scope must be selected first");

        // Spend the budget. The drain's watch has never opened.
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES {
            scoped.note_scope_outcome_now(&url("mem:///"), ScopeOutcome::Failed);
        }
        assert!(scoped.probing_roots().is_empty());
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.is_empty(),
            "a drain that never opened is not evidence the root grants anything"
        );

        // The control, and the property saxon's finding is about: once the
        // watch HAS been granted, the same paused root keeps it rather than
        // cancelling a productive watch and sweeping its subtree.
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.is_empty(),
            "and a paused root opens nothing new, so the slot stays empty"
        );
        let granted = ScopeDrain {
            cancel: shutdown.child_token(),
            handle: tokio::spawn(std::future::pending::<()>()),
            signals: Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(true),
                live: std::sync::atomic::AtomicBool::new(true),
                recursive: std::sync::atomic::AtomicBool::new(true),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            }),
            root: url("mem:///"),
            generation: 0,
        };
        drains.insert("mem:///a/".to_string(), granted);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            1,
            "a watch the root granted survives the budget being spent"
        );
        shutdown.cancel();
    }

    /// A backend whose `watch_directory` parks forever without answering, so a
    /// scope drain is selected and running but its watch is never live.
    struct ParkingWatchLayer;

    #[async_trait]
    impl Layer for ParkingWatchLayer {
        fn name(&self) -> &str {
            "parking-watch"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            crate::layers::descriptor("parking-watch", LayerType::Backend, true)
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            std::future::pending::<()>().await;
            unreachable!("a parked open never resolves on its own")
        }
    }

    /// A backend whose open succeeds after the drain has been retired — the
    /// case `ScopeDrain::stop` creates by design, since it cancels without
    /// aborting and this whole fallback is built for backends that do not
    /// observe watch cancellation.
    struct OpensAfterCancellationLayer {
        cancel: CancellationToken,
        opens: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Layer for OpensAfterCancellationLayer {
        fn name(&self) -> &str {
            "opens-after-cancellation"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            crate::layers::descriptor("opens-after-cancellation", LayerType::Backend, true)
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            // Retired while the open was in flight, and the backend answers
            // anyway rather than observing the token.
            self.cancel.cancel();
            Ok(Box::new(std::iter::empty()))
        }
    }

    /// An open that lands after retirement records nothing and sweeps nothing.
    ///
    /// The supervisor has already stopped believing in this drain. Acting on
    /// the open would refund the root's probe budget from a watch nobody
    /// selected — the mirror of the refusal the `Err` arm is guarded against
    /// charging — and, worse, run a subtree invalidation of a **persistent**
    /// cache for a scope that is no longer watched. That includes scopes
    /// retired precisely because they never opened, which retirement
    /// deliberately does not sweep, and it includes the way down:
    /// `CacheWatchState::drop` cancels the scope drains without aborting them.
    #[tokio::test]
    async fn an_open_that_lands_after_retirement_records_nothing() {
        let cancel = CancellationToken::new();
        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(OpensAfterCancellationLayer {
            cancel: cancel.clone(),
            opens: Arc::clone(&opens),
        });
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = one_scope_under_a_refused_root("mem:///a/obj");
        // Eight failures already charged, so a refund would be visible.
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES {
            scoped.note_scope_outcome_now(&url("mem:///"), ScopeOutcome::Failed);
        }
        let charged = scoped.probe_failures(&url("mem:///"));

        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(true),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
        });
        scope_drain_task(
            Arc::downgrade(&layer),
            url("mem:///"),
            url("mem:///a/"),
            current_generation(&scoped, "mem:///"),
            cancel,
            sweep,
            Arc::clone(&scoped),
            Arc::clone(&signals),
        )
        .await;

        assert_eq!(
            opens.load(Ordering::SeqCst),
            1,
            "the open must have happened, or this test measures nothing"
        );
        assert!(
            swept.lock().unwrap().is_empty(),
            "a retired drain must not invalidate a subtree of a persistent \
             cache, got {:?}",
            swept.lock().unwrap()
        );
        assert_eq!(
            scoped.probe_failures(&url("mem:///")),
            charged,
            "and it must not refund the probe budget from an open nobody wanted"
        );
        assert!(
            !signals.live.load(Ordering::SeqCst),
            "nor publish itself as a live watch the supervisor could collapse \
             other scopes onto"
        );
    }

    /// A backend that answers `Cancelled` without this drain's own token having
    /// fired — a cancellation raised below the cache. The drain must not read
    /// it as a verdict on the prefix, which means it exits recording nothing.
    struct CancellingWatchLayer {
        opens: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Layer for CancellingWatchLayer {
        fn name(&self) -> &str {
            "cancelling-watch"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            crate::layers::descriptor("cancelling-watch", LayerType::Backend, true)
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(
                ErrorCode::Cancelled,
                "cancelled below the cache",
            ))
        }
    }

    /// One refused root with one cached directory under it, and the supervisor
    /// state to reconcile it against.
    fn one_scope_under_a_refused_root(scope_of_read: &str) -> Arc<ScopedWatchState> {
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        scoped.note_cached(&url(scope_of_read));
        scoped
    }

    /// A watch that loses its slot invalidates what it was keeping fresh.
    ///
    /// Its entries were filled while it was live, so they were never TTL-bound
    /// — the byte cache has no TTL — and after retirement nothing reports the
    /// subtree at all. Being early costs a refetch; being late has no expiry.
    #[tokio::test]
    async fn a_displaced_watch_sweeps_the_subtree_it_was_protecting() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        for i in 0..=MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(drains.len(), MAX_WATCH_SCOPES);

        // Every incumbent's watch is open, so all of them are protected — until
        // one directory stops being read.
        for drain in drains.values() {
            drain.signals.live.store(true, Ordering::SeqCst);
            drain.signals.ever_opened.store(true, Ordering::SeqCst);
        }
        {
            let mut table = scoped.scopes.table.lock().unwrap();
            let idle = table
                .scopes
                .get_mut("mem:///d1/")
                .expect("d1 is a candidate");
            idle.direct_touch -= MIN_WATCH_RESIDENCY * 2;
        }
        scoped.note_cached(&url("mem:///d0/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.contains_key("mem:///d0/") && !drains.contains_key("mem:///d1/"),
            "the idle watch is the one that yields, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            *swept.lock().unwrap(),
            vec!["mem:///d1/".to_string()],
            "and exactly its subtree is invalidated on the way out"
        );
        shutdown.cancel();
    }

    /// Displacement protection belongs to a watch that has opened, not to one
    /// that is intended. A scope whose open never completes — a connection that
    /// never answers, which is what `ParkingWatchLayer` models — or one that
    /// keeps failing retryably records no denial and spends no budget, so
    /// protecting intent would let four such directories pin every slot for the
    /// life of the process and leave no room for a directory that could be
    /// watched.
    ///
    /// It is `ever_opened` and not `live`: a watch between streams is reopening
    /// after a backoff, and a reconcile landing in that window must not tear
    /// down and sweep a directory read a second ago.
    #[tokio::test(start_paused = true)]
    async fn only_a_scope_whose_watch_has_opened_holds_an_undisplaceable_slot() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        // One more hot directory than the budget can watch. The registry holds
        // all of them; selection is what has to choose.
        for i in 0..=MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();

        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES,
            "the budget must be full, or this test measures nothing"
        );
        assert!(
            !drains.contains_key("mem:///d0/"),
            "the coldest candidate is the one that misses out"
        );

        // Every open is still parked, so nothing is protected — until each
        // watch opens, after which the coldest directory becoming the hottest
        // takes nothing back.
        for i in 1..=MAX_WATCH_SCOPES {
            let signals = &drains[&format!("mem:///d{i}/")].signals;
            signals.ever_opened.store(true, Ordering::SeqCst);
            signals.live.store(true, Ordering::SeqCst);
        }
        scoped.note_cached(&url("mem:///d0/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            !drains.contains_key("mem:///d0/"),
            "a watch on a directory still being read keeps its slot, however hot \
             the newcomer"
        );
        assert!(
            retiring.is_empty(),
            "and nothing was torn down to find that out"
        );

        // A reconnect is not a loss of protection. Every stream ends and
        // reopens after a backoff, and a reconcile landing in that window would
        // otherwise sweep a subtree per reconnect.
        for i in 1..=MAX_WATCH_SCOPES {
            drains[&format!("mem:///d{i}/")].signals.note_stream_ended();
        }
        tokio::time::advance(MAX_DRAIN_BACKOFF / 2).await;
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            !drains.contains_key("mem:///d0/") && retiring.is_empty(),
            "a watch between streams keeps its slot, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );

        // The control, and the other half of the rule: a reopen has no
        // deadline, so a watch whose every attempt hangs would otherwise hold
        // its slot for the life of the process while reporting nothing. Past
        // `MAX_DRAIN_BACKOFF` since its stream ended it is wedged rather than
        // reconnecting, and a directory that could be watched takes the slot.
        // Every directory is re-read afterwards, so nothing here changes which
        // of them are being read — only how long the watches have been silent.
        tokio::time::advance(MAX_DRAIN_BACKOFF * 4).await;
        for i in 1..=MAX_WATCH_SCOPES {
            scoped.note_cached(&url(&format!("mem:///d{i}/obj")));
        }
        // `d0` last, so it is the hottest candidate exactly as it was in the
        // two assertions above.
        scoped.note_cached(&url("mem:///d0/obj"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.contains_key("mem:///d0/"),
            "an unproven slot must be displaceable, or the watch set could never \
             follow a working set that moves"
        );
        shutdown.cancel();
    }

    /// Which cover gets the one slot above the budget must not depend on
    /// recency. Two covers of two busy subtrees would otherwise swap it every
    /// time a read landed under the other, and a swap is not free: the loser is
    /// retired and its subtree swept, so a workload reading under both would
    /// discard a subtree per alternation, forever.
    #[test]
    fn the_cover_that_gets_the_extra_slot_does_not_change_with_the_last_read() {
        let roots = probing_views(&[url("mem:///")]);
        let protected: Vec<String> = ["mem:///p/a/", "mem:///p/b/", "mem:///q/a/"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        // `mem:///p/` subsumes two of the protected scopes and `mem:///q/` one,
        // so the answer is `mem:///p/` whichever was read last.
        let hot_q = [
            url("mem:///q/"),
            url("mem:///p/"),
            url("mem:///p/a/"),
            url("mem:///p/b/"),
            url("mem:///q/a/"),
        ];
        let hot_p = [
            url("mem:///p/"),
            url("mem:///q/"),
            url("mem:///p/a/"),
            url("mem:///p/b/"),
            url("mem:///q/a/"),
        ];
        for (order, name) in [(&hot_q, "q read last"), (&hot_p, "p read last")] {
            // Neither cover has opened, so neither covers anything yet — which
            // is the state this rule exists for.
            let selected = scope_urls(&select_scopes(
                &roots,
                order,
                MAX_WATCH_SCOPES,
                &|_: &SelectedScope| false,
                &|_| true,
                &[],
                &protected_under("mem:///", &protected),
            ));
            assert!(
                selected.contains(&"mem:///p/".to_string()),
                "the cover of the larger subtree must win with {name}, got {selected:?}"
            );
            // The subject is which cover gets the OVERSHOOT, so that is what is
            // asserted: at most one slot above the budget, and it is `p`'s.
            // Asserting `q`'s absence instead would pin the runner-up being
            // disqualified from the ordinary budget, which was a defect rather
            // than the rule — with a free slot `q` should compete for it like
            // any other candidate.
            assert!(
                selected.len() <= MAX_WATCH_SCOPES + 1,
                "the overshoot stays one slot, got {selected:?}"
            );
        }

        // With room to spare, the runner-up is an ordinary candidate and takes
        // an in-budget slot. It is not disqualified for having been a cover.
        let roomy = scope_urls(&select_scopes(
            &roots,
            &hot_p,
            MAX_WATCH_SCOPES + 1,
            &|_: &SelectedScope| false,
            &|_| true,
            &[],
            &protected_under("mem:///", &protected),
        ));
        assert!(
            roomy.contains(&"mem:///q/".to_string()),
            "a cover that lost the overshoot still competes normally, got {roomy:?}"
        );
    }

    /// A scope drain belongs to one advertisement of one root, not to a URL.
    ///
    /// Two things change the owner without changing any URL. `reconcile_roots`
    /// withdraws and re-advertises a root whose connection or route changed,
    /// and the drain's already-open stream stays bound to the old connection —
    /// so mutations on the replacement never reach it and its subtree is stale
    /// with nothing to expire it — the byte cache has no TTL. And a newly
    /// advertised nested root takes over the scopes beneath it by longest
    /// prefix, after which every outcome the drain reports is charged to a root
    /// that no longer owns it: the old root can be paused by failures it did
    /// not cause while the new one never accumulates the failures it did.
    #[tokio::test]
    async fn a_scope_drain_is_replaced_when_its_root_advertisement_is() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        scoped.note_cached(&url("mem:///team/proj/obj"));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let first = drains["mem:///team/proj/"].generation;
        assert_eq!(
            drains["mem:///team/proj/"].root.as_str(),
            "mem:///",
            "the only advertised root owns it to begin with"
        );

        // A nested root is advertised. That is a route mounted OVER this
        // subtree: reads for it now dispatch to a different backend while the
        // drain's open stream is still on the old one, so the drain must go and
        // its sweep must take the entries the old route produced with it. Until
        // the new root answers the scope is TTL-only, exactly as it is under
        // any root that has not answered yet. The drain's watch is OPEN, not
        // merely opened once. Retirement for a changed route is the one reason
        // that must not consult the watch's own liveness: a stream reporting a
        // backend the subtree no longer routes to is exactly the watch to end,
        // and the healthier it looks the longer it would go on answering for
        // entries nobody fetches from there. Setting `live` here is what makes
        // a guard of the form "keep a watch that is working" fail this test
        // rather than pass it.
        let signals = &drains
            .get_mut("mem:///team/proj/")
            .expect("a drain")
            .signals;
        signals.ever_opened.store(true, Ordering::SeqCst);
        signals.live.store(true, Ordering::SeqCst);
        scoped.advertise(&url("mem:///team/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            !drains.contains_key("mem:///team/proj/"),
            "a drain on the route that no longer serves this subtree must go, \
             got {:?}",
            drains.keys().collect::<Vec<_>>()
        );

        // Once the new root refuses, the scope is genuinely its to probe, and
        // the drain is reopened against the route that now serves it.
        scoped.refuse(&url("mem:///team/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains["mem:///team/proj/"].root.as_str(),
            "mem:///team/",
            "a reassigned scope must be reopened under the root that now owns it"
        );
        let reassigned = drains["mem:///team/proj/"].generation;
        assert_ne!(reassigned, first);

        // A route rebind withdraws and re-advertises the same URL. The stream
        // the running drain holds is bound to the old connection, so the URL
        // matching is exactly what must NOT keep it.
        //
        // The rebound root starts `Pending`, which admits no probes — and a
        // drain that has opened is otherwise exempt from that, which is the
        // rule that would keep this one alive under a route it no longer
        // belongs to. Marking it opened is what puts the exemption in play.
        drains["mem:///team/proj/"]
            .signals
            .ever_opened
            .store(true, Ordering::SeqCst);
        drains["mem:///team/proj/"]
            .signals
            .live
            .store(true, Ordering::SeqCst);
        scoped.withdraw(&url("mem:///team/"));
        scoped.advertise(&url("mem:///team/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            !drains.contains_key("mem:///team/proj/"),
            "a drain bound to a withdrawn route is not the watch the retention \
             rule is arguing for, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );

        scoped.refuse(&url("mem:///team/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_ne!(
            drains["mem:///team/proj/"].generation, reassigned,
            "and it is reopened against the root that now routes it"
        );

        // The control: with the root set unchanged, a reconcile keeps the drain
        // it has — so the two assertions above are about the advertisement
        // changing and not about every reconcile replacing everything.
        let stable = drains["mem:///team/proj/"].generation;
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(drains["mem:///team/proj/"].generation, stable);

        // And the third way a route goes: withdrawn with nothing advertised in
        // its place. A scope no advertised root owns has no route for its
        // stream to be bound to, so the drain goes for the same reason the two
        // above did — again with its watch open, since a route that no longer
        // exists is not made current by the watch on it still reporting.
        drains["mem:///team/proj/"]
            .signals
            .live
            .store(true, Ordering::SeqCst);
        scoped.withdraw(&url("mem:///team/"));
        scoped.withdraw(&url("mem:///"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.is_empty(),
            "a scope no advertised root owns keeps no drain, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        shutdown.cancel();
    }

    /// A watch that degraded to its immediate children stops collapsing the
    /// scopes below it, and the supervisor learns that from the drain rather
    /// than from selection.
    ///
    /// `ScopeView::covers_below` is `live` AND `recursive`, and only the second
    /// half distinguishes a watch that reports a subtree from one that reports
    /// a directory listing. Dropping it would collapse every descendant onto a
    /// watch that says nothing about them — entries with no watch and, with
    /// nothing to expire them: the byte cache has no TTL. The rule is stated
    /// against a hand-written `can_cover` by
    /// `a_degraded_scope_does_not_cover_the_scopes_beneath_it`; this drives the
    /// supervisor's own derivation of it from the drain's signals. The drain
    /// side — the degrade path that clears `recursive` — is written here by
    /// hand and is not covered by either.
    #[tokio::test]
    async fn a_degraded_watch_does_not_collapse_the_scopes_below_it() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = one_scope_under_a_refused_root("mem:///a/b/obj");
        scoped.note_cached(&url("mem:///a/"));
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.len(),
            2,
            "both directories start with a watch of their own, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );

        // Both watches open. `mem:///a/`'s recursive form was refused, so it
        // opened for its immediate children only: it is live, and it still
        // reports nothing about `mem:///a/b/`. The descendant's watch is open
        // too, so the subtree it protects is real and a collapse has something
        // to invalidate.
        let ancestor = &drains["mem:///a/"].signals;
        ancestor.ever_opened.store(true, Ordering::SeqCst);
        ancestor.live.store(true, Ordering::SeqCst);
        ancestor.recursive.store(false, Ordering::SeqCst);
        let descendant = &drains["mem:///a/b/"].signals;
        descendant.ever_opened.store(true, Ordering::SeqCst);
        descendant.live.store(true, Ordering::SeqCst);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.contains_key("mem:///a/b/"),
            "a degraded watch reports nothing below its immediate children, so \
             the scope beneath it keeps its own, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        assert!(
            swept.lock().unwrap().is_empty(),
            "and it is the SAME drain, not a retire-and-respawn: a replacement \
             would have swept the subtree it was protecting, got {:?}",
            swept.lock().unwrap()
        );

        // The control: the same watch, recursive, does collapse it — so the
        // assertion above is about the mode and not about the scope being
        // unconditionally kept.
        drains["mem:///a/"]
            .signals
            .recursive
            .store(true, Ordering::SeqCst);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(
            drains.keys().collect::<Vec<_>>(),
            vec!["mem:///a/"],
            "control: a recursive watch above it serves the whole subtree, so \
             exactly the ancestor is left"
        );
        assert_eq!(
            *swept.lock().unwrap(),
            vec!["mem:///a/b/".to_string()],
            "and the collapse invalidates what the narrower watch was keeping \
             fresh, since the cover's own activation sweep has already run"
        );
        shutdown.cancel();
    }

    /// A takeover the supervisor sees only after the new root has answered.
    ///
    /// `advertise` does not wake the supervisor, so a reconcile can land after
    /// both the advertisement of a nested root and its refusal. Then the scope
    /// IS selected — under the new root, which admits probes — and selection
    /// asking for a scope the map already has a drain for is exactly the case a
    /// key comparison reads as "nothing to do". Only matching the drain against
    /// the root and generation it was opened under retires it, so the stream
    /// bound to the route that no longer serves the subtree is replaced by one
    /// on the route that does.
    ///
    /// The other orderings in
    /// `a_scope_drain_is_replaced_when_its_root_advertisement_is` retire the
    /// drain a step earlier, because a root that has not answered admits no
    /// probes and the scope is not selected at all. This is the interleaving
    /// where the identity match is the only thing that acts.
    #[tokio::test]
    async fn a_takeover_that_is_already_refused_still_replaces_the_drain() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = one_scope_under_a_refused_root("mem:///team/proj/obj");
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let held = drains.get("mem:///team/proj/").expect("a drain");
        assert_eq!(held.root.as_str(), "mem:///");
        let first = held.generation;
        held.signals.ever_opened.store(true, Ordering::SeqCst);
        held.signals.live.store(true, Ordering::SeqCst);

        // Both root changes land between reconciles, so the new root is already
        // probing the first time selection sees it.
        scoped.advertise(&url("mem:///team/"));
        scoped.refuse(&url("mem:///team/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let held = drains
            .get("mem:///team/proj/")
            .expect("the scope is still worth watching, under whoever owns it");
        assert_eq!(
            held.root.as_str(),
            "mem:///team/",
            "the drain must be the one opened against the route that now serves \
             this subtree"
        );
        assert_ne!(
            held.generation, first,
            "and a same-URL keep is not a replacement: the old stream is on the \
             old route"
        );
        assert_eq!(
            *swept.lock().unwrap(),
            vec!["mem:///team/proj/".to_string()],
            "the entries the old route produced go with it, since nothing else \
             answers for a subtree that has moved"
        );
        shutdown.cancel();
    }

    /// A root's own watch coming up retires the scoped watches beneath it, and
    /// that too is decided without asking whether they are working.
    ///
    /// Redundancy is a question about the watch ABOVE — is this subtree already
    /// being reported — so the answer rests on the root's liveness, not on the
    /// scope's. A scope watch retired here is by construction a healthy one:
    /// probing only started because the root was refused, and the root granting
    /// it later is the good outcome, not a failure. Keeping the narrower
    /// watches on the grounds that they are working is how the budget stays
    /// spent on duplicates of a watch that already covers them — a thread and a
    /// Tokio runtime each on the broker client — for as long as they keep
    /// succeeding.
    #[tokio::test]
    async fn a_live_scoped_watch_yields_to_its_roots_own_watch() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let swept: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&swept);
        let sweep: RootSweep = Arc::new(move |prefix: &Url| {
            recorder.lock().unwrap().push(prefix.as_str().to_string());
        });
        let scoped = one_scope_under_a_refused_root("mem:///team/proj/obj");
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let signals = &drains
            .get("mem:///team/proj/")
            .expect("the refused root's one cached directory is probed")
            .signals;
        signals.ever_opened.store(true, Ordering::SeqCst);
        signals.live.store(true, Ordering::SeqCst);

        // A policy reload grants the root, so its own recursive watch opens.
        scoped.grant(&url("mem:///"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.is_empty(),
            "a watch the root's own watch now covers is redundant however well \
             it is working, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            *swept.lock().unwrap(),
            vec!["mem:///team/proj/".to_string()],
            "and it sweeps on the way out: its entries were filled while it was \
             live, and the root watch's own activation sweep is the only other \
             thing that would cover them"
        );

        // The control: the same reconcile with the root still refused keeps the
        // drain, so the assertion above is about the root's watch coming up and
        // not about every reconcile discarding everything.
        scoped.refuse(&url("mem:///"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(drains.contains_key("mem:///team/proj/"));
        drains["mem:///team/proj/"]
            .signals
            .live
            .store(true, Ordering::SeqCst);
        drains["mem:///team/proj/"]
            .signals
            .ever_opened
            .store(true, Ordering::SeqCst);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(drains.contains_key("mem:///team/proj/"));
        shutdown.cancel();
    }

    /// What "working recently" means, in all four directions.
    ///
    /// The interval covers a sleep AND the open that follows it, because an
    /// open has no deadline of its own — measured against one backoff, a
    /// healthy watch whose reopen takes a moment is read as wedged and swept
    /// just before its stream comes up. A watch that never opened is not
    /// working; neither is one whose streams keep ending at once with no
    /// events, at any point in its life, because the drain declines to stamp
    /// those and `NEVER_STOPPED` is not a reading the grace applies to; and
    /// neither is one silent far past the interval.
    #[tokio::test(start_paused = true)]
    async fn a_watch_is_working_while_it_is_open_or_briefly_between_streams() {
        let signals = ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(true),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
        };
        assert!(
            !signals.working_recently(),
            "a watch that never opened has proved nothing"
        );

        // Opened, and every stream since has ended at once with no events: the
        // drain clears `live` on those and deliberately does not stamp. This is
        // the state a backend that accepts every watch and drops it sits in,
        // and it must not qualify — not even for the reconnect grace, which is
        // what a zero `stopped_at_millis` would have granted it for the drain's
        // first two backoffs. Four such prefixes would otherwise hold every
        // slot for that window while a prefix whose watch would work goes
        // unselected.
        signals.ever_opened.store(true, Ordering::SeqCst);
        assert!(
            !signals.working_recently(),
            "a watch whose every stream ended at once has not been working"
        );
        tokio::time::advance(MAX_DRAIN_BACKOFF / 4).await;
        assert!(
            !signals.working_recently(),
            "and it does not qualify early in the drain's life either"
        );

        signals.live.store(true, Ordering::SeqCst);
        tokio::time::advance(MAX_DRAIN_BACKOFF * 10).await;
        assert!(
            signals.working_recently(),
            "an open watch is working however long it has been open"
        );

        signals.note_stream_ended();
        // Past a full backoff, which is where the open it is about to make
        // begins — the interval has to cover that open too.
        tokio::time::advance(MAX_DRAIN_BACKOFF + Duration::from_secs(5)).await;
        assert!(
            signals.working_recently(),
            "and it stays so through a full backoff, with room for the open"
        );
        tokio::time::advance(MAX_DRAIN_BACKOFF * 2).await;
        assert!(
            !signals.working_recently(),
            "but a watch silent far past that is wedged, not reconnecting"
        );
    }

    /// A candidate above a live watch is a consolidation, not a newcomer, and
    /// deferring it is a deadlock rather than a wait: it can only cover by
    /// opening and only open by being selected, while the reads that keep its
    /// descendants protected are the same reads — through the ancestor touch —
    /// that keep it the hottest candidate there is. Worse, the broader
    /// directory's own entries, the listing that registered it, would be
    /// watched by nothing at all, with no TTL under them: the byte cache has
    /// none. It is given one slot ABOVE the budget rather than taking one from
    /// the subtree it subsumes. An open has no deadline, so a cover whose watch
    /// never answers would otherwise have spent a working narrower watch on
    /// nothing, permanently and in the direction that cannot be undone. The
    /// overshoot is one slot however many covers appear, and it ends when the
    /// cover opens.
    #[tokio::test]
    async fn a_cover_gets_a_slot_rather_than_waiting_to_be_able_to_open() {
        let layer: Arc<dyn Layer> = Arc::new(ParkingWatchLayer);
        let weak = Arc::downgrade(&layer);
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let scoped = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        scoped.advertise(&url("mem:///"));
        scoped.refuse(&url("mem:///"));
        // Every affordable watch spent on busy children of one project
        // directory, plus one unrelated directory that is colder than all of
        // them.
        scoped.note_cached(&url("mem:///q/obj"));
        for i in 0..MAX_WATCH_SCOPES - 1 {
            scoped.note_cached(&url(&format!("mem:///p/c{i}/obj")));
        }
        let shutdown = CancellationToken::new();
        let mut drains = HashMap::new();
        let mut retiring = Vec::new();
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert_eq!(drains.len(), MAX_WATCH_SCOPES);
        for drain in drains.values() {
            drain.signals.ever_opened.store(true, Ordering::SeqCst);
            drain.signals.live.store(true, Ordering::SeqCst);
        }

        // Now the project directory itself is listed. Its watch has not opened,
        // so it covers nothing yet and cannot collapse the children.
        scoped.note_cached(&url("mem:///p/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.contains_key("mem:///p/"),
            "the cover must get a slot, or it can never open, cover, or \
             consolidate — got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            drains.len(),
            MAX_WATCH_SCOPES + 1,
            "and it must cost nothing that was working — the overshoot is one \
             slot, not a teardown, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );
        assert!(
            retiring.is_empty(),
            "so nothing is torn down and nothing is swept"
        );

        // A second cover does not buy a second slot: the overshoot is one.
        scoped.note_cached(&url("mem:///q/sub/obj"));
        scoped.note_cached(&url("mem:///q/"));
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        assert!(
            drains.len() <= MAX_WATCH_SCOPES + 1,
            "the overshoot is capped however many covers appear, got {:?}",
            drains.keys().collect::<Vec<_>>()
        );

        // Once its watch is open and recursive, the rest of the subtree
        // collapses onto it and gives its slots back.
        drains["mem:///p/"]
            .signals
            .live
            .store(true, Ordering::SeqCst);
        drains["mem:///p/"]
            .signals
            .ever_opened
            .store(true, Ordering::SeqCst);
        reconcile_scopes(
            &mut drains,
            &mut retiring,
            &weak,
            &shutdown,
            &sweep,
            &scoped,
        )
        .await;
        let mut held: Vec<&String> = drains.keys().collect();
        held.sort();
        assert_eq!(
            held,
            vec!["mem:///p/", "mem:///q/"],
            "one recursive watch serves the whole project directory"
        );
        shutdown.cancel();
    }

    /// The probe budget must survive the refusals that feed it. The root drain
    /// re-attempts its own watch on `DENIED_SCOPE_RETRY` and re-enters scoped
    /// mode on every refusal, so a state write that replaced the entry would
    /// reset the budget on exactly that interval — in the one deployment the
    /// budget exists for, where the root refusal recurs forever.
    #[test]
    fn re_entering_scoped_mode_does_not_refund_the_probe_budget() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES {
            // The root's own re-refusal interleaves with the scope failures,
            // which is what the deployment actually does.
            state.advertise(&root);
            state.refuse(&root);
            state.note_scope_outcome_now(&root, ScopeOutcome::Failed);
        }
        assert!(
            state.probing_roots().is_empty(),
            "the budget must still be spent after the root re-refuses"
        );
        assert!(state.has_pending_deadline());

        // The control: the budget is not permanent. A granted scope clears it,
        // so "empty" above means "paused", not "never probes again".
        state.note_scope_outcome_now(&root, ScopeOutcome::Worked);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "a granted watch clears the count even while paused"
        );
    }

    /// Spending a root's probe budget stops NEW probes under it. It must not
    /// retire the watches that are already open: a root that granted a watch is
    /// not a root that grants nothing, and retiring one cancels a live watch
    /// and sweeps the subtree it was keeping fresh.
    #[test]
    fn a_spent_probe_budget_stops_new_probes_without_retiring_open_ones() {
        let paused = vec![RootView {
            root: url("mem:///"),
            generation: 0,
            covers: false,
            admits_probes: false,
        }];
        let candidates = [url("mem:///open/"), url("mem:///fresh/")];
        let running = vec![("mem:///open/".to_string(), url("mem:///"), 0u64)];
        let selected = select_unprotected(
            &paused,
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &running,
        );
        assert_eq!(
            scope_urls(&selected),
            vec!["mem:///open/".to_string()],
            "the running drain is retained and the new one is not admitted"
        );

        // The control: the same inputs under a root that is still probing admit
        // both, so the retention above is the budget speaking and not the
        // antichain or the recency order.
        let probing = probing_views(&[url("mem:///")]);
        let mut both = scope_urls(&select_unprotected(
            &probing,
            &candidates,
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        ));
        both.sort();
        assert_eq!(
            both,
            vec!["mem:///fresh/".to_string(), "mem:///open/".to_string()]
        );
    }

    /// Assignment runs over every advertised root, exactly as the router
    /// dispatches — not over the refused ones alone. With an outer root refused
    /// and an inner one granted, a scope under the inner root would otherwise
    /// match the outer one and take a scoped watch the granted root watch
    /// already covers: a duplicate thread and runtime per scope, and a swept
    /// subtree when it retires.
    #[test]
    fn a_scope_under_a_live_root_watch_is_not_watched_again() {
        let roots = vec![
            RootView {
                root: url("mem:///team/"),
                generation: 0,
                covers: true,
                admits_probes: false,
            },
            RootView {
                root: url("mem:///"),
                generation: 0,
                covers: false,
                admits_probes: true,
            },
        ];
        let selected = select_unprotected(
            &roots,
            &[url("mem:///team/proj/"), url("mem:///other/")],
            MAX_WATCH_SCOPES,
            &covers_all(),
            &[],
        );
        assert_eq!(
            scope_urls(&selected),
            vec!["mem:///other/".to_string()],
            "only the scope under the REFUSED root needs a watch of its own"
        );

        // Coverage outranks retention, which is what separates it from a spent
        // probe budget: a paused root keeps the drains it already opened, but a
        // root whose own watch came up makes them redundant, so a scope already
        // running under it is retired rather than kept.
        let running = vec![("mem:///team/proj/".to_string(), url("mem:///team/"), 0u64)];
        assert!(
            select_unprotected(
                &roots,
                &[url("mem:///team/proj/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &running,
            )
            .is_empty(),
            "a live root watch retires the scoped watch beneath it"
        );
        let paused = vec![RootView {
            root: url("mem:///team/"),
            generation: 0,
            covers: false,
            admits_probes: false,
        }];
        assert_eq!(
            scope_urls(&select_unprotected(
                &paused,
                &[url("mem:///team/proj/")],
                MAX_WATCH_SCOPES,
                &covers_all(),
                &running,
            )),
            vec!["mem:///team/proj/".to_string()],
            "control: a merely paused root keeps the drain it already opened"
        );

        // The registry records a covered directory like any other, and the
        // registry is the only record of what the cache holds when that root's
        // watch is refused later. Because being a candidate is not holding a
        // watch, this costs nothing a directory that does need one would want.
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&url("mem:///team/"));
        state.grant(&url("mem:///team/"));
        state.advertise(&url("mem:///"));
        state.refuse(&url("mem:///"));
        for i in 0..MAX_WATCH_SCOPES {
            state.note_cached(&url(&format!("mem:///team/proj{i}/obj")));
        }
        state.note_cached(&url("mem:///other/obj"));
        let candidates = state.scopes.candidates(&any_owner);
        assert_eq!(
            candidates.len(),
            MAX_WATCH_SCOPES + 1,
            "a covered directory is still a candidate: its root's watch can be \
             refused later, and nothing else remembers what the cache holds"
        );
        assert_eq!(
            scope_urls(&select_unprotected(
                &state.root_views(),
                &candidates,
                MAX_WATCH_SCOPES,
                &covers_all(),
                &[],
            )),
            vec!["mem:///other/".to_string()],
            "and only the directory under the refused root spends a watch"
        );

        // The control: a read under a root whose watch has NOT opened is not
        // covered. Treating advertisement as coverage would give that subtree
        // no watch at all.
        let pending = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        pending.advertise(&url("mem:///team/"));
        assert!(!pending.covers(&url("mem:///team/proj/obj")));
    }

    /// A backend whose first watch open ends immediately with an empty stream
    /// and whose every later open honours its cancel token by answering
    /// [`ErrorCode::Cancelled`], as the `Layer` contract requires of a method
    /// given a token that fires mid-flight.
    ///
    /// That sequence puts the cancellation in the window it actually lands in:
    /// a reopen, after the watch has been live once.
    struct CancelOnReopenLayer {
        opens: Arc<AtomicUsize>,
        reopening: Arc<AtomicBool>,
        /// Whether the reopen waits for its cancel token before answering. With
        /// it clear the answer is a cancellation raised BELOW the cache, which
        /// is the case the drain's own token cannot describe.
        await_token: bool,
    }

    #[async_trait]
    impl Layer for CancelOnReopenLayer {
        fn name(&self) -> &str {
            "cancel-on-reopen"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            crate::layers::descriptor("cancel-on-reopen", LayerType::Backend, true)
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            if self.opens.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(Box::new(std::iter::empty()));
            }
            self.reopening.store(true, Ordering::SeqCst);
            if self.await_token
                && let Some(cancel) = cancel
            {
                cancel.cancelled().await;
            }
            Err(Error::new(ErrorCode::Cancelled, "watch open cancelled"))
        }
    }

    /// A root whose drain dies non-retryably stops admitting probes.
    ///
    /// The refusal path keeps retrying the root every `DENIED_SCOPE_RETRY`, and
    /// any of those retries can answer `Unsupported`, or `Internal` from a
    /// broker hiccup — neither retryable, both ending the drain. The root then
    /// held `Refused` with a dead drain: `admits_probes` stayed true, so the
    /// supervisor kept opening scoped watches under a backend that had already
    /// answered non-retryably, for the life of the process, and nothing could
    /// clear it because only the drain that just died wrote that state.
    ///
    /// `only_a_refusal_narrows_the_watch` pins the contrast: a root that never
    /// refused stays absorbing-`Pending` and admits nothing. This is the same
    /// situation reached from the other side.
    #[test]
    fn a_root_whose_drain_dies_terminally_stops_probing() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        assert!(
            state.root_views().iter().any(|view| view.admits_probes),
            "a refused root must admit probes, or this test starts where it \
             means to end"
        );

        // A stale drain's terminal end must not silence the live route.
        state.root_unwatchable(&root, generation.wrapping_add(1));
        assert!(
            state.root_views().iter().any(|view| view.admits_probes),
            "a terminal end from a withdrawn advertisement must not silence \
             the one that replaced it"
        );

        state.root_unwatchable(&root, generation);
        let views = state.root_views();
        let view = views.first().expect("the root is still advertised");
        assert!(
            !view.admits_probes,
            "a root that answered non-retryably must stop being probed"
        );
        assert!(
            !view.covers,
            "and it covers nothing, so the scopes below are not suppressed \
             either — as silent as Pending, which is the point"
        );

        // Recovery is re-advertisement, the same event that recovers any route
        // change, rather than a retry loop against a non-retryable answer.
        state.withdraw(&root);
        state.advertise(&root);
        state.refuse(&root);
        assert!(
            state.root_views().iter().any(|view| view.admits_probes),
            "re-advertising the root must bring it back"
        );
    }

    /// The retired drain's DENIAL is guarded too, not just its budget charge.
    ///
    /// `note_scope_outcome` carries its own generation check, so a test that
    /// calls it directly covers only half of the guard. The other half is
    /// `still_owns_scope` wrapping `scopes.deny(...)`, and `deny` has no
    /// internal check — without that wrapper the 300-second denial lands on the
    /// route that replaced the drain. This test drives the REBIND arm; the
    /// nested-takeover arm, which no generation comparison can see, is
    /// `a_nested_takeover_silences_the_outer_drains_denial_at_the_call_site`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_drains_denial_does_not_withhold_the_replacements_scope() {
        struct RefusingLayer;
        #[async_trait]
        impl Layer for RefusingLayer {
            fn name(&self) -> &str {
                "refusing"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("refusing", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                Err(Error::new(ErrorCode::Unsupported, "no watches"))
            }
        }

        let layer: Arc<dyn Layer> = Arc::new(RefusingLayer);
        let root = url("mem:///");
        let scope = url("mem:///a/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        state.note_cached(&url("mem:///a/obj"));
        let stale = current_generation(&state, root.as_str());

        // The route is rebound while this drain is in flight, so by the time it
        // reports, its advertisement is gone.
        state.withdraw(&root);
        state.advertise(&root);
        state.refuse(&root);

        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            scope_drain_task(
                Arc::downgrade(&layer),
                root.clone(),
                scope.clone(),
                stale,
                cancel.clone(),
                sweep,
                Arc::clone(&state),
                Arc::new(ScopeSignals {
                    ever_opened: std::sync::atomic::AtomicBool::new(false),
                    live: std::sync::atomic::AtomicBool::new(false),
                    recursive: std::sync::atomic::AtomicBool::new(true),
                    started: tokio::time::Instant::now(),
                    stopped_at_millis: std::sync::atomic::AtomicU64::new(
                        ScopeSignals::NEVER_STOPPED,
                    ),
                }),
            ),
        )
        .await
        .expect("an Unsupported scope watch must end the drain");

        assert!(
            state
                .scopes
                .candidates(&any_owner)
                .iter()
                .any(|candidate| candidate.as_str() == scope.as_str()),
            "the retired drain's denial must not withhold the directory from \
             the advertisement that replaced it, got {:?}",
            state.scopes.candidates(&any_owner)
        );
        cancel.cancel();
    }

    /// A refusal is the refusing ROUTE's, and does not survive it.
    ///
    /// The half of this that is not a race at all: `advertise`/`withdraw` do not
    /// clear denial memos, so a memo written before a rebind reads as the
    /// replacement's for the rest of `DENIED_SCOPE_RETRY` — withholding the
    /// directory from a backend that never refused it. Guarding the WRITE cannot
    /// fix that, because at write time the memo was legitimate.
    ///
    /// It also makes the check-then-write window harmless rather than narrow:
    /// a memo that lands after a takeover is stamped with a route that no longer
    /// owns anything, so the reader discards it.
    #[test]
    fn a_refusal_does_not_outlive_the_route_that_issued_it() {
        let root = url("mem:///");
        let scope = url("mem:///a/");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        state.note_cached(&url("mem:///a/obj"));
        let first = current_generation(&state, root.as_str());

        // The route refuses the scope in both modes.
        state
            .scopes
            .deny(&scope, WatchMode::NonRecursive, &root, first);
        assert!(
            !state
                .scopes
                .candidates(&state.memo_owner_still_owns())
                .contains(&scope),
            "the refusing route's own memo must withhold the directory"
        );
        assert_eq!(
            state
                .scopes
                .starting_mode(&scope, &state.memo_owner_still_owns()),
            WatchMode::NonRecursive,
            "and narrow what it would ask for"
        );

        // A NESTED root takes the scope over. The outer root keeps its
        // advertisement and its generation, so a memo check that asked only
        // "is the issuing route still advertised?" would still honour this
        // refusal — and withhold the directory from the backend that now serves
        // it, which never refused anything.
        state.advertise(&scope);
        assert!(
            state
                .scopes
                .candidates(&state.memo_owner_still_owns())
                .contains(&scope),
            "a nested route that took the scope over must not inherit the \
             outer route's refusal"
        );
        assert_eq!(
            state
                .scopes
                .starting_mode(&scope, &state.memo_owner_still_owns()),
            WatchMode::Recursive,
            "and must get its own first ask at full width"
        );
        state.withdraw(&scope);

        // The route is rebound: same URL, new advertisement, new backend.
        state.withdraw(&root);
        state.advertise(&root);
        state.refuse(&root);
        assert!(
            state
                .scopes
                .candidates(&state.memo_owner_still_owns())
                .contains(&scope),
            "the replacement never refused this directory, so it must be a \
             candidate again rather than waiting out a stranger's memo"
        );
        assert_eq!(
            state
                .scopes
                .starting_mode(&scope, &state.memo_owner_still_owns()),
            WatchMode::Recursive,
            "and must get its own first ask at full width"
        );
    }

    /// A backend that cannot be reached at all runs out of probe budget too.
    ///
    /// The arm the refusal and terminal paths do not cover. A drain that has
    /// never opened is not `worth_defending` — `working_recently` needs
    /// `ever_opened` — so candidate churn displaces it, and its cancelled exit
    /// returns before `deny` or `note_scope_outcome` runs. Uncharged, a workload
    /// walking fresh directories against an unreachable backend attempts a watch
    /// per directory — each an OS thread and its own runtime on the broker
    /// client — at a rate bounded by nothing, while the count stays at zero.
    /// Concurrency stays bounded by `MAX_WATCH_SCOPES`; it is the attempt RATE
    /// that runs away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_that_cannot_be_reached_runs_out_of_budget() {
        struct UnavailableLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for UnavailableLayer {
            fn name(&self) -> &str {
                "unavailable"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("unavailable", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(ErrorCode::Transient, "broker unavailable"))
            }
        }

        let root = url("mem:///");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        let sweep: RootSweep = Arc::new(|_: &Url| {});

        // Three drains, as a workload walking fresh directories produces. Each
        // is cancelled after its first failure, exactly as displacement does.
        let opens = Arc::new(AtomicUsize::new(0));
        for i in 0..3 {
            let layer: Arc<dyn Layer> = Arc::new(UnavailableLayer {
                opens: opens.clone(),
            });
            let cancel = CancellationToken::new();
            let before = opens.load(Ordering::SeqCst);
            let task = tokio::spawn(scope_drain_task(
                Arc::downgrade(&layer),
                root.clone(),
                url(&format!("mem:///d{i}/")),
                generation,
                cancel.clone(),
                sweep.clone(),
                Arc::clone(&state),
                Arc::new(ScopeSignals {
                    ever_opened: std::sync::atomic::AtomicBool::new(false),
                    live: std::sync::atomic::AtomicBool::new(false),
                    recursive: std::sync::atomic::AtomicBool::new(true),
                    started: tokio::time::Instant::now(),
                    stopped_at_millis: std::sync::atomic::AtomicU64::new(
                        ScopeSignals::NEVER_STOPPED,
                    ),
                }),
            ));
            for _ in 0..2_000 {
                if opens.load(Ordering::SeqCst) > before {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        assert_eq!(
            state.probe_failures(&root),
            Some(3),
            "each directory the workload could not watch must cost the root a \
             probe, or an unreachable backend is attempted once per directory \
             for the life of the process"
        );
    }

    /// A backend that accepts a watch and immediately ERRORS runs out of budget
    /// too.
    ///
    /// The error arm of the same shape. `StreamEnd::of` classifies a quick
    /// empty end as `Barren` whether it ended cleanly or in error, so a rule
    /// that reads `DrainEnd` here charges one of them and lets the other evade:
    /// the uncharged shape gets its refund suppressed and nothing added, freezes
    /// its count, and is probed for fresh directories forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_that_accepts_then_errors_runs_out_of_budget_too() {
        struct AcceptThenErrorLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for AcceptThenErrorLayer {
            fn name(&self) -> &str {
                "accept-then-error"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("accept-then-error", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                // Accepted, then one error item and over — no events, so
                // `StreamEnd::Barren` with `DrainEnd::Error`.
                Ok(Box::new(std::iter::once(Err(Error::new(
                    ErrorCode::Transient,
                    "reset",
                )))))
            }
        }

        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(AcceptThenErrorLayer {
            opens: opens.clone(),
        });
        let root = url("mem:///");
        let scope = url("mem:///a/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            scope.clone(),
            generation,
            cancel.clone(),
            sweep,
            Arc::clone(&state),
            Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(false),
                live: std::sync::atomic::AtomicBool::new(false),
                recursive: std::sync::atomic::AtomicBool::new(true),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            }),
        ));

        for _ in 0..2_000 {
            if state.probe_failures(&root).unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let failures = state.probe_failures(&root);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

        assert!(
            opens.load(Ordering::SeqCst) >= 3,
            "the drain never reopened, so this test measured nothing"
        );
        assert!(
            failures.unwrap_or(0) >= 2,
            "an accepted-then-errored watch must cost probe budget once it \
             repeats, or the backend is probed forever, got {failures:?}"
        );
    }

    /// A root that recovers must start refunding again — through the drain, not
    /// just through the state machine.
    ///
    /// `consecutive_barren` falls only on `ScopeOutcome::Worked`, so the drain
    /// reporting it is load-bearing: without that one call a root which produced
    /// two barren ends early would stop refunding on every later open however
    /// healthy its streams became, and stay TTL-only until the pause expiry
    /// happened to reset it. This runs a real drain whose stream ends barren
    /// twice and then RUNS, and asserts the root has forgotten the history.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_recovering_backend_clears_the_roots_barren_history() {
        struct BarrenThenWorkingLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for BarrenThenWorkingLayer {
            fn name(&self) -> &str {
                "barren-then-working"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("barren-then-working", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                let n = self.opens.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    // Accepted, over at once, nothing to show.
                    return Ok(Box::new(std::iter::empty()));
                }
                // A stream with an EVENT is `worked()` regardless of uptime.
                Ok(Box::new(std::iter::once(Ok(ChangeEvent::Object {
                    address: url("mem:///a/obj"),
                    kind: ChangeKind::Modified,
                    etag: None,
                    version: None,
                    size: None,
                    mtime: None,
                    at: std::time::SystemTime::now(),
                    cursor: Default::default(),
                }))))
            }
        }

        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(BarrenThenWorkingLayer {
            opens: opens.clone(),
        });
        let root = url("mem:///");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            url("mem:///a/"),
            generation,
            cancel.clone(),
            sweep,
            Arc::clone(&state),
            Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(false),
                live: std::sync::atomic::AtomicBool::new(false),
                recursive: std::sync::atomic::AtomicBool::new(true),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            }),
        ));

        // Wait until the working streams have been running for a while, so any
        // barren charge has had every chance to land and then be cleared.
        for _ in 0..2_000 {
            if opens.load(Ordering::SeqCst) >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let failures = state.probe_failures(&root);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

        assert!(
            opens.load(Ordering::SeqCst) >= 5,
            "the drain never got past its barren phase, so this measured nothing"
        );
        assert_eq!(
            failures,
            Some(0),
            "a backend whose watches now WORK must have its probe budget \
             refunded, or two early barren ends make the root TTL-only until \
             the pause expiry happens to reset it"
        );
    }

    /// A NEW drain's first open must not launder a root's barren history.
    ///
    /// The budget is per root, so the history guarding it has to be per root
    /// too. Held per drain it would be vacuous: a fresh drain has no barren
    /// history by definition, so its first accepted open would refund the root —
    /// and a workload walking fresh directories replaces drains continuously, so
    /// an accept-and-drop backend would have its budget wiped by every newcomer
    /// and never reach the pause. A single-drain test cannot see that.
    #[test]
    fn a_new_drains_first_open_does_not_launder_the_roots_barren_history() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());

        // One drain accumulates: open, then barren ends. The first barren is a
        // transient fault and costs nothing; the second onwards charges.
        state.note_scope_outcome(&root, generation, ScopeOutcome::Opened);
        state.note_scope_outcome(&root, generation, ScopeOutcome::Barren);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "one barren end is a transient fault, not a verdict"
        );
        state.note_scope_outcome(&root, generation, ScopeOutcome::Barren);
        state.note_scope_outcome(&root, generation, ScopeOutcome::Barren);
        assert_eq!(
            state.probe_failures(&root),
            Some(2),
            "a run of them charges once per repeat"
        );

        // A DIFFERENT drain is spawned and its first open is accepted. Under a
        // per-drain counter this refunded and the count went to zero.
        state.note_scope_outcome(&root, generation, ScopeOutcome::Opened);
        assert_eq!(
            state.probe_failures(&root),
            Some(2),
            "a newcomer's accepted open must not wipe what the root has \
             already learned about this backend"
        );

        // A stream that actually RAN is the evidence that clears it, and it
        // clears the barren history too — so the next open refunds again.
        state.note_scope_outcome(&root, generation, ScopeOutcome::Worked);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "a working stream is the grant the budget is about"
        );
        state.note_scope_outcome(&root, generation, ScopeOutcome::Failed);
        state.note_scope_outcome(&root, generation, ScopeOutcome::Opened);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "and with the barren history cleared, an accepted open refunds \
             normally again"
        );
    }

    /// One barren end must not silently withdraw every later refund.
    ///
    /// The count is read by two rules — whether a barren end costs budget, and
    /// whether an accepted open still refunds it — and they have to agree on
    /// what counts as a history. Read at different thresholds the pair latches
    /// in the reassuring direction: the charge calls a single end transient and
    /// takes nothing, while the refund treats the same end as proof the root
    /// hands out watches that do not work. Nothing repairs that, because the
    /// count falls only on a stream that ENDS having worked and a granting
    /// root's watches stay open — so one broker blip makes a partially-granting
    /// root pause all probing every `DENIED_SCOPE_RETRY` for the life of the
    /// process, while it is serving healthy watches.
    ///
    /// The refused directories here are the ordinary shape: a workload walking
    /// fresh directories under a policy that grants some and refuses others.
    #[test]
    fn a_single_barren_end_does_not_withdraw_the_roots_refunds() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());

        // One blip, below the charging threshold, so it costs nothing.
        state.note_scope_outcome(&root, generation, ScopeOutcome::Barren);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "one barren end is transient on the charging side, which is the \
             premise the refund side has to share"
        );

        // Twice the budget in refused directories, each followed by a granted
        // one. The refunds are what keep the count from reaching the pause.
        for _ in 0..MAX_CONSECUTIVE_SCOPE_FAILURES * 2 {
            state.note_scope_outcome(&root, generation, ScopeOutcome::Failed);
            state.note_scope_outcome(&root, generation, ScopeOutcome::Opened);
        }
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "an accepted open refunds while the barren history is still below \
             the threshold that charges for it"
        );
        assert_eq!(
            state.probing_roots(),
            vec![root.clone()],
            "a root serving healthy watches must not be paused by refusals it \
             kept refunding"
        );

        // At the threshold the charge fires, and only then does the refund
        // stop: an accepted open no longer launders the count.
        state.note_scope_outcome(&root, generation, ScopeOutcome::Barren);
        state.note_scope_outcome(&root, generation, ScopeOutcome::Failed);
        state.note_scope_outcome(&root, generation, ScopeOutcome::Opened);
        assert_eq!(
            state.probe_failures(&root),
            Some(2),
            "past the threshold the barren history is a verdict, and an \
             accepted open must not wipe it"
        );
    }

    /// A degrade whose memo is suppressed must not retry at full speed.
    ///
    /// The recursive-refusal degrade skips the backoff at the foot of the drain
    /// loop, which is sound only while the next iteration really does open
    /// narrowly. It does not carry the narrowing in a local: the loop re-reads
    /// `starting_mode` unconditionally, so the degrade survives only through the
    /// denial memo — and `state_deny_recursive` suppresses that write when the
    /// drain no longer owns the scope. A nested root advertised above the scope
    /// is exactly that case and changes no generation, so the drain does not
    /// know it has been overtaken.
    ///
    /// What that costs is a spin rather than a wrong answer: open, refuse,
    /// suppress, retry, with no sleep and no probe charge, at whatever rate the
    /// backend can refuse — and on the broker client every attempt is a
    /// dedicated OS thread and its own Tokio runtime. Nothing bounds it but the
    /// supervisor's next reconcile, which itself awaits a blocking subtree
    /// delete for each retiring drain that had opened.
    ///
    /// The assertion is a RATE, because that is what the defect is. With the
    /// backoff taken there is one open in the window; without it the loop turns
    /// as fast as the layer answers. Paired with an assertion that the drain is
    /// still running, because giving up is quiet too and is not the fix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_degrade_that_records_nothing_backs_off_instead_of_spinning() {
        struct RefusingLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for RefusingLayer {
            fn name(&self) -> &str {
                "refusing"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("refusing", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(ErrorCode::PermissionDenied, "no"))
            }
        }

        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(RefusingLayer {
            opens: opens.clone(),
        });
        let root = url("mem:///");
        let scope = url("mem:///a/b/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        // Advertised AFTER the generation is taken, so the drain's own root and
        // generation still match and only the longest-prefix rule refuses it.
        state.advertise(&url("mem:///a/"));

        let cancel = CancellationToken::new();
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            scope.clone(),
            generation,
            cancel.clone(),
            Arc::new(|_: &Url| {}) as RootSweep,
            Arc::clone(&state),
            Arc::new(ScopeSignals {
                ever_opened: std::sync::atomic::AtomicBool::new(false),
                live: std::sync::atomic::AtomicBool::new(false),
                recursive: std::sync::atomic::AtomicBool::new(true),
                started: tokio::time::Instant::now(),
                stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            }),
        ));

        // Shorter than the first backoff (`INITIAL_DRAIN_BACKOFF` doubled), so
        // a drain that sleeps at all opens exactly once in it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let attempts = opens.load(Ordering::SeqCst);
        // Backing off and giving up are both quiet, and only one of them is the
        // fix: a drain that took its refusal and exited would satisfy the rate
        // assertion below while leaving the scope permanently unwatched. Its
        // terminal write is guarded by `still_owns_scope` too, so the memo
        // assertion cannot separate them either.
        let still_running = !task.is_finished();
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

        assert!(
            attempts >= 1,
            "the drain never attempted its watch, so this test measured nothing"
        );
        assert!(
            still_running,
            "the drain must still be retrying; a quiet drain that exited is not \
             a drain that backed off"
        );
        assert!(
            attempts <= 3,
            "a degrade that recorded no memo must back off, not retry at the \
             rate the backend can refuse; got {attempts} attempts in 300ms"
        );
        assert_eq!(
            state.scopes.starting_mode(&scope, &any_owner),
            WatchMode::Recursive,
            "no memo may have been recorded, or this test measured the owning \
             path rather than the overtaken one it exists for"
        );
    }

    /// An open that has not succeeded must not widen what the watch claims.
    ///
    /// `signals.recursive` is read as a claim about what this watch REPORTS:
    /// `covers_below` collapses the subtree onto it, and the subtree half of
    /// `worth_defending` credits it with that subtree's traffic. Published from
    /// the mode being ASKED for, it says "recursive" for a scope whose recursive
    /// form has only ever been refused — from the moment the denial memo expires
    /// until the next open resolves, which has no deadline. `covers_below` used
    /// to mask that by conjoining `live`; defensibility deliberately spans the
    /// reconnect and cannot, so the claim has to be true when it is published.
    ///
    /// The layer here answers a RETRYABLE error, so the drain neither degrades
    /// nor exits: it sits in the arm where the ask is re-read and the open never
    /// resolves, which is exactly the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unresolved_open_does_not_publish_a_recursive_watch() {
        struct UnavailableLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for UnavailableLayer {
            fn name(&self) -> &str {
                "unavailable"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("unavailable", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(ErrorCode::Transient, "later"))
            }
        }

        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(UnavailableLayer {
            opens: opens.clone(),
        });
        let root = url("mem:///");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        // The state a degraded watch is left in: it holds a non-recursive watch,
        // and nothing has granted it a wider one.
        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(true),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(false),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(0),
        });
        assert_eq!(
            state.scopes.starting_mode(&url("mem:///a/"), &any_owner),
            WatchMode::Recursive,
            "with no unexpired refusal the ASK is recursive, which is what \
             makes this test about the gap between asking and holding"
        );

        let cancel = CancellationToken::new();
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            url("mem:///a/"),
            generation,
            cancel.clone(),
            Arc::new(|_: &Url| {}) as RootSweep,
            Arc::clone(&state),
            Arc::clone(&signals),
        ));

        for _ in 0..2_000 {
            if opens.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let attempted = opens.load(Ordering::SeqCst);
        let widened = signals.recursive.load(Ordering::SeqCst);
        let live = signals.live.load(Ordering::SeqCst);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

        assert!(
            attempted >= 1,
            "the drain never asked, so this test measured nothing"
        );
        assert!(
            !live,
            "no open succeeded, so nothing may claim this watch is up"
        );
        assert!(
            !widened,
            "an open that has not succeeded must not publish a recursive \
             watch: selection defends it on subtree traffic it has never \
             reported, and the directory generating that traffic competes \
             undefended"
        );
    }

    /// The nested-takeover arm THROUGH the drain, because the predicate being
    /// right says nothing about the call site using it.
    ///
    /// `a_stale_drains_denial_does_not_withhold_the_replacements_scope` covers
    /// the rebind arm only, and a rebind bumps the generation — which the weaker
    /// predicate also catches, so it stays green if the call sites regress. A
    /// nested takeover changes no generation, so it is the arm that distinguishes
    /// them, and until this test existed the whole change was invisible to the
    /// suite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_nested_takeover_silences_the_outer_drains_denial_at_the_call_site() {
        struct RefusingLayer;
        #[async_trait]
        impl Layer for RefusingLayer {
            fn name(&self) -> &str {
                "refusing"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("refusing", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                Err(Error::new(ErrorCode::Unsupported, "no watches"))
            }
        }

        let layer: Arc<dyn Layer> = Arc::new(RefusingLayer);
        let outer = url("mem:///");
        let scope = url("mem:///a/inner/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&outer);
        state.refuse(&outer);
        state.note_cached(&url("mem:///a/inner/obj"));
        let generation = current_generation(&state, outer.as_str());

        // A nested root is mounted over the scope while the drain is in flight.
        // The OUTER root keeps its advertisement and its generation, which is
        // exactly what a generation-only guard cannot see.
        state.advertise(&scope);
        assert!(
            state.advertisement_is_current(&outer, generation),
            "premise: the outer advertisement is still current, so a \
             generation-only guard would let the write through"
        );

        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            scope_drain_task(
                Arc::downgrade(&layer),
                outer.clone(),
                scope.clone(),
                generation,
                cancel.clone(),
                sweep,
                Arc::clone(&state),
                Arc::new(ScopeSignals {
                    ever_opened: std::sync::atomic::AtomicBool::new(false),
                    live: std::sync::atomic::AtomicBool::new(false),
                    recursive: std::sync::atomic::AtomicBool::new(true),
                    started: tokio::time::Instant::now(),
                    stopped_at_millis: std::sync::atomic::AtomicU64::new(
                        ScopeSignals::NEVER_STOPPED,
                    ),
                }),
            ),
        )
        .await
        .expect("an Unsupported scope watch must end the drain");

        assert!(
            state
                .scopes
                .candidates(&any_owner)
                .iter()
                .any(|candidate| candidate.as_str() == scope.as_str()),
            "the outer drain's refusal must not withhold the directory from \
             the nested route that now owns it, got {:?}",
            state.scopes.candidates(&any_owner)
        );
        assert_eq!(
            state.probe_failures(&outer),
            Some(0),
            "nor charge the outer root for a scope it no longer owns"
        );
        cancel.cancel();
    }

    /// A nested root taking a scope over must silence the outer drain's verdict,
    /// even though the outer root is still advertised.
    ///
    /// The case a root-generation check cannot see: mounting
    /// `mem:///a/inner/` under `mem:///` leaves `mem:///`'s own advertisement
    /// untouched, so a guard that asks only "is my root still current?" answers
    /// yes while the scope it is about now belongs to a different backend. The
    /// retired drain's refusal would then withhold that directory from the
    /// nested route for the whole `DENIED_SCOPE_RETRY` window.
    #[test]
    fn a_verdict_is_silenced_by_a_nested_takeover_not_just_a_rebind() {
        let outer = url("mem:///");
        let scope = url("mem:///a/inner/");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&outer);
        state.refuse(&outer);
        let generation = current_generation(&state, outer.as_str());

        assert!(
            state.still_owns_scope(&outer, generation, &scope),
            "control: with no nested root the outer route owns the scope and \
             its verdict must land"
        );
        assert!(
            state.advertisement_is_current(&outer, generation),
            "and its own advertisement is current in both cases, which is why \
             that question is not the one to ask"
        );

        // A nested root is mounted over the scope. The OUTER root is untouched.
        state.advertise(&url("mem:///a/inner/"));
        assert!(
            state.advertisement_is_current(&outer, generation),
            "the outer advertisement really is still current — the weaker \
             guard would pass here"
        );
        assert!(
            !state.still_owns_scope(&outer, generation, &scope),
            "but it no longer owns the scope, so its verdict must not land"
        );

        // A sibling nested root is not a takeover of this scope.
        assert!(
            state.still_owns_scope(&outer, generation, &url("mem:///b/")),
            "a nested root elsewhere must not silence verdicts about scopes it \
             does not own"
        );
    }

    /// A root drain that dies on a code which is NOT a capability verdict must
    /// leave the scopes alone.
    ///
    /// The control for `a_terminal_root_drain_records_itself`, and the reason
    /// `Unsupported` is a separate exit kind. `Internal` is non-retryable, so a
    /// broker hiccup on one of a refused root's five-minute re-probes ends its
    /// drain — but it says nothing about whether the directories beneath can be
    /// watched, and those scoped watches are the feature working. Marking the
    /// root unwatchable there would take a deployment from four live watches to
    /// zero for the life of the process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_drain_dying_on_a_transient_verdict_keeps_the_scopes() {
        struct InternalLayer;
        #[async_trait]
        impl Layer for InternalLayer {
            fn name(&self) -> &str {
                "internal"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("internal", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                Err(Error::new(ErrorCode::Internal, "broker hiccup"))
            }
        }

        let layer: Arc<dyn Layer> = Arc::new(InternalLayer);
        let root = url("mem:///");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();

        tokio::time::timeout(
            Duration::from_secs(10),
            root_drain_task(
                Arc::downgrade(&layer),
                root.clone(),
                cancel.clone(),
                sweep,
                Arc::clone(&state),
                generation,
            ),
        )
        .await
        .expect("a non-retryable root watch must end the drain");

        assert!(
            state.root_views().iter().any(|view| view.admits_probes),
            "an `Internal` verdict on the ROOT's watch must not stop the \
             scoped probing beneath it — that probing is the feature, and \
             nothing under the byte cache expires to catch it"
        );
        cancel.cancel();
    }

    /// The same thing through the drain, because the state machine being right
    /// says nothing about whether anything calls it.
    ///
    /// `root_drain_task` has to act on its `DrainExit`; discarding it leaves
    /// every assertion about `Unwatchable` passing with the root still
    /// `Refused` forever. This runs a real root drain against a backend that
    /// answers `Unsupported` and asserts the root stops admitting probes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_terminal_root_drain_records_itself() {
        struct UnsupportedLayer;
        #[async_trait]
        impl Layer for UnsupportedLayer {
            fn name(&self) -> &str {
                "unsupported"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("unsupported", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                Err(Error::new(ErrorCode::Unsupported, "no watches here"))
            }
        }

        let layer: Arc<dyn Layer> = Arc::new(UnsupportedLayer);
        let root = url("mem:///");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        // Start from the refusal path, which is where the drain can outlive its
        // own state: the root keeps retrying rather than exiting.
        state.refuse(&root);
        let generation = current_generation(&state, root.as_str());
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let cancel = CancellationToken::new();

        tokio::time::timeout(
            Duration::from_secs(10),
            root_drain_task(
                Arc::downgrade(&layer),
                root.clone(),
                cancel.clone(),
                sweep,
                Arc::clone(&state),
                generation,
            ),
        )
        .await
        .expect("an Unsupported root watch must end the drain rather than retry");

        assert!(
            !state.root_views().iter().any(|view| view.admits_probes),
            "the drain ended non-retryably, so the root must stop being probed \
             — otherwise the supervisor opens scoped watches under it forever"
        );
        cancel.cancel();
    }

    /// A retired drain cannot deny a scope, or charge a probe budget, on behalf
    /// of a route it is no longer watching.
    ///
    /// Retirement cancels without aborting, so a drain can be between its
    /// cancellation check and its terminal write while the manager
    /// re-advertises the same URL — or while a nested root takes the scope
    /// over. Both writes are keyed by URL and would otherwise land on the
    /// replacement: the denial withholds the directory from the new route for
    /// the whole retry window, and the charge pauses a probe budget that route
    /// never spent.
    #[test]
    fn a_stale_drains_verdict_does_not_land_on_the_replacement_route() {
        let root = url("mem:///");
        let state = ScopedWatchState::new(Arc::new(WatchScopes::new(true)));
        state.advertise(&root);
        state.refuse(&root);
        let stale = current_generation(&state, root.as_str());

        // The route is rebound: same URL, new advertisement.
        state.withdraw(&root);
        state.advertise(&root);
        state.refuse(&root);
        let current = current_generation(&state, root.as_str());
        assert_ne!(stale, current, "a rebind must mint a new generation");

        // The retired drain reports its refusal now.
        assert!(
            !state.advertisement_is_current(&root, stale),
            "the old advertisement must not read as current"
        );
        state.note_scope_outcome(&root, stale, ScopeOutcome::Failed);
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "a retired drain must not charge the replacement route's probe \
             budget for a refusal it never issued"
        );

        // The control: the CURRENT drain's identical report does land.
        state.note_scope_outcome(&root, current, ScopeOutcome::Failed);
        assert_eq!(
            state.probe_failures(&root),
            Some(1),
            "control: the live advertisement's own outcome is still recorded"
        );
    }

    /// A backend that accepts every watch and immediately ends it must run out
    /// of probe budget.
    ///
    /// `StreamEnd::Barren` names exactly this backend, but naming it is not
    /// charging it. A refund that fires on a successful open before the stream
    /// is classified gives the cycle reset, barren, reset, barren — the count
    /// never rises, `admits_probes` stays true, and every fresh directory the
    /// workload reads becomes another accepted-and-dropped watch, each a thread
    /// and a stream, for the life of the process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_that_accepts_watches_without_watching_runs_out_of_budget() {
        struct BarrenLayer {
            opens: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Layer for BarrenLayer {
            fn name(&self) -> &str {
                "barren"
            }
            fn descriptor(&self) -> LayerKindDescriptor {
                crate::layers::descriptor("barren", LayerType::Backend, true)
            }
            async fn watch_directory(
                &self,
                _request: Request<WatchDirectoryRequest>,
                _cancel: Option<CancellationToken>,
            ) -> Result<ChangeStream> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                // Accepted, and over at once with nothing to show.
                Ok(Box::new(std::iter::empty()))
            }
        }

        let opens = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(BarrenLayer {
            opens: opens.clone(),
        });
        let root = url("mem:///");
        let scope = url("mem:///a/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        let cancel = CancellationToken::new();
        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            recursive: std::sync::atomic::AtomicBool::new(false),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
        });
        let sweep: RootSweep = Arc::new(|_: &Url| {});
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            scope.clone(),
            current_generation(&state, root.as_str()),
            cancel.clone(),
            sweep,
            state.clone(),
            signals,
        ));

        // Three barren cycles is enough to show the count RISING, which is the
        // property the reset-loop destroyed. Waiting for the whole budget would
        // only measure the backoff doubling.
        for _ in 0..2_000 {
            if state.probe_failures(&root).unwrap_or(0) >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let failures = state.probe_failures(&root);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

        assert!(
            opens.load(Ordering::SeqCst) >= 3,
            "the drain never reopened, so this test measured nothing"
        );
        assert!(
            failures.unwrap_or(0) >= 3,
            "an accepted-but-barren watch must cost probe budget, or the \
             backend is probed for fresh directories forever, got {failures:?}"
        );
    }

    /// Cancellation is not a verdict on the prefix, and a scoped drain that
    /// reads it as one destroys data. `Cancelled` is not retryable, so without
    /// a guard it classifies as a terminal failure: the caller then denies the
    /// directory for [`DENIED_SCOPE_RETRY`], charges the root's probe budget,
    /// and — because the watch had been live — sweeps the scope's subtree out
    /// of a cache that has no TTL at all. On ordinary retirement, which
    /// fires an individual drain's token, the damage is the denial and the
    /// budget charge: the supervisor has already swept that subtree
    /// deliberately. At process exit, where the layer's token fires every
    /// drain's, `sweep_off_runtime` reaches `spawn_blocking` before its await,
    /// so a drain that gets there ahead of the abort discards a live subtree of
    /// a persistent store.
    ///
    /// Three affirmative readings rather than an absence: the scope is still a
    /// candidate, the root's failure count is still zero, and exactly the one
    /// activation sweep ran.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_scope_open_is_not_a_terminal_failure() {
        let opens = Arc::new(AtomicUsize::new(0));
        let reopening = Arc::new(AtomicBool::new(false));
        let backend = Arc::new(CancelOnReopenLayer {
            opens: opens.clone(),
            reopening: reopening.clone(),
            await_token: true,
        });
        let layer: Arc<dyn Layer> = backend.clone();
        let sweeps = Arc::new(AtomicUsize::new(0));
        let counted = sweeps.clone();
        let sweep: RootSweep = Arc::new(move |_: &Url| {
            counted.fetch_add(1, Ordering::SeqCst);
        });

        let root = url("mem:///");
        let scope = url("mem:///a/b/");
        let state = Arc::new(ScopedWatchState::new(Arc::new(WatchScopes::new(true))));
        state.advertise(&root);
        state.refuse(&root);
        state.scopes.note_cached(&url("mem:///a/b/obj"));

        let cancel = CancellationToken::new();
        let signals = Arc::new(ScopeSignals {
            ever_opened: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(false),
            started: tokio::time::Instant::now(),
            stopped_at_millis: std::sync::atomic::AtomicU64::new(ScopeSignals::NEVER_STOPPED),
            recursive: std::sync::atomic::AtomicBool::new(true),
        });
        let task = tokio::spawn(scope_drain_task(
            Arc::downgrade(&layer),
            root.clone(),
            scope.clone(),
            current_generation(&state, root.as_str()),
            cancel.clone(),
            sweep,
            Arc::clone(&state),
            Arc::clone(&signals),
        ));

        // Cancel only once the reopen is genuinely in flight. Cancelling during
        // the backoff would leave through the loop's own shutdown arm and prove
        // nothing about the error branch.
        for _ in 0..2_000 {
            if reopening.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            reopening.load(Ordering::SeqCst),
            "the reopen never began, so no open was cancelled and this test \
             measured nothing"
        );
        // The two open-related signals answer different questions and this is
        // the moment they disagree: the watch HAS opened, so retirement would
        // have a subtree to sweep, and it is NOT open, so its slot is no longer
        // worth protecting from a directory that could be watched.
        assert!(signals.ever_opened.load(Ordering::SeqCst));
        assert!(
            !signals.live.load(Ordering::SeqCst),
            "a scope whose stream has ended is not holding a live watch"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("a cancelled drain must exit rather than keep retrying")
            .unwrap();

        assert_eq!(
            sweeps.load(Ordering::SeqCst),
            1,
            "only the activation sweep may run: a retirement sweep here \
             discards a live subtree of a persistent cache"
        );
        assert!(
            state
                .scopes
                .candidates(&any_owner)
                .iter()
                .any(|candidate| candidate.as_str() == scope.as_str()),
            "a cancelled open must not withhold the directory for the denial \
             window, got {:?}",
            state.scopes.candidates(&any_owner)
        );
        // Zero, and both halves matter. The cancelled open charges nothing,
        // which is this test's subject. And the ONE barren stream this drain
        // ends to force the reopen charges nothing either, because a single
        // quick empty end is a transient fault rather than a verdict — only a
        // repeat is charged. So this reads zero for two independent reasons and
        // would catch either of them changing.
        assert_eq!(
            state.probe_failures(&root),
            Some(0),
            "neither a cancelled open nor a single barren stream may charge \
             the root's probe budget"
        );
    }
}
