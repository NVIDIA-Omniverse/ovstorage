// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! [`ConnectionSet`]: the generic, backend-agnostic connection-lifecycle
//! machinery a connection-owning backend layer embeds (RFC-0066 §2041-2065).
//! It owns the [`ConnectionAuthState`] machine and its
//! transitions, single-flight bring-up coalescing + failure cooldown,
//! per-connection credential state, one background-refresh task per
//! auth-bearing connection, the data-path invalidate-and-retry-once recovery
//! loop, secret persistence + cross-process refresh coalescing (through
//! `crate::marshal` host callbacks), and `ConnectionChange` emission. The
//! per-backend [`ConnectionAuthDriver`] supplies only the protocol verbs.
//!
//! ## Rotation-safety serialization
//!
//! Refresh-token grants on a rotating IdP must be serialized, or two concurrent
//! grants on one refresh token trip IdP reuse-detection and revoke the whole
//! token family. Every grant path is covered:
//! - `coalesced_refresh` (the data-path / background grant) holds BOTH the
//!   per-`ConnectionId` in-process `bringup_lock` (via its callers) AND the
//!   stable-id-keyed cross-process `auth_refresh_lock`, and always reloads the
//!   keyring's persisted head under the lock so it never replays a consumed
//!   token — including on the unlocked fallback paths (`refresh_from_head`).
//! - `add_connection` / `bring_up` / `update_credentials` drive `validate`
//!   through `validate_under_lock`, which holds the SAME stable-keyed
//!   cross-process lock (ZERO freshness window). A warm-continue / rotation seed
//!   refresh grant the driver drives inside `validate` — which reloads the
//!   keyring head and persists the successor under the lock — is therefore
//!   coalesced with `coalesced_refresh` and with peer processes / same-host
//!   sibling connections (distinct `ConnectionId`s, one stable id). `bring_up`
//!   additionally reloads the persisted head so a re-validation never grants a
//!   stale in-memory token.
//!
//! The cross-process lock requires a registered host + stable id + a
//! multi-thread runtime (its closure drives the async grant via
//! `block_in_place`). On a hostless embedding or a current-thread runtime the
//! grant runs UNLOCKED but STILL reloads the secret store head first, so a consumed
//! token is never replayed; only the cross-process *coalescing* is unavailable
//! there (there is no cross-process peer without a host anyway).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

use ovstorage_layer::ordered::{Emit, Ordered};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use super::driver::{ConnectionAuthDriver, GrantPolicy, Obtained, ProbeOutcome, Refreshed};

/// Which durable-credential verb a purge issues. Both retire the same
/// stable-id-keyed secret and so share one chokepoint.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DurablePurge {
    /// Retire the secret with the connection (removal / orphan cleanup).
    Delete,
    /// Retire the durable head while the connection stays registered.
    Purge,
}

/// Whether a grant's input credentials are the caller's own (`Fresh`) or come
/// from durable storage (the secret store). Decided by CALL SITE, not by sniffing the
/// bundle shape: a stored-lineage input reloads the persisted head under the
/// cross-process lock before granting, so a stale in-memory predecessor left by
/// a prior rotation is never replayed into IdP reuse-detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Lineage {
    /// The caller supplied these credentials to be used as-is (operator paste /
    /// rotation push / user-typed): do NOT reload the secret store head.
    Fresh,
    /// Warm-continue / bring-up / recovery: reload the persisted head under the
    /// lock so the grant consumes the latest rotation lineage.
    Stored,
}

/// The result of a locked obtain grant, plus the supersession fences captured at
/// grant start. Both cover the whole obtain→verify→activate window: `activate`
/// (identity_gen) and the set-side commit (cred_gen) discard rather than regress
/// the live cell / entry if a concurrent interactive success or refresh won.
struct GrantCommit {
    outcome: Obtained,
    expected_identity_gen: u64,
    expected_cred_gen: u64,
    /// Lineage of the input credentials (decided by call site): a `Fresh`
    /// explicit update commits onto the live cell with REPLACE semantics
    /// (`activate_replacing`), a stored-lineage warm-continue / bring-up with MERGE
    /// semantics (`activate`).
    lineage: Lineage,
}
use crate::{
    AuthAttempt, AuthEvent, AuthEventStream, AuthReason, CancellationToken, Connection,
    ConnectionAuthState, ConnectionChange, ConnectionId, ConnectionSnapshot,
    ConnectionUpdateStream, Error, ErrorCode, InteractiveAuthCapability, Result, SecretBundle,
    SecretValue,
};

/// Tunables for a [`ConnectionSet`]. Defaults match the RFC: `refresh_skew` is
/// 60 s, `bringup_cooldown` is 10 s, and `max_auth_attempts` is 5 before
/// `AuthFailed`.
#[derive(Clone, Debug)]
pub struct ConnectionSetConfig {
    /// Wake the background refresh at `expires_at - refresh_skew`.
    pub refresh_skew: Duration,
    /// After a failed silent bring-up, reject re-attempts for this window
    /// (unless `force`d).
    pub bringup_cooldown: Duration,
    /// Consecutive failed auth attempts before a connection latches
    /// `AuthFailed` (recoverable only via `update_credentials`).
    pub max_auth_attempts: u32,
    /// Bounded `AuthAttempt` history kept per connection.
    pub max_attempt_history: usize,
    /// Freshness window handed to the host's cross-process refresh lock: a
    /// refresh is skipped if another process refreshed within this window.
    pub refresh_freshness_window: Duration,
    /// Lower bound on the background-refresh wakeup delay. A very short token
    /// TTL (or an already-past `expires_at`) would otherwise schedule a refresh
    /// at ~0, busy-looping the IdP; the delay is floored here so the refresh
    /// rate stays bounded (the data-path recovery covers the gap for
    /// tokens whose TTL is shorter than this floor).
    pub min_refresh_delay: Duration,
}

impl Default for ConnectionSetConfig {
    fn default() -> Self {
        Self {
            refresh_skew: Duration::from_secs(60),
            bringup_cooldown: Duration::from_secs(10),
            max_auth_attempts: 5,
            max_attempt_history: 8,
            refresh_freshness_window: Duration::from_secs(60),
            min_refresh_delay: MIN_REFRESH_DELAY,
        }
    }
}

/// The mutable per-connection state `ConnectionSet` owns.
struct EntryState {
    /// The connection view (its `auth_state` is authoritative here); addresses
    /// / capabilities are set by the owning layer via [`ConnectionSet::set_addresses`].
    connection: Connection,
    /// Current in-memory credentials the backend transport reads.
    credentials: SecretBundle,
    /// Bounded history of auth attempts (most recent last).
    history: Vec<AuthAttempt>,
    /// Consecutive failed auth attempts (→ `AuthFailed` at the threshold).
    attempts: u32,
    /// Bumped on every credential swap. Lets the data-path recovery
    /// single-flight detect that a concurrent op/task already refreshed and
    /// skip a redundant grant (avoids racing refresh-token rotation).
    cred_gen: u64,
    /// Persist-debt (Brian's design §6): set when a rotation successor was
    /// committed to `credentials` in memory but the durable secret persist
    /// FAILED (all retries) — the secret store is stranded on the pre-rotation
    /// predecessor while memory holds the strictly-newer successor. While set,
    /// a stored-lineage grant must NOT reload the stale keyring head: memory is
    /// authoritative, so it grants the in-memory successor instead (replaying a
    /// consumed predecessor would trip IdP reuse-detection and revoke the token
    /// family). A later successful persist retires the debt and normal
    /// head-reload resumes. Never causes the successor to be discarded.
    persist_debt: bool,
    /// Whether `ConnectionChange::Added` has been emitted for this connection.
    /// `add_connection_deferred` leaves this `false`; the owning layer
    /// installs its route, then `announce_connection` sets it and emits `Added`.
    /// While `false`, `Updated`/`Removed` emissions are suppressed so a
    /// subscriber never sees an event for a connection it has not yet seen
    /// `Added` for — and, crucially, a subscriber reacting to `Added` by
    /// removing the connection cannot win a race against route installation.
    announced: bool,
}

struct ConnEntry<D: ConnectionAuthDriver> {
    driver: Arc<D>,
    state: Mutex<EntryState>,
    /// Serializes a terminal interactive credential commit with stale-keyring
    /// purges. Without this lock, a failed warm-continue can delete a newer
    /// interactive winner after its generation check but before durable purge.
    credential_mutation: tokio::sync::Mutex<()>,
    /// The removing caller's purge intent, recorded (under the entries write
    /// lock, before unregistration) so an interactive commit that persists a
    /// durable head AFTER the removal reads the remover's actual intent instead
    /// of inferring deletion from unregistration alone: an explicit
    /// [`ConnectionSet::remove_connection`] (`true`) deletes the orphan, while a
    /// non-purging [`ConnectionSet::unregister_connection`] (`false`) preserves
    /// the durable head for the next warm continuation.
    purge_on_removal: AtomicBool,
    /// Whether this connection's durable secret is KNOWN to have been deleted.
    /// Set only by a `delete_credentials` that returned `Ok`, which is what
    /// separates it from [`Self::purge_on_removal`]: that flag records the
    /// remover's intent, while the delete itself is skipped when a live sibling
    /// shares the stable id, and can fail (both call sites discard the error for
    /// control flow). The teardown report gates on THIS, because what strands a
    /// consumed token is a secret still being there, not an intent to remove one.
    durable_secret_deleted: AtomicBool,
    refresh_task: Mutex<Option<JoinHandle<()>>>,
    /// Child of the set's parent token; cancelled when the entry is removed,
    /// which stops its background-refresh task deterministically.
    cancel: CancellationToken,
}

impl<D: ConnectionAuthDriver> ConnEntry<D> {
    /// Record the outcome of a teardown `delete_credentials`, so the teardown
    /// report knows whether a secret was actually left behind.
    ///
    /// `deleted` must come from a delete that RETURNED `Ok`; a failure leaves
    /// the secret marked as still present, which is what it is. Callers keep
    /// their own error handling — the teardown ones swallow it as best-effort
    /// orphan cleanup, `purge_persisted_credentials` propagates it.
    fn record_secret_deleted(&self, deleted: bool) {
        if deleted {
            self.durable_secret_deleted.store(true, Ordering::SeqCst);
        }
    }
}

impl<D: ConnectionAuthDriver> Drop for ConnEntry<D> {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.refresh_task.lock().take() {
            handle.abort();
        }
        // Persist-debt is process-local, so teardown is the last point at which
        // it can be reported: the durable store holds a refresh token a rotation
        // already consumed, and the next start would warm-continue on it. The
        // operator's action is to sign in again for this connection before that
        // start. `state` is a sync mutex and the last `Arc` is gone by the time
        // `drop` runs, so nothing can be holding it.
        //
        // Only a teardown that LEFT the durable head in place strands anything,
        // so the gate is the observed outcome of the delete, not the remover's
        // intent. A purge that ran deleted the secret before this drop, leaving
        // nothing stranded and no next start to protect. A purge whose delete
        // was skipped for a stable-id sibling, or that failed, left the consumed
        // predecessor exactly where it was — and that is when the operator most
        // needs to hear about it.
        //
        // A hard crash reports nothing — that is this report's bound.
        // TODO: add a durable record so the debt survives a hard crash.
        let guard = self.state.lock();
        if guard.persist_debt && !self.durable_secret_deleted.load(Ordering::SeqCst) {
            tracing::warn!(
                target: "ovstorage.connection",
                connection = %guard.connection.id.0,
                persist_debt = true,
                "connection torn down with outstanding credential persist-debt: its \
                 stored refresh token was PRESERVED, and it is the superseded one — \
                 the live successor was only ever in memory. Sign in again for this \
                 connection before the next start rather than warm-continuing on \
                 the stored credential",
            );
        }
    }
}

/// Generic connection-lifecycle machinery embedded by a connection-owning
/// backend layer. `D` is the per-backend driver; each connection carries its
/// own `Arc<D>` instance.
pub struct ConnectionSet<D: ConnectionAuthDriver> {
    config: ConnectionSetConfig,
    /// The connection registry: the map of live entries, bound to the
    /// `ConnectionChange` channel that reports its commits. They are one value
    /// because they are one guarantee — every membership change and the event
    /// describing it happen in the same critical section, and no call site can
    /// pair this guard with a different channel.
    entries: Ordered<HashMap<ConnectionId, Arc<ConnEntry<D>>>, broadcast::Sender<ConnectionChange>>,
    /// Per-connection async lock coalescing concurrent silent bring-ups.
    bringup_locks: Mutex<HashMap<ConnectionId, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-connection failure cooldown (`Instant` of the last failed bring-up).
    cooldowns: Mutex<HashMap<ConnectionId, Instant>>,
    /// Per-connection bring-up generation + the winner's outcome, recorded
    /// after every completed `validate` attempt under the single-flight lock
    /// (`None` = the winner authenticated). A waiter captures the generation
    /// before awaiting the lock and, if it changed while waiting, shares the
    /// winner's ACTUAL outcome (its error, with its real class — transient /
    /// permission-denied / auth) instead of re-running `validate` — so a
    /// concurrent burst can't hammer the IdP and latch `AuthFailed` from a
    /// single failed winner. A `Cancelled` winner does NOT bump the generation:
    /// no attempt completed, so waiters (whose own tokens never fired) run
    /// their own validate rather than being converted into spurious
    /// sign-in demands.
    bringup_gens: Mutex<HashMap<ConnectionId, (u64, Option<Error>)>>,
    /// Per-STABLE-ID lock serializing a durable credential purge against a
    /// registration of that same identity. Secrets are keyed by stable id, so a
    /// purge and a registration resolving to the same key contend for one
    /// durable slot, and the purge's delete is awaited — so without this the
    /// delete can land on a credential a newly registered connection already
    /// persisted.
    ///
    /// Held by `Weak`, so the map does not grow with every stable id ever seen
    /// (which a peer could otherwise influence). Reclaiming is safe precisely
    /// because a dead entry proves nobody holds that lock: every user keeps the
    /// `Arc` alive for as long as it holds the guard, so a fresh mutex cannot
    /// split mutual exclusion with a live one.
    purge_locks: Mutex<HashMap<ConnectionId, Weak<tokio::sync::Mutex<()>>>>,
    /// Per-connection generation of COMPLETED refresh attempts (success or
    /// failure), bumped under the single-flight lock. `cred_gen` only moves on
    /// success, so `with_recovery` waiters queued behind a FAILED refresh
    /// winner use this to share the failure instead of each re-driving the
    /// grant with the same dead credentials (attempt inflation → `AuthFailed`).
    refresh_gens: Mutex<HashMap<ConnectionId, u64>>,
    /// Cross-process refresh-lock provider. `None` uses the host callbacks
    /// (production); tests inject an in-memory lock so the locked
    /// reload→grant→persist transaction is unit-testable.
    refresh_lock: Option<Arc<dyn CrossProcessRefreshLock>>,
    /// Parent token for every per-connection refresh task.
    cancel: CancellationToken,
    /// Test seam: invoked by [`Self::announce_connection`] after it resolves the
    /// entry and before it commits the announce decision, so a test can drive the
    /// announce/removal interleaving from a gate rather than from timing.
    #[cfg(test)]
    announce_seam: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Test seam: invoked by [`Self::remove_inner`] immediately after its commit
    /// section, so a test can run a re-registration in the window where the
    /// removal's tail is still executing.
    #[cfg(test)]
    remove_seam: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Abstraction over the host's cross-process refresh lock
/// (`HostCallbacks::auth_refresh_lock_with_refresh`) so the locked
/// reload→grant→persist transaction is testable — the real host callbacks are
/// a process-global FFI registration a unit test cannot safely install.
pub(crate) trait CrossProcessRefreshLock: Send + Sync + 'static {
    /// Run `run` under the per-`(backend_kind, stable)` cross-process lock,
    /// unless a peer refreshed within `freshness` — then skip (`Ok(false)`,
    /// `run` not invoked). `Ok(true)` = `run` ran to `Ok(())` and the host
    /// published a fresh refresh timestamp.
    fn with_lock(
        &self,
        backend_kind: &str,
        stable: &ConnectionId,
        freshness: Duration,
        run: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool>;
}

/// Production [`CrossProcessRefreshLock`]: the plugin host's
/// `auth_refresh_lock_with_refresh`. Constructed per call only when
/// `marshal::host()` is present.
struct HostRefreshLock;

impl CrossProcessRefreshLock for HostRefreshLock {
    fn with_lock(
        &self,
        backend_kind: &str,
        stable: &ConnectionId,
        freshness: Duration,
        run: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        let Some(host) = crate::marshal::host() else {
            return Err(Error::new(
                ErrorCode::Internal,
                "cross-process refresh lock requested without a registered host",
            ));
        };
        let mut ran = false;
        host.auth_refresh_lock_with_refresh(backend_kind, stable, freshness, || {
            ran = true;
            run()
        })?;
        Ok(ran)
    }
}

impl<D: ConnectionAuthDriver> Drop for ConnectionSet<D> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl<D: ConnectionAuthDriver> ConnectionSet<D> {
    pub fn new(config: ConnectionSetConfig) -> Self {
        Self {
            config,
            entries: Ordered::broadcast(HashMap::new(), 64),
            bringup_locks: Mutex::new(HashMap::new()),
            cooldowns: Mutex::new(HashMap::new()),
            bringup_gens: Mutex::new(HashMap::new()),
            refresh_gens: Mutex::new(HashMap::new()),
            purge_locks: Mutex::new(HashMap::new()),
            refresh_lock: None,
            cancel: CancellationToken::new(),
            #[cfg(test)]
            announce_seam: Mutex::new(None),
            #[cfg(test)]
            remove_seam: Mutex::new(None),
        }
    }

    /// Install the [`Self::announce_connection`] test seam.
    #[cfg(test)]
    pub(crate) fn set_announce_seam(&self, seam: Arc<dyn Fn() + Send + Sync>) {
        *self.announce_seam.lock() = Some(seam);
    }

    #[cfg(test)]
    fn announce_seam(&self) {
        let seam = self.announce_seam.lock().clone();
        if let Some(seam) = seam {
            seam();
        }
    }

    #[cfg(not(test))]
    fn announce_seam(&self) {}

    /// Install the [`Self::remove_inner`] test seam.
    #[cfg(test)]
    pub(crate) fn set_remove_seam(&self, seam: Arc<dyn Fn() + Send + Sync>) {
        *self.remove_seam.lock() = Some(seam);
    }

    #[cfg(test)]
    fn remove_seam(&self) {
        let seam = self.remove_seam.lock().clone();
        if let Some(seam) = seam {
            seam();
        }
    }

    #[cfg(not(test))]
    fn remove_seam(&self) {}

    pub fn with_defaults() -> Self {
        Self::new(ConnectionSetConfig::default())
    }

    /// The commit chokepoint: hold the `entries` write guard — the lock that
    /// orders every membership change — and run `f` with the map and the
    /// capability to emit on the connection-change channel that guard owns.
    ///
    /// Registration, unregistration, the `announced` decision and the event that
    /// reports them all happen here, so no subscriber can observe an event that
    /// disagrees with the committed membership.
    ///
    /// `f` runs under a `parking_lot` guard: it must not await, block, or re-enter
    /// `entries` (including via `is_registered` / `stable_id_shared_by_other`).
    /// Locks nest `entries` → `entry.state`, never the reverse.
    fn commit<R>(
        &self,
        f: impl FnOnce(
            &mut HashMap<ConnectionId, Arc<ConnEntry<D>>>,
            &Emit<'_, broadcast::Sender<ConnectionChange>>,
        ) -> R,
    ) -> R {
        self.entries.commit(f)
    }

    /// Test constructor injecting an in-memory [`CrossProcessRefreshLock`] so
    /// the locked reload→grant→persist transaction can be exercised without a
    /// process-global host registration.
    #[cfg(test)]
    pub(crate) fn new_with_refresh_lock(
        config: ConnectionSetConfig,
        refresh_lock: Arc<dyn CrossProcessRefreshLock>,
    ) -> Self {
        let mut set = Self::new(config);
        set.refresh_lock = Some(refresh_lock);
        set
    }

    /// Subscribe to `ConnectionChange` events (add / update / remove).
    ///
    /// A slow consumer that overflows the broadcast buffer receives an `Err`
    /// *resync* item (rather than silently missing events): on lag, re-snapshot
    /// via [`Self::list_connections`] to recover the current state, then keep
    /// reading. This keeps the `updates: true` contract honest.
    pub fn subscribe(&self) -> ConnectionUpdateStream {
        let rx = self.entries.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(change) => Some((Ok(change), rx)),
                Err(broadcast::error::RecvError::Lagged(n)) => Some((
                    Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        format!(
                            "connection update stream lagged {n} event(s); \
                             re-snapshot via list_connections() to resync"
                        ),
                    )),
                    rx,
                )),
                Err(broadcast::error::RecvError::Closed) => None,
            }
        }))
    }

    /// Snapshot the connection views (auth_state authoritative).
    ///
    /// Deferred (not-yet-announced) connections are EXCLUDED: this is the
    /// only host-facing enumerator, so filtering it here keeps a deferred
    /// connection invisible on BOTH the snapshot and the event channel — closing
    /// the pre-announce `ConnectionId` leak (a host could otherwise poll this,
    /// grab a not-yet-installed id, and `remove_connection` it during the
    /// install→lookup window) and the snapshot/stream ghost (a captured deferred
    /// connection whose discovery then fails emits neither `Added` nor
    /// `Removed`). Internal routing uses `connection()` / the layer's own
    /// instance table, never this, so filtering is safe.
    pub fn list_connections(&self) -> ConnectionSnapshot {
        let connections = self
            .entries
            .read()
            .values()
            .filter(|entry| entry.state.lock().announced)
            .map(|entry| entry.state.lock().connection.clone())
            .collect();
        ConnectionSnapshot {
            connections,
            updates: true,
        }
    }

    /// The current auth state for `id`, if present.
    pub fn auth_state(&self, id: &ConnectionId) -> Option<ConnectionAuthState> {
        self.entries
            .read()
            .get(id)
            .map(|entry| entry.state.lock().connection.auth_state.clone())
    }

    /// The current in-memory credentials for `id` (for the backend transport).
    pub fn credentials(&self, id: &ConnectionId) -> Option<SecretBundle> {
        self.entries
            .read()
            .get(id)
            .map(|entry| entry.state.lock().credentials.clone())
    }

    /// Whether `id` currently carries persist-debt: a rotation successor is
    /// live in memory that the durable store REFUSED or failed to accept, so
    /// the stored credential is a refresh token the provider has already
    /// consumed. `None` when `id` is not registered.
    ///
    /// The debt is process-local, so a restart cannot see it. A host, CLI or
    /// probe reads this to tell an operator to sign in again for the connection
    /// rather than let the next start warm-continue on the stored credential.
    /// `persist_with_debt_policy` retires it whenever a later durable
    /// write succeeds — on a rotating connection, the next successful refresh
    /// inside the cross-process lock.
    pub fn persist_debt(&self, id: &ConnectionId) -> Option<bool> {
        self.entries
            .read()
            .get(id)
            .map(|entry| entry.state.lock().persist_debt)
    }

    /// The connection view for `id`, if present.
    pub fn connection(&self, id: &ConnectionId) -> Option<Connection> {
        self.entries
            .read()
            .get(id)
            .map(|entry| entry.state.lock().connection.clone())
    }

    /// Replace the addresses/capabilities on a connection view (the owning
    /// layer sets these; `ConnectionSet` only owns auth_state + credentials).
    pub fn set_addresses(
        &self,
        id: &ConnectionId,
        addresses: Vec<crate::Url>,
        capabilities: crate::Capabilities,
    ) {
        self.commit(|entries, emit| {
            let Some(entry) = entries.get(id) else {
                return;
            };
            let mut state = entry.state.lock();
            state.connection.current_addresses = addresses;
            state.connection.capabilities = capabilities;
            // Pre-announce (the layer sets roots between
            // `add_connection_deferred` and `announce_connection`): update
            // the view silently — the pending `Added` carries these
            // addresses. Suppresses an `Updated`-before-`Added`.
            if !state.announced {
                return;
            }
            let updated = state.connection.clone();
            drop(state);
            emit.send(ConnectionChange::Updated(updated));
        });
    }

    /// Patch a connection's `display_name` / `user_metadata` (the owning layer's
    /// `update_connection_attributes` slot), emitting `ConnectionChange::Updated`.
    /// `user_metadata` entries with `Some(value)` upsert; `None` removes the key.
    pub fn update_attributes(
        &self,
        id: &ConnectionId,
        display_name: Option<String>,
        user_metadata: Vec<(String, Option<String>)>,
    ) -> Result<Connection> {
        self.commit(|entries, emit| {
            let entry = entries
                .get(id)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
            let mut state = entry.state.lock();
            if let Some(name) = display_name {
                state.connection.display_name = name;
            }
            for (key, value) in user_metadata {
                match value {
                    Some(value) => {
                        state.connection.user_metadata.insert(key, value);
                    }
                    None => {
                        state.connection.user_metadata.remove(&key);
                    }
                }
            }
            let updated = state.connection.clone();
            let announced = state.announced;
            drop(state);
            // Suppress the `Updated` while still deferred (mirrors
            // `set_addresses`); the connection view is still returned to the
            // caller.
            if announced {
                emit.send(ConnectionChange::Updated(updated.clone()));
            }
            Ok(updated)
        })
    }

    /// Bring a connection up: validate `initial_creds` (or the driver's
    /// warm-continue creds), record the resulting `ConnectionAuthState`, spawn
    /// background refresh if authenticated with a known expiry, and emit
    /// `ConnectionChange::Added`. Never errors on auth grounds (it parks
    /// `AwaitingAuth`); `Err` only signals an internal contract violation.
    ///
    /// This is the single-shot form: it announces (`Added`) immediately. A
    /// connection-owning layer that must install a route BEFORE the connection
    /// becomes visible should instead call [`Self::add_connection_deferred`],
    /// install its route, then [`Self::announce_connection`] — closing the
    /// race where a subscriber reacting to `Added` by removing the connection
    /// wins against route installation.
    pub async fn add_connection(
        self: &Arc<Self>,
        connection: Connection,
        driver: Arc<D>,
        initial_creds: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<ConnectionAuthState> {
        let id = connection.id.clone();
        let state = self
            .add_connection_deferred(connection, driver, initial_creds, cancel)
            .await?;
        self.announce_connection(&id);
        Ok(state)
    }

    /// Register + validate a connection WITHOUT emitting `ConnectionChange::Added`.
    /// The owning layer installs its route from the returned state, then
    /// calls [`Self::announce_connection`] to emit `Added`. Until announced, the
    /// connection is live (routable, removable) but invisible to subscribers, so
    /// no `Updated`/`Removed` is emitted for it and a remove-on-`Added` consumer
    /// cannot race route installation. Same auth semantics as
    /// [`Self::add_connection`]: never errors on auth grounds (parks
    /// `AwaitingAuth`); `Err` only signals an internal contract violation, and
    /// leaves nothing registered.
    pub async fn add_connection_deferred(
        self: &Arc<Self>,
        connection: Connection,
        driver: Arc<D>,
        initial_creds: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<ConnectionAuthState> {
        let id = connection.id.clone();
        // Claim this identity's durable slot for the whole
        // load-then-register window. A concurrent removal purging the same
        // stable id either completes its delete before this runs — so the
        // warm-continue load below correctly finds nothing — or blocks behind
        // this registration and then observes it live and skips the delete.
        // Without it the purge's membership check is stale by the time its
        // awaited delete fires, and it destroys this connection's credential.
        // Released before validation, so it never nests with the single-flight
        // bring-up lock taken there.
        let registration_guard = match driver.stable_id() {
            Some(stable) => Some(self.purge_lock_for(&stable).lock_owned().await),
            None => None,
        };
        // Warm-continue: if no creds were supplied, try the driver's persisted set.
        let mut creds = initial_creds;
        let mut lineage = Lineage::Fresh;
        if creds.fields.is_empty()
            && let Ok(Some(loaded)) = driver.load_credentials().await
        {
            creds = loaded;
            // Warm-continue lineage: the grant reloads the secret store head under the
            // cross-process lock so a peer's concurrent rotation is picked up.
            lineage = Lineage::Stored;
        }

        let entry = Arc::new(ConnEntry {
            driver: driver.clone(),
            state: Mutex::new(EntryState {
                connection: connection.clone(),
                credentials: creds.clone(),
                history: Vec::new(),
                attempts: 0,
                cred_gen: 0,
                persist_debt: false,
                announced: false,
            }),
            credential_mutation: tokio::sync::Mutex::new(()),
            purge_on_removal: AtomicBool::new(false),
            durable_secret_deleted: AtomicBool::new(false),
            refresh_task: Mutex::new(None),
            cancel: self.cancel.child_token(),
        });
        self.entries.write().insert(id.clone(), entry.clone());
        drop(registration_guard);

        // Serialize the initial validate on the per-connection single-flight
        // lock — like `bring_up` / `update_credentials` — so a warm-continue
        // seed refresh grant driven inside `validate` cannot race a concurrent
        // data-path recovery or background-refresh grant on the same connection.
        // `run_validation` additionally routes the validate through
        // `validate_under_lock` (the stable-keyed CROSS-process lock), so a seed
        // grant is also coalesced with peer processes / same-host siblings
        // (3539838324).
        let state = {
            let lock = self.bringup_lock_for(&id);
            let _guard = lock.lock().await;
            match self
                .run_validation(
                    &entry,
                    &creds,
                    lineage,
                    cancel,
                    AuthReason::NeverAuthenticated,
                )
                .await
            {
                Ok(state) => state,
                Err(error) => {
                    // Cancellation / contract error: don't commit a ghost entry
                    // or emit `Added` — remove the staged entry and propagate.
                    self.entries.write().remove(&id);
                    return Err(error);
                }
            }
        };
        // Deferred: `Added` is emitted by `announce_connection` AFTER the owning
        // layer installs its route.
        Ok(state)
    }

    /// Emit the deferred `ConnectionChange::Added` for a connection registered by
    /// [`Self::add_connection_deferred`], AFTER the owning layer has installed
    /// its route. Idempotent: a call on an already-announced or
    /// absent connection is a no-op. A connection removed before it is
    /// announced never emits `Added` (nor a paired `Removed`).
    pub fn announce_connection(&self, id: &ConnectionId) {
        self.commit(|entries, emit| {
            let Some(entry) = entries.get(id) else {
                return;
            };
            self.announce_seam();
            let mut guard = entry.state.lock();
            if guard.announced {
                return;
            }
            guard.announced = true;
            let view = guard.connection.clone();
            drop(guard);
            emit.send(ConnectionChange::Added(view));
        });
    }

    /// Test-Connection probe: `obtain(NonConsumingOnly)` on the supplied
    /// credentials, then `verify`, returning a [`ProbeOutcome`] verdict WITHOUT
    /// any durable side effect — it does not register the connection, persist
    /// credentials, spawn background refresh, run the `on_authenticated` hook, or
    /// emit any [`ConnectionChange`]. Hosts use this to test a prospective
    /// connection; a probe must not overwrite a keyring secret or perturb the
    /// live set.
    ///
    /// `obtain` / `verify` touch only driver-*private* staging state (the grant
    /// runs against a throwaway `DiscoveryState`; `verify` uses an ephemeral
    /// transport), so a probe never perturbs a live connection's token cell: a
    /// persist-inside-validate footgun cannot arise by construction.
    ///
    /// A probe never consumes a one-time credential: with
    /// [`GrantPolicy::NonConsumingOnly`], a bundle whose only path to a bearer
    /// would drive a refresh-token grant returns [`Obtained::WouldConsume`] →
    /// [`ProbeOutcome::Unverifiable`] (register the connection via the warm-
    /// continue `add_connection` path instead). The supplied bundle (even an
    /// EMPTY one) is still run through `obtain` — an anonymous-friendly backend
    /// reports [`Obtained::Anonymous`], so probe and `add_connection` agree on
    /// credential-less connections — but the probe never falls back to
    /// `load_credentials`.
    pub async fn probe_connection(
        self: &Arc<Self>,
        driver: Arc<D>,
        initial_creds: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<ProbeOutcome> {
        let creds = initial_creds;
        // `obtain(NonConsumingOnly)` produces a bearer from the supplied bundle
        // using only replayable work: a refresh-token-only bundle (whose only
        // path to a bearer would consume the token) returns `WouldConsume` →
        // `Unverifiable`, so a probe never burns a live refresh token. No lock,
        // no keyring read/write, no persist/register/events.
        match driver
            .obtain(&creds, GrantPolicy::NonConsumingOnly, cancel.clone())
            .await
        {
            Ok(Obtained::Bearer {
                credentials,
                expires_at,
            }) => match driver.verify(&credentials, cancel).await {
                Ok(()) => Ok(ProbeOutcome::Authenticated { expires_at }),
                Err(error) => Self::probe_error(error),
            },
            Ok(Obtained::Anonymous) => Ok(ProbeOutcome::Anonymous),
            Ok(Obtained::AwaitingInteractive { reason }) => {
                Ok(ProbeOutcome::NeedsInteractive { reason })
            }
            Ok(Obtained::WouldConsume) => Ok(ProbeOutcome::Unverifiable),
            Err(error) => Self::probe_error(error),
        }
    }

    /// Map an `obtain`/`verify` error into a probe verdict: contract-class errors
    /// surface as `Err`; a soft backend/IdP rejection is a delivered
    /// `Rejected` verdict (no durable state mutated either way).
    fn probe_error(error: Error) -> Result<ProbeOutcome> {
        if matches!(
            error.code(),
            ErrorCode::Cancelled | ErrorCode::InvalidArgument | ErrorCode::Internal
        ) {
            return Err(error);
        }
        Ok(ProbeOutcome::Rejected { error })
    }

    /// Non-interactive credential update (operator paste, broker push, rotation).
    /// Validate, swap + persist on success (`Authenticated`), else park
    /// `AwaitingAuth { CredentialsRotated }` and return the error.
    ///
    /// The validate-and-commit runs under the per-connection single-flight lock
    /// (shared with `bring_up`, `with_recovery`, and the background refresh
    /// task): an in-flight refresh grant of the OLD credential lineage must not
    /// remain concurrent with — and later overwrite — a successful rotation to
    /// a new lineage.
    pub async fn update_credentials(
        self: &Arc<Self>,
        id: &ConnectionId,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<ConnectionAuthState> {
        let entry = self.entry(id)?;
        let lock = self.bringup_lock_for(id);
        let _guard = lock.lock().await;
        // Caller-supplied credentials → `Fresh` lineage (use them as-is, no
        // keyring-head reload). obtain (under the lock) → verify → commit.
        let outcome = async {
            let commit = self
                .obtain_under_lock(&entry, &credentials, Lineage::Fresh, cancel.clone())
                .await?;
            self.apply_grant(&entry, credentials.clone(), commit, cancel.clone())
                .await
        }
        .await;
        match outcome {
            Ok(()) => {}
            // Cancellation must not count as a rotation failure (no park, no
            // counter advance) — mirror `run_validation` / `bring_up`.
            Err(error) if error.code() == ErrorCode::Cancelled => return Err(error),
            Err(error) => {
                self.park(&entry, AuthReason::CredentialsRotated, Some(error.clone()));
                self.emit_updated_if_live(&entry);
                return Err(error);
            }
        }
        let state = entry.state.lock().connection.auth_state.clone();
        self.emit_updated_if_live(&entry);
        // Supplied credentials that did not produce `Authenticated`/`Anonymous`
        // are a failed update, not a success: return `Err` so rotation
        // automation does not believe rejected credentials were accepted. Map
        // the error by the PARK REASON: a `BackendUnreachable` park here means
        // the credentials were ACCEPTED and session establishment (the
        // `on_authenticated` hook) failed — surface the hook's own error (a
        // plain retry after the backend recovers suffices) rather than telling
        // rotation automation to drive a futile interactive sign-in.
        match state {
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous => Ok(state),
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::BackendUnreachable,
                ref last_attempt,
            } => Err(last_attempt
                .as_ref()
                .and_then(|attempt| attempt.error.clone())
                .unwrap_or_else(|| {
                    Error::new(
                        ErrorCode::Transient,
                        "credentials accepted but backend session establishment failed; retry",
                    )
                })),
            _ => Err(Error::new(
                ErrorCode::AuthRequired,
                "supplied credentials did not authenticate; interactive sign-in required",
            )),
        }
    }

    /// Drive the interactive flow. Returns the driver's `AuthEventStream` wrapped
    /// so that a `Succeeded { credentials: Some(..) }` event atomically swaps the
    /// new creds into the connection, transitions to `Authenticated`, restarts
    /// background refresh, and emits `ConnectionChange::Updated` before the event
    /// is forwarded; a `Failed` event records the attempt and parks / latches
    /// `AuthFailed` at the threshold.
    pub async fn authenticate(
        self: &Arc<Self>,
        id: &ConnectionId,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let entry = self.entry(id)?;
        let connection = entry.state.lock().connection.clone();
        // Capture the supersession fence at flow start (cred_gen BEFORE
        // identity_gen, matching the sibling capture sites): a bundle-less
        // `Succeeded { None }` from a fence-lost sign-in must not regress a winner
        // that committed while this flow ran.
        let expected_cred_gen = entry.state.lock().cred_gen;
        let expected_identity_gen = entry.driver.identity_gen();
        // The flow's cancel token is a child of the ENTRY's lifecycle token, so
        // `remove_connection` (which cancels the entry) also cancels the flow —
        // the driver's flow thread uses this as its liveness fence: a sign-in
        // completing after removal must not durably re-persist a secret the
        // removal just deleted. A caller-supplied token is linked in.
        let flow_cancel = entry.cancel.child_token();
        if let Some(caller) = cancel {
            let linked = flow_cancel.clone();
            tokio::spawn(async move {
                caller.cancelled().await;
                linked.cancel();
            });
        }
        let inner = entry
            .driver
            .interactive(connection, capability, Some(flow_cancel))
            .await?;
        Ok(Box::new(AuthStreamAdapter {
            inner,
            set: self.clone(),
            entry,
            expected_cred_gen,
            expected_identity_gen,
        }))
    }

    /// Remove a connection: stop its refresh task, forget its cooldown/lock,
    /// delete persisted secrets, and emit `ConnectionChange::Removed`. This is
    /// explicit user removal — it purges the durable secret.
    pub async fn remove_connection(&self, id: &ConnectionId) -> Result<()> {
        self.remove_inner(id, true).await
    }

    /// Unregister a connection WITHOUT deleting its durable secret — for
    /// bring-up / root-discovery rollback, where a transient failure right after
    /// a rotating grant must not erase the only live refresh token. Cancels the
    /// refresh task and emits `Removed`, but reserves secret deletion for
    /// explicit [`Self::remove_connection`].
    pub async fn unregister_connection(&self, id: &ConnectionId) -> Result<()> {
        self.remove_inner(id, false).await
    }

    /// Delete this connection's durable credential without unregistering it.
    ///
    /// Session-full drivers use this after a rejected credential replacement:
    /// the connection remains parked, but the prior identity must no longer be
    /// warm-continuable. Preserve a shared entry while another live connection
    /// has the same stable identity, matching removal semantics.
    pub async fn purge_persisted_credentials(&self, id: &ConnectionId) -> Result<()> {
        let entry = self.entry(id)?;
        self.purge_durable_credential(&entry, DurablePurge::Purge, || true)
            .await?;
        entry.state.lock().credentials.fields.remove("oauth");
        Ok(())
    }

    async fn remove_inner(&self, id: &ConnectionId, purge_secret: bool) -> Result<()> {
        // Record the purge intent, unregister, decide announcedness and emit
        // `Removed` in one commit section. A concurrent interactive commit that
        // reaches its post-persist liveness check therefore observes both the
        // unregistration and this intent atomically (it reads the flag only
        // after seeing `!is_registered`, which the entries RwLock orders after
        // this store); and a concurrent `announce_connection` either commits its
        // `Added` before this section — in which case `announced` is true here
        // and the paired `Removed` follows — or finds the entry already gone and
        // emits nothing at all.
        //
        // `Removed` is emitted at the commit point rather than after the durable
        // credential purge below: the connection is unregistered the moment this
        // section ends, so a subscriber told later would be reading a stale set
        // for the whole purge (which does remote I/O).
        //
        // That makes the section publishing `Removed` the boundary a subscriber
        // can act on, so EVERYTHING keyed by `id` retires inside it. A consumer
        // reacting to `Removed` by re-registering the same id installs a fresh
        // single-flight lock, cooldown and generation counters; retiring the old
        // ones after the section would drop the NEW connection's entries and
        // leave its next grant unserialized against an in-flight one. The
        // sibling-stable-id decision is taken here too, against the membership
        // this section committed, so a re-add cannot land between the check and
        // the delete and lose its durable secret. Only entry-keyed work (the
        // cancel token, the refresh task) and the awaited purge itself remain
        // outside; neither can be claimed by a re-add.
        let Some(entry) = self.commit(|entries, emit| {
            if let Some(entry) = entries.get(id) {
                entry.purge_on_removal.store(purge_secret, Ordering::SeqCst);
            }
            let entry = entries.remove(id)?;
            // Only a connection subscribers ever saw `Added` for gets a
            // `Removed`: a connection removed while still deferred was never
            // visible.
            if entry.state.lock().announced {
                emit.send(ConnectionChange::Removed { id: id.clone() });
            }
            self.bringup_locks.lock().remove(id);
            self.cooldowns.lock().remove(id);
            self.bringup_gens.lock().remove(id);
            self.refresh_gens.lock().remove(id);
            Some(entry)
        }) else {
            return Err(Error::new(ErrorCode::NotFound, "connection not found"));
        };
        self.remove_seam();
        entry.cancel.cancel();
        if let Some(handle) = entry.refresh_task.lock().take() {
            handle.abort();
        }
        // Delete the persisted secret only when no OTHER live connection shares
        // this connection's stable id (secrets are keyed per stable id, which
        // some drivers derive per host, so a sibling connection to the same host
        // must not lose its token).
        //
        // The check and the delete are taken under this identity's
        // registration lock, not under the membership commit above: the commit
        // section ends before the awaited delete, so a decision taken there is
        // stale by the time the delete lands, and a connection registered in
        // between would lose the credential it had just persisted. Holding the
        // lock across both makes "nothing live claims this identity" true AT the
        // delete rather than merely before it.
        if purge_secret {
            let _ = self
                .purge_durable_credential(&entry, DurablePurge::Delete, || true)
                .await;
        }
        Ok(())
    }

    /// Silent bring-up of a parked connection, coalesced single-flight with a
    /// failure cooldown. `force` skips the cooldown so an explicit re-auth can
    /// retry immediately.
    pub async fn bring_up(
        self: &Arc<Self>,
        id: &ConnectionId,
        force: bool,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let entry = self.entry(id)?;
        // Fast path: already authenticated / anonymous.
        if matches!(
            entry.state.lock().connection.auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            return Ok(());
        }
        if !force && self.in_cooldown(id) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "connection awaiting bring-up; retry after cooldown or call authenticate",
            ));
        }
        // Capture the bring-up generation BEFORE awaiting the lock so we can
        // detect that a winner completed a `validate` attempt while we queued.
        let gen_before = self.bringup_gen(id);
        let lock = self.bringup_lock_for(id);
        let _guard = lock.lock().await;
        // Re-check under the single-flight lock — a waiter may have won the race.
        if matches!(
            entry.state.lock().connection.auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            return Ok(());
        }
        // A winner ran (and FAILED — else the check above returned) while we
        // waited: share its ACTUAL outcome instead of re-validating. Otherwise
        // one concurrent burst runs `validate` per waiter, each advancing
        // `attempts` and hammering the IdP off a single transient failure. The
        // stored outcome preserves the winner's real error class (transient /
        // permission-denied / auth), so headless waiters are not degraded from
        // a retryable state to a hard auth error. (A CANCELLED winner never
        // bumps the generation, so waiters behind it run their own validate.)
        // Non-forced callers additionally respect a cooldown set under the lock.
        if self.bringup_gen(id) != gen_before {
            if !force && self.in_cooldown(id) {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "connection awaiting bring-up; retry after cooldown or call authenticate",
                ));
            }
            return Err(self.bringup_outcome(id).unwrap_or_else(|| {
                Error::new(
                    ErrorCode::AuthRequired,
                    "silent bring-up did not authenticate; call authenticate",
                )
            }));
        }
        // Re-validation of a parked connection: reload the driver's persisted
        // head (the authoritative refresh lineage) rather than replaying a
        // possibly stale in-memory `entry.credentials` — a sibling PROCESS may
        // have rotated the secret store past it, and granting the stale copy trips IdP
        // reuse-detection even serially (S2a / 3539838324). The driver reloads
        // again under the cross-process lock (`validate_under_lock`); handing it
        // the head routes a warm-continue through that reload. Falls back to the
        // in-memory creds when the driver has no persisted head (client-
        // credentials / anonymous).
        //
        // EXCEPT while persist-debted: a prior rotation committed the successor
        // to memory but could NOT persist it, so the secret store head is a CONSUMED
        // predecessor and memory is strictly newer. Skip the reload and grant the
        // in-memory successor (the debt is retired by the next successful persist,
        // after which head-reload resumes). Reading the flag and the creds in ONE
        // lock acquisition avoids racing a concurrent debt retirement.
        let debted_creds = {
            let g = entry.state.lock();
            g.persist_debt.then(|| g.credentials.clone())
        };
        let creds = match debted_creds {
            Some(successor) => successor,
            None => match entry.driver.load_credentials().await {
                Ok(Some(head)) => head,
                // No persisted head (client-credentials / anonymous / never
                // stored): fall back to the in-memory creds.
                Ok(None) => entry.state.lock().credentials.clone(),
                // Secret-store READ error: fail closed. Re-validating on a stale
                // in-memory token we cannot verify against the persisted head
                // risks replaying a consumed token; surface the error and let the
                // caller retry.
                Err(err) => return Err(err),
            },
        };
        // Stored lineage: `obtain` reloads the head under the cross-process lock
        // (picking up a peer's concurrent rotation) before granting; `verify`
        // then runs outside the lock, and commit is fenced on cred/identity gen.
        let result = async {
            let commit = self
                .obtain_under_lock(&entry, &creds, Lineage::Stored, cancel.clone())
                .await?;
            self.apply_grant(&entry, creds.clone(), commit, cancel.clone())
                .await
        }
        .await;
        match result {
            Ok(()) => {
                // Read the resulting state into a local FIRST (releasing the
                // parking_lot guard) — `emit_updated` re-locks `entry.state`, and
                // parking_lot mutexes are not reentrant.
                let authed = matches!(
                    entry.state.lock().connection.auth_state,
                    ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
                );
                if authed {
                    self.record_bringup_outcome(id, None);
                    self.clear_cooldown(id);
                    // Don't emit `Updated` for a connection removed while its
                    // bring-up validate was in flight — subscribers already saw
                    // `Removed` (3539858972).
                    self.emit_updated_if_live(&entry);
                    Ok(())
                } else {
                    // Still parked → surface (needs interactive).
                    let error = Error::new(
                        ErrorCode::AuthRequired,
                        "silent bring-up did not authenticate; call authenticate",
                    );
                    self.record_bringup_outcome(id, Some(error.clone()));
                    self.set_cooldown(id);
                    self.emit_updated_if_live(&entry);
                    Err(error)
                }
            }
            // Cancellation must never count as an auth attempt (no park, no
            // counter advance, no cooldown) — app shutdown / UI navigation
            // racing a silent bring-up would otherwise latch `AuthFailed`. It
            // also does NOT bump the bring-up generation: no attempt actually
            // completed, so queued waiters (whose own tokens never fired) run
            // their own validate instead of receiving a spurious auth error.
            Err(error) if error.code() == ErrorCode::Cancelled => Err(error),
            Err(error) => {
                let reason = if self.classify_reason(&entry, &error) {
                    AuthReason::NeverAuthenticated
                } else {
                    AuthReason::BackendUnreachable
                };
                self.record_bringup_outcome(id, Some(error.clone()));
                self.park(&entry, reason, Some(error.clone()));
                self.set_cooldown(id);
                self.emit_updated_if_live(&entry);
                Err(error)
            }
        }
    }

    /// Data-path recovery: run one object op, and if it fails with a
    /// driver-classified *recoverable credential* error, invalidate + refresh +
    /// retry **once** before surfacing. `PermissionDenied`, interactive-only,
    /// and non-auth errors surface without a retry.
    ///
    /// Success is not read as evidence here. Use
    /// [`Self::with_recovery_promoting_if`] to promote a parked connection on
    /// an operation that the backend is KNOWN to have accepted.
    pub async fn with_recovery<T, F, Fut>(self: &Arc<Self>, id: &ConnectionId, op: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.recover(id, None::<fn() -> bool>, op).await
    }

    /// [`Self::with_recovery`], plus: ask `backend_accepted` whether the backend
    /// accepted a request signed with this connection's credentials while the
    /// operation ran, and if so promote a connection parked in `AwaitingAuth`
    /// to `Authenticated`, emitting `Updated`. Asked on BOTH arms — a request
    /// the service authenticated and then answered with a verdict the caller
    /// sees as an error is still proof of the credential.
    ///
    /// `backend_accepted` is asked AFTER the operation, deliberately. Whether a
    /// slot reached the wire is a property of the RUN, not of the slot: the same
    /// `read` mints a URL locally on a flat namespace and sends a kind preflight
    /// on a hierarchical one; a paged list can answer an empty page without
    /// asking; a `check_access` reports the backend's refusal as `Ok`. An
    /// implementation that answers this from a per-slot table is guessing —
    /// answer it from something that observed the response, such as a counter on
    /// the transport that saw it.
    pub async fn with_recovery_promoting_if<T, F, Fut, A>(
        self: &Arc<Self>,
        id: &ConnectionId,
        backend_accepted: A,
        op: F,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        A: Fn() -> bool,
    {
        self.recover(id, Some(backend_accepted), op).await
    }

    /// Promote a parked connection on an operation the backend accepted,
    /// WITHOUT the retry-once recovery loop.
    ///
    /// A write consumes its body, so it cannot be replayed and does not run
    /// under [`Self::with_recovery`] — but a response the service gave it is
    /// the same evidence any other accepted request is, and a connection whose
    /// writes the backend is answering must not go on reporting that it needs
    /// authentication. `backend_accepted` carries the same contract as
    /// [`Self::with_recovery_promoting_if`]'s, including that it may be false
    /// for an operation whose requests were performed by someone else.
    pub async fn with_promotion_if<T, Fut, A>(
        self: &Arc<Self>,
        id: &ConnectionId,
        backend_accepted: A,
        op: Fut,
    ) -> Result<T>
    where
        Fut: std::future::Future<Output = Result<T>>,
        A: Fn() -> bool,
    {
        // Captured before the op, for the identity fence `recover` documents.
        let promotable = self.entries.read().get(id).cloned();
        let outcome = op.await;
        // Evidence, not outcome: a write that lost a precondition still had its
        // request authenticated, so it promotes exactly as a successful one
        // does. See `recover` for why both arms are read.
        if let Some(entry) = promotable
            && backend_accepted()
        {
            self.note_backend_accepted(&entry);
        }
        outcome
    }

    async fn recover<T, F, Fut, A>(
        self: &Arc<Self>,
        id: &ConnectionId,
        backend_accepted: Option<A>,
        op: F,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        A: Fn() -> bool,
    {
        // Captured BEFORE the op so the promotion can be fenced on entry
        // IDENTITY, not just on the id: a removal and a re-add of the same id
        // while this op is in flight installs a DIFFERENT connection, and this
        // op's success says nothing about that one's credentials. A caller that
        // never promotes pays nothing for it.
        let promotable = backend_accepted
            .as_ref()
            .and_then(|_| self.entries.read().get(id).cloned());
        // Acceptance is read on BOTH arms, because an implementation's
        // allowlist deliberately counts verdicts that surface to the caller as
        // `Err` — a 412 for a lost precondition, say, or a plugin's own
        // directory refusal whose kind preflight the service answered before
        // `read` refused the address. Those are requests the backend
        // authenticated; a workload made of them would otherwise leave a
        // working connection parked forever. Which statuses qualify is the
        // implementation's judgment, not this function's.
        let first = op().await;
        // `promotable` is CAPTURED, not passed: it is the entry this operation
        // started against, and handing the closure a different one — the
        // post-op lookup below, say — would silently defeat the identity fence.
        let note_acceptance = || {
            if let (Some(entry), Some(check)) = (promotable.as_ref(), backend_accepted.as_ref())
                && check()
            {
                self.note_backend_accepted(entry);
            }
        };
        let error = match first {
            Ok(value) => {
                note_acceptance();
                return Ok(value);
            }
            Err(error) => {
                note_acceptance();
                error
            }
        };
        let Some(entry) = self.entries.read().get(id).cloned() else {
            return Err(error);
        };
        if !entry.driver.classify(&error).is_recoverable() {
            return Err(error);
        }
        // Coalesce concurrent recoveries: under load, N ops failing on the same
        // expired token must drive exactly ONE refresh grant — concurrent grants
        // on a rotating refresh token can trip IdP reuse-detection and revoke the
        // token family, turning a recoverable expiry into forced interactive
        // re-auth. Serialize on the per-connection lock (shared with `bring_up`),
        // then re-check: if another op/task already refreshed while we waited,
        // skip the grant and just retry the op with the fresh creds.
        let (gen_before, refresh_gen_before) = (entry.state.lock().cred_gen, self.refresh_gen(id));
        let lock = self.bringup_lock_for(id);
        // Only the `cred_gen` re-check and the refresh grant need the exclusion
        // (concurrent grants on a rotating refresh token can trip IdP
        // reuse-detection). The retried `op` — potentially a long data transfer
        // — is driven OUTSIDE the guard, so N ops recovering from the same
        // expiry don't serialize behind one slow retry.
        let refresh_outcome = {
            let _guard = lock.lock().await;
            if entry.state.lock().cred_gen != gen_before {
                // Another op/task already refreshed while we waited — retry with
                // the fresh creds, no grant of our own.
                RecoveryStep::Retry
            } else if self.refresh_gen(id) != refresh_gen_before {
                // A refresh attempt COMPLETED while we waited and did NOT move
                // `cred_gen` — i.e. the winner's refresh FAILED. Share that
                // failure (the winner already classified + parked as needed)
                // instead of re-driving the grant with the same dead
                // credentials: N queued waiters re-granting would hammer the
                // IdP and inflate `attempts` toward `AuthFailed` off a single
                // failing winner.
                RecoveryStep::Surface
            } else {
                let creds = entry.state.lock().credentials.clone();
                // Capture the driver's identity generation at grant start — the
                // second supersession fence (alongside `gen_before` / cred_gen)
                // threaded through the whole refresh→record window. A concurrent
                // interactive `Succeeded { credentials: None }` winner bumps ONLY
                // this, so both the in-lock commit and `record_refreshed` gate on
                // it to discard a superseded refresh whole.
                let identity_before = entry.driver.identity_gen();
                let outcome = self
                    .coalesced_refresh(&entry, &creds, gen_before, identity_before)
                    .await;
                // Every COMPLETED attempt (success or failure) bumps the
                // refresh generation so queued waiters coalesce on it.
                self.bump_refresh_gen(id);
                match outcome {
                    Ok((refreshed, persisted)) => {
                        self.record_refreshed(
                            &entry,
                            refreshed,
                            gen_before,
                            identity_before,
                            persisted,
                        )
                        .await;
                        RecoveryStep::Retry
                    }
                    Err(refresh_err) => {
                        // Classify the refresh failure: a credential/revoked/
                        // interactive-class failure means the token is dead —
                        // park + emit `Updated` so subscribers stop seeing a
                        // healthy connection and the host re-auths. A transient
                        // failure keeps `Authenticated` (a later op / background
                        // refresh may recover).
                        use super::driver::AuthErrorClass;
                        if matches!(
                            entry.driver.classify(&refresh_err),
                            AuthErrorClass::RecoverableCredential
                                | AuthErrorClass::Revoked
                                | AuthErrorClass::NeedsInteractive
                        ) {
                            self.park_refresh_failure(&entry, &refresh_err);
                        }
                        RecoveryStep::Surface
                    }
                }
            }
        };
        match refresh_outcome {
            RecoveryStep::Retry => {
                // The retry is an operation too: whatever the refresh did or
                // did not commit, a request the backend accepted on this
                // attempt is the same evidence the first attempt would have
                // been. A retry that succeeds because another task refreshed
                // meanwhile leaves the connection parked otherwise.
                let retried = op().await;
                note_acceptance();
                retried
            }
            RecoveryStep::Surface => Err(error),
        }
    }

    /// Promote a connection parked in `AwaitingAuth` on evidence that the
    /// backend accepted one of its own data-path requests.
    ///
    /// Note "request", not "operation": the caller may report acceptance for an
    /// operation that went on to fail, because a lost precondition or a
    /// backend's own type refusal are answers to a request the service
    /// authenticated. Which statuses qualify is the implementation's judgment
    /// — every backend in this tree deliberately excludes 404, which a missing
    /// bucket earns without the credential deciding anything.
    ///
    /// `verify` proves one probe call on one verb; the data path proves the
    /// operation the caller actually asked for, with the credentials the
    /// connection actually holds. When the two disagree the data path is the
    /// better evidence, and the disagreement is reachable: a driver's probe can
    /// be refused (a verb the account scopes differently, a gateway in front of
    /// one path, clock skew at add time) while every subsequent signed request
    /// succeeds. Without this, such a connection reports `AwaitingAuth`
    /// permanently — a host trusting the report prompts for authentication that
    /// is not needed, or calls a working connection unavailable — and for a
    /// driver with no refresh and frozen credentials nothing can ever clear it.
    ///
    /// Only `AwaitingAuth` promotes. `Anonymous` has no credentials to
    /// vindicate, `Authenticated` is already the answer, and `AuthFailed` is
    /// latched deliberately for the host to act on. Credentials are untouched,
    /// so `cred_gen` does not move; the promotion carries no `expires_at`
    /// because a successful op tells us nothing about expiry. It does not go
    /// near the refresh task either — `spawn_refresh` is what would ABORT a
    /// live one on a `None` expiry, so a connection that still has a refresh
    /// armed from an earlier authenticated stretch keeps it.
    ///
    /// The limit that follows, stated so nobody has to rediscover it: the
    /// refresh loop exits when it wakes on a connection that is not
    /// `Authenticated`, so a connection parked long enough to lose its task and
    /// then promoted here has no PROACTIVE refresh — an expiry is recovered
    /// reactively, on the next op, through this same function's caller. That is
    /// the state the connection was already in while parked; the promotion
    /// makes it report the truth, it does not make the schedule worse.
    /// `entry` is the entry the operation actually ran against, captured before
    /// it started: a remove-then-re-add reuses the id with a FRESH entry, and
    /// this op's success is no evidence about that one's credentials. The
    /// commit section re-checks identity through [`Self::is_live`] for exactly
    /// that reason, as every other `Updated`-emitting path here does.
    fn note_backend_accepted(&self, entry: &Arc<ConnEntry<D>>) {
        // Every successful proving op passes here, so the common case — a
        // connection that is already `Authenticated` — costs one state peek.
        // Only a parked connection enters the commit section.
        if !matches!(
            entry.state.lock().connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ) {
            return;
        }
        self.commit(|entries, emit| {
            if !Self::is_live(entries, entry) {
                return;
            }
            let id = {
                // Re-checked under the commit section: a concurrent bring-up or
                // interactive success may have promoted it in the gap.
                let mut guard = entry.state.lock();
                if !matches!(
                    guard.connection.auth_state,
                    ConnectionAuthState::AwaitingAuth { .. }
                ) {
                    return;
                }
                let now = SystemTime::now();
                guard.connection.auth_state = ConnectionAuthState::Authenticated {
                    last_authenticated_at: now,
                    expires_at: None,
                };
                guard.connection.last_probed = Some(now);
                guard.attempts = 0;
                guard.connection.id.clone()
            };
            // Inside the section, like every other retirement of id-keyed state:
            // a removal landing between the write and the clear would otherwise
            // drop the SUCCESSOR connection's cooldown.
            self.clear_cooldown(&id);
            self.emit_updated(emit, entry);
        });
    }

    // ---- internals -------------------------------------------------------

    fn entry(&self, id: &ConnectionId) -> Result<Arc<ConnEntry<D>>> {
        self.entries
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))
    }

    /// True when `error` is a credential-class failure (vs. backend/wire).
    fn classify_reason(&self, entry: &ConnEntry<D>, error: &Error) -> bool {
        use super::driver::AuthErrorClass;
        matches!(
            entry.driver.classify(error),
            AuthErrorClass::RecoverableCredential
                | AuthErrorClass::Revoked
                | AuthErrorClass::NeedsInteractive
                | AuthErrorClass::PermissionDenied
        )
    }

    /// Apply a `validate` outcome to the entry at bring-up (`add_connection`).
    /// Returns `Err` for cancellation + non-lifecycle contract errors
    /// (`Cancelled`/`InvalidArgument`/`Internal`) so the caller removes the
    /// staged entry rather than committing a retriable-looking parked ghost;
    /// genuine auth / backend-reachability failures park and return `Ok`.
    async fn run_validation(
        self: &Arc<Self>,
        entry: &Arc<ConnEntry<D>>,
        creds: &SecretBundle,
        lineage: Lineage,
        cancel: Option<CancellationToken>,
        park_reason: AuthReason,
    ) -> Result<ConnectionAuthState> {
        // obtain (under the cross-process lock) → verify (outside it) → commit.
        // An `obtain` error and a `verify` rejection both flow to the same park.
        let outcome = async {
            let commit = self
                .obtain_under_lock(entry, creds, lineage, cancel.clone())
                .await?;
            self.apply_grant(entry, creds.clone(), commit, cancel.clone())
                .await
        }
        .await;
        if let Err(error) = outcome {
            if matches!(
                error.code(),
                ErrorCode::Cancelled | ErrorCode::InvalidArgument | ErrorCode::Internal
            ) {
                return Err(error);
            }
            let reason = if self.classify_reason(entry, &error) {
                park_reason
            } else {
                AuthReason::BackendUnreachable
            };
            self.park(entry, reason, Some(error));
            self.set_cooldown(&entry.state.lock().connection.id.clone());
        }
        Ok(entry.state.lock().connection.auth_state.clone())
    }

    /// Commit a locked obtain grant: run `verify` (OUTSIDE the cross-process
    /// lock, on the driver's ephemeral transport) and, on backend acceptance,
    /// `activate` + swap state. Returns `Err(error)` ONLY when the backend
    /// `verify` rejected the bearer — the caller classifies + parks (same as an
    /// `obtain` error). `Anonymous` / `AwaitingInteractive` commit directly.
    async fn apply_grant(
        self: &Arc<Self>,
        entry: &Arc<ConnEntry<D>>,
        creds: SecretBundle,
        commit: GrantCommit,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        match commit.outcome {
            Obtained::Bearer {
                credentials,
                expires_at,
            } => {
                // Prove backend acceptance on an ephemeral transport, OUTSIDE any
                // lock. Nothing touched the live cell yet, so a rejection needs no
                // rollback — the rotated successor is already durable (persisted
                // under the lock in `obtain_and_persist`), and the next bring_up
                // reloads it.
                entry.driver.verify(&credentials, cancel.clone()).await?;
                self.commit_authenticated(
                    entry,
                    credentials,
                    expires_at,
                    commit.expected_identity_gen,
                    commit.expected_cred_gen,
                    commit.lineage,
                    cancel,
                )
                .await;
            }
            Obtained::Anonymous => {
                self.set_state(entry, creds, ConnectionAuthState::Anonymous);
            }
            Obtained::AwaitingInteractive { reason } => {
                // A successful grant that merely reports interactive sign-in is
                // required must NOT advance the failure counter.
                self.park_awaiting(entry, reason);
            }
            Obtained::WouldConsume => {
                // `AllowConsuming` never yields `WouldConsume`; defensive.
                self.park_awaiting(entry, AuthReason::NeverAuthenticated);
            }
        }
        Ok(())
    }

    /// Install a verified bearer on the live cell and swap state, fenced on the
    /// supersession generations captured at grant start. `verify` ran OUTSIDE the
    /// cross-process lock, so a concurrent interactive success (identity_gen) or
    /// refresh/update (cred_gen) may have committed a NEWER bundle meanwhile —
    /// discard rather than regress to this now-stale bundle. The successor was
    /// already persisted under the lock; do NOT re-persist.
    #[allow(clippy::too_many_arguments)]
    async fn commit_authenticated(
        self: &Arc<Self>,
        entry: &Arc<ConnEntry<D>>,
        effective: SecretBundle,
        expires_at: Option<SystemTime>,
        expected_identity_gen: u64,
        expected_cred_gen: u64,
        lineage: Lineage,
        cancel: Option<CancellationToken>,
    ) {
        let now = SystemTime::now();
        let id = entry.state.lock().connection.id.clone();
        // Fence removal (grant completed after removal) and a concurrent set-side
        // commit (cred_gen advanced): do not touch a removed / superseded entry.
        if !self.is_registered(&id) || entry.state.lock().cred_gen != expected_cred_gen {
            return;
        }
        // Install on the live cell, identity_gen-fenced INSIDE the driver: a
        // concurrent interactive success bumped identity_gen → the fenced install
        // SKIPS (reporting `Ok(false)`) rather than regress the live cell. A driver
        // `Err` (e.g. a malformed bundle) is likewise discarded. A `Fresh` explicit
        // update (operator paste / rotation push) is a NEW identity, so it commits
        // with REPLACE semantics (overwrite/clear the refresh + M2M slots, bump
        // identity_gen); a stored-lineage bring-up / warm-continue merges onto the same
        // identity.
        //
        // The returned flag is whether the fenced install COMMITTED, computed under
        // the driver's install lock (`identity_gen == expected`). Gate the set-side
        // write on THIS flag, not a post-hoc `identity_gen()` re-read: the replace
        // path (`activate_replacing`) bumps `identity_gen` ITSELF on a successful
        // commit, so an equality re-read cannot tell the driver's own legitimate
        // bump from a racing winner's — it would false-positive on every `Fresh`
        // commit and drop the whole set-side write. A re-read would also reopen the
        // race a winner landing between the internal commit and the re-read exploits.
        let committed = match lineage {
            Lineage::Fresh => {
                entry
                    .driver
                    .activate_replacing(&effective, expected_identity_gen)
                    .await
            }
            Lineage::Stored => {
                entry
                    .driver
                    .activate(&effective, expected_identity_gen)
                    .await
            }
        };
        // A driver error or a NON-committed fenced install (a real racing winner
        // superseded this grant before it could install) discards set-side, exactly
        // as an identity_gen mismatch did.
        if !matches!(committed, Ok(true)) {
            return;
        }
        // Perform the final cred_gen recheck AND the set-side state write
        // under ONE held `entry.state` guard. `verify` and the fenced install ran
        // OUTSIDE the cross-process lock, so a concurrent interactive winner may
        // commit set-side (its `set_state` bumps cred_gen) meanwhile. With the
        // recheck and the write as SEPARATE lock acquisitions, that winner's
        // set-side commit could land BETWEEN them, letting this now-stale grant
        // regress `entry.credentials` / `auth_state`. Holding the guard across the
        // cred_gen check and the state write — with NO await between them —
        // serializes this commit against the winner's set-side write, so a
        // superseded grant DISCARDS rather than regresses. (The live-cell / M2M
        // resurrection is already fenced INSIDE the install by the committed flag
        // above.) Inlines `set_state`'s body because the recheck and the write must
        // share one guard (a re-entrant `set_state` call would deadlock the
        // parking_lot mutex).
        {
            let mut guard = entry.state.lock();
            if guard.cred_gen != expected_cred_gen {
                return;
            }
            // The `cred_gen` flag alone gates the `Fresh` / replace path: its
            // `activate_replacing` self-bumps `identity_gen` on a successful commit,
            // so an equality re-read here would false-positive on every `Fresh`
            // commit. The `secret store` bring-up / warm-continue path's `activate` does
            // NOT bump `identity_gen`, so a racing interactive winner can bump it
            // between this grant's `activate` returning `Ok(true)` and this guard,
            // with `cred_gen` unchanged — recheck `identity_gen` on the secret store arm
            // to discard rather than commit a stale grant over the newer identity.
            if matches!(lineage, Lineage::Stored)
                && entry.driver.identity_gen() != expected_identity_gen
            {
                return;
            }
            guard.credentials = effective;
            guard.cred_gen = guard.cred_gen.wrapping_add(1);
            guard.connection.auth_state = ConnectionAuthState::Authenticated {
                last_authenticated_at: now,
                expires_at,
            };
            guard.connection.last_probed = Some(now);
            guard.attempts = 0;
        }
        // Run the session-establishment hook BEFORE arming refresh; a hook
        // failure parks the connection rather than leaving it `Authenticated`.
        if self.run_on_authenticated(entry, cancel).await.is_err() {
            return;
        }
        self.spawn_refresh(entry, expires_at);
    }

    /// Run the driver's `on_authenticated` session-establishment hook after an
    /// authenticated commit. On failure, park the connection (and emit) so a
    /// failed session establishment does not leave it reporting `Authenticated`.
    /// Every path that ESTABLISHES a connection's credentials routes the hook
    /// through here, so the extension point runs consistently. The one
    /// transition to `Authenticated` that does not is
    /// [`Self::note_backend_accepted`], and deliberately: it commits no
    /// credentials and establishes no session — the op whose success promoted
    /// the connection already ran over the session this hook would set up.
    async fn run_on_authenticated(
        &self,
        entry: &ConnEntry<D>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let connection = entry.state.lock().connection.clone();
        match entry.driver.on_authenticated(&connection, cancel).await {
            Ok(()) => Ok(()),
            Err(error) => {
                // Fence removal (mirrors the adapter's `Failed` arm): a hook that
                // failed BECAUSE removal cancelled its token must not park the
                // removed entry or emit `Updated` for an id subscribers just saw
                // `Removed`. A live entry's hook failure still parks + emits once.
                self.park_and_emit_if_live(
                    entry,
                    AuthReason::BackendUnreachable,
                    Some(error.clone()),
                );
                Err(error)
            }
        }
    }

    /// Store creds + auth_state, clear the failure counter on success.
    fn set_state(
        &self,
        entry: &ConnEntry<D>,
        creds: SecretBundle,
        auth_state: ConnectionAuthState,
    ) {
        let mut guard = entry.state.lock();
        guard.credentials = creds;
        guard.cred_gen = guard.cred_gen.wrapping_add(1);
        let authed = matches!(
            auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        );
        guard.connection.auth_state = auth_state;
        guard.connection.last_probed = Some(SystemTime::now());
        if authed {
            guard.attempts = 0;
        }
    }

    fn commit_interactive_credentials(
        &self,
        entry: &ConnEntry<D>,
        credentials: SecretBundle,
        expires_at: Option<SystemTime>,
    ) -> bool {
        let id = entry.state.lock().connection.id.clone();
        if !self.is_registered(&id) {
            return false;
        }
        let mut guard = entry.state.lock();
        // The flow was fenced before its terminal event was QUEUED; this is the
        // point where the queue has drained, and a newer flow may have committed
        // in the gap. Asked of the driver, under the same guard as the write, so
        // the answer cannot go stale between the two. Refusing here only
        // declines the swap — the winner's credentials stand.
        if !entry.driver.credentials_are_current(&credentials) {
            return false;
        }
        guard.credentials = credentials;
        guard.cred_gen = guard.cred_gen.wrapping_add(1);
        guard.connection.auth_state = ConnectionAuthState::Authenticated {
            last_authenticated_at: SystemTime::now(),
            expires_at,
        };
        guard.connection.last_probed = Some(SystemTime::now());
        guard.attempts = 0;
        true
    }

    /// Transition to `Authenticated` WITHOUT swapping the stored credential
    /// bundle — for an interactive `Succeeded { credentials: None }` where the
    /// driver installed tokens into its own transport/state and reports success
    /// but hands back no bundle for us to store. Resets the failure counter.
    ///
    /// Fenced on `expected_cred_gen` / `expected_identity_gen` (captured at flow
    /// start) under one held guard, mirroring [`Self::record_refreshed`]: a
    /// superseded loser's terminal `Succeeded { None }` (a driver downgrades a
    /// fence-lost sign-in to exactly that) must not overwrite the winner's
    /// `expires_at` — clobbering it to `None` would silently disarm proactive
    /// refresh. Returns whether the transition committed.
    fn set_authenticated_keep_creds(
        &self,
        entry: &ConnEntry<D>,
        expires_at: Option<SystemTime>,
        expected_cred_gen: u64,
        expected_identity_gen: u64,
    ) -> bool {
        let mut guard = entry.state.lock();
        if guard.cred_gen != expected_cred_gen
            || entry.driver.identity_gen() != expected_identity_gen
        {
            return false;
        }
        guard.connection.auth_state = ConnectionAuthState::Authenticated {
            last_authenticated_at: SystemTime::now(),
            expires_at,
        };
        guard.connection.last_probed = Some(SystemTime::now());
        guard.attempts = 0;
        true
    }

    /// Park `AwaitingAuth { reason }` WITHOUT advancing the failure counter or
    /// recording a (non-error) attempt — for a successful validation that only
    /// reports interactive sign-in is required. Only real `Err` outcomes (via
    /// [`Self::park`]) advance toward `AuthFailed`.
    fn park_awaiting(&self, entry: &ConnEntry<D>, reason: AuthReason) {
        let mut guard = entry.state.lock();
        guard.connection.auth_state = ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt: None,
        };
        guard.connection.last_probed = Some(SystemTime::now());
    }

    /// Park `AwaitingAuth { reason }` (or latch `AuthFailed` past the attempt
    /// threshold), recording the attempt in bounded history.
    fn park(&self, entry: &ConnEntry<D>, reason: AuthReason, error: Option<Error>) {
        let mut guard = entry.state.lock();
        let attempt = AuthAttempt {
            at: SystemTime::now(),
            error: error.clone(),
        };
        guard.history.push(attempt.clone());
        let max = self.config.max_attempt_history;
        if guard.history.len() > max {
            let overflow = guard.history.len() - max;
            guard.history.drain(0..overflow);
        }
        guard.attempts = guard.attempts.saturating_add(1);
        if guard.attempts >= self.config.max_auth_attempts {
            let error = error.unwrap_or_else(|| {
                Error::new(ErrorCode::AuthRequired, "auth attempt threshold reached")
            });
            guard.connection.auth_state = ConnectionAuthState::AuthFailed {
                error,
                attempts: guard.attempts,
            };
        } else {
            guard.connection.auth_state = ConnectionAuthState::AwaitingAuth {
                reason,
                last_attempt: Some(attempt),
            };
        }
    }

    /// Record refreshed creds (background refresh + data-path recovery): swap in
    /// the fresh bundle, set `Authenticated`, persist, respawn the refresh task.
    ///
    /// `expected_gen` / `expected_identity_gen` are the `cred_gen` and the
    /// driver's `identity_gen` the refresh's INPUT credentials were cloned at: if
    /// EITHER moved while the grant was in flight (an interactive success —
    /// including a `Succeeded { credentials: None }` that bumps ONLY
    /// `identity_gen` — or a credential update / refresh committed a NEWER
    /// lineage), the stale result is DISCARDED rather than committed. A refresh of
    /// old lineage A must not overwrite a successful rotation to B, nor let a
    /// refresh successor clobber an interactive identity set-side, in memory or
    /// the secret store.
    async fn record_refreshed(
        self: &Arc<Self>,
        entry: &Arc<ConnEntry<D>>,
        refreshed: Refreshed,
        expected_gen: u64,
        expected_identity_gen: u64,
        persisted: bool,
    ) {
        // Fence removal: if the connection was removed while this refresh grant
        // was in flight, do NOT re-persist the (just-deleted) secret, respawn a
        // task, or emit `Updated` for a removed id.
        let id = entry.state.lock().connection.id.clone();
        if !self.is_registered(&id) {
            return;
        }
        let now = SystemTime::now();
        // Perform the dual-generation supersession recheck AND the set-side state
        // write under ONE held `entry.state` guard, with NO `.await` between them
        // (mirrors `commit_authenticated`). This refresh grant ran OUTSIDE the
        // bring-up lock, so a concurrent interactive winner may commit a NEWER
        // lineage set-side WITHOUT taking that lock: its `AuthStreamAdapter`
        // `set_state` bumps `cred_gen`, and a `Succeeded { credentials: None }`
        // winner's driver token replacement bumps ONLY the driver's `identity_gen`.
        // With the recheck and the write as SEPARATE lock acquisitions, that
        // winner's set-side commit could land BETWEEN them, letting this now-stale
        // refresh successor regress `entry.credentials` / `auth_state` / `cred_gen`
        // back to the consumed predecessor's lineage — and, on the `!persisted`
        // fallback below, persist it OVER the winner. Holding the guard across the
        // `identity_gen` read (a driver-side atomic), the `cred_gen` check, and the
        // state write serializes this commit against the winner's set-side write,
        // so a superseded grant DISCARDS rather than regresses. Inlines
        // `set_state`'s body (state / credentials / cred_gen / auth_state write)
        // because the recheck and the write must share one guard — a re-entrant
        // `set_state` call would deadlock the parking_lot mutex.
        {
            let mut guard = entry.state.lock();
            if guard.cred_gen != expected_gen
                || entry.driver.identity_gen() != expected_identity_gen
            {
                tracing::debug!(
                    target: "ovstorage.connection",
                    connection = %id.0,
                    "discarding a refresh result superseded by a newer credential or identity commit",
                );
                return;
            }
            guard.credentials = refreshed.credentials.clone();
            guard.cred_gen = guard.cred_gen.wrapping_add(1);
            guard.connection.auth_state = ConnectionAuthState::Authenticated {
                last_authenticated_at: now,
                expires_at: refreshed.expires_at,
            };
            guard.connection.last_probed = Some(now);
            guard.attempts = 0;
        }
        // Reaching here means the guarded recheck PASSED and this grant committed
        // its successor to memory atomically — so the fallback persist below writes
        // the bundle this grant actually committed, never one superseded at the
        // atomic commit point (a superseded grant returned inside the guard above,
        // before any persist). The remaining window between this guarded commit and
        // the async keyring write is the pre-existing tracked issue 3539858459.
        //
        // Persist ONLY if `coalesced_refresh` did not already persist the
        // successor inside the cross-process lock (3539858459): a second,
        // out-of-lock persist here could overwrite a peer's freshly-rotated
        // token with our now-consumed predecessor and re-arm IdP reuse-detection.
        if !persisted {
            // Route the out-of-lock fallback persist through the debt policy so a
            // keyring write failure marks persist-debt (memory stays authoritative
            // on the successor) instead of silently stranding memory on a
            // predecessor a later secret store-lineage bring-up would replay.
            self.persist_with_debt_policy(entry, &refreshed.credentials)
                .await;
            // The `is_registered` check above and this persist are not atomic
            // (3539858875): a `remove_connection` landing between them would
            // leave the just-deleted secret re-written as an orphan. Re-check
            // liveness after the persist; if the connection was removed (and no
            // sibling shares its stable id), delete the orphan, mirroring
            // `remove_inner`'s guard.
            if !self.is_registered(&id) {
                let _ = self
                    .purge_durable_credential(entry, DurablePurge::Delete, || {
                        !self.is_registered(&id)
                    })
                    .await;
                return;
            }
        }
        // Re-run the session-establishment hook on every re-authentication (a
        // refreshed bearer may need the session re-established); park on failure.
        if self.run_on_authenticated(entry, None).await.is_err() {
            return;
        }
        self.spawn_refresh(entry, refreshed.expires_at);
        self.emit_updated_if_live(entry);
    }

    /// Whether another live connection shares `entry`'s driver stable id — used
    /// to avoid deleting a per-stable (e.g. per-host/origin) secret a sibling
    /// connection still needs. Mirrors `remove_inner`'s sibling guard.
    fn stable_id_shared_by_other(&self, entry: &ConnEntry<D>) -> bool {
        let Some(stable) = entry.driver.stable_id() else {
            return false;
        };
        self.entries.read().values().any(|other| {
            !std::ptr::eq(other.as_ref(), entry)
                && other.driver.stable_id().as_ref() == Some(&stable)
        })
    }

    /// Emit `Updated` for `entry` from inside a commit section.
    fn emit_updated(
        &self,
        emit: &Emit<'_, broadcast::Sender<ConnectionChange>>,
        entry: &ConnEntry<D>,
    ) {
        let guard = entry.state.lock();
        // Suppress `Updated` until the connection has been announced —
        // e.g. a validation hook failure during `add_connection_deferred`.
        // The pending `Added` will carry the current state.
        if !guard.announced {
            return;
        }
        let view = guard.connection.clone();
        drop(guard);
        emit.send(ConnectionChange::Updated(view));
    }

    /// Whether `entry` is still THIS set's registered entry — identity, not just
    /// "something is registered under that id". A remove-then-re-add reuses the
    /// id with a fresh entry, and the retired entry's view must not be reported
    /// as an update to the new connection.
    fn is_live(entries: &HashMap<ConnectionId, Arc<ConnEntry<D>>>, entry: &ConnEntry<D>) -> bool {
        let id = entry.state.lock().connection.id.clone();
        entries
            .get(&id)
            .is_some_and(|current| std::ptr::eq(current.as_ref(), entry))
    }

    /// Emit `Updated` for `entry`, but only while it is still registered — an
    /// operation whose connection was removed while it was in flight must not
    /// emit `Updated` for an id subscribers just saw `Removed`. Nothing follows
    /// it, so a consumer keyed by connection resurrects a dead entry.
    ///
    /// The liveness check and the emission share the commit section that orders
    /// unregistration, so the removal lands wholly before this (and nothing is
    /// emitted) or wholly after (and its `Removed` follows this `Updated`). Split
    /// across two sections they interleave, and the fence is advisory.
    ///
    /// This is the only way to emit `Updated`: every caller's mutation is
    /// committed under `entry.state`, which does not order against the `entries`
    /// map, so none of them may report it unfenced.
    fn emit_updated_if_live(&self, entry: &ConnEntry<D>) {
        self.commit(|entries, emit| {
            if Self::is_live(entries, entry) {
                self.emit_updated(emit, entry);
            }
        });
    }

    /// Park `entry` and emit its `Updated`, both only while it is still
    /// registered. For the callers that must not park a removed entry either.
    fn park_and_emit_if_live(
        &self,
        entry: &ConnEntry<D>,
        reason: AuthReason,
        error: Option<Error>,
    ) {
        self.commit(|entries, emit| {
            if !Self::is_live(entries, entry) {
                return;
            }
            self.park(entry, reason, error);
            self.emit_updated(emit, entry);
        });
    }

    /// The purge/registration lock for a driver's stable credential key.
    fn purge_lock_for(&self, stable: &ConnectionId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.purge_locks.lock();
        if let Some(live) = locks.get(stable).and_then(Weak::upgrade) {
            return live;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(stable.clone(), Arc::downgrade(&lock));
        // Drop identities nobody is purging or registering. The entry just
        // inserted is kept alive by `lock`.
        locks.retain(|_, held| held.strong_count() > 0);
        lock
    }

    /// The ONE path that may delete a durable credential.
    ///
    /// Durable secrets are keyed by the driver's stable id, so a delete races
    /// every registration resolving to that same key. This takes the identity's
    /// lock, re-evaluates orphanhood UNDER it, and only then deletes — making
    /// "nothing live claims this identity" true AT the delete rather than merely
    /// before it.
    ///
    /// Liveness a caller tests before calling is already stale by the time the
    /// awaited delete lands; that is the defect this exists to retire, and it
    /// recurred at six separate sites. Put every such condition in
    /// `still_orphaned`, which runs under the lock. The shared-stable-id check
    /// is built in, since all six sites need it.
    ///
    /// `set/tests.rs::every_durable_credential_delete_goes_through_the_chokepoint`
    /// enforces that no call site bypasses this.
    async fn purge_durable_credential(
        &self,
        entry: &ConnEntry<D>,
        verb: DurablePurge,
        still_orphaned: impl Fn() -> bool,
    ) -> Result<()> {
        let stable = entry.driver.stable_id();
        let lock = stable.as_ref().map(|stable| self.purge_lock_for(stable));
        let _guard = match &lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        // Re-evaluated under the lock: a sibling connection sharing this stable
        // id keeps the secret, and the caller's own condition may have been
        // invalidated by a registration that landed since it was tested.
        if self.stable_id_shared_by_other(entry) || !still_orphaned() {
            return Ok(());
        }
        // Both verbs are durable deletions, so both are recorded the same way:
        // a persist-debt latched before this must not be reported at teardown as
        // a preserved token that is no longer there.
        match verb {
            DurablePurge::Delete => {
                let outcome = entry.driver.delete_credentials().await; // purge-chokepoint
                entry.record_secret_deleted(outcome.is_ok());
            }
            // `purge_credentials` defaults to `delete_credentials`; unlike the
            // orphan-cleanup paths its failure is surfaced to the caller.
            DurablePurge::Purge => {
                let outcome = entry.driver.purge_credentials().await; // purge-chokepoint
                entry.record_secret_deleted(outcome.is_ok());
                outcome?;
            }
        }
        Ok(())
    }

    fn bringup_lock_for(&self, id: &ConnectionId) -> Arc<tokio::sync::Mutex<()>> {
        self.bringup_locks
            .lock()
            .entry(id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn in_cooldown(&self, id: &ConnectionId) -> bool {
        self.cooldowns
            .lock()
            .get(id)
            .map(|t| t.elapsed() < self.config.bringup_cooldown)
            .unwrap_or(false)
    }

    fn set_cooldown(&self, id: &ConnectionId) {
        self.cooldowns.lock().insert(id.clone(), Instant::now());
    }

    fn clear_cooldown(&self, id: &ConnectionId) {
        self.cooldowns.lock().remove(id);
    }

    fn bringup_gen(&self, id: &ConnectionId) -> u64 {
        self.bringup_gens
            .lock()
            .get(id)
            .map(|(generation, _)| *generation)
            .unwrap_or(0)
    }

    /// The stored outcome of the most recent COMPLETED bring-up attempt
    /// (`None` = authenticated, or no attempt recorded).
    fn bringup_outcome(&self, id: &ConnectionId) -> Option<Error> {
        self.bringup_gens
            .lock()
            .get(id)
            .and_then(|(_, outcome)| outcome.clone())
    }

    /// Record a COMPLETED bring-up attempt: bump the generation and store the
    /// winner's outcome so queued waiters share the actual error class.
    /// Cancelled attempts are never recorded (see `bring_up`).
    fn record_bringup_outcome(&self, id: &ConnectionId, outcome: Option<Error>) {
        let mut gens = self.bringup_gens.lock();
        let slot = gens.entry(id.clone()).or_insert((0, None));
        slot.0 = slot.0.wrapping_add(1);
        slot.1 = outcome;
    }

    fn refresh_gen(&self, id: &ConnectionId) -> u64 {
        self.refresh_gens.lock().get(id).copied().unwrap_or(0)
    }

    /// Record a COMPLETED refresh attempt (success or failure) under the
    /// single-flight lock, so `with_recovery` waiters queued behind a FAILED
    /// winner share the failure instead of re-driving the grant.
    fn bump_refresh_gen(&self, id: &ConnectionId) {
        let mut gens = self.refresh_gens.lock();
        let g = gens.entry(id.clone()).or_insert(0);
        *g = g.wrapping_add(1);
    }

    /// True while `id` is still a live entry — lifecycle commits check this
    /// before persisting/emitting so work finishing after `remove_connection`
    /// does not re-persist a deleted secret or emit `Updated` for a removed id.
    fn is_registered(&self, id: &ConnectionId) -> bool {
        self.entries.read().contains_key(id)
    }

    /// Spawn (replacing any prior) the one background-refresh task for `entry`,
    /// waking at `expires_at - refresh_skew`. No expiry → no task (static creds).
    fn spawn_refresh(self: &Arc<Self>, entry: &Arc<ConnEntry<D>>, expires_at: Option<SystemTime>) {
        let Some(expires_at) = expires_at else {
            // Static creds / no expiry: no task, but still abort any prior one.
            if let Some(handle) = entry.refresh_task.lock().take() {
                handle.abort();
            }
            return;
        };
        let set = Arc::downgrade(self);
        let weak_entry = Arc::downgrade(entry);
        let cancel = entry.cancel.clone();
        let skew = self.config.refresh_skew;
        let min_delay = self.config.min_refresh_delay;
        let handle = tokio::spawn(async move {
            let mut next_wakeup = expires_at;
            loop {
                let sleep = wakeup_delay(next_wakeup, skew, min_delay);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(sleep) => {}
                }
                let (Some(set), Some(entry)) = (set.upgrade(), weak_entry.upgrade()) else {
                    return;
                };
                // Only refresh while authenticated. `gen_before` is snapshotted
                // in the SAME lock acquisition (pre-lock) so the under-lock
                // recheck below is meaningful.
                let (id, gen_before) = {
                    let guard = entry.state.lock();
                    if !matches!(
                        guard.connection.auth_state,
                        ConnectionAuthState::Authenticated { .. }
                    ) {
                        return;
                    }
                    (guard.connection.id.clone(), guard.cred_gen)
                };
                // Serialize the grant on the per-connection bring-up lock with a
                // `cred_gen` recheck, mirroring `with_recovery`: on the
                // no-host / current-thread fallback paths `coalesced_refresh`
                // grants in-process, and without this a background grant could
                // race a concurrent data-path recovery grant on the same
                // rotating refresh token (IdP reuse-detection).
                let lock = set.bringup_lock_for(&id);
                let guard = lock.lock().await;
                // Re-clone the credentials AND re-read the generation in ONE
                // lock acquisition AFTER acquiring the single-flight lock: a
                // credential commit landing between a stale creds clone and the
                // generation read could pass the recheck while the grant is
                // driven with the consumed pre-rotation bundle (reuse-detection
                // family revocation).
                let (creds, gen_now) = {
                    let g = entry.state.lock();
                    (g.credentials.clone(), g.cred_gen)
                };
                if gen_now != gen_before {
                    // A concurrent op/task already refreshed — skip our grant and
                    // re-arm off the fresh expiry.
                    drop(guard);
                    next_wakeup = match entry.state.lock().connection.auth_state {
                        ConnectionAuthState::Authenticated {
                            expires_at: Some(exp),
                            ..
                        } => exp,
                        _ => SystemTime::now() + skew,
                    };
                    continue;
                }
                // Capture the driver's identity generation at grant start — the
                // second supersession fence (alongside `gen_now` / cred_gen)
                // threaded through the refresh→record window so a concurrent
                // interactive `Succeeded { credentials: None }` winner (which bumps
                // ONLY identity_gen) makes this refresh discard whole.
                let identity_now = entry.driver.identity_gen();
                let outcome = set
                    .coalesced_refresh(&entry, &creds, gen_now, identity_now)
                    .await;
                // A completed attempt (success or failure) is shared with
                // queued `with_recovery` waiters via the refresh generation.
                set.bump_refresh_gen(&id);
                match outcome {
                    Ok((refreshed, persisted)) => {
                        next_wakeup = refreshed
                            .expires_at
                            .unwrap_or_else(|| SystemTime::now() + Duration::from_secs(3600));
                        set.record_refreshed(&entry, refreshed, gen_now, identity_now, persisted)
                            .await;
                        drop(guard);
                    }
                    Err(error) => {
                        drop(guard);
                        use super::driver::AuthErrorClass;
                        match entry.driver.classify(&error) {
                            // Credential-class failure OR a definitive
                            // authorization denial: park and stop the loop — the
                            // host/UI must re-auth (the data path may also
                            // recover). `PermissionDenied` is never-retry, so it
                            // must NOT stay on the bounded retry cadence forever.
                            AuthErrorClass::RecoverableCredential
                            | AuthErrorClass::Revoked
                            | AuthErrorClass::NeedsInteractive
                            | AuthErrorClass::PermissionDenied => {
                                set.park_refresh_failure(&entry, &error);
                                return;
                            }
                            // Transient / non-auth (network blip, IdP 5xx): the
                            // connection is STILL `Authenticated` — keep it and
                            // retry on the bounded floor cadence WITHOUT
                            // advancing the failure counter. A
                            // single blip at the wakeup point must not strand a
                            // headless connection.
                            AuthErrorClass::NotAuth => {
                                tracing::warn!(
                                    target: "ovstorage.connection",
                                    error = %error,
                                    "background token refresh hit a transient failure; retrying",
                                );
                                next_wakeup = SystemTime::now() + skew;
                            }
                        }
                    }
                }
            }
        });
        // Install the new task under a single guard and abort the displaced one
        // (not drop-detach): concurrent credential commits must not leave two
        // refresh loops racing the same rotating refresh token.
        let mut slot = entry.refresh_task.lock();
        if let Some(old) = slot.replace(handle) {
            old.abort();
        }
    }

    /// Drive `driver.obtain` under the SAME stable-id-keyed cross-process
    /// refresh lock `coalesced_refresh` uses.
    ///
    /// A warm-continue / rotation SEED grant (`obtain`) is otherwise the one
    /// grant path outside the reuse-detection serialization — and the
    /// highest-frequency one, at connection bring-up: two processes, or two
    /// same-host sibling connections (distinct `ConnectionId`s, one stable id),
    /// warm-continuing the same discovery URL both consume the same refresh
    /// token, and a reuse-detecting IdP revokes the whole family
    /// (3539838324). Serializing `obtain` on the stable-keyed lock coalesces it
    /// with `coalesced_refresh` and with peer processes. A ZERO freshness
    /// window: `obtain` must always run (it mints THIS process's access token);
    /// the set-side keyring-head reload (by `Lineage`, in `obtain_and_persist`)
    /// before the grant picks up a peer's concurrent rotation. Falls back to an
    /// unlocked obtain when no provider / stable id / multi-thread runtime is
    /// available — the set's keyring-head reload still prevents replaying a
    /// consumed token there. Callers already hold the per-`ConnectionId`
    /// `bringup_lock`, so lock ordering (bringup → host) is the same as
    /// `coalesced_refresh`'s; no deadlock.
    async fn obtain_under_lock(
        &self,
        entry: &ConnEntry<D>,
        creds: &SecretBundle,
        lineage: Lineage,
        cancel: Option<CancellationToken>,
    ) -> Result<GrantCommit> {
        // Capture the supersession fences BEFORE the grant, so they cover the
        // whole obtain→verify→activate window: a concurrent interactive success
        // bumps the driver's identity_gen (live cell), a concurrent refresh /
        // update bumps this entry's cred_gen — the commit discards rather than
        // regress if either advanced.
        //
        // Read `cred_gen` FIRST (parity with the sibling capture sites
        // `with_recovery` and the background-refresh task): a concurrent refresh
        // bumps only `cred_gen`, so capturing it before `identity_gen` ensures a
        // refresh committing between the two reads is caught pre-bump →
        // mismatch → discarded, rather than captured post-bump.
        let expected_cred_gen = entry.state.lock().cred_gen;
        let expected_identity_gen = entry.driver.identity_gen();
        let make = |outcome: Obtained| GrantCommit {
            outcome,
            expected_identity_gen,
            expected_cred_gen,
            lineage,
        };

        let stable = entry.driver.stable_id();
        let multi_thread = matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        );
        let provider: Option<Arc<dyn CrossProcessRefreshLock>> = self
            .refresh_lock
            .clone()
            .or_else(|| crate::marshal::host().map(|_| Arc::new(HostRefreshLock) as Arc<_>));
        let (Some(provider), Some(stable)) = (provider, stable) else {
            // Unlocked fallback (no provider / stable id): no cross-process
            // serialization, but secret store lineage still reloads the head so a
            // consumed predecessor is not replayed.
            return self
                .obtain_and_persist(
                    entry,
                    creds,
                    lineage,
                    expected_cred_gen,
                    expected_identity_gen,
                    cancel,
                )
                .await
                .map(make);
        };
        if !multi_thread {
            // Current-thread runtime: `block_in_place` would panic. Unlocked, but
            // the secret store-lineage reload still prevents a consumed-token replay.
            return self
                .obtain_and_persist(
                    entry,
                    creds,
                    lineage,
                    expected_cred_gen,
                    expected_identity_gen,
                    cancel,
                )
                .await
                .map(make);
        }
        let backend_kind = entry.driver.backend_kind().to_string();
        let slot: Mutex<Option<Result<Obtained>>> = Mutex::new(None);
        let ran = {
            let mut run = || -> std::result::Result<(), Error> {
                let outcome = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(self.obtain_and_persist(
                        entry,
                        creds,
                        lineage,
                        expected_cred_gen,
                        expected_identity_gen,
                        cancel.clone(),
                    ))
                });
                // Store BOTH Ok and Err so an obtain error is surfaced to the
                // caller rather than swallowed as a lock failure.
                *slot.lock() = Some(outcome);
                Ok(())
            };
            // Wrap the WHOLE synchronous `with_lock` in `block_in_place` (we
            // are on a multi-thread runtime here — the `!multi_thread` guard
            // returned above). `with_lock` blocks acquiring the cross-process lock;
            // on a single-worker multi-thread runtime an unwrapped blocking call
            // would starve the sole worker and deadlock a second grant contending
            // for the same lock. `block_in_place` lets tokio run the peer's task on
            // another thread. The inner `block_in_place` (driving the async grant)
            // nests fine on tokio 1.52.
            tokio::task::block_in_place(|| {
                provider.with_lock(&backend_kind, &stable, Duration::ZERO, &mut run)
            })?
        };
        match slot.into_inner() {
            Some(result) if ran => result.map(make),
            // Defensive: a lock that skipped a zero window — obtain unlocked.
            _ => self
                .obtain_and_persist(
                    entry,
                    creds,
                    lineage,
                    expected_cred_gen,
                    expected_identity_gen,
                    cancel,
                )
                .await
                .map(make),
        }
    }

    /// Persist a rotation successor under the persist-debt policy (Brian's design
    /// §6). Tries `driver.persist_credentials` with bounded retries + short
    /// backoff. On success the entry's `persist_debt` is RETIRED. On final
    /// failure the debt is SET and a warning logged — the successor stays live in
    /// `entry.credentials` (memory is authoritative and strictly newer than the
    /// now-stranded keyring head), and a subsequent secret store-lineage grant skips
    /// the stale head-reload until a later persist retires the debt.
    ///
    /// This NEVER returns an error: a keyring write failure must not drop the
    /// rotated successor. Discarding it (or `?`-propagating so the caller keeps
    /// the predecessor) would strand the connection on a token the IdP has
    /// already rotated past — the exact reuse-detection footgun this closes.
    async fn persist_with_debt_policy(&self, entry: &ConnEntry<D>, bundle: &SecretBundle) {
        /// Bounded persist attempts before declaring persist-debt.
        const MAX_ATTEMPTS: u32 = 3;
        /// Short backoff between persist attempts (a transient keyring/store
        /// outage often clears within a few ms).
        const RETRY_BACKOFF: Duration = Duration::from_millis(20);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match entry.driver.persist_credentials(bundle).await {
                Ok(()) => {
                    // Durable store accepted the successor: retire any debt.
                    entry.state.lock().persist_debt = false;
                    entry.durable_secret_deleted.store(false, Ordering::SeqCst);
                    // The store holds a secret for this connection again, so an
                    // earlier delete is no longer what teardown would find. A
                    // connection survives `purge_persisted_credentials`, so
                    // without this the first purge would make every later debt
                    // on it permanently unreportable.
                    return;
                }
                Err(err) if attempt < MAX_ATTEMPTS => {
                    tracing::debug!(
                        target: "ovstorage.connection",
                        error = %err,
                        attempt,
                        "secret persist failed; retrying under the debt policy",
                    );
                    tokio::time::sleep(RETRY_BACKOFF).await;
                }
                Err(err) => {
                    // Final failure: strand the stored copy, keep memory authoritative.
                    entry.state.lock().persist_debt = true;
                    tracing::warn!(
                        target: "ovstorage.connection",
                        error = %err,
                        attempts = MAX_ATTEMPTS,
                        "secret persist failed after all retries; the durable store \
                         is stranded on the pre-rotation predecessor while in-memory \
                         credentials hold the rotated successor (memory is \
                         authoritative). A stored-lineage bring-up will grant the \
                         in-memory successor and skip the stale head reload until a \
                         later persist retires the debt",
                    );
                    return;
                }
            }
        }
    }

    /// Reload the secret store head (secret store lineage) → `obtain(AllowConsuming)` →
    /// commit the effective successor to in-memory `entry.credentials` → persist
    /// it. Runs INSIDE the cross-process lock (and on the unlocked fallback).
    /// Committing the rotated successor to MEMORY and persisting it HERE, before
    /// the caller's `verify`, is what makes a consumed rotation survive a verify
    /// rejection AND a persist failure: memory holds the successor, the secret store
    /// holds it (or, on persist failure, latches debt while memory stays
    /// authoritative), and nothing was installed on the live cell to roll back.
    /// `expected_cred_gen` / `expected_identity_gen` are the entry's `cred_gen`
    /// and the driver's `identity_gen` captured at grant start: the memory commit
    /// AND the persist are fenced on BOTH (WITHOUT bumping `cred_gen`) so a
    /// concurrent interactive success / credential update / refresh that won
    /// meanwhile is not regressed — see the superseded-discard note at the commit.
    async fn obtain_and_persist(
        &self,
        entry: &ConnEntry<D>,
        creds: &SecretBundle,
        lineage: Lineage,
        expected_cred_gen: u64,
        expected_identity_gen: u64,
        cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        let base = match lineage {
            Lineage::Fresh => creds.clone(),
            // Persist-debt short-circuit: a prior rotation stranded the secret store on
            // a CONSUMED predecessor while memory holds the successor (passed in as
            // `creds`). Memory is strictly newer, so grant it directly — reloading
            // the stale head would replay the consumed token into IdP
            // reuse-detection. A successful `persist_with_debt_policy` below retires
            // the debt, after which the normal head-reload resumes.
            Lineage::Stored if entry.state.lock().persist_debt => creds.clone(),
            Lineage::Stored => match entry.driver.load_credentials().await {
                Ok(Some(loaded)) => loaded,
                Ok(None) => creds.clone(),
                // Secret-store READ error: fail CLOSED — cannot confirm `creds` is the
                // persisted head, and granting a possibly-consumed token trips IdP
                // reuse-detection.
                Err(err) => return Err(err),
            },
        };
        let outcome = match entry
            .driver
            .obtain(&base, GrantPolicy::AllowConsuming, cancel)
            .await
        {
            Ok(outcome) => outcome,
            Err(error)
                if matches!(lineage, Lineage::Stored)
                    && matches!(
                        error.code(),
                        ErrorCode::AuthRequired
                            | ErrorCode::AuthExpired
                            | ErrorCode::PermissionDenied
                    ) =>
            {
                let _mutation = entry.credential_mutation.lock().await;
                let still_current = {
                    let state = entry.state.lock();
                    state.cred_gen == expected_cred_gen
                        && entry.driver.identity_gen() == expected_identity_gen
                };
                if still_current {
                    let id = entry.state.lock().connection.id.clone();
                    let _ = self.purge_persisted_credentials(&id).await;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if let Obtained::Bearer { credentials, .. } = &outcome {
            // Commit the rotated successor to in-memory `entry.credentials` as
            // part of the grant transaction — BEFORE persist and REGARDLESS of the
            // later `verify` outcome. Without this, a verify REJECTION plus a
            // persist failure strands the successor: memory keeps the consumed
            // predecessor while the secret store holds the successor, and the next
            // secret store-lineage grant replays the consumed predecessor into IdP
            // reuse-detection.
            //
            // Dual-generation supersession fence (mirrors `commit_authenticated`):
            // the memory commit AND the persist are applied ONLY if NEITHER
            // `cred_gen` NOR the driver's `identity_gen` advanced since grant start.
            // A concurrent interactive success / credential update / refresh runs
            // lock-free (outside the bring-up lock this grant holds): a
            // `Succeeded { credentials: Some(..) }` / update / refresh bumps
            // `cred_gen`, while a `Succeeded { credentials: None }` bumps ONLY the
            // driver's `identity_gen` (it installs a new live-cell identity but
            // hands back no bundle, so nothing bumps `cred_gen`). Fencing on
            // `cred_gen` alone let that identity-only winner slip through, so this
            // grant would (a) on a persist failure latch a SPURIOUS `persist_debt`
            // stranding the durable head on a superseded lineage — a cross-process
            // consumed-token replay — and (b) for an M2M `client_credentials` grant
            // durably RESURRECT the superseded identity in memory AND the secret store
            // before `commit_authenticated` later discards it set-side. If EITHER
            // generation advanced the grant is superseded → DISCARD it whole: no
            // memory write, no persist, no `persist_debt`. Read BOTH gens under the
            // SAME `entry.state` guard as the memory write (no await between) to
            // serialize against the winner's set-side commit. On the non-superseded
            // path this still commits + persists exactly as before; on the
            // verify-success path `commit_authenticated` re-commits the same
            // successor via `set_state` (bumping cred_gen).
            let superseded = {
                let mut g = entry.state.lock();
                if g.cred_gen != expected_cred_gen
                    || entry.driver.identity_gen() != expected_identity_gen
                {
                    true
                } else {
                    g.credentials = credentials.clone();
                    false
                }
            };
            if superseded {
                return Ok(outcome);
            }
            // Persist the effective (possibly rotated) successor now, before the
            // caller runs `verify`. Fenced on liveness so a removal mid-grant does
            // not re-persist a deleted secret; re-fence + orphan-delete if removed
            // during the (non-atomic) persist. The persist runs under the
            // debt policy: a keyring write failure marks persist-debt (keeping the
            // successor live in memory) rather than silently stranding memory on a
            // predecessor the next reload would replay.
            let id = entry.state.lock().connection.id.clone();
            if self.is_registered(&id) {
                self.persist_with_debt_policy(entry, credentials).await;
                let _ = self
                    .purge_durable_credential(entry, DurablePurge::Delete, || {
                        !self.is_registered(&id)
                    })
                    .await;
            }
        }
        Ok(outcome)
    }

    /// Run `driver.refresh` under the host's cross-process refresh lock when a
    /// host + stable id are available (so concurrent processes coalesce), else
    /// in-process only. The host lock's closure is synchronous, so the async
    /// grant is driven via `block_in_place` on a multi-thread runtime.
    ///
    /// Returns `(refreshed, persisted)`: `persisted` is true iff the successor
    /// was durably written to the secret store INSIDE the cross-process lock. On the
    /// in-process fallbacks it is false and the caller (`record_refreshed`)
    /// performs the persist. Gating the caller's persist on `!persisted` keeps
    /// the locked path's single in-lock persist authoritative — an out-of-lock
    /// re-persist could overwrite a peer's freshly-rotated token with a
    /// now-consumed predecessor (3539858459).
    ///
    /// `expected_cred_gen` / `expected_identity_gen` are the entry's `cred_gen`
    /// and the driver's `identity_gen` captured at grant start (the same values
    /// the caller threads into `record_refreshed`): the in-lock memory commit AND
    /// persist of the rotated successor are fenced on BOTH (WITHOUT bumping
    /// `cred_gen`) so a concurrent interactive success / credential update /
    /// refresh that won meanwhile is discarded whole rather than regressed — a
    /// `Succeeded { credentials: None }` winner bumps ONLY `identity_gen`, so
    /// fencing on `cred_gen` alone would let it slip through.
    async fn coalesced_refresh(
        &self,
        entry: &ConnEntry<D>,
        creds: &SecretBundle,
        expected_cred_gen: u64,
        expected_identity_gen: u64,
    ) -> Result<(Refreshed, bool)> {
        let stable = entry.driver.stable_id();
        // Cross-process coalescing needs a lock provider (the plugin host, or a
        // test-injected one), a stable id, AND a multi-thread runtime: the
        // lock's closure is synchronous and drives the async grant via
        // `block_in_place`, which PANICS on a current-thread runtime (and that
        // panic, on the spawned refresh task, would be swallowed and silently
        // kill the scheduler). Fall back to an in-process refresh otherwise.
        let multi_thread = matches!(
            tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        );
        let provider: Option<Arc<dyn CrossProcessRefreshLock>> = self
            .refresh_lock
            .clone()
            .or_else(|| crate::marshal::host().map(|_| Arc::new(HostRefreshLock) as Arc<_>));
        let (Some(provider), Some(stable)) = (provider, stable) else {
            // No cross-process lock/stable id — still reload the secret store head so
            // a stale `entry.credentials` (a consumed predecessor after a
            // rotation) is never replayed on this unlocked fallback.
            return self
                .refresh_from_head(entry, creds, expected_identity_gen)
                .await;
        };
        if !multi_thread {
            tracing::warn!(
                target: "ovstorage.connection",
                "cross-process refresh coalescing requires a multi-thread runtime; \
                 refreshing in-process",
            );
            // Current-thread runtime (e.g. a single-thread `#[tokio::test]` or a
            // hostless embedding): unlocked, but STILL reload the secret store head so
            // a consumed predecessor is not replayed.
            return self
                .refresh_from_head(entry, creds, expected_identity_gen)
                .await;
        }
        let backend_kind = entry.driver.backend_kind().to_string();
        let window = self.config.refresh_freshness_window;
        let id = entry.state.lock().connection.id.clone();
        // Drive reload (optional) → `driver.refresh` → durable persist as ONE
        // transaction INSIDE the cross-process lock's closure. Loading before
        // the lock could reload a token a concurrently-locked peer is about to
        // consume, and persisting after the lock releases publishes freshness
        // BEFORE the successor is stored — either way a sibling process then
        // grants with the already-consumed token, and a reuse-detecting IdP
        // revokes the whole token family. `freshness` = the skip window: a
        // peer that refreshed within it means the lock skips our closure
        // (`None` from the slot).
        let locked_refresh = |current: SecretBundle,
                              freshness: Duration|
         -> Result<Option<Result<(Refreshed, bool)>>> {
            let slot: Mutex<Option<Result<(Refreshed, bool)>>> = Mutex::new(None);
            let ran = {
                let mut run = || -> std::result::Result<(), Error> {
                    let outcome = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            // While persist-debted, a prior rotation stranded
                            // the secret store on a CONSUMED predecessor while memory
                            // holds the strictly-newer successor — so SKIP the head
                            // reload and grant the in-memory successor (mirroring
                            // the obtain path). Reloading the stale head here would
                            // replay the consumed token into IdP reuse-detection. A
                            // later successful persist retires the debt, after which
                            // the head reload resumes. Read the flag + creds in ONE
                            // lock acquisition to avoid racing a debt retirement.
                            let debted = {
                                let g = entry.state.lock();
                                g.persist_debt.then(|| g.credentials.clone())
                            };
                            // Otherwise ALWAYS reload the secret store's persisted head
                            // UNDER the lock so the grant consumes the live token,
                            // never a pre-lock in-memory snapshot: a rotation (this
                            // process's prior failed validate, or a sibling's
                            // freshness-window refresh) advanced the secret store past
                            // `current`, and granting on the stale copy would
                            // replay an already-consumed refresh token
                            // (3539838239 / 3539858459). The keyring holds only
                            // the refresh token; `driver.refresh` mints this
                            // process's access token from it.
                            let base = match debted {
                                Some(successor) => successor,
                                None => match entry.driver.load_credentials().await {
                                    Ok(Some(loaded)) => loaded,
                                    // No persisted head: `current` is the only
                                    // candidate (nothing rotated past it).
                                    Ok(None) => current.clone(),
                                    // Secret-store READ error: fail CLOSED. We
                                    // cannot verify `current` is the persisted head,
                                    // and granting a possibly-consumed token trips
                                    // IdP reuse-detection. Surface the error (the op
                                    // retries) rather than replay under the lock.
                                    Err(err) => return Err(err),
                                },
                            };
                            // Fence the driver's live-cell commit on the SAME
                            // identity gen the set captured at grant start (the
                            // identity this refresh intended), not one the driver
                            // re-captures at its own entry: an interactive sign-in
                            // bumping `identity_gen` in the window between the set's
                            // capture and the driver's entry (widened by the
                            // cross-process lock + keyring-head reload above) must
                            // make the driver's install DISCARD, not regress the
                            // live cell to this prior identity's freshly-minted
                            // token. Same capture fed to `activate` / the memory
                            // fence below.
                            let refreshed = entry
                                .driver
                                .refresh(&base, None, expected_identity_gen)
                                .await?;
                            // Commit the rotated successor to in-memory
                            // `entry.credentials` as part of the grant
                            // transaction — BEFORE the persist and REGARDLESS of
                            // its outcome. Without this, a keyring-write failure
                            // below would `?`-fail the whole refresh:
                            // `record_refreshed`'s `set_state` never runs, the
                            // rotated successor is LOST from memory, and the next
                            // grant reloads the stranded keyring head and replays
                            // the consumed token into IdP reuse-detection.
                            //
                            // Dual-generation supersession fence (mirrors
                            // `obtain_and_persist` / `commit_authenticated`): the
                            // memory commit AND the persist are applied ONLY if
                            // NEITHER `cred_gen` NOR the driver's `identity_gen`
                            // advanced since grant start. A concurrent interactive
                            // `Succeeded { credentials: Some(..) }` / update /
                            // refresh bumps `cred_gen`; a
                            // `Succeeded { credentials: None }` bumps ONLY
                            // `identity_gen` (new live-cell identity, no bundle
                            // handed back). Fencing on `cred_gen` alone let that
                            // identity-only winner slip through, latching a SPURIOUS
                            // `persist_debt` on a persist failure (stranding the
                            // durable head on a superseded lineage — a cross-process
                            // replay) or durably resurrecting a superseded identity.
                            // If EITHER advanced the grant is superseded → discard
                            // whole: no memory write, no persist, no `persist_debt`
                            // (report `persisted = false`; `record_refreshed`'s own
                            // dual-gen recheck then discards it set-side without a
                            // fallback persist). Read both gens under the SAME guard
                            // as the memory write.
                            let superseded = {
                                let mut g = entry.state.lock();
                                if g.cred_gen != expected_cred_gen
                                    || entry.driver.identity_gen() != expected_identity_gen
                                {
                                    true
                                } else {
                                    g.credentials = refreshed.credentials.clone();
                                    false
                                }
                            };
                            // Persist the successor BEFORE the lock releases (and
                            // freshness is published): a sibling skipping on our
                            // freshness stamp must reload OUR successor. Route the
                            // persist through the debt policy (bounded retries; on
                            // final failure SET persist_debt + keep the successor
                            // live in memory, on success RETIRE the debt) rather
                            // than `?`-failing — a keyring-write failure on this
                            // locked production path must not drop the rotation.
                            // The locked path stays authoritative (`persisted =
                            // true`), so `record_refreshed` does NOT re-persist
                            // out-of-lock (3539858459). Fenced on liveness like
                            // `record_refreshed` so a removal mid-grant does not
                            // re-persist a deleted secret.
                            let persisted = if superseded {
                                false
                            } else if self.is_registered(&id) {
                                self.persist_with_debt_policy(entry, &refreshed.credentials)
                                    .await;
                                // The check above and this persist are not atomic
                                // (3539858875): a `remove_connection` landing
                                // between them leaves the successor as a live
                                // orphan in the secret store AFTER removal — and the
                                // caller skips its own cleanup because we report
                                // `persisted = true`. Re-fence here: if removed
                                // (and no sibling shares the stable id), delete
                                // the orphan.
                                //
                                // LATENT (not reachable today): this deletes on
                                // `!is_registered`, which a NON-purging
                                // `unregister_connection(purge=false)` (bring-up /
                                // root-discovery rollback, meant to PRESERVE the
                                // token) also makes true — so a persist racing
                                // such an unregister could delete a token it
                                // intends to keep. Unreachable because the only
                                // grant paths (background refresh floored at
                                // `min_refresh_delay`, data-path recovery) cannot
                                // fire before `instantiate_connection` returns the
                                // instance, and `unregister(purge=false)` only
                                // runs inside that call. Honoring purge semantics
                                // in the fence would need the removal kind
                                // threaded here.
                                let _ = self
                                    .purge_durable_credential(entry, DurablePurge::Delete, || {
                                        !self.is_registered(&id)
                                    })
                                    .await;
                                true
                            } else {
                                false
                            };
                            Ok::<_, Error>((refreshed, persisted))
                        })
                    })?;
                    *slot.lock() = Some(Ok(outcome));
                    Ok(())
                };
                // Wrap the WHOLE synchronous `with_lock` in `block_in_place`
                // (we are on a multi-thread runtime here — the `!multi_thread`
                // guard returned above). `with_lock` blocks acquiring the
                // cross-process lock; on a single-worker multi-thread runtime an
                // unwrapped blocking call would starve the sole worker and deadlock
                // a peer grant contending for the same lock. `block_in_place` lets
                // tokio run the peer's task on another thread. The inner
                // `block_in_place` (driving the async grant) nests fine on tokio
                // 1.52.
                tokio::task::block_in_place(|| {
                    provider.with_lock(&backend_kind, &stable, freshness, &mut run)
                })?
            };
            Ok(if ran { slot.into_inner() } else { None })
        };
        match locked_refresh(creds.clone(), window)? {
            Some(result) => result,
            // The lock skipped our closure: a sibling process refreshed within
            // the freshness window (possibly rotating the refresh token). That
            // is SUCCESS, not failure — reload the sibling's persisted secret
            // and mint our own access token from it (the secret store holds only the
            // refresh token, not the access token this process's transport
            // needs). Never park on a freshness skip. Re-enter the SAME
            // cross-process lock with a ZERO window — with the reload INSIDE
            // the locked closure — so the post-skip grant is mutually excluded
            // AND always consumes the latest persisted successor: two skipped
            // processes must not drive grants on the same rotating refresh
            // token (IdP reuse-detection revokes the family).
            None => {
                match locked_refresh(creds.clone(), Duration::ZERO)? {
                    Some(result) => result,
                    // Zero window means the closure always runs; `None` here
                    // would only occur on a lock that unconditionally skips —
                    // fall back to an unlocked in-process grant rather than loop.
                    None => {
                        self.refresh_from_head(entry, creds, expected_identity_gen)
                            .await
                    }
                }
            }
        }
    }

    /// Reload the secret store's persisted refresh head (the authoritative rotation
    /// lineage) and refresh from it, falling back to `creds` only when the
    /// keyring holds none. Used on every UNLOCKED refresh fallback so a stale
    /// in-memory `entry.credentials` — a consumed predecessor left behind by a
    /// rotation during a prior failed validate — is never replayed into IdP
    /// reuse-detection (3539838239). Reports `persisted = false`: the
    /// caller (`record_refreshed`) persists the successor.
    ///
    /// The exception is while persist-debted — then the secret store head is a CONSUMED
    /// predecessor and memory holds the strictly-newer successor, so skip the
    /// reload and grant the in-memory successor (mirroring the obtain path and the
    /// locked refresh path); a later successful persist retires the debt.
    async fn refresh_from_head(
        &self,
        entry: &ConnEntry<D>,
        creds: &SecretBundle,
        expected_identity_gen: u64,
    ) -> Result<(Refreshed, bool)> {
        let debted = {
            let g = entry.state.lock();
            g.persist_debt.then(|| g.credentials.clone())
        };
        let base = match debted {
            Some(successor) => successor,
            None => match entry.driver.load_credentials().await {
                Ok(Some(loaded)) => loaded,
                // No persisted head: `creds` is the only candidate.
                Ok(None) => creds.clone(),
                // Secret-store READ error: fail CLOSED. Cannot verify `creds` is
                // the persisted head; replaying a possibly-consumed token trips IdP
                // reuse-detection. Surface the error (the data-path op retries).
                Err(err) => return Err(err),
            },
        };
        entry
            .driver
            .refresh(&base, None, expected_identity_gen)
            .await
            .map(|r| (r, false))
    }

    fn park_refresh_failure(&self, entry: &ConnEntry<D>, error: &Error) {
        use super::driver::AuthErrorClass;
        let reason = match entry.driver.classify(error) {
            AuthErrorClass::Revoked => AuthReason::RefreshTokenRevoked,
            AuthErrorClass::RecoverableCredential | AuthErrorClass::NeedsInteractive => {
                AuthReason::RefreshTokenExpired
            }
            _ => AuthReason::BackendUnreachable,
        };
        self.park(entry, reason, Some(error.clone()));
        self.emit_updated_if_live(entry);
    }
}

/// Minimum background-refresh re-arm interval. A token whose TTL is `<= skew`
/// (or a driver returning an already-past `expires_at`) would otherwise make the
/// loop fire every ~1 ms, hammering the token endpoint + keyring; this floor
/// bounds the rate. A token that
/// expires sooner than this is covered on the data path by
/// [`ConnectionSet::with_recovery`] in the meantime.
// Private internal timing constant flooring the background token-refresh
// re-arm cadence; not a C ABI symbol.
/// cbindgen:ignore
const MIN_REFRESH_DELAY: Duration = Duration::from_secs(30);

/// Delay until `expires_at - skew`, floored at `min_delay` (the
/// [`ConnectionSetConfig::min_refresh_delay`] knob, default
/// [`MIN_REFRESH_DELAY`]) so a short-TTL / already-past expiry re-arms on a
/// bounded cadence rather than busy-looping.
fn wakeup_delay(expires_at: SystemTime, skew: Duration, min_delay: Duration) -> Duration {
    let target = expires_at.checked_sub(skew).unwrap_or(expires_at);
    let remaining = target
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);
    remaining.max(min_delay)
}

/// The action [`ConnectionSet::with_recovery`] takes after its guarded refresh
/// step, decided under the single-flight lock but executed after releasing it.
enum RecoveryStep {
    /// Creds are fresh (we refreshed, or a peer did) — retry the op once.
    Retry,
    /// Refresh could not recover — surface the original op error.
    Surface,
}

/// Wraps the driver's interactive `AuthEventStream`, intercepting `Succeeded` /
/// `Failed` to keep the connection's auth state consistent (RFC §1995).
struct AuthStreamAdapter<D: ConnectionAuthDriver> {
    inner: AuthEventStream,
    set: Arc<ConnectionSet<D>>,
    entry: Arc<ConnEntry<D>>,
    /// `cred_gen` / `identity_gen` captured at flow start — the supersession
    /// fence for a bundle-less `Succeeded { None }` transition (see
    /// [`ConnectionSet::set_authenticated_keep_creds`]).
    expected_cred_gen: u64,
    expected_identity_gen: u64,
}

impl<D: ConnectionAuthDriver> Iterator for AuthStreamAdapter<D> {
    type Item = Result<AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut event = self.inner.next()?;
        if let Ok(current) = &mut event {
            match current {
                AuthEvent::Succeeded {
                    connection,
                    credentials,
                } => {
                    // EVERY `Succeeded` is a terminal authenticated transition —
                    // the `AuthEvent` contract defines `Succeeded { None }` as a
                    // successful flow that installed tokens itself or uses static
                    // creds (the host default emits exactly that). Only the
                    // credential swap + persistence is conditioned on `Some`.
                    let expires_at = credentials.as_ref().and_then(oauth_expiry);
                    // The effective bundle is an internal handoff to ConnectionSet.
                    // Scrub it BEFORE any liveness branch so a success racing
                    // removal cannot leak replayable credentials to FFI/broker/REST.
                    let effective = credentials.take();
                    if let Err(failure) = complete_interactive_transition(
                        self.set.clone(),
                        self.entry.clone(),
                        effective,
                        expires_at,
                        self.expected_cred_gen,
                        self.expected_identity_gen,
                    ) {
                        if failure.park {
                            self.set.park_and_emit_if_live(
                                &self.entry,
                                AuthReason::BackendUnreachable,
                                Some(failure.error.clone()),
                            );
                        }
                        return Some(Ok(AuthEvent::Failed {
                            error: failure.error,
                        }));
                    }
                    // The driver seeded this event's `connection` from a
                    // pre-transition clone. Now that the transition is committed,
                    // refresh it from the entry so `Succeeded` reports the actual
                    // post-authentication view (`Authenticated`, current
                    // capabilities), not the stale `AwaitingAuth` snapshot — every
                    // backend emits its true post-transition connection.
                    **connection = self.entry.state.lock().connection.clone();
                }
                AuthEvent::Failed { error } => {
                    // Fence removal (mirrors the `Succeeded` arm): a `Failed`
                    // arriving after `remove_connection` must not park the
                    // removed entry or emit `Updated` for an id subscribers
                    // just saw `Removed`.
                    self.set.park_and_emit_if_live(
                        &self.entry,
                        AuthReason::ManuallyRequested,
                        Some(error.clone()),
                    );
                }
                _ => {}
            }
        }
        Some(event)
    }
}

struct InteractiveTransitionFailure {
    error: Error,
    /// `false` when the entry was removed/superseded or the lifecycle hook
    /// already parked and emitted the failure itself.
    park: bool,
}

fn complete_interactive_transition<D: ConnectionAuthDriver>(
    set: Arc<ConnectionSet<D>>,
    entry: Arc<ConnEntry<D>>,
    credentials: Option<SecretBundle>,
    expires_at: Option<SystemTime>,
    expected_cred_gen: u64,
    expected_identity_gen: u64,
) -> std::result::Result<(), InteractiveTransitionFailure> {
    let transition = async move {
        let _mutation = entry.credential_mutation.lock().await;
        let id = entry.state.lock().connection.id.clone();
        if !set.is_registered(&id) {
            return Err(InteractiveTransitionFailure {
                error: Error::new(
                    ErrorCode::AuthCancelled,
                    "connection removed during interactive authentication",
                ),
                park: false,
            });
        }

        match credentials.as_ref() {
            Some(credentials) => {
                if !set.commit_interactive_credentials(&entry, credentials.clone(), expires_at) {
                    return Err(InteractiveTransitionFailure {
                        error: Error::new(
                            ErrorCode::AuthCancelled,
                            "interactive authentication was superseded",
                        ),
                        park: false,
                    });
                }
            }
            None => {
                if !set.set_authenticated_keep_creds(
                    &entry,
                    expires_at,
                    expected_cred_gen,
                    expected_identity_gen,
                ) {
                    return Err(InteractiveTransitionFailure {
                        error: Error::new(
                            ErrorCode::AuthCancelled,
                            "interactive authentication was superseded",
                        ),
                        park: false,
                    });
                }
            }
        }
        set.clear_cooldown(&id);

        if let Some(credentials) = credentials.as_ref() {
            set.persist_with_debt_policy(&entry, credentials).await;
            // A removal landing during persistence leaves a just-written durable
            // head. Delete it as an orphan ONLY when the remover purged
            // (`remove_connection`); a non-purging `unregister_connection`
            // preserves it for the next warm continuation. Preserve a shared
            // stable-id sibling's entry either way.
            if !set.is_registered(&id) {
                let _ = set
                    .purge_durable_credential(&entry, DurablePurge::Delete, || {
                        !set.is_registered(&id) && entry.purge_on_removal.load(Ordering::SeqCst)
                    })
                    .await;
                return Err(InteractiveTransitionFailure {
                    error: Error::new(
                        ErrorCode::AuthCancelled,
                        "connection removed during interactive authentication",
                    ),
                    park: false,
                });
            }
        }

        if let Err(error) = set
            .run_on_authenticated(&entry, Some(entry.cancel.clone()))
            .await
        {
            // `run_on_authenticated` parks + emits exactly once IFF the entry is
            // still registered; a removal-cancelled hook leaves the removed entry
            // untouched. Either way the failure is fully handled there.
            return Err(InteractiveTransitionFailure { error, park: false });
        }
        if !set.is_registered(&id) {
            return Err(InteractiveTransitionFailure {
                error: Error::new(
                    ErrorCode::AuthCancelled,
                    "connection removed during interactive authentication",
                ),
                park: false,
            });
        }
        set.spawn_refresh(&entry, expires_at);
        set.emit_updated_if_live(&entry);
        Ok(())
    };

    // Drive the commit on a dedicated, process-owned runtime that progresses on
    // its own worker threads — INDEPENDENTLY of the consumer's drain runtime.
    // This is what lets a completed sign-in commit whether the stream is drained
    // on a multi-thread runtime, a current-thread runtime, or a plain blocking
    // thread with no runtime at all: blocking this thread on the result cannot
    // deadlock the drain runtime (the commit runs elsewhere) nor hang on an idle
    // one. Driver tasks the hook spawns (e.g. session keepalive) land on this
    // persistent runtime and outlive the terminal event.
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    auth_commit_runtime().spawn(async move {
        let _ = tx.send(transition.await);
    });
    let receive = || {
        rx.recv().map_err(|_| InteractiveTransitionFailure {
            error: Error::new(
                ErrorCode::Internal,
                "interactive authentication transition task ended without a result",
            ),
            park: true,
        })?
    };
    // Yield the worker rather than block it when the drain itself runs on a
    // multi-thread runtime; a current-thread or runtime-less drain blocks the
    // calling thread, which is fine — the commit progresses on its own runtime.
    if matches!(
        tokio::runtime::Handle::try_current().map(|current| current.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    ) {
        tokio::task::block_in_place(receive)
    } else {
        receive()
    }
}

/// The process-wide runtime that drives interactive-auth commits (persist + the
/// `on_authenticated` hook + refresh re-arm). It is multi-thread so the commit
/// progresses on its own workers regardless of the consumer's drain runtime, and
/// persistent so hook-spawned tasks (session keepalives) outlive the terminal
/// event. Lazily built on first interactive success.
fn auth_commit_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ovs-auth-commit")
            .build()
            .expect("build the interactive-auth commit runtime")
    })
}

/// Extract an OAuth bundle's `expires_at`, if present.
fn oauth_expiry(bundle: &SecretBundle) -> Option<SystemTime> {
    match bundle.fields.get("oauth") {
        Some(SecretValue::OAuthToken { expires_at, .. }) => *expires_at,
        _ => None,
    }
}

#[cfg(test)]
mod tests;
