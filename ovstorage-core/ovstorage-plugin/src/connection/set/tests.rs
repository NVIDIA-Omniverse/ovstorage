// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests over a programmable mock [`ConnectionAuthDriver`], covering the
//! full `ConnectionSet` lifecycle: state transitions, single-flight bring-up
//! coalescing, cooldown, background refresh, and the data-path recovery
//! loop.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use futures::StreamExt;
use parking_lot::Mutex;

use super::*;
use crate::connection::credential_conformance::{
    CredentialSnapshot, CredentialTransactionSubject, assert_credential_transaction_conformance,
    assert_delegated_replacement_conformance,
};
use crate::connection::driver::{
    AuthErrorClass, ConnectionAuthDriver, GrantPolicy, Obtained, ProbeOutcome, Refreshed,
};

/// Test stand-in for the deleted `Validated` enum: `push_validate` still queues
/// one of these so the ~30 lifecycle tests read unchanged; `MockDriver::obtain`
/// maps it onto an [`Obtained`] (and `verify` defaults to `Ok`), so a queued
/// `Authenticated`/`Anonymous`/`AwaitingInteractive` produces the same lifecycle
/// disposition the old `validate` did, and a queued `Err` is an `obtain` error.
#[derive(Clone, Debug)]
enum MockValidated {
    Authenticated {
        credentials: Option<SecretBundle>,
        expires_at: Option<SystemTime>,
    },
    Anonymous,
    AwaitingInteractive {
        reason: AuthReason,
    },
}
use crate::{
    AuthEvent, AuthEventStream, AuthReason, Capabilities, Connection, ConnectionAuthState,
    ConnectionChange, ConnectionId, ConnectionSource, Error, ErrorCode, InteractiveAuthCapability,
    Result, SecretBundle, SecretBytes, SecretValue, UserMetadata,
};

mod live_cell {
    use super::{SecretBundle, SecretBytes, SecretValue};
    use crate::connection::credential_conformance::CredentialSnapshot;
    use crate::oauth_secret_store::{IdentityBinding, fingerprint, identity_from_access_token};
    use parking_lot::{Mutex, MutexGuard};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    /// The client name this cell derives its identity binding under — the
    /// broker's `client_name`, which the real derivation falls back to for a
    /// token that carries no client claim.
    const CLIENT_NAME: &str = "mock";

    /// How a write treats the refresh slot, mirroring the broker's
    /// `RefreshPolicy`.
    pub(super) enum RefreshPolicy {
        /// A response that omits the refresh preserves the slot (RFC 6749 §6).
        Merge,
        /// The slot is overwritten, CLEARED when the write carries no refresh.
        Replace,
    }

    /// What a write does to the cached M2M pair, mirroring the broker's
    /// `ClientCredentialsAction`.
    pub(super) enum ClientCredentialsAction {
        /// Leave the slot untouched (the guard is still held).
        Keep,
        /// Assign the slot — `Some` caches the pair, `None` clears it.
        Set(Option<(String, String)>),
    }

    /// One credential write, as [`LiveCellGuard::write`] performs it. The
    /// parameters are the broker `write_tokens` parameters, because this cell
    /// stands in for that transaction.
    pub(super) struct TokenWrite<'a> {
        pub(super) credentials: &'a SecretBundle,
        pub(super) refresh_policy: RefreshPolicy,
        pub(super) client_credentials: ClientCredentialsAction,
        pub(super) bump_identity: bool,
    }

    /// Everything one credential write moves, besides the identity generation:
    /// the installed bundle (the access / refresh / expiry triple), the cached
    /// M2M pair, the credential lineage, the write generation, the published
    /// credential, and the identity binding — the dimensions
    /// [`CredentialSnapshot`] enumerates.
    #[derive(Default)]
    struct Cell {
        installed: Option<SecretBundle>,
        client_credentials: Option<(String, String)>,
        interactive_identity: bool,
        generation: u64,
        published_credential: Option<String>,
        binding: Option<IdentityBinding>,
    }

    /// The [`super::MockDriver`]'s live cell: the installed bundle and the
    /// identity generation as ONE value, because that is what the real drivers
    /// are. The broker mutates both inside a single `write_tokens` core holding
    /// every credential write lock, so no observer sees a bundle beside a
    /// generation that disagrees with it.
    ///
    /// The two halves are reachable only through [`Self::lock`], which hands
    /// back a guard borrowing THIS cell's generation. There is no step at which
    /// a caller selects which generation to bump, so pairing one cell's lock
    /// with another cell's generation is not expressible — the guard is not a
    /// token that any `MutexGuard` can satisfy, it is the cell's own handle.
    ///
    /// Modelling the halves as independently writable is what produced the
    /// defect this guards: a
    /// bump landing between a fenced install's generation compare and its
    /// bundle store leaves the cell holding a bundle whose generation says it
    /// was fenced out — a state no real driver can reach, and one that makes
    /// `credentials_are_current` refuse an interactive winner's own bundle.
    #[derive(Default)]
    pub(super) struct LiveCell {
        cell: Mutex<Cell>,
        identity_gen: AtomicU64,
    }

    impl LiveCell {
        /// Lock-free generation read. The set calls this while holding its own
        /// `entry.state` guard, so taking the cell here would invert lock
        /// order. Reads need no guard: a reader can straddle a completed write,
        /// which is a normal interleaving, but never observe a torn one.
        pub(super) fn identity_gen(&self) -> u64 {
            self.identity_gen.load(Ordering::SeqCst)
        }

        /// A snapshot of the installed bundle.
        pub(super) fn installed(&self) -> Option<SecretBundle> {
            self.cell.lock().installed.clone()
        }

        /// Every dimension of the cell, read as ONE observation — the reading
        /// half of the shared credential-transaction conformance expectation.
        pub(super) fn snapshot(&self) -> CredentialSnapshot {
            let cell = self.cell.lock();
            let (access_token, refresh_token, expires_at) = cell
                .installed
                .as_ref()
                .and_then(oauth_parts)
                .map_or((None, None, None), |(access, refresh, expires_at)| {
                    (Some(access), refresh, expires_at)
                });
            CredentialSnapshot {
                access_token,
                refresh_token,
                expires_at,
                client_credentials: cell.client_credentials.clone(),
                interactive_lineage: cell.interactive_identity,
                generation: cell.generation,
                identity_generation: self.identity_gen.load(Ordering::SeqCst),
                published_credential: cell.published_credential.clone(),
                binding: cell.binding.clone(),
            }
        }

        /// Exclusive access to both halves, together.
        pub(super) fn lock(&self) -> LiveCellGuard<'_> {
            LiveCellGuard {
                cell: self.cell.lock(),
                identity_gen: &self.identity_gen,
            }
        }
    }

    /// The `(access, refresh, expires_at)` triple an `oauth` bundle carries.
    fn oauth_parts(bundle: &SecretBundle) -> Option<(String, Option<String>, Option<SystemTime>)> {
        let SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        } = bundle.fields.get("oauth")?
        else {
            return None;
        };
        Some((
            String::from_utf8(token.0.clone()).ok()?,
            refresh
                .as_ref()
                .and_then(|rt| String::from_utf8(rt.0.clone()).ok()),
            *expires_at,
        ))
    }

    /// Exclusive access to one [`LiveCell`]. Every mutation of either half is a
    /// method here, so holding this guard is what it means to be allowed to
    /// write — and the generation it writes is necessarily the one belonging to
    /// the cell that produced it.
    pub(super) struct LiveCellGuard<'a> {
        cell: MutexGuard<'a, Cell>,
        identity_gen: &'a AtomicU64,
    }

    impl LiveCellGuard<'_> {
        pub(super) fn identity_gen(&self) -> u64 {
            self.identity_gen.load(Ordering::SeqCst)
        }

        pub(super) fn installed(&self) -> Option<&SecretBundle> {
            self.cell.installed.as_ref()
        }

        /// The credential transaction, in the shape the broker's `write_tokens`
        /// performs it: the token triple, the M2M pair, the lineage, the write
        /// generation, the published credential, the binding and the identity
        /// generation all move here, under the one lock, or none of them do.
        ///
        /// There is no method that moves a subset — installing a bundle without
        /// republishing the credential it is serving on, or bumping the identity
        /// without recording the identity, is not expressible.
        pub(super) fn write(&mut self, write: TokenWrite<'_>) {
            // A bundle carrying no `oauth` field installs no tokens, so it moves
            // NO dimension of the cell: `BrokerDriver::activate` and
            // `::activate_replacing` both parse the bundle first and return
            // `Ok(true)` without reaching `write_tokens` when the `oauth` field
            // is absent, so no slot, no lineage, and neither generation moves.
            // Storing the bundle here instead would leave the mock reporting a
            // write the drivers it stands for never perform.
            let Some((access, refresh, expires_at)) = oauth_parts(write.credentials) else {
                return;
            };
            let refresh = match write.refresh_policy {
                RefreshPolicy::Merge => refresh.or_else(|| self.refresh_slot()),
                RefreshPolicy::Replace => refresh,
            };
            let mut installed = write.credentials.clone();
            installed.fields.insert(
                "oauth".into(),
                SecretValue::OAuthToken {
                    token: SecretBytes(access.clone().into_bytes()),
                    refresh: refresh
                        .as_ref()
                        .map(|rt| SecretBytes(rt.clone().into_bytes())),
                    expires_at,
                },
            );
            self.cell.installed = Some(installed);
            // The credential the connection is serving on RIGHT NOW,
            // republished by every write that leaves the slot assigned — a
            // same-identity rotation included.
            self.cell.published_credential = refresh.as_deref().map(fingerprint);
            if write.bump_identity {
                // The identity being installed, derived from the access
                // token this very write stores, in the same transaction as
                // the generation bump: nothing outside this critical
                // section can name the identity of the credential inside it.
                self.cell.binding = Some(identity_from_access_token(&access, CLIENT_NAME));
            }
            if let ClientCredentialsAction::Set(pair) = write.client_credentials {
                // An identity-CHANGING write records the new identity's
                // lineage: clearing the pair is the interactive shape, setting
                // it is a service/M2M (re)establishment. Same-identity merges
                // leave the lineage untouched.
                if write.bump_identity {
                    self.cell.interactive_identity = pair.is_none();
                }
                self.cell.client_credentials = pair;
            }
            self.cell.generation += 1;
            if write.bump_identity {
                self.identity_gen.fetch_add(1, Ordering::SeqCst);
            }
        }

        /// The refresh token the cell currently holds, which a `Merge` write
        /// preserves when it carries none of its own.
        fn refresh_slot(&self) -> Option<String> {
            self.cell
                .installed
                .as_ref()
                .and_then(oauth_parts)
                .and_then(|(_, refresh, _)| refresh)
        }

        /// A bump with no write of its own — the mock's stand-in for a
        /// CONCURRENT driver-external identity change landing in a test's chosen
        /// window. No real driver reaches this: every driver-side bump happens
        /// inside [`Self::write`], with the identity it installs.
        pub(super) fn bump_identity_gen(&mut self) {
            self.identity_gen.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Programmable driver: each verb pops a queued outcome (or a default) and
/// counts its invocations so coalescing / retry-once are assertable.
struct MockDriver {
    kind: String,
    stable: Option<ConnectionId>,
    validate_calls: AtomicUsize,
    refresh_calls: AtomicUsize,
    persist_calls: AtomicUsize,
    load_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    on_authenticated_calls: AtomicUsize,
    validate_queue: Mutex<VecDeque<Result<MockValidated>>>,
    /// Queued `verify` outcomes (default `Ok`): a queued `Err` models a backend
    /// rejection of an already-obtained bearer (verify-vs-obtain-failure tests).
    verify_queue: Mutex<VecDeque<Result<()>>>,
    /// `activate` call count + the last bundle it installed on the "live cell".
    activate_calls: AtomicUsize,
    /// The "live cell": the last bundle installed on it, plus the driver's live
    /// identity generation (the verify→activate fence). Tests bump the
    /// generation to simulate a concurrent interactive success / cred
    /// replacement landing during the verify window, so `activate(expected_gen)`
    /// discards.
    live: live_cell::LiveCell,
    /// When true, `verify` bumps `identity_gen` before returning — deterministic
    /// simulation of a concurrent identity change committing DURING the verify
    /// window (so the subsequent `activate` sees a stale expected_gen).
    verify_bumps_identity: std::sync::atomic::AtomicBool,
    /// When true, `obtain` bumps `identity_gen` before returning its bearer —
    /// deterministic simulation of a concurrent interactive `Succeeded { None }`
    /// winner installing a NEW live-cell identity DURING the obtain grant window
    /// (bumping ONLY identity_gen, NOT cred_gen). The set captured the pre-grant
    /// `expected_identity_gen`, so `obtain_and_persist`'s dual-gen fence sees it
    /// advanced and discards the grant whole (no memory write, no persist, no
    /// persist_debt).
    obtain_bumps_identity: std::sync::atomic::AtomicBool,
    /// When true, `refresh` bumps `identity_gen` before returning — same
    /// identity-only supersession, but for the refresh grant window
    /// (`coalesced_refresh` / `record_refreshed` dual-gen fences).
    refresh_bumps_identity: std::sync::atomic::AtomicBool,
    /// When true, `activate_replacing` takes the TRAIT DEFAULT: delegate to
    /// `activate`, keeping same-identity merge semantics and bumping nothing.
    /// That is a real driver shape — a static-key backend whose live cell holds
    /// only the bearer being replaced has no auxiliary slot to strand, so merge
    /// and replace coincide — and
    /// `mock_driver_conforms_to_the_delegated_replacement` pins exactly what it
    /// is allowed to omit.
    ///
    /// DEFAULT (false): the shape every credential-owning driver implements — a
    /// fenced REPLACEMENT install that BUMPS `identity_gen` on a successful
    /// commit, because an explicit-cred `Lineage::Fresh` change is a NEW
    /// identity. The lifecycle tests run this shape, and
    /// `mock_driver_conforms_to_the_credential_transaction` certifies it, so
    /// they are the same transaction rather than a certified variant beside an
    /// uncertified one in service. It is also the shape that makes the
    /// post-activate identity_gen-recheck regression visible: the driver's own
    /// legitimate bump makes a post-activate `identity_gen()` re-read
    /// false-positive.
    activate_replacing_delegates_to_activate: std::sync::atomic::AtomicBool,
    /// When true, the plain merge `activate` (the `Lineage::Stored` arm) still
    /// installs its bundle on a matching `expected_gen`, but BUMPS `identity_gen`
    /// as it returns `Ok(true)` — a deterministic stand-in for a concurrent
    /// interactive `Succeeded { None }` winner that installs a new live-cell
    /// identity in the window between the driver's internal merge-commit and the
    /// SET's post-`activate` guard. It lets a test pin `commit_authenticated`'s
    /// secret store-arm `identity_gen` recheck — the arm that DISCARDS a merge whose
    /// identity advanced AFTER it committed `Ok(true)`. The plain supersession
    /// fence (a stale `expected_gen` → `Ok(false)`) cannot reach that recheck: it
    /// discards at the `activate` fence instead. Off by default (no behavior
    /// change); distinct from `activate_replacing_delegates_to_activate`, which models
    /// the `Fresh`/replace path's own legitimate self-bump.
    activate_bumps_identity: std::sync::atomic::AtomicBool,
    /// When true, `refresh` commits its freshly-minted successor onto the "live
    /// cell" (`installed`) fenced on the SET-captured `expected_gen` it was passed
    /// — mirroring the broker driver's `install_tokens_if_identity_unchanged`. If
    /// `refresh_bumps_identity` modeled a concurrent interactive winner installing
    /// its own identity + bumping `identity_gen` in the gap BEFORE this commit, the
    /// passed `expected_gen` is now stale and the fenced install is SKIPPED — the
    /// residual window the set-captured fence closes.
    refresh_commits_live: std::sync::atomic::AtomicBool,
    refresh_queue: Mutex<VecDeque<Result<Refreshed>>>,
    interactive: Mutex<Option<Vec<Result<AuthEvent>>>>,
    load_result: Mutex<Option<SecretBundle>>,
    validate_delay: Duration,
    /// Overrides `classify` for every error when set (background-refresh tests).
    classify_override: Mutex<Option<AuthErrorClass>>,
    /// When set, `refresh` waits on this before resolving (concurrency tests).
    refresh_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    /// When set, `persist_credentials` waits on this BEFORE writing the secret store
    /// (removal-vs-in-lock-persist race tests).
    persist_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    /// When set, `delete_credentials` waits on this before deleting, so a test
    /// can hold the durable purge open and observe what a removal has already
    /// reported to subscribers by that point.
    delete_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    /// When set, `obtain` waits on this before granting, so a test can hold a
    /// credential update open across a concurrent removal.
    obtain_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    /// Bumped immediately BEFORE `obtain` parks on `obtain_gate`, and again
    /// after it resumes. A test spins on `parked > released` to know the grant
    /// is genuinely held open — entering `obtain` is not the same as parking in
    /// it, and a test that only proves entry silently stops covering its race.
    obtain_parked: AtomicUsize,
    obtain_released: AtomicUsize,
    /// Same, for `delete_credentials`.
    delete_parked: AtomicUsize,
    delete_released: AtomicUsize,
    /// Fail the next N `persist_credentials` calls (the secret NOT written) then
    /// succeed — models a transient durable-store outage for persist-debt tests.
    persist_fail_remaining: AtomicUsize,
    /// When true, `obtain` ROTATES the passed-in base (append "+" to its refresh
    /// token) and logs the consumed token to `shared_grant_log`, WITHOUT reloading
    /// the secret store or self-persisting — so the SET's `obtain_and_persist` is the
    /// sole secret-store writer (a programmed `persist_fail_remaining` there strands the
    /// stored secret, exercising persist-debt). Distinct from `validate_seed_grants`,
    /// which self-reloads + self-persists.
    rotate_grants: std::sync::atomic::AtomicBool,
    /// When true, `delete_credentials` fails and leaves the secret store untouched —
    /// a best-effort teardown purge whose durable delete did not take.
    delete_fails: std::sync::atomic::AtomicBool,
    /// When true, `load_credentials` returns a secret-store READ error (fail-closed
    /// reload tests).
    load_error: std::sync::atomic::AtomicBool,
    /// When true, `on_authenticated` returns an error (hook-failure tests).
    on_authenticated_fails: std::sync::atomic::AtomicBool,
    /// When true, `on_authenticated` caches a runtime-owned pending task. The
    /// task must remain live after the terminal interactive event is forwarded.
    on_authenticated_spawns_task: std::sync::atomic::AtomicBool,
    on_authenticated_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// When true, `on_authenticated` blocks on its cancellation token and, once
    /// cancelled (e.g. by a concurrent removal), returns an error — modelling a
    /// cancel-honoring session-establishment hook.
    on_authenticated_honors_cancel: std::sync::atomic::AtomicBool,
    /// Bumped when `on_authenticated` is entered, so a test can deterministically
    /// remove the connection only once the hook is in flight.
    on_authenticated_entered: AtomicUsize,
    /// Every `current` bundle `refresh` was invoked with (rotation tests).
    refresh_inputs: Mutex<Vec<SecretBundle>>,
    /// When true, `refresh` derives its successor from `current` (appends "+"
    /// to the refresh token), simulating a rotating IdP.
    rotate_refresh: std::sync::atomic::AtomicBool,
    /// Shared secret store: `persist_credentials` writes it, `load_credentials`
    /// reads it — lets two ConnectionSets simulate two processes sharing one
    /// durable secret store (cross-process coalescing tests).
    shared_secrets: Option<Arc<Mutex<Option<SecretBundle>>>>,
    /// When true, `validate` simulates a services-style warm-continue SEED
    /// grant: reload the secret store head, record the consumed refresh token in
    /// `shared_grant_log`, persist the rotated successor, return `Authenticated`.
    /// Models the refresh-token grant `seed_connection_auth` drives inside
    /// `validate` (serialization tests).
    validate_seed_grants: std::sync::atomic::AtomicBool,
    /// Shared log of every refresh token a `validate` seed grant CONSUMED —
    /// across drivers, so a duplicate entry proves two grants ran on one token
    /// (IdP reuse-detection).
    shared_grant_log: Option<Arc<Mutex<Vec<String>>>>,
    /// `verify` call count (verify-vs-lock / cred_gen supersession tests).
    verify_calls: AtomicUsize,
    /// When set, `verify` waits on this before resolving — lets a test hold a
    /// grant in its verify window while a concurrent commit lands.
    verify_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    /// Shared "is the cross-process lock held right now" flag, set by an
    /// instrumented [`CrossProcessRefreshLock`] around its critical section.
    /// `obtain` / `verify` sample it to prove obtain runs UNDER the lock and
    /// verify runs OUTSIDE it.
    lock_probe: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// What `obtain` / `verify` observed `lock_probe` to be when they ran.
    obtain_saw_lock_held: Mutex<Option<bool>>,
    verify_saw_lock_held: Mutex<Option<bool>>,
}

impl MockDriver {
    fn new() -> Self {
        Self {
            kind: "mock".into(),
            stable: None,
            validate_calls: AtomicUsize::new(0),
            refresh_calls: AtomicUsize::new(0),
            persist_calls: AtomicUsize::new(0),
            load_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            on_authenticated_calls: AtomicUsize::new(0),
            validate_queue: Mutex::new(VecDeque::new()),
            verify_queue: Mutex::new(VecDeque::new()),
            activate_calls: AtomicUsize::new(0),
            live: live_cell::LiveCell::default(),
            verify_bumps_identity: std::sync::atomic::AtomicBool::new(false),
            obtain_bumps_identity: std::sync::atomic::AtomicBool::new(false),
            refresh_bumps_identity: std::sync::atomic::AtomicBool::new(false),
            activate_replacing_delegates_to_activate: std::sync::atomic::AtomicBool::new(false),
            activate_bumps_identity: std::sync::atomic::AtomicBool::new(false),
            refresh_commits_live: std::sync::atomic::AtomicBool::new(false),
            refresh_queue: Mutex::new(VecDeque::new()),
            interactive: Mutex::new(None),
            load_result: Mutex::new(None),
            validate_delay: Duration::ZERO,
            classify_override: Mutex::new(None),
            refresh_gate: Mutex::new(None),
            persist_gate: Mutex::new(None),
            delete_gate: Mutex::new(None),
            obtain_gate: Mutex::new(None),
            obtain_parked: AtomicUsize::new(0),
            obtain_released: AtomicUsize::new(0),
            delete_parked: AtomicUsize::new(0),
            delete_released: AtomicUsize::new(0),
            persist_fail_remaining: AtomicUsize::new(0),
            rotate_grants: std::sync::atomic::AtomicBool::new(false),
            delete_fails: std::sync::atomic::AtomicBool::new(false),
            load_error: std::sync::atomic::AtomicBool::new(false),
            on_authenticated_fails: std::sync::atomic::AtomicBool::new(false),
            on_authenticated_spawns_task: std::sync::atomic::AtomicBool::new(false),
            on_authenticated_task: Mutex::new(None),
            on_authenticated_honors_cancel: std::sync::atomic::AtomicBool::new(false),
            on_authenticated_entered: AtomicUsize::new(0),
            refresh_inputs: Mutex::new(Vec::new()),
            rotate_refresh: std::sync::atomic::AtomicBool::new(false),
            shared_secrets: None,
            validate_seed_grants: std::sync::atomic::AtomicBool::new(false),
            shared_grant_log: None,
            verify_calls: AtomicUsize::new(0),
            verify_gate: Mutex::new(None),
            lock_probe: None,
            obtain_saw_lock_held: Mutex::new(None),
            verify_saw_lock_held: Mutex::new(None),
        }
    }
    fn push_validate(&self, r: Result<MockValidated>) {
        self.validate_queue.lock().push_back(r);
    }
    fn push_verify(&self, r: Result<()>) {
        self.verify_queue.lock().push_back(r);
    }
    fn push_refresh(&self, r: Result<Refreshed>) {
        self.refresh_queue.lock().push_back(r);
    }
    /// Count of `obtain` calls — the grant half of a validate. Named `validates`
    /// so the lifecycle tests (which assert attempt counts) read unchanged.
    fn validates(&self) -> usize {
        self.validate_calls.load(Ordering::SeqCst)
    }
    fn activates(&self) -> usize {
        self.activate_calls.load(Ordering::SeqCst)
    }
    fn installed(&self) -> Option<SecretBundle> {
        self.live.installed()
    }
    /// Acquire the live cell and bump the generation.
    fn bump_identity_gen(&self) {
        self.live.lock().bump_identity_gen();
    }
    /// Fenced live-cell install — the `activate` primitive, with the same
    /// atomicity the real drivers guarantee: the broker's
    /// `install_tokens_if_identity_unchanged` compares `identity_gen` while
    /// holding every credential write lock, so check-then-install is ONE
    /// indivisible step. Returns whether the install committed.
    fn install_if_identity_unchanged(&self, credentials: &SecretBundle, expected_gen: u64) -> bool {
        let mut live = self.live.lock();
        if live.identity_gen() != expected_gen {
            return false;
        }
        live.write(merge_write(credentials));
        true
    }
    /// Fenced identity-REPLACING install — the `activate_replacing` primitive,
    /// mirroring the broker's `replace_tokens_if_identity_unchanged`: compare
    /// the fence, install, and bump `identity_gen`, all under ONE live-cell
    /// lock. Distinct from [`Self::install_if_identity_unchanged`] followed by
    /// [`Self::bump_identity_gen`] — that pair releases the lock in between,
    /// which is exactly the split this primitive exists to prevent. Returns
    /// whether the install committed.
    fn install_new_identity_if_identity_unchanged(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
    ) -> bool {
        let mut live = self.live.lock();
        if live.identity_gen() != expected_gen {
            return false;
        }
        live.write(replace_write(credentials));
        true
    }
    /// Unfenced SAME-identity live-cell store — a rotation of the identity the
    /// cell already holds, which by design does not move `identity_gen`.
    fn install_same_identity(&self, credentials: &SecretBundle) {
        self.live.lock().write(merge_write(credentials));
    }
    /// Unfenced identity-ESTABLISHING live-cell commit (an interactive success,
    /// which establishes a new identity unconditionally): install and bump under
    /// ONE lock, mirroring the real drivers' single `write_tokens` core.
    fn install_new_identity(&self, credentials: &SecretBundle) {
        self.live.lock().write(replace_write(credentials));
    }
    fn refreshes(&self) -> usize {
        self.refresh_calls.load(Ordering::SeqCst)
    }
    fn verifies(&self) -> usize {
        self.verify_calls.load(Ordering::SeqCst)
    }
    fn loads(&self) -> usize {
        self.load_calls.load(Ordering::SeqCst)
    }
    /// True while a call is parked on the gate (entered and not yet resumed).
    fn obtain_is_parked(&self) -> bool {
        self.obtain_parked.load(Ordering::SeqCst) > self.obtain_released.load(Ordering::SeqCst)
    }

    fn delete_is_parked(&self) -> bool {
        self.delete_parked.load(Ordering::SeqCst) > self.delete_released.load(Ordering::SeqCst)
    }

    fn deletes(&self) -> usize {
        self.delete_calls.load(Ordering::SeqCst)
    }
    fn on_authenticateds(&self) -> usize {
        self.on_authenticated_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ConnectionAuthDriver for MockDriver {
    fn backend_kind(&self) -> &str {
        &self.kind
    }
    fn stable_id(&self) -> Option<ConnectionId> {
        self.stable.clone()
    }
    async fn obtain(
        &self,
        creds: &SecretBundle,
        policy: GrantPolicy,
        _cancel: Option<crate::CancellationToken>,
    ) -> Result<Obtained> {
        self.validate_calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.obtain_gate.lock().clone();
        if let Some(gate) = gate {
            self.obtain_parked.fetch_add(1, Ordering::SeqCst);
            gate.notified().await;
            self.obtain_released.fetch_add(1, Ordering::SeqCst);
        }
        // Sample the cross-process lock: obtain runs INSIDE it (held == true).
        if let Some(probe) = &self.lock_probe {
            *self.obtain_saw_lock_held.lock() = Some(probe.load(Ordering::SeqCst));
        }
        if !self.validate_delay.is_zero() {
            tokio::time::sleep(self.validate_delay).await;
        }
        // Simulate a concurrent interactive `Succeeded { None }` winner installing
        // a NEW live-cell identity DURING the obtain grant window: bump ONLY
        // identity_gen (not cred_gen). A `NonConsumingOnly` probe must stay
        // side-effect-free, so never bump for a probe.
        if policy != GrantPolicy::NonConsumingOnly
            && self.obtain_bumps_identity.load(Ordering::SeqCst)
        {
            self.bump_identity_gen();
        }
        if self.validate_seed_grants.load(Ordering::SeqCst) {
            // A probe (`NonConsumingOnly`) must never burn a refresh token.
            if policy == GrantPolicy::NonConsumingOnly {
                return Ok(Obtained::WouldConsume);
            }
            // Simulate `seed_connection_auth`'s warm-continue refresh grant, which
            // `obtain_under_lock` drives under the cross-process lock: reload the
            // stored head, CONSUME it (log it for reuse-detection), persist the
            // rotated successor. Serialization must ensure two peers never consume
            // the same token.
            let head = self
                .load_credentials()
                .await
                .ok()
                .flatten()
                .and_then(|b| bundle_refresh(&b))
                .unwrap_or_default();
            if let Some(log) = &self.shared_grant_log {
                log.lock().push(head.clone());
            }
            let successor = format!("{head}+");
            let _ = self.persist_credentials(&named_bundle(&successor)).await;
            return Ok(Obtained::Bearer {
                credentials: named_bundle(&successor),
                expires_at: None,
            });
        }
        if self.rotate_grants.load(Ordering::SeqCst) {
            // A probe (`NonConsumingOnly`) must never burn a refresh token.
            if policy == GrantPolicy::NonConsumingOnly {
                return Ok(Obtained::WouldConsume);
            }
            // Rotate the PASSED-IN base (the set already chose the lineage: a
            // reloaded stored head, or — while persist-debted — the in-memory
            // successor). Log the consumed token so a duplicate proves a replay.
            // Do NOT reload the secret store or self-persist: the set's
            // `obtain_and_persist` is the sole secret-store writer, so a programmed
            // persist failure there strands the secret store (persist-debt).
            let head = bundle_refresh(creds).unwrap_or_default();
            if let Some(log) = &self.shared_grant_log {
                log.lock().push(head.clone());
            }
            let successor = format!("{head}+");
            return Ok(Obtained::Bearer {
                credentials: named_bundle(&successor),
                expires_at: None,
            });
        }
        match self.validate_queue.lock().pop_front() {
            Some(Ok(MockValidated::Authenticated {
                credentials,
                expires_at,
            })) => Ok(Obtained::Bearer {
                credentials: credentials.unwrap_or_else(|| creds.clone()),
                expires_at,
            }),
            Some(Ok(MockValidated::Anonymous)) => Ok(Obtained::Anonymous),
            Some(Ok(MockValidated::AwaitingInteractive { reason })) => {
                Ok(Obtained::AwaitingInteractive { reason })
            }
            Some(Err(error)) => Err(error),
            None => Ok(Obtained::Bearer {
                credentials: creds.clone(),
                expires_at: None,
            }),
        }
    }
    async fn verify(
        &self,
        _credentials: &SecretBundle,
        _cancel: Option<crate::CancellationToken>,
    ) -> Result<()> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        // Sample the cross-process lock: verify runs OUTSIDE it (held == false).
        if let Some(probe) = &self.lock_probe {
            *self.verify_saw_lock_held.lock() = Some(probe.load(Ordering::SeqCst));
        }
        // Simulate a concurrent identity change landing during the verify window.
        if self.verify_bumps_identity.load(Ordering::SeqCst) {
            self.bump_identity_gen();
        }
        // Hold the grant in its verify window so a concurrent commit can land.
        let gate = self.verify_gate.lock().clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        self.verify_queue.lock().pop_front().unwrap_or(Ok(()))
    }
    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        self.activate_calls.fetch_add(1, Ordering::SeqCst);
        // Supersession fence — MATCHES THE REAL DRIVER: a concurrent identity
        // change during the verify window bumped identity_gen, so the merge is
        // SKIPPED (nothing installed on the live cell) and `activate` reports
        // `Ok(false)` (NOT committed). The compare and the install are atomic,
        // as they are in the real drivers. The SET gates its set-side commit on
        // this flag; `activate` reserves `Err` for genuine failures.
        if !self.install_if_identity_unchanged(credentials, expected_gen) {
            return Ok(false);
        }
        // Model a concurrent interactive winner bumping identity_gen in the window
        // between this merge-commit and the set's post-activate guard, so the
        // secret store-arm identity_gen recheck in `commit_authenticated` is exercised.
        if self.activate_bumps_identity.load(Ordering::SeqCst) {
            self.bump_identity_gen();
        }
        Ok(true)
    }
    async fn activate_replacing(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
    ) -> Result<bool> {
        if self
            .activate_replacing_delegates_to_activate
            .load(Ordering::SeqCst)
        {
            // The TRAIT DEFAULT shape: same-identity merge semantics, no
            // identity bump, no binding write. What a driver taking it may omit
            // is pinned by `assert_delegated_replacement_conformance`.
            return self.activate(credentials, expected_gen).await;
        }
        // Broker-shaped REPLACE primitive: a fenced install that BUMPS
        // identity_gen on a successful commit. A stale `expected_gen` means a real
        // racing winner already superseded this grant — install nothing, report
        // NOT committed. On a match, install, BUMP identity_gen (the new identity),
        // and report committed. The set must gate on THIS flag: a post-activate
        // `identity_gen()` re-read would see this self-bump (G→G+1) and wrongly
        // discard the whole set-side write (the post-activate identity_gen-recheck regression).
        self.activate_calls.fetch_add(1, Ordering::SeqCst);
        if !self.install_new_identity_if_identity_unchanged(credentials, expected_gen) {
            return Ok(false);
        }
        Ok(true)
    }
    fn identity_gen(&self) -> u64 {
        self.live.identity_gen()
    }
    /// Answers from the live cell, the way the OAuth drivers answer from the
    /// credential their live identity published: a bundle whose refresh token
    /// is not the one installed belongs to a flow something has moved past.
    fn credentials_are_current(&self, credentials: &SecretBundle) -> bool {
        let live = self.live.lock();
        match live.installed() {
            Some(live) => bundle_refresh(live) == bundle_refresh(credentials),
            None => true,
        }
    }
    async fn refresh(
        &self,
        current: &SecretBundle,
        _cancel: Option<crate::CancellationToken>,
        expected_gen: u64,
    ) -> Result<Refreshed> {
        self.refresh_inputs.lock().push(current.clone());
        // Register the gate wait BEFORE bumping the counter is wrong for the
        // concurrency test (it must observe both ops in-flight); bump first so
        // `refreshes()` reflects entry, then park on the gate.
        let gate = self.refresh_gate.lock().clone();
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = gate {
            gate.notified().await;
        }
        // Simulate a concurrent interactive `Succeeded { None }` winner installing
        // a NEW live-cell identity DURING the refresh grant window: bump ONLY
        // identity_gen (not cred_gen), so the refresh's dual-gen fences discard it.
        if self.refresh_bumps_identity.load(Ordering::SeqCst) {
            // When modeling the driver-side live-cell commit, the winner FIRST
            // installs its own identity onto the live cell, THEN bumps
            // identity_gen (install-then-bump under one lock, as a real
            // interactive success does) — landing in the gap between the set's
            // identity capture and this driver's fenced commit below.
            if self.refresh_commits_live.load(Ordering::SeqCst) {
                self.install_new_identity(&named_bundle("interactive"));
            } else {
                self.bump_identity_gen();
            }
        }
        // Mint the successor bundle (rotating IdP appends "+"; else a fixed token).
        let minted = if self.rotate_refresh.load(Ordering::SeqCst) {
            named_bundle(&format!("{}+", bundle_refresh(current).unwrap_or_default()))
        } else {
            named_bundle("refresh-minted")
        };
        // Driver-side LIVE-cell commit, fenced on the SET-captured `expected_gen`
        // this method was PASSED (not one re-captured at entry) — mirrors the
        // broker's `install_tokens_if_identity_unchanged`. If a winner bumped
        // identity_gen above, `expected_gen` is stale and the install is SKIPPED,
        // so the live cell keeps the winner's identity (the residual set-captured-fence fix).
        if self.refresh_commits_live.load(Ordering::SeqCst) {
            self.install_if_identity_unchanged(&minted, expected_gen);
        }
        if self.rotate_refresh.load(Ordering::SeqCst) {
            return Ok(Refreshed {
                credentials: minted,
                expires_at: None,
            });
        }
        self.refresh_queue.lock().pop_front().unwrap_or_else(|| {
            Ok(Refreshed {
                credentials: oauth_bundle(None),
                expires_at: None,
            })
        })
    }
    async fn interactive(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<crate::CancellationToken>,
    ) -> Result<AuthEventStream> {
        let events = self.interactive.lock().take().unwrap_or_else(|| {
            vec![Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: Some(oauth_bundle(None)),
            })]
        });
        // A real driver's flow lands its minted bearer on the live cell BEFORE
        // it emits the terminal event — that is what makes the bundle it hands
        // back the one the connection is serving on. Modelling that here is
        // what lets `credentials_are_current` tell a live bundle from one a
        // later commit has moved past. A `Succeeded { None }` installed nothing.
        for event in &events {
            if let Ok(AuthEvent::Succeeded {
                credentials: Some(bundle),
                ..
            }) = event
            {
                // An interactive success establishes a NEW identity, so it
                // installs and bumps the identity generation atomically, the
                // same way the real drivers' replace-commit does. That is what
                // fences a grant still in its verify window out of installing
                // over this one.
                self.install_new_identity(bundle);
            }
        }
        Ok(Box::new(events.into_iter()))
    }
    fn classify(&self, error: &Error) -> crate::connection::driver::AuthErrorClass {
        if let Some(class) = *self.classify_override.lock() {
            return class;
        }
        crate::connection::driver::default_classify(error)
    }
    async fn persist_credentials(&self, creds: &SecretBundle) -> Result<()> {
        self.persist_calls.fetch_add(1, Ordering::SeqCst);
        // Programmable failure: fail the next N calls (the secret NOT written), then
        // succeed — models a transient durable-store outage for persist-debt tests.
        if self.persist_fail_remaining.load(Ordering::SeqCst) > 0 {
            self.persist_fail_remaining.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::new(ErrorCode::Transient, "secret persist failed"));
        }
        // Gate BEFORE the write so a test can remove the connection first, then
        // release — reproducing a persist that writes an ORPHAN after removal.
        let gate = self.persist_gate.lock().clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        if let Some(store) = &self.shared_secrets {
            *store.lock() = Some(creds.clone());
        }
        Ok(())
    }
    async fn load_credentials(&self) -> Result<Option<SecretBundle>> {
        self.load_calls.fetch_add(1, Ordering::SeqCst);
        if self.load_error.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorCode::Transient, "secret store read failed"));
        }
        if let Some(store) = &self.shared_secrets {
            return Ok(store.lock().clone());
        }
        Ok(self.load_result.lock().clone())
    }
    async fn delete_credentials(&self) -> Result<()> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.delete_gate.lock().clone();
        if let Some(gate) = gate {
            self.delete_parked.fetch_add(1, Ordering::SeqCst);
            gate.notified().await;
            self.delete_released.fetch_add(1, Ordering::SeqCst);
        }
        if self.delete_fails.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorCode::Transient, "store delete failed"));
        }
        if let Some(store) = &self.shared_secrets {
            *store.lock() = None;
        }
        Ok(())
    }
    async fn on_authenticated(
        &self,
        _connection: &Connection,
        cancel: Option<crate::CancellationToken>,
    ) -> Result<()> {
        self.on_authenticated_calls.fetch_add(1, Ordering::SeqCst);
        self.on_authenticated_entered.fetch_add(1, Ordering::SeqCst);
        if self.on_authenticated_honors_cancel.load(Ordering::SeqCst) {
            // Block until the lifecycle token cancels (a concurrent removal), then
            // fail the hook the way a cancel-honoring driver would.
            if let Some(cancel) = cancel {
                cancel.cancelled().await;
            }
            return Err(Error::new(
                ErrorCode::AuthCancelled,
                "on_authenticated cancelled",
            ));
        }
        if self.on_authenticated_fails.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorCode::Internal, "hook failed"));
        }
        if self.on_authenticated_spawns_task.load(Ordering::SeqCst) {
            *self.on_authenticated_task.lock() = Some(tokio::spawn(std::future::pending()));
        }
        Ok(())
    }
}

fn oauth_bundle(expires_at: Option<SystemTime>) -> SecretBundle {
    let mut b = SecretBundle::default();
    b.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(b"access".to_vec()),
            refresh: Some(SecretBytes(b"refresh".to_vec())),
            expires_at,
        },
    );
    b
}

/// An oauth bundle whose refresh token is `name` (distinguishable lineages).
fn named_bundle(name: &str) -> SecretBundle {
    let mut b = SecretBundle::default();
    b.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(b"access".to_vec()),
            refresh: Some(SecretBytes(name.as_bytes().to_vec())),
            expires_at: None,
        },
    );
    b
}

/// The refresh-token string of every bundle `driver.refresh` was invoked with,
/// in order — the lineage of tokens the refresh path consumed (rotation tests).
fn refresh_input_tokens(driver: &MockDriver) -> Vec<String> {
    driver
        .refresh_inputs
        .lock()
        .iter()
        .map(|b| bundle_refresh(b).unwrap_or_default())
        .collect()
}

/// The refresh-token string of an oauth bundle, if any.
fn bundle_refresh(bundle: &SecretBundle) -> Option<String> {
    match bundle.fields.get("oauth") {
        Some(SecretValue::OAuthToken {
            refresh: Some(r), ..
        }) => String::from_utf8(r.0.clone()).ok(),
        _ => None,
    }
}

/// The `(client_id, client_secret)` pair an effective bundle carries, if any —
/// parsed exactly as `BrokerDriver::parse_activation_bundle` parses it, because
/// the same bundle reaches both.
fn bundle_client_credentials(bundle: &SecretBundle) -> Option<(String, String)> {
    let (SecretValue::Bytes(id), SecretValue::Bytes(secret)) = (
        bundle.fields.get("client_id")?,
        bundle.fields.get("client_secret")?,
    ) else {
        return None;
    };
    let (id, secret) = (
        String::from_utf8(id.0.clone()).ok()?,
        String::from_utf8(secret.0.clone()).ok()?,
    );
    (!id.is_empty() && !secret.is_empty()).then_some((id, secret))
}

/// The SAME-identity merge write, as `BrokerDriver::activate` issues it: a
/// `None` refresh preserves the slot (RFC 6749 §6), the M2M pair is cached when
/// the effective bundle carries one, and the identity generation does not move.
fn merge_write(credentials: &SecretBundle) -> live_cell::TokenWrite<'_> {
    live_cell::TokenWrite {
        credentials,
        refresh_policy: live_cell::RefreshPolicy::Merge,
        client_credentials: match bundle_client_credentials(credentials) {
            Some(pair) => live_cell::ClientCredentialsAction::Set(Some(pair)),
            None => live_cell::ClientCredentialsAction::Keep,
        },
        bump_identity: false,
    }
}

/// The identity-CHANGING replacement write, as `BrokerDriver::activate_replacing`
/// issues it: the refresh slot is overwritten (CLEARED when the bundle carries
/// none), the M2M pair is replaced by whatever the bundle carries (cleared when
/// it carries none, which is the interactive shape), and the identity
/// generation moves.
fn replace_write(credentials: &SecretBundle) -> live_cell::TokenWrite<'_> {
    live_cell::TokenWrite {
        credentials,
        refresh_policy: live_cell::RefreshPolicy::Replace,
        client_credentials: live_cell::ClientCredentialsAction::Set(bundle_client_credentials(
            credentials,
        )),
        bump_identity: true,
    }
}

#[async_trait]
impl CredentialTransactionSubject for MockDriver {
    async fn credential_snapshot(&self) -> CredentialSnapshot {
        self.live.snapshot()
    }
}

/// The mock stands the SAME credential-transaction expectation the real drivers
/// stand — `ovstorage-plugin-broker`'s
/// `broker_driver_conforms_to_the_credential_transaction` runs this very
/// harness against `BrokerDriver`.
///
/// This is what keeps the double honest without a hand-maintained list: the
/// harness enumerates the dimensions one credential write moves, so a mock that
/// models fewer of them than the real transaction fails here rather than
/// silently making every test that uses it vacuous.
#[tokio::test]
async fn mock_driver_conforms_to_the_credential_transaction() {
    // The mock's DEFAULT `activate_replacing` is the real replacement
    // primitive, which is also the shape the lifecycle tests below run, so what
    // this certifies and what they exercise are the same transaction.
    let driver = MockDriver::new();
    assert_credential_transaction_conformance(&driver).await;
}

/// The mock's OTHER `activate_replacing` shape — the trait default, which a
/// driver whose live cell holds only the bearer legitimately takes.
///
/// It is a weaker transaction, so certifying it against the harness above would
/// be false; pinning it here states what it may omit (clearing the cached M2M
/// pair, moving the binding, bumping the identity generation) and what it may
/// not (splitting the fenced write). The divergence between the two shapes is
/// then written down rather than living in a flag nothing checks.
#[tokio::test]
async fn mock_driver_conforms_to_the_delegated_replacement() {
    let driver = MockDriver::new();
    driver
        .activate_replacing_delegates_to_activate
        .store(true, Ordering::SeqCst);
    assert_delegated_replacement_conformance(&driver).await;
}

fn conn(id: &str) -> Connection {
    Connection {
        id: ConnectionId(id.into()),
        backend_kind: "mock".into(),
        display_name: id.into(),
        source: ConnectionSource::Runtime { persisted: false },
        capabilities: Capabilities::empty(),
        current_addresses: Vec::new(),
        auth_state: ConnectionAuthState::Anonymous,
        last_probed: None,
        user_metadata: UserMetadata::new(),
    }
}

fn set() -> Arc<ConnectionSet<MockDriver>> {
    Arc::new(ConnectionSet::with_defaults())
}

fn cred_error(code: ErrorCode) -> Error {
    Error::new(code, "mock auth error")
}

/// Rendered `tracing` events captured off the thread-local subscriber. A log
/// line is the whole of the operator-facing signal for persist-debt, so the
/// tests that own that signal assert on the line itself rather than on a
/// side effect that happens to accompany it.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl CapturedLogs {
    /// Install as the current thread's subscriber for the returned guard's
    /// lifetime.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_default(
            tracing_subscriber::registry().with(CaptureLayer(self.clone())),
        )
    }

    /// Every captured line at `level` whose rendered text contains `needle`.
    fn matching(&self, level: tracing::Level, needle: &str) -> Vec<String> {
        self.0
            .lock()
            .iter()
            .filter(|(lvl, text)| *lvl == level && text.contains(needle))
            .map(|(_, text)| text.clone())
            .collect()
    }
}

struct CaptureLayer(CapturedLogs);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = RenderVisitor(String::new());
        event.record(&mut visitor);
        (self.0.0)
            .lock()
            .push((*event.metadata().level(), visitor.0));
    }
}

struct RenderVisitor(String);

impl tracing::field::Visit for RenderVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = write!(self.0, "{}={value:?}", field.name());
    }
}

#[tokio::test]
async fn bring_up_success_is_authenticated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(state, ConnectionAuthState::Authenticated { .. }));
    assert_eq!(driver.validates(), 1);
    assert_eq!(driver.persist_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn anonymous_validation_parks_no_refresh() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::Anonymous));
    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(state, ConnectionAuthState::Anonymous));
    // An anonymous connection carries no credentials — no background refresh is
    // ever scheduled or driven (3539858972).
    assert_eq!(
        driver.refreshes(),
        0,
        "anonymous connection drives no refresh"
    );
}

#[tokio::test]
async fn credential_failure_parks_never_authenticated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let state = set
        .add_connection(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(
        state,
        ConnectionAuthState::AwaitingAuth {
            reason: crate::AuthReason::NeverAuthenticated,
            ..
        }
    ));
}

#[tokio::test]
async fn backend_failure_parks_backend_unreachable() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::Transient)));
    let state = set
        .add_connection(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(
        state,
        ConnectionAuthState::AwaitingAuth {
            reason: crate::AuthReason::BackendUnreachable,
            ..
        }
    ));
}

#[tokio::test]
async fn bring_up_coalesces_concurrent_callers_to_one_validate() {
    let set = set();
    let mut driver = MockDriver::new();
    driver.validate_delay = Duration::from_millis(30);
    let driver = Arc::new(driver);
    // Park first (auth failure), then let the next validate succeed.
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert_eq!(driver.validates(), 1);

    // Fire N concurrent forced bring-ups; the single-flight lock + under-lock
    // re-check means exactly one more validate runs.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let set = set.clone();
        let id = id.clone();
        tasks.push(tokio::spawn(
            async move { set.bring_up(&id, true, None).await },
        ));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(driver.validates(), 2, "concurrent bring-ups coalesced");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

#[tokio::test]
async fn cooldown_blocks_unforced_retry_without_validating() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::Transient))); // add → BackendUnreachable + cooldown
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let before = driver.validates();
    let err = set.bring_up(&id, false, None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(driver.validates(), before, "cooldown skipped validate");
    // Forced retry bypasses cooldown and validates again.
    set.bring_up(&id, true, None).await.unwrap();
    assert_eq!(driver.validates(), before + 1);
}

#[tokio::test]
async fn update_credentials_success_and_rotation_park() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // initial park
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // Good creds → Authenticated.
    let state = set
        .update_credentials(&id, oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(state, ConnectionAuthState::Authenticated { .. }));
    // Bad creds → CredentialsRotated park + error.
    driver.push_validate(Err(cred_error(ErrorCode::AuthExpired)));
    let err = set
        .update_credentials(&id, oauth_bundle(None), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthExpired);
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth {
            reason: crate::AuthReason::CredentialsRotated,
            ..
        }
    ));
}

#[tokio::test]
async fn repeated_failures_latch_auth_failed() {
    let config = ConnectionSetConfig {
        max_auth_attempts: 3,
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    for _ in 0..5 {
        driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    }
    let id = ConnectionId("c1".into());
    // add = attempt 1 (→ AwaitingAuth), then force bring-ups until the threshold.
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let _ = set.bring_up(&id, true, None).await;
    let _ = set.bring_up(&id, true, None).await;
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AuthFailed { attempts: 3, .. }
    ));
}

#[tokio::test]
async fn with_recovery_refreshes_and_retries_once() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    driver.push_refresh(Ok(Refreshed {
        credentials: oauth_bundle(None),
        expires_at: None,
    }));
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                // Fail the first call with a recoverable credential error; succeed the retry.
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "op retried once");
    assert_eq!(driver.refreshes(), 1, "refresh ran before retry");
}

#[tokio::test]
async fn with_recovery_permission_denied_surfaces_without_retry() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err(cred_error(ErrorCode::PermissionDenied))
            }
        })
        .await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::PermissionDenied);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "no retry on PermissionDenied"
    );
    assert_eq!(driver.refreshes(), 0);
}

#[tokio::test]
async fn with_recovery_interactive_surfaces_without_retry() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    // AuthRequired classifies NeedsInteractive → not recoverable on the data path.
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err(cred_error(ErrorCode::AuthRequired))
            }
        })
        .await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::AuthRequired);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(driver.refreshes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticate_succeeded_swaps_to_authenticated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // start parked
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    // Drain the interactive stream; the adapter processes Succeeded.
    let events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();
    assert!(matches!(
        events.last(),
        Some(AuthEvent::Succeeded {
            credentials: None,
            ..
        })
    ));
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        1,
        "interactive persistence completes before Succeeded is observable"
    );
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_refresh_fires_before_expiry() {
    let config = ConnectionSetConfig {
        refresh_skew: Duration::from_millis(10),
        // Drop the bounded-rate floor so the 50 ms TTL drives a sub-second
        // wakeup (production defaults it to 30 s).
        min_refresh_delay: Duration::from_millis(5),
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    let soon = SystemTime::now() + Duration::from_millis(50);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: Some(soon),
    }));
    driver.push_refresh(Ok(Refreshed {
        credentials: oauth_bundle(Some(SystemTime::now() + Duration::from_secs(3600))),
        expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
    }));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(driver.refreshes() >= 1, "background refresh fired");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

#[tokio::test]
async fn remove_connection_emits_and_forgets() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    assert_eq!(set.list_connections().connections.len(), 1);
    set.remove_connection(&id).await.unwrap();
    assert!(set.list_connections().connections.is_empty());
    assert!(set.remove_connection(&id).await.is_err());
}

/// C11: `probe_connection` reports the validated auth state but is
/// side-effect-free — it must NOT persist credentials, register the connection,
/// spawn refresh, or emit any `ConnectionChange`. Uses a sentinel `Added` after
/// the probe to deterministically prove nothing was emitted before it.
#[tokio::test]
async fn probe_connection_is_side_effect_free() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(oauth_bundle(None)),
        expires_at: None,
    }));
    let mut updates = set.subscribe();

    let outcome = set
        .probe_connection(driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // The probe obtained a bearer (once) and reports the resulting verdict...
    assert_eq!(driver.validates(), 1);
    assert!(matches!(outcome, ProbeOutcome::Authenticated { .. }));
    // ...but wrote NOTHING durable: no persist, no refresh, no registration.
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        0,
        "probe must not persist credentials (no store write)"
    );
    assert_eq!(driver.refreshes(), 0, "probe must not drive refresh");
    assert!(
        set.connection(&ConnectionId("c1".into())).is_none(),
        "probe must not register the connection"
    );
    assert!(set.list_connections().connections.is_empty());

    // Emit a sentinel; if the probe had emitted a change it would arrive first.
    set.add_connection(
        conn("sentinel"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    match updates.next().await {
        Some(Ok(ConnectionChange::Added(c))) => assert_eq!(
            c.id,
            ConnectionId("sentinel".into()),
            "probe must emit no ConnectionChange before the sentinel Added"
        ),
        other => panic!("expected the sentinel Added first, got {other:?}"),
    }
}

/// C11 (cont.): a probe whose validation reports interactive sign-in is required
/// surfaces `AwaitingAuth` in the returned view — again without registering or
/// emitting anything.
#[tokio::test]
async fn probe_connection_reports_awaiting_without_registering() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    let outcome = set
        .probe_connection(driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(matches!(outcome, ProbeOutcome::NeedsInteractive { .. }));
    assert!(set.connection(&ConnectionId("c1".into())).is_none());
    assert_eq!(driver.persist_calls.load(Ordering::SeqCst), 0);
}

/// Merge gate (verify→activate supersession): `verify` runs OUTSIDE the
/// cross-process lock, so a concurrent interactive success / credential update
/// can commit a NEWER identity before `activate`. The REAL driver's `activate`
/// SKIPS the merge (identity_gen advanced) but returns `Ok(())`; the SET must then
/// perform the discard itself via its post-`activate` identity_gen recheck,
/// rather than `set_state`-ing the now-stale bundle onto the entry. This test
/// drives the mock the same way the real driver behaves (activate returns Ok on
/// mismatch, installs nothing) and asserts the set-side discard.
#[tokio::test]
async fn verify_to_activate_supersession_discards_stale_grant() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("stale")),
        expires_at: None,
    }));
    // A concurrent identity change lands DURING verify, bumping identity_gen
    // past the value captured at grant start.
    driver.verify_bumps_identity.store(true, Ordering::SeqCst);

    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // activate was ATTEMPTED (and returned Ok while skipping the install, like the
    // real driver); the SET's post-activate identity_gen recheck then DISCARDED
    // the grant, so nothing landed on the live cell and the entry did NOT commit
    // the stale bundle as Authenticated.
    assert_eq!(driver.activates(), 1, "activate is attempted after verify");
    assert!(
        driver.installed().is_none(),
        "a superseded activate installs nothing on the live cell (Ok, skipped)"
    );
    assert!(
        !matches!(state, ConnectionAuthState::Authenticated { .. }),
        "the set-side identity_gen recheck discards the stale grant — not Authenticated"
    );
    // NB: `entry.credentials` is not asserted here — in a REAL supersession the
    // winning concurrent interactive/credential-update commit bumps `cred_gen`,
    // so the in-grant memory commit is skipped and the winner's bundle stands.
    // This synthetic test bumps only `identity_gen` (via `verify_bumps_identity`)
    // with no real winner committing to the entry, so the set-side credential
    // slot is not a meaningful signal here — the live-cell + auth_state discard is.
}

/// REGRESSION GUARD: an explicit-cred `Lineage::Fresh` commit through a
/// driver whose `activate_replacing` BUMPS `identity_gen` on a successful
/// commit (the broker's shape) must still reach `Authenticated` set-side — bump
/// `cred_gen`, fire `on_authenticated`, and land the bundle on the live cell.
///
/// The prior fix gated the set-side write on a post-activate
/// `identity_gen() != expected` re-read. For the merge path that held, but the
/// replace path bumps `identity_gen` ITSELF, so the re-read saw G+1 != G and
/// early-returned — dropping the WHOLE set-side write on every `Fresh` broker
/// commit. No `ConnectionSet`-level test exercised a bumping `activate_replacing`,
/// so it hid. This drives exactly that shape; it FAILS on the pre-fix code (stays
/// `Anonymous`, `on_authenticated` never fires) and passes once the set gates on
/// the fenced-install committed-flag instead.
#[tokio::test]
async fn fresh_lineage_bumping_activate_replacing_reaches_authenticated_setside() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    // The driver replaces-and-bumps on an explicit-cred commit, like the broker's
    // `replace_tokens_and_client_credentials_if_identity_unchanged` — the mock's
    // default shape.
    let id = ConnectionId("c1".into());

    // Explicit creds → `Lineage::Fresh` → `activate_replacing`.
    let state = set
        .add_connection(conn("c1"), driver.clone(), named_bundle("explicit"), None)
        .await
        .unwrap();

    // The fenced install committed (identity_gen was uncontended), so the set-side
    // write must proceed IN FULL despite the driver's own G→G+1 bump.
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a Fresh commit through a bumping activate_replacing must reach Authenticated"
    );
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::Authenticated { .. }
        ),
        "the entry is Authenticated set-side"
    );
    assert_eq!(
        driver.on_authenticateds(),
        1,
        "the on_authenticated hook fires on the authenticated commit"
    );
    assert!(
        driver.installed().is_some(),
        "the replacement bundle landed on the live cell"
    );
    // The driver bumped identity_gen itself (its legitimate self-bump).
    assert_eq!(
        driver.identity_gen(),
        1,
        "the replace commit bumped identity_gen"
    );
    // cred_gen advanced past its initial 0 — the set-side credential swap ran.
    assert_eq!(
        set.entry(&id).unwrap().state.lock().cred_gen,
        1,
        "the set-side credential swap bumped cred_gen"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("explicit"),
        "the entry holds the explicit bundle set-side"
    );
}

/// Companion to the regression guard above: a GENUINE racing winner (the fenced
/// install does NOT commit because a concurrent identity change already bumped
/// `identity_gen` past the grant's captured generation) must still DISCARD
/// set-side. Here `verify_bumps_identity` lands the winner's bump DURING the
/// verify window, so `activate_replacing`'s fence fails → reports NOT committed →
/// the set drops the write. This proves the committed-flag gate did not simply
/// disable the supersession fence.
#[tokio::test]
async fn fresh_lineage_racing_winner_still_discards_setside() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    // A concurrent identity change lands DURING verify, past the captured gen.
    driver.verify_bumps_identity.store(true, Ordering::SeqCst);
    let id = ConnectionId("c1".into());

    let state = set
        .add_connection(conn("c1"), driver.clone(), named_bundle("stale"), None)
        .await
        .unwrap();

    assert_eq!(driver.activates(), 1, "activate_replacing is attempted");
    assert!(
        driver.installed().is_none(),
        "a stale-fenced replace installs nothing on the live cell"
    );
    assert!(
        !matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a genuinely superseded Fresh grant discards set-side — not Authenticated"
    );
    assert_eq!(
        driver.on_authenticateds(),
        0,
        "the hook never fires for a discarded grant"
    );
    assert_eq!(
        set.entry(&id).unwrap().state.lock().cred_gen,
        0,
        "no set-side credential swap ran for a discarded grant"
    );
}

/// secret store-arm `identity_gen` recheck asymmetry (`commit_authenticated` ~1182):
/// the post-`activate` recheck `matches!(lineage, Lineage::Stored) && identity_gen
/// != expected` fires on the MERGE (`Lineage::Stored`) arm but NOT on the REPLACE
/// (`Lineage::Fresh`) arm. The asymmetry is deliberate: `Fresh`'s `activate_replacing`
/// self-bumps `identity_gen` on its own successful commit, so rechecking it would
/// false-discard the driver's OWN legitimate bump; `secret store`'s `activate` merge does
/// NOT self-bump, so an advanced `identity_gen` after it committed `Ok(true)` can only
/// be a racing interactive winner — which the arm must discard rather than commit a
/// stale merge over the newer identity. Both arms are driven with the SAME condition —
/// `activate`/`activate_replacing` returns `Ok(true)` AND bumps `identity_gen` as it
/// commits — so only the lineage differs.
#[tokio::test]
async fn keyring_arm_identity_recheck_discards_while_fresh_self_bump_lands() {
    // ---- Arm K (secret store / merge): the recheck FIRES → the merge is DISCARDED. --
    {
        let set = set();
        let driver = Arc::new(MockDriver::new());
        // A persisted stored head + EMPTY supplied creds → warm-continue
        // `Lineage::Stored` → `activate` (the merge arm).
        *driver.load_result.lock() = Some(named_bundle("head"));
        // The merge commits `Ok(true)` but bumps identity_gen as it returns —
        // modeling a racing interactive winner landing in the commit→guard window.
        driver.activate_bumps_identity.store(true, Ordering::SeqCst);
        let id = ConnectionId("c1".into());

        let state = set
            .add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
            .await
            .unwrap();

        // The merge installed on the live cell and bumped identity_gen (proving it
        // returned `Ok(true)` — the discard came from the set-side recheck at ~1182,
        // NOT the `activate` supersession fence, which would have returned `Ok(false)`
        // and left identity_gen at 0).
        assert_eq!(
            driver.activates(),
            1,
            "the secret store merge activate is attempted"
        );
        assert_eq!(
            driver.identity_gen(),
            1,
            "the merge committed Ok(true) and bumped identity_gen (recheck path, not the activate fence)",
        );
        // Set-side: the secret store recheck saw identity_gen advanced and DISCARDED — no
        // authenticated commit, no cred_gen bump, hook never fired.
        assert!(
            !matches!(state, ConnectionAuthState::Authenticated { .. }),
            "the secret store-arm recheck discards a merge whose identity advanced — not Authenticated",
        );
        assert!(
            !matches!(
                set.auth_state(&id).unwrap(),
                ConnectionAuthState::Authenticated { .. }
            ),
            "the entry is not Authenticated set-side",
        );
        assert_eq!(
            set.entry(&id).unwrap().state.lock().cred_gen,
            0,
            "no set-side credential swap ran for the discarded merge",
        );
        assert_eq!(
            driver.on_authenticateds(),
            0,
            "the on_authenticated hook never fires for a discarded merge",
        );
    }

    // ---- Arm F (Fresh / replace): the recheck MUST NOT fire → the commit LANDS. -
    {
        let set = set();
        let driver = Arc::new(MockDriver::new());
        // Explicit supplied creds → `Lineage::Fresh` → `activate_replacing`, whose
        // successful commit self-bumps identity_gen (the broker replace shape,
        // and the mock's default).
        let id = ConnectionId("c1".into());

        let state = set
            .add_connection(conn("c1"), driver.clone(), named_bundle("explicit"), None)
            .await
            .unwrap();

        // Same "commit Ok(true) + bump identity_gen" condition as Arm K, but the
        // Fresh arm does NOT recheck — so the commit LANDS despite the self-bump.
        assert_eq!(
            driver.identity_gen(),
            1,
            "the replace commit self-bumped identity_gen",
        );
        assert!(
            matches!(state, ConnectionAuthState::Authenticated { .. }),
            "a Fresh commit whose activate self-bumps identity_gen must LAND (no Fresh recheck)",
        );
        assert_eq!(
            set.entry(&id).unwrap().state.lock().cred_gen,
            1,
            "the set-side credential swap ran (cred_gen advanced)",
        );
        assert_eq!(
            driver.on_authenticateds(),
            1,
            "the on_authenticated hook fires on the landed Fresh commit",
        );
    }
}

/// A backend `verify` REJECTION of an already-obtained bearer parks the
/// connection with no live-cell install — the rotated successor is already
/// durable (persisted under the lock in `obtain_and_persist`), so there is
/// nothing to roll back, and `activate` never runs.
#[tokio::test]
async fn verify_rejection_parks_without_installing() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("rotated")),
        expires_at: None,
    }));
    driver.push_verify(Err(cred_error(ErrorCode::AuthRequired)));

    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a verify rejection parks the connection"
    );
    assert_eq!(
        driver.activates(),
        0,
        "a rejected bearer is never activated onto the live cell"
    );
    assert!(driver.installed().is_none());
}

/// A [`CrossProcessRefreshLock`] that flips a shared "held" flag around its
/// critical section, so a driver can observe whether the lock was held when a
/// given verb ran. Serializes like `MockRefreshLock` but without a freshness
/// registry (bring-up's `obtain_under_lock` uses a zero window).
struct HeldProbeLock {
    serial: std::sync::Mutex<()>,
    held: Arc<std::sync::atomic::AtomicBool>,
}

impl crate::connection::set::CrossProcessRefreshLock for HeldProbeLock {
    fn with_lock(
        &self,
        _backend_kind: &str,
        _stable: &ConnectionId,
        _freshness: Duration,
        run: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        let _guard = self.serial.lock().unwrap();
        self.held.store(true, Ordering::SeqCst);
        let outcome = run();
        self.held.store(false, Ordering::SeqCst);
        outcome.map(|()| true)
    }
}

/// Hazard: `verify` runs OUTSIDE the stable-keyed cross-process lock. `obtain`
/// (the grant, which can rotate a one-time refresh token) is serialized under the
/// lock so peers never consume the same token; `verify` — potentially a slow
/// backend round-trip — must NOT hold the lock, or one process's probe stalls
/// every peer's grant. An instrumented lock exposes its held-state; the driver
/// samples it inside each verb.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_runs_outside_cross_process_lock() {
    let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lock = Arc::new(HeldProbeLock {
        serial: std::sync::Mutex::new(()),
        held: held.clone(),
    });
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-Z".into()));
    d.lock_probe = Some(held.clone());
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    // Default obtain → Bearer, default verify → Ok: bring-up reaches both verbs.
    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "bring-up authenticates so both obtain and verify ran"
    );
    assert_eq!(
        *driver.obtain_saw_lock_held.lock(),
        Some(true),
        "obtain (the token-rotating grant) must run UNDER the cross-process lock"
    );
    assert_eq!(
        *driver.verify_saw_lock_held.lock(),
        Some(false),
        "verify must run OUTSIDE the cross-process lock — a slow probe cannot stall peers"
    );
}

/// Merge gate, `cred_gen` path (Stage A covered the `identity_gen` path): `verify`
/// runs outside the cross-process lock, so a concurrent interactive `Succeeded`
/// commit can swap a NEWER lineage into the entry (bumping `cred_gen`) before the
/// grant's `activate`. `commit_authenticated` is fenced on the `cred_gen`
/// captured at grant start — a bump during the verify window makes it DISCARD the
/// stale grant rather than regress the entry to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_to_activate_cred_gen_supersession_discards_stale_grant() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Register parked (obtain reports interactive) so a forced bring_up drives a
    // fresh obtain→verify→commit we can hold in the verify window.
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // The forced bring_up obtains a "stale" bearer, then BLOCKS in verify.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.verify_gate.lock() = Some(gate.clone());
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("stale")),
        expires_at: None,
    }));
    // A concurrent interactive success commits a NEWER lineage (bumps cred_gen).
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("interactive")),
    })]);

    let s1 = set.clone();
    let id1 = id.clone();
    let bring = tokio::spawn(async move { s1.bring_up(&id1, true, None).await });
    // Wait until the bring_up grant is parked in its verify window.
    while driver.verifies() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Interactive success commits `interactive` (lock-free), bumping cred_gen past
    // the value the bring_up captured at grant start.
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "the interactive commit lands while the bring_up grant is still in verify"
    );
    // Release verify → the bring_up's commit sees cred_gen advanced and DISCARDS.
    gate.notify_one();
    let _ = bring.await.unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "a cred_gen-superseded grant must not overwrite the interactive commit"
    );
    assert_eq!(
        driver
            .installed()
            .as_ref()
            .and_then(bundle_refresh)
            .as_deref(),
        Some("interactive"),
        "the stale bearer was discarded before activate — the live cell still \
         holds what the interactive winner installed",
    );
}

/// M2M set-side resurrection guard: a superseded M2M (client_credentials)
/// grant must NOT re-cache its client_credentials identity into `entry.credentials`
/// set-side — a `set_state` of the stale M2M bundle would durably resurrect the old
/// identity on the next persist. A concurrent interactive winner commits a newer
/// lineage while the M2M grant is held in verify; when released, the M2M grant's
/// atomic recheck sees cred_gen advanced and DISCARDS, so the set-side credentials
/// hold the winner's identity, never the M2M pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_m2m_grant_does_not_resurrect_client_credentials_setside() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Register parked so a forced bring_up drives a fresh M2M obtain→verify→commit.
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // The forced bring_up obtains the M2M (client_credentials) bearer, then BLOCKS
    // in verify.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.verify_gate.lock() = Some(gate.clone());
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("m2m-client-creds")),
        expires_at: None,
    }));
    // A concurrent interactive success commits a NEWER identity (bumps cred_gen).
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("interactive")),
    })]);

    let s1 = set.clone();
    let id1 = id.clone();
    let bring = tokio::spawn(async move { s1.bring_up(&id1, true, None).await });
    while driver.verifies() == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // The interactive winner commits `interactive` while the M2M grant is still in
    // verify — bumping cred_gen past the value the M2M grant captured at grant start.
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "the interactive commit lands while the M2M grant is still in verify"
    );

    // Release verify → the M2M grant's atomic recheck sees cred_gen advanced and
    // DISCARDS: it must NOT re-cache the client_credentials identity set-side.
    gate.notify_one();
    let _ = bring.await.unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "a superseded M2M grant must not resurrect the client_credentials identity set-side",
    );
}

/// Obtain-side durable resurrection guard: the SET-SIDE recheck in
/// `commit_authenticated` is not enough on its own — `obtain_and_persist` commits
/// the rotated successor to memory AND persists it to the secret store UNDER the
/// cross-process lock, BEFORE `verify`/`commit_authenticated` run. If that
/// in-lock commit is fenced on `cred_gen` alone, a concurrent interactive
/// `Succeeded { credentials: None }` winner — which installs a new live-cell
/// identity, bumping ONLY the driver's `identity_gen`, and hands back NO bundle so
/// nothing bumps `cred_gen` — slips through: the superseded M2M
/// `client_credentials` identity is durably resurrected in BOTH memory and the
/// store, and `commit_authenticated`'s later set-side discard cannot undo the
/// store write. The dual-generation fence makes `obtain_and_persist` discard the
/// grant WHOLE (no memory write, no persist) when identity_gen advanced mid-grant.
#[tokio::test]
async fn superseded_m2m_obtain_grant_no_durable_resurrection_in_memory_or_keyring() {
    // The store (and memory) start on the winner's lineage "winner"; the
    // superseded M2M grant must leave both untouched.
    let store = Arc::new(Mutex::new(Some(named_bundle("winner"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-M2M".into()));
    d.shared_secrets = Some(store.clone());
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());

    // Register parked (obtain reports interactive), WITHOUT bumping identity, so a
    // forced bring-up drives a fresh M2M obtain we then supersede.
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    set.add_connection(conn("c1"), driver.clone(), named_bundle("winner"), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();

    // The forced bring-up obtains the M2M client_credentials bearer; DURING the
    // obtain grant window a concurrent interactive `Succeeded { None }` winner
    // installs a new live-cell identity (bumps ONLY identity_gen, not cred_gen).
    driver.obtain_bumps_identity.store(true, Ordering::SeqCst);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("m2m-client-creds")),
        expires_at: None,
    }));
    let persist_before = driver.persist_calls.load(Ordering::SeqCst);

    // The grant is superseded (identity_gen advanced) → it stays parked; a parked
    // silent bring-up returns Err, which is expected here.
    let _ = set.bring_up(&id, true, None).await;

    // Discarded WHOLE: nothing re-cached the superseded M2M identity.
    assert_ne!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("m2m-client-creds"),
        "a superseded M2M obtain grant must not resurrect client_credentials in memory",
    );
    assert_ne!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("m2m-client-creds"),
        "a superseded M2M obtain grant must not persist client_credentials to the secret store",
    );
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        persist_before,
        "the discarded grant performs NO store write (discarded before persist)",
    );
    assert!(
        !entry.state.lock().persist_debt,
        "a discarded grant never latches persist_debt",
    );
    // Memory and the secret store both still hold the winner's lineage — unregressed.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("winner"),
        "memory still holds the winner's lineage",
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("winner"),
        "the secret store still holds the winner's lineage",
    );
}

/// Locked-refresh identity-only supersession guard: a LOCKED cross-process
/// refresh whose secret persist FAILS must NOT latch `persist_debt` when the
/// grant was superseded by a concurrent interactive `Succeeded { None }` winner
/// (which bumps ONLY the driver's `identity_gen`, not `cred_gen`). With the in-lock
/// commit + persist fenced on `cred_gen` alone, that identity-only winner slips
/// through: the successor is committed to memory and the persist failure latches a
/// SPURIOUS `persist_debt`, pinning the entry to a divergent in-memory lineage and
/// skipping the coalesced keyring-head reload — a cross-process consumed-token
/// replay vector. The dual-generation fence discards the refresh WHOLE (no memory
/// write, no persist, no debt): memory == store == the winner's lineage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_locked_refresh_with_persist_failure_does_not_latch_debt() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-FA-id".into()));
    d.shared_secrets = Some(store.clone());
    d.rotate_refresh.store(true, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("c1".into());

    // Clean bring-up: authenticate on "r0" (memory + store), NOT debted.
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("r0")),
        expires_at: None,
    }));
    set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    assert!(
        !entry.state.lock().persist_debt,
        "a clean bring-up is not debted"
    );
    let persist_before = driver.persist_calls.load(Ordering::SeqCst);

    // Arm a sustained keyring-persist failure AND an identity-only supersession
    // mid-refresh, then drive a data-path recovery: ONE locked refresh grant
    // reloads "r0", rotates to "r0+", and — because identity_gen advanced mid-grant
    // — the dual-gen fence DISCARDS it whole (no memory write, no persist attempt).
    driver.persist_fail_remaining.store(3, Ordering::SeqCst);
    driver.refresh_bumps_identity.store(true, Ordering::SeqCst);
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
    assert_eq!(
        result.unwrap(),
        "ok",
        "the recovery retried the op after the refresh"
    );

    // The superseded refresh is discarded WHOLE: NO spurious persist_debt.
    assert!(
        !entry.state.lock().persist_debt,
        "a superseded refresh whose persist fails must NOT latch persist_debt",
    );
    // Memory and store both still hold the winner's lineage "r0" — the divergent
    // successor "r0+" was never committed anywhere.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0"),
        "memory is not pinned to the divergent superseded successor",
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the secret store still holds the winner's lineage (no persist of the dead successor)",
    );
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        persist_before,
        "the discarded refresh attempted NO store write",
    );
    assert_eq!(
        driver.persist_fail_remaining.load(Ordering::SeqCst),
        3,
        "the persist-failure budget is untouched — persist was never attempted",
    );
    assert_eq!(
        refresh_input_tokens(&driver),
        vec!["r0".to_string()],
        "the locked refresh consumed the reloaded head r0 exactly once",
    );
}

/// record_refreshed identity fence (unlocked path): on the unlocked refresh
/// fallback (`refresh_from_head`), `record_refreshed` is the site that commits the
/// successor to memory and persists it. It discards a result whose `cred_gen`
/// moved; it must ALSO discard one whose `identity_gen` moved — a concurrent
/// interactive `Succeeded { None }` winner (identity-only) must not let a refresh
/// successor clobber the winner's identity in memory or the secret store.
#[tokio::test]
async fn superseded_refresh_by_identity_gen_discarded_in_record_refreshed() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Clean bring-up on "r0" (default obtain returns the input bearer).
    set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    let persist_before = driver.persist_calls.load(Ordering::SeqCst);

    // A data-path recovery drives one refresh (unlocked, current-thread runtime →
    // `refresh_from_head`); the rotating IdP mints "r0+" but a concurrent
    // interactive `Succeeded { None }` winner bumps ONLY identity_gen mid-refresh.
    driver.rotate_refresh.store(true, Ordering::SeqCst);
    driver.refresh_bumps_identity.store(true, Ordering::SeqCst);
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert_eq!(driver.refreshes(), 1, "exactly one refresh ran");

    // `record_refreshed` saw identity_gen advanced → DISCARDED: no set_state, no
    // fallback persist. Memory stays on the winner's "r0"; auth_state unchanged.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0"),
        "an identity-superseded refresh must not clobber the winner's identity in memory",
    );
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        persist_before,
        "record_refreshed performed NO fallback persist for the discarded successor",
    );
    assert!(
        matches!(
            entry.state.lock().connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the connection is still Authenticated (the discard left state untouched)",
    );
}

/// Residual driver-side live-cell fence: a driver's `refresh` commits
/// its freshly-minted bearer onto the LIVE cell fenced on the identity generation
/// the `ConnectionSet` CAPTURED at grant start — the value the set THREADS into
/// `refresh(.., expected_gen)` — NOT one the driver re-captures at its own entry.
/// The residual window this closes: an interactive sign-in bumps `identity_gen` in
/// the gap between the set's capture and the driver's commit (widened by the set's
/// cross-process lock + keyring-head reload). A driver re-capturing its own gen at
/// entry would see the bump ALREADY folded in, so its `install_if_identity_unchanged`
/// fence would pass and clobber the live cell with the PRIOR identity's token — a
/// transient wrong-principal bearer. Threading the set's pre-grant capture makes the
/// fence see the gen advanced and DISCARD. Mirrors the broker's
/// `install_tokens_if_identity_unchanged` via the mock's `refresh_commits_live`.
#[tokio::test]
async fn refresh_live_cell_install_fenced_on_set_captured_identity_gen() {
    // ---- Arm A: the residual race — the fenced install MUST be skipped. -------
    {
        let set = set();
        let driver = Arc::new(MockDriver::new());
        let id = ConnectionId("c1".into());
        // Clean bring-up on "r0"; `activate` seeds the live cell with the r0 bundle.
        set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
            .await
            .unwrap();

        // Model a driver that commits to the live cell fenced on the passed
        // `expected_gen`, AND a concurrent interactive winner that installs its
        // "interactive" identity and bumps `identity_gen` in the capture→commit
        // gap. The set captured the PRE-bump gen and threaded it into `refresh`,
        // so the driver's fenced install sees the gen advanced and SKIPS.
        driver.rotate_refresh.store(true, Ordering::SeqCst);
        driver.refresh_commits_live.store(true, Ordering::SeqCst);
        driver.refresh_bumps_identity.store(true, Ordering::SeqCst);
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let result: Result<&str> = set
            .with_recovery(&id, || {
                let a = a.clone();
                async move {
                    if a.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(cred_error(ErrorCode::AuthExpired))
                    } else {
                        Ok("ok")
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(driver.refreshes(), 1, "exactly one refresh ran");
        // The live cell keeps the interactive winner's identity — the refresh's
        // stale-identity minted successor "r0+" was NOT installed.
        assert_eq!(
            bundle_refresh(&driver.installed().unwrap()).as_deref(),
            Some("interactive"),
            "the fenced live-cell install must be SKIPPED: an interactive winner that \
             bumped identity_gen in the capture→commit gap keeps the live cell",
        );
    }

    // ---- Arm B: positive control — with NO racing bump the fence PASSES. ------
    {
        let set = set();
        let driver = Arc::new(MockDriver::new());
        let id = ConnectionId("c1".into());
        set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
            .await
            .unwrap();
        // Same live-cell-committing driver, but NO concurrent identity bump: the
        // set-captured gen still matches at commit, so the fence PASSES and the
        // freshly-minted successor lands on the live cell. Proves the fence is
        // gen-sensitive, not an unconditional skip.
        driver.rotate_refresh.store(true, Ordering::SeqCst);
        driver.refresh_commits_live.store(true, Ordering::SeqCst);
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let result: Result<&str> = set
            .with_recovery(&id, || {
                let a = a.clone();
                async move {
                    if a.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(cred_error(ErrorCode::AuthExpired))
                    } else {
                        Ok("ok")
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(driver.refreshes(), 1, "exactly one refresh ran");
        assert_eq!(
            bundle_refresh(&driver.installed().unwrap()).as_deref(),
            Some("r0+"),
            "with no racing identity bump the set-captured fence passes and the \
             refresh-minted successor is installed on the live cell",
        );
    }
}

/// record_refreshed `!persisted` fallback guard: when the dual-generation
/// recheck FAILS — a concurrent interactive winner committed a newer lineage
/// set-side (its `set_state` bumped cred_gen) while the refresh grant was in
/// flight — `record_refreshed` must discard the superseded successor BEFORE the
/// unlocked fallback persist, so the dead successor is never written OVER the
/// winner's durable lineage. Here the winner is driven to COMPLETION while the
/// refresh is held in its gate, so the recheck deterministically sees cred_gen
/// advanced: the atomic guard's early return skips BOTH the set-side write and the
/// fallback persist. (Complements `superseded_refresh_by_identity_gen_discarded_in_record_refreshed`,
/// which drives the same discard via `identity_gen` on a hostless store.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_refresh_no_fallback_persist_over_interactive_winner() {
    // Shared secret store starts on the bring-up lineage "r0".
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-R".into()));
    d.shared_secrets = Some(store.clone());
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    // Pin the secret store to "r0" after bring-up so the refresh reloads a known head.
    *store.lock() = Some(named_bundle("r0"));

    // A data-path recovery drives one unlocked refresh (no lock provider →
    // `refresh_from_head`, `persisted == false`): the rotating IdP mints "r0+" but
    // the grant BLOCKS in `refresh` on the gate.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.rotate_refresh.store(true, Ordering::SeqCst);
    // The interactive winner commits a NEWER lineage (its `set_state` bumps cred_gen).
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("interactive")),
    })]);

    let s1 = set.clone();
    let id1 = id.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let recover = tokio::spawn(async move {
        s1.with_recovery(&id1, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await
    });
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Drive the interactive winner to COMPLETION while the refresh is still gated,
    // so its `set_state` bumps cred_gen BEFORE `record_refreshed` runs its recheck.
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "the interactive winner committed while the refresh is still gated",
    );

    // Release the gate → `record_refreshed`'s recheck sees cred_gen advanced and
    // DISCARDS before the fallback persist.
    gate.notify_one();
    let _ = recover.await.unwrap();

    // Set-side memory holds the winner (never regressed to "r0+"), and the dead
    // successor was NEVER persisted over the winner's durable lineage.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "a superseded refresh successor must not regress the set-side credentials",
    );
    assert_ne!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0+"),
        "the discarded refresh successor must NOT be persisted over the winner",
    );
    assert!(
        matches!(
            entry.state.lock().connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the connection stays Authenticated on the winner's commit",
    );
}

/// Lineage convergence: a bring-up whose rotation grant SUCCEEDED (rotating the
/// store past the input) but whose `verify` was REJECTED leaves the successor
/// durable while the entry's in-memory creds stay on the consumed predecessor.
/// The NEXT bring-up must reload the persisted head (not replay the stale entry
/// token — a rotating IdP would revoke the family) and grant its successor; after
/// it, the secret store, the entry's memory, and the live cell all converge on the
/// same successor, and no refresh token was ever consumed twice.
#[tokio::test]
async fn bring_up_after_verify_failure_converges_lineage_no_replay() {
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let grant_log = Arc::new(Mutex::new(Vec::new()));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-C".into()));
    d.shared_secrets = Some(store.clone());
    d.shared_grant_log = Some(grant_log.clone());
    d.validate_seed_grants.store(true, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());

    // First bring-up: warm-continue reloads "r0"; the seed grant rotates it to
    // "r0+" and persists it — but the backend REJECTS the bearer (verify fails).
    driver.push_verify(Err(cred_error(ErrorCode::AuthRequired)));
    let state = set
        .add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a verify rejection at bring-up parks the connection"
    );
    // The rotated successor is durable; nothing landed on the live cell.
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0+"),
        "the consumed rotation's successor survives the verify rejection in the secret store"
    );
    assert!(driver.installed().is_none());

    // Second bring-up (forced): reload the PERSISTED head ("r0+", not the stale
    // entry token "r0"), grant its successor "r0++", and verify succeeds.
    set.bring_up(&id, true, None).await.unwrap();

    // Convergence: store, entry memory, and the live cell all hold "r0++".
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0++"),
        "the secret store holds the successor"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0++"),
        "the entry's in-memory creds hold the successor"
    );
    assert_eq!(
        bundle_refresh(&driver.installed().unwrap()).as_deref(),
        Some("r0++"),
        "the live cell holds the successor"
    );
    // No refresh token was ever consumed twice — a duplicate here is the
    // reuse-detection footgun the head-reload prevents.
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string(), "r0+".to_string()],
        "each refresh token consumed exactly once; the stale entry token was never replayed"
    );
}

/// Persist-debt (Brian's design §6): when a rotation successor is committed to
/// memory but the secret persist FAILS (all retries), the entry latches
/// `persist_debt`, keeping the in-memory successor authoritative while the
/// store is stranded on the pre-rotation predecessor. A later secret store-lineage
/// bring-up must then NOT reload the stale stored head (`load_credentials` is
/// skipped) and must grant the in-memory successor — never the consumed
/// predecessor (a duplicate in the shared grant log would be the IdP
/// reuse-detection footgun). A subsequent SUCCESSFUL persist retires the debt,
/// after which the normal head-reload resumes.
#[tokio::test]
async fn persist_failure_marks_debt_skips_reload_and_retires() {
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let grant_log = Arc::new(Mutex::new(Vec::new()));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-C".into()));
    d.shared_secrets = Some(store.clone());
    d.shared_grant_log = Some(grant_log.clone());
    // `obtain` rotates the passed-in base (no store reload, no self-persist), so
    // the set's `obtain_and_persist` is the sole secret-store writer.
    d.rotate_grants.store(true, Ordering::SeqCst);
    // Fail the FIRST rotation grant's persist for all 3 debt-policy attempts, then
    // let every later persist succeed.
    d.persist_fail_remaining.store(3, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());

    // --- Setup: a warm-continue grant rotates "r0" -> "r0+" (verify succeeds, so
    // memory commits the successor) but its secret persist FAILS every retry.
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    assert!(
        entry.state.lock().persist_debt,
        "an exhausted secret persist latches persist-debt"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0+"),
        "the in-memory successor is authoritative"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the secret store is stranded on the pre-rotation predecessor"
    );
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string()],
        "the setup grant consumed r0 exactly once"
    );

    // Simulate the access token expiring so a later silent bring-up re-grants
    // (the production trigger for the stranded-store replay this closes). Park
    // does not touch `credentials`/`persist_debt`, so the divergence persists.
    set.park(&entry, AuthReason::NeverAuthenticated, None);

    // --- Bring-up A: while debted, the secret store head is NOT reloaded and the grant
    // runs on the in-memory successor "r0+" (-> "r0++"). The successful persist
    // here (fail counter now exhausted) also RETIRES the debt.
    let loads_before_a = driver.loads();
    set.bring_up(&id, true, None).await.unwrap();
    assert_eq!(
        driver.loads(),
        loads_before_a,
        "no stored head reload while debted (bring_up + obtain_and_persist both skip it)"
    );
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string(), "r0+".to_string()],
        "the grant consumed the in-memory successor r0+, NOT a replayed stale store r0"
    );
    assert!(
        !entry.state.lock().persist_debt,
        "a successful persist retires the debt"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0++"),
        "the retiring persist converges the secret store onto the successor"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0++"),
        "memory holds the successor"
    );

    // --- Bring-up B: with the debt retired, the normal stored head reload
    // resumes (a fresh `load_credentials`) and the grant consumes the persisted
    // head "r0++".
    set.park(&entry, AuthReason::NeverAuthenticated, None);
    let loads_before_b = driver.loads();
    set.bring_up(&id, true, None).await.unwrap();
    assert!(
        driver.loads() > loads_before_b,
        "head reload resumes once the debt is retired"
    );
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string(), "r0+".to_string(), "r0++".to_string()],
        "each refresh token consumed exactly once across the whole sequence"
    );
}

/// A consuming grant commits the rotated successor to in-memory
/// `entry.credentials` as part of the grant transaction — BEFORE persist and
/// REGARDLESS of the later `verify` outcome. So a verify REJECTION combined with a
/// sustained persist failure does not STRAND the successor: memory holds it
/// (debt set), the secret store is stranded on the consumed predecessor, and the NEXT
/// grant consumes the in-memory successor — never replaying the predecessor into
/// IdP reuse-detection.
#[tokio::test]
async fn verify_failure_with_persist_failure_keeps_successor_in_memory() {
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let grant_log = Arc::new(Mutex::new(Vec::new()));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-D4".into()));
    d.shared_secrets = Some(store.clone());
    d.shared_grant_log = Some(grant_log.clone());
    // `obtain` rotates the passed-in base (no store reload, no self-persist), so
    // the set's `obtain_and_persist` is the sole secret-store writer.
    d.rotate_grants.store(true, Ordering::SeqCst);
    // The bring-up grant's persist fails all 3 debt-policy attempts.
    d.persist_fail_remaining.store(3, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());

    // Warm-continue: obtain rotates r0 -> r0+ (committed to memory by the grant),
    // its secret persist FAILS all retries (debt), then `verify` REJECTS.
    driver.push_verify(Err(cred_error(ErrorCode::AuthRequired)));
    let state = set
        .add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a verify rejection parks the connection"
    );
    let entry = set.entry(&id).unwrap();
    // Memory holds the successor even though verify FAILED (no `set_state` ran).
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0+"),
        "the rotated successor is committed to memory as part of the grant, surviving verify failure",
    );
    assert!(
        entry.state.lock().persist_debt,
        "the exhausted secret persist latched persist-debt"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the secret store is stranded on the consumed predecessor"
    );
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string()],
        "the bring-up grant consumed r0 exactly once"
    );

    // Next bring-up (forced): while debted it grants the in-memory successor r0+
    // (-> r0++), NEVER the stranded stored head r0 (a replay = reuse-detection).
    set.bring_up(&id, true, None).await.unwrap();
    assert_eq!(
        grant_log.lock().clone(),
        vec!["r0".to_string(), "r0+".to_string()],
        "the next grant consumed the in-memory successor r0+, never the stranded predecessor r0",
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0++"),
        "the entry converges on the new successor"
    );
}

/// Unlocked fallback: while persist-debted, `coalesced_refresh` on a
/// current-thread runtime (→ `refresh_from_head`) must NOT reload the stranded
/// stored head — memory holds the strictly-newer successor. The refresh grant
/// consumes the in-memory successor, never replaying the consumed predecessor.
#[tokio::test]
async fn debted_refresh_from_head_grants_in_memory_successor_not_stranded_head() {
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-D3a".into()));
    d.shared_secrets = Some(store.clone());
    d.rotate_grants.store(true, Ordering::SeqCst); // obtain rotates its base
    d.rotate_refresh.store(true, Ordering::SeqCst); // refresh rotates its base
    d.persist_fail_remaining.store(3, Ordering::SeqCst); // strand the setup grant
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());

    // Latch debt via the obtain path: obtain rotates r0 -> r0+, its persist fails.
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    assert!(
        entry.state.lock().persist_debt,
        "the exhausted persist latched debt"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0+")
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0")
    );

    // Drive a refresh directly on the unlocked fallback (no provider +
    // current-thread → `refresh_from_head`). While debted it must NOT reload the
    // stranded stored head "r0"; it grants the in-memory successor "r0+".
    let loads_before = driver.loads();
    let creds = set.credentials(&id).unwrap();
    let gen_now = entry.state.lock().cred_gen;
    let identity_now = entry.driver.identity_gen();
    let (refreshed, _persisted) = set
        .coalesced_refresh(&entry, &creds, gen_now, identity_now)
        .await
        .unwrap();
    assert_eq!(
        driver.loads(),
        loads_before,
        "no stored head reload while debted (refresh_from_head skips it)"
    );
    assert_eq!(
        bundle_refresh(driver.refresh_inputs.lock().last().unwrap()).as_deref(),
        Some("r0+"),
        "the refresh consumed the in-memory successor r0+, not the stranded stored head r0",
    );
    assert_eq!(
        bundle_refresh(&refreshed.credentials).as_deref(),
        Some("r0++"),
        "the successor rotated forward from the in-memory token"
    );
}

/// Locked path: the same invariant on the cross-process locked
/// `coalesced_refresh` closure (`locked_refresh`) — while debted it skips the
/// stored head reload and grants the in-memory successor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debted_locked_refresh_grants_in_memory_successor_not_stranded_head() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-D3b".into()));
    d.shared_secrets = Some(store.clone());
    d.rotate_grants.store(true, Ordering::SeqCst);
    d.rotate_refresh.store(true, Ordering::SeqCst);
    d.persist_fail_remaining.store(3, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("c1".into());

    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    assert!(
        entry.state.lock().persist_debt,
        "the exhausted persist latched debt"
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0+")
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0")
    );

    let loads_before = driver.loads();
    let creds = set.credentials(&id).unwrap();
    let gen_now = entry.state.lock().cred_gen;
    let identity_now = entry.driver.identity_gen();
    let (refreshed, persisted) = set
        .coalesced_refresh(&entry, &creds, gen_now, identity_now)
        .await
        .unwrap();
    assert_eq!(
        driver.loads(),
        loads_before,
        "the locked refresh closure skips the secret store head reload while debted"
    );
    assert_eq!(
        bundle_refresh(driver.refresh_inputs.lock().last().unwrap()).as_deref(),
        Some("r0+"),
        "the locked refresh consumed the in-memory successor, not the stranded head",
    );
    assert_eq!(
        bundle_refresh(&refreshed.credentials).as_deref(),
        Some("r0++")
    );
    assert!(persisted, "the locked path persists the successor in-lock");
}

/// Locked-path persist-failure residual: the LOCKED cross-process refresh path (host lock + stable
/// id + multi-thread) must give a SUSTAINED keyring-persist failure the same
/// memory-first + debt treatment the obtain path has. The old raw in-lock persist
/// `?`-propagated a store write error, so `coalesced_refresh` returned Err —
/// `record_refreshed`'s `set_state` never ran, the rotated successor was LOST from
/// memory, and the NEXT grant reloaded the stranded stored head and replayed the
/// consumed token (IdP reuse-detection family revocation). After the fix: the
/// successor is committed to memory in-lock, the persist runs under the debt
/// policy (SETS `persist_debt`, does NOT `?`-fail), the data-path recovery still
/// succeeds, the next grant consumes the in-memory successor (never the stranded
/// head), and a later successful persist retires the debt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_refresh_persist_failure_keeps_successor_in_memory_and_retires() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-FA".into()));
    d.shared_secrets = Some(store.clone());
    // `refresh` rotates its base (a rotating IdP) and records every input in
    // `refresh_inputs`; `obtain` uses the validate queue.
    d.rotate_refresh.store(true, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("c1".into());

    // Clean bring-up: authenticate on "r0" (memory + store), NOT debted — the
    // obtain persist succeeds (the fail counter is still 0).
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("r0")),
        expires_at: None,
    }));
    set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let entry = set.entry(&id).unwrap();
    assert!(
        !entry.state.lock().persist_debt,
        "a clean bring-up is not debted"
    );

    // Arm a sustained keyring-persist failure, then drive a data-path recovery: the
    // op fails once with a recoverable credential error → ONE locked refresh grant
    // (host lock + stable id + multi-thread → the `with_lock` closure) reloads the
    // head "r0", rotates to "r0+", commits it to memory, and persists — failing all
    // 3 debt-policy retries. The OLD raw in-lock persist `?`-failed here (losing
    // "r0+"); now the recovery still succeeds.
    driver.persist_fail_remaining.store(3, Ordering::SeqCst);
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
    assert_eq!(
        result.unwrap(),
        "ok",
        "the sustained persist failure did not `?`-fail the locked refresh; recovery retried the op",
    );

    // The successor "r0+" is authoritative in memory; `persist_debt` is latched;
    // the secret store is stranded on the consumed predecessor; the head was consumed
    // exactly once.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0+"),
        "the rotated successor stays in memory despite the persist failure (not lost)",
    );
    assert!(
        entry.state.lock().persist_debt,
        "the exhausted locked persist latched persist-debt"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the secret store is stranded on the pre-rotation predecessor",
    );
    assert_eq!(
        refresh_input_tokens(&driver),
        vec!["r0".to_string()],
        "the locked refresh consumed the reloaded head r0 exactly once",
    );

    // Next recovery grant: while debted the locked closure must NOT reload the
    // stranded head "r0" — it grants the in-memory successor "r0+" (-> "r0++"). The
    // persist now succeeds (fail counter exhausted), RETIRING the debt.
    let loads_before = driver.loads();
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let result: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok2")
                }
            }
        })
        .await;
    assert_eq!(result.unwrap(), "ok2");
    assert_eq!(
        driver.loads(),
        loads_before,
        "no stored head reload while debted (the locked closure grants the in-memory successor)",
    );
    assert_eq!(
        refresh_input_tokens(&driver),
        vec!["r0".to_string(), "r0+".to_string()],
        "the next grant consumed the in-memory successor r0+, never the stranded head r0",
    );
    assert!(
        !entry.state.lock().persist_debt,
        "a later successful persist retires the debt"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0++"),
        "the retiring persist converges the secret store onto the successor",
    );
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("r0++"),
        "memory converges on the successor",
    );
}

/// Latch persist-debt on a connection that ends the bring-up `Authenticated`,
/// so a test can drive teardown and the accessor from a realistic state: memory
/// holds the rotated successor, the secret store is stranded on the consumed
/// predecessor, and the connection is serving.
async fn debted_authenticated_connection(
    set: &Arc<ConnectionSet<MockDriver>>,
    store: &Arc<Mutex<Option<SecretBundle>>>,
    id: &str,
    stable: Option<&str>,
) -> Arc<MockDriver> {
    let mut d = MockDriver::new();
    d.shared_secrets = Some(store.clone());
    d.stable = stable.map(|s| ConnectionId(s.into()));
    // `obtain` rotates the base it is handed and does not self-persist, so the
    // set's `obtain_and_persist` is the only store writer.
    d.rotate_grants.store(true, Ordering::SeqCst);
    // Exhaust all three debt-policy attempts on the bring-up persist.
    d.persist_fail_remaining.store(3, Ordering::SeqCst);
    let driver = Arc::new(d);
    set.add_connection(conn(id), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    driver
}

/// Persist-debt lives only in this process's memory, so teardown is the last
/// point at which it can be reported at all. A connection that goes away still
/// carrying the debt leaves the durable store holding a refresh token a
/// rotation already consumed; the operator's only chance to act on that — sign
/// in again rather than warm-continue — is before the next start.
///
/// A hard crash still reports nothing. That is the acknowledged bound of this
/// report, not an oversight.
#[tokio::test]
async fn teardown_reports_outstanding_persist_debt() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let driver = debted_authenticated_connection(&set, &store, "c1", None).await;
    assert!(
        set.entry(&id).unwrap().state.lock().persist_debt,
        "the exhausted bring-up persist latched persist-debt"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the secret store is stranded on the consumed predecessor"
    );
    drop(driver);

    // Tear the connection down the way a clean shutdown does.
    set.unregister_connection(&id).await.unwrap();

    let reported = logs.matching(tracing::Level::WARN, "persist_debt=true");
    assert_eq!(
        reported.len(),
        1,
        "teardown reports the outstanding debt exactly once; captured warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
    assert!(
        reported[0].contains("c1"),
        "the report names the connection so an operator knows which one to sign in again: {}",
        reported[0],
    );
}

/// A purging `remove_connection` deletes the durable secret before the entry
/// drops. Reporting the debt then would name a store that no longer holds
/// anything, and ask for a sign-in on a connection that no longer exists —
/// both halves false. Only a teardown that PRESERVES the durable head (clean
/// shutdown, or a non-purging `unregister_connection`) strands a consumed
/// token, and only there is the remedy real.
#[tokio::test]
async fn purging_removal_does_not_report_persist_debt() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let driver = debted_authenticated_connection(&set, &store, "c1", None).await;
    assert_eq!(set.persist_debt(&id), Some(true));
    drop(driver);

    set.remove_connection(&id).await.unwrap();

    assert!(
        store.lock().is_none(),
        "the purging removal deleted the durable secret (so there is nothing \
         stranded to report)"
    );
    assert!(
        logs.matching(tracing::Level::WARN, "persist_debt")
            .is_empty(),
        "a purged connection has no stranded token and no next start; captured \
         warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
}

/// A purging removal only *intends* to delete; whether a secret is actually
/// left behind is a different question, and the report has to follow the
/// second one.
///
/// Secrets are keyed per stable id, so `remove_inner` skips the delete when a
/// live sibling shares that id. The removed connection's outstanding debt is
/// then still real — the stored token is the consumed predecessor, the sibling
/// keeps it alive, and the next start warm-continues on it. Gating on the
/// purge INTENT suppresses the warning in exactly this case.
#[tokio::test]
async fn shared_stable_id_removal_still_reports_persist_debt() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());

    // A live sibling on the SAME stable id, so the purge must spare the secret.
    let sibling = Arc::new({
        let mut d = MockDriver::new();
        d.stable = Some(ConnectionId("host-shared".into()));
        d.shared_secrets = Some(store.clone());
        d
    });
    set.add_connection(conn("c2"), sibling, named_bundle("r0"), None)
        .await
        .unwrap();

    let driver = debted_authenticated_connection(&set, &store, "c1", Some("host-shared")).await;
    assert_eq!(set.persist_debt(&id), Some(true));
    drop(driver);

    // Purge INTENT is recorded, but the shared stable id means no delete runs.
    set.remove_connection(&id).await.unwrap();

    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the sibling's shared stable id spared the secret, so the consumed \
         predecessor is still stored — there IS something stranded to report",
    );
    let reported = logs.matching(tracing::Level::WARN, "persist_debt=true");
    assert_eq!(
        reported.len(),
        1,
        "a removal that deleted nothing must still report the debt; captured \
         warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
    assert!(
        reported[0].contains("c1"),
        "the report names the removed connection: {}",
        reported[0],
    );
}

/// The other way intent and outcome diverge: the delete RUNS and fails. Both
/// teardown call sites discard the error, so nothing else notices — and the
/// consumed predecessor is still stored, which is the whole condition the
/// report exists to name.
#[tokio::test]
async fn failed_purge_delete_still_reports_persist_debt() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let driver = debted_authenticated_connection(&set, &store, "c1", None).await;
    assert_eq!(set.persist_debt(&id), Some(true));
    driver.delete_fails.store(true, Ordering::SeqCst);

    set.remove_connection(&id).await.unwrap();

    assert_eq!(
        driver.deletes(),
        1,
        "the purge did attempt the delete (this is the failure case, not the \
         skipped-for-a-sibling one)"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r0"),
        "the failed delete left the consumed predecessor stored"
    );
    assert_eq!(
        logs.matching(tracing::Level::WARN, "persist_debt=true")
            .len(),
        1,
        "a purge whose delete failed must still report the debt; captured \
         warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
}

/// A sixth durable-deletion path: `purge_persisted_credentials` deletes through
/// `purge_credentials`, whose default delegates to `delete_credentials`. The
/// connection stays LIVE afterwards, so this is not a teardown — but it empties
/// the store just the same, and `obtain_and_persist` reaches it on a
/// current-lineage rejection while debt may already be latched. Reporting a
/// preserved token at the eventual teardown would be false.
#[tokio::test]
async fn purged_credentials_are_not_reported_as_preserved_at_teardown() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let _driver = debted_authenticated_connection(&set, &store, "c1", None).await;
    assert_eq!(set.persist_debt(&id), Some(true));

    set.purge_persisted_credentials(&id).await.unwrap();
    assert!(
        store.lock().is_none(),
        "the purge emptied the durable store (so there is nothing stranded)"
    );
    assert_eq!(
        set.persist_debt(&id),
        Some(true),
        "the purge does not retire the debt, which is what makes the stale \
         report reachable"
    );

    set.unregister_connection(&id).await.unwrap();

    assert!(
        logs.matching(tracing::Level::WARN, "persist_debt=true")
            .is_empty(),
        "a purged store holds no superseded token to warn about; captured \
         warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
}

/// The mirror hazard of recording that purge: the connection stays live, so a
/// later successful durable write repopulates the store. "Known deleted" has to
/// stop being true at that point, or every subsequent debt on this connection is
/// silently unreportable.
#[tokio::test]
async fn a_durable_write_after_a_purge_restores_the_teardown_report() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let driver = debted_authenticated_connection(&set, &store, "c1", None).await;
    let entry = set.entry(&id).unwrap();

    set.purge_persisted_credentials(&id).await.unwrap();
    assert!(store.lock().is_none());

    // The connection re-establishes a durable credential (the bring-up retry
    // path's persist). The store is populated again.
    set.persist_with_debt_policy(&entry, &named_bundle("r1"))
        .await;
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r1"),
        "the durable store holds a credential again"
    );
    assert_eq!(
        set.persist_debt(&id),
        Some(false),
        "that write retired the debt"
    );

    // A later rotation strands it again, exactly as the first one did.
    driver.persist_fail_remaining.store(3, Ordering::SeqCst);
    set.persist_with_debt_policy(&entry, &named_bundle("r2"))
        .await;
    assert_eq!(set.persist_debt(&id), Some(true));
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r1"),
        "the store is stranded on the superseded r1"
    );
    drop(entry);

    set.unregister_connection(&id).await.unwrap();

    assert_eq!(
        logs.matching(tracing::Level::WARN, "persist_debt=true")
            .len(),
        1,
        "the earlier purge must not make this connection permanently \
         unreportable; captured warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
}

/// A connection torn down with no debt says nothing — the report has to be a
/// signal, not a line every shutdown prints.
#[tokio::test]
async fn teardown_without_persist_debt_reports_nothing() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(!set.entry(&id).unwrap().state.lock().persist_debt);

    set.unregister_connection(&id).await.unwrap();

    assert!(
        logs.matching(tracing::Level::WARN, "persist_debt")
            .is_empty(),
        "an undebted teardown is silent; captured warnings: {:?}",
        logs.matching(tracing::Level::WARN, ""),
    );
}

/// Persist-debt is readable from outside `connection/set.rs`. Without an
/// accessor the state is confined to this module — no host, CLI or probe can
/// tell an operator that a connection's stored credential is behind and that
/// they should sign in again before restarting.
#[tokio::test]
async fn persist_debt_is_readable_through_the_public_accessor() {
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let set = set();
    let id = ConnectionId("c1".into());
    let _driver = debted_authenticated_connection(&set, &store, "c1", None).await;

    assert_eq!(
        set.persist_debt(&id),
        Some(true),
        "a debted connection reads back as debted"
    );
    assert_eq!(
        set.persist_debt(&ConnectionId("absent".into())),
        None,
        "an unregistered connection has no debt to report"
    );

    set.unregister_connection(&id).await.unwrap();
    assert_eq!(
        set.persist_debt(&id),
        None,
        "a removed connection is no longer reportable"
    );
}

/// Single-worker deadlock guard: on a multi-thread runtime with a SINGLE worker,
/// the synchronous `provider.with_lock(...)` (which blocks acquiring the
/// cross-process lock) is wrapped in `block_in_place`, so a second grant
/// contending for the SAME stable-keyed lock cannot starve the sole worker into a
/// deadlock. Two concurrent same-stable grants must both finish within a bounded
/// timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn single_worker_concurrent_same_stable_grants_do_not_deadlock() {
    let lock = Arc::new(MockRefreshLock::new());
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let mk = || {
        let mut d = MockDriver::new();
        // SAME stable id → both grants contend on one cross-process lock.
        d.stable = Some(ConnectionId("host-D5".into()));
        // Widen the window where one grant holds the lock while the other waits.
        d.validate_delay = Duration::from_millis(20);
        Arc::new(d)
    };
    let (s1, s2) = (set.clone(), set.clone());
    let (d1, d2) = (mk(), mk());
    let a = tokio::spawn(async move {
        s1.add_connection(conn("a"), d1, oauth_bundle(None), None)
            .await
    });
    let b = tokio::spawn(async move {
        s2.add_connection(conn("b"), d2, oauth_bundle(None), None)
            .await
    });
    let (ra, rb) = tokio::time::timeout(Duration::from_secs(10), async {
        (a.await.unwrap(), b.await.unwrap())
    })
    .await
    .expect("two concurrent same-stable grants must not deadlock the single worker");
    assert!(matches!(
        ra.unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(matches!(
        rb.unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

// ---- round-2 review regressions -----------------------------------------

/// A driver with a stable id (so remove/delete keying is exercised).
fn stable_driver(stable: &str) -> Arc<MockDriver> {
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId(stable.into()));
    Arc::new(d)
}

/// 3537945808: a successful `bring_up` (parked → Authenticated) emits
/// `ConnectionChange::Updated` so `updates: true` subscribers see the transition.
#[tokio::test]
async fn bring_up_success_emits_updated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let mut updates = set.subscribe();
    // Next validate (default) succeeds → Authenticated.
    set.bring_up(&id, true, None).await.unwrap();
    match updates.next().await {
        Some(Ok(ConnectionChange::Updated(c))) => {
            assert_eq!(c.id, id);
            assert!(matches!(
                c.auth_state,
                ConnectionAuthState::Authenticated { .. }
            ));
        }
        other => panic!("expected Updated(Authenticated), got {other:?}"),
    }
}

/// 3537944091: a concurrent burst where the winner FAILS must share that
/// outcome — waiters must not each re-run `validate` (which would hammer the IdP
/// and latch `AuthFailed` from one transient failure).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failed_bring_up_coalesces_to_one_validate() {
    let set = set();
    let mut driver = MockDriver::new();
    driver.validate_delay = Duration::from_millis(40);
    let driver = Arc::new(driver);
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add attempt (#1)
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // winner (#2)
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert_eq!(driver.validates(), 1);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let set = set.clone();
        let id = id.clone();
        tasks.push(tokio::spawn(
            async move { set.bring_up(&id, true, None).await },
        ));
    }
    for t in tasks {
        assert!(
            t.await.unwrap().is_err(),
            "failed winner shared to all waiters"
        );
    }
    // Exactly ONE more validate ran for the whole batch; the rest coalesced.
    assert_eq!(
        driver.validates(),
        2,
        "concurrent failed bring-ups coalesced"
    );
    // A single transient failure did not latch AuthFailed via attempt inflation.
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth { .. }
    ));
}

/// 3537945298: `Cancelled` from `validate` in `bring_up` must not advance the
/// failure counter or park (no attempt recorded).
#[tokio::test]
async fn cancelled_bring_up_does_not_count_as_attempt() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked (attempt 1)
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // Cancelled bring-ups: no counter advance, connection stays AwaitingAuth.
    for _ in 0..10 {
        driver.push_validate(Err(cred_error(ErrorCode::Cancelled)));
        let err = set.bring_up(&id, true, None).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "repeated cancellations must not latch AuthFailed"
    );
}

/// 3537945298 (update_credentials): a `Cancelled` validate must not park
/// `CredentialsRotated` or advance the counter.
#[tokio::test]
async fn cancelled_update_credentials_does_not_park() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap(); // Authenticated
    driver.push_validate(Err(cred_error(ErrorCode::Cancelled)));
    let err = set
        .update_credentials(&id, oauth_bundle(None), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
    // Still Authenticated — no CredentialsRotated park.
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// 3537943264 (generic): `update_credentials` with creds that only yield
/// `AwaitingInteractive` returns `Err` (not a false success).
#[tokio::test]
async fn update_credentials_awaiting_interactive_is_err() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    let err = set
        .update_credentials(&id, oauth_bundle(None), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth { .. }
    ));
}

/// 3537944566: an interactive `Succeeded { credentials: None }` (driver installed
/// tokens itself / static creds) is a terminal Authenticated transition — the
/// connection must not stay parked in AwaitingAuth.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticate_succeeded_without_credentials_is_authenticated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // start parked
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: None,
    })]);
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::Authenticated { .. }
        ),
        "Succeeded{{None}} must authenticate, not stay parked"
    );
}

/// Fencing contract for `set_authenticated_keep_creds` in `set.rs`: a bundle-less
/// `Succeeded { None }` transition is fenced on the `cred_gen` / `identity_gen`
/// captured at flow start. Direction 1 — a `cred_gen` winner: a refresh commits a
/// NEWER lineage (bumping cred_gen) while the interactive flow runs. The fence FAILS,
/// so the loser's `Succeeded { None }` is DISCARDED and must NOT clobber the winner's
/// `expires_at` (clobbering it to `None` would silently disarm proactive refresh) or
/// clear the cooldown. `authenticate` captures the fence NOW; the terminal event is
/// only processed when the returned stream is drained, so the winning refresh injected
/// between the two deterministically supersedes the loser.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn succeeded_none_superseded_by_cred_gen_is_discarded() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Bring up Authenticated with a known expiry (arms proactive refresh); cred_gen → 1.
    let initial_expiry = SystemTime::now() + Duration::from_secs(1800);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("initial")),
        expires_at: Some(initial_expiry),
    }));
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // A stale cooldown is present so the discard's SKIPPED clear is observable.
    set.set_cooldown(&id);
    assert!(set.in_cooldown(&id));

    // Start the interactive flow: `authenticate` captures the fence (cred_gen = 1)
    // now, but the `Succeeded { None }` is processed only on drain below.
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: None,
    })]);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();

    // A racing WINNER commits a newer lineage via a refresh (bumps cred_gen to 2),
    // installing its OWN expiry on the connection.
    let winner_expiry = SystemTime::now() + Duration::from_secs(3600);
    driver.push_refresh(Ok(Refreshed {
        credentials: named_bundle("winner"),
        expires_at: Some(winner_expiry),
    }));
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let recovered: Result<&str> = set
        .with_recovery(&id, || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
    assert_eq!(recovered.unwrap(), "ok");
    assert_eq!(driver.refreshes(), 1, "the winning refresh ran");

    // Drain the loser's `Succeeded { None }` — the fence sees cred_gen advanced.
    let _events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();

    // The winner's `expires_at` SURVIVES (not clobbered to None → proactive refresh
    // stays armed) and the auth_state is unchanged.
    match set.auth_state(&id).unwrap() {
        ConnectionAuthState::Authenticated { expires_at, .. } => assert_eq!(
            expires_at,
            Some(winner_expiry),
            "a cred_gen-superseded Succeeded{{None}} must not overwrite the winner's expires_at",
        ),
        other => panic!("expected the winner's Authenticated to survive, got {other:?}"),
    }
    // The discard took the fence-failed path: no cooldown clear, no cred_gen bump.
    assert!(
        set.in_cooldown(&id),
        "a discarded Succeeded{{None}} must not clear the cooldown",
    );
    assert_eq!(
        set.entry(&id).unwrap().state.lock().cred_gen,
        2,
        "cred_gen holds the winner's value (bring-up = 1, refresh = 2); the loser did not bump it",
    );
}

/// Direction 2 — an `identity_gen` winner with `cred_gen`
/// UNCHANGED: a concurrent interactive `Succeeded { None }` winner installs a new
/// live-cell identity, bumping ONLY the driver's `identity_gen`. The fence's
/// `identity_gen` half FAILS, so the loser's `Succeeded { None }` is DISCARDED — the
/// winner's `expires_at` / auth_state survive and the cooldown is not cleared. Pins
/// the `identity_gen` arm of the same fence independently of the `cred_gen` arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn succeeded_none_superseded_by_identity_gen_is_discarded() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Bring up Authenticated with a known expiry; cred_gen → 1, identity_gen = 0.
    let winner_expiry = SystemTime::now() + Duration::from_secs(3600);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: Some(named_bundle("winner")),
        expires_at: Some(winner_expiry),
    }));
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.set_cooldown(&id);
    assert!(set.in_cooldown(&id));

    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: None,
    })]);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();

    // A racing winner bumps ONLY identity_gen (cred_gen unchanged) — the live-cell
    // identity change a `Succeeded { None }` winner performs.
    driver.bump_identity_gen();

    let _events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();

    match set.auth_state(&id).unwrap() {
        ConnectionAuthState::Authenticated { expires_at, .. } => assert_eq!(
            expires_at,
            Some(winner_expiry),
            "an identity_gen-superseded Succeeded{{None}} must not overwrite the winner's expires_at",
        ),
        other => panic!("expected the winner's Authenticated to survive, got {other:?}"),
    }
    assert!(
        set.in_cooldown(&id),
        "a discarded Succeeded{{None}} must not clear the cooldown",
    );
    assert_eq!(
        set.entry(&id).unwrap().state.lock().cred_gen,
        1,
        "cred_gen is unchanged (bring-up = 1); the discarded loser did not bump it",
    );
}

/// Positive pin (the OTHER failure direction): with `cred_gen`
/// / `identity_gen` UNCHANGED since flow start, a bundle-less `Succeeded { None }`
/// fence PASSES — the legitimate keep-creds path runs: it transitions the connection
/// to Authenticated, clears the cooldown, and arms proactive refresh (its spawned
/// task runs `on_authenticated` then `spawn_refresh`). A fence that FALSE-discarded a
/// legitimate sign-in would leave it parked and silently skip the refresh (re)arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn succeeded_none_fence_passes_arms_refresh_and_clears_cooldown() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    // Start PARKED (obtain reports AuthRequired) → AwaitingAuth + cooldown set, and
    // `on_authenticated` has NOT fired (nothing authenticated yet).
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(set.in_cooldown(&id), "a parked bring-up sets a cooldown");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth { .. }
    ));

    // A clean interactive flow (no racing commit) ends in a bundle-less success.
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: None,
    })]);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();
    // The fence passed: the connection transitioned to Authenticated, the cooldown
    // was cleared, and the owner-runtime transition ran the lifecycle hook before
    // the terminal event became observable.
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::Authenticated { .. }
        ),
        "an un-superseded Succeeded{{None}} must authenticate (no false-discard)",
    );
    assert!(
        !set.in_cooldown(&id),
        "the legitimate keep-creds path clears the cooldown",
    );
    assert_eq!(
        driver.on_authenticateds(),
        1,
        "the keep-creds success block armed refresh via its spawned task (on_authenticated fired once)",
    );
}

/// 3537944250: `with_recovery` whose refresh fails with a credential-class error
/// parks the connection + emits Updated (rather than leaving it Authenticated
/// with dead creds and surfacing the same error forever).
#[tokio::test]
async fn with_recovery_credential_refresh_failure_parks() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // The recovery refresh fails with a revoked-class error.
    driver.push_refresh(Err(cred_error(ErrorCode::AuthExpired)));
    let mut updates = set.subscribe();
    let result: Result<&str> = set
        .with_recovery(&id, || async { Err(cred_error(ErrorCode::AuthExpired)) })
        .await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::AuthExpired);
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "failed recovery refresh must park the connection"
    );
    assert!(matches!(
        updates.next().await,
        Some(Ok(ConnectionChange::Updated(_)))
    ));
}

/// 3537944250 (transient): a transient recovery-refresh failure keeps the
/// connection Authenticated (a later op / background refresh may recover).
#[tokio::test]
async fn with_recovery_transient_refresh_failure_stays_authenticated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    driver.push_refresh(Err(cred_error(ErrorCode::Transient)));
    let result: Result<&str> = set
        .with_recovery(&id, || async { Err(cred_error(ErrorCode::AuthExpired)) })
        .await;
    assert!(result.is_err());
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// A parked connection whose data-path op SUCCEEDS is promoted: the op proves
/// the credentials the probe could not, and the connection stops reporting
/// `AwaitingAuth`. The `Updated` fires so subscribers see it, and the
/// promotion carries no `expires_at` — a successful op says nothing about
/// expiry.
#[tokio::test]
async fn with_recovery_success_promotes_a_parked_connection() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    let state = set
        .add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "setup: the rejected validate must park, got {state:?}"
    );
    let mut updates = set.subscribe();

    let result: Result<&str> = set
        .with_recovery_promoting_if(&id, || true, || async { Ok("ok") })
        .await;

    assert_eq!(result.unwrap(), "ok");
    match set.auth_state(&id).unwrap() {
        ConnectionAuthState::Authenticated { expires_at, .. } => {
            assert!(expires_at.is_none(), "a successful op implies no expiry");
        }
        other => panic!("a successful op must promote the connection, got {other:?}"),
    }
    // What subscribers actually receive matters: an `Updated` carrying a stale
    // view, or one for another connection, is the failure the identity
    // machinery exists to prevent.
    match updates.next().await {
        Some(Ok(ConnectionChange::Updated(view))) => {
            assert_eq!(view.id, id, "the Updated must name this connection");
            assert!(
                matches!(view.auth_state, ConnectionAuthState::Authenticated { .. }),
                "subscribers must see the promoted state, got {:?}",
                view.auth_state
            );
        }
        other => panic!("expected an Updated for the promoted connection, got {other:?}"),
    }
    assert_eq!(driver.refreshes(), 0, "promotion grants nothing");
}

/// `with_recovery` — the helper every plugin that has not wired acceptance
/// evidence still uses — promotes nothing at all, whatever the op returns.
#[tokio::test]
async fn with_recovery_never_promotes() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let result: Result<&str> = set.with_recovery(&id, || async { Ok("ok") }).await;
    assert_eq!(result.unwrap(), "ok");
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "with_recovery must leave the connection exactly as it found it"
    );
}

/// A run the backend did not accept promotes nothing, however successful the
/// operation looked — otherwise a connection holding a rejected key would
/// report `Authenticated` off a locally-produced answer.
#[tokio::test]
async fn with_recovery_success_the_backend_did_not_accept_does_not_promote() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let result: Result<&str> = set
        .with_recovery_promoting_if(&id, || false, || async { Ok("ok") })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a success the backend never saw must leave the connection parked"
    );
}

/// The promotion is fenced on entry IDENTITY, not on the id. An op that
/// started against one connection must not vindicate a DIFFERENT connection
/// that was registered under the same id while it was in flight — its
/// credentials were never exercised.
#[tokio::test]
async fn with_recovery_success_does_not_promote_a_re_added_connection() {
    let set = set();
    let first_driver = Arc::new(MockDriver::new());
    first_driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), first_driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // The op removes the connection and re-adds the SAME id with a different
    // driver whose credentials are refused, then succeeds — standing in for an
    // op that was in flight across a remove-then-re-add.
    let set_for_op = set.clone();
    let successor = Arc::new(MockDriver::new());
    successor.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let result: Result<&str> = set
        .with_recovery_promoting_if(
            &id,
            || true,
            || {
                let set = set_for_op.clone();
                let successor = successor.clone();
                let id = id.clone();
                async move {
                    set.remove_connection(&id).await.unwrap();
                    set.add_connection(conn("c1"), successor, oauth_bundle(None), None)
                        .await
                        .unwrap();
                    Ok("ok")
                }
            },
        )
        .await;

    assert_eq!(result.unwrap(), "ok");
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "the successor's credentials were never exercised and must stay parked"
    );
}

/// `with_promotion_if` is the no-retry sibling, for operations whose body is
/// consumed. It promotes on the same evidence and carries the same
/// capture-before-the-op identity fence, which is the part a refactor could
/// silently drop: looking the entry up after the op would vindicate whatever is
/// registered under that id by then.
#[tokio::test]
async fn with_promotion_if_promotes_and_fences_on_identity() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // Evidence the backend accepted the op promotes it, with no retry loop.
    let result: Result<&str> = set
        .with_promotion_if(&id, || true, async { Ok("ok") })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(driver.refreshes(), 0, "no retry loop on this path");

    // A successor registered under the same id while the op ran is NOT
    // vindicated by it.
    let successor = Arc::new(MockDriver::new());
    successor.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let set_for_op = set.clone();
    let id_for_op = id.clone();
    let result: Result<&str> = set
        .with_promotion_if(&id, || true, async move {
            set_for_op.remove_connection(&id_for_op).await.unwrap();
            set_for_op
                .add_connection(conn("c1"), successor, oauth_bundle(None), None)
                .await
                .unwrap();
            Ok("ok")
        })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "the successor's credentials were never exercised"
    );
}

/// The `is_live` fence, which the re-add case cannot reach: an operation whose
/// connection is REMOVED while it runs must not emit an `Updated` for an id
/// subscribers have just seen `Removed`. The pre-op capture alone does not
/// cover this — the captured entry is exactly the one being promoted — so
/// without the fence a dead connection surfaces as an update with nothing
/// following it.
#[tokio::test]
async fn a_removed_connection_is_not_promoted_or_announced() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let mut updates = set.subscribe();

    let set_for_op = set.clone();
    let id_for_op = id.clone();
    let result: Result<&str> = set
        .with_recovery_promoting_if(
            &id,
            || true,
            || {
                let set = set_for_op.clone();
                let id = id_for_op.clone();
                async move {
                    set.remove_connection(&id).await.unwrap();
                    Ok("ok")
                }
            },
        )
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(
        set.auth_state(&id).is_none(),
        "the connection is gone, not promoted"
    );
    match updates.next().await {
        Some(Ok(ConnectionChange::Removed { id: removed })) => assert_eq!(removed, id),
        other => panic!("expected a Removed for the retired connection, got {other:?}"),
    }
    // And nothing after it. An `Updated` here would resurrect an id subscribers
    // have just been told is gone, with nothing following to retire it again.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            futures::StreamExt::next(&mut updates)
        )
        .await
        .is_err(),
        "a removed connection must not be announced again"
    );
}

/// The control: an `Anonymous` connection has no credentials to vindicate, so a
/// successful op leaves it exactly as it was.
#[tokio::test]
async fn with_recovery_success_leaves_an_anonymous_connection_anonymous() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::Anonymous));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let result: Result<&str> = set
        .with_recovery_promoting_if(&id, || true, || async { Ok("ok") })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Anonymous
    ));
}

/// The other control: `AuthFailed` is latched for the host to act on, and a
/// successful op does not quietly clear it.
#[tokio::test]
async fn with_recovery_success_leaves_auth_failed_latched() {
    let config = ConnectionSetConfig {
        max_auth_attempts: 3,
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    for _ in 0..5 {
        driver.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    }
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let _ = set.bring_up(&id, true, None).await;
    let _ = set.bring_up(&id, true, None).await;
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AuthFailed { .. }
        ),
        "setup: the attempt threshold must latch AuthFailed"
    );
    let result: Result<&str> = set
        .with_recovery_promoting_if(&id, || true, || async { Ok("ok") })
        .await;
    assert_eq!(result.unwrap(), "ok");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AuthFailed { .. }
    ));
}

/// 3537947255: two concurrent `with_recovery` ops recovering from the same
/// expiry drive EXACTLY ONE refresh grant (the second coalesces via `cred_gen`),
/// so a rotating refresh token is never granted concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_recovery_coalesces_concurrent_refreshes_to_one_grant() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // Gate the first refresh so it holds the single-flight lock until we release.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.push_refresh(Ok(Refreshed {
        credentials: oauth_bundle(None),
        expires_at: None,
    }));

    let op = |tag: &'static str| {
        let a = Arc::new(AtomicUsize::new(0));
        move || {
            let a = a.clone();
            async move {
                if a.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok(tag)
                }
            }
        }
    };

    let s1 = set.clone();
    let id1 = id.clone();
    let op1 = op("one");
    let t1 = tokio::spawn(async move { s1.with_recovery(&id1, op1).await });
    // Wait until op1 is parked inside the gated refresh (holding the lock).
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let s2 = set.clone();
    let id2 = id.clone();
    let op2 = op("two");
    let t2 = tokio::spawn(async move { s2.with_recovery(&id2, op2).await });
    // Give op2 time to fail-first and block on the single-flight lock.
    tokio::time::sleep(Duration::from_millis(60)).await;
    gate.notify_one(); // release op1's refresh
    assert_eq!(t1.await.unwrap().unwrap(), "one");
    assert_eq!(t2.await.unwrap().unwrap(), "two");
    assert_eq!(
        driver.refreshes(),
        1,
        "concurrent recoveries drove one grant"
    );
}

/// 3537947068 (transient): a background-refresh transient failure keeps the
/// connection Authenticated and re-arms (refreshes twice), without advancing the
/// failure counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_refresh_transient_failure_keeps_authenticated() {
    let config = ConnectionSetConfig {
        refresh_skew: Duration::from_millis(10),
        min_refresh_delay: Duration::from_millis(10),
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    let soon = SystemTime::now() + Duration::from_millis(30);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: Some(soon),
    }));
    // First refresh: transient Err (stay Authenticated); second: Ok.
    driver.push_refresh(Err(cred_error(ErrorCode::Transient)));
    driver.push_refresh(Ok(Refreshed {
        credentials: oauth_bundle(Some(SystemTime::now() + Duration::from_secs(3600))),
        expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
    }));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        driver.refreshes() >= 2,
        "transient failure re-armed the refresh"
    );
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// 3537947068 (credential): a background-refresh credential-class failure parks
/// the connection and stops the loop (no further refresh fires).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_refresh_credential_failure_parks_and_stops() {
    let config = ConnectionSetConfig {
        refresh_skew: Duration::from_millis(10),
        min_refresh_delay: Duration::from_millis(10),
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    let soon = SystemTime::now() + Duration::from_millis(30);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: Some(soon),
    }));
    driver.push_refresh(Err(cred_error(ErrorCode::AuthExpired))); // credential-class
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after_park = driver.refreshes();
    assert_eq!(
        after_park, 1,
        "loop stopped after the credential-class failure"
    );
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        driver.refreshes(),
        after_park,
        "no further refresh after park"
    );
}

/// 3537945401: `PermissionDenied` from a background refresh must park + stop —
/// never re-drive a definitive authorization denial on the retry cadence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_refresh_permission_denied_parks_and_stops() {
    let config = ConnectionSetConfig {
        refresh_skew: Duration::from_millis(10),
        min_refresh_delay: Duration::from_millis(10),
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    let soon = SystemTime::now() + Duration::from_millis(30);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: Some(soon),
    }));
    driver.push_refresh(Err(cred_error(ErrorCode::PermissionDenied)));
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(driver.refreshes(), 1, "PermissionDenied did not loop");
    assert!(matches!(
        set.auth_state(&id).unwrap(),
        ConnectionAuthState::AwaitingAuth { .. }
    ));
}

/// 3537942738: explicit `remove_connection` deletes the durable secret exactly
/// once for the last connection of a stable id; a sibling sharing the stable id
/// suppresses the delete.
#[tokio::test]
async fn remove_connection_deletes_secret_with_stable_id_guard() {
    // Last connection for a stable id → exactly one delete.
    let set = set();
    let d1 = stable_driver("host-A");
    set.add_connection(conn("c1"), d1.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.remove_connection(&ConnectionId("c1".into()))
        .await
        .unwrap();
    assert_eq!(d1.deletes(), 1, "last connection deletes its secret");

    // Sibling shares the stable id → zero deletes when the first is removed.
    let set = Arc::new(ConnectionSet::with_defaults());
    let a = stable_driver("host-B");
    let b = stable_driver("host-B");
    set.add_connection(conn("a"), a.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.add_connection(conn("b"), b.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.remove_connection(&ConnectionId("a".into()))
        .await
        .unwrap();
    assert_eq!(a.deletes(), 0, "sibling shares the stable id: no delete");
}

#[tokio::test]
async fn purge_persisted_credentials_keeps_connection_and_honors_stable_id_guard() {
    let set = set();
    let driver = stable_driver("identity-A");
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.purge_persisted_credentials(&id).await.unwrap();
    assert_eq!(driver.deletes(), 1);
    assert!(set.connection(&id).is_some(), "purge does not unregister");
    assert!(
        !set.credentials(&id).unwrap().fields.contains_key("oauth"),
        "purge also removes the in-memory warm-continuation token"
    );

    let set = Arc::new(ConnectionSet::with_defaults());
    let a = stable_driver("identity-B");
    let b = stable_driver("identity-B");
    set.add_connection(conn("a"), a.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.add_connection(conn("b"), b, oauth_bundle(None), None)
        .await
        .unwrap();
    set.purge_persisted_credentials(&ConnectionId("a".into()))
        .await
        .unwrap();
    assert_eq!(a.deletes(), 0, "a live sibling preserves the shared secret");
}

#[tokio::test]
async fn rejected_keyring_warm_continue_purges_dead_token() {
    let set = set();
    let driver = stable_driver("identity-dead");
    *driver.load_result.lock() = Some(named_bundle("dead"));
    driver.push_validate(Err(cred_error(ErrorCode::AuthExpired)));
    let id = ConnectionId("dead".into());

    set.add_connection(conn("dead"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();

    assert_eq!(driver.deletes(), 1);
    assert!(
        !set.credentials(&id).unwrap().fields.contains_key("oauth"),
        "the dead stored head must not remain replayable from memory"
    );
}

/// 3537942738 (rollback): the non-purging `unregister_connection` keeps the
/// durable secret (bring-up rollback must not erase a just-rotated refresh token).
#[tokio::test]
async fn unregister_connection_preserves_secret() {
    let set = set();
    let d = stable_driver("host-C");
    set.add_connection(conn("c1"), d.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    set.unregister_connection(&ConnectionId("c1".into()))
        .await
        .unwrap();
    assert_eq!(d.deletes(), 0, "rollback removal preserves the secret");
    assert!(set.connection(&ConnectionId("c1".into())).is_none());
}

/// 3537942929 / 3537943104 / 3539557466: `probe_connection` with NO supplied
/// credentials must NOT warm-load the durable secret (disclose + consume it) —
/// but the (empty) supplied bundle IS still validated through the driver, so an
/// anonymous-friendly backend reports `Anonymous` and probe/add agree. The
/// security invariant is `loads() == 0`, not "no validate".
#[tokio::test]
async fn probe_with_empty_creds_does_not_warm_load() {
    let set = set();
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-D".into()));
    let driver = Arc::new(d);
    *driver.load_result.lock() = Some(oauth_bundle(None)); // a durable secret exists
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    let outcome = set
        .probe_connection(driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    assert!(matches!(outcome, ProbeOutcome::NeedsInteractive { .. }));
    assert_eq!(
        driver.loads(),
        0,
        "probe must not warm-load the durable secret"
    );
    assert_eq!(
        driver.validates(),
        1,
        "the empty supplied bundle is still validated (anonymous parity)"
    );
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        0,
        "probe performs zero durable writes"
    );
}

/// 3539557466: probe and `add_connection` AGREE on a credential-less
/// connection to an anonymous-friendly backend — both report `Anonymous`
/// (probe must not deterministically demand sign-in where add succeeds).
#[tokio::test]
async fn probe_and_add_agree_on_anonymous_backend() {
    let set = set();
    let probe_driver = Arc::new(MockDriver::new());
    probe_driver.push_validate(Ok(MockValidated::Anonymous));
    let outcome = set
        .probe_connection(probe_driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    assert!(
        matches!(outcome, ProbeOutcome::Anonymous),
        "probe reports Anonymous for an anonymous-friendly backend"
    );

    let add_driver = Arc::new(MockDriver::new());
    add_driver.push_validate(Ok(MockValidated::Anonymous));
    let state = set
        .add_connection(conn("c1"), add_driver, SecretBundle::default(), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::Anonymous),
        "add_connection agrees with the probe verdict"
    );
}

/// 3537946668: a refresh grant that finishes AFTER `remove_connection` must not
/// re-persist the deleted secret or emit `Updated` for the removed id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_after_remove_does_not_persist_or_emit() {
    let set = set();
    let driver = stable_driver("host-E");
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let persists_before = driver.persist_calls.load(Ordering::SeqCst);
    // Gate a recovery refresh so it is in flight when we remove the connection.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.push_refresh(Ok(Refreshed {
        credentials: oauth_bundle(None),
        expires_at: None,
    }));
    let mut updates = set.subscribe();
    let s = set.clone();
    let idc = id.clone();
    let t = tokio::spawn(async move {
        let r: Result<()> = s
            .with_recovery(&idc, || async { Err(cred_error(ErrorCode::AuthExpired)) })
            .await;
        r
    });
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Remove while the refresh is gated in-flight.
    set.remove_connection(&id).await.unwrap();
    // Drain the Removed event.
    assert!(matches!(
        updates.next().await,
        Some(Ok(ConnectionChange::Removed { .. }))
    ));
    gate.notify_one();
    let _ = t.await.unwrap();
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        persists_before,
        "refresh after remove must not re-persist the deleted secret"
    );
}

/// 3537945517: the `on_authenticated` hook runs on validate + refresh commits,
/// and a hook failure parks the connection (not left reporting Authenticated).
#[tokio::test]
async fn on_authenticated_hook_runs_and_failure_parks() {
    // Hook runs on the bring-up authenticated commit.
    let set = set();
    let driver = Arc::new(MockDriver::new());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert_eq!(driver.on_authenticateds(), 1, "hook ran on validate commit");

    // A failing hook parks the connection rather than reporting Authenticated.
    let set = Arc::new(ConnectionSet::with_defaults());
    let driver = Arc::new(MockDriver::new());
    driver.on_authenticated_fails.store(true, Ordering::SeqCst);
    let state = set
        .add_connection(conn("c2"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "failed session-establishment hook must park, got {state:?}"
    );
}

// ---- round-3 review regressions ------------------------------------------

/// 3539558103: a CANCELLED bring-up winner does not bump the coalescing
/// generation — queued waiters (whose own tokens never fired) run their own
/// validate instead of receiving a spurious "sign in required".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_bring_up_winner_lets_waiters_validate() {
    let set = set();
    let mut driver = MockDriver::new();
    driver.validate_delay = Duration::from_millis(50);
    let driver = Arc::new(driver);
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked (#1)
    driver.push_validate(Err(cred_error(ErrorCode::Cancelled))); // winner (#2)
    // waiter (#3) takes the default → Authenticated.
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    let s1 = set.clone();
    let id1 = id.clone();
    let winner = tokio::spawn(async move { s1.bring_up(&id1, true, None).await });
    tokio::time::sleep(Duration::from_millis(10)).await; // waiter queues behind the winner
    let s2 = set.clone();
    let id2 = id.clone();
    let waiter = tokio::spawn(async move { s2.bring_up(&id2, true, None).await });

    let winner_err = winner.await.unwrap().unwrap_err();
    assert_eq!(winner_err.code(), ErrorCode::Cancelled);
    assert!(
        waiter.await.unwrap().is_ok(),
        "waiter behind a cancelled winner runs its own validate and succeeds"
    );
    assert_eq!(driver.validates(), 3, "add + cancelled winner + waiter");
}

/// 3539558103: waiters queued behind a FAILED winner receive the winner's
/// ACTUAL error class (transient / permission-denied), not a synthesized
/// `AuthRequired` — headless callers must not be degraded from a retryable
/// state to a hard auth error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiters_share_winner_actual_error_class() {
    for code in [ErrorCode::Transient, ErrorCode::PermissionDenied] {
        let set = set();
        let mut driver = MockDriver::new();
        driver.validate_delay = Duration::from_millis(50);
        let driver = Arc::new(driver);
        driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked
        driver.push_validate(Err(cred_error(code))); // winner
        let id = ConnectionId("c1".into());
        set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
            .await
            .unwrap();

        let s1 = set.clone();
        let id1 = id.clone();
        let winner = tokio::spawn(async move { s1.bring_up(&id1, true, None).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let s2 = set.clone();
        let id2 = id.clone();
        let waiter = tokio::spawn(async move { s2.bring_up(&id2, true, None).await });

        assert_eq!(winner.await.unwrap().unwrap_err().code(), code);
        let waiter_err = waiter.await.unwrap().unwrap_err();
        assert_eq!(
            waiter_err.code(),
            code,
            "waiter shares the winner's actual {code:?} outcome"
        );
        assert_eq!(driver.validates(), 2, "waiter did not re-validate");
    }
}

/// 3539557632: `update_credentials` serializes with an in-flight refresh grant
/// on the per-connection single-flight lock — the update commits strictly
/// after the refresh, so the final credentials are the update's lineage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_credentials_serializes_with_inflight_refresh() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), named_bundle("initial"), None)
        .await
        .unwrap();
    // Gate the recovery refresh so it holds the single-flight lock.
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.push_refresh(Ok(Refreshed {
        credentials: named_bundle("refreshed"),
        expires_at: None,
    }));
    let s1 = set.clone();
    let id1 = id.clone();
    let recovery = tokio::spawn(async move {
        let attempts = AtomicUsize::new(0);
        let r: Result<&str> = s1
            .with_recovery(&id1, || async {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok("ok")
                }
            })
            .await;
        r
    });
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The update validates + commits lineage B — it must BLOCK behind the lock.
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: None,
    }));
    let s2 = set.clone();
    let id2 = id.clone();
    let update = tokio::spawn(async move {
        s2.update_credentials(&id2, named_bundle("updated"), None)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !update.is_finished(),
        "update_credentials must serialize behind the in-flight refresh"
    );
    gate.notify_one();
    assert!(recovery.await.unwrap().is_ok());
    assert!(update.await.unwrap().is_ok());
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("updated"),
        "the update's lineage wins (committed after the refresh)"
    );
}

/// 3539557632: a refresh result whose input generation was superseded by an
/// interactive commit mid-grant is DISCARDED — the stale lineage must not
/// overwrite the newer credentials in memory or the secret store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_refresh_result_discarded_after_interactive_commit() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), named_bundle("initial"), None)
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.push_refresh(Ok(Refreshed {
        credentials: named_bundle("stale-refresh"),
        expires_at: None,
    }));
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("interactive")),
    })]);
    let persists_before = driver.persist_calls.load(Ordering::SeqCst);

    let s1 = set.clone();
    let id1 = id.clone();
    let recovery = tokio::spawn(async move {
        let r: Result<()> = s1
            .with_recovery(&id1, || async { Err(cred_error(ErrorCode::AuthExpired)) })
            .await;
        r
    });
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Interactive success commits a NEWER lineage while the grant is in flight
    // (the adapter's commit does not take the single-flight lock).
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive")
    );
    gate.notify_one();
    let _ = recovery.await.unwrap();
    // The stale refresh result was discarded, not committed.
    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("interactive"),
        "a superseded refresh result must not overwrite the interactive commit"
    );
    // Give any (incorrect) stale persist a chance to run, then check none did
    // beyond the interactive one.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let persists_after = driver.persist_calls.load(Ordering::SeqCst);
    assert!(
        persists_after <= persists_before + 1,
        "only the interactive commit may persist; the stale refresh must not"
    );
}

/// 3539557776: `with_recovery` waiters queued behind a FAILED refresh winner
/// share the failure instead of re-driving the grant with the same dead
/// credentials — exactly ONE grant, no attempt inflation toward `AuthFailed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failing_recoveries_drive_one_grant() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(gate.clone());
    driver.push_refresh(Err(cred_error(ErrorCode::AuthExpired))); // the ONE failing grant

    let s1 = set.clone();
    let id1 = id.clone();
    let t1 = tokio::spawn(async move {
        let r: Result<()> = s1
            .with_recovery(&id1, || async { Err(cred_error(ErrorCode::AuthExpired)) })
            .await;
        r
    });
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let s2 = set.clone();
    let id2 = id.clone();
    let t2 = tokio::spawn(async move {
        let r: Result<()> = s2
            .with_recovery(&id2, || async { Err(cred_error(ErrorCode::AuthExpired)) })
            .await;
        r
    });
    tokio::time::sleep(Duration::from_millis(50)).await; // t2 queues on the lock
    gate.notify_one();
    assert!(t1.await.unwrap().is_err());
    assert!(t2.await.unwrap().is_err());
    assert_eq!(
        driver.refreshes(),
        1,
        "the waiter shares the failed winner's outcome — no second grant"
    );
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "one failing winner parks once; waiters do not inflate attempts"
    );
}

/// In-memory [`CrossProcessRefreshLock`]: a serial mutex + a freshness-stamp
/// registry, mirroring the host's begin/finish-refresh semantics so the locked
/// reload→grant→persist transaction is testable in-process.
struct MockRefreshLock {
    serial: std::sync::Mutex<()>,
    stamps: Mutex<std::collections::HashMap<(String, String), std::time::Instant>>,
}

impl MockRefreshLock {
    fn new() -> Self {
        Self {
            serial: std::sync::Mutex::new(()),
            stamps: Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn stamp_now(&self, kind: &str, stable: &str) {
        self.stamps
            .lock()
            .insert((kind.into(), stable.into()), std::time::Instant::now());
    }
}

impl crate::connection::set::CrossProcessRefreshLock for MockRefreshLock {
    fn with_lock(
        &self,
        backend_kind: &str,
        stable: &ConnectionId,
        freshness: Duration,
        run: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        let _guard = self.serial.lock().unwrap();
        let key = (backend_kind.to_string(), stable.0.clone());
        if !freshness.is_zero()
            && let Some(at) = self.stamps.lock().get(&key)
            && at.elapsed() < freshness
        {
            return Ok(false); // a peer refreshed within the window — skip
        }
        run()?;
        self.stamps.lock().insert(key, std::time::Instant::now());
        Ok(true)
    }
}

/// 3539557134: the freshness-skip recovery grant reloads the sibling's
/// persisted successor UNDER the cross-process lock and persists its own
/// successor BEFORE the lock releases — so of two "processes" that both hit
/// the freshness skip, the second grants with the FIRST's persisted successor,
/// never with the pre-lock (already-consumed) token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_process_freshness_skip_reloads_persisted_successor() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r2")))); // sibling's persisted token
    lock.stamp_now("mock", "host-X"); // a sibling refreshed just now → both skip

    let mk = |gated: bool| {
        let mut d = MockDriver::new();
        d.stable = Some(ConnectionId("host-X".into()));
        d.shared_secrets = Some(store.clone());
        d.rotate_refresh.store(true, Ordering::SeqCst);
        let d = Arc::new(d);
        let gate = Arc::new(tokio::sync::Notify::new());
        if gated {
            *d.refresh_gate.lock() = Some(gate.clone());
        }
        (d, gate)
    };
    let (driver_a, gate_a) = mk(true);
    let (driver_b, _gate_b) = mk(false);
    let set_a = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let set_b = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    set_a
        .add_connection(conn("a"), driver_a.clone(), named_bundle("r2"), None)
        .await
        .unwrap();
    set_b
        .add_connection(conn("b"), driver_b.clone(), named_bundle("r2"), None)
        .await
        .unwrap();

    let failing_once = || {
        let attempts = AtomicUsize::new(0);
        move || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok(())
                }
            }
        }
    };

    let sa = set_a.clone();
    let ta = tokio::spawn(async move {
        sa.with_recovery(&ConnectionId("a".into()), failing_once())
            .await
    });
    // Wait until A is inside its (gated) zero-window grant, HOLDING the lock.
    while driver_a.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let sb = set_b.clone();
    let tb = tokio::spawn(async move {
        sb.with_recovery(&ConnectionId("b".into()), failing_once())
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await; // B blocks on the lock
    gate_a.notify_one(); // A grants with "r2" → persists "r2+" before unlocking
    assert!(ta.await.unwrap().is_ok());
    assert!(tb.await.unwrap().is_ok());

    // A granted with the reloaded sibling token; B granted with A's PERSISTED
    // successor (reloaded under the lock), never the stale pre-lock "r2".
    assert_eq!(
        bundle_refresh(&driver_a.refresh_inputs.lock()[0]).as_deref(),
        Some("r2")
    );
    assert_eq!(
        bundle_refresh(&driver_b.refresh_inputs.lock()[0]).as_deref(),
        Some("r2+"),
        "the second skipped process must grant with the first's persisted successor"
    );
    assert_eq!(
        bundle_refresh(store.lock().as_ref().unwrap()).as_deref(),
        Some("r2++"),
        "each grant persisted its successor before releasing the lock"
    );
}

/// 3539838239 (part 2): the data-path refresh ALWAYS reloads the secret store's
/// persisted head under the lock, so a STALE in-memory `entry.credentials` —
/// left on a consumed predecessor by a rotation during a prior failed validate
/// — is never replayed. The grant must consume the successor from the secret store,
/// not the stale entry token, or a rotating IdP revokes the token family.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_path_refresh_reloads_keyring_head_not_stale_entry_creds() {
    let lock = Arc::new(MockRefreshLock::new());
    // The store holds the rotated successor; `entry.credentials` is stale.
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-Y".into()));
    d.shared_secrets = Some(store.clone());
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("y".into());
    set.add_connection(
        conn("y"),
        driver.clone(),
        named_bundle("stale-consumed"),
        None,
    )
    .await
    .unwrap();
    // A rotation elsewhere advanced the persisted head PAST `entry.credentials`
    // (which still holds the now-consumed "stale-consumed" token).
    *store.lock() = Some(named_bundle("successor"));

    let attempts = AtomicUsize::new(0);
    set.with_recovery(&id, || {
        let n = attempts.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                Err(cred_error(ErrorCode::AuthExpired))
            } else {
                Ok(())
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(
        bundle_refresh(&driver.refresh_inputs.lock()[0]).as_deref(),
        Some("successor"),
        "the data-path grant must reload the secret store head, never replay the stale consumed entry token",
    );
    assert_ne!(
        bundle_refresh(&driver.refresh_inputs.lock()[0]).as_deref(),
        Some("stale-consumed"),
        "a consumed predecessor must never be replayed",
    );
    assert_eq!(driver.refreshes(), 1);
}

/// 3539858459: on the locked (cross-process) refresh path the successor is
/// persisted exactly ONCE — inside the lock — and `record_refreshed` does NOT
/// re-persist out-of-lock (a stale out-of-lock persist could overwrite a peer's
/// freshly-rotated token with a now-consumed predecessor).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coalesced_refresh_persists_exactly_once_under_lock() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-Z".into()));
    d.shared_secrets = Some(store.clone());
    d.rotate_refresh.store(true, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("z".into());
    set.add_connection(conn("z"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let persists_after_add = driver.persist_calls.load(Ordering::SeqCst);

    let attempts = AtomicUsize::new(0);
    set.with_recovery(&id, || {
        let n = attempts.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                Err(cred_error(ErrorCode::AuthExpired))
            } else {
                Ok(())
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst) - persists_after_add,
        1,
        "the locked refresh persists the successor exactly once (in-lock); \
         record_refreshed must not re-persist out-of-lock",
    );
}

/// (3539838239): on the UNLOCKED refresh fallbacks — no cross-process
/// provider / a current-thread runtime (the `#[tokio::test]` default and
/// hostless embeddings) — the grant STILL reloads the secret store head, so a stale
/// `entry.credentials` (a consumed predecessor after a rotation) is never
/// replayed. This test is single-thread ON PURPOSE (no `multi_thread`), so
/// `coalesced_refresh` takes the unlocked fallback.
#[tokio::test]
async fn unlocked_fallback_refresh_reloads_head_not_stale_creds() {
    let set = set(); // no cross-process provider
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-U".into()));
    d.shared_secrets = Some(store.clone());
    let driver = Arc::new(d);
    let id = ConnectionId("u".into());
    set.add_connection(
        conn("u"),
        driver.clone(),
        named_bundle("stale-consumed"),
        None,
    )
    .await
    .unwrap();
    // A rotation advanced the persisted head past `entry.credentials`.
    *store.lock() = Some(named_bundle("successor"));

    let attempts = AtomicUsize::new(0);
    set.with_recovery(&id, || {
        let n = attempts.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                Err(cred_error(ErrorCode::AuthExpired))
            } else {
                Ok(())
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(
        bundle_refresh(&driver.refresh_inputs.lock()[0]).as_deref(),
        Some("successor"),
        "the unlocked fallback grant must reload the secret store head, not replay the stale consumed token",
    );
}

/// (3539838324): two ConnectionSets sharing ONE cross-process lock + store
/// (two processes) warm-continuing the SAME stable concurrently must drive
/// exactly one grant PER refresh token — the seed grant the driver drives inside
/// `validate` is serialized on the stable-keyed cross-process lock
/// (`validate_under_lock`), so a reuse-detecting IdP never sees a token consumed
/// twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_warm_continue_validate_serializes_seed_grant() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let grant_log = Arc::new(Mutex::new(Vec::new()));
    let mk = || {
        let mut d = MockDriver::new();
        d.stable = Some(ConnectionId("host-X".into()));
        d.shared_secrets = Some(store.clone());
        d.shared_grant_log = Some(grant_log.clone());
        d.validate_seed_grants.store(true, Ordering::SeqCst);
        Arc::new(d)
    };
    let set_a = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let set_b = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let (da, db) = (mk(), mk());
    let ta = {
        let s = set_a.clone();
        tokio::spawn(async move {
            s.add_connection(conn("a"), da, named_bundle("r0"), None)
                .await
        })
    };
    let tb = {
        let s = set_b.clone();
        tokio::spawn(async move {
            s.add_connection(conn("b"), db, named_bundle("r0"), None)
                .await
        })
    };
    ta.await.unwrap().unwrap();
    tb.await.unwrap().unwrap();

    let log = grant_log.lock().clone();
    assert_eq!(log.len(), 2, "both warm-continue seeds granted: {log:?}");
    let mut distinct = log.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        2,
        "no refresh token consumed by two grants (IdP reuse-detection): {log:?}",
    );
    assert!(
        log.contains(&"r0".to_string()) && log.contains(&"r0+".to_string()),
        "the second seed grant consumed the first's persisted successor: {log:?}",
    );
}

/// A store READ error during the reload must fail CLOSED —
/// the grant must NOT fire on the stale in-memory token (a possibly-consumed
/// predecessor). The op surfaces the error and retries later, rather than
/// replaying a token into IdP reuse-detection.
#[tokio::test]
async fn keyring_read_error_fails_closed_not_replay() {
    let set = set(); // no provider → unlocked `refresh_from_head` reload path
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-R".into()));
    let driver = Arc::new(d);
    let id = ConnectionId("r".into());
    // entry.credentials holds a (possibly-consumed) token.
    set.add_connection(conn("r"), driver.clone(), named_bundle("consumed"), None)
        .await
        .unwrap();
    // The store read now ERRORS (locked store / D-Bus timeout).
    driver.load_error.store(true, Ordering::SeqCst);

    let attempts = AtomicUsize::new(0);
    let r: Result<()> = set
        .with_recovery(&id, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(cred_error(ErrorCode::AuthExpired))
                } else {
                    Ok(())
                }
            }
        })
        .await;

    assert!(
        r.is_err(),
        "a store read error must surface, not silently replay a stale token",
    );
    assert_eq!(
        driver.refreshes(),
        0,
        "the grant must NOT fire on the stale in-memory token when the head can't be read",
    );
}

/// (3539858875): a `remove_connection` landing between the IN-LOCK persist's
/// liveness check and its write must not leave the rotated successor as a live
/// ORPHAN in the secret store after removal — the in-lock persist re-fences and
/// deletes the orphan.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_during_in_lock_persist_leaves_no_orphan_secret() {
    let lock = Arc::new(MockRefreshLock::new());
    let store = Arc::new(Mutex::new(Some(named_bundle("r0"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("host-W".into()));
    d.shared_secrets = Some(store.clone());
    d.rotate_refresh.store(true, Ordering::SeqCst);
    let driver = Arc::new(d);
    let set = Arc::new(ConnectionSet::new_with_refresh_lock(
        ConnectionSetConfig::default(),
        lock.clone(),
    ));
    let id = ConnectionId("w".into());
    set.add_connection(conn("w"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();
    let persists_after_add = driver.persist_calls.load(Ordering::SeqCst);
    // Gate the recovery refresh's grant AND its in-lock persist.
    let refresh_gate = Arc::new(tokio::sync::Notify::new());
    let persist_gate = Arc::new(tokio::sync::Notify::new());
    *driver.refresh_gate.lock() = Some(refresh_gate.clone());
    *driver.persist_gate.lock() = Some(persist_gate.clone());

    let s = set.clone();
    let idc = id.clone();
    let t = tokio::spawn(async move {
        let r: Result<()> = s
            .with_recovery(&idc, || async { Err(cred_error(ErrorCode::AuthExpired)) })
            .await;
        r
    });
    // Wait for the in-lock grant to be in flight, then let it finish so the
    // closure proceeds (past its liveness check) into the gated persist.
    while driver.refreshes() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    refresh_gate.notify_one();
    while driver.persist_calls.load(Ordering::SeqCst) == persists_after_add {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The persist is now blocked BEFORE its write; remove the connection (which
    // deletes the secret), then release the persist so it writes the orphan.
    set.remove_connection(&id).await.unwrap();
    persist_gate.notify_one();
    let _ = t.await.unwrap();

    assert!(
        store.lock().is_none(),
        "an in-lock persist racing a removal must not leave a live orphan secret",
    );
}

/// 3539858972: after a failed bring-up sets the cooldown, an UNFORCED bring_up
/// during the window is rejected without re-validating, but once the cooldown
/// ELAPSES an unforced bring_up validates again.
#[tokio::test]
async fn cooldown_expiry_allows_unforced_bring_up_to_revalidate() {
    let config = ConnectionSetConfig {
        bringup_cooldown: Duration::from_millis(30),
        ..ConnectionSetConfig::default()
    };
    let set = Arc::new(ConnectionSet::new(config));
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked + cooldown
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    assert_eq!(driver.validates(), 1);
    // Unforced during the cooldown → rejected without re-validating.
    assert!(set.bring_up(&id, false, None).await.is_err());
    assert_eq!(
        driver.validates(),
        1,
        "cooldown blocks the unforced re-validate"
    );
    // After the cooldown elapses, an unforced bring_up validates again (the next
    // validate takes the default → Authenticated).
    tokio::time::sleep(Duration::from_millis(50)).await;
    set.bring_up(&id, false, None).await.unwrap();
    assert_eq!(
        driver.validates(),
        2,
        "cooldown expiry permits an unforced re-validate"
    );
}

/// 3539858972: removing a connection whose bring-up `validate` is still in
/// flight must not persist an orphan or emit `Updated` for the removed id when
/// the delayed validate finally completes (the bring-up success path is fenced
/// like `record_refreshed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_during_in_flight_bring_up_does_not_persist_or_emit() {
    let set = set();
    let mut driver = MockDriver::new();
    driver.validate_delay = Duration::from_millis(100);
    let driver = Arc::new(driver);
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // add → parked
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: None,
    })); // the in-flight bring_up would authenticate
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let persists_before = driver.persist_calls.load(Ordering::SeqCst);
    let mut updates = set.subscribe();

    let s1 = set.clone();
    let id1 = id.clone();
    let bring = tokio::spawn(async move { s1.bring_up(&id1, true, None).await });
    // Wait until the delayed second validate is in flight.
    while driver.validates() < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    set.remove_connection(&id).await.unwrap();
    // The Removed event is emitted; the delayed validate then completes.
    assert!(matches!(
        updates.next().await,
        Some(Ok(ConnectionChange::Removed { .. }))
    ));
    let _ = bring.await.unwrap();
    assert_eq!(
        driver.persist_calls.load(Ordering::SeqCst),
        persists_before,
        "a bring-up completing after removal must not persist an orphan secret",
    );
}

/// 3539558910: a `Failed` interactive event arriving AFTER `remove_connection`
/// must not park the removed entry or emit `Updated` for an id subscribers just
/// saw `Removed` (mirrors the `Succeeded` fence).
#[tokio::test]
async fn interactive_failed_after_remove_does_not_park_or_emit() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // parked
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Failed {
        error: cred_error(ErrorCode::AuthCancelled),
    })]);
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    set.remove_connection(&id).await.unwrap();
    let mut updates = set.subscribe();
    // Drain the stream — the Failed event arrives after removal.
    let _events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();
    // Sentinel: if the Failed arm had emitted Updated it would arrive first.
    set.add_connection(
        conn("sentinel"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    match futures::StreamExt::next(&mut updates).await {
        Some(Ok(ConnectionChange::Added(c))) => assert_eq!(
            c.id,
            ConnectionId("sentinel".into()),
            "no Updated may be emitted for a removed id"
        ),
        other => panic!("expected the sentinel Added first, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_hook_failure_parks_and_emits_once() {
    let set = Arc::new(ConnectionSet::new(ConnectionSetConfig {
        max_auth_attempts: 2,
        ..ConnectionSetConfig::default()
    }));
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    driver.on_authenticated_fails.store(true, Ordering::SeqCst);
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    let mut updates = set.subscribe();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(events.last(), Some(AuthEvent::Failed { .. })));
    let entry = set.entry(&id).unwrap();
    {
        let state = entry.state.lock();
        assert_eq!(state.attempts, 1, "the hook failure is counted once");
        assert_eq!(state.history.len(), 1, "the hook failure is recorded once");
        assert!(matches!(
            state.connection.auth_state,
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::BackendUnreachable,
                ..
            }
        ));
    }
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut updates)
        )
        .await,
        Ok(Some(Ok(ConnectionChange::Updated(_))))
    ));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            futures::StreamExt::next(&mut updates)
        )
        .await
        .is_err(),
        "the hook failure must not emit a duplicate update"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_persist_racing_removal_scrubs_and_deletes_orphan() {
    let store = Arc::new(Mutex::new(None));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("interactive-remove".into()));
    d.shared_secrets = Some(store.clone());
    d.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    d.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("winner")),
    })]);
    let persist_gate = Arc::new(tokio::sync::Notify::new());
    *d.persist_gate.lock() = Some(persist_gate.clone());
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let drain = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>());
    while driver.persist_calls.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    set.remove_connection(&id).await.unwrap();
    persist_gate.notify_one();
    let events = drain.await.unwrap().unwrap();

    assert!(matches!(
        events.last(),
        Some(AuthEvent::Failed { error }) if error.code() == ErrorCode::AuthCancelled
    ));
    assert!(
        store.lock().is_none(),
        "persistence completing after removal must delete its orphan"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_warm_continue_failure_does_not_purge_interactive_winner() {
    let store = Arc::new(Mutex::new(Some(named_bundle("old"))));
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("purge-fence".into()));
    d.shared_secrets = Some(store.clone());
    d.validate_delay = Duration::from_millis(100);
    d.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();

    driver.push_validate(Err(cred_error(ErrorCode::AuthExpired)));
    let bring_set = set.clone();
    let bring_id = id.clone();
    let bring = tokio::spawn(async move { bring_set.bring_up(&bring_id, true, None).await });
    while driver.validates() < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("winner")),
    })]);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert!(bring.await.unwrap().is_err());

    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("winner"),
        "a superseded failed grant must not delete the newer durable lineage"
    );
    assert_eq!(driver.deletes(), 0);
}

/// 3539559086: when `update_credentials` validates successfully but the
/// `on_authenticated` session-establishment hook fails, the surfaced error is
/// the HOOK's error (retryable) — not `AuthRequired`/"interactive sign-in
/// required", which would send rotation automation down a futile re-auth.
#[tokio::test]
async fn update_credentials_hook_failure_is_not_reported_as_auth_required() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    driver.on_authenticated_fails.store(true, Ordering::SeqCst);
    driver.push_validate(Ok(MockValidated::Authenticated {
        credentials: None,
        expires_at: None,
    }));
    let err = set
        .update_credentials(&id, oauth_bundle(None), None)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        ErrorCode::Internal,
        "the hook's own error surfaces (credentials were accepted), got {err:?}"
    );
    assert_ne!(err.code(), ErrorCode::AuthRequired);
}

/// 3539557932 (generic half): interactive success runs the `on_authenticated`
/// session-establishment hook — the extension point a layer uses to re-apply
/// credential-gated roots/routes after sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_success_runs_on_authenticated_hook() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // parked (no hook yet)
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    driver
        .on_authenticated_spawns_task
        .store(true, Ordering::SeqCst);
    assert_eq!(driver.on_authenticateds(), 0);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let _events = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        driver.on_authenticateds(),
        1,
        "interactive success must finish the session-establishment hook before forwarding"
    );
    let task = driver
        .on_authenticated_task
        .lock()
        .take()
        .expect("hook cached a runtime-owned task");
    assert!(
        !task.is_finished(),
        "the hook's runtime-owned resource must outlive the terminal event"
    );
    task.abort();
}

/// Finding 1: a completed interactive sign-in drained on a CURRENT-THREAD
/// runtime commits successfully — the freshly minted bundle is persisted and
/// installed, not dropped. (The regressed guard converted this into
/// `Failed(Internal)` and lost the bundle before it could persist.)
#[tokio::test]
async fn interactive_success_on_current_thread_commits_and_keeps_bundle() {
    let store = Arc::new(Mutex::new(None));
    let mut d = MockDriver::new();
    d.shared_secrets = Some(store.clone());
    d.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // parked
    d.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("fresh")),
    })]);
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    // Drain synchronously ON the current-thread test runtime (ambient current
    // thread); the commit must still progress on its own runtime.
    let events = stream.collect::<Result<Vec<_>>>().unwrap();
    assert!(
        matches!(
            events.last(),
            Some(AuthEvent::Succeeded {
                credentials: None,
                ..
            })
        ),
        "the terminal event is a scrubbed success, got {:?}",
        events.last()
    );
    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("fresh"),
        "the freshly minted bundle is persisted, not dropped"
    );
    let entry = set.entry(&id).unwrap();
    let state = entry.state.lock();
    assert!(matches!(
        state.connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(
        bundle_refresh(&state.credentials).as_deref(),
        Some("fresh"),
        "the committed live credentials are the interactive winner"
    );
}

/// Finding 1 (false-deadlock half): draining on a current-thread runtime while
/// the flow was created on a DIFFERENT multi-thread runtime is not a real
/// self-deadlock and must commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_success_drained_cross_runtime_commits() {
    let store = Arc::new(Mutex::new(None));
    let mut d = MockDriver::new();
    d.shared_secrets = Some(store.clone());
    d.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
    d.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("fresh")),
    })]);
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    // Flow created on THIS multi-thread runtime.
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    // Drain inside a distinct current-thread runtime, off a blocking thread so it
    // does not sit on this runtime's workers.
    let events = tokio::task::spawn_blocking(move || {
        let rt_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt_a.block_on(async move { stream.collect::<Result<Vec<_>>>() })
    })
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        events.last(),
        Some(AuthEvent::Succeeded {
            credentials: None,
            ..
        })
    ));
    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("fresh")
    );
}

/// Finding 2: the interactive commit progresses even when the thread draining
/// the stream has no ambient runtime (the natural blocking-iterator / sync-
/// wrapper pattern) and the flow's origin runtime sits idle. The commit runs on
/// its own runtime, so it completes rather than hanging forever.
#[test]
fn interactive_commit_progresses_when_origin_runtime_idle() {
    // A current-thread "app" runtime that goes idle the moment `authenticate`
    // returns — nothing drives it while the stream is drained.
    let app_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = Arc::new(Mutex::new(None));
    let (set, id, stream) = app_rt.block_on(async {
        let mut d = MockDriver::new();
        d.shared_secrets = Some(store.clone());
        d.push_validate(Err(cred_error(ErrorCode::AuthRequired)));
        d.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
            connection: Box::new(conn("c1")),
            credentials: Some(named_bundle("fresh")),
        })]);
        let driver = Arc::new(d);
        let set = set();
        let id = ConnectionId("c1".into());
        set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
            .await
            .unwrap();
        let stream = set
            .authenticate(&id, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap();
        (set, id, stream)
    });
    // Drain on a plain thread with NO ambient runtime, while `app_rt` is idle.
    // Watchdog: fail loudly instead of hanging the suite if the commit stalls.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(stream.collect::<Result<Vec<_>>>());
    });
    let events = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("interactive commit must not hang when the origin runtime is idle")
        .unwrap();
    assert!(matches!(
        events.last(),
        Some(AuthEvent::Succeeded {
            credentials: None,
            ..
        })
    ));
    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("fresh")
    );
    assert!(set.entry(&id).is_ok());
    drop(app_rt);
}

/// Finding 3: a removal that cancels a cancel-honoring `on_authenticated` hook
/// must NOT emit `Updated` for an id subscribers just saw `Removed`. Mirrors
/// `interactive_failed_after_remove_does_not_park_or_emit` for the hook path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_hook_cancelled_by_removal_does_not_emit_updated() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // parked (Added emitted)
    driver
        .on_authenticated_honors_cancel
        .store(true, Ordering::SeqCst);
    driver
        .interactive
        .lock()
        .replace(vec![Ok(AuthEvent::Succeeded {
            connection: Box::new(conn("c1")),
            credentials: Some(named_bundle("fresh")),
        })]);
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    // Subscribe AFTER Added(c1): the only c1 event we may see is Removed; any
    // Updated(c1) is the fence violation.
    let mut updates = set.subscribe();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let drain = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>());
    // Remove only once the hook is in flight (blocked on its cancel token).
    while driver.on_authenticated_entered.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    set.remove_connection(&id).await.unwrap();
    let events = drain.await.unwrap().unwrap();
    assert!(
        matches!(events.last(), Some(AuthEvent::Failed { .. })),
        "the cancelled hook surfaces a terminal Failed, got {:?}",
        events.last()
    );
    let mut saw_removed = false;
    while let Ok(Some(Ok(change))) = tokio::time::timeout(
        Duration::from_millis(200),
        futures::StreamExt::next(&mut updates),
    )
    .await
    {
        match change {
            ConnectionChange::Removed { id: rid } if rid == id => saw_removed = true,
            ConnectionChange::Updated(c) => panic!(
                "Updated emitted for {:?} after Removed (removed-connection fence violated)",
                c.id
            ),
            _ => {}
        }
    }
    assert!(saw_removed, "the removal must still emit Removed(c1)");
}

/// Finding 4: a NON-purging `unregister_connection` racing the awaited persist
/// preserves the durable head (the next warm continuation needs it); a purging
/// `remove_connection` still deletes the just-written orphan. Deletion follows
/// the remover's intent, not bare unregistration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_persist_racing_unregister_preserves_credential() {
    async fn race_persist_with_removal(purge: bool) -> Option<String> {
        let store = Arc::new(Mutex::new(None));
        let mut d = MockDriver::new();
        d.stable = Some(ConnectionId("interactive-unregister".into()));
        d.shared_secrets = Some(store.clone());
        d.push_validate(Ok(MockValidated::AwaitingInteractive {
            reason: AuthReason::NeverAuthenticated,
        }));
        d.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
            connection: Box::new(conn("c1")),
            credentials: Some(named_bundle("winner")),
        })]);
        let persist_gate = Arc::new(tokio::sync::Notify::new());
        *d.persist_gate.lock() = Some(persist_gate.clone());
        let driver = Arc::new(d);
        let set = set();
        let id = ConnectionId("c1".into());
        set.add_connection(conn("c1"), driver.clone(), SecretBundle::default(), None)
            .await
            .unwrap();
        let stream = set
            .authenticate(&id, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap();
        let drain = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>());
        while driver.persist_calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if purge {
            set.remove_connection(&id).await.unwrap();
        } else {
            set.unregister_connection(&id).await.unwrap();
        }
        persist_gate.notify_one();
        let events = drain.await.unwrap().unwrap();
        assert!(matches!(
            events.last(),
            Some(AuthEvent::Failed { error }) if error.code() == ErrorCode::AuthCancelled
        ));
        store.lock().as_ref().and_then(bundle_refresh)
    }

    assert_eq!(
        race_persist_with_removal(false).await.as_deref(),
        Some("winner"),
        "a non-purging unregistration must preserve the durable head"
    );
    assert_eq!(
        race_persist_with_removal(true).await,
        None,
        "a purging removal must delete the just-written orphan"
    );
}

// ---------------------------------------------------------------------------
// Deferred-announce two-phase commit (Added-after-route-install)
// ---------------------------------------------------------------------------

/// `add_connection_deferred` registers + validates but emits NO `Added`; the
/// deferred `Added` fires only at `announce_connection`, and a pre-announce
/// `set_addresses` is folded into it rather than emitting a premature
/// `Updated`-before-`Added`.
#[tokio::test]
async fn deferred_add_defers_added_until_announced() {
    let set = set();
    let mut updates = set.subscribe();
    set.add_connection_deferred(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    // Pre-announce: the layer publishes its route addresses. This must NOT emit
    // `Updated` (nothing has seen `Added` yet) — it rides the pending `Added`.
    let root = crate::Url::parse("mock://root/").unwrap();
    set.set_addresses(
        &ConnectionId("c1".into()),
        vec![root.clone()],
        Capabilities::empty(),
    );
    // Announce (route now installed). The FIRST event a subscriber sees is the
    // `Added`, carrying the pre-announce addresses — proving nothing leaked
    // before it.
    set.announce_connection(&ConnectionId("c1".into()));
    match updates.next().await {
        Some(Ok(ConnectionChange::Added(c))) => {
            assert_eq!(c.id, ConnectionId("c1".into()));
            assert_eq!(
                c.current_addresses,
                vec![root],
                "the deferred Added must carry the pre-announce set_addresses"
            );
        }
        other => panic!("expected Added(c1) first, got {other:?}"),
    }
}

/// A connection removed while still deferred was never visible to subscribers,
/// so it emits neither `Added` nor a paired `Removed` — closing the race
/// where a remove-on-`Added` consumer could act before route installation.
#[tokio::test]
async fn remove_before_announce_emits_no_events() {
    let set = set();
    let mut updates = set.subscribe();
    set.add_connection_deferred(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    set.remove_connection(&ConnectionId("c1".into()))
        .await
        .unwrap();
    // Sentinel: if the deferred c1 had emitted anything, it would arrive before
    // the sentinel's `Added`.
    set.add_connection(
        conn("sentinel"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    match updates.next().await {
        Some(Ok(ConnectionChange::Added(c))) => assert_eq!(
            c.id,
            ConnectionId("sentinel".into()),
            "a connection removed before announce must emit no Added/Removed"
        ),
        other => panic!("expected the sentinel Added first, got {other:?}"),
    }
}

/// The single-shot `add_connection` wrapper stays backward-compatible: it
/// announces immediately (emits `Added`), after which a `set_addresses` emits
/// `Updated` normally.
#[tokio::test]
async fn add_connection_wrapper_announces_immediately() {
    let set = set();
    let mut updates = set.subscribe();
    set.add_connection(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    assert!(
        matches!(updates.next().await, Some(Ok(ConnectionChange::Added(c))) if c.id == ConnectionId("c1".into())),
        "the wrapper must emit Added immediately"
    );
    // Announced → a later set_addresses emits Updated (suppression applies only while deferred).
    set.set_addresses(
        &ConnectionId("c1".into()),
        vec![crate::Url::parse("mock://root/").unwrap()],
        Capabilities::empty(),
    );
    assert!(
        matches!(updates.next().await, Some(Ok(ConnectionChange::Updated(_)))),
        "a post-announce set_addresses must emit Updated"
    );
}

/// A deferred connection is invisible to `list_connections` (the only
/// host-facing enumerator), so its id cannot leak pre-announce — closing the
/// snapshot side of the deferred-announce invariant. Internal routing (`connection()`) still
/// resolves it, and it becomes enumerable once announced.
#[tokio::test]
async fn deferred_connection_hidden_from_list_connections() {
    let set = set();
    set.add_connection_deferred(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    assert!(
        set.list_connections().connections.is_empty(),
        "a deferred connection must not be enumerable (no pre-announce id leak)"
    );
    // Internal routing can still resolve the (deferred) connection by id.
    assert!(set.connection(&ConnectionId("c1".into())).is_some());
    // Announcing makes it enumerable.
    set.announce_connection(&ConnectionId("c1".into()));
    let listed = set.list_connections().connections;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, ConnectionId("c1".into()));
}

/// The `Succeeded` event's `connection` payload must reflect the committed
/// post-transition view, not the driver's pre-transition clone. A driver seeds
/// the event from the connection captured at flow start (here `Anonymous`); the
/// adapter commits the authenticated transition, then must refresh the event's
/// connection from the entry so a consumer (e.g. an AliasWrapper projecting the
/// delegated connection) sees `Authenticated`, not the stale snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_succeeded_event_carries_committed_connection() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    driver.push_validate(Err(cred_error(ErrorCode::AuthRequired))); // start parked
    // The driver emits `Succeeded` carrying the pre-transition (Anonymous) clone.
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(oauth_bundle(None)),
    })]);
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let events: Vec<_> = stream.collect::<Result<Vec<_>>>().unwrap();
    let succeeded = events
        .iter()
        .find_map(|event| match event {
            AuthEvent::Succeeded { connection, .. } => Some(connection),
            _ => None,
        })
        .expect("a Succeeded event");
    assert!(
        matches!(
            succeeded.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "Succeeded event's connection must be the committed Authenticated view, got {:?}",
        succeeded.auth_state
    );
}

// ---------------------------------------------------------------------------
// Commit-ordered emission
// ---------------------------------------------------------------------------

/// Drain every `ConnectionChange` currently queued on `updates`.
async fn drain_changes(updates: &mut ConnectionUpdateStream) -> Vec<ConnectionChange> {
    let mut seen = Vec::new();
    while let Ok(Some(Ok(change))) = tokio::time::timeout(
        Duration::from_millis(200),
        futures::StreamExt::next(updates),
    )
    .await
    {
        seen.push(change);
    }
    seen
}

/// `announce_connection` and `remove_inner` must agree on whether a
/// connection was announced, or a subscriber is left holding a phantom.
///
/// The seam parks `announce_connection` once it has resolved the entry but
/// before it commits the announce decision, and the removal runs to completion
/// in that window. The announce decision and the unregistration are both
/// commits on the `entries` map, so they must serialize: the subscriber sees
/// `Added` then `Removed`, never an `Added` for a connection that is already
/// gone and for which no `Removed` will ever follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announce_racing_removal_never_strands_an_added() {
    let set = set();
    let id = ConnectionId("c1".into());
    let driver = Arc::new(MockDriver::new());
    set.add_connection_deferred(conn("c1"), driver, oauth_bundle(None), None)
        .await
        .unwrap();
    let mut updates = set.subscribe();

    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let resume_rx = Mutex::new(resume_rx);
    set.set_announce_seam(Arc::new(move || {
        reached_tx.send(()).expect("the test awaits the seam");
        // Bounded: when the announce decision is serialized against the
        // removal, the removal is parked behind the same guard and never
        // signals, so the announce completes on its own and the removal
        // follows it.
        let _ = resume_rx.lock().recv_timeout(Duration::from_secs(1));
    }));

    let announcer = {
        let set = set.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || set.announce_connection(&id))
    };
    reached_rx
        .recv()
        .expect("announce_connection reaches the seam");
    set.remove_connection(&id).await.unwrap();
    let _ = resume_tx.send(());
    announcer.await.unwrap();

    assert!(!set.is_registered(&id), "the removal unregistered c1");
    let seen = drain_changes(&mut updates).await;
    let for_c1: Vec<_> = seen
        .iter()
        .filter(|change| match change {
            ConnectionChange::Added(c) | ConnectionChange::Updated(c) => c.id == id,
            ConnectionChange::Removed { id: rid } => *rid == id,
            ConnectionChange::Snapshot(_) => false,
        })
        .collect();
    assert!(
        matches!(
            for_c1.as_slice(),
            [ConnectionChange::Added(c), ConnectionChange::Removed { id: rid }]
                if c.id == id && *rid == id
        ),
        "an Added racing the removal must be followed by its Removed, got {for_c1:?}"
    );
}

/// `Removed` reports the unregistration, which is committed the moment the
/// `entries` section ends — so it must reach subscribers there, not after the
/// durable credential purge that follows it. The purge does remote I/O; a
/// subscriber told only afterwards reads a set that no longer contains the
/// connection for the whole of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_is_emitted_at_the_commit_point_not_after_the_purge() {
    let mut d = MockDriver::new();
    d.stable = Some(ConnectionId("purge-fence".into()));
    let delete_gate = Arc::new(tokio::sync::Notify::new());
    *d.delete_gate.lock() = Some(delete_gate.clone());
    let driver = Arc::new(d);
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    let mut updates = set.subscribe();

    let removal = {
        let set = set.clone();
        let id = id.clone();
        tokio::spawn(async move { set.remove_connection(&id).await })
    };
    // Hold the durable purge open. The unregistration is already committed.
    // Spin on the purge being PARKED, not merely entered: `delete_calls` is
    // bumped before the gate, so entry alone would not prove the purge is still
    // in flight when the assertion below runs.
    while !driver.delete_is_parked() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !set.is_registered(&id),
        "the unregistration commits before the purge"
    );
    let seen = tokio::time::timeout(
        Duration::from_millis(500),
        futures::StreamExt::next(&mut updates),
    )
    .await
    .expect("Removed must not wait on the durable purge")
    .expect("the stream is live")
    .expect("no lag");
    assert!(
        matches!(&seen, ConnectionChange::Removed { id: rid } if *rid == id),
        "expected Removed(c1) while the purge is still in flight, got {seen:?}"
    );

    delete_gate.notify_one();
    removal.await.unwrap().unwrap();
}

/// A connection removed while a credential update is in flight must not then
/// emit `Updated`: subscribers already saw `Removed`, and nothing follows it, so
/// a consumer keyed by connection resurrects a dead entry permanently.
///
/// `commit_authenticated` already fences the state WRITE on registration, so the
/// grant's result is correctly discarded — but the emission reporting it has to
/// be fenced on the same guard, or the discarded grant still reaches subscribers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_credentials_racing_removal_emits_no_updated_after_removed() {
    let driver = Arc::new(MockDriver::new());
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), oauth_bundle(None), None)
        .await
        .unwrap();
    // Arm the gate only AFTER bring-up. Arming it earlier and releasing the
    // bring-up's own grant with `notify_one` would leave a stored permit behind
    // (`Notify` keeps one when nobody is waiting), and the update's grant would
    // consume it and never park — the race would go unexercised.
    let obtain_gate = Arc::new(tokio::sync::Notify::new());
    *driver.obtain_gate.lock() = Some(obtain_gate.clone());
    let mut updates = set.subscribe();

    let updater = {
        let set = set.clone();
        let id = id.clone();
        tokio::spawn(async move {
            set.update_credentials(&id, named_bundle("rotated"), None)
                .await
        })
    };
    // Spin until the grant is genuinely PARKED, not merely entered.
    while !driver.obtain_is_parked() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    set.remove_connection(&id).await.unwrap();
    assert!(
        driver.obtain_is_parked(),
        "the removal must land while the grant is still held open, or this test \
         is not exercising the update-vs-removal race"
    );
    obtain_gate.notify_one();
    let _ = updater.await.unwrap();

    let seen = drain_changes(&mut updates).await;
    let removed_at = seen
        .iter()
        .position(|change| matches!(change, ConnectionChange::Removed { .. }))
        .expect("the removal emits Removed(c1)");
    assert!(
        !seen
            .iter()
            .skip(removed_at)
            .any(|change| matches!(change, ConnectionChange::Updated(_))),
        "Updated emitted after Removed for a connection that is gone: {seen:?}"
    );
}

/// A queued interactive success must not overwrite the credentials a newer
/// commit already installed.
///
/// The flow is fenced before its terminal event is QUEUED, not when the
/// consumer drains it. Between those two points another commit can land on the
/// live cell — a second sign-in, or a rotation of the same identity, which by
/// design does not move `identity_gen`. Draining the older event then swaps the
/// connection's credentials back to a bundle the live cell no longer holds, and
/// the next refresh seeds its grant from exactly that bundle: a token the
/// provider's rotation has already consumed, replayed into its reuse detection.
///
/// The durable write refuses the stale bundle, but it cannot undo the in-memory
/// regression — which is why the compare has to happen at the commit too.
#[tokio::test]
async fn a_queued_interactive_success_does_not_regress_newer_credentials() {
    let set = set();
    let driver = Arc::new(MockDriver::new());
    let id = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver.clone(), named_bundle("r0"), None)
        .await
        .unwrap();

    // Flow A completes and its terminal event is queued, carrying A's bundle.
    *driver.interactive.lock() = Some(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("flow-a")),
    })]);
    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();

    // A newer commit lands on the live cell while A's event sits in the queue,
    // and takes the set-side credentials with it.
    driver.install_same_identity(&named_bundle("newer"));
    set.commit_interactive_credentials(&set.entry(&id).unwrap(), named_bundle("newer"), None);

    // A's event now drains.
    let _ = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>()).await;

    assert_eq!(
        bundle_refresh(&set.credentials(&id).unwrap()).as_deref(),
        Some("newer"),
        "the queued flow's bundle must not regress the credentials a newer \
         commit installed",
    );
}

/// A subscriber that reacts to `Removed` by re-registering the same
/// `ConnectionId` must not have its state destroyed by the removal's own tail.
///
/// Everything the removal cleans up after unregistering — the single-flight
/// bring-up lock, the cooldown, the generation counters — is keyed by `id`, not
/// by the entry. Publishing `Removed` before that cleanup makes the window
/// reachable from the event: the re-add installs a fresh single-flight mutex and
/// the removal then drops it from the map, so the NEXT grant for the re-added
/// connection takes a different mutex and no longer excludes the in-flight one.
/// Two concurrent grants on one rotating refresh token is the IdP
/// reuse-detection failure this module's rotation-safety discipline exists to
/// prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removal_tail_does_not_evict_a_re_added_connections_single_flight_lock() {
    let set = set();
    let id = ConnectionId("c1".into());
    set.add_connection(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();

    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let resume_rx = Mutex::new(resume_rx);
    set.set_remove_seam(Arc::new(move || {
        reached_tx.send(()).expect("the test awaits the seam");
        let _ = resume_rx.lock().recv_timeout(Duration::from_secs(5));
    }));

    let removal = {
        let set = set.clone();
        let id = id.clone();
        tokio::spawn(async move { set.remove_connection(&id).await })
    };
    reached_rx.recv().expect("remove_inner reaches the seam");

    // The subscriber's reaction: re-register the same id while the removal's
    // tail is still to run.
    set.add_connection_deferred(
        conn("c1"),
        Arc::new(MockDriver::new()),
        oauth_bundle(None),
        None,
    )
    .await
    .unwrap();
    let readded_lock = set.bringup_lock_for(&id);
    // The rationale covers the cooldown and generation counters too, not just
    // the single-flight lock, so pin those as well.
    set.set_cooldown(&id);
    set.record_bringup_outcome(&id, None);
    let readded_gen = set.bringup_gen(&id);

    let _ = resume_tx.send(());
    removal.await.unwrap().unwrap();

    assert!(
        Arc::ptr_eq(&readded_lock, &set.bringup_lock_for(&id)),
        "the removal's tail evicted the re-added connection's single-flight \
         lock, so its next grant would not exclude the in-flight one"
    );
    assert!(
        set.in_cooldown(&id),
        "the removal's tail wiped the re-added connection's failure cooldown"
    );
    assert_eq!(
        set.bringup_gen(&id),
        readded_gen,
        "the removal's tail reset the re-added connection's bring-up generation, \
         so a queued waiter would re-run validate instead of sharing the outcome"
    );
}

/// The durable purge is keyed by the driver's STABLE id, not by the connection,
/// so it must be serialized against a re-registration of that same identity.
///
/// `Removed` is published at the commit point; the purge that follows it runs
/// outside that section and awaits remote I/O. A subscriber reacting to
/// `Removed` by registering a connection that resolves to the SAME stable
/// credential key can therefore load or persist a credential that the outgoing
/// removal then deletes — destroying a live secret, not a stale one. The
/// membership decision taken inside the commit section is necessary but not
/// sufficient: it is stale by the time the delete actually fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removal_purge_does_not_delete_a_re_added_identitys_credential() {
    let stable = ConnectionId("shared-identity".into());
    let store = Arc::new(Mutex::new(Some(named_bundle("old"))));

    let mut d1 = MockDriver::new();
    d1.stable = Some(stable.clone());
    d1.shared_secrets = Some(store.clone());
    let delete_gate = Arc::new(tokio::sync::Notify::new());
    *d1.delete_gate.lock() = Some(delete_gate.clone());
    let driver1 = Arc::new(d1);

    let set = set();
    let id1 = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver1.clone(), oauth_bundle(None), None)
        .await
        .unwrap();

    // Purging removal: parks inside `delete_credentials`, holding the durable
    // secret for `shared-identity` open.
    let removal = {
        let set = set.clone();
        let id1 = id1.clone();
        tokio::spawn(async move { set.remove_connection(&id1).await })
    };
    while !driver1.delete_is_parked() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The subscriber's reaction: register a connection resolving to the SAME
    // stable credential key, and persist a credential under it.
    let mut d2 = MockDriver::new();
    d2.stable = Some(stable.clone());
    d2.shared_secrets = Some(store.clone());
    let driver2 = Arc::new(d2);
    let readd = {
        let set = set.clone();
        tokio::spawn(async move {
            set.add_connection(conn("c2"), driver2, named_bundle("new"), None)
                .await
        })
    };

    // Give the re-add every chance to land its credential BEFORE the purge
    // fires. Where the purge is serialized against registration the re-add is
    // parked here and this simply expires; where it is not, the new credential
    // lands and the outgoing purge then destroys it.
    let landed_before_delete = tokio::time::timeout(Duration::from_secs(1), async {
        while bundle_refresh(store.lock().as_ref().unwrap()).as_deref() != Some("new") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();

    delete_gate.notify_one();
    removal.await.unwrap().unwrap();
    readd.await.unwrap().unwrap();

    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("new"),
        "the outgoing removal's purge deleted the credential the re-added \
         identity had already persisted (re-add landed before the delete: \
         {landed_before_delete})"
    );
    // Whichever way the two serialized, the re-add's credential is the one that
    // survives; record which order actually ran so a green result cannot hide
    // the registration simply never having been scheduled.
    assert!(
        set.credentials(&ConnectionId("c2".into())).is_some(),
        "the re-added connection must be registered with its credentials \
         (landed before delete: {landed_before_delete})"
    );
}

/// The orphan-cleanup paths delete the same stable-id-keyed secret as
/// `remove_inner`, so they need the same serialization.
///
/// This drives the interactive-commit orphan delete: a sign-in whose persist
/// lands after its connection was removed writes a durable head, then deletes it
/// as an orphan. That delete is awaited, so a registration resolving to the same
/// stable identity can land between the shared-identity check and the delete —
/// and lose the credential it just persisted. Guarding only `remove_inner`
/// leaves this reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_orphan_delete_does_not_destroy_a_re_added_identitys_credential() {
    let stable = ConnectionId("shared-identity".into());
    let store = Arc::new(Mutex::new(None));

    let mut d1 = MockDriver::new();
    d1.stable = Some(stable.clone());
    d1.shared_secrets = Some(store.clone());
    d1.push_validate(Ok(MockValidated::AwaitingInteractive {
        reason: AuthReason::NeverAuthenticated,
    }));
    d1.interactive.lock().replace(vec![Ok(AuthEvent::Succeeded {
        connection: Box::new(conn("c1")),
        credentials: Some(named_bundle("orphan")),
    })]);
    let persist_gate = Arc::new(tokio::sync::Notify::new());
    *d1.persist_gate.lock() = Some(persist_gate.clone());
    let driver1 = Arc::new(d1);

    let set = set();
    let id1 = ConnectionId("c1".into());
    set.add_connection(conn("c1"), driver1.clone(), SecretBundle::default(), None)
        .await
        .unwrap();
    let stream = set
        .authenticate(&id1, InteractiveAuthCapability::Browser, None)
        .await
        .unwrap();
    let drain = tokio::task::spawn_blocking(move || stream.collect::<Result<Vec<_>>>());
    while driver1.persist_calls.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Purging removal while the sign-in's persist is parked. Its own purge runs
    // (and finds nothing) before the gate below is armed, so only the interactive
    // orphan delete parks.
    set.remove_connection(&id1).await.unwrap();

    let delete_gate = Arc::new(tokio::sync::Notify::new());
    *driver1.delete_gate.lock() = Some(delete_gate.clone());
    // The parked persist now writes its orphan and moves to delete it.
    persist_gate.notify_one();
    while !driver1.delete_is_parked() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // A registration resolving to the SAME stable identity, under a different
    // connection id, lands while that orphan delete is in flight.
    let mut d2 = MockDriver::new();
    d2.stable = Some(stable.clone());
    d2.shared_secrets = Some(store.clone());
    let readd = {
        let set = set.clone();
        tokio::spawn(async move {
            set.add_connection(conn("c2"), Arc::new(d2), named_bundle("new"), None)
                .await
        })
    };
    let landed_before_delete = tokio::time::timeout(Duration::from_secs(1), async {
        while store.lock().as_ref().and_then(bundle_refresh).as_deref() != Some("new") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();

    delete_gate.notify_one();
    let _ = drain.await.unwrap();
    readd.await.unwrap().unwrap();

    assert_eq!(
        store.lock().as_ref().and_then(bundle_refresh).as_deref(),
        Some("new"),
        "the interactive orphan delete destroyed the re-added identity's \
         credential (re-add landed before the delete: {landed_before_delete})"
    );
}

/// Every durable-credential delete must go through
/// [`ConnectionSet::purge_durable_credential`], which holds the stable
/// identity's lock across the orphan check and the delete.
///
/// This is a source guard rather than a type gate because `entry.driver` is
/// reachable throughout the module and the verbs are plain trait methods, so
/// nothing in the type system stops a bare call. The invariant recurred at six
/// sites over three review rounds — each fix addressed the sites named rather
/// than the shape — so it is enforced mechanically here: a new bare call fails
/// this test with instructions instead of shipping as the seventh instance.
#[test]
fn every_durable_credential_delete_goes_through_the_chokepoint() {
    const SENTINEL: &str = "// purge-chokepoint";
    let source = include_str!("../set.rs");

    let offenders: Vec<_> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            line.contains(".delete_credentials()") || line.contains(".purge_credentials()")
        })
        .filter(|(_, line)| !line.trim_end().ends_with(SENTINEL))
        .map(|(n, line)| format!("  set.rs:{}: {}", n + 1, line.trim()))
        .collect();

    assert!(
        offenders.is_empty(),
        "durable credential deletes must be routed through \
         `ConnectionSet::purge_durable_credential`, which serializes the orphan \
         check and the delete against a registration of the same stable id. \
         A bare call here deletes a live connection's credential when a \
         registration lands in that window.\n\
         Offending call sites:\n{}\n\
         If this really is the chokepoint itself, mark the line `{SENTINEL}`.",
        offenders.join("\n"),
    );

    // The chokepoint itself must still exist, or the check above passes for the
    // wrong reason once every call site is gone.
    let marked = source
        .lines()
        .filter(|line| line.trim_end().ends_with(SENTINEL))
        .count();
    assert_eq!(
        marked, 2,
        "expected exactly the chokepoint's two marked verbs (delete + purge)"
    );
}
