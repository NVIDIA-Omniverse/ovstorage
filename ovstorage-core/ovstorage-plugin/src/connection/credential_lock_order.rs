// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The regression harnesses for the credential lock order: publication lock
//! FIRST, before every credential guard.
//!
//! Two OAuth driver crates — `ovstorage-plugin-broker` and
//! `ovstorage-plugin-services-client` — keep the same credential-state shape: a
//! set of credential guards, and a `std::sync::Mutex<()>` publication lock that
//! serializes a durable store write against an identity-changing install. The
//! rule that keeps those two out of a cycle is a property of the SHAPE, so the
//! tests that hold the rule live here rather than once per crate: a fix or an
//! extension made in one place is made for both, which byte-identical copies
//! could only achieve in lockstep.
//!
//! What a subject supplies is small on purpose. [`PublicationLockHolder`] is
//! the whole shared vocabulary — a cloneable handle that can hand out its
//! publication lock — and everything a harness must do to a subject beyond that
//! (construct one, run the install site under test, run the racing credential
//! update, read the request path) arrives as a closure. Neither crate's
//! `DiscoveryState` is named here, so neither can drift into being the shape
//! the harness assumes.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A credential state that publishes its publication lock.
///
/// `Clone` because every harness hands a handle to a thread of its own, and the
/// real states are `Arc`-backed: two clones share one lock, which is what makes
/// the contention reproducible at all.
pub trait PublicationLockHolder: Clone + Send + 'static {
    /// The lock a durable credential write holds across its secret store round
    /// trip, and which every install site must take BEFORE any credential
    /// guard.
    fn publication_lock(&self) -> &std::sync::Mutex<()>;
}

/// Stand-in for a durable store write, which is what the publication lock
/// exists to serialize. `oauth_secret_store::persist_current_lineage` and
/// `write_leased_refresh_token` hold that lock across a full secret store
/// round trip (DBus, Keychain, the Windows credential manager), which the
/// driver crates' lock-order docs record as taking seconds. This holds the same
/// lock, on a thread of its own, for exactly as long as the test says — the
/// "blocks on command" without which the contention under test is never
/// reproduced.
pub struct SecretPersistInFlight {
    release: Option<std::sync::mpsc::Sender<()>>,
    exited: Option<std::sync::mpsc::Receiver<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// How long either side of the stub's handshake may take before the harness
/// calls it a failure. Generous relative to a lock acquisition and a thread
/// exit, and the same order as the per-round wedge deadline below.
///
/// cbindgen:ignore
///
/// The ignore is required, not tidiness: cbindgen parses every source in the
/// crate regardless of `cfg`, so it reaches this test-only module and reports
/// a diagnostic for a top-level const it cannot emit. The header gate treats
/// any cbindgen diagnostic as an error. Making the const `pub` does not help
/// and makes it worse — cbindgen then tries to evaluate it and fails on
/// `Duration::from_secs(10)` as an unsupported call expression.
const STUB_DEADLINE: Duration = Duration::from_secs(10);

impl SecretPersistInFlight {
    /// Returns once the stub is provably holding the publication lock.
    ///
    /// Both waits here are deadlined for the same reason the per-round wedge
    /// check below is: an unbounded wait in a harness whose whole subject is
    /// lock order turns the exact defect it hunts into a test binary that
    /// never exits, and a CI job that burns its timeout says far less than a
    /// named panic.
    pub fn start<S: PublicationLockHolder>(state: &S) -> Self {
        let state = state.clone();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _publishing = state
                .publication_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = holding_tx.send(());
            let _ = release_rx.recv();
            drop(_publishing);
            let _ = exited_tx.send(());
        });
        holding_rx
            .recv_timeout(STUB_DEADLINE)
            .expect("keyring stub never took the publication lock");
        Self {
            release: Some(release_tx),
            exited: Some(exited_rx),
            thread: Some(thread),
        }
    }

    /// End the round trip and drop the publication lock.
    pub fn finish(mut self) {
        drop(self.release.take());
        if let Some(exited) = self.exited.take() {
            exited
                .recv_timeout(STUB_DEADLINE)
                .expect("keyring stub never released the publication lock");
        }
        if let Some(thread) = self.thread.take() {
            // The stub signalled that it is past its last blocking wait, so
            // this join is bounded by thread teardown alone.
            thread.join().expect("keyring stub thread");
        }
    }
}

/// Run a credential write on a detached OS thread, bumping `done` when it
/// returns.
///
/// Detached, and NOT a tokio task, on purpose: a half-applied hoist wedges
/// these permanently, and a wedged tokio worker hangs the whole test binary
/// at runtime shutdown instead of reporting a failure.
pub fn race_thread(done: &Arc<AtomicUsize>, work: impl Future<Output = ()> + Send + 'static) {
    let done = Arc::clone(done);
    std::thread::spawn(move || {
        futures::executor::block_on(work);
        done.fetch_add(1, Ordering::SeqCst);
    });
}

/// The failure the lock hoist could INTRODUCE. Hoisting the publication lock
/// above the credential guards at only SOME install sites leaves two
/// synchronous, non-reentrant locks acquired in opposite orders:
///
/// ```text
/// T1 (token install, hoisted):  publication        -> blocks on client_credentials
/// T2 (credential update, not):  client_credentials -> blocks on publication
/// ```
///
/// The compiler cannot see it — a `parking_lot` guard held across a
/// `std::sync::Mutex::lock()` is legal Rust — so this races the two writers
/// behind an in-flight secret persist, repeatedly, under a deadline. With
/// a half-applied hoist a round wedges permanently within a few iterations;
/// with the hoist applied at every site the cycle does not exist and no
/// round can wedge.
///
/// `site` names the install site under test, for the failure message.
/// `new_state` builds a fresh subject per round and reports the identity
/// generation to fence the install on — the two together, because reading the
/// generation is the caller's vocabulary, not this module's. `install` is the
/// site under test; `update` is the racing writer, the site that takes a
/// credential guard on its own.
pub fn assert_install_racing_a_credential_update_cannot_deadlock<S, N, I, IFut, U, UFut>(
    site: &str,
    new_state: N,
    install: I,
    update: U,
) where
    S: PublicationLockHolder,
    N: Fn() -> (S, u64),
    I: Fn(S, u64) -> IFut + Send + Sync + 'static,
    IFut: Future<Output = ()> + Send + 'static,
    U: Fn(S) -> UFut + Send + Sync + 'static,
    UFut: Future<Output = ()> + Send + 'static,
{
    let install = Arc::new(install);
    let update = Arc::new(update);
    for round in 0..200 {
        let (state, expected_identity_gen) = new_state();
        let done = Arc::new(AtomicUsize::new(0));
        // Both writers pile up behind a secret-store round trip; releasing it is
        // what starts the race.
        let persisting = SecretPersistInFlight::start(&state);
        race_thread(&done, {
            let state = state.clone();
            let install = Arc::clone(&install);
            async move { install(state, expected_identity_gen).await }
        });
        race_thread(&done, {
            let state = state.clone();
            let update = Arc::clone(&update);
            async move { update(state).await }
        });
        std::thread::sleep(Duration::from_millis(5));
        persisting.finish();

        let deadline = Instant::now() + Duration::from_secs(10);
        while done.load(Ordering::SeqCst) < 2 {
            assert!(
                Instant::now() < deadline,
                "round {round}: `{site}` and a credential update deadlocked. \
                 EVERY install site must take the publication lock BEFORE the \
                 credential guards — see the crate's credential lock order",
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// What the request path must still see while a secret persist holds the
/// publication lock: the bearer it was serving on, and a silent grant.
///
/// One observation rather than two reads, because the two are read together at
/// each sample and a driver that loses either has the same symptom.
pub struct RequestPathObservation {
    /// The `authorization` header the transport interceptor emits, if any.
    pub bearer: Option<String>,
    /// Whether the driver reports a grant it can replay without a prompt.
    pub has_silent_grant: bool,
}

/// The defect this ordering exists to prevent. While a secret persist holds the
/// publication lock, an install must not be sitting on the credential cells
/// waiting for it: the tonic interceptor reads the access token with `try_read`
/// and silently emits NO bearer on a miss, so every RPC comes back
/// UNAUTHENTICATED, and `classify`'s `has_silent_grant` — also a `try_read` —
/// then reports `false`, which routes the user to an interactive sign-in prompt
/// instead of a silent refresh.
///
/// Mutant: move `publication.lock()` back BELOW the credential `.write()`
/// acquisitions in the token-install core. The bearer disappears and
/// `has_silent_grant` goes false for the whole secret-store round trip.
///
/// The subject arrives already seeded with the live credential; `observe`
/// samples the request path, and `identity_changing_install` is the write that
/// arrives mid-persist and blocks. Returns once that install has completed, so
/// the caller can assert what it landed.
pub fn assert_a_keyring_persist_leaves_the_request_path_intact<S, I, IFut>(
    state: &S,
    expected_bearer: &str,
    observe: impl Fn() -> RequestPathObservation,
    identity_changing_install: I,
) where
    S: PublicationLockHolder,
    I: FnOnce(S) -> IFut,
    IFut: Future<Output = ()> + Send + 'static,
{
    let persisting = SecretPersistInFlight::start(state);
    // An identity-changing install arrives mid-persist and blocks.
    let installed = Arc::new(AtomicUsize::new(0));
    race_thread(&installed, identity_changing_install(state.clone()));

    // Sample the request path throughout the round trip rather than once,
    // so the assertion does not hinge on catching the blocked install at
    // one particular instant.
    for sample in 0..100 {
        let observed = observe();
        assert_eq!(
            observed.bearer.as_deref(),
            Some(expected_bearer),
            "sample {sample}: an in-flight secret persist must not strip the \
             bearer — an install blocked on the publication lock must not be \
             holding the access-token cell",
        );
        assert!(
            observed.has_silent_grant,
            "sample {sample}: an in-flight secret persist must not hide the \
             silent grant — that is what downgrades a background refresh into \
             an interactive sign-in prompt",
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    persisting.finish();
    let deadline = Instant::now() + Duration::from_secs(10);
    while installed.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the blocked install never completed once the persist finished",
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
