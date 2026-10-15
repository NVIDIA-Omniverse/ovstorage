// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bookkeeping behind promoting a parked connection on an operation its
//! provider demonstrably accepted.
//!
//! [`ConnectionSet::with_recovery_promoting_if`] and
//! [`ConnectionSet::with_promotion_if`] take a predicate and act on it. This
//! module is what a connection-owning layer builds that predicate OUT of: a
//! per-operation acceptance sink, a per-connection refusal epoch, and the
//! status set that says a request was authenticated and routed.
//!
//! It is not the whole predicate. Every adopter conjoins at least one clause
//! this module knows nothing about — that the backend instance which ran the
//! operation is still installed, and on GCS and Azure that the IdP has not
//! refused the credential's most recent grant.
//!
//! [`ConnectionSet::with_recovery_promoting_if`]: super::ConnectionSet::with_recovery_promoting_if
//! [`ConnectionSet::with_promotion_if`]: super::ConnectionSet::with_promotion_if
//!
//! # The two halves are scoped differently, and the asymmetry is the design
//!
//! **Acceptance is per-operation**, recorded in a task-local sink the layer
//! installs around the operation. One backend serves every caller of a
//! connection, and under the broker those are unrelated remote callers; a
//! connection-wide tally would let a caller whose own operation never reached
//! the provider — a `read` that only mints a signed URL — be vindicated by a
//! neighbour's request.
//!
//! **Refusal is per-connection**, in a [`RefusalEpoch`], because the credential
//! is one object and a refusal answered to anyone condemns it for everyone. It
//! is an epoch rather than a tally because the question is "did a refusal land
//! while my operation ran?", which a witness answers by snapshotting it and
//! requiring it unchanged. Being connection-wide it also catches the refusal a
//! CONCURRENT operation heard, which a per-operation sink discards by
//! construction — and any refusal belonging to no operation at all that the
//! plugin chooses to route into it.
//!
//! # What is here and what is not
//!
//! The mechanism, and one judgment the current adopters happen to agree on.
//!
//! Almost every judgment about what a particular provider's response MEANS
//! stays in that provider's plugin, because the adopters do not agree and
//! making them agree would change when connections promote. S3 vetoes a
//! promotion on any `400`, `401` or `403` read from the status line alone,
//! because its error code rides in a body the judgment cannot wait for; GCS
//! vetoes only on `401`, because its status mapping makes `403` mean
//! "identified, then scoped"; Azure vetoes on a `401`, on an
//! `x-ms-error-code` naming a refused credential whatever status carries it,
//! and on any `403` that is not an affirmative authorization-scope verdict —
//! except on a best-effort request whose failure the caller ignores, where it
//! narrows to the credential-rejection rule alone. Each asks for a different
//! origin header, and the three treat redirects differently — S3 needs no rule
//! at all, because its transport does not follow them.
//!
//! [`status_is_routed_verdict`] is the exception, and it is worth being precise
//! about what kind of exception it is: it is **shared policy, not mechanism**.
//! It lives here because the three adopters require the same set, and because a
//! second copy of a set they all require drifts silently — a correction applied
//! to one copy and not the others is invisible to every test, since each copy
//! has only its own. What the module offers is therefore that these adopters
//! agree, not that the set is a property of storage providers in general: a
//! fourth adopter owes it a check rather than an assumption.
//!
//! # What an adopter supplies
//!
//! Nothing here promotes anything on its own. A plugin adopting it owes six
//! things, and this module decides none of them:
//!
//! 1. **A `tokio::task_local!` and an [`EvidenceScope`] naming it.** One slot
//!    per plugin; [`EvidenceScope`] says why it cannot be shared. Declare one
//!    scope type and keep it crate-private, which is what makes a foreign
//!    scope unnameable from anywhere else rather than merely unconventional.
//! 2. **A wrap at the operation boundary** — [`with_operation_evidence`] around
//!    whatever the layer treats as one operation. Omitting it is the wiring bug
//!    [`OperationEvidence::require_installed`] exists to make loud.
//! 3. **A credit point on the response path** — [`credit_operation_acceptance`]
//!    where the plugin sees a response its acceptance predicate approves. Where
//!    that sits is a property of the plugin's transport rather than of this
//!    module: it is an SDK interceptor in one adopter and the transport's own
//!    response path in the other two, and a transport a plugin deliberately
//!    leaves uninstrumented contributes evidence in neither direction.
//! 4. **An acceptance predicate.** [`status_is_routed_verdict`] is at most one
//!    conjunct of it: every adopter also asks for its own origin header. Two of
//!    the three additionally judge redirects, and that judgment belongs to
//!    neither predicate — a response fetched after a disqualifying hop is
//!    evidence in NEITHER direction, so it must skip the veto as well as the
//!    credit.
//! 5. **A veto predicate, and the [`RefusalEpoch`] bumps that feed it** — which
//!    responses condemn the credential, and which of the plugin's transports may
//!    condemn it.
//! 6. **The clauses this module cannot see** — that the backend instance which
//!    ran the operation is still installed, and any IdP-refusal latch the
//!    plugin's authenticator carries. The latch is a flag its authenticator
//!    sets when the IdP refuses a grant and clears on the next grant it
//!    accepts; a [`RefusalEpoch`] cannot stand in for it, because that refusal
//!    is answered by the IdP rather than by storage and advances no storage
//!    epoch however it overlaps an operation in time.
//!
//! A best-effort request — one that provokes an answer rather than earning it,
//! or one whose failure its caller ignores — wants a carve-out, and the two
//! adopters that have one carve in OPPOSITE directions. S3 suppresses the
//! acceptance while every refusal still counts, because a `200` answering its
//! probe's own question vindicates nothing. Azure keeps the acceptance and
//! narrows the veto instead, because the refusals it would otherwise count are
//! ambiguous enough to starve promotion outright. Which trade a new adopter
//! wants follows from what its own probe asks, and this module takes no
//! position.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// How many of one operation's OWN requests the provider demonstrably
/// processed.
///
/// Refusal is NOT recorded here; it belongs to the connection's
/// [`RefusalEpoch`]. See the module header for why the two are scoped
/// differently.
#[derive(Debug, Default)]
pub struct OperationEvidence {
    accepted: AtomicU64,
    /// Set once the sink has actually been installed around an operation.
    ///
    /// The obligation is in two parts — build the evidence before the operation
    /// and wrap the operation in [`with_operation_evidence`] — and only the
    /// first is structural. A call site that builds the evidence and forgets to
    /// wrap compiles and records nothing, so its connection stays parked
    /// however well its operations go — and it fails no test unless that slot
    /// has a promotion test of its own. This flag is what makes it fail loudly
    /// instead: see [`Self::require_installed`].
    installed: AtomicBool,
}

impl OperationEvidence {
    /// Whether a request this operation made was answered in a way only a
    /// credential the provider accepted could have produced. The refusal half
    /// of the question is [`RefusalEpoch`].
    pub fn saw_acceptance(&self) -> bool {
        self.accepted.load(Ordering::Relaxed) > 0
    }

    /// Whether this sink was ever installed around an operation.
    pub fn was_installed(&self) -> bool {
        self.installed.load(Ordering::Relaxed)
    }

    /// Whether this evidence may be judged at all — that is, whether the sink
    /// was installed around the operation that is now being judged.
    ///
    /// A caller that never wrapped its operation has recorded nothing, so
    /// reading its evidence would answer "no acceptance" for ever and park a
    /// connection whose credential works. That is a wiring bug rather than a
    /// verdict, so it is made loud: debug builds assert on the first operation
    /// through that slot, release builds log and decline to promote.
    ///
    /// `plugin` labels the log line. Callers pass their own plugin name, since
    /// the operator reading it needs to know which layer is miswired.
    ///
    /// The assertion is compiled against THIS crate's `debug_assertions`, not
    /// the caller's. A build that turns them on per package — which this
    /// workspace does not do — would need `ovstorage-plugin` in that set for a
    /// miswired layer to panic rather than only log.
    ///
    /// Calling this is a convention, not an obligation the types impose. An
    /// adopter that skips it still declines to promote, because an unscoped
    /// sink saw no acceptance; what it loses is being told why.
    pub fn require_installed(&self, plugin: &'static str) -> bool {
        debug_assert!(
            self.was_installed(),
            "{plugin}: the promotion evidence sink was never installed around \
             the operation; its requests recorded nothing, so this operation \
             cannot promote its connection. Wrap the operation in \
             `with_operation_evidence`."
        );
        self.installed_or_declined(plugin)
    }

    /// The verdict [`Self::require_installed`] returns once its assertion has
    /// had its say.
    ///
    /// Separate from it so the declining path is reachable from a test: in a
    /// debug build the `debug_assert!` panics first, so a test that went
    /// through `require_installed` could only ever exercise the arm that
    /// promotes — and the other arm is the one release builds take.
    fn installed_or_declined(&self, plugin: &'static str) -> bool {
        if !self.was_installed() {
            tracing::error!(
                plugin,
                "promotion evidence was never installed around the operation; \
                 refusing to promote. Wrap the operation in \
                 `with_operation_evidence`."
            );
            return false;
        }
        true
    }

    /// Record that a request belonging to this operation was accepted.
    fn record_acceptance(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bumped when the provider refuses this connection's CREDENTIAL on a request
/// this process made.
///
/// Cloneable, so one connection can hand the same epoch to every transport
/// whose refusals should condemn its credential. WHICH transports those are is
/// the plugin's decision and not this type's: the S3 plugin deliberately leaves
/// its SQS watch client out, so a watch-only connection contributes evidence in
/// neither direction.
///
/// `Relaxed` is the honest ordering, not a shortcut. The proof depends on the
/// value of this one atomic and on nothing it publishes, and a refusal on
/// another task has no happens-before with the operation reading it, so no
/// stronger ordering would make the two indivisible. Single-location
/// modification order is total, which is all the comparison needs.
#[derive(Clone, Debug, Default)]
pub struct RefusalEpoch(Arc<AtomicU64>);

impl RefusalEpoch {
    /// The current epoch. A witness snapshots this before its operation and
    /// requires it unchanged after.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Record that the provider refused this connection's credential.
    ///
    /// Public because a plugin's transports live in its own crate, which also
    /// means this type imposes no chokepoint: any code holding a clone can
    /// advance the epoch. Deciding which refusals count is the plugin's job, and
    /// each of the three adopters gives this method exactly one call site — a
    /// `note_refusal` shim in two of them, the sole response interceptor in the
    /// third. That is one call site, not one refusal SOURCE: Azure routes both
    /// its storage responses and its IdP grant failures through the same shim.
    /// Keep that shape, because it is what makes "which of this plugin's
    /// transports condemn its credential" answerable by reading one function
    /// rather than every caller.
    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// The status set the S3, GCS and Azure plugins agree marks a verdict their
/// provider could only have reached by authenticating the request and routing
/// it: the request ran, or it was answered by a conflict, a precondition or a
/// range.
///
/// **This is shared policy, not a universal truth about storage providers.** It
/// is one function because those three adopters require the same set, and
/// because a set they all require is exactly the kind that drifts silently when
/// it is copied: each copy is covered only by its own plugin's tests, so a
/// correction applied to one and not the others fails nothing. A new adopter
/// owes this a check against its own provider — a gateway that can answer `409`
/// before authenticating, or a provider that reaches none of these three codes
/// after routing, wants its own predicate rather than this one.
///
/// This is the ACCEPTANCE half of the judgment and it is deliberately strict —
/// the mirror image of the lenient rule the drivers' `verify` parks on. A
/// `429`, a `5xx`, or a request rejected before anything looked at the
/// credential says nothing about that credential.
///
/// It is not the negation of any plugin's veto predicate, and collapsing the
/// two would be wrong: they are duals with opposite biases. `verify` asks
/// whether the credential was REFUTED and is lenient, so an outage leaves a
/// connection usable. This asks whether it was PROVEN.
///
/// **404 is deliberately NOT among them**, though it looks like it belongs, and
/// the route by which it goes wrong is worth stating exactly, because the
/// obvious one is not it: a 404 probe does not park a connection — every driver
/// here treats a non-credential failure as a lenient PASS. The route is a
/// connection parked for a real reason, whose bucket or container is then
/// deleted or renamed. Every subsequent operation 404s without the credential
/// deciding anything, and a credential revoked months ago would report
/// `Authenticated` with no path back. Losing 404 costs a workload made entirely
/// of missing-object lookups its promotion, which the next operation that finds
/// something repairs.
///
/// This is the whole of what the three cloud plugins share on the acceptance
/// side. Each still asks for its own origin header, and two of the three apply
/// a redirect rule as well. Where those sit relative to this call is each
/// plugin's own decision and is load-bearing for them: S3 asks its origin gate
/// first, GCS asks this first so that an unstamped `500` does not spend its
/// one-per-connection origin warning, and Azure asks its credential-rejection
/// check first.
pub fn status_is_routed_verdict(status: u16) -> bool {
    match status {
        // The provider ran the request.
        200..=299 => true,
        // Verdicts only reachable once a request is authenticated and routed:
        // a conflict, a precondition, a range.
        409 | 412 | 416 => true,
        _ => false,
    }
}

/// A plugin's own acceptance sink.
///
/// Implemented by a zero-sized type per plugin over a `tokio::task_local!` the
/// PLUGIN declares. The task-local deliberately does not live here: one shared
/// slot would put every plugin's operations in the same scope, so a request
/// issued by one plugin inside another plugin's operation would credit that
/// other operation's evidence — promoting a connection on a response its own
/// provider never sent — and a nested scope would shadow the outer one, so a
/// credit the outer operation earned would reach the inner sink instead.
/// `tokio::task_local!` cannot be generic, so the isolation is kept by naming
/// one slot per plugin here instead.
pub trait EvidenceScope: 'static {
    /// The task-local slot holding this plugin's current operation sink.
    fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>>;
}

/// Run `future` with `evidence` installed as `S`'s current operation sink.
pub async fn with_operation_evidence<S, F>(evidence: Arc<OperationEvidence>, future: F) -> F::Output
where
    S: EvidenceScope,
    F: Future,
{
    evidence.installed.store(true, Ordering::Relaxed);
    S::sink().scope(evidence, future).await
}

/// Credit an acceptance to the `S` operation running on this task, if any.
///
/// Work that belongs to no operation — a watch poller, a background token
/// refresh — credits nothing, and an acceptance recorded nowhere vindicates
/// nobody. Refusals are not routed through here at all: the ones a plugin
/// counts go to the connection-wide [`RefusalEpoch`] instead, so a refusal this
/// task-local would have dropped still vetoes. Which refusals a plugin counts
/// is its own decision — S3's SQS poller and GCS's Pub/Sub transport route none,
/// and a response fetched after a disqualifying redirect is evidence in neither
/// direction.
pub fn credit_operation_acceptance<S: EvidenceScope>() {
    let _ = S::sink().try_with(|evidence| evidence.record_acceptance());
}

#[cfg(test)]
mod tests {
    use super::*;

    tokio::task_local! {
        static TEST_SINK: Arc<OperationEvidence>;
        static OTHER_SINK: Arc<OperationEvidence>;
    }

    struct TestScope;
    impl EvidenceScope for TestScope {
        fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>> {
            &TEST_SINK
        }
    }

    struct OtherScope;
    impl EvidenceScope for OtherScope {
        fn sink() -> &'static tokio::task::LocalKey<Arc<OperationEvidence>> {
            &OTHER_SINK
        }
    }

    /// Acceptance is scoped to the operation that earned it, which is the whole
    /// reason the sink is a task-local rather than connection state.
    ///
    /// Asserted on the sinks directly: an accepted neighbour would promote the
    /// connection either way, so no connection-state assertion can tell a
    /// per-operation sink from a connection-wide tally.
    #[tokio::test(flavor = "multi_thread")]
    async fn acceptance_does_not_cross_between_operations() {
        let earner = Arc::new(OperationEvidence::default());
        let neighbour = Arc::new(OperationEvidence::default());

        // Separate TASKS, not `join!` on one: the sink is a task-local, so two
        // futures interleaved on a single task would not exercise the isolation
        // this claims to pin.
        let earning = tokio::spawn(with_operation_evidence::<TestScope, _>(
            earner.clone(),
            async {
                tokio::task::yield_now().await;
                credit_operation_acceptance::<TestScope>();
            },
        ));
        let neighbouring = tokio::spawn(with_operation_evidence::<TestScope, _>(
            neighbour.clone(),
            async {
                tokio::task::yield_now().await;
                tokio::task::yield_now().await;
            },
        ));
        earning.await.expect("the earner joins");
        neighbouring.await.expect("the neighbour joins");

        assert!(
            earner.saw_acceptance(),
            "control: the operation that made the request recorded it"
        );
        assert!(
            !neighbour.saw_acceptance(),
            "an operation that reached no request must not be vindicated by \
             its neighbour's"
        );
    }

    /// The property [`EvidenceScope`] exists for: one plugin's acceptance must
    /// not credit another plugin's operation, however the two nest.
    ///
    /// The inner credit is issued for `OtherScope` while a `TestScope`
    /// operation is on the stack — the shape a composed stack produces when a
    /// layer of one plugin runs an operation that reaches a backend of another.
    /// A single shared task-local would credit the outer sink here.
    #[tokio::test]
    async fn one_scope_does_not_credit_another() {
        let outer = Arc::new(OperationEvidence::default());
        let inner = Arc::new(OperationEvidence::default());

        with_operation_evidence::<TestScope, _>(outer.clone(), async {
            credit_operation_acceptance::<OtherScope>();
            // The outer scope is still the one on this task, and crediting the
            // other plugin must not have reached it.
            assert!(
                !outer.saw_acceptance(),
                "a foreign plugin's acceptance must not vindicate this operation"
            );
            with_operation_evidence::<OtherScope, _>(inner.clone(), async {
                credit_operation_acceptance::<TestScope>();
            })
            .await;
        })
        .await;

        assert!(
            outer.saw_acceptance(),
            "control: nesting a foreign scope must not hide this plugin's own \
             sink from its own credit"
        );
        assert!(
            !inner.saw_acceptance(),
            "the nested foreign operation earned nothing of its own"
        );
    }

    #[tokio::test]
    async fn evidence_is_marked_installed_only_once_scoped() {
        let evidence = Arc::new(OperationEvidence::default());
        assert!(
            !evidence.was_installed(),
            "evidence that has never been scoped records nothing"
        );
        with_operation_evidence::<TestScope, _>(evidence.clone(), async {}).await;
        assert!(evidence.was_installed());
        assert!(evidence.require_installed("test"));
    }

    /// The verdict a RELEASE build reaches on a miswired layer, which is the
    /// half that protects production. It is asserted on
    /// [`OperationEvidence::installed_or_declined`] rather than on
    /// [`OperationEvidence::require_installed`] because the latter's
    /// `debug_assert!` panics before returning in the build this test runs in.
    #[test]
    fn an_uninstalled_sink_declines_to_promote() {
        let evidence = OperationEvidence::default();
        assert!(
            !evidence.installed_or_declined("test"),
            "a sink that was never scoped around an operation must decline \
             rather than answer for it"
        );
    }

    /// Credit outside any scope is dropped rather than panicking: a watch
    /// poller and a background token refresh both run on tasks of their own.
    #[tokio::test]
    async fn credit_outside_an_operation_is_dropped() {
        credit_operation_acceptance::<TestScope>();
        let evidence = Arc::new(OperationEvidence::default());
        with_operation_evidence::<TestScope, _>(evidence.clone(), async {}).await;
        assert!(
            !evidence.saw_acceptance(),
            "an acceptance recorded nowhere vindicates nobody"
        );
    }

    #[test]
    fn a_refusal_epoch_is_shared_by_its_clones() {
        let epoch = RefusalEpoch::default();
        let clone = epoch.clone();
        assert_eq!(epoch.get(), 0);
        clone.bump();
        assert_eq!(
            epoch.get(),
            1,
            "a refusal answered to any clone condemns the credential for all \
             of them"
        );
    }

    /// The status set the three cloud plugins share. A 404 is excluded on
    /// purpose — see [`status_is_routed_verdict`] — and this is the assertion
    /// that keeps it excluded in one place rather than three.
    #[test]
    fn only_a_routed_verdict_proves_the_request_was_authenticated() {
        for status in [200, 201, 204, 299, 409, 412, 416] {
            assert!(
                status_is_routed_verdict(status),
                "{status} is a verdict only a routed request reaches"
            );
        }
        for status in [100, 199, 300, 308, 400, 401, 403, 404, 429, 500, 503] {
            assert!(
                !status_is_routed_verdict(status),
                "{status} is no proof of a working credential"
            );
        }
    }
}
