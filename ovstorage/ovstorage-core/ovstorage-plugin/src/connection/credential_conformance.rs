// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The conformance expectations for the credential transaction, held over each
//! [`ConnectionAuthDriver`] ENROLLED as a [`CredentialTransactionSubject`].
//! Enrolled today: the plugin crate's `MockDriver`, and the two real drivers
//! that own an OAuth credential cell — `ovstorage-plugin-broker`'s
//! `BrokerDriver` and `ovstorage-plugin-services-client`'s
//! `OmniverseStorageDriver`.
//!
//! Enrollment is the whole constraint: a driver that owns credential state and
//! does not implement [`CredentialTransactionSubject`] — `NucleusDriver` and
//! `S3Driver` both keep a live cell and are not enrolled — is held to nothing
//! here. Enrolling one is implementing that trait and calling whichever of the
//! two harnesses matches the `activate_replacing` shape it is in service as.
//!
//! There are two, one per supported shape of
//! [`ConnectionAuthDriver::activate_replacing`], and a subject stands the one
//! matching the shape it is actually in service as:
//! [`assert_credential_transaction_conformance`] for a driver that owns the real
//! replacement primitive, and [`assert_delegated_replacement_conformance`] for
//! one taking the trait default. Certifying only the first while a subject runs
//! as the second is the same vacuity in a new place — the divergence has to be
//! written down, not left to be inferred from a flag.
//!
//! A driver's live credential cell is not one value: it is the access token,
//! the refresh token, the expiry, the cached machine-to-machine pair, the
//! credential lineage, the write generation, the identity generation, the
//! published credential, and the identity binding, all moved together inside a
//! single guarded transaction. A double that models a subset of those passes
//! every test that uses it while exercising none of the transaction — the shape
//! behind three separate defects in this area.
//!
//! So the correspondence is not maintained by hand here. An implementor
//! supplies exactly one thing, [`CredentialTransactionSubject::credential_snapshot`];
//! the writing is done by the production [`ConnectionAuthDriver`] verbs, and
//! [`assert_credential_transaction_conformance`] states what a write must have
//! moved. Two levers keep a double from drifting again:
//!
//! * [`CredentialSnapshot`] is destructured exhaustively in
//!   [`changed_dimensions`], so a dimension added to the real transaction is a
//!   compile error in every implementor until that implementor reports it; and
//! * the harness asserts the *set* of moved dimensions, so an implementor that
//!   reports a dimension it never mutates fails rather than diverging quietly.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::connection::ConnectionAuthDriver;
use crate::oauth_secret_store::IdentityBinding;
use crate::{SecretBundle, SecretBytes, SecretValue};

/// Every dimension one credential transaction mutates, read as a single
/// observation.
///
/// Adding a field here is deliberately a breaking change for every
/// implementor: the real transaction grew a dimension, and a double that does
/// not mirror it is exactly the divergence this type exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialSnapshot {
    /// The bearer the connection is serving on.
    pub access_token: Option<String>,
    /// The refresh token the live identity holds, if any.
    pub refresh_token: Option<String>,
    /// Expiry of the live access token.
    pub expires_at: Option<SystemTime>,
    /// Cached `(client_id, client_secret)` machine-to-machine pair.
    pub client_credentials: Option<(String, String)>,
    /// Whether the live identity was established interactively rather than by
    /// a service/M2M grant.
    pub interactive_lineage: bool,
    /// Generation of *every* credential write.
    pub generation: u64,
    /// Generation of identity-CHANGING writes only — the supersession fence.
    pub identity_generation: u64,
    /// Fingerprint of the refresh token the connection is serving on.
    pub published_credential: Option<String>,
    /// Identity the live credential belongs to.
    pub binding: Option<IdentityBinding>,
}

/// Every dimension, in the order [`CredentialSnapshot`] declares them.
///
/// A function rather than a `const`: this module is Rust-only test support
/// compiled under `cfg(test)` or the `test-credential-conformance` feature, and
/// cbindgen parses the crate's sources regardless of `cfg`. A const here — `pub`
/// or not — makes it emit a diagnostic about a `&[&str]` it cannot represent in
/// C, and the header gate treats cbindgen diagnostics as errors.
fn all_dimensions() -> [&'static str; 9] {
    [
        "access_token",
        "refresh_token",
        "expires_at",
        "client_credentials",
        "interactive_lineage",
        "generation",
        "identity_generation",
        "published_credential",
        "binding",
    ]
}

/// Which dimensions moved between two observations.
///
/// Both snapshots are destructured exhaustively, so a field added to
/// [`CredentialSnapshot`] fails to compile here until it is compared — the
/// table cannot fall behind the type.
pub fn changed_dimensions(
    before: &CredentialSnapshot,
    after: &CredentialSnapshot,
) -> BTreeSet<&'static str> {
    let CredentialSnapshot {
        access_token: before_access_token,
        refresh_token: before_refresh_token,
        expires_at: before_expires_at,
        client_credentials: before_client_credentials,
        interactive_lineage: before_interactive_lineage,
        generation: before_generation,
        identity_generation: before_identity_generation,
        published_credential: before_published_credential,
        binding: before_binding,
    } = before;
    let CredentialSnapshot {
        access_token: after_access_token,
        refresh_token: after_refresh_token,
        expires_at: after_expires_at,
        client_credentials: after_client_credentials,
        interactive_lineage: after_interactive_lineage,
        generation: after_generation,
        identity_generation: after_identity_generation,
        published_credential: after_published_credential,
        binding: after_binding,
    } = after;

    let mut changed = BTreeSet::new();
    let mut note = |moved: bool, dimension: &'static str| {
        if moved {
            changed.insert(dimension);
        }
    };
    note(before_access_token != after_access_token, "access_token");
    note(before_refresh_token != after_refresh_token, "refresh_token");
    note(before_expires_at != after_expires_at, "expires_at");
    note(
        before_client_credentials != after_client_credentials,
        "client_credentials",
    );
    note(
        before_interactive_lineage != after_interactive_lineage,
        "interactive_lineage",
    );
    note(before_generation != after_generation, "generation");
    note(
        before_identity_generation != after_identity_generation,
        "identity_generation",
    );
    note(
        before_published_credential != after_published_credential,
        "published_credential",
    );
    note(before_binding != after_binding, "binding");
    changed
}

/// A driver whose credential state the harness can read.
///
/// The write side is the production [`ConnectionAuthDriver`] surface —
/// `activate` (same-identity merge) and `activate_replacing` (identity-changing
/// replacement) — so an implementor cannot satisfy the harness with a
/// test-only path that the lifecycle never takes.
#[async_trait]
pub trait CredentialTransactionSubject: ConnectionAuthDriver {
    /// Read every dimension of the live credential cell.
    async fn credential_snapshot(&self) -> CredentialSnapshot;
}

/// A JWT-shaped access token naming `subject`, so a binding derived from it is
/// distinguishable from one derived from another subject. Unsigned: the
/// binding derivation reads claims without verifying them (see
/// [`crate::oauth_secret_store::identity_from_access_token`]).
pub fn access_token_for(subject: &str) -> String {
    let claims = serde_json::json!({
        "iss": "https://idp.example",
        "azp": "conformance-client",
        "sub": subject,
    });
    format!(
        "e30.{}.sig",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"))
    )
}

/// An activation bundle in the shape both `activate` and `activate_replacing`
/// parse: an `oauth` triple, plus the M2M pair when one is supplied.
pub fn activation_bundle(
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in: Option<Duration>,
    client_credentials: Option<(&str, &str)>,
) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(access_token.as_bytes().to_vec()),
            refresh: refresh_token.map(|rt| SecretBytes(rt.as_bytes().to_vec())),
            expires_at: expires_in.map(|d| SystemTime::now() + d),
        },
    );
    if let Some((client_id, client_secret)) = client_credentials {
        bundle.fields.insert(
            "client_id".into(),
            SecretValue::Bytes(SecretBytes(client_id.as_bytes().to_vec())),
        );
        bundle.fields.insert(
            "client_secret".into(),
            SecretValue::Bytes(SecretBytes(client_secret.as_bytes().to_vec())),
        );
    }
    bundle
}

fn expect_changed(
    before: &CredentialSnapshot,
    after: &CredentialSnapshot,
    expected: &[&'static str],
    what: &str,
) {
    let changed = changed_dimensions(before, after);
    let expected: BTreeSet<&'static str> = expected.iter().copied().collect();
    let missing: Vec<_> = expected.difference(&changed).copied().collect();
    let unexpected: Vec<_> = changed.difference(&expected).copied().collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "{what}: dimensions this driver failed to move: {missing:?}; \
         dimensions it moved but must not have: {unexpected:?}\n\
         before: {before:?}\nafter:  {after:?}"
    );
}

/// Drive one credential-owning driver through the transaction every such driver
/// performs, and assert what each write moved.
///
/// The subjects standing this one are those that own the real replacement
/// primitive: `MockDriver` in its default shape, and `BrokerDriver`. A subject
/// whose `activate_replacing` takes the trait default stands
/// [`assert_delegated_replacement_conformance`] instead.
///
/// The subject starts from a clean credential cell (a freshly constructed
/// driver); the harness seeds it, then checks five properties:
///
/// 1. an identity-changing write moves **every** dimension;
/// 2. a same-identity merge moves the merge dimensions and **only** those — an
///    identity's lineage, M2M pair, binding and identity generation survive a
///    routine rotation;
/// 3. a merge with no refresh token preserves the slot (RFC 6749 §6);
/// 4. a write fenced out by a stale identity generation moves **nothing** — the
///    transaction is all-or-nothing, not a sequence of independent stores; and
/// 5. a bundle carrying no `oauth` field moves **nothing** and still reports
///    committed.
pub async fn assert_credential_transaction_conformance<S: CredentialTransactionSubject>(
    subject: &S,
) {
    // Seed a service identity, so the identity-changing write below has a
    // populated cell to move away from on every dimension.
    let seed = activation_bundle(
        &access_token_for("seed"),
        Some("rt-seed"),
        Some(Duration::from_secs(3600)),
        Some(("seed-id", "seed-secret")),
    );
    let committed = subject
        .activate_replacing(&seed, subject.identity_gen())
        .await
        .expect("seeding an identity is not an error");
    assert!(committed, "an uncontended identity write must commit");

    // (1) An identity-changing write moves every dimension: a new bearer and
    // refresh, a new expiry, the M2M pair cleared (which is the interactive
    // lineage), both generations, the published credential and the binding.
    let before = subject.credential_snapshot().await;
    let winner = activation_bundle(
        &access_token_for("winner"),
        Some("rt-winner"),
        Some(Duration::from_secs(7200)),
        None,
    );
    let committed = subject
        .activate_replacing(&winner, subject.identity_gen())
        .await
        .expect("an identity-changing write is not an error");
    assert!(committed, "an uncontended identity write must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &all_dimensions(),
        "an identity-changing credential write",
    );

    // Re-establish a SERVICE identity before the merge below. The winner above
    // is the interactive shape — it carries no M2M pair, so it cleared the
    // cached one — and running the merge from there would leave
    // `client_credentials` absent when the merge starts. It would then land in
    // the "did not move" set for the wrong reason: not because the merge
    // preserved it, but because there was nothing there to preserve, and a
    // driver that wrongly clears the cached pair on a routine merge would pass.
    //
    // Preserving the pair across a merge is what lets a service-account
    // connection re-drive its client-credentials grant on the next background
    // refresh without re-reading the operator's client secret, so the merge has
    // to run with the pair actually present.
    let before = subject.credential_snapshot().await;
    let service = activation_bundle(
        &access_token_for("service"),
        Some("rt-service"),
        Some(Duration::from_secs(3600)),
        Some(("service-id", "service-secret")),
    );
    let committed = subject
        .activate_replacing(&service, subject.identity_gen())
        .await
        .expect("re-establishing a service identity is not an error");
    assert!(committed, "an uncontended identity write must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &all_dimensions(),
        "an identity-changing write re-establishing a service identity",
    );

    // (2) A same-identity merge rotates the credential without disturbing the
    // identity — note the bearer names a DIFFERENT subject, and the binding
    // still must not move: a merge does not re-derive the identity. The cached
    // M2M pair is present when this runs, so `client_credentials` is in the
    // must-NOT-move set because the merge preserved it.
    let before = subject.credential_snapshot().await;
    assert!(
        before.client_credentials.is_some(),
        "the merge below only pins M2M preservation if the pair is present when \
         it runs — the write above must have cached one",
    );
    let merged = activation_bundle(
        &access_token_for("merged"),
        Some("rt-merged"),
        Some(Duration::from_secs(900)),
        None,
    );
    let committed = subject
        .activate(&merged, subject.identity_gen())
        .await
        .expect("a same-identity merge is not an error");
    assert!(committed, "an uncontended merge must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[
            "access_token",
            "refresh_token",
            "expires_at",
            "generation",
            "published_credential",
        ],
        "a same-identity merge",
    );

    // (3) A merge carrying no refresh token PRESERVES the slot (RFC 6749 §6:
    // the IdP may omit an unchanged refresh), so the published credential —
    // derived from that slot — does not move either.
    let before = subject.credential_snapshot().await;
    let access_only = activation_bundle(
        &access_token_for("access-only"),
        None,
        Some(Duration::from_secs(1800)),
        None,
    );
    let committed = subject
        .activate(&access_only, subject.identity_gen())
        .await
        .expect("an access-only merge is not an error");
    assert!(committed, "an uncontended merge must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &["access_token", "expires_at", "generation"],
        "a merge that omits the refresh token",
    );

    // (4) A write fenced out by a concurrent identity change moves NOTHING. The
    // fence compare and the stores are one transaction, so a superseded write
    // cannot leave a partial trace — half-applied state is what a driver whose
    // dimensions move independently produces.
    let stale = subject
        .identity_gen()
        .checked_sub(1)
        .expect("the seed and the identity write both bumped the identity generation");
    let loser = activation_bundle(
        &access_token_for("loser"),
        Some("rt-loser"),
        Some(Duration::from_secs(60)),
        Some(("loser-id", "loser-secret")),
    );
    let before = subject.credential_snapshot().await;
    let committed = subject
        .activate_replacing(&loser, stale)
        .await
        .expect("a superseded write is a discard, not an error");
    assert!(!committed, "a superseded identity write must not commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[],
        "an identity-changing write fenced out by a stale identity generation",
    );

    let before = subject.credential_snapshot().await;
    let committed = subject
        .activate(&loser, stale)
        .await
        .expect("a superseded merge is a discard, not an error");
    assert!(!committed, "a superseded merge must not commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[],
        "a merge fenced out by a stale identity generation",
    );

    assert_empty_bundle_moves_nothing(subject).await;
}

/// (5) A bundle carrying no `oauth` field installs nothing and moves NO
/// dimension — not the write generation either — and still reports committed.
///
/// This is the anonymous / config-only activation the `ConnectionSet` performs,
/// and both real drivers implement it as an early return before they reach
/// their credential transaction at all. A subject that instead stores the
/// bundle, or bumps a generation for it, is claiming a write the drivers it
/// stands beside never perform — and a double doing that reports a credential
/// change to every lifecycle test that activates anonymously.
///
/// Shared by both harnesses: the shape is the same whichever
/// `activate_replacing` a subject owns, because neither reaches the
/// transaction.
async fn assert_empty_bundle_moves_nothing<S: CredentialTransactionSubject>(subject: &S) {
    let empty = SecretBundle::default();

    let before = subject.credential_snapshot().await;
    let committed = subject
        .activate(&empty, subject.identity_gen())
        .await
        .expect("a merge carrying no credentials is not an error");
    assert!(
        committed,
        "a merge carrying no `oauth` field must report committed — there is \
         nothing to fence",
    );
    let after = subject.credential_snapshot().await;
    expect_changed(&before, &after, &[], "a merge carrying no `oauth` field");

    let before = subject.credential_snapshot().await;
    let committed = subject
        .activate_replacing(&empty, subject.identity_gen())
        .await
        .expect("a replacement carrying no credentials is not an error");
    assert!(
        committed,
        "a replacement carrying no `oauth` field must report committed — there \
         is nothing to fence",
    );
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[],
        "a replacement carrying no `oauth` field",
    );
}

/// The other supported shape: a driver whose `activate_replacing` takes the
/// trait default and delegates to [`ConnectionAuthDriver::activate`].
///
/// That default is legitimate — a driver whose live cell holds only the bearer
/// being replaced (a static-key backend) has no auxiliary slot to strand, so
/// merge and replace coincide — but it is a strictly WEAKER transaction than
/// [`assert_credential_transaction_conformance`] certifies, and a subject
/// standing only that one would leave the difference undescribed. This states
/// the difference instead: what a delegating `activate_replacing` is allowed to
/// omit, and what it must still do.
///
/// Allowed to omit, all three because the write is a merge: clearing an
/// auxiliary slot the new bundle does not carry, moving the binding, and
/// bumping the identity generation. Still required: the fenced,
/// all-or-nothing transaction — a mismatched fence commits NOTHING.
///
/// A subject stands exactly one of the two. A driver that owns auxiliary
/// credential slots and takes this shape is a defect, not a variant: the
/// stranded M2M pair this pins as "not cleared" is precisely the stale identity
/// a later background refresh would revert to.
pub async fn assert_delegated_replacement_conformance<S: CredentialTransactionSubject>(
    subject: &S,
) {
    let start_identity_gen = subject.identity_gen();

    // Seed a service identity through `activate_replacing`, from a clean cell.
    let seed = activation_bundle(
        &access_token_for("seed"),
        Some("rt-seed"),
        Some(Duration::from_secs(3600)),
        Some(("seed-id", "seed-secret")),
    );
    let before = subject.credential_snapshot().await;
    let committed = subject
        .activate_replacing(&seed, subject.identity_gen())
        .await
        .expect("seeding is not an error");
    assert!(committed, "an uncontended write must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[
            "access_token",
            "refresh_token",
            "expires_at",
            "client_credentials",
            "generation",
            "published_credential",
        ],
        "a delegating `activate_replacing` seeding a cell: it caches the M2M pair \
         the bundle carries, but establishes no identity",
    );

    // The divergence itself. A REPLACING write whose bundle carries no M2M pair
    // leaves the cached one in place, leaves the binding naming whoever it named
    // before, and does not advance the supersession fence — none of which a real
    // replacement primitive is allowed to do.
    let before = subject.credential_snapshot().await;
    let replacement = activation_bundle(
        &access_token_for("replacement"),
        Some("rt-replacement"),
        Some(Duration::from_secs(7200)),
        None,
    );
    let committed = subject
        .activate_replacing(&replacement, subject.identity_gen())
        .await
        .expect("a replacement is not an error");
    assert!(committed, "an uncontended write must commit");
    let after = subject.credential_snapshot().await;
    expect_changed(
        &before,
        &after,
        &[
            "access_token",
            "refresh_token",
            "expires_at",
            "generation",
            "published_credential",
        ],
        "a delegating `activate_replacing` is a merge: it must NOT clear the \
         cached M2M pair, move the binding, or bump the identity generation",
    );

    // The fence still holds, and still moves the cell as one transaction. The
    // generation never advanced under this shape, so there is no OLDER value to
    // offer: the fence is an equality compare, and a value that does not match
    // is what a superseded caller holds.
    let mismatched = subject.identity_gen().wrapping_add(1);
    let loser = activation_bundle(
        &access_token_for("loser"),
        Some("rt-loser"),
        Some(Duration::from_secs(60)),
        Some(("loser-id", "loser-secret")),
    );
    for (what, committed) in [
        (
            "a delegating `activate_replacing` fenced out by a mismatched identity generation",
            {
                let before = subject.credential_snapshot().await;
                let committed = subject
                    .activate_replacing(&loser, mismatched)
                    .await
                    .expect("a superseded write is a discard, not an error");
                let after = subject.credential_snapshot().await;
                expect_changed(
                    &before,
                    &after,
                    &[],
                    "a delegating `activate_replacing` fenced out by a mismatched \
                     identity generation",
                );
                committed
            },
        ),
        ("a merge fenced out by a mismatched identity generation", {
            let before = subject.credential_snapshot().await;
            let committed = subject
                .activate(&loser, mismatched)
                .await
                .expect("a superseded merge is a discard, not an error");
            let after = subject.credential_snapshot().await;
            expect_changed(
                &before,
                &after,
                &[],
                "a merge fenced out by a mismatched identity generation",
            );
            committed
        }),
    ] {
        assert!(!committed, "{what} must not commit");
    }

    assert_empty_bundle_moves_nothing(subject).await;

    assert_eq!(
        subject.identity_gen(),
        start_identity_gen,
        "a driver delegating `activate_replacing` never establishes an identity, \
         so its identity generation never moves — if it does, this subject owns \
         the real replacement primitive and must stand \
         `assert_credential_transaction_conformance` instead",
    );
}
