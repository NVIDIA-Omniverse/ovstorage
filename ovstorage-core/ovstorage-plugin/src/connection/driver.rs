// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The per-backend `ConnectionAuthDriver` trait: the small set of protocol
//! verbs a connection-owning backend layer implements. Everything
//! backend-agnostic (the [`crate::ConnectionAuthState`] machine, single-flight
//! bring-up, cooldown, background refresh, cross-process coalescing, the
//! data-path recovery loop, and change emission) lives in the generic
//! [`super::ConnectionSet`]; a driver writes only these verbs.
//!
//! One driver *instance* is bound to one connection (it carries that
//! connection's config / discovery context), mirroring the role
//! `services-client`'s `DiscoveryState` plays today; a `ConnectionSet<D>`
//! holds many such instances of the same driver type `D`.

use std::time::SystemTime;

use async_trait::async_trait;

use crate::{
    AuthEventStream, AuthReason, CancellationToken, Connection, ConnectionId, Error, ErrorCode,
    InteractiveAuthCapability, Result, SecretBundle,
};

/// Whether [`ConnectionAuthDriver::obtain`] may drive a grant that consumes a
/// one-time credential (a refresh-token rotation). Non-defaultable so every
/// driver author handles both arms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GrantPolicy {
    /// Registered paths (`add_connection` / `update_credentials` / `bring_up`).
    /// `obtain` may drive a grant that consumes a one-time credential; the
    /// [`super::ConnectionSet`] persists the returned effective bundle before any
    /// backend `verify` runs, so a consumed rotation is never lost.
    AllowConsuming,
    /// Probe ([`super::ConnectionSet::probe_connection`]). Only *replayable* work
    /// is permitted — use a supplied bearer as-is, drive a client-credentials
    /// grant, fetch discovery. A bundle whose only path to a bearer would consume
    /// a one-time credential MUST return [`Obtained::WouldConsume`] instead of
    /// granting, so a probe never burns a live refresh token.
    NonConsumingOnly,
}

/// Outcome of [`ConnectionAuthDriver::obtain`]: what turning `creds` into a
/// working bearer produced (the IdP's answer, *pre*-`verify`). The
/// [`super::ConnectionSet`] persists the effective bundle before verifying, so
/// the rotated successor survives a `verify` rejection.
#[derive(Clone, Debug)]
pub enum Obtained {
    /// A working bearer exists. `credentials` is the *effective* bundle — the
    /// post-rotation successor when a consuming grant ran. `expires_at` drives
    /// background refresh (`None` = no known expiry / static creds).
    Bearer {
        credentials: SecretBundle,
        expires_at: Option<SystemTime>,
    },
    /// The backend needs no credentials for this connection.
    Anonymous,
    /// Cannot authenticate without interactive sign-in.
    AwaitingInteractive { reason: AuthReason },
    /// Policy was [`GrantPolicy::NonConsumingOnly`] and the only path to a bearer
    /// would consume a one-time credential (a refresh-token grant). Probes map
    /// this to [`ProbeOutcome::Unverifiable`].
    WouldConsume,
}

/// Verdict of [`super::ConnectionSet::probe_connection`] — a *Test Connection*
/// result for caller-supplied credentials (*post*-`verify`). Never carries a
/// credential bundle back to the caller (unlike [`Obtained`], which is internal
/// to a grant and holds the effective bundle the set must persist).
#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    /// Credentials authenticate and the backend accepts them.
    Authenticated { expires_at: Option<SystemTime> },
    /// The backend needs no credentials.
    Anonymous,
    /// Interactive sign-in is required.
    NeedsInteractive { reason: AuthReason },
    /// The backend (or IdP) rejected the credentials — a delivered soft-failure
    /// verdict, not a transport error.
    Rejected { error: Error },
    /// The bundle can only be tested by consuming a one-time credential, which a
    /// probe never does — register the connection instead.
    Unverifiable,
}

/// Outcome of [`ConnectionAuthDriver::refresh`].
#[derive(Clone, Debug)]
pub struct Refreshed {
    /// The fresh credential bundle to swap into the connection.
    pub credentials: SecretBundle,
    /// New expiry (drives the next background-refresh wakeup).
    pub expires_at: Option<SystemTime>,
}

/// How the connection lifecycle should treat a backend error. Produced by
/// [`ConnectionAuthDriver::classify`]; consumed by the data-path recovery loop
/// and the background-refresh scheduler.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthErrorClass {
    /// A non-interactive `refresh` / re-resolve may recover: invalidate the
    /// cached creds, refresh, retry the op **once** (the data-path
    /// recovery). Also drives a background-refresh failure to
    /// `AwaitingAuth { RefreshTokenExpired }`.
    RecoverableCredential,
    /// The refresh token was explicitly revoked at the IdP — background refresh
    /// parks `AwaitingAuth { RefreshTokenRevoked }`; the data path surfaces.
    Revoked,
    /// Interactive re-auth is required; the data path surfaces it (no silent
    /// retry) and the caller drives `authenticate`.
    NeedsInteractive,
    /// Authenticated but not authorized — surface, never re-auth/retry.
    PermissionDenied,
    /// Not an auth error (wire-transient / other) — the lifecycle does not act;
    /// the host `RetryWrapper` handles transients.
    NotAuth,
}

impl AuthErrorClass {
    /// Whether the data-path recovery loop should invalidate + refresh + retry
    /// once for this class. Only [`AuthErrorClass::RecoverableCredential`]
    /// qualifies: a `Revoked` token is dead at the IdP, so a refresh with it is
    /// a guaranteed-futile round-trip — the data path surfaces it (matching the
    /// `Revoked` doc) and the caller drives interactive re-auth.
    pub fn is_recoverable(self) -> bool {
        matches!(self, AuthErrorClass::RecoverableCredential)
    }
}

/// Default error classification by [`ErrorCode`], matching the RFC-0066
/// orchestration error-code table (§1998-2011). Drivers override only when
/// their backend needs a finer mapping.
pub fn default_classify(error: &Error) -> AuthErrorClass {
    match error.code() {
        ErrorCode::AuthExpired
        | ErrorCode::CredentialExpired
        | ErrorCode::CredentialUnavailable => AuthErrorClass::RecoverableCredential,
        ErrorCode::AuthRequired | ErrorCode::AuthCancelled => AuthErrorClass::NeedsInteractive,
        ErrorCode::PermissionDenied => AuthErrorClass::PermissionDenied,
        _ => AuthErrorClass::NotAuth,
    }
}

/// The per-backend protocol verbs. Everything else is generic
/// ([`super::ConnectionSet`]). Implementations are bound to a single
/// connection's config; `Send + Sync` so the background-refresh task and
/// data-path callers can share one via `Arc<D>`.
#[async_trait]
pub trait ConnectionAuthDriver: Send + Sync + 'static {
    /// The backend-kind string (keyring keying + `Connection.backend_kind`).
    fn backend_kind(&self) -> &str;

    /// A stable, cross-restart/cross-process identity for this connection, used
    /// for secret persistence and the cross-process refresh lock. The RFC
    /// `ConnectionId` is `pid+nanos` and not stable, so drivers derive this
    /// from durable config (e.g. a hash of the discovery URL). `None` disables
    /// persistence + cross-process coalescing for this connection.
    fn stable_id(&self) -> Option<ConnectionId> {
        None
    }

    /// Turn `creds` into a working bearer (discovery fetch, IdP grants). MUST NOT
    /// read or write the secret store, and MUST NOT touch live transport state — all
    /// work happens against driver-*private* staging state, so a concurrent RPC
    /// on the live connection never observes an unverified candidate. `policy` is
    /// non-defaultable: every driver handles both arms (a
    /// [`GrantPolicy::NonConsumingOnly`] probe returns [`Obtained::WouldConsume`]
    /// rather than consume a one-time credential). The returned
    /// [`Obtained::Bearer`] carries the *effective* (post-rotation) bundle so the
    /// [`super::ConnectionSet`] can persist it before [`Self::verify`] can reject
    /// it — a consumed rotation is never lost on the rejection path.
    async fn obtain(
        &self,
        creds: &SecretBundle,
        policy: GrantPolicy,
        cancel: Option<CancellationToken>,
    ) -> Result<Obtained>;

    /// Prove the backend accepts `credentials` with one read-only RPC over an
    /// **ephemeral** transport (built, used once, torn down — win or lose). MUST
    /// NOT grant, persist, or touch live transport state. `Err` is classified via
    /// [`Self::classify`].
    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;

    /// Install a *proven* bundle onto the live transport state (the cell the
    /// transport interceptor reads), at commit time, after [`Self::verify`]
    /// passed. `expected_gen` is [`Self::identity_gen`] captured by the
    /// [`super::ConnectionSet`] at the start of the grant: `activate` MUST install
    /// **only if** the driver's identity generation is still `expected_gen`, and
    /// otherwise discard — a concurrent interactive success or credential update
    /// already won, and the live cell must never regress to this now-stale
    /// bundle.
    ///
    /// Returns whether the **fenced install committed**: `Ok(true)` when the
    /// bundle was installed (identity generation still matched under the install
    /// lock), `Ok(false)` when a concurrent identity change already won and the
    /// install was SKIPPED (not an error). The [`super::ConnectionSet`] gates its
    /// own set-side commit on this flag rather than re-reading
    /// [`Self::identity_gen`] afterwards — a winner landing between the internal
    /// commit and an external re-read would reopen the race the flag closes, and
    /// the merge/replace split ([`Self::activate_replacing`] bumps
    /// `identity_gen` itself) makes a post-hoc equality check ambiguous. Default:
    /// no-op that reports committed (`Ok(true)`) — a driver with no live token
    /// cell has nothing to fence, so the set-side commit always proceeds.
    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        let _ = (credentials, expected_gen);
        Ok(true)
    }

    /// [`Self::activate`] for an EXPLICIT, caller-supplied credential change
    /// (operator paste / rotation push via `update_credentials`) rather than a
    /// same-identity bring-up / warm-continue. The bundle is a NEW identity, so a
    /// driver whose live cell carries auxiliary credential slots (an OAuth refresh
    /// token, a cached machine-to-machine pair) must REPLACE them — clearing any
    /// slot the new bundle does not carry — and BUMP [`Self::identity_gen`] so an
    /// in-flight interactive sign-in / refresh of the PRIOR identity is fenced out
    /// of its own commit. Still fenced on `expected_gen` exactly like
    /// [`Self::activate`]: a concurrent identity change that already won is not
    /// regressed.
    ///
    /// Returns whether the **fenced install committed** (same contract as
    /// [`Self::activate`]): `Ok(true)` when the replacement was installed,
    /// `Ok(false)` when a concurrent identity change already won and the install
    /// was SKIPPED. A driver that bumps `identity_gen` on a successful commit MUST
    /// report the primitive's own committed-flag here — the
    /// [`super::ConnectionSet`] cannot distinguish that legitimate self-bump from
    /// a racing winner's bump by re-reading `identity_gen`, so it gates its
    /// set-side commit on this returned flag instead. Default: delegate to
    /// [`Self::activate`], forwarding its flag — a driver whose live cell holds
    /// only the bearer being replaced (static-key backends) has no stale auxiliary
    /// slot to strand, so merge and replace coincide.
    async fn activate_replacing(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
    ) -> Result<bool> {
        self.activate(credentials, expected_gen).await
    }

    /// The driver's live *identity* generation — a monotonic counter bumped only
    /// by identity-changing writes to the live transport cell (interactive
    /// success, credential replacement), NOT by same-identity refresh merges. The
    /// [`super::ConnectionSet`] snapshots it before a grant and threads it into
    /// [`Self::activate`] as the supersession fence for the verify→activate
    /// window. Default: `0` (drivers with no live cell never supersede).
    fn identity_gen(&self) -> u64 {
        0
    }

    /// Whether `credentials` still describe the identity the driver's live cell
    /// holds, and so may be committed on its behalf.
    ///
    /// [`Self::identity_gen`] cannot answer this on its own. An interactive
    /// flow's terminal event is fenced before it is QUEUED, but the
    /// [`super::ConnectionSet`] drains it later; a newer flow — or a rotation of
    /// the same identity, which by design does not move `identity_gen` —
    /// can commit in between. Committing the queued bundle then regresses the
    /// connection's credentials to one the live cell no longer holds, and the
    /// next refresh drives a grant on a token the provider has already consumed.
    ///
    /// Default: `true` — a driver with no live cell has nothing that could have
    /// moved on. Drivers holding OAuth token cells answer from
    /// [`crate::oauth_secret_store::bundle_carries_published_credential`].
    ///
    /// This gates a WRITE and never removes anything: a bundle refused here
    /// leaves the winner's credentials standing in memory and in the secret store, so
    /// a false negative costs a re-authentication, never a credential.
    fn credentials_are_current(&self, credentials: &SecretBundle) -> bool {
        let _ = credentials;
        true
    }

    /// Obtain fresh credentials from `current` (OAuth refresh, SigV4/STS
    /// re-resolution). Return `Err(Unsupported)` for static keys with no
    /// refresh path — the lifecycle then parks rather than looping.
    ///
    /// `expected_gen` is [`Self::identity_gen`] captured by the
    /// [`super::ConnectionSet`] at the start of the grant (the identity the set
    /// intended to refresh). A driver that commits the freshly-minted bearer onto
    /// its live cell MUST fence that install on `expected_gen` — install **only
    /// if** the driver's identity generation is still `expected_gen`, else discard
    /// — so a concurrent interactive success / credential replacement that bumped
    /// `identity_gen` since the set's capture wins, and the live cell never
    /// regresses to this now-stale identity's freshly-minted token. Threaded from
    /// the same capture the set feeds [`Self::activate`], so `refresh` and
    /// `activate` fence live-cell installs on one identity generation the set owns.
    async fn refresh(
        &self,
        current: &SecretBundle,
        cancel: Option<CancellationToken>,
        expected_gen: u64,
    ) -> Result<Refreshed> {
        let _ = (current, cancel, expected_gen);
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend has no non-interactive credential refresh",
        ))
    }

    /// Drive the interactive flow, returning an `AuthEventStream`. On the flow's
    /// `AuthEvent::Succeeded { credentials: Some(..) }` the [`super::ConnectionSet`]
    /// persists + swaps the credentials and transitions to `Authenticated`
    /// before forwarding the event. Session-full drivers must fence their live
    /// install against concurrent identity replacement and emit `Failed` rather
    /// than `Succeeded` when that fence is lost.
    ///
    /// **A driver with no interactive flow returns
    /// `Err(ErrorCode::Unsupported)`, not a `Succeeded` event.** Every terminal
    /// `Succeeded` — including `credentials: None`, which means "the flow
    /// installed tokens itself" — is a claim that a sign-in happened, and
    /// [`super::ConnectionSet`] promotes the connection to `Authenticated` on
    /// it. A static-credential backend that answers that way launders a
    /// connection its origin refused into `Authenticated` with no grant and no
    /// probe. The error is raised before the promoting adapter exists, so it
    /// leaves the connection's state untouched in every state — which is the
    /// honest outcome when nothing ran.
    ///
    /// Two refusals, and they are not interchangeable:
    ///
    /// - [`ErrorCode::Unsupported`] — **this backend has no interactive flow at
    ///   all.** A host reads it as "no flow was offered": nothing ran, so the
    ///   registration stands. What it does next is its own policy — the CLI's
    ///   `connect` keeps the connection and reports its state, while `reauth`,
    ///   whose entire purpose was to run a flow, reports the refusal.
    /// - [`ErrorCode::AuthRequired`] — a flow exists, but the host's
    ///   [`InteractiveAuthCapability`] cannot drive it (typically
    ///   [`InteractiveAuthCapability::None`]: CI, a render worker, a sandboxed
    ///   service). This is an ordinary failure.
    ///
    /// **Answer `Unsupported` before inspecting `capability`.** Whether a flow
    /// exists is a property of the backend; `capability` describes only what the
    /// caller could drive if one did. A driver whose flow depends on the
    /// connection's own configuration — the broker client, where a direct
    /// endpoint has no OAuth surface but a discovered one does — decides
    /// `Unsupported` on that configuration first, and reaches the capability
    /// check only on the arm that really has a flow. Ordering it the other way
    /// makes a backend's lack of a flow look like a host limitation, and costs
    /// the caller the registration.
    async fn interactive(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream>;

    /// Map a backend error onto [`AuthErrorClass`]. Default: [`default_classify`].
    fn classify(&self, error: &Error) -> AuthErrorClass {
        default_classify(error)
    }

    /// Persist the connection's durable secret (e.g. an OAuth refresh token) so
    /// a later process can warm-continue. Default: no-op. Implementations
    /// typically use `crate::marshal::secret_put` keyed on [`Self::stable_id`].
    ///
    /// **Set-called only.** Durability is owned by the [`super::ConnectionSet`]'s
    /// single `locked_grant` primitive (reload → grant → persist, under the
    /// cross-process lock). A driver must NOT call its own
    /// `persist_/load_/delete_credentials` from any other verb — `obtain`,
    /// `verify`, and `activate` never touch the secret store, which is what makes a
    /// probe structurally side-effect-free (no footgun to forget).
    async fn persist_credentials(&self, creds: &SecretBundle) -> Result<()> {
        let _ = creds;
        Ok(())
    }

    /// Load a persisted secret for warm-continue at bring-up.
    /// Default: `None`.
    async fn load_credentials(&self) -> Result<Option<SecretBundle>> {
        Ok(None)
    }

    /// Delete the connection's durable secret on removal — the inverse of
    /// [`Self::persist_credentials`]. Default: no-op. Implementations use
    /// `crate::marshal::secret_delete` keyed on [`Self::stable_id`]. The
    /// [`super::ConnectionSet`] calls this only when no other live connection
    /// shares this connection's [`Self::stable_id`], so a per-host shared secret
    /// is not deleted out from under a sibling connection.
    async fn delete_credentials(&self) -> Result<()> {
        Ok(())
    }

    /// Delete durable warm-continuation state and forget any driver-local copy.
    /// The default has no driver-local cache.
    async fn purge_credentials(&self) -> Result<()> {
        self.delete_credentials().await
    }

    /// Session-full backends (e.g. Nucleus) establish a session here after the
    /// connection becomes `Authenticated`. Default: no-op.
    async fn on_authenticated(
        &self,
        connection: &Connection,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = (connection, cancel);
        Ok(())
    }
}
