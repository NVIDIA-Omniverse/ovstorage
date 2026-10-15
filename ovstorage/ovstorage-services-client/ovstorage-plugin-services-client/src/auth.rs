// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC discovery state + bearer interceptor for the Omniverse Storage Service gRPC client.
//!
//! Adapted from `ovstorage-plugin-broker/src/auth.rs`. The Omniverse Storage Service
//! discovery surface is the HTTP root that serves `/api/v1/services` and
//! `/api/v1/auth-config`; the rest of the OIDC dance is identical to the
//! broker pattern.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{
    AuthEvent, AuthEventStream, BackendId, CancellationToken, Connection, ConnectionId, Error,
    ErrorCode, InteractiveAuthCapability, Result, SecretValue,
};
use parking_lot::RwLock as SyncRwLock;
use serde::Deserialize;
use tokio::sync::{Notify, RwLock};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};
use tracing::Instrument;

/// Refresh proactively when less than this much lifetime remains; absorbs
/// client/IDP clock skew.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    pub openid_configuration: String,
    #[serde(default)]
    pub clients: std::collections::BTreeMap<String, AuthClientConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// A test seam marking the generation-compare point inside
/// [`DiscoveryState::observe_binding_unless_superseded`].
///
/// It must stay immediately before that compare: the test asserts the binding
/// lock is held when it runs, which is how "the compare and the check share one
/// lock" is checked. Moving the compare without moving this would leave the
/// test asserting nothing.
#[cfg(test)]
pub type BindingObservationGate = std::sync::Arc<dyn Fn(&DiscoveryState) + Send + Sync>;

#[derive(Clone)]
pub struct DiscoveryState {
    inner: Arc<DiscoveryStateInner>,
}

struct DiscoveryStateInner {
    generation: AtomicU64,
    /// Bumped ONLY by identity-changing writes — [`DiscoveryState::replace_tokens`]
    /// (interactive sign-in), the restore paths (candidate rollback), and
    /// [`DiscoveryState::set_client_credentials`] (explicit credential update) —
    /// NOT by same-identity `install_tokens` merges (routine refresh grants).
    /// The interactive flow's supersession guard keys on this, so a background
    /// refresh of the SAME identity completing during a minutes-long sign-in
    /// does not make the guard misfire and drop the sign-in tokens.
    identity_gen: AtomicU64,
    /// The credential cells are `parking_lot::RwLock`, not `tokio::sync::RwLock`:
    /// the publication lock is a `std::sync::Mutex` and is acquired BEFORE them
    /// (see the crate's credential lock order), which an async guard would make
    /// impossible — a `std::sync::MutexGuard` held across a `.write().await`
    /// makes the enclosing future `!Send`, and `ConnectionAuthDriver` is a boxed
    /// `Send` future. No credential guard is held across an `.await`.
    access_token: SyncRwLock<Option<String>>,
    refresh_token: SyncRwLock<Option<String>>,
    expires_at: SyncRwLock<Option<SystemTime>>,
    auth_config: RwLock<Option<AuthConfig>>,
    oidc_config: RwLock<Option<OidcConfig>>,
    /// The identity the LIVE credential belongs to.
    ///
    /// It lives here, beside the tokens, rather than on the driver: every
    /// identity-changing write holds this lock across its `identity_gen` bump,
    /// so anything that takes the lock sees the binding and the generation
    /// agree. Kept on the driver they were two independent loads, and a warm
    /// continuation that had read the previous account's record could restore
    /// it over a sign-in that had already won — writing the wrong identity into
    /// durable state and locking the winner out on its next grant.
    ///
    /// A `std::sync::Mutex`, not an async one, because the interactive flow's
    /// persistence callback is synchronous and must be able to take it.
    binding: std::sync::Mutex<Option<ovstorage_plugin::oauth_secret_store::IdentityBinding>>,
    /// A [`fingerprint`](ovstorage_plugin::oauth_binding::fingerprint) of the
    /// refresh token the connection is serving on,
    /// reassigned by every write that leaves the refresh slot assigned — a
    /// same-identity rotation included, not only an identity change. Written
    /// while the refresh slot's own write guard is held, so it cannot name a
    /// token the live cell does not hold.
    published_credential: std::sync::Mutex<Option<String>>,
    /// Serializes a durable credential write against an identity-changing
    /// install. See the crate's credential lock order.
    publication: std::sync::Mutex<()>,
    #[cfg(test)]
    binding_observation_gate: std::sync::Mutex<Option<BindingObservationGate>>,
    client_name: String,
    /// Cached `(client_id, client_secret)` for the `client_credentials`
    /// grant. Populated by the factory when a connection is instantiated
    /// with `client_id`/`client_secret` credentials so the background
    /// refresh loop can re-drive the grant without prompting the user.
    /// `None` when the connection is using the interactive refresh-token
    /// grant or is anonymous.
    client_credentials: SyncRwLock<Option<(String, String)>>,
    /// Woken when `install_tokens` lands a fresh access token. Lets
    /// `wait_for_token` block the dynamic-roots watcher until the OIDC flow
    /// completes — without busy-polling.
    token_arrived: Notify,
}

/// The identity fence is the binding mutex, which every identity-changing
/// write holds across its generation bump. See the crate's credential lock
/// order for what may run inside it.
impl ovstorage_plugin::oauth_secret_store::IdentityEpoch for DiscoveryState {
    fn with_identity_fence(
        &self,
        f: &mut dyn FnMut(
            ovstorage_plugin::oauth_secret_store::EpochView<'_>,
        ) -> ovstorage_plugin::oauth_secret_store::LeaseVerdict,
    ) -> ovstorage_plugin::oauth_secret_store::LeaseVerdict {
        let fence = self.binding_slot();
        let published = self
            .inner
            .published_credential
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(ovstorage_plugin::oauth_secret_store::EpochView {
            generation: self.inner.identity_gen.load(Ordering::SeqCst),
            binding: fence.as_ref(),
            published_credential: published.as_deref(),
        })
    }
}

impl DiscoveryState {
    /// Build the shared token cell. Background refresh is owned by the generic
    /// `ConnectionSet` (RFC-0066), not this state — the state only holds
    /// the tokens the transport interceptor reads and the driver's grants
    /// install into.
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(DiscoveryStateInner {
                generation: AtomicU64::new(0),
                identity_gen: AtomicU64::new(0),
                access_token: SyncRwLock::new(None),
                refresh_token: SyncRwLock::new(None),
                expires_at: SyncRwLock::new(None),
                auth_config: RwLock::new(None),
                oidc_config: RwLock::new(None),
                binding: std::sync::Mutex::new(None),
                published_credential: std::sync::Mutex::new(None),
                publication: std::sync::Mutex::new(()),
                #[cfg(test)]
                binding_observation_gate: std::sync::Mutex::new(None),
                client_name: client_name.into(),
                client_credentials: SyncRwLock::new(None),
                token_arrived: Notify::new(),
            }),
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::SeqCst)
    }

    /// Generation of identity-changing writes only (see `identity_gen`).
    pub fn identity_generation(&self) -> u64 {
        self.inner.identity_gen.load(Ordering::SeqCst)
    }

    pub async fn access_token(&self) -> Option<String> {
        self.inner.access_token.read().clone()
    }

    pub async fn refresh_token(&self) -> Option<String> {
        self.inner.refresh_token.read().clone()
    }

    pub async fn access_token_expires_at(&self) -> Option<SystemTime> {
        *self.inner.expires_at.read()
    }

    pub async fn auth_config(&self) -> Option<AuthConfig> {
        self.inner.auth_config.read().await.clone()
    }

    pub async fn oidc_config(&self) -> Option<OidcConfig> {
        self.inner.oidc_config.read().await.clone()
    }

    pub fn client_name(&self) -> &str {
        &self.inner.client_name
    }

    /// Cache the `(client_id, client_secret)` pair so the background
    /// refresh loop can re-drive the `client_credentials` grant without
    /// re-fetching credentials from the host. Called by the factory when
    /// a connection is instantiated (or has its credentials updated) with
    /// `client_id`/`client_secret` fields.
    pub async fn set_client_credentials(&self, client_id: String, client_secret: String) {
        self.set_client_credentials_inner(client_id, client_secret, || {})
            .await;
    }

    /// [`Self::set_client_credentials`] with an observation seam.
    ///
    /// `after_identity_bump` runs inside the critical section, holding BOTH the
    /// publication lock and the `client_credentials` write guard. Both are
    /// synchronous and non-reentrant, so the callback may not take either:
    /// calling [`Self::publication_lock`] from it — directly, or through a
    /// durable write such as `oauth_secret_store::persist_current_lineage` — is a
    /// self-deadlock on this very thread. Keep it to a bounded, lock-free
    /// observation.
    async fn set_client_credentials_inner(
        &self,
        client_id: String,
        client_secret: String,
        after_identity_bump: impl FnOnce(),
    ) {
        // Publication lock FIRST, before any credential guard, per the crate's
        // credential lock order: this bumps the identity generation, so it is an
        // identity-changing install and must not interleave a durable write.
        // Taking it first is what keeps a secret-store round trip off the credential
        // cells; taking it here but after the pair — while `replace_tokens_inner`
        // takes it first — would close the lock graph into a cycle and deadlock
        // the connection's whole credential path.
        let _publishing = self.publishing();
        // Keep the pair locked through the identity bump. Otherwise an
        // interleaving fenced interactive commit can observe the old generation,
        // clear the newly written pair, and silently win with stale credentials.
        let mut client_credentials = self.inner.client_credentials.write();
        let mut binding = self.binding_slot();
        *client_credentials = Some((client_id, client_secret));
        // An explicit credential update is an identity change: a slow
        // interactive flow dispatched before it must not clobber it.
        *binding = None;
        self.publish_live_credential(None);
        self.inner.identity_gen.fetch_add(1, Ordering::SeqCst);
        drop(binding);
        // The production observer is a no-op; the regression test uses this
        // point to pin that the pair is still locked after the bump.
        after_identity_bump();
        drop(client_credentials);
    }

    /// Read the cached `(client_id, client_secret)` pair, if any. Returns
    /// `None` for connections using the interactive / refresh-token grant
    /// or for anonymous connections.
    pub async fn client_credentials(&self) -> Option<(String, String)> {
        self.inner.client_credentials.read().clone()
    }

    /// Whether a *non-interactive* grant is available right now — a stored
    /// refresh token or a cached `client_credentials` pair. The driver's
    /// (sync) `classify` uses this to route a gRPC `UNAUTHENTICATED`
    /// (→ [`ErrorCode::AuthRequired`]) to a silent refresh + retry-once (the
    /// data-path recovery) instead of a dead-end interactive prompt when a
    /// refresh would recover. Uses non-blocking `try_read`; a momentarily
    /// write-locked slot reports `false` (the op then surfaces and the caller
    /// re-drives) rather than blocking the data path.
    pub fn has_silent_grant(&self) -> bool {
        let has_refresh = self
            .inner
            .refresh_token
            .try_read()
            .map(|g| g.as_ref().is_some_and(|t| !t.is_empty()))
            .unwrap_or(false);
        let has_client_credentials = self
            .inner
            .client_credentials
            .try_read()
            .map(|g| g.is_some())
            .unwrap_or(false);
        has_refresh || has_client_credentials
    }

    /// Seed only the refresh token slot — used by the warm-continue path
    /// where the caller has a stored refresh_token but no access_token yet
    /// and is about to drive a refresh-token grant.
    ///
    /// Under the publication lock like every other install, though it takes a
    /// single credential guard and so could not close the graph on its own: the
    /// crate's rule is a property of the SITE, not of how many locks it happens
    /// to need today, and a seam exempted from it is where a later slot write
    /// gets added in the wrong order.
    pub async fn install_refresh_token(&self, refresh_token: String) {
        let _publishing = self.publishing();
        *self.inner.refresh_token.write() = Some(refresh_token);
    }

    pub async fn install_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        // Publication lock FIRST, before every credential guard, per the crate's
        // credential lock order — see [`Self::publishing`].
        let _publishing = self.publishing();
        // Hold ALL credential write guards across the slot writes AND the
        // generation bump — in the same access→refresh→expires→client_credentials
        // order `replace_tokens_inner`/`install_tokens_if_identity_unchanged` use,
        // so no deadlock — so a concurrent identity-gen-guarded writer can never
        // observe a TORN set (slots written but `generation` not yet bumped)
        // (3539858147). On `None` refresh the slot is left unchanged (merge
        // semantics: the IdP legitimately omits an unchanged refresh token).
        let mut access = self.inner.access_token.write();
        let mut refresh = self.inner.refresh_token.write();
        let mut expires = self.inner.expires_at.write();
        let _client_credentials = self.inner.client_credentials.write();
        *access = Some(access_token);
        if let Some(rt) = refresh_token {
            *refresh = Some(rt);
        }
        *expires = expires_at;
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        drop((_client_credentials, expires, refresh, access));
        self.inner.token_arrived.notify_waiters();
    }

    /// [`Self::install_tokens`] (merge semantics: `None` refresh preserves the
    /// existing token, the cached `client_credentials` is untouched, and
    /// `identity_gen` is NOT bumped), but committed ONLY if the identity
    /// generation still equals `expected_identity_gen`. The compare happens while
    /// holding every credential write lock, so the check-then-install is atomic
    /// with respect to concurrent writers (no TOCTOU window). Returns whether the
    /// install was committed.
    ///
    /// This is the driver's `activate` primitive: it lands a PROVEN bring-up /
    /// refresh / warm-continue bearer on the live cell, fenced so a concurrent
    /// interactive success or explicit credential update (each an identity change
    /// that bumped `identity_gen`) is never regressed to this now-stale bundle. A
    /// `false` return means the bundle was superseded — the newer identity wins.
    pub async fn install_tokens_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        expected_identity_gen: u64,
    ) -> bool {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        // Publication lock FIRST, before every credential guard, per the crate's
        // credential lock order — see [`Self::publishing`]. This is the driver's
        // `activate` primitive, so it runs on every bring-up and every
        // background refresh: a durable write must not be able to interleave
        // between the fence read and the secret store write it guards.
        let _publishing = self.publishing();
        // Acquire ALL four write guards (same access→refresh→expires→
        // client_credentials order as the other writers) so the identity-gen
        // compare and the merge install are atomic against concurrent writers.
        let mut access = self.inner.access_token.write();
        let mut refresh = self.inner.refresh_token.write();
        let mut expires = self.inner.expires_at.write();
        let _client_credentials = self.inner.client_credentials.write();
        if self.inner.identity_gen.load(Ordering::SeqCst) != expected_identity_gen {
            return false;
        }
        *access = Some(access_token);
        if let Some(rt) = refresh_token {
            *refresh = Some(rt);
        }
        *expires = expires_at;
        self.publish_live_credential(refresh.as_deref());
        // Same-identity merge: bump only the plain `generation`, NOT `identity_gen`
        // (this is a routine bring-up/refresh, not an identity change), and leave
        // `client_credentials` untouched so a later M2M refresh still works.
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        drop((_client_credentials, expires, refresh, access));
        self.inner.token_arrived.notify_waiters();
        true
    }

    /// [`Self::install_tokens_if_identity_unchanged`], but ALSO caches the
    /// `(client_id, client_secret)` machine-to-machine pair on the live cell —
    /// atomically, under the SAME identity-gen guard, and WITHOUT bumping
    /// `identity_gen`. This is the driver's `activate` primitive for an M2M
    /// bring-up: the `client_credentials` grant ran on driver-PRIVATE staging, so
    /// the live cell never saw the pair; caching it here (rather than waiting for
    /// the first background `refresh`) makes [`Self::has_silent_grant`] report
    /// `true` IMMEDIATELY after bring-up, so the data-path recovery can
    /// re-drive the grant before the scheduler ever runs. A `false` return means
    /// a concurrent identity-changing write (interactive success / credential
    /// update) already won — the pair is NOT resurrected onto the live cell, and
    /// the newer identity stands.
    pub async fn install_tokens_and_client_credentials_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        client_id: String,
        client_secret: String,
        expected_identity_gen: u64,
    ) -> bool {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        // Publication lock FIRST, before every credential guard, per the crate's
        // credential lock order — see [`Self::publishing`]. This is the driver's
        // `activate` primitive, so it runs on every bring-up and every
        // background refresh: a durable write must not be able to interleave
        // between the fence read and the secret store write it guards.
        let _publishing = self.publishing();
        // Acquire ALL four write guards (same access→refresh→expires→
        // client_credentials order as the other writers) so the identity-gen
        // compare and the merge install are atomic against concurrent writers.
        let mut access = self.inner.access_token.write();
        let mut refresh = self.inner.refresh_token.write();
        let mut expires = self.inner.expires_at.write();
        let mut client_credentials = self.inner.client_credentials.write();
        if self.inner.identity_gen.load(Ordering::SeqCst) != expected_identity_gen {
            return false;
        }
        *access = Some(access_token);
        if let Some(rt) = refresh_token {
            *refresh = Some(rt);
        }
        *expires = expires_at;
        *client_credentials = Some((client_id, client_secret));
        self.publish_live_credential(refresh.as_deref());
        // Same-identity merge (M2M bring-up): bump only the plain `generation`,
        // NOT `identity_gen` — caching the replayable pair is not an identity
        // change and must not trip the interactive supersession guard.
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        drop((client_credentials, expires, refresh, access));
        self.inner.token_arrived.notify_waiters();
        true
    }

    /// **Replace** the credential state for an interactively-authenticated
    /// identity (3537944901): unlike the merge-style [`Self::install_tokens`]
    /// (which preserves the old refresh token on `None` and never touches the
    /// cached `client_credentials`), this OVERWRITES the refresh slot — including
    /// CLEARING it when the response carried none — and CLEARS the cached
    /// `client_credentials` pair. Interactive sign-in establishes a new identity,
    /// so a later background `refresh` must not silently revert to the previous
    /// service (client-credentials) or user (stale refresh) identity. Reserve the
    /// merge semantics of `install_tokens` for refresh-grant responses (where the
    /// IdP legitimately omits an unchanged refresh token).
    pub async fn replace_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        let _ = self
            .replace_tokens_inner(access_token, refresh_token, expires_in, None)
            .await;
    }

    /// [`Self::replace_tokens`], but committed ONLY if no identity-changing
    /// write landed since `expected_identity_gen` was observed — the compare
    /// happens while holding every credential write lock, so the
    /// check-then-install is atomic with respect to concurrent writers (no
    /// TOCTOU window). Returns whether the install was committed. The
    /// interactive flow thread uses this as its supersession guard.
    pub async fn replace_tokens_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        expected_identity_gen: u64,
    ) -> Option<u64> {
        self.replace_tokens_inner(
            access_token,
            refresh_token,
            expires_in,
            Some(expected_identity_gen),
        )
        .await
    }

    async fn replace_tokens_inner(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        expected_identity_gen: Option<u64>,
    ) -> Option<u64> {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        // Publication lock FIRST, before every credential guard and before the
        // binding mutex, per the crate's credential lock order: a durable write
        // and an identity-changing install must not interleave, the durable
        // write must not run under the identity fence itself, and a reader of
        // the credential cells must never end up queued behind an secret store
        // round trip.
        let _publishing = self.publishing();
        // Hold ALL credential write locks for the compare + install (writers
        // acquire in this same order, so no deadlock and no interleaving).
        let mut access = self.inner.access_token.write();
        let mut refresh = self.inner.refresh_token.write();
        let mut expires = self.inner.expires_at.write();
        let mut client_credentials = self.inner.client_credentials.write();
        // Hold the binding lock across the fence compare and the identity
        // bump. An identity-changing write clears the binding it supersedes, so
        // an observer taking this lock sees the binding and the generation
        // agree — never a previous account's record beside a generation that
        // has already moved on, which is what let a stale warm continuation
        // restore the wrong identity over a sign-in that had won.
        let mut binding = self.binding_slot();
        if let Some(expected) = expected_identity_gen
            && self.inner.identity_gen.load(Ordering::SeqCst) != expected
        {
            return None;
        }
        let published_identity_source = access_token.clone();
        let published_refresh = refresh_token.clone();
        *access = Some(access_token);
        *refresh = refresh_token;
        *expires = expires_at;
        // Interactive auth supersedes any machine-to-machine grant: drop it so a
        // later refresh drives the refresh-token grant, not the stale M2M one.
        *client_credentials = None;
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        // The identity is changing, so publish the one this very write is
        // installing — derived from the access token being stored, under
        // the same lock and in the same transaction as the generation bump.
        //
        // Leaving publication to the caller was a fenced transaction
        // followed by an unfenced publish: a superseded flow could still
        // install ITS binding afterwards, leaving the live token from one
        // account beside a binding (and then a stored secret) describing
        // another. Nothing outside this critical section can name the
        // identity of the credential inside it.
        *binding = Some(
            ovstorage_plugin::oauth_secret_store::identity_from_access_token(
                &published_identity_source,
                &self.inner.client_name,
            ),
        );
        self.publish_live_credential(published_refresh.as_deref());
        self.inner.identity_gen.fetch_add(1, Ordering::SeqCst);
        // The generation this write leaves behind, so the caller can hold a
        // lease on the identity it just established rather than on the one it
        // started at — which its own bump has already moved past.
        let generation = self.inner.identity_gen.load(Ordering::SeqCst);
        drop(binding);
        self.inner.token_arrived.notify_waiters();
        Some(generation)
    }

    /// Block until an access token is present, for a cold-start path that must
    /// defer its first auth-required call until interactive sign-in completes.
    ///
    /// The dynamic-roots watcher is the only such caller. Services discovery is
    /// NOT one: `fetch_service_endpoints` reads the token optionally and sends
    /// the request either way, so it never waits here.
    ///
    /// Nothing wakes this on a connection that will never hold a token, so a
    /// caller that can be in that position must not reach it — see
    /// `OmniverseStorageTransport::requires_bearer`.
    /// Uses the register-then-check pattern — `notify_waiters` doesn't
    /// store permits, so a naive `notified().await` after a None check
    /// would race with `install_tokens`.
    pub async fn wait_for_token(&self) {
        loop {
            let notified = self.inner.token_arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // An EMPTY access token is not a usable bearer — it is the
            // warm-continue placeholder shape (`oauth_bundle("", refresh)`).
            // Treating it as token-ready would release a credential-gated
            // waiter (e.g. the one-shot root watcher) to probe with an empty
            // bearer, fail UNAUTHENTICATED, and exit permanently — leaving the
            // connection with no routes even after a later interactive
            // sign-in succeeds.
            if self
                .access_token()
                .await
                .is_some_and(|token| !token.is_empty())
            {
                return;
            }
            notified.await;
        }
    }

    /// This connection's publication lock. See the crate's credential lock
    /// order: held across a durable write and across an identity-changing
    /// install, and never across an `.await`.
    pub fn publication_lock(&self) -> &std::sync::Mutex<()> {
        &self.inner.publication
    }

    /// The identity the live credential belongs to.
    pub fn current_binding(&self) -> Option<ovstorage_plugin::oauth_secret_store::IdentityBinding> {
        self.binding_slot().clone()
    }

    /// Record the identity an interactive sign-in established, discarding
    /// whatever the connection was bound to before. A sign-in establishes an
    /// identity rather than continuing one.
    pub fn set_binding(&self, binding: ovstorage_plugin::oauth_secret_store::IdentityBinding) {
        *self.binding_slot() = Some(binding);
    }

    /// Forget the binding, for credential removal and purge.
    pub fn clear_binding(&self) {
        *self.binding_slot() = None;
    }

    /// Record the refresh token the live cell now holds, so a later durable
    /// write can prove it carries THIS credential rather than a stale flow's.
    ///
    /// Called by every write that leaves the refresh slot assigned, while that
    /// slot's write guard is still held. Recording only at an identity change
    /// would leave the field naming the token live at the last sign-in: a
    /// background refresh rotates through the merge primitive, so the next
    /// persist would offer the successor, fail the compare, and strand the
    /// keyring on a predecessor the grant has already consumed.
    fn publish_live_credential(&self, refresh: Option<&str>) {
        *self
            .inner
            .published_credential
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            refresh.map(ovstorage_plugin::oauth_secret_store::fingerprint);
    }

    /// Enter the publication critical section — the FIRST lock every write to
    /// the live credential cell takes, ahead of every credential guard and the
    /// binding mutex, per the crate's credential lock order.
    ///
    /// Every install site calls this, not only the identity-changing ones. A
    /// same-identity merge moves `published_credential` and the refresh slot,
    /// which is exactly what `oauth_secret_store::persist_current_lineage` reads
    /// between its fence read and its keyring write; leaving the merge
    /// unserialized lets a rotation land in that gap and strand the secret store on
    /// a token the grant has already consumed. Routing every site through one
    /// method is also what keeps the order itself from being retyped
    /// differently at a sixth site.
    ///
    /// The guard must be taken BEFORE any credential guard, never after: these
    /// are synchronous, non-reentrant locks, so a single site taking a
    /// credential guard first closes the graph into a cycle and permanently
    /// deadlocks the connection's credential path. Nothing called while it is
    /// held may take it again, for the same reason.
    fn publishing(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner
            .publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn binding_slot(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<ovstorage_plugin::oauth_secret_store::IdentityBinding>>
    {
        self.inner
            .binding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Seed the expectation from a durable record, unless an identity-changing
    /// write landed since `expected_identity_gen` was read.
    ///
    /// Returns whether the record was adopted. The compare happens under the
    /// binding lock, which every identity-changing write holds across its
    /// generation bump, so a sign-in is either wholly visible here or not at
    /// all — a load that raced one is refused rather than half-applied.
    pub fn adopt_binding_if_identity_unchanged(
        &self,
        binding: ovstorage_plugin::oauth_secret_store::IdentityBinding,
        expected_identity_gen: u64,
    ) -> bool {
        let mut slot = self.binding_slot();
        if self.inner.identity_gen.load(Ordering::SeqCst) != expected_identity_gen {
            return false;
        }
        *slot = Some(binding);
        true
    }

    /// Check a freshly authenticated identity against the binding, unless an
    /// identity-changing write landed since `expected_identity_gen` was read.
    ///
    /// `Ok(false)` means superseded: the caller skips rather than failing, so a
    /// grant that lost the race is not reported as an impostor against the
    /// connection that won. `Err` means the session really did authenticate as
    /// somebody else. Both the generation compare and the check run under the
    /// binding lock, so an install cannot be observed half-applied — the window
    /// in which a winner has recorded its identity but not yet bumped the
    /// generation is not observable from here.
    pub fn observe_binding_unless_superseded(
        &self,
        observed: ovstorage_plugin::oauth_secret_store::IdentityBinding,
        expected_identity_gen: u64,
    ) -> Result<bool> {
        let mut slot = self.binding_slot();
        #[cfg(test)]
        {
            let gate = self
                .inner
                .binding_observation_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(gate) = gate {
                gate(self);
            }
        }
        if self.inner.identity_gen.load(Ordering::SeqCst) != expected_identity_gen {
            return Ok(false);
        }
        match slot.as_ref() {
            Some(stored) => {
                stored.verify(&observed)?;
                *slot = Some(stored.merged(&observed));
            }
            None => *slot = Some(observed),
        }
        Ok(true)
    }

    /// Test seam invoked inside the binding-locked section of
    /// [`Self::observe_binding_unless_superseded`], so a test can assert the
    /// generation compare really is guarded.
    #[cfg(test)]
    pub fn set_binding_observation_gate(&self, gate: Option<BindingObservationGate>) {
        *self
            .inner
            .binding_observation_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = gate;
    }

    /// Whether the binding lock is currently held.
    #[cfg(test)]
    pub fn binding_lock_is_held(&self) -> bool {
        self.inner.binding.try_lock().is_err()
    }

    pub async fn install_auth_config(&self, config: AuthConfig) {
        *self.inner.auth_config.write().await = Some(config);
    }

    pub async fn install_oidc_config(&self, config: OidcConfig) {
        *self.inner.oidc_config.write().await = Some(config);
    }

    pub async fn token_needs_refresh(&self) -> bool {
        let token = self.inner.access_token.read();
        let expires_at = self.inner.expires_at.read();
        let needs = match (token.as_ref(), *expires_at) {
            (None, _) => true,
            // An empty access token is not a usable bearer — this is the
            // warm-continue shape (`oauth_bundle("", Some(refresh), None)`),
            // where a stored refresh token seeds the state but no access token
            // has been minted yet. Treat it as needing refresh so
            // `seed_connection_auth` drives the refresh-token grant rather than
            // reporting `Authenticated` with an empty `Bearer` that fails every
            // RPC with UNAUTHENTICATED.
            (Some(t), _) if t.is_empty() => true,
            (Some(_), None) => false,
            (Some(_), Some(at)) => SystemTime::now() + REFRESH_SKEW >= at,
        };
        if needs {
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.auth",
                plugin = "omniverse-storage-service",
                cache.hit = false,
                cache.kind = "oauth_token",
                "omniverse-storage-service: token cache miss — refresh required",
            );
        } else {
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.auth",
                plugin = "omniverse-storage-service",
                cache.hit = true,
                cache.kind = "oauth_token",
                "omniverse-storage-service: token cache hit",
            );
        }
        needs
    }
}

#[derive(Clone)]
pub struct AuthorizationInterceptor {
    state: DiscoveryState,
}

impl AuthorizationInterceptor {
    pub fn new(state: DiscoveryState) -> Self {
        Self { state }
    }
}

/// The `authorization` header value carrying `token`, and the token as it will
/// actually be sent.
///
/// `None` means `token` cannot ride in an HTTP header at all. The predicate is
/// `HeaderValue`'s own and it is narrower than "ASCII": a field value may carry
/// horizontal tab, `0x20..=0x7e`, and the obs-text range `0x80..=0xff`, so what
/// it refuses is the CONTROL characters — notably CR and LF, which is what a
/// token read out of a file arrives with. Non-ASCII bytes are accepted here, and
/// naming them as the refused case is a claim this function does not make.
///
/// **Leading and trailing ASCII whitespace is dropped, and that is a repair
/// rather than a liberty.** RFC 6750 spells a bearer token as `b64token`, whose
/// alphabet admits no whitespace, so trimming can destroy no legal token; the
/// commonest way to acquire some is a secret read out of a file or a Kubernetes
/// secret, which arrives with a trailing newline; and HTTP strips the leading
/// and trailing whitespace a header value could legally carry anyway, so this
/// only extends that to the spellings a header value cannot carry.
///
/// **Both callers must agree, which is why there is one function.**
/// [`AuthorizationInterceptor`] puts the value on every RPC, and the driver
/// refuses a configured token this rejects, so a token accepted when it is
/// configured cannot fail *on header legality* when it is sent. That is the
/// only property claimed — a token can be legal here and still rejected further
/// down, since h2 caps the header list size and a very large JWT builds fine
/// and fails at the transport. Two predicates here would let a
/// token pass configuration and then fail every RPC — and on the direct path
/// that failure is fatal to host startup rather than to one connection.
///
/// Emptiness is deliberately NOT decided here: an empty token means "send no
/// header" to the interceptor and "no bearer offered" to the driver, and those
/// are different answers. Each caller checks the returned token itself.
pub fn bearer_header(token: &str) -> Option<(&str, MetadataValue<tonic::metadata::Ascii>)> {
    let trimmed = token.trim_matches(|c: char| c.is_ascii_whitespace());
    // Exact-size, rather than `format!`: the buffer holds a credential and a
    // reallocating build leaves a copy of it in freed heap.
    let mut header = String::with_capacity("Bearer ".len() + trimmed.len());
    header.push_str("Bearer ");
    header.push_str(trimmed);
    MetadataValue::try_from(header.as_str())
        .ok()
        .map(|value| (trimmed, value))
}

impl Interceptor for AuthorizationInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        // Sync interceptor: try_read avoids blocking under refresh contention.
        //
        // A miss emits NO Authorization header, so the RPC comes back
        // UNAUTHENTICATED and `classify` — whose `has_silent_grant` also
        // `try_read`s — reports `NeedsInteractive` and prompts the user. That
        // makes the width of the contended write window a correctness property,
        // not a latency one: it must stay bounded by the in-memory swap in
        // `replace_tokens_inner`. It is bounded precisely because the
        // publication lock is taken BEFORE these guards (see the crate's
        // credential lock order), so an installer waiting on a keyring round
        // trip is not holding the access-token cell while it waits.
        let token = match self.state.inner.access_token.try_read() {
            Some(guard) => guard.clone(),
            None => None,
        };
        // An EMPTY access token is not a bearer, and emitting `Bearer ` for one
        // is worse than emitting nothing: it is a malformed credential the
        // server must reject, where an absent header is a well-formed
        // anonymous request the deployment may serve. Two ways to arrive at
        // one, and they are unrelated: the warm-continue placeholder shape
        // (`oauth_bundle("", Some(refresh))`, which `wait_for_token` also
        // refuses to treat as a token), and a credential REMOVAL, which clears
        // the cell by installing an empty string.
        if let Some(token) = token {
            match bearer_header(&token) {
                // Emptiness is read off the token as it would be SENT, so a cell
                // holding only whitespace is the empty case above rather than a
                // `Bearer` header with nothing after it.
                Some(("", _)) => {}
                Some((_, value)) => {
                    request.metadata_mut().insert("authorization", value);
                }
                // Reachable only from the discovery path, which takes its token
                // from the IDP's response. A configured token that cannot ride
                // in a header is refused by `driver::direct_bearer` when it is
                // accepted, so it never arrives here.
                None => {
                    return Err(Status::internal(
                        "omniverse-storage-service: access token contains characters \
                         invalid in an HTTP header",
                    ));
                }
            }
        }
        Ok(request)
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

pub async fn fetch_auth_config(
    client: &reqwest::Client,
    discovery_url: &str,
) -> Result<AuthConfig> {
    let trimmed = discovery_url.trim_end_matches('/');
    let url = format!("{trimmed}/api/v1/auth-config");
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: fetching auth-config",
    );
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: auth-config fetch failed for {url}: {err}"),
        )
    })?;
    if response.status().as_u16() == 404 {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "omniverse-storage-service: {url} returned 404 (server publishes no auth-config)"
            ),
        ));
    }
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::Transient,
            format!(
                "omniverse-storage-service: auth-config returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: auth-config body read failed: {err}"),
        )
    })?;
    let parsed = serde_json::from_slice::<AuthConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("omniverse-storage-service: auth-config JSON parse failed: {err}"),
        )
    })?;
    tracing::trace!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        url = %url,
        auth_config = ?parsed,
        "omniverse-storage-service: /api/v1/auth-config response body",
    );
    Ok(parsed)
}

pub async fn fetch_oidc_config(
    client: &reqwest::Client,
    auth_config: &AuthConfig,
) -> Result<OidcConfig> {
    let url = auth_config
        .openid_configuration
        .trim_end_matches('/')
        .to_string();
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: fetching OIDC discovery",
    );
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: OIDC discovery fetch failed for {url}: {err}"),
        )
    })?;
    let response = if response.status().is_success() {
        response
    } else {
        let alt = format!("{url}/.well-known/openid-configuration");
        client.get(&alt).send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: OIDC discovery fetch failed for {alt}: {err}"),
            )
        })?
    };
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "omniverse-storage-service: OIDC discovery returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: OIDC discovery body read failed: {err}"),
        )
    })?;
    serde_json::from_slice::<OidcConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("omniverse-storage-service: OIDC discovery JSON parse failed: {err}"),
        )
    })
}

pub async fn drive_refresh_token_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let span = tracing::debug_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        outcome = tracing::field::Empty,
    );
    async move {
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.auth",
            plugin = "omniverse-storage-service",
            "omniverse-storage-service: refresh token grant triggered",
        );
        let result = drive_refresh_token_grant_inner(client, state).await;
        match &result {
            Ok(_) => {
                tracing::span::Span::current().record("outcome", "ok");
                tracing::info!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    "omniverse-storage-service: token refreshed",
                );
            }
            Err(err) => {
                tracing::span::Span::current().record("outcome", "err");
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    error.code = ?err.code(),
                    "omniverse-storage-service: refresh token grant failed",
                );
            }
        }
        result
    }
    .instrument(span)
    .await
}

async fn drive_refresh_token_grant_inner(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: refresh requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: refresh requested but auth-config not loaded",
        )
    })?;
    let refresh_token = state.refresh_token().await.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: refresh requested but no refresh_token is stored",
        )
    })?;
    let client_id = auth_config
        .clients
        .get(state.client_name())
        .map(|c| c.client_id.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(scope) = auth_config
        .clients
        .get(state.client_name())
        .and_then(|c| c.scope.clone())
    {
        form.push(("scope", scope));
    }
    let response = client
        .post(&oidc.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body);
        let code = if status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_grant"))
        {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        return Err(Error::new(
            code,
            format!(
                "omniverse-storage-service: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            token_response.refresh_token,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// Drive an OAuth2 `client_credentials` grant against the IDP's token
/// endpoint. Used for machine-to-machine identities that authenticate
/// with a `(client_id, client_secret)` pair instead of an interactive
/// user sign-in. On success the response's access token is installed on
/// `state` via `install_tokens`; a refresh token is rarely issued for
/// this grant type (and is not required since the grant can be
/// re-driven from the cached credentials).
pub async fn drive_client_credentials_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
    client_id: &str,
    client_secret: &str,
) -> Result<u64> {
    let span = tracing::debug_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        grant = "client_credentials",
        outcome = tracing::field::Empty,
    );
    async move {
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.auth",
            plugin = "omniverse-storage-service",
            "omniverse-storage-service: client_credentials grant triggered",
        );
        let result =
            drive_client_credentials_grant_inner(client, state, client_id, client_secret).await;
        match &result {
            Ok(_) => {
                tracing::span::Span::current().record("outcome", "ok");
                tracing::info!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    "omniverse-storage-service: client_credentials grant succeeded",
                );
            }
            Err(err) => {
                tracing::span::Span::current().record("outcome", "err");
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    error.code = ?err.code(),
                    "omniverse-storage-service: client_credentials grant failed",
                );
            }
        }
        result
    }
    .instrument(span)
    .await
}

async fn drive_client_credentials_grant_inner(
    client: &reqwest::Client,
    state: &DiscoveryState,
    client_id: &str,
    client_secret: &str,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: client_credentials grant requested but OIDC config not loaded",
        )
    })?;
    // auth-config is optional for this grant — the caller supplies the
    // client_id/client_secret directly — but if it's loaded and has a
    // scope for the configured client, honour it. This mirrors the
    // refresh-token grant's scope handling so server-side enforcement
    // sees the same scope on both grants.
    let scope = state
        .auth_config()
        .await
        .and_then(|cfg| cfg.clients.get(state.client_name()).cloned())
        .and_then(|client| client.scope);
    let mut form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id.to_string()),
        ("client_secret", client_secret.to_string()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let response = client
        .post(&oidc.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body);
        let code = if status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_client"))
        {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        return Err(Error::new(
            code,
            format!(
                "omniverse-storage-service: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            token_response.refresh_token,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// Drive an interactive OIDC login (PKCE on `Browser`, RFC 8628 device flow
/// Pick the OIDC URL that maps to `OAuthEndpoints.authorization_endpoint`
/// for the given capability. PKCE wants the IDP's
/// `authorization_endpoint`; the device-code flow wants
/// `device_authorization_endpoint` — the host's field is overloaded
/// (see `ovstorage::auth::flow::run_device_flow`). Wiring PKCE's URL
/// to the device flow makes the client POST the device-code request
/// to `/authorize`, which the IDP rejects.
fn endpoint_for_capability(
    oidc: &OidcConfig,
    capability: InteractiveAuthCapability,
) -> Result<&str> {
    match capability {
        InteractiveAuthCapability::Browser => {
            oidc.authorization_endpoint.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "omniverse-storage-service: IDP discovery missing authorization_endpoint \
                 (required for PKCE / browser flow)",
                )
            })
        }
        InteractiveAuthCapability::Headless => oidc
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "omniverse-storage-service: IDP discovery missing \
                     device_authorization_endpoint (required for headless / device-code flow)",
                )
            }),
        InteractiveAuthCapability::None => Err(Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: host declared no interactive auth capability",
        )),
    }
}

/// on `Headless`) using the shared `ovstorage::OAuthFlow` infra. The
/// `AuthEvent` stream is bridged from async (BoxStream) to the sync iterator
/// the SPI expects via a dedicated thread + per-bridge tokio runtime — both
/// flows park waiting on a user action, so collecting first would deadlock
/// the prompt.
/// Persist the interactively-minted refresh token durably (keyring), invoked in
/// the flow thread BEFORE the terminal `Succeeded` is forwarded (3537945622).
/// `None` clears the stored token.
///
/// The access token carries the identity claims the persisted lineage is bound
/// to, so the sink records the account alongside the secret. A failure is
/// reported rather than swallowed; the caller logs it and still forwards
/// success, since the in-memory tokens are authoritative for this process and
/// the set-side persist retries.
pub type PersistRefresh = Arc<dyn Fn(&str, Option<String>, u64) -> Result<()> + Send + Sync>;

pub async fn drive_interactive_login(
    state: &DiscoveryState,
    connection: Connection,
    capability: InteractiveAuthCapability,
    persist: PersistRefresh,
    liveness: Option<CancellationToken>,
) -> Result<AuthEventStream> {
    let span = tracing::info_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        outcome = tracing::field::Empty,
    );
    let _guard = span.enter();

    if matches!(capability, InteractiveAuthCapability::None) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: host declared no interactive auth capability",
        ));
    }
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: interactive login requested but auth-config not loaded",
        )
    })?;
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: interactive login requested but OIDC discovery not loaded",
        )
    })?;
    let client = auth_config
        .clients
        .get(state.client_name())
        .cloned()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    // The host's `OAuthEndpoints.authorization_endpoint` is overloaded:
    // for PKCE flow it is the OIDC `authorization_endpoint`; for the
    // device-code flow it is the OIDC `device_authorization_endpoint`.
    // Choose by capability so headless auth POSTs the device-code
    // request to the right URL (was using `/authorize` for both).
    let endpoint_str = endpoint_for_capability(&oidc, capability)?;
    let endpoints = ovstorage::OAuthEndpoints {
        authorization_endpoint: url::Url::parse(endpoint_str).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: malformed authorization_endpoint: {err}"),
            )
        })?,
        token_endpoint: url::Url::parse(&oidc.token_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: malformed token_endpoint: {err}"),
            )
        })?,
        client_id: client.client_id,
        scope: client.scope,
    };
    tracing::info!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: interactive OAuth flow started",
    );
    let connection_id: ConnectionId = connection.id.clone();
    let backend_id = BackendId(format!("omniverse-storage-service:{}", state.client_name()));
    let flow = match capability {
        InteractiveAuthCapability::Headless => {
            ovstorage::OAuthFlow::device(backend_id).with_connection(connection_id)
        }
        InteractiveAuthCapability::Browser => {
            // Path matches the omniverse-storage-service AAD app's registered redirect URI.
            let redirect_base = url::Url::parse("http://127.0.0.1/openid").map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("omniverse-storage-service: redirect base parse: {err}"),
                )
            })?;
            ovstorage::OAuthFlow::pkce(backend_id, redirect_base).with_connection(connection_id)
        }
        InteractiveAuthCapability::None => unreachable!("checked above"),
    };
    let flow = flow.with_endpoints(endpoints);
    tracing::info!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: interactive OAuth flow dispatched to bridge thread",
    );
    // Clone the shared token cell into the flow thread so a successful sign-in
    // installs the freshly-minted access/refresh tokens into the *same*
    // `DiscoveryState` the transport's `AuthorizationInterceptor` reads. Without
    // this the `ConnectionSet` records the credentials on the connection but the
    // live transport keeps sending the pre-login (empty/stale) bearer, so the
    // very next RPC fails UNAUTHENTICATED.
    let install_state = state.clone();
    // Capture the IDENTITY generation at flow start. A slow / abandoned /
    // superseded interactive flow must NOT overwrite a newer identity-changing
    // credential update that landed on the shared cell while the user was
    // signing in (3537944750) — but a routine same-identity refresh grant
    // (`install_tokens` merge) completing mid-sign-in must NOT trip the guard
    // (3539557310): the freshly-minted sign-in tokens still win. The compare
    // itself happens inside `replace_tokens_if_identity_unchanged`, under the
    // credential write locks, so there is no check-then-act window.
    let identity_gen_at_start = state.identity_generation();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ovs-oms-auth".into())
        .spawn(move || {
            use futures::StreamExt;
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = sender.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!(
                            "omniverse-storage-service: failed to create OAuth flow runtime: {err}"
                        ),
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                match flow.run().await {
                    Ok(mut stream) => {
                        while let Some(event) = stream.next().await {
                            // On success, land the tokens on the transport cell
                            // AND persist the refresh token durably BEFORE
                            // forwarding the event, so the connection is usable
                            // and the secret is saved the instant `Succeeded` is
                            // observed (3537945622 — persist-before-Succeeded).
                            // A `Succeeded` whose install is NOT committed —
                            // superseded by a newer identity, or the connection
                            // was removed mid-flow — is downgraded to
                            // `Succeeded { credentials: None }` so the generic
                            // adapter's keep-creds branch transitions state
                            // WITHOUT swapping the entry bundle or persisting
                            // the losing tokens (3539558503): entry and keyring
                            // stay consistent with the winning update.
                            let event = match event {
                                Ok(AuthEvent::Succeeded {
                                    connection,
                                    credentials: Some(bundle),
                                }) => {
                                    let mut committed = false;
                                    // The generation this flow's OWN commit
                                    // established; the persist leases on that.
                                    #[allow(unused_assignments)]
                                    let mut committed_generation = 0u64;
                                    // Set when this flow's own commit succeeded but
                                    // another identity landed before its credential
                                    // could be published.
                                    let mut superseded_before_publish = false;
                                    // Liveness fence (3539558624): the token is a
                                    // child of the ConnectionSet entry's lifecycle
                                    // token, cancelled by `remove_connection` — a
                                    // sign-in completing after removal must not
                                    // re-persist the secret removal just deleted.
                                    let live =
                                        liveness.as_ref().is_none_or(|token| !token.is_cancelled());
                                    if live
                                        && let Some(SecretValue::OAuthToken {
                                            token,
                                            refresh,
                                            expires_at,
                                        }) = bundle.fields.get("oauth")
                                        && let Ok(access) = std::str::from_utf8(&token.0)
                                        && !access.is_empty()
                                    {
                                        let refresh = refresh
                                            .as_ref()
                                            .and_then(|r| std::str::from_utf8(&r.0).ok())
                                            .map(str::to_owned);
                                        let expires_in = expires_at.and_then(|at| {
                                            at.duration_since(SystemTime::now()).ok()
                                        });
                                        // 944901: REPLACE (not merge) — interactive
                                        // auth establishes a new identity, clearing
                                        // any cached client-credentials grant and
                                        // overwriting the refresh slot, so a later
                                        // refresh cannot revert the identity.
                                        // 944750/3539557310: committed only if no
                                        // newer IDENTITY-changing update landed,
                                        // compared under the write locks.
                                        let outcome = install_state
                                            .replace_tokens_if_identity_unchanged(
                                                access.to_owned(),
                                                refresh.clone(),
                                                expires_in,
                                                identity_gen_at_start,
                                            )
                                            .await;
                                        committed = outcome.is_some();
                                        committed_generation = outcome.unwrap_or_default();
                                        if committed {
                                            // 945622: persist synchronously before
                                            // the terminal event is forwarded.
                                            // The in-memory tokens are already
                                            // installed and authoritative for
                                            // this process, so a keyring failure
                                            // is reported and the sign-in still
                                            // succeeds; the set-side persist
                                            // retries, and its failure is the one
                                            // that propagates.
                                            //
                                            // `committed` was true when this flow's
                                            // own commit ran; another may have
                                            // committed since. The persist carries
                                            // this flow's identity lease and answers
                                            // `AuthCancelled` when it has, which is
                                            // also the answer to whether this bundle
                                            // may still be published.
                                            match persist(
                                                access,
                                                refresh.clone(),
                                                committed_generation,
                                            ) {
                                                Ok(()) => {}
                                                Err(err)
                                                    if err.code() == ErrorCode::AuthCancelled =>
                                                {
                                                    superseded_before_publish = true;
                                                }
                                                Err(err) => {
                                                    tracing::warn!(
                                                        target: "ovstorage.omniverse_storage_service.auth",
                                                        plugin = "omniverse-storage-service",
                                                        error = %err.message(),
                                                        "interactive refresh-token persist failed; \
                                                         durable store not updated (memory \
                                                         authoritative)"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    if committed && !superseded_before_publish {
                                        Ok(AuthEvent::Succeeded {
                                            connection,
                                            credentials: Some(bundle),
                                        })
                                    } else {
                                        tracing::info!(
                                            target: "ovstorage.omniverse_storage_service.auth",
                                            plugin = "omniverse-storage-service",
                                            "interactive sign-in not committed (superseded or \
                                             connection removed); forwarding Succeeded without \
                                             credentials",
                                        );
                                        Ok(AuthEvent::Succeeded {
                                            connection,
                                            credentials: None,
                                        })
                                    }
                                }
                                other => other,
                            };
                            if sender.send(event).is_err() {
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        let _ = sender.send(Err(err.into_error()));
                    }
                }
            });
        })
        .expect("failed to spawn thread");
    Ok(Box::new(receiver.into_iter()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::connection::credential_lock_order::{
        PublicationLockHolder, RequestPathObservation,
        assert_a_keyring_persist_leaves_the_request_path_intact,
        assert_install_racing_a_credential_update_cannot_deadlock,
    };

    #[tokio::test]
    async fn install_tokens_bumps_generation() {
        let state = DiscoveryState::new("default");
        assert_eq!(state.generation(), 0);
        state
            .install_tokens(
                "at1".into(),
                Some("rt1".into()),
                Some(Duration::from_secs(3600)),
            )
            .await;
        assert_eq!(state.generation(), 1);
        assert_eq!(state.access_token().await.as_deref(), Some("at1"));
        assert_eq!(state.refresh_token().await.as_deref(), Some("rt1"));
        // Refresh preserved when install_tokens doesn't supply one.
        state
            .install_tokens("at2".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert_eq!(state.generation(), 2);
        assert_eq!(state.refresh_token().await.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn token_needs_refresh_handles_unset_and_skew() {
        let state = DiscoveryState::new("default");
        assert!(state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert!(!state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(30)))
            .await;
        assert!(state.token_needs_refresh().await);
    }

    #[tokio::test]
    async fn interceptor_injects_bearer_when_token_present() {
        let state = DiscoveryState::new("default");
        state.install_tokens("token123".into(), None, None).await;
        let mut interceptor = AuthorizationInterceptor::new(state);
        let request: Request<()> = Request::new(());
        let intercepted = interceptor.call(request).unwrap();
        let auth = intercepted.metadata().get("authorization").unwrap();
        assert_eq!(auth.to_str().unwrap(), "Bearer token123");
    }

    #[tokio::test]
    async fn interceptor_passes_through_when_no_token() {
        let state = DiscoveryState::new("default");
        let mut interceptor = AuthorizationInterceptor::new(state);
        let request: Request<()> = Request::new(());
        let intercepted = interceptor.call(request).unwrap();
        assert!(intercepted.metadata().get("authorization").is_none());
    }

    /// An empty access token is a cell that holds no bearer, not a bearer whose
    /// value is empty. `Bearer ` is a malformed credential the server must
    /// reject, where no header at all is a well-formed anonymous request.
    ///
    /// Two live sources of an empty cell, arrived at independently: the
    /// warm-continue placeholder bundle, and a credential removal — which
    /// clears the cell by installing an empty string, and would otherwise leave
    /// a connection that reports anonymous sending a broken header on every
    /// request.
    ///
    /// Mutation control, run: dropping the `.filter(|t| !t.is_empty())` from the
    /// interceptor reddens this test and
    /// `direct_endpoint::a_host_can_remove_a_direct_connections_bearer`, and
    /// nothing else.
    #[tokio::test]
    async fn interceptor_sends_no_header_for_an_empty_token() {
        let state = DiscoveryState::new("default");
        state.install_tokens(String::new(), None, None).await;
        assert_eq!(
            state.access_token().await,
            Some(String::new()),
            "the cell must actually hold an empty token, or this proves nothing",
        );
        let mut interceptor = AuthorizationInterceptor::new(state);
        let intercepted = interceptor.call(Request::new(())).unwrap();
        assert!(
            intercepted.metadata().get("authorization").is_none(),
            "an empty token must produce no header at all, not `Bearer `",
        );
    }

    #[tokio::test]
    async fn set_and_read_client_credentials_round_trips() {
        let state = DiscoveryState::new("default");
        assert!(state.client_credentials().await.is_none());
        state
            .set_client_credentials("svc-id".into(), "svc-secret".into())
            .await;
        assert_eq!(
            state.client_credentials().await,
            Some(("svc-id".into(), "svc-secret".into()))
        );
    }

    #[tokio::test]
    async fn set_client_credentials_holds_pair_lock_through_identity_bump() {
        let state = DiscoveryState::new("default");
        let stale_identity_gen = state.identity_generation();
        let observed = state.clone();

        state
            .set_client_credentials_inner("new-id".into(), "new-secret".into(), move || {
                assert_eq!(
                    observed.identity_generation(),
                    stale_identity_gen + 1,
                    "the hook runs after the new identity generation is visible",
                );
                assert!(
                    observed.inner.client_credentials.try_read().is_none(),
                    "the credential pair must remain locked when the identity bump becomes visible",
                );
            })
            .await;

        let committed = state
            .replace_tokens_if_identity_unchanged(
                "stale-interactive".into(),
                Some("stale-refresh".into()),
                None,
                stale_identity_gen,
            )
            .await;
        assert!(
            committed.is_none(),
            "the stale interactive commit must be fenced out"
        );
        assert_eq!(
            state.client_credentials().await,
            Some(("new-id".into(), "new-secret".into())),
            "the explicit credential update must remain installed",
        );
    }

    /// Stand up a single-shot token endpoint that captures the form body
    /// and replies with a canned `TokenResponse`. Asserts the body shape
    /// produced by `drive_client_credentials_grant` matches RFC 6749 §4.4
    /// (`grant_type=client_credentials&client_id=…&client_secret=…`) and
    /// that the access token lands in the state.
    #[tokio::test]
    async fn client_credentials_grant_form_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            // Read headers, then continue reading until we have a full
            // body matching Content-Length.
            let mut content_length: Option<usize> = None;
            let mut header_end: Option<usize> = None;
            while total < buf.len() {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    header_end = Some(idx + 4);
                    let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                    for line in header_str.lines() {
                        if let Some(value) = line
                            .strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length)
                    && total >= hend + cl
                {
                    break;
                }
            }
            let header_end = header_end.unwrap_or(total);
            let body = String::from_utf8_lossy(&buf[header_end..total]).to_string();
            let _ = body_tx.send(body);
            let response_body =
                r#"{"access_token":"cc-access","token_type":"Bearer","expires_in":300}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let state = DiscoveryState::new("default");
        state
            .install_oidc_config(OidcConfig {
                issuer: "http://test".into(),
                token_endpoint: token_endpoint.clone(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let http = reqwest::Client::new();
        let generation =
            drive_client_credentials_grant(&http, &state, "svc-client", "svc-secret-shhh")
                .await
                .expect("grant succeeds");
        assert_eq!(generation, 1, "install_tokens must bump generation to 1");
        assert_eq!(
            state.access_token().await.as_deref(),
            Some("cc-access"),
            "access token must be installed",
        );

        let body = body_rx.await.expect("server captured form body");
        // Parse the URL-encoded form body so we don't depend on field order.
        let pairs: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            pairs.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("svc-client")
        );
        assert_eq!(
            pairs.get("client_secret").map(String::as_str),
            Some("svc-secret-shhh"),
        );
        // No auth-config installed → no scope field on the wire.
        assert!(
            !pairs.contains_key("scope"),
            "scope absent when no auth-config"
        );
    }

    /// When auth-config carries a `scope` for the configured client, the
    /// grant must include it on the wire so server-side enforcement matches
    /// the refresh-token grant path.
    #[tokio::test]
    async fn client_credentials_grant_includes_scope_when_configured() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            let mut content_length: Option<usize> = None;
            let mut header_end: Option<usize> = None;
            while total < buf.len() {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    header_end = Some(idx + 4);
                    let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                    for line in header_str.lines() {
                        if let Some(value) = line
                            .strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length)
                    && total >= hend + cl
                {
                    break;
                }
            }
            let header_end = header_end.unwrap_or(total);
            let body = String::from_utf8_lossy(&buf[header_end..total]).to_string();
            let _ = body_tx.send(body);
            let response_body = r#"{"access_token":"cc-2","expires_in":300}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let state = DiscoveryState::new("default");
        let mut clients = std::collections::BTreeMap::new();
        clients.insert(
            "default".to_string(),
            AuthClientConfig {
                client_id: "ignored-default-client".into(),
                scope: Some("storage.read storage.write".into()),
            },
        );
        state
            .install_auth_config(AuthConfig {
                openid_configuration: "http://test".into(),
                clients,
            })
            .await;
        state
            .install_oidc_config(OidcConfig {
                issuer: "http://test".into(),
                token_endpoint: token_endpoint.clone(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let http = reqwest::Client::new();
        drive_client_credentials_grant(&http, &state, "svc-id", "svc-secret")
            .await
            .expect("grant succeeds");
        let body = body_rx.await.expect("captured");
        let pairs: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            pairs.get("scope").map(String::as_str),
            Some("storage.read storage.write"),
        );
    }

    fn oidc_with(auth: Option<&str>, device: Option<&str>) -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
            authorization_endpoint: auth.map(str::to_string),
            device_authorization_endpoint: device.map(str::to_string),
            end_session_endpoint: None,
        }
    }

    /// Browser/PKCE flow uses the OIDC `authorization_endpoint`.
    #[test]
    fn endpoint_for_capability_browser_picks_authorization_endpoint() {
        let oidc = oidc_with(
            Some("https://idp.example/authorize"),
            Some("https://idp.example/device"),
        );
        let url = endpoint_for_capability(&oidc, InteractiveAuthCapability::Browser).unwrap();
        assert_eq!(url, "https://idp.example/authorize");
    }

    /// Headless/device flow uses the OIDC `device_authorization_endpoint`
    /// — NOT `authorization_endpoint`. The host's OAuthEndpoints field
    /// is overloaded for device flow.
    #[test]
    fn endpoint_for_capability_headless_picks_device_endpoint() {
        let oidc = oidc_with(
            Some("https://idp.example/authorize"),
            Some("https://idp.example/device"),
        );
        let url = endpoint_for_capability(&oidc, InteractiveAuthCapability::Headless).unwrap();
        assert_eq!(
            url, "https://idp.example/device",
            "device flow must POST to the device_authorization_endpoint, \
             not the authorization_endpoint",
        );
    }

    #[test]
    fn endpoint_for_capability_browser_missing_endpoint_errors() {
        let oidc = oidc_with(None, Some("https://idp.example/device"));
        let err = endpoint_for_capability(&oidc, InteractiveAuthCapability::Browser).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("authorization_endpoint"));
    }

    #[test]
    fn endpoint_for_capability_headless_missing_endpoint_errors() {
        let oidc = oidc_with(Some("https://idp.example/authorize"), None);
        let err = endpoint_for_capability(&oidc, InteractiveAuthCapability::Headless).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("device_authorization_endpoint"));
    }

    /// This crate's `DiscoveryState` is one of the two shapes the shared
    /// lock-order harnesses hold: an `Arc`-backed handle over a
    /// `std::sync::Mutex<()>` publication lock. That is the entire vocabulary
    /// those harnesses need, which is why they can live in `ovstorage-plugin`
    /// instead of once per driver crate.
    impl PublicationLockHolder for DiscoveryState {
        fn publication_lock(&self) -> &std::sync::Mutex<()> {
            DiscoveryState::publication_lock(self)
        }
    }

    /// A fresh state per round, with the identity generation an install fences
    /// on.
    fn state_and_fence() -> (DiscoveryState, u64) {
        let state = DiscoveryState::new("default");
        let expected_identity_gen = state.identity_generation();
        (state, expected_identity_gen)
    }

    /// The racing writer in every lock-order round: the site that takes the
    /// `client_credentials` guard on its own.
    async fn racing_client_credentials_update(state: DiscoveryState) {
        state
            .set_client_credentials("svc-id".into(), "svc-secret".into())
            .await;
    }

    /// One install site per test, all four against the same racing
    /// client-credentials update. The cycle, the deadline and the diagnosis
    /// come from the shared harness; only the site differs.
    #[test]
    fn client_credentials_update_racing_a_fenced_install_cannot_deadlock() {
        assert_install_racing_a_credential_update_cannot_deadlock(
            "replace_tokens_if_identity_unchanged",
            state_and_fence,
            |state, expected_identity_gen| async move {
                let _ = state
                    .replace_tokens_if_identity_unchanged(
                        "at".into(),
                        Some("rt".into()),
                        None,
                        expected_identity_gen,
                    )
                    .await;
            },
            racing_client_credentials_update,
        );
    }

    /// The same cycle on the driver's `activate` primitive — the site the
    /// interactive-supersession race above does NOT reach, and the one that
    /// runs on every bring-up and every background refresh. A hoist applied
    /// only to the replace/update sites leaves this one wedging the connection
    /// on a routine refresh, which no interactive flow need be anywhere near.
    #[test]
    fn client_credentials_update_racing_the_activate_primitive_cannot_deadlock() {
        assert_install_racing_a_credential_update_cannot_deadlock(
            "install_tokens_if_identity_unchanged",
            state_and_fence,
            |state, expected_identity_gen| async move {
                let _ = state
                    .install_tokens_if_identity_unchanged(
                        "at".into(),
                        Some("rt".into()),
                        None,
                        expected_identity_gen,
                    )
                    .await;
            },
            racing_client_credentials_update,
        );
    }

    /// The M2M bring-up `activate`, which assigns the `client_credentials` slot
    /// the racing writer also assigns.
    #[test]
    fn client_credentials_update_racing_the_m2m_activate_primitive_cannot_deadlock() {
        assert_install_racing_a_credential_update_cannot_deadlock(
            "install_tokens_and_client_credentials_if_identity_unchanged",
            state_and_fence,
            |state, expected_identity_gen| async move {
                let _ = state
                    .install_tokens_and_client_credentials_if_identity_unchanged(
                        "at".into(),
                        Some("rt".into()),
                        None,
                        "m2m-id".into(),
                        "m2m-secret".into(),
                        expected_identity_gen,
                    )
                    .await;
            },
            racing_client_credentials_update,
        );
    }

    /// The unfenced merge install, which the factory's seeding path takes.
    #[test]
    fn client_credentials_update_racing_the_unfenced_install_cannot_deadlock() {
        assert_install_racing_a_credential_update_cannot_deadlock(
            "install_tokens",
            state_and_fence,
            |state, _expected_identity_gen| async move {
                state
                    .install_tokens("at".into(), Some("rt".into()), None)
                    .await;
            },
            racing_client_credentials_update,
        );
    }

    /// The request path must survive a secret-store round trip untouched — the
    /// symptom, and the mutant that reproduces it, are stated on
    /// [`assert_a_keyring_persist_leaves_the_request_path_intact`]. Supplied
    /// here: this crate's interceptor and silent-grant reads.
    #[test]
    fn a_keyring_persist_in_flight_leaves_the_bearer_and_the_silent_grant_intact() {
        let state = DiscoveryState::new("default");
        futures::executor::block_on(state.install_tokens(
            "live-token".into(),
            Some("live-refresh".into()),
            Some(Duration::from_secs(3600)),
        ));

        assert_a_keyring_persist_leaves_the_request_path_intact(
            &state,
            "Bearer live-token",
            || {
                let mut interceptor = AuthorizationInterceptor::new(state.clone());
                let intercepted = interceptor
                    .call(Request::new(()))
                    .expect("interceptor must not fail");
                RequestPathObservation {
                    bearer: intercepted
                        .metadata()
                        .get("authorization")
                        .map(|value| value.to_str().expect("header is ASCII").to_owned()),
                    has_silent_grant: state.has_silent_grant(),
                }
            },
            |state| async move {
                state
                    .replace_tokens("new-token".into(), Some("new-refresh".into()), None)
                    .await;
            },
        );

        assert_eq!(
            futures::executor::block_on(state.access_token()).as_deref(),
            Some("new-token"),
        );
    }

    /// A token-endpoint rejection must not carry the IDP's response body into
    /// the error message.
    ///
    /// The body of an OAuth error carries `error_description`, and on a
    /// `client_credentials` grant that field echoes the rejected client secret
    /// back to the caller. Every sink the error reaches — a log line, a trace
    /// span, a client of this host — then holds it.
    ///
    /// The load-bearing assertion is the absence of `SECRET`: deleting the
    /// `oauth_error_detail` call and interpolating the body reddens it. The
    /// `invalid_client` assertion pins the other half — the code token still
    /// reaches the operator — and the `AuthExpired` assertion pins that the
    /// body is still *read* for classification, which is a separate decision
    /// from what is reported.
    #[tokio::test]
    async fn a_token_endpoint_rejection_reports_a_code_and_never_the_body() {
        const SECRET: &str = "s3cr3t-client-assertion-value";
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(wiremock::ResponseTemplate::new(400).set_body_raw(
                format!(
                    r#"{{"error":"invalid_client","error_description":"Invalid client secret provided: {SECRET}"}}"#
                ),
                "application/json",
            ))
            .mount(&server)
            .await;
        let state = DiscoveryState::new("default");
        state
            .install_oidc_config(OidcConfig {
                issuer: server.uri(),
                token_endpoint: format!("{}/token", server.uri()),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let error =
            drive_client_credentials_grant(&reqwest::Client::new(), &state, "client-1", SECRET)
                .await
                .expect_err("a 400 from the token endpoint must fail the grant");
        let message = error.to_string();
        assert!(
            !message.contains(SECRET),
            "the rejected secret reached the error message: {message}"
        );
        assert!(
            message.contains("invalid_client"),
            "the provider error code must survive: {message}"
        );
        assert_eq!(error.code(), ErrorCode::AuthExpired);
    }

    /// A body carrying no usable `error` field is reported as a length, never
    /// as text — the same discipline the object path applies. Without it, a
    /// provider that answers an OAuth failure with an HTML error page would put
    /// that page into the message.
    #[tokio::test]
    async fn a_token_endpoint_body_with_no_code_is_reported_as_a_length() {
        const MARKER: &str = "Bearer eyJhbGciOiJSUzI1NiJ9.leaked";
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(500)
                    .set_body_raw(format!("<html><body>{MARKER}</body></html>"), "text/html"),
            )
            .mount(&server)
            .await;
        let state = DiscoveryState::new("default");
        state
            .install_oidc_config(OidcConfig {
                issuer: server.uri(),
                token_endpoint: format!("{}/token", server.uri()),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let error =
            drive_client_credentials_grant(&reqwest::Client::new(), &state, "client-1", "unused")
                .await
                .expect_err("a 500 from the token endpoint must fail the grant");
        let message = error.to_string();
        assert!(
            !message.contains(MARKER),
            "an unparseable body reached the error message: {message}"
        );
        assert!(
            message.contains("byte body suppressed"),
            "the body length must be reported instead: {message}"
        );
    }
}
