// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-client OIDC authentication: discovery state + bearer interceptor.
//!
//! The interceptor reads the access token from `DiscoveryState` per RPC,
//! so a fresh token from refresh / `update_credentials` is visible on
//! the next call without channel rebuild.
//!
//! No internal retry on transient HTTP failures: callers propagate the
//! error and the library's retry layer handles it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ovstorage_broker_protocol::{
    X_OV_IAUTH, capability_from_metadata as protocol_capability_from_metadata,
    capability_metadata_value as protocol_capability_metadata_value,
};
use ovstorage_plugin::{
    AuthEvent, CancellationToken, ConnectionId, Error, ErrorCode, ErrorContext,
    InteractiveAuthCapability, Result, SecretValue,
};
use parking_lot::RwLock as SyncRwLock;
use serde::Deserialize;
use tokio::sync::RwLock;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Proactive-refresh window: refresh when the access token has less than
/// this remaining lifetime, to absorb client/IDP clock skew.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// Broker-published auth-config document, fetched at `/api/v1/auth-config`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    /// URL of the IDP's OpenID discovery doc.
    pub openid_configuration: String,
    /// Per-client config keyed by client name; selected via the
    /// `oidc_client_name` config knob (defaults to `"default"`).
    #[serde(default)]
    pub clients: std::collections::BTreeMap<String, AuthClientConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Selected fields from the OIDC discovery doc.
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

/// Per-backend auth state. Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct DiscoveryState {
    inner: Arc<DiscoveryStateInner>,
}

struct DiscoveryStateInner {
    /// Bumps on every refresh or install; useful for downstream invalidation.
    generation: AtomicU64,
    /// Bumped ONLY by identity-changing writes — [`DiscoveryState::replace_tokens`]
    /// (interactive sign-in) and [`DiscoveryState::set_client_credentials`]
    /// (explicit credential update) — NOT by same-identity `install_tokens`
    /// merges (routine refresh grants). The interactive flow's supersession
    /// guard keys on this, so a background refresh of the SAME identity
    /// completing during a minutes-long sign-in does not make the guard misfire
    /// and drop the sign-in tokens.
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
    /// inside the same critical section as `binding`, so the two are one
    /// snapshot.
    published_credential: std::sync::Mutex<Option<String>>,
    /// Serializes a durable credential write against an identity-changing
    /// install. See the crate's credential lock order.
    publication: std::sync::Mutex<()>,
    #[cfg(test)]
    binding_observation_gate: std::sync::Mutex<Option<BindingObservationGate>>,
    client_name: String,
    /// Cached `(client_id, client_secret)` for the `client_credentials` grant.
    /// Populated by [`DiscoveryState::set_client_credentials`] so the background
    /// refresh loop can re-drive the grant without prompting. `None` for
    /// interactive / refresh-token or anonymous connections.
    client_credentials: SyncRwLock<Option<(String, String)>>,
    /// Credential lineage of the live identity: `true` after an
    /// interactive sign-in's `replace_tokens` (an identity-changing write
    /// that CLEARS the M2M cache), `false` initially and after any write
    /// that (re)establishes a service/M2M lineage. `replace_tokens` can
    /// clear the cached pair but not the immutable `client_secret_file`
    /// config field — this flag is what lets `BrokerDriver::refresh`
    /// suppress that config-driven grant so a background refresh does not
    /// silently revert the user's bearer to the service principal.
    interactive_identity: AtomicBool,
    /// Host's declared interactive-auth capability; read per-RPC by the
    /// interceptor to compose the `x-ov-iauth` metadata header.
    capability: std::sync::atomic::AtomicU8,
}

/// How [`DiscoveryState::write_tokens`] treats the refresh slot.
enum RefreshPolicy {
    /// A `None` response preserves the existing slot (RFC 6749 §6 — the IdP may
    /// legitimately omit an unchanged refresh on a refresh-token grant).
    Merge,
    /// The slot is overwritten unconditionally, CLEARED when the response
    /// carried no refresh, so a stale refresh from a prior identity cannot
    /// survive an access-only rotation / interactive sign-in.
    Replace,
}

/// What [`DiscoveryState::write_tokens`] does to the cached `client_credentials`
/// pair.
enum ClientCredentialsAction {
    /// Leave the slot untouched (the guard is still held for atomicity).
    Keep,
    /// Assign the slot — `Some` caches the M2M pair, `None` clears it.
    Set(Option<(String, String)>),
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
                interactive_identity: AtomicBool::new(false),
                capability: std::sync::atomic::AtomicU8::new(
                    InteractiveAuthCapability::Browser as u8,
                ),
            }),
        }
    }

    /// Set the host's declared interactive-auth capability. Default `Browser`.
    pub fn set_capability(&self, capability: InteractiveAuthCapability) {
        self.inner
            .capability
            .store(capability as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read back the currently-installed capability.
    pub fn capability(&self) -> InteractiveAuthCapability {
        match self
            .inner
            .capability
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            x if x == InteractiveAuthCapability::None as u8 => InteractiveAuthCapability::None,
            x if x == InteractiveAuthCapability::Headless as u8 => {
                InteractiveAuthCapability::Headless
            }
            _ => InteractiveAuthCapability::Browser,
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::SeqCst)
    }

    /// Generation of identity-changing writes only (see `identity_gen`). The
    /// `BrokerDriver` threads this into `activate` as the
    /// verify→activate supersession fence.
    pub fn identity_generation(&self) -> u64 {
        self.inner.identity_gen.load(Ordering::SeqCst)
    }

    /// Cache the `(client_id, client_secret)` pair so the background refresh
    /// loop can re-drive the `client_credentials` grant without re-fetching
    /// credentials from the host. An explicit credential update is an identity
    /// change, so this bumps `identity_gen`.
    pub async fn set_client_credentials(&self, client_id: String, client_secret: String) {
        // Publication lock FIRST, before any credential guard, per the crate's
        // credential lock order: this bumps the identity generation, so it is an
        // identity-changing install and must not interleave a durable write.
        // Taking it first is what keeps a secret-store round trip off the credential
        // cells; taking it here but after the pair — while `write_tokens` takes
        // it first — would close the lock graph into a cycle and deadlock the
        // connection's whole credential path.
        let _publishing = self.publishing();
        // Hold the pair's write guard across the lineage store AND the
        // identity bump so this identity-changing write is atomic like
        // every `write_tokens` path: an interleaving `replace_tokens`
        // (which acquires this same lock) can never observe the pair set
        // with the lineage/generation not yet recorded — the torn state
        // where the lineage gate would fail to suppress the service grant.
        let mut client_credentials = self.inner.client_credentials.write();
        let mut binding = self.binding_slot();
        *client_credentials = Some((client_id, client_secret));
        // An explicit M2M credential update restores the service lineage.
        self.inner
            .interactive_identity
            .store(false, Ordering::SeqCst);
        *binding = None;
        *self
            .inner
            .published_credential
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.inner.identity_gen.fetch_add(1, Ordering::SeqCst);
        drop((binding, client_credentials));
    }

    /// Whether the live identity was established by an interactive sign-in
    /// (see `interactive_identity` on the inner state).
    pub fn interactive_identity(&self) -> bool {
        self.inner.interactive_identity.load(Ordering::SeqCst)
    }

    /// Read the cached `(client_id, client_secret)` pair, if any.
    pub async fn client_credentials(&self) -> Option<(String, String)> {
        self.inner.client_credentials.read().clone()
    }

    /// Whether a *non-interactive* grant is available right now — a stored
    /// refresh token or a cached `client_credentials` pair. The driver's (sync)
    /// `classify` uses this to route a gRPC `UNAUTHENTICATED`
    /// (→ [`ErrorCode::AuthRequired`]) to a silent refresh + retry-once (the
    /// data-path recovery) instead of a dead-end interactive prompt.
    /// Non-blocking `try_read`; a momentarily write-locked slot reports `false`
    /// (the op then surfaces and the caller re-drives) rather than blocking.
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

    pub async fn access_token(&self) -> Option<String> {
        self.inner.access_token.read().clone()
    }

    pub async fn refresh_token(&self) -> Option<String> {
        self.inner.refresh_token.read().clone()
    }

    pub async fn access_token_expires_at(&self) -> Option<SystemTime> {
        *self.inner.expires_at.read()
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

    pub async fn auth_config(&self) -> Option<AuthConfig> {
        self.inner.auth_config.read().await.clone()
    }

    pub async fn oidc_config(&self) -> Option<OidcConfig> {
        self.inner.oidc_config.read().await.clone()
    }

    pub fn client_name(&self) -> &str {
        &self.inner.client_name
    }

    /// Install a fresh access + refresh token pair. Bumps generation.
    ///
    /// `refresh_token == None` PRESERVES the existing in-memory refresh
    /// slot. The refresh-token grant flow legitimately omits the
    /// refresh on response (RFC 6749 §6 — issuing a new refresh is
    /// optional), and we want to keep using the prior one. For the
    /// access-only credential-rotation path that must clear the slot,
    /// see [`Self::replace_tokens`].
    pub async fn install_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Merge,
            ClientCredentialsAction::Keep,
            None,
            false,
        )
        .await;
    }

    /// [`Self::install_tokens`] (merge semantics: `None` refresh preserves the
    /// existing token, the cached `client_credentials` is untouched, and
    /// `identity_gen` is NOT bumped), but committed ONLY if the identity
    /// generation still equals `expected_identity_gen`. The compare happens
    /// while holding every credential write lock, so check-then-install is
    /// atomic. Returns whether the install was committed. This is the driver's
    /// `activate` primitive: it lands a PROVEN bring-up / refresh / warm-continue
    /// bearer on the live cell, fenced so a concurrent interactive success or
    /// explicit credential update is never regressed to this now-stale bundle.
    pub async fn install_tokens_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        expected_identity_gen: u64,
    ) -> bool {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Merge,
            ClientCredentialsAction::Keep,
            Some(expected_identity_gen),
            false,
        )
        .await
        .is_some()
    }

    /// [`Self::install_tokens_if_identity_unchanged`], but ALSO caches the
    /// `(client_id, client_secret)` machine-to-machine pair on the live cell —
    /// atomically, under the SAME identity-gen guard, and WITHOUT bumping
    /// `identity_gen`. The driver's `activate` primitive for an M2M bring-up:
    /// the `client_credentials` grant ran on driver-PRIVATE staging, so caching
    /// the pair here makes [`Self::has_silent_grant`] report `true` immediately
    /// after bring-up (before the first background refresh).
    pub async fn install_tokens_and_client_credentials_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        client_id: String,
        client_secret: String,
        expected_identity_gen: u64,
    ) -> bool {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Merge,
            ClientCredentialsAction::Set(Some((client_id, client_secret))),
            Some(expected_identity_gen),
            false,
        )
        .await
        .is_some()
    }

    /// Replacement-commit sibling of
    /// [`Self::install_tokens_if_identity_unchanged`] for an EXPLICIT,
    /// caller-supplied credential change (operator paste / rotation push) — a NEW
    /// identity. Committed only while the identity generation still equals
    /// `expected_identity_gen` (compared while holding every credential write
    /// lock, so check-then-install is atomic), it then:
    /// - OVERWRITES the refresh slot, CLEARING it when `refresh_token` is `None`
    ///   (unlike the merge primitive, which preserves an unchanged refresh per
    ///   RFC 6749 §6) so a stale refresh from the prior identity cannot survive an
    ///   access-only rotation;
    /// - REPLACES the cached `client_credentials` — the supplied pair when `Some`,
    ///   CLEARED when `None` — so a prior M2M identity does not linger; and
    /// - BUMPS `identity_gen`, fencing any in-flight interactive sign-in or
    ///   background refresh of the PRIOR identity out of its own commit.
    ///
    /// Returns whether the install committed. This is the driver's `activate`
    /// primitive for an explicit credential update; the merge-style
    /// [`Self::install_tokens_if_identity_unchanged`] /
    /// [`Self::install_tokens_and_client_credentials_if_identity_unchanged`]
    /// remain the SAME-identity bring-up / refresh / warm-continue path.
    pub async fn replace_tokens_and_client_credentials_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        client_credentials: Option<(String, String)>,
        expected_identity_gen: u64,
    ) -> bool {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Replace,
            ClientCredentialsAction::Set(client_credentials),
            Some(expected_identity_gen),
            true,
        )
        .await
        .is_some()
    }

    /// **Replace** the credential state for an interactively-authenticated
    /// identity: unlike the merge-style [`Self::install_tokens`], this
    /// OVERWRITES the refresh slot (including CLEARING it when the response
    /// carried none) and CLEARS the cached `client_credentials` pair, and bumps
    /// `identity_gen`. Interactive sign-in establishes a new identity, so a
    /// later background `refresh` must not silently revert to the previous
    /// service (client-credentials) or user (stale refresh) identity.
    pub async fn replace_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Replace,
            ClientCredentialsAction::Set(None),
            None,
            true,
        )
        .await;
    }

    /// [`Self::replace_tokens`], but committed ONLY if no identity-changing
    /// write landed since `expected_identity_gen` was observed (compared under
    /// the credential write locks). Returns whether the install was committed.
    /// The interactive flow thread uses this as its supersession guard.
    pub async fn replace_tokens_if_identity_unchanged(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        expected_identity_gen: u64,
    ) -> Option<u64> {
        self.write_tokens(
            access_token,
            refresh_token,
            expires_in,
            RefreshPolicy::Replace,
            ClientCredentialsAction::Set(None),
            Some(expected_identity_gen),
            true,
        )
        .await
    }

    /// The single fenced token-install core behind every public install/replace
    /// primitive. Acquires the credential write guards in one fixed order —
    /// access → refresh → expires → client_credentials — and holds ALL of them
    /// across the fence compare, the slot writes, AND the generation bump, so a
    /// concurrent guarded writer can never deadlock (every caller uses this same
    /// order) nor observe a TORN set (slots written but `generation` not yet
    /// bumped). Returns whether the write committed (always `true` when `fence`
    /// is `None`).
    ///
    /// - `refresh_policy`: whether a `None` `refresh_token` preserves the slot
    ///   (`Merge`) or clears it (`Replace`).
    /// - `cc_action`: leave the cached `client_credentials` untouched (`Keep`)
    ///   or assign it (`Set`).
    /// - `fence`: when `Some`, commit only while `identity_gen` still equals it.
    /// - `bump_identity`: whether this is an identity-CHANGING write.
    // One parameter per independent behavior dimension is the point of this
    // core; grouping them into a struct would only bloat the thin wrappers.
    #[allow(clippy::too_many_arguments)]
    async fn write_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
        refresh_policy: RefreshPolicy,
        cc_action: ClientCredentialsAction,
        fence: Option<u64>,
        bump_identity: bool,
    ) -> Option<u64> {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        // Publication lock FIRST, before every credential guard and before the
        // binding mutex, per the crate's credential lock order: a durable write
        // and an identity-changing install must not interleave, the durable
        // write must not run under the identity fence itself, and a reader of
        // the credential cells must never end up queued behind an secret store
        // round trip.
        let _publishing = self.publishing();
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
        if let Some(expected) = fence
            && self.inner.identity_gen.load(Ordering::SeqCst) != expected
        {
            return None;
        }
        let published_identity_source = access_token.clone();
        *access = Some(access_token);
        match refresh_policy {
            RefreshPolicy::Merge => {
                if let Some(rt) = refresh_token {
                    *refresh = Some(rt);
                }
            }
            RefreshPolicy::Replace => *refresh = refresh_token,
        }
        *expires = expires_at;
        if let ClientCredentialsAction::Set(cc) = cc_action {
            // An identity-CHANGING write records the new identity's lineage:
            // clearing the pair is the interactive shape, setting it
            // is a service/M2M (re)establishment. Same-identity merges leave
            // the lineage untouched.
            if bump_identity {
                self.inner
                    .interactive_identity
                    .store(cc.is_none(), Ordering::SeqCst);
            }
            *client_credentials = cc;
        }
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        // The refresh token the connection is serving on RIGHT NOW, republished
        // by every write that leaves the slot assigned — a rotation included.
        // A later durable write proves it carries THIS credential, which the
        // binding cannot show for an opaque-token deployment.
        //
        // Tracking only identity-CHANGING writes would name the token live at
        // the last sign-in instead: a background refresh commits through the
        // merge primitive, so the very next persist would offer the rotated
        // successor, fail the compare, and leave the secret store holding a
        // predecessor the provider's grant has already consumed.
        *self
            .inner
            .published_credential
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = refresh
            .as_deref()
            .map(ovstorage_plugin::oauth_secret_store::fingerprint);
        if bump_identity {
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
            self.inner.identity_gen.fetch_add(1, Ordering::SeqCst);
        }
        // The generation this write leaves behind, so the caller can hold a
        // lease on the identity it just established rather than on the one it
        // started at — which its own bump has already moved past.
        let generation = self.inner.identity_gen.load(Ordering::SeqCst);
        drop((binding, client_credentials, expires, refresh, access));
        Some(generation)
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

    /// Enter the publication critical section — the FIRST lock every write to
    /// the live credential cell takes, ahead of every credential guard and the
    /// binding mutex, per the crate's credential lock order.
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

    /// True when the access token is unset, EMPTY, or within `REFRESH_SKEW` of
    /// expiring. An empty access token is the warm-continue shape
    /// (`oauth_bundle("", Some(refresh), None)`), where a stored refresh token
    /// seeds the state but no access token has been minted yet — treat it as
    /// needing refresh so the seed drives the refresh-token grant rather than
    /// reporting a usable bearer that fails every RPC with UNAUTHENTICATED.
    pub async fn token_needs_refresh(&self) -> bool {
        let token = self.inner.access_token.read();
        let expires_at = self.inner.expires_at.read();
        match (token.as_ref(), *expires_at) {
            (None, _) => true,
            (Some(t), _) if t.is_empty() => true,
            (Some(_), None) => false,
            (Some(_), Some(at)) => SystemTime::now() + REFRESH_SKEW >= at,
        }
    }
}

/// Tonic interceptor that injects `Authorization: Bearer <token>` per RPC,
/// reading the token from `DiscoveryState`. With no token, the request
/// passes through unchanged so the broker surfaces `AuthRequired`.
#[derive(Clone)]
pub struct AuthorizationInterceptor {
    state: DiscoveryState,
}

impl AuthorizationInterceptor {
    pub fn new(state: DiscoveryState) -> Self {
        Self { state }
    }
}

impl Interceptor for AuthorizationInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        // Synchronous interceptor: `try_read()` rather than `.await`.
        //
        // A miss emits NO Authorization header, so the RPC comes back
        // UNAUTHENTICATED and `classify` — whose `has_silent_grant` also
        // `try_read`s — reports `NeedsInteractive` and prompts the user. That
        // makes the width of the contended write window a correctness
        // property, not a latency one: it must stay bounded by the in-memory
        // swap in `write_tokens`. It is bounded precisely because the
        // publication lock is taken BEFORE these guards (see the crate's
        // credential lock order), so an installer waiting on a keyring round
        // trip is not holding the access-token cell while it waits.
        let token = match self.state.inner.access_token.try_read() {
            Some(guard) => guard.clone(),
            None => None,
        };
        if let Some(token) = token {
            let header = format!("Bearer {token}");
            match MetadataValue::try_from(header.as_str()) {
                Ok(value) => {
                    request.metadata_mut().insert("authorization", value);
                }
                Err(_) => {
                    // Refuse rather than emit a malformed header.
                    return Err(Status::internal(
                        "broker: access token contains characters \
                         invalid in an HTTP header",
                    ));
                }
            }
        }
        // `Auth` may carry the capability selected for that individual
        // `authenticate_connection` call. Preserve that explicit value; all
        // other RPCs inherit the connection-wide capability from the state.
        if request.metadata().get(X_OV_IAUTH).is_none() {
            let capability_value = protocol_capability_metadata_value(self.state.capability());
            request.metadata_mut().insert(X_OV_IAUTH, capability_value);
        }
        Ok(request)
    }
}

/// Re-export of the protocol-level metadata parser; lets broker-only
/// callers read the capability off a `MetadataMap` without depending on
/// `ovstorage-broker-protocol` directly.
pub fn capability_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> InteractiveAuthCapability {
    protocol_capability_from_metadata(metadata)
}

/// OIDC token-endpoint response (subset used by the refresh path).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Fetch the broker's `/api/v1/auth-config` and parse into [`AuthConfig`].
pub async fn fetch_auth_config(
    client: &reqwest::Client,
    discovery_url: &str,
) -> Result<AuthConfig> {
    let trimmed = discovery_url.trim_end_matches('/');
    let url = format!("{trimmed}/api/v1/auth-config");
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: auth-config fetch failed for {url}: {err}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "broker: auth-config returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: auth-config body read failed: {err}"),
        )
    })?;
    let parsed = serde_json::from_slice::<AuthConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker: auth-config JSON parse failed: {err}"),
        )
    })?;
    tracing::trace!(
        target: "ovstorage.broker.auth",
        url = %url,
        auth_config = ?parsed,
        "broker: /api/v1/auth-config response body",
    );
    Ok(parsed)
}

/// Fetch the IDP's OIDC discovery document and parse into [`OidcConfig`].
pub async fn fetch_oidc_config(
    client: &reqwest::Client,
    auth_config: &AuthConfig,
) -> Result<OidcConfig> {
    let url = auth_config
        .openid_configuration
        .trim_end_matches('/')
        .to_string();
    // OIDC discovery may be served at the configured URL OR at issuer-root
    // + `.well-known/openid-configuration`; try configured first, fall back.
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: OIDC discovery fetch failed for {url}: {err}"),
        )
    })?;
    let response = if response.status().is_success() {
        response
    } else {
        let alt = format!("{url}/.well-known/openid-configuration");
        client.get(&alt).send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("broker: OIDC discovery fetch failed for {alt}: {err}"),
            )
        })?
    };
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "broker: OIDC discovery returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: OIDC discovery body read failed: {err}"),
        )
    })?;
    serde_json::from_slice::<OidcConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker: OIDC discovery JSON parse failed: {err}"),
        )
    })
}

/// Persist the interactively-minted refresh token durably (keyring), invoked in
/// the flow thread BEFORE the terminal `Succeeded` is forwarded. `None` clears
/// the stored token. Returns `Err` on a real durable-write failure so the caller
/// can surface it (the durable store is stranded while the live cell already
/// holds the token — memory stays authoritative).
/// Durable-write hook invoked with the freshly minted `(access, refresh)`
/// pair. The access token carries the identity claims the persisted lineage is
/// bound to, so the sink records the account alongside the secret.
pub type PersistRefresh = Arc<dyn Fn(&str, Option<String>, u64) -> Result<()> + Send + Sync>;

/// Drive an interactive OAuth login against the broker's IDP, returning an
/// `AuthEventStream` the host surfaces to the caller. On the flow's `Succeeded`
/// the freshly-minted tokens are installed on the shared `state` (the transport
/// interceptor's cell) and the refresh token persisted via `persist` BEFORE the
/// terminal event is forwarded, so the connection is usable and the secret saved
/// the instant `Succeeded` is observed. The install is fenced on the identity
/// generation captured at flow start: a slow / abandoned / superseded sign-in
/// must not clobber a newer identity-changing update; when the fence fails (or
/// `liveness` was cancelled by `remove_connection`) the event is downgraded to
/// `Succeeded { credentials: None }` so the generic adapter keeps the entry and
/// keyring consistent with the winning update.
///
/// `liveness` also BOUNDS the flow: cancelling it ends the returned stream with
/// a terminal `AuthEvent::Cancelled` and tears the flow down, so a consumer
/// blocked in `next()` — the stream is a blocking iterator — returns on
/// cancellation instead of waiting for an OAuth event or the flow's deadline.
pub async fn drive_interactive_login(
    state: &DiscoveryState,
    connection: ovstorage_plugin::Connection,
    capability: InteractiveAuthCapability,
    persist: PersistRefresh,
    liveness: Option<CancellationToken>,
) -> ovstorage_plugin::Result<ovstorage_plugin::AuthEventStream> {
    if matches!(capability, InteractiveAuthCapability::None) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "broker: host declared no interactive auth capability",
        ));
    }
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: interactive login requested but auth-config not loaded",
        )
    })?;
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: interactive login requested but OIDC discovery not loaded",
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
                    "broker: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let authorization_endpoint = oidc.authorization_endpoint.as_ref().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: IDP discovery missing authorization_endpoint",
        )
    })?;
    let endpoints = ovstorage::OAuthEndpoints {
        authorization_endpoint: url::Url::parse(authorization_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker: malformed authorization_endpoint: {err}"),
            )
        })?,
        token_endpoint: url::Url::parse(&oidc.token_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker: malformed token_endpoint: {err}"),
            )
        })?,
        client_id: client.client_id,
        scope: client.scope,
    };
    let connection_id = connection.id.clone();
    let backend_id = ovstorage_plugin::BackendId(format!("broker:{}", state.client_name()));
    let flow = match capability {
        InteractiveAuthCapability::Headless => {
            ovstorage::OAuthFlow::device(backend_id).with_connection(connection_id)
        }
        InteractiveAuthCapability::Browser => {
            // Path matches the broker's IDP app registration.
            let redirect_base = url::Url::parse("http://127.0.0.1/openid").map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("broker: redirect base parse: {err}"),
                )
            })?;
            ovstorage::OAuthFlow::pkce(backend_id, redirect_base).with_connection(connection_id)
        }
        InteractiveAuthCapability::None => unreachable!("handled above"),
    };
    let flow = flow.with_endpoints(endpoints);
    // Clone the shared token cell into the flow thread so a successful sign-in
    // installs the freshly-minted tokens into the *same* `DiscoveryState` the
    // transport's `AuthorizationInterceptor` reads. Capture the IDENTITY
    // generation at flow start as the supersession fence (see `replace_tokens`).
    let install_state = state.clone();
    let identity_gen_at_start = state.identity_generation();
    // Bridge async stream to sync iterator without buffering: browser/device
    // flows emit a prompt then wait for user action, so collecting first
    // would hide the prompt until the flow terminates. Dedicated thread +
    // per-bridge Runtime mirrors `watch_directory`.
    //
    // The consumer's `next()` is a blocking `recv()` on this channel, so
    // cancellation is the flow thread's job: the flow's own wait — the PKCE
    // redirect listener's `accept`, the device flow's poll loop — is RACED
    // against `liveness`, so a cancellation ends the stream, emits the terminal
    // `AuthEvent::Cancelled`, and drops the sender. A consumer parked in
    // `next()` therefore returns on cancellation rather than on an OAuth event
    // or the flow's deadline, and dropping the raced stream tears the flow's
    // listener / poll task down with it.
    let flow_liveness = liveness.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ovs-bc-auth".into())
        .spawn(move || {
            use futures::StreamExt;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                let _ = sender.send(Err(Error::new(
                    ErrorCode::Internal,
                    "broker: failed to create OAuth flow runtime",
                )));
                return;
            };
            runtime.block_on(async move {
                // Resolves only on cancellation; a flow with no liveness token
                // races against a future that never completes.
                // Boxed so the raced stream stays `Unpin`.
                let cancelled = Box::pin(async move {
                    match flow_liveness {
                        Some(token) => token.cancelled().await,
                        None => std::future::pending::<()>().await,
                    }
                });
                match flow.run().await {
                    Ok(stream) => {
                        let mut stream = stream.take_until(cancelled);
                        let mut forwarded_terminal = false;
                        while let Some(event) = stream.next().await {
                            // On success, land the tokens on the transport cell
                            // AND persist the refresh token durably BEFORE
                            // forwarding the event. A `Succeeded` whose install is
                            // NOT committed — superseded by a newer identity, or
                            // the connection removed mid-flow — is downgraded to
                            // `Succeeded { credentials: None }` so the generic
                            // adapter's keep-creds branch transitions state WITHOUT
                            // swapping the entry bundle or persisting losing tokens.
                            let event = match event {
                                Ok(AuthEvent::Succeeded {
                                    connection,
                                    credentials: Some(bundle),
                                }) => {
                                    let live =
                                        liveness.as_ref().is_none_or(|token| !token.is_cancelled());
                                    if !live {
                                        // Removal-cancellation: `remove_connection`
                                        // cancelled the flow mid-sign-in. Downgrade
                                        // to `Succeeded { None }`; the set adapter
                                        // re-fences on `is_registered`, so a removed
                                        // entry commits nothing. Do NOT install or
                                        // persist a token the removal just purged.
                                        Ok(AuthEvent::Succeeded {
                                            connection,
                                            credentials: None,
                                        })
                                    } else {
                                        // Extract the minted bearer as fully OWNED
                                        // pieces (no borrow of `bundle` survives),
                                        // distinguishing "no usable bearer" from a
                                        // usable one we then try to install.
                                        let parsed = match bundle.fields.get("oauth") {
                                            Some(SecretValue::OAuthToken {
                                                token,
                                                refresh,
                                                expires_at,
                                            }) => match std::str::from_utf8(&token.0) {
                                                Ok(access) if !access.is_empty() => Some((
                                                    access.to_owned(),
                                                    refresh
                                                        .as_ref()
                                                        .and_then(|r| {
                                                            std::str::from_utf8(&r.0).ok()
                                                        })
                                                        .map(str::to_owned),
                                                    expires_at.and_then(|at| {
                                                        at.duration_since(SystemTime::now()).ok()
                                                    }),
                                                )),
                                                _ => None,
                                            },
                                            _ => None,
                                        };
                                        match parsed {
                                            None => {
                                                // The flow reported success but
                                                // installed NO usable bearer (missing
                                                // / malformed / empty access token).
                                                // Surface a FAILURE — not
                                                // `Succeeded { None }`, which the
                                                // adapter would mark `Authenticated`
                                                // with no `Authorization` header,
                                                // yielding UNAUTHENTICATED on every
                                                // RPC.
                                                Ok(AuthEvent::Failed {
                                                    error: Error::new(
                                                        ErrorCode::AuthRequired,
                                                        "broker: interactive login \
                                                         produced no usable access token",
                                                    ),
                                                })
                                            }
                                            Some((access, refresh, expires_in)) => {
                                                // REPLACE (not merge): interactive
                                                // auth establishes a new identity,
                                                // clearing any cached
                                                // client-credentials grant and
                                                // overwriting the refresh slot.
                                                // Committed only if no newer
                                                // identity-changing update landed,
                                                // compared under the write locks.
                                                let committed = install_state
                                                    .replace_tokens_if_identity_unchanged(
                                                        access.clone(),
                                                        refresh.clone(),
                                                        expires_in,
                                                        identity_gen_at_start,
                                                    )
                                                    .await;
                                                // Re-sample liveness AFTER the commit
                                                // await: `remove_connection` may have
                                                // cancelled the flow and purged the
                                                // keyring during it. Without this
                                                // re-check the persist below would
                                                // resurrect the token the removal just
                                                // deleted.
                                                let still_live = liveness
                                                    .as_ref()
                                                    .is_none_or(|token| !token.is_cancelled());
                                                // `committed` was true when this
                                                // flow's own commit ran; another flow
                                                // may have committed since. The persist
                                                // carries this flow's identity lease and
                                                // answers `AuthCancelled` when it has,
                                                // which is also the answer to whether
                                                // this bundle may still be published.
                                                let persisted = match (committed, still_live) {
                                                    // The generation this flow's
                                                    // OWN commit established: the
                                                    // persist holds a lease on
                                                    // that, not on the one the
                                                    // flow started at, which its
                                                    // own bump has moved past.
                                                    (Some(generation), true) => persist(
                                                        &access,
                                                        refresh.clone(),
                                                        generation,
                                                    ),
                                                    _ => Ok(()),
                                                };
                                                let superseded =
                                                    persisted.as_ref().err().is_some_and(|err| {
                                                        err.code() == ErrorCode::AuthCancelled
                                                    });
                                                if let Err(err) = &persisted
                                                    && !superseded
                                                {
                                                    // Durable-write failure leaves the
                                                    // live cell (and the returned
                                                    // bundle) authoritative on the
                                                    // token; the set-side persist
                                                    // retries. Warn but still forward
                                                    // success.
                                                    tracing::warn!(
                                                        target: "ovstorage.broker.auth",
                                                        error = %err.message(),
                                                        "broker: interactive refresh-token \
                                                         persist failed; durable store not \
                                                         updated (memory authoritative)"
                                                    );
                                                }
                                                if committed.is_some() && still_live && !superseded
                                                {
                                                    Ok(AuthEvent::Succeeded {
                                                        connection,
                                                        credentials: Some(bundle),
                                                    })
                                                } else {
                                                    // Supersession (fence lost either at
                                                    // this flow's commit or before its
                                                    // credential could be published) or
                                                    // removal during the commit await:
                                                    // downgrade to `Succeeded { None }`
                                                    // so the adapter keeps the winner's
                                                    // entry / keyring consistent.
                                                    Ok(AuthEvent::Succeeded {
                                                        connection,
                                                        credentials: None,
                                                    })
                                                }
                                            }
                                        }
                                    }
                                }
                                other => other,
                            };
                            forwarded_terminal = matches!(
                                event,
                                Err(_)
                                    | Ok(AuthEvent::Succeeded { .. })
                                    | Ok(AuthEvent::Failed { .. })
                                    | Ok(AuthEvent::Cancelled)
                            );
                            if sender.send(event).is_err() {
                                break;
                            }
                        }
                        // A raced end — `is_stopped` means the cancellation future
                        // fired, not that the flow reached its own end — closes the
                        // stream with the terminal `Cancelled`. Guarded on the
                        // forwarded event so a cancellation observed AFTER the flow
                        // already sent `Succeeded` / `Failed` adds nothing: exactly
                        // one terminal event reaches the consumer.
                        if !forwarded_terminal && stream.is_stopped() {
                            let _ = sender.send(Ok(AuthEvent::Cancelled));
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

/// Drive a refresh-token grant against the IDP's token endpoint, updating
/// the discovery state on success and returning the new generation counter.
pub async fn drive_refresh_token_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: refresh requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: refresh requested but auth-config not loaded",
        )
    })?;
    let refresh_token = state.refresh_token().await.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "broker: refresh requested but no refresh_token is stored",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("no_refresh_token_stored".into()),
            expired_at: None,
        })
    })?;
    let client_id = auth_config
        .clients
        .get(state.client_name())
        .map(|c| c.client_id.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "broker: auth-config has no client named '{}'",
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
                format!("broker: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        // 401 / 400 with `invalid_grant` => refresh revoked/expired;
        // surface as AuthExpired so the host drives a fresh interactive flow.
        let body_str = String::from_utf8_lossy(&body);
        let is_auth_expired = status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_grant"));
        let code = if is_auth_expired {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        let err = Error::new(
            code,
            format!(
                "broker: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        );
        let err = if is_auth_expired {
            err.with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some(format!("refresh_token_grant_{}", status.as_u16())),
                expired_at: None,
            })
        } else {
            err
        };
        return Err(err);
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("broker: token endpoint response JSON parse failed: {err}"),
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

/// OAuth2 `client_credentials` grant. Used by `[connection.auth] client_secret_file`
/// to skip the interactive flow for non-interactive workloads (CI, batch jobs,
/// service accounts that have an OAuth client at the IDP).
///
/// Reads the secret at call time so kubelet- or vault-managed secret files
/// rotate transparently. The grant uses the discovered `client_id` + `scope`
/// for `state.client_name()`.
pub async fn drive_client_credentials_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
    secret_file: &std::path::Path,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: client_credentials grant requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: client_credentials grant requested but auth-config not loaded",
        )
    })?;
    let client_entry = auth_config
        .clients
        .get(state.client_name())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "broker: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let client_id = client_entry.client_id.clone();
    let scope = client_entry.scope.clone();
    let client_secret = std::fs::read_to_string(secret_file)
        .map_err(|err| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                format!(
                    "broker: client_secret_file '{}' read failed: {err}",
                    secret_file.display()
                ),
            )
        })?
        .trim()
        .to_string();
    if client_secret.is_empty() {
        return Err(Error::new(
            ErrorCode::CredentialUnavailable,
            format!(
                "broker: client_secret_file '{}' is empty",
                secret_file.display()
            ),
        ));
    }
    let mut form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id),
        ("client_secret", client_secret),
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
                format!("broker: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        return Err(Error::new(
            if status.as_u16() == 401 || status.as_u16() == 400 {
                ErrorCode::AuthExpired
            } else {
                ErrorCode::Transient
            },
            format!(
                "broker: client_credentials grant returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("broker: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            None,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// OAuth2 `client_credentials` grant driven from an explicit
/// `(client_id, client_secret)` pair supplied in the connection's
/// [`ovstorage_plugin::SecretBundle`] — the descriptor's `client_credentials`
/// credential method, as opposed to the config-driven `client_secret_file` path
/// above. Scope is taken from the discovered auth-config for
/// `state.client_name()` when present, so server-side enforcement matches the
/// other grants. On success the access token is installed on `state`.
pub async fn drive_client_credentials_grant_with_secret(
    client: &reqwest::Client,
    state: &DiscoveryState,
    client_id: &str,
    client_secret: &str,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: client_credentials grant requested but OIDC config not loaded",
        )
    })?;
    // auth-config is optional here — the caller supplies client_id/secret — but
    // honour a configured scope when present.
    let scope = state
        .auth_config()
        .await
        .and_then(|cfg| cfg.clients.get(state.client_name()).cloned())
        .and_then(|c| c.scope);
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
                format!("broker: token endpoint POST failed: {err}"),
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
                "broker: client_credentials grant returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("broker: token endpoint response JSON parse failed: {err}"),
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

/// Drive the broker's per-user upstream OAuth flow over the streaming `Auth`
/// RPC with this authentication request's interactive capability, rebuilding
/// each `AuthEventPartial` into the SPI `AuthEvent` shape.
/// Cancelling `liveness` ends the returned stream with a terminal
/// `AuthEvent::Cancelled`. Dropping the returned stream cancels and joins its
/// bridge thread so plugin code cannot outlive the cdylib.
///
/// This relay deliberately does not call `register_credential`: wire
/// `Succeeded` carries only the connection id, not bearer bytes. The broker
/// daemon persists the credential before emitting success.
pub async fn drive_upstream_auth(
    transport: &dyn ovstorage_broker_protocol::BrokerClientTransport,
    address: ovstorage_plugin::Url,
    capability: ovstorage_plugin::InteractiveAuthCapability,
    connection: ovstorage_plugin::Connection,
    liveness: Option<CancellationToken>,
) -> ovstorage_plugin::Result<ovstorage_plugin::AuthEventStream> {
    let stream = transport.auth_stream(address, capability).await?;
    Ok(bridge_upstream_auth(stream, connection, liveness))
}

struct UpstreamAuthEventStreamBridge {
    receiver: std::sync::mpsc::IntoIter<Result<AuthEvent>>,
    shutdown: CancellationToken,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Iterator for UpstreamAuthEventStreamBridge {
    type Item = Result<AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.next()
    }
}

impl Drop for UpstreamAuthEventStreamBridge {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn bridge_upstream_auth(
    stream: ovstorage_broker_protocol::UpstreamAuthStream,
    connection: ovstorage_plugin::Connection,
    liveness: Option<CancellationToken>,
) -> ovstorage_plugin::AuthEventStream {
    // Bridge async-to-sync without buffering so interactive prompts reach the
    // host while the daemon continues driving and persisting the OAuth flow.
    let (sender, receiver) = std::sync::mpsc::channel();
    let shutdown = CancellationToken::new();
    let bridge_shutdown = shutdown.clone();
    let join = std::thread::Builder::new()
        .name("ovs-bc-upstream".into())
        .spawn(move || {
            use futures::StreamExt;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                let _ = sender.send(Err(Error::new(
                    ErrorCode::Internal,
                    "broker: failed to create upstream-auth runtime",
                )));
                return;
            };
            runtime.block_on(async move {
                let mut stream = stream;
                loop {
                    let frame = tokio::select! {
                        biased;
                        _ = bridge_shutdown.cancelled() => return,
                        _ = async {
                            match &liveness {
                                Some(token) => token.cancelled().await,
                                None => std::future::pending::<()>().await,
                            }
                        } => {
                            let _ = sender.send(Ok(AuthEvent::Cancelled));
                            return;
                        }
                        frame = stream.next() => frame,
                    };
                    let Some(frame) = frame else {
                        return;
                    };
                    let partial = match frame {
                        Ok(p) => p,
                        Err(err) => {
                            let _ = sender.send(Err(err));
                            return;
                        }
                    };
                    let event = match partial {
                        ovstorage_broker_protocol::AuthEventPartial::OpenBrowser {
                            url,
                            expires_at,
                        } => Ok(ovstorage_plugin::AuthEvent::OpenBrowser { url, expires_at }),
                        ovstorage_broker_protocol::AuthEventPartial::DeviceCode {
                            user_code,
                            verification_url,
                            expires_at,
                            interval,
                        } => Ok(ovstorage_plugin::AuthEvent::DeviceCode {
                            user_code,
                            verification_url,
                            expires_at,
                            interval,
                        }),
                        ovstorage_broker_protocol::AuthEventPartial::Progress { message } => {
                            Ok(ovstorage_plugin::AuthEvent::Progress { message })
                        }
                        ovstorage_broker_protocol::AuthEventPartial::Succeeded {
                            connection_id: _,
                        } => Ok(ovstorage_plugin::AuthEvent::Succeeded {
                            connection: Box::new(connection.clone()),
                            credentials: None,
                        }),
                        ovstorage_broker_protocol::AuthEventPartial::Failed { error } => {
                            Ok(ovstorage_plugin::AuthEvent::Failed { error })
                        }
                        ovstorage_broker_protocol::AuthEventPartial::Cancelled => {
                            Ok(ovstorage_plugin::AuthEvent::Cancelled)
                        }
                    };
                    let terminal = matches!(
                        event,
                        Ok(ovstorage_plugin::AuthEvent::Succeeded { .. })
                            | Ok(ovstorage_plugin::AuthEvent::Failed { .. })
                            | Ok(ovstorage_plugin::AuthEvent::Cancelled)
                    );
                    if sender.send(event).is_err() {
                        return;
                    }
                    if terminal {
                        return;
                    }
                }
            });
        })
        .expect("failed to spawn thread");
    Box::new(UpstreamAuthEventStreamBridge {
        receiver: receiver.into_iter(),
        shutdown,
        join: Some(join),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::connection::credential_lock_order::{
        PublicationLockHolder, RequestPathObservation,
        assert_a_keyring_persist_leaves_the_request_path_intact,
        assert_install_racing_a_credential_update_cannot_deadlock,
    };

    /// Discovery state wired to unroutable-but-parseable IDP endpoints. The
    /// PKCE flow only binds its loopback redirect listener before parking, so
    /// no request ever reaches these.
    async fn state_with_pkce_endpoints() -> DiscoveryState {
        let state = DiscoveryState::new("default");
        state
            .install_auth_config(AuthConfig {
                openid_configuration: "https://idp.invalid/.well-known/openid-configuration".into(),
                clients: std::collections::BTreeMap::from([(
                    "default".to_string(),
                    AuthClientConfig {
                        client_id: "client-1".into(),
                        scope: None,
                    },
                )]),
            })
            .await;
        state
            .install_oidc_config(OidcConfig {
                issuer: "https://idp.invalid".into(),
                token_endpoint: "https://idp.invalid/token".into(),
                authorization_endpoint: Some("https://idp.invalid/authorize".into()),
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        state
    }

    /// Every durable write a flow attempted, as `(access, refresh, generation)`.
    type PersistLog = Arc<std::sync::Mutex<Vec<(String, Option<String>, u64)>>>;

    /// A persistence sink that RECORDS rather than discards.
    ///
    /// Both interactive-stream tests end without a success — one cancelled at
    /// its park, one denied at the redirect — so neither flow may write
    /// anything. A stub that swallowed its arguments could not tell a flow that
    /// persisted nothing from one that persisted a credential no sign-in
    /// produced, which is the failure worth catching on these paths.
    fn recording_persist() -> (PersistRefresh, PersistLog) {
        let calls: PersistLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&calls);
        let persist: PersistRefresh = Arc::new(
            move |access: &str, refresh: Option<String>, generation: u64| {
                sink.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((access.to_owned(), refresh, generation));
                Ok(())
            },
        );
        (persist, calls)
    }

    /// The recorder itself records.
    ///
    /// The two stream tests assert their log is EMPTY, which a broken sink
    /// would satisfy for the wrong reason. This is what keeps those assertions
    /// from being vacuous.
    #[test]
    fn recording_persist_observes_a_write() {
        let (persist, persisted) = recording_persist();
        persist("access", Some("rt".into()), 7).unwrap();
        assert_eq!(
            persisted.lock().unwrap().as_slice(),
            [("access".to_string(), Some("rt".to_string()), 7)],
        );
    }

    fn dummy_connection() -> ovstorage_plugin::Connection {
        use ovstorage_plugin::ConnectionSource;
        ovstorage_plugin::Connection {
            id: ConnectionId("c1".into()),
            backend_kind: crate::KIND.into(),
            display_name: "broker".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: ovstorage_plugin::Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ovstorage_plugin::ConnectionAuthState::AwaitingAuth {
                reason: ovstorage_plugin::AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: ovstorage_plugin::UserMetadata::new(),
        }
    }

    struct ParkedUpstreamStream {
        first_poll: Option<std::sync::mpsc::SyncSender<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl futures::Stream for ParkedUpstreamStream {
        type Item = Result<ovstorage_broker_protocol::AuthEventPartial>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            if let Some(first_poll) = self.first_poll.take() {
                let _ = first_poll.send(());
            }
            std::task::Poll::Pending
        }
    }

    impl Drop for ParkedUpstreamStream {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn parked_upstream_stream() -> (
        ovstorage_broker_protocol::UpstreamAuthStream,
        std::sync::mpsc::Receiver<()>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let (first_poll, polled) = std::sync::mpsc::sync_channel(1);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            Box::pin(ParkedUpstreamStream {
                first_poll: Some(first_poll),
                dropped: dropped.clone(),
            }),
            polled,
            dropped,
        )
    }

    #[test]
    fn upstream_auth_cancellation_unblocks_a_parked_next_with_cancelled() {
        let (upstream, polled, dropped) = parked_upstream_stream();
        let cancel = CancellationToken::new();
        let events = bridge_upstream_auth(upstream, dummy_connection(), Some(cancel.clone()));
        polled
            .recv_timeout(Duration::from_secs(5))
            .expect("bridge polls the upstream stream");

        let (parked, consumer_ready) = std::sync::mpsc::sync_channel(1);
        let (drained, consumer_result) = std::sync::mpsc::sync_channel(1);
        let consumer = std::thread::spawn(move || {
            let _ = parked.send(());
            let _ = drained.send(events.collect::<Vec<_>>());
        });
        consumer_ready
            .recv_timeout(Duration::from_secs(5))
            .expect("consumer is ready to block in next()");

        cancel.cancel();

        let tail = consumer_result
            .recv_timeout(Duration::from_secs(5))
            .expect("cancellation unblocks the consumer");
        assert!(
            matches!(tail.as_slice(), [Ok(AuthEvent::Cancelled)]),
            "cancellation emits one terminal Cancelled: {tail:?}"
        );
        consumer.join().expect("consumer thread");
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn dropping_upstream_auth_stream_terminates_its_bridge_thread() {
        let (upstream, polled, dropped) = parked_upstream_stream();
        let events = bridge_upstream_auth(upstream, dummy_connection(), None);
        polled
            .recv_timeout(Duration::from_secs(5))
            .expect("bridge parks while polling the upstream stream");

        drop(events);

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "drop joins the bridge after its parked upstream stream is torn down"
        );
    }

    /// Cancelling the liveness token unblocks a consumer parked in the
    /// interactive stream's blocking `next()`. The PKCE flow emits its prompt
    /// and then waits on the loopback redirect listener with no deadline, so
    /// without racing the wait against the token this `next()` never returns.
    #[tokio::test]
    async fn interactive_login_cancellation_unblocks_a_parked_next() {
        let state = state_with_pkce_endpoints().await;
        let cancel = CancellationToken::new();
        let (persist, persisted) = recording_persist();
        let stream = drive_interactive_login(
            &state,
            dummy_connection(),
            InteractiveAuthCapability::Browser,
            persist,
            Some(cancel.clone()),
        )
        .await
        .expect("PKCE flow starts");

        // Gate on the flow reaching its park: the two pre-park events are the
        // proof that the next `next()` waits on the redirect listener. A plain
        // thread — not `spawn_blocking` — so the failure path is a bounded test
        // failure: the runtime joins its blocking pool at shutdown, which an
        // uncancellable park would turn into a hang instead of a timeout.
        let (parked_tx, parked_rx) = tokio::sync::oneshot::channel();
        let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut stream = stream;
            let prompt = stream.next().expect("OpenBrowser");
            let progress = stream.next().expect("Progress");
            let _ = parked_tx.send(());
            // Parks until cancellation ends the flow. The channel buffers, so a
            // cancellation landing before this call is not lost.
            let tail: Vec<_> = stream.collect();
            let _ = drained_tx.send((prompt, progress, tail));
        });
        parked_rx.await.expect("flow reached its park");

        cancel.cancel();

        let (prompt, progress, tail) = tokio::time::timeout(Duration::from_secs(10), drained_rx)
            .await
            .expect("cancellation must unblock the parked next()")
            .expect("drain thread");
        assert!(matches!(prompt, Ok(AuthEvent::OpenBrowser { .. })));
        assert!(matches!(progress, Ok(AuthEvent::Progress { .. })));
        assert!(
            matches!(tail.as_slice(), [Ok(AuthEvent::Cancelled)]),
            "cancellation ends the stream with one terminal Cancelled: {tail:?}"
        );
        assert!(
            persisted.lock().unwrap().is_empty(),
            "a cancelled flow reached no success, so it must have written no \
             credential",
        );
    }

    /// The uncancelled flow still delivers its own events, in order, and ends
    /// on its own terminal event — racing the wait against the liveness token
    /// adds nothing to a flow that reaches a conclusion.
    #[tokio::test]
    async fn interactive_login_delivers_flow_events_in_order() {
        use tokio::io::AsyncWriteExt;

        let state = state_with_pkce_endpoints().await;
        let cancel = CancellationToken::new();
        let (persist, persisted) = recording_persist();
        let stream = drive_interactive_login(
            &state,
            dummy_connection(),
            InteractiveAuthCapability::Browser,
            persist,
            Some(cancel.clone()),
        )
        .await
        .expect("PKCE flow starts");

        // Pump the blocking iterator on a plain thread; `recv` yielding `None`
        // is the stream ending.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for event in stream {
                if tx.send(event).is_err() {
                    return;
                }
            }
        });
        async fn next(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<AuthEvent>>,
        ) -> Option<Result<AuthEvent>> {
            tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("flow event")
        }

        let prompt = next(&mut rx).await.expect("OpenBrowser");
        let authorize = match prompt {
            Ok(AuthEvent::OpenBrowser { url, .. }) => url,
            other => panic!("first event is the browser prompt: {other:?}"),
        };
        assert!(matches!(
            next(&mut rx).await.expect("Progress"),
            Ok(AuthEvent::Progress { .. })
        ));

        // Answer the flow's loopback listener with a denied authorisation; the
        // flow concludes without reaching the (unroutable) token endpoint.
        let redirect = url::Url::parse(&authorize)
            .expect("authorize URL")
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .map(|(_, value)| value.into_owned())
            .expect("authorize URL carries redirect_uri");
        let redirect = url::Url::parse(&redirect).expect("redirect URL");
        let mut socket = tokio::net::TcpStream::connect((
            "127.0.0.1",
            redirect.port().expect("redirect carries the listener port"),
        ))
        .await
        .expect("connect to the flow's redirect listener");
        socket
            .write_all(
                format!(
                    "GET {}?error=access_denied HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    redirect.path()
                )
                .as_bytes(),
            )
            .await
            .expect("write the redirect");

        assert!(matches!(
            next(&mut rx).await.expect("Failed"),
            Ok(AuthEvent::Failed { .. })
        ));
        assert!(
            next(&mut rx).await.is_none(),
            "the flow's own terminal event ends the stream"
        );
        assert!(
            persisted.lock().unwrap().is_empty(),
            "a denied authorisation is not a sign-in, so it must have written \
             no credential",
        );
    }

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
        assert_eq!(state.access_token().await, Some("at1".into()));
        assert_eq!(state.refresh_token().await, Some("rt1".into()));
        state
            .install_tokens("at2".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert_eq!(state.generation(), 2);
        assert_eq!(state.access_token().await, Some("at2".into()));
        // Refresh preserved when install_tokens doesn't supply one.
        assert_eq!(state.refresh_token().await, Some("rt1".into()));
    }

    #[tokio::test]
    async fn token_needs_refresh_handles_unset_and_skew() {
        let state = DiscoveryState::new("default");
        assert!(state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert!(!state.token_needs_refresh().await);
        // Token already inside the skew window.
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

    #[test]
    fn interceptor_preserves_request_specific_interactive_capability() {
        let state = DiscoveryState::new("default");
        assert_eq!(state.capability(), InteractiveAuthCapability::Browser);
        let mut interceptor = AuthorizationInterceptor::new(state);
        let mut request: Request<()> = Request::new(());
        request.metadata_mut().insert(
            X_OV_IAUTH,
            protocol_capability_metadata_value(InteractiveAuthCapability::Headless),
        );

        let intercepted = interceptor.call(request).unwrap();

        assert_eq!(
            capability_from_metadata(intercepted.metadata()),
            InteractiveAuthCapability::Headless,
            "the per-authentication capability must override the connection default",
        );
    }

    #[tokio::test]
    async fn set_and_read_client_credentials_round_trips_and_bumps_identity() {
        let state = DiscoveryState::new("default");
        assert!(state.client_credentials().await.is_none());
        assert_eq!(state.identity_generation(), 0);
        state
            .set_client_credentials("svc-id".into(), "svc-secret".into())
            .await;
        assert_eq!(
            state.client_credentials().await,
            Some(("svc-id".into(), "svc-secret".into()))
        );
        // An explicit credential update is an identity change.
        assert_eq!(state.identity_generation(), 1);
    }

    #[tokio::test]
    async fn has_silent_grant_reflects_refresh_and_client_credentials() {
        let state = DiscoveryState::new("default");
        assert!(!state.has_silent_grant(), "fresh state has no silent grant");
        state.install_refresh_token("rt".into()).await;
        assert!(
            state.has_silent_grant(),
            "a stored refresh is a silent grant"
        );

        let state2 = DiscoveryState::new("default");
        state2
            .set_client_credentials("id".into(), "secret".into())
            .await;
        assert!(
            state2.has_silent_grant(),
            "a cached client_credentials pair is a silent grant"
        );
    }

    #[tokio::test]
    async fn install_tokens_merge_does_not_bump_identity_gen() {
        let state = DiscoveryState::new("default");
        state
            .install_tokens("at".into(), Some("rt".into()), None)
            .await;
        // A routine refresh grant is a same-identity merge.
        assert_eq!(state.identity_generation(), 0);
        assert_eq!(state.generation(), 1);
    }

    #[tokio::test]
    async fn replace_tokens_bumps_identity_gen_and_clears_client_credentials() {
        let state = DiscoveryState::new("default");
        state
            .set_client_credentials("id".into(), "secret".into())
            .await;
        assert_eq!(state.identity_generation(), 1);
        state
            .replace_tokens("at".into(), Some("rt".into()), None)
            .await;
        // Interactive auth supersedes any M2M grant and is a fresh identity.
        assert!(state.client_credentials().await.is_none());
        assert_eq!(state.identity_generation(), 2);
    }

    /// Credential lineage tracks identity-changing writes — interactive
    /// `replace_tokens` (pair-clearing) marks the live identity
    /// non-service, an explicit M2M (re)establishment clears the mark, and
    /// same-identity merges leave it untouched.
    #[tokio::test]
    async fn interactive_identity_lineage_follows_identity_changing_writes() {
        let state = DiscoveryState::new("default");
        assert!(
            !state.interactive_identity(),
            "fresh state is not interactive"
        );

        // Interactive sign-in: lineage flips to interactive.
        state
            .replace_tokens("user-at".into(), Some("user-rt".into()), None)
            .await;
        assert!(state.interactive_identity());

        // A same-identity refresh merge does not change the lineage.
        let fence_gen = state.identity_generation();
        state
            .install_tokens_if_identity_unchanged("user-at2".into(), None, None, fence_gen)
            .await;
        assert!(state.interactive_identity());

        // An explicit M2M credential update restores the service lineage.
        state
            .set_client_credentials("id".into(), "secret".into())
            .await;
        assert!(!state.interactive_identity());

        // An explicit identity replacement that SETS a pair is service
        // lineage; one that CLEARS it is not.
        let fence_gen = state.identity_generation();
        state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                "svc".into(),
                None,
                None,
                Some(("id2".into(), "secret2".into())),
                fence_gen,
            )
            .await;
        assert!(!state.interactive_identity());
        let fence_gen = state.identity_generation();
        state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                "pasted".into(),
                None,
                None,
                None,
                fence_gen,
            )
            .await;
        assert!(
            state.interactive_identity(),
            "a pair-clearing identity write is non-service lineage"
        );
    }

    #[tokio::test]
    async fn install_tokens_if_identity_unchanged_respects_the_fence() {
        let state = DiscoveryState::new("default");
        let gen0 = state.identity_generation();
        // A concurrent identity change lands first.
        state
            .replace_tokens("interactive".into(), Some("rt".into()), None)
            .await;
        // The stale-fenced install is discarded, and the live cell keeps the
        // interactive token.
        let committed = state
            .install_tokens_if_identity_unchanged("stale".into(), None, None, gen0)
            .await;
        assert!(!committed, "a superseded install must not commit");
        assert_eq!(state.access_token().await.as_deref(), Some("interactive"));

        // A fresh fence commits and merges.
        let gen_now = state.identity_generation();
        let committed = state
            .install_tokens_if_identity_unchanged("merged".into(), None, None, gen_now)
            .await;
        assert!(committed, "an up-to-date fence must commit");
        assert_eq!(state.access_token().await.as_deref(), Some("merged"));
    }

    #[tokio::test]
    async fn replace_tokens_and_client_credentials_if_identity_unchanged_replaces_and_bumps() {
        let state = DiscoveryState::new("default");
        // Seed a refresh-bearing + M2M identity.
        state
            .install_tokens("old".into(), Some("old-rt".into()), None)
            .await;
        state
            .set_client_credentials("old-id".into(), "old-secret".into())
            .await;
        let gen0 = state.identity_generation();

        // Explicit access-only replacement: refresh slot CLEARED, M2M CLEARED,
        // identity_gen BUMPED.
        let committed = state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                "new".into(),
                None,
                None,
                None,
                gen0,
            )
            .await;
        assert!(committed);
        assert_eq!(state.access_token().await.as_deref(), Some("new"));
        assert_eq!(state.refresh_token().await, None);
        assert_eq!(state.client_credentials().await, None);
        assert_eq!(state.identity_generation(), gen0 + 1);

        // Replacing WITH a supplied M2M pair sets it.
        let gen1 = state.identity_generation();
        let committed = state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                "newer".into(),
                None,
                None,
                Some(("id2".into(), "secret2".into())),
                gen1,
            )
            .await;
        assert!(committed);
        assert_eq!(
            state.client_credentials().await,
            Some(("id2".into(), "secret2".into()))
        );
        assert_eq!(state.identity_generation(), gen1 + 1);
    }

    #[tokio::test]
    async fn replace_tokens_and_client_credentials_if_identity_unchanged_respects_the_fence() {
        let state = DiscoveryState::new("default");
        let stale_gen = state.identity_generation();
        // A concurrent identity change lands first.
        state
            .replace_tokens("winner".into(), Some("winner-rt".into()), None)
            .await;
        // The stale-fenced replacement is discarded; the live cell keeps the
        // winner and does NOT bump again.
        let gen_after_winner = state.identity_generation();
        let committed = state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                "stale".into(),
                None,
                None,
                None,
                stale_gen,
            )
            .await;
        assert!(!committed, "a superseded replacement must not commit");
        assert_eq!(state.access_token().await.as_deref(), Some("winner"));
        assert_eq!(state.refresh_token().await.as_deref(), Some("winner-rt"));
        assert_eq!(state.identity_generation(), gen_after_winner);
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

    /// The install site under test is the fenced replacement; the shared
    /// harness supplies the cycle, the deadline and the diagnosis.
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
                    r#"{{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided: {SECRET}"}}"#
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
        let error = drive_client_credentials_grant_with_secret(
            &reqwest::Client::new(),
            &state,
            "client-1",
            SECRET,
        )
        .await
        .expect_err("a 400 from the token endpoint must fail the grant");
        let message = error.to_string();
        assert!(
            !message.contains(SECRET),
            "the rejected secret reached the error message: {message}"
        );
        assert!(
            !message.contains("AADSTS7000215"),
            "the error_description reached the error message: {message}"
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
        let error = drive_client_credentials_grant_with_secret(
            &reqwest::Client::new(),
            &state,
            "client-1",
            "unused",
        )
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
