// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Identity binding for persisted OAuth refresh-token lineages.
//!
//! A durable refresh token is only safe to adopt if the process can show the
//! lineage belongs to the account this connection is configured for. Two
//! independent mechanisms carry that guarantee, and they compose:
//!
//! 1. **A durable account discriminator.** The `persistence_id` connection
//!    setting is immutable operator-chosen text folded into the durable key, so
//!    two same-endpoint connections meant for different accounts land on
//!    different keyring entries. It is deliberately separate from
//!    `display_name`: a presentation label is mutable, and a discriminator
//!    derived from one would move a connection's credential on every rename.
//!
//!    That is a property of this key derivation, not of every plugin. The
//!    `nucleus` plugin keys on `display_name` plus its whole config map (see
//!    `conn_id_from_request`), so a rename does move its credential there; its
//!    documentation states the caveat.
//! 2. **A verified-identity binding.** Each persisted refresh token carries an
//!    [`IdentityBinding`] — the issuer, OIDC client, and principal learned from
//!    the token the provider actually minted. Warm continuation re-derives that
//!    triple from the freshly granted access token and refuses the session when
//!    it disagrees with the stored record.
//!
//! Where neither mechanism can discriminate — no `persistence_id`, an opaque
//! access token with no inspectable principal, and two live connections on one
//! endpoint and client — the two connections contend for one key. That
//! ambiguity is resolved by refusing: [`PersistenceClaim::is_exclusive`] reports
//! false while a key has more than one live claimant, and callers neither adopt
//! nor rotate the shared lineage until the operator gives the connections
//! distinct `persistence_id`s.
//!
//! # Scope of the guarantee
//!
//! Mechanism 3 is **process-local**. The claim registry is a process-wide map,
//! so two ovstorage processes running as one OS user — a broker daemon and a
//! CLI, or two DCC applications — each see themselves as the sole claimant of a
//! shared key. Mechanism 2 does not cover that case either: the second process
//! warm-continues on the *stored* lineage, so the grant returns the lineage
//! owner's identity and verification passes by construction.
//!
//! So the guarantee is: two connections cannot silently share a lineage **when
//! they carry distinct `persistence_id`s, or when they are live in one
//! process**. Across processes with no discriminator set, mechanism 1 is the
//! only defence, which is why the plugin docs tell operators to set
//! `persistence_id` whenever one endpoint serves more than one account.
//!
//! Every failure mode here fails closed: an unverifiable lineage is not
//! adopted, and the connection falls back to interactive authentication.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::types::{ConnectionId, SecretBundle, SecretValue};
use crate::{Error, ErrorCode, Result};

/// Serialization version of the stored binding record. A record written under a
/// version this build does not understand is treated as absent, which fails
/// closed into interactive re-authentication.
///
/// cbindgen:ignore
/// Host-side keyring bookkeeping, not part of the plugin ABI: this version tags
/// a record the host reads and writes on its own, and no plugin ever sees it.
const BINDING_VERSION: u64 = 1;

/// The identity a persisted refresh-token lineage belongs to.
///
/// Fields are recorded from the token the provider minted, not from
/// configuration, so the binding describes the account that actually
/// authenticated. An empty field means "the provider did not expose this" —
/// an opaque (non-JWT) access token yields an empty `issuer` and `subject` —
/// and an empty stored field matches anything, because refusing on a
/// discriminator the provider never emits would strand every deployment behind
/// such a provider. Discrimination for those deployments comes from
/// `persistence_id` instead.
///
/// A record with *every* field empty is a different thing: it constrains
/// nothing at all, so it is not a binding. [`Self::is_specific`] separates the
/// two, and the storage layer neither writes nor adopts a non-specific record.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IdentityBinding {
    /// OIDC issuer that minted the lineage (`iss`).
    pub issuer: String,
    /// OIDC client the lineage was minted for (`azp` / `client_id` / `appid`,
    /// falling back to the configured client name).
    pub client_id: String,
    /// Verified principal (`sub`).
    pub subject: String,
}

/// Renders every field as a [`fingerprint`], never in the clear. A subject or
/// issuer is personally identifying, and a derived `Debug` would put it into any
/// log line or assertion failure that touched a binding — including through the
/// containing types, which is why redacting the token alone is not enough. The
/// fingerprints still compare, so a log or a failure remains diagnosable.
impl std::fmt::Debug for IdentityBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityBinding")
            .field("issuer", &fingerprint(&self.issuer))
            .field("client_id", &fingerprint(&self.client_id))
            .field("subject", &fingerprint(&self.subject))
            .finish()
    }
}

impl IdentityBinding {
    /// A binding that names an account on at least one axis, and so can refuse
    /// at least one identity. The storage layer requires this of every record
    /// it writes or adopts.
    pub fn is_specific(&self) -> bool {
        !self.issuer.is_empty() || !self.client_id.is_empty() || !self.subject.is_empty()
    }

    /// Serialize for storage next to the refresh token.
    ///
    /// The encoding is a version tag plus length-framed fields, so a value
    /// containing the separator cannot forge a neighbouring field.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("ovstorage-oauth-binding-v{BINDING_VERSION}");
        for value in [&self.issuer, &self.client_id, &self.subject] {
            out.push('\n');
            out.push_str(&STANDARD_NO_PAD.encode(value.as_bytes()));
        }
        out.into_bytes()
    }

    /// Parse a stored record. `None` for an absent, truncated, unknown-version,
    /// or otherwise undecodable record — all of which callers treat as an
    /// unbound lineage and refuse to adopt.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.split('\n');
        let tag = lines.next()?;
        if tag != format!("ovstorage-oauth-binding-v{BINDING_VERSION}") {
            return None;
        }
        let mut field = || -> Option<String> {
            let raw = lines.next()?;
            String::from_utf8(STANDARD_NO_PAD.decode(raw).ok()?).ok()
        };
        let issuer = field()?;
        let client_id = field()?;
        let subject = field()?;
        Some(Self {
            issuer,
            client_id,
            subject,
        })
    }

    /// Confirm `observed` is the same account as `self` (the stored record).
    ///
    /// A stored field that names something must be reproduced exactly by the
    /// freshly authenticated identity; a stored field left empty imposes no
    /// constraint. An observed field that went empty where the record names a
    /// value is a mismatch, not a pass: a provider that once emitted the claim
    /// keeps emitting it, so its disappearance means the token came from
    /// somewhere else.
    pub fn verify(&self, observed: &Self) -> Result<()> {
        for (label, stored, seen) in [
            ("issuer", &self.issuer, &observed.issuer),
            ("client_id", &self.client_id, &observed.client_id),
            ("subject", &self.subject, &observed.subject),
        ] {
            if !stored.is_empty() && stored != seen {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    format!(
                        "persisted credential belongs to a different identity: {label} \
                         bound to {} but the authenticated session is {}; \
                         sign in again, and give same-endpoint connections distinct \
                         `persistence_id` values so each keeps its own credential",
                        fingerprint(stored),
                        fingerprint(seen),
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Fold a freshly observed identity into the stored record, sharpening
    /// fields the record left empty and keeping the rest. Callers run
    /// [`Self::verify`] first, so the two agree wherever both are specific.
    pub fn merged(&self, observed: &Self) -> Self {
        fn pick(stored: &str, seen: &str) -> String {
            if seen.is_empty() {
                stored.to_string()
            } else {
                seen.to_string()
            }
        }
        Self {
            issuer: pick(&self.issuer, &observed.issuer),
            client_id: pick(&self.client_id, &observed.client_id),
            subject: pick(&self.subject, &observed.subject),
        }
    }
}

/// Validate an operator-supplied durable account discriminator.
///
/// Surrounding whitespace is **rejected, not trimmed**. Trimming would map
/// `"alice"` and `"alice "` onto one durable key, silently merging two
/// connections the operator wrote as different — which is the collapse this
/// setting exists to prevent, and it happens across processes where claim
/// detection offers nothing. An all-whitespace value would likewise become
/// "absent" without saying so. Rejecting says which of the two the operator
/// meant, at the only point where the answer is still recoverable.
///
/// An empty value is valid and means "not set".
pub fn validate_persistence_id(value: &str) -> Result<&str> {
    if value != value.trim() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "`persistence_id` must not begin or end with whitespace: it is a durable \
             key, and trimming it would silently merge two connections written as \
             different (or split one written as the same). Remove the surrounding \
             whitespace, or leave the setting out entirely",
        ));
    }
    Ok(value)
}

/// A short, non-reversible tag for an identity value, safe to log and stable
/// enough to compare two log lines. Empty values render as `<none>`.
pub fn fingerprint(value: &str) -> String {
    if value.is_empty() {
        return "<none>".into();
    }
    let digest = Sha256::digest(value.as_bytes());
    format!("id:{}", &URL_SAFE_NO_PAD.encode(digest)[..12])
}

/// Derive the identity a granted access token attests to.
///
/// A JWT contributes its `iss`, `sub`, and client claim. Any other shape —
/// an opaque provider token, a malformed segment, unparseable JSON — yields a
/// binding carrying only `configured_client`, which names the account on no
/// axis the provider controls; such deployments discriminate by
/// `persistence_id`.
///
/// The claims are read without signature verification. That is sound because of
/// what the result is used for, not because of where the token came from — a
/// caller-supplied `oauth` bundle installed at connection seeding reaches here
/// without this process ever driving a grant. Two properties carry it:
///
/// * The triple never reaches an authorization decision. It decides only
///   whether a durable credential slot belongs to this connection; every access
///   check is made by the server against the token's real signature.
/// * It cannot relax an existing binding. [`BindingCell::observe`] verifies
///   before it merges, so a forged or altered token is refused rather than
///   overwriting the stored record — the most a crafted token achieves is
///   denying its own connection a warm continuation.
///
/// Claiming a stored lineage still requires deriving its key, which requires
/// reading the secret store — at which point the attacker holds the secret itself
/// and needs none of this.
pub fn identity_from_access_token(access: &str, configured_client: &str) -> IdentityBinding {
    let fallback = IdentityBinding {
        issuer: String::new(),
        client_id: configured_client.to_string(),
        subject: String::new(),
    };
    let mut parts = access.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return fallback;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')) else {
        return fallback;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return fallback;
    };
    let claim = |name: &str| -> String {
        claims
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let client_id = ["azp", "client_id", "appid"]
        .iter()
        .map(|name| claim(name))
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| configured_client.to_string());
    IdentityBinding {
        issuer: claim("iss"),
        client_id,
        subject: claim("sub"),
    }
}

/// Pull the access token out of the `oauth` field of a credential bundle.
pub fn access_token_of(creds: &SecretBundle) -> Option<String> {
    match creds.fields.get("oauth")? {
        SecretValue::OAuthToken { token, .. } => {
            let text = std::str::from_utf8(&token.0).ok()?;
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => None,
    }
}

/// Pull the refresh token out of the `oauth` field of a credential bundle.
///
/// `None` for a bundle with no `oauth` field, a non-OAuth field, a missing or
/// empty refresh token, or non-UTF-8 bytes — every case where the bundle names
/// no lineage to compare against.
pub fn refresh_token_of(creds: &SecretBundle) -> Option<String> {
    match creds.fields.get("oauth")? {
        SecretValue::OAuthToken { refresh, .. } => {
            let text = std::str::from_utf8(&refresh.as_ref()?.0).ok()?;
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => None,
    }
}

/// A connection's live view of the identity its persisted lineage is bound to.
///
/// `expect` seeds it from the durable store during warm continuation, `observe`
/// checks each freshly granted token against that seed, and `current` supplies
/// the record to write back on rotation. Rotation therefore preserves the
/// binding: the record travels with the connection rather than being rederived
/// from whatever the last grant happened to contain.
#[derive(Debug, Default)]
pub struct BindingCell {
    inner: Mutex<Option<IdentityBinding>>,
}

impl BindingCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the expectation from a durable record.
    pub fn expect(&self, binding: IdentityBinding) {
        *self.inner.lock() = Some(binding);
    }

    /// The record to persist alongside the refresh token.
    pub fn current(&self) -> Option<IdentityBinding> {
        self.inner.lock().clone()
    }

    /// Forget the binding, for credential removal and purge.
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }

    /// Check a freshly authenticated identity against the expectation and latch
    /// the sharpened record.
    ///
    /// `Err` means the session authenticated as an identity the persisted
    /// lineage is not bound to: the caller refuses the session rather than
    /// adopting a credential whose owner it cannot confirm.
    pub fn observe(&self, observed: IdentityBinding) -> Result<()> {
        let mut guard = self.inner.lock();
        match guard.as_ref() {
            Some(stored) => {
                stored.verify(&observed)?;
                *guard = Some(stored.merged(&observed));
            }
            None => *guard = Some(observed),
        }
        Ok(())
    }

    /// [`Self::observe`] for the identity a granted access token attests to. An
    /// empty token teaches nothing and leaves the cell untouched.
    pub fn observe_access_token(&self, access: &str, configured_client: &str) -> Result<()> {
        if access.is_empty() {
            return Ok(());
        }
        self.observe(identity_from_access_token(access, configured_client))
    }

    /// [`Self::observe_access_token`] for the access token carried by a
    /// credential bundle. A bundle with no access token teaches nothing.
    pub fn observe_bundle(&self, creds: &SecretBundle, configured_client: &str) -> Result<()> {
        match access_token_of(creds) {
            Some(access) => self.observe_access_token(&access, configured_client),
            None => Ok(()),
        }
    }
}

/// Live claimants of one durable persistence key, and how many times the key
/// has ever been contended.
#[derive(Debug, Default, Clone, Copy)]
struct KeyClaims {
    live: usize,
    /// Incremented whenever a second claimant arrives. A claim compares this
    /// against the value it captured at acquisition, so contention that begins
    /// *and ends* while the claim is alive still leaves the claim ambiguous.
    contentions: u64,
}

/// The owner of a connection's identity generation.
///
/// Implemented by whatever holds the live credential state — `DiscoveryState`
/// in the OAuth plugins, `NucleusShared` in the Nucleus plugin. It exists so
/// that "is this flow still current?" is asked of the generation's owner under
/// the owner's own lock, rather than compared against a `u64` some caller read
/// earlier.
///
/// # What may run inside the fence
///
/// The closure runs while an identity lock is held, and that lock is on the
/// path of every credential install. It MUST be bounded, non-blocking, and
/// MUST NOT acquire another lock or perform I/O. Durable writes belong on the
/// publication lock instead, which exists precisely so a slow secret store call
/// never runs here — a DBus, Keychain or Windows credential-manager round trip
/// can take seconds, and the Nucleus identity fence is its session lock, which
/// the read path also takes.
pub trait IdentityEpoch: Send + Sync {
    /// Run `f` while holding the lock that makes this connection's identity
    /// generation and its identity binding atomic, passing the generation as
    /// read under that lock.
    fn with_identity_fence(&self, f: &mut dyn FnMut(EpochView<'_>) -> LeaseVerdict)
    -> LeaseVerdict;
}

/// What the identity fence exposes, read as one consistent snapshot.
#[derive(Debug, Clone, Copy)]
pub struct EpochView<'a> {
    /// The connection's identity generation.
    pub generation: u64,
    /// The identity the live credential belongs to.
    pub binding: Option<&'a IdentityBinding>,
    /// A [`fingerprint`] of the refresh token the live identity published.
    ///
    /// This is what lets a durable write prove the credential it carries
    /// belongs to the CURRENT generation rather than merely coexisting with it.
    /// The binding cannot do that job: an opaque-token deployment collapses
    /// every identity onto the same client-only binding, so two flows agree
    /// there while carrying different secrets. The secret itself always
    /// differs, and a fingerprint compares it without copying it.
    pub published_credential: Option<&'a str>,
}

/// The outcome of work attempted under an identity fence.
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseVerdict {
    /// The lease was current and the work ran.
    Current,
    /// The generation had moved, or its owner is gone: the work did not run.
    Superseded,
}

/// A capability to publish credential state on behalf of one identity epoch.
///
/// Minted when a flow begins and required by every entry point that publishes
/// credential state — a durable write, a binding adoption, a terminal auth
/// event. A flow that has been superseded cannot express the write, so
/// fencing stops being a decision each call site makes (and a new call site
/// forgets) and becomes the only way to reach the operation at all.
///
/// The epoch is held **weakly**, and that is a guard against a future shape
/// rather than a live one: today `identity_epoch()` hands out a fresh `Arc` per
/// call over an already-`Arc`'d inner state, so the state is retained
/// regardless and the upgrade never fails. It is `Weak` so that a lease held by
/// a flow which parks for minutes — an interactive sign-in waiting on a person
/// — cannot be what keeps a removed connection's credential state alive if the
/// epoch ever becomes uniquely owned. A dropped epoch reads as superseded,
/// which is the fail-closed answer: state that no longer exists cannot
/// authorize a durable write.
pub struct IdentityLease {
    epoch: std::sync::Weak<dyn IdentityEpoch>,
    anchor: LeaseAnchor,
}

/// What a lease is measured against.
///
/// Which anchor is correct depends on whether the flow holding the lease is
/// the one that changed the identity.
#[derive(Debug, Clone)]
enum LeaseAnchor {
    /// An identity generation this flow must still own.
    ///
    /// For a flow that made no identity change, that is the generation it
    /// began at. For an interactive sign-in it is the generation its OWN commit
    /// produced — anchoring such a flow where it started would refuse every
    /// sign-in, since by the time its credential is written the generation has
    /// moved by exactly one: its own.
    ///
    /// Anchoring on the published IDENTITY instead was tried and is wrong:
    /// `identity_from_access_token` collapses every opaque token onto the same
    /// `{"", configured_client, ""}`, so two flows on one connection derive the
    /// same anchor and a superseded one reads as current. Opaque-token
    /// deployments are first-class here.
    Generation(u64),
}

impl std::fmt::Debug for IdentityLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLease")
            .field("anchor", &self.anchor)
            .field("epoch_live", &self.epoch.upgrade().is_some())
            .finish()
    }
}

impl IdentityLease {
    /// Capture the epoch's current generation.
    pub fn capture(epoch: &Arc<dyn IdentityEpoch>) -> Self {
        let mut captured = 0;
        epoch.with_identity_fence(&mut |view| {
            captured = view.generation;
            LeaseVerdict::Current
        });
        Self {
            epoch: Arc::downgrade(epoch),
            anchor: LeaseAnchor::Generation(captured),
        }
    }

    /// A lease on a generation the caller already knows — for an interactive
    /// sign-in, the one its own commit produced.
    pub fn at_generation(epoch: &Arc<dyn IdentityEpoch>, generation: u64) -> Self {
        Self {
            epoch: Arc::downgrade(epoch),
            anchor: LeaseAnchor::Generation(generation),
        }
    }

    /// Run `f` under the identity fence, but only while this lease is current.
    ///
    /// The compare and the work are one step: an identity-changing install
    /// holds the same lock across its own generation bump, so it cannot land
    /// between them.
    pub fn if_current(&self, f: &mut dyn FnMut() -> LeaseVerdict) -> LeaseVerdict {
        let Some(epoch) = self.epoch.upgrade() else {
            return LeaseVerdict::Superseded;
        };
        epoch.with_identity_fence(&mut |view| {
            let LeaseAnchor::Generation(captured) = &self.anchor;
            let current = view.generation == *captured;
            if !current {
                return LeaseVerdict::Superseded;
            }
            f()
        })
    }

    /// Whether the flow that minted this lease still owns the identity.
    pub fn is_current(&self) -> bool {
        self.if_current(&mut || LeaseVerdict::Current) == LeaseVerdict::Current
    }

    /// The error a superseded flow reports rather than publishing.
    pub fn superseded_error(&self) -> Error {
        Error::new(
            ErrorCode::AuthCancelled,
            "this sign-in was superseded by a newer one for the same connection; \
             its credentials were not published",
        )
    }
}

/// Process-wide claim registry for durable persistence keys.
///
/// cbindgen:ignore
/// Host-internal state with no C representation: a `Mutex<HashMap<..>>` has no
/// stable layout to expose, and claims are arbitrated entirely inside the host —
/// a plugin neither sees nor participates in them.
type ClaimRegistry = Mutex<HashMap<String, KeyClaims>>;

fn claims() -> &'static ClaimRegistry {
    static CLAIMS: std::sync::OnceLock<ClaimRegistry> = std::sync::OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A live connection's claim on one durable persistence key.
///
/// Held for as long as the connection exists. While two connections hold a
/// claim on one key, neither can tell which of them the stored lineage belongs
/// to, so [`Self::is_exclusive`] reports false and callers neither adopt nor
/// rotate the entry. Giving the connections distinct `persistence_id` values
/// separates their keys and restores exclusivity; removing the duplicate does
/// too, since the claim releases on drop.
///
/// The registry is **per process**: a claim held in another process is
/// invisible here, so this detects duplicates within one host application and
/// not across two. See the module-level "Scope of the guarantee". A durable
/// cross-process registry is deliberately not attempted — a crashed process
/// would strand a claim nobody can release, converting a shared-key warning
/// into a permanent lockout.
#[derive(Debug)]
pub struct PersistenceClaim {
    key: ConnectionId,
    /// The registry key: `key` namespaced by backend kind.
    namespaced: String,
    registry: &'static ClaimRegistry,
    /// Whether this claim has adopted a durable lineage.
    adopted: std::sync::atomic::AtomicBool,
    /// Contention count as it stood *before* this claim registered. Any
    /// contention this claim takes part in — including its own arrival onto an
    /// already-claimed key — moves the registry's count past this, and nothing
    /// moves it back.
    contentions_at_acquire: u64,
}

impl PersistenceClaim {
    /// Register a claim on `key`.
    pub fn acquire(backend_kind: &str, key: &ConnectionId) -> Self {
        // Namespaced by backend kind: the durable store entries are, so two
        // plugins whose keys collide (a broker and a services-client against one
        // origin and OIDC client derive the same origin#client string) address
        // different secrets and must not contend.
        let namespaced = format!("{backend_kind}\n{}", key.0);
        let registry = claims();
        let contentions_at_acquire = {
            let mut guard = registry.lock();
            let entry = guard.entry(namespaced.clone()).or_default();
            // Read before the increment, so a claim that arrives onto a key
            // somebody already holds counts itself as contended. Reading after
            // would let the newcomer call itself clean the moment the earlier
            // claimants left — and it is exactly the newcomer that must not
            // inherit a lineage established before it existed.
            let observed = entry.contentions;
            // Saturating, not wrapping: a release build that wrapped either
            // counter would fail OPEN — a wrapped contention count could match
            // a long-lived claim's captured value again, and a wrapped `live`
            // could reach zero and drop the entry, which reads as "unclaimed".
            // Both are unreachable in practice; neither should be a silent
            // path back to exclusivity.
            entry.live = entry.live.saturating_add(1);
            if entry.live > 1 {
                entry.contentions = entry.contentions.saturating_add(1);
            }
            observed
        };
        Self {
            key: key.clone(),
            namespaced,
            registry,
            adopted: std::sync::atomic::AtomicBool::new(false),
            contentions_at_acquire,
        }
    }

    /// The key claimed.
    pub fn key(&self) -> &ConnectionId {
        &self.key
    }

    /// Whether this claim is the only live one on the key *in this process*,
    /// and has been for its whole life.
    ///
    /// A momentary count would be a check-then-act race: a caller that read
    /// "exclusive", then loaded a credential and drove a grant, could have had
    /// a sibling claim the key throughout that window and would still adopt the
    /// lineage. So contention is remembered — once a second claimant has been
    /// seen, this claim stays ambiguous even after that sibling goes away,
    /// because nothing it does afterwards can establish whose the stored
    /// lineage was. A caller that checks before *and* after an operation
    /// therefore refuses any operation a sibling overlapped.
    ///
    /// Recovering means giving the connections distinct `persistence_id`s and
    /// reconnecting, which is the operator action the ambiguity calls for.
    pub fn is_exclusive(&self) -> bool {
        let guard = self.registry.lock();
        let Some(entry) = guard.get(&self.namespaced) else {
            return true;
        };
        entry.live <= 1 && entry.contentions == self.contentions_at_acquire
    }

    /// Record that this claim adopted a durable lineage.
    ///
    /// Adoption is a decision made once, at warm continuation. Contention can
    /// arrive afterwards — connections are restored sequentially, so the first
    /// one to load is genuinely the sole claimant at that moment — which makes
    /// the adoption a thing that must be revisited, not only guarded going in.
    pub fn record_adoption(&self) {
        self.adopted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Give back an adoption the caller then declined to use.
    ///
    /// [`read_claimed_refresh_token`](crate::oauth_secret_store::read_claimed_refresh_token)
    /// latches on the read, so a driver cannot forget to record one. A driver
    /// does have a legitimate reason to decline AFTER that read, though: its own
    /// generation fence discards a record an identity-changing write superseded
    /// while the secret-store round trip was in flight, and the connection then
    /// serves on nothing it read. Leaving the latch standing would make a later
    /// sibling's arrival retro-actively fatal — [`Self::ensure_usable`] refusing
    /// a connection that never adopted anything — so the decline says so here.
    ///
    /// Retracting is the fail-SAFE direction of the pair: a driver that forgets
    /// to retract stays over-strict, where a driver that forgot to record would
    /// serve on a lineage nobody can attribute.
    pub fn retract_adoption(&self) {
        self.adopted
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether this claim may still act on the lineage it holds.
    ///
    /// `Err` means a sibling connection claimed this key AFTER this one had
    /// already adopted its stored lineage.
    ///
    /// The retraction is bounded by when this is called — the adopter keeps
    /// serving on the adopted credential until its next credential operation,
    /// which with a valid access token can be up to that token's lifetime.
    /// Narrowing that would need a channel from this registry up into
    /// `ConnectionSet` so a claim can park a live connection; claims are a leaf
    /// substrate holding no handle on the lifecycle that owns the connection,
    /// so there is no such channel. Setting a distinct per-connection
    /// `persistence_id` prevents the situation entirely. Nothing distinguishes the two
    /// connections, so nothing can say the lineage was this one's — and it is
    /// already serving on it. The connection re-authenticates, and the sign-in
    /// binds it to whoever actually signs in.
    pub fn ensure_usable(&self) -> Result<()> {
        if !self.adopted.load(std::sync::atomic::Ordering::SeqCst) || self.is_exclusive() {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::AuthRequired,
            "this connection adopted a stored credential, and another live connection \
             then claimed the same credential persistence key; nothing can show the \
             credential was this connection's. Set a distinct `persistence_id` on each \
             connection and sign in again",
        ))
    }

    /// The error to surface when a caller must refuse an ambiguous key.
    pub fn ambiguity_error(&self) -> Error {
        Error::new(
            ErrorCode::AuthRequired,
            "two live connections share one credential persistence key; \
             set a distinct `persistence_id` on each so they keep separate \
             credentials, then sign in again",
        )
    }
}

impl Drop for PersistenceClaim {
    fn drop(&mut self) {
        let mut guard = self.registry.lock();
        if let Some(entry) = guard.get_mut(&self.namespaced) {
            entry.live = entry.live.saturating_sub(1);
            // The whole entry goes only when nobody holds the key: a surviving
            // claim must keep seeing the contention count that outranks its
            // own, and a key nobody claims has no claim left to mislead.
            if entry.live == 0 {
                guard.remove(&self.namespaced);
            }
        }
    }
}

/// A [`PersistenceClaim`] shared by the clones of one connection's driver.
pub type SharedPersistenceClaim = Arc<PersistenceClaim>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecretBytes;

    fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            URL_SAFE_NO_PAD.encode(b"signature"),
        )
    }

    fn binding(issuer: &str, client_id: &str, subject: &str) -> IdentityBinding {
        IdentityBinding {
            issuer: issuer.into(),
            client_id: client_id.into(),
            subject: subject.into(),
        }
    }

    #[test]
    fn binding_round_trips_through_storage() {
        let original = binding("https://idp.example/realm", "storage-cli", "alice@example");
        let decoded = IdentityBinding::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn binding_encoding_frames_fields_unambiguously() {
        // A value containing the separator cannot spill into the next field.
        let sneaky = binding("iss\nspill", "client", "sub");
        assert_eq!(IdentityBinding::decode(&sneaky.encode()).unwrap(), sneaky);
    }

    #[test]
    fn undecodable_records_read_as_absent() {
        assert!(IdentityBinding::decode(b"").is_none());
        assert!(IdentityBinding::decode(b"garbage").is_none());
        // A future version tag is not silently reinterpreted under this schema.
        assert!(IdentityBinding::decode(b"ovstorage-oauth-binding-v9\nx\ny\nz").is_none());
        // A truncated record is incomplete, not a partially-populated binding.
        assert!(IdentityBinding::decode(b"ovstorage-oauth-binding-v1\nx").is_none());
    }

    #[test]
    fn verify_rejects_a_different_principal() {
        let stored = binding("https://idp.example", "cli", "alice");
        let other = binding("https://idp.example", "cli", "bob");
        let err = stored.verify(&other).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(err.to_string().contains("subject"));
        // The message names identities by fingerprint, never in the clear.
        assert!(!err.to_string().contains("alice"));
        assert!(!err.to_string().contains("bob"));
    }

    #[test]
    fn verify_rejects_a_different_issuer_or_client() {
        let stored = binding("https://idp.example", "cli", "alice");
        assert!(
            stored
                .verify(&binding("https://evil.example", "cli", "alice"))
                .is_err()
        );
        assert!(
            stored
                .verify(&binding("https://idp.example", "other", "alice"))
                .is_err()
        );
        assert!(stored.verify(&stored).is_ok());
    }

    #[test]
    fn verify_fails_closed_when_a_bound_claim_disappears() {
        // A provider that emitted `sub` keeps emitting it; its absence means the
        // token came from elsewhere, so the session is refused rather than
        // adopted on the strength of the fields that still agree.
        let stored = binding("https://idp.example", "cli", "alice");
        assert!(
            stored
                .verify(&binding("https://idp.example", "cli", ""))
                .is_err()
        );
    }

    #[test]
    fn verify_admits_fields_the_provider_never_exposed() {
        // An opaque-token deployment records no issuer or subject; those axes
        // impose no constraint, and `persistence_id` discriminates instead.
        let stored = binding("", "cli", "");
        assert!(
            stored
                .verify(&binding("https://idp.example", "cli", "alice"))
                .is_ok()
        );
    }

    #[test]
    fn merged_sharpens_empty_fields_and_keeps_the_rest() {
        let stored = binding("", "cli", "");
        let observed = binding("https://idp.example", "cli", "alice");
        assert_eq!(stored.merged(&observed), observed);
    }

    #[test]
    fn identity_reads_standard_claims_from_a_jwt() {
        let token = jwt(r#"{"iss":"https://idp.example","sub":"alice","azp":"storage-cli"}"#);
        assert_eq!(
            identity_from_access_token(&token, "configured"),
            binding("https://idp.example", "storage-cli", "alice"),
        );
    }

    #[test]
    fn identity_falls_back_to_the_configured_client() {
        let token = jwt(r#"{"iss":"https://idp.example","sub":"alice"}"#);
        assert_eq!(
            identity_from_access_token(&token, "configured"),
            binding("https://idp.example", "configured", "alice"),
        );
        // An opaque token names the account on no provider-controlled axis.
        assert_eq!(
            identity_from_access_token("opaque-token", "configured"),
            binding("", "configured", ""),
        );
        // Neither does a JWT-shaped token with an undecodable payload.
        assert_eq!(
            identity_from_access_token("a.!!!.c", "configured"),
            binding("", "configured", ""),
        );
    }

    #[test]
    fn cell_latches_the_first_identity_and_holds_it_across_rotation() {
        let cell = BindingCell::new();
        let alice = jwt(r#"{"iss":"https://idp.example","sub":"alice","azp":"cli"}"#);
        cell.observe_access_token(&alice, "cli").unwrap();
        assert_eq!(
            cell.current().unwrap(),
            binding("https://idp.example", "cli", "alice"),
        );
        // Rotation to another token for the same account keeps the record.
        cell.observe_access_token(&alice, "cli").unwrap();
        assert_eq!(
            cell.current().unwrap(),
            binding("https://idp.example", "cli", "alice"),
        );
    }

    #[test]
    fn cell_refuses_a_session_that_authenticated_as_someone_else() {
        let cell = BindingCell::new();
        cell.expect(binding("https://idp.example", "cli", "alice"));
        let bob = jwt(r#"{"iss":"https://idp.example","sub":"bob","azp":"cli"}"#);
        let err = cell.observe_access_token(&bob, "cli").unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        // The expectation survives the refusal, so a retry is refused too.
        assert_eq!(cell.current().unwrap().subject, "alice");
    }

    #[test]
    fn cell_ignores_bundles_with_nothing_to_learn_from() {
        let cell = BindingCell::new();
        cell.expect(binding("https://idp.example", "cli", "alice"));
        // A refresh-token-only warm-continuation bundle carries no access token.
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(Vec::new()),
                refresh: Some(SecretBytes(b"rt".to_vec())),
                expires_at: None,
            },
        );
        cell.observe_bundle(&bundle, "cli").unwrap();
        assert_eq!(cell.current().unwrap().subject, "alice");
    }

    #[test]
    fn cell_clear_drops_the_expectation() {
        let cell = BindingCell::new();
        cell.expect(binding("https://idp.example", "cli", "alice"));
        cell.clear();
        assert!(cell.current().is_none());
    }

    #[test]
    fn a_lone_claim_is_exclusive_and_a_duplicate_makes_both_ambiguous() {
        let key = ConnectionId("claim-test-shared".into());
        let first = PersistenceClaim::acquire("test-kind", &key);
        assert!(first.is_exclusive());
        {
            let second = PersistenceClaim::acquire("test-kind", &key);
            assert!(!first.is_exclusive());
            assert!(!second.is_exclusive());
            assert_eq!(second.ambiguity_error().code(), ErrorCode::AuthRequired);
        }
        // Releasing the duplicate does NOT restore exclusivity for a claim that
        // lived through the contention: nothing the survivor can do afterwards
        // establishes whose the stored lineage was while both were live, and a
        // momentary count would let a caller that sampled it before a slow read
        // adopt the lineage anyway. Recovery is an operator giving the
        // connections distinct `persistence_id`s and reconnecting.
        assert!(!first.is_exclusive());

        // A claim that ARRIVES onto a key somebody already holds is contended
        // by its own arrival, and stays so after that holder leaves. This is
        // the shape that recreates the original defect: the newcomer is the
        // connection that must never inherit a lineage established before it
        // existed, and "the other connection was removed" is not evidence the
        // stored credential was ever its own.
        let later = PersistenceClaim::acquire("test-kind", &key);
        assert!(!later.is_exclusive(), "contended on arrival");
        drop(first);
        assert!(
            !later.is_exclusive(),
            "a survivor does not inherit the key by outliving the others",
        );

        // Only a claim on a key nobody holds starts clean.
        drop(later);
        let fresh = PersistenceClaim::acquire("test-kind", &key);
        assert!(fresh.is_exclusive());
    }

    #[test]
    fn the_last_survivor_of_three_claimants_does_not_become_exclusive() {
        // Draining claimants one at a time must not walk the key back to
        // "unambiguous" for whoever happens to remain.
        let key = ConnectionId("claim-test-three".into());
        let a = PersistenceClaim::acquire("test-kind", &key);
        let b = PersistenceClaim::acquire("test-kind", &key);
        let c = PersistenceClaim::acquire("test-kind", &key);
        drop(a);
        assert!(!b.is_exclusive());
        assert!(!c.is_exclusive());
        drop(b);
        assert!(!c.is_exclusive());
    }

    #[test]
    fn a_claim_that_loses_exclusivity_mid_operation_does_not_regain_it() {
        // The check-then-act window: A samples exclusivity, begins a read or a
        // grant, and B claims the key before A finishes. A re-check after the
        // operation must refuse, or A adopts a lineage B was already contending
        // for — the failure this mechanism exists to prevent, at the moment it
        // exists for.
        let key = ConnectionId("claim-test-toctou".into());
        let a = PersistenceClaim::acquire("test-kind", &key);
        assert!(a.is_exclusive(), "the pre-operation check passes");
        {
            let _b = PersistenceClaim::acquire("test-kind", &key);
        }
        // `_b` came and went entirely within A's operation.
        assert!(!a.is_exclusive(), "the post-operation check refuses");
    }

    #[test]
    fn distinct_keys_do_not_contend() {
        let a = PersistenceClaim::acquire("test-kind", &ConnectionId("claim-test-a".into()));
        let b = PersistenceClaim::acquire("test-kind", &ConnectionId("claim-test-b".into()));
        assert!(a.is_exclusive());
        assert!(b.is_exclusive());
        assert_eq!(a.key().0, "claim-test-a");
    }
}
