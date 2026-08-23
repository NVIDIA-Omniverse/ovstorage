// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for the Omniverse Storage Service backend
//! (RFC-0066). The generic `ConnectionSet<OmniverseStorageDriver>` embedded on
//! the crate's `OmniverseStorageLayer` (private) owns the `ConnectionAuthState`
//! machine, single-flight bring-up, cooldown, background-refresh scheduling,
//! cross-process coalescing, and the data-path recovery loop; this driver
//! supplies only the OAuth protocol verbs (obtain / verify / activate / refresh /
//! interactive / classify) plus secret persistence, wrapping the existing
//! `auth`/`factory` machinery. `obtain` grants against a driver-PRIVATE staging
//! `DiscoveryState` and `verify` probes over an EPHEMERAL transport, so neither
//! ever touches the live token cell; only `activate` installs a proven bearer
//! onto it at commit time. The single exception is named where it lives: a
//! REGISTERED grant on a direct-endpoint connection that is handed no
//! credential clears the live cell, because that is what removing a credential
//! means and no other verb is called on that path. One driver instance is bound to one connection (it
//! carries that connection's discovery context + shared `DiscoveryState` token
//! cell the transport interceptor reads).

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ovstorage_plugin::connection::{
    AuthErrorClass, ConnectionAuthDriver, GrantPolicy, Obtained, Refreshed,
};
use ovstorage_plugin::{
    AuthEventStream, AuthReason, CancellationToken, Connection, ConnectionAuthState, ConnectionId,
    Error, ErrorCode, InteractiveAuthCapability, Result, SecretBundle, SecretBytes, SecretValue,
    oauth_secret_store, race_cancel,
};

use crate::auth::{
    self, DiscoveryState, drive_client_credentials_grant, drive_interactive_login,
    drive_refresh_token_grant,
};
use crate::config;
use crate::factory::{
    PLUGIN_NAME, SeedOutcome, list_top_level_addresses, seed_connection_auth,
    warn_direct_credentials_unusable,
};
use crate::transport::OmniverseStorageTransport;

/// Per-connection OAuth driver. Holds the connection's discovery URL, the shared
/// [`DiscoveryState`] (the token cell the transport's `AuthorizationInterceptor`
/// reads, and where `refresh`/`interactive` install fresh tokens), the transport
/// for the auth-gated probe, a shared HTTP client, and the stable keyring id.
pub struct OmniverseStorageDriver {
    /// The connection's HTTP discovery root, or `None` when it is configured
    /// with a direct gRPC endpoint. `None` means there is no auth-config, so no
    /// OIDC grant of any kind can run and the connection takes no part in
    /// credential persistence — it can still carry a bearer the host supplies
    /// and replaces directly.
    discovery_url: Option<String>,
    state: DiscoveryState,
    transport: OmniverseStorageTransport,
    http: reqwest::Client,
    /// Stable cross-process/cross-restart id (discovery URL + OIDC client +
    /// durable account discriminator) for the secret store + refresh lock — the host
    /// `ConnectionId` is `pid+nanos`.
    ///
    /// `None` for a direct-endpoint connection, which has no credential to
    /// persist and therefore no durable key. That is not a cosmetic
    /// simplification: taking a claim is what would let an anonymous connection
    /// contend with a real one — contention is recorded when a claim arrives
    /// onto a key another claim already holds, and is then remembered for that
    /// claim's whole life (see `claim` below).
    stable: Option<ConnectionId>,
    /// This connection's claim on its durable key.
    ///
    /// Taken lazily, on first use — where "use" means touching the durable
    /// store. Laziness alone does NOT keep a probe out: a probe drives
    /// `obtain`, so any guard there that reached through this accessor would
    /// acquire and contend. What keeps it out is that every path a probe takes
    /// inspects the claim without taking one (see `ensure_claim_usable`), and
    /// only load/persist — which a probe does not do — acquire.
    ///
    /// It matters because contention is remembered for a claim's whole life: a
    /// probe that acquired would leave the LIVE connection non-exclusive
    /// forever, refusing its grants and stranding the secret store on a token the
    /// provider has already rotated past.
    ///
    /// A second live connection claiming the same key makes the stored lineage
    /// ambiguous, and persistence is refused for both until the operator sets
    /// distinct `persistence_id`s.
    claim: std::sync::OnceLock<oauth_secret_store::SharedPersistenceClaim>,
    /// Latched the first time this connection reports that part of the bundle
    /// it was handed cannot be acted on. `obtain` runs per operation — every
    /// add, probe and recovery — and an unchanging misconfiguration does not
    /// become news by being restated.
    warned_credentials_unusable: std::sync::atomic::AtomicBool,
    /// Latched the first time this connection is seen sending a bearer over a
    /// cleartext channel. Same reasoning as the field above: `obtain` runs per
    /// operation, and a standing property of the configuration is not news each
    /// time it is restated.
    warned_plaintext_bearer: std::sync::atomic::AtomicBool,
    /// The operator's stated acceptance of sending a bearer over a cleartext
    /// channel that leaves this machine, from
    /// [`config::ALLOW_PLAINTEXT_CREDENTIALS_KEY`].
    ///
    /// A parameter rather than a config lookup at the point of use, so the one
    /// place that reads the key is the layer that builds the connection, and so
    /// every route into this driver — including this public constructor — has to
    /// answer the question rather than inherit a default.
    allow_plaintext_credentials: bool,
}

impl OmniverseStorageDriver {
    pub fn new(
        discovery_url: Option<String>,
        state: DiscoveryState,
        transport: OmniverseStorageTransport,
        http: reqwest::Client,
        persistence_id: &str,
        allow_plaintext_credentials: bool,
    ) -> Result<Self> {
        // Scope the durable key by the OIDC client identity too: two
        // connections to the same discovery URL under different clients are
        // distinct refresh-token lineages and must not share one stored secret /
        // refresh lease. `client_name` lives on the shared `DiscoveryState`.
        // `persistence_id` separates two connections that agree on both.
        // Validated here as well as in the layer: this constructor is public,
        // so it is a way into the durable key that does not pass through
        // config parsing.
        let persistence_id = oauth_secret_store::validate_persistence_id(persistence_id)?;
        // Validated even for a direct-endpoint connection, which derives no key:
        // an operator who sets `persistence_id` on one should hear that it is
        // malformed rather than have it silently ignored.
        let stable = discovery_url.as_deref().map(|url| {
            oauth_secret_store::conn_id_from_url_and_account(
                url,
                state.client_name(),
                persistence_id,
            )
        });
        Ok(Self {
            discovery_url,
            state,
            transport,
            http,
            stable,
            claim: std::sync::OnceLock::new(),
            warned_credentials_unusable: std::sync::atomic::AtomicBool::new(false),
            warned_plaintext_bearer: std::sync::atomic::AtomicBool::new(false),
            allow_plaintext_credentials,
        })
    }

    /// This connection's identity epoch, for minting a flow's lease.
    pub fn identity_epoch(&self) -> std::sync::Arc<dyn oauth_secret_store::IdentityEpoch> {
        std::sync::Arc::new(self.state.clone())
    }

    /// Refuse if this connection's adoption has been retracted.
    ///
    /// Deliberately inspects the claim WITHOUT taking one. `probe` drives
    /// `obtain` on a throwaway driver built from the same request, so it
    /// derives the same durable key — and acquiring here would contend with the
    /// live connection's claim. Contention is remembered for a claim's whole
    /// life, so a single "Test connection" would permanently refuse the live
    /// connection's grants and writes.
    ///
    /// A driver that has never touched the durable store has taken no claim and
    /// has no adoption to retract, which is exactly the probe's case.
    fn ensure_claim_usable(&self) -> Result<()> {
        match self.claim.get() {
            Some(claim) => claim.ensure_usable(),
            None => Ok(()),
        }
    }

    /// Whether this connection is configured with a direct gRPC endpoint, and
    /// therefore has no auth-config, no grant of any kind, and no durable key.
    fn is_direct(&self) -> bool {
        self.discovery_url.is_none()
    }

    /// Whether this connection has actually acquired its persistence claim.
    ///
    /// Exists so a test can assert the *absence* of an acquisition rather than
    /// only the return values of the credential verbs — the damage a stray
    /// claim does is to a sibling connection's exclusivity, which no return
    /// value here would show.
    pub fn has_persistence_claim(&self) -> bool {
        self.claim.get().is_some()
    }

    /// This connection's claim on its durable key, taken on first use.
    ///
    /// `None` for a direct-endpoint connection, which has no key to claim.
    ///
    /// Returning an `Option` rather than deriving a placeholder key is what
    /// makes the rule hard to break: `persist_credentials` and
    /// `load_credentials` cannot reach the secret store without first writing
    /// `let Some(claim) = self.claim() else { … }`, so for those two the
    /// direct-mode answer and the claim-avoidance are a single statement.
    /// `delete_credentials` guards on `stable` instead, because it needs the
    /// key rather than the claim, and `interactive` refuses direct mode
    /// outright before reaching either — those two are separate checks and are
    /// the places to look first if this ever regresses.
    ///
    /// It matters because a direct connection that acquired here would contend
    /// with a real connection on the same key. Contention is remembered for a
    /// claim's whole life, so the live connection's grants would be refused
    /// from then on and its stored credential eventually purged.
    fn claim(&self) -> Option<&oauth_secret_store::SharedPersistenceClaim> {
        let stable = self.stable.as_ref()?;
        Some(self.claim.get_or_init(|| {
            std::sync::Arc::new(oauth_secret_store::PersistenceClaim::acquire(
                config::KIND,
                stable,
            ))
        }))
    }

    /// Check a freshly granted bearer against the identity the persisted
    /// lineage is bound to, latching the sharpened record for the next persist.
    ///
    /// `Err(AuthRequired)` means the session authenticated as someone other
    /// than the account this connection's stored credential belongs to.
    fn check_identity(&self, access: &str) -> Result<()> {
        let observed =
            oauth_secret_store::identity_from_access_token(access, self.state.client_name());
        // No fence: `obtain`'s adoption decision is not racing a commit of its
        // own, and an unfenced check there is the strict one.
        self.state
            .observe_binding_unless_superseded(observed, self.state.identity_generation())?;
        Ok(())
    }

    /// [`Self::check_identity`], with supersession outranking an identity
    /// failure.
    ///
    /// A grant whose identity generation has already moved past `expected_gen`
    /// is being discarded anyway: its commit is fenced out downstream.
    /// Reporting *its* bearer as an identity mismatch would name the connection
    /// that just won the sign-in, and the lifecycle parks a credential-class
    /// failure — leaving the winner holding valid tokens it cannot use.
    ///
    /// The generation compare and the identity check happen under the binding
    /// lock, which every identity-changing write holds across its bump, so a
    /// winner cannot be observed half-applied.
    fn check_identity_unless_superseded(&self, access: &str, expected_gen: u64) -> Result<bool> {
        let observed =
            oauth_secret_store::identity_from_access_token(access, self.state.client_name());
        self.state
            .observe_binding_unless_superseded(observed, expected_gen)
    }

    /// The shared token cell (also held by the transport interceptor).
    pub fn state(&self) -> &DiscoveryState {
        &self.state
    }

    /// The transport this connection dispatches ops through.
    pub fn transport(&self) -> &OmniverseStorageTransport {
        &self.transport
    }

    /// Fenced live-cell commit shared by `activate` and `refresh`:
    /// same-identity MERGE semantics, atomically caching the replayable M2M
    /// pair when one rides the bundle (so `has_silent_grant` holds the
    /// moment the commit lands), under the set-captured identity fence.
    /// Returns whether the install committed (a skip means a concurrent
    /// interactive success or credential update won).
    async fn commit_fenced(
        &self,
        access: String,
        refresh: Option<String>,
        expires_in: Option<Duration>,
        m2m: Option<&(String, String)>,
        expected_gen: u64,
    ) -> bool {
        match m2m {
            Some((client_id, client_secret)) => {
                self.state
                    .install_tokens_and_client_credentials_if_identity_unchanged(
                        access,
                        refresh,
                        expires_in,
                        client_id.clone(),
                        client_secret.clone(),
                        expected_gen,
                    )
                    .await
            }
            None => {
                self.state
                    .install_tokens_if_identity_unchanged(access, refresh, expires_in, expected_gen)
                    .await
            }
        }
    }
}

/// Extract a validated M2M `(client_id, client_secret)` pair from a bundle:
/// both fields present as UTF-8 `Bytes` and non-empty, else `None`.
fn m2m_pair(bundle: &SecretBundle) -> Option<(String, String)> {
    match (
        bundle.fields.get("client_id"),
        bundle.fields.get("client_secret"),
    ) {
        (Some(SecretValue::Bytes(id)), Some(SecretValue::Bytes(secret))) => {
            match (
                String::from_utf8(id.0.clone()),
                String::from_utf8(secret.0.clone()),
            ) {
                (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => Some((id, secret)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Stamp the replayable M2M pair onto `bundle` so the `ConnectionSet`
/// entry keeps it in-memory for a later background / data-path refresh
/// (persistence ignores these fields — only the oauth refresh token rides
/// the secret store).
fn stamp_m2m(bundle: &mut SecretBundle, client_id: &str, client_secret: &str) {
    bundle.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(client_id.as_bytes().to_vec())),
    );
    bundle.fields.insert(
        "client_secret".into(),
        SecretValue::Bytes(SecretBytes(client_secret.as_bytes().to_vec())),
    );
}

/// The bearer a direct-endpoint connection can serve from, as an *effective*
/// bundle stripped to the access token alone.
///
/// A direct endpoint publishes no auth-config, so it can name no OIDC token
/// endpoint. The only credential it can act on is therefore an access token the
/// host already holds: the transport's interceptor puts it on every RPC, and
/// the host replaces it through `update_connection_credentials` when it expires.
///
/// **The stripping is load-bearing, not tidiness.** A refresh token or a
/// `client_credentials` pair reaching the live cell would make
/// `DiscoveryState::has_silent_grant` true, and [`OmniverseStorageDriver::classify`]
/// reads that to decide whether a rejected bearer is recoverable by a silent
/// grant. On this connection no such grant exists, so the recovery loop would
/// drive a `refresh` that answers `Unsupported` instead of surfacing the
/// rejection to the caller who can act on it.
///
/// The supplied expiry is dropped with the rest. Keeping it would put a real
/// `expires_in` on the live cell while the connection reports no expiry to the
/// lifecycle — one fact in two places, disagreeing, with nothing to reconcile
/// them. Nothing on this path can act on an expiry anyway: there is no
/// successor to schedule, and the host that minted the token is the party
/// holding its lifetime.
///
/// An `Err` means the credential was supplied and cannot be used as a bearer at
/// all: it is not UTF-8, or it holds a control character, which no HTTP header
/// value may carry. Both report [`ErrorCode::Unsupported`], because the lifecycle reads
/// `InvalidArgument` as a caller contract failure and the stack builder is fatal
/// on it — a malformed token in one configured connection must park that
/// connection, not stop the host.
///
/// `None` means there is no usable bearer here. What the CALLER does with that
/// is not the same in every case and is decided there: a bundle naming no
/// credential is a removal, while one that names a credential this plugin
/// models and carries nothing usable — the warm-continue placeholder shape, or
/// an environment reference that resolved to an empty string — is refused.
/// Neither ever installs an empty `authorization` header.
fn direct_bearer(creds: &SecretBundle) -> Result<Option<SecretBundle>> {
    // BOTH spellings of the same value, and the second one is not a
    // convenience. Configuration and the CLI can produce only
    // `SecretValue::Bytes`: `[connections.credentials]` entries and `--auth`
    // fields are strings, and both build every credential that way. The
    // structured `OAuthToken` is reachable from a programmatic caller — Rust,
    // or the Python binding's token constructor — but not from a config file.
    // Accepting only the structured form would leave the documented spelling
    // `oauth = "<token>"` doing nothing at all.
    //
    // Wildcard-free, for the same reason as `field_carries_material`: the two
    // functions decide one question between them, so a variant added to one and
    // not the other reopens the gap. A `_` arm here would silently answer "no
    // bearer" for a shape somebody had just taught the other function to
    // recognise.
    let token = match creds.fields.get("oauth") {
        Some(SecretValue::OAuthToken { token, .. }) | Some(SecretValue::Bytes(token)) => token,
        // Shapes this endpoint cannot turn into a bearer. They are not "no
        // credential": `offers_no_credential` sees them as material, so the
        // caller refuses rather than treating them as a removal.
        Some(SecretValue::File(_))
        | Some(SecretValue::MtlsCertPair { .. })
        | Some(SecretValue::SystemIdentity)
        | None => return Ok(None),
    };
    let access = String::from_utf8(token.0.clone()).map_err(|_| {
        // `Unsupported`, the same code the caller's refusal uses, and for the
        // same reason: the lifecycle reads `InvalidArgument` as a caller
        // contract failure and the stack builder is fatal on it, so a malformed
        // credential in one configured connection would stop the whole host.
        // "This credential cannot be used here" is one answer however the
        // credential is malformed.
        Error::new(
            ErrorCode::Unsupported,
            "omniverse-storage-service: the 'oauth' credential must be a valid UTF-8 access token",
        )
    })?;
    // A token is checked for header legality HERE, where it is accepted, and not
    // left to the interceptor that sends it. The interceptor's only answer is
    // `Status::internal`, and on this path that is fatal rather than local:
    // bring-up drives an RPC through it, `run_validation` propagates `Internal`
    // instead of parking, and the stack builder is fatal on every code except
    // `RouteConflict` — so one `[[connections]]` entry whose token carries a
    // newline would stop the whole host from starting, taking every unrelated
    // backend with it. Refusing here parks this one connection instead.
    //
    // `auth::bearer_header` is the SAME function the interceptor builds its
    // header with, so the set of tokens accepted here and the set that can be
    // sent cannot drift apart. It also trims the surrounding whitespace a
    // file-borne or Kubernetes secret arrives with, which is why the effective
    // bundle carries what it returns rather than what was supplied.
    let Some((access, _)) = auth::bearer_header(&access) else {
        return Err(Error::new(
            ErrorCode::Unsupported,
            // Says "as a credential" rather than "as a bearer token" for the
            // same reason the plaintext refusal does: `redact_message` rewrites
            // the word after "bearer", so the phrase would reach the operator as
            // "sent as a bearer REDACTED".
            "omniverse-storage-service: the 'oauth' credential holds a control character, which no \
             HTTP header value may carry, so it cannot be sent as a credential. Surrounding \
             whitespace is removed already, so this is a control character inside the token \
             itself rather than the trailing newline a file-borne secret arrives with.",
        ));
    };
    if access.is_empty() {
        return Ok(None);
    }
    Ok(Some(oauth_secret_store::oauth_bundle(access, None, None)))
}

/// Whether `creds` carries a field a direct endpoint has no way to act on,
/// *beside* a usable access token.
///
/// Both shapes named here need the OIDC token endpoint that only
/// `/api/v1/auth-config` can publish. Alongside a working bearer they are
/// reported rather than refused: an over-specified bundle is not a hostile one,
/// and the access token is perfectly usable without them.
fn carries_unusable_direct_fields(creds: &SecretBundle) -> bool {
    if field_carries_material(creds, "client_id") || field_carries_material(creds, "client_secret")
    {
        return true;
    }
    matches!(
        creds.fields.get("oauth"),
        Some(SecretValue::OAuthToken {
            refresh: Some(rt), ..
        }) if !rt.0.is_empty()
    )
}

/// Whether `key` is present in `creds` AND carries something.
///
/// A content test, for the callers that want one. A form or a secrets adapter
/// can serialize an optional field it was given nothing for, so a blank value
/// carries nothing to act on. [`offers_no_credential`] applies this only to keys
/// outside [`config::credential_schema`] — naming a modelled key is an offer
/// whatever it holds — while [`carries_unusable_direct_fields`] applies it to
/// `client_id`/`client_secret`, where the question is whether there is anything
/// to warn the operator about rather than whether anything was offered.
fn field_carries_material(creds: &SecretBundle, key: &str) -> bool {
    // Wildcard-free at BOTH levels, and the second level is the one that was
    // learned the hard way. No `_` arm, so a new `SecretValue` variant fails to
    // compile until somebody decides what it means — and no `..` inside a
    // variant either, so a new FIELD on an existing variant does too. The first
    // version of this function classified `OAuthToken` on its two token fields
    // and elided `expires_at` behind a `..`, which made a bundle carrying only
    // an expiry read as "nothing offered" — and a bundle read as nothing
    // offered CLEARS a live connection's bearer. Both directions of that
    // mistake are now a build failure rather than a thing to notice.
    match creds.fields.get(key) {
        Some(SecretValue::Bytes(b)) => !b.0.is_empty(),
        Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) => {
            !token.0.is_empty()
                || matches!(refresh, Some(rt) if !rt.0.is_empty())
                || expires_at.is_some()
        }
        Some(SecretValue::File(path)) => !path.0.is_empty(),
        Some(SecretValue::MtlsCertPair { cert_pem, key_pem }) => {
            !cert_pem.0.is_empty() || !key_pem.0.is_empty()
        }
        // Carries no bytes, but it is an OFFER — "use the ambient identity" —
        // so it is a credential this endpoint cannot use rather than an absent
        // one. Classifying it as nothing would make it a silent removal.
        Some(SecretValue::SystemIdentity) => true,
        None => false,
    }
}

/// Whether `creds` offers **no credential at all** — the only bundle that means
/// "remove the one in use".
///
/// Two rules, and which one applies is decided by whether this plugin models the
/// key — that is, whether [`config::credential_schema`] publishes it:
///
/// - a **modelled** key is an offer by PRESENCE, whatever it carries, because
///   naming one is a statement of intent and the blank arrives by accident;
/// - an **unmodelled** key is an offer by CONTENT, because a generic form or
///   secrets adapter can serialize a field it was given nothing for.
///
/// The unmodelled arm is deliberately the complement of "carries something"
/// rather than an allowlist of names. That direction is load-bearing: an
/// allowlist would read a bundle of unrecognised but *populated* fields — a
/// typo, a host that names its token differently — as a removal, and silently
/// delete a working bearer while reporting success. Written this way, a field
/// that is not understood makes the bundle a failed credential operation rather
/// than a removal, which is the safe direction.
fn offers_no_credential(creds: &SecretBundle) -> bool {
    // Naming a key this plugin MODELS is an offer, blank or not. That is the one
    // place presence is read rather than content, and the boundary is the
    // credential schema rather than any single key: a bundle naming a field this
    // plugin publishes is a bundle whose author believed they were supplying a
    // credential. The realistic way to get a blank into one is an environment
    // reference that resolved to nothing — an unpopulated CI secret, a
    // token-minting sidecar that wrote an empty string, a UI form submitted with
    // the boxes empty — and treating that as "remove the credential" would
    // delete a live connection's bearer and report success, which is the outcome
    // every version of this predicate has existed to prevent. That accident is a
    // property of the ENV REFERENCE, not of the key it sits under, so it reaches
    // `client_id` and `client_secret` exactly as it reaches `oauth`.
    //
    // Derived from `config::credential_schema()` rather than spelled here, so a
    // field added to the schema is covered by this rule the moment it is
    // published. A hand-written list is the shape that left this rule reaching
    // one key of the three.
    //
    // Content is then inspected only for keys the plugin does NOT model, where
    // presence carries no such intent: a generic adapter serializing a blank
    // field it knows nothing about is not an offer, while a POPULATED unmodelled
    // field is one — a typo, or a host that names its token differently. That
    // direction is load-bearing: an allowlist would read a populated but
    // unrecognised field as a removal and silently delete a working bearer.
    //
    // Removing therefore means naming no credential at all. The refusal's own
    // message says so, and an empty bundle is unambiguous in a way a blank value
    // is not.
    if config::credential_schema()
        .iter()
        .any(|field| creds.fields.contains_key(&field.key))
    {
        return false;
    }
    creds
        .fields
        .keys()
        .all(|key| !field_carries_material(creds, key))
}

/// Whether the ONLY path from `creds` to a working bearer is a *consuming*
/// refresh-token grant — the condition a [`GrantPolicy::NonConsumingOnly`]
/// `obtain` (a probe) must refuse with [`Obtained::WouldConsume`] rather than
/// burn a one-time refresh token.
///
/// A `client_credentials` pair is replayable (re-drivable), so it never consumes
/// and returns `false`. For an `oauth` bundle: a supplied access token is usable
/// as-is ONLY while it is non-empty AND still valid beyond [`auth::REFRESH_SKEW`]
/// — then `false` (probe it directly). Once the access token is empty, EXPIRED,
/// or within `REFRESH_SKEW` of expiry, the only path to a fresh bearer is a
/// consuming refresh-token grant, so this returns `true` iff a refresh token is
/// present to drive it (else there is nothing to consume — awaiting-interactive /
/// anonymous — and it returns `false`). Treating an expired-access + refresh
/// bundle as usable was the bug: the probe would then drive a refresh grant in
/// `seed_connection_auth` and burn the one-time token.
fn would_consume_only(creds: &SecretBundle) -> bool {
    // A machine-to-machine `client_credentials` grant is replayable — the pair
    // can be re-driven, so it never consumes a one-time credential.
    if creds.fields.contains_key("client_id") && creds.fields.contains_key("client_secret") {
        return false;
    }
    let Some(SecretValue::OAuthToken {
        token,
        refresh,
        expires_at,
    }) = creds.fields.get("oauth")
    else {
        // No oauth bundle and no client-credentials pair: nothing to consume.
        return false;
    };
    let has_refresh = matches!(refresh, Some(rt) if !rt.0.is_empty());
    // A supplied, non-empty access token that is still valid beyond REFRESH_SKEW
    // is usable as-is — probe it directly, no grant needed.
    let access_usable = !token.0.is_empty()
        && match expires_at {
            None => true,
            Some(at) => SystemTime::now() + auth::REFRESH_SKEW < *at,
        };
    if access_usable {
        return false;
    }
    // Empty / expired / within-REFRESH_SKEW access token: the only path to a
    // fresh bearer is a consuming refresh-token grant — would-consume iff a
    // refresh token is present to drive it.
    has_refresh
}

#[async_trait]
impl ConnectionAuthDriver for OmniverseStorageDriver {
    fn backend_kind(&self) -> &str {
        config::KIND
    }

    fn stable_id(&self) -> Option<ConnectionId> {
        self.stable.clone()
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        policy: GrantPolicy,
        cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // FIRST, ahead of every consideration below. A direct endpoint
        // publishes no auth-config, so there is no grant to drive and no
        // one-time credential to consume, whatever bundle is attached. Deciding
        // this after the `would_consume_only` gate would make a PROBE of a
        // direct connection carrying a stale OAuth bundle report `WouldConsume`
        // — which the layer surfaces as unverifiable — while ADDING the
        // identical connection succeeded. Same config, two answers.
        //
        // What keeps this connection out of the secret store is NOT this early
        // return: `self.stable` is `None` for a direct endpoint, so `claim()`
        // answers `None` and every keyring verb short-circuits on that. The
        // `ensure_claim_usable()` below inspects the claim without acquiring
        // one, so running it here would be harmless — the guard is the absent
        // key, and that is the thing to check first if this ever regresses.
        if self.is_direct() {
            let bearer = direct_bearer(creds)?;
            // A bearer leaving this machine in clear is a disclosure that cannot
            // be taken back, so the operator states the acceptance in the config
            // file rather than in a log line they may never read.
            //
            // The symmetry argument does not carry here, and it is the argument
            // worth writing down because it is the plausible one: the object
            // bytes already cross this same cleartext link, so what is one more
            // secret on it? The answer is that the token is not bounded by the
            // data it fetches. It is minted by the operator's IDP, its audience
            // is whatever that IDP put in it, and whoever can read this link can
            // replay it wherever else that audience is accepted. The bytes are
            // exposed on one link; the credential is exposed everywhere.
            //
            // OFF by default because of which mistake can be undone. A
            // connection that should have sent a token and parks is fixed by one
            // key in the config file; a token disclosed on a wire is disclosed,
            // and no later change retracts it. Nothing is grandfathered by the
            // choice: a direct endpoint has never served a credential in a
            // released build, so off-by-default takes no working deployment away.
            //
            // LOOPBACK is exempt because the packets reach no network. That is
            // a strictly narrower test than the one config validation applies to
            // the ADDRESS — private, shared and in-cluster space are fine to
            // speak cleartext to and are exactly where an eavesdropper who is
            // not this machine lives. Exempt is not "discloses to nobody": a
            // process on this machine with `CAP_NET_RAW` can read loopback, and
            // the exemption for the NAME `localhost` trusts local resolution.
            // Both are judgements that the shipped documentation states, not
            // properties this code establishes.
            //
            // `Unsupported`, for the blast-radius reason the refusal below
            // spells out in full: an argument error here is fatal to host
            // startup, and this refusal must park one connection.
            if bearer.is_some()
                && self.transport.is_plaintext_beyond_loopback()
                && !self.allow_plaintext_credentials
            {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!(
                        // Deliberately does not say "bearer token": the shared
                        // `redact_message` sanitizer rewrites the word after
                        // "bearer" to REDACTED, which is right for a message
                        // quoting a header and turns this sentence into
                        // "the supplied bearer REDACTED would expose".
                        "omniverse-storage-service: this connection is configured with a \
                         plaintext grpc:// endpoint that is not loopback, so sending the \
                         supplied access token would expose a replayable credential to anyone \
                         who can read the link. Use grpcs://, or set '{}' on this connection to \
                         state that the link is trusted end to end.",
                        config::ALLOW_PLAINTEXT_CREDENTIALS_KEY,
                    ),
                ));
            }
            // Permitted, and still worth saying once — so the audience is the
            // operator who set the key, not every loopback dev connection.
            // Gated on the SAME predicate as the refusal above, which is why
            // there is only one: a warning keyed on "the channel is cleartext"
            // would fire for every loopback development connection, where there
            // is nothing to disclose, and teach its reader to skim.
            //
            // Latched: `obtain` runs per operation, and a standing property of
            // the configuration does not become news by being restated.
            if bearer.is_some()
                && self.transport.is_plaintext_beyond_loopback()
                && !self
                    .warned_plaintext_bearer
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    // Named so an operator running several direct connections
                    // can tell which one is disclosing, and redacted like every
                    // other locator that reaches a diagnostic.
                    service_url = %self.transport.redacted_locator(),
                    "omniverse-storage-service: this connection sends its bearer token over a \
                     plaintext gRPC channel; use grpcs:// unless the link is trusted end to end",
                );
            }
            // A bundle that carries SOMETHING but no usable access token is a
            // failed credential operation, not a credential removal, and
            // keeping those two apart is the whole point of this refusal.
            //
            // The alternative — answer `Anonymous` — is the dangerous one:
            // `Anonymous` on a registered path clears the live cell below. So a
            // host that sent a client-credentials pair, or misspelled the field
            // its token goes in, would have its WORKING bearer deleted and be
            // told the update succeeded. An error leaves the live cell alone
            // and says what to send instead.
            //
            // The condition is the COMPLEMENT of "nothing was offered", not a
            // list of field names this plugin knows. An allowlist was the first
            // version and it was wrong in the direction that costs state: an
            // unrecognised but populated field fell through it and read as a
            // removal.
            //
            // `Unsupported`, NOT `InvalidArgument`, and the reason is blast
            // radius rather than taxonomy. The generic lifecycle treats
            // `InvalidArgument` as a caller contract failure: the initial
            // validation propagates it, `add_connection` deletes the staged
            // entry, and the stack builder is fatal on every code except
            // `RouteConflict` — so ONE mistyped credential in one
            // `[[connections]]` entry would stop the whole host from starting,
            // taking every unrelated backend with it. That is the exact failure
            // the builder's `RouteConflict` arm exists to avoid, and it says so
            // in as many words.
            //
            // `Unsupported` parks the connection instead. The park reason is
            // `CredentialsRotated` on a credential update — which is accurate,
            // and the one an operator actually meets — and `BackendUnreachable`
            // at bring-up, which is not: the backend was never asked. No
            // lifecycle code today means "the credential you handed me is one I
            // cannot use" without also meaning "the caller broke the contract".
            // That imprecision is the price of not being able to take a host
            // down, and it is the right way round: the error itself is returned
            // to the caller and carries the reason.
            if bearer.is_none() && !offers_no_credential(creds) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: this connection is configured with a direct gRPC \
                     endpoint, which publishes no auth-config, so a refresh token, a \
                     client-credentials pair and any other credential needing an OIDC token \
                     endpoint cannot be redeemed. Supply an access token in the 'oauth' \
                     credential, or an empty credential bundle to remove the one in use.",
                ));
            }
            // Latched: `obtain` runs per operation — every add, probe and
            // recovery — and an unchanging misconfiguration does not become
            // news by being restated. The remaining case is a usable access
            // token arriving BESIDE something unusable, which is served from
            // the token with the rest reported and dropped.
            if bearer.is_some()
                && carries_unusable_direct_fields(creds)
                && !self
                    .warned_credentials_unusable
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                warn_direct_credentials_unusable();
            }
            return Ok(match bearer {
                // `expires_at` is deliberately `None` even when the supplied
                // bundle carries one. That field's job is scheduling —
                // `ConnectionSet::spawn_refresh` starts a background task if
                // and only if it is `Some` — and the task it would start calls
                // `refresh`, which on this connection can only answer
                // `Unsupported`. `Unsupported` classifies as `NotAuth`, which
                // the scheduler reads as a transient blip and retries on the
                // floor cadence, so reporting the expiry would buy a warning
                // every skew interval and no behaviour. From the plugin's side
                // a host-supplied bearer IS the "static creds" case that field
                // documents `None` for: there is no successor this connection
                // can mint. The party that knows when it expires is the host
                // that minted it, and rotating it is that host's call to
                // `update_connection_credentials`.
                Some(credentials) => Obtained::Bearer {
                    credentials,
                    expires_at: None,
                },
                // Reached only when NOTHING was offered — the refusal above
                // has taken every bundle that carries anything at all without a
                // usable access token. So this is the host saying "no
                // credential", and it must be honoured as one.
                None => {
                    // Removing the credential has to CLEAR the live cell, and
                    // this is the only place that can. `ConnectionSet` handles
                    // `Obtained::Anonymous` by recording the state and nothing
                    // else — it never calls `activate` — so a host that rotated
                    // to an empty bundle in order to drop its bearer would get a
                    // connection reporting `Anonymous` while the interceptor
                    // kept sending the previous token. "Remove the credential"
                    // is one of the standard credential-update verbs, so it has
                    // to actually remove it.
                    //
                    // Gated on the policy, which is exact rather than
                    // approximate: `AllowConsuming` is every REGISTERED path
                    // (bring-up, credential update, recovery) and
                    // `NonConsumingOnly` is the probe, which must not mutate
                    // anything. The probe additionally runs on a throwaway
                    // driver with its own token cell, so this is the second of
                    // two independent reasons it cannot disturb a live
                    // connection.
                    //
                    // `replace_tokens` rather than a merge: the merge form
                    // preserves the previous refresh token and the cached
                    // client-credentials pair on a `None`, which is exactly
                    // what must not survive a removal.
                    if policy == GrantPolicy::AllowConsuming {
                        self.state.replace_tokens(String::new(), None, None).await;
                    }
                    Obtained::Anonymous
                }
            });
        }
        // A sibling that claimed this key after the adoption retracts it: the
        // connection is serving on a lineage nothing can show is its own, so it
        // re-authenticates rather than continuing.
        self.ensure_claim_usable()?;
        // A probe (`NonConsumingOnly`) must never burn a one-time refresh token:
        // if the ONLY path to a bearer is a consuming refresh-token grant, report
        // `WouldConsume` up front — before touching the network. The generic
        // `ConnectionSet` maps this to `ProbeOutcome::Unverifiable`.
        if policy == GrantPolicy::NonConsumingOnly && would_consume_only(creds) {
            return Ok(Obtained::WouldConsume);
        }
        // Grant against a PRIVATE staging `DiscoveryState` — never the live
        // `self.state` the transport interceptor reads and never the secret store (the
        // `ConnectionSet` owns the secret store reload/persist, under its cross-process
        // lock). Because the candidate tokens land only on this throwaway state, a
        // concurrent RPC on the live connection can never observe an unverified
        // candidate, and a probe is structurally side-effect-free.
        let staging = DiscoveryState::new(self.state.client_name().to_string());
        // Thread `policy` through: a `NonConsumingOnly` probe whose bundle still
        // reaches the `token_needs_refresh && refresh present` branch (empty /
        // expired / near-expiry access token) reports `WouldConsume` from the seed
        // rather than driving the consuming refresh-token grant.
        let auth_state = match seed_connection_auth(
            &staging,
            self.discovery_url.as_deref(),
            &self.http,
            creds,
            policy,
            cancel,
        )
        .await?
        {
            SeedOutcome::WouldConsume => return Ok(Obtained::WouldConsume),
            SeedOutcome::State(state) => state,
        };
        Ok(match auth_state {
            ConnectionAuthState::Authenticated { expires_at, .. } => {
                // Read the effective (post-rotation) bundle out of `staging` — a
                // warm-continue seed may have driven a refresh-token grant that
                // rotated the refresh token.
                let access = staging.access_token().await.unwrap_or_default();
                // Adopt the session only once the bearer proves it belongs to
                // the account the persisted lineage is bound to. An identity
                // refusal returns before the effective bundle is assembled, so
                // a rotation consumed by that grant is not handed back here;
                // `AuthRequired` instead routes the `ConnectionSet` to purge the
                // lineage and re-authenticate, which is the intended outcome —
                // a token belonging to somebody else must not be kept.
                self.check_identity(&access)?;
                let refresh = staging.refresh_token().await;
                let exp = staging.access_token_expires_at().await;
                let mut effective =
                    oauth_secret_store::oauth_bundle(&access, refresh.as_deref(), exp);
                // M2M: if the input `creds` carried a `client_credentials`
                // (client_id + client_secret) pair, the grant ran on the PRIVATE
                // `staging` state, so the live cell never cached it. Carry the
                // replayable pair through in the effective bundle so a later
                // background / data-path `refresh` can re-seed it onto the live
                // cell and re-drive the client-credentials grant (a
                // client_credentials connection has no refresh token to fall back
                // on). Persistence ignores these fields — only the oauth refresh
                // token rides the secret store — so the pair stays in-memory on the
                // `ConnectionSet` entry's credentials. A refresh-token / oauth
                // grant carries no such pair and the bundle is unchanged.
                if let Some((client_id, client_secret)) = m2m_pair(creds) {
                    stamp_m2m(&mut effective, &client_id, &client_secret);
                }
                Obtained::Bearer {
                    credentials: effective,
                    expires_at,
                }
            }
            ConnectionAuthState::Anonymous => Obtained::Anonymous,
            ConnectionAuthState::AwaitingAuth { reason, .. } => {
                Obtained::AwaitingInteractive { reason }
            }
            ConnectionAuthState::AuthFailed { .. } => Obtained::AwaitingInteractive {
                reason: AuthReason::NeverAuthenticated,
            },
        })
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // Prove the backend accepts the bearer with ONE read-only RPC over an
        // EPHEMERAL transport: a fresh private `DiscoveryState` seeded with only
        // `credentials`' bearer, wrapped around the live transport's CHANNEL (so a
        // test-injected in-memory channel and a discovered production channel both
        // work) but reading its bearer from the private state — so `verify` never
        // installs the candidate on the live cell, drives a grant, or persists.
        let vstate = DiscoveryState::new(self.state.client_name().to_string());
        if let Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) = credentials.fields.get("oauth")
        {
            let access = String::from_utf8(token.0.clone()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "omniverse-storage-service: oauth access token must be valid UTF-8",
                )
            })?;
            let refresh = match refresh {
                Some(rt) => Some(String::from_utf8(rt.0.clone()).map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: oauth refresh token must be valid UTF-8",
                    )
                })?),
                None => None,
            };
            let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
            vstate.install_tokens(access, refresh, expires_in).await;
        }
        let vt = self.transport.probe_with_state(vstate);
        race_cancel(cancel.as_ref(), async {
            list_top_level_addresses(&vt).await
        })
        .await
        .map(|_| ())
    }

    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        // Install a PROVEN bundle onto the LIVE cell (the transport interceptor's
        // token slot) with same-identity MERGE semantics — this is the bring-up /
        // refresh / warm-continue path, NOT an identity change, so it does NOT
        // clear the cached `client_credentials` and does NOT bump `identity_gen`.
        // The install is fenced on `expected_gen` (the identity generation the
        // `ConnectionSet` captured at grant start): if a concurrent interactive
        // success or credential update already bumped it, the merge is SKIPPED and
        // the newer identity correctly wins. A skip is not an error — the set
        // discards this now-stale bundle — so return `Ok(())` either way.
        //
        // LATENT (update_credentials different-identity edge; not a regression):
        // `activate` always MERGES onto the live cell — correct for bring-up /
        // refresh / warm-continue (all same-identity). A genuinely DIFFERENT
        // client identity supplied via `update_credentials` would also merge here:
        // it would NOT evict a stale cached `client_credentials` pair and would NOT
        // bump `identity_gen` (only the interactive path's `replace_tokens` and an
        // explicit `set_client_credentials` do). The pre-reshape path was likewise
        // a merge, so this is no regression — but if identity-change eviction is
        // ever needed (e.g. rotating an M2M connection to a new service principal),
        // `update_credentials` should route through an identity-clearing install
        // rather than this same-identity merge. Tracked as a follow-up.
        if let Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) = credentials.fields.get("oauth")
        {
            let access = String::from_utf8(token.0.clone()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "omniverse-storage-service: oauth access token must be valid UTF-8",
                )
            })?;
            let refresh = match refresh {
                Some(rt) => Some(String::from_utf8(rt.0.clone()).map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: oauth refresh token must be valid UTF-8",
                    )
                })?),
                None => None,
            };
            let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
            // M2M (data-path recovery): if the effective bundle carries a
            // `client_credentials` pair — `obtain` stamps it through because the
            // grant ran on PRIVATE staging, so the live cell never cached it —
            // install the tokens AND cache the pair on the live cell atomically,
            // under the same identity-gen fence. This makes `has_silent_grant`
            // true the instant M2M bring-up commits (before the first background
            // refresh), so a data-path `UNAUTHENTICATED` classifies as a
            // recoverable credential and the recovery loop re-drives the grant.
            let client_credentials = m2m_pair(credentials);
            let committed = self
                .commit_fenced(
                    access,
                    refresh,
                    expires_in,
                    client_credentials.as_ref(),
                    expected_gen,
                )
                .await;
            // Whether the fenced merge committed (the primitive's own flag): the
            // `ConnectionSet` gates its set-side commit on this rather than a
            // post-hoc `identity_gen` re-read.
            return Ok(committed);
        }
        // A bundle carrying no `oauth` field installs nothing — report committed so
        // the set-side commit proceeds (nothing to fence).
        Ok(true)
    }

    fn identity_gen(&self) -> u64 {
        self.state.identity_generation()
    }

    /// Answered from the credential the live identity published: a bundle
    /// carrying a different refresh token belongs to a flow the live cell has
    /// moved past, and committing it would regress the connection onto a token
    /// the provider's rotation has already consumed.
    fn credentials_are_current(&self, credentials: &SecretBundle) -> bool {
        oauth_secret_store::bundle_carries_published_credential(&self.state, credentials)
    }

    async fn refresh(
        &self,
        current: &SecretBundle,
        cancel: Option<CancellationToken>,
        expected_gen: u64,
    ) -> Result<Refreshed> {
        // A sibling that claimed this key after the adoption retracts it: the
        // connection is serving on a lineage nothing can show is its own, so it
        // re-authenticates rather than continuing.
        self.ensure_claim_usable()?;
        // `expected_gen` is the identity generation the `ConnectionSet` captured
        // at the START of this grant — the supersession fence for the whole
        // refresh. Mirroring the broker driver (and this driver's own
        // `obtain`): the grant runs on driver-PRIVATE staging, so the live cell
        // the transport interceptor reads is never mutated mid-grant, and only
        // the fenced commit below ever touches it — a concurrent interactive
        // sign-in that bumps `identity_gen` wins, and this refresh's now-stale
        // bundle is skipped rather than clobbering the winner's bearer.
        race_cancel(cancel.as_ref(), async {
            // `obtain` ran OIDC discovery on PRIVATE staging, so the live cell may
            // still lack the auth/OIDC config a grant needs (token endpoint,
            // client id/scope). Load it here, idempotently — this is
            // identity-neutral config, not a token write — then seed a PRIVATE
            // staging cell from it for the grant itself.
            if self.state.oidc_config().await.is_none() {
                let Some(discovery_url) = self.discovery_url.as_deref() else {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "omniverse-storage-service: this connection is configured with a direct \
                         gRPC endpoint, which publishes no auth-config, so there is no OIDC token \
                         endpoint to refresh against",
                    ));
                };
                let auth_config = auth::fetch_auth_config(&self.http, discovery_url).await?;
                self.state.install_auth_config(auth_config.clone()).await;
                let oidc = auth::fetch_oidc_config(&self.http, &auth_config).await?;
                self.state.install_oidc_config(oidc).await;
            }
            let staging = DiscoveryState::new(self.state.client_name().to_string());
            if let Some(cfg) = self.state.auth_config().await {
                staging.install_auth_config(cfg).await;
            }
            if let Some(oidc) = self.state.oidc_config().await {
                staging.install_oidc_config(oidc).await;
            }

            // The M2M `(client_id, client_secret)` pair for the grant: prefer
            // `current` (= the `ConnectionSet` entry's credentials — `obtain`
            // granted on PRIVATE staging, so the live cell never cached the
            // pair and `obtain` stamped it onto the bundle instead), else the
            // live cell's cache (stamped by a fenced `activate`).
            //
            // IDENTITY-PROTECTION NOTE (the broker sibling): this
            // driver has NO explicit lineage gate — it relies on interactive
            // sign-in REPLACING both sources (`replace_tokens` clears the
            // live cell's cached pair under the same write span that bumps
            // `identity_gen`, and the set replaces the entry credentials),
            // so this fallback resolves to `None` afterwards and the refresh
            // takes the refresh-token grant. If a future change lets a
            // stale pair survive an interactive success on either source
            // (e.g. routing an M2M connection's interactive win through a
            // keep-creds merge), this fallback would silently revert the
            // user's bearer to the service principal — that change must
            // bring the broker's explicit lineage gate with it.
            let m2m = match m2m_pair(current) {
                Some(pair) => Some(pair),
                None => self.state.client_credentials().await,
            };

            // Prefer the machine-to-machine grant; else the OAuth refresh-token
            // grant. Both run on the PRIVATE `staging` cell, never the live one.
            if let Some((client_id, client_secret)) = &m2m {
                drive_client_credentials_grant(&self.http, &staging, client_id, client_secret)
                    .await?;
            } else {
                // Seed the refresh token onto STAGING: prefer the reloaded
                // (possibly rotated) token from `current` (the freshness-skip
                // fallback carries a sibling process's persisted successor),
                // else the live cell's current refresh.
                let seed_refresh = match current.fields.get("oauth") {
                    Some(SecretValue::OAuthToken {
                        refresh: Some(rt), ..
                    }) => String::from_utf8(rt.0.clone())
                        .ok()
                        .filter(|s| !s.is_empty()),
                    _ => None,
                };
                match seed_refresh {
                    Some(rt) => staging.install_refresh_token(rt).await,
                    None => {
                        if let Some(rt) = self.state.refresh_token().await {
                            staging.install_refresh_token(rt).await;
                        }
                    }
                }
                drive_refresh_token_grant(&self.http, &staging).await?;
            }

            // Commit the freshly-minted bearer to the LIVE cell with
            // same-identity MERGE semantics, fenced on the set-captured
            // identity generation. If a concurrent interactive success bumped
            // `identity_gen` since that capture, the merge is SKIPPED and the
            // live cell keeps the winning identity; the minted bundle is still
            // returned so the set-side commit applies its own fence.
            let access = staging.access_token().await.unwrap_or_default();
            // Supersession outranks the identity check here: the commit below
            // is already fenced on `expected_gen`, so a superseded grant is
            // discarded either way — but failing it would park the winner.
            self.check_identity_unless_superseded(&access, expected_gen)?;
            // A `client_credentials` bearer is access-only and re-mintable —
            // carry NO refresh token onto the committed / returned bundle.
            let refresh = if m2m.is_some() {
                None
            } else {
                staging.refresh_token().await
            };
            let expires_at = staging.access_token_expires_at().await;
            let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
            // (The old unstaged path seeded the pair via
            // `set_client_credentials`, which was unfenced AND bumped
            // `identity_gen`; `commit_fenced` caches it atomically under the
            // same fence, keeping `has_silent_grant` true after the first
            // background refresh.)
            let _committed = self
                .commit_fenced(
                    access.clone(),
                    refresh.clone(),
                    expires_in,
                    m2m.as_ref(),
                    expected_gen,
                )
                .await;
            let mut credentials =
                oauth_secret_store::oauth_bundle(&access, refresh.as_deref(), expires_at);
            // Stamp the M2M pair back onto the returned bundle (mirroring
            // `obtain`) so the set-side entry keeps the replayable pair and a
            // fenced `activate` can cache it on the live cell.
            if let Some((client_id, client_secret)) = &m2m {
                stamp_m2m(&mut credentials, client_id, client_secret);
            }
            Ok(Refreshed {
                credentials,
                expires_at,
            })
        })
        .await
    }

    async fn interactive(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // FIRST, ahead of the capability check and ahead of anything that could
        // take a persistence claim below. `Unsupported` is the code
        // `Layer::authenticate_connection` documents for a backend with no flow
        // at all, as opposed to `AuthRequired`, which is a flow that exists and
        // could not be driven. That is the distinction the cloud backends
        // settled on: a driver with no flow must refuse rather than emit a
        // terminal success event, which would promote a parked connection to
        // authenticated on no grant and nothing proven.
        if self.is_direct() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: this connection is configured with a direct gRPC \
                 endpoint, which publishes no auth-config, so there is no interactive \
                 authentication flow to drive",
            ));
        }
        if matches!(capability, InteractiveAuthCapability::None) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "omniverse-storage-service: host declared no interactive auth capability",
            ));
        }
        // Persist the interactively-minted refresh token BEFORE the flow thread
        // forwards `Succeeded` (3537945622). Keyed on this connection's stable id
        // exactly like `persist_credentials`.
        let claim = std::sync::Arc::clone(
            self.claim()
                .expect("interactive returns Unsupported for a direct endpoint before this point"),
        );
        // A sign-in superseded before its callback runs cannot express the
        // write at all. Anchored on the identity being published, not on the
        // generation at flow start: this flow's OWN commit advances the
        // generation, so a start anchor would refuse every sign-in.
        let epoch = self.identity_epoch();
        let publication = self.state.clone();
        let state = self.state.clone();
        let persist: auth::PersistRefresh = std::sync::Arc::new(
            move |_access: &str, refresh: Option<String>, generation: u64| {
                // Anchored on the generation this flow's own commit produced,
                // so a flow superseded before its callback ran cannot write.
                let lease = oauth_secret_store::IdentityLease::at_generation(&epoch, generation);
                // The binding is NOT published here. The token install that
                // preceded this callback published it, fenced and under one
                // lock; republishing would reopen the window where a superseded
                // flow overwrites the winner's identity. What this callback
                // reads is therefore whatever the winning install recorded.
                // Through the claim, like every other write: a sign-in that
                // stamped its token onto a key a sibling connection also
                // derives would hand that sibling this account's lineage on the
                // next warm continuation.
                match refresh {
                    Some(rt) if !rt.is_empty() => oauth_secret_store::write_leased_refresh_token(
                        PLUGIN_NAME,
                        config::KIND,
                        &claim,
                        &lease,
                        publication.publication_lock(),
                        &rt,
                        &state.current_binding().unwrap_or_default(),
                    ),
                    _ => oauth_secret_store::delete_leased_refresh_token(
                        PLUGIN_NAME,
                        config::KIND,
                        &claim,
                        &lease,
                        publication.publication_lock(),
                    ),
                }
            },
        );
        race_cancel(cancel.as_ref(), async {
            // Ensure auth-config + OIDC discovery are loaded on the shared state
            // before driving the flow (idempotent; `validate` usually did this).
            if self.state.oidc_config().await.is_none() {
                let discovery_url = self
                    .discovery_url
                    .as_deref()
                    .expect("interactive refuses a direct endpoint before this point");
                let auth_config = auth::fetch_auth_config(&self.http, discovery_url).await?;
                self.state.install_auth_config(auth_config.clone()).await;
                let oidc = auth::fetch_oidc_config(&self.http, &auth_config).await?;
                self.state.install_oidc_config(oidc).await;
            }
            // The cancel token here is the ConnectionSet entry's lifecycle
            // child (cancelled on remove_connection): the flow thread uses it
            // as its liveness fence before installing/persisting (3539558624).
            drive_interactive_login(&self.state, connection, capability, persist, cancel.clone())
                .await
        })
        .await
    }

    fn classify(&self, error: &Error) -> AuthErrorClass {
        match error.code() {
            // Expired-credential codes: a refresh always may recover.
            ErrorCode::AuthExpired | ErrorCode::CredentialExpired => {
                AuthErrorClass::RecoverableCredential
            }
            // gRPC UNAUTHENTICATED maps to `AuthRequired` (see `convert.rs`).
            // It is ambiguous: it means "the access token was rejected". If we
            // still hold a non-interactive grant (refresh token / client
            // credentials) the token has almost certainly just expired — route
            // to a silent refresh + retry-once instead of forcing an
            // interactive prompt, which would be a dead end where a refresh
            // would have recovered. With no silent grant, interactive re-auth
            // genuinely is required.
            ErrorCode::AuthRequired if self.state.has_silent_grant() => {
                AuthErrorClass::RecoverableCredential
            }
            ErrorCode::AuthRequired | ErrorCode::AuthCancelled => AuthErrorClass::NeedsInteractive,
            ErrorCode::PermissionDenied => AuthErrorClass::PermissionDenied,
            _ => AuthErrorClass::NotAuth,
        }
    }

    async fn persist_credentials(&self, creds: &SecretBundle) -> Result<()> {
        // A direct-endpoint connection has no DURABLE credential: the secret store
        // holds an OAuth refresh token, and this mode has no token endpoint to
        // redeem one against, so it never holds one. A bearer the host supplied
        // lives in memory only, and the host is the party that replaces it.
        // Returning before `claim()` is the point — see that function.
        let Some(claim) = self.claim() else {
            return Ok(());
        };
        // Mirror the (possibly rotated) refresh token into the secret store so a
        // later process warm-continues without an interactive sign-in; delete a
        // stale entry when there is no refresh token. The write carries the
        // identity binding, so rotation keeps the lineage's account on record.
        if let Some(SecretValue::OAuthToken { refresh, .. }) = creds.fields.get("oauth") {
            match refresh {
                Some(rt) => {
                    let rt = String::from_utf8(rt.0.clone()).map_err(|_| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            "omniverse-storage-service: refresh token must be valid UTF-8",
                        )
                    })?;
                    // A persistence failure PROPAGATES: reporting success
                    // retires the connection's persistence debt, so a rotated
                    // one-time refresh token that never reached the secret store
                    // would leave the next start replaying its consumed
                    // predecessor — provider reuse detection then revokes the
                    // whole lineage.
                    if rt.is_empty() {
                        oauth_secret_store::delete_current_lineage(
                            PLUGIN_NAME,
                            config::KIND,
                            claim,
                            self.state.publication_lock(),
                        )?;
                    } else {
                        oauth_secret_store::persist_current_lineage(
                            PLUGIN_NAME,
                            config::KIND,
                            claim,
                            &self.state,
                            self.state.publication_lock(),
                            &rt,
                        )?;
                    }
                }
                None => oauth_secret_store::delete_current_lineage(
                    PLUGIN_NAME,
                    config::KIND,
                    claim,
                    self.state.publication_lock(),
                )?,
            }
        }
        Ok(())
    }

    async fn load_credentials(&self) -> Result<Option<SecretBundle>> {
        // Warm-continue: a persisted refresh token seeds a refresh-token-only
        // bundle. `validate` then drives the grant to mint a fresh access token,
        // and the identity that grant authenticates as must match the binding
        // recorded here — a stored lineage is adopted only once its owner is
        // confirmed. A keyring READ error propagates (`?`) so callers can fail
        // closed rather than replay an unverifiable in-memory token.
        // A direct-endpoint connection stores nothing, so there is nothing to
        // warm-continue from. Returning before `claim()` is the point — see that
        // function. `ConnectionSet` calls this regardless of `stable_id`, so
        // this guard, not `stable_id`, is what keeps an anonymous connection out
        // of the secret store.
        let Some(claim) = self.claim() else {
            return Ok(None);
        };
        let read_gen = self.state.identity_generation();
        match oauth_secret_store::read_claimed_refresh_token(PLUGIN_NAME, config::KIND, claim)? {
            Some(stored) if !stored.refresh_token.is_empty() => {
                // Fenced on the generation read BEFORE the secret-store round trip:
                // an identity-changing write that landed while this was in
                // flight owns the live identity, and restoring what was read
                // would overwrite it — durably, once the winner's token is
                // persisted under this record.
                if !self
                    .state
                    .adopt_binding_if_identity_unchanged(stored.binding, read_gen)
                {
                    // The read latched the adoption; this connection is
                    // declining the record, so it serves on nothing it read and
                    // a later sibling must not find it retro-actively refused.
                    claim.retract_adoption();
                    return Ok(None);
                }
                Ok(Some(oauth_secret_store::oauth_bundle(
                    "",
                    Some(&stored.refresh_token),
                    None,
                )))
            }
            _ => Ok(None),
        }
    }

    async fn delete_credentials(&self) -> Result<()> {
        // Inverse of `persist_credentials`: drop the stored refresh token and
        // its binding on explicit user removal so a later `add_connection`/probe
        // to the same host does not silently warm-continue on a secret the user
        // removed. Both fields live under this connection's key alone, so a
        // sibling identity — which occupies a different key — is untouched.
        // A failure propagates rather than reporting a removal that did not
        // happen: a caller told the secret was gone would not know to retry,
        // and a later probe to the same host would warm-continue on it.
        //
        // A direct-endpoint connection has no key, and this is the path where
        // that matters most: `ConnectionSet::purge_durable_credential` skips the
        // purge lock AND disables its sibling-sharing guard when `stable_id()`
        // is `None`, then calls this unconditionally. Deleting under any key
        // derived here would therefore be an unguarded delete of somebody
        // else's entry.
        let Some(stable) = self.stable.as_ref() else {
            return Ok(());
        };
        oauth_secret_store::delete_bound_refresh_token(PLUGIN_NAME, config::KIND, stable)?;
        self.state.clear_binding();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// A discovery-mode driver always has a durable key, so its claim is
    /// always present. Only a direct-endpoint driver answers `None`, and these
    /// tests build discovery-mode drivers.
    const CLAIMED: &str = "a discovery-mode driver has a persistence claim";

    use super::*;
    use ovstorage_plugin::connection::credential_conformance::{
        CredentialSnapshot, CredentialTransactionSubject, assert_delegated_replacement_conformance,
    };
    use ovstorage_plugin::oauth_secret_store::{IdentityEpoch, LeaseVerdict};
    use ovstorage_plugin::{Capabilities, ConnectionSource, UserMetadata};

    /// The real driver's reading of its own credential transaction, for the
    /// shared conformance harness. The identity generation, the binding and the
    /// published credential are read inside ONE identity fence, so they are a
    /// coherent observation rather than three independent loads.
    ///
    /// `interactive_lineage` is constant `false`: this crate's `DiscoveryState`
    /// keeps no lineage bit. Where the broker records whether the live identity
    /// came from an interactive grant, here an identity-changing write always
    /// CLEARS the cached M2M pair (`replace_tokens_inner` assigns `None`
    /// unconditionally), so there is no service-lineage shape for a flag to
    /// distinguish. Reporting a dimension this driver does not model as never
    /// moving is the honest answer; the harness would fail it for claiming a
    /// dimension it never mutates.
    #[async_trait]
    impl CredentialTransactionSubject for OmniverseStorageDriver {
        async fn credential_snapshot(&self) -> CredentialSnapshot {
            let mut epoch = None;
            self.state.with_identity_fence(&mut |view| {
                epoch = Some((
                    view.generation,
                    view.binding.cloned(),
                    view.published_credential.map(str::to_string),
                ));
                LeaseVerdict::Current
            });
            let (identity_generation, binding, published_credential) =
                epoch.expect("the identity-fence body always runs");
            CredentialSnapshot {
                access_token: self.state.access_token().await,
                refresh_token: self.state.refresh_token().await,
                expires_at: self.state.access_token_expires_at().await,
                client_credentials: self.state.client_credentials().await,
                interactive_lineage: false,
                generation: self.state.generation(),
                identity_generation,
                published_credential,
                binding,
            }
        }
    }

    /// This driver stands the DELEGATED shape of the shared expectation, not the
    /// one `BrokerDriver` stands: it supplies no `activate_replacing`, so it
    /// takes the trait default and every activation is a same-identity merge.
    ///
    /// That is the difference worth pinning. A merge leaves the cached M2M pair
    /// in place and never advances the supersession fence, and this crate's
    /// `update_credentials` path therefore cannot rotate one identity onto
    /// another through the driver — the divergence
    /// `assert_delegated_replacement_conformance` states rather than leaves to
    /// be inferred. Standing it also holds this driver's install set to the same
    /// per-dimension description as the broker's, so a dimension added to the
    /// transaction fails here too.
    #[tokio::test]
    async fn the_services_driver_conforms_to_the_delegated_replacement() {
        assert_delegated_replacement_conformance(&detached_driver()).await;
    }

    fn detached_driver() -> OmniverseStorageDriver {
        use tonic::transport::{Channel, Endpoint};
        // Channel never connects; these tests exercise only the server-free
        // driver surface (backend_kind / stable_id / classify / the
        // interactive None-capability guard).
        let endpoint = Endpoint::try_from("http://[::1]:1").unwrap();
        let channel = Channel::balance_list(std::iter::once(endpoint));
        let state = DiscoveryState::new("default");
        let transport = OmniverseStorageTransport::with_channel(channel, state.clone());
        OmniverseStorageDriver::new(
            Some("https://svc.example".to_string()),
            state,
            transport,
            reqwest::Client::new(),
            "",
            false,
        )
        .unwrap()
    }

    /// A signed-shaped bearer whose claims name alice at the test issuer and
    /// client; payload
    /// `{"iss":"https://idp.example","sub":"alice","azp":"default"}`.
    const ALICE_BEARER: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJhenAiOiJkZWZhdWx0In0.c2ln";

    fn alice_subject() -> String {
        "alice".to_string()
    }

    /// The same shape naming bob; payload
    /// `{"iss":"https://idp.example","sub":"bob","azp":"default"}`.
    const BOB_BEARER: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiYm9iIiwiYXpwIjoiZGVmYXVsdCJ9.c2ln";

    /// An interactive commit publishes its binding inside the same fenced
    /// transaction that installs its tokens.
    ///
    /// Scope, stated exactly: these two commits run in sequence, so this
    /// asserts the property — each commit publishes the identity it installed,
    /// leaving nothing for a later unfenced publish to get wrong — and NOT the
    /// interleaving itself. The interleaved sequence, where a descheduled flow
    /// resumes after another has committed, is
    /// `a_superseded_flow_cannot_persist`.
    #[tokio::test]
    async fn an_interactive_commit_publishes_its_binding_atomically() {
        let driver = detached_driver();

        // Flow A commits alice's tokens.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("alice-rt".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            alice_subject(),
            "the commit publishes the identity it installed",
        );

        // Flow B commits bob's tokens at the next generation.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    BOB_BEARER.into(),
                    Some("bob-rt".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        // The live identity is bob's, established by the write that installed
        // bob's tokens — not left for an unfenced publish that flow A could
        // still win.
        assert_eq!(driver.state.current_binding().unwrap().subject, "bob");
    }

    /// A credential ROTATION must leave the connection with an identity to
    /// persist under.
    ///
    /// `obtain` establishes the candidate identity, then the activation
    /// replaces the tokens — an identity-changing write. If that write cleared
    /// the binding and only interactive sign-in ever republished it, the
    /// immediately following persist would find no identity and write nothing.
    ///
    /// Scope, stated exactly: this asserts the PRECONDITION, because these
    /// crates register no keyring host and a durable assertion here would test
    /// nothing. That the write then actually lands is asserted where a stub
    /// host exists — `ovstorage-plugin`'s `oauth_identity_binding` suite for
    /// the storage layer, and the Nucleus driver's
    /// `a_rotation_advances_the_stored_token` for a driver's `persist_credentials`
    /// end to end.
    #[tokio::test]
    async fn a_rotation_leaves_the_connection_able_to_persist() {
        let driver = detached_driver();

        // Alice is live and bound, as after a sign-in.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-0".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        // Her token rotates: an identity-changing replacement carrying rt-1.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-1".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        assert!(
            driver.state.current_binding().is_some(),
            "the rotation left an identity to persist under",
        );
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            alice_subject(),
        );
    }

    /// A same-identity ROTATION must still be persistable after a sign-in
    /// published the credential it superseded.
    ///
    /// The supersession proof compares the offered token against the one the
    /// live identity published. A refresh commits through the MERGE primitive,
    /// which rotates the refresh slot without changing the identity, so a proof
    /// that only tracked identity-CHANGING writes would still name the consumed
    /// predecessor and refuse every rotation that followed a sign-in — leaving
    /// the secret store holding a token the provider has already retired.
    #[tokio::test]
    async fn a_rotation_after_a_sign_in_is_still_persistable() {
        let driver = detached_driver_keyed("rotation-after-sign-in");

        // An interactive sign-in commits rt-0 and publishes it.
        driver
            .state
            .replace_tokens_if_identity_unchanged(
                ALICE_BEARER.into(),
                Some("rt-0".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("the sign-in commits");
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            config::KIND,
            driver.claim().expect(CLAIMED),
            &driver.state,
            driver.state.publication_lock(),
            "rt-0",
        )
        .expect("the credential the sign-in published is persistable");

        // A background refresh consumes rt-0 and merges rt-1 onto the live
        // cell. Same identity, so the generation does not move.
        let generation = driver.state.identity_generation();
        assert!(
            driver
                .state
                .install_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-1".into()),
                    None,
                    generation,
                )
                .await,
            "the rotation commits onto the live cell",
        );
        assert_eq!(
            driver.state.identity_generation(),
            generation,
            "a rotation is not an identity change",
        );

        // The lifecycle now persists the successor the live cell holds.
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            config::KIND,
            driver.claim().expect(CLAIMED),
            &driver.state,
            driver.state.publication_lock(),
            "rt-1",
        )
        .expect("the rotated token the live cell holds is persistable");
    }

    /// A transient probe must not poison a live connection's claim.
    ///
    /// Contention is remembered for a claim's whole life, deliberately. So a
    /// probe that briefly claims the same key leaves the live connection
    /// non-exclusive forever: its next rotation consumes rt-0, obtains rt-1,
    /// and the persist is refused — the secret store stays on the consumed token.
    /// A probe is supposed to be side-effect free.
    #[tokio::test]
    async fn a_probe_does_not_poison_a_live_connections_claim() {
        // Drives the guard `obtain` runs first. A probe builds a throwaway
        // driver from the same request — same durable key — so a guard that
        // reached through the claim accessor would acquire and leave the live
        // connection permanently refused. Asserting only that the keys match
        // would pass in exactly that case.
        let live = detached_driver_keyed("probe-victim");
        let _ = live.claim();
        assert!(live.claim().expect(CLAIMED).is_exclusive());

        {
            let probe = detached_driver_keyed("probe-victim");
            assert_eq!(probe.stable, live.stable, "the probe derives the same key");
            // `obtain`, not the helper it happens to call. Calling the helper
            // would still pass if `obtain` were changed back to reach through
            // the claim accessor — which is exactly the regression. The grant
            // itself has no server to reach and is expected to fail; what is
            // under test is whether getting there took a claim.
            let _ = probe
                .obtain(
                    &SecretBundle::default(),
                    ovstorage_plugin::connection::GrantPolicy::NonConsumingOnly,
                    None,
                )
                .await;
        }

        assert!(
            live.claim().expect(CLAIMED).is_exclusive(),
            "a probe that never touched the durable store left the live \
             connection able to grant and to persist",
        );
        assert!(live.claim().expect(CLAIMED).ensure_usable().is_ok());
    }

    /// A superseded flow must not be able to persist at all.
    ///
    /// Flow A installs alice and publishes alice's binding atomically, then is
    /// descheduled before its persistence callback runs. Flow B installs and
    /// persists bob at the new generation. A resumes still carrying ALICE's
    /// refresh token, reads the now-current binding — bob's — and writes
    /// alice's token under bob's record. The live transport is bob while the
    /// keyring describes a mix.
    ///
    /// The lease is what makes that unwritable: A captured the generation when
    /// its flow began, and the write refuses when the generation has moved.
    #[tokio::test]
    async fn a_superseded_flow_cannot_persist() {
        let driver = detached_driver_keyed("superseded-flow");
        let epoch = driver.identity_epoch();

        // Flow A commits alice and takes a lease on the generation ITS OWN
        // commit produced — the anchor the interactive callback uses.
        let gen_a = driver
            .state
            .replace_tokens_if_identity_unchanged(
                ALICE_BEARER.into(),
                Some("alice-rt".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("flow A commits");
        let lease_a = oauth_secret_store::IdentityLease::at_generation(&epoch, gen_a);
        assert!(
            lease_a.is_current(),
            "A owns the identity it just established"
        );

        // Flow B commits bob at the next generation.
        let gen_b = driver
            .state
            .replace_tokens_if_identity_unchanged(
                BOB_BEARER.into(),
                Some("bob-rt".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("flow B commits");
        assert_ne!(gen_a, gen_b);

        // Flow A's callback finally runs. It must not be able to write.
        assert!(!lease_a.is_current());
        let refused = oauth_secret_store::write_leased_refresh_token(
            "test",
            "test-kind",
            driver.claim().expect(CLAIMED),
            &lease_a,
            driver.state.publication_lock(),
            "alice-rt",
            &oauth_secret_store::identity_from_access_token(ALICE_BEARER, "default"),
        );
        assert_eq!(
            refused.unwrap_err().code(),
            ErrorCode::AuthCancelled,
            "a superseded flow cannot persist",
        );

        // B, which does own the identity, can.
        let lease_b = oauth_secret_store::IdentityLease::at_generation(&epoch, gen_b);
        assert!(lease_b.is_current());
    }

    /// A stale durable binding load must not overwrite the identity a
    /// concurrent sign-in just established.
    ///
    /// The stale commit being generation-fenced does not cover this: that
    /// fences the TOKEN, and this corrupts the BINDING. Left unfenced, the
    /// interactive persist then writes the winner's token under the previous
    /// account's record, and the winner is refused on its next grant.
    #[tokio::test]
    async fn a_stale_binding_load_does_not_overwrite_a_concurrent_sign_in() {
        let driver = detached_driver();
        // The generation a warm continuation reads before its keyring round
        // trip.
        let read_gen = driver.state.identity_generation();

        // Bob signs in: identity-changing token write, then his binding.
        driver
            .state
            .replace_tokens("bob-access".into(), Some("bob-rt".into()), None)
            .await;
        driver
            .state
            .set_binding(oauth_secret_store::identity_from_access_token(
                BOB_BEARER, "default",
            ));
        assert_ne!(driver.state.identity_generation(), read_gen);

        // The warm continuation resumes and offers what it read.
        let adopted = driver.state.adopt_binding_if_identity_unchanged(
            oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            },
            read_gen,
        );

        assert!(!adopted, "a load from before the sign-in is refused");
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            "bob",
            "the winner's identity survives a stale load",
        );
    }

    /// The generation compare must be guarded by the same lock the identity
    /// check runs under.
    ///
    /// Two independent loads leave a window: a winner that has recorded its
    /// identity but not yet bumped the generation is visible as "another
    /// principal, same generation", so the in-flight grant reports a false
    /// `AuthRequired` against the connection about to win. The seam runs INSIDE
    /// the checked section, so a version that samples the generation outside
    /// the lock fails here.
    #[tokio::test]
    async fn the_identity_check_and_the_generation_compare_share_one_lock() {
        let driver = detached_driver();
        let observed_under_lock = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::clone(&observed_under_lock);
        driver
            .state
            .set_binding_observation_gate(Some(std::sync::Arc::new(
                move |state: &DiscoveryState| {
                    seen.store(
                        state.binding_lock_is_held(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                },
            )));

        let expected_gen = driver.state.identity_generation();
        driver
            .state
            .set_binding(oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            });
        let _ = driver.check_identity_unless_superseded(BOB_BEARER, expected_gen);
        driver.state.set_binding_observation_gate(None);

        assert!(
            observed_under_lock.load(std::sync::atomic::Ordering::SeqCst),
            "the binding lock is held across the generation compare and the check, \
             so a half-applied identity install is not observable",
        );
    }

    /// A refresh whose grant is superseded by a concurrent sign-in must not be
    /// reported as an identity failure.
    ///
    /// The winning connection holds valid tokens; parking it on a
    /// credential-class error leaves it unusable. The commit is already fenced
    /// on the generation, so supersession outranks the identity check.
    #[tokio::test]
    async fn a_superseded_refresh_is_skipped_rather_than_failed_as_an_impostor() {
        let driver = detached_driver();
        let expected_gen = driver.state.identity_generation();
        driver
            .state
            .set_binding(oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            });

        // Without supersession, this bearer disagrees with the binding.
        assert_eq!(
            driver.check_identity(BOB_BEARER).unwrap_err().code(),
            ErrorCode::AuthRequired,
        );

        // A concurrent sign-in advances the identity generation.
        driver
            .state
            .set_client_credentials("id".into(), "secret".into())
            .await;
        assert_ne!(driver.state.identity_generation(), expected_gen);

        // Now the same bearer is a superseded grant, not an impostor.
        assert!(
            !driver
                .check_identity_unless_superseded(BOB_BEARER, expected_gen)
                .unwrap(),
            "reported as superseded, so the caller skips instead of failing",
        );
        assert!(driver.state.current_binding().is_none());
    }

    /// A driver on a durable key of its own. The claim registry is process
    /// wide, so tests that take a claim must not share one.
    /// A DIRECT-endpoint driver, which has no discovery URL and therefore no
    /// durable key at all.
    fn detached_direct_driver() -> OmniverseStorageDriver {
        use tonic::transport::{Channel, Endpoint};
        let endpoint = Endpoint::try_from("http://[::1]:1").unwrap();
        let channel = Channel::balance_list(std::iter::once(endpoint));
        let state = DiscoveryState::new("default");
        let transport = OmniverseStorageTransport::with_channel(channel, state.clone());
        OmniverseStorageDriver::new(None, state, transport, reqwest::Client::new(), "", false)
            .unwrap()
    }

    /// A direct-endpoint connection must not contend for a REAL connection's
    /// durable key.
    ///
    /// Contention is what this pins, and it is worth being exact about the
    /// limit, because the obvious stronger claim cannot be made here.
    ///
    /// A review asked for the sibling's stored token to be read back after the
    /// direct driver runs every credential verb, so that a regression deriving
    /// a key inside `delete_credentials` would be caught. That was built and
    /// measured, and it does not work: keyring reads and writes route through a
    /// host callback (`marshal::host()`) that no unit test in this workspace
    /// registers, so `load_credentials` returns `None` here whatever happened,
    /// and `is_exclusive` does not observe a delete — deleting takes no claim.
    /// A mutation that fabricates a key inside `delete_credentials` passes
    /// every assertion available at this level, which is why that assertion is
    /// not written as though it held.
    ///
    /// So: this test pins that the direct driver derives no key and takes no
    /// claim, and that the live connection remains exclusive and writable
    /// across the direct driver's whole credential surface. What it CANNOT
    /// cover is a regression that fabricates a key rather than deriving one
    /// from `stable` — that needs a registered host, which is a process-global
    /// `unsafe` pointer and would leak across every test in this binary. The
    /// structural guard is that `stable` is the only key source and is `None`
    /// in this mode.
    #[tokio::test]
    async fn a_direct_connection_cannot_disturb_a_real_connections_credential() {
        let live = detached_driver_keyed("sibling-victim");
        let _ = live.claim();
        assert!(
            live.claim().expect(CLAIMED).is_exclusive(),
            "the live connection starts exclusive, or this proves nothing",
        );
        live.state
            .replace_tokens_if_identity_unchanged(
                ALICE_BEARER.into(),
                Some("rt-live".into()),
                None,
                live.state.identity_generation(),
            )
            .await
            .expect("the sign-in commits");
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            config::KIND,
            live.claim().expect(CLAIMED),
            &live.state,
            live.state.publication_lock(),
            "rt-live",
        )
        .expect("the live connection persists its token");

        let direct = detached_direct_driver();
        assert_eq!(direct.stable_id(), None, "a direct endpoint has no key");
        assert!(direct.load_credentials().await.unwrap().is_none());
        direct
            .persist_credentials(&oauth_secret_store::oauth_bundle(
                "access",
                Some("rt-direct"),
                None,
            ))
            .await
            .expect("persisting nothing succeeds");
        direct
            .delete_credentials()
            .await
            .expect("deleting nothing succeeds");

        // The sibling is untouched. The assertion is on its CLAIM, which is the
        // property the damage would show up in: contention is recorded when a
        // second claim lands on a held key and is never cleared, so a direct
        // connection that derived this key would leave the live one
        // non-exclusive for the rest of its life — and a non-exclusive
        // connection has its grants refused and its stored token purged.
        //
        // Not asserted by reading the token back: no unit test in this crate
        // does, because the secret store backend is not available here — the
        // existing sibling tests assert persistability and exclusivity for the
        // same reason. Persistability is checked again below, since a purge
        // would also have retracted the adoption this write depends on.
        assert!(
            live.claim().expect(CLAIMED).is_exclusive(),
            "a direct connection must not contend for a real connection's key",
        );
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            config::KIND,
            live.claim().expect(CLAIMED),
            &live.state,
            live.state.publication_lock(),
            "rt-live",
        )
        .expect("the live connection can still write its lineage");
    }

    fn detached_driver_keyed(persistence_id: &str) -> OmniverseStorageDriver {
        use tonic::transport::{Channel, Endpoint};
        let endpoint = Endpoint::try_from("http://[::1]:1").unwrap();
        let channel = Channel::balance_list(std::iter::once(endpoint));
        let state = DiscoveryState::new("default");
        let transport = OmniverseStorageTransport::with_channel(channel, state.clone());
        OmniverseStorageDriver::new(
            Some("https://svc.example".to_string()),
            state,
            transport,
            reqwest::Client::new(),
            persistence_id,
            false,
        )
        .unwrap()
    }

    fn dummy_connection() -> Connection {
        Connection {
            id: ConnectionId("c1".into()),
            backend_kind: config::KIND.into(),
            display_name: "svc".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    #[tokio::test]
    async fn backend_kind_and_stable_id() {
        let driver = detached_driver();
        assert_eq!(driver.backend_kind(), config::KIND);
        assert!(
            driver.stable_id().is_some(),
            "stable id derives from the discovery url"
        );
    }

    #[tokio::test]
    async fn classify_maps_the_auth_taxonomy() {
        let driver = detached_driver();
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthRequired, "")),
            AuthErrorClass::NeedsInteractive
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthExpired, "")),
            AuthErrorClass::RecoverableCredential
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::PermissionDenied, "")),
            AuthErrorClass::PermissionDenied
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::Transient, "")),
            AuthErrorClass::NotAuth
        );
    }

    /// Preserves the assertion from the retired factory `authenticate_rejects_no_capability`
    /// test: an interactive request with no host capability fails fast with
    /// `AuthRequired`, before any network work.
    #[tokio::test]
    async fn interactive_rejects_no_capability() {
        let driver = detached_driver();
        // `AuthEventStream` (a boxed iterator) isn't `Debug`, so match rather
        // than `unwrap_err`.
        match driver
            .interactive(dummy_connection(), InteractiveAuthCapability::None, None)
            .await
        {
            Err(err) => assert_eq!(err.code(), ErrorCode::AuthRequired),
            Ok(_) => panic!("None capability must fail fast"),
        }
    }

    /// The two direct-mode credential predicates, driven directly.
    ///
    /// They are unit-tested rather than only exercised through `obtain` because
    /// one of them gates a `tracing::warn!`, and a warning is invisible to every
    /// behavioural test in this crate — including the ones that would otherwise
    /// look like coverage for it.
    ///
    /// **The row that matters most is the first**: the canonical, correct input
    /// for this mode — one access token, nothing else — must produce a bearer
    /// and must NOT be reported as unusable. A predicate that warned there would
    /// tell every correctly-configured operator that their credentials do
    /// nothing, which is exactly the shape of defect a new refusal or a new
    /// warning tends to ship with.
    #[test]
    fn the_direct_credential_predicates_read_each_bundle_shape() {
        fn m2m(bundle: &mut SecretBundle) {
            bundle.fields.insert(
                "client_id".into(),
                SecretValue::Bytes(SecretBytes(b"an-id".to_vec())),
            );
            bundle.fields.insert(
                "client_secret".into(),
                SecretValue::Bytes(SecretBytes(b"a-secret".to_vec())),
            );
        }

        // (description, bundle, expect a bearer, expect "something unusable")
        let mut only_m2m = SecretBundle::default();
        m2m(&mut only_m2m);
        let mut access_and_m2m = oauth_secret_store::oauth_bundle("tok", None, None);
        m2m(&mut access_and_m2m);

        let cases: Vec<(&str, SecretBundle, bool, bool)> = vec![
            (
                "the canonical shape: one access token and nothing else",
                oauth_secret_store::oauth_bundle("tok", None, None),
                true,
                false,
            ),
            // The spelling a TOML `[connections.credentials]` entry and the
            // CLI's `--auth` both produce: every credential they build is
            // `Bytes`. If this row failed, the feature would work from Rust
            // and from nowhere an operator can reach.
            (
                "a raw token, as configuration and the CLI spell it",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "oauth".into(),
                        SecretValue::Bytes(SecretBytes(b"tok".to_vec())),
                    );
                    b
                },
                true,
                false,
            ),
            (
                "an access token with an expiry is still just a bearer",
                oauth_secret_store::oauth_bundle("tok", None, Some(SystemTime::now())),
                true,
                false,
            ),
            (
                "no credential at all",
                SecretBundle::default(),
                false,
                false,
            ),
            (
                "the warm-continue placeholder: empty access, refresh present",
                oauth_secret_store::oauth_bundle("", Some("rt"), None),
                false,
                true,
            ),
            (
                "an access token carrying a refresh token that cannot be redeemed",
                oauth_secret_store::oauth_bundle("tok", Some("rt"), None),
                true,
                true,
            ),
            (
                "an empty refresh token is not a refresh token",
                oauth_secret_store::oauth_bundle("tok", Some(""), None),
                true,
                false,
            ),
            ("a client-credentials pair alone", only_m2m, false, true),
            (
                "an access token beside a client-credentials pair",
                access_and_m2m,
                true,
                true,
            ),
        ];

        for (what, bundle, expect_bearer, expect_unusable) in cases {
            let bearer = direct_bearer(&bundle).expect("no case here is malformed");
            assert_eq!(bearer.is_some(), expect_bearer, "bearer, for {what}");
            assert_eq!(
                carries_unusable_direct_fields(&bundle),
                expect_unusable,
                "unusable fields, for {what}",
            );
            if let Some(effective) = bearer {
                assert!(
                    !effective.fields.contains_key("client_id")
                        && !effective.fields.contains_key("client_secret"),
                    "the effective bundle keeps no client-credentials pair, for {what}",
                );
                // Destructured exhaustively, with no `..`: a field elided here is
                // a field this table does not pin, and `expires_at` was elided
                // while the doc above called dropping it load-bearing.
                let Some(SecretValue::OAuthToken {
                    token: _,
                    refresh,
                    expires_at,
                }) = effective.fields.get("oauth")
                else {
                    panic!("a bearer carries an oauth field, for {what}");
                };
                assert!(
                    refresh.is_none(),
                    "the effective bundle keeps no refresh token, for {what}",
                );
                // The supplied expiry is dropped, and the row above supplies one
                // so that this can fail. Keeping it would put a real `expires_in`
                // on the live cell and start a refresh schedule whose only
                // possible answer on this connection is `Unsupported`.
                assert!(
                    expires_at.is_none(),
                    "the effective bundle keeps no expiry, for {what}",
                );
            }
        }
    }

    /// Which bundles mean "remove the credential in use", and which do not.
    ///
    /// The distinction is the one that costs state if it is drawn wrongly: a
    /// bundle read as a removal CLEARS a live connection's bearer, so anything
    /// that carries something must not be read as one. The first version of
    /// this predicate was an allowlist of the field names this plugin knows,
    /// and a populated field outside that list — a host that names its token
    /// differently, or a typo — fell through it and deleted a working bearer
    /// while reporting success.
    ///
    /// The rows carry both arms of the rule. A key the plugin MODELS is an offer
    /// by presence — `oauth`, `client_id` and `client_secret` alike, blank or not
    /// — because the blank arrives by accident, from an environment reference
    /// that resolved to nothing or a form submitted empty, and the accident
    /// belongs to the reference rather than to the key. A key it does NOT model
    /// is an offer by content, so a blank unmodelled field is a removal and a
    /// populated one is not.
    ///
    /// [`presence_covers_every_credential_schema_field`] is what keeps the first
    /// arm honest across the whole schema; the rows here pin the second arm and
    /// the `SecretValue` variants.
    #[test]
    fn only_a_bundle_offering_nothing_counts_as_a_removal() {
        fn bytes(value: &[u8]) -> SecretValue {
            SecretValue::Bytes(SecretBytes(value.to_vec()))
        }
        let mut blank_m2m = SecretBundle::default();
        blank_m2m.fields.insert("client_id".into(), bytes(b""));
        blank_m2m.fields.insert("client_secret".into(), bytes(b""));

        let mut unmodelled = SecretBundle::default();
        unmodelled
            .fields
            .insert("api_token".into(), bytes(b"a-real-secret"));

        let mut blank_unmodelled = SecretBundle::default();
        blank_unmodelled
            .fields
            .insert("api_token".into(), bytes(b""));

        let mut populated_m2m = SecretBundle::default();
        populated_m2m
            .fields
            .insert("client_id".into(), bytes(b"an-id"));

        for (what, bundle, is_removal) in [
            ("nothing at all", SecretBundle::default(), true),
            // Naming `oauth` is an offer whatever it carries. The realistic
            // way to arrive here is an environment reference that resolved to
            // an empty string, and reading that as "remove the credential"
            // deletes a live bearer and reports success.
            (
                "an oauth field carrying neither token",
                oauth_secret_store::oauth_bundle("", None, None),
                false,
            ),
            (
                "a blank oauth string, as an unset env reference resolves",
                {
                    let mut b = SecretBundle::default();
                    b.fields
                        .insert("oauth".into(), SecretValue::Bytes(SecretBytes(Vec::new())));
                    b
                },
                false,
            ),
            // Modelled keys, so naming them is the offer. A half-populated UI
            // form and an unresolved `${CLIENT_ID}` / `${CLIENT_SECRET}` pair
            // both arrive in exactly this shape, and reading it as a removal
            // would clear a live bearer and report success — the same accident
            // as a blank `oauth`, reached through the sibling fields.
            (
                "blank optional fields, as a form or a secrets adapter emits them",
                blank_m2m,
                false,
            ),
            // Not modelled, so there is no intent in the name and the blank is
            // all there is to read.
            ("a blank unmodelled field", blank_unmodelled, true),
            (
                "a POPULATED field this plugin does not model",
                unmodelled,
                false,
            ),
            ("a populated client id", populated_m2m, false),
            (
                "a refresh token",
                oauth_secret_store::oauth_bundle("", Some("rt"), None),
                false,
            ),
            // No token and no refresh, but an expiry, under a key the plugin
            // does NOT model — so the presence rule does not answer and
            // `field_carries_material` must, which makes the `expires_at`
            // clause there the only thing holding this row up. Elided behind a
            // `..` in the first version of that predicate, which made a bundle
            // carrying only an expiry clear a live bearer. Keyed under `oauth`
            // the row would pass on presence alone and pin nothing.
            (
                "an expiry and nothing else, under an unmodelled key",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "legacy_oauth".into(),
                        SecretValue::OAuthToken {
                            token: SecretBytes(Vec::new()),
                            refresh: None,
                            expires_at: Some(SystemTime::now()),
                        },
                    );
                    b
                },
                false,
            ),
            // The other two disjuncts of the same `OAuthToken` arm, each alone
            // and each under an unmodelled key, so that deleting any one of the
            // three reddens a row. Under `oauth` all three are answered by
            // presence and none of them is pinned.
            (
                "an access token alone, under an unmodelled key",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "legacy_oauth".into(),
                        SecretValue::OAuthToken {
                            token: SecretBytes(b"tok".to_vec()),
                            refresh: None,
                            expires_at: None,
                        },
                    );
                    b
                },
                false,
            ),
            (
                "a refresh token alone, under an unmodelled key",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "legacy_oauth".into(),
                        SecretValue::OAuthToken {
                            token: SecretBytes(Vec::new()),
                            refresh: Some(SecretBytes(b"rt".to_vec())),
                            expires_at: None,
                        },
                    );
                    b
                },
                false,
            ),
            // Every field of the same variant blank: nothing to act on, and no
            // modelled key naming it, so it IS a removal. The polarity control
            // for the three rows above — without it they would all pass against
            // an arm that simply answered `true` for any `OAuthToken`.
            (
                "a wholly blank oauth token, under an unmodelled key",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "legacy_oauth".into(),
                        SecretValue::OAuthToken {
                            token: SecretBytes(Vec::new()),
                            refresh: Some(SecretBytes(Vec::new())),
                            expires_at: None,
                        },
                    );
                    b
                },
                true,
            ),
            (
                "a blank file path",
                {
                    let mut b = SecretBundle::default();
                    b.fields
                        .insert("key".into(), SecretValue::File(SecretBytes(Vec::new())));
                    b
                },
                true,
            ),
            (
                "a file path",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "key".into(),
                        SecretValue::File(SecretBytes(b"/etc/token".to_vec())),
                    );
                    b
                },
                false,
            ),
            (
                "a blank mTLS pair",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "cert".into(),
                        SecretValue::MtlsCertPair {
                            cert_pem: SecretBytes(Vec::new()),
                            key_pem: SecretBytes(Vec::new()),
                        },
                    );
                    b
                },
                true,
            ),
            (
                "an mTLS pair",
                {
                    let mut b = SecretBundle::default();
                    b.fields.insert(
                        "cert".into(),
                        SecretValue::MtlsCertPair {
                            cert_pem: SecretBytes(b"-----BEGIN".to_vec()),
                            key_pem: SecretBytes(Vec::new()),
                        },
                    );
                    b
                },
                false,
            ),
            // Carries no bytes, and is still an OFFER: "use the ambient
            // identity" is a credential this endpoint cannot use, not an
            // absent one.
            (
                "a system-identity request",
                {
                    let mut b = SecretBundle::default();
                    b.fields
                        .insert("identity".into(), SecretValue::SystemIdentity);
                    b
                },
                false,
            ),
        ] {
            assert_eq!(
                offers_no_credential(&bundle),
                is_removal,
                "removal, for {what}",
            );
        }
    }

    /// EVERY field the credential schema publishes is an offer by presence, not
    /// just the one this rule was first written for.
    ///
    /// Enumerated from [`config::credential_schema`] rather than from a list
    /// spelled here, so the coverage cannot fall behind the schema: a field
    /// added there arrives in this test on the same commit that publishes it.
    /// The rule reaching `oauth` alone, with `client_id` and `client_secret`
    /// falling through to a content test, is what let a half-populated form
    /// clear a live bearer and report success.
    #[test]
    fn presence_covers_every_credential_schema_field() {
        let schema = config::credential_schema();
        // The enumeration is only worth as much as the thing enumerated; a
        // schema that came back empty would make every assertion below vacuous.
        assert!(
            schema.len() >= 3,
            "the credential schema publishes the fields this rule ranges over",
        );
        for field in &schema {
            let mut blank = SecretBundle::default();
            blank.fields.insert(
                field.key.clone(),
                SecretValue::Bytes(SecretBytes(Vec::new())),
            );
            assert!(
                !offers_no_credential(&blank),
                "a blank '{}' is an offer, not a removal",
                field.key,
            );
        }
        // The polarity control. Without it the assertions above would all hold
        // for a predicate that simply never reported a removal, and the removal
        // arm is the one that costs state.
        assert!(
            offers_no_credential(&SecretBundle::default()),
            "naming no credential at all is still a removal",
        );
    }

    /// A token that cannot ride in an HTTP header is refused where it is
    /// ACCEPTED, and the honest spellings still pass.
    ///
    /// The refusal is the point: left to the interceptor, an illegal token
    /// answers `Status::internal`, which bring-up propagates rather than parks
    /// and the stack builder is fatal on — so one `[[connections]]` entry would
    /// stop the whole host. `Unsupported` parks the one connection.
    ///
    /// The accepted rows are half the test. A refusal added without them is the
    /// shape that refuses the commonest legitimate input, and a token arriving
    /// with a trailing newline out of a file or a Kubernetes secret is the
    /// commonest legitimate input there is.
    #[test]
    fn a_token_that_cannot_ride_in_a_header_is_refused_where_it_is_accepted() {
        fn bundle_of(token: &str) -> SecretBundle {
            let mut bundle = SecretBundle::default();
            bundle.fields.insert(
                "oauth".into(),
                SecretValue::Bytes(SecretBytes(token.as_bytes().to_vec())),
            );
            bundle
        }
        /// A refusal must not arrive at the operator with a hole in it.
        ///
        /// `Error::new` runs every message through the shared `redact_message`,
        /// which rewrites the token following the word "bearer" — right for a
        /// message quoting a header, wrong for one merely using the phrase.
        /// "cannot be sent as a bearer token" reaches the operator as "as a
        /// bearer REDACTED". Both refusals on this path were written that way
        /// once, which is why this is a test rather than a comment.
        ///
        /// Asserted on the CONSTRUCTED message, not by re-running the sanitizer:
        /// `Error::new` has already applied it, so `redact_message(msg) == msg`
        /// is idempotence and holds however the message was written. Measured —
        /// the first version of this check was that comparison, and rewording
        /// either refusal back to "bearer token" left it green.
        fn assert_survives_redaction(message: &str, what: &str) {
            assert!(
                !message.contains("REDACTED"),
                "the diagnostic must not be mangled by the shared redactor, for {what}: {message}",
            );
        }

        fn bearer_of(bundle: &SecretBundle) -> String {
            let effective = direct_bearer(bundle)
                .expect("a legal token is not refused")
                .expect("a legal token is a bearer");
            let Some(SecretValue::OAuthToken { token, .. }) = effective.fields.get("oauth") else {
                panic!("a bearer carries an oauth field");
            };
            String::from_utf8(token.0.clone()).expect("the token round-trips as UTF-8")
        }

        // Refused. Each carries a CONTROL character, in a position trimming
        // cannot reach, so header legality is the only thing that can catch it.
        //
        // Control characters, not "non-ASCII": `HeaderValue` admits the obs-text
        // range `0x80..=0xff`, so `tok\u{e9}` is a legal header value and is
        // accepted. Asserting a refusal there would be asserting a rule this
        // code does not implement.
        for (what, token) in [
            ("an interior newline", "tok\nmore"),
            ("an interior carriage return", "tok\rmore"),
            ("an interior NUL", "tok\0more"),
            ("a DEL", "tok\u{7f}more"),
        ] {
            let err = direct_bearer(&bundle_of(token))
                .expect_err(&format!("{what} cannot ride in a header"));
            assert_eq!(err.code(), ErrorCode::Unsupported, "code, for {what}");
            assert!(
                !err.to_string().contains(token),
                "the diagnostic names the credential, never its value, for {what}",
            );
            assert_survives_redaction(&err.to_string(), what);
        }

        // Accepted unchanged. A bearer token's alphabet is `b64token`, so these
        // are the shapes an IDP actually mints.
        for (what, token) in [
            ("an opaque token", "AbC0-9._~+/=="),
            (
                "a JWT",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.s1gn-4tur3_x",
            ),
            // The row the comment above turns on, so that claim is measured
            // rather than asserted in prose. `HeaderValue` admits the obs-text
            // range, so this is ACCEPTED; a reader going by `MetadataValue`'s
            // "visible ASCII" description predicts a refusal, and the
            // disagreement is settled here rather than in a comment.
            ("a non-ASCII character", "tok\u{e9}"),
        ] {
            assert_eq!(bearer_of(&bundle_of(token)), token, "unchanged, for {what}");
        }

        // Accepted, with the surrounding whitespace removed. The effective
        // bundle must carry the TRIMMED token: asserting only that these are not
        // refused would pass while the untrimmed value went on to fail every RPC.
        for (what, token) in [
            (
                "a trailing newline, as a file-borne secret carries",
                "tok\n",
            ),
            ("a trailing CRLF", "tok\r\n"),
            ("leading and trailing spaces", "  tok\t"),
        ] {
            assert_eq!(bearer_of(&bundle_of(token)), "tok", "trimmed, for {what}");
        }

        // Whitespace and nothing else is no bearer rather than a refusal — and
        // the caller does not read it as a removal either, because naming
        // `oauth` is an offer.
        let only_space = bundle_of(" \n");
        assert!(
            direct_bearer(&only_space)
                .expect("whitespace is not malformed")
                .is_none(),
            "a token of only whitespace offers no bearer",
        );
        assert!(
            !offers_no_credential(&only_space),
            "and it is still an offer, so the caller refuses rather than removing",
        );
    }

    /// A non-UTF-8 access token is refused rather than silently dropped.
    /// Reporting "no credential supplied" for a credential that was supplied and
    /// could not be read is the absorbing behaviour this mode exists not to have.
    ///
    /// `Unsupported`, like every other "this credential cannot be used here"
    /// answer on this path: the lifecycle reads an argument error as a caller
    /// contract failure and the stack builder is fatal on it, so a malformed
    /// credential in one configured connection would stop the whole host.
    #[test]
    fn a_malformed_access_token_is_reported_rather_than_dropped() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(vec![0xff, 0xfe]),
                refresh: None,
                expires_at: None,
            },
        );
        let err = direct_bearer(&bundle).expect_err("invalid UTF-8 is not a usable bearer");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }
}
