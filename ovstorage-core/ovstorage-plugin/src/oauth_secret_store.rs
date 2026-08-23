// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OAuth refresh-token persistence helpers shared by plugins that
//! warm-continue a long-lived OIDC session across process restarts.
//!
//! The host's keyring API takes a `(backend_kind, connection_id, field)`
//! triple. Callers pass a stable hostname-shaped key so the entry
//! survives across restarts (the host-issued `ConnectionId` is
//! `pid + nanos`, non-stable).

use std::time::SystemTime;

use crate::ErrorCode;
use crate::marshal;
use crate::types::{ConnectionId, SecretBundle, SecretBytes, SecretValue};

/// Compatibility re-export; the cross-cutting identity derivation lives in
/// [`crate::connection::identity`].
pub use crate::connection::identity::conn_id_from_request;
pub use crate::oauth_binding::{
    BindingCell, EpochView, IdentityBinding, IdentityEpoch, IdentityLease, LeaseVerdict,
    PersistenceClaim, SharedPersistenceClaim, access_token_of, fingerprint,
    identity_from_access_token, refresh_token_of, validate_persistence_id,
};

// Private field-name literals used to store/fetch the refresh token and its
// identity binding in the secret store secret bundle; internal string constants, not
// C ABI symbols.
/// cbindgen:ignore
const REFRESH_TOKEN_FIELD: &str = "refresh_token";
/// cbindgen:ignore
const IDENTITY_BINDING_FIELD: &str = "identity_binding";

/// Map a discovery URL to a stable `ConnectionId` keyed on its **canonical
/// origin + path** (`scheme://host:port/path`), not the bare host.
///
/// Keying on `host` alone collapses distinct connections that share a hostname
/// but differ in scheme, port, or path — multiple services or tenants on one
/// host — onto a single key, so one connection's `persist_credentials` clobbers
/// another's refresh token and a warm-continue reads a sibling's token against
/// the wrong OIDC session (a cross-connection credential leak). The same key
/// also namespaces the cross-process refresh lock, so unrelated services on one
/// host would otherwise contend on one lease. Canonicalizing on the full origin
/// keeps them distinct.
///
/// `port_or_known_default()` normalizes `https://h` and `https://h:443` to the
/// same key; a trailing slash on the path is trimmed so `…/discovery` and
/// `…/discovery/` agree. Unparseable input falls back to the raw string.
///
/// NOTE: this changes the durable key shape, so refresh tokens persisted by a
/// prior build under the host-only key are not found after upgrade — a one-time
/// interactive re-auth per connection, no token loss. A silent migration is
/// deliberately NOT attempted: reading the legacy host-only entry as a fallback
/// would resurrect exactly the cross-connection wrong-token read this
/// identity-scoped keying closes (two connections sharing a host would both read it).
pub fn conn_id_from_url(discovery_url: &str) -> ConnectionId {
    match url::Url::parse(discovery_url) {
        Ok(u) if u.host_str().is_some() => {
            let scheme = u.scheme();
            let host = u.host_str().unwrap_or_default();
            let port = u
                .port_or_known_default()
                .map(|p| p.to_string())
                .unwrap_or_default();
            // One trailing slash is cosmetic variance operators type
            // interchangeably; more than one is a genuinely different path, and
            // collapsing them would merge two connections onto one key.
            let path = u.path().strip_suffix('/').unwrap_or(u.path());
            // Include the query so discovery URLs differing only by `?query`
            // (e.g. a tenant selector) don't collapse onto one key. Userinfo and
            // fragment are intentionally dropped (not part of the resource
            // identity); scope by auth identity via `conn_id_from_url_and_client`.
            let query = u.query().map(|q| format!("?{q}")).unwrap_or_default();
            ConnectionId(format!("{scheme}://{host}:{port}{path}{query}"))
        }
        _ => ConnectionId(discovery_url.to_string()),
    }
}

/// [`conn_id_from_url`] additionally scoped by the OIDC client identity.
///
/// Two connections to the SAME discovery URL under different OIDC clients are
/// distinct sessions with distinct refresh-token lineages: keying them only on
/// the URL collides them on one stored secret and one cross-process refresh
/// lease, so one connection's `persist_credentials` destroys the other's token
/// and a warm-continue grants a sibling client's refresh token (cross-client
/// confusion / IdP reuse-detection). Folding the client identity into the stable
/// id keeps them separate (S3 / 3539858355). `client_name` empty leaves the key
/// equal to the bare origin form.
pub fn conn_id_from_url_and_client(discovery_url: &str, client_name: &str) -> ConnectionId {
    conn_id_from_url_and_account(discovery_url, client_name, "")
}

/// [`conn_id_from_url_and_client`] additionally scoped by the connection's
/// durable account discriminator.
///
/// `persistence_id` is immutable operator-chosen text from connection config.
/// It exists because everything else in the key describes the *endpoint*: two
/// same-endpoint SSO connections under one OIDC client, intended for different
/// people, derive one key and would otherwise share one refresh-token lineage.
/// Deriving the discriminator from `display_name` instead is unsound in the
/// other direction — a presentation label is mutable, so renaming a connection
/// would move its credential to a fresh key and orphan the old one. (Plugins
/// keyed on [`conn_id_from_request`] rather than this function do hash
/// `display_name`, and pay exactly that cost.)
///
/// Empty `persistence_id` leaves the key equal to the client-scoped form, and
/// the connection relies on the stored [`IdentityBinding`] plus
/// [`PersistenceClaim`] exclusivity for account separation.
///
/// Every component is escaped, including the endpoint one, so a value
/// containing a separator cannot forge a neighbouring one: `client#a` with no
/// discriminator and `client` with discriminator `a` are distinct keys, and so
/// are a URL ending `…/a@b` and a `…/a` URL with discriminator `b`. The
/// endpoint has to be escaped like the rest because a separator survives URL
/// parsing in the path and query, and passes through verbatim on the
/// unparseable-URL fallback.
///
/// The escaping moves the key for any endpoint or client name containing `%`,
/// `#`, or `@`, so an entry a prior build wrote is no longer found. That costs
/// nothing beyond what upgrading already costs: an entry written before
/// [`IdentityBinding`] existed carries no binding record, and
/// `read_bound_refresh_token` refuses an unbound lineage whatever key it sits
/// under. Every pre-upgrade entry therefore forces one interactive sign-in
/// regardless of framing, and a fallback read of the unescaped key would buy
/// back no credential while reopening exactly the forgery this framing closes.
pub fn conn_id_from_url_and_account(
    discovery_url: &str,
    client_name: &str,
    persistence_id: &str,
) -> ConnectionId {
    let mut key = escape_component(&conn_id_from_url(discovery_url).0);
    if !client_name.is_empty() {
        key.push('#');
        key.push_str(&escape_component(client_name));
    }
    if !persistence_id.is_empty() {
        key.push('@');
        key.push_str(&escape_component(persistence_id));
    }
    ConnectionId(key)
}

/// Escape the separators the composite key reserves, so component values stay
/// distinguishable from the framing around them.
fn escape_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '#' => out.push_str("%23"),
            '@' => out.push_str("%40"),
            _ => out.push(ch),
        }
    }
    out
}

/// A persisted refresh token together with the identity it is bound to.
#[derive(Clone)]
pub struct BoundRefreshToken {
    /// The stored refresh token.
    pub refresh_token: String,
    /// The identity the lineage belongs to, to be confirmed against the
    /// session this token authenticates as.
    pub binding: IdentityBinding,
}

/// Renders the binding and the *presence* of the secret, never the secret —
/// the repo's rule for any type holding plaintext credential material.
impl std::fmt::Debug for BoundRefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundRefreshToken")
            .field("refresh_token", &"<redacted>")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Read the persisted refresh token together with its identity binding.
///
/// Crate-private on purpose: every driver adoption goes through
/// [`read_claimed_refresh_token`], which takes the claim rather than a bare
/// key. Keeping this unreachable from the plugin crates is what makes the
/// ambiguity gate structural instead of a convention each caller must
/// remember.
///
/// `Ok(None)` means "nothing adoptable here": no host, no entry, an empty
/// token, or an entry whose binding record is absent, undecodable, or names no
/// account on any axis. `Err` propagates a keyring READ failure exactly as
/// [`read_refresh_token`] does.
///
/// A record that names no account — every field empty — would be satisfied by
/// any identity whatsoever, so it is not a binding and is refused like an
/// absent one. Treating it as adoptable would reopen precisely the sharing this
/// module closes: a sibling connection deriving the same key would pass
/// verification against it.
///
/// MIGRATION: an entry written before bindings existed carries a refresh token
/// and no binding record. Such a lineage cannot be shown to belong to the
/// account this connection is configured for — it may equally be a sibling's,
/// which is the very sharing this binding closes — so it is refused rather than
/// adopted, and the connection falls back to interactive sign-in. The entry is
/// left in place rather than deleted, so the decision is reversible and the
/// next successful sign-in overwrites it with a bound record. The operator-
/// visible cost is one interactive re-authentication per connection on upgrade.
pub(crate) fn read_bound_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
) -> std::result::Result<Option<BoundRefreshToken>, crate::Error> {
    let Some(refresh_token) = read_refresh_token(plugin, backend_kind, conn)? else {
        return Ok(None);
    };
    let Some(host_cb) = marshal::host() else {
        return Ok(None);
    };
    let stored = match host_cb.secret_get(backend_kind, conn, IDENTITY_BINDING_FIELD) {
        Ok(Some(bytes)) => IdentityBinding::decode(&bytes.0),
        Ok(None) => None,
        Err(err) => {
            tracing::warn!(
                plugin,
                key = %conn.0,
                error = %err,
                "identity binding read failed",
            );
            return Err(err);
        }
    };
    match stored {
        Some(binding) if binding.is_specific() => Ok(Some(BoundRefreshToken {
            refresh_token,
            binding,
        })),
        _ => {
            tracing::warn!(
                plugin,
                key = %conn.0,
                "persisted refresh token carries no identity binding that names an \
                 account; interactive sign-in is required to bind it",
            );
            Ok(None)
        }
    }
}

/// Persist the refresh token together with the identity it belongs to.
///
/// Crate-private on purpose: every driver write goes through
/// [`write_claimed_refresh_token`]. A sign-in that wrote past the gate is
/// exactly how a shared key was handed to a sibling connection, so the gate
/// is enforced by reachability rather than by review.
///
/// Both fields are written under one key, so a rotation that carries the same
/// binding preserves it and a rotation that carries a sharpened one updates it
/// in step with the token.
///
/// The binding is written first, and a failure there abandons the token write.
/// Either interleaving fails closed on the next read — a token that disagrees
/// with its record is refused, and so is a token with no record — but this
/// order never leaves a secret stored without one, which is the shape a reader
/// cannot distinguish from a pre-binding entry. A binding left without a token
/// is inert: the read reports "no token" before it is ever consulted.
///
/// A binding naming no account on any axis is not written at all, and neither
/// is the token beside it. Such a record would be satisfied by any identity, so
/// storing it would leave an entry any same-key sibling could adopt — strictly
/// worse than not persisting, which costs only an interactive sign-in next
/// time. Reaching this means the caller could not learn who authenticated: the
/// provider issued an opaque access token *and* the connection has no
/// configured client name to fall back on. Setting `oidc_client_name` or
/// `persistence_id` gives such a deployment a durable lineage again.
pub(crate) fn write_bound_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
    token: &str,
    binding: &IdentityBinding,
) -> std::result::Result<(), crate::Error> {
    if !binding.is_specific() {
        tracing::warn!(
            plugin,
            key = %conn.0,
            "no identity could be established for this session, so the refresh token \
             is not persisted; a record matching every identity would be adoptable by \
             any connection sharing the key. Set `oidc_client_name` or \
             `persistence_id` to give this connection a durable lineage",
        );
        return Err(refusal(
            "no identity could be established for this session, so the credential \
             was not stored. Set `oidc_client_name` or `persistence_id` to give this \
             connection a durable lineage",
        ));
    }
    if let Some(host_cb) = marshal::host() {
        let value = SecretBytes(binding.encode());
        if let Err(err) = host_cb.secret_put(backend_kind, conn, IDENTITY_BINDING_FIELD, &value) {
            tracing::warn!(
                plugin,
                key = %conn.0,
                error = %err,
                "identity binding write failed; the refresh token is not persisted \
                 because an unbound entry is not adoptable",
            );
            return Err(err);
        }
    }
    write_refresh_token(plugin, backend_kind, conn, token)
}

/// Delete the persisted refresh token and its identity binding.
///
/// This one stays public, because an operator removing a connection must be
/// able to clear its secret even when the key is ambiguous — refusing there
/// would leave a credential behind after an explicit removal, which is the
/// worse failure. Where a sibling shares the key, neither connection was
/// permitted to write it, so what a removal can destroy is an entry from
/// before the ambiguity arose; the cost is one interactive sign-in, not a
/// credential handed to the wrong account. Rotation-time deletion is a
/// different act and uses [`delete_claimed_refresh_token`].
///
/// Both fields live under this connection's key alone, so removal reaches
/// exactly one lineage: a sibling identity, which by construction occupies a
/// different key, is untouched.
pub fn delete_bound_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
) -> std::result::Result<(), crate::Error> {
    let token_result = delete_refresh_token(plugin, backend_kind, conn);
    if let Some(host_cb) = marshal::host()
        && let Err(err) = host_cb.secret_delete(backend_kind, conn, IDENTITY_BINDING_FIELD)
        && err.code() != ErrorCode::NotFound
    {
        tracing::warn!(plugin, key = %conn.0, error = %err, "identity binding delete failed");
        return Err(err);
    }
    token_result
}

/// Adopt a persisted lineage only while this connection is its sole claimant.
///
/// This is `read_bound_refresh_token` with the ambiguity gate attached, and
/// it is the only read a driver should use. Exclusivity is checked both before
/// the read and after it: a sibling connection that claims the key at any point
/// during the read makes the lineage unattributable, and a claim that merely
/// sampled the count beforehand would adopt a credential a sibling was already
/// contending for.
///
/// `Ok(None)` covers the ambiguous case as well as the ordinary "nothing
/// adoptable" ones, so the connection falls back to interactive sign-in.
pub fn read_claimed_refresh_token(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
) -> std::result::Result<Option<BoundRefreshToken>, crate::Error> {
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "not adopting");
        return Ok(None);
    }
    let stored = read_bound_refresh_token(plugin, backend_kind, claim.key())?;
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "not adopting");
        return Ok(None);
    }
    if stored.is_some() {
        // Recorded here rather than by each driver: adoption is what makes a
        // later sibling's arrival retro-actively fatal, and a driver that
        // forgot to say so would serve on a lineage nobody can attribute.
        claim.record_adoption();
    }
    Ok(stored)
}

/// Persist a lineage only while this connection is its sole claimant.
///
/// This is `write_bound_refresh_token` with the ambiguity gate attached, and
/// it is the only write a driver should use — including the one an interactive
/// sign-in performs. Routing every write through the claim is what stops a
/// sign-in from stamping its token onto a key a sibling connection also
/// derives, which is exactly the sharing this module exists to prevent.
///
/// Exclusivity is checked before and after, so a sibling arriving mid-write
/// leaves the entry alone rather than half-claimed.
pub fn write_claimed_refresh_token(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
    token: &str,
    binding: &IdentityBinding,
) -> std::result::Result<(), crate::Error> {
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "not writing");
        // The stored entry is deliberately LEFT ALONE. A refused write cannot
        // tell whether the entry it would remove was superseded by this
        // caller's rotation or belongs to a sibling that consumed nothing —
        // token inequality proves difference, not supersession, and a fresh
        // login on a shared key produces inequality while destroying a valid
        // credential. Retiring a consumed head safely needs the predecessor the
        // rotation actually consumed, which is not on this path.
        // TODO: make the consumed head self-describing so a retirement can
        // identify the predecessor the rotation consumed.
        return Err(refusal(
            "another live connection shares this credential persistence key, so the \
             credential was not stored. Set a distinct `persistence_id` on each \
             connection and reconnect",
        ));
    }
    write_bound_refresh_token(plugin, backend_kind, claim.key(), token, binding)?;
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "removing the entry just written for");
        delete_bound_refresh_token(plugin, backend_kind, claim.key())?;
        return Err(refusal(
            "another live connection claimed this credential persistence key while \
             the credential was being stored, so it was taken back out. Set a \
             distinct `persistence_id` on each connection and reconnect",
        ));
    }
    Ok(())
}

/// Persist a lineage on behalf of a flow that still owns the identity.
///
/// [`write_claimed_refresh_token`] with the identity lease attached. A flow
/// descheduled between its own commit and its persistence callback is
/// superseded by whatever committed meanwhile, and would otherwise write ITS
/// token under the CURRENT binding — a stored secret describing one account
/// holding another's secret. Requiring the lease is what makes that
/// unwritable, rather than something each call site has to remember to check.
///
/// The write runs under `publication`, which identity-changing installs also
/// hold, so the lease compare and the write cannot be split by one. The
/// publication lock is separate from the identity fence precisely so this
/// secret-store round trip does not run under a lock the read path takes.
pub fn write_leased_refresh_token(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
    lease: &IdentityLease,
    publication: &std::sync::Mutex<()>,
    token: &str,
    binding: &IdentityBinding,
) -> std::result::Result<(), crate::Error> {
    let _publishing = publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !lease.is_current() {
        tracing::warn!(
            plugin,
            key = %claim.key().0,
            "this sign-in was superseded before its credential reached the secret store; \
             not writing a credential the connection no longer holds",
        );
        return Err(lease.superseded_error());
    }
    write_claimed_refresh_token(plugin, backend_kind, claim, token, binding)
}

/// [`delete_claimed_refresh_token`] with the identity lease attached.
pub fn delete_leased_refresh_token(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
    lease: &IdentityLease,
    publication: &std::sync::Mutex<()>,
) -> std::result::Result<(), crate::Error> {
    let _publishing = publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !lease.is_current() {
        return Err(lease.superseded_error());
    }
    delete_claimed_refresh_token(plugin, backend_kind, claim)
}

/// Remove a persisted lineage as part of rotation, only while this connection
/// is its sole claimant.
///
/// Deleting a key a sibling also claims would destroy a credential this
/// connection cannot show is its own. An operator-initiated removal is a
/// different act and goes through [`delete_bound_refresh_token`] directly.
///
/// Exclusivity is checked before and after, like the read and the write. A
/// deletion cannot be undone the way a write can, so a sibling arriving
/// mid-delete is reported as an error rather than silently reported as a clean
/// rotation: the caller has just destroyed an entry it can no longer show was
/// its own, and the connection must re-authenticate rather than carry on
/// believing the durable state matches its own lineage.
pub fn delete_claimed_refresh_token(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
) -> std::result::Result<(), crate::Error> {
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "not deleting");
        return Err(refusal(
            "another live connection shares this credential persistence key, so the \
             stored credential was left alone. Set a distinct `persistence_id` on \
             each connection and reconnect",
        ));
    }
    delete_bound_refresh_token(plugin, backend_kind, claim.key())?;
    if !claim.is_exclusive() {
        warn_shared_key(plugin, claim, "already deleted the entry for");
        return Err(refusal(
            "another live connection claimed this credential persistence key while \
             its entry was being removed; the removal cannot be taken back. Set a \
             distinct `persistence_id` on each connection and sign in again",
        ));
    }
    Ok(())
}

/// The error a refused persistence carries.
///
/// A refusal and a success must not share a return value. `ConnectionSet`'s
/// debt policy retires a connection's persistence debt on `Ok`, so a refusal
/// reported as `Ok` tells the lifecycle a rotated successor is durable while
/// the secret store still holds its consumed predecessor — and the next process
/// start replays that predecessor into the provider's reuse detection, which
/// can revoke the lineage. Reported as `Err`, the same refusal lands on the
/// path built for exactly this: the debt stands, memory stays authoritative,
/// and a keyring-lineage bring-up skips the stale head.
///
/// `CredentialUnavailable` rather than `AuthRequired`: nothing about the
/// session is wrong, and the connection must not be pushed toward purging a
/// credential it was not allowed to touch.
fn refusal(message: &str) -> crate::Error {
    crate::Error::new(ErrorCode::CredentialUnavailable, message)
}

/// Whether `creds` carries the credential the connection's live identity
/// published, and so may still be committed on its behalf.
///
/// The in-memory sibling of the compare [`persist_current_lineage`] makes
/// before a durable write. An interactive flow's terminal event is checked for
/// supersession before it is QUEUED, but the consumer drains it later, and a
/// newer flow can commit in between; committing then regresses the connection's
/// credentials to a bundle the live cell no longer holds, and the next refresh
/// drives a grant on a token the provider has already consumed. The durable
/// write refuses that bundle, but it cannot undo the in-memory regression —
/// this is the compare that stops it happening.
///
/// `true` when there is nothing to compare: the connection published no
/// credential, or the bundle names no lineage. Neither is evidence of
/// supersession, and refusing on absence would park sign-ins that are fine.
///
/// This declines a WRITE; it never removes anything. A connection whose bundle
/// is refused keeps whatever the winner installed, in memory and in the
/// keyring, so no valid credential can be destroyed by a false negative.
pub fn bundle_carries_published_credential(
    epoch: &dyn IdentityEpoch,
    creds: &SecretBundle,
) -> bool {
    let Some(offered) = refresh_token_of(creds) else {
        return true;
    };
    let mut published = None;
    epoch.with_identity_fence(&mut |view| {
        published = view.published_credential.map(str::to_owned);
        LeaseVerdict::Current
    });
    match published {
        Some(published) => published == fingerprint(&offered),
        None => true,
    }
}

/// Persist the lineage a connection is CURRENTLY bound to.
///
/// The binding and the token were two unsynchronised reads: a background
/// refresh could return one account's rotated token while an interactive
/// sign-in for another bumped the generation and replaced the binding, and the
/// persist would then write the first account's secret under the second's
/// record. Reading the binding here — inside the publication lock, which every
/// identity-changing install also takes — makes the read and the write one step
/// with respect to any install.
///
/// Refuses when the connection is bound to nobody: there is no record to write
/// the secret under, and an unattributable entry is not adoptable anyway.
pub fn persist_current_lineage(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
    epoch: &dyn IdentityEpoch,
    publication: &std::sync::Mutex<()>,
    token: &str,
) -> std::result::Result<(), crate::Error> {
    let _publishing = publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut binding = None;
    let mut published = None;
    epoch.with_identity_fence(&mut |view| {
        binding = view.binding.cloned();
        published = view.published_credential.map(str::to_owned);
        LeaseVerdict::Current
    });
    // The credential offered must be the one the live identity published, not
    // merely one that coexists with it. A flow whose terminal event queued
    // before a newer sign-in committed still carries ITS token, and the
    // lifecycle's persist runs after that queue drains — the last point at
    // which a stale flow can write, and the point this proof has to reach.
    if let Some(published) = published.as_deref()
        && published != fingerprint(token)
    {
        tracing::warn!(
            plugin,
            key = %claim.key().0,
            "the credential offered is not the one this connection's live identity \
             published, so a newer sign-in has superseded it; not writing",
        );
        return Err(crate::Error::new(
            ErrorCode::AuthCancelled,
            "this credential was superseded by a newer sign-in for the same \
             connection before it could be stored",
        ));
    }
    let Some(binding) = binding else {
        tracing::warn!(
            plugin,
            key = %claim.key().0,
            "the connection is bound to no identity, so its credential was not stored",
        );
        return Err(refusal(
            "no identity is established for this connection, so its credential was \
             not stored; it signs in again",
        ));
    };
    write_claimed_refresh_token(plugin, backend_kind, claim, token, &binding)
}

/// [`delete_claimed_refresh_token`] under the publication lock, so a rotation
/// that clears the durable entry cannot interleave an identity install either.
pub fn delete_current_lineage(
    plugin: &str,
    backend_kind: &str,
    claim: &PersistenceClaim,
    publication: &std::sync::Mutex<()>,
) -> std::result::Result<(), crate::Error> {
    let _publishing = publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    delete_claimed_refresh_token(plugin, backend_kind, claim)
}

fn warn_shared_key(plugin: &str, claim: &PersistenceClaim, action: &str) {
    tracing::warn!(
        plugin,
        key = %claim.key().0,
        "credential persistence key is shared by another live connection; {action} \
         a credential neither connection can claim. Set a distinct `persistence_id` \
         on each connection and reconnect",
    );
}

/// Read the persisted refresh token, with no identity binding and no claim.
///
/// Crate-private: a plugin adopting a lineage through this would skip both the
/// ambiguity gate and the identity check, which is the original failure. Every
/// driver adoption goes through [`read_claimed_refresh_token`].
///
/// `Ok(None)` means "no host / no entry /
/// empty / non-UTF-8 stored value" — genuinely no usable token. `Err` means the
/// keyring READ itself FAILED: callers that would otherwise grant on an
/// in-memory copy must fail closed rather than risk replaying a consumed token
/// they cannot verify against the persisted head (a keyring read error is not
/// the same as "no token").
pub(crate) fn read_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
) -> std::result::Result<Option<String>, crate::Error> {
    let Some(host_cb) = marshal::host() else {
        return Ok(None);
    };
    match host_cb.secret_get(backend_kind, conn, REFRESH_TOKEN_FIELD) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes.0) {
            Ok(s) if !s.is_empty() => Ok(Some(s.to_string())),
            Ok(_) => Ok(None),
            Err(_) => {
                tracing::warn!(
                    plugin,
                    key = %conn.0,
                    "stored refresh_token is not UTF-8; ignoring",
                );
                Ok(None)
            }
        },
        Ok(None) => Ok(None),
        Err(err) => {
            tracing::warn!(plugin, key = %conn.0, error = %err, "secret_get failed");
            Err(err)
        }
    }
}

/// Persist the refresh token durably. `Err` propagates a real keyring WRITE
/// failure so a caller running under a persist-debt policy can latch the debt
/// (memory stays authoritative on the successor) rather than silently strand the
/// durable store on a consumed predecessor. `Ok(())` when there is no host
/// (nothing to persist against).
pub(crate) fn write_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
    token: &str,
) -> std::result::Result<(), crate::Error> {
    let Some(host_cb) = marshal::host() else {
        return Ok(());
    };
    let value = SecretBytes(token.as_bytes().to_vec());
    if let Err(err) = host_cb.secret_put(backend_kind, conn, REFRESH_TOKEN_FIELD, &value) {
        tracing::warn!(
            plugin,
            key = %conn.0,
            error = %err,
            "secret_put failed; refresh_token will not survive process exit",
        );
        return Err(err);
    }
    Ok(())
}

/// Delete the persisted refresh token FIELD, leaving any identity binding
/// beside it.
///
/// Crate-private: deleting the token without its record strands an orphaned
/// binding, and doing it without presenting a claim removes durable
/// continuation from a connection that may still be its rightful owner. Both
/// the rotation path ([`delete_claimed_refresh_token`]) and operator removal
/// ([`delete_bound_refresh_token`]) clear the pair together, so no caller
/// outside this module needs the half. A `NotFound` from the host is success
/// (nothing to delete); any other keyring DELETE failure propagates as `Err` so
/// a caller can latch persist-debt rather than assume the durable store was
/// cleared. `Ok(())` when there is no host.
pub(crate) fn delete_refresh_token(
    plugin: &str,
    backend_kind: &str,
    conn: &ConnectionId,
) -> std::result::Result<(), crate::Error> {
    let Some(host_cb) = marshal::host() else {
        return Ok(());
    };
    if let Err(err) = host_cb.secret_delete(backend_kind, conn, REFRESH_TOKEN_FIELD)
        && err.code() != ErrorCode::NotFound
    {
        tracing::warn!(plugin, key = %conn.0, error = %err, "secret_delete failed");
        return Err(err);
    }
    Ok(())
}

/// Build the SecretBundle shape `update_credentials` expects from a
/// resolved access/refresh/expiry triple.
pub fn oauth_bundle(
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<SystemTime>,
) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(access.as_bytes().to_vec()),
            refresh: refresh.map(|r| SecretBytes(r.as_bytes().to_vec())),
            expires_at,
        },
    );
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::{ConfigValue, ConnectionRequest};

    fn request(display_name: &str, pairs: &[(&str, ConfigValue)]) -> ConnectionRequest {
        ConnectionRequest {
            backend_kind: "nucleus".into(),
            config: pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect::<HashMap<_, _>>(),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some(display_name.into()),
        }
    }

    #[test]
    fn conn_id_from_request_is_stable_across_config_order() {
        let a = request(
            "alice",
            &[
                ("server", ConfigValue::String("nucleus.example".into())),
                ("use_lft", ConfigValue::Bool(true)),
            ],
        );
        let b = request(
            "alice",
            &[
                ("use_lft", ConfigValue::Bool(true)),
                ("server", ConfigValue::String("nucleus.example".into())),
            ],
        );
        assert_eq!(conn_id_from_request(&a), conn_id_from_request(&b));
    }

    #[test]
    fn conn_id_from_request_scopes_same_endpoint_by_connection_identity() {
        let alice = request(
            "alice",
            &[("server", ConfigValue::String("nucleus.example".into()))],
        );
        let bob = request(
            "bob",
            &[("server", ConfigValue::String("nucleus.example".into()))],
        );
        assert_ne!(conn_id_from_request(&alice), conn_id_from_request(&bob));
    }

    #[test]
    fn conn_id_from_request_has_unambiguous_field_framing() {
        let embedded = request(
            "alice\nendpoint=S:e",
            &[("server", ConfigValue::String("srv".into()))],
        );
        let split = request(
            "alice",
            &[
                ("endpoint", ConfigValue::String("e".into())),
                ("server", ConfigValue::String("srv".into())),
            ],
        );
        assert_ne!(
            conn_id_from_request(&embedded),
            conn_id_from_request(&split)
        );

        let embedded_value = request("alice", &[("a", ConfigValue::String("x\nb=S:y".into()))]);
        let split_value = request(
            "alice",
            &[
                ("a", ConfigValue::String("x".into())),
                ("b", ConfigValue::String("y".into())),
            ],
        );
        assert_ne!(
            conn_id_from_request(&embedded_value),
            conn_id_from_request(&split_value)
        );
    }

    #[test]
    fn conn_id_from_request_includes_config_but_excludes_credentials_and_persist() {
        let mut base = request(
            "alice",
            &[("server", ConfigValue::String("nucleus.example".into()))],
        );
        let mut rotated = base.clone();
        rotated.persist = true;
        rotated.credentials.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"rotated".to_vec())),
        );
        assert_eq!(conn_id_from_request(&base), conn_id_from_request(&rotated));

        let mut different_value = base.clone();
        different_value
            .config
            .insert("server".into(), ConfigValue::String("other.example".into()));
        assert_ne!(
            conn_id_from_request(&base),
            conn_id_from_request(&different_value)
        );

        base.config
            .insert("mode".into(), ConfigValue::String("1".into()));
        let mut different_type = base.clone();
        different_type
            .config
            .insert("mode".into(), ConfigValue::Int(1));
        assert_ne!(
            conn_id_from_request(&base),
            conn_id_from_request(&different_type)
        );
    }

    #[test]
    fn conn_id_from_url_uses_canonical_origin_and_path() {
        let id = conn_id_from_url("https://storage.example.com/discovery");
        // Fully-qualified: scheme + host + known-default port + path.
        assert_eq!(id.0, "https://storage.example.com:443/discovery");
    }

    #[test]
    fn conn_id_from_url_distinguishes_port_scheme_and_path() {
        // The whole point of the canonical key: distinct connections that share
        // only a hostname must NOT collide on one stored secret.
        let a = conn_id_from_url("https://host.example.com:8443/tenant-a");
        let b = conn_id_from_url("https://host.example.com:9443/tenant-a");
        let c = conn_id_from_url("https://host.example.com:8443/tenant-b");
        let d = conn_id_from_url("http://host.example.com/tenant-a");
        assert_ne!(a.0, b.0, "different ports must not collide");
        assert_ne!(a.0, c.0, "different paths must not collide");
        assert_ne!(a.0, d.0, "different schemes must not collide");
    }

    #[test]
    fn conn_id_from_url_normalizes_default_port_and_trailing_slash() {
        // https default port and a trailing slash normalize away so the same
        // logical endpoint spelled two ways maps to one key.
        assert_eq!(
            conn_id_from_url("https://h.example.com/d").0,
            conn_id_from_url("https://h.example.com:443/d/").0,
        );
    }

    #[test]
    fn conn_id_from_url_distinguishes_query() {
        // Discovery URLs differing only by query (e.g. a tenant selector) must
        // not collapse onto one key.
        assert_ne!(
            conn_id_from_url("https://h.example.com/d?tenant=a").0,
            conn_id_from_url("https://h.example.com/d?tenant=b").0,
        );
    }

    #[test]
    fn conn_id_from_url_and_client_distinguishes_client() {
        // Same discovery URL, different OIDC client → distinct keys: a
        // shared key would let one client's persist clobber the other's token.
        let a = conn_id_from_url_and_client("https://h.example.com/d", "client-a");
        let b = conn_id_from_url_and_client("https://h.example.com/d", "client-b");
        assert_ne!(a.0, b.0, "different clients must not share a stored secret");
        assert!(a.0.starts_with("https://h.example.com:443/d#"));
        // An empty client name leaves the bare origin key unchanged.
        assert_eq!(
            conn_id_from_url_and_client("https://h.example.com/d", "").0,
            conn_id_from_url("https://h.example.com/d").0,
        );
    }

    #[test]
    fn conn_id_from_url_falls_back_to_raw_when_unparseable() {
        let id = conn_id_from_url("not a url");
        assert_eq!(id.0, "not a url");
    }

    #[test]
    fn oauth_bundle_round_trips_optional_fields() {
        let now = SystemTime::now();
        let bundle = oauth_bundle("AT", Some("RT"), Some(now));
        match bundle.fields.get("oauth").unwrap() {
            SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            } => {
                assert_eq!(token.0, b"AT");
                assert_eq!(refresh.as_ref().unwrap().0, b"RT");
                assert_eq!(*expires_at, Some(now));
            }
            _ => panic!("expected OAuthToken"),
        }
    }

    #[test]
    fn oauth_bundle_omits_refresh_when_none() {
        let bundle = oauth_bundle("AT", None, None);
        match bundle.fields.get("oauth").unwrap() {
            SecretValue::OAuthToken {
                refresh,
                expires_at,
                ..
            } => {
                assert!(refresh.is_none());
                assert!(expires_at.is_none());
            }
            _ => panic!("expected OAuthToken"),
        }
    }
}
