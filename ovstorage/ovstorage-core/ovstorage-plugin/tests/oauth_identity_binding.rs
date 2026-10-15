// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable behaviour of identity-bound OAuth persistence, driven against a stub
//! host secrets: account separation, warm-continuation verification, rotation,
//! sibling isolation, and the upgrade path for entries written before bindings
//! existed.
//!
//! The registered host is a process singleton and the tests run concurrently
//! against one secrets map, so every test works on connection keys of its own.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ovstorage_plugin::oauth_secret_store::{
    BindingCell, IdentityBinding, PersistenceClaim, conn_id_from_url_and_account,
    conn_id_from_url_and_client, delete_bound_refresh_token, delete_claimed_refresh_token,
    read_claimed_refresh_token, validate_persistence_id, write_claimed_refresh_token,
};
use ovstorage_plugin::{ConnectionId, ErrorCode, SecretBytes, ffi};

const PLUGIN: &str = "test-plugin";
const KIND: &str = "test-backend";
const DISCOVERY: &str = "https://storage.example.com/discovery";

// ---------------------------------------------------------------------
// Stub host secret store
// ---------------------------------------------------------------------

type Key = (String, String, String);

/// Runs inside the stub host's delete, so a test can act at that instant.
type DeleteHook = Box<dyn FnMut(&Key) + Send>;

struct StubHost {
    secrets: Mutex<HashMap<Key, SecretBytes>>,
    /// Runs inside `secret_delete`, so a test can make a sibling connection
    /// claim the key at the one instant that is otherwise unreachable: after
    /// the gate's pre-check and before the entry is actually gone.
    during_delete: Mutex<Option<DeleteHook>>,
}

static HOST: OnceLock<&'static StubHost> = OnceLock::new();

fn registered_host() -> &'static StubHost {
    HOST.get_or_init(|| {
        let host = Box::leak(Box::new(StubHost {
            secrets: Mutex::new(HashMap::new()),
            during_delete: Mutex::new(None),
        }));
        let callbacks = Box::leak(Box::new(ffi::HostCallbacks {
            struct_size: std::mem::size_of::<ffi::HostCallbacks>(),
            host_state: std::ptr::from_ref(host) as *mut core::ffi::c_void,
            secret_get,
            secret_put,
            secret_delete,
            auth_refresh_lock_with_refresh,
            host_kind: ffi::HostKindV1::Library as u32,
            log,
        }));
        // SAFETY: both the callback table and its state are leaked for the
        // lifetime of this test process.
        unsafe { ovstorage_plugin::marshal::register_host(callbacks) };
        host
    })
}

unsafe fn key_from_ffi(key: *const ffi::SecretKey) -> Key {
    unsafe {
        let key = &*key;
        let read = |value: &ffi::Str| {
            std::str::from_utf8(std::slice::from_raw_parts(
                value.ptr as *const u8,
                value.len,
            ))
            .unwrap()
            .to_owned()
        };
        (
            read(&key.backend_kind),
            read(&key.connection_id.id),
            read(&key.field),
        )
    }
}

unsafe extern "C" fn secret_get(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    out_value: *mut ffi::Optional<ffi::SecretBytes>,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        let value = host
            .secrets
            .lock()
            .unwrap()
            .get(&key_from_ffi(key))
            .cloned();
        std::ptr::write(
            out_value,
            value.map_or_else(ffi::Optional::none, |secret| {
                ffi::Optional::some(ovstorage_plugin::marshal::descriptor::secret_bytes_to_ffi(
                    secret,
                ))
            }),
        );
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn secret_put(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    value: *const ffi::SecretBytes,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        let bytes = std::slice::from_raw_parts((*value).bytes.ptr, (*value).bytes.len).to_vec();
        host.secrets
            .lock()
            .unwrap()
            .insert(key_from_ffi(key), SecretBytes(bytes));
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn secret_delete(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
) -> *mut ffi::Error {
    unsafe {
        let host = &*(state as *const StubHost);
        let key = key_from_ffi(key);
        if let Some(hook) = host.during_delete.lock().unwrap().as_mut() {
            hook(&key);
        }
        host.secrets.lock().unwrap().remove(&key);
        std::ptr::null_mut()
    }
}

unsafe extern "C" fn auth_refresh_lock_with_refresh(
    _state: *mut core::ffi::c_void,
    _backend_kind: *const ffi::Str,
    _connection_id: *const ffi::ConnectionId,
    _freshness_window_ms: u64,
    refresh_state: *mut core::ffi::c_void,
    refresh_fn: ffi::HostRefreshFn,
) -> *mut ffi::Error {
    unsafe { refresh_fn(refresh_state) }
}

unsafe extern "C" fn log(
    _state: *mut core::ffi::c_void,
    _level: u8,
    _target: *const ffi::Str,
    _message: *const ffi::Str,
) {
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// A JWT-shaped access token carrying the standard identity claims.
fn access_token(issuer: &str, client: &str, subject: &str) -> String {
    let payload = format!(r#"{{"iss":"{issuer}","azp":"{client}","sub":"{subject}"}}"#);
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"signature"),
    )
}

fn binding_of(access: &str) -> IdentityBinding {
    ovstorage_plugin::oauth_secret_store::identity_from_access_token(access, "cli")
}

/// A connection key, taken after ensuring the stub host is registered — the
/// secret-store helpers are no-ops without a host, so every test that touches the
/// store goes through this.
fn conn(id: &str) -> ConnectionId {
    registered_host();
    ConnectionId(id.into())
}

/// A durable key scoped by discriminator, with the stub host registered.
fn account_key(persistence_id: &str) -> ConnectionId {
    registered_host();
    conn_id_from_url_and_account(DISCOVERY, "cli", persistence_id)
}

/// Plant a refresh token with NO binding record, as a build predating identity
/// binding left it. Written straight into the stub secrets: there is no
/// supported write path that produces this shape, which is the point of the
/// migration tests.
fn plant_unbound_refresh_token(conn: &ConnectionId, token: &str) {
    registered_host().secrets.lock().unwrap().insert(
        (
            KIND.to_string(),
            conn.0.clone(),
            "refresh_token".to_string(),
        ),
        SecretBytes(token.as_bytes().to_vec()),
    );
}

/// The raw stored refresh token, for asserting a migration left it in place.
fn stored_refresh_token(conn: &ConnectionId) -> Option<String> {
    field(conn, "refresh_token").map(|bytes| String::from_utf8(bytes).unwrap())
}

/// A claim held only for the call it guards. Every persistence call a driver
/// makes presents one, so the tests exercise the same gated path rather than
/// the primitives beneath it.
fn sole_claim(conn: &ConnectionId) -> PersistenceClaim {
    PersistenceClaim::acquire(KIND, conn)
}

fn field(conn: &ConnectionId, name: &str) -> Option<Vec<u8>> {
    registered_host()
        .secrets
        .lock()
        .unwrap()
        .get(&(KIND.to_string(), conn.0.clone(), name.to_string()))
        .map(|secret| secret.0.clone())
}

// ---------------------------------------------------------------------
// Same-endpoint connections cannot silently share a persisted token
// ---------------------------------------------------------------------

#[test]
fn a_durable_account_discriminator_separates_same_endpoint_connections() {
    // Same endpoint, same OIDC client, different `persistence_id`: distinct
    // durable keys, so neither connection can reach the other's lineage.
    let alice = conn_id_from_url_and_account(DISCOVERY, "cli", "alice-work");
    let bob = conn_id_from_url_and_account(DISCOVERY, "cli", "bob-work");
    assert_ne!(alice, bob);

    // The discriminator is framed, so it cannot be forged from a client name.
    assert_ne!(
        conn_id_from_url_and_account(DISCOVERY, "cli@bob-work", ""),
        bob,
    );

    // An absent discriminator leaves the client-scoped key untouched, which is
    // what keeps configurations that never set one on their existing key.
    assert_eq!(
        conn_id_from_url_and_account(DISCOVERY, "cli", ""),
        conn_id_from_url_and_client(DISCOVERY, "cli"),
    );
}

#[test]
fn a_shared_key_refuses_the_second_account_rather_than_lending_it_the_lineage() {
    let conn = conn("shared-key-refusal");

    // Alice signs in and binds the lineage.
    let alice_token = access_token("https://idp.example", "cli", "alice");
    let alice_cell = BindingCell::new();
    alice_cell
        .observe_access_token(&alice_token, "cli")
        .unwrap();
    write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &sole_claim(&conn),
        "alice-rt",
        &alice_cell.current().unwrap(),
    )
    .unwrap();

    // Bob's connection is configured identically and lands on the same key. He
    // reads the entry, but the session his warm continuation authenticates as
    // is not the one the lineage is bound to, so it is refused.
    let bob_cell = BindingCell::new();
    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    bob_cell.expect(stored.binding);
    let bob_token = access_token("https://idp.example", "cli", "bob");
    let err = bob_cell
        .observe_access_token(&bob_token, "cli")
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);

    // Alice's own warm continuation over the same entry is admitted.
    let resumed = BindingCell::new();
    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    assert_eq!(stored.refresh_token, "alice-rt");
    resumed.expect(stored.binding);
    resumed.observe_access_token(&alice_token, "cli").unwrap();
}

#[test]
fn two_live_connections_on_one_key_refuse_until_one_is_configured() {
    let key = conn_id_from_url_and_account(DISCOVERY, "cli", "");
    let alice = PersistenceClaim::acquire(KIND, &key);
    assert!(alice.is_exclusive());

    // A second identically-configured connection makes the key ambiguous for
    // both: neither may adopt or rotate the shared lineage.
    let bob = PersistenceClaim::acquire(KIND, &key);
    assert!(!alice.is_exclusive());
    assert!(!bob.is_exclusive());
    assert_eq!(bob.ambiguity_error().code(), ErrorCode::AuthRequired);

    // Moving Bob to his own key does not retroactively make Alice's claim
    // exclusive: it lived through the contention, and nothing after the fact
    // shows which connection the stored lineage belonged to while both were
    // live.
    drop(bob);
    let bob =
        PersistenceClaim::acquire(KIND, &conn_id_from_url_and_account(DISCOVERY, "cli", "bob"));
    assert!(bob.is_exclusive());
    assert!(!alice.is_exclusive());

    // Reconnecting Alice — the other half of the operator's fix — does.
    drop(alice);
    let alice = PersistenceClaim::acquire(KIND, &key);
    assert!(alice.is_exclusive());
}

#[test]
fn a_discriminator_with_stray_whitespace_is_rejected_not_normalized() {
    // Trimming would map `"alice"` and `"alice "` onto one key, merging two
    // connections the operator wrote as different — across processes, where no
    // claim detection exists to catch it. The error is raised while the
    // operator can still say which they meant.
    assert!(validate_persistence_id("alice").is_ok());
    assert!(validate_persistence_id("").is_ok(), "unset is valid");
    assert!(
        validate_persistence_id("alice bob").is_ok(),
        "interior is fine"
    );
    for bad in ["alice ", " alice", "\talice", "alice\n", " "] {
        let err = validate_persistence_id(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}

#[test]
fn one_trailing_slash_is_cosmetic_but_two_are_a_different_path() {
    assert_eq!(
        conn_id_from_url_and_client("https://h.example/tenant", "cli"),
        conn_id_from_url_and_client("https://h.example/tenant/", "cli"),
    );
    assert_ne!(
        conn_id_from_url_and_client("https://h.example/tenant", "cli"),
        conn_id_from_url_and_client("https://h.example/tenant//", "cli"),
    );
}

#[test]
fn an_interactive_sign_in_does_not_write_to_a_key_a_sibling_also_claims() {
    // The real sequence, driven end to end through the claim-gated storage the
    // drivers use: Alice signs in on a shared key while Bob's identically
    // configured connection is live, then Bob warm-continues.
    let key = conn("shared-key-interactive");
    let alice_claim = PersistenceClaim::acquire(KIND, &key);
    let bob_claim = PersistenceClaim::acquire(KIND, &key);

    let alice_token = access_token("https://idp.example", "cli", "alice");
    let alice_cell = BindingCell::new();
    alice_cell
        .observe_access_token(&alice_token, "cli")
        .unwrap();
    let refused = write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &alice_claim,
        "alice-rt",
        &alice_cell.current().unwrap(),
    );
    assert_eq!(
        refused.unwrap_err().code(),
        ErrorCode::CredentialUnavailable,
        "the refusal is reported, not passed off as a persist",
    );

    // Alice's sign-in wrote nothing: the entry it would have created is exactly
    // the one Bob's next warm continuation would adopt as his own.
    assert!(field(&key, "refresh_token").is_none());
    assert!(field(&key, "identity_binding").is_none());

    // So Bob has nothing to adopt and signs in interactively, which is the
    // outcome — not Alice's lineage.
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &bob_claim)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_sibling_arriving_mid_delete_is_reported_rather_than_passed_off_as_clean() {
    // The delete-side check-then-act window, driven for real: the sibling claim
    // is taken from inside the secret store delete itself, after the gate's
    // pre-check has passed. The entry is gone by then and cannot be restored,
    // so the only honest outcome is to say so — reporting a clean rotation
    // would leave the connection believing the durable state is its own.
    let key = conn("shared-key-mid-delete");
    let claim = PersistenceClaim::acquire(KIND, &key);
    let cell = BindingCell::new();
    cell.observe_access_token(&access_token("https://idp.example", "cli", "alice"), "cli")
        .unwrap();
    write_claimed_refresh_token(PLUGIN, KIND, &claim, "alice-rt", &cell.current().unwrap())
        .unwrap();

    let sibling_key = key;
    let mut sibling: Option<PersistenceClaim> = None;
    *registered_host().during_delete.lock().unwrap() = Some(Box::new(move |seen: &Key| {
        if seen.1 == sibling_key.0 && sibling.is_none() {
            sibling = Some(PersistenceClaim::acquire(KIND, &sibling_key));
        }
    }));

    let err = delete_claimed_refresh_token(PLUGIN, KIND, &claim)
        .expect_err("a sibling that arrived mid-delete is reported");
    assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
    *registered_host().during_delete.lock().unwrap() = None;

    // And the claim stays ambiguous afterwards, so nothing it does next adopts
    // or rewrites the key.
    assert!(!claim.is_exclusive());
}

#[test]
fn a_lineage_is_not_adopted_by_a_claim_a_sibling_overlapped() {
    // A credential written while the key was unambiguous, then a sibling
    // connection appears. The adopting read refuses even though the stored
    // record is perfectly valid: with two live claimants nothing says which of
    // them it describes, and a warm continuation on it would authenticate as
    // its owner and so verify by construction.
    let key = conn("shared-key-late-sibling");
    let claim = PersistenceClaim::acquire(KIND, &key);
    let cell = BindingCell::new();
    cell.observe_access_token(&access_token("https://idp.example", "cli", "alice"), "cli")
        .unwrap();
    write_claimed_refresh_token(PLUGIN, KIND, &claim, "alice-rt", &cell.current().unwrap())
        .unwrap();
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &claim)
            .unwrap()
            .is_some(),
        "sole claimant adopts its own lineage",
    );

    let _sibling = PersistenceClaim::acquire(KIND, &key);
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &claim)
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------
// Warm continuation verifies the stored binding
// ---------------------------------------------------------------------

#[test]
fn warm_continuation_adopts_only_a_session_matching_the_stored_binding() {
    let conn = conn("warm-continuation");

    let token = access_token("https://idp.example", "cli", "alice");
    write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &sole_claim(&conn),
        "rt-0",
        &binding_of(&token),
    )
    .unwrap();

    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    assert_eq!(stored.refresh_token, "rt-0");
    assert_eq!(stored.binding.subject, "alice");

    let cell = BindingCell::new();
    cell.expect(stored.binding);
    // A token from another issuer for the same principal is still a different
    // identity and is refused.
    assert!(
        cell.observe_access_token(&access_token("https://evil.example", "cli", "alice"), "cli")
            .is_err()
    );
    cell.observe_access_token(&token, "cli").unwrap();
}

// ---------------------------------------------------------------------
// Rotation and removal
// ---------------------------------------------------------------------

#[test]
fn rotation_preserves_the_binding() {
    let conn = conn("rotation-preserves-binding");

    let token = access_token("https://idp.example", "cli", "alice");
    let cell = BindingCell::new();
    cell.observe_access_token(&token, "cli").unwrap();
    let first = cell.current().unwrap();
    write_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn), "rt-0", &first).unwrap();

    // Several rotations later the record still names the same account, and the
    // stored token is the newest one.
    for generation in 1..4 {
        cell.observe_access_token(&token, "cli").unwrap();
        write_claimed_refresh_token(
            PLUGIN,
            KIND,
            &sole_claim(&conn),
            &format!("rt-{generation}"),
            &cell.current().unwrap(),
        )
        .unwrap();
    }
    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    assert_eq!(stored.refresh_token, "rt-3");
    assert_eq!(stored.binding, first);
}

#[test]
fn removal_reaches_one_lineage_and_leaves_the_sibling_whole() {
    let alice = account_key("alice-removal");
    let bob = account_key("bob-removal");
    let alice_binding = binding_of(&access_token("https://idp.example", "cli", "alice"));
    let bob_binding = binding_of(&access_token("https://idp.example", "cli", "bob"));
    write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &sole_claim(&alice),
        "alice-rt",
        &alice_binding,
    )
    .unwrap();
    write_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&bob), "bob-rt", &bob_binding).unwrap();

    delete_bound_refresh_token(PLUGIN, KIND, &alice).unwrap();

    // Both fields of the removed entry are gone — an orphaned binding would
    // outlive the secret it describes.
    assert!(field(&alice, "refresh_token").is_none());
    assert!(field(&alice, "identity_binding").is_none());
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&alice))
            .unwrap()
            .is_none()
    );

    let sibling = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&bob))
        .unwrap()
        .unwrap();
    assert_eq!(sibling.refresh_token, "bob-rt");
    assert_eq!(sibling.binding, bob_binding);
}

// ---------------------------------------------------------------------
// Migration of entries written before bindings existed
// ---------------------------------------------------------------------

#[test]
fn an_unbound_legacy_entry_is_refused_and_left_intact_for_rebinding() {
    let conn = conn("legacy-unbound");

    // An entry as a prior build wrote it: a refresh token and no binding.
    plant_unbound_refresh_token(&conn, "legacy-rt");
    assert!(field(&conn, "identity_binding").is_none());

    // It cannot be shown to belong to this connection's account, so warm
    // continuation does not adopt it and the connection signs in interactively.
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
            .unwrap()
            .is_none()
    );

    // The secret is not destroyed in the process: the decision is reversible,
    // and a build without bindings still finds its entry.
    assert_eq!(stored_refresh_token(&conn).as_deref(), Some("legacy-rt"),);

    // The interactive sign-in rebinds the entry in place, and the next warm
    // continuation adopts it.
    let token = access_token("https://idp.example", "cli", "alice");
    write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &sole_claim(&conn),
        "bound-rt",
        &binding_of(&token),
    )
    .unwrap();
    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    assert_eq!(stored.refresh_token, "bound-rt");
    assert_eq!(stored.binding.subject, "alice");
}

#[test]
fn a_corrupt_or_future_binding_record_is_refused_like_an_unbound_entry() {
    let conn = conn("legacy-corrupt");

    plant_unbound_refresh_token(&conn, "rt");
    registered_host().secrets.lock().unwrap().insert(
        (
            KIND.to_string(),
            conn.0.clone(),
            "identity_binding".to_string(),
        ),
        SecretBytes(b"ovstorage-oauth-binding-v99\nunknown".to_vec()),
    );

    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_record_that_names_nobody_is_never_written() {
    let conn = conn("wildcard-write");

    // A record with every field empty constrains nothing, so it is not a
    // binding. Persisting the token beside it would leave an entry any
    // connection deriving this key could adopt — the exact sharing the binding
    // exists to close — so neither is written.
    let refused = write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &sole_claim(&conn),
        "rt",
        &IdentityBinding::default(),
    );
    assert_eq!(
        refused.unwrap_err().code(),
        ErrorCode::CredentialUnavailable,
        "the refusal is reported, not passed off as a persist",
    );

    assert!(field(&conn, "refresh_token").is_none());
    assert!(field(&conn, "identity_binding").is_none());
}

#[test]
fn a_record_that_names_nobody_is_never_adopted() {
    let conn = conn("wildcard-read");

    // The shape a pre-fix build could leave behind: a real token beside a
    // record that verifies against every identity. Adoption is refused like any
    // other unattributable entry, so a sibling on this key cannot claim it.
    plant_unbound_refresh_token(&conn, "rt");
    registered_host().secrets.lock().unwrap().insert(
        (
            KIND.to_string(),
            conn.0.clone(),
            "identity_binding".to_string(),
        ),
        SecretBytes(IdentityBinding::default().encode()),
    );
    // The record decodes — this is not the undecodable path.
    assert!(IdentityBinding::decode(&field(&conn, "identity_binding").unwrap()).is_some());

    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
            .unwrap()
            .is_none()
    );
}

#[test]
fn the_endpoint_component_cannot_forge_a_discriminator() {
    // A separator surviving in the URL's path must not let one connection
    // derive another's key: `…/a@b` with no discriminator is not `…/a` with
    // discriminator `b`.
    assert_ne!(
        conn_id_from_url_and_account("https://h.example/a@b", "", ""),
        conn_id_from_url_and_account("https://h.example/a", "", "b"),
    );
    // Same for the unparseable-URL fallback, which passes the string verbatim.
    assert_ne!(
        conn_id_from_url_and_account("h.example/a@b", "", ""),
        conn_id_from_url_and_account("h.example/a", "", "b"),
    );
    // And for the client separator.
    assert_ne!(
        conn_id_from_url_and_account("https://h.example/a#c", "", ""),
        conn_id_from_url_and_account("https://h.example/a", "c", ""),
    );
}

#[test]
fn an_opaque_token_deployment_binds_on_the_client_it_can_observe() {
    let conn = conn("opaque-token");

    // The provider issues a token with no inspectable claims: the record names
    // only the configured client, so issuer and subject impose no constraint
    // and `persistence_id` carries account separation for this deployment.
    let cell = BindingCell::new();
    cell.observe_access_token("opaque-access-token", "cli")
        .unwrap();
    let binding = cell.current().unwrap();
    assert_eq!(binding.client_id, "cli");
    assert!(binding.subject.is_empty());
    write_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn), "rt", &binding).unwrap();

    // The entry is bound — it is adoptable, unlike an entry with no record.
    let stored = read_claimed_refresh_token(PLUGIN, KIND, &sole_claim(&conn))
        .unwrap()
        .unwrap();
    let resumed = BindingCell::new();
    resumed.expect(stored.binding);
    resumed
        .observe_access_token("another-opaque-token", "cli")
        .unwrap();

    // A different OIDC client is still a different lineage and is refused.
    let other = BindingCell::new();
    other.expect(binding);
    assert!(
        other
            .observe_access_token("another-opaque-token", "other-cli")
            .is_err()
    );
}

// ---------------------------------------------------------------------
// A refusal is not a success
// ---------------------------------------------------------------------

#[test]
fn a_refused_write_is_not_reported_as_a_persist() {
    // The debt policy retires a connection's persistence debt on `Ok`. A
    // refusal that reports `Ok` therefore tells the lifecycle the rotated
    // successor is durable when the secret store still holds its consumed
    // predecessor — and the next process start replays that predecessor into
    // the provider's reuse detection, which can revoke the whole lineage.
    // Refusing to write and reporting success are different outcomes and must
    // not share a return value.
    let key = conn("refusal-is-not-success");
    let claim = sole_claim(&key);
    let sibling = PersistenceClaim::acquire(KIND, &key);
    assert!(!claim.is_exclusive(), "the key is ambiguous");

    let err = write_claimed_refresh_token(
        PLUGIN,
        KIND,
        &claim,
        "rt-1",
        &binding_of(&access_token("https://idp.example", "cli", "alice")),
    )
    .expect_err("a refusal is reported, not swallowed");
    assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
    // And the refusal is real: nothing was written.
    assert!(field(&key, "refresh_token").is_none());
    drop(sibling);
}

#[test]
fn a_write_refused_for_naming_nobody_is_not_reported_as_a_persist() {
    // Same shape, the other refusal: the session named no account, so no
    // adoptable record can be written. Reporting success would retire the debt
    // just the same.
    let key = conn("nameless-is-not-success");
    let claim = sole_claim(&key);
    let err =
        write_claimed_refresh_token(PLUGIN, KIND, &claim, "rt-1", &IdentityBinding::default())
            .expect_err("a refusal is reported, not swallowed");
    assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
    assert!(field(&key, "refresh_token").is_none());
}

#[test]
fn a_refused_delete_is_not_reported_as_a_persist() {
    let key = conn("delete-refusal-is-not-success");
    let claim = sole_claim(&key);
    let sibling = PersistenceClaim::acquire(KIND, &key);
    let err = delete_claimed_refresh_token(PLUGIN, KIND, &claim)
        .expect_err("a refusal is reported, not swallowed");
    assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
    drop(sibling);
}

#[test]
fn a_sibling_restored_later_invalidates_a_connection_that_already_adopted() {
    // Sequential startup, which is how a host restores saved connections. Two
    // same-endpoint connections with no `persistence_id` derive one key K.
    // The first is added alone, so it IS the sole claimant at the moment it
    // loads — the exclusivity checks have nothing to catch — and it adopts the
    // stored lineage and begins serving on it. The second is added afterwards.
    //
    // The pre/post checks stop overlapping keyring operations; they cannot
    // retract an adoption that already completed. So the adopter must be
    // invalidated when the sibling appears, or it goes on serving as an
    // account nothing can show is its own.
    let key = conn("sequential-startup");
    let planted = PersistenceClaim::acquire(KIND, &key);
    let cell = BindingCell::new();
    cell.observe_access_token(&access_token("https://idp.example", "cli", "alice"), "cli")
        .unwrap();
    write_claimed_refresh_token(PLUGIN, KIND, &planted, "alice-rt", &cell.current().unwrap())
        .unwrap();
    drop(planted);

    // First connection restored: sole claimant, adopts alice's lineage.
    let first = PersistenceClaim::acquire(KIND, &key);
    assert!(
        read_claimed_refresh_token(PLUGIN, KIND, &first)
            .unwrap()
            .is_some(),
        "the sole claimant adopts",
    );
    assert!(first.ensure_usable().is_ok(), "and may serve on it");

    // Second connection restored onto the same key.
    let second = PersistenceClaim::acquire(KIND, &key);

    let err = first
        .ensure_usable()
        .expect_err("the adoption is retracted when the sibling appears");
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    // The newcomer never adopted anything, so it has nothing to retract; it
    // simply signs in.
    assert!(second.ensure_usable().is_ok());
}

#[test]
fn a_claim_that_never_adopted_is_not_invalidated_by_contention() {
    // Contention alone refuses reads and writes; it must not also park a
    // connection that took nothing from the durable store.
    let key = conn("contended-without-adoption");
    let first = PersistenceClaim::acquire(KIND, &key);
    let _second = PersistenceClaim::acquire(KIND, &key);
    assert!(!first.is_exclusive());
    assert!(first.ensure_usable().is_ok());
}
