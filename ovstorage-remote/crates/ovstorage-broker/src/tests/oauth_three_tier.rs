// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Three-tier OAuth: broker → upstream OAuth-relay end-to-end.
//!
//! Drives `open_upstream_auth_stream` to `Succeeded`, registers the
//! resolved bearer, simulates revocation, and re-drives the flow.
//!
//! Stops short of a real plugin-nucleus backend; warm-path bearer
//! round-trip is covered by `oauth_provider.rs` unit tests because
//! keyring's mock backend treats each `Entry` as independent state and
//! returns `NoEntry` from a fresh handle.

use super::*;
use futures::StreamExt;
use ovstorage::address;
use ovstorage::auth::flow::test_support::FakeIdp;
use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy, SecretStore};
use ovstorage_broker_protocol::{
    AuthEventPartial, RegisterCredentialPayload, auth_event_from_proto_partial,
};
use std::sync::Arc;

/// Mock keyring once per process; OS keyrings flake under workspace
/// test pressure and the mock has identical put/get/delete semantics.
fn ensure_mock_keyring() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    });
}

/// Per-test substrate so tests don't see each other's tokens.
fn isolated_substrate(state_root: &std::path::Path) -> (Arc<SecretStore>, Arc<AuthRefreshLock>) {
    ensure_mock_keyring();
    let secret_store = Arc::new(SecretStore::new());
    let refresh_lock = Arc::new(AuthRefreshLock::open(state_root).unwrap());
    (secret_store, refresh_lock)
}

struct ThreeTierFixture {
    broker: Broker,
    refresh_lock: Arc<AuthRefreshLock>,
}

/// Broker with a PKCE provider `upstream-idp` bound to `nucleus://prod/`.
async fn fixture(inner_idp: &FakeIdp, state_root: &std::path::Path) -> ThreeTierFixture {
    let (secret_store, refresh_lock) = isolated_substrate(state_root);
    let endpoints = inner_idp.endpoints(false);
    let provider = Arc::new(OAuthCredentialProvider::new(
        "upstream-idp",
        "nucleus",
        endpoints,
        secret_store,
        refresh_lock.clone(),
        OAuthStrategy::Pkce {
            redirect_base: url::Url::parse("http://127.0.0.1").unwrap(),
        },
    ));
    let registry = Arc::new(OAuthProviderRegistry::new().with_provider("upstream-idp", provider));
    let bindings = BrokerOAuthRouteBindings::new()
        .with_route(url::Url::parse("nucleus://prod/").unwrap(), "upstream-idp");

    let library = Library::builder().open_with_test_plugins();
    let broker = Broker::with_authz_plugin(library, Arc::new(AllowAllAuthzPlugin))
        .with_oauth_providers(registry, bindings);
    ThreeTierFixture {
        broker,
        refresh_lock,
    }
}

/// Simulate the host SDK's browser hop: GET the loopback callback with
/// a fake `code` so the PKCE listener exchanges at FakeIdp's `/token`.
async fn simulate_browser_pkce_callback(open_browser_url: &str) {
    let parsed = url::Url::parse(open_browser_url).expect("OpenBrowser URL parses");
    let mut redirect_uri = String::new();
    let mut state = String::new();
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "redirect_uri" => redirect_uri = value.into_owned(),
            "state" => state = value.into_owned(),
            _ => {}
        }
    }
    let redirect_url = format!("{redirect_uri}?code=fake-code&state={state}");
    // Spawned so broker-side `accept_redirect` races ahead.
    tokio::spawn(async move {
        let _ = reqwest::get(&redirect_url).await;
    });
}

#[tokio::test]
async fn three_tier_oauth_flow_drives_inner_idp_and_persists_credential() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("inner-bearer-001").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();

    let fx = fixture(&inner_idp, &state_root).await;
    let address = address::parse("nucleus://prod/objects/file.bin").unwrap();
    let context = default_context();

    let mut stream = fx
        .broker
        .open_upstream_auth_stream(
            &context,
            ovstorage_plugin::InteractiveAuthCapability::Browser,
            address.clone(),
        )
        .await
        .expect("open_upstream_auth_stream");

    let first = stream.next().await.expect("first event").expect("ok");
    let first_partial = auth_event_from_proto_partial(first).unwrap();
    let browser_url = match first_partial {
        AuthEventPartial::OpenBrowser { url, .. } => url,
        other => panic!("expected OpenBrowser, got {other:?}"),
    };

    simulate_browser_pkce_callback(&browser_url).await;

    let mut saw_succeeded = false;
    while let Some(envelope) = stream.next().await {
        let partial = auth_event_from_proto_partial(envelope.unwrap()).unwrap();
        match partial {
            AuthEventPartial::Succeeded { .. } => {
                saw_succeeded = true;
                break;
            }
            AuthEventPartial::Failed { error } => {
                panic!("inner flow failed: {}", error.message())
            }
            _ => {}
        }
    }
    assert!(saw_succeeded, "inner flow must reach Succeeded");

    fx.broker
        .register_upstream_credential(
            &context,
            address.clone(),
            RegisterCredentialPayload {
                access_token: b"inner-bearer-001".to_vec(),
                refresh_token: Some(b"inner-refresh-001".to_vec()),
                expires_at: Some(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                ),
            },
        )
        .await
        .expect("register_upstream_credential");

    // Durable `secret_tokens` row is the persistence artifact under
    // test; warm-path read-back is covered separately.
    let row = fx
        .refresh_lock
        .load_secret_token("nucleus", &context.principal.id)
        .expect("load_secret_token")
        .expect("row present after register_upstream_credential");
    assert_eq!(row.source_name, "upstream-idp");
    assert_eq!(row.keyring_handle, "oauth/upstream-idp");
    assert!(row.expires_at_unix_ms.is_some(), "expires_at must persist");
    assert!(row.cred_epoch >= 1, "cred_epoch must increment");
}

#[tokio::test]
async fn three_tier_unconfigured_route_emits_auth_required() {
    // Empty registry/bindings: single Failed{AuthRequired} event and
    // close, matching the legacy stub so SDKs distinguish "no upstream
    // OAuth here" from transport errors.
    ensure_test_plugin_env();
    let library = Library::builder().open_with_test_plugins();
    let broker = Broker::with_authz_plugin(library, Arc::new(AllowAllAuthzPlugin));

    let address = address::parse("nucleus://prod/objects/file.bin").unwrap();
    let context = default_context();
    let mut stream = broker
        .open_upstream_auth_stream(
            &context,
            ovstorage_plugin::InteractiveAuthCapability::Browser,
            address.clone(),
        )
        .await
        .unwrap();
    let envelope = stream.next().await.expect("one event").unwrap();
    let partial = auth_event_from_proto_partial(envelope).unwrap();
    match partial {
        AuthEventPartial::Failed { error } => {
            assert_eq!(error.code(), ErrorCode::AuthRequired);
        }
        other => panic!("expected Failed{{AuthRequired}}, got {other:?}"),
    }
    assert!(stream.next().await.is_none(), "stream must close");

    let err = broker
        .register_upstream_credential(
            &context,
            address,
            RegisterCredentialPayload {
                access_token: b"x".to_vec(),
                refresh_token: None,
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn three_tier_missing_provider_emits_credential_unavailable() {
    // Unknown provider name → CredentialUnavailable so the SDK can
    // distinguish "retry later" from "no auth here".
    ensure_test_plugin_env();
    let library = Library::builder().open_with_test_plugins();
    let registry = Arc::new(OAuthProviderRegistry::new());
    let bindings = BrokerOAuthRouteBindings::new().with_route(
        url::Url::parse("nucleus://prod/").unwrap(),
        "ghost-provider",
    );
    let broker = Broker::with_authz_plugin(library, Arc::new(AllowAllAuthzPlugin))
        .with_oauth_providers(registry, bindings);

    let address = address::parse("nucleus://prod/objects/file.bin").unwrap();
    let context = default_context();
    let mut stream = broker
        .open_upstream_auth_stream(
            &context,
            ovstorage_plugin::InteractiveAuthCapability::Browser,
            address.clone(),
        )
        .await
        .unwrap();
    let envelope = stream.next().await.expect("one event").unwrap();
    let partial = auth_event_from_proto_partial(envelope).unwrap();
    match partial {
        AuthEventPartial::Failed { error } => {
            assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
            assert!(error.message().contains("ghost-provider"));
        }
        other => panic!("expected Failed{{CredentialUnavailable}}, got {other:?}"),
    }
}

#[tokio::test]
async fn three_tier_inner_revocation_redrives_flow_on_next_request() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("inner-bearer-002").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let fx = fixture(&inner_idp, &state_root).await;
    let address = address::parse("nucleus://prod/objects/file.bin").unwrap();
    let context = default_context();

    let mut stream = fx
        .broker
        .open_upstream_auth_stream(
            &context,
            ovstorage_plugin::InteractiveAuthCapability::Browser,
            address.clone(),
        )
        .await
        .unwrap();
    let first = auth_event_from_proto_partial(stream.next().await.unwrap().unwrap()).unwrap();
    let browser_url = match first {
        AuthEventPartial::OpenBrowser { url, .. } => url,
        other => panic!("expected OpenBrowser, got {other:?}"),
    };
    simulate_browser_pkce_callback(&browser_url).await;
    while let Some(env) = stream.next().await {
        if matches!(
            auth_event_from_proto_partial(env.unwrap()).unwrap(),
            AuthEventPartial::Succeeded { .. }
        ) {
            break;
        }
    }
    fx.broker
        .register_upstream_credential(
            &context,
            address.clone(),
            RegisterCredentialPayload {
                access_token: b"inner-bearer-002".to_vec(),
                refresh_token: None,
                expires_at: Some(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                ),
            },
        )
        .await
        .unwrap();
    drop(stream);

    let row = fx
        .refresh_lock
        .load_secret_token("nucleus", &context.principal.id)
        .unwrap()
        .expect("first hop persisted row");
    let first_epoch = row.cred_epoch;

    // Simulate inner-hop revocation: drop the secret_tokens row.
    fx.refresh_lock
        .delete_secret_token("nucleus", &context.principal.id)
        .unwrap();
    assert!(
        fx.refresh_lock
            .load_secret_token("nucleus", &context.principal.id)
            .unwrap()
            .is_none(),
        "row must be gone after delete"
    );

    let mut stream = fx
        .broker
        .open_upstream_auth_stream(
            &context,
            ovstorage_plugin::InteractiveAuthCapability::Browser,
            address.clone(),
        )
        .await
        .unwrap();
    let first = stream.next().await.expect("first event").unwrap();
    let partial = auth_event_from_proto_partial(first).unwrap();
    let browser_url = match partial {
        AuthEventPartial::OpenBrowser { url, .. } => url,
        other => panic!("expected fresh OpenBrowser after revocation, got {other:?}"),
    };
    simulate_browser_pkce_callback(&browser_url).await;
    while let Some(env) = stream.next().await {
        if matches!(
            auth_event_from_proto_partial(env.unwrap()).unwrap(),
            AuthEventPartial::Succeeded { .. }
        ) {
            break;
        }
    }
    drop(stream);
    fx.broker
        .register_upstream_credential(
            &context,
            address.clone(),
            RegisterCredentialPayload {
                access_token: b"inner-bearer-002-rotated".to_vec(),
                refresh_token: None,
                expires_at: Some(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                ),
            },
        )
        .await
        .unwrap();

    // After delete the table is empty so next_epoch restarts at 1
    // (== first_epoch); the durable table records current epoch per
    // slot. CredentialCache's in-memory generation counter is what
    // grows monotonically across the process. Just assert the row
    // reappeared.
    let new_row = fx
        .refresh_lock
        .load_secret_token("nucleus", &context.principal.id)
        .unwrap()
        .expect("post-revocation row");
    assert_eq!(new_row.source_name, "upstream-idp");
    assert_eq!(new_row.keyring_handle, "oauth/upstream-idp");
    let _ = first_epoch;
}
