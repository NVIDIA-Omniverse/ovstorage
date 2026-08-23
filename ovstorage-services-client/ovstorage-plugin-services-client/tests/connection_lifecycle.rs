// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end connection-lifecycle tests (RFC-0066).
//!
//! These drive the REAL auth paths — not synthetic errors:
//!
//! - an in-process tonic `CapabilitiesService` over a duplex channel provides
//!   the auth-gated `list_top_level_addresses` probe and a `list_services` data
//!   op (and records the bearer it actually received), and
//! - a `wiremock` OIDC provider (auth-config → discovery → token endpoint) backs
//!   the OAuth grants.
//!
//! Coverage:
//!
//! - C4 — warm-start (refresh-only bundle) mints a fresh access token during
//!   `validate` rather than sending an empty bearer.
//! - C17 — `validate` against a server that rejects the bearer does NOT report
//!   `Authenticated`.
//! - C3 — a successful interactive (device-code) sign-in installs the token into
//!   the shared `DiscoveryState`.
//! - C2 — a data op that gets `UNAUTHENTICATED` once, then succeeds, drives
//!   exactly one refresh + one retry via `ConnectionSet::with_recovery` through
//!   the real `map_status` chain.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use ovstorage_plugin::connection::{
    ConnectionAuthDriver, ConnectionSet, GrantPolicy, Obtained, ProbeOutcome,
};
use ovstorage_plugin::{
    AuthEvent, Capabilities, Connection, ConnectionAuthState, ConnectionId, ConnectionSource,
    ErrorCode, InteractiveAuthCapability, SecretBundle, SecretBytes, SecretValue, UserMetadata,
    oauth_secret_store,
};
use ovstorage_plugin_services_client::auth::{
    DiscoveryState, PersistRefresh, drive_interactive_login, fetch_auth_config, fetch_oidc_config,
};
use ovstorage_plugin_services_client::convert::map_status;
use ovstorage_plugin_services_client::driver::OmniverseStorageDriver;
use ovstorage_plugin_services_client::transport::OmniverseStorageTransport;
use ovstorage_services_protos::nvidia::omniverse::storage::capabilities::v1alpha as cap;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---- in-process gRPC CapabilitiesService mock -------------------------------

#[derive(Default)]
struct CapState {
    /// When true, `list_top_level_addresses` (the validate probe) rejects with
    /// UNAUTHENTICATED — used by C17.
    reject_top_level: bool,
    /// When true, the FIRST `list_services` call rejects with UNAUTHENTICATED;
    /// subsequent calls succeed — used by C2.
    fail_first_list_services: bool,
    /// When set, `list_top_level_addresses` awaits this before responding —
    /// lets a test hold the validate probe in flight.
    gate_top_level: Option<Arc<tokio::sync::Notify>>,
    top_level_calls: usize,
    list_services_calls: usize,
    /// The `authorization` header seen on the most recent probe call.
    last_top_level_bearer: Option<String>,
}

#[derive(Clone)]
struct FakeCapabilities {
    state: Arc<Mutex<CapState>>,
}

#[tonic::async_trait]
impl cap::capabilities_service_server::CapabilitiesService for FakeCapabilities {
    async fn list_services(
        &self,
        _req: Request<cap::ListServicesRequest>,
    ) -> std::result::Result<Response<cap::ListServicesResponse>, Status> {
        let reject = {
            let mut st = self.state.lock().unwrap();
            st.list_services_calls += 1;
            st.fail_first_list_services && st.list_services_calls == 1
        };
        if reject {
            return Err(Status::unauthenticated("bearer rejected"));
        }
        Ok(Response::new(cap::ListServicesResponse::default()))
    }

    async fn list_top_level_addresses(
        &self,
        req: Request<cap::ListTopLevelAddressesRequest>,
    ) -> std::result::Result<Response<cap::ListTopLevelAddressesResponse>, Status> {
        let (reject, gate) = {
            let mut st = self.state.lock().unwrap();
            st.top_level_calls += 1;
            st.last_top_level_bearer = req
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            (st.reject_top_level, st.gate_top_level.clone())
        };
        if let Some(gate) = gate {
            gate.notified().await;
        }
        if reject {
            return Err(Status::unauthenticated("bearer rejected"));
        }
        Ok(Response::new(cap::ListTopLevelAddressesResponse {
            items: vec![cap::TopLevelAddressEntry {
                top_level_address: "omni://server/root/".into(),
            }],
        }))
    }

    async fn list_routes(
        &self,
        _req: Request<cap::ListRoutesRequest>,
    ) -> std::result::Result<Response<cap::ListRoutesResponse>, Status> {
        Ok(Response::new(cap::ListRoutesResponse::default()))
    }
}

/// Stand up the fake CapabilitiesService over an in-memory duplex stream and
/// return a connected `Channel` plus the shared behavior/state handle.
async fn spawn_capabilities(state: Arc<Mutex<CapState>>) -> Channel {
    let service = FakeCapabilities {
        state: state.clone(),
    };
    let (client, server) = tokio::io::duplex(64 * 1024);
    let mut server_io = Some(server);
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(cap::capabilities_service_server::CapabilitiesServiceServer::new(service))
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(
                server_io.take().unwrap(),
            )))
            .await
            .ok();
    });
    let mut client_io = Some(client);
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let io = client_io.take().expect("connector called twice");
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
        }))
        .await
        .expect("duplex connect");
    // Detach; the server shuts down when its duplex peer closes.
    drop(server_task);
    channel
}

// ---- wiremock OIDC provider -------------------------------------------------

/// Mock the OIDC discovery + token endpoints. Returns `(server, base_url)`; the
/// `base_url` doubles as the driver's discovery URL. The token endpoint always
/// mints `fresh-access` (+ a rotated refresh token).
async fn mock_oidc() -> (MockServer, String) {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/api/v1/auth-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "openid_configuration": format!("{base}/oidc"),
            "clients": { "default": { "client_id": "svc-client", "scope": "openid" } }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/oidc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": base,
            "token_endpoint": format!("{base}/token"),
            "device_authorization_endpoint": format!("{base}/device_authorization"),
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rotated-refresh"
        })))
        .mount(&server)
        .await;

    // Device-code endpoint (RFC 8628): hands out a device code with a 1 s poll
    // interval; the very first token poll then succeeds against `/token`.
    Mock::given(method("POST"))
        .and(path("/device_authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev-code-123",
            "user_code": "WDJB-MJHT",
            "verification_uri": format!("{base}/device"),
            "expires_in": 300,
            "interval": 1
        })))
        .mount(&server)
        .await;

    (server, base)
}

fn build_driver(
    discovery_url: String,
    channel: Channel,
) -> (
    OmniverseStorageDriver,
    OmniverseStorageTransport,
    DiscoveryState,
) {
    let state = DiscoveryState::new("default");
    let transport = OmniverseStorageTransport::with_channel(channel, state.clone());
    let driver = OmniverseStorageDriver::new(
        Some(discovery_url),
        state.clone(),
        transport.clone(),
        reqwest::Client::new(),
        "",
        false,
    )
    .unwrap();
    (driver, transport, state)
}

fn conn(id: &str) -> Connection {
    Connection {
        id: ConnectionId(id.into()),
        backend_kind: "omniverse-storage-service".into(),
        display_name: id.into(),
        source: ConnectionSource::Runtime { persisted: false },
        capabilities: Capabilities::empty(),
        current_addresses: Vec::new(),
        auth_state: ConnectionAuthState::AwaitingAuth {
            reason: ovstorage_plugin::AuthReason::NeverAuthenticated,
            last_attempt: None,
        },
        last_probed: None,
        user_metadata: UserMetadata::new(),
    }
}

async fn count_token_posts(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == "/token")
        .count()
}

/// Count `/token` POSTs whose form body carries a specific `grant_type` — lets a
/// test tell a `client_credentials` grant apart from a `refresh_token` grant
/// (both mint `fresh-access` at this mock endpoint).
async fn count_grant_posts(server: &MockServer, grant_type: &str) -> usize {
    let needle = format!("grant_type={grant_type}");
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == "/token")
        .filter(|r| String::from_utf8_lossy(&r.body).contains(&needle))
        .count()
}

// ---- C4 ---------------------------------------------------------------------

/// C4: a keyring warm-start (refresh-token-only bundle, empty access token)
/// mints a fresh access token during `obtain` (on driver-private staging, never
/// the live cell), `verify`'s auth-gated probe carries that real bearer — never
/// an empty `Bearer ` — and `activate` lands it on the live cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn warm_start_mints_access_token_during_obtain() {
    let (oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // Warm-continue shape: refresh token, but NO access token yet.
    let warm = oauth_secret_store::oauth_bundle("", Some("stored-refresh"), None);
    let obtained = driver
        .obtain(&warm, GrantPolicy::AllowConsuming, None)
        .await
        .expect("obtain ok");

    let Obtained::Bearer {
        credentials: effective,
        ..
    } = obtained
    else {
        panic!("warm-start with a valid refresh token must obtain a bearer, got {obtained:?}");
    };
    // The effective bundle carries a freshly-minted access token — the refresh
    // grant ran on PRIVATE staging, so the live cell is still untouched here.
    match effective.fields.get("oauth") {
        Some(ovstorage_plugin::SecretValue::OAuthToken { token, .. }) => assert_eq!(
            token.0, b"fresh-access",
            "obtain must mint a real access token from the refresh grant"
        ),
        other => panic!("expected an oauth bundle on the effective creds, got {other:?}"),
    }
    assert!(
        disco.access_token().await.is_none(),
        "obtain grants on private staging; the live cell is untouched until activate"
    );

    // verify accepts the bearer, and its auth-gated probe carried that real
    // bearer (not an empty one) over an ephemeral transport.
    driver.verify(&effective, None).await.expect("verify ok");
    let bearer = state_handle.lock().unwrap().last_top_level_bearer.clone();
    assert_eq!(
        bearer.as_deref(),
        Some("Bearer fresh-access"),
        "the auth-gated verify probe must send the minted bearer"
    );

    // activate lands the proven bundle on the live cell (the transport reads it).
    driver
        .activate(&effective, driver.identity_gen())
        .await
        .expect("activate ok");
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("fresh-access"),
        "activate installs the minted bearer on the live cell"
    );
    assert!(
        count_token_posts(&oidc).await >= 1,
        "a token grant happened"
    );
}

// ---- C17 --------------------------------------------------------------------

/// C17 (round-2, 3537943264): even though the OAuth grant succeeds, if the
/// backend rejects the bearer (`list_top_level_addresses` → UNAUTHENTICATED)
/// the connection must NOT authenticate. `obtain` mints a bearer, but `verify`
/// surfaces the ORIGINAL probe error (`Err`) — so `ConnectionSet` reports
/// rejected credentials as a failed grant rather than a false success, and the
/// bring-up path classifies this `Err` and parks the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_probe_rejection_does_not_authenticate() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState {
        reject_top_level: true,
        ..CapState::default()
    }));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, _transport, _disco) = build_driver(discovery_url, channel);

    // A refresh token is present, so the token grant succeeds and a bearer is
    // minted — but the backend rejects it.
    let creds = oauth_secret_store::oauth_bundle("", Some("stored-refresh"), None);
    let obtained = driver
        .obtain(&creds, GrantPolicy::AllowConsuming, None)
        .await
        .expect("the refresh grant mints a bearer");
    let Obtained::Bearer {
        credentials: effective,
        ..
    } = obtained
    else {
        panic!("a valid refresh token must obtain a bearer, got {obtained:?}");
    };

    let err = driver
        .verify(&effective, None)
        .await
        .expect_err("a server-rejected bearer must surface Err from verify");
    assert!(
        matches!(
            err.code(),
            ErrorCode::AuthRequired | ErrorCode::AuthExpired | ErrorCode::PermissionDenied
        ),
        "probe rejection surfaces a credential/authz-class error, got {err:?}"
    );
    assert!(
        state_handle.lock().unwrap().top_level_calls >= 1,
        "verify must actually probe the backend"
    );
}

// ---- C2 ---------------------------------------------------------------------

/// C2: a data op that hits `UNAUTHENTICATED` once (post-auth) then succeeds is
/// recovered by `ConnectionSet::with_recovery` — exactly one refresh + one
/// retry — driving the real gRPC → `map_status` → `classify` → refresh chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_path_unauthenticated_triggers_single_refresh_and_retry() {
    let (oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState {
        fail_first_list_services: true,
        ..CapState::default()
    }));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, transport, _disco) = build_driver(discovery_url, channel);

    let set = Arc::new(ConnectionSet::<OmniverseStorageDriver>::with_defaults());
    let id = ConnectionId("c1".into());
    // Seed with a currently-valid access token (+ refresh), so `add_connection`
    // does NOT refresh at bring-up — the only refresh must be the recovery one.
    let initial = oauth_secret_store::oauth_bundle(
        "initial-access",
        Some("stored-refresh"),
        Some(SystemTime::now() + Duration::from_secs(3600)),
    );
    let auth_state = set
        .add_connection(conn("c1"), Arc::new(driver), initial, None)
        .await
        .expect("add_connection ok");
    assert!(
        matches!(auth_state, ConnectionAuthState::Authenticated { .. }),
        "bring-up authenticates (probe OK), got {auth_state:?}"
    );
    assert_eq!(
        count_token_posts(&oidc).await,
        0,
        "bring-up must not refresh — the initial access token is valid"
    );

    // The data op: `list_services` fails UNAUTHENTICATED the first time, then
    // succeeds. `with_recovery` must refresh once and retry once.
    let transport = transport.clone();
    let result = set
        .with_recovery(&id, || {
            let transport = transport.clone();
            async move {
                let mut client = transport.capabilities_client().await?;
                client
                    .list_services(Request::new(cap::ListServicesRequest {}))
                    .await
                    .map(|r| r.into_inner())
                    .map_err(map_status)
            }
        })
        .await;

    assert!(result.is_ok(), "op ultimately succeeds after recovery");
    assert_eq!(
        state_handle.lock().unwrap().list_services_calls,
        2,
        "exactly one failed attempt + one retry"
    );
    assert_eq!(
        count_token_posts(&oidc).await,
        1,
        "exactly one refresh grant during recovery"
    );
    assert!(
        matches!(
            set.auth_state(&id).unwrap(),
            ConnectionAuthState::Authenticated { .. }
        ),
        "connection stays authenticated after recovery"
    );
}

// ---- C3 ---------------------------------------------------------------------

/// C3: a successful interactive (device-code) sign-in installs the minted token
/// into the shared `DiscoveryState`, so the transport interceptor sends the new
/// bearer on the next RPC (and `wait_for_token` unblocks) — rather than the
/// connection succeeding on paper while every RPC still fails UNAUTHENTICATED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_success_installs_token_into_discovery_state() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // Before sign-in the shared token cell is empty.
    assert!(disco.access_token().await.is_none());

    let stream = driver
        .interactive(conn("c1"), InteractiveAuthCapability::Headless, None)
        .await
        .expect("interactive flow starts");
    // Drain the (sync) event stream to completion on a blocking thread; the last
    // event is `Succeeded`, and our fix installs the token before forwarding it.
    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::Succeeded { .. })),
        "device-code flow must reach Succeeded"
    );

    // C3: the minted access token landed on the shared DiscoveryState.
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("fresh-access"),
        "interactive Succeeded must install the token into DiscoveryState"
    );
    // A caller blocked in `wait_for_token` now unblocks promptly.
    tokio::time::timeout(Duration::from_secs(2), disco.wait_for_token())
        .await
        .expect("wait_for_token unblocks after interactive success");
}

// ---- round-2: DiscoveryState / flow-thread token-lifecycle rework -----------

/// 3537943586 + 3539838239 (reshaped): the concern the old live-cell staging +
/// `restore_access_only_if_current` rollback machinery solved is now gone by
/// construction — `obtain` grants on driver-PRIVATE staging and `verify` probes
/// over an EPHEMERAL transport, so a rejected candidate never touches the live
/// cell in the first place. A concurrent RPC / subsequent op keeps the
/// prior-good bearer with nothing to roll back. (The deleted test also asserted
/// the rotated refresh successor was retained; that is moot now — no rotation
/// ever lands on the live cell pre-`activate`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_candidate_leaves_live_cell_untouched() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // A prior-good bearer is already live on the transport.
    disco
        .install_tokens(
            "prior-good".into(),
            Some("prior-refresh".into()),
            Some(Duration::from_secs(3600)),
        )
        .await;

    // The backend will reject the candidate bearer the grant mints.
    state_handle.lock().unwrap().reject_top_level = true;
    let creds = oauth_secret_store::oauth_bundle("", Some("candidate-refresh"), None);
    // obtain grants on PRIVATE staging; verify probes on an EPHEMERAL transport.
    let obtained = driver
        .obtain(&creds, GrantPolicy::AllowConsuming, None)
        .await
        .expect("the refresh grant mints a bearer");
    let Obtained::Bearer {
        credentials: effective,
        ..
    } = obtained
    else {
        panic!("a valid refresh token must obtain a bearer, got {obtained:?}");
    };
    assert!(
        driver.verify(&effective, None).await.is_err(),
        "the backend rejects the candidate bearer"
    );

    // The live cell was NEVER touched — no candidate was staged onto it, so the
    // prior-good access + refresh remain exactly as they were (no rollback).
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("prior-good"),
        "obtain/verify never stage onto the live cell, so the prior-good bearer stands"
    );
    assert_eq!(
        disco.refresh_token().await.as_deref(),
        Some("prior-refresh"),
        "the live refresh token is untouched — nothing rotated on the live cell"
    );
}

/// 3537944750 / 3539557310 / 3539558503: a superseded (slow / abandoned)
/// interactive flow must NOT overwrite a newer IDENTITY-changing credential
/// update that landed on the shared cell while the user was signing in — and
/// the losing flow forwards `Succeeded { credentials: None }` so the generic
/// lifecycle does not commit/persist the superseded bundle either (entry and
/// keyring stay consistent with the winning update).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn superseded_interactive_flow_does_not_overwrite_newer_update() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // Start the device-code flow (it polls /token only after a 1s interval).
    let stream = driver
        .interactive(conn("c1"), InteractiveAuthCapability::Headless, None)
        .await
        .expect("interactive flow starts");
    // Before the flow's first token poll, a NEWER identity-changing update
    // lands (e.g. another interactive sign-in / an explicit credential update).
    disco
        .replace_tokens(
            "newer-access".into(),
            Some("newer-refresh".into()),
            Some(Duration::from_secs(3600)),
        )
        .await;
    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let succeeded = events
        .iter()
        .find_map(|e| match e {
            AuthEvent::Succeeded { credentials, .. } => Some(credentials.clone()),
            _ => None,
        })
        .expect("device-code flow must reach Succeeded");
    // 3539558503: the losing flow hands NO bundle to the lifecycle, so the
    // adapter cannot commit or persist the superseded tokens.
    assert!(
        succeeded.is_none(),
        "a superseded flow must forward Succeeded without credentials"
    );
    // The superseded flow did NOT clobber the newer update.
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("newer-access"),
        "a superseded interactive flow must not overwrite a newer credential update"
    );
    assert_eq!(
        disco.refresh_token().await.as_deref(),
        Some("newer-refresh")
    );
}

/// 3539557310: a routine SAME-IDENTITY refresh grant (`install_tokens` merge)
/// completing during the minutes-long sign-in must NOT trip the supersession
/// guard — the freshly-minted sign-in tokens still win, end-to-end through the
/// `ConnectionSet` (transport + entry stay consistent).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_identity_refresh_mid_flow_does_not_supersede_sign_in() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // Registered connection with currently-valid creds (no grant at bring-up).
    let set = Arc::new(ConnectionSet::<OmniverseStorageDriver>::with_defaults());
    let id = ConnectionId("c1".into());
    let initial = oauth_secret_store::oauth_bundle(
        "initial-access",
        Some("stored-refresh"),
        Some(SystemTime::now() + Duration::from_secs(3600)),
    );
    set.add_connection(conn("c1"), Arc::new(driver), initial, None)
        .await
        .expect("add_connection ok");

    let stream = set
        .authenticate(&id, InteractiveAuthCapability::Headless, None)
        .await
        .expect("interactive flow starts");
    // A background refresh of the SAME identity lands mid-sign-in (merge-style
    // install, as `drive_refresh_token_grant` performs).
    disco
        .install_tokens(
            "mid-flight-refresh".into(),
            None,
            Some(Duration::from_secs(3600)),
        )
        .await;
    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let succeeded = events
        .iter()
        .find_map(|e| match e {
            AuthEvent::Succeeded { credentials, .. } => Some(credentials.clone()),
            _ => None,
        })
        .expect("flow reaches Succeeded");
    assert!(
        succeeded.is_none(),
        "ConnectionSet consumes the internal persistence bundle before forwarding success"
    );
    // The sign-in tokens won on the live transport cell...
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("fresh-access"),
        "the sign-in tokens must win over a same-identity mid-flight refresh"
    );
    // ...and the ConnectionSet entry committed the same interactive bundle.
    let entry_creds = set.credentials(&id).expect("entry present");
    match entry_creds.fields.get("oauth") {
        Some(ovstorage_plugin::SecretValue::OAuthToken { refresh, .. }) => {
            assert_eq!(
                refresh.as_ref().map(|r| r.0.clone()),
                Some(b"rotated-refresh".to_vec()),
                "entry credentials carry the interactive refresh token"
            );
        }
        other => panic!("expected an oauth bundle on the entry, got {other:?}"),
    }
}

/// 3539558775 (reshaped): a credential update landing on the LIVE cell while a
/// `verify` probe is still in flight must be preserved — `verify` runs over an
/// EPHEMERAL transport bound to its own private state, so it can never wipe or
/// roll back a concurrent live-cell write (the old conditional-restore skip
/// machinery this exercised is deleted; the property is now structural).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_update_during_verify_is_preserved() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let gate = Arc::new(tokio::sync::Notify::new());
    let state_handle = Arc::new(Mutex::new(CapState {
        reject_top_level: true,
        gate_top_level: Some(gate.clone()),
        ..CapState::default()
    }));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    disco
        .install_tokens(
            "prior-good".into(),
            Some("prior-refresh".into()),
            Some(Duration::from_secs(3600)),
        )
        .await;

    // obtain the candidate bearer (on private staging), then run verify — whose
    // backend probe BLOCKS on the gate.
    let creds = oauth_secret_store::oauth_bundle("", Some("candidate-refresh"), None);
    let obtained = driver
        .obtain(&creds, GrantPolicy::AllowConsuming, None)
        .await
        .expect("the refresh grant mints a bearer");
    let Obtained::Bearer {
        credentials: effective,
        ..
    } = obtained
    else {
        panic!("a valid refresh token must obtain a bearer, got {obtained:?}");
    };
    let disco2 = disco.clone();
    let verify = tokio::spawn(async move {
        let driver = driver;
        driver.verify(&effective, None).await
    });
    // Wait until the verify probe is in flight (the RPC reached the fake service).
    loop {
        if state_handle.lock().unwrap().top_level_calls >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // A NEWER identity-changing update lands on the LIVE cell while verify blocks.
    disco2
        .replace_tokens(
            "newer-access".into(),
            Some("newer-refresh".into()),
            Some(Duration::from_secs(3600)),
        )
        .await;
    gate.notify_waiters(); // verify probe resumes → rejects the candidate
    let result = verify.await.unwrap();
    assert!(result.is_err(), "the candidate is rejected");
    // verify used an ephemeral transport, so the concurrent live-cell update is
    // untouched — it never regressed to the candidate or the prior-good bearer.
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("newer-access"),
        "verify must not disturb a credential update that landed on the live cell"
    );
    assert_eq!(
        disco.refresh_token().await.as_deref(),
        Some("newer-refresh")
    );
}

/// 3539558624: `remove_connection` cancels the entry's lifecycle token, and the
/// interactive flow thread fences its durable persist on it — a sign-in
/// completing after removal must not re-write the secret removal just deleted
/// (and must not land tokens on the transport either).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_during_interactive_flow_does_not_persist() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state = DiscoveryState::new("default");
    let http = reqwest::Client::new();
    let auth_config = fetch_auth_config(&http, &discovery_url).await.unwrap();
    state.install_auth_config(auth_config.clone()).await;
    let oidc = fetch_oidc_config(&http, &auth_config).await.unwrap();
    state.install_oidc_config(oidc).await;

    let persisted = Arc::new(AtomicBool::new(false));
    let p = persisted.clone();
    let persist: PersistRefresh = Arc::new(
        move |_access: &str, _rt: Option<String>, _generation: u64| {
            p.store(true, Ordering::SeqCst);
            Ok(())
        },
    );

    // The liveness token stands in for the ConnectionSet entry token that
    // `remove_connection` cancels (ConnectionSet::authenticate wires a child of
    // the entry token through the driver into this parameter).
    let liveness = ovstorage_plugin::CancellationToken::new();
    let stream = drive_interactive_login(
        &state,
        conn("c1"),
        InteractiveAuthCapability::Headless,
        persist,
        Some(liveness.clone()),
    )
    .await
    .expect("interactive flow starts");
    // The connection is removed while the user is mid-sign-in (device poll
    // fires only after the 1s interval).
    liveness.cancel();

    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let succeeded = events
        .iter()
        .find_map(|e| match e {
            AuthEvent::Succeeded { credentials, .. } => Some(credentials.clone()),
            _ => None,
        })
        .expect("flow still completes");
    assert!(
        succeeded.is_none(),
        "a removed connection's flow forwards Succeeded without credentials"
    );
    assert!(
        !persisted.load(Ordering::SeqCst),
        "no durable write after remove_connection deleted the secret"
    );
    assert!(
        state.access_token().await.is_none(),
        "no tokens installed on the transport for a removed connection"
    );
}

/// 3537944901: interactive success REPLACES a prior client-credentials identity
/// — it clears the cached M2M grant and overwrites the refresh slot — so a later
/// `refresh` drives the interactive refresh-token grant and cannot silently
/// revert to the previous service identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_replaces_client_credentials_identity_no_revert() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // Prior machine-to-machine identity cached on the state.
    disco
        .set_client_credentials("m2m-id".into(), "m2m-secret".into())
        .await;
    assert!(disco.client_credentials().await.is_some());

    // Interactive sign-in.
    let stream = driver
        .interactive(conn("c1"), InteractiveAuthCapability::Headless, None)
        .await
        .expect("interactive flow starts");
    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::Succeeded { .. }))
    );

    // The M2M grant was cleared and the refresh slot is the interactive one.
    assert!(
        disco.client_credentials().await.is_none(),
        "interactive success must clear the cached client-credentials grant"
    );
    assert_eq!(
        disco.refresh_token().await.as_deref(),
        Some("rotated-refresh"),
        "interactive success overwrites the refresh slot with the interactive token"
    );

    // A subsequent refresh drives the REFRESH-TOKEN grant (M2M is gone), keeping
    // the interactive identity rather than reverting.
    driver
        .refresh(&SecretBundle::default(), None, 0)
        .await
        .expect("refresh via the interactive refresh-token grant succeeds");
    assert!(
        !disco.access_token().await.unwrap_or_default().is_empty(),
        "refresh keeps a live access token for the interactive identity"
    );
    assert!(
        disco.client_credentials().await.is_none(),
        "refresh must not resurrect the client-credentials identity"
    );
}

/// 3537945622: durable persistence completes BEFORE the terminal `Succeeded` is
/// forwarded — the flow thread persists the refresh token synchronously ahead of
/// sending the event, so a process exit right after observing `Succeeded` cannot
/// lose the freshly-minted token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_persists_before_succeeded_is_observed() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state = DiscoveryState::new("default");
    let http = reqwest::Client::new();
    // Preload the config the flow needs (the driver normally does this).
    let auth_config = fetch_auth_config(&http, &discovery_url).await.unwrap();
    state.install_auth_config(auth_config.clone()).await;
    let oidc = fetch_oidc_config(&http, &auth_config).await.unwrap();
    state.install_oidc_config(oidc).await;

    // A persist hook that records whether it ran (and the token it saw).
    let persisted = Arc::new(AtomicBool::new(false));
    let seen_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let p = persisted.clone();
    let s = seen_token.clone();
    let persist: PersistRefresh =
        Arc::new(move |_access: &str, rt: Option<String>, _generation: u64| {
            *s.lock().unwrap() = rt;
            p.store(true, Ordering::SeqCst);
            Ok(())
        });

    let stream = drive_interactive_login(
        &state,
        conn("c1"),
        InteractiveAuthCapability::Headless,
        persist,
        None,
    )
    .await
    .expect("interactive flow starts");

    let persisted_at_succeeded = persisted.clone();
    let observed = tokio::task::spawn_blocking(move || {
        let mut ok = false;
        for event in stream.filter_map(std::result::Result::ok) {
            if matches!(event, AuthEvent::Succeeded { .. }) {
                // Persist MUST have already run by the time Succeeded is observed.
                ok = persisted_at_succeeded.load(Ordering::SeqCst);
            }
        }
        ok
    })
    .await
    .unwrap();

    assert!(
        observed,
        "persistence must complete before the terminal Succeeded is forwarded"
    );
    assert_eq!(
        seen_token.lock().unwrap().as_deref(),
        Some("rotated-refresh"),
        "the persisted token is the interactively-minted refresh token"
    );
}

/// The generation a real interactive flow hands its persist hook must be the
/// one its OWN commit produced, and a lease on it must read as current.
///
/// The lease's anchoring regression — anchored where the flow STARTED, which
/// its own commit has already moved past — passed every unit test that built a
/// lease by hand and only surfaced in a dlopen e2e, because nothing drove a
/// real flow through the lease. This drives `drive_interactive_login` and takes
/// the lease exactly where the driver's callback takes it.
#[tokio::test]
async fn interactive_hands_its_persist_hook_a_lease_that_is_current() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state = DiscoveryState::new("default");
    let http = reqwest::Client::new();
    let auth_config = fetch_auth_config(&http, &discovery_url).await.unwrap();
    state.install_auth_config(auth_config.clone()).await;
    let oidc = fetch_oidc_config(&http, &auth_config).await.unwrap();
    state.install_oidc_config(oidc).await;

    let epoch: Arc<dyn ovstorage_plugin::oauth_secret_store::IdentityEpoch> =
        Arc::new(state.clone());
    let lease_was_current = Arc::new(AtomicBool::new(false));
    let observed = lease_was_current.clone();
    let epoch_for_hook = Arc::clone(&epoch);
    let persist: PersistRefresh =
        Arc::new(move |_access: &str, _rt: Option<String>, generation: u64| {
            let lease = ovstorage_plugin::oauth_secret_store::IdentityLease::at_generation(
                &epoch_for_hook,
                generation,
            );
            observed.store(lease.is_current(), Ordering::SeqCst);
            Ok(())
        });

    let stream = drive_interactive_login(
        &state,
        conn("c1"),
        InteractiveAuthCapability::Headless,
        persist,
        None,
    )
    .await
    .expect("interactive flow starts");

    let succeeded = tokio::task::spawn_blocking(move || {
        stream.filter_map(std::result::Result::ok).any(|event| {
            matches!(
                event,
                AuthEvent::Succeeded {
                    credentials: Some(_),
                    ..
                }
            )
        })
    })
    .await
    .unwrap();

    assert!(
        succeeded,
        "the sign-in succeeds and publishes its credentials"
    );
    assert!(
        lease_was_current.load(Ordering::SeqCst),
        "a flow that just won must hold a lease it can write under; anchoring \
         where the flow started refuses every sign-in, since its own commit \
         advanced the generation",
    );
}

/// 3539557932: a STALE warm token at bring-up must not permanently kill root
/// discovery. Pre-fix, the warm-continue placeholder (`Some("")`) satisfied
/// `wait_for_token`, so the one-shot root watcher probed with an empty bearer,
/// failed, and exited — a later interactive success then yielded an
/// `Authenticated` connection with NO routes. Now the empty bearer does not
/// release the watcher (and the failed candidate is rolled off the cell), so
/// the watcher survives until the interactive sign-in installs a real token,
/// then discovers the roots — the connection is routable after sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_warm_start_interactive_success_restores_root_discovery() {
    use futures::StreamExt;
    use ovstorage_plugin_services_client::OmniverseStorageBackend;

    // OIDC provider whose FIRST token grant fails `invalid_grant` (the stale
    // warm refresh token); later grants (the interactive flow) succeed.
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/api/v1/auth-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "openid_configuration": format!("{base}/oidc"),
            "clients": { "default": { "client_id": "svc-client", "scope": "openid" } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": base,
            "token_endpoint": format!("{base}/token"),
            "device_authorization_endpoint": format!("{base}/device_authorization"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/device_authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev-code-123",
            "user_code": "WDJB-MJHT",
            "verification_uri": format!("{base}/device"),
            "expires_in": 300,
            "interval": 1
        })))
        .mount(&server)
        .await;
    // First /token POST: the stale warm grant → 400 invalid_grant.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Subsequent /token POSTs (the interactive flow) succeed.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rotated-refresh"
        })))
        .mount(&server)
        .await;

    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, transport, disco) = build_driver(base.clone(), channel);
    let backend = Arc::new(OmniverseStorageBackend::new(
        base.clone(),
        Capabilities::empty(),
        transport.clone(),
    ));

    // Stale warm bring-up: the refresh grant fails → obtain reports interactive
    // sign-in is required, and (because obtain grants on private staging) the
    // live cell is never touched by the dead warm placeholder.
    let warm = oauth_secret_store::oauth_bundle("", Some("stale-refresh"), None);
    let obtained = driver
        .obtain(&warm, GrantPolicy::AllowConsuming, None)
        .await
        .expect("obtain maps");
    assert!(
        matches!(obtained, Obtained::AwaitingInteractive { .. }),
        "a stale warm token parks for interactive sign-in, got {obtained:?}"
    );
    assert!(
        disco.access_token().await.is_none(),
        "obtain grants on private staging; the failed warm candidate never touches the live cell"
    );

    // The root watcher must STAY BLOCKED (no empty-bearer probe-and-die).
    let watcher = tokio::spawn(async move { backend.watch_address_roots(None).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !watcher.is_finished(),
        "the root watcher must wait for a real token, not probe with an empty bearer"
    );

    // Interactive sign-in succeeds and installs a real token.
    let stream = driver
        .interactive(conn("c1"), InteractiveAuthCapability::Headless, None)
        .await
        .expect("interactive flow starts");
    let events = tokio::task::spawn_blocking(move || {
        stream
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::Succeeded { .. })),
        "device-code flow must reach Succeeded"
    );

    // The watcher now unblocks and discovers the roots — routable again.
    let mut roots_stream = tokio::time::timeout(Duration::from_secs(5), watcher)
        .await
        .expect("watcher unblocks after interactive success")
        .unwrap()
        .expect("watch_address_roots opens");
    match tokio::time::timeout(Duration::from_secs(5), roots_stream.next()).await {
        Ok(Some(Ok(ovstorage_plugin::AddressRootsChange::Snapshot(roots)))) => {
            assert_eq!(roots.len(), 1, "the discovered root is advertised");
            assert_eq!(roots[0].address.as_str(), "omni://server/root/");
        }
        other => panic!("expected a roots Snapshot after sign-in, got {other:?}"),
    }
}

// ---- M2M (client_credentials) background-refresh regression ------------------

/// Build a machine-to-machine credential bundle: a `client_id` + `client_secret`
/// pair (stamped as `Bytes`, the SPI shape) and NO oauth token — the shape that
/// drives a `client_credentials` grant.
fn client_credentials_bundle(client_id: &str, client_secret: &str) -> SecretBundle {
    let mut creds = SecretBundle::default();
    creds.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(client_id.as_bytes().to_vec())),
    );
    creds.fields.insert(
        "client_secret".into(),
        SecretValue::Bytes(SecretBytes(client_secret.as_bytes().to_vec())),
    );
    creds
}

/// M2M regression: `obtain` grants on driver-PRIVATE staging, so the client-
/// credentials pair never reaches the live cell. The fix carries the pair through
/// in the effective bundle, and `refresh` re-seeds it — so a background /
/// data-path `refresh` re-drives the CLIENT-CREDENTIALS grant (which an M2M
/// connection needs) rather than falling through to a tokenless refresh-token
/// grant that would fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2m_refresh_redrives_client_credentials_grant() {
    let (oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // `obtain` mints an access token via the client_credentials grant on private
    // staging — the live cell is untouched, so it holds no cached pair yet.
    let creds = client_credentials_bundle("svc-id", "svc-secret");
    let obtained = driver
        .obtain(&creds, GrantPolicy::AllowConsuming, None)
        .await
        .expect("obtain ok");
    let Obtained::Bearer {
        credentials: effective,
        ..
    } = obtained
    else {
        panic!("an M2M grant must mint a bearer, got {obtained:?}");
    };
    // The effective bundle carries the replayable client-credentials pair through
    // (so the ConnectionSet entry keeps it in-memory for a later refresh).
    assert!(
        matches!(effective.fields.get("client_id"), Some(SecretValue::Bytes(b)) if b.0 == b"svc-id"),
        "obtain must carry the client_id through in the effective bundle"
    );
    assert!(
        matches!(effective.fields.get("client_secret"), Some(SecretValue::Bytes(b)) if b.0 == b"svc-secret"),
        "obtain must carry the client_secret through in the effective bundle"
    );
    assert!(
        disco.client_credentials().await.is_none(),
        "obtain grants on private staging; the live cell caches no pair yet"
    );
    assert_eq!(
        count_grant_posts(&oidc, "client_credentials").await,
        1,
        "obtain drove exactly one client_credentials grant"
    );
    assert_eq!(
        count_grant_posts(&oidc, "refresh_token").await,
        0,
        "an M2M bring-up drives no refresh-token grant"
    );

    // The regression: a background / data-path `refresh(&effective, None)` must
    // re-drive the CLIENT-CREDENTIALS grant (re-seeded from `current`), NOT a
    // refresh-token grant with no stored token.
    driver
        .refresh(&effective, None, 0)
        .await
        .expect("M2M refresh re-drives the client_credentials grant");
    assert!(
        disco.client_credentials().await.is_some(),
        "refresh re-seeds the client-credentials pair onto the live cell"
    );
    assert_eq!(
        count_grant_posts(&oidc, "client_credentials").await,
        2,
        "refresh re-drove the client_credentials grant, not a refresh-token grant"
    );
    assert_eq!(
        count_grant_posts(&oidc, "refresh_token").await,
        0,
        "refresh must NOT fall through to a (tokenless) refresh-token grant"
    );
    assert!(
        !disco.access_token().await.unwrap_or_default().is_empty(),
        "refresh keeps a live access token for the M2M identity"
    );
}

// ---- refresh grants on private staging, commits under the fence ------------

/// Regression: `refresh` runs its grant on driver-PRIVATE staging, not the
/// LIVE token cell (the transport interceptor's slot), and the live-cell
/// commit is fenced on the set-captured `expected_gen`. Without that
/// staging+fence an in-flight refresh could clobber a concurrent
/// interactive winner's bearer. A refresh carrying a STALE fence still
/// mints and returns its bundle (for the set-side fence), but the live
/// cell keeps the winner's tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_with_stale_identity_fence_does_not_clobber_live_cell() {
    let (_oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, disco) = build_driver(discovery_url, channel);

    // The refresh's identity capture happens BEFORE the interactive winner
    // lands (the race under test): capture the pre-sign-in generation.
    let stale_gen = disco.identity_generation();

    // A concurrent interactive sign-in wins the live cell and bumps
    // `identity_gen`.
    disco
        .replace_tokens("winner-access".into(), Some("winner-refresh".into()), None)
        .await;
    assert_ne!(disco.identity_generation(), stale_gen);

    // The in-flight M2M refresh completes with the stale fence: the grant
    // itself succeeds (on private staging) and the minted bundle is
    // returned, but the fenced live-cell commit must SKIP.
    let refreshed = driver
        .refresh(
            &client_credentials_bundle("svc-id", "svc-secret"),
            None,
            stale_gen,
        )
        .await
        .expect("the grant itself succeeds on private staging");
    assert!(
        matches!(
            refreshed.credentials.fields.get("oauth"),
            Some(SecretValue::OAuthToken { .. })
        ),
        "the minted bundle is still returned for the set-side fence"
    );
    assert_eq!(
        disco.access_token().await.as_deref(),
        Some("winner-access"),
        "a stale-fenced refresh must not clobber the interactive winner's bearer"
    );
    assert_eq!(
        disco.refresh_token().await.as_deref(),
        Some("winner-refresh"),
        "the winner's refresh token survives the stale-fenced commit"
    );
    assert!(
        disco.client_credentials().await.is_none(),
        "a stale-fenced M2M refresh must not cache the service pair over the winner"
    );
}

// ---- probe: refresh-token-only bundle is Unverifiable, consuming nothing -----

/// A refresh-token-only bundle can only reach a bearer via a CONSUMING
/// refresh-token grant, so `probe_connection` (which grants `NonConsumingOnly`)
/// must report `Unverifiable` and drive ZERO IdP token calls — it never burns
/// the one-time refresh token to test it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_refresh_only_bundle_is_unverifiable_without_consuming() {
    let (oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, _disco) = build_driver(discovery_url, channel);

    let set = Arc::new(ConnectionSet::<OmniverseStorageDriver>::with_defaults());
    let rt_only = oauth_secret_store::oauth_bundle("", Some("stored-refresh"), None);
    let outcome = set
        .probe_connection(Arc::new(driver), rt_only, None)
        .await
        .expect("probe returns a verdict");
    assert!(
        matches!(outcome, ProbeOutcome::Unverifiable),
        "a refresh-token-only bundle cannot be probed without consuming, got {outcome:?}"
    );
    assert_eq!(
        count_token_posts(&oidc).await,
        0,
        "a WouldConsume probe refuses before any network work — zero token calls"
    );
}

/// D1: a NON-EMPTY but already-EXPIRED access token plus a refresh token can only
/// reach a fresh bearer via a CONSUMING refresh-token grant — the old
/// `would_consume_only` treated any non-empty access token as usable and let the
/// probe drive (and burn) the refresh grant. The fix reports `WouldConsume` (→
/// `Unverifiable`) and drives ZERO IdP token calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_expired_access_with_refresh_is_unverifiable_without_consuming() {
    let (oidc, discovery_url) = mock_oidc().await;
    let state_handle = Arc::new(Mutex::new(CapState::default()));
    let channel = spawn_capabilities(state_handle).await;
    let (driver, _transport, _disco) = build_driver(discovery_url, channel);

    let set = Arc::new(ConnectionSet::<OmniverseStorageDriver>::with_defaults());
    // Non-empty access token, but expired 1s ago, plus a refresh token.
    let expired = oauth_secret_store::oauth_bundle(
        "expired-access",
        Some("rt"),
        Some(SystemTime::now() - Duration::from_secs(1)),
    );
    let outcome = set
        .probe_connection(Arc::new(driver), expired, None)
        .await
        .expect("probe returns a verdict");
    assert!(
        matches!(outcome, ProbeOutcome::Unverifiable),
        "an expired-access + refresh bundle cannot be probed without consuming, got {outcome:?}"
    );
    assert_eq!(
        count_token_posts(&oidc).await,
        0,
        "a WouldConsume probe never drives the refresh grant — zero token calls"
    );
}

// ---- M2M (data-path recovery): immediate silent grant after bring-up ---------

/// Mock OIDC whose `/token` endpoint issues NO refresh token — the correct shape
/// for a `client_credentials` grant (RFC 6749 §4.4.3). This makes
/// `has_silent_grant` depend SOLELY on the cached client-credentials pair, so the
/// M2M-recovery test actually exercises the pair caching (the default `mock_oidc` returns a
/// refresh token for every grant, which would mask the fix).
async fn mock_oidc_client_credentials_no_refresh() -> (MockServer, String) {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/api/v1/auth-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "openid_configuration": format!("{base}/oidc"),
            "clients": { "default": { "client_id": "svc-client", "scope": "openid" } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": base,
            "token_endpoint": format!("{base}/token"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    (server, base)
}

/// M2M recovery: after an M2M (`client_credentials`) bring-up, the
/// live cell must have the client-credentials pair cached IMMEDIATELY — via
/// `activate`, not just the first background refresh — so `has_silent_grant` is
/// true and a data-path `UNAUTHENTICATED` classifies as a recoverable credential.
/// `with_recovery` then re-drives the CLIENT-CREDENTIALS grant and retries. The
/// `/token` endpoint issues no refresh token, so this can ONLY pass if the pair
/// was cached (not because a spurious refresh token made `has_silent_grant` true).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2m_bringup_caches_client_credentials_for_immediate_recovery() {
    let (oidc, discovery_url) = mock_oidc_client_credentials_no_refresh().await;
    let state_handle = Arc::new(Mutex::new(CapState {
        fail_first_list_services: true,
        ..CapState::default()
    }));
    let channel = spawn_capabilities(state_handle.clone()).await;
    let (driver, transport, disco) = build_driver(discovery_url, channel);

    let set = Arc::new(ConnectionSet::<OmniverseStorageDriver>::with_defaults());
    let id = ConnectionId("c1".into());
    let creds = {
        let mut creds = SecretBundle::default();
        creds.fields.insert(
            "client_id".into(),
            SecretValue::Bytes(SecretBytes(b"svc-id".to_vec())),
        );
        creds.fields.insert(
            "client_secret".into(),
            SecretValue::Bytes(SecretBytes(b"svc-secret".to_vec())),
        );
        creds
    };
    let auth_state = set
        .add_connection(conn("c1"), Arc::new(driver), creds, None)
        .await
        .expect("M2M add_connection ok");
    assert!(
        matches!(auth_state, ConnectionAuthState::Authenticated { .. }),
        "M2M bring-up authenticates, got {auth_state:?}"
    );
    // `activate` cached the client-credentials pair on the LIVE cell during
    // bring-up, so a silent grant is available IMMEDIATELY (no background refresh
    // has run — the token TTL is an hour).
    assert!(
        disco.client_credentials().await.is_some(),
        "M2M bring-up must cache the client-credentials pair on the live cell"
    );
    assert!(
        disco.has_silent_grant(),
        "has_silent_grant is true right after M2M bring-up (the fix's payoff)"
    );
    assert!(
        disco.refresh_token().await.is_none(),
        "the client_credentials grant issued no refresh token — the pair is the only silent grant"
    );
    assert_eq!(
        count_grant_posts(&oidc, "client_credentials").await,
        1,
        "exactly one client_credentials grant at bring-up"
    );

    // A data op hits UNAUTHENTICATED once. Because has_silent_grant is true, the
    // driver classifies it RecoverableCredential and `with_recovery` re-drives the
    // client_credentials grant, then the retry succeeds.
    let result = set
        .with_recovery(&id, || {
            let transport = transport.clone();
            async move {
                let mut client = transport.capabilities_client().await?;
                client
                    .list_services(Request::new(cap::ListServicesRequest {}))
                    .await
                    .map(|r| r.into_inner())
                    .map_err(map_status)
            }
        })
        .await;
    assert!(
        result.is_ok(),
        "M2M recovery re-drove the client_credentials grant and retried, got {result:?}"
    );
    assert_eq!(
        count_grant_posts(&oidc, "client_credentials").await,
        2,
        "data-path recovery re-drove the client_credentials grant"
    );
    assert_eq!(
        count_grant_posts(&oidc, "refresh_token").await,
        0,
        "an M2M recovery must never fall through to a refresh-token grant"
    );
}
