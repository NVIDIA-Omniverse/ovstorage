// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Three-tier OAuth: client Stack → broker-client cdylib → daemon → upstream IdP.
//!
//! The happy path starts with an `AuthRequired` data operation on the client
//! Stack, then uses the address-bearing host helper to drive the daemon's OAuth
//! relay. The per-listener auth layer resolves the anonymous caller and stamps
//! its principal down to the upstream-credential wrapper, which persists the
//! bearer before the success event returns through the loaded v2 plugin.

use super::*;
use ovstorage::auth::flow::test_support::FakeIdp;
use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy, SecretStore};
use ovstorage::{
    AuthEvent, CancellationToken, ConfigValue, ConnectionRequest, InteractiveAuthCapability,
    ReadOptions, SecretBundle,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn sqlite_store(state_root: &std::path::Path) -> Arc<dyn ovstorage::auth::SecretStore> {
    Arc::new(ovstorage::auth::SqliteSecretStore::open(state_root).expect("open sqlite store"))
}

type ConfiguredOAuth = (
    SubstrateGuard,
    Arc<OAuthProviderRegistry>,
    BrokerOAuthRouteBindings,
    Arc<AuthRefreshLock>,
    Arc<dyn SecretStore>,
);

/// Serializes every test that touches the process-wide auth substrate. The
/// loaded HTTP plugin resolves credentials through host callbacks, and those
/// callbacks read the process auth root (`OVSTORAGE_AUTH_DIR`, pinned once by
/// `ensure_test_plugin_env`) — so this module's providers must persist into
/// that same `auth.sqlite`, and tests sharing it must not interleave.
static SUBSTRATE_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct SubstrateGuard {
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

async fn isolated_substrate(
    backend_kind: &str,
) -> (SubstrateGuard, Arc<dyn SecretStore>, Arc<AuthRefreshLock>) {
    let guard = SUBSTRATE_TESTS.lock().await;
    crate::test_utils::ensure_test_plugin_env();
    let root = std::path::PathBuf::from(
        std::env::var_os("OVSTORAGE_AUTH_DIR").expect("test auth dir is pinned per process"),
    );
    let secret_store = sqlite_store(&root);
    let refresh_lock = Arc::new(AuthRefreshLock::open(&root).unwrap());
    // Wipe the slot this suite exercises so a previous test's persisted
    // credential cannot serve a warm path that the test means to drive
    // through the IdP.
    refresh_lock
        .delete_secret_token(backend_kind, "anonymous")
        .unwrap();
    for field in ["oauth/upstream-idp", "oauth/upstream-idp/refresh"] {
        secret_store
            .delete(backend_kind, "anonymous", field)
            .unwrap();
    }
    (SubstrateGuard { _guard: guard }, secret_store, refresh_lock)
}

async fn configured_http_oauth(
    inner_idp: &FakeIdp,
    state_root: &std::path::Path,
) -> (ProtectedHttpOrigin, ConfiguredOAuth) {
    let origin = spawn_protected_http_origin("unused-test-bearer", Vec::new()).await;
    let configured = configured_oauth_for(inner_idp, state_root, "http", origin.root.clone()).await;
    (origin, configured)
}

async fn configured_oauth_for(
    inner_idp: &FakeIdp,
    _state_root: &std::path::Path,
    backend_kind: &str,
    route: url::Url,
) -> ConfiguredOAuth {
    let (substrate_guard, secret_store, refresh_lock) = isolated_substrate(backend_kind).await;
    let provider = Arc::new(OAuthCredentialProvider::new(
        "upstream-idp",
        backend_kind,
        inner_idp.endpoints(true),
        Arc::clone(&secret_store),
        refresh_lock.clone(),
        OAuthStrategy::Device,
    ));
    let registry = Arc::new(OAuthProviderRegistry::new().with_provider("upstream-idp", provider));
    let bindings = BrokerOAuthRouteBindings::new().with_route(route, "upstream-idp");
    (
        substrate_guard,
        registry,
        bindings,
        refresh_lock,
        secret_store,
    )
}

async fn spawn_three_tier_client(
    registry: Arc<OAuthProviderRegistry>,
    bindings: BrokerOAuthRouteBindings,
    backend_config: HashMap<String, ConfigValue>,
) -> (BrokerGrpcServer, Arc<ovstorage::Stack>) {
    let listener = test_listener_config();
    let auth_config = crate::broker_listener_auth_preflight(Some(&listener))
        .unwrap()
        .into_builtin_config()
        .unwrap();
    let fixture = BrokerStackFixture::new()
        .test_backend(backend_config)
        .auth_config(auth_config)
        .oauth(registry, bindings);
    let broker = fixture.build_broker().await;
    let server =
        spawn_broker_grpc_tcp_listener(Arc::new(broker), "127.0.0.1:0".parse().unwrap()).unwrap();
    let client_stack = broker_client_stack(&server.endpoint_url()).await;
    (server, client_stack)
}

async fn spawn_three_tier_http_client(
    registry: Arc<OAuthProviderRegistry>,
    bindings: BrokerOAuthRouteBindings,
    root_url: &ovstorage::Url,
) -> (BrokerGrpcServer, Arc<ovstorage::Stack>) {
    let listener = test_listener_config();
    let auth_config = crate::broker_listener_auth_preflight(Some(&listener))
        .unwrap()
        .into_builtin_config()
        .unwrap();
    let broker = BrokerStackFixture::new()
        .connection(ConnectionRequest {
            backend_kind: "http".into(),
            config: HashMap::from([(
                "root_url".into(),
                ConfigValue::String(root_url.as_str().to_string()),
            )]),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some("protected HTTP origin".into()),
        })
        .auth_config(auth_config)
        .oauth(registry, bindings)
        .build_broker()
        .await;
    let server =
        spawn_broker_grpc_tcp_listener(Arc::new(broker), "127.0.0.1:0".parse().unwrap()).unwrap();
    let client_stack = broker_client_stack(&server.endpoint_url()).await;
    (server, client_stack)
}

struct ProtectedHttpOrigin {
    root: ovstorage::Url,
    address: ovstorage::Url,
    expected_bearer: Arc<std::sync::Mutex<String>>,
    unauthorized_requests: Arc<AtomicUsize>,
    authorized_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

async fn spawn_protected_http_origin(
    expected_bearer: &str,
    payload: Vec<u8>,
) -> ProtectedHttpOrigin {
    spawn_protected_http_origin_with_barrier(expected_bearer, payload, None).await
}

async fn spawn_protected_http_origin_with_barrier(
    expected_bearer: &str,
    payload: Vec<u8>,
    unauthorized_barrier: Option<Arc<tokio::sync::Barrier>>,
) -> ProtectedHttpOrigin {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = ovstorage::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let address = root.join("objects/file.bin").unwrap();
    let expected_bearer = Arc::new(std::sync::Mutex::new(expected_bearer.to_string()));
    let task_expected_bearer = Arc::clone(&expected_bearer);
    let unauthorized_requests = Arc::new(AtomicUsize::new(0));
    let authorized_requests = Arc::new(AtomicUsize::new(0));
    let task_unauthorized = Arc::clone(&unauthorized_requests);
    let task_authorized = Arc::clone(&authorized_requests);
    let payload = Arc::new(payload);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let expected_bearer = Arc::clone(&task_expected_bearer);
            let unauthorized_requests = Arc::clone(&task_unauthorized);
            let authorized_requests = Arc::clone(&task_authorized);
            let unauthorized_barrier = unauthorized_barrier.clone();
            let payload = Arc::clone(&payload);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while let Ok(read) = stream.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let authorized = String::from_utf8_lossy(&request).lines().any(|line| {
                    let Some((name, value)) = line.split_once(':') else {
                        return false;
                    };
                    name.eq_ignore_ascii_case("authorization")
                        && value.trim()
                            == format!("Bearer {}", expected_bearer.lock().unwrap().as_str())
                });
                let (status, body) = if authorized {
                    authorized_requests.fetch_add(1, Ordering::SeqCst);
                    ("200 OK", payload.as_slice())
                } else {
                    unauthorized_requests.fetch_add(1, Ordering::SeqCst);
                    if let Some(barrier) = unauthorized_barrier {
                        barrier.wait().await;
                    }
                    ("401 Unauthorized", &[][..])
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(body).await;
                }
            });
        }
    });
    ProtectedHttpOrigin {
        root,
        address,
        expected_bearer,
        unauthorized_requests,
        authorized_requests,
        task,
    }
}

fn test_address() -> ovstorage::Url {
    ovstorage::address::parse("test://demo/objects/file.bin").unwrap()
}

async fn upstream_events(
    client_stack: &ovstorage::Stack,
    address: &ovstorage::Url,
    cancel: Option<CancellationToken>,
) -> ovstorage::AuthEventStream {
    upstream_events_with_capability(
        client_stack,
        address,
        InteractiveAuthCapability::Headless,
        cancel,
    )
    .await
}

async fn upstream_events_with_capability(
    client_stack: &ovstorage::Stack,
    address: &ovstorage::Url,
    capability: InteractiveAuthCapability,
    cancel: Option<CancellationToken>,
) -> ovstorage::AuthEventStream {
    ovstorage::auth::authenticate_upstream_for_address(
        client_stack,
        address,
        capability,
        false,
        cancel,
    )
    .await
    .expect("client Stack opens the brokered upstream OAuth flow")
}

fn finish_device_flow(events: &mut ovstorage::AuthEventStream) {
    let mut saw_device_code = false;
    for event in events.by_ref() {
        match event.expect("auth event succeeds") {
            AuthEvent::DeviceCode { .. } => saw_device_code = true,
            AuthEvent::Succeeded { credentials, .. } => {
                assert!(
                    credentials.is_none(),
                    "the daemon must not return bearer bytes to the client"
                );
                assert!(saw_device_code, "device flow must emit its user prompt");
                return;
            }
            AuthEvent::Failed { error } => panic!("upstream OAuth flow failed: {error}"),
            AuthEvent::Cancelled => panic!("upstream OAuth flow was cancelled"),
            _ => {}
        }
    }
    panic!("upstream OAuth flow closed before Succeeded");
}

fn assert_single_failed(events: &mut ovstorage::AuthEventStream, code: ErrorCode) -> String {
    let message = match events
        .next()
        .expect("one failed auth event")
        .expect("failure is carried as an AuthEvent")
    {
        AuthEvent::Failed { error } => {
            assert_eq!(error.code(), code);
            error.message().to_string()
        }
        other => panic!("expected Failed{{{code:?}}}, got {other:?}"),
    };
    assert!(events.next().is_none(), "failed auth stream must close");
    message
}

fn assert_clean_cancellation_tail(tail: &[ovstorage::Result<AuthEvent>]) {
    let mut terminal = false;
    for event in tail {
        match event {
            Ok(AuthEvent::Progress { .. }) if !terminal => {}
            Ok(AuthEvent::Cancelled) => {
                assert!(
                    !terminal,
                    "cancellation emitted more than one terminal event"
                );
                terminal = true;
            }
            Err(error) if error.code() == ErrorCode::Cancelled => {
                assert!(
                    !terminal,
                    "cancellation emitted more than one terminal event"
                );
                terminal = true;
            }
            other => panic!("unexpected event after client cancellation: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_oauth_flow_drives_inner_idp_and_persists_credential() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("inner-bearer-001").await;
    let payload = b"credential-gated object".to_vec();
    let origin = spawn_protected_http_origin("inner-bearer-001", payload.clone()).await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (_substrate_guard, registry, bindings, refresh_lock, secret_store) =
        configured_oauth_for(&inner_idp, &state_root, "http", origin.root.clone()).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let error = ovstorage::ext::LayerExt::read_bytes(
        &*client_stack,
        address.clone(),
        ReadOptions::default(),
        None,
    )
    .await
    .expect_err("the provider-aware data path must require upstream authentication");
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert_eq!(
        origin.unauthorized_requests.load(Ordering::SeqCst),
        1,
        "the production HTTP backend must issue the original anonymous request"
    );

    let mut events = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut events);
    drop(events);

    let row = refresh_lock
        .load_secret_token("http", "anonymous")
        .expect("load persisted upstream credential")
        .expect("Succeeded must persist a secret_tokens row");
    assert_eq!(row.source_name, "upstream-idp");
    assert_eq!(
        row.secret_handle, "oauth/upstream-idp",
        "handles are provider-deterministic; deployment isolation is the state root's sqlite"
    );
    assert!(row.expires_at_unix_ms.is_some(), "expiry must persist");
    assert!(row.cred_epoch >= 1, "credential epoch must advance");
    let access = secret_store
        .get("http", "anonymous", &row.secret_handle)
        .expect("read persisted upstream access token")
        .expect("Succeeded must cache the access token in the keyring");
    assert_eq!(access.as_bytes(), b"inner-bearer-001");
    let refresh = secret_store
        .get(
            "http",
            "anonymous",
            &format!("{}/refresh", row.secret_handle),
        )
        .expect("read persisted upstream refresh token")
        .expect("FakeIdp returns a refresh token");
    assert_eq!(refresh.as_bytes(), b"device-refresh");

    let (bytes, _) =
        ovstorage::ext::LayerExt::read_bytes(&*client_stack, address, ReadOptions::default(), None)
            .await
            .expect("the production HTTP backend re-resolves and sends the persisted bearer");
    assert_eq!(bytes, payload);
    assert_eq!(
        origin.authorized_requests.load(Ordering::SeqCst),
        1,
        "the retry must reach the origin with the exact persisted OAuth bearer"
    );

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_http_auth_required_refreshes_and_retries_once() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("initial-bearer").await;
    let payload = b"credential refresh recovered object".to_vec();
    let origin = spawn_protected_http_origin("initial-bearer", payload.clone()).await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (_substrate_guard, registry, bindings, refresh_lock, secret_store) =
        configured_oauth_for(&inner_idp, &state_root, "http", origin.root.clone()).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let mut events = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut events);
    drop(events);

    let (initial, _) = ovstorage::ext::LayerExt::read_bytes(
        &*client_stack,
        address.clone(),
        ReadOptions::default(),
        None,
    )
    .await
    .expect("the initially persisted bearer is accepted");
    assert_eq!(initial, payload);

    *inner_idp.access_token.lock().unwrap() = "refreshed-bearer".into();
    *origin.expected_bearer.lock().unwrap() = "refreshed-bearer".into();

    let (recovered, _) =
        ovstorage::ext::LayerExt::read_bytes(&*client_stack, address, ReadOptions::default(), None)
            .await
            .expect("one upstream 401 must invalidate, refresh, and retry the HTTP read");
    assert_eq!(recovered, payload);
    assert_eq!(
        origin.unauthorized_requests.load(Ordering::SeqCst),
        1,
        "the stale bearer must reach the origin exactly once"
    );
    assert_eq!(
        origin.authorized_requests.load(Ordering::SeqCst),
        2,
        "the initial read and one refreshed retry must be authorized"
    );

    let row = refresh_lock
        .load_secret_token("http", "anonymous")
        .unwrap()
        .expect("the refreshed credential row remains durable");
    assert_eq!(
        secret_store
            .get("http", "anonymous", &row.secret_handle)
            .unwrap()
            .expect("refreshed access token remains in the keyring")
            .as_bytes(),
        b"refreshed-bearer"
    );

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_http_retries_only_once_when_refreshed_bearer_is_rejected() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("initial-bearer").await;
    let origin = spawn_protected_http_origin("initial-bearer", b"unused".to_vec()).await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (_substrate_guard, registry, bindings, _refresh_lock, _secret_store) =
        configured_oauth_for(&inner_idp, &state_root, "http", origin.root.clone()).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let mut events = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut events);
    drop(events);

    *inner_idp.access_token.lock().unwrap() = "refreshed-bearer".into();
    *origin.expected_bearer.lock().unwrap() = "never-accepted".into();

    let error =
        ovstorage::ext::LayerExt::read_bytes(&*client_stack, address, ReadOptions::default(), None)
            .await
            .expect_err("the second upstream 401 must be returned without another retry");
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert_eq!(
        origin.unauthorized_requests.load(Ordering::SeqCst),
        2,
        "one stale request and one refreshed retry must reach the origin"
    );
    assert_eq!(origin.authorized_requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        inner_idp.refresh_grant_attempts.load(Ordering::SeqCst),
        1,
        "a rejected retry must not start another refresh cycle"
    );

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_tier_concurrent_rejections_single_flight_refresh() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_single_use_refresh_token("initial-bearer").await;
    let payload = b"single-flight credential refresh".to_vec();
    let stale_requests = Arc::new(tokio::sync::Barrier::new(2));
    let origin = spawn_protected_http_origin_with_barrier(
        "initial-bearer",
        payload.clone(),
        Some(stale_requests),
    )
    .await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (_substrate_guard, registry, bindings, _refresh_lock, _secret_store) =
        configured_oauth_for(&inner_idp, &state_root, "http", origin.root.clone()).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let mut events = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut events);
    drop(events);

    *inner_idp.access_token.lock().unwrap() = "refreshed-bearer".into();
    *origin.expected_bearer.lock().unwrap() = "refreshed-bearer".into();

    let first = ovstorage::ext::LayerExt::read_bytes(
        &*client_stack,
        address.clone(),
        ReadOptions::default(),
        None,
    );
    let second =
        ovstorage::ext::LayerExt::read_bytes(&*client_stack, address, ReadOptions::default(), None);
    let (first, second) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(first, second)
    })
    .await
    .expect("both stale requests must reach the origin and recover without deadlock");
    assert_eq!(first.expect("first read recovers").0, payload);
    assert_eq!(second.expect("second read recovers").0, payload);
    assert_eq!(
        origin.unauthorized_requests.load(Ordering::SeqCst),
        2,
        "both callers must observe rejection of the same stale credential"
    );
    assert_eq!(
        origin.authorized_requests.load(Ordering::SeqCst),
        2,
        "both callers must retry with the coalesced refreshed credential"
    );
    assert_eq!(
        inner_idp.refresh_grant_attempts.load(Ordering::SeqCst),
        1,
        "a single-use refresh token must be redeemed only once"
    );

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_unconfigured_route_emits_auth_required() {
    ensure_test_plugin_env();
    let (server, client_stack) = spawn_three_tier_client(
        Arc::new(OAuthProviderRegistry::new()),
        BrokerOAuthRouteBindings::new(),
        HashMap::new(),
    )
    .await;
    let address = test_address();

    let mut events = upstream_events(&client_stack, &address, None).await;
    assert_single_failed(&mut events, ErrorCode::AuthRequired);

    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut direct = pb::broker_service_client::BrokerServiceClient::new(channel);
    let status = direct
        .register_credential(pb::RegisterCredentialRequest {
            address: ovstorage_broker_protocol::object_address_to_proto(&address),
            access_token: b"unused".to_vec(),
            refresh_token: Vec::new(),
            expires_at_unix_millis: 0,
        })
        .await
        .expect_err("an unbound route cannot accept an upstream credential");
    let error = ovstorage_broker_protocol::status_to_error(status);
    assert_eq!(error.code(), ErrorCode::Unsupported);

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_missing_provider_emits_credential_unavailable() {
    ensure_test_plugin_env();
    let bindings = BrokerOAuthRouteBindings::new()
        .with_route(url::Url::parse("test://demo/").unwrap(), "ghost-provider");
    let (server, client_stack) = spawn_three_tier_client(
        Arc::new(OAuthProviderRegistry::new()),
        bindings,
        HashMap::new(),
    )
    .await;
    let address = test_address();

    let mut events = upstream_events(&client_stack, &address, None).await;
    let message = assert_single_failed(&mut events, ErrorCode::CredentialUnavailable);
    assert!(
        message.contains("ghost-provider"),
        "safe configured provider name must survive failure redaction: {message}"
    );

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_register_credential_replaces_refresh_and_rejects_empty_access() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("unused-register-token").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (origin, (_substrate_guard, registry, bindings, refresh_lock, secret_store)) =
        configured_http_oauth(&inner_idp, &state_root).await;
    let (server, _client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut direct = pb::broker_service_client::BrokerServiceClient::new(channel);

    direct
        .register_credential(pb::RegisterCredentialRequest {
            address: ovstorage_broker_protocol::object_address_to_proto(&address),
            access_token: b"account-a-access".to_vec(),
            refresh_token: b"account-a-refresh".to_vec(),
            expires_at_unix_millis: 0,
        })
        .await
        .expect("account A credential registers");
    direct
        .register_credential(pb::RegisterCredentialRequest {
            address: ovstorage_broker_protocol::object_address_to_proto(&address),
            access_token: b"account-b-access".to_vec(),
            refresh_token: Vec::new(),
            expires_at_unix_millis: 0,
        })
        .await
        .expect("account B credential replaces account A");

    let row = refresh_lock
        .load_secret_token("http", "anonymous")
        .unwrap()
        .expect("replacement metadata row");
    assert_eq!(
        secret_store
            .get("http", "anonymous", &row.secret_handle)
            .unwrap()
            .expect("replacement access token")
            .as_bytes(),
        b"account-b-access"
    );
    assert!(
        secret_store
            .get(
                "http",
                "anonymous",
                &format!("{}/refresh", row.secret_handle),
            )
            .unwrap()
            .is_none(),
        "an omitted replacement refresh token must remove account A's token"
    );

    let status = direct
        .register_credential(pb::RegisterCredentialRequest {
            address: ovstorage_broker_protocol::object_address_to_proto(&address),
            access_token: Vec::new(),
            refresh_token: b"must-not-land".to_vec(),
            expires_at_unix_millis: 0,
        })
        .await
        .expect_err("an empty access token must be rejected");
    assert_eq!(
        ovstorage_broker_protocol::status_to_error(status).code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        secret_store
            .get("http", "anonymous", &row.secret_handle)
            .unwrap()
            .expect("valid replacement remains after rejection")
            .as_bytes(),
        b"account-b-access"
    );
    assert!(
        secret_store
            .get(
                "http",
                "anonymous",
                &format!("{}/refresh", row.secret_handle),
            )
            .unwrap()
            .is_none(),
        "the rejected registration's refresh token must not be stored"
    );

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_downgrades_remote_browser_and_preserves_none_and_headless_capabilities() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("headless-bearer").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (origin, (_substrate_guard, registry, bindings, _refresh_lock, _secret_store)) =
        configured_http_oauth(&inner_idp, &state_root).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let browser_cancel = CancellationToken::new();
    let mut browser = ovstorage::auth::authenticate_upstream_for_address(
        &*client_stack,
        &address,
        InteractiveAuthCapability::Browser,
        false,
        Some(browser_cancel.clone()),
    )
    .await
    .expect("a device-capable provider downgrades remote Browser to Headless");
    assert!(matches!(
        browser
            .next()
            .expect("downgraded browser flow emits a device prompt")
            .expect("device prompt succeeds"),
        AuthEvent::DeviceCode { .. }
    ));
    browser_cancel.cancel();
    assert_clean_cancellation_tail(&browser.collect::<Vec<_>>());

    let mut none = upstream_events_with_capability(
        &client_stack,
        &address,
        InteractiveAuthCapability::None,
        None,
    )
    .await;
    assert_single_failed(&mut none, ErrorCode::AuthRequired);

    let cancel = CancellationToken::new();
    let mut headless = upstream_events_with_capability(
        &client_stack,
        &address,
        InteractiveAuthCapability::Headless,
        Some(cancel.clone()),
    )
    .await;
    match headless
        .next()
        .expect("headless flow emits a device-code event")
        .expect("headless auth event succeeds")
    {
        AuthEvent::DeviceCode { .. } => {}
        AuthEvent::OpenBrowser { .. } => {
            panic!("Headless capability must not open a browser flow")
        }
        other => panic!("Headless capability must select device flow, got {other:?}"),
    }
    cancel.cancel();
    let tail = headless.collect::<Vec<_>>();
    assert_clean_cancellation_tail(&tail);

    origin.task.abort();
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_inner_revocation_redrives_flow_on_next_request() {
    ensure_test_plugin_env();
    let inner_idp = FakeIdp::start_with_token("inner-bearer-002").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (origin, (_substrate_guard, registry, bindings, refresh_lock, secret_store)) =
        configured_http_oauth(&inner_idp, &state_root).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();

    let mut first_flow = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut first_flow);
    drop(first_flow);
    let first_row = refresh_lock
        .load_secret_token("http", "anonymous")
        .expect("load first persisted upstream credential")
        .expect("first flow persists a secret_tokens row");

    refresh_lock
        .delete_secret_token("http", "anonymous")
        .expect("simulate upstream revocation");
    assert!(
        refresh_lock
            .load_secret_token("http", "anonymous")
            .expect("check revoked upstream credential")
            .is_none(),
        "revocation must remove the durable credential row"
    );
    *inner_idp.access_token.lock().unwrap() = "inner-bearer-002-rotated".into();

    let mut second_flow = upstream_events(&client_stack, &address, None).await;
    finish_device_flow(&mut second_flow);
    drop(second_flow);

    let second_row = refresh_lock
        .load_secret_token("http", "anonymous")
        .expect("load re-persisted upstream credential")
        .expect("the re-driven flow must restore the secret_tokens row");
    assert_eq!(second_row.source_name, "upstream-idp");
    assert_eq!(second_row.secret_handle, first_row.secret_handle);
    assert!(second_row.expires_at_unix_ms.is_some());
    let rotated = secret_store
        .get("http", "anonymous", &second_row.secret_handle)
        .expect("read rotated upstream access token")
        .expect("the re-driven flow must replace the keyring access token");
    assert_eq!(rotated.as_bytes(), b"inner-bearer-002-rotated");

    origin.task.abort();
    shutdown_test_server(server).await;
}

/// Tonic 0.12 may deliver already-buffered non-terminal frames before dropping
/// the daemon's server-streaming response body. The broker couples that drop
/// to the Stack cancellation token: after those frames, client cancellation
/// closes cleanly (or yields one `Cancelled`) and ends the daemon `Auth` RPC
/// while its device flow is parked between polls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_tier_client_cancellation_tears_down_parked_upstream_auth() {
    ensure_test_plugin_env();
    // This fixture cannot grant during the assertion window: every device
    // token poll remains authorization_pending and the code lives for an hour.
    // Permit release therefore proves cancellation tore down the daemon flow.
    let inner_idp = FakeIdp::start_with_pending_device_flow("unused-after-cancel").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let (origin, (_substrate_guard, registry, bindings, _refresh_lock, _secret_store)) =
        configured_http_oauth(&inner_idp, &state_root).await;
    let (server, client_stack) =
        spawn_three_tier_http_client(registry, bindings, &origin.root).await;
    let address = origin.address.clone();
    let cancel = CancellationToken::new();
    let active_before = crate::active_upstream_auth_flows_for_test();

    let mut events = upstream_events(&client_stack, &address, Some(cancel.clone())).await;
    assert!(matches!(
        events
            .next()
            .expect("device flow emits a prompt")
            .expect("device prompt succeeds"),
        AuthEvent::DeviceCode { .. }
    ));
    assert_eq!(
        crate::active_upstream_auth_flows_for_test(),
        active_before + 1,
        "the parked daemon flow must hold one admission permit"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while inner_idp.poll_attempts_before_grant.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon flow must reach the indefinitely pending token endpoint");

    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let consumer = std::thread::Builder::new()
        .name("ovs-test-upstream-drain".into())
        .spawn(move || {
            let tail = events.collect::<Vec<_>>();
            let _ = done_tx.send(tail);
        })
        .expect("spawn blocking auth-event consumer");
    cancel.cancel();

    // `collect` consumes and drops the plugin's stream bridge before sending
    // this result; its Drop joins the internal client bridge worker.
    let tail = tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("client cancellation must terminate the blocking stream")
        .expect("auth-event consumer reports its tail");
    assert_clean_cancellation_tail(&tail);
    consumer.join().expect("the test drain thread must finish");

    tokio::time::timeout(Duration::from_secs(2), async {
        while crate::active_upstream_auth_flows_for_test() > active_before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client cancellation must join the daemon OAuth flow worker");

    origin.task.abort();
    shutdown_test_server(server).await;
}
