// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ovstorage::auth::flow::test_support::FakeIdp;
use ovstorage::auth::{AuthRefreshLock, OAuthCredentialProvider, OAuthStrategy};
use ovstorage::ext::LayerExt as _;
use ovstorage::{ConfigValue, ConnectionRequest, SecretBundle};

fn sqlite_store(state_root: &std::path::Path) -> Arc<dyn ovstorage::auth::SecretStore> {
    Arc::new(ovstorage::auth::SqliteSecretStore::open(state_root).expect("open sqlite store"))
}

const TEST_CLIENT_CA_PEM: &[u8] = include_bytes!("fixtures/client-ca.crt");
const TEST_CLIENT_CERT_PEM: &[u8] = include_bytes!("fixtures/client.crt");
const TEST_CLIENT_KEY_PEM: &[u8] = include_bytes!("fixtures/client.key");

#[test]
fn malformed_client_ca_is_rejected_before_the_server_thread_starts() {
    let error = crate::grpc::validate_client_ca_pem(
        b"this is not a certificate",
        std::path::Path::new("client-ca.pem"),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("contains no certificates"));
}

/// Verifies address-space preservation end-to-end through the
/// broker → gRPC → broker → file-plugin chain.
///
/// The client overlays an alias `bucket://app/` → `file:/tmp/...` on
/// the broker-served file route. The broker protocol carries
/// `ObjectInfo` values, so returned addresses must stay in the user's
/// `bucket://app/` address space.
#[tokio::test]
async fn broker_chain_keeps_addresses_in_user_address_space() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let backend_prefix = address_for_path(&root);
    let alias_prefix = address::parse("bucket://app/").unwrap();

    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack_with(
        &discovery_url,
        BrokerClientStackOptions {
            aliases: vec![(alias_prefix.clone(), backend_prefix.clone())],
            ..Default::default()
        },
    )
    .await;

    let object_via_alias = address::join_relative(&alias_prefix, "hello.txt").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
        object_via_alias.clone(),
        Body::Bytes(b"hi".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();

    let listed = client
        .list_page(
            alias_prefix.clone(),
            ovstorage::ListOptions::default(),
            None,
        )
        .await
        .unwrap()
        .items;
    let entry = listed
        .iter()
        .find(|item| item.kind == ovstorage::ObjectKind::File)
        .expect("object entry present");
    assert_eq!(entry.address, object_via_alias);

    for item in &listed {
        let address_str = item.address.as_str();
        assert!(
            address_str.starts_with("bucket://app/"),
            "address {address_str} leaks backend-side prefix"
        );
        assert!(
            !address_str.contains("file://"),
            "address {address_str} leaks file backend prefix"
        );
    }

    shutdown_test_server(server).await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_grpc_round_trips_without_client_backend_plugin() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let object = address::join_relative(&prefix, "via-broker.txt").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
        object.clone(),
        Body::Bytes(b"brokered bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"brokered bytes");
    assert_eq!(info.size, Some(14));
    let listed = client
        .list_page(prefix.clone(), ovstorage::ListOptions::default(), None)
        .await
        .unwrap()
        .items;
    assert!(listed.iter().any(|item| item.address == object));
    ovstorage::ext::LayerExt::delete(
        &*client,
        object.clone(),
        ovstorage::DeleteOptions::default(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        ovstorage::ext::LayerExt::stat(&*client, object, ovstorage::StatOptions::default(), None,)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    shutdown_test_server(server).await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_health_reports_serving() {
    let broker = Arc::new(Broker::new(empty_broker_stack().await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = health_pb::health_client::HealthClient::new(channel);
    let response = client
        .check(health_pb::HealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.status,
        health_pb::health_check_response::ServingStatus::Serving as i32
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_tls_health_uses_configured_certificate() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let cert_path = root.join("broker.crt");
    let key_path = root.join("broker.key");
    std::fs::write(&cert_path, TEST_TLS_CERT_PEM).unwrap();
    std::fs::write(&key_path, TEST_TLS_KEY_PEM).unwrap();

    let broker = Arc::new(Broker::new(empty_broker_stack().await));
    let tls = BrokerListenerTlsConfig {
        cert_path,
        key_path,
        client_ca_path: None,
    };
    let server =
        spawn_broker_grpc_tcp_listener_with_tls(broker, "127.0.0.1:0".parse().unwrap(), Some(&tls))
            .unwrap();
    assert!(server.endpoint_url().starts_with("grpc+tls://"));

    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = health_pb::health_client::HealthClient::new(channel);
    let response = client
        .check(health_pb::HealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.status,
        health_pb::health_check_response::ServingStatus::Serving as i32
    );

    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_mtls_gathers_verified_client_certificate() {
    const PRINCIPAL: &str =
        "mtls:sha256:8092648a1df6300d201a408a21628f92c2ae4ac4ab9caf46fe9052d2dc781f2f";
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let cert_path = root.join("broker.crt");
    let key_path = root.join("broker.key");
    let client_ca_path = root.join("client-ca.crt");
    std::fs::write(&cert_path, TEST_TLS_CERT_PEM).unwrap();
    std::fs::write(&key_path, TEST_TLS_KEY_PEM).unwrap();
    std::fs::write(&client_ca_path, TEST_CLIENT_CA_PEM).unwrap();

    let mut auth_config = ovstorage::LayerConfig::new();
    auth_config.insert(
        ovstorage_authz_layer::POLICY_CONFIG_KEY.into(),
        ConfigValue::Toml(format!(
            r#"
[[policy]]
id = "mtls-all"
effect = "allow"
principal = "{PRINCIPAL}"
operations = ["*"]
prefix = "*"
"#,
        )),
    );
    auth_config.insert(
        ovstorage_authz_layer::AUTHN_MODE_CONFIG_KEY.into(),
        ConfigValue::String("mtls".into()),
    );
    let broker = Arc::new(
        BrokerStackFixture::new()
            .auth_config(auth_config)
            .build_broker()
            .await,
    );
    let listener = BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: Some(BrokerListenerTlsConfig {
            cert_path,
            key_path,
            client_ca_path: Some(client_ca_path),
        }),
        trusted_proxy: false,
        trusted_peers: Vec::new(),
        auth: Some(
            r#"
kind = "builtin-auth"
[config]
authn_mode = "mtls"
"#
            .parse()
            .unwrap(),
        ),
    };
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();

    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
        .identity(tonic::transport::Identity::from_pem(
            TEST_CLIENT_CERT_PEM,
            TEST_CLIENT_KEY_PEM,
        ))
        .domain_name("localhost");
    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    client
        .list_address_roots(tonic::Request::new(pb::ListAddressRootsRequest {}))
        .await
        .expect("verified client cert principal is authorized");

    let missing_client_cert_channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut missing_client_cert_client =
        pb::broker_service_client::BrokerServiceClient::new(missing_client_cert_channel);
    let missing_client_cert = missing_client_cert_client
        .list_address_roots(tonic::Request::new(pb::ListAddressRootsRequest {}))
        .await;
    assert!(
        missing_client_cert.is_err(),
        "mTLS listener must reject a client that presents no certificate"
    );

    let unrelated_client_cert_channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
                    .identity(tonic::transport::Identity::from_pem(
                        TEST_TLS_CERT_PEM,
                        TEST_TLS_KEY_PEM,
                    ))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut unrelated_client_cert_client =
        pb::broker_service_client::BrokerServiceClient::new(unrelated_client_cert_channel);
    assert!(
        unrelated_client_cert_client
            .list_address_roots(tonic::Request::new(pb::ListAddressRootsRequest {}))
            .await
            .is_err(),
        "mTLS listener must reject a client signed by an unrelated CA"
    );

    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_trusted_forwarded_headers_enforces_peer_and_rejects_duplicates() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let cert_path = root.join("broker.crt");
    let key_path = root.join("broker.key");
    std::fs::write(&cert_path, TEST_TLS_CERT_PEM).unwrap();
    std::fs::write(&key_path, TEST_TLS_KEY_PEM).unwrap();
    let mut listener = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"
trusted_proxy = true
trusted_peers = ["127.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "x-authenticated-user"

[listener.auth.config.policy]
[[listener.auth.config.policy.policy]]
id = "alice-all"
effect = "allow"
principal = "alice"
operations = ["*"]
prefix = "*"
"#,
    )
    .unwrap()
    .listener
    .unwrap();
    listener.tls = Some(BrokerListenerTlsConfig {
        cert_path,
        key_path,
        client_ca_path: None,
    });
    let auth_config = broker_listener_auth_preflight(Some(&listener))
        .unwrap()
        .into_builtin_config()
        .unwrap();
    let broker = Arc::new(
        BrokerStackFixture::new()
            .auth_config(auth_config)
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let mut request = tonic::Request::new(pb::ListAddressRootsRequest {});
    request
        .metadata_mut()
        .insert("x-authenticated-user", "alice".parse().unwrap());
    client
        .list_address_roots(request)
        .await
        .expect("allowlisted proxy identity is authorized");

    let mut duplicate = tonic::Request::new(pb::ListAddressRootsRequest {});
    duplicate
        .metadata_mut()
        .append("x-authenticated-user", "alice".parse().unwrap());
    duplicate
        .metadata_mut()
        .append("x-authenticated-user", "mallory".parse().unwrap());
    assert_eq!(
        client
            .list_address_roots(duplicate)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );

    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_trusted_forwarded_headers_rejects_an_unallowlisted_peer() {
    // The peer gate's REJECT path, end to end. The allowlist excludes loopback,
    // so a loopback caller presenting a well-formed identity header must still
    // be `Unauthenticated` — proving the operator's `trusted_peers` reaches the
    // runtime gate through the host-injected `__host_trusted_peers` key, not
    // just that the gate works when handed a CIDR directly.
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let cert_path = root.join("broker.crt");
    let key_path = root.join("broker.key");
    std::fs::write(&cert_path, TEST_TLS_CERT_PEM).unwrap();
    std::fs::write(&key_path, TEST_TLS_KEY_PEM).unwrap();
    let mut listener = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"
trusted_proxy = true
trusted_peers = ["10.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "x-authenticated-user"

[listener.auth.config.policy]
[[listener.auth.config.policy.policy]]
id = "alice-all"
effect = "allow"
principal = "alice"
operations = ["*"]
prefix = "*"
"#,
    )
    .unwrap()
    .listener
    .unwrap();
    listener.tls = Some(BrokerListenerTlsConfig {
        cert_path,
        key_path,
        client_ca_path: None,
    });
    let auth_config = broker_listener_auth_preflight(Some(&listener))
        .unwrap()
        .into_builtin_config()
        .unwrap();
    let broker = Arc::new(
        BrokerStackFixture::new()
            .auth_config(auth_config)
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://{}", server.local_addr()))
            .unwrap()
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(TEST_TLS_CERT_PEM))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let mut request = tonic::Request::new(pb::ListAddressRootsRequest {});
    request
        .metadata_mut()
        .insert("x-authenticated-user", "alice".parse().unwrap());
    assert_eq!(
        client.list_address_roots(request).await.unwrap_err().code(),
        tonic::Code::Unauthenticated,
        "a loopback peer outside trusted_peers must be rejected"
    );

    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

#[test]
fn broker_gathers_raw_text_metadata_for_auth_layer_resolution() {
    let listener = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"
trusted_proxy = true
trusted_peers = ["127.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "X-Authenticated-User"
[listener.auth.config.forwarded_claim_headers]
team = "X-Authenticated-Team"
"#,
    )
    .unwrap()
    .listener
    .unwrap();
    validate_broker_config_for_startup(&BrokerConfig {
        listener: Some(listener.clone()),
        ..Default::default()
    })
    .unwrap();
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("x-authenticated-user", "alice".parse().unwrap());
    request
        .metadata_mut()
        .insert("x-authenticated-team", "rendering".parse().unwrap());
    request
        .metadata_mut()
        .insert("x-unconfigured-identity", "mallory".parse().unwrap());
    request
        .metadata_mut()
        .insert("authorization", "Bearer secret".parse().unwrap());

    let forwarded_config = crate::broker_listener_forwarded_header_config(Some(&listener)).unwrap();
    let credential = crate::grpc::gather_credential(
        crate::grpc::ListenerTransport::Tcp,
        &request,
        forwarded_config.as_ref(),
    );
    let forwarded = credential.forwarded.expect("text metadata gathered");
    assert!(
        forwarded
            .values
            .contains(&("x-authenticated-user".into(), "alice".into()))
    );
    assert!(
        forwarded
            .values
            .contains(&("x-authenticated-team".into(), "rendering".into()))
    );
    assert!(
        !forwarded
            .values
            .iter()
            .any(|(name, _)| name == "authorization")
    );
    assert!(
        !forwarded
            .values
            .iter()
            .any(|(name, _)| name == "x-unconfigured-identity")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_jwt_verify_validates_jwks_issuer_audience_and_signature() {
    // JWT authn lives in the broker's per-listener auth layer,
    // built from the OIDC params — not in a host-side listener authn mode. The
    // listener carries only the transport (TCP → `Tcp` credentials + bearer).
    let secret = b"abcdefghijklmnopqrstuvwxyz012345";
    let (jwks_url, shutdown) = spawn_test_jwks_server("test-key", secret);

    let broker = Arc::new(
        BrokerStackFixture::new()
            .jwt(crate::BrokerJwtParams {
                issuer: "https://issuer.test".into(),
                audience: "ovstorage-client".into(),
                jwks_url,
            })
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    client
        .list_address_roots(list_roots_request_with_bearer(signed_test_jwt(
            "alice",
            "https://issuer.test",
            "ovstorage-client",
            "test-key",
            secret,
            3600,
        )))
        .await
        .unwrap();

    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt(
            "alice",
            "https://issuer.test",
            "somebody-else",
            "test-key",
            secret,
            3600,
        ),
    )
    .await;
    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt(
            "alice",
            "https://wrong-issuer.test",
            "ovstorage-client",
            "test-key",
            secret,
            3600,
        ),
    )
    .await;
    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt(
            "alice",
            "https://issuer.test",
            "ovstorage-client",
            "test-key",
            secret,
            -3600,
        ),
    )
    .await;
    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt_with_nbf(
            "alice",
            "https://issuer.test",
            "ovstorage-client",
            "test-key",
            secret,
            3600,
            3600,
        ),
    )
    .await;
    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt(
            "alice",
            "https://issuer.test",
            "ovstorage-client",
            "missing-key",
            secret,
            3600,
        ),
    )
    .await;
    assert_list_roots_unauthenticated(
        &mut client,
        signed_test_jwt(
            "alice",
            "https://issuer.test",
            "ovstorage-client",
            "test-key",
            b"different-signing-secret-0123456789",
            3600,
        ),
    )
    .await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_rpc_threads_bearer_principal_and_audit_metadata() {
    let idp = FakeIdp::start_with_token("alice-upstream-access").await;
    let state_root = unique_temp_dir();
    std::fs::create_dir_all(&state_root).unwrap();
    let http_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let http_root =
        url::Url::parse(&format!("http://{}/", http_listener.local_addr().unwrap())).unwrap();
    let refresh_lock = Arc::new(AuthRefreshLock::open(&state_root).unwrap());
    let secret_store = sqlite_store(&state_root);
    let provider = Arc::new(OAuthCredentialProvider::new(
        "upstream-idp",
        "http",
        idp.endpoints(true),
        Arc::clone(&secret_store),
        Arc::clone(&refresh_lock),
        OAuthStrategy::Device,
    ));
    let providers =
        Arc::new(OAuthProviderRegistry::new().with_provider("upstream-idp", Arc::clone(&provider)));
    let bindings = BrokerOAuthRouteBindings::new().with_route(http_root.clone(), "upstream-idp");

    let jwt_secret = b"abcdefghijklmnopqrstuvwxyz012345";
    let (jwks_url, jwks_shutdown) = spawn_test_jwks_server("auth-key", jwt_secret);
    let broker = Arc::new(
        BrokerStackFixture::new()
            .connection(ConnectionRequest {
                backend_kind: "http".into(),
                config: HashMap::from([(
                    "root_url".into(),
                    ConfigValue::String(http_root.as_str().to_string()),
                )]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("authenticated HTTP route".into()),
            })
            .jwt(crate::BrokerJwtParams {
                issuer: "https://issuer.test".into(),
                audience: "ovstorage-client".into(),
                jwks_url,
            })
            .oauth(providers, bindings)
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let token = signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-client",
        "auth-key",
        jwt_secret,
        3_600,
    );
    let address = http_root.join("private/object.bin").unwrap();

    let auth_request = |capability: &str, audit_id: &str| {
        let mut request = tonic::Request::new(pb::AuthRequest {
            address: ovstorage_broker_protocol::object_address_to_proto(&address),
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request.metadata_mut().insert(
            ovstorage_broker_protocol::X_OV_IAUTH,
            capability.parse().unwrap(),
        );
        request
            .metadata_mut()
            .insert(crate::grpc::X_OV_AUDIT_ID, audit_id.parse().unwrap());
        request
    };

    // A terminal failure exercises the actual handler's context handoff to
    // the relay; the correlation value must come from this RPC's metadata.
    let mut failed = client
        .auth(auth_request("none", "audit-auth-rpc-7"))
        .await
        .unwrap()
        .into_inner();
    let frame = failed
        .message()
        .await
        .unwrap()
        .expect("None capability yields one failed event");
    let pb::auth_event_envelope::Event::Failed(failed_event) = frame.event.unwrap() else {
        panic!("None capability must yield Failed");
    };
    let detail = failed_event.error.expect("Failed carries ErrorDetail");
    assert_eq!(detail.audit_id, "audit-auth-rpc-7");
    assert!(failed.message().await.unwrap().is_none());

    // The same live RPC path must pass the bearer into the built-in auth layer,
    // whose JWT subject selects the durable upstream-credential slot.
    let mut events = client
        .auth(auth_request("headless", "audit-auth-rpc-8"))
        .await
        .unwrap()
        .into_inner();
    let mut succeeded = false;
    while let Some(frame) = events.message().await.unwrap() {
        match frame.event.expect("auth frame carries an event") {
            pb::auth_event_envelope::Event::Succeeded(_) => {
                succeeded = true;
                break;
            }
            pb::auth_event_envelope::Event::Failed(event) => {
                panic!("device flow failed: {:?}", event.error)
            }
            _ => {}
        }
    }
    assert!(succeeded, "device flow must reach Succeeded");
    assert!(
        refresh_lock
            .load_secret_token("http", "alice")
            .unwrap()
            .is_some(),
        "the handler must preserve bearer metadata so JWT sub selects Alice's slot"
    );
    assert!(
        refresh_lock
            .load_secret_token("http", "anonymous")
            .unwrap()
            .is_none(),
        "authenticated callers must never fall back to the anonymous slot"
    );
    assert_eq!(
        secret_store
            .get("http", "alice", "oauth/upstream-idp")
            .unwrap()
            .expect("Alice's upstream bearer is persisted")
            .as_bytes(),
        b"alice-upstream-access"
    );

    drop(events);
    shutdown_test_server(server).await;
    let _ = jwks_shutdown.send(());
    remove_dir_all_retry(state_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_rejects_chunk_before_open() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let stream = tokio_stream::iter(vec![pb::WriteRequest {
        step: Some(pb::write_request::Step::Chunk(b"orphan".to_vec())),
    }]);
    let err = client.write(tonic::Request::new(stream)).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_rejects_duplicate_open() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let object = address::join_relative(&prefix, "dup-open.txt").unwrap();
    let open = pb::WriteRequest {
        step: Some(pb::write_request::Step::Open(pb::WriteOpen {
            address: ovstorage_broker_protocol::object_address_to_proto(&object),
            options: None,
        })),
    };
    let stream = tokio_stream::iter(vec![open.clone(), open]);
    let err = client.write(tonic::Request::new(stream)).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}

/// Reject-before-drain: an unauthorized write is denied before any `Chunk`
/// is consumed. The broker's typed built-in-auth preflight evaluates `Write`
/// directly; it does not issue a host-side `check_access(write)` probe. The
/// test sends Open and holds the stream open, so draining before authorization
/// would block waiting for chunks and fire the timeout.
#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_rejects_unauthorized_caller_before_consuming_chunks() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    // The retained built-in auth layer (deny-all policy) rejects `Write` on the
    // address before the body stream is drained.
    let broker = Arc::new(
        BrokerStackFixture::new()
            .file(&root)
            .authz(DENY_ALL_POLICY)
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let object = address::join_relative(&prefix, "denied.bin").unwrap();
    let open = pb::WriteRequest {
        step: Some(pb::write_request::Step::Open(pb::WriteOpen {
            address: ovstorage_broker_protocol::object_address_to_proto(&object),
            options: None,
        })),
    };

    // Sender stays alive so the request stream never closes; a broker
    // that drains chunks before authz blocks here forever.
    let (tx, rx) = tokio::sync::mpsc::channel::<pb::WriteRequest>(2);
    tx.send(open).await.unwrap();
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.write(tonic::Request::new(stream)),
    )
    .await
    .expect(
        "broker did not respond within 5s — authz pre-flight regressed; \
         the broker is buffering chunks before deciding authz",
    );
    drop(tx);

    let err = response.expect_err("expected PermissionDenied, got success");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}

/// A principal granted `write` but NOT `check_access` writes successfully.
/// The deleted host-side `check_access(write)` probe FALSE-CLOSED here: the
/// in-stack authz Layer gates the `check_access` SPI call on the separate
/// `check_access` operation, so the probe saw `PermissionDenied` (denied the
/// pre-check, not the write) and rejected a writer who was in fact authorized
/// to write. With the probe gone the write routes straight to the in-stack
/// `Write` gate — which allows it. (Pre-fix this test fails with
/// PermissionDenied.)
#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_allows_writer_without_check_access_permission() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "writable.bin").unwrap();
    // Allow every op (`write` included) but deny `check_access` on the target:
    // the longer object-URL prefix wins over the `*` allow for `check_access`,
    // so the principal can write but cannot run a `check_access` pre-check.
    let policy = format!(
        r#"
[[policy]]
id = "allow-all"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"

[[policy]]
id = "deny-check-access"
effect = "deny"
principal = "*"
operations = ["check_access"]
prefix = "{object}"
"#
    );
    let broker = Arc::new(
        BrokerStackFixture::new()
            .file(&root)
            .authz(policy)
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let payload = b"writer-without-check-access".to_vec();
    let frames = vec![
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Open(pb::WriteOpen {
                address: ovstorage_broker_protocol::object_address_to_proto(&object),
                options: None,
            })),
        },
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Chunk(payload.clone())),
        },
    ];
    let mut responses = client
        .write(tonic::Request::new(tokio_stream::iter(frames)))
        .await
        .expect("a writer with `write` but not `check_access` must be allowed to write")
        .into_inner();
    let response = responses
        .message()
        .await
        .expect("write response stream")
        .expect("a write response frame");
    assert!(
        matches!(response.step, Some(pb::write_response::Step::Done(_))),
        "expected a terminal Done write response, got {:?}",
        response.step
    );

    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}

/// A chunk-pull error mid-stream must cancel the broker write rather
/// than commit the bytes seen so far. The body iterator yields a few
/// real chunks, then yields an `Err`. The broker surfaces that
/// captured error to the caller; the broker server, having seen
/// RST_STREAM on the request half rather than a graceful EOF, must
/// not dispatch to the backend — a follow-up `stat` returns NotFound.
#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_aborts_on_chunk_pull_error() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let object = address::join_relative(&prefix, "aborted.bin").unwrap();

    let chunks: Vec<ovstorage_plugin::Result<Vec<u8>>> = vec![
        Ok(vec![1u8; 4 * 1024]),
        Ok(vec![2u8; 4 * 1024]),
        Err(ovstorage_plugin::Error::new(
            ErrorCode::Internal,
            "test chunk-pull error",
        )),
    ];
    let stream = ovstorage_plugin::BodyStream::from_iter(chunks.into_iter());
    let err = ovstorage::ext::LayerExt::write(
        &*client,
        object.clone(),
        Body::Stream(stream),
        WriteOptions::default(),
        None,
    )
    .await
    .expect_err("write must propagate the chunk-pull error");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(
        err.message().contains("test chunk-pull error"),
        "expected captured error to surface, got: {}",
        err.message()
    );

    let stat_err =
        ovstorage::ext::LayerExt::stat(&*client, object, ovstorage::StatOptions::default(), None)
            .await
            .expect_err("broker must not commit a cancelled write");
    assert_eq!(stat_err.code(), ErrorCode::NotFound);

    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}
