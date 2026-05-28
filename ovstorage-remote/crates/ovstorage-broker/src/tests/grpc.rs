// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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

    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    let mut config = HashMap::new();
    config.insert("address".into(), ConfigValue::String(discovery_url.clone()));
    client
        .add_connection(
            ConnectionRequest {
                backend_kind: "broker".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("broker".into()),
            },
            None,
        )
        .await
        .unwrap();
    client
        .add_alias(ovstorage::AliasRequest {
            from: alias_prefix.clone(),
            to: backend_prefix.clone(),
            visibility: ovstorage::AddressVisibility::Visible,
            persist: false,
            display_name: Some("user-facing".into()),
            user_metadata: ovstorage::UserMetadata::new(),
        })
        .unwrap();

    let object_via_alias = address::join_relative(&alias_prefix, "hello.txt").unwrap();
    client
        .write(
            object_via_alias.clone(),
            Body::Bytes(b"hi".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let listed = client
        .list(
            alias_prefix.clone(),
            ovstorage::ListOptions::default(),
            None,
        )
        .await
        .unwrap();
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
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    let mut config = HashMap::new();
    config.insert("address".into(), ConfigValue::String(discovery_url.clone()));
    client
        .add_connection(
            ConnectionRequest {
                backend_kind: "broker".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("broker".into()),
            },
            None,
        )
        .await
        .unwrap();

    let object = address::join_relative(&prefix, "via-broker.txt").unwrap();
    client
        .write(
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
        .list(prefix.clone(), ovstorage::ListOptions::default(), None)
        .await
        .unwrap();
    assert!(listed.iter().any(|item| item.address == object));
    client
        .delete(object.clone(), ovstorage::DeleteOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(
        client
            .stat(object, ovstorage::StatOptions::default(), None)
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
    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
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

    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
    let tls = BrokerListenerTlsConfig {
        cert_path,
        key_path,
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
async fn broker_grpc_trusted_forwarded_headers_authenticates_request() {
    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
    let listener = test_listener_config(BrokerAuthnMode::TrustedForwardedHeaders);
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let missing = client
        .list_address_roots(pb::ListAddressRootsRequest {})
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::Unauthenticated);

    let mut request = tonic::Request::new(pb::ListAddressRootsRequest {});
    request
        .metadata_mut()
        .insert("x-forwarded-user", "alice".parse().unwrap());
    client.list_address_roots(request).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_trusted_unsigned_jwt_authenticates_and_checks_time() {
    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
    let listener = test_listener_config(BrokerAuthnMode::TrustedUnsignedJwt);
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let mut valid = tonic::Request::new(pb::ListAddressRootsRequest {});
    valid.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", unsigned_test_jwt("alice", 3600))
            .parse()
            .unwrap(),
    );
    client.list_address_roots(valid).await.unwrap();

    let mut expired = tonic::Request::new(pb::ListAddressRootsRequest {});
    expired.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", unsigned_test_jwt("alice", -3600))
            .parse()
            .unwrap(),
    );
    let error = client.list_address_roots(expired).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_jwt_verify_validates_jwks_issuer_audience_and_signature() {
    let secret = b"abcdefghijklmnopqrstuvwxyz012345";
    let (jwks_url, shutdown) = spawn_test_jwks_server("test-key", secret);
    let mut listener = test_listener_config(BrokerAuthnMode::JwtVerify);
    let authn = listener.authn.as_mut().expect("test listener has authn");
    authn.issuer = Some("https://issuer.test".into());
    authn.audience = Some("ovstorage-client".into());
    authn.jwks_url = Some(jwks_url);

    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_trusted_peer_cidr_rejects_unallowed_loopback() {
    // TEST-NET-1 (192.0.2.0/24) excludes loopback; listener must
    // reject before consulting the forwarded-identity header.
    let broker = Arc::new(Broker::new(build_default_library_for_test().await));
    let mut listener = test_listener_config(BrokerAuthnMode::TrustedForwardedHeaders);
    listener.trusted_peers = vec!["192.0.2.0/24".into()];
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);
    let mut request = tonic::Request::new(pb::ListAddressRootsRequest {});
    request
        .metadata_mut()
        .insert("x-forwarded-user", "alice".parse().unwrap());
    let err = client.list_address_roots(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_rejects_chunk_before_open() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
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
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
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

/// Publish-before-durable: authz must run on the `Open` frame before
/// any `Chunk` is consumed. Test sends Open + holds the stream open;
/// fixed broker returns PermissionDenied immediately, regressed broker
/// blocks waiting for chunks and the timeout fires.
#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_rejects_unauthorized_caller_before_consuming_chunks() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::with_authorizer(
        broker_library,
        Arc::new(DenyAllAuthorizer),
    ));
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
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

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
    let err = client
        .write(
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

    let stat_err = client
        .stat(object, ovstorage::StatOptions::default(), None)
        .await
        .expect_err("broker must not commit a cancelled write");
    assert_eq!(stat_err.code(), ErrorCode::NotFound);

    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}
