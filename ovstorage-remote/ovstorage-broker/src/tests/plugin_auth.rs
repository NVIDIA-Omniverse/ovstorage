// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end listener auth through the `mini-auth` test cdylib.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use ovstorage::{
    Body, ConfigValue, ConnectionConfig, ConnectionRequest, ErrorCode, Layer, Request,
    SecretBundle, StatOptions, StatRequest, WriteOptions,
};
use ovstorage_authz_context::{AuthCredential, Transport};

use super::*;
use crate::test_utils::workspace_plugin_dir;

const MINI_AUTH_KIND: &str = "mini-auth";
const MINI_WRAPPER_KIND: &str = "mini-wrapper";
const ALICE_PRINCIPAL: &str = "mini:bearer:616c696365";

fn auth_config(kind: &str) -> toml::Value {
    toml::Value::Table(toml::Table::from_iter([(
        "kind".to_string(),
        toml::Value::String(kind.to_string()),
    )]))
}

fn forwarded_auth_config(kind: &str, identity_header: &str) -> toml::Value {
    toml::Value::Table(toml::Table::from_iter([
        ("kind".to_string(), toml::Value::String(kind.to_string())),
        (
            "config".to_string(),
            toml::Value::Table(toml::Table::from_iter([(
                "forwarded_identity_header".to_string(),
                toml::Value::String(identity_header.to_string()),
            )])),
        ),
    ]))
}

fn context(bearer: &[u8]) -> RequestContext {
    RequestContext {
        credential: Some(AuthCredential::new(
            Some(bearer.to_vec()),
            Transport::Tcp {
                peer_addr: "127.0.0.1:4141".to_string(),
                tls_client_cert: None,
            },
        )),
        audit_id: None,
    }
}

async fn compose(root: &Path, auth_kind: &str) -> ovstorage::Result<BrokerStack> {
    let connection = ConnectionConfig::from_request(ConnectionRequest {
        backend_kind: "file".to_string(),
        config: HashMap::from([(
            "root".to_string(),
            ConfigValue::String(root.to_string_lossy().into_owned()),
        )]),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("plugin-auth-e2e".to_string()),
    });
    compose_connection(connection, auth_kind).await
}

async fn compose_connection(
    connection: ConnectionConfig,
    auth_kind: &str,
) -> ovstorage::Result<BrokerStack> {
    let stack_config = broker_stack_config(
        vec![connection],
        BrokerGraphOptions::default(),
        &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
    );

    // SAFETY: the broker build script stages this workspace's test-only
    // cdylibs in an isolated fixture directory.
    unsafe {
        BrokerStackBuilder::new()
            .plugin_dir(workspace_plugin_dir())
            .allow_test_plugins(true)
            .stack_config(stack_config)
            .listener_auth(
                Some(auth_config(auth_kind)),
                "plugin-auth-e2e",
                false,
                Vec::new(),
            )
            .build()
            .await
    }
}

#[tokio::test]
async fn cdylib_listener_auth_allows_denies_and_stamps_principal_down() {
    let root = tempfile::tempdir().unwrap();
    let broker = Broker::from_composed(compose(root.path(), MINI_AUTH_KIND).await.unwrap());
    let prefix = address_for_path(root.path());
    let allowed = address::join_relative(&prefix, "allowed.txt").unwrap();
    let denied = address::join_relative(&prefix, "denied.txt").unwrap();
    let alice = context(b"alice");

    broker
        .write(
            &alice,
            allowed.clone(),
            Body::Bytes(b"allowed".to_vec()),
            WriteOptions::default(),
        )
        .await
        .expect("mini-auth allows a non-sentinel credential");

    // `mini-auth` resolves the principal in the cdylib and stamps it DOWN
    // across the FFI; the in-stack attribution layer below the host boundary
    // records that stamped copy — the one routing, cache scoping, and
    // attribution read.
    let credential = alice.credential.as_ref().unwrap();
    let extensions = ovstorage_authz_layer::stamp_credential(Some(credential));
    let info = broker
        .stack()
        .stat(
            Request {
                extensions,
                input: StatRequest {
                    address: allowed,
                    options: StatOptions::default(),
                },
            },
            None,
        )
        .await
        .expect("allowed stat crosses plugin listener auth");
    assert_eq!(
        info.modified_by.as_deref(),
        Some(ALICE_PRINCIPAL),
        "the inner attribution layer observes mini-auth's DOWN-stamped principal"
    );

    let error = broker
        .write(
            &context(b"deny"),
            denied.clone(),
            Body::Bytes(b"must-not-reach-file".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);

    let error = broker
        .stat(&alice, denied, StatOptions::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::NotFound,
        "the denied write must not reach the inner file layer"
    );

    let error = broker.reload_auth_policy("unused").unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(error.message().contains(MINI_AUTH_KIND));
    assert!(error.message().contains("no policy hot-reload"));
    assert!(error.message().contains("SIGHUP rebuilds the host"));
}

#[tokio::test]
async fn cdylib_listener_auth_gates_backend_kind_discovery_with_credential_context() {
    let root = tempfile::tempdir().unwrap();
    let broker = Broker::from_composed(compose(root.path(), MINI_AUTH_KIND).await.unwrap());

    let kinds = broker
        .list_backend_kinds(&context(b"alice"))
        .await
        .expect("mini-auth receives and allows the discovery credential");
    assert!(
        kinds.iter().any(|kind| kind.kind == "file"),
        "authorized discovery returns the captured backend-kind set"
    );

    let error = broker
        .list_backend_kinds(&context(b"deny"))
        .await
        .expect_err("mini-auth receives and denies the sentinel credential");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);

    let error = broker
        .list_backend_kinds(&RequestContext {
            credential: None,
            audit_id: None,
        })
        .await
        .expect_err("backend-kind discovery remains authenticated");
    assert_eq!(error.code(), ErrorCode::AuthRequired);
}

#[tokio::test(flavor = "multi_thread")]
async fn cdylib_listener_auth_denies_open_only_write_before_body_drain() {
    let root = tempfile::tempdir().unwrap();
    let broker = Arc::new(Broker::from_composed(
        compose(root.path(), MINI_AUTH_KIND).await.unwrap(),
    ));
    let prefix = address_for_path(root.path());
    let denied = address::join_relative(&prefix, "denied-open-only.bin").unwrap();
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<pb::WriteRequest>(1);
    tx.send(pb::WriteRequest {
        step: Some(pb::write_request::Step::Open(pb::WriteOpen {
            address: ovstorage_broker_protocol::object_address_to_proto(&denied),
            options: None,
        })),
    })
    .await
    .unwrap();
    // Keep `tx` alive: a regressed handler that drains before plugin auth waits
    // forever for a Chunk or EOF instead of returning the denial.
    let mut request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
    request
        .metadata_mut()
        .insert("authorization", "Bearer deny".parse().unwrap());

    let response = tokio::time::timeout(std::time::Duration::from_secs(5), client.write(request))
        .await
        .expect("plugin auth did not reject the Open-only write before body drain");
    drop(tx);
    let error = response.expect_err("mini-auth deny sentinel must reject the write");
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(!root.path().join("denied-open-only.bin").exists());

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cdylib_listener_auth_lazy_grpc_write_allows_authenticated_chunks() {
    let root = tempfile::tempdir().unwrap();
    let broker = Arc::new(Broker::from_composed(
        compose(root.path(), MINI_AUTH_KIND).await.unwrap(),
    ));
    let prefix = address_for_path(root.path());
    let allowed = address::join_relative(&prefix, "allowed-stream.bin").unwrap();
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let payload = b"authenticated plugin stream".to_vec();
    let frames = vec![
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Open(pb::WriteOpen {
                address: ovstorage_broker_protocol::object_address_to_proto(&allowed),
                options: None,
            })),
        },
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Chunk(payload.clone())),
        },
    ];
    let mut request = tonic::Request::new(tokio_stream::iter(frames));
    request
        .metadata_mut()
        .insert("authorization", "Bearer alice".parse().unwrap());
    let mut responses = client.write(request).await.unwrap().into_inner();
    let response = responses
        .message()
        .await
        .unwrap()
        .expect("authenticated plugin write response");
    assert!(matches!(
        response.step,
        Some(pb::write_response::Step::Done(_))
    ));
    assert_eq!(
        std::fs::read(root.path().join("allowed-stream.bin")).unwrap(),
        payload
    );

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cdylib_listener_auth_restores_small_replayable_writes_after_admission() {
    let connection = ConnectionConfig::from_request(ConnectionRequest {
        backend_kind: "test".to_string(),
        config: HashMap::from([
            (
                "test_root".to_string(),
                ConfigValue::String("test://plugin-auth/".to_string()),
            ),
            (
                "test_caps_disable".to_string(),
                ConfigValue::String("write_stream,write_redirect".to_string()),
            ),
            (
                "test_inject_error_on".to_string(),
                ConfigValue::String("write".to_string()),
            ),
            (
                "test_inject_error_code".to_string(),
                ConfigValue::String("Transient".to_string()),
            ),
            ("test_inject_error_count".to_string(), ConfigValue::Int(1)),
        ]),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("plugin-auth-byte-only".to_string()),
    });
    let broker = Arc::new(Broker::from_composed(
        compose_connection(connection, MINI_AUTH_KIND)
            .await
            .unwrap(),
    ));
    let small = ovstorage::address::parse("test://plugin-auth/small.bin").unwrap();
    let empty = ovstorage::address::parse("test://plugin-auth/empty.bin").unwrap();
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let mut small_request = tonic::Request::new(tokio_stream::iter(vec![
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Open(pb::WriteOpen {
                address: ovstorage_broker_protocol::object_address_to_proto(&small),
                options: None,
            })),
        },
        pb::WriteRequest {
            step: Some(pb::write_request::Step::Chunk(vec![0x2a])),
        },
    ]));
    small_request
        .metadata_mut()
        .insert("authorization", "Bearer alice".parse().unwrap());
    let mut small_responses = client.write(small_request).await.unwrap().into_inner();
    assert!(matches!(
        small_responses.message().await.unwrap().unwrap().step,
        Some(pb::write_response::Step::Done(_))
    ));

    // Open followed by EOF is a valid zero-byte write. It must also arrive at
    // this backend as Bytes because the backend intentionally advertises
    // buffered writes but no write-stream support.
    let mut empty_request = tonic::Request::new(tokio_stream::iter(vec![pb::WriteRequest {
        step: Some(pb::write_request::Step::Open(pb::WriteOpen {
            address: ovstorage_broker_protocol::object_address_to_proto(&empty),
            options: None,
        })),
    }]));
    empty_request
        .metadata_mut()
        .insert("authorization", "Bearer alice".parse().unwrap());
    let mut empty_responses = client.write(empty_request).await.unwrap().into_inner();
    assert!(matches!(
        empty_responses.message().await.unwrap().unwrap().step,
        Some(pb::write_response::Step::Done(_))
    ));

    let alice = context(b"alice");
    assert_eq!(
        broker
            .stat(&alice, small, StatOptions::default())
            .await
            .unwrap()
            .size,
        Some(1),
        "the first transient buffered write must be replayed and committed"
    );
    assert_eq!(
        broker
            .stat(&alice, empty, StatOptions::default())
            .await
            .unwrap()
            .size,
        Some(0)
    );

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cdylib_listener_auth_health_probes_auth_free_inner_stack() {
    let root = tempfile::tempdir().unwrap();
    let broker = Arc::new(Broker::from_composed(
        compose(root.path(), MINI_AUTH_KIND).await.unwrap(),
    ));
    assert!(broker.health().is_ok());

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

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_tcp_listener_supplies_trusted_forwarded_headers_to_plugin_auth() {
    let root = tempfile::tempdir().unwrap();
    let broker = Arc::new(Broker::from_composed(
        compose(root.path(), MINI_AUTH_KIND).await.unwrap(),
    ));
    let listener = BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: None,
        trusted_proxy: true,
        trusted_peers: vec!["127.0.0.0/8".into()],
        auth: Some(forwarded_auth_config(
            MINI_AUTH_KIND,
            "x-authenticated-user",
        )),
    };
    let server = spawn_broker_grpc_tcp_listener_with_config(
        broker,
        "127.0.0.1:0".parse().unwrap(),
        &listener,
    )
    .expect("plugin-auth listener config must not enter built-in header parsing");
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let mut allowed = tonic::Request::new(pb::ListAddressRootsRequest {});
    allowed
        .metadata_mut()
        .insert("x-authenticated-user", "alice".parse().unwrap());
    allowed
        .metadata_mut()
        .insert("x-unconfigured-user", "deny".parse().unwrap());
    client
        .list_address_roots(allowed)
        .await
        .expect("the trusted TCP listener forwards selected identity metadata to mini-auth");

    let mut denied = tonic::Request::new(pb::ListAddressRootsRequest {});
    denied
        .metadata_mut()
        .insert("x-authenticated-user", "deny".parse().unwrap());
    let error = client
        .list_address_roots(denied)
        .await
        .expect_err("mini-auth forwarded-identity deny sentinel must remain authoritative");
    assert_eq!(error.code(), tonic::Code::PermissionDenied);

    let mut duplicate = tonic::Request::new(pb::ListAddressRootsRequest {});
    duplicate
        .metadata_mut()
        .append("x-authenticated-user", "alice".parse().unwrap());
    duplicate
        .metadata_mut()
        .append("x-authenticated-user", "mallory".parse().unwrap());
    let error = client
        .list_address_roots(duplicate)
        .await
        .expect_err("mini-auth must observe and reject duplicate forwarded identity metadata");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_tcp_listener_rejects_untrusted_peer_before_plugin_auth() {
    let root = tempfile::tempdir().unwrap();
    let broker = Arc::new(Broker::from_composed(
        compose(root.path(), MINI_AUTH_KIND).await.unwrap(),
    ));
    let listener = BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: None,
        trusted_proxy: true,
        trusted_peers: vec!["10.0.0.0/8".into()],
        auth: Some(forwarded_auth_config(
            MINI_AUTH_KIND,
            "x-authenticated-user",
        )),
    };
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
        .insert("x-authenticated-user", "alice".parse().unwrap());

    let error = client
        .list_address_roots(request)
        .await
        .expect_err("a direct peer outside trusted_peers must fail before plugin auth");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    shutdown_test_server(server).await;
}

#[tokio::test]
async fn ordinary_cdylib_wrapper_cannot_be_selected_as_listener_auth() {
    let root = tempfile::tempdir().unwrap();
    let error = compose(root.path(), MINI_WRAPPER_KIND)
        .await
        .err()
        .expect("non-auth-capable plugin wrapper must fail closed");

    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains(MINI_WRAPPER_KIND));
    assert!(error.message().contains(MINI_AUTH_KIND));
}
