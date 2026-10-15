// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loopback gRPC coverage for the broker-native watch admission chokepoint.

use super::*;
use crate::watch_limit::DEFAULT_MAX_WATCHES_PER_PRINCIPAL;

const JWT_SECRET: &[u8] = b"watch-limit-test-secret-0123456789";
const JWT_ISSUER: &str = "https://watch-limit.test";
const JWT_AUDIENCE: &str = "ovstorage-watch-limit";
const JWT_KID: &str = "watch-limit-key";
const TWO_PRINCIPAL_POLICY: &str = r#"
[[policy]]
id = "alice-watch"
effect = "allow"
principal = "alice"
operations = ["watch_directory", "read"]
prefix = "*"

[[policy]]
id = "bob-watch"
effect = "allow"
principal = "bob"
operations = ["watch_directory", "read"]
prefix = "*"
"#;

type GrpcClient = pb::broker_service_client::BrokerServiceClient<tonic::transport::Channel>;
type GrpcWatch = tonic::Streaming<pb::WatchDirectoryResponse>;

/// Keep each synthetic stream alive after its configured events so tests model
/// the blocking watch iterators used by real backends.
fn watch_test_cfg(event_count: i64) -> HashMap<String, ConfigValue> {
    HashMap::from([
        ("test_caps".into(), ConfigValue::String("full".into())),
        ("test_watch_keep_alive".into(), ConfigValue::Bool(true)),
        (
            "test_watch_event_count".into(),
            ConfigValue::Int(event_count),
        ),
        ("test_watch_emit_interval_ms".into(), ConfigValue::Int(20)),
    ])
}

fn test_connection(root: &str, event_count: i64) -> ConnectionRequest {
    let mut config = watch_test_cfg(event_count);
    config.insert("test_root".into(), ConfigValue::String(root.into()));
    ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some(root.into()),
    }
}

async fn authenticated_broker(
    fixture: BrokerStackFixture,
) -> (BrokerGrpcServer, oneshot::Sender<()>) {
    let (jwks_url, jwks_shutdown) = spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let broker = Arc::new(
        fixture
            .authz(TWO_PRINCIPAL_POLICY)
            .jwt(crate::BrokerJwtParams {
                issuer: JWT_ISSUER.into(),
                audience: JWT_AUDIENCE.into(),
                jwks_url,
            })
            .build_broker()
            .await,
    );
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    (server, jwks_shutdown)
}

async fn grpc_client(server: &BrokerGrpcServer) -> GrpcClient {
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    GrpcClient::new(channel)
}

fn bearer(subject: &str) -> String {
    signed_test_jwt(subject, JWT_ISSUER, JWT_AUDIENCE, JWT_KID, JWT_SECRET, 3600)
}

fn watch_request(subject: Option<&str>, prefix: &str) -> tonic::Request<pb::WatchDirectoryRequest> {
    let mut request = tonic::Request::new(pb::WatchDirectoryRequest {
        prefix: prefix.into(),
        recursive: true,
        include_metadata_changes: true,
        since: Vec::new(),
        poll_interval_millis: 10,
    });
    if let Some(subject) = subject {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", bearer(subject)).parse().unwrap(),
        );
    }
    request
}

async fn open_watch(
    client: &mut GrpcClient,
    subject: Option<&str>,
    prefix: &str,
) -> Result<GrpcWatch, tonic::Status> {
    client
        .watch_directory(watch_request(subject, prefix))
        .await
        .map(tonic::Response::into_inner)
}

fn assert_resource_exhausted(status: tonic::Status) {
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    let error = ovstorage_broker_protocol::status_to_error(status);
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    assert!(
        error.code().retryable(),
        "ResourceExhausted must retain its retryable bucket over gRPC"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_limit_is_global_per_principal_across_client_connections() {
    const K: usize = 2;
    let (server, jwks_shutdown) = authenticated_broker(
        BrokerStackFixture::new()
            .test_backend(watch_test_cfg(20))
            .watch_limits(K, 16),
    )
    .await;
    let mut alice_first_connection = grpc_client(&server).await;
    let mut alice_second_connection = grpc_client(&server).await;
    let mut bob_connection = grpc_client(&server).await;

    let alice_first = open_watch(&mut alice_first_connection, Some("alice"), "test://demo/")
        .await
        .unwrap();
    let alice_second = open_watch(&mut alice_second_connection, Some("alice"), "test://demo/")
        .await
        .unwrap();
    let rejected = open_watch(&mut alice_first_connection, Some("alice"), "test://demo/")
        .await
        .unwrap_err();
    assert_resource_exhausted(rejected);

    let bob = open_watch(&mut bob_connection, Some("bob"), "test://demo/")
        .await
        .expect("bob has an isolated principal budget");

    drop((alice_first, alice_second, bob));
    drop((
        alice_first_connection,
        alice_second_connection,
        bob_connection,
    ));
    shutdown_test_server(server).await;
    let _ = jwks_shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_watch_readmits_the_same_principal() {
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(watch_test_cfg(0))
            .watch_limits(1, 8)
            .build_stack()
            .await,
    ));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client = grpc_client(&server).await;

    let first = open_watch(&mut client, None, "test://demo/")
        .await
        .expect("first anonymous physical watch is admitted");
    assert_resource_exhausted(
        open_watch(&mut client, None, "test://demo/")
            .await
            .expect_err("second anonymous physical watch exceeds the principal cap"),
    );
    drop(first);

    let readmitted = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match open_watch(&mut client, None, "test://demo/").await {
                Ok(candidate) => break candidate,
                Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(status) => panic!("unexpected readmission error: {status}"),
            }
        }
    })
    .await
    .expect("dropped watch releases its admission lease");

    drop(readmitted);
    drop(client);
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn misplaced_watch_limit_is_rejected_at_startup() {
    let error = match BrokerStackFixture::new()
        .test_backend(watch_test_cfg(20))
        .watch_limits(1, 8)
        .misplace_watch_limit()
        .try_build()
        .await
    {
        Ok(_) => panic!("broker must reject a misplaced watch_limit declaration"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("orphan_watch_limit"));
    assert!(error.message().contains("shared data-plane root"));
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_limit_is_shared_across_backend_connections() {
    let (server, jwks_shutdown) = authenticated_broker(
        BrokerStackFixture::new()
            .connection(test_connection("test://one/", 10))
            .connection(test_connection("test://two/", 10))
            .watch_limits(1, 8),
    )
    .await;
    let mut alice = grpc_client(&server).await;

    let first_backend = open_watch(&mut alice, Some("alice"), "test://one/")
        .await
        .unwrap();
    assert_resource_exhausted(
        open_watch(&mut alice, Some("alice"), "test://two/")
            .await
            .unwrap_err(),
    );

    drop(first_backend);
    drop(alice);
    shutdown_test_server(server).await;
    let _ = jwks_shutdown.send(());
}

#[tokio::test(flavor = "multi_thread")]
async fn omitted_watch_limit_is_injected_and_enforces_defaults() {
    let broker = BrokerStackFixture::new()
        .test_backend(watch_test_cfg(1))
        .omit_watch_limit()
        .build_broker()
        .await;
    let context = RequestContext::default();
    let prefix = Url::parse("test://demo/").unwrap();
    let options = WatchDirectoryOptions::default();
    let mut admitted = Vec::with_capacity(DEFAULT_MAX_WATCHES_PER_PRINCIPAL);

    // Exercise the broker Stack directly: the low-limit loopback tests above
    // cover gRPC status mapping, while opening the full default through tonic
    // would allocate one OS bridge thread per admitted watch and make this cap
    // assertion depend on the test host's thread budget.
    for _ in 0..DEFAULT_MAX_WATCHES_PER_PRINCIPAL {
        admitted.push(
            broker
                .watch_directory(&context, prefix.clone(), options.clone())
                .await
                .expect("default per-principal budget admits watches below its cap"),
        );
    }
    let error = match broker.watch_directory(&context, prefix, options).await {
        Ok(_) => panic!("watch beyond the default per-principal cap must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    assert!(error.code().retryable());

    drop(admitted);
}
