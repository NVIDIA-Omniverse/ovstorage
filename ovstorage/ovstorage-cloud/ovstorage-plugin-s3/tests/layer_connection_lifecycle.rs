// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-lifecycle coverage for the ABI-v2 `S3Layer` (RFC-0066):
//! the `ConnectionSet<S3Driver>` integration — add/probe/update/remove, the
//! lenient verify policy, parked-connection behavior, credential swaps
//! observed on the presign path, and the `Layer::list` fold+paginate contract
//! — all against a scripted local mock S3 endpoint (no real network).

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use futures::TryStreamExt;
use ovstorage_plugin::{
    AccessOps, AuthenticateRequest, BackendFactory, Body, CheckAccessRequest, ConfigValue,
    ConnectionAuthState, ConnectionKey, ConnectionRequest, ErrorCode, InteractiveAuthCapability,
    LayerConfig, LayerConnectionRequest, LayerHandle, ListOptions, ListRequest, ObjectInfo,
    ObjectKind, ReadOptions, ReadRequest, ReadResult, Request, SecretBundle, SecretBytes,
    SecretValue, StatOptions, StatRequest, UpdateConnectionCredentialsRequest, WriteOptions,
    WriteRequest, address,
};
use ovstorage_plugin_s3::S3LayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

const PROXY_CHILD_MODE: &str = "OVSTORAGE_S3_PROXY_TEST_CHILD";
const PROXY_CHILD_ENDPOINT: &str = "OVSTORAGE_S3_PROXY_TEST_ENDPOINT";
/// Printed by the child once the redaction assertions have actually run. The
/// parent requires it so that a filter matching no test — libtest exits 0 —
/// or a child that never reaches the assertions cannot pass vacuously.
const REDACTION_SENTINEL: &str = "REDACTION_ASSERTED";
/// Cleared in the child before it builds a client. `REQUEST_METHOD` is not a
/// proxy variable: hyper-util treats its mere presence as "running as a CGI
/// script" and then disables proxying entirely (the httpoxy mitigation), so an
/// ambient value would silently turn every assertion below into a no-proxy run.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];

// === Scripted mock S3 server ===
//
// Shared ovstorage_plugin_test::ScriptedHttpServer answering every request
// with one canned (status, body) response. Enough to steer the driver's
// verify verdict (200 / 401 / 403 with a modeled code) and to feed
// `Layer::list` a ListBucketResult page.

fn spawn_scripted_server(status_line: &str, body: &str) -> ScriptedHttpServer {
    ScriptedHttpServer::spawn(CannedHttpResponse::xml(status_line, body))
}

const EMPTY_LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
    <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";

fn s3_error_body(code: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{code}</Code><Message>scripted</Message>\
         <RequestId>req-1</RequestId></Error>"
    )
}

// === Helpers ===

fn credentials_bundle(access: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "aws_access_key_id".into(),
        SecretValue::Bytes(SecretBytes(access.as_bytes().to_vec())),
    );
    bundle.fields.insert(
        "aws_secret_access_key".into(),
        SecretValue::Bytes(SecretBytes(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
        )),
    );
    bundle
}

fn connection_request(
    bucket: &str,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    ConnectionRequest {
        backend_kind: "s3".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn empty_layer() -> LayerHandle {
    S3LayerFactory::default()
        .create_backend("s3", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "s3".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

fn proxy_child_command(mode: &str, endpoint: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current integration test"));
    command
        .arg("proxy_environment_child")
        .arg("--exact")
        .arg("--nocapture")
        .env(PROXY_CHILD_MODE, mode)
        .env(PROXY_CHILD_ENDPOINT, endpoint);
    for key in PROXY_ENV_KEYS {
        command.env_remove(key);
    }
    command
}

/// A loopback authority with nothing listening on it: bind an ephemeral port,
/// learn its number, then drop the listener. Port 9 is the discard service, so
/// a host running it accepts the connection instead of refusing it — the
/// request then stalls to the 60s operation timeout and the resulting error
/// carries no proxy authority, turning a fast failure into a slow one.
fn closed_loopback_authority() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener
        .local_addr()
        .expect("ephemeral port address")
        .to_string()
}

fn assert_child_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "proxy child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Child-only operation used by the parent subprocess tests below. Keeping the
/// environment mutation outside this test process avoids racing other Rust
/// tests that construct HTTP clients in parallel.
#[tokio::test]
async fn proxy_environment_child() {
    let Ok(mode) = std::env::var(PROXY_CHILD_MODE) else {
        return;
    };
    let endpoint = std::env::var(PROXY_CHILD_ENDPOINT).expect("proxy child endpoint");
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", &endpoint, credentials_bundle("AKIAPROXYTEST")),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));

    if mode == "redaction" {
        let error = layer
            .stat(
                Request::new(StatRequest {
                    address: address::parse("s3://bkt/object.txt").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("the unreachable proxy must fail the request");
        let rendered = format!("{error:?} {error}");
        // The proxy authority must survive while its userinfo does not:
        // without the authority the failure could equally be a direct DNS miss
        // on the origin, which would satisfy the two negative assertions while
        // proving nothing about redaction.
        let authority = std::env::var("HTTP_PROXY")
            .expect("redaction child runs with HTTP_PROXY")
            .rsplit_once('@')
            .expect("the redaction proxy carries userinfo")
            .1
            .to_string();
        assert!(
            rendered.contains(&authority),
            "the error must come from the proxy hop ({authority}): {rendered}"
        );
        assert!(!rendered.contains("proxy-user"), "{rendered}");
        assert!(!rendered.contains("proxy-secret"), "{rendered}");
        println!("{REDACTION_SENTINEL}");
    }
}

#[test]
fn s3_http_proxy_routes_requests_and_sends_basic_credentials() {
    let proxy = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let proxy_with_auth =
        proxy
            .endpoint()
            .replacen("http://", "http://proxy-user:proxy-secret@", 1);
    let mut command = proxy_child_command("proxy", "http://origin.invalid");
    command.env("HTTP_PROXY", proxy_with_auth);
    let output = command.output().expect("run proxy child");
    assert_child_succeeded(&output);

    assert_eq!(proxy.hits(), 1, "the S3 verify must traverse the proxy");
    let request = &proxy.requests()[0];
    assert!(
        request.starts_with("GET http://origin.invalid/bkt/?"),
        "forward proxy must receive an absolute-form S3 URI: {request}"
    );
    assert!(
        ovstorage_plugin_test::request_has_header(
            request,
            "Proxy-Authorization",
            "Basic cHJveHktdXNlcjpwcm94eS1zZWNyZXQ="
        ),
        "Basic proxy credentials must travel only in Proxy-Authorization: {request}"
    );
}

#[test]
fn s3_all_proxy_is_fallback_and_http_proxy_takes_precedence() {
    let preferred = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let fallback = spawn_scripted_server("500 Internal Server Error", "");
    let mut command = proxy_child_command("proxy", "http://origin.invalid");
    command
        .env("HTTP_PROXY", preferred.endpoint())
        .env("ALL_PROXY", fallback.endpoint());
    let output = command.output().expect("run proxy child");
    assert_child_succeeded(&output);

    assert_eq!(preferred.hits(), 1);
    assert_eq!(fallback.hits(), 0, "HTTP_PROXY must override ALL_PROXY");

    let all_only = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let mut command = proxy_child_command("proxy", "http://origin.invalid");
    command.env("ALL_PROXY", all_only.endpoint());
    let output = command.output().expect("run ALL_PROXY child");
    assert_child_succeeded(&output);
    assert_eq!(all_only.hits(), 1, "ALL_PROXY must provide the fallback");
}

#[test]
fn s3_no_proxy_bypasses_the_process_proxy() {
    let origin = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let proxy = spawn_scripted_server("500 Internal Server Error", "");
    let mut command = proxy_child_command("proxy", origin.endpoint());
    command
        .env("HTTP_PROXY", proxy.endpoint())
        .env("NO_PROXY", "127.0.0.1");
    let output = command.output().expect("run NO_PROXY child");
    assert_child_succeeded(&output);

    assert_eq!(
        origin.hits(),
        1,
        "the origin must receive the direct request"
    );
    assert_eq!(proxy.hits(), 0, "NO_PROXY must bypass the proxy");
}

/// An `https://` endpoint reaches the proxy through a CONNECT tunnel instead of
/// the absolute-form forwarding the other tests cover — the dominant production
/// shape, since real S3 endpoints are HTTPS. The fixture answers the CONNECT and
/// then closes, so the TLS handshake fails; the child still observes
/// `Authenticated` because `S3Driver::verify` treats anything that is not a
/// modeled credential rejection as a pass (`src/driver.rs`, the lenient-verify
/// trade). Only the proxy hop is under test here.
#[test]
fn s3_https_proxy_uses_connect_for_tls_endpoints() {
    let proxy = spawn_scripted_server("200 OK", "");
    let mut command = proxy_child_command("proxy", "https://origin.invalid");
    command.env("HTTPS_PROXY", proxy.endpoint());
    let output = command.output().expect("run CONNECT child");
    assert_child_succeeded(&output);

    assert_eq!(proxy.hits(), 1, "the S3 verify must traverse the proxy");
    let request = &proxy.requests()[0];
    assert!(
        request.starts_with("CONNECT origin.invalid:443 HTTP/1.1"),
        "an HTTPS proxy must receive a CONNECT tunnel request: {request}"
    );
}

#[test]
fn s3_proxy_credentials_are_redacted_from_transport_errors() {
    let mut command = proxy_child_command("redaction", "http://origin.invalid");
    command.env(
        "HTTP_PROXY",
        format!(
            "http://proxy-user:proxy-secret@{}",
            closed_loopback_authority()
        ),
    );
    let output = command.output().expect("run redaction child");
    assert_child_succeeded(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(REDACTION_SENTINEL),
        "the child must reach the redaction assertions\nstdout:\n{stdout}"
    );
}

// === add_connection verify verdicts ===

/// A 200 verify authenticates the connection, and the verify RPC is a signed
/// ListObjectsV2 with max-keys=1.
#[tokio::test]
async fn add_connection_authenticates_on_verify_pass() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            server.endpoint(),
            credentials_bundle("AKIATESTFIXTURE"),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(server.hits(), 1, "exactly one verify RPC");
    let raw = server.requests()[0].clone();
    assert!(
        raw.contains("list-type=2"),
        "verify is ListObjectsV2: {raw}"
    );
    assert!(raw.contains("max-keys=1"), "verify is bounded: {raw}");
    assert!(
        raw.to_lowercase()
            .contains("authorization: aws4-hmac-sha256"),
        "verify is signed: {raw}"
    );
}

/// Anonymous connections skip verify entirely (zero RPCs) and stay read-only.
#[tokio::test]
async fn add_connection_anonymous_skips_verify() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), SecretBundle::default()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert_eq!(server.hits(), 0, "anonymous never verifies");
}

/// Lenient verify: 403 `AccessDenied` means the signature was accepted but the
/// principal's policy is restricted — the connection must still authenticate
/// (a GetObject-only IAM principal must remain registrable).
#[tokio::test]
async fn add_connection_authenticates_through_access_denied() {
    let server = spawn_scripted_server("403 Forbidden", &s3_error_body("AccessDenied"));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            server.endpoint(),
            credentials_bundle("AKIARESTRICTED"),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// A modeled `SignatureDoesNotMatch` is a credential rejection: the connection
/// parks (`AwaitingAuth`), stays listed, keeps its config-derived root
/// routable, and data ops fail with `AuthRequired` (the live cell was never
/// activated).
#[tokio::test]
async fn add_connection_parks_on_signature_mismatch() {
    let server = spawn_scripted_server("403 Forbidden", &s3_error_body("SignatureDoesNotMatch"));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIABADSIG")),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "credential rejection must park, got {:?}",
        connection.auth_state
    );
    // A parked connection remains listed and its root remains published so it
    // can receive a later credential update.
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
    let root = layer
        .root_info_for(
            &address::parse("s3://bkt/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "s3://bkt/");
    // Data op on the parked connection: AuthRequired from the empty live cell.
    let err = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

/// A raw 401 is likewise a credential rejection → parked, with the same
/// follow-through as the modeled-code park: the config-derived root stays
/// routable and data ops fail `AuthRequired` from the never-activated cell.
#[tokio::test]
async fn add_connection_parks_on_401() {
    let server = spawn_scripted_server("401 Unauthorized", &s3_error_body("Unauthorized"));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIAEXPIRED")),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    let root = layer
        .root_info_for(
            &address::parse("s3://bkt/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "s3://bkt/");
    let err = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

/// A parked connection is what `authenticate_connection` is called on, and
/// S3 has no interactive flow to run: credentials arrive with the
/// connection. The call is refused with `Unsupported`, and the connection is
/// left exactly as parked as it was, still registered.
///
/// The load-bearing line is the `Unsupported` error in
/// `S3Driver::interactive`. Restoring the
/// `AuthEvent::Succeeded { credentials: None }` it used to emit makes this
/// test hand back a stream instead; draining that stream runs the promoting
/// adapter, and the parked-state check then reads `Authenticated` — a
/// connection promoted on no grant and no probe, which is the defect this pins.
#[tokio::test]
async fn authenticate_connection_leaves_a_parked_connection_parked() {
    let server = spawn_scripted_server("401 Unauthorized", &s3_error_body("Unauthorized"));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIAEXPIRED")),
    )
    .await;
    // Everything below asserts something about a PARKED connection, so a
    // fixture that quietly authenticated would make the test vacuous.
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "fixture must park the connection, got {:?}",
        connection.auth_state
    );

    let key = ConnectionKey {
        target: "s3".into(),
        id: connection.id.clone(),
    };
    // Drive the call the way a host does. The promotion the defect produced
    // happens when the returned stream is DRAINED, not when the call returns,
    // so a test that only inspects the call cannot observe it: draining here is
    // what makes the parked-state check below load-bearing.
    let refusal = match layer
        .authenticate_connection(
            Request::new(AuthenticateRequest {
                key,
                capability: InteractiveAuthCapability::Browser,
                auto_open_browser: false,
            }),
            None,
        )
        .await
    {
        // Drain it. The promotion this test exists to catch happens when the
        // adapter consumes a terminal event, not when the call returns, so
        // leaving the stream undrained would make the state check below
        // unfalsifiable. The refusal is asserted after that check, so a
        // regression that promotes is reported as the promotion it is.
        Ok(mut stream) => {
            for event in std::iter::from_fn(|| stream.next()) {
                let _ = event;
            }
            None
        }
        Err(error) => Some(error),
    };

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    let [still] = snapshot.connections.as_slice() else {
        panic!(
            "the refused call must not unregister the connection, got {} connections",
            snapshot.connections.len()
        );
    };
    // "Untouched" means the whole park, not just the variant: a re-park under a
    // different reason, or one that recorded this call as a failed attempt,
    // would also be a state change this call must not make.
    let (before_reason, before_attempt) = match &connection.auth_state {
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => (reason.clone(), last_attempt.clone()),
        other => panic!("fixture must park the connection, got {other:?}"),
    };
    match &still.auth_state {
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => {
            assert_eq!(*reason, before_reason, "the park reason must not change");
            assert_eq!(
                *last_attempt, before_attempt,
                "a refused authenticate is not a failed attempt"
            );
        }
        // Reached when a stream was offered AND draining it moved the state —
        // the original defect exactly. The call was not refused, so say that
        // rather than describing a refusal that did not happen.
        other => panic!(
            "authenticate must not move a parked connection; draining what it \
             returned left it {other:?}"
        ),
    }
    // Only now the call itself: a driver that returned an empty or
    // progress-only stream would also leave the park untouched, and that is
    // still a contract violation — the answer must be an immediate refusal.
    let refusal = refusal.expect("a backend with no interactive flow must not offer a stream");
    assert_eq!(
        refusal.code(),
        ErrorCode::Unsupported,
        "a backend with no interactive flow answers Unsupported, got {refusal:?}"
    );
}

/// The backend shape is frozen at add time: attaching credentials to a
/// connection that was added WITHOUT them must be rejected with guidance
/// (accepting would activate an orphan cell and report `Authenticated` while
/// the anonymous backend keeps emitting unsigned reads). The connection's
/// state is untouched by the rejection.
#[tokio::test]
async fn update_credentials_on_anonymous_connection_is_rejected() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), SecretBundle::default()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));

    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "s3".into(),
                    id: connection.id.clone(),
                },
                credentials: credentials_bundle("AKIALATECOMER"),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(
        err.message().contains("re-add"),
        "rejection must carry guidance: {}",
        err.message()
    );
    assert_eq!(server.hits(), 0, "no verify RPC on rejection");
    // The connection is untouched: still listed, still Anonymous.
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
    assert!(matches!(
        snapshot.connections[0].auth_state,
        ConnectionAuthState::Anonymous
    ));
}

/// The mirror-image shape change: updating a CREDENTIALED connection with an
/// EMPTY bundle must be rejected. `obtain` would map the empty bundle to
/// `Anonymous` and the set would record the transition, but `activate` never
/// clears the live cell — the backend would keep presigning with the previous
/// keys while the connection reports `Anonymous`. The rejection leaves the
/// state `Authenticated` and the signing identity unchanged.
#[tokio::test]
async fn update_credentials_with_empty_bundle_on_credentialed_connection_is_rejected() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIAORIGINAL")),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));

    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "s3".into(),
                    id: connection.id.clone(),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(
        err.message().contains("re-add"),
        "rejection must carry guidance: {}",
        err.message()
    );
    // State untouched: still Authenticated, and reads still presign with the
    // ORIGINAL key — the API does not report an `Anonymous` state the
    // backend doesn't have.
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(matches!(
        snapshot.connections[0].auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    match result {
        ReadResult::Redirect(redirect) => {
            assert!(
                redirect.request.url.contains("AKIAORIGINAL"),
                "signing identity unchanged: {}",
                redirect.request.url
            );
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

// === probe ===

/// Probe validates without registering: verdict mirrors add_connection, no
/// connection appears, and the advertised address comes from config (no RPC
/// beyond the verify).
#[tokio::test]
async fn probe_reports_verdict_without_registering() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "s3".into(),
                connection: connection_request(
                    "bkt",
                    server.endpoint(),
                    credentials_bundle("AKIATESTFIXTURE"),
                ),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        probed.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(probed.last_probed.is_some());
    assert_eq!(probed.current_addresses[0].as_str(), "s3://bkt/");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot.connections.is_empty(),
        "probe must not register a connection"
    );
}

/// Probe with rejected credentials surfaces the rejection on the view.
#[tokio::test]
async fn probe_surfaces_credential_rejection() {
    let server = spawn_scripted_server("403 Forbidden", &s3_error_body("InvalidAccessKeyId"));
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "s3".into(),
                connection: connection_request(
                    "bkt",
                    server.endpoint(),
                    credentials_bundle("AKIABAD"),
                ),
            }),
            None,
        )
        .await
        .unwrap();
    match probed.auth_state {
        ConnectionAuthState::AwaitingAuth { last_attempt, .. } => {
            assert!(last_attempt.is_some(), "rejection must carry the attempt");
        }
        other => panic!("expected AwaitingAuth, got {other:?}"),
    }
}

// === credential swap observed on the presign path ===

/// `update_connection_credentials` installs the proven keys into the live
/// cell: the next `read` presigns with the NEW access key id
/// (X-Amz-Credential), proving driver and backend share one cell.
#[tokio::test]
async fn update_credentials_swaps_the_signing_identity() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIAORIGINAL")),
    )
    .await;

    async fn presigned_key_id(layer: &LayerHandle) -> String {
        let result = layer
            .read(
                Request::new(ReadRequest {
                    address: address::parse("s3://bkt/obj.txt").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Redirect(redirect) => {
                let url = redirect.request.url;
                assert!(url.contains("X-Amz-Credential="), "presigned URL: {url}");
                url
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    let before = presigned_key_id(&layer).await;
    assert!(before.contains("AKIAORIGINAL"), "presign before: {before}");

    let updated = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "s3".into(),
                    id: connection.id.clone(),
                },
                credentials: credentials_bundle("AKIAROTATED"),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        updated.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));

    let after = presigned_key_id(&layer).await;
    assert!(
        after.contains("AKIAROTATED") && !after.contains("AKIAORIGINAL"),
        "presign must use the rotated key: {after}"
    );
}

// === routing across connections ===

/// Two connections (two buckets) route by longest prefix; each read presigns
/// against its own connection's endpoint+bucket.
#[tokio::test]
async fn routes_across_two_connections() {
    let server_a = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let server_b = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "alpha",
            server_a.endpoint(),
            credentials_bundle("AKIAALPHA"),
        ),
    )
    .await;
    add(
        &layer,
        connection_request("beta", server_b.endpoint(), credentials_bundle("AKIABETA")),
    )
    .await;

    for (bucket, key_id) in [("alpha", "AKIAALPHA"), ("beta", "AKIABETA")] {
        let result = layer
            .read(
                Request::new(ReadRequest {
                    address: address::parse(&format!("s3://{bucket}/x.txt")).unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Redirect(redirect) => {
                let url = &redirect.request.url;
                assert!(
                    url.contains(&format!("/{bucket}/")) && url.contains(key_id),
                    "bucket {bucket} must presign with its own connection: {url}"
                );
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }
}

// === Layer::list contract: fold + numeric-offset pagination ===

const LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix></Prefix><KeyCount>3</KeyCount>\
    <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
    <Contents><Key>team/</Key><Size>0</Size><ETag>\"m\"</ETag>\
    <LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents>\
    <Contents><Key>team/file.txt</Key><Size>5</Size><ETag>\"f\"</ETag>\
    <LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents>\
    <CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>\
    </ListBucketResult>";

/// `Layer::list` folds marker objects to
/// `DirectoryMarker`, common prefixes surface as `DirectoryInferred`, and
/// pagination is the shared numeric-offset convention over the folded set.
#[tokio::test]
async fn list_folds_markers_and_paginates() {
    let server = spawn_scripted_server("200 OK", LIST_BODY);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "bkt",
            server.endpoint(),
            credentials_bundle("AKIATESTFIXTURE"),
        ),
    )
    .await;

    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("s3://bkt/").unwrap(),
                options: ListOptions {
                    max_results: Some(2),
                    ..ListOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].address.as_str(), "s3://bkt/team/");
    assert_eq!(page.items[0].kind, ObjectKind::DirectoryMarker);
    assert_eq!(page.items[1].address.as_str(), "s3://bkt/team/file.txt");
    assert_eq!(page.items[1].kind, ObjectKind::File);
    let token = page.next_page_token.expect("second page");

    let page2 = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("s3://bkt/").unwrap(),
                options: ListOptions {
                    max_results: Some(2),
                    page_token: Some(token),
                    ..ListOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.items[0].address.as_str(), "s3://bkt/docs/");
    assert_eq!(page2.items[0].kind, ObjectKind::DirectoryInferred);
    assert!(page2.next_page_token.is_none());
}

/// The native stream preserves the concatenated buffered-page sequence while
/// applying marker folding incrementally instead of materializing the prefix.
#[tokio::test]
async fn list_stream_matches_all_buffered_pages() {
    let server = spawn_scripted_server("200 OK", LIST_BODY);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "bkt",
            server.endpoint(),
            credentials_bundle("AKIATESTFIXTURE"),
        ),
    )
    .await;

    let prefix = address::parse("s3://bkt/").unwrap();
    let root = layer
        .root_info_for(&prefix, &ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(root.capabilities.supports_list_stream);

    let mut buffered = Vec::new();
    let mut page_token = None;
    loop {
        let page = layer
            .list(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options: ListOptions {
                        max_results: Some(2),
                        page_token,
                        ..ListOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        buffered.extend(page.items);
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }

    let streamed = layer
        .list_stream(
            Request::new(ListRequest {
                prefix,
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

    assert_eq!(streamed, buffered);
}

// === parked connections that are, in fact, working ===
//
// `S3Driver::verify` proves a credential with one bucket-scope `ListObjectsV2`;
// the data path is a different verb on a different scope, and no object
// operation consults `auth_state`. The two can therefore disagree — and the
// shape they disagree in is NOT the one at `add_connection`, because the live
// credential cell is only filled by `activate` (`driver.rs`), so a connection
// parked at add time cannot sign anything at all. It is a credential ROTATION
// that leaves a parked connection armed: `ConnectionSet::update_credentials`
// parks on a refused grant without committing the new bundle, so the cell keeps
// the keys the previous grant installed and every later request is signed with
// them and served.

/// An endpoint that decides per request on the SigV4 `Credential=` it was
/// signed with, rather than on call ordering: any request naming
/// [`Self::refuse_key`]'s key is answered `403 SignatureDoesNotMatch`, and
/// everything else is served. A refusal and a success are then both
/// consequences of WHICH key signed, which is what a deployment does once one
/// key of a rotating pair is revoked — nothing is scripted by ordinal, so a
/// test cannot pass by accident of request count.
///
/// A request whose path contains [`GATED_PATH_MARKER`] is held until
/// [`KeyAwareServer::release_gate`] is called, which is what lets a test
/// interleave two callers on one connection deterministically.
struct KeyAwareServer {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    bad_key: Arc<Mutex<String>>,
    /// Held requests wait on this; `release_gate` opens it for good.
    gate: Arc<(Mutex<bool>, Condvar)>,
    /// Incremented when a request enters the gate, so a test can wait for the
    /// held request to have actually arrived instead of sleeping.
    gated_arrivals: Arc<AtomicUsize>,
}

/// Substring of a request path that makes [`KeyAwareServer`] hold the request.
const GATED_PATH_MARKER: &str = "held";

impl KeyAwareServer {
    /// A variant whose responses carry NO S3 origin header, for the negative
    /// control on the acceptance gate.
    fn spawn_without_origin_header(bad_key: &str) -> Self {
        Self::spawn_inner(bad_key, OriginHeader::None)
    }

    /// Stamps only `x-amz-id-2`, the origin name no other test exercises.
    fn spawn_stamping_id2(bad_key: &str) -> Self {
        Self::spawn_inner(bad_key, OriginHeader::Id2)
    }

    fn spawn(bad_key: &str) -> Self {
        Self::spawn_inner(bad_key, OriginHeader::RequestId)
    }

    fn spawn_inner(bad_key: &str, stamp: OriginHeader) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let bad_key = Arc::new(Mutex::new(bad_key.to_lowercase()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gated_arrivals = Arc::new(AtomicUsize::new(0));
        let (h, r, k, g, a) = (
            hits.clone(),
            requests.clone(),
            bad_key.clone(),
            gate.clone(),
            gated_arrivals.clone(),
        );
        let refused = render_with_origin(
            "403 Forbidden",
            &s3_error_body("SignatureDoesNotMatch"),
            stamp,
        );
        let served = render_with_origin("200 OK", EMPTY_LIST_BODY, stamp);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (h, r, k, g, a) = (h.clone(), r.clone(), k.clone(), g.clone(), a.clone());
                let (refused, served) = (refused.clone(), served.clone());
                // One thread per connection: a held request must not stop the
                // endpoint answering the concurrent one the test is racing it
                // against.
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let Some(raw) = read_http_request(&mut stream) else {
                        return;
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    let lowered = raw.to_lowercase();
                    let signed_with_bad_key =
                        lowered.contains(&format!("credential={}/", k.lock().expect("poisoned")));
                    let held = lowered
                        .lines()
                        .next()
                        .is_some_and(|line| line.contains(GATED_PATH_MARKER));
                    r.lock().expect("poisoned").push(raw);
                    if held {
                        a.fetch_add(1, Ordering::SeqCst);
                        let (lock, cvar) = &*g;
                        let mut open = lock.lock().expect("poisoned");
                        while !*open {
                            open = cvar.wait(open).expect("poisoned");
                        }
                    }
                    let response = if signed_with_bad_key {
                        &refused
                    } else {
                        &served
                    };
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        Self {
            endpoint,
            hits,
            requests,
            bad_key,
            gate,
            gated_arrivals,
        }
    }

    /// Start refusing `key` from the next request onward.
    fn refuse_key(&self, key: &str) {
        *self.bad_key.lock().expect("poisoned") = key.to_lowercase();
    }

    fn release_gate(&self) {
        let (lock, cvar) = &*self.gate;
        *lock.lock().expect("poisoned") = true;
        cvar.notify_all();
    }

    fn gated_arrivals(&self) -> usize {
        self.gated_arrivals.load(Ordering::SeqCst)
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("poisoned").clone()
    }
}

/// Same wire framing as `ScriptedHttpServer` (`Connection: close` +
/// `Content-Length`), rendered locally because `CannedHttpResponse` keeps its
/// fields private and this server picks its reply per request.
///
/// `x-amz-request-id` is stamped because a real store stamps it: the promotion
/// rule counts a response as acceptance only if it carries an S3 origin header,
/// so an endpoint that omits it models a proxy answering for the store rather
/// than the store itself.
/// Which S3 origin header, if any, the scripted endpoint stamps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginHeader {
    RequestId,
    /// The second name in `ORIGIN_HEADERS`. Covered separately because a
    /// harness that only ever stamps the first cannot see that name being
    /// dropped from the list.
    Id2,
    /// Models a proxy answering for the store — the shape the promotion rule
    /// must not count as proof of the credential.
    None,
}

fn render_with_origin(status_line: &str, body: &str, stamp: OriginHeader) -> String {
    let origin = match stamp {
        OriginHeader::RequestId => "x-amz-request-id: scripted-req-1\r\n",
        OriginHeader::Id2 => "x-amz-id-2: scripted-id-2\r\n",
        OriginHeader::None => "",
    };
    format!(
        "HTTP/1.1 {status_line}\r\nConnection: close\r\n{origin}\
         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut request = Vec::new();
    let mut buf = [0u8; 8192];
    let mut header_end = None;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if header_end.is_none() {
                    header_end = request
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4);
                }
                if let Some(end) = header_end {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + content_length {
                        break;
                    }
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
}

async fn stat_at(layer: &LayerHandle, address: &str) -> ovstorage_plugin::Result<ObjectInfo> {
    layer
        .stat(
            Request::new(StatRequest {
                address: address::parse(address).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
}

async fn auth_state_of(layer: &LayerHandle) -> ConnectionAuthState {
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    snapshot.connections[0].auth_state.clone()
}

/// Add a connection on a good key, then rotate in a key the endpoint refuses.
/// The rotation fails and parks the connection; the live cell keeps the good
/// key, so the connection is parked and armed.
async fn parked_by_a_refused_rotation(server: &KeyAwareServer) -> LayerHandle {
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIAGOOD")),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "setup did not take: the good key must authenticate, got {:?}",
        connection.auth_state
    );
    let update = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "s3".into(),
                    id: connection.id.clone(),
                },
                credentials: credentials_bundle("AKIABADSIG"),
            }),
            None,
        )
        .await;
    assert!(
        update.is_err(),
        "setup did not take: a refused rotation must fail, got {update:?}"
    );
    assert!(
        matches!(
            auth_state_of(&layer).await,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "setup did not take: a refused rotation must park"
    );
    layer
}

/// The reported auth state must follow the data path, not the last probe.
///
/// An operator rotates in a key the backend refuses: the update parks the
/// connection, but nothing clears the live credential cell, so every later
/// request is signed with the PREVIOUS key and served. A connection whose own
/// requests the backend is answering must not go on reporting that it needs
/// authentication.
#[tokio::test]
async fn a_served_data_path_promotes_a_rotation_parked_connection() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let result = stat_at(&layer, "s3://bkt/obj.txt").await;

    // Control — the data path actually reached the wire. Without this a
    // short-circuit that never signed anything would look like the defect.
    assert_eq!(
        server.hits(),
        hits_before + 1,
        "control: the data path must have been sent, saw {:?}",
        server.requests()
    );
    // Control — the credential path was exercised, with the key the cell holds.
    let raw = server.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("credential=akiagood/"),
        "control: the data path is signed with the previously-activated key: {raw}"
    );
    assert!(
        !raw.contains("akiabadsig"),
        "control: the refused key never reached the cell: {raw}"
    );
    assert!(
        result.is_ok(),
        "a parked connection still serves signed requests: {result:?}"
    );

    // The fix: the reported state follows that evidence.
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a connection doing successful signed work must not report AwaitingAuth, got {state:?}"
    );
}

/// Negative control for the promotion above. Same connection, same filled cell,
/// same `stat`; only the endpoint's verdict changes. Once it refuses the key
/// the cell actually holds, the request fails at the wire and the connection
/// stays parked — so the promotion is earned by the key still being accepted,
/// not manufactured by the harness.
#[tokio::test]
async fn revoking_the_held_key_breaks_the_data_path_and_withholds_promotion() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    server.refuse_key("AKIAGOOD");
    let hits_before = server.hits();
    let after = stat_at(&layer, "s3://bkt/obj.txt").await;
    assert_eq!(
        server.hits(),
        hits_before + 1,
        "control: the request still reached the wire"
    );
    assert!(
        after.is_err(),
        "control: a key the endpoint refuses must not serve, got {after:?}"
    );
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a refused request is no evidence of a working credential, got {state:?}"
    );
}

/// A refusal answered to ANY caller on the connection withholds the promotion
/// of an operation running concurrently with it.
///
/// What this pins is the REFUSAL half being connection-wide: the held caller's
/// own request is accepted, and it still must not promote, because a refusal
/// landed on the connection while it ran. Under the broker those two callers
/// are unrelated remote clients, and a connection-wide accepted/rejected tally
/// sampled around an operation would report "accepted moved, rejected did not"
/// to whichever caller sampled between its neighbour's acceptance and its
/// neighbour's refusal.
///
/// It does not, on its own, pin acceptance being per-operation — an accepted
/// neighbour promotes the connection itself, so no assertion on `auth_state`
/// can separate the two scopings. The redirect test below is what covers that
/// side: an operation that sends nothing must not promote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_refusal_withholds_a_promotion() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = Arc::new(parked_by_a_refused_rotation(&server).await);

    // Caller A: a `stat` the endpoint holds open, signed with the good key, and
    // which will be answered 200 once released.
    let held = tokio::spawn({
        let layer = layer.clone();
        async move { stat_at(&layer, "s3://bkt/held.txt").await }
    });
    // Wait for A's request to have actually reached the endpoint and parked in
    // the gate. Without this the "concurrent" refusal could land before A even
    // signed, which is a different (and weaker) test.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.gated_arrivals() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "control: caller A's request never reached the endpoint"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Caller B: refused, on the same connection, while A is in flight.
    server.refuse_key("AKIAGOOD");
    let refused = stat_at(&layer, "s3://bkt/other.txt").await;
    assert!(
        refused.is_err(),
        "control: caller B must be refused, got {refused:?}"
    );

    // A's own request is answered — but with the key now refused, so release it
    // against an endpoint that has gone back to accepting it. A therefore sees
    // a genuine acceptance and no refusal of its own.
    server.refuse_key("AKIABADSIG");
    server.release_gate();
    let accepted = held.await.expect("caller A joins");
    assert!(
        accepted.is_ok(),
        "control: caller A's own request must be accepted, got {accepted:?}"
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a refusal on the connection must withhold a concurrent operation's \
         promotion, got {state:?}"
    );
}

/// The write path earns its own promotion. `write` does not run under the
/// retry-once recovery loop — its body cannot be replayed — so it takes the
/// no-retry promotion sibling, and a slot that forgot to install its evidence
/// sink would leave this connection parked for ever.
#[tokio::test]
async fn a_served_write_promotes_a_parked_connection() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let result = layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                body: Body::Bytes(b"payload".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await;
    assert_eq!(
        server.hits(),
        hits_before + 1,
        "control: the write must have been sent, saw {:?}",
        server.requests()
    );
    let raw = server.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("credential=akiagood/"),
        "control: the write is signed with the key the cell holds: {raw}"
    );
    assert!(result.is_ok(), "the write must be served: {result:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a connection whose write the store answered must not report \
         AwaitingAuth, got {state:?}"
    );
}

/// A SERVED `check_access` earns no promotion, and poisons nothing.
///
/// It asks the store what the caller may do by provoking the answer, so a `200`
/// it receives is the answer to its own question rather than evidence the
/// connection earned. Only that half is suppressed — a refusal the probe hears
/// still counts, which
/// `a_refusal_heard_by_check_access_withholds_a_concurrent_promotion` pins, so
/// this test deliberately drives the served case.
///
/// Both halves here are asserted: the served check does not promote, and it
/// leaves the epoch untouched for the operation that follows.
#[tokio::test]
async fn a_served_check_access_earns_no_promotion() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let decision = layer
        .check_access(
            Request::new(CheckAccessRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                operations: AccessOps::default(),
            }),
            None,
        )
        .await;
    // Control — the check really did reach the store, signed. Without this a
    // short-circuit would make the non-promotion prove nothing.
    assert!(
        server.hits() > hits_before,
        "control: the access probe must have been sent, saw {:?}",
        server.requests()
    );
    let raw = server.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("credential=akiagood/"),
        "control: the access probe is signed with the key the cell holds: {raw}"
    );
    assert!(decision.is_ok(), "the access probe is served: {decision:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a served access probe is not evidence about the credential, got {state:?}"
    );

    // ... and it withheld nothing either: the next ordinary operation promotes.
    let stat = stat_at(&layer, "s3://bkt/obj.txt").await;
    assert!(stat.is_ok(), "the data path still works: {stat:?}");
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "the access probe must not have advanced the refusal epoch, got {state:?}"
    );
}

/// A response carrying no S3 origin header is not proof of the credential.
///
/// The negative control the acceptance gate was missing: every other test's
/// endpoint stamps `x-amz-request-id`, so the header SCAN at the call site was
/// never exercised with it absent. Hardcoding that argument to `true` would
/// leave the gate silently dead with every test green — on the one clause whose
/// failure direction the code calls unrecoverable. (Dropping the FIRST name from
/// `ORIGIN_HEADERS` was already caught, by the promotion tests that rely on it;
/// dropping the second is what `an_x_amz_id_2_alone_is_an_origin_stamp` covers.)
#[tokio::test]
async fn a_response_without_an_s3_origin_header_does_not_promote() {
    let server = KeyAwareServer::spawn_without_origin_header("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let result = stat_at(&layer, "s3://bkt/obj.txt").await;

    // Control — the request reached the wire, signed, and was served. Only the
    // origin header is missing, so the non-promotion is that rule and nothing
    // else.
    assert_eq!(
        server.hits(),
        hits_before + 1,
        "control: the data path must have been sent, saw {:?}",
        server.requests()
    );
    let raw = server.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("credential=akiagood/"),
        "control: the request is signed with the key the cell holds: {raw}"
    );
    assert!(
        result.is_ok(),
        "control: the response is a served 200: {result:?}"
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "an answer composed by something that is not the store proves nothing, \
         got {state:?}"
    );
}

/// `x-amz-id-2` alone is a sufficient origin stamp.
///
/// Every other endpoint here stamps `x-amz-request-id`, so dropping the second
/// name from `ORIGIN_HEADERS` was invisible: the promotion tests still passed on
/// the first name, and the no-header test omits both. This is the arm that sees
/// it.
#[tokio::test]
async fn an_x_amz_id_2_alone_is_an_origin_stamp() {
    let server = KeyAwareServer::spawn_stamping_id2("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let result = stat_at(&layer, "s3://bkt/obj.txt").await;
    assert!(result.is_ok(), "the data path is served: {result:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a response stamped only with x-amz-id-2 still came from the store, \
         got {state:?}"
    );
}

/// A single-part `write_redirect` presigns only, so it earns nothing.
///
/// The negative half of the slot's transport claim: below the multipart
/// threshold the batch is minted locally and no request leaves the process, so
/// an `Ok` from it must not promote. (The positive half — a multipart batch
/// opening the upload with a signed `CreateMultipartUpload` — needs a
/// multipart-aware endpoint this harness does not have, and is stated as a gap
/// rather than claimed.)
#[tokio::test]
async fn a_single_part_write_redirect_does_not_promote() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(64),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await;
    assert!(batch.is_ok(), "the batch is minted: {batch:?}");
    assert_eq!(
        server.hits(),
        hits_before,
        "control: a single-part batch presigns and sends nothing, saw {:?}",
        server.requests()
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a locally minted batch is not proof of a working credential, got {state:?}"
    );
}

/// A permission check that is NOT concurrent with an operation costs it nothing.
///
/// The other side of the trade, and the reason "withheld" is not "latched" for a
/// workload whose checks and operations do not overlap: the refusal epoch asks
/// "did a refusal land while I ran?", so a probe's `403` between operations is
/// invisible to both. A host whose checks interleave continuously with its
/// operations is the case that can starve, and that is recorded at
/// `vetoes_promotion` rather than pretended away.
#[tokio::test]
async fn a_check_between_operations_does_not_withhold_a_later_promotion() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    // A permission check that is refused, entirely before the operation starts.
    server.refuse_key("AKIAGOOD");
    let decision = layer
        .check_access(
            Request::new(CheckAccessRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                operations: AccessOps::default(),
            }),
            None,
        )
        .await;
    assert!(
        decision.is_ok_and(|decision| !decision.allowed),
        "control: the probe must have been refused"
    );

    // The key works again; an ordinary operation now promotes, because no
    // refusal landed inside ITS window.
    server.refuse_key("AKIABADSIG");
    let served = stat_at(&layer, "s3://bkt/obj.txt").await;
    assert!(served.is_ok(), "the data path is served: {served:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a refusal that landed before this operation started is outside its \
         window, got {state:?}"
    );
}

/// A refusal `check_access` hears still withholds a concurrent promotion.
///
/// The race the suppression must not open: an ordinary operation is accepted
/// while the key works, the key is then disabled, and a permission check
/// concurrent with that operation receives the refusal. If the probe's refusal
/// were dropped, the in-flight operation would find the epoch unchanged and
/// promote a credential that is already dead — and nothing demotes it, since
/// `refresh` is `Unsupported` and no data-path operation parks a connection.
///
/// Only the probe's SUCCESSES are suppressed; a refusal it hears is one the
/// connection heard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_heard_by_check_access_withholds_a_concurrent_promotion() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = Arc::new(parked_by_a_refused_rotation(&server).await);

    // Caller A: accepted, and held open across the disabling below. Its verdict
    // is decided when the request arrives, so it is served on release.
    let held = tokio::spawn({
        let layer = layer.clone();
        async move { stat_at(&layer, "s3://bkt/held.txt").await }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.gated_arrivals() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "control: caller A's request never reached the endpoint"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The key is disabled, and the permission check is what hears about it.
    server.refuse_key("AKIAGOOD");
    let decision = layer
        .check_access(
            Request::new(CheckAccessRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                operations: AccessOps::default(),
            }),
            None,
        )
        .await;
    assert!(
        decision.is_ok_and(|decision| !decision.allowed),
        "control: the probe must have been refused"
    );

    server.release_gate();
    let accepted = held.await.expect("caller A joins");
    assert!(
        accepted.is_ok(),
        "control: caller A's own request was served: {accepted:?}"
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a refusal the connection heard must withhold the promotion of an \
         operation running across it, got {state:?}"
    );
}

/// `read` mints a presigned URL and sends nothing, so an `Ok` from it is no
/// evidence about the credential. Measured, not assumed: the endpoint's hit
/// count does not move.
#[tokio::test]
async fn minting_a_read_redirect_does_not_promote_a_parked_connection() {
    let server = KeyAwareServer::spawn("AKIABADSIG");
    let layer = parked_by_a_refused_rotation(&server).await;

    let hits_before = server.hits();
    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("s3://bkt/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await;
    // Assert on the artifact that crosses the boundary, not on `is_ok`: the
    // redirect really is a presigned URL signed with the key the cell holds, so
    // the caller gets a working download — and yet nothing was proved, because
    // no request left the process.
    match result.expect("a parked connection still mints redirects") {
        ReadResult::Redirect(redirect) => {
            let url = redirect.request.url.to_lowercase();
            assert!(
                url.contains("x-amz-credential=akiagood"),
                "the redirect is presigned with the key the cell holds: {url}"
            );
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
    assert_eq!(
        server.hits(),
        hits_before,
        "control: the redirect mint reaches no service"
    );
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a locally-minted redirect is not proof of a working credential, got {state:?}"
    );
}

/// The shape the issue described for S3, recorded because it does NOT
/// reproduce: with the probe refused at `add_connection` the live credential
/// cell was never filled, so the data path fails `AuthRequired` without
/// signing or sending anything. There is nothing to promote on, and the
/// connection stays parked.
#[tokio::test]
async fn add_time_park_leaves_the_data_path_unable_to_sign() {
    let server = ScriptedHttpServer::spawn_sequence(vec![
        Some(CannedHttpResponse::xml(
            "403 Forbidden",
            s3_error_body("SignatureDoesNotMatch"),
        )),
        Some(CannedHttpResponse::xml("200 OK", EMPTY_LIST_BODY)),
    ]);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), credentials_bundle("AKIABADSIG")),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "setup did not take: the refused probe must park, got {:?}",
        connection.auth_state
    );
    let probe_hits = server.hits();
    assert_eq!(probe_hits, 1, "control: the probe reached the endpoint");

    let result = stat_at(&layer, "s3://bkt/obj.txt").await;
    assert_eq!(
        result.expect_err("no credentials are installed").code(),
        ErrorCode::AuthRequired,
        "the data path fails from the empty cell, not from the endpoint"
    );
    assert_eq!(
        server.hits(),
        probe_hits,
        "no data-path request was ever signed or sent"
    );
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "nothing reached the backend, so nothing may promote, got {state:?}"
    );
}

// === Anonymous s3:// fallback ===
//
// `anonymous_fallback = ["s3"]` on the layer publishes one hidden scheme root,
// `s3:///`, and routes an `s3://` address no connection serves to a per-bucket
// anonymous backend built on first touch. The tests here drive the layer's
// factory and routing: what the grant publishes, what it refuses, and how it
// ranks against a configured connection. The wire-level properties (unsigned
// requests, refused mutations) live in `anonymous_public_bucket.rs`.

/// The grant as the host produces it: the array reserialized under its key.
fn grant(schemes: &[&str]) -> ConfigValue {
    let list = schemes
        .iter()
        .map(|scheme| format!("\"{scheme}\""))
        .collect::<Vec<_>>()
        .join(", ");
    ConfigValue::Toml(format!("anonymous_fallback = [{list}]\n"))
}

/// A layer table granting the `s3://` fallback and pointing every fallback
/// bucket at `endpoint`, path-style, so the loopback fixtures can answer.
fn fallback_policy(endpoint: &str) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert("anonymous_fallback".into(), grant(&["s3"]));
    config.insert(
        "anonymous_fallback_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    config.insert(
        "anonymous_fallback_force_path_style".into(),
        ConfigValue::Bool(true),
    );
    config
}

async fn create_layer(config: &LayerConfig) -> ovstorage_plugin::Result<LayerHandle> {
    S3LayerFactory::default()
        .create_backend("s3", config, None)
        .await
}

async fn fallback_layer(config: &LayerConfig) -> LayerHandle {
    create_layer(config)
        .await
        .expect("the granted layer builds")
}

async fn roots_of(layer: &LayerHandle) -> Vec<ovstorage_plugin::RootInfo> {
    layer
        .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .roots
}

async fn root_for(
    layer: &LayerHandle,
    address: &str,
) -> ovstorage_plugin::Result<ovstorage_plugin::RootInfo> {
    layer
        .root_info_for(
            &address::parse(address).unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
}

/// Without a grant nothing changes: an unconfigured bucket is `NoRoute` with
/// the message every host already pins, and no scheme root is published.
#[tokio::test]
async fn fallback_is_off_by_default() {
    let layer = empty_layer().await;
    let err = stat_at(&layer, "s3://unconfigured/object.txt")
        .await
        .expect_err("no connection serves the bucket");
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert_eq!(err.message(), "no route matches address");
    assert!(roots_of(&layer).await.is_empty(), "no root of any kind");
    let err = root_for(&layer, "s3://unconfigured/object.txt")
        .await
        .expect_err("no root either");
    assert_eq!(err.code(), ErrorCode::NoRoute);
}

/// The fallback keys are split off before the static-connection seed, so a
/// layer holding only the grant seeds no connection and publishes exactly the
/// hidden, marked, read-only scheme root.
#[tokio::test]
async fn a_layer_holding_only_the_fallback_key_seeds_no_static_connection() {
    let mut config = LayerConfig::new();
    config.insert("anonymous_fallback".into(), grant(&["s3"]));
    let layer = fallback_layer(&config).await;

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot.connections.is_empty(),
        "the grant is not a connection: {:?}",
        snapshot.connections
    );

    let roots = roots_of(&layer).await;
    assert_eq!(roots.len(), 1, "exactly the scheme root: {roots:?}");
    let root = &roots[0];
    assert_eq!(root.root.as_str(), "s3:///");
    assert_eq!(root.layer_kind, "s3");
    assert_eq!(root.connection_id, None);
    assert_eq!(root.owning_target, None);
    assert!(!root.visible);
    assert_eq!(root.visibility, ovstorage_plugin::AddressVisibility::Hidden);
    assert_eq!(
        root.user_metadata
            .get(ovstorage_plugin::fallback::SCHEME_FALLBACK_METADATA_KEY)
            .map(String::as_str),
        Some(ovstorage_plugin::fallback::SCHEME_FALLBACK_ANONYMOUS)
    );
    assert!(ovstorage_plugin::fallback::is_scheme_fallback_root(root));
    // The same client, the same ranged reads: the strategy the connection
    // roots advertise, so a consumer reading it off a fallback-served address
    // sees no less capable an answer than for a configured bucket.
    assert_eq!(
        root.range_read_strategy,
        ovstorage_plugin::RangeReadStrategy::Native
    );
    // Read-only: the read side of an anonymous connection, and nothing else.
    let caps = &root.capabilities;
    assert!(caps.supports_list && caps.supports_list_stream && caps.supports_recursive_list);
    assert!(caps.supports_version_listing && caps.supports_access_check);
    assert!(!caps.supports_write && !caps.supports_write_stream && !caps.supports_write_redirect);
    assert!(!caps.supports_delete && !caps.supports_copy && !caps.supports_rename);
    assert!(!caps.supports_create_directory && !caps.supports_delete_directory);
    assert!(!caps.supports_native_metadata_patch && !caps.supports_metadata_rewrite_emulation);
    assert!(!caps.supports_watch_directory);

    // An unconfigured address resolves to the scheme root verbatim — never a
    // synthesized per-bucket root.
    let resolved = root_for(&layer, "s3://unconfigured/object.txt")
        .await
        .expect("the fallback routes it");
    assert_eq!(resolved.root.as_str(), "s3:///");
    assert_eq!(resolved.connection_id, None);
    assert_eq!(
        resolved.range_read_strategy,
        ovstorage_plugin::RangeReadStrategy::Native
    );
}

/// A grant naming a scheme this kind does not serve is a configuration error,
/// not a silently inert key.
#[tokio::test]
async fn a_fallback_key_naming_a_scheme_this_layer_does_not_serve_is_refused() {
    for schemes in [&["gs"][..], &["s3", "azure"][..]] {
        let mut config = LayerConfig::new();
        config.insert("anonymous_fallback".into(), grant(schemes));
        let err = create_layer(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("{schemes:?} must be refused"));
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{schemes:?}: {err}");
        assert!(
            err.message().contains("does not serve") && err.message().contains("it serves s3"),
            "{schemes:?}: {}",
            err.message()
        );
    }
}

/// The grant must be a TOML array of scheme strings; a bare string is refused
/// rather than read as a one-element array.
#[tokio::test]
async fn a_non_array_fallback_key_is_refused_at_create_backend() {
    let mut config = LayerConfig::new();
    config.insert(
        "anonymous_fallback".into(),
        ConfigValue::String("s3".into()),
    );
    let err = create_layer(&config)
        .await
        .err()
        .expect("a bare string is refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("must be a TOML array"),
        "{}",
        err.message()
    );
}

/// A misspelt or unknown tunable is refused by name, and the tunables are
/// validated even when no grant is present, so the mistake surfaces where the
/// operator wrote it.
#[tokio::test]
async fn an_unknown_or_ill_typed_fallback_tunable_is_refused_at_create_backend() {
    let mut config = LayerConfig::new();
    config.insert(
        "anonymous_fallback_regoin".into(),
        ConfigValue::String("us-east-1".into()),
    );
    let err = create_layer(&config)
        .await
        .err()
        .expect("an unknown key is refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("anonymous_fallback_regoin"),
        "the message names the key: {}",
        err.message()
    );

    let mut config = LayerConfig::new();
    config.insert("anonymous_fallback".into(), grant(&["s3"]));
    config.insert(
        "anonymous_fallback_region".into(),
        ConfigValue::String("EU-WEST-1".into()),
    );
    let err = create_layer(&config)
        .await
        .err()
        .expect("a region that is not a region identifier is refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("anonymous_fallback_region"),
        "{}",
        err.message()
    );

    let mut config = LayerConfig::new();
    config.insert("anonymous_fallback".into(), grant(&["s3"]));
    config.insert(
        "anonymous_fallback_max_backends".into(),
        ConfigValue::Int(0),
    );
    let err = create_layer(&config)
        .await
        .err()
        .expect("a zero bound is refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("anonymous_fallback_max_backends"),
        "{}",
        err.message()
    );
}

/// A fallback endpoint that embeds a credential, or carries a query, fragment
/// or path, is refused at `create_backend` — granted or not — before any
/// client is built: the string is what every fallback host is derived from
/// and what an anonymous read's redirect is built from, so a credential in it
/// would ride a tier whose promise is that none is sent. The refusal names the
/// key and the layer, never the value.
#[tokio::test]
async fn a_credential_bearing_fallback_endpoint_is_refused_at_create_backend() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let authority = server
        .endpoint()
        .strip_prefix("http://")
        .expect("the fixture is plain http")
        .trim_end_matches('/')
        .to_string();
    for (spelling, complaint) in [
        (format!("http://reader:hunter2@{authority}"), "credentials"),
        (format!("http://{authority}/?x-id=GetObject"), "query"),
        (format!("http://{authority}/#anchor"), "fragment"),
        (format!("http://{authority}/prefix"), "path"),
    ] {
        for granted in [true, false] {
            let mut config = LayerConfig::new();
            if granted {
                config.insert("anonymous_fallback".into(), grant(&["s3"]));
            }
            config.insert(
                "anonymous_fallback_endpoint".into(),
                ConfigValue::String(spelling.clone()),
            );
            let err = create_layer(&config)
                .await
                .err()
                .unwrap_or_else(|| panic!("{spelling} (granted: {granted}) was accepted"));
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                err.message()
                    .contains("`anonymous_fallback_endpoint` on layer `s3`")
                    && err.message().contains(complaint),
                "{spelling}: {}",
                err.message()
            );
            assert!(
                !err.message().contains("hunter2") && !err.message().contains("reader"),
                "the refusal never echoes the credential: {}",
                err.message()
            );
        }
    }
    assert_eq!(server.hits(), 0, "nothing reached the wire");
}

/// A fallback key on a connection request is refused with a pointer to where
/// it belongs, on both `probe` and `add_connection`, and no RPC is sent.
#[tokio::test]
async fn a_connection_request_carrying_a_fallback_key_is_refused() {
    let server = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    for key in ["anonymous_fallback", "anonymous_fallback_region"] {
        let mut request = connection_request(
            "bkt",
            server.endpoint(),
            credentials_bundle("AKIATESTFIXTURE"),
        );
        request
            .config
            .insert(key.into(), ConfigValue::String("us-east-1".into()));
        for (slot, result) in [
            (
                "probe",
                layer
                    .probe(
                        Request::new(LayerConnectionRequest {
                            target: "s3".into(),
                            connection: request.clone(),
                        }),
                        None,
                    )
                    .await,
            ),
            (
                "add_connection",
                layer
                    .add_connection(
                        Request::new(LayerConnectionRequest {
                            target: "s3".into(),
                            connection: request.clone(),
                        }),
                        None,
                    )
                    .await,
            ),
        ] {
            let err = result.expect_err("a layer key on a connection is refused");
            assert_eq!(
                err.code(),
                ErrorCode::InvalidArgument,
                "{slot} {key}: {err}"
            );
            assert!(
                err.message().contains(key)
                    && err.message().contains("layer key")
                    && err.message().contains("[ovstorage.layers.s3]"),
                "{slot} {key}: {}",
                err.message()
            );
        }
    }
    assert_eq!(server.hits(), 0, "refused before any verify RPC");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(snapshot.connections.is_empty());
}

/// The first tier outranks the second: once a connection for a bucket
/// installs, its root serves the bucket and the fallback's cached backend for
/// it is evicted. Eviction is observed through the mint budget — a budget of
/// two lets the bucket be built twice (before the connection and after its
/// removal) and then refuses a third build, which a stale cache entry would
/// have made unnecessary.
#[tokio::test]
async fn a_configured_root_outranks_the_fallback_and_install_evicts_the_cached_backend() {
    let fallback_store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let configured_store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let mut config = fallback_policy(fallback_store.endpoint());
    config.insert(
        "anonymous_fallback_mints_per_minute".into(),
        ConfigValue::Int(2),
    );
    let layer = fallback_layer(&config).await;

    // (1) The fallback serves the bucket: build one.
    stat_at(&layer, "s3://bkt/object.txt")
        .await
        .expect("the fallback serves an unconfigured bucket");
    assert_eq!(fallback_store.hits(), 1);
    assert_eq!(
        root_for(&layer, "s3://bkt/object.txt")
            .await
            .unwrap()
            .root
            .as_str(),
        "s3:///"
    );

    // (2) A connection for the bucket installs and outranks the fallback.
    let connection = add(
        &layer,
        connection_request("bkt", configured_store.endpoint(), SecretBundle::default()),
    )
    .await;
    stat_at(&layer, "s3://bkt/object.txt")
        .await
        .expect("the configured connection serves the bucket");
    assert_eq!(
        configured_store.hits(),
        1,
        "the connection's store answered"
    );
    assert_eq!(fallback_store.hits(), 1, "the fallback's store did not");
    let root = root_for(&layer, "s3://bkt/object.txt").await.unwrap();
    assert_eq!(root.root.as_str(), "s3://bkt/");
    assert_eq!(root.connection_id.as_ref(), Some(&connection.id));
    // Another bucket still falls through to the scheme root.
    assert_eq!(
        root_for(&layer, "s3://other/object.txt")
            .await
            .unwrap()
            .root
            .as_str(),
        "s3:///"
    );

    // (3) Removing the connection hands the bucket back to the fallback, which
    // builds it again (build two) because install evicted its cached backend.
    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "s3".into(),
                id: connection.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    stat_at(&layer, "s3://bkt/object.txt")
        .await
        .expect("the fallback serves the bucket again");
    assert_eq!(fallback_store.hits(), 2);

    // (4) A third build is refused by the budget — proof that (3) was a build
    // and not a hit on a stale entry.
    let err = stat_at(&layer, "s3://other/object.txt")
        .await
        .expect_err("the two-build budget is spent");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
}

/// The bare scheme root and a hostless address both reach the fallback as
/// first-tier hits under its own root, and neither names a bucket: refused
/// as `InvalidArgument`, on the read side and the mutating side alike, with
/// nothing sent.
#[tokio::test]
async fn the_scheme_root_itself_is_invalid_argument() {
    let store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = fallback_layer(&fallback_policy(store.endpoint())).await;

    for spelling in ["s3:///", "s3:///k", "s3:///dir/"] {
        let err = stat_at(&layer, spelling)
            .await
            .expect_err("a hostless address names no bucket");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}: {err}");
        assert_eq!(
            err.message(),
            "an s3:// address names no bucket",
            "{spelling}"
        );

        let err = layer
            .list(
                Request::new(ListRequest {
                    prefix: address::parse(spelling).unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("nor can it be listed");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}: {err}");

        let err = layer
            .write(
                Request::new(WriteRequest {
                    address: address::parse(spelling).unwrap(),
                    body: Body::Bytes(b"bytes".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .expect_err("nor written to");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}: {err}");
    }
    assert_eq!(store.hits(), 0, "nothing reached the wire");
    // The root itself is still introspectable: it is a first-tier hit.
    let root = root_for(&layer, "s3:///").await.unwrap();
    assert_eq!(root.root.as_str(), "s3:///");
}

/// An address that authenticates itself through its query never takes the
/// fallback: an anonymous attempt would discard the authority the caller
/// presented. The version pin, which carries no authority, still routes.
#[tokio::test]
async fn a_presigned_or_sas_query_falls_through_to_no_route() {
    let store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = fallback_layer(&fallback_policy(store.endpoint())).await;

    for presigned in [
        "s3://unconfigured/object.txt?X-Amz-Signature=abc",
        "s3://unconfigured/object.txt?X-Amz-Credential=AKIA%2F20260101%2Fus-east-1%2Fs3%2Faws4_request",
        "s3://unconfigured/object.txt?sig=abc",
    ] {
        let err = stat_at(&layer, presigned)
            .await
            .expect_err("a credential-bearing query never takes the fallback");
        assert_eq!(err.code(), ErrorCode::NoRoute, "{presigned}: {err}");
        assert_eq!(err.message(), "no route matches address", "{presigned}");
        let err = root_for(&layer, presigned)
            .await
            .expect_err("no root either");
        assert_eq!(err.code(), ErrorCode::NoRoute, "{presigned}: {err}");
    }
    assert_eq!(store.hits(), 0);

    stat_at(&layer, "s3://unconfigured/object.txt?versionId=7")
        .await
        .expect("a version pin carries no authority and routes");
    assert_eq!(store.hits(), 1);
    assert!(
        store.requests()[0].contains("versionId=7"),
        "the pin reaches the store: {}",
        store.requests()[0]
    );
}

/// At most `anonymous_fallback_max_backends` anonymous backends stay
/// resident, evicted least-recently-used. Observed through the mint budget: a
/// bound of one and a budget of three make the sequence a, b, a build three
/// times and then refuse b, where an unbounded cache would have built twice
/// and answered b from the cache.
#[tokio::test]
async fn cached_backends_are_bounded() {
    let store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let mut config = fallback_policy(store.endpoint());
    config.insert(
        "anonymous_fallback_max_backends".into(),
        ConfigValue::Int(1),
    );
    config.insert(
        "anonymous_fallback_mints_per_minute".into(),
        ConfigValue::Int(3),
    );
    let layer = fallback_layer(&config).await;

    for address in [
        "s3://bucket-a/object.txt",
        "s3://bucket-b/object.txt",
        "s3://bucket-a/object.txt",
    ] {
        stat_at(&layer, address)
            .await
            .unwrap_or_else(|err| panic!("{address}: {err}"));
    }
    assert_eq!(store.hits(), 3, "every stat reached the store");
    let err = stat_at(&layer, "s3://bucket-b/object.txt")
        .await
        .expect_err("bucket-b was evicted by bucket-a's rebuild, and the budget is spent");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
    assert_eq!(store.hits(), 3, "the refusal sent nothing");
}

/// Past `anonymous_fallback_mints_per_minute` builds in a sliding minute, a
/// miss answers a retryable `ResourceExhausted`; hits keep answering.
#[tokio::test]
async fn the_mint_budget_answers_resource_exhausted() {
    let store = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let mut config = fallback_policy(store.endpoint());
    config.insert(
        "anonymous_fallback_mints_per_minute".into(),
        ConfigValue::Int(1),
    );
    let layer = fallback_layer(&config).await;

    stat_at(&layer, "s3://bucket-a/object.txt")
        .await
        .expect("the first build is within budget");
    let err = stat_at(&layer, "s3://bucket-b/object.txt")
        .await
        .expect_err("the second build is over budget");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
    assert_eq!(
        err.message(),
        "anonymous fallback mint budget exhausted; retry later"
    );
    assert!(err.code().retryable(), "a budget clears with time");
    assert!(err.next_action().is_some(), "and says so");
    assert_eq!(store.hits(), 1, "the refusal sent nothing");

    stat_at(&layer, "s3://bucket-a/object.txt")
        .await
        .expect("a hit is not charged");
    assert_eq!(store.hits(), 2);
}

/// A fallback endpoint naming a cloud instance-metadata host is refused at
/// `create_backend`, with or without the grant, before any client exists.
#[tokio::test]
async fn a_link_local_fallback_endpoint_is_refused_at_create_backend() {
    for granted in [true, false] {
        let mut config = LayerConfig::new();
        if granted {
            config.insert("anonymous_fallback".into(), grant(&["s3"]));
        }
        config.insert(
            "anonymous_fallback_endpoint".into(),
            ConfigValue::String("http://169.254.169.254/".into()),
        );
        let err = create_layer(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("granted={granted}: the endpoint must be refused"));
        assert_eq!(
            err.code(),
            ErrorCode::PermissionDenied,
            "granted={granted}: {err}"
        );
        assert!(
            err.message().contains("instance-metadata")
                && err.message().contains("169.254.169.254"),
            "granted={granted}: {}",
            err.message()
        );
    }
}
