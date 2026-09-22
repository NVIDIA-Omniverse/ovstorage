// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-lifecycle coverage for the ABI-v2 `AzureLayer` (RFC-0066):
//! the `ConnectionSet<AzureDriver>` integration — add/probe/remove,
//! the lenient verify policy judged on `x-ms-error-code`, parked-connection
//! behavior, the frozen-credentials update rejection, routing, and the
//! `Layer::list` fold contract — all against a scripted local mock Azure
//! endpoint (loopback `__test_endpoint`, Shared Key only; no real network).

use std::collections::HashMap;

use base64::Engine as _;
use futures::StreamExt as _;
use ovstorage_plugin::{
    AuthenticateRequest, BackendFactory, Body, ConfigValue, ConnectionAuthState, ConnectionKey,
    ConnectionRequest, ContinueWriteRequest, ErrorCode, InteractiveAuthCapability, LayerConfig,
    LayerConnectionRequest, LayerHandle, ListOptions, ListRequest, ObjectKind, RangeReadStrategy,
    ReadOptions, ReadRequest, ReadResult, RedirectResult, RedirectResultBatch, RenameOptions,
    RenameRequest, Request, RootInfo, SecretBundle, SecretBytes, SecretValue, StatOptions,
    StatRequest, UpdateConnectionCredentialsRequest, WatchDirectoryOptions, WatchDirectoryRequest,
    WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_azure::AzureLayerFactory;
use ovstorage_plugin_test::{
    CannedHttpResponse, Responder, Route, ScriptedHttpServer, ScriptedResponse,
};

mod support;
use support::{
    ANONYMOUS_FALLBACK_KEY, anonymous_fallback_grant, capture_logs, create_layer,
    fallback_layer_config,
};

// === Scripted mock Azure server ===
//
// Shared ovstorage_plugin_test::ScriptedHttpServer parameterized with one
// canned (status, x-ms-error-code, body) response. Enough to steer the
// driver's verify verdict (200 / 401 / 403 with an error code) and to feed
// `Layer::list` an EnumerationResults page.

fn spawn_scripted_server(
    status_line: &str,
    error_code: Option<&str>,
    body: &str,
) -> ScriptedHttpServer {
    let mut response = CannedHttpResponse::xml(status_line, body);
    if let Some(code) = error_code {
        response = response.with_header("x-ms-error-code", code);
    }
    ScriptedHttpServer::spawn(response)
}

const EMPTY_LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <EnumerationResults ServiceEndpoint=\"http://127.0.0.1/\" ContainerName=\"assets\">\
    <Blobs></Blobs><NextMarker /></EnumerationResults>";

const ERROR_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <Error><Code>scripted</Code><Message>scripted</Message></Error>";

/// Azure Storage and Azurite stamp `x-ms-request-id` on every response. The
/// acceptance counter requires it, so a fixture that means to stand in for the
/// service has to send it — that is the point of the gate, and a fixture
/// without it is standing in for a proxy.
const AZURE_REQUEST_ID: &str = "5e4d6c0e-201e-0042-3a1f-1f0b7c000000";

// === Helpers ===

fn account_key_bundle() -> SecretBundle {
    let key = base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "account_key".into(),
        SecretValue::Bytes(SecretBytes(key.into_bytes())),
    );
    bundle
}

fn connection_request(
    container: &str,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String("acct123".into()));
    config.insert("container".into(), ConfigValue::String(container.into()));
    config.insert(
        "__test_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    ConnectionRequest {
        backend_kind: "azure".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn empty_layer() -> LayerHandle {
    AzureLayerFactory::default()
        .create_backend("azure", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

// === add_connection verify verdicts ===

/// A 200 verify authenticates the connection, and the verify RPC is a signed
/// List Blobs with maxresults=1.
#[tokio::test]
async fn add_connection_authenticates_on_verify_pass() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(server.hits(), 1, "exactly one verify RPC");
    let raw = server.requests()[0].clone();
    assert!(raw.contains("comp=list"), "verify is List Blobs: {raw}");
    assert!(raw.contains("maxresults=1"), "verify is bounded: {raw}");
    assert!(
        raw.to_lowercase().contains("authorization: sharedkey"),
        "verify is signed: {raw}"
    );
}

/// Anonymous connections skip verify entirely (zero RPCs).
#[tokio::test]
async fn add_connection_anonymous_skips_verify() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), SecretBundle::default()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert_eq!(server.hits(), 0, "anonymous never verifies");
}

/// Lenient verify: 403 `AuthorizationPermissionMismatch` means the caller
/// authenticated but RBAC scopes it — the connection must still authenticate
/// (a read-scoped principal must remain registrable).
#[tokio::test]
async fn add_connection_authenticates_through_rbac_denial() {
    let server = spawn_scripted_server(
        "403 Forbidden",
        Some("AuthorizationPermissionMismatch"),
        ERROR_BODY,
    );
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// A 403 `AuthenticationFailed` (bad Shared Key signature / expired SAS) is a
/// credential rejection: the connection parks, stays listed, and keeps its
/// config-derived root routable.
#[tokio::test]
async fn add_connection_parks_on_authentication_failed() {
    let server = spawn_scripted_server("403 Forbidden", Some("AuthenticationFailed"), ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
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
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
    let root = layer
        .root_info_for(
            &address::parse("azure://acct123/assets/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "azure://acct123/assets/");
}

/// A raw 401 is likewise a credential rejection → parked.
#[tokio::test]
async fn add_connection_parks_on_401() {
    let server = spawn_scripted_server(
        "401 Unauthorized",
        Some("InvalidAuthenticationInfo"),
        ERROR_BODY,
    );
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    let root = layer
        .root_info_for(
            &address::parse("azure://acct123/assets/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "azure://acct123/assets/");
}

/// A parked connection is what `authenticate_connection` is called on, and
/// Azure has no interactive flow to run: credentials arrive with the
/// connection. The call is refused with `Unsupported`, and the connection is
/// left exactly as parked as it was, still registered.
///
/// The load-bearing line is the `Unsupported` error in
/// `AzureDriver::interactive`. Restoring the
/// `AuthEvent::Succeeded { credentials: None }` it used to emit makes this
/// test hand back a stream instead; draining that stream runs the promoting
/// adapter, and the parked-state check then reads `Authenticated` — a
/// connection promoted on no grant and no probe, which is the defect this pins.
#[tokio::test]
async fn authenticate_connection_leaves_a_parked_connection_parked() {
    let server = spawn_scripted_server(
        "401 Unauthorized",
        Some("InvalidAuthenticationInfo"),
        ERROR_BODY,
    );
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
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
        target: "azure".into(),
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

// === parked connections that are, in fact, working ===

/// The reported auth state must follow the data path, not just the probe.
///
/// The driver's verify is one container-scope `List Blobs`; the data path is a
/// different verb on a different scope, and a deployment can refuse the first
/// while serving the second. Auth is frozen into the backend at add time and no
/// object op consults `auth_state`, so the connection parks and then goes on
/// signing successful requests while reporting that it needs authentication. A
/// successful operation is the better evidence, so it promotes the connection.
#[tokio::test]
async fn successful_data_path_promotes_a_parked_connection() {
    let responder = Responder::start(vec![
        // The verify probe: container-scope List Blobs, refused as a credential
        // rejection so `add_connection` parks.
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The data path: HEAD Blob, served.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 200,
                headers: vec![
                    ("etag".into(), "\"0x8DCF\"".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a refused verify parks the connection, got {:?}",
        connection.auth_state
    );

    // Half one: the request really is Shared-Key signed, and really succeeds.
    let info = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("a parked connection still serves signed requests");
    assert_eq!(info.kind, ObjectKind::File);
    let head = responder
        .captures()
        .into_iter()
        .find(|request| request.method.eq_ignore_ascii_case("HEAD"))
        .expect("the data path reached the wire");
    assert!(
        head.headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                && value.starts_with("SharedKey ")),
        "the data-path request must be Shared-Key signed: {:?}",
        head.headers
    );

    // Half two: the reported state follows that evidence.
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a connection doing successful signed work must not report AwaitingAuth, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// A response fetched after a CROSS-ORIGIN redirect is not evidence.
///
/// reqwest follows redirects and strips `Authorization` when the hop changes
/// host or port, never restoring it — so the second leg is unsigned, and its
/// `200` says nothing about this connection's credential however well the final
/// URL matches. A parked connection must stay parked.
#[tokio::test]
async fn a_cross_origin_redirect_does_not_promote_a_parked_connection() {
    // The host the redirect lands on: serves the blob, stamped as Azure would.
    let elsewhere = Responder::start(vec![Route::new(
        "HEAD",
        "",
        ScriptedResponse {
            status: 200,
            headers: vec![
                ("etag".into(), "\"0x8DCF\"".into()),
                ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
            ],
            body: Vec::new(),
        },
    )])
    .expect("redirect target starts");
    let responder = Responder::start(vec![
        // The verify probe, refused, so `add_connection` parks.
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The data path, bounced to the other origin.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 302,
                headers: vec![(
                    "location".into(),
                    format!("{}assets/obj.txt", elsewhere.base_url()),
                )],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));

    let info = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await;

    // Control — the redirect was followed and the second leg really was served
    // WITHOUT the credential, which is what makes its success worthless here.
    let followed = elsewhere.captures();
    assert!(
        !followed.is_empty(),
        "control: the redirect must have been followed"
    );
    assert!(
        !followed[0]
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization")),
        "control: reqwest strips the bearer across origins: {:?}",
        followed[0].headers
    );
    assert!(info.is_ok(), "the redirected stat is served: {info:?}");

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a response fetched with no credential is no proof of one, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// On a FLAT namespace the same `read` mints its signed URL without the service
/// seeing anything, so nothing was accepted and nothing may be promoted. A
/// connection parked on a genuinely rejected key stays parked however many
/// redirects it hands out.
#[tokio::test]
async fn minting_a_read_redirect_does_not_promote_a_parked_connection() {
    let server = spawn_scripted_server("403 Forbidden", Some("AuthenticationFailed"), ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    let verify_hits = server.hits();

    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("a parked connection still mints redirects");
    assert!(matches!(result, ReadResult::Redirect { .. }));
    assert_eq!(
        server.hits(),
        verify_hits,
        "the redirect mint reaches no service"
    );

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a locally-minted redirect is not proof of a working credential, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// `watch_directory` establishes by spawning a producer and handing back a
/// stream, having sent nothing; the refusal, if there is one, arrives on the
/// stream. Nothing was accepted, so nothing may be promoted.
#[tokio::test]
async fn establishing_a_watch_does_not_promote_a_parked_connection() {
    let server = spawn_scripted_server("403 Forbidden", Some("AuthenticationFailed"), ERROR_BODY);
    let layer = empty_layer().await;
    let mut request = connection_request("assets", server.endpoint(), account_key_bundle());
    request
        .config
        .insert("change_feed_enabled".into(), ConfigValue::Bool(true));
    let connection = add(&layer, request).await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    let verify_hits = server.hits();

    let _stream = layer
        .watch_directory(
            Request::new(WatchDirectoryRequest {
                prefix: address::parse("azure://acct123/assets/dir/").unwrap(),
                options: WatchDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .expect("a parked connection still establishes a subscription");
    assert_eq!(
        server.hits(),
        verify_hits,
        "establishment reaches no service"
    );

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "spawning a producer is not proof of a working credential, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// The same `read` slot, on a hierarchical namespace, DOES reach the service:
/// its kind preflight is a signed request, and a service that answers it has
/// accepted the credential. The promotion follows the run, not the slot — which
/// is the whole point of measuring acceptance instead of classifying slots.
#[tokio::test]
async fn an_accepted_hns_read_preflight_promotes_a_parked_connection() {
    let responder = Responder::start(vec![
        // The verify probe is refused, so the connection parks.
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The HNS kind preflight is answered: a file, and an accepted credential.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 200,
                headers: vec![
                    ("x-ms-resource-type".into(), "file".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let mut request = connection_request("assets", &responder.base_url(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    let connection = add(&layer, request).await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));

    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("a file address still reads");
    assert!(matches!(result, ReadResult::Redirect { .. }));

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the preflight the service answered is proof, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// The counter is an allowlist of answers only an authenticated request can
/// get, not "anything that was not a refusal" — so an outage proves nothing.
/// The same HNS read whose 200 preflight promotes leaves the connection parked
/// when the preflight is a 503, because a front door can emit one without ever
/// looking at the signature.
#[tokio::test]
async fn a_service_outage_does_not_promote_a_parked_connection() {
    let responder = Responder::start(vec![
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The kind preflight is answered by an outage, not by the service.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 503,
                headers: vec![
                    ("x-ms-error-code".into(), "ServerBusy".into()),
                    // Azure's own answer, so this pins the STATUS allowlist and
                    // not the origin gate one clause earlier.
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let mut request = connection_request("assets", &responder.base_url(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    add(&layer, request).await;

    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("a preflight with no verdict still reads");
    assert!(matches!(result, ReadResult::Redirect { .. }));
    // Without this the test passes vacuously: if the preflight stopped being
    // issued, `read` would still redirect and the connection would still be
    // parked, and the allowlist this exists to pin would go unexercised.
    assert!(
        responder
            .captures()
            .iter()
            .any(|request| request.method.eq_ignore_ascii_case("HEAD")),
        "the kind preflight must have reached the responder"
    );

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a 503 is not evidence about a credential, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// A write consumes its body, so it runs outside the retry-once recovery loop
/// — but the service accepting it is the same evidence any other accepted
/// request is, and a connection that is demonstrably writing must not go on
/// reporting that it needs authentication.
#[tokio::test]
async fn an_accepted_write_promotes_a_parked_connection() {
    let responder = Responder::start(vec![
        // The verify probe is refused, so the connection parks.
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The Put Blob is accepted.
        Route::new(
            "PUT",
            "",
            ScriptedResponse {
                status: 201,
                headers: vec![
                    ("etag".into(), "\"0x8DCF\"".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));

    layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                body: Body::Bytes(b"hello".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("a parked connection still writes");

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "an accepted write is proof, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// A single-redirect write is performed by the caller's follower, so the
/// plugin's client never sees the response — and the 2xx the caller reports
/// back must NOT stand in for it. `results` arrives from whoever called
/// `continue_write`, and under the broker that is a remote client reading off
/// the wire, so honouring it would let anyone with write access flip an
/// operator's shared connection to `Authenticated` without performing a single
/// request. The connection stays parked; a redirect-only writer is promoted by
/// some other operation or not at all.
#[tokio::test]
async fn a_reported_redirect_result_does_not_promote_a_parked_connection() {
    let server = spawn_scripted_server("403 Forbidden", Some("AuthenticationFailed"), ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    let address = address::parse("azure://acct123/assets/big.bin").unwrap();

    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(8),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("a parked connection still mints redirects");
    let hits_before_continue = server.hits();

    // The caller's report — which here is a fabrication: no PUT was performed.
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 201,
                captured_headers: vec![
                    ("etag".into(), "\"0x8DCF\"".into()),
                    (
                        "last-modified".into(),
                        "Mon, 01 Jan 2024 00:00:00 GMT".into(),
                    ),
                ],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    layer
        .continue_write(
            Request::new(ContinueWriteRequest {
                address,
                redirects: batch,
                results,
            }),
            None,
        )
        .await
        .expect("the commit accepts the follower's 2xx");
    assert_eq!(
        server.hits(),
        hits_before_continue,
        "a single-redirect commit reaches no service of its own"
    );

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a result the caller reported is not evidence, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// Acceptance is evidence, not outcome. The HNS directory refusal this PR adds
/// is the sharpest case: the kind preflight is answered by the service — the
/// credential demonstrably works — and then `read` returns `InvalidArgument`
/// for the address. The connection must still be promoted, or a workload of
/// directory reads leaves a working connection parked forever.
#[tokio::test]
async fn an_authenticated_refusal_promotes_a_parked_connection() {
    let responder = Responder::start(vec![
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The service answers the kind probe: a directory, and an accepted
        // credential.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 200,
                headers: vec![
                    ("x-ms-resource-type".into(), "directory".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let mut request = connection_request("assets", &responder.base_url(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    add(&layer, request).await;

    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("azure://acct123/assets/dir/").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a directory address must be refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the service answered the probe; the refusal that followed is not a          verdict on the credential, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// A 200 that Azure did not produce is not evidence. A portal or proxy that
/// intercepts the request and answers on the service's behalf carries none of
/// Azure's response headers, and promoting on it would report a refused
/// credential as `Authenticated` with nothing able to undo it.
#[tokio::test]
async fn a_response_from_something_other_than_azure_does_not_promote() {
    let responder = Responder::start(vec![
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // A friendly 200 with no `x-ms-*` anything: an SSO portal, not Azure.
        Route::new(
            "HEAD",
            "",
            ScriptedResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/html".into())],
                body: Vec::new(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    let mut request = connection_request("assets", &responder.base_url(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    add(&layer, request).await;

    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("azure://acct123/assets/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("a probe with no verdict still reads");
    assert!(matches!(result, ReadResult::Redirect { .. }));

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "only Azure's own answer is evidence about an Azure credential, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// Acceptance is a property of the whole operation, not of its friendliest
/// response. A multi-request operation can have one request accepted and the
/// next refused — a SAS that expires, a key rotated mid-flight — and counting
/// only the accept side would promote a connection whose credential had just
/// died. The data path never parks on a 403 and these drivers have no refresh,
/// so nothing would undo it.
#[tokio::test]
async fn a_refusal_mid_operation_does_not_promote_a_parked_connection() {
    let responder = Responder::start(vec![
        // The verify probe is refused, so the connection parks.
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The rename's server-side copy is accepted...
        Route::new(
            "PUT",
            "",
            ScriptedResponse {
                status: 202,
                headers: vec![
                    ("x-ms-copy-status".into(), "success".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
        // ...and then the credential dies before the source delete.
        Route::new(
            "DELETE",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![
                    ("x-ms-error-code".into(), "AuthenticationFailed".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;

    let outcome = layer
        .rename(
            Request::new(RenameRequest {
                source: address::parse("azure://acct123/assets/from.txt").unwrap(),
                destination: address::parse("azure://acct123/assets/to.txt").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await;
    assert!(outcome.is_err(), "the delete was refused");

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a credential refused during the operation is not proof of it, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// The service's verdict arrives in the status and headers; the body is
/// commentary. A refusal whose body fails mid-stream — a reset connection, a
/// proxy closing early — must still count as a refusal, or a multi-request
/// operation whose credential died looks like one with an acceptance and no
/// refusal, and promotes.
#[tokio::test]
async fn a_refusal_with_a_truncated_body_still_counts_as_a_refusal() {
    let responder = Responder::start(vec![
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        // The copy is accepted.
        Route::new(
            "PUT",
            "",
            ScriptedResponse {
                status: 202,
                headers: vec![
                    ("x-ms-copy-status".into(), "success".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
        // The delete is refused — and the body is cut short of the length it
        // promises, so reading it fails after the verdict has been delivered.
        Route::new(
            "DELETE",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![
                    ("x-ms-error-code".into(), "AuthenticationFailed".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                    ("content-length".into(), "4096".into()),
                ],
                body: b"<Error>".to_vec(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;

    let outcome = layer
        .rename(
            Request::new(RenameRequest {
                source: address::parse("azure://acct123/assets/from.txt").unwrap(),
                destination: address::parse("azure://acct123/assets/to.txt").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await;
    assert!(outcome.is_err(), "the delete was refused");

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a refusal is a refusal however its body ended, got {:?}",
        snapshot.connections[0].auth_state
    );
}

/// The Shared Key refusal shapes the PARKING rule deliberately excludes still
/// have to veto a promotion: Azurite reports a failed signature as
/// `403 AuthorizationFailure`, and a proxy can strip `x-ms-error-code`
/// entirely. Neither is in the list `verify` parks on, and neither may leave a
/// mid-operation credential death looking like an operation with an acceptance
/// and no refusal.
#[tokio::test]
async fn an_ambiguous_refusal_mid_operation_does_not_promote() {
    let responder = Responder::start(vec![
        Route::new(
            "GET",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![("x-ms-error-code".into(), "AuthenticationFailed".into())],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
        Route::new(
            "PUT",
            "",
            ScriptedResponse {
                status: 202,
                headers: vec![
                    ("x-ms-copy-status".into(), "success".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: Vec::new(),
            },
        ),
        // Azurite's failed-signature shape, which `verify` does not park on.
        Route::new(
            "DELETE",
            "",
            ScriptedResponse {
                status: 403,
                headers: vec![
                    ("x-ms-error-code".into(), "AuthorizationFailure".into()),
                    ("x-ms-request-id".into(), AZURE_REQUEST_ID.into()),
                ],
                body: ERROR_BODY.as_bytes().to_vec(),
            },
        ),
    ])
    .expect("responder starts");
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request("assets", &responder.base_url(), account_key_bundle()),
    )
    .await;

    let outcome = layer
        .rename(
            Request::new(RenameRequest {
                source: address::parse("azure://acct123/assets/from.txt").unwrap(),
                destination: address::parse("azure://acct123/assets/to.txt").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await;
    assert!(outcome.is_err(), "the delete was refused");

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "an ambiguous 403 must withhold the promotion, got {:?}",
        snapshot.connections[0].auth_state
    );
}

// === probe ===

/// Probe validates without registering: verdict mirrors add_connection, no
/// connection appears, and the advertised address comes from config.
#[tokio::test]
async fn probe_reports_verdict_without_registering() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: connection_request("assets", server.endpoint(), account_key_bundle()),
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
    assert_eq!(
        probed.current_addresses[0].as_str(),
        "azure://acct123/assets/"
    );
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
    let server = spawn_scripted_server("403 Forbidden", Some("AuthenticationFailed"), ERROR_BODY);
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: connection_request("assets", server.endpoint(), account_key_bundle()),
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

// === frozen credentials ===

/// Azure credentials are frozen at add time (no live cell; `AzureAuth` is
/// immutable): EVERY `update_connection_credentials` is rejected with
/// remove-and-re-add guidance because the client has no live credential cell.
/// The connection's state is untouched.
#[tokio::test]
async fn update_credentials_is_rejected_with_guidance() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    let verify_hits = server.hits();

    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "azure".into(),
                    id: connection.id.clone(),
                },
                credentials: account_key_bundle(),
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
    assert_eq!(server.hits(), verify_hits, "no verify RPC on rejection");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
    assert!(matches!(
        snapshot.connections[0].auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// An unknown connection id is `NotFound`, not the frozen-credentials error.
#[tokio::test]
async fn update_credentials_on_unknown_connection_is_not_found() {
    let layer = empty_layer().await;
    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "azure".into(),
                    id: ovstorage_plugin::ConnectionId("nope".into()),
                },
                credentials: account_key_bundle(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
}

// === routing + teardown ===

/// Two connections (two containers) route by longest prefix; removal tears
/// the routes down.
#[tokio::test]
async fn routes_across_two_connections_and_removes() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let alpha = add(
        &layer,
        connection_request("alpha", server.endpoint(), SecretBundle::default()),
    )
    .await;
    add(
        &layer,
        connection_request("beta", server.endpoint(), SecretBundle::default()),
    )
    .await;

    for container in ["alpha", "beta"] {
        let root = layer
            .root_info_for(
                &address::parse(&format!("azure://acct123/{container}/x")).unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(root.root.as_str(), format!("azure://acct123/{container}/"));
    }

    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "azure".into(),
                id: alpha.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    let err = layer
        .root_info_for(
            &address::parse("azure://acct123/alpha/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoRoute);
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
}

// === Layer::list contract: fold + numeric-offset pagination ===

const LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <EnumerationResults ServiceEndpoint=\"http://127.0.0.1/\" ContainerName=\"assets\">\
    <Blobs>\
    <Blob><Name>team/</Name><Properties>\
    <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>\
    <Etag>0x8DCM</Etag><Content-Length>0</Content-Length>\
    </Properties></Blob>\
    <Blob><Name>team/file.txt</Name><Properties>\
    <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>\
    <Etag>0x8DCF</Etag><Content-Length>5</Content-Length>\
    </Properties></Blob>\
    <BlobPrefix><Name>docs/</Name></BlobPrefix>\
    </Blobs><NextMarker /></EnumerationResults>";

/// On Azure's flat namespace, `Layer::list` folds marker
/// objects fold to `DirectoryMarker`, blob prefixes surface as
/// `DirectoryInferred`, and pagination is the shared numeric-offset
/// convention over the folded set.
#[tokio::test]
async fn list_folds_markers_and_paginates() {
    let server = spawn_scripted_server("200 OK", None, LIST_BODY);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;

    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("azure://acct123/assets/").unwrap(),
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
    assert_eq!(
        page.items[0].address.as_str(),
        "azure://acct123/assets/team/"
    );
    assert_eq!(page.items[0].kind, ObjectKind::DirectoryMarker);
    assert_eq!(
        page.items[1].address.as_str(),
        "azure://acct123/assets/team/file.txt"
    );
    assert_eq!(page.items[1].kind, ObjectKind::File);
    let token = page.next_page_token.expect("second page");

    let page2 = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("azure://acct123/assets/").unwrap(),
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
    assert_eq!(
        page2.items[0].address.as_str(),
        "azure://acct123/assets/docs/"
    );
    assert_eq!(page2.items[0].kind, ObjectKind::DirectoryInferred);
    assert!(page2.next_page_token.is_none());
}

const HNS_LIST_BODY: &str = "{\
    \"paths\": [\
    { \"name\": \"team\", \"isDirectory\": \"true\", \"lastModified\": \"Tue, 02 Jan 2024 01:00:00 GMT\" },\
    { \"name\": \"team/file.txt\", \"contentLength\": \"5\", \"etag\": \"0x8DCF\", \"lastModified\": \"Tue, 02 Jan 2024 00:00:00 GMT\" }\
    ]}";

/// The ADLS Gen2 (hierarchical namespace) list branch: real directory inodes
/// pass through the fold as concrete `Directory` kinds — no marker synthesis
/// and, critically, no Directory → DirectoryInferred downgrade (which is
/// exactly what the flat branch would do). Pins `has_real_directories` being
/// threaded from the connection's `hierarchical_namespace` into the fold.
#[tokio::test]
async fn hns_list_passes_real_directories_through_unfolded() {
    let server = spawn_scripted_server("200 OK", None, HNS_LIST_BODY);
    let layer = empty_layer().await;
    let mut request = connection_request("assets", server.endpoint(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    add(&layer, request).await;

    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("azure://acct123/assets/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    // Emitted WITH the separator: one listing spells its directories one way,
    // whatever the backend reported. HNS reports a directory without one.
    let directory = page
        .items
        .iter()
        .find(|item| item.address.as_str() == "azure://acct123/assets/team/")
        .expect("directory entry listed");
    assert_eq!(
        directory.kind,
        ObjectKind::Directory,
        "a real HNS directory must stay concrete, not fold to DirectoryInferred"
    );
    let file = page
        .items
        .iter()
        .find(|item| item.address.as_str() == "azure://acct123/assets/team/file.txt")
        .expect("file entry listed");
    assert_eq!(file.kind, ObjectKind::File);
    assert!(page.next_page_token.is_none());
}

/// Native streaming uses the same per-instance directory model as buffered
/// listing: flat markers are folded, while HNS directory inodes remain real.
#[tokio::test]
async fn streamed_list_matches_buffered_fold_for_flat_and_hns_instances() {
    for (hierarchical_namespace, body, expected_directory_kind) in [
        (false, LIST_BODY, ObjectKind::DirectoryMarker),
        (true, HNS_LIST_BODY, ObjectKind::Directory),
    ] {
        let server = spawn_scripted_server("200 OK", None, body);
        let layer = empty_layer().await;
        let mut connection = connection_request("assets", server.endpoint(), account_key_bundle());
        connection.config.insert(
            "hierarchical_namespace".into(),
            ConfigValue::Bool(hierarchical_namespace),
        );
        let connection = add(&layer, connection).await;
        assert!(connection.capabilities.supports_list_stream);

        let prefix = address::parse("azure://acct123/assets/").unwrap();
        let buffered = layer
            .list(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap()
            .items;
        let mut stream = layer
            .list_stream(
                Request::new(ListRequest {
                    prefix,
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let mut streamed = Vec::new();
        while let Some(item) = stream.next().await {
            streamed.push(item.unwrap());
        }

        assert_eq!(streamed, buffered, "hns={hierarchical_namespace}");
        assert_eq!(
            streamed[0].kind, expected_directory_kind,
            "hns={hierarchical_namespace} must select its own fold mode"
        );
    }
}

// === Anonymous scheme fallback: layer policy, routing precedence, refusals ===
//
// The fallback is a layer-table grant, not a connection: it is built by the
// factory, publishes one hidden `azure:///` root, registers nothing in the
// connection set, and answers only the addresses no connection's root is a
// prefix of. The wire-level assertions (unsigned requests, refused mutations)
// live in `anonymous_public_container.rs`; this section pins the lifecycle
// side.

const FALLBACK_BUILT: &str = "anonymous fallback backend built";

async fn root_info(layer: &LayerHandle, address: &str) -> ovstorage_plugin::Result<RootInfo> {
    layer
        .root_info_for(
            &address::parse(address).unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
}

async fn root_for(layer: &LayerHandle, address: &str) -> ovstorage_plugin::Result<String> {
    root_info(layer, address)
        .await
        .map(|root| root.root.as_str().to_string())
}

async fn stat_code(layer: &LayerHandle, address: &str) -> ovstorage_plugin::Error {
    layer
        .stat(
            Request::new(StatRequest {
                address: address::parse(address).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("the stat must be refused")
}

async fn list_prefix(layer: &LayerHandle, prefix: &str) -> ovstorage_plugin::Result<()> {
    layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse(prefix).unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .map(|_| ())
}

/// No grant, no fallback: an address no connection serves is `NoRoute` with
/// the message every miss has always carried, whether the layer is empty or
/// serves some other container.
#[tokio::test]
async fn fallback_is_off_by_default() {
    let layer = empty_layer().await;
    let err = stat_code(&layer, "azure://acct123/assets/x").await;
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert_eq!(err.message(), "no route matches address");

    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    add(
        &layer,
        connection_request("alpha", server.endpoint(), SecretBundle::default()),
    )
    .await;
    let err = stat_code(&layer, "azure://acct123/beta/x").await;
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert_eq!(err.message(), "no route matches address");
    assert_eq!(server.hits(), 0, "a miss reaches no service");

    let (snapshot, _) = layer
        .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(
        snapshot
            .roots
            .iter()
            .map(|root| root.root.as_str().to_string())
            .collect::<Vec<_>>(),
        ["azure://acct123/alpha/"],
        "no scheme root is published without a grant"
    );
}

/// A layer table holding only the grant is policy, not a connection: the
/// factory seeds nothing, and the one root it publishes is the hidden, marked
/// scheme root with no connection behind it.
#[tokio::test]
async fn a_layer_holding_only_the_fallback_key_seeds_no_static_connection() {
    let mut config = LayerConfig::new();
    config.insert(
        ANONYMOUS_FALLBACK_KEY.into(),
        anonymous_fallback_grant(&["azure"]),
    );
    let layer = create_layer(&config)
        .await
        .expect("a grant alone is not a connection with a missing account");

    let (snapshot, _) = layer
        .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.roots.len(), 1, "{:?}", snapshot.roots);
    let root = &snapshot.roots[0];
    assert_eq!(root.root.as_str(), "azure:///");
    assert!(ovstorage_plugin::fallback::is_scheme_fallback_root(root));
    assert_eq!(root.visibility, ovstorage_plugin::AddressVisibility::Hidden);
    assert!(!root.visible);
    assert_eq!(root.connection_id, None);
    assert_eq!(root.owning_target, None);
    assert_eq!(root.layer_kind, "azure");
    assert_eq!(
        root.user_metadata
            .get(ovstorage_plugin::fallback::SCHEME_FALLBACK_METADATA_KEY)
            .map(String::as_str),
        Some(ovstorage_plugin::fallback::SCHEME_FALLBACK_ANONYMOUS)
    );
    assert_eq!(
        root.range_read_strategy,
        RangeReadStrategy::Native,
        "the fallback advertises the ranged reads its client supports"
    );

    let (connections, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        connections.connections.is_empty(),
        "the fallback registers no connection: {:?}",
        connections.connections
    );

    // The loopback-only test hook beside the grant is the fallback's, not a
    // half-written connection.
    let layer = create_layer(&fallback_layer_config("http://127.0.0.1:1", &[]))
        .await
        .expect("grant plus test hook seeds nothing");
    let (connections, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(connections.connections.is_empty());
}

/// The grant is checked against the schemes this kind serves. A scheme
/// another kind owns is refused at startup, naming both.
#[tokio::test]
async fn a_fallback_key_naming_a_scheme_this_layer_does_not_serve_is_refused() {
    for schemes in [&["s3"][..], &["azure", "gs"][..], &["https"][..]] {
        let mut config = LayerConfig::new();
        config.insert(
            ANONYMOUS_FALLBACK_KEY.into(),
            anonymous_fallback_grant(schemes),
        );
        let err = create_layer(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("{schemes:?} must be refused"));
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{schemes:?}");
        let foreign = schemes
            .iter()
            .find(|scheme| **scheme != "azure")
            .expect("each case names a foreign scheme");
        assert!(
            err.message().contains(&format!("`{foreign}`")),
            "{schemes:?}: {}",
            err.message()
        );
        assert!(
            err.message().contains("it serves azure"),
            "{schemes:?}: {}",
            err.message()
        );
    }
}

/// The grant must be a TOML array of scheme strings, and every other
/// `anonymous_fallback_*` key must be one this kind reads. Both are refused
/// at `create_backend`, before any connection is seeded.
#[tokio::test]
async fn a_non_array_fallback_key_is_refused_at_create_backend() {
    for value in [
        ConfigValue::String("azure".into()),
        ConfigValue::Bool(true),
        ConfigValue::Toml("anonymous_fallback = \"azure\"\n".into()),
    ] {
        let mut config = LayerConfig::new();
        config.insert(ANONYMOUS_FALLBACK_KEY.into(), value.clone());
        let err = create_layer(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("{value:?} must be refused"));
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{value:?}");
        assert!(
            err.message().contains("must be a TOML array"),
            "{value:?}: {}",
            err.message()
        );
    }

    // A tunable another kind reads is refused by name, granted or not.
    for granted in [true, false] {
        let mut config = LayerConfig::new();
        if granted {
            config.insert(
                ANONYMOUS_FALLBACK_KEY.into(),
                anonymous_fallback_grant(&["azure"]),
            );
        }
        config.insert(
            "anonymous_fallback_endpoint".into(),
            ConfigValue::String("http://127.0.0.1:1".into()),
        );
        let err = create_layer(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("granted={granted}: the S3 key must be refused"));
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("anonymous_fallback_endpoint"),
            "granted={granted}: {}",
            err.message()
        );
    }
}

/// A fallback key on a CONNECTION request — probe or add — is refused with a
/// message that says where the key belongs, and nothing is registered or
/// sent.
#[tokio::test]
async fn a_connection_request_carrying_a_fallback_key_is_refused() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    for key in ["anonymous_fallback", "anonymous_fallback_max_backends"] {
        let mut request = connection_request("assets", server.endpoint(), account_key_bundle());
        request
            .config
            .insert(key.into(), anonymous_fallback_grant(&["azure"]));
        let expected = format!(
            "`{key}` is a layer key, not connection config; set it on [ovstorage.layers.azure]"
        );

        let err = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "azure".into(),
                    connection: request.clone(),
                }),
                None,
            )
            .await
            .expect_err("add must refuse a fallback key");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), expected);

        let err = layer
            .probe(
                Request::new(LayerConnectionRequest {
                    target: "azure".into(),
                    connection: request,
                }),
                None,
            )
            .await
            .expect_err("probe must refuse a fallback key");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), expected);
    }
    assert_eq!(server.hits(), 0, "refused before any verify");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(snapshot.connections.is_empty());
}

/// A connection's root is a prefix hit and outranks the fallback for its
/// node; every other node keeps falling back. Installing the connection also
/// evicts the fallback backend cached for that node, which is what lets the
/// node be minted afresh when the connection goes away again.
#[tokio::test]
async fn a_configured_root_outranks_the_fallback_and_install_evicts_the_cached_backend() {
    let logs = capture_logs();
    let fallback_server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let connection_server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = create_layer(&fallback_layer_config(fallback_server.endpoint(), &[]))
        .await
        .unwrap();

    list_prefix(&layer, "azure://acct123/assets/")
        .await
        .expect("the fallback lists the container");
    assert_eq!(fallback_server.hits(), 1);
    assert_eq!(
        root_for(&layer, "azure://acct123/assets/x").await.unwrap(),
        "azure:///",
        "a tier-2 hit answers the scheme root verbatim"
    );
    assert_eq!(logs.containing(FALLBACK_BUILT).len(), 1);

    let connection = add(
        &layer,
        connection_request(
            "assets",
            connection_server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    list_prefix(&layer, "azure://acct123/assets/")
        .await
        .expect("the connection lists the container");
    assert_eq!(connection_server.hits(), 1, "the configured root answers");
    assert_eq!(
        fallback_server.hits(),
        1,
        "and the fallback is not consulted"
    );
    assert_eq!(
        root_for(&layer, "azure://acct123/assets/x").await.unwrap(),
        "azure://acct123/assets/"
    );
    // A sibling container on the same account is still the fallback's.
    list_prefix(&layer, "azure://acct123/other/")
        .await
        .expect("an unconfigured sibling still falls back");
    assert_eq!(fallback_server.hits(), 2);
    assert_eq!(connection_server.hits(), 1);

    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "azure".into(),
                id: connection.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    list_prefix(&layer, "azure://acct123/assets/")
        .await
        .expect("the fallback answers again once the connection is gone");
    assert_eq!(fallback_server.hits(), 3);
    assert_eq!(
        logs.containing(FALLBACK_BUILT).len(),
        3,
        "assets was rebuilt after the install evicted it; other was built once: {:?}",
        logs.containing(FALLBACK_BUILT)
    );
}

/// The scheme root names no account, and neither does a hostless address
/// with a path; both reach the fallback through the prefix tier and are
/// refused before any backend exists. `root_info_for` on the root still
/// returns the root — introspection, not an operation.
#[tokio::test]
async fn the_scheme_root_itself_is_invalid_argument() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = create_layer(&fallback_layer_config(server.endpoint(), &[]))
        .await
        .unwrap();
    for spelling in ["azure:///", "azure:///assets/x"] {
        let err = stat_code(&layer, spelling).await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
        assert_eq!(
            err.message(),
            "an azure:// address names no storage account",
            "{spelling}"
        );
        let err = list_prefix(&layer, spelling).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
    }
    assert_eq!(server.hits(), 0);
    assert_eq!(root_for(&layer, "azure:///").await.unwrap(), "azure:///");
}

/// `root_info_for` answers the scheme root verbatim for a fallback-served
/// address, so what that root advertises is what a consumer reads. The
/// fallback drives the same blob client a connection does and a ranged read
/// works the same way through either, so the strategy it advertises is the
/// connection root's: a store must not look less capable for being reached
/// anonymously than for being configured. Introspection only — nothing
/// reaches the wire.
#[tokio::test]
async fn a_fallback_served_address_advertises_the_range_read_strategy_of_a_configured_root() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = create_layer(&fallback_layer_config(server.endpoint(), &[]))
        .await
        .unwrap();
    add(
        &layer,
        connection_request("assets", server.endpoint(), SecretBundle::default()),
    )
    .await;

    let configured = root_info(&layer, "azure://acct123/assets/x").await.unwrap();
    let fallback = root_info(&layer, "azure://acct123/other/x").await.unwrap();
    assert_eq!(configured.root.as_str(), "azure://acct123/assets/");
    assert_eq!(fallback.root.as_str(), "azure:///");
    assert_eq!(configured.range_read_strategy, RangeReadStrategy::Native);
    assert_eq!(
        fallback.range_read_strategy, configured.range_read_strategy,
        "the direct and the fallback answer for one store agree"
    );
    assert_eq!(server.hits(), 0);
}

/// The fallback's `__test_endpoint` is read by the same endpoint parser the
/// connection keys use, so URL-embedded credentials, a query and a fragment
/// are refused at `create_backend` — before the fallback exists, let alone a
/// backend or a request — and the refusal names the hook and the shape
/// without echoing the value. A loopback host is used so the loopback guard
/// is not what refuses them.
#[tokio::test]
async fn a_fallback_test_endpoint_with_userinfo_a_query_or_a_fragment_is_refused_at_create_backend()
{
    for (endpoint, shape) in [
        ("http://user:s3cret@127.0.0.1:1", "credentials"),
        ("http://s3cret@127.0.0.1:1", "credentials"),
        ("http://127.0.0.1:1?sig=s3cret", "query string"),
        ("http://127.0.0.1:1#s3cret", "fragment"),
    ] {
        let Err(err) = create_layer(&fallback_layer_config(endpoint, &[])).await else {
            panic!("{endpoint} must be refused at create_backend");
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{endpoint}");
        assert!(
            err.message().contains("__test_endpoint"),
            "{endpoint}: the refusal names the hook: {}",
            err.message()
        );
        assert!(
            err.message().contains(shape),
            "{endpoint}: the refusal names the shape: {}",
            err.message()
        );
        assert!(
            !err.message().contains("s3cret"),
            "{endpoint}: the refusal echoes the value: {}",
            err.message()
        );
    }
}

/// An address whose query carries anything but a version id authenticates
/// itself — a SAS — and never takes the fallback: the miss is the same
/// `NoRoute` an ungranted layer answers. A version id alone still routes.
#[tokio::test]
async fn a_presigned_or_sas_query_falls_through_to_no_route() {
    let server = spawn_scripted_server("200 OK", None, EMPTY_LIST_BODY);
    let layer = create_layer(&fallback_layer_config(server.endpoint(), &[]))
        .await
        .unwrap();
    for address in [
        "azure://acct123/assets/x?sv=2024-01-01&sr=b&sig=abc",
        "azure://acct123/assets/x?sig=abc",
        "azure://acct123/assets/x?snapshot=2026-01-01T00:00:00Z",
    ] {
        let err = root_for(&layer, address).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoRoute, "{address}");
        assert_eq!(err.message(), "no route matches address", "{address}");
        let err = stat_code(&layer, address).await;
        assert_eq!(err.code(), ErrorCode::NoRoute, "{address}");
    }
    assert_eq!(
        server.hits(),
        0,
        "a credential-bearing address reaches nothing"
    );

    assert_eq!(
        root_for(&layer, "azure://acct123/assets/x?versionid=7")
            .await
            .unwrap(),
        "azure:///"
    );
    list_prefix(&layer, "azure://acct123/assets/?versionid=7")
        .await
        .expect("a version id is carried, not a credential");
    assert_eq!(server.hits(), 1);
}

/// A connection an operator points at an instance-metadata host is honoured,
/// with one warning naming the host. The unconditional refusal is for hosts
/// derived from a caller's address, which no configured connection has.
#[tokio::test]
async fn a_configured_instance_metadata_endpoint_is_honoured_with_a_warning() {
    let logs = capture_logs();
    let layer = empty_layer().await;
    let mut request = connection_request("assets", "http://127.0.0.1:1", SecretBundle::default());
    request.config.remove("__test_endpoint");
    request.config.insert(
        "blob_endpoint".into(),
        ConfigValue::String("http://169.254.169.254".into()),
    );
    let connection = add(&layer, request).await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    let warnings = logs
        .lines_at_least(tracing::Level::WARN)
        .into_iter()
        .filter(|line| line.contains("instance-metadata"))
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(
        warnings[0].contains("169.254.169.254"),
        "the warning names the host: {}",
        warnings[0]
    );
}
