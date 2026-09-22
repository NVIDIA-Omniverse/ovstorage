// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-lifecycle coverage for the ABI-v2 `GcsLayer` (RFC-0066):
//! the `ConnectionSet<GcsDriver>` integration — add/probe/remove, the lenient
//! verify (401 parks, 403 passes; token-endpoint 400/401 park, 429/5xx pass),
//! the frozen-credentials update rejection, routing, and the `Layer::list`
//! fold contract — all against local mock storage + token endpoints (the
//! service-account JSON's `token_uri` points at a mock IdP, so only synthetic
//! tokens ever travel; no real network).

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::Duration;

use ovstorage_plugin::fallback::{SCHEME_FALLBACK_METADATA_KEY, is_scheme_fallback_root};
use ovstorage_plugin::{
    AddressVisibility, AuthenticateRequest, BackendFactory, Body, ConfigValue, ConnectionAuthState,
    ConnectionKey, ConnectionRequest, ErrorCode, InteractiveAuthCapability, LayerConfig,
    LayerConnectionRequest, LayerHandle, ListOptions, ListRequest, ObjectInfo, ObjectKind,
    RangeReadStrategy, ReadOptions, ReadRequest, ReadResult, Request, RootInfo, SecretBundle,
    SecretBytes, SecretValue, StatOptions, StatRequest, UpdateConnectionCredentialsRequest,
    WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_gcs::GcsLayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

const SYNTHETIC_PEM: &str = include_str!("synthetic_rsa_pkcs8.pem");

// === Scripted mock servers ===

/// One canned (status, JSON body) response for every request; counts hits and
/// records raw requests (shared ovstorage_plugin_test::ScriptedHttpServer).
fn spawn_scripted_server(status_line: &str, body: &str) -> ScriptedHttpServer {
    ScriptedHttpServer::spawn(CannedHttpResponse::json(status_line, body))
}

const TOKEN_OK_BODY: &str = "{\"access_token\": \"synthetic-token\", \"expires_in\": 3600}";
const EMPTY_LIST_BODY: &str = "{\"items\": []}";
const ERROR_BODY: &str = "{\"error\": {\"message\": \"scripted\"}}";

/// Mock IdP answering the JWT-bearer token exchange with one canned response.
fn spawn_token_endpoint(status_line: &str, body: &str) -> ScriptedHttpServer {
    spawn_scripted_server(status_line, body)
}

// === Helpers ===

fn service_account_bundle(token_uri: &str) -> SecretBundle {
    let json = serde_json::json!({
        "type": "service_account",
        "client_email": "tester@example.iam.gserviceaccount.com",
        "private_key": SYNTHETIC_PEM,
        "token_uri": format!("{token_uri}/token"),
        "private_key_id": "kid-1",
    })
    .to_string();
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "service_account_key".into(),
        SecretValue::Bytes(SecretBytes(json.into_bytes())),
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
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn empty_layer() -> LayerHandle {
    GcsLayerFactory::default()
        .create_backend("gcs", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "gcs".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

// === add_connection verify verdicts ===

/// A 200 verify authenticates the connection: the token exchange hits the
/// mock IdP, and the storage RPC is a bearer-authorized `objects.list` with
/// `maxResults=1`.
#[tokio::test]
async fn add_connection_authenticates_on_verify_pass() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(idp.hits(), 1, "one token exchange");
    assert_eq!(storage.hits(), 1, "exactly one verify RPC");
    let raw = storage.requests()[0].clone();
    assert!(raw.contains("maxResults=1"), "verify is bounded: {raw}");
    assert!(
        raw.to_lowercase()
            .contains("authorization: bearer synthetic-token"),
        "verify is bearer-authorized: {raw}"
    );
}

/// Anonymous connections skip verify entirely (zero RPCs).
#[tokio::test]
async fn add_connection_anonymous_skips_verify() {
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", storage.endpoint(), SecretBundle::default()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert_eq!(storage.hits(), 0, "anonymous never verifies");
}

/// Lenient verify: a storage-side 403 means the caller authenticated but IAM
/// scopes it — the connection must still authenticate.
#[tokio::test]
async fn add_connection_authenticates_through_iam_denial() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("403 Forbidden", ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
}

/// A storage-side 401 is a credential rejection: the connection parks, stays
/// listed, and keeps its config-derived root routable.
#[tokio::test]
async fn add_connection_parks_on_storage_401() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("401 Unauthorized", ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
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
            &address::parse("gs://bkt/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "gs://bkt/");
}

/// A parked connection is what `authenticate_connection` is called on, and
/// GCS has no interactive flow to run: credentials arrive with the
/// connection. The call is refused with `Unsupported`, and the connection is
/// left exactly as parked as it was, still registered.
///
/// The load-bearing line is the `Unsupported` error in
/// `GcsDriver::interactive`. Restoring the
/// `AuthEvent::Succeeded { credentials: None }` it used to emit makes this
/// test hand back a stream instead; draining that stream runs the promoting
/// adapter, and the parked-state check then reads `Authenticated` — a
/// connection promoted on no grant and no probe, which is the defect this pins.
#[tokio::test]
async fn authenticate_connection_leaves_a_parked_connection_parked() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("401 Unauthorized", ERROR_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
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
        target: "gcs".into(),
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

/// A DEFINITIVE token-endpoint refusal (400 invalid_grant/invalid_client)
/// parks — the credential itself was refused by the IdP.
#[tokio::test]
async fn add_connection_parks_on_token_endpoint_400() {
    let idp = spawn_token_endpoint("400 Bad Request", ERROR_BODY);
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::AwaitingAuth { .. }
    ));
    assert!(idp.hits() >= 1, "the grant was tried");
    assert_eq!(
        storage.hits(),
        0,
        "no storage RPC after a definitive grant refusal"
    );
}

/// A TRANSIENT token-endpoint failure (503 outage / throttling) must NOT
/// park — with `refresh` unsupported, parking would strand a valid credential
/// until manual remove/re-add. The lenient verify passes and the data path
/// self-heals when the IdP recovers. The azure driver holds the same contract,
/// but pins it only at the predicate level
/// (`entra_rejection_is_limited_to_definitive_statuses`, an in-`src` unit
/// test); this end-to-end form, driving a real 503 token endpoint through
/// `add_connection`, exists only here.
#[tokio::test]
async fn add_connection_passes_through_token_endpoint_outage() {
    let idp = spawn_token_endpoint("503 Service Unavailable", ERROR_BODY);
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a transient IdP outage must not park a valid credential, got {:?}",
        connection.auth_state
    );
    assert_eq!(
        storage.hits(),
        0,
        "verify never reached storage (token grant failed transiently)"
    );
}

// === probe ===

/// Probe validates without registering.
#[tokio::test]
async fn probe_reports_verdict_without_registering() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "gcs".into(),
                connection: connection_request(
                    "bkt",
                    storage.endpoint(),
                    service_account_bundle(idp.endpoint()),
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
    assert_eq!(probed.current_addresses[0].as_str(), "gs://bkt/");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot.connections.is_empty(),
        "probe must not register a connection"
    );
}

// === frozen credentials ===

/// GCS credentials are frozen at add time (immutable `Authenticator`, no live
/// cell): EVERY `update_connection_credentials` is rejected with
/// remove-and-re-add guidance because the client has no live credential cell.
/// State is untouched.
#[tokio::test]
async fn update_credentials_is_rejected_with_guidance() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage.endpoint(),
            service_account_bundle(idp.endpoint()),
        ),
    )
    .await;
    let verify_hits = storage.hits();

    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "gcs".into(),
                    id: connection.id.clone(),
                },
                credentials: service_account_bundle(idp.endpoint()),
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
    assert_eq!(storage.hits(), verify_hits, "no verify RPC on rejection");
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

// === routing + teardown ===

/// Two connections (two buckets) route by longest prefix; removal tears the
/// routes down.
#[tokio::test]
async fn routes_across_two_connections_and_removes() {
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    let alpha = add(
        &layer,
        connection_request("alpha", storage.endpoint(), SecretBundle::default()),
    )
    .await;
    add(
        &layer,
        connection_request("beta", storage.endpoint(), SecretBundle::default()),
    )
    .await;

    for bucket in ["alpha", "beta"] {
        let root = layer
            .root_info_for(
                &address::parse(&format!("gs://{bucket}/x")).unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(root.root.as_str(), format!("gs://{bucket}/"));
    }

    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "gcs".into(),
                id: alpha.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    let err = layer
        .root_info_for(
            &address::parse("gs://alpha/x").unwrap(),
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

const LIST_BODY: &str = "{\
    \"items\": [\
    {\"bucket\": \"bkt\", \"name\": \"team/\", \"size\": \"0\", \"etag\": \"m\"},\
    {\"bucket\": \"bkt\", \"name\": \"team/file.txt\", \"size\": \"5\", \"etag\": \"f\"}\
    ],\
    \"prefixes\": [\"docs/\"]}";

/// On GCS's flat namespace, `Layer::list` folds marker
/// objects fold to `DirectoryMarker`, prefixes surface as
/// `DirectoryInferred`, and pagination is the shared numeric-offset
/// convention over the folded set.
#[tokio::test]
async fn list_folds_markers_and_paginates() {
    let storage = spawn_scripted_server("200 OK", LIST_BODY);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request("bkt", storage.endpoint(), SecretBundle::default()),
    )
    .await;

    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("gs://bkt/").unwrap(),
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
    assert_eq!(page.items[0].address.as_str(), "gs://bkt/team/");
    assert_eq!(page.items[0].kind, ObjectKind::DirectoryMarker);
    assert_eq!(page.items[1].address.as_str(), "gs://bkt/team/file.txt");
    assert_eq!(page.items[1].kind, ObjectKind::File);
    let token = page.next_page_token.expect("second page");

    let page2 = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("gs://bkt/").unwrap(),
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
    assert_eq!(page2.items[0].address.as_str(), "gs://bkt/docs/");
    assert_eq!(page2.items[0].kind, ObjectKind::DirectoryInferred);
    assert!(page2.next_page_token.is_none());
}

// === parked connections that are, in fact, working ===
//
// `GcsDriver::verify` proves a credential with one bucket-scope
// `objects.list maxResults=1`; the data path is a different call on a
// different scope, and no object operation consults `auth_state`. Unlike s3
// there is no live credential cell to gate the data path — the backend's
// `Authenticator` is built from the request's bundle at add time, independent
// of verify — so a connection parked by a refused probe is fully armed, and
// every later request goes out bearer-signed and is served.

const OBJECT_BODY: &str =
    "{\"bucket\": \"bkt\", \"name\": \"obj.txt\", \"size\": \"5\", \"etag\": \"f\"}";

/// A storage endpoint that decides per request on the PATH, so nothing is
/// scripted by ordinal and a test cannot pass by accident of request count:
///
/// - the driver's verify probe is answered `401`, which is what parks the
///   connection. It is recognised by [`PROBE_MARKER`] — a bucket-wide
///   `objects.list` with no `prefix=`, which is what `GcsDriver::verify` sends.
///   The `prefix=` clause matters: `list`, `has_descendants` and
///   `directory_has_descendants` also send `maxResults`, and matching on that
///   alone would answer them `401` too and mislead the next test written here;
/// - a path containing [`REFUSED_PATH_MARKER`] is answered `401`;
/// - a path containing [`GATED_PATH_MARKER`] is held until
///   [`PathAwareServer::release_gate`], then answered `200`;
/// - anything else is answered `200` with an object resource.
///
/// That split is the whole deployment shape this suite exists for: a
/// bucket-scope listing refused while object-scope calls are served.
struct PathAwareServer {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    gated_arrivals: Arc<AtomicUsize>,
    /// When set, the data path answers `302` to this location instead of
    /// serving the object.
    redirect_to: Arc<Mutex<Option<String>>>,
}

/// Substring of a request path the endpoint answers `401`.
const REFUSED_PATH_MARKER: &str = "refused";
/// Substring of a request path the endpoint holds open.
const GATED_PATH_MARKER: &str = "held";
/// Query parameter of `GcsDriver::verify`'s `objects.list maxResults=1`. Only
/// identifies the probe together with the absence of `prefix=` — see
/// [`PathAwareServer`].
const PROBE_MARKER: &str = "maxresults=";
/// Query parameter every bucket-scope listing EXCEPT the verify probe carries.
const PREFIXED_LISTING_MARKER: &str = "prefix=";
/// Substring of a request path a redirecting endpoint answers `302` to. Scoped
/// to one path so the same connection can also drive an unredirected request.
const BOUNCED_PATH_MARKER: &str = "bounce";

impl PathAwareServer {
    /// A variant whose responses carry no Google origin header.
    fn spawn_without_origin_header() -> Self {
        Self::spawn_inner(false)
    }

    fn spawn() -> Self {
        Self::spawn_inner(true)
    }

    fn spawn_inner(origin_stamped: bool) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gated_arrivals = Arc::new(AtomicUsize::new(0));
        let redirect_to: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let (h, r, g, a, redir) = (
            hits.clone(),
            requests.clone(),
            gate.clone(),
            gated_arrivals.clone(),
            redirect_to.clone(),
        );
        let refused = render_with_origin("401 Unauthorized", ERROR_BODY, origin_stamped);
        let served = render_with_origin("200 OK", OBJECT_BODY, origin_stamped);
        let endpoint_for_session = endpoint.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (h, r, g, a, redir) =
                    (h.clone(), r.clone(), g.clone(), a.clone(), redir.clone());
                let (refused, served) = (refused.clone(), served.clone());
                let endpoint_for_session = endpoint_for_session.clone();
                // One thread per connection: a held request must not stop the
                // endpoint answering the concurrent one it is raced against.
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let Some(raw) = read_http_request(&mut stream) else {
                        return;
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    let line = raw.lines().next().unwrap_or_default().to_lowercase();
                    r.lock().expect("poisoned").push(raw);
                    if line.contains(GATED_PATH_MARKER) {
                        a.fetch_add(1, Ordering::SeqCst);
                        let (lock, cvar) = &*g;
                        let mut open = lock.lock().expect("poisoned");
                        while !*open {
                            open = cvar.wait(open).expect("poisoned");
                        }
                    }
                    let is_probe =
                        line.contains(PROBE_MARKER) && !line.contains(PREFIXED_LISTING_MARKER);
                    let redirect = redir.lock().expect("poisoned").clone();
                    let rendered;
                    // A resumable initiate is answered with the session URL, as
                    // the service answers it; without one the batch cannot be
                    // minted and the slot's promotion could not be exercised.
                    let resumable_initiate = line.contains("uploadtype=resumable");
                    let session;
                    let response = if line.contains(REFUSED_PATH_MARKER) || is_probe {
                        &refused
                    } else if resumable_initiate {
                        session = format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-guploader-uploadid: scripted-upload-1\r\n\
                             Location: {endpoint_for_session}/upload/session-1\r\n\
                             Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
                        );
                        &session
                    } else if let Some(target) =
                        redirect.filter(|_| line.contains(BOUNCED_PATH_MARKER))
                    {
                        rendered = format!(
                            "HTTP/1.1 302 Found\r\nConnection: close\r\n\
                             Location: {target}/redirected\r\nContent-Length: 0\r\n\r\n"
                        );
                        &rendered
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
            gate,
            gated_arrivals,
            redirect_to,
        }
    }

    /// Point an existing server's redirect at `target`, for the same-origin
    /// case where the target must be the server's own endpoint.
    fn redirect_to(&self, target: &str) {
        *self.redirect_to.lock().expect("poisoned") = Some(target.to_string());
    }

    /// A variant that answers `302` to `target` for requests naming
    /// [`BOUNCED_PATH_MARKER`], leaving every other path served normally — so one
    /// connection can drive a redirected and an unredirected request.
    fn spawn_redirecting_to(target: &str) -> Self {
        let server = Self::spawn();
        server.redirect_to(target);
        server
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
/// `x-guploader-uploadid` is stamped because the promotion rule counts a
/// response as proof of the credential only if it carries a Google origin
/// marker, so an endpoint that omits one models a proxy answering for the
/// service rather than the service itself.
/// `origin_stamped: false` models a front door composing its own answer — the
/// shape the promotion rule must not count as proof of the credential.
fn render_with_origin(status_line: &str, body: &str, origin_stamped: bool) -> String {
    let origin = if origin_stamped {
        "x-guploader-uploadid: scripted-upload-1\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status_line}\r\nConnection: close\r\n{origin}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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

/// Add a connection whose verify probe the endpoint refuses. The connection
/// parks, and — GCS having no live credential cell — stays fully armed.
async fn parked_by_a_refused_probe(
    idp: &ScriptedHttpServer,
    storage_endpoint: &str,
) -> LayerHandle {
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "bkt",
            storage_endpoint,
            service_account_bundle(idp.endpoint()),
        ),
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
    layer
}

/// The reported auth state must follow the data path, not the last probe.
///
/// The probe (`objects.list`) is refused and parks the connection; the data
/// path is a different call the same deployment serves. The request goes out
/// bearer-signed and succeeds, so the connection must stop reporting that it
/// needs authentication.
#[tokio::test]
async fn a_served_data_path_promotes_a_parked_connection() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let result = stat_at(&layer, "gs://bkt/obj.txt").await;

    // Control — the data path actually reached the wire.
    assert_eq!(
        storage.hits(),
        hits_before + 1,
        "control: the data path must have been sent, saw {:?}",
        storage.requests()
    );
    // Control — the request really was signed from the frozen credentials. An
    // unsigned request would prove nothing about the credential.
    let raw = storage.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("authorization: bearer synthetic-token"),
        "control: the data path must be bearer-signed: {raw}"
    );
    let info = result.expect("a parked connection still serves signed requests");
    assert_eq!(info.size, Some(5));

    // The fix: the reported state follows that evidence.
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a connection doing successful signed work must not report AwaitingAuth, got {state:?}"
    );
}

/// Negative control for the promotion above: the same harness with the data
/// path ALSO refused. The request reaches the wire and is rejected, so there
/// is no acceptance to promote on and the connection stays parked.
#[tokio::test]
async fn a_refused_data_path_withholds_promotion() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let result = stat_at(&layer, "gs://bkt/refused.txt").await;
    assert_eq!(
        storage.hits(),
        hits_before + 1,
        "control: the request still reached the wire"
    );
    assert!(
        result.is_err(),
        "control: a refused data path must fail; the harness is not faking success"
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
/// are unrelated remote clients.
///
/// It does not, on its own, pin acceptance being per-operation — an accepted
/// neighbour promotes the connection itself, so no assertion on `auth_state`
/// can separate the two scopings. The redirect test below is what covers that
/// side: an operation that sends nothing must not promote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_refusal_withholds_a_promotion() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = Arc::new(parked_by_a_refused_probe(&idp, storage.endpoint()).await);

    let held = tokio::spawn({
        let layer = layer.clone();
        async move { stat_at(&layer, "gs://bkt/held.txt").await }
    });
    // Wait for the held request to have actually reached the endpoint. Without
    // this the "concurrent" refusal could land before it was even signed,
    // which is a different and weaker test.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while storage.gated_arrivals() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "control: the held request never reached the endpoint"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let refused = stat_at(&layer, "gs://bkt/refused.txt").await;
    assert!(
        refused.is_err(),
        "control: the neighbour must be refused, got {refused:?}"
    );

    storage.release_gate();
    let accepted = held.await.expect("the held caller joins");
    assert!(
        accepted.is_ok(),
        "control: the held caller's own request must be accepted, got {accepted:?}"
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
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let result = layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("gs://bkt/obj.txt").unwrap(),
                body: Body::Bytes(b"payload".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await;
    assert!(
        storage.hits() > hits_before,
        "control: the write must have been sent, saw {:?}",
        storage.requests()
    );
    let raw = storage.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("authorization: bearer synthetic-token"),
        "control: the write is bearer-signed: {raw}"
    );
    assert!(result.is_ok(), "the write must be served: {result:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a connection whose write the service answered must not report \
         AwaitingAuth, got {state:?}"
    );
}

/// A redirected response is not evidence, however successful.
///
/// reqwest follows redirects and strips the `Authorization` header on a
/// cross-host hop without re-adding it, so a response fetched after one was not
/// signed by this connection at all — even when the chain lands back on the
/// configured endpoint. The endpoint here answers the data path with a 302 to a
/// second server that serves the object unsigned; the connection must stay
/// parked.
#[tokio::test]
async fn a_redirected_response_does_not_promote_a_parked_connection() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let unsigned = PathAwareServer::spawn();
    let storage = PathAwareServer::spawn_redirecting_to(unsigned.endpoint());
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = unsigned.hits();
    let result = stat_at(&layer, "gs://bkt/bounce.txt").await;

    // Control — the redirect really was followed and really was served, so the
    // non-promotion is a property of the redirect and not of a failed request.
    assert!(
        unsigned.hits() > hits_before,
        "control: the redirect must have been followed, saw {:?}",
        unsigned.requests()
    );
    let raw = unsigned.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        !raw.contains("authorization:"),
        "control: reqwest strips the bearer across hosts, so the second leg is \
         unsigned: {raw}"
    );
    assert!(result.is_ok(), "the redirected read is served: {result:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a response fetched without this connection's bearer is no proof of it, \
         got {state:?}"
    );
}

/// A SAME-ORIGIN redirect keeps the bearer, so its answer is evidence.
///
/// This is the case a URL comparison gets wrong: a path-rewriting proxy in
/// front of the endpoint issues a `302` to another path on the same host,
/// reqwest re-sends the `Authorization` header because the origin did not
/// change, and the answer is therefore genuinely this connection's. Discarding
/// it would drop real verdicts — including the `401` a dying credential
/// produces, which is the direction that cannot be undone.
#[tokio::test]
async fn a_same_origin_redirect_still_counts_as_evidence() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    // Bounce to another path on the SAME server.
    let same_origin = storage.endpoint().to_string();
    storage.redirect_to(&same_origin);
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let result = stat_at(&layer, "gs://bkt/bounce.txt").await;
    assert!(
        result.is_ok(),
        "the redirected data path is served: {result:?}"
    );
    // Control — the SECOND leg specifically. Counting signed requests across
    // the server would be satisfied by the verify probe alone, which is already
    // bearer-signed, and would hold whether or not the redirect kept it.
    let second_leg = storage
        .requests()
        .into_iter()
        .find(|raw| {
            raw.lines()
                .next()
                .is_some_and(|line| line.contains("/redirected"))
        })
        .expect("control: the redirect must have been followed");
    assert!(
        second_leg.to_lowercase().contains("authorization: bearer"),
        "control: a same-origin hop must KEEP the bearer, which is the whole \
         reason its answer counts: {second_leg}"
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a same-origin redirect keeps the credential, so its answer is proof; \
         got {state:?}"
    );
}

/// `write_redirect` promotes, because on gcs it reaches the service.
///
/// The slot's own comment asserts that every batch routes through
/// `initiate_resumable_redirect`, which opens the session with a signed request
/// of our own. Nothing checked that, and if it stopped being true — or a
/// refactor moved the initiate off the witnessed transport — promotion would
/// quietly stop with every test still green.
#[tokio::test]
async fn a_served_write_redirect_promotes_a_parked_connection() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address::parse("gs://bkt/obj.txt").unwrap(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(11),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await;
    // Control — the initiate really was sent, and signed. Without it the
    // promotion below would be evidence of nothing.
    assert!(
        storage.hits() > hits_before,
        "control: the resumable initiate must reach the service, saw {:?}",
        storage.requests()
    );
    let raw = storage.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("authorization: bearer synthetic-token"),
        "control: the initiate is bearer-signed: {raw}"
    );
    assert!(batch.is_ok(), "the batch is minted: {batch:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a connection whose initiate the service answered must not report \
         AwaitingAuth, got {state:?}"
    );
}

/// A redirect records evidence in NEITHER direction.
///
/// The mirror of the test above, and the one that matters more. The redirect
/// target answers `401`, which is what any host wanting its own auth answers a
/// request reqwest stripped the bearer from — so counting it as a refusal would
/// condemn the credential on the strength of a request that never carried it.
///
/// It has to be driven CONCURRENTLY to mean anything: the refusal epoch answers
/// "did a refusal land while I ran?", so a redirected 401 that lands before an
/// operation starts is invisible to it either way. Here the accepted operation
/// is held open across the redirected one, which is exactly the interleaving a
/// broker produces and the only one that can tell the two orderings apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_redirected_refusal_does_not_condemn_the_connection() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let refuser = PathAwareServer::spawn();
    let storage = PathAwareServer::spawn_redirecting_to(&format!("{}/refused", refuser.endpoint()));
    let layer = Arc::new(parked_by_a_refused_probe(&idp, storage.endpoint()).await);

    // Caller A: an ordinary request the endpoint serves, held open.
    let held = tokio::spawn({
        let layer = layer.clone();
        async move { stat_at(&layer, "gs://bkt/held.txt").await }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while storage.gated_arrivals() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "control: caller A's request never reached the endpoint"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Caller B, while A is in flight: redirected to a host that refuses the
    // now-unsigned request.
    let refused = stat_at(&layer, "gs://bkt/bounce.txt").await;
    assert!(
        refused.is_err(),
        "control: the redirect target refuses, so B fails: {refused:?}"
    );
    assert!(
        refuser.hits() > 0,
        "control: the redirect must have been followed"
    );
    let raw = refuser.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        !raw.contains("authorization:"),
        "control: reqwest strips the bearer across hosts, so B's second leg is \
         unsigned: {raw}"
    );

    storage.release_gate();
    let accepted = held.await.expect("caller A joins");
    assert!(accepted.is_ok(), "caller A is served: {accepted:?}");

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::Authenticated { .. }),
        "a refusal answered to a request that carried no bearer must not \
         withhold a concurrent operation's promotion, got {state:?}"
    );
}

/// A response carrying no Google origin header is not proof of the credential.
///
/// The gcs half of the negative control. The scan itself lives inside
/// `proves_credentials` and is unit-tested with real `HeaderMap`s, so what this
/// closes is the wiring: that `note_promotion_evidence` passes
/// `response.headers()` through at all, and that a connection behind a
/// header-stripping front door stays parked rather than promoting.
#[tokio::test]
async fn a_response_without_a_google_origin_header_does_not_promote() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn_without_origin_header();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let result = stat_at(&layer, "gs://bkt/obj.txt").await;

    // Controls — the request reached the wire and was bearer-signed, and the
    // response was a served 200. Only the origin header is missing.
    assert_eq!(
        storage.hits(),
        hits_before + 1,
        "control: the data path must have been sent, saw {:?}",
        storage.requests()
    );
    let raw = storage.requests().last().cloned().unwrap().to_lowercase();
    assert!(
        raw.contains("authorization: bearer synthetic-token"),
        "control: the request really was signed: {raw}"
    );
    assert!(
        result.is_ok(),
        "control: the response is a served 200: {result:?}"
    );

    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "an answer composed by something that is not Google proves nothing, \
         got {state:?}"
    );
}

/// `read` mints a signed URL and sends nothing, so an `Ok` from it is no
/// evidence about the credential. Measured, not assumed: the storage
/// endpoint's hit count does not move.
#[tokio::test]
async fn minting_a_read_redirect_does_not_promote_a_parked_connection() {
    let idp = spawn_token_endpoint("200 OK", TOKEN_OK_BODY);
    let storage = PathAwareServer::spawn();
    let layer = parked_by_a_refused_probe(&idp, storage.endpoint()).await;

    let hits_before = storage.hits();
    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("gs://bkt/obj.txt").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await;
    // Assert on the artifact that crosses the boundary, not on `is_ok`: the
    // redirect really is a URL signed from the frozen credentials, so the caller
    // gets a working download — and yet nothing was proved, because no request
    // left the process.
    match result.expect("a parked connection still mints redirects") {
        ReadResult::Redirect(redirect) => {
            let url = redirect.request.url.to_lowercase();
            assert!(
                url.contains("x-goog-credential=") && url.contains("x-goog-signature="),
                "the redirect is a V4-signed URL: {url}"
            );
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
    assert_eq!(
        storage.hits(),
        hits_before,
        "control: the redirect mint reaches no service"
    );
    let state = auth_state_of(&layer).await;
    assert!(
        matches!(state, ConnectionAuthState::AwaitingAuth { .. }),
        "a locally-minted redirect is not proof of a working credential, got {state:?}"
    );
}

// === anonymous gs:// scheme fallback ===
//
// A layer granted `anonymous_fallback = ["gs"]` publishes one hidden, marked
// `gs:///` root and serves any `gs://bucket/...` address no connection routes
// through an anonymous per-bucket backend. Everything below drives the layer
// the way a host does; the fixture endpoint is the shared scripted server,
// reached through the `anonymous_fallback_endpoint` layer key.

const FALLBACK_KEY: &str = "anonymous_fallback";
const FALLBACK_ENDPOINT_KEY: &str = "anonymous_fallback_endpoint";

/// The host's wrapper shape for an array-valued layer key: the array
/// reserialized under its own key.
fn fallback_grant(schemes: &[&str]) -> ConfigValue {
    let list = schemes
        .iter()
        .map(|scheme| format!("\"{scheme}\""))
        .collect::<Vec<_>>()
        .join(", ");
    ConfigValue::Toml(format!("{FALLBACK_KEY} = [{list}]\n"))
}

async fn create_layer(config: LayerConfig) -> ovstorage_plugin::Result<LayerHandle> {
    GcsLayerFactory::default()
        .create_backend("gcs", &config, None)
        .await
}

/// The refusal `create_backend` answers for `config`; panics if it builds.
async fn create_layer_error(config: LayerConfig) -> ovstorage_plugin::Error {
    match create_layer(config).await {
        Err(error) => error,
        Ok(_) => panic!("create_backend must refuse this layer config"),
    }
}

/// A layer whose only configuration is the `gs` grant pointed at `endpoint`.
fn fallback_config(endpoint: &str) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert(FALLBACK_KEY.into(), fallback_grant(&["gs"]));
    config.insert(
        FALLBACK_ENDPOINT_KEY.into(),
        ConfigValue::String(endpoint.into()),
    );
    config
}

async fn fallback_layer(endpoint: &str) -> LayerHandle {
    create_layer(fallback_config(endpoint))
        .await
        .expect("a granted layer builds")
}

async fn roots_of(layer: &LayerHandle) -> Vec<RootInfo> {
    let (snapshot, _) = layer
        .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    snapshot.roots
}

async fn connection_count(layer: &LayerHandle) -> usize {
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    snapshot.connections.len()
}

async fn root_for(layer: &LayerHandle, address: &str) -> ovstorage_plugin::Result<RootInfo> {
    layer
        .root_info_for(
            &address::parse(address).unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
}

/// Rendered `tracing` events captured for the duration of one test. Hand-rolled
/// on `tracing` alone: this crate carries no subscriber crate, and the two
/// facts these tests need — how many backends were minted, and what the
/// first-touch line names — are legible from the rendered fields.
///
/// The subscriber is installed ONCE as the process-global default and fans
/// events out to a thread-local sink, rather than being set per test as a
/// scoped default. A scoped default is not enough here: `tracing` registers a
/// callsite lazily, the first time it fires anywhere in the process, and
/// computes its interest from the registering thread's dispatcher when only
/// one scoped dispatcher is alive. Tests run in parallel, so the mint line's
/// callsite can first fire on a thread with no subscriber, be cached as
/// "never", and stay silent for the test that installed a capture — measured,
/// roughly one run in ten. A global dispatcher is always the one consulted, so
/// the interest is always "sometimes" and every thread's events reach it; the
/// thread-local sink keeps each test's lines its own, because a
/// `#[tokio::test]` runs its whole future on the test's thread.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<String>>>);

/// The message the fallback logs once per minted backend.
const BUILT_MESSAGE: &str = "anonymous fallback backend built";

thread_local! {
    static SINK: RefCell<Option<CapturedLogs>> = const { RefCell::new(None) };
}

static INSTALL_CAPTURE: Once = Once::new();

impl CapturedLogs {
    fn install(&self) -> CaptureGuard {
        INSTALL_CAPTURE.call_once(|| {
            // Nothing else in this binary sets a global subscriber; if that
            // changes, the capture sees nothing and the assertions on it say so.
            let _ = tracing::subscriber::set_global_default(CaptureSubscriber);
        });
        SINK.with(|sink| *sink.borrow_mut() = Some(self.clone()));
        CaptureGuard
    }

    fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("the capture lock is not poisoned")
            .clone()
    }

    fn built_lines(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| line.contains(BUILT_MESSAGE))
            .collect()
    }
}

/// Detaches this thread's sink when the test ends.
struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        SINK.with(|sink| sink.borrow_mut().take());
    }
}

struct CaptureSubscriber;

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        SINK.with(|sink| {
            let Some(logs) = sink.borrow().clone() else {
                return;
            };
            let mut rendered = format!("{} ", event.metadata().target());
            event.record(&mut RenderVisitor(&mut rendered));
            logs.0
                .lock()
                .expect("the capture lock is not poisoned")
                .push(rendered);
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct RenderVisitor<'a>(&'a mut String);

impl tracing::field::Visit for RenderVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

/// Without a grant nothing changes: an unconfigured bucket is `NoRoute`, and
/// the message is the one every host already matches on.
#[tokio::test]
async fn fallback_is_off_by_default() {
    let layer = empty_layer().await;
    let err = stat_at(&layer, "gs://x/y").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert_eq!(err.message(), "no route matches address");
    assert!(roots_of(&layer).await.is_empty());

    // An explicit empty grant is off too, and publishes no root.
    let mut config = LayerConfig::new();
    config.insert(FALLBACK_KEY.into(), fallback_grant(&[]));
    let layer = create_layer(config).await.unwrap();
    let err = stat_at(&layer, "gs://x/y").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert!(roots_of(&layer).await.is_empty());
    assert_eq!(connection_count(&layer).await, 0);
}

/// The grant is layer policy, not a connection: a table holding only the
/// fallback keys seeds nothing, and the one root it publishes is the hidden,
/// marked scheme root with no connection behind it.
#[tokio::test]
async fn a_layer_holding_only_the_fallback_key_seeds_no_static_connection() {
    let mut config = LayerConfig::new();
    config.insert(FALLBACK_KEY.into(), fallback_grant(&["gs"]));
    let layer = create_layer(config).await.unwrap();

    assert_eq!(connection_count(&layer).await, 0, "no static connection");
    let roots = roots_of(&layer).await;
    let [root] = roots.as_slice() else {
        panic!("exactly the scheme root is published, got {roots:?}");
    };
    assert_eq!(root.root.as_str(), "gs:///");
    assert!(is_scheme_fallback_root(root));
    assert_eq!(root.layer_kind, "gcs");
    assert_eq!(root.visibility, AddressVisibility::Hidden);
    assert!(!root.visible);
    assert!(root.connection_id.is_none());
    assert!(root.owning_target.is_none());
    assert_eq!(
        root.user_metadata
            .get(SCHEME_FALLBACK_METADATA_KEY)
            .map(String::as_str),
        Some("anonymous")
    );
    // `root_info_for` on an unconfigured address answers that same root
    // verbatim — never a synthesized per-bucket root.
    let via_address = root_for(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(&via_address, root);
    // The fallback runs the same client a connection does, so the strategy a
    // consumer reads off a fallback-served address is the one a connection
    // root advertises for the same store.
    assert_eq!(via_address.range_read_strategy, RangeReadStrategy::Native);
}

/// The fallback root clamps the plugin's auth-agnostic capability set to its
/// read side: every mutation and watch bit is off, every read bit is on.
#[tokio::test]
async fn the_fallback_root_advertises_no_write_bits() {
    let mut config = LayerConfig::new();
    config.insert(FALLBACK_KEY.into(), fallback_grant(&["gs"]));
    let layer = create_layer(config).await.unwrap();
    let roots = roots_of(&layer).await;
    let caps = &roots[0].capabilities;

    assert!(!caps.supports_write);
    assert!(!caps.supports_write_stream);
    assert!(!caps.supports_write_redirect);
    assert!(!caps.supports_delete);
    assert!(!caps.supports_copy);
    assert!(!caps.supports_server_side_copy);
    assert!(!caps.supports_rename);
    assert!(!caps.supports_create_directory);
    assert!(!caps.supports_delete_directory);
    assert!(!caps.supports_native_metadata_patch);
    assert!(!caps.supports_if_match_write);
    assert!(!caps.supports_no_overwrite_write);
    assert!(!caps.supports_watch_directory);
    assert!(caps.watch_directory_max_lag.is_none());

    assert!(caps.supports_list);
    assert!(caps.supports_list_stream);
    assert!(caps.supports_recursive_list);
    assert!(caps.wants_list_backed_stat);
    assert!(caps.supports_version_listing);
    assert!(caps.supports_access_check);
    assert!(
        !caps.has_real_directories,
        "GCS is flat under the fallback too"
    );
}

/// The GCS kind serves `gs` and nothing else; a grant naming another scheme
/// is a configuration error, not a silent no-op.
#[tokio::test]
async fn a_fallback_key_naming_a_scheme_this_layer_does_not_serve_is_refused() {
    for schemes in [&["s3"][..], &["gs", "azure"][..], &["https"][..]] {
        let mut config = LayerConfig::new();
        config.insert(FALLBACK_KEY.into(), fallback_grant(schemes));
        let err = create_layer_error(config).await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{schemes:?}");
        let foreign = schemes.iter().find(|scheme| **scheme != "gs").unwrap();
        assert!(
            err.message().contains(&format!(
                "names scheme `{foreign}`, which this kind does not serve"
            )),
            "{}",
            err.message()
        );
        assert!(
            err.message().contains("it serves gs"),
            "the refusal names what the kind does serve: {}",
            err.message()
        );
    }
}

/// A grant is a security decision, so its shape is strict: a bare string is
/// not read as a one-element array.
#[tokio::test]
async fn a_non_array_fallback_key_is_refused_at_create_backend() {
    for value in [
        ConfigValue::String("gs".into()),
        ConfigValue::Bool(true),
        ConfigValue::Int(1),
        ConfigValue::Toml("anonymous_fallback = \"gs\"\n".into()),
    ] {
        let mut config = LayerConfig::new();
        config.insert(FALLBACK_KEY.into(), value.clone());
        let err = create_layer_error(config).await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{value:?}");
        assert_eq!(
            err.message(),
            "`anonymous_fallback` must be a TOML array of scheme strings"
        );
    }
}

/// A misspelled tunable is refused by name rather than parsed as nothing.
#[tokio::test]
async fn an_unknown_fallback_tunable_is_refused_at_create_backend() {
    let mut config = LayerConfig::new();
    config.insert(FALLBACK_KEY.into(), fallback_grant(&["gs"]));
    config.insert("anonymous_fallback_max_backend".into(), ConfigValue::Int(3));
    let err = create_layer_error(config).await;
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message()
            .contains("`anonymous_fallback_max_backend` on layer `gcs`"),
        "{}",
        err.message()
    );
}

/// A fallback endpoint on a cloud instance-metadata host is refused when the
/// layer is built, before any backend could be pointed at it.
#[tokio::test]
async fn a_link_local_fallback_endpoint_is_refused_at_create_backend() {
    for endpoint in ["http://169.254.169.254", "http://metadata.google.internal"] {
        let err = create_layer_error(fallback_config(endpoint)).await;
        assert_eq!(err.code(), ErrorCode::PermissionDenied, "{endpoint}");
        assert!(
            err.message().contains("instance-metadata"),
            "{}",
            err.message()
        );
    }
}

/// A fallback endpoint that embeds a credential, or carries a query or
/// fragment, is refused when the layer is built. The tier's promise is that no
/// credential travels; a URL-embedded one would ride every request as a Basic
/// `Authorization` header and come back to the caller in the `read` redirect.
/// The refusal names the key and the layer and never echoes the value.
#[tokio::test]
async fn a_credential_bearing_fallback_endpoint_is_refused_at_create_backend() {
    for endpoint in [
        "http://reader:hunter2@127.0.0.1:1",
        "http://@127.0.0.1:1",
        "http://127.0.0.1:1/?alt=media",
        "http://127.0.0.1:1/#anchor",
    ] {
        let err = create_layer_error(fallback_config(endpoint)).await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{endpoint}");
        assert!(
            err.message()
                .contains("`anonymous_fallback_endpoint` on layer `gcs`"),
            "{}",
            err.message()
        );
        assert!(
            !err.message().contains("hunter2"),
            "the refusal never echoes the credential: {}",
            err.message()
        );
    }
}

/// Fallback keys belong to the layer table. On a connection request — probe or
/// add — they are refused with guidance, and nothing is registered.
#[tokio::test]
async fn a_connection_request_carrying_a_fallback_key_is_refused() {
    let storage = spawn_scripted_server("200 OK", EMPTY_LIST_BODY);
    let layer = empty_layer().await;
    for (key, value) in [
        (FALLBACK_KEY, fallback_grant(&["gs"])),
        (
            FALLBACK_ENDPOINT_KEY,
            ConfigValue::String(storage.endpoint().into()),
        ),
    ] {
        let mut request = connection_request("bkt", storage.endpoint(), SecretBundle::default());
        request.config.insert(key.into(), value);
        let expected = format!(
            "`{key}` is a layer key, not connection config; set it on [ovstorage.layers.gcs]"
        );

        let probe_err = layer
            .probe(
                Request::new(LayerConnectionRequest {
                    target: "gcs".into(),
                    connection: request.clone(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(probe_err.code(), ErrorCode::InvalidArgument, "probe {key}");
        assert_eq!(probe_err.message(), expected);

        let add_err = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "gcs".into(),
                    connection: request,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(add_err.code(), ErrorCode::InvalidArgument, "add {key}");
        assert_eq!(add_err.message(), expected);
    }
    assert_eq!(connection_count(&layer).await, 0);
    assert_eq!(storage.hits(), 0, "a refused request reaches no service");
}

/// Both spellings of a hostless address — the bare scheme root and a hostless
/// path — are first-tier hits under `gs:///`; the fallback refuses them because
/// there is no bucket to mint for, and nothing reaches the wire.
#[tokio::test]
async fn the_scheme_root_itself_is_invalid_argument() {
    let storage = spawn_scripted_server("200 OK", OBJECT_BODY);
    let layer = fallback_layer(storage.endpoint()).await;
    for spelling in ["gs:///", "gs:///k", "gs:///a/b.txt"] {
        let err = stat_at(&layer, spelling).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
        assert_eq!(err.message(), "a gs:// address names no bucket");
    }
    let err = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("gs:///").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(storage.hits(), 0);
}

/// A query that carries anything but a version selector authenticates itself
/// (a signed URL's signature, say), so the second tier never answers it: the
/// caller sees the byte-identical `NoRoute`.
#[tokio::test]
async fn a_presigned_or_sas_query_falls_through_to_no_route() {
    let storage = spawn_scripted_server("200 OK", OBJECT_BODY);
    let layer = fallback_layer(storage.endpoint()).await;
    for address in [
        "gs://bkt/obj.txt?X-Goog-Signature=abc",
        "gs://bkt/obj.txt?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=x",
        "gs://bkt/obj.txt?sig=abc",
    ] {
        let err = stat_at(&layer, address).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoRoute, "{address}");
        assert_eq!(err.message(), "no route matches address");
    }
    assert_eq!(storage.hits(), 0);
    // Control: the same object without the query is served.
    stat_at(&layer, "gs://bkt/obj.txt")
        .await
        .expect("the unsigned spelling reaches the fallback");
    assert_eq!(storage.hits(), 1);
}

/// A configured connection for a bucket outranks the fallback for that bucket
/// alone, and installing it evicts the anonymous backend the fallback had
/// cached — measured by the mint log: after the connection is removed the
/// bucket is minted again rather than served from a stale resident.
#[tokio::test]
async fn a_configured_root_outranks_the_fallback_and_install_evicts_the_cached_backend() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let fallback_store = spawn_scripted_server("200 OK", OBJECT_BODY);
    let configured_store = spawn_scripted_server("200 OK", OBJECT_BODY);
    let layer = fallback_layer(fallback_store.endpoint()).await;

    stat_at(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(fallback_store.hits(), 1);
    assert_eq!(logs.built_lines().len(), 1, "first touch mints bkt");
    // A hit does not mint again.
    stat_at(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(logs.built_lines().len(), 1);

    let connection = add(
        &layer,
        connection_request("bkt", configured_store.endpoint(), SecretBundle::default()),
    )
    .await;
    let root = root_for(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(root.root.as_str(), "gs://bkt/");
    assert_eq!(root.connection_id, Some(connection.id.clone()));
    stat_at(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(
        configured_store.hits(),
        1,
        "the connection serves its bucket"
    );
    assert_eq!(
        fallback_store.hits(),
        2,
        "the fallback is not consulted for it"
    );
    // Other buckets still fall back.
    stat_at(&layer, "gs://other/obj.txt").await.unwrap();
    assert_eq!(fallback_store.hits(), 3);
    assert_eq!(logs.built_lines().len(), 2);
    let scheme_root = root_for(&layer, "gs://other/obj.txt").await.unwrap();
    assert_eq!(scheme_root.root.as_str(), "gs:///");
    // The scheme root is published beside the connection's root, ranked last.
    let roots = roots_of(&layer).await;
    assert_eq!(roots.len(), 2, "{roots:?}");
    assert!(roots.iter().any(|root| root.root.as_str() == "gs://bkt/"));
    assert!(roots.iter().any(|root| root.root.as_str() == "gs:///"));

    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "gcs".into(),
                id: connection.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    stat_at(&layer, "gs://bkt/obj.txt").await.unwrap();
    assert_eq!(fallback_store.hits(), 4, "the fallback serves bkt again");
    assert_eq!(
        logs.built_lines().len(),
        3,
        "installing the connection evicted the cached backend, so bkt is minted anew"
    );
}

/// `anonymous_fallback_max_backends` bounds the resident set: with a bound of
/// one, touching a second bucket evicts the first, which is minted again on
/// its next touch.
#[tokio::test]
async fn cached_backends_are_bounded() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let storage = spawn_scripted_server("200 OK", OBJECT_BODY);
    let mut config = fallback_config(storage.endpoint());
    config.insert(
        "anonymous_fallback_max_backends".into(),
        ConfigValue::Int(1),
    );
    let layer = create_layer(config).await.unwrap();

    stat_at(&layer, "gs://alpha/obj.txt").await.unwrap();
    stat_at(&layer, "gs://alpha/other.txt").await.unwrap();
    assert_eq!(logs.built_lines().len(), 1, "alpha is resident");
    stat_at(&layer, "gs://beta/obj.txt").await.unwrap();
    assert_eq!(logs.built_lines().len(), 2, "beta evicts alpha");
    stat_at(&layer, "gs://alpha/obj.txt").await.unwrap();
    assert_eq!(logs.built_lines().len(), 3, "alpha is minted again");
    assert_eq!(storage.hits(), 4, "every stat was served");
}

/// `anonymous_fallback_mints_per_minute` bounds how many buckets are minted
/// per sliding minute; past it a cold bucket answers a retryable
/// `ResourceExhausted` while resident buckets keep answering.
#[tokio::test]
async fn the_mint_budget_answers_resource_exhausted() {
    let storage = spawn_scripted_server("200 OK", OBJECT_BODY);
    let mut config = fallback_config(storage.endpoint());
    config.insert(
        "anonymous_fallback_mints_per_minute".into(),
        ConfigValue::Int(1),
    );
    let layer = create_layer(config).await.unwrap();

    stat_at(&layer, "gs://alpha/obj.txt").await.unwrap();
    let err = stat_at(&layer, "gs://beta/obj.txt").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    assert_eq!(
        err.message(),
        "anonymous fallback mint budget exhausted; retry later"
    );
    assert!(err.code().retryable());
    assert!(err.next_action().is_some());
    assert_eq!(storage.hits(), 1, "the refused bucket reaches no service");
    stat_at(&layer, "gs://alpha/other.txt")
        .await
        .expect("a resident bucket keeps answering");
    assert_eq!(storage.hits(), 2);
}

/// The first-touch line names the bucket origin and nothing else: no object
/// key, no query.
#[tokio::test]
async fn first_touch_logs_the_origin_and_not_the_key() {
    let logs = CapturedLogs::default();
    let _guard = logs.install();
    let storage = spawn_scripted_server("200 OK", OBJECT_BODY);
    let layer = fallback_layer(storage.endpoint()).await;

    stat_at(&layer, "gs://bucket-name/secret/path.bin")
        .await
        .unwrap();

    let built = logs.built_lines();
    assert_eq!(built.len(), 1, "one mint for the bucket: {built:?}");
    let line = &built[0];
    assert!(line.starts_with("ovstorage.fallback "), "{line}");
    assert!(line.contains("scheme=\"gs\""), "{line}");
    assert!(line.contains("gs://bucket-name"), "{line}");
    for withheld in ["secret", "path.bin"] {
        assert!(!line.contains(withheld), "`{withheld}` leaked into: {line}");
    }
    // The route table's own tier-two line is equally reticent.
    let routed: Vec<String> = logs
        .lines()
        .into_iter()
        .filter(|line| line.contains("routing by scheme fallback"))
        .collect();
    assert!(!routed.is_empty(), "the second tier logged the hit");
    for line in &routed {
        assert!(line.contains("gs://bucket-name"), "{line}");
        for withheld in ["secret", "path.bin"] {
            assert!(!line.contains(withheld), "`{withheld}` leaked into: {line}");
        }
    }
}
