// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `signed_query` credential channel, driven end to end against an origin
//! that checks the signature it receives.
//!
//! Every token here is minted with a real key and verified with a real
//! verifier, so each test states a property an origin that answered `200` to
//! anything could not:
//!
//! - a *prefix-scoped* token held on the connection authorizes reads at more
//!   than one object path, which is what makes it a shape a connection can
//!   hold;
//! - a signature with one byte flipped is refused by the origin, so the checks
//!   above are checks and not decoration;
//! - the held query arrives byte-identical — `%2F`, `%2B`, and `%3D` intact,
//!   parameters in the order supplied — because those bytes are the
//!   signature's subject;
//! - the separator is `&` when the address already carries a query and `?`
//!   when it does not;
//! - a *per-object* presign is refused at `add_connection` under either scope
//!   declaration, and the reason is demonstrated directly: the same presign
//!   verifies at the path it was minted for and at no other.
//!
//! Rotation is judged the same way. A signed query expires, so the origin here
//! serves one grant generation at a time: it rolls forward, the held token
//! stops being accepted, and only after `update_connection_credentials`
//! installs the replacement do reads resume. A rotation the resolver refuses
//! leaves the previous token serving, and a rotation cannot turn an anonymous
//! connection into a credentialed one.
//!
//! Finally, a signature is a credential and not configuration: a query on
//! `root_url` is refused at instantiate, and the refusal names the credential
//! field that carries one.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ovstorage_plugin::{
    BackendFactory, ConfigValue, Connection, ConnectionAuthState, ConnectionId, ConnectionKey,
    ConnectionRequest, ErrorCode, LayerConfig, LayerConnectionRequest, LayerHandle, ReadOptions,
    ReadRequest, ReadResult, Request, Result, SecretBundle, SecretBytes, SecretValue,
    UpdateConnectionCredentialsRequest, address,
};
use ovstorage_plugin_http::HttpBackendLayerFactory;
use support::{
    VerifyingOrigin, mint_container_sas, mint_sigv4_presign, verify_container_sas,
    verify_sigv4_presign,
};

/// Signing key shared by the minters and the origin's verifier, so a rejection
/// can only come from the request, never from a key disagreement.
const KEY: &[u8] = b"ovstorage-http-signed-query-key!";
/// Container the prefix-scoped grant covers; also the first path segment every
/// object address carries.
const CONTAINER: &str = "media";
const EXPIRY: &str = "2030-01-01T00:00:00Z";
/// A second grant generation: same key, same container, later expiry — so the
/// rotation tests hold two tokens that are both genuinely valid and textually
/// distinct.
const EXPIRY_NEXT: &str = "2031-06-30T12:00:00Z";
const AMZ_DATE: &str = "20300101T000000Z";

/// Root for the tests that are refused before any request is made.
/// `instantiate` never dials, so nothing listens here.
const REFUSAL_ROOT: &str = "https://origin.ovstorage.test/media/";

// === Fixtures ===

/// A bundle of UTF-8 `Bytes` credentials, the shape a host delivers through
/// `ConnectionRequest.credentials`.
fn bundle(pairs: &[(&str, &str)]) -> SecretBundle {
    SecretBundle {
        fields: pairs
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
                )
            })
            .collect(),
    }
}

/// An origin that authorizes with the real container-SAS verifier: a request
/// whose signature does not recompute, or whose path falls outside the
/// container, is answered `403`.
fn sas_origin(body: &str) -> VerifyingOrigin {
    VerifyingOrigin::spawn(body.as_bytes().to_vec(), |request| {
        verify_container_sas(KEY, CONTAINER, &request.path, &request.query)
    })
}

async fn http_layer() -> LayerHandle {
    // The auth substrate is process-global and already initialized when another
    // test in this binary got here first, as the crate's Stack tests do.
    let _ = ovstorage::init_auth_substrate(None);
    HttpBackendLayerFactory::default()
        .create_backend("http", &LayerConfig::new(), None)
        .await
        .expect("the HTTP layer factory builds an empty layer")
}

/// Ask `layer` to hold a connection rooted at `root_url` carrying `credentials`
/// under the declared `signed_query_scope`.
async fn add_connection(
    layer: &LayerHandle,
    root_url: &str,
    scope: Option<&str>,
    credentials: SecretBundle,
) -> Result<Connection> {
    let mut config = HashMap::from([(
        "root_url".to_string(),
        ConfigValue::String(root_url.to_string()),
    )]);
    if let Some(scope) = scope {
        config.insert(
            "signed_query_scope".to_string(),
            ConfigValue::String(scope.to_string()),
        );
    }
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "http".into(),
                connection: ConnectionRequest {
                    backend_kind: "http".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
}

/// Replace the secret a live connection presents, the way a host hands the
/// plugin a freshly-minted token.
async fn rotate(
    layer: &LayerHandle,
    id: &ConnectionId,
    credentials: SecretBundle,
) -> Result<Connection> {
    layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "http".into(),
                    id: id.clone(),
                },
                credentials,
            }),
            None,
        )
        .await
}

/// A layer holding one connection rooted at the origin's container, with
/// `signed_query` declared prefix-scoped. Returns the layer and the root
/// address reads are issued under.
async fn connected(origin: &VerifyingOrigin, signed_query: &str) -> (LayerHandle, String) {
    let (layer, root, _) = held_connection(origin, signed_query).await;
    (layer, root)
}

/// As [`connected`], plus the `Connection` a rotation is addressed to.
async fn held_connection(
    origin: &VerifyingOrigin,
    signed_query: &str,
) -> (LayerHandle, String, Connection) {
    let root = format!("{}/{CONTAINER}/", origin.endpoint());
    let layer = http_layer().await;
    let connection = add_connection(
        &layer,
        &root,
        Some("prefix"),
        bundle(&[("signed_query", signed_query)]),
    )
    .await
    .expect("a prefix-scoped signed query is a shape a connection can hold");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a held signed query is a credential, got {:?}",
        connection.auth_state
    );
    assert_eq!(
        origin.request_lines(),
        vec![format!("HEAD /{CONTAINER}/?{signed_query} HTTP/1.1")],
        "current HTTP connections require positive evidence from a root probe"
    );
    origin.clear_requests();
    (layer, root, connection)
}

/// Read one whole object through the layer, draining the streamed body.
async fn read_bytes(layer: &LayerHandle, address: &str) -> Result<Vec<u8>> {
    use futures::StreamExt;
    let result = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse(address)?,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await?;
    match result {
        ReadResult::Bytes { bytes, .. } => Ok(bytes),
        ReadResult::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
        other => panic!("an open-ended read returns bytes or a stream, got {other:?}"),
    }
}

/// Flip one byte inside the `sig=` value, leaving every other parameter — and
/// therefore the token's recognized shape — untouched. Percent escapes are
/// written with uppercase hex, so the first lowercase letter is always base64
/// payload rather than part of an escape.
fn tamper_signature(query: &str) -> String {
    let at = query
        .find("&sig=")
        .expect("a container SAS carries a sig parameter")
        + "&sig=".len();
    let mut bytes = query.as_bytes().to_vec();
    let flip = at
        + bytes[at..]
            .iter()
            .position(u8::is_ascii_lowercase)
            .expect("a base64 signature carries a lowercase letter");
    bytes[flip] = if bytes[flip] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).expect("ASCII stays UTF-8")
}

/// A minted container SAS whose percent-encoded signature carries `%2F`,
/// `%2B`, and `%3D` — the three escapes a re-encoding pass rewrites.
///
/// Base64 emits `/`, `+`, and `=` for some digests and not others, so the
/// signed expiry is walked over a fixed candidate list until one signature
/// carries all three. HMAC is deterministic, so the walk always lands on the
/// same token.
fn sas_with_escaped_signature() -> String {
    for day in 1..=28 {
        for hour in 0..24 {
            let expiry = format!("2030-01-{day:02}T{hour:02}:00:00Z");
            let sas = mint_container_sas(KEY, CONTAINER, &expiry);
            if ["%2F", "%2B", "%3D"]
                .iter()
                .all(|escape| sas.contains(escape))
            {
                return sas;
            }
        }
    }
    panic!("no candidate expiry produced a signature carrying all three escapes");
}

// === The prefix-scoped family works ===

/// One grant, many objects: the property that distinguishes a prefix-scoped
/// token from a per-object one. Both reads present the *same* token at
/// *different* paths, and the origin verifies the signature and the container
/// scope on each before serving.
#[tokio::test]
async fn prefix_scoped_sas_authorizes_every_object_under_the_root() {
    let origin = sas_origin("bytes-under-the-container");
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let (layer, root) = connected(&origin, &sas).await;

    for key in ["a.bin", "nested/deep/b.bin"] {
        let bytes = read_bytes(&layer, &format!("{root}{key}"))
            .await
            .unwrap_or_else(|err| panic!("one container grant covers {key}: {err}"));
        assert_eq!(bytes, origin.body());
    }

    // The origin serves one body, so the record of *which* object each read
    // asked for is the request line it verified.
    assert_eq!(
        origin.request_lines(),
        vec![
            format!("GET /{CONTAINER}/a.bin?{sas} HTTP/1.1"),
            format!("GET /{CONTAINER}/nested/deep/b.bin?{sas} HTTP/1.1"),
        ],
        "one held token reached two distinct object paths"
    );
}

/// The origin's check is a check: a signature with one byte flipped is refused
/// with `403`, which the plugin surfaces as `PermissionDenied`.
#[tokio::test]
async fn tampered_signed_query_is_refused_by_the_origin() {
    let origin = sas_origin("never-served");
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let tampered = tamper_signature(&sas);
    assert_ne!(sas, tampered, "the tamper changed the signature");

    let root = format!("{}/{CONTAINER}/", origin.endpoint());
    let layer = http_layer().await;
    let connection = add_connection(
        &layer,
        &root,
        Some("prefix"),
        bundle(&[("signed_query", &tampered)]),
    )
    .await
    .expect("a failed credential probe records state instead of rejecting the connection");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a 403 probe is not positive authentication evidence: {:?}",
        connection.auth_state
    );
    origin.clear_requests();
    let err = read_bytes(&layer, &format!("{root}a.bin"))
        .await
        .expect_err("a signature that does not recompute is refused");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        origin.request_lines().len(),
        1,
        "the refusal came from the origin, not from a local pre-check"
    );
}

// === Byte preservation on the wire ===

/// The held query is the signature's subject, so it is spliced onto the URL and
/// never re-encoded: the escapes survive and the parameters keep their order.
#[tokio::test]
async fn held_query_reaches_the_origin_byte_for_byte() {
    let origin = sas_origin("escaped-signature-body");
    let sas = sas_with_escaped_signature();
    for escape in ["%2F", "%2B", "%3D"] {
        assert!(
            sas.contains(escape),
            "the token under test carries {escape}: {sas}"
        );
    }

    let (layer, root) = connected(&origin, &sas).await;
    let bytes = read_bytes(&layer, &format!("{root}a.bin"))
        .await
        .expect("the origin recomputes the signature over the bytes it received");
    assert_eq!(bytes, origin.body());

    assert_eq!(
        origin.request_lines(),
        vec![format!("GET /{CONTAINER}/a.bin?{sas} HTTP/1.1")],
        "the request line carries the held query verbatim"
    );
    assert_eq!(
        origin.requests()[0].query,
        sas,
        "no re-encoding and no reordering"
    );
}

/// An address may carry its own query modifiers; the held token is appended
/// after them, with the separator the existing query implies.
#[tokio::test]
async fn held_query_appends_with_ampersand_when_the_address_already_has_a_query() {
    let origin = sas_origin("addressed-with-a-query");
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let (layer, root) = connected(&origin, &sas).await;

    for address in [format!("{root}a.bin?v=2"), format!("{root}a.bin")] {
        let bytes = read_bytes(&layer, &address)
            .await
            .unwrap_or_else(|err| panic!("{address} is authorized by the held grant: {err}"));
        assert_eq!(bytes, origin.body());
    }

    let queries: Vec<String> = origin
        .requests()
        .into_iter()
        .map(|request| request.query)
        .collect();
    assert_eq!(
        queries,
        vec![format!("v=2&{sas}"), sas],
        "'&' after an existing query, '?' when there is none"
    );
}

// === The per-object family is refused ===

/// A SigV4 presign signs the canonical request, path included. Declaring it
/// prefix-scoped is a claim the parameters contradict, and the mismatch is
/// refused where it is cheap — at `add_connection`.
#[tokio::test]
async fn per_object_presign_declared_prefix_is_refused() {
    let layer = http_layer().await;
    let presign = mint_sigv4_presign(KEY, "/a.bin", AMZ_DATE);
    let err = add_connection(
        &layer,
        REFUSAL_ROOT,
        Some("prefix"),
        bundle(&[("signed_query", &presign)]),
    )
    .await
    .expect_err("a per-object presign is not a prefix-scoped token");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// Declaring the scope honestly does not help: a per-object signature is not a
/// shape any connection can hold, whatever it is called.
#[tokio::test]
async fn object_scope_is_unsupported() {
    let layer = http_layer().await;
    let presign = mint_sigv4_presign(KEY, "/a.bin", AMZ_DATE);
    let err = add_connection(
        &layer,
        REFUSAL_ROOT,
        Some("object"),
        bundle(&[("signed_query", &presign)]),
    )
    .await
    .expect_err("a connection cannot hold a per-object signature");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

/// The scope family is the operator's statement about the token; the plugin
/// does not guess it from the parameters.
#[tokio::test]
async fn signed_query_without_scope_is_invalid_argument() {
    let layer = http_layer().await;
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let err = add_connection(
        &layer,
        REFUSAL_ROOT,
        None,
        bundle(&[("signed_query", &sas)]),
    )
    .await
    .expect_err("a signed query without a declared scope is incomplete");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("signed_query_scope"),
        "the refusal names the missing config key: {}",
        err.message()
    );
}

#[tokio::test]
async fn unknown_scope_value_is_invalid_argument() {
    let layer = http_layer().await;
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let err = add_connection(
        &layer,
        REFUSAL_ROOT,
        Some("container"),
        bundle(&[("signed_query", &sas)]),
    )
    .await
    .expect_err("'container' is not a scope family the plugin knows");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// Why a connection cannot hold this family, shown without the plugin: the
/// presign that verifies at `/a.bin` authenticates nothing at `/b.bin`, so a
/// connection holding it would serve exactly one key and fail on every sibling.
#[test]
fn per_object_presign_authenticates_nothing_at_another_path() {
    let presign = mint_sigv4_presign(KEY, "/a.bin", AMZ_DATE);
    assert!(
        verify_sigv4_presign(KEY, "/a.bin", &presign),
        "the presign verifies at the path it was minted for"
    );
    assert!(
        !verify_sigv4_presign(KEY, "/b.bin", &presign),
        "the path is signed material; a sibling key is unauthenticated"
    );
}

// === The undeclared config channel is closed ===

/// A signature written into `root_url` is refused, and the message points at
/// the credential field that carries one instead.
#[tokio::test]
async fn query_on_root_url_is_refused_and_names_the_credential() {
    let layer = http_layer().await;
    let sas = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let err = add_connection(
        &layer,
        &format!("{REFUSAL_ROOT}?{sas}"),
        None,
        SecretBundle::default(),
    )
    .await
    .expect_err("a route URL must not carry a query");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("signed_query"),
        "the refusal names the credential field that carries one: {}",
        err.message()
    );
}

// === Rotation, judged by the origin ===

/// The raw `se=` value of a container SAS: the generation stamp
/// [`generational_origin`] gates on. Read in the wire encoding and never
/// decoded — the same discipline the plugin applies to the whole query.
fn signed_expiry(query: &str) -> Option<&str> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("se="))
        .filter(|value| !value.is_empty())
}

/// An origin that serves one grant generation at a time.
///
/// A request is authorized only when its signature recomputes *and* its expiry
/// stamp is the one `live` currently names, so a token from the previous
/// generation is refused even though it is perfectly well-formed. Moving `live`
/// is how a test says "the origin has rolled its keys"; a read that still
/// succeeds afterwards can only be presenting the new token.
fn generational_origin(body: &str, live: Arc<Mutex<String>>) -> VerifyingOrigin {
    VerifyingOrigin::spawn(body.as_bytes().to_vec(), move |request| {
        let generation = live.lock().unwrap().clone();
        verify_container_sas(KEY, CONTAINER, &request.path, &request.query)
            && signed_expiry(&request.query) == Some(generation.as_str())
    })
}

/// Rotation is live, and the proof is the origin's own answer: the token the
/// connection was added with stops working the moment the origin rolls its
/// generation, and reads resume only after `update_connection_credentials`
/// installs the replacement. The recorded request lines show each read carried
/// the token of its own generation.
#[tokio::test]
async fn rotating_the_signed_query_changes_what_the_origin_accepts() {
    let token_a = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let token_b = mint_container_sas(KEY, CONTAINER, EXPIRY_NEXT);
    assert_ne!(token_a, token_b, "two generations, two tokens");

    let live = Arc::new(Mutex::new(
        signed_expiry(&token_a)
            .expect("a container SAS carries an expiry")
            .to_string(),
    ));
    let origin = generational_origin("rotated-bytes", Arc::clone(&live));
    let (layer, root, connection) = held_connection(&origin, &token_a).await;

    let bytes = read_bytes(&layer, &format!("{root}first.bin"))
        .await
        .expect("the token the connection was added with is the live generation");
    assert_eq!(bytes, origin.body());

    // The origin rolls forward. The connection still holds A, and A is now a
    // token the origin declines — without this step a rotation that changed
    // nothing would still look like a success.
    *live.lock().unwrap() = signed_expiry(&token_b).expect("an expiry").to_string();
    let err = read_bytes(&layer, &format!("{root}stale.bin"))
        .await
        .expect_err("the previous generation is not what this origin accepts now");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);

    let rotated = rotate(
        &layer,
        &connection.id,
        bundle(&[("signed_query", &token_b)]),
    )
    .await
    .expect("replacing the held token on a live connection is supported");
    assert!(
        matches!(
            rotated.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a rotated connection is still credentialed, got {:?}",
        rotated.auth_state
    );
    assert!(
        origin
            .request_lines()
            .last()
            .is_some_and(|line| line == &format!("HEAD /{CONTAINER}/?{token_b} HTTP/1.1")),
        "rotation proves the replacement at the root before swapping it"
    );
    origin.clear_requests();

    let bytes = read_bytes(&layer, &format!("{root}second.bin"))
        .await
        .expect("the replacement token is what the origin now accepts");
    assert_eq!(bytes, origin.body());

    assert_eq!(
        origin.request_lines(),
        vec![format!("GET /{CONTAINER}/second.bin?{token_b} HTTP/1.1")],
        "the post-rotation read carries only the replacement token"
    );
}

/// A rotation the resolver refuses is not a partial rotation: the connection
/// keeps serving with the token it already held, judged by the origin rather
/// than by reading the plugin's own state back.
#[tokio::test]
async fn rejected_rotation_leaves_the_previous_credential_serving() {
    let origin = sas_origin("still-serving");
    let token = mint_container_sas(KEY, CONTAINER, EXPIRY);
    let (layer, root, connection) = held_connection(&origin, &token).await;

    let bytes = read_bytes(&layer, &format!("{root}before.bin"))
        .await
        .expect("the held grant covers the container");
    assert_eq!(bytes, origin.body());

    // A per-object presign under this connection's declared 'prefix' scope is
    // the same mismatch `add_connection` refuses.
    let err = rotate(
        &layer,
        &connection.id,
        bundle(&[(
            "signed_query",
            &mint_sigv4_presign(KEY, "/after.bin", AMZ_DATE),
        )]),
    )
    .await
    .expect_err("a per-object presign is not a prefix-scoped replacement");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);

    let bytes = read_bytes(&layer, &format!("{root}after.bin"))
        .await
        .expect("the original token is untouched by a refused rotation");
    assert_eq!(bytes, origin.body());

    assert_eq!(
        origin.request_lines(),
        vec![
            format!("GET /{CONTAINER}/before.bin?{token} HTTP/1.1"),
            format!("GET /{CONTAINER}/after.bin?{token} HTTP/1.1"),
        ],
        "the refused bundle never reached the wire"
    );
}

/// A rotation replaces a secret; it does not grant one. An anonymous connection
/// stays anonymous, and the refusal names the remove-and-re-add that does build
/// the other shape.
#[tokio::test]
async fn anonymous_to_credentialed_rotation_is_unsupported() {
    let layer = http_layer().await;
    let connection = add_connection(&layer, REFUSAL_ROOT, None, SecretBundle::default())
        .await
        .expect("a connection with no credentials is anonymous");
    assert_eq!(connection.auth_state, ConnectionAuthState::Anonymous);

    let err = rotate(&layer, &connection.id, bundle(&[("bearer_token", "t0ken")]))
        .await
        .expect_err("attaching a credential to an anonymous connection is a shape change");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(
        err.message().contains("re-add"),
        "the refusal names the path that does attach one: {}",
        err.message()
    );

    // A signed query is refused earlier still: its scope family is
    // configuration, and a rotation carries secrets only.
    let err = rotate(
        &layer,
        &connection.id,
        bundle(&[("signed_query", &mint_container_sas(KEY, CONTAINER, EXPIRY))]),
    )
    .await
    .expect_err("a rotation cannot supply the scope declaration a signed query needs");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("signed_query_scope"),
        "the refusal names the config key that declares the family: {}",
        err.message()
    );

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .expect("the layer still lists its connections");
    let stored = snapshot
        .connections
        .iter()
        .find(|listed| listed.id == connection.id)
        .expect("connection still listed");
    assert_eq!(
        stored.auth_state,
        ConnectionAuthState::Anonymous,
        "two refused rotations left the connection as it was"
    );
}
