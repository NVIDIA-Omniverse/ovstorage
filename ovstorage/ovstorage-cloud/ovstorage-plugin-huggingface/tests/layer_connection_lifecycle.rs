// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-lifecycle contract for the Hugging Face layer: verify verdicts
//! at add time, the probe-vs-add split (probe reports, add records), routing
//! across connections and teardown, credential rotation through the live
//! cell, and the layer-side list fold/pagination conventions.

use std::collections::HashMap;

use futures::StreamExt;
use ovstorage_plugin::{
    BackendFactory, CancellationToken, ConfigValue, Connection, ConnectionAuthState, ConnectionKey,
    ConnectionRequest, ErrorCode, Extensions, LayerConfig, LayerConnectionRequest, LayerHandle,
    ListOptions, ListRequest, ObjectKind, Request, SecretBundle, SecretBytes, SecretValue,
    StatOptions, StatRequest, UpdateConnectionCredentialsRequest, address,
};
use ovstorage_plugin_huggingface::HfLayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

mod support;

const WHOAMI_OK: &str = r#"{"name":"tester"}"#;
const PATHS_INFO_FILE: &str = r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#;
const TREE_THREE_ENTRIES: &str = r#"[
    {"type":"directory","oid":"d1","size":0,"path":"team"},
    {"type":"file","oid":"a1","size":3,"path":"a.txt"},
    {"type":"file","oid":"b1","size":4,"path":"b.txt"}
]"#;

async fn empty_layer() -> LayerHandle {
    HfLayerFactory::default()
        .create_backend("huggingface", &LayerConfig::new(), None)
        .await
        .unwrap()
}

fn token_bundle(token: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "token".into(),
        SecretValue::Bytes(SecretBytes(token.as_bytes().to_vec())),
    );
    bundle
}

fn connection_request(
    repo_id: &str,
    repo_type: Option<&str>,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("repo_id".to_string(), ConfigValue::String(repo_id.into()));
    if let Some(repo_type) = repo_type {
        config.insert(
            "repo_type".to_string(),
            ConfigValue::String(repo_type.into()),
        );
    }
    config.insert("endpoint".to_string(), ConfigValue::String(endpoint.into()));
    ConnectionRequest {
        backend_kind: "huggingface".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn add(
    layer: &LayerHandle,
    request: ConnectionRequest,
) -> ovstorage_plugin::Result<Connection> {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: request,
            }),
            None,
        )
        .await
}

async fn connection_count(layer: &LayerHandle) -> usize {
    let (snapshot, _) = layer
        .list_connections(&Extensions::default(), None)
        .await
        .unwrap();
    snapshot.connections.len()
}

#[tokio::test]
async fn add_connection_anonymous_skips_verify() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert_eq!(server.hits(), 0, "anonymous add must not reach the wire");
    assert_eq!(
        connection.current_addresses[0].as_str(),
        "hf://models/acme/demo/"
    );
}

/// Add must never stop a host from starting: a rejected token PARKS the
/// connection (`AwaitingAuth` with the attempt recorded) instead of erroring,
/// and the config-derived root is still published so callers can locate and
/// re-credential it.
#[tokio::test]
async fn add_connection_records_a_credential_rejection() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            token_bundle("hf_expired"),
        ),
    )
    .await
    .unwrap();
    match &connection.auth_state {
        ConnectionAuthState::AwaitingAuth { last_attempt, .. } => {
            let error = last_attempt
                .as_ref()
                .and_then(|attempt| attempt.error.as_ref())
                .expect("the rejection is recorded on the attempt");
            assert_eq!(error.code(), ErrorCode::AuthRequired);
        }
        other => panic!("a rejected token must park, got {other:?}"),
    }
    assert_eq!(server.hits(), 1, "one whoami verify was spent");
    assert_eq!(
        connection_count(&layer).await,
        1,
        "the connection is listed"
    );
    let root = layer
        .root_info_for(
            &address::parse("hf://models/acme/demo/x").unwrap(),
            &Extensions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), "hf://models/acme/demo/");
}

/// A probe is transient and side-effect-free: it reports the verdict view
/// (including the config-derived root) but registers nothing.
#[tokio::test]
async fn probe_reports_verdict_without_registering() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", WHOAMI_OK));
    let layer = empty_layer().await;
    let view = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: connection_request(
                    "acme/demo",
                    None,
                    server.endpoint(),
                    token_bundle("hf_good"),
                ),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        view.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(view.last_probed.is_some());
    assert_eq!(view.current_addresses[0].as_str(), "hf://models/acme/demo/");
    assert_eq!(connection_count(&layer).await, 0, "probe registers nothing");
}

/// Probe reports a delivered 401 as a rejection verdict on the view — the
/// same evidence add records, surfaced instead of persisted.
#[tokio::test]
async fn probe_surfaces_credential_rejection() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
    let layer = empty_layer().await;
    let view = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: connection_request(
                    "acme/demo",
                    None,
                    server.endpoint(),
                    token_bundle("hf_bad"),
                ),
            }),
            None,
        )
        .await
        .unwrap();
    match &view.auth_state {
        ConnectionAuthState::AwaitingAuth { last_attempt, .. } => {
            let error = last_attempt
                .as_ref()
                .and_then(|attempt| attempt.error.as_ref())
                .expect("the rejection rides on the attempt");
            assert_eq!(error.code(), ErrorCode::AuthRequired);
        }
        other => panic!("a rejected probe must report AwaitingAuth, got {other:?}"),
    }
    assert_eq!(connection_count(&layer).await, 0);
}

/// Verify is LENIENT: only a definitive 401 rejects the credential itself.
/// A 5xx (or any transport blip) is not a refutation — with `refresh`
/// unsupported, parking on a transient would strand a valid token until
/// manual remove/re-add. Pinned so a future strictening is deliberate.
#[tokio::test]
async fn probe_verify_is_lenient_on_transient_failures() {
    let server =
        ScriptedHttpServer::spawn(CannedHttpResponse::new("500 Internal Server Error", ""));
    let layer = empty_layer().await;
    let view = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: connection_request(
                    "acme/demo",
                    None,
                    server.endpoint(),
                    token_bundle("hf_unproven"),
                ),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(view.auth_state, ConnectionAuthState::Authenticated { .. }),
        "a non-credential failure must not refute the token, got {:?}",
        view.auth_state
    );
}

#[tokio::test]
async fn routes_across_two_connections_and_removes() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    let model = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let dataset = add(
        &layer,
        connection_request(
            "acme/data",
            Some("dataset"),
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        model.current_addresses[0].as_str(),
        "hf://models/acme/demo/"
    );
    assert_eq!(
        dataset.current_addresses[0].as_str(),
        "hf://datasets/acme/data/"
    );
    let cx = Extensions::default();
    for (probe, root) in [
        (
            "hf://models/acme/demo/weights.bin",
            "hf://models/acme/demo/",
        ),
        (
            "hf://datasets/acme/data/rows.csv",
            "hf://datasets/acme/data/",
        ),
    ] {
        let info = layer
            .root_info_for(&address::parse(probe).unwrap(), &cx, None)
            .await
            .unwrap();
        assert_eq!(info.root.as_str(), root);
    }
    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "huggingface".into(),
                id: dataset.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    let err = layer
        .root_info_for(
            &address::parse("hf://datasets/acme/data/rows.csv").unwrap(),
            &cx,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert_eq!(connection_count(&layer).await, 1);
}

/// The registered row and the probe preview row both carry the
/// accepted-URL-spellings contract the alias wrapper consumes, and they agree
/// — so a host can show "these URLs will also resolve" before the caller
/// commits. The fixture endpoint is loopback, whose one spelling is exact; a
/// dataset carries the Hub's `datasets/` web prefix.
#[tokio::test]
async fn connection_and_probe_rows_carry_the_accepted_url_spellings() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    let request = connection_request(
        "acme/demo",
        None,
        server.endpoint(),
        SecretBundle::default(),
    );
    let connection = add(&layer, request.clone()).await.unwrap();
    let expected = format!("{}/acme/demo/", server.endpoint());
    assert_eq!(
        connection
            .user_metadata
            .get(ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY)
            .map(String::as_str),
        Some(expected.as_str())
    );
    assert_eq!(
        connection.current_addresses[0].as_str(),
        "hf://models/acme/demo/"
    );
    let preview = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        preview
            .user_metadata
            .get(ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY),
        connection
            .user_metadata
            .get(ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY),
        "the probe preview row carries the same contract as the registered row"
    );

    let dataset = add(
        &layer,
        connection_request(
            "acme/demo",
            Some("dataset"),
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        dataset
            .user_metadata
            .get(ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY)
            .map(String::as_str),
        Some(format!("{}/datasets/acme/demo/", server.endpoint()).as_str())
    );
    assert_eq!(
        dataset.current_addresses[0].as_str(),
        "hf://datasets/acme/demo/"
    );

    // A model whose namespace is a Hub route root would spell itself on top
    // of the dataset URL space, so its row carries no spellings at all — the
    // alias wrapper derives nothing and the URLs under that prefix keep
    // routing to whatever else serves them.
    let reserved = add(
        &layer,
        connection_request(
            "datasets/acme",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        reserved
            .user_metadata
            .get(ovstorage_plugin::ACCEPTED_URL_SPELLINGS_METADATA_KEY),
        None,
        "a model in a reserved Hub namespace advertises no web spelling"
    );
    assert_eq!(
        reserved.current_addresses[0].as_str(),
        "hf://models/datasets/acme/"
    );
    assert_eq!(
        server.hits(),
        0,
        "anonymous adds and probes spend no verify"
    );
}

/// One connection per repository: a second connection to the same repo —
/// even with a different default revision — is refused with `RouteConflict`
/// (alternate revisions ride as `?revision=` pins), and the refused add
/// leaves no orphan row behind.
#[tokio::test]
async fn a_duplicate_repo_connection_is_refused_with_route_conflict() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let mut request = connection_request(
        "acme/demo",
        None,
        server.endpoint(),
        token_bundle("hf_secret-token"),
    );
    request.config.insert(
        "revision".to_string(),
        ConfigValue::String("refs/pr/1".into()),
    );
    // The duplicate's verify still runs (lenient against the canned 200);
    // the refusal comes from route installation.
    let err = add(&layer, request).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RouteConflict);
    assert!(
        err.message().contains("hf://models"),
        "the refusal names the origin: {}",
        err.message()
    );
    assert!(
        !err.message().contains("hf_secret-token"),
        "the refusal must not carry the credential"
    );
    assert_eq!(
        connection_count(&layer).await,
        1,
        "the refused add must roll its registration back"
    );
}

/// Credential rotation flows obtain → verify → activate into the live cell
/// the backend reads, so the very next request carries the new bearer.
#[tokio::test]
async fn update_credentials_swaps_the_bearer() {
    let server = ScriptedHttpServer::spawn_sequence(vec![
        // add-time verify of token A
        Some(CannedHttpResponse::json("200 OK", WHOAMI_OK)),
        // update-time verify of token B
        Some(CannedHttpResponse::json("200 OK", WHOAMI_OK)),
        // the stat that must carry B
        Some(CannedHttpResponse::json("200 OK", PATHS_INFO_FILE)),
    ]);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("acme/demo", None, server.endpoint(), token_bundle("hf_A")),
    )
    .await
    .unwrap();
    layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "huggingface".into(),
                    id: connection.id.clone(),
                },
                credentials: token_bundle("hf_B"),
            }),
            None,
        )
        .await
        .unwrap();
    layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("hf://models/acme/demo/obj.txt").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let raw = server.requests();
    assert_eq!(raw.len(), 3, "verify, verify, stat: {raw:?}");
    assert!(
        request_has_header(&raw[2], "authorization", "Bearer hf_B"),
        "the post-rotation request must carry the new bearer: {}",
        raw[2]
    );
}

/// The anonymous/tokened distinction is frozen at add time (`activate` only
/// ever installs a token; an empty bundle never clears the cell), so both
/// shape changes are refused with remove-and-re-add guidance.
#[tokio::test]
async fn update_credentials_shape_changes_are_refused() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", WHOAMI_OK));
    let layer = empty_layer().await;
    let anonymous = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "huggingface".into(),
                    id: anonymous.id.clone(),
                },
                credentials: token_bundle("hf_late"),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);

    let tokened = add(
        &layer,
        connection_request(
            "acme/data",
            Some("dataset"),
            server.endpoint(),
            token_bundle("hf_A"),
        ),
    )
    .await
    .unwrap();
    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "huggingface".into(),
                    id: tokened.id.clone(),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn update_connection_attributes_is_local() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let updated = layer
        .update_connection_attributes(
            Request::new(ovstorage_plugin::UpdateConnectionAttributesRequest {
                key: ConnectionKey {
                    target: "huggingface".into(),
                    id: connection.id.clone(),
                },
                patch: ovstorage_plugin::AttributePatch {
                    display_name: Some("Weights mirror".into()),
                    ..Default::default()
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name, "Weights mirror");
    assert_eq!(server.hits(), 0, "attribute updates are local");
}

/// There is no interactive flow: the slot keeps the trait default and
/// answers `Unsupported` without opening a stream or touching state.
#[tokio::test]
async fn authenticate_connection_is_unsupported() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
    let layer = empty_layer().await;
    let parked = add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            token_bundle("hf_expired"),
        ),
    )
    .await
    .unwrap();
    let err = layer
        .authenticate_connection(
            Request::new(ovstorage_plugin::AuthenticateRequest {
                key: ConnectionKey {
                    target: "huggingface".into(),
                    id: parked.id.clone(),
                },
                capability: ovstorage_plugin::InteractiveAuthCapability::Browser,
                auto_open_browser: false,
            }),
            None,
        )
        .await
        .err()
        .expect("no interactive flow exists");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    let (snapshot, _) = layer
        .list_connections(&Extensions::default(), None)
        .await
        .unwrap();
    assert!(
        matches!(
            snapshot.connections[0].auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "the parked state is untouched"
    );
}

/// The SPI page token is the shared numeric-offset convention over the
/// folded listing — never the Hub cursor.
#[tokio::test]
async fn list_pages_with_the_shared_numeric_offset_convention() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", TREE_THREE_ENTRIES));
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let root = address::parse("hf://models/acme/demo/").unwrap();
    let first = layer
        .list(
            Request::new(ListRequest {
                prefix: root.clone(),
                options: ListOptions {
                    max_results: Some(2),
                    ..ListOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[0].kind, ObjectKind::Directory);
    assert_eq!(
        first.items[0].address.as_str(),
        "hf://models/acme/demo/team/",
        "real directories keep their kind and gain the trailing slash"
    );
    let token = first.next_page_token.expect("a second page exists");
    let second = layer
        .list(
            Request::new(ListRequest {
                prefix: root,
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
    assert_eq!(second.items.len(), 1);
    assert_eq!(
        second.items[0].address.as_str(),
        "hf://models/acme/demo/b.txt"
    );
    assert!(second.next_page_token.is_none());
}

/// Upstream Link-header pagination is followed inside one logical list: the
/// cursor rides in the server's own next URL, and the pages concatenate.
/// (`LinkedHubServer` because the `Link` target must reference the live
/// origin — the plugin refuses to follow it anywhere else.)
#[tokio::test]
async fn list_follows_link_header_pagination_upstream() {
    let server_with_link = support::LinkedHubServer::spawn(vec![
        support::LinkedPage {
            body: r#"[{"type":"file","oid":"a1","size":3,"path":"a.txt"}]"#.into(),
            next_path: Some("/api/models/acme/demo/tree/main?cursor=abc".into()),
        },
        support::LinkedPage {
            body: r#"[{"type":"file","oid":"b1","size":4,"path":"b.txt"}]"#.into(),
            next_path: None,
        },
    ]);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server_with_link.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("hf://models/acme/demo/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let addresses: Vec<&str> = page
        .items
        .iter()
        .map(|item| item.address.as_str())
        .collect();
    assert_eq!(
        addresses,
        vec!["hf://models/acme/demo/a.txt", "hf://models/acme/demo/b.txt"],
        "one logical list concatenates both upstream pages"
    );
    assert_eq!(server_with_link.hits(), 2);
    let raw = server_with_link.requests();
    assert!(
        raw[1].contains("cursor=abc"),
        "the second wire request follows the server's cursor URL: {}",
        raw[1]
    );
}

#[tokio::test]
async fn list_stream_matches_buffered_across_link_pages() {
    fn pages() -> Vec<support::LinkedPage> {
        vec![
            support::LinkedPage {
                body: r#"[
                    {"type":"directory","oid":"d1","size":0,"path":"team"},
                    {"type":"file","oid":"a1","size":3,"path":"a.txt"}
                ]"#
                .into(),
                next_path: Some("/api/models/acme/demo/tree/main?cursor=abc".into()),
            },
            support::LinkedPage {
                body: r#"[{"type":"file","oid":"b1","size":4,"path":"b.txt"}]"#.into(),
                next_path: None,
            },
        ]
    }

    let buffered_server = support::LinkedHubServer::spawn(pages());
    let buffered_layer = empty_layer().await;
    add(
        &buffered_layer,
        connection_request(
            "acme/demo",
            None,
            buffered_server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let prefix = address::parse("hf://models/acme/demo/").unwrap();
    let buffered = buffered_layer
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

    let streamed_server = support::LinkedHubServer::spawn(pages());
    let streamed_layer = empty_layer().await;
    add(
        &streamed_layer,
        connection_request(
            "acme/demo",
            None,
            streamed_server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let mut stream = streamed_layer
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

    assert_eq!(streamed, buffered);
    assert_eq!(buffered_server.hits(), 2);
    assert_eq!(streamed_server.hits(), 2);
}

#[tokio::test]
async fn list_stream_rejects_a_self_link_without_refetching_the_page() {
    let page = || support::LinkedPage {
        body: r#"[
            {"type":"file","oid":"a1","size":1,"path":"a.txt"},
            {"type":"file","oid":"b1","size":1,"path":"b.txt"}
        ]"#
        .into(),
        next_path: Some("/api/models/acme/demo/tree/main".into()),
    };
    // The second response exists only to catch a regression that follows the
    // self-link. A correct stream leaves it untouched.
    let server = support::LinkedHubServer::spawn(vec![page(), page()]);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let mut stream = layer
        .list_stream(
            Request::new(ListRequest {
                prefix: address::parse("hf://models/acme/demo/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        stream.next().await.unwrap().unwrap().address.as_str(),
        "hf://models/acme/demo/a.txt"
    );
    assert_eq!(
        stream.next().await.unwrap().unwrap().address.as_str(),
        "hf://models/acme/demo/b.txt"
    );
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);
    assert!(stream.next().await.is_none());
    assert_eq!(
        server.hits(),
        1,
        "a self-referential next link must fail before the page is requested again"
    );
}

#[tokio::test]
async fn list_stream_is_pull_driven_between_link_pages() {
    let server = support::LinkedHubServer::spawn(vec![
        support::LinkedPage {
            body: r#"[
                {"type":"file","oid":"a1","size":1,"path":"a.txt"},
                {"type":"file","oid":"b1","size":1,"path":"b.txt"},
                {"type":"file","oid":"c1","size":1,"path":"c.txt"}
            ]"#
            .into(),
            next_path: Some("/api/models/acme/demo/tree/main?cursor=abc".into()),
        },
        support::LinkedPage {
            body: r#"[{"type":"file","oid":"d1","size":1,"path":"d.txt"}]"#.into(),
            next_path: None,
        },
    ]);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let mut stream = layer
        .list_stream(
            Request::new(ListRequest {
                prefix: address::parse("hf://models/acme/demo/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(server.hits(), 0, "opening the stream must not fetch a page");
    assert_eq!(
        stream.next().await.unwrap().unwrap().address.as_str(),
        "hf://models/acme/demo/a.txt"
    );
    assert_eq!(server.hits(), 1);
    assert_eq!(
        stream.next().await.unwrap().unwrap().address.as_str(),
        "hf://models/acme/demo/b.txt"
    );
    assert_eq!(
        server.hits(),
        1,
        "the second Hub page stays unfetched while entries remain in the first"
    );

    let mut tail = Vec::new();
    while let Some(item) = stream.next().await {
        tail.push(item.unwrap().address.to_string());
    }
    assert_eq!(
        tail,
        vec!["hf://models/acme/demo/c.txt", "hf://models/acme/demo/d.txt"]
    );
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn list_stream_cancellation_stops_before_the_next_link_page() {
    let server = support::LinkedHubServer::spawn(vec![
        support::LinkedPage {
            body: r#"[
                {"type":"file","oid":"a1","size":1,"path":"a.txt"},
                {"type":"file","oid":"b1","size":1,"path":"b.txt"},
                {"type":"file","oid":"c1","size":1,"path":"c.txt"}
            ]"#
            .into(),
            next_path: Some("/api/models/acme/demo/tree/main?cursor=abc".into()),
        },
        support::LinkedPage {
            body: r#"[{"type":"file","oid":"d1","size":1,"path":"d.txt"}]"#.into(),
            next_path: None,
        },
    ]);
    let layer = empty_layer().await;
    add(
        &layer,
        connection_request(
            "acme/demo",
            None,
            server.endpoint(),
            SecretBundle::default(),
        ),
    )
    .await
    .unwrap();
    let cancel = CancellationToken::new();
    let mut stream = layer
        .list_stream(
            Request::new(ListRequest {
                prefix: address::parse("hf://models/acme/demo/").unwrap(),
                options: ListOptions::default(),
            }),
            Some(cancel.clone()),
        )
        .await
        .unwrap();

    assert!(stream.next().await.unwrap().is_ok());
    assert_eq!(server.hits(), 1);
    cancel.cancel();
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Cancelled);
    assert!(stream.next().await.is_none());
    assert_eq!(
        server.hits(),
        1,
        "cancellation must prevent the next Link page from being requested"
    );
}
