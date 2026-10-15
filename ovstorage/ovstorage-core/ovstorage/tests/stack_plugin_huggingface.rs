// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **huggingface cdylib** through a native
//! Stack.
//!
//! Loads the staged `libovstorage_plugin_huggingface` via `load_layer_plugin`
//! (exercising its `ovstorage_layer_plugin!` manifest, thunks, and loader),
//! opens a `backend_kind = "huggingface"` connection through the Stack, and
//! drives the real data path against ONE local mock hub: token verify
//! (whoami), stat (paths-info), a non-LFS direct read, an LFS read whose
//! minted redirect is FOLLOWED by the Stack's redirect follower, and
//! teardown — and, under an `alias` root, the accepted-URL-spellings
//! contract the plugin stamps: a pasted Hub URL resolves through a derived
//! hidden rule and stops routing when the connection is removed. Gated on
//! `OVSTORAGE_HUGGINGFACE_PLUGIN_SO_OVERRIDE` (hard error
//! under `OVSTORAGE_REQUIRE_TEST_PLUGINS`, else skip — matching
//! `mixed_layer_stack.rs`).

use std::collections::HashMap;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ovstorage::ext::LayerExt as _;
use ovstorage::{
    ACCEPTED_URL_SPELLINGS_METADATA_KEY, ALIAS_DERIVED_FROM_METADATA_KEY, AddressVisibility,
    AliasState, ConfigValue, ConnectionAuthState, ConnectionKey, ConnectionRequest, ErrorCode,
    Extensions, LayerConnectionRequest, ReadOptions, Request, SecretBundle, SecretBytes,
    SecretValue, Stack, StatOptions, Url,
};

mod support;

const LFS_BODY: &[u8] = b"hello-v2-huggingface-lfs";
const PLAIN_BODY: &[u8] = b"hello-v2-huggingface";
const LFS_SHA256: &str = "b43f4c2ea569da1d66ca74e26ca8ea4430dfc29195e97144b2d0b4f3f6cafa1c";

/// Read one HTTP request (headers + any Content-Length body) off `stream`.
fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    let mut header_end = None;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                raw.extend_from_slice(&buf[..len]);
                if header_end.is_none() {
                    header_end = raw
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|pos| pos + 4);
                }
                if let Some(end) = header_end {
                    let headers = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + content_length {
                        break;
                    }
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!raw.is_empty()).then(|| String::from_utf8_lossy(&raw).to_string())
}

fn bytes_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"hf-etag\"\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// One mock hub serving whoami (verify), paths-info (stat), and resolve (a
/// plain file answering 200 and an LFS file answering 302 onto a SEPARATE
/// mock CDN listener — a distinct origin, so the plugin must mint the
/// redirect rather than follow it); records request lines from both.
fn spawn_mock_hub() -> (String, Arc<Mutex<Vec<String>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));

    // The CDN half: a foreign origin serving the LFS blob.
    let cdn_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral cdn");
    let cdn_endpoint = format!("http://{}", cdn_listener.local_addr().unwrap());
    let cdn_requests = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-cdn".into())
        .spawn(move || {
            for stream in cdn_listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                let request_line = raw.lines().next().unwrap_or_default().to_string();
                cdn_requests
                    .lock()
                    .expect("requests poisoned")
                    .push(request_line.clone());
                let response: Vec<u8> = if request_line.starts_with("GET /cdn/blob") {
                    bytes_response(LFS_BODY)
                } else {
                    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_vec()
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        })
        .expect("spawn mock cdn");

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests_for_thread = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-hub".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                let request_line = raw.lines().next().unwrap_or_default().to_string();
                requests_for_thread
                    .lock()
                    .expect("requests poisoned")
                    .push(request_line.clone());
                let json = |body: &str| -> Vec<u8> {
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                };
                let response: Vec<u8> = if request_line.starts_with("GET /api/whoami-v2") {
                    json("{\"name\": \"tester\"}")
                } else if request_line.starts_with("POST /api/models/acme/demo/paths-info/") {
                    // Path-aware like the Hub: an entry for a path the repo
                    // has, an empty array (the plugin's `NotFound`) otherwise.
                    if raw.contains("weights/model.bin") {
                        json(&format!(
                            "[{{\"type\": \"file\", \"oid\": \"blob1\", \"size\": {}, \
                             \"path\": \"weights/model.bin\"}}]",
                            LFS_BODY.len()
                        ))
                    } else if raw.contains("plain.txt") {
                        json(&format!(
                            "[{{\"type\": \"file\", \"oid\": \"blob2\", \"size\": {}, \
                             \"path\": \"plain.txt\"}}]",
                            PLAIN_BODY.len()
                        ))
                    } else {
                        json("[]")
                    }
                } else if request_line.starts_with("GET /acme/demo/resolve/main/weights/model.bin")
                {
                    format!(
                        "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: {cdn_endpoint}/cdn/blob\r\nx-linked-etag: \"{LFS_SHA256}\"\r\nx-linked-size: {}\r\nContent-Length: 0\r\n\r\n",
                        LFS_BODY.len()
                    )
                    .into_bytes()
                } else if request_line.starts_with("GET /acme/demo/resolve/main/plain.txt") {
                    bytes_response(PLAIN_BODY)
                } else {
                    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_vec()
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        })
        .expect("spawn mock hub");
    std::thread::sleep(Duration::from_millis(50));
    (endpoint, requests)
}

fn token_bundle() -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "token".into(),
        SecretValue::Bytes(SecretBytes(b"hf_synthetic".to_vec())),
    );
    bundle
}

fn hf_connection_request(endpoint: &str, credentials: SecretBundle) -> ConnectionRequest {
    hf_connection_request_for("acme/demo", endpoint, credentials)
}

fn hf_connection_request_for(
    repo_id: &str,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    ConnectionRequest {
        backend_kind: "huggingface".into(),
        config: HashMap::from([
            ("repo_id".into(), ConfigValue::String(repo_id.into())),
            ("endpoint".into(), ConfigValue::String(endpoint.into())),
        ]),
        credentials,
        persist: false,
        display_name: Some("mock-hub".into()),
    }
}

fn staged_hf_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_HUGGINGFACE_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_HUGGINGFACE_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged huggingface cdylib"
            );
            eprintln!("skipping: OVSTORAGE_HUGGINGFACE_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

/// A linear Stack over the staged huggingface cdylib with `wrappers` above
/// it, every wrapper served by the staged core / http sibling cdylibs.
async fn hf_stack(so: &std::path::Path, wrappers: &[&str]) -> Arc<Stack> {
    let core = support::sibling_plugin(so, "ovstorage_plugin_core");
    let http = support::sibling_plugin(so, "ovstorage_plugin_http");
    let factories = support::load_plugins(&[so, &core, &http]);
    ovstorage::host::build_stack(
        &support::linear_stack_config("huggingface", wrappers),
        factories,
    )
    .await
    .expect("build huggingface Stack")
}

/// The full tokened round trip: load cdylib → bridge add_connection (whoami
/// verify observed on the wire) → paths-info stat → LFS read whose minted
/// redirect the Stack's follower executes → teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_huggingface_cdylib_and_round_trips() {
    let Some(so) = staged_hf_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_hub();
    let object = Url::parse("hf://models/acme/demo/weights/model.bin").unwrap();

    let stack = hf_stack(&so, &["redirect_follower", "retry"]).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "huggingface".into(),
            connection: hf_connection_request(&endpoint, token_bundle()),
        }),
        None,
    )
    .await
    .expect("open a huggingface connection to the loaded v2 cdylib through the Stack");
    assert_eq!(connection.backend_kind, "huggingface");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the token verifies against the mock whoami, got {:?}",
        connection.auth_state
    );
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "hf://models/acme/demo/"),
        "connection contributes the config-derived root"
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("GET /api/whoami-v2")),
        "the verify drove a whoami check against the mock hub"
    );

    // stat = paths-info POST through the composed Stack.
    let stat = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the loaded huggingface cdylib");
    assert_eq!(stat.size, Some(LFS_BODY.len() as u64));

    // read = the plugin follows the resolve 302 to the off-origin CDN itself
    // and streams the bytes, reporting the canonical linked LFS identity.
    let (bytes, info) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("redirect-followed read through the loaded huggingface cdylib");
    assert_eq!(bytes, LFS_BODY);
    assert_eq!(
        info.etag.as_deref(),
        Some(LFS_SHA256),
        "the followed LFS read reports the canonical sha256, not the CDN tag"
    );
    {
        let seen = requests.lock().unwrap();
        assert!(
            seen.iter().any(|line| line.starts_with("GET /cdn/blob")),
            "the followed read must reach the CDN path: {seen:?}"
        );
    }

    // Teardown: the root stops routing.
    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "huggingface".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .expect("remove huggingface connection");
    let err = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("root not routable after removal");
    assert!(
        matches!(err.code(), ErrorCode::NoRoute | ErrorCode::NotConfigured),
        "expected NoRoute/NotConfigured, got {:?}",
        err.code()
    );
}

/// Anonymous connection through the Stack: a non-LFS file resolves 200 and
/// streams directly — no redirect, no credential anywhere on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_anonymous_huggingface_connection_reads_direct() {
    let Some(so) = staged_hf_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_hub();
    let object = Url::parse("hf://models/acme/demo/plain.txt").unwrap();

    let stack = hf_stack(&so, &["redirect_follower", "retry"]).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "huggingface".into(),
            connection: hf_connection_request(&endpoint, SecretBundle::default()),
        }),
        None,
    )
    .await
    .expect("anonymous huggingface connection through the Stack");
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));

    let (bytes, _) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("anonymous direct read");
    assert_eq!(bytes, PLAIN_BODY);
    let seen = requests.lock().unwrap();
    assert!(
        seen.iter()
            .any(|line| line.starts_with("GET /acme/demo/resolve/main/plain.txt")),
        "the anonymous read reached the resolve endpoint: {seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|line| line.starts_with("GET /api/whoami-v2")),
        "an anonymous add spends no verify"
    );
}

/// A Hub URL spelling through the real cdylib under an `alias` root: the
/// accepted-URL-spellings metadata the plugin stamps crosses the C ABI, the
/// alias wrapper derives one hidden rule from it, a pasted
/// `{endpoint}/acme/demo/…` address reaches paths-info and projects back in
/// the caller's spelling — `?revision=` pin included — and the rule is
/// withdrawn with the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hub_url_spelling_resolves_through_the_alias_layer() {
    let Some(so) = staged_hf_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_hub();
    let stack = hf_stack(&so, &["alias", "redirect_follower", "retry"]).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "huggingface".into(),
            connection: hf_connection_request(&endpoint, SecretBundle::default()),
        }),
        None,
    )
    .await
    .expect("anonymous huggingface connection under the alias root");
    let spelling = format!("{endpoint}/acme/demo/");
    assert_eq!(
        connection
            .user_metadata
            .get(ACCEPTED_URL_SPELLINGS_METADATA_KEY)
            .map(String::as_str),
        Some(spelling.as_str()),
        "the row the cdylib returns carries the spellings contract across the ABI"
    );

    // The pasted spelling resolves through the derived rule to the plugin and
    // the result comes back in the caller's own spelling.
    let pasted = Url::parse(&format!("{endpoint}/acme/demo/weights/model.bin")).unwrap();
    let info = stack
        .stat(pasted.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the generated alias");
    assert_eq!(info.size, Some(LFS_BODY.len() as u64));
    assert_eq!(
        info.address, pasted,
        "results project back to the caller's own spelling"
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("POST /api/models/acme/demo/paths-info/main")),
        "the aliased stat reached paths-info at the default revision"
    );

    // The `?revision=` pin is a carried selector: it rides through the
    // generated rule and comes back on the projected address.
    let pinned = Url::parse(&format!(
        "{endpoint}/acme/demo/weights/model.bin?revision=main"
    ))
    .unwrap();
    let info = stack
        .stat(pinned.clone(), StatOptions::default(), None)
        .await
        .expect("pinned stat through the generated alias");
    assert_eq!(info.address, pinned);

    // The canonical form is untouched by the generated rule.
    let canonical = Url::parse("hf://models/acme/demo/weights/model.bin").unwrap();
    let info = stack
        .stat(canonical.clone(), StatOptions::default(), None)
        .await
        .expect("canonical stat");
    assert_eq!(info.address, canonical);

    // One derived row per spelling, marked with its provenance and rewriting
    // onto the canonical root.
    let (connections, _) = ovstorage::Layer::list_connections(&*stack, &Extensions::new(), None)
        .await
        .unwrap();
    let derived: Vec<_> = connections
        .connections
        .iter()
        .filter(|row| {
            row.user_metadata
                .contains_key(ALIAS_DERIVED_FROM_METADATA_KEY)
        })
        .collect();
    assert_eq!(
        derived.len(),
        1,
        "one derived rule per spelling: {:?}",
        connections.connections
    );
    assert_eq!(derived[0].current_addresses[0].as_str(), spelling);

    // Hidden: retained in the root snapshot as addressable but unlisted, so a
    // root browser keeps showing the canonical form only.
    let (roots, _) = ovstorage::Layer::list_address_roots(&*stack, &Extensions::new(), None)
        .await
        .unwrap();
    let visible: Vec<&str> = roots
        .roots
        .iter()
        .filter(|root| root.visible)
        .map(|root| root.root.as_str())
        .collect();
    assert_eq!(
        visible,
        vec!["hf://models/acme/demo/"],
        "listings keep showing the canonical form only"
    );
    let alias_root = roots
        .roots
        .iter()
        .find(|root| root.root.as_str() == spelling)
        .expect("the derived alias root is retained (addressable), just unlisted");
    assert_eq!(alias_root.visibility, AddressVisibility::Hidden);
    assert!(!alias_root.visible);
    assert_eq!(alias_root.alias_state, Some(AliasState::Live));

    // A model configured in a reserved Hub namespace registers (the plugin
    // validates syntax, not existence) but derives no rule: the dataset URL
    // space under that prefix is captured by nothing and stays `NoRoute`.
    ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "huggingface".into(),
            connection: hf_connection_request_for(
                "datasets/acme",
                &endpoint,
                SecretBundle::default(),
            ),
        }),
        None,
    )
    .await
    .expect("a model in a reserved namespace still registers on its hf:// root");
    let (connections, _) = ovstorage::Layer::list_connections(&*stack, &Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(
        connections
            .connections
            .iter()
            .filter(|row| row
                .user_metadata
                .contains_key(ALIAS_DERIVED_FROM_METADATA_KEY))
            .count(),
        1,
        "the reserved-namespace model derives no rule: {:?}",
        connections.connections
    );
    let err = stack
        .stat(
            Url::parse(&format!("{endpoint}/datasets/acme/other/data.csv")).unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a dataset URL under the reserved prefix is captured by nothing");
    assert!(
        matches!(err.code(), ErrorCode::NoRoute | ErrorCode::NotConfigured),
        "expected NoRoute/NotConfigured, got {:?}",
        err.code()
    );

    // A Hub web-view URL is not unwrapped: `blob/main/config.json` is read
    // as an in-repository path, paths-info answers an empty array for it,
    // and the plugin reports `NotFound` rather than a different file.
    let err = stack
        .stat(
            Url::parse(&format!("{endpoint}/acme/demo/blob/main/config.json")).unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a web-view path is read as an in-repository path");
    assert_eq!(err.code(), ErrorCode::NotFound);

    // The repository id is matched as configured; only the host is
    // case-folded, so a case-mismatched paste selects no rule.
    let err = stack
        .stat(
            Url::parse(&format!("{endpoint}/Acme/Demo/weights/model.bin")).unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a case-mismatched repository id selects no rule");
    assert!(
        matches!(err.code(), ErrorCode::NoRoute | ErrorCode::NotConfigured),
        "expected NoRoute/NotConfigured, got {:?}",
        err.code()
    );

    // Withdrawn with the connection: the spelling stops routing.
    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "huggingface".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .expect("remove huggingface connection");
    let err = stack
        .stat(pasted, StatOptions::default(), None)
        .await
        .expect_err("the spelling stops routing with its connection");
    assert!(
        matches!(err.code(), ErrorCode::NoRoute | ErrorCode::NotConfigured),
        "expected NoRoute/NotConfigured, got {:?}",
        err.code()
    );
    // ...because the RULE is gone, not merely the connection behind it: no
    // derived row remains and the spelling root left the snapshot.
    let (connections, _) = ovstorage::Layer::list_connections(&*stack, &Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        connections.connections.iter().all(|row| !row
            .user_metadata
            .contains_key(ALIAS_DERIVED_FROM_METADATA_KEY)),
        "the derived rule is withdrawn with its connection: {:?}",
        connections.connections
    );
    let (roots, _) = ovstorage::Layer::list_address_roots(&*stack, &Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        roots
            .roots
            .iter()
            .all(|root| root.root.as_str() != spelling),
        "the derived alias root is withdrawn from the snapshot: {:?}",
        roots
            .roots
            .iter()
            .map(|root| root.root.as_str())
            .collect::<Vec<_>>()
    );
}
