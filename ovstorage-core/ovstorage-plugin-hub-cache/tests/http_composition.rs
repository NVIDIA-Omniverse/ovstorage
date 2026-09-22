// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `hub_cache` layer over the real HTTP backend: the one composition
//! where omni.client's digest-tier key is reachable end to end. An
//! anonymous origin that sends `Content-MD5` must produce a fill under
//! exactly the key omni.client derives from that header — through the HTTP
//! plugin's actual metadata path, not an injected checksum.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use futures::StreamExt as _;
use md5::{Digest as _, Md5};
use ovstorage_hub_client::fake::{EntryState, FakeHub};
use ovstorage_hub_client::{KeyScheme, hub_key};
use ovstorage_plugin::*;
use ovstorage_plugin_http::HttpBackendLayerFactory;
use ovstorage_plugin_hub_cache::HubCacheWrapperFactory;

const CONTENT: &[u8] = b"the cached body over http";
const ETAG: &str = "abc123";

/// Serves `CONTENT` under any path: HEAD and GET both carry `ETag`,
/// `Content-Length` and `Content-MD5`, exactly as a plain origin would.
/// One connection per request (`Connection: close`), accepted until the
/// test process ends.
fn spawn_origin() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::Builder::new()
        .name("hub-cache-http-origin".into())
        .spawn(move || {
            let content_md5 = content_md5_header_value();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = [0_u8; 2048];
                let Ok(len) = stream.read(&mut request) else {
                    continue;
                };
                let request = String::from_utf8_lossy(&request[..len]);
                let head = request.starts_with("HEAD ");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"{ETAG}\"\r\n\
                     Content-MD5: {content_md5}\r\nConnection: close\r\n\r\n",
                    CONTENT.len()
                );
                let _ = stream.write_all(response.as_bytes());
                if !head {
                    let _ = stream.write_all(CONTENT);
                }
            }
        })
        .expect("spawn origin thread");
    port
}

/// The `Content-MD5` value for [`CONTENT`], spelled through the compat key
/// derivation so the test does not restate the base64 encoding: the key is
/// `md5;<Content-MD5>`, so the header is the key minus its prefix.
fn content_md5_header_value() -> String {
    expected_digest_key("http://irrelevant/object")
        .strip_prefix("md5;")
        .expect("a digest key is md5;-prefixed")
        .to_string()
}

fn expected_digest_key(url: &str) -> String {
    let digest = Md5::digest(CONTENT);
    hub_key(
        KeyScheme::OmniClientCompat,
        "local",
        &Url::parse(url).expect("test URL parses"),
        ETAG,
        Some(&digest),
    )
    .expect("a digest keys")
    .key
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_origin_with_content_md5_fills_under_omni_clients_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hub = FakeHub::start(dir.path().to_path_buf()).await;
    let port = spawn_origin();

    let mut http_config = LayerConfig::new();
    http_config.insert(
        "root_url".to_string(),
        ConfigValue::String(format!("http://127.0.0.1:{port}/")),
    );
    let origin = HttpBackendLayerFactory::default()
        .create_backend("origin", &http_config, None)
        .await
        .expect("the http backend builds");

    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(hub.endpoint()));
    config.insert(
        "key_scheme".to_string(),
        ConfigValue::String("omni-client-compat".to_string()),
    );
    let wrapper = HubCacheWrapperFactory
        .create_wrapper("hub-cache", &config, origin, None)
        .await
        .expect("the wrapper builds");

    let address = format!("http://127.0.0.1:{port}/assets/scene.usd");
    let request = Request::new(ReadRequest {
        address: Url::parse(&address).expect("address parses"),
        options: ReadOptions::default(),
    });
    let result = wrapper.read(request, None).await.expect("the read answers");
    let mut body = Vec::new();
    match result {
        ReadResult::Bytes { bytes, .. } => body = bytes,
        ReadResult::Stream { mut stream, .. } => {
            while let Some(chunk) = stream.next().await {
                body.extend_from_slice(&chunk.expect("stream chunk"));
            }
        }
        ReadResult::LocalDelegate(local) => {
            body = tokio::fs::read(&local.path).await.expect("delegate reads");
        }
        other => panic!("unexpected read result: {other:?}"),
    }
    assert_eq!(body, CONTENT);

    // The fill landed under the key omni.client derives for this object —
    // `md5;` + the origin's own Content-MD5 header — proving the HTTP
    // metadata path and the digest tier meet on one entry.
    let key = expected_digest_key(&address);
    hub.wait_for("the digest-tier fill commits", |hub| {
        matches!(hub.entry(&key), Some(EntryState::Committed { .. }))
    })
    .await;
    assert_eq!(hub.committed_bytes(&key).as_deref(), Some(CONTENT));
    hub.wait_for_open_handles(0).await;
}
