// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! LFS read contract: `resolve` answers a 302 to an off-origin signed CDN URL,
//! and the plugin FOLLOWS it in-process (it does not delegate a
//! `ReadRedirect`), streaming the CDN bytes while reporting the canonical LFS
//! identity — the `x-linked-etag` sha256 from the 302, not the CDN's own tag —
//! so a followed read agrees with `stat`. Off-origin targets are
//! scheme-restricted: `https` (and the loopback-`http` test seam) are
//! followed; `file://` and cleartext to non-loopback hosts are refused.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::ext::LayerExt as _;
use ovstorage::layers::REDIRECT_FOLLOWER_KIND;
use ovstorage::{LayerSpec, Stack};
use ovstorage_plugin::{
    BackendFactory, ChecksumAlgorithm, ConfigValue, ConnectionRequest, ErrorCode, LayerConfig,
    LayerConnectionRequest, LayerHandle, ObjectKind, ReadOptions, ReadRequest, ReadResult, Request,
    SecretBundle, SecretBytes, SecretValue, address,
};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;
use ovstorage_plugin_huggingface::HfLayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

const LFS_SHA256: &str = "b43f4c2ea569da1d66ca74e26ca8ea4430dfc29195e97144b2d0b4f3f6cafa1c";

async fn connected_layer(endpoint: &str, credentials: SecretBundle) -> LayerHandle {
    let layer = HfLayerFactory::default()
        .create_backend("huggingface", &LayerConfig::new(), None)
        .await
        .unwrap();
    let mut config = HashMap::new();
    config.insert(
        "repo_id".to_string(),
        ConfigValue::String("acme/demo".into()),
    );
    config.insert("endpoint".to_string(), ConfigValue::String(endpoint.into()));
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "huggingface".into(),
                connection: ConnectionRequest {
                    backend_kind: "huggingface".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .unwrap();
    layer
}

fn hub_302(cdn_url: &str) -> CannedHttpResponse {
    CannedHttpResponse::new("302 Found", "")
        .with_header("Location", cdn_url)
        .with_header("x-linked-etag", format!("\"{LFS_SHA256}\""))
        .with_header("x-linked-size", "11")
        .with_header("x-repo-commit", "deadbeef")
}

fn token_bundle(token: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "token".into(),
        SecretValue::Bytes(SecretBytes(token.as_bytes().to_vec())),
    );
    bundle
}

async fn drain(result: ReadResult) -> (Vec<u8>, ovstorage_plugin::ObjectInfo) {
    use futures::StreamExt;
    match result {
        ReadResult::Stream { mut stream, info } => {
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            (bytes, info)
        }
        ReadResult::Bytes { bytes, info } => (bytes, info),
        other => panic!("expected streamed/buffered bytes, got {other:?}"),
    }
}

/// The off-origin CDN 302 is followed in-plugin; the streamed bytes come from
/// the CDN while the reported identity is the linked LFS sha256 from the 302,
/// so a followed read reports the same etag `stat` does.
#[tokio::test]
async fn lfs_302_is_followed_with_the_linked_identity() {
    let cdn = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "lfs payload").with_header("ETag", "\"cdn-side-tag\""),
    );
    let cdn_url = format!("{}/repos/ab/cd/blob", cdn.endpoint());
    let hub = ScriptedHttpServer::spawn(hub_302(&cdn_url));
    let layer = connected_layer(hub.endpoint(), SecretBundle::default()).await;
    let (bytes, info) = drain(
        layer
            .read(
                Request::new(ReadRequest {
                    address: address::parse("hf://models/acme/demo/weights/model.bin").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(bytes, b"lfs payload");
    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(
        info.etag.as_deref(),
        Some(LFS_SHA256),
        "the read reports the canonical LFS sha256, not the CDN's own tag"
    );
    assert_eq!(info.size, Some(11), "size is the linked size");
    assert_eq!(info.version.as_deref(), Some("deadbeef"));
    assert_eq!(
        info.checksums
            .get(&ChecksumAlgorithm::sha256())
            .unwrap()
            .len(),
        32,
        "the sha256 checksum is carried"
    );
    assert_eq!(hub.hits(), 1, "one resolve GET");
    assert_eq!(cdn.hits(), 1, "the CDN is fetched once, in-plugin");
}

/// A tokened connection sends its bearer to the hub, and only there: the
/// off-origin CDN hop carries no authorization header.
#[tokio::test]
async fn a_tokened_read_does_not_leak_the_bearer_to_the_cdn() {
    let cdn = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "lfs payload"));
    let cdn_url = format!("{}/repos/ab/cd/blob", cdn.endpoint());
    let hub = ScriptedHttpServer::spawn_sequence(vec![
        Some(CannedHttpResponse::json("200 OK", r#"{"name":"tester"}"#)),
        Some(hub_302(&cdn_url)),
    ]);
    let layer = connected_layer(hub.endpoint(), token_bundle("hf_secret")).await;
    let _ = drain(
        layer
            .read(
                Request::new(ReadRequest {
                    address: address::parse("hf://models/acme/demo/weights/model.bin").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap(),
    )
    .await;
    let hub_requests = hub.requests();
    assert!(
        request_has_header(&hub_requests[1], "authorization", "Bearer hf_secret"),
        "the resolve GET carries the bearer: {}",
        hub_requests[1]
    );
    let cdn_requests = cdn.requests();
    assert!(
        !cdn_requests[0].to_lowercase().contains("authorization"),
        "the off-origin CDN hop carries no bearer: {}",
        cdn_requests[0]
    );
}

/// `if_match` settles against the 302's linked identity before the CDN is
/// touched: a mismatch surfaces `ObjectModified` and never fetches bytes.
#[tokio::test]
async fn if_match_mismatch_settles_against_the_linked_etag() {
    let cdn = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "lfs payload"));
    let cdn_url = format!("{}/repos/ab/cd/blob", cdn.endpoint());
    let hub = ScriptedHttpServer::spawn(hub_302(&cdn_url));
    let layer = connected_layer(hub.endpoint(), SecretBundle::default()).await;
    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("hf://models/acme/demo/weights/model.bin").unwrap(),
                options: ReadOptions {
                    if_match: Some("some-older-etag".into()),
                    ..ReadOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ObjectModified);
    assert_eq!(cdn.hits(), 0, "a precondition failure never fetches bytes");
}

/// A `file://` redirect target is refused rather than followed — the host's
/// follower would otherwise open it off disk, and even following in-plugin we
/// never fetch a non-CDN scheme.
#[tokio::test]
async fn a_file_scheme_redirect_is_refused() {
    let hub = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("302 Found", "").with_header("Location", "file:///etc/passwd"),
    );
    let layer = connected_layer(hub.endpoint(), SecretBundle::default()).await;
    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("hf://models/acme/demo/weights/model.bin").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

/// A cleartext redirect to a non-loopback (link-local/internal) host is
/// refused, closing the SSRF path.
#[tokio::test]
async fn a_non_loopback_http_redirect_is_refused() {
    let hub = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("302 Found", "")
            .with_header("Location", "http://169.254.169.254/latest/meta-data"),
    );
    let layer = connected_layer(hub.endpoint(), SecretBundle::default()).await;
    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("hf://models/acme/demo/weights/model.bin").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

/// End to end through a production `Stack` with the redirect follower
/// composed: the plugin follows the LFS 302 itself, so the follower is a
/// pass-through and `read_bytes` returns the CDN bytes with the linked etag.
#[tokio::test]
async fn stack_reads_an_lfs_object_end_to_end() {
    let expected = b"lfs bytes from the cdn".to_vec();
    let cdn = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "lfs bytes from the cdn")
            .with_header("ETag", "\"cdn-side-tag\""),
    );
    let cdn_url = format!("{}/repos/ab/cd/blob", cdn.endpoint());
    let hub = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("302 Found", "")
            .with_header("Location", &cdn_url)
            .with_header("x-linked-etag", format!("\"{LFS_SHA256}\""))
            .with_header("x-linked-size", format!("{}", expected.len())),
    );

    let mut config = HashMap::new();
    config.insert(
        "repo_id".to_string(),
        ConfigValue::String("acme/demo".into()),
    );
    config.insert(
        "endpoint".to_string(),
        ConfigValue::String(hub.endpoint().into()),
    );
    let stack = Stack::builder("redirect_follower")
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .backend_factory(Arc::new(HfLayerFactory::default()))
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            REDIRECT_FOLLOWER_KIND,
            "huggingface",
        ))
        .layer(LayerSpec::backend("huggingface", "huggingface"))
        .connection(LayerConnectionRequest {
            target: "huggingface".into(),
            connection: ConnectionRequest {
                backend_kind: "huggingface".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
        .build()
        .await
        .expect("build production Stack over the huggingface layer");

    let object = address::parse("hf://models/acme/demo/weights/model.bin").unwrap();
    let (actual, info) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("read the LFS object through the Stack");
    assert_eq!(actual, expected);
    assert_eq!(
        info.etag.as_deref(),
        Some(LFS_SHA256),
        "the end-to-end read reports the canonical LFS identity"
    );
    assert_eq!(info.size, Some(expected.len() as u64));
    assert_eq!(hub.hits(), 1);
    assert_eq!(cdn.hits(), 1);
}
