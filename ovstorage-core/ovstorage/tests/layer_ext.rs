// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `LayerExt` ergonomic extension trait gives any
//! `Layer`/`Stack` ergonomic Url+Options verbs. This exercises the blanket impl
//! directly over a minimal file
//! `Stack` (the same composition pattern as `default_stack.rs`).

use std::collections::HashMap;

use ovstorage::layers::{FILE_BACKEND_KIND, register_default_layer_factories};
use ovstorage::{
    Body, ConfigValue, ConnectionRequest, CreateDirectoryOptions, DeleteOptions,
    LayerConnectionRequest, LayerSpec, ReadOptions, SecretBundle, Stack, StatOptions, Url,
    WriteOptions,
};
use ovstorage_plugin_core::{AliasWrapperFactory, RetryWrapperFactory, RouterFactoryImpl};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;
// The extension trait under test.
use ovstorage::ext::LayerExt;

/// Compose the default wrapper chain over a `file` backend with one
/// connected root, mirroring `tests/default_stack.rs`.
async fn build_file_stack(root: &Url) -> Stack {
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let mut builder = register_default_layer_factories(Stack::builder("alias"))
        .router_factory(std::sync::Arc::new(RouterFactoryImpl))
        .wrapper_factory(std::sync::Arc::new(AliasWrapperFactory::default()))
        .wrapper_factory(std::sync::Arc::new(RetryWrapperFactory))
        .wrapper_factory(std::sync::Arc::new(RedirectFollowerWrapperFactory));
    for spec in [
        LayerSpec::wrapper("alias", "alias", "redirect_follower"),
        LayerSpec::wrapper("redirect_follower", "redirect_follower", "retry"),
        LayerSpec::wrapper("retry", "retry", "router"),
        LayerSpec::router("router", "router", vec!["files".into()]),
    ] {
        builder = builder.layer(spec);
    }
    builder
        .layer(LayerSpec::backend("files", FILE_BACKEND_KIND))
        .connection(LayerConnectionRequest {
            target: "files".into(),
            connection: ConnectionRequest {
                backend_kind: FILE_BACKEND_KIND.into(),
                config: HashMap::from([("root".into(), ConfigValue::String(root.to_string()))]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("workspace".into()),
            },
        })
        .build()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer_ext_write_read_stat_roundtrip_over_a_stack() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let stack = build_file_stack(&root).await;
    let url = root.join("obj.txt").unwrap();

    stack
        .write(
            url.clone(),
            Body::Bytes(b"ext".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let (bytes, info) = stack
        .read_bytes(url.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"ext");
    assert_eq!(info.size, Some(3));

    let stat = stack.stat(url, StatOptions::default(), None).await.unwrap();
    assert_eq!(stat.size, Some(3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer_ext_read_enforces_max_bytes_cap() {
    // A13: `max_bytes` is the security-relevant read cap (MCP `ovstorage_read`
    // always passes `Some(params.max_bytes)`). Exercise the cap on both buffered
    // (`read_bytes`) and streamed
    // (`read_stream`) paths over a real file `Stack`: an object larger than the
    // cap must be refused with `ResourceExhausted`, and an uncapped read of the
    // same object must still return every byte (so the cap — not some unrelated
    // read failure — is what rejected the capped read).
    use futures::StreamExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let stack = build_file_stack(&root).await;
    let url = root.join("big.bin").unwrap();

    let payload = vec![b'x'; 4096];
    stack
        .write(
            url.clone(),
            Body::Bytes(payload.clone()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let capped = ReadOptions {
        max_bytes: Some(16),
        ..Default::default()
    };

    // read_bytes: the cap is enforced eagerly once the object is buffered.
    let err = stack
        .read_bytes(url.clone(), capped.clone(), None)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        ovstorage::ErrorCode::ResourceExhausted,
        "read_bytes must enforce max_bytes: {err:?}"
    );

    // read_stream: the cap is enforced lazily while draining chunks — the stream
    // yields an error item once the running total exceeds the cap.
    let (mut stream, _info) = stack.read_stream(url.clone(), capped, None).await.unwrap();
    let mut delivered = 0usize;
    let mut hit_cap = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => delivered += bytes.len(),
            Err(err) => {
                assert_eq!(
                    err.code(),
                    ovstorage::ErrorCode::ResourceExhausted,
                    "read_stream cap error must be ResourceExhausted: {err:?}"
                );
                hit_cap = true;
                break;
            }
        }
    }
    assert!(
        hit_cap,
        "read_stream must surface ResourceExhausted once the cap is exceeded \
         (delivered {delivered} bytes before the cap fired)"
    );
    assert!(
        delivered as u64 <= 16,
        "read_stream must not deliver past the cap, delivered {delivered}"
    );

    // Negative control: without a cap the same object reads back in full, proving
    // the errors above are the cap and not a corrupt/unreadable object.
    let (bytes, info) = stack
        .read_bytes(url, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes.len(), payload.len());
    assert_eq!(info.size, Some(payload.len() as u64));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn layer_ext_read_stream_and_directory_and_catalog() {
    use futures::StreamExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let stack = build_file_stack(&root).await;

    // create_directory re-stamps the caller-facing address.
    let dir = root.join("sub/").unwrap();
    let dir_info = stack
        .create_directory(dir.clone(), CreateDirectoryOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(dir_info.address, dir);

    let obj = dir.join("s.txt").unwrap();
    stack
        .write(
            obj.clone(),
            Body::Bytes(b"stream-me".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    // read_stream adapts the backend LocalDelegate to a byte stream.
    let (mut stream, info) = stack
        .read_stream(obj.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(info.size, Some(9));
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(out, b"stream-me");

    // list_page returns the object under the directory prefix.
    let page = stack
        .list_page(dir.clone(), ovstorage::ListOptions::default(), None)
        .await
        .unwrap();
    assert!(page.items.iter().any(|i| i.address == obj));

    // Catalog adapters: the file root is discoverable and `file` is a backend kind.
    let roots = stack.list_address_roots(None).await.unwrap();
    assert!(roots.iter().any(|r| r.root == root));
    let kinds = stack.list_backend_kinds().unwrap();
    assert!(kinds.iter().any(|k| k.kind == FILE_BACKEND_KIND));
    let caps = stack.capabilities_for(&root, None).await.unwrap();
    assert!(caps.supports_write);

    // delete removes the object.
    stack
        .delete(obj.clone(), DeleteOptions::default(), None)
        .await
        .unwrap();
    let err = stack
        .stat(obj, StatOptions::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ovstorage::ErrorCode::NotFound);
}
