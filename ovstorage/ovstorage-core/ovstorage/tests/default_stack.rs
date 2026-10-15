// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An explicitly registered plugin wrapper chain must round-trip data end-to-end. This composes
//! `alias → redirect_follower → retry → router →
//! FileBackend` and writes + reads a file through it, asserting the wrappers
//! pass through transparently when unconfigured.

use std::collections::HashMap;

use futures::StreamExt as _;

use ovstorage::layers::{FILE_BACKEND_KIND, register_default_layer_factories};
use ovstorage::{
    Body, ConfigValue, ConnectionRequest, Layer, LayerConnectionRequest, LayerSpec, ReadOptions,
    ReadRequest, ReadResult, Request, SecretBundle, Stack, Url, WriteOptions, WriteRequest,
};
use ovstorage_plugin_core::{AliasWrapperFactory, RetryWrapperFactory, RouterFactoryImpl};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

fn public_chain(children: Vec<String>) -> Vec<LayerSpec> {
    vec![
        LayerSpec::wrapper("alias", "alias", "redirect_follower"),
        LayerSpec::wrapper("redirect_follower", "redirect_follower", "retry"),
        LayerSpec::wrapper("retry", "retry", "router"),
        LayerSpec::router("router", "router", children),
    ]
}

fn register_public_factories(builder: ovstorage::StackBuilder) -> ovstorage::StackBuilder {
    register_default_layer_factories(builder)
        .router_factory(std::sync::Arc::new(RouterFactoryImpl))
        .wrapper_factory(std::sync::Arc::new(AliasWrapperFactory::default()))
        .wrapper_factory(std::sync::Arc::new(RetryWrapperFactory))
        .wrapper_factory(std::sync::Arc::new(RedirectFollowerWrapperFactory))
}

/// Buffer a `ReadResult`'s content: the file backend returns a
/// `LocalDelegate` for whole-object reads.
async fn buffer_read(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Bytes { bytes, .. } => bytes,
        ReadResult::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.unwrap());
            }
            out
        }
        ReadResult::LocalDelegate(local) => tokio::fs::read(&local.path).await.unwrap(),
        other => panic!("unexpected read result: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_wrapper_chain_round_trips_file() {
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let file = root.join("hello.txt").unwrap();

    // Compose the default wrapper chain over a file backend, register
    // the default factories, attach the file connection, and build.
    let mut builder = register_public_factories(Stack::builder("alias"));
    for spec in public_chain(vec!["files".into()]) {
        builder = builder.layer(spec);
    }
    let stack = builder
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
        .unwrap();

    // Write then read through the whole chain — the unconfigured alias /
    // address-canon / redirect-follower / retry wrappers all pass through.
    stack
        .write(
            Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"default-stack".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let result = stack
        .read(
            Request::new(ReadRequest {
                address: file.clone(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let bytes = buffer_read(result).await;
    assert_eq!(bytes, b"default-stack");

    // The file root is discoverable through the chain.
    let roots = stack
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap()
        .0
        .roots;
    assert!(roots.iter().any(|r| r.root == root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicitly_registered_plugins_compose_from_connections() {
    let _ = ovstorage::init_auth_substrate(None);
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let file = root.join("obj.txt").unwrap();

    // From loaded factories (none here) and connections, build the
    // default-wrapper-chain Stack with one backend
    // Layer per kind.
    let mut builder = register_public_factories(Stack::builder("alias"));
    for spec in public_chain(vec!["file".into()]) {
        builder = builder.layer(spec);
    }
    let stack = builder
        .layer(LayerSpec::backend("file", FILE_BACKEND_KIND))
        .connection(LayerConnectionRequest {
            target: "file".into(),
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
        .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"composed".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let result = stack
        .read(
            Request::new(ReadRequest {
                address: file,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let bytes = buffer_read(result).await;
    assert_eq!(bytes, b"composed");
}
