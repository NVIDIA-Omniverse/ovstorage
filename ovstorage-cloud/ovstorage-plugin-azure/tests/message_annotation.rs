// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The per-operation `message` annotation reaches Azure as blob user metadata,
//! and the wire spelling of its key decides whether the service accepts the
//! write at all.

use std::collections::HashMap;

use ovstorage_plugin::{
    BackendFactory, Body, ConfigValue, ConnectionRequest, LayerConfig, LayerConnectionRequest,
    LayerHandle, Request, WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_azure::AzureLayerFactory;

mod support;
use support::spawn_capture_server_serving_verify;

async fn layer_for(endpoint: &str) -> LayerHandle {
    let layer = AzureLayerFactory::default()
        .create_backend("azure", &LayerConfig::new(), None)
        .await
        .expect("azure layer");
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String("acct".into()));
    config.insert("container".into(), ConfigValue::String("container".into()));
    config.insert(
        "__test_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: ConnectionRequest {
                    backend_kind: "azure".into(),
                    config,
                    credentials: support::shared_key_bundle(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add_connection");
    layer
}

/// A buffered write carrying a message stashes it as the `x_ov_message`
/// metadata entry on the `Put Blob` request.
///
/// The header name is a literal rather than derived from
/// `MESSAGE_METADATA_KEY`: Azure metadata names are C# identifiers, so a
/// hyphen anywhere in the key fails the write on the real service with
/// `400 InvalidMetadata`, while the capture server here accepts any header
/// name. Only the exact wire spelling catches the constant drifting out of the
/// portable `[a-z_][a-z0-9_]*` set.
#[tokio::test]
async fn buffered_write_stashes_the_message_under_a_portable_metadata_name() {
    let (endpoint, capture, _counter) = spawn_capture_server_serving_verify();
    let layer = layer_for(&endpoint).await;

    layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("azure://acct/container/annotated.txt").unwrap(),
                body: Body::Bytes(b"hello".to_vec()),
                options: WriteOptions {
                    message: Some("commit note".into()),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("a buffered write carrying a message commits");

    let put = capture.expect_one("PUT");
    assert_eq!(
        put.header_value("x-ms-meta-x_ov_message").as_deref(),
        Some("commit note"),
        "Put Blob must carry the message under the portable key; got:\n{}",
        put.raw
    );
}

/// A caller's own `x_ov_message` entry stands on the `Put Blob` request: user
/// metadata is persisted, the per-operation message is droppable by contract.
#[tokio::test]
async fn buffered_write_keeps_the_callers_entry_under_the_message_key() {
    let (endpoint, capture, _counter) = spawn_capture_server_serving_verify();
    let layer = layer_for(&endpoint).await;

    let mut user_metadata = HashMap::new();
    user_metadata.insert("x_ov_message".to_string(), "caller".to_string());
    layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("azure://acct/container/annotated.txt").unwrap(),
                body: Body::Bytes(b"hello".to_vec()),
                options: WriteOptions {
                    user_metadata: Some(user_metadata),
                    message: Some("real".into()),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("a buffered write carrying both a message and the caller's entry commits");

    let put = capture.expect_one("PUT");
    assert_eq!(
        put.header_value("x-ms-meta-x_ov_message").as_deref(),
        Some("caller"),
        "Put Blob must carry the caller's value under the key, not the message; got:\n{}",
        put.raw
    );
    assert!(
        !put.raw
            .to_ascii_lowercase()
            .contains("x-ms-meta-x_ov_message: real"),
        "the message must not reach the wire beside the caller's entry; got:\n{}",
        put.raw
    );
}

/// Azure compares metadata names case-insensitively and the HTTP client
/// lower-cases header names on the wire, so a caller's `X_OV_MESSAGE` entry is
/// the same header as the message's `x_ov_message`. The caller's stands, and
/// the `Put Blob` request carries that one header only.
#[tokio::test]
async fn buffered_write_keeps_a_differently_cased_caller_entry_under_the_message_key() {
    let (endpoint, capture, _counter) = spawn_capture_server_serving_verify();
    let layer = layer_for(&endpoint).await;

    let mut user_metadata = HashMap::new();
    user_metadata.insert("X_OV_MESSAGE".to_string(), "caller".to_string());
    layer
        .write(
            Request::new(WriteRequest {
                address: address::parse("azure://acct/container/annotated.txt").unwrap(),
                body: Body::Bytes(b"hello".to_vec()),
                options: WriteOptions {
                    user_metadata: Some(user_metadata),
                    message: Some("real".into()),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("a buffered write carrying both a message and an upper-cased caller entry commits");

    let put = capture.expect_one("PUT");
    let header_count = put
        .raw
        .to_ascii_lowercase()
        .matches("\r\nx-ms-meta-x_ov_message: ")
        .count();
    assert_eq!(
        header_count, 1,
        "Put Blob must carry the key once, whatever the caller's case; got:\n{}",
        put.raw
    );
    assert_eq!(
        put.header_value("x-ms-meta-x_ov_message").as_deref(),
        Some("caller"),
        "Put Blob must carry the caller's value under the key, not the message; got:\n{}",
        put.raw
    );
}
