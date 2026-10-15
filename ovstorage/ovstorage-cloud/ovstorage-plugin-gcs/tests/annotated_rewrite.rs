// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire pin for a `copy` that carries a message: the rewrite body the plugin
//! sends carries the source object's editable metadata beside the annotation.
//!
//! A non-empty `objects.rewrite` body replaces the destination's editable
//! metadata wholesale, while an empty one makes GCS copy the source's. The
//! plugin therefore reads the source first and sends its content type,
//! encoding, language, disposition, cache control, custom time, storage class
//! and user metadata together with the annotation. Without that, an annotated
//! copy would strip every one of those fields from the destination while the
//! identical copy without a message kept them. The read and the rewrite are
//! two calls, so the rewrite is pinned to the generation the read returned
//! unless the caller pinned one: a source overwritten in between cannot have
//! its new bytes stamped with the metadata of the old generation.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage_plugin::{
    BackendId, ConfigValue, ConnectionRequest, CopyOptions, MESSAGE_METADATA_KEY, ResolvedTarget,
    SecretBundle, address,
};
use ovstorage_plugin_gcs::GcsBackend;
use ovstorage_plugin_test::scripted_http::{CannedHttpResponse, ScriptedHttpServer};

async fn anonymous_backend(endpoint: &str, bucket: &str) -> Arc<GcsBackend> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let config =
        ovstorage_plugin_gcs::__test_only_parse_config(&request.config).expect("parse config");
    Arc::new(
        ovstorage_plugin_gcs::__test_only_backend(config, request.credentials)
            .expect("build backend"),
    )
}

fn target(bucket: &str, key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("gcs:gs://{bucket}/")),
        resolved_address: address::parse(&format!("gs://{bucket}/{key}")).unwrap(),
    }
}

const SOURCE: &str = r#"{"bucket":"bkt","name":"src.bin","generation":"7","metageneration":"3","size":"5","updated":"2026-01-01T00:00:00Z","md5Hash":"AAA=","contentType":"text/plain","contentEncoding":"gzip","contentLanguage":"en","contentDisposition":"inline","cacheControl":"no-store","customTime":"2026-01-02T03:04:05Z","storageClass":"NEARLINE","temporaryHold":true,"metadata":{"author":"caller"}}"#;

const REWRITE_DONE: &str = r#"{"done":true,"resource":{"bucket":"bkt","name":"dst.bin","generation":"100","metageneration":"1","size":"5","updated":"2026-01-01T00:00:00Z","md5Hash":"AAA="}}"#;

fn body_of(raw: &str) -> serde_json::Value {
    let (_, body) = raw
        .split_once("\r\n\r\n")
        .expect("an HTTP request with a body separator");
    serde_json::from_str(body).unwrap_or_else(|err| panic!("JSON body: {err}; raw:\n{raw}"))
}

/// The rewrite body of an annotated copy carries the source's editable
/// fields and its user metadata beside the annotation.
#[tokio::test]
async fn an_annotated_copy_sends_the_sources_editable_metadata_with_the_annotation() {
    let server = ScriptedHttpServer::spawn_sequence(vec![
        Some(CannedHttpResponse::json("200 OK", SOURCE)),
        Some(CannedHttpResponse::json("200 OK", REWRITE_DONE)),
    ]);
    let backend = anonymous_backend(server.endpoint(), "bkt").await;

    backend
        .copy(
            target("bkt", "src.bin"),
            target("bkt", "dst.bin"),
            CopyOptions {
                message: Some("copy note".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("annotated copy");

    let requests = server.requests();
    let read = requests
        .iter()
        .find(|raw| raw.starts_with("GET "))
        .expect("the plugin reads the source object first");
    assert!(
        read.lines()
            .next()
            .unwrap_or("")
            .contains("/storage/v1/b/bkt/o/src.bin?"),
        "the read targets the source object; request line:\n{}",
        read.lines().next().unwrap_or("")
    );
    let rewrite = requests
        .iter()
        .find(|raw| raw.starts_with("POST "))
        .expect("a POST for rewriteTo");
    let request_line = rewrite.lines().next().unwrap_or("");
    assert!(
        request_line.contains("sourceGeneration=7"),
        "the rewrite is pinned to the generation the read returned; request line:\n{request_line}"
    );
    let body = body_of(rewrite);
    let fields = body.as_object().expect("a JSON object body");
    assert_eq!(fields["contentType"], "text/plain", "body:\n{body:#}");
    assert_eq!(fields["contentEncoding"], "gzip", "body:\n{body:#}");
    assert_eq!(fields["contentLanguage"], "en", "body:\n{body:#}");
    assert_eq!(fields["contentDisposition"], "inline", "body:\n{body:#}");
    assert_eq!(fields["cacheControl"], "no-store", "body:\n{body:#}");
    assert_eq!(
        fields["customTime"], "2026-01-02T03:04:05Z",
        "body:\n{body:#}"
    );
    assert_eq!(fields["storageClass"], "NEARLINE", "body:\n{body:#}");
    assert!(
        !fields.contains_key("temporaryHold"),
        "holds stay out of the body, as they stay out of an empty body's copy; body:\n{body:#}"
    );
    assert_eq!(fields["metadata"]["author"], "caller", "body:\n{body:#}");
    assert_eq!(
        fields["metadata"][MESSAGE_METADATA_KEY], "copy note",
        "body:\n{body:#}"
    );
}

/// The identical copy without a message sends the empty body that makes GCS
/// copy the source's metadata itself, and reads nothing first.
#[tokio::test]
async fn a_copy_without_a_message_keeps_the_empty_body() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", REWRITE_DONE));
    let backend = anonymous_backend(server.endpoint(), "bkt").await;

    backend
        .copy(
            target("bkt", "src.bin"),
            target("bkt", "dst.bin"),
            CopyOptions::default(),
            None,
        )
        .await
        .expect("plain copy");

    let requests = server.requests();
    assert_eq!(
        requests.len(),
        1,
        "one rewrite call and no read; got {requests:#?}"
    );
    let rewrite = &requests[0];
    assert!(rewrite.starts_with("POST "), "request:\n{rewrite}");
    assert!(
        rewrite
            .to_ascii_lowercase()
            .contains("content-length: 0\r\n"),
        "an unannotated rewrite keeps the empty body; request:\n{rewrite}"
    );
    assert!(
        !rewrite
            .lines()
            .next()
            .unwrap_or("")
            .contains("sourceGeneration="),
        "with no read there is no snapshot to pin; request:\n{rewrite}"
    );
}

/// A caller's own generation pin governs both calls: the read fetches that
/// generation and the rewrite names it, whatever generation the read returns.
#[tokio::test]
async fn a_callers_pin_governs_the_annotated_read_and_rewrite() {
    let server = ScriptedHttpServer::spawn_sequence(vec![
        Some(CannedHttpResponse::json("200 OK", SOURCE)),
        Some(CannedHttpResponse::json("200 OK", REWRITE_DONE)),
    ]);
    let backend = anonymous_backend(server.endpoint(), "bkt").await;

    backend
        .copy(
            target("bkt", "src.bin?generation=5"),
            target("bkt", "dst.bin"),
            CopyOptions {
                message: Some("copy note".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("annotated copy of a pinned source");

    let requests = server.requests();
    let read_line = requests
        .iter()
        .find(|raw| raw.starts_with("GET "))
        .map(|raw| raw.lines().next().unwrap_or(""))
        .expect("the plugin reads the source object first");
    assert!(
        read_line.contains("generation=5"),
        "the read fetches the pinned generation; request line:\n{read_line}"
    );
    let rewrite_line = requests
        .iter()
        .find(|raw| raw.starts_with("POST "))
        .map(|raw| raw.lines().next().unwrap_or(""))
        .expect("a POST for rewriteTo");
    assert!(
        rewrite_line.contains("sourceGeneration=5") && !rewrite_line.contains("sourceGeneration=7"),
        "the caller's pin outranks the generation the read returned; request line:\n{rewrite_line}"
    );
}
