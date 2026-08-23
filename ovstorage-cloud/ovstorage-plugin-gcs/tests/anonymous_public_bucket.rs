// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an anonymous GCS connection can serve against a public bucket.
//!
//! A GCS bucket that grants `roles/storage.objectViewer` to `allUsers` answers
//! an unauthenticated `GET /storage/v1/b/<bucket>/o` (list) and
//! `GET /storage/v1/b/<bucket>/o/<object>` (stat); granting only
//! `storage.objects.get` and not `storage.objects.list` gives the familiar
//! read-yes / list-no shape, and there it is Google that refuses, not the
//! plugin.
//!
//! The plugin can issue both, and always could: `MaybeBearerAuth` skips the
//! `Authorization` header when the token is empty, and `Authenticator`
//! returns an empty token for `CredentialSource::Anonymous`.
//!
//! **Scope, because the conformance suite already covers most of this.**
//! `tests/conformance_scenarios.rs` drives EVERY scenario through
//! `anonymous_layer()`, so `drive_stat_basic_objectinfo` and
//! `drive_list_one_level_vs_recursive` already prove an anonymous connection
//! lists and stats and that the entries come back parsed. What they do not
//! assert is the WIRE FORM — that the request carries no `Authorization`
//! header — which is the property a plugin loses when anonymity becomes a fork
//! in client construction rather than a no-op at the header. That is what
//! these two tests add, and they are deliberately thin because of it.
//!
//! The property is easy to lose and costs nothing to hold here:
//! gcs's anonymity is a no-op branch in one hand-rolled client, whereas the s3
//! sibling reaches its store through an SDK that wants a credentials provider
//! and so has to construct an unsigned client explicitly. A plugin in that
//! shape can lose anonymous `list` by omission. This one cannot, and nothing in
//! this file changes gcs behaviour.
//!
//! The control for "no `Authorization` header" is
//! `layer_connection_lifecycle.rs::add_connection_authenticates_on_verify_pass`,
//! which asserts `authorization: bearer synthetic-token` on a credentialed
//! storage RPC against the same fixture shape. Without a positive somewhere, an
//! absence assertion would also hold on a build that signed nothing at all.

use std::collections::HashMap;

use ovstorage_plugin::{
    BackendId, ConfigValue, ConnectionRequest, ListOptions, ObjectKind, ResolvedTarget,
    SecretBundle, StatOptions, address,
};
use ovstorage_plugin_gcs::GcsBackend;
use ovstorage_plugin_test::scripted_http::{CannedHttpResponse, ScriptedHttpServer};

const BUCKET: &str = "bkt";

/// One object and one prefix, the two arms of the plugin's list mapping.
const PUBLIC_LIST_BODY: &str = r#"{
  "kind": "storage#objects",
  "items": [
    {
      "name": "assets/teapot.usd",
      "size": "2048",
      "etag": "CJmh8gE=",
      "generation": "1735786445000000",
      "updated": "2026-01-02T03:04:05.000Z",
      "contentType": "model/vnd.usd"
    }
  ],
  "prefixes": ["assets/textures/"]
}"#;

const PUBLIC_OBJECT_BODY: &str = r#"{
  "kind": "storage#object",
  "name": "assets/teapot.usd",
  "size": "2048",
  "etag": "CJmh8gE=",
  "generation": "1735786445000000",
  "updated": "2026-01-02T03:04:05.000Z",
  "contentType": "model/vnd.usd"
}"#;

async fn backend_with(endpoint: &str, credentials: SecretBundle) -> GcsBackend {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(BUCKET.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    };
    let config =
        ovstorage_plugin_gcs::__test_only_parse_config(&request.config).expect("parse gcs config");
    ovstorage_plugin_gcs::__test_only_backend(config, request.credentials).expect("build backend")
}

/// An empty `SecretBundle` is `CredentialSource::Anonymous`.
async fn anonymous_backend(endpoint: &str) -> GcsBackend {
    backend_with(endpoint, SecretBundle::default()).await
}

fn target(key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("gcs:gs://{BUCKET}/")),
        resolved_address: address::parse(&format!("gs://{BUCKET}/{key}")).expect("parse address"),
    }
}

fn has_authorization(raw: &str) -> bool {
    raw.to_lowercase().contains("\r\nauthorization: ")
}

/// A public bucket answers the listing, and the plugin issues it with no
/// `Authorization` header.
#[tokio::test]
async fn an_anonymous_connection_lists_a_public_bucket() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_LIST_BODY));
    let backend = anonymous_backend(server.endpoint()).await;

    let items = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("an anonymous list of a public bucket must succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "exactly one listing was issued");
    let listing = &requests[0];
    assert!(
        !has_authorization(listing),
        "an anonymous list must carry no Authorization header; got: {listing}"
    );
    let line = listing.split("\r\n").next().unwrap_or("");
    assert!(
        line.starts_with("GET /storage/v1/b/bkt/o?"),
        "the JSON API objects.list endpoint: {line}"
    );
    assert!(line.contains("prefix=assets%2F"), "prefix-scoped: {line}");
    assert!(line.contains("delimiter=%2F"), "one level: {line}");

    assert_eq!(items.len(), 2, "one object and one prefix");
    let object = items
        .iter()
        .find(|item| item.address.as_str() == "gs://bkt/assets/teapot.usd")
        .expect("the object is returned under its own address");
    assert_eq!(object.kind, ObjectKind::File);
    assert_eq!(object.size, Some(2048));
    assert!(object.mtime.is_some(), "`updated` is carried through");
    let directory = items
        .iter()
        .find(|item| item.address.as_str() == "gs://bkt/assets/textures/")
        .expect("the prefix is returned as a directory");
    assert_eq!(directory.kind, ObjectKind::DirectoryInferred);
}

/// `stat` on a public object is an unsigned `objects.get`, and the metadata
/// comes back parsed.
#[tokio::test]
async fn an_anonymous_connection_stats_a_public_object() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let backend = anonymous_backend(server.endpoint()).await;

    let info = backend
        .stat(target("assets/teapot.usd"), StatOptions::default(), None)
        .await
        .expect("an anonymous stat of a public object must succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "one metadata GET, no fallback probe");
    assert!(
        !has_authorization(&requests[0]),
        "an anonymous stat must carry no Authorization header; got: {}",
        requests[0]
    );
    assert!(
        requests[0].starts_with("GET /storage/v1/b/bkt/o/assets%2Fteapot.usd"),
        "the object-metadata endpoint: {}",
        requests[0].split("\r\n").next().unwrap_or("")
    );

    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));
    assert!(info.mtime.is_some(), "`updated` is carried through");
}
