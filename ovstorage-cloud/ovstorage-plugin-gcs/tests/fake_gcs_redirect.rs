// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end redirected-read coverage against `fake-gcs-server`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ovstorage::ext::LayerExt as _;
use ovstorage::layers::REDIRECT_FOLLOWER_KIND;
use ovstorage::{
    Body, ConfigValue, ConnectionRequest, LayerConnectionRequest, LayerSpec, ReadOptions,
    SecretBundle, Stack, WriteOptions, address,
};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

fn endpoint() -> Option<String> {
    match std::env::var("OVSTORAGE_FAKE_GCS_ENDPOINT") {
        Ok(value) if !value.trim().is_empty() => Some(value.trim_end_matches('/').to_string()),
        _ if std::env::var_os("OVSTORAGE_REQUIRE_FAKE_GCS").is_some() => {
            panic!("OVSTORAGE_REQUIRE_FAKE_GCS requires OVSTORAGE_FAKE_GCS_ENDPOINT")
        }
        _ => None,
    }
}

#[tokio::test]
async fn anonymous_redirect_reads_bytes_from_fake_gcs() {
    let Some(endpoint) = endpoint() else {
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after Unix epoch")
        .as_nanos();
    let bucket = format!("ovstorage-redirect-{}-{nonce}", std::process::id());
    let key = "nested/redirected-read.txt";
    let expected = b"redirect follower reached fake GCS".to_vec();
    let client = reqwest::Client::new();

    client
        .post(format!("{endpoint}/storage/v1/b?project=ovstorage"))
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .expect("create fake GCS bucket")
        .error_for_status()
        .expect("fake GCS accepted bucket creation");

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.clone()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.clone()));
    let stack = Stack::builder("redirect_follower")
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .backend_factory(Arc::new(ovstorage_plugin_gcs::GcsLayerFactory::default()))
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            REDIRECT_FOLLOWER_KIND,
            "gcs",
        ))
        .layer(LayerSpec::backend("gcs", "gcs"))
        .connection(LayerConnectionRequest {
            target: "gcs".into(),
            connection: ConnectionRequest {
                backend_kind: "gcs".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
        .build()
        .await
        .expect("build production Stack over anonymous GCS");
    let object = address::parse(&format!("gs://{bucket}/{key}")).expect("parse object address");

    stack
        .write(
            object.clone(),
            Body::Bytes(expected.clone()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write object through the production Stack");

    let (actual, _) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("follow redirected read through Stack::read_bytes");
    assert_eq!(actual, expected);
}
