// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The operator's anonymous fallback grant, at the broker's startup boundary.
//!
//! An address no configured connection serves is `NoRoute` unless the operator
//! granted its scheme a fallback, and a grant is a deployment property: a
//! brokered fetch runs from the broker's network position. So the decisions
//! here are the operator's, and the broker's job is to carry the grant onto the
//! backend layer that reads it — and to refuse, at startup, a grant that
//! nothing in the graph could carry rather than start with it silently inert.
//!
//! No cloud plugin is driven here; the fallback's data path is the backend's
//! own concern and is exercised against loopback endpoints in the plugin
//! crates. What the broker owns is the closed default and the startup refusal.

use super::*;

/// The closed default. The fixture's auth is the explicit anonymous allow-all,
/// so the request clears the auth layer and reaches the router, which owns
/// the `NoRoute`: nothing in a file-only graph answers `s3://`, and with no
/// grant there is no second tier to consult.
///
/// The same address under the deny-all policy is `PermissionDenied` instead,
/// which pins the ordering the grant relies on: authorization evaluates the
/// caller's address before routing, so a fallback grants routability and never
/// authority.
#[tokio::test(flavor = "multi_thread")]
async fn a_default_broker_answers_noroute_for_an_unrouted_address() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let unrouted = Url::parse("s3://public-bucket/object.bin").unwrap();

    let broker = BrokerStackFixture::new().file(&root).build_broker().await;
    let error = broker
        .stat(&default_context(), unrouted.clone(), StatOptions::default())
        .await
        .expect_err("a file-only broker with no grant must not route an s3 address");
    assert_eq!(
        error.code(),
        ErrorCode::NoRoute,
        "with the allow-all fixture policy the router answers, and it has no route: {error}"
    );
    drop(broker);

    let gated = BrokerStackFixture::new()
        .file(&root)
        .authz(DENY_ALL_POLICY)
        .build_broker()
        .await;
    let error = gated
        .stat(&default_context(), unrouted, StatOptions::default())
        .await
        .expect_err("the deny-all policy refuses before routing");
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "authorization runs before the route table, so a denied caller never learns \
         whether a route exists: {error}"
    );
    drop(gated);

    remove_dir_all_retry(root).unwrap();
}

/// A grant the graph cannot carry is refused at build, naming the fix. The
/// alternative — starting with the grant stamped nowhere — is the failure an
/// operator would never notice: their config says `gs` is granted, and every
/// `gs://` address keeps answering `NoRoute`.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_for_a_kind_the_graph_lacks_refuses_to_start() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();

    let error = BrokerStackFixture::new()
        .file(&root)
        .anonymous_fallback(&["gs"])
        .try_build()
        .await
        .err()
        .expect("a file-only graph cannot carry a `gs` grant");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    let message = error.to_string();
    for needle in ["grants `gs`", "kind `gcs`", "[ovstorage.layers.gcs]"] {
        assert!(message.contains(needle), "missing `{needle}` in: {message}");
    }

    remove_dir_all_retry(root).unwrap();
}

/// The same refusal through the operator's own path — TOML in,
/// `build_broker_from_config_str` out — so the stamp is pinned where
/// production calls it and not only where the fixture does.
#[tokio::test]
async fn an_operator_config_granting_a_kind_the_graph_lacks_refuses_to_start() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let contents = format!(
        r#"
anonymous_fallback_schemes = ["gs"]

[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
        root.to_string_lossy()
    );

    let error = match build_broker_from_config_str(&contents).await {
        Ok(_) => panic!("a grant the graph cannot carry must refuse to start"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        error.to_string().contains("[ovstorage.layers.gcs]"),
        "the startup refusal must name the fix, got: {error}"
    );

    remove_dir_all_retry(root).unwrap();
}
