// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ovstorage::UpdateMetadataOptions;
use ovstorage_authz::{ATTRIBUTION_KEY_MODIFIED_BY, AttributionStrategy, Principal};

/// Build a brokered file backend rooted at a fresh temp dir; returns
/// the broker, the prefix to write under, and the temp dir for cleanup.
async fn brokered_file_with_strategy(
    strategy: AttributionStrategy,
) -> (Broker, Url, std::path::PathBuf) {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::new(library)
        .with_attribution_strategy(strategy)
        .expect("strategy is valid");
    (broker, prefix, root)
}

fn context_for(principal_id: &str) -> RequestContext {
    RequestContext {
        principal: Principal {
            id: principal_id.to_string(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "test".to_string(),
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn user_metadata_strategy_stamps_writer_into_typed_field() {
    let (broker, prefix, root) =
        brokered_file_with_strategy(AttributionStrategy::UserMetadata).await;
    let object = address::join_relative(&prefix, "alice.txt").unwrap();
    let ctx = context_for("alice@example.com");

    broker
        .write(
            &ctx,
            object.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let info = broker
        .stat(&context_for("anyone"), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(info.modified_by.as_deref(), Some("alice@example.com"));
    // Reserved key hidden from the surfaced user_metadata bucket.
    assert!(
        info.user_metadata
            .as_ref()
            .map(|m| !m.contains_key(ATTRIBUTION_KEY_MODIFIED_BY))
            .unwrap_or(true),
        "broker leaked the reserved attribution key into user_metadata"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn client_supplied_reserved_key_is_silently_stripped_and_overwritten() {
    let (broker, prefix, root) =
        brokered_file_with_strategy(AttributionStrategy::UserMetadata).await;
    let object = address::join_relative(&prefix, "spoofed.txt").unwrap();

    let mut user_meta = HashMap::new();
    user_meta.insert(
        ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
        "mallory".to_string(),
    );
    user_meta.insert("regular".to_string(), "kept".to_string());

    broker
        .write(
            &context_for("alice"),
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions {
                user_metadata: Some(user_meta),
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap();

    let info = broker
        .stat(&context_for("alice"), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(info.modified_by.as_deref(), Some("alice"));
    let visible = info.user_metadata.expect("regular key survives");
    assert_eq!(visible.get("regular").map(String::as_str), Some("kept"));
    assert!(!visible.contains_key(ATTRIBUTION_KEY_MODIFIED_BY));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn passthrough_strategy_does_not_stamp_or_strip() {
    let (broker, prefix, root) =
        brokered_file_with_strategy(AttributionStrategy::Passthrough).await;
    let object = address::join_relative(&prefix, "passthrough.txt").unwrap();

    // Simulate an upstream-broker stamp arriving in user_metadata.
    let mut upstream_user_meta = HashMap::new();
    upstream_user_meta.insert(
        ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
        "alice-from-upstream".to_string(),
    );

    broker
        .write(
            &context_for("local-broker-svc"),
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions {
                user_metadata: Some(upstream_user_meta),
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap();

    let info = broker
        .stat(
            &context_for("local-broker-svc"),
            object,
            StatOptions::default(),
        )
        .await
        .unwrap();
    // Passthrough means: plugin's native value flows through unmodified
    // (plugin-file resolves the file's owning uid to a username, so this
    // is non-empty and reflects the OS-level writer, not the broker's
    // authn'd principal). Crucially the upstream broker's stamp under
    // user_metadata is preserved verbatim — that's what
    // `UserMetadata → Passthrough` chains rely on.
    let user_meta = info.user_metadata.expect("upstream stamp present");
    assert_eq!(
        user_meta
            .get(ATTRIBUTION_KEY_MODIFIED_BY)
            .map(String::as_str),
        Some("alice-from-upstream"),
        "passthrough must preserve upstream broker's stamp verbatim"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn update_metadata_re_stamps_with_current_writer() {
    let (broker, prefix, root) =
        brokered_file_with_strategy(AttributionStrategy::UserMetadata).await;
    let object = address::join_relative(&prefix, "two-writers.txt").unwrap();

    broker
        .write(
            &context_for("alice"),
            object.clone(),
            Body::Bytes(b"v1".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let info_after_alice = broker
        .stat(
            &context_for("alice"),
            object.clone(),
            StatOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(info_after_alice.modified_by.as_deref(), Some("alice"));

    broker
        .update_metadata(
            &context_for("bob"),
            object.clone(),
            UpdateMetadataOptions {
                user_metadata_set: {
                    let mut map = HashMap::new();
                    map.insert("note".to_string(), "touched-by-bob".to_string());
                    map
                },
                ..UpdateMetadataOptions::default()
            },
        )
        .await
        .unwrap();

    let info_after_bob = broker
        .stat(&context_for("anyone"), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(info_after_bob.modified_by.as_deref(), Some("bob"));
    let visible = info_after_bob.user_metadata.expect("note key surfaces");
    assert_eq!(
        visible.get("note").map(String::as_str),
        Some("touched-by-bob")
    );
    assert!(!visible.contains_key(ATTRIBUTION_KEY_MODIFIED_BY));
    std::fs::remove_dir_all(root).unwrap();
}
