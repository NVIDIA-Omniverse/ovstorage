// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ovstorage::UpdateMetadataOptions;
use ovstorage_authz::{ATTRIBUTION_KEY_MODIFIED_BY, AttributionStrategy};
use ovstorage_authz_context::{AuthCredential, Transport};

/// Build a brokered file backend rooted at a fresh temp dir; returns
/// the broker, the prefix to write under, and the temp dir for cleanup.
async fn brokered_file_with_strategy(
    strategy: AttributionStrategy,
) -> (Broker, Url, std::path::PathBuf) {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = BrokerStackFixture::new()
        .file(&root)
        .attribution_strategy(strategy)
        .build_broker()
        .await;
    (broker, prefix, root)
}

/// A stable non-anonymous uid for a test principal name. The allow-all test
/// broker carries no JWT config, so a Uds peer credential is the identity
/// source and the built-in auth layer resolves it to `uid:{uid}` — see
/// [`resolved_id`]. Distinct names hash to distinct uids (needed for the
/// per-principal isolation assertion).
fn stable_uid(name: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    // Keep it a plausible uid and away from the sentinel `u32::MAX` (anonymous).
    (h.finish() as u32 % 1_000_000) + 1000
}

/// The principal id the auth layer resolves a [`context_for`] credential to.
fn resolved_id(principal_id: &str) -> String {
    format!("uid:{}", stable_uid(principal_id))
}

/// A request context whose Uds peer credential resolves, in the built-in auth
/// layer, to a stable `uid:{uid}` principal derived from `principal_id`.
fn context_for(principal_id: &str) -> RequestContext {
    let uid = stable_uid(principal_id);
    RequestContext {
        credential: Some(AuthCredential::new(
            None,
            Transport::Uds {
                uid,
                gid: uid,
                pid: 0,
            },
        )),
        audit_id: None,
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
    assert_eq!(
        info.modified_by.as_deref(),
        Some(resolved_id("alice@example.com").as_str())
    );
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
    assert_eq!(
        info.modified_by.as_deref(),
        Some(resolved_id("alice").as_str())
    );
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
    assert_eq!(
        info_after_alice.modified_by.as_deref(),
        Some(resolved_id("alice").as_str())
    );

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
                // A client asking to delete the reserved key. The overlay drops
                // reserved keys from the removal list, so the stamp written moments
                // earlier in the same request survives — end to end, through a real
                // broker, not just as a unit property of the overlay.
                user_metadata_remove: vec![ATTRIBUTION_KEY_MODIFIED_BY.to_string()],
                ..UpdateMetadataOptions::default()
            },
        )
        .await
        .unwrap();

    let info_after_bob = broker
        .stat(&context_for("anyone"), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        info_after_bob.modified_by.as_deref(),
        Some(resolved_id("bob").as_str())
    );
    let visible = info_after_bob.user_metadata.expect("note key surfaces");
    assert_eq!(
        visible.get("note").map(String::as_str),
        Some("touched-by-bob")
    );
    assert!(!visible.contains_key(ATTRIBUTION_KEY_MODIFIED_BY));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn stat_cache_is_isolated_per_principal() {
    use ovstorage::{ErrorCode, MetadataCacheConfig};

    // A stat is authorized per principal and its `effective_permissions` are
    // principal-specific, so a result cached for one principal must never be
    // served to another. Regression guard: without `principal_id` in the key,
    // the broker's stat/list_versions cache would share one entry across
    // principals.
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Broker::new(
        BrokerStackFixture::new()
            .file(&root)
            .metadata_cache(Arc::new(
                MetadataCache::new(&MetadataCacheConfig::default()),
            ))
            .build_stack()
            .await,
    );

    let object = address::join_relative(&prefix, "secret.txt").unwrap();
    let alice = context_for("alice@example.com");
    broker
        .write(
            &alice,
            object.clone(),
            Body::Bytes(b"hi".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    // Alice stats the object, populating the metadata cache.
    broker
        .stat(&alice, object.clone(), StatOptions::default())
        .await
        .unwrap();

    // Remove the backing file out of band. Within TTL alice would still get a
    // hit, but bob must not inherit alice's cached entry: with per-principal
    // keying his lookup misses and hits the backend, which now reports the
    // object gone.
    std::fs::remove_file(root.join("secret.txt")).unwrap();

    let bob = context_for("bob@example.com");
    let bob_stat = broker.stat(&bob, object, StatOptions::default()).await;
    assert!(
        matches!(&bob_stat, Err(e) if e.code() == ErrorCode::NotFound),
        "bob received a cross-principal cache hit instead of a fresh NotFound: {bob_stat:?}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// A broker whose `test` backend declines copy, so `copy_rename_fallback`
/// emulates it. The fixture leaves the graph exactly as the shipped default
/// emits it: attribution on the `test` branch, below the router.
async fn brokered_emulating_copy() -> (Broker, Url) {
    let mut config = HashMap::new();
    config.insert("test_caps_copy".into(), ovstorage::ConfigValue::Bool(false));
    let broker = BrokerStackFixture::new()
        .test_backend(config)
        .attribution_strategy(AttributionStrategy::UserMetadata)
        .build_broker()
        .await;
    (broker, Url::parse("test://demo/").unwrap())
}

/// An emulated copy stamps its destination.
///
/// `copy_rename_fallback` serves a backend that declines copy by fabricating a
/// write from `WriteOptions::default()` and issuing it through its own `inner` —
/// so the write is born BELOW that wrapper and never passes a layer above it.
/// The branch-level attribution wrapper, sitting under the router, is in that
/// write's path; an attribution wrapper at the graph root is not.
///
/// **The load-bearing thing is the placement.** Its control is a mutation, not a
/// sibling test: moving attribution back to the graph root — `main`'s shape —
/// leaves every other behavioural test in this file passing and reddens only this
/// one, because a root wrapper still stamps ordinary writes, still sanitizes and
/// still harvests. It just never sees a write born below `copy_rename_fallback`.
#[tokio::test]
async fn emulated_copy_stamps_the_destination() {
    let (broker, prefix) = brokered_emulating_copy().await;
    let source = address::join_relative(&prefix, "source.txt").unwrap();
    let destination = address::join_relative(&prefix, "copied.txt").unwrap();

    // Alice writes; Bob copies. Distinct principals matter: the `test` backend
    // stores what it is handed, so a destination that merely inherited the
    // source's metadata would read as alice. Asserting bob isolates the
    // fabricated write as the only thing that can have produced the stamp.
    broker
        .write(
            &context_for("alice@example.com"),
            source.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    broker
        .copy(
            &context_for("bob@example.com"),
            source,
            destination.clone(),
            ovstorage::CopyOptions::default(),
        )
        .await
        .expect("emulated copy succeeds");

    let info = broker
        .stat(&context_for("anyone"), destination, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        info.modified_by.as_deref(),
        Some(resolved_id("bob@example.com").as_str()),
        "an emulated copy must attribute its destination to the caller who asked \
         for it, not to whoever wrote the source"
    );
}

/// A graph declaring attribution only at its root — the shape every deployment
/// written for the previous layout has — does not start. The host refuses it and
/// names the layer, rather than quietly running a graph nobody wrote.
///
/// This is the host-level half of the guarantee: the unit tests in
/// `ovstorage-authz` pin what the pass decides, and this pins that a broker
/// actually applies it and surfaces the refusal instead of booting.
#[tokio::test]
async fn a_root_shaped_graph_is_refused_at_startup() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let error = match BrokerStackFixture::new()
        .file(&root)
        .attribution_at_root()
        .attribution_strategy(AttributionStrategy::UserMetadata)
        .try_build()
        .await
    {
        Ok(_) => panic!("a root-declared attribution layer must not start"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
    assert!(
        error.message().contains("misplaced attribution layer"),
        "the operator must be told what is wrong: {}",
        error.message()
    );
    assert!(
        error.message().contains("'attribution'"),
        "and which layer: {}",
        error.message()
    );
    std::fs::remove_dir_all(root).unwrap();
}
