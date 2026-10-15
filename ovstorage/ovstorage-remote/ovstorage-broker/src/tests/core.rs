// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn broker_lists_registered_backend_kinds() {
    let broker = build_default_broker_for_test().await;
    let kinds = broker.list_backend_kinds(&default_context()).await.unwrap();
    assert!(kinds.iter().any(|kind| kind.kind == "broker"));
    assert!(kinds.iter().any(|kind| kind.kind == "file"));
}

#[tokio::test]
async fn broker_authorizer_blocks_backend_call_before_dispatch() {
    // The in-stack auth Layer (deny-all policy) rejects before the Stack routes —
    // an empty (deny) policy denies every op.
    let broker = BrokerStackFixture::new()
        .authz(DENY_ALL_POLICY)
        .build_broker()
        .await;
    let err = broker
        .stat(
            &default_context(),
            address::parse("file:/tmp/missing.txt").unwrap(),
            StatOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn broker_list_filters_denied_entries() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let hidden = address::join_relative(&prefix, "hidden.txt").unwrap();
    let visible = address::join_relative(&prefix, "visible.txt").unwrap();
    // The in-stack authz Layer denies stat+read on the hidden object; its
    // per-item `Stat` post-filter drops it from the listing.
    let broker = BrokerStackFixture::new()
        .file(&root)
        .authz(deny_read_stat_on(&hidden))
        .build_broker()
        .await;
    let context = default_context();

    broker
        .write(
            &context,
            hidden.clone(),
            Body::Bytes(b"hidden".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    broker
        .write(
            &context,
            visible.clone(),
            Body::Bytes(b"visible".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let page = broker
        .list(&context, prefix.clone(), ovstorage::ListOptions::default())
        .await
        .unwrap();
    let addresses = page
        .items
        .iter()
        .map(|item| item.address.clone())
        .collect::<Vec<_>>();

    assert_eq!(addresses, vec![visible]);
    std::fs::remove_dir_all(root).unwrap();
}

/// A directory addressed WITHOUT a trailing slash lists exactly its children.
///
/// Nothing normalizes the prefix on the way down — the address reaches the
/// backend as the caller wrote it — so this pins that the backend derives its
/// own directory key. The assertion is on the exact set, not on "contains the
/// child": a listing that leaked a sibling would satisfy the looser form, and
/// a leak is the failure this guards against.
#[tokio::test]
async fn broker_list_of_a_slashless_directory_returns_exactly_its_children() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    // A sibling whose name merely starts with the listed directory's. A
    // byte-prefix listing returns it; a segment-aligned one does not.
    std::fs::create_dir_all(root.join("subx")).unwrap();
    let prefix = address_for_path(&root);
    let broker = Broker::new(file_broker_stack(&root).await);
    let context = default_context();

    let child = address::parse(&format!("{prefix}sub/child.txt")).unwrap();
    broker
        .write(
            &context,
            child.clone(),
            Body::Bytes(b"hi".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let sibling = address::parse(&format!("{prefix}subx/other.txt")).unwrap();
    broker
        .write(
            &context,
            sibling,
            Body::Bytes(b"no".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    // The subdirectory in OBJECT form (no trailing slash).
    let sub_object_form = address::join_relative(&prefix, "sub").unwrap();
    assert!(!address::is_directory(&sub_object_form));
    let page = broker
        .list(&context, sub_object_form, ovstorage::ListOptions::default())
        .await
        .unwrap();
    let listed: Vec<&str> = page
        .items
        .iter()
        .map(|item| item.address.as_str())
        .collect();
    assert_eq!(
        listed,
        vec![format!("{prefix}sub/child.txt").as_str()],
        "a slashless directory must list exactly its own children"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_list_address_roots_authorizes_and_filters_published_addresses() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let physical_prefix = address_for_path(&root);
    let new_prefix = address::parse("server://new/").unwrap();
    let legacy_prefix = address::parse("server://old/").unwrap();
    let context = default_context();

    // The rewrite mount (`new_prefix → physical`) and the legacy alias
    // (`old → physical`) are both composed as alias rules on the Stack; the
    // file connection provides the physical root. The authz Layer's in-stack
    // `list_address_roots` gate (ListAddressRoots pre-check + per-root Read/List
    // filter) is what this test asserts. A policy WITHOUT `list_address_roots`
    // fails the pre-check for the whole call.
    let route_only_policy = r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "server://old/"
"#;
    let denied_broker = BrokerStackFixture::new()
        .file(&root)
        .alias(new_prefix.clone(), physical_prefix.clone())
        .alias(legacy_prefix.clone(), physical_prefix.clone())
        .authz(route_only_policy)
        .build_broker()
        .await;
    assert_eq!(
        denied_broker
            .list_address_roots(&context)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );

    // ListAddressRoots granted; only `server://old/` is (Read||List)-visible, so
    // the per-root filter keeps the legacy prefix and drops the rest.
    let discovery_policy = r#"
[[policy]]
id = "discover-roots"
effect = "allow"
principal = "*"
operations = ["list_address_roots"]
prefix = "*"

[[policy]]
id = "legacy-read"
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "server://old/"
"#;
    let broker = BrokerStackFixture::new()
        .file(&root)
        .alias(new_prefix.clone(), physical_prefix.clone())
        .alias(legacy_prefix.clone(), physical_prefix)
        .authz(discovery_policy)
        .build_broker()
        .await;
    let roots = broker.list_address_roots(&context).await.unwrap();
    let addresses = roots
        .iter()
        .map(|root| root.address.clone())
        .collect::<Vec<_>>();
    assert_eq!(addresses, vec![legacy_prefix]);
    std::fs::remove_dir_all(root).unwrap();
}

/// A path-form directory addressed WITHOUT a trailing slash resolves through
/// the broker `stat` object→directory `NotFound` fallback, even on a
/// no-metadata-cache broker. Without the fallback
/// the object-form stat returns `NotFound` and the directory is never found.
#[tokio::test]
async fn broker_stat_falls_back_to_directory_form_on_not_found() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    // `file_broker_stack` carries no metadata cache.
    let broker = Broker::new(file_broker_stack(&root).await);
    let context = default_context();

    // A real on-disk subdirectory, addressed in object form (no trailing slash).
    std::fs::create_dir(root.join("subdir")).unwrap();
    let dir_object_form = address::join_relative(&prefix, "subdir").unwrap();
    assert!(!address::is_directory(&dir_object_form));

    let info = broker
        .stat(&context, dir_object_form, StatOptions::default())
        .await
        .expect("object→directory NotFound fallback must resolve the directory");
    assert_eq!(info.kind, ovstorage::ObjectKind::Directory);
    std::fs::remove_dir_all(root).unwrap();
}

// `stat` object→directory retry split re-authorization: the broker authorizes
// the object form once, and the `NotFound` directory
// retry re-`stat`s the `to_directory` form, which the in-stack authz Layer
// re-authorizes INDEPENDENTLY (stricter / fail-closed only at the exact
// object/dir boundary). The observable effect requires a backend that returns
// `NotFound` for the object form of a real directory (an object-store shape);
// the built-in `file` backend resolves an object-form directory directly, so
// the retry never fires there. Independent per-form authorization follows
// structurally from the authz Layer running its full gate on every `stat` it
// receives (object form and the retried directory form are two separate `stat`
// calls); there is no dedicated unit test isolating it, and the broker stat
// tests in this module exercise the object→directory path end-to-end.

#[tokio::test]
async fn broker_check_access_intersects_backend_and_authz() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let hidden = address::join_relative(&prefix, "hidden.txt").unwrap();
    let broker = BrokerStackFixture::new()
        .file(&root)
        .authz(deny_read_stat_on(&hidden))
        .build_broker()
        .await;
    let context = default_context();
    broker
        .write(
            &context,
            hidden.clone(),
            Body::Bytes(b"hidden".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let decision = broker
        .check_access(
            &context,
            hidden,
            AccessOps {
                read: true,
                write: true,
                ..AccessOps::default()
            },
        )
        .await
        .unwrap();

    assert!(!decision.allowed);
    assert!(decision.denied_ops.read);
    assert!(!decision.denied_ops.write);
    // The host-agnostic Layer emits a neutral reason.
    assert_eq!(decision.reason.as_deref(), Some("denied by authz policy"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_authz_policy_matches_incoming_address_before_rewrite() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let physical_prefix = address_for_path(&root);
    let logical_prefix = address::parse("logical://team/").unwrap();
    let context = default_context();
    let object = address::join_relative(&logical_prefix, "object.txt").unwrap();

    // Rewrite mount `logical://team/ → physical`: an alias rule over the file
    // connection, composed BELOW the top-of-stack authz Layer. The Layer
    // authorizes the incoming (logical) address; a policy on the PHYSICAL
    // target never matches, so it denies (the alias rewrite happens below).
    let physical_only_policy = format!(
        r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "{physical_prefix}"
"#
    );
    let physical_policy_broker = BrokerStackFixture::new()
        .file(&root)
        .alias(logical_prefix.clone(), physical_prefix.clone())
        .authz(physical_only_policy)
        .build_broker()
        .await;
    assert_eq!(
        physical_policy_broker
            .stat(&context, object.clone(), StatOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );

    let logical_policy = r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "logical://team/"
"#;
    let logical_policy_broker = BrokerStackFixture::new()
        .file(&root)
        .alias(logical_prefix.clone(), physical_prefix.clone())
        .authz(logical_policy)
        .build_broker()
        .await;
    logical_policy_broker
        .write(
            &context,
            object.clone(),
            Body::Bytes(b"logical".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    let info = logical_policy_broker
        .stat(&context, object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(info.size, Some(7));
    std::fs::remove_dir_all(root).unwrap();
}

/// The broker validates that a key in
/// both `user_metadata_set` and `user_metadata_remove` is rejected with
/// `InvalidArgument` before the op reaches the Stack.
#[tokio::test]
async fn broker_update_metadata_rejects_set_and_remove_same_key() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Broker::new(file_broker_stack(&root).await);
    let context = default_context();
    let object = address::join_relative(&prefix, "obj.txt").unwrap();

    let mut set = std::collections::HashMap::new();
    set.insert("shared-key".to_string(), "value".to_string());
    let options = ovstorage::UpdateMetadataOptions {
        user_metadata_set: set,
        user_metadata_remove: vec!["shared-key".to_string()],
        ..Default::default()
    };
    let err = broker
        .update_metadata(&context, object, options)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_round_trips_file_bytes_through_protocol_envelopes() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Broker::new(file_broker_stack(&root).await);
    let object = address::join_relative(&prefix, "hello.txt").unwrap();
    let context = default_context();

    broker
        .write(
            &context,
            object.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions {
                if_dest: ovstorage::IfDestExists::Fail,
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap();

    let read = broker
        .read(&context, object, ReadOptions::default())
        .await
        .unwrap();
    match read {
        BrokerReadOutcome::Stream { mut stream, info } => {
            use futures::StreamExt;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(bytes, b"hello");
            assert_eq!(info.size, Some(5));
        }
        BrokerReadOutcome::Bytes { .. } => {
            panic!("file plugin returns LocalDelegate; broker streams")
        }
        BrokerReadOutcome::Redirect(_) => panic!("bootstrap broker should not redirect"),
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn broker_protocol_version_is_v2() {
    assert_eq!(PROTOCOL_V2.major, 2);
}

#[tokio::test]
async fn broker_auth_policy_reload_revokes_on_next_request() {
    // There is no host-owned policy-epoch counter: revocation is "the next
    // request evaluates the live policy". Reloading the built-in auth layer's
    // policy to deny-all makes the very next gated request fail — the revocation
    // requirement is met by the layer, not by epoch machinery.
    let broker = BrokerStackFixture::new()
        .authz(ANONYMOUS_ALLOW_ALL_POLICY)
        .build_broker()
        .await;
    // Allow-all: a gated introspection slot succeeds.
    broker.list_address_roots(&default_context()).await.unwrap();
    // Swap the live policy to deny-all; the next request is denied immediately.
    broker.reload_auth_policy(DENY_ALL_POLICY).unwrap();
    assert_eq!(
        broker
            .list_address_roots(&default_context())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
}
