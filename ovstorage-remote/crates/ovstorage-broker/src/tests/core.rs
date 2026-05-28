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
    let broker = Broker::with_authorizer(
        build_default_library_for_test().await,
        Arc::new(DenyAllAuthorizer),
    );
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
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::with_authorizer(library, Arc::new(DenyHiddenReadAuthorizer));
    let context = default_context();
    let hidden = address::join_relative(&prefix, "hidden.txt").unwrap();
    let visible = address::join_relative(&prefix, "visible.txt").unwrap();

    broker
        .write(
            &context,
            hidden,
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

#[tokio::test]
async fn broker_list_address_roots_authorizes_and_filters_published_addresses() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let physical_prefix = address_for_path(&root);
    let new_prefix = address::parse("server://new/").unwrap();
    let legacy_prefix = address::parse("server://old/").unwrap();
    let mut file_config = HashMap::new();
    file_config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    let library = Library::builder().open_with_test_plugins();
    library
        .add_rewrite_route(new_prefix.clone(), physical_prefix, "file", file_config)
        .await
        .unwrap();
    library
        .add_alias(ovstorage::AliasRequest {
            from: legacy_prefix.clone(),
            to: new_prefix,
            visibility: ovstorage::AddressVisibility::Visible,
            persist: false,
            display_name: Some("legacy server name".into()),
            user_metadata: ovstorage::UserMetadata::new(),
        })
        .unwrap();
    let context = default_context();

    let route_only_authz = Arc::new(
        TomlAuthzPlugin::from_config(
            toml::from_str::<TomlAuthzConfig>(
                r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "server://old/"
"#,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let denied_broker = Broker::with_authz_plugin(library.clone(), route_only_authz);
    assert_eq!(
        denied_broker
            .list_address_roots(&context)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );

    let discovery_authz = Arc::new(
        TomlAuthzPlugin::from_config(
            toml::from_str::<TomlAuthzConfig>(
                r#"
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
"#,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let broker = Broker::with_authz_plugin(library, discovery_authz);
    let roots = broker.list_address_roots(&context).await.unwrap();
    let addresses = roots
        .iter()
        .map(|root| root.address.clone())
        .collect::<Vec<_>>();
    assert_eq!(addresses, vec![legacy_prefix]);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_check_access_intersects_backend_and_authz() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::with_authorizer(library, Arc::new(DenyHiddenReadAuthorizer));
    let context = default_context();
    let hidden = address::join_relative(&prefix, "hidden.txt").unwrap();
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
    assert_eq!(decision.reason.as_deref(), Some("denied by broker authz"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_authz_policy_matches_incoming_address_before_rewrite() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let physical_prefix = address_for_path(&root);
    let logical_prefix = address::parse("logical://team/").unwrap();
    let mut file_config = HashMap::new();
    file_config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    let library = Library::builder().open_with_test_plugins();
    library
        .add_rewrite_route(
            logical_prefix.clone(),
            physical_prefix.clone(),
            "file",
            file_config,
        )
        .await
        .unwrap();
    let context = default_context();
    let object = address::join_relative(&logical_prefix, "object.txt").unwrap();

    let physical_only_authz = Arc::new(
        TomlAuthzPlugin::from_config(
            toml::from_str::<TomlAuthzConfig>(&format!(
                r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "{}"
"#,
                physical_prefix
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    let physical_policy_broker = Broker::with_authz_plugin(library.clone(), physical_only_authz);
    assert_eq!(
        physical_policy_broker
            .stat(&context, object.clone(), StatOptions::default(),)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );

    let logical_authz = Arc::new(
        TomlAuthzPlugin::from_config(
            toml::from_str::<TomlAuthzConfig>(
                r#"
[[policy]]
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "logical://team/"
"#,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let logical_policy_broker = Broker::with_authz_plugin(library, logical_authz);
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

#[tokio::test]
async fn broker_round_trips_file_bytes_through_protocol_envelopes() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::new(library);
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

#[tokio::test]
async fn broker_read_threshold_returns_redirect_for_oversized_object() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::with_route_policy(
        library,
        BrokerRoutePolicy {
            cache_max_object_bytes: Some(4),
            read_redirect_endpoint: Some("https://redirect.example/read".into()),
            ..BrokerRoutePolicy::default()
        },
    );
    let context = default_context();
    let small = address::join_relative(&prefix, "small.txt").unwrap();
    let large = address::join_relative(&prefix, "large.txt").unwrap();

    broker
        .write(
            &context,
            small.clone(),
            Body::Bytes(b"tiny".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    broker
        .write(
            &context,
            large.clone(),
            Body::Bytes(b"large".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    match broker
        .read(&context, small, ReadOptions::default())
        .await
        .unwrap()
    {
        BrokerReadOutcome::Stream { mut stream, info } => {
            use futures::StreamExt;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(bytes, b"tiny");
            assert_eq!(info.size, Some(4));
        }
        BrokerReadOutcome::Bytes { .. } => {
            panic!("file plugin returns LocalDelegate; broker streams")
        }
        BrokerReadOutcome::Redirect(_) => panic!("small object should not redirect"),
    }

    match broker
        .read(&context, large.clone(), ReadOptions::default())
        .await
        .unwrap()
    {
        BrokerReadOutcome::Redirect(redirect) => {
            assert_eq!(redirect.request.method, "GET");
            assert_eq!(redirect.request.url, "https://redirect.example/read");
            assert!(redirect.scope.operations.read);
            assert!(!redirect.scope.operations.write);
            assert_eq!(redirect.scope.physical_url_prefix, large.to_string());
            assert_eq!(redirect.policy_epoch, context.policy_epoch);
            assert!(redirect.expires_at > SystemTime::now());
        }
        BrokerReadOutcome::Bytes { .. } => panic!("large object should use redirect branch"),
        BrokerReadOutcome::Stream { .. } => panic!("large object should use redirect branch"),
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_write_threshold_redirects_unknown_and_oversized_bodies() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let library = Library::builder().open_with_test_plugins();
    add_file_connection(&library, &root).await;
    let broker = Broker::with_route_policy(
        library,
        BrokerRoutePolicy {
            cache_max_object_bytes: Some(4),
            write_redirect_endpoint: Some("https://redirect.example/write".into()),
            ..BrokerRoutePolicy::default()
        },
    );
    for _ in 0..17 {
        broker.advance_policy_epoch().unwrap();
    }
    let mut context = default_context();
    context.policy_epoch = broker.current_policy_epoch();
    context.audit_id = Some("audit-write-threshold".into());

    let unknown = address::join_relative(&prefix, "unknown.txt").unwrap();
    match broker
        .write(
            &context,
            unknown.clone(),
            Body::Bytes(b"tiny".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap()
    {
        BrokerWriteOutcome::Redirects(batch) => {
            let redirect = batch.redirects.first().unwrap();
            assert_eq!(redirect.request.method, "PUT");
            assert_eq!(redirect.request.url, "https://redirect.example/write");
            assert_eq!(
                redirect.body_source,
                RedirectBodySource::UserBytes { offset: 0, len: 4 }
            );
            assert!(redirect.scope.operations.write);
            assert_eq!(redirect.audit_id, "audit-write-threshold");
            assert_eq!(redirect.policy_epoch, broker.current_policy_epoch());
        }
        BrokerWriteOutcome::Done(_) => panic!("unknown-size body should use redirect branch"),
    }
    assert_eq!(
        broker
            .stat(&context, unknown, StatOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );

    let oversized = address::join_relative(&prefix, "oversized.txt").unwrap();
    match broker
        .write(
            &context,
            oversized,
            Body::Bytes(b"wide".to_vec()),
            WriteOptions {
                size_hint: Some(8),
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap()
    {
        BrokerWriteOutcome::Redirects(batch) => {
            assert_eq!(
                batch.redirects[0].body_source,
                RedirectBodySource::UserBytes { offset: 0, len: 8 }
            );
        }
        BrokerWriteOutcome::Done(_) => panic!("oversized body should use redirect branch"),
    }

    let small = address::join_relative(&prefix, "small-write.txt").unwrap();
    match broker
        .write(
            &context,
            small.clone(),
            Body::Bytes(b"tiny".to_vec()),
            WriteOptions {
                size_hint: Some(4),
                ..WriteOptions::default()
            },
        )
        .await
        .unwrap()
    {
        BrokerWriteOutcome::Done(result) => {
            assert_eq!(result.info.size, Some(4));
        }
        BrokerWriteOutcome::Redirects(_) => {
            panic!("under-threshold body should upload inline")
        }
    }
    let info = broker
        .stat(
            &context,
            address::join_relative(&prefix, "small-write.txt").unwrap(),
            StatOptions::default(),
        )
        .await
        .unwrap();
    match broker
        .read(&context, small, ReadOptions::default())
        .await
        .unwrap()
    {
        BrokerReadOutcome::Stream {
            info: back_info,
            mut stream,
        } => {
            use futures::StreamExt;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(bytes, b"tiny".to_vec());
            assert_eq!(back_info, info);
        }
        BrokerReadOutcome::Bytes { .. } => {
            panic!("file plugin returns LocalDelegate; broker streams")
        }
        BrokerReadOutcome::Redirect(_) => {
            panic!("under-threshold read should not redirect")
        }
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn broker_protocol_version_is_v2() {
    assert_eq!(PROTOCOL_V2.major, 2);
}

#[tokio::test]
async fn broker_policy_epoch_strict_mode_rejects_stale_requests() {
    let broker = Broker::with_authorizer(
        build_default_library_for_test().await,
        Arc::new(AllowAllAuthorizer),
    );
    let stale = default_context();
    broker.advance_policy_epoch().unwrap();
    let mut fresh = default_context();
    fresh.policy_epoch = broker.current_policy_epoch();

    assert_eq!(
        broker.list_backend_kinds(&stale).await.unwrap_err().code(),
        ErrorCode::PolicyEpochStale
    );
    broker.list_backend_kinds(&fresh).await.unwrap();
}

#[tokio::test]
async fn broker_policy_epoch_grace_window_closes_on_invalidation() {
    let broker = Broker::with_authorizer_and_policy_freshness(
        build_default_library_for_test().await,
        Arc::new(AllowAllAuthorizer),
        BrokerRoutePolicy::default(),
        BrokerPolicyFreshness::GraceWindow,
    );
    let stale = default_context();
    let stale_epoch = stale.policy_epoch;
    broker.advance_policy_epoch().unwrap();
    let mut fresh = default_context();
    fresh.policy_epoch = broker.current_policy_epoch();

    broker.list_backend_kinds(&stale).await.unwrap();
    broker
        .invalidate_policy_epochs_for_test(vec![stale_epoch])
        .unwrap();
    assert_eq!(
        broker.list_backend_kinds(&stale).await.unwrap_err().code(),
        ErrorCode::PolicyEpochStale
    );
    broker.list_backend_kinds(&fresh).await.unwrap();
}

#[tokio::test]
async fn broker_policy_epoch_persists_under_state_root_without_cache_root() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    let root_string = root.to_string_lossy().replace('\\', "/");
    let config = format!(
        r#"
[state]
state_root = "{}"

[authz]
plugin = "ovstorage-authz-toml"

[[authz.policy]]
id = "allow-test"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"
"#,
        root_string.replace('"', "\\\"")
    );

    let broker = build_broker_from_config_str(&config).await.unwrap();
    assert_eq!(broker.current_policy_epoch(), 0);
    assert_eq!(broker.advance_policy_epoch().unwrap(), 1);
    drop(broker);

    let broker = build_broker_from_config_str(&config).await.unwrap();
    assert_eq!(broker.current_policy_epoch(), 1);
    let mut fresh = default_context();
    fresh.policy_epoch = broker.current_policy_epoch();
    broker.list_backend_kinds(&fresh).await.unwrap();
    assert_eq!(
        broker
            .list_backend_kinds(&default_context())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PolicyEpochStale
    );

    std::fs::remove_dir_all(root).unwrap();
}
