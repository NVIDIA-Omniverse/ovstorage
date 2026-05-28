// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn broker_cache_hit_survives_broker_unavailability() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "cached-client.txt").unwrap();
    client
        .write(
            object.clone(),
            Body::Bytes(b"client cached bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    shutdown_test_server(server).await;

    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"client cached bytes");
    assert_eq!(info.size, Some(19));

    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_read_populates_cache_and_survives_listener_loss() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    std::fs::write(root.join("redirect-read.txt"), b"redirect cached bytes").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::with_route_policy(
        broker_library,
        BrokerRoutePolicy {
            cache_max_object_bytes: Some(4),
            read_redirect_endpoint: Some(file_url(&root.join("redirect-read.txt"))),
            ..BrokerRoutePolicy::default()
        },
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "redirect-read.txt").unwrap();
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"redirect cached bytes");
    assert_eq!(info.size, Some(21));

    shutdown_test_server(server).await;
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"redirect cached bytes");
    assert_eq!(info.size, Some(21));

    std::fs::remove_file(root.join("redirect-read.txt")).unwrap();

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"redirect cached bytes");
    assert_eq!(info.size, Some(21));

    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_populates_cache() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::with_route_policy(
        broker_library,
        BrokerRoutePolicy {
            cache_max_object_bytes: Some(4),
            write_redirect_endpoint: Some(file_url(&root.join("redirect-write.txt"))),
            ..BrokerRoutePolicy::default()
        },
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "redirect-write.txt").unwrap();
    client
        .write(
            object.clone(),
            Body::Bytes(b"redirect write cached bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(root.join("redirect-write.txt")).unwrap(),
        b"redirect write cached bytes"
    );

    shutdown_test_server(server).await;
    std::fs::remove_file(root.join("redirect-write.txt")).unwrap();

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"redirect write cached bytes");
    assert_eq!(info.size, Some(27));

    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_plugin_read_redirect_populates_cache() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("plugin-redirect-read.txt"),
        b"plugin redirect bytes",
    )
    .unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String(format!("file://{}/", root.display())),
    );
    add_test_connection(&broker_library, test_cfg).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "plugin-redirect-read.txt").unwrap();
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"plugin redirect bytes");
    assert_eq!(info.size, Some(21));

    shutdown_test_server(server).await;
    std::fs::remove_file(root.join("plugin-redirect-read.txt")).unwrap();

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"plugin redirect bytes");
    assert_eq!(info.size, Some(21));

    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_cached_read_survives_expired_redirects() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("cached-before-expiry.txt"), b"cached bytes").unwrap();
    std::fs::write(root.join("uncached-after-expiry.txt"), b"expired redirect").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String(format!("file://{}/", root.display())),
    );
    add_test_connection(&broker_library, test_cfg).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let cached = address::join_relative(&prefix, "cached-before-expiry.txt").unwrap();
    let (bytes, _) = client
        .read_bytes(cached.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"cached bytes");

    // Knob lands on the broker's backend instance (same one emitting
    // redirects) via broker → broker → test plugin.
    let knob = address::join_relative(&prefix, "__test_meta/redirect_expired").unwrap();
    client
        .write(
            knob,
            Body::Bytes(b"true".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let uncached = address::join_relative(&prefix, "uncached-after-expiry.txt").unwrap();
    assert_eq!(
        client
            .read_bytes(uncached, ReadOptions::default(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::RedirectExpired
    );
    let (bytes, info) = client
        .read_bytes(cached, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"cached bytes");
    assert_eq!(info.size, Some(12));

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_plugin_write_redirect_populates_cache() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String(format!("file://{}/", root.display())),
    );
    test_cfg.insert("test_multipart_parts".into(), ConfigValue::Int(1));
    add_test_connection(&broker_library, test_cfg).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: client_cache_root.join("state"),
                cache_root: client_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "plugin-redirect-write.txt").unwrap();
    client
        .write(
            object.clone(),
            Body::Bytes(b"plugin write redirect bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    shutdown_test_server(server).await;
    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"plugin write redirect bytes");
    assert_eq!(info.size, Some(27));

    drop(client);
    drop(broker);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_plugin_redirect_continue_write_rejects_wrong_cardinality() {
    let broker_library = Library::builder().open_with_test_plugins();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String("file:///tmp/unused/".into()),
    );
    test_cfg.insert("test_multipart_parts".into(), ConfigValue::Int(2));
    add_test_connection(&broker_library, test_cfg).await;
    let broker = Broker::new(broker_library);
    let context = default_context();
    let prefix = Url::parse("test://demo/").unwrap();
    let object = address::join_relative(&prefix, "wrong-cardinality.txt").unwrap();
    // Plugin-driven multipart batch lives behind `write_redirect` now;
    // body-bearing `write` only handles success paths.
    let batch = broker
        .write_redirect(&context, object.clone(), WriteOptions::default())
        .await
        .unwrap();
    assert_eq!(
        broker
            .continue_write(
                &context,
                object,
                batch,
                RedirectResultBatch {
                    results: Vec::new(),
                },
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_owned_cache_serves_brokered_read_after_backing_file_disappears() {
    let root = unique_temp_dir();
    let broker_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: broker_cache_root.join("state"),
                cache_root: broker_cache_root.join("cache"),
            })
            .unwrap(),
        )
        .open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let object = address::join_relative(&prefix, "cached-broker.txt").unwrap();
    client
        .write(
            object.clone(),
            Body::Bytes(b"broker cached bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    remove_file_retry(root.join("cached-broker.txt")).unwrap();

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"broker cached bytes");
    assert_eq!(info.size, Some(19));

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    remove_dir_all_retry(root).unwrap();
    remove_dir_all_retry(broker_cache_root).unwrap();
}

/// Per-route capability mirroring through broker; without this
/// round-trip the gateway can't gate `write_redirect` per route.
#[tokio::test(flavor = "multi_thread")]
async fn broker_mirrors_upstream_redirect_size_threshold() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    // file plugin advertises no threshold; broker mirrors None.
    let caps = client.capabilities_for(&prefix).unwrap();
    assert_eq!(
        caps.redirect_size_threshold, None,
        "broker should mirror file plugin's None threshold"
    );

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    remove_dir_all_retry(root).unwrap();
}

// Joe's review finding #1: write_redirect on a broker-policy-redirect
// route with WriteOptions::size_hint == None used to fall into
// write_redirect_batch with Body::Bytes(Vec::new()), letting the core
// redirect follower finalize an empty upload silently. Reject the
// case so callers stream the body via write() instead.
#[tokio::test(flavor = "multi_thread")]
async fn write_redirect_without_size_hint_returns_unsupported() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Broker::with_route_policy(
        broker_library,
        BrokerRoutePolicy {
            write_redirect_endpoint: Some(file_url(&root.join("redirect-write.txt"))),
            ..BrokerRoutePolicy::default()
        },
    );
    let context = default_context();
    let object = address::join_relative(&prefix, "no-size-hint.txt").unwrap();

    let err = broker
        .write_redirect(&context, object, WriteOptions::default())
        .await
        .expect_err("expected Unsupported when size_hint is None on a redirect route");
    assert_eq!(err.code(), ErrorCode::Unsupported);

    drop(broker);
    remove_dir_all_retry(root).unwrap();
}
