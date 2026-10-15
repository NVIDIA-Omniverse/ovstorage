// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_cache::{Cache, CacheConfig};
use ovstorage_plugin_test::{Route, ScriptedResponse, start_responder_with_redirect};

use super::*;
use ovstorage::ext::LayerExt as _;

fn strong_response(body: &[u8], etag: &str) -> ScriptedResponse {
    let mut response = ScriptedResponse::ok(body);
    response
        .headers
        .push(("etag".into(), format!("\"{etag}\"")));
    response
}

/// Revoke-mid-flight, structural: with a hot metadata cache
/// composed BELOW the per-listener auth layer, reloading the policy to deny-all
/// makes the next request rejected by the auth layer BEFORE the cache is
/// consulted. A cache hit would return the warmed `ObjectInfo`; the auth layer
/// instead returns `PermissionDenied`, proving authorization precedes cache
/// admission — the structural win of the auth layer sitting over the inner.
#[tokio::test(flavor = "multi_thread")]
async fn broker_authz_precedes_hot_cache_on_revocation() {
    let broker = BrokerStackFixture::new()
        .test_backend(HashMap::new())
        .metadata_cache(Arc::new(ovstorage::MetadataCache::new(
            &ovstorage::MetadataCacheConfig::default(),
        )))
        .authz(ANONYMOUS_ALLOW_ALL_POLICY)
        .build_broker()
        .await;

    let prefix = Url::parse("test://demo/").unwrap();
    let object = address::join_relative(&prefix, "hot.txt").unwrap();
    // Write + stat under allow-all warms the in-stack metadata cache.
    broker
        .write(
            &default_context(),
            object.clone(),
            Body::Bytes(b"hot".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();
    broker
        .stat(&default_context(), object.clone(), StatOptions::default())
        .await
        .unwrap();

    // Revoke by swapping the live policy to deny-all.
    broker.reload_auth_policy(DENY_ALL_POLICY).unwrap();

    // The request is rejected by the auth layer even though the object is hot
    // in the cache below — authz-before-cache is structural.
    assert_eq!(
        broker
            .stat(&default_context(), object.clone(), StatOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied,
    );

    drop(broker);
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_cache_hit_survives_broker_unavailability() {
    let client_cache_root = unique_temp_dir();
    let prefix = Url::parse("test://demo/").unwrap();
    // The synthetic backend declares its in-memory object validator Strong,
    // making this a trusted-cache availability test. The file backend's Weak
    // size+mtime validator deliberately takes the untrusted path.
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(HashMap::new())
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack_with(
        &discovery_url,
        BrokerClientStackOptions {
            byte_cache: Some(Arc::new(
                Cache::open(CacheConfig {
                    state_root: client_cache_root.join("state"),
                    cache_root: client_cache_root.join("cache"),
                })
                .unwrap(),
            )),
            ..Default::default()
        },
    )
    .await;

    let object = address::join_relative(&prefix, "cached-client.txt").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
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
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_plugin_read_redirect_populates_cache() {
    let client_cache_root = unique_temp_dir();
    let (responder, redirect_kv) = start_responder_with_redirect(vec![Route::new(
        "GET",
        "/plugin-redirect-read.txt",
        strong_response(b"plugin redirect bytes", "plugin-redirect-v1"),
    )])
    .expect("loopback responder binds");
    let test_cfg = HashMap::from([(redirect_kv.0.to_string(), redirect_kv.1)]);
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = broker_client_stack_with(
        &discovery_url,
        BrokerClientStackOptions {
            byte_cache: Some(Arc::new(
                Cache::open(CacheConfig {
                    state_root: client_cache_root.join("state"),
                    cache_root: client_cache_root.join("cache"),
                })
                .unwrap(),
            )),
            ..Default::default()
        },
    )
    .await;

    let object = address::join_relative(&prefix, "plugin-redirect-read.txt").unwrap();
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"plugin redirect bytes");
    assert_eq!(info.size, Some(21));

    shutdown_test_server(server).await;
    responder.set_routes(vec![Route::new("GET", "/", ScriptedResponse::not_found())]);

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"plugin redirect bytes");
    assert_eq!(info.size, Some(21));

    drop(client);
    drop(broker);
    drop(responder);
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_cached_read_survives_expired_redirects() {
    let client_cache_root = unique_temp_dir();
    let (responder, redirect_kv) = start_responder_with_redirect(vec![
        Route::new(
            "GET",
            "/cached-before-expiry.txt",
            strong_response(b"cached bytes", "cached-before-expiry-v1"),
        ),
        Route::new(
            "GET",
            "/uncached-after-expiry.txt",
            strong_response(b"expired redirect", "uncached-after-expiry-v1"),
        ),
    ])
    .expect("loopback responder binds");
    let test_cfg = HashMap::from([(redirect_kv.0.to_string(), redirect_kv.1)]);
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = broker_client_stack_with(
        &discovery_url,
        BrokerClientStackOptions {
            byte_cache: Some(Arc::new(
                Cache::open(CacheConfig {
                    state_root: client_cache_root.join("state"),
                    cache_root: client_cache_root.join("cache"),
                })
                .unwrap(),
            )),
            // The broker-client's stat surface answers NotFound for stats it
            // does not proxy, so a brokered-client composition that wants its
            // cache to survive redirect outages opts into the lost-backing
            // fallback, mirroring the broker daemon's own composition.
            lost_backing_fallback: true,
            ..Default::default()
        },
    )
    .await;

    let cached = address::join_relative(&prefix, "cached-before-expiry.txt").unwrap();
    let (bytes, _) = client
        .read_bytes(cached.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"cached bytes");

    // Knob lands on the broker's backend instance (same one emitting
    // redirects) via broker → broker → test plugin.
    let knob = address::join_relative(&prefix, "__test_meta/redirect_expired").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
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
    drop(responder);
    std::fs::remove_dir_all(client_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_plugin_write_redirect_populates_cache() {
    let root = unique_temp_dir();
    let client_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String(format!("file://{}/", root.display())),
    );
    test_cfg.insert("test_multipart_parts".into(), ConfigValue::Int(1));
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = broker_client_stack_with(
        &discovery_url,
        BrokerClientStackOptions {
            byte_cache: Some(Arc::new(
                Cache::open(CacheConfig {
                    state_root: client_cache_root.join("state"),
                    cache_root: client_cache_root.join("cache"),
                })
                .unwrap(),
            )),
            ..Default::default()
        },
    )
    .await;

    let object = address::join_relative(&prefix, "plugin-redirect-write.txt").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
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
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String("file:///tmp/unused/".into()),
    );
    test_cfg.insert("test_multipart_parts".into(), ConfigValue::Int(2));
    let broker = Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .build_stack()
            .await,
    );
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
async fn broker_owned_cache_serves_strong_content_after_backing_loss() {
    let broker_cache_root = unique_temp_dir();
    let prefix = Url::parse("test://demo/").unwrap();
    let test_cfg = HashMap::from([
        (
            "test_inject_error_on".into(),
            ConfigValue::String("stat".into()),
        ),
        (
            "test_inject_error_code".into(),
            ConfigValue::String("NotFound".into()),
        ),
    ]);
    // The broker composition shares a host byte cache into the in-stack
    // `byte_cache` wrapper. The Strong synthetic write result warms the cache;
    // persistent NotFound injection on stat then models lost backing without a
    // delete through the cache, which would intentionally invalidate the key.
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .byte_cache(Arc::new(
                Cache::open(CacheConfig {
                    state_root: broker_cache_root.join("state"),
                    cache_root: broker_cache_root.join("cache"),
                })
                .unwrap(),
            ))
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let object = address::join_relative(&prefix, "cached-broker.txt").unwrap();
    ovstorage::ext::LayerExt::write(
        &*client,
        object.clone(),
        Body::Bytes(b"broker cached bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"broker cached bytes");
    assert_eq!(info.size, Some(19));

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    remove_dir_all_retry(broker_cache_root).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_owned_cache_does_not_fallback_for_weak_file_validator() {
    let root = unique_temp_dir();
    let broker_cache_root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .file(&root)
            .byte_cache(Arc::new(
                Cache::open(CacheConfig {
                    state_root: broker_cache_root.join("state"),
                    cache_root: broker_cache_root.join("cache"),
                })
                .unwrap(),
            ))
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();
    let client = broker_client_stack(&discovery_url).await;
    let object = address::join_relative(&prefix, "weak-file.txt").unwrap();

    ovstorage::ext::LayerExt::write(
        &*client,
        object.clone(),
        Body::Bytes(b"weak file bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    let (_, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(info.etag_strength, ovstorage::EtagStrength::Weak);

    remove_file_retry(root.join("weak-file.txt")).unwrap();
    let error = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::NotFound);

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
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    // file plugin advertises no threshold; broker mirrors None.
    let caps = client.capabilities_for(&prefix, None).await.unwrap();
    assert_eq!(
        caps.redirect_size_threshold, None,
        "broker should mirror file plugin's None threshold"
    );

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    remove_dir_all_retry(root).unwrap();
}

// The one path the broker daemon wires that the rest of this suite can't reach: a
// *backend* read that returns `ReadResult::Redirect`, followed and teed into
// the broker's OWN byte cache by the single global follower. It needs
// `follow_reads = true`, which requires both a byte cache AND a daemon follow
// cap — the fixture's `follow_cap()` setter supplies the cap, which composes
// the follower as `follow_reads = true` with that cap. The `test` backend
// emits the backend redirect (`test_redirect_url` ⇒ `read` returns
// `Redirect(http://<origin>/<key>)`); the broker follows it, fetches the bytes,
// and tees them into the byte cache. The client holds NO cache, so every cache
// effect is broker-side. Making the origin answer NotFound after the first read
// proves the second read is served from the broker byte cache: the backend still
// emits a `Redirect`, but following it would fail.
#[tokio::test(flavor = "multi_thread")]
async fn broker_follows_backend_read_redirect_and_tees_into_byte_cache() {
    let broker_cache_root = unique_temp_dir();
    // The loopback origin returns a quoted strong validator, so the follower's
    // normalized ObjectInfo is eligible for trusted cache admission.
    let (responder, redirect_kv) = start_responder_with_redirect(vec![Route::new(
        "GET",
        "/follow-me.txt",
        strong_response(b"followed redirect bytes", "follow-me-v1"),
    )])
    .expect("loopback responder binds");
    let test_cfg = HashMap::from([(redirect_kv.0.to_string(), redirect_kv.1)]);
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(test_cfg)
            .byte_cache(Arc::new(
                Cache::open(CacheConfig {
                    state_root: broker_cache_root.join("state"),
                    cache_root: broker_cache_root.join("cache"),
                })
                .unwrap(),
            ))
            // A follow cap ⇒ the single follower is `follow_reads = true` (cap
            // 1 MiB, well above the object) — small reads are followed and teed
            // into the byte cache.
            .follow_cap(Some(1 << 20))
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("test://demo/").unwrap();
    let client = broker_client_stack(&discovery_url).await;

    let object = address::join_relative(&prefix, "follow-me.txt").unwrap();
    let (bytes, info) = client
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"followed redirect bytes");
    assert_eq!(info.size, Some(23));

    // Remove the redirect target logically. The backend keeps emitting a
    // Redirect, but following it now returns 404; success can only come from
    // the teed bytes in the broker byte cache.
    responder.set_routes(vec![Route::new("GET", "/", ScriptedResponse::not_found())]);

    let (bytes, info) = client
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"followed redirect bytes");
    assert_eq!(info.size, Some(23));

    shutdown_test_server(server).await;
    drop(client);
    drop(broker);
    drop(responder);
    remove_dir_all_retry(broker_cache_root).unwrap();
}

// The fixture's `visibility()` setter threads address-visibility overrides
// into the composed Stack's `alias` wrapper. `Hidden` roots remain in the
// broker advertisement with their true marker, while `Suppressed` roots stay
// absent and a sibling `Visible` root retains its marker.
#[tokio::test(flavor = "multi_thread")]
async fn broker_advertises_hidden_root_but_omits_suppressed_root() {
    let visible_root = unique_temp_dir();
    let hidden_root = unique_temp_dir();
    let suppressed_root = unique_temp_dir();
    std::fs::create_dir_all(&visible_root).unwrap();
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&suppressed_root).unwrap();
    let visible_addr = address_for_path(&visible_root);
    let hidden_addr = address_for_path(&hidden_root);
    let suppressed_addr = address_for_path(&suppressed_root);
    let broker = Broker::new(
        BrokerStackFixture::new()
            .file(&visible_root)
            .file(&hidden_root)
            .file(&suppressed_root)
            .visibility(hidden_addr.clone(), ovstorage::AddressVisibility::Hidden)
            .visibility(
                suppressed_addr.clone(),
                ovstorage::AddressVisibility::Suppressed,
            )
            .build_stack()
            .await,
    );

    let roots = broker.list_address_roots(&default_context()).await.unwrap();
    assert_eq!(
        roots
            .iter()
            .find(|root| root.address == visible_addr)
            .map(|root| root.visibility),
        Some(ovstorage::AddressVisibility::Visible),
        "the Visible root must advertise with its marker: {roots:?}"
    );
    assert_eq!(
        roots
            .iter()
            .find(|root| root.address == hidden_addr)
            .map(|root| root.visibility),
        Some(ovstorage::AddressVisibility::Hidden),
        "the Hidden root must advertise with its marker: {roots:?}"
    );
    assert!(
        roots.iter().all(|root| root.address != suppressed_addr),
        "the Suppressed root must be absent from list_address_roots: {roots:?}"
    );

    drop(broker);
    remove_dir_all_retry(visible_root).unwrap();
    remove_dir_all_retry(hidden_root).unwrap();
    remove_dir_all_retry(suppressed_root).unwrap();
}
