// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Build a test plugin config that advertises watch_directory and emits
/// `event_count` synthetic events, with keep-alive so multiple subscribers
/// can drain the stream without the broker re-subscribing.
fn watch_test_cfg(event_count: i64) -> HashMap<String, ConfigValue> {
    let mut cfg = HashMap::new();
    cfg.insert("test_caps".into(), ConfigValue::String("full".into()));
    cfg.insert("test_watch_keep_alive".into(), ConfigValue::Bool(true));
    cfg.insert(
        "test_watch_event_count".into(),
        ConfigValue::Int(event_count),
    );
    cfg
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_watch_delivers_brokered_events() {
    // The test plugin synthesizes `Created` events for synthetic relative
    // keys (`watch-event-{i}`); this test verifies the broker plumbs at
    // least one of them through to a brokered client.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_test_connection(&broker_library, watch_test_cfg(1)).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let mut stream = client
        .watch_directory(
            prefix.clone(),
            ovstorage::WatchDirectoryOptions {
                recursive: true,
                poll_interval: std::time::Duration::from_millis(10),
                ..ovstorage::WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match stream.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { kind, .. } => {
            assert_eq!(kind, ovstorage::ChangeKind::Created);
        }
        ovstorage::ChangeEvent::Lapsed { .. } => {
            panic!("fresh brokered watch_directory should not lapse")
        }
    }
    drop(stream);
    drop(client);
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_fans_out_to_multiple_watchers() {
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    // Pace the plugin's emission so both subscribers register before
    // event 0 lands. Real backends don't burst-emit synthetic events
    // and so this race doesn't exist in production; the test plugin's
    // default fast-emit is what surfaces it.
    let mut cfg = watch_test_cfg(1);
    cfg.insert("test_watch_emit_interval_ms".into(), ConfigValue::Int(100));
    add_test_connection(&broker_library, cfg).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let mut first = client
        .watch_directory(prefix.clone(), watch_directory_options.clone(), None)
        .await
        .unwrap();
    let mut second = client
        .watch_directory(prefix.clone(), watch_directory_options, None)
        .await
        .unwrap();

    // Both watchers see a Created event (the synthetic one).
    match first.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { kind, .. } => {
            assert_eq!(kind, ovstorage::ChangeKind::Created);
        }
        ovstorage::ChangeEvent::Lapsed { .. } => panic!("first watcher unexpectedly lapsed"),
    }
    match second.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { kind, .. } => {
            assert_eq!(kind, ovstorage::ChangeKind::Created);
        }
        ovstorage::ChangeEvent::Lapsed { .. } => panic!("second watcher unexpectedly lapsed"),
    }

    // Close watchers + client before draining the server. Otherwise
    // tonic's graceful_shutdown waits on the open watch streams.
    drop(first);
    drop(second);
    drop(client);
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_watch_directory_enforces_fanout_cap() {
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_test_connection(&broker_library, watch_test_cfg(0)).await;
    let broker = Broker::new(broker_library);
    let context = default_context();
    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let mut watchers = Vec::new();
    for _ in 0..DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT {
        watchers.push(
            broker
                .watch_directory(&context, prefix.clone(), watch_directory_options.clone())
                .await
                .unwrap(),
        );
    }
    let error = match broker
        .watch_directory(&context, prefix.clone(), watch_directory_options)
        .await
    {
        Ok(_) => panic!("watch_directory fan-out should reject watcher over the cap"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    drop(watchers);
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_watch_uses_real_broker_listener() {
    // Two clients must share exactly one backend watch_directory call
    // via the hub's per-key OnceCell coalescing.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_caps".into(),
        ovstorage::ConfigValue::String("full".into()),
    );
    // Without keep-alive the test plugin's finite iterator drains
    // before the second subscribe lands, causing a second backend call.
    test_cfg.insert(
        "test_watch_keep_alive".into(),
        ovstorage::ConfigValue::Bool(true),
    );
    add_test_connection(&broker_library, test_cfg).await;
    let broker_library_for_polling = broker_library.clone();
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let _first = client
        .watch_directory(prefix.clone(), watch_directory_options.clone(), None)
        .await
        .unwrap();
    let _second = client
        .watch_directory(prefix.clone(), watch_directory_options, None)
        .await
        .unwrap();
    wait_until_test_counter_eq(&broker_library_for_polling, "watch_directory", 1).await;

    drop(_first);
    drop(_second);
    drop(client);
    shutdown_test_server(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_reconnect_passes_watch_cursor() {
    // Test plugin advertises watch_directory_resumable = false; opening
    // with `since: Some(cursor)` against a non-resumable backend should
    // immediately yield `Lapsed`.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_test_connection(&broker_library, watch_test_cfg(1)).await;
    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let mut stream = client
        .watch_directory(prefix.clone(), watch_directory_options.clone(), None)
        .await
        .unwrap();
    let cursor = match stream.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { cursor, .. } => cursor,
        ovstorage::ChangeEvent::Lapsed { .. } => panic!("fresh watch should not lapse"),
    };
    drop(stream);

    let mut resumed = client
        .watch_directory(
            prefix,
            ovstorage::WatchDirectoryOptions {
                since: Some(cursor),
                ..watch_directory_options
            },
            None,
        )
        .await
        .unwrap();
    match resumed.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Lapsed { .. } => {}
        ovstorage::ChangeEvent::Object { .. } => {
            panic!(
                "non-resumable backend should surface a lapse when asked to resume from a cursor"
            )
        }
    }

    drop(resumed);
    drop(client);
    shutdown_test_server(server).await;
}

/// Authz plugin that denies reads against any address containing the
/// substring `watch-event-0`. Pairs with the test plugin's synthetic
/// events (`watch-event-{i}`): event 0 is filtered, event 1 reaches
/// the watcher.
struct DenyEventZeroReadAuthorizer;

#[async_trait::async_trait]
impl ovstorage_authz::AuthzPlugin for DenyEventZeroReadAuthorizer {
    fn plugin_name(&self) -> &str {
        "test-deny-event-zero-read"
    }

    async fn authorize(
        &self,
        request: &ovstorage_authz::AuthzRequest,
    ) -> ovstorage::Result<ovstorage_authz::AuthzDecision> {
        if request.operation == ovstorage_authz::Operation::Read
            && request
                .address
                .as_ref()
                .map(|a| a.as_str().contains("watch-event-0"))
                .unwrap_or(false)
        {
            return Ok(ovstorage_authz::AuthzDecision::deny(
                "event-0 filtered for test",
            ));
        }
        Ok(ovstorage_authz::AuthzDecision::allow())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_watch_does_not_emit_lapsed_for_visible_events() {
    // Two synthetic events; authz denies read on `watch-event-0` so the
    // broker filters it out, then `watch-event-1` arrives without the
    // filter triggering a Lapsed.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker_library = Library::builder().open_with_test_plugins();
    add_test_connection(&broker_library, watch_test_cfg(2)).await;
    let broker = Arc::new(Broker::with_authorizer(
        broker_library,
        Arc::new(DenyEventZeroReadAuthorizer),
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;
    let mut stream = client
        .watch_directory(
            prefix.clone(),
            ovstorage::WatchDirectoryOptions {
                recursive: true,
                poll_interval: std::time::Duration::from_millis(10),
                ..ovstorage::WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match stream.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { address, kind, .. } => {
            assert!(
                address.as_str().contains("watch-event-1"),
                "should see only event-1, got {address}"
            );
            assert_eq!(kind, ovstorage::ChangeKind::Created);
        }
        ovstorage::ChangeEvent::Lapsed { .. } => {
            panic!("authz-filtered event should not cause a lapse on the watch stream")
        }
    }

    drop(stream);
    drop(client);
    shutdown_test_server(server).await;
    drop(broker);
}
