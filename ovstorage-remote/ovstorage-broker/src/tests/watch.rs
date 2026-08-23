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
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(watch_test_cfg(1))
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let mut stream = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: ovstorage::WatchDirectoryOptions {
                recursive: true,
                poll_interval: std::time::Duration::from_millis(10),
                ..ovstorage::WatchDirectoryOptions::default()
            },
        }),
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
    // Pace the plugin's emission so both subscribers register before
    // event 0 lands. Real backends don't burst-emit synthetic events
    // and so this race doesn't exist in production; the test plugin's
    // default fast-emit is what surfaces it.
    let mut cfg = watch_test_cfg(1);
    cfg.insert("test_watch_emit_interval_ms".into(), ConfigValue::Int(100));
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(cfg)
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let mut first = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: watch_directory_options.clone(),
        }),
        None,
    )
    .await
    .unwrap();
    let mut second = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: watch_directory_options,
        }),
        None,
    )
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
async fn broker_grpc_reconnect_passes_watch_cursor() {
    // Test plugin advertises watch_directory_resumable = false; opening
    // with `since: Some(cursor)` against a non-resumable backend should
    // immediately yield `Lapsed`.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker = Arc::new(Broker::new(
        BrokerStackFixture::new()
            .test_backend(watch_test_cfg(1))
            .build_stack()
            .await,
    ));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let watch_directory_options = ovstorage::WatchDirectoryOptions {
        recursive: true,
        poll_interval: std::time::Duration::from_millis(10),
        ..ovstorage::WatchDirectoryOptions::default()
    };
    let mut stream = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: watch_directory_options.clone(),
        }),
        None,
    )
    .await
    .unwrap();
    let cursor = match stream.next().unwrap().unwrap() {
        ovstorage::ChangeEvent::Object { cursor, .. } => cursor,
        ovstorage::ChangeEvent::Lapsed { .. } => panic!("fresh watch should not lapse"),
    };
    drop(stream);

    let mut resumed = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix,
            options: ovstorage::WatchDirectoryOptions {
                since: Some(cursor),
                ..watch_directory_options
            },
        }),
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

/// Authz policy that allows watch + reads everywhere EXCEPT a read on
/// `test://demo/watch-event-0`. Pairs with the test plugin's synthetic events
/// (`watch-event-{i}`): the in-stack Layer's per-event Read re-auth drops
/// event 0, event 1 reaches the watcher. Longest-prefix precedence: the deny
/// rule's full-URL prefix outranks the `*` allow for exactly that object.
const DENY_EVENT_ZERO_READ_POLICY: &str = r#"
[[policy]]
id = "allow-all"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"

[[policy]]
id = "deny-event-zero"
effect = "deny"
principal = "*"
operations = ["read"]
prefix = "test://demo/watch-event-0"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_watch_does_not_emit_lapsed_for_visible_events() {
    // Two synthetic events; the in-stack authz Layer denies read on
    // `watch-event-0` so its per-event re-auth filters it, then `watch-event-1`
    // arrives without the filter triggering a Lapsed.
    let prefix = Url::parse("test://demo/").unwrap();
    let broker = Arc::new(
        BrokerStackFixture::new()
            .test_backend(watch_test_cfg(2))
            .authz(DENY_EVENT_ZERO_READ_POLICY)
            .build_broker()
            .await,
    );
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;
    let mut stream = ovstorage::Layer::watch_directory(
        &*client,
        ovstorage::Request::new(ovstorage::WatchDirectoryRequest {
            prefix: prefix.clone(),
            options: ovstorage::WatchDirectoryOptions {
                recursive: true,
                poll_interval: std::time::Duration::from_millis(10),
                ..ovstorage::WatchDirectoryOptions::default()
            },
        }),
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
