// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// The producer must hand a fatal pull error to the ack pump instead of
// publishing it directly. The receiver stays unread while the producer fills
// the event channel and receives the fatal response, so a direct terminal send
// parks forever. Pump routing lets the producer finish; once draining begins,
// the queued tail precedes the real provider terminal and every tail ack
// remains writable while the pump publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn producer_fatal_pull_routes_through_pump_with_saturated_event_channel() {
    const TAIL_EVENTS: usize = 3;
    let received = (0..TAIL_EVENTS)
        .map(|index| {
            serde_json::json!({
                "ackId": format!("ack-tail-{index}"),
                "message": {
                    "messageId": format!("message-tail-{index}"),
                    "attributes": {
                        "bucketId": "assets",
                        "objectId": format!("dir/tail-{index}.txt"),
                        "objectGeneration": "42",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    let tail_body = serde_json::json!({ "receivedMessages": received }).to_string();
    let provider_body = serde_json::json!({
        "error": {
            "code": 403,
            "status": "PERMISSION_DENIED",
            "message": "real pull denial"
        }
    })
    .to_string();
    let mock =
        MockPubsub::with_pull_responses(vec![(200, tail_body), (403, provider_body)], 200, "{}");
    let client = mock.client();
    let pending = Arc::new(PubsubPending::new());
    let clock = Arc::new(SystemClock);
    let (event_tx, event_rx) = mpsc::sync_channel::<UpstreamItem>(TAIL_EVENTS);
    let (ack_tx, ack_rx) = tokio_mpsc::channel::<PumpRequest>(ACK_CHANNEL_CAPACITY);
    let ack_probe = ack_tx.clone();
    let cancel = CancellationToken::new();
    let config = SubscriptionConfig {
        ack_deadline_seconds: 30,
        exactly_once_delivery: false,
    };

    let pump = tokio::spawn(ack_pump(
        client.clone(),
        pending.clone(),
        ack_rx,
        event_tx.clone(),
        cancel.clone(),
        config.clone(),
        clock.clone(),
    ));
    let producer = tokio::spawn(producer(ProducerContext {
        client,
        event_tx,
        ack_tx,
        cancel: cancel.clone(),
        target: GcsObjectRef {
            bucket: "assets".into(),
            object: String::new(),
            selector: None,
        },
        address_root: address_root(),
        opts: WatchDirectoryOptions {
            recursive: true,
            include_metadata_changes: true,
            since: None,
            poll_interval: Duration::from_millis(50),
        },
        pull_max: 10,
        cadence: Duration::from_millis(50),
        watch_config: config,
        pending,
        clock,
    }));

    // Keep `event_rx` unread until the producer has processed the fatal pull.
    // Regressing to producer-side `send_item(Err)` leaves that task parked on
    // the full channel and makes this timeout fail deterministically.
    tokio::time::timeout(Duration::from_secs(5), producer)
        .await
        .expect("producer parked publishing a fatal pull instead of routing it through the pump")
        .expect("producer task panicked");
    tokio::time::timeout(Duration::from_secs(5), async {
        while ack_probe.capacity() != ACK_CHANNEL_CAPACITY {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ack pump did not dequeue the producer terminal");

    for index in 0..TAIL_EVENTS {
        let item = event_rx.recv().expect("queued tail event");
        let (event, ack) = item.expect("queued tail must precede the terminal");
        match event {
            BackendChangeEvent::Object { address, .. } => assert!(
                address.as_str().contains(&format!("dir/tail-{index}.txt")),
                "tail event order changed: {address}"
            ),
            other => panic!("expected queued object event, got {other:?}"),
        }
        ack().expect("terminal pump must keep tail acknowledgements writable");
    }

    let terminal = event_rx.recv().expect("provider terminal item");
    let err = match terminal {
        Err(err) => err,
        Ok(_) => panic!("fatal pull must terminate after the queued tail"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::PermissionDenied,
        "real provider error was masked by ack-pump unavailability: {}",
        err.message()
    );
    assert!(
        err.message().contains("code=PERMISSION_DENIED"),
        "sanitized provider status did not survive pump routing: {}",
        err.message()
    );

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("ack pump did not stop after terminal teardown")
        .expect("ack pump task panicked");
}
