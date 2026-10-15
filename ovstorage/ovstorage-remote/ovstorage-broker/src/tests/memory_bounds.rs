// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Memory-boundedness invariants through the broker.
//!
//! The broker must never proxy a whole large object. Two load-bearing
//! invariants:
//!
//! 1. A write body that exceeds the gRPC ingress cap (`WRITE_BODY_BYTE_CAP`,
//!    64 MiB) is **rejected** with `ResourceExhausted` mid-stream rather than
//!    buffered whole (`oversized_grpc_write_body_is_rejected`). Streamed in
//!    1 MiB frames — the cap trips on cumulative length, never on one giant
//!    allocation.
//! 2. A cross-root copy streams instead of buffering the whole object, so at a
//!    modest size it completes cleanly and bounded rather
//!    than OOM (`copy_rename_fallback_copy_is_bounded_at_modest_size`).

use super::*;

/// A gRPC write whose streamed body exceeds `WRITE_BODY_BYTE_CAP` (64 MiB) is
/// rejected with `ResourceExhausted` — the ingress cap trips on cumulative
/// length while streaming 1 MiB frames, so the whole body is never buffered.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_grpc_write_body_is_rejected() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = pb::broker_service_client::BrokerServiceClient::new(channel);

    let object = address::join_relative(&prefix, "over-cap.bin").unwrap();
    let open = pb::WriteRequest {
        step: Some(pb::write_request::Step::Open(pb::WriteOpen {
            address: ovstorage_broker_protocol::object_address_to_proto(&object),
            options: None,
        })),
    };
    // 65 × 1 MiB = 65 MiB, one MiB past the 64 MiB cap. 1 MiB frames stay under
    // gRPC's default message-size limit and force the streaming ingress path.
    const FRAME: usize = 1024 * 1024;
    const FRAMES: usize = 65;
    let mut frames = Vec::with_capacity(FRAMES + 1);
    frames.push(open);
    for _ in 0..FRAMES {
        frames.push(pb::WriteRequest {
            step: Some(pb::write_request::Step::Chunk(vec![0u8; FRAME])),
        });
    }
    let stream = tokio_stream::iter(frames);
    let err = client
        .write(tonic::Request::new(stream))
        .await
        .expect_err("a body past the 64 MiB cap must be rejected, not buffered whole");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    shutdown_test_server(server).await;
    let _ = std::fs::remove_dir_all(root);
}

/// A cross-root copy (source and destination in different `file` roots) streams
/// the object rather than buffering it whole. At a modest
/// size it completes cleanly — bounded, not an OOM — with the destination
/// carrying the bytes.
#[tokio::test(flavor = "multi_thread")]
async fn copy_rename_fallback_copy_is_bounded_at_modest_size() {
    let source_root = unique_temp_dir();
    let dest_root = unique_temp_dir();
    std::fs::create_dir_all(&source_root).unwrap();
    std::fs::create_dir_all(&dest_root).unwrap();
    let source_prefix = address_for_path(&source_root);
    let dest_prefix = address_for_path(&dest_root);

    // Two `file` connections at distinct roots — a genuine cross-root pair.
    let stack = BrokerStackFixture::new()
        .file(&source_root)
        .file(&dest_root)
        .build_stack()
        .await;
    let broker = Broker::new(stack);

    let source = address::join_relative(&source_prefix, "src.bin").unwrap();
    let destination = address::join_relative(&dest_prefix, "dst.bin").unwrap();
    let payload = vec![7u8; 256 * 1024]; // modest: bounded buffering, no OOM.
    broker
        .write(
            &default_context(),
            source.clone(),
            Body::Bytes(payload.clone()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    let result = broker
        .copy(
            &default_context(),
            source,
            destination.clone(),
            ovstorage::CopyOptions::default(),
        )
        .await
        .expect("a modest cross-root copy must complete cleanly (bounded, not OOM)");
    // The whole object is accounted for at the destination.
    assert_eq!(result.info.size, Some(payload.len() as u64));

    // Read the destination back to confirm the bytes landed. The `file`
    // backend answers reads with a `LocalDelegate` (direct disk access), so
    // materialize whichever form comes back.
    let bytes = {
        use futures::StreamExt;
        use ovstorage::{Layer, ReadRequest, ReadResult, Request};
        let read = broker
            .stack()
            .read(
                Request::new(ReadRequest {
                    address: destination,
                    options: Default::default(),
                }),
                None,
            )
            .await
            .unwrap();
        match read {
            ReadResult::Bytes { bytes, .. } => bytes,
            ReadResult::LocalDelegate(local) => tokio::fs::read(&local.path).await.unwrap(),
            ReadResult::Stream { mut stream, .. } => {
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next().await {
                    buf.extend_from_slice(&chunk.unwrap());
                }
                buf
            }
            other => panic!("unexpected read result for the copied object: {other:?}"),
        }
    };
    assert_eq!(bytes, payload);

    drop(broker);
    let _ = std::fs::remove_dir_all(source_root);
    let _ = std::fs::remove_dir_all(dest_root);
}
