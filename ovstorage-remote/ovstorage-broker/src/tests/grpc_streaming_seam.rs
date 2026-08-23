// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Body-selection tests for the broker gRPC write RPC. Sub-threshold bodies
//! coalesce into replayable bytes; over-threshold bodies propagate to the
//! backend chunk-by-chunk through the bounded bridge.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::{Body, LoadedLayerFactory};
use ovstorage_plugin::{Url, WriteOptions};
use ovstorage_plugin_test::streaming::{
    RecordingStreamLayerFactory, StreamingRecorder, assert_streaming_invariants, make_test_stream,
    recording_stream_connection_request,
};

use super::*;

/// 32 chunks × 64 KiB = 2 MiB. Every source chunk streams through to the
/// backend as its own observation — 32 in total. Buffering the whole body
/// would yield one observation instead.
const STREAM_CHUNKS: usize = 32;
const STREAM_CHUNK_SIZE: usize = 64 * 1024;
const EXPECTED_OBSERVATIONS: usize = STREAM_CHUNKS;

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_propagates_body_stream_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());

    let factory = Arc::new(RecordingStreamLayerFactory::new(recorder.clone()));
    let broker_stack = BrokerStackFixture::new()
        .extra_factory(LoadedLayerFactory::Backend(factory))
        .connection(recording_stream_connection_request("rec://root/"))
        .build_stack()
        .await;

    let broker = Arc::new(Broker::new(broker_stack));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let address = Url::parse("rec://root/object").unwrap();
    let stream = make_test_stream(STREAM_CHUNKS, STREAM_CHUNK_SIZE);
    ovstorage::ext::LayerExt::write(
        &*client,
        address,
        Body::Stream(stream),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("client write Body::Stream through broker gRPC");

    // Skip the in-flight bound: the broker mpsc (cap 16) plus the
    // gRPC client's own buffering can put up to ~16 chunks in flight,
    // which is correct streaming behavior, not buffering. Time-spread
    // is the unambiguous buffering signal.
    assert_streaming_invariants(
        &recorder,
        EXPECTED_OBSERVATIONS,
        Duration::from_micros(100),
        None,
    );

    shutdown_test_server(server).await;
}

/// 4 chunks × 64 KiB = 256 KiB, below `WRITE_STREAM_THRESHOLD` (1 MiB).
const SMALL_WRITE_CHUNKS: usize = 4;
const SMALL_WRITE_CHUNK_SIZE: usize = 64 * 1024;

/// A write whose total stays below
/// `WRITE_STREAM_THRESHOLD` is coalesced at the gRPC seam into a single
/// replayable `Body::Bytes` — the backend observes ONE write, not one per source
/// chunk. That single-buffer dispatch is what lets the in-stack route-retry
/// wrapper replay a small write; the large-body test above proves multi-MiB
/// writes still stream frame-by-frame.
#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_small_write_coalesces_into_bytes() {
    let recorder = Arc::new(StreamingRecorder::new());
    let factory = Arc::new(RecordingStreamLayerFactory::new(recorder.clone()));
    let broker_stack = BrokerStackFixture::new()
        .extra_factory(LoadedLayerFactory::Backend(factory))
        .connection(recording_stream_connection_request("rec://root/"))
        .build_stack()
        .await;

    let broker = Arc::new(Broker::new(broker_stack));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let client = broker_client_stack(&discovery_url).await;

    let address = Url::parse("rec://root/small").unwrap();
    let stream = make_test_stream(SMALL_WRITE_CHUNKS, SMALL_WRITE_CHUNK_SIZE);
    ovstorage::ext::LayerExt::write(
        &*client,
        address,
        Body::Stream(stream),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("small client write through broker gRPC");

    let observed = recorder.observations();
    assert_eq!(
        observed.len(),
        1,
        "a sub-threshold write must be coalesced into one Body::Bytes (retryable), \
         got {} observations",
        observed.len()
    );
    let total: usize = observed.iter().map(|c| c.size).sum();
    assert_eq!(
        total,
        SMALL_WRITE_CHUNKS * SMALL_WRITE_CHUNK_SIZE,
        "the coalesced body must carry every source byte"
    );

    shutdown_test_server(server).await;
}
