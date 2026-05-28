// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming-invariant test for the broker gRPC write RPC. Bodies
//! above `WRITE_STREAM_THRESHOLD` (1 MiB) must propagate to the
//! broker library's backend chunk-by-chunk via the mpsc bridge —
//! never accumulate into a Vec at the gRPC boundary.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::{Body, Library, Storage as _};
use ovstorage_plugin::{Url, WriteOptions};
use ovstorage_plugin_test::streaming::{
    RecordingStreamFactory, StreamingRecorder, assert_streaming_invariants, make_test_stream,
    recording_stream_connection_request,
};

use super::*;

/// 32 chunks × 64 KiB = 2 MiB, comfortably above the broker's 1 MiB
/// streaming threshold. The first 16 source chunks accumulate into
/// the threshold buffer and arrive at the backend as one merged
/// 1 MiB chunk; the remaining 16 stream through chunk-by-chunk —
/// 17 observations in total. A regression to "drain whole body to
/// Vec" would yield one observation instead.
const STREAM_CHUNKS: usize = 32;
const STREAM_CHUNK_SIZE: usize = 64 * 1024;
const EXPECTED_OBSERVATIONS: usize = 17;

#[tokio::test(flavor = "multi_thread")]
async fn broker_grpc_write_propagates_body_stream_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());

    let broker_library = Library::builder()
        .register_backend_factory(Arc::new(RecordingStreamFactory::new(recorder.clone())))
        .open_with_test_plugins();
    broker_library
        .add_connection(recording_stream_connection_request("rec://root/"), None)
        .await
        .unwrap();

    let broker = Arc::new(Broker::new(broker_library));
    let server =
        spawn_broker_grpc_tcp_listener(broker.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let discovery_url = server.endpoint_url();

    let prefix = Url::parse("rec://root/").unwrap();
    let client = Library::builder().open_with_test_plugins();
    add_broker_connection(&client, &discovery_url, &prefix).await;

    let address = Url::parse("rec://root/object").unwrap();
    let stream = make_test_stream(STREAM_CHUNKS, STREAM_CHUNK_SIZE);
    client
        .write(address, Body::Stream(stream), WriteOptions::default(), None)
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
