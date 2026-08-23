// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming-invariant test for the Stack dispatcher seam: `LayerExt::write`
//! must propagate `Body::Stream` to the backend chunk-by-chunk, not drain it
//! to a Vec.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::ext::LayerExt as _;
use ovstorage::{Body, LayerConnectionRequest, LayerSpec, Stack};
use ovstorage_plugin::{Url, WriteOptions};
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, RecordingStreamLayerFactory, StreamingRecorder,
    assert_streaming_invariants, make_test_stream, recording_stream_connection_request,
};

#[tokio::test(flavor = "multi_thread")]
async fn dispatcher_propagates_body_stream_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());
    let stack = Stack::builder("recorder")
        .backend_factory(Arc::new(RecordingStreamLayerFactory::new(recorder.clone())))
        .layer(LayerSpec::backend("recorder", "stream-recorder"))
        .connection(LayerConnectionRequest {
            target: "recorder".into(),
            connection: recording_stream_connection_request("rec://root/"),
        })
        .build()
        .await
        .expect("build recording Stack");

    let address = Url::parse("rec://root/object").expect("address");
    let stream = make_test_stream(DEFAULT_NUM_CHUNKS, DEFAULT_CHUNK_SIZE);
    stack
        .write(address, Body::Stream(stream), WriteOptions::default(), None)
        .await
        .expect("write Body::Stream");

    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        // 50µs sleep × 16 chunks ≈ 800µs total spread; require ≥100µs.
        Duration::from_micros(100),
        Some(DEFAULT_CHUNK_SIZE * 2),
    );
}
