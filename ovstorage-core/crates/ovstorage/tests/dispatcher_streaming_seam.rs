// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming-invariant test for the dispatcher seam: `Library::write`
//! → `Backend::write_stream` must propagate `Body::Stream` chunk-by-
//! chunk, not drain to a Vec.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::{Body, Library, Storage as _};
use ovstorage_plugin::{Url, WriteOptions};
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, RecordingStreamFactory, StreamingRecorder,
    assert_streaming_invariants, make_test_stream, recording_stream_connection_request,
};

#[tokio::test(flavor = "multi_thread")]
async fn dispatcher_propagates_body_stream_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());
    let library = Library::builder()
        .register_backend_factory(Arc::new(RecordingStreamFactory::new(recorder.clone())))
        .open()
        .expect("library open");

    library
        .add_connection(recording_stream_connection_request("rec://root/"), None)
        .await
        .expect("add_connection");

    let address = Url::parse("rec://root/object").expect("address");
    let stream = make_test_stream(DEFAULT_NUM_CHUNKS, DEFAULT_CHUNK_SIZE);
    library
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
