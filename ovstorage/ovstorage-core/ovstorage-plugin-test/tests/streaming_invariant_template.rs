// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reference template for the `streaming` helper. Per-seam tests in
//! other crates copy this shape, replacing the synthetic consumer
//! with the real seam.

use std::sync::Arc;
use std::time::Duration;

use ovstorage_plugin::BodyStream;
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, StreamingRecorder, assert_streaming_invariants,
    make_test_stream,
};

// Synthetic consumer; real seam tests wrap the FFI thunk / gRPC frame
// / etc. in equivalent observation.
fn drive_streaming_consumer(mut stream: BodyStream, recorder: Arc<StreamingRecorder>) {
    while let Some(chunk) = stream.next_chunk() {
        let bytes = chunk.expect("test stream yields no errors");
        let n = bytes.len();
        recorder.record_arrival(n);
        std::thread::sleep(Duration::from_micros(50));
        recorder.record_release(n);
    }
}

#[test]
fn synthetic_seam_passes_streaming_invariants() {
    let stream = make_test_stream(DEFAULT_NUM_CHUNKS, DEFAULT_CHUNK_SIZE);
    let recorder = Arc::new(StreamingRecorder::new());
    drive_streaming_consumer(stream, recorder.clone());
    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        // 50µs per chunk * 16 ≈ 800µs total spread.
        Duration::from_micros(100),
        Some(DEFAULT_CHUNK_SIZE * 2),
    );
}

#[test]
#[should_panic(expected = "seam is buffering")]
fn synthetic_buffering_seam_fails_streaming_invariants() {
    // Buffering consumer: the bug per-seam tests catch.
    let stream = make_test_stream(DEFAULT_NUM_CHUNKS, 1024);
    let recorder = Arc::new(StreamingRecorder::new());
    let buffered: Vec<Vec<u8>> = stream.map(|r| r.unwrap()).collect();
    for chunk in &buffered {
        recorder.record_arrival(chunk.len());
        recorder.record_release(chunk.len());
    }
    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        Duration::from_micros(100),
        Some(1024 * 2),
    );
}
