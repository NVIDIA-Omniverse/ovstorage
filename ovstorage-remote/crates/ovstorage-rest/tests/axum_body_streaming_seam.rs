// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming-invariant test for the REST PUT seam: an axum chunked
//! request body must propagate to the backend chunk-by-chunk via the
//! mpsc bridge (see `objects.rs:114-135`), never accumulate into a Vec.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body as AxumBody;
use axum::http::{Method, Request, StatusCode};
use bytes::Bytes;
use futures::stream;
use ovstorage::{Library, Storage as _};
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, RecordingStreamFactory, StreamingRecorder,
    assert_streaming_invariants, recording_stream_connection_request,
};
use ovstorage_rest::router;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread")]
async fn rest_put_propagates_chunked_body_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());
    let library = Library::builder()
        .register_backend_factory(Arc::new(RecordingStreamFactory::new(recorder.clone())))
        .open()
        .expect("library open");
    library
        .add_connection(recording_stream_connection_request("rec://root/"), None)
        .await
        .expect("add_connection");

    let app = router(library.clone(), None, None);

    // Build a chunked request body with `num_chunks` distinct chunks.
    // axum reads chunks from the stream as the seam pulls them, so the
    // recorder timestamps (paced by the backend's per-chunk sleep)
    // catch any host-side accumulation.
    let chunks: Vec<Result<Bytes, Infallible>> = (0..DEFAULT_NUM_CHUNKS)
        .map(|i| Ok(Bytes::from(vec![i as u8; DEFAULT_CHUNK_SIZE])))
        .collect();
    let body = AxumBody::from_stream(stream::iter(chunks));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/objects?dest=rec://root/streamed.bin")
                .header("content-type", "application/octet-stream")
                .body(body)
                .unwrap(),
        )
        .await
        .expect("PUT response");
    assert_eq!(response.status(), StatusCode::OK);

    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        Duration::from_micros(100),
        Some(DEFAULT_CHUNK_SIZE * 2),
    );
}
