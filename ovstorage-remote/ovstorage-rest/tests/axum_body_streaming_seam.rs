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
use ovstorage::LoadedLayerFactory;
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, RecordingStreamLayerFactory, StreamingRecorder,
    assert_streaming_invariants, recording_stream_connection_request,
};
use ovstorage_rest::{GatewayStackBuilder, rest_stack_config, router};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread")]
async fn rest_put_propagates_chunked_body_chunk_by_chunk() {
    let recorder = Arc::new(StreamingRecorder::new());
    // Register the in-process ABI-v2 recording backend directly in the
    // gateway Stack.
    let factory = Arc::new(RecordingStreamLayerFactory::new(recorder.clone()));
    // SAFETY: the build-script fixture contains only workspace-built core/HTTP
    // utility plugins and the conformance backend. The in-process recorder
    // overrides the fixture backend for this test.
    let gateway = unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(std::path::PathBuf::from(env!(
                "OVSTORAGE_REST_TEST_PLUGIN_DIR"
            )))
            .allow_test_plugins(true)
            .extra_factory(LoadedLayerFactory::Backend(factory))
            .auth_config({
                // Explicit anonymous allow-all — this test exercises the data
                // plane, not authz (fail-closed).
                let mut config = ovstorage::LayerConfig::new();
                config.insert(
                    ovstorage_authz_layer::POLICY_CONFIG_KEY.to_string(),
                    ovstorage::ConfigValue::Toml(
                        ovstorage_authz_layer::ANONYMOUS_ALLOW_ALL_POLICY.to_string(),
                    ),
                );
                config
            })
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    recording_stream_connection_request("rec://root/"),
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .expect("gateway build")
    };

    let app = router(gateway);

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
