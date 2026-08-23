// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `RetryWrapper` behavior: transient backoff budget, non-retryable and
//! non-replayable pass-through, and factory config validation.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ovstorage::layers::RETRY_KIND;
use ovstorage::{Body, ErrorCode, Layer, Request, Url, WriteOptions, WriteRequest};
use ovstorage_plugin_core::RetryWrapperFactory;

use crate::common::*;

// ---------------------------------------------------------------------------
// RetryWrapper
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retry_wrapper_recovers_within_budget() {
    // Two transient failures then success, within a 5-attempt budget.
    let backend = ProbeBackend::flaky(2, ErrorCode::Transient, b"hello");
    let stack = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend.clone(),
        retry_config(5),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    assert_eq!(collect(result).await, b"hello");
    assert_eq!(backend.reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_wrapper_surfaces_after_exhausting_budget() {
    let backend = ProbeBackend::flaky(99, ErrorCode::Transient, b"unused");
    let stack = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend.clone(),
        retry_config(3),
    )
    .await
    .unwrap();

    let error = stack
        .read(read_request("probe://obj"), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_wrapper_does_not_retry_non_retryable() {
    let backend = ProbeBackend::flaky(99, ErrorCode::NotFound, b"unused");
    let stack = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend.clone(),
        retry_config(5),
    )
    .await
    .unwrap();

    let error = stack
        .read(read_request("probe://obj"), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_wrapper_does_not_retry_write_stream() {
    // Streamed writes can't be replayed, so a transient `write_stream`
    // failure surfaces on the first attempt.
    let backend = ProbeBackend::flaky(0, ErrorCode::Transient, b"");
    let stack = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend.clone(),
        retry_config(5),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"payload".to_vec()),
        options: WriteOptions::default(),
    });
    let error = stack.write_stream(request, None).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_wrapper_factory_rejects_invalid_config() {
    // `max_attempts = 0` fails `RetryConfig::validate` at build time.
    let backend = ProbeBackend::flaky(0, ErrorCode::Transient, b"");
    let result = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend,
        retry_config(0),
    )
    .await;
    let error = result.err().expect("build must reject max_attempts = 0");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn retry_wrapper_retries_buffered_write() {
    // A buffered `Body::Bytes` write IS replayable, so `RetryWrapper::write`
    // retries it (unlike the streamed `write_stream` path). Two transient
    // failures then success within a 5-attempt budget.
    let backend = FlakyWriteBackend::new(2);
    let stack = build_stack(
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        backend.clone(),
        retry_config(5),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"payload".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();
    assert_eq!(backend.writes.load(Ordering::SeqCst), 3);
}
