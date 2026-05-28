// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request tracing: wraps each handler in an `info_span` with
//! method, path, and principal so downstream `tracing` events
//! correlate with the REST request that triggered them.

use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::http::Response;
use axum::middleware::Next;
use ovstorage_authz::Principal;
use tracing::Instrument;

pub(crate) async fn span_per_request(request: Request, next: Next) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let principal = request
        .extensions()
        .get::<Principal>()
        .map(|p| p.id.clone())
        .unwrap_or_else(|| "anonymous".into());
    let span = tracing::info_span!(
        "rest.request",
        http.method = %method,
        http.path = %path,
        principal = %principal,
    );
    async move {
        tracing::info!(target: "rest", "request received");
        let started = Instant::now();
        let response = next.run(request).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            target: "rest",
            status = response.status().as_u16(),
            elapsed_ms,
            "request complete"
        );
        response
    }
    .instrument(span)
    .await
}
