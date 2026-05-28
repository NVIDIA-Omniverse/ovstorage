// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Axum middleware that emits `ovstorage_rest_*` metrics for every
//! handled request. Uses templated routes (not substituted paths) as
//! the `route` label to prevent high-cardinality explosions.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

const REQUESTS_TOTAL: &str = "ovstorage_rest_requests_total";
const REQUEST_DURATION_SECONDS: &str = "ovstorage_rest_request_duration_seconds";

pub fn describe_rest_metrics() {
    metrics::describe_counter!(
        REQUESTS_TOTAL,
        "Total REST requests by route, method, and status class."
    );
    metrics::describe_histogram!(
        REQUEST_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Wall-clock latency of REST requests."
    );
}

pub async fn record_request_metrics(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_owned();
    // MatchedPath is the templated route (e.g. `/v1/objects/{address}`),
    // not the substituted path. Falls back to `req.uri().path()` for
    // unmatched requests (e.g. 404s), trimmed to prevent unbounded cardinality.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".to_owned());

    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status_class = match response.status().as_u16() {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };

    metrics::counter!(REQUESTS_TOTAL, "route" => route.clone(), "method" => method.clone(), "status_class" => status_class)
        .increment(1);
    metrics::histogram!(REQUEST_DURATION_SECONDS, "route" => route, "method" => method)
        .record(elapsed);

    response
}
