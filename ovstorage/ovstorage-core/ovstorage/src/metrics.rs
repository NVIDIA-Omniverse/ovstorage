// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Metric name constants and one-time describe_* registrations for the
// core ovstorage library. Call `describe_metrics()` once at startup
// (init_tracing already does this). Embedders that install their own
// recorder before calling describe_metrics get the descriptions; those
// that install after still get the correct data, just without
// human-readable descriptions.

use metrics::{Unit, describe_counter, describe_histogram};

// --- SPI dispatch (v2 plugin FFI) ---

pub const SPI_CALLS_TOTAL: &str = "ovstorage_spi_calls_total";
pub const SPI_DURATION_SECONDS: &str = "ovstorage_spi_duration_seconds";

// --- Retry ---

pub const RETRY_CALLS_TOTAL: &str = "ovstorage_retry_calls_total";
pub const RETRY_EXHAUSTED_TOTAL: &str = "ovstorage_retry_exhausted_total";

// --- hub_cache ---

pub const HUB_CACHE_REQUESTS_TOTAL: &str = "ovstorage_hub_cache_requests_total";
pub const HUB_CACHE_LOOKUP_DURATION_SECONDS: &str = "ovstorage_hub_cache_lookup_duration_seconds";
pub const HUB_CACHE_FILLS_TOTAL: &str = "ovstorage_hub_cache_fills_total";

/// Register human-readable descriptions for all ovstorage library
/// metrics. Safe to call before or after a recorder is installed.
pub fn describe_metrics() {
    describe_counter!(
        SPI_CALLS_TOTAL,
        "Total SPI calls dispatched to a storage backend plugin, by op and outcome."
    );
    describe_histogram!(
        SPI_DURATION_SECONDS,
        Unit::Seconds,
        "Wall-clock latency of individual SPI calls to storage backend plugins."
    );
    describe_counter!(
        RETRY_CALLS_TOTAL,
        "Retry attempts (per-backoff-step) for retryable SPI errors."
    );
    describe_counter!(
        RETRY_EXHAUSTED_TOTAL,
        "SPI calls where retry was exhausted without success."
    );
    describe_counter!(
        HUB_CACHE_REQUESTS_TOTAL,
        "hub_cache layer lookups by op, outcome (hit/miss/bypass), and reason."
    );
    describe_histogram!(
        HUB_CACHE_LOOKUP_DURATION_SECONDS,
        Unit::Seconds,
        "Wall-clock latency of a hub_cache lookup from entry to its hit/miss/bypass classification, by op."
    );
    describe_counter!(
        HUB_CACHE_FILLS_TOTAL,
        "hub_cache fill attempts by op, outcome (committed/aborted/skipped), and reason."
    );
}

/// Convert an `ErrorCode` into a low-cardinality Prometheus label value.
pub fn error_code_label(code: ovstorage_plugin::ErrorCode) -> &'static str {
    use ovstorage_plugin::ErrorCode;
    match code {
        ErrorCode::NotFound => "not_found",
        ErrorCode::AlreadyExists => "already_exists",
        ErrorCode::PermissionDenied => "permission_denied",
        ErrorCode::InvalidArgument => "invalid_argument",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::Internal => "internal",
        ErrorCode::Transient => "transient",
        ErrorCode::BrokerUnavailable => "broker_unavailable",
        ErrorCode::ResourceExhausted => "resource_exhausted",
        ErrorCode::NoRoute => "no_route",
        ErrorCode::IntegrityFailure => "integrity_failure",
        _ => "other",
    }
}
