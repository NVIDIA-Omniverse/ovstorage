// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared retry policy and instrumentation for hosts and Layer plugins.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{Instrument, debug, debug_span, field, warn};

use ovstorage_layer::{Error, ErrorCode, Result};

/// cbindgen:ignore
/// Observability identifier, not part of the C ABI.
const RETRY_CALLS_TOTAL: &str = "ovstorage_retry_calls_total";
/// cbindgen:ignore
/// Observability identifier, not part of the C ABI.
const RETRY_EXHAUSTED_TOTAL: &str = "ovstorage_retry_exhausted_total";

/// Rust retry policy shared by hosts and plugin implementations.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetryConfig {
    #[serde(default = "default_initial_delay_ms")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

const fn default_initial_delay_ms() -> u64 {
    100
}

const fn default_max_delay_ms() -> u64 {
    30_000
}

const fn default_max_attempts() -> u32 {
    5
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: default_initial_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
            max_attempts: default_max_attempts(),
        }
    }
}

impl RetryConfig {
    pub const NONE: Self = Self {
        initial_delay_ms: 0,
        max_delay_ms: 0,
        max_attempts: 1,
    };

    /// Validate the retry bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidArgument`] for zero attempts or an initial
    /// delay above the maximum when retries are enabled.
    pub fn validate(&self) -> Result<()> {
        if self.max_attempts == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retry.max_attempts must be at least 1",
            ));
        }
        if self.initial_delay_ms > self.max_delay_ms && self.max_attempts > 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "retry.initial_delay_ms must be <= retry.max_delay_ms",
            ));
        }
        Ok(())
    }
}

pub fn is_retryable(code: ErrorCode) -> bool {
    code.retryable()
}

pub async fn with_retry_async<T, F, Fut>(config: &RetryConfig, mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let span = debug_span!(
        "retry.with_retry_async",
        retry.max = config.max_attempts,
        retry.attempt = field::Empty,
        outcome = field::Empty,
    );
    async move {
        let mut attempt = 0_u32;
        let mut next_delay = Duration::from_millis(config.initial_delay_ms);
        let max_delay = Duration::from_millis(config.max_delay_ms);
        let cap = config.max_attempts.max(1);
        loop {
            match operation().await {
                Ok(value) => {
                    tracing::Span::current().record("retry.attempt", attempt + 1);
                    tracing::Span::current().record("outcome", "ok");
                    return Ok(value);
                }
                Err(error) => {
                    attempt = attempt.saturating_add(1);
                    let code = error.code();
                    if !is_retryable(code) || attempt >= cap {
                        tracing::Span::current().record("retry.attempt", attempt);
                        tracing::Span::current().record("outcome", "err");
                        if is_retryable(code) {
                            warn!(
                                retry.attempt = attempt,
                                retry.max = cap,
                                error.code = ?code,
                                "retry exhausted"
                            );
                            metrics::counter!(
                                RETRY_EXHAUSTED_TOTAL,
                                "error_code" => error_code_label(code)
                            )
                            .increment(1);
                        }
                        return Err(error);
                    }
                    metrics::counter!(
                        RETRY_CALLS_TOTAL,
                        "error_code" => error_code_label(code)
                    )
                    .increment(1);
                    let delay = jittered(next_delay);
                    debug!(
                        retry.attempt = attempt,
                        retry.delay_ms = delay.as_millis() as u64,
                        error.code = ?code,
                        "retrying"
                    );
                    tokio::time::sleep(delay).await;
                    next_delay = (next_delay * 2).min(max_delay);
                }
            }
        }
    }
    .instrument(span)
    .await
}

/// Rust-only outcome for one HTTP retry attempt.
pub enum RetryStep<T> {
    Done(T),
    Failed(Error),
    RetryAfter(Error, Option<Duration>),
}

pub async fn with_http_retry_async<T, F, Fut>(config: &RetryConfig, mut operation: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = RetryStep<T>>,
{
    let span = debug_span!(
        "retry.with_http_retry_async",
        retry.max = config.max_attempts,
        retry.attempt = field::Empty,
        outcome = field::Empty,
    );
    async move {
        let mut attempt = 0_u32;
        let mut next_delay = Duration::from_millis(config.initial_delay_ms);
        let max_delay = Duration::from_millis(config.max_delay_ms);
        let cap = config.max_attempts.max(1);
        loop {
            let step = operation(attempt).await;
            attempt = attempt.saturating_add(1);
            match step {
                RetryStep::Done(value) => {
                    tracing::Span::current().record("retry.attempt", attempt);
                    tracing::Span::current().record("outcome", "ok");
                    return Ok(value);
                }
                RetryStep::Failed(error) => {
                    tracing::Span::current().record("retry.attempt", attempt);
                    tracing::Span::current().record("outcome", "err");
                    return Err(error);
                }
                RetryStep::RetryAfter(error, hint) => {
                    let code = error.code();
                    if attempt >= cap {
                        tracing::Span::current().record("retry.attempt", attempt);
                        tracing::Span::current().record("outcome", "err");
                        warn!(
                            retry.attempt = attempt,
                            retry.max = cap,
                            error.code = ?code,
                            "retry exhausted"
                        );
                        metrics::counter!(
                            RETRY_EXHAUSTED_TOTAL,
                            "error_code" => error_code_label(code)
                        )
                        .increment(1);
                        return Err(error);
                    }
                    metrics::counter!(
                        RETRY_CALLS_TOTAL,
                        "error_code" => error_code_label(code)
                    )
                    .increment(1);
                    let delay = hint
                        .map(|hint| hint.min(max_delay))
                        .unwrap_or_else(|| jittered(next_delay));
                    debug!(
                        retry.attempt = attempt,
                        retry.delay_ms = delay.as_millis() as u64,
                        error.code = ?code,
                        "retrying"
                    );
                    tokio::time::sleep(delay).await;
                    next_delay = (next_delay * 2).min(max_delay);
                }
            }
        }
    }
    .instrument(span)
    .await
}

fn jittered(cap: Duration) -> Duration {
    let cap_nanos = cap.as_nanos() as u64;
    if cap_nanos == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(rand::random::<u64>() % cap_nanos)
}

fn error_code_label(code: ErrorCode) -> &'static str {
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
