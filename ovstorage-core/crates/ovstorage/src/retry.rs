// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Library-side retry policy for transient backend failures.
//!
//! Per `ovstorage.md` § "Retries and idempotency" the library owns the
//! retry loop on top of the plugin SPI: plugins surface `Transient`
//! immediately and never retry internally, so observability shows one
//! logical operation with N annotated attempts.
//!
//! Two shapes:
//!
//! - [`with_retry`] / [`with_retry_async`]: pure config-driven backoff.
//! - [`with_http_retry_async`]: lets the operation surface a server-
//!   supplied `Retry-After` value that overrides the calculated delay.
//!
//! Backoff is exponential with full jitter capped at `max_delay`.

use std::time::Duration;

use ovstorage_plugin::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use tracing::{Instrument, debug, debug_span, field, warn};

use crate::metrics::{RETRY_CALLS_TOTAL, RETRY_EXHAUSTED_TOTAL, error_code_label};

/// Retry policy. Defaults match the spec.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetryConfig {
    /// First delay; subsequent delays double until `max_delay_ms`.
    #[serde(default = "default_initial_delay_ms", rename = "initial_delay_ms")]
    pub initial_delay_ms: u64,
    /// Cap on a single delay. Total wall time can exceed this.
    #[serde(default = "default_max_delay_ms", rename = "max_delay_ms")]
    pub max_delay_ms: u64,
    /// Total attempts including the first. `1` disables retry.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

fn default_initial_delay_ms() -> u64 {
    100
}
fn default_max_delay_ms() -> u64 {
    30_000
}
fn default_max_attempts() -> u32 {
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
    /// Disable retry entirely.
    pub const NONE: Self = Self {
        initial_delay_ms: 0,
        max_delay_ms: 0,
        max_attempts: 1,
    };

    pub(crate) fn validate(&self) -> Result<()> {
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

/// Whether the library retries an operation that surfaced this code.
pub fn is_retryable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Transient
            | ErrorCode::BrokerUnavailable
            | ErrorCode::ResourceExhausted
            | ErrorCode::DeadlineExceeded
            | ErrorCode::CacheLockContention
            | ErrorCode::AuthorizationLeaseExpired
    )
}

/// Run `op` with exponential-backoff retry. Non-retryable errors
/// surface immediately. Sync variant for blocking keyring / SQLite
/// callers; backend SPI calls use [`with_retry_async`].
pub fn with_retry<T, F>(config: &RetryConfig, mut op: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    with_retry_inner(config, |_attempt| op())
}

/// Async counterpart of [`with_retry`]; sleeps via `tokio::time::sleep`.
pub async fn with_retry_async<T, F, Fut>(config: &RetryConfig, mut op: F) -> Result<T>
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
            match op().await {
                Ok(value) => {
                    let s = tracing::Span::current();
                    s.record("retry.attempt", attempt + 1);
                    s.record("outcome", "ok");
                    return Ok(value);
                }
                Err(error) => {
                    attempt = attempt.saturating_add(1);
                    let code = error.code();
                    if !is_retryable(code) || attempt >= cap {
                        let s = tracing::Span::current();
                        s.record("retry.attempt", attempt);
                        s.record("outcome", "err");
                        if is_retryable(code) {
                            warn!(
                                retry.attempt = attempt,
                                retry.max = cap,
                                error.code = ?code,
                                "retry exhausted"
                            );
                            metrics::counter!(RETRY_EXHAUSTED_TOTAL, "error_code" => error_code_label(code)).increment(1);
                        }
                        return Err(error);
                    }
                    metrics::counter!(RETRY_CALLS_TOTAL, "error_code" => error_code_label(code)).increment(1);
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

/// Outcome of one HTTP-style attempt, fed to [`with_http_retry_async`].
pub enum RetryStep<T> {
    /// Success — return value to caller.
    Done(T),
    /// Non-retryable error — propagate immediately.
    Failed(Error),
    /// Retryable error; optional server-supplied delay overrides
    /// the calculated backoff.
    RetryAfter(Error, Option<Duration>),
}

/// HTTP-shaped retry: a server-supplied `Retry-After` Duration
/// overrides the calculated delay. `attempt` is 0-based.
pub async fn with_http_retry_async<T, F, Fut>(config: &RetryConfig, mut op: F) -> Result<T>
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
            let step = op(attempt).await;
            attempt = attempt.saturating_add(1);
            match step {
                RetryStep::Done(value) => {
                    let s = tracing::Span::current();
                    s.record("retry.attempt", attempt);
                    s.record("outcome", "ok");
                    return Ok(value);
                }
                RetryStep::Failed(error) => {
                    let s = tracing::Span::current();
                    s.record("retry.attempt", attempt);
                    s.record("outcome", "err");
                    return Err(error);
                }
                RetryStep::RetryAfter(error, hint) => {
                    let code = error.code();
                    if attempt >= cap {
                        let s = tracing::Span::current();
                        s.record("retry.attempt", attempt);
                        s.record("outcome", "err");
                        warn!(
                            retry.attempt = attempt,
                            retry.max = cap,
                            error.code = ?code,
                            "retry exhausted"
                        );
                        metrics::counter!(RETRY_EXHAUSTED_TOTAL, "error_code" => error_code_label(code)).increment(1);
                        return Err(error);
                    }
                    metrics::counter!(RETRY_CALLS_TOTAL, "error_code" => error_code_label(code)).increment(1);
                    let delay = match hint {
                        Some(server_hint) => server_hint.min(max_delay),
                        None => jittered(next_delay),
                    };
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

fn with_retry_inner<T, F>(config: &RetryConfig, mut op: F) -> Result<T>
where
    F: FnMut(u32) -> Result<T>,
{
    let span = debug_span!(
        "retry.with_retry",
        retry.max = config.max_attempts,
        retry.attempt = field::Empty,
        outcome = field::Empty,
    );
    let _enter = span.enter();
    let mut attempt = 0_u32;
    let mut next_delay = Duration::from_millis(config.initial_delay_ms);
    let max_delay = Duration::from_millis(config.max_delay_ms);
    let cap = config.max_attempts.max(1);
    loop {
        match op(attempt) {
            Ok(value) => {
                span.record("retry.attempt", attempt + 1);
                span.record("outcome", "ok");
                return Ok(value);
            }
            Err(error) => {
                attempt = attempt.saturating_add(1);
                let code = error.code();
                if !is_retryable(code) || attempt >= cap {
                    span.record("retry.attempt", attempt);
                    span.record("outcome", "err");
                    if is_retryable(code) {
                        warn!(
                            retry.attempt = attempt,
                            retry.max = cap,
                            error.code = ?code,
                            "retry exhausted"
                        );
                    }
                    return Err(error);
                }
                let delay = jittered(next_delay);
                debug!(
                    retry.attempt = attempt,
                    retry.delay_ms = delay.as_millis() as u64,
                    error.code = ?code,
                    "retrying"
                );
                std::thread::sleep(delay);
                next_delay = (next_delay * 2).min(max_delay);
            }
        }
    }
}

/// Full jitter so concurrent retriers don't synchronize.
fn jittered(cap: Duration) -> Duration {
    let cap_nanos = cap.as_nanos() as u64;
    if cap_nanos == 0 {
        return Duration::ZERO;
    }
    let pick = pseudo_random_u64() % cap_nanos;
    Duration::from_nanos(pick)
}

/// Not cryptographic; biased low-order bits don't matter for jitter.
fn pseudo_random_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xBAD_F00D)
            .max(1);
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fast_config() -> RetryConfig {
        RetryConfig {
            initial_delay_ms: 0,
            max_delay_ms: 0,
            max_attempts: 5,
        }
    }

    #[test]
    fn succeeds_on_first_attempt_without_sleeping() {
        let calls = AtomicU32::new(0);
        let result: Result<u32> = with_retry(&fast_config(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(42)
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retries_on_transient_until_success() {
        let calls = AtomicU32::new(0);
        let result: Result<u32> = with_retry(&fast_config(), || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(Error::new(ErrorCode::Transient, "blip"))
            } else {
                Ok(7)
            }
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn surfaces_after_max_attempts() {
        let calls = AtomicU32::new(0);
        let result: Result<()> = with_retry(&fast_config(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(ErrorCode::Transient, "always blips"))
        });
        assert_eq!(result.unwrap_err().code(), ErrorCode::Transient);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn does_not_retry_non_transient_errors() {
        let calls = AtomicU32::new(0);
        let result: Result<()> = with_retry(&fast_config(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(ErrorCode::NotFound, "gone"))
        });
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retries_union_retryable_codes() {
        for code in [
            ErrorCode::BrokerUnavailable,
            ErrorCode::ResourceExhausted,
            ErrorCode::DeadlineExceeded,
            ErrorCode::CacheLockContention,
            ErrorCode::AuthorizationLeaseExpired,
        ] {
            let calls = AtomicU32::new(0);
            let result: Result<u32> = with_retry(&fast_config(), || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n < 1 {
                    Err(Error::new(code, "blip"))
                } else {
                    Ok(1)
                }
            });
            assert_eq!(result.unwrap(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_retry_honors_retry_after_hint() {
        let calls = AtomicU32::new(0);
        let result: Result<u32> = with_http_retry_async(&fast_config(), |_attempt| async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n < 1 {
                RetryStep::RetryAfter(
                    Error::new(ErrorCode::Transient, "rate-limited"),
                    Some(Duration::ZERO),
                )
            } else {
                RetryStep::Done(99)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 99);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn validate_rejects_zero_attempts() {
        let bad = RetryConfig {
            max_attempts: 0,
            ..RetryConfig::default()
        };
        assert!(bad.validate().is_err());
    }
}
