// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stack wrapper retry policy for transient backend failures.
//!
//! Per `ovstorage.md` § "Retries and idempotency" the retry Layer owns the
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

use ovstorage_plugin::{ErrorCode, Result};
use tracing::{debug, debug_span, field, warn};

pub use ovstorage_retry::{RetryConfig, RetryStep, with_http_retry_async, with_retry_async};

/// Whether the library retries an operation that surfaced this code.
pub fn is_retryable(code: ErrorCode) -> bool {
    code.retryable()
}

/// Run `op` with exponential-backoff retry. Non-retryable errors
/// surface immediately. Sync variant for blocking keyring / SQLite
/// callers; backend SPI calls use [`with_retry_async`].
///
/// # Errors
///
/// Propagates any error from `op`, either immediately (non-retryable) or
/// after `config.max_attempts` attempts (retryable).
pub fn with_retry<T, F>(config: &RetryConfig, mut op: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    with_retry_inner(config, |_attempt| op())
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
    use ovstorage_plugin::Error;
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
