// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use tokio_util::sync::CancellationToken;

use crate::{Error, ErrorCode, Result};

/// Race a future against a cancellation token. Cancel before
/// completion → `ErrorCode::Cancelled`. `None` → just `fut.await`.
///
/// The losing future is **dropped**, which is what makes cancellation
/// effective even against an inner factory or Layer that never observes the
/// token. Dropping does not reach across the plugin ABI: a foreign Layer whose
/// slot call is still outstanding keeps its own state alive through the
/// reference the call carries (`consume_v2::ForeignVtableLayer`), and that call
/// is signalled on the way out, so an abandoned build cannot free plugin state
/// under a live call.
///
/// # Errors
///
/// - [`ErrorCode::Cancelled`] — `cancel` fired before the future
///   completed.
/// - Any error the wrapped future returns.
pub async fn race_cancel<F, T>(cancel: Option<&CancellationToken>, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match cancel {
        Some(token) => {
            tokio::select! {
                biased;
                _ = token.cancelled() => Err(Error::new(ErrorCode::Cancelled, "cancelled by host")),
                res = fut => res,
            }
        }
        None => fut.await,
    }
}

pub struct CancelOnDrop<I> {
    iter: I,
    cancel: CancellationToken,
}

impl<I> CancelOnDrop<I> {
    pub fn new(iter: I, cancel: CancellationToken) -> Self {
        Self { iter, cancel }
    }
}

impl<I: Iterator> Iterator for CancelOnDrop<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<I> Drop for CancelOnDrop<I> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub fn cancel_on_drop<I: Iterator>(iter: I, cancel: CancellationToken) -> CancelOnDrop<I> {
    CancelOnDrop::new(iter, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_on_drop_delegates_next_unchanged() {
        let cancel = CancellationToken::new();
        let mut iter = cancel_on_drop([1, 2].into_iter(), cancel);

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn cancel_on_drop_cancels_token_on_drop() {
        let cancel = CancellationToken::new();
        let observed = cancel.clone();

        {
            let _iter = cancel_on_drop(std::iter::empty::<()>(), cancel);
            assert!(!observed.is_cancelled());
        }

        assert!(observed.is_cancelled());
    }
}
