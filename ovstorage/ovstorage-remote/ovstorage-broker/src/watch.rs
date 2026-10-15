// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use tokio_util::sync::CancellationToken;

/// Owns broker-process cancellation for live watch RPCs.
///
/// Concurrent-subscription coalescing is a backend concern: a competing-consumer
/// backend self-coalesces via the SDK `WatchCoalescer`. Keeping shutdown here
/// lets tonic drain terminate every current and future RPC without duplicating
/// that transport machinery.
pub(crate) struct WatchDirectoryState {
    shutdown: CancellationToken,
}

impl Default for WatchDirectoryState {
    fn default() -> Self {
        Self {
            shutdown: CancellationToken::new(),
        }
    }
}

impl WatchDirectoryState {
    pub(crate) fn cancel_all(&self) {
        self.shutdown.cancel();
    }

    pub(crate) async fn watch_directory(
        &self,
        stack: Arc<Stack>,
        prefix: Url,
        opts: WatchDirectoryOptions,
        extensions: ovstorage::Extensions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<(ChangeStream, CancellationToken)> {
        let span = tracing::info_span!(
            "broker.watch",
            op = "watch_directory",
            object.address = %crate::trace::RedactedUrl(&prefix),
        );
        let _guard = span.enter();
        let rpc_cancel = self.shutdown.child_token();
        if let Some(caller_cancel) = cancel {
            let bridge_cancel = rpc_cancel.clone();
            let bridge_done = bridge_cancel.clone();
            // Intentionally detached: it owns only token clones and exits as
            // soon as either the caller or the RPC cancellation fires.
            drop(tokio::spawn(async move {
                tokio::select! {
                    _ = caller_cancel.cancelled() => bridge_cancel.cancel(),
                    _ = bridge_done.cancelled() => {}
                }
            }));
        }

        let stream = match stack
            .watch_directory(
                ovstorage::Request {
                    extensions,
                    input: WatchDirectoryRequest {
                        prefix,
                        options: opts,
                    },
                },
                Some(rpc_cancel.clone()),
            )
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                rpc_cancel.cancel();
                return Err(error);
            }
        };

        // Direct in-process callers do not have a tonic response body whose
        // Drop can signal cancellation. Make every returned iterator own the
        // per-RPC token so abandoning it also unblocks a quiet backend watch.
        Ok((
            Box::new(ovstorage::cancel_on_drop(stream, rpc_cancel.clone())),
            rpc_cancel,
        ))
    }
}

impl Drop for WatchDirectoryState {
    fn drop(&mut self) {
        self.cancel_all();
    }
}
