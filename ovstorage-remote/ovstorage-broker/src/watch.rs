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
    ) -> ovstorage::Result<ChangeStream> {
        let span = tracing::info_span!(
            "broker.watch",
            op = "watch_directory",
            object.address = %crate::trace::RedactedUrl(&prefix),
        );
        let _guard = span.enter();
        stack
            .watch_directory(
                ovstorage::Request {
                    extensions,
                    input: WatchDirectoryRequest {
                        prefix,
                        options: opts,
                    },
                },
                Some(self.shutdown.child_token()),
            )
            .await
    }
}

impl Drop for WatchDirectoryState {
    fn drop(&mut self) {
        self.cancel_all();
    }
}
