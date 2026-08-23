// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `RetryWrapper` applies transient-error
//! backoff through the [`WrapperFactory`] trait. It retries single-shot,
//! replayable operations (read/stat/list/delete/copy/...) and does **not** retry
//! the non-replayable streamed writes (`write_stream`) or the multi-round
//! redirect ops. See the [module docs](super) for the default-Stack order.

use async_trait::async_trait;
use ovstorage_retry::{RetryConfig, with_retry_async};
use std::sync::Arc;

use crate::layers::{RETRY_KIND, descriptor};
use crate::*;

use super::config_u64;

/// Read a [`RetryConfig`] from a wrapper's [`LayerConfig`], falling back to
/// the spec defaults for any absent key. The three keys mirror the
/// `RetryConfig` field names (`initial_delay_ms`, `max_delay_ms`,
/// `max_attempts`); each must be a non-negative integer. The result is
/// validated, so a wrapper with `max_attempts = 0` or `initial_delay_ms >
/// max_delay_ms` fails at build time rather than misbehaving at runtime.
fn retry_config_from(config: &LayerConfig) -> Result<RetryConfig> {
    let mut retry = RetryConfig::default();
    if let Some(value) = config.get("initial_delay_ms") {
        retry.initial_delay_ms = config_u64(value, "initial_delay_ms")?;
    }
    if let Some(value) = config.get("max_delay_ms") {
        retry.max_delay_ms = config_u64(value, "max_delay_ms")?;
    }
    if let Some(value) = config.get("max_attempts") {
        retry.max_attempts = config_u32(value, "max_attempts")?;
    }
    retry.validate()?;
    Ok(retry)
}

fn config_u32(value: &ConfigValue, key: &str) -> Result<u32> {
    let n = config_u64(value, key)?;
    u32::try_from(n).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("retry config `{key}` exceeds the supported maximum"),
        )
    })
}

/// [`WrapperFactory`] for the `retry` wrapper kind ([`RETRY_KIND`]).
pub struct RetryWrapperFactory;

#[async_trait]
impl WrapperFactory for RetryWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor(RETRY_KIND, LayerType::Wrapper, false)
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let retry = retry_config_from(config)?;
        Ok(Arc::new(RetryWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            retry,
        }))
    }
}

/// Retries transient backend failures with exponential backoff. Only the
/// replayable, single-shot operations are retried; streamed writes and the
/// multi-round redirect ops are forwarded unretried.
struct RetryWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    retry: RetryConfig,
}

/// Wrap a single inner-Layer call in the retry loop. Each attempt clones the
/// owned inputs into a fresh `'static` future, so a non-`Clone` request never
/// reaches this macro.
macro_rules! retried {
    ($self:ident, $cancel:ident, $method:ident, $request:expr) => {{
        let request = $request;
        with_retry_async(&$self.retry, || {
            let inner = Arc::clone(&$self.inner);
            let request = request.clone();
            let cancel = $cancel.clone();
            async move { inner.$method(request, cancel).await }
        })
        .await
    }};
}

#[async_trait]
impl Layer for RetryWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Pass-through slots delegate to `inner` via the trait defaults — that
    /// includes the deliberately unretried, non-replayable operations
    /// (`write_stream` and the multi-round redirect ops).
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    // --- retried operations -------------------------------------------------

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        retried!(self, cancel, stat, request)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        retried!(self, cancel, read, request)
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Only buffered (`Body::Bytes`) writes are replayable. `Body::LocalFile`
        // and `Body::Stream` pass through on a single attempt.
        let Request { extensions, input } = request;
        let WriteRequest {
            address,
            body,
            options,
        } = input;
        match body {
            Body::Bytes(bytes) => {
                with_retry_async(&self.retry, || {
                    let inner = Arc::clone(&self.inner);
                    let cancel = cancel.clone();
                    let request = Request {
                        extensions: extensions.clone(),
                        input: WriteRequest {
                            address: address.clone(),
                            body: Body::Bytes(bytes.clone()),
                            options: options.clone(),
                        },
                    };
                    async move { inner.write(request, cancel).await }
                })
                .await
            }
            body => {
                self.inner
                    .write(
                        Request {
                            extensions,
                            input: WriteRequest {
                                address,
                                body,
                                options,
                            },
                        },
                        cancel,
                    )
                    .await
            }
        }
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        retried!(self, cancel, delete, request)
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        retried!(self, cancel, copy, request)
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        retried!(self, cancel, rename, request)
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        retried!(self, cancel, update_metadata, request)
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        retried!(self, cancel, check_access, request)
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        retried!(self, cancel, materialize, request)
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        retried!(self, cancel, list, request)
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        retried!(self, cancel, list_versions, request)
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        retried!(self, cancel, get_latest_version, request)
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        retried!(self, cancel, watch_directory, request)
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        retried!(self, cancel, create_directory, request)
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        retried!(self, cancel, delete_directory, request)
    }
}
