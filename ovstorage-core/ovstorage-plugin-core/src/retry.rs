// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `RetryWrapper` applies transient-error
//! backoff through the [`WrapperFactory`] trait. It retries single-shot,
//! replayable operations (read/stat/list/delete/copy/...) and does **not** retry
//! the non-replayable streamed writes (`write_stream`) or the multi-round
//! redirect ops. A streaming list retries while opening and while obtaining its
//! first item, before anything can have been delivered. Once an item has been
//! returned, stream errors are forwarded without replay. The open and
//! first-item phases each receive the configured `max_attempts` budget, so the
//! worst case is `2 * max_attempts - 1` calls to the inner `list_stream`. See
//! the [module docs](super) for the default-Stack order.

use async_trait::async_trait;
use futures::StreamExt as _;
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

    /// Retry the stream open eagerly, then retry a lazy first-poll failure when
    /// the caller first requests an item. No item has been exposed at that
    /// point, so reopening cannot duplicate output. After the first successful
    /// item, the remainder is forwarded unchanged and never reopens.
    ///
    /// Opening and first-item establishment use independent `max_attempts`
    /// budgets. The already-open stream is the first attempt of the second
    /// phase, bounding total inner opens at `2 * max_attempts - 1`.
    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        if request.input.options.max_results.is_some() || request.input.options.page_token.is_some()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }

        let initial_stream = retried!(self, cancel, list_stream, request.clone())?;
        let inner = Arc::clone(&self.inner);
        let retry = self.retry;

        // `once` does not run this future until the consumer polls the returned
        // stream, preserving the pull-demand boundary. The first retry attempt
        // consumes the stream opened above; later attempts reopen it. Once an
        // item succeeds, `chain` restores it ahead of the untouched remainder.
        let stream = futures::stream::once(async move {
            let mut initial_stream = Some(initial_stream);
            match with_retry_async(&retry, || {
                let initial_stream = initial_stream.take();
                let inner = Arc::clone(&inner);
                let request = request.clone();
                let cancel = cancel.clone();
                async move {
                    let mut stream = match initial_stream {
                        Some(stream) => stream,
                        None => inner.list_stream(request, cancel).await?,
                    };
                    match stream.next().await {
                        Some(Ok(first)) => Ok(Box::pin(
                            futures::stream::once(async move { Ok(first) }).chain(stream),
                        ) as ListStream),
                        Some(Err(error)) => Err(error),
                        None => Ok(Box::pin(futures::stream::empty()) as ListStream),
                    }
                }
            })
            .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    Box::pin(futures::stream::once(async move { Err(error) })) as ListStream
                }
            }
        })
        .flatten();
        Ok(Box::pin(stream))
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

#[cfg(test)]
mod list_stream_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::StreamExt as _;

    use super::*;

    struct ListingLayer {
        items: Vec<ObjectInfo>,
        stream_opens: AtomicUsize,
        stream_polls: Arc<AtomicUsize>,
        fail_first_open: bool,
        fail_first_poll: bool,
        fail_first_poll_nonretryable: bool,
        fail_mid_stream: bool,
    }

    impl ListingLayer {
        fn new(items: Vec<ObjectInfo>) -> Self {
            Self {
                items,
                stream_opens: AtomicUsize::new(0),
                stream_polls: Arc::new(AtomicUsize::new(0)),
                fail_first_open: false,
                fail_first_poll: false,
                fail_first_poll_nonretryable: false,
                fail_mid_stream: false,
            }
        }
    }

    #[async_trait]
    impl Layer for ListingLayer {
        fn name(&self) -> &str {
            "listing"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("listing", LayerType::Backend, false)
        }

        async fn list(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListPage> {
            Ok(ListPage {
                items: self.items.clone(),
                next_page_token: None,
            })
        }

        async fn list_stream(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListStream> {
            let open = self.stream_opens.fetch_add(1, Ordering::SeqCst);
            if self.fail_first_open && open == 0 {
                return Err(Error::new(ErrorCode::Transient, "open failed"));
            }
            let mut entries = self.items.iter().cloned().map(Ok).collect::<Vec<_>>();
            if self.fail_first_poll && open == 0 {
                entries.insert(
                    0,
                    Err(Error::new(ErrorCode::Transient, "first poll failed")),
                );
            }
            if self.fail_first_poll_nonretryable && open == 0 {
                entries.insert(
                    0,
                    Err(Error::new(ErrorCode::PermissionDenied, "access denied")),
                );
            }
            if self.fail_mid_stream {
                entries.push(Err(Error::new(ErrorCode::Transient, "mid-stream failed")));
            }
            let mut entries = entries.into_iter();
            let stream_polls = Arc::clone(&self.stream_polls);
            Ok(Box::pin(futures::stream::poll_fn(move |_| {
                stream_polls.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(entries.next())
            })))
        }
    }

    fn item(address: &str) -> ObjectInfo {
        ObjectInfo::from((
            Url::parse(address).unwrap(),
            BackendItemInfo {
                kind: ObjectKind::File,
                ..BackendItemInfo::default()
            },
        ))
    }

    fn request(options: ListOptions) -> Request<ListRequest> {
        Request::new(ListRequest {
            prefix: Url::parse("test://host/root/").unwrap(),
            options,
        })
    }

    fn wrapper(inner: LayerHandle) -> RetryWrapper {
        RetryWrapper {
            name: "retry".to_string(),
            descriptor: RetryWrapperFactory.descriptor(),
            inner,
            retry: RetryConfig {
                initial_delay_ms: 0,
                max_delay_ms: 0,
                max_attempts: 3,
            },
        }
    }

    #[tokio::test]
    async fn streaming_matches_buffered_listing() {
        let expected = vec![item("test://host/root/a"), item("test://host/root/b")];
        let retry = wrapper(Arc::new(ListingLayer::new(expected.clone())));

        let buffered = retry
            .list(request(ListOptions::default()), None)
            .await
            .unwrap()
            .items;
        let streamed = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(streamed, buffered);
        assert_eq!(streamed, expected);
    }

    #[tokio::test]
    async fn retries_open_but_never_retries_a_mid_stream_error() {
        let inner = Arc::new(ListingLayer {
            items: vec![item("test://host/root/a")],
            stream_opens: AtomicUsize::new(0),
            stream_polls: Arc::new(AtomicUsize::new(0)),
            fail_first_open: true,
            fail_first_poll: false,
            fail_first_poll_nonretryable: false,
            fail_mid_stream: true,
        });
        let retry = wrapper(inner.clone());

        let mut stream = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .expect("the transient open is retried");
        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 2);
        assert_eq!(stream.next().await.unwrap().unwrap(), inner.items[0]);

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Transient);
        assert_eq!(error.message(), "mid-stream failed");
        assert!(stream.next().await.is_none());
        assert_eq!(
            inner.stream_opens.load(Ordering::SeqCst),
            2,
            "polling a returned stream must never enter the open retry loop",
        );
    }

    #[tokio::test]
    async fn retries_a_lazy_first_poll_failure_before_delivery() {
        let inner = Arc::new(ListingLayer {
            items: vec![item("test://host/root/a")],
            stream_opens: AtomicUsize::new(0),
            stream_polls: Arc::new(AtomicUsize::new(0)),
            fail_first_open: false,
            fail_first_poll: true,
            fail_first_poll_nonretryable: false,
            fail_mid_stream: false,
        });
        let retry = wrapper(inner.clone());

        let mut stream = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .expect("opening the lazy stream succeeds");

        assert_eq!(
            inner.stream_polls.load(Ordering::SeqCst),
            0,
            "opening list_stream must not pull its first item",
        );
        assert_eq!(stream.next().await.unwrap().unwrap(), inner.items[0]);
        assert!(stream.next().await.is_none());

        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 2);
        assert_eq!(inner.stream_polls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn forwards_a_nonretryable_first_poll_failure_without_reopening() {
        let inner = Arc::new(ListingLayer {
            items: vec![item("test://host/root/a")],
            stream_opens: AtomicUsize::new(0),
            stream_polls: Arc::new(AtomicUsize::new(0)),
            fail_first_open: false,
            fail_first_poll: false,
            fail_first_poll_nonretryable: true,
            fail_mid_stream: false,
        });
        let retry = wrapper(inner.clone());

        let mut stream = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .expect("opening the lazy stream succeeds");

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert_eq!(error.message(), "access denied");
        assert!(stream.next().await.is_none());
        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn opening_does_not_poll_the_inner_stream() {
        let inner = Arc::new(ListingLayer::new(vec![item("test://host/root/a")]));
        let retry = wrapper(inner.clone());

        let mut stream = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .expect("opening the lazy stream succeeds");

        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 1);
        assert_eq!(inner.stream_polls.load(Ordering::SeqCst), 0);
        assert_eq!(stream.next().await.unwrap().unwrap(), inner.items[0]);
        assert_eq!(inner.stream_polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn empty_inner_stream_terminates_without_repolling() {
        let inner = Arc::new(ListingLayer::new(Vec::new()));
        let retry = wrapper(inner.clone());

        let mut stream = retry
            .list_stream(request(ListOptions::default()), None)
            .await
            .expect("opening the empty stream succeeds");

        assert!(stream.next().await.is_none());
        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            inner.stream_polls.load(Ordering::SeqCst),
            1,
            "the adapter must replace an exhausted inner stream with a fresh terminator",
        );
        assert!(stream.next().await.is_none());
        assert_eq!(inner.stream_polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_page_windows_without_opening_the_inner_stream() {
        let inner = Arc::new(ListingLayer::new(Vec::new()));
        let retry = wrapper(inner.clone());

        for options in [
            ListOptions {
                max_results: Some(1),
                ..ListOptions::default()
            },
            ListOptions {
                page_token: Some("next".to_string()),
                ..ListOptions::default()
            },
        ] {
            let error = match retry.list_stream(request(options), None).await {
                Ok(_) => panic!("a page window must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }
        assert_eq!(inner.stream_opens.load(Ordering::SeqCst), 0);
    }
}
