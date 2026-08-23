// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `CopyRenameFallbackWrapper` behavior: emulation of copy/rename whenever
//! the layer below declines, delegation when it does not, propagation of
//! every non-`Unsupported` error, and server-side-copy rename routing.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt as _;

use ovstorage::layers::COPY_RENAME_FALLBACK_KIND;
use ovstorage::{
    Body, CancellationToken, Capabilities, ConfigValue, CopyOptions, CopyRequest, DeleteRequest,
    Error, ErrorCode, ErrorContext, IfDestExists, Layer, LayerConfig, LayerKindDescriptor,
    LocalDelegate, ReadRequest, ReadResult, ReadStream, RenameOptions, RenameRequest, Request,
    Result, RootInfo, Url, WriteRequest, WriteResult, WriteStep,
};
use ovstorage_plugin_core::CopyRenameFallbackWrapperFactory;
use ovstorage_plugin_core::MAX_BUFFERED_TRANSFER_BYTES;

use crate::common::*;

// ---------------------------------------------------------------------------
// AliasWrapper / CopyRenameFallbackWrapper + Stack canonicalization
// ---------------------------------------------------------------------------

/// What the probe's `read` returns — the source shapes the fallback's
/// streaming path must handle.
enum SourceBody {
    /// `ReadResult::Bytes` with this content.
    Bytes(Vec<u8>),
    /// `ReadResult::Stream` yielding `chunks`, then optionally failing with
    /// `trailing_error`, then optionally never terminating (`pend`, for the
    /// cancellation test).
    Stream {
        chunks: Vec<Vec<u8>>,
        trailing_error: Option<ErrorCode>,
        pend: bool,
    },
    /// `ReadResult::LocalDelegate` pointing at this file.
    LocalFile(PathBuf),
    /// `ReadResult::LocalDelegate` pointing at this file with an UNKNOWN size
    /// (`ObjectInfo.size == None`) — exercises the buffered cap's `stat`
    /// fallback.
    LocalFileUnsized(PathBuf),
    /// `ReadResult::Stream` yielding `chunks` with an UNKNOWN size
    /// (`ObjectInfo.size == None`) — exercises the buffered cap's running-total
    /// enforcement when the source size can't be known up front.
    UnsizedStream(Vec<Vec<u8>>),
    /// `ReadResult::Stream` that panics on first poll — kills the bridge's
    /// drain task without a terminal item (the producer-death test).
    PanickingStream,
    /// `ReadResult::Stream` that pends forever, holding a [`DropFlag`] so a
    /// test can observe the bridge producer releasing the source when the
    /// consumer is dropped (early-consumer-drop test).
    PendingWithDrop(Arc<AtomicBool>),
}

/// The etag the probe reports on an injected `ObjectModified` read failure.
const INJECTED_READ_ETAG: &str = "etag-observed";

/// The recovery hint the probe attaches to an injected `ObjectModified` read
/// failure.
const INJECTED_READ_NEXT_ACTION: &str = "re-read the object and retry with the new etag";

/// Flips its flag on drop — lets a test observe that the bridge producer
/// released the (pending) source stream instead of leaking it.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A backend whose `copy`/`rename` either succeed or refuse with
/// [`Self::refusal_code`]; `read` returns a configurable [`SourceBody`] and
/// `write`/`write_stream` record what they received, so the fallback's
/// read+write is observable.
struct FallbackProbe {
    source: SourceBody,
    inner_refuses: bool,
    /// Advertised via `root_info_for` (longest-prefix match, `NoRoute`
    /// otherwise) — the Router contract the wrapper's server-side gates and
    /// destination-slot selection resolve against.
    roots: Vec<RootInfo>,
    copy_calls: AtomicUsize,
    rename_calls: AtomicUsize,
    write_calls: AtomicUsize,
    write_stream_calls: AtomicUsize,
    written: Mutex<Vec<(Url, Vec<u8>)>>,
    /// `(address, received chunks, if_dest, size_hint)` of each successful
    /// `write_stream` — chunks are kept separate so tests can assert the
    /// delivery was chunked, not one mega-chunk.
    #[allow(clippy::type_complexity)]
    stream_written: Mutex<Vec<(Url, Vec<Vec<u8>>, IfDestExists, Option<u64>)>>,
    /// Cancelled after each streamed chunk `write_stream` drains — the
    /// cancellation test's mid-stream trigger.
    cancel_on_chunk: Mutex<Option<CancellationToken>>,
    /// When set, `write_stream` rejects immediately WITHOUT draining the body —
    /// dropping the consumer while the source is still pending.
    reject_write_stream: AtomicBool,
    /// `(address, if_match)` of each `delete` the backend received — lets the
    /// rename-fallback test assert the source was deleted with its precondition.
    deleted: Mutex<Vec<(Url, Option<String>)>>,
    /// Error code `copy`/`rename` refuse with when `inner_refuses` is
    /// set. `Unsupported` is the trigger the wrapper emulates on; any other
    /// code must propagate untouched.
    refusal_code: Mutex<ErrorCode>,
    /// When set, `delete` refuses any populated `if_match` — the Nucleus /
    /// OpenDAL shape: a conditional read is accepted but a conditional delete
    /// is not, so the rename fallback reaches its final step and fails there.
    refuses_conditional_delete: AtomicBool,
    /// When set, `delete` fails with this code regardless of preconditions.
    delete_error: Mutex<Option<ErrorCode>>,
    /// `(address, if_match)` of each `read` — lets a test assert the fallback
    /// carried the caller's `if_source` onto the read half.
    reads: Mutex<Vec<(Url, Option<String>)>>,
    /// When set, `read` fails with this code.
    read_error: Mutex<Option<ErrorCode>>,
}

/// A [`test_root`] with the transfer-relevant capability bits set, so the
/// wrapper's server-side gates attempt the native ops.
fn transfer_root(prefix: &str) -> RootInfo {
    let mut root = test_root(prefix);
    root.capabilities.supports_server_side_copy = true;
    root.capabilities.supports_server_side_rename = true;
    root.capabilities.supports_copy = true;
    root.capabilities.supports_rename = true;
    root.capabilities.supports_write = true;
    root.capabilities.supports_write_stream = true;
    // The rename fallback ends in a source delete, so a root that advertises
    // rename must advertise delete too.
    root.capabilities.supports_delete = true;
    root
}

impl FallbackProbe {
    /// The standard layout: `file:///src/` and `file:///dst/` are distinct
    /// roots (a genuine cross-root pair) and `file:///d/` is a third root for
    /// same-root scenarios.
    fn new(content: &[u8], inner_refuses: bool) -> Arc<Self> {
        Self::with_roots(
            content,
            inner_refuses,
            vec![
                transfer_root("file:///src/"),
                transfer_root("file:///dst/"),
                transfer_root("file:///d/"),
            ],
        )
    }

    fn with_roots(content: &[u8], inner_refuses: bool, roots: Vec<RootInfo>) -> Arc<Self> {
        Self::with_source(SourceBody::Bytes(content.to_vec()), inner_refuses, roots)
    }

    fn with_source(source: SourceBody, inner_refuses: bool, roots: Vec<RootInfo>) -> Arc<Self> {
        Arc::new(Self {
            source,
            inner_refuses,
            roots,
            copy_calls: AtomicUsize::new(0),
            rename_calls: AtomicUsize::new(0),
            write_calls: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            written: Mutex::new(Vec::new()),
            stream_written: Mutex::new(Vec::new()),
            cancel_on_chunk: Mutex::new(None),
            reject_write_stream: AtomicBool::new(false),
            deleted: Mutex::new(Vec::new()),
            refusal_code: Mutex::new(ErrorCode::Unsupported),
            refuses_conditional_delete: AtomicBool::new(false),
            delete_error: Mutex::new(None),
            reads: Mutex::new(Vec::new()),
            read_error: Mutex::new(None),
        })
    }

    /// Make the inner `copy`/`rename` refuse with `code` instead of
    /// `Unsupported`.
    fn refuse_with(self: &Arc<Self>, code: ErrorCode) {
        *self.refusal_code.lock().unwrap() = code;
    }

    /// Make `read` fail with `code`, carrying the typed payload and recovery
    /// hint a real backend attaches (see [`Self::read`]).
    fn fail_read_with(self: &Arc<Self>, code: ErrorCode) {
        *self.read_error.lock().unwrap() = Some(code);
    }

    /// Make `delete` fail with `code`, regardless of preconditions.
    fn fail_delete_with(self: &Arc<Self>, code: ErrorCode) {
        *self.delete_error.lock().unwrap() = Some(code);
    }

    /// Make `delete` refuse a populated `if_match`, so an emulated conditional
    /// `rename` fails at its final step with the destination already written.
    fn refuse_conditional_delete(self: &Arc<Self>) {
        self.refuses_conditional_delete
            .store(true, Ordering::SeqCst);
    }

    /// Like [`Self::new`], advertising one all-covering root with
    /// `capabilities`, so the wrapper's server-side gates are observable.
    fn with_capabilities(
        content: &[u8],
        inner_refuses: bool,
        capabilities: Capabilities,
    ) -> Arc<Self> {
        Self::with_roots(
            content,
            inner_refuses,
            vec![RootInfo {
                capabilities,
                ..test_root("file:///")
            }],
        )
    }
}

#[async_trait]
impl Layer for FallbackProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        if let Some(code) = *self.read_error.lock().unwrap() {
            // Mirror what a real backend attaches to an etag mismatch: the
            // observed etag as `ErrorContext::Identity`, plus a recovery hint.
            // Both must survive the wrapper's pre-write precondition remap —
            // `new_etag` is what a caller retries a conditional copy with.
            let error = Error::new(code, "injected read failure");
            return Err(if code == ErrorCode::ObjectModified {
                error
                    .with_context(ErrorContext::Identity {
                        new_etag: Some(INJECTED_READ_ETAG.to_string()),
                    })
                    .with_next_action(INJECTED_READ_NEXT_ACTION)
            } else {
                error
            });
        }
        let address = request.input.address;
        self.reads
            .lock()
            .unwrap()
            .push((address.clone(), request.input.options.if_match));
        match &self.source {
            SourceBody::Bytes(bytes) => Ok(ReadResult::Bytes {
                bytes: bytes.clone(),
                info: object_info(address, bytes.len() as u64),
            }),
            SourceBody::Stream {
                chunks,
                trailing_error,
                pend,
            } => {
                let total: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
                let mut items: Vec<Result<bytes::Bytes>> = chunks
                    .iter()
                    .cloned()
                    .map(|chunk| Ok(bytes::Bytes::from(chunk)))
                    .collect();
                if let Some(code) = trailing_error {
                    items.push(Err(Error::new(*code, "injected mid-stream read failure")));
                }
                let items = futures::stream::iter(items);
                let stream: ReadStream = if *pend {
                    Box::pin(items.chain(futures::stream::pending()))
                } else {
                    Box::pin(items)
                };
                Ok(ReadResult::Stream {
                    stream,
                    info: object_info(address, total),
                })
            }
            SourceBody::LocalFile(path) => {
                let size = std::fs::metadata(path).unwrap().len();
                Ok(ReadResult::LocalDelegate(LocalDelegate {
                    path: path.clone(),
                    info: object_info(address, size),
                    guard: None,
                }))
            }
            SourceBody::LocalFileUnsized(path) => {
                // A `LocalDelegate` whose `ObjectInfo.size` is unknown —
                // exercises the buffered cap's `stat` fallback.
                let mut info = object_info(address, 0);
                info.size = None;
                Ok(ReadResult::LocalDelegate(LocalDelegate {
                    path: path.clone(),
                    info,
                    guard: None,
                }))
            }
            SourceBody::PanickingStream => {
                let stream: ReadStream = Box::pin(futures::stream::poll_fn(|_| {
                    panic!("injected source-stream panic")
                }));
                Ok(ReadResult::Stream {
                    stream,
                    info: object_info(address, 0),
                })
            }
            SourceBody::UnsizedStream(chunks) => {
                // Own the chunks so the mapped iterator is `'static` for the
                // boxed `ReadStream`.
                let owned = chunks.clone();
                let items = futures::stream::iter(
                    owned
                        .into_iter()
                        .map(|chunk| Ok::<_, Error>(bytes::Bytes::from(chunk))),
                );
                let mut info = object_info(address, 0);
                info.size = None;
                Ok(ReadResult::Stream {
                    stream: Box::pin(items),
                    info,
                })
            }
            SourceBody::PendingWithDrop(dropped) => {
                // Pend forever, keeping a `DropFlag` alive with the stream so
                // dropping the stream (producer released it) flips the flag.
                let flag = DropFlag(dropped.clone());
                let stream: ReadStream = Box::pin(futures::stream::poll_fn(move |_| {
                    let _ = &flag;
                    std::task::Poll::Pending
                }));
                Ok(ReadResult::Stream {
                    stream,
                    info: object_info(address, 0),
                })
            }
        }
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.copy_calls.fetch_add(1, Ordering::SeqCst);
        if self.inner_refuses {
            Err(Error::new(
                *self.refusal_code.lock().unwrap(),
                "inner copy refused",
            ))
        } else {
            Ok(WriteStep::Done(WriteResult {
                info: object_info(request.input.destination, 0),
            }))
        }
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(
        ovstorage::RootInfoSnapshot,
        Option<ovstorage::RootInfoUpdateStream>,
    )> {
        Ok((
            ovstorage::RootInfoSnapshot {
                roots: self.roots.clone(),
                updates: false,
            },
            None,
        ))
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.roots
            .iter()
            .filter(|root| ovstorage::address::is_ancestor_or_self(&root.root, url))
            .max_by_key(|root| root.root.as_str().len())
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    async fn rename(
        &self,
        _request: Request<RenameRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.rename_calls.fetch_add(1, Ordering::SeqCst);
        if self.inner_refuses {
            Err(Error::new(
                *self.refusal_code.lock().unwrap(),
                "inner rename refused",
            ))
        } else {
            Ok(())
        }
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        let WriteRequest { address, body, .. } = request.input;
        if let Body::Bytes(bytes) = body {
            self.written.lock().unwrap().push((address.clone(), bytes));
        }
        Ok(WriteResult {
            info: object_info(address, 0),
        })
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_stream_calls.fetch_add(1, Ordering::SeqCst);
        let WriteRequest {
            address,
            body,
            options,
        } = request.input;
        // Reject before draining: `body` (and its bridge receiver) drops here,
        // closing the channel while the source is still pending.
        if self.reject_write_stream.load(Ordering::SeqCst) {
            drop(body);
            return Err(Error::new(
                ErrorCode::Transient,
                "injected write_stream rejection before draining",
            ));
        }
        let cancel_on_chunk = self.cancel_on_chunk.lock().unwrap().clone();
        // Drain on the blocking pool — the `BodyStream` consumer contract
        // (the wrapper's async→sync bridge parks the pulling thread, so a
        // runtime thread must never block on `next_chunk`).
        let chunks = match body {
            Body::Stream(mut stream) => tokio::task::spawn_blocking(move || {
                let mut chunks: Vec<Vec<u8>> = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    chunks.push(chunk?);
                    if let Some(token) = &cancel_on_chunk {
                        token.cancel();
                    }
                }
                Ok::<_, Error>(chunks)
            })
            .await
            .expect("drain task panicked")?,
            _ => Vec::new(),
        };
        self.stream_written.lock().unwrap().push((
            address.clone(),
            chunks,
            options.if_dest,
            options.size_hint,
        ));
        Ok(WriteResult {
            info: object_info(address, 0),
        })
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if let Some(code) = *self.delete_error.lock().unwrap() {
            return Err(Error::new(code, "injected delete failure"));
        }
        if request.input.options.if_match.is_some()
            && self.refuses_conditional_delete.load(Ordering::SeqCst)
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "backend delete cannot express an if_match precondition",
            ));
        }
        self.deleted
            .lock()
            .unwrap()
            .push((request.input.address, request.input.options.if_match));
        Ok(())
    }
}

#[tokio::test]
async fn copy_rename_fallback_falls_back_to_read_write() {
    // A `write`-only destination takes the buffered path, because
    // `Body::Bytes` needs the whole object.
    let mut dst = transfer_root("file:///dst/");
    dst.capabilities.supports_write_stream = false;
    let backend =
        FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///src/"), dst]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: destination.clone(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    // inner.copy reported cross-root → wrapper read source + wrote destination.
    assert_eq!(backend.copy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 0);
    let written = backend.written.lock().unwrap();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].0, destination);
    assert_eq!(written[0].1, b"payload");
}

#[tokio::test]
async fn copy_rename_fallback_delegates_same_root() {
    let backend = FallbackProbe::new(b"payload", false);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    // Same-root copy delegated to inner.copy — no read+write fallback.
    assert_eq!(backend.copy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn same_root_unsupported_copy_emulates() {
    // The reported case: source and destination in ONE root, inner answering
    // `Unsupported`. The fallback must serve it — a stack that copies
    // across roots but refuses the same-root copy is the asymmetry this
    // wrapper exists to remove.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed.len(), 1, "the fallback must write the destination");
    assert_eq!(streamed[0].0, Url::parse("file:///d/b").unwrap());
}

#[tokio::test]
async fn same_root_unsupported_rename_emulates_with_source_delete() {
    // Same-root rename emulates too: copy, then delete the source. Treating
    // rename differently from copy would just relocate the asymmetry.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let deleted = backend.deleted.lock().unwrap();
    assert_eq!(
        deleted.len(),
        1,
        "the emulated rename must delete the source"
    );
    assert_eq!(deleted[0].0, Url::parse("file:///d/a").unwrap());
}

#[tokio::test]
async fn unresolvable_endpoints_still_emulate() {
    // Root resolution is not part of the trigger, so endpoints that resolve
    // to no root at all are served like any other refusal — via the
    // streaming slot, because an unresolvable destination probe must not be
    // what decides to buffer the whole object in host memory.
    let backend = FallbackProbe::with_roots(b"payload", true, Vec::new());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "an unresolvable probe must not select the unbounded buffered slot"
    );
    assert_eq!(backend.stream_written.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn non_unsupported_copy_error_propagates_without_writing() {
    // The safety property the narrowed trigger protected: only `Unsupported`
    // means "the layer below declines to perform this". A refusal — policy,
    // precondition,
    // anything else — must reach the caller with nothing written, never be
    // re-attempted as an emulated transfer that performs the very operation
    // that was denied.
    for code in [
        ErrorCode::PermissionDenied,
        ErrorCode::PreconditionFailed,
        ErrorCode::NotFound,
        ErrorCode::IncompatibleType,
    ] {
        let backend =
            FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
        backend.refuse_with(code);
        let stack = build_stack(
            COPY_RENAME_FALLBACK_KIND,
            Arc::new(CopyRenameFallbackWrapperFactory),
            backend.clone(),
            LayerConfig::new(),
        )
        .await
        .unwrap();

        let error = stack
            .copy(
                Request::new(CopyRequest {
                    source: Url::parse("file:///d/a").unwrap(),
                    destination: Url::parse("file:///d/b").unwrap(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
        assert!(backend.written.lock().unwrap().is_empty());
        assert!(backend.stream_written.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn non_unsupported_rename_error_propagates_without_source_delete() {
    // The rename-shaped hazard, preserved: a denied rename must never reach
    // the fallback, which would copy and then DELETE THE SOURCE.
    for code in [ErrorCode::PermissionDenied, ErrorCode::PreconditionFailed] {
        let backend =
            FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
        backend.refuse_with(code);
        let stack = build_stack(
            COPY_RENAME_FALLBACK_KIND,
            Arc::new(CopyRenameFallbackWrapperFactory),
            backend.clone(),
            LayerConfig::new(),
        )
        .await
        .unwrap();

        let error = stack
            .rename(
                Request::new(RenameRequest {
                    source: Url::parse("file:///d/a").unwrap(),
                    destination: Url::parse("file:///d/b").unwrap(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), code);
        assert!(
            backend.deleted.lock().unwrap().is_empty(),
            "a propagated rename error must never delete the source"
        );
        // The probe refuses `copy` with the same code, so the delete assertion
        // alone would also pass had the wrapper wrongly entered the fallback.
        // Pin the write half too.
        assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
        assert!(backend.written.lock().unwrap().is_empty());
        assert!(backend.stream_written.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn copy_rename_fallback_rename_falls_back_with_source_delete() {
    let backend = FallbackProbe::new(b"payload", true);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let source = Url::parse("file:///src/obj").unwrap();
    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .rename(
            Request::new(RenameRequest {
                source: source.clone(),
                destination: destination.clone(),
                options: RenameOptions {
                    if_source: Some("etag-1".to_string()),
                    ..RenameOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();

    // Cross-root rename = read source → write destination → delete source.
    // The destination root advertises `write_stream`, so the fallback
    // streams.
    {
        let streamed = backend.stream_written.lock().unwrap();
        assert_eq!(streamed.len(), 1);
        assert_eq!(streamed[0].0, destination);
        assert_eq!(streamed[0].1.concat(), b"payload");
    }
    // The source is deleted after the write, carrying the `if_source`
    // precondition into the delete's `if_match`.
    let deleted = backend.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].0, source);
    assert_eq!(deleted[0].1, Some("etag-1".to_string()));
}

#[tokio::test]
async fn copy_rename_fallback_fallback_promotes_to_write_stream_only_destination() {
    // Promote buffered bytes to a one-chunk stream for
    // destinations that support write_stream but not write; nothing below
    // this wrapper performs that promotion, so the wrapper must select
    // the destination root's advertised slot — carrying the body, the
    // if_dest precondition, and the request extensions intact.
    let mut dst = transfer_root("file:///dst/");
    dst.capabilities.supports_write = false;
    dst.capabilities.supports_write_stream = true;
    let backend =
        FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///src/"), dst]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: destination.clone(),
                options: CopyOptions {
                    if_dest: IfDestExists::MatchEtag("dst-etag".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "a write-stream-only destination must not see the buffered write slot"
    );
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 1);
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed.len(), 1);
    assert_eq!(streamed[0].0, destination);
    // A `ReadResult::Bytes` source is already materialized — it arrives as
    // one chunk.
    assert_eq!(streamed[0].1, vec![b"payload".to_vec()]);
    assert_eq!(
        streamed[0].2,
        IfDestExists::MatchEtag("dst-etag".to_string())
    );
}

#[tokio::test]
async fn rename_without_server_side_rename_uses_server_side_copy() {
    // The classic S3 shape: no server-side rename, but server-side copy. The
    // wrapper must route its rename fallback through `copy` — the backend's
    // native copy, never buffering the object through host memory.
    let mut caps = Capabilities::empty();
    caps.supports_server_side_copy = true;
    caps.supports_server_side_rename = false;
    caps.supports_copy = true;
    // No native rename at all, so the wrapper emulates — and must route the
    // emulation through the backend's server-side copy rather than buffering.
    caps.supports_rename = false;
    // S3 deletes, which the rename fallback's final step needs.
    caps.supports_delete = true;
    let backend = FallbackProbe::with_capabilities(b"payload", false, caps);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let source = Url::parse("file:///src/obj").unwrap();
    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .rename(
            Request::new(RenameRequest {
                source: source.clone(),
                destination,
                options: RenameOptions {
                    if_source: Some("etag-1".to_string()),
                    ..RenameOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        backend.rename_calls.load(Ordering::SeqCst),
        0,
        "root advertises no server-side rename; the backend must not see rename"
    );
    assert_eq!(
        backend.copy_calls.load(Ordering::SeqCst),
        1,
        "the fallback must use the backend's server-side copy"
    );
    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "a server-side copy must not degrade to buffered read+write"
    );
    let deleted = backend.deleted.lock().unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].0, source);
    assert_eq!(deleted[0].1, Some("etag-1".to_string()));
}

/// A cross-root pair whose destination advertises only the buffered `write`
/// slot (no `write_stream`) — the memory-scaling path the cap guards.
fn write_only_roots() -> Vec<RootInfo> {
    let mut dst = transfer_root("file:///dst/");
    dst.capabilities.supports_write_stream = false;
    vec![transfer_root("file:///src/"), dst]
}

#[tokio::test]
async fn an_empty_first_chunk_is_not_movement() {
    // `ReadStream` carries no non-empty-chunk invariant, so a backend may
    // yield `Bytes::new()` and only then report its lazily-checked
    // precondition. Zero bytes have moved, so that is still a failure to open
    // and must report like an eager backend's — otherwise, on this slot, the
    // code depends on whether a backend happens to emit an empty leading
    // chunk. The streaming slot drains inside the destination write, past any
    // remap, so it reports `ObjectModified` for the same source either way.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![vec![]],
            trailing_error: Some(ErrorCode::ObjectModified),
            pend: false,
        },
        true,
        write_only_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::PreconditionFailed,
        "an empty chunk moved nothing: {error}"
    );
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_lazily_checked_precondition_reports_like_an_eager_one() {
    // A backend may defer its `if_match` check to the first poll of a
    // `ReadResult::Stream` rather than performing it at read-open. A mismatch
    // reported there has still moved no bytes and written nothing, so it is the
    // pre-write precondition failure the native path reports — the caller must
    // not get a different code because of where inside the backend the check
    // happens to sit.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![],
            trailing_error: Some(ErrorCode::ObjectModified),
            pend: false,
        },
        true,
        write_only_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::PreconditionFailed,
        "a mismatch on the first poll moved nothing: {error}"
    );
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Buffered-transfer memory cap (write-only destinations)
// ---------------------------------------------------------------------------

/// A `LayerConfig` setting the buffered-transfer cap to `bytes`.
fn cap_config(bytes: i64) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert(MAX_BUFFERED_TRANSFER_BYTES.into(), ConfigValue::Int(bytes));
    config
}

#[tokio::test]
async fn buffered_transfer_over_cap_is_refused() {
    // A copy of an object larger than the cap to a write-only
    // destination fails with `ResourceExhausted` — refused up front from the
    // known `ObjectInfo.size`, never buffering or writing.
    let backend = FallbackProbe::with_roots(&[7u8; 100], true, write_only_roots());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        cap_config(50),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "an over-cap transfer must not reach the destination write"
    );
    assert!(backend.written.lock().unwrap().is_empty());
}

#[tokio::test]
async fn buffered_transfer_under_cap_succeeds() {
    // A transfer under the cap to a write-only destination is unaffected.
    let backend = FallbackProbe::with_roots(b"payload", true, write_only_roots());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        cap_config(1024),
    )
    .await
    .unwrap();

    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: destination.clone(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let written = backend.written.lock().unwrap();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].1, b"payload");
}

#[tokio::test]
async fn unsized_over_cap_stream_is_refused_by_running_total() {
    // When the source size is unknown (`ObjectInfo.size == None`), the cap
    // is enforced on the running total as the object buffers, so an over-cap
    // object still fails with `ResourceExhausted`.
    let backend = FallbackProbe::with_source(
        SourceBody::UnsizedStream(vec![vec![1u8; 40], vec![2u8; 40]]),
        true,
        write_only_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        cap_config(50),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsized_local_delegate_over_cap_is_refused_via_stat() {
    // A `LocalDelegate` source with an unknown size to a write-only
    // destination is `stat`-ed and refused when over cap — the buffered path
    // never slurps the whole file unbounded.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("src-object");
    std::fs::write(&path, vec![9u8; 200]).unwrap();
    let backend =
        FallbackProbe::with_source(SourceBody::LocalFileUnsized(path), true, write_only_roots());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        cap_config(50),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ResourceExhausted);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn write_stream_destination_ignores_buffered_cap() {
    // The cap gates only the buffered slot. A `write_stream`-capable
    // destination streams (bounded by chunk × channel capacity) regardless of
    // a tiny cap, so a large object transfers unaffected.
    let chunks = vec![vec![1u8; 40], vec![2u8; 40], vec![3u8; 40]];
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: chunks.clone(),
            trailing_error: None,
            pend: false,
        },
        true,
        streaming_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        cap_config(10),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "a write_stream-capable destination must not take the capped buffered slot"
    );
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 1);
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed[0].1.concat(), chunks.concat());
}
// ---------------------------------------------------------------------------
// Streamed cross-root transfers (bounded host memory)
// ---------------------------------------------------------------------------

/// The standard cross-root pair with a `write_stream`-capable destination.
fn streaming_roots() -> Vec<RootInfo> {
    vec![transfer_root("file:///src/"), transfer_root("file:///dst/")]
}

#[tokio::test]
async fn streamed_source_delivers_chunked_to_write_stream_destination() {
    // A `ReadResult::Stream` source reaches a `write_stream`-capable
    // destination chunk by chunk — never assembled into one mega-chunk, even
    // when the destination also advertises the buffered `write` slot.
    let chunks = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: chunks.clone(),
            trailing_error: None,
            pend: false,
        },
        true,
        streaming_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let destination = Url::parse("file:///dst/obj").unwrap();
    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: destination.clone(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "a write_stream-capable destination must stream, not buffer"
    );
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 1);
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed.len(), 1);
    assert_eq!(streamed[0].0, destination);
    assert_eq!(
        streamed[0].1, chunks,
        "source chunk boundaries must survive the async→sync bridge"
    );
    assert_eq!(
        streamed[0].3,
        Some(14),
        "the source's size must ride the write as size_hint"
    );
}

#[tokio::test]
async fn local_delegate_source_streams_from_file() {
    // A `LocalDelegate` source is streamed from its file in bounded
    // chunks instead of `tokio::fs::read`-ing it whole.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("src-object");
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &content).unwrap();
    let backend = FallbackProbe::with_source(SourceBody::LocalFile(path), true, streaming_roots());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed.len(), 1);
    assert!(
        streamed[0].1.len() > 1,
        "a 200 KB file must arrive in multiple bounded chunks, got {}",
        streamed[0].1.len()
    );
    assert_eq!(streamed[0].1.concat(), content);
    assert_eq!(streamed[0].3, Some(content.len() as u64));
}

#[tokio::test]
async fn mid_stream_read_error_fails_streaming_copy() {
    // A source-stream error surfaces through the bridge as the write
    // body's error — the copy fails instead of committing a truncated object.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![b"alpha".to_vec()],
            trailing_error: Some(ErrorCode::Transient),
            pend: false,
        },
        true,
        streaming_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);
    assert!(
        backend.stream_written.lock().unwrap().is_empty(),
        "a failed stream must not record a completed write"
    );
}

#[tokio::test]
async fn mid_stream_read_error_rename_does_not_delete_source() {
    // The rename-shaped hazard: a mid-stream failure aborts the destination
    // write, so the source must survive.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![b"alpha".to_vec()],
            trailing_error: Some(ErrorCode::Transient),
            pend: false,
        },
        true,
        streaming_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);
    assert!(
        backend.deleted.lock().unwrap().is_empty(),
        "a failed streaming rename must never delete the source"
    );
}

#[tokio::test]
async fn cancellation_mid_stream_fails_streaming_copy() {
    // Cancelling the operation mid-stream aborts the bridge's drain
    // task with `Cancelled` — the destination write fails rather than
    // seeing a clean (truncated) end-of-stream. The source stream never
    // terminates on its own, so only cancellation can end this copy.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![b"alpha".to_vec()],
            trailing_error: None,
            pend: true,
        },
        true,
        streaming_roots(),
    );
    let token = CancellationToken::new();
    backend
        .cancel_on_chunk
        .lock()
        .unwrap()
        .replace(token.clone());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            Some(token),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Cancelled);
    assert!(
        backend.stream_written.lock().unwrap().is_empty(),
        "a cancelled stream must not record a completed write"
    );
}

#[tokio::test]
async fn bridge_producer_death_is_an_error_not_eof() {
    // Anti-truncation guarantee: when the bridge's drain task dies
    // without sending a terminal item (here: the source stream panics on
    // first poll, unwinding the spawned task with the sender still open),
    // the consumer must see an `Internal` error on its next pull — never a
    // clean EOF that would commit a truncated destination object.
    let backend = FallbackProbe::with_source(SourceBody::PanickingStream, true, streaming_roots());
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Internal);
    assert!(
        error.to_string().contains("end-of-stream marker"),
        "producer death must surface the missing-marker error, got: {error}"
    );
    assert!(
        backend.stream_written.lock().unwrap().is_empty(),
        "a dead producer must not record a completed write"
    );
}

#[tokio::test]
async fn early_consumer_drop_releases_pending_source() {
    // The destination write rejects BEFORE draining while the source
    // stream is still pending and NO cancel token is supplied. The bridge
    // producer's only liveness fence is then consumer closure — it must
    // observe the dropped `BodyStream` via `tx.closed()` and terminate,
    // releasing the source stream/connection, instead of staying parked in
    // `stream.next()` on the stalled source and leaking the spawned task.
    let dropped = Arc::new(AtomicBool::new(false));
    let backend = FallbackProbe::with_source(
        SourceBody::PendingWithDrop(dropped.clone()),
        true,
        streaming_roots(),
    );
    backend.reject_write_stream.store(true, Ordering::SeqCst);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            // No cancel token: the producer must terminate on consumer drop
            // alone, with no cancellation to fall back on.
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Transient);

    // The producer runs on a spawned task, so poll briefly for it to observe
    // the consumer drop and release the source. Without the `tx.closed()`
    // branch it stays parked forever and this never flips.
    for _ in 0..200 {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        dropped.load(Ordering::SeqCst),
        "the bridge producer must release the pending source once the consumer \
         is dropped, rather than leaking the source stream"
    );
}

#[tokio::test]
async fn rename_refuses_up_front_when_the_source_root_cannot_delete() {
    // Without delete on the source, the emulation can never complete. Refuse
    // before writing rather than after.
    let mut root = transfer_root("file:///d/");
    root.capabilities.supports_server_side_rename = false;
    root.capabilities.supports_delete = false;
    let backend = FallbackProbe::with_roots(b"payload", true, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert_eq!(
        backend.write_calls.load(Ordering::SeqCst),
        0,
        "nothing may be written when the rename cannot complete"
    );
    assert!(backend.stream_written.lock().unwrap().is_empty());
}

#[tokio::test]
async fn root_info_raises_availability_without_touching_mechanism() {
    // The wrapper reports what it can actually serve, but must not claim the
    // backend does it natively: a caller optimizing on the server-side bits
    // has to keep seeing the truth.
    let mut root = test_root("file:///d/");
    root.capabilities.supports_write = true;
    root.capabilities.supports_delete = true;
    let backend = FallbackProbe::with_roots(b"payload", true, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let info = stack
        .root_info_for(
            &Url::parse("file:///d/a").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(info.capabilities.supports_copy, "copy is always servable");
    assert!(
        info.capabilities.supports_rename,
        "delete on the source makes an emulated rename servable"
    );
    assert!(!info.capabilities.supports_server_side_copy);
    assert!(!info.capabilities.supports_server_side_rename);
    assert!(!info.capabilities.supports_atomic_rename);
}

#[tokio::test]
async fn root_info_leaves_rename_unavailable_without_delete() {
    // No delete on the source means no emulated rename, so the availability
    // bit must stay false rather than promising something that cannot work.
    let mut root = test_root("file:///d/");
    root.capabilities.supports_write = true;
    root.capabilities.supports_delete = false;
    let backend = FallbackProbe::with_roots(b"payload", true, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let info = stack
        .root_info_for(
            &Url::parse("file:///d/a").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(info.capabilities.supports_copy);
    assert!(!info.capabilities.supports_rename);
}

#[tokio::test]
async fn emulated_rename_onto_the_same_address_never_deletes_the_object() {
    // copy-then-delete in place destroys the object: the copy writes it onto
    // itself and the delete then removes the only surviving copy. This layer
    // composes below alias rewriting, so the addresses compared here are the
    // rewritten ones and naming one object is the whole hazard.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let same = Url::parse("file:///d/a").unwrap();
    let error = stack
        .rename(
            Request::new(RenameRequest {
                source: same.clone(),
                destination: same,
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidArgument, "{error}");
    assert!(
        backend.deleted.lock().unwrap().is_empty(),
        "the object must survive"
    );
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    assert!(backend.stream_written.lock().unwrap().is_empty());
}

#[tokio::test]
async fn emulated_rename_treats_an_already_deleted_source_as_success() {
    // Another actor deleted the source between the copy and the delete. The
    // end state — destination present, source absent — is exactly what a
    // rename produces, so reporting ambiguity would send the caller hunting
    // for a duplicate that does not exist.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    backend.fail_delete_with(ErrorCode::NotFound);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.stream_written.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn emulated_rename_reports_ambiguity_for_other_delete_failures() {
    // Any other delete failure leaves the outcome genuinely unknown.
    for code in [ErrorCode::Transient, ErrorCode::PermissionDenied] {
        let backend =
            FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
        backend.fail_delete_with(code);
        let stack = build_stack(
            COPY_RENAME_FALLBACK_KIND,
            Arc::new(CopyRenameFallbackWrapperFactory),
            backend.clone(),
            LayerConfig::new(),
        )
        .await
        .unwrap();

        let error = stack
            .rename(
                Request::new(RenameRequest {
                    source: Url::parse("file:///d/a").unwrap(),
                    destination: Url::parse("file:///d/b").unwrap(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::CommitAmbiguous, "{error}");
    }
}

#[tokio::test]
async fn emulated_copy_carries_both_preconditions() {
    // The case the fallback is justified on: a backend that declines a
    // *conditional* copy still yields one, because `if_source` rides the read
    // and `if_dest` rides the write. Without asserting the read half, dropping
    // `if_source` would silently turn a conditional copy into an unconditional
    // one and every other test here would stay green.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    if_dest: IfDestExists::MatchEtag("etag-2".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap();

    let reads = backend.reads.lock().unwrap();
    assert_eq!(
        reads.as_slice(),
        &[(
            Url::parse("file:///d/a").unwrap(),
            Some("etag-1".to_string())
        )],
        "the read must carry the caller's if_source"
    );
    let streamed = backend.stream_written.lock().unwrap();
    assert_eq!(streamed.len(), 1);
    assert_eq!(
        streamed[0].2,
        IfDestExists::MatchEtag("etag-2".to_string()),
        "the write must carry the caller's if_dest"
    );
}

#[tokio::test]
async fn emulated_copy_onto_the_same_address_is_refused() {
    // In place the emulation would read and write one object, racing its own
    // read against the destination write — and a non-atomic write slot can
    // commit a truncated object.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let same = Url::parse("file:///d/a").unwrap();
    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: same.clone(),
                destination: same,
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidArgument, "{error}");
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    assert!(backend.stream_written.lock().unwrap().is_empty());
}

#[tokio::test]
async fn availability_agrees_across_both_introspection_paths() {
    // A UI building a root picker from `list_address_roots` must not grey out
    // an operation that `root_info_for` on the same root reports as available.
    let mut root = test_root("file:///d/");
    root.capabilities.supports_write = true;
    root.capabilities.supports_delete = true;
    let backend = FallbackProbe::with_roots(b"payload", true, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let point = stack
        .root_info_for(
            &Url::parse("file:///d/a").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    let (snapshot, _updates) = stack
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .unwrap();
    let listed = snapshot
        .roots
        .iter()
        .find(|r| r.root == point.root)
        .expect("the root appears in discovery");

    assert_eq!(
        (
            listed.capabilities.supports_copy,
            listed.capabilities.supports_rename
        ),
        (
            point.capabilities.supports_copy,
            point.capabilities.supports_rename
        ),
    );
    assert!(listed.capabilities.supports_copy);
}

#[tokio::test]
async fn emulated_copy_reports_a_pre_write_precondition_failure_like_the_native_path() {
    // `if_source` rides the fabricated read as `ReadOptions::if_match`, whose
    // contract is `ObjectModified`. Here the mismatch is detected before
    // anything is written, which the native path reports as
    // `PreconditionFailed` — the same failed conditional copy must not report
    // two different codes depending on who served it.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    backend.fail_read_with(ErrorCode::ObjectModified);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PreconditionFailed, "{error}");
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    assert!(backend.stream_written.lock().unwrap().is_empty());

    // Only the code is rewritten. The native path reports `PreconditionFailed`
    // carrying the observed etag, so dropping the typed payload here would
    // reintroduce the very divergence the remap closes — and leave a caller
    // retrying a conditional copy with nothing to retry against.
    assert_eq!(
        error.context(),
        Some(&ErrorContext::Identity {
            new_etag: Some(INJECTED_READ_ETAG.to_string()),
        }),
        "the remap must carry the identity context across"
    );
    assert_eq!(error.next_action(), Some(INJECTED_READ_NEXT_ACTION));
}

#[tokio::test]
async fn the_buffered_slot_remaps_a_read_open_failure_too() {
    // The sibling test drives a `write_stream`-capable destination, so it only
    // covers `read_to_body`. The buffered slot opens its read in a different
    // helper and must report the same code for the same failure — otherwise a
    // conditional copy's error depends on which slot the destination happens to
    // advertise.
    let backend = FallbackProbe::with_roots(b"payload", true, write_only_roots());
    backend.fail_read_with(ErrorCode::ObjectModified);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PreconditionFailed, "{error}");
    assert_eq!(
        error.context(),
        Some(&ErrorContext::Identity {
            new_etag: Some(INJECTED_READ_ETAG.to_string()),
        })
    );
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_object_modified_read_without_if_source_is_not_remapped() {
    // The remap answers for the caller's own precondition. With no `if_source`
    // the read carries no `if_match`, so an `ObjectModified` came from
    // something else entirely — a rejected backend-native identity token, or
    // the object moving under the read. Retagging it `PreconditionFailed`
    // would tell a caller a precondition it never supplied had failed, and a
    // retry loop keyed on that code would re-fetch an etag it does not use.
    let backend = FallbackProbe::with_roots(b"payload", true, streaming_roots());
    backend.fail_read_with(ErrorCode::ObjectModified);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ObjectModified, "{error}");
}

#[tokio::test]
async fn a_source_moving_mid_transfer_stays_object_modified() {
    // The remap covers opening the read and nothing after it. Once the
    // transfer is under way the caller's precondition has already been
    // satisfied, so a source that moves during the drain is `ObjectModified` —
    // exactly what `CopyOptions::if_source` documents, and the distinction a
    // caller needs to tell "your etag was stale" from "it went stale under
    // you".
    //
    // Drives the buffered slot, whose drain runs inside the wrapper; on the
    // streaming slot the drain happens inside the destination write, past any
    // remap at all.
    let backend = FallbackProbe::with_source(
        SourceBody::Stream {
            chunks: vec![vec![1u8; 8]],
            trailing_error: Some(ErrorCode::ObjectModified),
            pend: false,
        },
        true,
        write_only_roots(),
    );
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src/obj").unwrap(),
                destination: Url::parse("file:///dst/obj").unwrap(),
                options: CopyOptions {
                    if_source: Some("etag-1".to_string()),
                    ..CopyOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::ObjectModified,
        "a mid-transfer change must not be reported as a pre-write \
         precondition failure: {error}"
    );
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn certain_emulation_clears_the_atomicity_guarantee() {
    // A root that reports no rename of its own is never asked, so every rename
    // against it is emulated copy-then-delete. Advertising atomic rename there
    // is a promise the stack cannot keep for any call — distinct from the
    // per-request case, where the native path is usually taken.
    let mut root = test_root("file:///d/");
    root.capabilities.supports_write = true;
    root.capabilities.supports_delete = true;
    root.capabilities.supports_rename = false;
    root.capabilities.supports_server_side_rename = true;
    root.capabilities.supports_atomic_rename = true;
    let backend = FallbackProbe::with_roots(b"payload", true, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let info = stack
        .root_info_for(
            &Url::parse("file:///d/a").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(info.capabilities.supports_rename, "emulation serves it");
    assert!(
        !info.capabilities.supports_atomic_rename,
        "an always-emulated rename is never atomic"
    );
    assert!(
        !info.capabilities.supports_server_side_rename,
        "and the bytes never stay on the server"
    );
}

#[tokio::test]
async fn conditional_rename_reports_the_partial_state_rather_than_synthesizing_cas() {
    // Nucleus and OpenDAL accept a conditional read but cannot express a
    // conditional delete, so an emulated `rename(if_source)` reaches its final
    // step with the destination already committed. The wrapper must NOT
    // "finish" by re-checking the source and deleting unconditionally:
    // CONFORMANCE.md forbids synthesizing CAS from stat-then-delete, because a
    // writer landing in that window has its content removed without ever being
    // copied. Reporting the partial state is the correct trade.
    let backend = FallbackProbe::with_roots(b"payload", true, vec![transfer_root("file:///d/")]);
    backend.refuse_conditional_delete();
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: RenameOptions {
                    if_source: Some("etag-1".to_string()),
                    ..RenameOptions::default()
                },
            }),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CommitAmbiguous, "{error}");
    assert!(
        backend.deleted.lock().unwrap().is_empty(),
        "no unconditional delete may be synthesized"
    );
}

#[tokio::test]
async fn a_root_that_publishes_no_copy_or_rename_refuses_them() {
    // The self-gate contract from the other side: a route advertising the
    // operations as unavailable must refuse them rather than quietly serving
    // them. Without this, a read-only profile can be mutated through `copy`
    // and the conformance harness would not notice.
    let mut root = test_root("file:///d/");
    root.capabilities.supports_write = true;
    root.capabilities.supports_copy = false;
    root.capabilities.supports_rename = false;
    root.capabilities.supports_delete = false;
    let backend = FallbackProbe::with_roots(b"payload", false, vec![root]);
    let stack = build_stack(
        COPY_RENAME_FALLBACK_KIND,
        Arc::new(CopyRenameFallbackWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // The wrapper raises availability because it can emulate, so the caller
    // sees `copy` offered — but `rename` needs a source delete this root does
    // not have, and the wrapper must say so before writing anything.
    let error = stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///d/a").unwrap(),
                destination: Url::parse("file:///d/b").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported, "{error}");
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    assert!(backend.stream_written.lock().unwrap().is_empty());
}
