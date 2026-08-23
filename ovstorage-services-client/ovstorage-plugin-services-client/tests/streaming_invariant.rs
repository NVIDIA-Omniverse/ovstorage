// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-seam `streaming_invariant` test for the omniverse-storage-service plugin's
//! `Backend::write_stream` path. The seam is the bidirectional gRPC
//! `FileObjectService::Write` stream — chunks must reach the server
//! one-by-one, never collected into a single buffer at the host.
//!
//! The recorder/assertion shapes mirror
//! `ovstorage_plugin_test::streaming` (see `ovstorage-plugin-test`'s
//! README § "Streaming seams"). They're inlined here because pulling in
//! that crate as an rlib collides at link time on the C ABI symbols
//! emitted by both plugins' Layer ABI exports.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::Stream;
use ovstorage_plugin::{
    BackendId, BodyStream, Capabilities, Error, ErrorCode, ResolvedTarget, Url, WriteOptions,
};
use ovstorage_plugin_services_client::auth::DiscoveryState;
use ovstorage_plugin_services_client::backend::OmniverseStorageBackend;
use ovstorage_plugin_services_client::transport::OmniverseStorageTransport;
use ovstorage_services_protos::nvidia::omniverse::storage::fileobject::v1alpha as fo;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

// === Streaming-invariant helpers (mirror of ovstorage_plugin_test::streaming) ===

const DEFAULT_NUM_CHUNKS: usize = 16;
const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
struct ChunkObservation {
    size: usize,
    at: Instant,
}

#[derive(Default)]
struct StreamingRecorder {
    inner: Mutex<RecorderInner>,
}

#[derive(Default)]
struct RecorderInner {
    chunks: Vec<ChunkObservation>,
    max_in_flight: usize,
    current_in_flight: usize,
}

impl StreamingRecorder {
    fn new() -> Self {
        Self::default()
    }

    fn record_arrival(&self, size: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.chunks.push(ChunkObservation {
            size,
            at: Instant::now(),
        });
        inner.current_in_flight = inner.current_in_flight.saturating_add(size);
        inner.max_in_flight = inner.max_in_flight.max(inner.current_in_flight);
    }

    fn record_release(&self, size: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.current_in_flight = inner.current_in_flight.saturating_sub(size);
    }

    fn observations(&self) -> Vec<ChunkObservation> {
        self.inner.lock().unwrap().chunks.clone()
    }

    fn max_in_flight(&self) -> usize {
        self.inner.lock().unwrap().max_in_flight
    }
}

fn assert_streaming_invariants(
    recorder: &StreamingRecorder,
    expected_chunks: usize,
    min_spread: Duration,
    max_in_flight_bound: Option<usize>,
) {
    let observed = recorder.observations();
    assert_eq!(
        observed.len(),
        expected_chunks,
        "chunk count: expected {expected_chunks}, got {}",
        observed.len()
    );
    if observed.len() > 1 {
        let spread = observed
            .last()
            .unwrap()
            .at
            .duration_since(observed.first().unwrap().at);
        assert!(
            spread >= min_spread,
            "chunks arrived all at once (spread {spread:?} < {min_spread:?}): seam is buffering"
        );
    }
    if let Some(bound) = max_in_flight_bound {
        assert!(
            recorder.max_in_flight() <= bound,
            "max in-flight bytes {} exceeded bound {}",
            recorder.max_in_flight(),
            bound
        );
    }
}

// === Recording fake server ===

struct RecordingService {
    recorder: Arc<StreamingRecorder>,
    completed: Arc<Mutex<bool>>,
}

#[tonic::async_trait]
impl fo::file_object_service_server::FileObjectService for RecordingService {
    type EnumerateStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::EnumerateResponse, Status>> + Send>>;
    type ReadStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::ReadResponse, Status>> + Send>>;
    type ReadFromAddressStream = Pin<
        Box<dyn Stream<Item = std::result::Result<fo::ReadFromAddressResponse, Status>> + Send>,
    >;
    type WriteStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::WriteResponse, Status>> + Send>>;

    async fn enumerate(
        &self,
        _req: Request<fo::EnumerateRequest>,
    ) -> std::result::Result<Response<Self::EnumerateStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn stat(
        &self,
        _req: Request<fo::StatRequest>,
    ) -> std::result::Result<Response<fo::StatResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn read(
        &self,
        _req: Request<fo::ReadRequest>,
    ) -> std::result::Result<Response<Self::ReadStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn read_from_address(
        &self,
        _req: Request<fo::ReadFromAddressRequest>,
    ) -> std::result::Result<Response<Self::ReadFromAddressStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn fetch_write_type_info(
        &self,
        _req: Request<fo::FetchWriteTypeInfoRequest>,
    ) -> std::result::Result<Response<fo::FetchWriteTypeInfoResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn write(
        &self,
        req: Request<Streaming<fo::WriteRequest>>,
    ) -> std::result::Result<Response<Self::WriteStream>, Status> {
        let mut inbound = req.into_inner();
        let recorder = self.recorder.clone();
        let completed = self.completed.clone();
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = inbound.message().await;
            while let Ok(Some(frame)) = inbound.message().await {
                if let Some(fo::write_request::WriteRequestType::Chunk(chunk)) =
                    frame.write_request_type
                {
                    let n = chunk.chunk.len();
                    recorder.record_arrival(n);
                    tokio::time::sleep(Duration::from_micros(50)).await;
                    recorder.record_release(n);
                }
            }
            *completed.lock().unwrap() = true;
            let _ = tx
                .send(Ok(fo::WriteResponse {
                    write_response_type: Some(fo::write_response::WriteResponseType::ResourceInfo(
                        fo::ResourceInfo {
                            resource_identity: Some(fo::ResourceIdentity {
                                encoded_identity: "etag".into(),
                            }),
                            metadata: Some(fo::Metadata {
                                data_object_size: Some(0),
                                last_modified_timestamp: None,
                            }),
                        },
                    )),
                }))
                .await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn complete_redirect_upload(
        &self,
        _req: Request<fo::CompleteRedirectUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteRedirectUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn upload_part(
        &self,
        _req: Request<fo::UploadPartRequest>,
    ) -> std::result::Result<Response<fo::UploadPartResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn complete_multipart_upload(
        &self,
        _req: Request<fo::CompleteMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteMultipartUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn abort_multipart_upload(
        &self,
        _req: Request<fo::AbortMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::AbortMultipartUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn delete(
        &self,
        _req: Request<fo::DeleteRequest>,
    ) -> std::result::Result<Response<fo::DeleteResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn copy(
        &self,
        _req: Request<fo::CopyRequest>,
    ) -> std::result::Result<Response<fo::CopyResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn r#move(
        &self,
        _req: Request<fo::MoveRequest>,
    ) -> std::result::Result<Response<fo::MoveResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn get_optimistic_locking_support(
        &self,
        _req: Request<fo::GetOptimisticLockingSupportRequest>,
    ) -> std::result::Result<Response<fo::GetOptimisticLockingSupportResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_stream_passes_streaming_invariants() {
    let recorder = Arc::new(StreamingRecorder::new());
    let completed = Arc::new(Mutex::new(false));
    let service = RecordingService {
        recorder: recorder.clone(),
        completed: completed.clone(),
    };
    let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
    let mut server_io = Some(server);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                fo::file_object_service_server::FileObjectServiceServer::new(service)
                    .max_decoding_message_size(16 * 1024 * 1024)
                    .max_encoding_message_size(16 * 1024 * 1024),
            )
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(
                server_io.take().unwrap(),
            )))
            .await
            .ok();
    });
    let mut client_io = Some(client);
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let io = client_io.take().expect("connector called twice");
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
        }))
        .await
        .expect("duplex connect");
    let backend = OmniverseStorageBackend::new(
        "http://duplex".into(),
        Capabilities::empty(),
        OmniverseStorageTransport::with_channel(channel, DiscoveryState::new("default")),
    );

    // 16 × 4 MiB = 64 MiB through the bidi seam.
    let body = BodyStream::from_iter(
        (0..DEFAULT_NUM_CHUNKS).map(|i| Ok(vec![i as u8; DEFAULT_CHUNK_SIZE])),
    );
    let target = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/path").unwrap(),
    };
    backend
        .write_stream(
            target,
            body,
            WriteOptions {
                size_hint: Some((DEFAULT_NUM_CHUNKS * DEFAULT_CHUNK_SIZE) as u64),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_stream ok");

    assert!(*completed.lock().unwrap(), "server saw end-of-stream");
    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        // 50µs per chunk × 16 ≈ 800µs spread; 100µs is a comfortable lower bound.
        Duration::from_micros(100),
        // mpsc channel(2) + tonic per-message → at most a few chunks in
        // flight. Generous bound to avoid flake on slow CI runners.
        Some(DEFAULT_CHUNK_SIZE * 4),
    );
    let total: usize = recorder.observations().iter().map(|o| o.size).sum();
    assert_eq!(total, DEFAULT_NUM_CHUNKS * DEFAULT_CHUNK_SIZE);
}

// === Fake server for the source-error test ===

/// Minimal FileObjectService used by
/// [`write_stream_surfaces_source_error`]. Counts received chunks
/// and signals when the inbound stream has fully closed (either via
/// clean EOS or h2 RST) so the test can wait deterministically.
struct SourceErrorService {
    chunks_received: Arc<AtomicUsize>,
    stream_closed: Arc<AtomicBool>,
}

#[tonic::async_trait]
impl fo::file_object_service_server::FileObjectService for SourceErrorService {
    type EnumerateStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::EnumerateResponse, Status>> + Send>>;
    type ReadStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::ReadResponse, Status>> + Send>>;
    type ReadFromAddressStream = Pin<
        Box<dyn Stream<Item = std::result::Result<fo::ReadFromAddressResponse, Status>> + Send>,
    >;
    type WriteStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::WriteResponse, Status>> + Send>>;

    async fn enumerate(
        &self,
        _req: Request<fo::EnumerateRequest>,
    ) -> std::result::Result<Response<Self::EnumerateStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn stat(
        &self,
        _req: Request<fo::StatRequest>,
    ) -> std::result::Result<Response<fo::StatResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn read(
        &self,
        _req: Request<fo::ReadRequest>,
    ) -> std::result::Result<Response<Self::ReadStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn read_from_address(
        &self,
        _req: Request<fo::ReadFromAddressRequest>,
    ) -> std::result::Result<Response<Self::ReadFromAddressStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn fetch_write_type_info(
        &self,
        _req: Request<fo::FetchWriteTypeInfoRequest>,
    ) -> std::result::Result<Response<fo::FetchWriteTypeInfoResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn write(
        &self,
        req: Request<Streaming<fo::WriteRequest>>,
    ) -> std::result::Result<Response<Self::WriteStream>, Status> {
        let mut inbound = req.into_inner();
        let chunks_received = self.chunks_received.clone();
        let stream_closed = self.stream_closed.clone();
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            // Skip params frame.
            let _ = inbound.message().await;
            // Drain until end-of-stream or cancellation.
            while let Ok(Some(frame)) = inbound.message().await {
                if let Some(fo::write_request::WriteRequestType::Chunk(_)) =
                    frame.write_request_type
                {
                    chunks_received.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            stream_closed.store(true, Ordering::SeqCst);
            // Don't finalize — the test asserts the client returns
            // Err regardless of whether the server would have.
            drop(tx);
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn complete_redirect_upload(
        &self,
        _req: Request<fo::CompleteRedirectUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteRedirectUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn upload_part(
        &self,
        _req: Request<fo::UploadPartRequest>,
    ) -> std::result::Result<Response<fo::UploadPartResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn complete_multipart_upload(
        &self,
        _req: Request<fo::CompleteMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteMultipartUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn abort_multipart_upload(
        &self,
        _req: Request<fo::AbortMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::AbortMultipartUploadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn delete(
        &self,
        _req: Request<fo::DeleteRequest>,
    ) -> std::result::Result<Response<fo::DeleteResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn copy(
        &self,
        _req: Request<fo::CopyRequest>,
    ) -> std::result::Result<Response<fo::CopyResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn r#move(
        &self,
        _req: Request<fo::MoveRequest>,
    ) -> std::result::Result<Response<fo::MoveResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn get_optimistic_locking_support(
        &self,
        _req: Request<fo::GetOptimisticLockingSupportRequest>,
    ) -> std::result::Result<Response<fo::GetOptimisticLockingSupportResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}

/// A failure midway through reading the body must surface to the
/// caller — the prior code stripped errors with `filter_map(item.ok())`
/// and could report `Ok(WriteResult)` for a truncated upload.
///
/// NOTE: we don't assert the server saw an RPC cancellation. tonic
/// 0.14's generated client wraps the request stream as `s.map(Ok)`,
/// so source errors cannot reach h2's error path, and dropping the
/// response future lets h2 send END_STREAM instead of RST_STREAM.
/// The OmniverseStorageService also doesn't validate received bytes
/// against `WriteParameters.data_object_size`, so a truncated upload
/// can finalize server-side. Closing that gap requires server-side
/// changes (see `ovstorage-services` filesystem_example/fileobject.py)
/// and is out of scope for this client-side fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_stream_surfaces_source_error() {
    let chunks_received = Arc::new(AtomicUsize::new(0));
    let stream_closed = Arc::new(AtomicBool::new(false));
    let service = SourceErrorService {
        chunks_received: chunks_received.clone(),
        stream_closed: stream_closed.clone(),
    };

    let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
    let mut server_io = Some(server);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                fo::file_object_service_server::FileObjectServiceServer::new(service)
                    .max_decoding_message_size(16 * 1024 * 1024)
                    .max_encoding_message_size(16 * 1024 * 1024),
            )
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(
                server_io.take().unwrap(),
            )))
            .await
            .ok();
    });
    let mut client_io = Some(client);
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let io = client_io.take().expect("connector called twice");
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
        }))
        .await
        .expect("duplex connect");
    let backend = OmniverseStorageBackend::new(
        "http://duplex".into(),
        Capabilities::empty(),
        OmniverseStorageTransport::with_channel(channel, DiscoveryState::new("default")),
    );

    // Two healthy chunks, then a read failure mid-stream.
    //
    // The error item waits for the server to surface a chunk first. A source
    // error tears the request stream down immediately, and h2 is free to drop
    // DATA frames it has not flushed yet — so the "server saw a chunk" sanity
    // check below otherwise races the teardown and observes zero chunks under
    // CPU contention. `body_stream_to_request_stream` drives this iterator on
    // a dedicated OS thread, never a runtime worker, so blocking here is safe.
    // The bounded deadline keeps a genuine regression failing rather than
    // hanging.
    let acked = chunks_received.clone();
    let body = BodyStream::from_iter(
        vec![Ok(vec![0u8; 1024]), Ok(vec![1u8; 1024])]
            .into_iter()
            .chain(std::iter::once_with(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while acked.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(Error::new(
                    ErrorCode::Transient,
                    "simulated read failure on chunk 3",
                ))
            })),
    );
    let target = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/path").unwrap(),
    };

    let result = backend
        .write_stream(
            target,
            body,
            WriteOptions {
                size_hint: Some(3 * 1024),
                ..Default::default()
            },
            None,
        )
        .await;

    let err = result.expect_err("write_stream must surface the source error");
    assert!(
        err.to_string().contains("simulated read failure"),
        "error must carry the source message: {err}",
    );

    // Give the server task a bounded window to drain — we only need
    // to confirm it received the chunks already in flight; this is
    // not asserting anything about cancellation semantics.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !stream_closed.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Sanity: the server got at least one chunk before the source
    // errored, so we know the RPC actually started.
    assert!(
        chunks_received.load(Ordering::SeqCst) >= 1,
        "server should have received at least one chunk before the source error \
         (chunks={}, stream_closed={})",
        chunks_received.load(Ordering::SeqCst),
        stream_closed.load(Ordering::SeqCst),
    );
}
