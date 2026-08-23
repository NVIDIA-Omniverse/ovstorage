// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::write_body::{
    AccumulateWriteChunk, WRITE_BODY_BYTE_CAP, WRITE_STREAM_THRESHOLD, WriteBodyAccumulator,
};
use tracing::Instrument;

mod auth;

use auth::{GrpcAuthStream, bridge_auth_stream, register_credential_payload_from_proto};

/// Max body bytes per `ReadResponse` frame when emitting a whole-object
/// `Bytes` read (cache hit or bounded read). tonic bounds per-frame size
/// (default 4 MiB decode limit), so a large cache cap could otherwise
/// pack a single `Bytes` body into one over-limit frame; chunking keeps
/// every frame well under that ceiling.
const READ_BODY_CHUNK_BYTES: usize = 1024 * 1024;

/// HTTP/2 PING interval for the TCP server. Symmetric with the
/// broker and `provider_omnistorage/StorageProvider.cpp:1089-1091`.
const BROKER_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Time the server waits for a PING ack before declaring a client dead.
const BROKER_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

fn blocking_recv_body_chunk(
    rx: &async_channel::Receiver<ovstorage::Result<Vec<u8>>>,
) -> Option<ovstorage::Result<Vec<u8>>> {
    if let Ok(handle) = tokio::runtime::Handle::try_current()
        && matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    {
        return tokio::task::block_in_place(|| rx.recv_blocking().ok());
    }
    rx.recv_blocking().ok()
}

/// Validated reader for the Chunk tail of one gRPC write request.
///
/// Every listener-auth mode uses this reader, keeping protocol validation,
/// cancellation mapping, empty-frame handling, and aggregate size accounting
/// at one chokepoint. Small-vs-streaming selection happens once beneath auth.
struct WriteFrameReader {
    stream: tonic::Streaming<pb::WriteRequest>,
    total: usize,
}

impl WriteFrameReader {
    fn new(stream: tonic::Streaming<pb::WriteRequest>) -> Self {
        Self { stream, total: 0 }
    }

    async fn next_chunk(&mut self) -> ovstorage::Result<Option<Vec<u8>>> {
        loop {
            let message = match self.stream.message().await {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(None),
                Err(status) if status.code() == tonic::Code::Cancelled => {
                    return Err(ovstorage::Error::new(
                        ovstorage::ErrorCode::Cancelled,
                        "client cancelled write",
                    ));
                }
                Err(status) => return Err(protocol::status_to_error(status)),
            };
            let step = message.step.ok_or_else(|| {
                ovstorage::Error::new(
                    ovstorage::ErrorCode::InvalidArgument,
                    "broker write request is missing a step",
                )
            })?;
            let chunk = match step {
                pb::write_request::Step::Open(_) => {
                    return Err(ovstorage::Error::new(
                        ovstorage::ErrorCode::InvalidArgument,
                        "write Open frame must appear exactly once",
                    ));
                }
                pb::write_request::Step::Chunk(chunk) => chunk,
                pb::write_request::Step::RedirectResults(_) => {
                    return Err(ovstorage::Error::new(
                        ovstorage::ErrorCode::InvalidArgument,
                        "redirect results must be sent with ContinueWrite",
                    ));
                }
            };
            if chunk.is_empty() {
                continue;
            }
            if self.total.saturating_add(chunk.len()) > WRITE_BODY_BYTE_CAP {
                return Err(ovstorage::Error::new(
                    ovstorage::ErrorCode::ResourceExhausted,
                    format!(
                        "write body exceeded broker buffer cap of {} bytes",
                        WRITE_BODY_BYTE_CAP
                    ),
                ));
            }
            self.total += chunk.len();
            return Ok(Some(chunk));
        }
    }
}

/// Run one validated frame reader behind the synchronous
/// [`ovstorage_plugin::BodyStream`] seam.
fn spawn_write_body_stream(
    mut reader: WriteFrameReader,
    initial_chunks: Vec<Vec<u8>>,
    wait_for_first_pull: bool,
) -> ovstorage_plugin::BodyStream {
    let (tx, rx) = async_channel::bounded::<ovstorage::Result<Vec<u8>>>(16);
    let (start, started) = if wait_for_first_pull {
        let (start, started) = oneshot::channel::<()>();
        (Some(start), Some(started))
    } else {
        (None, None)
    };
    tokio::spawn(async move {
        if let Some(started) = started
            && started.await.is_err()
        {
            return;
        }
        for chunk in initial_chunks {
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
        }
        loop {
            match reader.next_chunk().await {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = tx.send(Err(error)).await;
                    return;
                }
            }
        }
    });

    let mut start = start;
    ovstorage_plugin::BodyStream::from_iter(std::iter::from_fn(move || {
        if let Some(start) = start.take()
            && start.send(()).is_err()
        {
            return None;
        }
        blocking_recv_body_chunk(&rx)
    }))
}

/// Bridge an unread gRPC tail into a body that remains untouched until an
/// in-Stack auth wrapper delegates it.
fn lazy_write_body(stream: tonic::Streaming<pb::WriteRequest>) -> ovstorage_plugin::BodyStream {
    spawn_write_body_stream(WriteFrameReader::new(stream), Vec::new(), true)
}

/// Select replayable bytes versus a bounded stream after host preflight.
/// Threshold transitions and byte assembly live in [`WriteBodyAccumulator`],
/// shared with the beneath-plugin-auth normalizer.
async fn select_write_body(stream: tonic::Streaming<pb::WriteRequest>) -> ovstorage::Result<Body> {
    let mut reader = WriteFrameReader::new(stream);
    let mut accumulator = WriteBodyAccumulator::new(WRITE_STREAM_THRESHOLD, WRITE_BODY_BYTE_CAP);
    loop {
        let Some(chunk) = reader.next_chunk().await? else {
            return Ok(Body::Bytes(accumulator.finish()));
        };
        match accumulator.push(chunk) {
            AccumulateWriteChunk::Continue => {}
            AccumulateWriteChunk::Stream(prefix) => {
                return Ok(Body::Stream(spawn_write_body_stream(reader, prefix, false)));
            }
            AccumulateWriteChunk::CapExceeded => {
                return Err(ovstorage::Error::new(
                    ovstorage::ErrorCode::ResourceExhausted,
                    format!(
                        "write body exceeded broker buffer cap of {} bytes",
                        WRITE_BODY_BYTE_CAP
                    ),
                ));
            }
        }
    }
}

fn write_response_from_outcome(outcome: BrokerWriteOutcome) -> pb::WriteResponse {
    match outcome {
        BrokerWriteOutcome::Done(result) => pb::WriteResponse {
            step: Some(pb::write_response::Step::Done(
                protocol::write_result_to_proto(&result),
            )),
        },
        BrokerWriteOutcome::Redirects(batch) => pb::WriteResponse {
            step: Some(pb::write_response::Step::Redirects(
                protocol::write_redirect_batch_to_proto(&batch),
            )),
        },
    }
}

pub struct BrokerGrpcServer {
    local_addr: Option<SocketAddr>,
    endpoint_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    drained: Option<oneshot::Receiver<()>>,
    broker_handle: BrokerHandle,
}

impl BrokerGrpcServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
            .expect("broker gRPC server does not have a TCP socket address")
    }

    pub fn endpoint_url(&self) -> String {
        self.endpoint_url.clone()
    }

    /// Idempotent shutdown. Cancels every live watch fanout before
    /// signalling tonic so its `graceful_shutdown` can drain in-flight
    /// streaming watch RPCs — without this, tonic waits forever (or up
    /// to the lifecycle drain timeout in production) on watch streams
    /// whose upstream keep-alive iterators have nothing else to signal
    /// them to stop.
    pub fn fire_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            self.broker_handle.load().watch_directory_state.cancel_all();
            let _ = shutdown.send(());
        }
    }

    /// Resolves when the server task has fully exited (serve future
    /// returned). Lets the lifecycle controller wait for real drain
    /// completion rather than sleeping the whole drain_timeout.
    pub fn take_drained(&mut self) -> Option<oneshot::Receiver<()>> {
        self.drained.take()
    }
}

impl Drop for BrokerGrpcServer {
    fn drop(&mut self) {
        self.fire_shutdown();
    }
}

pub fn spawn_broker_grpc_tcp_listener(
    broker: Arc<Broker>,
    listen: SocketAddr,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(wrap_broker_in_handle(broker), listen, None, None)
}

/// SIGHUP-aware variant: shared `BrokerHandle` lets the lifecycle
/// controller atomically swap the live `Broker`; in-flight RPCs hold
/// their dispatch-time snapshot.
pub fn spawn_broker_grpc_tcp_listener_with_handle(
    broker_handle: BrokerHandle,
    listen: SocketAddr,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(broker_handle, listen, None, None)
}

pub fn spawn_broker_grpc_tcp_listener_with_tls(
    broker: Arc<Broker>,
    listen: SocketAddr,
    tls: Option<&BrokerListenerTlsConfig>,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(wrap_broker_in_handle(broker), listen, tls, None)
}

pub fn spawn_broker_grpc_tcp_listener_with_config(
    broker: Arc<Broker>,
    listen: SocketAddr,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    let forwarded = crate::broker_listener_forwarded_header_config(Some(listener_config))?;
    spawn_broker_grpc_tcp_listener_inner(
        wrap_broker_in_handle(broker),
        listen,
        listener_config.tls.as_ref(),
        forwarded,
    )
}

pub fn spawn_broker_grpc_tcp_listener_with_handle_and_config(
    broker_handle: BrokerHandle,
    listen: SocketAddr,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    let forwarded = crate::broker_listener_forwarded_header_config(Some(listener_config))?;
    spawn_broker_grpc_tcp_listener_inner(
        broker_handle,
        listen,
        listener_config.tls.as_ref(),
        forwarded,
    )
}

fn wrap_broker_in_handle(broker: Arc<Broker>) -> BrokerHandle {
    // Private handle; only the shared-handle spawn path sees SIGHUP swaps.
    Arc::new(arc_swap::ArcSwap::new(broker))
}

fn spawn_broker_grpc_tcp_listener_inner(
    broker_handle: BrokerHandle,
    listen: SocketAddr,
    tls: Option<&BrokerListenerTlsConfig>,
    forwarded: Option<BrokerForwardedHeaderConfig>,
) -> ovstorage::Result<BrokerGrpcServer> {
    let listener = std::net::TcpListener::bind(listen).map_err(map_io)?;
    listener.set_nonblocking(true).map_err(map_io)?;
    let local_addr = listener.local_addr().map_err(map_io)?;
    let tls_config = match tls {
        Some(tls) => {
            let cert = fs::read(&tls.cert_path).map_err(map_io)?;
            let key = fs::read(&tls.key_path).map_err(map_io)?;
            let mut tls_config = tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, key));
            if let Some(client_ca_path) = &tls.client_ca_path {
                let client_ca = fs::read(client_ca_path).map_err(map_io)?;
                validate_client_ca_pem(&client_ca, client_ca_path)?;
                tls_config =
                    tls_config.client_ca_root(tonic::transport::Certificate::from_pem(client_ca));
            }
            Some(tls_config)
        }
        None => None,
    };
    let tls_enabled = tls_config.is_some();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (drained_tx, drained_rx) = oneshot::channel();
    let stashed_broker_handle = broker_handle.clone();
    std::thread::Builder::new()
        .name("ovs-grpc-tcp".into())
        .spawn(move || {
            let _drained_tx = drained_tx;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                    return;
                };
                let incoming = TcpListenerStream::new(listener);
                let health_handle = broker_handle.clone();
                let service =
                    pb::broker_service_server::BrokerServiceServer::new(GrpcBrokerService {
                        broker_handle,
                        transport: ListenerTransport::Tcp,
                        forwarded,
                    });
                let health = health_pb::health_server::HealthServer::new(GrpcHealthService {
                    broker_handle: health_handle,
                });
                // HTTP/2 keepalive on the TCP listener. Server-side PINGs
                // detect dead clients (e.g. process killed behind an idle
                // proxy) so per-connection state — auth gates, watcher
                // subscriptions — reclaims promptly. Symmetric with the
                // broker and omnistorage-plugin keepalive policies and
                // matches `provider_omnistorage/StorageProvider.cpp:1089-1091`.
                let mut builder = tonic::transport::Server::builder()
                    .http2_keepalive_interval(Some(BROKER_KEEPALIVE_INTERVAL))
                    .http2_keepalive_timeout(Some(BROKER_KEEPALIVE_TIMEOUT));
                if let Some(tls_config) = tls_config {
                    let Ok(tls_builder) = builder.tls_config(tls_config) else {
                        return;
                    };
                    builder = tls_builder;
                }
                let _ = builder
                    .add_service(service)
                    .add_service(health)
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })
        .expect("failed to spawn thread");
    let scheme = if tls_enabled { "grpc+tls" } else { "grpc+tcp" };
    Ok(BrokerGrpcServer {
        local_addr: Some(local_addr),
        endpoint_url: format!("{scheme}://{local_addr}"),
        shutdown: Some(shutdown),
        drained: Some(drained_rx),
        broker_handle: stashed_broker_handle,
    })
}

pub(crate) fn validate_client_ca_pem(pem: &[u8], path: &Path) -> ovstorage::Result<()> {
    use rustls_pki_types::pem::PemObject as _;

    let certificates = rustls_pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "listener TLS client CA '{}' is not valid PEM: {error}",
                    path.display()
                ),
            )
        })?;
    if certificates.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "listener TLS client CA '{}' contains no certificates",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub fn spawn_broker_grpc_unix_socket_listener(
    broker: Arc<Broker>,
    path: impl AsRef<Path>,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_unix_socket_listener_with_handle(
        wrap_broker_in_handle(broker),
        path,
        listener_config,
    )
}

#[cfg(unix)]
pub fn spawn_broker_grpc_unix_socket_listener_with_handle(
    broker_handle: BrokerHandle,
    path: impl AsRef<Path>,
    // Retained for API stability; the listener's authn lives in the broker's
    // per-listener auth layer, so the UDS spawn needs no authn config here.
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    use std::os::unix::fs::FileTypeExt;

    let path = path.as_ref().to_path_buf();
    if !path.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "unix_socket listener bind must be an absolute socket path",
        ));
    }
    if let Ok(metadata) = fs::metadata(&path) {
        if metadata.file_type().is_socket() {
            fs::remove_file(&path).map_err(map_io)?;
        } else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unix_socket listener bind '{}' already exists and is not a socket",
                    path.display()
                ),
            ));
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(&path).map_err(map_io)?;
    listener.set_nonblocking(true).map_err(map_io)?;
    let endpoint_url = format!("unix://{}", path.display());
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (drained_tx, drained_rx) = oneshot::channel();
    let thread_path = path;
    let stashed_broker_handle = broker_handle.clone();
    std::thread::Builder::new()
        .name("ovs-grpc-uds".into())
        .spawn(move || {
            let _drained_tx = drained_tx;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                    return;
                };
                let incoming = UnixListenerStream::new(listener);
                let health_handle = broker_handle.clone();
                let service =
                    pb::broker_service_server::BrokerServiceServer::new(GrpcBrokerService {
                        broker_handle,
                        transport: ListenerTransport::Uds,
                        forwarded: None,
                    });
                let health = health_pb::health_server::HealthServer::new(GrpcHealthService {
                    broker_handle: health_handle,
                });
                let _ = tonic::transport::Server::builder()
                    .add_service(service)
                    .add_service(health)
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
                let _ = fs::remove_file(thread_path);
            });
        })
        .expect("failed to spawn thread");
    Ok(BrokerGrpcServer {
        local_addr: None,
        endpoint_url,
        shutdown: Some(shutdown),
        drained: Some(drained_rx),
        broker_handle: stashed_broker_handle,
    })
}

#[cfg(not(unix))]
pub fn spawn_broker_grpc_unix_socket_listener(
    _broker: Arc<Broker>,
    _path: impl AsRef<Path>,
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "unix_socket listener serving is not available on this platform",
    ))
}

#[cfg(not(unix))]
pub fn spawn_broker_grpc_unix_socket_listener_with_handle(
    _broker_handle: BrokerHandle,
    _path: impl AsRef<Path>,
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "unix_socket listener serving is not available on this platform",
    ))
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(crate) struct NamedPipeConnectInfo {
    client_process_id: Option<u32>,
}

#[cfg(windows)]
impl NamedPipeConnectInfo {
    pub(crate) fn client_process_id(&self) -> Option<u32> {
        self.client_process_id
    }
}

#[cfg(windows)]
pub(crate) struct BrokerNamedPipeServer {
    inner: tokio::net::windows::named_pipe::NamedPipeServer,
    connect_info: NamedPipeConnectInfo,
}

#[cfg(windows)]
pub(crate) struct LocalSecurityDescriptor {
    ptr: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let _ = windows_sys::Win32::Foundation::LocalFree(self.ptr as _);
            }
        }
    }
}

#[cfg(windows)]
impl AsyncRead for BrokerNamedPipeServer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

#[cfg(windows)]
impl AsyncWrite for BrokerNamedPipeServer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(windows)]
impl tonic::transport::server::Connected for BrokerNamedPipeServer {
    type ConnectInfo = NamedPipeConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.connect_info.clone()
    }
}

#[cfg(windows)]
pub fn spawn_broker_grpc_named_pipe_listener(
    broker: Arc<Broker>,
    name: impl AsRef<str>,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_named_pipe_listener_with_handle(
        wrap_broker_in_handle(broker),
        name,
        listener_config,
    )
}

#[cfg(windows)]
pub fn spawn_broker_grpc_named_pipe_listener_with_handle(
    broker_handle: BrokerHandle,
    name: impl AsRef<str>,
    // Retained for API stability; the listener's authn lives in the broker's
    // per-listener auth layer, so the named-pipe spawn needs no authn config
    // here. Mirrors the `#[cfg(unix)]` UDS spawn above.
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    let name = normalize_named_pipe_name(name.as_ref())?;
    let pipe_path = named_pipe_path(&name);
    let endpoint_url = format!("npipe:///{name}");
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (drained_tx, drained_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let stashed_broker_handle = broker_handle.clone();
    std::thread::Builder::new()
        .name("ovs-grpc-np".into())
        .spawn(move || {
            let _drained_tx = drained_tx;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                let _ = ready_tx.send(Err("failed to create named-pipe runtime".to_string()));
                return;
            };
            runtime.block_on(async move {
                let first = match create_named_pipe_server(&pipe_path) {
                    Ok(first) => first,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
                let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
                tokio::spawn(async move {
                    let _ = shutdown_rx.await;
                    let _ = stop_tx.send(true);
                });
                let mut accept_stop = stop_rx.clone();
                let accept_path = pipe_path.clone();
                tokio::spawn(async move {
                    let mut server = first;
                    loop {
                        tokio::select! {
                            _ = accept_stop.changed() => break,
                            result = server.connect() => {
                                if let Err(error) = result {
                                    let _ = incoming_tx.send(Err(error)).await;
                                    break;
                                }
                                let next = match create_named_pipe_server(&accept_path) {
                                    Ok(next) => next,
                                    Err(error) => {
                                        let _ = incoming_tx.send(Err(error)).await;
                                        break;
                                    }
                                };
                                let connect_info = NamedPipeConnectInfo {
                                    client_process_id: named_pipe_client_process_id(&server),
                                };
                                if incoming_tx
                                    .send(Ok(BrokerNamedPipeServer {
                                        inner: server,
                                        connect_info,
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                server = next;
                            }
                        }
                    }
                });
                let _ = ready_tx.send(Ok(()));
                let health_handle = broker_handle.clone();
                let service =
                    pb::broker_service_server::BrokerServiceServer::new(GrpcBrokerService {
                        broker_handle,
                        transport: ListenerTransport::NamedPipe,
                        forwarded: None,
                    });
                let health = health_pb::health_server::HealthServer::new(GrpcHealthService {
                    broker_handle: health_handle,
                });
                let _ = tonic::transport::Server::builder()
                    .add_service(service)
                    .add_service(health)
                    .serve_with_incoming_shutdown(ReceiverStream::new(incoming_rx), async move {
                        while !*stop_rx.borrow() {
                            if stop_rx.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
            });
        })
        .expect("failed to spawn thread");
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(Error::new(ErrorCode::BrokerUnavailable, error)),
        Err(error) => {
            return Err(Error::new(
                ErrorCode::BrokerUnavailable,
                format!("timed out starting named_pipe listener: {error}"),
            ));
        }
    }
    Ok(BrokerGrpcServer {
        local_addr: None,
        endpoint_url,
        shutdown: Some(shutdown),
        drained: Some(drained_rx),
        broker_handle: stashed_broker_handle,
    })
}

#[cfg(not(windows))]
pub fn spawn_broker_grpc_named_pipe_listener(
    _broker: Arc<Broker>,
    _name: impl AsRef<str>,
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "named_pipe listener serving is not available on this platform",
    ))
}

#[cfg(not(windows))]
pub fn spawn_broker_grpc_named_pipe_listener_with_handle(
    _broker_handle: BrokerHandle,
    _name: impl AsRef<str>,
    _listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "named_pipe listener serving is not available on this platform",
    ))
}

#[cfg(windows)]
fn create_named_pipe_server(
    path: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let (descriptor, mut attrs) = named_pipe_security_attributes()?;
    let server = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(path, &mut attrs as *mut _ as *mut _)
    };
    drop(descriptor);
    server
}

#[cfg(windows)]
fn named_pipe_security_attributes() -> std::io::Result<(
    LocalSecurityDescriptor,
    windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
)> {
    // PIPE_REJECT_REMOTE_CLIENTS keeps this local-only; explicit DACL
    // avoids restricted-token shells inheriting a descriptor that
    // blocks same-host clients.
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)(A;;GA;;;WD)";
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    let ok = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            windows_sys::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalSecurityDescriptor { ptr: descriptor };
    let attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr,
        bInheritHandle: 0,
    };
    Ok((descriptor, attrs))
}

#[cfg(windows)]
fn normalize_named_pipe_name(name: &str) -> ovstorage::Result<String> {
    let trimmed = name
        .trim()
        .trim_start_matches("\\\\.\\pipe\\")
        .trim_matches(['/', '\\']);
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "named_pipe listener bind must include a pipe name",
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(windows)]
fn named_pipe_path(name: &str) -> String {
    if name.starts_with("\\\\.\\pipe\\") {
        name.to_string()
    } else {
        format!("\\\\.\\pipe\\{name}")
    }
}

#[cfg(windows)]
fn named_pipe_client_process_id(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Option<u32> {
    let mut pid = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
            server.as_raw_handle(),
            &mut pid,
        )
    };
    (ok != 0).then_some(pid)
}

/// Atomic-swappable broker handle; each RPC snapshots via `load_full()`
/// at dispatch and holds it for the duration.
pub type BrokerHandle = Arc<arc_swap::ArcSwap<Broker>>;

pub fn broker_handle(broker: Broker) -> BrokerHandle {
    Arc::new(arc_swap::ArcSwap::from(Arc::new(broker)))
}

/// The transport a listener serves. It selects which peer-credential shape the
/// credential-gathering seam builds; the built-in auth layer resolves identity
/// from the transport tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListenerTransport {
    Tcp,
    #[cfg_attr(not(unix), allow(dead_code))]
    Uds,
    #[cfg_attr(not(windows), allow(dead_code))]
    NamedPipe,
}

#[derive(Clone)]
pub(crate) struct GrpcBrokerService {
    broker_handle: BrokerHandle,
    transport: ListenerTransport,
    forwarded: Option<BrokerForwardedHeaderConfig>,
}

impl GrpcBrokerService {
    fn broker(&self) -> Arc<Broker> {
        self.broker_handle.load_full()
    }

    /// Gather the caller's transport peer credentials + bearer token into a
    /// [`RequestContext`]. The broker performs **no** authentication here: it
    /// only collects the material (only the socket owner can) and stamps it
    /// UNDECODED for the per-listener auth layer.
    fn request_context<T>(&self, request: &Request<T>) -> Result<RequestContext, Status> {
        if let Some(forwarded) = &self.forwarded {
            let peer_addr = request.remote_addr().ok_or_else(|| {
                Status::unauthenticated(
                    "trusted-proxy listener could not capture the TCP connection peer",
                )
            })?;
            if !forwarded.trusts_peer(&peer_addr.to_string()) {
                return Err(Status::unauthenticated(format!(
                    "connection peer {peer_addr} is not in the trusted proxy CIDR allowlist"
                )));
            }
        }
        Ok(RequestContext {
            credential: Some(gather_credential(
                self.transport,
                request,
                self.forwarded.as_ref(),
            )),
            audit_id: audit_id(request),
        })
    }
}

/// gRPC metadata carrying the caller's opaque audit-correlation id. It grants
/// no authority; the value is only threaded through spans and response error
/// context so one logical operation can be correlated across service hops.
pub(crate) const X_OV_AUDIT_ID: &str = "x-ov-audit-id";

fn audit_id<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(X_OV_AUDIT_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The raw bearer token from the gRPC `authorization` metadata (scheme prefix
/// stripped, UNDECODED), or `None` when absent/blank. The auth layer validates
/// it; the host never decodes it.
fn bearer_token<T>(request: &Request<T>) -> Option<Vec<u8>> {
    let value = request.metadata().get("authorization")?;
    let value = value.to_str().ok()?;
    ovstorage_authz_context::bearer_from_authorization_value(value)
}

/// Build the caller's [`AuthCredential`] from the listener transport + request:
/// UDS `SO_PEERCRED` (`uid`/`gid`/`pid`), named-pipe client pid, or TCP peer
/// address, plus any bearer token. The auth layer resolves identity from it.
pub(crate) fn gather_credential<T>(
    transport: ListenerTransport,
    request: &Request<T>,
    forwarded: Option<&BrokerForwardedHeaderConfig>,
) -> AuthCredential {
    let bearer = bearer_token(request);
    let transport = match transport {
        ListenerTransport::Tcp => {
            let peer_addr = request
                .remote_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_default();
            Transport::Tcp {
                peer_addr,
                tls_client_cert: request
                    .peer_certs()
                    .and_then(|certs| certs.first().map(|cert| cert.as_ref().to_vec())),
            }
        }
        ListenerTransport::Uds => uds_transport(request),
        ListenerTransport::NamedPipe => named_pipe_transport(request),
    };
    AuthCredential {
        bearer,
        transport,
        forwarded: forwarded.and_then(|config| forwarded_headers(request, config.headers())),
    }
}

fn forwarded_headers<T>(
    request: &Request<T>,
    config: &ovstorage_authz_layer::ForwardedHeaderConfig,
) -> Option<ForwardedHeaders> {
    let values = request
        .metadata()
        .iter()
        .filter_map(|item| match item {
            tonic::metadata::KeyAndValueRef::Ascii(key, value)
                if key.as_str() == config.identity_header
                    || config
                        .claim_headers
                        .values()
                        .any(|header| header == key.as_str()) =>
            {
                value
                    .to_str()
                    .ok()
                    .map(|value| (key.as_str().to_string(), value.to_string()))
            }
            tonic::metadata::KeyAndValueRef::Ascii(_, _)
            | tonic::metadata::KeyAndValueRef::Binary(_, _) => None,
        })
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(ForwardedHeaders { values })
}

#[cfg(unix)]
fn uds_transport<T>(request: &Request<T>) -> Transport {
    match request
        .extensions()
        .get::<tonic::transport::server::UdsConnectInfo>()
        .and_then(|info| info.peer_cred)
    {
        Some(cred) => Transport::Uds {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid().unwrap_or(0),
        },
        // No peer credentials available: a `uid == u32::MAX` sentinel that the
        // auth layer's peer resolver maps to anonymous (a credential-less caller
        // carries no identity and must not match a `uid:*` policy glob).
        None => Transport::Uds {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: 0,
        },
    }
}

#[cfg(not(unix))]
fn uds_transport<T>(_request: &Request<T>) -> Transport {
    Transport::Uds {
        uid: u32::MAX,
        gid: u32::MAX,
        pid: 0,
    }
}

#[cfg(windows)]
fn named_pipe_transport<T>(request: &Request<T>) -> Transport {
    // tonic's named-pipe connect info exposes only the client pid today; the
    // real client SID must be gathered producer-side (a follow-up gap noted in
    // task 3.3). Client-SID gathering is deferred, so the SID is empty; the auth
    // layer's peer resolver maps the empty SID to anonymous, so an anonymous
    // named-pipe listener functions until real SID gathering lands.
    let pid = request
        .extensions()
        .get::<NamedPipeConnectInfo>()
        .and_then(|info| info.client_process_id())
        .unwrap_or(0);
    Transport::NamedPipe {
        sid: String::new(),
        pid,
    }
}

#[cfg(not(windows))]
fn named_pipe_transport<T>(_request: &Request<T>) -> Transport {
    Transport::NamedPipe {
        sid: String::new(),
        pid: 0,
    }
}

#[derive(Clone)]
pub(crate) struct GrpcHealthService {
    broker_handle: BrokerHandle,
}

impl GrpcHealthService {
    fn broker(&self) -> Arc<Broker> {
        self.broker_handle.load_full()
    }
}

/// Build a `tonic::Status` folding `audit_id` into `pb::ErrorDetail`;
/// preferred over `protocol::error_to_status` when a `RequestContext` is in scope.
fn ctx_status(error: ovstorage::Error, context: &RequestContext) -> Status {
    protocol::error_to_status_with_context(error, None, context.audit_id.as_deref(), None)
}

/// Like [`ctx_status`] but also threads the parsed `address`.
fn ctx_status_addr(
    error: ovstorage::Error,
    context: &RequestContext,
    address: &ovstorage_plugin::Url,
) -> Status {
    protocol::error_to_status_with_context(error, Some(address), context.audit_id.as_deref(), None)
}

type GrpcReadStream =
    Pin<Box<dyn Stream<Item = Result<pb::ReadResponse, Status>> + Send + 'static>>;

/// Frame a whole-object `Bytes` read body the way the streaming arm
/// frames a backend-yielded stream: an info frame first, then the body
/// split into `READ_BODY_CHUNK_BYTES`-bounded body frames, with gRPC
/// stream close as the terminator (no explicit EOF frame). An empty
/// body yields the info frame alone, matching a zero-chunk stream.
///
/// Chunks slice the owned `bytes` in place and copy one chunk at a time
/// into each frame; the iterator is polled lazily by tonic, so no path
/// buffers a second whole copy of the object.
fn bytes_read_frames(
    info: &ObjectInfo,
    bytes: Vec<u8>,
) -> impl Iterator<Item = Result<pb::ReadResponse, Status>> + Send + 'static {
    let info_frame = pb::ReadResponse {
        result: Some(pb::read_response::Result::Info(
            protocol::object_info_to_proto(info),
        )),
    };
    let mut offset = 0usize;
    let body_frames = std::iter::from_fn(move || {
        if offset >= bytes.len() {
            return None;
        }
        let end = offset
            .saturating_add(READ_BODY_CHUNK_BYTES)
            .min(bytes.len());
        let frame = pb::ReadResponse {
            result: Some(pb::read_response::Result::Body(bytes[offset..end].to_vec())),
        };
        offset = end;
        Some(Ok(frame))
    });
    std::iter::once(Ok(info_frame)).chain(body_frames)
}
type GrpcWriteStream =
    Pin<Box<dyn Stream<Item = Result<pb::WriteResponse, Status>> + Send + 'static>>;
type GrpcWatchDirectoryStream =
    Pin<Box<dyn Stream<Item = Result<pb::WatchDirectoryResponse, Status>> + Send + 'static>>;
type GrpcWatchAddressRootsStream =
    Pin<Box<dyn Stream<Item = Result<pb::AddressRootsChange, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl pb::broker_service_server::BrokerService for GrpcBrokerService {
    type ReadStream = GrpcReadStream;
    type WriteStream = GrpcWriteStream;
    type WatchDirectoryStream = GrpcWatchDirectoryStream;
    type WatchAddressRootsStream = GrpcWatchAddressRootsStream;
    type AuthStream = GrpcAuthStream;

    async fn list_address_roots(
        &self,
        request: Request<pb::ListAddressRootsRequest>,
    ) -> Result<GrpcResponse<pb::ListAddressRootsResponse>, Status> {
        let context = self.request_context(&request)?;
        let span = tracing::info_span!(
            "broker.list_address_roots",
            op = "list_address_roots",
            audit_id = context.audit_id.as_deref(),
        );
        async move {
            let broker = self.broker();
            let roots = broker
                .list_address_roots(&context)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::ListAddressRootsResponse {
                roots: roots.iter().map(protocol::address_root_to_proto).collect(),
            }))
        }
        .instrument(span)
        .await
    }

    async fn watch_address_roots(
        &self,
        request: Request<pb::WatchAddressRootsRequest>,
    ) -> Result<GrpcResponse<Self::WatchAddressRootsStream>, Status> {
        let context = self.request_context(&request)?;
        let _span = tracing::info_span!(
            "broker.watch_address_roots",
            op = "watch_address_roots",
            audit_id = context.audit_id.as_deref(),
        );
        let _guard = _span.enter();
        // Snapshot-once today; deltas land when the route table can
        // mutate at runtime.
        let broker = self.broker();
        let roots = broker
            .list_address_roots(&context)
            .await
            .map_err(|e| ctx_status(e, &context))?;
        let snapshot = ovstorage_broker_protocol::AddressRootsChange::Snapshot(roots);
        let snapshot_proto = protocol::address_roots_change_to_proto(&snapshot);
        let stream = tokio_stream::once(Ok(snapshot_proto));
        Ok(GrpcResponse::new(Box::pin(stream)))
    }

    async fn stat(
        &self,
        request: Request<pb::StatRequest>,
    ) -> Result<GrpcResponse<pb::StatResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.stat",
            op = "stat",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let info = self
                .broker()
                .stat(
                    &context,
                    address.clone(),
                    protocol::stat_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status_addr(e, &context, &address))?;
            Ok(GrpcResponse::new(pb::StatResponse {
                info: Some(protocol::object_info_to_proto(&info)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn read(
        &self,
        request: Request<pb::ReadRequest>,
    ) -> Result<GrpcResponse<Self::ReadStream>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.read",
            op = "read",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        let _guard = _span.enter();
        let outcome = self
            .broker()
            .read(
                &context,
                address.clone(),
                protocol::read_options_from_proto(request.options),
            )
            .await
            .map_err(|e| ctx_status_addr(e, &context, &address))?;
        match outcome {
            BrokerReadOutcome::Bytes { info, bytes } => {
                // Info frame then body split into bounded frames, same
                // shape the streaming arm emits; gRPC stream close is the
                // terminator. Chunking keeps a large cache-hit / bounded
                // body under gRPC's per-frame message-size limit.
                Ok(GrpcResponse::new(Box::pin(tokio_stream::iter(
                    bytes_read_frames(&info, bytes),
                ))))
            }
            BrokerReadOutcome::Redirect(redirect) => {
                // Standalone redirect; no preceding info frame.
                let response = pb::ReadResponse {
                    result: Some(pb::read_response::Result::Redirect(
                        protocol::read_redirect_to_proto(&redirect),
                    )),
                };
                Ok(GrpcResponse::new(Box::pin(tokio_stream::iter(vec![Ok(
                    response,
                )]))))
            }
            BrokerReadOutcome::Stream { info, stream } => {
                // Server-streaming: info then 0+ body chunks; peak
                // broker memory bounded by chunk size × channel cap (16).
                let info_frame = pb::ReadResponse {
                    result: Some(pb::read_response::Result::Info(
                        protocol::object_info_to_proto(&info),
                    )),
                };
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::ReadResponse, Status>>(16);
                if tx.send(Ok(info_frame)).await.is_err() {
                    return Ok(GrpcResponse::new(Box::pin(
                        tokio_stream::wrappers::ReceiverStream::new(rx),
                    )));
                }
                tokio::spawn(async move {
                    use futures::StreamExt;
                    let mut s = stream;
                    loop {
                        match s.next().await {
                            None => return,
                            Some(Ok(chunk)) => {
                                let chunk_vec: Vec<u8> = chunk.to_vec();
                                if tx
                                    .send(Ok(pb::ReadResponse {
                                        result: Some(pb::read_response::Result::Body(chunk_vec)),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            Some(Err(error)) => {
                                let _ = tx.send(Err(protocol::error_to_status(error))).await;
                                return;
                            }
                        }
                    }
                });
                Ok(GrpcResponse::new(Box::pin(
                    tokio_stream::wrappers::ReceiverStream::new(rx),
                )))
            }
        }
    }

    async fn write(
        &self,
        request: Request<tonic::Streaming<pb::WriteRequest>>,
    ) -> Result<GrpcResponse<Self::WriteStream>, Status> {
        let context = self.request_context(&request)?;
        let broker = self.broker();
        let mut stream = request.into_inner();
        // First frame must be Open so authz runs before any chunk is
        // buffered; otherwise an unauthorized caller could push
        // arbitrary bytes before being rejected.
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("write missing open step"))?;
        let open = match first
            .step
            .ok_or_else(|| Status::invalid_argument("broker write request is missing a step"))?
        {
            pb::write_request::Step::Open(open) => open,
            pb::write_request::Step::Chunk(_) => {
                return Err(Status::invalid_argument(
                    "write must begin with Open before any Chunk",
                ));
            }
            pb::write_request::Step::RedirectResults(_) => {
                return Err(Status::invalid_argument(
                    "redirect results must be sent with ContinueWrite",
                ));
            }
        };
        let address = protocol::object_address_from_proto(open.address)
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.write",
            op = "write",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        let _guard = _span.enter();
        let options = protocol::write_options_from_proto(open.options)
            .map_err(|e| ctx_status_addr(e, &context, &address))?;
        // Built-in auth can reject from its typed preflight before any Chunk is
        // consumed. Plugin auth has no preflight slot and receives the unpulled
        // body as its authoritative in-Stack request. Both routes feed the same
        // accumulator: here after built-in preflight, or beneath plugin auth
        // after delegation. It coalesces empty/small uploads to replayable Bytes
        // and preserves over-threshold uploads as a bounded stream.
        let body = if broker.write_admission() == ListenerWriteAdmission::HostPreflight {
            broker
                .authorize_write(&context, &address)
                .map_err(|e| ctx_status_addr(e, &context, &address))?;
            select_write_body(stream)
                .await
                .map_err(|e| ctx_status_addr(e, &context, &address))?
        } else {
            Body::Stream(lazy_write_body(stream))
        };
        let outcome = broker
            .write(&context, address, body, options)
            .await
            .map_err(|e| ctx_status(e, &context))?;
        let response = write_response_from_outcome(outcome);
        Ok(GrpcResponse::new(Box::pin(tokio_stream::iter(vec![Ok(
            response,
        )]))))
    }

    async fn write_redirect(
        &self,
        request: Request<pb::WriteRedirectRequest>,
    ) -> Result<GrpcResponse<pb::WriteRedirectResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.write_redirect",
            op = "write_redirect",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let options = protocol::write_options_from_proto(request.options)
                .map_err(|e| ctx_status(e, &context))?;
            let batch = self
                .broker()
                .write_redirect(&context, address, options)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::WriteRedirectResponse {
                redirects: Some(protocol::write_redirect_batch_to_proto(&batch)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn continue_write(
        &self,
        request: Request<pb::ContinueWriteRequest>,
    ) -> Result<GrpcResponse<pb::ContinueWriteResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.continue_write",
            op = "continue_write",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let step = self
                .broker()
                .continue_write(
                    &context,
                    address,
                    protocol::write_redirect_batch_from_proto(request.redirects)
                        .map_err(|e| ctx_status(e, &context))?,
                    protocol::redirect_result_batch_from_proto(request.results)
                        .map_err(|e| ctx_status(e, &context))?,
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            let proto_step = match step {
                ovstorage_plugin::WriteStep::Redirects(batch) => {
                    pb::continue_write_response::Step::Redirects(
                        protocol::write_redirect_batch_to_proto(&batch),
                    )
                }
                ovstorage_plugin::WriteStep::Done(result) => {
                    pb::continue_write_response::Step::Done(protocol::write_result_to_proto(
                        &result,
                    ))
                }
            };
            Ok(GrpcResponse::new(pb::ContinueWriteResponse {
                step: Some(proto_step),
            }))
        }
        .instrument(span)
        .await
    }

    async fn delete(
        &self,
        request: Request<pb::DeleteRequest>,
    ) -> Result<GrpcResponse<pb::DeleteResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.delete",
            op = "delete",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            self.broker()
                .delete(
                    &context,
                    address,
                    protocol::delete_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::DeleteResponse {}))
        }
        .instrument(span)
        .await
    }

    async fn list(
        &self,
        request: Request<pb::ListRequest>,
    ) -> Result<GrpcResponse<pb::ListResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let prefix = protocol::object_address_from_proto(request.prefix)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.list",
            op = "list",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&prefix),
        );
        async move {
            let page = self
                .broker()
                .list(
                    &context,
                    prefix,
                    protocol::list_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::ListResponse {
                page: Some(protocol::list_page_to_proto(&page)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn list_versions(
        &self,
        request: Request<pb::ListVersionsRequest>,
    ) -> Result<GrpcResponse<pb::ListVersionsResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.list_versions",
            op = "list_versions",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let items = self
                .broker()
                .list_versions(
                    &context,
                    address,
                    protocol::list_versions_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::ListVersionsResponse {
                items: items.iter().map(protocol::object_info_to_proto).collect(),
            }))
        }
        .instrument(span)
        .await
    }

    async fn get_latest_version(
        &self,
        request: Request<pb::GetLatestVersionRequest>,
    ) -> Result<GrpcResponse<pb::GetLatestVersionResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.get_latest_version",
            op = "get_latest_version",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let item = self
                .broker()
                .get_latest_version(&context, address)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::GetLatestVersionResponse {
                version: Some(protocol::object_info_to_proto(&item)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn watch_directory(
        &self,
        request: Request<pb::WatchDirectoryRequest>,
    ) -> Result<GrpcResponse<Self::WatchDirectoryStream>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let prefix = request.prefix.clone();
        let prefix_addr = protocol::object_address_from_proto(prefix.clone())
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.watch_directory",
            op = "watch_directory",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&prefix_addr),
        );
        let _guard = _span.enter();
        let stream = self
            .broker()
            .watch_directory(
                &context,
                prefix_addr,
                protocol::watch_directory_options_from_proto(&request),
            )
            .await
            .map_err(|e| ctx_status(e, &context))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        std::thread::Builder::new()
            .name("ovs-grpc-watch".into())
            .spawn(move || {
                for event in stream {
                    let response = event
                        .map(|event| pb::WatchDirectoryResponse {
                            event: Some(protocol::change_event_to_proto(&event)),
                        })
                        .map_err(|e| ctx_status(e, &context));
                    if sender.blocking_send(response).is_err() {
                        break;
                    }
                }
            })
            .expect("failed to spawn thread");
        Ok(GrpcResponse::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn create_directory(
        &self,
        request: Request<pb::CreateDirectoryRequest>,
    ) -> Result<GrpcResponse<pb::CreateDirectoryResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.create_directory",
            op = "create_directory",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let info = self
                .broker()
                .create_directory(
                    &context,
                    address,
                    protocol::create_directory_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::CreateDirectoryResponse {
                info: Some(protocol::object_info_to_proto(&info)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn delete_directory(
        &self,
        request: Request<pb::DeleteDirectoryRequest>,
    ) -> Result<GrpcResponse<pb::DeleteDirectoryResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.delete_directory",
            op = "delete_directory",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            self.broker()
                .delete_directory(
                    &context,
                    address,
                    protocol::delete_directory_options_from_proto(request.options),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::DeleteDirectoryResponse {}))
        }
        .instrument(span)
        .await
    }

    async fn copy(
        &self,
        request: Request<pb::CopyRequest>,
    ) -> Result<GrpcResponse<pb::CopyResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let source = protocol::object_address_from_proto(request.source)
            .map_err(|e| ctx_status(e, &context))?;
        let destination = protocol::object_address_from_proto(request.destination)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.copy",
            op = "copy",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&source),
        );
        async move {
            let options = protocol::copy_options_from_proto(request.options)
                .map_err(|e| ctx_status(e, &context))?;
            let result = self
                .broker()
                .copy(&context, source, destination, options)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::CopyResponse {
                result: Some(protocol::write_result_to_proto(&result)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn rename(
        &self,
        request: Request<pb::RenameRequest>,
    ) -> Result<GrpcResponse<pb::RenameResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let source = protocol::object_address_from_proto(request.source)
            .map_err(|e| ctx_status(e, &context))?;
        let destination = protocol::object_address_from_proto(request.destination)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.rename",
            op = "rename",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&source),
        );
        async move {
            let options = protocol::rename_options_from_proto(request.options)
                .map_err(|e| ctx_status(e, &context))?;
            self.broker()
                .rename(&context, source, destination, options)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::RenameResponse {}))
        }
        .instrument(span)
        .await
    }

    async fn update_metadata(
        &self,
        request: Request<pb::UpdateMetadataRequest>,
    ) -> Result<GrpcResponse<pb::UpdateMetadataResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address.clone())
            .map_err(|e| ctx_status(e, &context))?;
        let options = protocol::update_metadata_options_from_proto(&request);
        let span = tracing::info_span!(
            "broker.update_metadata",
            op = "update_metadata",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let info = self
                .broker()
                .update_metadata(&context, address, options)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::UpdateMetadataResponse {
                info: Some(protocol::object_info_to_proto(&info)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn check_access(
        &self,
        request: Request<pb::CheckAccessRequest>,
    ) -> Result<GrpcResponse<pb::CheckAccessResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.check_access",
            op = "check_access",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let decision = self
                .broker()
                .check_access(
                    &context,
                    address,
                    protocol::access_ops_from_proto(request.operations),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::CheckAccessResponse {
                decision: Some(protocol::access_decision_to_proto(&decision)),
            }))
        }
        .instrument(span)
        .await
    }

    async fn auth(
        &self,
        request: Request<pb::AuthRequest>,
    ) -> Result<GrpcResponse<Self::AuthStream>, Status> {
        let context = self.request_context(&request)?;
        let capability = protocol::capability_from_metadata(request.metadata());
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.auth",
            op = "auth",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let cancel = ovstorage::CancellationToken::new();
            let broker = self.broker();
            let failure_diagnostic = broker.upstream_auth_failure_diagnostic(&address);
            let stream = broker
                .open_upstream_auth_stream(
                    &context,
                    capability,
                    address.clone(),
                    Some(cancel.clone()),
                )
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(bridge_auth_stream(
                stream,
                address,
                context,
                cancel,
                failure_diagnostic,
            )?))
        }
        .instrument(span)
        .await
    }

    async fn register_credential(
        &self,
        request: Request<pb::RegisterCredentialRequest>,
    ) -> Result<GrpcResponse<pb::RegisterCredentialResponse>, Status> {
        let context = self.request_context(&request)?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address.clone())
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.register_credential",
            op = "register_credential",
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let payload = register_credential_payload_from_proto(request)
                .map_err(|e| ctx_status(e, &context))?;
            self.broker()
                .register_upstream_credential(&context, address, payload)
                .await
                .map_err(|e| ctx_status(e, &context))?;
            Ok(GrpcResponse::new(pb::RegisterCredentialResponse {}))
        }
        .instrument(span)
        .await
    }
}

#[tonic::async_trait]
impl health_pb::health_server::Health for GrpcHealthService {
    async fn check(
        &self,
        _request: Request<health_pb::HealthCheckRequest>,
    ) -> Result<GrpcResponse<health_pb::HealthCheckResponse>, Status> {
        let status = if self.broker().health().is_ok() {
            health_pb::health_check_response::ServingStatus::Serving
        } else {
            health_pb::health_check_response::ServingStatus::NotServing
        };
        Ok(GrpcResponse::new(health_pb::HealthCheckResponse {
            status: status as i32,
        }))
    }
}

#[cfg(test)]
mod write_chunk_classify_tests {
    use crate::write_body::{ChunkDisposition, classify_write_chunk};

    const THRESHOLD: usize = 1024;
    const CAP: usize = 4096;

    /// OOM guard: an unbounded run of empty chunk frames is always discarded
    /// and never advances the buffered length, so `buffered`/`buffered_len` stay
    /// pinned regardless of frame count. Simulate the drain loop's accounting.
    #[test]
    fn empty_chunks_are_discarded_and_never_buffered() {
        // Mirror the drain loop's accounting: it only pushes a frame / advances
        // `buffered_len` on `ChunkDisposition::Buffer`. Feed a run of empty chunks
        // well beyond any plausible frame count and confirm the buffer state never
        // moves — the unbounded-empty-frame heap growth cannot occur.
        let mut buffered_frames = 0usize;
        let mut buffered_len = 0usize;
        for _ in 0..1_000_000 {
            match classify_write_chunk(0, buffered_len, THRESHOLD, CAP) {
                ChunkDisposition::Discard => {}
                ChunkDisposition::Buffer => {
                    buffered_frames += 1;
                    buffered_len += 1;
                }
                other => panic!("empty chunk must be discarded, got {other:?}"),
            }
        }
        assert_eq!(buffered_frames, 0, "no empty frame is ever retained");
        assert_eq!(
            buffered_len, 0,
            "empty frames never advance buffered length"
        );
    }

    #[test]
    fn non_empty_chunk_dispositions() {
        // Under threshold → buffered.
        assert_eq!(
            classify_write_chunk(512, 0, THRESHOLD, CAP),
            ChunkDisposition::Buffer
        );
        // Crossing the threshold → overflow to the streaming path.
        assert_eq!(
            classify_write_chunk(600, 512, THRESHOLD, CAP),
            ChunkDisposition::Overflow
        );
        // Crossing the absolute cap → reject.
        assert_eq!(
            classify_write_chunk(1, CAP, THRESHOLD, CAP),
            ChunkDisposition::CapExceeded
        );
        // A zero-length frame is discarded even when buffered_len is already high.
        assert_eq!(
            classify_write_chunk(0, CAP, THRESHOLD, CAP),
            ChunkDisposition::Discard
        );
    }
}

#[cfg(test)]
mod bytes_frame_tests {
    use super::*;

    /// Reassemble the `Body` frames and return `(body_frame_count,
    /// info_frame_count, reassembled)`, asserting the info frame is
    /// first and every body frame stays within the chunk bound.
    fn collect(frames: Vec<Result<pb::ReadResponse, Status>>) -> (usize, usize, Vec<u8>) {
        let mut body_frames = 0usize;
        let mut info_frames = 0usize;
        let mut seen_body = false;
        let mut reassembled = Vec::new();
        for (idx, frame) in frames.into_iter().enumerate() {
            match frame.expect("frame ok").result.expect("result set") {
                pb::read_response::Result::Info(_) => {
                    assert_eq!(idx, 0, "info frame must be first");
                    assert!(!seen_body, "info must precede any body");
                    info_frames += 1;
                }
                pb::read_response::Result::Body(body) => {
                    assert!(
                        body.len() <= READ_BODY_CHUNK_BYTES,
                        "body frame {} exceeds chunk bound",
                        body.len()
                    );
                    seen_body = true;
                    body_frames += 1;
                    reassembled.extend_from_slice(&body);
                }
                pb::read_response::Result::Redirect(_) => panic!("no redirect expected"),
            }
        }
        (body_frames, info_frames, reassembled)
    }

    fn test_info() -> ObjectInfo {
        ObjectInfo::from((
            address::parse("test://demo/big.bin").unwrap(),
            ovstorage_plugin::BackendItemInfo::default(),
        ))
    }

    #[test]
    fn oversize_body_splits_into_multiple_frames_and_reassembles() {
        // 2 full chunks + a partial third: proves a body past the chunk
        // bound arrives as several frames that reassemble byte-identical.
        let len = READ_BODY_CHUNK_BYTES * 2 + 500;
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let info = test_info();
        let frames: Vec<_> = bytes_read_frames(&info, body.clone()).collect();
        let (body_frames, info_frames, reassembled) = collect(frames);
        assert_eq!(info_frames, 1);
        assert_eq!(body_frames, 3);
        assert_eq!(reassembled, body);
    }

    #[test]
    fn exact_chunk_body_is_a_single_body_frame() {
        let body: Vec<u8> = (0..READ_BODY_CHUNK_BYTES)
            .map(|i| (i % 251) as u8)
            .collect();
        let info = test_info();
        let frames: Vec<_> = bytes_read_frames(&info, body.clone()).collect();
        let (body_frames, info_frames, reassembled) = collect(frames);
        assert_eq!(info_frames, 1);
        assert_eq!(body_frames, 1);
        assert_eq!(reassembled, body);
    }

    #[test]
    fn small_body_is_a_single_body_frame() {
        let body = b"small cached body".to_vec();
        let info = test_info();
        let frames: Vec<_> = bytes_read_frames(&info, body.clone()).collect();
        let (body_frames, info_frames, reassembled) = collect(frames);
        assert_eq!(info_frames, 1);
        assert_eq!(body_frames, 1);
        assert_eq!(reassembled, body);
    }

    #[test]
    fn empty_body_yields_info_frame_only() {
        // Mirrors a zero-chunk stream: the streaming arm emits no body
        // frame for an empty object, so neither does the Bytes arm.
        let info = test_info();
        let frames: Vec<_> = bytes_read_frames(&info, Vec::new()).collect();
        let (body_frames, info_frames, reassembled) = collect(frames);
        assert_eq!(info_frames, 1);
        assert_eq!(body_frames, 0);
        assert!(reassembled.is_empty());
    }
}
