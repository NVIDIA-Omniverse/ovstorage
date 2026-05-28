// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tracing::Instrument;

/// Aggregate body cap; tonic only bounds per-frame size, not total
/// accumulated bytes. 64 MiB matches the prior implicit ceiling.
const WRITE_BODY_BYTE_CAP: usize = 64 * 1024 * 1024;

/// Bodies up to this size accumulate into `Body::Bytes` so dispatcher
/// behaviors that key on body type (cache fill on Body::Bytes; some
/// plugins' meta-path knobs) keep working. Above this threshold the
/// body switches to chunk-by-chunk `Body::Stream` so multi-MiB / GiB
/// uploads never sit in broker memory.
const WRITE_STREAM_THRESHOLD: usize = 1024 * 1024;

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
            self.broker_handle.load().watch_directory_hub.cancel_all();
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
    spawn_broker_grpc_tcp_listener_inner(
        wrap_broker_in_handle(broker),
        listen,
        None,
        GrpcAuthn::dev_current_user(),
    )
}

/// SIGHUP-aware variant: shared `BrokerHandle` lets the lifecycle
/// controller atomically swap the live `Broker`; in-flight RPCs hold
/// their dispatch-time snapshot.
pub fn spawn_broker_grpc_tcp_listener_with_handle(
    broker_handle: BrokerHandle,
    listen: SocketAddr,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(broker_handle, listen, None, GrpcAuthn::dev_current_user())
}

pub fn spawn_broker_grpc_tcp_listener_with_tls(
    broker: Arc<Broker>,
    listen: SocketAddr,
    tls: Option<&BrokerListenerTlsConfig>,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(
        wrap_broker_in_handle(broker),
        listen,
        tls,
        GrpcAuthn::dev_current_user(),
    )
}

pub fn spawn_broker_grpc_tcp_listener_with_config(
    broker: Arc<Broker>,
    listen: SocketAddr,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(
        wrap_broker_in_handle(broker),
        listen,
        listener_config.tls.as_ref(),
        GrpcAuthn::from_listener(listener_config)?,
    )
}

pub fn spawn_broker_grpc_tcp_listener_with_handle_and_config(
    broker_handle: BrokerHandle,
    listen: SocketAddr,
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    spawn_broker_grpc_tcp_listener_inner(
        broker_handle,
        listen,
        listener_config.tls.as_ref(),
        GrpcAuthn::from_listener(listener_config)?,
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
    authn: GrpcAuthn,
) -> ovstorage::Result<BrokerGrpcServer> {
    let listener = std::net::TcpListener::bind(listen).map_err(map_io)?;
    listener.set_nonblocking(true).map_err(map_io)?;
    let local_addr = listener.local_addr().map_err(map_io)?;
    let tls_config = match tls {
        Some(tls) => {
            let cert = fs::read(&tls.cert_path).map_err(map_io)?;
            let key = fs::read(&tls.key_path).map_err(map_io)?;
            Some(
                tonic::transport::ServerTlsConfig::new()
                    .identity(tonic::transport::Identity::from_pem(cert, key)),
            )
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
                        authn,
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
    listener_config: &BrokerListenerConfig,
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
    let authn = GrpcAuthn::from_listener(listener_config)?;
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
                        authn,
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
    listener_config: &BrokerListenerConfig,
) -> ovstorage::Result<BrokerGrpcServer> {
    let name = normalize_named_pipe_name(name.as_ref())?;
    let pipe_path = named_pipe_path(&name);
    let authn = GrpcAuthn::from_listener(listener_config)?;
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
                        authn,
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

#[derive(Clone)]
pub(crate) struct GrpcBrokerService {
    broker_handle: BrokerHandle,
    authn: GrpcAuthn,
}

impl GrpcBrokerService {
    fn broker(&self) -> Arc<Broker> {
        self.broker_handle.load_full()
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

/// Build a `tonic::Status` folding `audit_id` and `policy_epoch` into
/// `pb::ErrorDetail`; preferred over `protocol::error_to_status` when a
/// `RequestContext` is in scope.
fn ctx_status(error: ovstorage::Error, context: &RequestContext) -> Status {
    protocol::error_to_status_with_context(
        error,
        None,
        context.audit_id.as_deref(),
        Some(context.policy_epoch),
    )
}

/// Like [`ctx_status`] but also threads the parsed `address`.
fn ctx_status_addr(
    error: ovstorage::Error,
    context: &RequestContext,
    address: &ovstorage_plugin::Url,
) -> Status {
    protocol::error_to_status_with_context(
        error,
        Some(address),
        context.audit_id.as_deref(),
        Some(context.policy_epoch),
    )
}

type GrpcReadStream =
    Pin<Box<dyn Stream<Item = Result<pb::ReadResponse, Status>> + Send + 'static>>;
type GrpcWriteStream =
    Pin<Box<dyn Stream<Item = Result<pb::WriteResponse, Status>> + Send + 'static>>;
type GrpcWatchDirectoryStream =
    Pin<Box<dyn Stream<Item = Result<pb::WatchDirectoryResponse, Status>> + Send + 'static>>;
type GrpcWatchAddressRootsStream =
    Pin<Box<dyn Stream<Item = Result<pb::AddressRootsChange, Status>> + Send + 'static>>;
type GrpcAuthStream =
    Pin<Box<dyn Stream<Item = Result<pb::AuthEventEnvelope, Status>> + Send + 'static>>;

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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let span = tracing::info_span!(
            "broker.list_address_roots",
            op = "list_address_roots",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let _span = tracing::info_span!(
            "broker.watch_address_roots",
            op = "watch_address_roots",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.stat",
            op = "stat",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.read",
            op = "read",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
                // Two-frame shape: info then body; gRPC stream close
                // is the terminator (no explicit frame).
                let info_frame = pb::ReadResponse {
                    result: Some(pb::read_response::Result::Info(
                        protocol::object_info_to_proto(&info),
                    )),
                };
                let body_frame = pb::ReadResponse {
                    result: Some(pb::read_response::Result::Body(bytes)),
                };
                Ok(GrpcResponse::new(Box::pin(tokio_stream::iter(vec![
                    Ok(info_frame),
                    Ok(body_frame),
                ]))))
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
        let context = self.request_context(self.authn.input(&request)?).await?;
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
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        let _guard = _span.enter();
        let options = protocol::write_options_from_proto(open.options)
            .map_err(|e| ctx_status_addr(e, &context, &address))?;
        // Pre-flight authz so unauthorized callers get PermissionDenied
        // before any body chunk is accepted.
        self.broker()
            .authorize_for_grpc(&context, Operation::Write, Some(&address))
            .await
            .map_err(|e| ctx_status_addr(e, &context, &address))?;
        // Drain frames up to WRITE_STREAM_THRESHOLD. Below it, dispatch
        // as Body::Bytes so dispatcher cache-fill and plugins' Bytes-only
        // meta-path knobs stay wired. At/above it, hand off to a streaming
        // bridge so multi-MiB / GiB writes never sit in broker memory.
        let body_cap = WRITE_BODY_BYTE_CAP;
        let mut buffered: Vec<u8> = Vec::new();
        let mut overflow: Option<Vec<u8>> = None;
        loop {
            let frame = match stream.message().await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(status) if status.code() == tonic::Code::Cancelled => {
                    drop(buffered);
                    return Err(Status::cancelled("client cancelled write"));
                }
                Err(status) => return Err(status),
            };
            match frame
                .step
                .ok_or_else(|| Status::invalid_argument("broker write request is missing a step"))?
            {
                pb::write_request::Step::Open(_) => {
                    return Err(Status::invalid_argument(
                        "write Open frame must appear exactly once",
                    ));
                }
                pb::write_request::Step::Chunk(chunk) => {
                    if buffered.len().saturating_add(chunk.len()) > body_cap {
                        return Err(Status::resource_exhausted(format!(
                            "write body exceeded broker buffer cap of {body_cap} bytes",
                        )));
                    }
                    if buffered.len().saturating_add(chunk.len()) > WRITE_STREAM_THRESHOLD {
                        overflow = Some(chunk);
                        break;
                    }
                    buffered.extend(chunk);
                }
                pb::write_request::Step::RedirectResults(_) => {
                    return Err(Status::invalid_argument(
                        "redirect results must be sent with ContinueWrite",
                    ));
                }
            }
        }

        let outcome = if let Some(first_overflow) = overflow {
            // Streaming path. Hand the in-flight tonic stream off to a
            // task that pushes remaining frames through a bounded
            // async channel. The producer must await backpressure
            // instead of blocking a Tokio worker: newer HTTP/2 stacks
            // need runtime progress while large request bodies are in
            // flight. The consumer is still the synchronous SPI
            // `BodyStream`, so its blocking receive is wrapped below.
            //
            // The cap counter runs in the task; overflow surfaces as
            // a ResourceExhausted chunk on the next pull. Consumers
            // pull at the pace of the backend.
            let (tx, rx) = async_channel::bounded::<ovstorage::Result<Vec<u8>>>(16);
            let initial_total = buffered.len() + first_overflow.len();
            // Seed with everything we already drained so the consumer
            // sees the full body in order. Skip an empty seed when
            // the very first chunk overflowed (no buffering happened).
            if !buffered.is_empty() {
                let _ = tx.send(Ok(std::mem::take(&mut buffered))).await;
            }
            let _ = tx.send(Ok(first_overflow)).await;
            tokio::spawn(async move {
                let mut total = initial_total;
                loop {
                    match stream.message().await {
                        Ok(Some(message)) => {
                            let step = match message.step {
                                Some(step) => step,
                                None => {
                                    let _ = tx
                                        .send(Err(ovstorage::Error::new(
                                            ovstorage::ErrorCode::InvalidArgument,
                                            "broker write request is missing a step",
                                        )))
                                        .await;
                                    return;
                                }
                            };
                            match step {
                                pb::write_request::Step::Open(_) => {
                                    let _ = tx
                                        .send(Err(ovstorage::Error::new(
                                            ovstorage::ErrorCode::InvalidArgument,
                                            "write Open frame must appear exactly once",
                                        )))
                                        .await;
                                    return;
                                }
                                pb::write_request::Step::Chunk(chunk) => {
                                    if total.saturating_add(chunk.len()) > body_cap {
                                        let _ = tx
                                            .send(Err(ovstorage::Error::new(
                                                ovstorage::ErrorCode::ResourceExhausted,
                                                format!(
                                                    "write body exceeded broker buffer cap \
                                                     of {body_cap} bytes"
                                                ),
                                            )))
                                            .await;
                                        return;
                                    }
                                    total += chunk.len();
                                    if tx.send(Ok(chunk)).await.is_err() {
                                        return;
                                    }
                                }
                                pb::write_request::Step::RedirectResults(_) => {
                                    let _ = tx
                                        .send(Err(ovstorage::Error::new(
                                            ovstorage::ErrorCode::InvalidArgument,
                                            "redirect results must be sent with ContinueWrite",
                                        )))
                                        .await;
                                    return;
                                }
                            }
                        }
                        Ok(None) => return,
                        Err(status) if status.code() == tonic::Code::Cancelled => {
                            let _ = tx
                                .send(Err(ovstorage::Error::new(
                                    ovstorage::ErrorCode::Cancelled,
                                    "client cancelled write",
                                )))
                                .await;
                            return;
                        }
                        Err(status) => {
                            let _ = tx
                                .send(Err(ovstorage::Error::new(
                                    ovstorage::ErrorCode::Transient,
                                    format!("broker gRPC body read error: {status}"),
                                )))
                                .await;
                            return;
                        }
                    }
                }
            });
            let body_stream =
                ovstorage_plugin::BodyStream::from_iter(std::iter::from_fn(move || {
                    blocking_recv_body_chunk(&rx)
                }));
            self.broker()
                .write(&context, address, Body::Stream(body_stream), options)
                .await
                .map_err(|e| ctx_status(e, &context))?
        } else {
            self.broker()
                .write(&context, address, Body::Bytes(buffered), options)
                .await
                .map_err(|e| ctx_status(e, &context))?
        };
        let response = match outcome {
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
        };
        Ok(GrpcResponse::new(Box::pin(tokio_stream::iter(vec![Ok(
            response,
        )]))))
    }

    async fn write_redirect(
        &self,
        request: Request<pb::WriteRedirectRequest>,
    ) -> Result<GrpcResponse<pb::WriteRedirectResponse>, Status> {
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.write_redirect",
            op = "write_redirect",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.continue_write",
            op = "continue_write",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.delete",
            op = "delete",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let prefix = protocol::object_address_from_proto(request.prefix)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.list",
            op = "list",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.list_versions",
            op = "list_versions",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.get_latest_version",
            op = "get_latest_version",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let prefix = request.prefix.clone();
        let prefix_addr = protocol::object_address_from_proto(prefix.clone())
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.watch_directory",
            op = "watch_directory",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.create_directory",
            op = "create_directory",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.delete_directory",
            op = "delete_directory",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let source = protocol::object_address_from_proto(request.source)
            .map_err(|e| ctx_status(e, &context))?;
        let destination = protocol::object_address_from_proto(request.destination)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.copy",
            op = "copy",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let source = protocol::object_address_from_proto(request.source)
            .map_err(|e| ctx_status(e, &context))?;
        let destination = protocol::object_address_from_proto(request.destination)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.rename",
            op = "rename",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address.clone())
            .map_err(|e| ctx_status(e, &context))?;
        let options = protocol::update_metadata_options_from_proto(&request);
        let span = tracing::info_span!(
            "broker.update_metadata",
            op = "update_metadata",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.check_access",
            op = "check_access",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
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
        // Auth RPC is the one place `x-ov-iauth` steers behavior; non-
        // auth RPCs use the capability-agnostic `request_context`.
        let input = self.authn.input(&request)?;
        let (context, capability) = self
            .request_context_with_metadata(input, Some(request.metadata()))
            .await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let _span = tracing::info_span!(
            "broker.auth",
            op = "auth",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        let _guard = _span.enter();
        let stream = self
            .broker()
            .open_upstream_auth_stream(&context, capability, address)
            .await
            .map_err(|e| ctx_status(e, &context))?;
        Ok(GrpcResponse::new(stream))
    }

    async fn register_credential(
        &self,
        request: Request<pb::RegisterCredentialRequest>,
    ) -> Result<GrpcResponse<pb::RegisterCredentialResponse>, Status> {
        let context = self.request_context(self.authn.input(&request)?).await?;
        let request = request.into_inner();
        let address = protocol::object_address_from_proto(request.address)
            .map_err(|e| ctx_status(e, &context))?;
        let span = tracing::info_span!(
            "broker.register_credential",
            op = "register_credential",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            audit_id = context.audit_id.as_deref(),
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            let payload = ovstorage_broker_protocol::RegisterCredentialPayload {
                access_token: request.access_token,
                refresh_token: (!request.refresh_token.is_empty()).then_some(request.refresh_token),
                expires_at: (request.expires_at_unix_millis > 0).then(|| {
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_millis(request.expires_at_unix_millis)
                }),
            };
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

impl GrpcBrokerService {
    async fn request_context(&self, input: GrpcAuthnInput) -> Result<RequestContext, Status> {
        let (context, _capability) = self.request_context_with_metadata(input, None).await?;
        Ok(context)
    }

    /// Build a `RequestContext` plus the host-declared
    /// `InteractiveAuthCapability` for the `auth` RPC; capability
    /// defaults to `Browser` when `metadata` is `None`. The capability
    /// is returned alongside (not inside) the context because it's a
    /// listener-authn signal, not an authz input.
    async fn request_context_with_metadata(
        &self,
        input: GrpcAuthnInput,
        metadata: Option<&tonic::metadata::MetadataMap>,
    ) -> Result<(RequestContext, ovstorage_plugin::InteractiveAuthCapability), Status> {
        let principal = self.authn.principal(input).await?;
        let capability = metadata
            .map(ovstorage_broker_protocol::capability_from_metadata)
            .unwrap_or(ovstorage_plugin::InteractiveAuthCapability::Browser);
        Ok((self.broker().context_for_principal(principal), capability))
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
