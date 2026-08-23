// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use anyhow::Result;
use futures::{SinkExt, StreamExt, stream::SplitSink};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::error::TransportError;
use crate::redact::{message_kind, message_len, redact_url};
use crate::runtime::io_runtime;
use crate::transport::{RawResponse, Subscription, Transport, TransportDescriptor};

const REQUEST_SEND: u8 = 1;
const REQUEST_STOP: u8 = 0;

const RESPONSE_ERROR: u8 = 0;
const RESPONSE_SEND: u8 = 1;
const RESPONSE_DONE: u8 = 5;

const STOP_CHANNEL_CAPACITY: usize = 1024;

static CONN_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn next_conn_id() -> String {
    CONN_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

struct PendingEntry {
    tx: mpsc::Sender<Result<RawResponse>>,
    finished: Arc<AtomicBool>,
}

type PendingMap = Arc<tokio::sync::Mutex<HashMap<u32, PendingEntry>>>;
type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

pub struct SowsTransport {
    conn_id: String,
    send_tx: mpsc::Sender<Message>,
    pending: PendingMap,
    next_id: AtomicU32,
    stop_tx: mpsc::Sender<u64>,
    cancel: CancellationToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl SowsTransport {
    pub async fn connect(url: &str) -> Result<Self> {
        // Run the entire connect on the plugin-wide IO runtime so the
        // resulting WebSocket's I/O driver is registered there, not on the
        // caller's runtime. See ConnLibTransport::connect for the full
        // explanation.
        let url = url.to_string();
        io_runtime()
            .spawn(async move { Self::connect_inner(&url).await })
            .await
            .map_err(|join_err| {
                TransportError::ConnectionFailed(format!("SOWS connect task panicked: {join_err}"))
                    .into()
            })
            .and_then(|result| result)
    }

    async fn connect_inner(url: &str) -> Result<Self> {
        let conn_id = next_conn_id();
        // No SOWS caller splices a credential into its URL today. Redacting
        // here keeps that a property of the transport rather than of every
        // caller, which is what the sibling ConnLib path failed to be.
        let logged_url = redact_url(url);
        info!(conn_id = %conn_id, url = %logged_url, "connecting");

        let (ws, _response) = connect_async(url).await.map_err(|e| {
            error!(conn_id = %conn_id, url = %logged_url, err = %e, "websocket connection failed");
            TransportError::ConnectionFailed(format!("websocket connect failed: {e}"))
        })?;

        info!(conn_id = %conn_id, url = %logged_url, "connected");

        let (sink, stream) = ws.split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let (send_tx, send_rx) = mpsc::channel::<Message>(64);
        let (stop_tx, stop_rx) = mpsc::channel(STOP_CHANNEL_CAPACITY);

        // We're on `io_runtime` (see `connect`); plain `tokio::spawn` lands
        // the loops on the same runtime that owns the websocket's I/O driver.
        let send_handle = tokio::spawn(Self::send_loop(
            sink,
            send_rx,
            Arc::clone(&pending),
            cancel.clone(),
            conn_id.clone(),
        ));
        let read_handle = tokio::spawn(Self::read_loop(
            stream,
            Arc::clone(&pending),
            cancel.clone(),
            conn_id.clone(),
            send_tx.clone(),
        ));
        let stop_handle = tokio::spawn(Self::stop_loop(
            stop_rx,
            send_tx.clone(),
            Arc::clone(&pending),
            cancel.clone(),
            conn_id.clone(),
        ));

        Ok(Self {
            conn_id,
            send_tx,
            pending,
            next_id: AtomicU32::new(1),
            stop_tx,
            cancel,
            handles: Mutex::new(vec![send_handle, read_handle, stop_handle]),
        })
    }

    fn next_id(&self) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        assert!(id < u32::MAX - 1, "SOWS request ID space exhausted");
        if id == 0 {
            self.next_id.fetch_add(1, Ordering::Relaxed)
        } else {
            id
        }
    }

    async fn read_loop(
        mut stream: futures::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        pending: PendingMap,
        cancel: CancellationToken,
        conn_id: String,
        send_tx: mpsc::Sender<Message>,
    ) {
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => {
                    Self::notify_pending_error(&conn_id, &pending, || {
                        TransportError::ConnectionClosed.into()
                    })
                    .await;
                    return;
                }
                next = stream.next() => next,
            };
            match next {
                Some(Ok(Message::Binary(data))) => {
                    if data.len() < 5 {
                        warn!(conn_id = %conn_id, len = data.len(), "response frame too short");
                        continue;
                    }

                    let resp_type = data[0];
                    let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                    let payload = &data[5..];

                    match resp_type {
                        RESPONSE_ERROR => {
                            let (code, msg) = if payload.len() >= 2 {
                                let code = u16::from_le_bytes([payload[0], payload[1]]);
                                let message =
                                    std::str::from_utf8(&payload[2..]).unwrap_or("unknown error");
                                let msg = format!("sows remote error {code}: {message}");
                                (code, msg)
                            } else {
                                (0u16, "sows remote error (no details)".into())
                            };
                            debug!(conn_id = %conn_id, id, code, "received remote error for request");
                            let err: Result<RawResponse> =
                                Err(TransportError::ConnectionFailed(msg).into());
                            let entry = pending.lock().await.remove(&id);
                            if let Some(entry) = entry {
                                entry.finished.store(true, Ordering::Relaxed);
                                let _ = entry.tx.send(err).await;
                            }
                        }
                        RESPONSE_SEND => {
                            if payload.len() < 5 {
                                Self::fail_pending(
                                    &conn_id,
                                    &pending,
                                    id,
                                    "malformed RESPONSE_SEND: header truncated",
                                )
                                .await;
                                continue;
                            }
                            let _last = payload[0];
                            let result_size = u32::from_le_bytes([
                                payload[1], payload[2], payload[3], payload[4],
                            ]) as usize;
                            let result_end = 5 + result_size;
                            if payload.len() < result_end {
                                Self::fail_pending(
                                    &conn_id,
                                    &pending,
                                    id,
                                    "malformed RESPONSE_SEND: result body truncated",
                                )
                                .await;
                                continue;
                            }
                            let json = payload[5..result_end].to_vec();
                            let json_len = json.len();
                            let blob = if payload.len() > result_end {
                                Some(payload[result_end..].to_vec())
                            } else {
                                None
                            };
                            let blob_len = blob.as_ref().map_or(0, |b| b.len());
                            // The auth response envelopes carry `access_token`
                            // and `refresh_token`, so the body stays out.
                            trace!(conn_id = %conn_id, id, json_len, blob_len, "received response");
                            let raw = Ok(RawResponse { json, blob });

                            let entry = {
                                let map = pending.lock().await;
                                map.get(&id).map(|e| PendingEntry {
                                    tx: e.tx.clone(),
                                    finished: Arc::clone(&e.finished),
                                })
                            };
                            if let Some(entry) = entry {
                                // Await-send applies HOL backpressure: a slow
                                // consumer pauses the read loop instead of
                                // dropping frames or terminating the sub.
                                if entry.tx.send(raw).await.is_err() {
                                    debug!(conn_id = %conn_id, id, "subscriber dropped");
                                    pending.lock().await.remove(&id);
                                }
                            } else {
                                debug!(conn_id = %conn_id, id, "response for unknown request");
                            }
                        }
                        RESPONSE_DONE => {
                            if let Some(entry) = pending.lock().await.remove(&id) {
                                entry.finished.store(true, Ordering::Relaxed);
                            }
                        }
                        other => {
                            // Forward-compatibility: a server adding new
                            // RESPONSE_* variants must not break old clients.
                            trace!(conn_id = %conn_id, id, response_type = other, "ignoring unknown SOWS response type");
                        }
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    // Tungstenite queues an auto-pong but only flushes it on the
                    // next outgoing frame; idle subscriptions go silent for
                    // minutes and the server's "no pong" timer drops us. Reply
                    // explicitly.
                    if send_tx.send(Message::Pong(payload)).await.is_err() {
                        trace!(conn_id = %conn_id, "send loop closed; pong dropped");
                    }
                }
                Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    info!(conn_id = %conn_id, "websocket closed");
                    cancel.cancel();
                    Self::notify_pending_error(&conn_id, &pending, || {
                        TransportError::ConnectionClosed.into()
                    })
                    .await;
                    return;
                }
                Some(Err(e)) => {
                    let msg = e.to_string();
                    warn!(conn_id = %conn_id, err = %msg, "websocket error");
                    cancel.cancel();
                    Self::notify_pending_error(&conn_id, &pending, || {
                        TransportError::ConnectionFailed(msg.clone()).into()
                    })
                    .await;
                    return;
                }
                Some(Ok(msg)) => {
                    // The payload stays out: the variant reaching this arm is
                    // text, which is the shape a server-sent auth envelope
                    // takes if it is not binary.
                    warn!(conn_id = %conn_id, kind = message_kind(&msg), len = message_len(&msg), "unexpected websocket message type");
                }
            }
        }
    }

    async fn fail_pending(conn_id: &str, pending: &PendingMap, id: u32, reason: &str) {
        warn!(conn_id = %conn_id, id, reason, "delivering terminal error to pending request");
        if let Some(entry) = pending.lock().await.remove(&id) {
            entry.finished.store(true, Ordering::Relaxed);
            let _ = entry
                .tx
                .send(Err(
                    TransportError::ConnectionFailed(reason.to_string()).into()
                ))
                .await;
        }
    }

    async fn notify_pending_error(
        conn_id: &str,
        pending: &PendingMap,
        make_err: impl Fn() -> anyhow::Error,
    ) {
        let entries: Vec<_> = pending.lock().await.drain().map(|(_, e)| e).collect();
        let pending_count = entries.len();
        info!(conn_id = %conn_id, pending_count, "connection closed, notifying pending requests");
        for entry in entries {
            entry.finished.store(true, Ordering::Relaxed);
            let _ = entry.tx.send(Err(make_err())).await;
        }
    }

    async fn send_loop(
        mut sink: WsSink,
        mut send_rx: mpsc::Receiver<Message>,
        pending: PendingMap,
        cancel: CancellationToken,
        conn_id: String,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                msg = send_rx.recv() => match msg {
                    Some(msg) => {
                        if let Err(e) = sink.send(msg).await {
                            error!(conn_id = %conn_id, err = %e, "websocket send failed, send loop exiting");
                            cancel.cancel();
                            let msg = format!("send half failed: {e}");
                            Self::notify_pending_error(&conn_id, &pending, || {
                                TransportError::ConnectionFailed(msg.clone()).into()
                            })
                            .await;
                            return;
                        }
                    }
                    None => return,
                }
            }
        }
    }

    async fn stop_loop(
        mut stop_rx: mpsc::Receiver<u64>,
        send_tx: mpsc::Sender<Message>,
        pending: PendingMap,
        cancel: CancellationToken,
        conn_id: String,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                next = stop_rx.recv() => match next {
                    Some(id) => {
                        let id32 = id as u32;
                        pending.lock().await.remove(&id32);

                        let mut frame = Vec::with_capacity(5);
                        frame.push(REQUEST_STOP);
                        frame.extend_from_slice(&id32.to_le_bytes());

                        if send_tx.send(Message::Binary(frame)).await.is_err() {
                            warn!(conn_id = %conn_id, "failed to send stop frame");
                        }
                    }
                    None => return,
                }
            }
        }
    }

    fn build_request_frame(
        &self,
        id: u32,
        interface: &str,
        method: &str,
        params: &serde_json::Value,
        blob: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let params_bytes = serde_json::to_vec(params)?;
        let blob_len = blob.map_or(0, |b| b.len());
        // `Tokens.auth_with_api_token` and `Credentials.auth` carry a literal
        // API token and a username/password payload in `params`, so the body
        // stays out of the event and only its length is reported.
        trace!(conn_id = %self.conn_id, id, interface, method, params_len = params_bytes.len(), blob_len, "sending request");
        let method_str = format!("{interface}.{method}");

        let header_len = 1 + 4 + method_str.len() + 1 + 4 + params_bytes.len();
        let total_len = header_len + blob_len;
        let mut frame = Vec::with_capacity(total_len);

        frame.push(REQUEST_SEND);
        frame.extend_from_slice(&id.to_le_bytes());
        frame.extend_from_slice(method_str.as_bytes());
        frame.push(0);
        frame.extend_from_slice(&(params_bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&params_bytes);

        if let Some(b) = blob {
            frame.extend_from_slice(b);
        }

        Ok(frame)
    }
}

impl Drop for SowsTransport {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut handles) = self.handles.try_lock() {
            for h in handles.drain(..) {
                h.abort();
            }
        }
    }
}

impl Transport for SowsTransport {
    fn descriptors() -> Vec<TransportDescriptor> {
        vec![
            TransportDescriptor {
                name: "sows",
                meta: &[
                    ("serializer", "json"),
                    ("marshaller", "bs"),
                    ("ssl", "true"),
                ],
            },
            TransportDescriptor {
                name: "sows",
                meta: &[
                    ("serializer", "json"),
                    ("marshaller", "bs"),
                    ("ssl", "true"),
                    ("supports_path", "true"),
                ],
            },
            TransportDescriptor {
                name: "sows",
                meta: &[
                    ("serializer", "json"),
                    ("marshaller", "bs"),
                    ("ssl", "false"),
                ],
            },
            TransportDescriptor {
                name: "sows",
                meta: &[
                    ("serializer", "json"),
                    ("marshaller", "bs"),
                    ("ssl", "false"),
                    ("supports_path", "true"),
                ],
            },
        ]
    }

    fn send(
        &self,
        interface: &str,
        method: &str,
        params: serde_json::Value,
        binary: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Subscription>> + Send {
        let id = self.next_id();
        let frame_res = self.build_request_frame(id, interface, method, &params, binary.as_deref());

        let (tx, rx) = mpsc::channel(256);
        let finished = Arc::new(AtomicBool::new(false));
        let pending = Arc::clone(&self.pending);
        let send_tx = self.send_tx.clone();
        let stop_tx = self.stop_tx.clone();
        let conn_id = self.conn_id.clone();

        async move {
            let frame = match frame_res {
                Ok(f) => f,
                Err(e) => return Err(e),
            };

            pending.lock().await.insert(
                id,
                PendingEntry {
                    tx,
                    finished: Arc::clone(&finished),
                },
            );

            if let Err(e) = send_tx.send(Message::Binary(frame)).await {
                error!(conn_id = %conn_id, id, method, "failed to send request (transport disconnected)");
                pending.lock().await.remove(&id);
                return Err(e.into());
            }
            Ok(Subscription::new(rx, id as u64, stop_tx, finished))
        }
    }
}
