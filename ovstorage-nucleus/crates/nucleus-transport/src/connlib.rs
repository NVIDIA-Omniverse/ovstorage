// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use anyhow::Result;
use futures::{SinkExt, StreamExt, stream::SplitSink};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::error::TransportError;
use crate::runtime::io_runtime;
use crate::transport::{RawResponse, Subscription, Transport, TransportDescriptor};

const STOP_CHANNEL_CAPACITY: usize = 1024;

struct PendingEntry {
    tx: mpsc::Sender<Result<RawResponse>>,
    finished: Arc<AtomicBool>,
}

type PendingMap = Arc<tokio::sync::Mutex<HashMap<u64, PendingEntry>>>;
type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

static CONN_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn next_conn_id() -> String {
    CONN_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

pub struct ConnLibTransport {
    conn_id: String,
    send_tx: mpsc::Sender<Message>,
    pending: PendingMap,
    next_id: Arc<AtomicU64>,
    stop_tx: mpsc::Sender<u64>,
    cancel: CancellationToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl ConnLibTransport {
    pub async fn connect(url: &str) -> Result<Self> {
        // Run the entire connect — `connect_async` plus loop spawns — on the
        // plugin-wide IO runtime. Tokio registers the underlying TCP/TLS I/O
        // driver with whichever runtime ran `connect_async`; if we did it on
        // the caller's runtime, the WebSocket stream would still depend on
        // that runtime even after we moved the loops to `io_runtime`. When
        // the caller's runtime later drops (e.g. an auth-pump runtime that
        // ends with the handshake), the stream's I/O driver disappears and
        // the read loop dies with "Tokio 1.x context ... shutdown".
        let url = url.to_string();
        io_runtime()
            .spawn(async move { Self::connect_inner(&url).await })
            .await
            .map_err(|join_err| {
                TransportError::ConnectionFailed(format!(
                    "ConnLib connect task panicked: {join_err}"
                ))
                .into()
            })
            .and_then(|result| result)
    }

    async fn connect_inner(url: &str) -> Result<Self> {
        let conn_id = next_conn_id();
        info!(conn_id = %conn_id, url, "connecting to nucleus");

        let (ws, _response) = connect_async(url).await.map_err(|e| {
            error!(conn_id = %conn_id, url, err = %e, "websocket connection failed");
            TransportError::ConnectionFailed(format!("websocket connect failed: {e}"))
        })?;

        info!(conn_id = %conn_id, url, "connected");

        let (sink, stream) = ws.split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let next_id = Arc::new(AtomicU64::new(1));
        let cancel = CancellationToken::new();

        let (send_tx, send_rx) = mpsc::channel::<Message>(64);
        let (stop_tx, stop_rx) = mpsc::channel(STOP_CHANNEL_CAPACITY);

        // We're already running on `io_runtime` (see `connect`); plain
        // `tokio::spawn` lands the loops on the same runtime that owns the
        // websocket's I/O driver.
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
            Arc::clone(&next_id),
            cancel.clone(),
            conn_id.clone(),
        ));

        Ok(Self {
            conn_id,
            send_tx,
            pending,
            next_id,
            stop_tx,
            cancel,
            handles: Mutex::new(vec![send_handle, read_handle, stop_handle]),
        })
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
                    let json_end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    let json = &data[..json_end];

                    let meta = match serde_json::from_slice::<ResponseMeta>(json) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!(conn_id = %conn_id, err = %e, "failed to parse response metadata");
                            continue;
                        }
                    };

                    let blob = if json_end < data.len() {
                        Some(data[json_end + 1..].to_vec())
                    } else {
                        None
                    };
                    let blob_len = blob.as_ref().map_or(0, |b| b.len());

                    let json_preview = String::from_utf8_lossy(json);
                    trace!(conn_id = %conn_id, id = meta.id, json_len = json.len(), blob_len, fin = meta.fin, stopped = meta.stopped, json = %json_preview, "received response");

                    let raw = RawResponse {
                        json: json.to_vec(),
                        blob,
                    };

                    let is_final = meta.fin || meta.stopped;

                    let entry = if is_final {
                        let entry = pending.lock().await.remove(&meta.id);
                        if let Some(ref e) = entry {
                            e.finished.store(true, Ordering::Relaxed);
                        }
                        entry
                    } else {
                        let map = pending.lock().await;
                        map.get(&meta.id).map(|e| PendingEntry {
                            tx: e.tx.clone(),
                            finished: Arc::clone(&e.finished),
                        })
                    };

                    if let Some(entry) = entry {
                        // Await-send applies HOL backpressure: a slow consumer
                        // pauses the read loop instead of dropping frames or
                        // terminating the sub.
                        if entry.tx.send(Ok(raw)).await.is_err() && !is_final {
                            debug!(conn_id = %conn_id, id = meta.id, "subscriber dropped");
                            pending.lock().await.remove(&meta.id);
                        }
                    } else {
                        trace!(conn_id = %conn_id, id = meta.id, "received response for unknown request");
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    // Tungstenite queues an auto-pong but only flushes it on the
                    // next outgoing frame. Idle subscriptions go silent for
                    // minutes between RPCs, so the server's "no pong received"
                    // timer fires and drops us. Reply explicitly.
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
                    warn!(conn_id = %conn_id, "unexpected websocket message type: {msg:?}");
                }
            }
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
        next_id: Arc<AtomicU64>,
        cancel: CancellationToken,
        conn_id: String,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                next = stop_rx.recv() => match next {
                    Some(subscription_id) => {
                        pending.lock().await.remove(&subscription_id);

                        let request_id = next_id.fetch_add(1, Ordering::Relaxed);
                        let frame = serde_json::json!({
                            "command": "stop",
                            "id": request_id,
                            "subscription_id": subscription_id,
                        });
                        if let Ok(bytes) = serde_json::to_vec(&frame)
                            && send_tx.send(Message::Binary(bytes)).await.is_err()
                        {
                            warn!(conn_id = %conn_id, "failed to send stop frame");
                        }
                    }
                    None => return,
                }
            }
        }
    }

    fn build_frame(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        binary: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut envelope = if params.is_object() {
            params
        } else {
            serde_json::json!({})
        };
        envelope["command"] = serde_json::json!(method);
        envelope["id"] = serde_json::json!(id);

        let json_bytes = serde_json::to_vec(&envelope)?;

        if let Some(blob) = binary {
            let mut frame = Vec::with_capacity(json_bytes.len() + 1 + blob.len());
            frame.extend_from_slice(&json_bytes);
            frame.push(0);
            frame.extend_from_slice(blob);
            Ok(frame)
        } else {
            Ok(json_bytes)
        }
    }
}

impl Drop for ConnLibTransport {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut handles) = self.handles.try_lock() {
            for h in handles.drain(..) {
                h.abort();
            }
        }
    }
}

impl Transport for ConnLibTransport {
    fn descriptors() -> Vec<TransportDescriptor> {
        vec![TransportDescriptor {
            name: "connlib",
            meta: &[],
        }]
    }

    async fn send(
        &self,
        _interface: &str,
        method: &str,
        params: serde_json::Value,
        binary: Option<Vec<u8>>,
    ) -> Result<Subscription> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = self.build_frame(id, method, params, binary.as_deref())?;
        let json_len = frame.iter().position(|&b| b == 0).unwrap_or(frame.len());
        let blob_len = frame.len().saturating_sub(json_len + 1);
        let json_preview = String::from_utf8_lossy(&frame[..json_len.min(frame.len())]);
        trace!(conn_id = %self.conn_id, id, method, json_len, blob_len, json = %json_preview, "sending request");

        let (tx, rx) = mpsc::channel(256);
        let finished = Arc::new(AtomicBool::new(false));
        self.pending.lock().await.insert(
            id,
            PendingEntry {
                tx,
                finished: Arc::clone(&finished),
            },
        );

        if let Err(e) = self.send_tx.send(Message::Binary(frame)).await {
            error!(conn_id = %self.conn_id, id, method, "failed to send request (transport disconnected)");
            self.pending.lock().await.remove(&id);
            return Err(e.into());
        }

        Ok(Subscription::new(rx, id, self.stop_tx.clone(), finished))
    }
}

/// `fin` = request complete; `stopped` = server-side cancel (don't echo a stop frame).
#[derive(serde::Deserialize)]
struct ResponseMeta {
    id: u64,
    #[serde(default)]
    fin: bool,
    #[serde(default)]
    stopped: bool,
}
