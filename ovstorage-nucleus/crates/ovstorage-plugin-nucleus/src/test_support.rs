// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process mock Nucleus transport used by SPI translation tests.
//!
//! Tests enqueue canned responses; the first entry matching the request's
//! `(interface, method)` plus an optional content-predicate is consumed.
//! Pure same-method enqueues preserve FIFO order. Predicate-keyed entries
//! survive concurrent dispatch when multiple racing requests arrive in
//! non-deterministic order.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use nucleus_transport::{RawResponse, Subscription, Transport, TransportDescriptor};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub(crate) struct RecordedRequest {
    pub interface: String,
    pub method: String,
    pub params: serde_json::Value,
    #[allow(dead_code)]
    pub blob: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct CannedResponse {
    pub interface: String,
    pub method: String,
    pub frames: Vec<RawFrame>,
}

#[derive(Clone, Debug)]
pub(crate) struct RawFrame {
    pub json: Vec<u8>,
    pub blob: Option<Vec<u8>>,
}

impl RawFrame {
    pub fn from_json<S: serde::Serialize>(value: &S) -> Self {
        Self {
            json: serde_json::to_vec(value).expect("test json serialize"),
            blob: None,
        }
    }

    pub fn from_json_with_blob<S: serde::Serialize>(value: &S, blob: Vec<u8>) -> Self {
        Self {
            json: serde_json::to_vec(value).expect("test json serialize"),
            blob: Some(blob),
        }
    }
}

type ParamsPredicate = Arc<dyn Fn(&serde_json::Value) -> bool + Send + Sync>;

struct CannedEntry {
    response: CannedResponse,
    /// `None` means "match any params" (legacy FIFO entry); `Some` means
    /// the entry only matches when the predicate accepts the request's
    /// params. Walked front-to-back; first matching entry is consumed.
    predicate: Option<ParamsPredicate>,
}

#[derive(Default)]
pub(crate) struct MockTransport {
    inner: Arc<MockState>,
}

#[derive(Default)]
struct MockState {
    queue: Mutex<VecDeque<CannedEntry>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a content-agnostic response. Matched by `(interface, method)`
    /// in FIFO order against any request.
    pub fn enqueue(&self, response: CannedResponse) {
        self.inner.queue.lock().unwrap().push_back(CannedEntry {
            response,
            predicate: None,
        });
    }

    /// Enqueue a response gated on a custom predicate over the request's
    /// `params` JSON. Useful when concurrent requests may arrive in any
    /// order and need pairing by content.
    #[allow(dead_code)]
    pub fn enqueue_filtered<F>(&self, response: CannedResponse, predicate: F)
    where
        F: Fn(&serde_json::Value) -> bool + Send + Sync + 'static,
    {
        self.inner.queue.lock().unwrap().push_back(CannedEntry {
            response,
            predicate: Some(Arc::new(predicate)),
        });
    }

    /// Convenience: match on `params["path"]["path"] == path`. Equivalent
    /// to `enqueue_filtered` with that predicate.
    #[allow(dead_code)]
    pub fn enqueue_for_path(&self, response: CannedResponse, path: impl Into<String>) {
        let want = path.into();
        self.enqueue_filtered(response, move |params| {
            params
                .get("path")
                .and_then(|p| p.get("path"))
                .and_then(|p| p.as_str())
                .map(|s| s == want)
                .unwrap_or(false)
        });
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.inner.requests.lock().unwrap().clone()
    }
}

impl Transport for MockTransport {
    fn descriptors() -> Vec<TransportDescriptor> {
        vec![TransportDescriptor {
            name: "mock",
            meta: &[],
        }]
    }

    fn send(
        &self,
        interface: &str,
        method: &str,
        params: serde_json::Value,
        binary: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<Subscription>> + Send {
        let inner = Arc::clone(&self.inner);
        let interface = interface.to_string();
        let method = method.to_string();
        async move {
            inner.requests.lock().unwrap().push(RecordedRequest {
                interface: interface.clone(),
                method: method.clone(),
                params: params.clone(),
                blob: binary,
            });
            let canned = {
                let mut queue = inner.queue.lock().unwrap();
                let matched_index = queue.iter().position(|entry| {
                    if entry.response.interface != interface || entry.response.method != method {
                        return false;
                    }
                    match &entry.predicate {
                        Some(pred) => pred(&params),
                        None => true,
                    }
                });
                match matched_index {
                    Some(i) => queue.remove(i).unwrap().response,
                    None => {
                        anyhow::bail!(
                            "mock transport: no matching response for {}.{} (queue len={})",
                            interface,
                            method,
                            queue.len(),
                        );
                    }
                }
            };
            // Channel must hold every queued frame so the mock never drops responses pre-consumption.
            let (tx, rx) = mpsc::channel(canned.frames.len().max(1));
            for frame in canned.frames {
                tx.send(Ok(RawResponse {
                    json: frame.json,
                    blob: frame.blob,
                }))
                .await
                .ok();
            }
            drop(tx);
            let (stop_tx, _stop_rx) = mpsc::channel(1);
            let finished = Arc::new(AtomicBool::new(false));
            Ok(Subscription::new(rx, 1, stop_tx, finished))
        }
    }
}
