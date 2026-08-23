// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use futures::Stream;
use tokio::sync::mpsc;
use tracing::warn;

use crate::error::TransportError;

#[derive(Debug)]
pub struct RawResponse {
    pub json: Vec<u8>,
    pub blob: Option<Vec<u8>>,
}

pub struct Subscription {
    rx: mpsc::Receiver<Result<RawResponse>>,
    id: u64,
    stop_tx: mpsc::Sender<u64>,
    finished: Arc<AtomicBool>,
}

impl Subscription {
    pub fn new(
        rx: mpsc::Receiver<Result<RawResponse>>,
        id: u64,
        stop_tx: mpsc::Sender<u64>,
        finished: Arc<AtomicBool>,
    ) -> Self {
        Self {
            rx,
            id,
            stop_tx,
            finished,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn recv_raw(&mut self) -> Result<RawResponse, TransportError> {
        // The inner channel item is `anyhow::Result<RawResponse>` from
        // upstream legacy code; downcast / wrap rather than erase.
        match self.rx.recv().await {
            Some(Ok(raw)) => Ok(raw),
            Some(Err(err)) => Err(TransportError::ConnectionFailed(err.to_string())),
            None => Err(TransportError::SubscriptionClosed),
        }
    }

    pub async fn recv<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<(T, Option<Vec<u8>>), TransportError> {
        let raw = self.recv_raw().await?;
        let resp: T = serde_json::from_slice(&raw.json)?;
        Ok((resp, raw.blob))
    }

    pub async fn recv_timeout<T: serde::de::DeserializeOwned>(
        &mut self,
        duration: Duration,
    ) -> Result<(T, Option<Vec<u8>>), TransportError> {
        tokio::time::timeout(duration, self.recv())
            .await
            .map_err(|_| TransportError::Timeout)?
    }

    pub async fn stop(&mut self) {
        self.finished.store(true, Ordering::Relaxed);
        self.rx.close();
        let _ = self.stop_tx.send(self.id).await;
    }
}

impl Stream for Subscription {
    type Item = Result<RawResponse>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if !self.finished.load(Ordering::Relaxed)
            && let Err(e) = self.stop_tx.try_send(self.id)
        {
            warn!(id = self.id, err = %e, "subscription drop cancellation lost");
        }
    }
}

pub struct TransportDescriptor {
    pub name: &'static str,
    pub meta: &'static [(&'static str, &'static str)],
}

pub trait Transport: Send + Sync {
    fn descriptors() -> Vec<TransportDescriptor>
    where
        Self: Sized,
    {
        vec![]
    }

    fn send(
        &self,
        interface: &str,
        method: &str,
        params: serde_json::Value,
        binary: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Subscription>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_recv_returns_sent_data() {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, _stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 42, stop_tx, finished);

        assert_eq!(sub.id(), 42);

        let raw = RawResponse {
            json: br#"{"ok":true}"#.to_vec(),
            blob: None,
        };
        tx.send(Ok(raw)).await.unwrap();

        let result = sub.recv_raw().await.unwrap();
        assert_eq!(result.json, br#"{"ok":true}"#);
        assert!(result.blob.is_none());
    }

    #[tokio::test]
    async fn subscription_recv_deserializes_json() {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, _stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 1, stop_tx, finished);

        let raw = RawResponse {
            json: br#"{"value":123}"#.to_vec(),
            blob: Some(vec![0xDE, 0xAD]),
        };
        tx.send(Ok(raw)).await.unwrap();

        #[derive(serde::Deserialize)]
        struct Resp {
            value: u32,
        }
        let (resp, blob): (Resp, _) = sub.recv().await.unwrap();
        assert_eq!(resp.value, 123);
        assert_eq!(blob.unwrap(), vec![0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn subscription_recv_timeout_fires() {
        let (_tx, rx) = mpsc::channel::<Result<RawResponse>>(4);
        let (stop_tx, _stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 1, stop_tx, finished);

        let result = sub
            .recv_timeout::<serde_json::Value>(Duration::from_millis(10))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn subscription_recv_raw_errors_on_closed_channel() {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, _stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 1, stop_tx, finished);

        drop(tx);

        let result = sub.recv_raw().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("closed"));
    }

    #[tokio::test]
    async fn subscription_stop_sets_finished() {
        let (_tx, rx) = mpsc::channel(4);
        let (stop_tx, mut stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 99, stop_tx, Arc::clone(&finished));

        sub.stop().await;

        assert!(finished.load(Ordering::Relaxed));
        let stopped_id = stop_rx.recv().await.unwrap();
        assert_eq!(stopped_id, 99);
    }

    #[tokio::test]
    async fn subscription_drop_sends_stop_if_not_finished() {
        let (_tx, rx) = mpsc::channel(4);
        let (stop_tx, mut stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let sub = Subscription::new(rx, 77, stop_tx, finished);

        drop(sub);

        let stopped_id = stop_rx.recv().await.unwrap();
        assert_eq!(stopped_id, 77);
    }

    #[tokio::test]
    async fn subscription_drop_skips_stop_if_already_finished() {
        let (_tx, rx) = mpsc::channel(4);
        let (stop_tx, mut stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(true));
        let sub = Subscription::new(rx, 77, stop_tx, finished);

        drop(sub);

        let result = stop_rx.try_recv();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subscription_implements_stream() {
        use futures::StreamExt;

        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, _stop_rx) = mpsc::channel(4);
        let finished = Arc::new(AtomicBool::new(false));
        let mut sub = Subscription::new(rx, 1, stop_tx, finished);

        let raw = RawResponse {
            json: b"{}".to_vec(),
            blob: None,
        };
        tx.send(Ok(raw)).await.unwrap();
        drop(tx);

        let mut count = 0;
        while let Some(item) = sub.next().await {
            assert!(item.is_ok());
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn default_descriptors_is_empty() {
        struct DummyTransport;
        impl Transport for DummyTransport {
            async fn send(
                &self,
                _interface: &str,
                _method: &str,
                _params: serde_json::Value,
                _binary: Option<Vec<u8>>,
            ) -> Result<Subscription> {
                unimplemented!()
            }
        }
        assert!(DummyTransport::descriptors().is_empty());
    }
}
