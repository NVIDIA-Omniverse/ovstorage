// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use nucleus_auth::start_interactive_with_timeout;
use nucleus_transport::{RawResponse, Subscription, Transport};
use tokio::sync::mpsc;

#[derive(Default)]
struct HangingTransport {
    keepalive: Mutex<Vec<mpsc::Sender<anyhow::Result<RawResponse>>>>,
}

impl Transport for HangingTransport {
    async fn send(
        &self,
        _interface: &str,
        _method: &str,
        _params: serde_json::Value,
        _binary: Option<Vec<u8>>,
    ) -> anyhow::Result<Subscription> {
        let (tx, rx) = mpsc::channel::<anyhow::Result<RawResponse>>(1);
        let (stop_tx, _stop_rx) = mpsc::channel::<u64>(1);
        let finished = Arc::new(AtomicBool::new(false));
        self.keepalive.lock().unwrap().push(tx);
        Ok(Subscription::new(rx, 1, stop_tx, finished))
    }
}

#[tokio::test]
async fn start_interactive_times_out_when_subscribe_hangs() {
    let transport = HangingTransport::default();
    let started = Instant::now();
    let result = start_interactive_with_timeout(
        &transport,
        "https://nucleus.example/login",
        "host.example",
        Some(Duration::from_millis(50)),
    )
    .await;
    let elapsed = started.elapsed();

    let err = match result {
        Ok(_) => panic!("expected timeout error"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Tokens::subscribe first frame") && msg.contains("timed out"),
        "unexpected error: {msg}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "timeout did not fire promptly: {elapsed:?}"
    );
}
