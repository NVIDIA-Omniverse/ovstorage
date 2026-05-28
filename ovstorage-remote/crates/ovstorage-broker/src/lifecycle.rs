// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker process lifecycle: SIGHUP reload + graceful drain.
//!
//! SIGHUP (Unix) atomically swaps the live `Broker` behind the shared
//! `BrokerHandle`; in-flight RPCs hold their snapshot, new RPCs see the
//! new broker. On reload failure the running broker stays in place —
//! the broker never serves a half-loaded config. `policy_epoch` advances
//! on success so stale clients get `PolicyEpochStale` and re-resolve.
//!
//! SIGTERM / SIGINT (Unix) and CTRL-C / CTRL-BREAK (Windows) drain via
//! `serve_with_incoming_shutdown`, then wait up to `drain_timeout`.
//!
//! Windows has no SIGHUP; reload there is deferred to an admin RPC.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::Result;

use crate::{BrokerGrpcServer, BrokerHandle};

pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Lifecycle controller; owns the swappable handle and running servers.
pub struct LifecycleController {
    broker_handle: BrokerHandle,
    servers: Vec<BrokerGrpcServer>,
    drain_timeout: Duration,
    config_path: Option<std::path::PathBuf>,
}

impl LifecycleController {
    pub fn new(broker_handle: BrokerHandle, servers: Vec<BrokerGrpcServer>) -> Self {
        Self {
            broker_handle,
            servers,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            config_path: None,
        }
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Path the SIGHUP reloader re-reads; SIGHUP is a no-op when unset.
    pub fn with_config_path(mut self, path: std::path::PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Snapshot of the current live broker.
    pub fn current_broker(&self) -> Arc<crate::Broker> {
        self.broker_handle.load_full()
    }

    pub fn broker_handle(&self) -> BrokerHandle {
        Arc::clone(&self.broker_handle)
    }

    /// Re-parse, build, swap. On any failure the existing broker stays
    /// live; caller decides whether to log or escalate.
    pub async fn reload(&self) -> Result<u64> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ovstorage::Error::new(
                ovstorage::ErrorCode::NotConfigured,
                "broker reload requested but no config path was configured",
            )
        })?;
        let config = crate::load_broker_config_file(path)?;
        crate::validate_broker_config_for_startup(&config)?;
        let prev_epoch = self.broker_handle.load_full().current_policy_epoch();
        let new_broker =
            crate::build_broker_from_config_str(&std::fs::read_to_string(path).map_err(|err| {
                ovstorage::Error::new(
                    ovstorage::ErrorCode::Transient,
                    format!("broker reload could not re-read config: {err}"),
                )
            })?)
            .await?;
        // In-memory mode resets to epoch 0 on rebuild; advance past
        // the previous live epoch so each reload yields a strictly
        // fresher epoch. (On-disk store path does this naturally via
        // `PolicyEpochState::open`.)
        let mut new_epoch = new_broker.advance_policy_epoch()?;
        while new_epoch <= prev_epoch {
            new_epoch = new_broker.advance_policy_epoch()?;
        }
        self.broker_handle.store(Arc::new(new_broker));
        tracing::info!(
            target: "ovstorage.broker.lifecycle",
            event = "reload",
            policy_epoch = new_epoch,
            "broker config reloaded; policy_epoch advanced"
        );
        Ok(new_epoch)
    }

    /// Send shutdown to every server; returns immediately.
    pub fn signal_drain(&mut self) {
        for server in &mut self.servers {
            server.fire_shutdown();
        }
    }

    /// Run the lifecycle loop until drain completes or timeout fires.
    pub async fn run(mut self) -> Result<()> {
        let drain_timeout = self.drain_timeout;
        let mut reload_signal = install_reload_signal();
        let mut shutdown_signal = install_shutdown_signal();
        loop {
            tokio::select! {
                Some(()) = reload_signal.recv() => {
                    match self.reload().await {
                        Ok(epoch) => {
                            tracing::info!(
                                target: "ovstorage.broker.lifecycle",
                                event = "reload_ok",
                                policy_epoch = epoch,
                                "SIGHUP reload completed"
                            );
                            metrics::counter!(crate::observability::LIFECYCLE_EVENTS, "event" => "reload_ok").increment(1);
                            metrics::counter!(crate::observability::POLICY_EPOCH_ADVANCES).increment(1);
                        }
                        Err(err) => {
                            tracing::warn!(
                                target: "ovstorage.broker.lifecycle",
                                event = "reload_failed",
                                error = %err.message(),
                                "SIGHUP reload failed; running broker unchanged"
                            );
                            metrics::counter!(crate::observability::LIFECYCLE_EVENTS, "event" => "reload_failed").increment(1);
                        }
                    }
                }
                Some(()) = shutdown_signal.recv() => {
                    tracing::info!(
                        target: "ovstorage.broker.lifecycle",
                        event = "drain_start",
                        timeout_secs = drain_timeout.as_secs(),
                        "shutdown signal received; draining"
                    );
                    metrics::counter!(crate::observability::LIFECYCLE_EVENTS, "event" => "drain_start").increment(1);
                    self.signal_drain();
                    let drained: Vec<_> = self
                        .servers
                        .iter_mut()
                        .filter_map(|s| s.take_drained())
                        .collect();
                    let outcome = tokio::time::timeout(
                        drain_timeout,
                        futures::future::join_all(drained),
                    )
                    .await;
                    let timed_out = outcome.is_err();
                    tracing::info!(
                        target: "ovstorage.broker.lifecycle",
                        event = "drain_complete",
                        timed_out,
                        "drain finished; exiting"
                    );
                    metrics::counter!(crate::observability::LIFECYCLE_EVENTS, "event" => "drain_complete").increment(1);
                    return Ok(());
                }
                else => {
                    return Ok(());
                }
            }
        }
    }
}

/// SIGHUP listener (Unix) or no-op (Windows).
#[cfg(unix)]
fn install_reload_signal() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(
                    target: "ovstorage.broker.lifecycle",
                    error = %err,
                    "failed to install SIGHUP handler"
                );
                return;
            }
        };
        while signal.recv().await.is_some() {
            if tx.send(()).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(windows)]
fn install_reload_signal() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    // No SIGHUP on Windows; receiver kept open so select! doesn't
    // yield prematurely.
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    rx
}

#[cfg(unix)]
fn install_shutdown_signal() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let term_tx = tx.clone();
    tokio::spawn(async move {
        let mut signal =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!(
                        target: "ovstorage.broker.lifecycle",
                        error = %err,
                        "failed to install SIGTERM handler"
                    );
                    return;
                }
            };
        while signal.recv().await.is_some() {
            if term_tx.send(()).is_err() {
                break;
            }
        }
    });
    let int_tx = tx;
    tokio::spawn(async move {
        let mut signal =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!(
                        target: "ovstorage.broker.lifecycle",
                        error = %err,
                        "failed to install SIGINT handler"
                    );
                    return;
                }
            };
        while signal.recv().await.is_some() {
            if int_tx.send(()).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(windows)]
fn install_shutdown_signal() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let break_tx = tx.clone();
    tokio::spawn(async move {
        let mut signal = match tokio::signal::windows::ctrl_break() {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(
                    target: "ovstorage.broker.lifecycle",
                    error = %err,
                    "failed to install ctrl-break handler"
                );
                return;
            }
        };
        while signal.recv().await.is_some() {
            if break_tx.send(()).is_err() {
                break;
            }
        }
    });
    let c_tx = tx;
    tokio::spawn(async move {
        let mut signal = match tokio::signal::windows::ctrl_c() {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(
                    target: "ovstorage.broker.lifecycle",
                    error = %err,
                    "failed to install ctrl-c handler"
                );
                return;
            }
        };
        while signal.recv().await.is_some() {
            if c_tx.send(()).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{broker_handle, build_default_broker};

    #[tokio::test]
    async fn current_broker_returns_swappable_snapshot() {
        let broker = build_default_broker().await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle, Vec::new());
        let first = controller.current_broker();
        let second = controller.current_broker();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn signal_drain_fires_shutdown_on_all_servers() {
        let broker = build_default_broker().await.unwrap();
        let handle = broker_handle(broker);
        let server = crate::spawn_broker_grpc_tcp_listener_with_handle(
            handle.clone(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut controller = LifecycleController::new(handle, vec![server]);
        controller.signal_drain();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn reload_advances_epoch_strictly_in_memory() {
        crate::test_utils::ensure_test_plugin_env();
        let dir = std::env::temp_dir().join(format!(
            "ovstorage-broker-reload-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("broker.toml");
        std::fs::write(
            &cfg,
            r#"
[authz]
plugin = "ovstorage-authz-toml"
"#,
        )
        .unwrap();
        let broker = build_default_broker().await.unwrap();
        let handle = broker_handle(broker);
        let controller =
            LifecycleController::new(handle.clone(), Vec::new()).with_config_path(cfg.clone());
        let first = controller.reload().await.unwrap();
        let second = controller.reload().await.unwrap();
        assert!(
            second > first,
            "reload epochs must advance strictly: first={first}, second={second}"
        );
        let live = controller.current_broker();
        assert_eq!(
            live.policy_state.check(first).unwrap_err().code(),
            ovstorage::ErrorCode::PolicyEpochStale,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
