// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker process lifecycle: SIGHUP reload + graceful drain.
//!
//! SIGHUP (Unix) atomically swaps the live `Broker` behind the shared
//! `BrokerHandle`; in-flight RPCs hold their snapshot, new RPCs see the
//! new broker. On reload failure the running broker stays in place —
//! the broker never serves a half-loaded config.
//!
//! SIGTERM / SIGINT (Unix) and CTRL-C / CTRL-BREAK (Windows) drain via
//! `serve_with_incoming_shutdown`, then wait up to `drain_timeout`.
//!
//! Windows has no SIGHUP; reload there is deferred to an admin RPC.

use std::sync::Arc;
use std::time::Duration;

use ovstorage::Result;

use crate::{BrokerGrpcServer, BrokerHandle, BrokerListenerConfig};

pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Lifecycle controller; owns the swappable handle and running servers.
pub struct LifecycleController {
    broker_handle: BrokerHandle,
    servers: Vec<BrokerGrpcServer>,
    drain_timeout: Duration,
    config_path: Option<std::path::PathBuf>,
    listener_snapshot: Option<ListenerRuntimeSnapshot>,
    /// The effective `--listen` bind override, if the broker was started with
    /// one. The config file never carries it, so `reload` re-applies it before
    /// snapshotting the reloaded listener; otherwise the file-derived reload
    /// snapshot could never match the effective running listener.
    listen_override: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenerRuntimeSnapshot(Option<ListenerRuntimeConfig>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenerRuntimeConfig {
    bind: String,
    tls: Option<TlsRuntimeConfig>,
    forwarded: Option<crate::BrokerForwardedHeaderConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TlsRuntimeConfig {
    config: crate::BrokerListenerTlsConfig,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    client_ca: Option<Vec<u8>>,
}

impl ListenerRuntimeSnapshot {
    fn capture(listener: Option<&BrokerListenerConfig>) -> Result<Self> {
        let Some(listener) = listener else {
            return Ok(Self(None));
        };
        let tls = listener
            .tls
            .as_ref()
            .map(|config| -> Result<TlsRuntimeConfig> {
                Ok(TlsRuntimeConfig {
                    config: config.clone(),
                    certificate: read_listener_file(&config.cert_path)?,
                    private_key: read_listener_file(&config.key_path)?,
                    client_ca: config
                        .client_ca_path
                        .as_ref()
                        .map(|path| read_listener_file(path))
                        .transpose()?,
                })
            })
            .transpose()?;
        let forwarded = crate::broker_listener_forwarded_header_config(Some(listener))?;
        Ok(Self(Some(ListenerRuntimeConfig {
            bind: listener.bind.clone(),
            tls,
            forwarded,
        })))
    }
}

fn read_listener_file(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| {
        ovstorage::Error::new(
            ovstorage::ErrorCode::Transient,
            format!(
                "could not read listener runtime file '{}': {error}",
                path.display()
            ),
        )
    })
}

impl LifecycleController {
    pub fn new(broker_handle: BrokerHandle, servers: Vec<BrokerGrpcServer>) -> Self {
        Self {
            broker_handle,
            servers,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            config_path: None,
            listener_snapshot: None,
            listen_override: None,
        }
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Path the SIGHUP reloader re-reads. The listener state is snapshotted now
    /// so a later reload cannot report success for changes the already-bound
    /// server cannot apply.
    pub fn with_config_path(mut self, path: std::path::PathBuf) -> Result<Self> {
        let config = crate::load_broker_config_file(&path)?;
        self.listener_snapshot = Some(ListenerRuntimeSnapshot::capture(config.listener.as_ref())?);
        self.config_path = Some(path);
        Ok(self)
    }

    /// Record the effective listener (after command-line overrides) as the
    /// reload-guard baseline, plus the `--listen` bind override itself so
    /// `reload` can re-apply it to the file-derived config and compare like
    /// against like.
    pub fn with_runtime_listener(
        mut self,
        listener: Option<&BrokerListenerConfig>,
        listen_override: Option<String>,
    ) -> Result<Self> {
        self.listener_snapshot = Some(ListenerRuntimeSnapshot::capture(listener)?);
        self.listen_override = listen_override;
        Ok(self)
    }

    /// Snapshot of the current live broker.
    pub fn current_broker(&self) -> Arc<crate::Broker> {
        self.broker_handle.load_full()
    }

    pub fn broker_handle(&self) -> BrokerHandle {
        Arc::clone(&self.broker_handle)
    }

    /// Re-parse, build, swap. On any failure the existing broker stays
    /// live; caller decides whether to log or escalate. The rebuild
    /// reconstructs the per-listener auth layer from fresh config (policy +
    /// JWKS), so a SIGHUP applies an updated policy on the next request without
    /// any epoch counter (revocation is "next request evaluates the live
    /// policy").
    ///
    /// Validation and the rebuild consume one effective config — the file, the
    /// `OVSTORAGE_BROKER__` environment overlay, and the `--listen` override —
    /// so the broker that goes live is the one that passed validation, and an
    /// environment-supplied setting survives the reload.
    pub async fn reload(&self) -> Result<()> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ovstorage::Error::new(
                ovstorage::ErrorCode::NotConfigured,
                "broker reload requested but no config path was configured",
            )
        })?;
        let mut config = crate::load_broker_config_file(path)?;
        // Re-apply the `--listen` override the broker was started with, exactly as
        // startup does (overriding an existing listener's bind, or synthesizing one
        // when the file declares none), before validating and snapshotting. The file
        // never carries the override, so without this the effective startup snapshot
        // could never match a bare file-derived snapshot and every SIGHUP would be
        // rejected while an override is active, even reloads that only change policy.
        // Validation runs on the effective config, matching startup.
        if let Some(bind) = &self.listen_override {
            crate::apply_listen_override(&mut config, bind.clone());
        }
        crate::validate_broker_config_for_startup(&config)?;
        let reloaded_listener = ListenerRuntimeSnapshot::capture(config.listener.as_ref())?;
        let running_listener = self.listener_snapshot.as_ref().ok_or_else(|| {
            ovstorage::Error::new(
                ovstorage::ErrorCode::NotConfigured,
                "broker reload has no snapshot of the running listener",
            )
        })?;
        if &reloaded_listener != running_listener {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                "listener bind, TLS material, and forwarded-header capture settings cannot be \
                 changed by SIGHUP; restart the broker to apply listener changes",
            ));
        }
        // Build from the SAME effective config that was just validated — file
        // plus the `OVSTORAGE_BROKER__` environment overlay plus any `--listen`
        // override. Re-parsing the file alone would drop the overlay, so a
        // setting supplied by environment (an auth policy, or the
        // `trusted_unsigned_jwt` issuer/audience claim checks) would be enforced
        // at startup and absent from the broker a SIGHUP swaps in: a silent
        // security downgrade that validation cannot see, because validation runs
        // on the effective config.
        let new_broker = crate::build_broker_from_config(&config).await?;
        self.broker_handle.store(Arc::new(new_broker));
        tracing::info!(
            target: "ovstorage.broker.lifecycle",
            event = "reload",
            "broker config reloaded"
        );
        Ok(())
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
                        Ok(()) => {
                            tracing::info!(
                                target: "ovstorage.broker.lifecycle",
                                event = "reload_ok",
                                "SIGHUP reload completed"
                            );
                            metrics::counter!(crate::observability::LIFECYCLE_EVENTS, "event" => "reload_ok").increment(1);
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
    async fn reload_rebuilds_and_swaps_broker() {
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
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#,
        )
        .unwrap();
        let broker = build_default_broker().await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle.clone(), Vec::new())
            .with_config_path(cfg.clone())
            .unwrap();
        let before = controller.current_broker();
        controller.reload().await.unwrap();
        let after = controller.current_broker();
        // Reload rebuilds and atomically swaps the live broker (no epoch counter;
        // the rebuilt auth layer evaluates the fresh policy).
        assert!(!Arc::ptr_eq(&before, &after));
        assert!(after.health().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_succeeds_when_started_with_listen_override() {
        // A broker started with `--listen` runs on an effective bind the config
        // file never carries. The reload guard must compare the effective
        // listener against the effective startup snapshot, so a SIGHUP that
        // leaves the file listener untouched is accepted rather than rejected as
        // an unsupported listener change.
        crate::test_utils::ensure_test_plugin_env();
        let dir = reload_e2e_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("broker.toml");
        std::fs::write(
            &cfg,
            r#"
[listener]
bind = "127.0.0.1:9000"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#,
        )
        .unwrap();
        let broker = build_default_broker().await.unwrap();
        let handle = broker_handle(broker);
        // Mirror main.rs startup: capture the file baseline, then record the
        // effective listener and the `--listen` override stamped over it.
        let file_config = crate::load_broker_config_file(&cfg).unwrap();
        let override_bind = "127.0.0.1:9001".to_string();
        let mut effective = file_config.listener.clone().unwrap();
        effective.bind = override_bind.clone();
        let controller = LifecycleController::new(handle, Vec::new())
            .with_config_path(cfg.clone())
            .unwrap()
            .with_runtime_listener(Some(&effective), Some(override_bind))
            .unwrap();
        // The guard compares the effective bind (override 9001) on both sides,
        // not the file bind (9000) against the override, so the reload succeeds.
        controller.reload().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // SIGHUP reload enforces the reloaded policy
    //
    // `reload_rebuilds_and_swaps_broker` above proves a *different* healthy broker
    // is installed. These go end-to-end: an actual request flips from allowed to
    // denied across a reload, and a malformed reload leaves the prior broker live
    // and still enforcing its policy.
    // -----------------------------------------------------------------------

    fn reload_e2e_temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ovstorage-broker-reload-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ))
    }

    /// The `root` path as a config-string literal (forward slashes, quotes
    /// escaped).
    fn root_literal(root: &std::path::Path) -> String {
        root.to_string_lossy()
            .replace('\\', "/")
            .replace('"', "\\\"")
    }

    /// The `file:` address of `probe.txt` under `root`, the object the reload
    /// tests stat before and after a policy swap.
    fn probe_address(root: &std::path::Path) -> ovstorage::Url {
        let mut path = root.to_string_lossy().replace('\\', "/");
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        ovstorage::address::parse(&format!("file:{path}/probe.txt")).unwrap()
    }

    /// Anonymous allow-all listener over a `file` backend rooted at `root`.
    fn allow_config(root: &std::path::Path) -> String {
        format!(
            r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
            root_literal(root)
        )
    }

    /// Gated `builtin-auth` listener with an empty rule set (deny-all) over a
    /// `file` backend rooted at `root`.
    fn deny_config(root: &std::path::Path) -> String {
        format!(
            r#"
[listener]
bind = "127.0.0.1:0"

[listener.auth]
kind = "builtin-auth"

[listener.auth.config.policy]
plugin = "ovstorage-authz-toml"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
            root_literal(root)
        )
    }

    #[tokio::test]
    async fn reload_flips_allow_policy_to_deny_through_lifecycle() {
        crate::test_utils::ensure_test_plugin_env();
        let dir = reload_e2e_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("probe.txt"), b"hello").unwrap();
        let cfg = dir.join("broker.toml");
        std::fs::write(&cfg, allow_config(&dir)).unwrap();

        let broker = crate::build_broker_from_config_file(&cfg).await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle, Vec::new())
            .with_config_path(cfg.clone())
            .unwrap();
        let address = probe_address(&dir);

        // Under the anonymous allow-all policy the stat succeeds through the
        // lifecycle-managed broker.
        controller
            .current_broker()
            .stat(
                &crate::default_context(),
                address.clone(),
                ovstorage::StatOptions::default(),
            )
            .await
            .unwrap();

        // Rewrite the on-disk config with a deny-all gated policy and reload.
        std::fs::write(&cfg, deny_config(&dir)).unwrap();
        controller.reload().await.unwrap();

        // The SAME request is now denied by the reloaded policy.
        let err = controller
            .current_broker()
            .stat(
                &crate::default_context(),
                address,
                ovstorage::StatOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ovstorage::ErrorCode::PermissionDenied);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_rejects_changed_client_ca_material() {
        crate::test_utils::ensure_test_plugin_env();
        let dir = reload_e2e_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("server.crt");
        let key = dir.join("server.key");
        let client_ca = dir.join("client-ca.crt");
        std::fs::write(&cert, b"server certificate v1").unwrap();
        std::fs::write(&key, b"server key v1").unwrap();
        std::fs::write(&client_ca, b"client CA v1").unwrap();
        let cfg = dir.join("broker.toml");
        let contents = format!(
            "{}\n[listener.tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\nclient_ca_path = \"{}\"\n",
            allow_config(&dir),
            root_literal(&cert),
            root_literal(&key),
            root_literal(&client_ca),
        );
        std::fs::write(&cfg, contents).unwrap();

        let broker = crate::build_broker_from_config_file(&cfg).await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle, Vec::new())
            .with_config_path(cfg.clone())
            .unwrap();
        let before = controller.current_broker();

        std::fs::write(&client_ca, b"client CA v2").unwrap();
        let error = controller.reload().await.unwrap_err();
        assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(error.message().contains("restart the broker"));
        assert!(Arc::ptr_eq(&before, &controller.current_broker()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_with_malformed_config_keeps_prior_broker_enforcing() {
        crate::test_utils::ensure_test_plugin_env();
        let dir = reload_e2e_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("probe.txt"), b"hello").unwrap();
        let cfg = dir.join("broker.toml");
        // Start with a deny-all policy so "still enforcing" is a concrete deny.
        std::fs::write(&cfg, deny_config(&dir)).unwrap();

        let broker = crate::build_broker_from_config_file(&cfg).await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle, Vec::new())
            .with_config_path(cfg.clone())
            .unwrap();
        let address = probe_address(&dir);

        // The deny-all policy denies the anonymous stat.
        let before_err = controller
            .current_broker()
            .stat(
                &crate::default_context(),
                address.clone(),
                ovstorage::StatOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(before_err.code(), ovstorage::ErrorCode::PermissionDenied);
        let before = controller.current_broker();

        // A malformed config fails to parse; reload returns Err and must NOT swap.
        std::fs::write(&cfg, "this is = = not valid toml [[[").unwrap();
        controller.reload().await.unwrap_err();

        // The prior broker stays live (same pointer) and still enforces its policy.
        assert!(Arc::ptr_eq(&before, &controller.current_broker()));
        let after_err = controller
            .current_broker()
            .stat(
                &crate::default_context(),
                address,
                ovstorage::StatOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(after_err.code(), ovstorage::ErrorCode::PermissionDenied);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `trusted_unsigned_jwt` listener over a `file` backend, allowing the
    /// `alice` principal. `jwt_audience` is deliberately absent from the FILE:
    /// the test supplies it through the environment overlay.
    fn unsigned_jwt_config(root: &std::path::Path) -> String {
        format!(
            r#"
[listener]
bind = "127.0.0.1:0"
trusted_proxy = true
trusted_peers = ["127.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"

[listener.auth.config]
authn_mode = "trusted_unsigned_jwt"

[[listener.auth.config.policy.policy]]
id = "alice-all"
effect = "allow"
principal = "alice"
operations = ["*"]
prefix = "*"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
            root_literal(root)
        )
    }

    /// A proxy-verified (unsigned) JWT for `alice` carrying `audience`.
    fn unsigned_jwt_for(audience: &str) -> Vec<u8> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"sub": "alice", "aud": audience})).unwrap(),
        );
        format!("{header}.{payload}.proxy-signature").into_bytes()
    }

    fn proxy_context(token: Vec<u8>) -> crate::RequestContext {
        crate::RequestContext {
            credential: Some(ovstorage_authz_context::AuthCredential::new(
                Some(token),
                ovstorage_authz_context::Transport::Tcp {
                    peer_addr: "127.0.0.1:4443".to_string(),
                    tls_client_cert: None,
                },
            )),
            audit_id: None,
        }
    }

    #[tokio::test]
    async fn reload_preserves_environment_supplied_audience_check() {
        const CHILD_ENV: &str = "OVSTORAGE_BROKER_AUDIENCE_RELOAD_TEST_CHILD";
        const AUDIENCE_ENV: &str = "OVSTORAGE_BROKER__LISTENER__AUTH__CONFIG__JWT_AUDIENCE";

        if std::env::var_os(CHILD_ENV).is_none() {
            // Environment overlays are process-global. Re-execute only this
            // test with the overlay present from process start so parallel
            // sibling tests cannot observe a partially overlaid auth table.
            let status = std::process::Command::new(
                std::env::current_exe().expect("current broker test binary"),
            )
            .args([
                "lifecycle::tests::reload_preserves_environment_supplied_audience_check",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .env(AUDIENCE_ENV, "ovstorage")
            .status()
            .expect("run isolated environment-overlay reload test");
            assert!(
                status.success(),
                "isolated environment-overlay reload test failed: {status}"
            );
            return;
        }

        // The claim checks that defend against confused-deputy replay may be
        // supplied by the environment rather than the file. A reload that
        // rebuilt from the file alone would drop them and silently install a
        // broker that accepts a foreign-audience token — a security downgrade
        // that config validation cannot see, because validation reads the
        // effective config. Reload builds from that same effective config.
        crate::test_utils::ensure_test_plugin_env();
        let dir = reload_e2e_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("probe.txt"), b"hello").unwrap();
        let cfg = dir.join("broker.toml");
        std::fs::write(&cfg, unsigned_jwt_config(&dir)).unwrap();

        // The overlay is what puts the audience into the effective config.
        let effective = crate::load_broker_config_file(&cfg).unwrap();
        let auth_config = crate::broker_listener_auth_preflight(effective.listener.as_ref())
            .unwrap()
            .into_builtin_config()
            .unwrap();
        assert!(
            !ovstorage_authz_layer::trusted_unsigned_jwt_unenforced_claims(&auth_config)
                .unwrap()
                .contains(&ovstorage_authz_layer::JWT_AUDIENCE_CONFIG_KEY),
            "the environment overlay must supply jwt_audience"
        );

        let broker = crate::build_broker_from_config_file(&cfg).await.unwrap();
        let handle = broker_handle(broker);
        let controller = LifecycleController::new(handle, Vec::new())
            .with_config_path(cfg.clone())
            .unwrap();
        let address = probe_address(&dir);

        let foreign = || proxy_context(unsigned_jwt_for("some-other-service"));
        let matching = || proxy_context(unsigned_jwt_for("ovstorage"));

        // Before the reload the audience is enforced: the foreign-audience token
        // is rejected, the matching one is admitted.
        assert_eq!(
            controller
                .current_broker()
                .stat(&foreign(), address.clone(), Default::default())
                .await
                .unwrap_err()
                .code(),
            ovstorage::ErrorCode::AuthRequired
        );
        controller
            .current_broker()
            .stat(&matching(), address.clone(), Default::default())
            .await
            .unwrap();

        controller.reload().await.unwrap();

        // And after: the reloaded broker still enforces the overlaid audience.
        assert_eq!(
            controller
                .current_broker()
                .stat(&foreign(), address.clone(), Default::default())
                .await
                .unwrap_err()
                .code(),
            ovstorage::ErrorCode::AuthRequired,
            "SIGHUP must not drop the environment-supplied audience check"
        );
        controller
            .current_broker()
            .stat(&matching(), address, Default::default())
            .await
            .unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
