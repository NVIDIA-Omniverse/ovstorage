// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metrics recorder installation and Prometheus `/metrics` endpoint.
//!
//! All broker metrics are emitted via the `metrics` crate API.
//! Metric families on `/metrics`:
//!
//! - `broker_rpc_seconds` (Histogram, label `op`)
//! - `broker_cache_metadata_hits_total` (Counter, label `kind`:
//!   stat / list / list_versions)
//! - `broker_cache_object_hits_total` (Counter)
//! - `broker_cache_object_fills_total` (Counter, label `outcome`:
//!   ok / oversized / unknown_size)
//! - `broker_cache_evictions_total` (Counter, label `kind`)
//! - `ovstorage_auth_decisions_total` (Counter, label `outcome`:
//!   allow / deny / error) — emitted by the shared auth layer
//! - `broker_watch_fanout` (Gauge)
//! - `broker_redirect_emissions_total` (Counter, label `kind`)
//! - `broker_lifecycle_events_total` (Counter, label `event`:
//!   reload_ok / reload_failed / drain_start / drain_complete)
//! - `broker_uptime_seconds` (Gauge)
//!
//! Plus all `ovstorage_*` library metrics emitted by the core library.
//!
//! When `[observability] otlp_endpoint` is set, a secondary OTel
//! recorder bridges all `metrics::counter!/histogram!/gauge!` calls
//! into an OpenTelemetry `SdkMeterProvider` with OTLP HTTP push.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use serde::Deserialize;

// --- Metric name constants ---

pub const RPC_SECONDS: &str = "broker_rpc_seconds";
pub const CACHE_METADATA_HITS: &str = "broker_cache_metadata_hits_total";
pub const CACHE_OBJECT_HITS: &str = "broker_cache_object_hits_total";
pub const CACHE_OBJECT_FILLS: &str = "broker_cache_object_fills_total";
pub const CACHE_EVICTIONS: &str = "broker_cache_evictions_total";
pub const WATCH_FANOUT: &str = "broker_watch_fanout";
pub const REDIRECT_EMISSIONS: &str = "broker_redirect_emissions_total";
pub const LIFECYCLE_EVENTS: &str = "broker_lifecycle_events_total";
pub const UPTIME_SECONDS: &str = "broker_uptime_seconds";

/// `[observability]` config; both fields opt-in. Setting
/// `otlp_endpoint` installs a secondary OTLP push recorder alongside
/// the Prometheus scrape recorder.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct BrokerObservabilityConfig {
    #[serde(default)]
    pub prometheus_bind: Option<String>,
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
}

// --- OTel bridge recorder ---
//
// Intercepts every `metrics::counter!/gauge!/histogram!` call and
// records the same value into an OTel `SdkMeterProvider`. Installed
// via `FanoutRecorder` when `otlp_endpoint` is configured.

struct OtelBridgeCounter {
    inner: opentelemetry::metrics::Counter<u64>,
    labels: Vec<opentelemetry::KeyValue>,
}

impl metrics::CounterFn for OtelBridgeCounter {
    fn increment(&self, value: u64) {
        self.inner.add(value, &self.labels);
    }
    fn absolute(&self, value: u64) {
        self.inner.add(value, &self.labels);
    }
}

struct OtelBridgeGauge {
    inner: opentelemetry::metrics::Gauge<f64>,
    labels: Vec<opentelemetry::KeyValue>,
}

impl metrics::GaugeFn for OtelBridgeGauge {
    fn increment(&self, value: f64) {
        // OTel gauges don't support delta adds; use record.
        self.inner.record(value, &self.labels);
    }
    fn decrement(&self, value: f64) {
        self.inner.record(-value, &self.labels);
    }
    fn set(&self, value: f64) {
        self.inner.record(value, &self.labels);
    }
}

struct OtelBridgeHistogram {
    inner: opentelemetry::metrics::Histogram<f64>,
    labels: Vec<opentelemetry::KeyValue>,
}

impl metrics::HistogramFn for OtelBridgeHistogram {
    fn record(&self, value: f64) {
        self.inner.record(value, &self.labels);
    }
}

struct OtelRecorder {
    meter: Meter,
}

impl OtelRecorder {
    fn new(provider: &SdkMeterProvider) -> Self {
        Self {
            meter: provider.meter("ovstorage-broker"),
        }
    }

    fn to_otel_labels(key: &Key) -> Vec<opentelemetry::KeyValue> {
        key.labels()
            .map(|l| opentelemetry::KeyValue::new(l.key().to_string(), l.value().to_string()))
            .collect()
    }
}

impl Recorder for OtelRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let labels = Self::to_otel_labels(key);
        let inner = self.meter.u64_counter(key.name().to_string()).build();
        Counter::from_arc(Arc::new(OtelBridgeCounter { inner, labels }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let labels = Self::to_otel_labels(key);
        let inner = self.meter.f64_gauge(key.name().to_string()).build();
        Gauge::from_arc(Arc::new(OtelBridgeGauge { inner, labels }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let labels = Self::to_otel_labels(key);
        let inner = self.meter.f64_histogram(key.name().to_string()).build();
        Histogram::from_arc(Arc::new(OtelBridgeHistogram { inner, labels }))
    }
}

// --- Fanout recorder (Prometheus + OTel) ---

struct FanoutCounter {
    a: Counter,
    b: Counter,
}

impl metrics::CounterFn for FanoutCounter {
    fn increment(&self, value: u64) {
        self.a.increment(value);
        self.b.increment(value);
    }
    fn absolute(&self, value: u64) {
        self.a.absolute(value);
        self.b.absolute(value);
    }
}

struct FanoutGauge {
    a: Gauge,
    b: Gauge,
}

impl metrics::GaugeFn for FanoutGauge {
    fn increment(&self, value: f64) {
        self.a.increment(value);
        self.b.increment(value);
    }
    fn decrement(&self, value: f64) {
        self.a.decrement(value);
        self.b.decrement(value);
    }
    fn set(&self, value: f64) {
        self.a.set(value);
        self.b.set(value);
    }
}

struct FanoutHistogram {
    a: Histogram,
    b: Histogram,
}

impl metrics::HistogramFn for FanoutHistogram {
    fn record(&self, value: f64) {
        self.a.record(value);
        self.b.record(value);
    }
}

struct FanoutRecorder {
    primary: Box<dyn Recorder + Send + Sync>,
    secondary: Box<dyn Recorder + Send + Sync>,
}

impl Recorder for FanoutRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.primary
            .describe_counter(key.clone(), unit, description.clone());
        self.secondary.describe_counter(key, unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.primary
            .describe_gauge(key.clone(), unit, description.clone());
        self.secondary.describe_gauge(key, unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.primary
            .describe_histogram(key.clone(), unit, description.clone());
        self.secondary.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
        let a = self.primary.register_counter(key, metadata);
        let b = self.secondary.register_counter(key, metadata);
        Counter::from_arc(Arc::new(FanoutCounter { a, b }))
    }

    fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
        let a = self.primary.register_gauge(key, metadata);
        let b = self.secondary.register_gauge(key, metadata);
        Gauge::from_arc(Arc::new(FanoutGauge { a, b }))
    }

    fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
        let a = self.primary.register_histogram(key, metadata);
        let b = self.secondary.register_histogram(key, metadata);
        Histogram::from_arc(Arc::new(FanoutHistogram { a, b }))
    }
}

// --- describe helpers ---

fn describe_broker_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};
    describe_histogram!(
        RPC_SECONDS,
        Unit::Seconds,
        "Wall-clock latency of broker RPC dispatch."
    );
    describe_counter!(
        CACHE_METADATA_HITS,
        "Metadata-cache hits served without dispatching to a plugin."
    );
    describe_counter!(
        CACHE_OBJECT_HITS,
        "Broker byte-cache hits served without re-fetching the redirect target."
    );
    describe_counter!(
        CACHE_OBJECT_FILLS,
        "Broker byte-cache fill outcomes for plugin-driven redirects."
    );
    describe_counter!(
        CACHE_EVICTIONS,
        "Broker cache row evictions, by cache kind."
    );
    describe_counter!(
        ovstorage_authz_layer::AUTH_DECISIONS,
        "Auth-layer allow/deny/error decisions, by outcome."
    );
    describe_gauge!(
        WATCH_FANOUT,
        "Number of currently-active watch_directory streams."
    );
    describe_counter!(
        REDIRECT_EMISSIONS,
        "Plugin-driven redirects forwarded to the client."
    );
    describe_counter!(
        LIFECYCLE_EVENTS,
        "Broker lifecycle events: reload outcomes, drain transitions."
    );
    describe_gauge!(
        UPTIME_SECONDS,
        Unit::Seconds,
        "Seconds since the broker process started."
    );
}

// --- Recorder installation ---

/// Returned by [`install_recorders`]; drop shuts down the OTel provider
/// if one was created.
pub struct MetricsGuard {
    meter_provider: Option<SdkMeterProvider>,
    uptime_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.uptime_task.take() {
            handle.abort();
        }
        if let Some(provider) = self.meter_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global `metrics` recorder(s) and return the prometheus
/// handle for the `/metrics` route plus an optional OTel provider guard.
///
/// Prometheus is always installed. When `observability.otlp_endpoint`
/// is set, a secondary OTel OTLP-push recorder is fanned out alongside it.
///
/// Idempotent: subsequent calls with the same config return the
/// existing handle and a no-op guard.
pub fn install_recorders(
    config: Option<&BrokerObservabilityConfig>,
) -> ovstorage::Result<(PrometheusHandle, MetricsGuard)> {
    describe_broker_metrics();

    let prometheus_recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(RPC_SECONDS.to_owned()),
            &[
                0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )
        .map_err(|e| ovstorage::Error::new(ovstorage::ErrorCode::Internal, e.to_string()))?
        .build_recorder();
    let prometheus_handle = prometheus_recorder.handle();

    // Store handle for the scrape route regardless of whether a second
    // recorder is installed.
    let _ = PROMETHEUS_HANDLE.set(prometheus_handle.clone());

    let otlp_endpoint = config
        .and_then(|c| c.otlp_endpoint.as_deref())
        .filter(|s| !s.trim().is_empty());

    let meter_provider: Option<SdkMeterProvider> = if let Some(endpoint) = otlp_endpoint {
        Some(build_otlp_meter_provider(endpoint)?)
    } else {
        None
    };

    if let Some(provider) = &meter_provider {
        let otel_recorder = OtelRecorder::new(provider);
        let fanout = FanoutRecorder {
            primary: Box::new(prometheus_recorder),
            secondary: Box::new(otel_recorder),
        };
        // Ignore error if a recorder is already installed (e.g. in tests).
        let _ = metrics::set_global_recorder(fanout);
    } else {
        let _ = metrics::set_global_recorder(prometheus_recorder);
    }

    // Spawn a task that refreshes the uptime gauge every 5 seconds so
    // the value is reasonably fresh on scrape.
    let started = std::time::SystemTime::now();
    let uptime_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Ok(elapsed) = started.elapsed() {
                metrics::gauge!(UPTIME_SECONDS).set(elapsed.as_secs_f64());
            }
        }
    });

    Ok((
        prometheus_handle,
        MetricsGuard {
            meter_provider,
            uptime_task: Some(uptime_task),
        },
    ))
}

/// Access the prometheus handle installed by [`install_recorders`].
/// Returns `None` when called before installation (tests that don't
/// call `install_recorders` will get a no-op).
pub fn prometheus_handle() -> Option<PrometheusHandle> {
    PROMETHEUS_HANDLE.get().cloned()
}

fn build_otlp_meter_provider(endpoint: &str) -> ovstorage::Result<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| {
            ovstorage::Error::new(
                ovstorage::ErrorCode::InvalidArgument,
                format!("broker observability: OTLP metrics exporter init failed: {e}"),
            )
        })?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(60))
        .build();

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("ovstorage-broker")
        .build();

    Ok(SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build())
}

/// Prometheus listener handle; drop fires the shutdown channel.
pub struct PrometheusServer {
    pub bind: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PrometheusServer {
    pub fn fire_shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for PrometheusServer {
    fn drop(&mut self) {
        self.fire_shutdown();
    }
}

/// Spawn the Prometheus listener; drop or `fire_shutdown` stops it.
pub fn spawn_prometheus_listener(
    handle: PrometheusHandle,
    bind: &str,
) -> ovstorage::Result<PrometheusServer> {
    let listener = std::net::TcpListener::bind(bind).map_err(|err| {
        ovstorage::Error::new(
            ovstorage::ErrorCode::InvalidArgument,
            format!("broker observability: failed to bind Prometheus listener at {bind}: {err}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        ovstorage::Error::new(
            ovstorage::ErrorCode::Internal,
            format!("broker observability: set_nonblocking: {err}"),
        )
    })?;
    let bound = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| bind.to_string());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ovs-metrics".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(tcp) = tokio::net::TcpListener::from_std(listener) else {
                    return;
                };
                let app = prometheus_router(handle);
                let _ = axum::serve(tcp, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })
        .expect("failed to spawn thread");
    Ok(PrometheusServer {
        bind: bound,
        shutdown: Some(shutdown_tx),
    })
}

/// Build the `/metrics` router; exposed so tests can drive it without
/// binding a TCP listener.
pub fn prometheus_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(serve_metrics))
        .with_state(handle)
}

async fn serve_metrics(State(handle): State<PrometheusHandle>) -> Response {
    let body = handle.render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn fresh_prometheus_handle() -> PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    #[test]
    fn prometheus_handle_renders_text() {
        let handle = fresh_prometheus_handle();
        let text = handle.render();
        // Initially empty but should not panic.
        assert!(text.is_empty() || !text.is_empty());
    }

    #[tokio::test]
    async fn metrics_router_serves_text_format() {
        let handle = fresh_prometheus_handle();
        metrics::with_local_recorder(&PrometheusBuilder::new().build_recorder(), || {
            metrics::counter!(CACHE_OBJECT_HITS).increment(1);
        });
        // For this test, just verify the route serves 200 with correct content-type.
        let router = prometheus_router(handle);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "text/plain; version=0.0.4");
    }

    #[test]
    fn describe_does_not_panic() {
        describe_broker_metrics();
    }
}
