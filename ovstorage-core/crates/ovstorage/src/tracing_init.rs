// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            service_name: "ovstorage".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            otlp_traces: false,
        }
    }
}

impl TracingConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(service_name) = std::env::var("OTEL_SERVICE_NAME")
            && !service_name.is_empty()
        {
            config.service_name = service_name;
        }
        if let Ok(service_version) = std::env::var("OVSTORAGE_SERVICE_VERSION")
            && !service_version.is_empty()
        {
            config.service_version = service_version;
        }
        config.otlp_traces = otlp_traces_enabled_from_env();
        config
    }
}

impl TracingGuard {
    pub fn noop() -> Self {
        Self {
            tracer_provider: None,
        }
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
    }
}
pub fn init_tracing_from_env() -> Result<TracingGuard> {
    init_tracing(TracingConfig::from_env())
}

pub fn init_tracing(config: TracingConfig) -> Result<TracingGuard> {
    crate::metrics::describe_metrics();
    ovstorage_cache::MetricsObserver::describe();
    // Bridge `log::log!` calls into the tracing pipeline. Plugin events
    // arrive via the host log callback as `log` records (so the
    // plugin-supplied target, only knowable at runtime, survives as the
    // event's metadata target — `tracing::event!`'s `target:` would
    // require const). `LogTracer` re-emits each record as a tracing
    // event with the right target, so EnvFilter rules like
    // `RUST_LOG=ovstorage_plugin_http=trace` work as expected.
    let _ = tracing_log::LogTracer::init();
    // The host log callback hands every plugin event to `log::log!`
    // regardless of level; downstream filtering happens at EnvFilter.
    // Override log's max-level filter so it doesn't drop events before
    // they reach our subscriber.
    log::set_max_level(log::LevelFilter::Trace);
    let tracer_provider = if config.otlp_traces {
        Some(build_tracer_provider(&config)?)
    } else {
        None
    };
    let otel_layer = tracer_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("ovstorage")));
    let filter = tracing_subscriber::EnvFilter::try_from_env("OVSTORAGE_LOG")
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,ovstorage=info"));
    // Suppress per-keystroke / per-frame chatter from UI / transport
    // crates that's almost never what someone debugging ovstorage
    // wants. Appending these directives last makes them override any
    // catch-all in the user's RUST_LOG (e.g. `RUST_LOG=debug`). To
    // see them anyway, override explicitly: `RUST_LOG=...,rustyline=debug`.
    let filter = noisy_silenced(filter);
    let registry = tracing_subscriber::registry().with(filter).with(otel_layer);
    match resolve_log_format() {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stderr),
            )
            .try_init(),
        LogFormat::Compact => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_writer(std::io::stderr),
            )
            .try_init(),
        LogFormat::Pretty => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_writer(std::io::stderr),
            )
            .try_init(),
    }
    .map_err(|_| Error::new(ErrorCode::AlreadyExists, "tracing is already initialized"))?;
    Ok(TracingGuard { tracer_provider })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum LogFormat {
    Json,
    Compact,
    Pretty,
}

/// Append `<crate>=warn` directives to silence crates whose `debug`
/// output is interactive-UI noise that drowns out the actual diagnostic
/// signal a user wanted. Each directive overrides any earlier match for
/// that target; explicitly setting `<crate>=debug` later in `RUST_LOG`
/// still wins.
fn noisy_silenced(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    // Crates whose `debug`/`trace` output is per-keystroke / per-frame /
    // per-poll plumbing chatter. Flooding from any of these drowns the
    // signal a debugger is actually looking for. Override explicitly to
    // re-enable: `RUST_LOG=debug,h2=trace`.
    const NOISY: &[&str] = &[
        // Interactive shell key handling.
        "rustyline=warn",
        // WebSocket frame-level chatter (one record per keepalive ping
        // and per frame parsed).
        "tungstenite=warn",
        "tokio_tungstenite=warn",
        // HTTP/2 framing — one event per data frame is too granular
        // for the application-level debugging anyone runs from the CLI.
        "h2=warn",
        // Hyper connection / pool management noise.
        "hyper=warn",
        "hyper_util=warn",
        // reqwest's per-request span tree.
        "reqwest=warn",
        // TLS handshake / cipher negotiation. Useful for cert / SNI
        // bring-up; opt back in with `rustls=debug`.
        "rustls=warn",
        // mio's `poll()` loop trace lines.
        "mio=warn",
    ];
    NOISY.iter().fold(filter, |acc, directive| {
        match directive.parse() {
            Ok(d) => acc.add_directive(d),
            // Static strings; if a parse error ever surfaces, it's a
            // typo above, not a runtime concern. Drop it silently.
            Err(_) => acc,
        }
    })
}

/// `OVSTORAGE_LOG_FORMAT=json|compact|pretty` overrides; otherwise pick
/// based on whether stderr is a terminal — humans get colored compact
/// lines, log shippers get JSON. Compact (not Pretty) is the
/// interactive default because Pretty's multi-line block-per-event
/// layout drowns CLI output for anything noisier than `info`.
fn resolve_log_format() -> LogFormat {
    if let Ok(value) = std::env::var("OVSTORAGE_LOG_FORMAT") {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => return LogFormat::Json,
            "compact" | "text" => return LogFormat::Compact,
            "pretty" => return LogFormat::Pretty,
            _ => {} // unknown values fall through to detection
        }
    }
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        LogFormat::Compact
    } else {
        LogFormat::Json
    }
}

pub(crate) fn build_tracer_provider(
    config: &TracingConfig,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .build()
        .map_err(|error| Error::new(ErrorCode::Transient, error.to_string()))?;
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attribute(KeyValue::new(
            "service.version",
            config.service_version.clone(),
        ))
        .build();
    Ok(opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

/// `OVSTORAGE_PLUGIN_DIR` if set; else `<exe-dir>/plugins/`. `None`
/// if neither is available.
pub fn default_plugin_dir() -> Option<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_PLUGIN_DIR") {
        return Some(std::path::PathBuf::from(value));
    }
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;
    Some(parent.join("plugins"))
}

/// Used by `register_plugins_from_dir` to skip non-plugin dylibs
/// matching the name pattern (e.g. proc-macro dylibs in shared target
/// dirs).
pub(crate) fn missing_plugin_symbol(error: &Error) -> bool {
    error.code() == ErrorCode::InvalidArgument
        && error
            .message()
            .contains("plugin manifest symbol is missing")
}

/// Used by `load_plugins_from_dir` to skip plugins refused by host
/// policy (today: `test_only` manifests when `allow_test_plugins` is
/// off). Direct `load_plugin` callers still receive the rejection —
/// they asked for that specific plugin and silent success would
/// surprise them. Bulk discovery is lenient because the policy
/// rejection is a host-wide opt-out, not a "this file is broken"
/// signal.
pub(crate) fn policy_rejected_plugin(error: &Error) -> bool {
    error.code() == ErrorCode::PluginRejected
}

/// Matches `libovstorage_plugin_*.{so,dylib}` (Unix) or
/// `ovstorage_plugin_*.dll` (Windows).
pub(crate) fn is_plugin_artifact(path: &std::path::Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let unix_ok = matches!(ext, "so" | "dylib") && stem.starts_with("libovstorage_plugin_");
    let windows_ok = ext == "dll" && stem.starts_with("ovstorage_plugin_");
    unix_ok || windows_ok
}

pub(crate) fn otlp_traces_enabled_from_env() -> bool {
    if env_is_true("OTEL_SDK_DISABLED") || env_is_false("OVSTORAGE_OTLP") {
        return false;
    }
    if env_is_true("OVSTORAGE_OTLP") {
        return true;
    }
    std::env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
}

pub(crate) fn env_is_true(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub(crate) fn env_is_false(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(false)
}
