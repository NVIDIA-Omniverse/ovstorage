// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plugin-side bridge from `tracing` events to the host's logging
//! pipeline. Each `tracing::Event` emitted inside a plugin gets its
//! rendered fields shipped through `HostCallbacks::log` so the host's
//! single `tracing-subscriber` can format and route it like any other
//! event.
//!
//! The plugin and host each have their own `tracing` global subscriber
//! (cdylibs don't share statics with the host binary), so plugin events
//! would otherwise vanish into the plugin's uninitialized subscriber.
//! This Layer is what makes `RUST_LOG=...` work for plugin code.

use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::ffi;
use crate::shim;

/// Subscriber layer that ships every event through the host's `log`
/// callback. Install once at plugin init via [`install`].
pub struct HostLogLayer;

impl HostLogLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HostLogLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Subscriber> Layer<S> for HostLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(host) = shim::host() else {
            // Pre-init or null host: events have nowhere to go. Cheaper
            // to drop than to buffer (host ABI says callbacks are valid
            // for the cdylib's lifetime, so absence is permanent).
            return;
        };
        // tracing-subscriber's `try_init` auto-registers a `LogTracer`
        // when the `tracing-log` feature is on, so plugin-internal
        // `log::log!` calls (e.g. from `tokio_tungstenite`) reach this
        // layer as events with metadata target `"log"`. Normalize so
        // the host sees the real target — otherwise host-side EnvFilter
        // directives like `tokio_tungstenite=warn` never match.
        let normalized = event.normalized_metadata();
        let metadata = normalized.as_ref().unwrap_or_else(|| event.metadata());
        let level = ffi_level(*metadata.level());
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        host.log(level, metadata.target(), &visitor.rendered);
    }
}

fn ffi_level(level: Level) -> ffi::LogLevelV1 {
    match level {
        Level::TRACE => ffi::LogLevelV1::Trace,
        Level::DEBUG => ffi::LogLevelV1::Debug,
        Level::INFO => ffi::LogLevelV1::Info,
        Level::WARN => ffi::LogLevelV1::Warn,
        Level::ERROR => ffi::LogLevelV1::Error,
    }
}

/// Renders an event's `message` field plus `key=value` pairs for any
/// other fields. Mirrors what `tracing-subscriber`'s default formatter
/// does, just into a plain string. Field-values are written via
/// `Debug` because that's the trait every `tracing` value implements.
#[derive(Default)]
struct MessageVisitor {
    rendered: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        // `tracing-log` exposes the original log call's target/file/line
        // as `log.*` fields on the bridged event. The host's formatter
        // reads them off the normalized metadata; surfacing them again
        // in the rendered message duplicates info and pollutes output.
        if name.starts_with("log.") {
            return;
        }
        if name == "message" {
            // The bare message goes first, no `message=` prefix; matches
            // the way `tracing-subscriber` formats events for humans.
            if !self.rendered.is_empty() {
                self.rendered.push(' ');
            }
            let _ = write!(self.rendered, "{value:?}");
            // `Debug` for `&str` quotes the string; strip the surrounding
            // quotes so plain messages look natural in the host's log.
            let trimmed = self
                .rendered
                .trim_start_matches('"')
                .trim_end_matches('"')
                .to_string();
            self.rendered = trimmed;
        } else {
            if !self.rendered.is_empty() {
                self.rendered.push(' ');
            }
            let _ = write!(self.rendered, "{name}={value:?}");
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name.starts_with("log.") {
            return;
        }
        if !self.rendered.is_empty() {
            self.rendered.push(' ');
        }
        if name == "message" {
            self.rendered.push_str(value);
        } else {
            let _ = write!(self.rendered, "{name}={value:?}");
        }
    }
}

/// Install [`HostLogLayer`] as the plugin's process-wide tracing
/// subscriber. Idempotent — calling more than once is a no-op (the
/// second `try_init` returns `Err` and we swallow it). Safe to call
/// from the plugin's init thunk before any host event is emitted.
pub fn install() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let subscriber = tracing_subscriber::registry().with(HostLogLayer::new());
    let _ = subscriber.try_init();
}
