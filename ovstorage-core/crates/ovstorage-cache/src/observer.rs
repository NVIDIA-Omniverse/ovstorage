// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Observability hook trait. Hosts wire `Observer::on_*` calls to
//! their own Prometheus / OTLP / log sink via [`crate::CacheOptions`].

use std::time::Duration;

/// Observability hook called on every state-changing cache event.
pub trait Observer: Send + Sync {
    /// Cache lookup completed with the given outcome.
    fn on_lookup(&self, _outcome: LookupOutcome) {}
    /// Cache fill (the `put` path) completed.
    fn on_fill(&self, _outcome: FillOutcome, _bytes: u64, _elapsed: Duration) {}
    /// Eviction was triggered for a CAS row.
    fn on_eviction(&self, _reason: EvictionReason, _bytes: u64) {}
    /// `delta = +1` on mint, `-1` on release.
    fn on_lease(&self, _delta: i32) {}
    /// A herd-collapse waiter joined an in-flight fill.
    fn on_herd_collapse_join(&self) {}
    /// Crash-recovery sweep completed.
    fn on_crash_recovery(&self, _rows_examined: u64, _rows_reaped: u64) {}
}

/// Lookup-result categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LookupOutcome {
    Hit,
    Miss,
    /// CAS verification failed; row was quarantined.
    CorruptQuarantine,
    /// `verified_at` older than the freshness window; treated as miss.
    Expired,
}

/// Fill-result categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FillOutcome {
    Success,
    /// Partial CAS file was discarded.
    Failure,
    /// Caller cancelled before the bytes were committed.
    Aborted,
}

/// Eviction-reason categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvictionReason {
    /// LRU eviction over the byte budget.
    SizePressure,
    /// Caller invoked `remove_*`.
    Explicit,
    /// CAS verification failure quarantined the row.
    Corrupt,
}

/// No-op observer; default when no host observer is supplied.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopObserver;

impl Observer for NoopObserver {}

// --- Metric name constants used by MetricsObserver ---
const CACHE_LOOKUPS_TOTAL: &str = "ovstorage_cache_lookups_total";
const CACHE_FILLS_TOTAL: &str = "ovstorage_cache_fills_total";
const CACHE_FILL_BYTES_TOTAL: &str = "ovstorage_cache_fill_bytes_total";
const CACHE_EVICTIONS_TOTAL: &str = "ovstorage_cache_evictions_total";
const CACHE_EVICTED_BYTES_TOTAL: &str = "ovstorage_cache_evicted_bytes_total";

/// [`Observer`] implementation that emits metrics via the `metrics`
/// crate facade. Install on [`crate::CacheOptions::observer`] to
/// surface cache telemetry in whatever recorder is active.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetricsObserver;

impl MetricsObserver {
    /// Register human-readable descriptions for all cache metrics.
    /// Call once at startup, safe to call before or after recorder
    /// install.
    pub fn describe() {
        metrics::describe_counter!(CACHE_LOOKUPS_TOTAL, "Cache lookups by outcome.");
        metrics::describe_counter!(CACHE_FILLS_TOTAL, "Cache fill attempts by outcome.");
        metrics::describe_counter!(CACHE_FILL_BYTES_TOTAL, "Bytes written to the cache.");
        metrics::describe_counter!(CACHE_EVICTIONS_TOTAL, "Cache evictions by reason.");
        metrics::describe_counter!(CACHE_EVICTED_BYTES_TOTAL, "Bytes evicted from the cache.");
    }
}

impl Observer for MetricsObserver {
    fn on_lookup(&self, outcome: LookupOutcome) {
        let label = match outcome {
            LookupOutcome::Hit => "hit",
            LookupOutcome::Miss => "miss",
            LookupOutcome::CorruptQuarantine => "corrupt",
            LookupOutcome::Expired => "expired",
        };
        metrics::counter!(CACHE_LOOKUPS_TOTAL, "outcome" => label).increment(1);
    }

    fn on_fill(&self, outcome: FillOutcome, bytes: u64, _elapsed: Duration) {
        let label = match outcome {
            FillOutcome::Success => "ok",
            FillOutcome::Failure => "failed",
            FillOutcome::Aborted => "aborted",
        };
        metrics::counter!(CACHE_FILLS_TOTAL, "outcome" => label).increment(1);
        if outcome == FillOutcome::Success {
            metrics::counter!(CACHE_FILL_BYTES_TOTAL).increment(bytes);
        }
    }

    fn on_eviction(&self, reason: EvictionReason, bytes: u64) {
        let label = match reason {
            EvictionReason::SizePressure => "size_pressure",
            EvictionReason::Explicit => "explicit",
            EvictionReason::Corrupt => "corrupt",
        };
        metrics::counter!(CACHE_EVICTIONS_TOTAL, "reason" => label).increment(1);
        metrics::counter!(CACHE_EVICTED_BYTES_TOTAL).increment(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<&'static str>>,
    }

    impl Observer for RecordingObserver {
        fn on_lookup(&self, _outcome: LookupOutcome) {
            self.events.lock().unwrap().push("lookup");
        }
        fn on_fill(&self, _outcome: FillOutcome, _bytes: u64, _elapsed: Duration) {
            self.events.lock().unwrap().push("fill");
        }
        fn on_eviction(&self, _reason: EvictionReason, _bytes: u64) {
            self.events.lock().unwrap().push("eviction");
        }
    }

    #[test]
    fn observer_methods_dispatch_through_trait_object() {
        let observer: std::sync::Arc<dyn Observer> =
            std::sync::Arc::new(RecordingObserver::default());
        observer.on_lookup(LookupOutcome::Hit);
        observer.on_fill(FillOutcome::Success, 1024, Duration::from_millis(2));
        observer.on_eviction(EvictionReason::SizePressure, 1024);
    }

    #[test]
    fn noop_observer_dispatches_without_panicking() {
        let n = NoopObserver;
        n.on_lookup(LookupOutcome::Miss);
        n.on_fill(FillOutcome::Aborted, 0, Duration::from_secs(0));
        n.on_eviction(EvictionReason::Explicit, 0);
        n.on_lease(1);
        n.on_herd_collapse_join();
        n.on_crash_recovery(100, 5);
    }
}
