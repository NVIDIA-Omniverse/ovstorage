// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metric names and low-cardinality label mapping for the `hub_cache`
//! layer's observability: request classification (hit, miss, bypass),
//! lookup latency, and fill outcomes (committed, aborted, skipped).
//!
//! Mirrors the shape `ovstorage-retry` uses: this crate declares private
//! `const` metric names and emits through the `metrics` crate directly; the
//! `ovstorage` crate re-declares the same names as `pub const` and
//! registers their descriptions in `ovstorage::metrics::describe_metrics`.
//! The label-building logic lives here rather than inline at every call
//! site because `read.rs` and `materialize.rs` each have many terminal
//! points that need to agree on the same low-cardinality vocabulary.
//!
//! No label ever carries a URL, key, etag, endpoint, or partition — every
//! label value comes from a fixed, small set defined by the enums below.

use std::time::Instant;

const HUB_CACHE_REQUESTS_TOTAL: &str = "ovstorage_hub_cache_requests_total";
const HUB_CACHE_LOOKUP_DURATION_SECONDS: &str = "ovstorage_hub_cache_lookup_duration_seconds";
const HUB_CACHE_FILLS_TOTAL: &str = "ovstorage_hub_cache_fills_total";

/// Which [`ovstorage_plugin::Layer`] slot a lookup or fill belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Read,
    Materialize,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Read => "read",
            Op::Materialize => "materialize",
        }
    }
}

/// The hit/miss/bypass classification a lookup reaches, and why.
///
/// Recorded exactly once per request that reaches an answer from this
/// layer's cache logic. A stat error that propagates as `Cancelled` or
/// `NotFound` never reaches a classification — the caller's request did not
/// get an answer from the cache logic, it got the propagated error instead
/// — so that route intentionally records nothing here. The same is true of
/// a hit whose body exceeds the caller's `max_bytes` budget: that is a
/// caller-side policy rejection layered on top of a verdict this metric
/// already reported when the entry was filled, not a fresh cache verdict of
/// its own.
pub(crate) enum Outcome {
    Hit,
    Miss(MissReason),
    Bypass(BypassReason),
}

#[derive(Clone, Copy)]
pub(crate) enum MissReason {
    NotCached,
    PendingWrite,
    /// The extension trap (the hub named a path it never wrote), a length
    /// that contradicts the object's declared size, or bytes that do not
    /// carry the digest the entry's key names.
    EntryUnusable,
}

#[derive(Clone, Copy)]
pub(crate) enum BypassReason {
    Conditional,
    Credential,
    NoValidator,
    StatError,
    HubUnavailable,
    NoKey,
}

impl Outcome {
    fn labels(&self) -> (&'static str, &'static str) {
        match self {
            Outcome::Hit => ("hit", "cached"),
            Outcome::Miss(reason) => (
                "miss",
                match reason {
                    MissReason::NotCached => "not_cached",
                    MissReason::PendingWrite => "pending_write",
                    MissReason::EntryUnusable => "entry_unusable",
                },
            ),
            Outcome::Bypass(reason) => (
                "bypass",
                match reason {
                    BypassReason::Conditional => "conditional",
                    BypassReason::Credential => "credential",
                    BypassReason::NoValidator => "no_validator",
                    BypassReason::StatError => "stat_error",
                    BypassReason::HubUnavailable => "hub_unavailable",
                    BypassReason::NoKey => "no_key",
                },
            ),
        }
    }
}

/// Records a lookup's hit/miss/bypass classification and the latency from
/// `start` — the moment `read`/`materialize` was entered — to now, which is
/// always the moment the classification was reached, before any fill is
/// attempted.
pub(crate) fn observe(op: Op, outcome: Outcome, start: Instant) {
    metrics::histogram!(HUB_CACHE_LOOKUP_DURATION_SECONDS, "op" => op.as_str())
        .record(start.elapsed().as_secs_f64());
    let (outcome_label, reason_label) = outcome.labels();
    // The same classification as a structured log line, so hit/miss/bypass
    // is visible from logs alone on a host with no metrics recorder. The
    // fields carry no URL or key.
    tracing::debug!(
        op = op.as_str(),
        outcome = outcome_label,
        reason = reason_label,
        elapsed_us = start.elapsed().as_micros() as u64,
        "hub cache lookup"
    );
    metrics::counter!(
        HUB_CACHE_REQUESTS_TOTAL,
        "op" => op.as_str(),
        "outcome" => outcome_label,
        "reason" => reason_label
    )
    .increment(1);
}

/// A fill's terminal state: committed, aborted after being reserved, or
/// skipped before a reservation was even attempted.
pub(crate) enum FillOutcome {
    Committed,
    Aborted(AbortReason),
    Skipped(SkipReason),
}

#[derive(Clone, Copy)]
pub(crate) enum AbortReason {
    StreamError,
    SizeMismatch,
    ValidatorDrift,
    /// The key names a content digest the staged bytes do not carry.
    DigestMismatch,
    StagingError,
    CommitRefused,
    Cancelled,
    /// The caller dropped the read path's tee mid-body. Observed only
    /// through [`Armed`]'s `Drop` impl: nothing in this crate runs when an
    /// external caller simply stops polling a stream, so there is no other
    /// point to record from.
    CallerDropped,
    /// The inner read answered with a delegate or a redirect: its bytes
    /// never transit this layer, so there was nothing to stage.
    BodyShape,
    InnerError,
}

#[derive(Clone, Copy)]
pub(crate) enum SkipReason {
    Disabled,
    NoSlot,
    /// The stat declared no size, or declared zero — the hub reserves by
    /// size and refuses a zero-byte reservation.
    NoSize,
    OverCap,
    AlreadyExists,
    /// Another client is filling the key right now.
    PendingWrite,
    TooLarge,
    HubUnavailable,
}

impl FillOutcome {
    fn labels(&self) -> (&'static str, &'static str) {
        match self {
            FillOutcome::Committed => ("committed", "filled"),
            FillOutcome::Aborted(reason) => (
                "aborted",
                match reason {
                    AbortReason::StreamError => "stream_error",
                    AbortReason::SizeMismatch => "size_mismatch",
                    AbortReason::ValidatorDrift => "validator_drift",
                    AbortReason::DigestMismatch => "digest_mismatch",
                    AbortReason::StagingError => "staging_error",
                    AbortReason::CommitRefused => "commit_refused",
                    AbortReason::Cancelled => "cancelled",
                    AbortReason::CallerDropped => "caller_dropped",
                    AbortReason::BodyShape => "body_shape",
                    AbortReason::InnerError => "inner_error",
                },
            ),
            FillOutcome::Skipped(reason) => (
                "skipped",
                match reason {
                    SkipReason::Disabled => "disabled",
                    SkipReason::NoSlot => "no_slot",
                    SkipReason::NoSize => "no_size",
                    SkipReason::OverCap => "over_cap",
                    SkipReason::AlreadyExists => "already_exists",
                    SkipReason::PendingWrite => "pending_write",
                    SkipReason::TooLarge => "too_large",
                    SkipReason::HubUnavailable => "hub_unavailable",
                },
            ),
        }
    }
}

/// Records a fill's terminal outcome.
pub(crate) fn record_fill(op: Op, outcome: FillOutcome) {
    let (outcome_label, reason_label) = outcome.labels();
    // The same outcome as a structured log line, so fill behavior is
    // visible from logs alone on a host with no metrics recorder. The
    // fields carry no URL or key.
    tracing::debug!(
        op = op.as_str(),
        outcome = outcome_label,
        reason = reason_label,
        "hub cache fill"
    );
    metrics::counter!(
        HUB_CACHE_FILLS_TOTAL,
        "op" => op.as_str(),
        "outcome" => outcome_label,
        "reason" => reason_label
    )
    .increment(1);
}

/// Emits `fills_total{outcome="aborted", reason="caller_dropped"}` if a
/// [`crate::read::FillTicket`] is dropped without any terminal fill outcome
/// having been recorded.
///
/// Every explicit terminal path (`commit`, `abort_with`,
/// `record_abandoned`) disarms this guard first, so double counting cannot
/// happen. The one route that reaches this `Drop` impl live is the read
/// path's tee: a caller can drop the `ReadStream` it returned mid-body,
/// which drops the ticket from inside `futures::stream::unfold`'s saved
/// state with no async context left to record from directly. This impl
/// only ever increments a counter — no I/O, no `.await` — so it is safe to
/// run from an arbitrary drop glue.
pub(crate) struct Armed {
    op: Op,
    live: bool,
}

impl Armed {
    pub(crate) fn new(op: Op) -> Self {
        Self { op, live: true }
    }

    pub(crate) fn disarm(&mut self) {
        self.live = false;
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        if self.live {
            record_fill(self.op, FillOutcome::Aborted(AbortReason::CallerDropped));
        }
    }
}
