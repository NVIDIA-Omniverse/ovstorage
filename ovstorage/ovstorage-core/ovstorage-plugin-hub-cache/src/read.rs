// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `hub_cache` read path: the validator probe, hub hit serving, and the
//! streaming tee fill.
//!
//! Every branch here preserves two invariants. **Best effort**: a hub
//! failure of any kind degrades to the inner read; nothing the hub does can
//! fail a caller's request that the inner layer could serve. **Lease
//! discipline**: every hub handle this path obtains is released on every
//! route out — explicitly where the code can await, and through the engine
//! handles' drop behavior (read handles close, write handles remove) where
//! it cannot, so an abandoned fill can never commit and a dropped delegate
//! can never pin an entry.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt as _;
use md5::{Digest as _, Md5};
use ovstorage_hub_client::{HubKey, ReadHandle, ReadOpen, WriteHandle, WriteOpen, hub_key};
use ovstorage_plugin::*;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::OwnedSemaphorePermit;
use tracing::debug;

use crate::metrics::{
    self, AbortReason, Armed, BypassReason, FillOutcome, MissReason, Op, Outcome, SkipReason,
};
use crate::{HubCacheWrapper, READ_TO_BYTES_EXTENSION};

/// What the pre-read `stat` proved: the object's current metadata, carrying
/// the non-empty, declared-strong validator hub keys are derived from.
pub(crate) struct ValidatorProbe {
    pub(crate) info: ObjectInfo,
    pub(crate) etag: String,
}

/// Whether `info` re-proves the validator a fill is keyed under: the same
/// etag, still declared strong. A weak or unspecified declaration is no
/// proof even when the token matches — such a token may stay equal across a
/// byte-level change, which is exactly what a fill must not publish.
pub(crate) fn proves_validator(info: &ObjectInfo, etag: &str) -> bool {
    info.etag_strength == EtagStrength::Strong && info.etag.as_deref() == Some(etag)
}

/// The error a cancelled caller receives everywhere on this layer's paths.
pub(crate) fn cancelled_error() -> Error {
    Error::new(ErrorCode::Cancelled, "cancelled by host")
}

/// What [`HubCacheWrapper::probe_validator`] determined: a usable
/// validator, an object with no (or an empty) etag, or a stat that failed
/// for an availability or refusal reason. `Cancelled` and `NotFound` never
/// reach this type — they propagate as errors instead.
pub(crate) enum ProbeOutcome {
    /// Boxed so an unvalidated or errored probe — the common bypass case —
    /// does not carry `ValidatorProbe`'s `ObjectInfo` around for nothing.
    Validated(Box<ValidatorProbe>),
    NoValidator,
    StatError,
}

/// A reserved hub entry a fill may stream into, opened BEFORE the inner
/// read so concurrent fills of one key dedupe across processes: every
/// racer after the first is turned away — pending-write while the winner
/// is still filling, already-exists once it has committed — and skips its
/// own fill.
///
/// Dropping the ticket without committing enqueues `Remove` through the
/// write handle, so an abandoned fill — an inner read error, a caller
/// dropping the stream mid-body, a size mismatch — discards the
/// reservation instead of publishing it.
pub(crate) struct FillTicket {
    handle: WriteHandle,
    /// The object's declared size from the validator probe. A clean stream
    /// end commits only when the byte count matches: a short body is a
    /// truncated object, not a cacheable one, and hub reserved exactly this
    /// many bytes.
    pub(crate) expected: u64,
    /// The base budget every staging filesystem operation runs under; see
    /// [`HubCacheWrapper::io_deadline`].
    pub(crate) io_timeout: Duration,
    /// The shared stall latch every staging operation runs through.
    pub(crate) fs: Arc<FsHealth>,
    /// The raw content digest the key names, when the digest tier keyed
    /// this fill. A commit under a digest key must prove the staged bytes
    /// carry it: the key claims a content identity independent of the URL,
    /// so an etag match is no proof — a source that reuses an etag across
    /// two bodies would otherwise publish the wrong bytes under the digest
    /// of the right ones, on a write-once key that never gets corrected.
    pub(crate) digest: Option<Vec<u8>>,
    op: Op,
    /// Emits the `caller_dropped` fill outcome if this ticket is ever
    /// dropped without a terminal outcome having been recorded; every
    /// terminal method below disarms it first.
    armed: Armed,
    /// Bounds concurrent streaming fills; released when the fill ends by
    /// any route.
    _permit: OwnedSemaphorePermit,
}

impl FillTicket {
    /// The staging file the body is written into before a commit publishes
    /// it.
    pub(crate) fn path(&self) -> &Path {
        self.handle.path()
    }

    /// Publishes the staged entry, reporting whether the hub accepted it
    /// and recording `committed` or, on a hub refusal, `aborted {
    /// commit_refused }`.
    ///
    /// A refused commit costs the cache entry and nothing else on the read
    /// path; `materialize` reads the answer, because there the hub file is
    /// only servable once the entry is committed.
    pub(crate) async fn commit(mut self) -> bool {
        self.armed.disarm();
        let op = self.op;
        match self.handle.commit().await {
            Ok(()) => {
                metrics::record_fill(op, FillOutcome::Committed);
                true
            }
            Err(error) => {
                debug!(%error, "hub fill commit failed");
                metrics::record_fill(op, FillOutcome::Aborted(AbortReason::CommitRefused));
                false
            }
        }
    }

    /// Discards the reservation, waiting for the hub's acknowledgement and
    /// recording `aborted` with `reason`.
    pub(crate) async fn abort_with(mut self, reason: AbortReason) {
        self.armed.disarm();
        let op = self.op;
        self.handle.abort().await;
        metrics::record_fill(op, FillOutcome::Aborted(reason));
    }

    /// Discards the reservation with `reason`, waiting for the hub's
    /// acknowledgement only while someone is still waiting on the outcome:
    /// a caller whose token has fired takes the fire-and-forget route —
    /// the same reason recorded, the drop-enqueued `Remove` doing the
    /// cleanup — so no route out of a cancelled request ever waits on a
    /// hub release round trip.
    pub(crate) async fn abort_for(
        mut self,
        reason: AbortReason,
        cancel: Option<&CancellationToken>,
    ) {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            self.record_abandoned(reason);
        } else {
            self.abort_with(reason).await;
        }
    }

    /// Records `aborted` with `reason` without waiting for the hub's
    /// acknowledgement, for hot paths (the per-chunk tee) that must not
    /// block forwarding the caller's chunk on a network round trip. The
    /// ticket's own drop still enqueues the write handle's `Remove`, exactly
    /// as an unrecorded drop would.
    pub(crate) fn record_abandoned(&mut self, reason: AbortReason) {
        self.armed.disarm();
        metrics::record_fill(self.op, FillOutcome::Aborted(reason));
    }
}

impl HubCacheWrapper {
    /// Serves `read` through the hub: bypass, validator probe, hub lookup,
    /// and on a miss the tee fill.
    pub(crate) async fn read_impl(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let start = Instant::now();
        // A broker-resolved OAuth credential can make the representation
        // vary by principal even when the origin reuses one validator for
        // every caller. Hub entries are principal-agnostic (hub has no
        // auth), so such reads neither consult nor populate the cache —
        // delegate before even issuing the validator stat, exactly as
        // byte_cache does.
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            metrics::observe(Op::Read, Outcome::Bypass(BypassReason::Credential), start);
            return self.inner.read(request, cancel).await;
        }
        // Conditional and partial reads are never cached: the cached full
        // object would hide the precondition or range.
        if request.input.options.if_match.is_some() || request.input.options.range.is_some() {
            metrics::observe(Op::Read, Outcome::Bypass(BypassReason::Conditional), start);
            return self.inner.read(request, cancel).await;
        }
        // A hub known to be in its failure cooldown cannot answer, so the
        // validator stat below would tax the backend purely for the hub's
        // sake — the opposite of what pass-through degradation promises.
        // The check is one mutex acquisition and no I/O; a never-dialled
        // client reports available, so the first read still probes.
        if self.client.unavailable() {
            metrics::observe(
                Op::Read,
                Outcome::Bypass(BypassReason::HubUnavailable),
                start,
            );
            return self.inner.read(request, cancel).await;
        }
        let to_bytes = request.extensions.get(READ_TO_BYTES_EXTENSION).is_some();
        let max_bytes = request.input.options.max_bytes;
        let address = request.input.address.clone();

        // Validator-keyed lookup: the current etag proves a hub entry
        // fresh; without one the hub is bypassed entirely — unversioned
        // content is never cached, and a stale entry is unreachable by
        // construction because its key names an etag no stat reports.
        let probe = match self
            .probe_validator(&request.extensions, &address, cancel.clone())
            .await?
        {
            ProbeOutcome::Validated(probe) => probe,
            ProbeOutcome::NoValidator => {
                metrics::observe(Op::Read, Outcome::Bypass(BypassReason::NoValidator), start);
                return self.inner.read(request, cancel).await;
            }
            ProbeOutcome::StatError => {
                metrics::observe(Op::Read, Outcome::Bypass(BypassReason::StatError), start);
                return self.inner.read(request, cancel).await;
            }
        };
        let Some(key) = hub_key(
            self.key_scheme,
            &self.partition,
            &address,
            &probe.etag,
            probe.info.checksums.get(&ChecksumAlgorithm::md5()),
        ) else {
            metrics::observe(Op::Read, Outcome::Bypass(BypassReason::NoKey), start);
            return self.inner.read(request, cancel).await;
        };

        match race_hub(
            cancel.as_ref(),
            self.client
                .open_for_read(&key.key, &key.provider, &key.extension),
        )
        .await?
        {
            Ok(ReadOpen::Opened(handle)) => {
                let served = self
                    .serve_hit(
                        handle,
                        &probe,
                        key.digest.as_deref(),
                        to_bytes,
                        max_bytes,
                        cancel.as_ref(),
                    )
                    .await?;
                // The serve paid filesystem waits the token may have fired
                // during — including one that made the entry look unusable,
                // which must not degrade into the inner layer's answer. A
                // cancelled caller gets the truth on either branch, and
                // dropping an unreturned result releases any lease it
                // carries.
                if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
                    return Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
                }
                match served {
                    Some(result) => {
                        metrics::observe(Op::Read, Outcome::Hit, start);
                        return Ok(result);
                    }
                    // The entry answered but cannot be served: its file does
                    // not exist (the extension trap), or its length or
                    // content contradicts the identity the key claims.
                    // Serve uncached WITHOUT filling: the key is already
                    // taken, so a refill would only collect ALREADY_EXISTS.
                    None => {
                        metrics::observe(Op::Read, Outcome::Miss(MissReason::EntryUnusable), start);
                        return self.inner.read(request, cancel).await;
                    }
                }
            }
            // Another client is writing this key. There is nothing to read
            // yet and nothing to fill; no retry loop — the protocol's
            // timeout is a server-side no-op, so waiting cannot help.
            Ok(ReadOpen::PendingWrite) => {
                metrics::observe(Op::Read, Outcome::Miss(MissReason::PendingWrite), start);
                return self.inner.read(request, cancel).await;
            }
            Ok(ReadOpen::NotCached) => {
                metrics::observe(Op::Read, Outcome::Miss(MissReason::NotCached), start);
            }
            Err(error) => {
                debug!(
                    address = %redact_url(&address),
                    %error,
                    "hub open-for-read failed; serving uncached"
                );
                metrics::observe(
                    Op::Read,
                    Outcome::Bypass(BypassReason::HubUnavailable),
                    start,
                );
                return self.inner.read(request, cancel).await;
            }
        }

        // Miss: reserve the entry BEFORE the inner read (cross-process fill
        // dedupe), then serve the body while the tee spools it hub-ward.
        // A key that turns out already committed (another client won the
        // fill race) needs nothing extra here: the body is already flowing
        // from inner, and the next read hits.
        let ticket = match self
            .begin_fill(Op::Read, &address, &probe, &key, cancel.as_ref())
            .await
        {
            FillStart::Begun(ticket) => Some(ticket),
            FillStart::AlreadyCommitted | FillStart::Skipped => None,
        };
        let result = match self.inner.read(request, cancel.clone()).await {
            Ok(result) => result,
            Err(error) => {
                if let Some(mut ticket) = ticket {
                    ticket.record_abandoned(AbortReason::InnerError);
                }
                return Err(error);
            }
        };
        // One gate for every result shape, fillable or not: a token that
        // fired while the inner read produced this result is terminal, and
        // continuing past it — even just to pass a drifted body or a
        // delegate through — would answer a cancelled caller with success.
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            if let Some(mut ticket) = ticket {
                ticket.record_abandoned(AbortReason::Cancelled);
            }
            return Err(cancelled_error());
        }
        let Some(mut ticket) = ticket else {
            return Ok(result);
        };
        match result {
            // Fill only under the result's own validator: bytes whose read
            // reports a different (or no) etag belong to some other version
            // than the key names, and committing them would let a later
            // revert to this etag serve the wrong body.
            ReadResult::Bytes { bytes, info } => {
                if !proves_validator(&info, &probe.etag) {
                    ticket.record_abandoned(AbortReason::ValidatorDrift);
                    Ok(ReadResult::Bytes { bytes, info })
                } else if bytes.len() as u64 != ticket.expected {
                    ticket.record_abandoned(AbortReason::SizeMismatch);
                    Ok(ReadResult::Bytes { bytes, info })
                } else {
                    fill_from_bytes(ticket, &bytes, cancel.as_ref()).await;
                    // The fill observes the token, so a fired one may have
                    // been acted on just above — and an operation that saw
                    // the cancellation must not answer with success, however
                    // ready its bytes are.
                    if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
                        return Err(cancelled_error());
                    }
                    Ok(ReadResult::Bytes { bytes, info })
                }
            }
            ReadResult::Stream { stream, info } => {
                if proves_validator(&info, &probe.etag) {
                    Ok(ReadResult::Stream {
                        stream: tee_into_hub(stream, ticket, cancel.clone()),
                        info,
                    })
                } else {
                    ticket.record_abandoned(AbortReason::ValidatorDrift);
                    Ok(ReadResult::Stream { stream, info })
                }
            }
            // Delegates and redirects pass through unchanged: their bytes
            // never transit this layer, so there is nothing to tee.
            // Dropping the ticket discards the reservation.
            other => {
                ticket.record_abandoned(AbortReason::BodyShape);
                Ok(other)
            }
        }
    }

    /// The validator to key hub lookups on: the object's current `etag` via
    /// an inner `stat` carrying the caller's request extensions (so
    /// principal scoping and tracing flow). An answer without an etag —
    /// with an empty one, which cannot distinguish two versions, or with
    /// one not declared [`EtagStrength::Strong`], which may stay equal
    /// across a byte-level change — reports [`ProbeOutcome::NoValidator`]:
    /// weak and unspecified validators are no trusted content identity, and
    /// keying write-once entries on one is how a cache serves stale bytes.
    ///
    /// A stat error is discriminated by shape. `Cancelled` propagates (a
    /// cancelled stat must not produce a read) and `NotFound` propagates
    /// (an absent object must stop being served, and the inner read would
    /// only repeat the answer). Everything else — outages and refusals
    /// alike — reports [`ProbeOutcome::StatError`], which bypasses to the
    /// inner read exactly as [`ProbeOutcome::NoValidator`] does; the two are
    /// kept apart only so the bypass metric can name which one happened.
    pub(crate) async fn probe_validator(
        &self,
        extensions: &Extensions,
        address: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ProbeOutcome> {
        let request = Request {
            extensions: extensions.clone(),
            input: StatRequest {
                address: address.clone(),
                options: StatOptions::default(),
            },
        };
        match self.inner.stat(request, cancel).await {
            Ok(info) => Ok(
                match (info.etag_strength == EtagStrength::Strong)
                    .then(|| info.etag.clone())
                    .flatten()
                    .filter(|etag| !etag.is_empty())
                {
                    Some(etag) => ProbeOutcome::Validated(Box::new(ValidatorProbe { info, etag })),
                    None => ProbeOutcome::NoValidator,
                },
            ),
            Err(error) => match error.code() {
                ErrorCode::Cancelled | ErrorCode::NotFound => Err(error),
                _ => Ok(ProbeOutcome::StatError),
            },
        }
    }

    /// Serves a hub hit, or reports `None` for an entry that answered but
    /// cannot be served — a path that does not exist (the extension trap),
    /// a file whose length contradicts the object's declared size, or one
    /// whose bytes do not carry the digest its key names.
    ///
    /// A `None` releases the lease before returning; a served delegate
    /// carries the lease as its guard, so the entry is pinned against
    /// eviction for exactly as long as any clone of the delegate lives. A
    /// caller whose `max_bytes` budget a proven hit exceeds gets `Err`
    /// instead: the error is the caller's own policy rejecting an entry
    /// that is otherwise servable. That route deliberately records no
    /// fresh hit/miss classification — see the `Outcome` docs in
    /// `metrics.rs` for why a policy rejection is not a cache verdict.
    async fn serve_hit(
        &self,
        handle: ReadHandle,
        probe: &ValidatorProbe,
        digest: Option<&[u8]>,
        to_bytes: bool,
        max_bytes: Option<u64>,
        cancel: Option<&CancellationToken>,
    ) -> Result<Option<ReadResult>> {
        if !to_bytes {
            // A streaming caller must not have the object re-materialized
            // into one allocation, so it gets the leased path itself — the
            // same answer `materialize` produces.
            return Ok(self
                .serve_leased(handle, probe, digest, cancel)
                .await
                .map(ReadResult::LocalDelegate));
        }
        let Ok(meta) = self
            .fs
            .run(
                self.io_deadline(),
                cancel,
                tokio::fs::metadata(handle.path().to_path_buf()),
            )
            .await
        else {
            release_lease(handle, cancel).await;
            return Ok(None);
        };
        if probe.info.size.is_some_and(|size| size != meta.len()) {
            release_lease(handle, cancel).await;
            return Ok(None);
        }
        let mut info = probe.info.clone();
        info.size = Some(meta.len());
        // The answer is the hub's copy: `size` describes it (byte-identical
        // to the source by the fill's own checks), but the origin object's
        // modification time does not describe this file — the same absence
        // the byte cache reports for its CAS copies.
        info.mtime = None;
        // A buffering caller (`read_bytes`) gets whole-object `Bytes`,
        // under its own budget: the budget is a property of the request,
        // so a cached object over it errors exactly as an uncached one
        // buffered elsewhere would. But the policy may only reject an
        // entry that could actually be served: a digest key's entry is
        // unproven until its bytes are read, and proving an over-budget
        // one just to reject it defeats this early check's purpose — so
        // such an entry is treated as unusable instead, and the inner
        // layer serves a request nothing here was entitled to fail.
        if let Some(cap) = max_bytes
            && meta.len() > cap
        {
            release_lease(handle, cancel).await;
            if digest.is_some() {
                return Ok(None);
            }
            return Err(read_bytes_max_bytes_error(cap));
        }
        let path = handle.path().to_path_buf();
        let bytes = match self
            .fs
            .run(
                scaled_deadline(self.io_deadline(), meta.len()),
                cancel,
                tokio::fs::read(path.clone()),
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(_) => {
                release_lease(handle, cancel).await;
                return Ok(None);
            }
        };
        release_lease(handle, cancel).await;
        // Always hashed, never memoized: the digest is computed over the
        // exact bytes about to be returned, so proof and use are one object
        // and no rewrite of the file — however well it forges the memo's
        // identifiers — can slip planted bytes past it. The cost is CPU
        // over bytes already in memory, not another disk pass.
        if let Some(expected) = digest
            && Md5::digest(&bytes)[..] != *expected
        {
            debug!("a hub entry failed its digest proof; serving uncached");
            return Ok(None);
        }
        if let Some(cap) = max_bytes
            && bytes.len() as u64 > cap
        {
            return Err(read_bytes_max_bytes_error(cap));
        }
        info.size = Some(bytes.len() as u64);
        Ok(Some(ReadResult::Bytes { bytes, info }))
    }

    /// Builds the delegate for an entry the hub opened, or `None` for an
    /// entry that cannot be served: a path that does not exist (the
    /// extension trap), a length the object's declared size contradicts, or
    /// bytes that do not carry the `digest` the entry's key names.
    ///
    /// The digest is proven on the way out, not just on the way in: this
    /// layer proves its own fills before committing, but a digest key is
    /// shared with omni.client, which copies bodies into the hub with the
    /// origin's `Content-MD5` passed through unverified — so a foreign
    /// entry's bytes may not carry the digest its key claims, and serving
    /// them would answer every URL whose stat reports that digest with the
    /// wrong body. Hashing the local file costs one bounded-buffer pass;
    /// an entry that fails is simply unusable, exactly like the extension
    /// trap.
    ///
    /// A `None` releases the lease before returning. A delegate carries the
    /// lease as its guard — the handle IS the guard, so dropping the
    /// delegate enqueues the close, and the entry is pinned against
    /// eviction for exactly as long as any clone of the delegate lives.
    ///
    /// The waits — the digest pass above all, whose budget scales with the
    /// object — race the caller's token, so a cancelled caller stops
    /// waiting immediately; the entry then merely looks unusable here, and
    /// the caller's own cancellation gate turns that into `Cancelled`
    /// before any fallback answer is produced.
    pub(crate) async fn serve_leased(
        &self,
        handle: ReadHandle,
        probe: &ValidatorProbe,
        digest: Option<&[u8]>,
        cancel: Option<&CancellationToken>,
    ) -> Option<LocalDelegate> {
        let Ok(meta) = self
            .fs
            .run(
                self.io_deadline(),
                cancel,
                tokio::fs::metadata(handle.path().to_path_buf()),
            )
            .await
        else {
            release_lease(handle, cancel).await;
            return None;
        };
        if probe.info.size.is_some_and(|size| size != meta.len()) {
            release_lease(handle, cancel).await;
            return None;
        }
        if let Some(expected) = digest
            && !self.proven.contains(handle.path(), &meta, expected)
        {
            // The proof's budget is a policy floor, not a health probe: a
            // slow mount missing it on a huge entry must not latch the
            // shared cooldown that gates every other request.
            let hashed = self
                .fs
                .run_unlatched(
                    scaled_deadline(self.io_deadline(), meta.len()),
                    cancel,
                    file_md5(handle.path().to_path_buf()),
                )
                .await;
            if !hashed.is_ok_and(|hash| hash[..] == *expected) {
                debug!("a hub entry failed its digest proof; serving uncached");
                release_lease(handle, cancel).await;
                return None;
            }
            self.proven.record(handle.path(), &meta, expected);
        }
        let mut info = probe.info.clone();
        info.size = Some(meta.len());
        // The answer is the hub's copy: `size` describes it (byte-identical
        // to the source by the fill's own checks), but the origin object's
        // modification time does not describe this file — the same absence
        // the byte cache reports for its CAS copies.
        info.mtime = None;
        let path = handle.path().to_path_buf();
        Some(LocalDelegate {
            path,
            info,
            guard: Some(Arc::new(handle)),
        })
    }

    /// Reserves the hub entry a fill would stream into, or reports why not.
    /// Every route that does not reserve records its reason on the
    /// fill-outcome counter under `op`.
    pub(crate) async fn begin_fill(
        &self,
        op: Op,
        address: &Url,
        probe: &ValidatorProbe,
        key: &HubKey,
        cancel: Option<&CancellationToken>,
    ) -> FillStart {
        let Some(slots) = self.fill_slots.as_ref() else {
            metrics::record_fill(op, FillOutcome::Skipped(SkipReason::Disabled));
            return FillStart::Skipped;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            // Every fill slot is busy: serving uncached beats queueing.
            metrics::record_fill(op, FillOutcome::Skipped(SkipReason::NoSlot));
            return FillStart::Skipped;
        };
        // No usable size means no reservation: the hub reserves by size and
        // refuses a zero-byte one outright, and the commit check needs the
        // declared count. Skipping up front keeps a routine empty object
        // from collecting a hub error on every read.
        let Some(expected) = probe.info.size.filter(|size| *size > 0) else {
            metrics::record_fill(op, FillOutcome::Skipped(SkipReason::NoSize));
            return FillStart::Skipped;
        };
        if self.max_object_bytes.is_some_and(|cap| expected > cap) {
            metrics::record_fill(op, FillOutcome::Skipped(SkipReason::OverCap));
            return FillStart::Skipped;
        }
        let opened = match race_hub(
            cancel,
            self.client
                .open_for_write(&key.key, &key.provider, &key.extension, expected),
        )
        .await
        {
            Ok(opened) => opened,
            // The caller is gone. Skip quietly and record nothing — its own
            // next await returns `Cancelled`, and a cancelled request never
            // reaches a classification.
            Err(_) => return FillStart::Skipped,
        };
        match opened {
            Ok(WriteOpen::Opened(handle)) => FillStart::Begun(FillTicket {
                handle,
                expected,
                io_timeout: self.io_deadline(),
                fs: self.fs.clone(),
                digest: key.digest.clone(),
                op,
                armed: Armed::new(op),
                _permit: permit,
            }),
            Ok(WriteOpen::AlreadyExists) => {
                metrics::record_fill(op, FillOutcome::Skipped(SkipReason::AlreadyExists));
                FillStart::AlreadyCommitted
            }
            Ok(WriteOpen::PendingWrite) => {
                metrics::record_fill(op, FillOutcome::Skipped(SkipReason::PendingWrite));
                FillStart::Skipped
            }
            Ok(WriteOpen::TooLarge) => {
                metrics::record_fill(op, FillOutcome::Skipped(SkipReason::TooLarge));
                FillStart::Skipped
            }
            Err(error) => {
                debug!(
                    address = %redact_url(address),
                    %error,
                    "hub open-for-write failed; serving uncached"
                );
                metrics::record_fill(op, FillOutcome::Skipped(SkipReason::HubUnavailable));
                FillStart::Skipped
            }
        }
    }
}

/// How a fill attempt began — or why it did not.
pub(crate) enum FillStart {
    /// The entry is reserved; the fill proceeds under this ticket.
    Begun(FillTicket),
    /// Another client committed this key between this request's read-open
    /// and its write-open. There is nothing to fill, and a committed entry
    /// exists for callers that can re-probe and serve it.
    AlreadyCommitted,
    /// No fill this time: filling disabled, every slot busy, no usable
    /// size, over the object cap, another client mid-fill, or the hub
    /// unavailable.
    Skipped,
}

impl HubCacheWrapper {
    /// The base budget for one operation on the hub's cache filesystem: the
    /// same per-call deadline the hub RPCs run under.
    ///
    /// The cache directory belongs to the hub, not to this layer — it may
    /// even sit on a network mount — so its filesystem is held to the same
    /// contract as the hub's socket: no failure mode may hold a caller's
    /// request beyond a bounded wait. An operation that misses its budget
    /// is treated exactly like a failed one.
    pub(crate) fn io_deadline(&self) -> Duration {
        self.client.config().timeout
    }
}

/// How long the cache filesystem stays presumed-stalled after an operation
/// misses its budget.
const FS_STALL_COOLDOWN: Duration = Duration::from_secs(5);

/// The most cache-filesystem operations that may exist at once, finished or
/// not. Far above any healthy concurrent count — these operations normally
/// take microseconds — so the bound only ever binds when operations stop
/// finishing.
const FS_MAX_INFLIGHT: usize = 256;

/// Health guard for the hub's cache filesystem, in two parts.
///
/// The runtime's filesystem operations run on the blocking pool and cannot
/// be cancelled once started: a timed-out operation returns control to the
/// caller while its blocking work keeps running until the filesystem
/// yields. The **slots** are what actually bound that: every operation runs
/// as its own task holding a slot that is returned only when the operation
/// finishes, so however many callers give up waiting, at most
/// [`FS_MAX_INFLIGHT`] operations exist against the mount — a stalled one
/// keeps its slot for exactly as long as it is stalled, and a burst that
/// arrives while earlier operations are stuck is turned away by the slots
/// themselves, not by any timer.
///
/// The **cooldown latch** is the fast path layered on top: the first missed
/// budget latches a window during which every operation fails immediately,
/// so the hit and fill paths degrade to the inner layer at once instead of
/// each paying a fresh deadline against a mount already presumed wedged.
pub(crate) struct FsHealth {
    stalled_until: std::sync::Mutex<Option<tokio::time::Instant>>,
    slots: Arc<tokio::sync::Semaphore>,
}

impl FsHealth {
    pub(crate) fn new() -> Self {
        Self::with_slots(FS_MAX_INFLIGHT)
    }

    fn with_slots(slots: usize) -> Self {
        Self {
            stalled_until: std::sync::Mutex::new(None),
            slots: Arc::new(tokio::sync::Semaphore::new(slots)),
        }
    }

    fn available(&self) -> bool {
        let mut stalled = self.stalled_until.lock().expect("FsHealth mutex poisoned");
        match *stalled {
            Some(until) if tokio::time::Instant::now() < until => false,
            Some(_) => {
                *stalled = None;
                true
            }
            None => true,
        }
    }

    fn note_stall(&self) {
        let mut stalled = self.stalled_until.lock().expect("FsHealth mutex poisoned");
        *stalled = Some(tokio::time::Instant::now() + FS_STALL_COOLDOWN);
    }

    /// Runs one hub-cache filesystem operation under `limit`, mapping an
    /// expired budget — a still-running cooldown from an earlier one, or a
    /// slot table with nothing free — to a timed-out I/O error so every
    /// caller's existing failure arm handles it.
    ///
    /// The operation runs in its own task owning its slot, which is why it
    /// must own its inputs: a caller that stops waiting leaves the task
    /// running, and the slot comes back only when the filesystem actually
    /// yields. That, not the deadline, is the bound on abandoned work.
    ///
    /// The wait — not the operation — additionally races `cancel`: a budget
    /// here can scale with the object, and a cancelled caller must not sit
    /// out a whole-object allowance against a stalled mount. Abandoning the
    /// wait leaves the operation running exactly as a timeout would, but
    /// latches no cooldown, because nothing was proven about the
    /// filesystem.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        limit: Duration,
        cancel: Option<&CancellationToken>,
        op: impl Future<Output = std::io::Result<T>> + Send + 'static,
    ) -> std::io::Result<T> {
        self.run_inner(limit, cancel, op, true).await
    }

    /// Like [`FsHealth::run`], except an expired budget latches no
    /// cooldown. For work whose budget is a policy floor rather than a
    /// health probe — the serve-path digest proof above all, whose
    /// ~32 MiB/s allowance a merely slow mount can legitimately miss on a
    /// huge object — where arming the shared latch would degrade every
    /// other request over one slow file.
    pub(crate) async fn run_unlatched<T: Send + 'static>(
        &self,
        limit: Duration,
        cancel: Option<&CancellationToken>,
        op: impl Future<Output = std::io::Result<T>> + Send + 'static,
    ) -> std::io::Result<T> {
        self.run_inner(limit, cancel, op, false).await
    }

    async fn run_inner<T: Send + 'static>(
        &self,
        limit: Duration,
        cancel: Option<&CancellationToken>,
        op: impl Future<Output = std::io::Result<T>> + Send + 'static,
        latch: bool,
    ) -> std::io::Result<T> {
        if !self.available() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the hub cache filesystem is in its stall cooldown",
            ));
        }
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            // Every slot belongs to an operation that has not finished — on
            // a stalled mount, to the abandoned operations themselves.
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "every hub cache filesystem slot is occupied by an unfinished operation",
            ));
        };
        let task = tokio::spawn(async move {
            let _slot = slot;
            op.await
        });
        let waited = match cancel {
            Some(token) => tokio::select! {
                biased;
                _ = token.cancelled() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "the caller cancelled while waiting on the hub cache filesystem",
                    ));
                }
                waited = tokio::time::timeout(limit, task) => waited,
            },
            None => tokio::time::timeout(limit, task).await,
        };
        match waited {
            Ok(Ok(result)) => result,
            Ok(Err(join_error)) => Err(std::io::Error::other(join_error)),
            Err(_) => {
                if latch {
                    self.note_stall();
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "a hub cache filesystem operation exceeded its deadline",
                ))
            }
        }
    }
}

/// Digest proofs already carried out, so a write-once entry is hashed once
/// rather than on every hit.
///
/// The memo must not weaken the proof it is caching: the actor the proof
/// defends against is a local process that can rewrite the hub's file
/// directly, and such a process can preserve the length and restore the
/// modification time (`utimensat` sets it freely). A record therefore also
/// pins identifiers a non-root local writer cannot restore — on Unix the
/// device, inode, and change time, which the kernel advances on every
/// write (including the timestamp restore itself) and refuses to move
/// back. Where no such identifier exists the memo stays empty and every
/// serve re-proves; a root-privileged writer is outside the threat model,
/// as the configuration guide's trust-boundary note states. The set is
/// bounded by clearing it when full — crude, but a cleared record only
/// costs one re-hash.
#[derive(Default)]
pub(crate) struct DigestProofs {
    #[cfg(unix)]
    proven: std::sync::Mutex<std::collections::HashSet<ProofKey>>,
}

#[cfg(unix)]
#[derive(Hash, PartialEq, Eq)]
struct ProofKey {
    path: std::path::PathBuf,
    len: u64,
    mtime: Option<std::time::SystemTime>,
    /// `(dev, ino, ctime, ctime_nsec)`: the identity a non-root local
    /// writer cannot forge or restore.
    identity: (u64, u64, i64, i64),
    digest: Vec<u8>,
}

/// The most proofs retained at once. Far above any realistic working set of
/// distinct cached objects served between process restarts.
#[cfg(unix)]
const DIGEST_PROOF_CAP: usize = 1024;

impl DigestProofs {
    #[cfg(unix)]
    fn key(path: &Path, meta: &std::fs::Metadata, digest: &[u8]) -> ProofKey {
        use std::os::unix::fs::MetadataExt as _;
        ProofKey {
            path: path.to_path_buf(),
            len: meta.len(),
            mtime: meta.modified().ok(),
            identity: (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
            digest: digest.to_vec(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn contains(&self, path: &Path, meta: &std::fs::Metadata, digest: &[u8]) -> bool {
        self.proven
            .lock()
            .expect("DigestProofs mutex poisoned")
            .contains(&Self::key(path, meta, digest))
    }

    /// Without a kernel-maintained change identifier, a rewrite can be made
    /// invisible to any key this memo could build, so nothing is ever
    /// remembered and every serve re-proves.
    #[cfg(not(unix))]
    pub(crate) fn contains(&self, _path: &Path, _meta: &std::fs::Metadata, _digest: &[u8]) -> bool {
        false
    }

    #[cfg(unix)]
    pub(crate) fn record(&self, path: &Path, meta: &std::fs::Metadata, digest: &[u8]) {
        let mut proven = self.proven.lock().expect("DigestProofs mutex poisoned");
        if proven.len() >= DIGEST_PROOF_CAP {
            proven.clear();
        }
        proven.insert(Self::key(path, meta, digest));
    }

    #[cfg(not(unix))]
    pub(crate) fn record(&self, _path: &Path, _meta: &std::fs::Metadata, _digest: &[u8]) {}
}

/// Releases a hit's lease: acknowledged when someone is still waiting,
/// fire-and-forget when the caller has already cancelled — a departed
/// caller must not sit out the hub's release round trip, and the dropped
/// handle enqueues the same `Close`.
async fn release_lease(handle: ReadHandle, cancel: Option<&CancellationToken>) {
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        drop(handle);
    } else {
        let _ = handle.close().await;
    }
}

/// Races a hub call against the caller's cancellation token.
///
/// A cancelled caller stops waiting immediately rather than paying out the
/// hub deadline. The abandoned call's correlation entry keeps its
/// late-release duty, so a lease its response later carries is still given
/// back.
pub(crate) async fn race_hub<T>(
    cancel: Option<&CancellationToken>,
    call: impl Future<Output = std::result::Result<T, ovstorage_hub_client::HubError>>,
) -> Result<std::result::Result<T, ovstorage_hub_client::HubError>> {
    match cancel {
        Some(token) => tokio::select! {
            biased;
            _ = token.cancelled() => Err(Error::new(ErrorCode::Cancelled, "cancelled by host")),
            result = call => Ok(result),
        },
        None => Ok(call.await),
    }
}

/// The budget for a filesystem operation that moves `bytes`: the base
/// deadline plus a floor-throughput allowance (~32 MiB/s), so a
/// legitimately large body gets time proportional to its size while every
/// wait stays bounded.
pub(crate) fn scaled_deadline(base: Duration, bytes: u64) -> Duration {
    base + Duration::from_micros(bytes / 32)
}

/// How much of a buffered body one staging operation owns at a time.
///
/// A staging operation runs as a task that may outlive its waiter (see
/// [`FsHealth::run`]), so whatever it owns is retained until the filesystem
/// yields. Copying the body into the entry one bounded chunk at a time
/// caps that retention at one chunk per abandoned operation — never the
/// caller's whole body, which stays borrowed and is returned to the caller
/// untouched whatever happens here.
const FILL_COPY_CHUNK: usize = 512 * 1024;

/// Writes a fully buffered body into the reserved entry and commits,
/// reporting whether the entry became visible.
///
/// The body is staged through [`StagedFill`], so the buffered path obeys
/// the same allowance accounting and the same digest proof as the streamed
/// one, and an abandoned staging operation retains at most
/// [`FILL_COPY_CHUNK`] copied bytes. The caller's token is observed at
/// every chunk boundary and before the final sync-and-commit: a cancelled
/// caller does not wait out the staging of a large body — the fill is
/// discarded and the bytes already in hand answer them.
///
/// Best-effort by construction on the read path: the caller's bytes are
/// already in hand, so nothing here can affect the read — a write or commit
/// failure only costs the cache entry, and the abort path discards the
/// reservation.
pub(crate) async fn fill_from_bytes(
    ticket: FillTicket,
    bytes: &[u8],
    cancel: Option<&CancellationToken>,
) -> bool {
    let body: ReadStream = Box::pin(futures::stream::empty());
    let mut fill = StagedFill::new(body, ticket, cancel.cloned());
    for chunk in bytes.chunks(FILL_COPY_CHUNK) {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            fill.ticket.record_abandoned(AbortReason::Cancelled);
            return false;
        }
        if fill
            .stage_chunk(Bytes::copy_from_slice(chunk))
            .await
            .is_err()
        {
            // The staging wait itself races the token, so a failure may be
            // the caller leaving rather than the filesystem misbehaving —
            // and a departed caller must not wait on the hub's release
            // acknowledgement either: record and drop, the drop enqueues
            // the fire-and-forget `Remove`.
            if cancel.is_some_and(CancellationToken::is_cancelled) {
                fill.ticket.record_abandoned(AbortReason::Cancelled);
            } else {
                fill.ticket.abort_with(AbortReason::StagingError).await;
            }
            return false;
        }
    }
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        fill.ticket.record_abandoned(AbortReason::Cancelled);
        return false;
    }
    fill.settle().await
}

/// The md5 of the file at `path`, computed in bounded chunks so an
/// arbitrarily large entry is never buffered whole.
async fn file_md5(path: std::path::PathBuf) -> std::io::Result<[u8; 16]> {
    use tokio::io::AsyncReadExt as _;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Md5::new();
    let mut buffer = vec![0u8; FILL_COPY_CHUNK];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Tees the inner body into the reserved hub entry chunk-by-chunk while
/// forwarding every chunk to the caller unchanged (the streaming
/// invariant: nothing is buffered beyond the chunk in hand).
///
/// The commit decision is the tee's, made at end of stream: a clean end
/// whose byte count matches the declared size syncs and commits; a short
/// or over-long body, a stream error, or a staging write failure aborts.
/// The caller dropping the stream mid-body drops the ticket, whose write
/// handle enqueues `Remove` — an abandoned fill discards its reservation
/// without needing an async context, and its [`Armed`] guard records the
/// `caller_dropped` fill outcome from the same drop.
///
/// The caller's token is a second, first-class way out: it is raced
/// against every poll of the inner stream and every staging wait —
/// including the size-scaled end-of-body sync, which runs inside the
/// caller's final poll — and once it fires the stream yields
/// `Err(Cancelled)` and ends, discarding the reservation.
fn tee_into_hub(
    stream: ReadStream,
    ticket: FillTicket,
    cancel: Option<CancellationToken>,
) -> ReadStream {
    enum State {
        /// Boxed so the active variant does not bloat the unfold state.
        Teeing(Box<StagedFill>),
        Passthrough(ReadStream, Option<CancellationToken>),
        Done,
    }
    Box::pin(futures::stream::unfold(
        State::Teeing(Box::new(StagedFill::new(stream, ticket, cancel))),
        |state| async move {
            match state {
                State::Teeing(mut tee) => {
                    // `None` marks cancellation; the checked-first bias
                    // makes an already-fired token observed before any
                    // chunk is awaited.
                    let polled = match tee.cancel.clone() {
                        Some(token) => tokio::select! {
                            biased;
                            _ = token.cancelled() => None,
                            next = tee.stream.next() => Some(next),
                        },
                        None => Some(tee.stream.next().await),
                    };
                    let Some(next) = polled else {
                        tee.ticket.record_abandoned(AbortReason::Cancelled);
                        return Some((Err(cancelled_error()), State::Done));
                    };
                    match next {
                        Some(Ok(chunk)) => {
                            if tee.overflows(&chunk) {
                                // A body longer than the declared size can
                                // never commit; stop staging now rather
                                // than spooling bytes the end-of-stream
                                // check would discard anyway. Abandon the
                                // fill, keep serving: dropping the ticket
                                // removes the reservation.
                                tee.ticket.record_abandoned(AbortReason::SizeMismatch);
                                let StagedFill { stream, cancel, .. } = *tee;
                                return Some((Ok(chunk), State::Passthrough(stream, cancel)));
                            }
                            match tee.stage_chunk(chunk.clone()).await {
                                Ok(()) => Some((Ok(chunk), State::Teeing(tee))),
                                // The staging wait itself races the token,
                                // so a failure may be the caller leaving —
                                // terminal — rather than the filesystem
                                // misbehaving, which only abandons the
                                // fill.
                                Err(()) => {
                                    if tee
                                        .cancel
                                        .as_ref()
                                        .is_some_and(CancellationToken::is_cancelled)
                                    {
                                        tee.ticket.record_abandoned(AbortReason::Cancelled);
                                        return Some((Err(cancelled_error()), State::Done));
                                    }
                                    tee.ticket.record_abandoned(AbortReason::StagingError);
                                    let StagedFill { stream, cancel, .. } = *tee;
                                    Some((Ok(chunk), State::Passthrough(stream, cancel)))
                                }
                            }
                        }
                        // A truncated or errored body never commits: the
                        // drop of the ticket discards the reservation.
                        Some(Err(error)) => {
                            tee.ticket.record_abandoned(AbortReason::StreamError);
                            Some((Err(error), State::Done))
                        }
                        None => {
                            let cancel = tee.cancel.clone();
                            // The settle labels a cancelled sync itself; a
                            // token that fired during it still ends the
                            // stream with the truth rather than a clean
                            // EOF.
                            let _ = tee.settle().await;
                            if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                                return Some((Err(cancelled_error()), State::Done));
                            }
                            None
                        }
                    }
                }
                State::Passthrough(mut stream, cancel) => {
                    let polled = match cancel.clone() {
                        Some(token) => tokio::select! {
                            biased;
                            _ = token.cancelled() => None,
                            next = stream.next() => Some(next),
                        },
                        None => Some(stream.next().await),
                    };
                    match polled {
                        None => Some((Err(cancelled_error()), State::Done)),
                        Some(next) => next.map(|item| (item, State::Passthrough(stream, cancel))),
                    }
                }
                State::Done => None,
            }
        },
    ))
}

/// A body being spooled into a reserved hub entry one chunk at a time:
/// the read path's tee and the `materialize` drain share it, so both obey
/// the same size accounting, the same digest proof, and the same commit
/// decision.
pub(crate) struct StagedFill {
    pub(crate) stream: ReadStream,
    pub(crate) ticket: FillTicket,
    /// Opened on the first chunk, so a body that errors immediately never
    /// touches the file.
    file: Option<tokio::fs::File>,
    written: u64,
    /// Hashes the staged bytes when the ticket's key names a digest, so the
    /// commit can prove they carry it.
    hasher: Option<Md5>,
    /// What remains of the fill's whole-body filesystem allowance: the same
    /// floor-throughput budget one operation moving the entire declared
    /// body would get. Each staging operation draws down what it actually
    /// spends, so a filesystem that stays just inside every per-chunk
    /// deadline cannot stretch an N-chunk fill to N deadlines — in total, a
    /// fill's staging waits are bounded by this allowance plus one
    /// operation's own budget.
    fs_allowance: Duration,
    /// The caller's token, raced against every staging wait so a cancelled
    /// caller never sits out a filesystem deadline.
    cancel: Option<CancellationToken>,
}

impl StagedFill {
    /// Begins staging `stream` into the entry `ticket` reserves.
    pub(crate) fn new(
        stream: ReadStream,
        ticket: FillTicket,
        cancel: Option<CancellationToken>,
    ) -> Self {
        let hasher = ticket.digest.as_ref().map(|_| Md5::new());
        let fs_allowance = scaled_deadline(ticket.io_timeout, ticket.expected);
        Self {
            stream,
            ticket,
            file: None,
            written: 0,
            hasher,
            fs_allowance,
            cancel,
        }
    }

    /// Whether staging `chunk` would exceed the reservation. Hub reserved
    /// exactly the declared size, and a longer body can never commit.
    pub(crate) fn overflows(&self, chunk: &[u8]) -> bool {
        self.written + chunk.len() as u64 > self.ticket.expected
    }

    /// Runs one staging operation under its own `per_op` budget and the
    /// fill's remaining allowance.
    ///
    /// The per-operation budget is never shortened — an operation either
    /// gets all of it or, once the allowance is spent, is not launched at
    /// all — so the shared stall latch only ever learns about genuine
    /// per-operation misses, never about a fill that merely ran out of its
    /// own time.
    async fn run_within_allowance<T: Send + 'static>(
        &mut self,
        per_op: Duration,
        op: impl Future<Output = std::io::Result<T>> + Send + 'static,
    ) -> std::io::Result<T> {
        if self.fs_allowance.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the fill's filesystem allowance is exhausted",
            ));
        }
        let started = tokio::time::Instant::now();
        let result = self.ticket.fs.run(per_op, self.cancel.as_ref(), op).await;
        self.fs_allowance = self.fs_allowance.saturating_sub(started.elapsed());
        result
    }

    /// Settles the fill at end of body, reporting whether the entry became
    /// visible: a clean end whose byte count matches the reservation — and
    /// whose bytes carry the digest, when the key names one — syncs and
    /// commits; everything else discards it. A sync the caller's
    /// cancellation interrupted is recorded as `cancelled`, not as a
    /// filesystem failure.
    pub(crate) async fn settle(mut self) -> bool {
        let synced = match self.file.take() {
            Some(file) => {
                let limit = scaled_deadline(self.ticket.io_timeout, self.written);
                self.run_within_allowance(limit, async move { file.sync_all().await })
                    .await
                    .is_ok()
            }
            // No chunk was ever staged. The reservation is at least one
            // byte (a zero-size fill never begins), so a bodyless end is a
            // size mismatch and the arm below discards it.
            None => true,
        };
        let Self {
            mut ticket,
            written,
            hasher,
            cancel,
            ..
        } = self;
        if !synced {
            // A cancelled sync means the caller is gone: record and drop
            // rather than wait on the hub's release acknowledgement; the
            // drop enqueues the fire-and-forget `Remove`.
            if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                ticket.record_abandoned(AbortReason::Cancelled);
            } else {
                ticket.abort_with(AbortReason::StagingError).await;
            }
            return false;
        }
        if written != ticket.expected {
            ticket
                .abort_for(AbortReason::SizeMismatch, cancel.as_ref())
                .await;
            return false;
        }
        if let (Some(hasher), Some(expected)) = (hasher, ticket.digest.as_deref())
            && hasher.finalize()[..] != *expected
        {
            // The key names a digest the staged bytes do not carry: the
            // stat and the body disagree about the content, however well
            // the etag matched.
            ticket
                .abort_for(AbortReason::DigestMismatch, cancel.as_ref())
                .await;
            return false;
        }
        ticket.commit().await
    }

    /// Appends one chunk to the staging file, opening it on first use. An
    /// `Err` means the fill is abandoned; the chunk itself is unaffected.
    /// Both operations run under the ticket's filesystem budget and the
    /// fill's allowance, so a stalled cache filesystem abandons the fill
    /// instead of stalling the caller's next chunk.
    ///
    /// The chunk is taken owned — one cheap [`Bytes`] refcount from the
    /// tee, never a copy — and the staging file travels through the
    /// operation's task, because the operation must own everything it
    /// touches (see [`FsHealth::run`]). A write abandoned by its deadline
    /// takes the file with it, which is correct: the fill is over.
    pub(crate) async fn stage_chunk(&mut self, chunk: Bytes) -> std::result::Result<(), ()> {
        if self.file.is_none() {
            let path = self.ticket.path().to_path_buf();
            let opened = self
                .run_within_allowance(self.ticket.io_timeout, async move {
                    tokio::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(path)
                        .await
                })
                .await;
            match opened {
                Ok(file) => self.file = Some(file),
                Err(_) => return Err(()),
            }
        }
        if let Some(hasher) = &mut self.hasher {
            hasher.update(&chunk);
        }
        let limit = scaled_deadline(self.ticket.io_timeout, chunk.len() as u64);
        let mut file = self.file.take().expect("the staging file is open");
        let written = chunk.len() as u64;
        let staged = self
            .run_within_allowance(limit, async move {
                file.write_all(&chunk).await?;
                Ok(file)
            })
            .await;
        match staged {
            Ok(file) => {
                self.file = Some(file);
                self.written += written;
                Ok(())
            }
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use ovstorage_hub_client::fake::{EntryState, FakeHubConfig};
    use ovstorage_hub_client::{HubCacheClient, HubClientConfig, KeyScheme, WriteOpen, hub_key};

    use super::*;
    use crate::testing::{
        ADDRESS, CONTENT, ETAG, collect, expected_key, fixture, fixture_with_hub_config,
        read_request,
    };

    #[tokio::test]
    async fn a_fill_race_against_a_still_filling_writer_skips_without_disturbing_it() {
        let fx = fixture(|_| {}).await;
        let holder = HubCacheClient::new(HubClientConfig {
            endpoint: fx.hub.endpoint(),
            ..HubClientConfig::default()
        });
        let url = Url::parse(ADDRESS).unwrap();
        let key = hub_key(KeyScheme::Ovstorage, "local", &url, ETAG, None).unwrap();
        let WriteOpen::Opened(pending) = holder
            .open_for_write(
                &key.key,
                &key.provider,
                &key.extension,
                CONTENT.len() as u64,
            )
            .await
            .unwrap()
        else {
            panic!("the holder reserves the key");
        };
        // The cross-process ordering: this read's own lookup answered
        // not-cached before the racer's reservation was visible, so the
        // fill path runs into the still-open write.
        fx.hub.answer_not_cached_once(&key.key);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            2,
            "the racer's attempt reaches the hub and is turned away"
        );
        assert_eq!(
            fx.hub.entry(&key.key),
            Some(EntryState::PendingWrite),
            "the loser leaves the winner's reservation untouched"
        );
        pending.abort().await;
    }

    #[tokio::test]
    async fn a_zero_byte_object_is_served_but_never_reserved() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stat_size.lock().unwrap() = Some(0);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        // The lookup still runs; only the reservation is skipped — the hub
        // refuses a zero-byte reservation, so attempting one would collect
        // an error on every read of a routine empty object.
        assert_eq!(fx.hub.counters().opens_for_read, 1);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_filesystem_stall_latches_a_cooldown() {
        let fs = FsHealth::new();
        let limit = Duration::from_millis(10);

        // An operation that never completes misses its budget and latches.
        let err = fs
            .run(limit, None, std::future::pending::<std::io::Result<()>>())
            .await
            .expect_err("the budget expires");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // During the cooldown even an instant operation fails fast: no new
        // blocking work is launched against a mount presumed wedged.
        let err = fs
            .run(limit, None, std::future::ready(Ok(())))
            .await
            .expect_err("the cooldown fails fast");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // The latch expires on its own.
        tokio::time::advance(FS_STALL_COOLDOWN).await;
        fs.run(limit, None, std::future::ready(Ok(())))
            .await
            .expect("the cooldown has expired");
    }

    #[tokio::test(start_paused = true)]
    async fn stuck_operations_hold_their_slots_beyond_the_cooldown() {
        let fs = FsHealth::with_slots(2);
        let limit = Duration::from_millis(10);

        // Two operations wedge; each cooldown is waited out so the next
        // launch is admitted by the latch and stopped by the slots alone.
        for _ in 0..2 {
            let err = fs
                .run(limit, None, std::future::pending::<std::io::Result<()>>())
                .await
                .expect_err("the budget expires");
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
            tokio::time::advance(FS_STALL_COOLDOWN).await;
        }

        // The latch is open, but both slots still belong to operations that
        // never finished: however many callers have since given up, nothing
        // new is launched against the mount until one actually completes.
        let err = fs
            .run(limit, None, std::future::ready(Ok(())))
            .await
            .expect_err("every slot is stuck");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    /// A wait whose budget can scale with the object must not outlive the
    /// caller: cancellation abandons the wait immediately — the operation
    /// keeps its slot and runs on — and no cooldown latches, because the
    /// filesystem was never proven slow.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_caller_stops_waiting_on_a_stalled_operation() {
        let fs = FsHealth::new();
        let token = CancellationToken::new();
        let waiter = fs.run(
            Duration::from_secs(3600),
            Some(&token),
            std::future::pending::<std::io::Result<()>>(),
        );
        tokio::pin!(waiter);
        assert!(
            futures::poll!(waiter.as_mut()).is_pending(),
            "the stalled operation keeps the waiter pending"
        );
        token.cancel();

        let err = waiter.await.expect_err("the wait is abandoned");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
        fs.run(Duration::from_millis(10), None, std::future::ready(Ok(())))
            .await
            .expect("no stall was latched by the abandoned wait");
    }

    /// A cancelled caller stops a hit's serve mid-wait: the entry merely
    /// looks unusable here, the lease is released, and the caller's own
    /// gate — not this path — produces the `Cancelled` answer.
    #[tokio::test]
    async fn a_cancelled_wait_makes_a_leased_entry_unusable_without_hanging() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let claimed = Md5::digest(CONTENT).to_vec();
        let key = digest_key(&claimed);
        fx.hub.seed_entry(&key, "usd", CONTENT);
        let client = HubCacheClient::new(HubClientConfig {
            endpoint: fx.hub.endpoint(),
            ..HubClientConfig::default()
        });
        let ovstorage_hub_client::ReadOpen::Opened(handle) =
            client.open_for_read(&key, "test", "usd").await.unwrap()
        else {
            panic!("the seeded entry opens");
        };
        let probe = ValidatorProbe {
            info: crate::testing::probe_object_info(&Url::parse(ADDRESS).unwrap()),
            etag: ETAG.to_string(),
        };
        let token = CancellationToken::new();
        token.cancel();

        let served = fx
            .wrapper
            .serve_leased(handle, &probe, Some(&claimed), Some(&token))
            .await;
        assert!(served.is_none(), "a cancelled wait serves nothing");

        client.quiesce().await;
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The digest proof's budget is a policy floor, not a health probe: an
    /// overrun must not latch the cooldown that gates every other request.
    #[tokio::test(start_paused = true)]
    async fn an_unlatched_overrun_arms_no_cooldown() {
        let fs = FsHealth::new();
        let err = fs
            .run_unlatched(
                Duration::from_millis(10),
                None,
                std::future::pending::<std::io::Result<()>>(),
            )
            .await
            .expect_err("the budget expires");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        fs.run(Duration::from_millis(10), None, std::future::ready(Ok(())))
            .await
            .expect("no cooldown was latched by the unlatched overrun");
    }

    /// One proof per file state: the record pins path, length, mtime and
    /// digest, so any change re-proves and the set stays bounded.
    #[tokio::test]
    async fn digest_proofs_pin_the_exact_file_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("entry.bin");
        std::fs::write(&path, CONTENT).expect("stages");
        let meta = std::fs::metadata(&path).expect("stats");
        let proofs = DigestProofs::default();
        let digest = Md5::digest(CONTENT).to_vec();

        assert!(!proofs.contains(&path, &meta, &digest));
        proofs.record(&path, &meta, &digest);
        assert!(proofs.contains(&path, &meta, &digest));
        // A different digest for the same state is a different proof.
        assert!(!proofs.contains(&path, &meta, b"other"));

        // A same-length rewrite with the modification time restored — the
        // forgery a local writer can actually produce — still misses: the
        // change time advanced on both writes and cannot be moved back. The
        // sleep spans the filesystem clock's coarse granularity, as the gap
        // between a real proof and a real rewrite always does.
        #[cfg(unix)]
        {
            std::thread::sleep(Duration::from_millis(30));
            let mtime = meta.modified().expect("mtime");
            std::fs::write(&path, b"planted bytes!!").expect("rewrites in place");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("reopens");
            file.set_times(std::fs::FileTimes::new().set_modified(mtime))
                .expect("restores the modification time");
            drop(file);
            let restored = std::fs::metadata(&path).expect("stats");
            assert_eq!(restored.len(), meta.len(), "the forgery preserves length");
            assert_eq!(
                restored.modified().ok(),
                meta.modified().ok(),
                "the forgery restores the modification time"
            );
            assert!(
                !proofs.contains(&path, &restored, &digest),
                "a restored surface state must not satisfy the memo"
            );
        }

        // A rewrite produces a new length (or timestamp) and re-proves.
        std::fs::write(&path, b"rewritten with another length").expect("rewrites");
        let rewritten = std::fs::metadata(&path).expect("stats");
        assert!(!proofs.contains(&path, &rewritten, &digest));
    }

    /// BrianHarris's probe from the review, end to end: a local writer
    /// rewrites the hub's file in place with same-length planted bytes and
    /// restores the modification time. The memo must not let the planted
    /// bytes ride an earlier proof — the changed inode change-time forces a
    /// re-proof, which fails, and the backend answers.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_rewritten_entry_with_restored_times_is_reproven_and_refused() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let claimed = Md5::digest(CONTENT).to_vec();
        *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
        fx.hub.seed_entry(&digest_key(&claimed), "usd", CONTENT);

        // The first serve proves the entry and memoizes its state.
        let first = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::LocalDelegate(delegate) = first else {
            panic!("a streaming hit is a delegate");
        };
        let entry_path = delegate.path.clone();
        let mtime = std::fs::metadata(&entry_path)
            .expect("stats")
            .modified()
            .expect("mtime");
        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;

        // Span the filesystem clock's coarse granularity, as the gap
        // between a real proof and a real rewrite always does.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let planted: Vec<u8> = CONTENT.iter().map(|byte| byte.wrapping_add(1)).collect();
        std::fs::write(&entry_path, &planted).expect("rewrites in place");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&entry_path)
            .expect("reopens");
        file.set_times(std::fs::FileTimes::new().set_modified(mtime))
            .expect("restores the modification time");
        drop(file);

        let second = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(
            collect(second).await,
            CONTENT,
            "planted bytes are never served"
        );
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            1,
            "the failed re-proof degrades to the backend"
        );
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_finished_operation_returns_its_slot() {
        let fs = FsHealth::with_slots(1);
        for _ in 0..2 {
            fs.run(Duration::from_secs(5), None, std::future::ready(Ok(())))
                .await
                .expect("a completed operation frees its slot");
        }
    }

    #[tokio::test]
    async fn a_cancelled_caller_stops_before_the_hub_answers() {
        let fx = fixture(|_| {}).await;
        let cancel = CancellationToken::new();
        cancel.cancel();

        let error = fx
            .wrapper
            .read(read_request(ADDRESS), Some(cancel))
            .await
            .expect_err("a cancelled read is cancelled");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        // The raced hub lookup was never paid for: the token is checked
        // before the call is awaited.
        assert_eq!(fx.hub.counters().opens_for_read, 0);
    }

    /// The compat digest key for [`ADDRESS`] at [`ETAG`] carrying `digest`.
    fn digest_key(digest: &[u8]) -> String {
        let url = Url::parse(ADDRESS).unwrap();
        hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &url,
            ETAG,
            Some(digest),
        )
        .expect("a digest keys")
        .key
    }

    #[tokio::test]
    async fn a_digest_bearing_object_fills_under_the_compat_hash_tier() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        // The digest the source reports is the digest the body carries;
        // anything else must never commit (the test below pins that).
        let digest = Md5::digest(CONTENT).to_vec();
        *fx.probe.md5.lock().unwrap() = Some(digest.clone());

        let first = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(first).await, CONTENT);
        fx.wrapper.client.quiesce().await;
        assert!(
            matches!(
                fx.hub.entry(&digest_key(&digest)),
                Some(EntryState::Committed { .. })
            ),
            "the fill lands under omni.client's digest-tier key"
        );

        let second = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(second).await, CONTENT);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            1,
            "the digest-tier entry answers the repeat read"
        );
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The etag-reuse poisoning path: the stat reports the digest of one
    /// body and the read produces another under the SAME etag and size. The
    /// key names the digest, so committing would let the wrong bytes answer
    /// every URL whose stat reports that digest — the fill must prove the
    /// staged bytes instead, and refuse.
    #[tokio::test]
    async fn a_body_that_does_not_carry_the_keys_digest_is_served_but_never_committed() {
        for chunked in [None, Some(4)] {
            let fx = fixture(|config| {
                config.insert(
                    "key_scheme".to_string(),
                    ConfigValue::String("omni-client-compat".to_string()),
                );
            })
            .await;
            let claimed = Md5::digest(b"a body the source no longer has").to_vec();
            *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
            *fx.probe.stream_chunk.lock().unwrap() = chunked;

            let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
            assert_eq!(collect(result).await, CONTENT, "the caller is unaffected");

            fx.wrapper.client.quiesce().await;
            assert_eq!(
                fx.hub.entry(&digest_key(&claimed)),
                None,
                "the unproven fill is discarded (chunked: {chunked:?})"
            );
            fx.hub.wait_for_open_handles(0).await;
        }
    }

    /// omni.client copies bodies into the hub with the origin's
    /// `Content-MD5` passed through unverified, so a foreign digest entry's
    /// bytes may not carry the digest its key claims. A hit proves the
    /// bytes before serving them; an entry that fails is unusable and the
    /// read degrades to the backend — on both serve shapes.
    #[tokio::test]
    async fn a_foreign_digest_entry_whose_bytes_do_not_match_its_key_is_never_served() {
        for to_bytes in [false, true] {
            let fx = fixture(|config| {
                config.insert(
                    "key_scheme".to_string(),
                    ConfigValue::String("omni-client-compat".to_string()),
                );
            })
            .await;
            let claimed = Md5::digest(CONTENT).to_vec();
            *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
            // Same length as the declared size, different bytes: only the
            // digest proof can tell them apart.
            let wrong: Vec<u8> = CONTENT.iter().map(|byte| byte.wrapping_add(1)).collect();
            fx.hub.seed_entry(&digest_key(&claimed), "usd", &wrong);

            let mut request = read_request(ADDRESS);
            if to_bytes {
                request
                    .extensions
                    .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
            }
            let result = fx.wrapper.read(request, None).await.unwrap();
            assert_eq!(
                collect(result).await,
                CONTENT,
                "the poisoned entry is never served (to_bytes: {to_bytes})"
            );
            assert_eq!(
                fx.probe.reads.load(Ordering::SeqCst),
                1,
                "the backend answers instead (to_bytes: {to_bytes})"
            );
            fx.wrapper.client.quiesce().await;
            fx.hub.wait_for_open_handles(0).await;
        }
    }

    /// A budget rejection may only fail a request over an entry that could
    /// actually be served: a digest key's entry is unproven until its bytes
    /// are read, so an over-budget one degrades to the inner layer instead
    /// of failing the caller on the hub's behalf.
    #[tokio::test]
    async fn an_over_budget_digest_entry_degrades_instead_of_failing_the_read() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let claimed = Md5::digest(CONTENT).to_vec();
        *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
        fx.hub.seed_entry(&digest_key(&claimed), "usd", CONTENT);

        let mut buffered = read_request(ADDRESS);
        buffered
            .extensions
            .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
        buffered.input.options.max_bytes = Some(CONTENT.len() as u64 - 1);
        let result = fx
            .wrapper
            .read(buffered, None)
            .await
            .expect("the inner layer serves what the hub could not prove");
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The proof is a filter, not a lockout: a foreign entry whose bytes do
    /// carry the claimed digest is served without touching the backend.
    #[tokio::test]
    async fn a_foreign_digest_entry_with_matching_bytes_is_served() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let claimed = Md5::digest(CONTENT).to_vec();
        *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
        fx.hub.seed_entry(&digest_key(&claimed), "usd", CONTENT);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            0,
            "the proven entry answers"
        );
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// A token that fires once the body is already in hand still stops the
    /// staging: the fill loop observes it before copying a single chunk,
    /// and the reservation is discarded.
    #[tokio::test]
    async fn a_cancelled_buffered_fill_stops_without_staging() {
        let fx = fixture(|_| {}).await;
        let url = Url::parse(ADDRESS).unwrap();
        let key = hub_key(KeyScheme::Ovstorage, "local", &url, ETAG, None).unwrap();
        let probe = ValidatorProbe {
            info: crate::testing::probe_object_info(&url),
            etag: ETAG.to_string(),
        };
        let FillStart::Begun(ticket) = fx
            .wrapper
            .begin_fill(Op::Read, &url, &probe, &key, None)
            .await
        else {
            panic!("the reservation begins");
        };
        let token = CancellationToken::new();
        token.cancel();

        assert!(
            !fill_from_bytes(ticket, CONTENT, Some(&token)).await,
            "a cancelled fill never commits"
        );
        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&key.key), None, "the reservation is discarded");
    }

    /// The buffered-miss contract: an operation that observed the token —
    /// aborting its fill on it — must not answer with success, however
    /// ready its bytes are.
    #[tokio::test]
    async fn a_cancelled_buffered_miss_answers_cancelled_not_ok() {
        let fx = fixture(|_| {}).await;
        let token = CancellationToken::new();
        *fx.probe.cancel_on_read.lock().unwrap() = Some(token.clone());

        let error = fx
            .wrapper
            .read(read_request(ADDRESS), Some(token))
            .await
            .expect_err("a fired token is terminal");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The post-read gate covers the shapes that never fill, too: a body
    /// whose validator drifted, or a delegate answer, arriving with a fired
    /// token is still terminal — never a pass-through success.
    #[tokio::test]
    async fn a_cancelled_read_is_terminal_even_when_the_result_could_not_fill() {
        for shape in ["drifted", "delegate"] {
            let fx = fixture(|_| {}).await;
            let token = CancellationToken::new();
            *fx.probe.cancel_on_read.lock().unwrap() = Some(token.clone());
            match shape {
                "drifted" => *fx.probe.read_etag.lock().unwrap() = Some("v2".to_string()),
                _ => {
                    *fx.probe.read_delegate.lock().unwrap() =
                        Some(std::path::PathBuf::from("/nonexistent"))
                }
            }

            let error = fx
                .wrapper
                .read(read_request(ADDRESS), Some(token))
                .await
                .expect_err("a fired token is terminal");
            assert_eq!(error.code(), ErrorCode::Cancelled, "{shape}");

            fx.wrapper.client.quiesce().await;
            assert_eq!(fx.hub.entry(&expected_key()), None, "{shape}");
            fx.hub.wait_for_open_handles(0).await;
        }
    }

    /// The token is a first-class way out of the tee, not just dropping
    /// the stream: cancelling mid-body yields `Err(Cancelled)` promptly
    /// and discards the reservation.
    #[tokio::test]
    async fn cancelling_a_streamed_read_mid_body_yields_cancelled() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        let token = CancellationToken::new();

        let result = fx
            .wrapper
            .read(read_request(ADDRESS), Some(token.clone()))
            .await
            .unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("a streamed miss stays a stream");
        };
        let first = stream.next().await.expect("one chunk").expect("ok");
        assert_eq!(&first[..], &CONTENT[..4]);
        token.cancel();

        let next = stream
            .next()
            .await
            .expect("cancellation is an item, not a silent end");
        assert_eq!(
            next.expect_err("the tee answers the fired token").code(),
            ErrorCode::Cancelled
        );
        assert!(stream.next().await.is_none(), "the stream ends after it");

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_miss_fills_and_a_second_read_hits_without_touching_inner() {
        let fx = fixture(|_| {}).await;

        let first = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(first).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert!(matches!(
            fx.hub.entry(&expected_key()),
            Some(EntryState::Committed { .. })
        ));

        let second = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert!(matches!(second, ReadResult::LocalDelegate(_)));
        assert_eq!(collect(second).await, CONTENT);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            1,
            "a hit must not re-read the inner layer"
        );
        assert_eq!(fx.probe.stats.load(Ordering::SeqCst), 2);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// A hit answers with the hub's copy: its size describes that file, but
    /// the origin object's modification time does not, and echoing it next
    /// to the hub file would hand consumers a mismatched (path, mtime) pair.
    #[tokio::test]
    async fn cached_answers_do_not_report_the_origin_objects_mtime() {
        let fx = fixture(|_| {}).await;
        *fx.probe.mtime.lock().unwrap() = Some(std::time::SystemTime::UNIX_EPOCH);

        let first = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(first).await, CONTENT);

        let hit = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::LocalDelegate(delegate) = hit else {
            panic!("a streaming hit returns the hub's local file");
        };
        assert_eq!(delegate.info.mtime, None);
        drop(delegate);

        let mut buffered = read_request(ADDRESS);
        buffered
            .extensions
            .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
        let hit = fx.wrapper.read(buffered, None).await.unwrap();
        let ReadResult::Bytes { info, .. } = hit else {
            panic!("a buffering hit returns bytes");
        };
        assert_eq!(info.mtime, None);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_streaming_read_tees_into_the_hub_and_commits() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert!(matches!(result, ReadResult::Stream { .. }));
        assert_eq!(collect(result).await, CONTENT);
        fx.wrapper.client.quiesce().await;
        assert_eq!(
            fx.hub.committed_bytes(&expected_key()).as_deref(),
            Some(CONTENT)
        );

        let second = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(second).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn dropping_a_streamed_fill_mid_body_discards_the_reservation() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("a streamed miss stays a stream");
        };
        let first = stream.next().await.expect("one chunk").expect("ok");
        assert_eq!(&first[..], &CONTENT[..4]);
        drop(stream);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
        fx.hub
            .wait_for("the abandoned reservation is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
    }

    #[tokio::test]
    async fn a_read_whose_validator_drifts_mid_flight_never_fills() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_etag.lock().unwrap() = Some("v2".to_string());

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);

        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the drifted fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_drifting_streamed_read_passes_through_untouched() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        *fx.probe.read_etag.lock().unwrap() = None;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);

        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the unproven fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
    }

    #[tokio::test]
    async fn bypasses_never_touch_the_hub_or_the_validator_stat() {
        let fx = fixture(|_| {}).await;

        let mut conditional = read_request(ADDRESS);
        conditional.input.options.if_match = Some(ETAG.to_string());
        collect(fx.wrapper.read(conditional, None).await.unwrap()).await;

        let mut ranged = read_request(ADDRESS);
        ranged.input.options.range = Some(ByteRange {
            start: 0,
            end_inclusive: Some(3),
        });
        collect(fx.wrapper.read(ranged, None).await.unwrap()).await;

        let mut credentialed = read_request(ADDRESS);
        credentialed
            .extensions
            .insert(ext::RESOLVED_OAUTH_CREDENTIAL.to_string(), vec![1]);
        collect(fx.wrapper.read(credentialed, None).await.unwrap()).await;

        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 3);
        assert_eq!(
            fx.probe.stats.load(Ordering::SeqCst),
            0,
            "a bypass must not pay the validator stat"
        );
        assert_eq!(fx.hub.counters().opens_for_read, 0);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn a_hub_that_is_down_serves_uncached() {
        let fx = fixture(|_| {}).await;
        fx.hub.shutdown();

        for _ in 0..2 {
            let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
            assert_eq!(collect(result).await, CONTENT);
        }
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 2);
        // The first read paid the validator stat and discovered the outage;
        // during the failure cooldown the layer must not keep taxing the
        // backend with stats for a hub it knows cannot answer.
        assert_eq!(
            fx.probe.stats.load(Ordering::SeqCst),
            1,
            "reads during the cooldown bypass without the validator stat"
        );
    }

    #[tokio::test]
    async fn a_pending_write_is_a_miss_without_a_fill() {
        let fx = fixture(|_| {}).await;
        let holder = HubCacheClient::new(HubClientConfig {
            endpoint: fx.hub.endpoint(),
            ..HubClientConfig::default()
        });
        let url = Url::parse(ADDRESS).unwrap();
        let key = hub_key(KeyScheme::Ovstorage, "local", &url, ETAG, None).unwrap();
        let WriteOpen::Opened(pending) = holder
            .open_for_write(
                &key.key,
                &key.provider,
                &key.extension,
                CONTENT.len() as u64,
            )
            .await
            .unwrap()
        else {
            panic!("the holder reserves the key");
        };

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            1,
            "a pending key is not refilled"
        );
        pending.abort().await;
    }

    #[tokio::test]
    async fn the_extension_trap_serves_uncached_without_filling() {
        let fx = fixture(|_| {}).await;
        // The entry exists under the key this read derives, but was written
        // with a different extension, so the path the hub answers with does
        // not exist.
        fx.hub.seed_entry(&expected_key(), "usd", CONTENT);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            0,
            "a taken key is never refilled"
        );
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// Weak and unspecified validators are no trusted content identity:
    /// their token may stay equal across a byte-level change, so neither a
    /// lookup nor a fill is ever keyed on one.
    #[tokio::test]
    async fn a_non_strong_validator_never_touches_the_hub() {
        for strength in [EtagStrength::Weak, EtagStrength::Unspecified] {
            let fx = fixture(|_| {}).await;
            *fx.probe.etag_strength.lock().unwrap() = strength;

            let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
            assert_eq!(collect(result).await, CONTENT);
            assert_eq!(fx.hub.counters().opens_for_read, 0, "{strength:?}");
            assert_eq!(fx.hub.counters().opens_for_write, 0, "{strength:?}");
        }
    }

    /// A validator the read demotes to weak no longer proves the fill, even
    /// with the token unchanged.
    #[tokio::test]
    async fn a_validator_demoted_to_weak_mid_flight_never_fills() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_etag_strength.lock().unwrap() = Some(EtagStrength::Weak);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);

        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the demoted fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_etagless_object_never_touches_the_hub() {
        let fx = fixture(|_| {}).await;
        *fx.probe.etag.lock().unwrap() = None;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_read, 0);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn an_oversized_object_is_served_but_never_filled() {
        let fx = fixture(|config| {
            config.insert(
                "max_object_bytes".to_string(),
                ConfigValue::Int(CONTENT.len() as i64 - 1),
            );
        })
        .await;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn zero_max_streaming_fills_disables_filling() {
        let fx = fixture(|config| {
            config.insert("max_streaming_fills".to_string(), ConfigValue::Int(0));
        })
        .await;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
        // The lookup itself still runs: disabling fills is not disabling
        // the cache.
        assert_eq!(fx.hub.counters().opens_for_read, 1);
    }

    #[tokio::test]
    async fn a_buffering_caller_gets_bytes_on_a_hit() {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;

        let mut buffered = read_request(ADDRESS);
        buffered
            .extensions
            .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
        let result = fx.wrapper.read(buffered, None).await.unwrap();
        let ReadResult::Bytes { bytes, info } = result else {
            panic!("a buffering hit returns bytes");
        };
        assert_eq!(bytes, CONTENT);
        assert_eq!(info.etag.as_deref(), Some(ETAG));

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_buffering_hit_over_the_callers_budget_errors() {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;

        let mut buffered = read_request(ADDRESS);
        buffered
            .extensions
            .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
        buffered.input.options.max_bytes = Some(CONTENT.len() as u64 - 1);
        let error = fx
            .wrapper
            .read(buffered, None)
            .await
            .expect_err("the budget is enforced");
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_hit_whose_size_contradicts_the_stat_serves_uncached() {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        *fx.probe.stat_size.lock().unwrap() = Some(CONTENT.len() as u64 + 7);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            2,
            "a contradicted entry is not served"
        );
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn stat_not_found_propagates_without_reading() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stat_error.lock().unwrap() = Some(ErrorCode::NotFound);

        let error = fx
            .wrapper
            .read(read_request(ADDRESS), None)
            .await
            .expect_err("an absent object is absent");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_stat_outage_bypasses_to_the_inner_read() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stat_error.lock().unwrap() = Some(ErrorCode::Transient);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_read, 0);
    }

    #[tokio::test]
    async fn a_dropped_hit_delegate_releases_its_lease() {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::LocalDelegate(delegate) = result else {
            panic!("a streaming hit is a delegate");
        };
        assert!(delegate.guard.is_some(), "the lease travels as the guard");
        assert!(fx.hub.open_handles() > 0);
        drop(delegate);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_inner_read_error_while_a_fill_ticket_is_held_discards_the_reservation() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_error.lock().unwrap() = Some(ErrorCode::Transient);

        let error = fx
            .wrapper
            .read(read_request(ADDRESS), None)
            .await
            .expect_err("the inner error propagates");
        assert_eq!(error.code(), ErrorCode::Transient);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_mid_stream_error_is_forwarded_after_the_chunks_already_produced() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        *fx.probe.stream_error_after.lock().unwrap() = Some(2);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("a streamed miss stays a stream");
        };

        let first = stream.next().await.expect("chunk 1").expect("ok");
        assert_eq!(&first[..], &CONTENT[..4]);
        let second = stream.next().await.expect("chunk 2").expect("ok");
        assert_eq!(&second[..], &CONTENT[4..8]);
        let third = stream
            .next()
            .await
            .expect("the error is forwarded, not swallowed as end-of-stream");
        assert!(
            third.is_err(),
            "an injected mid-body failure must reach the caller"
        );
        assert!(
            stream.next().await.is_none(),
            "the stream ends after the forwarded error"
        );

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_oversized_stream_body_aborts_the_fill_but_still_forwards_every_chunk() {
        let fx = fixture(|_| {}).await;
        // Longer than the validator probe's declared size (`CONTENT.len()`).
        let overridden = b"01234567890123456789".to_vec();
        assert!(overridden.len() as u64 > CONTENT.len() as u64);
        *fx.probe.content_override.lock().unwrap() = Some(overridden.clone());
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert!(matches!(result, ReadResult::Stream { .. }));
        assert_eq!(
            collect(result).await,
            overridden,
            "the caller receives every chunk of the longer body intact"
        );

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_short_stream_body_ends_cleanly_but_discards_the_reservation() {
        let fx = fixture(|_| {}).await;
        // Shorter than the validator probe's declared size.
        let shortened = b"short".to_vec();
        assert!((shortened.len() as u64) < CONTENT.len() as u64);
        *fx.probe.content_override.lock().unwrap() = Some(shortened.clone());
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert!(matches!(result, ReadResult::Stream { .. }));
        assert_eq!(collect(result).await, shortened);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_buffered_body_whose_length_contradicts_the_stat_is_served_but_not_filled() {
        let fx = fixture(|_| {}).await;
        let mismatched = b"a body of a different length".to_vec();
        assert_ne!(mismatched.len() as u64, CONTENT.len() as u64);
        *fx.probe.content_override.lock().unwrap() = Some(mismatched.clone());

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert!(matches!(result, ReadResult::Bytes { .. }));
        assert_eq!(collect(result).await, mismatched);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_refused_commit_serves_the_caller_and_the_key_degrades_to_pass_through() {
        let fx = fixture(|_| {}).await;
        fx.hub.refuse_next_close(&expected_key());

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);

        // The hub consumes the handle before attempting the close, so the
        // refused commit orphans the reservation: the follow-up remove
        // cannot land, the key stays pending hub-side, and every later read
        // of it degrades to pass-through — availability, never corruption.
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
        assert_eq!(
            fx.hub.entry(&expected_key()),
            Some(ovstorage_hub_client::fake::EntryState::PendingWrite)
        );
        let again = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(again).await, CONTENT);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            2,
            "the orphaned key serves from the backend"
        );
    }

    #[tokio::test]
    async fn a_missing_declared_size_is_served_but_never_reserved() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stat_size.lock().unwrap() = None;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_read, 1);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn a_hub_that_refuses_a_too_large_reservation_serves_uncached() {
        let fx = fixture_with_hub_config(
            FakeHubConfig {
                max_entry_size: Some(CONTENT.len() as u64 - 1),
                ..FakeHubConfig::default()
            },
            |_| {},
        )
        .await;

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            1,
            "the refused reservation attempt still reaches the hub"
        );
        assert_eq!(fx.hub.entry(&expected_key()), None);
    }

    #[tokio::test]
    async fn an_inner_delegate_answer_on_a_miss_is_forwarded_and_discards_the_reservation() {
        let fx = fixture(|_| {}).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("staged.bin");
        tokio::fs::write(&path, CONTENT).await.expect("stages");
        *fx.probe.read_delegate.lock().unwrap() = Some(path.clone());

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::LocalDelegate(delegate) = result else {
            panic!("the inner delegate is forwarded unchanged");
        };
        assert_eq!(delegate.path, path);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_empty_etag_is_treated_as_no_validator() {
        let fx = fixture(|_| {}).await;
        *fx.probe.etag.lock().unwrap() = Some(String::new());

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
        assert_eq!(fx.hub.counters().opens_for_read, 0);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn a_saturated_fill_semaphore_serves_the_second_miss_without_a_reservation_attempt() {
        let fx = fixture(|config| {
            config.insert("max_streaming_fills".to_string(), ConfigValue::Int(1));
        })
        .await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let first = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::Stream { mut stream, .. } = first else {
            panic!("a streamed miss stays a stream");
        };
        // Pull exactly one chunk: the tee's fill-slot permit is held for as
        // long as the caller has not finished draining the stream.
        let chunk = stream.next().await.expect("one chunk").expect("ok");
        assert_eq!(&chunk[..], &CONTENT[..4]);

        let second_address = "test:///assets/other.usd";
        let second = fx
            .wrapper
            .read(read_request(second_address), None)
            .await
            .unwrap();
        assert_eq!(collect(second).await, CONTENT);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            1,
            "the saturated slot must not attempt a second reservation"
        );

        drop(stream);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
        fx.hub
            .wait_for("the abandoned first fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
    }
}
