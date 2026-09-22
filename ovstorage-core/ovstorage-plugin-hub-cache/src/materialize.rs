// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `hub_cache` `materialize` path: answering with the hub's own copy of
//! an object as a local file, and filling the hub when there is none yet.
//!
//! In the composition this layer is built for it stands where the byte
//! cache would, above a cloud backend whose `materialize` is `Unsupported`.
//! There, on a miss, this layer is what makes a local path exist at all —
//! which is why the fill sources its body from `inner.read` rather than
//! `inner.materialize`: those backends stream bytes perfectly well, they
//! just cannot stage a file.
//!
//! The read path's invariants carry over unchanged. Every hub failure
//! degrades to `inner.materialize`, whose own answer — including
//! `Unsupported` — is the honest one when neither the hub nor the inner
//! layer can produce a path. Cancellation is the one thing that never
//! degrades: a cancelled caller gets `Cancelled`, because falling through
//! would answer someone who is gone with `Unsupported`. And a path is only
//! ever handed back under a live lease: an unleased entry can be evicted
//! out from under the caller between this answer and their `open`.

use std::path::Path;
use std::time::Instant;

use futures::StreamExt as _;
use md5::{Digest as _, Md5};
use ovstorage_hub_client::{HubKey, ReadOpen, hub_key};
use ovstorage_plugin::*;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::debug;

use crate::HubCacheWrapper;
use crate::metrics::{self, AbortReason, BypassReason, MissReason, Op, Outcome};
use crate::read::{
    FillStart, FillTicket, ProbeOutcome, StagedFill, ValidatorProbe, cancelled_error,
    fill_from_bytes, race_hub, scaled_deadline,
};

/// What a fill left behind, and so what answers the caller.
enum Filled {
    /// The entry is committed and can be served under a fresh lease.
    Committed,
    /// Nothing was committed, but `inner` answered with a delegate that
    /// stands on its own.
    Delegate(Box<LocalDelegate>),
    /// Nothing local exists; only `inner.materialize` can answer.
    Uncached,
}

impl HubCacheWrapper {
    /// Serves `materialize` through the hub: bypass, validator probe, hub
    /// lookup, and on a miss a fill that becomes the answer.
    pub(crate) async fn materialize_impl(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let start = Instant::now();
        // The read path's bypasses, for the read path's reasons: hub
        // entries are principal-agnostic (hub has no auth), and a cached
        // whole object answers for neither a precondition nor a range.
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            metrics::observe(
                Op::Materialize,
                Outcome::Bypass(BypassReason::Credential),
                start,
            );
            return self.inner.materialize(request, cancel).await;
        }
        if request.input.options.if_match.is_some() || request.input.options.range.is_some() {
            metrics::observe(
                Op::Materialize,
                Outcome::Bypass(BypassReason::Conditional),
                start,
            );
            return self.inner.materialize(request, cancel).await;
        }
        // A hub in its failure cooldown cannot answer; skip the validator
        // stat rather than tax the backend for the hub's sake, exactly as
        // the read path does.
        if self.client.unavailable() {
            metrics::observe(
                Op::Materialize,
                Outcome::Bypass(BypassReason::HubUnavailable),
                start,
            );
            return self.inner.materialize(request, cancel).await;
        }
        let address = request.input.address.clone();

        // Validator-keyed lookup, exactly as `read` derives it: no etag
        // means no entry may be trusted or created, and a changed etag
        // names a key no fill has ever written.
        let probe = match self
            .probe_validator(&request.extensions, &address, cancel.clone())
            .await?
        {
            ProbeOutcome::Validated(probe) => probe,
            ProbeOutcome::NoValidator => {
                metrics::observe(
                    Op::Materialize,
                    Outcome::Bypass(BypassReason::NoValidator),
                    start,
                );
                return self.inner.materialize(request, cancel).await;
            }
            ProbeOutcome::StatError => {
                metrics::observe(
                    Op::Materialize,
                    Outcome::Bypass(BypassReason::StatError),
                    start,
                );
                return self.inner.materialize(request, cancel).await;
            }
        };
        let Some(key) = hub_key(
            self.key_scheme,
            &self.partition,
            &address,
            &probe.etag,
            probe.info.checksums.get(&ChecksumAlgorithm::md5()),
        ) else {
            metrics::observe(Op::Materialize, Outcome::Bypass(BypassReason::NoKey), start);
            return self.inner.materialize(request, cancel).await;
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
                    .serve_leased(handle, &probe, key.digest.as_deref(), cancel.as_ref())
                    .await;
                // The serve paid filesystem waits the token may have fired
                // during — including one that made the entry look unusable,
                // which must not degrade into the inner layer's answer. A
                // cancelled caller gets the truth on either branch, and
                // dropping an unreturned delegate releases its lease.
                if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
                    return Err(cancelled_error());
                }
                if let Some(delegate) = served {
                    metrics::observe(Op::Materialize, Outcome::Hit, start);
                    return Ok(delegate);
                }
                // The entry answered but cannot be served: its file does not
                // exist (the extension trap), or its length or content
                // contradicts the identity the key claims. The key is
                // taken, so a refill would only collect ALREADY_EXISTS:
                // this is a miss that cannot be filled.
                metrics::observe(
                    Op::Materialize,
                    Outcome::Miss(MissReason::EntryUnusable),
                    start,
                );
                return self.inner.materialize(request, cancel).await;
            }
            // Another client is writing this key: nothing to serve and
            // nothing to fill, and no retry loop — the protocol's timeout
            // is a server-side no-op, so waiting cannot help.
            Ok(ReadOpen::PendingWrite) => {
                metrics::observe(
                    Op::Materialize,
                    Outcome::Miss(MissReason::PendingWrite),
                    start,
                );
                return self.inner.materialize(request, cancel).await;
            }
            Ok(ReadOpen::NotCached) => {
                metrics::observe(Op::Materialize, Outcome::Miss(MissReason::NotCached), start);
            }
            Err(error) => {
                debug!(
                    address = %redact_url(&address),
                    %error,
                    "hub open-for-read failed; materializing through the inner layer"
                );
                metrics::observe(
                    Op::Materialize,
                    Outcome::Bypass(BypassReason::HubUnavailable),
                    start,
                );
                return self.inner.materialize(request, cancel).await;
            }
        }

        // Miss: reserve the entry BEFORE the body is fetched (cross-process
        // fill dedupe), then make the fill the answer.
        let mut ticket = match self
            .begin_fill(Op::Materialize, &address, &probe, &key, cancel.as_ref())
            .await
        {
            FillStart::Begun(ticket) => ticket,
            // Another client committed this key between this request's
            // read-open and its write-open. One re-probe serves the entry
            // the racer just published — the answer the caller wanted —
            // where falling straight back would surface
            // `inner.materialize`'s own answer (often `Unsupported`) with a
            // servable entry sitting in the hub.
            FillStart::AlreadyCommitted => {
                // The racer's entry is a foreign fill, so a digest key is
                // proven against it exactly as on any other hit.
                return match self
                    .serve_committed(&key, &probe, key.digest.as_deref(), cancel.as_ref())
                    .await?
                {
                    Some(delegate) => Ok(delegate),
                    None => self.inner.materialize(request, cancel).await,
                };
            }
            FillStart::Skipped => return self.inner.materialize(request, cancel).await,
        };
        let filled = match self.inner.read(request.clone(), cancel.clone()).await {
            Ok(result) => self.stage(result, &probe, ticket, cancel.as_ref()).await?,
            // Cancellation is terminal: the caller is gone, so the honest
            // answer is `Cancelled`, not whatever `inner.materialize` would
            // tell nobody.
            Err(error) if error.code() == ErrorCode::Cancelled => {
                ticket.record_abandoned(AbortReason::Cancelled);
                return Err(error);
            }
            // The caller asked to materialize, so the answer — this error
            // included — is `inner.materialize`'s to give; the read was
            // this layer's fill mechanism, not the caller's request.
            Err(_) => {
                ticket
                    .abort_for(AbortReason::InnerError, cancel.as_ref())
                    .await;
                Filled::Uncached
            }
        };
        // Staging can span the whole body, so the token may have fired
        // anywhere inside it. Every outcome then answers `Cancelled`; the
        // cache keeps whatever the fill honestly earned — a committed body
        // stays committed for the next caller.
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Err(cancelled_error());
        }
        match filled {
            // No digest re-proof here: the entry being reopened is this
            // request's own fill, proven byte-by-byte as it was staged, and
            // a committed key cannot be rewritten.
            Filled::Committed => match self
                .serve_committed(&key, &probe, None, cancel.as_ref())
                .await?
            {
                Some(delegate) => Ok(delegate),
                None => self.inner.materialize(request, cancel).await,
            },
            Filled::Delegate(delegate) => Ok(*delegate),
            Filled::Uncached => self.inner.materialize(request, cancel).await,
        }
    }

    /// Stages the inner read's answer into the reserved entry.
    ///
    /// Every route commits only under the answer's own validator and the
    /// reserved size: bytes whose read reports a different (or no) etag
    /// belong to another version than the key names, and committing them
    /// would let a later revert to this etag serve the wrong body. A key
    /// that names a digest additionally has the staged bytes proven against
    /// it. Anything that does not commit discards the reservation rather
    /// than leaving it pending for the next reader to trip over; a
    /// cancelled drain propagates `Cancelled` instead of answering at all.
    async fn stage(
        &self,
        result: ReadResult,
        probe: &ValidatorProbe,
        mut ticket: FillTicket,
        cancel: Option<&CancellationToken>,
    ) -> Result<Filled> {
        // The token may have fired while the inner read produced this
        // result — a buffered or delegate answer arrives whole, with no
        // chunk boundary for the drain's race to observe. A cancelled
        // caller gets `Cancelled` before any staging is paid for.
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            ticket.record_abandoned(AbortReason::Cancelled);
            return Err(cancelled_error());
        }
        match result {
            ReadResult::Bytes { bytes, info } => {
                if !proves(&info, probe) {
                    ticket.abort_for(AbortReason::ValidatorDrift, cancel).await;
                } else if bytes.len() as u64 != ticket.expected {
                    ticket.abort_for(AbortReason::SizeMismatch, cancel).await;
                } else if fill_from_bytes(ticket, &bytes, cancel).await {
                    return Ok(Filled::Committed);
                }
                Ok(Filled::Uncached)
            }
            ReadResult::Stream { stream, info } => {
                if !proves(&info, probe) {
                    ticket.abort_for(AbortReason::ValidatorDrift, cancel).await;
                    return Ok(Filled::Uncached);
                }
                if drain_into_hub(stream, ticket, cancel).await? {
                    Ok(Filled::Committed)
                } else {
                    Ok(Filled::Uncached)
                }
            }
            // An inner layer that stages its own file already answers the
            // caller. Copying it in costs one pass over a local file and
            // spares every later reader the fetch.
            ReadResult::LocalDelegate(local) => {
                if !proves(&local.info, probe) {
                    ticket.abort_for(AbortReason::ValidatorDrift, cancel).await;
                } else if file_len(&local.path, &ticket, cancel).await != Some(ticket.expected) {
                    // A cancelled metadata wait also lands here (the length
                    // comes back unknown); the departed caller must not
                    // wait on the release acknowledgement either.
                    if cancel.is_some_and(CancellationToken::is_cancelled) {
                        ticket.record_abandoned(AbortReason::Cancelled);
                    } else {
                        ticket.abort_for(AbortReason::SizeMismatch, cancel).await;
                    }
                } else {
                    // The budget covers the copy plus the stability
                    // re-read, both of which move `expected` bytes.
                    let copied = ticket
                        .fs
                        .run(
                            scaled_deadline(ticket.io_timeout, ticket.expected.saturating_mul(2)),
                            cancel,
                            copy_hash_sync(
                                local.path.clone(),
                                ticket.path().to_path_buf(),
                                cancel.cloned(),
                            ),
                        )
                        .await;
                    match copied {
                        // The copy observes the token between chunks, and
                        // the wait itself races it, so a cancelled caller
                        // does not wait out a size-scaled copy of a large
                        // body — stalled or healthy.
                        Err(_) if cancel.is_some_and(CancellationToken::is_cancelled) => {
                            ticket.record_abandoned(AbortReason::Cancelled);
                        }
                        Err(_) => ticket.abort_for(AbortReason::StagingError, cancel).await,
                        // The pre-copy length check above cannot vouch for
                        // the bytes the copy actually read; only the copy's
                        // own count can, exactly as the streamed settle
                        // re-checks `written`.
                        Ok((copied, _)) if copied != ticket.expected => {
                            ticket.abort_for(AbortReason::SizeMismatch, cancel).await;
                        }
                        // Proven against what was actually copied, not what
                        // the source claimed: a digest key answers any URL
                        // whose stat reports the digest, so the wrong bytes
                        // under it poison more than this one address.
                        Ok((_, hash))
                            if ticket
                                .digest
                                .as_deref()
                                .is_some_and(|expected| hash[..] != *expected) =>
                        {
                            ticket.abort_for(AbortReason::DigestMismatch, cancel).await;
                        }
                        Ok(_) => {
                            if ticket.commit().await {
                                return Ok(Filled::Committed);
                            }
                        }
                    }
                }
                Ok(Filled::Delegate(Box::new(local)))
            }
            // A redirect's bytes never transit this layer and it names no
            // local file, so there is nothing to stage and nothing to
            // answer with.
            ReadResult::Redirect(_) => {
                ticket.abort_for(AbortReason::BodyShape, cancel).await;
                Ok(Filled::Uncached)
            }
        }
    }

    /// Takes the serving lease on a just-committed entry.
    ///
    /// The fill's write handle is spent by its commit, so the entry is
    /// opened again for reading: handing back a path without a lease would
    /// let the hub evict the file between this answer and the caller's
    /// `open`. An entry already collected, a racing writer, or a hub that
    /// went away in between all answer `Ok(None)`, and nothing is retried —
    /// `inner.materialize` is the fallback for all three.
    ///
    /// The reopen is raced against the caller's token and the answer is
    /// gated on it: a caller that cancelled while the entry was reopened
    /// gets `Cancelled`, and dropping the unreturned delegate releases its
    /// lease. `digest` is proven exactly as on any hit; the one caller that
    /// passes `None` is the just-committed own fill, whose bytes were
    /// proven as they were staged.
    async fn serve_committed(
        &self,
        key: &HubKey,
        probe: &ValidatorProbe,
        digest: Option<&[u8]>,
        cancel: Option<&CancellationToken>,
    ) -> Result<Option<LocalDelegate>> {
        let opened = race_hub(
            cancel,
            self.client
                .open_for_read(&key.key, &key.provider, &key.extension),
        )
        .await?;
        let served = match opened {
            Ok(ReadOpen::Opened(handle)) => self.serve_leased(handle, probe, digest, cancel).await,
            Ok(ReadOpen::NotCached | ReadOpen::PendingWrite) | Err(_) => None,
        };
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(cancelled_error());
        }
        Ok(served)
    }
}

/// Whether `info` reports the very validator the entry is keyed under,
/// still declared strong.
fn proves(info: &ObjectInfo, probe: &ValidatorProbe) -> bool {
    crate::read::proves_validator(info, &probe.etag)
}

/// Drains the inner body into the reserved entry chunk by chunk and
/// commits, reporting whether the entry became visible.
///
/// Unlike the read path's tee there is no downstream consumer to forward
/// to — `materialize` answers with a path, not a body — but the streaming
/// invariant is the same one: only the chunk in hand is ever in memory,
/// however large the object.
///
/// Cancellation is raced against the stream itself, so a body that stops
/// yielding cannot outwait a caller who already gave up — and it is
/// terminal: a cancelled caller gets `Cancelled`, not whatever
/// `inner.materialize` would tell someone who is gone.
async fn drain_into_hub(
    stream: ReadStream,
    ticket: FillTicket,
    cancel: Option<&CancellationToken>,
) -> Result<bool> {
    let mut fill = StagedFill::new(stream, ticket, cancel.cloned());
    loop {
        // `None` marks cancellation; the checked-first bias makes an
        // already-cancelled caller observe it before any chunk is awaited.
        let polled = match cancel {
            Some(token) => tokio::select! {
                biased;
                _ = token.cancelled() => None,
                next = fill.stream.next() => Some(next),
            },
            None => Some(fill.stream.next().await),
        };
        let Some(next) = polled else {
            fill.ticket.record_abandoned(AbortReason::Cancelled);
            return Err(cancelled_error());
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                fill.ticket
                    .abort_for(AbortReason::StreamError, cancel)
                    .await;
                return Ok(false);
            }
        };
        // A body longer than the declared size can never commit; stop
        // staging rather than spool bytes the end-of-body check would
        // discard anyway.
        if fill.overflows(&chunk) {
            fill.ticket
                .abort_for(AbortReason::SizeMismatch, cancel)
                .await;
            return Ok(false);
        }
        if fill.stage_chunk(chunk).await.is_err() {
            // The staging wait itself races the token, so a failure may be
            // the caller leaving rather than the filesystem misbehaving.
            if cancel.is_some_and(CancellationToken::is_cancelled) {
                fill.ticket.record_abandoned(AbortReason::Cancelled);
                return Err(cancelled_error());
            }
            fill.ticket
                .abort_for(AbortReason::StagingError, cancel)
                .await;
            return Ok(false);
        }
    }
    // The body ended, but the settle still pays a size-scaled sync; a token
    // that fired by now discards the fill instead of waiting it out.
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        fill.ticket.record_abandoned(AbortReason::Cancelled);
        return Err(cancelled_error());
    }
    Ok(fill.settle().await)
}

/// The length of `path` within the ticket's filesystem budget, or `None`
/// when it cannot be measured in time.
async fn file_len(
    path: &Path,
    ticket: &FillTicket,
    cancel: Option<&CancellationToken>,
) -> Option<u64> {
    ticket
        .fs
        .run(
            ticket.io_timeout,
            cancel,
            tokio::fs::metadata(path.to_path_buf()),
        )
        .await
        .ok()
        .map(|meta| meta.len())
}

/// Copies a staged file into the reserved entry chunk by chunk and syncs it
/// before the commit makes it visible, so a crash cannot publish a torn
/// body that would then be served forever (hub validates nothing after a
/// commit). Returns the byte count actually copied — the pre-copy length
/// check cannot vouch for it — together with the md5 of the copied bytes,
/// for the digest proof when the key names one.
///
/// Two integrity checks bracket the copy, and both anchor on the open file
/// handle rather than the path, so an atomic replace-over of the path
/// neither confuses them nor fails a copy whose inode still holds the
/// proven version's bytes.
///
/// * The handle's length and modification time must be unchanged across
///   the copy. This is what catches a mutation confined to bytes the copy
///   had **not yet reached**: the copy then reads post-mutation bytes
///   there, producing a clean copy of a version other than the one the
///   caller proved — self-consistent, so no hash of the copy itself can
///   reveal it.
/// * The handle is then rewound and re-hashed against the copy's hash.
///   This is what catches a mutation **behind** the cursor — a torn copy
///   matching no version — even when it lands inside the timestamps'
///   granularity, where the first check is blind.
///
/// The residue is a mutation confined ahead of the cursor that preserves
/// the length and leaves the modification time unchanged (inside the
/// clock's granularity, or bypassing it the way an unflushed mmap write
/// can): a clean copy of the wrong version, indistinguishable here. Both
/// checks fail conservatively — a legitimate rewrite mid-copy discards a
/// fill (availability), never commits one. The token — owned, because this
/// future runs as its own task (see `FsHealth::run`) — is observed between
/// chunks of both passes, so a cancelled caller never waits out
/// size-scaled work.
async fn copy_hash_sync(
    from: std::path::PathBuf,
    to: std::path::PathBuf,
    cancel: Option<CancellationToken>,
) -> std::io::Result<(u64, [u8; 16])> {
    let cancelled = || {
        std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "the caller cancelled mid-copy",
        )
    };
    let changed = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the source changed while it was being copied",
        )
    };
    let mut source = tokio::fs::File::open(&from).await?;
    let before = source.metadata().await?;
    let mut target = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)
        .await?;
    let mut hasher = Md5::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0u8; 512 * 1024];
    loop {
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Err(cancelled());
        }
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        copied += read as u64;
        target.write_all(&buffer[..read]).await?;
    }
    target.sync_all().await?;
    let hash: [u8; 16] = hasher.finalize().into();

    let after = source.metadata().await?;
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return Err(changed());
    }
    source.seek(std::io::SeekFrom::Start(0)).await?;
    let mut verify = Md5::new();
    loop {
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Err(cancelled());
        }
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        verify.update(&buffer[..read]);
    }
    if verify.finalize()[..] != hash {
        return Err(changed());
    }
    Ok((copied, hash))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use ovstorage_hub_client::fake::EntryState;
    use ovstorage_hub_client::{HubCacheClient, HubClientConfig, KeyScheme, WriteOpen, hub_key};

    use super::*;
    use crate::testing::{
        ADDRESS, CONTENT, ETAG, MaterializeAnswer, collect, expected_key, fixture, read_request,
    };

    #[tokio::test]
    async fn a_fill_race_lost_to_a_committed_entry_serves_it_after_one_reprobe() {
        let fx = fixture(|_| {}).await;
        fx.hub.seed_entry(&expected_key(), "bin", CONTENT);
        // The cross-process ordering: this request's read-open answered
        // not-cached, then the racer committed before this write-open.
        fx.hub.answer_not_cached_once(&expected_key());

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the racer's committed entry answers");
        assert!(
            delegate.guard.is_some(),
            "the entry is served under a live lease"
        );
        assert_eq!(
            tokio::fs::read(&delegate.path)
                .await
                .expect("the hub file reads"),
            CONTENT
        );
        assert_eq!(
            fx.probe.materializes.load(Ordering::SeqCst),
            0,
            "the hub, not the inner layer, answers the race loser"
        );
        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// Stages `CONTENT` in its own directory, standing in for a file the
    /// inner layer produced. Returns the directory (held for its `Drop`)
    /// and the file's path.
    async fn staged_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("staged.usd");
        tokio::fs::write(&path, CONTENT).await.expect("stages");
        (dir, path)
    }

    #[tokio::test]
    async fn a_miss_fills_from_a_buffered_read_and_serves_the_leased_hub_path() {
        let fx = fixture(|_| {}).await;

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the fill answers");
        assert!(
            delegate.path.starts_with(fx.hub.cache_dir()),
            "the answer is the hub's own copy: {}",
            delegate.path.display()
        );
        assert!(delegate.guard.is_some(), "the lease travels as the guard");
        assert_eq!(
            tokio::fs::read(&delegate.path).await.expect("reads"),
            CONTENT
        );
        assert_eq!(delegate.info.size, Some(CONTENT.len() as u64));
        assert_eq!(delegate.info.etag.as_deref(), Some(ETAG));
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.probe.materializes.load(Ordering::SeqCst),
            0,
            "the hub fill is the answer, not the inner layer"
        );
        assert_eq!(
            fx.hub.committed_bytes(&expected_key()).as_deref(),
            Some(CONTENT)
        );

        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_miss_fills_from_a_streamed_read_without_buffering_the_body() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the streamed fill answers");
        assert!(delegate.path.starts_with(fx.hub.cache_dir()));
        assert!(delegate.guard.is_some());
        assert_eq!(
            tokio::fs::read(&delegate.path).await.expect("reads"),
            CONTENT
        );
        assert_eq!(
            fx.hub.committed_bytes(&expected_key()).as_deref(),
            Some(CONTENT)
        );
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);

        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_hit_serves_the_hub_file_without_touching_the_inner_body() {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        fx.wrapper.client.quiesce().await;
        assert!(matches!(
            fx.hub.entry(&expected_key()),
            Some(EntryState::Committed { .. })
        ));

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the hit answers");
        assert_eq!(
            tokio::fs::read(&delegate.path).await.expect("reads"),
            CONTENT
        );
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            1,
            "a hit must not re-read the inner layer"
        );
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            1,
            "a hit never reserves anything"
        );

        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn dropping_the_delegate_releases_the_lease() {
        let fx = fixture(|_| {}).await;

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the fill answers");
        assert!(fx.hub.open_handles() > 0, "the served entry is pinned");
        drop(delegate);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_inner_delegate_answer_is_copied_into_the_hub_and_still_answers() {
        let fx = fixture(|_| {}).await;
        let (_staging, staged) = staged_file().await;
        *fx.probe.read_delegate.lock().unwrap() = Some(staged);

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the staged file answers");
        assert_eq!(
            tokio::fs::read(&delegate.path).await.expect("reads"),
            CONTENT
        );
        fx.wrapper.client.quiesce().await;
        assert_eq!(
            fx.hub.committed_bytes(&expected_key()).as_deref(),
            Some(CONTENT),
            "the staged copy is cached for the next reader"
        );
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);

        drop(delegate);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_inner_delegate_that_contradicts_the_validator_answers_unfilled() {
        let fx = fixture(|_| {}).await;
        let (_staging, staged) = staged_file().await;
        *fx.probe.read_delegate.lock().unwrap() = Some(staged.clone());
        *fx.probe.read_etag.lock().unwrap() = Some("v2".to_string());

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the inner delegate still answers");
        assert_eq!(delegate.path, staged);
        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the drifted fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
    }

    /// The delegate-copy variant of the digest proof: the key names the
    /// digest the stat claimed, the staged file carries other bytes, and
    /// the copy's own hash — not the source's claim — decides the commit.
    #[tokio::test]
    async fn an_inner_delegate_that_does_not_carry_the_keys_digest_answers_unfilled() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let (_staging, staged) = staged_file().await;
        *fx.probe.read_delegate.lock().unwrap() = Some(staged.clone());
        let claimed = Md5::digest(b"a body the source no longer has").to_vec();
        *fx.probe.md5.lock().unwrap() = Some(claimed.clone());

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the inner delegate still answers");
        assert_eq!(delegate.path, staged);

        let key = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &Url::parse(ADDRESS).unwrap(),
            ETAG,
            Some(&claimed),
        )
        .expect("the digest keys")
        .key;
        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&key), None, "the unproven copy is discarded");
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_hub_that_is_down_falls_back_to_the_inner_materialize() {
        let fx = fixture(|_| {}).await;
        let (_staging, staged) = staged_file().await;
        *fx.probe.materialize_answer.lock().unwrap() = MaterializeAnswer::Staged(staged.clone());
        fx.hub.shutdown();

        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the inner layer answers");
        assert_eq!(delegate.path, staged);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_hub_that_is_down_propagates_an_unsupported_inner_materialize() {
        let fx = fixture(|_| {}).await;
        fx.hub.shutdown();

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("neither the hub nor the inner layer can produce a path");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_extension_trap_falls_back_without_refilling() {
        let fx = fixture(|_| {}).await;
        // The entry exists under the key this request derives, but was
        // written with a different extension, so the path the hub answers
        // with does not exist.
        fx.hub.seed_entry(&expected_key(), "usd", CONTENT);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the inner layer's answer propagates");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            0,
            "a taken key is never refilled"
        );
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 0);

        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_pending_write_falls_back_without_a_fill() {
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

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the inner layer's answer propagates");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);
        assert_eq!(
            fx.hub.counters().opens_for_write,
            1,
            "a pending key is not refilled"
        );
        pending.abort().await;
    }

    #[tokio::test]
    async fn a_validator_that_drifts_mid_flight_aborts_the_fill_and_falls_back() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_etag.lock().unwrap() = Some("v2".to_string());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("nothing was cached, so the inner layer answers");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.reads.load(Ordering::SeqCst), 1);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);

        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the drifted fill is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn an_oversized_object_falls_back_without_reserving() {
        let fx = fixture(|config| {
            config.insert(
                "max_object_bytes".to_string(),
                ConfigValue::Int(CONTENT.len() as i64 - 1),
            );
        })
        .await;

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the inner layer's answer propagates");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
        assert_eq!(
            fx.probe.reads.load(Ordering::SeqCst),
            0,
            "a fill that cannot happen is not attempted"
        );
    }

    #[tokio::test]
    async fn bypasses_go_straight_to_the_inner_materialize() {
        let fx = fixture(|_| {}).await;

        let mut conditional = read_request(ADDRESS);
        conditional.input.options.if_match = Some(ETAG.to_string());
        let _ = fx.wrapper.materialize(conditional, None).await;

        let mut ranged = read_request(ADDRESS);
        ranged.input.options.range = Some(ByteRange {
            start: 0,
            end_inclusive: Some(3),
        });
        let _ = fx.wrapper.materialize(ranged, None).await;

        let mut credentialed = read_request(ADDRESS);
        credentialed
            .extensions
            .insert(ext::RESOLVED_OAUTH_CREDENTIAL.to_string(), vec![1]);
        let _ = fx.wrapper.materialize(credentialed, None).await;

        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 3);
        assert_eq!(
            fx.probe.stats.load(Ordering::SeqCst),
            0,
            "a bypass must not pay the validator stat"
        );
        assert_eq!(fx.hub.counters().opens_for_read, 0);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn an_etagless_object_falls_back_without_touching_the_hub() {
        let fx = fixture(|_| {}).await;
        *fx.probe.etag.lock().unwrap() = None;

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the inner layer's answer propagates");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.hub.counters().opens_for_read, 0);
        assert_eq!(fx.hub.counters().opens_for_write, 0);
    }

    #[tokio::test]
    async fn stat_not_found_propagates_without_materializing() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stat_error.lock().unwrap() = Some(ErrorCode::NotFound);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("an absent object is absent");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_inner_read_error_while_a_fill_ticket_is_held_falls_back_and_discards() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_error.lock().unwrap() = Some(ErrorCode::Transient);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the fallback inner materialize is Unsupported");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_mid_stream_error_during_the_materialize_drain_falls_back_and_discards() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        *fx.probe.stream_error_after.lock().unwrap() = Some(2);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the drain's error falls back to the inner materialize");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn cancellation_during_the_materialize_drain_is_terminal() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        // The token cancels as the inner body starts flowing, so the raced
        // hub lookups have already passed and the drain itself is what
        // observes it.
        let token = CancellationToken::new();
        *fx.probe.cancel_on_read.lock().unwrap() = Some(token.clone());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), Some(token))
            .await
            .expect_err("a cancelled drain is cancelled");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            fx.probe.materializes.load(Ordering::SeqCst),
            0,
            "a cancelled caller is never answered by the inner materialize"
        );

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn cancellation_while_the_drain_awaits_a_chunk_is_prompt_and_terminal() {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);
        // One chunk arrives, then the body stops yielding — and the caller
        // gives up exactly there. The drain must observe the token while
        // `next()` is pending, not wait for a chunk that never comes.
        *fx.probe.stall_after.lock().unwrap() = Some(1);
        let token = CancellationToken::new();
        *fx.probe.cancel_on_stall.lock().unwrap() = Some(token.clone());

        let error = tokio::time::timeout(
            Duration::from_secs(10),
            fx.wrapper.materialize(read_request(ADDRESS), Some(token)),
        )
        .await
        .expect("cancellation interrupts the stalled body promptly")
        .expect_err("a cancelled drain is cancelled");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_cancelled_inner_read_during_a_fill_is_terminal() {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_error.lock().unwrap() = Some(ErrorCode::Cancelled);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the cancellation propagates");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            fx.probe.materializes.load(Ordering::SeqCst),
            0,
            "a cancelled caller is never answered by the inner materialize"
        );

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    /// A foreign digest entry (omni.client passes `Content-MD5` through
    /// unverified) whose bytes do not carry the claimed digest is unusable:
    /// the caller gets the inner layer's answer, never the wrong body.
    #[tokio::test]
    async fn a_foreign_digest_entry_whose_bytes_do_not_match_its_key_falls_back() {
        let fx = fixture(|config| {
            config.insert(
                "key_scheme".to_string(),
                ConfigValue::String("omni-client-compat".to_string()),
            );
        })
        .await;
        let claimed = Md5::digest(CONTENT).to_vec();
        *fx.probe.md5.lock().unwrap() = Some(claimed.clone());
        let wrong: Vec<u8> = CONTENT.iter().map(|byte| byte.wrapping_add(1)).collect();
        let key = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &Url::parse(ADDRESS).unwrap(),
            ETAG,
            Some(&claimed),
        )
        .expect("the digest keys")
        .key;
        fx.hub.seed_entry(&key, "usd", &wrong);

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("the poisoned entry is never served");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// A caller whose token fired while the validator probe was in flight
    /// never receives a hit: every stage after the stat sees the token, and
    /// the taken lease is released rather than returned.
    #[tokio::test]
    async fn a_hit_is_never_served_to_a_caller_that_already_cancelled() {
        let fx = fixture(|_| {}).await;
        fx.hub.seed_entry(&expected_key(), "bin", CONTENT);
        let token = CancellationToken::new();
        *fx.probe.cancel_on_stat.lock().unwrap() = Some(token.clone());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), Some(token))
            .await
            .expect_err("a cancelled caller is answered with the truth");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The delegate copy observes the token between chunks rather than
    /// running its size-scaled entirety for a caller who already left.
    #[tokio::test]
    async fn a_cancelled_copy_is_interrupted_between_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("from.bin");
        tokio::fs::write(&from, CONTENT).await.expect("stages");
        let token = CancellationToken::new();
        token.cancel();

        let err = copy_hash_sync(from, dir.path().join("to.bin"), Some(token))
            .await
            .expect_err("a cancelled copy is interrupted");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
    }

    /// The copy reports what it actually moved: the byte count the commit
    /// decision re-checks against the reservation, and the digest of those
    /// same bytes — pinned against an independently computed reference.
    #[tokio::test]
    async fn the_copy_reports_the_count_and_digest_of_the_bytes_it_moved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("from.bin");
        tokio::fs::write(&from, CONTENT).await.expect("stages");
        let to = dir.path().join("to.bin");

        let (copied, hash) = copy_hash_sync(from, to.clone(), None)
            .await
            .expect("a stable source copies");
        assert_eq!(copied, CONTENT.len() as u64);
        assert_eq!(hash[..], Md5::digest(CONTENT)[..]);
        assert_eq!(tokio::fs::read(&to).await.expect("the copy reads"), CONTENT);
    }

    /// A buffered body arrives whole: there is no chunk boundary for the
    /// drain's race to observe, so the staging gate is what has to see the
    /// token that fired while the inner read produced it.
    #[tokio::test]
    async fn a_cancellation_arriving_with_a_buffered_body_is_terminal() {
        let fx = fixture(|_| {}).await;
        let token = CancellationToken::new();
        *fx.probe.cancel_on_read.lock().unwrap() = Some(token.clone());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), Some(token))
            .await
            .expect_err("a cancelled caller is answered with the truth");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            fx.probe.materializes.load(Ordering::SeqCst),
            0,
            "a cancelled caller is never answered by the inner materialize"
        );

        fx.wrapper.client.quiesce().await;
        assert_eq!(
            fx.hub.entry(&expected_key()),
            None,
            "nothing is staged for a cancelled caller"
        );
        fx.hub.wait_for_open_handles(0).await;
    }

    /// The same gate covers a delegate answer, which also arrives whole.
    #[tokio::test]
    async fn a_cancellation_arriving_with_an_inner_delegate_is_terminal() {
        let fx = fixture(|_| {}).await;
        let (_staging, staged) = staged_file().await;
        *fx.probe.read_delegate.lock().unwrap() = Some(staged);
        let token = CancellationToken::new();
        *fx.probe.cancel_on_read.lock().unwrap() = Some(token.clone());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), Some(token))
            .await
            .expect_err("a cancelled caller is answered with the truth");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 0);

        fx.wrapper.client.quiesce().await;
        assert_eq!(fx.hub.entry(&expected_key()), None);
        fx.hub.wait_for_open_handles(0).await;
    }

    #[tokio::test]
    async fn a_refused_commit_falls_back_and_the_key_is_orphaned_pending() {
        let fx = fixture(|_| {}).await;
        fx.hub.refuse_next_close(&expected_key());

        let error = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect_err("an uncommitted entry is never served as the answer");
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(fx.probe.materializes.load(Ordering::SeqCst), 1);

        // The hub consumes the handle before attempting the close, so the
        // refused commit orphans the reservation: the key stays pending
        // hub-side and later requests for it fall back — availability,
        // never a served uncommitted path.
        fx.wrapper.client.quiesce().await;
        fx.hub.wait_for_open_handles(0).await;
        assert_eq!(
            fx.hub.entry(&expected_key()),
            Some(ovstorage_hub_client::fake::EntryState::PendingWrite)
        );
    }
}
