// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `CopyRenameFallbackWrapper` composes **above** the `Router`; delegates
//! `copy`/`rename` to inner and, when inner will not perform the operation,
//! falls back to read-source plus write-destination, with `delete`-source for
//! `rename`.
//!
//! ## Fallback trigger
//!
//! The wrapper emulates whenever the layer below declines the operation,
//! independent of the roots involved. Two signals mean "declined":
//!
//! - The source root reports `supports_copy` / `supports_rename` as `false`,
//!   in which case inner is never asked. The gate is availability, not
//!   `supports_server_side_*`: a backend that performs the operation itself
//!   without the bytes staying on the server must still be asked.
//! - Inner answers `Unsupported`, which is the SPI's single marker for "this
//!   layer does not perform this operation" — the roots differ, the backend
//!   has no copy, or it declines the request's preconditions. The fallback
//!   serves all of these, carrying the caller's `if_source` onto the read and
//!   `if_dest` onto the write, so a backend that refuses a *conditional* copy
//!   still yields one. A policy refusal is `PermissionDenied` and propagates.
//!
//! Root topology is not part of the trigger: whether the two addresses share a
//! root says nothing about whether the layer below can perform the operation,
//! so the same `copy` succeeds or fails on capability alone.
//!
//! ## Composition requirement: below any address-rewriting layer
//!
//! This layer must compose **below** `alias` and any other layer that rewrites
//! addresses, which is where all four shipped configurations place it
//! (`alias.inner = copy_rename_fallback`). The emulation refuses to run when
//! source and destination name one object, and that check compares the
//! addresses as they arrive: there is no address-resolution slot in the SPI, so
//! a rewriting layer *below* this one could collapse two distinct caller
//! addresses onto one object after the check has passed. The emulation would
//! then write the object onto itself and — for `rename` — delete the only copy.
//!
//! ## Lossy fallback semantics (documented)
//!
//! The fallback does not preserve native-copy metadata or checksums, and for
//! `rename` deletes the source (with the caller's `if_source` precondition)
//! only after the destination write succeeds.
//!
//! ## Destination write slot
//!
//! The fallback selects the destination slot **before** reading the source:
//!
//! - A `write_stream`-capable destination root receives the body on
//!   `write_stream`, chunk by chunk — a `ReadResult::Stream` source is bridged
//!   async→sync through a bounded channel drained by a spawned task
//!   ([`body_stream_from_read_stream`]) and a `LocalDelegate` source is
//!   streamed from its file, so neither is held whole. A source the layer
//!   below already materialized (`ReadResult::Bytes`) rides the write as a
//!   single chunk, holding the whole object — but that allocation is the
//!   backend's, and a plain `read` of the same object makes it too.
//! - A `write`-only destination root uses the buffered path:
//!   `Body::Bytes` needs the whole object in host memory. When neither slot
//!   resolves, `write` is attempted and the backend's own typed error
//!   surfaces, per the capability self-gate contract.
//!
//! Preconditions and the caller's request extensions ride both slots.
//!
//! ## Buffered-transfer memory cap
//!
//! Because a `write`-only destination cannot stream, the buffered path is the
//! one slot whose host memory scales with object size (~object-size resident
//! per transfer; N concurrent transfers are N × object-size). The optional
//! [`MAX_BUFFERED_TRANSFER_BYTES`] `LayerConfig` key bounds it: a source larger
//! than the cap surfaces `ResourceExhausted` instead of OOMing the host,
//! refusing up front when the source's size is known (`ObjectInfo.size`) and
//! enforcing the running total chunk by chunk when it is not. The cap is
//! opt-in (absent → uncapped); streamed `write_stream`
//! transfers are bounded by chunk size × channel capacity regardless and are
//! never gated by it.

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt as _;

use super::config_u64;
use crate::layers::{COPY_RENAME_FALLBACK_KIND, descriptor};
use crate::*;

/// [`LayerConfig`] key bounding host memory for a buffered transfer
/// to a `write`-only destination. A non-negative integer byte cap;
/// absent (the default) leaves buffered transfers uncapped. Streamed transfers to `write_stream`-capable destinations are
/// bounded by chunk size × channel capacity regardless and are never gated by
/// this cap.
pub const MAX_BUFFERED_TRANSFER_BYTES: &str = "max_buffered_transfer_bytes";

// ---------------------------------------------------------------------------
// CopyRenameFallbackWrapper
// ---------------------------------------------------------------------------

/// [`WrapperFactory`] for the `copy_rename_fallback` wrapper kind
/// ([`COPY_RENAME_FALLBACK_KIND`]).
pub struct CopyRenameFallbackWrapperFactory;

#[async_trait]
impl WrapperFactory for CopyRenameFallbackWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor(COPY_RENAME_FALLBACK_KIND, LayerType::Wrapper, false)
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let max_buffered_bytes = match config.get(MAX_BUFFERED_TRANSFER_BYTES) {
            Some(value) => Some(config_u64(value, MAX_BUFFERED_TRANSFER_BYTES)?),
            None => None,
        };
        Ok(Arc::new(CopyRenameFallbackWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            max_buffered_bytes,
        }))
    }
}

/// Handles `copy`/`rename` that the layer below declines, falling back to
/// read-source + write-destination — streamed chunk-by-chunk to a
/// `write_stream`-capable destination, buffered to a `write`-only one.
/// Operations the layer below performs itself delegate straight to inner.
struct CopyRenameFallbackWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    /// Optional cap on host memory for the buffered (`write`-only destination)
    /// fallback path. `None` leaves buffered transfers uncapped.
    max_buffered_bytes: Option<u64>,
}

/// The refusal for an emulated `copy`/`rename` whose endpoints name one
/// object. The emulation reads the source and writes the destination, so in
/// place it races its own read against the destination write — and for
/// `rename` the trailing delete then removes the only copy.
fn same_object_error(op: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("{op} source and destination resolve to the same object"),
    )
    .with_next_action(
        "Name a different destination. This layer emulates the operation as \
         read-then-write, which cannot be performed in place.",
    )
}

/// Re-map a precondition failure detected on the fabricated source read.
///
/// The read carries the caller's `if_source` as `ReadOptions::if_match`, whose
/// contract is to surface `ObjectModified`. On the read path that is right —
/// the object changed under a reader. Here the read is an implementation
/// detail of a `copy`, the mismatch is detected before anything is written,
/// and the native path reports `PreconditionFailed` for exactly that. Without
/// this, the same failed conditional copy reports a different code depending
/// on whether the backend served it natively or the fallback emulated it.
///
/// Only when the caller supplied `if_source`, and only until the transfer has
/// moved a byte. `ObjectModified` also arises for reasons that are not a
/// caller precondition at all — a backend-native identity token being
/// rejected, or the source changing partway through a transfer that had
/// already started — and those must keep their meaning.
///
/// "Has moved a byte" rather than "`read` has returned", because the SPI lets
/// a backend defer its `if_match` check to the first poll of a
/// `ReadResult::Stream`. Both are failures to open the transfer, and
/// [`CopyOptions::if_source`] splits on whether work had started, so drawing
/// the line at `read` returning would make the reported code depend on where
/// inside a backend the check sits. Callers therefore apply this to
/// `inner.read` and, on the buffered path, to a drain failure that precedes
/// the first chunk — never to one after it.
///
/// The streaming slot reaches only the first of those: its drain runs inside
/// the destination write, past any remap here, so a lazily-checking backend
/// behind a streaming destination still surfaces `ObjectModified`. Closing
/// that gap needs a signal the write slot does not carry. What the caller
/// finally sees there is whatever the destination backend does with a
/// body-stream error; every in-tree backend propagates it verbatim, but the
/// SPI does not require that.
///
/// Only the code changes. The typed [`ErrorContext::Identity`] payload and the
/// recovery hint carry across untouched — `new_etag` is precisely what a
/// caller retrying a conditional copy needs, and the native path reports
/// `PreconditionFailed` carrying it, so dropping it here would reintroduce the
/// native/emulated divergence this remap exists to close.
fn as_pre_write_precondition(error: Error, had_if_source: bool) -> Error {
    if !had_if_source || error.code() != ErrorCode::ObjectModified {
        return error;
    }
    let mut remapped = Error::new(ErrorCode::PreconditionFailed, error.message().to_string());
    if let Some(context) = error.context() {
        remapped = remapped.with_context(context.clone());
    }
    if let Some(next_action) = error.next_action() {
        remapped = remapped.with_next_action(next_action.to_string());
    }
    remapped
}

/// Whether `source` and `destination` name the same object.
///
/// This is a plain comparison of the addresses as they arrive, which is
/// correct **only because this layer composes below every address-rewriting
/// layer** — see the composition requirement in the module docs. There is no
/// address-resolution slot in the SPI, so a rewriting layer placed *below*
/// this one could still collapse two distinct addresses onto one object after
/// the check has run, and the emulation would then destroy it.
fn names_same_object(source: &Url, destination: &Url) -> bool {
    source == destination
}

/// Raise the **availability** bits this wrapper makes true, leaving mechanism
/// (`supports_server_side_*`) and guarantee (`supports_atomic_rename`) as the
/// layer below reported them — except on a root that reports the operation
/// unavailable, where emulation is certain and the mechanism and guarantee
/// bits describe a native path that will never run. See the comment in the
/// body.
///
/// The single source of truth for "what can this wrapper serve?", so the
/// advertisement and the executable path cannot drift: `copy` is always
/// servable, and `rename` additionally needs the source root to delete,
/// because the emulation is a copy followed by a delete of the source.
fn raise_availability(caps: &mut Capabilities) {
    // A root that reports no rename of its own is never asked, so every
    // rename against it is emulated — copy-then-delete, which is not atomic.
    // Clearing the guarantee here is not the per-request over-reach of
    // clearing it whenever this wrapper is merely composed: emulation is
    // certain for this root, so `true` would be a promise the stack cannot
    // keep for any call.
    //
    // Where the root does rename, the bit is left alone. Whether a
    // *particular* request degrades is decided per request — a backend can
    // rename most objects natively and decline the one carrying a
    // precondition it cannot express — and a per-root bit cannot express
    // that. Those callers get the emulation event instead.
    if !caps.supports_rename {
        caps.supports_atomic_rename = false;
        caps.supports_server_side_rename = false;
    }
    if !caps.supports_copy {
        caps.supports_server_side_copy = false;
    }
    caps.supports_copy = true;
    caps.supports_rename = caps.supports_rename || emulated_rename_available(caps);
}

fn raise_all(mut roots: Vec<RootInfo>) -> Vec<RootInfo> {
    for root in &mut roots {
        raise_availability(&mut root.capabilities);
    }
    roots
}

/// Whether an emulated `rename` can complete against a root with `caps`.
///
/// The emulation is a copy followed by a delete of the source, so it needs
/// `delete` and nothing else. [`raise_availability`] publishes
/// `supports_rename || emulated_rename_available(..)`, so the advertisement is
/// derived from this rather than restating it — a root can be advertised
/// because inner renames natively *or* because this wrapper can emulate.
fn emulated_rename_available(caps: &Capabilities) -> bool {
    caps.supports_delete
}

/// The wrapper's fallback-read `Request` for `address`: a full-object read
/// (no range) carrying the caller's `if_source` precondition and request
/// extensions. `max_bytes` bounds the read on the buffered (`write`-only
/// destination) path so a cooperative backend caps its own buffered
/// read; the streamed path passes `None`.
fn source_read_request(
    address: Url,
    if_match: Option<String>,
    extensions: Extensions,
    max_bytes: Option<u64>,
) -> Request<ReadRequest> {
    Request {
        extensions,
        input: ReadRequest {
            address,
            options: ReadOptions {
                if_match,
                range: None,
                max_bytes,
            },
        },
    }
}

/// The typed error surfaced when a buffered transfer to a
/// `write`-only destination would exceed the configured host-memory cap.
/// `size` is the source's known size when available.
fn buffered_transfer_cap_error(cap: u64, size: Option<u64>) -> Error {
    let detail = match size {
        Some(size) => format!(
            "transfer source is {size} bytes, over the \
             {cap}-byte buffered-transfer cap for this write-only destination"
        ),
        None => format!(
            "transfer exceeded the {cap}-byte buffered-transfer \
             cap for this write-only destination"
        ),
    };
    Error::new(ErrorCode::ResourceExhausted, detail).with_next_action(
        "The destination root supports only buffered writes, which hold the \
         whole object in host memory. Transfer to a write_stream-capable \
         destination, raise the copy_rename_fallback `max_buffered_transfer_bytes` \
         cap, or transfer a smaller object.",
    )
}

/// Error if `resident` exceeds `max_bytes` — the running-total guard the
/// buffered path applies as it fills, so at most the cap is ever resident.
fn ensure_within_cap(resident: u64, max_bytes: Option<u64>) -> Result<()> {
    match max_bytes {
        Some(cap) if resident > cap => Err(buffered_transfer_cap_error(cap, None)),
        _ => Ok(()),
    }
}

/// Refuse a buffered transfer up front when the source's size is KNOWN and over
/// cap — so a too-large object never begins buffering (the size rides the read's
/// `ObjectInfo.size`).
fn refuse_known_size_over_cap(size: Option<u64>, max_bytes: Option<u64>) -> Result<()> {
    match (max_bytes, size) {
        (Some(cap), Some(size)) if size > cap => Err(buffered_transfer_cap_error(cap, Some(size))),
        _ => Ok(()),
    }
}

/// The composition error every fallback-read arm surfaces for an unfollowed
/// `ReadResult::Redirect`.
fn unfollowed_redirect_error() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "transfer received an unfollowed redirect \
         (RedirectFollower must compose below CopyRenameFallback)",
    )
}

impl CopyRenameFallbackWrapper {
    /// Read `address` fully into memory — the `write`-only destination path
    /// (`Body::Bytes` needs the whole object). A `Redirect` here is a
    /// composition error — `RedirectFollower`
    /// must sit below this wrapper.
    ///
    /// `max_bytes` bounds host memory: the source's known size (from the
    /// read's `ObjectInfo.size`) refuses an over-cap transfer up front — never
    /// beginning to buffer — and, when the size is unknown, the running total is
    /// checked chunk by chunk so at most the cap is ever resident. Either way an
    /// over-cap transfer surfaces [`buffered_transfer_cap_error`]
    /// (`ResourceExhausted`) instead of OOMing the host.
    async fn read_to_bytes(
        &self,
        address: Url,
        if_match: Option<String>,
        extensions: Extensions,
        cancel: Option<CancellationToken>,
        max_bytes: Option<u64>,
    ) -> Result<Vec<u8>> {
        let had_if_source = if_match.is_some();
        let request = source_read_request(address, if_match, extensions, max_bytes);
        // The remap reaches until the first chunk arrives, not just until
        // `read` returns: the SPI lets a backend defer its `if_match` check to
        // the first poll of a `ReadResult::Stream`, and a mismatch reported
        // there has still moved nothing. What it must not reach is a failure
        // *after* bytes have flowed, which is a source moving under a started
        // transfer and stays `ObjectModified`.
        let result = self
            .inner
            .read(request, cancel)
            .await
            .map_err(|error| as_pre_write_precondition(error, had_if_source))?;
        match result {
            ReadResult::Bytes { bytes, .. } => {
                ensure_within_cap(bytes.len() as u64, max_bytes)?;
                Ok(bytes)
            }
            ReadResult::Stream { mut stream, info } => {
                // Refuse up front when the source's size is known and over cap —
                // never begin buffering a too-large object.
                refuse_known_size_over_cap(info.size, max_bytes)?;
                use futures::StreamExt as _;
                let mut out = Vec::new();
                let mut moved_bytes = false;
                while let Some(chunk) = stream.next().await {
                    // A failure before the first chunk is still a failure to
                    // open: nothing has moved, so a caller precondition that
                    // the backend checked lazily reports like an eager one.
                    let chunk = chunk.map_err(|error| {
                        as_pre_write_precondition(error, had_if_source && !moved_bytes)
                    })?;
                    // Only a non-empty chunk counts as movement. `ReadStream`
                    // carries no non-empty invariant, so a backend may yield
                    // `Bytes::new()` before reporting a lazily-checked
                    // precondition — after which nothing has moved and the
                    // failure is still one to open.
                    moved_bytes = moved_bytes || !chunk.is_empty();
                    ensure_within_cap(
                        (out.len() as u64).saturating_add(chunk.len() as u64),
                        max_bytes,
                    )?;
                    out.extend_from_slice(&chunk);
                }
                Ok(out)
            }
            ReadResult::LocalDelegate(local) => {
                // Cap the local read too, holding the "buffers at most the cap"
                // property on every arm (the stream arm caps chunk-by-chunk).
                // A delegate almost always carries a known size; when it does
                // not and a cap is set, `stat` the file for its length rather
                // than slurping the whole file unbounded.
                let size = match (local.info.size, max_bytes) {
                    (Some(size), _) => Some(size),
                    (None, Some(_)) => Some(
                        tokio::fs::metadata(&local.path)
                            .await
                            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
                            .len(),
                    ),
                    (None, None) => None,
                };
                refuse_known_size_over_cap(size, max_bytes)?;
                tokio::fs::read(&local.path)
                    .await
                    .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))
            }
            ReadResult::Redirect(_) => Err(unfollowed_redirect_error()),
        }
    }

    /// Read `address` as a chunked [`Body::Stream`] plus the source's size
    /// (the destination write's `size_hint`) — the `write_stream` destination
    /// path. Each `ReadResult` variant maps to its cheapest streaming shape.
    /// A `Redirect` here is a composition error — `RedirectFollower` must sit
    /// below this wrapper.
    ///
    /// Only a source the backend already buffered (`ReadResult::Bytes`)
    /// occupies whole-object host memory here, as a single chunk; the other
    /// variants stream, so this path takes no `max_bytes`.
    async fn read_to_body(
        &self,
        address: Url,
        if_match: Option<String>,
        extensions: Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(Body, Option<u64>)> {
        let had_if_source = if_match.is_some();
        // The streamed path is bounded by chunk size × channel capacity
        // regardless of object size — no `max_bytes` cap.
        let request = source_read_request(address, if_match, extensions, None);
        // As in `read_to_bytes`, the remap covers opening the read only. The
        // drain happens later, inside the destination write, and a source that
        // moves then stays `ObjectModified`.
        let result = self
            .inner
            .read(request, cancel.clone())
            .await
            .map_err(|error| as_pre_write_precondition(error, had_if_source))?;
        match result {
            ReadResult::Bytes { bytes, info } => Ok((
                Body::Stream(BodyStream::from_iter(std::iter::once(Ok(bytes)))),
                info.size,
            )),
            ReadResult::Stream { stream, info } => Ok((
                Body::Stream(body_stream_from_read_stream(stream, cancel)),
                info.size,
            )),
            ReadResult::LocalDelegate(local) => {
                let size = local.info.size;
                let stream = ovstorage_layer::body_stream_from_file(&local.path)?;
                // The delegate's guard pins the file against cache eviction
                // only while held — ride it on the iterator so the lease
                // outlives the last chunk.
                let guard = local.guard;
                let stream = BodyStream::from_iter(stream.inspect(move |_| {
                    let _ = &guard;
                }));
                Ok((Body::Stream(stream), size))
            }
            ReadResult::Redirect(_) => Err(unfollowed_redirect_error()),
        }
    }

    /// Record that this request degraded to emulation.
    ///
    /// Whether a given `copy`/`rename` runs natively or is emulated is a
    /// property of the **request**, not of the root: a backend can perform
    /// most renames server-side and decline the one that carries a
    /// precondition it cannot express. So `supports_server_side_*` and
    /// `supports_atomic_rename` stay accurate about the native path and cannot
    /// be lowered to describe this — lowering them would deny a capability that
    /// usually holds. This event is the only per-request signal, and the reason
    /// an operator sees egress or a non-atomic outcome where the capability
    /// bits promised neither.
    fn note_emulated(&self, op: &str, reason: &str) {
        tracing::info!(
            layer = %self.name,
            op,
            reason,
            "copy_rename_fallback: emulating through the host; this transfer is \
             not server-side and an emulated rename is not atomic",
        );
    }

    /// Read `source` and write it to `destination` on the slot the
    /// destination root advertises, selecting the slot
    /// **before** reading so the read can keep its streaming shape:
    /// `write_stream` chunk-by-chunk when the root supports it, the buffered
    /// `write` otherwise (`Body::Bytes` needs the full object; when neither
    /// slot resolves, `write` surfaces the backend's own typed error, per
    /// the capability self-gate contract). Preconditions and the caller's
    /// request extensions ride both slots.
    async fn transfer_fallback(
        &self,
        source: Url,
        destination: Url,
        if_source: Option<String>,
        options: WriteOptions,
        extensions: Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // The probe carries the caller's extensions: `root_info_for` is
        // context-sensitive by contract, and an anonymous probe against a
        // credential-gated destination answers `NoRoute`/`AuthRequired`, which
        // `unwrap_or` would silently read as "cannot stream".
        //
        // Slot choice is streaming-first, decided by `supports_write_stream`
        // alone. It is tempting to divert a *conditional* destination to the
        // buffered slot, on the theory that the buffered slot is the one that
        // enforces preconditions — the in-tree OpenDAL fs/webdav profiles are
        // that shape, their `write_stream` refusing an `IfDestExists::Fail`
        // that `write` honours via `if_none_match`. But the capability bits
        // are per-root, not per-slot, and every other in-tree backend enforces
        // `if_dest` on `write_stream` too. Diverting on a per-root bit would
        // therefore buffer the whole object on backends that stream it
        // perfectly well, and the buffered path is the one whose host memory
        // scales with object size.
        //
        // An unresolvable probe selects the STREAMING slot, not the buffered
        // one. Both are guesses, but the buffered guess is the one that
        // materializes the whole object in host memory, uncapped by default —
        // so a transient `NoRoute`/`AuthRequired`/`Transient` on the probe
        // must not be what decides to buffer a multi-gigabyte source. If the
        // destination truly has no streaming slot, its own typed error
        // surfaces, per the capability self-gate contract.
        let stream_capable = self
            .inner
            .root_info_for(&destination, &extensions, cancel.clone())
            .await
            .map(|info| info.capabilities.supports_write_stream)
            .unwrap_or(true);
        if !stream_capable {
            let bytes = self
                .read_to_bytes(
                    source,
                    if_source,
                    extensions.clone(),
                    cancel.clone(),
                    self.max_buffered_bytes,
                )
                .await?;
            let request = Request {
                extensions,
                input: WriteRequest {
                    address: destination,
                    body: Body::Bytes(bytes),
                    options,
                },
            };
            return self.inner.write(request, cancel).await;
        }
        let (body, size_hint) = self
            .read_to_body(source, if_source, extensions.clone(), cancel.clone())
            .await?;
        let request = Request {
            extensions,
            input: WriteRequest {
                address: destination,
                body,
                // The stream carries no length; the source's size lets the
                // backend pick its upload strategy up front.
                options: WriteOptions {
                    size_hint,
                    ..options
                },
            },
        };
        self.inner.write_stream(request, cancel).await
    }
}

/// Capacity of the async→sync bridge channel in
/// [`body_stream_from_read_stream`]: peak in-flight memory is
/// Approximately chunk size times capacity (the FFI codec uses the same bound).
const BRIDGE_CHANNEL_CAPACITY: usize = 16;

/// One item on the async→sync bridge. The explicit `End` marker lets the
/// consumer distinguish a clean end-of-stream from the drain task dying
/// (runtime shutdown, panic) — a bare channel-close would otherwise read as
/// EOF and silently commit a truncated destination object.
enum BridgeItem {
    Chunk(Vec<u8>),
    End,
    Failed(Error),
}

/// Bridge an async [`ReadStream`] into the sync-pull [`BodyStream`] chunk by
/// chunk: a bounded channel drained by a spawned task, so a slow destination
/// backpressures the source read instead of buffering it. A source error
/// mid-stream propagates as the next chunk's error, and `cancel` aborts the
/// drain with `ErrorCode::Cancelled` — either way the destination write
/// fails rather than committing a truncated object. Dropping the
/// [`BodyStream`] (consumer gone) closes the channel and ends the drain
/// task immediately — the producer selects on `tx.closed()`, so it releases
/// the source stream even while parked on a stalled source, rather than
/// leaking until its next send.
///
/// The returned [`BodyStream`] pulls with `recv_blocking` and MUST be
/// drained on a blocking thread (the standard `BodyStream` consumer
/// contract — see the `redirect.rs` write-probe notes): draining it on a
/// runtime worker parks that worker while the spawned drain task still
/// needs the runtime to make progress, which deadlocks a current-thread
/// runtime outright.
fn body_stream_from_read_stream(
    stream: ReadStream,
    cancel: Option<CancellationToken>,
) -> BodyStream {
    use futures::StreamExt as _;
    let (tx, rx) = async_channel::bounded::<BridgeItem>(BRIDGE_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let mut stream = stream;
        loop {
            let next = match &cancel {
                Some(token) => tokio::select! {
                    _ = token.cancelled() => {
                        let _ = tx
                            .send(BridgeItem::Failed(Error::new(
                                ErrorCode::Cancelled,
                                "transfer cancelled mid-stream",
                            )))
                            .await;
                        return;
                    }
                    // The consumer (the sync `BodyStream`) was dropped — the
                    // destination write rejected (or the transfer future was
                    // dropped with no cancel token) before draining. Terminate
                    // now, releasing the source stream/connection, instead of
                    // staying parked in `stream.next()` on a stalled source
                    // until the next `tx.send`.
                    _ = tx.closed() => return,
                    next = stream.next() => next,
                },
                // No cancel token: still observe consumer closure so a dropped
                // consumer terminates the producer immediately rather than
                // leaking the spawned task and source stream.
                None => tokio::select! {
                    _ = tx.closed() => return,
                    next = stream.next() => next,
                },
            };
            let item = match next {
                Some(Ok(bytes)) => BridgeItem::Chunk(bytes.to_vec()),
                Some(Err(error)) => BridgeItem::Failed(error),
                None => BridgeItem::End,
            };
            let last = !matches!(item, BridgeItem::Chunk(_));
            if tx.send(item).await.is_err() || last {
                return;
            }
        }
    });
    let mut finished = false;
    BodyStream::from_iter(std::iter::from_fn(move || {
        if finished {
            return None;
        }
        match rx.recv_blocking() {
            Ok(BridgeItem::Chunk(chunk)) => Some(Ok(chunk)),
            Ok(BridgeItem::End) => {
                finished = true;
                None
            }
            Ok(BridgeItem::Failed(error)) => {
                finished = true;
                Some(Err(error))
            }
            Err(_) => {
                finished = true;
                Some(Err(Error::new(
                    ErrorCode::Internal,
                    "transfer source stream ended without an \
                     end-of-stream marker",
                )))
            }
        }
    }))
}

#[async_trait]
impl Layer for CopyRenameFallbackWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Everything except `copy`/`rename` and `root_info_for` delegates to
    /// `inner` via the trait defaults.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    /// Raise the **availability** bits the fallback makes true. The mechanism
    /// bits (`supports_server_side_*`, `supports_atomic_rename`) keep
    /// describing the native path — an emulated transfer is not server-side
    /// and an emulated rename is not atomic, and a caller optimizing for those
    /// must still see the truth — except where the root reports the operation
    /// unavailable, in which case every such call is emulated and those bits
    /// are cleared rather than left promising a path that cannot run.
    ///
    /// `supports_copy` is unconditional — a `copy` naming this root can always
    /// be attempted, and the fallback serves it when the backend will not.
    /// `supports_rename` additionally needs the source root to support
    /// `delete`, because an emulated rename is a copy followed by a delete of
    /// the source.
    async fn root_info_for(
        &self,
        address: &Url,
        extensions: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let mut info = self
            .inner
            .root_info_for(address, extensions, cancel)
            .await?;
        raise_availability(&mut info.capabilities);
        Ok(info)
    }

    async fn list_address_roots(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        // Discovery must agree with the point lookup above, on the snapshot and
        // on every update. A UI that builds a root picker from this stream and
        // greys out `copy` on `false` would otherwise hide operations the stack
        // actually serves.
        let (mut snapshot, updates) = self.inner.list_address_roots(cx, cancel).await?;
        for root in &mut snapshot.roots {
            raise_availability(&mut root.capabilities);
        }
        let updates = updates.map(|stream| {
            let mapped: RootInfoUpdateStream = Box::pin(stream.map(|change| {
                change.map(|change| match change {
                    RootInfoChange::Snapshot(roots) => RootInfoChange::Snapshot(raise_all(roots)),
                    RootInfoChange::Added(roots) => RootInfoChange::Added(raise_all(roots)),
                    RootInfoChange::Removed(roots) => RootInfoChange::Removed(raise_all(roots)),
                    RootInfoChange::Updated(roots) => RootInfoChange::Updated(raise_all(roots)),
                })
            }));
            mapped
        });
        Ok((snapshot, updates))
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let extensions = request.extensions.clone();
        let source = request.input.source.clone();
        let destination = request.input.destination.clone();
        let options = request.input.options.clone();
        // Ask inner whenever the root says a copy can be *attempted*. Gating on
        // `supports_server_side_copy` instead would skip the native path of a
        // backend that implements `copy` without the bytes staying on the
        // server — the availability-without-mechanism shape this vocabulary
        // exists to express — and emulate an operation it could have done
        // itself. Mechanism stays an optimization hint, never a dispatch gate.
        // When the caps cannot be resolved, attempt and fall back on
        // `Unsupported`.
        let attempt_inner = self
            .inner
            .root_info_for(&source, &extensions, cancel.clone())
            .await
            .map(|info| info.capabilities.supports_copy)
            .unwrap_or(true);
        if !attempt_inner {
            self.note_emulated("copy", "root reports copy unavailable");
        }
        if attempt_inner {
            match self.inner.copy(request, cancel.clone()).await {
                Ok(step) => return Ok(step),
                // `Unsupported` means the layer below does not perform this
                // operation — because the roots differ, because the backend has
                // no copy, or because it declines the request's preconditions.
                // All of those are cases the fallback can serve, carrying the
                // caller's `if_source`/`if_dest` onto the read and the write.
                // Any other error stands.
                Err(error) if error.code() == ErrorCode::Unsupported => {
                    self.note_emulated("copy", "inner declined with Unsupported");
                }
                Err(error) => return Err(error),
            }
        }
        // The emulation reads the source and writes the destination; in place
        // that races the read against the destination write, and a
        // non-atomic write slot can commit a truncated object. Guard here
        // rather than before delegating, so a backend that performs the
        // in-place copy natively still gets the chance.
        if names_same_object(&source, &destination) {
            return Err(same_object_error("copy"));
        }
        // Carry the caller's request context onto the fabricated read+write
        // (matching the sibling wrappers — no empty-extension drop).
        let mut result = self
            .transfer_fallback(
                source,
                destination.clone(),
                options.if_source.clone(),
                WriteOptions {
                    if_dest: options.if_dest,
                    message: options.message,
                    ..WriteOptions::default()
                },
                extensions,
                cancel,
            )
            .await?;
        result.info.address = destination;
        Ok(WriteStep::Done(result))
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let extensions = request.extensions.clone();
        let source = request.input.source.clone();
        let destination = request.input.destination.clone();
        let options = request.input.options.clone();
        // See `copy`: gate on availability so a backend that renames via its
        // own copy-then-delete (GCS, Azure without a hierarchical namespace)
        // is still asked.
        let attempt_inner = self
            .inner
            .root_info_for(&source, &extensions, cancel.clone())
            .await
            .map(|info| info.capabilities.supports_rename)
            .unwrap_or(true);
        if !attempt_inner {
            self.note_emulated("rename", "root reports rename unavailable");
        }
        if attempt_inner {
            match self.inner.rename(request, cancel.clone()).await {
                Ok(()) => return Ok(()),
                // See `copy`: `Unsupported` is the layer below declining to
                // perform the operation, whatever the reason, and the fallback
                // can serve every such case.
                Err(error) if error.code() == ErrorCode::Unsupported => {
                    self.note_emulated("rename", "inner declined with Unsupported");
                }
                Err(error) => return Err(error),
            }
        }
        // The emulation is copy-then-delete, which destroys the object outright
        // when the two addresses are the same one: the copy writes it onto
        // itself and the delete then removes the only surviving copy. A native
        // rename has no such hazard, so this is checked only on the emulated
        // path. Refusing keeps the caller's error rather than inventing a
        // success for an operation that was declined.
        if names_same_object(&source, &destination) {
            return Err(same_object_error("rename"));
        }
        // The emulation ends in a delete of the source, so a source root that
        // cannot delete can never complete one. Refuse now, before the
        // destination write, rather than leaving a committed duplicate behind
        // a failure at the last step.
        if !self
            .inner
            .root_info_for(&source, &extensions, cancel.clone())
            .await
            .map(|info| emulated_rename_available(&info.capabilities))
            .unwrap_or(true)
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "rename fallback requires delete on the source root",
            ));
        }
        // No server-side rename: copy, then delete the source.
        // Route the copy through this wrapper's `copy` so a
        // root with server-side copy (the classic S3 shape: no server-side
        // rename, server-side copy) still transfers server-side — never
        // buffering the object through host memory — and only degrades to the
        // streamed read+write emulation when the root lacks that too.
        let copy = Request {
            extensions: extensions.clone(),
            input: CopyRequest {
                source: source.clone(),
                destination: destination.clone(),
                options: CopyOptions {
                    if_source: options.if_source.clone(),
                    if_dest: options.if_dest,
                    message: options.message,
                },
            },
        };
        match self.copy(copy, cancel.clone()).await? {
            WriteStep::Done(_) => {}
            // A redirected copy hands the transfer to the caller; deleting the
            // source here would lose the object before the redirect completes.
            WriteStep::Redirects(_) => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "rename fallback cannot complete through a redirected copy",
                ));
            }
        }
        let source_for_error = source.clone();
        let destination_for_error = destination;
        let delete = Request {
            extensions,
            input: DeleteRequest {
                address: source,
                options: DeleteOptions {
                    if_match: options.if_source.clone(),
                },
            },
        };
        // The destination is already committed. A failure here leaves the
        // object at BOTH addresses, and the wrapper deliberately stops rather
        // than finishing the job: re-checking the source and deleting it
        // unconditionally would synthesize a compare-and-swap out of
        // stat-then-delete, which CONFORMANCE.md forbids precisely because a
        // writer landing in that window has its content deleted without ever
        // being copied. Reporting the partial state is worse ergonomics and
        // strictly better than silently destroying a write.
        //
        // A failure here cannot surface as the inner code —
        // a bare `Unsupported` would be indistinguishable from the
        // nothing-happened refusal the caller gets when the fallback declines
        // up front. Backends exist that accept a conditional read but not a
        // conditional delete (Nucleus, OpenDAL), which reach exactly here.
        match self.inner.delete(delete, cancel.clone()).await {
            Ok(()) => Ok(()),
            // The source is already gone — that is the state a rename
            // produces, so the operation succeeded.
            Err(error) if error.code() == ErrorCode::NotFound => Ok(()),
            Err(error) => Err(Error::new(
                ErrorCode::CommitAmbiguous,
                format!(
                    "rename fallback wrote the destination {} but could not \
                     delete the source {}: {error}",
                    RedactedUrl(&destination_for_error),
                    RedactedUrl(&source_for_error)
                ),
            )
            .with_next_action(
                "The destination is committed. Whether the source was deleted \
                 is unknown — a delete can commit and still report failure if \
                 its response is lost. Inspect both addresses before deleting \
                 either one.",
            )),
        }
    }
}
