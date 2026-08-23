// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant, SystemTime};

use aws_sdk_sqs::types::DeleteMessageBatchRequestEntry;
use ovstorage_plugin::provider_error;
use ovstorage_plugin::subscription::{
    AckHandle, AckingStream, Clock, CoalesceKey, DeliveryId, Pending, PendingDecrement,
    SystemClock, UpstreamFactory,
};
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, CancellationToken, ChangeKind, Error, ErrorCode,
    ResolvedTarget, Result, WatchDirectoryCursor, WatchDirectoryOptions, address, race_cancel,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::backend::S3Backend;
use crate::errors::map_sdk_error;

/// Bounded capacity of the event channel between the async SQS producer and
/// the coalescer's blocking fan-out dispatcher.
const EVENT_CHANNEL_CAPACITY: usize = 256;
/// Bounded capacity of the ack pump channel. The dispatcher dispatches each
/// event's ack nonblockingly; a `Full`/`Closed` `try_send` is a terminal
/// upstream error (never a silently-dropped ack).
const ACK_CHANNEL_CAPACITY: usize = 256;
const STALE_HANDLE_SKEW: Duration = Duration::from_secs(5);
/// SQS `DeleteMessageBatch` accepts at most 10 entries per call.
const DELETE_BATCH_MAX: usize = 10;

/// One item on the coalescer's [`AckingStream`]: an event plus the nonblocking
/// [`AckHandle`] the dispatcher invokes after fanning it out, or a terminal
/// error (an async provider ack failure surfaces here, drained after any
/// already-queued events).
type UpstreamItem = Result<(BackendChangeEvent, AckHandle)>;

/// The future the [`UpstreamFactory`] returns. Equivalent to
/// `futures::future::BoxFuture<'static, Result<AckingStream>>`, spelled without
/// the extra dependency.
type UpstreamFuture = Pin<Box<dyn std::future::Future<Output = Result<AckingStream>> + Send>>;

#[derive(Debug, Clone)]
pub struct SqsHandle {
    pub receipt_handle: String,
    pub message_id: String,
}

pub type SqsPending = Pending<SqsHandle>;

pub struct SubscriptionRuntime<C: Clock> {
    pub pending: Arc<SqsPending>,
    pub clock: Arc<C>,
}

pub async fn watch_directory(
    backend: &S3Backend,
    prefix: ResolvedTarget,
    opts: WatchDirectoryOptions,
    effective_cadence: Duration,
    cancel: Option<CancellationToken>,
) -> Result<BackendChangeStream> {
    watch_directory_with_clock(
        backend,
        prefix,
        opts,
        effective_cadence,
        cancel,
        Arc::new(SystemClock),
    )
    .await
}

async fn watch_directory_with_clock<C: Clock + 'static>(
    backend: &S3Backend,
    prefix: ResolvedTarget,
    opts: WatchDirectoryOptions,
    effective_cadence: Duration,
    cancel: Option<CancellationToken>,
    clock: Arc<C>,
) -> Result<BackendChangeStream> {
    let parts = backend.parse_target(&prefix)?;
    let Some(queue_url) = backend.config().sqs_queue_url.clone() else {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "S3 watch_directory requires sqs_queue_url in the connection config",
        ));
    };
    if backend.is_anonymous() {
        // `Unsupported`, not `AuthRequired`: this connection has no credential
        // to be wrong, so nothing is served by pointing a caller at a
        // credential refresh or an interactive flow. The same reasoning as
        // `S3Backend::signed_client` and `errors::map_anonymous_refusal`, and
        // it must stay in step with them.
        return Err(Error::new(
            ErrorCode::Unsupported,
            "S3 watch_directory needs credentials for SQS, and this connection \
             is anonymous",
        )
        .with_next_action(
            "remove and re-add this connection with credentials to watch this prefix",
        ));
    }
    backend.resolve_credentials(None)?;
    let sqs = backend
        .sqs_client()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "S3 watch_directory requires sqs_queue_url with credentials",
            )
        })?
        .clone();

    // This subscriber's prefix view (always a directory boundary, trailing
    // slash). The coalescer filters the connection-wide feed against it before
    // this subscriber's queue.
    let prefix_key = address::directory_key(&parts.key);
    let subscriber_prefix = address::join_relative(&backend.config().address_root, &prefix_key)?;

    // The upstream opens at the CONNECTION ROOT (recursive + metadata) so one
    // SQS consumer feeds every prefix on the connection; per-subscriber prefix
    // filtering is the coalescer's job. Bucket rejection stays here.
    let config = backend.config();
    let bucket = config.bucket.clone();
    let address_root = config.address_root.clone();
    let max_messages = config.sqs_max_messages as i32;
    let visibility_timeout_seconds = config.sqs_visibility_timeout;

    // Coalescing key = the SQS queue URL: a stable per-connection resource id,
    // independent of prefix/cadence.
    let key: CoalesceKey = queue_url.clone();

    let upstream: UpstreamFactory =
        Arc::new(move |cancel: CancellationToken, cadence: Duration| {
            let sqs = sqs.clone();
            let queue_url = queue_url.clone();
            let bucket = bucket.clone();
            let address_root = address_root.clone();
            let clock = clock.clone();
            Box::pin(async move {
                // The negotiated cadence IS the SQS long-poll duration (S3 has no
                // other cadence knob); clamp to the SQS 0..=20s ceiling.
                let wait_seconds = cadence.as_secs().min(20) as i32;
                let client = SqsClient {
                    sqs,
                    queue_url,
                    max_messages,
                    wait_seconds,
                    visibility_timeout_seconds,
                };
                let watch = WatchFilter {
                    bucket,
                    address_root,
                    prefix_key: String::new(),
                    recursive: true,
                    include_metadata_changes: true,
                };
                let runtime = Arc::new(SubscriptionRuntime {
                    pending: Arc::new(SqsPending::new()),
                    clock,
                });
                let (event_tx, event_rx) =
                    std::sync::mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
                let (ack_tx, ack_rx) = mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);

                tokio::spawn(ack_pump(
                    client.clone(),
                    runtime.clone(),
                    ack_rx,
                    event_tx.clone(),
                    cancel.clone(),
                ));
                tokio::spawn(producer(client, runtime, event_tx, ack_tx, cancel, watch));

                Ok(Box::new(event_rx.into_iter()) as AckingStream)
            }) as UpstreamFuture
        });

    backend
        .watch_coalescer()
        .subscribe(
            key,
            subscriber_prefix,
            opts,
            effective_cadence,
            cancel,
            upstream,
        )
        .await
}

/// Drive one SQS consumer, feeding parsed events (each paired with a
/// nonblocking [`AckHandle`]) to the coalescer's dispatcher. One SQS message
/// may parse into several events; they share one [`DeliveryId`] whose refcount
/// is the event count, so the message is deleted exactly once — after every
/// one of its events' ack handles has fired.
async fn producer<C: Clock + 'static>(
    client: SqsClient,
    runtime: Arc<SubscriptionRuntime<C>>,
    tx: SyncSender<UpstreamItem>,
    ack_tx: mpsc::Sender<DeliveryId>,
    cancel: CancellationToken,
    watch: WatchFilter,
) {
    let mut backoff = Duration::from_millis(250);
    while !cancel.is_cancelled() {
        let messages = match race_cancel(Some(&cancel), client.receive()).await {
            Ok(messages) => {
                backoff = Duration::from_millis(250);
                messages
            }
            Err(err)
                if matches!(
                    err.code(),
                    ErrorCode::Transient
                        | ErrorCode::DeadlineExceeded
                        | ErrorCode::ResourceExhausted
                ) =>
            {
                warn!(plugin = "s3", op = "watch_directory", error = %err.message(), "SQS receive failed transiently");
                // A transient stall is a gap: broadcast a Lapsed (no message to
                // delete, so a no-op ack) and back off.
                let _ = send_item(&tx, Ok((lapsed_event(), noop_ack()))).await;
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(4));
                continue;
            }
            Err(err) => {
                if err.code() == ErrorCode::Cancelled && cancel.is_cancelled() {
                    break;
                }
                let _ = send_item(&tx, Err(err)).await;
                break;
            }
        };

        for message in messages {
            if cancel.is_cancelled() {
                break;
            }
            let received_at = runtime.clock.now();
            let deadline =
                received_at + Duration::from_secs(u64::from(client.visibility_timeout_seconds));
            let handle = SqsHandle {
                receipt_handle: message.receipt_handle,
                message_id: message.message_id,
            };
            let events = match parse_notification_body(&message.body, &watch) {
                Ok(events) => events,
                Err(err) => {
                    warn!(plugin = "s3", op = "watch_directory", error = %err.message(), "malformed S3 notification");
                    vec![lapsed_event()]
                }
            };

            if events.is_empty() {
                // No event this subscriber cohort could carry an ack for (the
                // record was bucket-mismatched or an unrecognized event kind).
                // Route the delete THROUGH THE ACK PUMP as a one-count delivery —
                // the same `provider_ack`/`ack_tx` mechanism the eventful path
                // uses — so every async provider (delete) failure originates in
                // the pump and gets its concurrent publish-and-drain masking
                // protection ([`publish_terminal_then_drain`]). The producer never
                // performs a terminal `send_item(Err)` for a provider Fatal: from
                // this thread it cannot drain `ack_rx`, so a parked terminal send
                // would let the dispatcher's queued-tail acks fill `ack_rx` and
                // mask the real provider error with a generic `Full` `Internal`.
                //
                // The enqueue is an AWAITED send, not a nonblocking drop: this
                // producer thread can await, so a saturated pump applies natural
                // backpressure (we stop pulling until the pump drains) rather than
                // dropping the delete and orphaning the one-count `Pending` entry
                // we just inserted. `Closed` means the pump receiver is gone
                // (teardown), so we stop the producer; racing `cancel` keeps the
                // send from hanging when teardown is under way (the `Pending`
                // entry drops with the runtime).
                let delivery_id = runtime.pending.insert(handle, 1, deadline);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    res = ack_tx.send(delivery_id) => {
                        if res.is_err() {
                            // Pump receiver gone => teardown underway; stop the
                            // producer.
                            return;
                        }
                    }
                }
                continue;
            }

            // One refcounted delivery for the whole message; each event's
            // AckHandle decrements it, and the last one triggers the delete.
            let delivery_id = runtime.pending.insert(handle, events.len(), deadline);
            for event in events {
                let ack = provider_ack(ack_tx.clone(), delivery_id);
                if send_item(&tx, Ok((event, ack))).await.is_err() {
                    // The dispatcher (and thus the last subscriber) is gone;
                    // stop this upstream.
                    cancel.cancel();
                    return;
                }
            }
        }
    }
}

/// Drain ack requests, decrement the owning delivery's refcount, and delete the
/// SQS message when its last event acks. A provider (delete) failure is
/// published as a terminal `Err` on the event stream — ordered AFTER any events
/// already queued ahead of it — so the coalescer tears the fan-out down and
/// reopens; an ack is never silently lost.
///
/// Publishing that terminal `Err` and draining `ack_rx` run CONCURRENTLY (see
/// [`publish_terminal_then_drain`]). The terminal send is a blocking send on the
/// bounded event channel; while it is parked behind the already-queued tail the
/// pump keeps receiving and discarding acks. That way the dispatcher's
/// post-fan-out `provider_ack.try_send` for a still-queued event never sees a
/// `Full`/`Closed` channel and never masks the real terminal with a fresh,
/// generic `Internal` (which the dispatcher would treat as terminal and tear
/// down on BEFORE it drains the queued tail and reaches the real provider `Err`).
/// Each discarded delivery redelivers via SQS at-least-once, leaving the provider
/// error the single deterministic terminal after the queued tail.
async fn ack_pump<C: Clock + 'static>(
    client: SqsClient,
    runtime: Arc<SubscriptionRuntime<C>>,
    mut ack_rx: mpsc::Receiver<DeliveryId>,
    tx: SyncSender<UpstreamItem>,
    cancel: CancellationToken,
) {
    while let Some(delivery_id) = ack_rx.recv().await {
        // Batch the network deletes. The dispatcher's fan-out is in-memory (fast)
        // while each SQS delete is a round-trip (slow), so a per-message ack could
        // never keep pace with sustained delivery — the bounded ack channel would
        // fill and a `provider_ack.try_send` would return `Full`, terminating the
        // stream on a routine backlog. After receiving one id, drain up to
        // `DELETE_BATCH_MAX - 1` more READY receipts nonblockingly and issue ONE
        // `DeleteMessageBatch`. This lifts ack throughput to match batched
        // delivery, so the channel drains and `Full` is a pathological-only
        // backstop. Only READY deliveries (refcount hit 0 in `decrement`)
        // contribute a receipt; a still-`Pending` decrement adds nothing but is
        // still consumed from the channel.
        let mut batch: Vec<AckEntry> = Vec::new();
        match decrement_entry(&runtime.pending, delivery_id) {
            Ok(Some(entry)) => batch.push(entry),
            Ok(None) => {}
            Err(id) => {
                publish_terminal_then_drain(&tx, unknown_delivery_error(id), &mut ack_rx, &cancel)
                    .await;
                return;
            }
        }
        while batch.len() < DELETE_BATCH_MAX {
            match ack_rx.try_recv() {
                Ok(id) => match decrement_entry(&runtime.pending, id) {
                    Ok(Some(entry)) => batch.push(entry),
                    Ok(None) => continue,
                    Err(id) => {
                        publish_terminal_then_drain(
                            &tx,
                            unknown_delivery_error(id),
                            &mut ack_rx,
                            &cancel,
                        )
                        .await;
                        return;
                    }
                },
                // Channel drained or closed: delete what we have. A closed
                // channel is observed as `None` on the next outer `recv`.
                Err(mpsc::error::TryRecvError::Empty)
                | Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        if batch.is_empty() {
            continue;
        }
        match ack_batch_with_cancel(&client, &batch, runtime.clock.as_ref(), &cancel).await {
            Some(AckOutcome::Success | AckOutcome::Transient) => {}
            Some(AckOutcome::Fatal(err)) => {
                publish_terminal_then_drain(&tx, err, &mut ack_rx, &cancel).await;
                return;
            }
            // Cancelled mid-delete: the upstream is tearing down, nothing to
            // report.
            None => break,
        }
    }
}

/// One ready receipt awaiting a batched delete: the message handle and its
/// visibility deadline (for stale-receipt classification).
struct AckEntry {
    handle: SqsHandle,
    deadline: Instant,
}

/// Decrement `id`'s refcount: `Ok(Some(entry))` when it was the last event of its
/// message (delete it), `Ok(None)` when other events remain (nothing to delete
/// yet), `Err(id)` when the delivery is unknown (a terminal invariant violation).
fn decrement_entry(
    pending: &SqsPending,
    id: DeliveryId,
) -> std::result::Result<Option<AckEntry>, DeliveryId> {
    match pending.decrement(id) {
        Ok(PendingDecrement::Pending) => Ok(None),
        Ok(PendingDecrement::Ready { handle, deadline }) => Ok(Some(AckEntry { handle, deadline })),
        Err(_) => Err(id),
    }
}

fn unknown_delivery_error(_id: DeliveryId) -> Error {
    Error::new(
        ErrorCode::Internal,
        "S3 watch ack referenced an unknown delivery",
    )
}

/// Publish the terminal `Err` on the event stream while CONCURRENTLY draining
/// (discarding) ack requests, then keep discarding until teardown.
///
/// The terminal send is a blocking [`SyncSender::send`] on the bounded event
/// channel; if that channel is full it parks until the dispatcher drains the
/// events already queued ahead of it. While the send is parked the pump must
/// keep receiving from `ack_rx`: as the dispatcher fans out each queued event it
/// calls `provider_ack.try_send`, and an unread `ack_rx` fills to capacity,
/// turning the next `try_send` into a fresh `Full` `Internal` the dispatcher
/// would terminate on BEFORE reaching the real provider `Err`. Draining
/// concurrently keeps those `try_send`s succeeding, so the provider error stays
/// the single deterministic terminal after the queued tail. Discarding acks does
/// not reorder the already-queued events; each discarded delivery redelivers via
/// SQS at-least-once.
///
/// Once the terminal send completes it falls through to
/// [`drain_acks_until_cancel`] to keep discarding until teardown. Cancellation is
/// prioritized (biased) over both completing the send and receiving an ack.
async fn publish_terminal_then_drain(
    tx: &SyncSender<UpstreamItem>,
    err: Error,
    ack_rx: &mut mpsc::Receiver<DeliveryId>,
    cancel: &CancellationToken,
) {
    let mut send = std::pin::pin!(send_item(tx, Err(err)));
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = &mut send => break,
            next = ack_rx.recv() => {
                if next.is_none() {
                    return;
                }
            }
        }
    }
    drain_acks_until_cancel(ack_rx, cancel).await;
}

/// The tail of [`publish_terminal_then_drain`]: once the terminal `Err` is on the
/// event stream, keep accepting and discarding ack requests so the dispatcher's
/// post-fan-out `provider_ack` calls keep succeeding — no `Full`/`Closed`
/// `Internal` masks the real terminal already queued on the event stream. Each
/// discarded message redelivers via SQS at-least-once. Exits when the dispatcher
/// cancels the upstream (teardown) or the ack channel closes.
async fn drain_acks_until_cancel(
    ack_rx: &mut mpsc::Receiver<DeliveryId>,
    cancel: &CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            next = ack_rx.recv() => {
                if next.is_none() {
                    return;
                }
            }
        }
    }
}

/// A nonblocking [`AckHandle`] that dispatches this event's delete into the
/// bounded ack pump. A `Full`/`Closed` `try_send` is a terminal upstream error.
fn provider_ack(ack_tx: mpsc::Sender<DeliveryId>, delivery_id: DeliveryId) -> AckHandle {
    Box::new(move || {
        ack_tx.try_send(delivery_id).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("S3 watch ack pump unavailable: {err}"),
            )
        })
    })
}

/// A no-op ack for events with no backing SQS message to delete (e.g. a
/// synthesized `Lapsed`).
fn noop_ack() -> AckHandle {
    Box::new(|| Ok(()))
}

async fn ack_batch_with_cancel<C: Clock + ?Sized>(
    client: &SqsClient,
    batch: &[AckEntry],
    clock: &C,
    cancel: &CancellationToken,
) -> Option<AckOutcome> {
    tokio::select! {
        biased;
        outcome = client.ack_batch(batch, clock) => Some(outcome),
        _ = cancel.cancelled() => None,
    }
}

/// Send an item into the blocking event channel from an async task without
/// stalling the runtime on a full channel. `Err` means the receiver (the
/// dispatcher) is gone.
async fn send_item(
    tx: &SyncSender<UpstreamItem>,
    item: UpstreamItem,
) -> std::result::Result<(), ()> {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || tx.send(item).map_err(|_| ()))
        .await
        .map_err(|_| ())?
}

#[derive(Clone)]
struct SqsClient {
    sqs: aws_sdk_sqs::Client,
    queue_url: String,
    max_messages: i32,
    wait_seconds: i32,
    visibility_timeout_seconds: u32,
}

impl SqsClient {
    async fn receive(&self) -> Result<Vec<SqsMessage>> {
        let output = self
            .sqs
            .receive_message()
            .queue_url(&self.queue_url)
            .max_number_of_messages(self.max_messages)
            .wait_time_seconds(self.wait_seconds)
            .visibility_timeout(self.visibility_timeout_seconds as i32)
            .send()
            .await
            .map_err(|err| map_sdk_error("SQS ReceiveMessage", err))?;
        let mut messages = Vec::new();
        for message in output.messages() {
            let message_id = message.message_id().unwrap_or_default();
            let receipt_handle = message.receipt_handle().unwrap_or_default();
            let body = message.body().unwrap_or_default();
            if message_id.is_empty() || receipt_handle.is_empty() || body.is_empty() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "SQS ReceiveMessage response contained an incomplete Message",
                ));
            }
            messages.push(SqsMessage {
                message_id: message_id.to_string(),
                receipt_handle: receipt_handle.to_string(),
                body: body.to_string(),
            });
        }
        Ok(messages)
    }

    /// Delete a whole batch of ready receipts in one `DeleteMessageBatch`. AWS
    /// returns per-entry `Successful`/`Failed` lists; a `Failed` entry is
    /// classified against ITS OWN visibility deadline, and any fatal entry makes
    /// the whole batch fatal (terminal). A transport-level error is transient or
    /// fatal for the whole call.
    async fn ack_batch<C: Clock + ?Sized>(&self, batch: &[AckEntry], clock: &C) -> AckOutcome {
        debug!(
            plugin = "s3",
            op = "watch_directory",
            count = batch.len(),
            message_ids = %batch
                .iter()
                .map(|entry| entry.handle.message_id.as_str())
                .collect::<Vec<_>>()
                .join(","),
            "deleting SQS message batch"
        );
        match self.delete_message_batch(batch).await {
            Ok(failures) if failures.is_empty() => AckOutcome::Success,
            Ok(failures) => classify_batch_failures(failures, batch, clock),
            Err(err)
                if matches!(
                    err.code(),
                    ErrorCode::Transient
                        | ErrorCode::DeadlineExceeded
                        | ErrorCode::ResourceExhausted
                ) =>
            {
                warn!(plugin = "s3", op = "watch_directory", error = %err.message(), "SQS delete failed transiently");
                AckOutcome::Transient
            }
            Err(err) => AckOutcome::Fatal(err),
        }
    }

    async fn delete_message_batch(&self, batch: &[AckEntry]) -> Result<Vec<BatchFailure>> {
        // Entry ids are the batch position (`m{index}`), so a `Failed` entry maps
        // back to its `AckEntry` (and thus its deadline) by parsing the index.
        let mut request = self.sqs.delete_message_batch().queue_url(&self.queue_url);
        for (index, entry) in batch.iter().enumerate() {
            let built = DeleteMessageBatchRequestEntry::builder()
                .id(format!("m{index}"))
                .receipt_handle(&entry.handle.receipt_handle)
                .build()
                .map_err(|err| {
                    Error::new(
                        ErrorCode::Internal,
                        format!("SQS DeleteMessageBatch entry build failed: {err}"),
                    )
                })?;
            request = request.entries(built);
        }
        let output = request
            .send()
            .await
            .map_err(|err| map_sdk_error("SQS DeleteMessageBatch", err))?;
        let failures = output
            .failed()
            .iter()
            .map(|failure| BatchFailure {
                id: failure.id().to_string(),
                code: failure.code().to_string(),
                message: failure.message().unwrap_or_default().to_string(),
                sender_fault: failure.sender_fault(),
            })
            .collect();
        Ok(failures)
    }
}

enum AckOutcome {
    Success,
    Transient,
    Fatal(Error),
}

/// The visibility deadline of the batch entry a `Failed` result names, looked up
/// by parsing the `m{index}` id back to its position. Returns `None` when the id
/// doesn't map to a batch entry: we always send ids `m0..m{n-1}` and AWS echoes
/// them, so an unmatched id is an unexpected response that can't be classified
/// against a real deadline — the caller treats it as terminal (Fatal) rather
/// than guessing a deadline and silently continuing.
fn entry_deadline(id: &str, batch: &[AckEntry]) -> Option<Instant> {
    id.strip_prefix('m')
        .and_then(|index| index.parse::<usize>().ok())
        .and_then(|index| batch.get(index))
        .map(|entry| entry.deadline)
}

fn classify_batch_failures<C: Clock + ?Sized>(
    failures: Vec<BatchFailure>,
    batch: &[AckEntry],
    clock: &C,
) -> AckOutcome {
    let now = clock.now();
    for failure in failures {
        let Some(deadline) = entry_deadline(&failure.id, batch) else {
            // The one path where the id is NOT already known to be `m<index>`:
            // reaching here means it did not match, so this is the only place a
            // hostile echoed value can surface. Allowlist it like any other
            // provider-controlled field.
            return AckOutcome::Fatal(Error::new(
                ErrorCode::Internal,
                format!(
                    "SQS DeleteMessageBatch returned an unrecognized entry id '{}'",
                    reportable_entry_id(&failure.id)
                ),
            ));
        };
        if failure.code == "InvalidParameterValue"
            && failure
                .message
                .to_ascii_lowercase()
                .contains("receipt handle")
            && failure.message.to_ascii_lowercase().contains("has expired")
        {
            if now >= deadline + STALE_HANDLE_SKEW {
                warn!(
                    plugin = "s3",
                    op = "watch_directory",
                    "SQS receipt handle expired after visibility timeout"
                );
                continue;
            }
            return AckOutcome::Fatal(Error::new(
                ErrorCode::Internal,
                "SQS receipt handle expired before its visibility deadline",
            ));
        }
        if failure.code == "ReceiptHandleIsInvalid" {
            return AckOutcome::Fatal(Error::new(
                ErrorCode::Internal,
                batch_failure_detail(&failure),
            ));
        }
        if !failure.sender_fault {
            // The log gets the same treatment as the error: a log line is where
            // this material would land either way, so the endpoint-controlled
            // code is allowlisted before it is recorded. Classification above
            // still compares against the raw value.
            warn!(
                plugin = "s3",
                op = "watch_directory",
                code = %reportable_code(&failure.code),
                "SQS delete failed with transient batch entry"
            );
            continue;
        }
        return AckOutcome::Fatal(Error::new(
            if failure.code == "AccessDenied" {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::Internal
            },
            batch_failure_detail(&failure),
        ));
    }
    AckOutcome::Transient
}

#[derive(Clone)]
struct WatchFilter {
    bucket: String,
    address_root: ovstorage_plugin::Url,
    prefix_key: String,
    recursive: bool,
    include_metadata_changes: bool,
}

fn parse_notification_body(body: &str, filter: &WatchFilter) -> Result<Vec<BackendChangeEvent>> {
    let value: Value = serde_json::from_str(body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "S3 notification body was not valid JSON: {}",
                crate::errors::decode_failure(&err, body.len())
            ),
        )
    })?;
    if let Some(records) = value.get("Records").and_then(Value::as_array) {
        let mut events = Vec::new();
        for record in records {
            match direct_record_to_event(record, filter) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(err) => {
                    warn!(plugin = "s3", op = "watch_directory", error = %err.message(), "malformed S3 notification record");
                    events.push(lapsed_event());
                }
            }
        }
        return Ok(events);
    }
    if value.get("detail-type").is_some() && value.get("detail").is_some() {
        return Ok(eventbridge_to_event(&value, filter)?.into_iter().collect());
    }
    Err(Error::new(
        ErrorCode::Internal,
        "S3 notification body was neither a Records notification nor an EventBridge event",
    ))
}

fn direct_record_to_event(
    record: &Value,
    filter: &WatchFilter,
) -> Result<Option<BackendChangeEvent>> {
    let event_name = required_str(record, &["eventName"])?;
    let Some(kind) = direct_event_kind(event_name) else {
        return Ok(None);
    };
    if kind == ChangeKind::MetadataChanged && !filter.include_metadata_changes {
        return Ok(None);
    }
    let bucket = required_str(record, &["s3", "bucket", "name"])?;
    if bucket != filter.bucket {
        return Ok(None);
    }
    let encoded_key = required_str(record, &["s3", "object", "key"])?;
    let key = decode_s3_key(encoded_key)?;
    let Some(_relative_key) = relative_key(&key, filter) else {
        return Ok(None);
    };
    let identity = identity_from_fields(
        record.pointer("/s3/object/eTag").and_then(Value::as_str),
        record
            .pointer("/s3/object/versionId")
            .and_then(Value::as_str),
        record.pointer("/s3/object/size").and_then(Value::as_u64),
    );
    object_event(
        filter,
        &key,
        kind,
        identity,
        required_str(record, &["eventTime"])
            .ok()
            .and_then(parse_iso8601_to_system_time)
            .unwrap_or_else(SystemTime::now),
    )
}

fn eventbridge_to_event(value: &Value, filter: &WatchFilter) -> Result<Option<BackendChangeEvent>> {
    let detail_type = required_str(value, &["detail-type"])?;
    let detail = value
        .get("detail")
        .ok_or_else(|| Error::new(ErrorCode::Internal, "EventBridge event missing detail"))?;
    let Some(kind) = eventbridge_kind(detail_type, detail) else {
        return Ok(None);
    };
    if kind == ChangeKind::MetadataChanged && !filter.include_metadata_changes {
        return Ok(None);
    }
    let bucket = required_str(detail, &["bucket", "name"])?;
    if bucket != filter.bucket {
        return Ok(None);
    }
    let key = required_str(detail, &["object", "key"])?;
    let Some(_relative_key) = relative_key(key, filter) else {
        return Ok(None);
    };
    let identity = identity_from_fields(
        detail.pointer("/object/etag").and_then(Value::as_str),
        detail.pointer("/object/version-id").and_then(Value::as_str),
        detail.pointer("/object/size").and_then(Value::as_u64),
    );
    object_event(
        filter,
        key,
        kind,
        identity,
        value
            .get("time")
            .and_then(Value::as_str)
            .and_then(parse_iso8601_to_system_time)
            .unwrap_or_else(SystemTime::now),
    )
}

fn direct_event_kind(event_name: &str) -> Option<ChangeKind> {
    match event_name {
        "ObjectCreated:Put"
        | "ObjectCreated:Post"
        | "ObjectCreated:Copy"
        | "ObjectCreated:CompleteMultipartUpload" => Some(ChangeKind::Created),
        "ObjectRemoved:Delete" | "ObjectRemoved:DeleteMarkerCreated" => Some(ChangeKind::Deleted),
        "ObjectRestore:Completed" => Some(ChangeKind::Modified),
        "ObjectRestore:Delete" => Some(ChangeKind::MetadataChanged),
        name if name.starts_with("ObjectTagging:") => Some(ChangeKind::MetadataChanged),
        name if name.starts_with("LifecycleExpiration:") => Some(ChangeKind::Deleted),
        _ => None,
    }
}

fn eventbridge_kind(detail_type: &str, detail: &Value) -> Option<ChangeKind> {
    match detail_type {
        "Object Created" => match detail.get("reason").and_then(Value::as_str) {
            Some("PutObject" | "POST Object" | "CopyObject" | "CompleteMultipartUpload") => {
                Some(ChangeKind::Created)
            }
            _ => None,
        },
        "Object Deleted" => match detail.get("deletion-type").and_then(Value::as_str) {
            Some("Delete Marker Created" | "Permanently Deleted") => Some(ChangeKind::Deleted),
            _ => None,
        },
        "Object Restore Completed" => Some(ChangeKind::Modified),
        "Object Restore Expired"
        | "Object Tags Added"
        | "Object Tags Deleted"
        | "Object ACL Updated"
        | "Object Storage Class Changed"
        | "Object Access Tier Changed" => Some(ChangeKind::MetadataChanged),
        _ => None,
    }
}

fn relative_key(key: &str, filter: &WatchFilter) -> Option<String> {
    let stripped = key.strip_prefix(&filter.prefix_key)?;
    let relative = stripped.strip_prefix('/').unwrap_or(stripped);
    if relative.is_empty() {
        return None;
    }
    if !filter.recursive && relative.contains('/') {
        return None;
    }
    Some(relative.to_string())
}

fn object_event(
    filter: &WatchFilter,
    key: &str,
    kind: ChangeKind,
    identity: ObjectIdentity,
    at: SystemTime,
) -> Result<Option<BackendChangeEvent>> {
    // Skip, never propagate. A key that cannot be named by a URI path must not
    // end the stream for every other object under the watched prefix — the
    // same treatment the listing emitters give it.
    let Ok(mut event_address) = address::join_relative(&filter.address_root, key) else {
        tracing::warn!(
            target: "ovstorage.s3.subscription",
            plugin = "s3",
            key = %key,
            "s3: object key is not addressable as a URI path; change event omitted",
        );
        return Ok(None);
    };
    if let Some(version) = identity.version.as_deref() {
        event_address = address::with_query_pair(&event_address, "versionId", version)?;
    }
    Ok(Some(BackendChangeEvent::Object {
        address: event_address,
        kind,
        etag: identity.etag,
        version: identity.version,
        size: identity.size,
        // S3 notifications carry `eventTime` (when the event fired) but
        // not a separate `lastModified` for the object itself, so the
        // wire payload has no mtime to surface.
        mtime: None,
        at,
        cursor: WatchDirectoryCursor::default(),
    }))
}

#[derive(Debug, Default)]
struct ObjectIdentity {
    etag: Option<String>,
    version: Option<String>,
    size: Option<u64>,
}

fn identity_from_fields(
    etag: Option<&str>,
    version: Option<&str>,
    size: Option<u64>,
) -> ObjectIdentity {
    ObjectIdentity {
        // The S3 HTTP etag IS the SPI etag verbatim (`If-Match` accepts
        // it including any `W/` prefix and surrounding quotes), but the
        // SQS notification body delivers it without quotes; trim defensively.
        etag: etag.map(|value| value.trim_matches('"').to_string()),
        version: version.map(str::to_string),
        size,
    }
}

fn required_str<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor.get(*segment).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!("S3 notification missing '{}'", path.join(".")),
            )
        })?;
    }
    cursor.as_str().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "S3 notification field '{}' was not a string",
                path.join(".")
            ),
        )
    })
}

fn decode_s3_key(value: &str) -> Result<String> {
    let form_encoded = value.replace('+', " ");
    urlencoding::decode(&form_encoded)
        .map(|decoded| decoded.into_owned())
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("S3 object key was not URL-encoded UTF-8: {err}"),
            )
        })
}

fn lapsed_event() -> BackendChangeEvent {
    BackendChangeEvent::Lapsed {
        since: None,
        cursor: WatchDirectoryCursor::default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqsMessage {
    message_id: String,
    receipt_handle: String,
    body: String,
}

/// The batch-entry error code as it is safe to report, in a message or a log.
///
/// `(unreportable code)` means the endpoint sent something that is not a code
/// shape; the value is withheld deliberately, not missing.
fn reportable_code(code: &str) -> String {
    provider_error::validate_code_token(code.as_bytes())
        .unwrap_or_else(|| "(unreportable code)".to_string())
}

/// The batch entry id as it is safe to report.
///
/// The id is one this crate generated (`m0`..`m{n-1}`) but it arrives echoed by
/// the endpoint, so it is provider-controlled on the wire. Allowlisting it costs
/// nothing on the paths where it already matched an entry, and is the only guard
/// on the path where it did not.
///
/// `(unreportable id)` in a message means the endpoint echoed something that is
/// not an id shape — the value is withheld deliberately, not missing.
fn reportable_entry_id(id: &str) -> String {
    provider_error::validate_code_token(id.as_bytes())
        .unwrap_or_else(|| "(unreportable id)".to_string())
}

/// Describe a failed `DeleteMessageBatch` entry without quoting provider text.
///
/// `message` is free-form and echoes the offending value — on
/// `ReceiptHandleIsInvalid` it renders as ``The input receipt handle
/// 'AQEB-secret' is not valid.``, putting a live receipt handle into every log
/// that renders the error. It is kept for classification (the callers branch on
/// `code`) and never interpolated.
///
/// `id` and `code` are allowlisted rather than trusted: the id is the batch
/// entry id this crate generated, but it arrives echoed by the endpoint, and a
/// code is a code only if it looks like one.
fn batch_failure_detail(failure: &BatchFailure) -> String {
    let entry = reportable_entry_id(&failure.id);
    match provider_error::validate_code_token(failure.code.as_bytes()) {
        Some(code) => format!("SQS DeleteMessageBatch failed for entry '{entry}': {code}"),
        None => format!(
            "SQS DeleteMessageBatch failed for entry '{entry}': no provider error code; {} byte message suppressed",
            failure.message.len()
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BatchFailure {
    id: String,
    code: String,
    message: String,
    sender_fault: bool,
}

fn parse_iso8601_to_system_time(value: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    type EventBridgeField = (&'static str, &'static str);
    type EventBridgeCase = (&'static str, &'static [EventBridgeField], ChangeKind);

    struct ManualClock {
        base: Instant,
        offset_nanos: AtomicU64,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_nanos: AtomicU64::new(0),
            }
        }

        fn advance(&self, by: Duration) {
            self.offset_nanos
                .fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.offset_nanos.load(Ordering::Relaxed))
        }
    }

    fn filter() -> WatchFilter {
        WatchFilter {
            bucket: "example-bucket".into(),
            address_root: address::parse("s3://example-bucket/").unwrap(),
            prefix_key: "photos/".into(),
            recursive: true,
            include_metadata_changes: true,
        }
    }

    fn object_kind(event: &BackendChangeEvent) -> ChangeKind {
        match event {
            BackendChangeEvent::Object { kind, .. } => *kind,
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn eventbridge_body(detail_type: &str, fields: &[(&str, &str)]) -> String {
        let mut detail = serde_json::json!({
            "bucket": {"name": "example-bucket"},
            "object": {"key": "photos/a.jpg"}
        });
        let detail_map = detail.as_object_mut().unwrap();
        for (key, value) in fields {
            detail_map.insert((*key).to_string(), Value::String((*value).to_string()));
        }
        serde_json::json!({
            "detail-type": detail_type,
            "time": "2026-05-12T10:11:12Z",
            "detail": detail
        })
        .to_string()
    }

    fn a_delivery_id() -> DeliveryId {
        let pending: SqsPending = Pending::new();
        pending.insert(
            SqsHandle {
                receipt_handle: "rh".into(),
                message_id: "m".into(),
            },
            1,
            Instant::now(),
        )
    }

    #[tokio::test]
    async fn provider_ack_dispatches_delivery_then_reports_full_and_closed() {
        let (tx, mut rx) = mpsc::channel::<DeliveryId>(1);
        let id = a_delivery_id();

        // A successful dispatch hands the delivery id to the pump, in order.
        provider_ack(tx.clone(), id)().expect("first ack dispatches");
        assert_eq!(rx.recv().await, Some(id));

        // Fill the capacity-1 channel; the next try_send returns `Full`, which
        // the handle reports as a terminal upstream error (never a dropped ack).
        provider_ack(tx.clone(), id)().expect("fills the bounded pump");
        let full = provider_ack(tx.clone(), id)().expect_err("a full pump is terminal");
        assert_eq!(full.code(), ErrorCode::Internal);

        // A closed pump (receiver gone) is likewise terminal.
        drop(rx);
        let closed = provider_ack(tx, id)().expect_err("a closed pump is terminal");
        assert_eq!(closed.code(), ErrorCode::Internal);
    }

    #[test]
    fn noop_ack_is_ok() {
        assert!(noop_ack()().is_ok());
    }

    // The masking window FIX A closes: while the terminal `Err` send is parked
    // behind the already-queued event tail, the pump must keep draining `ack_rx`
    // so the dispatcher's post-fan-out `try_send`s never fill it and mask the
    // real provider terminal with a fresh `Full`/`Closed` `Internal`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_terminal_then_drain_discards_acks_and_publishes_provider_error() {
        // A capacity-1 event channel PRE-FILLED to capacity: the terminal send
        // must block until the queued tail is consumed, modeling the dispatcher
        // draining already-queued events before it reaches the terminal `Err`.
        let (tx, rx) = std::sync::mpsc::sync_channel::<UpstreamItem>(1);
        tx.send(Ok((lapsed_event(), noop_ack())))
            .expect("prefill the queued tail");

        // Saturate the ack channel: a non-draining pump would let the
        // dispatcher's next `try_send` return `Full` and mask the real terminal.
        let (ack_tx, mut ack_rx) = mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let id = a_delivery_id();
        for _ in 0..ACK_CHANNEL_CAPACITY {
            ack_tx.try_send(id).expect("saturate the ack channel");
        }

        let cancel = CancellationToken::new();
        let provider_err = Error::new(ErrorCode::PermissionDenied, "the real provider terminal");
        let helper = {
            let tx = tx.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                publish_terminal_then_drain(&tx, provider_err, &mut ack_rx, &cancel).await;
            })
        };

        // The terminal send is still parked (the event channel is full — we have
        // not drained the tail yet), so the helper is in its concurrent-drain
        // loop. Pushing FAR more than capacity acks through therefore succeeds; a
        // non-draining pump would deadlock this loop on a `Full` channel forever.
        //
        // Bound the deadlock-prone section: a defective (non-draining) impl parks
        // the first over-capacity `send` forever, so without this timeout the test
        // would hang and rely on the CI wall-clock. 5s only ever trips on the
        // broken code — correct draining completes in microseconds.
        tokio::time::timeout(Duration::from_secs(5), async move {
            for _ in 0..(ACK_CHANNEL_CAPACITY * 2) {
                ack_tx
                    .send(id)
                    .await
                    .expect("a draining pump keeps the ack channel writable");
            }

            // Drain the queued tail: the prefilled Lapsed unblocks the terminal
            // send, then the provider `Err` surfaces as the single terminal — NOT
            // a generic "ack pump unavailable" `Internal`.
            let first = rx.recv().expect("queued tail item");
            assert!(
                matches!(first, Ok((BackendChangeEvent::Lapsed { .. }, _))),
                "the already-queued event must precede the terminal"
            );
            let terminal = rx.recv().expect("terminal item");
            let err = match terminal {
                Err(err) => err,
                Ok(_) => panic!("the terminal must be the provider Err, not another event"),
            };
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
            assert!(err.message().contains("the real provider terminal"));

            // Tear the drain tail down cleanly.
            cancel.cancel();
            drop(ack_tx);
            helper.await.expect("helper task joins");
        })
        .await
        .expect(
            "publish_terminal_then_drain deadlocked: ack draining is not concurrent with terminal publication",
        );
    }

    // === FIX (differentiator) — the producer ROUTES a zero-event
    // acknowledgement through the ack pump (an `ack_tx` enqueue) instead of
    // deleting the SQS message inline on the producer thread. With no pump
    // running, the enqueue is observable on `ack_rx` and NO inline
    // `DeleteMessageBatch` fires. The pre-fix inline-delete code hits
    // `DeleteMessageBatch` and never enqueues, so this test fails against it
    // (no enqueue AND a nonzero delete hit). Parity with the GCS
    // `zero_event_ack_is_routed_to_pump_not_acked_inline` lock. ===
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_event_ack_is_routed_to_pump_not_deleted_inline() {
        // One bucket-mismatched (zero-event) message, then empty receives so the
        // producer idles. `DeleteMessageBatch` would succeed IF called — but the
        // fixed producer must NOT call it (no pump is running to drive it).
        let mock = MockSqs::new(vec![mismatched_receive_body()]);
        let client = SqsClient {
            sqs: mock.client(),
            queue_url: mock.queue_url(),
            max_messages: 10,
            wait_seconds: 0,
            visibility_timeout_seconds: 30,
        };
        let runtime = Arc::new(SubscriptionRuntime {
            pending: Arc::new(SqsPending::new()),
            clock: Arc::new(SystemClock),
        });
        let (event_tx, _event_rx) =
            std::sync::mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, mut ack_rx) = mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();

        // NOTE: no `ack_pump` is spawned — the enqueue itself is the assertion.
        tokio::spawn(producer(
            client,
            runtime,
            event_tx,
            ack_tx,
            cancel.clone(),
            filter(),
        ));

        // The fixed producer enqueues the zero-event delivery into the pump.
        let _enqueued = tokio::time::timeout(Duration::from_secs(5), ack_rx.recv())
            .await
            .expect("zero-event ack was not routed to the pump (inline-delete regression)")
            .expect("ack channel closed unexpectedly");

        // And it did NOT delete inline on the producer thread:
        // `DeleteMessageBatch` belongs to the pump, which is not running here.
        assert_eq!(
            mock.delete_hits(),
            0,
            "the zero-event delete must be routed to the pump, not deleted inline"
        );

        cancel.cancel();
    }

    // === FIX (backpressure lock) — the producer's zero-event ack enqueue is an
    // AWAITED, backpressured `ack_tx.send`, NOT a nonblocking `try_send` that
    // drops the delivery on `Full`. With a capacity-1 ack channel PREFILLED to
    // capacity and no pump draining it, the producer inserts the one-count
    // `Pending` delivery and then must PARK on the enqueue — it neither drops
    // the delivery nor deletes inline. Only after a slot frees does the
    // synthetic `DeliveryId` reach the pump. A regression to
    // `let _ = ack_tx.try_send(delivery_id)` drops on `Full`, so the delivery
    // never appears after the slot frees (leaking the orphaned `Pending`
    // entry). Parity with the GCS `zero_event_ack_backpressures_when_pump_saturated`
    // lock. ===
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_event_ack_backpressures_when_pump_saturated() {
        // One bucket-mismatched (zero-event) message, then empty receives so the
        // producer idles after the single enqueue attempt.
        let mock = MockSqs::new(vec![mismatched_receive_body()]);
        let client = SqsClient {
            sqs: mock.client(),
            queue_url: mock.queue_url(),
            max_messages: 10,
            wait_seconds: 0,
            visibility_timeout_seconds: 30,
        };
        // Prefill a sentinel delivery through the producer's OWN pending map so
        // its id (0) precedes and differs from the producer's synthetic
        // zero-event delivery (1); `pending.len()` then doubles as the sync point.
        let pending = Arc::new(SqsPending::new());
        let sentinel = pending.insert(
            SqsHandle {
                receipt_handle: "rh-sentinel".into(),
                message_id: "m-sentinel".into(),
            },
            1,
            Instant::now(),
        );
        let runtime = Arc::new(SubscriptionRuntime {
            pending: pending.clone(),
            clock: Arc::new(SystemClock),
        });
        let (event_tx, _event_rx) =
            std::sync::mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);

        // Capacity-1 ack channel, PREFILLED to capacity (no free slot): any
        // enqueue must wait. No `ack_pump` drains it.
        let (ack_tx, mut ack_rx) = mpsc::channel::<DeliveryId>(1);
        ack_tx.try_send(sentinel).expect("prefill the single slot");

        let cancel = CancellationToken::new();
        tokio::spawn(producer(
            client,
            runtime,
            event_tx,
            ack_tx,
            cancel.clone(),
            filter(),
        ));

        // Sync point: the producer registers its one-count zero-event delivery
        // (pending grows from 1 to 2) immediately BEFORE it attempts the enqueue.
        // Once registered, the producer has reached the `ack_tx.send` (fixed) or
        // `try_send` (regression) with the slot still full.
        tokio::time::timeout(Duration::from_secs(5), async {
            while pending.len() < 2 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("producer never registered the zero-event delivery");

        // Bounded grace so the enqueue attempt executes: the fixed `send` parks
        // on the full channel; a `try_send` regression drops the delivery here.
        // The producer is BLOCKED, not racing ahead — nothing was deleted inline
        // and the single slot still holds the sentinel.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            mock.delete_hits(),
            0,
            "the zero-event delete must never fire inline on the producer thread"
        );

        // Free exactly one slot by draining the sentinel; it must still be there
        // (the parked producer did not displace it).
        assert_eq!(
            ack_rx.recv().await,
            Some(sentinel),
            "the prefilled slot must still hold the sentinel (producer parked, did not drop)"
        );

        // With a slot freed, the fixed producer's parked `send` completes and the
        // synthetic zero-event delivery reaches the pump. A `try_send` regression
        // already dropped it, so this times out.
        let synthetic = tokio::time::timeout(Duration::from_secs(5), ack_rx.recv())
            .await
            .expect(
                "backpressured zero-event ack never arrived after the slot freed (try_send drop regression)",
            )
            .expect("ack channel closed unexpectedly");
        assert_ne!(
            synthetic, sentinel,
            "the synthetic zero-event delivery must arrive, distinct from the sentinel"
        );

        // No inline delete fired throughout: the delete is the pump's job.
        assert_eq!(
            mock.delete_hits(),
            0,
            "the zero-event delete must be routed to the pump, never deleted inline"
        );

        cancel.cancel();
    }

    /// A `ReceiveMessage` JSON response carrying one bucket-mismatched
    /// notification (classifies to ZERO events for `filter()`'s bucket).
    fn mismatched_receive_body() -> String {
        let notification = serde_json::json!({
            "Records": [{
                "eventTime": "2026-05-12T10:11:12Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "other-bucket"},
                    "object": {"key": "photos/ignored.jpg"}
                }
            }]
        })
        .to_string();
        serde_json::json!({
            "Messages": [{
                "MessageId": "m-zero",
                "ReceiptHandle": "rh-zero",
                "Body": notification
            }]
        })
        .to_string()
    }

    /// A minimal in-process SQS endpoint speaking AWS JSON 1.0. `ReceiveMessage`
    /// pops a queued response body (then returns an empty batch so the producer
    /// idles); `DeleteMessageBatch` is counted and answered with success. Lets an
    /// inline test drive the real `producer` against a real `aws_sdk_sqs::Client`
    /// and observe whether a delete fires.
    struct MockSqs {
        endpoint: String,
        shared: Arc<MockSqsShared>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    struct MockSqsShared {
        receive_bodies: std::sync::Mutex<std::collections::VecDeque<String>>,
        delete_hits: std::sync::atomic::AtomicUsize,
        shutdown: std::sync::atomic::AtomicBool,
    }

    impl MockSqs {
        fn new(receive_bodies: Vec<String>) -> Self {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
            listener.set_nonblocking(true).expect("nonblocking");
            let addr = listener.local_addr().unwrap();
            let shared = Arc::new(MockSqsShared {
                receive_bodies: std::sync::Mutex::new(receive_bodies.into()),
                delete_hits: std::sync::atomic::AtomicUsize::new(0),
                shutdown: std::sync::atomic::AtomicBool::new(false),
            });
            let shared_t = shared.clone();
            let handle = std::thread::Builder::new()
                .name("ovs-test-sqs".into())
                .spawn(move || mock_sqs_accept_loop(listener, shared_t))
                .expect("spawn mock");
            Self {
                endpoint: format!("http://{addr}"),
                shared,
                handle: Some(handle),
            }
        }

        fn delete_hits(&self) -> usize {
            self.shared
                .delete_hits
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        fn queue_url(&self) -> String {
            format!("{}/000000000000/ovs-test-queue", self.endpoint)
        }

        fn client(&self) -> aws_sdk_sqs::Client {
            let conf = aws_sdk_sqs::Config::builder()
                .behavior_version(aws_sdk_sqs::config::BehaviorVersion::latest())
                .http_client(crate::client::build_http_client())
                .region(aws_sdk_sqs::config::Region::new("us-east-1"))
                .credentials_provider(aws_credential_types::Credentials::new(
                    "test-ak", "test-sk", None, None, "ovs-test",
                ))
                .endpoint_url(self.endpoint.clone())
                .build();
            aws_sdk_sqs::Client::from_conf(conf)
        }
    }

    impl Drop for MockSqs {
        fn drop(&mut self) {
            self.shared
                .shutdown
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn mock_sqs_accept_loop(listener: std::net::TcpListener, shared: Arc<MockSqsShared>) {
        loop {
            if shared.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let shared = shared.clone();
                    std::thread::spawn(move || mock_sqs_handle_conn(stream, shared));
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    }

    fn mock_sqs_handle_conn(mut stream: std::net::TcpStream, shared: Arc<MockSqsShared>) {
        use std::sync::atomic::Ordering;
        let Some(target) = mock_sqs_read_request(&mut stream) else {
            return;
        };
        let body = if target.ends_with("DeleteMessageBatch") {
            shared.delete_hits.fetch_add(1, Ordering::SeqCst);
            r#"{"Successful":[{"Id":"m1"}],"Failed":[]}"#.to_string()
        } else if target.ends_with("ReceiveMessage") {
            let queued = shared.receive_bodies.lock().unwrap().pop_front();
            match queued {
                Some(body) => body,
                None => {
                    // Drained: model a long-poll returning no messages, without
                    // busy-spinning the producer's receive loop.
                    std::thread::sleep(Duration::from_millis(25));
                    r#"{"Messages":[]}"#.to_string()
                }
            }
        } else {
            "{}".to_string()
        };
        mock_sqs_write_response(&mut stream, &body);
    }

    /// Read one HTTP/1.1 request, returning its `X-Amz-Target` header value (the
    /// AWS JSON operation selector). The body is consumed per `Content-Length`.
    fn mock_sqs_read_request(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read as _;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        let header_end = loop {
            let n = stream.read(&mut buf).ok()?;
            if n == 0 {
                return None;
            }
            bytes.extend_from_slice(&buf[..n]);
            if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let target = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-amz-target")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while bytes.len() < body_start + content_length {
            let n = stream.read(&mut buf).ok()?;
            if n == 0 {
                return None;
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        Some(target)
    }

    fn mock_sqs_write_response(stream: &mut std::net::TcpStream, body: &str) {
        use std::io::Write as _;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    #[test]
    fn direct_notification_maps_created_event() {
        let body = r#"{
            "Records": [{
                "eventTime": "2026-05-12T10:11:12Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "example-bucket"},
                    "object": {"key": "photos/cat%20one.jpg", "eTag": "abc", "versionId": "v1", "size": 12}
                }
            }]
        }"#;
        let events = parse_notification_body(body, &filter()).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            BackendChangeEvent::Object {
                address,
                kind,
                etag,
                version,
                size,
                mtime,
                cursor,
                ..
            } => {
                assert_eq!(
                    address.as_str(),
                    "s3://example-bucket/photos/cat%20one.jpg?versionId=v1"
                );
                assert_eq!(*kind, ChangeKind::Created);
                assert_eq!(etag.as_deref(), Some("abc"));
                assert_eq!(version.as_deref(), Some("v1"));
                assert_eq!(*size, Some(12));
                // S3 notifications do not carry a separate lastModified.
                assert!(mtime.is_none());
                assert!(cursor.0.is_empty());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn direct_notification_maps_delete_restore_tagging_and_lifecycle_events() {
        let cases = [
            ("ObjectRemoved:Delete", ChangeKind::Deleted),
            ("ObjectRemoved:DeleteMarkerCreated", ChangeKind::Deleted),
            ("ObjectRestore:Completed", ChangeKind::Modified),
            ("ObjectRestore:Delete", ChangeKind::MetadataChanged),
            ("ObjectTagging:Put", ChangeKind::MetadataChanged),
            ("ObjectTagging:Delete", ChangeKind::MetadataChanged),
            ("LifecycleExpiration:Delete", ChangeKind::Deleted),
            (
                "LifecycleExpiration:DeleteMarkerCreated",
                ChangeKind::Deleted,
            ),
        ];
        let records: Vec<Value> = cases
            .iter()
            .enumerate()
            .map(|(index, (event_name, _))| {
                serde_json::json!({
                    "eventTime": "2026-05-12T10:11:12Z",
                    "eventName": event_name,
                    "s3": {
                        "bucket": {"name": "example-bucket"},
                        "object": {"key": format!("photos/{index}.jpg")}
                    }
                })
            })
            .collect();
        let body = serde_json::json!({ "Records": records }).to_string();

        let events = parse_notification_body(&body, &filter()).unwrap();
        let kinds: Vec<_> = events.iter().map(object_kind).collect();
        let expected: Vec<_> = cases.iter().map(|(_, kind)| *kind).collect();

        assert_eq!(kinds, expected);
    }

    #[test]
    fn eventbridge_maps_metadata_and_respects_gate() {
        let body = r#"{
            "detail-type": "Object Tags Added",
            "time": "2026-05-12T10:11:12Z",
            "detail": {
                "bucket": {"name": "example-bucket"},
                "object": {"key": "photos/a.jpg", "etag": "def", "version-id": "v2", "size": 3}
            }
        }"#;
        let events = parse_notification_body(body, &filter()).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            BackendChangeEvent::Object { kind, .. } => {
                assert_eq!(*kind, ChangeKind::MetadataChanged);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let mut no_metadata = filter();
        no_metadata.include_metadata_changes = false;
        assert!(
            parse_notification_body(body, &no_metadata)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn eventbridge_maps_created_deleted_restore_and_metadata_events() {
        let cases: &[EventBridgeCase] = &[
            (
                "Object Created",
                &[("reason", "PutObject")],
                ChangeKind::Created,
            ),
            (
                "Object Created",
                &[("reason", "POST Object")],
                ChangeKind::Created,
            ),
            (
                "Object Created",
                &[("reason", "CopyObject")],
                ChangeKind::Created,
            ),
            (
                "Object Created",
                &[("reason", "CompleteMultipartUpload")],
                ChangeKind::Created,
            ),
            (
                "Object Deleted",
                &[("deletion-type", "Delete Marker Created")],
                ChangeKind::Deleted,
            ),
            (
                "Object Deleted",
                &[("deletion-type", "Permanently Deleted")],
                ChangeKind::Deleted,
            ),
            ("Object Restore Completed", &[], ChangeKind::Modified),
            ("Object Restore Expired", &[], ChangeKind::MetadataChanged),
            ("Object ACL Updated", &[], ChangeKind::MetadataChanged),
            (
                "Object Storage Class Changed",
                &[],
                ChangeKind::MetadataChanged,
            ),
            (
                "Object Access Tier Changed",
                &[],
                ChangeKind::MetadataChanged,
            ),
        ];

        for (detail_type, fields, expected) in cases {
            let body = eventbridge_body(detail_type, fields);
            let events = parse_notification_body(&body, &filter()).unwrap();

            assert_eq!(events.len(), 1, "event should map: {detail_type}");
            assert_eq!(object_kind(&events[0]), *expected, "{detail_type}");
        }
    }

    #[test]
    fn non_recursive_filter_drops_nested_children() {
        let mut one_level = filter();
        one_level.recursive = false;
        let body = r#"{
            "Records": [{
                "eventTime": "2026-05-12T10:11:12Z",
                "eventName": "ObjectRemoved:Delete",
                "s3": {
                    "bucket": {"name": "example-bucket"},
                    "object": {"key": "photos/2026/a.jpg"}
                }
            }]
        }"#;
        assert!(
            parse_notification_body(body, &one_level)
                .unwrap()
                .is_empty()
        );
    }

    /// An SQS batch-entry `message` is free-form provider text and echoes the
    /// offending value — on `ReceiptHandleIsInvalid` it quotes a LIVE receipt
    /// handle. It must never reach a surfaced error.
    #[test]
    fn a_batch_failure_message_never_reaches_the_error() {
        let failure = BatchFailure {
            id: "m0".into(),
            code: "ReceiptHandleIsInvalid".into(),
            message: "The input receipt handle 'AQEBk7h2secretHANDLE' is not valid.".into(),
            sender_fault: true,
        };
        let detail = batch_failure_detail(&failure);
        assert_eq!(
            detail,
            "SQS DeleteMessageBatch failed for entry 'm0': ReceiptHandleIsInvalid"
        );
        for leaked in ["AQEBk7h2secretHANDLE", "receipt handle", "not valid"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
    }

    /// The code is allowlisted rather than trusted: the endpoint controls it,
    /// and it is not reported unless it looks like a token.
    #[test]
    fn a_batch_failure_code_is_allowlisted() {
        let hostile = BatchFailure {
            id: "m0".into(),
            code: "AccessDenied X-Amz-Signature=4a7f".into(),
            message: "nope".into(),
            sender_fault: true,
        };
        let detail = batch_failure_detail(&hostile);
        assert!(detail.contains("byte message suppressed"), "{detail}");
        for leaked in ["X-Amz-Signature", "4a7f"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
    }

    /// A transient failure logs the code rather than surfacing it, but a log
    /// line is exactly where this material would land, so it gets the same
    /// allowlist.
    #[test]
    fn a_transient_batch_failure_does_not_log_a_raw_code() {
        assert_eq!(
            reportable_code("AccessDenied X-Amz-Signature=4a7f"),
            "(unreportable code)"
        );
        assert_eq!(reportable_code("AccessDenied"), "AccessDenied");
    }

    /// A hostile entry id can only reach the UNRECOGNIZED-id path, because
    /// every other path required `entry_deadline` to match it as `m<index>`
    /// first. So that path is where the id must be allowlisted, and this drives
    /// `classify_batch_failures` rather than the helper to prove it.
    #[test]
    fn an_unrecognized_entry_id_is_not_echoed() {
        let clock = ManualClock::new();
        let batch = vec![AckEntry {
            handle: SqsHandle {
                receipt_handle: "rh".into(),
                message_id: "m".into(),
            },
            deadline: clock.now() + Duration::from_secs(30),
        }];
        let failure = BatchFailure {
            id: "m0 X-Amz-Signature=4a7f9c".into(),
            code: "AccessDenied".into(),
            message: "nope".into(),
            sender_fault: true,
        };
        let AckOutcome::Fatal(err) = classify_batch_failures(vec![failure], &batch, &clock) else {
            panic!("an unrecognized entry id is terminal");
        };
        assert!(
            err.message().contains("(unreportable id)"),
            "{}",
            err.message()
        );
        for leaked in ["X-Amz-Signature", "4a7f9c"] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} survived: {}",
                err.message()
            );
        }
    }

    #[test]
    fn expired_receipt_is_transient_only_after_deadline_skew() {
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(30);
        // The `Failed` entry names `m0`, which maps to the single batch entry's
        // deadline for the stale-skew decision.
        let batch = vec![AckEntry {
            handle: SqsHandle {
                receipt_handle: "rh".into(),
                message_id: "m".into(),
            },
            deadline,
        }];
        let failure = BatchFailure {
            id: "m0".into(),
            code: "InvalidParameterValue".into(),
            message: "The receipt handle has expired.".into(),
            sender_fault: true,
        };
        assert!(matches!(
            classify_batch_failures(vec![failure.clone()], &batch, &clock),
            AckOutcome::Fatal(_)
        ));
        clock.advance(Duration::from_secs(36));
        assert!(matches!(
            classify_batch_failures(vec![failure], &batch, &clock),
            AckOutcome::Transient
        ));
    }

    // === FIX #1 (batching) — the pump collects up to `DELETE_BATCH_MAX` READY
    // receipts and deletes them in ONE `DeleteMessageBatch`. Drives the real
    // `ack_pump`: many enqueued single-count deliveries must drain via a small
    // number of batched delete calls, not one call per message. A per-message
    // regression fires one delete per delivery. ===
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ack_pump_batches_ready_deletes_into_one_call() {
        let mock = MockSqs::new(Vec::new());
        let client = SqsClient {
            sqs: mock.client(),
            queue_url: mock.queue_url(),
            max_messages: 10,
            wait_seconds: 0,
            visibility_timeout_seconds: 30,
        };
        let runtime = Arc::new(SubscriptionRuntime {
            pending: Arc::new(SqsPending::new()),
            clock: Arc::new(SystemClock),
        });
        let (event_tx, _event_rx) =
            std::sync::mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, ack_rx) = mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();

        // Enqueue 25 one-count (ready) deliveries BEFORE the pump starts, so the
        // first `recv` is followed by a full `try_recv` drain: at 10 per batch
        // that is 3 delete calls (10 + 10 + 5), never 25.
        let count = 25usize;
        for i in 0..count {
            let id = runtime.pending.insert(
                SqsHandle {
                    receipt_handle: format!("rh-{i}"),
                    message_id: format!("m-{i}"),
                },
                1,
                Instant::now() + Duration::from_secs(30),
            );
            ack_tx.try_send(id).expect("enqueue ready delivery");
        }

        let pump = tokio::spawn(ack_pump(
            client,
            runtime.clone(),
            ack_rx,
            event_tx,
            cancel.clone(),
        ));

        // All deliveries drain (their pending entries are removed) with far fewer
        // delete calls than messages.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !runtime.pending.is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("all ready deliveries must drain through the batched pump");

        let hits = mock.delete_hits();
        assert!(
            hits < count,
            "batched deletes must use fewer calls than messages: {hits} calls for {count} messages"
        );
        assert!(
            hits <= count.div_ceil(DELETE_BATCH_MAX) + 1,
            "expected ~{} batched calls, got {hits}",
            count.div_ceil(DELETE_BATCH_MAX)
        );

        cancel.cancel();
        drop(ack_tx);
        let _ = pump.await;
    }
}
