// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use ovstorage_plugin::subscription::{
    AckHandle, AckingStream, Clock, CoalesceKey, DeliveryId, Pending, PendingDecrement,
    SystemClock, UpstreamFactory,
};
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, CancellationToken, ChangeKind, Error, ErrorCode,
    ErrorContext, ResolvedTarget, Result, Url, WatchDirectoryCursor, WatchDirectoryOptions,
    address,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc as tokio_mpsc;
use tracing::warn;

use crate::{GcsBackend, GcsObjectRef, MaybeBearerAuth, relative_key_for};

const DEFAULT_PUBSUB_ENDPOINT: &str = "https://pubsub.googleapis.com";
const ACK_STALE_SKEW: Duration = Duration::from_secs(5);
const EMPTY_PULL_IDLE_INTERVAL: Duration = Duration::from_secs(1);
/// Bounded capacity of the event channel between the async Pub/Sub producer
/// and the coalescer's blocking fan-out dispatcher.
const EVENT_CHANNEL_CAPACITY: usize = 256;
/// Bounded capacity of the ack pump channel. The dispatcher dispatches each
/// event's ack nonblockingly; a `Full`/`Closed` `try_send` is a terminal
/// upstream error (never a silently-dropped ack).
const ACK_CHANNEL_CAPACITY: usize = 256;
/// Maximum ackIds coalesced into one Pub/Sub `acknowledge` call. Bounded by the
/// ack channel so a drain-until-empty collects at most one channel's worth.
const ACK_BATCH_MAX: usize = ACK_CHANNEL_CAPACITY;

/// One item on the coalescer's [`AckingStream`]: an event plus the nonblocking
/// [`AckHandle`] the dispatcher invokes after fanning it out, or a terminal
/// error (an async provider ack failure surfaces here, drained after any
/// already-queued events).
type UpstreamItem = Result<(BackendChangeEvent, AckHandle)>;

/// The future the [`UpstreamFactory`] returns.
type UpstreamFuture = Pin<Box<dyn std::future::Future<Output = Result<AckingStream>> + Send>>;

#[derive(Debug, Clone)]
pub struct PubsubHandle {
    pub ack_id: String,
}

pub type PubsubPending = Pending<PubsubHandle>;

#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    pub ack_deadline_seconds: u32,
    pub exactly_once_delivery: bool,
}

#[derive(Clone)]
struct PubsubClient {
    http: reqwest::Client,
    auth: Arc<crate::auth::Authenticator>,
    subscription: String,
    endpoint: String,
}

pub async fn watch_directory(
    backend: &GcsBackend,
    prefix: ResolvedTarget,
    opts: WatchDirectoryOptions,
    cancel: Option<CancellationToken>,
) -> Result<BackendChangeStream> {
    // Bucket rejection stays here (via `parse_target`); the upstream itself
    // opens at the connection root so one Pub/Sub consumer feeds every prefix.
    let subscriber_object = directory_watch_target(backend.parse_target(&prefix, false)?).object;
    // This subscriber's prefix view; the coalescer filters the connection-wide
    // feed against it before this subscriber's queue.
    let subscriber_prefix =
        address::join_relative(&backend.config.address_root, &subscriber_object)?;

    let Some(subscription) = backend.config.pubsub_subscription.clone() else {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "GCS watch_directory requires pubsub_subscription",
        ));
    };

    // Coalescing key = the Pub/Sub subscription path: a stable per-connection
    // resource id, independent of prefix/cadence.
    let key: CoalesceKey = subscription.clone();

    // Reuse GCS's request-level cadence normalizer; the coalescer mins the
    // opening cohort's `effective_cadence`s and passes that min to the factory.
    let effective_cadence = empty_pull_idle_interval(&opts);

    let http = backend.http.clone();
    let auth = backend.auth.clone();
    let endpoint = backend
        .config
        .pubsub_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_PUBSUB_ENDPOINT.to_string());
    let address_root = backend.config.address_root.clone();
    let bucket = backend.config.bucket.clone();
    let pull_max = backend.config.pubsub_pull_max;

    let upstream: UpstreamFactory =
        Arc::new(move |cancel: CancellationToken, cadence: Duration| {
            let client = PubsubClient {
                http: http.clone(),
                auth: auth.clone(),
                subscription: subscription.clone(),
                endpoint: endpoint.clone(),
            };
            let address_root = address_root.clone();
            let bucket = bucket.clone();
            Box::pin(async move {
                // Fetch the subscription config ONCE, inside the factory, under
                // the upstream cancel token — before starting the puller + ack
                // pump. Its `exactly_once_delivery` + `ack_deadline_seconds`
                // configure THIS physical upstream's ack pump. Running it here
                // (not per joining subscriber) keeps a joiner from performing its
                // own network request against an already-healthy shared upstream.
                let watch_config = client.get_subscription(Some(&cancel)).await?;

                // The upstream opens at the CONNECTION ROOT (recursive +
                // metadata) so one Pub/Sub consumer feeds every prefix on the
                // connection; per-subscriber prefix filtering is the coalescer's
                // job.
                let root_target = GcsObjectRef {
                    bucket,
                    object: String::new(),
                    selector: None,
                };
                let root_opts = WatchDirectoryOptions {
                    recursive: true,
                    include_metadata_changes: true,
                    since: None,
                    poll_interval: cadence,
                };
                let pending = Arc::new(PubsubPending::new());
                let clock = Arc::new(SystemClock);
                let (event_tx, event_rx) =
                    mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
                let (ack_tx, ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);

                tokio::spawn(ack_pump(
                    client.clone(),
                    pending.clone(),
                    ack_rx,
                    event_tx.clone(),
                    cancel.clone(),
                    watch_config.clone(),
                    clock.clone(),
                ));
                tokio::spawn(producer(ProducerContext {
                    client,
                    event_tx,
                    ack_tx,
                    cancel,
                    target: root_target,
                    address_root,
                    opts: root_opts,
                    pull_max,
                    // The negotiated cohort-minimum cadence drives the
                    // empty-pull idle pacing, NOT the joining request's
                    // `opts.poll_interval`.
                    cadence,
                    watch_config,
                    pending,
                    clock,
                }));

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

fn directory_watch_target(mut target: GcsObjectRef) -> GcsObjectRef {
    target.object = address::directory_key(&target.object);
    target
}

struct ProducerContext {
    client: PubsubClient,
    event_tx: mpsc::SyncSender<UpstreamItem>,
    ack_tx: tokio_mpsc::Sender<DeliveryId>,
    cancel: CancellationToken,
    target: GcsObjectRef,
    address_root: Url,
    opts: WatchDirectoryOptions,
    pull_max: u32,
    cadence: Duration,
    watch_config: SubscriptionConfig,
    pending: Arc<PubsubPending>,
    clock: Arc<SystemClock>,
}

/// Drive one Pub/Sub pull consumer, feeding parsed events (each paired with a
/// nonblocking [`AckHandle`]) to the coalescer's dispatcher. One Pub/Sub
/// message classifies into at most one event; the refcounted delivery is acked
/// exactly once after its event's ack handle has fired.
async fn producer(ctx: ProducerContext) {
    let ProducerContext {
        client,
        event_tx,
        ack_tx,
        cancel,
        target,
        address_root,
        opts,
        pull_max,
        cadence,
        watch_config,
        pending,
        clock,
    } = ctx;

    let mut backoff = Duration::from_millis(250);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match client.pull(pull_max, &cancel).await {
            Ok(messages) => {
                if messages.is_empty() {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(cadence) => {}
                    }
                    continue;
                }
                backoff = Duration::from_millis(250);
                for received in messages {
                    if cancel.is_cancelled() {
                        return;
                    }
                    let now = clock.now();
                    let handle = PubsubHandle {
                        ack_id: received.ack_id.clone(),
                    };
                    let deadline =
                        now + Duration::from_secs(u64::from(watch_config.ack_deadline_seconds));
                    let events =
                        match classify_message(&received.message, &target, &address_root, &opts) {
                            Ok(events) => events,
                            Err(err) => {
                                warn!(
                                    plugin = "gcs",
                                    error = %err.message(),
                                    "malformed Pub/Sub storage notification"
                                );
                                vec![lapsed_event()]
                            }
                        };
                    if events.is_empty() {
                        // No event this subscriber cohort carries an ack for (the
                        // record was bucket-mismatched, filtered, or a
                        // replacement delete). Route the acknowledgement THROUGH
                        // THE ACK PUMP as a one-count delivery — the same
                        // `provider_ack`/`ack_tx` mechanism the eventful path uses
                        // — so every async provider ack failure originates in the
                        // pump and gets its concurrent publish-and-drain masking
                        // protection ([`publish_terminal_then_drain`]). The
                        // producer never performs a terminal `send_item(Err)` for
                        // a provider Fatal: from this thread it cannot drain
                        // `ack_rx`, so a parked terminal send would let the
                        // dispatcher's queued-tail acks fill `ack_rx` and mask the
                        // real provider error with a generic `Full` `Internal`.
                        //
                        // The enqueue is an AWAITED send, not a nonblocking drop:
                        // this producer thread can await, so a saturated pump
                        // applies natural backpressure (we stop pulling until the
                        // pump drains) rather than dropping the ack and orphaning
                        // the one-count `Pending` entry we just inserted. `Closed`
                        // means the pump receiver is gone (teardown), so we stop
                        // the producer; racing `cancel` keeps the send from
                        // hanging when teardown is under way (the `Pending` entry
                        // drops with the runtime).
                        let delivery_id = pending.insert(handle, 1, deadline);
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => return,
                            res = ack_tx.send(delivery_id) => {
                                if res.is_err() {
                                    // Pump receiver gone => teardown underway;
                                    // stop the producer.
                                    return;
                                }
                            }
                        }
                        continue;
                    }

                    // One refcounted delivery for the whole message; each event's
                    // AckHandle decrements it, and the last one triggers the ack.
                    let delivery_id = pending.insert(handle, events.len(), deadline);
                    for event in events {
                        let ack = provider_ack(ack_tx.clone(), delivery_id);
                        if send_item(&event_tx, Ok((event, ack))).await.is_err() {
                            // The dispatcher (and thus the last subscriber) is
                            // gone; stop this upstream.
                            cancel.cancel();
                            return;
                        }
                    }
                }
            }
            Err(err) if is_retryable_pull_error(err.code()) => {
                warn!(plugin = "gcs", error = %err.message(), "Pub/Sub pull failed transiently");
                // A transient stall is a gap: broadcast a Lapsed (no message to
                // ack, so a no-op ack) and back off.
                if send_item(&event_tx, Ok((lapsed_event(), noop_ack())))
                    .await
                    .is_err()
                {
                    cancel.cancel();
                    return;
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(4));
            }
            Err(err) if err.code() == ErrorCode::Cancelled => return,
            Err(err) => {
                let _ = send_item(&event_tx, Err(err)).await;
                return;
            }
        }
    }
}

fn lapsed_event() -> BackendChangeEvent {
    BackendChangeEvent::Lapsed {
        since: None,
        cursor: WatchDirectoryCursor::default(),
    }
}

fn is_retryable_pull_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Transient | ErrorCode::DeadlineExceeded | ErrorCode::ResourceExhausted
    )
}

fn empty_pull_idle_interval(opts: &WatchDirectoryOptions) -> Duration {
    if opts.poll_interval.is_zero() {
        EMPTY_PULL_IDLE_INTERVAL
    } else {
        opts.poll_interval
    }
}

/// Drain ack requests, decrement the owning delivery's refcount, and
/// acknowledge the Pub/Sub message when its last event acks. A provider (ack)
/// failure is published as a terminal `Err` on the event stream — ordered AFTER
/// any events already queued ahead of it — so the coalescer tears the fan-out
/// down and reopens; an ack is never silently lost.
///
/// Publishing that terminal `Err` and draining `ack_rx` run CONCURRENTLY (see
/// [`publish_terminal_then_drain`]). The terminal send is a blocking send on the
/// bounded event channel; while it is parked behind the already-queued tail the
/// pump keeps receiving and discarding acks so the dispatcher's post-fan-out
/// `provider_ack.try_send` never sees a `Full`/`Closed` channel and masks the
/// real terminal with a fresh generic `Internal`. Each discarded delivery
/// redelivers via Pub/Sub at-least-once.
async fn ack_pump(
    client: PubsubClient,
    pending: Arc<PubsubPending>,
    mut ack_rx: tokio_mpsc::Receiver<DeliveryId>,
    event_tx: mpsc::SyncSender<UpstreamItem>,
    cancel: CancellationToken,
    watch_config: SubscriptionConfig,
    clock: Arc<SystemClock>,
) {
    while let Some(delivery_id) = ack_rx.recv().await {
        // Batch the network acks. The dispatcher's fan-out is in-memory (fast)
        // while each Pub/Sub `acknowledge` is a round-trip (slow), so a
        // per-message ack could never keep pace with sustained delivery — the
        // bounded ack channel would fill and a `provider_ack.try_send` would
        // return `Full`, terminating the stream on a routine backlog. After
        // receiving one id, drain up to `ACK_BATCH_MAX - 1` more READY receipts
        // nonblockingly and acknowledge them all in ONE call. This lifts ack
        // throughput to match batched delivery, so the channel drains and `Full`
        // is a pathological-only backstop. Only READY deliveries (refcount hit 0
        // in `decrement`) contribute an ackId; a still-`Pending` decrement adds
        // nothing but is still consumed from the channel.
        let mut batch: Vec<AckEntry> = Vec::new();
        match decrement_entry(&pending, delivery_id) {
            Ok(Some(entry)) => batch.push(entry),
            Ok(None) => {}
            Err(id) => {
                publish_terminal_then_drain(
                    &event_tx,
                    missing_delivery_error(id),
                    &mut ack_rx,
                    &cancel,
                )
                .await;
                return;
            }
        }
        while batch.len() < ACK_BATCH_MAX {
            match ack_rx.try_recv() {
                Ok(id) => match decrement_entry(&pending, id) {
                    Ok(Some(entry)) => batch.push(entry),
                    Ok(None) => continue,
                    Err(id) => {
                        publish_terminal_then_drain(
                            &event_tx,
                            missing_delivery_error(id),
                            &mut ack_rx,
                            &cancel,
                        )
                        .await;
                        return;
                    }
                },
                // Channel drained or closed: acknowledge what we have. A closed
                // channel is observed as `None` on the next outer `recv`.
                Err(tokio_mpsc::error::TryRecvError::Empty)
                | Err(tokio_mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        if batch.is_empty() {
            continue;
        }
        match client
            .ack_batch(&batch, &watch_config, clock.as_ref(), &cancel)
            .await
        {
            AckOutcome::Success | AckOutcome::ExpectedStale => {}
            AckOutcome::Transient(err) => {
                warn!(plugin = "gcs", error = %err.message(), "Pub/Sub ack failed transiently");
            }
            AckOutcome::Fatal(err) => {
                publish_terminal_then_drain(&event_tx, err, &mut ack_rx, &cancel).await;
                return;
            }
        }
    }
}

/// One ready receipt awaiting a batched acknowledge: the ackId and its ack
/// deadline (for stale-ack classification under exactly-once delivery).
#[derive(Clone, Debug)]
struct AckEntry {
    ack_id: String,
    deadline: Instant,
}

/// Decrement `id`'s refcount: `Ok(Some(entry))` when it was the last event of its
/// message (ack it), `Ok(None)` when other events remain (nothing to ack yet),
/// `Err(id)` when the delivery is unknown (a terminal invariant violation).
fn decrement_entry(
    pending: &PubsubPending,
    id: DeliveryId,
) -> std::result::Result<Option<AckEntry>, DeliveryId> {
    match pending.decrement(id) {
        Ok(PendingDecrement::Pending) => Ok(None),
        Ok(PendingDecrement::Ready { handle, deadline }) => Ok(Some(AckEntry {
            ack_id: handle.ack_id,
            deadline,
        })),
        Err(_) => Err(id),
    }
}

fn missing_delivery_error(id: DeliveryId) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("GCS Pub/Sub missing pending delivery {id:?}"),
    )
}

/// Publish the terminal `Err` on the event stream while CONCURRENTLY draining
/// (discarding) ack requests, then keep discarding until teardown.
///
/// The terminal send is a blocking [`mpsc::SyncSender::send`] on the bounded
/// event channel; if that channel is full it parks until the dispatcher drains
/// the events already queued ahead of it. While the send is parked the pump must
/// keep receiving from `ack_rx`: as the dispatcher fans out each queued event it
/// calls `provider_ack.try_send`, and an unread `ack_rx` fills to capacity,
/// turning the next `try_send` into a fresh `Full` `Internal` the dispatcher
/// would terminate on BEFORE reaching the real provider `Err`. Draining
/// concurrently keeps those `try_send`s succeeding, so the provider error stays
/// the single deterministic terminal after the queued tail. Cancellation is
/// prioritized (biased) over both completing the send and receiving an ack.
async fn publish_terminal_then_drain(
    tx: &mpsc::SyncSender<UpstreamItem>,
    err: Error,
    ack_rx: &mut tokio_mpsc::Receiver<DeliveryId>,
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

/// The tail of [`publish_terminal_then_drain`]: once the terminal `Err` is on
/// the event stream, keep accepting and discarding ack requests so the
/// dispatcher's post-fan-out `provider_ack` calls keep succeeding — no
/// `Full`/`Closed` `Internal` masks the real terminal already queued on the
/// event stream. Exits when the dispatcher cancels the upstream (teardown) or
/// the ack channel closes.
async fn drain_acks_until_cancel(
    ack_rx: &mut tokio_mpsc::Receiver<DeliveryId>,
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

/// A nonblocking [`AckHandle`] that dispatches this event's acknowledge into the
/// bounded ack pump. A `Full`/`Closed` `try_send` is a terminal upstream error.
fn provider_ack(ack_tx: tokio_mpsc::Sender<DeliveryId>, delivery_id: DeliveryId) -> AckHandle {
    Box::new(move || {
        ack_tx.try_send(delivery_id).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("GCS Pub/Sub ack pump unavailable: {err}"),
            )
        })
    })
}

/// A no-op ack for events with no backing Pub/Sub message to acknowledge (e.g. a
/// synthesized `Lapsed`).
fn noop_ack() -> AckHandle {
    Box::new(|| Ok(()))
}

/// Send an item into the blocking event channel from an async task without
/// stalling the runtime on a full channel. `Err` means the receiver (the
/// dispatcher) is gone.
async fn send_item(
    tx: &mpsc::SyncSender<UpstreamItem>,
    item: UpstreamItem,
) -> std::result::Result<(), ()> {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || tx.send(item).map_err(|_| ()))
        .await
        .map_err(|_| ())?
}

impl PubsubClient {
    async fn bearer_token(&self) -> Result<String> {
        self.auth.access_token().await
    }

    /// Acquire a bearer token under the upstream cancellation token.
    /// [`crate::auth::Authenticator::access_token`] may perform an unbounded
    /// network refresh; racing it against `cancel` keeps an all-waiters
    /// cancellation from leaving a detached factory (or pull/ack pump) alive
    /// across the refresh while the coalescer has already released its slots.
    async fn bearer_token_cancelable(&self, cancel: &CancellationToken) -> Result<String> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new(ErrorCode::Cancelled, "cancelled by host")),
            token = self.bearer_token() => token,
        }
    }

    fn subscription_url(&self) -> String {
        format!("{}/v1/{}", self.endpoint, self.subscription)
    }

    fn pull_url(&self) -> String {
        format!(
            "{}/{}:pull",
            self.subscription_url_base(),
            self.subscription
        )
    }

    fn ack_url(&self) -> String {
        format!(
            "{}/{}:acknowledge",
            self.subscription_url_base(),
            self.subscription
        )
    }

    fn subscription_url_base(&self) -> String {
        format!("{}/v1", self.endpoint)
    }

    async fn get_subscription(
        &self,
        cancel: Option<&CancellationToken>,
    ) -> Result<SubscriptionConfig> {
        let token = match cancel {
            Some(cancel) => self.bearer_token_cancelable(cancel).await?,
            None => self.bearer_token().await?,
        };
        let request = self
            .http
            .get(self.subscription_url())
            .maybe_bearer_auth(token);
        let response = send_with_cancel(request, cancel).await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(map_pubsub_status(status, &body));
        }
        let parsed: SubscriptionGetResponse = serde_json::from_str(&body).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "Pub/Sub subscription response was not JSON: {}",
                    crate::error_body::decode_failure(&err, body.len())
                ),
            )
        })?;
        Ok(SubscriptionConfig {
            ack_deadline_seconds: normalize_ack_deadline(parsed.ack_deadline_seconds),
            exactly_once_delivery: parsed.enable_exactly_once_delivery,
        })
    }

    async fn pull(
        &self,
        max_messages: u32,
        cancel: &CancellationToken,
    ) -> Result<Vec<ReceivedMessage>> {
        let token = self.bearer_token_cancelable(cancel).await?;
        let request = self
            .http
            .post(self.pull_url())
            .maybe_bearer_auth(token)
            .json(&PullRequest {
                max_messages: max_messages.max(1),
            });
        let response = send_with_cancel(request, Some(cancel)).await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(map_pubsub_status(status, &body));
        }
        parse_pull_response(&body)
    }

    /// Acknowledge a whole batch of ready receipts in one `:acknowledge`. Pub/Sub
    /// `acknowledge` is all-or-nothing at the HTTP level (one status/body for the
    /// whole call), so a mixed exactly-once 400 that could be EITHER a stale
    /// receipt OR a genuine pre-deadline invalid cannot be told apart from that one
    /// status. This method fully isolates that ambiguity so a genuine fatal ALWAYS
    /// surfaces (no indefinite masking) with a bounded amount of extra work.
    ///
    /// On an ambiguous mixed 400 [`classify_ack_batch`] returns
    /// [`AckBatchClass::IsolateFresh`] with the fresh (pre-deadline) subset; the
    /// stale entries are dropped as `ExpectedStale` and redeliver. The fresh subset
    /// is re-`acknowledge`d:
    /// - success (or any non-400) ⇒ the original 400 was the stale receipt: the
    ///   fresh receipts are now resolved (continue).
    /// - a 400 with NO fresh entry gone stale ⇒ nothing but a genuine pre-deadline
    ///   invalid explains it ⇒ `Fatal` (terminal).
    /// - a 400 still MIXED (some fresh entries crossed their deadline during the
    ///   re-ack window, some stayed fresh) ⇒ still ambiguous: the newly-stale
    ///   entries drop (`ExpectedStale`) and each STILL-fresh receipt is isolated
    ///   ONE ackId per call. A lone fresh receipt that 400s is unambiguous ⇒
    ///   `Fatal`; one that succeeds is resolved; one that went stale redelivers.
    ///
    /// Bound: the fresh subset (≤ `ACK_BATCH_MAX`) shrinks strictly at every step
    /// (acked/stale/isolated entries are removed), and per-ackId isolation only
    /// runs after the mixed re-ack already dropped ≥1 newly-stale entry, so total
    /// `:acknowledge` calls on this error path is at most `batch.len()` — O(number
    /// of entries). No unbounded recursion, no livelock. This replaces the prior
    /// one-retry rule, which classified a mixed re-ack as blanket `ExpectedStale`
    /// and could indefinitely mask a real pre-deadline invalid under sustained
    /// backlog. Every receipt is `:acknowledge`d successfully at most once across
    /// the whole isolation: a 400 commits nothing server-side, so re-acking a
    /// rejected id is safe, and once an id succeeds it is never re-acked.
    async fn ack_batch<C: Clock>(
        &self,
        batch: &[AckEntry],
        config: &SubscriptionConfig,
        clock: &C,
        cancel: &CancellationToken,
    ) -> AckOutcome {
        let ack_ids = batch.iter().map(|entry| entry.ack_id.clone()).collect();
        let (status, body) = match self.acknowledge(ack_ids, cancel).await {
            Ok(response) => response,
            Err(outcome) => return outcome,
        };
        let fresh = match classify_ack_batch(status, &body, config, batch, clock.now()) {
            AckBatchClass::Outcome(outcome) => return outcome,
            AckBatchClass::IsolateFresh(fresh) => fresh,
        };
        // Re-ack ONLY the fresh subset to disambiguate a real fatal from the
        // dropped stale receipt.
        let fresh_ids = fresh.iter().map(|entry| entry.ack_id.clone()).collect();
        let (status, body) = match self.acknowledge(fresh_ids, cancel).await {
            Ok(response) => response,
            Err(outcome) => return outcome,
        };
        let individual = match classify_fresh_batch(status, &body, config, &fresh, clock.now()) {
            FreshBatchClass::Outcome(outcome) => return outcome,
            FreshBatchClass::IsolateIndividually(entries) => entries,
        };
        // Still-mixed re-ack: the still-fresh receipts remain ambiguous as a group
        // (a newly-stale entry could be the sole cause, or one of them is genuinely
        // invalid). Isolate each ONE ackId per call so a genuine pre-deadline
        // invalid is acked alone and its 400 is unambiguous. Each iteration removes
        // one entry, so this loop is bounded by `individual.len()`.
        for entry in individual {
            let ack_id = entry.ack_id.clone();
            let (status, body) = match self.acknowledge(vec![ack_id], cancel).await {
                Ok(response) => response,
                Err(outcome) => return outcome,
            };
            match classify_ack_response(status, &body, config, entry.deadline, clock.now()) {
                AckOutcome::Fatal(err) => return AckOutcome::Fatal(err),
                AckOutcome::Transient(err) => return AckOutcome::Transient(err),
                AckOutcome::ExpectedStale | AckOutcome::Success => {}
            }
        }
        // Every still-fresh receipt resolved as acked or redelivered, with no
        // genuine fatal among them: continue.
        AckOutcome::ExpectedStale
    }

    /// Issue one `:acknowledge` for `ack_ids` under the cancel token, returning the
    /// HTTP status + body on a completed round-trip. The token/transport failures
    /// that never reach a status short-circuit to an [`AckOutcome`]: a cancellation
    /// mid-refresh or in-flight is a teardown, not a provider failure, so it
    /// classifies `Transient` (the pump treats it as nonterminal, and the closed
    /// ack channel ends the pump cleanly with no spurious terminal); a token
    /// refresh failure is `Fatal`; a transport error is `Transient`.
    async fn acknowledge(
        &self,
        ack_ids: Vec<String>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(StatusCode, String), AckOutcome> {
        let token = match self.bearer_token_cancelable(cancel).await {
            Ok(token) => token,
            Err(err) if err.code() == ErrorCode::Cancelled => {
                return Err(AckOutcome::Transient(err));
            }
            Err(err) => return Err(AckOutcome::Fatal(err)),
        };
        let request = self
            .http
            .post(self.ack_url())
            .maybe_bearer_auth(token)
            .json(&AcknowledgeRequest { ack_ids });
        let response = match send_with_cancel(request, Some(cancel)).await {
            Ok(response) => response,
            Err(err) if err.code() == ErrorCode::Cancelled => {
                return Err(AckOutcome::Transient(err));
            }
            Err(err) => return Err(AckOutcome::Transient(err)),
        };
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Ok((status, body))
    }
}

/// The verdict of classifying one all-or-nothing `acknowledge` response. Most
/// responses resolve directly to an [`AckOutcome`]. The single exception is an
/// exactly-once 400 `INVALID_ARGUMENT` over a batch holding BOTH a stale
/// (past-deadline) and a fresh (pre-deadline) receipt: the shared status cannot
/// say which caused it, so [`AckBatchClass::IsolateFresh`] hands the fresh subset
/// back to the ack pump, which re-issues `acknowledge` for just those ids to
/// disambiguate a redeliverable stale receipt from a genuine fatal.
#[derive(Debug)]
enum AckBatchClass {
    Outcome(AckOutcome),
    IsolateFresh(Vec<AckEntry>),
}

/// Classify one all-or-nothing `acknowledge` response for a whole batch.
///
/// Pub/Sub `acknowledge` is all-or-nothing: one status/body covers the whole
/// batch, so a 400 INVALID_ARGUMENT cannot be attributed to a specific ackId
/// (barring per-ackId errorInfo). Under exactly-once delivery a routine batch
/// realistically mixes an expired receipt with fresh ones — the pump drains a
/// backlog that accumulated behind one slow acknowledge round-trip — and the
/// expired receipt alone makes the whole call return 400.
///
/// The stale-vs-genuine distinction is resolved by which entries are past their
/// deadline (`now >= deadline + skew`):
/// - all entries stale ⇒ the batch is a routine post-deadline stale ack:
///   `ExpectedStale`/continue (the receipts redeliver).
/// - no entry stale ⇒ no deadline explains the 400, so it is a genuine
///   pre-deadline invalid argument: `Fatal`/terminal.
/// - MIXED (some stale, some fresh) ⇒ ambiguous: the stale receipt could be the
///   sole cause (then the fresh receipts are fine) or a fresh receipt could be a
///   genuine invalid (then it MUST terminate). Returning `ExpectedStale`
///   unconditionally here — the prior rule — could indefinitely mask a real
///   pre-deadline invalid whenever sustained backlog keeps a stale receipt in
///   every batch. Instead hand the fresh subset back for a bounded re-ack
///   ([`AckBatchClass::IsolateFresh`]); the stale entries drop and redeliver.
///
/// Every status OTHER than that exactly-once mixed-400 branch yields the same
/// verdict for all entries via [`combine_entry_verdicts`].
fn classify_ack_batch(
    status: StatusCode,
    body: &str,
    config: &SubscriptionConfig,
    batch: &[AckEntry],
    now: Instant,
) -> AckBatchClass {
    if config.exactly_once_delivery
        && !batch.is_empty()
        && status.as_u16() == 400
        && google_error_status(body).as_deref() == Some("INVALID_ARGUMENT")
    {
        let (stale, fresh): (Vec<AckEntry>, Vec<AckEntry>) = batch
            .iter()
            .cloned()
            .partition(|entry| now >= entry.deadline + ACK_STALE_SKEW);
        if fresh.is_empty() {
            // Every entry is past deadline+skew: a routine all-stale batch.
            return AckBatchClass::Outcome(AckOutcome::ExpectedStale);
        }
        if stale.is_empty() {
            // No entry's deadline explains the 400: a genuine pre-deadline invalid.
            return AckBatchClass::Outcome(AckOutcome::Fatal(invalid_argument_before_deadline(
                body,
            )));
        }
        // Ambiguous stale+fresh: isolate the fresh subset with a bounded re-ack.
        return AckBatchClass::IsolateFresh(fresh);
    }

    AckBatchClass::Outcome(combine_entry_verdicts(status, body, config, batch, now))
}

/// The verdict of classifying the fresh-subset re-`acknowledge` (the SECOND call,
/// issued when [`classify_ack_batch`] returned [`AckBatchClass::IsolateFresh`]).
/// Most results resolve directly to an [`AckOutcome`]; a STILL-mixed 400 (some
/// fresh entries crossed their deadline during the re-ack window, some stayed
/// fresh) is still ambiguous as a group, so the still-fresh receipts are handed
/// back for per-ackId isolation via [`FreshBatchClass::IsolateIndividually`].
#[derive(Debug)]
enum FreshBatchClass {
    Outcome(AckOutcome),
    IsolateIndividually(Vec<AckEntry>),
}

/// Classify the fresh-subset re-`acknowledge`.
///
/// - Success (or any non-400 status) ⇒ fold the fresh entries' per-entry verdicts
///   ([`combine_entry_verdicts`]); a plain success means the original 400 was the
///   dropped stale receipt and the fresh receipts are now acked (continue).
/// - A second exactly-once 400 partitions the fresh subset by whether each entry
///   crossed its deadline+skew during the re-ack window:
///   - none went stale ⇒ nothing but a genuine pre-deadline invalid explains the
///     400 ⇒ `Fatal`/terminal (the anti-masking guarantee).
///   - every entry went stale ⇒ staleness fully explains it ⇒ `ExpectedStale`
///     (they redeliver).
///   - still MIXED (some newly stale, some still fresh) ⇒ ambiguous as a group:
///     drop the newly-stale (they redeliver) and hand the STILL-fresh receipts
///     back for per-ackId isolation — acking a genuine invalid alone makes its 400
///     unambiguous. This is the bounded narrowing that eliminates the masking the
///     prior one-retry `any-stale ⇒ ExpectedStale` rule allowed.
fn classify_fresh_batch(
    status: StatusCode,
    body: &str,
    config: &SubscriptionConfig,
    fresh: &[AckEntry],
    now: Instant,
) -> FreshBatchClass {
    if config.exactly_once_delivery
        && !fresh.is_empty()
        && status.as_u16() == 400
        && google_error_status(body).as_deref() == Some("INVALID_ARGUMENT")
    {
        let (_stale, still_fresh): (Vec<AckEntry>, Vec<AckEntry>) = fresh
            .iter()
            .cloned()
            .partition(|entry| now >= entry.deadline + ACK_STALE_SKEW);
        if still_fresh.is_empty() {
            // Every remaining entry went stale during the re-ack window: the 400 is
            // fully explained by staleness (they redeliver).
            return FreshBatchClass::Outcome(AckOutcome::ExpectedStale);
        }
        if still_fresh.len() == fresh.len() {
            // No entry went stale: nothing but a genuine pre-deadline invalid can
            // explain the 400. Surface it (no need to isolate which one).
            return FreshBatchClass::Outcome(AckOutcome::Fatal(invalid_argument_before_deadline(
                body,
            )));
        }
        // Still mixed: isolate the still-fresh receipts one ackId per call.
        return FreshBatchClass::IsolateIndividually(still_fresh);
    }

    FreshBatchClass::Outcome(combine_entry_verdicts(status, body, config, fresh, now))
}

/// Fold the per-entry [`classify_ack_response`] verdicts for one all-or-nothing
/// `acknowledge` response that is NOT the ambiguous exactly-once mixed-400 case.
/// Transient outranks ExpectedStale outranks Success; any Fatal entry makes the
/// whole batch terminal. Every non-400 status yields the same verdict for all
/// entries, so this collapses to that shared verdict.
fn combine_entry_verdicts(
    status: StatusCode,
    body: &str,
    config: &SubscriptionConfig,
    entries: &[AckEntry],
    now: Instant,
) -> AckOutcome {
    let mut combined = AckOutcome::Success;
    for entry in entries {
        match classify_ack_response(status, body, config, entry.deadline, now) {
            AckOutcome::Fatal(err) => return AckOutcome::Fatal(err),
            AckOutcome::Transient(err) => combined = AckOutcome::Transient(err),
            AckOutcome::ExpectedStale => {
                if matches!(combined, AckOutcome::Success) {
                    combined = AckOutcome::ExpectedStale;
                }
            }
            AckOutcome::Success => {}
        }
    }
    combined
}

fn invalid_argument_before_deadline(body: &str) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!(
            "Pub/Sub acknowledge rejected ack ID before deadline (HTTP 400): {}",
            crate::error_body::provider_detail(body)
        ),
    )
}

/// Deliberately records NO connection-promotion evidence, unlike the storage
/// chokepoint `crate::send`, and for the same reasons its s3 counterpart skips
/// the SQS client.
///
/// The subscription is a separate resource with its own IAM binding and often a
/// separate project, so a Pub/Sub refusal is evidence about the subscription
/// rather than about the storage credential. It is also not a refusal this crate
/// can read the same way: `map_pubsub_status` treats a `403` carrying
/// `ACCESS_TOKEN_SCOPE_INSUFFICIENT` as an auth failure, while the storage rule
/// reads every `403` as an identified principal that IAM scopes. And the poller
/// re-establishes after a fatal pull error, so one wrong verdict would repeat
/// for as long as the watch does, holding a connection whose storage requests
/// all succeed permanently unpromotable — the condition the promotion mechanism
/// exists to end. A credential that is genuinely dead is refused on the storage
/// transport too, where it is read correctly.
async fn send_with_cancel(
    request: reqwest::RequestBuilder,
    cancel: Option<&CancellationToken>,
) -> Result<reqwest::Response> {
    match cancel {
        Some(cancel) => {
            tokio::select! {
                _ = cancel.cancelled() => Err(Error::new(ErrorCode::Cancelled, "cancelled by host")),
                response = request.send() => response.map_err(|err| {
                    Error::new(ErrorCode::Transient, format!("Pub/Sub HTTP transport error: {err}"))
                }),
            }
        }
        None => request.send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Pub/Sub HTTP transport error: {err}"),
            )
        }),
    }
}

#[derive(Debug)]
enum AckOutcome {
    Success,
    ExpectedStale,
    Transient(Error),
    Fatal(Error),
}

fn classify_ack_response(
    status: StatusCode,
    body: &str,
    config: &SubscriptionConfig,
    deadline: Instant,
    now: Instant,
) -> AckOutcome {
    if status.is_success() {
        return AckOutcome::Success;
    }
    if status.as_u16() == 400 && google_error_status(body).as_deref() == Some("INVALID_ARGUMENT") {
        if config.exactly_once_delivery && now >= deadline + ACK_STALE_SKEW {
            return AckOutcome::ExpectedStale;
        }
        return AckOutcome::Fatal(invalid_argument_before_deadline(body));
    }
    if status.is_server_error() || status.as_u16() == 408 || status.as_u16() == 429 {
        return AckOutcome::Transient(Error::new(
            ErrorCode::Transient,
            format!(
                "Pub/Sub acknowledge returned HTTP {status}: {}",
                crate::error_body::provider_detail(body)
            ),
        ));
    }
    AckOutcome::Fatal(map_pubsub_status(status, body))
}

fn map_pubsub_status(status: StatusCode, body: &str) -> Error {
    // The body never reaches the message; only the allowlisted provider code
    // does. Classification below still reads the raw body.
    let detail = crate::error_body::provider_detail(body);
    if status.as_u16() == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("Pub/Sub request requires authentication (HTTP 401): {detail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ovstorage_plugin::ConnectionId(String::new()),
            reason: Some("pubsub_unauthorized".into()),
            expired_at: None,
        });
    }
    if status.as_u16() == 403 {
        if google_error_has_reason(body, "ACCESS_TOKEN_SCOPE_INSUFFICIENT") {
            return Error::new(
                ErrorCode::AuthRequired,
                format!("Pub/Sub credentials lack the pubsub OAuth scope (HTTP 403): {detail}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ovstorage_plugin::ConnectionId(String::new()),
                reason: Some("pubsub_scope_insufficient".into()),
                expired_at: None,
            });
        }
        return Error::new(
            ErrorCode::PermissionDenied,
            format!("Pub/Sub returned HTTP 403: {detail}"),
        );
    }
    let code = match status.as_u16() {
        400 => ErrorCode::InvalidArgument,
        404 => ErrorCode::NotFound,
        410 => ErrorCode::Transient,
        408 | 504 => ErrorCode::DeadlineExceeded,
        429 | 503 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Transient,
    };
    Error::new(code, format!("Pub/Sub returned HTTP {status}: {detail}"))
}

fn google_error_status(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .pointer("/error/status")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn google_error_has_reason(body: &str, needle: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    json_contains_reason(&value, needle)
}

fn json_contains_reason(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("reason").and_then(|v| v.as_str()) == Some(needle)
                || map.values().any(|v| json_contains_reason(v, needle))
        }
        serde_json::Value::Array(values) => values.iter().any(|v| json_contains_reason(v, needle)),
        _ => false,
    }
}

fn normalize_ack_deadline(value: u32) -> u32 {
    if value == 0 { 10 } else { value }
}

fn classify_message(
    message: &PubsubMessage,
    target: &GcsObjectRef,
    address_root: &Url,
    opts: &WatchDirectoryOptions,
) -> Result<Vec<BackendChangeEvent>> {
    let attrs = StorageAttributes::from_map(&message.attributes)?;
    if attrs.bucket_id != target.bucket || !attrs.object_id.starts_with(&target.object) {
        return Ok(Vec::new());
    }
    let kind = match attrs.event_type.as_str() {
        "OBJECT_FINALIZE" => ChangeKind::Created,
        "OBJECT_METADATA_UPDATE" => ChangeKind::MetadataChanged,
        "OBJECT_DELETE" | "OBJECT_ARCHIVE" if attrs.overwritten_by_generation.is_some() => {
            return Ok(Vec::new());
        }
        "OBJECT_DELETE" | "OBJECT_ARCHIVE" => ChangeKind::Deleted,
        _ => return Ok(Vec::new()),
    };
    if kind == ChangeKind::MetadataChanged && !opts.include_metadata_changes {
        return Ok(Vec::new());
    }
    let relative_key = relative_key_for(&target.object, &attrs.object_id);
    if relative_key.is_empty() || relative_key.starts_with('/') {
        return Ok(Vec::new());
    }
    if !opts.recursive && relative_key.contains('/') {
        return Ok(Vec::new());
    }
    let Ok(mut event_address) = address::join_relative(address_root, &attrs.object_id) else {
        // Skip, never propagate: an unaddressable name must not end the
        // stream for every other object under the watched prefix.
        tracing::warn!(
            target: "ovstorage.gcs.subscription",
            plugin = "gcs",
            key = %attrs.object_id,
            "gcs: object name is not addressable as a URI path; change event omitted",
        );
        return Ok(Vec::new());
    };
    event_address =
        address::with_query_pair(&event_address, "generation", &attrs.object_generation)?;
    // SPI etag for GCS is the generation (see `parse.rs`). The pubsub
    // attributes already carry it parsed; the JSON body's HTTP etag
    // would not round-trip through `if_match`.
    //
    // The pubsub `data` field, when present, base64-encodes the GCS
    // Object resource (JSON_API_V1 format). Its `size` and `updated`
    // fields are the only place where the per-object byte length and
    // last-modified time appear in the notification stream.
    let payload = decode_object_payload(message.data.as_deref());
    Ok(vec![BackendChangeEvent::Object {
        address: event_address,
        kind,
        etag: Some(attrs.object_generation.clone()),
        version: Some(attrs.object_generation.clone()),
        size: payload.size,
        mtime: payload.mtime,
        at: attrs.event_time,
        cursor: WatchDirectoryCursor::default(),
    }])
}

#[derive(Debug, Default)]
struct ObjectPayload {
    size: Option<u64>,
    mtime: Option<SystemTime>,
}

fn decode_object_payload(data: Option<&str>) -> ObjectPayload {
    let Some(encoded) = data else {
        return ObjectPayload::default();
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()) else {
        return ObjectPayload::default();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return ObjectPayload::default();
    };
    // GCS Object resource encodes `size` as a string-formatted u64
    // (the underlying type is int64). `updated` is RFC3339.
    let size = value
        .get("size")
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| raw.parse::<u64>().ok());
    let mtime = value
        .get("updated")
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| parse_rfc3339_time(raw).ok());
    ObjectPayload { size, mtime }
}

#[derive(Debug)]
struct StorageAttributes {
    bucket_id: String,
    object_id: String,
    object_generation: String,
    event_type: String,
    event_time: SystemTime,
    overwritten_by_generation: Option<String>,
}

impl StorageAttributes {
    fn from_map(attrs: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            bucket_id: required_attr(attrs, "bucketId")?.to_string(),
            object_id: required_attr(attrs, "objectId")?.to_string(),
            object_generation: required_attr(attrs, "objectGeneration")?.to_string(),
            event_type: required_attr(attrs, "eventType")?.to_string(),
            event_time: parse_rfc3339_time(required_attr(attrs, "eventTime")?)?,
            overwritten_by_generation: attrs.get("overwrittenByGeneration").cloned(),
        })
    }
}

fn required_attr<'a>(attrs: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    attrs.get(key).map(String::as_str).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("Pub/Sub storage notification missing attribute '{key}'"),
        )
    })
}

fn parse_rfc3339_time(value: &str) -> Result<SystemTime> {
    let parsed = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("Pub/Sub storage notification has invalid eventTime: {err}"),
            )
        })?;
    Ok(parsed.into())
}

#[derive(Debug, Deserialize)]
struct SubscriptionGetResponse {
    #[serde(default, rename = "ackDeadlineSeconds")]
    ack_deadline_seconds: u32,
    #[serde(default, rename = "enableExactlyOnceDelivery")]
    enable_exactly_once_delivery: bool,
}

#[derive(Debug, Serialize)]
struct PullRequest {
    #[serde(rename = "maxMessages")]
    max_messages: u32,
}

#[derive(Debug, Deserialize)]
struct PullResponse {
    #[serde(default, rename = "receivedMessages")]
    received_messages: Vec<ReceivedMessage>,
}

fn parse_pull_response(body: &str) -> Result<Vec<ReceivedMessage>> {
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parsed: PullResponse = serde_json::from_str(body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "Pub/Sub pull response was not JSON: {}",
                crate::error_body::decode_failure(&err, body.len())
            ),
        )
    })?;
    Ok(parsed.received_messages)
}

#[derive(Debug, Deserialize)]
struct ReceivedMessage {
    #[serde(rename = "ackId")]
    ack_id: String,
    message: PubsubMessage,
}

#[derive(Debug, Deserialize)]
struct PubsubMessage {
    #[serde(default, rename = "messageId")]
    _message_id: String,
    #[serde(default)]
    attributes: HashMap<String, String>,
    /// Base64-encoded GCS Object resource (JSON_API_V1 format).
    /// Optional; only the JSON_API_V1 payload format includes it.
    /// Carries `size` and `updated` which the attributes do not.
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Serialize)]
struct AcknowledgeRequest {
    #[serde(rename = "ackIds")]
    ack_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GcsConnectionConfig;
    use ovstorage_plugin::ConfigValue;

    fn target(prefix: &str) -> GcsObjectRef {
        GcsObjectRef {
            bucket: "assets".into(),
            object: prefix.into(),
            selector: None,
        }
    }

    fn address_root() -> Url {
        address::parse("gs://assets/").unwrap()
    }

    fn classify_test_message(
        message: &PubsubMessage,
        target: &GcsObjectRef,
        opts: &WatchDirectoryOptions,
    ) -> Result<Vec<BackendChangeEvent>> {
        classify_message(message, target, &address_root(), opts)
    }

    fn message(event_type: &str, object_id: &str) -> PubsubMessage {
        let mut attributes = HashMap::new();
        attributes.insert("bucketId".into(), "assets".into());
        attributes.insert("objectId".into(), object_id.into());
        attributes.insert("objectGeneration".into(), "42".into());
        attributes.insert("eventType".into(), event_type.into());
        attributes.insert("eventTime".into(), "2026-05-12T13:45:00Z".into());
        PubsubMessage {
            _message_id: "m1".into(),
            attributes,
            data: None,
        }
    }

    fn encode_object_payload(size: u64, updated: &str) -> String {
        let body = serde_json::json!({
            "size": size.to_string(),
            "updated": updated,
        });
        base64::engine::general_purpose::STANDARD.encode(body.to_string().as_bytes())
    }

    #[test]
    fn finalize_from_attributes_without_payload_yields_created() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let events = classify_test_message(
            &message("OBJECT_FINALIZE", "dir/file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            BackendChangeEvent::Object {
                address,
                kind,
                etag,
                version,
                size,
                mtime,
                ..
            } => {
                assert_eq!(address.as_str(), "gs://assets/dir/file.txt?generation=42");
                assert_eq!(*kind, ChangeKind::Created);
                // SPI etag for GCS is the pubsub `objectGeneration`
                // attribute ("42" in the fixture); a missing payload
                // body does not suppress the etag.
                assert_eq!(etag.as_deref(), Some("42"));
                // `version` mirrors the generation; pubsub attributes
                // do not surface a separate version identifier.
                assert_eq!(version.as_deref(), Some("42"));
                // Without the JSON_API_V1 payload, size and mtime stay None.
                assert!(size.is_none());
                assert!(mtime.is_none());
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn finalize_with_json_api_v1_payload_populates_size_and_mtime() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let mut msg = message("OBJECT_FINALIZE", "dir/file.txt");
        msg.data = Some(encode_object_payload(1234, "2026-05-12T13:45:01Z"));

        let events = classify_test_message(&msg, &target("dir/"), &opts).unwrap();

        match &events[0] {
            BackendChangeEvent::Object {
                size, mtime, etag, ..
            } => {
                assert_eq!(*size, Some(1234));
                assert_eq!(
                    *mtime,
                    Some(parse_rfc3339_time("2026-05-12T13:45:01Z").unwrap())
                );
                // Generation as etag is unaffected by the payload.
                assert_eq!(etag.as_deref(), Some("42"));
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn finalize_with_malformed_payload_leaves_size_and_mtime_none() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let mut msg = message("OBJECT_FINALIZE", "dir/file.txt");
        msg.data = Some("!!not base64!!".into());

        let events = classify_test_message(&msg, &target("dir/"), &opts).unwrap();

        match &events[0] {
            BackendChangeEvent::Object { size, mtime, .. } => {
                assert!(size.is_none());
                assert!(mtime.is_none());
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn change_event_carries_generation_as_etag() {
        // SPI etag for GCS is the generation (`ifGenerationMatch` on
        // the wire). The pubsub attribute is `objectGeneration`,
        // populated as "42" by the `message` fixture above.
        let msg = message("OBJECT_FINALIZE", "dir/file.txt");
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(&msg, &target("dir/"), &opts).unwrap();

        match &events[0] {
            BackendChangeEvent::Object {
                etag: Some(etag), ..
            } => {
                assert_eq!(etag.as_str(), "42");
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn metadata_events_are_gated() {
        let opts = WatchDirectoryOptions {
            include_metadata_changes: false,
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(
            &message("OBJECT_METADATA_UPDATE", "dir/file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn replacement_delete_is_dropped() {
        let mut msg = message("OBJECT_DELETE", "dir/file.txt");
        msg.attributes
            .insert("overwrittenByGeneration".into(), "43".into());
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(&msg, &target("dir/"), &opts).unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn archive_without_replacement_is_deleted() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(
            &message("OBJECT_ARCHIVE", "dir/file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        match &events[0] {
            BackendChangeEvent::Object { kind, .. } => assert_eq!(*kind, ChangeKind::Deleted),
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn unknown_event_type_is_forward_compatible_drop() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(
            &message("OBJECT_CUSTOM", "dir/file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn non_recursive_watch_drops_descendants() {
        let opts = WatchDirectoryOptions {
            recursive: false,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(
            &message("OBJECT_FINALIZE", "dir/sub/file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn target_directory_object_is_dropped() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events =
            classify_test_message(&message("OBJECT_FINALIZE", "dir/"), &target("dir/"), &opts)
                .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn no_trailing_slash_watch_treats_target_as_directory_prefix() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let target = directory_watch_target(target("dir"));

        let events =
            classify_test_message(&message("OBJECT_FINALIZE", "dir/a.txt"), &target, &opts)
                .unwrap();

        match &events[0] {
            BackendChangeEvent::Object { address, .. } => {
                assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn no_trailing_slash_watch_drops_sibling_prefixes() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let target = directory_watch_target(target("dir"));

        let events = classify_test_message(
            &message("OBJECT_FINALIZE", "directory/a.txt"),
            &target,
            &opts,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn root_watch_target_stays_empty() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };
        let target = directory_watch_target(target(""));

        let events =
            classify_test_message(&message("OBJECT_FINALIZE", "a.txt"), &target, &opts).unwrap();

        match &events[0] {
            BackendChangeEvent::Object { address, .. } => {
                assert_eq!(address.as_str(), "gs://assets/a.txt?generation=42")
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn root_watch_drops_slash_leading_object_ids() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events =
            classify_test_message(&message("OBJECT_FINALIZE", "/file.txt"), &target(""), &opts)
                .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn prefixed_watch_drops_slash_leading_relative_keys() {
        let opts = WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        };

        let events = classify_test_message(
            &message("OBJECT_FINALIZE", "dir//file.txt"),
            &target("dir/"),
            &opts,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn missing_required_attribute_is_malformed() {
        let mut msg = message("OBJECT_FINALIZE", "dir/file.txt");
        msg.attributes.remove("objectGeneration");

        let err = classify_test_message(&msg, &target("dir/"), &WatchDirectoryOptions::default())
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn subscription_config_normalizes_default_ack_deadline() {
        assert_eq!(normalize_ack_deadline(0), 10);
        assert_eq!(normalize_ack_deadline(17), 17);
    }

    #[test]
    fn empty_pull_idle_interval_uses_poll_interval_or_default() {
        let mut opts = WatchDirectoryOptions {
            poll_interval: Duration::from_millis(250),
            ..WatchDirectoryOptions::default()
        };

        assert_eq!(empty_pull_idle_interval(&opts), Duration::from_millis(250));

        opts.poll_interval = Duration::ZERO;
        assert_eq!(empty_pull_idle_interval(&opts), EMPTY_PULL_IDLE_INTERVAL);
    }

    #[test]
    fn pull_response_empty_body_is_empty_messages() {
        assert!(parse_pull_response("").unwrap().is_empty());
        assert!(parse_pull_response(" \n\t ").unwrap().is_empty());
    }

    #[test]
    fn pubsub_scope_403_maps_to_auth_required() {
        let body = serde_json::json!({
            "error": {
                "code": 403,
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT"
                }]
            }
        })
        .to_string();

        let err = map_pubsub_status(StatusCode::FORBIDDEN, &body);

        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[test]
    fn pubsub_non_scope_403_maps_to_permission_denied() {
        let err = map_pubsub_status(StatusCode::FORBIDDEN, r#"{"error":{"code":403}}"#);

        assert_eq!(err.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn exactly_once_invalid_argument_after_deadline_is_expected_stale() {
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let deadline = Instant::now();
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let outcome = classify_ack_response(
            StatusCode::BAD_REQUEST,
            body,
            &config,
            deadline,
            deadline + Duration::from_secs(16),
        );

        assert!(matches!(outcome, AckOutcome::ExpectedStale));
    }

    #[test]
    fn invalid_argument_before_deadline_is_fatal() {
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let outcome = classify_ack_response(
            StatusCode::BAD_REQUEST,
            body,
            &config,
            deadline,
            Instant::now(),
        );

        assert!(matches!(outcome, AckOutcome::Fatal(_)));
    }

    /// Classification keeps reading the raw body — the stale-ack verdict below
    /// still turns on `INVALID_ARGUMENT` — while the message that reaches a log
    /// carries only the sanitized provider code.
    #[test]
    fn ack_classification_reads_the_raw_body_but_the_message_is_sanitized() {
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let body = concat!(
            r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","#,
            r#""message":"You have passed an invalid ack ID: Bearer ya29.leaked_token; "#,
            r#"X-Goog-Signature=4a7f0b91cc"}}"#,
        );

        let outcome = classify_ack_response(
            StatusCode::BAD_REQUEST,
            body,
            &config,
            deadline,
            Instant::now(),
        );

        let AckOutcome::Fatal(err) = outcome else {
            panic!("a pre-deadline INVALID_ARGUMENT is fatal, got {outcome:?}");
        };
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(err.message().contains("before deadline"));
        assert!(err.message().contains("INVALID_ARGUMENT"));
        assert!(!err.message().contains("ya29."));
        assert!(!err.message().contains("X-Goog-Signature"));
    }

    /// The scope-insufficient 403 keeps its `Auth` context — carried for the
    /// broker, which serializes it across the wire — with a sanitized message.
    #[test]
    fn pubsub_scope_insufficient_keeps_auth_context_without_the_body() {
        let body = concat!(
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","#,
            r#""message":"Request had insufficient authentication scopes: Bearer ya29.leaked_token","#,
            r#""errors":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}"#,
        );

        let err = map_pubsub_status(StatusCode::FORBIDDEN, body);

        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("pubsub_scope_insufficient"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
        assert!(err.message().contains("PERMISSION_DENIED"));
        // Markers the core redactor does NOT scrub. `ya29.` alone proves
        // nothing here: the core removes `Bearer …` literals from every
        // message, so it disappears whether or not the sanitizer ran, while
        // `PERMISSION_DENIED` appears verbatim in the raw body. These are what
        // actually distinguish a sanitized message from an interpolated one.
        for leaked in [
            "Request had insufficient authentication scopes",
            "X-Goog-Signature",
            "4a7f0b91cc",
            "\"error\"",
            "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
        ] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} reached the message: {}",
                err.message()
            );
        }
    }

    /// A pull response is the one carrying notification payloads and
    /// attributes, so a type error inside it is the sharpest of the decode
    /// paths: serde's `Display` renders the offending value
    /// (`invalid type: string "…"`), which would put provider payload text
    /// into `error.message`.
    ///
    /// The fixture is valid JSON with a wrongly-typed field rather than
    /// syntactic garbage — a syntax error only ever renders a position, so it
    /// could not distinguish the safe formatter from the unsafe one. The
    /// planted value is signature-shaped rather than `Bearer`-prefixed for the
    /// same reason as the sibling tests: the core redactor scrubs the latter.
    #[test]
    fn a_malformed_pull_response_reports_length_not_payload_text() {
        let body = r#"{"receivedMessages":"X-Goog-Signature=4a7f0b91cc_7hK4wQ2mZ9pR1tY6uXbN"}"#;
        let err = parse_pull_response(body).expect_err("a wrongly-typed field is an error");

        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            err.message()
                .contains(&format!("{} byte body suppressed", body.len())),
            "{}",
            err.message()
        );
        for leaked in ["X-Goog-Signature", "4a7f0b91cc", "7hK4wQ2mZ9pR"] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} reached the message: {}",
                err.message()
            );
        }
        // Classification and position keep the failure diagnosable.
        assert!(err.message().contains("Data"), "{}", err.message());
    }

    #[test]
    fn non_exactly_once_invalid_argument_is_fatal_even_after_deadline() {
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: false,
        };
        let deadline = Instant::now();
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let outcome = classify_ack_response(
            StatusCode::BAD_REQUEST,
            body,
            &config,
            deadline,
            deadline + Duration::from_secs(20),
        );

        assert!(matches!(outcome, AckOutcome::Fatal(_)));
    }

    #[test]
    fn mixed_expiry_batch_invalid_argument_isolates_the_fresh_subset() {
        // Under exactly-once, a batch draining a backlog can mix one EXPIRED
        // receipt with FRESH ones. Pub/Sub `acknowledge` is all-or-nothing, so the
        // expired receipt alone makes the whole call return 400 INVALID_ARGUMENT.
        // The all-or-nothing status cannot say whether the stale receipt or a fresh
        // receipt caused it, so the classifier isolates the fresh subset for a
        // bounded re-ack rather than blanket-continuing (which could indefinitely
        // mask a genuine fatal).
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "expired".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "fresh".into(),
                deadline: now + Duration::from_secs(30),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_ack_batch(StatusCode::BAD_REQUEST, body, &config, &batch, now);

        match class {
            AckBatchClass::IsolateFresh(fresh) => {
                let ids: Vec<&str> = fresh.iter().map(|e| e.ack_id.as_str()).collect();
                assert_eq!(
                    ids,
                    vec!["fresh"],
                    "only the pre-deadline receipt is retried"
                );
            }
            other => panic!("expected IsolateFresh, got {other:?}"),
        }
    }

    #[test]
    fn all_fresh_batch_invalid_argument_is_still_fatal() {
        // A 400 that NO entry's deadline explains is a genuine pre-deadline invalid
        // argument and stays terminal — with no stale entry there is nothing to
        // isolate, so it resolves to Fatal directly (no retry).
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "fresh-a".into(),
                deadline: now + Duration::from_secs(10),
            },
            AckEntry {
                ack_id: "fresh-b".into(),
                deadline: now + Duration::from_secs(30),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_ack_batch(StatusCode::BAD_REQUEST, body, &config, &batch, now);

        assert!(matches!(
            class,
            AckBatchClass::Outcome(AckOutcome::Fatal(_))
        ));
    }

    #[test]
    fn all_stale_batch_invalid_argument_is_expected_stale_no_retry() {
        // Every entry is past deadline+skew: a routine all-stale batch resolves to
        // ExpectedStale directly with no fresh subset to isolate (no retry).
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "expired-a".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "expired-b".into(),
                deadline: now - Duration::from_secs(10),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_ack_batch(StatusCode::BAD_REQUEST, body, &config, &batch, now);

        assert!(matches!(
            class,
            AckBatchClass::Outcome(AckOutcome::ExpectedStale)
        ));
    }

    #[test]
    fn fresh_retry_second_400_with_no_stale_entry_is_fatal() {
        // The fresh subset is re-acked and STILL 400s with no entry gone stale
        // between the calls → nothing but a genuine pre-deadline invalid explains it
        // → Fatal (the anti-masking guarantee), no further isolation needed.
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let fresh = vec![AckEntry {
            ack_id: "fresh".into(),
            deadline: now + Duration::from_secs(30),
        }];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_fresh_batch(StatusCode::BAD_REQUEST, body, &config, &fresh, now);

        assert!(matches!(
            class,
            FreshBatchClass::Outcome(AckOutcome::Fatal(_))
        ));
    }

    #[test]
    fn fresh_retry_second_400_still_mixed_isolates_still_fresh_individually() {
        // THE anti-masking guarantee at the classification level. If a fresh entry
        // crossed its deadline during the re-ack window while ANOTHER stayed fresh,
        // the second 400 is STILL ambiguous: the newly-stale entry could be the sole
        // cause, or the still-fresh receipt is genuinely invalid. The prior one-retry
        // rule blanket-returned ExpectedStale here — masking the still-fresh invalid.
        // The fix instead hands the still-fresh receipt back for per-ackId isolation
        // so a genuine fatal can never be masked by a co-batched newly-stale entry.
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let fresh = vec![
            AckEntry {
                ack_id: "now-stale".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "still-fresh".into(),
                deadline: now + Duration::from_secs(30),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_fresh_batch(StatusCode::BAD_REQUEST, body, &config, &fresh, now);

        match class {
            FreshBatchClass::IsolateIndividually(still_fresh) => {
                let ids: Vec<&str> = still_fresh.iter().map(|e| e.ack_id.as_str()).collect();
                assert_eq!(
                    ids,
                    vec!["still-fresh"],
                    "only the still-fresh receipt is isolated further; the newly-stale drops"
                );
            }
            other => panic!("a still-mixed 400 must isolate individually, got {other:?}"),
        }
    }

    #[test]
    fn fresh_retry_second_400_all_newly_stale_is_expected_stale() {
        // If EVERY remaining fresh entry crossed its deadline during the re-ack
        // window, staleness fully explains the 400 → ExpectedStale (redeliver), with
        // no still-fresh receipt left to isolate.
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let fresh = vec![
            AckEntry {
                ack_id: "now-stale-a".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "now-stale-b".into(),
                deadline: now - Duration::from_secs(10),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_fresh_batch(StatusCode::BAD_REQUEST, body, &config, &fresh, now);

        assert!(matches!(
            class,
            FreshBatchClass::Outcome(AckOutcome::ExpectedStale)
        ));
    }

    #[test]
    fn fresh_retry_success_continues() {
        // A plain success on the fresh subset means the original 400 was the dropped
        // stale receipt; the fresh receipts are acked and the batch continues.
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: true,
        };
        let now = Instant::now();
        let fresh = vec![AckEntry {
            ack_id: "fresh".into(),
            deadline: now + Duration::from_secs(30),
        }];

        let class = classify_fresh_batch(StatusCode::OK, "{}", &config, &fresh, now);

        assert!(matches!(
            class,
            FreshBatchClass::Outcome(AckOutcome::Success)
        ));
    }

    #[test]
    fn mixed_expiry_batch_invalid_argument_is_fatal_without_exactly_once() {
        // The stale-vs-genuine distinction only applies under exactly-once; a plain
        // 400 stays terminal even when a receipt is past its deadline, and is never
        // isolated (no retry).
        let config = SubscriptionConfig {
            ack_deadline_seconds: 10,
            exactly_once_delivery: false,
        };
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "expired".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "fresh".into(),
                deadline: now + Duration::from_secs(30),
            },
        ];
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

        let class = classify_ack_batch(StatusCode::BAD_REQUEST, body, &config, &batch, now);

        assert!(matches!(
            class,
            AckBatchClass::Outcome(AckOutcome::Fatal(_))
        ));
    }

    fn a_delivery_id() -> DeliveryId {
        let pending: PubsubPending = Pending::new();
        pending.insert(
            PubsubHandle {
                ack_id: "ack".into(),
            },
            1,
            Instant::now(),
        )
    }

    #[tokio::test]
    async fn provider_ack_dispatches_delivery_then_reports_full_and_closed() {
        let (tx, mut rx) = tokio_mpsc::channel::<DeliveryId>(1);
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

    // The masking window this closes: while the terminal `Err` send is parked
    // behind the already-queued event tail, the pump must keep draining `ack_rx`
    // so the dispatcher's post-fan-out `try_send`s never fill it and mask the
    // real provider terminal with a fresh `Full`/`Closed` `Internal`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_terminal_then_drain_discards_acks_and_publishes_provider_error() {
        // A capacity-1 event channel PRE-FILLED to capacity: the terminal send
        // must block until the queued tail is consumed, modeling the dispatcher
        // draining already-queued events before it reaches the terminal `Err`.
        let (tx, rx) = mpsc::sync_channel::<UpstreamItem>(1);
        tx.send(Ok((lapsed_event(), noop_ack())))
            .expect("prefill the queued tail");

        // Saturate the ack channel: a non-draining pump would let the
        // dispatcher's next `try_send` return `Full` and mask the real terminal.
        let (ack_tx, mut ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
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
        // The timeout only ever trips on the broken (sequential send-then-drain)
        // code — correct draining completes in microseconds.
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

    // === Pub/Sub HTTP mock: drives the real `producer`/`ack_pump` against
    // canned `:pull`/`:acknowledge` responses so the async ack path — and its
    // classification — is exercised end to end through the pump, not just at
    // the `classify_ack_response` unit level. ===

    struct MockPubsub {
        endpoint: String,
        shared: Arc<MockShared>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    struct MockShared {
        // Successive `:pull` response bodies; once drained, `:pull` returns an
        // empty batch so the producer idles on its cadence.
        pull_bodies: std::sync::Mutex<std::collections::VecDeque<String>>,
        // Successive `:acknowledge` responses (status, body). Popped per call; once
        // drained, `ack_fallback` answers every subsequent call. This lets a test
        // drive the ambiguous-400 isolation, whose fresh-subset retry is a SECOND
        // `:acknowledge` that must be able to answer differently from the first.
        ack_responses: std::sync::Mutex<std::collections::VecDeque<(u16, String)>>,
        ack_fallback: (u16, String),
        // 1-based `:acknowledge` call index from which the handler hangs (sleeps)
        // before responding, so a test can park the client in `send_with_cancel`
        // and exercise cancellation mid-call. `usize::MAX` never hangs.
        hang_from_ack: std::sync::atomic::AtomicUsize,
        ack_hits: std::sync::atomic::AtomicUsize,
        // Total ackIds observed across every `:acknowledge` body (one HTTP call
        // carries a whole batch), so a test can wait until every message has
        // actually been acknowledged before bounding the call count.
        ack_ids_seen: std::sync::atomic::AtomicUsize,
        shutdown: std::sync::atomic::AtomicBool,
    }

    impl MockPubsub {
        fn new(pull_bodies: Vec<String>, ack_status: u16, ack_body: &str) -> Self {
            Self::with_ack_responses(pull_bodies, Vec::new(), (ack_status, ack_body))
        }

        /// Like [`MockPubsub::new`] but with a SEQUENCE of `:acknowledge` responses
        /// (one popped per call), falling back to `fallback` once drained.
        fn with_ack_responses(
            pull_bodies: Vec<String>,
            ack_responses: Vec<(u16, &str)>,
            fallback: (u16, &str),
        ) -> Self {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
            listener.set_nonblocking(true).expect("nonblocking");
            let addr = listener.local_addr().unwrap();
            let shared = Arc::new(MockShared {
                pull_bodies: std::sync::Mutex::new(pull_bodies.into()),
                ack_responses: std::sync::Mutex::new(
                    ack_responses
                        .into_iter()
                        .map(|(status, body)| (status, body.to_string()))
                        .collect(),
                ),
                ack_fallback: (fallback.0, fallback.1.to_string()),
                hang_from_ack: std::sync::atomic::AtomicUsize::new(usize::MAX),
                ack_hits: std::sync::atomic::AtomicUsize::new(0),
                ack_ids_seen: std::sync::atomic::AtomicUsize::new(0),
                shutdown: std::sync::atomic::AtomicBool::new(false),
            });
            let shared_t = shared.clone();
            let handle = std::thread::Builder::new()
                .name("ovs-test-pubsub".into())
                .spawn(move || mock_accept_loop(listener, shared_t))
                .expect("spawn mock");
            Self {
                endpoint: format!("http://{addr}"),
                shared,
                handle: Some(handle),
            }
        }

        fn ack_hits(&self) -> usize {
            self.shared
                .ack_hits
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        fn ack_ids_seen(&self) -> usize {
            self.shared
                .ack_ids_seen
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Make the handler hang before responding from the given 1-based
        /// `:acknowledge` call index onward (so a test can cancel mid-call).
        fn hang_from_ack(&self, call_index: usize) {
            self.shared
                .hang_from_ack
                .store(call_index, std::sync::atomic::Ordering::SeqCst);
        }

        fn client(&self) -> PubsubClient {
            let auth = Arc::new(
                crate::auth::Authenticator::new(
                    &ovstorage_plugin::SecretBundle::default(),
                    reqwest::Client::new(),
                )
                .expect("anonymous authenticator"),
            );
            PubsubClient {
                http: reqwest::Client::new(),
                auth,
                subscription: "projects/p/subscriptions/s".into(),
                endpoint: self.endpoint.clone(),
            }
        }
    }

    impl Drop for MockPubsub {
        fn drop(&mut self) {
            self.shared
                .shutdown
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn mock_accept_loop(listener: std::net::TcpListener, shared: Arc<MockShared>) {
        loop {
            if shared.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let shared = shared.clone();
                    std::thread::spawn(move || mock_handle_conn(stream, shared));
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    }

    fn mock_handle_conn(mut stream: std::net::TcpStream, shared: Arc<MockShared>) {
        use std::sync::atomic::Ordering;
        let Some((path, req_body)) = mock_read_request(&mut stream) else {
            return;
        };
        let (status, body) = if path.ends_with(":acknowledge") {
            let call_index = shared.ack_hits.fetch_add(1, Ordering::SeqCst) + 1;
            // Count how many ackIds this one call carried, so a test can wait for
            // every message to be acknowledged (not just for `Pending` to empty,
            // which happens before the network call fires).
            let ids = serde_json::from_str::<serde_json::Value>(&req_body)
                .ok()
                .and_then(|v| v.get("ackIds").and_then(|a| a.as_array().map(Vec::len)))
                .unwrap_or(0);
            shared.ack_ids_seen.fetch_add(ids, Ordering::SeqCst);
            // Optionally park before responding so a test can cancel mid-call. The
            // call index is already visible via `ack_hits`, so the test can wait
            // for the hanging call to arrive before cancelling.
            if call_index >= shared.hang_from_ack.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(30));
            }
            shared
                .ack_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| shared.ack_fallback.clone())
        } else if path.ends_with(":pull") {
            let body = shared
                .pull_bodies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| "{}".to_string());
            (200u16, body)
        } else {
            (404u16, "{}".to_string())
        };
        mock_write_response(&mut stream, status, &body);
    }

    /// Read one HTTP/1.1 request, returning its request-target (the second
    /// whitespace-separated token of the request line) and its body. The body is
    /// consumed (per `Content-Length`) so the socket is left in a clean state.
    fn mock_read_request(stream: &mut std::net::TcpStream) -> Option<(String, String)> {
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
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
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
        let body =
            String::from_utf8_lossy(&bytes[body_start..body_start + content_length]).to_string();
        Some((path, body))
    }

    fn mock_write_response(stream: &mut std::net::TcpStream, status: u16, body: &str) {
        use std::io::Write as _;
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    async fn recv_blocking(
        rx: mpsc::Receiver<UpstreamItem>,
        timeout: Duration,
    ) -> (mpsc::Receiver<UpstreamItem>, UpstreamItem) {
        tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                let item = rx.recv().expect("event stream closed unexpectedly");
                (rx, item)
            }),
        )
        .await
        .expect("timed out waiting for a stream item")
        .expect("blocking recv task panicked")
    }

    // === FIX 3 — case (b): a PRE-deadline exactly-once `INVALID_ARGUMENT` ack
    // is a genuine ack-ID error, surfaced as a terminal through the REAL pump
    // (previously only asserted at the `classify_ack_response` unit level). ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_surfaces_pre_deadline_exactly_once_invalid_argument_as_terminal() {
        let mock = MockPubsub::new(
            vec![],
            400,
            r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#,
        );
        let client = mock.client();
        let pending = Arc::new(PubsubPending::new());
        let clock = Arc::new(SystemClock);
        let (event_tx, event_rx) = mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        // Exactly-once, deadline in the FUTURE → `now < deadline`, so this is a
        // genuine ack-ID rejection, NOT an expected post-deadline stale ack.
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: true,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let id = pending.insert(
            PubsubHandle {
                ack_id: "ack-b".into(),
            },
            1,
            deadline,
        );
        ack_tx.try_send(id).expect("enqueue the delivery");

        let pump = tokio::spawn(ack_pump(
            client,
            pending,
            ack_rx,
            event_tx,
            cancel.clone(),
            config,
            clock,
        ));

        let (_rx, terminal) = recv_blocking(event_rx, Duration::from_secs(5)).await;
        let err = match terminal {
            Err(err) => err,
            Ok(_) => panic!("a pre-deadline INVALID_ARGUMENT ack must be terminal"),
        };
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            err.message().contains("before deadline"),
            "unexpected terminal message: {}",
            err.message()
        );

        cancel.cancel();
        let _ = pump.await;
    }

    // === Ambiguous-ack-batch isolation — on an exactly-once
    // mixed (stale+fresh) 400 the pump re-issues `:acknowledge` for ONLY the fresh
    // subset to disambiguate a redeliverable stale receipt from a genuine fatal.
    // Drives the REAL `ack_batch` against a two-response mock. ===

    const INVALID_ARGUMENT_400: &str = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT"}}"#;

    /// A mixed exactly-once batch: one past-deadline (stale) + one pre-deadline
    /// (fresh) receipt, so a shared 400 is ambiguous and triggers isolation.
    fn mixed_stale_fresh_batch() -> Vec<AckEntry> {
        let now = Instant::now();
        vec![
            AckEntry {
                ack_id: "stale".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "fresh".into(),
                deadline: now + Duration::from_secs(30),
            },
        ]
    }

    fn exactly_once_config() -> SubscriptionConfig {
        SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: true,
        }
    }

    /// A `Clock` whose `now()` advances by a fixed `step` on EVERY call. `ack_batch`
    /// reads the clock exactly once per `:acknowledge` round, so a test can walk
    /// receipts deterministically across their deadlines between rounds (round `k`
    /// observes `base + step * k`) and drive the full ambiguous-ack isolation.
    struct SteppingClock {
        base: Instant,
        step: Duration,
        calls: std::sync::atomic::AtomicU64,
    }

    impl SteppingClock {
        fn new(base: Instant, step: Duration) -> Self {
            Self {
                base,
                step,
                calls: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }

    impl Clock for SteppingClock {
        fn now(&self) -> Instant {
            let k = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            self.base + self.step * (k as u32)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ambiguous_ack_isolation_surfaces_genuine_fatal_alone_bounded() {
        // KEY anti-masking test. An ambiguous batch where, across the isolation
        // rounds, a still-fresh receipt is genuinely invalid (persistently 400s
        // while fresh):
        //   round 1 (full batch) 400 → drop the stale receipt, re-ack the fresh
        //     subset;
        //   round 2 (fresh subset) 400 → one fresh entry has just crossed its
        //     deadline while the genuine invalid stays fresh: STILL mixed → isolate
        //     the still-fresh receipt one ackId per call;
        //   round 3 (that receipt alone) 400 while fresh → UNAMBIGUOUS genuine fatal.
        // Against the prior one-retry code round 2 blanket-returned ExpectedStale and
        // this fatal was masked forever (see the failure mode below). Here it
        // surfaces as Fatal in exactly `batch.len()` `:acknowledge` calls (the O(n)
        // bound), never masked.
        let mock = MockPubsub::new(Vec::new(), 400, INVALID_ARGUMENT_400);
        let client = mock.client();
        let cancel = CancellationToken::new();
        let config = exactly_once_config();

        let base = Instant::now();
        let clock = SteppingClock::new(base, Duration::from_secs(100));
        let batch = vec![
            AckEntry {
                ack_id: "stale".into(),
                deadline: base,
            },
            AckEntry {
                // Fresh at round 1 (now base+100 < deadline+skew), stale at round 2
                // (now base+200 ≥ deadline+skew).
                ack_id: "goes-stale".into(),
                deadline: base + Duration::from_secs(150),
            },
            AckEntry {
                // Fresh through every round: the genuine pre-deadline invalid.
                ack_id: "genuinely-invalid".into(),
                deadline: base + Duration::from_secs(100_000),
            },
        ];

        let outcome = client.ack_batch(&batch, &config, &clock, &cancel).await;

        assert!(
            matches!(outcome, AckOutcome::Fatal(_)),
            "the isolated genuine pre-deadline invalid must surface as Fatal, not be \
             masked as ExpectedStale: {outcome:?}"
        );
        assert!(
            mock.ack_hits() <= batch.len(),
            "ambiguous-ack isolation must be bounded by the entry count (O(n)); got {} \
             calls for {} entries",
            mock.ack_hits(),
            batch.len(),
        );
        assert_eq!(
            mock.ack_hits(),
            3,
            "full isolation walks three rounds: full batch, fresh subset, lone invalid",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn isolation_newly_stale_does_not_suppress_a_later_still_fresh_fatal() {
        // A newly-stale receipt encountered DURING per-ackId isolation redelivers
        // (ExpectedStale) and must not suppress a different still-fresh genuine
        // fatal isolated afterward. Four receipts:
        //   round 1 (full) 400 → drop `stale`, re-ack {A, B, C};
        //   round 2 (fresh subset) 400 → A just went stale, {B, C} still fresh →
        //     isolate B then C individually;
        //   round 3 (B alone) 400 → B has now gone stale → ExpectedStale, continue;
        //   round 4 (C alone) 400 while fresh → genuine fatal surfaces.
        // The newly-stale A (round 2) and B (round 3) do NOT mask C's fatal, and the
        // whole path stays within `batch.len()` acknowledge calls.
        let mock = MockPubsub::new(Vec::new(), 400, INVALID_ARGUMENT_400);
        let client = mock.client();
        let cancel = CancellationToken::new();
        let config = exactly_once_config();

        let base = Instant::now();
        let clock = SteppingClock::new(base, Duration::from_secs(100));
        let batch = vec![
            AckEntry {
                ack_id: "stale".into(),
                deadline: base,
            },
            AckEntry {
                // Stale by round 2 (now base+200 ≥ deadline+skew).
                ack_id: "a-goes-stale-round2".into(),
                deadline: base + Duration::from_secs(150),
            },
            AckEntry {
                // Fresh at round 2 (now base+200 < deadline+skew), stale at its
                // round-3 individual ack (now base+300 ≥ deadline+skew).
                ack_id: "b-goes-stale-round3".into(),
                deadline: base + Duration::from_secs(250),
            },
            AckEntry {
                // Fresh through every round: the genuine pre-deadline invalid.
                ack_id: "c-genuinely-invalid".into(),
                deadline: base + Duration::from_secs(100_000),
            },
        ];

        let outcome = client.ack_batch(&batch, &config, &clock, &cancel).await;

        assert!(
            matches!(outcome, AckOutcome::Fatal(_)),
            "a still-fresh genuine invalid must surface even when co-isolated receipts \
             go stale: {outcome:?}"
        );
        assert!(
            mock.ack_hits() <= batch.len(),
            "isolation must stay within the entry-count bound; got {} calls for {} entries",
            mock.ack_hits(),
            batch.len(),
        );
        assert_eq!(
            mock.ack_hits(),
            4,
            "walks all four rounds: full batch, fresh subset, B alone (stale), C alone (fatal)",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mixed_400_fresh_subset_retry_success_continues() {
        // First `:acknowledge` (whole batch) → 400; the fresh-subset retry → 200.
        // The original 400 was the stale receipt: the batch continues (non-terminal)
        // and exactly TWO `:acknowledge` calls fire (primary + isolation retry).
        let mock = MockPubsub::with_ack_responses(
            Vec::new(),
            vec![(400, INVALID_ARGUMENT_400)],
            (200, "{}"),
        );
        let client = mock.client();
        let cancel = CancellationToken::new();

        let outcome = client
            .ack_batch(
                &mixed_stale_fresh_batch(),
                &exactly_once_config(),
                &SystemClock,
                &cancel,
            )
            .await;

        assert!(
            matches!(outcome, AckOutcome::Success | AckOutcome::ExpectedStale),
            "a successful fresh-subset retry is non-terminal: {outcome:?}"
        );
        assert_eq!(mock.ack_hits(), 2, "primary ack + one fresh-subset retry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mixed_400_fresh_subset_retry_also_400_surfaces_fatal_as_terminal() {
        // The anti-masking guarantee: the fresh-subset retry ALSO 400s with the
        // fresh receipt still pre-deadline → no stale entry explains it → the
        // genuine pre-deadline invalid surfaces as a terminal `Err` THROUGH the real
        // pump. Against the prior pure any-stale→continue code this batch would
        // continue and NO terminal would ever be published (the mask this fix
        // removes).
        let mock = MockPubsub::with_ack_responses(
            Vec::new(),
            vec![(400, INVALID_ARGUMENT_400), (400, INVALID_ARGUMENT_400)],
            (400, INVALID_ARGUMENT_400),
        );
        let client = mock.client();
        let pending = Arc::new(PubsubPending::new());
        let clock = Arc::new(SystemClock);
        let (event_tx, event_rx) = mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let config = exactly_once_config();

        // A stale + a fresh delivery, both enqueued before the pump starts so its
        // recv+drain folds them into ONE mixed batch.
        let now = Instant::now();
        let stale = pending.insert(
            PubsubHandle {
                ack_id: "stale".into(),
            },
            1,
            now - Duration::from_secs(30),
        );
        let fresh = pending.insert(
            PubsubHandle {
                ack_id: "fresh".into(),
            },
            1,
            now + Duration::from_secs(30),
        );
        ack_tx.try_send(stale).expect("enqueue stale");
        ack_tx.try_send(fresh).expect("enqueue fresh");

        let pump = tokio::spawn(ack_pump(
            client,
            pending,
            ack_rx,
            event_tx,
            cancel.clone(),
            config,
            clock,
        ));

        let (_rx, terminal) = recv_blocking(event_rx, Duration::from_secs(5)).await;
        let err = match terminal {
            Err(err) => err,
            Ok(_) => panic!("the isolated genuine fatal must surface as the terminal"),
        };
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            err.message().contains("before deadline"),
            "unexpected terminal message: {}",
            err.message()
        );
        assert_eq!(mock.ack_hits(), 2, "primary ack + one fresh-subset retry");

        cancel.cancel();
        let _ = pump.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_call_400_with_no_stale_entry_is_fatal_without_retry() {
        // An all-fresh exactly-once 400 has no stale entry to explain it: it is a
        // genuine pre-deadline invalid resolved on the FIRST call — no isolation
        // retry is issued (exactly ONE `:acknowledge`).
        let mock = MockPubsub::new(Vec::new(), 400, INVALID_ARGUMENT_400);
        let client = mock.client();
        let cancel = CancellationToken::new();
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "fresh-a".into(),
                deadline: now + Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "fresh-b".into(),
                deadline: now + Duration::from_secs(30),
            },
        ];

        let outcome = client
            .ack_batch(&batch, &exactly_once_config(), &SystemClock, &cancel)
            .await;

        assert!(matches!(outcome, AckOutcome::Fatal(_)), "{outcome:?}");
        assert_eq!(
            mock.ack_hits(),
            1,
            "no fresh-subset retry for an all-fresh 400"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_exactly_once_mixed_400_is_fatal_without_retry() {
        // Without exactly-once the stale-vs-genuine distinction does not apply: a
        // mixed 400 stays terminal and is never isolated (one `:acknowledge`).
        let mock = MockPubsub::new(Vec::new(), 400, INVALID_ARGUMENT_400);
        let client = mock.client();
        let cancel = CancellationToken::new();
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: false,
        };

        let outcome = client
            .ack_batch(&mixed_stale_fresh_batch(), &config, &SystemClock, &cancel)
            .await;

        assert!(matches!(outcome, AckOutcome::Fatal(_)), "{outcome:?}");
        assert_eq!(mock.ack_hits(), 1, "no retry without exactly-once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_stale_400_is_expected_stale_without_retry() {
        // Every receipt past deadline+skew → a routine all-stale batch continues on
        // the FIRST call with no fresh subset to isolate (one `:acknowledge`, no
        // spurious terminal).
        let mock = MockPubsub::new(Vec::new(), 400, INVALID_ARGUMENT_400);
        let client = mock.client();
        let cancel = CancellationToken::new();
        let now = Instant::now();
        let batch = vec![
            AckEntry {
                ack_id: "stale-a".into(),
                deadline: now - Duration::from_secs(30),
            },
            AckEntry {
                ack_id: "stale-b".into(),
                deadline: now - Duration::from_secs(10),
            },
        ];

        let outcome = client
            .ack_batch(&batch, &exactly_once_config(), &SystemClock, &cancel)
            .await;

        assert!(matches!(outcome, AckOutcome::ExpectedStale), "{outcome:?}");
        assert_eq!(mock.ack_hits(), 1, "no retry for an all-stale batch");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_during_fresh_subset_retry_is_transient_not_terminal() {
        // Cancellation while the isolation retry is in flight is a teardown, not a
        // provider failure: the retry classifies `Transient` (nonterminal), so the
        // pump would simply warn and let the closed channel end it — NO spurious
        // terminal `Err`. The mock hangs on the SECOND `:acknowledge` (the retry) so
        // the client parks in `send_with_cancel` until we cancel.
        let mock = MockPubsub::with_ack_responses(
            Vec::new(),
            vec![(400, INVALID_ARGUMENT_400)],
            (200, "{}"),
        );
        mock.hang_from_ack(2);
        let client = mock.client();
        let cancel = CancellationToken::new();

        let batch = mixed_stale_fresh_batch();
        let outcome = {
            let client = client.clone();
            let task_cancel = cancel.clone();
            let task = tokio::spawn(async move {
                client
                    .ack_batch(&batch, &exactly_once_config(), &SystemClock, &task_cancel)
                    .await
            });
            // Wait until the retry (2nd ack) has reached the hanging mock, then
            // cancel to interrupt the in-flight call.
            tokio::time::timeout(Duration::from_secs(5), async {
                while mock.ack_hits() < 2 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("fresh-subset retry never reached the mock");
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("ack_batch did not return after cancellation")
                .expect("ack_batch task panicked")
        };

        assert!(
            matches!(outcome, AckOutcome::Transient(_)),
            "a cancelled retry is a nonterminal teardown, not a terminal: {outcome:?}"
        );
    }

    // === FIX #1 (batching) — the pump collects up to `ACK_BATCH_MAX` READY
    // receipts and acknowledges them in ONE `:acknowledge`. Drives the real
    // `ack_pump`: many enqueued single-count deliveries must drain via far fewer
    // acknowledge calls than messages. A per-message regression fires one
    // acknowledge per delivery. ===
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ack_pump_batches_ready_acks_into_one_call() {
        let mock = MockPubsub::new(Vec::new(), 200, "{}");
        let client = mock.client();
        let pending = Arc::new(PubsubPending::new());
        let clock = Arc::new(SystemClock);
        let (event_tx, _event_rx) = mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: false,
        };

        // Enqueue 25 one-count (ready) deliveries BEFORE the pump starts, so the
        // first `recv` is followed by a full `try_recv` drain into ONE batch.
        let count = 25usize;
        for i in 0..count {
            let id = pending.insert(
                PubsubHandle {
                    ack_id: format!("ack-{i}"),
                },
                1,
                Instant::now() + Duration::from_secs(30),
            );
            ack_tx.try_send(id).expect("enqueue ready delivery");
        }

        let pump = tokio::spawn(ack_pump(
            client,
            pending.clone(),
            ack_rx,
            event_tx,
            cancel.clone(),
            config,
            clock,
        ));

        // Wait until every ackId has actually reached the fixture over the
        // network — NOT merely until `pending` empties. Entries are removed
        // before the `:acknowledge` fires, so waiting on `pending` alone lets a
        // per-message (batch-size-1) implementation be caught mid-drain (e.g. 24
        // calls for 25 messages), momentarily satisfying `hits < count` and
        // falsely passing. Gating on all 25 acknowledgements ensures every ack
        // was issued before the call count is bounded.
        tokio::time::timeout(Duration::from_secs(5), async {
            while mock.ack_ids_seen() < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("all ready deliveries must be acknowledged through the batched pump");

        // With every ack now issued, the call count must reflect batching: one
        // `:acknowledge` per full batch (+1 slack for a boundary split). A
        // per-message implementation lands ~`count` calls and fails this bound.
        let hits = mock.ack_hits();
        assert!(
            hits <= count.div_ceil(ACK_BATCH_MAX) + 1,
            "expected ~{} batched acknowledge calls for {count} messages, got {hits}",
            count.div_ceil(ACK_BATCH_MAX)
        );

        cancel.cancel();
        drop(ack_tx);
        let _ = pump.await;
    }

    // === FIX 1 — a ZERO-EVENT message whose provider ack fails FATALLY is
    // routed through the ack pump (not a producer-side terminal send), so its
    // terminal error gets `publish_terminal_then_drain`'s concurrent
    // publish-and-drain protection even with a queued eventful tail parking the
    // terminal send. Drives the REAL `producer` + REAL `ack_pump`. ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn zero_event_fatal_ack_routes_through_pump_with_queued_tail() {
        // A well-formed notification for a DIFFERENT bucket → classifies to
        // ZERO events for this subscriber cohort (the zero-event path).
        let pull_body = serde_json::json!({
            "receivedMessages": [{
                "ackId": "ack-zero",
                "message": {
                    "messageId": "m-zero",
                    "attributes": {
                        "bucketId": "other-bucket",
                        "objectId": "x/y.txt",
                        "objectGeneration": "1",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            }]
        })
        .to_string();
        // Non-scope HTTP 403 on `:acknowledge` → a fatal `PermissionDenied`,
        // distinct from the generic `Internal` a masking `Full`/`Closed`
        // `try_send` would produce.
        let mock = MockPubsub::new(vec![pull_body], 403, r#"{"error":{"code":403}}"#);
        let client = mock.client();
        let pending = Arc::new(PubsubPending::new());
        let clock = Arc::new(SystemClock);

        // A capacity-1 event channel PRE-FILLED to capacity models a queued
        // eventful tail: the pump's terminal send must park behind it.
        let (event_tx, event_rx) = mpsc::sync_channel::<UpstreamItem>(1);
        event_tx
            .send(Ok((lapsed_event(), noop_ack())))
            .expect("prefill the queued tail");
        let (ack_tx, ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: false,
        };

        tokio::spawn(ack_pump(
            client.clone(),
            pending.clone(),
            ack_rx,
            event_tx.clone(),
            cancel.clone(),
            config.clone(),
            clock.clone(),
        ));
        tokio::spawn(producer(ProducerContext {
            client,
            event_tx,
            ack_tx: ack_tx.clone(),
            cancel: cancel.clone(),
            target: GcsObjectRef {
                bucket: "assets".into(),
                object: String::new(),
                selector: None,
            },
            address_root: address_root(),
            opts: WatchDirectoryOptions {
                recursive: true,
                include_metadata_changes: true,
                since: None,
                poll_interval: Duration::from_millis(50),
            },
            pull_max: 10,
            cadence: Duration::from_millis(50),
            watch_config: config,
            pending,
            clock,
        }));

        tokio::time::timeout(Duration::from_secs(10), async move {
            // Wait until the pump has dequeued the zero-event delivery and hit
            // `:acknowledge` (the producer routed it through the pump). If the
            // producer had instead acked inline, the `:acknowledge` still fires
            // here — but the FATAL would then be published by the PRODUCER via a
            // bare `send_item(Err)` with no concurrent ack drain.
            loop {
                if mock.ack_hits() >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // With the pump's terminal send parked behind the full event
            // channel, flood the ack channel FAR past capacity. Only a pump that
            // drains `ack_rx` CONCURRENTLY with its parked terminal send keeps
            // this writable; a non-draining terminal path deadlocks here.
            let flood_id = pending_zero_flood_id();
            for _ in 0..(ACK_CHANNEL_CAPACITY * 2) {
                ack_tx
                    .send(flood_id)
                    .await
                    .expect("a draining pump keeps the ack channel writable");
            }

            // The queued tail drains first, then the REAL provider error surfaces
            // as the single terminal — never a generic masking `Internal`.
            let (event_rx, first) = recv_blocking(event_rx, Duration::from_secs(5)).await;
            assert!(
                matches!(first, Ok((BackendChangeEvent::Lapsed { .. }, _))),
                "the queued tail must precede the terminal"
            );
            let (_event_rx, terminal) = recv_blocking(event_rx, Duration::from_secs(5)).await;
            let err = match terminal {
                Err(err) => err,
                Ok(_) => panic!("the zero-event fatal ack must surface as the terminal"),
            };
            assert_eq!(
                err.code(),
                ErrorCode::PermissionDenied,
                "the real provider error must surface, not a masking Internal: {}",
                err.message()
            );

            cancel.cancel();
        })
        .await
        .expect("zero-event fatal ack did not surface through the draining pump in time");
    }

    // === FIX 1 (differentiator) — the producer ROUTES a zero-event
    // acknowledgement through the ack pump (an `ack_tx` enqueue) instead of
    // acking it inline on the producer thread. With no pump running, the
    // enqueue is observable on `ack_rx` and NO inline `:acknowledge` fires.
    // The pre-fix inline-ack code hits `:acknowledge` and never enqueues, so
    // this test times out / fails against it. ===

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_event_ack_is_routed_to_pump_not_acked_inline() {
        let pull_body = serde_json::json!({
            "receivedMessages": [{
                "ackId": "ack-zero",
                "message": {
                    "messageId": "m-zero",
                    "attributes": {
                        "bucketId": "other-bucket",
                        "objectId": "x/y.txt",
                        "objectGeneration": "1",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            }]
        })
        .to_string();
        // `:acknowledge` would succeed IF it were called — but the fixed
        // producer must NOT call it (no pump is running to drive the ack).
        let mock = MockPubsub::new(vec![pull_body], 200, "{}");
        let client = mock.client();
        let pending = Arc::new(PubsubPending::new());
        let clock = Arc::new(SystemClock);
        let (event_tx, _event_rx) = mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        let (ack_tx, mut ack_rx) = tokio_mpsc::channel::<DeliveryId>(ACK_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: false,
        };

        // NOTE: no `ack_pump` is spawned — the enqueue itself is the assertion.
        tokio::spawn(producer(ProducerContext {
            client,
            event_tx,
            ack_tx,
            cancel: cancel.clone(),
            target: GcsObjectRef {
                bucket: "assets".into(),
                object: String::new(),
                selector: None,
            },
            address_root: address_root(),
            opts: WatchDirectoryOptions {
                recursive: true,
                include_metadata_changes: true,
                since: None,
                poll_interval: Duration::from_millis(50),
            },
            pull_max: 10,
            cadence: Duration::from_millis(50),
            watch_config: config,
            pending,
            clock,
        }));

        // The fixed producer enqueues the zero-event delivery into the pump.
        let enqueued = tokio::time::timeout(Duration::from_secs(5), ack_rx.recv())
            .await
            .expect("zero-event ack was not routed to the pump (inline-ack regression)")
            .expect("ack channel closed unexpectedly");
        let _ = enqueued;

        // And it did NOT ack inline on the producer thread: `:acknowledge`
        // belongs to the pump, which is not running here.
        assert_eq!(
            mock.ack_hits(),
            0,
            "the zero-event ack must be routed to the pump, not acked inline"
        );

        cancel.cancel();
    }

    // === FIX 1 (backpressure lock) — the producer's zero-event ack enqueue is
    // an AWAITED, backpressured `ack_tx.send`, NOT a nonblocking `try_send` that
    // drops the delivery on `Full`. With a capacity-1 ack channel PREFILLED to
    // capacity and no pump draining it, the producer inserts the one-count
    // `Pending` delivery and then must PARK on the enqueue — it neither drops
    // the delivery nor acks inline. Only after a slot frees does the synthetic
    // `DeliveryId` reach the pump. A regression to
    // `let _ = ack_tx.try_send(delivery_id)` drops on `Full`, so the delivery
    // never appears after the slot frees (leaking the orphaned `Pending`
    // entry). Parity with the S3 `zero_event_ack_backpressures_when_pump_saturated`
    // lock. ===
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_event_ack_backpressures_when_pump_saturated() {
        // A well-formed notification for a DIFFERENT bucket → classifies to ZERO
        // events for this subscriber cohort (the zero-event path), then empty
        // pulls so the producer idles after the single enqueue attempt.
        let pull_body = serde_json::json!({
            "receivedMessages": [{
                "ackId": "ack-zero",
                "message": {
                    "messageId": "m-zero",
                    "attributes": {
                        "bucketId": "other-bucket",
                        "objectId": "x/y.txt",
                        "objectGeneration": "1",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            }]
        })
        .to_string();
        // `:acknowledge` would succeed IF called — but no inline ack must fire.
        let mock = MockPubsub::new(vec![pull_body], 200, "{}");
        let client = mock.client();
        let clock = Arc::new(SystemClock);
        let config = SubscriptionConfig {
            ack_deadline_seconds: 30,
            exactly_once_delivery: false,
        };

        // Prefill a sentinel delivery through the producer's OWN pending map so
        // its id (0) precedes and differs from the producer's synthetic
        // zero-event delivery (1); `pending.len()` then doubles as the sync point.
        let pending = Arc::new(PubsubPending::new());
        let sentinel = pending.insert(
            PubsubHandle {
                ack_id: "ack-sentinel".into(),
            },
            1,
            Instant::now(),
        );

        let (event_tx, _event_rx) = mpsc::sync_channel::<UpstreamItem>(EVENT_CHANNEL_CAPACITY);
        // Capacity-1 ack channel, PREFILLED to capacity (no free slot): any
        // enqueue must wait. No `ack_pump` drains it.
        let (ack_tx, mut ack_rx) = tokio_mpsc::channel::<DeliveryId>(1);
        ack_tx.try_send(sentinel).expect("prefill the single slot");
        let cancel = CancellationToken::new();

        tokio::spawn(producer(ProducerContext {
            client,
            event_tx,
            ack_tx,
            cancel: cancel.clone(),
            target: GcsObjectRef {
                bucket: "assets".into(),
                object: String::new(),
                selector: None,
            },
            address_root: address_root(),
            opts: WatchDirectoryOptions {
                recursive: true,
                include_metadata_changes: true,
                since: None,
                poll_interval: Duration::from_millis(50),
            },
            pull_max: 10,
            cadence: Duration::from_millis(50),
            watch_config: config,
            pending: pending.clone(),
            clock,
        }));

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
        // The producer is BLOCKED, not racing ahead — nothing was acked inline
        // and the single slot still holds the sentinel.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            mock.ack_hits(),
            0,
            "the zero-event ack must never fire inline on the producer thread"
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

        // No inline ack fired throughout: the ack is the pump's job.
        assert_eq!(
            mock.ack_hits(),
            0,
            "the zero-event ack must be routed to the pump, never acked inline"
        );

        cancel.cancel();
    }

    // A throwaway `DeliveryId` for saturating the ack channel: the pump's
    // `publish_terminal_then_drain` discards ack requests WITHOUT decrementing,
    // so this id needs no matching pending entry to consume.
    fn pending_zero_flood_id() -> DeliveryId {
        let pending: PubsubPending = Pending::new();
        pending.insert(
            PubsubHandle {
                ack_id: "flood".into(),
            },
            1,
            Instant::now(),
        )
    }

    #[test]
    fn config_accepts_pubsub_watch_keys() {
        let mut config_map = HashMap::new();
        config_map.insert("bucket".into(), ConfigValue::String("assets".into()));
        let mut request = ovstorage_plugin::ConnectionRequest {
            backend_kind: "gcs".into(),
            config: config_map,
            credentials: ovstorage_plugin::SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        request.config.insert(
            "pubsub_subscription".into(),
            ConfigValue::String("projects/p/subscriptions/s".into()),
        );
        request
            .config
            .insert("pubsub_pull_max".into(), ConfigValue::Int(25));

        let config = GcsConnectionConfig::from_request(&request).unwrap();

        assert_eq!(
            config.pubsub_subscription.as_deref(),
            Some("projects/p/subscriptions/s")
        );
        assert_eq!(config.pubsub_pull_max, 25);
    }
}
