// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use ovstorage_plugin::subscription::{
    AckToken, Clock, Pending, PendingDecrement, SubscriptionEvent, SystemClock,
};
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, CancellationToken, ChangeKind, Error, ErrorCode,
    ErrorContext, ResolvedTarget, Result, Url, WatchDirectoryCursor, WatchDirectoryOptions,
    address, cancel_on_drop,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tracing::warn;

use crate::{GcsBackend, GcsObjectRef, MaybeBearerAuth, relative_key_for};

const DEFAULT_PUBSUB_ENDPOINT: &str = "https://pubsub.googleapis.com";
const ACK_STALE_SKEW: Duration = Duration::from_secs(5);
const EMPTY_PULL_IDLE_INTERVAL: Duration = Duration::from_secs(1);

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
    let target = directory_watch_target(backend.parse_target(&prefix, false)?);
    let subscription = backend.config.pubsub_subscription.clone().ok_or_else(|| {
        Error::new(
            ErrorCode::Unsupported,
            "GCS watch_directory requires pubsub_subscription",
        )
    })?;
    let client = PubsubClient {
        http: backend.http.clone(),
        auth: backend.auth.clone(),
        subscription,
        endpoint: backend
            .config
            .pubsub_endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_PUBSUB_ENDPOINT.to_string()),
    };
    let watch_config = client.get_subscription(cancel.as_ref()).await?;

    let local_cancel = CancellationToken::new();
    if let Some(host_cancel) = cancel {
        let local = local_cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = host_cancel.cancelled() => local.cancel(),
                _ = local.cancelled() => {}
            }
        });
    }

    let (tx, rx) = mpsc::sync_channel::<Result<SubscriptionEvent>>(256);
    let (ack_tx, ack_rx) = tokio_mpsc::unbounded_channel::<AckToken>();
    let (fatal_tx, fatal_rx) = watch::channel::<Option<Error>>(None);
    let pending = Arc::new(PubsubPending::new());
    let clock = Arc::new(SystemClock);
    let pull_max = backend.config.pubsub_pull_max;

    tokio::spawn(ack_pump(
        client.clone(),
        pending.clone(),
        ack_rx,
        fatal_tx.clone(),
        local_cancel.clone(),
        watch_config.clone(),
        clock.clone(),
    ));
    tokio::spawn(producer_loop(ProducerLoopContext {
        client,
        tx,
        fatal_tx,
        cancel: local_cancel.clone(),
        target,
        address_root: backend.config.address_root.clone(),
        opts,
        pull_max,
        watch_config,
        pending,
        clock,
    }));

    let iter = SubscriptionIter {
        rx: Some(rx),
        ack_tx,
        fatal_rx,
        last_token: None,
        done: false,
    };
    Ok(Box::new(cancel_on_drop(iter, local_cancel)))
}

fn directory_watch_target(mut target: GcsObjectRef) -> GcsObjectRef {
    if !target.object.is_empty() && !target.object.ends_with('/') {
        target.object.push('/');
    }
    target
}

struct ProducerLoopContext<C: Clock + 'static> {
    client: PubsubClient,
    tx: mpsc::SyncSender<Result<SubscriptionEvent>>,
    fatal_tx: watch::Sender<Option<Error>>,
    cancel: CancellationToken,
    target: GcsObjectRef,
    address_root: Url,
    opts: WatchDirectoryOptions,
    pull_max: u32,
    watch_config: SubscriptionConfig,
    pending: Arc<PubsubPending>,
    clock: Arc<C>,
}

async fn producer_loop<C: Clock + 'static>(ctx: ProducerLoopContext<C>) {
    let ProducerLoopContext {
        client,
        tx,
        fatal_tx,
        cancel,
        target,
        address_root,
        opts,
        pull_max,
        watch_config,
        pending,
        clock,
    } = ctx;

    if opts.since.is_some()
        && !send_event(
            &tx,
            SubscriptionEvent {
                event: BackendChangeEvent::Lapsed {
                    since: None,
                    cursor: WatchDirectoryCursor::default(),
                },
                ack_token: AckToken::Noop,
            },
        )
        .await
    {
        cancel.cancel();
        return;
    }

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
                        _ = tokio::time::sleep(empty_pull_idle_interval(&opts)) => {}
                    }
                    continue;
                }
                backoff = Duration::from_millis(250);
                for received in messages {
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
                                vec![BackendChangeEvent::Lapsed {
                                    since: None,
                                    cursor: WatchDirectoryCursor::default(),
                                }]
                            }
                        };
                    if events.is_empty() {
                        match client
                            .ack(handle, deadline, &watch_config, clock.as_ref(), &cancel)
                            .await
                        {
                            AckOutcome::Success | AckOutcome::ExpectedStale => {}
                            AckOutcome::Transient(err) => {
                                warn!(plugin = "gcs", error = %err.message(), "Pub/Sub ack failed transiently");
                            }
                            AckOutcome::Fatal(err) => {
                                publish_fatal(&fatal_tx, err);
                                cancel.cancel();
                                return;
                            }
                        }
                        continue;
                    }

                    let delivery_id = pending.insert(handle, events.len(), deadline);
                    for event in events {
                        if !send_event(
                            &tx,
                            SubscriptionEvent {
                                event,
                                ack_token: AckToken::Provider(delivery_id),
                            },
                        )
                        .await
                        {
                            cancel.cancel();
                            return;
                        }
                    }
                }
            }
            Err(err) if is_retryable_pull_error(err.code()) => {
                warn!(plugin = "gcs", error = %err.message(), "Pub/Sub pull failed transiently");
                if !send_event(
                    &tx,
                    SubscriptionEvent {
                        event: BackendChangeEvent::Lapsed {
                            since: None,
                            cursor: WatchDirectoryCursor::default(),
                        },
                        ack_token: AckToken::Noop,
                    },
                )
                .await
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
                publish_fatal(&fatal_tx, err);
                cancel.cancel();
                return;
            }
        }
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

async fn ack_pump<C: Clock + 'static>(
    client: PubsubClient,
    pending: Arc<PubsubPending>,
    mut ack_rx: tokio_mpsc::UnboundedReceiver<AckToken>,
    fatal_tx: watch::Sender<Option<Error>>,
    cancel: CancellationToken,
    watch_config: SubscriptionConfig,
    clock: Arc<C>,
) {
    loop {
        let Some(token) = (tokio::select! {
            _ = cancel.cancelled() => return,
            token = ack_rx.recv() => token,
        }) else {
            return;
        };
        let AckToken::Provider(delivery_id) = token else {
            continue;
        };
        let (handle, deadline) = match pending.decrement(delivery_id) {
            Ok(PendingDecrement::Pending) => continue,
            Ok(PendingDecrement::Ready { handle, deadline }) => (handle, deadline),
            Err(missing) => {
                publish_fatal(
                    &fatal_tx,
                    Error::new(
                        ErrorCode::Internal,
                        format!("GCS Pub/Sub missing pending delivery {:?}", missing.id),
                    ),
                );
                cancel.cancel();
                return;
            }
        };
        match client
            .ack(handle, deadline, &watch_config, clock.as_ref(), &cancel)
            .await
        {
            AckOutcome::Success | AckOutcome::ExpectedStale => {}
            AckOutcome::Transient(err) => {
                warn!(plugin = "gcs", error = %err.message(), "Pub/Sub ack failed transiently");
            }
            AckOutcome::Fatal(err) => {
                publish_fatal(&fatal_tx, err);
                cancel.cancel();
                return;
            }
        }
    }
}

async fn send_event(
    tx: &mpsc::SyncSender<Result<SubscriptionEvent>>,
    event: SubscriptionEvent,
) -> bool {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || tx.send(Ok(event)).is_ok())
        .await
        .unwrap_or(false)
}

fn publish_fatal(fatal_tx: &watch::Sender<Option<Error>>, err: Error) {
    let _ = fatal_tx.send_replace(Some(err));
}

struct SubscriptionIter {
    rx: Option<mpsc::Receiver<Result<SubscriptionEvent>>>,
    ack_tx: tokio_mpsc::UnboundedSender<AckToken>,
    fatal_rx: watch::Receiver<Option<Error>>,
    last_token: Option<AckToken>,
    done: bool,
}

impl Iterator for SubscriptionIter {
    type Item = Result<BackendChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if let Some(token) = self.last_token.take() {
            let _ = self.ack_tx.send(token);
        }
        if let Some(err) = self.fatal_rx.borrow().clone() {
            self.done = true;
            self.rx.take();
            return Some(Err(err));
        }
        let Some(rx) = self.rx.as_ref() else {
            self.done = true;
            return None;
        };
        match rx.recv() {
            Ok(Ok(envelope)) => {
                self.last_token = Some(envelope.ack_token);
                Some(Ok(envelope.event))
            }
            Ok(Err(err)) => {
                self.done = true;
                self.rx.take();
                Some(Err(err))
            }
            Err(_) => {
                self.done = true;
                self.rx.take();
                self.fatal_rx.borrow().clone().map(Err)
            }
        }
    }
}

impl PubsubClient {
    async fn bearer_token(&self) -> Result<String> {
        self.auth.access_token().await
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
        let token = self.bearer_token().await?;
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
                format!("Pub/Sub subscription response was not JSON: {err}"),
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
        let token = self.bearer_token().await?;
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

    async fn ack<C: Clock>(
        &self,
        handle: PubsubHandle,
        deadline: Instant,
        config: &SubscriptionConfig,
        clock: &C,
        cancel: &CancellationToken,
    ) -> AckOutcome {
        let token = match self.bearer_token().await {
            Ok(token) => token,
            Err(err) => return AckOutcome::Fatal(err),
        };
        let request = self
            .http
            .post(self.ack_url())
            .maybe_bearer_auth(token)
            .json(&AcknowledgeRequest {
                ack_ids: vec![handle.ack_id.clone()],
            });
        let response = match send_with_cancel(request, Some(cancel)).await {
            Ok(response) => response,
            Err(err) if err.code() == ErrorCode::Cancelled => return AckOutcome::Transient(err),
            Err(err) => return AckOutcome::Transient(err),
        };
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        classify_ack_response(status, &body, config, deadline, clock.now())
    }
}

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
        return AckOutcome::Fatal(Error::new(
            ErrorCode::Internal,
            format!("Pub/Sub acknowledge rejected ack ID before deadline (HTTP 400): {body}"),
        ));
    }
    if status.is_server_error() || status.as_u16() == 408 || status.as_u16() == 429 {
        return AckOutcome::Transient(Error::new(
            ErrorCode::Transient,
            format!("Pub/Sub acknowledge returned HTTP {status}: {body}"),
        ));
    }
    AckOutcome::Fatal(map_pubsub_status(status, body))
}

fn map_pubsub_status(status: StatusCode, body: &str) -> Error {
    if status.as_u16() == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("Pub/Sub request requires authentication (HTTP 401): {body}"),
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
                format!("Pub/Sub credentials lack the pubsub OAuth scope (HTTP 403): {body}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ovstorage_plugin::ConnectionId(String::new()),
                reason: Some("pubsub_scope_insufficient".into()),
                expired_at: None,
            });
        }
        return Error::new(
            ErrorCode::PermissionDenied,
            format!("Pub/Sub returned HTTP 403: {body}"),
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
    Error::new(code, format!("Pub/Sub returned HTTP {status}: {body}"))
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
    let mut event_address = address::join_relative(address_root, &attrs.object_id)?;
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
            format!("Pub/Sub pull response was not JSON: {err}"),
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
    fn iterator_ack_is_one_next_delayed() {
        let (tx, rx) = mpsc::sync_channel(2);
        let (ack_tx, mut ack_rx) = tokio_mpsc::unbounded_channel();
        let (_fatal_tx, fatal_rx) = watch::channel(None);
        let pending: Pending<()> = Pending::new();
        let id1 = pending.insert((), 1, Instant::now());
        let id2 = pending.insert((), 1, Instant::now());
        tx.send(Ok(SubscriptionEvent {
            event: BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            },
            ack_token: AckToken::Provider(id1),
        }))
        .unwrap();
        tx.send(Ok(SubscriptionEvent {
            event: BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            },
            ack_token: AckToken::Provider(id2),
        }))
        .unwrap();
        let mut iter = SubscriptionIter {
            rx: Some(rx),
            ack_tx,
            fatal_rx,
            last_token: None,
            done: false,
        };

        assert!(iter.next().unwrap().is_ok());
        assert!(ack_rx.try_recv().is_err());
        assert!(iter.next().unwrap().is_ok());
        assert!(matches!(ack_rx.try_recv(), Ok(AckToken::Provider(_))));
    }

    #[test]
    fn iterator_drop_leaves_last_event_unacked() {
        let (tx, rx) = mpsc::sync_channel(1);
        let (ack_tx, mut ack_rx) = tokio_mpsc::unbounded_channel();
        let (_fatal_tx, fatal_rx) = watch::channel(None);
        let pending: Pending<()> = Pending::new();
        let id = pending.insert((), 1, Instant::now());
        tx.send(Ok(SubscriptionEvent {
            event: BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            },
            ack_token: AckToken::Provider(id),
        }))
        .unwrap();
        let mut iter = SubscriptionIter {
            rx: Some(rx),
            ack_tx,
            fatal_rx,
            last_token: None,
            done: false,
        };

        assert!(iter.next().unwrap().is_ok());
        drop(iter);

        assert!(ack_rx.try_recv().is_err());
    }

    #[test]
    fn iterator_drops_receiver_after_fatal_with_buffered_data() {
        let (tx, rx) = mpsc::sync_channel(1);
        let (ack_tx, _ack_rx) = tokio_mpsc::unbounded_channel();
        let (fatal_tx, fatal_rx) = watch::channel(None);
        tx.send(Ok(SubscriptionEvent {
            event: BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            },
            ack_token: AckToken::Noop,
        }))
        .unwrap();
        fatal_tx
            .send(Some(Error::new(ErrorCode::Internal, "receive failed")))
            .unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let item = Ok(SubscriptionEvent {
                event: BackendChangeEvent::Lapsed {
                    since: None,
                    cursor: WatchDirectoryCursor::default(),
                },
                ack_token: AckToken::Noop,
            });
            let _ = tx.send(item);
            let _ = done_tx.send(());
        });

        let mut iter = SubscriptionIter {
            rx: Some(rx),
            ack_tx,
            fatal_rx,
            last_token: None,
            done: false,
        };

        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(iter.next().transpose().unwrap(), None);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocked producer send should unblock when receiver is dropped");
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
