// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, Instant, SystemTime};

use ovstorage_plugin::subscription::{
    AckToken, Clock, Pending, PendingDecrement, SubscriptionEvent, SystemClock,
};
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, CancellationToken, ChangeKind, Error, ErrorCode,
    ResolvedTarget, Result, WatchDirectoryCursor, WatchDirectoryOptions, address, cancel_on_drop,
    race_cancel,
};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::backend::{S3Backend, current_amz_date};
use crate::config::S3Config;
use crate::credentials::AwsCredentials;
use crate::http::{HttpResponse, execute};
use crate::sigv4::{CanonicalRequest, SigningContext, payload_hash, sign_request};

const CHANNEL_CAPACITY: usize = 256;
const STALE_HANDLE_SKEW: Duration = Duration::from_secs(5);

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
    cancel: Option<CancellationToken>,
) -> Result<BackendChangeStream> {
    watch_directory_with_clock(backend, prefix, opts, cancel, Arc::new(SystemClock)).await
}

async fn watch_directory_with_clock<C: Clock + 'static>(
    backend: &S3Backend,
    prefix: ResolvedTarget,
    opts: WatchDirectoryOptions,
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
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "S3 watch_directory requires AWS credentials for SQS",
        ));
    }
    let credentials = backend.resolve_credentials(None)?;
    let client = SqsClient::new(
        backend.client().clone(),
        backend.config().clone(),
        credentials,
        queue_url,
    )?;
    let prefix_key = if parts.key.is_empty() || parts.key.ends_with('/') {
        parts.key
    } else {
        format!("{}/", parts.key)
    };
    let watch = WatchFilter {
        bucket: backend.config().bucket.clone(),
        address_root: backend.config().address_root.clone(),
        prefix_key,
        recursive: opts.recursive,
        include_metadata_changes: opts.include_metadata_changes,
    };
    let cancel = cancel.unwrap_or_default();
    let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAPACITY);
    let (ack_tx, ack_rx) = mpsc::unbounded_channel();
    let (fatal_tx, fatal_rx) = watch::channel(None);
    let runtime = Arc::new(SubscriptionRuntime {
        pending: Arc::new(SqsPending::new()),
        clock,
    });

    tokio::spawn(ack_pump(
        client.clone(),
        runtime.clone(),
        ack_rx,
        fatal_tx.clone(),
        cancel.clone(),
    ));
    tokio::spawn(producer(
        client,
        runtime,
        tx,
        fatal_tx,
        cancel.clone(),
        watch,
        opts.since.is_some(),
    ));

    let iter = SubscriptionIter {
        rx: Some(rx),
        ack_tx,
        fatal_rx,
        cancel: cancel.clone(),
        last_token: None,
        done: false,
    };
    Ok(Box::new(cancel_on_drop(iter, cancel)))
}

async fn producer<C: Clock + 'static>(
    client: SqsClient,
    runtime: Arc<SubscriptionRuntime<C>>,
    tx: SyncSender<Result<SubscriptionEvent>>,
    fatal_tx: watch::Sender<Option<Error>>,
    cancel: CancellationToken,
    watch: WatchFilter,
    emit_initial_lapsed: bool,
) {
    if emit_initial_lapsed
        && send_event(
            &tx,
            Ok(SubscriptionEvent {
                event: lapsed_event(),
                ack_token: AckToken::Noop,
            }),
        )
        .await
        .is_err()
    {
        return;
    }

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
                let _ = send_event(
                    &tx,
                    Ok(SubscriptionEvent {
                        event: lapsed_event(),
                        ack_token: AckToken::Noop,
                    }),
                )
                .await;
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
                publish_fatal(&fatal_tx, &cancel, err);
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
                match ack_with_cancel(&client, handle, deadline, runtime.clock.as_ref(), &cancel)
                    .await
                {
                    Some(AckOutcome::Success | AckOutcome::Transient) => {}
                    Some(AckOutcome::Fatal(err)) => {
                        publish_fatal(&fatal_tx, &cancel, err);
                        break;
                    }
                    None => break,
                }
                continue;
            }

            let delivery_id = runtime.pending.insert(handle, events.len(), deadline);
            for event in events {
                let item = SubscriptionEvent {
                    event,
                    ack_token: AckToken::Provider(delivery_id),
                };
                if send_event(&tx, Ok(item)).await.is_err() {
                    cancel.cancel();
                    return;
                }
            }
        }
    }
}

async fn ack_pump<C: Clock + 'static>(
    client: SqsClient,
    runtime: Arc<SubscriptionRuntime<C>>,
    mut ack_rx: mpsc::UnboundedReceiver<AckRequest>,
    fatal_tx: watch::Sender<Option<Error>>,
    cancel: CancellationToken,
) {
    while let Some(request) = ack_rx.recv().await {
        let AckToken::Provider(delivery_id) = request.token else {
            request.complete();
            continue;
        };
        let ready = match runtime.pending.decrement(delivery_id) {
            Ok(PendingDecrement::Pending) => {
                request.complete();
                continue;
            }
            Ok(PendingDecrement::Ready { handle, deadline }) => (handle, deadline),
            Err(_) => {
                publish_fatal(
                    &fatal_tx,
                    &cancel,
                    Error::new(
                        ErrorCode::Internal,
                        "S3 watch ack referenced an unknown delivery",
                    ),
                );
                request.complete();
                break;
            }
        };
        let outcome =
            ack_with_cancel(&client, ready.0, ready.1, runtime.clock.as_ref(), &cancel).await;
        match outcome {
            Some(AckOutcome::Success | AckOutcome::Transient) => {}
            Some(AckOutcome::Fatal(err)) => {
                publish_fatal(&fatal_tx, &cancel, err);
                request.complete();
                break;
            }
            None => {
                request.complete();
                break;
            }
        }
        request.complete();
    }
}

async fn ack_with_cancel<C: Clock + ?Sized>(
    client: &SqsClient,
    handle: SqsHandle,
    deadline: Instant,
    clock: &C,
    cancel: &CancellationToken,
) -> Option<AckOutcome> {
    tokio::select! {
        biased;
        outcome = client.ack(handle, deadline, clock) => Some(outcome),
        _ = cancel.cancelled() => None,
    }
}

async fn send_event(
    tx: &SyncSender<Result<SubscriptionEvent>>,
    item: Result<SubscriptionEvent>,
) -> std::result::Result<(), ()> {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || tx.send(item).map_err(|_| ()))
        .await
        .map_err(|_| ())?
}

fn publish_fatal(fatal_tx: &watch::Sender<Option<Error>>, cancel: &CancellationToken, err: Error) {
    fatal_tx.send_if_modified(|slot| {
        if slot.is_some() {
            return false;
        }
        *slot = Some(err);
        true
    });
    cancel.cancel();
}

struct SubscriptionIter {
    rx: Option<Receiver<Result<SubscriptionEvent>>>,
    ack_tx: mpsc::UnboundedSender<AckRequest>,
    fatal_rx: watch::Receiver<Option<Error>>,
    cancel: CancellationToken,
    last_token: Option<AckToken>,
    done: bool,
}

struct AckRequest {
    token: AckToken,
    completed: Option<std::sync::mpsc::SyncSender<()>>,
}

impl AckRequest {
    fn complete(mut self) {
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(());
        }
    }
}

impl Drop for AckRequest {
    fn drop(&mut self) {
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(());
        }
    }
}

impl Iterator for SubscriptionIter {
    type Item = Result<BackendChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if let Some(token) = self.last_token.take() {
            self.send_ack(token);
        }
        if let Some(err) = self.fatal_rx.borrow().clone() {
            self.done = true;
            self.rx.take();
            return Some(Err(err));
        }
        if self.cancel.is_cancelled() {
            self.done = true;
            self.rx.take();
            return None;
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
                if let Some(err) = self.fatal_rx.borrow().clone() {
                    self.done = true;
                    self.rx.take();
                    Some(Err(err))
                } else {
                    self.done = true;
                    self.rx.take();
                    None
                }
            }
        }
    }
}

impl SubscriptionIter {
    fn send_ack(&mut self, token: AckToken) {
        if self.cancel.is_cancelled() {
            return;
        }
        let AckToken::Provider(_) = token else {
            let _ = self.ack_tx.send(AckRequest {
                token,
                completed: None,
            });
            return;
        };
        let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(0);
        if self
            .ack_tx
            .send(AckRequest {
                token,
                completed: Some(completed_tx),
            })
            .is_ok()
        {
            while !self.cancel.is_cancelled() {
                match completed_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        }
    }
}

#[derive(Clone)]
struct SqsClient {
    http: Client,
    config: S3Config,
    credentials: AwsCredentials,
    queue_url: String,
    host: String,
    canonical_uri: String,
    visibility_timeout_seconds: u32,
}

impl SqsClient {
    fn new(
        http: Client,
        config: S3Config,
        credentials: AwsCredentials,
        queue_url: String,
    ) -> Result<Self> {
        let parsed = url::Url::parse(&queue_url).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 sqs_queue_url is not a valid URL: {err}"),
            )
        })?;
        let host = match (parsed.host_str(), parsed.port()) {
            (Some(host), Some(port)) => format!("{}:{port}", host.to_ascii_lowercase()),
            (Some(host), None) => host.to_ascii_lowercase(),
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "S3 sqs_queue_url must include a host",
                ));
            }
        };
        let canonical_uri = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        Ok(Self {
            visibility_timeout_seconds: config.sqs_visibility_timeout,
            http,
            config,
            credentials,
            queue_url,
            host,
            canonical_uri,
        })
    }

    async fn receive(&self) -> Result<Vec<SqsMessage>> {
        let mut params = vec![
            ("Action".to_string(), "ReceiveMessage".to_string()),
            ("Version".to_string(), "2012-11-05".to_string()),
            (
                "MaxNumberOfMessages".to_string(),
                self.config.sqs_max_messages.to_string(),
            ),
            (
                "WaitTimeSeconds".to_string(),
                self.config.sqs_wait_seconds.to_string(),
            ),
            (
                "VisibilityTimeout".to_string(),
                self.config.sqs_visibility_timeout.to_string(),
            ),
        ];
        params.sort();
        let body = form_body(&params);
        let response = self.signed_post(&body).await?;
        if !is_success(response.status) {
            return Err(map_sqs_status(response.status, &response.body));
        }
        let text = response_text(response.body, "SQS ReceiveMessage response")?;
        parse_receive_message_response(&text)
    }

    async fn ack<C: Clock + ?Sized>(
        &self,
        handle: SqsHandle,
        deadline: Instant,
        clock: &C,
    ) -> AckOutcome {
        debug!(
            plugin = "s3",
            op = "watch_directory",
            message_id = %handle.message_id,
            "deleting SQS message"
        );
        match self.delete_message_batch(&handle.receipt_handle).await {
            Ok(failures) if failures.is_empty() => AckOutcome::Success,
            Ok(failures) => classify_batch_failures(failures, deadline, clock),
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

    async fn delete_message_batch(&self, receipt_handle: &str) -> Result<Vec<BatchFailure>> {
        let params = vec![
            ("Action".to_string(), "DeleteMessageBatch".to_string()),
            ("Version".to_string(), "2012-11-05".to_string()),
            (
                "DeleteMessageBatchRequestEntry.1.Id".to_string(),
                "m1".to_string(),
            ),
            (
                "DeleteMessageBatchRequestEntry.1.ReceiptHandle".to_string(),
                receipt_handle.to_string(),
            ),
        ];
        let body = form_body(&params);
        let response = self.signed_post(&body).await?;
        if !is_success(response.status) {
            return Err(map_sqs_status(response.status, &response.body));
        }
        let text = response_text(response.body, "SQS DeleteMessageBatch response")?;
        parse_delete_message_batch_response(&text)
    }

    async fn signed_post(&self, body: &str) -> Result<HttpResponse> {
        let (_, amz_date, date_stamp) = current_amz_date();
        let ctx = SigningContext {
            region: self.config.signing_region(),
            service: "sqs",
            amz_date: &amz_date,
            date_stamp: &date_stamp,
        };
        let hash = payload_hash(body.as_bytes());
        let canonical = CanonicalRequest {
            method: "POST",
            canonical_uri: self.canonical_uri.clone(),
            canonical_query: String::new(),
            host: &self.host,
            extra_signed_headers: vec![
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("x-amz-content-sha256".to_string(), hash.clone()),
            ],
            payload_hash: hash,
        };
        let signed = sign_request(&self.credentials, &ctx, &canonical);
        execute(
            &self.http,
            "POST",
            &self.queue_url,
            &signed.headers,
            body.as_bytes(),
        )
        .await
    }
}

enum AckOutcome {
    Success,
    Transient,
    Fatal(Error),
}

fn classify_batch_failures<C: Clock + ?Sized>(
    failures: Vec<BatchFailure>,
    deadline: Instant,
    clock: &C,
) -> AckOutcome {
    let now = clock.now();
    for failure in failures {
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
                format!(
                    "SQS DeleteMessageBatch failed for entry '{}': {}: {}",
                    failure.id, failure.code, failure.message
                ),
            ));
        }
        if !failure.sender_fault {
            warn!(
                plugin = "s3",
                op = "watch_directory",
                code = %failure.code,
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
            format!(
                "SQS DeleteMessageBatch failed for entry '{}': {}: {}",
                failure.id, failure.code, failure.message
            ),
        ));
    }
    AckOutcome::Transient
}

fn map_sqs_status(status: u16, body: &[u8]) -> Error {
    let text = String::from_utf8_lossy(body);
    let trail = if text.trim().is_empty() {
        String::new()
    } else {
        format!(": {}", text.trim())
    };
    match status {
        401 => Error::new(
            ErrorCode::AuthRequired,
            format!("SQS request requires authentication (HTTP 401){trail}"),
        ),
        403 => Error::new(
            ErrorCode::PermissionDenied,
            format!("SQS request forbidden (HTTP 403){trail}"),
        ),
        408 | 504 => Error::new(
            ErrorCode::DeadlineExceeded,
            format!("SQS deadline exceeded (HTTP {status}){trail}"),
        ),
        429 | 500..=599 => Error::new(
            ErrorCode::Transient,
            format!("SQS returned transient HTTP {status}{trail}"),
        ),
        status => Error::new(
            ErrorCode::Internal,
            format!("SQS returned unexpected HTTP {status}{trail}"),
        ),
    }
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
            format!("S3 notification body was not valid JSON: {err}"),
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
    Ok(Some(object_event(
        filter,
        &key,
        kind,
        identity,
        required_str(record, &["eventTime"])
            .ok()
            .and_then(parse_iso8601_to_system_time)
            .unwrap_or_else(SystemTime::now),
    )?))
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
    Ok(Some(object_event(
        filter,
        key,
        kind,
        identity,
        value
            .get("time")
            .and_then(Value::as_str)
            .and_then(parse_iso8601_to_system_time)
            .unwrap_or_else(SystemTime::now),
    )?))
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
) -> Result<BackendChangeEvent> {
    let mut event_address = address::join_relative(&filter.address_root, key)?;
    if let Some(version) = identity.version.as_deref() {
        event_address = address::with_query_pair(&event_address, "versionId", version)?;
    }
    Ok(BackendChangeEvent::Object {
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
    })
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BatchFailure {
    id: String,
    code: String,
    message: String,
    sender_fault: bool,
}

fn parse_receive_message_response(body: &str) -> Result<Vec<SqsMessage>> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut current = SqsMessage {
        message_id: String::new(),
        receipt_handle: String::new(),
        body: String::new(),
    };
    let mut messages = Vec::new();
    let mut text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = xml_name(tag.name().as_ref())?;
                if name == "Message" {
                    current = SqsMessage {
                        message_id: String::new(),
                        receipt_handle: String::new(),
                        body: String::new(),
                    };
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::End(_)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                let value = std::mem::take(&mut text);
                match (parent, name.as_str()) {
                    (Some("Message"), "MessageId") => current.message_id = value,
                    (Some("Message"), "ReceiptHandle") => current.receipt_handle = value,
                    (Some("Message"), "Body") => current.body = value,
                    (Some("ReceiveMessageResult"), "Message") => {
                        if current.message_id.is_empty()
                            || current.receipt_handle.is_empty()
                            || current.body.is_empty()
                        {
                            return Err(Error::new(
                                ErrorCode::Internal,
                                "SQS ReceiveMessage response contained an incomplete Message",
                            ));
                        }
                        messages.push(current.clone());
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(value)) => text.push_str(&value.unescape().map_err(xml_err)?),
            Ok(Event::CData(value)) => text.push_str(&String::from_utf8_lossy(&value)),
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }
    Ok(messages)
}

fn parse_delete_message_batch_response(body: &str) -> Result<Vec<BatchFailure>> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut current = BatchFailure::default();
    let mut failures = Vec::new();
    let mut text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = xml_name(tag.name().as_ref())?;
                if name == "BatchResultErrorEntry" {
                    current = BatchFailure::default();
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::End(_)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                let value = std::mem::take(&mut text);
                match (parent, name.as_str()) {
                    (Some("BatchResultErrorEntry"), "Id") => current.id = value,
                    (Some("BatchResultErrorEntry"), "Code") => current.code = value,
                    (Some("BatchResultErrorEntry"), "Message") => current.message = value,
                    (Some("BatchResultErrorEntry"), "SenderFault") => {
                        current.sender_fault = value.eq_ignore_ascii_case("true");
                    }
                    (Some("DeleteMessageBatchResult"), "BatchResultErrorEntry") => {
                        failures.push(std::mem::take(&mut current));
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(value)) => text.push_str(&value.unescape().map_err(xml_err)?),
            Ok(Event::CData(value)) => text.push_str(&String::from_utf8_lossy(&value)),
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }
    Ok(failures)
}

fn xml_name(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(xml_err)
}

fn xml_err(err: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Internal, format!("SQS XML parse error: {err}"))
}

fn form_body(params: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn response_text(body: Vec<u8>, context: &str) -> Result<String> {
    String::from_utf8(body)
        .map_err(|_| Error::new(ErrorCode::Internal, format!("{context} was not UTF-8")))
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
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

    #[test]
    fn publish_fatal_keeps_first_error() {
        let (fatal_tx, fatal_rx) = watch::channel(None);
        let cancel = CancellationToken::new();

        publish_fatal(
            &fatal_tx,
            &cancel,
            Error::new(ErrorCode::Internal, "ack failed"),
        );
        publish_fatal(
            &fatal_tx,
            &cancel,
            Error::new(ErrorCode::Cancelled, "cancelled by host"),
        );

        let err = fatal_rx.borrow().clone().unwrap();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(err.message(), "ack failed");
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn iterator_drops_receiver_after_fatal_error() {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let (fatal_tx, fatal_rx) = watch::channel(None);
        fatal_tx
            .send(Some(Error::new(ErrorCode::Internal, "receive failed")))
            .unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let item = Ok(SubscriptionEvent {
                event: lapsed_event(),
                ack_token: AckToken::Noop,
            });
            let _ = tx.send(item);
            let _ = done_tx.send(());
        });

        let mut iter = SubscriptionIter {
            rx: Some(rx),
            ack_tx,
            fatal_rx,
            cancel: CancellationToken::new(),
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

    #[test]
    fn receive_message_xml_extracts_body_and_receipt() {
        let xml = r#"<ReceiveMessageResponse>
          <ReceiveMessageResult>
            <Message>
              <MessageId>m-1</MessageId>
              <ReceiptHandle>rh-1</ReceiptHandle>
              <Body>{&quot;Records&quot;:[]}</Body>
            </Message>
          </ReceiveMessageResult>
        </ReceiveMessageResponse>"#;
        let messages = parse_receive_message_response(xml).unwrap();
        assert_eq!(
            messages,
            vec![SqsMessage {
                message_id: "m-1".into(),
                receipt_handle: "rh-1".into(),
                body: r#"{"Records":[]}"#.into()
            }]
        );
    }

    #[test]
    fn delete_batch_xml_extracts_failures() {
        let xml = r#"<DeleteMessageBatchResponse>
          <DeleteMessageBatchResult>
            <BatchResultErrorEntry>
              <Id>m1</Id>
              <SenderFault>true</SenderFault>
              <Code>ReceiptHandleIsInvalid</Code>
              <Message>bad handle</Message>
            </BatchResultErrorEntry>
          </DeleteMessageBatchResult>
        </DeleteMessageBatchResponse>"#;
        assert_eq!(
            parse_delete_message_batch_response(xml).unwrap(),
            vec![BatchFailure {
                id: "m1".into(),
                code: "ReceiptHandleIsInvalid".into(),
                message: "bad handle".into(),
                sender_fault: true,
            }]
        );
    }

    #[test]
    fn expired_receipt_is_transient_only_after_deadline_skew() {
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(30);
        let failure = BatchFailure {
            id: "m1".into(),
            code: "InvalidParameterValue".into(),
            message: "The receipt handle has expired.".into(),
            sender_fault: true,
        };
        assert!(matches!(
            classify_batch_failures(vec![failure.clone()], deadline, &clock),
            AckOutcome::Fatal(_)
        ));
        clock.advance(Duration::from_secs(36));
        assert!(matches!(
            classify_batch_failures(vec![failure], deadline, &clock),
            AckOutcome::Transient
        ));
    }
}
