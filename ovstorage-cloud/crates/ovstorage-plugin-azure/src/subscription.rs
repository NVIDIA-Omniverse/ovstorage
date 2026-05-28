// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, CancellationToken, ChangeKind, Error, ErrorCode,
    ResolvedTarget, Result, WatchDirectoryCursor, WatchDirectoryOptions, address, cancel_on_drop,
    race_cancel,
};
use reqwest::Method;
use serde::Deserialize;
use time::{Date, Month, OffsetDateTime, Time};
use tokio::sync::watch;
use tracing::warn;

use crate::avro_changefeed::{ChangeFeedRecord, decode_change_feed_records};
use crate::backend::AzureBackend;
use crate::client::{AzureClient, AzureRequest, map_status_to_error};
use crate::config::{AzureAddress, AzureConnectionConfig};
use crate::parse::parse_blob_list_xml;

const CHANGE_FEED_CONTAINER: &str = "$blobchangefeed";
const CHANNEL_CAPACITY: usize = 256;
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CHANGE_FEED_SEGMENT_DURATION: Duration = Duration::from_secs(60 * 60);
const TERMINAL_CHUNK_OFFSET: u64 = u64::MAX;

type ChunkOffsets = HashMap<String, u64>;

pub async fn watch_directory(
    backend: &AzureBackend,
    prefix: ResolvedTarget,
    opts: WatchDirectoryOptions,
    cancel: Option<CancellationToken>,
) -> Result<BackendChangeStream> {
    if !backend.config.change_feed_enabled {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "Azure watch_directory requires change_feed_enabled=true",
        ));
    }
    if backend.config.hierarchical_namespace {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "Azure Blob Change Feed is not supported for hierarchical namespace accounts",
        ));
    }
    let parsed = AzureAddress::parse(&prefix.resolved_address)?;
    if parsed.account != backend.config.account || parsed.container != backend.config.container {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "azure watch prefix is outside the configured account/container",
        ));
    }
    let emit_initial_lapsed = opts.since.is_some();

    let prefix_key = if parsed.key.is_empty() || parsed.key.ends_with('/') {
        parsed.key
    } else {
        format!("{}/", parsed.key)
    };
    let filter = WatchFilter {
        container: backend.config.container.clone(),
        address_root: backend.config.address_root.clone(),
        prefix_key,
        recursive: opts.recursive,
        include_metadata_changes: opts.include_metadata_changes,
    };
    let client = ChangeFeedClient {
        client: backend.client.clone(),
        config: backend.config.as_ref().clone(),
    };
    let cancel = cancel.unwrap_or_default();
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let (fatal_tx, fatal_rx) = watch::channel(None);
    let poll_interval = effective_poll_interval(
        opts.poll_interval,
        backend.config.change_feed_poll_interval_seconds,
    );

    tokio::spawn(producer_loop(ProducerContext {
        client,
        tx,
        fatal_tx,
        cancel: cancel.clone(),
        filter,
        poll_interval,
        segment_lag: Duration::from_secs(backend.config.change_feed_segment_lag_seconds),
        emit_initial_lapsed,
    }));

    let iter = SubscriptionIter {
        rx: Some(rx),
        fatal_rx,
        done: false,
    };
    Ok(Box::new(cancel_on_drop(iter, cancel)))
}

struct ProducerContext {
    client: ChangeFeedClient,
    tx: mpsc::SyncSender<Result<BackendChangeEvent>>,
    fatal_tx: watch::Sender<Option<Error>>,
    cancel: CancellationToken,
    filter: WatchFilter,
    poll_interval: Duration,
    segment_lag: Duration,
    emit_initial_lapsed: bool,
}

async fn producer_loop(ctx: ProducerContext) {
    let ProducerContext {
        client,
        tx,
        fatal_tx,
        cancel,
        filter,
        poll_interval,
        segment_lag,
        emit_initial_lapsed,
    } = ctx;
    if emit_initial_lapsed
        && !send_event(
            &tx,
            Ok(BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            }),
        )
        .await
    {
        cancel.cancel();
        return;
    }

    let mut poll_state = PollState::default();
    let mut backoff = Duration::from_millis(250);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match poll_once(
            &client,
            &filter,
            segment_lag,
            poll_interval,
            &mut poll_state,
            &cancel,
        )
        .await
        {
            Ok(events) => {
                backoff = Duration::from_millis(250);
                for event in events {
                    if !send_event(&tx, Ok(event)).await {
                        cancel.cancel();
                        return;
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(poll_interval) => {}
                }
            }
            Err(err) if is_retryable(err.code()) => {
                warn!(plugin = "azure", error = %err.message(), "Azure change-feed poll failed transiently");
                let _ = send_event(
                    &tx,
                    Ok(BackendChangeEvent::Lapsed {
                        since: None,
                        cursor: WatchDirectoryCursor::default(),
                    }),
                )
                .await;
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

async fn poll_once(
    client: &ChangeFeedClient,
    filter: &WatchFilter,
    segment_lag: Duration,
    poll_interval: Duration,
    state: &mut PollState,
    cancel: &CancellationToken,
) -> Result<Vec<BackendChangeEvent>> {
    let mut progress = PollProgress::from_committed(&state.chunk_offsets, state.last_window_end);
    let last_consumable = client.last_consumable(cancel).await?;
    let window = SegmentWindow::live(last_consumable, segment_lag);
    let mut out = Vec::new();
    let mut segments = client.list_segment_manifests(window, cancel).await?;
    segments.sort();
    for segment in segments {
        let manifest = match client.segment_manifest(&segment, cancel).await {
            Ok(manifest) => manifest,
            Err(err) if err.code() == ErrorCode::NotFound => {
                out.push(BackendChangeEvent::Lapsed {
                    since: None,
                    cursor: WatchDirectoryCursor::default(),
                });
                continue;
            }
            Err(err) => return Err(err),
        };
        for chunk_dir in manifest.chunk_file_paths {
            let mut chunk_files = client.list_chunk_files(&chunk_dir, cancel).await?;
            chunk_files.sort();
            for chunk_file in chunk_files {
                let Some(previous_offset) = progress.next_offset(&chunk_file) else {
                    continue;
                };
                match client.chunk_bytes(&chunk_file, cancel).await {
                    Ok(bytes) => match decode_change_feed_records(&bytes) {
                        Ok(records) => {
                            let record_count = records.len();
                            let chunk_events = map_decoded_chunk_records(
                                records,
                                filter,
                                CursorParts {
                                    segment: segment.clone(),
                                    chunk_dir: chunk_dir.clone(),
                                    chunk_file: chunk_file.clone(),
                                    offset: 0,
                                },
                                previous_offset,
                            )?;
                            progress.mark_decoded(chunk_file, record_count);
                            out.extend(chunk_events);
                        }
                        Err(err) => {
                            if matches!(decode_error_disposition(&err), ChunkDisposition::Retry) {
                                return Err(err);
                            }
                            warn!(plugin = "azure", error = %err.message(), "Azure change-feed Avro decode failed");
                            out.push(BackendChangeEvent::Lapsed {
                                since: None,
                                cursor: cursor(CursorParts {
                                    segment: segment.clone(),
                                    chunk_dir: chunk_dir.clone(),
                                    chunk_file: chunk_file.clone(),
                                    offset: 0,
                                }),
                            });
                            progress.mark_terminal(chunk_file);
                        }
                    },
                    Err(err) => match chunk_get_error_disposition(&err)? {
                        ChunkDisposition::Complete => {
                            out.push(BackendChangeEvent::Lapsed {
                                since: None,
                                cursor: cursor(CursorParts {
                                    segment: segment.clone(),
                                    chunk_dir: chunk_dir.clone(),
                                    chunk_file: chunk_file.clone(),
                                    offset: 0,
                                }),
                            });
                            progress.mark_terminal(chunk_file);
                        }
                        ChunkDisposition::Retry => return Err(err),
                    },
                }
            }
        }
    }
    progress.last_window_end = Some(window.end);
    let poll_finished_at = SystemTime::now();
    if should_emit_wall_clock_lapsed(state.last_poll_at, poll_finished_at, poll_interval)
        || should_emit_behind_lapsed(state.last_window_end, window)
    {
        out.insert(
            0,
            BackendChangeEvent::Lapsed {
                since: None,
                cursor: WatchDirectoryCursor::default(),
            },
        );
    }
    progress.commit(&mut state.chunk_offsets, &mut state.last_window_end);
    state.last_poll_at = Some(poll_finished_at);
    Ok(out)
}

async fn send_event(
    tx: &mpsc::SyncSender<Result<BackendChangeEvent>>,
    event: Result<BackendChangeEvent>,
) -> bool {
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || tx.send(event).is_ok())
        .await
        .unwrap_or(false)
}

fn publish_fatal(fatal_tx: &watch::Sender<Option<Error>>, err: Error) {
    let _ = fatal_tx.send_replace(Some(err));
}

fn is_retryable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Transient | ErrorCode::DeadlineExceeded | ErrorCode::ResourceExhausted
    )
}

struct SubscriptionIter {
    rx: Option<mpsc::Receiver<Result<BackendChangeEvent>>>,
    fatal_rx: watch::Receiver<Option<Error>>,
    done: bool,
}

impl Iterator for SubscriptionIter {
    type Item = Result<BackendChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(rx) = self.rx.as_ref() else {
            self.done = true;
            return None;
        };
        match rx.try_recv() {
            Ok(item) => return Some(item),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.done = true;
                self.rx.take();
                return self.fatal_rx.borrow().clone().map(Err);
            }
        }
        if let Some(err) = self.fatal_rx.borrow().clone() {
            self.done = true;
            self.rx.take();
            return Some(Err(err));
        }
        match rx.recv() {
            Ok(item) => Some(item),
            Err(_) => {
                self.done = true;
                self.rx.take();
                self.fatal_rx.borrow().clone().map(Err)
            }
        }
    }
}

#[derive(Clone)]
struct ChangeFeedClient {
    client: AzureClient,
    config: AzureConnectionConfig,
}

impl ChangeFeedClient {
    async fn last_consumable(&self, cancel: &CancellationToken) -> Result<SystemTime> {
        let bytes = self.get_blob("meta/Segments.json", cancel).await?;
        let parsed: SegmentsMeta = serde_json::from_slice(&bytes).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("Azure change-feed Segments.json was not JSON: {err}"),
            )
        })?;
        parse_rfc3339(&parsed.last_consumable).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "Azure change-feed Segments.json lacked a valid lastConsumable timestamp",
            )
        })
    }

    async fn list_segment_manifests(
        &self,
        window: SegmentWindow,
        cancel: &CancellationToken,
    ) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for prefix in segment_hour_prefixes(window) {
            names.extend(self.list_blobs(&prefix, cancel).await?);
        }
        Ok(names
            .into_iter()
            .filter(|name| name.ends_with("meta.json"))
            .filter(|name| segment_manifest_in_window(name, window))
            .collect())
    }

    async fn segment_manifest(
        &self,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<SegmentManifest> {
        let bytes = self.get_blob(path, cancel).await?;
        serde_json::from_slice(&bytes).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("Azure change-feed segment manifest was not JSON: {err}"),
            )
        })
    }

    async fn list_chunk_files(
        &self,
        chunk_dir: &str,
        cancel: &CancellationToken,
    ) -> Result<Vec<String>> {
        let prefix = chunk_dir
            .strip_prefix("$blobchangefeed/")
            .unwrap_or(chunk_dir);
        Ok(self
            .list_blobs(prefix, cancel)
            .await?
            .into_iter()
            .filter(|name| name.ends_with(".avro"))
            .collect())
    }

    async fn chunk_bytes(&self, path: &str, cancel: &CancellationToken) -> Result<Vec<u8>> {
        let path = path.strip_prefix("$blobchangefeed/").unwrap_or(path);
        self.get_blob(path, cancel).await
    }

    async fn get_blob(&self, path: &str, cancel: &CancellationToken) -> Result<Vec<u8>> {
        let url = format!(
            "{}/{}/{}",
            self.config.change_feed_base_url(),
            CHANGE_FEED_CONTAINER,
            url_encode_path(path)
        );
        let canonical_path = format!("/{CHANGE_FEED_CONTAINER}/{path}");
        let req = AzureRequest {
            method: Method::GET,
            url,
            canonical_path: &canonical_path,
            canonical_query: Vec::new(),
            extra_headers: Vec::new(),
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
            body: None,
        };
        let response = race_cancel(Some(cancel), self.client.send(req)).await?;
        if response.ok() {
            Ok(response.body)
        } else {
            Err(map_status_to_error(&response, "change-feed read"))
        }
    }

    async fn list_blobs(&self, prefix: &str, cancel: &CancellationToken) -> Result<Vec<String>> {
        let mut marker: Option<String> = None;
        let mut out = Vec::new();
        loop {
            let mut query = vec![
                ("restype".to_string(), "container".to_string()),
                ("comp".to_string(), "list".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(marker) = marker.as_ref() {
                query.push(("marker".to_string(), marker.clone()));
            }
            let url = format!(
                "{}/{CHANGE_FEED_CONTAINER}?{}",
                self.config.change_feed_base_url(),
                encode_query(&query)
            );
            let canonical_path = format!("/{CHANGE_FEED_CONTAINER}");
            let req = AzureRequest {
                method: Method::GET,
                url,
                canonical_path: &canonical_path,
                canonical_query: query,
                extra_headers: Vec::new(),
                content_type: None,
                content_md5: None,
                if_match: None,
                if_none_match: None,
                range: None,
                body: None,
            };
            let response = race_cancel(Some(cancel), self.client.send(req)).await?;
            if !response.ok() {
                return Err(map_status_to_error(&response, "change-feed list"));
            }
            let body = response.body_str()?;
            let parsed = parse_blob_list_xml(body)?;
            out.extend(parsed.items.into_iter().map(|blob| blob.name));
            match parsed.next_marker {
                Some(next) if !next.is_empty() => marker = Some(next),
                _ => return Ok(out),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SegmentsMeta {
    last_consumable: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SegmentManifest {
    chunk_file_paths: Vec<String>,
}

#[derive(Clone)]
struct WatchFilter {
    container: String,
    address_root: ovstorage_plugin::Url,
    prefix_key: String,
    recursive: bool,
    include_metadata_changes: bool,
}

#[derive(Clone)]
struct CursorParts {
    segment: String,
    chunk_dir: String,
    chunk_file: String,
    offset: u64,
}

#[derive(Default)]
struct PollState {
    chunk_offsets: ChunkOffsets,
    last_window_end: Option<SystemTime>,
    last_poll_at: Option<SystemTime>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SegmentWindow {
    start: SystemTime,
    end: SystemTime,
}

impl SegmentWindow {
    fn live(last_consumable: SystemTime, segment_lag: Duration) -> Self {
        let end = system_time_saturating_sub(last_consumable, segment_lag);
        let start = system_time_saturating_sub(end, CHANGE_FEED_SEGMENT_DURATION);
        Self { start, end }
    }
}

fn system_time_saturating_sub(time: SystemTime, duration: Duration) -> SystemTime {
    let since_epoch = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    SystemTime::UNIX_EPOCH + since_epoch.saturating_sub(duration)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ChunkDisposition {
    Complete,
    Retry,
}

struct PollProgress {
    chunk_offsets: ChunkOffsets,
    last_window_end: Option<SystemTime>,
}

impl PollProgress {
    fn from_committed(chunk_offsets: &ChunkOffsets, last_window_end: Option<SystemTime>) -> Self {
        Self {
            chunk_offsets: chunk_offsets.clone(),
            last_window_end,
        }
    }

    fn next_offset(&self, chunk_file: &str) -> Option<u64> {
        match self.chunk_offsets.get(chunk_file).copied() {
            Some(TERMINAL_CHUNK_OFFSET) => None,
            Some(offset) => Some(offset),
            None => Some(0),
        }
    }

    fn mark_decoded(&mut self, chunk_file: String, record_count: usize) {
        self.chunk_offsets.insert(chunk_file, record_count as u64);
    }

    fn mark_terminal(&mut self, chunk_file: String) {
        self.chunk_offsets.insert(chunk_file, TERMINAL_CHUNK_OFFSET);
    }

    fn commit(self, chunk_offsets: &mut ChunkOffsets, last_window_end: &mut Option<SystemTime>) {
        *chunk_offsets = self.chunk_offsets;
        *last_window_end = self.last_window_end;
    }
}

fn effective_poll_interval(requested: Duration, configured_seconds: u64) -> Duration {
    let configured = Duration::from_secs(configured_seconds).max(MIN_POLL_INTERVAL);
    let default_requested = WatchDirectoryOptions::default().poll_interval;
    if requested.is_zero() || requested == default_requested {
        configured
    } else {
        requested.max(MIN_POLL_INTERVAL)
    }
}

fn should_emit_behind_lapsed(
    last_window_end: Option<SystemTime>,
    next_window: SegmentWindow,
) -> bool {
    last_window_end
        .map(|end| end < next_window.start)
        .unwrap_or(false)
}

fn should_emit_wall_clock_lapsed(
    last_poll_at: Option<SystemTime>,
    now: SystemTime,
    poll_interval: Duration,
) -> bool {
    let Some(last_poll_at) = last_poll_at else {
        return false;
    };
    let max_lag = poll_interval.checked_mul(2).unwrap_or(Duration::MAX);
    now.duration_since(last_poll_at)
        .map(|lag| lag > max_lag)
        .unwrap_or(false)
}

fn decode_error_disposition(err: &Error) -> ChunkDisposition {
    if is_retryable(err.code()) {
        ChunkDisposition::Retry
    } else {
        ChunkDisposition::Complete
    }
}

fn chunk_get_error_disposition(err: &Error) -> Result<ChunkDisposition> {
    if err.code() == ErrorCode::NotFound {
        Ok(ChunkDisposition::Complete)
    } else if is_retryable(err.code()) {
        Ok(ChunkDisposition::Retry)
    } else {
        Err(err.clone())
    }
}

fn map_record(
    record: ChangeFeedRecord,
    filter: &WatchFilter,
    cursor_parts: CursorParts,
) -> Result<Option<BackendChangeEvent>> {
    let Some(kind) = map_event_kind(&record.event_type, filter.include_metadata_changes) else {
        return Ok(None);
    };
    let Some(key) = key_from_record(&record, &filter.container) else {
        return Ok(None);
    };
    let Some(_relative_key) = relative_key(&key, filter) else {
        return Ok(None);
    };
    let encoded_key = url_encode_path(&key);
    let mut event_address = address::join_relative(&filter.address_root, &encoded_key)?;
    let at = parse_rfc3339(&record.event_time).unwrap_or_else(SystemTime::now);
    let etag = record.etag.clone();
    // Azure change-feed records do not carry a separate `lastModified`;
    // `eventTime` is the moment the blob version was written, which is
    // semantically the modification time for `BlobCreated` and the
    // metadata-write time for `BlobPropertiesUpdated` / `BlobTierChanged`.
    let mtime = match kind {
        ChangeKind::Deleted => None,
        _ => Some(at),
    };
    // Prefer the explicit `blobVersion`/`versionId` when present
    // (versioning enabled); fall back to the etag so unversioned
    // accounts still surface a stable identity token.
    let version = record.version_id.clone().or_else(|| etag.clone());
    if let Some(version_id) = record.version_id.as_deref() {
        event_address = address::with_query_pair(&event_address, "versionid", version_id)?;
    }
    // Size is absent on deletes; `contentLength` is otherwise the
    // post-write byte count.
    let size = if kind == ChangeKind::Deleted {
        None
    } else {
        record.content_length
    };
    Ok(Some(BackendChangeEvent::Object {
        address: event_address,
        kind,
        etag,
        version,
        size,
        mtime,
        at,
        cursor: cursor(cursor_parts),
    }))
}

fn map_decoded_chunk_records(
    records: Vec<ChangeFeedRecord>,
    filter: &WatchFilter,
    mut cursor_parts: CursorParts,
    previous_offset: u64,
) -> Result<Vec<BackendChangeEvent>> {
    let mut chunk_events = Vec::new();
    for (offset, record) in records.into_iter().enumerate() {
        let offset = offset as u64;
        if offset < previous_offset {
            continue;
        }
        cursor_parts.offset = offset;
        if let Some(event) = map_record(record, filter, cursor_parts.clone())? {
            chunk_events.push(event);
        }
    }
    Ok(chunk_events)
}

fn map_event_kind(event_type: &str, include_metadata_changes: bool) -> Option<ChangeKind> {
    match event_type {
        "BlobCreated" => Some(ChangeKind::Created),
        "BlobDeleted" => Some(ChangeKind::Deleted),
        "BlobPropertiesUpdated" | "BlobTierChanged" if include_metadata_changes => {
            Some(ChangeKind::MetadataChanged)
        }
        "BlobPropertiesUpdated" | "BlobTierChanged" => None,
        _ => None,
    }
}

fn key_from_record(record: &ChangeFeedRecord, container: &str) -> Option<String> {
    let marker = format!("/blobServices/default/containers/{container}/blobs/");
    if let Some(raw) = record.subject.strip_prefix(&marker) {
        return percent_decode_key(raw);
    }
    let url = record.url.as_ref()?;
    let parsed = ovstorage_plugin::Url::parse(url).ok()?;
    let path = parsed.path().trim_start_matches('/');
    let prefix = format!("{container}/");
    path.strip_prefix(&prefix).and_then(percent_decode_key)
}

fn relative_key(key: &str, filter: &WatchFilter) -> Option<String> {
    let relative = key.strip_prefix(&filter.prefix_key)?;
    if !filter.recursive && relative.contains('/') {
        return None;
    }
    if relative.is_empty() {
        return None;
    }
    Some(relative.to_string())
}

fn cursor(parts: CursorParts) -> WatchDirectoryCursor {
    let mut body = HashMap::new();
    body.insert("v", serde_json::json!(1));
    body.insert("segment", serde_json::json!(parts.segment));
    body.insert("chunk_dir", serde_json::json!(parts.chunk_dir));
    body.insert("chunk_file", serde_json::json!(parts.chunk_file));
    body.insert("offset", serde_json::json!(parts.offset));
    WatchDirectoryCursor(serde_json::to_vec(&body).unwrap_or_default())
}

fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

fn segment_time_from_manifest(path: &str) -> Option<SystemTime> {
    let rest = path.strip_prefix("idx/segments/")?;
    let mut parts = rest.split('/');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u8>().ok()?;
    let day = parts.next()?.parse::<u8>().ok()?;
    let slot = parts.next()?;
    if slot.len() < 4 {
        return None;
    }
    let hour = slot[0..2].parse::<u8>().ok()?;
    let minute = slot[2..4].parse::<u8>().ok()?;
    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, 0).ok()?;
    Some(SystemTime::from(OffsetDateTime::new_utc(date, time)))
}

fn segment_manifest_in_window(name: &str, window: SegmentWindow) -> bool {
    let Some(at) = segment_time_from_manifest(name) else {
        return true;
    };
    let segment_end = at
        .checked_add(CHANGE_FEED_SEGMENT_DURATION)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    at <= window.end && segment_end > window.start
}

fn segment_hour_prefixes(window: SegmentWindow) -> Vec<String> {
    let Ok(start) = window.start.duration_since(SystemTime::UNIX_EPOCH) else {
        return Vec::new();
    };
    let Ok(end) = window.end.duration_since(SystemTime::UNIX_EPOCH) else {
        return Vec::new();
    };
    let mut hour = (start.as_secs() / CHANGE_FEED_SEGMENT_DURATION.as_secs())
        * CHANGE_FEED_SEGMENT_DURATION.as_secs();
    let end_hour = (end.as_secs() / CHANGE_FEED_SEGMENT_DURATION.as_secs())
        * CHANGE_FEED_SEGMENT_DURATION.as_secs();
    let mut out = Vec::new();
    while hour <= end_hour {
        if let Ok(dt) = OffsetDateTime::from_unix_timestamp(hour as i64) {
            out.push(format!(
                "idx/segments/{:04}/{:02}/{:02}/{:02}",
                dt.year(),
                u8::from(dt.month()),
                dt.day(),
                dt.hour()
            ));
        }
        hour = match hour.checked_add(CHANGE_FEED_SEGMENT_DURATION.as_secs()) {
            Some(next) => next,
            None => break,
        };
    }
    out
}

fn url_encode_path(key: &str) -> String {
    key.split('/')
        .map(|seg| urlencoding::encode(seg).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_decode_key(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut utf8 = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            let decoded = (high << 4) | low;
            utf8.push(decoded);
            index += 3;
            continue;
        }
        if bytes[index] == b'/' {
            flush_utf8(&mut out, &mut utf8)?;
            out.push('/');
        } else {
            utf8.push(bytes[index]);
        }
        index += 1;
    }
    flush_utf8(&mut out, &mut utf8)?;
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn flush_utf8(out: &mut String, utf8: &mut Vec<u8>) -> Option<()> {
    if utf8.is_empty() {
        return Some(());
    }
    out.push_str(std::str::from_utf8(utf8).ok()?);
    utf8.clear();
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS;

    fn filter(prefix_key: &str, recursive: bool, include_metadata_changes: bool) -> WatchFilter {
        WatchFilter {
            container: "container".into(),
            address_root: address::parse("azure://acct/container/").unwrap(),
            prefix_key: prefix_key.into(),
            recursive,
            include_metadata_changes,
        }
    }

    fn record(event_type: &str, key: &str) -> ChangeFeedRecord {
        ChangeFeedRecord {
            event_type: event_type.into(),
            subject: format!("/blobServices/default/containers/container/blobs/{key}"),
            event_time: "2026-05-12T10:00:00Z".into(),
            etag: Some("0x8DB".into()),
            url: None,
            content_length: Some(2048),
            version_id: None,
            metadata: HashMap::new(),
        }
    }

    fn parts() -> CursorParts {
        CursorParts {
            segment: "idx/segments/2026/05/12/1000/meta.json".into(),
            chunk_dir: "$blobchangefeed/log/00/2026/05/12/1000/".into(),
            chunk_file: "log/00/2026/05/12/1000/00000.avro".into(),
            offset: 7,
        }
    }

    fn ts(value: &str) -> SystemTime {
        parse_rfc3339(value).unwrap()
    }

    #[test]
    fn maps_created_deleted_and_metadata_events() {
        let filter = filter("dir/", true, true);
        let created = map_record(record("BlobCreated", "dir/a.txt"), &filter, parts())
            .unwrap()
            .unwrap();
        let BackendChangeEvent::Object {
            kind,
            address,
            etag,
            version,
            size,
            mtime,
            cursor,
            ..
        } = created
        else {
            panic!("expected object event");
        };
        assert_eq!(kind, ChangeKind::Created);
        assert_eq!(address.as_str(), "azure://acct/container/dir/a.txt");
        assert_eq!(etag.as_deref(), Some("0x8DB"));
        // Unversioned account: `version` falls back to the etag so the
        // SPI carries a stable identity token.
        assert_eq!(version.as_deref(), Some("0x8DB"));
        assert_eq!(size, Some(2048));
        // `mtime` is sourced from `eventTime` since Azure change feed
        // records do not carry a separate lastModified.
        assert_eq!(mtime, Some(ts("2026-05-12T10:00:00Z")));
        assert!(
            String::from_utf8(cursor.0)
                .unwrap()
                .contains("\"offset\":7")
        );

        let deleted = map_record(record("BlobDeleted", "dir/a.txt"), &filter, parts())
            .unwrap()
            .unwrap();
        let BackendChangeEvent::Object {
            kind, size, mtime, ..
        } = deleted
        else {
            panic!("expected object event");
        };
        assert_eq!(kind, ChangeKind::Deleted);
        // Deletes carry neither a post-state byte count nor a mtime.
        assert!(size.is_none());
        assert!(mtime.is_none());

        let metadata = map_record(
            record("BlobPropertiesUpdated", "dir/a.txt"),
            &filter,
            parts(),
        )
        .unwrap()
        .unwrap();
        let BackendChangeEvent::Object { kind, .. } = metadata else {
            panic!("expected object event");
        };
        assert_eq!(kind, ChangeKind::MetadataChanged);

        let metadata = map_record(record("BlobTierChanged", "dir/a.txt"), &filter, parts())
            .unwrap()
            .unwrap();
        let BackendChangeEvent::Object { kind, .. } = metadata else {
            panic!("expected object event");
        };
        assert_eq!(kind, ChangeKind::MetadataChanged);

        assert!(
            map_record(record("BlobMetadataUpdated", "dir/a.txt"), &filter, parts())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn filters_prefix_recursive_and_metadata_gate() {
        assert!(
            map_record(
                record("BlobCreated", "other/a.txt"),
                &filter("dir/", true, true),
                parts()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            map_record(
                record("BlobCreated", "dir/sub/a.txt"),
                &filter("dir/", false, true),
                parts()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            map_record(
                record("BlobTierChanged", "dir/a.txt"),
                &filter("dir/", true, false),
                parts(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            map_record(
                record("BlobPropertiesUpdated", "dir/a.txt"),
                &filter("dir/", true, false),
                parts(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            map_record(
                record("BlobRenamed", "dir/a.txt"),
                &filter("dir/", true, true),
                parts()
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn percent_decodes_subject_key_before_filtering_and_emitting() {
        let event = map_record(
            record("BlobCreated", "dir/a%20b%25%E2%98%83.txt"),
            &filter("dir/", true, true),
            parts(),
        )
        .unwrap()
        .unwrap();
        let BackendChangeEvent::Object { address, .. } = event else {
            panic!("expected object event");
        };
        assert_eq!(
            address.as_str(),
            "azure://acct/container/dir/a%20b%25%E2%98%83.txt"
        );
    }

    #[test]
    fn percent_decodes_url_key_before_filtering_and_emitting() {
        let mut record = record("BlobCreated", "unmatched");
        record.subject = "/blobServices/default/containers/other/blobs/dir/a.txt".into();
        record.url =
            Some("https://acct.blob.core.windows.net/container/dir/a%20b%25%E2%98%83.txt".into());
        let event = map_record(record, &filter("dir/", true, true), parts())
            .unwrap()
            .unwrap();
        let BackendChangeEvent::Object { address, .. } = event else {
            panic!("expected object event");
        };
        assert_eq!(
            address.as_str(),
            "azure://acct/container/dir/a%20b%25%E2%98%83.txt"
        );
    }

    #[test]
    fn encoded_slash_matches_directory_watch() {
        let event = map_record(
            record("BlobCreated", "dir%2Ffile.txt"),
            &filter("dir/", true, true),
            parts(),
        )
        .unwrap()
        .unwrap();
        let BackendChangeEvent::Object { address, .. } = event else {
            panic!("expected object event");
        };
        assert_eq!(address.as_str(), "azure://acct/container/dir/file.txt");
    }

    #[test]
    fn encoded_slash_emits_decoded_key_for_root_watch() {
        let event = map_record(
            record("BlobCreated", "dir%2Ffile.txt"),
            &filter("", true, true),
            parts(),
        )
        .unwrap()
        .unwrap();
        let BackendChangeEvent::Object { address, .. } = event else {
            panic!("expected object event");
        };
        assert_eq!(address.as_str(), "azure://acct/container/dir/file.txt");
    }

    #[test]
    fn encoded_slash_in_url_matches_directory_watch() {
        let mut record = record("BlobCreated", "unmatched");
        record.subject = "/blobServices/default/containers/other/blobs/dir/file.txt".into();
        record.url = Some("https://acct.blob.core.windows.net/container/dir%2Ffile.txt".into());
        let event = map_record(record, &filter("dir/", true, true), parts())
            .unwrap()
            .unwrap();
        let BackendChangeEvent::Object { address, .. } = event else {
            panic!("expected object event");
        };
        assert_eq!(address.as_str(), "azure://acct/container/dir/file.txt");
    }

    #[test]
    fn chunk_offsets_emit_only_appended_records() {
        let mut progress = PollProgress::from_committed(&HashMap::new(), None);
        let chunk_file = "log/00/2026/05/12/1000/00000.avro".to_string();
        let first = vec![
            record("BlobCreated", "dir/a.txt"),
            record("BlobCreated", "dir/b.txt"),
        ];
        let first_events =
            map_decoded_chunk_records(first, &filter("dir/", true, true), parts(), 0).unwrap();
        progress.mark_decoded(chunk_file.clone(), 2);
        assert_eq!(first_events.len(), 2);
        assert_eq!(progress.next_offset(&chunk_file), Some(2));

        let appended = vec![
            record("BlobCreated", "dir/a.txt"),
            record("BlobCreated", "dir/b.txt"),
            record("BlobCreated", "dir/c.txt"),
        ];
        let appended_events = map_decoded_chunk_records(
            appended,
            &filter("dir/", true, true),
            parts(),
            progress.next_offset(&chunk_file).unwrap(),
        )
        .unwrap();
        progress.mark_decoded(chunk_file.clone(), 3);
        assert_eq!(appended_events.len(), 1);
        let BackendChangeEvent::Object { address, .. } = &appended_events[0] else {
            panic!("expected object event");
        };
        assert_eq!(address.as_str(), "azure://acct/container/dir/c.txt");
        assert_eq!(progress.next_offset(&chunk_file), Some(3));
    }

    #[test]
    fn retryable_partial_poll_does_not_commit_pending_chunk_offsets() {
        let mut committed = HashMap::new();
        let mut committed_window = None;
        let mut progress = PollProgress::from_committed(&committed, committed_window);
        progress.mark_decoded("log/00/2026/05/12/1000/00000.avro".into(), 2);
        progress.last_window_end = Some(ts("2026-05-12T10:00:00Z"));

        let transient = Error::new(ErrorCode::Transient, "retry");
        assert_eq!(
            chunk_get_error_disposition(&transient).unwrap(),
            ChunkDisposition::Retry
        );
        drop(progress);
        assert!(committed.is_empty());
        assert!(committed_window.is_none());

        let mut progress = PollProgress::from_committed(&committed, committed_window);
        progress.mark_decoded("log/00/2026/05/12/1000/00000.avro".into(), 2);
        progress.last_window_end = Some(ts("2026-05-12T10:00:00Z"));
        progress.commit(&mut committed, &mut committed_window);
        assert_eq!(committed.get("log/00/2026/05/12/1000/00000.avro"), Some(&2));
        assert_eq!(committed_window, Some(ts("2026-05-12T10:00:00Z")));
    }

    #[test]
    fn parses_segment_time_from_manifest_path() {
        let parsed = segment_time_from_manifest("idx/segments/2026/05/12/1030/meta.json")
            .expect("segment timestamp");
        let expected = parse_rfc3339("2026-05-12T10:30:00Z").unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn live_segment_window_filters_retained_history_and_open_tail() {
        let window = SegmentWindow::live(ts("2026-05-12T10:05:00Z"), Duration::from_secs(60));
        assert_eq!(window.start, ts("2026-05-12T09:04:00Z"));
        assert_eq!(window.end, ts("2026-05-12T10:04:00Z"));

        let retained = "idx/segments/2026/05/12/0800/meta.json";
        let overlapping_lower_bound = "idx/segments/2026/05/12/0900/meta.json";
        let current = "idx/segments/2026/05/12/1000/meta.json";
        let open_tail = "idx/segments/2026/05/12/1005/meta.json";
        assert!(!segment_manifest_in_window(retained, window));
        assert!(segment_manifest_in_window(overlapping_lower_bound, window));
        assert!(segment_manifest_in_window(current, window));
        assert!(!segment_manifest_in_window(open_tail, window));
        assert_eq!(
            segment_hour_prefixes(window),
            vec![
                "idx/segments/2026/05/12/09".to_string(),
                "idx/segments/2026/05/12/10".to_string()
            ]
        );
    }

    #[test]
    fn live_segment_window_saturates_before_unix_epoch() {
        let window = SegmentWindow::live(
            SystemTime::UNIX_EPOCH + Duration::from_secs(30),
            Duration::from_secs(60),
        );
        assert_eq!(window.start, SystemTime::UNIX_EPOCH);
        assert_eq!(window.end, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn behind_lapsed_guard_trips_when_live_window_leaps_past_processed_end() {
        let previous_end = ts("2026-05-12T10:00:00Z");
        let contiguous = SegmentWindow {
            start: ts("2026-05-12T09:00:00Z"),
            end: ts("2026-05-12T10:30:00Z"),
        };
        let missed = SegmentWindow {
            start: ts("2026-05-12T10:00:01Z"),
            end: ts("2026-05-12T11:00:00Z"),
        };
        assert!(!should_emit_behind_lapsed(Some(previous_end), contiguous));
        assert!(should_emit_behind_lapsed(Some(previous_end), missed));
        assert!(!should_emit_behind_lapsed(None, missed));
    }

    #[test]
    fn wall_clock_lapsed_guard_trips_after_twice_poll_interval() {
        let last_poll_at = ts("2026-05-12T10:00:00Z");
        assert!(!should_emit_wall_clock_lapsed(
            Some(last_poll_at),
            ts("2026-05-12T10:00:02Z"),
            Duration::from_secs(1)
        ));
        assert!(should_emit_wall_clock_lapsed(
            Some(last_poll_at),
            ts("2026-05-12T10:00:03Z"),
            Duration::from_secs(1)
        ));
        assert!(!should_emit_wall_clock_lapsed(
            None,
            ts("2026-05-12T10:00:03Z"),
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn default_watch_poll_interval_uses_azure_configured_default() {
        assert_eq!(
            effective_poll_interval(
                WatchDirectoryOptions::default().poll_interval,
                DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS
            ),
            Duration::from_secs(DEFAULT_CHANGE_FEED_POLL_INTERVAL_SECONDS)
        );
        assert_eq!(
            effective_poll_interval(Duration::ZERO, 30),
            Duration::from_secs(30)
        );
        assert_eq!(
            effective_poll_interval(Duration::from_secs(3), 30),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn subscription_iter_drains_queued_events_before_fatal() {
        let (tx, rx) = mpsc::sync_channel(2);
        let (fatal_tx, fatal_rx) = watch::channel(None);
        tx.send(Ok(BackendChangeEvent::Lapsed {
            since: None,
            cursor: WatchDirectoryCursor::default(),
        }))
        .unwrap();
        tx.send(Ok(BackendChangeEvent::Object {
            address: address::parse("azure://acct/container/queued.txt").unwrap(),
            kind: ChangeKind::Created,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            at: SystemTime::UNIX_EPOCH,
            cursor: WatchDirectoryCursor::default(),
        }))
        .unwrap();
        publish_fatal(&fatal_tx, Error::new(ErrorCode::Internal, "fatal"));

        let mut iter = SubscriptionIter {
            rx: Some(rx),
            fatal_rx,
            done: false,
        };
        assert!(matches!(
            iter.next().unwrap().unwrap(),
            BackendChangeEvent::Lapsed { .. }
        ));
        let BackendChangeEvent::Object { address, .. } = iter.next().unwrap().unwrap() else {
            panic!("expected queued object event");
        };
        assert_eq!(address.as_str(), "azure://acct/container/queued.txt");
        assert_eq!(
            iter.next().unwrap().unwrap_err().code(),
            ErrorCode::Internal
        );
        assert!(iter.rx.is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn chunk_completion_disposition_keeps_retryable_failures_uncompleted() {
        let transient = Error::new(ErrorCode::Transient, "retry");
        let throttled = Error::new(ErrorCode::ResourceExhausted, "retry");
        let corrupt = Error::new(ErrorCode::Internal, "corrupt");
        let unsupported = Error::new(ErrorCode::Unsupported, "unsupported codec");
        assert_eq!(
            decode_error_disposition(&transient),
            ChunkDisposition::Retry
        );
        assert_eq!(
            decode_error_disposition(&throttled),
            ChunkDisposition::Retry
        );
        assert_eq!(
            decode_error_disposition(&corrupt),
            ChunkDisposition::Complete
        );
        assert_eq!(
            decode_error_disposition(&unsupported),
            ChunkDisposition::Complete
        );

        let missing = Error::new(ErrorCode::NotFound, "missing");
        let denied = Error::new(ErrorCode::PermissionDenied, "denied");
        assert_eq!(
            chunk_get_error_disposition(&missing).unwrap(),
            ChunkDisposition::Complete
        );
        assert_eq!(
            chunk_get_error_disposition(&transient).unwrap(),
            ChunkDisposition::Retry
        );
        assert_eq!(
            chunk_get_error_disposition(&denied).unwrap_err().code(),
            ErrorCode::PermissionDenied
        );
    }
}
