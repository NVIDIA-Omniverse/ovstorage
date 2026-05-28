// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming-invariant test helpers. See the README for the seam
//! inventory and the rule that every seam needs a test using this
//! module.
//!
//! The time-spread assertion is the reliable buffering signal:
//! chunks landing within microseconds of each other means the seam
//! drained to a buffer. Max-in-flight is approximate because not
//! every seam can observe consume.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ovstorage_plugin::shim::{Backend, BackendInstance, Factory};
use ovstorage_plugin::{
    AddressRoot, AddressVisibility, BackendId, BackendItemInfo, BodyStream, CancellationToken,
    Capabilities, ChecksumSet, ConfigField, ConfigFieldKind, ConfigLayer, ConfigValue,
    ConnectionAuthState, ConnectionRequest, CreateDirectoryOptions, DeleteDirectoryOptions,
    DeleteOptions, Error, ErrorCode, ListOptions, ObjectInfo, ObjectKind, ReadOptions, ReadResult,
    ResolvedTarget, Result, RouteSource, StatOptions, StorageBackendKindDescriptor, Url,
    UserMetadata, WriteOptions, WriteResult, address,
};

/// One observed chunk crossing a seam.
#[derive(Clone, Debug)]
pub struct ChunkObservation {
    pub size: usize,
    pub at: Instant,
}

/// Records chunk arrivals at a seam.
#[derive(Debug, Default)]
pub struct StreamingRecorder {
    inner: Mutex<RecorderInner>,
}

#[derive(Debug, Default)]
struct RecorderInner {
    chunks: Vec<ChunkObservation>,
    max_in_flight: usize,
    current_in_flight: usize,
}

impl StreamingRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bridge calls this when bytes reach the far side of the seam.
    pub fn record_arrival(&self, size: usize) {
        let mut inner = self.inner.lock().expect("StreamingRecorder mutex poisoned");
        inner.chunks.push(ChunkObservation {
            size,
            at: Instant::now(),
        });
        inner.current_in_flight = inner.current_in_flight.saturating_add(size);
        inner.max_in_flight = inner.max_in_flight.max(inner.current_in_flight);
    }

    /// Optional: bridge calls this when the chunk is fully consumed,
    /// so in-flight bookkeeping reflects it.
    pub fn record_release(&self, size: usize) {
        let mut inner = self.inner.lock().expect("StreamingRecorder mutex poisoned");
        inner.current_in_flight = inner.current_in_flight.saturating_sub(size);
    }

    pub fn observations(&self) -> Vec<ChunkObservation> {
        self.inner
            .lock()
            .expect("StreamingRecorder mutex poisoned")
            .chunks
            .clone()
    }

    pub fn max_in_flight(&self) -> usize {
        self.inner
            .lock()
            .expect("StreamingRecorder mutex poisoned")
            .max_in_flight
    }
}

/// Build a `BodyStream` of `num_chunks` chunks of `chunk_size` bytes.
/// Chunk `i` is filled with `i as u8` so receivers can verify ordering.
pub fn make_test_stream(num_chunks: usize, chunk_size: usize) -> BodyStream {
    BodyStream::from_iter((0..num_chunks).map(move |i| Ok(vec![i as u8; chunk_size])))
}

/// 16 chunks at 4 MiB = 64 MiB; enough that buffering shows up as a
/// memory spike.
pub const DEFAULT_NUM_CHUNKS: usize = 16;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Asserts chunk count, time spread (catches buffering), and an
/// optional in-flight bound. `max_in_flight_bound = None` skips the
/// in-flight check; the time-spread assertion alone still catches
/// buffering.
pub fn assert_streaming_invariants(
    recorder: &StreamingRecorder,
    expected_chunks: usize,
    min_spread: Duration,
    max_in_flight_bound: Option<usize>,
) {
    let observed = recorder.observations();
    assert_eq!(
        observed.len(),
        expected_chunks,
        "chunk count: expected {expected_chunks}, got {}",
        observed.len()
    );
    if observed.len() > 1 {
        let spread = observed
            .last()
            .expect("non-empty checked above")
            .at
            .duration_since(observed.first().expect("non-empty checked above").at);
        assert!(
            spread >= min_spread,
            "chunks arrived all at once (spread {spread:?} < {min_spread:?}): seam is buffering"
        );
    }
    if let Some(bound) = max_in_flight_bound {
        let actual = recorder.max_in_flight();
        assert!(
            actual <= bound,
            "max in-flight bytes {actual} exceeded bound {bound}: seam buffered"
        );
    }
}

/// A `Backend` that records each chunk arriving at `write_stream`
/// against a `StreamingRecorder`, with a small per-chunk sleep so the
/// time-spread assertion has a meaningful gap to compare against.
/// Used by per-seam streaming-invariant tests; *not* a general-purpose
/// fake — it returns `Unsupported` for everything other than `stat`,
/// `read`, and `write_stream`.
pub struct RecordingStreamBackend {
    recorder: Arc<StreamingRecorder>,
    per_chunk_pause: Duration,
}

impl RecordingStreamBackend {
    /// Default per-chunk pause (50µs) yields ≥800µs spread for a
    /// 16-chunk test stream — well above the 100µs assertion floor.
    pub const DEFAULT_PER_CHUNK_PAUSE: Duration = Duration::from_micros(50);

    pub fn capabilities() -> Capabilities {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_list = true;
        capabilities.supports_write_stream = true;
        capabilities
    }

    pub fn new(recorder: Arc<StreamingRecorder>) -> Self {
        Self {
            recorder,
            per_chunk_pause: Self::DEFAULT_PER_CHUNK_PAUSE,
        }
    }
}

#[async_trait::async_trait]
impl Backend for RecordingStreamBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test stub: synthesizes responses without async work
        Ok(dummy_info(target.resolved_address, 0))
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test stub: synthesizes responses without async work
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info: dummy_info(target.resolved_address, 0),
        })
    }

    async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: BodyStream,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test stub: drains body synchronously without honoring cancel
        let mut total = 0usize;
        for chunk in body {
            let chunk = chunk?;
            self.recorder.record_arrival(chunk.len());
            std::thread::sleep(self.per_chunk_pause);
            self.recorder.record_release(chunk.len());
            total += chunk.len();
        }
        Ok(WriteResult {
            info: dummy_info(target.resolved_address, total as u64),
        })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test stub: synchronous no-op
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test stub: synchronous no-op
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test stub: returns Unsupported synchronously
        Err(Error::new(
            ErrorCode::Unsupported,
            "RecordingStreamBackend does not implement create_directory",
        ))
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test stub: returns Unsupported synchronously
        Err(Error::new(
            ErrorCode::Unsupported,
            "RecordingStreamBackend does not implement delete_directory",
        ))
    }
}

/// `Factory` that hands every connection a fresh
/// [`RecordingStreamBackend`] sharing the recorder. Backend kind is
/// `"stream-recorder"`; connections take a single `prefix` config
/// field naming the address root.
pub struct RecordingStreamFactory {
    recorder: Arc<StreamingRecorder>,
}

impl RecordingStreamFactory {
    pub const KIND: &'static str = "stream-recorder";

    pub fn new(recorder: Arc<StreamingRecorder>) -> Self {
        Self { recorder }
    }
}

#[async_trait::async_trait]
impl Factory for RecordingStreamFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: Self::KIND.into(),
            display_name: "Streaming Recorder".into(),
            description: None,
            config_schema: vec![ConfigField {
                key: "prefix".into(),
                display_name: "Prefix".into(),
                kind: ConfigFieldKind::Url,
                required: true,
                default: None,
                help: None,
                example: Some("rec://root/".into()),
                group: None,
                advanced: false,
            }],
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendInstance> {
        let _ = &cancel; // test stub: synchronous in-memory construction
        let prefix = prefix_from(request)?;
        let backend = Arc::new(RecordingStreamBackend::new(self.recorder.clone()));
        let capabilities = RecordingStreamBackend::capabilities();
        Ok(BackendInstance {
            backend_id: BackendId(format!("stream-recorder:{prefix}")),
            backend,
            address_roots: vec![AddressRoot {
                address: prefix,
                display_name: None,
                backend_kind: "stream-recorder".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request.display_name.clone(),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

/// Build a `ConnectionRequest` for [`RecordingStreamFactory`] with the
/// given prefix.
pub fn recording_stream_connection_request(prefix: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("prefix".into(), ConfigValue::String(prefix.into()));
    ConnectionRequest {
        backend_kind: RecordingStreamFactory::KIND.into(),
        config,
        credentials: ovstorage_plugin::SecretBundle::default(),
        persist: false,
        display_name: Some("rec".into()),
    }
}

fn dummy_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn prefix_from(request: &ConnectionRequest) -> Result<Url> {
    let prefix = request
        .config
        .get("prefix")
        .and_then(|v| match v {
            ConfigValue::String(s) => Some(s.as_str()),
            _ => None,
        })
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "missing prefix"))?;
    address::parse(prefix).map_err(|err| Error::new(ErrorCode::InvalidArgument, err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_test_stream_preserves_chunk_order_and_sizes() {
        let mut stream = make_test_stream(3, 16);
        let c0 = stream.next_chunk().unwrap().unwrap();
        let c1 = stream.next_chunk().unwrap().unwrap();
        let c2 = stream.next_chunk().unwrap().unwrap();
        assert!(stream.next_chunk().is_none());
        assert_eq!(c0.len(), 16);
        assert_eq!(c0[0], 0);
        assert_eq!(c1[0], 1);
        assert_eq!(c2[0], 2);
    }

    #[test]
    fn recorder_tracks_in_flight_high_water() {
        let r = StreamingRecorder::new();
        r.record_arrival(100);
        r.record_arrival(50);
        assert_eq!(r.max_in_flight(), 150);
        r.record_release(100);
        r.record_arrival(25);
        assert_eq!(r.max_in_flight(), 150);
    }

    #[test]
    fn assert_invariants_passes_for_a_streaming_consumer() {
        let r = StreamingRecorder::new();
        for i in 0..3 {
            r.record_arrival(10);
            r.record_release(10);
            if i < 2 {
                std::thread::sleep(Duration::from_micros(50));
            }
        }
        assert_streaming_invariants(&r, 3, Duration::from_micros(10), Some(20));
    }

    #[test]
    #[should_panic(expected = "seam is buffering")]
    fn assert_invariants_fails_when_chunks_land_at_once() {
        let r = StreamingRecorder::new();
        // Instant-burst pattern: bridge buffered before notifying.
        for _ in 0..3 {
            r.record_arrival(10);
            r.record_release(10);
        }
        assert_streaming_invariants(&r, 3, Duration::from_millis(1), None);
    }

    #[test]
    #[should_panic(expected = "max in-flight bytes")]
    fn assert_invariants_fails_when_in_flight_bound_exceeded() {
        let r = StreamingRecorder::new();
        for _ in 0..3 {
            r.record_arrival(10);
            // No release; sleep lets time-spread pass so the in-flight
            // bound is what fails.
            std::thread::sleep(Duration::from_micros(50));
        }
        assert_streaming_invariants(&r, 3, Duration::from_micros(1), Some(15));
    }
}
