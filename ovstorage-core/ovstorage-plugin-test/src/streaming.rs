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
use std::time::{Duration, Instant, SystemTime};

use ovstorage_plugin::{
    AddressVisibility, BackendFactory, BackendId, Body, BodyStream, CancellationToken,
    Capabilities, ChecksumSet, ConfigField, ConfigFieldKind, ConfigLayer, ConfigValue, Connection,
    ConnectionAuthState, ConnectionId, ConnectionRequest, ConnectionSnapshot, ConnectionSource,
    ConnectionUpdateStream, Error, ErrorCode, Extensions, Layer, LayerConfig,
    LayerConnectionRequest, LayerHandle, LayerKindDescriptor, ObjectInfo, ObjectKind,
    RangeReadStrategy, Request, ResolvedTarget, Result, RootInfo, RootInfoSnapshot,
    RootInfoUpdateStream, RouteSource, SecretBundle, StorageBackendKindDescriptor, Url,
    UserMetadata, WriteOptions, WriteRequest, WriteResult, address, body_stream_from_file,
    descriptor_to_layer_kind, fresh_id,
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

impl RecordingStreamBackend {
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
}

const RECORDING_STREAM_KIND: &str = "stream-recorder";

/// Native ABI-v2 factory for the recording stream backend.
///
/// Seam tests compose it directly into a [`Stack`](ovstorage_plugin::Stack), keeping
/// their streaming assertions on the native Layer dispatch path.
pub struct RecordingStreamLayerFactory {
    recorder: Arc<StreamingRecorder>,
}

impl RecordingStreamLayerFactory {
    pub fn new(recorder: Arc<StreamingRecorder>) -> Self {
        Self { recorder }
    }
}

#[async_trait::async_trait]
impl BackendFactory for RecordingStreamLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&recording_stream_descriptor())
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(RecordingStreamLayer {
            name: name.to_string(),
            recorder: self.recorder.clone(),
            connection: Mutex::new(None),
        });
        if !config.is_empty() {
            layer.install_connection(
                ConnectionRequest {
                    backend_kind: RECORDING_STREAM_KIND.into(),
                    config: config.clone(),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
                ConnectionSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
            )?;
        }
        Ok(layer)
    }
}

struct RecordingConnection {
    root: Url,
    connection: Connection,
}

struct RecordingStreamLayer {
    name: String,
    recorder: Arc<StreamingRecorder>,
    connection: Mutex<Option<RecordingConnection>>,
}

impl RecordingStreamLayer {
    fn install_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
    ) -> Result<Connection> {
        if request.backend_kind != RECORDING_STREAM_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "connection kind does not match recording stream layer",
            ));
        }
        let root = prefix_from(&request)?;
        let connection = Connection {
            id: ConnectionId(fresh_id(RECORDING_STREAM_KIND)),
            backend_kind: RECORDING_STREAM_KIND.into(),
            display_name: request
                .display_name
                .unwrap_or_else(|| "Streaming Recorder".into()),
            source,
            capabilities: RecordingStreamBackend::capabilities(),
            current_addresses: vec![root.clone()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
        };
        *self.connection.lock().expect("recording connection") = Some(RecordingConnection {
            root,
            connection: connection.clone(),
        });
        Ok(connection)
    }

    fn root_info(entry: &RecordingConnection) -> RootInfo {
        let source = match &entry.connection.source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: entry.connection.id.clone(),
            },
        };
        RootInfo {
            root: entry.root.clone(),
            display_name: None,
            layer_kind: RECORDING_STREAM_KIND.into(),
            connection_id: Some(entry.connection.id.clone()),
            owning_target: None,
            capabilities: RecordingStreamBackend::capabilities(),
            range_read_strategy: RangeReadStrategy::Native,
            source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    fn target(&self, address: &Url) -> Result<ResolvedTarget> {
        let guard = self.connection.lock().expect("recording connection");
        let entry = guard.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NoRoute,
                "recording stream layer has no connection",
            )
        })?;
        if !ovstorage_plugin::address::is_ancestor_or_self(&entry.root, address) {
            return Err(Error::new(
                ErrorCode::NoRoute,
                "address is outside recording root",
            ));
        }
        Ok(ResolvedTarget {
            backend_id: BackendId(format!("stream-recorder:{}", entry.root)),
            resolved_address: address.clone(),
        })
    }
}

#[async_trait::async_trait]
impl Layer for RecordingStreamLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&recording_stream_descriptor())
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.target(url)?;
        let guard = self.connection.lock().expect("recording connection");
        Ok(Self::root_info(
            guard.as_ref().expect("target proved connection"),
        ))
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        let roots = self
            .connection
            .lock()
            .expect("recording connection")
            .as_ref()
            .map(Self::root_info)
            .into_iter()
            .collect();
        Ok((
            RootInfoSnapshot {
                roots,
                updates: false,
            },
            None,
        ))
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let target = self.target(&request.input.address)?;
        let body = match request.input.body {
            Body::Bytes(bytes) => BodyStream::from_iter(std::iter::once(Ok(bytes))),
            Body::LocalFile(path) => body_stream_from_file(&path)?,
            Body::Stream(stream) => stream,
        };
        RecordingStreamBackend::new(self.recorder.clone())
            .write_stream(target, body, request.input.options, cancel)
            .await
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write(request, cancel).await
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let persist = request.input.connection.persist;
        self.install_connection(
            request.input.connection,
            ConnectionSource::Runtime { persisted: persist },
        )
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        let connections = self
            .connection
            .lock()
            .expect("recording connection")
            .as_ref()
            .map(|entry| entry.connection.clone())
            .into_iter()
            .collect();
        Ok((
            ConnectionSnapshot {
                connections,
                updates: false,
            },
            None,
        ))
    }
}

fn recording_stream_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: RECORDING_STREAM_KIND.into(),
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
        supports_user_metadata: true,
    }
}

/// Build a `ConnectionRequest` for [`RecordingStreamLayerFactory`] with the
/// given prefix.
pub fn recording_stream_connection_request(prefix: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("prefix".into(), ConfigValue::String(prefix.into()));
    ConnectionRequest {
        backend_kind: RECORDING_STREAM_KIND.into(),
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
