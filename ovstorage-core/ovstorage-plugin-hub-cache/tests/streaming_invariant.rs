// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-seam `streaming_invariant` test for the hub cache's read tee. The
//! seam is the wrapper's returned [`ReadResult::Stream`]: chunks must flow
//! from the inner layer through the staging tee to the caller one at a
//! time, never collected into a buffer, while the tee spools them into the
//! hub's reserved file on the side.
//!
//! Arrivals are recorded where bytes ENTER the seam (the inner stream
//! producing a chunk) and released where they leave it (the consumer
//! finishing one), so `max_in_flight` measures exactly what the wrapper
//! holds between the two — a wrapper that drained the body would fail both
//! the in-flight bound and the time-spread assertion.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_hub_client::fake::{EntryState, FakeHub};
use ovstorage_hub_client::{KeyScheme, hub_key};
use ovstorage_plugin::{
    CancellationToken, ChecksumSet, ConfigValue, EtagStrength, Layer, LayerConfig,
    LayerKindDescriptor, LayerType, ObjectInfo, ObjectKind, ReadRequest, ReadResult, ReadStream,
    Request, Result, StatRequest, Url, WrapperFactory as _,
};
use ovstorage_plugin_hub_cache::HubCacheWrapperFactory;
use ovstorage_plugin_test::streaming::{
    DEFAULT_CHUNK_SIZE, DEFAULT_NUM_CHUNKS, StreamingRecorder, assert_streaming_invariants,
};

const ADDRESS: &str = "test:///assets/large-scene.usd";
const ETAG: &str = "v1";
const TOTAL: usize = DEFAULT_NUM_CHUNKS * DEFAULT_CHUNK_SIZE;

/// A backend whose `read` produces the 64 MiB test body chunk-by-chunk,
/// recording each chunk as it enters the seam. `stat` reports the identity
/// the wrapper keys the fill on.
struct PacedBackend {
    recorder: Arc<StreamingRecorder>,
}

impl PacedBackend {
    fn info(address: Url) -> ObjectInfo {
        ObjectInfo {
            address,
            kind: ObjectKind::File,
            etag: Some(ETAG.to_string()),
            etag_strength: EtagStrength::Strong,
            version: None,
            size: Some(TOTAL as u64),
            mtime: Some(SystemTime::UNIX_EPOCH),
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }
}

#[async_trait]
impl Layer for PacedBackend {
    fn name(&self) -> &str {
        "paced"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: "paced".to_string(),
            kind: "paced".to_string(),
            layer_type: LayerType::Backend,
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        Ok(Self::info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let recorder = self.recorder.clone();
        let stream: ReadStream = Box::pin(futures::stream::unfold(0usize, move |index| {
            let recorder = recorder.clone();
            async move {
                if index == DEFAULT_NUM_CHUNKS {
                    return None;
                }
                recorder.record_arrival(DEFAULT_CHUNK_SIZE);
                let chunk = bytes::Bytes::from(vec![index as u8; DEFAULT_CHUNK_SIZE]);
                Some((Ok(chunk), index + 1))
            }
        }));
        Ok(ReadResult::Stream {
            stream,
            info: Self::info(request.input.address),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_read_tee_passes_streaming_invariants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hub = FakeHub::start(dir.path()).await;
    let recorder = Arc::new(StreamingRecorder::new());
    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(hub.endpoint()));
    let wrapper = HubCacheWrapperFactory
        .create_wrapper(
            "hub-cache",
            &config,
            Arc::new(PacedBackend {
                recorder: recorder.clone(),
            }),
            None,
        )
        .await
        .expect("the wrapper builds");

    let result = wrapper
        .read(
            Request::new(ReadRequest {
                address: Url::parse(ADDRESS).unwrap(),
                options: Default::default(),
            }),
            None,
        )
        .await
        .expect("the read succeeds");
    let ReadResult::Stream { mut stream, .. } = result else {
        panic!("a streamed miss stays a stream");
    };

    // 16 × 4 MiB = 64 MiB through the tee, one chunk in hand at a time.
    let mut index = 0usize;
    let mut total = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("a chunk");
        assert_eq!(chunk.len(), DEFAULT_CHUNK_SIZE);
        assert!(
            chunk.iter().all(|byte| *byte == index as u8),
            "chunk {index} arrived out of order or corrupted"
        );
        total += chunk.len();
        tokio::time::sleep(Duration::from_micros(50)).await;
        recorder.record_release(chunk.len());
        index += 1;
    }
    assert_eq!(total, TOTAL);

    assert_streaming_invariants(
        &recorder,
        DEFAULT_NUM_CHUNKS,
        // 50µs of consumer work per chunk × 16 ≈ 800µs; 100µs is a
        // comfortable lower bound that still catches an eager drain.
        Duration::from_micros(100),
        // One chunk in hand plus one being staged; four leaves room for
        // slow CI runners without admitting a drained body.
        Some(DEFAULT_CHUNK_SIZE * 4),
    );

    // The tee committed the very bytes it forwarded.
    let url = Url::parse(ADDRESS).unwrap();
    let key = hub_key(KeyScheme::Ovstorage, "local", &url, ETAG, None).expect("the etag keys");
    assert_eq!(
        hub.entry(&key.key),
        Some(EntryState::Committed {
            size: TOTAL as u64,
            extension: "bin".to_string()
        })
    );
}
