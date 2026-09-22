// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hot read-path micro-benchmarks over the shipped `Stack` / `LayerExt`
//! surface, with zero I/O: every byte comes from an in-memory backend, so
//! the numbers price the host-side machinery, not a disk or network.
//!
//! Two configurations bracket the framework cost:
//!
//! - `stack`: the routed `Stack` over the in-process test backend factory —
//!   canonicalization, routing, and dispatch with no ABI crossing.
//! - `ffi`: the same operations on a payload layer called directly
//!   (`inproc`) versus through `export_handle` +
//!   `import_handle_force_foreign` (`foreign`), so the inproc/foreign delta
//!   is exactly one ABI-v2 codec crossing. Buffered (`bytes_result`) and
//!   streamed (`stream_result`) shapes are separate ids because the
//!   streamed crossing pays a bridge thread plus bounded channels per read.
//!
//! Wall-time on shared runners is noisy; these numbers are for local
//! comparison and CI trend recording, not gating.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::StreamExt as _;
use ovstorage::ext::LayerExt;
use ovstorage::{
    Body, CancellationToken, ChecksumSet, ConfigValue, ConnectionRequest, Layer,
    LayerConnectionRequest, LayerKindDescriptor, LayerSpec, LayerType, ObjectInfo, ObjectKind,
    ReadOptions, ReadRequest, ReadResult, Request, Result, Stack, StatOptions, StatRequest, Url,
    WriteOptions, export_handle, import_handle_force_foreign,
};
use ovstorage_plugin_test::TestLayerFactory;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;
const SIZES: [(u64, &str); 2] = [(4 * KIB, "4KiB"), (MIB, "1MiB")];

/// Chunk granularity for the streamed shape; matches the order of magnitude
/// network backends emit, so the per-chunk crossing count is realistic.
const STREAM_CHUNK: usize = 64 * KIB as usize;

fn payload(size: u64) -> Vec<u8> {
    (0..size).map(|byte| (byte % 251) as u8).collect()
}

fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build bench runtime")
}

/// Configure a group for sub-millisecond async operations: long criterion
/// defaults would put this file's wall time far past its information value.
fn tune(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
}

// --- stack configuration -------------------------------------------------

/// Routed `Stack` over the in-process test backend, seeded with one object
/// per benchmarked size under `test://bench/`.
async fn build_seeded_stack() -> Arc<Stack> {
    let stack = Arc::new(
        Stack::builder("test")
            .backend_factory(Arc::new(TestLayerFactory::default()))
            .layer(LayerSpec::backend("test", "test"))
            .build()
            .await
            .expect("build test Stack"),
    );
    stack
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "test".into(),
                connection: ConnectionRequest {
                    backend_kind: "test".into(),
                    config: HashMap::from([(
                        "test_root".into(),
                        ConfigValue::String("test://bench/".into()),
                    )]),
                    credentials: ovstorage::SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add test connection");
    for (size, label) in SIZES {
        LayerExt::write(
            &*stack,
            object_url(label),
            Body::Bytes(payload(size)),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("seed bench object");
    }
    stack
}

fn object_url(label: &str) -> Url {
    Url::parse(&format!("test://bench/{label}.bin")).expect("bench object URL")
}

fn bench_stack(c: &mut Criterion) {
    let rt = bench_runtime();
    let stack = rt.block_on(build_seeded_stack());

    let mut group = c.benchmark_group("stack");
    tune(&mut group);
    for (size, label) in SIZES {
        let url = object_url(label);
        group.throughput(Throughput::BytesDecimal(size));
        group.bench_function(BenchmarkId::new("read_bytes", label), |b| {
            b.to_async(&rt).iter(|| {
                let url = url.clone();
                let stack = &stack;
                async move {
                    black_box(
                        stack
                            .read_bytes(url, ReadOptions::default(), None)
                            .await
                            .expect("stack read_bytes"),
                    )
                }
            });
        });
        group.bench_function(BenchmarkId::new("read_stream", label), |b| {
            b.to_async(&rt).iter(|| {
                let url = url.clone();
                let stack = &stack;
                async move {
                    let (mut stream, info) = stack
                        .read_stream(url, ReadOptions::default(), None)
                        .await
                        .expect("stack read_stream");
                    while let Some(chunk) = stream.next().await {
                        black_box(chunk.expect("stream chunk"));
                    }
                    black_box(info)
                }
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("stack_stat");
    tune(&mut group);
    let url = object_url(SIZES[0].1);
    group.bench_function("stat", |b| {
        b.to_async(&rt).iter(|| {
            let url = url.clone();
            let stack = &stack;
            async move {
                black_box(
                    LayerExt::stat(&**stack, url, StatOptions::default(), None)
                        .await
                        .expect("stack stat"),
                )
            }
        });
    });
    group.finish();
}

// --- ffi configuration ----------------------------------------------------

/// Which `ReadResult` shape [`PayloadLayer`] serves.
#[derive(Clone, Copy)]
enum Shape {
    Bytes,
    Stream,
}

/// Zero-I/O backend serving one pre-chunked payload, so a read costs only
/// the result construction the shape implies — everything else measured on
/// top of it is framework.
struct PayloadLayer {
    bytes: Vec<u8>,
    chunks: Vec<bytes::Bytes>,
    shape: Shape,
}

impl PayloadLayer {
    fn new(size: u64, shape: Shape) -> Self {
        let bytes = payload(size);
        let chunks = bytes
            .chunks(STREAM_CHUNK)
            .map(bytes::Bytes::copy_from_slice)
            .collect();
        Self {
            bytes,
            chunks,
            shape,
        }
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            address,
            kind: ObjectKind::File,
            etag: None,
            etag_strength: Default::default(),
            version: None,
            size: Some(self.bytes.len() as u64),
            mtime: None,
            checksums: ChecksumSet::new(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }
}

#[async_trait]
impl Layer for PayloadLayer {
    fn name(&self) -> &str {
        "bench-payload"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "bench-payload".to_string(),
            layer_type: LayerType::Backend,
            display_name: "bench payload backend".to_string(),
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
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let info = self.info(request.input.address);
        match self.shape {
            Shape::Bytes => Ok(ReadResult::Bytes {
                bytes: self.bytes.clone(),
                info,
            }),
            Shape::Stream => {
                let chunks: Vec<Result<bytes::Bytes>> =
                    self.chunks.iter().cloned().map(Ok).collect();
                Ok(ReadResult::Stream {
                    stream: Box::pin(futures::stream::iter(chunks)),
                    info,
                })
            }
        }
    }
}

/// The two subjects of one shape/size combination: the layer as-is and the
/// same layer re-imported over the forced-foreign ABI codec bridge.
fn subjects(size: u64, shape: Shape) -> [(&'static str, Arc<dyn Layer>); 2] {
    let inproc: Arc<dyn Layer> = Arc::new(PayloadLayer::new(size, shape));
    let foreign = unsafe { import_handle_force_foreign(export_handle(inproc.clone())) }
        .expect("forced-foreign import");
    [("inproc", inproc), ("foreign", foreign)]
}

fn bench_ffi(c: &mut Criterion) {
    let rt = bench_runtime();
    let url = Url::parse("bench://payload/object.bin").expect("payload URL");

    let mut group = c.benchmark_group("ffi");
    tune(&mut group);
    for (size, label) in SIZES {
        group.throughput(Throughput::BytesDecimal(size));
        for (config, layer) in subjects(size, Shape::Bytes) {
            group.bench_function(
                BenchmarkId::new(format!("bytes_result/{config}"), label),
                |b| {
                    b.to_async(&rt).iter(|| {
                        let url = url.clone();
                        let layer = &layer;
                        async move {
                            black_box(
                                layer
                                    .read_bytes(url, ReadOptions::default(), None)
                                    .await
                                    .expect("payload read_bytes"),
                            )
                        }
                    });
                },
            );
        }
        for (config, layer) in subjects(size, Shape::Stream) {
            group.bench_function(
                BenchmarkId::new(format!("stream_result/{config}"), label),
                |b| {
                    b.to_async(&rt).iter(|| {
                        let url = url.clone();
                        let layer = &layer;
                        async move {
                            let (mut stream, info) = layer
                                .read_stream(url, ReadOptions::default(), None)
                                .await
                                .expect("payload read_stream");
                            while let Some(chunk) = stream.next().await {
                                black_box(chunk.expect("stream chunk"));
                            }
                            black_box(info)
                        }
                    });
                },
            );
        }
    }
    group.finish();

    let mut group = c.benchmark_group("ffi_stat");
    tune(&mut group);
    for (config, layer) in subjects(4 * KIB, Shape::Bytes) {
        group.bench_function(BenchmarkId::new("stat", config), |b| {
            b.to_async(&rt).iter(|| {
                let url = url.clone();
                let layer = &layer;
                async move {
                    black_box(
                        LayerExt::stat(&**layer, url, StatOptions::default(), None)
                            .await
                            .expect("payload stat"),
                    )
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_stack, bench_ffi);
criterion_main!(benches);
