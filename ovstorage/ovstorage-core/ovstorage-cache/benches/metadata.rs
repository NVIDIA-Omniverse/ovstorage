// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks for [`MetadataCache`] on the per-request path: every hit
//! and miss serializes on the cache's single mutex and a hit also bumps LRU
//! state, so `get_hit`/`get_miss` price what a cached stat costs a read.
//! `insert_replace` is the steady-state refresh (remove + insert, no
//! eviction); `insert_evict` inserts a fresh key into a cache at budget, so
//! it carries the LRU victim sort — the worst case a fill pays.
//!
//! Wall-time on shared runners is noisy; these numbers are for local
//! comparison and CI trend recording, not gating.

use std::cell::Cell;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ovstorage_cache::{
    CostFlags, MetadataCache, MetadataCacheConfig, MetadataCacheKey, MetadataCachePayload,
    MetadataKind,
};
use ovstorage_layer::{ChecksumSet, ObjectInfo, ObjectKind, Url};

/// Configure a group for nanosecond-scale operations: long criterion
/// defaults would put this file's wall time far past its information value.
fn tune(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
}

/// Entries the cache is populated to. Also the budget for `insert_evict`, so
/// that case is at capacity and every insert pays one eviction pass.
const POPULATION: usize = 1024;

fn stub_info() -> ObjectInfo {
    ObjectInfo {
        address: Url::parse("file:///tmp/x").expect("stub address parses"),
        kind: ObjectKind::File,
        etag: None,
        etag_strength: Default::default(),
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
        versioned_address: None,
    }
}

fn key(index: u64) -> MetadataCacheKey {
    MetadataCacheKey {
        kind: MetadataKind::Stat,
        principal_id: None,
        address: format!("s3://bucket/objects/obj-{index:06}"),
        credential_scope: None,
    }
}

/// A cache filled to exactly `POPULATION` Stat entries (each charges 1
/// against the budget). TTL is long enough that nothing expires mid-run.
fn populated(max_entries: usize) -> MetadataCache {
    let cache = MetadataCache::new(&MetadataCacheConfig {
        max_entries: Some(max_entries),
        ttl_seconds: Some(3600),
    });
    for index in 0..POPULATION as u64 {
        cache.insert(
            key(index),
            MetadataCachePayload::Stat(stub_info()),
            CostFlags::default(),
        );
    }
    cache
}

fn bench_metadata_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_cache");
    tune(&mut group);

    // Budget above the population so gets never race an eviction.
    let cache = populated(POPULATION * 2);
    let hit = key(POPULATION as u64 / 2);
    let miss = key(POPULATION as u64 * 2);
    group.bench_function("get_hit", |b| {
        b.iter(|| std::hint::black_box(cache.get(&hit, CostFlags::default())));
    });
    group.bench_function("get_miss", |b| {
        b.iter(|| std::hint::black_box(cache.get(&miss, CostFlags::default())));
    });
    // Key/payload construction (Url::parse, clones) must stay in the untimed
    // setup closure: inline it and it dominates the ~100 ns insert itself.
    group.bench_function("insert_replace", |b| {
        b.iter_batched(
            || (hit.clone(), MetadataCachePayload::Stat(stub_info())),
            |(key, payload)| std::hint::black_box(cache.insert(key, payload, CostFlags::default())),
            BatchSize::SmallInput,
        );
    });

    // At budget: every fresh key evicts the LRU victim, sort pass included.
    let full = populated(POPULATION);
    let fresh = Cell::new(POPULATION as u64);
    group.bench_function("insert_evict", |b| {
        b.iter_batched(
            || {
                let index = fresh.get();
                fresh.set(index + 1);
                (key(index), MetadataCachePayload::Stat(stub_info()))
            },
            |(key, payload)| std::hint::black_box(full.insert(key, payload, CostFlags::default())),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_metadata_cache);
criterion_main!(benches);
