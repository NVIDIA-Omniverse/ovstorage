// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks for the address-routing primitives on the per-request
//! path: [`RouteTable::lookup`] is a linear longest-prefix scan, so its cost
//! scales with root count and with where the matching root ranks — `first`,
//! `last`, and `miss` ids bracket that range at each table size; the
//! `miss_with_fallback` id prices the second tier — a full scan that misses,
//! then one hash probe for the marked scheme root — which is what an
//! unrouted address on a granted scheme costs. [`RouteTable::build`] prices
//! the sort + collision scan connection (re)registration pays.
//! [`relative_suffix`] is the predicate every scan step calls; its three ids
//! separate the string-prefix fast path, the respell fallback for
//! slash-differing spellings of one node, and the early-out miss.
//!
//! Wall-time on shared runners is noisy; these numbers are for local
//! comparison and CI trend recording, not gating.

use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ovstorage_plugin::routing::RouteTable;
use ovstorage_plugin::{Capabilities, RootInfo, address, fallback};

/// Configure a group for nanosecond-scale pure functions: long criterion
/// defaults would put this file's wall time far past its information value.
fn tune(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
}

/// Roots are built with `address::parse`, not `Url::parse`, for the same
/// reason the crate's own routing tests do: `build`/`lookup` are pure over
/// the `RootInfo`s handed in, and a `Url::parse` fixture would bypass
/// canonicalization.
fn route_root(root: &str) -> RootInfo {
    RootInfo {
        root: address::parse(root).expect("bench root parses"),
        display_name: None,
        layer_kind: "test".to_string(),
        connection_id: None,
        owning_target: None,
        capabilities: ovstorage_plugin::Capabilities::empty(),
        range_read_strategy: ovstorage_plugin::RangeReadStrategy::default(),
        source: ovstorage_plugin::RouteSource::Static {
            layer: ovstorage_plugin::ConfigLayer::Programmatic,
        },
        visible: true,
        visibility: ovstorage_plugin::AddressVisibility::Visible,
        alias_state: None,
        icon: None,
        user_metadata: ovstorage_plugin::UserMetadata::new(),
    }
}

/// `count` equal-depth roots on distinct hosts, so `node_rank` ties and the
/// ranked order is the input order — which makes `first`/`last` lookup ids
/// genuinely best/worst positions in the linear scan.
fn roots(count: usize) -> Vec<(RootInfo, usize)> {
    (0..count)
        .map(|index| (route_root(&format!("s3://bucket-{index:03}/data/")), index))
        .collect()
}

const TABLE_SIZES: [usize; 3] = [1, 8, 64];

fn bench_route_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_table");
    tune(&mut group);

    for count in TABLE_SIZES {
        let template = roots(count);
        group.bench_function(BenchmarkId::new("build", count), |b| {
            b.iter_batched(
                || template.clone(),
                RouteTable::build,
                BatchSize::SmallInput,
            );
        });

        let table = RouteTable::build(roots(count));
        let first = address::parse("s3://bucket-000/data/dir/file.bin").expect("address parses");
        let last = address::parse(&format!("s3://bucket-{:03}/data/dir/file.bin", count - 1))
            .expect("address parses");
        let miss =
            address::parse("s3://unrouted-bucket/data/dir/file.bin").expect("address parses");
        group.bench_function(BenchmarkId::new("lookup_first", count), |b| {
            b.iter(|| std::hint::black_box(table.lookup(&first)));
        });
        group.bench_function(BenchmarkId::new("lookup_last", count), |b| {
            b.iter(|| std::hint::black_box(table.lookup(&last)));
        });
        group.bench_function(BenchmarkId::new("lookup_miss", count), |b| {
            b.iter(|| std::hint::black_box(table.lookup(&miss)));
        });

        // The same miss against a table that also holds the marked `s3:///`
        // root: the scan still runs to the end, then the second tier answers.
        let mut with_fallback = roots(count);
        with_fallback.push((
            fallback::scheme_fallback_root("s3", "test", Capabilities::empty(), None)
                .expect("s3 is a fallback scheme"),
            count,
        ));
        let with_fallback = RouteTable::build(with_fallback);
        group.bench_function(BenchmarkId::new("lookup_miss_with_fallback", count), |b| {
            b.iter(|| std::hint::black_box(with_fallback.lookup(&miss)));
        });
    }
    group.finish();
}

fn bench_relative_suffix(c: &mut Criterion) {
    let mut group = c.benchmark_group("relative_suffix");
    tune(&mut group);

    let prefix = address::parse("s3://bucket/data/").expect("prefix parses");
    // Serialized string prefix of the address: the strip_prefix fast path.
    let fast = address::parse("s3://bucket/data/reports/q3/file.bin").expect("address parses");
    // The other spelling of the prefix's own node: forces the respell
    // fallback that re-derives the head from the address's authority.
    let respell = address::parse("s3://bucket/data").expect("address parses");
    // Host mismatch: the ancestry predicate rejects before any string work.
    let miss = address::parse("s3://other-bucket/data/file.bin").expect("address parses");

    group.bench_function("match_fast", |b| {
        b.iter(|| std::hint::black_box(address::relative_suffix(&fast, &prefix)));
    });
    group.bench_function("match_respell", |b| {
        b.iter(|| std::hint::black_box(address::relative_suffix(&respell, &prefix)));
    });
    group.bench_function("miss", |b| {
        b.iter(|| std::hint::black_box(address::relative_suffix(&miss, &prefix)));
    });
    group.finish();
}

criterion_group!(benches, bench_route_table, bench_relative_suffix);
criterion_main!(benches);
