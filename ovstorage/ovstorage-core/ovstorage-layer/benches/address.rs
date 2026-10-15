// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks for [`ovstorage_layer::address::canonicalize`], the pure
//! byte-level normalization the `Stack` applies to every address on every
//! operation. Each corpus entry is a separate id because the function's cost
//! is shaped by which rewrites the input triggers: an already-canonical
//! address pays only the decode/re-encode round trip, while dot-segments,
//! percent escapes, and host case each exercise a distinct branch.
//!
//! Wall-time on shared runners is noisy; these numbers are for local
//! comparison and CI trend recording, not gating.

use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ovstorage_layer::Url;
use ovstorage_layer::address::canonicalize;

/// Configure a group for nanosecond-scale pure functions: long criterion
/// defaults would put this file's wall time far past its information value.
fn tune(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
}

/// A hierarchical path deep enough that segment iteration, not fixed setup,
/// dominates.
fn long_path_url() -> Url {
    let mut spelling = String::from("s3://bucket");
    for depth in 0..32 {
        spelling.push_str(&format!("/segment-{depth:02}"));
    }
    spelling.push_str("/file.bin");
    Url::parse(&spelling).expect("long bench URL parses")
}

fn bench_canonicalize(c: &mut Criterion) {
    let corpus: Vec<(&str, Url)> = vec![
        // Fast path: nothing to rewrite, so this prices the unconditional
        // decode → normalize → re-encode round trip alone.
        (
            "canonical_simple",
            Url::parse("s3://bucket/data/file.bin").expect("bench URL parses"),
        ),
        // Dot-segment resolution plus `//` collapse — the path state machine's
        // busiest branch.
        (
            "dot_segments",
            Url::parse("s3://bucket/a/b/../c/./d//e/../../f/file.bin").expect("bench URL parses"),
        ),
        // Percent-decoding of multi-byte UTF-8 and re-encoding against the
        // canonical set.
        (
            "percent_encoded",
            Url::parse("s3://bucket/reports%202026/%E6%97%A5%E6%9C%AC%E8%AA%9E/file%7Ename.bin")
                .expect("bench URL parses"),
        ),
        // Non-special scheme, so the host lowering is canonicalize's own work
        // (the `url` crate only pre-lowers hosts of special schemes), plus the
        // fragment strip.
        (
            "upper_host_fragment",
            Url::parse("s3://BUCKET-Name/container/file.bin#section-3").expect("bench URL parses"),
        ),
        ("long_path", long_path_url()),
    ];

    let mut group = c.benchmark_group("canonicalize");
    tune(&mut group);
    for (label, url) in &corpus {
        group.bench_function(BenchmarkId::from_parameter(label), |b| {
            // `canonicalize` consumes its input, so the clone lives in setup
            // where criterion excludes it from the measurement.
            b.iter_batched(|| url.clone(), canonicalize, BatchSize::SmallInput);
        });
    }
    group.finish();
}

criterion_group!(benches, bench_canonicalize);
criterion_main!(benches);
