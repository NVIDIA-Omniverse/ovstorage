// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod byte;
pub mod coordination;
pub mod errors;
pub mod fs_probe;
mod lease;
pub mod metadata;
mod migrations;
pub mod observer;

pub use errors::map_sql;

pub use byte::{
    ByteCache, ByteCacheEntry, ByteCacheLookup, ByteCacheObject, ByteCachePut, ByteCacheStatus,
    Cache, CacheConfig, CacheEntry, CacheKeyLock, CacheLookup, CacheOptions, CachePut, CacheStatus,
    CachedObject, HerdKey, RecoveryOutcome, StreamingPut,
};
#[cfg(any(test, feature = "test-seams"))]
pub use byte::{CompareAndPutPhase, CompareAndPutSeam, RemoveIndexReturningSeam};
pub use coordination::CacheCoordination;
pub use fs_probe::{FsKind, fs_kind};
pub use lease::{CacheProcess, Lease};
pub use metadata::{
    DisabledDispatcher, Invalidation, MetadataCache, MetadataCacheConfig, MetadataCacheKey,
    MetadataCachePayload, MetadataKind, NotificationDispatcher, hash_list_options,
    hash_list_versions_options, hash_stat_options,
};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use observer::{
    EvictionReason, FillOutcome, LookupOutcome, MetricsObserver, NoopObserver, Observer,
};
