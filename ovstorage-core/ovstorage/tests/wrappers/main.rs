// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stack-level behavior tests for the default-Stack wrappers: the
//! `RetryWrapper` transient backoff and `RedirectFollowerWrapper` read-path
//! redirect following plus write-redirect orchestration; the
//! `ByteCacheWrapper` / `MetadataCacheWrapper` caches (hit/range/conditional
//! reads, write-through, materialize, and invalidation across the mutating ops
//! and the direct `continue_write` API); the `AliasWrapper` (address
//! rewrite and reverse projection, visibility, alias-root synthesis) and
//! `CopyRenameFallbackWrapper` (cross-root copy/rename fallback); and the `Stack`
//! URL-canonicalization boundary. Each test composes the wrapper(s) above a
//! programmable in-process
//! backend Layer and drives it through the public `Stack` API, so the
//! assertions exercise the default host composition.

mod common;

mod alias;
mod byte_cache;
mod copy_rename_fallback;
mod metadata_cache;
mod redirect_follower;
mod retry;
mod watch_architecture;
