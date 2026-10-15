// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-RPC span field helpers; centralised in ovstorage-plugin.
//!
//! Re-exports: `RedactedUrl` (strips query/fragment/userinfo from URLs for safe logging).
//! Span attrs: `principal.id`, `audit_id`, `cache.hit`,
//! `redirect.kind`, plus the redacted `object.address`. `route.id` and
//! `backend.id` are deferred until the broker stamps routes.

pub use ovstorage_plugin::RedactedUrl;
