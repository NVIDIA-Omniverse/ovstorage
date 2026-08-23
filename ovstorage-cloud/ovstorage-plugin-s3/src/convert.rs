// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPI precondition helpers.
//!
//! The SPI carries `if_match: Option<String>` (etag) directly; no
//! field-level narrowing helper is needed.

use ovstorage_plugin::Result;

/// No-op: the SPI's `if_match` is already an opaque etag string. Kept
/// as a call site so call paths read uniformly across cloud plugins.
#[inline]
pub fn require_etag_only_if_match<S: AsRef<str> + ?Sized>(_if_match: Option<&S>) -> Result<()> {
    Ok(())
}
