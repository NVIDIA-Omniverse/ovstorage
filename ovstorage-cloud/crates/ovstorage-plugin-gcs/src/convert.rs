// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPI precondition helpers.
//!
//! GCS's wire conditional is `ifGenerationMatch` (a numeric
//! generation), not an ETag. Under the new SPI, the precondition
//! primitive is `Option<String>`; the plugin interprets that string
//! as a GCS generation number. No field-level narrowing helper is
//! needed any more — the helper exists only as a call site so call
//! paths read uniformly across cloud plugins.

use ovstorage_plugin::Result;

/// No-op: the SPI's `if_match` is already an opaque string. GCS
/// callsites interpret it as a generation number when handing it to
/// the wire.
#[inline]
pub fn require_version_only_if_match<S: AsRef<str> + ?Sized>(_if_match: Option<&S>) -> Result<()> {
    Ok(())
}
