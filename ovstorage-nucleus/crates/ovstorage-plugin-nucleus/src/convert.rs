// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPI precondition helpers.
//!
//! The SPI's `if_match` on read/delete/update_metadata is an opaque
//! etag string (`Option<String>`).
//!
//! Nucleus's enforceable wire conditional on the one mutating op that
//! carries one (`update_asset`) is an etag — IDL: `update_asset(path,
//! etag?, ...)`. Read-side address selection uses the `?branch&checkpoint`
//! URL fragment, which is part of the resolved address, not `if_match`.
//!
//! `delete` / `copy` / `rename` on Nucleus refuse `if_match` entirely
//! because their omni1 IDLs (`delete2`, `copy2`, `rename2`) carry no
//! per-path etag field; those refusals live on the SPI entry points
//! themselves, not in this helper. This helper is retained as a no-op
//! call site so call paths read uniformly with the other plugins (see
//! `ovstorage-plugin-s3/src/convert.rs`).

use ovstorage_plugin::Result;

/// No-op: the SPI's `if_match` is already an opaque etag string. Kept
/// as a call site so call paths read uniformly across plugins.
#[inline]
pub fn require_etag_only_if_match<S: AsRef<str> + ?Sized>(_if_match: Option<&S>) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_none() {
        require_etag_only_if_match::<str>(None).expect("None is no precondition");
    }

    #[test]
    fn accepts_etag_only() {
        require_etag_only_if_match(Some("v1")).expect("etag-only is supported");
    }
}
