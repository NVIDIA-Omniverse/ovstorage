// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPI precondition helpers used at every entry point.
//!
//! The SPI's `if_match` is `Option<String>` (the etag), which is
//! exactly what Azure's wire conditionals (`If-Match`,
//! `x-ms-source-if-match`, `x-ms-copy-source-if-match`) natively
//! carry. The helper in this module is therefore a no-op kept for
//! callsite-signature uniformity with sibling plugins; it is generic
//! over `AsRef<str>` so call sites passing `opts.if_match.as_ref()`
//! compile unchanged.

use ovstorage_plugin::Result;

/// No-op precondition check kept for callsite-signature stability.
///
/// After the SPI migration, callers pass an etag string directly and
/// there is nothing to refuse — the Azure wire conditionals
/// (`If-Match`, `x-ms-source-if-match`, `x-ms-copy-source-if-match`)
/// natively carry exactly an etag. `Some("")` is treated the same as
/// `None` would be (no precondition); callers are responsible for
/// upstream validation.
pub fn require_etag_only_if_match<S>(_if_match: Option<&S>) -> Result<()>
where
    S: AsRef<str>,
{
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_etag_only_accepts_none() {
        require_etag_only_if_match::<String>(None).expect("None is no precondition");
    }

    #[test]
    fn require_etag_only_accepts_etag_string() {
        let etag = "v1".to_string();
        require_etag_only_if_match(Some(&etag)).expect("etag-only is supported");
    }
}
