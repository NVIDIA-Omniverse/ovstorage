// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! URL inspection helpers shared across plugins.

use crate::{Error, ErrorCode, Result};
use url::Url;

/// Reject mutating ops on a pinned-version address whose wire protocol
/// can't honor the modifier. Plugins call this at the top of any mutating
/// op (write, delete, copy(dst), rename, update_metadata, delete_directory)
/// where the backend's wire format would silently drop the modifier or
/// can't address a specific historical version.
///
/// `modifier_keys` lists the query-parameter keys that pin a version on
/// the plugin's URL convention (e.g. `&["versionId"]` for S3, `&["generation"]`
/// for GCS, `&["versionid"]` for Azure, `&["checkpoint"]` for
/// Nucleus). If the URL carries any of those keys
/// with a non-empty value, return `InvalidArgument`.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the URL carries a version-pinning
///   modifier that the mutating operation cannot honor.
pub fn reject_pinned_for_mutation(url: &Url, op_name: &str, modifier_keys: &[&str]) -> Result<()> {
    for (key, value) in url.query_pairs() {
        if modifier_keys.iter().any(|k| k.eq_ignore_ascii_case(&key)) && !value.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{op_name}: cannot operate on a pinned version address \
                     (drop the ?{key}=… modifier to operate on the current version)"
                ),
            ));
        }
    }
    Ok(())
}

/// First non-empty value of any `modifier_keys` query parameter on `url`.
/// Plugins use this to recover a caller-supplied version selector before
/// trusting a server-echoed identity (e.g. `get_latest_version` returns the
/// caller's pin verbatim when present).
pub fn extract_pinned_value(url: &Url, modifier_keys: &[&str]) -> Option<String> {
    for (key, value) in url.query_pairs() {
        if modifier_keys.iter().any(|k| k.eq_ignore_ascii_case(&key)) && !value.is_empty() {
            return Some(value.into_owned());
        }
    }
    None
}
