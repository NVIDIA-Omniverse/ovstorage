// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The reserved-metadata spelling shared by the host's attribution overlay and
//! the plugins that commit a redirect write.
//!
//! A host that attributes writes puts the authenticated principal into
//! `WriteOptions.user_metadata` under [`ATTRIBUTION_KEY_MODIFIED_BY`] and
//! harvests it back into `ObjectInfo::modified_by`. That overlay is host-side
//! and a plugin crate may not depend on it, so the key, the reserved namespace
//! it lives in, and the one operation a plugin needs — re-asserting the host's
//! value over a copy that made a round trip through a client — are defined
//! here, in the crate both sides already share.
//!
//! ## Why a plugin ever has to re-assert it
//! On the redirect protocol the plugin hands the caller signed upload requests
//! plus an opaque continuation, and the caller echoes the whole batch back to
//! `continue_write`. A backend whose metadata is bound when the redirect is
//! minted — signed into a presigned URL, or committed server-side as the
//! session is created — needs nothing from this module: the caller cannot
//! reach the bound copy. A backend whose metadata is applied by the *commit*
//! call does, because the copy it applies came back through the caller.
//!
//! Such a plugin reads [`attested_modified_by`] from the request extensions
//! and passes it to [`reassert_attribution`] before applying the
//! continuation's metadata. Absence means no host attribution layer spoke for
//! this request, and the continuation's metadata is then applied as-is.

use std::collections::HashMap;

use crate::UserMetadata;
use crate::traits::Extensions;

/// Reserved `user_metadata` key carrying the host-attested writer identity.
pub const ATTRIBUTION_KEY_MODIFIED_BY: &str = "ovstorage-modified-by";

/// Namespace reserved for host-attested `user_metadata` keys. A host that
/// attributes writes strips this namespace out of client-supplied metadata, so
/// a key inside it is either the host's or absent.
pub const RESERVED_METADATA_PREFIX: &str = "ovstorage-";

/// Whether `key` is in the reserved namespace. Case-insensitive: backends
/// differ on metadata-key case and a namespace that could be escaped by
/// capitalizing it would not be reserved.
pub fn is_reserved_metadata_key(key: &str) -> bool {
    key.to_ascii_lowercase()
        .starts_with(RESERVED_METADATA_PREFIX)
}

/// Drop every reserved-namespace key from `map`.
pub fn strip_reserved_metadata(map: &mut HashMap<String, String>) {
    map.retain(|key, value| {
        if is_reserved_metadata_key(key) {
            if !value.is_empty() {
                tracing::debug!(
                    target: "ovstorage::attribution",
                    key = %key,
                    "stripped reserved-namespace key from client metadata",
                );
            }
            false
        } else {
            true
        }
    });
}

/// The writer identity a host attribution layer asserted for this request, from
/// [`crate::ext::ATTRIBUTED_MODIFIED_BY`].
///
/// `None` means no attribution layer spoke for the request — the branch carries
/// none, the host's strategy is a pass-through, or there is no attributing host
/// at all. It does not mean "anonymous": an attributing host stamps its
/// anonymous principal id explicitly.
///
/// Bytes that are not UTF-8 decode lossily rather than reading as absent, and
/// for the same reason the host's own principal decoding does
/// (`String::from_utf8_lossy`): a present-but-undecodable assertion still says
/// the host meant to speak for this request, and treating it as absent would
/// hand the decision back to a value that travelled through the caller.
pub fn attested_modified_by(extensions: &Extensions) -> Option<String> {
    extensions
        .get(crate::ext::ATTRIBUTED_MODIFIED_BY)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

/// Replace the reserved namespace in `metadata` with the host-attested writer
/// identity, when there is one.
///
/// `attested` is [`attested_modified_by`]'s result. When it is `Some`, this
/// mirrors what the host's overlay does to client metadata at mint: every
/// reserved-namespace key goes, and the attested key is inserted. When it is
/// `None`, `metadata` is left exactly as it was.
pub fn reassert_attribution(attested: Option<&str>, metadata: &mut Option<UserMetadata>) {
    let Some(principal) = attested else {
        return;
    };
    let map = metadata.get_or_insert_with(UserMetadata::default);
    strip_reserved_metadata(map);
    map.insert(
        ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
        principal.to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> UserMetadata {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn reassert_overwrites_a_forged_value() {
        let mut metadata = Some(map(&[
            ("ovstorage-modified-by", "victim"),
            ("author", "alice"),
        ]));
        assert_eq!(metadata.as_ref().map(HashMap::len), Some(2));
        reassert_attribution(Some("alice@example.com"), &mut metadata);
        let out = metadata.expect("metadata survives");
        assert_eq!(
            out.get(ATTRIBUTION_KEY_MODIFIED_BY).map(String::as_str),
            Some("alice@example.com")
        );
        assert_eq!(out.get("author").map(String::as_str), Some("alice"));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn reassert_drops_every_reserved_key_not_only_the_attribution_one() {
        let mut metadata = Some(map(&[
            ("OVSTORAGE-Modified-By", "victim"),
            ("ovstorage-planted", "value"),
        ]));
        reassert_attribution(Some("alice"), &mut metadata);
        let out = metadata.expect("metadata survives");
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.get(ATTRIBUTION_KEY_MODIFIED_BY).map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn reassert_populates_an_absent_map() {
        let mut metadata: Option<UserMetadata> = None;
        reassert_attribution(Some("alice"), &mut metadata);
        let out = metadata.expect("an attested value creates the map");
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.get(ATTRIBUTION_KEY_MODIFIED_BY).map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn no_attested_value_leaves_the_metadata_untouched() {
        let forged = map(&[("ovstorage-modified-by", "victim"), ("author", "alice")]);
        let mut metadata = Some(forged.clone());
        reassert_attribution(None, &mut metadata);
        assert_eq!(metadata, Some(forged));
    }

    #[test]
    fn attested_modified_by_reads_the_extension() {
        let mut extensions = Extensions::new();
        assert_eq!(attested_modified_by(&extensions), None);
        extensions.insert(crate::ext::ATTRIBUTED_MODIFIED_BY, b"alice".to_vec());
        assert_eq!(attested_modified_by(&extensions).as_deref(), Some("alice"));
    }

    /// A present assertion the host could not encode must still overwrite what
    /// travelled through the caller, not read as "no host spoke".
    #[test]
    fn a_non_utf8_assertion_is_present_not_absent() {
        let mut extensions = Extensions::new();
        extensions.insert(crate::ext::ATTRIBUTED_MODIFIED_BY, vec![0xff, 0xfe]);
        let attested = attested_modified_by(&extensions);
        assert!(attested.is_some(), "undecodable is not absent");
        let mut metadata = Some(map(&[("ovstorage-modified-by", "victim")]));
        reassert_attribution(attested.as_deref(), &mut metadata);
        assert_ne!(
            metadata
                .and_then(|m| m.get(ATTRIBUTION_KEY_MODIFIED_BY).cloned())
                .as_deref(),
            Some("victim")
        );
    }
}
