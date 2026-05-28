// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-layer attribution of `modified_by`.
//!
//! ## Why
//! The brokered case forces a separation between *the principal that
//! authenticated to the broker* (e.g. `alice@example.com` via OIDC) and
//! *the principal the backend sees* (the broker's service account).
//! Backends that record per-write identity natively will record the
//! broker, not Alice. Backends that don't record it at all (S3, GCS,
//! Azure) leave `modified_by` empty in direct-library mode.
//!
//! This layer is the trust boundary's overlay: the broker, having just
//! authenticated Alice, stamps her identity into a reserved key in
//! `user_metadata` (`ovstorage-modified-by`) on every mutating call.
//! On reads it harvests the same key back into the typed
//! [`ObjectInfo::modified_by`](ovstorage_plugin::ObjectInfo::modified_by)
//! field and hides it from the surfaced `user_metadata` map.
//!
//! ## Strategies
//! - [`AttributionStrategy::UserMetadata`] (default): stamp + harvest
//!   the reserved key.
//! - [`AttributionStrategy::Passthrough`]: no-op. Use for intermediate
//!   brokers in a chain so the upstream broker's stamp survives
//!   end-to-end (`UserMetadata → Passthrough → backend` preserves
//!   the original principal).
//! - [`AttributionStrategy::ExternalDb`]: reserved for v2; broker
//!   refuses to start with `NotConfigured`.
//!
//! ## Cost gating
//! Populating `modified_by` from a plugin's native source can require
//! extra OS calls (POSIX `getpwuid_r`, Windows DACL probe) or extra
//! round-trips (S3 `GetObjectAcl`). Plugins gate this behind
//! `StatOptions::full_metadata` / `ListOptions::full_metadata`, so a
//! cheap default stat pays nothing.
//!
//! ## Threat model
//! In `UserMetadata` mode the broker overwrites whatever the client
//! supplied for `ovstorage-modified-by`, so a client cannot succeed at
//! spoofing through the broker. The broker also strips other
//! `ovstorage-*` keys from the inbound `user_metadata` (defensive — the
//! namespace is reserved). A *direct-library* writer that bypasses the
//! broker entirely can write any value to the reserved key; the broker
//! has no signature to verify. Treat the broker as the only mutating
//! path or use HMAC-signed values (deferred for v1).
//!
//! ## Chained brokers
//! `client → local broker (UserMetadata) → remote broker (Passthrough)
//! → backend` preserves Alice's identity end-to-end. Two `UserMetadata`
//! brokers in a chain re-stamp at the deeper broker and lose the
//! original principal — documented behavior; trusted-upstream-broker
//! delegation is a future enhancement.

use ovstorage_plugin::{Error, ErrorCode, ObjectInfo, Result, UpdateMetadataOptions, WriteOptions};

use crate::Principal;

pub const ATTRIBUTION_KEY_MODIFIED_BY: &str = "ovstorage-modified-by";
pub const RESERVED_METADATA_PREFIX: &str = "ovstorage-";

/// Storage channel for broker-attested attribution. Configurable so
/// chained-broker setups (`UserMetadata → Passthrough`) can preserve
/// the original principal end-to-end.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum AttributionStrategy {
    /// Default. Stamp `ovstorage-modified-by` into `user_metadata`
    /// and read it back on stat/list.
    #[default]
    UserMetadata,
    /// Don't touch `user_metadata`. The plugin's native modified_by
    /// (or any reserved keys forwarded from an upstream broker) flow
    /// through unchanged.
    Passthrough,
    /// Reserved for the v2 external-DB strategy. v1 refuses to start.
    ExternalDb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionLayer {
    strategy: AttributionStrategy,
}

impl AttributionLayer {
    pub fn new(strategy: AttributionStrategy) -> Result<Self> {
        if strategy == AttributionStrategy::ExternalDb {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "external_db attribution strategy is not yet implemented",
            ));
        }
        Ok(Self { strategy })
    }

    pub fn strategy(&self) -> AttributionStrategy {
        self.strategy
    }

    pub fn stamp_write(&self, principal: &Principal, opts: &mut WriteOptions) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        let map = opts.user_metadata.get_or_insert_with(Default::default);
        strip_reserved(map);
        map.insert(
            ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
            principal.id.clone(),
        );
    }

    pub fn stamp_update_metadata(&self, principal: &Principal, opts: &mut UpdateMetadataOptions) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        strip_reserved(&mut opts.user_metadata_set);
        opts.user_metadata_remove.retain(|k| !is_reserved_key(k));
        opts.user_metadata_set.insert(
            ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
            principal.id.clone(),
        );
    }

    /// Promote the broker-attested key into the typed `modified_by`
    /// slot on read, and hide the reserved namespace from clients.
    pub fn unwrap_read(&self, info: &mut ObjectInfo) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        let Some(map) = info.user_metadata.as_mut() else {
            return;
        };
        if let Some(value) = map.remove(ATTRIBUTION_KEY_MODIFIED_BY) {
            info.modified_by = Some(value);
        }
        // Hide any other reserved-namespace keys so they don't leak
        // to clients; only the typed slot exposes broker state.
        map.retain(|k, _| !is_reserved_key(k));
        if map.is_empty() {
            info.user_metadata = None;
        }
    }
}

fn is_reserved_key(key: &str) -> bool {
    key.to_ascii_lowercase()
        .starts_with(RESERVED_METADATA_PREFIX)
}

fn strip_reserved(map: &mut std::collections::HashMap<String, String>) {
    map.retain(|key, value| {
        if is_reserved_key(key) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Principal;
    use std::collections::HashMap;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "test".to_string(),
        }
    }

    fn info_with_metadata(pairs: &[(&str, &str)]) -> ObjectInfo {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_string(), (*v).to_string());
        }
        ObjectInfo {
            address: ovstorage_plugin::address::parse("file:///tmp/x").unwrap(),
            kind: ovstorage_plugin::ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: Default::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: if map.is_empty() { None } else { Some(map) },
            modified_by: None,
        }
    }

    #[test]
    fn external_db_strategy_refuses_construction() {
        let err = AttributionLayer::new(AttributionStrategy::ExternalDb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn user_metadata_stamp_round_trips_through_unwrap() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = WriteOptions::default();
        layer.stamp_write(&principal("alice"), &mut opts);

        let mut info = info_with_metadata(&[("ovstorage-modified-by", "alice")]);
        layer.unwrap_read(&mut info);
        assert_eq!(info.modified_by.as_deref(), Some("alice"));
        assert!(info.user_metadata.is_none());
    }

    #[test]
    fn stamp_strips_client_supplied_reserved_keys() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = WriteOptions::default();
        let mut user_meta = HashMap::new();
        user_meta.insert("ovstorage-modified-by".to_string(), "bob".to_string());
        user_meta.insert("ovstorage-some-future-key".to_string(), "x".to_string());
        user_meta.insert("regular-key".to_string(), "kept".to_string());
        opts.user_metadata = Some(user_meta);

        layer.stamp_write(&principal("alice"), &mut opts);

        let metadata = opts.user_metadata.expect("metadata present after stamp");
        // Client-supplied reserved keys gone; only broker stamp + regular key remain.
        assert_eq!(
            metadata.get("regular-key").map(String::as_str),
            Some("kept")
        );
        assert_eq!(
            metadata.get("ovstorage-modified-by").map(String::as_str),
            Some("alice"),
        );
        assert!(!metadata.contains_key("ovstorage-some-future-key"));
    }

    #[test]
    fn stamp_update_metadata_strips_reserved_in_set_and_remove() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = UpdateMetadataOptions {
            user_metadata_set: {
                let mut map = HashMap::new();
                map.insert("ovstorage-modified-by".to_string(), "spoofed".to_string());
                map.insert("normal-key".to_string(), "v".to_string());
                map
            },
            user_metadata_remove: vec![
                "ovstorage-modified-by".to_string(),
                "user-asked-to-remove".to_string(),
            ],
            ..Default::default()
        };

        layer.stamp_update_metadata(&principal("alice"), &mut opts);

        assert_eq!(
            opts.user_metadata_set
                .get("ovstorage-modified-by")
                .map(String::as_str),
            Some("alice"),
        );
        assert_eq!(
            opts.user_metadata_set.get("normal-key").map(String::as_str),
            Some("v")
        );
        // Removal of the reserved key is dropped silently; non-reserved removal preserved.
        assert_eq!(
            opts.user_metadata_remove,
            vec!["user-asked-to-remove".to_string()]
        );
    }

    #[test]
    fn passthrough_is_a_true_no_op() {
        let layer = AttributionLayer::new(AttributionStrategy::Passthrough).unwrap();
        let mut opts = WriteOptions::default();
        let mut user_meta = HashMap::new();
        // Simulate an upstream broker's stamp arriving at this passthrough broker.
        user_meta.insert("ovstorage-modified-by".to_string(), "alice".to_string());
        opts.user_metadata = Some(user_meta);

        layer.stamp_write(&principal("local-broker-svc"), &mut opts);

        // Upstream stamp preserved verbatim; local broker did not re-stamp.
        let metadata = opts.user_metadata.unwrap();
        assert_eq!(
            metadata.get("ovstorage-modified-by").map(String::as_str),
            Some("alice"),
        );
    }

    #[test]
    fn passthrough_unwrap_does_not_promote() {
        let layer = AttributionLayer::new(AttributionStrategy::Passthrough).unwrap();
        let mut info = info_with_metadata(&[("ovstorage-modified-by", "alice")]);
        layer.unwrap_read(&mut info);
        // Passthrough leaves the typed slot alone; client sees raw plugin output.
        assert!(info.modified_by.is_none());
        assert!(info.user_metadata.is_some());
    }

    #[test]
    fn unwrap_read_strips_other_reserved_keys() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut info = info_with_metadata(&[
            ("ovstorage-modified-by", "alice"),
            ("ovstorage-future-key", "should-be-hidden"),
            ("user-key", "visible"),
        ]);
        layer.unwrap_read(&mut info);

        assert_eq!(info.modified_by.as_deref(), Some("alice"));
        let metadata = info.user_metadata.expect("non-reserved key remains");
        assert_eq!(
            metadata.get("user-key").map(String::as_str),
            Some("visible")
        );
        assert!(!metadata.contains_key("ovstorage-future-key"));
    }

    #[test]
    fn unwrap_read_with_no_reserved_key_preserves_native_modified_by() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut info = info_with_metadata(&[("user-key", "v")]);
        info.modified_by = Some("plugin-native".to_string());
        layer.unwrap_read(&mut info);
        // No broker stamp present; plugin's native value left alone.
        assert_eq!(info.modified_by.as_deref(), Some("plugin-native"));
    }
}
