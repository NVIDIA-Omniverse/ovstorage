// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stateless conversions between omni1 wire types and the host-facing SPI types.

use std::time::SystemTime;

use nucleus_client::types::{PathAtVersion, PathPermission, PathType};
use ovstorage_plugin::{
    Error, ErrorCode, ObjectInfo, ObjectKind, Result, SystemMetadata, Url, address,
};

use crate::address::NucleusTarget;
use crate::ops::acl_to_effective_permissions;

pub(super) fn poisoned_state(_: std::sync::PoisonError<impl Sized>) -> Error {
    Error::new(
        ErrorCode::Internal,
        "Nucleus shared state mutex is poisoned",
    )
}

pub(super) fn path_at_version(target: &NucleusTarget) -> PathAtVersion {
    PathAtVersion {
        path: target.path.clone(),
        branch: target.branch.clone(),
        checkpoint: target.checkpoint,
    }
}

pub(super) fn stat2_to_object_info(
    address: Url,
    result: nucleus_client::types::Stat2Result,
) -> ObjectInfo {
    // Nucleus has native directory inodes — `Stat2Result.type`
    // carries the entry kind authoritatively. Map `Folder`/`Mount` to
    // `ObjectKind::Directory` (which lets the host dispatcher skip
    // the flat-namespace marker-fold pass) and everything else to
    // `File`. The dispatcher's marker-folding runs on `list`, not
    // `stat`, so this is the only place a direct `stat` learns the
    // kind.
    let is_directory = matches!(result.r#type, Some(PathType::Folder | PathType::Mount));
    let kind = if is_directory {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    // Stash the surfacing fields before the system_metadata move; we
    // promote nucleus's `modified_by` to the typed slot, with
    // `created_by` as the fallback when nucleus has only the latter.
    let promoted_modified_by = result
        .modified_by
        .clone()
        .or_else(|| result.created_by.clone());
    let mut system_metadata = SystemMetadata::new();
    if let Some(created) = result.created {
        system_metadata.insert("created".into(), created);
    }
    if let Some(created_by) = result.created_by {
        system_metadata.insert("created_by".into(), created_by);
    }
    if let Some(modified) = result.modified {
        system_metadata.insert("modified".into(), modified);
    }
    if let Some(modified_by) = result.modified_by {
        system_metadata.insert("modified_by".into(), modified_by);
    }
    if let Some(locked_by) = result.locked_by {
        system_metadata.insert("locked_by".into(), locked_by);
    }
    if let Some(lock_owner) = result.lock_owner {
        system_metadata.insert("lock_owner".into(), lock_owner);
    }
    if let Some(lock_etag) = result.lock_etag {
        system_metadata.insert("lock_etag".into(), lock_etag);
    }
    if let Some(lock_time) = result.lock_time {
        system_metadata.insert("lock_time".into(), lock_time.to_string());
    }
    if let Some(lock_duration) = result.lock_duration {
        system_metadata.insert("lock_duration".into(), lock_duration.to_string());
    }
    let effective_permissions = result.acl.as_ref().map(|acl| {
        let perms: Vec<PathPermission> =
            serde_json::from_value(serde_json::to_value(acl).unwrap_or_default())
                .unwrap_or_default();
        acl_to_effective_permissions(&perms)
    });
    ObjectInfo {
        address,
        kind,
        etag: result.etag,
        version: result.transaction_id,
        size: result.size,
        mtime: result
            .modified_date_seconds
            .map(|secs| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
        checksums: Default::default(),
        effective_permissions,
        system_metadata: if system_metadata.is_empty() {
            None
        } else {
            Some(system_metadata)
        },
        user_metadata: None,
        modified_by: promoted_modified_by,
    }
}

pub(super) fn read_result_to_object_info(
    address: Url,
    result: &nucleus_client::types::ReadAssetVersionResult,
    bytes: &[u8],
) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: result.etag.clone(),
        version: result.transaction_id.map(|t| t.to_string()),
        size: result.size.or(Some(bytes.len() as u64)),
        mtime: None,
        checksums: Default::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub(super) fn create_asset_to_object_info(
    address: Url,
    result: nucleus_client::types::CreateAssetResult,
) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: result.etag,
        version: result.transaction_id.map(|t| t.to_string()),
        size: None,
        mtime: None,
        checksums: Default::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub(super) fn update_asset_to_object_info(
    address: Url,
    result: nucleus_client::types::UpdateAssetResult,
) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: result.etag,
        version: result.transaction_id.map(|t| t.to_string()),
        size: None,
        mtime: None,
        checksums: Default::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub(super) fn list_entry_to_item(
    prefix_address: &Url,
    prefix_path: &str,
    entry: nucleus_client::types::List2ResponsePathEntry,
    recursive: bool,
) -> Result<Option<ObjectInfo>> {
    let Some(entry_path) = entry.path.clone() else {
        return Ok(None);
    };
    let Some(relative_key) = relative_key_for(prefix_path, &entry_path) else {
        return Ok(None);
    };
    // The trailing slash on a directory entry isn't a path separator —
    // strip it before checking for nesting so top-level subdirectories
    // (`Library/`) aren't filtered out as if they were nested children.
    if !recursive && relative_key.trim_end_matches('/').contains('/') {
        return Ok(None);
    }
    let Ok(absolute_address) = address::join_relative(prefix_address, &relative_key) else {
        // The key cannot be spelled as a URI path, so any address built for it
        // would resolve to a different node. Omit the entry and keep the page:
        // invisible beats mis-addressed, and failing the page would hide every
        // sibling too. `None` is the skip channel this function already has.
        tracing::warn!(
            target: "ovstorage.nucleus.backend",
            plugin = "nucleus",
            key = %relative_key,
            "nucleus: path is not addressable as a URI path; omitted from listing",
        );
        return Ok(None);
    };
    let effective_permissions = entry.acl.as_ref().map(|acl| {
        let perms: Vec<PathPermission> =
            serde_json::from_value(serde_json::to_value(acl).unwrap_or_default())
                .unwrap_or_default();
        acl_to_effective_permissions(&perms)
    });
    let is_directory = matches!(entry.path_type, Some(PathType::Folder | PathType::Mount));
    let modified_by = entry
        .modified_by
        .clone()
        .or_else(|| entry.created_by.clone());
    let info = ObjectInfo {
        address: absolute_address,
        // Nucleus has native directory inodes — directory entries are
        // `ObjectKind::Directory`, which skips the host-side marker-fold pass.
        kind: if is_directory {
            ObjectKind::Directory
        } else {
            ObjectKind::File
        },
        etag: entry.etag,
        version: entry.transaction_id.map(|t| t.to_string()),
        size: entry.size,
        mtime: entry
            .modified_timestamp
            .map(|secs| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
        checksums: Default::default(),
        effective_permissions,
        system_metadata: None,
        user_metadata: None,
        modified_by,
    };
    Ok(Some(info))
}

pub(super) fn relative_key_for(prefix_path: &str, entry_path: &str) -> Option<String> {
    let trimmed_prefix = if prefix_path == "/" {
        ""
    } else {
        prefix_path.trim_end_matches('/')
    };
    let stripped = entry_path.strip_prefix(trimmed_prefix)?;
    let rel = stripped.trim_start_matches('/');
    if rel.is_empty() {
        None
    } else {
        Some(rel.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listing omits an unaddressable path instead of failing the page.
    ///
    /// A path containing `//` cannot be spelled as a URI path — the empty
    /// segment collapses, so the address would name a different node.
    /// Propagating that would fail the whole page and hide every sibling with
    /// it. Invisible beats mis-addressed, and it beats unavailable.
    #[test]
    fn a_path_with_no_address_is_omitted_from_a_listing_not_propagated() {
        let prefix_address = address::parse("omniverse://server/root/").unwrap();
        let entry = nucleus_client::types::List2ResponsePathEntry {
            path: Some("/root/a//b.usd".into()),
            ..Default::default()
        };
        assert!(
            list_entry_to_item(&prefix_address, "/root/", entry, true)
                .expect("an unaddressable path must not fail the page")
                .is_none(),
            "an unaddressable path must be omitted from the listing"
        );
    }

    /// The control: an ordinary sibling in the same shape is still returned.
    #[test]
    fn an_ordinary_path_is_still_listed() {
        let prefix_address = address::parse("omniverse://server/root/").unwrap();
        let entry = nucleus_client::types::List2ResponsePathEntry {
            path: Some("/root/a/b.usd".into()),
            ..Default::default()
        };
        let item = list_entry_to_item(&prefix_address, "/root/", entry, true)
            .unwrap()
            .expect("an ordinary path must be listed");
        assert_eq!(item.address.as_str(), "omniverse://server/root/a/b.usd");
    }
}
