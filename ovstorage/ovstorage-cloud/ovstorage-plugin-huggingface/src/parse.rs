// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hub JSON entries → [`ObjectInfo`]. Shared by `stat` (paths-info) and
//! `list` (tree), so the two surfaces cannot drift on identity fields.

use std::time::SystemTime;

use ovstorage_plugin::{
    ChecksumAlgorithm, ChecksumSet, Error, ErrorCode, EtagStrength, ObjectInfo, ObjectKind, Result,
    SystemMetadata, Url, address,
};

use crate::api::TreeEntry;

/// Convert one tree / paths-info entry into an `ObjectInfo` at `address`
/// (already pin-carrying when the operation was pinned).
///
/// Identity choices, deliberately aligned with what the `read` path serves:
/// the etag is the LFS content sha256 when the entry is LFS-backed (the
/// `resolve` 302 reports the same value in `x-linked-etag`), else the git blob
/// oid (the non-LFS `resolve` 200 reports it as `ETag`). `version` is filled
/// only from `lastCommit` (present under `expand=true`) — never fabricated.
///
/// `versioned_address` echoes the caller's own `?revision=` pin when it is an
/// immutable commit sha (the address already names one version, whatever
/// else the request asked for); otherwise it pins a file entry to
/// `?revision=<lastCommit.id>`, the commit that last touched the entry, so
/// the pin names exactly these bytes. A ref such as `main` or `refs/pr/1`
/// selects whatever it points at at the moment, so it is not a pin and is not
/// echoed. Directories carry `None`.
pub(crate) fn entry_info(address: &Url, entry: &TreeEntry) -> Result<ObjectInfo> {
    let kind = match entry.entry_type.as_str() {
        "file" => ObjectKind::File,
        "directory" => ObjectKind::Directory,
        // Unknown discriminator: refuse rather than guess. The raw value is
        // server text and is not echoed.
        _ => {
            return Err(Error::new(
                ErrorCode::Internal,
                "huggingface entry has an unrecognized type",
            ));
        }
    };
    let is_file = kind == ObjectKind::File;
    let etag = entry
        .lfs
        .as_ref()
        .map(|lfs| lfs.oid.clone())
        .or_else(|| entry.oid.clone());
    // Hub LFS oids and Git object ids are content addresses, not validators
    // inferred from an arbitrary token shape.
    let etag_strength = etag
        .as_ref()
        .map_or(EtagStrength::Unspecified, |_| EtagStrength::Strong);
    let mut checksums = ChecksumSet::new();
    if is_file
        && let Some(lfs) = entry.lfs.as_ref()
        && let Some(sha256) = decode_hex_sha256(&lfs.oid)
    {
        checksums.insert(ChecksumAlgorithm::sha256(), sha256);
    }
    let mut system_metadata = SystemMetadata::new();
    if let Some(oid) = entry.oid.as_deref() {
        system_metadata.insert("hf.oid".into(), oid.to_string());
    }
    if let Some(pointer_size) = entry.lfs.as_ref().and_then(|lfs| lfs.pointer_size) {
        system_metadata.insert("hf.lfs.pointer-size".into(), pointer_size.to_string());
    }
    if let Some(last_commit) = entry.last_commit.as_ref() {
        system_metadata.insert("hf.last-commit.id".into(), last_commit.id.clone());
        if let Some(title) = last_commit.title.as_deref() {
            system_metadata.insert("hf.last-commit.title".into(), title.to_string());
        }
    }
    let versioned_address = if is_file {
        match caller_sha_pin(address)? {
            Some(pin) => Some(pin),
            None => entry
                .last_commit
                .as_ref()
                .map(|last_commit| pinned_to(address, &last_commit.id))
                .transpose()?,
        }
    } else {
        None
    };
    Ok(ObjectInfo {
        etag_strength,
        address: address.clone(),
        kind,
        etag,
        version: entry
            .last_commit
            .as_ref()
            .map(|last_commit| last_commit.id.clone()),
        size: if is_file { entry.size } else { None },
        mtime: entry
            .last_commit
            .as_ref()
            .and_then(|last_commit| last_commit.date.as_deref())
            .and_then(parse_rfc3339),
        checksums,
        effective_permissions: None,
        system_metadata: if system_metadata.is_empty() {
            None
        } else {
            Some(system_metadata)
        },
        user_metadata: None,
        modified_by: None,
        versioned_address,
    })
}

/// `address` pinned to one commit. The query is rebuilt so the pin replaces
/// whatever selector the caller spelled.
fn pinned_to(address: &Url, sha: &str) -> Result<Url> {
    let mut base = address.clone();
    base.set_query(None);
    base.set_fragment(None);
    address::with_query_pair(&base, "revision", sha)
}

/// The caller's own `?revision=` pin, re-spelled, when it is an immutable
/// commit sha; `None` for an unpinned address or a mutable ref.
fn caller_sha_pin(address: &Url) -> Result<Option<Url>> {
    let pin = address
        .query_pairs()
        .find(|(key, _)| key == "revision")
        .map(|(_, value)| value.into_owned());
    match pin {
        Some(sha) if is_commit_sha(&sha) => Ok(Some(pinned_to(address, &sha)?)),
        _ => Ok(None),
    }
}

/// A full git object id: 40 lowercase hex digits. Anything else (a branch, a
/// tag, an abbreviated sha) can move or resolve differently later.
fn is_commit_sha(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The repository root as a directory `ObjectInfo`, from repo-info facts.
pub(crate) fn repo_root_info(address: &Url, sha: Option<String>) -> ObjectInfo {
    ObjectInfo {
        etag_strength: EtagStrength::Unspecified,
        address: address.clone(),
        kind: ObjectKind::Directory,
        etag: None,
        version: sha,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
        versioned_address: None,
    }
}

pub(crate) fn parse_rfc3339(raw: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

/// Decode a 64-hex-char sha256; anything else answers `None` rather than a
/// half-decoded digest.
pub(crate) fn decode_hex_sha256(raw: &str) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(32);
    let mut chars = raw.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        bytes.push(((high.to_digit(16)? as u8) << 4) | (low.to_digit(16)? as u8));
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{LastCommit, LfsInfo};

    fn address() -> Url {
        ovstorage_plugin::address::parse("hf://models/acme/demo/weights/model.bin").unwrap()
    }

    fn lfs_entry() -> TreeEntry {
        TreeEntry {
            entry_type: "file".into(),
            path: "weights/model.bin".into(),
            oid: Some("45fa7c3d85ee7dd4139adbc056da25ae136a65f2".into()),
            size: Some(69_512_435),
            lfs: Some(LfsInfo {
                oid: "b43f4c2ea569da1d66ca74e26ca8ea4430dfc29195e97144b2d0b4f3f6cafa1c".into(),
                pointer_size: Some(133),
            }),
            last_commit: None,
        }
    }

    #[test]
    fn lfs_files_use_the_content_sha_as_etag_and_checksum() {
        let info = entry_info(&address(), &lfs_entry()).unwrap();
        assert_eq!(info.kind, ObjectKind::File);
        assert_eq!(info.size, Some(69_512_435));
        assert_eq!(
            info.etag.as_deref(),
            Some("b43f4c2ea569da1d66ca74e26ca8ea4430dfc29195e97144b2d0b4f3f6cafa1c")
        );
        assert_eq!(info.etag_strength, EtagStrength::Strong);
        let digest = info.checksums.get(&ChecksumAlgorithm::sha256()).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest[0], 0xb4);
        assert_eq!(digest[31], 0x1c);
        let metadata = info.system_metadata.unwrap();
        assert_eq!(
            metadata.get("hf.oid").map(String::as_str),
            Some("45fa7c3d85ee7dd4139adbc056da25ae136a65f2")
        );
        assert_eq!(
            metadata.get("hf.lfs.pointer-size").map(String::as_str),
            Some("133")
        );
    }

    #[test]
    fn plain_files_use_the_blob_oid_and_carry_no_checksum() {
        let entry = TreeEntry {
            lfs: None,
            ..lfs_entry()
        };
        let info = entry_info(&address(), &entry).unwrap();
        assert_eq!(
            info.etag.as_deref(),
            Some("45fa7c3d85ee7dd4139adbc056da25ae136a65f2")
        );
        assert_eq!(info.etag_strength, EtagStrength::Strong);
        assert!(info.checksums.is_empty());
    }

    #[test]
    fn directory_with_git_tree_oid_is_strong_and_carries_no_size() {
        let entry = TreeEntry {
            entry_type: "directory".into(),
            path: "weights".into(),
            oid: Some("d1".into()),
            size: Some(4096),
            lfs: None,
            last_commit: None,
        };
        let info = entry_info(&address(), &entry).unwrap();
        assert_eq!(info.kind, ObjectKind::Directory);
        assert_eq!(info.etag.as_deref(), Some("d1"));
        assert_eq!(info.etag_strength, EtagStrength::Strong);
        assert_eq!(info.size, None);
        assert!(info.checksums.is_empty());
    }

    #[test]
    fn repository_root_without_an_etag_is_unspecified() {
        let info = repo_root_info(&address(), Some("deadbeef".into()));
        assert_eq!(info.etag, None);
        assert_eq!(info.etag_strength, EtagStrength::Unspecified);
    }

    #[test]
    fn expanded_entries_populate_version_and_mtime() {
        let entry = TreeEntry {
            last_commit: Some(LastCommit {
                id: "deadbeef".into(),
                title: Some("add weights".into()),
                date: Some("2022-04-14T21:04:33.000Z".into()),
            }),
            ..lfs_entry()
        };
        let info = entry_info(&address(), &entry).unwrap();
        assert_eq!(info.version.as_deref(), Some("deadbeef"));
        assert!(info.mtime.is_some());
        let metadata = info.system_metadata.unwrap();
        assert_eq!(
            metadata.get("hf.last-commit.id").map(String::as_str),
            Some("deadbeef")
        );
    }

    #[test]
    fn an_unrecognized_entry_type_is_refused_without_echo() {
        let entry = TreeEntry {
            entry_type: "symlink https://evil.example".into(),
            ..lfs_entry()
        };
        let err = entry_info(&address(), &entry).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(!err.message().contains("evil.example"));
    }
}
