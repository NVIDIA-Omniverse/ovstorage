// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory bytes store + per-method counters.

use std::collections::BTreeMap;
use std::time::SystemTime;

use ovstorage_plugin::{BackendItemInfo, ChecksumSet, ObjectInfo, ObjectKind, Url, UserMetadata};

/// Stored bytes + metadata for stat/read/list.
#[derive(Clone, Debug)]
pub struct StoredObject {
    pub bytes: Vec<u8>,
    pub mtime: SystemTime,
    pub user_metadata: UserMetadata,
}

impl StoredObject {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mtime: SystemTime::now(),
            user_metadata: UserMetadata::default(),
        }
    }

    pub fn with_user_metadata(mut self, user_metadata: UserMetadata) -> Self {
        self.user_metadata = user_metadata;
        self
    }

    pub fn etag(&self) -> String {
        format!("etag-{}", self.bytes.len())
    }

    pub fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            address,
            kind: ObjectKind::File,
            etag: Some(self.etag()),
            version: None,
            size: Some(self.bytes.len() as u64),
            mtime: Some(self.mtime),
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: if self.user_metadata.is_empty() {
                None
            } else {
                Some(self.user_metadata.clone())
            },
            modified_by: None,
        }
    }

    pub fn item_info(&self) -> BackendItemInfo {
        BackendItemInfo {
            kind: ObjectKind::File,
            etag: Some(self.etag()),
            version: None,
            size: Some(self.bytes.len() as u64),
            mtime: Some(self.mtime),
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: if self.user_metadata.is_empty() {
                None
            } else {
                Some(self.user_metadata.clone())
            },
            modified_by: None,
        }
    }
}

#[derive(Default)]
pub struct TestStore {
    /// Key → version chain. Last element is the current version.
    pub objects: BTreeMap<String, Vec<StoredObject>>,
    /// Keys explicitly created as directories via `create_directory`.
    /// Only consulted in real-directories mode (`has_real_directories`),
    /// where file-vs-directory type mismatches surface `InvalidArgument`
    /// instead of the marker-folding backends' permissive behavior.
    /// This set alone is not the full directory model — see
    /// [`TestStore::is_directory`], which also treats implicit parents of
    /// stored objects as directories, mirroring `FileBackend` where
    /// `write a/b` materializes `a` on disk.
    pub directories: std::collections::BTreeSet<String>,
    /// Surfaced via `__test_meta/method_calls.json`.
    pub counters: MethodCounters,
    /// Toggled by PUT to `__test_meta/redirect_expired`; forces every
    /// redirect to already-expired so tests exercise the broker's
    /// "redirect expired but cache still serves" path.
    pub redirect_force_expired: bool,
    /// Bounds `test_inject_error_count` per method.
    pub injections: BTreeMap<String, u64>,
}

impl TestStore {
    pub fn current(&self, key: &str) -> Option<&StoredObject> {
        self.objects.get(key).and_then(|chain| chain.last())
    }

    pub fn put(&mut self, key: String, object: StoredObject) {
        self.objects.entry(key).or_default().push(object);
    }

    pub fn remove(&mut self, key: &str) {
        self.objects.remove(key);
    }

    /// Real-directories model: a key is a directory if it was explicitly
    /// created via `create_directory` *or* exists implicitly as the parent
    /// prefix of stored objects — mirroring `FileBackend`, where `write a/b`
    /// materializes `a` as an on-disk directory. The empty key is the
    /// connection root, always a directory.
    pub fn is_directory(&self, key: &str) -> bool {
        if key.is_empty() || self.directories.contains(key) {
            return true;
        }
        let child_prefix = format!("{key}/");
        self.objects
            .range(child_prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&child_prefix))
            .any(|(_, chain)| chain.last().is_some())
    }
}

impl TestStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bump(&mut self, method: &str) {
        self.counters.bump(method);
    }
}

#[derive(Default, Debug, Clone)]
pub struct MethodCounters {
    pub stat: u64,
    pub read: u64,
    pub write: u64,
    pub write_stream: u64,
    pub write_redirect: u64,
    pub continue_write: u64,
    pub delete: u64,
    pub list: u64,
    pub list_versions: u64,
    pub copy: u64,
    pub rename: u64,
    pub update_metadata: u64,
    pub check_access: u64,
    pub create_directory: u64,
    pub delete_directory: u64,
    pub watch_directory: u64,
    pub watch_address_roots: u64,
    pub list_address_roots: u64,
    pub probe: u64,
    pub instantiate: u64,
    pub authenticate: u64,
}

impl MethodCounters {
    pub fn bump(&mut self, method: &str) {
        match method {
            "stat" => self.stat += 1,
            "read" => self.read += 1,
            "write" => self.write += 1,
            "write_stream" => self.write_stream += 1,
            "write_redirect" => self.write_redirect += 1,
            "continue_write" => self.continue_write += 1,
            "delete" => self.delete += 1,
            "list" => self.list += 1,
            "list_versions" => self.list_versions += 1,
            "copy" => self.copy += 1,
            "rename" => self.rename += 1,
            "update_metadata" => self.update_metadata += 1,
            "check_access" => self.check_access += 1,
            "create_directory" => self.create_directory += 1,
            "delete_directory" => self.delete_directory += 1,
            "watch_directory" => self.watch_directory += 1,
            "watch_address_roots" => self.watch_address_roots += 1,
            "list_address_roots" => self.list_address_roots += 1,
            "probe" => self.probe += 1,
            "instantiate" => self.instantiate += 1,
            "authenticate" => self.authenticate += 1,
            _ => {}
        }
    }

    pub fn as_json(&self) -> String {
        format!(
            "{{\"stat\":{},\"read\":{},\"write\":{},\"write_stream\":{},\
             \"write_redirect\":{},\"continue_write\":{},\
             \"delete\":{},\"list\":{},\"list_versions\":{},\"copy\":{},\
             \"rename\":{},\"update_metadata\":{},\"check_access\":{},\
             \"create_directory\":{},\"delete_directory\":{},\"watch_directory\":{},\
             \"watch_address_roots\":{},\"list_address_roots\":{},\
             \"probe\":{},\"instantiate\":{},\"authenticate\":{}}}",
            self.stat,
            self.read,
            self.write,
            self.write_stream,
            self.write_redirect,
            self.continue_write,
            self.delete,
            self.list,
            self.list_versions,
            self.copy,
            self.rename,
            self.update_metadata,
            self.check_access,
            self.create_directory,
            self.delete_directory,
            self.watch_directory,
            self.watch_address_roots,
            self.list_address_roots,
            self.probe,
            self.instantiate,
            self.authenticate,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_bump_known_methods() {
        let mut store = TestStore::new();
        store.bump("read");
        store.bump("read");
        store.bump("write");
        assert_eq!(store.counters.read, 2);
        assert_eq!(store.counters.write, 1);
        assert_eq!(store.counters.delete, 0);
    }

    #[test]
    fn counters_ignore_unknown_methods() {
        let mut store = TestStore::new();
        store.bump("not_a_real_method");
        assert_eq!(store.counters.read, 0);
    }

    #[test]
    fn counters_json_includes_every_field() {
        let mut store = TestStore::new();
        store.bump("read");
        let json: serde_json::Value =
            serde_json::from_str(&store.counters.as_json()).expect("counters json parses");
        assert_eq!(json["read"], 1);
        assert_eq!(json["write"], 0);
    }

    #[test]
    fn stored_object_etag_includes_size() {
        let obj = StoredObject::new(b"hello".to_vec());
        let etag = obj.etag();
        assert!(etag.contains("5"));
    }
}
