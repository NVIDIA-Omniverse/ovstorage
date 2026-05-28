// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[allow(unused_imports)]
use ovstorage_plugin::shim::{Backend as _, Factory as _};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ovstorage_cache::{Cache, CacheConfig};

struct RecordingBackend {
    capabilities: Capabilities,
}

struct CountingBackend {
    capabilities: Capabilities,
    reads: Arc<AtomicUsize>,
    stats: Arc<AtomicUsize>,
}

impl CountingBackend {
    fn new(reads: Arc<AtomicUsize>, stats: Arc<AtomicUsize>) -> Self {
        Self {
            capabilities: Capabilities::empty(),
            reads,
            stats,
        }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for CountingBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.stats.fetch_add(1, Ordering::SeqCst);
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(4),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.reads.fetch_add(1, Ordering::SeqCst);
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(4),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: b"data".to_vec(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let size = bytes.len() as u64;
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(size),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }
}

struct NoOptionalBackend {
    capabilities: Capabilities,
}

struct TargetRecordingBackend {
    capabilities: Capabilities,
    seen: Arc<Mutex<Vec<String>>>,
    exact_stat_not_found: bool,
}

struct ObjectOnlyStatBackend {
    capabilities: Capabilities,
}

struct DirectoryDeniedStatBackend {
    capabilities: Capabilities,
    seen: Arc<Mutex<Vec<String>>>,
}

struct ListStatBackend {
    capabilities: Capabilities,
    lists: Arc<AtomicUsize>,
    stats: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl NoOptionalBackend {
    fn new() -> Self {
        // No optional bits except those needed for the host's
        // copy / rename fallback paths (which decompose into
        // read + write + delete). copy/rename themselves stay
        // unsupported so the dispatcher must gate them before
        // reaching this backend's panicking impls.
        let mut capabilities = Capabilities::empty();
        capabilities.supports_write = true;
        capabilities.supports_delete = true;
        Self { capabilities }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for NoOptionalBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: b"fallback".to_vec(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn copy(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        panic!("dispatcher should not call unsupported copy")
    }

    async fn rename(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        panic!("dispatcher should not call unsupported rename")
    }

    async fn update_metadata(
        &self,
        _target: ResolvedTarget,
        _opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        panic!("dispatcher should not call unsupported update_metadata")
    }

    async fn check_access(
        &self,
        _target: ResolvedTarget,
        _ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        panic!("dispatcher should not call unsupported check_access")
    }
}

impl TargetRecordingBackend {
    fn new(seen: Arc<Mutex<Vec<String>>>) -> Self {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_list = true;
        capabilities.supports_recursive_list = true;
        capabilities.supports_create_directory = true;
        capabilities.supports_delete_directory = true;
        Self {
            capabilities,
            seen,
            exact_stat_not_found: false,
        }
    }

    fn new_directory_only(seen: Arc<Mutex<Vec<String>>>) -> Self {
        let mut backend = Self::new(seen);
        backend.exact_stat_not_found = true;
        backend
    }

    fn record(&self, target: &ResolvedTarget) {
        self.seen
            .lock()
            .unwrap()
            .push(target.resolved_address.as_str().to_string());
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for TargetRecordingBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        if self.exact_stat_not_found && !address::is_directory(&target.resolved_address) {
            return Err(Error::new(ErrorCode::NotFound, "object not found"));
        }
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        Ok(())
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&prefix);
        Ok(vec![ObjectInfo {
            address: address::join_relative(&prefix.resolved_address, "child.txt")?,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        }])
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        Ok(())
    }
}

impl ObjectOnlyStatBackend {
    fn new() -> Self {
        Self {
            capabilities: Capabilities::empty(),
        }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for ObjectOnlyStatBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        if address::is_directory(&target.resolved_address) {
            return Err(Error::new(ErrorCode::NotFound, "directory not found"));
        }
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }
}

impl DirectoryDeniedStatBackend {
    fn new(seen: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            capabilities: Capabilities::empty(),
            seen,
        }
    }

    fn record(&self, target: &ResolvedTarget) {
        self.seen
            .lock()
            .unwrap()
            .push(target.resolved_address.as_str().to_string());
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for DirectoryDeniedStatBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.record(&target);
        if !address::is_directory(&target.resolved_address) {
            return Err(Error::new(ErrorCode::NotFound, "object not found"));
        }
        Err(Error::new(
            ErrorCode::PermissionDenied,
            "directory probe denied",
        ))
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }
}

impl ListStatBackend {
    fn new(lists: Arc<AtomicUsize>, stats: Arc<AtomicUsize>, writes: Arc<AtomicUsize>) -> Self {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_list = true;
        capabilities.wants_list_backed_stat = true;
        capabilities.supports_write = true;
        capabilities.supports_delete = true;
        Self {
            capabilities,
            lists,
            stats,
            writes,
        }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for ListStatBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.stats.fetch_add(1, Ordering::SeqCst);
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(99),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.writes.fetch_add(1, Ordering::SeqCst);
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        self.lists.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            ObjectInfo {
                address: address::join_relative(&prefix.resolved_address, "a.txt")?,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(1),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            },
            ObjectInfo {
                address: address::join_relative(&prefix.resolved_address, "b.txt")?,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(2),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            },
        ])
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }
}

impl RecordingBackend {
    fn new() -> Self {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_list = true;
        capabilities.supports_recursive_list = true;
        capabilities.supports_write = true;
        capabilities.supports_write_stream = true;
        capabilities.supports_write_redirect = true;
        capabilities.supports_delete = true;
        capabilities.supports_create_directory = true;
        capabilities.supports_delete_directory = true;
        Self { capabilities }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for RecordingBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        if target.resolved_address.as_str().ends_with(".txt/") {
            return Err(Error::new(ErrorCode::NotFound, "directory not found"));
        }
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some(4),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(ReadResult::Bytes {
            bytes: b"data".to_vec(),
            info,
        })
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        Ok(WriteResult { info })
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(vec![
            ObjectInfo {
                address: address::join_relative(&prefix.resolved_address, "child.txt")?,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(9),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            },
            ObjectInfo {
                address: address::join_relative(&prefix.resolved_address, "sub/")?,
                kind: ObjectKind::Directory,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            },
        ])
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let _ = target;
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }
}

struct MockFactory;

#[async_trait::async_trait]
impl shim::Factory for MockFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "mock".into(),
            display_name: "Mock".into(),
            description: None,
            config_schema: vec![ConfigField {
                key: "prefix".into(),
                display_name: "Prefix".into(),
                kind: ConfigFieldKind::Url,
                required: true,
                default: None,
                help: None,
                example: Some("mock://root/".into()),
                group: None,
                advanced: false,
            }],
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let prefix = mock_factory_prefix(request)?;
        let backend = Arc::new(RecordingBackend::new());
        let capabilities = backend.capabilities().clone();
        Ok(shim::BackendInstance {
            backend_id: BackendId(format!("mock:{prefix}")),
            backend,
            address_roots: vec![AddressRoot {
                address: prefix,
                display_name: None,
                backend_kind: "mock".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request.display_name.clone(),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

fn mock_factory_prefix(request: &ConnectionRequest) -> Result<Url> {
    match request.config.get("prefix") {
        Some(ConfigValue::String(value)) => address::parse(value),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "mock factory requires a string prefix",
        )),
    }
}

fn mock_connection_request(prefix: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("prefix".into(), ConfigValue::String(prefix.into()));
    ConnectionRequest {
        backend_kind: "mock".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("mock connection".into()),
    }
}

#[test]
fn redacted_url_strips_userinfo_query_and_fragment() {
    use crate::RedactedUrl;
    let url = Url::parse("s3://user:secret@example.com/path/file.usd?token=abc&versionId=7#frag")
        .unwrap();
    assert_eq!(
        RedactedUrl(&url).to_string(),
        "s3://example.com/path/file.usd"
    );
    let file_url = Url::parse("file:///tmp/a.usd").unwrap();
    assert_eq!(RedactedUrl(&file_url).to_string(), "file:///tmp/a.usd");
}

#[test]
fn error_constructed_with_signed_url_is_redacted_end_to_end() {
    use crate::{Error, ErrorCode};

    let err = Error::new(
        ErrorCode::Transient,
        "broker redirect fetch failed from \
         https://bucket.s3.amazonaws.com/key\
         ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIA/20260513/us-east-1/s3/aws4_request\
         &X-Amz-Signature=topsecret\
         &versionId=42",
    );

    let msg = err.message();
    assert!(msg.contains("X-Amz-Signature=REDACTED"), "{msg}");
    assert!(msg.contains("X-Amz-Credential=REDACTED"), "{msg}");
    assert!(msg.contains("versionId=42"), "{msg}");
    assert!(!msg.contains("topsecret"), "{msg}");
    assert!(!msg.contains("AKIA"), "{msg}");

    let display = format!("{err}");
    assert!(!display.contains("topsecret"), "{display}");
}

#[test]
fn next_action_populated_for_no_route_error() {
    use crate::{Error, ErrorCode};

    let err = Error::new(ErrorCode::NoRoute, "no route matches address").with_next_action(
        "Call library.add_connection(...) for a backend that serves \
         this address prefix, or load a saved configuration via \
         library.load_config(...).",
    );

    assert_eq!(err.code(), ErrorCode::NoRoute);
    assert!(err.next_action().is_some());
    let hint = err.next_action().unwrap();
    assert!(hint.contains("library.add_connection"), "{hint}");
}

#[tokio::test]
async fn direct_connection_management_adds_and_removes_routes() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(MockFactory))
        .open()
        .unwrap();
    assert_eq!(lib.list_backend_kinds().unwrap()[0].kind, "mock");

    let connection = lib
        .add_connection(mock_connection_request("mock://root/"), None)
        .await
        .unwrap();
    assert_eq!(connection.current_addresses[0].as_str(), "mock://root/");
    assert_eq!(lib.list_connections().unwrap().len(), 1);
    assert_eq!(
        lib.list_address_roots().unwrap()[0].address.as_str(),
        "mock://root/"
    );
    let (bytes, _) = lib
        .read_bytes(
            Url::parse("mock://root/object.txt").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(bytes, b"data");

    let mut auth = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    assert!(matches!(
        auth.next().unwrap().unwrap(),
        AuthEvent::Succeeded { .. }
    ));
    let mut watched = lib.watch_connections().unwrap();
    assert!(matches!(
        watched.next().unwrap().unwrap(),
        ConnectionChange::Snapshot(snapshot) if snapshot.len() == 1
    ));

    lib.remove_connection(&connection.id).unwrap();
    assert_eq!(
        lib.read_bytes(
            Url::parse("mock://root/object.txt").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::NoRoute
    );
}

#[tokio::test]
async fn aliases_and_visibility_participate_in_resolution() {
    let lib = Library::builder()
        .add_route(
            Url::parse("physical://root/").unwrap(),
            "mock",
            Arc::new(RecordingBackend::new()),
            RecordingBackend::new().capabilities().clone(),
        )
        .open()
        .unwrap();
    let alias = lib
        .add_alias(AliasRequest {
            from: Url::parse("assets://").unwrap(),
            to: Url::parse("physical://root/").unwrap(),
            visibility: AddressVisibility::Visible,
            persist: false,
            display_name: None,
            user_metadata: UserMetadata::new(),
        })
        .unwrap();
    assert_eq!(alias.state, AliasState::Live);

    let (bytes, info) = lib
        .read_bytes(
            Url::parse("assets://object.txt").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(bytes, b"data");
    assert_eq!(info.address.as_str(), "assets://object.txt");

    lib.set_address_visibility(
        Url::parse("physical://root/").unwrap(),
        AddressVisibility::Suppressed,
        false,
    )
    .unwrap();
    assert_eq!(
        lib.stat(
            Url::parse("physical://root/object.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::NotConfigured
    );
    assert!(
        lib.read_bytes(
            Url::parse("assets://object.txt").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .is_ok()
    );

    let chain = lib.add_alias(AliasRequest {
        from: Url::parse("chain://").unwrap(),
        to: Url::parse("assets://").unwrap(),
        visibility: AddressVisibility::Visible,
        persist: false,
        display_name: None,
        user_metadata: UserMetadata::new(),
    });
    assert_eq!(chain.unwrap_err().code(), ErrorCode::AliasChainTooLong);

    lib.remove_alias(&alias.id).unwrap();
    assert_eq!(lib.list_aliases().unwrap().len(), 0);
}

#[tokio::test]
async fn longest_prefix_wins_and_results_stay_caller_facing() {
    let backend = Arc::new(RecordingBackend::new());
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_rewrite_route_with_backend_handle(
            Url::parse("logical://").unwrap(),
            Url::parse("physical://root/").unwrap(),
            "base",
            backend.clone(),
            caps.clone(),
        )
        .add_rewrite_route_with_backend_handle(
            Url::parse("logical://team/").unwrap(),
            Url::parse("physical://team-root/").unwrap(),
            "team",
            backend,
            caps,
        )
        .open()
        .unwrap();

    let info = lib
        .stat(
            Url::parse("logical://team/file.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.address.as_str(), "logical://team/file.txt");

    let items = lib
        .list(
            Url::parse("logical://team/dir/").unwrap(),
            ListOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(items[0].address.as_str(), "logical://team/dir/child.txt");
    assert_eq!(items[1].address.as_str(), "logical://team/dir/sub/");
}

#[tokio::test]
async fn list_page_returns_stable_boundary_tokens() {
    let lib = Library::builder()
        .add_route(
            Url::parse("logical://").unwrap(),
            "mock",
            Arc::new(RecordingBackend::new()),
            RecordingBackend::new().capabilities().clone(),
        )
        .open()
        .unwrap();
    let prefix = Url::parse("logical://team/dir").unwrap();

    let first = lib
        .list_page(
            prefix.clone(),
            ListOptions {
                max_results: Some(1),
                ..ListOptions::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(
        first.items[0].address.as_str(),
        "logical://team/dir/child.txt"
    );
    assert_eq!(first.next_page_token.as_deref(), Some("1"));

    let second = lib
        .list_page(
            prefix,
            ListOptions {
                max_results: Some(1),
                page_token: first.next_page_token,
                ..ListOptions::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].address.as_str(), "logical://team/dir/sub/");
    assert_eq!(second.next_page_token, None);
}

#[test]
fn duplicate_route_prefix_is_rejected() {
    let backend = Arc::new(RecordingBackend::new());
    let caps = backend.capabilities().clone();
    let result = Library::builder()
        .add_route(
            Url::parse("file:/").unwrap(),
            "a",
            backend.clone(),
            caps.clone(),
        )
        .add_route(Url::parse("file:/").unwrap(), "b", backend, caps)
        .open();
    let err = match result {
        Ok(_) => panic!("duplicate prefix should fail"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::RouteConflict);
}

#[tokio::test]
async fn cached_read_does_not_reenter_backend() {
    let reads = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let cache_root = unique_temp_path("cache-hit");
    let lib = Library::builder()
        .with_cache(
            Cache::open(CacheConfig {
                state_root: cache_root.join("state"),
                cache_root: cache_root.join("bytes"),
            })
            .unwrap(),
        )
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(CountingBackend::new(reads.clone(), stats.clone())),
            CountingBackend::new(reads.clone(), stats.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();
    let addr = Url::parse("mock://object").unwrap();

    assert_eq!(
        lib.read_bytes(addr.clone(), ReadOptions::default(), None)
            .await
            .unwrap()
            .0,
        b"data"
    );
    assert_eq!(
        lib.read_bytes(addr, ReadOptions::default(), None)
            .await
            .unwrap()
            .0,
        b"data"
    );
    let local = lib
        .materialize(
            Url::parse("mock://object").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(local.path).unwrap(), b"data");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
    drop(lib);
    std::fs::remove_dir_all(cache_root).unwrap();
}

#[tokio::test]
async fn list_backed_stat_reuses_parent_listing_for_siblings() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .with_metadata_cache(MetadataCacheConfig::default())
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    let a = lib
        .stat(
            Url::parse("mock://bucket/a.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();
    let b = lib
        .stat(
            Url::parse("mock://bucket/b.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(a.size, Some(1));
    assert_eq!(b.size, Some(2));
    assert_eq!(lists.load(Ordering::SeqCst), 1);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn list_then_stat_reads_child_from_metadata_cache() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .with_metadata_cache(MetadataCacheConfig::default())
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    lib.list(
        Url::parse("mock://bucket/").unwrap(),
        ListOptions::default(),
        None,
    )
    .await
    .unwrap();
    let info = lib
        .stat(
            Url::parse("mock://bucket/a.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(info.size, Some(1));
    assert_eq!(lists.load(Ordering::SeqCst), 1);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn full_metadata_stat_bypasses_parent_listing() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    let info = lib
        .stat(
            Url::parse("mock://bucket/a.txt").unwrap(),
            StatOptions {
                full_metadata: true,
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(info.size, Some(99));
    assert_eq!(lists.load(Ordering::SeqCst), 0);
    assert_eq!(stats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn list_backed_stat_skips_version_selected_urls() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    let info = lib
        .stat(
            Url::parse("mock://bucket/a.txt?versionId=1").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(info.size, Some(99));
    assert_eq!(lists.load(Ordering::SeqCst), 0);
    assert_eq!(stats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn list_backed_stat_returns_not_found_from_cached_parent_listing() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .with_metadata_cache(MetadataCacheConfig::default())
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    lib.list(
        Url::parse("mock://bucket/").unwrap(),
        ListOptions::default(),
        None,
    )
    .await
    .unwrap();
    let err = lib
        .stat(
            Url::parse("mock://bucket/c.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(lists.load(Ordering::SeqCst), 1);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn list_backed_stat_dirty_parent_folder_after_write() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .with_metadata_cache(MetadataCacheConfig::default())
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    lib.stat(
        Url::parse("mock://bucket/a.txt").unwrap(),
        StatOptions::default(),
        None,
    )
    .await
    .unwrap();
    lib.write(
        Url::parse("mock://bucket/c.txt").unwrap(),
        Body::Bytes(Vec::new()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    lib.list(
        Url::parse("mock://bucket/").unwrap(),
        ListOptions::default(),
        None,
    )
    .await
    .unwrap();
    lib.stat(
        Url::parse("mock://bucket/b.txt").unwrap(),
        StatOptions::default(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(lists.load(Ordering::SeqCst), 2);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn list_backed_stat_cache_is_size_bounded() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let lib = Library::builder()
        .with_metadata_cache(MetadataCacheConfig {
            max_entries: Some(1),
            ttl_seconds: Some(30),
            notification_sources: Vec::new(),
        })
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(ListStatBackend::new(
                lists.clone(),
                stats.clone(),
                writes.clone(),
            )),
            ListStatBackend::new(lists.clone(), stats.clone(), writes.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    lib.stat(
        Url::parse("mock://bucket/one/a.txt").unwrap(),
        StatOptions::default(),
        None,
    )
    .await
    .unwrap();
    lib.stat(
        Url::parse("mock://bucket/two/a.txt").unwrap(),
        StatOptions::default(),
        None,
    )
    .await
    .unwrap();
    lib.stat(
        Url::parse("mock://bucket/one/b.txt").unwrap(),
        StatOptions::default(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(lists.load(Ordering::SeqCst), 3);
    assert_eq!(stats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn list_backed_stat_honors_provider_preference() {
    let lists = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut backend = ListStatBackend::new(lists.clone(), stats.clone(), writes.clone());
    backend.capabilities.wants_list_backed_stat = false;
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://bucket/").unwrap(),
            "mock",
            Arc::new(backend),
            caps,
        )
        .open()
        .unwrap();

    let info = lib
        .stat(
            Url::parse("mock://bucket/a.txt").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(info.size, Some(99));
    assert_eq!(lists.load(Ordering::SeqCst), 0);
    assert_eq!(stats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unsupported_optional_methods_are_gated_before_dispatch() {
    let backend = Arc::new(NoOptionalBackend::new());
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(Url::parse("mock://").unwrap(), "mock", backend, caps)
        .open()
        .unwrap();
    let src = Url::parse("mock://src").unwrap();
    let dest = Url::parse("mock://dest").unwrap();

    let copied = lib
        .copy(src.clone(), dest.clone(), CopyOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(copied.info.address, dest);
    lib.rename(
        src.clone(),
        Url::parse("mock://moved").unwrap(),
        RenameOptions::default(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        lib.update_metadata(src.clone(), UpdateMetadataOptions::default(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        lib.check_access(
            src,
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Unsupported
    );
}

#[tokio::test]
async fn directory_operations_accept_bare_directory_addresses() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(TargetRecordingBackend::new(seen.clone())),
            TargetRecordingBackend::new(seen.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();
    let bare = Url::parse("mock://team").unwrap();
    let slash = Url::parse("mock://team/").unwrap();

    assert_eq!(
        lib.stat(slash, StatOptions::default(), None)
            .await
            .unwrap()
            .address
            .as_str(),
        "mock://team/"
    );
    assert_eq!(
        lib.list(bare.clone(), ListOptions::default(), None)
            .await
            .unwrap()[0]
            .address
            .as_str(),
        "mock://team/child.txt"
    );
    assert_eq!(
        lib.create_directory(bare.clone(), CreateDirectoryOptions::default(), None)
            .await
            .unwrap()
            .address
            .as_str(),
        "mock://team/"
    );
    lib.delete_directory(bare, DeleteDirectoryOptions, None)
        .await
        .unwrap();

    assert_eq!(
        &*seen.lock().unwrap(),
        &[
            "mock://team/".to_string(),
            "mock://team/".to_string(),
            "mock://team/".to_string(),
            "mock://team/".to_string()
        ]
    );
}

#[tokio::test]
async fn bare_stat_prefers_exact_object_before_directory() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(TargetRecordingBackend::new(seen.clone())),
            TargetRecordingBackend::new(seen.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    assert_eq!(
        lib.stat(
            Url::parse("mock://team").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap()
        .address
        .as_str(),
        "mock://team"
    );
    assert_eq!(&*seen.lock().unwrap(), &["mock://team".to_string()]);
}

#[tokio::test]
async fn bare_stat_falls_back_to_directory_when_exact_object_is_absent() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(TargetRecordingBackend::new_directory_only(seen.clone())),
            TargetRecordingBackend::new_directory_only(seen.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    assert_eq!(
        lib.stat(
            Url::parse("mock://team").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap()
        .address
        .as_str(),
        "mock://team/"
    );
    assert_eq!(
        &*seen.lock().unwrap(),
        &["mock://team".to_string(), "mock://team/".to_string()]
    );
}

#[tokio::test]
async fn bare_stat_returns_exact_object_when_directory_is_absent() {
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(ObjectOnlyStatBackend::new()),
            ObjectOnlyStatBackend::new().capabilities().clone(),
        )
        .open()
        .unwrap();

    assert_eq!(
        lib.stat(
            Url::parse("mock://object").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap()
        .address
        .as_str(),
        "mock://object"
    );
}

#[tokio::test]
async fn slash_stat_never_falls_back_to_exact_object() {
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(ObjectOnlyStatBackend::new()),
            ObjectOnlyStatBackend::new().capabilities().clone(),
        )
        .open()
        .unwrap();

    assert_eq!(
        lib.stat(
            Url::parse("mock://object/").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn bare_stat_returns_directory_denial_after_exact_object_is_absent() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lib = Library::builder()
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(DirectoryDeniedStatBackend::new(seen.clone())),
            DirectoryDeniedStatBackend::new(seen.clone())
                .capabilities()
                .clone(),
        )
        .open()
        .unwrap();

    assert_eq!(
        lib.stat(
            Url::parse("mock://team").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        &*seen.lock().unwrap(),
        &["mock://team".to_string(), "mock://team/".to_string()]
    );
}

/// Backend that yields scripted `AddressRootsChange` events through
/// `watch_address_roots`. Tests use it to assert
/// `Library`'s dynamic-roots watcher applies frames to the route
/// table and bumps `route_epoch`.
struct DynamicRootsBackend {
    capabilities: Capabilities,
    events: Mutex<Option<Vec<Result<AddressRootsChange>>>>,
}

impl DynamicRootsBackend {
    fn new(events: Vec<AddressRootsChange>) -> Self {
        let caps = RecordingBackend::new().capabilities().clone();
        Self {
            capabilities: caps,
            events: Mutex::new(Some(events.into_iter().map(Ok).collect())),
        }
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for DynamicRootsBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        _target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "stub"))
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(())
    }

    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let events = self.events.lock().unwrap().take().unwrap_or_default();
        Ok(Box::pin(futures::stream::iter(events)))
    }
}

struct DynamicRootsFactory;

#[async_trait::async_trait]
impl shim::Factory for DynamicRootsFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "dynamic".into(),
            display_name: "Dynamic".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        // First instantiate yields a Snapshot with one root, then
        // Added with a second root, so a successful run lands two
        // routes in the table after the watcher drains.
        let backend = Arc::new(DynamicRootsBackend::new(vec![
            AddressRootsChange::Snapshot(vec![AddressRoot {
                address: Url::parse("dynamic://seed/").unwrap(),
                display_name: None,
                backend_kind: "dynamic".into(),
                connection_id: None,
                capabilities: backend_caps_for_dynamic(),
                source: RouteSource::ConnectionContributed {
                    connection_id: ConnectionId("placeholder".into()),
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }]),
            AddressRootsChange::Added(vec![AddressRoot {
                address: Url::parse("dynamic://added/").unwrap(),
                display_name: None,
                backend_kind: "dynamic".into(),
                connection_id: None,
                capabilities: backend_caps_for_dynamic(),
                source: RouteSource::ConnectionContributed {
                    connection_id: ConnectionId("placeholder".into()),
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }]),
        ]));
        let caps = backend.capabilities().clone();
        Ok(shim::BackendInstance {
            backend_id: BackendId("dynamic:0".into()),
            backend,
            address_roots: vec![AddressRoot {
                address: Url::parse("dynamic://seed/").unwrap(),
                display_name: None,
                backend_kind: "dynamic".into(),
                connection_id: None,
                capabilities: caps,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: None,
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

struct EmptyDynamicRootsFactory;

#[async_trait::async_trait]
impl shim::Factory for EmptyDynamicRootsFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "empty-dynamic".into(),
            display_name: "Empty Dynamic".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel;
        Ok(shim::BackendInstance {
            backend_id: BackendId("empty-dynamic:0".into()),
            backend: Arc::new(DynamicRootsBackend::new(vec![
                AddressRootsChange::Snapshot(Vec::new()),
            ])),
            address_roots: Vec::new(),
            display_name: Some("empty-dynamic".into()),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

struct PendingRootsBackend;

#[async_trait::async_trait]
impl shim::Backend for PendingRootsBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel;
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        _target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel;
        Err(Error::new(ErrorCode::Unsupported, "stub"))
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel;
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel;
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel;
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel;
        Ok(())
    }

    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        let _ = &cancel;
        Ok(Box::pin(futures::stream::pending()))
    }
}

struct PendingRootsFactory;

#[async_trait::async_trait]
impl shim::Factory for PendingRootsFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "pending-roots".into(),
            display_name: "Pending Roots".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel;
        Ok(shim::BackendInstance {
            backend_id: BackendId("pending-roots:0".into()),
            backend: Arc::new(PendingRootsBackend),
            address_roots: Vec::new(),
            display_name: Some("pending-roots".into()),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

fn backend_caps_for_dynamic() -> Capabilities {
    RecordingBackend::new().capabilities().clone()
}

#[tokio::test]
async fn route_epoch_bumps_on_connection_lifecycle_and_aliases() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(MockFactory))
        .open()
        .unwrap();
    assert_eq!(lib.route_epoch(), 0);

    let connection = lib
        .add_connection(mock_connection_request("mock://root/"), None)
        .await
        .unwrap();
    let after_add = lib.route_epoch();
    assert!(after_add >= 1, "epoch must advance on add_connection");

    lib.add_alias(AliasRequest {
        from: Url::parse("alias://").unwrap(),
        to: Url::parse("mock://root/").unwrap(),
        visibility: AddressVisibility::Visible,
        persist: false,
        display_name: None,
        user_metadata: UserMetadata::new(),
    })
    .unwrap();
    let after_alias = lib.route_epoch();
    assert!(after_alias > after_add, "epoch must advance on add_alias");

    lib.set_address_visibility(
        Url::parse("mock://root/").unwrap(),
        AddressVisibility::Hidden,
        false,
    )
    .unwrap();
    let after_visibility = lib.route_epoch();
    assert!(
        after_visibility > after_alias,
        "epoch must advance on visibility change"
    );

    lib.remove_connection(&connection.id).unwrap();
    let after_remove = lib.route_epoch();
    assert!(
        after_remove > after_visibility,
        "epoch must advance on remove_connection"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_roots_watcher_applies_snapshot_then_added() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(DynamicRootsFactory))
        .open()
        .unwrap();
    let _ = lib
        .add_connection(
            ConnectionRequest {
                backend_kind: "dynamic".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();
    // The watcher runs in a spawned task. Yield repeatedly until
    // we see both routes show up; bound the wait so a regression
    // surfaces as a test timeout rather than hang.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let roots = lib.list_address_roots().unwrap();
        let addrs: Vec<&str> = roots.iter().map(|r| r.address.as_str()).collect();
        if addrs.contains(&"dynamic://seed/") && addrs.contains(&"dynamic://added/") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "watcher did not apply both events: {addrs:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Two route-bumps from the watcher (Snapshot + Added) plus
    // the initial bump from add_connection means epoch >= 3.
    assert!(lib.route_epoch() >= 3);
}

#[tokio::test]
async fn add_connection_accepts_empty_dynamic_roots_snapshot() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(EmptyDynamicRootsFactory))
        .open()
        .unwrap();
    let connection = lib
        .add_connection(
            ConnectionRequest {
                backend_kind: "empty-dynamic".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();

    assert!(connection.current_addresses.is_empty());
    assert!(lib.list_address_roots().unwrap().is_empty());
    assert_eq!(lib.list_connections().unwrap().len(), 1);
}

#[tokio::test]
async fn add_connection_times_out_when_dynamic_roots_never_reports() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(PendingRootsFactory))
        .open()
        .unwrap();
    let err = lib
        .add_connection(
            ConnectionRequest {
                backend_kind: "pending-roots".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    assert!(lib.list_connections().unwrap().is_empty());
    assert!(lib.list_address_roots().unwrap().is_empty());
}

#[tokio::test]
async fn watch_address_roots_emits_snapshots_for_connection_and_alias_table_changes() {
    let lib = Library::builder()
        .register_backend_factory(Arc::new(MockFactory))
        .open()
        .unwrap();
    let cancel = CancellationToken::new();
    let mut stream = lib.watch_address_roots(Some(cancel.clone())).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for _ in 0..3 {
            tx.send(stream.next().expect("watch event"))
                .expect("receiver is alive");
        }
    });

    let first = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("initial snapshot")
        .unwrap();
    assert!(first.is_empty());

    let connection = lib
        .add_connection(mock_connection_request("mock://watched/"), None)
        .await
        .unwrap();
    let second = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("connection root added")
        .unwrap();
    assert!(
        second
            .iter()
            .any(|root| root.address.as_str() == "mock://watched/")
    );

    let alias = lib
        .add_alias(AliasRequest {
            from: Url::parse("alias://watched/").unwrap(),
            to: Url::parse("mock://watched/target").unwrap(),
            visibility: AddressVisibility::Visible,
            persist: false,
            display_name: Some("watched alias".into()),
            user_metadata: UserMetadata::new(),
        })
        .unwrap();
    let third = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("alias root added")
        .unwrap();
    assert!(
        third
            .iter()
            .any(|root| root.address.as_str() == "alias://watched/"
                && root.backend_kind == "alias")
    );

    handle.join().unwrap();
    cancel.cancel();
    lib.remove_alias(&alias.id).unwrap();
    lib.remove_connection(&connection.id).unwrap();
}

struct CredentialGatedRootsState {
    installed: AtomicBool,
    token_arrived: tokio::sync::Notify,
}

impl CredentialGatedRootsState {
    fn new() -> Self {
        Self {
            installed: AtomicBool::new(false),
            token_arrived: tokio::sync::Notify::new(),
        }
    }

    async fn wait_for_credentials(&self) {
        loop {
            let notified = self.token_arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.installed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

struct CredentialGatedRootsBackend {
    state: Arc<CredentialGatedRootsState>,
    capabilities: Capabilities,
}

#[async_trait::async_trait]
impl shim::Backend for CredentialGatedRootsBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel;
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        _target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel;
        Err(Error::new(ErrorCode::Unsupported, "stub"))
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel;
        Ok(())
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel;
        Ok(Vec::new())
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel;
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel;
        Ok(())
    }

    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        match cancel {
            Some(cancel) => {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        return Err(Error::new(ErrorCode::Cancelled, "cancelled"));
                    }
                    _ = self.state.wait_for_credentials() => {}
                }
            }
            None => self.state.wait_for_credentials().await,
        }
        let capabilities = self.capabilities.clone();
        let roots = vec![AddressRoot {
            address: Url::parse("credential-gated://root/").unwrap(),
            display_name: None,
            backend_kind: "credential-gated".into(),
            connection_id: None,
            capabilities,
            source: RouteSource::ConnectionContributed {
                connection_id: ConnectionId("placeholder".into()),
            },
            visibility: AddressVisibility::Visible,
            user_metadata: UserMetadata::new(),
        }];
        Ok(Box::pin(futures::stream::once(async move {
            Ok(AddressRootsChange::Snapshot(roots))
        })))
    }
}

struct CredentialGatedRootsFactory {
    state: Arc<CredentialGatedRootsState>,
}

#[async_trait::async_trait]
impl shim::Factory for CredentialGatedRootsFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "credential-gated".into(),
            display_name: "Credential Gated".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel;
        let capabilities = backend_caps_for_dynamic();
        let backend = Arc::new(CredentialGatedRootsBackend {
            state: self.state.clone(),
            capabilities,
        });
        Ok(shim::BackendInstance {
            backend_id: BackendId("credential-gated:0".into()),
            backend,
            address_roots: Vec::new(),
            display_name: Some("credential-gated".into()),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
        })
    }

    async fn update_credentials(
        &self,
        _connection: &Connection,
        _credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel;
        self.state.installed.store(true, Ordering::SeqCst);
        self.state.token_arrived.notify_waiters();
        Ok(())
    }

    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let _ = &cancel;
        Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: Some(SecretBundle::default()),
        }))))
    }
}

#[tokio::test]
async fn update_connection_credentials_waits_for_dynamic_address_roots() {
    let state = Arc::new(CredentialGatedRootsState::new());
    let lib = Library::builder()
        .register_backend_factory(Arc::new(CredentialGatedRootsFactory { state }))
        .open()
        .unwrap();
    let connection = lib
        .add_connection(
            ConnectionRequest {
                backend_kind: "credential-gated".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();
    assert!(connection.current_addresses.is_empty());
    assert!(lib.list_address_roots().unwrap().is_empty());

    let updated = lib
        .update_connection_credentials(&connection.id, SecretBundle::default(), None)
        .await
        .unwrap();

    assert!(matches!(
        updated.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert_eq!(
        updated.current_addresses[0].as_str(),
        "credential-gated://root/"
    );
    let roots = lib.list_address_roots().unwrap();
    assert_eq!(roots[0].address.as_str(), "credential-gated://root/");
    let info = lib
        .stat(
            Url::parse("credential-gated://root/scene.usd").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.address.as_str(), "credential-gated://root/scene.usd");
}

#[tokio::test]
async fn authenticate_connection_waits_for_dynamic_address_roots() {
    let state = Arc::new(CredentialGatedRootsState::new());
    let lib = Library::builder()
        .register_backend_factory(Arc::new(CredentialGatedRootsFactory { state }))
        .open()
        .unwrap();
    let connection = lib
        .add_connection(
            ConnectionRequest {
                backend_kind: "credential-gated".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();
    assert!(connection.current_addresses.is_empty());
    assert!(lib.list_address_roots().unwrap().is_empty());

    let mut stream = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    let event = tokio::task::spawn_blocking(move || stream.next().expect("auth event"))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, AuthEvent::Succeeded { .. }));

    let updated = lib
        .list_connections()
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.id == connection.id)
        .unwrap();
    assert_eq!(
        updated.current_addresses[0].as_str(),
        "credential-gated://root/"
    );
    let roots = lib.list_address_roots().unwrap();
    assert_eq!(roots[0].address.as_str(), "credential-gated://root/");
}

fn unique_temp_path(label: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ovstorage-{label}-{}-{stamp}", std::process::id()))
}

/// Backend that returns `ReadResult::Stream` with a configurable
/// chunk count and chunk size. The iterator generates a
/// deterministic byte pattern so tests can verify both the byte
/// count AND the content. The total object size is
/// `chunk_size * chunk_count` bytes; the iterator NEVER
/// materializes the whole object — it generates one chunk per
/// `next()` call. This is the conformance-grade fixture for
/// "streaming reads use bounded memory".
struct StreamingBackend {
    capabilities: Capabilities,
    chunk_size: usize,
    chunk_count: usize,
}

impl StreamingBackend {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl shim::Backend for StreamingBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Ok(ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some((self.chunk_size * self.chunk_count) as u64),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        })
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        _opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let info = ObjectInfo {
            address: target.resolved_address,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: Some((self.chunk_size * self.chunk_count) as u64),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        let chunk_size = self.chunk_size;
        let chunk_count = self.chunk_count;
        // Generator stream: synthesizes one chunk per `.next()`;
        // chunk N is filled with byte (N % 251). No accumulator
        // — peak stream memory is one chunk.
        let stream: ReadStream =
            Box::pin(futures::stream::unfold(0usize, move |emitted| async move {
                if emitted >= chunk_count {
                    return None;
                }
                let byte = (emitted % 251) as u8;
                let chunk = bytes::Bytes::from(vec![byte; chunk_size]);
                Some((Ok(chunk), emitted + 1))
            }));
        Ok(ReadResult::Stream { stream, info })
    }

    async fn write(
        &self,
        _target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "writes not supported"))
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "deletes not supported"))
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "list not supported"))
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "mkdir not supported"))
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        Err(Error::new(ErrorCode::Unsupported, "rmdir not supported"))
    }
}

/// Streaming-read conformance test.
///
/// Drives `Library::read_stream` against a backend that returns
/// `ReadResult::Stream` and asserts the async stream yields one
/// chunk at a time WITHOUT collecting the whole object into a
/// single `Vec<u8>`. The backend's stream generates a
/// deterministic byte pattern; the test verifies the digest
/// matches and that the stream's chunk boundaries are
/// preserved end-to-end.
///
/// Object size: 1 GiB (16 MiB chunks × 64). Peak stream memory:
/// one 16 MiB chunk. If the dispatcher silently collected to Vec,
/// the test would still pass on byte content but RSS would
/// balloon to 1 GiB+ — observable in CI memory profiles. The
/// chunk-count assertion below is the programmatic complement:
/// it requires the dispatcher to preserve chunking, which is
/// impossible if it collected to a single buffer.
///
/// `ReadStream` is a `futures::Stream` — the drain loop is
/// `.next().await` on the runtime, no `spawn_blocking` hop.
#[tokio::test]
async fn read_stream_preserves_chunking_through_dispatcher() {
    use futures::StreamExt;
    const CHUNK_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
    const CHUNK_COUNT: usize = 64; // 1 GiB total
    let backend = Arc::new(StreamingBackend {
        capabilities: Capabilities::empty(),
        chunk_size: CHUNK_SIZE,
        chunk_count: CHUNK_COUNT,
    });
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("stream://root/").unwrap(),
            "stream-mock",
            backend,
            caps,
        )
        .open()
        .unwrap();

    let (mut stream, info) = lib
        .read_stream(
            Url::parse("stream://root/big.bin").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.size, Some((CHUNK_SIZE * CHUNK_COUNT) as u64));

    let mut chunks_seen = 0usize;
    let mut total_bytes = 0u64;
    let mut max_chunk_seen = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        let expected_byte = (chunks_seen % 251) as u8;
        assert!(
            chunk.iter().all(|b| *b == expected_byte),
            "chunk {chunks_seen} did not match expected byte pattern"
        );
        if chunk.len() > max_chunk_seen {
            max_chunk_seen = chunk.len();
        }
        total_bytes += chunk.len() as u64;
        chunks_seen += 1;
    }
    assert_eq!(
        chunks_seen, CHUNK_COUNT,
        "dispatcher silently collected the stream — saw {chunks_seen} chunk(s) instead of {CHUNK_COUNT}"
    );
    assert_eq!(total_bytes, (CHUNK_SIZE * CHUNK_COUNT) as u64);
    assert_eq!(
        max_chunk_seen, CHUNK_SIZE,
        "dispatcher rebuffered chunks (max chunk {max_chunk_seen} bytes; expected {CHUNK_SIZE})"
    );
}

/// Companion test for `Library::read_bytes` against the same
/// streaming backend. The bytes path drains the async stream
/// natively (no `spawn_blocking`) and returns the full
/// `Vec<u8>` — expected memory is O(object) for callers that
/// explicitly asked for the whole object as bytes. The test
/// object is kept small (1 MiB) so this stays cheap; the
/// large-object memory bound is the read_stream test above.
#[tokio::test]
async fn read_bytes_drains_streaming_backend() {
    const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB
    const CHUNK_COUNT: usize = 16; // 1 MiB total
    let backend = Arc::new(StreamingBackend {
        capabilities: Capabilities::empty(),
        chunk_size: CHUNK_SIZE,
        chunk_count: CHUNK_COUNT,
    });
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("stream://root/").unwrap(),
            "stream-mock",
            backend,
            caps,
        )
        .open()
        .unwrap();
    let (bytes, info) = lib
        .read_bytes(
            Url::parse("stream://root/small.bin").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(bytes.len(), CHUNK_SIZE * CHUNK_COUNT);
    assert_eq!(info.size, Some((CHUNK_SIZE * CHUNK_COUNT) as u64));
    // Spot-check first/last byte to verify the pattern from the
    // streaming backend was preserved through the drain.
    assert_eq!(bytes[0], 0u8);
    assert_eq!(bytes[CHUNK_SIZE], 1u8);
}

#[tokio::test]
async fn materialize_stream_writes_multi_chunk_file() {
    const CHUNK_SIZE: usize = 4096;
    const CHUNK_COUNT: usize = 3;
    let backend = Arc::new(StreamingBackend {
        capabilities: Capabilities::empty(),
        chunk_size: CHUNK_SIZE,
        chunk_count: CHUNK_COUNT,
    });
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("stream://materialize/").unwrap(),
            "stream-mock",
            backend,
            caps,
        )
        .open()
        .unwrap();
    let local = lib
        .materialize(
            Url::parse("stream://materialize/object.bin").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .unwrap();

    let bytes = std::fs::read(&local.path).unwrap();
    assert_eq!(bytes.len(), CHUNK_SIZE * CHUNK_COUNT);
    assert!(bytes[..CHUNK_SIZE].iter().all(|b| *b == 0));
    assert!(bytes[CHUNK_SIZE..CHUNK_SIZE * 2].iter().all(|b| *b == 1));
    assert!(
        bytes[CHUNK_SIZE * 2..CHUNK_SIZE * 3]
            .iter()
            .all(|b| *b == 2)
    );

    let path = local.path.clone();
    drop(local);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn materialize_stream_cleans_partial_file_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial-error.tmp");
    let stream: ReadStream = Box::pin(futures::stream::iter(vec![
        Ok(bytes::Bytes::from_static(b"partial")),
        Err(Error::new(ErrorCode::Transient, "stream failed")),
    ]));

    let err = crate::dispatch::materialize_stream_to_test_path(stream, None, path.clone())
        .await
        .expect_err("stream error should fail materialize");

    assert_eq!(err.code(), ErrorCode::Transient);
    assert!(!path.exists(), "partial materialize file was not cleaned");
}

#[tokio::test]
async fn materialize_stream_cleans_partial_file_on_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial-cancel.tmp");
    let token = CancellationToken::new();
    let cancel_in_stream = token.clone();
    let stream: ReadStream = Box::pin(futures::stream::once(async move {
        cancel_in_stream.cancel();
        Ok(bytes::Bytes::from_static(b"partial"))
    }));

    let err = crate::dispatch::materialize_stream_to_test_path(stream, Some(token), path.clone())
        .await
        .expect_err("cancel should fail materialize");

    assert_eq!(err.code(), ErrorCode::Cancelled);
    assert!(!path.exists(), "partial materialize file was not cleaned");
}

#[tokio::test]
async fn read_bytes_under_max_bytes_succeeds() {
    let backend = Arc::new(CountingBackend::new(
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ));
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(Url::parse("mock://max/").unwrap(), "mock", backend, caps)
        .open()
        .unwrap();
    let opts = ReadOptions {
        max_bytes: Some(1024),
        ..ReadOptions::default()
    };
    let (bytes, _info) = lib
        .read_bytes(Url::parse("mock://max/object.bin").unwrap(), opts, None)
        .await
        .expect("under cap");
    assert_eq!(bytes, b"data");
}

#[tokio::test]
async fn read_bytes_exceeding_max_bytes_errors_resource_exhausted() {
    let backend = Arc::new(CountingBackend::new(
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ));
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(Url::parse("mock://max/").unwrap(), "mock", backend, caps)
        .open()
        .unwrap();
    let opts = ReadOptions {
        max_bytes: Some(3),
        ..ReadOptions::default()
    };
    let err = lib
        .read_bytes(Url::parse("mock://max/object.bin").unwrap(), opts, None)
        .await
        .expect_err("over cap should fail");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    assert!(err.message().contains("max_bytes"));
    assert!(err.next_action().is_some());
}

#[tokio::test]
async fn read_bytes_no_max_bytes_unbounded_today() {
    const CHUNK_SIZE: usize = 10_000;
    const CHUNK_COUNT: usize = 10;
    let backend = Arc::new(StreamingBackend {
        capabilities: Capabilities::empty(),
        chunk_size: CHUNK_SIZE,
        chunk_count: CHUNK_COUNT,
    });
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("stream://max/").unwrap(),
            "stream-mock",
            backend,
            caps,
        )
        .open()
        .unwrap();
    let (bytes, _info) = lib
        .read_bytes(
            Url::parse("stream://max/big.bin").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("no cap, unbounded read works");
    assert_eq!(bytes.len(), CHUNK_SIZE * CHUNK_COUNT);
}

#[tokio::test]
async fn read_stream_exceeding_max_bytes_errors_resource_exhausted() {
    use futures::StreamExt;

    let backend = Arc::new(StreamingBackend {
        capabilities: Capabilities::empty(),
        chunk_size: 512,
        chunk_count: 4,
    });
    let caps = backend.capabilities().clone();
    let lib = Library::builder()
        .add_route(
            Url::parse("stream://max/").unwrap(),
            "stream-mock",
            backend,
            caps,
        )
        .open()
        .unwrap();
    let opts = ReadOptions {
        max_bytes: Some(1024),
        ..ReadOptions::default()
    };
    let (mut stream, _info) = lib
        .read_stream(Url::parse("stream://max/big.bin").unwrap(), opts, None)
        .await
        .expect("stream opens");

    assert!(stream.next().await.unwrap().is_ok());
    assert!(stream.next().await.unwrap().is_ok());
    let err = stream
        .next()
        .await
        .expect("cap error item")
        .expect_err("third chunk exceeds cap");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    assert!(err.message().contains("max_bytes"));
    assert!(err.next_action().is_some());
}

/// Capability-aware test factory used by the matrix tests below.
/// Captures the capability the host hands to `authenticate`, then
/// emits a transcript that the test asserts against. `None` mode
/// returns `Err(AuthRequired)` immediately (the canonical
/// fail-fast shape); `Headless` and `Browser` emit a single
/// `Progress { mode_label }` followed by `Succeeded`.
struct CapabilityAwareFactory {
    observed: Arc<Mutex<Option<InteractiveAuthCapability>>>,
}

#[async_trait::async_trait]
impl shim::Factory for CapabilityAwareFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "iauth-mock".into(),
            display_name: "IAuth Mock".into(),
            description: None,
            config_schema: vec![ConfigField {
                key: "prefix".into(),
                display_name: "Prefix".into(),
                kind: ConfigFieldKind::Url,
                required: true,
                default: None,
                help: None,
                example: Some("iauth-mock://root/".into()),
                group: None,
                advanced: false,
            }],
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        let prefix = mock_factory_prefix(request)?;
        let backend = Arc::new(RecordingBackend::new());
        let capabilities = backend.capabilities().clone();
        Ok(shim::BackendInstance {
            backend_id: BackendId(format!("iauth-mock:{prefix}")),
            backend,
            address_roots: vec![AddressRoot {
                address: prefix,
                display_name: None,
                backend_kind: "iauth-mock".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request.display_name.clone(),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }

    async fn authenticate(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let _ = &cancel; // test mock: synchronous, no work to interrupt.
        *self.observed.lock().unwrap() = Some(capability);
        match capability {
            InteractiveAuthCapability::None => Err(Error::new(
                ErrorCode::AuthRequired,
                "iauth-mock: None capability — fail fast",
            )),
            InteractiveAuthCapability::Headless => {
                let events: Vec<Result<AuthEvent>> = vec![
                    Ok(AuthEvent::Progress {
                        message: "headless".into(),
                    }),
                    Ok(AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: None,
                    }),
                ];
                Ok(Box::new(events.into_iter()))
            }
            InteractiveAuthCapability::Browser => {
                let events: Vec<Result<AuthEvent>> = vec![
                    Ok(AuthEvent::Progress {
                        message: "browser".into(),
                    }),
                    Ok(AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: None,
                    }),
                ];
                Ok(Box::new(events.into_iter()))
            }
        }
    }
}

fn iauth_mock_request(prefix: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("prefix".into(), ConfigValue::String(prefix.into()));
    ConnectionRequest {
        backend_kind: "iauth-mock".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("iauth-mock connection".into()),
    }
}

#[tokio::test]
async fn library_explicit_browser_capability_threads_through_to_factory() {
    // Ticket #63 replaced the hardcoded `Browser` default with
    // smart-default detection from the host env, so the prior
    // "default == Browser" assertion no longer holds across all
    // hosts (a Linux test runner with no `DISPLAY` resolves to
    // `Headless`). Setting it explicitly via the builder is the
    // canonical "I want Browser" path and is what this test
    // exercises end-to-end.
    let observed = Arc::new(Mutex::new(None));
    let factory = Arc::new(CapabilityAwareFactory {
        observed: observed.clone(),
    });
    let lib = Library::builder()
        .register_backend_factory(factory)
        .interactive_auth_capability(InteractiveAuthCapability::Browser)
        .open()
        .unwrap();
    assert_eq!(
        lib.interactive_auth_capability(),
        InteractiveAuthCapability::Browser,
        "builder-set Browser must win"
    );
    let connection = lib
        .add_connection(iauth_mock_request("iauth-mock://root1/"), None)
        .await
        .unwrap();
    let _ = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    assert_eq!(
        *observed.lock().unwrap(),
        Some(InteractiveAuthCapability::Browser)
    );
}

#[tokio::test]
async fn library_none_capability_emits_no_auth_events_before_error() {
    let observed = Arc::new(Mutex::new(None));
    let factory = Arc::new(CapabilityAwareFactory {
        observed: observed.clone(),
    });
    let lib = Library::builder()
        .register_backend_factory(factory)
        .interactive_auth_capability(InteractiveAuthCapability::None)
        .open()
        .unwrap();
    let connection = lib
        .add_connection(iauth_mock_request("iauth-mock://root2/"), None)
        .await
        .unwrap();
    // None mode: the factory returns Err synchronously — there is
    // no AuthEventStream and so no AuthEvents to count. The plugin
    // observed the capability before the error.
    let result = lib.authenticate_connection(&connection.id, None).await;
    let err = match result {
        Ok(_) => panic!("None capability must surface AuthRequired"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(
        *observed.lock().unwrap(),
        Some(InteractiveAuthCapability::None)
    );
}

#[tokio::test]
async fn library_headless_capability_threads_through_to_factory() {
    let observed = Arc::new(Mutex::new(None));
    let factory = Arc::new(CapabilityAwareFactory {
        observed: observed.clone(),
    });
    let lib = Library::builder()
        .register_backend_factory(factory)
        .interactive_auth_capability(InteractiveAuthCapability::Headless)
        .open()
        .unwrap();
    let connection = lib
        .add_connection(iauth_mock_request("iauth-mock://root3/"), None)
        .await
        .unwrap();
    let mut stream = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    // Expect Progress("headless") then Succeeded.
    let first = stream.next().expect("first event").unwrap();
    match first {
        AuthEvent::Progress { message } => assert_eq!(message, "headless"),
        other => panic!("expected Progress(headless), got {other:?}"),
    }
    let second = stream.next().expect("second event").unwrap();
    assert!(matches!(second, AuthEvent::Succeeded { .. }));
    assert_eq!(
        *observed.lock().unwrap(),
        Some(InteractiveAuthCapability::Headless)
    );
}

/// Render-worker scenario: coordinator drives `Browser`, worker
/// hits a cache miss with `None` and gets `AuthRequired`
/// immediately. Two independent `Library` instances stand in for
/// coordinator + worker; the same `iauth-mock` factory class is
/// registered on both.
#[tokio::test]
async fn render_worker_scenario_none_worker_fails_fast_browser_coordinator_succeeds() {
    let coord_observed = Arc::new(Mutex::new(None));
    let coord = Library::builder()
        .register_backend_factory(Arc::new(CapabilityAwareFactory {
            observed: coord_observed.clone(),
        }))
        .interactive_auth_capability(InteractiveAuthCapability::Browser)
        .open()
        .unwrap();
    let worker_observed = Arc::new(Mutex::new(None));
    let worker = Library::builder()
        .register_backend_factory(Arc::new(CapabilityAwareFactory {
            observed: worker_observed.clone(),
        }))
        .interactive_auth_capability(InteractiveAuthCapability::None)
        .open()
        .unwrap();

    let coord_conn = coord
        .add_connection(iauth_mock_request("iauth-mock://render/"), None)
        .await
        .unwrap();
    let worker_conn = worker
        .add_connection(iauth_mock_request("iauth-mock://render/"), None)
        .await
        .unwrap();

    // Coordinator: two events.
    let mut coord_stream = coord
        .authenticate_connection(&coord_conn.id, None)
        .await
        .unwrap();
    assert!(matches!(
        coord_stream.next().unwrap().unwrap(),
        AuthEvent::Progress { .. }
    ));
    assert!(matches!(
        coord_stream.next().unwrap().unwrap(),
        AuthEvent::Succeeded { .. }
    ));

    // Worker: AuthRequired without any AuthEvents on the wire.
    let worker_result = worker.authenticate_connection(&worker_conn.id, None).await;
    let err = match worker_result {
        Ok(_) => panic!("None capability must surface AuthRequired"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(
        *worker_observed.lock().unwrap(),
        Some(InteractiveAuthCapability::None)
    );
}

/// Mirrors the services-client / broker warm-continue shape:
/// `instantiate` parks the connection in `AwaitingAuth`, then
/// `authenticate` does its own token install and yields
/// `Succeeded { credentials: None }`. The host must still flip
/// the connection slot to `Authenticated`; otherwise the next
/// dispatch triggers `bring_up_or_fail` and re-instantiates a
/// stub.
struct WarmContinueFactory {
    address: Url,
}

#[async_trait::async_trait]
impl shim::Factory for WarmContinueFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "warm-continue-mock".into(),
            display_name: "Warm Continue Mock".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        _cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let backend = Arc::new(RecordingBackend::new());
        let capabilities = backend.capabilities().clone();
        Ok(shim::BackendInstance {
            backend_id: BackendId("warm-continue-mock".into()),
            backend,
            address_roots: vec![AddressRoot {
                address: self.address.clone(),
                display_name: None,
                backend_kind: "warm-continue-mock".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: Some("warm-continue-mock".into()),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
        })
    }

    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let events: Vec<Result<AuthEvent>> = vec![Ok(AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: None,
        })];
        Ok(Box::new(events.into_iter()))
    }
}

#[tokio::test]
async fn authenticate_connection_marks_slot_authenticated_on_credentials_none() {
    let address = Url::parse("warm-continue-mock://root/").unwrap();
    let factory = Arc::new(WarmContinueFactory {
        address: address.clone(),
    });
    let lib = Library::builder()
        .register_backend_factory(factory)
        .interactive_auth_capability(InteractiveAuthCapability::Headless)
        .open()
        .unwrap();
    let request = ConnectionRequest {
        backend_kind: "warm-continue-mock".into(),
        config: HashMap::new(),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let connection = lib.add_connection(request, None).await.unwrap();
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "instantiate should park the connection in AwaitingAuth",
    );

    let stream = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    for event in stream {
        let _ = event.unwrap();
    }

    let after = lib
        .list_connections()
        .unwrap()
        .into_iter()
        .find(|c| c.id == connection.id)
        .expect("connection survives authenticate");
    assert!(
        matches!(after.auth_state, ConnectionAuthState::Authenticated { .. }),
        "Succeeded {{ credentials: None }} must flip slot to Authenticated, got {:?}",
        after.auth_state,
    );
}

/// Cover the interactive-auth-capability precedence chain end-to-
/// end against the public `auth::capability` API. The actual
/// `LibraryBuilder`
/// resolution path glues the same primitives together with
/// `StdEnv` reads, so verifying the pieces here keeps the
/// builder-side wiring trivial.
mod capability_precedence {
    use super::*;
    use crate::auth::{
        EnvSource, INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, MockEnv, detect_default_capability,
        parse_capability_str, read_env_capability,
    };

    /// Mirror of the precedence used inside `LibraryBuilder::open`,
    /// but parameterised on `EnvSource` so tests don't reach into
    /// real process env.
    fn resolve(
        builder: Option<InteractiveAuthCapability>,
        config: Option<InteractiveAuthCapability>,
        env: &impl EnvSource,
    ) -> InteractiveAuthCapability {
        builder
            .or_else(|| read_env_capability(env))
            .or(config)
            .unwrap_or_else(|| detect_default_capability(env))
    }

    #[test]
    fn builder_set_wins_over_env_and_config() {
        let env = MockEnv::new()
            .with(INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, "headless")
            .with("CI", "true"); // smart default would be None
        let resolved = resolve(
            Some(InteractiveAuthCapability::Browser),
            Some(InteractiveAuthCapability::None),
            &env,
        );
        assert_eq!(resolved, InteractiveAuthCapability::Browser);
    }

    #[test]
    fn env_wins_over_config_and_default() {
        let env = MockEnv::new()
            .with(INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, "headless")
            .with("CI", "true");
        let resolved = resolve(None, Some(InteractiveAuthCapability::Browser), &env);
        assert_eq!(resolved, InteractiveAuthCapability::Headless);
    }

    #[test]
    fn config_wins_over_smart_default() {
        // No builder, no env, but CI=true (smart default = None).
        // Config carries Headless and must win.
        let env = MockEnv::new().with("CI", "true");
        let resolved = resolve(None, Some(InteractiveAuthCapability::Headless), &env);
        assert_eq!(resolved, InteractiveAuthCapability::Headless);
    }

    #[test]
    fn smart_default_used_when_nothing_else_set_ci_runner() {
        let env = MockEnv::new().with("CI", "true");
        let resolved = resolve(None, None, &env);
        assert_eq!(
            resolved,
            InteractiveAuthCapability::None,
            "render-worker / CI runner must default to None (fail-fast)"
        );
    }

    #[test]
    fn invalid_env_falls_through_to_config() {
        // Env var typo → warn + fall through; config provides
        // Headless; smart default would be None (CI=true).
        let env = MockEnv::new()
            .with(INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, "broswer") // typo
            .with("CI", "true");
        let resolved = resolve(None, Some(InteractiveAuthCapability::Headless), &env);
        assert_eq!(resolved, InteractiveAuthCapability::Headless);
    }

    #[test]
    fn invalid_env_no_config_falls_through_to_smart_default() {
        let env = MockEnv::new()
            .with(INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, "yolo")
            .with("CI", "1");
        assert_eq!(resolve(None, None, &env), InteractiveAuthCapability::None);
    }

    #[test]
    fn parse_capability_round_trips_canonical_forms() {
        // Belt-and-suspenders against the auth::capability test
        // module: assert the module-level re-exports are wired.
        assert_eq!(
            parse_capability_str("browser"),
            Some(InteractiveAuthCapability::Browser)
        );
        assert_eq!(
            parse_capability_str("none"),
            Some(InteractiveAuthCapability::None)
        );
    }
}

/// End-to-end smoke test for `interactive_auth_capability` on the builder:
/// the value flows through `Library::open()` and out via
/// `Library::interactive_auth_capability()`, then into per-call factory
/// `authenticate` invocations. Skips the assertion under leaked env (CI
/// matrix may set the var) — the `capability_precedence` unit tests cover
/// the deterministic resolution-order behaviour with `MockEnv`.
#[tokio::test]
async fn library_capability_threads_through_to_factory() {
    if std::env::var(crate::auth::INTERACTIVE_AUTH_CAPABILITY_ENV_VAR).is_ok() {
        // Env-var leakage would override the builder value.
        return;
    }
    let observed = Arc::new(Mutex::new(None));
    let factory = Arc::new(CapabilityAwareFactory {
        observed: observed.clone(),
    });
    let lib = Library::builder()
        .register_backend_factory(factory)
        .interactive_auth_capability(InteractiveAuthCapability::Headless)
        .open()
        .unwrap();
    assert_eq!(
        lib.interactive_auth_capability(),
        InteractiveAuthCapability::Headless,
        "builder-set capability must win when no env override"
    );
    let connection = lib
        .add_connection(iauth_mock_request("iauth-mock://config/"), None)
        .await
        .unwrap();
    let mut stream = lib
        .authenticate_connection(&connection.id, None)
        .await
        .unwrap();
    // The Headless arm of CapabilityAwareFactory emits a
    // `Progress { message: "headless" }` first event.
    let event = stream.next().expect("first event").unwrap();
    match event {
        AuthEvent::Progress { message } => assert_eq!(message, "headless"),
        other => panic!("expected Progress(headless), got {other:?}"),
    }
    assert_eq!(
        *observed.lock().unwrap(),
        Some(InteractiveAuthCapability::Headless)
    );
}

// ----- Ticket #64: external token injection ------------------------

#[tokio::test]
async fn library_set_credential_populates_cache_without_provider_chain() {
    let lib = Library::builder().open().unwrap();
    let backend = BackendId("portal-backed".into());
    let principal = auth::PrincipalView::new("brian");
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "access_token".into(),
        SecretValue::Bytes(SecretBytes(b"injected-bearer".to_vec())),
    );
    let credential = auth::ResolvedCredential {
        bytes: bundle,
        expires_at: None,
        source_name: "portal".into(),
    };
    lib.set_credential(backend.clone(), principal.clone(), credential.clone())
        .await
        .unwrap();
    // resolve_credentials must hit the cache (no provider chain
    // configured) and return our injected bytes.
    let got = lib.resolve_credentials(&backend, &principal).await.unwrap();
    assert_eq!(got.source_name, "portal");
    assert!(got.bytes.fields.contains_key("access_token"));
}

#[tokio::test]
async fn callback_credential_provider_resolves_on_cache_miss() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let calls = Arc::new(AtomicU32::new(0));
    let lib = {
        let calls = calls.clone();
        Library::builder()
            .interactive_auth_capability(InteractiveAuthCapability::None)
            .with_credential_callback("portal-fetch", move |_backend, _principal| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let mut bundle = SecretBundle::default();
                    bundle.fields.insert(
                        "access_token".into(),
                        SecretValue::Bytes(SecretBytes(b"fresh".to_vec())),
                    );
                    Ok(auth::ResolvedCredential {
                        bytes: bundle,
                        expires_at: None,
                        source_name: "portal-fetch".into(),
                    })
                }
            })
            .open()
            .unwrap()
    };
    let backend = BackendId("ephemeral-vm".into());
    let principal = auth::PrincipalView::new("brian");

    // Cold start: capability=None must NOT block the callback path.
    // The callback populates the cache; subsequent resolve hits L1.
    let got = lib.resolve_credentials(&backend, &principal).await.unwrap();
    assert_eq!(got.source_name, "portal-fetch");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Second resolve hits the cache; callback NOT invoked again.
    let _ = lib.resolve_credentials(&backend, &principal).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // After invalidate, a re-resolve fires the callback once more.
    lib.invalidate_credentials(&backend, &principal);
    let _ = lib.resolve_credentials(&backend, &principal).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn with_credential_cache_durability_in_memory_only_skips_persistence() {
    // Build a stub persistence that records every store; constructing
    // a Library with InMemoryOnly + persistence wired must NOT
    // commit a set_credential to the persistence layer.
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct CountingPersistence {
        stores: AtomicU32,
    }

    impl auth::CredentialPersistence for CountingPersistence {
        fn load(
            &self,
            _backend: &BackendId,
            _principal: &auth::PrincipalView,
        ) -> std::result::Result<Option<auth::PersistedEntry>, auth::CredentialError> {
            Ok(None)
        }
        fn store(
            &self,
            _backend: &BackendId,
            _principal: &auth::PrincipalView,
            _entry: &auth::PersistedEntry,
        ) -> std::result::Result<(), auth::CredentialError> {
            self.stores.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn delete(
            &self,
            _backend: &BackendId,
            _principal: &auth::PrincipalView,
        ) -> std::result::Result<(), auth::CredentialError> {
            Ok(())
        }
        fn max_cred_epoch(&self) -> std::result::Result<u64, auth::CredentialError> {
            Ok(0)
        }
    }

    let counter: Arc<CountingPersistence> = Arc::new(CountingPersistence::default());
    let mut builder = Library::builder()
        .with_credential_cache_durability(auth::CredentialCacheDurability::InMemoryOnly);
    builder.credential_persistence = Some(counter.clone() as Arc<dyn auth::CredentialPersistence>);
    let lib = builder.open().unwrap();

    let backend = BackendId("ephemeral".into());
    let principal = auth::PrincipalView::new("p");
    let credential = auth::ResolvedCredential {
        bytes: SecretBundle::default(),
        expires_at: None,
        source_name: "x".into(),
    };
    lib.set_credential(backend, principal, credential)
        .await
        .unwrap();
    // InMemoryOnly drops the persistence on the floor — store
    // must not have been called.
    assert_eq!(counter.stores.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn materialize_lease_pins_path_through_concurrent_eviction_pressure() {
    use ovstorage_cache::CacheOptions;

    struct AddressKeyedBackend {
        capabilities: Capabilities,
    }

    impl AddressKeyedBackend {
        fn capabilities(&self) -> &Capabilities {
            &self.capabilities
        }
    }

    #[async_trait::async_trait]
    impl shim::Backend for AddressKeyedBackend {
        async fn stat(
            &self,
            target: ResolvedTarget,
            _opts: StatOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(ObjectInfo {
                address: target.resolved_address,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            })
        }

        async fn read(
            &self,
            target: ResolvedTarget,
            _opts: ReadOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<ReadResult> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            let last = target.resolved_address.host_str().unwrap_or("").to_string();
            let bytes = format!("data-{last}").into_bytes();
            let info = ObjectInfo {
                address: target.resolved_address,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(bytes.len() as u64),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            };
            Ok(ReadResult::Bytes { bytes, info })
        }

        async fn write(
            &self,
            target: ResolvedTarget,
            _bytes: Vec<u8>,
            _opts: WriteOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<WriteResult> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(WriteResult {
                info: ObjectInfo {
                    address: target.resolved_address,
                    kind: ObjectKind::File,
                    etag: None,
                    version: None,
                    size: None,
                    mtime: None,
                    checksums: ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: None,
                    user_metadata: None,
                    modified_by: None,
                },
            })
        }

        async fn delete(
            &self,
            _target: ResolvedTarget,
            _opts: DeleteOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<()> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(())
        }

        async fn list(
            &self,
            _prefix: ResolvedTarget,
            _opts: ListOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<Vec<ObjectInfo>> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(Vec::new())
        }

        async fn create_directory(
            &self,
            _target: ResolvedTarget,
            _opts: CreateDirectoryOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<BackendItemInfo> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(BackendItemInfo::default())
        }

        async fn delete_directory(
            &self,
            _target: ResolvedTarget,
            _opts: DeleteDirectoryOptions,
            cancel: Option<CancellationToken>,
        ) -> Result<()> {
            let _ = &cancel; // test mock: synchronous, no work to interrupt.
            Ok(())
        }
    }

    let cache_root = unique_temp_path("lease-pin");
    let cache = Cache::open_with_options(
        CacheConfig {
            state_root: cache_root.join("state"),
            cache_root: cache_root.join("bytes"),
        },
        CacheOptions {
            max_bytes: Some(16),
            ..CacheOptions::default()
        },
    )
    .unwrap();
    let lib = Library::builder()
        .with_cache(cache)
        .add_route(
            Url::parse("mock://").unwrap(),
            "mock",
            Arc::new(AddressKeyedBackend {
                capabilities: Capabilities::empty(),
            }),
            AddressKeyedBackend {
                capabilities: Capabilities::empty(),
            }
            .capabilities()
            .clone(),
        )
        .open()
        .unwrap();

    let target = Url::parse("mock://obj-a").unwrap();
    let local = lib
        .materialize(target.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    let pinned_path = local.path.clone();
    assert_eq!(std::fs::read(&pinned_path).unwrap(), b"data-obj-a");

    for label in ["obj-b", "obj-c", "obj-d", "obj-e", "obj-f"] {
        let url = Url::parse(&format!("mock://{label}")).unwrap();
        lib.materialize(url, ReadOptions::default(), None)
            .await
            .unwrap();
    }

    assert!(
        pinned_path.exists(),
        "lease guard must keep CAS file alive through eviction pressure",
    );
    assert_eq!(std::fs::read(&pinned_path).unwrap(), b"data-obj-a");

    drop(local);
    drop(lib);
    std::fs::remove_dir_all(cache_root).unwrap();
}

#[tokio::test]
async fn load_config_round_trip() {
    // Single test covers both no-file and with-file paths. Plugin SPI host
    // callbacks are set-once-per-process, so each unit test can build at
    // most one Library; combining the cases here avoids substrate conflict.
    // `init_auth_substrate(None)` accepts whatever substrate is already
    // registered by a previous test in this binary.
    init_auth_substrate(None).unwrap();
    let lib = Library::builder()
        .register_backend_factory(Arc::new(MockFactory))
        .open()
        .unwrap();

    // Case 1: explicit path to a non-existent file → typed error.
    let missing = lib
        .load_config(Some(std::path::Path::new("/nonexistent/ovstorage.toml")))
        .await;
    assert!(missing.is_err());

    // Case 2: explicit path to a real file with one connection → registers it.
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("ovstorage.toml");
    std::fs::write(
        &cfg_path,
        "[[connections]]\nbackend_kind = \"mock\"\ndisplay_name = \"test-mock\"\n\
         [connections.config]\nprefix = \"mock://root/\"\n",
    )
    .unwrap();
    let registered = lib.load_config(Some(&cfg_path)).await.unwrap();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].current_addresses[0].as_str(), "mock://root/");
    assert_eq!(lib.list_connections().unwrap().len(), 1);

    // Case 3: None with no file at the default search path → empty result.
    // Point XDG_CONFIG_HOME at an empty dir and cwd at it so neither
    // `./ovstorage.toml` nor `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`
    // exists.
    let empty = tempfile::tempdir().unwrap();
    let _xdg = EnvGuard::set("XDG_CONFIG_HOME", empty.path());
    let _cwd = CwdGuard::change_to(empty.path());
    let none = lib.load_config(None).await.unwrap();
    assert!(none.is_empty());
}

struct EnvGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::path::Path>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: tests run single-threaded by default; setter mirrors prior pattern in this file.
        unsafe { std::env::set_var(key, value.as_ref()) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            // SAFETY: see EnvGuard::set.
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

struct CwdGuard {
    previous: std::path::PathBuf,
}

impl CwdGuard {
    fn change_to(path: impl AsRef<std::path::Path>) -> Self {
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(path.as_ref()).unwrap();
        Self { previous }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.previous);
    }
}
