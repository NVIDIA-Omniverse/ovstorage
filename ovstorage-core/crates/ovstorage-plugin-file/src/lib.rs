// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
#[cfg(windows)]
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use ovstorage_plugin::address;
use ovstorage_plugin::shim;
use ovstorage_plugin::*;
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendItemInfo, ReadResult, WriteStep, race_cancel,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Internal identity record for change detection and precondition
/// checks. The SPI carries only `etag: Option<String>`; this struct
/// captures the fields the file plugin needs and synthesizes the SPI
/// etag at the ObjectInfo / BackendChangeEvent boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FileIdentity {
    etag: Option<String>,
    version: Option<String>,
    size: Option<u64>,
    mtime: Option<SystemTime>,
}

impl FileIdentity {
    fn synthesize_etag(&self) -> Option<String> {
        if let Some(e) = &self.etag {
            return Some(e.clone());
        }
        match (self.size, self.mtime) {
            (Some(size), Some(mtime)) => {
                let ms = mtime
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                Some(format!("size:{size},mtime:{ms}"))
            }
            _ => self.etag.clone(),
        }
    }
}

pub struct FileBackend {
    root: Option<PathBuf>,
    target_locks: std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>,
}

impl FileBackend {
    pub fn capabilities() -> Capabilities {
        let mut capabilities = Capabilities::empty();
        capabilities.supports_if_match_write = true;
        capabilities.supports_no_overwrite_write = true;
        capabilities.supports_native_metadata_patch = true;
        capabilities.writes_are_atomic = true;
        capabilities.supports_server_side_copy = true;
        capabilities.supports_server_side_rename = true;
        capabilities.supports_atomic_rename = true;
        capabilities.has_real_directories = true;
        capabilities.supports_write = true;
        capabilities.supports_write_stream = true;
        capabilities.supports_delete = true;
        capabilities.supports_list = true;
        capabilities.supports_recursive_list = true;
        capabilities.populates_subdirectory_metadata = true;
        capabilities.supports_create_directory = true;
        capabilities.supports_delete_directory = true;
        capabilities.populates_effective_permissions_on_stat = true;
        capabilities.supports_access_check = true;
        capabilities
    }

    pub fn new() -> Self {
        Self {
            root: None,
            target_locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Some(root.into()),
            ..Self::new()
        }
    }

    fn target_lock(&self, path: &Path) -> Arc<Mutex<()>> {
        let mut map = self.target_locks.lock().expect("target_locks poisoned");
        map.entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn path_from_address(&self, address: &Url) -> Result<PathBuf> {
        let path = path_from_file_address(address)?;
        if let Some(root) = self.canonical_root()? {
            ensure_path_within_root(&path, &root)?;
        }
        Ok(path)
    }

    fn canonical_root(&self) -> Result<Option<PathBuf>> {
        self.root
            .as_deref()
            .map(canonicalize_scope_root)
            .transpose()
    }
}

impl Default for FileBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct FileBackendFactory;

#[async_trait::async_trait]
impl shim::Factory for FileBackendFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "file".into(),
            display_name: "Local filesystem".into(),
            description: Some("Reads and writes file: addresses on the local host".into()),
            config_schema: vec![
                ConfigField {
                    key: "root".into(),
                    display_name: "Root".into(),
                    kind: ConfigFieldKind::Path,
                    required: true,
                    default: None,
                    help: Some("Filesystem directory this connection may serve".into()),
                    example: None,
                    group: None,
                    advanced: false,
                },
                ConfigField {
                    key: "prefix".into(),
                    display_name: "Address prefix".into(),
                    kind: ConfigFieldKind::Url,
                    required: false,
                    default: None,
                    help: Some(
                        "Optional caller-facing route prefix; defaults to file:<root>/".into(),
                    ),
                    example: Some("file:/data/assets/".into()),
                    group: None,
                    advanced: true,
                },
            ],
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "instantiate"))]
    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // synchronous in-memory construction; no async work to interrupt.
        let root = config_path(&request.config, "root")?;
        let prefix = connection_prefix(&request.config, &root)?;
        let backend = Arc::new(FileBackend::with_root(root));
        Ok(shim::BackendInstance {
            backend_id: BackendId(format!("file:{prefix}")),
            backend,
            address_roots: vec![AddressRoot {
                address: prefix,
                display_name: None,
                backend_kind: "file".into(),
                connection_id: None,
                capabilities: FileBackend::capabilities(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request.display_name.clone().or_else(|| Some("file".into())),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

enum WriteFill {
    Bytes(Vec<u8>),
    Stream(BodyStream),
}

impl FileBackend {
    /// Write via temp-sibling + fsync + rename so observers never see a partial file.
    ///
    /// `writes_are_atomic` covers object bytes only; the user-metadata sidecar
    /// publishes after the bytes commit and a failure between the two surfaces
    /// as `Transient` so the host re-issues the whole operation.
    ///
    /// In-process if-match / no-overwrite races are closed by a per-destination
    /// async mutex held across the precondition check and the rename. Cross-
    /// process races on the same filesystem still need `renameat2(RENAME_NOREPLACE)`,
    /// not implemented here.
    async fn write_atomic(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        fill: WriteFill,
    ) -> Result<WriteResult> {
        let path = self.path_from_address(&target.resolved_address)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
        }
        let tmp = create_new_temp_sibling(&path).await?;
        let guard = TempFileGuard::arm(tmp.clone());
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&tmp)
                .await
                .map_err(map_io)?;
            match fill {
                WriteFill::Bytes(bytes) => {
                    file.write_all(&bytes).await.map_err(map_io)?;
                }
                WriteFill::Stream(stream) => {
                    for chunk in stream {
                        file.write_all(&chunk?).await.map_err(map_io)?;
                    }
                }
            }
            file.sync_all().await.map_err(map_io)?;
        }
        let user_metadata = opts.user_metadata.unwrap_or_default();
        let staged_sidecar = stage_user_metadata(&path, &user_metadata).await?;
        let lock = self.target_lock(&path);
        let _guard_lock = lock.lock().await;
        let exists = tokio::fs::try_exists(&path).await.map_err(map_io)?;
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => {
                if exists {
                    return Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "if_dest=Fail: write target already exists",
                    ));
                }
            }
            IfDestExists::MatchEtag(expected) => {
                if exists {
                    let meta = tokio::fs::metadata(&path).await.map_err(map_io)?;
                    let current = identity_from_metadata(&meta)?;
                    check_etag_write(Some(expected), &current)?;
                } else {
                    return Err(Error::new(ErrorCode::NotFound, "file does not exist"));
                }
            }
        }
        tokio::fs::rename(&tmp, &path).await.map_err(map_io)?;
        guard.commit();
        sync_parent(&path).await?;
        publish_staged_user_metadata(&path, staged_sidecar).await?;
        let info = info_for_path(target.resolved_address, &path, true).await?;
        Ok(WriteResult { info })
    }
}

/// Best-effort drop guard that unlinks the temp file when a write fails;
/// uses sync `std::fs::remove_file` because Drop is sync.
struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    fn arm(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn commit(mut self) {
        self.path.take();
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

async fn create_new_temp_sibling(path: &Path) -> Result<PathBuf> {
    let mut last_err: Option<io::Error> = None;
    for _ in 0..16 {
        let candidate = temp_sibling(path);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                last_err = Some(err);
                continue;
            }
            Err(err) => return Err(map_io(err)),
        }
    }
    Err(map_io(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temp sibling",
        )
    })))
}

enum StagedSidecar {
    Remove,
    Rename {
        tmp: PathBuf,
        final_path: PathBuf,
        guard: TempFileGuard,
    },
}

async fn stage_user_metadata(path: &Path, metadata: &UserMetadata) -> Result<StagedSidecar> {
    let final_path = metadata_path(path)?;
    if metadata.is_empty() {
        return Ok(StagedSidecar::Remove);
    }
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
    }
    let tmp = sidecar_temp(&final_path);
    let mut lines = String::new();
    let mut pairs: Vec<_> = metadata.iter().collect();
    pairs.sort_by_key(|(left, _)| *left);
    for (key, value) in pairs {
        lines.push_str(&hex_encode(key.as_bytes()));
        lines.push('=');
        lines.push_str(&hex_encode(value.as_bytes()));
        lines.push('\n');
    }
    tokio::fs::write(&tmp, lines).await.map_err(map_io)?;
    let guard = TempFileGuard::arm(tmp.clone());
    Ok(StagedSidecar::Rename {
        tmp,
        final_path,
        guard,
    })
}

async fn publish_staged_user_metadata(path: &Path, staged: StagedSidecar) -> Result<()> {
    match staged {
        StagedSidecar::Remove => {
            let final_path = metadata_path(path)?;
            if metadata_exists(&final_path).await {
                tokio::fs::remove_file(final_path).await.map_err(map_io)?;
            }
            Ok(())
        }
        StagedSidecar::Rename {
            tmp,
            final_path,
            guard,
        } => match tokio::fs::rename(&tmp, &final_path).await {
            Ok(()) => {
                guard.commit();
                Ok(())
            }
            Err(err) => Err(Error::new(
                ErrorCode::Transient,
                format!(
                    "user metadata sidecar publish failed after bytes commit: {err}; \
                     re-issuing the write will recover"
                ),
            )),
        },
    }
}

fn sidecar_temp(final_path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| "sidecar".into());
    final_path.with_file_name(format!("{name}.{stamp}.{pid}.{counter}.tmp"))
}

#[async_trait::async_trait]
impl shim::Backend for FileBackend {
    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "stat"))]
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            info_for_path(target.resolved_address, &path, opts.full_metadata).await
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "read"))]
    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            let meta = tokio::fs::metadata(&path).await.map_err(map_io)?;
            reject_special_file(&meta)?;
            let identity = identity_from_metadata(&meta)?;
            check_etag(opts.if_match.as_deref(), &identity)?;
            let modified_by = modified_by_for_path(&path, &meta);
            let kind = if meta.is_dir() {
                ObjectKind::Directory
            } else {
                ObjectKind::File
            };
            let info = ObjectInfo {
                address: target.resolved_address,
                kind,
                etag: identity.synthesize_etag(),
                version: identity.version,
                size: object_size(kind, identity.size),
                mtime: identity.mtime,
                checksums: ChecksumSet::default(),
                effective_permissions: Some(effective_permissions_from_metadata(&meta)),
                system_metadata: Some(SystemMetadata::new()),
                user_metadata: Some(read_user_metadata(&path).await?),
                modified_by,
            };
            if let Some(range) = opts.range {
                let stream = open_ranged_stream(&path, meta.len(), range).await?;
                return Ok(ReadResult::Stream { stream, info });
            }
            Ok(ReadResult::LocalDelegate(LocalDelegate {
                path,
                info,
                guard: None,
            }))
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "write"))]
    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        race_cancel(
            cancel.as_ref(),
            self.write_atomic(target, opts, WriteFill::Bytes(bytes)),
        )
        .await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "write_stream")
    )]
    async fn write_stream(
        &self,
        target: ResolvedTarget,
        stream: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        race_cancel(
            cancel.as_ref(),
            self.write_atomic(target, opts, WriteFill::Stream(stream)),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "delete"))]
    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            if let Some(expected) = opts.if_match.as_deref() {
                match tokio::fs::metadata(&path).await {
                    Ok(meta) => {
                        let current = identity_from_metadata(&meta)?;
                        check_etag_write(Some(expected), &current)?;
                    }
                    // delete is idempotent: precondition on a missing target is satisfied vacuously.
                    Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Err(err) => return Err(map_io(err)),
                }
            }
            // delete is idempotent: a missing target is success.
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(map_io(err)),
            }
            remove_metadata_file(&path).await?;
            Ok(())
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "list"))]
    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let root = self.path_from_address(&prefix.resolved_address)?;
        let jail_root = self.canonical_root()?;
        race_cancel(cancel.as_ref(), async move {
            let mut out = Vec::new();
            let base_address = address::to_directory(&prefix.resolved_address)?;
            if opts.recursive {
                collect_recursive(
                    &root,
                    &root,
                    &base_address,
                    opts.full_metadata,
                    jail_root.as_deref(),
                    &mut out,
                )
                .await?;
            } else {
                let mut entries = tokio::fs::read_dir(&root).await.map_err(map_io)?;
                while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
                    let path = entry.path();
                    if is_internal_entry(&path) {
                        continue;
                    }
                    if let Some(jail_root) = jail_root.as_deref() {
                        ensure_path_within_root(&path, jail_root)?;
                    }
                    let name = entry.file_name().to_string_lossy().replace('\\', "/");
                    let metadata = entry.metadata().await.map_err(map_io)?;
                    let relative_key = if metadata.is_dir() {
                        format!("{name}/")
                    } else {
                        name
                    };
                    let address = address::join_relative(&base_address, &relative_key)?;
                    out.push(info_for_path(address, &path, opts.full_metadata).await?);
                }
            }
            out.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
            Ok(out)
        })
        .await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "watch_directory")
    )]
    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let root = self.path_from_address(&prefix.resolved_address)?;
        let base_address = address::to_directory(&prefix.resolved_address)?;
        let jail_root = self.canonical_root()?;
        // Initial snapshot is sync (sync-Iterator stream); run on the blocking pool.
        let cancel_for_stream = cancel.clone();
        let stream = tokio::task::spawn_blocking(move || {
            FileChangeStream::new(root, base_address, jail_root, opts, cancel_for_stream)
        })
        .await
        .map_err(|join_err| {
            Error::new(
                ErrorCode::Internal,
                format!("watch_directory initial scan task: {join_err}"),
            )
        })??;
        Ok(Box::new(stream))
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "create_directory")
    )]
    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            tokio::fs::create_dir_all(&path).await.map_err(map_io)?;
            item_info_for_path(&path, true).await
        })
        .await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "delete_directory")
    )]
    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            let mut entries = match tokio::fs::read_dir(&path).await {
                Ok(entries) => entries,
                // delete_directory is idempotent: a missing target is success.
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(map_io(err)),
            };
            let mut has_user_entries = false;
            while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
                if !is_internal_entry(&entry.path()) {
                    has_user_entries = true;
                    break;
                }
            }
            if has_user_entries {
                return Err(Error::new(
                    ErrorCode::DirectoryNotEmpty,
                    "directory is not empty",
                ));
            }
            remove_directory_metadata_dir(&path).await?;
            match tokio::fs::remove_dir(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(map_io(err)),
            }
            remove_metadata_file(&path).await?;
            Ok(())
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "copy"))]
    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let src_path = self.path_from_address(&src.resolved_address)?;
        let dest_path = self.path_from_address(&dest.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            let src_meta = tokio::fs::metadata(&src_path).await.map_err(map_io)?;
            reject_special_file(&src_meta)?;
            if let Some(expected) = opts.if_source.as_deref() {
                let current = identity_from_metadata(&src_meta)?;
                check_etag_write(Some(expected), &current)?;
            }
            let dest_lock = self.target_lock(&dest_path);
            let _dest_guard = dest_lock.lock().await;
            let dest_exists = tokio::fs::try_exists(&dest_path).await.map_err(map_io)?;
            match &opts.if_dest {
                IfDestExists::Overwrite => {}
                IfDestExists::Fail => {
                    if dest_exists {
                        return Err(Error::new(
                            ErrorCode::AlreadyExists,
                            "if_dest=Fail: copy destination already exists",
                        ));
                    }
                }
                IfDestExists::MatchEtag(expected) => {
                    if !dest_exists {
                        return Err(Error::new(
                            ErrorCode::NotFound,
                            "if_dest=MatchEtag: destination does not exist",
                        ));
                    }
                    let meta = tokio::fs::metadata(&dest_path).await.map_err(map_io)?;
                    let current = identity_from_metadata(&meta)?;
                    check_etag_write(Some(expected), &current)?;
                }
            }
            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
            }
            tokio::fs::copy(&src_path, &dest_path)
                .await
                .map_err(map_io)?;
            copy_metadata_file(&src_path, &dest_path).await?;
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                let mut metadata = read_user_metadata(&dest_path).await?;
                metadata.insert("x-ov-message".to_string(), message.to_string());
                write_user_metadata(&dest_path, &metadata).await?;
            }
            let info = info_for_path(dest.resolved_address, &dest_path, true).await?;
            Ok(WriteStep::Done(WriteResult { info }))
        })
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "file", op = "rename"))]
    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let src_path = self.path_from_address(&src.resolved_address)?;
        let dest_path = self.path_from_address(&dest.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            if let Some(expected) = opts.if_source.as_deref() {
                let meta = tokio::fs::metadata(&src_path).await.map_err(map_io)?;
                let current = identity_from_metadata(&meta)?;
                check_etag_write(Some(expected), &current)?;
            }
            let dest_lock = self.target_lock(&dest_path);
            let _dest_guard = dest_lock.lock().await;
            let dest_exists = tokio::fs::try_exists(&dest_path).await.map_err(map_io)?;
            match &opts.if_dest {
                IfDestExists::Overwrite => {}
                IfDestExists::Fail => {
                    if dest_exists {
                        return Err(Error::new(
                            ErrorCode::AlreadyExists,
                            "if_dest=Fail: rename destination already exists",
                        ));
                    }
                }
                IfDestExists::MatchEtag(expected) => {
                    if !dest_exists {
                        return Err(Error::new(
                            ErrorCode::NotFound,
                            "if_dest=MatchEtag: destination does not exist",
                        ));
                    }
                    let meta = tokio::fs::metadata(&dest_path).await.map_err(map_io)?;
                    let current = identity_from_metadata(&meta)?;
                    check_etag_write(Some(expected), &current)?;
                }
            }
            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
            }
            tokio::fs::rename(&src_path, &dest_path)
                .await
                .map_err(map_io)?;
            move_metadata_file(&src_path, &dest_path).await?;
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                let mut metadata = read_user_metadata(&dest_path).await?;
                metadata.insert("x-ov-message".to_string(), message.to_string());
                write_user_metadata(&dest_path, &metadata).await?;
            }
            Ok(())
        })
        .await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "update_metadata")
    )]
    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            let meta = tokio::fs::metadata(&path).await.map_err(map_io)?;
            if let Some(expected) = opts.if_match.as_deref() {
                let current = identity_from_metadata(&meta)?;
                check_etag_write(Some(expected), &current)?;
            }
            let mut metadata = read_user_metadata(&path).await?;
            for key in opts.user_metadata_remove {
                metadata.remove(&key);
            }
            for (key, value) in opts.user_metadata_set {
                metadata.insert(key, value);
            }
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                metadata.insert("x-ov-message".to_string(), message.to_string());
            }
            write_user_metadata(&path, &metadata).await?;
            item_info_for_path(&path, true).await
        })
        .await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(plugin = "file", op = "check_access")
    )]
    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let path = self.path_from_address(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            // SPI: check_access on a missing target returns NotFound, not an empty AccessDecision.
            if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
                return Err(Error::new(ErrorCode::NotFound, "file does not exist"));
            }
            let mut denied_ops = AccessOps::default();
            let readonly = tokio::fs::metadata(&path)
                .await
                .map(|metadata| metadata.permissions().readonly())
                .unwrap_or(false);
            let parent_readonly = match path.parent() {
                Some(parent) => tokio::fs::metadata(parent)
                    .await
                    .map(|metadata| metadata.permissions().readonly())
                    .unwrap_or(false),
                None => false,
            };
            if ops.write && readonly {
                denied_ops.write = true;
            }
            if ops.delete && (readonly || parent_readonly) {
                denied_ops.delete = true;
            }
            if ops.update_metadata && readonly {
                denied_ops.update_metadata = true;
            }
            let allowed = denied_ops == AccessOps::default();
            Ok(AccessDecision {
                allowed,
                denied_ops,
                reason: if allowed {
                    None
                } else {
                    Some("filesystem metadata denies at least one requested operation".into())
                },
            })
        })
        .await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSnapshotEntry {
    identity: FileIdentity,
    object_mtime: Option<SystemTime>,
    metadata_mtime: Option<SystemTime>,
}

struct FileChangeStream {
    root: PathBuf,
    base_address: Url,
    jail_root: Option<PathBuf>,
    recursive: bool,
    include_metadata_changes: bool,
    poll_interval: Duration,
    snapshot: BTreeMap<String, FileSnapshotEntry>,
    pending: VecDeque<BackendChangeEvent>,
    /// Checked before and after each poll sleep; mid-sleep cancellation
    /// is observed within one poll interval.
    cancel: Option<CancellationToken>,
}

impl FileChangeStream {
    fn new(
        root: PathBuf,
        base_address: Url,
        jail_root: Option<PathBuf>,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Self> {
        let snapshot = scan_watch_directory_snapshot(&root, opts.recursive, jail_root.as_deref())?;
        let mut pending = VecDeque::new();
        if opts.since.is_some() {
            pending.push_back(BackendChangeEvent::Lapsed {
                since: None,
                cursor: fresh_watch_directory_cursor(),
            });
        }
        Ok(Self {
            root,
            base_address,
            jail_root,
            recursive: opts.recursive,
            include_metadata_changes: opts.include_metadata_changes,
            poll_interval: opts.poll_interval.max(Duration::from_millis(10)),
            snapshot,
            pending,
            cancel,
        })
    }

    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|token| token.is_cancelled())
            .unwrap_or(false)
    }
}

impl Iterator for FileChangeStream {
    type Item = Result<BackendChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.is_cancelled() {
                return None;
            }
            if let Some(event) = self.pending.pop_front() {
                return Some(Ok(event));
            }
            std::thread::sleep(self.poll_interval);
            if self.is_cancelled() {
                return None;
            }
            match scan_watch_directory_snapshot(
                &self.root,
                self.recursive,
                self.jail_root.as_deref(),
            ) {
                Ok(next) => match diff_watch_directory_snapshots(
                    &self.snapshot,
                    &next,
                    &self.base_address,
                    self.include_metadata_changes,
                ) {
                    Ok(pending) => {
                        self.pending = pending;
                        self.snapshot = next;
                    }
                    Err(error) => return Some(Err(error)),
                },
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

fn scan_watch_directory_snapshot(
    root: &Path,
    recursive: bool,
    jail_root: Option<&Path>,
) -> Result<BTreeMap<String, FileSnapshotEntry>> {
    let mut out = BTreeMap::new();
    scan_watch_directory_dir(root, root, recursive, jail_root, &mut out)?;
    Ok(out)
}

fn scan_watch_directory_dir(
    base: &Path,
    current: &Path,
    recursive: bool,
    jail_root: Option<&Path>,
    out: &mut BTreeMap<String, FileSnapshotEntry>,
) -> Result<()> {
    for entry in fs::read_dir(current).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let path = entry.path();
        if is_internal_entry(&path) {
            continue;
        }
        if let Some(jail_root) = jail_root {
            ensure_path_within_root(&path, jail_root)?;
        }
        if path.is_dir() {
            if recursive {
                scan_watch_directory_dir(base, &path, recursive, jail_root, out)?;
            }
            continue;
        }
        let relative_key = relative_path(base, &path)?;
        out.insert(relative_key, file_snapshot_entry(&path)?);
    }
    Ok(())
}

fn file_snapshot_entry(path: &Path) -> Result<FileSnapshotEntry> {
    let metadata = fs::metadata(path).map_err(map_io)?;
    let metadata_mtime = metadata_path(path)
        .ok()
        .and_then(|path| fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok());
    Ok(FileSnapshotEntry {
        identity: identity_from_metadata(&metadata)?,
        object_mtime: metadata.modified().ok(),
        metadata_mtime,
    })
}

fn diff_watch_directory_snapshots(
    old: &BTreeMap<String, FileSnapshotEntry>,
    new: &BTreeMap<String, FileSnapshotEntry>,
    base_address: &Url,
    include_metadata_changes: bool,
) -> Result<VecDeque<BackendChangeEvent>> {
    let keys = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut out = VecDeque::new();
    for key in keys {
        match (old.get(&key), new.get(&key)) {
            (None, Some(current)) => out.push_back(change_event(
                base_address,
                key,
                ChangeKind::Created,
                Some(&current.identity),
            )?),
            (Some(_), None) => {
                out.push_back(change_event(base_address, key, ChangeKind::Deleted, None)?)
            }
            (Some(previous), Some(current)) if previous.identity != current.identity => {
                out.push_back(change_event(
                    base_address,
                    key,
                    ChangeKind::Modified,
                    Some(&current.identity),
                )?);
            }
            (Some(previous), Some(current))
                if include_metadata_changes
                    && previous.metadata_mtime != current.metadata_mtime =>
            {
                out.push_back(change_event(
                    base_address,
                    key,
                    ChangeKind::MetadataChanged,
                    Some(&current.identity),
                )?);
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Builds a `BackendChangeEvent::Object` from the post-change file
/// identity. `identity = None` represents a delete (or any case where
/// the post-change snapshot is absent); the descriptive fields
/// (`etag`/`version`/`size`/`mtime`) all collapse to `None`. The file
/// plugin has no notion of a backend `version`, so `version` is always
/// `None`.
fn change_event(
    base_address: &Url,
    relative_key: String,
    kind: ChangeKind,
    identity: Option<&FileIdentity>,
) -> Result<BackendChangeEvent> {
    let (etag, size, mtime) = match identity {
        Some(identity) => (identity.synthesize_etag(), identity.size, identity.mtime),
        None => (None, None, None),
    };
    Ok(BackendChangeEvent::Object {
        address: address::join_relative(base_address, &relative_key)?,
        kind,
        etag,
        version: None,
        size,
        mtime,
        at: SystemTime::now(),
        cursor: fresh_watch_directory_cursor(),
    })
}

fn fresh_watch_directory_cursor() -> WatchDirectoryCursor {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    WatchDirectoryCursor(nanos.to_string().into_bytes())
}

/// Iterative walk: an explicit stack avoids the `Box::pin` recursing async fns force.
async fn collect_recursive(
    base: &Path,
    root: &Path,
    base_address: &Url,
    include_modified_by: bool,
    jail_root: Option<&Path>,
    out: &mut Vec<ObjectInfo>,
) -> Result<()> {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&current).await.map_err(map_io)?;
        while let Some(entry) = entries.next_entry().await.map_err(map_io)? {
            let path = entry.path();
            if is_internal_entry(&path) {
                continue;
            }
            if let Some(jail_root) = jail_root {
                ensure_path_within_root(&path, jail_root)?;
            }
            let metadata = entry.metadata().await.map_err(map_io)?;
            if metadata.is_dir() {
                let mut relative_key = relative_path(base, &path)?;
                if !relative_key.ends_with('/') {
                    relative_key.push('/');
                }
                let address = address::join_relative(base_address, &relative_key)?;
                out.push(info_for_path(address, &path, include_modified_by).await?);
                stack.push(path);
            } else {
                let relative_key = relative_path(base, &path)?;
                let address = address::join_relative(base_address, &relative_key)?;
                out.push(info_for_path(address, &path, include_modified_by).await?);
            }
        }
    }
    Ok(())
}

/// `include_modified_by = false` skips the per-platform owner-resolve
/// path (Unix uid lookup, Windows DACL probe). Public callers wire it
/// from `StatOptions::full_metadata` / `ListOptions::full_metadata`;
/// internal callers that only need identity/etag for a precondition
/// check pass `false`.
async fn info_for_path(address: Url, path: &Path, include_modified_by: bool) -> Result<ObjectInfo> {
    let meta = tokio::fs::metadata(path).await.map_err(map_io)?;
    let kind = if meta.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    let identity = identity_from_metadata(&meta)?;
    Ok(ObjectInfo {
        address,
        kind,
        etag: identity.synthesize_etag(),
        version: identity.version,
        size: object_size(kind, identity.size),
        mtime: identity.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: Some(effective_permissions_from_metadata(&meta)),
        system_metadata: Some(SystemMetadata::new()),
        user_metadata: Some(read_user_metadata(path).await?),
        modified_by: if include_modified_by {
            modified_by_for_path(path, &meta)
        } else {
            None
        },
    })
}

async fn item_info_for_path(path: &Path, include_modified_by: bool) -> Result<BackendItemInfo> {
    let meta = tokio::fs::metadata(path).await.map_err(map_io)?;
    let kind = if meta.is_dir() {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    let identity = identity_from_metadata(&meta)?;
    Ok(BackendItemInfo {
        kind,
        etag: identity.synthesize_etag(),
        version: identity.version,
        size: object_size(kind, identity.size),
        mtime: identity.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: Some(effective_permissions_from_metadata(&meta)),
        system_metadata: Some(SystemMetadata::new()),
        user_metadata: Some(read_user_metadata(path).await?),
        modified_by: if include_modified_by {
            modified_by_for_path(path, &meta)
        } else {
            None
        },
    })
}

fn object_size(kind: ObjectKind, size: Option<u64>) -> Option<u64> {
    kind.is_file().then_some(size).flatten()
}

fn identity_from_metadata(meta: &fs::Metadata) -> Result<FileIdentity> {
    Ok(FileIdentity {
        etag: None,
        version: None,
        size: Some(meta.len()),
        mtime: meta.modified().ok(),
    })
}

#[cfg(unix)]
fn reject_special_file(meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let kind = meta.file_type();
    if kind.is_fifo() || kind.is_socket() || kind.is_block_device() || kind.is_char_device() {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "cannot read special filesystem objects",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_special_file(_meta: &fs::Metadata) -> Result<()> {
    Ok(())
}

/// Owner-as-best-effort modifier. POSIX `st_uid` and Windows DACL
/// owner are *owner*, not strictly *modifier* — neither kernel
/// records the principal of the last `write()`. On most single-user
/// systems they coincide. The broker overrides this in brokered mode
/// via the attribution layer; in direct-library mode this is what
/// surfaces.
#[cfg(unix)]
fn modified_by_for_path(_path: &Path, meta: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(resolve_uid(meta.uid()))
}

#[cfg(windows)]
fn modified_by_for_path(path: &Path, _meta: &fs::Metadata) -> Option<String> {
    windows_owner::resolve(path)
}

#[cfg(not(any(unix, windows)))]
fn modified_by_for_path(_path: &Path, _meta: &fs::Metadata) -> Option<String> {
    None
}

/// Resolve a POSIX uid to a username via `getpwuid_r`, falling back to
/// `uid:N` if the entry is missing (containers without `/etc/passwd`,
/// NSS misconfiguration, etc.) so the field is never empty. Cached
/// per-process: uids are stable for a process lifetime.
#[cfg(unix)]
fn resolve_uid(uid: u32) -> String {
    let cache = UID_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Some(name) = cache.lock().expect("uid cache poisoned").get(&uid) {
        return name.clone();
    }
    let resolved = lookup_uid(uid).unwrap_or_else(|| format!("uid:{uid}"));
    cache
        .lock()
        .expect("uid cache poisoned")
        .insert(uid, resolved.clone());
    resolved
}

#[cfg(unix)]
static UID_CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<u32, String>>> =
    std::sync::OnceLock::new();

#[cfg(unix)]
fn lookup_uid(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let cstr = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        return cstr.to_str().ok().map(String::from);
    }
}

/// Resolve the file's NTFS owner SID to `DOMAIN\username` (or to the
/// stringified SID when name lookup fails — common on orphaned ACLs
/// from removed AD accounts). Mirrors the Unix `resolve_uid` fallback
/// pattern: never returns an empty string when an owner SID exists.
#[cfg(windows)]
mod windows_owner {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID};

    pub(super) fn resolve(path: &Path) -> Option<String> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut sid: PSID = std::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();

        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut sid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd as *mut _ as *mut _,
            )
        };

        if rc != ERROR_SUCCESS || sid.is_null() {
            // `sd` is only populated on success; nothing to free.
            return None;
        }

        let resolved = lookup_name(sid).or_else(|| sid_to_string(sid));

        // SAFETY: GetNamedSecurityInfoW allocates `sd` with LocalAlloc on success.
        unsafe {
            LocalFree(sd as HLOCAL);
        }

        resolved
    }

    fn lookup_name(sid: PSID) -> Option<String> {
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut sid_use: i32 = 0;
        // Probe call: returns 0 with ERROR_INSUFFICIENT_BUFFER and fills the lengths.
        unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                std::ptr::null_mut(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut sid_use,
            );
        }
        if name_len == 0 {
            return None;
        }

        let mut name_buf = vec![0u16; name_len as usize];
        let mut domain_buf = vec![0u16; domain_len as usize];
        let rc = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name_buf.as_mut_ptr(),
                &mut name_len,
                domain_buf.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if rc == 0 {
            return None;
        }

        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .into_owned();
        let domain = OsString::from_wide(&domain_buf[..domain_len as usize])
            .to_string_lossy()
            .into_owned();
        if domain.is_empty() {
            Some(name)
        } else {
            Some(format!("{domain}\\{name}"))
        }
    }

    fn sid_to_string(sid: PSID) -> Option<String> {
        let mut s: *mut u16 = std::ptr::null_mut();
        let rc = unsafe { ConvertSidToStringSidW(sid, &mut s) };
        if rc == 0 || s.is_null() {
            return None;
        }
        // Walk to the NUL terminator; ConvertSidToStringSidW guarantees one.
        let mut len = 0;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: pointer + length validated above.
        let slice = unsafe { std::slice::from_raw_parts(s, len) };
        let result = OsString::from_wide(slice).to_string_lossy().into_owned();
        unsafe {
            LocalFree(s as HLOCAL);
        }
        Some(result)
    }
}

fn effective_permissions_from_metadata(meta: &fs::Metadata) -> EffectivePermissions {
    if meta.permissions().readonly() {
        EffectivePermissions::READ
    } else {
        EffectivePermissions::all()
    }
}

async fn read_user_metadata(path: &Path) -> Result<UserMetadata> {
    let metadata_path = metadata_path(path)?;
    let Ok(text) = tokio::fs::read_to_string(metadata_path).await else {
        return Ok(UserMetadata::new());
    };
    let mut out = UserMetadata::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::new(
                ErrorCode::CacheCorrupt,
                "file metadata sidecar contains a malformed line",
            ));
        };
        out.insert(hex_decode_string(key)?, hex_decode_string(value)?);
    }
    Ok(out)
}

async fn write_user_metadata(path: &Path, metadata: &UserMetadata) -> Result<()> {
    let metadata_path = metadata_path(path)?;
    if metadata.is_empty() {
        if metadata_exists(&metadata_path).await {
            tokio::fs::remove_file(metadata_path)
                .await
                .map_err(map_io)?;
        }
        return Ok(());
    }
    if let Some(parent) = metadata_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
    }
    let mut lines = String::new();
    let mut pairs: Vec<_> = metadata.iter().collect();
    pairs.sort_by_key(|(left, _)| *left);
    for (key, value) in pairs {
        lines.push_str(&hex_encode(key.as_bytes()));
        lines.push('=');
        lines.push_str(&hex_encode(value.as_bytes()));
        lines.push('\n');
    }
    tokio::fs::write(metadata_path, lines).await.map_err(map_io)
}

fn metadata_path(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let name = path.file_name().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for named filesystem entries",
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for entries with a parent directory",
            )
        })?;
        let mut stream_name = OsString::from(name);
        stream_name.push(":ovstorage.metadata");
        Ok(parent.join(stream_name))
    }

    #[cfg(not(windows))]
    {
        let name = path.file_name().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for named filesystem entries",
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for entries with a parent directory",
            )
        })?;
        let encoded = hex_encode(name.to_string_lossy().as_bytes());
        Ok(parent
            .join(".ovstorage-meta")
            .join(format!("{encoded}.meta")))
    }
}

async fn copy_metadata_file(src: &Path, dest: &Path) -> Result<()> {
    let src_meta = metadata_path(src)?;
    if !metadata_exists(&src_meta).await {
        remove_metadata_file(dest).await?;
        return Ok(());
    }
    let dest_meta = metadata_path(dest)?;
    if let Some(parent) = dest_meta.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
    }
    let bytes = tokio::fs::read(src_meta).await.map_err(map_io)?;
    tokio::fs::write(dest_meta, bytes).await.map_err(map_io)?;
    Ok(())
}

async fn move_metadata_file(src: &Path, dest: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = (src, dest);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let src_meta = metadata_path(src)?;
        if !metadata_exists(&src_meta).await {
            remove_metadata_file(dest).await?;
            return Ok(());
        }
        let dest_meta = metadata_path(dest)?;
        if let Some(parent) = dest_meta.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(map_io)?;
        }
        let bytes = tokio::fs::read(&src_meta).await.map_err(map_io)?;
        tokio::fs::write(dest_meta, bytes).await.map_err(map_io)?;
        tokio::fs::remove_file(src_meta).await.map_err(map_io)
    }
}

async fn remove_metadata_file(path: &Path) -> Result<()> {
    let metadata_path = metadata_path(path)?;
    if metadata_exists(&metadata_path).await {
        tokio::fs::remove_file(metadata_path)
            .await
            .map_err(map_io)?;
    }
    Ok(())
}

async fn metadata_exists(path: &Path) -> bool {
    tokio::fs::metadata(path).await.is_ok()
}

async fn remove_directory_metadata_dir(path: &Path) -> Result<()> {
    let metadata_dir = path.join(".ovstorage-meta");
    if tokio::fs::try_exists(&metadata_dir).await.unwrap_or(false) {
        tokio::fs::remove_dir_all(metadata_dir)
            .await
            .map_err(map_io)?;
    }
    Ok(())
}

fn is_metadata_dir(path: &Path) -> bool {
    path.file_name()
        .map(|name| name == ".ovstorage-meta")
        .unwrap_or(false)
}

fn is_internal_entry(path: &Path) -> bool {
    is_metadata_dir(path) || is_atomic_write_temp_sibling(path)
}

fn is_atomic_write_temp_sibling(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let trailing_digit_groups = inner
        .rsplit('.')
        .take_while(|seg| !seg.is_empty() && seg.bytes().all(|byte| byte.is_ascii_digit()))
        .count();
    trailing_digit_groups >= 1
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode_string(value: &str) -> Result<String> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar has invalid hex",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<_> = value.as_bytes().to_vec();
    for pair in chars.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar is not valid UTF-8",
        )
    })
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar has invalid hex",
        )),
    }
}

fn etag_mismatch(expected: &str, actual: &FileIdentity) -> bool {
    match actual.synthesize_etag() {
        Some(a) => a != expected,
        None => true,
    }
}

// Read-side etag check; ObjectModified signals the read path that the
// pre-stream etag didn't match.
fn check_etag(expected: Option<&str>, actual: &FileIdentity) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.is_empty() {
        return Ok(());
    }
    if etag_mismatch(expected, actual) {
        Err(
            Error::new(ErrorCode::ObjectModified, "object etag changed").with_context(
                ErrorContext::Identity {
                    new_etag: actual.synthesize_etag(),
                },
            ),
        )
    } else {
        Ok(())
    }
}

// Write-side preconditions return PreconditionFailed: no bytes flowed,
// the caller's expected etag did not match.
fn check_etag_write(expected: Option<&str>, actual: &FileIdentity) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.is_empty() {
        return Ok(());
    }
    if etag_mismatch(expected, actual) {
        Err(
            Error::new(ErrorCode::PreconditionFailed, "if_match etag mismatch").with_context(
                ErrorContext::Identity {
                    new_etag: actual.synthesize_etag(),
                },
            ),
        )
    } else {
        Ok(())
    }
}

async fn open_ranged_stream(
    path: &std::path::Path,
    len: u64,
    range: ByteRange,
) -> Result<ReadStream> {
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if len == 0 || range.start >= len {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "byte range is outside the object",
        ));
    }
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "byte range end precedes start",
        ));
    }
    let end = range.end_inclusive.unwrap_or(len - 1).min(len - 1);
    let take = end - range.start + 1;
    let mut file = tokio::fs::File::open(path).await.map_err(map_io)?;
    file.seek(std::io::SeekFrom::Start(range.start))
        .await
        .map_err(map_io)?;
    let limited = file.take(take);
    let reader = tokio_util::io::ReaderStream::new(limited);
    let stream: ReadStream = Box::pin(reader.map(|chunk| chunk.map_err(map_io)));
    Ok(stream)
}

fn config_path(
    config: &std::collections::HashMap<String, ConfigValue>,
    key: &str,
) -> Result<PathBuf> {
    match config.get(key) {
        Some(ConfigValue::String(path)) => Ok(PathBuf::from(path)),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("file connection config '{key}' must be a path"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required file connection config '{key}'"),
        )),
    }
}

fn connection_prefix(
    config: &std::collections::HashMap<String, ConfigValue>,
    root: &Path,
) -> Result<Url> {
    let root_address = address_for_filesystem_path(root);
    match config.get("prefix") {
        Some(ConfigValue::String(value)) => {
            let parsed = address::parse(value)?;
            let prefix_path = path_from_file_address(&parsed)?;
            let canonical_root = canonicalize_scope_root(root)?;
            if let Err(error) = ensure_path_within_root(&prefix_path, &canonical_root) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "file connection 'prefix' ({value}) must resolve under the configured \
                         root ({}); cross-root rewriting is not supported: {}",
                        root.display(),
                        error.message()
                    ),
                ));
            }
            Ok(parsed)
        }
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "file connection config 'prefix' must be a URL string",
        )),
        None => Ok(root_address),
    }
}

fn address_for_filesystem_path(path: &Path) -> Url {
    let mut path = path.to_string_lossy().replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    address::parse(&format!("file:{path}")).unwrap()
}

fn path_from_file_address(address: &Url) -> Result<PathBuf> {
    if address.scheme() != "file" {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "file backend requires file: URLs",
        ));
    }
    // Reject non-empty/non-localhost authority: URL parsers silently strip it,
    // and UNC-style `file://server/share/...` would otherwise confuse downstream paths.
    if let Some(host) = address.host_str()
        && !host.is_empty()
        && !host.eq_ignore_ascii_case("localhost")
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "file:// URL must have empty or 'localhost' authority, got '{host}' \
                 (UNC paths and remote shares are not supported)"
            ),
        ));
    }
    // Re-prepend the leading `/` that `address::key` strips for relative-key backends.
    let decoded = address::key(address);
    let mut normalized = format!("/{}", decoded);
    normalized = normalized.replace('\\', "/");
    // Windows drive-letter form file:/C:/... → C:/...
    if normalized.starts_with('/') && normalized.as_bytes().get(2) == Some(&b':') {
        normalized.remove(0);
    }
    let path = PathBuf::from(normalized.replace('/', std::path::MAIN_SEPARATOR_STR));
    reject_parent_components(&path)?;
    reject_metadata_namespace(&path)?;
    Ok(path)
}

fn canonicalize_scope_root(root: &Path) -> Result<PathBuf> {
    fs::canonicalize(root).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "configured file root ({}) is not accessible: {err}",
                root.display()
            ),
        )
    })
}

fn ensure_path_within_root(path: &Path, canonical_root: &Path) -> Result<()> {
    let canonical_anchor = canonical_existing_anchor(path)?;
    if canonical_anchor.starts_with(canonical_root) {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::PermissionDenied,
        "file address resolves outside the configured root",
    ))
}

fn canonical_existing_anchor(path: &Path) -> Result<PathBuf> {
    let mut candidate = path;
    loop {
        match fs::canonicalize(candidate) {
            Ok(canonical) => return Ok(canonical),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or_else(|| map_io(err))?;
            }
            Err(err) => return Err(map_io(err)),
        }
    }
}

fn reject_parent_components(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "file addresses must not contain '..' path components",
        ));
    }
    Ok(())
}

fn reject_metadata_namespace(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| component.as_os_str() == ".ovstorage-meta")
    {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            "the .ovstorage-meta namespace is reserved for ovstorage metadata sidecars",
        ));
    }
    Ok(())
}

fn relative_path(base: &Path, path: &Path) -> Result<String> {
    let rel = path.strip_prefix(base).map_err(|_| {
        Error::new(
            ErrorCode::Internal,
            "listed path was not under the requested base path",
        )
    })?;
    Ok(rel.to_string_lossy().replace('\\', "/"))
}

fn temp_sibling(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| "object".into());
    path.with_file_name(format!(".{name}.{stamp}.{pid}.{counter}.tmp"))
}

async fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent).await?;
    }
    Ok(())
}

#[cfg(not(windows))]
async fn sync_directory(path: &Path) -> Result<()> {
    let file = tokio::fs::File::open(path).await.map_err(map_io)?;
    file.sync_all().await.map_err(map_io)
}

#[cfg(windows)]
async fn sync_directory(path: &Path) -> Result<()> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .await
        .map_err(map_io)?;
    match file.sync_all().await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(map_io(error)),
    }
}

fn map_io(err: io::Error) -> Error {
    // EISDIR/ENOTDIR signal a file-vs-directory shape mismatch — the path
    // doesn't exist with that shape — so map to NotFound (matches Nucleus's
    // InvalidPath → NotFound precedent).
    let code = match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory => {
            ErrorCode::NotFound
        }
        io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::BrokenPipe => ErrorCode::Cancelled,
        io::ErrorKind::InvalidInput => ErrorCode::InvalidArgument,
        _ if err.raw_os_error() == Some(267) => ErrorCode::NotFound,
        _ if is_invalid_path_error(&err) => ErrorCode::InvalidArgument,
        _ if is_storage_full_error(&err) => ErrorCode::ResourceExhausted,
        _ if is_read_only_filesystem_error(&err) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, err.to_string())
}

#[cfg(unix)]
fn is_invalid_path_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == libc::ENAMETOOLONG || code == libc::ELOOP || code == libc::EINVAL
    )
}

#[cfg(not(unix))]
fn is_invalid_path_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_storage_full_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::ENOSPC)
}

#[cfg(not(unix))]
fn is_storage_full_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_read_only_filesystem_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::EROFS)
}

#[cfg(not(unix))]
fn is_read_only_filesystem_error(_err: &io::Error) -> bool {
    false
}

// C ABI plugin entry points; the `shim` blanket bridge handles the rest.
ovstorage_plugin::ovstorage_plugin!(FileBackendFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ovstorage::{Library, Storage};
    use ovstorage_cache::{Cache, CacheConfig};

    #[cfg(unix)]
    #[test]
    fn modified_by_resolves_owning_user_or_falls_back_to_uid_string() {
        // Pick a uid that exists on every Unix box: the running process's own uid.
        let my_uid = unsafe { libc::getuid() };
        let resolved = resolve_uid(my_uid);
        // Either a real username (containers with /etc/passwd) or `uid:N`
        // (containers without it). Never empty.
        assert!(!resolved.is_empty(), "resolve_uid produced empty string");
        // Wholly unlikely uid; verifies the fallback path even on hosts
        // that have a real /etc/passwd.
        let absent_uid = 0xFFFE_FFFEu32;
        let absent = resolve_uid(absent_uid);
        assert_eq!(absent, format!("uid:{absent_uid}"));
    }

    #[test]
    fn file_address_parser_accepts_single_and_triple_slash_forms() {
        assert_eq!(
            path_from_file_address(&address::parse("file:/tmp/ovstorage.txt").unwrap()).unwrap(),
            PathBuf::from(std::path::MAIN_SEPARATOR_STR)
                .join("tmp")
                .join("ovstorage.txt")
        );
        assert_eq!(
            path_from_file_address(&address::parse("file:///tmp/ovstorage.txt").unwrap()).unwrap(),
            PathBuf::from(std::path::MAIN_SEPARATOR_STR)
                .join("tmp")
                .join("ovstorage.txt")
        );
    }

    #[test]
    fn file_address_rejects_non_empty_authority() {
        let err = path_from_file_address(&address::parse("file://hostname/tmp/x.txt").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("hostname"));
    }

    #[test]
    fn file_address_rejects_unc_share() {
        let err = path_from_file_address(&address::parse("file://fileserver/share/x.txt").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn file_address_accepts_localhost_authority() {
        path_from_file_address(&address::parse("file://localhost/tmp/x.txt").unwrap())
            .expect("localhost authority is accepted");
        path_from_file_address(&address::parse("file://LocalHost/tmp/x.txt").unwrap())
            .expect("case-insensitive localhost is accepted");
    }

    #[tokio::test]
    async fn file_backend_round_trips_through_library() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let cache_config = CacheConfig {
            state_root: root.join(".state"),
            cache_root: root.join(".cache"),
        };
        let lib = Library::builder()
            .with_cache(Cache::open(cache_config.clone()).unwrap())
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();
        let capabilities = lib.capabilities_for(&prefix).unwrap();
        assert!(capabilities.supports_list);
        assert!(!capabilities.wants_list_backed_stat);

        let dir = address::join_relative(&prefix, "nested/").unwrap();
        lib.create_directory(dir.clone(), CreateDirectoryOptions::default(), None)
            .await
            .unwrap();
        let recursive_dir = address::join_relative(&prefix, "missing/child/").unwrap();
        lib.create_directory(
            recursive_dir.clone(),
            CreateDirectoryOptions::default(),
            None,
        )
        .await
        .unwrap();
        assert!(root.join("missing").join("child").is_dir());
        lib.create_directory(recursive_dir, CreateDirectoryOptions::default(), None)
            .await
            .unwrap();

        let object = address::join_relative(&prefix, "nested/hello.txt").unwrap();
        let mut write_metadata = UserMetadata::new();
        write_metadata.insert("origin".into(), "write".into());
        let written = lib
            .write(
                object.clone(),
                Body::Bytes(b"hello".to_vec()),
                WriteOptions {
                    if_dest: IfDestExists::Fail,
                    user_metadata: Some(write_metadata),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(written.info.size, Some(5));
        assert_eq!(
            written.info.effective_permissions,
            Some(EffectivePermissions::all())
        );
        assert_eq!(
            written
                .info
                .user_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("origin")),
            Some(&"write".to_string())
        );

        let (bytes, info) = lib
            .read_bytes(object.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(bytes, b"hello");
        assert_eq!(info.address, object);

        let local = lib
            .materialize(object.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(fs::read(local.path).unwrap(), b"hello");

        let (range, _) = lib
            .read_bytes(
                object.clone(),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 1,
                        end_inclusive: Some(3),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(range, b"ell");

        let root_items = lib
            .list(prefix.clone(), ListOptions::default(), None)
            .await
            .unwrap();
        let nested_entry = root_items
            .iter()
            .find(|item| item.address == dir)
            .expect("root listing should include nested directory");
        assert_eq!(nested_entry.kind, ObjectKind::Directory);
        assert_eq!(nested_entry.size, None);

        let recursive_items = lib
            .list(
                prefix.clone(),
                ListOptions {
                    recursive: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let recursive_nested_entry = recursive_items
            .iter()
            .find(|item| item.address == dir)
            .expect("recursive listing should include real directory entries");
        assert_eq!(recursive_nested_entry.kind, ObjectKind::Directory);

        let items = lib
            .list(dir.clone(), ListOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, ObjectKind::File);
        assert_eq!(
            items[0].address.as_str(),
            address::join_relative(&prefix, "nested/hello.txt")
                .unwrap()
                .as_str()
        );

        let copied = address::join_relative(&prefix, "nested/copied.txt").unwrap();
        lib.copy(object.clone(), copied.clone(), CopyOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(
            lib.read_bytes(copied.clone(), ReadOptions::default(), None)
                .await
                .unwrap()
                .0,
            b"hello"
        );

        let mut options = UpdateMetadataOptions::default();
        options
            .user_metadata_set
            .insert("color".into(), "blue".into());
        let patched = lib
            .update_metadata(copied.clone(), options, None)
            .await
            .unwrap();
        assert_eq!(
            patched
                .user_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("color")),
            Some(&"blue".to_string())
        );

        let moved = address::join_relative(&prefix, "nested/moved.txt").unwrap();
        lib.rename(
            copied.clone(),
            moved.clone(),
            RenameOptions::default(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            lib.stat(moved.clone(), StatOptions::default(), None)
                .await
                .unwrap()
                .user_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("color")),
            Some(&"blue".to_string())
        );
        assert_eq!(
            lib.stat(copied, StatOptions::default(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );

        let access = lib
            .check_access(
                moved.clone(),
                AccessOps {
                    read: true,
                    write: true,
                    delete: true,
                    update_metadata: true,
                },
                None,
            )
            .await
            .unwrap();
        assert!(access.allowed);

        let reserved = address::join_relative(&prefix, ".ovstorage-meta/sidecar.meta").unwrap();
        assert_eq!(
            lib.write(
                reserved,
                Body::Bytes(b"reserved".to_vec()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::PermissionDenied
        );

        lib.read_bytes(moved.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
        lib.delete(moved.clone(), DeleteOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(
            lib.read_bytes(moved, ReadOptions::default(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );

        let blocker = address::join_relative(&prefix, "nested/blocker.txt").unwrap();
        lib.write(
            blocker.clone(),
            Body::Bytes(b"blocker".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
        lib.read_bytes(blocker.clone(), ReadOptions::default(), None)
            .await
            .unwrap();

        let err = lib
            .delete_directory(dir.clone(), DeleteDirectoryOptions, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty);

        lib.delete(blocker.clone(), DeleteOptions::default(), None)
            .await
            .unwrap();
        lib.delete(object.clone(), DeleteOptions::default(), None)
            .await
            .unwrap();
        lib.delete_directory(dir, DeleteDirectoryOptions, None)
            .await
            .unwrap();
        assert!(!root.join("nested").exists());

        let cached = address::join_relative(&prefix, "cached.txt").unwrap();
        lib.write(
            cached.clone(),
            Body::Bytes(b"still cached".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
        lib.read_bytes(cached.clone(), ReadOptions::default(), None)
            .await
            .unwrap();

        drop(lib);
        let reopened_cache = Cache::open(cache_config).unwrap();
        // Cache keys carry a `policy_partition` prefix; the default Library partition is `"local"`.
        assert_eq!(
            reopened_cache
                .get(&format!("local\0file\0{blocker}"))
                .unwrap(),
            None
        );
        assert_eq!(
            reopened_cache
                .get(&format!("local\0file\0{cached}"))
                .unwrap(),
            Some(b"still cached".to_vec())
        );
        drop(reopened_cache);

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn streamed_body_round_trips_through_temp_file_then_rename() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        let object = address::join_relative(&prefix, "streamed.bin").unwrap();
        let chunks: Vec<Result<Vec<u8>>> = vec![
            Ok(b"chunk-one-".to_vec()),
            Ok(b"chunk-two-".to_vec()),
            Ok(b"chunk-three".to_vec()),
        ];
        let stream = BodyStream::from_iter(chunks.into_iter());
        let written = lib
            .write(
                object.clone(),
                Body::Stream(stream),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(written.info.size, Some(31));

        let (bytes, _info) = lib
            .read_bytes(object.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(bytes, b"chunk-one-chunk-two-chunk-three");

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn streamed_body_chunk_error_leaves_no_destination_file() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        let object = address::join_relative(&prefix, "broken.bin").unwrap();
        let chunks: Vec<Result<Vec<u8>>> = vec![
            Ok(b"good-chunk".to_vec()),
            Err(Error::new(ErrorCode::Internal, "synthetic stream failure")),
        ];
        let stream = BodyStream::from_iter(chunks.into_iter());
        let err = lib
            .write(
                object.clone(),
                Body::Stream(stream),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        let final_path = path_from_file_address(&object).unwrap();
        assert!(
            !final_path.exists(),
            "destination should not exist after failed stream"
        );

        // Stream-error paths must unlink the `.tmp` sibling, not just hide it via `is_internal_entry`.
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "stream-error left {} `.tmp` siblings: {:?}",
            leftovers.len(),
            leftovers.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn rooted_file_backend_rejects_escape_addresses() {
        let root = unique_temp_dir();
        let outside = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let lib = Library::builder()
            .add_route(
                address::parse("file:/").unwrap(),
                "file",
                Arc::new(FileBackend::with_root(root.clone())),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        let inside = address::join_relative(&address_for_path(&root), "ok.txt").unwrap();
        lib.write(
            inside,
            Body::Bytes(b"inside".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

        let outside_addr =
            address::join_relative(&address_for_path(&outside), "outside.txt").unwrap();
        assert_eq!(
            lib.write(
                outside_addr,
                Body::Bytes(b"outside".to_vec()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::PermissionDenied
        );
        // RFC 3986 join canonicalizes `..` away before `path_from_file_address` sees it,
        // so escapes land at an absolute path outside `root` and trip the root gate instead.
        assert_eq!(
            lib.write(
                address::join_relative(&address_for_path(&root), "../escape.txt").unwrap(),
                Body::Bytes(b"escape".to_vec()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::PermissionDenied
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rooted_file_backend_rejects_symlink_file_escape() {
        let root = unique_temp_dir();
        let outside = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_secret = outside.join("secret.txt");
        fs::write(&outside_secret, b"outside secret").unwrap();
        std::os::unix::fs::symlink(&outside_secret, root.join("link.txt")).unwrap();

        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::with_root(root.clone())),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        let link = address::join_relative(&prefix, "link.txt").unwrap();
        assert_eq!(
            lib.read_bytes(link, ReadOptions::default(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::PermissionDenied
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rooted_file_backend_allows_symlink_file_inside_root() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("target.txt"), b"inside target").unwrap();
        std::os::unix::fs::symlink(root.join("target.txt"), root.join("link.txt")).unwrap();

        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::with_root(root.clone())),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        let link = address::join_relative(&prefix, "link.txt").unwrap();
        let (bytes, _) = lib
            .read_bytes(link, ReadOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(bytes, b"inside target");

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rooted_file_backend_rejects_recursive_list_symlink_directory_escape() {
        let root = unique_temp_dir();
        let outside = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"outside secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("outside-link")).unwrap();

        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::with_root(root.clone())),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();

        assert_eq!(
            lib.list(
                prefix,
                ListOptions {
                    recursive: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::PermissionDenied
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_rejects_fifo_read_without_opening_it() {
        use ovstorage_plugin::shim::Backend as _;

        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let fifo = root.join("pipe");
        create_fifo(&fifo);

        let prefix = address_for_path(&root);
        let target = address::join_relative(&prefix, "pipe").unwrap();
        let backend = FileBackend::with_root(root.clone());

        let err = backend
            .read(
                ResolvedTarget {
                    backend_id: BackendId("file:test".into()),
                    resolved_address: target,
                },
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);

        fs::remove_file(fifo).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_backend_maps_permanent_linux_io_errors_without_transient() {
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ENAMETOOLONG)).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ELOOP)).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ENOSPC)).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::EROFS)).code(),
            ErrorCode::PermissionDenied
        );
    }

    #[cfg(unix)]
    fn create_fifo(path: &Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            rc,
            0,
            "mkfifo({}) failed: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }

    fn unique_temp_dir() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ovstorage-plugin-file-test-{}-{stamp}",
            std::process::id()
        ))
    }

    fn address_for_path(path: &Path) -> Url {
        let mut path = path.to_string_lossy().replace('\\', "/");
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        address::parse(&format!("file:{path}")).unwrap()
    }

    /// `ObjectModified` carries `ErrorContext::Identity { new_etag }` so callers
    /// can re-issue the if-match write against the freshly observed etag.
    #[test]
    fn check_identity_mismatch_populates_identity_context() {
        let actual = FileIdentity {
            size: Some(11),
            mtime: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            ..Default::default()
        };
        let expected_etag = "size:10,mtime:0";
        let err = check_etag(Some(expected_etag), &actual).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        let expected_actual_etag = actual.synthesize_etag();
        match err.context() {
            Some(ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), expected_actual_etag.as_deref());
            }
            other => panic!("expected Identity context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_overwrite_concurrent_writers_only_one_succeeds() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let backend = Arc::new(FileBackend::with_root(root.clone()));
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                backend.clone(),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();
        let object = address::join_relative(&prefix, "race.txt").unwrap();

        let mut handles = Vec::new();
        for tag in ["one", "two", "three", "four"] {
            let lib = lib.clone();
            let addr = object.clone();
            handles.push(tokio::spawn(async move {
                lib.write(
                    addr,
                    Body::Bytes(tag.as_bytes().to_vec()),
                    WriteOptions {
                        if_dest: IfDestExists::Fail,
                        ..WriteOptions::default()
                    },
                    None,
                )
                .await
            }));
        }
        let mut successes = 0;
        let mut conflicts = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => successes += 1,
                Err(err) if err.code() == ErrorCode::AlreadyExists => conflicts += 1,
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        }
        assert_eq!(
            successes, 1,
            "exactly one IfDestExists::Fail writer must commit"
        );
        assert_eq!(conflicts, 3, "three peers must observe AlreadyExists");

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn read_returns_identity_consistent_with_bytes() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();
        let object = address::join_relative(&prefix, "consistent.txt").unwrap();
        lib.write(
            object.clone(),
            Body::Bytes(b"abcdefghij".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
        let (bytes, info) = lib
            .read_bytes(object.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(bytes, b"abcdefghij");
        assert_eq!(info.size, Some(bytes.len() as u64));

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn update_metadata_on_missing_path_does_not_orphan_sidecar() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();
        let missing = address::join_relative(&prefix, "ghost.txt").unwrap();
        let mut options = UpdateMetadataOptions::default();
        options
            .user_metadata_set
            .insert("color".into(), "red".into());
        let err = lib
            .update_metadata(missing.clone(), options, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let path = path_from_file_address(&missing).unwrap();
        let sidecar = metadata_path(&path).unwrap();
        assert!(
            !sidecar.exists(),
            "sidecar must not be created for nonexistent target"
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn directory_delete_removes_directory_sidecar() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let prefix = address_for_path(&root);
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "file",
                Arc::new(FileBackend::new()),
                FileBackend::capabilities(),
            )
            .open()
            .unwrap();
        let dir = address::join_relative(&prefix, "subdir/").unwrap();
        lib.create_directory(dir.clone(), CreateDirectoryOptions::default(), None)
            .await
            .unwrap();
        let mut options = UpdateMetadataOptions::default();
        options
            .user_metadata_set
            .insert("origin".into(), "first".into());
        lib.update_metadata(dir.clone(), options, None)
            .await
            .unwrap();
        let dir_path = path_from_file_address(&dir).unwrap();
        let sidecar = metadata_path(&dir_path).unwrap();
        assert!(
            sidecar.exists(),
            "directory sidecar should exist after update_metadata"
        );
        lib.delete_directory(dir.clone(), DeleteDirectoryOptions, None)
            .await
            .unwrap();
        assert!(
            !sidecar.exists(),
            "delete must remove the directory sidecar (no orphan)"
        );

        lib.create_directory(dir.clone(), CreateDirectoryOptions::default(), None)
            .await
            .unwrap();
        let info = lib.stat(dir, StatOptions::default(), None).await.unwrap();
        assert!(
            info.user_metadata
                .as_ref()
                .map(|m| m.is_empty())
                .unwrap_or(true),
            "recreated directory must not inherit orphan metadata"
        );

        drop(lib);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn connection_prefix_rejects_prefix_outside_root() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).unwrap();
        let mut config = std::collections::HashMap::new();
        config.insert(
            "prefix".into(),
            ConfigValue::String("file:/elsewhere/".into()),
        );
        let err = connection_prefix(&config, &root).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let mut config_ok = std::collections::HashMap::new();
        let inside_prefix = format!("file:{}/sub/", root.to_string_lossy());
        config_ok.insert("prefix".into(), ConfigValue::String(inside_prefix));
        let prefix = connection_prefix(&config_ok, &root).unwrap();
        assert!(prefix.as_str().ends_with("/sub/"));

        fs::remove_dir_all(root).unwrap();
    }
}
