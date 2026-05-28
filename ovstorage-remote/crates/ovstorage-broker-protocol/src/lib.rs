// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, AddressVisibility, Body, ByteRange, ChecksumAlgorithm,
    ChecksumSet, ConnectionId, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions,
    DeleteOptions, EffectivePermissions, Error, ErrorCode, IfDestExists, InteractiveAuthCapability,
    ListOptions, ListPage, ListVersionsOptions, ObjectInfo, ObjectKind, ReadOptions,
    RedirectBodySource, RedirectResult, RedirectResultBatch, RedirectScope, RenameOptions,
    RouteSource, StatOptions, UpdateMetadataOptions, Url, WatchDirectoryCursor,
    WatchDirectoryOptions, WriteOptions, WriteRedirect, WriteRedirectBatch, WriteResult, address,
};
use prost::Message;

// prost-generated `oneof` enums vary widely in variant size; reshaping
// requires `tonic_build` boxing config we don't control here.
#[allow(clippy::large_enum_variant)]
pub mod pb {
    tonic::include_proto!("ovstorage.v2");
}

#[allow(clippy::large_enum_variant)]
pub mod health_pb {
    tonic::include_proto!("grpc.health.v1");
}

pub use ovstorage_plugin::{
    HttpRequest, ReadRedirect, RedirectResult as CoreRedirectResult,
    WriteRedirect as CoreWriteRedirect, validate_redirect_results,
};

mod transport;
pub use transport::{
    AddressRootsChange, AddressRootsChangeStream, BrokerClientTransport,
    BrokerClientWatchDirectoryStream, RegisterCredentialPayload, UpstreamAuthStream,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

pub const PROTOCOL_V2: ProtocolVersion = ProtocolVersion { major: 2, minor: 0 };

/// gRPC metadata header carrying the host's [`InteractiveAuthCapability`]. Values:
/// `"none" | "headless" | "browser"`; absent → `Browser`. Lowercase so HPACK indexes repeats.
pub const X_OV_IAUTH: &str = "x-ov-iauth";

/// Map an [`InteractiveAuthCapability`] to its `x-ov-iauth` wire token.
pub fn capability_metadata_value(
    capability: InteractiveAuthCapability,
) -> tonic::metadata::MetadataValue<tonic::metadata::Ascii> {
    match capability {
        InteractiveAuthCapability::None => tonic::metadata::MetadataValue::from_static("none"),
        InteractiveAuthCapability::Headless => {
            tonic::metadata::MetadataValue::from_static("headless")
        }
        InteractiveAuthCapability::Browser => {
            tonic::metadata::MetadataValue::from_static("browser")
        }
    }
}

/// Parse the `x-ov-iauth` metadata header. Absent or malformed → `Browser`.
pub fn capability_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> InteractiveAuthCapability {
    let Some(value) = metadata.get(X_OV_IAUTH) else {
        return InteractiveAuthCapability::Browser;
    };
    match value.to_str() {
        Ok("none") => InteractiveAuthCapability::None,
        Ok("headless") => InteractiveAuthCapability::Headless,
        Ok("browser") => InteractiveAuthCapability::Browser,
        _ => InteractiveAuthCapability::Browser,
    }
}

pub fn object_address_to_proto(address: &Url) -> String {
    address.as_str().to_string()
}

pub fn object_address_from_proto(address: String) -> ovstorage_plugin::Result<Url> {
    if address.is_empty() {
        return Err(invalid_argument("missing object address"));
    }
    address::parse(&address)
}

pub fn object_info_to_proto(info: &ObjectInfo) -> pb::ObjectInfo {
    pb::ObjectInfo {
        address: object_address_to_proto(&info.address),
        kind: object_kind_to_proto(info.kind) as i32,
        etag: info.etag.clone(),
        version: info.version.clone(),
        size: info.size,
        mtime_unix_millis: info.mtime.map(system_time_to_millis),
        modified_by: info.modified_by.clone(),
        checksums: checksum_set_to_proto(&info.checksums),
        effective_permissions: info
            .effective_permissions
            .map(effective_permissions_to_proto),
        user_metadata: info.user_metadata.clone().unwrap_or_default(),
        system_metadata: info.system_metadata.clone().unwrap_or_default(),
    }
}

pub fn object_info_from_proto(
    info: Option<pb::ObjectInfo>,
) -> ovstorage_plugin::Result<ObjectInfo> {
    let info = info.ok_or_else(|| invalid_argument("missing object info"))?;
    Ok(ObjectInfo {
        address: object_address_from_proto(info.address)?,
        kind: object_kind_from_proto(info.kind),
        etag: info.etag,
        version: info.version,
        size: info.size,
        mtime: info.mtime_unix_millis.map(millis_to_system_time),
        checksums: checksum_set_from_proto(info.checksums)?,
        effective_permissions: info
            .effective_permissions
            .map(effective_permissions_from_proto),
        system_metadata: (!info.system_metadata.is_empty()).then_some(info.system_metadata),
        user_metadata: (!info.user_metadata.is_empty()).then_some(info.user_metadata),
        modified_by: info.modified_by,
    })
}

fn object_kind_to_proto(kind: ObjectKind) -> pb::ObjectKind {
    match kind {
        ObjectKind::File => pb::ObjectKind::File,
        ObjectKind::Directory => pb::ObjectKind::Directory,
        ObjectKind::DirectoryMarker => pb::ObjectKind::DirectoryMarker,
        ObjectKind::DirectoryInferred => pb::ObjectKind::DirectoryInferred,
    }
}

fn object_kind_from_proto(value: i32) -> ObjectKind {
    match pb::ObjectKind::try_from(value) {
        Ok(pb::ObjectKind::File) => ObjectKind::File,
        Ok(pb::ObjectKind::Directory) => ObjectKind::Directory,
        Ok(pb::ObjectKind::DirectoryMarker) => ObjectKind::DirectoryMarker,
        Ok(pb::ObjectKind::DirectoryInferred) => ObjectKind::DirectoryInferred,
        // Unknown discriminant: default to File (matches `ObjectKind::default()`).
        _ => ObjectKind::File,
    }
}

fn if_dest_exists_to_proto(if_dest: &IfDestExists) -> pb::IfDestExists {
    match if_dest {
        IfDestExists::Overwrite => pb::IfDestExists {
            kind: pb::IfDestExistsKind::Overwrite as i32,
            match_etag: None,
        },
        IfDestExists::Fail => pb::IfDestExists {
            kind: pb::IfDestExistsKind::Fail as i32,
            match_etag: None,
        },
        IfDestExists::MatchEtag(etag) => pb::IfDestExists {
            kind: pb::IfDestExistsKind::MatchEtag as i32,
            match_etag: Some(etag.clone()),
        },
    }
}

fn if_dest_exists_from_proto(
    value: Option<pb::IfDestExists>,
) -> ovstorage_plugin::Result<IfDestExists> {
    // Absent message → `Overwrite`: the wire-default zero bytes
    // round-trip through `IfDestExists::default()`.
    let Some(value) = value else {
        return Ok(IfDestExists::Overwrite);
    };
    match pb::IfDestExistsKind::try_from(value.kind) {
        Ok(pb::IfDestExistsKind::Overwrite) => Ok(IfDestExists::Overwrite),
        Ok(pb::IfDestExistsKind::Fail) => Ok(IfDestExists::Fail),
        Ok(pb::IfDestExistsKind::MatchEtag) => match value.match_etag {
            Some(etag) => Ok(IfDestExists::MatchEtag(etag)),
            // CAS precondition without an etag is malformed — fail
            // closed rather than silently fall back to `Overwrite`.
            None => Err(invalid_argument(
                "IfDestExists::MatchEtag missing match_etag",
            )),
        },
        Err(_) => Err(invalid_argument("unknown IfDestExistsKind discriminant")),
    }
}

pub fn checksum_set_to_proto(checksums: &ChecksumSet) -> Vec<pb::Checksum> {
    checksums
        .iter()
        .map(|(algorithm, value)| pb::Checksum {
            algorithm: algorithm.as_str().to_string(),
            value: value.to_vec(),
        })
        .collect()
}

pub fn checksum_set_from_proto(
    checksums: Vec<pb::Checksum>,
) -> ovstorage_plugin::Result<ChecksumSet> {
    let mut out = ChecksumSet::default();
    for checksum in checksums {
        let algorithm = ChecksumAlgorithm::new(checksum.algorithm)?;
        out.insert(algorithm, checksum.value);
    }
    Ok(out)
}

fn effective_permissions_to_proto(permissions: EffectivePermissions) -> pb::AccessOps {
    pb::AccessOps {
        read: permissions.contains(EffectivePermissions::READ),
        write: permissions.contains(EffectivePermissions::WRITE),
        delete: permissions.contains(EffectivePermissions::DELETE),
        update_metadata: permissions.contains(EffectivePermissions::UPDATE_METADATA),
    }
}

fn effective_permissions_from_proto(permissions: pb::AccessOps) -> EffectivePermissions {
    let mut out = EffectivePermissions::empty();
    if permissions.read {
        out |= EffectivePermissions::READ;
    }
    if permissions.write {
        out |= EffectivePermissions::WRITE;
    }
    if permissions.delete {
        out |= EffectivePermissions::DELETE;
    }
    if permissions.update_metadata {
        out |= EffectivePermissions::UPDATE_METADATA;
    }
    out
}

pub fn stat_options_to_proto(options: &StatOptions) -> pb::StatOptions {
    pb::StatOptions {
        full_metadata: options.full_metadata,
    }
}

pub fn stat_options_from_proto(options: Option<pb::StatOptions>) -> StatOptions {
    let options = options.unwrap_or_default();
    StatOptions {
        full_metadata: options.full_metadata,
    }
}

pub fn read_options_to_proto(options: &ReadOptions) -> pb::ReadOptions {
    pb::ReadOptions {
        if_match: options.if_match.clone(),
        range: options.range.as_ref().map(|range| pb::ByteRange {
            start: range.start,
            end_inclusive: range.end_inclusive,
        }),
    }
}

pub fn read_options_from_proto(options: Option<pb::ReadOptions>) -> ReadOptions {
    let options = options.unwrap_or_default();
    ReadOptions {
        if_match: options.if_match,
        range: options.range.map(|range| ByteRange {
            start: range.start,
            end_inclusive: range.end_inclusive,
        }),
        max_bytes: None,
    }
}

pub fn write_options_to_proto(options: &WriteOptions) -> pb::WriteOptions {
    pb::WriteOptions {
        if_dest: Some(if_dest_exists_to_proto(&options.if_dest)),
        size_hint: options.size_hint,
        user_metadata: options.user_metadata.clone().unwrap_or_default(),
        message: options.message.clone(),
    }
}

pub fn write_options_from_proto(
    options: Option<pb::WriteOptions>,
) -> ovstorage_plugin::Result<WriteOptions> {
    let options = options.unwrap_or_default();
    Ok(WriteOptions {
        if_dest: if_dest_exists_from_proto(options.if_dest)?,
        size_hint: options.size_hint,
        user_metadata: (!options.user_metadata.is_empty()).then_some(options.user_metadata),
        message: options.message,
    })
}

pub fn delete_options_to_proto(options: &DeleteOptions) -> pb::DeleteOptions {
    pb::DeleteOptions {
        if_match: options.if_match.clone(),
    }
}

pub fn delete_options_from_proto(options: Option<pb::DeleteOptions>) -> DeleteOptions {
    let options = options.unwrap_or_default();
    DeleteOptions {
        if_match: options.if_match,
    }
}

pub fn list_options_to_proto(options: &ListOptions) -> pb::ListOptions {
    pb::ListOptions {
        recursive: options.recursive,
        max_results: options.max_results,
        page_token: options.page_token.clone().unwrap_or_default(),
        full_metadata: options.full_metadata,
    }
}

pub fn list_options_from_proto(options: Option<pb::ListOptions>) -> ListOptions {
    let options = options.unwrap_or_default();
    ListOptions {
        recursive: options.recursive,
        max_results: options.max_results,
        page_token: nonempty(options.page_token),
        full_metadata: options.full_metadata,
    }
}

pub fn list_versions_options_to_proto(options: &ListVersionsOptions) -> pb::ListVersionsOptions {
    pb::ListVersionsOptions {
        max_results: options.max_results,
        page_token: options.page_token.clone().unwrap_or_default(),
    }
}

pub fn list_versions_options_from_proto(
    options: Option<pb::ListVersionsOptions>,
) -> ListVersionsOptions {
    let options = options.unwrap_or_default();
    ListVersionsOptions {
        max_results: options.max_results,
        page_token: nonempty(options.page_token),
    }
}

pub fn create_directory_options_to_proto(
    _options: &CreateDirectoryOptions,
) -> pb::CreateDirectoryOptions {
    pb::CreateDirectoryOptions {}
}

pub fn create_directory_options_from_proto(
    _options: Option<pb::CreateDirectoryOptions>,
) -> CreateDirectoryOptions {
    CreateDirectoryOptions::default()
}

pub fn delete_directory_options_to_proto(
    _options: &DeleteDirectoryOptions,
) -> pb::DeleteDirectoryOptions {
    pb::DeleteDirectoryOptions {}
}

pub fn delete_directory_options_from_proto(
    _options: Option<pb::DeleteDirectoryOptions>,
) -> DeleteDirectoryOptions {
    DeleteDirectoryOptions
}

pub fn copy_options_to_proto(options: &CopyOptions) -> pb::CopyOptions {
    pb::CopyOptions {
        if_source: options.if_source.clone(),
        if_dest: Some(if_dest_exists_to_proto(&options.if_dest)),
        message: options.message.clone(),
    }
}

pub fn copy_options_from_proto(
    options: Option<pb::CopyOptions>,
) -> ovstorage_plugin::Result<CopyOptions> {
    let options = options.unwrap_or_default();
    Ok(CopyOptions {
        if_source: options.if_source,
        if_dest: if_dest_exists_from_proto(options.if_dest)?,
        message: options.message,
    })
}

pub fn rename_options_to_proto(options: &RenameOptions) -> pb::RenameOptions {
    pb::RenameOptions {
        if_source: options.if_source.clone(),
        if_dest: Some(if_dest_exists_to_proto(&options.if_dest)),
        message: options.message.clone(),
    }
}

pub fn rename_options_from_proto(
    options: Option<pb::RenameOptions>,
) -> ovstorage_plugin::Result<RenameOptions> {
    let options = options.unwrap_or_default();
    Ok(RenameOptions {
        if_source: options.if_source,
        if_dest: if_dest_exists_from_proto(options.if_dest)?,
        message: options.message,
    })
}

pub fn update_metadata_options_from_proto(
    request: &pb::UpdateMetadataRequest,
) -> UpdateMetadataOptions {
    UpdateMetadataOptions {
        if_match: request.if_match.clone(),
        allow_rewrite_emulation: request.allow_rewrite_emulation,
        user_metadata_set: request.user_metadata_set.clone(),
        user_metadata_remove: request.user_metadata_remove.clone(),
        message: request.message.clone(),
    }
}

/// Default chunk size for streaming `Body::LocalFile` over the gRPC `Write` stream; sized
/// against the broker's max receive size while keeping per-chunk syscall cost low.
pub const LOCAL_FILE_CHUNK_BYTES: usize = 256 * 1024;

/// Lazy chunk iterator for the gRPC `Write` RPC. `Bytes` / `LocalFile` slice into
/// `LOCAL_FILE_CHUNK_BYTES` chunks; `Stream` passes through. No body is ever buffered into a
/// single `Vec<u8>`.
pub fn body_to_chunk_iter(
    body: Body,
) -> ovstorage_plugin::Result<Box<dyn Iterator<Item = ovstorage_plugin::Result<Vec<u8>>> + Send>> {
    match body {
        Body::Bytes(bytes) => Ok(Box::new(BytesChunkIter::new(bytes))),
        Body::LocalFile(path) => {
            let file = std::fs::File::open(&path).map_err(map_io)?;
            Ok(Box::new(LocalFileChunkIter::new(file)))
        }
        Body::Stream(stream) => Ok(Box::new(stream)),
    }
}

struct BytesChunkIter {
    bytes: Vec<u8>,
    offset: usize,
}

impl BytesChunkIter {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Iterator for BytesChunkIter {
    type Item = ovstorage_plugin::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let end = (self.offset + LOCAL_FILE_CHUNK_BYTES).min(self.bytes.len());
        let chunk = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Some(Ok(chunk))
    }
}

struct LocalFileChunkIter {
    file: std::fs::File,
    done: bool,
}

impl LocalFileChunkIter {
    fn new(file: std::fs::File) -> Self {
        Self { file, done: false }
    }
}

impl Iterator for LocalFileChunkIter {
    type Item = ovstorage_plugin::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        use std::io::Read;
        if self.done {
            return None;
        }
        let mut buf = vec![0u8; LOCAL_FILE_CHUNK_BYTES];
        match self.file.read(&mut buf) {
            Ok(0) => {
                self.done = true;
                None
            }
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf))
            }
            Err(err) => {
                self.done = true;
                Some(Err(map_io(err)))
            }
        }
    }
}

pub fn access_ops_to_proto(ops: &AccessOps) -> pb::AccessOps {
    pb::AccessOps {
        read: ops.read,
        write: ops.write,
        delete: ops.delete,
        update_metadata: ops.update_metadata,
    }
}

pub fn access_ops_from_proto(ops: Option<pb::AccessOps>) -> AccessOps {
    let ops = ops.unwrap_or_default();
    AccessOps {
        read: ops.read,
        write: ops.write,
        delete: ops.delete,
        update_metadata: ops.update_metadata,
    }
}

pub fn access_decision_to_proto(decision: &AccessDecision) -> pb::AccessDecision {
    pb::AccessDecision {
        allowed: decision.allowed,
        denied_ops: Some(access_ops_to_proto(&decision.denied_ops)),
        reason: decision.reason.clone().unwrap_or_default(),
    }
}

pub fn access_decision_from_proto(decision: Option<pb::AccessDecision>) -> AccessDecision {
    let decision = decision.unwrap_or_default();
    AccessDecision {
        allowed: decision.allowed,
        denied_ops: access_ops_from_proto(decision.denied_ops),
        reason: nonempty(decision.reason),
    }
}

pub fn list_page_to_proto(page: &ListPage) -> pb::ListPage {
    pb::ListPage {
        items: page.items.iter().map(object_info_to_proto).collect(),
        next_page_token: page.next_page_token.clone().unwrap_or_default(),
    }
}

pub fn list_page_from_proto(page: Option<pb::ListPage>) -> ovstorage_plugin::Result<ListPage> {
    let page = page.unwrap_or_default();
    Ok(ListPage {
        items: page
            .items
            .into_iter()
            .map(|item| object_info_from_proto(Some(item)))
            .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
        next_page_token: nonempty(page.next_page_token),
    })
}

pub fn address_root_to_proto(root: &AddressRoot) -> pb::AddressRoot {
    pb::AddressRoot {
        address: object_address_to_proto(&root.address),
        display_name: root.display_name.clone().unwrap_or_default(),
        backend_kind: root.backend_kind.clone(),
        connection_id: root
            .connection_id
            .as_ref()
            .map(|id| id.0.clone())
            .unwrap_or_default(),
        visibility: address_visibility_to_proto(root.visibility) as i32,
        user_metadata: root.user_metadata.clone(),
        capabilities: Some(capabilities_to_proto(&root.capabilities)),
    }
}

pub fn address_root_from_proto(root: pb::AddressRoot) -> ovstorage_plugin::Result<AddressRoot> {
    let connection_id = nonempty(root.connection_id).map(ConnectionId);
    let capabilities = root
        .capabilities
        .map(capabilities_from_proto)
        .transpose()?
        .unwrap_or_else(ovstorage_plugin::Capabilities::empty);
    Ok(AddressRoot {
        address: object_address_from_proto(root.address)?,
        display_name: nonempty(root.display_name),
        backend_kind: if root.backend_kind.is_empty() {
            "broker".into()
        } else {
            root.backend_kind
        },
        connection_id: connection_id.clone(),
        capabilities,
        source: RouteSource::BrokerDelivered {
            broker_principal: "broker".into(),
            connection_id: connection_id.unwrap_or_else(|| ConnectionId("broker-route".into())),
        },
        visibility: address_visibility_from_proto(root.visibility),
        user_metadata: root.user_metadata,
    })
}

pub fn address_roots_change_to_proto(change: &AddressRootsChange) -> pb::AddressRootsChange {
    let kind = match change {
        AddressRootsChange::Snapshot(roots) => {
            pb::address_roots_change::Kind::Snapshot(pb::AddressRootsSnapshot {
                roots: roots.iter().map(address_root_to_proto).collect(),
            })
        }
        AddressRootsChange::Added(roots) => {
            pb::address_roots_change::Kind::Added(pb::AddressRootsAdded {
                roots: roots.iter().map(address_root_to_proto).collect(),
            })
        }
        AddressRootsChange::Removed(roots) => {
            pb::address_roots_change::Kind::Removed(pb::AddressRootsRemoved {
                roots: roots.iter().map(address_root_to_proto).collect(),
            })
        }
    };
    pb::AddressRootsChange { kind: Some(kind) }
}

pub fn address_roots_change_from_proto(
    change: pb::AddressRootsChange,
) -> ovstorage_plugin::Result<AddressRootsChange> {
    let kind = change
        .kind
        .ok_or_else(|| invalid_argument("AddressRootsChange has no kind variant"))?;
    Ok(match kind {
        pb::address_roots_change::Kind::Snapshot(snap) => AddressRootsChange::Snapshot(
            snap.roots
                .into_iter()
                .map(address_root_from_proto)
                .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
        ),
        pb::address_roots_change::Kind::Added(added) => AddressRootsChange::Added(
            added
                .roots
                .into_iter()
                .map(address_root_from_proto)
                .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
        ),
        pb::address_roots_change::Kind::Removed(removed) => AddressRootsChange::Removed(
            removed
                .roots
                .into_iter()
                .map(address_root_from_proto)
                .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
        ),
    })
}

/// Convert a Rust `Capabilities` to proto. The wire mirrors the upstream backend's actual
/// per-route profile, not a generic always-true mask.
pub fn capabilities_to_proto(caps: &ovstorage_plugin::Capabilities) -> pb::Capabilities {
    pb::Capabilities {
        supports_if_match_write: caps.supports_if_match_write,
        supports_no_overwrite_write: caps.supports_no_overwrite_write,
        supports_native_metadata_patch: caps.supports_native_metadata_patch,
        supports_metadata_rewrite_emulation: caps.supports_metadata_rewrite_emulation,
        writes_are_atomic: caps.writes_are_atomic,
        supports_server_side_copy: caps.supports_server_side_copy,
        supports_server_side_rename: caps.supports_server_side_rename,
        supports_atomic_rename: caps.supports_atomic_rename,
        has_real_directories: caps.has_real_directories,
        supports_list: caps.supports_list,
        wants_list_backed_stat: caps.wants_list_backed_stat,
        supports_recursive_list: caps.supports_recursive_list,
        populates_subdirectory_metadata: caps.populates_subdirectory_metadata,
        supports_version_listing: caps.supports_version_listing,
        version_list_order: caps.version_list_order.as_ref().map(|order| {
            (match order {
                ovstorage_plugin::VersionListOrder::Newest => pb::VersionListOrder::Newest,
                ovstorage_plugin::VersionListOrder::Oldest => pb::VersionListOrder::Oldest,
                ovstorage_plugin::VersionListOrder::Unordered => pb::VersionListOrder::Unordered,
            }) as i32
        }),
        populates_effective_permissions_on_stat: caps.populates_effective_permissions_on_stat,
        supports_access_check: caps.supports_access_check,
        supports_watch_directory: caps.supports_watch_directory,
        watch_directory_kinds: Some(change_kind_set_to_proto(&caps.watch_directory_kinds)),
        watch_directory_resumable: caps.watch_directory_resumable,
        watch_directory_max_lag_millis: caps.watch_directory_max_lag.map(|d| d.as_millis() as u64),
        redirect_size_threshold: caps.redirect_size_threshold,
        supports_write: caps.supports_write,
        supports_write_stream: caps.supports_write_stream,
        supports_write_redirect: caps.supports_write_redirect,
        supports_delete: caps.supports_delete,
        supports_create_directory: caps.supports_create_directory,
        supports_delete_directory: caps.supports_delete_directory,
    }
}

pub fn capabilities_from_proto(
    caps: pb::Capabilities,
) -> ovstorage_plugin::Result<ovstorage_plugin::Capabilities> {
    let version_list_order = match caps.version_list_order {
        None => None,
        Some(value) => Some(
            match pb::VersionListOrder::try_from(value)
                .map_err(|_| invalid_argument("unknown VersionListOrder"))?
            {
                pb::VersionListOrder::Newest => ovstorage_plugin::VersionListOrder::Newest,
                pb::VersionListOrder::Oldest => ovstorage_plugin::VersionListOrder::Oldest,
                pb::VersionListOrder::Unordered => ovstorage_plugin::VersionListOrder::Unordered,
            },
        ),
    };
    Ok(ovstorage_plugin::Capabilities {
        supports_if_match_write: caps.supports_if_match_write,
        supports_no_overwrite_write: caps.supports_no_overwrite_write,
        supports_native_metadata_patch: caps.supports_native_metadata_patch,
        supports_metadata_rewrite_emulation: caps.supports_metadata_rewrite_emulation,
        writes_are_atomic: caps.writes_are_atomic,
        supports_server_side_copy: caps.supports_server_side_copy,
        supports_server_side_rename: caps.supports_server_side_rename,
        supports_atomic_rename: caps.supports_atomic_rename,
        has_real_directories: caps.has_real_directories,
        supports_list: caps.supports_list,
        wants_list_backed_stat: caps.wants_list_backed_stat,
        supports_recursive_list: caps.supports_recursive_list,
        populates_subdirectory_metadata: caps.populates_subdirectory_metadata,
        supports_version_listing: caps.supports_version_listing,
        version_list_order,
        populates_effective_permissions_on_stat: caps.populates_effective_permissions_on_stat,
        supports_access_check: caps.supports_access_check,
        supports_watch_directory: caps.supports_watch_directory,
        watch_directory_kinds: caps
            .watch_directory_kinds
            .map(change_kind_set_from_proto)
            .unwrap_or_else(ovstorage_plugin::ChangeKindSet::empty),
        watch_directory_resumable: caps.watch_directory_resumable,
        watch_directory_max_lag: caps
            .watch_directory_max_lag_millis
            .map(std::time::Duration::from_millis),
        redirect_size_threshold: caps.redirect_size_threshold,
        supports_write: caps.supports_write,
        supports_write_stream: caps.supports_write_stream,
        supports_write_redirect: caps.supports_write_redirect,
        supports_delete: caps.supports_delete,
        supports_create_directory: caps.supports_create_directory,
        supports_delete_directory: caps.supports_delete_directory,
    })
}

fn change_kind_set_to_proto(set: &ovstorage_plugin::ChangeKindSet) -> pb::ChangeKindSet {
    pb::ChangeKindSet {
        created: set.created,
        modified: set.modified,
        deleted: set.deleted,
        metadata_changed: set.metadata_changed,
    }
}

fn change_kind_set_from_proto(set: pb::ChangeKindSet) -> ovstorage_plugin::ChangeKindSet {
    ovstorage_plugin::ChangeKindSet {
        created: set.created,
        modified: set.modified,
        deleted: set.deleted,
        metadata_changed: set.metadata_changed,
    }
}

pub fn read_redirect_to_proto(redirect: &ovstorage_plugin::ReadRedirect) -> pb::ReadRedirect {
    pb::ReadRedirect {
        request: Some(http_request_to_proto(&redirect.request)),
        expires_at_unix_millis: system_time_to_millis_u64(redirect.expires_at),
        scope: Some(redirect_scope_to_proto(&redirect.scope)),
        audit_id: redirect.audit_id.clone(),
        policy_epoch: redirect.policy_epoch,
        response_parsing: Some(response_parsing_to_proto(&redirect.response_parsing)),
    }
}

pub fn read_redirect_from_proto(
    redirect: pb::ReadRedirect,
) -> ovstorage_plugin::Result<ovstorage_plugin::ReadRedirect> {
    Ok(ovstorage_plugin::ReadRedirect {
        request: http_request_from_proto(redirect.request)?,
        response_parsing: redirect
            .response_parsing
            .map(response_parsing_from_proto)
            .transpose()?
            .unwrap_or_default(),
        expires_at: millis_to_system_time_u64(redirect.expires_at_unix_millis),
        scope: redirect_scope_from_proto(redirect.scope)?,
        audit_id: redirect.audit_id,
        policy_epoch: redirect.policy_epoch,
    })
}

pub fn write_redirect_batch_to_proto(batch: &WriteRedirectBatch) -> pb::WriteRedirectBatch {
    pb::WriteRedirectBatch {
        redirects: batch
            .redirects
            .iter()
            .map(write_redirect_to_proto)
            .collect(),
        continuation: batch.continuation.clone(),
    }
}

pub fn write_redirect_batch_from_proto(
    batch: Option<pb::WriteRedirectBatch>,
) -> ovstorage_plugin::Result<WriteRedirectBatch> {
    let batch = batch.unwrap_or_default();
    Ok(WriteRedirectBatch {
        continuation: batch.continuation,
        redirects: batch
            .redirects
            .into_iter()
            .map(write_redirect_from_proto)
            .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
    })
}

pub fn redirect_result_batch_to_proto(batch: &RedirectResultBatch) -> pb::RedirectResultBatch {
    pb::RedirectResultBatch {
        results: batch
            .results
            .iter()
            .map(|result| pb::RedirectResult {
                status_code: u32::from(result.status_code),
                captured_headers: headers_to_proto(&result.captured_headers),
                captured_body: result.captured_body.clone(),
            })
            .collect(),
    }
}

pub fn redirect_result_batch_from_proto(
    batch: Option<pb::RedirectResultBatch>,
) -> ovstorage_plugin::Result<RedirectResultBatch> {
    let batch = batch.unwrap_or_default();
    Ok(RedirectResultBatch {
        results: batch
            .results
            .into_iter()
            .map(|result| {
                let status_code = u16::try_from(result.status_code).map_err(|_| {
                    invalid_argument("redirect result status code is outside the u16 range")
                })?;
                Ok(RedirectResult {
                    status_code,
                    captured_headers: headers_from_proto(result.captured_headers),
                    captured_body: result.captured_body,
                })
            })
            .collect::<ovstorage_plugin::Result<Vec<_>>>()?,
    })
}

pub fn write_result_to_proto(result: &WriteResult) -> pb::WriteResult {
    pb::WriteResult {
        info: Some(object_info_to_proto(&result.info)),
    }
}

pub fn write_result_from_proto(
    result: Option<pb::WriteResult>,
) -> ovstorage_plugin::Result<WriteResult> {
    let result = result.ok_or_else(|| invalid_argument("missing write result"))?;
    Ok(WriteResult {
        info: object_info_from_proto(result.info)?,
    })
}

pub fn watch_directory_request_to_proto(
    prefix: &Url,
    options: &WatchDirectoryOptions,
) -> pb::WatchDirectoryRequest {
    pb::WatchDirectoryRequest {
        prefix: object_address_to_proto(prefix),
        recursive: options.recursive,
        include_metadata_changes: options.include_metadata_changes,
        since: options
            .since
            .as_ref()
            .map(|cursor| cursor.0.clone())
            .unwrap_or_default(),
        poll_interval_millis: options.poll_interval.as_millis() as u64,
    }
}

pub fn watch_directory_options_from_proto(
    request: &pb::WatchDirectoryRequest,
) -> WatchDirectoryOptions {
    WatchDirectoryOptions {
        recursive: request.recursive,
        include_metadata_changes: request.include_metadata_changes,
        since: (!request.since.is_empty()).then_some(WatchDirectoryCursor(request.since.clone())),
        poll_interval: Duration::from_millis(request.poll_interval_millis.max(1)),
    }
}

pub fn change_event_to_proto(event: &ovstorage_plugin::ChangeEvent) -> pb::ChangeEvent {
    let event = match event {
        ovstorage_plugin::ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        } => pb::change_event::Event::Object(pb::ObjectChange {
            address: object_address_to_proto(address),
            kind: change_kind_to_proto(*kind) as i32,
            etag: etag.clone(),
            version: version.clone(),
            size: *size,
            mtime_unix_millis: mtime.map(system_time_to_millis),
            at_unix_millis: system_time_to_millis_u64(*at),
            cursor: cursor.0.clone(),
        }),
        ovstorage_plugin::ChangeEvent::Lapsed { since, cursor } => {
            pb::change_event::Event::Lapsed(pb::LapsedChange {
                since_unix_millis: since.map(system_time_to_millis_u64),
                cursor: cursor.0.clone(),
            })
        }
    };
    pb::ChangeEvent { event: Some(event) }
}

pub fn change_event_from_proto(
    event: Option<pb::ChangeEvent>,
) -> ovstorage_plugin::Result<ovstorage_plugin::ChangeEvent> {
    match event
        .ok_or_else(|| invalid_argument("missing change event"))?
        .event
        .ok_or_else(|| invalid_argument("missing change event variant"))?
    {
        pb::change_event::Event::Object(object) => Ok(ovstorage_plugin::ChangeEvent::Object {
            address: object_address_from_proto(object.address)?,
            kind: change_kind_from_proto(object.kind)?,
            etag: object.etag,
            version: object.version,
            size: object.size,
            mtime: object.mtime_unix_millis.map(millis_to_system_time),
            at: millis_to_system_time_u64(object.at_unix_millis),
            cursor: WatchDirectoryCursor(object.cursor),
        }),
        pb::change_event::Event::Lapsed(lapsed) => Ok(ovstorage_plugin::ChangeEvent::Lapsed {
            since: lapsed.since_unix_millis.map(millis_to_system_time_u64),
            cursor: WatchDirectoryCursor(lapsed.cursor),
        }),
    }
}

/// Convert an `AuthEvent` into the streaming `Auth` RPC envelope.
///
/// `Succeeded` is intentionally lossy on the wire: only `connection.id` propagates. Resolved
/// credential bytes flow via the unary `RegisterCredential` RPC, never embedded in the stream.
pub fn auth_event_to_proto(event: &ovstorage_plugin::AuthEvent) -> pb::AuthEventEnvelope {
    auth_event_to_proto_with_context(event, None, None, None)
}

/// Like [`auth_event_to_proto`] but populates `Failed`'s `ErrorDetail.address` / `audit_id` /
/// `policy_epoch` so operators can localise the failure. Non-`Failed` variants unchanged.
pub fn auth_event_to_proto_with_context(
    event: &ovstorage_plugin::AuthEvent,
    address: Option<&Url>,
    audit_id: Option<&str>,
    policy_epoch: Option<u64>,
) -> pb::AuthEventEnvelope {
    use ovstorage_plugin::AuthEvent as Ev;
    let event = match event {
        Ev::OpenBrowser { url, expires_at } => {
            pb::auth_event_envelope::Event::OpenBrowser(pb::AuthOpenBrowser {
                url: url.clone(),
                expires_at_unix_millis: system_time_to_millis_u64(*expires_at),
            })
        }
        Ev::DeviceCode {
            user_code,
            verification_url,
            expires_at,
            interval,
        } => pb::auth_event_envelope::Event::DeviceCode(pb::AuthDeviceCode {
            user_code: user_code.clone(),
            verification_url: verification_url.clone(),
            expires_at_unix_millis: system_time_to_millis_u64(*expires_at),
            interval_millis: interval.as_millis().min(u64::MAX as u128) as u64,
        }),
        Ev::Progress { message } => pb::auth_event_envelope::Event::Progress(pb::AuthProgress {
            message: message.clone(),
        }),
        Ev::Succeeded { connection, .. } => {
            pb::auth_event_envelope::Event::Succeeded(pb::AuthSucceeded {
                connection_id: connection.id.0.clone(),
            })
        }
        Ev::Failed { error } => pb::auth_event_envelope::Event::Failed(pb::AuthFailed {
            error: Some(pb::ErrorDetail {
                code: error_code_name(error.code()).into(),
                message: error.message().to_string(),
                address: address.map(|u| u.as_str().to_string()).unwrap_or_default(),
                audit_id: audit_id.map(str::to_string).unwrap_or_default(),
                policy_epoch,
                context: error.context().map(error_context_to_proto),
            }),
        }),
        Ev::Cancelled => pb::auth_event_envelope::Event::Cancelled(pb::AuthCancelled {}),
    };
    pb::AuthEventEnvelope { event: Some(event) }
}

/// Wire only carries `connection_id` for `Succeeded`; the SDK rebuilds the full `Connection`
/// before surfacing the event to the host.
pub fn auth_event_from_proto_partial(
    envelope: pb::AuthEventEnvelope,
) -> ovstorage_plugin::Result<AuthEventPartial> {
    use pb::auth_event_envelope::Event as Ev;
    let event = envelope
        .event
        .ok_or_else(|| invalid_argument("AuthEventEnvelope missing event variant"))?;
    Ok(match event {
        Ev::OpenBrowser(open) => AuthEventPartial::OpenBrowser {
            url: open.url,
            expires_at: millis_to_system_time_u64(open.expires_at_unix_millis),
        },
        Ev::DeviceCode(device) => AuthEventPartial::DeviceCode {
            user_code: device.user_code,
            verification_url: device.verification_url,
            expires_at: millis_to_system_time_u64(device.expires_at_unix_millis),
            interval: Duration::from_millis(device.interval_millis),
        },
        Ev::Progress(progress) => AuthEventPartial::Progress {
            message: progress.message,
        },
        Ev::Succeeded(succeeded) => AuthEventPartial::Succeeded {
            connection_id: succeeded.connection_id,
        },
        Ev::Failed(failed) => AuthEventPartial::Failed {
            error: failed
                .error
                .map(|detail| {
                    let mut error = Error::new(
                        error_code_from_name(&detail.code).unwrap_or(ErrorCode::Internal),
                        detail.message,
                    );
                    if let Some(context) = detail.context.and_then(error_context_from_proto) {
                        error = error.with_context(context);
                    }
                    error
                })
                .unwrap_or_else(|| Error::new(ErrorCode::Internal, "AuthFailed missing detail")),
        },
        Ev::Cancelled(_) => AuthEventPartial::Cancelled,
    })
}

/// Wire-shape of `AuthEvent` with `Succeeded` reduced to just `connection_id` — the resolved
/// credential travels on the separate unary `RegisterCredential` RPC. The SDK pairs the id
/// with the in-flight `Connection` to rebuild a full `AuthEvent::Succeeded`.
#[derive(Clone, Debug)]
pub enum AuthEventPartial {
    OpenBrowser {
        url: String,
        expires_at: SystemTime,
    },
    DeviceCode {
        user_code: String,
        verification_url: String,
        expires_at: SystemTime,
        interval: Duration,
    },
    Progress {
        message: String,
    },
    Succeeded {
        connection_id: String,
    },
    Failed {
        error: Error,
    },
    Cancelled,
}

pub fn error_to_status(error: Error) -> tonic::Status {
    error_to_status_with_context(error, None, None, None)
}

/// Like [`error_to_status`] but populates `pb::ErrorDetail.address` / `audit_id` /
/// `policy_epoch` so operators get matching context on the wire for a failing request.
pub fn error_to_status_with_context(
    error: Error,
    address: Option<&Url>,
    audit_id: Option<&str>,
    policy_epoch: Option<u64>,
) -> tonic::Status {
    let code = error_code_to_status_code(error.code());
    let message = format!("{}: {}", error_code_name(error.code()), error.message());
    let context = error.context().map(error_context_to_proto);
    let detail = pb::ErrorDetail {
        code: error_code_name(error.code()).into(),
        message: error.message().to_string(),
        address: address.map(|u| u.as_str().to_string()).unwrap_or_default(),
        audit_id: audit_id.map(str::to_string).unwrap_or_default(),
        policy_epoch,
        context,
    };
    tonic::Status::with_details(code, message, detail.encode_to_vec().into())
}

pub fn status_to_error(status: tonic::Status) -> Error {
    let fallback_code = status_code_to_error_code(status.code());
    match pb::ErrorDetail::decode(status.details()) {
        Ok(detail) => {
            let mut error = Error::new(
                error_code_from_name(&detail.code).unwrap_or(fallback_code),
                if detail.message.is_empty() {
                    status.message().to_string()
                } else {
                    detail.message
                },
            );
            if let Some(context) = detail.context.and_then(error_context_from_proto) {
                error = error.with_context(context);
            }
            error
        }
        Err(_) => Error::new(fallback_code, status.message().to_string()),
    }
}

fn error_code_to_status_code(code: ErrorCode) -> tonic::Code {
    match code {
        ErrorCode::NotFound | ErrorCode::NoRoute => tonic::Code::NotFound,
        ErrorCode::AlreadyExists => tonic::Code::AlreadyExists,
        ErrorCode::PermissionDenied | ErrorCode::PluginRejected => tonic::Code::PermissionDenied,
        ErrorCode::AuthRequired
        | ErrorCode::AuthExpired
        | ErrorCode::CredentialExpired
        | ErrorCode::CredentialUnavailable => tonic::Code::Unauthenticated,
        ErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        ErrorCode::Unsupported => tonic::Code::Unimplemented,
        ErrorCode::BrokerUnavailable
        | ErrorCode::Transient
        | ErrorCode::NetworkFilesystemRefused => tonic::Code::Unavailable,
        ErrorCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        ErrorCode::Cancelled | ErrorCode::AuthCancelled => tonic::Code::Cancelled,
        ErrorCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        ErrorCode::PolicyEpochStale
        | ErrorCode::PreconditionFailed
        | ErrorCode::ObjectModified
        | ErrorCode::ContentMismatch
        | ErrorCode::RedirectExpired
        | ErrorCode::StagingExpired
        | ErrorCode::AuthorizationLeaseExpired
        | ErrorCode::DirectoryNotEmpty
        | ErrorCode::IncompatibleType
        | ErrorCode::AliasChainTooLong
        | ErrorCode::NotConfigured
        | ErrorCode::StateRootUnavailable
        | ErrorCode::BrokerRequired => tonic::Code::FailedPrecondition,
        ErrorCode::Conflict
        | ErrorCode::RouteConflict
        | ErrorCode::Locked
        | ErrorCode::CommitAmbiguous
        | ErrorCode::CacheLockContention => tonic::Code::Aborted,
        ErrorCode::ContentChecksumMismatch
        | ErrorCode::IntegrityFailure
        | ErrorCode::CacheCorrupt => tonic::Code::DataLoss,
        ErrorCode::Internal => tonic::Code::Internal,
        // Defensive: future ErrorCode variants surface as Internal
        // until this match is updated. `ErrorCode` is `#[non_exhaustive]`.
        _ => tonic::Code::Internal,
    }
}

fn error_context_to_proto(context: &ovstorage_plugin::ErrorContext) -> pb::error_detail::Context {
    match context {
        ovstorage_plugin::ErrorContext::Identity { new_etag } => {
            pb::error_detail::Context::Identity(pb::ErrorIdentityContext {
                new_etag: new_etag.clone(),
            })
        }
        ovstorage_plugin::ErrorContext::Auth {
            connection_id,
            reason,
            expired_at,
        } => pb::error_detail::Context::Auth(pb::ErrorAuthContext {
            connection_id: connection_id.0.clone(),
            reason: reason.clone(),
            expired_at_unix_millis: expired_at.map(system_time_to_millis_u64),
        }),
    }
}

fn error_context_from_proto(
    context: pb::error_detail::Context,
) -> Option<ovstorage_plugin::ErrorContext> {
    match context {
        pb::error_detail::Context::Identity(identity) => {
            Some(ovstorage_plugin::ErrorContext::Identity {
                new_etag: identity.new_etag,
            })
        }
        pb::error_detail::Context::Auth(auth) => Some(ovstorage_plugin::ErrorContext::Auth {
            connection_id: ConnectionId(auth.connection_id),
            reason: auth.reason,
            expired_at: auth.expired_at_unix_millis.map(millis_to_system_time_u64),
        }),
    }
}

fn http_request_to_proto(request: &ovstorage_plugin::HttpRequest) -> pb::HttpRequest {
    pb::HttpRequest {
        method: request.method.clone(),
        url: request.url.clone(),
        headers: headers_to_proto(&request.headers),
    }
}

fn http_request_from_proto(
    request: Option<pb::HttpRequest>,
) -> ovstorage_plugin::Result<ovstorage_plugin::HttpRequest> {
    let request = request.ok_or_else(|| invalid_argument("missing HTTP redirect request"))?;
    Ok(ovstorage_plugin::HttpRequest {
        method: request.method,
        url: request.url,
        headers: headers_from_proto(request.headers),
    })
}

fn redirect_scope_to_proto(scope: &RedirectScope) -> pb::RedirectScope {
    pb::RedirectScope {
        physical_url_prefix: scope.physical_url_prefix.clone(),
        operations: Some(access_ops_to_proto(&scope.operations)),
        expires_at_unix_millis: system_time_to_millis_u64(scope.expires_at),
    }
}

fn redirect_scope_from_proto(
    scope: Option<pb::RedirectScope>,
) -> ovstorage_plugin::Result<RedirectScope> {
    let scope = scope.ok_or_else(|| invalid_argument("missing redirect scope"))?;
    Ok(RedirectScope {
        physical_url_prefix: scope.physical_url_prefix,
        operations: access_ops_from_proto(scope.operations),
        expires_at: millis_to_system_time_u64(scope.expires_at_unix_millis),
    })
}

fn write_redirect_to_proto(redirect: &WriteRedirect) -> pb::WriteRedirect {
    pb::WriteRedirect {
        request: Some(http_request_to_proto(&redirect.request)),
        body_source: Some(redirect_body_source_to_proto(&redirect.body_source)),
        expires_at_unix_millis: system_time_to_millis_u64(redirect.expires_at),
        scope: Some(redirect_scope_to_proto(&redirect.scope)),
        audit_id: redirect.audit_id.clone(),
        policy_epoch: redirect.policy_epoch,
        result_capture: Some(result_capture_to_proto(&redirect.result_capture)),
    }
}

fn write_redirect_from_proto(
    redirect: pb::WriteRedirect,
) -> ovstorage_plugin::Result<WriteRedirect> {
    Ok(WriteRedirect {
        request: http_request_from_proto(redirect.request)?,
        body_source: redirect_body_source_from_proto(redirect.body_source)?,
        result_capture: redirect
            .result_capture
            .map(result_capture_from_proto)
            .unwrap_or_default(),
        expires_at: millis_to_system_time_u64(redirect.expires_at_unix_millis),
        scope: redirect_scope_from_proto(redirect.scope)?,
        audit_id: redirect.audit_id,
        policy_epoch: redirect.policy_epoch,
    })
}

fn response_parsing_to_proto(parsing: &ovstorage_plugin::ResponseParsing) -> pb::ResponseParsing {
    pb::ResponseParsing {
        etag_header: parsing.etag_header.clone(),
        version_header: parsing.version_header.clone(),
        size_header: parsing.size_header.clone(),
        mtime_header: parsing.mtime_header.clone(),
        mtime_format: mtime_format_to_proto(parsing.mtime_format) as i32,
        system_metadata_headers: parsing.system_metadata_headers.clone(),
        content_checksum_header: parsing.content_checksum_header.clone(),
        content_checksum_algorithm: parsing
            .content_checksum_algorithm
            .as_ref()
            .map(|alg| alg.as_str().to_string()),
        checksum_headers: parsing
            .checksum_headers
            .iter()
            .map(|(alg, header)| pb::ChecksumHeader {
                algorithm: alg.as_str().to_string(),
                header: header.clone(),
            })
            .collect(),
    }
}

fn response_parsing_from_proto(
    parsing: pb::ResponseParsing,
) -> ovstorage_plugin::Result<ovstorage_plugin::ResponseParsing> {
    let mut checksum_headers = std::collections::HashMap::new();
    for entry in parsing.checksum_headers {
        let algorithm = ChecksumAlgorithm::new(entry.algorithm)?;
        checksum_headers.insert(algorithm, entry.header);
    }
    let content_checksum_algorithm = parsing
        .content_checksum_algorithm
        .map(ChecksumAlgorithm::new)
        .transpose()?;
    Ok(ovstorage_plugin::ResponseParsing {
        etag_header: parsing.etag_header,
        version_header: parsing.version_header,
        size_header: parsing.size_header,
        mtime_header: parsing.mtime_header,
        mtime_format: mtime_format_from_proto(parsing.mtime_format)?,
        system_metadata_headers: parsing.system_metadata_headers,
        content_checksum_header: parsing.content_checksum_header,
        content_checksum_algorithm,
        checksum_headers,
    })
}

fn mtime_format_to_proto(format: ovstorage_plugin::MtimeFormat) -> pb::MtimeFormat {
    match format {
        ovstorage_plugin::MtimeFormat::Rfc1123 => pb::MtimeFormat::Rfc1123,
        ovstorage_plugin::MtimeFormat::Iso8601 => pb::MtimeFormat::Iso8601,
        ovstorage_plugin::MtimeFormat::UnixSeconds => pb::MtimeFormat::UnixSeconds,
    }
}

fn mtime_format_from_proto(value: i32) -> ovstorage_plugin::Result<ovstorage_plugin::MtimeFormat> {
    match pb::MtimeFormat::try_from(value) {
        Ok(pb::MtimeFormat::Rfc1123) => Ok(ovstorage_plugin::MtimeFormat::Rfc1123),
        Ok(pb::MtimeFormat::Iso8601) => Ok(ovstorage_plugin::MtimeFormat::Iso8601),
        Ok(pb::MtimeFormat::UnixSeconds) => Ok(ovstorage_plugin::MtimeFormat::UnixSeconds),
        Err(_) => Err(invalid_argument("unknown MtimeFormat")),
    }
}

fn result_capture_to_proto(capture: &ovstorage_plugin::ResultCapture) -> pb::ResultCapture {
    pb::ResultCapture {
        headers: capture.headers.clone(),
        body_max_bytes: capture.body_max_bytes,
    }
}

fn result_capture_from_proto(capture: pb::ResultCapture) -> ovstorage_plugin::ResultCapture {
    ovstorage_plugin::ResultCapture {
        headers: capture.headers,
        body_max_bytes: capture.body_max_bytes,
    }
}

fn redirect_body_source_to_proto(source: &RedirectBodySource) -> pb::RedirectBodySource {
    let source = match source {
        RedirectBodySource::Empty => pb::redirect_body_source::Source::Empty(pb::Empty {}),
        RedirectBodySource::UserBytes { offset, len } => {
            pb::redirect_body_source::Source::UserBytes(pb::UserBytes {
                offset: *offset,
                len: *len,
            })
        }
        RedirectBodySource::Inline(bytes) => {
            pb::redirect_body_source::Source::InlineBytes(bytes.clone())
        }
    };
    pb::RedirectBodySource {
        source: Some(source),
    }
}

fn redirect_body_source_from_proto(
    source: Option<pb::RedirectBodySource>,
) -> ovstorage_plugin::Result<RedirectBodySource> {
    match source
        .ok_or_else(|| invalid_argument("missing redirect body source"))?
        .source
        .ok_or_else(|| invalid_argument("missing redirect body source variant"))?
    {
        pb::redirect_body_source::Source::Empty(_) => Ok(RedirectBodySource::Empty),
        pb::redirect_body_source::Source::UserBytes(value) => Ok(RedirectBodySource::UserBytes {
            offset: value.offset,
            len: value.len,
        }),
        pb::redirect_body_source::Source::InlineBytes(bytes) => {
            Ok(RedirectBodySource::Inline(bytes))
        }
    }
}

fn headers_to_proto(headers: &[(String, String)]) -> Vec<pb::Header> {
    headers
        .iter()
        .map(|(name, value)| pb::Header {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

fn headers_from_proto(headers: Vec<pb::Header>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect()
}

fn address_visibility_to_proto(visibility: AddressVisibility) -> pb::AddressVisibility {
    match visibility {
        AddressVisibility::Visible => pb::AddressVisibility::Visible,
        AddressVisibility::Hidden => pb::AddressVisibility::Hidden,
        AddressVisibility::Suppressed => pb::AddressVisibility::Suppressed,
    }
}

fn address_visibility_from_proto(visibility: i32) -> AddressVisibility {
    match pb::AddressVisibility::try_from(visibility) {
        Ok(pb::AddressVisibility::Visible) => AddressVisibility::Visible,
        Ok(pb::AddressVisibility::Hidden) => AddressVisibility::Hidden,
        Ok(pb::AddressVisibility::Suppressed) => AddressVisibility::Suppressed,
        Err(_) => AddressVisibility::Suppressed,
    }
}

fn change_kind_to_proto(kind: ovstorage_plugin::ChangeKind) -> pb::ChangeKind {
    match kind {
        ovstorage_plugin::ChangeKind::Created => pb::ChangeKind::Created,
        ovstorage_plugin::ChangeKind::Modified => pb::ChangeKind::Modified,
        ovstorage_plugin::ChangeKind::Deleted => pb::ChangeKind::Deleted,
        ovstorage_plugin::ChangeKind::MetadataChanged => pb::ChangeKind::MetadataChanged,
    }
}

fn change_kind_from_proto(kind: i32) -> ovstorage_plugin::Result<ovstorage_plugin::ChangeKind> {
    match pb::ChangeKind::try_from(kind) {
        Ok(pb::ChangeKind::Created) => Ok(ovstorage_plugin::ChangeKind::Created),
        Ok(pb::ChangeKind::Modified) => Ok(ovstorage_plugin::ChangeKind::Modified),
        Ok(pb::ChangeKind::Deleted) => Ok(ovstorage_plugin::ChangeKind::Deleted),
        Ok(pb::ChangeKind::MetadataChanged) => Ok(ovstorage_plugin::ChangeKind::MetadataChanged),
        Err(_) => Err(invalid_argument("unknown ChangeKind")),
    }
}

/// Signed millis since the Unix epoch. Pre-epoch times (rare; file plugin
/// clock skew, etc.) become negative; everything else fits in `i64`.
fn system_time_to_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_millis())
            .map(|m| -m)
            .unwrap_or(i64::MIN),
    }
}

fn millis_to_system_time(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}

/// Unsigned-millis variant for the expiry / event-time wire fields. These
/// fields encode future or recent timestamps that must be non-negative;
/// any pre-epoch input clamps to 0.
fn system_time_to_millis_u64(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn millis_to_system_time_u64(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn invalid_argument(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn map_io(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotFound => "NotFound",
        ErrorCode::AlreadyExists => "AlreadyExists",
        ErrorCode::PermissionDenied => "PermissionDenied",
        ErrorCode::PreconditionFailed => "PreconditionFailed",
        ErrorCode::Conflict => "Conflict",
        ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
        ErrorCode::Unsupported => "Unsupported",
        ErrorCode::InvalidArgument => "InvalidArgument",
        ErrorCode::IncompatibleType => "IncompatibleType",
        ErrorCode::Locked => "Locked",
        ErrorCode::Cancelled => "Cancelled",
        ErrorCode::DeadlineExceeded => "DeadlineExceeded",
        ErrorCode::Transient => "Transient",
        ErrorCode::ResourceExhausted => "ResourceExhausted",
        ErrorCode::IntegrityFailure => "IntegrityFailure",
        ErrorCode::Internal => "Internal",
        ErrorCode::BrokerUnavailable => "BrokerUnavailable",
        ErrorCode::BrokerRequired => "BrokerRequired",
        ErrorCode::RedirectExpired => "RedirectExpired",
        ErrorCode::PolicyEpochStale => "PolicyEpochStale",
        ErrorCode::AuthorizationLeaseExpired => "AuthorizationLeaseExpired",
        ErrorCode::CacheCorrupt => "CacheCorrupt",
        ErrorCode::StagingExpired => "StagingExpired",
        ErrorCode::CommitAmbiguous => "CommitAmbiguous",
        ErrorCode::CacheLockContention => "CacheLockContention",
        ErrorCode::StateRootUnavailable => "StateRootUnavailable",
        ErrorCode::NetworkFilesystemRefused => "NetworkFilesystemRefused",
        ErrorCode::ObjectModified => "ObjectModified",
        ErrorCode::NoRoute => "NoRoute",
        ErrorCode::RouteConflict => "RouteConflict",
        ErrorCode::NotConfigured => "NotConfigured",
        ErrorCode::AliasChainTooLong => "AliasChainTooLong",
        ErrorCode::CredentialExpired => "CredentialExpired",
        ErrorCode::CredentialUnavailable => "CredentialUnavailable",
        ErrorCode::AuthRequired => "AuthRequired",
        ErrorCode::AuthCancelled => "AuthCancelled",
        ErrorCode::AuthExpired => "AuthExpired",
        ErrorCode::ContentMismatch => "ContentMismatch",
        ErrorCode::ContentChecksumMismatch => "ContentChecksumMismatch",
        ErrorCode::PluginRejected => "PluginRejected",
        // Defensive: a future ErrorCode variant surfaces as a generic
        // wire name rather than failing to compile a published binary.
        // Add the explicit arm above when the variant lands.
        _ => "Unknown",
    }
}

fn error_code_from_name(name: &str) -> Option<ErrorCode> {
    match name {
        "NotFound" => Some(ErrorCode::NotFound),
        "AlreadyExists" => Some(ErrorCode::AlreadyExists),
        "PermissionDenied" => Some(ErrorCode::PermissionDenied),
        "PreconditionFailed" => Some(ErrorCode::PreconditionFailed),
        "Conflict" => Some(ErrorCode::Conflict),
        "DirectoryNotEmpty" => Some(ErrorCode::DirectoryNotEmpty),
        "Unsupported" => Some(ErrorCode::Unsupported),
        "InvalidArgument" => Some(ErrorCode::InvalidArgument),
        "IncompatibleType" => Some(ErrorCode::IncompatibleType),
        "Locked" => Some(ErrorCode::Locked),
        "Cancelled" => Some(ErrorCode::Cancelled),
        "DeadlineExceeded" => Some(ErrorCode::DeadlineExceeded),
        "Transient" => Some(ErrorCode::Transient),
        "ResourceExhausted" => Some(ErrorCode::ResourceExhausted),
        "IntegrityFailure" => Some(ErrorCode::IntegrityFailure),
        "Internal" => Some(ErrorCode::Internal),
        "BrokerUnavailable" => Some(ErrorCode::BrokerUnavailable),
        "BrokerRequired" => Some(ErrorCode::BrokerRequired),
        "RedirectExpired" => Some(ErrorCode::RedirectExpired),
        "PolicyEpochStale" => Some(ErrorCode::PolicyEpochStale),
        "AuthorizationLeaseExpired" => Some(ErrorCode::AuthorizationLeaseExpired),
        "CacheCorrupt" => Some(ErrorCode::CacheCorrupt),
        "StagingExpired" => Some(ErrorCode::StagingExpired),
        "CommitAmbiguous" => Some(ErrorCode::CommitAmbiguous),
        "CacheLockContention" => Some(ErrorCode::CacheLockContention),
        "StateRootUnavailable" => Some(ErrorCode::StateRootUnavailable),
        "NetworkFilesystemRefused" => Some(ErrorCode::NetworkFilesystemRefused),
        "ObjectModified" => Some(ErrorCode::ObjectModified),
        "NoRoute" => Some(ErrorCode::NoRoute),
        "RouteConflict" => Some(ErrorCode::RouteConflict),
        "NotConfigured" => Some(ErrorCode::NotConfigured),
        "AliasChainTooLong" => Some(ErrorCode::AliasChainTooLong),
        "CredentialExpired" => Some(ErrorCode::CredentialExpired),
        "CredentialUnavailable" => Some(ErrorCode::CredentialUnavailable),
        "AuthRequired" => Some(ErrorCode::AuthRequired),
        "AuthCancelled" => Some(ErrorCode::AuthCancelled),
        "AuthExpired" => Some(ErrorCode::AuthExpired),
        "ContentMismatch" => Some(ErrorCode::ContentMismatch),
        "ContentChecksumMismatch" => Some(ErrorCode::ContentChecksumMismatch),
        "PluginRejected" => Some(ErrorCode::PluginRejected),
        _ => None,
    }
}

fn status_code_to_error_code(code: tonic::Code) -> ErrorCode {
    match code {
        tonic::Code::NotFound => ErrorCode::NotFound,
        tonic::Code::AlreadyExists => ErrorCode::AlreadyExists,
        tonic::Code::PermissionDenied => ErrorCode::PermissionDenied,
        tonic::Code::Unauthenticated => ErrorCode::AuthRequired,
        tonic::Code::InvalidArgument => ErrorCode::InvalidArgument,
        tonic::Code::Unimplemented => ErrorCode::Unsupported,
        tonic::Code::Unavailable => ErrorCode::BrokerUnavailable,
        tonic::Code::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        tonic::Code::Cancelled => ErrorCode::Cancelled,
        tonic::Code::ResourceExhausted => ErrorCode::ResourceExhausted,
        tonic::Code::FailedPrecondition => ErrorCode::PreconditionFailed,
        tonic::Code::Aborted => ErrorCode::Conflict,
        tonic::Code::DataLoss => ErrorCode::IntegrityFailure,
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_v2() {
        assert_eq!(PROTOCOL_V2, ProtocolVersion { major: 2, minor: 0 });
    }

    #[test]
    fn object_info_round_trips_flat_fields() {
        let url = address::parse("file:///tmp/x").unwrap();
        let info = ObjectInfo {
            address: url,
            kind: ObjectKind::File,
            etag: Some("e1".into()),
            version: None,
            size: Some(7),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        let proto = object_info_to_proto(&info);
        let back = object_info_from_proto(Some(proto)).unwrap();
        assert_eq!(back.etag.as_deref(), Some("e1"));
        assert_eq!(back.size, Some(7));
    }

    #[test]
    fn checksum_algorithms_round_trip_as_strings() {
        let mut checksums = ChecksumSet::default();
        checksums.insert(ChecksumAlgorithm::new("crc64-nvme").unwrap(), vec![1, 2, 3]);
        let proto = checksum_set_to_proto(&checksums);
        assert_eq!(proto[0].algorithm, "crc64nvme");

        let round_tripped = checksum_set_from_proto(proto).unwrap();
        assert_eq!(
            round_tripped
                .get(&ChecksumAlgorithm::new("crc64nvme").unwrap())
                .unwrap(),
            &[1, 2, 3]
        );
    }

    #[test]
    fn error_status_preserves_core_code_class() {
        let status = error_to_status(Error::new(ErrorCode::PermissionDenied, "denied"));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status_to_error(status).code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn error_status_preserves_core_code_details() {
        let status = error_to_status(Error::new(ErrorCode::NoRoute, "missing route"));
        assert_eq!(status.code(), tonic::Code::NotFound);
        let decoded = status_to_error(status);
        assert_eq!(decoded.code(), ErrorCode::NoRoute);
        assert_eq!(decoded.message(), "missing route");

        let status = error_to_status(Error::new(ErrorCode::AuthExpired, "token expired"));
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(status_to_error(status).code(), ErrorCode::AuthExpired);
    }

    #[test]
    fn object_kind_round_trips_through_object_info_proto() {
        let url = address::parse("file:///tmp/x").unwrap();
        for kind in [
            ObjectKind::File,
            ObjectKind::Directory,
            ObjectKind::DirectoryMarker,
            ObjectKind::DirectoryInferred,
        ] {
            let info = ObjectInfo {
                address: url.clone(),
                kind,
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
            let proto = object_info_to_proto(&info);
            let back = object_info_from_proto(Some(proto)).unwrap();
            assert_eq!(back.kind, kind, "round-trip mismatch for {kind:?}");
        }
    }

    #[test]
    fn object_kind_unspecified_proto_value_decodes_as_file() {
        // Default-constructed proto carries `kind = 0` (File) — must decode File.
        let proto = pb::ObjectInfo {
            address: "file:///tmp/x".into(),
            ..Default::default()
        };
        let info = object_info_from_proto(Some(proto)).unwrap();
        assert_eq!(info.kind, ObjectKind::File);
    }

    #[test]
    fn status_without_details_uses_grpc_fallback_class() {
        let status = tonic::Status::unauthenticated("login required");
        let decoded = status_to_error(status);
        assert_eq!(decoded.code(), ErrorCode::AuthRequired);
        assert_eq!(decoded.message(), "login required");
    }

    #[test]
    fn capability_metadata_round_trip_for_each_variant() {
        for cap in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
            InteractiveAuthCapability::Browser,
        ] {
            let value = capability_metadata_value(cap);
            let mut map = tonic::metadata::MetadataMap::new();
            map.insert(X_OV_IAUTH, value);
            assert_eq!(
                capability_from_metadata(&map),
                cap,
                "round-trip mismatch for {cap:?}"
            );
        }
    }

    #[test]
    fn capability_from_absent_metadata_defaults_to_browser() {
        let map = tonic::metadata::MetadataMap::new();
        assert_eq!(
            capability_from_metadata(&map),
            InteractiveAuthCapability::Browser
        );
    }

    #[test]
    fn capability_from_unknown_value_defaults_to_browser() {
        let mut map = tonic::metadata::MetadataMap::new();
        map.insert(
            X_OV_IAUTH,
            tonic::metadata::MetadataValue::from_static("bogus"),
        );
        assert_eq!(
            capability_from_metadata(&map),
            InteractiveAuthCapability::Browser
        );
    }

    #[test]
    fn capability_metadata_header_name_is_x_ov_iauth() {
        // Lowercase ASCII per HTTP/2 wire encoding; pin the exact header name (no longer prefix).
        assert_eq!(X_OV_IAUTH, "x-ov-iauth");
    }

    #[test]
    fn body_bytes_chunks_at_local_file_chunk_size() {
        let body = Body::Bytes(vec![0; LOCAL_FILE_CHUNK_BYTES * 2 + 1]);
        let chunks: Vec<Vec<u8>> = body_to_chunk_iter(body)
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), LOCAL_FILE_CHUNK_BYTES);
        assert_eq!(chunks[1].len(), LOCAL_FILE_CHUNK_BYTES);
        assert_eq!(chunks[2].len(), 1);
    }

    #[test]
    fn body_bytes_empty_yields_no_chunks() {
        let body = Body::Bytes(Vec::new());
        let chunks: Vec<Vec<u8>> = body_to_chunk_iter(body)
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        assert!(chunks.is_empty());
    }

    #[test]
    fn body_bytes_at_chunk_boundary_yields_one_chunk() {
        let body = Body::Bytes(vec![0; LOCAL_FILE_CHUNK_BYTES]);
        let chunks: Vec<Vec<u8>> = body_to_chunk_iter(body)
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), LOCAL_FILE_CHUNK_BYTES);
    }

    #[test]
    fn read_redirect_round_trips_non_default_response_parsing() {
        use ovstorage_plugin::{HttpRequest, MtimeFormat, ResponseParsing};
        let mut checksum_headers = std::collections::HashMap::new();
        checksum_headers.insert(
            ChecksumAlgorithm::new("sha256").unwrap(),
            "x-amz-checksum-sha256".into(),
        );
        checksum_headers.insert(
            ChecksumAlgorithm::new("crc32c").unwrap(),
            "x-amz-checksum-crc32c".into(),
        );
        let parsing = ResponseParsing {
            etag_header: Some("x-amz-etag".into()),
            version_header: Some("x-amz-version-id".into()),
            size_header: Some("x-amz-size".into()),
            mtime_header: Some("x-amz-mtime".into()),
            mtime_format: MtimeFormat::Iso8601,
            system_metadata_headers: vec!["x-meta-storage-class".into()],
            content_checksum_header: Some("x-amz-content-sha256".into()),
            content_checksum_algorithm: Some(ChecksumAlgorithm::new("sha256").unwrap()),
            checksum_headers,
        };
        let redirect = ovstorage_plugin::ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url: "https://example.com/x".into(),
                headers: vec![],
            },
            response_parsing: parsing.clone(),
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            scope: RedirectScope {
                physical_url_prefix: "https://example.com".into(),
                operations: AccessOps::default(),
                expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            },
            audit_id: "audit-1".into(),
            policy_epoch: 7,
        };
        let proto = read_redirect_to_proto(&redirect);
        let back = read_redirect_from_proto(proto).unwrap();
        assert_eq!(back.response_parsing, parsing);
    }

    #[test]
    fn write_redirect_round_trips_non_default_result_capture() {
        use ovstorage_plugin::{HttpRequest, ResultCapture};
        let capture = ResultCapture {
            headers: vec!["etag".into(), "x-amz-checksum-sha256".into()],
            body_max_bytes: 16_384,
        };
        let redirect = WriteRedirect {
            request: HttpRequest {
                method: "PUT".into(),
                url: "https://example.com/upload".into(),
                headers: vec![],
            },
            body_source: RedirectBodySource::Empty,
            result_capture: capture.clone(),
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            scope: RedirectScope {
                physical_url_prefix: "https://example.com".into(),
                operations: AccessOps::default(),
                expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            },
            audit_id: "audit-2".into(),
            policy_epoch: 9,
        };
        let proto = write_redirect_to_proto(&redirect);
        let back = write_redirect_from_proto(proto).unwrap();
        assert_eq!(back.result_capture, capture);
    }

    #[test]
    fn error_context_identity_round_trips() {
        let error = Error::new(ErrorCode::ObjectModified, "stale identity").with_context(
            ovstorage_plugin::ErrorContext::Identity {
                new_etag: Some("new-etag".into()),
            },
        );
        let status = error_to_status(error);
        let decoded = status_to_error(status);
        assert_eq!(decoded.code(), ErrorCode::ObjectModified);
        match decoded.context() {
            Some(ovstorage_plugin::ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), Some("new-etag"));
            }
            other => panic!("unexpected context: {other:?}"),
        }
    }

    #[test]
    fn error_context_auth_round_trips() {
        let expired = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_500);
        let error = Error::new(ErrorCode::AuthExpired, "token expired").with_context(
            ovstorage_plugin::ErrorContext::Auth {
                connection_id: ConnectionId("conn-42".into()),
                reason: Some("refresh_failed".into()),
                expired_at: Some(expired),
            },
        );
        let status = error_to_status(error);
        let decoded = status_to_error(status);
        assert_eq!(decoded.code(), ErrorCode::AuthExpired);
        match decoded.context() {
            Some(ovstorage_plugin::ErrorContext::Auth {
                connection_id,
                reason,
                expired_at,
            }) => {
                assert_eq!(connection_id.0, "conn-42");
                assert_eq!(reason.as_deref(), Some("refresh_failed"));
                assert_eq!(*expired_at, Some(expired));
            }
            other => panic!("unexpected context: {other:?}"),
        }
    }

    #[test]
    fn error_code_to_status_code_table() {
        let cases: &[(ErrorCode, tonic::Code)] = &[
            (ErrorCode::NotFound, tonic::Code::NotFound),
            (ErrorCode::NoRoute, tonic::Code::NotFound),
            (ErrorCode::AlreadyExists, tonic::Code::AlreadyExists),
            (ErrorCode::PermissionDenied, tonic::Code::PermissionDenied),
            (ErrorCode::PluginRejected, tonic::Code::PermissionDenied),
            (ErrorCode::AuthRequired, tonic::Code::Unauthenticated),
            (ErrorCode::AuthExpired, tonic::Code::Unauthenticated),
            (ErrorCode::CredentialExpired, tonic::Code::Unauthenticated),
            (
                ErrorCode::CredentialUnavailable,
                tonic::Code::Unauthenticated,
            ),
            (ErrorCode::InvalidArgument, tonic::Code::InvalidArgument),
            (ErrorCode::Unsupported, tonic::Code::Unimplemented),
            (ErrorCode::BrokerUnavailable, tonic::Code::Unavailable),
            (ErrorCode::Transient, tonic::Code::Unavailable),
            (
                ErrorCode::NetworkFilesystemRefused,
                tonic::Code::Unavailable,
            ),
            (ErrorCode::DeadlineExceeded, tonic::Code::DeadlineExceeded),
            (ErrorCode::Cancelled, tonic::Code::Cancelled),
            (ErrorCode::AuthCancelled, tonic::Code::Cancelled),
            (ErrorCode::ResourceExhausted, tonic::Code::ResourceExhausted),
            (ErrorCode::PolicyEpochStale, tonic::Code::FailedPrecondition),
            (
                ErrorCode::PreconditionFailed,
                tonic::Code::FailedPrecondition,
            ),
            (ErrorCode::ObjectModified, tonic::Code::FailedPrecondition),
            (ErrorCode::ContentMismatch, tonic::Code::FailedPrecondition),
            (ErrorCode::RedirectExpired, tonic::Code::FailedPrecondition),
            (ErrorCode::StagingExpired, tonic::Code::FailedPrecondition),
            (
                ErrorCode::AuthorizationLeaseExpired,
                tonic::Code::FailedPrecondition,
            ),
            (
                ErrorCode::DirectoryNotEmpty,
                tonic::Code::FailedPrecondition,
            ),
            (ErrorCode::IncompatibleType, tonic::Code::FailedPrecondition),
            (
                ErrorCode::AliasChainTooLong,
                tonic::Code::FailedPrecondition,
            ),
            (ErrorCode::NotConfigured, tonic::Code::FailedPrecondition),
            (
                ErrorCode::StateRootUnavailable,
                tonic::Code::FailedPrecondition,
            ),
            (ErrorCode::BrokerRequired, tonic::Code::FailedPrecondition),
            (ErrorCode::Conflict, tonic::Code::Aborted),
            (ErrorCode::RouteConflict, tonic::Code::Aborted),
            (ErrorCode::Locked, tonic::Code::Aborted),
            (ErrorCode::CommitAmbiguous, tonic::Code::Aborted),
            (ErrorCode::CacheLockContention, tonic::Code::Aborted),
            (ErrorCode::ContentChecksumMismatch, tonic::Code::DataLoss),
            (ErrorCode::IntegrityFailure, tonic::Code::DataLoss),
            (ErrorCode::CacheCorrupt, tonic::Code::DataLoss),
            (ErrorCode::Internal, tonic::Code::Internal),
        ];
        for (code, expected) in cases {
            let status = error_to_status(Error::new(*code, "x"));
            assert_eq!(status.code(), *expected, "code mismatch for {code:?}");
            assert_eq!(
                status_to_error(status).code(),
                *code,
                "round-trip mismatch for {code:?}"
            );
        }
    }

    #[test]
    fn unknown_address_visibility_falls_closed_to_suppressed() {
        assert_eq!(
            address_visibility_from_proto(i32::MAX),
            AddressVisibility::Suppressed
        );
        assert_eq!(
            address_visibility_from_proto(-1),
            AddressVisibility::Suppressed
        );
        assert_eq!(
            address_visibility_from_proto(pb::AddressVisibility::Visible as i32),
            AddressVisibility::Visible
        );
        assert_eq!(
            address_visibility_from_proto(pb::AddressVisibility::Hidden as i32),
            AddressVisibility::Hidden
        );
        assert_eq!(
            address_visibility_from_proto(pb::AddressVisibility::Suppressed as i32),
            AddressVisibility::Suppressed
        );
    }

    #[test]
    fn unknown_change_kind_is_invalid_argument() {
        let proto = pb::ChangeEvent {
            event: Some(pb::change_event::Event::Object(pb::ObjectChange {
                address: "file:///tmp/x".into(),
                kind: i32::MAX,
                etag: None,
                version: None,
                size: None,
                mtime_unix_millis: None,
                at_unix_millis: 0,
                cursor: vec![],
            })),
        };
        let err = change_event_from_proto(Some(proto)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn change_event_object_descriptive_fields_round_trip() {
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_123_456);
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_999_000);
        let original = ovstorage_plugin::ChangeEvent::Object {
            address: Url::parse("file:///tmp/x").unwrap(),
            kind: ovstorage_plugin::ChangeKind::Modified,
            etag: Some("etag-1".into()),
            version: Some("v-7".into()),
            size: Some(4096),
            mtime: Some(mtime),
            at,
            cursor: WatchDirectoryCursor(b"cur".to_vec()),
        };
        let wire = change_event_to_proto(&original);
        let restored = change_event_from_proto(Some(wire)).unwrap();
        match restored {
            ovstorage_plugin::ChangeEvent::Object {
                etag,
                version,
                size,
                mtime: rt_mtime,
                ..
            } => {
                assert_eq!(etag.as_deref(), Some("etag-1"));
                assert_eq!(version.as_deref(), Some("v-7"));
                assert_eq!(size, Some(4096));
                assert_eq!(rt_mtime, Some(mtime));
            }
            other => panic!("expected Object, got {other:?}"),
        }
    }

    #[test]
    fn if_dest_exists_match_etag_without_payload_is_invalid_argument() {
        let proto = pb::IfDestExists {
            kind: pb::IfDestExistsKind::MatchEtag as i32,
            match_etag: None,
        };
        let err = if_dest_exists_from_proto(Some(proto)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn if_dest_exists_unknown_kind_is_invalid_argument() {
        let proto = pb::IfDestExists {
            kind: i32::MAX,
            match_etag: None,
        };
        let err = if_dest_exists_from_proto(Some(proto)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn if_dest_exists_absent_message_decodes_as_overwrite() {
        let result = if_dest_exists_from_proto(None).unwrap();
        assert_eq!(result, IfDestExists::Overwrite);
    }

    #[test]
    fn if_dest_exists_round_trips_each_variant() {
        for original in [
            IfDestExists::Overwrite,
            IfDestExists::Fail,
            IfDestExists::MatchEtag("etag-x".into()),
        ] {
            let proto = if_dest_exists_to_proto(&original);
            let back = if_dest_exists_from_proto(Some(proto)).unwrap();
            assert_eq!(back, original);
        }
    }

    #[test]
    fn object_info_mtime_round_trips_pre_epoch() {
        // i64-signed millis on the wire: pre-epoch mtimes (file plugin
        // clock skew can produce them via UNIX_EPOCH-relative arithmetic)
        // round-trip without collapsing to the epoch.
        let pre_epoch = UNIX_EPOCH - Duration::from_millis(12_345);
        let url = address::parse("file:///tmp/x").unwrap();
        let info = ObjectInfo {
            address: url,
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: Some(pre_epoch),
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        };
        let proto = object_info_to_proto(&info);
        assert_eq!(proto.mtime_unix_millis, Some(-12_345));
        let back = object_info_from_proto(Some(proto)).unwrap();
        assert_eq!(back.mtime, Some(pre_epoch));
    }
}
