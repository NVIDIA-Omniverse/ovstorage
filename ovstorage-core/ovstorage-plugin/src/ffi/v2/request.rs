// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! repr(C) request payloads for the ABI-v2 Layer vtable's object and
//! runtime-state introspection operations. Each mirrors an
//! `ovstorage_layer::Request<T>` (or, for the introspection slots, the
//! method's `&Extensions`/`&Url` arguments): a `{struct_size, extensions,
//! ...}` prefix (`extensions` at offset `size_of::<usize>()`) followed by
//! the operation's resolved address(es) and its options. Options reuse the
//! shared FFI option shadows verbatim; only the bundling is new.
//! Per-request structs carry no `abi_version` — `struct_size` gives
//! per-struct forward-compat and the cdylib's ABI is fixed by the
//! manifest/init prefix.
//!
//! Addresses arrive as resolved (post-alias, post-rewrite) URL strings,
//! not `ResolvedTarget`s — v2 Layers route internally rather than being
//! handed a pre-resolved backend target.
//!
//! The three runtime-state introspection requests
//! ([`RootInfoForRequest`], [`ListAddressRootsRequest`],
//! [`ListConnectionsRequest`]) carry the same prefix so `root_info_for` /
//! `list_address_roots` / `list_connections` cross the ABI as always-async,
//! cancellable ops like the data ops; the two `list_*` requests take no
//! address, only the request-context `extensions`.

use super::super::*;

/// `stat` request. Mirrors `Request<ovstorage_layer::StatRequest>`.
#[repr(C)]
pub struct StatRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: StatOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for StatRequest {}

/// `read` / `materialize` / `get_latest_version` request. Mirrors
/// `Request<ovstorage_layer::ReadRequest>`.
#[repr(C)]
pub struct ReadRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: ReadOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ReadRequest {}

/// `write` / `write_stream` / `write_redirect` request. Mirrors
/// `Request<ovstorage_layer::WriteRequest>`. The `body` tag selects
/// buffered bytes, a local file, or a chunk stream; redirect-emitting
/// writes ignore it.
#[repr(C)]
pub struct WriteRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub body: Body,
    pub options: WriteOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for WriteRequest {}

/// `continue_write` request. Mirrors
/// `Request<ovstorage_layer::ContinueWriteRequest>`.
#[repr(C)]
pub struct ContinueWriteRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub redirects: WriteRedirectBatch,
    pub results: RedirectResultBatch,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ContinueWriteRequest {}

/// `delete` request. Mirrors `Request<ovstorage_layer::DeleteRequest>`.
#[repr(C)]
pub struct DeleteRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: DeleteOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for DeleteRequest {}

/// `copy` request. Mirrors `Request<ovstorage_layer::CopyRequest>`.
#[repr(C)]
pub struct CopyRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub source: Str,
    pub destination: Str,
    pub options: CopyOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CopyRequest {}

/// `rename` request. Mirrors `Request<ovstorage_layer::RenameRequest>`.
#[repr(C)]
pub struct RenameRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub source: Str,
    pub destination: Str,
    pub options: RenameOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for RenameRequest {}

/// `update_metadata` request. Mirrors
/// `Request<ovstorage_layer::UpdateMetadataRequest>`.
#[repr(C)]
pub struct UpdateMetadataRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: UpdateMetadataOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for UpdateMetadataRequest {}

/// `check_access` request. Mirrors
/// `Request<ovstorage_layer::CheckAccessRequest>`.
#[repr(C)]
pub struct CheckAccessRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub operations: AccessOps,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CheckAccessRequest {}

/// `list` request. Mirrors `Request<ovstorage_layer::ListRequest>`.
#[repr(C)]
pub struct ListRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub prefix: Str,
    pub options: ListOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ListRequest {}

/// `list_versions` request. Mirrors
/// `Request<ovstorage_layer::ListVersionsRequest>`.
#[repr(C)]
pub struct ListVersionsRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: ListVersionsOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ListVersionsRequest {}

/// `watch_directory` request. Mirrors
/// `Request<ovstorage_layer::WatchDirectoryRequest>`.
#[repr(C)]
pub struct WatchDirectoryRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub prefix: Str,
    pub options: WatchDirectoryOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for WatchDirectoryRequest {}

/// `create_directory` request. Mirrors
/// `Request<ovstorage_layer::CreateDirectoryRequest>`.
#[repr(C)]
pub struct CreateDirectoryRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: CreateDirectoryOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CreateDirectoryRequest {}

/// `delete_directory` request. Mirrors
/// `Request<ovstorage_layer::DeleteDirectoryRequest>`.
#[repr(C)]
pub struct DeleteDirectoryRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub address: Str,
    pub options: DeleteDirectoryOptions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for DeleteDirectoryRequest {}

// ---------------------------------------------------------------------
// Runtime-state introspection request payloads
//
// The three runtime-state queries (`root_info_for`, `list_address_roots`,
// `list_connections`) are always-async and cancellable, so — unlike the
// synchronous `list_kinds` — they take a `*const Request` envelope like the
// data ops. `root_info_for` also carries the resolved URL to introspect;
// the two `list_*` slots take no address.
// ---------------------------------------------------------------------

/// `root_info_for` request. Mirrors the `(url, cx)` arguments of
/// `ovstorage_layer::Layer::root_info_for`, wrapped in the standard
/// `{struct_size, extensions}` request prefix. `url` is the resolved
/// (post-alias) address whose [`RootInfo`] the slot resolves.
#[repr(C)]
pub struct RootInfoForRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub url: Str,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for RootInfoForRequest {}

/// `list_address_roots` request. The prefix carries only the per-request
/// `extensions`; the slot takes no address. Mirrors the `cx`-only argument
/// of `ovstorage_layer::Layer::list_address_roots`.
#[repr(C)]
pub struct ListAddressRootsRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ListAddressRootsRequest {}

/// `list_connections` request. Same `extensions`-only prefix as
/// [`ListAddressRootsRequest`]. Mirrors the `cx`-only argument of
/// `ovstorage_layer::Layer::list_connections`.
#[repr(C)]
pub struct ListConnectionsRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for ListConnectionsRequest {}
