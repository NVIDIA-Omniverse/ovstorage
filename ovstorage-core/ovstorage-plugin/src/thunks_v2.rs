// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plugin-side projection of the Rust `ovstorage_layer` surface onto the
//! ABI-v2 C vtables. A
//! Rust plugin's factory set becomes the [`PLUGIN_VTABLE`]
//! (`create_backend` / `create_wrapper` / `create_router`); each
//! `Arc<dyn Layer>` it produces is handed back behind the generic
//! [`LAYER_VTABLE`], whose slot thunks marshal each request from FFI,
//! drive the trait method on the plugin runtime, and fire `on_complete`
//! with the heap-boxed result or error.
//!
//! Wherever a leaf type already has an FFI converter this module reuses
//! [`crate::marshal`]'s converters; only the layer-specific
//! introspection/connection shadows (`RootInfo`, snapshots, paged
//! results, `LayerKindDescriptor`) get fresh converters here.
//!
//! This module also owns the cross-language live-handoff verbs
//! ([`export_handle`] / [`import_handle`]): any
//! `Arc<dyn Layer>` mints into a movable `LayerHandle`, and importing one
//! either unwraps it (same linked image, zero FFI) or wraps it in the
//! consumer-side [`crate::consume_v2::ForeignVtableLayer`].
//!
//! # Ownership & panic safety
//!
//! Layer state is `Box<Arc<dyn Layer>>::into_raw`, reclaimed by the
//! `drop` slot; result and error payloads are heap-allocated by the
//! producer and reclaimed by the receiver. Every spawned task wraps its
//! await in `catch_unwind` via the shared `ffi_runtime` machinery,
//! so a plugin panic surfaces as `ErrorCode::Internal` rather than
//! unwinding across the C ABI frame.

use crate::ffi;
use crate::ffi::abi_alloc;
use crate::ffi_runtime::fire_complete_err;
use crate::{
    AddressVisibility, AliasSource, AliasState, AttributePatch, AuthenticateRequest,
    ConnectionChange, ConnectionId, ConnectionKey, ConnectionSnapshot, ConnectionUpdateStream,
    Error, ErrorCode, Extensions, LayerConfig, LayerConnectionRequest, LayerKindDescriptor,
    LayerType, ListPage, RangeReadStrategy, RootInfo, RootInfoChange, RootInfoSnapshot,
    RootInfoUpdateStream, RouteSource, UpdateConnectionAttributesRequest,
    UpdateConnectionCredentialsRequest, VersionPage, marshal,
};

// =====================================================================
// Rust -> FFI: identity / kind
// =====================================================================

pub(crate) fn layer_type_to_ffi(value: LayerType) -> ffi::LayerType {
    match value {
        LayerType::Backend => ffi::LayerType::Backend,
        LayerType::Wrapper => ffi::LayerType::Wrapper,
        LayerType::Router => ffi::LayerType::Router,
    }
}

pub fn layer_type_from_ffi(value: ffi::LayerType) -> LayerType {
    match value {
        ffi::LayerType::Backend => LayerType::Backend,
        ffi::LayerType::Wrapper => LayerType::Wrapper,
        ffi::LayerType::Router => LayerType::Router,
    }
}

pub(crate) fn layer_kind_descriptor_to_ffi(value: LayerKindDescriptor) -> ffi::LayerKindDescriptor {
    ffi::LayerKindDescriptor {
        struct_size: std::mem::size_of::<ffi::LayerKindDescriptor>(),
        layer_type: layer_type_to_ffi(value.layer_type),
        accepts_connections: value.accepts_connections,
        supports_user_metadata: value.supports_user_metadata,
        kind: marshal::primitive::str_to_ffi(value.kind),
        display_name: marshal::primitive::str_to_ffi(value.display_name),
        description: marshal::primitive::optional_to_ffi(
            value.description,
            marshal::primitive::str_to_ffi,
        ),
        config_schema: marshal::primitive::list_to_ffi(
            value.config_schema,
            marshal::descriptor::config_field_to_ffi,
        ),
        credential_schema: marshal::primitive::list_to_ffi(
            value.credential_schema,
            marshal::descriptor::credential_field_to_ffi,
        ),
        credential_methods: marshal::primitive::list_to_ffi(
            value.credential_methods,
            marshal::descriptor::credential_method_to_ffi,
        ),
        icon: marshal::primitive::optional_to_ffi(value.icon, marshal::primitive::bytes_to_ffi),
        auth_capable: value.auth_capable,
        _reserved: [std::ptr::null_mut(); 8],
    }
}

// =====================================================================
// Rust -> FFI: per-root introspection (RootInfo and friends)
// =====================================================================

fn range_read_strategy_to_ffi(value: RangeReadStrategy) -> ffi::RangeReadStrategy {
    match value {
        RangeReadStrategy::Native => ffi::RangeReadStrategy::Native,
        RangeReadStrategy::CachedReadThrough => ffi::RangeReadStrategy::CachedReadThrough,
        RangeReadStrategy::MaterializeOnly => ffi::RangeReadStrategy::MaterializeOnly,
        RangeReadStrategy::Unsupported => ffi::RangeReadStrategy::Unsupported,
    }
}

fn address_visibility_to_ffi(value: AddressVisibility) -> ffi::AddressVisibility {
    match value {
        AddressVisibility::Visible => ffi::AddressVisibility::Visible,
        AddressVisibility::Hidden => ffi::AddressVisibility::Hidden,
        AddressVisibility::Suppressed => ffi::AddressVisibility::Suppressed,
    }
}

fn alias_source_to_ffi(value: AliasSource) -> ffi::AliasSource {
    match value {
        AliasSource::Static { layer } => ffi::AliasSource {
            tag: ffi::AliasSourceTag::Static,
            layer: marshal::connection::config_layer_to_ffi(layer),
            persisted: false,
            broker_principal: ffi::Optional::none(),
        },
        AliasSource::Runtime { persisted } => ffi::AliasSource {
            tag: ffi::AliasSourceTag::Runtime,
            layer: marshal::connection::config_layer_to_ffi(crate::ConfigLayer::Programmatic),
            persisted,
            broker_principal: ffi::Optional::none(),
        },
        AliasSource::BrokerDelivered { broker_principal } => ffi::AliasSource {
            tag: ffi::AliasSourceTag::BrokerDelivered,
            layer: marshal::connection::config_layer_to_ffi(crate::ConfigLayer::Programmatic),
            persisted: false,
            broker_principal: ffi::Optional::some(marshal::primitive::str_to_ffi(broker_principal)),
        },
    }
}

fn alias_state_to_ffi(value: AliasState) -> ffi::AliasState {
    match value {
        AliasState::Live => ffi::AliasState {
            tag: ffi::AliasStateTag::Live,
            reason: ffi::Optional::none(),
        },
        AliasState::Dangling => ffi::AliasState {
            tag: ffi::AliasStateTag::Dangling,
            reason: ffi::Optional::none(),
        },
        AliasState::ChainTooLong { reason } => ffi::AliasState {
            tag: ffi::AliasStateTag::ChainTooLong,
            reason: ffi::Optional::some(marshal::primitive::str_to_ffi(reason)),
        },
    }
}

fn route_source_to_ffi(value: RouteSource) -> ffi::RouteSource {
    let mut out = ffi::RouteSource {
        tag: ffi::RouteSourceTag::Static,
        layer: marshal::connection::config_layer_to_ffi(crate::ConfigLayer::Programmatic),
        connection_id: ffi::Optional::none(),
        broker_principal: ffi::Optional::none(),
        alias_to: ffi::Optional::none(),
        alias_source: ffi::Optional::none(),
    };
    match value {
        RouteSource::Static { layer } => {
            out.tag = ffi::RouteSourceTag::Static;
            out.layer = marshal::connection::config_layer_to_ffi(layer);
        }
        RouteSource::ConnectionContributed { connection_id } => {
            out.tag = ffi::RouteSourceTag::ConnectionContributed;
            out.connection_id =
                ffi::Optional::some(marshal::connection::connection_id_to_ffi(connection_id));
        }
        RouteSource::BrokerDelivered {
            broker_principal,
            connection_id,
        } => {
            out.tag = ffi::RouteSourceTag::BrokerDelivered;
            out.connection_id =
                ffi::Optional::some(marshal::connection::connection_id_to_ffi(connection_id));
            out.broker_principal =
                ffi::Optional::some(marshal::primitive::str_to_ffi(broker_principal));
        }
        RouteSource::Alias { to, alias_source } => {
            out.tag = ffi::RouteSourceTag::Alias;
            out.alias_to = ffi::Optional::some(marshal::address::object_address_to_ffi(to));
            out.alias_source = ffi::Optional::some(alias_source_to_ffi(alias_source));
        }
    }
    out
}

pub(crate) fn root_info_to_ffi(value: RootInfo) -> ffi::RootInfo {
    ffi::RootInfo {
        struct_size: std::mem::size_of::<ffi::RootInfo>(),
        root: marshal::address::object_address_to_ffi(value.root),
        display_name: marshal::primitive::optional_to_ffi(
            value.display_name,
            marshal::primitive::str_to_ffi,
        ),
        layer_kind: marshal::primitive::str_to_ffi(value.layer_kind),
        connection_id: marshal::primitive::optional_to_ffi(
            value.connection_id,
            marshal::connection::connection_id_to_ffi,
        ),
        capabilities: marshal::capabilities::capabilities_to_ffi(value.capabilities),
        range_read_strategy: range_read_strategy_to_ffi(value.range_read_strategy),
        source: route_source_to_ffi(value.source),
        visible: value.visible,
        visibility: address_visibility_to_ffi(value.visibility),
        alias_state: marshal::primitive::optional_to_ffi(value.alias_state, alias_state_to_ffi),
        icon: marshal::primitive::optional_to_ffi(value.icon, marshal::primitive::bytes_to_ffi),
        user_metadata: marshal::metadata::user_metadata_to_ffi(value.user_metadata),
        // Appended at the tail (see `ffi::RootInfo`); consumes three of the
        // original eight reserved slots, so the total size is unchanged.
        owning_target: marshal::primitive::optional_to_ffi(
            value.owning_target,
            marshal::primitive::str_to_ffi,
        ),
        _reserved: [std::ptr::null_mut(); 5],
    }
}

pub(crate) fn root_info_snapshot_to_ffi(value: RootInfoSnapshot) -> ffi::RootInfoSnapshot {
    ffi::RootInfoSnapshot {
        roots: marshal::primitive::list_to_ffi(value.roots, root_info_to_ffi),
        updates: value.updates,
    }
}

// =====================================================================
// Rust -> FFI: connection introspection + paged results
// =====================================================================

pub(crate) fn connection_snapshot_to_ffi(value: ConnectionSnapshot) -> ffi::ConnectionSnapshot {
    ffi::ConnectionSnapshot {
        connections: marshal::primitive::list_to_ffi(
            value.connections,
            marshal::auth::connection_to_ffi,
        ),
        updates: value.updates,
    }
}

/// Encode a [`RootInfoChange`] into its FFI shadow.
pub(crate) fn root_info_change_to_ffi(value: RootInfoChange) -> ffi::RootInfoChange {
    let (tag, roots) = match value {
        RootInfoChange::Snapshot(roots) => (ffi::RootInfoChangeTag::Snapshot, roots),
        RootInfoChange::Added(roots) => (ffi::RootInfoChangeTag::Added, roots),
        RootInfoChange::Removed(roots) => (ffi::RootInfoChangeTag::Removed, roots),
        RootInfoChange::Updated(roots) => (ffi::RootInfoChangeTag::Updated, roots),
    };
    ffi::RootInfoChange {
        tag,
        roots: marshal::primitive::list_to_ffi(roots, root_info_to_ffi),
    }
}

/// Encode a [`ConnectionChange`] into its FFI shadow. Every field is always
/// initialized; the `tag` names which carry meaning (the host decoder reads
/// only the tagged field), so the absent payloads are an empty list / `None`.
pub(crate) fn connection_change_to_ffi(value: ConnectionChange) -> ffi::ConnectionChange {
    let mut change = ffi::ConnectionChange {
        tag: ffi::ConnectionChangeTag::Snapshot,
        connection: marshal::primitive::optional_to_ffi(None, marshal::auth::connection_to_ffi),
        connections: marshal::primitive::list_to_ffi(Vec::new(), marshal::auth::connection_to_ffi),
        removed_id: marshal::primitive::optional_to_ffi(
            None,
            marshal::connection::connection_id_to_ffi,
        ),
    };
    match value {
        ConnectionChange::Added(connection) => {
            change.tag = ffi::ConnectionChangeTag::Added;
            change.connection = marshal::primitive::optional_to_ffi(
                Some(connection),
                marshal::auth::connection_to_ffi,
            );
        }
        ConnectionChange::Updated(connection) => {
            change.tag = ffi::ConnectionChangeTag::Updated;
            change.connection = marshal::primitive::optional_to_ffi(
                Some(connection),
                marshal::auth::connection_to_ffi,
            );
        }
        ConnectionChange::Removed { id } => {
            change.tag = ffi::ConnectionChangeTag::Removed;
            change.removed_id = marshal::primitive::optional_to_ffi(
                Some(id),
                marshal::connection::connection_id_to_ffi,
            );
        }
        ConnectionChange::Snapshot(connections) => {
            change.tag = ffi::ConnectionChangeTag::Snapshot;
            change.connections =
                marshal::primitive::list_to_ffi(connections, marshal::auth::connection_to_ffi);
        }
    }
    change
}

// The `RootInfoChange` / `ConnectionChange` FFI encoders above are
// `pub(crate)` — they are internal ABI marshalling, not part of this crate's
// semver surface. The host crate's cross-crate round-trip tests (`loaded_v2`)
// still need to feed a plugin-encoded frame into the host decoder, so these
// thin wrappers re-export the encoders under the `test-codec` feature, which
// `ovstorage` enables only as a dev-dependency. Production builds leave the
// feature off and the encoders crate-private.
#[cfg(feature = "test-codec")]
pub fn root_info_change_to_ffi_for_test(value: RootInfoChange) -> ffi::RootInfoChange {
    root_info_change_to_ffi(value)
}

#[cfg(feature = "test-codec")]
pub fn connection_change_to_ffi_for_test(value: ConnectionChange) -> ffi::ConnectionChange {
    connection_change_to_ffi(value)
}

pub(crate) fn list_page_to_ffi(value: ListPage) -> ffi::ListPage {
    ffi::ListPage {
        items: marshal::primitive::list_to_ffi(value.items, marshal::metadata::object_info_to_ffi),
        next_page_token: marshal::primitive::optional_to_ffi(
            value.next_page_token,
            marshal::primitive::str_to_ffi,
        ),
    }
}

pub(crate) fn version_page_to_ffi(value: VersionPage) -> ffi::VersionPage {
    ffi::VersionPage {
        items: marshal::primitive::list_to_ffi(value.items, marshal::metadata::object_info_to_ffi),
        next_page_token: marshal::primitive::optional_to_ffi(
            value.next_page_token,
            marshal::primitive::str_to_ffi,
        ),
    }
}

// =====================================================================
// FFI -> Rust: leaf + request payload decoders. The thunk `std::ptr::read`s
// the whole request and
// these consume it; the host `mem::forget`s its copy after the call).
// =====================================================================

/// Materialize the `Extensions` a request prefix borrows. NULL → empty.
/// The pointer is borrowed (host-owned) for the synchronous slot
/// prologue and never consumed: entries are copied out, so the caller's
/// buffers stay intact for it to reclaim after the slot returns.
///
/// # Safety
///
/// `ptr` must be NULL or point at a valid `ffi::Extensions` borrowed
/// for the duration of the call.
pub unsafe fn extensions_from_ffi(ptr: *const ffi::Extensions) -> Result<Extensions, Error> {
    let mut out = Extensions::new();
    if ptr.is_null() {
        return Ok(out);
    }
    let entries = unsafe { &(*ptr).entries };
    if !entries.ptr.is_null() {
        for entry in unsafe { std::slice::from_raw_parts(entries.ptr, entries.len) } {
            let key = unsafe { marshal::primitive::str_borrow(&entry.key)? };
            let value = unsafe { marshal::primitive::bytes_borrow(&entry.value) };
            out.insert(key, value.to_vec());
        }
    }
    Ok(out)
}

/// Consume an FFI URL string into a canonical `Url`.
///
/// This is the entry point every address arriving over the plugin ABI passes
/// through, under any host — so canonicalizing here is what gives a C host the
/// same normalization the Rust one gets from `address::parse`, without the C
/// side having to implement it. A request that skipped it would reach routing
/// and authorization spelled however the caller wrote it.
pub(crate) unsafe fn url_from_ffi(value: ffi::Str) -> Result<crate::Url, Error> {
    let raw = unsafe { marshal::primitive::str_from_ffi(value)? };
    let url = crate::Url::parse(&raw).map_err(|e| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid address URL: {e}"),
        )
    })?;
    if url.cannot_be_a_base() {
        // The same refusal `address::parse` makes. The path state machine
        // never runs for an authority-less URL, so `canonicalize` cannot
        // normalize one — it would manufacture a separator and leave a
        // traversal unresolved, and the request would reach routing and
        // authorization with none of the guarantees they assume.
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            // Not interpolated: for a cannot-be-a-base URL the whole
            // post-scheme payload is opaque and may carry userinfo, which the
            // error redactor cannot normalize.
            format!(
                "address must have an authority; scheme '{}' was parsed as \
                 authority-less",
                url.scheme()
            ),
        ));
    }
    Ok(ovstorage_layer::canonicalize(url))
}

/// Consume a `List<ConnectionConfigEntry>` config payload into a
/// `LayerConfig`.
pub(crate) unsafe fn config_from_ffi(
    list: ffi::List<ffi::ConnectionConfigEntry>,
) -> Result<LayerConfig, Error> {
    let entries = unsafe {
        marshal::primitive::list_from_ffi(list, |entry: ffi::ConnectionConfigEntry| {
            let key = marshal::primitive::str_from_ffi(entry.key)?;
            let value = marshal::descriptor::config_value_from_ffi(entry.value)?;
            Ok::<_, Error>((key, value))
        })?
    };
    Ok(entries.into_iter().collect())
}

unsafe fn connection_key_from_ffi(value: ffi::ConnectionKey) -> Result<ConnectionKey, Error> {
    Ok(ConnectionKey {
        target: unsafe { marshal::primitive::str_from_ffi(value.target)? },
        id: ConnectionId(unsafe { marshal::primitive::str_from_ffi(value.id)? }),
    })
}

pub(crate) unsafe fn layer_connection_request_from_ffi(
    request: ffi::LayerConnectionRequest,
) -> Result<LayerConnectionRequest, Error> {
    let ffi::LayerConnectionRequest {
        target, connection, ..
    } = request;
    Ok(LayerConnectionRequest {
        target: unsafe { marshal::primitive::str_from_ffi(target)? },
        connection: unsafe { marshal::descriptor::connection_request_from_ffi(connection)? },
    })
}

pub(crate) unsafe fn authenticate_request_from_ffi(
    request: ffi::AuthenticateRequest,
) -> Result<AuthenticateRequest, Error> {
    let ffi::AuthenticateRequest {
        key,
        capability,
        auto_open_browser,
        ..
    } = request;
    Ok(AuthenticateRequest {
        key: unsafe { connection_key_from_ffi(key)? },
        capability: marshal::auth::interactive_auth_capability_from_ffi(capability),
        auto_open_browser,
    })
}

pub(crate) unsafe fn update_connection_credentials_request_from_ffi(
    request: ffi::UpdateConnectionCredentialsRequest,
) -> Result<UpdateConnectionCredentialsRequest, Error> {
    let ffi::UpdateConnectionCredentialsRequest {
        key, credentials, ..
    } = request;
    Ok(UpdateConnectionCredentialsRequest {
        key: unsafe { connection_key_from_ffi(key)? },
        credentials: unsafe { marshal::descriptor::secret_bundle_from_ffi(credentials)? },
    })
}

unsafe fn attribute_patch_from_ffi(value: ffi::AttributePatch) -> Result<AttributePatch, Error> {
    let ffi::AttributePatch {
        display_name,
        access_mode,
        visible,
        set_user_metadata,
        remove_user_metadata,
    } = value;
    let display_name = unsafe {
        marshal::primitive::optional_from_ffi(display_name, |s| {
            marshal::primitive::str_from_ffi(s)
        })?
    };
    let access_mode = unsafe {
        marshal::primitive::optional_from_ffi(access_mode, |s| marshal::primitive::str_from_ffi(s))?
    };
    let visible = unsafe { marshal::primitive::optional_from_ffi(visible, Ok::<bool, Error>)? };
    let mut user_metadata: std::collections::HashMap<String, Option<String>> =
        unsafe { marshal::primitive::key_value_list_from_ffi(set_user_metadata)? }
            .into_iter()
            .map(|(k, v)| (k, Some(v)))
            .collect();
    let removes = unsafe {
        marshal::primitive::list_from_ffi(remove_user_metadata, |s: ffi::Str| {
            marshal::primitive::str_from_ffi(s)
        })?
    };
    for key in removes {
        user_metadata.insert(key, None);
    }
    Ok(AttributePatch {
        display_name,
        access_mode,
        visible,
        user_metadata,
    })
}

pub(crate) unsafe fn update_connection_attributes_request_from_ffi(
    request: ffi::UpdateConnectionAttributesRequest,
) -> Result<UpdateConnectionAttributesRequest, Error> {
    let ffi::UpdateConnectionAttributesRequest { key, patch, .. } = request;
    Ok(UpdateConnectionAttributesRequest {
        key: unsafe { connection_key_from_ffi(key)? },
        patch: unsafe { attribute_patch_from_ffi(patch)? },
    })
}

// =====================================================================
// Object-operation request decoders (FFI request -> Rust `Request<T>`)
// =====================================================================

use crate::{
    BackendFactory, ChangeStream, ContinueWriteRequest, CopyRequest, CreateDirectoryRequest,
    DeleteDirectoryRequest, DeleteRequest, Layer, ListRequest, ListVersionsRequest, ReadRequest,
    RenameRequest, Request, RouterFactory, StatRequest, UpdateMetadataRequest,
    WatchDirectoryRequest, WrapperFactory, WriteRequest,
};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

unsafe fn body_request(value: ffi::WriteRequest) -> Result<Request<WriteRequest>, Error> {
    let ffi::WriteRequest {
        extensions,
        address,
        body,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: WriteRequest {
            address: unsafe { url_from_ffi(address)? },
            body: unsafe { marshal::payload::body_from_ffi(body)? },
            options: unsafe { marshal::options::write_options_from_ffi(options)? },
        },
    })
}

unsafe fn stat_request(value: ffi::StatRequest) -> Result<Request<StatRequest>, Error> {
    let ffi::StatRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: StatRequest {
            address: unsafe { url_from_ffi(address)? },
            options: marshal::options::stat_options_from_ffi(options)?,
        },
    })
}

unsafe fn read_request(value: ffi::ReadRequest) -> Result<Request<ReadRequest>, Error> {
    let ffi::ReadRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: ReadRequest {
            address: unsafe { url_from_ffi(address)? },
            options: unsafe { marshal::options::read_options_from_ffi(options)? },
        },
    })
}

unsafe fn continue_write_request(
    value: ffi::ContinueWriteRequest,
) -> Result<Request<ContinueWriteRequest>, Error> {
    let ffi::ContinueWriteRequest {
        extensions,
        address,
        redirects,
        results,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: ContinueWriteRequest {
            address: unsafe { url_from_ffi(address)? },
            redirects: unsafe { marshal::redirect::write_redirect_batch_from_ffi(redirects)? },
            results: unsafe { marshal::redirect::redirect_result_batch_from_ffi(results)? },
        },
    })
}

unsafe fn delete_request(value: ffi::DeleteRequest) -> Result<Request<DeleteRequest>, Error> {
    let ffi::DeleteRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: DeleteRequest {
            address: unsafe { url_from_ffi(address)? },
            options: unsafe { marshal::options::delete_options_from_ffi(options)? },
        },
    })
}

unsafe fn copy_request(value: ffi::CopyRequest) -> Result<Request<CopyRequest>, Error> {
    let ffi::CopyRequest {
        extensions,
        source,
        destination,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: CopyRequest {
            source: unsafe { url_from_ffi(source)? },
            destination: unsafe { url_from_ffi(destination)? },
            options: unsafe { marshal::options::copy_options_from_ffi(options)? },
        },
    })
}

unsafe fn rename_request(value: ffi::RenameRequest) -> Result<Request<RenameRequest>, Error> {
    let ffi::RenameRequest {
        extensions,
        source,
        destination,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: RenameRequest {
            source: unsafe { url_from_ffi(source)? },
            destination: unsafe { url_from_ffi(destination)? },
            options: unsafe { marshal::options::rename_options_from_ffi(options)? },
        },
    })
}

unsafe fn update_metadata_request(
    value: ffi::UpdateMetadataRequest,
) -> Result<Request<UpdateMetadataRequest>, Error> {
    let ffi::UpdateMetadataRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: UpdateMetadataRequest {
            address: unsafe { url_from_ffi(address)? },
            options: unsafe { marshal::options::update_metadata_options_from_ffi(options)? },
        },
    })
}

unsafe fn check_access_request(
    value: ffi::CheckAccessRequest,
) -> Result<Request<crate::CheckAccessRequest>, Error> {
    let ffi::CheckAccessRequest {
        extensions,
        address,
        operations,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: crate::CheckAccessRequest {
            address: unsafe { url_from_ffi(address)? },
            operations: marshal::access::access_ops_from_ffi(operations),
        },
    })
}

unsafe fn list_request(value: ffi::ListRequest) -> Result<Request<ListRequest>, Error> {
    let ffi::ListRequest {
        extensions,
        prefix,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: ListRequest {
            prefix: unsafe { url_from_ffi(prefix)? },
            options: unsafe { marshal::options::list_options_from_ffi(options)? },
        },
    })
}

unsafe fn list_versions_request(
    value: ffi::ListVersionsRequest,
) -> Result<Request<ListVersionsRequest>, Error> {
    let ffi::ListVersionsRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: ListVersionsRequest {
            address: unsafe { url_from_ffi(address)? },
            options: unsafe { marshal::options::list_versions_options_from_ffi(options)? },
        },
    })
}

unsafe fn watch_directory_request(
    value: ffi::WatchDirectoryRequest,
) -> Result<Request<WatchDirectoryRequest>, Error> {
    let ffi::WatchDirectoryRequest {
        extensions,
        prefix,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: WatchDirectoryRequest {
            prefix: unsafe { url_from_ffi(prefix)? },
            options: unsafe { marshal::options::watch_directory_options_from_ffi(options)? },
        },
    })
}

unsafe fn create_directory_request(
    value: ffi::CreateDirectoryRequest,
) -> Result<Request<CreateDirectoryRequest>, Error> {
    let ffi::CreateDirectoryRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: CreateDirectoryRequest {
            address: unsafe { url_from_ffi(address)? },
            options: marshal::options::create_directory_options_from_ffi(options)?,
        },
    })
}

unsafe fn delete_directory_request(
    value: ffi::DeleteDirectoryRequest,
) -> Result<Request<DeleteDirectoryRequest>, Error> {
    let ffi::DeleteDirectoryRequest {
        extensions,
        address,
        options,
        ..
    } = value;
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(extensions)? },
        input: DeleteDirectoryRequest {
            address: unsafe { url_from_ffi(address)? },
            options: unsafe { marshal::options::delete_directory_options_from_ffi(options)? },
        },
    })
}

// =====================================================================
// Result -> FFI stream encoders for the LayerVTable streaming slots
// =====================================================================

/// Wrap a `ChangeStream` (`watch_directory`'s result) as the pull-based
/// `ffi::BackendChangeStream`, projecting each `ChangeEvent` onto the SPI
/// change-event via the shared `marshal::change` mirror.
fn change_stream_to_ffi_with_cancel(
    stream: ChangeStream,
    cancel_guard: Option<ffi::CancelTokenLocal>,
) -> ffi::BackendChangeStream {
    let backend: crate::BackendChangeStream =
        Box::new(stream.map(|r| r.map(marshal::change::change_event_to_backend)));
    crate::ffi_runtime::stream::change_stream_to_ffi_with_cancel(backend, cancel_guard)
}

// The `list_address_roots` / `list_connections` update streams are async
// (`futures::Stream`), unlike `watch_directory`'s sync `ChangeStream`. Each
// FFI `next_fn` drives the async stream once on the plugin runtime via
// `block_on`. The `terminal` latch
// defends the `StreamStep` contract: once `Failed`/`Ended` is returned, later
// `next_fn` calls short-circuit even if the underlying stream would yield more.

struct RootInfoChangeState {
    stream: RootInfoUpdateStream,
    terminal: bool,
    /// Retains the host cancel token for the returned stream's lifetime and,
    /// crucially, is READ by `next_fn`: a parked pull selects on this token so
    /// a host cancel unblocks it instead of leaving the caller's bridge thread
    /// wedged until the next spontaneous update. Dropped with the stream
    /// state. `None` when the async slot ran without a cancel token.
    cancel_guard: Option<ffi::CancelTokenLocal>,
}

/// Encode a host `RootInfoUpdateStream` as the pull-based
/// `ffi::RootInfoChangeStream` the host decodes in `loaded_v2`, retaining
/// the cancellation guard the async `list_address_roots` slot hands in so
/// the host token stays connected for the stream's lifetime.
fn root_info_change_stream_to_ffi_with_cancel(
    stream: RootInfoUpdateStream,
    cancel_guard: Option<ffi::CancelTokenLocal>,
) -> ffi::RootInfoChangeStream {
    let outer: Box<RootInfoChangeState> = Box::new(RootInfoChangeState {
        stream,
        terminal: false,
        cancel_guard,
    });
    ffi::RootInfoChangeStream {
        state: Box::into_raw(outer) as *mut core::ffi::c_void,
        next_fn: root_info_change_next_thunk,
        drop_fn: root_info_change_drop_thunk,
    }
}

/// Map one blocking pull of a plugin update stream onto a `StreamStep`,
/// writing the caller's `out_item` / `out_error`. `Ok(Some(Ok))` encodes and
/// yields; `Ok(Some(Err))` surfaces the plugin error as `TransientError` — the
/// update-stream contract treats a stream error as a recoverable resync signal,
/// NOT exhaustion, so the stream is left live and `terminal` is not latched;
/// `Ok(None)` ends and latches `terminal`; a caught panic (`Err`) is a genuinely
/// unrecoverable fault, so it becomes a terminal `Failed` carrying an `Internal`
/// error with `panic_msg` and latches `terminal`. Shared by the root-info and
/// connection update-stream thunks.
///
/// # Safety
///
/// `out_item` / `out_error` must be valid, writable, uninitialized caller
/// storage; only one is written per call, per the returned `StreamStep`.
unsafe fn drive_blocking_update_next<FfiItem, T, EncodeFn>(
    pulled: std::thread::Result<Option<Result<T, Error>>>,
    out_item: *mut FfiItem,
    out_error: *mut ffi::Error,
    terminal: &mut bool,
    encode: EncodeFn,
    panic_msg: &str,
) -> ffi::StreamStep
where
    EncodeFn: FnOnce(T) -> FfiItem,
{
    match pulled {
        Ok(Some(Ok(item))) => {
            unsafe { std::ptr::write(out_item, encode(item)) };
            ffi::StreamStep::Yielded
        }
        Ok(Some(Err(error))) => {
            unsafe { std::ptr::write(out_error, marshal::error::to_ffi(&error)) };
            // Recoverable: the stream stays live so the host watcher resyncs
            // rather than treating this as EOF. `terminal` is NOT latched.
            ffi::StreamStep::TransientError
        }
        Ok(None) => {
            *terminal = true;
            ffi::StreamStep::Ended
        }
        Err(_) => {
            unsafe {
                std::ptr::write(
                    out_error,
                    marshal::error::to_ffi(&Error::new(ErrorCode::Internal, panic_msg)),
                )
            };
            *terminal = true;
            ffi::StreamStep::Failed
        }
    }
}

// `next_fn` slot of the `ffi::RootInfoChangeStream` erased-state vtable; called
// through the stream pointer to pull the next root-info change, not by symbol.
/// cbindgen:ignore
unsafe extern "C" fn root_info_change_next_thunk(
    state: *mut core::ffi::c_void,
    out_item: *mut ffi::RootInfoChange,
    out_error: *mut ffi::Error,
) -> ffi::StreamStep {
    unsafe {
        let s = &mut *(state as *mut RootInfoChangeState);
        if s.terminal {
            return ffi::StreamStep::Ended;
        }
        // Race the pull against the host token. Without this the guard would
        // only keep the token ALLOCATED: a cancel firing while this pull is
        // parked on a quiet stream could not be observed, and the host's
        // dedicated bridge thread would stay blocked here until an unrelated
        // update happened to arrive. `StreamExt::next` is cancel-safe, so
        // losing the race drops the pull without dropping an item.
        let cancel = s
            .cancel_guard
            .as_ref()
            .map(ffi::CancelTokenLocal::token_clone);
        let stream = &mut s.stream;
        let pulled = std::panic::catch_unwind(AssertUnwindSafe(|| {
            use futures::StreamExt as _;
            crate::ffi_runtime::runtime().block_on(async {
                match cancel {
                    // Biased: an already-fired token wins over an item that is
                    // simultaneously ready, so cancellation is deterministic.
                    // `None` latches `terminal` and reports `Ended` — the host
                    // asked for teardown, so this is a clean end, not an error.
                    Some(token) => tokio::select! {
                        biased;
                        () = token.cancelled() => None,
                        item = stream.next() => item,
                    },
                    None => stream.next().await,
                }
            })
        }));
        drive_blocking_update_next(
            pulled,
            out_item,
            out_error,
            &mut s.terminal,
            root_info_change_to_ffi,
            "plugin panicked iterating a RootInfoChangeStream",
        )
    }
}

// `drop_fn` slot of the `ffi::RootInfoChangeStream` erased-state vtable; called
// through the stream pointer to free its erased state.
/// cbindgen:ignore
unsafe extern "C" fn root_info_change_drop_thunk(state: *mut core::ffi::c_void) {
    crate::ffi_runtime::guard_drop("RootInfoChangeStream", || unsafe {
        let _ = Box::from_raw(state as *mut RootInfoChangeState);
    });
}

struct ConnectionChangeState {
    stream: ConnectionUpdateStream,
    terminal: bool,
    /// Retains and observes the host cancel token, like
    /// [`RootInfoChangeState::cancel_guard`]. `None` when the async slot ran
    /// without a cancel token.
    cancel_guard: Option<ffi::CancelTokenLocal>,
}

/// Encode a host `ConnectionUpdateStream` as the pull-based
/// `ffi::ConnectionChangeStream` the host decodes in `loaded_v2`, retaining
/// the cancellation guard the async `list_connections` slot hands in so the
/// host token stays connected for the stream's lifetime.
fn connection_change_stream_to_ffi_with_cancel(
    stream: ConnectionUpdateStream,
    cancel_guard: Option<ffi::CancelTokenLocal>,
) -> ffi::ConnectionChangeStream {
    let outer: Box<ConnectionChangeState> = Box::new(ConnectionChangeState {
        stream,
        terminal: false,
        cancel_guard,
    });
    ffi::ConnectionChangeStream {
        state: Box::into_raw(outer) as *mut core::ffi::c_void,
        next_fn: connection_change_next_thunk,
        drop_fn: connection_change_drop_thunk,
    }
}

// `next_fn` slot of the `ffi::ConnectionChangeStream` erased-state vtable;
// called through the stream pointer to pull the next connection change.
/// cbindgen:ignore
unsafe extern "C" fn connection_change_next_thunk(
    state: *mut core::ffi::c_void,
    out_item: *mut ffi::ConnectionChange,
    out_error: *mut ffi::Error,
) -> ffi::StreamStep {
    unsafe {
        let s = &mut *(state as *mut ConnectionChangeState);
        if s.terminal {
            return ffi::StreamStep::Ended;
        }
        // Race the pull against the host token. Without this the guard would
        // only keep the token ALLOCATED: a cancel firing while this pull is
        // parked on a quiet stream could not be observed, and the host's
        // dedicated bridge thread would stay blocked here until an unrelated
        // update happened to arrive. `StreamExt::next` is cancel-safe, so
        // losing the race drops the pull without dropping an item.
        let cancel = s
            .cancel_guard
            .as_ref()
            .map(ffi::CancelTokenLocal::token_clone);
        let stream = &mut s.stream;
        let pulled = std::panic::catch_unwind(AssertUnwindSafe(|| {
            use futures::StreamExt as _;
            crate::ffi_runtime::runtime().block_on(async {
                match cancel {
                    // Biased: an already-fired token wins over an item that is
                    // simultaneously ready, so cancellation is deterministic.
                    // `None` latches `terminal` and reports `Ended` — the host
                    // asked for teardown, so this is a clean end, not an error.
                    Some(token) => tokio::select! {
                        biased;
                        () = token.cancelled() => None,
                        item = stream.next() => item,
                    },
                    None => stream.next().await,
                }
            })
        }));
        drive_blocking_update_next(
            pulled,
            out_item,
            out_error,
            &mut s.terminal,
            connection_change_to_ffi,
            "plugin panicked iterating a ConnectionChangeStream",
        )
    }
}

// `drop_fn` slot of the `ffi::ConnectionChangeStream` erased-state vtable;
// called through the stream pointer to free its erased state.
/// cbindgen:ignore
unsafe extern "C" fn connection_change_drop_thunk(state: *mut core::ffi::c_void) {
    crate::ffi_runtime::guard_drop("ConnectionChangeStream", || unsafe {
        let _ = Box::from_raw(state as *mut ConnectionChangeState);
    });
}

// =====================================================================
// Layer state ownership
// =====================================================================

/// Leak an `Arc<dyn Layer>` into a `LayerHandle.state` pointer. The
/// outer `Box` keeps the canonical handle; slot thunks clone the inner
/// `Arc` into spawned tasks. Reclaimed by `layer_drop_thunk`.
pub fn leak_layer(layer: Arc<dyn Layer>) -> *mut core::ffi::c_void {
    let outer: Box<Arc<dyn Layer>> = Box::new(layer);
    Box::into_raw(outer) as *mut core::ffi::c_void
}

unsafe fn clone_layer_arc(state: *mut core::ffi::c_void) -> Arc<dyn Layer> {
    unsafe { Arc::clone(&*(state as *const Arc<dyn Layer>)) }
}

// `drop` slot of the Layer vtable; called through the `LayerHandle` to reclaim
// the leaked `Box<Arc<dyn Layer>>` state, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn layer_drop_thunk(state: *mut core::ffi::c_void) {
    if state.is_null() {
        return;
    }
    #[cfg(debug_assertions)]
    handoff_accounting::forget(state);
    crate::ffi_runtime::guard_drop("Layer", || unsafe {
        let _ = Box::from_raw(state as *mut Arc<dyn Layer>);
    });
}

unsafe fn decode_async_request<Ffi, Request>(
    request: *const Ffi,
    ffi_name: &'static str,
    op: &'static str,
    decode: unsafe fn(Ffi) -> std::result::Result<Request, Error>,
) -> std::result::Result<Request, Error> {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let raw = unsafe { ffi::read_options_at_ptr::<Ffi>(request, ffi_name)? };
        unsafe { decode(raw) }
    })) {
        Ok(result) => result,
        Err(_) => Err(Error::new(
            ErrorCode::Internal,
            format!("plugin panicked decoding {op} request"),
        )),
    }
}

// =====================================================================
// Async object/connection slot thunks (callback-shaped)
// =====================================================================

/// Generate an async LayerVTable slot thunk: validate + consume the
/// request, spawn the trait method on the plugin runtime, fire
/// `on_complete` with the heap-boxed FFI result (`$encode`) or error.
macro_rules! layer_async_op {
    ($thunk:ident, $ReqFfi:ty, $decode:path, $method:ident, $encode:path) => {
        unsafe extern "C" fn $thunk(
            state: *mut core::ffi::c_void,
            request: *const $ReqFfi,
            cancel: *const ffi::CancelTokenFFI,
            on_complete: ffi::OnComplete,
            user_data: *mut core::ffi::c_void,
        ) {
            let req = match unsafe {
                decode_async_request(request, stringify!($ReqFfi), stringify!($method), $decode)
            } {
                Ok(r) => r,
                Err(e) => return fire_complete_err(e, on_complete, user_data),
            };
            let layer = unsafe { clone_layer_arc(state) };
            let cancel_local = crate::ffi_runtime::local_cancel(cancel);
            crate::ffi_runtime::spawn_async_thunk(
                stringify!($method),
                cancel_local,
                on_complete,
                user_data,
                move |cancel_token| Box::pin(async move { layer.$method(req, cancel_token).await }),
                move |value| Some(abi_alloc::AbiOwned::new($encode(value))),
            );
        }
    };
}

/// Like [`layer_async_op`] but for unit-result slots (`delete`,
/// `rename`, `delete_directory`, `remove_connection`): success fires a
/// NULL result.
macro_rules! layer_async_unit_op {
    ($thunk:ident, $ReqFfi:ty, $decode:path, $method:ident) => {
        unsafe extern "C" fn $thunk(
            state: *mut core::ffi::c_void,
            request: *const $ReqFfi,
            cancel: *const ffi::CancelTokenFFI,
            on_complete: ffi::OnComplete,
            user_data: *mut core::ffi::c_void,
        ) {
            let req = match unsafe {
                decode_async_request(request, stringify!($ReqFfi), stringify!($method), $decode)
            } {
                Ok(r) => r,
                Err(e) => return fire_complete_err(e, on_complete, user_data),
            };
            let layer = unsafe { clone_layer_arc(state) };
            let cancel_local = crate::ffi_runtime::local_cancel(cancel);
            crate::ffi_runtime::spawn_async_thunk(
                stringify!($method),
                cancel_local,
                on_complete,
                user_data,
                move |cancel_token| Box::pin(async move { layer.$method(req, cancel_token).await }),
                // A unit slot completes with a NULL result rather than an
                // envelope; `None` is how the chokepoint spells that.
                move |()| None,
            );
        }
    };
}

layer_async_op!(
    stat_thunk,
    ffi::StatRequest,
    stat_request,
    stat,
    marshal::metadata::object_info_to_ffi
);
layer_async_op!(
    read_thunk,
    ffi::ReadRequest,
    read_request,
    read,
    marshal::payload::read_result_to_ffi
);
layer_async_op!(
    write_thunk,
    ffi::WriteRequest,
    body_request,
    write,
    marshal::payload::write_result_to_ffi
);
layer_async_op!(
    write_stream_thunk,
    ffi::WriteRequest,
    body_request,
    write_stream,
    marshal::payload::write_result_to_ffi
);
layer_async_op!(
    write_redirect_thunk,
    ffi::WriteRequest,
    body_request,
    write_redirect,
    marshal::redirect::write_redirect_batch_to_ffi
);
layer_async_op!(
    continue_write_thunk,
    ffi::ContinueWriteRequest,
    continue_write_request,
    continue_write,
    marshal::payload::write_step_to_ffi
);
layer_async_unit_op!(delete_thunk, ffi::DeleteRequest, delete_request, delete);
layer_async_op!(
    copy_thunk,
    ffi::CopyRequest,
    copy_request,
    copy,
    marshal::payload::write_step_to_ffi
);
layer_async_unit_op!(rename_thunk, ffi::RenameRequest, rename_request, rename);
layer_async_op!(
    update_metadata_thunk,
    ffi::UpdateMetadataRequest,
    update_metadata_request,
    update_metadata,
    marshal::payload::backend_item_info_to_ffi
);
layer_async_op!(
    check_access_thunk,
    ffi::CheckAccessRequest,
    check_access_request,
    check_access,
    marshal::payload::access_decision_to_ffi
);
layer_async_op!(
    materialize_thunk,
    ffi::ReadRequest,
    read_request,
    materialize,
    marshal::payload::local_delegate_to_ffi
);
layer_async_op!(
    list_thunk,
    ffi::ListRequest,
    list_request,
    list,
    list_page_to_ffi
);
layer_async_op!(
    list_versions_thunk,
    ffi::ListVersionsRequest,
    list_versions_request,
    list_versions,
    version_page_to_ffi
);
layer_async_op!(
    get_latest_version_thunk,
    ffi::ReadRequest,
    read_request,
    get_latest_version,
    marshal::metadata::object_info_to_ffi
);
// `watch_directory` is the one streaming slot on the async-op path, so it is
// hand-written rather than macro-generated: it uses `spawn_async_stream_thunk`
// to retain the cancel guard in the returned stream state instead of dropping
// it when the open future resolves. Body otherwise mirrors
// `layer_async_op!`.
// `watch_directory` slot of the Layer vtable; invoked through the `LayerHandle`
// to open the directory-watch stream, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn watch_directory_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::WatchDirectoryRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let req = match unsafe {
        decode_async_request(
            request,
            "WatchDirectoryRequest",
            "watch_directory",
            watch_directory_request,
        )
    } {
        Ok(r) => r,
        Err(e) => return fire_complete_err(e, on_complete, user_data),
    };
    let layer = unsafe { clone_layer_arc(state) };
    let cancel_local = crate::ffi_runtime::local_cancel(cancel);
    crate::ffi_runtime::spawn_async_stream_thunk(
        "watch_directory",
        cancel_local,
        on_complete,
        user_data,
        move |cancel_token| Box::pin(async move { layer.watch_directory(req, cancel_token).await }),
        move |stream, cancel_guard| {
            Some(abi_alloc::AbiOwned::new(change_stream_to_ffi_with_cancel(
                stream,
                cancel_guard,
            )))
        },
    );
}
layer_async_op!(
    create_directory_thunk,
    ffi::CreateDirectoryRequest,
    create_directory_request,
    create_directory,
    marshal::payload::backend_item_info_to_ffi
);
layer_async_unit_op!(
    delete_directory_thunk,
    ffi::DeleteDirectoryRequest,
    delete_directory_request,
    delete_directory
);

// Connection-management async slots.

unsafe fn layer_connection_request(
    value: ffi::LayerConnectionRequest,
) -> Result<Request<LayerConnectionRequest>, Error> {
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(value.extensions)? },
        input: unsafe { layer_connection_request_from_ffi(value)? },
    })
}

unsafe fn remove_connection_request(
    value: ffi::RemoveConnectionRequest,
) -> Result<Request<ConnectionKey>, Error> {
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(value.extensions)? },
        input: unsafe { connection_key_from_ffi(value.key)? },
    })
}

unsafe fn update_credentials_request(
    value: ffi::UpdateConnectionCredentialsRequest,
) -> Result<Request<UpdateConnectionCredentialsRequest>, Error> {
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(value.extensions)? },
        input: unsafe { update_connection_credentials_request_from_ffi(value)? },
    })
}

unsafe fn update_attributes_request(
    value: ffi::UpdateConnectionAttributesRequest,
) -> Result<Request<UpdateConnectionAttributesRequest>, Error> {
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(value.extensions)? },
        input: unsafe { update_connection_attributes_request_from_ffi(value)? },
    })
}

unsafe fn authenticate_request(
    value: ffi::AuthenticateRequest,
) -> Result<Request<AuthenticateRequest>, Error> {
    Ok(Request {
        extensions: unsafe { extensions_from_ffi(value.extensions)? },
        input: unsafe { authenticate_request_from_ffi(value)? },
    })
}

layer_async_op!(
    probe_thunk,
    ffi::LayerConnectionRequest,
    layer_connection_request,
    probe,
    marshal::auth::connection_to_ffi
);
layer_async_op!(
    add_connection_thunk,
    ffi::LayerConnectionRequest,
    layer_connection_request,
    add_connection,
    marshal::auth::connection_to_ffi
);
layer_async_unit_op!(
    remove_connection_thunk,
    ffi::RemoveConnectionRequest,
    remove_connection_request,
    remove_connection
);
layer_async_op!(
    update_connection_credentials_thunk,
    ffi::UpdateConnectionCredentialsRequest,
    update_credentials_request,
    update_connection_credentials,
    marshal::auth::connection_to_ffi
);
layer_async_op!(
    update_connection_attributes_thunk,
    ffi::UpdateConnectionAttributesRequest,
    update_attributes_request,
    update_connection_attributes,
    marshal::auth::connection_to_ffi
);
// `authenticate_connection` is a streaming slot, so it is hand-written rather
// than macro-generated: `spawn_async_stream_thunk` hands the cancel guard to
// the returned auth stream's state, where it lives as long as the stream. That
// keeps the host's wake callback registered for the wait an interactive flow
// parks on, which happens inside the stream rather than in the open future.
// Body otherwise mirrors `layer_async_op!`.
// `authenticate_connection` slot of the Layer vtable; invoked through the
// `LayerHandle` to open the auth event stream, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn authenticate_connection_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::AuthenticateRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let req = match unsafe {
        decode_async_request(
            request,
            "AuthenticateRequest",
            "authenticate_connection",
            authenticate_request,
        )
    } {
        Ok(r) => r,
        Err(e) => return fire_complete_err(e, on_complete, user_data),
    };
    let layer = unsafe { clone_layer_arc(state) };
    let cancel_local = crate::ffi_runtime::local_cancel(cancel);
    crate::ffi_runtime::spawn_async_stream_thunk(
        "authenticate_connection",
        cancel_local,
        on_complete,
        user_data,
        move |cancel_token| {
            Box::pin(async move { layer.authenticate_connection(req, cancel_token).await })
        },
        move |stream, cancel_guard| {
            Some(abi_alloc::AbiOwned::new(
                crate::ffi_runtime::stream::auth_event_stream_to_ffi_with_cancel(
                    stream,
                    cancel_guard,
                ),
            ))
        },
    );
}

// =====================================================================
// Sync identity + structural introspection slot thunks
//
// Identity getters plus `list_kinds` (fixed manifest/graph metadata under
// the no-I/O contract). The three runtime-state queries moved to the async
// section below, so `run_sync` now backs only `list_kinds`.
// =====================================================================

// `name` slot of the Layer vtable; invoked through the `LayerHandle` to read
// the layer's name, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn name_thunk(state: *mut core::ffi::c_void, out: *mut ffi::Str) {
    let value = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let layer = unsafe { &*(state as *const Arc<dyn Layer>) };
        marshal::primitive::str_ref_to_ffi(layer.name())
    }))
    .unwrap_or_else(|_| marshal::primitive::str_ref_to_ffi(""));
    unsafe { std::ptr::write(out, value) };
}

/// Minimal descriptor written to the `descriptor` out-param when the
/// plugin's `descriptor()` panics — so the host (which `assume_init`s the
/// out-param unconditionally) never reads uninitialized memory.
fn fallback_kind_descriptor() -> ffi::LayerKindDescriptor {
    layer_kind_descriptor_to_ffi(LayerKindDescriptor {
        kind: String::new(),
        layer_type: LayerType::Backend,
        display_name: String::new(),
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        // Reached when the plugin's `descriptor()` panics, so it declared
        // nothing. Declining matches `accepts_connections` beside it: for the
        // two fields that grant a host permission, an invented descriptor
        // grants neither.
        supports_user_metadata: false,
    })
}

// `descriptor` slot of the Layer vtable; invoked through the `LayerHandle` to
// read the layer's kind descriptor, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn descriptor_thunk(
    state: *mut core::ffi::c_void,
    out: *mut ffi::LayerKindDescriptor,
) {
    // Always write `out`: `name_thunk` / `owned_targets_thunk` and the
    // host's `assume_init` rely on every infallible getter populating its
    // out-param even on a plugin panic.
    let value = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let layer = unsafe { &*(state as *const Arc<dyn Layer>) };
        layer_kind_descriptor_to_ffi(layer.descriptor())
    }))
    .unwrap_or_else(|_| fallback_kind_descriptor());
    unsafe { std::ptr::write(out, value) };
}

// `owned_targets` slot of the Layer vtable; invoked through the `LayerHandle`
// to list the targets the layer owns, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn owned_targets_thunk(
    state: *mut core::ffi::c_void,
    out: *mut ffi::List<ffi::Str>,
) {
    let value = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let layer = unsafe { &*(state as *const Arc<dyn Layer>) };
        marshal::primitive::list_to_ffi(layer.owned_targets(), marshal::primitive::str_to_ffi)
    }))
    .unwrap_or_else(|_| {
        marshal::primitive::list_to_ffi(Vec::<String>::new(), marshal::primitive::str_to_ffi)
    });
    unsafe { std::ptr::write(out, value) };
}

/// Run a sync fallible introspection slot: write the success value (if
/// any) via `write_ok` and return `*mut Error` (NULL on success).
fn run_sync<R>(
    op: &'static str,
    body: impl FnOnce() -> Result<R, Error>,
    write_ok: impl FnOnce(R),
) -> *mut ffi::Error {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => {
            write_ok(value);
            std::ptr::null_mut()
        }
        Ok(Err(e)) => abi_alloc::abi_box(marshal::error::to_ffi(&e)),
        Err(_) => abi_alloc::abi_box(marshal::error::to_ffi(&Error::new(
            ErrorCode::Internal,
            format!("plugin panicked in {op}"),
        ))),
    }
}

// `list_kinds` slot of the Layer vtable; invoked through the `LayerHandle` to
// enumerate the layer's kind descriptors, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn list_kinds_thunk(
    state: *mut core::ffi::c_void,
    extensions: *const ffi::Extensions,
    out: *mut ffi::List<ffi::LayerKindDescriptor>,
) -> *mut ffi::Error {
    run_sync(
        "list_kinds",
        || {
            let layer = unsafe { &*(state as *const Arc<dyn Layer>) };
            let cx = unsafe { extensions_from_ffi(extensions)? };
            layer.list_kinds(&cx)
        },
        |kinds| {
            let list = marshal::primitive::list_to_ffi(kinds, layer_kind_descriptor_to_ffi);
            unsafe { std::ptr::write(out, list) };
        },
    )
}

// =====================================================================
// Async runtime-state introspection slot thunks (callback-shaped)
//
// `root_info_for` / `list_address_roots` / `list_connections` inspect live
// backend state, so they are async + cancellable like the object ops
// rather than dispatching through `run_sync` (which now serves only
// `list_kinds`). `root_info_for` is a one-shot (`spawn_async_thunk`); the
// two `list_*` slots retain the cancel guard in their returned change
// stream via `spawn_async_stream_thunk`, mirroring `watch_directory`.
// =====================================================================

/// Decode a `RootInfoForRequest` into the `root_info_for` arguments: the
/// resolved URL to introspect and the borrowed request-context extensions.
unsafe fn root_info_for_request(
    value: ffi::RootInfoForRequest,
) -> Result<(crate::Url, Extensions), Error> {
    let ffi::RootInfoForRequest {
        extensions, url, ..
    } = value;
    Ok((unsafe { url_from_ffi(url)? }, unsafe {
        extensions_from_ffi(extensions)?
    }))
}

// `root_info_for` slot of the Layer vtable; invoked through the `LayerHandle`
// to resolve a URL to its root info, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn root_info_for_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::RootInfoForRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::RootInfoForRequest>(request, "RootInfoForRequest")?
        };
        unsafe { root_info_for_request(raw) }
    }));
    let (url, cx) = match decoded {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return fire_complete_err(e, on_complete, user_data),
        Err(_) => {
            return fire_complete_err(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked decoding root_info_for request",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let layer = unsafe { clone_layer_arc(state) };
    let cancel_local = crate::ffi_runtime::local_cancel(cancel);
    crate::ffi_runtime::spawn_async_thunk(
        "root_info_for",
        cancel_local,
        on_complete,
        user_data,
        move |cancel_token| {
            Box::pin(async move { layer.root_info_for(&url, &cx, cancel_token).await })
        },
        move |value| Some(abi_alloc::AbiOwned::new(root_info_to_ffi(value))),
    );
}

// `list_address_roots` slot of the Layer vtable; invoked through the
// `LayerHandle` to fetch the root snapshot + update stream, never by C symbol.
/// cbindgen:ignore
unsafe extern "C" fn list_address_roots_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::ListAddressRootsRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::ListAddressRootsRequest>(
                request,
                "ListAddressRootsRequest",
            )?
        };
        unsafe { extensions_from_ffi(raw.extensions) }
    }));
    let cx = match decoded {
        Ok(Ok(cx)) => cx,
        Ok(Err(e)) => return fire_complete_err(e, on_complete, user_data),
        Err(_) => {
            return fire_complete_err(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked decoding list_address_roots request",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let layer = unsafe { clone_layer_arc(state) };
    let cancel_local = crate::ffi_runtime::local_cancel(cancel);
    crate::ffi_runtime::spawn_async_stream_thunk(
        "list_address_roots",
        cancel_local,
        on_complete,
        user_data,
        move |cancel_token| {
            Box::pin(async move { layer.list_address_roots(&cx, cancel_token).await })
        },
        // Emit the snapshot and, when the Layer advertises one, the
        // heap-boxed root-update stream — retaining the cancel guard so a
        // host cancel can unblock its parked pulls. The host
        // (`loaded_v2::LoadedV2Layer::list_address_roots`) bridges the stream
        // back into an async stream its Stack root watchers consume, so roots
        // discovered after the snapshot propagate live.
        move |(snapshot, updates), cancel_guard| {
            // The nested `updates` envelope is a field of the result rather
            // than the completion payload, so it stays outside the
            // `AbiOwned` chokepoint and is convention-governed.
            let updates_ptr = match updates {
                Some(stream) => abi_alloc::abi_box(root_info_change_stream_to_ffi_with_cancel(
                    stream,
                    cancel_guard,
                )),
                None => std::ptr::null_mut(),
            };
            Some(abi_alloc::AbiOwned::new(ffi::ListAddressRootsResult {
                snapshot: root_info_snapshot_to_ffi(snapshot),
                updates: updates_ptr,
            }))
        },
    );
}

// `list_connections` slot of the Layer vtable; invoked through the
// `LayerHandle` to fetch the connection snapshot + update stream, never by C symbol.
/// cbindgen:ignore
unsafe extern "C" fn list_connections_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::ListConnectionsRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::ListConnectionsRequest>(
                request,
                "ListConnectionsRequest",
            )?
        };
        unsafe { extensions_from_ffi(raw.extensions) }
    }));
    let cx = match decoded {
        Ok(Ok(cx)) => cx,
        Ok(Err(e)) => return fire_complete_err(e, on_complete, user_data),
        Err(_) => {
            return fire_complete_err(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked decoding list_connections request",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let layer = unsafe { clone_layer_arc(state) };
    let cancel_local = crate::ffi_runtime::local_cancel(cancel);
    crate::ffi_runtime::spawn_async_stream_thunk(
        "list_connections",
        cancel_local,
        on_complete,
        user_data,
        move |cancel_token| {
            Box::pin(async move { layer.list_connections(&cx, cancel_token).await })
        },
        // Bridge the connection-update stream the same way as
        // `list_address_roots_thunk`, retaining the cancel guard, so a Layer
        // that mutates its connection set at runtime (e.g. a discovery-driven
        // backend) propagates live changes to the host.
        move |(snapshot, updates), cancel_guard| {
            // Nested envelope, as in `list_address_roots_thunk`.
            let updates_ptr = match updates {
                Some(stream) => abi_alloc::abi_box(connection_change_stream_to_ffi_with_cancel(
                    stream,
                    cancel_guard,
                )),
                None => std::ptr::null_mut(),
            };
            Some(abi_alloc::AbiOwned::new(ffi::ListConnectionsResult {
                snapshot: connection_snapshot_to_ffi(snapshot),
                updates: updates_ptr,
            }))
        },
    );
}

// =====================================================================
// The generic Layer vtable
// =====================================================================

/// The one [`ffi::LayerVTableV1`] value this image installs. A `const` (the
/// static below is its canonical address) so the `test-codec`
/// `layer_vtable_template_for_test` hook can hand tests a by-value copy.
// Internal const initializer for the Layer vtable (private, not `pub`); its
// slots are Rust `extern "C"` fn items, not a C ABI symbol.
/// cbindgen:ignore
const LAYER_VTABLE_INIT: ffi::LayerVTableV1 = ffi::LayerVTableV1 {
    struct_size: std::mem::size_of::<ffi::LayerVTableV1>(),
    abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
    drop: layer_drop_thunk,
    name: name_thunk,
    descriptor: descriptor_thunk,
    owned_targets: owned_targets_thunk,
    root_info_for: root_info_for_thunk,
    list_kinds: list_kinds_thunk,
    list_address_roots: list_address_roots_thunk,
    stat: stat_thunk,
    read: read_thunk,
    write: write_thunk,
    write_stream: write_stream_thunk,
    write_redirect: write_redirect_thunk,
    continue_write: continue_write_thunk,
    delete: delete_thunk,
    copy: copy_thunk,
    rename: rename_thunk,
    update_metadata: update_metadata_thunk,
    check_access: check_access_thunk,
    materialize: materialize_thunk,
    list: list_thunk,
    list_versions: list_versions_thunk,
    get_latest_version: get_latest_version_thunk,
    watch_directory: watch_directory_thunk,
    create_directory: create_directory_thunk,
    delete_directory: delete_directory_thunk,
    probe: probe_thunk,
    add_connection: add_connection_thunk,
    remove_connection: remove_connection_thunk,
    list_connections: list_connections_thunk,
    update_connection_credentials: update_connection_credentials_thunk,
    update_connection_attributes: update_connection_attributes_thunk,
    authenticate_connection: authenticate_connection_thunk,
    _reserved: [None; 16],
};

/// Process-wide Layer vtable installed in every `LayerHandle` produced
/// by a Rust v2 plugin. Each slot downcasts `state` to the canonical
/// `Arc<dyn Layer>` and drives the trait method. Its **address** doubles as
/// the same-binary identity [`import_handle`]'s fast path keys on — one per
/// linked image (host, each cdylib), so two copies of the same code
/// correctly see each other's handles as foreign.
// The Layer vtable instance; the host reaches it through the plugin
// manifest/init entry point (its address is handed over there), never by C
// symbol name, so it is not part of the generated header.
/// cbindgen:ignore
pub static LAYER_VTABLE: ffi::LayerVTableV1 = LAYER_VTABLE_INIT;

// =====================================================================
// Cross-language live handoff: export_handle / import_handle
// =====================================================================

/// Debug-build accounting for every live `LayerHandle.state` this linked
/// image has minted, keyed by state pointer and tagged with its origin. It
/// backs the producer-lifetime tripwires: [`live_export_count`] /
/// [`debug_assert_no_live_exports`] for handoff roots, and the
/// `plugin_drop_thunk` assertion that a plugin is never dropped while
/// factory-minted handles are still live. Compiled out of release builds.
/// Per-linked-image on purpose (each image's copy of this crate has its own
/// map), mirroring [`LAYER_VTABLE`] identity.
#[cfg(debug_assertions)]
mod handoff_accounting {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Origin of a live `LayerHandle.state` minted by this linked image.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Origin {
        /// Minted by [`super::export_handle`] — a cross-language handoff
        /// root whose producer-lifetime contract is documentation, not a
        /// keep-alive pin.
        Exported,
        /// Minted by a factory thunk on behalf of the given `plugin_state`,
        /// whose drop contract is exclusive-after-drain of these handles.
        Factory(usize),
    }

    // Internal debug-only liveness map tracking minted `LayerHandle.state`
    // pointers; process-local accounting, not a C ABI symbol.
    /// cbindgen:ignore
    static LIVE: Mutex<BTreeMap<usize, Origin>> = Mutex::new(BTreeMap::new());

    pub(super) fn register(state: *mut core::ffi::c_void, origin: Origin) {
        LIVE.lock().unwrap().insert(state as usize, origin);
    }

    /// Forget `state`: it was reclaimed via the vtable `drop` slot or
    /// unwrapped by the same-binary import fast path. A no-op for states
    /// minted outside the tracked paths.
    pub(super) fn forget(state: *mut core::ffi::c_void) {
        LIVE.lock().unwrap().remove(&(state as usize));
    }

    pub(super) fn live_exports() -> usize {
        LIVE.lock()
            .unwrap()
            .values()
            .filter(|origin| **origin == Origin::Exported)
            .count()
    }

    pub(super) fn live_factory_handles(plugin_state: *mut core::ffi::c_void) -> usize {
        LIVE.lock()
            .unwrap()
            .values()
            .filter(|origin| **origin == Origin::Factory(plugin_state as usize))
            .count()
    }

    #[cfg(feature = "test-codec")]
    pub(super) fn is_live(state: usize) -> bool {
        LIVE.lock().unwrap().contains_key(&state)
    }
}

/// Mint one owned, movable [`ffi::LayerHandle`] over `layer` — the produce
/// side of the cross-language live handoff. The handle has the exact shape
/// every plugin factory returns: `state` is the canonical
/// `Box<Arc<dyn Layer>>` ([`leak_layer`]) and `vtable` this image's
/// [`LAYER_VTABLE`].
///
/// Handles are **move-only** (the frozen Layer vtable has no clone slot):
/// one call mints exactly one owned reference, consumed by
/// [`import_handle`] on the receiving side or by the vtable `drop` slot.
/// Multiple consumers ⇒ export multiple times (each call clones the Arc).
/// Re-exporting an imported foreign layer wraps the adapter behind this
/// image's vtable — correct, one extra bridge hop per boundary.
///
/// The producer — this linked image, plus whatever runtime drives `layer` —
/// must outlive every handle it exports. That is a documented ABI contract
/// (a bare handle carries no keep-alive pin); debug builds tripwire it via
/// [`live_export_count`] / [`debug_assert_no_live_exports`].
pub fn export_handle(layer: Arc<dyn Layer>) -> ffi::LayerHandle {
    let state = leak_layer(layer);
    #[cfg(debug_assertions)]
    handoff_accounting::register(state, handoff_accounting::Origin::Exported);
    ffi::LayerHandle {
        state,
        vtable: &LAYER_VTABLE,
    }
}

/// Method-syntax sugar for [`export_handle`] (`layer.export_handle()`).
/// The `Layer` trait itself is frozen — the vtable slot-order gate parses
/// its method list — so this lives on an extension trait rather than a
/// trait default.
pub trait LayerExportExt {
    /// Mint one owned [`ffi::LayerHandle`] over this layer (clones the Arc;
    /// see [`export_handle`] for the move-only ownership contract).
    fn export_handle(&self) -> ffi::LayerHandle;
}

impl LayerExportExt for Arc<dyn Layer> {
    fn export_handle(&self) -> ffi::LayerHandle {
        export_handle(Arc::clone(self))
    }
}

/// Import a `LayerHandle` as an `Arc<dyn Layer>`, taking ownership — the
/// consume side of the cross-language live handoff.
///
/// A same-binary handle (its `vtable` is this image's [`LAYER_VTABLE`])
/// unwraps back to the original Arc with zero FFI, preserving Arc identity
/// (`Arc::ptr_eq` holds across an export/import round-trip). Anything else
/// is validated against the ABI handshake and wrapped in a
/// [`ForeignVtableLayer`](crate::consume_v2::ForeignVtableLayer) that
/// drives the producer's vtable slot-by-slot. The fast path is
/// per-linked-image on purpose: two copies of the same cdylib, or host vs
/// cdylib, have distinct `LAYER_VTABLE` addresses and correctly take the
/// foreign path.
///
/// Handshake failures and their disposal (see
/// `ForeignVtableLayer::from_handle_with_fallback`, the single
/// implementation):
/// - null `state`/`vtable` → `InvalidArgument`; undersized
///   `vtable.struct_size` → `IncompatibleType`. In both cases the handle
///   carries no trustworthy `drop` slot, so it **cannot be safely dropped**
///   and is returned undisposed — the error return documents that the
///   caller retains whatever it passed.
/// - `vtable.abi_version` not the exact supported Layer ABI →
///   `IncompatibleType`, and the handle **is consumed** — dropped via its
///   vtable `drop` slot (the drop slot immediately follows the stable
///   header; that is the layout convention's purpose).
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the handle has a null `state` or
///   `vtable` pointer.
/// - [`ErrorCode::IncompatibleType`] — the `vtable` is undersized (smaller
///   than required by the ABI contract) or `abi_version` does not match the
///   supported Layer ABI version.
///
/// # Safety
///
/// Trusted like a plugin load (cf. `ovstorage::load_layer_plugin`): the
/// handle must be a live Layer-ABI `{state, vtable}` pair whose producer
/// outlives every use of the imported layer, and ownership of the handle
/// must genuinely transfer to this call (it must not be driven or dropped
/// elsewhere afterwards).
pub unsafe fn import_handle(handle: ffi::LayerHandle) -> Result<Arc<dyn Layer>, Error> {
    if !handle.state.is_null() && std::ptr::eq(handle.vtable, &LAYER_VTABLE) {
        // Same-binary fast path: `state` is this image's canonical
        // `Box<Arc<dyn Layer>>` (`leak_layer`), so unwrap it directly.
        let state = handle.state;
        let arc = unsafe { *Box::from_raw(state as *mut Arc<dyn Layer>) };
        #[cfg(debug_assertions)]
        handoff_accounting::forget(state);
        std::mem::forget(handle); // state consumed; don't run the drop slot
        return Ok(arc);
    }
    crate::consume_v2::ForeignVtableLayer::from_handle(handle, None)
        .map(|layer| layer as Arc<dyn Layer>)
}

/// [`import_handle`] minus the same-binary fast path: always validates and
/// wraps, so a single-process test drives the full FFI slot bridge (request
/// builders → vtable thunks → result decoders) that only a genuinely
/// cross-binary handoff would otherwise reach.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the handle has a null `state` or
///   `vtable` pointer.
/// - [`ErrorCode::IncompatibleType`] — the `vtable` is undersized or
///   `abi_version` does not match the supported Layer ABI version.
///
/// # Safety
///
/// Same contract as [`import_handle`].
#[cfg(feature = "test-codec")]
pub unsafe fn import_handle_force_foreign(
    handle: ffi::LayerHandle,
) -> Result<Arc<dyn Layer>, Error> {
    crate::consume_v2::ForeignVtableLayer::from_handle(handle, None)
        .map(|layer| layer as Arc<dyn Layer>)
}

/// Recover a child `LayerHandle` a factory thunk received (`create_wrapper`'s
/// `inner`, `create_router`'s children) as an `Arc<dyn Layer>`. Replaces the
/// G1 `recover_same_binary_child`, which dropped-and-refused every foreign
/// child with `Unsupported`: a same-binary child still unwraps to its
/// original Arc, and a foreign child — a host-native layer or another
/// image's export — now imports through the full [`import_handle`]
/// handshake instead, unblocking cross-binary wrapper/router composition.
///
/// # Safety
///
/// Same contract as [`import_handle`].
unsafe fn import_child(handle: ffi::LayerHandle) -> Result<Arc<dyn Layer>, Error> {
    unsafe { import_handle(handle) }
}

/// Mint the `LayerHandle` a factory thunk writes to its out-param,
/// registering it (debug builds) against `plugin_state` for the
/// plugin-drop tripwire.
#[cfg_attr(not(debug_assertions), allow(unused_variables))]
fn mint_factory_handle(
    plugin_state: *mut core::ffi::c_void,
    layer: Arc<dyn Layer>,
) -> ffi::LayerHandle {
    let state = leak_layer(layer);
    #[cfg(debug_assertions)]
    handoff_accounting::register(
        state,
        handoff_accounting::Origin::Factory(plugin_state as usize),
    );
    ffi::LayerHandle {
        state,
        vtable: &LAYER_VTABLE,
    }
}

/// Number of live `LayerHandle`s minted by this linked image's
/// [`export_handle`] that have not yet been dropped (or re-imported by the
/// same-binary fast path). Debug builds only — always 0 in release builds,
/// where the accounting is compiled out. Teardown probes use it to check
/// the "producer outlives its exported handles" contract; see
/// [`debug_assert_no_live_exports`].
pub fn live_export_count() -> usize {
    #[cfg(debug_assertions)]
    {
        handoff_accounting::live_exports()
    }
    #[cfg(not(debug_assertions))]
    {
        0
    }
}

/// Debug-build tripwire for producer teardown points (e.g. the Python
/// interpreter-finalization fence): panics in debug builds when handles
/// minted by this image's [`export_handle`] are still live, i.e. the
/// producer is being torn down out from under its consumers. A no-op in
/// release builds. There is no reachable dlclose path to hook — plugin
/// cdylibs are never unloaded by design — so explicit teardown fences like
/// this are the limit of the assertion.
pub fn debug_assert_no_live_exports(context: &str) {
    let live = live_export_count();
    debug_assert!(
        live == 0,
        "{context}: {live} exported LayerHandle(s) minted by this linked image are still \
         live at producer teardown — the ABI contract requires every exported handle to \
         be dropped (or imported) before its producer goes away",
    );
}

/// `test-codec` only: a by-value copy of this image's [`LAYER_VTABLE`].
/// Tests leak a copy at a fresh address to stand in for "the same vtable in
/// a second linked image" (defeating the same-binary ptr-eq fast path with
/// real, working thunks), or tweak its header fields to drive the ABI
/// handshake negatives against a vtable whose `drop` slot is genuinely
/// callable.
#[cfg(feature = "test-codec")]
pub fn layer_vtable_template_for_test() -> ffi::LayerVTableV1 {
    LAYER_VTABLE_INIT
}

/// `test-codec` + debug builds only: whether `state` (a `LayerHandle.state`
/// captured before an import/drop) is still registered in this image's
/// debug handle accounting. Pointer-keyed so concurrently running tests
/// cannot interfere with each other's assertions.
#[cfg(all(feature = "test-codec", debug_assertions))]
pub fn is_live_handle_for_test(state: *const core::ffi::c_void) -> bool {
    handoff_accounting::is_live(state as usize)
}

// =====================================================================
// Plugin state + the three-factory PLUGIN_VTABLE
// =====================================================================

/// One Layer factory a v2 cdylib ships, tagged by construction shape.
pub enum LayerFactory {
    Backend(Arc<dyn BackendFactory>),
    Wrapper(Arc<dyn WrapperFactory>),
    Router(Arc<dyn RouterFactory>),
}

impl LayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        match self {
            LayerFactory::Backend(f) => f.descriptor(),
            LayerFactory::Wrapper(f) => f.descriptor(),
            LayerFactory::Router(f) => f.descriptor(),
        }
    }
}

/// Plugin-scoped state for a v2 cdylib: the set of Layer factories it
/// ships, plus the borrowed-by-the-host FFI kind descriptors. Built by
/// the `ovstorage_layer_plugin!` macro and handed back as
/// `PluginInitResultV1.plugin_state`; the host borrows
/// `ffi_kinds` for the cdylib's lifetime, and both the
/// factories and the descriptor allocations are released when
/// `plugin_drop_thunk` drops this struct.
pub struct LayerPlugin {
    factories: Vec<LayerFactory>,
    /// Cached kind string per factory (parallel to `factories`), so
    /// `find` doesn't re-run `descriptor()` (which allocates the full
    /// schema Vecs) on every `create_*`.
    kinds: Vec<String>,
    /// Owned FFI projections of each factory's kind descriptor. Pinned
    /// inside the boxed `LayerPlugin`, so `ffi_kinds()`'s pointer stays
    /// valid until drop.
    ffi_kinds: Vec<ffi::LayerKindDescriptor>,
}

impl LayerPlugin {
    pub fn new(factories: Vec<LayerFactory>) -> Self {
        // One `descriptor()` call per factory; cache the kind string and
        // the FFI projection from it.
        let mut kinds = Vec::with_capacity(factories.len());
        let mut ffi_kinds = Vec::with_capacity(factories.len());
        for factory in &factories {
            let descriptor = factory.descriptor();
            kinds.push(descriptor.kind.clone());
            ffi_kinds.push(layer_kind_descriptor_to_ffi(descriptor));
        }
        Self {
            factories,
            kinds,
            ffi_kinds,
        }
    }

    /// Borrowed `(ptr, len)` over the FFI kind descriptors. Valid for the
    /// lifetime of the boxed `LayerPlugin`.
    fn ffi_kinds(&self) -> (*const ffi::LayerKindDescriptor, usize) {
        (self.ffi_kinds.as_ptr(), self.ffi_kinds.len())
    }

    fn find(&self, kind: &str) -> Option<&LayerFactory> {
        self.kinds
            .iter()
            .position(|k| k == kind)
            .map(|i| &self.factories[i])
    }
}

/// Leak a [`LayerPlugin`] into a `PluginInitResultV1.plugin_state`
/// pointer, reclaimed by `plugin_drop_thunk`.
pub fn leak_plugin(plugin: LayerPlugin) -> *mut core::ffi::c_void {
    Box::into_raw(Box::new(plugin)) as *mut core::ffi::c_void
}

/// Build the complete `PluginInitResultV1` for a v2 cdylib: leak the
/// `LayerPlugin` as plugin-scoped state, borrow its FFI kind descriptors,
/// and reference the shared [`PLUGIN_VTABLE`]. The
/// `ovstorage_layer_plugin!` macro calls this from
/// `ovstorage_plugin_init_v1`, keeping all raw-pointer handling inside
/// this (tested) crate rather than in macro-expanded code.
pub fn install_plugin(plugin: LayerPlugin) -> ffi::PluginInitResultV1 {
    let state = leak_plugin(plugin);
    // SAFETY: `state` was just produced by `leak_plugin`; the boxed
    // `LayerPlugin` (and the `ffi_kinds` Vec inside it) outlive the host's
    // use of the borrowed pointer, since the host releases it only via
    // `plugin_vtable.drop`.
    let (kinds, kind_count) = unsafe { (*(state as *const LayerPlugin)).ffi_kinds() };
    ffi::PluginInitResultV1 {
        struct_size: std::mem::size_of::<ffi::PluginInitResultV1>(),
        abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
        plugin_state: state,
        plugin_vtable: &PLUGIN_VTABLE,
        kinds,
        kind_count,
    }
}

unsafe fn plugin_ref<'a>(state: *mut core::ffi::c_void) -> &'a LayerPlugin {
    unsafe { &*(state as *const LayerPlugin) }
}

// `drop` slot of the Plugin vtable; invoked through the host's `HostPluginV2`
// to reclaim the leaked `LayerPlugin` state, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn plugin_drop_thunk(state: *mut core::ffi::c_void) {
    if state.is_null() {
        return;
    }
    // Producer-lifetime tripwire, reached via the host's `HostPluginV2` drop: the ABI
    // drop contract is exclusive-after-drain — every layer handle this
    // plugin's factories minted must already have been dropped when the
    // plugin itself drops. Per-plugin-instance accounting, so concurrent
    // hosts of the same mapped cdylib don't trip each other.
    #[cfg(debug_assertions)]
    debug_assert!(
        handoff_accounting::live_factory_handles(state) == 0,
        "v2 plugin dropped while {} of its factory-minted LayerHandle(s) are still live",
        handoff_accounting::live_factory_handles(state),
    );
    crate::ffi_runtime::guard_drop("LayerPlugin", || unsafe {
        let _ = Box::from_raw(state as *mut LayerPlugin);
    });
}

fn write_create_error(err: *mut *mut ffi::Error, e: Error) -> ffi::FfiStatus {
    if !err.is_null() {
        unsafe { *err = abi_alloc::abi_box(marshal::error::to_ffi(&e)) };
    }
    ffi::FFI_STATUS_ERR
}

// `create_backend` factory slot of the Plugin vtable; invoked through the
// plugin handle to mint a backend `LayerHandle`, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn plugin_create_backend(
    plugin_state: *mut core::ffi::c_void,
    request: *const ffi::CreateBackendRequest,
    out: *mut ffi::LayerHandle,
    err: *mut *mut ffi::Error,
) -> ffi::FfiStatus {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<Arc<dyn Layer>, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::CreateBackendRequest>(request, "CreateBackendRequest")?
        };
        let ffi::CreateBackendRequest {
            kind,
            instance_id,
            config,
            ..
        } = raw;
        let kind = unsafe { marshal::primitive::str_from_ffi(kind)? };
        let instance_id = unsafe { marshal::primitive::str_from_ffi(instance_id)? };
        let config = unsafe { config_from_ffi(config)? };
        let plugin = unsafe { plugin_ref(plugin_state) };
        match plugin.find(&kind) {
            Some(LayerFactory::Backend(factory)) => {
                let factory = factory.clone();
                crate::ffi_runtime::runtime().block_on(async move {
                    factory.create_backend(&instance_id, &config, None).await
                })
            }
            Some(_) => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("kind '{kind}' is not a backend layer"),
            )),
            None => Err(Error::new(
                ErrorCode::NotConfigured,
                format!("no backend factory for kind '{kind}'"),
            )),
        }
    }));
    match result {
        Ok(Ok(layer)) => {
            unsafe { std::ptr::write(out, mint_factory_handle(plugin_state, layer)) };
            ffi::FFI_STATUS_OK
        }
        Ok(Err(e)) => write_create_error(err, e),
        Err(_) => write_create_error(
            err,
            Error::new(ErrorCode::Internal, "plugin panicked in create_backend"),
        ),
    }
}

// `create_wrapper` factory slot of the Plugin vtable; invoked through the
// plugin handle to mint a wrapper `LayerHandle`, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn plugin_create_wrapper(
    plugin_state: *mut core::ffi::c_void,
    request: *const ffi::CreateWrapperRequest,
    out: *mut ffi::LayerHandle,
    err: *mut *mut ffi::Error,
) -> ffi::FfiStatus {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<Arc<dyn Layer>, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::CreateWrapperRequest>(request, "CreateWrapperRequest")?
        };
        let ffi::CreateWrapperRequest {
            inner,
            kind,
            instance_id,
            config,
            ..
        } = raw;
        let kind = unsafe { marshal::primitive::str_from_ffi(kind)? };
        let instance_id = unsafe { marshal::primitive::str_from_ffi(instance_id)? };
        let config = unsafe { config_from_ffi(config)? };
        // Same-plugin children unwrap; foreign children (host-native layers
        // or another image's exports) wrap — never drop-and-refuse.
        let inner = unsafe { import_child(inner)? };
        let plugin = unsafe { plugin_ref(plugin_state) };
        match plugin.find(&kind) {
            Some(LayerFactory::Wrapper(factory)) => {
                let factory = factory.clone();
                crate::ffi_runtime::runtime().block_on(async move {
                    factory
                        .create_wrapper(&instance_id, &config, inner, None)
                        .await
                })
            }
            Some(_) => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("kind '{kind}' is not a wrapper layer"),
            )),
            None => Err(Error::new(
                ErrorCode::NotConfigured,
                format!("no wrapper factory for kind '{kind}'"),
            )),
        }
    }));
    match result {
        Ok(Ok(layer)) => {
            unsafe { std::ptr::write(out, mint_factory_handle(plugin_state, layer)) };
            ffi::FFI_STATUS_OK
        }
        Ok(Err(e)) => write_create_error(err, e),
        Err(_) => write_create_error(
            err,
            Error::new(ErrorCode::Internal, "plugin panicked in create_wrapper"),
        ),
    }
}

// `create_router` factory slot of the Plugin vtable; invoked through the
// plugin handle to mint a router `LayerHandle`, never by C symbol name.
/// cbindgen:ignore
unsafe extern "C" fn plugin_create_router(
    plugin_state: *mut core::ffi::c_void,
    request: *const ffi::CreateRouterRequest,
    out: *mut ffi::LayerHandle,
    err: *mut *mut ffi::Error,
) -> ffi::FfiStatus {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<Arc<dyn Layer>, Error> {
        let raw = unsafe {
            ffi::read_options_at_ptr::<ffi::CreateRouterRequest>(request, "CreateRouterRequest")?
        };
        let ffi::CreateRouterRequest {
            kind,
            instance_id,
            config,
            children,
            child_count,
            ..
        } = raw;
        let kind = unsafe { marshal::primitive::str_from_ffi(kind)? };
        let instance_id = unsafe { marshal::primitive::str_from_ffi(instance_id)? };
        let config = unsafe { config_from_ffi(config)? };
        // Take ownership of every child handle up front, so an early
        // error drops the un-recovered remainder rather than leaking them.
        // The ownership split is: the host transfers every child HANDLE,
        // so this side must drop each one on any path; the array's
        // backing ALLOCATION is not transferred. `children` is a bare
        // pointer with no length-carrying owner and possibly a foreign
        // allocator — the host owns it (see the host-side owner
        // `crate::marshal::factory::RouterChildArray`) and frees it once
        // this call returns, so never free it here.
        let mut handles: Vec<ffi::LayerHandle> = (0..child_count)
            .map(|i| {
                let ffi::RouterChild { handle, .. } = unsafe { std::ptr::read(children.add(i)) };
                handle
            })
            .collect();
        let mut recovered = Vec::with_capacity(handles.len());
        for handle in handles.drain(..) {
            // Same-plugin children unwrap; foreign children wrap — never
            // drop-and-refuse. On a handshake failure `handles` still owns
            // the not-yet-drained children and drops them as it goes out of
            // scope here.
            recovered.push(unsafe { import_child(handle)? });
        }
        let plugin = unsafe { plugin_ref(plugin_state) };
        match plugin.find(&kind) {
            Some(LayerFactory::Router(factory)) => {
                let factory = factory.clone();
                crate::ffi_runtime::runtime().block_on(async move {
                    factory
                        .create_router(&instance_id, &config, recovered, None)
                        .await
                })
            }
            Some(_) => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("kind '{kind}' is not a router layer"),
            )),
            None => Err(Error::new(
                ErrorCode::NotConfigured,
                format!("no router factory for kind '{kind}'"),
            )),
        }
    }));
    match result {
        Ok(Ok(layer)) => {
            unsafe { std::ptr::write(out, mint_factory_handle(plugin_state, layer)) };
            ffi::FFI_STATUS_OK
        }
        Ok(Err(e)) => write_create_error(err, e),
        Err(_) => write_create_error(
            err,
            Error::new(ErrorCode::Internal, "plugin panicked in create_router"),
        ),
    }
}

/// Process-wide plugin vtable referenced from the macro-generated
/// `ovstorage_plugin_init_v1`.
// The Plugin vtable instance; the host reaches it through the plugin
// manifest/init entry point (its address is returned there), never by C symbol
// name, so it is not part of the generated header.
/// cbindgen:ignore
pub static PLUGIN_VTABLE: ffi::PluginVTableV1 = ffi::PluginVTableV1 {
    struct_size: std::mem::size_of::<ffi::PluginVTableV1>(),
    abi_version: ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
    drop: plugin_drop_thunk,
    create_backend: plugin_create_backend,
    create_wrapper: plugin_create_wrapper,
    create_router: plugin_create_router,
    _reserved: [None; 16],
};

/// `test-codec` only: a by-value copy of this image's [`PLUGIN_VTABLE`],
/// the [`layer_vtable_template_for_test`] counterpart. Tests tweak its
/// header fields to drive the loader's factory-vtable ABI handshake
/// negatives.
#[cfg(feature = "test-codec")]
pub fn plugin_vtable_template_for_test() -> ffi::PluginVTableV1 {
    ffi::PluginVTableV1 {
        struct_size: PLUGIN_VTABLE.struct_size,
        abi_version: PLUGIN_VTABLE.abi_version,
        drop: PLUGIN_VTABLE.drop,
        create_backend: PLUGIN_VTABLE.create_backend,
        create_wrapper: PLUGIN_VTABLE.create_wrapper,
        create_router: PLUGIN_VTABLE.create_router,
        _reserved: [None; 16],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    /// The export half of the descriptor chain: every Rust plugin's declaration
    /// leaves through `layer_kind_descriptor_to_ffi`. A constant substituted
    /// here would strip the declaration off every dynamically loaded Rust
    /// backend at once, and a host would report nothing — the graph builds and
    /// the writes succeed with no attribution ever recorded.
    #[test]
    fn the_export_thunk_carries_the_user_metadata_declaration() {
        for declared in [true, false] {
            let descriptor = LayerKindDescriptor {
                kind: "export-fixture".into(),
                layer_type: LayerType::Backend,
                display_name: "Export fixture".into(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: true,
                auth_capable: false,
                supports_user_metadata: declared,
            };
            let exported = layer_kind_descriptor_to_ffi(descriptor);
            assert_eq!(
                exported.supports_user_metadata, declared,
                "the export thunk dropped the plugin's declaration"
            );
            // Decode it back so the fixture's heap payloads are released.
            let decoded = unsafe {
                crate::consume_v2::layer_kind_descriptor_from_ffi(exported)
                    .expect("the exported descriptor decodes")
            };
            assert_eq!(decoded.supports_user_metadata, declared);
        }
    }

    use crate::{
        CancellationToken, ChangeEvent, ChangeKind, ChangeStream, Result, Url,
        WatchDirectoryCursor, WatchDirectoryOptions,
    };

    #[test]
    fn layer_vtable_is_self_consistent() {
        assert_eq!(
            LAYER_VTABLE.struct_size,
            std::mem::size_of::<ffi::LayerVTableV1>()
        );
        assert_eq!(
            LAYER_VTABLE.abi_version,
            ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION
        );
        assert!(LAYER_VTABLE._reserved.iter().all(Option::is_none));
    }

    #[test]
    fn plugin_vtable_is_self_consistent() {
        assert_eq!(
            PLUGIN_VTABLE.struct_size,
            std::mem::size_of::<ffi::PluginVTableV1>()
        );
        assert_eq!(
            PLUGIN_VTABLE.abi_version,
            ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION
        );
    }

    #[test]
    fn layer_kind_descriptor_encode_carries_auth_capable() {
        let encoded = layer_kind_descriptor_to_ffi(LayerKindDescriptor {
            kind: "auth-test".into(),
            layer_type: LayerType::Wrapper,
            display_name: "Auth test".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            supports_user_metadata: false,
            auth_capable: true,
        });

        assert!(encoded.auth_capable);
    }

    #[test]
    fn drop_thunks_handle_null() {
        unsafe {
            layer_drop_thunk(std::ptr::null_mut());
            plugin_drop_thunk(std::ptr::null_mut());
        }
    }

    #[derive(Default)]
    struct DecodeCapture {
        status: AtomicI32,
        code: std::sync::Mutex<Option<ErrorCode>>,
        message: std::sync::Mutex<Option<String>>,
    }

    extern "C" fn capture_decode_error(
        status: i32,
        result: *mut core::ffi::c_void,
        error: *mut ffi::Error,
        user_data: *mut core::ffi::c_void,
    ) {
        assert!(result.is_null());
        assert!(!error.is_null());
        let capture = unsafe { &*(user_data as *const DecodeCapture) };
        capture.status.store(status, Ordering::SeqCst);
        let error = unsafe { abi_alloc::abi_unbox(error) };
        let decoded = unsafe { marshal::error::from_ffi(error) };
        *capture.code.lock().unwrap() = Some(decoded.code());
        *capture.message.lock().unwrap() = Some(decoded.to_string());
    }

    #[test]
    fn watch_directory_thunk_reports_request_decode_error() {
        let mut request = std::mem::MaybeUninit::<ffi::WatchDirectoryRequest>::zeroed();
        let request = unsafe { request.assume_init_mut() };
        request.struct_size = 0;
        let capture = DecodeCapture {
            status: AtomicI32::new(ffi::FFI_STATUS_OK),
            ..Default::default()
        };

        unsafe {
            watch_directory_thunk(
                std::ptr::null_mut(),
                request,
                std::ptr::null(),
                capture_decode_error,
                (&capture as *const DecodeCapture).cast_mut().cast(),
            )
        };
        assert_eq!(capture.status.load(Ordering::SeqCst), ffi::FFI_STATUS_ERR);
        // A zero `struct_size` is an ABI/shape violation: the typed error must be
        // `InvalidArgument`, and the message must name the offending request.
        assert_eq!(
            capture.code.lock().unwrap().unwrap(),
            ErrorCode::InvalidArgument
        );
        assert!(
            capture
                .message
                .lock()
                .unwrap()
                .as_deref()
                .unwrap()
                .contains("WatchDirectoryRequest"),
            "decode error message must name the request struct"
        );
    }

    struct ParkedWatchLayer {
        dropped: Arc<AtomicBool>,
    }

    struct ParkedWatchStream {
        yielded: bool,
        dropped: Arc<AtomicBool>,
    }

    impl Iterator for ParkedWatchStream {
        type Item = Result<ChangeEvent>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.yielded {
                std::thread::park();
                return None;
            }
            self.yielded = true;
            Some(Ok(ChangeEvent::Object {
                address: Url::parse("test://root/a.bin").unwrap(),
                kind: ChangeKind::Created,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                at: std::time::SystemTime::UNIX_EPOCH,
                cursor: WatchDirectoryCursor(vec![1]),
            }))
        }
    }

    impl Drop for ParkedWatchStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl Layer for ParkedWatchLayer {
        fn name(&self) -> &str {
            "parked-watch"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "parked-watch".into(),
                layer_type: LayerType::Backend,
                display_name: "Parked watch test layer".into(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                auth_capable: false,
                supports_user_metadata: true,
            }
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            Ok(Box::new(ParkedWatchStream {
                yielded: false,
                dropped: self.dropped.clone(),
            }))
        }
    }

    extern "C" fn capture_watch_stream(
        status: i32,
        result: *mut core::ffi::c_void,
        error: *mut ffi::Error,
        user_data: *mut core::ffi::c_void,
    ) {
        let sender = unsafe {
            Box::from_raw(
                user_data as *mut std::sync::mpsc::Sender<Result<ffi::BackendChangeStream>>,
            )
        };
        let value = if status == ffi::FFI_STATUS_OK {
            assert!(error.is_null());
            Ok(unsafe { abi_alloc::abi_unbox(result.cast::<ffi::BackendChangeStream>()) })
        } else {
            assert!(result.is_null());
            let error = unsafe { abi_alloc::abi_unbox(error) };
            Err(unsafe { marshal::error::from_ffi(error) })
        };
        sender.send(value).unwrap();
    }

    #[test]
    fn watch_directory_thunk_round_trips_stream_and_drop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let layer: Arc<dyn Layer> = Arc::new(ParkedWatchLayer {
            dropped: dropped.clone(),
        });
        let state = leak_layer(layer);
        let request =
            crate::consume_v2::build_watch_directory(Request::new(WatchDirectoryRequest {
                prefix: Url::parse("test://root/").unwrap(),
                options: WatchDirectoryOptions::default(),
            }));
        let (sender, receiver) = std::sync::mpsc::channel::<Result<ffi::BackendChangeStream>>();

        unsafe {
            watch_directory_thunk(
                state,
                &request,
                std::ptr::null(),
                capture_watch_stream,
                Box::into_raw(Box::new(sender)).cast(),
            )
        };
        std::mem::forget(request);
        let ffi_stream = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        let mut stream = crate::consume_v2::change_stream_from_ffi(ffi_stream);
        assert!(matches!(
            stream.next(),
            Some(Ok(ChangeEvent::Object { .. }))
        ));
        drop(stream);
        assert!(dropped.load(Ordering::SeqCst));
        unsafe { layer_drop_thunk(state) };
    }
    /// A decode failure releases the fields the decoder never reached.
    ///
    /// The host `mem::forget`s the request before the slot runs, so the callee
    /// owns every field. What discharges that ownership on an early return is
    /// ordinary `Drop`: the decoder destructures the request by value, so the
    /// fields it never converts are owning locals, and `Str`, `Bytes` and
    /// `Body` each free their buffer when dropped — `Body`'s `Stream` arm by
    /// running the host's `drop_fn`.
    ///
    /// That is worth pinning because it is what makes releasing the request at
    /// the macro's error arm a DOUBLE free rather than a leak fix, which is
    /// the shape a reader coming from the C side will expect to need.
    ///
    /// `"not a url"` is the realistic trigger: it is valid UTF-8, so
    /// `str_from_ffi` succeeds and consumes the buffer, and only then does
    /// `Url::parse` reject it — so the failure lands with `body` and `options`
    /// still un-converted.
    ///
    /// What this observes is the BODY specifically, via the stream's drop
    /// flag. `WriteOptions::default()` carries no heap, so the un-converted
    /// options are not measured here and this test would not notice a decoder
    /// that released the body and forgot them. Covering that needs an
    /// allocation oracle rather than a drop flag; the C contract carries that
    /// dimension instead.
    ///
    /// The observable is the stream's drop rather than a sanitizer, so this
    /// fails deterministically on an ordinary test run. The mutant is
    /// `std::mem::forget` on any un-converted field; reordering the `?`s is
    /// NOT one, since every order leaves the remainder owned by a local.
    #[test]
    fn a_decode_failure_releases_the_fields_it_did_not_reach() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        // The flag lives in the iterator's closure, so it drops exactly when
        // the stream does — which is what releasing the body means.
        let stream = crate::BodyStream::from_iter(std::iter::from_fn(move || {
            let _held = &flag;
            None
        }));
        let request = ffi::WriteRequest {
            struct_size: std::mem::size_of::<ffi::WriteRequest>(),
            extensions: std::ptr::null(),
            address: crate::marshal::primitive::str_to_ffi("not a url".to_owned()),
            body: crate::marshal::payload::body_to_ffi(crate::Body::Stream(stream)),
            options: crate::marshal::options::write_options_to_ffi(crate::WriteOptions::default()),
            _reserved: Default::default(),
        };

        // Before the decode, so the assertion after it means "the decoder
        // released the body" rather than "the body was already gone". Without
        // this, a `body_to_ffi` that DROPPED the Rust `Body` instead of
        // forgetting it -- a use-after-free, not a leak -- would set the flag
        // early and the test would certify the opposite contract.
        assert!(
            !dropped.load(Ordering::SeqCst),
            "the body was released before the decode ran, so this test cannot \
             attribute a later release to the decoder"
        );

        let error = unsafe { body_request(request) }.expect_err("the address is not a URL");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            dropped.load(Ordering::SeqCst),
            "the body outlived a failed decode, so the request leaked the fields \
             the decoder never reached"
        );
    }

    /// A stream a completed op handed back stays usable after the host drops
    /// the Layer that produced it.
    ///
    /// This is the order a real host uses, not a contrived one:
    /// `notification_drain` upgrades its `Weak`, opens the watch, drops its
    /// only strong Layer reference, and then pulls the stream for the whole
    /// subscription — with the pull inside `spawn_blocking`, which `abort`
    /// cannot interrupt. The sibling test above drops the stream FIRST, so it
    /// says nothing about this direction.
    ///
    /// What this pins is that the stream keeps yielding, and still reclaims its
    /// producer, when the host has already released its Layer reference. It
    /// does NOT reproduce a producer that frees state `drop(state)` owns and
    /// leaves the stream pointing into it: `ParkedWatchStream` holds only a
    /// `bool` and an `Arc<AtomicBool>`, so it has nothing to dangle. That class
    /// is barely representable here at all, since `ChangeStream` is `'static`
    /// and a `Layer` impl cannot hand back a stream borrowing its own state.
    /// The C producer can express it, and `ovc_file_test_watch_outlives_layer`
    /// pins it there by counting layer destruction.
    ///
    /// Reversing the last two statements of this test is the mutant.
    #[test]
    fn a_stream_outlives_the_layer_that_produced_it() {
        let dropped = Arc::new(AtomicBool::new(false));
        let layer: Arc<dyn Layer> = Arc::new(ParkedWatchLayer {
            dropped: dropped.clone(),
        });
        let state = leak_layer(layer);
        let request =
            crate::consume_v2::build_watch_directory(Request::new(WatchDirectoryRequest {
                prefix: Url::parse("test://root/").unwrap(),
                options: WatchDirectoryOptions::default(),
            }));
        let (sender, receiver) = std::sync::mpsc::channel::<Result<ffi::BackendChangeStream>>();

        unsafe {
            watch_directory_thunk(
                state,
                &request,
                std::ptr::null(),
                capture_watch_stream,
                Box::into_raw(Box::new(sender)).cast(),
            )
        };
        std::mem::forget(request);
        let ffi_stream = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        let mut stream = crate::consume_v2::change_stream_from_ffi(ffi_stream);

        // The host relinquishes its Layer reference while the derived handle is
        // still live. Per the contract on `LayerHandle`, this may free layer
        // state but must not invalidate the stream.
        unsafe { layer_drop_thunk(state) };

        // ... and the stream still yields, and still tears down cleanly.
        assert!(
            matches!(stream.next(), Some(Ok(ChangeEvent::Object { .. }))),
            "the stream stopped yielding once its Layer reference was dropped"
        );
        drop(stream);
        assert!(
            dropped.load(Ordering::SeqCst),
            "the producer was never reclaimed"
        );
    }
}
