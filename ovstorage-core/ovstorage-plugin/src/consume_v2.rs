// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Consumer-side ABI-v2 (Layer) codec: FFI→Rust request builders,
//! introspection decoders, and update-stream bridges a host uses to drive
//! a foreign `LayerHandle`'s vtable — the inverse of [`crate::thunks_v2`]'s
//! producer-side `*_to_ffi` encoders.
//!
//! Relocated from `ovstorage`'s `loaded_v2.rs` so these
//! pieces sit next to the produce-side `thunks_v2` and can be reused by both
//! the host loader and plugin cdylibs that import foreign children.
//! `ovstorage` re-consumes them through its `pub use ovstorage_plugin::*`
//! glob. This module owns the generic [`ForeignVtableLayer`] — the `Layer`
//! over a foreign `ffi::LayerHandle` — plus the `on_complete` result decoders
//! (`decode_async_result` et al.).
//! The host-side plugin loader (`HostPluginV2`), the `LoadedV2*Factory` glue,
//! and the borrowed-manifest `clone_*` decoders stay in `ovstorage`.

use std::any::Any;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::Arc;

use tokio::sync::oneshot;

use crate::*;

// =====================================================================
// Dedicated-thread stream bridge (for the address-roots and update-stream
// FFI bridges below).
// =====================================================================

/// Drain a blocking `Result<T>` iterator on a dedicated std thread,
/// forwarding each item onto a bounded tokio mpsc channel, and hand back
/// the receiver as an async `Stream`. A dedicated thread is required
/// because a blocking FFI pull iterator's `next` may park awaiting a
/// server- or plugin-pushed frame, and a tokio worker must not block.
/// Shared by the address-roots bridge here and the update-stream
/// bridge (`loaded_v2::BridgeUpdateStream`).
pub fn spawn_bridge_thread<T, I>(
    thread_name: &'static str,
    iter: I,
) -> tokio_stream::wrappers::ReceiverStream<Result<T>>
where
    T: Send + 'static,
    I: Iterator<Item = Result<T>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<T>>(16);
    std::thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            for item in iter {
                if tx.blocking_send(item).is_err() {
                    break;
                }
            }
        })
        .expect("update-stream bridge thread");
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

pub fn cancel_ptr(handle: &Option<ffi::CancelTokenHandle>) -> *const ffi::CancelTokenFFI {
    handle.as_ref().map_or(std::ptr::null(), |h| h.as_ffi_ptr())
}

// =====================================================================
// Request builders (Rust `Request<T>` -> FFI request struct)
// =====================================================================

/// Encode a request's `Extensions` for the borrowed `*const Extensions`
/// request-prefix slot: a non-empty set becomes a heap `ffi::Extensions`
/// the caller owns, empty encodes as NULL (the ABI's "none" sentinel).
/// The consumer copies the entries out during the slot's synchronous
/// prologue and never adopts the allocation, so the caller reclaims the
/// returned pointer — via the NULL-safe
/// [`ffi::ovstorage_plugin_extensions_free`] — once the slot call
/// returns.
pub fn extensions_to_ffi(value: Extensions) -> *const ffi::Extensions {
    if value.is_empty() {
        return std::ptr::null();
    }
    ffi::abi_alloc::abi_box(ffi::Extensions {
        entries: marshal::primitive::extension_list_to_ffi(value.into_iter().collect()),
    })
}

pub fn build_stat(request: Request<StatRequest>) -> ffi::StatRequest {
    let Request { extensions, input } = request;
    ffi::StatRequest {
        struct_size: std::mem::size_of::<ffi::StatRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::stat_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_read(request: Request<ReadRequest>) -> ffi::ReadRequest {
    let Request { extensions, input } = request;
    ffi::ReadRequest {
        struct_size: std::mem::size_of::<ffi::ReadRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::read_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_write(request: Request<WriteRequest>) -> ffi::WriteRequest {
    let Request { extensions, input } = request;
    ffi::WriteRequest {
        struct_size: std::mem::size_of::<ffi::WriteRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        body: marshal::payload::body_to_ffi(input.body),
        options: marshal::options::write_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_continue_write(request: Request<ContinueWriteRequest>) -> ffi::ContinueWriteRequest {
    let Request { extensions, input } = request;
    ffi::ContinueWriteRequest {
        struct_size: std::mem::size_of::<ffi::ContinueWriteRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        redirects: marshal::redirect::write_redirect_batch_to_ffi(input.redirects),
        results: marshal::redirect::redirect_result_batch_to_ffi(input.results),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_delete(request: Request<DeleteRequest>) -> ffi::DeleteRequest {
    let Request { extensions, input } = request;
    ffi::DeleteRequest {
        struct_size: std::mem::size_of::<ffi::DeleteRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::delete_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_copy(request: Request<CopyRequest>) -> ffi::CopyRequest {
    let Request { extensions, input } = request;
    ffi::CopyRequest {
        struct_size: std::mem::size_of::<ffi::CopyRequest>(),
        extensions: extensions_to_ffi(extensions),
        source: marshal::address::object_address_to_ffi(input.source),
        destination: marshal::address::object_address_to_ffi(input.destination),
        options: marshal::options::copy_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_rename(request: Request<RenameRequest>) -> ffi::RenameRequest {
    let Request { extensions, input } = request;
    ffi::RenameRequest {
        struct_size: std::mem::size_of::<ffi::RenameRequest>(),
        extensions: extensions_to_ffi(extensions),
        source: marshal::address::object_address_to_ffi(input.source),
        destination: marshal::address::object_address_to_ffi(input.destination),
        options: marshal::options::rename_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_update_metadata(
    request: Request<UpdateMetadataRequest>,
) -> ffi::UpdateMetadataRequest {
    let Request { extensions, input } = request;
    ffi::UpdateMetadataRequest {
        struct_size: std::mem::size_of::<ffi::UpdateMetadataRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::update_metadata_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_check_access(request: Request<CheckAccessRequest>) -> ffi::CheckAccessRequest {
    let Request { extensions, input } = request;
    ffi::CheckAccessRequest {
        struct_size: std::mem::size_of::<ffi::CheckAccessRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        operations: marshal::access::access_ops_to_ffi(input.operations),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_list(request: Request<ListRequest>) -> ffi::ListRequest {
    let Request { extensions, input } = request;
    ffi::ListRequest {
        struct_size: std::mem::size_of::<ffi::ListRequest>(),
        extensions: extensions_to_ffi(extensions),
        prefix: marshal::address::object_address_to_ffi(input.prefix),
        options: marshal::options::list_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_list_versions(request: Request<ListVersionsRequest>) -> ffi::ListVersionsRequest {
    let Request { extensions, input } = request;
    ffi::ListVersionsRequest {
        struct_size: std::mem::size_of::<ffi::ListVersionsRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::list_versions_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_watch_directory(
    request: Request<WatchDirectoryRequest>,
) -> ffi::WatchDirectoryRequest {
    let Request { extensions, input } = request;
    ffi::WatchDirectoryRequest {
        struct_size: std::mem::size_of::<ffi::WatchDirectoryRequest>(),
        extensions: extensions_to_ffi(extensions),
        prefix: marshal::address::object_address_to_ffi(input.prefix),
        options: marshal::options::watch_directory_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_create_directory(
    request: Request<CreateDirectoryRequest>,
) -> ffi::CreateDirectoryRequest {
    let Request { extensions, input } = request;
    ffi::CreateDirectoryRequest {
        struct_size: std::mem::size_of::<ffi::CreateDirectoryRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::create_directory_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_delete_directory(
    request: Request<DeleteDirectoryRequest>,
) -> ffi::DeleteDirectoryRequest {
    let Request { extensions, input } = request;
    ffi::DeleteDirectoryRequest {
        struct_size: std::mem::size_of::<ffi::DeleteDirectoryRequest>(),
        extensions: extensions_to_ffi(extensions),
        address: marshal::address::object_address_to_ffi(input.address),
        options: marshal::options::delete_directory_options_to_ffi(input.options),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_connection_key(key: ConnectionKey) -> ffi::ConnectionKey {
    ffi::ConnectionKey {
        target: marshal::primitive::str_to_ffi(key.target),
        id: marshal::primitive::str_to_ffi(key.id.0),
    }
}

pub fn build_layer_connection(
    request: Request<LayerConnectionRequest>,
) -> ffi::LayerConnectionRequest {
    let Request { extensions, input } = request;
    let LayerConnectionRequest { target, connection } = input;
    ffi::LayerConnectionRequest {
        struct_size: std::mem::size_of::<ffi::LayerConnectionRequest>(),
        extensions: extensions_to_ffi(extensions),
        target: marshal::primitive::str_to_ffi(target),
        connection: marshal::descriptor::connection_request_to_ffi(connection),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_remove_connection(request: Request<ConnectionKey>) -> ffi::RemoveConnectionRequest {
    let Request { extensions, input } = request;
    ffi::RemoveConnectionRequest {
        struct_size: std::mem::size_of::<ffi::RemoveConnectionRequest>(),
        extensions: extensions_to_ffi(extensions),
        key: build_connection_key(input),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_update_credentials(
    request: Request<UpdateConnectionCredentialsRequest>,
) -> ffi::UpdateConnectionCredentialsRequest {
    let Request { extensions, input } = request;
    let UpdateConnectionCredentialsRequest { key, credentials } = input;
    ffi::UpdateConnectionCredentialsRequest {
        struct_size: std::mem::size_of::<ffi::UpdateConnectionCredentialsRequest>(),
        extensions: extensions_to_ffi(extensions),
        key: build_connection_key(key),
        credentials: marshal::descriptor::secret_bundle_to_ffi(credentials),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

fn build_attribute_patch(patch: AttributePatch) -> ffi::AttributePatch {
    let mut set = std::collections::HashMap::new();
    let mut remove = Vec::new();
    for (k, v) in patch.user_metadata {
        match v {
            Some(v) => {
                set.insert(k, v);
            }
            None => remove.push(k),
        }
    }
    ffi::AttributePatch {
        display_name: marshal::primitive::optional_to_ffi(
            patch.display_name,
            marshal::primitive::str_to_ffi,
        ),
        access_mode: marshal::primitive::optional_to_ffi(
            patch.access_mode,
            marshal::primitive::str_to_ffi,
        ),
        visible: marshal::primitive::optional_to_ffi(patch.visible, |b| b),
        set_user_metadata: marshal::primitive::key_value_list_to_ffi(set),
        remove_user_metadata: marshal::primitive::list_to_ffi(
            remove,
            marshal::primitive::str_to_ffi,
        ),
    }
}

pub fn build_update_attributes(
    request: Request<UpdateConnectionAttributesRequest>,
) -> ffi::UpdateConnectionAttributesRequest {
    let Request { extensions, input } = request;
    let UpdateConnectionAttributesRequest { key, patch } = input;
    ffi::UpdateConnectionAttributesRequest {
        struct_size: std::mem::size_of::<ffi::UpdateConnectionAttributesRequest>(),
        extensions: extensions_to_ffi(extensions),
        key: build_connection_key(key),
        patch: build_attribute_patch(patch),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

pub fn build_authenticate(request: Request<AuthenticateRequest>) -> ffi::AuthenticateRequest {
    let Request { extensions, input } = request;
    let AuthenticateRequest {
        key,
        capability,
        auto_open_browser,
    } = input;
    ffi::AuthenticateRequest {
        struct_size: std::mem::size_of::<ffi::AuthenticateRequest>(),
        extensions: extensions_to_ffi(extensions),
        key: build_connection_key(key),
        capability: marshal::auth::interactive_auth_capability_to_ffi(capability),
        auto_open_browser,
        _reserved: [std::ptr::null_mut(); 8],
    }
}

// =====================================================================
// Runtime-state introspection request builders (Rust args -> FFI request
// envelope). The three always-async slots (`root_info_for`,
// `list_address_roots`, `list_connections`) take a `*const Request`
// envelope like the data ops; `extensions` encodes as the borrowed
// request-context pointer (see [`extensions_to_ffi_ptr`]); the foreign thunk
// copies every extension during the slot's synchronous prologue.
// =====================================================================

/// Build the `root_info_for` request envelope from the resolved `url` and the
/// request-context `cx`. `url` becomes an owned [`ffi::Str`] the producer
/// adopts during the slot's synchronous prologue.
pub fn build_root_info_for(url: &Url, cx: &Extensions) -> ffi::RootInfoForRequest {
    ffi::RootInfoForRequest {
        struct_size: std::mem::size_of::<ffi::RootInfoForRequest>(),
        extensions: extensions_to_ffi_ptr(cx),
        url: marshal::address::object_address_to_ffi(url.clone()),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

/// Build the `list_address_roots` request envelope. Carries only the borrowed
/// request-context `extensions`; the slot takes no address.
pub fn build_list_address_roots(cx: &Extensions) -> ffi::ListAddressRootsRequest {
    ffi::ListAddressRootsRequest {
        struct_size: std::mem::size_of::<ffi::ListAddressRootsRequest>(),
        extensions: extensions_to_ffi_ptr(cx),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

/// Build the `list_connections` request envelope. Same `extensions`-only
/// prefix as [`build_list_address_roots`].
pub fn build_list_connections(cx: &Extensions) -> ffi::ListConnectionsRequest {
    ffi::ListConnectionsRequest {
        struct_size: std::mem::size_of::<ffi::ListConnectionsRequest>(),
        extensions: extensions_to_ffi_ptr(cx),
        _reserved: [std::ptr::null_mut(); 8],
    }
}

// =====================================================================
// Introspection decoders (FFI -> Rust): mirror of thunks_v2's *_to_ffi
// =====================================================================

/// Decode an **owned** FFI kind descriptor (e.g. the result of the
/// `descriptor` / `list_kinds` slots, which the host owns) by moving its
/// fields out.
///
/// # Safety
///
/// `value` must be a valid `ffi::LayerKindDescriptor` produced by an
/// ovstorage call; this takes ownership of and frees its heap payloads.
pub unsafe fn layer_kind_descriptor_from_ffi(
    value: ffi::LayerKindDescriptor,
) -> Result<LayerKindDescriptor> {
    let ffi::LayerKindDescriptor {
        layer_type,
        accepts_connections,
        supports_user_metadata,
        kind,
        display_name,
        description,
        config_schema,
        credential_schema,
        credential_methods,
        icon,
        auth_capable,
        ..
    } = value;
    Ok(LayerKindDescriptor {
        kind: unsafe { marshal::primitive::str_from_ffi(kind)? },
        layer_type: crate::thunks_v2::layer_type_from_ffi(layer_type),
        display_name: unsafe { marshal::primitive::str_from_ffi(display_name)? },
        description: unsafe {
            marshal::primitive::optional_from_ffi(description, |s| {
                marshal::primitive::str_from_ffi(s)
            })?
        },
        config_schema: unsafe {
            marshal::primitive::list_from_ffi(config_schema, |f| {
                marshal::descriptor::config_field_from_ffi(f)
            })?
        },
        credential_schema: unsafe {
            marshal::primitive::list_from_ffi(credential_schema, |f| {
                marshal::descriptor::credential_field_from_ffi(f)
            })?
        },
        credential_methods: unsafe {
            marshal::primitive::list_from_ffi(credential_methods, |m| {
                marshal::descriptor::credential_method_from_ffi(m)
            })?
        },
        icon: unsafe {
            marshal::primitive::optional_from_ffi(icon, |b| {
                Ok::<_, Error>(marshal::primitive::bytes_from_ffi(b))
            })?
        },
        accepts_connections,
        auth_capable,
        supports_user_metadata,
    })
}

fn range_read_strategy_from_ffi(value: ffi::RangeReadStrategy) -> RangeReadStrategy {
    match value {
        ffi::RangeReadStrategy::Native => RangeReadStrategy::Native,
        ffi::RangeReadStrategy::CachedReadThrough => RangeReadStrategy::CachedReadThrough,
        ffi::RangeReadStrategy::MaterializeOnly => RangeReadStrategy::MaterializeOnly,
        ffi::RangeReadStrategy::Unsupported => RangeReadStrategy::Unsupported,
    }
}

fn address_visibility_from_ffi(value: ffi::AddressVisibility) -> AddressVisibility {
    match value {
        ffi::AddressVisibility::Visible => AddressVisibility::Visible,
        ffi::AddressVisibility::Hidden => AddressVisibility::Hidden,
        ffi::AddressVisibility::Suppressed => AddressVisibility::Suppressed,
    }
}

unsafe fn alias_source_from_ffi(value: ffi::AliasSource) -> Result<AliasSource> {
    Ok(match value.tag {
        ffi::AliasSourceTag::Static => AliasSource::Static {
            layer: marshal::connection::config_layer_from_ffi(value.layer),
        },
        ffi::AliasSourceTag::Runtime => AliasSource::Runtime {
            persisted: value.persisted,
        },
        ffi::AliasSourceTag::BrokerDelivered => AliasSource::BrokerDelivered {
            broker_principal: unsafe {
                marshal::primitive::optional_from_ffi(value.broker_principal, |s| {
                    marshal::primitive::str_from_ffi(s)
                })?
            }
            .unwrap_or_default(),
        },
    })
}

unsafe fn alias_state_from_ffi(value: ffi::AliasState) -> Result<AliasState> {
    Ok(match value.tag {
        ffi::AliasStateTag::Live => AliasState::Live,
        ffi::AliasStateTag::Dangling => AliasState::Dangling,
        ffi::AliasStateTag::ChainTooLong => AliasState::ChainTooLong {
            reason: unsafe {
                marshal::primitive::optional_from_ffi(value.reason, |s| {
                    marshal::primitive::str_from_ffi(s)
                })?
            }
            .unwrap_or_default(),
        },
    })
}

unsafe fn route_source_from_ffi(value: ffi::RouteSource) -> Result<RouteSource> {
    let ffi::RouteSource {
        tag,
        layer,
        connection_id,
        broker_principal,
        alias_to,
        alias_source,
    } = value;
    Ok(match tag {
        ffi::RouteSourceTag::Static => RouteSource::Static {
            layer: marshal::connection::config_layer_from_ffi(layer),
        },
        ffi::RouteSourceTag::ConnectionContributed => RouteSource::ConnectionContributed {
            connection_id: unsafe { decode_connection_id(connection_id)? },
        },
        ffi::RouteSourceTag::BrokerDelivered => RouteSource::BrokerDelivered {
            broker_principal: unsafe {
                marshal::primitive::optional_from_ffi(broker_principal, |s| {
                    marshal::primitive::str_from_ffi(s)
                })?
            }
            .unwrap_or_default(),
            connection_id: unsafe { decode_connection_id(connection_id)? },
        },
        ffi::RouteSourceTag::Alias => RouteSource::Alias {
            to: {
                let raw = unsafe {
                    marshal::primitive::optional_from_ffi(alias_to, |s| {
                        marshal::primitive::str_from_ffi(s)
                    })?
                }
                .unwrap_or_default();
                Url::parse(&raw).map_err(|e| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid alias URL: {e}"),
                    )
                })?
            },
            alias_source: unsafe {
                marshal::primitive::optional_from_ffi(alias_source, |s| alias_source_from_ffi(s))?
            }
            .unwrap_or(AliasSource::Runtime { persisted: false }),
        },
    })
}

unsafe fn decode_connection_id(value: ffi::Optional<ffi::ConnectionId>) -> Result<ConnectionId> {
    let decoded = unsafe {
        marshal::primitive::optional_from_ffi(value, |c| {
            marshal::primitive::str_from_ffi(c.id).map(ConnectionId)
        })?
    };
    Ok(decoded.unwrap_or_else(|| ConnectionId(String::new())))
}

/// Normalize a plugin's published root, refusing one that names a different
/// node than it spells.
///
/// `Stack` canonicalizes requests but never values a layer returns, so a root
/// left in a non-canonical spelling never matches a canonical request and the
/// connection is silently unroutable — a `NoRoute` with no diagnostic. The
/// remedy is not symmetric with the request path, though: a root is a *claim*,
/// so the rules that leave the node alone are applied and the one that would
/// move it is refused.
///
/// The fragment is **stripped rather than refused**, which is the one place
/// this differs from validating a returned object address. Every request has
/// already lost its own fragment by the time it reaches routing, so a root that
/// kept one would be permanently unroutable — refusing at load would be
/// correct-but-useless where stripping makes it work.
fn root_from_ffi_str(raw: &str) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("invalid root URL: {e}")))?;
    if url.cannot_be_a_base() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            // Not interpolated: a published root may carry userinfo, and for
            // a cannot-be-a-base URL the redactor cannot normalize it.
            format!(
                "published root must have an authority; scheme '{}' was parsed \
                 as authority-less",
                url.scheme()
            ),
        ));
    }
    if !ovstorage_layer::parsing_preserves_node(raw) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            // `RedactedUrl`, not `redact_url` and never `raw`. Both drop
            // userinfo, but `redact_url` scrubs only the query names it knows
            // — measured, `?api_key=hunter2` survives it verbatim — while
            // `RedactedUrl` drops the query entirely. A published root is
            // operator- or plugin-supplied and its query may be a signed
            // token under any name, and the scheme, host and path are enough
            // to identify which root was refused.
            format!(
                "published root is rewritten by the URL parser before it can be checked: \
                 it parses to {}, a different node from the one the spelling names",
                crate::RedactedUrl(&url)
            ),
        ));
    }
    if !ovstorage_layer::canonicalize_preserves_node(&url) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            // Both spellings go through `RedactedUrl`, not through `raw`.
            // `Error`'s redactor scrubs by re-serializing a URL token it can
            // recognize, so a published root whose userinfo carries
            // token-breaking punctuation would pass through it verbatim; the
            // parsed URL has no such gap, and stripping at the source keeps the
            // whole diagnostic rather than dropping the rejected spelling.
            // `RedactedUrl` rather than `redact_url` for the reason the sibling
            // refusal above gives: `redact_url` scrubs only the query names it
            // knows, and the two spellings differ in their PATH, which is what
            // `RedactedUrl` keeps.
            format!(
                "published root resolves elsewhere: {} names {}",
                crate::RedactedUrl(&url),
                crate::RedactedUrl(&ovstorage_layer::canonicalize(url.clone()))
            ),
        ));
    }
    Ok(ovstorage_layer::canonicalize(url))
}

/// Decode an owned `ffi::RootInfo` by moving its fields out.
///
/// # Safety
///
/// `value` must be a valid `ffi::RootInfo` produced by an ovstorage call;
/// this takes ownership of and frees its heap payloads.
pub unsafe fn root_info_from_ffi(value: ffi::RootInfo) -> Result<RootInfo> {
    let ffi::RootInfo {
        root,
        display_name,
        layer_kind,
        connection_id,
        owning_target,
        capabilities,
        range_read_strategy,
        source,
        visible,
        visibility,
        alias_state,
        icon,
        user_metadata,
        ..
    } = value;
    let root_raw = unsafe { marshal::primitive::str_from_ffi(root)? };
    Ok(RootInfo {
        root: root_from_ffi_str(&root_raw)?,
        display_name: unsafe {
            marshal::primitive::optional_from_ffi(display_name, |s| {
                marshal::primitive::str_from_ffi(s)
            })?
        },
        layer_kind: unsafe { marshal::primitive::str_from_ffi(layer_kind)? },
        connection_id: unsafe {
            marshal::primitive::optional_from_ffi(connection_id, |c| {
                marshal::primitive::str_from_ffi(c.id).map(ConnectionId)
            })?
        },
        owning_target: unsafe {
            marshal::primitive::optional_from_ffi(owning_target, |s| {
                marshal::primitive::str_from_ffi(s)
            })?
        },
        capabilities: unsafe { marshal::capabilities::capabilities_from_ffi(capabilities)? },
        range_read_strategy: range_read_strategy_from_ffi(range_read_strategy),
        source: unsafe { route_source_from_ffi(source)? },
        visible,
        visibility: address_visibility_from_ffi(visibility),
        alias_state: unsafe {
            marshal::primitive::optional_from_ffi(alias_state, |s| alias_state_from_ffi(s))?
        },
        icon: unsafe {
            marshal::primitive::optional_from_ffi(icon, |b| {
                Ok::<_, Error>(marshal::primitive::bytes_from_ffi(b))
            })?
        },
        user_metadata: unsafe { marshal::metadata::user_metadata_from_ffi(user_metadata)? },
    })
}

/// Encode the host request-context bag for a synchronous introspection slot.
///
/// Faithful encoding is required here because an auth-capable foreign wrapper
/// may gate `list_kinds` using the caller's `AUTH_CREDENTIAL`; substituting an
/// empty bag would silently evaluate that security decision without identity.
/// The plugin thunk copies the borrowed entries during the slot call, so the
/// caller must reclaim the returned ABI allocation immediately after the call
/// returns. Native-only local extensions are omitted by [`Extensions`]'s
/// `IntoIterator` implementation. An empty bag uses the ABI's NULL sentinel.
fn extensions_to_ffi_ptr(cx: &Extensions) -> *const ffi::Extensions {
    extensions_to_ffi(cx.clone())
}

/// # Safety
///
/// `value` must be a valid `ffi::RootInfoSnapshot` produced by an
/// ovstorage call; this takes ownership of and frees its heap payloads.
pub unsafe fn root_info_snapshot_from_ffi(
    value: ffi::RootInfoSnapshot,
) -> Result<RootInfoSnapshot> {
    Ok(RootInfoSnapshot {
        roots: unsafe {
            marshal::primitive::list_from_ffi(value.roots, |r| root_info_from_ffi(r))?
        },
        updates: value.updates,
    })
}

/// # Safety
///
/// `value` must be a valid `ffi::ConnectionSnapshot` produced by an
/// ovstorage call; this takes ownership of and frees its heap payloads.
pub unsafe fn connection_snapshot_from_ffi(
    value: ffi::ConnectionSnapshot,
) -> Result<ConnectionSnapshot> {
    Ok(ConnectionSnapshot {
        connections: unsafe {
            marshal::primitive::list_from_ffi(value.connections, |c| {
                marshal::auth::connection_from_ffi(c)
            })?
        },
        updates: value.updates,
    })
}

/// # Safety
///
/// `value` must be a valid `ffi::ListPage` produced by an ovstorage call;
/// this takes ownership of and frees its heap payloads.
pub unsafe fn list_page_from_ffi(value: ffi::ListPage) -> Result<ListPage> {
    Ok(ListPage {
        items: unsafe {
            marshal::primitive::list_from_ffi(value.items, |o| {
                marshal::metadata::object_info_from_ffi(o)
            })?
        },
        next_page_token: unsafe {
            marshal::primitive::optional_from_ffi(value.next_page_token, |s| {
                marshal::primitive::str_from_ffi(s)
            })?
        },
    })
}

/// # Safety
///
/// `value` must be a valid `ffi::VersionPage` produced by an ovstorage
/// call; this takes ownership of and frees its heap payloads.
pub unsafe fn version_page_from_ffi(value: ffi::VersionPage) -> Result<VersionPage> {
    Ok(VersionPage {
        items: unsafe {
            marshal::primitive::list_from_ffi(value.items, |o| {
                marshal::metadata::object_info_from_ffi(o)
            })?
        },
        next_page_token: unsafe {
            marshal::primitive::optional_from_ffi(value.next_page_token, |s| {
                marshal::primitive::str_from_ffi(s)
            })?
        },
    })
}

/// Wrap a host-consumed `ffi::BackendChangeStream` as a Rust `ChangeStream`
/// of `ChangeEvent`. Drains the pull iterator on demand.
///
/// `Iter` holds the FFI stream by value; `ffi::BackendChangeStream`'s own
/// `Drop` runs the vtable `drop_fn` exactly once, so this adapter must NOT
/// also drop it — a second `drop_fn` call would double-free the plugin
/// state (cf. [`RootInfoChangeIter`] / [`ConnectionChangeIter`]).
pub fn change_stream_from_ffi(stream: ffi::BackendChangeStream) -> ChangeStream {
    struct Iter {
        stream: ffi::BackendChangeStream,
        done: bool,
    }
    impl Iterator for Iter {
        type Item = Result<ChangeEvent>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.done {
                return None;
            }
            let mut item = MaybeUninit::<ffi::BackendChangeEvent>::uninit();
            let mut error = MaybeUninit::<ffi::Error>::uninit();
            let step = unsafe {
                (self.stream.next_fn)(self.stream.state, item.as_mut_ptr(), error.as_mut_ptr())
            };
            match step {
                ffi::StreamStep::Yielded => {
                    let ev = unsafe {
                        marshal::change::backend_change_event_from_ffi(item.assume_init())
                    };
                    Some(ev.map(marshal::change::backend_change_event_to_change))
                }
                ffi::StreamStep::Ended => {
                    self.done = true;
                    None
                }
                // The backend change stream is terminal-on-error;
                // `TransientError` folds into `Failed`.
                ffi::StreamStep::Failed | ffi::StreamStep::TransientError => {
                    self.done = true;
                    Some(Err(unsafe {
                        marshal::error::from_ffi(error.assume_init())
                    }))
                }
            }
        }
    }
    // SAFETY: `Iter` owns the stream; the `ffi::BackendChangeStream` field's
    // own `Drop` runs the vtable `drop_fn` exactly once when `Iter` drops.
    unsafe impl Send for Iter {}
    Box::new(Iter {
        stream,
        done: false,
    })
}

// =====================================================================
// Introspection update-stream bridges (v2 FFI → host async streams)
//
// `list_address_roots` / `list_connections` each optionally hand back a
// plugin-emitted change stream. The plugin encodes its async
// `RootInfoUpdateStream` / `ConnectionUpdateStream` as a synchronous
// `ffi::*ChangeStream` pull iterator (`thunks_v2`); the host drains that
// iterator on a dedicated thread and re-exposes it as the async stream the
// Stack's root watchers consume. This is the inverse of the plugin encoder
// and mirrors the read-body bridge (`marshal::payload::read_result_from_ffi`).
// =====================================================================

/// # Safety
///
/// `value` must be a valid `ffi::RootInfoChange` produced by an ovstorage
/// call; this takes ownership of and frees its heap payloads.
pub unsafe fn root_info_change_from_ffi(value: ffi::RootInfoChange) -> Result<RootInfoChange> {
    let ffi::RootInfoChange { tag, roots } = value;
    let roots = unsafe { marshal::primitive::list_from_ffi(roots, |r| root_info_from_ffi(r))? };
    Ok(match tag {
        ffi::RootInfoChangeTag::Snapshot => RootInfoChange::Snapshot(roots),
        ffi::RootInfoChangeTag::Added => RootInfoChange::Added(roots),
        ffi::RootInfoChangeTag::Removed => RootInfoChange::Removed(roots),
        ffi::RootInfoChangeTag::Updated => RootInfoChange::Updated(roots),
    })
}

/// Decode the `connection` field an `Added` / `Updated` `ConnectionChange`
/// requires, mapping an absent payload to an `Internal` error naming `variant`.
///
/// # Safety
///
/// `opt` must be a valid `ffi::Optional<ffi::Connection>` produced by an
/// ovstorage call.
unsafe fn required_connection(
    opt: ffi::Optional<ffi::Connection>,
    variant: &'static str,
) -> Result<Connection> {
    unsafe {
        marshal::primitive::optional_from_ffi(opt, |c| marshal::auth::connection_from_ffi(c))?
    }
    .ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("ConnectionChange::{variant} missing connection"),
        )
    })
}

/// # Safety
///
/// `value` must be a valid `ffi::ConnectionChange` produced by an
/// ovstorage call; this takes ownership of and frees its heap payloads.
pub unsafe fn connection_change_from_ffi(value: ffi::ConnectionChange) -> Result<ConnectionChange> {
    // Every FFI field is initialized; the tag names which one carries meaning
    // (mirrors `thunks_v2::connection_change_to_ffi`). Fields the tag does not
    // name are dropped unread at the end of the arm.
    let ffi::ConnectionChange {
        tag,
        connection,
        connections,
        removed_id,
    } = value;
    Ok(match tag {
        ffi::ConnectionChangeTag::Added => {
            ConnectionChange::Added(unsafe { required_connection(connection, "Added")? })
        }
        ffi::ConnectionChangeTag::Updated => {
            ConnectionChange::Updated(unsafe { required_connection(connection, "Updated")? })
        }
        ffi::ConnectionChangeTag::Removed => ConnectionChange::Removed {
            id: unsafe {
                marshal::primitive::optional_from_ffi(removed_id, |c| {
                    marshal::connection::connection_id_from_ffi(c)
                })?
            }
            .ok_or_else(|| {
                Error::new(ErrorCode::Internal, "ConnectionChange::Removed missing id")
            })?,
        },
        ffi::ConnectionChangeTag::Snapshot => ConnectionChange::Snapshot(unsafe {
            marshal::primitive::list_from_ffi(connections, |c| {
                marshal::auth::connection_from_ffi(c)
            })?
        }),
    })
}

/// Drive one step of a plugin-emitted FFI pull iterator: invoke `next_fn`,
/// then map the `StreamStep` onto `Option<Result<T>>`. `Yielded` decodes the
/// freshly-written `out_item`; `TransientError` decodes the error WITHOUT
/// latching, so the update-stream watcher can resync and keep watching (the
/// Layer update-stream contract treats errors as recoverable resync signals,
/// not EOF); `Failed` decodes the error and latches `done` (terminal error);
/// `Ended` latches `done` and returns `None`. Once `done` is set the caller must
/// not call again (the plugin's `next_fn` is one-shot past a terminal frame).
/// Shared verbatim by [`RootInfoChangeIter`] and [`ConnectionChangeIter`].
///
/// # Safety
///
/// `state`/`next_fn` must come from a live FFI stream; `decode` must match the
/// `FfiItem` the plugin writes into `out_item` on `Yielded`.
unsafe fn ffi_pull_step<FfiItem, T>(
    state: *mut std::ffi::c_void,
    next_fn: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut FfiItem,
        *mut ffi::Error,
    ) -> ffi::StreamStep,
    done: &mut bool,
    decode: unsafe fn(FfiItem) -> Result<T>,
) -> Option<Result<T>> {
    let mut item = MaybeUninit::<FfiItem>::uninit();
    let mut error = MaybeUninit::<ffi::Error>::uninit();
    let step = unsafe { next_fn(state, item.as_mut_ptr(), error.as_mut_ptr()) };
    match step {
        ffi::StreamStep::Yielded => Some(unsafe { decode(item.assume_init()) }),
        ffi::StreamStep::Ended => {
            *done = true;
            None
        }
        ffi::StreamStep::TransientError => {
            // Recoverable error: surface it but do NOT latch, so the watcher
            // resyncs and the next pull can still yield further items.
            Some(Err(unsafe {
                marshal::error::from_ffi(error.assume_init())
            }))
        }
        ffi::StreamStep::Failed => {
            *done = true;
            Some(Err(unsafe {
                marshal::error::from_ffi(error.assume_init())
            }))
        }
    }
}

/// Sync iterator over an `ffi::RootInfoChangeStream`, decoding each frame. Holds
/// the FFI stream by value; its own `Drop` runs the vtable `drop_fn` exactly
/// once, so this adapter must NOT also drop it (a second `drop_fn` call would
/// double-free the plugin state — cf. `marshal::payload::BodyStreamIter`).
pub struct RootInfoChangeIter {
    pub stream: ffi::RootInfoChangeStream,
    pub done: bool,
}

impl Iterator for RootInfoChangeIter {
    type Item = Result<RootInfoChange>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        unsafe {
            ffi_pull_step(
                self.stream.state,
                self.stream.next_fn,
                &mut self.done,
                root_info_change_from_ffi,
            )
        }
    }
}

/// Sync iterator over an `ffi::ConnectionChangeStream`. Same drop discipline as
/// [`RootInfoChangeIter`].
pub struct ConnectionChangeIter {
    pub stream: ffi::ConnectionChangeStream,
    pub done: bool,
}

impl Iterator for ConnectionChangeIter {
    type Item = Result<ConnectionChange>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        unsafe {
            ffi_pull_step(
                self.stream.state,
                self.stream.next_fn,
                &mut self.done,
                connection_change_from_ffi,
            )
        }
    }
}

/// Async `Stream` that forwards each `Result<T>` from a blocking FFI
/// pull-iterator onto a tokio mpsc channel. The draining thread — and with it
/// the plugin-side subscription the iterator holds open — is spawned lazily, on
/// the first poll. A consumer that constructs the stream and drops it without
/// polling (the `Router::rebuild_maps` snapshot-only re-read across every child
/// on each root change, and consumers that discard the
/// update stream) therefore spawns no thread and releases the plugin
/// subscription immediately on drop, instead of leaking a parked thread and a
/// live subscription per call. Once started, the FFI `next_fn` may park until
/// the plugin pushes the next frame, so it is driven on a dedicated std thread —
/// a tokio worker must not block. A dropped stream that was
/// polled at least once leaves the bridge thread parked in the plugin's
/// blocking `next_fn` until the plugin's next emission or plugin teardown ends
/// the subscription.
struct BridgeUpdateStream<T, I> {
    state: BridgeState<T, I>,
}

enum BridgeState<T, I> {
    /// Not yet polled: the iterator (holding the FFI stream, hence the plugin
    /// subscription) is parked here and dropped intact if the stream is dropped
    /// before any poll.
    Idle {
        thread_name: &'static str,
        iter: Option<I>,
    },
    Draining(tokio_stream::wrappers::ReceiverStream<Result<T>>),
}

impl<T, I> futures::Stream for BridgeUpdateStream<T, I>
where
    T: Send + 'static,
    I: Iterator<Item = Result<T>> + Send + Unpin + 'static,
{
    type Item = Result<T>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let BridgeState::Idle { thread_name, iter } = &mut this.state {
            let iter = iter.take().expect("bridge iterator taken exactly once");
            this.state = BridgeState::Draining(spawn_bridge_thread(thread_name, iter));
        }
        match &mut this.state {
            BridgeState::Draining(rx) => std::pin::Pin::new(rx).poll_next(cx),
            BridgeState::Idle { .. } => unreachable!("state advanced to Draining above"),
        }
    }
}

/// Wrap a blocking FFI pull-iterator as the lazily-drained async `Stream` the
/// host Stack consumes. See `BridgeUpdateStream` for the laziness contract.
///
/// Route-epoch disposition: live root/connection propagation at the Stack layer
/// happens through these bridged update streams; there is no Stack-layer epoch
/// counter.
pub fn bridge_update_stream<T, I>(
    thread_name: &'static str,
    iter: I,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<T>> + Send>>
where
    T: Send + 'static,
    I: Iterator<Item = Result<T>> + Send + Unpin + 'static,
{
    Box::pin(BridgeUpdateStream {
        state: BridgeState::Idle {
            thread_name,
            iter: Some(iter),
        },
    })
}

// =====================================================================
// `on_complete` result decoders. Each callback-shaped slot fires
// `on_complete(status, result, error, user_data)` exactly once; these
// turn the `(status, result, error)` outcome into a `Result`.
// =====================================================================

/// Decode `(status, result, error)` into `Result<R, Error>`.
///
/// **Pointer presence is the primary signal**, not `status`:
/// `ErrorCode::NotFound` has discriminant `0`, colliding with
/// "0 = success."
///
/// Kept a safe fn (not `unsafe`): `result`/`error` are the exactly-once
/// `on_complete` pointers the producer minted on the ABI heap for this
/// callback, reclaimed here.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn decode_async_result<FfiR: 'static, R>(
    _status: i32,
    result: *mut FfiR,
    error: *mut ffi::Error,
    on_ok: impl FnOnce(*mut FfiR) -> Result<R>,
) -> Result<R> {
    if !error.is_null() {
        if !result.is_null() {
            // Reclaim the spurious result so it doesn't leak. It may own
            // producer teardown (a change stream, a body, a `list_*` envelope
            // whose `Drop` drives an update stream's `drop_fn`), and
            // `abi_box_free` would run that `Drop` right here, inside the
            // producer's own `on_complete`. Hand it to the call's retirement
            // instead.
            // SAFETY: contract — the producer minted `result` on the ABI heap.
            let spurious = unsafe { ffi::abi_alloc::abi_unbox(result) };
            orphan_producer_value(spurious);
        }
        // SAFETY: contract — the producer minted `error` on the ABI heap.
        let boxed = unsafe { ffi::abi_alloc::abi_unbox(error) };
        Err(unsafe { marshal::error::from_ffi(boxed) })
    } else if !result.is_null() {
        on_ok(result)
    } else {
        Err(Error::new(
            ErrorCode::Internal,
            "plugin produced null result and null error in non-unit method",
        ))
    }
}

/// Unit variant of [`decode_async_result`]; same pointer contract.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn decode_async_unit_result(_status: i32, error: *mut ffi::Error) -> Result<()> {
    if error.is_null() {
        Ok(())
    } else {
        let boxed = unsafe { ffi::abi_alloc::abi_unbox(error) };
        Err(unsafe { marshal::error::from_ffi(boxed) })
    }
}

/// Producer dropped its `on_complete` Sender before firing.
pub fn dropped_sender_error() -> Error {
    Error::new(
        ErrorCode::Internal,
        "plugin dropped on_complete sender without firing",
    )
}

/// Decode the `list_address_roots` slot's success payload: split the heap
/// [`ffi::ListAddressRootsResult`] into its snapshot and optional change
/// stream, bridging the latter into the async [`RootInfoUpdateStream`] the
/// Stack's root watchers consume (inverse of
/// `thunks_v2::list_address_roots_thunk`). The envelope's two fields are read
/// out and its own `Drop` suppressed (via [`std::mem::ManuallyDrop`]) so
/// neither the snapshot buffers nor the change stream is freed twice. The
/// change stream is adopted (its `Drop` runs the producer `drop_fn`) BEFORE
/// the snapshot is decoded, so a snapshot-decode error still releases the
/// producer-side subscription rather than leaking it.
///
/// # Safety
///
/// `result` must be a non-null ABI-heap [`ffi::ListAddressRootsResult`] the
/// producer minted for the `list_address_roots` `on_complete`.
unsafe fn decode_list_address_roots_result(
    result: *mut ffi::ListAddressRootsResult,
) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
    // Reclaim the envelope allocation as `ManuallyDrop` so reading its two
    // fields out by value does not also run `ListAddressRootsResult::Drop`
    // (which frees `updates`); the fields' ownership moves here instead.
    let envelope = unsafe {
        ffi::abi_alloc::abi_unbox(
            result as *mut std::mem::ManuallyDrop<ffi::ListAddressRootsResult>,
        )
    };
    let snapshot_ffi = unsafe { std::ptr::read(&envelope.snapshot) };
    let updates_ptr = envelope.updates;
    let updates_iter = if updates_ptr.is_null() {
        None
    } else {
        Some(RootInfoChangeIter {
            stream: unsafe { ffi::abi_alloc::abi_unbox(updates_ptr) },
            done: false,
        })
    };
    // A decode failure here runs inside the producer's `on_complete` frame, and
    // `updates_iter` already owns the producer's change stream — releasing it in
    // place would drive that producer's `drop_fn` re-entrantly under its own
    // call. Hand it to `complete_call`, which retires it holding this call's
    // pin, so the Layer state it came from cannot be released first. Only when
    // there IS a stream: orphaning `None` would mint a retirement with nothing
    // to release, and a retirement that cannot spawn strands the pin — and with
    // it the Layer state — for the process lifetime.
    let snapshot = match unsafe { root_info_snapshot_from_ffi(snapshot_ffi) } {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if let Some(iter) = updates_iter {
                orphan_producer_value(iter);
            }
            return Err(error);
        }
    };
    let updates = updates_iter
        .map(|iter| bridge_update_stream::<RootInfoChange, _>("ovs-v2-root-update", iter));
    Ok((snapshot, updates))
}

/// Decode the `list_connections` slot's success payload. Same ownership and
/// adopt-before-decode discipline as [`decode_list_address_roots_result`]
/// (inverse of `thunks_v2::list_connections_thunk`).
///
/// # Safety
///
/// `result` must be a non-null ABI-heap [`ffi::ListConnectionsResult`] the
/// producer minted for the `list_connections` `on_complete`.
unsafe fn decode_list_connections_result(
    result: *mut ffi::ListConnectionsResult,
) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
    let envelope = unsafe {
        ffi::abi_alloc::abi_unbox(result as *mut std::mem::ManuallyDrop<ffi::ListConnectionsResult>)
    };
    let snapshot_ffi = unsafe { std::ptr::read(&envelope.snapshot) };
    let updates_ptr = envelope.updates;
    let updates_iter = if updates_ptr.is_null() {
        None
    } else {
        Some(ConnectionChangeIter {
            stream: unsafe { ffi::abi_alloc::abi_unbox(updates_ptr) },
            done: false,
        })
    };
    // A decode failure here runs inside the producer's `on_complete` frame, and
    // `updates_iter` already owns the producer's change stream — releasing it in
    // place would drive that producer's `drop_fn` re-entrantly under its own
    // call. Hand it to `complete_call`, which retires it holding this call's
    // pin, so the Layer state it came from cannot be released first. Only when
    // there IS a stream: orphaning `None` would mint a retirement with nothing
    // to release, and a retirement that cannot spawn strands the pin — and with
    // it the Layer state — for the process lifetime.
    let snapshot = match unsafe { connection_snapshot_from_ffi(snapshot_ffi) } {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if let Some(iter) = updates_iter {
                orphan_producer_value(iter);
            }
            return Err(error);
        }
    };
    let updates = updates_iter
        .map(|iter| bridge_update_stream::<ConnectionChange, _>("ovs-v2-conn-update", iter));
    Ok((snapshot, updates))
}

// =====================================================================
// The foreign-vtable `Layer`
// =====================================================================

/// Producer-supplied fallback for [`ForeignVtableLayer::descriptor`] when the
/// live `descriptor` slot returns a value the host cannot decode. Plugin loads
/// pass a hook returning the loaded plugin's first advertised manifest kind
/// (preserving the pre-generalization fallback); a bare imported handle has no
/// manifest, so it passes `None` and a minimal descriptor is synthesized.
pub type KindsFallback = Box<dyn Fn() -> Option<LayerKindDescriptor> + Send + Sync>;

/// The producer-minted `state`/`vtable` pair behind a foreign Layer, released
/// through the vtable's `drop` slot when the last reference goes away.
///
/// The ABI reads `drop` as **exclusive-after-drain**: the producer may be told
/// to release `state` only once no call against it is outstanding. There is no
/// verb in the frozen ABI meaning "abandon your call", so a host that cannot
/// drain must instead wait, and the reference count is how this host waits.
/// Exactly two kinds of owner exist:
///
/// - the [`ForeignVtableLayer`] itself, for as long as the host Stack holds it;
/// - one [`CallPin`] per in-flight async slot call, living inside the
///   `user_data` the producer carries and released by its `on_complete`.
///
/// So the drop slot runs when the Layer is gone **and** every call it started
/// has completed, whichever finishes last. A producer that never completes
/// pins its own state — and the factory/plugin mapping `keepalive` holds — for
/// the process lifetime, which is the same terminal case the pure-C host
/// accepts: the alternative is freeing state under a live call.
struct ForeignLayerState {
    /// Pins the producer of `state`/`vtable` alive for as long as the state is
    /// reachable. Type-erased so this generic adapter need not name the
    /// loaded-plugin type (which lives in `ovstorage`); today's value is
    /// `Arc<HostPluginV2>`.
    keepalive: Option<Arc<dyn Any + Send + Sync>>,
    state: *mut c_void,
    vtable: *const ffi::LayerVTableV1,
}

// SAFETY: concurrent slot invocation is an existing ABI-level obligation — the
// pure-C host drives I/O slots from 2–32 pool workers with no serialization,
// and `drop` runs exclusive-after-drain. The raw pointers stay valid while
// `keepalive` pins the producer (or, for a bare import, the producer-lifetime
// ABI contract holds); the reference count above is what keeps drop exclusive.
unsafe impl Send for ForeignLayerState {}
unsafe impl Sync for ForeignLayerState {}

impl Drop for ForeignLayerState {
    fn drop(&mut self) {
        if !self.state.is_null() && !self.vtable.is_null() {
            // SAFETY: `vtable->drop` is valid for the lifetime of `state`, and
            // this is the last reference — so every call this Layer started has
            // completed and the ABI's exclusive-after-drain precondition holds.
            unsafe { ((*self.vtable).drop)(self.state) };
            self.state = std::ptr::null_mut();
            self.vtable = std::ptr::null();
        }
        // Keep the producer pinned until after the drop slot runs.
        let _ = &self.keepalive;
    }
}

/// One in-flight call's share of the foreign Layer state, held inside the
/// `user_data` the producer carries and released by its `on_complete`.
///
/// # Where the drain point is, exactly
///
/// The ABI puts it at the completion callback: "invoke `vtable->drop(state)`
/// exactly once when done, **after every in-flight op has completed**", and an
/// op completes when its [`ffi::OnComplete`] fires (exactly once). So a pin
/// released from `on_complete` has, by the contract, satisfied
/// exclusive-after-drain, and the host owes the producer nothing further.
///
/// # Why the release is still moved off that thread
///
/// The contract does not make a re-entrant release *safe in practice*. A
/// producer that completes while holding its own lock — `on_complete(...)`
/// then `pthread_mutex_unlock(&s->lock)` — is common and is not forbidden
/// anywhere in the header. Running `vtable->drop(state)` inside that frame
/// turns such a producer's unwind into a guaranteed use-after-free, and a
/// `drop` slot that takes the same lock into a self-deadlock. Handing the
/// state to a retirement thread turns both into a race the producer's prompt
/// return normally wins. The pure-C host makes the identical trade
/// (`ovc_stack_build_slot_release`: `from_completion` + re-enters-plugin →
/// `ovc_runtime_submit`, never released on the completing thread).
///
/// # What this does NOT establish
///
/// It is hardening, not drain. Nothing waits for `on_complete` to *return*,
/// so a producer that keeps touching `state` after firing its completion still
/// races the drop slot — it has simply traded a certainty for a race. The
/// frozen ABI has no verb meaning "my call has returned", so no host can close
/// that window; both hosts carry it identically. What the host does guarantee
/// is the part the ABI does define: the drop slot never runs while an op is
/// outstanding, i.e. before that op's `on_complete` has fired.
///
/// A synchronous completion — a producer that fires `on_complete` from inside
/// the slot call, before it returns — cannot reach retirement at all: the host
/// holds `&self` across the whole slot invocation, so the Layer's own
/// reference is live and this pin is never the last one. See
/// `foreign_layer_abandoned_call.rs`.
///
/// # Ordering comes from the count, not from who happens to be last
///
/// Producer-owned values derived from this Layer — an unread outcome, anything
/// [`orphan_producer_value`] collected — must be torn down before the state
/// they came from. [`complete_call`] gets that by holding this pin until those
/// teardowns are done and releasing it last, on the same thread
/// ([`release_in_place`](Self::release_in_place)). Whether this pin was the
/// last reference is then irrelevant: while it is alive the state cannot be
/// released, by anyone, on any thread.
struct CallPin(Option<Arc<ForeignLayerState>>);

impl CallPin {
    /// Release this pin on the calling thread.
    ///
    /// Only sound where no producer frame is on the stack — in practice, from
    /// inside the retirement thread itself, after the producer-owned values
    /// derived from this Layer have already been torn down there. Holding the
    /// pin until that point is what orders those teardowns before the Layer's
    /// own `drop` slot: the state cannot be released while any reference to it
    /// is alive, so ordering is enforced by the reference count rather than by
    /// two retirements happening to run in the right sequence.
    fn release_in_place(mut self) {
        drop(self.0.take());
    }
}

impl Drop for CallPin {
    fn drop(&mut self) {
        let Some(pinned) = self.0.take() else { return };
        // `into_inner` is the atomic last-reference take: `Some` means this
        // frame is the sole owner and would otherwise run the drop slot here.
        if let Some(state) = Arc::into_inner(pinned) {
            retire_off_thread(move || drop(state));
        }
    }
}

/// Carries teardown to the retirement thread, stranding it if that thread never
/// starts.
///
/// [`std::thread::Builder::spawn`] takes its closure **by value and drops it on
/// failure**, so a closure owning the teardown outright would run it on exactly
/// the thread the hop exists to keep it off. Wrapping it in a
/// [`ManuallyDrop`](std::mem::ManuallyDrop) makes the failure path a no-op drop:
/// the work is stranded for the process lifetime rather than performed in the
/// producer's frame. Dropping a `Retirement` without calling
/// [`run`](Self::run) is therefore the strand, and is the whole point of the
/// type — it is exercised directly by
/// `dropping_a_retirement_strands_its_work_instead_of_running_it`, which does
/// not depend on being able to make a real spawn fail.
struct Retirement<F: FnOnce()>(std::mem::ManuallyDrop<F>);

impl<F: FnOnce()> Retirement<F> {
    fn new(work: F) -> Self {
        Self(std::mem::ManuallyDrop::new(work))
    }

    /// Perform the teardown. Consumes the carrier, so it runs at most once.
    fn run(mut self) {
        // SAFETY: `self` is consumed here and the value is taken exactly once;
        // the `ManuallyDrop` left behind drops as a no-op.
        let work = unsafe { std::mem::ManuallyDrop::take(&mut self.0) };
        work();
    }
}

/// A producer-owned value a completion callback adopted but cannot deliver,
/// erased to the teardown it needs.
type Orphan = Box<dyn FnOnce() + Send>;

thread_local! {
    /// Orphans collected for the completion callback currently running on this
    /// thread. `Some` exactly while [`collect_orphans`] is on the stack, which
    /// is exactly while a producer's `on_complete` frame is.
    static ORPHANS: std::cell::RefCell<Option<Vec<Orphan>>> =
        const { std::cell::RefCell::new(None) };
}

/// Hand a producer-owned value to the surrounding completion callback's
/// retirement instead of releasing it here.
///
/// Several places inside an `on_complete` frame adopt a producer-owned value
/// and then find they cannot deliver it: a change stream adopted before its
/// snapshot fails to decode, a result that arrived alongside an error, a body
/// stream orphaned by a metadata decode failure. Releasing any of them where it
/// is found runs producer teardown inside the producer's own call — the hazard
/// [`CallPin`] exists to avoid — and releasing it on a retirement of its own
/// would race the Layer state's release rather than being ordered before it.
///
/// So the value goes to [`complete_call`], the one frame that holds the call's
/// pin and can retire it *and* the Layer state together, in order, on one
/// thread. With no scope active there is no producer frame on the stack, and
/// releasing in place is exactly what the caller wants.
pub(crate) fn orphan_producer_value<T: 'static>(value: T) {
    /// Moves a producer-minted payload to the retirement thread.
    ///
    /// The payload is owned solely by this frame, and the ABI's thread contract
    /// already lets a producer's teardown run on any thread ("slots may be
    /// invoked concurrently from multiple threads; `drop` is
    /// exclusive-after-drain"), which is precisely what a retirement performs.
    struct Retired<T>(T);
    // SAFETY: see above — sole ownership plus the ABI's own thread contract.
    unsafe impl<T> Send for Retired<T> {}

    let retained = ORPHANS.with(|slot| {
        let mut borrowed = slot.borrow_mut();
        match borrowed.as_mut() {
            Some(list) => {
                let retired = Retired(value);
                list.push(Box::new(move || drop(retired)));
                None
            }
            None => Some(value),
        }
    });
    // Outside the borrow: releasing here must not re-enter the `RefCell`.
    drop(retained);
}

/// Run `work` with orphan collection active, returning whatever it produced
/// alongside anything it orphaned.
fn collect_orphans<R>(work: impl FnOnce() -> R) -> (R, Vec<Orphan>) {
    /// Restores the enclosing scope even if `work` unwinds.
    struct Scope(Option<Vec<Orphan>>);
    impl Drop for Scope {
        fn drop(&mut self) {
            ORPHANS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    let mut scope = Scope(ORPHANS.with(|slot| slot.replace(Some(Vec::new()))));
    let result = work();
    let collected = ORPHANS
        .with(|slot| slot.replace(scope.0.take()))
        .unwrap_or_default();
    std::mem::forget(scope);
    (result, collected)
}

/// Run producer-visible teardown on a thread of the host's own, off the
/// completing thread (see [`CallPin`] for why).
///
/// `work` is whatever this frame would otherwise have released in place: a
/// foreign Layer's `drop` slot, an unread outcome's producer-owned handles, or
/// both in order.
///
/// `Builder::spawn` takes the closure **by value and drops it on failure**, so
/// a closure owning that teardown outright would run it on exactly the thread
/// this function exists to keep it off. `work` therefore travels inside a
/// [`ManuallyDrop`](std::mem::ManuallyDrop): a failed spawn drops the closure
/// without ever calling it, stranding what it owns for the process lifetime.
/// That is deliberate and matches the pure-C host, which likewise strands a
/// slot it cannot queue rather than reaping it on the completing thread — a
/// leak under thread exhaustion is recoverable, a release into a live producer
/// frame is not.
fn retire_off_thread<F: FnOnce() + Send + 'static>(work: F) {
    let work = Retirement::new(work);
    let spawned = std::thread::Builder::new()
        .name("ovs-layer-retire".to_string())
        .spawn(move || work.run());
    if let Err(error) = spawned {
        tracing::error!(
            error = %error,
            "cannot spawn a retirement thread for an abandoned foreign Layer; \
             stranding its state for the process lifetime",
        );
    }
}

/// The `user_data` every async slot call hands the producer: the completion
/// channel and the call's share of the foreign Layer state. Pairing them in
/// one allocation makes the pin survive request marshalling — a callback
/// cannot reclaim the sender without also recovering it.
struct SlotCall<T> {
    tx: oneshot::Sender<Result<T>>,
    pin: CallPin,
}

/// The host side of one in-flight slot call: the completion channel, plus the
/// cancel handle to fire if the host gives up before the producer answers.
///
/// [`ForeignVtableLayer::begin_call`] mints this together with the
/// producer's `user_data`, so every async slot in this module opens its call
/// the same way and none can skip the pin.
struct SlotHandle<'a, T> {
    rx: oneshot::Receiver<Result<T>>,
    /// Armed until [`complete`](Self::complete) observes the producer's
    /// answer. `CancelTokenHandle::drop` aborts the host→FFI bridge task, and
    /// that task is the only path from the host's `CancellationToken` to the
    /// FFI cancel state the producer's call polls — so a future dropped
    /// mid-flight takes the bridge down with it and the producer is never told
    /// to stop. Firing the FFI state directly on the abandoning thread is what
    /// lets a cooperative producer finish, release its pin, and let the Layer
    /// go.
    abandon_cancel: Option<&'a ffi::CancelTokenHandle>,
}

impl<T> SlotHandle<'_, T> {
    /// Await the producer's completion. Returning at all means the call
    /// drained, so the abandon signal is disarmed.
    async fn complete(mut self) -> Result<T> {
        let res = (&mut self.rx).await.map_err(|_| dropped_sender_error());
        self.abandon_cancel = None;
        res?
    }
}

impl<T> Drop for SlotHandle<'_, T> {
    fn drop(&mut self) {
        if let Some(handle) = self.abandon_cancel {
            handle.cancel_producer();
        }
    }
}

/// Deliver one slot completion: reclaim the `user_data`
/// [`ForeignVtableLayer::begin_call`] handed the producer, decode the
/// producer's answer, forward it, and release the call's pin — retiring
/// anything producer-owned that is left in this frame rather than releasing it
/// here.
///
/// `decode` runs inside this frame on purpose. It is the step that adopts the
/// producer's payload, so it is also the step that can end up holding a
/// producer-owned value it cannot deliver; running it under
/// [`collect_orphans`] is what lets those values ride this call's pin
/// ([`orphan_producer_value`]) instead of being released where they are found.
///
/// Everything producer-visible then goes onto **one** retirement, in this
/// order: values orphaned by the decode, the outcome the host never took, and
/// last the pin. Order matters because they are all derived from the same
/// Layer state, and holding the pin until the end is what enforces it — the
/// state cannot be released while a reference to it is alive, so this does not
/// depend on which retirement happens to run first. It also means they strand
/// together: a spawn failure strands the whole set, never some of it.
///
/// # Safety
///
/// `user_data` must be the pointer `begin_call` minted for **this** call, with
/// the same `T`. The ABI fires `on_complete` exactly once, so this runs exactly
/// once per call.
unsafe fn complete_call<T: Send + 'static>(
    user_data: *mut c_void,
    decode: impl FnOnce() -> Result<T>,
) {
    // SAFETY: the caller guarantees this is `begin_call`'s `Box::into_raw`.
    let call: Box<SlotCall<T>> = unsafe { Box::from_raw(user_data as *mut SlotCall<T>) };
    let SlotCall { tx, pin } = *call;

    let (res, orphans) = collect_orphans(decode);
    // `Err` hands the outcome back: the host abandoned this call before the
    // producer answered, so nothing is waiting for it and this frame owns it.
    // It can carry producer-owned handles whose release runs producer code — a
    // `watch_directory` change stream, an auth event stream, a read body, the
    // `list_*` update streams.
    let unread = tx.send(res).err();

    if orphans.is_empty() && unread.is_none() {
        // The host took the outcome and the decode kept everything it adopted,
        // so no producer teardown is owed by this frame beyond the pin itself.
        //
        // The successful send says only that the receiver was alive *when it
        // ran*. The host can drop the awaiting future — and with it the last
        // other reference to the Layer — before the line below executes, in
        // which case this pin IS the last reference and `CallPin::drop` retires
        // the Layer's own release onto the retirement thread from here. That is
        // sound, and is why a producer release can be observed arbitrarily
        // later than the call that triggered it; what makes it sound is
        // `Arc::into_inner`, the atomic last-reference decision, not any
        // inference from send time about the next instruction.
        drop(pin);
        return;
    }

    retire_off_thread(move || {
        for orphan in orphans {
            orphan();
        }
        drop(unread);
        pin.release_in_place();
    });
}

/// A host-side `Layer` over a foreign `ffi::LayerHandle` — the state/vtable a
/// producer minted, driven slot-by-slot across the ABI. The state itself lives
/// in a reference-counted `ForeignLayerState` shared with every in-flight
/// call, so dropping this Layer releases the producer's state only once those
/// calls have completed.
pub struct ForeignVtableLayer {
    pinned: Arc<ForeignLayerState>,
    /// Cached config name (the trait's `name` returns `&str`).
    name: String,
    /// Fallback kind for a `descriptor()` decode failure (see [`KindsFallback`]).
    kinds_fallback: Option<KindsFallback>,
}

impl ForeignVtableLayer {
    /// Wrap a foreign `LayerHandle`, validating the ABI handshake and caching
    /// the layer name via the `name` slot (this calls into the producer at
    /// import time). `keepalive` pins the producer; pass `None` for a bare
    /// import. A `descriptor()` decode failure synthesizes a minimal
    /// descriptor — use [`from_handle_with_fallback`](Self::from_handle_with_fallback)
    /// to supply a producer-known fallback kind instead.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the handle has a null `state` or
    ///   `vtable` pointer.
    /// - [`ErrorCode::IncompatibleType`] — the `vtable` is undersized or
    ///   `abi_version` does not match the supported Layer ABI version.
    /// - Any error the `name` slot returns when decoded.
    pub fn from_handle(
        handle: ffi::LayerHandle,
        keepalive: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Result<Arc<Self>> {
        Self::from_handle_with_fallback(handle, keepalive, None)
    }

    /// [`from_handle`](Self::from_handle) plus a producer-supplied
    /// [`KindsFallback`] for the `descriptor()` decode-failure path.
    ///
    /// ABI handshake and failure disposal:
    /// - null `state`/`vtable` → `InvalidArgument`; the handle carries no
    ///   trustworthy drop slot, so it is returned undisposed.
    /// - `vtable.struct_size` below `LayerVTableV1` → `IncompatibleType`; the
    ///   header is too small to trust the drop slot, so it is returned
    ///   undisposed.
    /// - `vtable.abi_version` not the supported Layer ABI → `IncompatibleType`;
    ///   the stable header guarantees a valid drop slot here, so the handle is
    ///   consumed via it. Exact match (no band): this host validates exactly
    ///   the V2 Layer ABI — a mismatched ABI read with the current layout would
    ///   be unsound. Future hosts widen this to the set of ABIs they can
    ///   validate (mirrors `loaded_v2::load_v2_plugin`).
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the handle has a null `state` or
    ///   `vtable` pointer.
    /// - [`ErrorCode::IncompatibleType`] — the `vtable` is undersized or
    ///   `abi_version` does not match the supported Layer ABI version.
    /// - Any error the `name` slot returns when decoded.
    pub fn from_handle_with_fallback(
        handle: ffi::LayerHandle,
        keepalive: Option<Arc<dyn Any + Send + Sync>>,
        kinds_fallback: Option<KindsFallback>,
    ) -> Result<Arc<Self>> {
        if handle.state.is_null() || handle.vtable.is_null() {
            // `LayerHandle::drop` is already a no-op on a null pointer; forget
            // it so the undisposed contract is explicit at every arm.
            std::mem::forget(handle);
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "foreign LayerHandle has a null state or vtable",
            ));
        }
        if unsafe { (*handle.vtable).struct_size } < std::mem::size_of::<ffi::LayerVTableV1>() {
            // Undersized header: do not trust (hence do not invoke) the drop
            // slot; leave the handle undisposed.
            std::mem::forget(handle);
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                "foreign LayerVTableV1 struct_size is too small",
            ));
        }
        if unsafe { (*handle.vtable).abi_version } != ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION {
            // The stable header holds, so the drop slot is trustworthy: let
            // `handle` fall out of scope and dispose itself via that slot.
            return Err(Error::new(
                ErrorCode::IncompatibleType,
                "foreign LayerVTableV1 abi_version is not the supported Layer ABI",
            ));
        }
        let state = handle.state;
        let vtable = handle.vtable;
        std::mem::forget(handle); // ownership moves into ForeignVtableLayer

        // Past the `forget`, `state`/`vtable` are the sole owners of the foreign
        // Layer — the forgotten handle does not dispose it on drop. Every early return
        // between here and the successful `Arc::new` below must therefore
        // dispose the pair through its (now handshake-verified) drop slot, or
        // the whole foreign Layer/Stack leaks. The `name` decode is the only
        // such fallible step today.
        let name = {
            let mut out = MaybeUninit::<ffi::Str>::uninit();
            // SAFETY: `name` writes an owned Str into `out`; the decode consumes
            // it.
            let decoded = unsafe {
                ((*vtable).name)(state, out.as_mut_ptr());
                marshal::primitive::str_from_ffi(out.assume_init())
            };
            match decoded {
                Ok(name) => name,
                Err(error) => {
                    // A producer whose `name` slot writes a malformed/non-UTF-8
                    // Str lands here; dispose the forgotten handle via its drop
                    // slot before surfacing the error.
                    // SAFETY: `state`/`vtable` are the forgotten handle's live
                    // pair and the header handshake proved the drop slot
                    // trustworthy, so reconstituting the handle fires it once.
                    drop(ffi::LayerHandle { state, vtable });
                    return Err(error);
                }
            }
        };
        Ok(Arc::new(Self {
            pinned: Arc::new(ForeignLayerState {
                keepalive,
                state,
                vtable,
            }),
            name,
            kinds_fallback,
        }))
    }

    fn vt(&self) -> &ffi::LayerVTableV1 {
        // SAFETY: validated non-null in `from_handle_with_fallback`; valid while
        // the producer (pinned by `keepalive`, or the ABI contract) lives.
        unsafe { &*self.pinned.vtable }
    }

    /// The producer's opaque state pointer, the first argument of every slot.
    fn state(&self) -> *mut c_void {
        self.pinned.state
    }

    /// Open an async slot call: mint the completion channel and the `user_data`
    /// the producer hands back to `on_complete`. The `user_data` carries this
    /// Layer's state pin, so the producer's outstanding call keeps the state
    /// alive even after the host drops the Layer.
    fn begin_call<'a, T: Send + 'static>(
        &self,
        cancel: Option<&'a ffi::CancelTokenHandle>,
    ) -> (*mut c_void, SlotHandle<'a, T>) {
        let (tx, rx) = oneshot::channel::<Result<T>>();
        let user_data = Box::into_raw(Box::new(SlotCall {
            tx,
            pin: CallPin(Some(Arc::clone(&self.pinned))),
        })) as *mut c_void;
        (
            user_data,
            SlotHandle {
                rx,
                abandon_cancel: cancel,
            },
        )
    }

    /// Minimal descriptor used when the live `descriptor` slot returns an
    /// undecodable value and no [`KindsFallback`] is available (a bare import).
    /// Non-panicking degraded stand-in built from the cached name.
    fn synthetic_descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: self.name.clone(),
            layer_type: LayerType::Backend,
            display_name: self.name.clone(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            // The plugin's own descriptor could not be decoded, so it declared
            // nothing. A host that read `true` here would compose an attribution
            // layer over a backend that never said it could keep the reserved
            // key, which is the one answer this field exists to stop being
            // guessed.
            supports_user_metadata: false,
        }
    }
}

/// Generate an async `Layer` slot that builds the FFI request, drives the
/// vtable slot, and decodes the heap-boxed result.
macro_rules! v2_op {
    ($method:ident, $ReqRust:ty, $ResRust:ty, $build:path, $ReqFfi:ident, $slot:ident, $ResFfi:ident, $decode:path) => {
        async fn $method(
            &self,
            request: Request<$ReqRust>,
            cancel: Option<CancellationToken>,
        ) -> Result<$ResRust> {
            let req_ffi: ffi::$ReqFfi = $build(request);
            let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
            let (user_data, call) = self.begin_call::<$ResRust>(cancel_handle.as_ref());

            extern "C" fn on_done(
                status: i32,
                result: *mut c_void,
                error: *mut ffi::Error,
                user_data: *mut c_void,
            ) {
                let decode = || {
                    decode_async_result(status, result as *mut ffi::$ResFfi, error, |r| unsafe {
                        $decode(ffi::abi_alloc::abi_unbox(r))
                    })
                };
                // SAFETY: `user_data` is this call's `begin_call` allocation,
                // carrying a `Result<$ResRust>` sender; `on_complete` fires once.
                unsafe { complete_call::<$ResRust>(user_data, decode) };
            }

            let vt = self.vt();
            let extensions = req_ffi.extensions;
            unsafe {
                (vt.$slot)(
                    self.state(),
                    &req_ffi,
                    cancel_ptr(&cancel_handle),
                    on_done,
                    user_data,
                );
            }
            std::mem::forget(req_ffi);
            // The producer copied the borrowed `extensions` during the
            // slot's synchronous prologue (it adopts the rest of the
            // forgotten request, never this pointee); reclaim the
            // host-owned encoding. NULL-safe.
            unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
            let res = call.complete().await;
            drop(cancel_handle);
            res
        }
    };
}

/// Like [`v2_op`] for unit-result slots (NULL result on success).
macro_rules! v2_unit_op {
    ($method:ident, $ReqRust:ty, $build:path, $ReqFfi:ident, $slot:ident) => {
        async fn $method(
            &self,
            request: Request<$ReqRust>,
            cancel: Option<CancellationToken>,
        ) -> Result<()> {
            let req_ffi: ffi::$ReqFfi = $build(request);
            let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
            let (user_data, call) = self.begin_call::<()>(cancel_handle.as_ref());

            extern "C" fn on_done(
                _status: i32,
                _result: *mut c_void,
                error: *mut ffi::Error,
                user_data: *mut c_void,
            ) {
                let decode = || decode_async_unit_result(_status, error);
                // SAFETY: `user_data` is this call's `begin_call` allocation,
                // carrying a `Result<()>` sender; `on_complete` fires once.
                unsafe { complete_call::<()>(user_data, decode) };
            }

            let vt = self.vt();
            let extensions = req_ffi.extensions;
            unsafe {
                (vt.$slot)(
                    self.state(),
                    &req_ffi,
                    cancel_ptr(&cancel_handle),
                    on_done,
                    user_data,
                );
            }
            std::mem::forget(req_ffi);
            // Same borrowed-extensions reclaim as `v2_op!`. NULL-safe.
            unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
            let res = call.complete().await;
            drop(cancel_handle);
            res
        }
    };
}

// Inherent async helpers generated by the macros above. They live in a
// plain `impl` (not the `#[async_trait]` one) because a function-like
// macro that emits `async fn` inside an `#[async_trait]` impl is not seen
// by the attribute expansion; the trait methods below forward to these.
impl ForeignVtableLayer {
    v2_op!(
        stat_op,
        StatRequest,
        ObjectInfo,
        build_stat,
        StatRequest,
        stat,
        ObjectInfo,
        marshal::metadata::object_info_from_ffi
    );
    v2_op!(
        read_op,
        ReadRequest,
        ReadResult,
        build_read,
        ReadRequest,
        read,
        ReadResult,
        marshal::payload::read_result_from_ffi
    );
    v2_op!(
        write_op,
        WriteRequest,
        WriteResult,
        build_write,
        WriteRequest,
        write,
        WriteResult,
        marshal::payload::write_result_from_ffi
    );
    v2_op!(
        write_stream_op,
        WriteRequest,
        WriteResult,
        build_write,
        WriteRequest,
        write_stream,
        WriteResult,
        marshal::payload::write_result_from_ffi
    );
    v2_op!(
        write_redirect_op,
        WriteRequest,
        WriteRedirectBatch,
        build_write,
        WriteRequest,
        write_redirect,
        WriteRedirectBatch,
        marshal::redirect::write_redirect_batch_from_ffi
    );
    v2_op!(
        continue_write_op,
        ContinueWriteRequest,
        WriteStep,
        build_continue_write,
        ContinueWriteRequest,
        continue_write,
        WriteStep,
        marshal::payload::write_step_from_ffi
    );
    v2_unit_op!(
        delete_op,
        DeleteRequest,
        build_delete,
        DeleteRequest,
        delete
    );
    v2_op!(
        copy_op,
        CopyRequest,
        WriteStep,
        build_copy,
        CopyRequest,
        copy,
        WriteStep,
        marshal::payload::write_step_from_ffi
    );
    v2_unit_op!(
        rename_op,
        RenameRequest,
        build_rename,
        RenameRequest,
        rename
    );
    v2_op!(
        update_metadata_op,
        UpdateMetadataRequest,
        BackendItemInfo,
        build_update_metadata,
        UpdateMetadataRequest,
        update_metadata,
        BackendItemInfo,
        marshal::payload::backend_item_info_from_ffi
    );
    v2_op!(
        check_access_op,
        CheckAccessRequest,
        AccessDecision,
        build_check_access,
        CheckAccessRequest,
        check_access,
        AccessDecision,
        marshal::payload::access_decision_from_ffi
    );
    v2_op!(
        materialize_op,
        ReadRequest,
        LocalDelegate,
        build_read,
        ReadRequest,
        materialize,
        LocalDelegate,
        marshal::payload::local_delegate_from_ffi
    );
    v2_op!(
        list_op,
        ListRequest,
        ListPage,
        build_list,
        ListRequest,
        list,
        ListPage,
        list_page_from_ffi
    );
    v2_op!(
        list_versions_op,
        ListVersionsRequest,
        VersionPage,
        build_list_versions,
        ListVersionsRequest,
        list_versions,
        VersionPage,
        version_page_from_ffi
    );
    v2_op!(
        get_latest_version_op,
        ReadRequest,
        ObjectInfo,
        build_read,
        ReadRequest,
        get_latest_version,
        ObjectInfo,
        marshal::metadata::object_info_from_ffi
    );
    v2_op!(
        create_directory_op,
        CreateDirectoryRequest,
        BackendItemInfo,
        build_create_directory,
        CreateDirectoryRequest,
        create_directory,
        BackendItemInfo,
        marshal::payload::backend_item_info_from_ffi
    );
    v2_unit_op!(
        delete_directory_op,
        DeleteDirectoryRequest,
        build_delete_directory,
        DeleteDirectoryRequest,
        delete_directory
    );
    v2_op!(
        probe_op,
        LayerConnectionRequest,
        Connection,
        build_layer_connection,
        LayerConnectionRequest,
        probe,
        Connection,
        marshal::auth::connection_from_ffi
    );
    v2_op!(
        add_connection_op,
        LayerConnectionRequest,
        Connection,
        build_layer_connection,
        LayerConnectionRequest,
        add_connection,
        Connection,
        marshal::auth::connection_from_ffi
    );
    v2_unit_op!(
        remove_connection_op,
        ConnectionKey,
        build_remove_connection,
        RemoveConnectionRequest,
        remove_connection
    );
    v2_op!(
        update_connection_credentials_op,
        UpdateConnectionCredentialsRequest,
        Connection,
        build_update_credentials,
        UpdateConnectionCredentialsRequest,
        update_connection_credentials,
        Connection,
        marshal::auth::connection_from_ffi
    );
    v2_op!(
        update_connection_attributes_op,
        UpdateConnectionAttributesRequest,
        Connection,
        build_update_attributes,
        UpdateConnectionAttributesRequest,
        update_connection_attributes,
        Connection,
        marshal::auth::connection_from_ffi
    );
}

#[async_trait::async_trait]
impl Layer for ForeignVtableLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        let mut out = MaybeUninit::<ffi::LayerKindDescriptor>::uninit();
        unsafe {
            (self.vt().descriptor)(self.state(), out.as_mut_ptr());
            layer_kind_descriptor_from_ffi(out.assume_init()).unwrap_or_else(|_| {
                // The producer's `descriptor` slot returned a value we cannot
                // decode. Prefer the producer-supplied fallback (a plugin load
                // hands its advertised first kind — preserving the historical
                // behavior); otherwise synthesize a minimal descriptor rather
                // than panicking (a bare imported handle has no manifest).
                self.kinds_fallback
                    .as_ref()
                    .and_then(|hook| hook())
                    .unwrap_or_else(|| self.synthetic_descriptor())
            })
        }
    }

    fn owned_targets(&self) -> Vec<String> {
        let mut out = MaybeUninit::<ffi::List<ffi::Str>>::uninit();
        unsafe {
            (self.vt().owned_targets)(self.state(), out.as_mut_ptr());
            marshal::primitive::list_from_ffi(out.assume_init(), |s| {
                marshal::primitive::str_from_ffi(s)
            })
            .unwrap_or_default()
        }
    }

    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let req_ffi = build_root_info_for(url, cx);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
        let (user_data, call) = self.begin_call::<RootInfo>(cancel_handle.as_ref());

        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(status, result as *mut ffi::RootInfo, error, |r| unsafe {
                    root_info_from_ffi(ffi::abi_alloc::abi_unbox(r))
                })
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation,
            // carrying a `Result<RootInfo>` sender; `on_complete` fires once.
            unsafe { complete_call::<RootInfo>(user_data, decode) };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.root_info_for)(
                self.state(),
                &req_ffi,
                cancel_ptr(&cancel_handle),
                on_done,
                user_data,
            );
        }
        std::mem::forget(req_ffi);
        // Same borrowed-extensions reclaim as `v2_op!`. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        let res = call.complete().await;
        drop(cancel_handle);
        let mut info = res?;
        // A plugin that reports a connection but not `owning_target` (e.g. one
        // built before the field) is filled host-side by the SAME
        // leaf-ownership rule as `Layer::owning_target_for`'s default —
        // `leaf_owning_target` (sole `owned_targets` entry, else name) — so a
        // single-owned-target composite plugin resolves to its internal backend
        // name, not this loaded layer's outer name, and the two copies of the
        // rule cannot drift. A plugin that reports its own `owning_target` is
        // respected.
        if info.owning_target.is_none() && info.connection_id.is_some() {
            info.owning_target = Some(ovstorage_layer::leaf_owning_target(
                &self.owned_targets(),
                self.name(),
            ));
        }
        Ok(info)
    }

    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        let extensions = extensions_to_ffi_ptr(cx);
        let mut out = MaybeUninit::<ffi::List<ffi::LayerKindDescriptor>>::uninit();
        let err = unsafe { (self.vt().list_kinds)(self.state(), extensions, out.as_mut_ptr()) };
        // `list_kinds` is synchronous and its thunk has copied the borrowed
        // request context before returning. Reclaim the host-owned encoding on
        // both the success and error paths. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        if err.is_null() {
            unsafe {
                marshal::primitive::list_from_ffi(out.assume_init(), |k| {
                    layer_kind_descriptor_from_ffi(k)
                })
            }
        } else {
            Err(unsafe { marshal::error::from_ffi(ffi::abi_alloc::abi_unbox(err)) })
        }
    }

    async fn list_address_roots(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        let req_ffi = build_list_address_roots(cx);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
        let (user_data, call) = self
            .begin_call::<(RootInfoSnapshot, Option<RootInfoUpdateStream>)>(cancel_handle.as_ref());

        // The producer hands back a heap `ListAddressRootsResult` pairing the
        // snapshot with a nullable change-stream pointer; the decoder splits it,
        // bridging the stream so roots the producer discovers after the
        // snapshot propagate live to the Stack's root watchers.
        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(
                    status,
                    result as *mut ffi::ListAddressRootsResult,
                    error,
                    |r| unsafe { decode_list_address_roots_result(r) },
                )
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation, carrying
            // a sender for this slot's decoded pair; `on_complete` fires once.
            unsafe {
                complete_call::<(RootInfoSnapshot, Option<RootInfoUpdateStream>)>(user_data, decode)
            };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.list_address_roots)(
                self.state(),
                &req_ffi,
                cancel_ptr(&cancel_handle),
                on_done,
                user_data,
            );
        }
        // Unlike the data-op requests, `ListAddressRootsRequest` carries no
        // owned fields the producer adopts (only the borrowed `extensions`
        // pointer), so there is nothing to `mem::forget`; just reclaim the
        // host-owned extensions encoding. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        let res = call.complete().await?;
        // Retain `cancel_handle` for the UPDATE STREAM's lifetime rather than
        // dropping it with the snapshot: `CancelTokenHandle::drop` aborts the
        // host->FFI cancel bridge, and that bridge task is the only thing that
        // ever signals the plugin-local token the stream's `next_fn` selects
        // on. Dropping it here would make a later `cancel.cancel()` inert while
        // the stream is still live. Same contract as `watch_directory`; when
        // there is no update stream the handle drops here as before.
        let (snapshot, updates) = res;
        let updates = updates.map(|stream| {
            Box::pin(marshal::change::CancelGuardedStream::new(
                stream,
                cancel_handle,
            )) as RootInfoUpdateStream
        });
        Ok((snapshot, updates))
    }

    async fn list_connections(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        let req_ffi = build_list_connections(cx);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
        let (user_data, call) = self
            .begin_call::<(ConnectionSnapshot, Option<ConnectionUpdateStream>)>(
                cancel_handle.as_ref(),
            );

        // Split the heap `ListConnectionsResult` and bridge the connection
        // update stream the same way as `list_address_roots`.
        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(
                    status,
                    result as *mut ffi::ListConnectionsResult,
                    error,
                    |r| unsafe { decode_list_connections_result(r) },
                )
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation, carrying
            // a sender for this slot's decoded pair; `on_complete` fires once.
            unsafe {
                complete_call::<(ConnectionSnapshot, Option<ConnectionUpdateStream>)>(
                    user_data, decode,
                )
            };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.list_connections)(
                self.state(),
                &req_ffi,
                cancel_ptr(&cancel_handle),
                on_done,
                user_data,
            );
        }
        // Unlike the data-op requests, `ListConnectionsRequest` carries no
        // owned fields the producer adopts (only the borrowed `extensions`
        // pointer), so there is nothing to `mem::forget`; just reclaim the
        // host-owned extensions encoding. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        let res = call.complete().await?;
        // Retain `cancel_handle` for the UPDATE STREAM's lifetime rather than
        // dropping it with the snapshot: `CancelTokenHandle::drop` aborts the
        // host->FFI cancel bridge, and that bridge task is the only thing that
        // ever signals the plugin-local token the stream's `next_fn` selects
        // on. Dropping it here would make a later `cancel.cancel()` inert while
        // the stream is still live. Same contract as `watch_directory`; when
        // there is no update stream the handle drops here as before.
        let (snapshot, updates) = res;
        let updates = updates.map(|stream| {
            Box::pin(marshal::change::CancelGuardedStream::new(
                stream,
                cancel_handle,
            )) as ConnectionUpdateStream
        });
        Ok((snapshot, updates))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stat_op(request, cancel).await
    }
    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.read_op(request, cancel).await
    }
    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_op(request, cancel).await
    }
    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_stream_op(request, cancel).await
    }
    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        self.write_redirect_op(request, cancel).await
    }
    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.continue_write_op(request, cancel).await
    }
    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.delete_op(request, cancel).await
    }
    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.copy_op(request, cancel).await
    }
    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.rename_op(request, cancel).await
    }
    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.update_metadata_op(request, cancel).await
    }
    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        self.check_access_op(request, cancel).await
    }
    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.materialize_op(request, cancel).await
    }
    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.list_op(request, cancel).await
    }
    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        self.list_versions_op(request, cancel).await
    }
    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.get_latest_version_op(request, cancel).await
    }
    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.create_directory_op(request, cancel).await
    }
    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.delete_directory_op(request, cancel).await
    }
    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.probe_op(request, cancel).await
    }
    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.add_connection_op(request, cancel).await
    }
    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.update_connection_credentials_op(request, cancel).await
    }
    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.update_connection_attributes_op(request, cancel).await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let req_ffi = build_watch_directory(request);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
        let (user_data, call) = self.begin_call::<ChangeStream>(cancel_handle.as_ref());

        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(
                    status,
                    result as *mut ffi::BackendChangeStream,
                    error,
                    |r| {
                        Ok(change_stream_from_ffi(unsafe {
                            ffi::abi_alloc::abi_unbox(r)
                        }))
                    },
                )
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation,
            // carrying a `Result<ChangeStream>` sender; `on_complete` fires once.
            unsafe { complete_call::<ChangeStream>(user_data, decode) };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.watch_directory)(
                self.state(),
                &req_ffi,
                cancel_ptr(&cancel_handle),
                on_done,
                user_data,
            );
        }
        std::mem::forget(req_ffi);
        // Same borrowed-extensions reclaim as `v2_op!`. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        let stream = call.complete().await?;
        // Retain `cancel_handle` for the stream's lifetime instead of dropping
        // it here: a host cancel must keep reaching the plugin token the
        // stream polls. Dropping the returned stream drops the handle (aborts
        // the bridge, tears down the transport). On the error arm the handle
        // drops with the early return above.
        Ok(Box::new(marshal::change::CancelGuardedChangeStream::new(
            stream,
            cancel_handle,
        )) as ChangeStream)
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.remove_connection_op(key, cancel).await
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let req_ffi = build_authenticate(request);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);
        let (user_data, call) = self.begin_call::<AuthEventStream>(cancel_handle.as_ref());

        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(status, result as *mut ffi::AuthEventStream, error, |r| {
                    let stream = unsafe {
                        marshal::auth::AuthEventStream::from_ffi(ffi::abi_alloc::abi_unbox(r))
                    };
                    Ok(Box::new(stream) as AuthEventStream)
                })
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation, carrying
            // a `Result<AuthEventStream>` sender; `on_complete` fires once.
            unsafe { complete_call::<AuthEventStream>(user_data, decode) };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.authenticate_connection)(
                self.state(),
                &req_ffi,
                cancel_ptr(&cancel_handle),
                on_done,
                user_data,
            );
        }
        std::mem::forget(req_ffi);
        // Same borrowed-extensions reclaim as `v2_op!`. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        let stream = call.complete().await?;
        // `cancel_handle` lives as long as the returned stream, so a host
        // cancel keeps reaching the plugin token that stream polls — the wait
        // an interactive auth flow parks on (browser round-trip, device-code
        // poll) is inside the stream, not the call. Dropping the stream drops
        // the handle (aborts the bridge, tears down the subscription). On the
        // error arm the early return above drops the handle.
        Ok(Box::new(marshal::change::CancelGuardedChangeStream::new(
            stream,
            cancel_handle,
        )) as AuthEventStream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A published root the URL parser rewrites is refused, not installed.
    ///
    /// `root_from_ffi_str` runs two checks because two steps can move a root.
    /// This row is refused by the first: `Url::parse` resolves the dot segment
    /// itself, so the root arrives as `https://origin/private/` and passes
    /// `canonicalize_preserves_node` as a fixed point. Installing it would give
    /// the connection a route over a subtree the plugin never published.
    ///
    /// The load-bearing line is the `parsing_preserves_node(raw)` call;
    /// deleting it turns this test red and leaves the sibling refusal's own
    /// test (below) green, which is what makes the two independent.
    #[test]
    fn a_published_root_the_parser_rewrites_is_refused() {
        let error = root_from_ffi_str("https://origin/public/../private/")
            .expect_err("a root the parser resolves elsewhere is refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        // And this arm's own rendering is load-bearing: the sibling refusal's
        // credential test cannot reach it, because its input is a fixed point
        // of the parser. Measured with `redact_url(&url)` here replaced by
        // `raw` — only this assertion turns red. `api_key` is not a name
        // `Error`'s redactor knows, so nothing downstream covers for it.
        let leaky = root_from_ffi_str("https://origin/public/../private/?api_key=hunter2")
            .expect_err("still refused with a query attached");
        assert!(
            !leaky.message().contains("hunter2"),
            "the refusal leaked the root's credential: {}",
            leaky.message()
        );
        // The honest spelling of the same root must still load, or the refusal
        // would have cost a working configuration.
        let ok = root_from_ffi_str("https://origin/private/")
            .expect("a root that spells the node it names must load");
        assert_eq!(ok.as_str(), "https://origin/private/");
    }

    /// The retargeting refusal must not echo the credential a published root
    /// carries.
    ///
    /// `Error` redacts by re-serializing a *recognizable* URL token, so it can
    /// only clean a spelling the tokenizer finds. A password containing a space
    /// breaks the token, so interpolating the operator's raw string would put
    /// the plaintext into the connect-time error and into any startup log that
    /// records it. Rendering the *parsed* URL through `redact_url` keeps the
    /// whole diagnostic — the reader still sees which spelling was rejected and
    /// which node it named — with the userinfo removed at the source rather
    /// than left to a scan that cannot see it.
    ///
    /// The load-bearing line is the `redact_url(&url)` in the refusal message:
    /// substituting `{raw}` there turns this test red. The doubled separator is
    /// what routes the input to this branch at all.
    #[test]
    fn the_retargeting_refusal_does_not_echo_a_published_roots_credential() {
        let error = root_from_ffi_str("https://reader:hunt er2@origin/a//b?api_key=s3cret")
            .expect_err("a root whose path names another node is refused");

        assert!(
            !error.message().contains("s3cret"),
            "a query credential must not survive either, and `redact_url` \
             scrubs only the names it knows: {}",
            error.message()
        );

        assert!(
            !error.message().contains("hunt er2"),
            "the password must not survive into the diagnostic: {}",
            error.message()
        );
        assert!(
            !error.message().contains("reader"),
            "nor the username: {}",
            error.message()
        );
        // The refusal still has to be actionable, or dropping the raw string
        // would have traded a leak for an unusable message.
        assert!(
            error.message().contains("origin") && error.message().contains("/a/b"),
            "the canonical node it resolves to must still be named: {}",
            error.message()
        );
    }

    /// The orphan hand-off `complete_call` drains: nothing is collected unless
    /// something is actually handed over, one hand-off collects exactly one, and
    /// outside a scope the value is released in place.
    ///
    /// The first case is what makes the `if let Some(iter)` guard at the
    /// `list_*` decode-failure arms load-bearing rather than cosmetic: an
    /// orphan-free decode must leave `complete_call` with an empty set, so it
    /// takes the fast path and mints no retirement. A retirement with nothing to
    /// release still strands the call's pin — and with it the Layer state — for
    /// the process lifetime if its thread cannot be spawned.
    #[test]
    fn orphans_are_collected_only_when_something_is_handed_over() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static RELEASED: AtomicUsize = AtomicUsize::new(0);

        struct Producer;
        impl Drop for Producer {
            fn drop(&mut self) {
                RELEASED.fetch_add(1, Ordering::SeqCst);
            }
        }

        // A decode that orphans nothing collects nothing, so the caller has no
        // retirement to mint.
        let (value, orphans) = collect_orphans(|| 7);
        assert_eq!(value, 7);
        assert!(
            orphans.is_empty(),
            "a decode that hands nothing over must collect nothing",
        );

        // A decode that orphans one value collects exactly one, and the value is
        // untouched until that orphan is run.
        let ((), orphans) = collect_orphans(|| orphan_producer_value(Producer));
        assert_eq!(orphans.len(), 1);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            0,
            "a collected orphan must not be released inside the scope",
        );
        for orphan in orphans {
            orphan();
        }
        assert_eq!(RELEASED.load(Ordering::SeqCst), 1);

        // Outside any scope there is no producer frame to protect, so the value
        // is released in place.
        orphan_producer_value(Producer);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            2,
            "with no scope active the value is released where it is handed over",
        );
    }

    /// The strand semantics `retire_off_thread` depends on, tested directly
    /// rather than through a real spawn failure.
    ///
    /// `Builder::spawn` drops its closure when the spawn fails, so the carrier
    /// must make that drop a no-op — otherwise the teardown runs on the
    /// producer's own completion frame, which is the one thread the hop exists
    /// to keep it off. The end-to-end leg for this
    /// (`a_retirement_that_cannot_spawn_strands_rather_than_releasing_in_place`)
    /// depends on `RLIMIT_NPROC` actually blocking thread creation, which not
    /// every environment honours; this one depends on nothing.
    #[test]
    fn dropping_a_retirement_strands_its_work_instead_of_running_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static RAN: AtomicUsize = AtomicUsize::new(0);

        struct Work;
        impl Drop for Work {
            fn drop(&mut self) {
                RAN.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Goes out of scope without running: the payload must not be touched.
        {
            let _stranded = Retirement::new({
                let work = Work;
                move || drop(work)
            });
        }
        assert_eq!(
            RAN.load(Ordering::SeqCst),
            0,
            "a retirement that never starts must strand its work, not run it",
        );

        // Run: the payload is released exactly once, proving the assertion
        // above is not vacuous.
        let performed = Retirement::new({
            let work = Work;
            move || drop(work)
        });
        performed.run();
        assert_eq!(
            RAN.load(Ordering::SeqCst),
            1,
            "a retirement that runs must release its work exactly once",
        );
    }

    /// A backend change stream that reports end-of-stream immediately and, on
    /// teardown, increments the `AtomicUsize` its `state` points at. `next_fn`
    /// never yields, so `out_item` / `out_error` stay untouched.
    unsafe extern "C" fn counting_change_next(
        _state: *mut c_void,
        _out_item: *mut ffi::BackendChangeEvent,
        _out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        ffi::StreamStep::Ended
    }

    unsafe extern "C" fn counting_change_drop(state: *mut c_void) {
        let counter = unsafe { &*(state as *const std::sync::atomic::AtomicUsize) };
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// The double-free fix at [`change_stream_from_ffi`]: the adapter holds the
    /// `ffi::BackendChangeStream` by value and relies on that field's own `Drop`
    /// to run the vtable `drop_fn` exactly once. Dropping the host adapter must
    /// drive `drop_fn` a single time — not zero (a leak of the plugin state) and
    /// not twice (a double-free). The `AtomicUsize` lives on the stack and
    /// outlives the adapter, so `drop_fn` only ever borrows it; the count is
    /// read after the adapter is dropped.
    #[test]
    fn change_stream_from_ffi_drops_plugin_state_exactly_once() {
        let drops = std::sync::atomic::AtomicUsize::new(0);
        let stream = ffi::BackendChangeStream {
            state: &drops as *const _ as *mut c_void,
            next_fn: counting_change_next,
            drop_fn: counting_change_drop,
        };
        let adapter = change_stream_from_ffi(stream);
        drop(adapter);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "change_stream_from_ffi adapter must drive drop_fn exactly once"
        );
    }

    /// Once the ABI handshake passes, `from_handle` runs
    /// `mem::forget(handle)` and then decodes the producer's `name` slot. A
    /// producer whose `name` slot writes a malformed (non-UTF-8) `Str` fails
    /// that decode *after* the handle is forgotten — so the fix must dispose the
    /// foreign Layer via its (handshake-verified) drop slot before returning the
    /// error. A `DropFlag`-style counter proves the drop slot ran exactly once:
    /// not zero (the leak this fixes) and not twice.
    #[cfg(feature = "test-codec")]
    #[test]
    fn from_handle_disposes_via_drop_slot_when_name_decode_fails() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropCountingLayer {
            drops: Arc<AtomicUsize>,
        }

        impl Drop for DropCountingLayer {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[async_trait::async_trait]
        impl Layer for DropCountingLayer {
            fn name(&self) -> &str {
                "drop-counting"
            }

            fn descriptor(&self) -> LayerKindDescriptor {
                LayerKindDescriptor {
                    kind: "drop-counting".to_string(),
                    layer_type: LayerType::Backend,
                    display_name: "name-decode-failure test layer".to_string(),
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
        }

        // A `name` slot that writes a non-UTF-8 `Str`, so the post-`forget`
        // decode errors. Minted on the ABI heap with capacity == length,
        // mirroring `str_to_ffi`: the consumer reclaims it through
        // `ffi::Str::drop` → `abi_buffer_free`, so a `Vec` here would hand a
        // global-allocator block to a `System` free.
        unsafe extern "C" fn malformed_name_slot(_state: *mut c_void, out: *mut ffi::Str) {
            let bytes = vec![0xFFu8, 0xFE, 0xFD];
            let len = bytes.len();
            let ptr = ffi::abi_alloc::abi_vec_into_raw(bytes) as *mut std::os::raw::c_char;
            unsafe { out.write(ffi::Str { ptr, len }) };
        }

        // Start from the real Layer vtable (valid header + real drop slot) and
        // override only `name`, so the handshake passes and the drop slot
        // genuinely releases the leaked `Arc<dyn Layer>`.
        let mut vtable = crate::thunks_v2::layer_vtable_template_for_test();
        vtable.name = malformed_name_slot;
        let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

        let drops = Arc::new(AtomicUsize::new(0));
        let layer: Arc<dyn Layer> = Arc::new(DropCountingLayer {
            drops: Arc::clone(&drops),
        });
        let state = crate::thunks_v2::leak_layer(layer);

        let err = ForeignVtableLayer::from_handle(ffi::LayerHandle { state, vtable }, None)
            .err()
            .expect("a malformed name Str must fail the import");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the forgotten handle must be disposed via its drop slot exactly once",
        );
    }

    /// Root-update stream that reports end-of-stream immediately and, on
    /// teardown, bumps the `AtomicUsize` its `state` points at.
    unsafe extern "C" fn counting_root_next(
        _state: *mut c_void,
        _out_item: *mut ffi::RootInfoChange,
        _out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        ffi::StreamStep::Ended
    }

    /// Connection-update stream mirror of [`counting_root_next`].
    unsafe extern "C" fn counting_conn_next(
        _state: *mut c_void,
        _out_item: *mut ffi::ConnectionChange,
        _out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        ffi::StreamStep::Ended
    }

    unsafe extern "C" fn counting_stream_drop(state: *mut c_void) {
        let counter = unsafe { &*(state as *const std::sync::atomic::AtomicUsize) };
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// The `list_address_roots` `on_complete` decoder splits the heap
    /// `ListAddressRootsResult` into its snapshot and change stream, adopting
    /// the stream and suppressing the envelope's own `Drop`. Dropping the
    /// bridged (unpolled) stream must run the producer `drop_fn` exactly once —
    /// not zero (a leak) and not twice (a double-free through the envelope's
    /// suppressed `Drop`).
    #[test]
    fn decode_list_address_roots_result_adopts_stream_and_drops_it_once() {
        let drops = std::sync::atomic::AtomicUsize::new(0);
        let stream = ffi::RootInfoChangeStream {
            state: &drops as *const _ as *mut c_void,
            next_fn: counting_root_next,
            drop_fn: counting_stream_drop,
        };
        let result = ffi::abi_alloc::abi_box(ffi::ListAddressRootsResult {
            snapshot: crate::thunks_v2::root_info_snapshot_to_ffi(RootInfoSnapshot {
                roots: Vec::new(),
                updates: true,
            }),
            updates: ffi::abi_alloc::abi_box(stream),
        });
        let (snapshot, updates) = unsafe { decode_list_address_roots_result(result) }
            .expect("decode ListAddressRootsResult");
        assert!(snapshot.roots.is_empty());
        assert!(updates.is_some());
        drop(updates);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the adopted change stream's drop_fn must run exactly once",
        );
    }

    /// A NULL `updates` pointer decodes to `None` with the snapshot intact.
    #[test]
    fn decode_list_address_roots_result_null_updates_yields_none() {
        let result = ffi::abi_alloc::abi_box(ffi::ListAddressRootsResult {
            snapshot: crate::thunks_v2::root_info_snapshot_to_ffi(RootInfoSnapshot {
                roots: Vec::new(),
                updates: false,
            }),
            updates: std::ptr::null_mut(),
        });
        let (snapshot, updates) = unsafe { decode_list_address_roots_result(result) }
            .expect("decode null-updates ListAddressRootsResult");
        assert!(snapshot.roots.is_empty());
        assert!(updates.is_none());
    }

    /// The `list_connections` decoder shares the address-roots discipline:
    /// dropping the bridged stream runs `drop_fn` exactly once.
    #[test]
    fn decode_list_connections_result_adopts_stream_and_drops_it_once() {
        let drops = std::sync::atomic::AtomicUsize::new(0);
        let stream = ffi::ConnectionChangeStream {
            state: &drops as *const _ as *mut c_void,
            next_fn: counting_conn_next,
            drop_fn: counting_stream_drop,
        };
        let result = ffi::abi_alloc::abi_box(ffi::ListConnectionsResult {
            snapshot: crate::thunks_v2::connection_snapshot_to_ffi(ConnectionSnapshot {
                connections: Vec::new(),
                updates: true,
            }),
            updates: ffi::abi_alloc::abi_box(stream),
        });
        let (snapshot, updates) = unsafe { decode_list_connections_result(result) }
            .expect("decode ListConnectionsResult");
        assert!(snapshot.connections.is_empty());
        assert!(updates.is_some());
        drop(updates);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the adopted change stream's drop_fn must run exactly once",
        );
    }
}
