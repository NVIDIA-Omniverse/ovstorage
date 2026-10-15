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
                marshal::primitive::optional_str_unset_as_none(value.broker_principal)?
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
            reason: unsafe { marshal::primitive::optional_str_unset_as_none(value.reason)? }
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
                marshal::primitive::optional_str_unset_as_none(broker_principal)?
            }
            .unwrap_or_default(),
            connection_id: unsafe { decode_connection_id(connection_id)? },
        },
        ffi::RouteSourceTag::Alias => RouteSource::Alias {
            to: {
                let raw = unsafe { marshal::primitive::optional_str_unset_as_none(alias_to)? }
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
    let decoded = unsafe { marshal::primitive::optional_connection_id_unset_as_none(value)? };
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
        display_name: unsafe { marshal::primitive::optional_str_unset_as_none(display_name)? },
        layer_kind: unsafe { marshal::primitive::str_from_ffi(layer_kind)? },
        connection_id: unsafe {
            marshal::primitive::optional_connection_id_unset_as_none(connection_id)?
        },
        // **`present` can outrun the payload, and the two shapes underneath it
        // are different statements.** `optional_from_ffi` answers `Some`
        // whenever `present` is set, and `str_from_ffi` maps both a null
        // pointer and a zero length to an empty `String` — so on their own the
        // two cannot tell a producer that never wrote this field from one that
        // wrote it as `""`.
        //
        // `present == true, ptr == NULL, len == 0` is the first: exactly the
        // shape `calloc` already gives a C plugin, so it arrives by omission
        // rather than by mistake, and it carries no attribution to preserve.
        // `present == true, ptr != NULL, len == 0` is the second: a target
        // encoded as the empty string on purpose. `optional_str_unset_as_none`
        // separates them, here and on the other root-info and operation-result
        // strings; the wholly-zeroed `Optional` needs no help, since
        // `present == 0` is already `None`. This field is where the rule is
        // argued, because it is the one where the wrong answer routes.
        //
        // **The two shapes differ in how reachable they are, and the
        // difference runs the opposite way to what "empty" suggests.**
        //
        // The UNSET shape is not reachable from this tree: every shipping
        // plugin backend leaves `RootInfo.owning_target` as `None` and lets the
        // host attribute the row, and the two producers that do stamp a name —
        // the in-process Rust file backend, which never crosses this boundary,
        // and the C file backend, which refuses an empty instance name — cannot
        // emit it. Ruling it out here is defence-in-depth for a public ABI.
        //
        // The ENCODED-EMPTY shape is reachable by construction. `str_to_ffi`
        // sends an empty string through `abi_capacity`, which mints a
        // one-element sentinel for a zero length, so any Rust plugin returning
        // `Some(String::new())` puts `ptr != NULL, len == 0` on the wire today.
        // No shipping plugin does so, but nothing stops one, and a decode that
        // discarded it would be dropping an attribution a producer really made.
        // `a_deliberately_empty_root_owning_target_survives_the_round_trip`
        // pins that end to end, encoder included.
        //
        // Discriminating rather than testing `is_empty()` matters for what the
        // code asserts. An empty layer instance name is legal at the graph
        // level: neither stack builder rejects one, nor does the TOML config
        // path, and a Router routes target `""` like any other key. The C file
        // backend's refusal above is its own per-backend guard, not a rule of
        // the graph, and no other factory carries it. So "present and empty
        // means absent" would be a false rule that merely happens to be
        // unreachable. This states something true about the encoding instead.
        //
        // `marshal::auth::connection_from_ffi` decodes the same field of
        // `Connection` through this same helper, so the two decoders of one
        // concept apply one rule from one definition.
        owning_target: unsafe { marshal::primitive::optional_str_unset_as_none(owning_target)? },
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
            marshal::primitive::optional_str_unset_as_none(value.next_page_token)?
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
            marshal::primitive::optional_str_unset_as_none(value.next_page_token)?
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

/// Blocking iterator over a plugin-emitted `ffi::ListEntryStream`.
///
/// The FFI stream is held by value, so its own `Drop` invokes `drop_fn`
/// exactly once when this iterator is exhausted or abandoned. Both FFI error
/// steps are terminal on the list surface, matching
/// [`change_stream_from_ffi`]; the distinction is reserved for update streams,
/// whose `TransientError` frames are recoverable resync signals.
struct ListEntryIter {
    stream: ffi::ListEntryStream,
    done: bool,
}

impl Iterator for ListEntryIter {
    type Item = Result<ObjectInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut item = MaybeUninit::<ffi::ObjectInfo>::uninit();
        let mut error = MaybeUninit::<ffi::Error>::uninit();
        let step = unsafe {
            (self.stream.next_fn)(self.stream.state, item.as_mut_ptr(), error.as_mut_ptr())
        };
        match step {
            ffi::StreamStep::Yielded => {
                Some(unsafe { marshal::metadata::object_info_from_ffi(item.assume_init()) })
            }
            ffi::StreamStep::Ended => {
                self.done = true;
                None
            }
            ffi::StreamStep::Failed | ffi::StreamStep::TransientError => {
                self.done = true;
                Some(Err(unsafe {
                    marshal::error::from_ffi(error.assume_init())
                }))
            }
        }
    }
}

// A single queued entry lets the FFI pull overlap with consumer work while
// bounding the bridge to one buffered ObjectInfo plus the sender's current
// item. This is deliberately smaller than the long-lived update-stream bridge:
// listings can be arbitrarily large and their backpressure is contractual.
/// Rust-only host bridge bound; not part of the generated plugin ABI.
/// cbindgen:ignore
const LIST_STREAM_BRIDGE_CAPACITY: usize = 1;

/// Host-only async receiver; the pull-iterator C ABI is represented separately.
/// cbindgen:ignore
type ListStreamReceiver = tokio_stream::wrappers::ReceiverStream<Result<ObjectInfo>>;
/// Host-only injection seam for fallible bridge-thread creation tests.
/// cbindgen:ignore
type ListStreamThreadSpawner = fn(ListEntryIter) -> Result<ListStreamReceiver>;

fn spawn_list_stream_thread(iter: ListEntryIter) -> Result<ListStreamReceiver> {
    let (tx, rx) = tokio::sync::mpsc::channel(LIST_STREAM_BRIDGE_CAPACITY);
    std::thread::Builder::new()
        .name("ovs-list-stream".into())
        .spawn(move || {
            for item in iter {
                if tx.blocking_send(item).is_err() {
                    break;
                }
            }
        })
        .map_err(|error| {
            Error::new(
                ErrorCode::ResourceExhausted,
                format!("failed to spawn list-stream bridge thread: {error}"),
            )
        })?;
    Ok(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Lazy async facade over a blocking FFI list iterator.
///
/// The first poll starts the dedicated pull thread. Dropping an unpolled
/// stream drops the FFI iterator in place; dropping a polled stream first
/// signals the producer through the retained open-time cancellation handle,
/// which wakes a cooperative `next_fn`, and then closes the bounded receiver.
/// If the host cannot create the pull thread, the first poll yields a terminal
/// `ResourceExhausted` error and releases the FFI iterator.
struct BridgeListStream {
    state: BridgeListState,
    cancel: ffi::CancelTokenHandle,
}

enum BridgeListState {
    Idle {
        iter: Option<ListEntryIter>,
        spawn: ListStreamThreadSpawner,
    },
    Draining(ListStreamReceiver),
    SpawnFailed(Option<Error>),
}

impl futures::Stream for BridgeListStream {
    type Item = Result<ObjectInfo>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let BridgeListState::Idle { iter, spawn } = &mut this.state {
            let iter = iter
                .take()
                .expect("list bridge iterator taken exactly once");
            this.state = match spawn(iter) {
                Ok(receiver) => BridgeListState::Draining(receiver),
                Err(error) => BridgeListState::SpawnFailed(Some(error)),
            };
        }
        match &mut this.state {
            BridgeListState::Draining(rx) => std::pin::Pin::new(rx).poll_next(cx),
            BridgeListState::SpawnFailed(error) => std::task::Poll::Ready(error.take().map(Err)),
            BridgeListState::Idle { .. } => {
                unreachable!("state advanced out of Idle above")
            }
        }
    }
}

impl Drop for BridgeListStream {
    fn drop(&mut self) {
        // `CancelTokenHandle::drop` only tears down the host-side bridge. Fire
        // the FFI state first so a plugin-side iterator parked in `next_fn`
        // observes early abandonment and can release its state.
        self.cancel.cancel_producer();
    }
}

fn bridge_list_stream(stream: ffi::ListEntryStream, cancel: ffi::CancelTokenHandle) -> ListStream {
    bridge_list_stream_with_spawn(stream, cancel, spawn_list_stream_thread)
}

fn bridge_list_stream_with_spawn(
    stream: ffi::ListEntryStream,
    cancel: ffi::CancelTokenHandle,
    spawn: ListStreamThreadSpawner,
) -> ListStream {
    Box::pin(BridgeListStream {
        state: BridgeListState::Idle {
            iter: Some(ListEntryIter {
                stream,
                done: false,
            }),
            spawn,
        },
        cancel,
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
    /// Attribute a row this plugin left unattributed, so a caller holding it can
    /// build the `ConnectionKey` that reaches it.
    ///
    /// THE one home for the connection rule in this file. Every path that
    /// decodes a `Connection` — the snapshot, the update stream, and the four
    /// single-connection ops — goes through here, so a consumer keyed by
    /// `(target, id)` cannot see one connection under two keys depending on
    /// which path it arrived through.
    ///
    /// **`sole_owning_target`, not `leaf_owning_target`.** The `name()` fallback
    /// is right for a `RootInfo` and wrong here. `owned_targets` reports a
    /// loaded plugin's INTERNAL names, and a Router's target table is built from
    /// exactly those, so this layer's outer name is not in it: substituting it
    /// for a composite would hand back a `Some` that answers `NotFound` at
    /// `route_target` against a graph that holds the connection. A `RootInfo`
    /// can absorb that because it carries the address it is about and a caller
    /// still has `owning_target_for`; a connection parked in `AwaitingAuth`
    /// publishes no address at all. So a composite that declines to attribute
    /// its own rows stays `None`, which says "ask the graph" instead of failing
    /// at use.
    ///
    /// A plugin that reported a target is respected, and it is not validated
    /// against `owned_targets()`: that slot may legitimately be narrower, and
    /// rewriting the row on a mismatch would make a wrong answer
    /// indistinguishable from no answer.
    fn backfill_connection_owner(sole_target: &Option<String>, connection: &mut Connection) {
        if connection.owning_target.is_none() {
            connection.owning_target = sole_target.clone();
        }
    }

    /// The same fill applied to a change frame. `Removed` carries no
    /// `Connection` and so carries no target; a consumer resolves it against the
    /// key it retained from the frame that introduced the row.
    fn backfill_change_owner(sole_target: &Option<String>, change: &mut ConnectionChange) {
        match change {
            ConnectionChange::Added(connection) | ConnectionChange::Updated(connection) => {
                Self::backfill_connection_owner(sole_target, connection);
            }
            ConnectionChange::Snapshot(connections) => {
                for connection in connections {
                    Self::backfill_connection_owner(sole_target, connection);
                }
            }
            ConnectionChange::Removed { .. } => {}
        }
    }

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
        //
        // A `Connection` takes the NARROWER rule — `sole_owning_target`, with no
        // name fallback — and `backfill_connection_owner` says why: a `RootInfo`
        // carries the address it is about, so a caller handed an unroutable name
        // still has `owning_target_for` to fall back on, and a connection parked
        // in `AwaitingAuth` publishes no address and has no such recourse.
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
        let (mut snapshot, updates) = res;
        // Resolved ONCE, and shared by the snapshot and the stream so the two
        // halves of this plugin's answer agree. `owned_targets` is fixed
        // manifest/topology metadata under the trait's synchronous no-I/O
        // contract, so hoisting it here is sound and keeps this from being one
        // FFI call per frame.
        let sole_target = ovstorage_layer::sole_owning_target(&self.owned_targets());
        for connection in &mut snapshot.connections {
            Self::backfill_connection_owner(&sole_target, connection);
        }
        let updates = updates.map(|stream| {
            let guarded = marshal::change::CancelGuardedStream::new(stream, cancel_handle);
            Box::pin(futures::StreamExt::map(guarded, move |change| {
                change.map(|mut change| {
                    Self::backfill_change_owner(&sole_target, &mut change);
                    change
                })
            })) as ConnectionUpdateStream
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
    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        if request.input.options.max_results.is_some() || request.input.options.page_token.is_some()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }

        // A foreign producer may use its language's default vtable, whose
        // list_stream slot declines with Unsupported. Keep the original
        // request so that outcome can take the same buffered compatibility
        // path as the Rust Layer default.
        let fallback_request = request.clone();
        let stream_cancel = cancel.clone();
        let req_ffi = build_list(request);
        // Always provide an open-time token, even when the caller supplied
        // none. The private token is what lets dropping a polled bridge wake a
        // plugin `next_fn` that is parked waiting for its next page.
        let cancel_handle = ffi::cancel_token_to_ffi(cancel.unwrap_or_default());
        let (user_data, call) = self.begin_call::<ffi::ListEntryStream>(Some(&cancel_handle));

        extern "C" fn on_done(
            status: i32,
            result: *mut c_void,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let decode = || {
                decode_async_result(status, result as *mut ffi::ListEntryStream, error, |r| {
                    Ok(unsafe { ffi::abi_alloc::abi_unbox(r) })
                })
            };
            // SAFETY: `user_data` is this call's `begin_call` allocation,
            // carrying a `Result<ffi::ListEntryStream>` sender; completion is
            // exactly once.
            unsafe { complete_call::<ffi::ListEntryStream>(user_data, decode) };
        }

        let vt = self.vt();
        let extensions = req_ffi.extensions;
        unsafe {
            (vt.list_stream)(
                self.state(),
                &req_ffi,
                cancel_handle.as_ffi_ptr(),
                on_done,
                user_data,
            );
        }
        std::mem::forget(req_ffi);
        // Same borrowed-extensions reclaim as `v2_op!`. NULL-safe.
        unsafe { ffi::ovstorage_plugin_extensions_free(extensions as *mut ffi::Extensions) };
        match call.complete().await {
            Ok(stream) => Ok(cancel_list_stream(
                bridge_list_stream(stream, cancel_handle),
                stream_cancel,
            )),
            Err(error) if error.code() == ErrorCode::Unsupported => {
                drop(cancel_handle);
                let page = self.list(fallback_request, stream_cancel.clone()).await?;
                if page.next_page_token.is_some() {
                    return Err(Error::new(
                        ErrorCode::Internal,
                        "list returned a continuation token the buffered list_stream adapter cannot follow; implement list_stream natively",
                    ));
                }
                let stream = Box::pin(futures::stream::iter(page.items.into_iter().map(Ok)));
                Ok(cancel_list_stream(stream, stream_cancel))
            }
            Err(error) => Err(error),
        }
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
        let mut connection = self.probe_op(request, cancel).await?;
        // Filled on the way out for the same reason the snapshot is: a row this
        // op just returned and the same row from `list_connections` must not
        // disagree about which target reaches it.
        Self::backfill_connection_owner(
            &ovstorage_layer::sole_owning_target(&self.owned_targets()),
            &mut connection,
        );
        Ok(connection)
    }
    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let mut connection = self.add_connection_op(request, cancel).await?;
        // Filled on the way out for the same reason the snapshot is: a row this
        // op just returned and the same row from `list_connections` must not
        // disagree about which target reaches it.
        Self::backfill_connection_owner(
            &ovstorage_layer::sole_owning_target(&self.owned_targets()),
            &mut connection,
        );
        Ok(connection)
    }
    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let mut connection = self
            .update_connection_credentials_op(request, cancel)
            .await?;
        // Filled on the way out for the same reason the snapshot is: a row this
        // op just returned and the same row from `list_connections` must not
        // disagree about which target reaches it.
        Self::backfill_connection_owner(
            &ovstorage_layer::sole_owning_target(&self.owned_targets()),
            &mut connection,
        );
        Ok(connection)
    }
    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let mut connection = self
            .update_connection_attributes_op(request, cancel)
            .await?;
        // Filled on the way out for the same reason the snapshot is: a row this
        // op just returned and the same row from `list_connections` must not
        // disagree about which target reaches it.
        Self::backfill_connection_owner(
            &ovstorage_layer::sole_owning_target(&self.owned_targets()),
            &mut connection,
        );
        Ok(connection)
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
        // A `Succeeded` event carries a `Connection`, so it is a fourth path a
        // row reaches a caller through and it must agree with the other three.
        // A caller that replaces its cached row with this one would otherwise
        // lose the target it had — the same connection under two keys depending
        // on which path delivered it, which is exactly what
        // `backfill_connection_owner` exists to prevent. Resolved once here,
        // like the listing's, rather than per event.
        let sole_target = ovstorage_layer::sole_owning_target(&self.owned_targets());
        let stream: AuthEventStream = Box::new(stream.map(move |event| match event {
            Ok(AuthEvent::Succeeded {
                mut connection,
                credentials,
            }) => {
                Self::backfill_connection_owner(&sole_target, &mut connection);
                Ok(AuthEvent::Succeeded {
                    connection,
                    credentials,
                })
            }
            other => other,
        }));
        // `cancel_handle` lives as long as the returned stream, so a host
        // cancel keeps reaching the plugin token that stream polls — the wait
        // an interactive auth flow parks on (browser round-trip, device-code
        // poll) is inside the stream, not the call. Dropping the stream drops
        // the handle (aborts the bridge, tears down the subscription). On the
        // error arm the early return above drops the handle. The map above sits
        // INSIDE this guard so cancellation still reaches the plugin's stream.
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

    fn root_info_fixture(owning_target: Option<String>) -> RootInfo {
        RootInfo {
            root: root_from_ffi_str("file:///data/root/").expect("the fixture root parses"),
            display_name: None,
            layer_kind: "file".to_string(),
            connection_id: Some(ConnectionId("c-1".into())),
            owning_target,
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::default(),
            source: RouteSource::ConnectionContributed {
                connection_id: ConnectionId("c-1".into()),
            },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    /// A `RootInfo` carrying a target, encoded and decoded, keeps it verbatim,
    /// and one carrying none still answers `None`.
    ///
    /// This is the guard on the emptiness normalisation below: a filter that
    /// rejected too much would silence an attribution the plugin actually made,
    /// and every consumer would fall back to deriving the owner. Asserting the
    /// `Some` case separately means the two failures are told apart. The absent
    /// case is not the same code path either: an `Optional` that is not present
    /// carries unspecified bytes, and the decoder must answer `None` rather than
    /// reading them.
    #[test]
    fn a_root_infos_owning_target_survives_the_round_trip() {
        for target in [Some("files".to_string()), None] {
            let original = root_info_fixture(target);
            let back = unsafe {
                root_info_from_ffi(crate::thunks_v2::root_info_to_ffi(original.clone()))
                    .expect("the fixture decodes")
            };
            assert_eq!(original.owning_target, back.owning_target);
        }
    }

    /// An UNSET `owning_target` payload on a `RootInfo` decodes to `None`.
    ///
    /// `present == true` with `ptr == NULL, len == 0` is the shape a C plugin
    /// reaches by omission rather than by mistake: `calloc` gives exactly that,
    /// so setting `present` on a zero-initialised struct produces it. The
    /// producer never wrote the field, so there is no attribution to carry, and
    /// `None` is what the row means.
    #[test]
    fn an_unset_root_owning_target_payload_decodes_as_absent() {
        let mut encoded = crate::thunks_v2::root_info_to_ffi(root_info_fixture(None));

        // The fixture must arrive UNATTRIBUTED, or the overwrite below would not
        // be what makes the payload unset and the test would be proving
        // something about the encoder instead.
        assert!(
            !encoded.owning_target.present,
            "an unattributed fixture must encode to an absent Optional",
        );

        // Overwrite it with the zeroed-but-present shape. The encoder cannot
        // produce this; a C producer does, which is the point.
        encoded.owning_target = ffi::Optional::some(ffi::Str {
            ptr: std::ptr::null_mut(),
            len: 0,
        });

        let decoded = unsafe { root_info_from_ffi(encoded).expect("the fixture decodes") };
        assert_eq!(
            decoded.owning_target, None,
            "a payload the producer never wrote is not an attribution",
        );
    }

    /// A DELIBERATELY empty `owning_target` survives the ROUND TRIP as
    /// `Some("")`, through the real encoder rather than a hand-built `Str`.
    ///
    /// This is the half that distinguishes discriminating on the encoding from
    /// testing the decoded length, and it is a shape a Rust producer reaches by
    /// construction rather than a hypothetical one. `str_to_ffi` routes the
    /// empty string through `abi_capacity`, which returns a one-element
    /// sentinel for a zero length, and `abi_alloc_array` aborts rather than
    /// return NULL — so `Some(String::new())` on a plugin's `RootInfo` encodes
    /// to `ptr != NULL, len == 0` every time. The encoded assertions below are
    /// what pins that, so the claim rests on this test rather than on a comment
    /// somewhere else.
    ///
    /// Losing it would matter: an empty layer instance name is legal at the
    /// graph level (neither stack builder nor the TOML config path rejects one)
    /// and a Router routes target `""` like any other key.
    #[test]
    fn a_deliberately_empty_root_owning_target_survives_the_round_trip() {
        let encoded = crate::thunks_v2::root_info_to_ffi(root_info_fixture(Some(String::new())));

        // The encoder's own output is the premise: `present`, a non-NULL
        // pointer, and a zero length. If this ever became the calloc shape the
        // decode below would be reading the OTHER case and would pass for the
        // wrong reason.
        assert!(
            encoded.owning_target.present,
            "an attributed fixture must encode to a present Optional",
        );
        // SAFETY: `present` was just asserted, so the payload is initialized.
        let payload = unsafe { &*encoded.owning_target.value.as_ptr() };
        assert!(
            !payload.ptr.is_null(),
            "str_to_ffi must mint the sentinel allocation for an empty string",
        );
        assert_eq!(payload.len, 0, "an empty target encodes to a zero length");

        let decoded = unsafe { root_info_from_ffi(encoded).expect("the fixture decodes") };
        assert_eq!(
            decoded.owning_target,
            Some(String::new()),
            "an empty target the producer encoded on purpose must survive",
        );
    }

    /// The present-but-unwritten shape a C producer reaches by `calloc`: the
    /// encoder cannot produce it, so tests overwrite an absent field with it.
    fn unset_str() -> ffi::Optional<ffi::Str> {
        ffi::Optional::some(ffi::Str {
            ptr: std::ptr::null_mut(),
            len: 0,
        })
    }

    /// The other root-info optional strings follow the `owning_target` rule:
    /// a payload the producer never wrote decodes to `None`, the way the C
    /// host delivers NULL for the same bytes. `connection_id` wraps its string
    /// one struct further in and is decoded by the wrapper's own helper.
    #[test]
    fn unset_root_display_name_and_connection_id_payloads_decode_as_absent() {
        let mut encoded = crate::thunks_v2::root_info_to_ffi(RootInfo {
            connection_id: None,
            ..root_info_fixture(None)
        });
        assert!(
            !encoded.display_name.present,
            "the fixture display name must be absent"
        );
        assert!(
            !encoded.connection_id.present,
            "the fixture connection id must be absent"
        );

        encoded.display_name = unset_str();
        encoded.connection_id = ffi::Optional::some(ffi::ConnectionId {
            id: ffi::Str {
                ptr: std::ptr::null_mut(),
                len: 0,
            },
        });

        let decoded = unsafe { root_info_from_ffi(encoded).expect("the fixture decodes") };
        assert_eq!(decoded.display_name, None);
        assert_eq!(decoded.connection_id, None);
    }

    /// The nested route-source and alias-state strings decode into
    /// non-optional fields, so an unset payload reads as `""` there; the
    /// decode must still succeed, and the deliberately-empty shape must read
    /// the same way, so the two hosts agree on what the row says.
    #[test]
    fn unset_nested_root_info_strings_decode_without_error() {
        let mut encoded = crate::thunks_v2::root_info_to_ffi(RootInfo {
            source: RouteSource::BrokerDelivered {
                broker_principal: String::new(),
                connection_id: ConnectionId("c-1".into()),
            },
            alias_state: Some(AliasState::ChainTooLong {
                reason: String::new(),
            }),
            ..root_info_fixture(None)
        });
        assert!(encoded.source.broker_principal.present);
        assert!(encoded.alias_state.present);

        // Replace rather than assign so the encoder's sentinel allocations
        // are released instead of leaked.
        drop(std::mem::replace(
            &mut encoded.source.broker_principal,
            unset_str(),
        ));
        // SAFETY: `present` was just asserted, so the payload is initialized.
        unsafe {
            drop(std::mem::replace(
                &mut (*encoded.alias_state.value.as_mut_ptr()).reason,
                unset_str(),
            ));
        }

        let decoded = unsafe { root_info_from_ffi(encoded).expect("the fixture decodes") };
        assert_eq!(
            decoded.source,
            RouteSource::BrokerDelivered {
                broker_principal: String::new(),
                connection_id: ConnectionId("c-1".into()),
            }
        );
        assert_eq!(
            decoded.alias_state,
            Some(AliasState::ChainTooLong {
                reason: String::new()
            })
        );
    }

    /// A `next_page_token` the producer never wrote is `None`, so a lister
    /// stops rather than re-issuing with an empty token; one it encoded as
    /// empty on purpose survives, so the rule is a discrimination on the
    /// encoding and not a length test.
    #[test]
    fn unset_page_token_payloads_decode_as_absent() {
        let mut list = crate::thunks_v2::list_page_to_ffi(ListPage {
            items: vec![],
            next_page_token: None,
        });
        let mut versions = crate::thunks_v2::version_page_to_ffi(VersionPage {
            items: vec![],
            next_page_token: None,
        });
        assert!(!list.next_page_token.present);
        assert!(!versions.next_page_token.present);

        list.next_page_token = unset_str();
        versions.next_page_token = unset_str();
        let list = unsafe { list_page_from_ffi(list).expect("the page decodes") };
        let versions = unsafe { version_page_from_ffi(versions).expect("the page decodes") };
        assert_eq!(list.next_page_token, None);
        assert_eq!(versions.next_page_token, None);

        let list = crate::thunks_v2::list_page_to_ffi(ListPage {
            items: vec![],
            next_page_token: Some(String::new()),
        });
        let versions = crate::thunks_v2::version_page_to_ffi(VersionPage {
            items: vec![],
            next_page_token: Some(String::new()),
        });
        let list = unsafe { list_page_from_ffi(list).expect("the page decodes") };
        let versions = unsafe { version_page_from_ffi(versions).expect("the page decodes") };
        assert_eq!(list.next_page_token, Some(String::new()));
        assert_eq!(versions.next_page_token, Some(String::new()));
    }

    // -----------------------------------------------------------------
    // v17 list-stream consumer bridge
    // -----------------------------------------------------------------

    enum StubListFrame {
        Item(Box<ObjectInfo>),
        Error(ffi::StreamStep, Error),
        BlockUntilCancelled,
    }

    struct StubLayerState {
        frames: std::sync::Mutex<Option<std::collections::VecDeque<StubListFrame>>>,
        layer_drops: Arc<std::sync::atomic::AtomicUsize>,
        stream_drops: Arc<std::sync::atomic::AtomicUsize>,
        pulls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for StubLayerState {
        fn drop(&mut self) {
            self.layer_drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct StubListEntryState {
        frames: std::collections::VecDeque<StubListFrame>,
        cancel: Option<ffi::CancelTokenLocal>,
        stream_drops: Arc<std::sync::atomic::AtomicUsize>,
        pulls: Arc<std::sync::atomic::AtomicUsize>,
        terminal: bool,
    }

    impl Drop for StubListEntryState {
        fn drop(&mut self) {
            self.stream_drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn stub_layer_name(_state: *mut c_void, out: *mut ffi::Str) {
        unsafe {
            out.write(marshal::primitive::str_to_ffi(
                "consume-list-stream-stub".to_string(),
            ));
        }
    }

    unsafe extern "C" fn stub_layer_drop(state: *mut c_void) {
        unsafe {
            drop(Box::from_raw(state as *mut StubLayerState));
        }
    }

    unsafe extern "C" fn stub_list_entry_drop(state: *mut c_void) {
        unsafe {
            drop(Box::from_raw(state as *mut StubListEntryState));
        }
    }

    unsafe extern "C" fn stub_list_entry_next(
        state: *mut c_void,
        out_item: *mut ffi::ObjectInfo,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        let state = unsafe { &mut *(state as *mut StubListEntryState) };
        if state.terminal {
            return ffi::StreamStep::Ended;
        }
        state
            .pulls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if state
            .cancel
            .as_ref()
            .is_some_and(|cancel| cancel.token().is_cancelled())
        {
            state.terminal = true;
            unsafe {
                out_error.write(marshal::error::to_ffi(&Error::new(
                    ErrorCode::Cancelled,
                    "stub listing cancelled",
                )));
            }
            return ffi::StreamStep::Failed;
        }
        match state.frames.pop_front() {
            Some(StubListFrame::Item(item)) => {
                unsafe { out_item.write(marshal::metadata::object_info_to_ffi(*item)) };
                ffi::StreamStep::Yielded
            }
            Some(StubListFrame::Error(step, error)) => {
                unsafe { out_error.write(marshal::error::to_ffi(&error)) };
                state.terminal = step == ffi::StreamStep::Failed;
                step
            }
            Some(StubListFrame::BlockUntilCancelled) => {
                while !state
                    .cancel
                    .as_ref()
                    .is_some_and(|cancel| cancel.token().is_cancelled())
                {
                    std::thread::park_timeout(std::time::Duration::from_millis(1));
                }
                state.terminal = true;
                unsafe {
                    out_error.write(marshal::error::to_ffi(&Error::new(
                        ErrorCode::Cancelled,
                        "stub listing cancelled",
                    )));
                }
                ffi::StreamStep::Failed
            }
            None => {
                state.terminal = true;
                ffi::StreamStep::Ended
            }
        }
    }

    unsafe extern "C" fn stub_list_stream_slot(
        state: *mut c_void,
        request: *const ffi::ListRequest,
        cancel: *const ffi::CancelTokenFFI,
        on_complete: ffi::OnComplete,
        user_data: *mut c_void,
    ) {
        // Adopt the request fields the consumer deliberately forgets. The
        // extensions pointer remains borrowed and is reclaimed by the host
        // after this synchronous prologue returns.
        let request = unsafe { std::ptr::read(request) };
        let ffi::ListRequest {
            prefix, options, ..
        } = request;
        drop(prefix);
        drop(options);

        let layer = unsafe { &*(state as *const StubLayerState) };
        let frames = layer
            .frames
            .lock()
            .expect("stub frames mutex")
            .take()
            .expect("stub list_stream opened once");
        let stream_drops = Arc::clone(&layer.stream_drops);
        let pulls = Arc::clone(&layer.pulls);
        let cancel_local = crate::ffi_runtime::local_cancel(cancel);
        crate::ffi_runtime::spawn_async_stream_thunk(
            "stub_list_stream",
            cancel_local,
            on_complete,
            user_data,
            |_cancel_token| Box::pin(async { Ok(()) }),
            move |(), cancel_guard| {
                let stream_state = Box::new(StubListEntryState {
                    frames,
                    cancel: cancel_guard,
                    stream_drops,
                    pulls,
                    terminal: false,
                });
                Some(ffi::abi_alloc::AbiOwned::new(ffi::ListEntryStream {
                    state: Box::into_raw(stream_state) as *mut c_void,
                    next_fn: stub_list_entry_next,
                    drop_fn: stub_list_entry_drop,
                }))
            },
        );
    }

    struct ListStreamStub {
        layer: Arc<ForeignVtableLayer>,
        layer_drops: Arc<std::sync::atomic::AtomicUsize>,
        stream_drops: Arc<std::sync::atomic::AtomicUsize>,
        pulls: Arc<std::sync::atomic::AtomicUsize>,
    }

    fn list_stream_stub(frames: Vec<StubListFrame>) -> ListStreamStub {
        let layer_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = Box::into_raw(Box::new(StubLayerState {
            frames: std::sync::Mutex::new(Some(frames.into())),
            layer_drops: Arc::clone(&layer_drops),
            stream_drops: Arc::clone(&stream_drops),
            pulls: Arc::clone(&pulls),
        })) as *mut c_void;

        // Copy the complete in-tree vtable as inert padding, then replace the
        // only three slots this hand-built foreign stub exercises. A fresh
        // address forces the real ForeignVtableLayer path.
        let mut vtable =
            unsafe { std::ptr::read(std::ptr::addr_of!(crate::thunks_v2::LAYER_VTABLE)) };
        vtable.drop = stub_layer_drop;
        vtable.name = stub_layer_name;
        vtable.list_stream = stub_list_stream_slot;
        let vtable = Box::leak(Box::new(vtable));
        let layer = ForeignVtableLayer::from_handle(ffi::LayerHandle { state, vtable }, None)
            .expect("import hand-built list-stream vtable");
        ListStreamStub {
            layer,
            layer_drops,
            stream_drops,
            pulls,
        }
    }

    fn list_stream_request() -> Request<ListRequest> {
        Request::new(ListRequest {
            prefix: Url::parse("stub://root/prefix/").expect("fixture URL"),
            options: ListOptions::default(),
        })
    }

    fn list_info(index: usize) -> ObjectInfo {
        ObjectInfo {
            etag_strength: EtagStrength::Strong,
            address: Url::parse(&format!("stub://root/prefix/{index:03}")).expect("fixture URL"),
            kind: ObjectKind::File,
            etag: Some(format!("etag-{index}")),
            version: None,
            size: Some(index as u64),
            mtime: None,
            checksums: ChecksumSet::new(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }

    async fn wait_for_count(counter: &std::sync::atomic::AtomicUsize, target: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while counter.load(std::sync::atomic::Ordering::SeqCst) < target {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("counter reached target");
    }

    // -----------------------------------------------------------------
    // Rust producer -> v17 thunk -> ForeignVtableLayer round trips
    // -----------------------------------------------------------------

    fn round_trip_descriptor(kind: &str) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: kind.to_string(),
            layer_type: LayerType::Backend,
            display_name: format!("{kind} test layer"),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    fn round_trip_layer(layer: Arc<dyn Layer>) -> Arc<ForeignVtableLayer> {
        let handle = crate::thunks_v2::export_handle(layer);
        ForeignVtableLayer::from_handle(handle, None)
            .expect("import the Rust-produced handle through the foreign vtable adapter")
    }

    unsafe extern "C" fn unsupported_list_stream_slot(
        _state: *mut c_void,
        request: *const ffi::ListRequest,
        _cancel: *const ffi::CancelTokenFFI,
        on_complete: ffi::OnComplete,
        user_data: *mut c_void,
    ) {
        // Adopt the request fields exactly as a foreign default thunk does.
        // Extensions remain borrowed and are reclaimed by the host after this
        // synchronous prologue returns.
        let request = unsafe { std::ptr::read(request) };
        let ffi::ListRequest {
            prefix, options, ..
        } = request;
        drop(prefix);
        drop(options);

        crate::ffi_runtime::fire_complete_err(
            Error::new(
                ErrorCode::Unsupported,
                "operation is unsupported by this layer",
            ),
            on_complete,
            user_data,
        );
    }

    fn round_trip_layer_with_unsupported_list_stream(
        layer: Arc<dyn Layer>,
    ) -> Arc<ForeignVtableLayer> {
        let handle = crate::thunks_v2::export_handle(layer);
        let state = handle.state;
        std::mem::forget(handle);

        let mut vtable =
            unsafe { std::ptr::read(std::ptr::addr_of!(crate::thunks_v2::LAYER_VTABLE)) };
        vtable.list_stream = unsupported_list_stream_slot;
        ForeignVtableLayer::from_handle(
            ffi::LayerHandle {
                state,
                vtable: Box::leak(Box::new(vtable)),
            },
            None,
        )
        .expect("import a foreign layer whose list_stream slot declines")
    }

    struct ScriptObservation {
        polls: std::sync::atomic::AtomicUsize,
        polled: tokio::sync::Notify,
        dropped: std::sync::atomic::AtomicBool,
        drop_notified: tokio::sync::Notify,
    }

    impl ScriptObservation {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                polls: std::sync::atomic::AtomicUsize::new(0),
                polled: tokio::sync::Notify::new(),
                dropped: std::sync::atomic::AtomicBool::new(false),
                drop_notified: tokio::sync::Notify::new(),
            })
        }

        async fn wait_for_polls(&self, target: usize) {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    let notified = self.polled.notified();
                    if self.polls.load(std::sync::atomic::Ordering::SeqCst) >= target {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("scripted source reached the expected poll gate");
        }

        async fn wait_for_drop(&self) {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    let notified = self.drop_notified.notified();
                    if self.dropped.load(std::sync::atomic::Ordering::SeqCst) {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("scripted source was dropped promptly");
        }
    }

    struct ScriptDropGuard(Arc<ScriptObservation>);

    impl Drop for ScriptDropGuard {
        fn drop(&mut self) {
            self.0
                .dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.0.drop_notified.notify_waiters();
        }
    }

    struct ScriptedListLayer {
        entries: Arc<Vec<ObjectInfo>>,
        observation: Arc<ScriptObservation>,
    }

    impl ScriptedListLayer {
        fn new(count: usize, observation: Arc<ScriptObservation>) -> Self {
            Self {
                entries: Arc::new((0..count).map(list_info).collect()),
                observation,
            }
        }
    }

    #[async_trait::async_trait]
    impl Layer for ScriptedListLayer {
        fn name(&self) -> &str {
            "ffi-round-trip-script"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            round_trip_descriptor(self.name())
        }

        async fn list(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListPage> {
            Ok(ListPage {
                items: self.entries.as_ref().clone(),
                next_page_token: None,
            })
        }

        async fn list_stream(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListStream> {
            let entries = Arc::clone(&self.entries);
            let observation = Arc::clone(&self.observation);
            let drop_guard = ScriptDropGuard(Arc::clone(&observation));
            let mut index = 0;
            Ok(Box::pin(futures::stream::poll_fn(move |_cx| {
                let _keep_drop_guard_in_stream = &drop_guard;
                if index == entries.len() {
                    return std::task::Poll::Ready(None);
                }
                let item = entries[index].clone();
                index += 1;
                observation
                    .polls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                observation.polled.notify_waiters();
                std::task::Poll::Ready(Some(Ok(item)))
            })))
        }
    }

    struct BufferedOnlyRoundTripLayer {
        entries: Vec<ObjectInfo>,
        next_page_token: Option<String>,
    }

    #[async_trait::async_trait]
    impl Layer for BufferedOnlyRoundTripLayer {
        fn name(&self) -> &str {
            "ffi-round-trip-buffered-only"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            round_trip_descriptor(self.name())
        }

        async fn list(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListPage> {
            Ok(ListPage {
                items: self.entries.clone(),
                next_page_token: self.next_page_token.clone(),
            })
        }
    }

    struct CountedListEntryState {
        inner: ffi::ListEntryStream,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    unsafe extern "C" fn counted_list_entry_next(
        state: *mut c_void,
        out_item: *mut ffi::ObjectInfo,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        let state = unsafe { &mut *(state as *mut CountedListEntryState) };
        unsafe { (state.inner.next_fn)(state.inner.state, out_item, out_error) }
    }

    unsafe extern "C" fn counted_list_entry_drop(state: *mut c_void) {
        let state = unsafe { Box::from_raw(state as *mut CountedListEntryState) };
        state
            .drops
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        drop(state);
    }

    struct CountedOpenCall {
        on_complete: ffi::OnComplete,
        user_data: *mut c_void,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    extern "C" fn counted_list_stream_opened(
        status: i32,
        result: *mut c_void,
        error: *mut ffi::Error,
        user_data: *mut c_void,
    ) {
        let call = unsafe { Box::from_raw(user_data as *mut CountedOpenCall) };
        if status != ffi::FFI_STATUS_OK {
            (call.on_complete)(status, result, error, call.user_data);
            return;
        }
        let inner = unsafe { ffi::abi_alloc::abi_unbox(result.cast::<ffi::ListEntryStream>()) };
        let state = Box::new(CountedListEntryState {
            inner,
            drops: call.drops,
        });
        let stream = ffi::ListEntryStream {
            state: Box::into_raw(state).cast(),
            next_fn: counted_list_entry_next,
            drop_fn: counted_list_entry_drop,
        };
        (call.on_complete)(
            status,
            ffi::abi_alloc::abi_box(stream).cast(),
            error,
            call.user_data,
        );
    }

    struct CountedLayerState {
        inner: *mut c_void,
        stream_drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    unsafe extern "C" fn counted_layer_name(state: *mut c_void, out: *mut ffi::Str) {
        let state = unsafe { &*(state as *const CountedLayerState) };
        unsafe { (crate::thunks_v2::LAYER_VTABLE.name)(state.inner, out) };
    }

    unsafe extern "C" fn counted_layer_drop(state: *mut c_void) {
        let state = unsafe { Box::from_raw(state as *mut CountedLayerState) };
        unsafe { (crate::thunks_v2::LAYER_VTABLE.drop)(state.inner) };
    }

    unsafe extern "C" fn counted_list_stream_slot(
        state: *mut c_void,
        request: *const ffi::ListRequest,
        cancel: *const ffi::CancelTokenFFI,
        on_complete: ffi::OnComplete,
        user_data: *mut c_void,
    ) {
        let state = unsafe { &*(state as *const CountedLayerState) };
        let call = Box::new(CountedOpenCall {
            on_complete,
            user_data,
            drops: Arc::clone(&state.stream_drops),
        });
        unsafe {
            (crate::thunks_v2::LAYER_VTABLE.list_stream)(
                state.inner,
                request,
                cancel,
                counted_list_stream_opened,
                Box::into_raw(call).cast(),
            )
        };
    }

    fn counted_round_trip_layer(
        layer: Arc<dyn Layer>,
        stream_drops: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Arc<ForeignVtableLayer> {
        let handle = crate::thunks_v2::export_handle(layer);
        let inner = handle.state;
        std::mem::forget(handle);
        let state = Box::new(CountedLayerState {
            inner,
            stream_drops,
        });
        let mut vtable =
            unsafe { std::ptr::read(std::ptr::addr_of!(crate::thunks_v2::LAYER_VTABLE)) };
        vtable.name = counted_layer_name;
        vtable.drop = counted_layer_drop;
        vtable.list_stream = counted_list_stream_slot;
        let vtable = Box::leak(Box::new(vtable));
        ForeignVtableLayer::from_handle(
            ffi::LayerHandle {
                state: Box::into_raw(state).cast(),
                vtable,
            },
            None,
        )
        .expect("import the drop-counted Rust-produced handle")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rust_produced_list_stream_matches_buffered_list_across_v17() {
        use futures::StreamExt as _;

        let observation = ScriptObservation::new();
        let layer = round_trip_layer(Arc::new(ScriptedListLayer::new(
            384,
            Arc::clone(&observation),
        )));
        let buffered = layer
            .list(list_stream_request(), None)
            .await
            .expect("buffered list across the ABI");
        let streamed = layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("streamed list across the ABI")
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .expect("all streamed entries decode");

        assert_eq!(streamed, buffered.items);
        observation.wait_for_drop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_rust_produced_list_stream_is_terminal_and_stops_source_polls() {
        use futures::StreamExt as _;

        let observation = ScriptObservation::new();
        let layer = round_trip_layer(Arc::new(ScriptedListLayer::new(
            384,
            Arc::clone(&observation),
        )));
        let cancel = CancellationToken::new();
        let mut stream = layer
            .list_stream(list_stream_request(), Some(cancel.clone()))
            .await
            .expect("streamed list across the ABI");

        for expected in 0..17 {
            let item = stream
                .next()
                .await
                .expect("script has another entry")
                .expect("entry before cancellation");
            assert_eq!(item, list_info(expected));
        }
        cancel.cancel();

        let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match stream.next().await {
                    Some(Ok(_queued_before_cancel)) => continue,
                    Some(Err(error)) => return error,
                    None => panic!("cancellation ended the stream without a Cancelled frame"),
                }
            }
        })
        .await
        .expect("cancellation reaches the consumer promptly");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(stream.next().await.is_none(), "cancellation is terminal");
        observation.wait_for_drop().await;
        let polls_when_stopped = observation.polls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            polls_when_stopped < 384,
            "cancellation must stop the scripted source before exhaustion"
        );
        assert_eq!(
            observation.polls.load(std::sync::atomic::Ordering::SeqCst),
            polls_when_stopped,
            "a dropped scripted source cannot be polled after cancellation"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_preempts_a_prefetched_foreign_end_of_stream() {
        use futures::StreamExt as _;

        let observation = ScriptObservation::new();
        let layer = round_trip_layer(Arc::new(ScriptedListLayer::new(
            1,
            Arc::clone(&observation),
        )));
        let cancel = CancellationToken::new();
        let mut stream = layer
            .list_stream(list_stream_request(), Some(cancel.clone()))
            .await
            .expect("streamed list across the ABI");

        assert_eq!(
            stream
                .next()
                .await
                .expect("one entry")
                .expect("valid entry"),
            list_info(0)
        );
        observation.wait_for_drop().await;
        cancel.cancel();

        let error = stream
            .next()
            .await
            .expect("cancellation preempts an unobserved EOF")
            .expect_err("cancellation is terminal");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(stream.next().await.is_none(), "cancellation is terminal");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_foreign_consumer_bounds_end_to_end_source_residency() {
        use futures::StreamExt as _;

        let observation = ScriptObservation::new();
        let layer = round_trip_layer(Arc::new(ScriptedListLayer::new(
            384,
            Arc::clone(&observation),
        )));
        let mut stream = layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("streamed list across the ABI");
        let first = stream
            .next()
            .await
            .expect("first scripted entry")
            .expect("first entry decodes");
        assert_eq!(first, list_info(0));

        // One item has reached the caller. Each capacity-one ABI channel may
        // retain one item, and each of its senders may own one parked item.
        // Waiting on the poll notification is the gate proving the pipeline
        // reached that bound; the consumer remains parked until the assertion.
        let residency_bound = 1
            + LIST_STREAM_BRIDGE_CAPACITY
            + crate::thunks_v2::list_entry_channel_capacity_for_test()
            + 2;
        observation.wait_for_polls(residency_bound).await;
        assert_eq!(
            observation.polls.load(std::sync::atomic::Ordering::SeqCst),
            residency_bound,
            "the composed capacity-one bridges retain only their queues and parked sends"
        );

        let mut count = 1;
        while let Some(item) = stream.next().await {
            item.expect("remaining entry decodes");
            count += 1;
        }
        assert_eq!(count, 384, "resuming the consumer drains every entry");
        observation.wait_for_drop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffered_only_layer_default_serves_v17_round_trip_slot() {
        use futures::StreamExt as _;

        let expected: Vec<_> = (0..257).map(list_info).collect();
        let layer = round_trip_layer(Arc::new(BufferedOnlyRoundTripLayer {
            entries: expected.clone(),
            next_page_token: None,
        }));
        let actual = layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("default list_stream opens across the ABI")
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .expect("default-adapted entries decode");
        assert_eq!(actual, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsupported_foreign_list_stream_adapts_the_buffered_list_slot() {
        use futures::StreamExt as _;

        let expected: Vec<_> = (0..257).map(list_info).collect();
        let layer =
            round_trip_layer_with_unsupported_list_stream(Arc::new(BufferedOnlyRoundTripLayer {
                entries: expected.clone(),
                next_page_token: None,
            }));
        let actual = layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("foreign Unsupported list_stream adapts list")
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .expect("buffered fallback entries decode");

        assert_eq!(actual, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsupported_foreign_list_stream_refuses_a_partial_buffered_list() {
        let layer =
            round_trip_layer_with_unsupported_list_stream(Arc::new(BufferedOnlyRoundTripLayer {
                entries: vec![list_info(0)],
                next_page_token: Some("foreign-token".into()),
            }));
        let result = layer.list_stream(list_stream_request(), None).await;
        let error = match result {
            Ok(_) => panic!("partial foreign listing unexpectedly became a stream"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::Internal);
        assert!(error.message().contains("continuation token"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsupported_foreign_list_stream_preserves_open_time_cancellation() {
        use futures::StreamExt as _;

        let layer =
            round_trip_layer_with_unsupported_list_stream(Arc::new(BufferedOnlyRoundTripLayer {
                entries: vec![list_info(0)],
                next_page_token: None,
            }));
        let cancel = CancellationToken::new();
        let mut stream = layer
            .list_stream(list_stream_request(), Some(cancel.clone()))
            .await
            .expect("foreign Unsupported list_stream adapts list");
        cancel.cancel();

        let error = stream
            .next()
            .await
            .expect("cancellation emits one terminal frame")
            .expect_err("a cancelled fallback cannot yield its buffered entry");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(stream.next().await.is_none(), "cancellation is terminal");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_half_consumed_round_trip_stream_runs_ffi_drop_once() {
        use futures::StreamExt as _;

        let observation = ScriptObservation::new();
        let stream_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let layer = counted_round_trip_layer(
            Arc::new(ScriptedListLayer::new(384, Arc::clone(&observation))),
            Arc::clone(&stream_drops),
        );
        let mut stream = layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("streamed list across the counted ABI");
        for _ in 0..17 {
            stream
                .next()
                .await
                .expect("script has another entry")
                .expect("entry decodes");
        }
        drop(stream);

        wait_for_count(&stream_drops, 1).await;
        observation.wait_for_drop().await;
        assert_eq!(
            stream_drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "dropping a half-consumed host stream drives the FFI drop_fn exactly once"
        );
    }

    fn fail_list_stream_thread_spawn(_iter: ListEntryIter) -> Result<ListStreamReceiver> {
        Err(Error::new(
            ErrorCode::ResourceExhausted,
            "injected list-stream bridge thread spawn failure",
        ))
    }

    #[tokio::test]
    async fn foreign_list_stream_thread_spawn_failure_is_a_terminal_error_item() {
        use futures::StreamExt as _;

        let stream_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pulls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = Box::new(StubListEntryState {
            frames: vec![StubListFrame::Item(Box::new(list_info(0)))].into(),
            cancel: None,
            stream_drops: Arc::clone(&stream_drops),
            pulls: Arc::clone(&pulls),
            terminal: false,
        });
        let foreign_stream = ffi::ListEntryStream {
            state: Box::into_raw(state) as *mut c_void,
            next_fn: stub_list_entry_next,
            drop_fn: stub_list_entry_drop,
        };
        let cancel = ffi::cancel_token_to_ffi(CancellationToken::new());
        let mut stream =
            bridge_list_stream_with_spawn(foreign_stream, cancel, fail_list_stream_thread_spawn);

        let error = stream
            .next()
            .await
            .expect("spawn failure emits one frame")
            .expect_err("spawn failure cannot yield an object");
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(stream.next().await.is_none(), "spawn failure is terminal");
        assert_eq!(pulls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            stream_drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the failed spawn must release the foreign iterator exactly once",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_list_stream_flows_in_order_with_bounded_prefetch() {
        use futures::StreamExt as _;

        let stub = list_stream_stub(
            (0..20)
                .map(|index| StubListFrame::Item(Box::new(list_info(index))))
                .collect(),
        );
        let mut stream = stub
            .layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("open foreign list stream");
        assert_eq!(
            stub.pulls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "opening alone must not prefetch"
        );

        let first = stream
            .next()
            .await
            .expect("first frame")
            .expect("first item");
        assert_eq!(first.address.as_str(), "stub://root/prefix/000");
        wait_for_count(&stub.pulls, 3).await;
        assert_eq!(
            stub.pulls.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "capacity-one bridge may hold one queued and one sending item only"
        );

        let mut addresses = vec![first.address];
        while let Some(item) = stream.next().await {
            addresses.push(item.expect("stream item").address);
        }
        let expected: Vec<_> = (0..20)
            .map(|index| Url::parse(&format!("stub://root/prefix/{index:03}")).unwrap())
            .collect();
        assert_eq!(addresses, expected);
        assert_eq!(
            stub.stream_drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "natural exhaustion must release the plugin iterator exactly once"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_foreign_list_stream_releases_plugin_iterator() {
        use futures::StreamExt as _;

        let stub = list_stream_stub(
            (0..100)
                .map(|index| StubListFrame::Item(Box::new(list_info(index))))
                .collect(),
        );
        let mut stream = stub
            .layer
            .list_stream(list_stream_request(), None)
            .await
            .expect("open foreign list stream");
        stream
            .next()
            .await
            .expect("first frame")
            .expect("first item");
        drop(stream);
        wait_for_count(&stub.stream_drops, 1).await;
        assert_eq!(
            stub.stream_drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "early drop must drive drop_fn exactly once"
        );
        drop(stub.layer);
        assert_eq!(
            stub.layer_drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the foreign Layer state remains independently releasable"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_foreign_list_stream_wakes_blocking_pull_promptly() {
        use futures::StreamExt as _;

        let stub = list_stream_stub(vec![StubListFrame::BlockUntilCancelled]);
        let cancel = CancellationToken::new();
        let mut stream = stub
            .layer
            .list_stream(list_stream_request(), Some(cancel.clone()))
            .await
            .expect("open foreign list stream");
        let next = tokio::spawn(async move { stream.next().await });
        wait_for_count(&stub.pulls, 1).await;
        cancel.cancel();
        let item = tokio::time::timeout(std::time::Duration::from_secs(1), next)
            .await
            .expect("cancel wakes FFI next_fn")
            .expect("consumer task did not panic")
            .expect("cancel emits a terminal error")
            .expect_err("cancel cannot yield an object");
        assert_eq!(item.code(), ErrorCode::Cancelled);
        wait_for_count(&stub.stream_drops, 1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_list_stream_error_steps_preserve_codes_and_are_terminal() {
        use futures::StreamExt as _;

        for (step, code) in [
            (ffi::StreamStep::Failed, ErrorCode::Internal),
            (ffi::StreamStep::TransientError, ErrorCode::Transient),
        ] {
            let stub = list_stream_stub(vec![
                StubListFrame::Error(step, Error::new(code, "stub stream error")),
                StubListFrame::Item(Box::new(list_info(99))),
            ]);
            let mut stream = stub
                .layer
                .list_stream(list_stream_request(), None)
                .await
                .expect("open foreign list stream");
            let error = stream
                .next()
                .await
                .expect("error frame")
                .expect_err("frame must remain an error");
            assert_eq!(error.code(), code);
            assert!(
                stream.next().await.is_none(),
                "both error steps are terminal"
            );
            assert_eq!(
                stub.pulls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the bridge must not pull after an error step"
            );
            assert_eq!(
                stub.stream_drops.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "terminal errors release plugin state"
            );
        }
    }
}
