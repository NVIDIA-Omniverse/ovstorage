// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Visibility overrides + discovery surface.
//!
//! Three opaque types + their list handles:
//!
//! - `AddressVisibilityOverride` — returned from
//!   `ovstorage_library_set_address_visibility` and listed by
//!   `ovstorage_library_list_address_visibility_overrides`.
//! - `AddressRoot` — listed by `ovstorage_library_list_address_roots`;
//!   carries the route the host resolved for a given prefix.
//! - `BackendKindDescriptor` — listed by
//!   `ovstorage_library_list_backend_kinds`; describes one known
//!   backend (kind id, display name, capabilities, runtime-add
//!   support, optional icon).
//!
//! Schema accessors on `BackendKindDescriptor` (config / credential
//! field walks) are deferred — they target UI-generation tools and
//! need their own discriminant enums.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use super::aliases::{AddressVisibility, AliasSourceKind};
use super::connection::{CapabilitiesV1, ConfigLayer, write_capabilities};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouteSourceKind {
    Static = 0,
    ConnectionContributed = 1,
    BrokerDelivered = 2,
    Alias = 3,
}

fn address_visibility_to_ffi(v: ovstorage::AddressVisibility) -> AddressVisibility {
    match v {
        ovstorage::AddressVisibility::Visible => AddressVisibility::Visible,
        ovstorage::AddressVisibility::Hidden => AddressVisibility::Hidden,
        ovstorage::AddressVisibility::Suppressed => AddressVisibility::Suppressed,
    }
}

fn config_layer_to_ffi(layer: &ovstorage::ConfigLayer) -> ConfigLayer {
    match layer {
        ovstorage::ConfigLayer::Programmatic => ConfigLayer::Programmatic,
        ovstorage::ConfigLayer::Env => ConfigLayer::Env,
        ovstorage::ConfigLayer::Project => ConfigLayer::Project,
        ovstorage::ConfigLayer::User => ConfigLayer::User,
        ovstorage::ConfigLayer::Machine => ConfigLayer::Machine,
    }
}

fn cstring_lossy(s: &str) -> CString {
    super::cstring_lossy(s)
}

// ---------------------------------------------------------------------
// AddressVisibilityOverride + list
// ---------------------------------------------------------------------

pub struct AddressVisibilityOverride {
    inner: ovstorage::AddressVisibilityOverride,
    address: CString,
}

impl AddressVisibilityOverride {
    pub(crate) fn from_override(o: ovstorage::AddressVisibilityOverride) -> Self {
        let address = cstring_lossy(o.address.as_str());
        Self { inner: o, address }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_destroy(
    o: *mut AddressVisibilityOverride,
) {
    unsafe {
        if o.is_null() {
            return;
        }
        drop(Box::from_raw(o));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_address(
    o: *const AddressVisibilityOverride,
) -> *const c_char {
    if o.is_null() {
        return ptr::null();
    }
    unsafe { (*o).address.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_visibility(
    o: *const AddressVisibilityOverride,
) -> AddressVisibility {
    if o.is_null() {
        return AddressVisibility::Visible;
    }
    unsafe { address_visibility_to_ffi((*o).inner.visibility) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_persisted(
    o: *const AddressVisibilityOverride,
) -> bool {
    if o.is_null() {
        return false;
    }
    unsafe { (*o).inner.persisted }
}

pub struct AddressVisibilityOverrideList {
    pub(crate) items: Vec<AddressVisibilityOverride>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_list_destroy(
    list: *mut AddressVisibilityOverrideList,
) {
    unsafe {
        if list.is_null() {
            return;
        }
        drop(Box::from_raw(list));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_list_len(
    list: *const AddressVisibilityOverrideList,
) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).items.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_visibility_override_list_item_at(
    list: *const AddressVisibilityOverrideList,
    index: usize,
) -> *const AddressVisibilityOverride {
    if list.is_null() {
        return ptr::null();
    }
    unsafe {
        let l = &*list;
        l.items
            .get(index)
            .map_or(ptr::null(), |o| o as *const AddressVisibilityOverride)
    }
}

// ---------------------------------------------------------------------
// AddressRoot + list
// ---------------------------------------------------------------------

pub struct AddressRoot {
    inner: ovstorage::AddressRoot,
    address: CString,
    backend_kind: CString,
    display_name: CString,
    connection_id: Option<CString>,
    user_metadata: Vec<(CString, CString)>,
    source_connection_id: Option<CString>,
    source_broker_principal: Option<CString>,
    source_alias_to: Option<CString>,
    source_alias_broker_principal: Option<CString>,
}

impl AddressRoot {
    pub(crate) fn from_root(root: ovstorage::AddressRoot) -> Self {
        let address = cstring_lossy(root.address.as_str());
        let backend_kind = cstring_lossy(&root.backend_kind);
        let display_name = root
            .display_name
            .as_deref()
            .map(cstring_lossy)
            .unwrap_or_default();
        let connection_id = root.connection_id.as_ref().map(|id| cstring_lossy(&id.0));
        let user_metadata = root
            .user_metadata
            .iter()
            .map(|(k, v)| (cstring_lossy(k), cstring_lossy(v)))
            .collect();
        let mut source_connection_id = None;
        let mut source_broker_principal = None;
        let mut source_alias_to = None;
        let mut source_alias_broker_principal = None;
        match &root.source {
            ovstorage::RouteSource::ConnectionContributed { connection_id } => {
                source_connection_id = Some(cstring_lossy(&connection_id.0));
            }
            ovstorage::RouteSource::BrokerDelivered {
                broker_principal,
                connection_id,
            } => {
                source_connection_id = Some(cstring_lossy(&connection_id.0));
                source_broker_principal = Some(cstring_lossy(broker_principal));
            }
            ovstorage::RouteSource::Alias { to, alias_source } => {
                source_alias_to = Some(cstring_lossy(to.as_str()));
                if let ovstorage::AliasSource::BrokerDelivered { broker_principal } = alias_source {
                    source_alias_broker_principal = Some(cstring_lossy(broker_principal));
                }
            }
            _ => {}
        }
        Self {
            inner: root,
            address,
            backend_kind,
            display_name,
            connection_id,
            user_metadata,
            source_connection_id,
            source_broker_principal,
            source_alias_to,
            source_alias_broker_principal,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_destroy(root: *mut AddressRoot) {
    unsafe {
        if root.is_null() {
            return;
        }
        drop(Box::from_raw(root));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_address(root: *const AddressRoot) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe { (*root).address.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_backend_kind(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe { (*root).backend_kind.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_display_name(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe { (*root).display_name.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_has_connection_id(
    root: *const AddressRoot,
) -> bool {
    if root.is_null() {
        return false;
    }
    unsafe { (*root).connection_id.is_some() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_connection_id(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        (*root)
            .connection_id
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_visibility(
    root: *const AddressRoot,
) -> AddressVisibility {
    if root.is_null() {
        return AddressVisibility::Visible;
    }
    unsafe { address_visibility_to_ffi((*root).inner.visibility) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_capabilities(
    root: *const AddressRoot,
    out: *mut CapabilitiesV1,
) {
    if root.is_null() {
        return;
    }
    unsafe { write_capabilities(&(*root).inner.capabilities, out) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_kind(
    root: *const AddressRoot,
) -> RouteSourceKind {
    if root.is_null() {
        return RouteSourceKind::Static;
    }
    unsafe {
        match &(*root).inner.source {
            ovstorage::RouteSource::Static { .. } => RouteSourceKind::Static,
            ovstorage::RouteSource::ConnectionContributed { .. } => {
                RouteSourceKind::ConnectionContributed
            }
            ovstorage::RouteSource::BrokerDelivered { .. } => RouteSourceKind::BrokerDelivered,
            ovstorage::RouteSource::Alias { .. } => RouteSourceKind::Alias,
        }
    }
}

/// Returns the alias `to` URL for the Alias variant. Null otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_alias_to(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        (*root)
            .source_alias_to
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

/// Returns the alias-source kind for the Alias variant. Returns
/// `Runtime` for any other parent variant (safe default).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_alias_source_kind(
    root: *const AddressRoot,
) -> AliasSourceKind {
    if root.is_null() {
        return AliasSourceKind::Runtime;
    }
    unsafe {
        match &(*root).inner.source {
            ovstorage::RouteSource::Alias { alias_source, .. } => match alias_source {
                ovstorage::AliasSource::Static { .. } => AliasSourceKind::Static,
                ovstorage::AliasSource::Runtime { .. } => AliasSourceKind::Runtime,
                ovstorage::AliasSource::BrokerDelivered { .. } => AliasSourceKind::BrokerDelivered,
            },
            _ => AliasSourceKind::Runtime,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_alias_source_static_layer(
    root: *const AddressRoot,
) -> ConfigLayer {
    if root.is_null() {
        return ConfigLayer::Programmatic;
    }
    unsafe {
        match &(*root).inner.source {
            ovstorage::RouteSource::Alias {
                alias_source: ovstorage::AliasSource::Static { layer },
                ..
            } => config_layer_to_ffi(layer),
            _ => ConfigLayer::Programmatic,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_alias_source_runtime_persisted(
    root: *const AddressRoot,
) -> bool {
    if root.is_null() {
        return false;
    }
    unsafe {
        match &(*root).inner.source {
            ovstorage::RouteSource::Alias {
                alias_source: ovstorage::AliasSource::Runtime { persisted },
                ..
            } => *persisted,
            _ => false,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_alias_source_broker_principal(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        (*root)
            .source_alias_broker_principal
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_static_layer(
    root: *const AddressRoot,
) -> ConfigLayer {
    if root.is_null() {
        return ConfigLayer::Programmatic;
    }
    unsafe {
        match &(*root).inner.source {
            ovstorage::RouteSource::Static { layer } => config_layer_to_ffi(layer),
            _ => ConfigLayer::Programmatic,
        }
    }
}

/// Returns the connection_id for the ConnectionContributed and
/// BrokerDelivered variants. Returns null otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_connection_id(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        (*root)
            .source_connection_id
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_source_broker_principal(
    root: *const AddressRoot,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        (*root)
            .source_broker_principal
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_user_metadata_count(
    root: *const AddressRoot,
) -> usize {
    if root.is_null() {
        return 0;
    }
    unsafe { (*root).user_metadata.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_user_metadata_key(
    root: *const AddressRoot,
    index: usize,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        let r = &*root;
        r.user_metadata
            .get(index)
            .map_or(ptr::null(), |(k, _)| k.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_user_metadata_value(
    root: *const AddressRoot,
    index: usize,
) -> *const c_char {
    if root.is_null() {
        return ptr::null();
    }
    unsafe {
        let r = &*root;
        r.user_metadata
            .get(index)
            .map_or(ptr::null(), |(_, v)| v.as_ptr())
    }
}

pub struct AddressRootList {
    pub(crate) items: Vec<AddressRoot>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_list_destroy(list: *mut AddressRootList) {
    unsafe {
        if list.is_null() {
            return;
        }
        drop(Box::from_raw(list));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_list_len(list: *const AddressRootList) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).items.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_address_root_list_item_at(
    list: *const AddressRootList,
    index: usize,
) -> *const AddressRoot {
    if list.is_null() {
        return ptr::null();
    }
    unsafe {
        let l = &*list;
        l.items
            .get(index)
            .map_or(ptr::null(), |r| r as *const AddressRoot)
    }
}

// ---------------------------------------------------------------------
// BackendKindDescriptor + list
// ---------------------------------------------------------------------

pub struct BackendKindDescriptor {
    inner: ovstorage::StorageBackendKindDescriptor,
    kind: CString,
    display_name: CString,
    description: Option<CString>,
}

impl BackendKindDescriptor {
    pub(crate) fn from_descriptor(d: ovstorage::StorageBackendKindDescriptor) -> Self {
        let kind = cstring_lossy(&d.kind);
        let display_name = cstring_lossy(&d.display_name);
        let description = d.description.as_deref().map(cstring_lossy);
        Self {
            inner: d,
            kind,
            display_name,
            description,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_destroy(d: *mut BackendKindDescriptor) {
    unsafe {
        if d.is_null() {
            return;
        }
        drop(Box::from_raw(d));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_kind(
    d: *const BackendKindDescriptor,
) -> *const c_char {
    if d.is_null() {
        return ptr::null();
    }
    unsafe { (*d).kind.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_display_name(
    d: *const BackendKindDescriptor,
) -> *const c_char {
    if d.is_null() {
        return ptr::null();
    }
    unsafe { (*d).display_name.as_ptr() }
}

/// Returns null if the descriptor has no `description` set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_description(
    d: *const BackendKindDescriptor,
) -> *const c_char {
    if d.is_null() {
        return ptr::null();
    }
    unsafe {
        (*d).description
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_supports_runtime_add(
    d: *const BackendKindDescriptor,
) -> bool {
    if d.is_null() {
        return false;
    }
    unsafe { (*d).inner.supports_runtime_add }
}

/// Returns the icon byte length, or 0 if no icon is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_icon_len(
    d: *const BackendKindDescriptor,
) -> usize {
    if d.is_null() {
        return 0;
    }
    unsafe { (*d).inner.icon.as_ref().map_or(0, |bytes| bytes.len()) }
}

/// Returns a borrowed pointer to the icon bytes, valid while the
/// descriptor handle lives. Returns null if no icon is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_icon_data(
    d: *const BackendKindDescriptor,
) -> *const u8 {
    if d.is_null() {
        return ptr::null();
    }
    unsafe {
        (*d).inner
            .icon
            .as_ref()
            .map_or(ptr::null(), |bytes| bytes.as_ptr())
    }
}

pub struct BackendKindDescriptorList {
    pub(crate) items: Vec<BackendKindDescriptor>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_list_destroy(
    list: *mut BackendKindDescriptorList,
) {
    unsafe {
        if list.is_null() {
            return;
        }
        drop(Box::from_raw(list));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_list_len(
    list: *const BackendKindDescriptorList,
) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).items.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_backend_kind_descriptor_list_item_at(
    list: *const BackendKindDescriptorList,
    index: usize,
) -> *const BackendKindDescriptor {
    if list.is_null() {
        return ptr::null();
    }
    unsafe {
        let l = &*list;
        l.items
            .get(index)
            .map_or(ptr::null(), |d| d as *const BackendKindDescriptor)
    }
}
