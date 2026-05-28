// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Alias surface: builder + sync ops.
//!
//! `AliasRequest` is the opaque builder consumed by
//! `ovstorage_library_add_alias`. `Alias` is the read-side handle
//! returned by `add_alias` / `list_aliases`. `AliasList` is the
//! indexed-list handle returned by `list_aliases`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use super::{ConfigLayer, cstring_lossy};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressVisibility {
    Visible = 0,
    Hidden = 1,
    Suppressed = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AliasSourceKind {
    Static = 0,
    Runtime = 1,
    BrokerDelivered = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AliasStateKind {
    Live = 0,
    Dangling = 1,
    ChainTooLong = 2,
}

fn address_visibility_to_ffi(v: ovstorage::AddressVisibility) -> AddressVisibility {
    match v {
        ovstorage::AddressVisibility::Visible => AddressVisibility::Visible,
        ovstorage::AddressVisibility::Hidden => AddressVisibility::Hidden,
        ovstorage::AddressVisibility::Suppressed => AddressVisibility::Suppressed,
    }
}

fn address_visibility_from_ffi(v: AddressVisibility) -> ovstorage::AddressVisibility {
    match v {
        AddressVisibility::Visible => ovstorage::AddressVisibility::Visible,
        AddressVisibility::Hidden => ovstorage::AddressVisibility::Hidden,
        AddressVisibility::Suppressed => ovstorage::AddressVisibility::Suppressed,
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

// ---------------------------------------------------------------------
// AliasRequest builder
// ---------------------------------------------------------------------

/// Opaque alias-request builder. Built with
/// `ovstorage_alias_request_create(from, to)` and per-field setters;
/// consumed by `ovstorage_library_add_alias`. Ownership matches
/// `ConnectionRequest`: the caller's `*mut` is invalidated on success;
/// on a prologue error the caller still owns it (and must free with
/// `ovstorage_alias_request_destroy`).
pub struct AliasRequest {
    pub(crate) inner: Option<ovstorage::AliasRequest>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_create(
    from: *const c_char,
    to: *const c_char,
) -> *mut AliasRequest {
    unsafe {
        if from.is_null() || to.is_null() {
            return ptr::null_mut();
        }
        let Ok(from_str) = CStr::from_ptr(from).to_str() else {
            return ptr::null_mut();
        };
        let Ok(to_str) = CStr::from_ptr(to).to_str() else {
            return ptr::null_mut();
        };
        let Ok(from_url) = ovstorage::address::parse(from_str) else {
            return ptr::null_mut();
        };
        let Ok(to_url) = ovstorage::address::parse(to_str) else {
            return ptr::null_mut();
        };
        Box::into_raw(Box::new(AliasRequest {
            inner: Some(ovstorage::AliasRequest {
                from: from_url,
                to: to_url,
                visibility: ovstorage::AddressVisibility::Visible,
                persist: false,
                display_name: None,
                user_metadata: HashMap::new(),
            }),
        }))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_destroy(request: *mut AliasRequest) {
    unsafe {
        if request.is_null() {
            return;
        }
        drop(Box::from_raw(request));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_set_visibility(
    request: *mut AliasRequest,
    visibility: AddressVisibility,
) {
    unsafe {
        if request.is_null() {
            return;
        }
        if let Some(inner) = (*request).inner.as_mut() {
            inner.visibility = address_visibility_from_ffi(visibility);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_set_persist(
    request: *mut AliasRequest,
    persist: bool,
) {
    unsafe {
        if request.is_null() {
            return;
        }
        if let Some(inner) = (*request).inner.as_mut() {
            inner.persist = persist;
        }
    }
}

/// Set the request's display name. Pass `NULL` to clear.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_set_display_name(
    request: *mut AliasRequest,
    display_name: *const c_char,
) {
    unsafe {
        if request.is_null() {
            return;
        }
        let Some(inner) = (*request).inner.as_mut() else {
            return;
        };
        if display_name.is_null() {
            inner.display_name = None;
        } else if let Ok(s) = CStr::from_ptr(display_name).to_str() {
            inner.display_name = Some(s.to_string());
        }
    }
}

/// Add a user-metadata key/value pair to the request. Returns `true`
/// on success, `false` on null arg / non-UTF-8 / consumed-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_request_add_user_metadata(
    request: *mut AliasRequest,
    key: *const c_char,
    value: *const c_char,
) -> bool {
    unsafe {
        if request.is_null() || key.is_null() || value.is_null() {
            return false;
        }
        let Ok(key_str) = CStr::from_ptr(key).to_str() else {
            return false;
        };
        let Ok(value_str) = CStr::from_ptr(value).to_str() else {
            return false;
        };
        let Some(inner) = (*request).inner.as_mut() else {
            return false;
        };
        inner
            .user_metadata
            .insert(key_str.to_string(), value_str.to_string());
        true
    }
}

pub(crate) unsafe fn take_alias_request(ptr: *mut AliasRequest) -> Option<ovstorage::AliasRequest> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let mut handle = Box::from_raw(ptr);
        handle.inner.take()
    }
}

// ---------------------------------------------------------------------
// Alias (read-side opaque)
// ---------------------------------------------------------------------

pub struct Alias {
    inner: ovstorage::Alias,
    id: CString,
    from: CString,
    to: CString,
    display_name: CString,
    user_metadata: Vec<(CString, CString)>,
    source_broker_principal: Option<CString>,
    state_chain_too_long_reason: Option<CString>,
}

impl Alias {
    pub(crate) fn from_alias(alias: ovstorage::Alias) -> Self {
        let id = cstring_lossy(&alias.id.0);
        let from = cstring_lossy(alias.from.as_str());
        let to = cstring_lossy(alias.to.as_str());
        let display_name = alias
            .display_name
            .as_deref()
            .map(cstring_lossy)
            .unwrap_or_default();
        let user_metadata = alias
            .user_metadata
            .iter()
            .map(|(k, v)| (cstring_lossy(k), cstring_lossy(v)))
            .collect();
        let source_broker_principal = match &alias.source {
            ovstorage::AliasSource::BrokerDelivered { broker_principal } => {
                Some(cstring_lossy(broker_principal))
            }
            _ => None,
        };
        let state_chain_too_long_reason = match &alias.state {
            ovstorage::AliasState::ChainTooLong { reason } => Some(cstring_lossy(reason)),
            _ => None,
        };
        Self {
            inner: alias,
            id,
            from,
            to,
            display_name,
            user_metadata,
            source_broker_principal,
            state_chain_too_long_reason,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_destroy(alias: *mut Alias) {
    unsafe {
        if alias.is_null() {
            return;
        }
        drop(Box::from_raw(alias));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_id(alias: *const Alias) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe { (*alias).id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_from(alias: *const Alias) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe { (*alias).from.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_to(alias: *const Alias) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe { (*alias).to.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_visibility(alias: *const Alias) -> AddressVisibility {
    if alias.is_null() {
        return AddressVisibility::Visible;
    }
    unsafe { address_visibility_to_ffi((*alias).inner.visibility) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_display_name(alias: *const Alias) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe { (*alias).display_name.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_user_metadata_count(alias: *const Alias) -> usize {
    if alias.is_null() {
        return 0;
    }
    unsafe { (*alias).user_metadata.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_user_metadata_key(
    alias: *const Alias,
    index: usize,
) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe {
        let a = &*alias;
        a.user_metadata
            .get(index)
            .map_or(ptr::null(), |(k, _)| k.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_user_metadata_value(
    alias: *const Alias,
    index: usize,
) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe {
        let a = &*alias;
        a.user_metadata
            .get(index)
            .map_or(ptr::null(), |(_, v)| v.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_source_kind(alias: *const Alias) -> AliasSourceKind {
    if alias.is_null() {
        return AliasSourceKind::Runtime;
    }
    unsafe {
        match &(*alias).inner.source {
            ovstorage::AliasSource::Static { .. } => AliasSourceKind::Static,
            ovstorage::AliasSource::Runtime { .. } => AliasSourceKind::Runtime,
            ovstorage::AliasSource::BrokerDelivered { .. } => AliasSourceKind::BrokerDelivered,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_source_static_layer(alias: *const Alias) -> ConfigLayer {
    if alias.is_null() {
        return ConfigLayer::Programmatic;
    }
    unsafe {
        match &(*alias).inner.source {
            ovstorage::AliasSource::Static { layer } => config_layer_to_ffi(layer),
            _ => ConfigLayer::Programmatic,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_source_runtime_persisted(alias: *const Alias) -> bool {
    if alias.is_null() {
        return false;
    }
    unsafe {
        match &(*alias).inner.source {
            ovstorage::AliasSource::Runtime { persisted } => *persisted,
            _ => false,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_source_broker_principal(
    alias: *const Alias,
) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe {
        (*alias)
            .source_broker_principal
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_state_kind(alias: *const Alias) -> AliasStateKind {
    if alias.is_null() {
        return AliasStateKind::Live;
    }
    unsafe {
        match &(*alias).inner.state {
            ovstorage::AliasState::Live => AliasStateKind::Live,
            ovstorage::AliasState::Dangling => AliasStateKind::Dangling,
            ovstorage::AliasState::ChainTooLong { .. } => AliasStateKind::ChainTooLong,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_state_chain_too_long_reason(
    alias: *const Alias,
) -> *const c_char {
    if alias.is_null() {
        return ptr::null();
    }
    unsafe {
        (*alias)
            .state_chain_too_long_reason
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

// ---------------------------------------------------------------------
// AliasList (parallel to ConnectionList)
// ---------------------------------------------------------------------

pub struct AliasList {
    pub(crate) items: Vec<Alias>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_list_destroy(list: *mut AliasList) {
    unsafe {
        if list.is_null() {
            return;
        }
        drop(Box::from_raw(list));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_list_len(list: *const AliasList) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).items.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_alias_list_item_at(
    list: *const AliasList,
    index: usize,
) -> *const Alias {
    if list.is_null() {
        return ptr::null();
    }
    unsafe {
        let l = &*list;
        l.items
            .get(index)
            .map_or(ptr::null(), |a| a as *const Alias)
    }
}

// ---------------------------------------------------------------------
