// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C-ABI exports for the cdylib facet.
//!
//! Drop drains in-flight tasks up to `DROP_DRAIN_TIMEOUT` so callbacks
//! never observe a torn-down runtime / plugin slot.

use std::ffi::c_char;
use std::os::raw::c_void;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ovstorage_authz::AuthzPlugin;
use ovstorage_authz::ffi as authz_ffi;
use ovstorage_authz::ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION;
use ovstorage_authz::shim as authz_shim;
use ovstorage_plugin::ffi as plugin_ffi;
use ovstorage_plugin::shim as plugin_shim;
use ovstorage_plugin::shim::primitive;
use ovstorage_plugin::{Error, ErrorCode, OVSTORAGE_PLUGIN_ABI_VERSION, PluginManifestV1, address};

struct StatusCb {
    on_complete: authz_ffi::AuthzConfigureCallback,
    user_data: usize,
}

struct DecisionCb {
    on_complete: authz_ffi::AuthzAuthorizeCallback,
    user_data: usize,
}

struct FilterCb {
    on_complete: authz_ffi::AuthzFilterCallback,
    user_data: usize,
}

use crate::TomlAuthzPlugin;

const PLUGIN_NAME: &[u8] = b"ovstorage-authz-toml\0";
const PLUGIN_VERSION: &[u8] = b"0.1.0\0";
const DROP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[unsafe(no_mangle)]
pub static ovstorage_authz_plugin_manifest_v1: PluginManifestV1 = PluginManifestV1 {
    struct_size: std::mem::size_of::<PluginManifestV1>(),
    abi_version: OVSTORAGE_PLUGIN_ABI_VERSION,
    name: PLUGIN_NAME.as_ptr() as *const c_char,
    version: PLUGIN_VERSION.as_ptr() as *const c_char,
    test_only: false,
};

struct InFlightTracker {
    count: Mutex<usize>,
    condvar: Condvar,
}

impl InFlightTracker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: Mutex::new(0),
            condvar: Condvar::new(),
        })
    }

    fn enter(self: &Arc<Self>) -> InFlightGuard {
        *self.count.lock().unwrap() += 1;
        InFlightGuard {
            tracker: self.clone(),
        }
    }

    fn drain(&self, timeout: Duration) -> bool {
        let mut guard = self.count.lock().unwrap();
        let deadline = std::time::Instant::now() + timeout;
        while *guard > 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, wait) = self.condvar.wait_timeout(guard, deadline - now).unwrap();
            guard = next;
            if wait.timed_out() && *guard > 0 {
                return false;
            }
        }
        true
    }
}

struct InFlightGuard {
    tracker: Arc<InFlightTracker>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut count = self.tracker.count.lock().unwrap();
        *count -= 1;
        if *count == 0 {
            self.tracker.condvar.notify_all();
        }
    }
}

struct PluginState {
    plugin: Arc<Mutex<Option<TomlAuthzPlugin>>>,
    runtime: tokio::runtime::Runtime,
    in_flight: Arc<InFlightTracker>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_authz_plugin_init_v1() -> authz_ffi::AuthzPluginInitResultV1 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            return authz_ffi::AuthzPluginInitResultV1 {
                struct_size: std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
                abi_version: OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION,
                plugin_state: std::ptr::null_mut(),
                vtable: std::ptr::null(),
            };
        }
    };
    let state = Box::new(PluginState {
        plugin: Arc::new(Mutex::new(None)),
        runtime,
        in_flight: InFlightTracker::new(),
    });
    authz_ffi::AuthzPluginInitResultV1 {
        struct_size: std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
        abi_version: OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION,
        plugin_state: Box::into_raw(state) as *mut c_void,
        vtable: &VTABLE,
    }
}

unsafe extern "C" fn drop_plugin(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    // SAFETY: state was Box::into_raw'd by `ovstorage_authz_plugin_init_v1`.
    let boxed = unsafe { Box::from_raw(state as *mut PluginState) };
    let _ = boxed.in_flight.drain(DROP_DRAIN_TIMEOUT);
    drop(boxed);
}

fn cancel_is_signalled(cancel: *const plugin_ffi::CancelTokenFFI) -> bool {
    if cancel.is_null() {
        return false;
    }
    // SAFETY: caller contract — `cancel` is a borrowed valid pointer when non-null.
    let token = unsafe { &*cancel };
    if token.state.is_null() {
        return false;
    }
    (token.is_canceled)(token.state)
}

unsafe extern "C" fn configure_thunk(
    state_ptr: *mut c_void,
    config: *const plugin_ffi::List<plugin_ffi::ConnectionConfigEntry>,
    cancel: *const plugin_ffi::CancelTokenFFI,
    on_complete: authz_ffi::AuthzConfigureCallback,
    user_data: *mut c_void,
) {
    let state = unsafe { &*(state_ptr as *const PluginState) };
    let cb = StatusCb {
        on_complete,
        user_data: user_data as usize,
    };
    if cancel_is_signalled(cancel) {
        complete_status_cancelled(cb);
        return;
    }
    let plugin_slot = state.plugin.clone();
    let config_owned = unsafe { std::ptr::read(config) };
    let parse_result = unsafe { authz_shim::config_from_ffi(config_owned) };
    let guard = state.in_flight.enter();

    state.runtime.spawn(async move {
        let _guard = guard;
        let result = configure_inner(plugin_slot, parse_result);
        complete_status(cb, result);
    });
}

fn configure_inner(
    plugin_slot: Arc<Mutex<Option<TomlAuthzPlugin>>>,
    parse_result: Result<std::collections::HashMap<String, ovstorage_plugin::ConfigValue>, Error>,
) -> Result<(), Error> {
    let config_map = parse_result?;
    let mut policy_toml = String::new();
    let mut decision_ttl_max_seconds: Option<u64> = None;
    for (key, value) in config_map {
        match key.as_str() {
            "policy" => match value {
                ovstorage_plugin::ConfigValue::Toml(t) => {
                    policy_toml = t;
                }
                ovstorage_plugin::ConfigValue::String(s) => {
                    policy_toml = s;
                }
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "authz-toml: 'policy' must be a TOML table or array",
                    ));
                }
            },
            "decision_ttl_max_seconds" => match value {
                ovstorage_plugin::ConfigValue::Int(n) => {
                    let ttl = u64::try_from(n).map_err(|_| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            "authz-toml: decision_ttl_max_seconds must be non-negative",
                        )
                    })?;
                    decision_ttl_max_seconds = Some(ttl);
                }
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "authz-toml: decision_ttl_max_seconds must be an integer",
                    ));
                }
            },
            "plugin" => {}
            _ => {
                tracing::debug!(
                    target: "ovstorage::authz-toml",
                    "ignoring unknown config key '{key}'"
                );
            }
        }
    }

    let mut config = if policy_toml.is_empty() {
        crate::TomlAuthzConfig::default()
    } else {
        #[derive(serde::Deserialize)]
        struct PolicyWrapper {
            #[serde(default)]
            policy: Vec<crate::TomlAuthzPolicy>,
        }
        let parsed: PolicyWrapper = toml::from_str(&policy_toml).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("authz-toml: failed to parse policy TOML: {err}"),
            )
        })?;
        crate::TomlAuthzConfig {
            plugin: crate::PLUGIN_NAME.into(),
            decision_ttl_max_seconds: None,
            policy: parsed.policy,
        }
    };
    config.decision_ttl_max_seconds = decision_ttl_max_seconds;

    let plugin = TomlAuthzPlugin::from_config(config)?;
    *plugin_slot.lock().unwrap() = Some(plugin);
    Ok(())
}

fn complete_status(cb: StatusCb, result: Result<(), Error>) {
    match result {
        Ok(()) => (cb.on_complete)(0, std::ptr::null_mut(), cb.user_data as *mut c_void),
        Err(err) => {
            let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
            (cb.on_complete)(1, e, cb.user_data as *mut c_void);
        }
    }
}

fn complete_status_cancelled(cb: StatusCb) {
    let err = Error::new(ErrorCode::Cancelled, "authz-toml: cancelled by host");
    let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
    (cb.on_complete)(1, e, cb.user_data as *mut c_void);
}

unsafe extern "C" fn authorize_thunk(
    state_ptr: *mut c_void,
    request: *const authz_ffi::AuthzRequestV1,
    cancel: *const plugin_ffi::CancelTokenFFI,
    on_complete: authz_ffi::AuthzAuthorizeCallback,
    user_data: *mut c_void,
) {
    let state = unsafe { &*(state_ptr as *const PluginState) };
    let cb = DecisionCb {
        on_complete,
        user_data: user_data as usize,
    };
    if cancel_is_signalled(cancel) {
        complete_decision_cancelled(cb);
        return;
    }
    let plugin_slot = state.plugin.clone();
    let request_owned = unsafe { std::ptr::read(request) };
    let request_result = unsafe { authz_shim::authz_request_from_ffi(request_owned) };
    let guard = state.in_flight.enter();

    state.runtime.spawn(async move {
        let _guard = guard;
        let result: Result<_, Error> = async {
            let request_rust = request_result?;
            let plugin_opt = plugin_slot.lock().unwrap().clone();
            let plugin = plugin_opt.ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "authz-toml: plugin not configured (call configure first)",
                )
            })?;
            plugin.authorize(&request_rust).await
        }
        .await;
        complete_decision(cb, result);
    });
}

fn complete_decision(cb: DecisionCb, result: Result<ovstorage_authz::AuthzDecision, Error>) {
    match result {
        Ok(decision) => {
            let ffi_decision = authz_shim::authz_decision_to_ffi(decision);
            let boxed = Box::into_raw(Box::new(ffi_decision));
            (cb.on_complete)(0, boxed, std::ptr::null_mut(), cb.user_data as *mut c_void);
        }
        Err(err) => {
            let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
            (cb.on_complete)(1, std::ptr::null_mut(), e, cb.user_data as *mut c_void);
        }
    }
}

fn complete_decision_cancelled(cb: DecisionCb) {
    let err = Error::new(ErrorCode::Cancelled, "authz-toml: cancelled by host");
    let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
    (cb.on_complete)(1, std::ptr::null_mut(), e, cb.user_data as *mut c_void);
}

unsafe extern "C" fn filter_list_batch_thunk(
    state_ptr: *mut c_void,
    request: *const authz_ffi::AuthzRequestV1,
    addresses: *const plugin_ffi::List<plugin_ffi::Str>,
    cancel: *const plugin_ffi::CancelTokenFFI,
    on_complete: authz_ffi::AuthzFilterCallback,
    user_data: *mut c_void,
) {
    let state = unsafe { &*(state_ptr as *const PluginState) };
    let cb = FilterCb {
        on_complete,
        user_data: user_data as usize,
    };
    if cancel_is_signalled(cancel) {
        complete_filter_cancelled(cb);
        return;
    }
    let plugin_slot = state.plugin.clone();
    let request_owned = unsafe { std::ptr::read(request) };
    let addresses_owned = unsafe { std::ptr::read(addresses) };
    let pre_marshal: Result<_, Error> = (|| {
        let request_rust = unsafe { authz_shim::authz_request_from_ffi(request_owned)? };
        let address_strings =
            unsafe { primitive::list_from_ffi(addresses_owned, |s| primitive::str_from_ffi(s))? };
        let urls: Result<Vec<_>, Error> =
            address_strings.iter().map(|s| address::parse(s)).collect();
        Ok((request_rust, urls?))
    })();
    let guard = state.in_flight.enter();

    state.runtime.spawn(async move {
        let _guard = guard;
        let result: Result<_, Error> = async {
            let (request_rust, urls) = pre_marshal?;
            let plugin_opt = plugin_slot.lock().unwrap().clone();
            let plugin = plugin_opt.ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "authz-toml: plugin not configured (call configure first)",
                )
            })?;
            plugin.filter_list_batch(&request_rust, &urls).await
        }
        .await;
        complete_filter(cb, result);
    });
}

fn complete_filter(cb: FilterCb, result: Result<Vec<ovstorage_authz::AuthzDecision>, Error>) {
    match result {
        Ok(decisions) => {
            let ffi_list = primitive::list_to_ffi(decisions, authz_shim::authz_decision_to_ffi);
            let boxed = Box::into_raw(Box::new(ffi_list));
            (cb.on_complete)(0, boxed, std::ptr::null_mut(), cb.user_data as *mut c_void);
        }
        Err(err) => {
            let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
            (cb.on_complete)(1, std::ptr::null_mut(), e, cb.user_data as *mut c_void);
        }
    }
}

fn complete_filter_cancelled(cb: FilterCb) {
    let err = Error::new(ErrorCode::Cancelled, "authz-toml: cancelled by host");
    let e = Box::into_raw(Box::new(plugin_shim::error::to_ffi(&err)));
    (cb.on_complete)(1, std::ptr::null_mut(), e, cb.user_data as *mut c_void);
}

static VTABLE: authz_ffi::AuthzPluginVTableV1 = authz_ffi::AuthzPluginVTableV1 {
    struct_size: std::mem::size_of::<authz_ffi::AuthzPluginVTableV1>(),
    drop: drop_plugin,
    configure: configure_thunk,
    authorize: authorize_thunk,
    filter_list_batch: filter_list_batch_thunk,
};
