// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `LoadedAuthzPlugin`: dlopen wrapper driving a cdylib authz plugin.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ovstorage_plugin::ffi as plugin_ffi;
use ovstorage_plugin::{Error, ErrorCode, PluginManifest, Result, Url};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::ffi as authz_ffi;
use crate::shim;
use crate::thunks::{
    AuthzPluginHandle, Outcome, StatusOutcome, from_status_user_data, from_user_data,
    into_status_user_data, into_user_data, outcome_into_result, status_into_result,
};
use crate::{AuthzDecision, AuthzPlugin, AuthzRequest};

// Filename-disjoint from backend cdylibs (`libovstorage_plugin_*`) so
// neither loader has to filter manifests at scan time.
const AUTHZ_PLUGIN_FILE_PREFIX: &str = "libovstorage_authz_";
const AUTHZ_PLUGIN_FILE_PREFIX_DLL: &str = "ovstorage_authz_";

/// Init function signature for authz plugins.
pub type AuthzPluginInitV1 = unsafe extern "C" fn() -> authz_ffi::AuthzPluginInitResultV1;

/// Validate an authz plugin's init-result header against the host's
/// authz ABI version (separate from the storage SPI's).
pub fn validate_authz_init_result_header(
    actual_struct_size: usize,
    expected_struct_size: usize,
    abi_version: u32,
    vtable_ptr: *const core::ffi::c_void,
) -> Result<()> {
    if actual_struct_size < expected_struct_size {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "authz plugin init result struct_size is too small",
        ));
    }
    let host_abi = authz_ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION;
    if abi_version != host_abi {
        return Err(Error::new(
            ErrorCode::IncompatibleType,
            format!("authz plugin advertises ABI {abi_version} but host runs authz ABI {host_abi}"),
        ));
    }
    if vtable_ptr.is_null() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "authz plugin init returned a null vtable",
        ));
    }
    Ok(())
}

/// Loaded authz plugin; dispatches `AuthzPlugin` calls through the
/// cdylib's vtable + oneshot bridge.
pub struct LoadedAuthzPlugin {
    handle: Arc<AuthzPluginHandle>,
    manifest: PluginManifest,
}

impl LoadedAuthzPlugin {
    /// # Safety
    ///
    /// `dlopen` runs platform loader hooks in the current process.
    /// Callers must load only trusted plugin binaries.
    pub unsafe fn open(path: impl AsRef<Path>) -> Result<Self> {
        unsafe {
            let path = path.as_ref();
            let library = libloading::Library::new(path).map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("failed to load authz plugin library: {error}"),
                )
            })?;
            let library = Arc::new(library);

            let manifest = {
                let manifest_symbol: libloading::Symbol<*const ovstorage_plugin::PluginManifestV1> =
                    library
                        .get(b"ovstorage_authz_plugin_manifest_v1\0")
                        .map_err(|error| {
                            Error::new(
                                ErrorCode::InvalidArgument,
                                format!("authz plugin manifest symbol is missing: {error}"),
                            )
                        })?;
                PluginManifest::from_raw(*manifest_symbol)?
            };

            let init_result: authz_ffi::AuthzPluginInitResultV1 = {
                let init_symbol: libloading::Symbol<AuthzPluginInitV1> = library
                    .get(b"ovstorage_authz_plugin_init_v1\0")
                    .map_err(|error| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            format!("authz plugin init symbol is missing: {error}"),
                        )
                    })?;
                init_symbol()
            };
            validate_authz_init_result_header(
                init_result.struct_size,
                std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
                init_result.abi_version,
                init_result.vtable as *const core::ffi::c_void,
            )?;

            let vtable = init_result.vtable;
            if (*vtable).struct_size < std::mem::size_of::<authz_ffi::AuthzPluginVTableV1>() {
                return Err(Error::new(
                    ErrorCode::IncompatibleType,
                    "authz plugin vtable struct_size is too small",
                ));
            }

            Ok(Self {
                handle: Arc::new(AuthzPluginHandle {
                    plugin_state: init_result.plugin_state,
                    vtable,
                    _library: library,
                }),
                manifest,
            })
        }
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    /// Apply the host's parsed `[authz]` config; call once after `open`
    /// and before any `authorize`.
    pub async fn configure(
        &self,
        config: HashMap<String, ovstorage_plugin::ConfigValue>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let handle = self.handle.clone();
        let (tx, rx) = oneshot::channel();
        // Cancel handle must outlive the vtable call; dropped after the oneshot fires.
        let cancel_handle = cancel.map(plugin_ffi::cancel_token_to_ffi);
        let cancel_ptr = cancel_handle
            .as_ref()
            .map_or(std::ptr::null(), |h| h.as_ffi_ptr());
        {
            let config_ffi = shim::config_to_ffi(config);
            let user_data = into_status_user_data(tx);
            // SAFETY: vtable.configure is valid for the lifetime of `handle`;
            // `user_data` is heap-owned here and reclaimed in the callback.
            unsafe {
                ((*handle.vtable).configure)(
                    handle.plugin_state,
                    &config_ffi,
                    cancel_ptr,
                    configure_callback,
                    user_data,
                );
            }
            std::mem::forget(config_ffi);
        }
        let outcome = rx.await.map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "authz plugin configure callback never fired",
            )
        })?;
        drop(cancel_handle);
        // SAFETY: outcome carries plugin-allocated FFI pointers.
        unsafe { status_into_result(outcome) }
    }
}

extern "C" fn configure_callback(
    status: i32,
    error: *mut plugin_ffi::Error,
    user_data: *mut core::ffi::c_void,
) {
    // SAFETY: user_data was Box::into_raw'd as a oneshot::Sender<StatusOutcome>.
    let tx = unsafe { from_status_user_data(user_data) };
    let _ = tx.send(StatusOutcome { status, error });
}

extern "C" fn authorize_callback(
    status: i32,
    result: *mut authz_ffi::AuthzDecisionV1,
    error: *mut plugin_ffi::Error,
    user_data: *mut core::ffi::c_void,
) {
    let tx = unsafe { from_user_data::<authz_ffi::AuthzDecisionV1>(user_data) };
    let _ = tx.send(Outcome {
        status,
        result,
        error,
    });
}

extern "C" fn filter_callback(
    status: i32,
    result: *mut plugin_ffi::List<authz_ffi::AuthzDecisionV1>,
    error: *mut plugin_ffi::Error,
    user_data: *mut core::ffi::c_void,
) {
    let tx = unsafe { from_user_data::<plugin_ffi::List<authz_ffi::AuthzDecisionV1>>(user_data) };
    let _ = tx.send(Outcome {
        status,
        result,
        error,
    });
}

#[async_trait::async_trait]
impl AuthzPlugin for LoadedAuthzPlugin {
    fn plugin_name(&self) -> &str {
        &self.manifest.name
    }

    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision> {
        let handle = self.handle.clone();
        let (tx, rx) = oneshot::channel::<Outcome<authz_ffi::AuthzDecisionV1>>();
        // `cancel` is null: the trait method takes no CancellationToken;
        // the host's outer timeout bounds a stuck plugin.
        {
            let request_ffi = shim::authz_request_to_ffi(request.clone());
            let user_data = into_user_data(tx);
            // SAFETY: vtable.authorize is valid for the lifetime of `handle`.
            unsafe {
                ((*handle.vtable).authorize)(
                    handle.plugin_state,
                    &request_ffi,
                    std::ptr::null(),
                    authorize_callback,
                    user_data,
                );
            }
            std::mem::forget(request_ffi);
        }
        let outcome = rx.await.map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "authz plugin authorize callback never fired",
            )
        })?;
        // SAFETY: outcome.result is a Box::into_raw'd AuthzDecisionV1.
        unsafe { outcome_into_result(outcome, |d| shim::authz_decision_from_ffi(d)) }
    }

    async fn filter_list_batch(
        &self,
        request: &AuthzRequest,
        addresses: &[Url],
    ) -> Result<Vec<AuthzDecision>> {
        let handle = self.handle.clone();
        let address_strings: Vec<String> = addresses.iter().map(|u| u.to_string()).collect();
        let (tx, rx) = oneshot::channel::<Outcome<plugin_ffi::List<authz_ffi::AuthzDecisionV1>>>();
        // `cancel` is null: same gap as `authorize`.
        {
            let request_ffi = shim::authz_request_to_ffi(request.clone());
            let address_list_ffi = ovstorage_plugin::shim::primitive::list_to_ffi(
                address_strings,
                ovstorage_plugin::shim::primitive::str_to_ffi,
            );
            let user_data = into_user_data(tx);
            // SAFETY: vtable.filter_list_batch is valid for the lifetime of `handle`.
            unsafe {
                ((*handle.vtable).filter_list_batch)(
                    handle.plugin_state,
                    &request_ffi,
                    &address_list_ffi,
                    std::ptr::null(),
                    filter_callback,
                    user_data,
                );
            }
            std::mem::forget(request_ffi);
            std::mem::forget(address_list_ffi);
        }
        let outcome = rx.await.map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "authz plugin filter_list_batch callback never fired",
            )
        })?;
        unsafe {
            outcome_into_result(outcome, |list| {
                let decisions = ovstorage_plugin::shim::primitive::list_from_ffi(list, |d| {
                    shim::authz_decision_from_ffi(d)
                })?;
                Ok(decisions)
            })
        }
    }
}

/// Resolve the authz plugin search dir: `OVSTORAGE_AUTHZ_PLUGIN_DIR`,
/// then `OVSTORAGE_PLUGIN_DIR`, then `<exe-dir>/plugins/`.
pub fn default_authz_plugin_dir() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTHZ_PLUGIN_DIR") {
        return Some(PathBuf::from(value));
    }
    if let Some(value) = std::env::var_os("OVSTORAGE_PLUGIN_DIR") {
        return Some(PathBuf::from(value));
    }
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;
    Some(parent.join("plugins"))
}

/// Filename test for an authz cdylib: `libovstorage_authz_*.so/dylib` or
/// `ovstorage_authz_*.dll`.
pub fn is_plugin_artifact(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let unix_ok = matches!(ext, "so" | "dylib") && stem.starts_with(AUTHZ_PLUGIN_FILE_PREFIX);
    let win_ok = ext == "dll" && stem.starts_with(AUTHZ_PLUGIN_FILE_PREFIX_DLL);
    unix_ok || win_ok
}

/// Scan `dir` for an authz plugin whose manifest reports
/// `name == kind`. Returns the first match.
///
/// # Safety
///
/// Loads each candidate cdylib via `dlopen`. Callers must trust the
/// directory contents.
pub unsafe fn load_authz_plugin_for_kind(dir: &Path, kind: &str) -> Result<LoadedAuthzPlugin> {
    let entries = std::fs::read_dir(dir).map_err(|err| {
        Error::new(
            ErrorCode::NotConfigured,
            format!(
                "authz plugin dir '{}' is not readable: {err}",
                dir.display()
            ),
        )
    })?;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if is_plugin_artifact(&path) {
            candidates.push(path);
        }
    }
    candidates.sort();
    // Filename filter already excluded backends; surface any open error
    // if no name match is found.
    let mut authz_errors: Vec<Error> = Vec::new();
    for path in &candidates {
        match unsafe { LoadedAuthzPlugin::open(path) } {
            Ok(plugin) => {
                if plugin.manifest().name == kind {
                    return Ok(plugin);
                }
            }
            Err(err) => {
                authz_errors.push(err);
            }
        }
    }
    if let Some(err) = authz_errors.into_iter().next() {
        return Err(err);
    }
    Err(Error::new(
        ErrorCode::NotConfigured,
        format!(
            "no authz plugin matching kind '{kind}' found in {}",
            dir.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_accepts_matching_authz_abi() {
        let dummy_vtable = std::ptr::NonNull::<core::ffi::c_void>::dangling().as_ptr();
        validate_authz_init_result_header(
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            authz_ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION,
            dummy_vtable,
        )
        .expect("matching ABI should validate");
    }

    #[test]
    fn validator_rejects_mismatched_authz_abi() {
        let dummy_vtable = std::ptr::NonNull::<core::ffi::c_void>::dangling().as_ptr();
        let wrong_abi = authz_ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION + 99;
        let err = validate_authz_init_result_header(
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            wrong_abi,
            dummy_vtable,
        )
        .expect_err("mismatched ABI should fail validation");
        assert_eq!(err.code(), ErrorCode::IncompatibleType);
        assert!(
            err.message().contains("authz plugin advertises ABI"),
            "expected authz-specific error message, got: {}",
            err.message()
        );
    }

    #[test]
    fn validator_rejects_struct_size_too_small() {
        let dummy_vtable = std::ptr::NonNull::<core::ffi::c_void>::dangling().as_ptr();
        let err = validate_authz_init_result_header(
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>() - 1,
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            authz_ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION,
            dummy_vtable,
        )
        .expect_err("too-small struct_size should fail validation");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn validator_rejects_null_vtable() {
        let err = validate_authz_init_result_header(
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            std::mem::size_of::<authz_ffi::AuthzPluginInitResultV1>(),
            authz_ffi::OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION,
            std::ptr::null(),
        )
        .expect_err("null vtable should fail validation");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
