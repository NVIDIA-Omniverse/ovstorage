// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared FFI mirrors and a dlopen loader for the capi integration
//! tests. The cdylib has `crate-type = ["cdylib"]` (no rlib), so the
//! tests call the C ABI via libloading. `build.rs` exports the cdylib
//! path as `OVSTORAGE_CAPI_SO`.
//!
//! `cargo test` compiles `crate-type = ["cdylib"]` libraries as test
//! binaries but does not emit the standalone cdylib output, so
//! `Loader::load` checks the env-pointed path and falls back to
//! `cargo build --package ovstorage-capi --lib` when the artifact is
//! missing. Cargo's workspace lock is released by the time the test
//! binary runs, so the nested invocation is safe.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    AlreadyExists = 2,
    PermissionDenied = 3,
    PreconditionFailed = 4,
    Conflict = 5,
    DirectoryNotEmpty = 6,
    Unsupported = 7,
    InvalidArgument = 8,
    ObjectModified = 9,
    NoRoute = 10,
    Transient = 11,
    Cancelled = 12,
    Internal = 255,
}

#[repr(C)]
pub struct Error {
    pub code: Status,
    pub message: *mut c_char,
}

impl Default for Error {
    fn default() -> Self {
        Self {
            code: Status::Ok,
            message: ptr::null_mut(),
        }
    }
}

pub type ReservedOptionsPadding = [*const c_void; 8];
pub const RESERVED_PADDING_ZERO: ReservedOptionsPadding = [ptr::null(); 8];

// Layout-compatible with the real `OvCredentialCallback`. The real
// struct holds `Option<unsafe extern "C" fn(...)>` fields; null
// function pointers and null `*const c_void` have identical ABI
// representation, and these tests only ever pass the all-null default.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OvCredentialCallback {
    pub resolve: *const c_void,
    pub free_userdata: *const c_void,
    pub userdata: *mut c_void,
}

impl Default for OvCredentialCallback {
    fn default() -> Self {
        Self {
            resolve: ptr::null(),
            free_userdata: ptr::null(),
            userdata: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct InitAuthSubstrateOptionsV1 {
    pub struct_size: usize,
    pub auth_dir: *const c_char,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct LibraryInitOptionsV1 {
    pub struct_size: usize,
    pub runtime_threads: u32,
    pub interactive_auth_capability: i32,
    pub credential_cache_durability: i32,
    pub has_credential_callback: bool,
    pub credential_callback: OvCredentialCallback,
    pub credential_callback_name: *const c_char,
    pub allow_test_plugins: bool,
    pub _reserved: ReservedOptionsPadding,
}

// Opaque handle types — the C ABI never lets us dereference them.
pub enum Library {}
pub enum Info {}
pub enum Connection {}
pub enum ConnectionRequest {}
pub enum ConfigValue {}

pub type StatusCallback =
    Option<unsafe extern "C" fn(status: Status, error: *const Error, user_data: *mut c_void)>;

pub type InfoCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        info: *mut Info,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ConnectionCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        connection: *mut Connection,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

// Resolved fn pointers cloned out of libloading Symbols. The Symbols
// borrow from the underlying Library, so the Library is kept alive in
// `_lib` while these copies are usable.
pub struct Loader {
    _lib: libloading::Library,
    pub ovstorage_error_clear: unsafe extern "C" fn(*mut Error),
    pub ovstorage_init_auth_substrate:
        unsafe extern "C" fn(*const InitAuthSubstrateOptionsV1, *mut Error) -> Status,
    pub ovstorage_library_init:
        unsafe extern "C" fn(*const LibraryInitOptionsV1, *mut *mut Library, *mut Error) -> Status,
    pub ovstorage_library_shutdown: unsafe extern "C" fn(*mut Library),
    pub ovstorage_library_load_plugins_from_dir:
        unsafe extern "C" fn(*mut Library, *const c_char, StatusCallback, *mut c_void),
    pub ovstorage_library_add_connection: unsafe extern "C" fn(
        *mut Library,
        *mut ConnectionRequest,
        *const c_void,
        ConnectionCallback,
        *mut c_void,
    ),
    pub ovstorage_connection_destroy: unsafe extern "C" fn(*mut Connection),
    pub ovstorage_connection_request_create:
        unsafe extern "C" fn(*const c_char) -> *mut ConnectionRequest,
    pub ovstorage_connection_request_add_config:
        unsafe extern "C" fn(*mut ConnectionRequest, *const c_char, *mut ConfigValue) -> bool,
    pub ovstorage_connection_request_set_persist:
        unsafe extern "C" fn(*mut ConnectionRequest, bool),
    pub ovstorage_config_value_create_string:
        unsafe extern "C" fn(*const c_char) -> *mut ConfigValue,
    pub ovstorage_write: unsafe extern "C" fn(
        *mut Library,
        *const c_char,
        *const u8,
        usize,
        *const c_void,
        *const c_void,
        InfoCallback,
        *mut c_void,
    ),
    pub ovstorage_stat: unsafe extern "C" fn(
        *mut Library,
        *const c_char,
        *const c_void,
        *const c_void,
        InfoCallback,
        *mut c_void,
    ),
    pub ovstorage_info_destroy: unsafe extern "C" fn(*mut Info),
    pub ovstorage_info_size: unsafe extern "C" fn(*const Info) -> u64,
}

impl Loader {
    pub fn load() -> Self {
        let path = env!("OVSTORAGE_CAPI_SO");
        ensure_cdylibs_built(&["ovstorage-capi"]);
        // SAFETY: dlopen runs the platform loader on a trusted path the
        // build script wrote (or that the fallback `cargo build` just
        // produced).
        unsafe {
            let lib =
                libloading::Library::new(path).unwrap_or_else(|err| panic!("dlopen {path}: {err}"));

            // Capture the raw function pointers (deref the libloading
            // Symbol). The Library lives in `_lib`, so the pointers
            // remain valid for the lifetime of the Loader.
            macro_rules! sym {
                ($name:ident) => {{
                    let s: libloading::Symbol<_> = lib
                        .get(concat!(stringify!($name), "\0").as_bytes())
                        .expect(concat!("resolve ", stringify!($name)));
                    *s
                }};
            }

            let ovstorage_error_clear = sym!(ovstorage_error_clear);
            let ovstorage_init_auth_substrate = sym!(ovstorage_init_auth_substrate);
            let ovstorage_library_init = sym!(ovstorage_library_init);
            let ovstorage_library_shutdown = sym!(ovstorage_library_shutdown);
            let ovstorage_library_load_plugins_from_dir =
                sym!(ovstorage_library_load_plugins_from_dir);
            let ovstorage_library_add_connection = sym!(ovstorage_library_add_connection);
            let ovstorage_connection_destroy = sym!(ovstorage_connection_destroy);
            let ovstorage_connection_request_create = sym!(ovstorage_connection_request_create);
            let ovstorage_connection_request_add_config =
                sym!(ovstorage_connection_request_add_config);
            let ovstorage_connection_request_set_persist =
                sym!(ovstorage_connection_request_set_persist);
            let ovstorage_config_value_create_string = sym!(ovstorage_config_value_create_string);
            let ovstorage_write = sym!(ovstorage_write);
            let ovstorage_stat = sym!(ovstorage_stat);
            let ovstorage_info_destroy = sym!(ovstorage_info_destroy);
            let ovstorage_info_size = sym!(ovstorage_info_size);

            Self {
                _lib: lib,
                ovstorage_error_clear,
                ovstorage_init_auth_substrate,
                ovstorage_library_init,
                ovstorage_library_shutdown,
                ovstorage_library_load_plugins_from_dir,
                ovstorage_library_add_connection,
                ovstorage_connection_destroy,
                ovstorage_connection_request_create,
                ovstorage_connection_request_add_config,
                ovstorage_connection_request_set_persist,
                ovstorage_config_value_create_string,
                ovstorage_write,
                ovstorage_stat,
                ovstorage_info_destroy,
                ovstorage_info_size,
            }
        }
    }
}

// ----- callback completion plumbing -----------------------------------

/// Materialize one or more workspace cdylibs by package name if their
/// `target/<profile>/lib<name>.{so,dylib,dll}` artifact is missing.
/// `cargo test` compiles cdylib-only libs as test binaries without
/// producing the standalone cdylib output, so a bare
/// `cargo test -p ovstorage-capi` from a clean checkout has no artifact
/// for the integration tests to dlopen — including any plugin cdylibs
/// `ovstorage_library_load_plugins_from_dir` scans for.
pub fn ensure_cdylibs_built(packages: &[&str]) {
    let missing: Vec<&str> = packages
        .iter()
        .filter(|pkg| !cdylib_path_for(pkg).exists())
        .copied()
        .collect();
    if missing.is_empty() {
        return;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args(["build", "--lib", "--quiet"]);
    // The `OVSTORAGE_CAPI_SO` env var is computed under the active
    // profile dir, so a release-mode test run needs a release build.
    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }
    for pkg in &missing {
        cmd.arg("--package").arg(pkg);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|err| panic!("invoke cargo to build {missing:?}: {err}"));
    assert!(
        status.success(),
        "`cargo build --lib {}` failed: {status}",
        missing
            .iter()
            .map(|p| format!("--package {p}"))
            .collect::<Vec<_>>()
            .join(" "),
    );
    for pkg in &missing {
        let path = cdylib_path_for(pkg);
        assert!(
            path.exists(),
            "cargo build succeeded but {} was not produced",
            path.display(),
        );
    }
}

fn cdylib_path_for(package: &str) -> std::path::PathBuf {
    // ovstorage-capi sets `[lib] name = "ovstorage"`, so its cdylib is
    // `libovstorage.*`, not `libovstorage_capi.*`. Other workspace
    // plugins follow the cargo default of crate-name → underscore.
    let stem = if package == "ovstorage-capi" {
        "ovstorage".to_string()
    } else {
        package.replace('-', "_")
    };
    let filename = if cfg!(target_os = "windows") {
        format!("{stem}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    };
    workspace_profile_dir().join(filename)
}

/// Derive the active target/<profile>/ directory from the cdylib path
/// the build script captured. Going through `OVSTORAGE_CAPI_SO` (built
/// from `OUT_DIR`) keeps the test honest under `CARGO_TARGET_DIR`
/// overrides, which CI and isolated-target developer runs use.
pub fn workspace_profile_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("OVSTORAGE_CAPI_SO"))
        .parent()
        .expect("OVSTORAGE_CAPI_SO has parent")
        .to_path_buf()
}

pub struct InfoSlot {
    inner: Mutex<Option<InfoOutcome>>,
    cv: Condvar,
}

pub struct InfoOutcome {
    pub status: Status,
    pub info: Option<*mut Info>,
}

// `*mut Info` is only ever produced by the cdylib (a tokio worker
// thread) and consumed by the test (main thread). Sending it across is
// safe because the underlying object is host-owned and thread-safe.
unsafe impl Send for InfoOutcome {}

impl InfoSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    pub fn wait(&self, timeout: Duration) -> Option<InfoOutcome> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = guard.take() {
                return Some(v);
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (g, t) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if t.timed_out() && guard.is_none() {
                return None;
            }
        }
    }
}

pub unsafe extern "C" fn info_cb(
    status: Status,
    info: *mut Info,
    _error: *const Error,
    user_data: *mut c_void,
) {
    let info = if info.is_null() { None } else { Some(info) };
    let slot = unsafe { &*(user_data as *const InfoSlot) };
    let mut guard = slot.inner.lock().unwrap();
    *guard = Some(InfoOutcome { status, info });
    slot.cv.notify_all();
}

pub struct StatusSlot {
    inner: Mutex<Option<Status>>,
    cv: Condvar,
}

impl StatusSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    pub fn wait(&self, timeout: Duration) -> Option<Status> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = guard.take() {
                return Some(s);
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (g, t) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if t.timed_out() && guard.is_none() {
                return None;
            }
        }
    }
}

pub unsafe extern "C" fn status_cb(status: Status, _error: *const Error, user_data: *mut c_void) {
    let slot = unsafe { &*(user_data as *const StatusSlot) };
    let mut guard = slot.inner.lock().unwrap();
    *guard = Some(status);
    slot.cv.notify_all();
}

pub struct ConnectionSlot {
    inner: Mutex<Option<ConnectionOutcome>>,
    cv: Condvar,
}

pub struct ConnectionOutcome {
    pub status: Status,
    pub connection: Option<*mut Connection>,
}

unsafe impl Send for ConnectionOutcome {}

impl ConnectionSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    pub fn wait(&self, timeout: Duration) -> Option<ConnectionOutcome> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = guard.take() {
                return Some(v);
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (g, t) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if t.timed_out() && guard.is_none() {
                return None;
            }
        }
    }
}

pub unsafe extern "C" fn connection_cb(
    status: Status,
    connection: *mut Connection,
    _error: *const Error,
    user_data: *mut c_void,
) {
    let connection = if connection.is_null() {
        None
    } else {
        Some(connection)
    };
    let slot = unsafe { &*(user_data as *const ConnectionSlot) };
    let mut guard = slot.inner.lock().unwrap();
    *guard = Some(ConnectionOutcome { status, connection });
    slot.cv.notify_all();
}
