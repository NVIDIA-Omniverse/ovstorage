// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C-ABI round-trip + cancellation tests.
//!
//! Drive the new callback-shaped C ABI from Rust test code by
//! synthesizing per-method `Completion<T>` slots that the test thread
//! waits on while a tokio worker runs the spawned operation. This is
//! the equivalent of a C client using a condvar/notify to bridge the
//! async callback to a synchronous test driver.
//!
//! The host's plugin SPI registers `SecretStore` + `AuthRefreshLock`
//! process-globally — only one `Library` can build per process. All
//! lib-tests therefore share a single library handle (via
//! `shared_library()`), with both the file plugin (dlopen-loaded) and
//! `TestFactory` (rlib-registered) installed so file + test backends
//! both work. The `ovstorage_library_init` codepath itself is
//! exercised by the integration test in `tests/library_init.rs`,
//! which runs in its own process.

use super::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::path::Path;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage::Storage;

// --- generic completion shim --------------------------------------

struct Completion<T> {
    inner: Mutex<Option<T>>,
    cv: Condvar,
}

impl<T> Completion<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            cv: Condvar::new(),
        })
    }
    fn set(&self, value: T) {
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(value);
        self.cv.notify_all();
    }
    fn wait(&self) -> T {
        let mut guard = self.inner.lock().unwrap();
        loop {
            if let Some(v) = guard.take() {
                return v;
            }
            guard = self.cv.wait(guard).unwrap();
        }
    }
    fn wait_timeout(&self, dur: Duration) -> Option<T> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = std::time::Instant::now() + dur;
        loop {
            if let Some(v) = guard.take() {
                return Some(v);
            }
            let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
            let (g, timeout) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if timeout.timed_out() && guard.is_none() {
                return None;
            }
        }
    }
}

fn ptr_for<T>(slot: &Arc<Completion<T>>) -> *mut c_void {
    Arc::as_ptr(slot) as *mut c_void
}

unsafe fn read_message(error: *const Error) -> Option<String> {
    if error.is_null() {
        return None;
    }
    let msg = unsafe { (*error).message };
    if msg.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(msg) }
            .to_string_lossy()
            .into_owned(),
    )
}

// --- per-callback-shape outcomes (Send-clean wrappers) ------------

#[allow(dead_code)]
struct InfoOutcome {
    status: Status,
    info: Option<Box<Info>>,
    message: Option<String>,
}
unsafe impl Send for InfoOutcome {}

#[allow(dead_code)]
struct StatusOutcome {
    status: Status,
    message: Option<String>,
}

#[allow(dead_code)]
struct ReadBytesOutcome {
    status: Status,
    bytes: Vec<u8>,
    info: Option<Box<Info>>,
    message: Option<String>,
}
unsafe impl Send for ReadBytesOutcome {}

#[allow(dead_code)]
struct LocalDelegateOutcome {
    status: Status,
    delegate: Option<Box<LocalDelegate>>,
    message: Option<String>,
}
unsafe impl Send for LocalDelegateOutcome {}

#[allow(dead_code)]
struct ListOutcome {
    status: Status,
    list: Option<Box<List>>,
    message: Option<String>,
}
unsafe impl Send for ListOutcome {}

#[allow(dead_code)]
struct ListVersionsOutcome {
    status: Status,
    list: Option<Box<VersionList>>,
    message: Option<String>,
}
unsafe impl Send for ListVersionsOutcome {}

#[allow(dead_code)]
struct CheckAccessOutcome {
    status: Status,
    decision: Option<AccessDecision>,
    message: Option<String>,
}
unsafe impl Send for CheckAccessOutcome {}

impl Drop for CheckAccessOutcome {
    fn drop(&mut self) {
        if let Some(mut decision) = self.decision.take() {
            unsafe { ovstorage_access_decision_clear(&mut decision) };
        }
    }
}

// --- per-callback adapters ----------------------------------------

unsafe extern "C" fn info_cb(
    status: Status,
    info: *mut Info,
    error: *const Error,
    user_data: *mut c_void,
) {
    let info = if info.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(info) })
    };
    let outcome = InfoOutcome {
        status,
        info,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<InfoOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn status_cb(status: Status, error: *const Error, user_data: *mut c_void) {
    let outcome = StatusOutcome {
        status,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<StatusOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn read_bytes_cb(
    status: Status,
    mut bytes: Bytes,
    info: *mut Info,
    error: *const Error,
    user_data: *mut c_void,
) {
    let bytes_vec = if bytes.data.is_null() {
        Vec::new()
    } else {
        let v = unsafe { std::slice::from_raw_parts(bytes.data, bytes.len) }.to_vec();
        unsafe { ovstorage_bytes_destroy(&mut bytes) };
        v
    };
    let info = if info.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(info) })
    };
    let outcome = ReadBytesOutcome {
        status,
        bytes: bytes_vec,
        info,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<ReadBytesOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn local_delegate_cb(
    status: Status,
    delegate: *mut LocalDelegate,
    error: *const Error,
    user_data: *mut c_void,
) {
    let delegate = if delegate.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(delegate) })
    };
    let outcome = LocalDelegateOutcome {
        status,
        delegate,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<LocalDelegateOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn list_cb(
    status: Status,
    list: *mut List,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = ListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<ListOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn list_versions_cb(
    status: Status,
    list: *mut VersionList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = ListVersionsOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<ListVersionsOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn check_access_cb(
    status: Status,
    decision: AccessDecision,
    error: *const Error,
    user_data: *mut c_void,
) {
    let outcome = CheckAccessOutcome {
        status,
        decision: Some(decision),
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<CheckAccessOutcome>) };
    slot.set(outcome);
}

// --- read_stream slot (per-chunk accumulator) ---------------------

struct StreamSlot {
    state: Mutex<StreamState>,
    cv: Condvar,
}
struct StreamState {
    bytes: Vec<u8>,
    done: bool,
    status: Status,
    message: Option<String>,
}

impl StreamSlot {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StreamState {
                bytes: Vec::new(),
                done: false,
                status: Status::Ok,
                message: None,
            }),
            cv: Condvar::new(),
        })
    }
    fn wait(&self) -> StreamState {
        let mut guard = self.state.lock().unwrap();
        while !guard.done {
            guard = self.cv.wait(guard).unwrap();
        }
        StreamState {
            bytes: std::mem::take(&mut guard.bytes),
            done: guard.done,
            status: guard.status,
            message: guard.message.take(),
        }
    }
}

unsafe extern "C" fn stream_cb(
    mut chunk: Bytes,
    error: *const Error,
    done: bool,
    user_data: *mut c_void,
) {
    let slot = unsafe { &*(user_data as *const StreamSlot) };
    let mut state = slot.state.lock().unwrap();
    if !chunk.data.is_null() {
        state
            .bytes
            .extend_from_slice(unsafe { std::slice::from_raw_parts(chunk.data, chunk.len) });
        unsafe { ovstorage_bytes_destroy(&mut chunk) };
    }
    if !error.is_null() {
        state.status = unsafe { (*error).code };
        state.message = unsafe { read_message(error) };
    }
    if done {
        state.done = true;
        slot.cv.notify_all();
    }
}

fn stream_ptr(slot: &Arc<StreamSlot>) -> *mut c_void {
    Arc::as_ptr(slot) as *mut c_void
}

// --- shared library (one per test process) ------------------------

/// Newtype to push a raw `*mut Library` through
/// `OnceLock<T: Send + Sync>`. The pointer lives for the lifetime of
/// the test process; we never call shutdown.
#[derive(Clone, Copy)]
struct SharedLibraryPtr(*mut Library);
unsafe impl Send for SharedLibraryPtr {}
unsafe impl Sync for SharedLibraryPtr {}

fn shared_library() -> *mut Library {
    static SHARED: OnceLock<SharedLibraryPtr> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
            let auth_root =
                std::env::temp_dir().join(format!("ovstorage-capi-tests-{}", std::process::id()));
            std::fs::create_dir_all(&auth_root).expect("auth tempdir");
            ovstorage::init_auth_substrate(Some(&auth_root)).expect("init auth substrate");
            let inner = ovstorage::Library::builder()
                .allow_test_plugins(true)
                .register_backend_factory(Arc::new(ovstorage_plugin_test::TestFactory::new()))
                .open()
                .expect("library open");
            unsafe {
                inner
                    .load_plugins_from_dir(Some(&workspace_plugin_dir()))
                    .expect("load plugins from dir");
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            let ptr = Box::into_raw(Box::new(Library {
                inner,
                runtime: Arc::new(runtime),
            }));
            SharedLibraryPtr(ptr)
        })
        .0
}

/// Register a "file" backend connection at `root` (a directory on
/// disk) and return the `file:` prefix to address it.
fn register_file_route(library: &Library, root: &Path) -> String {
    let mut config = std::collections::HashMap::new();
    config.insert(
        "root".to_string(),
        ovstorage::ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    let request = ovstorage::ConnectionRequest {
        backend_kind: "file".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    library
        .runtime
        .block_on(async { library.inner.add_connection(request, None).await })
        .expect("add_connection (file)");
    address_for_path(root)
}

/// Register a "test" backend connection at `test://<name>/` with the
/// given `test_read_delay_ms` and return that root URL.
fn register_test_route(library: &Library, name: &str, read_delay_ms: u64) -> String {
    let root = format!("test://{name}/");
    let mut config = std::collections::HashMap::new();
    config.insert(
        "test_root".to_string(),
        ovstorage::ConfigValue::String(root.clone()),
    );
    config.insert(
        "test_read_delay_ms".to_string(),
        ovstorage::ConfigValue::Int(read_delay_ms as i64),
    );
    let request = ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    library
        .runtime
        .block_on(async { library.inner.add_connection(request, None).await })
        .expect("add_connection (test)");
    root
}

fn seed_test_object(library: &Library, address: &str, payload: &[u8]) {
    let url = ovstorage::address::parse(address).expect("parse");
    library
        .runtime
        .block_on(async {
            library
                .inner
                .write(
                    url,
                    ovstorage::Body::Bytes(payload.to_vec()),
                    ovstorage::WriteOptions::default(),
                    None,
                )
                .await
        })
        .expect("seed write");
}

// --- round-trip test (file plugin via dlopen) ---------------------

#[test]
fn c_api_round_trips_file_backend() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let library = shared_library();
    unsafe {
        let prefix = register_file_route(&*library, &root);
        let dir = CString::new(format!("{prefix}/dir")).unwrap();
        let object = CString::new(format!("{prefix}/dir/hello.txt")).unwrap();
        let copied = CString::new(format!("{prefix}/dir/copied.txt")).unwrap();
        let moved = CString::new(format!("{prefix}/dir/moved.txt")).unwrap();

        // create_directory
        {
            let slot = Completion::<InfoOutcome>::new();
            let opts = CreateDirectoryOptionsV1 {
                struct_size: std::mem::size_of::<CreateDirectoryOptionsV1>(),
                _reserved: crate::RESERVED_OPTIONS_PADDING_ZERO,
            };
            ovstorage_create_directory(
                library,
                dir.as_ptr(),
                &opts,
                ptr::null(),
                Some(info_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(
                outcome.status,
                Status::Ok,
                "create_directory: {:?}",
                outcome.message
            );
        }

        // write
        {
            let slot = Completion::<InfoOutcome>::new();
            let bytes = b"hello";
            ovstorage_write(
                library,
                object.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                ptr::null(),
                ptr::null(),
                Some(info_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            let info = outcome.info.unwrap();
            assert_eq!(ovstorage_info_size(&*info), 5);
        }

        // stat
        {
            let slot = Completion::<InfoOutcome>::new();
            ovstorage_stat(
                library,
                object.as_ptr(),
                ptr::null(),
                ptr::null(),
                Some(info_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            assert_eq!(ovstorage_info_size(&*outcome.info.unwrap()), 5);
        }

        // read_bytes
        {
            let slot = Completion::<ReadBytesOutcome>::new();
            ovstorage_read_bytes(
                library,
                object.as_ptr(),
                ptr::null(),
                ptr::null(),
                Some(read_bytes_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            assert_eq!(outcome.bytes, b"hello");
        }

        // read_stream
        {
            let slot = StreamSlot::new();
            ovstorage_read_stream(
                library,
                object.as_ptr(),
                ptr::null(),
                ptr::null(),
                Some(stream_cb),
                stream_ptr(&slot),
            );
            let final_state = slot.wait();
            assert_eq!(final_state.status, Status::Ok);
            assert_eq!(final_state.bytes, b"hello");
        }

        // read_local_file
        {
            let slot = Completion::<LocalDelegateOutcome>::new();
            ovstorage_read_local_file(
                library,
                object.as_ptr(),
                ptr::null(),
                ptr::null(),
                Some(local_delegate_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            let delegate = outcome.delegate.unwrap();
            let path = CStr::from_ptr(ovstorage_local_delegate_path(&*delegate));
            assert_eq!(std::fs::read(path.to_str().unwrap()).unwrap(), b"hello");
        }

        // list
        {
            let slot = Completion::<ListOutcome>::new();
            let list_options = ListOptionsV1 {
                struct_size: std::mem::size_of::<ListOptionsV1>(),
                recursive: false,
                has_max_results: true,
                max_results: 1,
                page_token: ptr::null(),
                full_metadata: false,
                _reserved: crate::RESERVED_OPTIONS_PADDING_ZERO,
            };
            ovstorage_list(
                library,
                dir.as_ptr(),
                &list_options,
                ptr::null(),
                Some(list_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            let list = outcome.list.unwrap();
            assert_eq!(ovstorage_list_len(&*list), 1);
        }

        // copy
        {
            let slot = Completion::<InfoOutcome>::new();
            ovstorage_copy(
                library,
                object.as_ptr(),
                copied.as_ptr(),
                ptr::null(),
                Some(info_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
        }

        // update_metadata
        {
            let patch = ovstorage_update_metadata_options_create();
            let key = CString::new("color").unwrap();
            let value = CString::new("blue").unwrap();
            let mut local_error = Error {
                code: Status::Ok,
                message: ptr::null_mut(),
            };
            assert_eq!(
                ovstorage_update_metadata_options_set(
                    patch,
                    key.as_ptr(),
                    value.as_ptr(),
                    &mut local_error,
                ),
                Status::Ok
            );
            let slot = Completion::<InfoOutcome>::new();
            ovstorage_update_metadata(
                library,
                copied.as_ptr(),
                patch,
                ptr::null(),
                Some(info_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            let info = outcome.info.unwrap();
            assert_eq!(ovstorage_info_user_metadata_len(&*info), 1);
            ovstorage_update_metadata_options_destroy(patch);
        }

        // rename
        {
            let slot = Completion::<StatusOutcome>::new();
            ovstorage_rename(
                library,
                copied.as_ptr(),
                moved.as_ptr(),
                ptr::null(),
                Some(status_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
        }

        // check_access
        {
            let slot = Completion::<CheckAccessOutcome>::new();
            ovstorage_check_access(
                library,
                moved.as_ptr(),
                AccessOps {
                    read: true,
                    write: true,
                    delete: true,
                    update_metadata: true,
                },
                ptr::null(),
                Some(check_access_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Ok);
            assert!(outcome.decision.as_ref().unwrap().allowed);
        }

        // list_versions (file plugin returns Unsupported)
        {
            let slot = Completion::<ListVersionsOutcome>::new();
            let version_options = ListVersionsOptionsV1 {
                struct_size: std::mem::size_of::<ListVersionsOptionsV1>(),
                has_max_results: false,
                max_results: 0,
                page_token: ptr::null(),
                _reserved: crate::RESERVED_OPTIONS_PADDING_ZERO,
            };
            ovstorage_list_versions(
                library,
                moved.as_ptr(),
                &version_options,
                ptr::null(),
                Some(list_versions_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait();
            assert_eq!(outcome.status, Status::Unsupported);
            assert!(outcome.list.is_none());
        }

        // delete + delete_directory
        {
            let slot = Completion::<StatusOutcome>::new();
            ovstorage_delete(
                library,
                object.as_ptr(),
                ptr::null(),
                Some(status_cb),
                ptr_for(&slot),
            );
            assert_eq!(slot.wait().status, Status::Ok);
        }
        {
            let slot = Completion::<StatusOutcome>::new();
            ovstorage_delete(
                library,
                moved.as_ptr(),
                ptr::null(),
                Some(status_cb),
                ptr_for(&slot),
            );
            assert_eq!(slot.wait().status, Status::Ok);
        }
        {
            let slot = Completion::<StatusOutcome>::new();
            let rmdir_options = DeleteDirectoryOptionsV1 {
                struct_size: std::mem::size_of::<DeleteDirectoryOptionsV1>(),
                _reserved: crate::RESERVED_OPTIONS_PADDING_ZERO,
            };
            ovstorage_delete_directory(
                library,
                dir.as_ptr(),
                &rmdir_options,
                ptr::null(),
                Some(status_cb),
                ptr_for(&slot),
            );
            assert_eq!(slot.wait().status, Status::Ok);
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

// --- cancellation tests (rlib path with plugin-test) --------------

#[test]
fn cancel_token_aborts_in_flight_read() {
    let library = shared_library();
    unsafe {
        let root = register_test_route(&*library, "cancel-read", 5_000);
        let object_addr = format!("{root}hello.txt");
        seed_test_object(&*library, &object_addr, b"hello");

        let cancel = ovstorage_cancel_token_create();
        let address = CString::new(object_addr).unwrap();
        let slot = Completion::<ReadBytesOutcome>::new();

        ovstorage_read_bytes(
            library,
            address.as_ptr(),
            ptr::null(),
            cancel,
            Some(read_bytes_cb),
            ptr_for(&slot),
        );

        // Give the task a moment to enter the test-plugin's
        // cooperative-delay branch, then trigger cancellation.
        std::thread::sleep(Duration::from_millis(100));
        ovstorage_cancel_token_cancel(cancel);

        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("callback fires after cancel");
        assert_eq!(
            outcome.status,
            Status::Cancelled,
            "expected Cancelled, got {:?}: {:?}",
            outcome.status,
            outcome.message,
        );

        ovstorage_cancel_token_destroy(cancel);
    }
}

#[test]
fn cancel_token_pre_canceled_short_circuits() {
    let library = shared_library();
    unsafe {
        let root = register_test_route(&*library, "pre-cancel", 5_000);
        let object_addr = format!("{root}hello.txt");
        seed_test_object(&*library, &object_addr, b"hello");

        let cancel = ovstorage_cancel_token_create();
        ovstorage_cancel_token_cancel(cancel);
        assert!(ovstorage_cancel_token_is_canceled(cancel));

        let address = CString::new(object_addr).unwrap();
        let slot = Completion::<ReadBytesOutcome>::new();
        ovstorage_read_bytes(
            library,
            address.as_ptr(),
            ptr::null(),
            cancel,
            Some(read_bytes_cb),
            ptr_for(&slot),
        );

        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("callback fires for pre-canceled token");
        assert_eq!(outcome.status, Status::Cancelled);

        ovstorage_cancel_token_destroy(cancel);
    }
}

#[test]
fn null_library_fires_invalid_argument_inline_for_single_fire() {
    // Programmer-error contract: calling a thunk with a null library
    // handle (e.g. before `ovstorage_library_init` returned, or after
    // `ovstorage_library_shutdown` already ran and the caller forgot
    // to clear their pointer) fires InvalidArgument inline. There is
    // no runtime to dispatch on, but supplied callbacks still get a
    // completion instead of hanging forever.
    let slot = Completion::<InfoOutcome>::new();
    let user_data = ptr_for(&slot);

    unsafe {
        ovstorage_stat(
            ptr::null_mut(), // null library handle
            ptr::null(),     // address (irrelevant — never reached)
            ptr::null(),     // options
            ptr::null(),     // cancel
            Some(info_cb),
            user_data,
        );
    }

    let outcome = slot
        .wait_timeout(Duration::from_secs(2))
        .expect("callback fires for null library");
    assert_eq!(outcome.status, Status::InvalidArgument);
    assert!(outcome.info.is_none());
}

#[test]
fn null_library_fires_invalid_argument_done_for_stream() {
    let slot = StreamSlot::new();

    unsafe {
        ovstorage_read_stream(
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            Some(stream_cb),
            stream_ptr(&slot),
        );
    }

    let outcome = slot.wait();
    assert!(outcome.done);
    assert_eq!(outcome.status, Status::InvalidArgument);
    assert!(outcome.bytes.is_empty());
}

#[test]
fn invalid_argument_fires_callback_via_runtime() {
    let library = shared_library();
    unsafe {
        // Null address is detected during the synchronous prologue
        // (the address pointer can't be borrowed past this fn's
        // return). The error itself is delivered asynchronously: the
        // thunk captures the prologue result, hands it to
        // runtime.spawn, and the spawned task fires on_complete from
        // a tokio worker thread. This is the always-async invariant
        // — no callback ever fires inline.
        let slot = Completion::<InfoOutcome>::new();
        ovstorage_stat(
            library,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            Some(info_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires within timeout");
        assert_eq!(outcome.status, Status::InvalidArgument);
        assert!(outcome.info.is_none());
    }
}

// --- add_connection round-trip via builders -----------------------

#[allow(dead_code)]
struct ConnectionOutcome {
    status: Status,
    connection: Option<Box<Connection>>,
    message: Option<String>,
}
unsafe impl Send for ConnectionOutcome {}

unsafe extern "C" fn connection_cb(
    status: Status,
    connection: *mut Connection,
    error: *const Error,
    user_data: *mut c_void,
) {
    let connection = if connection.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(connection) })
    };
    let outcome = ConnectionOutcome {
        status,
        connection,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<ConnectionOutcome>) };
    slot.set(outcome);
}

#[test]
fn add_connection_via_c_builders_round_trip() {
    let library = shared_library();
    unsafe {
        // Build a `test://demo-builders/` connection request through
        // the C ABI builders. Mirrors what a C client would do:
        //   1. _create the request with backend_kind="test"
        //   2. _add_config "test_root" -> ConfigValue::String(...)
        //   3. _add_config "test_caps" -> ConfigValue::String("full")
        //   4. _add_credential is skipped (test plugin doesn't need it)
        //   5. _set_persist(false) — default
        //   6. _add_connection consumes the request and delivers Connection
        let request = ovstorage_connection_request_create(CString::new("test").unwrap().as_ptr());
        assert!(!request.is_null());

        let root = "test://demo-builders/";
        let root_cv = ovstorage_config_value_create_string(CString::new(root).unwrap().as_ptr());
        assert!(!root_cv.is_null());
        let key = CString::new("test_root").unwrap();
        assert!(ovstorage_connection_request_add_config(
            request,
            key.as_ptr(),
            root_cv,
        ));
        // root_cv is now consumed; do NOT destroy it.

        let caps_cv = ovstorage_config_value_create_string(CString::new("full").unwrap().as_ptr());
        let caps_key = CString::new("test_caps").unwrap();
        assert!(ovstorage_connection_request_add_config(
            request,
            caps_key.as_ptr(),
            caps_cv,
        ));

        ovstorage_connection_request_set_persist(request, false);

        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_add_connection(
            library,
            request,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("add_connection callback fires");

        assert_eq!(
            outcome.status,
            Status::Ok,
            "add_connection should succeed; got status={:?}, message={:?}",
            outcome.status,
            outcome.message
        );
        let conn = outcome.connection.expect("connection handle on Ok");
        let conn_ptr: *const Connection = &*conn;

        // Verify accessors: id is non-empty, backend_kind is "test",
        // and at least one address is present.
        let id = CStr::from_ptr(ovstorage_connection_id(conn_ptr));
        assert!(!id.to_bytes().is_empty(), "connection id is non-empty");
        let backend_kind = CStr::from_ptr(ovstorage_connection_backend_kind(conn_ptr));
        assert_eq!(backend_kind.to_str().unwrap(), "test");
        assert!(
            ovstorage_connection_address_count(conn_ptr) > 0,
            "test backend should expose at least one address"
        );

        // Capabilities round-trip: caller stack-allocates, sets struct_size,
        // gets it filled. test_caps="full" should give us watch + write + access.
        let mut caps = CapabilitiesV1 {
            struct_size: std::mem::size_of::<CapabilitiesV1>(),
            supports_if_match_write: false,
            supports_no_overwrite_write: false,
            supports_native_metadata_patch: false,
            supports_metadata_rewrite_emulation: false,
            writes_are_atomic: false,
            supports_server_side_copy: false,
            supports_server_side_rename: false,
            supports_atomic_rename: false,
            has_real_directories: false,
            supports_list: false,
            wants_list_backed_stat: false,
            supports_recursive_list: false,
            populates_subdirectory_metadata: false,
            supports_version_listing: false,
            has_version_list_order: false,
            version_list_order: VersionListOrder::Newest,
            populates_effective_permissions_on_stat: false,
            supports_access_check: false,
            supports_watch_directory: false,
            watch_directory_kinds: ChangeKindSet::default(),
            watch_directory_resumable: false,
            has_watch_directory_max_lag: false,
            watch_directory_max_lag_nanos: 0,
            has_redirect_size_threshold: false,
            redirect_size_threshold: 0,
        };
        ovstorage_connection_capabilities(conn_ptr, &mut caps);
        // Plugin-test with caps="full" supports access-check, watch_directory.
        assert!(
            caps.supports_access_check,
            "full caps should support access_check"
        );
        assert!(
            caps.supports_watch_directory,
            "full caps should support watch_directory"
        );

        // Source kind: this came in via add_connection, so it's Runtime
        // with persisted=false.
        assert_eq!(
            ovstorage_connection_source_kind(conn_ptr),
            ConnectionSourceKind::Runtime,
        );
        assert!(!ovstorage_connection_source_runtime_persisted(conn_ptr));

        // Round-trip an I/O op against the new connection — proves the
        // routing actually works.
        let target_url = format!("{}rt-test.bin", root);
        let target_cstring = CString::new(target_url.as_str()).unwrap();
        let payload = b"hello via c builders";
        let write_slot = Completion::<InfoOutcome>::new();
        ovstorage_write(
            library,
            target_cstring.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            ptr::null(),
            ptr::null(),
            Some(info_cb),
            ptr_for(&write_slot),
        );
        let write_outcome = write_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("write callback fires");
        assert_eq!(
            write_outcome.status,
            Status::Ok,
            "write through new connection should succeed; message={:?}",
            write_outcome.message
        );

        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn add_connection_consumes_request_only_on_success() {
    let library = shared_library();
    unsafe {
        // Pass a freshly-built request to a thunk with a null library.
        // The callback fires InvalidArgument inline, and the request is
        // still not consumed by this prologue error.
        let request = ovstorage_connection_request_create(CString::new("test").unwrap().as_ptr());
        let null_slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_add_connection(
            ptr::null_mut(),
            request,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&null_slot),
        );
        let null_outcome = null_slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null library");
        assert_eq!(null_outcome.status, Status::InvalidArgument);
        // Request is still owned by us; destroy it to prove it was not consumed.
        ovstorage_connection_request_destroy(request);

        // Second case: pass a null request to a real library. The
        // callback should fire with InvalidArgument, and we have
        // nothing to clean up (the null pointer is already invalid).
        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_add_connection(
            library,
            ptr::null_mut(),
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null request");
        assert_eq!(outcome.status, Status::InvalidArgument);
    }
}

// --- list / remove / update_credentials ---------------------------

#[allow(dead_code)]
struct ConnectionListOutcome {
    status: Status,
    list: Option<Box<ConnectionList>>,
    message: Option<String>,
}
unsafe impl Send for ConnectionListOutcome {}

unsafe extern "C" fn connection_list_cb(
    status: Status,
    list: *mut ConnectionList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = ConnectionListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<ConnectionListOutcome>) };
    slot.set(outcome);
}

/// Helper: build a plugin-test ConnectionRequest via the C builders
/// and add_connection. Returns the resulting Connection handle.
unsafe fn add_test_connection_via_c(library: *mut Library, backend_root: &str) -> Box<Connection> {
    unsafe {
        let request = ovstorage_connection_request_create(CString::new("test").unwrap().as_ptr());
        let cv = ovstorage_config_value_create_string(CString::new(backend_root).unwrap().as_ptr());
        let key = CString::new("test_root").unwrap();
        assert!(ovstorage_connection_request_add_config(
            request,
            key.as_ptr(),
            cv
        ));

        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_add_connection(
            library,
            request,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("add_connection callback fires");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "add_connection should succeed; message={:?}",
            outcome.message
        );
        outcome.connection.expect("connection on Ok")
    }
}

#[test]
fn list_connections_returns_added_ones() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://list-c-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let slot = Completion::<ConnectionListOutcome>::new();
        ovstorage_library_list_connections(
            library,
            ptr::null(),
            Some(connection_list_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_connections callback fires");
        assert_eq!(outcome.status, Status::Ok);
        let list = outcome.list.expect("list on Ok");
        let len = ovstorage_connection_list_len(&*list);
        assert!(
            len >= 1,
            "list should contain at least the just-added connection"
        );

        // Find our connection in the list.
        let mut found = false;
        for i in 0..len {
            let item = ovstorage_connection_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let id = CStr::from_ptr(ovstorage_connection_id(item))
                .to_str()
                .unwrap();
            if id == conn_id {
                found = true;
                break;
            }
        }
        assert!(found, "list should include the just-added connection id");

        // Cleanup: remove the connection so we don't leak state into
        // other tests sharing the library.
        let id_cstring = CString::new(conn_id).unwrap();
        let remove_slot = Completion::<StatusOutcome>::new();
        ovstorage_library_remove_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(status_cb),
            ptr_for(&remove_slot),
        );
        let _ = remove_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("remove_connection callback fires");

        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn remove_connection_drops_it_from_list() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://list-c-2/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        // Remove
        let remove_slot = Completion::<StatusOutcome>::new();
        ovstorage_library_remove_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(status_cb),
            ptr_for(&remove_slot),
        );
        let outcome = remove_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("remove_connection callback fires");
        assert_eq!(outcome.status, Status::Ok);

        // Confirm it's gone from list
        let slot = Completion::<ConnectionListOutcome>::new();
        ovstorage_library_list_connections(
            library,
            ptr::null(),
            Some(connection_list_cb),
            ptr_for(&slot),
        );
        let list_outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_connections callback fires");
        let list = list_outcome.list.expect("list on Ok");
        let len = ovstorage_connection_list_len(&*list);
        for i in 0..len {
            let item = ovstorage_connection_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let id = CStr::from_ptr(ovstorage_connection_id(item))
                .to_str()
                .unwrap();
            assert_ne!(id, &conn_id, "removed connection should NOT be in list");
        }

        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn update_credentials_returns_updated_connection() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://update-creds-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        // Build a SecretBundle via the C builder and add a single
        // bytes credential.
        let bundle = ovstorage_secret_bundle_create();
        let secret = ovstorage_secret_value_create_bytes(b"new-token".as_ptr(), 9);
        let bundle_key = CString::new("token").unwrap();
        assert!(ovstorage_secret_bundle_add(
            bundle,
            bundle_key.as_ptr(),
            secret
        ));

        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_update_connection_credentials(
            library,
            id_cstring.as_ptr(),
            bundle,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("update_credentials callback fires");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "update_credentials should succeed; message={:?}",
            outcome.message
        );
        let updated = outcome.connection.expect("connection on Ok");
        let updated_id = CStr::from_ptr(ovstorage_connection_id(&*updated))
            .to_str()
            .unwrap();
        assert_eq!(updated_id, conn_id, "id should round-trip through update");

        // Cleanup
        let remove_slot = Completion::<StatusOutcome>::new();
        ovstorage_library_remove_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(status_cb),
            ptr_for(&remove_slot),
        );
        let _ = remove_slot.wait_timeout(Duration::from_secs(5));

        ovstorage_connection_destroy(Box::into_raw(conn));
        ovstorage_connection_destroy(Box::into_raw(updated));
    }
}

#[test]
fn update_credentials_does_not_consume_bundle_on_prologue_error() {
    let library = shared_library();
    unsafe {
        // Pass null connection_id with a real bundle. Prologue should
        // fire InvalidArgument WITHOUT consuming the bundle, so we can
        // destroy it ourselves.
        let bundle = ovstorage_secret_bundle_create();
        let secret = ovstorage_secret_value_create_bytes(b"x".as_ptr(), 1);
        let key = CString::new("token").unwrap();
        assert!(ovstorage_secret_bundle_add(bundle, key.as_ptr(), secret));

        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_update_connection_credentials(
            library,
            ptr::null(),
            bundle,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null connection_id");
        assert_eq!(outcome.status, Status::InvalidArgument);

        // Bundle is still ours — destroy it.
        ovstorage_secret_bundle_destroy(bundle);
    }
}

// --- streaming authenticate_connection ----------------------------

/// Captures every auth-event callback fire into a Vec for the test
/// thread to inspect after the stream completes.
struct AuthEventLog {
    inner: Mutex<Vec<AuthEventLogEntry>>,
    cv: Condvar,
}

#[allow(dead_code)]
struct AuthEventLogEntry {
    kind: Option<AuthEventKind>, // None on the final `done` fire
    succeeded_connection_id: Option<String>,
    progress_message: Option<String>,
    open_browser_url: Option<String>,
    failed_message: Option<String>,
    error_message: Option<String>,
    done: bool,
}
unsafe impl Send for AuthEventLogEntry {}

impl AuthEventLog {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Vec::new()),
            cv: Condvar::new(),
        })
    }
    fn push(&self, entry: AuthEventLogEntry) {
        let mut guard = self.inner.lock().unwrap();
        let done = entry.done;
        guard.push(entry);
        if done {
            self.cv.notify_all();
        }
    }
    fn wait_for_done(&self, dur: Duration) -> Option<Vec<AuthEventLogEntry>> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = std::time::Instant::now() + dur;
        loop {
            if guard.last().map(|e| e.done).unwrap_or(false) {
                return Some(std::mem::take(&mut *guard));
            }
            let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
            let (g, _) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if guard.last().map(|e| e.done).unwrap_or(false) {
                return Some(std::mem::take(&mut *guard));
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
        }
    }
}

unsafe extern "C" fn auth_event_cb(
    event: *mut AuthEvent,
    error: *const Error,
    done: bool,
    user_data: *mut c_void,
) {
    let log = unsafe { &*(user_data as *const AuthEventLog) };
    let mut entry = AuthEventLogEntry {
        kind: None,
        succeeded_connection_id: None,
        progress_message: None,
        open_browser_url: None,
        failed_message: None,
        error_message: unsafe { read_message(error) },
        done,
    };
    if !event.is_null() {
        let kind = unsafe { ovstorage_auth_event_kind(event) };
        entry.kind = Some(kind);
        match kind {
            AuthEventKind::OpenBrowser => {
                let url_ptr = unsafe { ovstorage_auth_event_open_browser_url(event) };
                if !url_ptr.is_null() {
                    entry.open_browser_url = Some(
                        unsafe { CStr::from_ptr(url_ptr) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
            AuthEventKind::Progress => {
                let msg_ptr = unsafe { ovstorage_auth_event_progress_message(event) };
                if !msg_ptr.is_null() {
                    entry.progress_message = Some(
                        unsafe { CStr::from_ptr(msg_ptr) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
            AuthEventKind::Succeeded => {
                let conn = unsafe { ovstorage_auth_event_succeeded_connection(event) };
                if !conn.is_null() {
                    let id_ptr = unsafe { ovstorage_connection_id(conn) };
                    if !id_ptr.is_null() {
                        entry.succeeded_connection_id = Some(
                            unsafe { CStr::from_ptr(id_ptr) }
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                }
            }
            AuthEventKind::Failed => {
                let msg_ptr = unsafe { ovstorage_auth_event_failed_error_message(event) };
                if !msg_ptr.is_null() {
                    entry.failed_message = Some(
                        unsafe { CStr::from_ptr(msg_ptr) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
            _ => {}
        }
        // Free the event handle now that we've extracted the fields.
        unsafe { ovstorage_auth_event_destroy(event) };
    }
    log.push(entry);
}

unsafe fn add_test_connection_with_flow(
    library: *mut Library,
    backend_root: &str,
    auth_flow: &str,
) -> Box<Connection> {
    unsafe {
        let request = ovstorage_connection_request_create(CString::new("test").unwrap().as_ptr());
        let cv = ovstorage_config_value_create_string(CString::new(backend_root).unwrap().as_ptr());
        let key = CString::new("test_root").unwrap();
        assert!(ovstorage_connection_request_add_config(
            request,
            key.as_ptr(),
            cv
        ));

        let flow_cv =
            ovstorage_config_value_create_string(CString::new(auth_flow).unwrap().as_ptr());
        let flow_key = CString::new("test_auth_flow").unwrap();
        assert!(ovstorage_connection_request_add_config(
            request,
            flow_key.as_ptr(),
            flow_cv,
        ));

        let slot = Completion::<ConnectionOutcome>::new();
        ovstorage_library_add_connection(
            library,
            request,
            ptr::null(),
            Some(connection_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("add_connection callback fires");
        assert_eq!(outcome.status, Status::Ok, "add: {:?}", outcome.message);
        outcome.connection.expect("connection on Ok")
    }
}

unsafe fn cleanup_connection(library: *mut Library, conn_id: &str) {
    unsafe {
        let id_cstring = CString::new(conn_id).unwrap();
        let remove_slot = Completion::<StatusOutcome>::new();
        ovstorage_library_remove_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(status_cb),
            ptr_for(&remove_slot),
        );
        let _ = remove_slot.wait_timeout(Duration::from_secs(5));
    }
}

#[test]
fn authenticate_connection_succeed_flow() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_with_flow(library, "test://auth-succeed/", "succeed");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        let log = AuthEventLog::new();
        ovstorage_library_authenticate_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(auth_event_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );
        let entries = log
            .wait_for_done(Duration::from_secs(5))
            .expect("auth stream completes");

        // Expect: one Succeeded event + one final done with no event.
        assert!(
            entries.len() >= 2,
            "succeed flow should emit at least one event + done; got {} entries",
            entries.len()
        );
        let succeeded = entries
            .iter()
            .find(|e| e.kind == Some(AuthEventKind::Succeeded))
            .expect("Succeeded event present");
        assert_eq!(
            succeeded.succeeded_connection_id.as_deref(),
            Some(conn_id.as_str()),
            "Succeeded.connection.id should match"
        );
        let final_entry = entries.last().expect("at least one entry");
        assert!(final_entry.done, "final entry has done=true");
        assert!(final_entry.error_message.is_none(), "final has no error");

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn authenticate_connection_progress_then_succeed() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_with_flow(
            library,
            "test://auth-progress/",
            "progress-then-succeed",
        );
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        let log = AuthEventLog::new();
        ovstorage_library_authenticate_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(auth_event_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );
        let entries = log
            .wait_for_done(Duration::from_secs(5))
            .expect("auth stream completes");

        let kinds: Vec<_> = entries.iter().filter_map(|e| e.kind).collect();
        assert!(
            kinds.contains(&AuthEventKind::Progress),
            "Progress event present; got {:?}",
            kinds
        );
        assert!(
            kinds.contains(&AuthEventKind::Succeeded),
            "Succeeded event present; got {:?}",
            kinds
        );
        // Order: Progress before Succeeded.
        let progress_idx = kinds.iter().position(|&k| k == AuthEventKind::Progress);
        let succeeded_idx = kinds.iter().position(|&k| k == AuthEventKind::Succeeded);
        assert!(
            progress_idx < succeeded_idx,
            "Progress fires before Succeeded"
        );

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn authenticate_connection_open_browser_then_succeed() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_with_flow(
            library,
            "test://auth-browser/",
            "open-browser-then-succeed",
        );
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        let log = AuthEventLog::new();
        ovstorage_library_authenticate_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(auth_event_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );
        let entries = log
            .wait_for_done(Duration::from_secs(5))
            .expect("auth stream completes");

        let open_browser = entries
            .iter()
            .find(|e| e.kind == Some(AuthEventKind::OpenBrowser))
            .expect("OpenBrowser event present");
        assert!(
            open_browser.open_browser_url.is_some(),
            "OpenBrowser event has url"
        );

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn authenticate_connection_failed_flow() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_with_flow(library, "test://auth-fail/", "fail");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();
        let id_cstring = CString::new(conn_id.clone()).unwrap();

        let log = AuthEventLog::new();
        ovstorage_library_authenticate_connection(
            library,
            id_cstring.as_ptr(),
            ptr::null(),
            Some(auth_event_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );
        let entries = log
            .wait_for_done(Duration::from_secs(5))
            .expect("auth stream completes");

        // The fail flow emits a Failed event then ends — done with no
        // terminal-error pointer. (The Failed *event* itself carries
        // the failure context, NOT the callback's error pointer.)
        let failed = entries
            .iter()
            .find(|e| e.kind == Some(AuthEventKind::Failed))
            .expect("Failed event present");
        assert!(failed.failed_message.is_some(), "Failed event has message");

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn authenticate_connection_null_id_fires_error() {
    let library = shared_library();
    unsafe {
        let log = AuthEventLog::new();
        ovstorage_library_authenticate_connection(
            library,
            ptr::null(),
            ptr::null(),
            Some(auth_event_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );
        let entries = log
            .wait_for_done(Duration::from_secs(2))
            .expect("auth callback fires for null id");
        let final_entry = entries.last().expect("at least one entry");
        assert!(final_entry.done, "final entry done=true");
        assert!(
            final_entry.error_message.is_some(),
            "null id surfaces an error message"
        );
    }
}

// --- aliases (add / remove / list / watch) ------------------------

#[allow(dead_code)]
struct AliasOutcome {
    status: Status,
    alias: Option<Box<Alias>>,
    message: Option<String>,
}
unsafe impl Send for AliasOutcome {}

#[allow(dead_code)]
struct AliasListOutcome {
    status: Status,
    list: Option<Box<AliasList>>,
    message: Option<String>,
}
unsafe impl Send for AliasListOutcome {}

unsafe extern "C" fn alias_cb(
    status: Status,
    alias: *mut Alias,
    error: *const Error,
    user_data: *mut c_void,
) {
    let alias = if alias.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(alias) })
    };
    let outcome = AliasOutcome {
        status,
        alias,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<AliasOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn alias_list_cb(
    status: Status,
    list: *mut AliasList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = AliasListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<AliasListOutcome>) };
    slot.set(outcome);
}

#[derive(Clone)]
struct AddressRootSnapshotLogEntry {
    snapshot_len: Option<usize>,
    addresses: Vec<String>,
    error_message: Option<String>,
    done: bool,
}
unsafe impl Send for AddressRootSnapshotLogEntry {}

struct AddressRootSnapshotLog {
    inner: Mutex<Vec<AddressRootSnapshotLogEntry>>,
    cv: Condvar,
}

impl AddressRootSnapshotLog {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Vec::new()),
            cv: Condvar::new(),
        })
    }

    fn push(&self, entry: AddressRootSnapshotLogEntry) {
        let mut guard = self.inner.lock().unwrap();
        guard.push(entry);
        self.cv.notify_all();
    }

    fn wait_for_address(
        &self,
        address: &str,
        dur: Duration,
    ) -> Option<Vec<AddressRootSnapshotLogEntry>> {
        self.wait_until(dur, |entries| {
            entries
                .iter()
                .any(|entry| entry.addresses.iter().any(|candidate| candidate == address))
        })
    }

    fn wait_for_done(&self, dur: Duration) -> Option<Vec<AddressRootSnapshotLogEntry>> {
        self.wait_until(dur, |entries| {
            entries.last().map(|entry| entry.done).unwrap_or(false)
        })
    }

    fn wait_until(
        &self,
        dur: Duration,
        pred: impl Fn(&[AddressRootSnapshotLogEntry]) -> bool,
    ) -> Option<Vec<AddressRootSnapshotLogEntry>> {
        let mut guard = self.inner.lock().unwrap();
        let deadline = std::time::Instant::now() + dur;
        loop {
            if pred(&guard) {
                return Some(guard.clone());
            }
            let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
            let (g, _) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = g;
            if pred(&guard) {
                return Some(guard.clone());
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
        }
    }
}

unsafe extern "C" fn address_root_watch_cb(
    list: *mut AddressRootList,
    error: *const Error,
    done: bool,
    user_data: *mut c_void,
) {
    let log = unsafe { &*(user_data as *const AddressRootSnapshotLog) };
    let mut entry = AddressRootSnapshotLogEntry {
        snapshot_len: None,
        addresses: Vec::new(),
        error_message: unsafe { read_message(error) },
        done,
    };
    if !list.is_null() {
        let list = unsafe { Box::from_raw(list) };
        let len = unsafe { ovstorage_address_root_list_len(&*list) };
        entry.snapshot_len = Some(len);
        for i in 0..len {
            let root = unsafe { ovstorage_address_root_list_item_at(&*list, i) };
            if root.is_null() {
                continue;
            }
            let address = unsafe { ovstorage_address_root_address(root) };
            if !address.is_null() {
                entry.addresses.push(
                    unsafe { CStr::from_ptr(address) }
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    log.push(entry);
}

/// Build an alias request via the C builders, then add_alias.
unsafe fn add_alias_via_c(
    library: *mut Library,
    from: &str,
    to: &str,
    persist: bool,
) -> Box<Alias> {
    unsafe {
        let from_c = CString::new(from).unwrap();
        let to_c = CString::new(to).unwrap();
        let request = ovstorage_alias_request_create(from_c.as_ptr(), to_c.as_ptr());
        assert!(!request.is_null(), "alias_request_create succeeded");
        ovstorage_alias_request_set_persist(request, persist);

        let slot = Completion::<AliasOutcome>::new();
        ovstorage_library_add_alias(
            library,
            request,
            ptr::null(),
            Some(alias_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("add_alias callback fires");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "add_alias should succeed; message={:?}",
            outcome.message
        );
        outcome.alias.expect("alias on Ok")
    }
}

unsafe fn cleanup_alias(library: *mut Library, alias_id: &str) {
    unsafe {
        let id = CString::new(alias_id).unwrap();
        let slot = Completion::<StatusOutcome>::new();
        ovstorage_library_remove_alias(
            library,
            id.as_ptr(),
            ptr::null(),
            Some(status_cb),
            ptr_for(&slot),
        );
        let _ = slot.wait_timeout(Duration::from_secs(5));
    }
}

#[test]
fn add_alias_round_trips_through_list() {
    let library = shared_library();
    unsafe {
        // First register a real test connection so we have valid
        // backend addresses to point the alias at.
        let conn = add_test_connection_via_c(library, "test://alias-roundtrip-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let alias = add_alias_via_c(
            library,
            "test://alias-roundtrip-1/from.txt",
            "test://alias-roundtrip-1/to.txt",
            false,
        );
        let alias_id = CStr::from_ptr(ovstorage_alias_id(&*alias))
            .to_str()
            .unwrap()
            .to_string();
        let from_str = CStr::from_ptr(ovstorage_alias_from(&*alias))
            .to_str()
            .unwrap()
            .to_string();
        let to_str = CStr::from_ptr(ovstorage_alias_to(&*alias))
            .to_str()
            .unwrap()
            .to_string();
        assert!(from_str.contains("from.txt"));
        assert!(to_str.contains("to.txt"));
        assert_eq!(
            ovstorage_alias_visibility(&*alias),
            AddressVisibility::Visible,
            "default visibility is Visible"
        );

        // list_aliases should include it.
        let list_slot = Completion::<AliasListOutcome>::new();
        ovstorage_library_list_aliases(
            library,
            ptr::null(),
            Some(alias_list_cb),
            ptr_for(&list_slot),
        );
        let list_outcome = list_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_aliases callback fires");
        assert_eq!(list_outcome.status, Status::Ok);
        let list = list_outcome.list.expect("list on Ok");
        let len = ovstorage_alias_list_len(&*list);
        let mut found = false;
        for i in 0..len {
            let item = ovstorage_alias_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let id = CStr::from_ptr(ovstorage_alias_id(item)).to_str().unwrap();
            if id == alias_id {
                found = true;
                break;
            }
        }
        assert!(found, "list_aliases should include the just-added alias");

        cleanup_alias(library, &alias_id);
        cleanup_connection(library, &conn_id);
        ovstorage_alias_destroy(Box::into_raw(alias));
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn remove_alias_drops_it_from_list() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://alias-remove-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let alias = add_alias_via_c(
            library,
            "test://alias-remove-1/x",
            "test://alias-remove-1/y",
            false,
        );
        let alias_id = CStr::from_ptr(ovstorage_alias_id(&*alias))
            .to_str()
            .unwrap()
            .to_string();

        cleanup_alias(library, &alias_id);

        let list_slot = Completion::<AliasListOutcome>::new();
        ovstorage_library_list_aliases(
            library,
            ptr::null(),
            Some(alias_list_cb),
            ptr_for(&list_slot),
        );
        let list_outcome = list_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_aliases callback fires");
        let list = list_outcome.list.expect("list on Ok");
        let len = ovstorage_alias_list_len(&*list);
        for i in 0..len {
            let item = ovstorage_alias_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let id = CStr::from_ptr(ovstorage_alias_id(item)).to_str().unwrap();
            assert_ne!(id, &alias_id, "removed alias should NOT be in list");
        }

        cleanup_connection(library, &conn_id);
        ovstorage_alias_destroy(Box::into_raw(alias));
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn watch_address_roots_emits_snapshots() {
    let library = shared_library();
    unsafe {
        let cancel = ovstorage_cancel_token_create();
        let log = AddressRootSnapshotLog::new();
        ovstorage_library_watch_address_roots(
            library,
            cancel,
            Some(address_root_watch_cb),
            Arc::as_ptr(&log) as *mut c_void,
        );

        let conn = add_test_connection_via_c(library, "test://root-watch-c-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let entries = log
            .wait_for_address("test://root-watch-c-1/", Duration::from_secs(5))
            .expect("snapshot containing new address root arrives");
        assert!(
            entries
                .iter()
                .any(|entry| entry.snapshot_len.is_some() && entry.error_message.is_none()),
            "watch should deliver successful snapshots"
        );

        ovstorage_cancel_token_cancel(cancel);
        let done_entries = log
            .wait_for_done(Duration::from_secs(5))
            .expect("watch terminates after cancel");
        assert!(done_entries.last().unwrap().done);

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
        ovstorage_cancel_token_destroy(cancel);
    }
}

#[test]
fn alias_request_consume_discipline_on_prologue_error() {
    let library = shared_library();
    unsafe {
        // Pass null library to a real request. The callback fires
        // InvalidArgument inline, and the caller still owns the
        // request because the prologue did not consume it.
        let from = CString::new("test://noroute/from").unwrap();
        let to = CString::new("test://noroute/to").unwrap();
        let request = ovstorage_alias_request_create(from.as_ptr(), to.as_ptr());
        let null_slot = Completion::<AliasOutcome>::new();
        ovstorage_library_add_alias(
            ptr::null_mut(),
            request,
            ptr::null(),
            Some(alias_cb),
            ptr_for(&null_slot),
        );
        let null_outcome = null_slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null library");
        assert_eq!(null_outcome.status, Status::InvalidArgument);
        ovstorage_alias_request_destroy(request);

        // Null request to a real library — error fires from runtime;
        // request was null so nothing to destroy.
        let slot = Completion::<AliasOutcome>::new();
        ovstorage_library_add_alias(
            library,
            ptr::null_mut(),
            ptr::null(),
            Some(alias_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null request");
        assert_eq!(outcome.status, Status::InvalidArgument);
    }
}

// --- visibility overrides + discovery -----------------------------

#[allow(dead_code)]
struct AddressVisibilityOverrideOutcome {
    status: Status,
    result: Option<Box<AddressVisibilityOverride>>,
    message: Option<String>,
}
unsafe impl Send for AddressVisibilityOverrideOutcome {}

#[allow(dead_code)]
struct AddressVisibilityOverrideListOutcome {
    status: Status,
    list: Option<Box<AddressVisibilityOverrideList>>,
    message: Option<String>,
}
unsafe impl Send for AddressVisibilityOverrideListOutcome {}

#[allow(dead_code)]
struct AddressRootListOutcome {
    status: Status,
    list: Option<Box<AddressRootList>>,
    message: Option<String>,
}
unsafe impl Send for AddressRootListOutcome {}

#[allow(dead_code)]
struct BackendKindDescriptorListOutcome {
    status: Status,
    list: Option<Box<BackendKindDescriptorList>>,
    message: Option<String>,
}
unsafe impl Send for BackendKindDescriptorListOutcome {}

#[allow(dead_code)]
struct CapabilitiesOutcome {
    status: Status,
    caps: Option<CapabilitiesV1>,
    message: Option<String>,
}
unsafe impl Send for CapabilitiesOutcome {}

unsafe extern "C" fn address_visibility_override_cb(
    status: Status,
    result: *mut AddressVisibilityOverride,
    error: *const Error,
    user_data: *mut c_void,
) {
    let result = if result.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(result) })
    };
    let outcome = AddressVisibilityOverrideOutcome {
        status,
        result,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<AddressVisibilityOverrideOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn address_visibility_override_list_cb(
    status: Status,
    list: *mut AddressVisibilityOverrideList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = AddressVisibilityOverrideListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<AddressVisibilityOverrideListOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn address_root_list_cb(
    status: Status,
    list: *mut AddressRootList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = AddressRootListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<AddressRootListOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn backend_kind_descriptor_list_cb(
    status: Status,
    list: *mut BackendKindDescriptorList,
    error: *const Error,
    user_data: *mut c_void,
) {
    let list = if list.is_null() {
        None
    } else {
        Some(unsafe { Box::from_raw(list) })
    };
    let outcome = BackendKindDescriptorListOutcome {
        status,
        list,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<BackendKindDescriptorListOutcome>) };
    slot.set(outcome);
}

unsafe extern "C" fn capabilities_cb(
    status: Status,
    caps: *const CapabilitiesV1,
    error: *const Error,
    user_data: *mut c_void,
) {
    // Copy the caller-borrowed CapabilitiesV1 into our outcome struct.
    let caps = if caps.is_null() {
        None
    } else {
        Some(unsafe { std::ptr::read(caps) })
    };
    let outcome = CapabilitiesOutcome {
        status,
        caps,
        message: unsafe { read_message(error) },
    };
    let slot = unsafe { &*(user_data as *const Completion<CapabilitiesOutcome>) };
    slot.set(outcome);
}

#[test]
fn set_address_visibility_round_trips_through_list() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://visibility-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        // set_address_visibility requires the address be an existing
        // route — use the connection's first address.
        let addr_ptr = ovstorage_connection_address_at(&*conn, 0);
        assert!(
            !addr_ptr.is_null(),
            "test connection has at least one address"
        );
        let target_addr = CStr::from_ptr(addr_ptr).to_str().unwrap().to_string();
        let addr_c = CString::new(target_addr.clone()).unwrap();

        let slot = Completion::<AddressVisibilityOverrideOutcome>::new();
        ovstorage_library_set_address_visibility(
            library,
            addr_c.as_ptr(),
            AddressVisibility::Hidden,
            false,
            ptr::null(),
            Some(address_visibility_override_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("set_address_visibility callback fires");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "set_address_visibility should succeed; message={:?}",
            outcome.message
        );
        let result = outcome.result.expect("override on Ok");
        assert_eq!(
            ovstorage_address_visibility_override_visibility(&*result),
            AddressVisibility::Hidden
        );
        assert!(!ovstorage_address_visibility_override_persisted(&*result));

        // List overrides should include this address.
        let list_slot = Completion::<AddressVisibilityOverrideListOutcome>::new();
        ovstorage_library_list_address_visibility_overrides(
            library,
            ptr::null(),
            Some(address_visibility_override_list_cb),
            ptr_for(&list_slot),
        );
        let list_outcome = list_slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_address_visibility_overrides callback fires");
        let list = list_outcome.list.expect("list on Ok");
        let len = ovstorage_address_visibility_override_list_len(&*list);
        let mut found = false;
        for i in 0..len {
            let item = ovstorage_address_visibility_override_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let addr_ptr2 = ovstorage_address_visibility_override_address(item);
            if !addr_ptr2.is_null() {
                let addr = CStr::from_ptr(addr_ptr2).to_str().unwrap();
                if addr == target_addr.as_str() {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "list should include the just-set override");

        cleanup_connection(library, &conn_id);
        ovstorage_address_visibility_override_destroy(Box::into_raw(result));
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn list_address_roots_returns_test_backend_root() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://roots-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let slot = Completion::<AddressRootListOutcome>::new();
        ovstorage_library_list_address_roots(
            library,
            ptr::null(),
            Some(address_root_list_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_address_roots callback fires");
        assert_eq!(outcome.status, Status::Ok);
        let list = outcome.list.expect("list on Ok");
        let len = ovstorage_address_root_list_len(&*list);
        assert!(
            len >= 1,
            "list_address_roots should return at least one root after add_connection"
        );

        let mut saw_test_backend = false;
        for i in 0..len {
            let item = ovstorage_address_root_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let backend_kind = CStr::from_ptr(ovstorage_address_root_backend_kind(item))
                .to_str()
                .unwrap();
            if backend_kind == "test" {
                saw_test_backend = true;
                // Capabilities should be queryable.
                let mut caps = empty_capabilities();
                ovstorage_address_root_capabilities(item, &mut caps);
                // No specific assertion on caps fields — the test
                // backend's capabilities depend on test_caps config;
                // just verify the call doesn't crash and struct_size
                // is preserved.
                assert_eq!(caps.struct_size, std::mem::size_of::<CapabilitiesV1>());
            }
        }
        assert!(
            saw_test_backend,
            "list should include the test backend root"
        );

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn list_backend_kinds_includes_test_and_file() {
    let library = shared_library();
    unsafe {
        let slot = Completion::<BackendKindDescriptorListOutcome>::new();
        ovstorage_library_list_backend_kinds(
            library,
            ptr::null(),
            Some(backend_kind_descriptor_list_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("list_backend_kinds callback fires");
        assert_eq!(outcome.status, Status::Ok);
        let list = outcome.list.expect("list on Ok");
        let len = ovstorage_backend_kind_descriptor_list_len(&*list);

        let mut kinds: Vec<String> = Vec::new();
        for i in 0..len {
            let item = ovstorage_backend_kind_descriptor_list_item_at(&*list, i);
            if item.is_null() {
                continue;
            }
            let kind = CStr::from_ptr(ovstorage_backend_kind_descriptor_kind(item))
                .to_str()
                .unwrap()
                .to_string();
            kinds.push(kind);
        }
        assert!(
            kinds.contains(&"test".to_string()),
            "list_backend_kinds should include 'test'; got {:?}",
            kinds
        );
        assert!(
            kinds.contains(&"file".to_string()),
            "list_backend_kinds should include 'file' (proves discovery isn't accidentally test-only); got {:?}",
            kinds
        );
    }
}

#[test]
fn capabilities_for_returns_routed_caps() {
    let library = shared_library();
    unsafe {
        let conn = add_test_connection_via_c(library, "test://caps-for-1/");
        let conn_id = CStr::from_ptr(ovstorage_connection_id(&*conn))
            .to_str()
            .unwrap()
            .to_string();

        let prefix = CString::new("test://caps-for-1/").unwrap();
        let slot = Completion::<CapabilitiesOutcome>::new();
        ovstorage_library_capabilities_for(
            library,
            prefix.as_ptr(),
            ptr::null(),
            Some(capabilities_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(5))
            .expect("capabilities_for callback fires");
        assert_eq!(
            outcome.status,
            Status::Ok,
            "capabilities_for should succeed; message={:?}",
            outcome.message
        );
        let caps = outcome.caps.expect("caps on Ok");
        assert_eq!(caps.struct_size, std::mem::size_of::<CapabilitiesV1>());
        // No field-specific assertion — depends on test plugin's caps
        // config. Just verify the struct round-trips through the
        // borrowed-pointer callback.

        cleanup_connection(library, &conn_id);
        ovstorage_connection_destroy(Box::into_raw(conn));
    }
}

#[test]
fn capabilities_for_null_prefix_fires_error() {
    let library = shared_library();
    unsafe {
        let slot = Completion::<CapabilitiesOutcome>::new();
        ovstorage_library_capabilities_for(
            library,
            ptr::null(),
            ptr::null(),
            Some(capabilities_cb),
            ptr_for(&slot),
        );
        let outcome = slot
            .wait_timeout(Duration::from_secs(2))
            .expect("callback fires for null prefix");
        assert_eq!(outcome.status, Status::InvalidArgument);
        assert!(outcome.caps.is_none());
    }
}

fn empty_capabilities() -> CapabilitiesV1 {
    CapabilitiesV1 {
        struct_size: std::mem::size_of::<CapabilitiesV1>(),
        supports_if_match_write: false,
        supports_no_overwrite_write: false,
        supports_native_metadata_patch: false,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: false,
        supports_server_side_copy: false,
        supports_server_side_rename: false,
        supports_atomic_rename: false,
        has_real_directories: false,
        supports_list: false,
        wants_list_backed_stat: false,
        supports_recursive_list: false,
        populates_subdirectory_metadata: false,
        supports_version_listing: false,
        has_version_list_order: false,
        version_list_order: VersionListOrder::Newest,
        populates_effective_permissions_on_stat: false,
        supports_access_check: false,
        supports_watch_directory: false,
        watch_directory_kinds: ChangeKindSet::default(),
        watch_directory_resumable: false,
        has_watch_directory_max_lag: false,
        watch_directory_max_lag_nanos: 0,
        has_redirect_size_threshold: false,
        redirect_size_threshold: 0,
    }
}

// --- helpers ------------------------------------------------------

fn unique_temp_dir() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ovstorage-capi-test-{}-{stamp}",
        std::process::id()
    ))
}

fn workspace_plugin_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has parent")
        .parent()
        .expect("workspace root")
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
}

fn address_for_path(path: &Path) -> String {
    let mut path = path.to_string_lossy().replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    format!("file:{path}")
}

// ---------------------------------------------------------------------
// Ticket #64: credential-callback continuation pattern + set_credential
// ---------------------------------------------------------------------

mod credential_tests {
    use super::*;
    use crate::ffi::RESERVED_OPTIONS_PADDING_ZERO;
    use crate::ffi::credential::{
        OvCredentialCallback, OvCredentialCallbackCompletion, OvResolvedCredentialV1,
        build_callback_provider, ovstorage_library_set_credential,
        ovstorage_resolved_credential_bundle_add_field,
        ovstorage_resolved_credential_bundle_create,
    };
    use std::os::raw::c_char;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    unsafe extern "C" fn noop_free(_userdata: *mut c_void) {}

    /// Sync resolve: completion fires inline from `resolve` itself.
    /// Builds `CallbackCredentialProvider` from a C-shaped callback,
    /// drives `provider.resolve(...)`, asserts the resolved value
    /// flows back through the oneshot channel.
    #[test]
    fn callback_provider_sync_resolve_fires_completion_inline() {
        struct State {
            calls: AtomicU32,
        }
        let state = Arc::new(State {
            calls: AtomicU32::new(0),
        });
        unsafe extern "C" fn resolve(
            userdata: *mut c_void,
            backend_id: *const c_char,
            principal_id: *const c_char,
            completion: OvCredentialCallbackCompletion,
            completion_userdata: *mut c_void,
        ) {
            let state = unsafe { &*(userdata as *const State) };
            state.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                unsafe { CStr::from_ptr(backend_id) }.to_str().unwrap(),
                "test-backend"
            );
            assert_eq!(
                unsafe { CStr::from_ptr(principal_id) }.to_str().unwrap(),
                "brian"
            );
            // Build a credential and fire completion synchronously.
            unsafe {
                let bundle = ovstorage_resolved_credential_bundle_create();
                let key = CString::new("access_token").unwrap();
                let secret =
                    crate::ffi::ovstorage_secret_value_create_bytes(b"sync-bearer".as_ptr(), 11);
                let mut err = Error {
                    code: Status::Ok,
                    message: ptr::null_mut(),
                };
                let s = ovstorage_resolved_credential_bundle_add_field(
                    bundle,
                    key.as_ptr(),
                    secret,
                    &mut err,
                );
                assert_eq!(s, Status::Ok);
                let source = CString::new("sync-portal").unwrap();
                let credential = OvResolvedCredentialV1 {
                    struct_size: std::mem::size_of::<OvResolvedCredentialV1>(),
                    bundle,
                    has_expires_at: false,
                    expires_at_unix_nanos: 0,
                    source_name: source.as_ptr(),
                    _reserved: RESERVED_OPTIONS_PADDING_ZERO,
                };
                completion(completion_userdata, Status::Ok, &credential);
                // `bundle` was consumed by the host on success (Box::from_raw
                // inside the completion thunk); we don't free here.
                drop(source); // keep CString alive until completion returns
            }
        }
        let cb = OvCredentialCallback {
            resolve: Some(resolve),
            free_userdata: Some(noop_free),
            userdata: Arc::into_raw(state.clone()) as *mut c_void,
        };
        let provider = build_callback_provider("sync-portal".into(), cb).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolved = runtime.block_on(async {
            provider
                .resolve(
                    &ovstorage::BackendId("test-backend".into()),
                    &ovstorage::auth::PrincipalView::new("brian"),
                )
                .await
                .unwrap()
        });
        assert_eq!(resolved.source_name, "sync-portal");
        assert!(resolved.bytes.fields.contains_key("access_token"));
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
        unsafe {
            // Reclaim the leaked Arc so we don't leak in the test.
            let _ = Arc::from_raw(state.as_ref() as *const State);
        }
    }

    /// Async resolve: implementer spawns a thread, returns immediately
    /// from `resolve`, fires completion later. Verifies the oneshot
    /// channel correctly bridges the cross-thread async work.
    #[test]
    fn callback_provider_async_resolve_fires_completion_from_other_thread() {
        unsafe extern "C" fn resolve(
            _userdata: *mut c_void,
            _backend_id: *const c_char,
            _principal_id: *const c_char,
            completion: OvCredentialCallbackCompletion,
            completion_userdata: *mut c_void,
        ) {
            let cu = completion_userdata as usize;
            std::thread::Builder::new()
                .name("ovs-test-capi".into())
                .spawn(move || {
                    std::thread::sleep(Duration::from_millis(15));
                    unsafe {
                        let bundle = ovstorage_resolved_credential_bundle_create();
                        let key = CString::new("access_token").unwrap();
                        let secret = crate::ffi::ovstorage_secret_value_create_bytes(
                            b"async-bearer".as_ptr(),
                            12,
                        );
                        let mut err = Error {
                            code: Status::Ok,
                            message: ptr::null_mut(),
                        };
                        let _ = ovstorage_resolved_credential_bundle_add_field(
                            bundle,
                            key.as_ptr(),
                            secret,
                            &mut err,
                        );
                        let source = CString::new("async-portal").unwrap();
                        let credential = OvResolvedCredentialV1 {
                            struct_size: std::mem::size_of::<OvResolvedCredentialV1>(),
                            bundle,
                            has_expires_at: false,
                            expires_at_unix_nanos: 0,
                            source_name: source.as_ptr(),
                            _reserved: RESERVED_OPTIONS_PADDING_ZERO,
                        };
                        completion(cu as *mut c_void, Status::Ok, &credential);
                        drop(source);
                    }
                })
                .expect("failed to spawn thread");
        }
        let cb = OvCredentialCallback {
            resolve: Some(resolve),
            free_userdata: Some(noop_free),
            userdata: ptr::null_mut(),
        };
        let provider = build_callback_provider("async-portal".into(), cb).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolved = runtime.block_on(async {
            provider
                .resolve(
                    &ovstorage::BackendId("b".into()),
                    &ovstorage::auth::PrincipalView::new("p"),
                )
                .await
                .unwrap()
        });
        assert_eq!(resolved.source_name, "async-portal");
        assert!(resolved.bytes.fields.contains_key("access_token"));
    }

    /// Error path: completion fires with a non-Ok status; the
    /// provider returns `CredentialError::Backend`.
    #[test]
    fn callback_provider_error_status_propagates_as_backend_error() {
        unsafe extern "C" fn resolve(
            _userdata: *mut c_void,
            _backend_id: *const c_char,
            _principal_id: *const c_char,
            completion: OvCredentialCallbackCompletion,
            completion_userdata: *mut c_void,
        ) {
            unsafe { completion(completion_userdata, Status::PermissionDenied, ptr::null()) };
        }
        let cb = OvCredentialCallback {
            resolve: Some(resolve),
            free_userdata: Some(noop_free),
            userdata: ptr::null_mut(),
        };
        let provider = build_callback_provider("err-portal".into(), cb).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime.block_on(async {
            provider
                .resolve(
                    &ovstorage::BackendId("b".into()),
                    &ovstorage::auth::PrincipalView::new("p"),
                )
                .await
                .unwrap_err()
        });
        match err {
            ovstorage::auth::CredentialError::Backend(_) => {}
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    /// `free_userdata` MUST run exactly once when the wrapper drops.
    #[test]
    fn callback_provider_free_userdata_invoked_on_drop() {
        static FREES: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn free_thunk(_ud: *mut c_void) {
            FREES.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn resolve(
            _u: *mut c_void,
            _b: *const c_char,
            _p: *const c_char,
            _c: OvCredentialCallbackCompletion,
            _cu: *mut c_void,
        ) {
        }
        FREES.store(0, Ordering::SeqCst);
        let cb = OvCredentialCallback {
            resolve: Some(resolve),
            free_userdata: Some(free_thunk),
            userdata: 0xdeadbeef as *mut c_void,
        };
        let provider = build_callback_provider("freer".into(), cb).unwrap();
        drop(provider);
        assert_eq!(FREES.load(Ordering::SeqCst), 1);
    }

    /// Receiver-drop is graceful: the provider's caller cancels (drops
    /// the future) before completion fires. The completion thunk's
    /// `Sender::send` returns Err and the result is silently
    /// discarded — no panic, no UB.
    #[test]
    fn callback_provider_receiver_drop_is_graceful() {
        // Implementer fires completion AFTER a delay; the test drops
        // the resolve future before the completion lands.
        unsafe extern "C" fn resolve(
            _u: *mut c_void,
            _b: *const c_char,
            _p: *const c_char,
            completion: OvCredentialCallbackCompletion,
            completion_userdata: *mut c_void,
        ) {
            let cu = completion_userdata as usize;
            std::thread::Builder::new()
                .name("ovs-test-capi".into())
                .spawn(move || {
                    // Sleep long enough that the test's
                    // `runtime::block_on(timeout(...))` cancels the future
                    // before this thread fires.
                    std::thread::sleep(Duration::from_millis(80));
                    unsafe { completion(cu as *mut c_void, Status::Internal, ptr::null()) };
                })
                .expect("failed to spawn thread");
        }
        let cb = OvCredentialCallback {
            resolve: Some(resolve),
            free_userdata: Some(noop_free),
            userdata: ptr::null_mut(),
        };
        let provider = build_callback_provider("cancel-test".into(), cb).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        // Drive the resolve with a short timeout that fires before the
        // implementer's completion thread wakes — the future drops.
        runtime.block_on(async {
            let _ = tokio::time::timeout(
                Duration::from_millis(10),
                provider.resolve(
                    &ovstorage::BackendId("b".into()),
                    &ovstorage::auth::PrincipalView::new("p"),
                ),
            )
            .await;
        });
        // Give the implementer thread time to fire completion against
        // the dropped receiver. If we crash, that's UB. We don't —
        // `Sender::send` returns Err and we silently discard.
        std::thread::sleep(Duration::from_millis(120));
    }

    /// `ovstorage_library_set_credential` end-to-end: build a resolved
    /// credential, push it via the C ABI, observe it landed in the
    /// cache through the Library's `resolve_credentials` API.
    #[test]
    fn library_set_credential_thunk_round_trip() {
        let library_ptr = shared_library();
        let library = unsafe { &*library_ptr };
        let slot = Completion::<StatusOutcome>::new();
        unsafe {
            let bundle = ovstorage_resolved_credential_bundle_create();
            let key = CString::new("access_token").unwrap();
            let secret = crate::ffi::ovstorage_secret_value_create_bytes(b"injected".as_ptr(), 8);
            let mut err = Error {
                code: Status::Ok,
                message: ptr::null_mut(),
            };
            ovstorage_resolved_credential_bundle_add_field(bundle, key.as_ptr(), secret, &mut err);
            let source = CString::new("capi-test").unwrap();
            let credential = OvResolvedCredentialV1 {
                struct_size: std::mem::size_of::<OvResolvedCredentialV1>(),
                bundle,
                has_expires_at: false,
                expires_at_unix_nanos: 0,
                source_name: source.as_ptr(),
                _reserved: RESERVED_OPTIONS_PADDING_ZERO,
            };
            let backend_id = CString::new("portal-route").unwrap();
            let principal = CString::new("brian").unwrap();
            ovstorage_library_set_credential(
                library_ptr,
                backend_id.as_ptr(),
                principal.as_ptr(),
                &credential,
                Some(status_cb),
                ptr_for(&slot),
            );
            // Wait for the on_complete callback.
            let outcome = slot.wait_timeout(Duration::from_secs(5)).expect("timeout");
            assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.message);
            // Verify the cache entry is observable via the host API.
            let resolved = library
                .runtime
                .block_on(library.inner.resolve_credentials(
                    &ovstorage::BackendId("portal-route".into()),
                    &ovstorage::auth::PrincipalView::new("brian"),
                ))
                .expect("resolve_credentials");
            assert_eq!(resolved.source_name, "capi-test");
            assert!(resolved.bytes.fields.contains_key("access_token"));
            drop(source);
        }
    }

    #[test]
    fn build_callback_provider_rejects_null_resolve() {
        let cb = OvCredentialCallback {
            resolve: None,
            free_userdata: None,
            userdata: ptr::null_mut(),
        };
        let err = build_callback_provider("null-resolve".into(), cb).unwrap_err();
        assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
    }

    #[test]
    fn library_set_credential_does_not_consume_bundle_on_invalid_source_name() {
        let library_ptr = shared_library();
        let slot = Completion::<StatusOutcome>::new();
        unsafe {
            let bundle = ovstorage_resolved_credential_bundle_create();
            let key = CString::new("access_token").unwrap();
            let secret = crate::ffi::ovstorage_secret_value_create_bytes(b"injected".as_ptr(), 8);
            let mut err = Error {
                code: Status::Ok,
                message: ptr::null_mut(),
            };
            ovstorage_resolved_credential_bundle_add_field(bundle, key.as_ptr(), secret, &mut err);
            let bad_source: [c_char; 3] = [-0x41, 0, 0];
            let credential = OvResolvedCredentialV1 {
                struct_size: std::mem::size_of::<OvResolvedCredentialV1>(),
                bundle,
                has_expires_at: false,
                expires_at_unix_nanos: 0,
                source_name: bad_source.as_ptr(),
                _reserved: RESERVED_OPTIONS_PADDING_ZERO,
            };
            let backend_id = CString::new("portal-route-2").unwrap();
            let principal = CString::new("brian").unwrap();
            ovstorage_library_set_credential(
                library_ptr,
                backend_id.as_ptr(),
                principal.as_ptr(),
                &credential,
                Some(status_cb),
                ptr_for(&slot),
            );
            let outcome = slot.wait_timeout(Duration::from_secs(5)).expect("timeout");
            assert_eq!(outcome.status, Status::InvalidArgument);
            // Bundle is still owned by us — destroy it. If the prologue
            // had wrongly consumed it, this would double-free.
            ovstorage_resolved_credential_bundle_destroy(bundle);
        }
    }
}

mod null_accessor_tests {
    use super::*;
    use crate::ffi::builders::{
        ConfigValueKind, ovstorage_config_value_as_bool, ovstorage_config_value_as_int,
        ovstorage_config_value_as_string, ovstorage_config_value_as_toml,
        ovstorage_config_value_kind,
    };

    #[test]
    fn config_value_kind_null_returns_string_default() {
        unsafe {
            assert_eq!(
                ovstorage_config_value_kind(ptr::null()),
                ConfigValueKind::String,
            );
        }
    }

    #[test]
    fn config_value_as_string_null_returns_null() {
        unsafe { assert!(ovstorage_config_value_as_string(ptr::null()).is_null()) };
    }

    #[test]
    fn config_value_as_int_null_returns_zero() {
        unsafe { assert_eq!(ovstorage_config_value_as_int(ptr::null()), 0) };
    }

    #[test]
    fn config_value_as_bool_null_returns_false() {
        unsafe { assert!(!ovstorage_config_value_as_bool(ptr::null())) };
    }

    #[test]
    fn config_value_as_toml_null_returns_null() {
        unsafe { assert!(ovstorage_config_value_as_toml(ptr::null()).is_null()) };
    }
}

mod header_smoke_tests {
    use std::path::PathBuf;
    use std::process::Command;

    fn header_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include")
    }

    #[test]
    fn c99_header_compiles() {
        let dir = header_dir();
        let header = dir.join("ovstorage.h");
        let output = match Command::new("cc")
            .arg("-std=c99")
            .arg("-I")
            .arg(&dir)
            .arg("-x")
            .arg("c")
            .arg("-fsyntax-only")
            .arg(&header)
            .output()
        {
            Ok(o) => o,
            Err(error) => {
                eprintln!(
                    "skipping c99_header_compiles: cc unavailable ({error}); install gcc/clang to enable"
                );
                return;
            }
        };
        assert!(
            output.status.success(),
            "cc -std=c99 failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn cpp20_header_compiles() {
        let dir = header_dir();
        let header = dir.join("ovstorage.hpp");
        let output = match Command::new("g++")
            .arg("-std=c++20")
            .arg("-I")
            .arg(&dir)
            .arg("-x")
            .arg("c++")
            .arg("-fsyntax-only")
            .arg(&header)
            .output()
        {
            Ok(o) => o,
            Err(error) => {
                eprintln!(
                    "skipping cpp20_header_compiles: g++ unavailable ({error}); install g++ to enable"
                );
                return;
            }
        };
        assert!(
            output.status.success(),
            "g++ -std=c++20 failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Compile and run a small C++20 program that exercises the
    /// task<T> race coordination: body completion (on a worker thread)
    /// vs. consumer await_suspend (on the main thread). The program
    /// runs the race in both orderings repeatedly; if the atomic
    /// state machine in promise_type is wrong, the consumer hangs or
    /// the worker resumes a not-yet-suspended continuation.
    #[test]
    fn cpp20_task_deferred_await_race() {
        let dir = header_dir();
        let mut src = std::env::temp_dir();
        src.push(format!(
            "ovstorage_task_deferred_await_race_{}.cc",
            std::process::id()
        ));
        let mut bin = src.clone();
        bin.set_extension("bin");
        std::fs::write(&src, CPP_TASK_DEFERRED_AWAIT_RACE_SRC).expect("write src");

        let compile = match Command::new("g++")
            .arg("-std=c++20")
            .arg("-O2")
            .arg("-pthread")
            .arg("-I")
            .arg(&dir)
            .arg("-o")
            .arg(&bin)
            .arg(&src)
            .output()
        {
            Ok(o) => o,
            Err(error) => {
                eprintln!("skipping cpp20_task_deferred_await_race: g++ unavailable ({error})");
                let _ = std::fs::remove_file(&src);
                return;
            }
        };
        if !compile.status.success() {
            let _ = std::fs::remove_file(&src);
            panic!(
                "g++ compile failed:\n{}",
                String::from_utf8_lossy(&compile.stderr)
            );
        }

        let run = Command::new(&bin).output().expect("run bin");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&bin);
        assert!(
            run.status.success(),
            "task race binary failed (status={:?}):\nstdout: {}\nstderr: {}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        );
    }

    const CPP_TASK_DEFERRED_AWAIT_RACE_SRC: &str = r#"
#include "ovstorage.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

using ovstorage::task;
using ovstorage::Result;
using ovstorage::Error;

namespace {

struct manual_awaiter {
    std::atomic<int> state{0};
    std::coroutine_handle<> continuation;
    int value = 0;
    int delay_ms = 0;

    bool await_ready() noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> h) noexcept {
        continuation = h;
        std::thread([this] {
            if (delay_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            }
            value = 42;
            if (state.exchange(1, std::memory_order_acq_rel) == 2) {
                continuation.resume();
            }
        }).detach();
        return state.exchange(2, std::memory_order_acq_rel) != 1;
    }
    int await_resume() noexcept { return value; }
};

task<int> make_task(int delay_ms) {
    manual_awaiter a;
    a.delay_ms = delay_ms;
    int v = co_await a;
    co_return Result<int>::success(std::move(v));
}

} // namespace

int main() {
    // Run with three timing regimes to exercise: (a) body completed
    // before consumer awaits (delay=0), (b) body racing with consumer
    // await_suspend (delay=1ms), (c) consumer awaits well before
    // body completes (delay=20ms).
    const int delays[] = {0, 1, 20};
    for (int d : delays) {
        for (int i = 0; i < 100; ++i) {
            auto t = make_task(d);
            if (d == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            Result<int> r = ovstorage::sync_wait(std::move(t));
            if (!r) {
                std::fprintf(stderr, "delay %d iter %d: failed\n", d, i);
                return 1;
            }
            if (r.value() != 42) {
                std::fprintf(stderr, "delay %d iter %d: got %d\n", d, i, r.value());
                return 1;
            }
        }
    }
    return 0;
}
"#;

    /// Compile and run a C++20 program that exercises the consumer
    /// dropping the task while the C callback is still in flight. With
    /// the Round 2 stack-allocated awaiter this dereferenced freed
    /// memory (UB / crash); the Round 3 shared-ownership refactor lets
    /// the leaked C-side ref outlive the dropped coroutine frame, with
    /// the awaiter destructor flagging the state "abandoned" so the
    /// callback drops cleanly without touching the destroyed handle.
    #[test]
    fn cpp20_task_drop_before_await_no_uaf() {
        let dir = header_dir();
        let mut src = std::env::temp_dir();
        src.push(format!(
            "ovstorage_task_drop_before_await_{}.cc",
            std::process::id()
        ));
        let mut bin = src.clone();
        bin.set_extension("bin");
        std::fs::write(&src, CPP_TASK_DROP_BEFORE_AWAIT_SRC).expect("write src");

        let compile = match Command::new("g++")
            .arg("-std=c++20")
            .arg("-O2")
            .arg("-g")
            .arg("-pthread")
            .arg("-fsanitize=address")
            .arg("-fno-omit-frame-pointer")
            .arg("-I")
            .arg(&dir)
            .arg("-o")
            .arg(&bin)
            .arg(&src)
            .output()
        {
            Ok(o) => o,
            Err(error) => {
                eprintln!(
                    "skipping cpp20_task_drop_before_await_no_uaf: g++ unavailable ({error})"
                );
                let _ = std::fs::remove_file(&src);
                return;
            }
        };
        if !compile.status.success() {
            let stderr = String::from_utf8_lossy(&compile.stderr).to_string();
            let _ = std::fs::remove_file(&src);
            // ASan may not be present on minimal sandboxes; fall back to a
            // plain build that at least exercises the logic (the leak
            // detector won't catch a dangling deref but a true UAF still
            // tends to crash on glibc + tcmalloc-poisoned slots).
            if stderr.contains("libasan") || stderr.contains("asan") {
                let plain = match Command::new("g++")
                    .arg("-std=c++20")
                    .arg("-O2")
                    .arg("-g")
                    .arg("-pthread")
                    .arg("-I")
                    .arg(&dir)
                    .arg("-o")
                    .arg(&bin)
                    .arg(&src)
                    .output()
                {
                    Ok(o) => o,
                    Err(error) => {
                        eprintln!(
                            "skipping cpp20_task_drop_before_await_no_uaf: g++ unavailable ({error})"
                        );
                        return;
                    }
                };
                if !plain.status.success() {
                    panic!(
                        "g++ compile (no ASan) failed:\n{}",
                        String::from_utf8_lossy(&plain.stderr)
                    );
                }
            } else {
                panic!("g++ compile failed:\n{stderr}");
            }
        }

        let run = Command::new(&bin).output().expect("run bin");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&bin);
        assert!(
            run.status.success(),
            "drop-before-await binary failed (status={:?}):\nstdout: {}\nstderr: {}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        );
    }

    const CPP_TASK_DROP_BEFORE_AWAIT_SRC: &str = r#"
#include "ovstorage.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

using ovstorage::task;
using ovstorage::Result;
using ovstorage::Error;
using ovstorage::detail::awaiter_base;
using ovstorage::detail::awaiter_state;

namespace {

// Stand-in for the production op<...> structs in Library methods: derives
// from awaiter_base<int> just like info_awaiter et al., schedules a
// "C callback" on a worker thread that fires after a short delay, and
// hands the leaked shared_ptr ref over as the user_data the callback
// will reclaim via reclaim_state.
struct delayed_int_awaiter : awaiter_base<int> {
    int delay_ms = 0;
    int value = 0;

    static void on_complete(void* user_data, int v) {
        auto state = reclaim_state(user_data);
        state->outcome = Result<int>::success(std::move(v));
        deliver(state);
    }

    bool await_suspend(std::coroutine_handle<> h) {
        s->continuation = h;
        // Spawn a worker that fires the "C callback" after delay_ms.
        // The worker holds the leaked ref via the void* it carries.
        // If the consumer drops the task before this fires, the body
        // stays alive (task::~task did NOT destroy because handle.done()
        // was false; it set the promise's state to 3) until the worker
        // resumes the continuation, the body runs to final_suspend, and
        // final_awaiter sees state==3 and destroys the frame itself.
        void* ud = release_user_data();
        int captured_value = value;
        int captured_delay = delay_ms;
        std::thread([ud, captured_value, captured_delay]() {
            if (captured_delay > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(captured_delay));
            }
            on_complete(ud, captured_value);
        }).detach();
        return commit_suspend();
    }
};

task<int> work(int delay_ms, int value) {
    delayed_int_awaiter a;
    a.delay_ms = delay_ms;
    a.value = value;
    co_return co_await a;
}

} // namespace

int main() {
    // Regime 1: construct + immediately drop. The C "callback" is still
    // pending in the worker when the task's dtor runs handle_.destroy().
    // A dangling-deref bug shows up as ASan use-after-free or a crash
    // when the worker thread fires.
    for (int i = 0; i < 200; ++i) {
        {
            auto t = work(/*delay_ms=*/5, /*value=*/i);
            // Drop without awaiting.
        }
        // Sleep enough for the worker to fire after the dtor ran.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Regime 2: construct + drop without ANY delay so the callback may
    // fire before, during, or after the dtor.
    for (int i = 0; i < 200; ++i) {
        {
            auto t = work(/*delay_ms=*/0, /*value=*/i);
        }
    }

    // Regime 3: normal completion still works.
    for (int i = 0; i < 100; ++i) {
        auto t = work(/*delay_ms=*/0, /*value=*/i);
        Result<int> r = ovstorage::sync_wait(std::move(t));
        if (!r || r.value() != i) {
            std::fprintf(stderr, "regime 3 iter %d failed (value=%d)\n",
                i, r ? r.value() : -1);
            return 1;
        }
    }

    // Let any in-flight workers from regime 2 finish so leak-checkers
    // see the leaked shared_ptr refs reclaimed.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return 0;
}
"#;
}
