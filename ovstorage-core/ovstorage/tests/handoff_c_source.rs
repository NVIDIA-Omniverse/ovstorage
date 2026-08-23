// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C -> Rust cross-language live-handoff leg.
//!
//! `dlopen`s the fixture `.so`
//! (`target/test-plugins/libovsx_c_source_handoff_fixture.so`, staged by
//! `tools/ovtasks/_test_plugins.py`: the FULL pure-C source distribution
//! `ovstorage-c-source/src/*.c` plus a producer TU
//! (`ovstorage/tests/csrc/handoff_c_source_producer.c`), cc-compiled
//! directly with `-fPIC -shared` -- genuinely pure-C-compiled code in its
//! own linked image, never linked against `ovstorage-plugin`'s rlib. This
//! test deliberately lives here rather than in `ovstorage-c-source-cc-test`:
//! that crate links the pure-C archive, and an `ovstorage` dev-dependency
//! there would pull in `ovstorage-plugin`'s rlib too -- both export
//! `ovstorage_plugin_*` symbols, a hard link collision.
//!
//! `create_exported_stack` builds a temp-dir file-backend Stack, seeds one
//! object, and exports its root through the pure-C `ovstorage_export_handle`
//! (see the producer TU). Importing it through the real
//! `ovstorage::import_handle` entry point and driving stat/read/write/list
//! live-validates the cross-allocator error-free contract: payload
//! bytes allocated by the pure-C runtime's `malloc`-backed allocator cross
//! into Rust's `System` allocator (and back, for the write leg) with no
//! leaks or double-frees.

use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong};
use std::path::PathBuf;

use ovstorage::{
    Body, ListOptions, ListRequest, ReadOptions, ReadRequest, ReadResult, Request, StatOptions,
    StatRequest, Url, WriteOptions, WriteRequest, import_handle,
};
use ovstorage_plugin::ffi;

/// The pure-C file backend answers local (`file://`) reads with a
/// [`ReadResult::LocalDelegate`] (a materialized local path), not buffered
/// `Bytes` -- unlike the in-memory producers the cross-binary suite uses.
/// Accept either shape and resolve to the actual bytes so the assertions
/// below exercise whichever the real backend chose to send across the
/// bridge.
fn read_result_bytes(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Bytes { bytes, .. } => bytes,
        ReadResult::LocalDelegate(delegate) => {
            std::fs::read(&delegate.path).unwrap_or_else(|error| {
                panic!(
                    "failed to read the LocalDelegate path {}: {error}",
                    delegate.path.display()
                )
            })
        }
        other => panic!("expected Bytes or LocalDelegate, got {other:?}"),
    }
}

/// Locate the fixture staged by `_test_plugins.py` under
/// `target/test-plugins/` -- a fixed, deterministic location (unlike the
/// cdylib plugins, this fixture is never built by `cargo`, only by the
/// staging script's own `cc` invocation, so there is no per-plugin
/// `OVSTORAGE_*_OVERRIDE` env var to plumb).
fn fixture_so() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // <target>/<profile>/deps/<test-binary> -> <target>/<profile>/deps ->
    // <target>/<profile> -> <target>
    let target_dir = exe.parent()?.parent()?.parent()?;
    let file = if cfg!(target_os = "macos") {
        "libovsx_c_source_handoff_fixture.dylib"
    } else {
        "libovsx_c_source_handoff_fixture.so"
    };
    let path = target_dir.join("test-plugins").join(file);
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
        "pure-C handoff fixture not found at {} but OVSTORAGE_REQUIRE_TEST_PLUGINS is set: \
         run `make build-test-plugins`",
        path.display(),
    );
    None
}

type CreateExportedStackFn = unsafe extern "C" fn(*mut ffi::LayerHandle) -> i32;
type FixtureStrFn = unsafe extern "C" fn() -> *const c_char;
type FixtureBytesFn = unsafe extern "C" fn() -> *const u8;
type FixtureLenFn = unsafe extern "C" fn() -> c_ulong;

/// A live `dlopen` of the fixture plus its producer/getter symbols.
/// Must outlive every `Arc<dyn Layer>` imported from a handle it exported --
/// a bare (unpinned) import carries no keep-alive on the producer, the
/// ABI contract instead. The fixture also owns the pure-C implementation's
/// detached, process-lifetime worker pool, so its mapping must remain pinned
/// after the imported Layer drops; `dlclose` would unmap code those workers
/// may still execute during test-process teardown.
struct Fixture {
    #[allow(dead_code)]
    library: std::mem::ManuallyDrop<libloading::Library>,
    create_exported_stack: CreateExportedStackFn,
    fixture_last_error: FixtureStrFn,
    fixture_prefix: FixtureStrFn,
    fixture_object_address: FixtureStrFn,
    fixture_payload: FixtureBytesFn,
    fixture_payload_len: FixtureLenFn,
}

impl Fixture {
    fn open() -> Option<Self> {
        let so = fixture_so()?;
        // SAFETY: our own workspace-staged fixture, cc-compiled with no
        // runtime linkage beyond libc/pthread.
        let library = unsafe { libloading::Library::new(&so) }.expect("dlopen the pure-C fixture");
        // SAFETY: the producer TU exports these exact symbols/signatures
        // (`ovstorage/tests/csrc/handoff_c_source_producer.c`).
        let create_exported_stack = *unsafe {
            library
                .get::<CreateExportedStackFn>(b"create_exported_stack\0")
                .expect("resolve create_exported_stack")
        };
        let fixture_last_error = *unsafe {
            library
                .get::<FixtureStrFn>(b"ovsx_fixture_last_error\0")
                .expect("resolve ovsx_fixture_last_error")
        };
        let fixture_prefix = *unsafe {
            library
                .get::<FixtureStrFn>(b"ovsx_fixture_prefix\0")
                .expect("resolve ovsx_fixture_prefix")
        };
        let fixture_object_address = *unsafe {
            library
                .get::<FixtureStrFn>(b"ovsx_fixture_object_address\0")
                .expect("resolve ovsx_fixture_object_address")
        };
        let fixture_payload = *unsafe {
            library
                .get::<FixtureBytesFn>(b"ovsx_fixture_payload\0")
                .expect("resolve ovsx_fixture_payload")
        };
        let fixture_payload_len = *unsafe {
            library
                .get::<FixtureLenFn>(b"ovsx_fixture_payload_len\0")
                .expect("resolve ovsx_fixture_payload_len")
        };
        Some(Self {
            library: std::mem::ManuallyDrop::new(library),
            create_exported_stack,
            fixture_last_error,
            fixture_prefix,
            fixture_object_address,
            fixture_payload,
            fixture_payload_len,
        })
    }

    /// Build a fresh fixture Stack in the pure-C producer and import its
    /// exported root through the real `ovstorage::import_handle` entry
    /// point.
    fn export_and_import(&self) -> std::sync::Arc<dyn ovstorage::Layer> {
        let mut out = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
        // SAFETY: `out` is a valid, writable `*mut ffi::LayerHandle` for the
        // call, per `create_exported_stack`'s contract.
        let status = unsafe { (self.create_exported_stack)(out.as_mut_ptr()) };
        assert_eq!(
            status,
            0,
            "create_exported_stack failed: {}",
            self.last_error()
        );
        // SAFETY: `status == 0` means `out` was fully written.
        let handle = unsafe { out.assume_init() };
        // SAFETY: `handle` is a live, freshly exported ABI-v2 pair from
        // `self.library`, which we keep mapped for the caller's use of the
        // returned `Arc<dyn Layer>`.
        unsafe { import_handle(handle) }.expect("import the pure-C exported handle")
    }

    fn last_error(&self) -> String {
        // SAFETY: `ovsx_fixture_last_error` always returns a valid,
        // NUL-terminated buffer owned by the fixture's own static storage.
        unsafe { CStr::from_ptr((self.fixture_last_error)()) }
            .to_string_lossy()
            .into_owned()
    }

    fn prefix(&self) -> String {
        // SAFETY: valid NUL-terminated static buffer for the lifetime of
        // `self.library`.
        unsafe { CStr::from_ptr((self.fixture_prefix)()) }
            .to_str()
            .expect("fixture prefix is valid UTF-8")
            .to_string()
    }

    fn object_address(&self) -> String {
        // SAFETY: valid NUL-terminated static buffer for the lifetime of
        // `self.library`.
        unsafe { CStr::from_ptr((self.fixture_object_address)()) }
            .to_str()
            .expect("fixture object address is valid UTF-8")
            .to_string()
    }

    fn payload(&self) -> Vec<u8> {
        let len = unsafe { (self.fixture_payload_len)() } as usize;
        // SAFETY: `ovsx_fixture_payload` returns a pointer to a static
        // buffer of exactly `ovsx_fixture_payload_len()` bytes.
        unsafe { std::slice::from_raw_parts((self.fixture_payload)(), len) }.to_vec()
    }
}

#[test]
fn pure_c_producer_exports_a_layer_rust_imports_and_drives_ops() {
    let Some(fixture) = Fixture::open() else {
        eprintln!(
            "skipping pure_c_producer_exports_a_layer_rust_imports_and_drives_ops: pure-C \
             handoff fixture not built"
        );
        return;
    };
    let imported = fixture.export_and_import();
    let object_address = fixture.object_address();
    let payload = fixture.payload();
    let prefix = fixture.prefix();

    let rt = tokio::runtime::Runtime::new().expect("driver runtime");
    rt.block_on(async {
        let object_url = Url::parse(&object_address).unwrap();

        // stat: sizes match across the pure-C -> Rust bridge.
        let info = imported
            .stat(
                Request::new(StatRequest {
                    address: object_url.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("stat across the pure-C -> Rust bridge");
        assert_eq!(info.size, Some(payload.len() as u64));

        // read: the seeded payload, allocated by the pure-C runtime's
        // malloc-backed allocator, crosses into a Rust `Vec<u8>` (via a
        // buffered `Bytes` result or a `LocalDelegate` local path -- the
        // real file backend answers with the latter).
        let read = imported
            .read(
                Request::new(ReadRequest {
                    address: object_url,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("read across the pure-C -> Rust bridge");
        assert_eq!(read_result_bytes(read), payload);

        // write: a Rust-allocated request body crosses the other way and is
        // freed by the pure-C plugin decode path (the cross-allocator contract, other
        // direction), then reads back through the same imported handle.
        let written_url = Url::parse(&format!("{prefix}written.bin")).unwrap();
        let written_payload = b"written across the pure-C -> Rust bridge".to_vec();
        imported
            .write(
                Request::new(WriteRequest {
                    address: written_url.clone(),
                    body: Body::Bytes(written_payload.clone()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .expect("write across the pure-C -> Rust bridge");
        let read_back = imported
            .read(
                Request::new(ReadRequest {
                    address: written_url,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("read back the written object");
        assert_eq!(read_result_bytes(read_back), written_payload);

        // list: both the seeded and written objects are visible.
        let page = imported
            .list(
                Request::new(ListRequest {
                    prefix: Url::parse(&prefix).unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect("list across the pure-C -> Rust bridge");
        assert_eq!(
            page.items.len(),
            2,
            "both the seeded and written objects list"
        );
    });

    drop(imported);
}
