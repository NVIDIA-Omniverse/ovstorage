// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Same-process tests for the cross-language live-handoff core —
//! `export_handle` / `import_handle` (the stable `ovstorage::` re-exports)
//! plus the `test-codec` hooks that let one process exercise the genuinely
//! foreign paths: `import_handle_force_foreign` bypasses the same-binary
//! fast path, and `layer_vtable_template_for_test` mints a byte-identical
//! vtable at a fresh address (a stand-in for "the same code in a second
//! linked image", which is exactly how two copies of one cdylib look). The
//! real cross-binary legs land in `handoff_cross_binary.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use ovstorage::{
    CancellationToken, ChecksumSet, Error, ErrorCode, Layer, LayerConfig, LayerKindDescriptor,
    LayerType, ListOptions, ListPage, ListRequest, ObjectInfo, ObjectKind, ReadOptions,
    ReadRequest, ReadResult, Request, Result, StatOptions, StatRequest, Url, WrapperFactory,
    export_handle, import_handle,
};
use ovstorage_plugin::{ffi, import_handle_force_foreign, marshal, thunks_v2};

const ROOT: &str = "mem://data/";
const A_PAYLOAD: &[u8] = b"handoff payload a";
const B_PAYLOAD: &[u8] = b"handoff payload b (second object)";

fn object_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: Some(format!("size:{size}")),
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Minimal in-memory producer Layer: seeded read-only store driving the
/// `stat`/`read`/`list` slots, plus an optional flag flipped on `Drop` so a
/// test can observe the producer-side Arc releasing across the bridge
/// (DropFlag pattern, cf. `wrappers/copy_rename_fallback.rs`).
struct MemLayer {
    name: String,
    store: HashMap<String, Vec<u8>>,
    dropped: Option<Arc<AtomicBool>>,
}

impl MemLayer {
    fn seeded(dropped: Option<Arc<AtomicBool>>) -> Arc<dyn Layer> {
        let mut store = HashMap::new();
        store.insert(format!("{ROOT}a.bin"), A_PAYLOAD.to_vec());
        store.insert(format!("{ROOT}b.bin"), B_PAYLOAD.to_vec());
        Arc::new(MemLayer {
            name: "mem".to_string(),
            store,
            dropped,
        })
    }
}

impl Drop for MemLayer {
    fn drop(&mut self) {
        if let Some(flag) = &self.dropped {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl Layer for MemLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "mem".to_string(),
            layer_type: LayerType::Backend,
            display_name: "handoff test layer".to_string(),
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

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        match self.store.get(address.as_str()) {
            Some(bytes) => Ok(object_info(address, bytes.len() as u64)),
            None => Err(Error::new(ErrorCode::NotFound, "object not found")),
        }
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let address = request.input.address;
        match self.store.get(address.as_str()) {
            Some(bytes) => Ok(ReadResult::Bytes {
                bytes: bytes.clone(),
                info: object_info(address, bytes.len() as u64),
            }),
            None => Err(Error::new(ErrorCode::NotFound, "object not found")),
        }
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let prefix = request.input.prefix;
        let mut items: Vec<ObjectInfo> = self
            .store
            .iter()
            .filter(|(key, _)| key.starts_with(prefix.as_str()))
            .map(|(key, bytes)| object_info(Url::parse(key).unwrap(), bytes.len() as u64))
            .collect();
        items.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
        Ok(ListPage {
            items,
            next_page_token: None,
        })
    }
}

/// A same-binary export/import round-trip takes the ptr-eq fast path: zero
/// FFI, and the exact producer Arc comes back out (`Arc::ptr_eq`).
/// Wait for a driven call's Layer release, which is not synchronous.
///
/// `complete_call` sends the result to the awaiting future (`consume_v2.rs:1555`)
/// and only then drops its `CallPin` (`:1570`). If the caller drops its own
/// handle inside that window, the caller's drop is not the last reference — the
/// pin's is, and `CallPin::drop` hands the Layer's release to the retirement
/// thread rather than running it in the producer's frame. So after any op has
/// been driven through a Layer, "the child was released" is an eventual
/// property, not an immediate one.
///
/// Asserting it immediately is a race the fast path usually wins, which is why
/// it passed locally and failed on loaded 2-core CI runners. The bound keeps a
/// genuine leak a failure rather than a hang.
#[track_caller]
fn assert_released_eventually(flag: &std::sync::atomic::AtomicBool, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !flag.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: the foreign child was never released, 10s after the last \
             handle was dropped"
        );
        std::thread::yield_now();
    }
}

#[test]
fn same_binary_import_preserves_arc_identity() {
    let layer = MemLayer::seeded(None);
    let handle = export_handle(Arc::clone(&layer));
    assert!(
        std::ptr::eq(handle.vtable, &thunks_v2::LAYER_VTABLE),
        "export mints this image's LAYER_VTABLE"
    );
    let imported = unsafe { import_handle(handle) }.expect("same-binary import");
    assert!(
        Arc::ptr_eq(&layer, &imported),
        "fast path preserves Arc identity"
    );
}

/// A forced-foreign import wraps (a fresh adapter, not the original Arc) and
/// faithfully round-trips `stat` / `read` / `list` through the full FFI slot
/// bridge: request builders → vtable thunks → result decoders.
#[tokio::test]
async fn forced_foreign_import_round_trips_stat_read_list() {
    let layer = MemLayer::seeded(None);
    let handle = export_handle(Arc::clone(&layer));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");
    assert!(
        !Arc::ptr_eq(&layer, &imported),
        "forced-foreign wraps rather than unwraps"
    );
    assert_eq!(imported.name(), "mem", "name cached via the sync slot");

    let a_url = Url::parse(&format!("{ROOT}a.bin")).unwrap();
    let info = imported
        .stat(
            Request::new(StatRequest {
                address: a_url.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("stat across the bridge");
    assert_eq!(info.size, Some(A_PAYLOAD.len() as u64));

    let read = imported
        .read(
            Request::new(ReadRequest {
                address: a_url,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("read across the bridge");
    match read {
        ReadResult::Bytes { bytes, .. } => assert_eq!(bytes, A_PAYLOAD),
        other => panic!("expected buffered bytes, got {other:?}"),
    }

    let page = imported
        .list(
            Request::new(ListRequest {
                prefix: Url::parse(ROOT).unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .expect("list across the bridge");
    assert_eq!(page.items.len(), 2, "both seeded objects list");
    assert!(page.items[0].address.as_str().ends_with("a.bin"));
}

/// Dropping the last import releases the producer-side Arc across the bridge
/// (the vtable `drop` slot reclaims the leaked `Box<Arc<dyn Layer>>`).
#[test]
fn dropping_the_last_import_releases_the_producer_arc() {
    let flag = Arc::new(AtomicBool::new(false));
    let handle = export_handle(MemLayer::seeded(Some(flag.clone())));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");
    assert!(
        !flag.load(Ordering::SeqCst),
        "producer Arc is pinned while the import lives"
    );
    drop(imported);
    assert_released_eventually(
        &flag,
        "dropping the last import must release the producer Arc",
    );
}

/// The ABI version handshake, version-mismatch arm: an `abi_version` the consumer does not
/// support is `IncompatibleType`, and — because the stable vtable header is
/// otherwise valid — the handle IS consumed, via its own `drop` slot.
#[test]
fn version_mismatch_is_incompatible_and_disposes_via_the_drop_slot() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.abi_version = ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION + 1;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let flag = Arc::new(AtomicBool::new(false));
    let handle = ffi::LayerHandle {
        state: thunks_v2::leak_layer(MemLayer::seeded(Some(flag.clone()))),
        vtable,
    };
    let err = unsafe { import_handle(handle) }
        .err()
        .expect("mismatched abi_version must fail");
    assert_eq!(err.code(), ErrorCode::IncompatibleType);
    assert!(
        flag.load(Ordering::SeqCst),
        "a version-mismatched handle is consumed via its (trustworthy) drop slot"
    );
}

/// The ABI version handshake, stale-version arm: the exact-match check also rejects an
/// *earlier* Layer ABI — a v5-era handle (the frozen family floor) under the
/// current consumer is `IncompatibleType`, never decoded with the current layout,
/// and is consumed via its (trustworthy) drop slot like any other version
/// mismatch.
#[test]
fn stale_floor_version_is_incompatible_not_reinterpreted() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.abi_version = ffi::OVSTORAGE_PLUGIN_ABI_V2_FLOOR;
    assert_ne!(
        vtable.abi_version,
        ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION,
        "the floor must lag the current version for this arm to be meaningful"
    );
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let flag = Arc::new(AtomicBool::new(false));
    let handle = ffi::LayerHandle {
        state: thunks_v2::leak_layer(MemLayer::seeded(Some(flag.clone()))),
        vtable,
    };
    let err = unsafe { import_handle(handle) }
        .err()
        .expect("stale abi_version must fail");
    assert_eq!(err.code(), ErrorCode::IncompatibleType);
    assert!(
        flag.load(Ordering::SeqCst),
        "a stale-version handle is consumed via its drop slot"
    );
}

/// The ABI version handshake, no-trustworthy-drop-slot arms: null pointers are
/// `InvalidArgument` and an undersized vtable header is `IncompatibleType`;
/// in both cases the handle is returned **undisposed** (the drop slot cannot
/// be trusted), so the caller retains — and here manually reclaims — what it
/// passed.
#[test]
fn null_and_undersized_handles_error_and_return_undisposed() {
    // Null state (with this image's real vtable): must NOT take the
    // fast path and dereference null.
    let err = unsafe {
        import_handle(ffi::LayerHandle {
            state: std::ptr::null_mut(),
            vtable: &thunks_v2::LAYER_VTABLE,
        })
    }
    .err()
    .expect("null state must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);

    // Null vtable: InvalidArgument, state left untouched.
    let flag = Arc::new(AtomicBool::new(false));
    let state = thunks_v2::leak_layer(MemLayer::seeded(Some(flag.clone())));
    let err = unsafe {
        import_handle(ffi::LayerHandle {
            state,
            vtable: std::ptr::null(),
        })
    }
    .err()
    .expect("null vtable must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(!flag.load(Ordering::SeqCst), "handle returned undisposed");
    // The caller retains ownership: reconstitute a valid handle and drop it.
    drop(ffi::LayerHandle {
        state,
        vtable: &thunks_v2::LAYER_VTABLE,
    });
    assert!(flag.load(Ordering::SeqCst));

    // Undersized vtable header: IncompatibleType, undisposed.
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.struct_size = std::mem::size_of::<usize>();
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));
    let flag = Arc::new(AtomicBool::new(false));
    let state = thunks_v2::leak_layer(MemLayer::seeded(Some(flag.clone())));
    let err = unsafe { import_handle(ffi::LayerHandle { state, vtable }) }
        .err()
        .expect("undersized vtable must fail");
    assert_eq!(err.code(), ErrorCode::IncompatibleType);
    assert!(!flag.load(Ordering::SeqCst), "handle returned undisposed");
    drop(ffi::LayerHandle {
        state,
        vtable: &thunks_v2::LAYER_VTABLE,
    });
    assert!(flag.load(Ordering::SeqCst));
}

/// The debug-build live-export accounting: an export registers its
/// state pointer; the same-binary import fast path and the vtable `drop`
/// slot both unregister it. Pointer-keyed assertions, so concurrent tests
/// in this binary cannot interfere.
#[cfg(debug_assertions)]
#[test]
fn debug_accounting_tracks_live_exports() {
    let handle = export_handle(MemLayer::seeded(None));
    let state = handle.state;
    assert!(thunks_v2::is_live_handle_for_test(state));
    assert!(ovstorage::live_export_count() >= 1);

    let imported = unsafe { import_handle(handle) }.expect("fast-path import");
    assert!(
        !thunks_v2::is_live_handle_for_test(state),
        "the fast-path import consumes the export"
    );

    let handle = export_handle(imported);
    let state = handle.state;
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");
    assert!(
        thunks_v2::is_live_handle_for_test(state),
        "a forced-foreign wrap holds the export live"
    );
    drop(imported);
    assert!(
        !thunks_v2::is_live_handle_for_test(state),
        "the vtable drop slot unregisters the export"
    );
}

/// Pass-through wrapper that drives `plugin_create_wrapper` end-to-end.
struct PassWrapper {
    name: String,
    inner: Arc<dyn Layer>,
}

#[async_trait]
impl Layer for PassWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "pass-wrapper".to_string(),
            layer_type: LayerType::Wrapper,
            display_name: "pass-through wrapper".to_string(),
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

    fn inner_layer(&self) -> Option<&Arc<dyn Layer>> {
        Some(&self.inner)
    }
}

struct PassWrapperFactory;

#[async_trait]
impl WrapperFactory for PassWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "pass-wrapper".to_string(),
            layer_type: LayerType::Wrapper,
            display_name: "pass-through wrapper".to_string(),
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

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: Arc<dyn Layer>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Arc<dyn Layer>> {
        Ok(Arc::new(PassWrapper {
            name: name.to_string(),
            inner,
        }))
    }
}

/// `plugin_create_wrapper` composes over a FOREIGN child end-to-end: the
/// child handle carries a leaked vtable-template copy (a second-image
/// stand-in whose address defeats the ptr-eq fast path), so `import_child`
/// takes the foreign-wrap path — where a naive path would drop-and-refuse
/// `Unsupported` — and an op then flows wrapper → foreign bridge → producer.
/// Plain `#[test]`: the factory thunk `block_on`s the plugin runtime, which
/// must not happen from inside a tokio worker.
#[test]
fn plugin_create_wrapper_composes_over_a_foreign_child() {
    let plugin_state = thunks_v2::leak_plugin(thunks_v2::LayerPlugin::new(vec![
        thunks_v2::LayerFactory::Wrapper(Arc::new(PassWrapperFactory)),
    ]));

    // A genuinely-foreign-looking child: same working thunks, fresh address.
    let foreign_vtable: &'static ffi::LayerVTableV1 =
        Box::leak(Box::new(thunks_v2::layer_vtable_template_for_test()));
    let flag = Arc::new(AtomicBool::new(false));
    let child_handle = ffi::LayerHandle {
        state: thunks_v2::leak_layer(MemLayer::seeded(Some(flag.clone()))),
        vtable: foreign_vtable,
    };

    let request = ffi::CreateWrapperRequest {
        struct_size: std::mem::size_of::<ffi::CreateWrapperRequest>(),
        extensions: std::ptr::null(),
        inner: child_handle,
        kind: marshal::primitive::str_to_ffi("pass-wrapper".to_string()),
        instance_id: marshal::primitive::str_to_ffi("wrap".to_string()),
        config: marshal::primitive::list_to_ffi(
            Vec::<ffi::ConnectionConfigEntry>::new(),
            |entry| entry,
        ),
        _reserved: [std::ptr::null_mut(); 8],
    };
    let mut out = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
    let mut err: *mut ffi::Error = std::ptr::null_mut();
    let status = unsafe {
        (thunks_v2::PLUGIN_VTABLE.create_wrapper)(
            plugin_state,
            &request,
            out.as_mut_ptr(),
            &mut err,
        )
    };
    std::mem::forget(request); // ownership moved into the plugin thunk
    if status != ffi::FFI_STATUS_OK {
        let e = unsafe { marshal::error::from_ffi(*Box::from_raw(err)) };
        panic!("create_wrapper over a foreign child failed: {e}");
    }

    let wrapper =
        unsafe { import_handle(out.assume_init()) }.expect("import the wrapper (fast path)");
    // Drive an op through wrapper → ForeignVtableLayer → producer.
    let rt = tokio::runtime::Runtime::new().expect("driver runtime");
    let info = rt
        .block_on(wrapper.stat(
            Request::new(StatRequest {
                address: Url::parse(&format!("{ROOT}a.bin")).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        ))
        .expect("stat through the composed wrapper");
    assert_eq!(info.size, Some(A_PAYLOAD.len() as u64));

    // Ownership chain: dropping the wrapper releases the foreign child.
    assert!(!flag.load(Ordering::SeqCst));
    drop(wrapper);
    assert_released_eventually(
        &flag,
        "dropping the wrapper must release the foreign child across the bridge",
    );
    // All factory-minted handles are gone; the plugin may drop (this also
    // exercises the debug plugin-drop tripwire's happy path).
    unsafe { (thunks_v2::PLUGIN_VTABLE.drop)(plugin_state) };
}
