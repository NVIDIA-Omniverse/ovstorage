// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust<->Rust cross-binary live-handoff tests. `dlopen`s the `mini-v2` test
//! cdylib directly and resolves its export symbol (`ovstorage_test_export_stack`,
//! `ovstorage-plugin-test-layer`) — bypassing the plugin manifest/init
//! handshake entirely — then imports the resulting handle through the real
//! `ovstorage::import_handle` entry point and asserts the import genuinely
//! took the foreign-vtable path (`vtable` pointer inequality with this test
//! binary's own `LAYER_VTABLE`, so this suite cannot pass via the
//! same-binary fast path) before driving op families, streams, mid-flight
//! cancellation, and producer-lifetime teardown across the boundary. A
//! same-binary leg and the version-band handshake negatives round out the
//! file (`handoff_core.rs` covers the same handshake logic in
//! isolation; this file's job is the genuinely cross-binary + lifetime
//! sweep).
//!
//! The `mini-v2` cdylib is a workspace member, so `cargo test --workspace`
//! (`make test` / `make test-ci`) builds it into the target profile dir; run
//! via plain `cargo test -p ovstorage` it may be absent, in which case these
//! tests skip (hard error under `OVSTORAGE_REQUIRE_TEST_PLUGINS`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use futures::StreamExt as _;
use ovstorage::{
    AuthenticateRequest, CancellationToken, ConnectionId, ConnectionKey, ErrorCode,
    InteractiveAuthCapability, Layer, LayerKindDescriptor, LayerType, ListOptions, ListRequest,
    ReadOptions, ReadRequest, ReadResult, Request, StatOptions, StatRequest, Url, WriteOptions,
    WriteRequest, export_handle, import_handle,
};
use ovstorage_plugin::{ffi, thunks_v2};

mod plugin_locator;

use plugin_locator::plugin_so;

/// Serializes every test in this file that touches the `mini-v2` cdylib's
/// statics (`OVSTORAGE_TEST_HANDOFF_DROPPED_GEN`, the cancel-gate
/// rendezvous barrier): both are process-wide *per linked image*, so two
/// tests that concurrently `dlopen` the same cdylib and drive its gated read
/// or drop counter would race each other's rendezvous/assertions.
///
/// It orders test *bodies*, not everything they set in motion. A producer
/// release can migrate onto a detached `ovs-layer-retire` thread
/// (`CallPin::drop`, `ovstorage-plugin/src/consume_v2.rs`) and land after the
/// guard is released — which is exactly why the drop observability below is a
/// monotonic generation counter rather than a bool. What this guard does buy
/// is that *exports* are serialized, so generations increase in test-body
/// order and a straggling release always carries a strictly earlier one.
static SERIAL: Mutex<()> = Mutex::new(());

type ExportStackFn = unsafe extern "C" fn(*mut ffi::LayerHandle, *mut u64) -> i32;
type ReleaseGateFn = extern "C" fn();

/// A live `dlopen` of the `mini-v2` cdylib plus its three symbols. Must
/// outlive every `Arc<dyn Layer>` imported from a handle it exported — a
/// bare (unpinned) import carries no keep-alive on the producer, the ABI
/// contract instead — so callers hold this for the whole test and drop every
/// imported handle before it (Rust's declaration-order drop takes care of
/// this automatically as long as `imported` is declared after `library`).
struct HandoffLibrary {
    /// Pinned for the process lifetime, exactly as production pins every
    /// plugin cdylib it loads (`HostPluginV2::library`,
    /// `ovstorage/src/loaded_v2.rs:53`, documented under "Pinning" in
    /// `ovstorage/src/lib.rs`). These fixtures reach for raw `libloading`
    /// to bypass the manifest/init handshake, which also bypasses that
    /// pinning — and the hazard the pinning exists for is live here: a
    /// producer teardown can be running `layer_drop_thunk` inside this image
    /// on a detached `ovs-layer-retire` thread when the test's scope ends,
    /// and `dlclose` while that code is executing is executing freed text.
    ///
    /// There is no quiesce point to join instead: `retire_off_thread`
    /// (`ovstorage-plugin/src/consume_v2.rs`) is a bare detached spawn with
    /// no handle, counter, or hook, and adding one would be production API
    /// invented for a fixture.
    #[allow(dead_code)]
    library: std::mem::ManuallyDrop<libloading::Library>,
    export_stack_fn: ExportStackFn,
    release_gate_fn: ReleaseGateFn,
    dropped_gen: *const AtomicU64,
}

// SAFETY: the raw pointers/fn pointers only ever dereference into the
// mapped cdylib image, which `library` keeps mapped for `self`'s lifetime;
// nothing here is thread-affine.
unsafe impl Send for HandoffLibrary {}

impl HandoffLibrary {
    /// `dlopen` the `mini-v2` cdylib and resolve its symbols directly —
    /// bypassing `ovstorage::load_layer_plugin`'s manifest/init handshake,
    /// which `ovstorage_test_export_stack` deliberately lives outside of.
    fn open() -> Option<Self> {
        let so = plugin_so("ovstorage_plugin_test_layer")?;
        // SAFETY: our own workspace-built test cdylib.
        let library = unsafe { libloading::Library::new(&so) }.expect("dlopen mini-v2 cdylib");
        // SAFETY: `mini-v2` exports these three symbols with these exact
        // signatures (`ovstorage-plugin-test-layer/src/lib.rs`).
        let export_stack_fn = *unsafe {
            library
                .get::<ExportStackFn>(b"ovstorage_test_export_stack\0")
                .expect("resolve ovstorage_test_export_stack")
        };
        let release_gate_fn = *unsafe {
            library
                .get::<ReleaseGateFn>(b"ovstorage_test_release_handoff_gate\0")
                .expect("resolve ovstorage_test_release_handoff_gate")
        };
        let dropped_gen = *unsafe {
            library
                .get::<*const AtomicU64>(b"OVSTORAGE_TEST_HANDOFF_DROPPED_GEN\0")
                .expect("resolve OVSTORAGE_TEST_HANDOFF_DROPPED_GEN")
        };
        Some(Self {
            library: std::mem::ManuallyDrop::new(library),
            export_stack_fn,
            release_gate_fn,
            dropped_gen,
        })
    }

    /// Export a fresh `HandoffBackend` stack from the cdylib and import it
    /// through the real `ovstorage::import_handle` entry point.
    ///
    /// Returns the raw `vtable` pointer the exported handle carried (captured
    /// before the handle is consumed) alongside the imported layer and **this
    /// handle's own generation**, which the export symbol hands back as an
    /// out-parameter. The generation is what makes the drop observability
    /// below handle-specific; see [`Self::dropped_gen`].
    fn export_and_import(&self) -> (*const ffi::LayerVTableV1, std::sync::Arc<dyn Layer>, u64) {
        let mut out = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
        let mut generation: u64 = 0;
        // SAFETY: `out` is a valid, writable `*mut ffi::LayerHandle` and
        // `&mut generation` a valid `*mut u64` for the call, per
        // `ovstorage_test_export_stack`'s safety contract.
        let status = unsafe { (self.export_stack_fn)(out.as_mut_ptr(), &mut generation) };
        assert_eq!(status, 0, "ovstorage_test_export_stack failed");
        // SAFETY: `status == 0` means `out` was fully written.
        let handle = unsafe { out.assume_init() };
        let vtable_ptr = handle.vtable;
        assert_ne!(
            generation, 0,
            "the export symbol must publish a strictly positive generation",
        );
        // SAFETY: `handle` is a live, freshly exported Layer-ABI pair whose
        // producer (this `HandoffLibrary`) we keep mapped for the caller's
        // use of the returned `Arc<dyn Layer>`.
        let imported = unsafe { import_handle(handle) }.expect("import the cross-binary handle");
        (vtable_ptr, imported, generation)
    }

    /// The highest export generation whose producer-side `HandoffBackend` Arc
    /// has released (`OVSTORAGE_TEST_HANDOFF_DROPPED_GEN`).
    ///
    /// Compare it against the generation `export_and_import` returned for the
    /// handle under test: `< mine` means this handle's producer is still
    /// pinned, `>= mine` means it has released. A bare bool cannot express
    /// that, because an earlier test's release can land here at any later
    /// moment via the detached retirement thread.
    fn dropped_gen(&self) -> u64 {
        // SAFETY: valid for the lifetime of `self.library`.
        unsafe { (*self.dropped_gen).load(Ordering::SeqCst) }
    }

    /// Release one rendezvous on the cdylib's cancel-gate barrier — see
    /// `ovstorage_test_release_handoff_gate`'s doc comment for the protocol.
    fn release_gate(&self) {
        (self.release_gate_fn)();
    }
}

type ExportParkedStackFn = unsafe extern "C" fn(*mut ffi::LayerHandle) -> i32;
type ReleaseParkGateFn = extern "C" fn();
type ParkWaitArrivedFn = extern "C" fn();

/// A live `dlopen` of the `ovstorage-plugin-test-abi` cdylib plus the parked
/// introspection fixture's three export symbols. Same direct-symbol resolution
/// as [`HandoffLibrary`], pointed at the OTHER test cdylib — the one
/// `OVSTORAGE_PLUGIN_TEST_SO` names — whose async v8 dynamic-query slots park
/// until released or cancelled. The two tests below drive that parking across
/// the genuinely-foreign vtable. See the fixture's contract in
/// `ovstorage-plugin-test-abi/src/lib.rs`.
struct ParkedLibrary {
    /// Pinned for the process lifetime for the same reason as
    /// [`HandoffLibrary::library`], and with more exposure: the tests below
    /// drive parked async introspection across the foreign vtable, which is
    /// precisely the `CallPin` path that mints off-thread retirements.
    #[allow(dead_code)]
    library: std::mem::ManuallyDrop<libloading::Library>,
    export_parked_stack_fn: ExportParkedStackFn,
    release_park_gate_fn: ReleaseParkGateFn,
    park_wait_arrived_fn: ParkWaitArrivedFn,
}

// SAFETY: as `HandoffLibrary` — the fn pointers only dereference into the
// mapped cdylib image, which `library` keeps mapped for `self`'s lifetime.
unsafe impl Send for ParkedLibrary {}

impl ParkedLibrary {
    /// `dlopen` the `plugin-test-abi` cdylib and resolve the parked fixture's
    /// three plain `#[no_mangle]` symbols directly — bypassing the plugin
    /// manifest/init handshake, exactly as `HandoffLibrary` does for `mini-v2`.
    fn open() -> Option<Self> {
        let so = plugin_so("ovstorage_plugin_test_abi")?;
        // SAFETY: our own workspace-built test cdylib.
        let library =
            unsafe { libloading::Library::new(&so) }.expect("dlopen plugin-test-abi cdylib");
        // SAFETY: `plugin-test-abi` exports these three symbols with these
        // exact signatures (`ovstorage-plugin-test-abi/src/lib.rs`).
        let export_parked_stack_fn = *unsafe {
            library
                .get::<ExportParkedStackFn>(b"ovstorage_test_export_parked_stack\0")
                .expect("resolve ovstorage_test_export_parked_stack")
        };
        let release_park_gate_fn = *unsafe {
            library
                .get::<ReleaseParkGateFn>(b"ovstorage_test_release_park_gate\0")
                .expect("resolve ovstorage_test_release_park_gate")
        };
        let park_wait_arrived_fn = *unsafe {
            library
                .get::<ParkWaitArrivedFn>(b"ovstorage_test_park_wait_arrived\0")
                .expect("resolve ovstorage_test_park_wait_arrived")
        };
        Some(Self {
            library: std::mem::ManuallyDrop::new(library),
            export_parked_stack_fn,
            release_park_gate_fn,
            park_wait_arrived_fn,
        })
    }

    /// Export a fresh `ParkBackend` (resetting the fixture's gate) and import it
    /// through the real `ovstorage::import_handle` entry point.
    fn export_and_import(&self) -> std::sync::Arc<dyn Layer> {
        let mut out = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
        // SAFETY: `out` is a valid, writable `*mut ffi::LayerHandle` for the
        // call, per `ovstorage_test_export_parked_stack`'s safety contract.
        let status = unsafe { (self.export_parked_stack_fn)(out.as_mut_ptr()) };
        assert_eq!(status, 0, "ovstorage_test_export_parked_stack failed");
        // SAFETY: `status == 0` means `out` was fully written.
        let handle = unsafe { out.assume_init() };
        // SAFETY: `handle` is a live, freshly exported Layer-ABI pair whose
        // producer (this `ParkedLibrary`) we keep mapped for the caller's use.
        unsafe { import_handle(handle) }.expect("import the parked cross-binary handle")
    }

    /// Release every parked introspection op (`ovstorage_test_release_park_gate`).
    fn release(&self) {
        (self.release_park_gate_fn)();
    }

    /// Block until a parked op reaches its park point
    /// (`ovstorage_test_park_wait_arrived`) — a deterministic in-flight
    /// rendezvous with no sleeps.
    fn wait_arrived(&self) {
        (self.park_wait_arrived_fn)();
    }
}

/// Both fixture libraries stay mapped for the whole process — asserted at
/// **compile** time, because there is no honest runtime observation of it.
///
/// A test that reopened the cdylib and compared base addresses would pass with
/// the defect present: Rust cdylibs commonly register TLS/`atexit` destructors
/// that make the dynamic linker keep the image resident, so the address is the
/// same whether or not `dlclose` ran. The property that actually matters —
/// no `dlclose` is *reachable* — is a property of the type, so that is what is
/// checked here. Demote either field back to a bare `libloading::Library` and
/// this stops compiling.
const _: () = {
    #[allow(dead_code)]
    fn libraries_are_pinned(handoff: &HandoffLibrary, parked: &ParkedLibrary) {
        fn pinned<T>(_: &std::mem::ManuallyDrop<T>) {}
        pinned(&handoff.library);
        pinned(&parked.library);
    }
};

fn seeded_url() -> Url {
    Url::parse("handoff://data/a.bin").unwrap()
}

const SEEDED_PAYLOAD: &[u8] = b"handoff cross-binary payload";

/// The import must take `ForeignVtableLayer`'s foreign-wrap path, not the
/// same-binary `ptr::eq` fast path — otherwise this whole suite would pass
/// vacuously without ever crossing the FFI. The exported handle's `vtable`
/// is the `mini-v2` cdylib's own `LAYER_VTABLE`, a distinct static from this
/// test binary's statically-linked copy of the same symbol name.
#[test]
fn cross_binary_import_takes_the_foreign_path() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(handoff_lib) = HandoffLibrary::open() else {
        eprintln!("skipping cross_binary_import_takes_the_foreign_path: mini-v2 cdylib not built");
        return;
    };
    let (vtable_ptr, imported, _generation) = handoff_lib.export_and_import();
    assert!(
        !std::ptr::eq(vtable_ptr, &thunks_v2::LAYER_VTABLE),
        "the exported handle's vtable must be the cdylib's own LAYER_VTABLE, distinct from \
         this test binary's — otherwise import_handle would (wrongly) take the same-binary \
         fast path and this suite would never cross the FFI"
    );
    assert_eq!(
        imported.name(),
        "handoff",
        "name cached via the sync slot across the bridge"
    );
    drop(imported);
}

/// Drives stat / buffered read / write / list / a fully-drained stream read
/// / an early-dropped stream read, all across the genuinely foreign vtable —
/// the representative "op families + streams + early drop" sweep.
#[test]
fn cross_binary_drives_op_families_streams_and_early_drop() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(handoff_lib) = HandoffLibrary::open() else {
        eprintln!(
            "skipping cross_binary_drives_op_families_streams_and_early_drop: mini-v2 cdylib \
             not built"
        );
        return;
    };
    let (_vtable_ptr, imported, _generation) = handoff_lib.export_and_import();

    futures::executor::block_on(async {
        // stat
        let info = imported
            .stat(
                Request::new(StatRequest {
                    address: seeded_url(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("stat across the cross-binary bridge");
        assert_eq!(info.size, Some(SEEDED_PAYLOAD.len() as u64));

        // buffered read
        let read = imported
            .read(
                Request::new(ReadRequest {
                    address: seeded_url(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("buffered read across the cross-binary bridge");
        match read {
            ReadResult::Bytes { bytes, .. } => assert_eq!(bytes, SEEDED_PAYLOAD),
            other => panic!("expected buffered bytes, got {other:?}"),
        }

        // write a new object
        let b_url = Url::parse("handoff://data/b.bin").unwrap();
        let b_payload = b"second cross-binary object".to_vec();
        imported
            .write(
                Request::new(WriteRequest {
                    address: b_url.clone(),
                    body: ovstorage::Body::Bytes(b_payload.clone()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .expect("write across the cross-binary bridge");
        let read_back = imported
            .read(
                Request::new(ReadRequest {
                    address: b_url.clone(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("read back the written object");
        match read_back {
            ReadResult::Bytes { bytes, .. } => assert_eq!(bytes, b_payload),
            other => panic!("expected buffered bytes, got {other:?}"),
        }

        // list
        let page = imported
            .list(
                Request::new(ListRequest {
                    prefix: Url::parse("handoff://data/").unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect("list across the cross-binary bridge");
        assert_eq!(
            page.items.len(),
            2,
            "both the seeded and written objects list"
        );

        // fully-drained stream read
        let streamed = imported
            .read(
                Request::new(ReadRequest {
                    address: Url::parse("handoff://data/a.bin/stream").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("streamed read across the cross-binary bridge");
        match streamed {
            ReadResult::Stream { mut stream, .. } => {
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next().await {
                    buf.extend_from_slice(&chunk.expect("stream chunk"));
                }
                assert_eq!(buf, SEEDED_PAYLOAD);
            }
            other => panic!("expected a stream, got {other:?}"),
        }

        // early-dropped stream read: pull one chunk, drop the rest without
        // draining — must not hang or panic, and the layer must stay usable
        // afterward (proves the vtable stream's drop_fn ran cleanly).
        let streamed = imported
            .read(
                Request::new(ReadRequest {
                    address: Url::parse("handoff://data/b.bin/stream").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("streamed read (early-drop leg) across the cross-binary bridge");
        match streamed {
            ReadResult::Stream { mut stream, .. } => {
                let first = stream.next().await;
                assert!(first.is_some(), "at least one chunk before the early drop");
                drop(stream);
            }
            other => panic!("expected a stream, got {other:?}"),
        }
        // The layer is still usable after the early drop.
        imported
            .stat(
                Request::new(StatRequest {
                    address: b_url,
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("layer still usable after an early-dropped stream");
    });

    drop(imported);
}

/// Mid-flight cancellation: the `/gated` read blocks (twice,
/// via a rendezvous barrier exported by the cdylib) so cancellation always
/// fires while the read call is genuinely still in flight, rather than
/// racing a sleep against the whole call the way
/// `cancel_token_aborts_in_flight_read` (`host_plugin_behaviors.rs`) does —
/// only the much narrower cancel-bridge propagation latency below still uses
/// a (short, generously-bounded) sleep. Note the FFI cancel token is only
/// plumbed to the *op dispatch* call, not to already-returned stream pulls
/// (`ForeignVtableLayer`'s `v2_op!` drops the cancel bridge once the op's
/// oneshot resolves) — so "mid-stream" here means "while the call that would
/// produce the read result is genuinely still in flight".
#[test]
fn cross_binary_cancel_mid_flight_via_gate() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(handoff_lib) = HandoffLibrary::open() else {
        eprintln!("skipping cross_binary_cancel_mid_flight_via_gate: mini-v2 cdylib not built");
        return;
    };
    let (_vtable_ptr, imported, _generation) = handoff_lib.export_and_import();

    let cancel = CancellationToken::new();
    let gated_url = Url::parse("handoff://data/a.bin/gated").unwrap();
    let read_thread = {
        let imported = std::sync::Arc::clone(&imported);
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            // `ffi::cancel_token_to_ffi` (the consumer-side FFI cancel
            // bridge `read_op` builds) spawns a bridge task via
            // `tokio::spawn` and needs a live Tokio runtime context on the
            // calling thread — a bare `futures::executor::block_on` has
            // none, so this leg needs a real (single-thread is enough)
            // Tokio runtime rather than the lighter executor the other
            // (cancel-less) tests in this file use.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("driver runtime");
            rt.block_on(imported.read(
                Request::new(ReadRequest {
                    address: gated_url,
                    options: ReadOptions::default(),
                }),
                Some(cancel),
            ))
        })
    };

    // RV1: the gated read has entered its blocking window (the FFI slot
    // call is non-blocking — it spawns onto the producer's own runtime and
    // returns immediately — so this rendezvous only unblocks once the
    // spawned Layer::read call itself reaches the gate).
    handoff_lib.release_gate();
    cancel.cancel();
    // `cancel.cancel()` only flips the consumer-side `CancellationToken`
    // synchronously; propagating that into the producer-side
    // `AtomicCancelState` (and from there into the `CancelTokenLocal` the
    // gated read actually reads) crosses `ffi::cancel_token_to_ffi`'s
    // internal bridge *task*, which needs a turn of `read_thread`'s own
    // runtime to run — this main thread has no direct signal for "that
    // task has now run", so a short, generously-bounded sleep here plays
    // the same role `cancel_token_aborts_in_flight_read`
    // (`host_plugin_behaviors.rs`) accepts for the same class of
    // cross-boundary cancellation timing. The Barrier gate above is what
    // makes the read call's *own* in-flight-ness deterministic; this sleep
    // only covers the cancel bridge's internal task-scheduling latency.
    std::thread::sleep(std::time::Duration::from_millis(100));
    // RV2: release it to observe the cancellation.
    handoff_lib.release_gate();

    let result = read_thread.join().expect("gated read thread panicked");
    let err = result.expect_err("a gated read must observe cancellation fired mid-flight");
    assert_eq!(err.code(), ErrorCode::Cancelled);

    drop(imported);
}

/// Mid-flight cancellation of a *parked introspection* across the FFI. The
/// parked-introspection analog of `cross_binary_cancel_mid_flight_via_gate`: it
/// drives the v8 async `list_address_roots` dynamic-query slot (rather than a
/// data op) against the `plugin-test-abi` fixture, whose slot parks. The park
/// is deterministic — the fixture signals arrival and `wait_arrived` blocks
/// until it does, so nothing races the park — and a sibling `stat` proves the
/// plugin runtime keeps servicing work while the introspection is parked.
/// Firing the FFI cancel token then completes the parked slot with `Cancelled`.
/// No sleep is needed: the parked slot wakes directly on its bridged cancel
/// token rather than on a second rendezvous.
#[test]
fn cross_binary_cancel_mid_flight_parked_introspection() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(parked_lib) = ParkedLibrary::open() else {
        eprintln!(
            "skipping cross_binary_cancel_mid_flight_parked_introspection: plugin-test-abi cdylib \
             not built"
        );
        return;
    };
    let imported = parked_lib.export_and_import();

    let cancel = CancellationToken::new();
    let introspection_thread = {
        let imported = std::sync::Arc::clone(&imported);
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            // The FFI cancel bridge (`cancel_token_to_ffi`) spawns via
            // `tokio::spawn`, so this leg needs a live Tokio runtime — the same
            // reason `cross_binary_cancel_mid_flight_via_gate` uses one.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("driver runtime");
            rt.block_on(Layer::list_address_roots(
                &*imported,
                &ovstorage::Extensions::new(),
                Some(cancel),
            ))
        })
    };

    // The fixture signals arrival the instant its slot parks; block until then
    // so the cancel below lands on a genuinely in-flight, parked op.
    parked_lib.wait_arrived();

    // A sibling op progresses while the introspection is parked — the parked
    // slot yields the plugin runtime rather than blocking it.
    futures::executor::block_on(async {
        let info = imported
            .stat(
                Request::new(StatRequest {
                    address: Url::parse("park://data/a.bin").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("a sibling stat progresses while the introspection is parked");
        assert_eq!(info.address.as_str(), "park://data/a.bin");
    });

    // Fire cancellation; the parked slot observes it mid-flight and completes.
    cancel.cancel();
    let result = introspection_thread
        .join()
        .expect("introspection thread panicked");
    // The `Ok` half (`RootInfoSnapshot`, update stream) is not `Debug`, so
    // match rather than `expect_err`.
    let err = match result {
        Ok(_) => panic!("a parked introspection must observe mid-flight cancellation"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::Cancelled);

    drop(imported);
}

/// Companion to the cancel leg: a parked introspection completes NORMALLY once
/// released. Same deterministic park rendezvous, but instead of cancelling we
/// fire the fixture's release gate (`ovstorage_test_release_park_gate`) and
/// assert the v8 async `root_info_for` slot returns its resolved `RootInfo`
/// across the foreign vtable.
#[test]
fn cross_binary_parked_introspection_completes_when_released() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(parked_lib) = ParkedLibrary::open() else {
        eprintln!(
            "skipping cross_binary_parked_introspection_completes_when_released: plugin-test-abi \
             cdylib not built"
        );
        return;
    };
    let imported = parked_lib.export_and_import();

    let introspection_thread = {
        let imported = std::sync::Arc::clone(&imported);
        std::thread::spawn(move || {
            // No cancel token → no FFI cancel bridge → the lighter executor the
            // other cancel-less legs in this file use suffices.
            futures::executor::block_on(Layer::root_info_for(
                &*imported,
                &Url::parse("park://data/a.bin").unwrap(),
                &ovstorage::Extensions::new(),
                None,
            ))
        })
    };

    // Block until the slot parks, then release it; it must complete normally.
    parked_lib.wait_arrived();
    parked_lib.release();

    let result = introspection_thread
        .join()
        .expect("introspection thread panicked");
    let info = result.expect("a released parked introspection completes normally");
    assert_eq!(
        info.root.as_str(),
        "park://data/",
        "the resolved RootInfo round-trips across the foreign vtable after release",
    );

    drop(imported);
}

/// Dropping the last cross-binary import releases the producer-side Arc —
/// observed via the cdylib's own `OVSTORAGE_TEST_HANDOFF_DROPPED_GEN` data
/// symbol, since the host test process has no other way to look inside a
/// second linked image's heap.
///
/// Both assertions are against **this handle's** generation, which the export
/// symbol returns as an out-parameter, rather than against a process-global
/// flag. A `dlclose`d cdylib is not reliably unmapped, so earlier `#[test]`
/// fns in this process very likely left the image — and its statics — mapped,
/// and one of their producer releases can still be in flight on a detached
/// `ovs-layer-retire` thread. Such a release carries a strictly earlier
/// generation than this test's export (exports are serialized by `SERIAL`),
/// so it satisfies `< generation` and cannot forge the post-drop assertion
/// either.
#[test]
fn cross_binary_drop_releases_producer_arc_across_binaries() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(handoff_lib) = HandoffLibrary::open() else {
        eprintln!(
            "skipping cross_binary_drop_releases_producer_arc_across_binaries: mini-v2 cdylib \
             not built"
        );
        return;
    };
    let (_vtable_ptr, imported, generation) = handoff_lib.export_and_import();
    assert!(
        handoff_lib.dropped_gen() < generation,
        "producer Arc is pinned while the cross-binary import lives: published generation {} \
         must still be below this export's {generation}",
        handoff_lib.dropped_gen(),
    );
    drop(imported);
    assert!(
        handoff_lib.dropped_gen() >= generation,
        "dropping the last cross-binary import must release the producer Arc across binaries: \
         published generation {} never reached this export's {generation}",
        handoff_lib.dropped_gen(),
    );
}

/// The published counter is a **high-water mark**, not a last-writer-wins
/// store: a release that lands late must not pull it backwards past a later
/// export's already-observed release.
///
/// The ordering is what makes this discriminate. Export A then B, drop **B
/// first** so the counter reaches B's (higher) generation, and only then drop
/// A. Under `fetch_max` the counter holds at B's generation; under a plain
/// `store` it regresses to A's. Dropping A before B would leave both
/// implementations agreeing on the final value, and the mutant would survive.
///
/// A is released from a spawned thread — the off-thread release the
/// `ovs-layer-retire` hop makes real — joined through a bounded rendezvous so
/// a regression that never releases fails this test rather than hanging the
/// suite.
#[test]
fn cross_binary_drop_generation_is_a_high_water_mark() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(handoff_lib) = HandoffLibrary::open() else {
        eprintln!(
            "skipping cross_binary_drop_generation_is_a_high_water_mark: mini-v2 cdylib not built"
        );
        return;
    };
    let (_vtable_a, imported_a, gen_a) = handoff_lib.export_and_import();
    let (_vtable_b, imported_b, gen_b) = handoff_lib.export_and_import();
    assert!(
        gen_b > gen_a,
        "each export must take a fresh, strictly increasing generation (got {gen_a} then {gen_b})",
    );

    drop(imported_b);
    assert_eq!(
        handoff_lib.dropped_gen(),
        gen_b,
        "releasing the later export publishes its generation",
    );

    // Release the earlier export off-thread; its generation is strictly lower.
    let (released_tx, released_rx) = std::sync::mpsc::channel();
    let releaser = std::thread::spawn(move || {
        drop(imported_a);
        let _ = released_tx.send(());
    });
    released_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect(
            "releasing the earlier cross-binary import must complete: it is holding the last \
             reference and nothing else can be blocking its teardown",
        );
    releaser.join().expect("releaser thread panicked");

    assert_eq!(
        handoff_lib.dropped_gen(),
        gen_b,
        "a straggling release from generation {gen_a} must not pull the published generation \
         back below {gen_b} — the counter is a high-water mark (fetch_max), not a store",
    );
}

/// Same-binary leg: exporting and re-importing a layer that lives in THIS
/// test binary (not the cdylib) takes the `ptr::eq` fast path and preserves
/// Arc identity — zero FFI. Complements the cross-binary legs above.
struct LocalPingLayer {
    name: String,
}

#[async_trait::async_trait]
impl Layer for LocalPingLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "local-ping".to_string(),
            layer_type: LayerType::Backend,
            display_name: "same-binary leg test layer".to_string(),
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

#[test]
fn same_binary_export_import_preserves_arc_identity() {
    let layer: std::sync::Arc<dyn Layer> = std::sync::Arc::new(LocalPingLayer {
        name: "ping".to_string(),
    });
    let handle = export_handle(std::sync::Arc::clone(&layer));
    assert!(
        std::ptr::eq(handle.vtable, &thunks_v2::LAYER_VTABLE),
        "export mints this test binary's own LAYER_VTABLE"
    );
    let imported = unsafe { import_handle(handle) }.expect("same-binary import");
    assert!(
        std::sync::Arc::ptr_eq(&layer, &imported),
        "the same-binary fast path preserves Arc identity (zero FFI)"
    );
}

// ---------------------------------------------------------------------
// Version-band handshake negatives. These drive
// `import_handle`'s handshake logic directly against a hand-built vtable —
// same mechanism as `handoff_core.rs`'s coverage, included here too so
// this file's own suite is a complete a/e/f sweep on its own.
// ---------------------------------------------------------------------

struct DropFlagLayer {
    dropped: std::sync::Arc<AtomicBool>,
}

impl Drop for DropFlagLayer {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Layer for DropFlagLayer {
    fn name(&self) -> &str {
        "drop-flag"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "drop-flag".to_string(),
            layer_type: LayerType::Backend,
            display_name: "version-band negative test layer".to_string(),
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

fn drop_flag_layer() -> (std::sync::Arc<AtomicBool>, std::sync::Arc<dyn Layer>) {
    let dropped = std::sync::Arc::new(AtomicBool::new(false));
    let layer: std::sync::Arc<dyn Layer> = std::sync::Arc::new(DropFlagLayer {
        dropped: dropped.clone(),
    });
    (dropped, layer)
}

/// An `abi_version` mismatch is `IncompatibleType`, and — because the
/// stable vtable header is otherwise valid — the handle IS consumed via its
/// own `drop` slot.
#[test]
fn version_mismatch_is_incompatible_and_disposes_via_drop_slot() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.abi_version = ffi::OVSTORAGE_PLUGIN_ABI_V2_VERSION + 1;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let (dropped, layer) = drop_flag_layer();
    let handle = ffi::LayerHandle {
        state: thunks_v2::leak_layer(layer),
        vtable,
    };
    let err = unsafe { import_handle(handle) }
        .err()
        .expect("mismatched abi_version must fail");
    assert_eq!(err.code(), ErrorCode::IncompatibleType);
    assert!(
        dropped.load(Ordering::SeqCst),
        "a version-mismatched handle is consumed via its (trustworthy) drop slot"
    );
}

/// Undersized `struct_size` is `IncompatibleType`, and — because the header
/// is too small to trust the `drop` slot — the handle is returned
/// undisposed.
#[test]
fn undersized_struct_size_is_incompatible_and_undisposed() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.struct_size = std::mem::size_of::<usize>();
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let (dropped, layer) = drop_flag_layer();
    let state = thunks_v2::leak_layer(layer);
    let err = unsafe { import_handle(ffi::LayerHandle { state, vtable }) }
        .err()
        .expect("undersized vtable must fail");
    assert_eq!(err.code(), ErrorCode::IncompatibleType);
    assert!(
        !dropped.load(Ordering::SeqCst),
        "handle returned undisposed"
    );
    // The caller retains ownership: reconstitute a valid handle and drop it
    // to release the layer we leaked above.
    drop(ffi::LayerHandle {
        state,
        vtable: &thunks_v2::LAYER_VTABLE,
    });
    assert!(dropped.load(Ordering::SeqCst));
}

/// A null `state` or `vtable` is `InvalidArgument`; the handle carries no
/// trustworthy drop slot either way, so it is returned undisposed.
#[test]
fn null_state_and_vtable_are_invalid_argument_and_undisposed() {
    // Null state (with a real vtable): must NOT take the fast path and
    // dereference null.
    let err = unsafe {
        import_handle(ffi::LayerHandle {
            state: std::ptr::null_mut(),
            vtable: &thunks_v2::LAYER_VTABLE,
        })
    }
    .err()
    .expect("null state must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);

    // Null vtable: InvalidArgument, state left untouched (caller retains it).
    let (dropped, layer) = drop_flag_layer();
    let state = thunks_v2::leak_layer(layer);
    let err = unsafe {
        import_handle(ffi::LayerHandle {
            state,
            vtable: std::ptr::null(),
        })
    }
    .err()
    .expect("null vtable must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        !dropped.load(Ordering::SeqCst),
        "handle returned undisposed"
    );
    drop(ffi::LayerHandle {
        state,
        vtable: &thunks_v2::LAYER_VTABLE,
    });
    assert!(dropped.load(Ordering::SeqCst));
}

/// A host cancel must unblock a pull parked on a LIVE update stream, across
/// the FFI. This is the leg the two cancel tests above cannot reach: they
/// cancel the *snapshot* call before it returns, whereas the hazard is a cancel
/// arriving after the snapshot, while the returned update stream is parked.
///
/// It fails if EITHER half of the cancel path is missing, which is why it is
/// written against the returned stream rather than the slot:
///
///   * consumer (`consume_v2`): dropping the `CancelTokenHandle` when the
///     snapshot returns aborts the host→FFI bridge task, so `cancel.cancel()`
///     never signals the plugin-local token and the pull below parks forever;
///   * producer (`thunks_v2`): a `next_fn` that pulls with a bare `block_on`
///     instead of selecting on that token cannot observe the signal even when
///     it does arrive, and parks forever just the same.
///
/// The fixture's stream is `stream::pending()` — it never yields and never
/// ends — so a pull can only return by observing cancellation. The bounded
/// join below turns the "parks forever" failure into a test failure instead of
/// a hung suite.
#[test]
fn cross_binary_cancel_unblocks_a_quiet_update_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(parked_lib) = ParkedLibrary::open() else {
        eprintln!(
            "skipping cross_binary_cancel_unblocks_a_quiet_update_stream: plugin-test-abi cdylib \
             not built"
        );
        return;
    };
    let imported = parked_lib.export_and_import();

    // Release the gate up front: this test is about the update stream, not the
    // snapshot, so the slot itself must complete promptly.
    parked_lib.release();

    let cancel = CancellationToken::new();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("driver runtime");

    let updates = rt.block_on(async {
        let (_snapshot, updates) = Layer::list_address_roots(
            &*imported,
            &ovstorage::Extensions::new(),
            Some(cancel.clone()),
        )
        .await
        .expect("the released introspection slot completes");
        updates.expect("the fixture publishes a live update stream")
    });

    // Park a pull on the quiet stream. `next()` cannot return on its own.
    let (pulled_tx, pulled_rx) = std::sync::mpsc::channel();
    let pull_thread = std::thread::spawn(move || {
        use futures::StreamExt as _;
        let mut updates = updates;
        let item = futures::executor::block_on(updates.next());
        let _ = pulled_tx.send(());
        item.is_none()
    });

    // Nothing should have returned yet — the stream is quiet by construction.
    assert!(
        pulled_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "a pull on a quiet update stream must stay parked until cancelled",
    );

    cancel.cancel();

    pulled_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect(
            "cancelling must unblock the parked pull: either the consumer dropped the FFI cancel \
             handle with the snapshot, or the producer's next_fn is not selecting on the token",
        );
    let ended = pull_thread.join().expect("pull thread panicked");
    assert!(
        ended,
        "a cancelled update-stream pull reports end-of-stream, not an item",
    );

    drop(imported);
}

/// The `authenticate_connection` twin of the update-stream test above: a host
/// cancel must unblock a pull parked on a LIVE auth event stream, across the
/// FFI. Interactive auth is the flow that parks the longest — a browser
/// round-trip or a device-code poll — and the hazard is the same on both
/// halves of the bridge:
///
///   * consumer (`consume_v2`): dropping the `CancelTokenHandle` once the
///     stream is handed back aborts the host→FFI bridge task, so
///     `cancel.cancel()` never signals the plugin-local token;
///   * producer (`thunks_v2`): dropping the `CancelTokenLocal` guard when the
///     open future resolves unregisters the wake callback, so the signal has
///     nothing left to fire even if it does arrive.
///
/// Either omission leaves the pull below parked inside the cdylib forever. So
/// the body asserts nothing until the pulling thread is joined: on the failure
/// path it first fires the fixture's release gate — an escape hatch that
/// reaches the parked pull WITHOUT the FFI cancel bridge — and joins, so the
/// thread is out of the cdylib before any panic unwinds `parked_lib` and
/// unloads it. The alternative, panicking straight from `recv_timeout`,
/// detaches a thread still executing plugin code and turns a regression into a
/// use-after-unload crash.
///
/// The fixture's stream never yields and never ends on its own, and the
/// release gate stays un-fired on the success path, so a pull that returns
/// there can only have observed cancellation.
#[test]
fn cross_binary_cancel_unblocks_a_quiet_auth_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(parked_lib) = ParkedLibrary::open() else {
        eprintln!(
            "skipping cross_binary_cancel_unblocks_a_quiet_auth_stream: plugin-test-abi cdylib \
             not built"
        );
        return;
    };
    let imported = parked_lib.export_and_import();

    let cancel = CancellationToken::new();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("driver runtime");

    // The fixture's auth slot opens immediately — the park is in the stream.
    let stream = rt.block_on(async {
        Layer::authenticate_connection(
            &*imported,
            Request::new(AuthenticateRequest {
                key: ConnectionKey {
                    target: "park".to_string(),
                    id: ConnectionId("park-connection".to_string()),
                },
                capability: InteractiveAuthCapability::Browser,
                auto_open_browser: false,
            }),
            Some(cancel.clone()),
        )
        .await
        .expect("the fixture opens an auth event stream")
    });

    // Park a pull on the quiet stream. `next()` cannot return on its own.
    let (pulled_tx, pulled_rx) = std::sync::mpsc::channel();
    let pull_thread = std::thread::spawn(move || {
        let mut stream = stream;
        let item = stream.next();
        let _ = pulled_tx.send(());
        item.is_none()
    });

    // Nothing should have returned yet — the stream is quiet by construction.
    // Record the outcomes rather than asserting on them: every assertion waits
    // until after the join below.
    let returned_early = pulled_rx
        .recv_timeout(std::time::Duration::from_millis(200))
        .is_ok();

    let unblocked_by_cancel = if returned_early {
        // The pull is already out of the plugin; there is nothing to unblock.
        false
    } else {
        cancel.cancel();
        let unblocked = pulled_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .is_ok();
        if !unblocked {
            // Cancellation never reached the parked pull. Free the thread
            // through the fixture's out-of-band gate so it leaves the cdylib
            // before this test fails and unloads it.
            parked_lib.release();
        }
        unblocked
    };

    let ended = pull_thread.join().expect("pull thread panicked");

    assert!(
        !returned_early,
        "a pull on a quiet auth stream must stay parked until cancelled",
    );
    assert!(
        unblocked_by_cancel,
        "cancelling must unblock the parked pull: either the consumer dropped the FFI cancel \
         handle with the auth stream, or the producer dropped its cancel guard when the slot \
         completed",
    );
    assert!(
        ended,
        "a cancelled auth-stream pull reports end-of-stream, not an event",
    );

    drop(imported);
}
