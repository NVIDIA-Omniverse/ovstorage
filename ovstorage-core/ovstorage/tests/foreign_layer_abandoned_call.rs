// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Rust host must not release a foreign Layer's state while that Layer is
//! still being used by its producer.
//!
//! `race_cancel` (`ovstorage_plugin::cancel`) drops the losing future on
//! cancel, which drops the partially-built Stack, which drops the
//! `ForeignVtableLayer` — and the vtable `drop` slot frees the plugin's
//! `void *state`. A plugin parked inside `add_connection` that does not
//! observe its cancel token then reads state the host has already released.
//! Every in-tree plugin is Rust and clones its layer `Arc` into the spawned
//! task, so it survives by accident of implementation; a C or C++ plugin
//! receives a raw `void *state` the host owns and has no such cushion. The
//! pure-C host pins the Layer for exactly this reason.
//!
//! # The three cases, kept apart on purpose
//!
//! A producer can finish in more than one shape, and a test that covers only
//! one of them passes for the wrong reason against the others:
//!
//! 1. **Asynchronous completion** — the slot returns immediately and a worker
//!    fires `on_complete` later. This is the case the pin is for: the host may
//!    have dropped the Layer in between.
//!    (`foreign_layer_state_survives_an_abandoned_call`)
//! 2. **Synchronous completion** — the producer fires `on_complete` from
//!    inside the slot call and keeps using its state before returning. The
//!    host cannot reach retirement here at all, because it holds `&self`
//!    across the whole invocation; this test pins that reasoning down rather
//!    than leaving it as an argument.
//!    (`a_synchronous_completion_cannot_retire_under_its_own_slot_call`)
//! 3. **Retirement that cannot spawn** — the release must be stranded, never
//!    performed on the producer's own completion frame. The failure is
//!    injected via `RLIMIT_NPROC` and probe-verified, not waited for.
//!    (`a_retirement_that_cannot_spawn_strands_rather_than_releasing_in_place`)
//!
//! 4. **An outcome nobody is left to receive** — on the abandoned path the
//!    completion channel's receiver is already gone, so the outcome comes back
//!    to the producer's own frame. It can carry producer-owned handles (a
//!    change stream, an auth stream, a body), and releasing those there drives
//!    the producer's `drop_fn` re-entrantly for the same reason the Layer's own
//!    release is moved off that thread.
//!    (`an_unread_outcome_is_not_released_in_the_producers_completion_frame`)
//!
//! 5. **Teardown order when this call's pin is not the last reference** — the
//!    outcome and the Layer state are derived from each other, so the state
//!    must go last. That cannot come from "this frame happens to own the
//!    state"; it comes from holding the pin across the outcome's teardown, so
//!    the reference count enforces it.
//!    (`an_unread_outcome_is_torn_down_before_the_layer_state_it_came_from`)
//! 6. **A result handed back alongside an error** — the ABI has the host
//!    reclaim the result, and that reclaim runs the result's producer-owned
//!    `Drop`. It takes the same route out of the frame, and the same ordering.
//!    (`a_result_arriving_alongside_an_error_is_torn_down_before_the_layer_state`)
//!
//! A seventh test covers the other half of the fix — that an abandoned call is
//! actually told to stop, so the pin is bounded
//! (`abandoning_a_call_tells_the_producer_to_stop`).
//!
//! The strand-on-spawn-failure property has a deterministic guard of its own in
//! `ovstorage-plugin` (`dropping_a_retirement_strands_its_work_instead_of_running_it`),
//! which does not depend on being able to make a real spawn fail; case 3 below
//! is the end-to-end leg for it and skips loudly where `RLIMIT_NPROC` is not
//! honoured.
//!
//! # How the use-after-free is made observable
//!
//! No sanitizer is available for Rust here (the pinned toolchain is stable
//! and `rustup` cannot install nightly on this read-only filesystem, which
//! blocks Miri for the same reason), so `-Zsanitizer=address` and Miri are
//! both out. These fixtures instead model a C plugin whose state is its own
//! `mmap`'d page and whose `drop` slot releases it with
//! `mprotect(PROT_NONE)`. That is a release whose use-after-free faults at
//! the MMU rather than silently reading recycled heap: if the host runs the
//! drop slot while the producer is still using its state, the producer's read
//! raises `SIGSEGV`.
//!
//! The repros therefore run in re-executed child processes and the parent
//! asserts on the child's exit status. A crash is the RED signal and names
//! the defect; a clean exit plus the child's own post-conditions is GREEN.
//!
//! Limits of this evidence, stated plainly: `mprotect` is a page-granular
//! stand-in for `free`, so this proves "the host released the state while the
//! producer was still using it", not "glibc's allocator reused those bytes".
//! It is strictly stronger than asserting "the drop slot was not called",
//! because the failure it catches is the producer's own load faulting on
//! released memory. TODO: run ASan against a C plugin driven by the Rust host
//! to cover the heap-reuse half as well; that needs a sanitizer-capable
//! environment this one is not.
//!
//! What none of these can test is the window the ABI leaves open: a producer
//! that keeps touching `state` after firing `on_complete` on the asynchronous
//! path races the retirement thread, and no host can close that race because
//! the frozen ABI has no verb meaning "my call has returned". See `CallPin` in
//! `consume_v2.rs`.

#![cfg(unix)]

use std::ffi::c_void;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use ovstorage::{
    CancellationToken, ConnectionRequest, Error, ErrorCode, Layer, LayerConnectionRequest, Request,
    SecretBundle, WatchDirectoryRequest,
};
use ovstorage_plugin::consume_v2::ForeignVtableLayer;
use ovstorage_plugin::{ffi, marshal, race_cancel, thunks_v2};

/// Re-execution switch: set to the name of the `#[test]` the child re-runs.
const CHILD_ENV: &str = "OVSTORAGE_TEST_302_CHILD";

/// Sentinel the parked call reads back out of its own state after the host
/// has given up on the call. Any value but this means the read did not
/// observe the state the fixture wrote.
const STATE_MAGIC: u64 = 0x0302_0BEE_F302_0BEE;

/// Upper bound on the child's repro; a wedged rendezvous aborts with a named
/// failure instead of hanging CI.
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------
// The fixture: a Layer modelled on a C plugin, not a Rust one
// ---------------------------------------------------------------------

/// The plugin's `void *state`. Lives alone in an `mmap`'d page so the
/// fixture's `drop` slot can release it observably.
#[repr(C)]
struct ParkedPluginState {
    magic: u64,
}

/// Arrival rendezvous: the parked call announces that it has reached its park
/// point, so the test cancels at a moment when the call is provably in flight
/// (no sleeps, no timing assumptions).
static ARRIVED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// Release gate: opened by the test once the host has abandoned the call and
/// dropped the Layer. The parked call waits on this and on nothing else — in
/// particular it never consults its cancel token, which is the whole point.
static RELEASED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// Set once the parked call has fired `on_complete`.
static COMPLETED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// How many times the vtable `drop` slot ran, and what the parked call read
/// back out of its own state when it resumed.
static DROP_SLOT_CALLS: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_MAGIC: AtomicU64 = AtomicU64::new(0);
static DROPPED_BEFORE_RESUME: AtomicBool = AtomicBool::new(false);

/// Threads the producer's `on_complete` and the vtable `drop` slot ran on. The
/// ABI's exclusive-after-drain contract means the drop slot must not run inside
/// the producer's own completion frame, so these must differ.
static COMPLETION_THREAD: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);
static DROP_SLOT_THREAD: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

/// Set only by the spawn-failure leg: make the parked worker read its own state
/// again *after* `on_complete` returns, and record what it saw.
static TOUCH_AFTER_COMPLETION: AtomicBool = AtomicBool::new(false);
static DROPS_AFTER_COMPLETION: AtomicUsize = AtomicUsize::new(usize::MAX);
static OBSERVED_MAGIC_AFTER_COMPLETION: AtomicU64 = AtomicU64::new(0);

fn signal(gate: &(Mutex<bool>, Condvar)) {
    *gate.0.lock().expect("gate mutex") = true;
    gate.1.notify_all();
}

fn wait(gate: &(Mutex<bool>, Condvar)) {
    let mut open = gate.0.lock().expect("gate mutex");
    while !*open {
        open = gate.1.wait(open).expect("gate condvar");
    }
}

/// Raw pointer wrapper so the fixture can move `state` / `user_data` into the
/// thread that models the plugin's worker. The pointers are opaque to the
/// fixture apart from the one deliberate state read.
struct SendPtr(*mut c_void);
// SAFETY: the fixture only passes these pointers through and performs one
// documented read of `state`; both address allocations that outlive the thread
// (or, in the defect case, are exactly what the test is probing).
unsafe impl Send for SendPtr {}

/// `name` slot: the only synchronous slot `ForeignVtableLayer::from_handle`
/// drives at import time.
unsafe extern "C" fn parked_name(_state: *mut c_void, out: *mut ffi::Str) {
    unsafe {
        out.write(marshal::primitive::str_to_ffi(
            "parked-c-plugin".to_string(),
        ))
    };
}

/// `add_connection` slot: park on a thread, ignoring the cancel token
/// entirely, exactly as a non-cooperative C plugin does.
///
/// The borrowed request's owned fields are deliberately not adopted — this
/// fixture leaks them rather than reimplementing the producer-side decoder.
/// A leak is irrelevant to what the test observes and cannot mask a
/// use-after-free.
unsafe extern "C" fn parked_add_connection(
    state: *mut c_void,
    _request: *const ffi::LayerConnectionRequest,
    _cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut c_void,
) {
    let state = SendPtr(state);
    let user_data = SendPtr(user_data);
    std::thread::Builder::new()
        .name("parked-plugin-call".to_string())
        .spawn(move || {
            let state = state;
            let user_data = user_data;

            signal(&ARRIVED);
            wait(&RELEASED);

            // Resume. A C plugin reads its own state here — to find its
            // completion queue, its mutex, its allocator. If the host ran the
            // `drop` slot while this call was outstanding, this load faults.
            DROPPED_BEFORE_RESUME
                .store(DROP_SLOT_CALLS.load(Ordering::SeqCst) > 0, Ordering::SeqCst);
            let magic = unsafe {
                std::ptr::read_volatile(std::ptr::addr_of!(
                    (*(state.0 as *const ParkedPluginState)).magic
                ))
            };
            OBSERVED_MAGIC.store(magic, Ordering::SeqCst);

            let error = ffi::abi_alloc::abi_box(marshal::error::to_ffi(&Error::new(
                ErrorCode::Cancelled,
                "parked add_connection released after the host abandoned it",
            )));
            *COMPLETION_THREAD.lock().expect("completion thread") =
                Some(std::thread::current().id());
            on_complete(
                ErrorCode::Cancelled as i32,
                std::ptr::null_mut(),
                error,
                user_data.0,
            );

            // Post-completion touch, used only by the spawn-failure leg. It is
            // gated because in the normal configuration the retirement thread
            // is racing this read by design (see `CallPin`'s "what this does
            // NOT establish"); the spawn-failure leg is the one configuration
            // where no retirement can be in flight, so the read there is a
            // clean probe for a release that happened on this very thread.
            if TOUCH_AFTER_COMPLETION.load(Ordering::SeqCst) {
                DROPS_AFTER_COMPLETION
                    .store(DROP_SLOT_CALLS.load(Ordering::SeqCst), Ordering::SeqCst);
                let magic = unsafe {
                    std::ptr::read_volatile(std::ptr::addr_of!(
                        (*(state.0 as *const ParkedPluginState)).magic
                    ))
                };
                OBSERVED_MAGIC_AFTER_COMPLETION.store(magic, Ordering::SeqCst);
            }
            signal(&COMPLETED);
        })
        .expect("spawn the parked plugin worker");
}

/// `drop` slot: release the plugin's state the way a C plugin's `free` does,
/// but through `mprotect` so the release is observable. The page stays
/// reserved, so a later access faults deterministically instead of racing
/// whatever would have reused a freed heap block.
unsafe extern "C" fn parked_drop(state: *mut c_void) {
    *DROP_SLOT_THREAD.lock().expect("drop slot thread") = Some(std::thread::current().id());
    DROP_SLOT_CALLS.fetch_add(1, Ordering::SeqCst);
    let rc = unsafe { libc::mprotect(state, page_size(), libc::PROT_NONE) };
    assert_eq!(rc, 0, "mprotect(PROT_NONE) must succeed on the state page");
}

fn page_size() -> usize {
    // SAFETY: `sysconf` is always callable and returns a positive page size.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(value > 0, "sysconf(_SC_PAGESIZE)");
    value as usize
}

/// Allocate the plugin's state in its own page.
fn alloc_state() -> *mut c_void {
    // SAFETY: a fresh anonymous private mapping of exactly one page.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED, "mmap the plugin state page");
    // SAFETY: the mapping is writable and larger than `ParkedPluginState`.
    unsafe {
        (page as *mut ParkedPluginState).write(ParkedPluginState { magic: STATE_MAGIC });
    }
    page
}

fn connection_request() -> Request<LayerConnectionRequest> {
    Request::new(LayerConnectionRequest {
        target: "parked-c-plugin".to_string(),
        connection: ConnectionRequest {
            backend_kind: "parked-c-plugin".to_string(),
            config: Default::default(),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        },
    })
}

// ---------------------------------------------------------------------
// The repro
// ---------------------------------------------------------------------

/// Model the cancel path the C API takes: `ovstorage_stack_build_async`
/// races the whole build against the build
/// token with `race_cancel`, and the losing build future is dropped — taking
/// the partially-built Stack, and with it the last `Arc<ForeignVtableLayer>`,
/// down with it. Here the build is one `add_connection` against one foreign
/// Layer, which is the slot this whole fixture exists to cover.
fn child_repro() {
    // Watchdog: a wedged rendezvous must name itself rather than hang CI.
    std::thread::Builder::new()
        .name("repro-watchdog".to_string())
        .spawn(|| {
            std::thread::sleep(CHILD_TIMEOUT);
            eprintln!("child repro exceeded {CHILD_TIMEOUT:?}; aborting");
            std::process::abort();
        })
        .expect("spawn the watchdog");

    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    // Only these three slots are ever driven: `name` at import, then the
    // parked `add_connection`, then `drop`. The remaining slots stay the real
    // thunks, which expect a `leak_layer` state and must NOT be called against
    // this fixture's raw state.
    vtable.name = parked_name;
    vtable.add_connection = parked_add_connection;
    vtable.drop = parked_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let state = alloc_state();
    let layer = ForeignVtableLayer::from_handle(ffi::LayerHandle { state, vtable }, None)
        .expect("import the parked fixture handle");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let error = runtime.block_on({
        let cancel = CancellationToken::new();
        let layer = layer.clone();
        async move {
            // Cancel the instant the plugin is provably parked inside the
            // slot, so the abandoned call is genuinely in flight.
            let canceller = tokio::task::spawn_blocking({
                let cancel = cancel.clone();
                move || {
                    wait(&ARRIVED);
                    cancel.cancel();
                }
            });
            let outcome = race_cancel(
                Some(&cancel),
                layer.add_connection(connection_request(), Some(cancel.clone())),
            )
            .await;
            canceller.await.expect("the cancelling task");
            outcome.expect_err("the raced build must lose to the cancel")
        }
    });
    assert_eq!(error.code(), ErrorCode::Cancelled);

    // The partially-built Stack unwinds: this is the last reference to the
    // foreign Layer.
    drop(layer);

    // Let the parked call resume and read its own state.
    signal(&RELEASED);
    wait(&COMPLETED);

    assert!(
        !DROPPED_BEFORE_RESUME.load(Ordering::SeqCst),
        "the host ran the vtable `drop` slot while the plugin's call was still \
         outstanding — the plugin's state was released under a live call (#302)",
    );
    assert_eq!(
        OBSERVED_MAGIC.load(Ordering::SeqCst),
        STATE_MAGIC,
        "the parked call must observe the state it was minted with",
    );

    // The pin releases when the completion arrives, and it releases exactly
    // once — a pinned Layer that is never dropped is a leak, and one dropped
    // twice is a double free. The release is deliberately off this thread, so
    // poll for it rather than assuming it has already landed.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while DROP_SLOT_CALLS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        DROP_SLOT_CALLS.load(Ordering::SeqCst),
        1,
        "the pinned Layer must be released exactly once, after the completion",
    );

    // Exclusive-after-drain also forbids running the producer's `drop` slot
    // inside the producer's own `on_complete` frame — its call is still on that
    // stack. The last pin release must hand the state to a thread of the host's.
    let completion = *COMPLETION_THREAD.lock().expect("completion thread");
    let released = *DROP_SLOT_THREAD.lock().expect("drop slot thread");
    assert!(completion.is_some() && released.is_some());
    assert_ne!(
        completion, released,
        "the vtable `drop` slot must not run re-entrantly inside the producer's \
         `on_complete` frame",
    );

    // Keep the runtime alive until here so no shutdown ordering can be
    // mistaken for the property under test.
    drop(runtime);
}

// ---------------------------------------------------------------------
// The other half: an abandoned call must be told to stop
// ---------------------------------------------------------------------

/// Arrival rendezvous and drop-slot counter for the cooperative fixture below.
static COOP_ARRIVED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static COOP_DROP_SLOT_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn coop_name(_state: *mut c_void, out: *mut ffi::Str) {
    unsafe {
        out.write(marshal::primitive::str_to_ffi(
            "cooperative-plugin".to_string(),
        ))
    };
}

/// `add_connection` for a producer that DOES honor its cancel token: it
/// materializes the plugin-local token in the synchronous prologue (the ABI's
/// retention contract) and completes as soon as that token fires.
unsafe extern "C" fn coop_add_connection(
    _state: *mut c_void,
    _request: *const ffi::LayerConnectionRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut c_void,
) {
    assert!(!cancel.is_null(), "the fixture is driven with a token");
    // SAFETY: the borrowed handle is valid for this synchronous prologue, and
    // `cancel_token_from_ffi` takes the refcount that outlives it.
    let local = unsafe { ffi::cancel_token_from_ffi(&*cancel) };
    let user_data = SendPtr(user_data);
    std::thread::Builder::new()
        .name("cooperative-plugin-call".to_string())
        .spawn(move || {
            let user_data = user_data;
            let local = local;
            signal(&COOP_ARRIVED);
            futures::executor::block_on(local.token().cancelled());
            let error = ffi::abi_alloc::abi_box(marshal::error::to_ffi(&Error::new(
                ErrorCode::Cancelled,
                "cooperative add_connection observed its token",
            )));
            on_complete(
                ErrorCode::Cancelled as i32,
                std::ptr::null_mut(),
                error,
                user_data.0,
            );
        })
        .expect("spawn the cooperative plugin worker");
}

unsafe extern "C" fn coop_drop(state: *mut c_void) {
    COOP_DROP_SLOT_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the `Box::into_raw` this fixture minted as its opaque state.
    drop(unsafe { Box::from_raw(state as *mut u64) });
}

/// Pinning a Layer across an abandoned call is only bounded if the producer is
/// actually told to stop. `CancelTokenHandle::drop` aborts the host→FFI bridge
/// task, and that task is the sole path from the host `CancellationToken` to
/// the FFI state the producer polls — so abandoning a call must fire that state
/// directly.
///
/// The host token here is deliberately **never** cancelled: the call is
/// abandoned by dropping its future outright, which is also what a `select!`
/// arm losing to an unrelated event does. That removes the bridge from the
/// picture entirely, so the producer can only learn of the abandonment through
/// the direct signal, and the test cannot pass by racing the bridge.
#[test]
fn abandoning_a_call_tells_the_producer_to_stop() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.name = coop_name;
    vtable.add_connection = coop_add_connection;
    vtable.drop = coop_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let layer = ForeignVtableLayer::from_handle(
        ffi::LayerHandle {
            state: Box::into_raw(Box::new(0u64)) as *mut c_void,
            vtable,
        },
        None,
    )
    .expect("import the cooperative fixture handle");

    let never_cancelled = CancellationToken::new();
    runtime.block_on(async {
        let call = layer.add_connection(connection_request(), Some(never_cancelled.clone()));
        tokio::pin!(call);
        let arrived = tokio::task::spawn_blocking(|| wait(&COOP_ARRIVED));
        tokio::select! {
            _ = &mut call => panic!("the parked call must not answer on its own"),
            joined = arrived => joined.expect("the arrival task"),
        }
        // `call` is dropped here: the host abandoned it.
    });
    drop(layer);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while COOP_DROP_SLOT_CALLS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        COOP_DROP_SLOT_CALLS.load(Ordering::SeqCst),
        1,
        "abandoning the call must fire the producer's cancel token, so the producer \
         completes and the pinned Layer is released",
    );
    drop(runtime);
}

/// Run `body` in this process when we are the child, otherwise re-execute this
/// test binary as a child running only `test_name` and assert it exited
/// cleanly. A fault in the child is the RED signal these repros are built to
/// produce, so it is reported by name rather than as a bare exit code.
fn in_child(test_name: &str, body: fn()) {
    if std::env::var_os(CHILD_ENV).is_some() {
        body();
        return;
    }

    let exe = std::env::current_exe().expect("current test binary");
    let status = Command::new(exe)
        .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, test_name)
        .status()
        .expect("re-execute this test binary as the repro child");

    if let Some(signal) = status.signal() {
        panic!(
            "the repro child died on signal {signal}: the host released the foreign Layer's \
             state while the plugin was still using it (#302)",
        );
    }
    assert!(
        status.success(),
        "the repro child failed: {status:?} (see its output above)",
    );
}

#[test]
fn foreign_layer_state_survives_an_abandoned_call() {
    in_child(
        "foreign_layer_state_survives_an_abandoned_call",
        child_repro,
    );
}

// ---------------------------------------------------------------------
// Case 2: a producer that completes SYNCHRONOUSLY, inside the slot call
// ---------------------------------------------------------------------

/// Drop-slot counter and observations for the synchronous fixture.
static SYNC_DROP_SLOT_CALLS: AtomicUsize = AtomicUsize::new(0);
static SYNC_DROPS_AT_TOUCH: AtomicUsize = AtomicUsize::new(usize::MAX);
static SYNC_OBSERVED_MAGIC: AtomicU64 = AtomicU64::new(0);
/// ABI-heap balance read on entry to the producer's slot call, so the leg can
/// weigh the completion envelope's round trip in isolation. Reading it here
/// rather than around the whole call excludes the request buffers the host
/// minted before the call, which this fixture (unlike a real producer) never
/// consumes.
static SYNC_ABI_AT_SLOT_ENTRY: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

unsafe extern "C" fn sync_name(_state: *mut c_void, out: *mut ffi::Str) {
    unsafe {
        out.write(marshal::primitive::str_to_ffi(
            "synchronous-c-plugin".to_string(),
        ))
    };
}

/// `add_connection` for a producer that fires `on_complete` from **inside** the
/// slot call and then keeps using its own state before returning — the shape
/// the ABI explicitly allows and the one an "invocation pin" would be needed
/// for, if the host could reach retirement here.
unsafe extern "C" fn sync_add_connection(
    state: *mut c_void,
    _request: *const ffi::LayerConnectionRequest,
    _cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut c_void,
) {
    SYNC_ABI_AT_SLOT_ENTRY.store(ffi::abi_alloc::abi_live_bytes(), Ordering::SeqCst);
    let error = ffi::abi_alloc::abi_box(marshal::error::to_ffi(&Error::new(
        ErrorCode::Cancelled,
        "synchronous add_connection completed inside its own slot call",
    )));
    on_complete(
        ErrorCode::Cancelled as i32,
        std::ptr::null_mut(),
        error,
        user_data,
    );

    // Still inside the slot. A release triggered by the completion above would
    // have unmapped this page.
    SYNC_DROPS_AT_TOUCH.store(
        SYNC_DROP_SLOT_CALLS.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    let magic = unsafe {
        std::ptr::read_volatile(std::ptr::addr_of!(
            (*(state as *const ParkedPluginState)).magic
        ))
    };
    SYNC_OBSERVED_MAGIC.store(magic, Ordering::SeqCst);
}

unsafe extern "C" fn sync_drop(state: *mut c_void) {
    SYNC_DROP_SLOT_CALLS.fetch_add(1, Ordering::SeqCst);
    let rc = unsafe { libc::mprotect(state, page_size(), libc::PROT_NONE) };
    assert_eq!(rc, 0, "mprotect(PROT_NONE) must succeed on the state page");
}

/// A synchronous completion cannot retire the Layer under its own slot call.
///
/// The host borrows `&self` for the whole of `Layer::add_connection`, and the
/// future that holds that borrow cannot be dropped while the slot invocation is
/// on the stack — there is no await point between `begin_call` and the slot
/// returning. So while a synchronous `on_complete` runs, the Layer's own
/// reference is live and the call's pin is never the last one: `Arc::into_inner`
/// yields `None` and no retirement is scheduled. This test drives that path
/// against the poison-page fixture so a release inside the slot would fault,
/// and separately asserts the drop slot had not run when the producer resumed.
fn sync_completion_child() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.name = sync_name;
    vtable.add_connection = sync_add_connection;
    vtable.drop = sync_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let state = alloc_state();
    let layer = ForeignVtableLayer::from_handle(ffi::LayerHandle { state, vtable }, None)
        .expect("import the synchronous fixture handle");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let cancel = CancellationToken::new();
    let error = runtime.block_on(async {
        race_cancel(
            Some(&cancel),
            layer.add_connection(connection_request(), Some(cancel.clone())),
        )
        .await
        .expect_err("the fixture always completes with Cancelled")
    });
    assert_eq!(error.code(), ErrorCode::Cancelled);

    // This leg runs alone in a child process, so the process-wide ABI-heap
    // balance over the window is attributable to this one completion. The
    // fixture is a foreign producer, and the host reclaims a producer's error
    // envelope with `abi_alloc::abi_unbox` (`loaded_v2::LoadedV2Layer`): an
    // envelope minted on the Rust global allocator instead debits the ABI heap
    // without ever having credited it, which against a plugin running jemalloc
    // or mimalloc is heap corruption rather than an accounting figure. It is
    // invisible here only because a test binary's global allocator happens to
    // be `System`, which is not a property a foreign plugin shares.
    let abi_delta =
        ffi::abi_alloc::abi_live_bytes() - SYNC_ABI_AT_SLOT_ENTRY.load(Ordering::SeqCst);
    assert_eq!(
        abi_delta, 0,
        "the completion left {abi_delta} bytes of ABI-heap imbalance between \
         the producer's mint and the host's reclaim; a negative figure means \
         the producer minted the envelope off the ABI heap",
    );

    assert_eq!(
        SYNC_DROPS_AT_TOUCH.load(Ordering::SeqCst),
        0,
        "the drop slot must not have run while the producer's slot call was still \
         on the stack, however it completed",
    );
    assert_eq!(
        SYNC_OBSERVED_MAGIC.load(Ordering::SeqCst),
        STATE_MAGIC,
        "the producer must still see its own state after completing synchronously",
    );
    assert_eq!(
        SYNC_DROP_SLOT_CALLS.load(Ordering::SeqCst),
        0,
        "the Layer is still held, so nothing is released yet",
    );

    // Now the host really is done with it: this is the drained release, and it
    // runs inline on this thread because no producer frame is involved.
    drop(layer);
    assert_eq!(
        SYNC_DROP_SLOT_CALLS.load(Ordering::SeqCst),
        1,
        "dropping the last reference releases the state exactly once",
    );
    drop(runtime);
}

#[test]
fn a_synchronous_completion_cannot_retire_under_its_own_slot_call() {
    in_child(
        "a_synchronous_completion_cannot_retire_under_its_own_slot_call",
        sync_completion_child,
    );
}

// ---------------------------------------------------------------------
// Case 3: retirement cannot spawn — strand, never release in place
// ---------------------------------------------------------------------

/// Lower `RLIMIT_NPROC` far enough that thread creation fails, and confirm by
/// probe that it really does. Returns `false` when the limit does not bite in
/// this environment, so the caller can skip rather than assert on a mechanism
/// that is not actually armed.
fn arm_thread_spawn_failure() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `setrlimit` with a valid `rlimit`; lowering the soft limit is
    // always permitted, and this process spawns nothing else afterwards.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) };
    if rc != 0 {
        return false;
    }
    // Probe: a limit that does not actually block thread creation would leave
    // the leg silently unarmed and passing for the wrong reason.
    match std::thread::Builder::new().spawn(|| {}) {
        Ok(handle) => {
            handle.join().expect("probe thread");
            false
        }
        Err(_) => true,
    }
}

/// When the retirement thread cannot be spawned, the state must be **stranded**,
/// not released on the completing thread.
///
/// `Builder::spawn` takes its closure by value and drops it on failure, so the
/// naive `spawn(move || drop(state))` releases the state right there — on the
/// producer's `on_complete` frame, which is the single thread this machinery
/// exists to keep the drop slot off. The failure is injected (`RLIMIT_NPROC`),
/// not waited for, and the injection is probe-verified before it is relied on.
fn spawn_failure_child() {
    std::thread::Builder::new()
        .name("repro-watchdog".to_string())
        .spawn(|| {
            std::thread::sleep(CHILD_TIMEOUT);
            eprintln!("child repro exceeded {CHILD_TIMEOUT:?}; aborting");
            std::process::abort();
        })
        .expect("spawn the watchdog");

    TOUCH_AFTER_COMPLETION.store(true, Ordering::SeqCst);

    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.name = parked_name;
    vtable.add_connection = parked_add_connection;
    vtable.drop = parked_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let state = alloc_state();
    let layer = ForeignVtableLayer::from_handle(ffi::LayerHandle { state, vtable }, None)
        .expect("import the parked fixture handle");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let error = runtime.block_on({
        let cancel = CancellationToken::new();
        let layer = layer.clone();
        async move {
            let canceller = tokio::task::spawn_blocking({
                let cancel = cancel.clone();
                move || {
                    wait(&ARRIVED);
                    cancel.cancel();
                }
            });
            let outcome = race_cancel(
                Some(&cancel),
                layer.add_connection(connection_request(), Some(cancel.clone())),
            )
            .await;
            canceller.await.expect("the cancelling task");
            outcome.expect_err("the raced build must lose to the cancel")
        }
    });
    assert_eq!(error.code(), ErrorCode::Cancelled);
    drop(layer);

    // Every thread this test needs now exists; from here the only spawn
    // attempt in the process is the retirement thread.
    if !arm_thread_spawn_failure() {
        eprintln!(
            "skipping the end-to-end spawn-failure leg: RLIMIT_NPROC does not block thread \
             creation in this environment. The property itself is still covered, \
             deterministically and without injection, by ovstorage-plugin's \
             `dropping_a_retirement_strands_its_work_instead_of_running_it`."
        );
        signal(&RELEASED);
        wait(&COMPLETED);
        return;
    }

    signal(&RELEASED);
    wait(&COMPLETED);

    assert_eq!(
        DROPS_AFTER_COMPLETION.load(Ordering::SeqCst),
        0,
        "a retirement that cannot be spawned must strand the state, not release it \
         on the producer's own completion frame",
    );
    assert_eq!(
        OBSERVED_MAGIC_AFTER_COMPLETION.load(Ordering::SeqCst),
        STATE_MAGIC,
        "the producer must still see its own state after `on_complete` returns",
    );
    assert_eq!(
        DROP_SLOT_CALLS.load(Ordering::SeqCst),
        0,
        "a stranded Layer is never released",
    );
}

#[test]
fn a_retirement_that_cannot_spawn_strands_rather_than_releasing_in_place() {
    in_child(
        "a_retirement_that_cannot_spawn_strands_rather_than_releasing_in_place",
        spawn_failure_child,
    );
}

// ---------------------------------------------------------------------
// Case 4: the outcome nobody is left to receive
// ---------------------------------------------------------------------

/// Rendezvous and observations for the producer that answers an abandoned call
/// with a producer-owned stream.
static STREAM_ARRIVED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static STREAM_RELEASED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static STREAM_COMPLETED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static STREAM_DROP_FN_CALLS: AtomicUsize = AtomicUsize::new(0);
static STREAM_COMPLETION_THREAD: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);
static STREAM_DROP_FN_THREAD: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

unsafe extern "C" fn stream_name(_state: *mut c_void, out: *mut ffi::Str) {
    unsafe {
        out.write(marshal::primitive::str_to_ffi(
            "streaming-c-plugin".to_string(),
        ))
    };
}

unsafe extern "C" fn stream_next(
    _state: *mut c_void,
    _out_item: *mut ffi::BackendChangeEvent,
    _out_error: *mut ffi::Error,
) -> ffi::StreamStep {
    ffi::StreamStep::Ended
}

/// The producer's own teardown for the stream it handed back. This is arbitrary
/// producer code — in a C plugin it unlocks and destroys the mutex the
/// completing worker is still holding — so the host must not drive it from
/// inside `on_complete`.
unsafe extern "C" fn stream_drop_fn(_state: *mut c_void) {
    *STREAM_DROP_FN_THREAD.lock().expect("stream drop thread") = Some(std::thread::current().id());
    STREAM_DROP_FN_CALLS.fetch_add(1, Ordering::SeqCst);
}

/// `watch_directory` that parks, then answers with a producer-owned change
/// stream — long after the host gave up waiting for it.
unsafe extern "C" fn stream_watch_directory(
    _state: *mut c_void,
    _request: *const ffi::WatchDirectoryRequest,
    _cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut c_void,
) {
    let user_data = SendPtr(user_data);
    std::thread::Builder::new()
        .name("streaming-plugin-call".to_string())
        .spawn(move || {
            let user_data = user_data;
            signal(&STREAM_ARRIVED);
            wait(&STREAM_RELEASED);

            let stream = ffi::abi_alloc::abi_box(ffi::BackendChangeStream {
                state: std::ptr::dangling_mut(),
                next_fn: stream_next,
                drop_fn: stream_drop_fn,
            });
            *STREAM_COMPLETION_THREAD.lock().expect("completion thread") =
                Some(std::thread::current().id());
            on_complete(0, stream as *mut c_void, std::ptr::null_mut(), user_data.0);
            signal(&STREAM_COMPLETED);
        })
        .expect("spawn the streaming plugin worker");
}

unsafe extern "C" fn stream_layer_drop(_state: *mut c_void) {}

fn watch_request() -> Request<WatchDirectoryRequest> {
    Request::new(WatchDirectoryRequest {
        prefix: ovstorage::Url::parse("mem://watched/").expect("prefix"),
        options: Default::default(),
    })
}

/// An outcome the host is no longer waiting for must not be released inside the
/// producer's `on_complete` frame.
///
/// On the abandoned-call path the receiver is already gone, so `tx.send` hands
/// the value back. Dropping it there runs the producer's own `drop_fn` — for
/// `watch_directory` that is the change stream it just minted — re-entrantly
/// under its own completion, which is precisely the hazard the Layer's own
/// release is moved off that thread to avoid. The pure-C host sequences the
/// same pair the same way: `ovc_stack_build_slot_reenters_plugin` counts an
/// unread outcome on its own as a reason to defer.
#[test]
fn an_unread_outcome_is_not_released_in_the_producers_completion_frame() {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.name = stream_name;
    vtable.watch_directory = stream_watch_directory;
    vtable.drop = stream_layer_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let layer = ForeignVtableLayer::from_handle(
        ffi::LayerHandle {
            state: Box::into_raw(Box::new(0u64)) as *mut c_void,
            vtable,
        },
        None,
    )
    .expect("import the streaming fixture handle");

    let error = runtime.block_on({
        let cancel = CancellationToken::new();
        let layer = layer.clone();
        async move {
            let canceller = tokio::task::spawn_blocking({
                let cancel = cancel.clone();
                move || {
                    wait(&STREAM_ARRIVED);
                    cancel.cancel();
                }
            });
            let outcome = race_cancel(
                Some(&cancel),
                layer.watch_directory(watch_request(), Some(cancel.clone())),
            )
            .await;
            canceller.await.expect("the cancelling task");
            // `ChangeStream` is not `Debug`, so unwrap the arm by hand.
            match outcome {
                Ok(_) => panic!("the raced watch must lose to the cancel"),
                Err(error) => error,
            }
        }
    });
    assert_eq!(error.code(), ErrorCode::Cancelled);

    // Keep the Layer alive, so this leg isolates the outcome from the Layer's
    // own pin: the only thing the completion can release is the stream.
    signal(&STREAM_RELEASED);
    wait(&STREAM_COMPLETED);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while STREAM_DROP_FN_CALLS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        STREAM_DROP_FN_CALLS.load(Ordering::SeqCst),
        1,
        "the unread stream must still be released exactly once — not leaked, not twice",
    );

    let completion = *STREAM_COMPLETION_THREAD.lock().expect("completion thread");
    let released = *STREAM_DROP_FN_THREAD.lock().expect("stream drop thread");
    assert!(completion.is_some() && released.is_some());
    assert_ne!(
        completion, released,
        "the producer's `drop_fn` for an unread outcome must not run on the thread \
         that is still inside its own `on_complete`",
    );

    drop(layer);
    drop(runtime);
}

// ---------------------------------------------------------------------
// Case 6: teardown ORDER, when this call's pin is not the last reference
// ---------------------------------------------------------------------

/// Gates and counters for the ordering fixture. The stream's `drop_fn` parks so
/// the test can drop the Layer while that teardown is provably in flight — the
/// window in which an unordered release would free the state underneath it.
static ORDER_ARRIVED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_RELEASED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_COMPLETED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_STREAM_DROP_ENTERED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_STREAM_DROP_GATE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_STREAM_DROP_DONE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static ORDER_LAYER_DROPS: AtomicUsize = AtomicUsize::new(0);
static ORDER_LAYER_DROPS_AT_STREAM_TEARDOWN: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Set for the leg that answers with a result *and* an error, so the orphan
/// path in `decode_async_result` is the one under test.
static ORDER_ALSO_SEND_ERROR: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn order_name(_state: *mut c_void, out: *mut ffi::Str) {
    unsafe {
        out.write(marshal::primitive::str_to_ffi(
            "ordering-c-plugin".to_string(),
        ))
    };
}

unsafe extern "C" fn order_stream_next(
    _state: *mut c_void,
    _out_item: *mut ffi::BackendChangeEvent,
    _out_error: *mut ffi::Error,
) -> ffi::StreamStep {
    ffi::StreamStep::Ended
}

/// The producer's teardown for the stream. It parks at a gate so the test can
/// drop the Layer while this is running, then records whether the Layer's own
/// `drop` slot has been driven yet. It must not have been: the stream is
/// derived from that state.
unsafe extern "C" fn order_stream_drop_fn(_state: *mut c_void) {
    signal(&ORDER_STREAM_DROP_ENTERED);
    wait(&ORDER_STREAM_DROP_GATE);
    ORDER_LAYER_DROPS_AT_STREAM_TEARDOWN
        .store(ORDER_LAYER_DROPS.load(Ordering::SeqCst), Ordering::SeqCst);
    signal(&ORDER_STREAM_DROP_DONE);
}

unsafe extern "C" fn order_layer_drop(_state: *mut c_void) {
    ORDER_LAYER_DROPS.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn order_watch_directory(
    _state: *mut c_void,
    _request: *const ffi::WatchDirectoryRequest,
    _cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::OnComplete,
    user_data: *mut c_void,
) {
    let user_data = SendPtr(user_data);
    std::thread::Builder::new()
        .name("ordering-plugin-call".to_string())
        .spawn(move || {
            let user_data = user_data;
            signal(&ORDER_ARRIVED);
            wait(&ORDER_RELEASED);

            let stream = ffi::abi_alloc::abi_box(ffi::BackendChangeStream {
                state: std::ptr::dangling_mut(),
                next_fn: order_stream_next,
                drop_fn: order_stream_drop_fn,
            });
            // The result-and-error leg: the ABI lets a producer hand back both,
            // and the host must reclaim the result. Reclaiming it runs the
            // stream's `drop_fn`, so it takes the same orphan route.
            let error = if ORDER_ALSO_SEND_ERROR.load(Ordering::SeqCst) {
                ffi::abi_alloc::abi_box(marshal::error::to_ffi(&Error::new(
                    ErrorCode::Internal,
                    "producer answered with a result and an error",
                )))
            } else {
                std::ptr::null_mut()
            };
            on_complete(0, stream as *mut c_void, error, user_data.0);
            signal(&ORDER_COMPLETED);
        })
        .expect("spawn the ordering plugin worker");
}

/// Drive one leg of the ordering fixture and assert the Layer's `drop` slot has
/// not run when the producer's stream teardown is in flight.
fn run_ordering_leg(also_send_error: bool) {
    std::thread::Builder::new()
        .name("repro-watchdog".to_string())
        .spawn(|| {
            std::thread::sleep(CHILD_TIMEOUT);
            eprintln!("ordering leg exceeded {CHILD_TIMEOUT:?}; aborting");
            std::process::abort();
        })
        .expect("spawn the watchdog");

    ORDER_ALSO_SEND_ERROR.store(also_send_error, Ordering::SeqCst);

    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.name = order_name;
    vtable.watch_directory = order_watch_directory;
    vtable.drop = order_layer_drop;
    let vtable: &'static ffi::LayerVTableV1 = Box::leak(Box::new(vtable));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the host runtime");

    let layer = ForeignVtableLayer::from_handle(
        ffi::LayerHandle {
            state: Box::into_raw(Box::new(0u64)) as *mut c_void,
            vtable,
        },
        None,
    )
    .expect("import the ordering fixture handle");

    runtime.block_on({
        let cancel = CancellationToken::new();
        let layer = layer.clone();
        async move {
            let canceller = tokio::task::spawn_blocking({
                let cancel = cancel.clone();
                move || {
                    wait(&ORDER_ARRIVED);
                    cancel.cancel();
                }
            });
            let outcome = race_cancel(
                Some(&cancel),
                layer.watch_directory(watch_request(), Some(cancel.clone())),
            )
            .await;
            canceller.await.expect("the cancelling task");
            assert!(outcome.is_err(), "the raced watch must lose to the cancel");
        }
    });

    // The Layer is still held here, so when the completion lands this call's pin
    // is NOT the last reference — the case where teardown order cannot come
    // from "this frame happens to own the state".
    signal(&ORDER_RELEASED);
    wait(&ORDER_STREAM_DROP_ENTERED);

    // The producer's stream teardown is now provably in flight. Drop the host's
    // last handle on the Layer: with the pin held across that teardown this is
    // simply not the last reference, so nothing is released. Without it the
    // count reaches zero here and the `drop` slot runs on this very thread,
    // under the stream teardown that is still running.
    drop(layer);

    signal(&ORDER_STREAM_DROP_GATE);
    // Wait for the stream teardown to finish before reading what it observed;
    // otherwise the assertion below races it and reports "never ran" rather
    // than the ordering violation it is there to name.
    wait(&ORDER_STREAM_DROP_DONE);
    wait(&ORDER_COMPLETED);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while ORDER_LAYER_DROPS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }

    assert_eq!(
        ORDER_LAYER_DROPS_AT_STREAM_TEARDOWN.load(Ordering::SeqCst),
        0,
        "the Layer's `drop` slot ran while the producer's stream teardown — which is \
         derived from that same state — was still in flight",
    );
    assert_eq!(
        ORDER_LAYER_DROPS.load(Ordering::SeqCst),
        1,
        "the Layer must still be released exactly once, after the stream it produced",
    );
    drop(runtime);
}

/// Teardown order must come from the reference count, not from this frame
/// happening to hold the last reference.
///
/// `complete_call` retires the unread outcome and the Layer state together, and
/// keeps the call's pin alive until the outcome is gone. That is what makes the
/// order hold when the pin is *not* the last reference — here the host still
/// holds the Layer when the completion lands, and drops it midway through the
/// producer's stream teardown.
#[test]
fn an_unread_outcome_is_torn_down_before_the_layer_state_it_came_from() {
    in_child(
        "an_unread_outcome_is_torn_down_before_the_layer_state_it_came_from",
        || run_ordering_leg(false),
    );
}

// ---------------------------------------------------------------------
// Case 7: a result handed back alongside an error
// ---------------------------------------------------------------------

/// A producer may answer with both a `result` and an `error`; the ABI makes the
/// host reclaim the result. That reclaim runs the result's `Drop` — for
/// `watch_directory`, the change stream's producer-owned `drop_fn` — so it must
/// take the same route out of the producer's frame as an unread outcome, and be
/// ordered ahead of the Layer state the same way.
///
/// This is the `decode_async_result` orphan path; the two `list_*`
/// snapshot-decode arms and the read-body metadata arm reach the retirement
/// through the same chokepoint.
#[test]
fn a_result_arriving_alongside_an_error_is_torn_down_before_the_layer_state() {
    in_child(
        "a_result_arriving_alongside_an_error_is_torn_down_before_the_layer_state",
        || run_ordering_leg(true),
    );
}
