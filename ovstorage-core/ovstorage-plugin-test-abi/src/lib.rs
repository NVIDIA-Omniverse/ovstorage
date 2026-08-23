// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib export of the conformance test backend.
//!
//! The `ovstorage_layer_plugin!` invocation lives here — NOT in
//! `ovstorage-plugin-test` — because the macro emits the fixed-name
//! `ovstorage_plugin_manifest_v1` / `ovstorage_plugin_init_v1` entry
//! points as strong `#[no_mangle]` symbols into every crate type,
//! including the rlib. Keeping the harness rlib symbol-free lets other
//! plugin crates (which export the same entry points from their own
//! cdylibs) link the harness into their test binaries for
//! registry-driven conformance runs. The dlopen coverage of this
//! artifact lives in `tests/loaded.rs`.
//!
//! Below the macro, this cdylib additionally ships a
//! **park-until-released-or-cancelled** introspection fixture, hand-rolled
//! outside the plugin manifest/init handshake the same way
//! `ovstorage-plugin-test-layer`'s `ovstorage_test_export_stack` is. It exists
//! so the cross-`.so` v8 ABI tests — and, later, the C/C++ parked-build tests
//! that drive this cdylib via `OVSTORAGE_PLUGIN_TEST_SO` — can prove the async
//! v8 dynamic-query slots (`root_info_for` / `list_address_roots` /
//! `list_connections`) genuinely park across the FFI and unblock on either an
//! external release signal or a `CancelTokenFFI`. See the "Parked introspection
//! fixture" section near the bottom of this file for the exact contract.

use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use ovstorage_plugin::*;

ovstorage_plugin::ovstorage_layer_plugin!(
    backend,
    ovstorage_plugin_test::TestLayerFactory::default,
    test_only
);

// =====================================================================
// Parked introspection fixture
// =====================================================================
//
// Everything below is independent of the plugin manifest/init handshake the
// macro above emits — the `ovstorage_test_*` symbols are plain `#[no_mangle]`
// entry points a host resolves directly via `libloading` / `dlsym` (mirroring
// `ovstorage-plugin-test-layer`'s `ovstorage_test_export_stack` /
// `ovstorage_test_release_handoff_gate`), so this fixture is usable across a
// process/FFI boundary without any Rust test helpers.
//
// CONTRACT (also driven by the C/C++ parked-build unit, wu12, via
// `OVSTORAGE_PLUGIN_TEST_SO`):
//
//   1. `ovstorage_test_export_parked_stack(out)` writes a `LayerHandle` over a
//      `ParkBackend` and resets the fixture's gate to the un-released state.
//      Import it (`import_handle`) to drive its slots across the FFI.
//   2. Each of the three dynamic-query slots — `root_info_for`,
//      `list_address_roots`, `list_connections` — signals arrival, then PARKS.
//      `stat` stays immediate, so a host can prove a sibling op keeps running
//      while an introspection is parked.
//   3. `ovstorage_test_park_wait_arrived()` blocks the caller until a parked op
//      reaches its park point — a deterministic in-flight rendezvous, no sleeps.
//   4. `ovstorage_test_release_park_gate()` releases every parked op; they then
//      complete normally. Alternatively, firing the op's own `CancelTokenFFI`
//      makes it complete with `Cancelled`.
//   5. `authenticate_connection` opens immediately and returns a quiet auth
//      event stream whose `next` parks until the op's own `CancelTokenFFI`
//      fires, so a host can prove cancellation still reaches a live auth
//      stream after the slot itself has completed. The release gate (3/4
//      above) is the second arm of that park: it frees a parked pull without
//      the FFI cancel bridge, so a host can recover its pulling thread when
//      the bridge under test is broken.

/// The release gate for parked introspection ops. Cancelling this token
/// releases every op currently parked in a dynamic-query slot;
/// [`ovstorage_test_export_parked_stack`] installs a fresh (un-cancelled) token
/// so each export starts un-released. An external host fires it through
/// [`ovstorage_test_release_park_gate`].
static PARK_RELEASE_GATE: Mutex<Option<CancellationToken>> = Mutex::new(None);

/// Clone the current release token (minting one on first use). A parked op
/// clones this at park time and waits on its `cancelled()`; a fresh token from
/// [`reset_park_release_gate`] is un-cancelled, so a subsequent park waits anew.
fn park_release_token() -> CancellationToken {
    PARK_RELEASE_GATE
        .lock()
        .expect("park release gate")
        .get_or_insert_with(CancellationToken::new)
        .clone()
}

/// Install a fresh, un-cancelled release token so the next export's parked ops
/// block until explicitly released.
fn reset_park_release_gate() {
    *PARK_RELEASE_GATE.lock().expect("park release gate") = Some(CancellationToken::new());
}

/// Release every parked introspection op. Idempotent; safe to call across the
/// FFI boundary from a host process that resolved this symbol.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_release_park_gate() {
    park_release_token().cancel();
}

/// The two ends of the arrival rendezvous channel, guarded for shared access.
type ParkArrivals = (Mutex<mpsc::Sender<()>>, Mutex<mpsc::Receiver<()>>);

/// Arrival rendezvous: a parked op sends one message the instant it reaches its
/// park point; [`ovstorage_test_park_wait_arrived`] blocks a host until one
/// arrives. An `mpsc` channel, so several ops can arrive and a host can wait
/// for each independently — deterministic, no sleeps.
fn park_arrivals() -> &'static ParkArrivals {
    static ARRIVALS: OnceLock<ParkArrivals> = OnceLock::new();
    ARRIVALS.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        (Mutex::new(tx), Mutex::new(rx))
    })
}

/// Announce (non-blocking) that a parked op has reached its park point.
fn signal_park_arrived() {
    let _ = park_arrivals()
        .0
        .lock()
        .expect("park arrival sender")
        .send(());
}

/// Drop any stale arrival messages left by a prior export so a fresh
/// `ovstorage_test_park_wait_arrived` waits on THIS export's op.
fn drain_park_arrivals() {
    let rx = park_arrivals().1.lock().expect("park arrival receiver");
    while rx.try_recv().is_ok() {}
}

/// Block until a parked op reaches its park point (a matching
/// `signal_park_arrived`). Deterministic in-flight rendezvous — no sleeps —
/// so a host can fire cancel/release knowing the op is genuinely parked.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_park_wait_arrived() {
    let _ = park_arrivals()
        .1
        .lock()
        .expect("park arrival receiver")
        .recv();
}

/// Park until the release gate fires or the op's own cancel token trips.
/// Signals arrival first, then awaits — both waits are `.await`s that yield the
/// shared plugin runtime, so a sibling op (`stat`) keeps running on the single
/// worker thread while this op is parked. Returns `Err(Cancelled)` when the
/// cancel token wins the race, `Ok(())` when released.
async fn park_until_released_or_cancelled(cancel: &Option<CancellationToken>) -> Result<()> {
    let release = park_release_token();
    signal_park_arrived();
    match cancel {
        Some(token) => {
            use futures::future::{Either, select};
            let released = std::pin::pin!(release.cancelled());
            let cancelled = std::pin::pin!(token.cancelled());
            match select(released, cancelled).await {
                Either::Left(_) => Ok(()),
                Either::Right(_) => Err(Error::new(
                    ErrorCode::Cancelled,
                    "test-plugin: parked introspection cancelled",
                )),
            }
        }
        None => {
            release.cancelled().await;
            Ok(())
        }
    }
}

/// Backend layer kind the parked fixture advertises (never registered on the
/// cdylib's `ovstorage_plugin_init_v1` factory set — reached only via
/// [`ovstorage_test_export_parked_stack`]).
const PARK_KIND: &str = "test-park";
/// Root the parked fixture owns.
const PARK_ROOT: &str = "park://data/";
/// The single object [`ParkBackend::stat`] serves, so a host can prove a
/// sibling op progresses while an introspection is parked.
const PARK_OBJECT: &str = "park://data/a.bin";
/// Byte length reported for [`PARK_OBJECT`].
const PARK_PAYLOAD_LEN: u64 = b"parked fixture payload".len() as u64;

fn park_object_info(address: Url, size: u64) -> ObjectInfo {
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

fn park_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: PARK_KIND.to_string(),
        layer_type: LayerType::Backend,
        display_name: "Parked introspection test backend".to_string(),
        description: Some("Parks its dynamic-query slots until released or cancelled".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

/// Backend whose three dynamic-query slots (`root_info_for`,
/// `list_address_roots`, `list_connections`) park until released or cancelled;
/// `stat` stays immediate so a host can prove a sibling op keeps running while
/// an introspection is parked. Exported by
/// [`ovstorage_test_export_parked_stack`]; kept separate from the conformance
/// `TestLayer` so this fixture's process-wide gate can't leak into the
/// loader-path tests in `tests/loaded.rs`.
struct ParkBackend {
    name: String,
    root: Url,
}

impl ParkBackend {
    fn seeded() -> Arc<Self> {
        Arc::new(Self {
            name: "park".to_string(),
            root: Url::parse(PARK_ROOT).expect("park root parses"),
        })
    }

    fn root_info(&self) -> RootInfo {
        RootInfo {
            root: self.root.clone(),
            display_name: Some("Parked fixture".to_string()),
            layer_kind: PARK_KIND.to_string(),
            connection_id: None,
            // Static route, no owning connection — so no owning target either.
            owning_target: None,
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::Native,
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }
}

#[async_trait]
impl Layer for ParkBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        park_descriptor()
    }

    async fn root_info_for(
        &self,
        _url: &Url,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        park_until_released_or_cancelled(&cancel).await?;
        Ok(self.root_info())
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        park_until_released_or_cancelled(&cancel).await?;
        // A deliberately QUIET update stream: it never yields and never ends,
        // so a host pulling it parks indefinitely unless cancellation reaches
        // the plugin-side `next_fn`. That is the only way to exercise the
        // cancel path of a live update stream — a stream that produced items
        // would let a pull return for the wrong reason. See
        // `cross_binary_cancel_unblocks_a_quiet_update_stream`.
        Ok((
            RootInfoSnapshot {
                roots: vec![self.root_info()],
                updates: true,
            },
            Some(
                Box::pin(futures::stream::pending::<Result<RootInfoChange>>())
                    as RootInfoUpdateStream,
            ),
        ))
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        park_until_released_or_cancelled(&cancel).await?;
        Ok((
            ConnectionSnapshot {
                connections: Vec::new(),
                updates: false,
            },
            None,
        ))
    }

    /// Opens immediately and hands back a QUIET auth event stream: the park
    /// happens inside the stream, which is where an interactive flow waits on
    /// a browser round-trip or a device-code poll. The stream never yields and
    /// never ends on its own, so a host pulling it parks until cancellation
    /// reaches the plugin-side iterator — the only way to exercise the cancel
    /// path of a live auth stream. See
    /// `cross_binary_cancel_unblocks_a_quiet_auth_stream`.
    async fn authenticate_connection(
        &self,
        _request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        Ok(Box::new(QuietAuthStream {
            cancel,
            ended: false,
        }) as AuthEventStream)
    }

    /// Immediate (never parks): the "sibling op" a host runs to prove the
    /// plugin runtime keeps servicing work while an introspection is parked.
    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        if address.as_str() == PARK_OBJECT {
            Ok(park_object_info(address, PARK_PAYLOAD_LEN))
        } else {
            Err(Error::new(
                ErrorCode::NotFound,
                "test-plugin: parked fixture only serves park://data/a.bin",
            ))
        }
    }
}

/// The auth event stream [`ParkBackend::authenticate_connection`] returns: a
/// pull blocks in `next` until either the op's own cancel token trips or the
/// release gate fires, then reports end-of-stream. `AuthEventStream` is a
/// synchronous iterator, so the block happens on the host's pulling thread —
/// exactly where an interactive flow waits for its out-of-band step.
/// Gate-based, no sleeps.
///
/// The release-gate arm is the host's escape hatch: it reaches the parked pull
/// without going through the FFI cancel bridge, so a host testing that bridge
/// can free its pulling thread — and get it back out of the cdylib before
/// unloading — even when the bridge is the thing that is broken.
///
/// Without a cancel token the release gate is the only arm, matching
/// [`park_until_released_or_cancelled`].
struct QuietAuthStream {
    cancel: Option<CancellationToken>,
    ended: bool,
}

impl Iterator for QuietAuthStream {
    type Item = Result<AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        self.ended = true;
        let release = park_release_token();
        match self.cancel.take() {
            Some(cancel) => {
                use futures::future::select;
                let released = std::pin::pin!(release.cancelled());
                let cancelled = std::pin::pin!(cancel.cancelled());
                futures::executor::block_on(async {
                    select(released, cancelled).await;
                });
            }
            None => futures::executor::block_on(release.cancelled()),
        }
        None
    }
}

/// Export a parked-introspection backend so a host can drive the v8 async
/// dynamic-query slots across the FFI while the plugin parks them. Resets the
/// release gate to un-released and drains stale arrival signals so each export
/// starts clean. Returns `0` on success.
///
/// # Safety
///
/// `out` must be a valid, writable `*mut ffi::LayerHandle` for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_test_export_parked_stack(out: *mut ffi::LayerHandle) -> i32 {
    reset_park_release_gate();
    drain_park_arrivals();
    let layer: Arc<dyn Layer> = ParkBackend::seeded();
    let handle = export_handle(layer);
    // SAFETY: `out` is valid and writable for the call per this function's
    // safety contract.
    unsafe { out.write(handle) };
    0
}

// =====================================================================
// Why the parked fixture must be driven by one test at a time
// =====================================================================

/// Pins the fixture's process-wide scope: its release gate and its arrival
/// channel belong to the loaded image, not to an exported handle, so two
/// concurrent drivers in one process interfere.
///
/// This is the constraint that makes a serializing guard mandatory in every
/// host that drives the fixture more than once
/// (`ovstorage-c-source-cc-test/tests/roundtrip.rs`'s `PARK_FIXTURE_SERIAL`,
/// `ovstorage/tests/handoff_cross_binary.rs`'s `SERIAL`). The interference is
/// invisible from outside: `ovstorage_test_park_wait_arrived` returns on
/// *someone's* arrival, the caller then fires cancel believing its own op is
/// parked, the op parks afterwards, the release gate frees it, and the
/// discovery completes `Ok` -- a green run over a cancel that never landed.
///
/// Both cases drive the real `ovstorage_test_export_parked_stack` and, where
/// the fact under test permits it, a real parked `list_address_roots` over an
/// imported handle. Nothing here restates the export's prologue: a change to
/// what the export does to the gate or the channel changes what these tests
/// observe.
///
/// The assertions live here because the C ABI exposes no session concept and
/// the state they read is private; `cargo test --lib` builds a test harness
/// for this cdylib crate that can reach it. Adding `"rlib"` to `crate-type`
/// is not an option -- the macro-emitted `ovstorage_plugin_*` exports would
/// collide when the rlib is linked into other plugins' test binaries, which
/// is the whole reason this crate is split out.
///
/// If the fixture ever grows per-export sessions, these tests fail; that is
/// the signal that the hosts' serializing guards can go.
#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::MutexGuard;
    use std::time::Duration;

    /// Both cases below drive the same process-wide statics, so they cannot
    /// run concurrently with each other either.
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    fn serialize() -> MutexGuard<'static, ()> {
        TEST_SERIAL
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Every wait here is bounded. `ovstorage_test_park_wait_arrived` blocks
    /// forever on an empty channel and a parked op never completes on its
    /// own, so an unbounded driver would HANG on a regression instead of
    /// failing -- and a hang reads as an infrastructure flake, which is
    /// exactly the failure mode this coverage exists to end.
    const PRESENT: Duration = Duration::from_secs(5);
    /// Waiting for something that must be absent only has to outlast the work
    /// that would have produced it, which has already happened by the time it
    /// is checked.
    const ABSENT: Duration = Duration::from_millis(250);

    fn arrival_within(timeout: Duration) -> bool {
        park_arrivals()
            .1
            .lock()
            .expect("park arrival receiver")
            .recv_timeout(timeout)
            .is_ok()
    }

    /// One real export, imported exactly as a host imports it.
    fn export_parked_stack() -> Arc<dyn Layer> {
        let mut out = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
        // SAFETY: `out` is a valid, writable `*mut ffi::LayerHandle` for the
        // call, per `ovstorage_test_export_parked_stack`'s safety contract.
        let status = unsafe { ovstorage_test_export_parked_stack(out.as_mut_ptr()) };
        assert_eq!(status, 0, "ovstorage_test_export_parked_stack must succeed");
        // SAFETY: `status == 0` means `out` was fully written.
        let handle = unsafe { out.assume_init() };
        // SAFETY: a live handle freshly exported by this image, which is the
        // test binary itself and outlives every import taken from it.
        unsafe { ovstorage::import_handle(handle) }.expect("import the exported root")
    }

    /// A real parked `list_address_roots`, driven on its own thread.
    ///
    /// Not a stand-in for a parked op: the slot parks inside `ParkBackend`
    /// exactly as it does for any host, reached through the same imported
    /// proxy. Drop recovers the thread through both arms of the park, so a
    /// failing assertion cannot leave one running.
    struct ParkedOp {
        cancel: CancellationToken,
        finished: mpsc::Receiver<bool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl ParkedOp {
        fn start(layer: Arc<dyn Layer>) -> Self {
            let cancel = CancellationToken::new();
            let op_cancel = cancel.clone();
            let (sender, finished) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let outcome = futures::executor::block_on(
                    layer.list_address_roots(&ovstorage::Extensions::new(), Some(op_cancel)),
                );
                let _ = sender.send(outcome.is_ok());
            });
            Self {
                cancel,
                finished,
                thread: Some(thread),
            }
        }

        /// `Some(true)` completed, `Some(false)` failed (cancelled), `None`
        /// still parked when the bound expired.
        fn finished_within(&self, timeout: Duration) -> Option<bool> {
            self.finished.recv_timeout(timeout).ok()
        }
    }

    impl Drop for ParkedOp {
        fn drop(&mut self) {
            // Both arms: the op's own token, and the shared release gate.
            self.cancel.cancel();
            ovstorage_test_release_park_gate();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    fn a_second_export_orphans_the_release_token_a_parked_op_holds() {
        let _serial = serialize();

        // Control: with no second export, releasing the gate completes the
        // parked op -- so the negative case below cannot pass merely because
        // the release never worked.
        {
            let layer = export_parked_stack();
            let op = ParkedOp::start(layer);
            assert!(
                arrival_within(PRESENT),
                "the parked op must reach its park point"
            );
            ovstorage_test_release_park_gate();
            assert_eq!(
                op.finished_within(PRESENT),
                Some(true),
                "releasing the gate must complete an op parked on the current token"
            );
        }

        // A second real export lands while the first session's op is parked.
        {
            let layer = export_parked_stack();
            let op = ParkedOp::start(layer);
            assert!(
                arrival_within(PRESENT),
                "the parked op must reach its park point"
            );

            let _second_session = export_parked_stack();
            ovstorage_test_release_park_gate();

            assert_eq!(
                op.finished_within(ABSENT),
                None,
                "a second export installs a fresh release token, so the op \
                 already parked on the previous one is not freed by a release \
                 -- the gate has no per-export session"
            );
        }
    }

    #[test]
    fn a_second_export_drains_a_pending_park_arrival() {
        let _serial = serialize();

        // Control: after a real export, a real parked op's arrival is
        // observable on the channel.
        {
            let layer = export_parked_stack();
            let _op = ParkedOp::start(layer);
            assert!(
                arrival_within(PRESENT),
                "a parked op's arrival must be observable"
            );
        }

        // The arrival is raised by `signal_park_arrived` rather than by a real
        // op, because "the op has parked" is a fact readable only by
        // CONSUMING its arrival -- which is the thing under test. This is the
        // production call: `park_until_released_or_cancelled` makes exactly
        // this one at its park point. The operation under test, the export, is
        // real.
        let _first_session = export_parked_stack();
        signal_park_arrived();
        let _second_session = export_parked_stack();

        assert!(
            !arrival_within(ABSENT),
            "a second export drains the arrival channel, so a driver waiting \
             on ITS op's arrival is left waiting on the next op's -- the \
             fixture has no per-export session"
        );
    }
}
