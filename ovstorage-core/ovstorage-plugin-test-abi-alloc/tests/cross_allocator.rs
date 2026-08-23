// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proves that values crossing the plugin ABI are minted and reclaimed on
//! the shared ABI heap rather than on the per-binary Rust global allocator.
//!
//! # The defect this pins
//!
//! `#[global_allocator]` is chosen per artifact. The host test binary and
//! the cdylib under `OVSTORAGE_PLUGIN_TEST_ALLOC_SO` install different ones.
//! If a result envelope, a snapshot, or any `Str`/`Bytes`/`List` buffer
//! inside them is allocated with `Vec`/`Box` in the plugin and released with
//! `Vec`/`Box` in the host, the plugin's allocator hands out a block it never
//! gets back — on a real jemalloc/mimalloc plugin that is heap corruption on
//! the first completion.
//!
//! # How it is observed without corrupting the process
//!
//! The cdylib's allocator delegates to the system allocator and only keeps
//! book, so a cross-allocator free stays survivable and shows up as an
//! accounting imbalance instead of an abort. Imbalance-per-round-trip is the
//! signature: run the same round-trip `FEW` times and `MANY` times, and
//! compare. Per-process warm-up (lazy statics, pools, runtime scaffolding)
//! is identical in both samples and cancels; anything that scales with the
//! round-trip count does not.
//!
//! Both directions are read and asserted separately — the plugin producing a
//! value the host releases, and the host producing one the plugin releases.
//! One of each per round-trip would cancel in a single net figure.
//!
//! Gate-based: every round-trip is awaited to completion, so there is
//! nothing in flight when a sample is taken.
//!
//! # Rebuild the cdylib
//!
//! This test is only hermetic when something has rebuilt the cdylib it
//! loads. `cargo test` builds this test binary but not that artifact, so
//! `make test` / `make test-ci` go through `build-test-plugins`, which
//! pre-builds the package and keeps it out of the stale-plugin prune.
//!
//! A bare `cargo test -p ovstorage-plugin-test-abi-alloc` has no such
//! guarantee, and the loader's version gate does not close the hole: it is
//! exact-match, so it catches a cdylib from a *different* ABI version but
//! not a stale one built at the same version. A change to `ffi::abi_alloc`
//! or to marshalling that does not also bump
//! `OVSTORAGE_PLUGIN_ABI_V2_VERSION` is then measured against the old
//! artifact and passes for the wrong reason. Rebuild the package when
//! changing either, or drive the test through `make`.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::ext::LayerExt as _;
use ovstorage::{
    AuthenticateRequest, ConfigValue, ConnectionKey, ConnectionRequest, Extensions,
    InteractiveAuthCapability, LayerConnectionRequest, LayerTable, Request, SecretBundle, Stack,
    StackConfig,
};
use ovstorage_plugin::Url;

const PLUGIN_PATH: &str = env!("OVSTORAGE_PLUGIN_TEST_ALLOC_SO");

/// Round-trip counts for the two samples. The gap is what the assertion
/// measures; both samples run after warm-up.
const FEW: usize = 5;
const MANY: usize = 105;

/// Read one of the cdylib's counter exports.
///
/// The plugin is already resident (the Stack holds it open), so this
/// `dlopen` resolves to the same image rather than loading a second copy.
fn counter(symbol: &[u8]) -> i64 {
    // SAFETY: the library is already loaded by the Stack under test; this
    // only takes another reference to it and reads a plain counter export.
    unsafe {
        let lib = libloading::Library::new(PLUGIN_PATH).expect("reopen instrumented plugin");
        let read: libloading::Symbol<extern "C" fn() -> i64> =
            lib.get(symbol).expect("counter export");
        read()
    }
}

/// The two directions, sampled together so one reading covers both.
#[derive(Clone, Copy)]
struct Probes {
    /// Blocks the plugin minted on its own allocator and never got back.
    retained: i64,
    /// Blocks the plugin released through its own allocator without having
    /// minted them.
    foreign_frees: i64,
}

impl Probes {
    fn read() -> Self {
        let probes = Self {
            retained: counter(b"ovstorage_test_abi_alloc_retained"),
            foreign_frees: counter(b"ovstorage_test_abi_alloc_foreign_frees"),
        };
        let untracked = counter(b"ovstorage_test_abi_alloc_untracked");
        assert_eq!(
            untracked, 0,
            "the plugin's membership table overflowed ({untracked} blocks), so \
             neither direction's counter can be trusted (retained {}, foreign \
             frees {})",
            probes.retained, probes.foreign_frees,
        );
        probes
    }
}

/// The Stack under test plus a connection key that `authenticate_connection`
/// resolves, so the auth slot can be driven to a SUCCESSFUL completion.
///
/// A failed authentication returns through the error path, which was already
/// covered; only the success path mints the `AuthEventStream` result
/// envelope, which is the slot this fixture exists to weigh.
struct Fixture {
    stack: Arc<Stack>,
    connection: ConnectionKey,
}

async fn open_stack() -> Fixture {
    let temp = tempfile::tempdir().expect("auth tempdir");
    // Set-once per process; a second call in the same process is a no-op
    // for this test's purposes.
    let _ = ovstorage::init_auth_substrate(Some(temp.path()));
    std::mem::forget(temp);

    // SAFETY: the test harness intentionally opts into this test-only plugin.
    let factories = unsafe { ovstorage::load_layer_plugin(PLUGIN_PATH, true) }
        .expect("load instrumented test layer plugin");
    let stack = ovstorage::host::build_stack(
        &StackConfig {
            root: Some("test".into()),
            layers: HashMap::from([(
                "test".into(),
                LayerTable {
                    kind: Some("test".into()),
                    ..LayerTable::default()
                },
            )]),
            connections: Vec::new(),
        },
        factories,
    )
    .await
    .expect("build instrumented test plugin Stack");

    // `authenticate_connection` resolves its request against an installed
    // connection, so one has to exist before the auth slot can complete
    // successfully.
    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "test".into(),
            connection: ConnectionRequest {
                backend_kind: "test".into(),
                config: HashMap::from([(
                    "test_root".into(),
                    ConfigValue::String("test://abi-alloc/".into()),
                )]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        }),
        None,
    )
    .await
    .expect("add a connection for the auth round-trip");

    Fixture {
        connection: ConnectionKey {
            target: "test".into(),
            id: connection.id,
        },
        stack,
    }
}

/// One full plugin-to-host value handoff, on both halves of the contract:
///
/// * `list_backend_kinds` returns a `List<LayerKindDescriptor>` — nested
///   `Str`, `List`, and `Optional<Bytes>` buffers, all minted in the cdylib
///   and released in this binary.
/// * `root_info_for` against an unroutable URL returns a heap `Error`
///   envelope carrying its own message buffer: the boxed-envelope half.
/// * `root_info_for` against an installed root SUCCEEDS, which is the only
///   way to reach the `RootInfo` result envelope. The error path above
///   completes through the callback's error slot, which weighs the `Error`
///   envelope instead.
/// * `authenticate_connection` against an installed connection SUCCEEDS,
///   which is the only way to reach the `AuthEventStream` result envelope.
///   A failing authentication completes through the callback's error slot,
///   which mints an `Error` envelope and no `AuthEventStream` — which is how
///   this slot's envelope stayed on the plugin's global allocator unnoticed.
///
/// Every slot here is stateless in the backend. The auth slot mutates
/// nothing either — the connection is installed once, in `open_stack` — so
/// whatever the plugin's allocator retains across a round-trip came from the
/// ABI handoff and nothing else.
///
/// # Three slots this fixture cannot host
///
/// `list_address_roots` and `list_connections` carry the most envelope
/// surface of any slot — a snapshot plus a nested update stream — and are
/// exactly the two it cannot weigh. `ovstorage-plugin-test`'s `TestLayer`
/// pushes a subscriber `Sender` into `root_subs` / `conn_subs` on **every**
/// call and prunes those vectors only in `add_connection` /
/// `remove_connection`, so one `Sender` per round-trip stays live on the
/// plugin's allocator.
///
/// `watch_directory` is blocked independently: the test backend records
/// `ObservedCall::WatchDirectory { prefix: Url }` into an unbounded call
/// recorder, and that `Url`'s heap buffer is one retained block per call.
/// Driving it here costs exactly one extra retained block per round-trip,
/// measured.
///
/// In all three cases plugin-internal state grows with the round-trip count,
/// which is the signature an ABI defect has, so the differencing assertions
/// below would fail on state that never crossed the ABI. The test backend's
/// subscriber and recorder lifecycles have to be bounded first.
async fn round_trip(fixture: &Fixture) {
    let stack = &*fixture.stack;

    let kinds = stack.list_backend_kinds().expect("list_backend_kinds");
    assert!(
        !kinds.is_empty(),
        "test backend advertises at least one kind"
    );

    let url = Url::parse("unroutable://nowhere/x").expect("probe url");
    ovstorage::Layer::root_info_for(stack, &url, &Extensions::new(), None)
        .await
        .expect_err("an unroutable URL yields an error envelope");

    // The same slot's SUCCESS path, which is a different envelope entirely:
    // the call above completes through the callback's error slot and so never
    // weighs the `RootInfo` result `root_info_for_thunk` mints. The test
    // backend answers this one by reading its installed roots and mutates
    // nothing, so it adds no plugin-internal state that would scale with the
    // round-trip count.
    let routable = Url::parse("test://abi-alloc/probe.bin").expect("routable url");
    ovstorage::Layer::root_info_for(stack, &routable, &Extensions::new(), None)
        .await
        .expect("an installed root resolves to its RootInfo");

    // Drain the stream as well as opening it: the envelope is reclaimed at
    // completion, its backing stream state when the handle drops.
    let events = ovstorage::Layer::authenticate_connection(
        stack,
        Request::new(AuthenticateRequest {
            key: fixture.connection.clone(),
            capability: InteractiveAuthCapability::None,
            auto_open_browser: false,
        }),
        None,
    )
    .await
    .expect("authenticate_connection completes successfully");
    for event in events {
        event.expect("auth event");
    }
}

async fn drive(fixture: &Fixture, count: usize) -> Probes {
    let before = Probes::read();
    for _ in 0..count {
        round_trip(fixture).await;
    }
    let after = Probes::read();
    Probes {
        retained: after.retained - before.retained,
        foreign_frees: after.foreign_frees - before.foreign_frees,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn abi_values_do_not_ride_the_plugin_global_allocator() {
    let fixture = open_stack().await;

    // Warm up so first-use lazy state is not attributed to a sample.
    for _ in 0..FEW {
        round_trip(&fixture).await;
    }

    let few = drive(&fixture, FEW).await;
    let many = drive(&fixture, MANY).await;

    // Any per-round-trip imbalance shows up as a difference that scales with
    // the extra `MANY - FEW` round-trips. Warm-up state appears in both
    // samples and cancels, so each expected difference is exactly zero.
    //
    // The two directions are asserted separately, never summed: `round_trip`
    // exercises both — the plugin produces result envelopes, and this binary
    // mints the request buffers the plugin frees — so one regression of each
    // kind per round-trip would cancel in a single total and pass.
    let extra = MANY - FEW;

    let retained = many.retained - few.retained;
    assert_eq!(
        retained, 0,
        "the plugin's allocator retained {retained} extra blocks across \
         {extra} additional ABI round-trips: values the plugin produces are \
         minted on its global allocator and released on the host's",
    );

    let foreign = many.foreign_frees - few.foreign_frees;
    assert_eq!(
        foreign, 0,
        "the plugin's allocator released {foreign} extra blocks it never \
         minted across {extra} additional ABI round-trips: values the host \
         produces are released on the plugin's global allocator",
    );
}
