// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust proof that a parked dynamic introspection query
//! (`root_info_for` / `list_address_roots` / `list_connections`) neither
//! blocks the runtime nor ignores its cancel token.
//!
//! Every test runs on an explicit current-thread runtime, which makes the
//! concurrent-progress proof strict: with a single executor thread, an
//! unrelated spawned task can only complete while the query is parked if the
//! parked query genuinely yields (awaits) rather than blocking the thread.
//! The rendezvous style follows `cross_binary_cancel_mid_flight_via_gate`
//! (`handoff_cross_binary.rs`): deterministic gate signals, no sleeps, no
//! timing assumptions.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use ovstorage::{
    AddressVisibility, CancellationToken, Capabilities, ConfigLayer, ConnectionSnapshot,
    ConnectionUpdateStream, Error, ErrorCode, Extensions, Layer, LayerKindDescriptor, LayerType,
    RangeReadStrategy, Result, RootInfo, RootInfoSnapshot, RootInfoUpdateStream, RouteSource, Url,
    UserMetadata,
};

const PARKING_KIND: &str = "parking";
const PARKING_ROOT: &str = "park://root/";

/// A Layer test double whose three runtime-state queries park at a gate.
///
/// Each query signals `entered` the moment it reaches the gate (the RV1
/// rendezvous: the test knows the query is provably parked, with no timing
/// assumption), then races gate release against cancellation with
/// `tokio::select!`, mirroring how the first-party layers race cancel (see
/// `body_stream_from_read_stream` in `src/wrappers/copy_rename_fallback.rs`): the
/// cancel arm resolves to an error whose code is exactly
/// [`ErrorCode::Cancelled`].
struct ParkingLayer {
    /// Released by the test to let a parked query complete normally.
    gate: Notify,
    /// Signaled by a query when it reaches the gate. `notify_one` stores a
    /// permit, so the test's `notified().await` observes the rendezvous even
    /// if the query gets there first.
    entered: Notify,
}

impl ParkingLayer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: Notify::new(),
            entered: Notify::new(),
        })
    }

    async fn park(&self, cancel: Option<CancellationToken>) -> Result<()> {
        self.entered.notify_one();
        match cancel {
            Some(token) => tokio::select! {
                _ = token.cancelled() => Err(Error::new(
                    ErrorCode::Cancelled,
                    "introspection query cancelled while parked",
                )),
                _ = self.gate.notified() => Ok(()),
            },
            None => {
                self.gate.notified().await;
                Ok(())
            }
        }
    }

    fn root(&self) -> RootInfo {
        RootInfo {
            root: Url::parse(PARKING_ROOT).unwrap(),
            display_name: None,
            layer_kind: PARKING_KIND.to_string(),
            connection_id: None,
            owning_target: None,
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::default(),
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::default(),
        }
    }
}

#[async_trait]
impl Layer for ParkingLayer {
    fn name(&self) -> &str {
        "parking"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: PARKING_KIND.to_string(),
            kind: PARKING_KIND.to_string(),
            layer_type: LayerType::Backend,
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

    async fn root_info_for(
        &self,
        _url: &Url,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.park(cancel).await?;
        Ok(self.root())
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        self.park(cancel).await?;
        Ok((
            RootInfoSnapshot {
                roots: vec![self.root()],
                updates: false,
            },
            None,
        ))
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        self.park(cancel).await?;
        Ok((
            ConnectionSnapshot {
                connections: Vec::new(),
                updates: false,
            },
            None,
        ))
    }
}

/// Drive one already-spawned parked query through the deterministic
/// three-step proof:
///
/// 1. RV1 — await `entered`: the query has provably reached the gate (and,
///    on the current-thread scheduler, has already registered its select
///    waiters and yielded before this test task resumes).
/// 2. Concurrent progress — an unrelated spawned task runs to completion
///    while the query is still parked (`!is_finished()` is deterministic
///    here: neither the gate nor the token has fired, so the query cannot
///    have resolved).
/// 3. RV2 — fire the token: the parked query must resolve to an error whose
///    code is exactly `ErrorCode::Cancelled`.
async fn assert_cancelled_while_parked(
    layer: &ParkingLayer,
    cancel: &CancellationToken,
    query: JoinHandle<Result<()>>,
) {
    // RV1: the query is at the gate.
    layer.entered.notified().await;

    // Concurrent progress while parked: on this current-thread runtime the
    // unrelated task can only complete if the parked query yielded instead of
    // blocking the sole executor thread.
    let unrelated = tokio::spawn(async { 7 });
    assert_eq!(
        unrelated.await.expect("unrelated task panicked"),
        7,
        "an unrelated task must complete while the query is parked"
    );
    assert!(
        !query.is_finished(),
        "the query must still be parked at the gate (nothing released it)"
    );

    // RV2: cancel — the parked query resolves without the gate ever opening.
    cancel.cancel();
    let err = query
        .await
        .expect("query task panicked")
        .expect_err("a parked query must observe cancellation");
    assert_eq!(err.code(), ErrorCode::Cancelled, "got {err}");
}

/// (a)+(b) for `root_info_for`: a parked per-URL introspection query leaves
/// the runtime live, and cancelling it yields exactly `Cancelled`.
#[tokio::test(flavor = "current_thread")]
async fn parked_root_info_for_leaves_runtime_live_and_cancels() {
    let layer = ParkingLayer::new();
    let cancel = CancellationToken::new();
    let query = tokio::spawn({
        let layer = Arc::clone(&layer);
        let cancel = cancel.clone();
        async move {
            let url = Url::parse("park://root/obj.bin").unwrap();
            layer
                .root_info_for(&url, &Extensions::new(), Some(cancel))
                .await
                .map(|_| ())
        }
    });
    assert_cancelled_while_parked(&layer, &cancel, query).await;
}

/// (a)+(b) for `list_address_roots`: a parked snapshot query leaves the
/// runtime live, and cancelling it yields exactly `Cancelled`.
#[tokio::test(flavor = "current_thread")]
async fn parked_list_address_roots_leaves_runtime_live_and_cancels() {
    let layer = ParkingLayer::new();
    let cancel = CancellationToken::new();
    let query = tokio::spawn({
        let layer = Arc::clone(&layer);
        let cancel = cancel.clone();
        async move {
            layer
                .list_address_roots(&Extensions::new(), Some(cancel))
                .await
                .map(|_| ())
        }
    });
    assert_cancelled_while_parked(&layer, &cancel, query).await;
}

/// (a)+(b) for `list_connections`: a parked connection-snapshot query leaves
/// the runtime live, and cancelling it yields exactly `Cancelled`.
#[tokio::test(flavor = "current_thread")]
async fn parked_list_connections_leaves_runtime_live_and_cancels() {
    let layer = ParkingLayer::new();
    let cancel = CancellationToken::new();
    let query = tokio::spawn({
        let layer = Arc::clone(&layer);
        let cancel = cancel.clone();
        async move {
            layer
                .list_connections(&Extensions::new(), Some(cancel))
                .await
                .map(|_| ())
        }
    });
    assert_cancelled_while_parked(&layer, &cancel, query).await;
}

/// The double's release arm is real, not a cancel-only stub: with an unfired
/// token racing in the same `select!`, opening the gate completes the parked
/// query successfully. Guards the fixture itself — if `park` stopped racing
/// both arms, either this test or the cancel legs above would fail.
#[tokio::test(flavor = "current_thread")]
async fn released_gate_completes_parked_root_info_query() {
    let layer = ParkingLayer::new();
    let cancel = CancellationToken::new();
    let query = tokio::spawn({
        let layer = Arc::clone(&layer);
        let cancel = cancel.clone();
        async move {
            let url = Url::parse("park://root/obj.bin").unwrap();
            layer
                .root_info_for(&url, &Extensions::new(), Some(cancel))
                .await
        }
    });

    // RV1: parked at the gate, with the (never-fired) token still racing.
    layer.entered.notified().await;
    assert!(!query.is_finished(), "query must be parked before release");

    // Release the gate: the query completes with its answer.
    layer.gate.notify_one();
    let info = query
        .await
        .expect("query task panicked")
        .expect("a released query must complete successfully");
    assert_eq!(info.root.as_str(), PARKING_ROOT);
}
