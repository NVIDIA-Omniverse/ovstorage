// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the `hub_cache` layer's request/fill metrics (`src/metrics.rs`).
//!
//! `metrics::with_local_recorder` scopes a recorder to a synchronous
//! closure, so each test builds its own single-threaded Tokio runtime and
//! drives the async fixture with `block_on` from inside that closure. That
//! keeps every metrics macro call on the one OS thread the local recorder
//! is bound to for the whole of the test, current-thread runtimes never
//! hopping the driving task to another thread.

use ovstorage_plugin::*;

use crate::testing::{
    ADDRESS, CONTENT, ETAG, TestRecorder, collect, expected_key, fixture, read_request,
};

const REQUESTS_TOTAL: &str = "ovstorage_hub_cache_requests_total";
const LOOKUP_DURATION_SECONDS: &str = "ovstorage_hub_cache_lookup_duration_seconds";
const FILLS_TOTAL: &str = "ovstorage_hub_cache_fills_total";

/// Runs `body` with a fresh [`TestRecorder`] installed as the local
/// recorder, driving it on a fresh current-thread runtime, and returns the
/// recorder for assertions.
fn recorded<F, Fut>(body: F) -> TestRecorder
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let recorder = TestRecorder::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime builds");
    metrics::with_local_recorder(&recorder, || rt.block_on(body()));
    recorder
}

#[test]
fn a_miss_records_not_cached_and_the_fill_commits() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "miss"),
                ("reason", "not_cached")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "committed"),
                ("reason", "filled")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.total(LOOKUP_DURATION_SECONDS),
        1,
        "one lookup was classified"
    );
}

#[test]
fn a_second_read_records_a_hit() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[("op", "read"), ("outcome", "hit"), ("reason", "cached")]
        ),
        1
    );
    assert_eq!(recorder.total(LOOKUP_DURATION_SECONDS), 2);
}

#[test]
fn a_conditional_read_records_bypass_conditional() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        let mut conditional = read_request(ADDRESS);
        conditional.input.options.if_match = Some(ETAG.to_string());
        collect(fx.wrapper.read(conditional, None).await.unwrap()).await;
    });

    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "bypass"),
                ("reason", "conditional")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.total(FILLS_TOTAL),
        0,
        "a bypass never reaches the fill logic"
    );
}

#[test]
fn the_extension_trap_records_a_miss_with_no_fill_attempt() {
    // The entry exists under the derived key but was written with a
    // different extension, so the hub answers with a path that does not
    // exist. This is a miss (`entry_unusable`), and — because the key is
    // already taken — never reaches `begin_fill`: there is no `skipped`
    // fill outcome to record here, only the miss.
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        fx.hub.seed_entry(&expected_key(), "usd", CONTENT);
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "miss"),
                ("reason", "entry_unusable")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.total(FILLS_TOTAL),
        0,
        "a taken key is never refilled, so no fill outcome is recorded at all"
    );
}

#[test]
fn a_validator_drift_mid_flight_aborts_the_fill() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        *fx.probe.read_etag.lock().unwrap() = Some("v2".to_string());
        collect(fx.wrapper.read(read_request(ADDRESS), None).await.unwrap()).await;
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "aborted"),
                ("reason", "validator_drift")
            ]
        ),
        1
    );
}

#[test]
fn dropping_a_streamed_fill_mid_body_records_caller_dropped() {
    // Nothing in this crate runs when a caller simply stops polling the
    // stream mid-body: the `FillTicket`'s `Armed` drop guard is the only
    // thing that can observe this, since it is the ticket's own drop glue.
    use futures::StreamExt as _;

    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        *fx.probe.stream_chunk.lock().unwrap() = Some(4);

        let result = fx.wrapper.read(read_request(ADDRESS), None).await.unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("a streamed miss stays a stream");
        };
        stream.next().await.expect("one chunk").expect("ok");
        drop(stream);

        fx.wrapper.client.quiesce().await;
        fx.hub
            .wait_for("the abandoned reservation is discarded", |hub| {
                hub.entry(&expected_key()).is_none()
            })
            .await;
    });

    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "aborted"),
                ("reason", "caller_dropped")
            ]
        ),
        1
    );
}

#[test]
fn materialize_records_its_own_op_label_on_a_miss_then_a_hit() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the fill answers");
        drop(delegate);
        let delegate = fx
            .wrapper
            .materialize(read_request(ADDRESS), None)
            .await
            .expect("the hit answers");
        drop(delegate);
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[
                ("op", "materialize"),
                ("outcome", "miss"),
                ("reason", "not_cached")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[
                ("op", "materialize"),
                ("outcome", "hit"),
                ("reason", "cached")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "materialize"),
                ("outcome", "committed"),
                ("reason", "filled")
            ]
        ),
        1
    );
    // The `read` op's names never appear on a `materialize` call.
    assert_eq!(
        recorder.count(
            REQUESTS_TOTAL,
            &[("op", "read"), ("outcome", "hit"), ("reason", "cached")]
        ),
        0
    );
}

/// A final sync the caller's cancellation interrupted is a cancelled fill,
/// not a filesystem failure: the stall latch never fired and the mount was
/// never proven slow, so the metric must not say otherwise.
#[test]
fn a_sync_interrupted_by_cancellation_records_cancelled_not_staging_error() {
    let recorder = recorded(|| async {
        let fx = fixture(|_| {}).await;
        let url = Url::parse(ADDRESS).unwrap();
        let key = ovstorage_hub_client::hub_key(
            ovstorage_hub_client::KeyScheme::Ovstorage,
            "local",
            &url,
            ETAG,
            None,
        )
        .expect("the etag keys");
        let probe = crate::read::ValidatorProbe {
            info: crate::testing::probe_object_info(&url),
            etag: ETAG.to_string(),
        };
        let crate::read::FillStart::Begun(ticket) = fx
            .wrapper
            .begin_fill(crate::metrics::Op::Read, &url, &probe, &key, None)
            .await
        else {
            panic!("the reservation begins");
        };
        let token = CancellationToken::new();
        let body: ReadStream = Box::pin(futures::stream::empty());
        let mut fill = crate::read::StagedFill::new(body, ticket, Some(token.clone()));
        fill.stage_chunk(bytes::Bytes::from_static(CONTENT))
            .await
            .expect("the chunk stages");
        // The token fires between the last chunk and the settle, so the
        // sync's wait is what observes it.
        token.cancel();
        assert!(!fill.settle().await, "a cancelled settle never commits");
        fx.wrapper.client.quiesce().await;
    });

    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "aborted"),
                ("reason", "cancelled")
            ]
        ),
        1
    );
    assert_eq!(
        recorder.count(
            FILLS_TOTAL,
            &[
                ("op", "read"),
                ("outcome", "aborted"),
                ("reason", "staging_error")
            ]
        ),
        0
    );
}
