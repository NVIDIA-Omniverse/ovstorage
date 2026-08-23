// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-as-spec conformance pass for the ABI-v2 `GcsLayer` (RFC-0066):
//! iterate every named scenario in
//! `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and either
//! DRIVE it against the layer (scripted local mock storage endpoint; no
//! real network) or SKIP it with a concrete reason. Drives use anonymous
//! connections: GCS sends unsigned requests for those, so no token
//! endpoint or synthetic service-account key is needed and every canned
//! response is consumed by exactly the op under test. Recorder-based
//! `expected_calls` verification is test-backend-only, so driven
//! scenarios assert the observable outcome (success shape or the exact
//! `failure_contract` error code) and push `ScenarioReport::passed`.
//!
//! gcs maps the `ifGenerationMatch=0` refusal (HTTP 412) to the
//! documented `ErrorCode::AlreadyExists`, so the
//! `write-no-overwrite-existing` scenario drives.

use std::collections::HashMap;
use std::time::Duration;

use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendFactory, BackendId, Body, CancellationToken,
    ConfigValue, ConnectionAuthState, ConnectionRequest, DeleteOptions, DeleteRequest, ErrorCode,
    IfDestExists, LayerConfig, LayerConnectionRequest, LayerHandle, ListOptions, ListRequest,
    ObjectKind, RenameOptions, RenameRequest, Request, ResolvedTarget, SecretBundle, StatOptions,
    StatRequest, WatchDirectoryOptions, WatchDirectoryRequest, WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_gcs::{GcsBackend, GcsLayerFactory};
use ovstorage_plugin_test::{
    CannedHttpResponse, ConformanceReport, Scenario, ScenarioOutcome, ScenarioRegistry,
    ScenarioReport, ScenarioRunner, ScriptedHttpServer,
};

mod support;
use support::{GatedPubsubFixture, PubsubMessageSpec};

// === Scripted mock storage server (shared
// ovstorage_plugin_test::ScriptedHttpServer with gcs's JSON wire format) ===

/// Answers every request with one canned (status, JSON body) response,
/// counts hits, and records raw requests for wire-level assertions.
fn spawn_scripted_server(status_line: &str, body: &str) -> ScriptedHttpServer {
    ScriptedHttpServer::spawn(CannedHttpResponse::json(status_line, body))
}

const OBJECT_BODY: &str =
    "{\"bucket\": \"bkt\", \"name\": \"obj.txt\", \"size\": \"5\", \"etag\": \"f\"}";

const LIST_BODY: &str = "{\
    \"items\": [\
    {\"bucket\": \"bkt\", \"name\": \"team/\", \"size\": \"0\", \"etag\": \"m\"},\
    {\"bucket\": \"bkt\", \"name\": \"team/file.txt\", \"size\": \"5\", \"etag\": \"f\"}\
    ],\
    \"prefixes\": [\"docs/\"]}";

const ERROR_BODY: &str = "{\"error\": {\"message\": \"scripted\"}}";

// === Helpers ===

fn connection_request(
    bucket: &str,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn empty_layer() -> LayerHandle {
    GcsLayerFactory::default()
        .create_backend("gcs", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "gcs".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

/// Layer + one anonymous connection against a fresh scripted server.
/// Anonymous connections skip verify entirely (zero RPCs), so every
/// canned response goes to the op under test.
async fn anonymous_layer(status_line: &str, body: &str) -> (LayerHandle, ScriptedHttpServer) {
    let server = spawn_scripted_server(status_line, body);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("bkt", server.endpoint(), SecretBundle::default()),
    )
    .await;
    assert!(
        matches!(connection.auth_state, ConnectionAuthState::Anonymous),
        "empty bundle must add anonymously, got {:?}",
        connection.auth_state
    );
    assert_eq!(server.hits(), 0, "anonymous never verifies");
    (layer, server)
}

fn object_address(key: &str) -> ovstorage_plugin::Url {
    address::parse(&format!("gs://bkt/{key}")).unwrap()
}

fn pass(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn fail(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

// === Driven scenarios ===

/// stat → exactly one `objects.get` metadata fetch materializing an
/// ObjectInfo (unsigned for the anonymous connection).
async fn drive_stat_basic_objectinfo(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("200 OK", OBJECT_BODY).await;
    let info = match layer
        .stat(
            Request::new(StatRequest {
                address: object_address("obj.txt"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
    {
        Ok(info) => info,
        Err(err) => return fail(scenario, format!("stat failed: {err}")),
    };
    if info.kind != ObjectKind::File {
        return fail(scenario, format!("expected File kind, got {:?}", info.kind));
    }
    if info.size != Some(5) {
        return fail(scenario, format!("expected size 5, got {:?}", info.size));
    }
    if server.hits() != 1 {
        return fail(scenario, "stat must be exactly one objects.get RPC".into());
    }
    pass(scenario)
}

/// stat on a missing object surfaces exactly `NotFound`. The flat
/// backend runs its full fallback chain (object fetch, slash-marker
/// fetch, bounded descendant probe) and every leg answers the canned
/// 404, so the surfaced code is still `NotFound` on `stat`.
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (layer, _server) = anonymous_layer("404 Not Found", ERROR_BODY).await;
    match layer
        .stat(
            Request::new(StatRequest {
                address: object_address("missing.txt"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
    {
        Err(err) if err.code() == ErrorCode::NotFound => pass(scenario),
        Err(err) => fail(
            scenario,
            format!("expected NotFound on stat, got {:?}: {err}", err.code()),
        ),
        Ok(info) => fail(scenario, format!("stat unexpectedly succeeded: {info:?}")),
    }
}

/// Zero-byte write completes inline (single `uploadType=multipart` POST,
/// no resumable session).
async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("200 OK", OBJECT_BODY).await;
    let result = match layer
        .write(
            Request::new(WriteRequest {
                address: object_address("inline.txt"),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("write failed: {err}")),
    };
    if result.info.kind != ObjectKind::File {
        return fail(
            scenario,
            format!(
                "inline write must report a File, got {:?}",
                result.info.kind
            ),
        );
    }
    if server.hits() != 1 {
        return fail(
            scenario,
            "inline write must be exactly one upload RPC".into(),
        );
    }
    pass(scenario)
}

/// write then delete both succeed (one RPC each; the canned 200 stands
/// in for the object existing).
async fn drive_delete_existing_object(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("200 OK", OBJECT_BODY).await;
    if let Err(err) = layer
        .write(
            Request::new(WriteRequest {
                address: object_address("victim.txt"),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
    {
        return fail(scenario, format!("seed write failed: {err}"));
    }
    if let Err(err) = layer
        .delete(
            Request::new(DeleteRequest {
                address: object_address("victim.txt"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
    {
        return fail(scenario, format!("delete failed: {err}"));
    }
    if server.hits() != 2 {
        return fail(scenario, "write + delete must be exactly two RPCs".into());
    }
    pass(scenario)
}

/// One-level vs recursive listing: the flat call sends `delimiter=/`,
/// the recursive call omits it, and marker folding shapes the flat page
/// (DirectoryMarker + File + DirectoryInferred). The single canned body
/// serves both calls, so the level distinction is proven at the wire.
async fn drive_list_one_level_vs_recursive(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("200 OK", LIST_BODY).await;
    let prefix = address::parse("gs://bkt/").unwrap();
    let flat = match layer
        .list(
            Request::new(ListRequest {
                prefix: prefix.clone(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
    {
        Ok(page) => page,
        Err(err) => return fail(scenario, format!("flat list failed: {err}")),
    };
    let kinds: Vec<ObjectKind> = flat.items.iter().map(|item| item.kind).collect();
    if kinds
        != vec![
            ObjectKind::DirectoryMarker,
            ObjectKind::File,
            ObjectKind::DirectoryInferred,
        ]
    {
        return fail(scenario, format!("unexpected flat list fold: {kinds:?}"));
    }
    let recursive = match layer
        .list(
            Request::new(ListRequest {
                prefix,
                options: ListOptions {
                    recursive: true,
                    ..ListOptions::default()
                },
            }),
            None,
        )
        .await
    {
        Ok(page) => page,
        Err(err) => return fail(scenario, format!("recursive list failed: {err}")),
    };
    if !recursive
        .items
        .iter()
        .any(|item| item.address.as_str() == "gs://bkt/team/file.txt")
    {
        return fail(scenario, "recursive list must surface nested files".into());
    }
    let raw = server.requests();
    // Anonymous connections never verify: [0] flat, [1] recursive.
    if !raw[0].contains("delimiter=") {
        return fail(
            scenario,
            format!("flat list must send a delimiter: {}", raw[0]),
        );
    }
    if raw[1].contains("delimiter=") {
        return fail(
            scenario,
            format!("recursive list must not send a delimiter: {}", raw[1]),
        );
    }
    pass(scenario)
}

/// `IfDestExists::Fail` against an existing destination surfaces exactly
/// `AlreadyExists`: the canned 412 stands in for the
/// `ifGenerationMatch=0` refusal, and the wire proves the query was sent.
async fn drive_write_no_overwrite_existing(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("412 Precondition Failed", ERROR_BODY).await;
    let outcome = layer
        .write(
            Request::new(WriteRequest {
                address: object_address("existing.txt"),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    if_dest: IfDestExists::Fail,
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::AlreadyExists => {
            if server.hits() != 1 {
                return fail(
                    scenario,
                    "no-overwrite write must be exactly one upload RPC".into(),
                );
            }
            let raw = server.requests();
            if !raw[0].contains("ifGenerationMatch=0") {
                return fail(
                    scenario,
                    format!(
                        "no-overwrite write must send ifGenerationMatch=0: {}",
                        raw[0]
                    ),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected AlreadyExists on the no-overwrite refusal, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(result) => fail(
            scenario,
            format!(
                "no-overwrite write unexpectedly succeeded: {:?}",
                result.info
            ),
        ),
    }
}

/// `rename` is rewrite-then-delete on gcs, and its `IfDestExists::Fail`
/// rides the rewrite as `ifGenerationMatch=0` — the canned 412 refusal
/// surfaces exactly `AlreadyExists` (the contract on the copy/rename
/// path), and the source-delete never happens.
async fn drive_rename_no_overwrite_existing(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("412 Precondition Failed", ERROR_BODY).await;
    let outcome = layer
        .rename(
            Request::new(RenameRequest {
                source: object_address("move-src.txt"),
                destination: object_address("move-dst.txt"),
                options: RenameOptions {
                    if_dest: IfDestExists::Fail,
                    ..RenameOptions::default()
                },
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::AlreadyExists => {
            if server.hits() != 1 {
                return fail(
                    scenario,
                    "the refused rename must be exactly one rewrite RPC (no delete)".into(),
                );
            }
            let raw = server.requests();
            if !raw[0].contains("ifGenerationMatch=0") || !raw[0].contains("rewriteTo") {
                return fail(
                    scenario,
                    format!(
                        "the rename's rewrite must send ifGenerationMatch=0: {}",
                        raw[0]
                    ),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected AlreadyExists on the no-overwrite rename, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(()) => fail(
            scenario,
            "no-overwrite rename unexpectedly succeeded".into(),
        ),
    }
}

/// Capability self-gate: without `pubsub_subscription` gcs does not
/// advertise `supports_watch_directory`, and `watch_directory` refuses
/// locally with a typed `Unsupported` before any Pub/Sub RPC.
async fn drive_gate_watch_directory(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) = anonymous_layer("200 OK", OBJECT_BODY).await;
    let outcome = layer
        .watch_directory(
            Request::new(WatchDirectoryRequest {
                prefix: object_address("dir/"),
                options: WatchDirectoryOptions::default(),
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::Unsupported => {
            if server.hits() != 0 {
                return fail(
                    scenario,
                    "gated watch_directory must not reach the wire".into(),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!("expected Unsupported, got {:?}: {err}", err.code()),
        ),
        Ok(_) => fail(
            scenario,
            "watch_directory unexpectedly returned a stream".into(),
        ),
    }
}

// === Cross-prefix no-split watch driver ===

/// A GCS backend (one connection) wired to the gated Pub/Sub mock, with
/// `pubsub_subscription` configured so `watch_directory` is admitted (not
/// `Unsupported`).
fn watch_backend(endpoint: &str) -> GcsBackend {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("assets".into()));
    config.insert(
        "pubsub_subscription".into(),
        ConfigValue::String("projects/p/subscriptions/s".into()),
    );
    config.insert(
        "pubsub_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    config.insert("pubsub_pull_max".into(), ConfigValue::Int(10));
    let parsed = ovstorage_plugin_gcs::__test_only_parse_config(&config).expect("parse config");
    ovstorage_plugin_gcs::__test_only_backend(parsed, SecretBundle::default())
        .expect("backend init")
}

fn watch_target(prefix: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("gcs:gs://assets/".into()),
        resolved_address: address::parse(&format!("gs://assets/{prefix}")).unwrap(),
    }
}

/// The object address an `Object` change event carries, if any (non-object
/// events — e.g. `Lapsed` — return `None`).
fn event_address(event: &BackendChangeEvent) -> Option<String> {
    match event {
        BackendChangeEvent::Object { address, .. } => Some(address.as_str().to_string()),
        _ => None,
    }
}

/// Read the next stream item, bounded by `timeout`. On timeout, cancel the
/// watcher (unblocking the parked `next()`) and report end-of-stream, so a
/// starved watcher yields `None` instead of hanging the conformance pass.
async fn read_next(
    stream: BackendChangeStream,
    cancel: &CancellationToken,
    timeout: Duration,
) -> (
    Option<BackendChangeStream>,
    Option<ovstorage_plugin::Result<BackendChangeEvent>>,
) {
    let mut handle = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        let item = stream.next();
        (stream, item)
    });
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(joined) => {
            let (stream, item) = joined.expect("blocking next() task panicked");
            match item {
                Some(event) => (Some(stream), Some(event)),
                None => (None, None),
            }
        }
        Err(_elapsed) => {
            cancel.cancel();
            // Bound the post-cancel drain: a wedged cancellation must not hang
            // the read. If the blocking next() does not unpark, detach it.
            match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                Ok(joined) => {
                    let _ = joined.expect("blocking next() task panicked after cancel");
                }
                Err(_) => handle.abort(),
            }
            (None, None)
        }
    }
}

/// Drain every object-event address a watcher delivers within its window,
/// expecting `expected` object events. Returns `Err(reason)` on a terminal
/// upstream error OR on any non-object event (e.g. `Lapsed`): a gap means
/// events were lost, which must FAIL the "none lost" scenario rather than be
/// silently discarded.
async fn collect_addresses(
    stream: BackendChangeStream,
    cancel: &CancellationToken,
    label: &str,
    expected: usize,
) -> Result<Vec<String>, String> {
    // A generous per-event bound tolerates slow CI scheduling so a
    // slow-to-arrive event is not misread as missing. Once the expected count
    // is reached, only a short quiet window is needed to confirm the stream is
    // idle (and to catch any over-delivery), without inflating the wait.
    const PER_EVENT: Duration = Duration::from_secs(5);
    const QUIET_WINDOW: Duration = Duration::from_millis(400);

    let mut addresses = Vec::new();
    let mut stream = Some(stream);
    while let Some(current) = stream.take() {
        let wait = if addresses.len() < expected {
            PER_EVENT
        } else {
            QUIET_WINDOW
        };
        let (next_stream, item) = read_next(current, cancel, wait).await;
        match item {
            Some(Ok(event)) => match event_address(&event) {
                Some(address) => {
                    addresses.push(address);
                    stream = next_stream;
                }
                None => {
                    return Err(format!(
                        "{label} watcher saw a non-object change event (a Lapsed/gap \
                         signals lost events, failing the none-lost scenario): {event:?}"
                    ));
                }
            },
            Some(Err(err)) => {
                return Err(format!("{label} watcher saw a terminal error: {err}"));
            }
            None => break,
        }
    }
    addresses.sort();
    Ok(addresses)
}

/// Three watches on ONE connection: W1 `root/a/`, W2 `root/b/` (disjoint),
/// W3 `root/` recursive (overlaps both). After all are open, one batch
/// carrying an `a/` and a `b/` event is released to exactly one physical
/// Pub/Sub puller. The MUST: W1 gets only its `a/`, W2 only its `b/`, W3
/// both, none lost. Pre-adoption (one puller per `watch_directory` call) the
/// pullers cannibalize — the batch reaches a single watcher and the others
/// starve — so this driver reports `Failed`. Post-adoption (self-coalescing)
/// it passes.
async fn drive_watch_concurrent_cross_prefix_no_split(scenario: &Scenario) -> ScenarioReport {
    let a_event = "gs://assets/root/a/x.txt?generation=42".to_string();
    let b_event = "gs://assets/root/b/y.txt?generation=42".to_string();
    let fixture = GatedPubsubFixture::new(vec![
        PubsubMessageSpec::new("ack-a", "root/a/x.txt"),
        PubsubMessageSpec::new("ack-b", "root/b/y.txt"),
    ]);
    let backend = watch_backend(fixture.endpoint());

    let recursive = WatchDirectoryOptions {
        recursive: true,
        ..WatchDirectoryOptions::default()
    };

    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();
    let cancel_c = CancellationToken::new();

    let w1 = match backend
        .watch_directory(
            watch_target("root/a/"),
            recursive.clone(),
            Some(cancel_a.clone()),
        )
        .await
    {
        Ok(stream) => stream,
        Err(err) => return fail(scenario, format!("W1 watch_directory failed: {err}")),
    };
    let w2 = match backend
        .watch_directory(
            watch_target("root/b/"),
            recursive.clone(),
            Some(cancel_b.clone()),
        )
        .await
    {
        Ok(stream) => stream,
        Err(err) => return fail(scenario, format!("W2 watch_directory failed: {err}")),
    };
    let w3 = match backend
        .watch_directory(
            watch_target("root/"),
            recursive.clone(),
            Some(cancel_c.clone()),
        )
        .await
    {
        Ok(stream) => stream,
        Err(err) => return fail(scenario, format!("W3 watch_directory failed: {err}")),
    };

    // Open all watches FIRST, then release exactly one batch to one puller. A
    // CORRECT coalescer opens exactly ONE physical Pub/Sub puller per
    // connection, so the barrier waits for a single puller — not one per
    // watch. Pre-adoption, all three watch_directory calls above have already
    // returned (their producers registered), so one delivered batch still
    // deterministically starves >=2 of the 3 watchers (RED); post-adoption a
    // single coalesced puller fans the batch out to all three (GREEN).
    if !fixture.wait_for_pullers(1, Duration::from_secs(5)) {
        return fail(
            scenario,
            "no watch opened a physical Pub/Sub puller within 5s".into(),
        );
    }
    fixture.open_gate();

    let got_w1 = match collect_addresses(w1, &cancel_a, "W1(root/a/)", 1).await {
        Ok(addresses) => addresses,
        Err(reason) => return fail(scenario, reason),
    };
    let got_w2 = match collect_addresses(w2, &cancel_b, "W2(root/b/)", 1).await {
        Ok(addresses) => addresses,
        Err(reason) => return fail(scenario, reason),
    };
    let got_w3 = match collect_addresses(w3, &cancel_c, "W3(root/ recursive)", 2).await {
        Ok(addresses) => addresses,
        Err(reason) => return fail(scenario, reason),
    };

    let want_w1 = vec![a_event.clone()];
    let want_w2 = vec![b_event.clone()];
    let mut want_w3 = vec![a_event, b_event];
    want_w3.sort();

    // The load-bearing anti-cannibalization invariant: one connection must run
    // exactly ONE physical Pub/Sub puller no matter how many watches it holds.
    let max_pulls = fixture.max_concurrent_pulls();
    if max_pulls != 1 {
        return fail(
            scenario,
            format!(
                "cross-prefix watches opened {max_pulls} concurrent Pub/Sub pullers; a \
                 self-coalescing connection must run exactly one"
            ),
        );
    }

    if got_w1 == want_w1 && got_w2 == want_w2 && got_w3 == want_w3 {
        return pass(scenario);
    }
    fail(
        scenario,
        format!(
            "cross-prefix watches split the subscription (competing-consumer \
             cannibalization): W1(root/a/) got {got_w1:?} want {want_w1:?}, \
             W2(root/b/) got {got_w2:?} want {want_w2:?}, W3(root/ recursive) \
             got {got_w3:?} want {want_w3:?}"
        ),
    )
}

// === Registry sweep ===

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_scenarios_cover_the_registry() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    let mut driven: Vec<&'static str> = Vec::new();

    for scenario in registry.iter() {
        let entry = match scenario.name {
            "stat-basic-objectinfo" => {
                driven.push(scenario.name);
                drive_stat_basic_objectinfo(scenario).await
            }
            "stat-not-found" => {
                driven.push(scenario.name);
                drive_stat_not_found(scenario).await
            }
            "write-done-inline" => {
                driven.push(scenario.name);
                drive_write_done_inline(scenario).await
            }
            "delete-existing-object" => {
                driven.push(scenario.name);
                drive_delete_existing_object(scenario).await
            }
            "list-one-level-vs-recursive" => {
                driven.push(scenario.name);
                drive_list_one_level_vs_recursive(scenario).await
            }
            "write-no-overwrite-existing" => {
                driven.push(scenario.name);
                drive_write_no_overwrite_existing(scenario).await
            }
            "rename-no-overwrite-existing" => {
                driven.push(scenario.name);
                drive_rename_no_overwrite_existing(scenario).await
            }
            "copy-to-self-preserves-content" => runner.skip(
                scenario.name,
                "data preservation on a same-object rewrite is service-enforced (GCS treats \
                 it as a no-op copy); a canned mock can only echo the test's own script, \
                 proving nothing about the provider",
            ),
            "capability-gate-watch-directory-unsupported" => {
                driven.push(scenario.name);
                drive_gate_watch_directory(scenario).await
            }
            "watch-concurrent-cross-prefix-no-split" => {
                driven.push(scenario.name);
                drive_watch_concurrent_cross_prefix_no_split(scenario).await
            }
            "read-streamed-empty" => runner.skip(
                scenario.name,
                "anonymous and service-account reads return ReadResult::Redirect; the \
                 user-credential streaming path needs distinct metadata and media responses \
                 the single-canned mock cannot script",
            ),
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion; expected_calls verification is \
                 test-backend-only",
            ),
            "delete-on-directory-type-mismatch"
            | "delete-directory-on-file-type-mismatch"
            | "list-on-file-type-mismatch"
            | "read-on-directory-type-mismatch" => runner.skip(
                scenario.name,
                "requires DirectoriesReal: gcs is a flat namespace with marker folding \
                 (has_real_directories=false)",
            ),
            "capability-gate-delete-unsupported"
            | "capability-gate-write-redirect-unsupported"
            | "capability-gate-create-directory-unsupported"
            | "capability-gate-delete-directory-unsupported"
            | "capability-gate-list-versions-unsupported" => runner.skip(
                scenario.name,
                "gcs always advertises this op; there is no unsupported configuration whose \
                 self-gate could be observed",
            ),
            "capability-gate-update-metadata-unsupported" => runner.skip(
                scenario.name,
                "gcs advertises supports_native_metadata_patch=true; update_metadata is a \
                 supported wire op with no self-gate to prove",
            ),
            "capability-gate-check-access-unsupported" => runner.skip(
                scenario.name,
                "gcs advertises supports_access_check=true and check_access probes the service \
                 over the wire; no self-gated refusal exists",
            ),
            "readonly-connection-rejects-mutations" => runner.skip(
                scenario.name,
                "no read-only connection mode: anonymous gcs connections advertise the full \
                 capability vector and mutations are attempted unsigned over the wire",
            ),
            "compat-gates-v1-capability" => runner.skip(
                scenario.name,
                "stable capability-gate scenario; driven in ovstorage's \
                 conformance_protocol_slots.rs",
            ),
            "write-redirect-commits-on-done"
            | "retry-never-replays-continue-write"
            | "protocol-slots-pass-through" => runner.skip(
                scenario.name,
                "host/wrapper-side protocol-slot contract; driven in ovstorage's \
                 conformance_protocol_slots.rs",
            ),
            _ => runner.skip(
                scenario.name,
                "no provider driver wired; extend tests/conformance_scenarios.rs",
            ),
        };
        report.push(entry);
    }

    eprintln!("{}", report.render_human());
    assert_eq!(
        report.entries.len(),
        registry.len(),
        "every registry scenario must be reported"
    );

    // The cross-prefix no-split scenario is a DRIVEN gate: `ConformanceReport::ok()`
    // counts `Skipped` as success, so a skip would silently pass the gate. Assert
    // it is not skipped BEFORE checking `ok()` — a struct variant, so `!=` won't
    // compile and `matches!` is required.
    let cross_prefix = report
        .entries
        .iter()
        .find(|entry| entry.name == "watch-concurrent-cross-prefix-no-split")
        .expect("cross-prefix scenario must be reported");
    assert!(
        !matches!(&cross_prefix.outcome, ScenarioOutcome::Skipped { .. }),
        "cross-prefix watch scenario must be driven, not skipped"
    );

    assert!(
        report.ok(),
        "conformance failures:\n{}",
        report.render_human()
    );
    assert_eq!(report.failed(), 0);

    // Pin the driven set so silently-lost coverage fails loudly.
    driven.sort_unstable();
    assert_eq!(
        driven,
        vec![
            "capability-gate-watch-directory-unsupported",
            "delete-existing-object",
            "list-one-level-vs-recursive",
            "rename-no-overwrite-existing",
            "stat-basic-objectinfo",
            "stat-not-found",
            "watch-concurrent-cross-prefix-no-split",
            "write-done-inline",
            "write-no-overwrite-existing",
        ],
        "the driven scenario set changed; update the pin deliberately"
    );
}
