// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-as-spec conformance pass for the ABI-v2 `AzureLayer`
//! (RFC-0066): iterate every named scenario in
//! `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and either
//! DRIVE it against the layer (scripted local mock Azure endpoint via
//! `__test_endpoint`, Shared Key only; no real network) or SKIP it with
//! a concrete reason. Recorder-based `expected_calls` verification is
//! test-backend-only, so driven scenarios assert the observable outcome
//! (success shape or the exact `failure_contract` error code) and push
//! `ScenarioReport::passed`.
//!
//! `write-no-overwrite-existing` is driven on its refusal half: the
//! registry demands `AlreadyExists` (the documented `IfDestExists::Fail`
//! contract) and azure maps the `If-None-Match: *` refusal (HTTP 409
//! `BlobAlreadyExists`) to exactly that.

use std::collections::HashMap;

use base64::Engine as _;
use ovstorage_plugin::{
    AccessOps, BackendFactory, Body, CheckAccessRequest, ConfigValue, ConnectionAuthState,
    ConnectionRequest, CreateDirectoryOptions, CreateDirectoryRequest, DeleteOptions,
    DeleteRequest, ErrorCode, IfDestExists, LayerConfig, LayerConnectionRequest, LayerHandle,
    ListOptions, ListRequest, ObjectKind, ReadOptions, ReadRequest, RenameOptions, RenameRequest,
    Request, SecretBundle, SecretBytes, SecretValue, StatOptions, StatRequest,
    WatchDirectoryOptions, WatchDirectoryRequest, WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_azure::AzureLayerFactory;
use ovstorage_plugin_test::{
    CannedHttpResponse, ConformanceReport, Scenario, ScenarioRegistry, ScenarioReport,
    ScenarioRunner, ScriptedHttpServer, request_has_header,
};

// === Scripted mock Azure server (shared
// ovstorage_plugin_test::ScriptedHttpServer, parameterized with azure's
// x-ms-error-code header) ===

/// Answers every request with one canned (status, x-ms-error-code, body)
/// response, counts hits, and records raw requests for wire-level
/// assertions.
fn spawn_scripted_server(
    status_line: &str,
    error_code: Option<&str>,
    body: &str,
) -> ScriptedHttpServer {
    let mut response = CannedHttpResponse::xml(status_line, body);
    if let Some(code) = error_code {
        response = response.with_header("x-ms-error-code", code);
    }
    ScriptedHttpServer::spawn(response)
}

const EMPTY_LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <EnumerationResults ServiceEndpoint=\"http://127.0.0.1/\" ContainerName=\"assets\">\
    <Blobs></Blobs><NextMarker /></EnumerationResults>";

const LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <EnumerationResults ServiceEndpoint=\"http://127.0.0.1/\" ContainerName=\"assets\">\
    <Blobs>\
    <Blob><Name>team/</Name><Properties>\
    <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>\
    <Etag>0x8DCM</Etag><Content-Length>0</Content-Length>\
    </Properties></Blob>\
    <Blob><Name>team/file.txt</Name><Properties>\
    <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>\
    <Etag>0x8DCF</Etag><Content-Length>5</Content-Length>\
    </Properties></Blob>\
    <BlobPrefix><Name>docs/</Name></BlobPrefix>\
    </Blobs><NextMarker /></EnumerationResults>";

const ERROR_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
    <Error><Code>scripted</Code><Message>scripted</Message></Error>";

// === Helpers ===

fn account_key_bundle() -> SecretBundle {
    let key = base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "account_key".into(),
        SecretValue::Bytes(SecretBytes(key.into_bytes())),
    );
    bundle
}

fn connection_request(
    container: &str,
    endpoint: &str,
    credentials: SecretBundle,
) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String("acct123".into()));
    config.insert("container".into(), ConfigValue::String(container.into()));
    config.insert(
        "__test_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    ConnectionRequest {
        backend_kind: "azure".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

async fn empty_layer() -> LayerHandle {
    AzureLayerFactory::default()
        .create_backend("azure", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

/// Layer + one Shared-Key connection against a fresh scripted server.
/// The lenient verify consumes one canned response regardless of status
/// (only `AuthenticationFailed` / `InvalidAuthenticationInfo` / 401
/// park), so drivers snapshot the hit count after add.
async fn credentialed_layer(
    status_line: &str,
    error_code: Option<&str>,
    body: &str,
) -> (LayerHandle, ScriptedHttpServer, usize) {
    let server = spawn_scripted_server(status_line, error_code, body);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        connection_request("assets", server.endpoint(), account_key_bundle()),
    )
    .await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "lenient verify must authenticate, got {:?}",
        connection.auth_state
    );
    let verify_hits = server.hits();
    (layer, server, verify_hits)
}

fn object_address(key: &str) -> ovstorage_plugin::Url {
    address::parse(&format!("azure://acct123/assets/{key}")).unwrap()
}

fn pass(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn fail(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

// === Driven scenarios ===

/// stat → exactly one signed HEAD, materializing an ObjectInfo.
async fn drive_stat_basic_objectinfo(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer("200 OK", None, EMPTY_LIST_BODY).await;
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
    if server.hits() != verify_hits + 1 {
        return fail(scenario, "stat must be exactly one HEAD RPC".into());
    }
    pass(scenario)
}

/// stat on a missing blob surfaces exactly `NotFound` (HTTP 404
/// `BlobNotFound`; the lenient verify passes through the same canned
/// 404, and a non-trailing-slash key skips the marker fallback probes).
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (layer, _server, _verify_hits) =
        credentialed_layer("404 Not Found", Some("BlobNotFound"), ERROR_BODY).await;
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

/// Zero-byte write completes inline (single signed Put Blob, no
/// redirect round-trip).
async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer("200 OK", None, EMPTY_LIST_BODY).await;
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
    if server.hits() != verify_hits + 1 {
        return fail(
            scenario,
            "inline write must be exactly one Put Blob RPC".into(),
        );
    }
    pass(scenario)
}

/// write then delete both succeed (one RPC each; the canned 200 stands
/// in for the blob existing).
async fn drive_delete_existing_object(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer("200 OK", None, EMPTY_LIST_BODY).await;
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
    if server.hits() != verify_hits + 2 {
        return fail(scenario, "write + delete must be exactly two RPCs".into());
    }
    pass(scenario)
}

/// One-level vs recursive listing: the flat call sends `delimiter=/`,
/// the recursive call omits it, and marker folding shapes the flat page
/// (DirectoryMarker + File + DirectoryInferred). The single canned body
/// serves both calls, so the level distinction is proven at the wire.
async fn drive_list_one_level_vs_recursive(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, _verify_hits) = credentialed_layer("200 OK", None, LIST_BODY).await;
    let prefix = address::parse("azure://acct123/assets/").unwrap();
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
        .any(|item| item.address.as_str() == "azure://acct123/assets/team/file.txt")
    {
        return fail(scenario, "recursive list must surface nested files".into());
    }
    let raw = server.requests();
    // raw[0] is the connection verify; [1] flat, [2] recursive.
    if !raw[1].contains("delimiter=") {
        return fail(
            scenario,
            format!("flat list must send a delimiter: {}", raw[1]),
        );
    }
    if raw[2].contains("delimiter=") {
        return fail(
            scenario,
            format!("recursive list must not send a delimiter: {}", raw[2]),
        );
    }
    pass(scenario)
}

/// Drives `write-no-overwrite-existing` on its refusal half (the
/// contract point): the `If-None-Match: *` refusal (HTTP 409
/// `BlobAlreadyExists`) must surface as the registry's demanded
/// `AlreadyExists`, and the Put Blob must actually carry the
/// `If-None-Match: *` conditional on the wire — otherwise a driver
/// that dropped `IfDestExists::Fail` would still map the canned 409.
/// The preceding successful first write is generic write plumbing
/// already covered by `write-done-inline`; scripting the 200-then-409
/// sequence is beyond the single-canned mock.
async fn drive_write_no_overwrite_refusal(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, _verify_hits) =
        credentialed_layer("409 Conflict", Some("BlobAlreadyExists"), ERROR_BODY).await;
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
            // The refusal must be azure honoring IfDestExists::Fail on
            // the wire, not just the canned 409 mapping through.
            let raw = server.requests();
            let Some(put) = raw.last() else {
                return fail(scenario, "no-overwrite write never reached the wire".into());
            };
            if !request_has_header(put, "If-None-Match", "*") {
                return fail(
                    scenario,
                    format!("no-overwrite Put Blob must send If-None-Match: *: {put}"),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "IfDestExists::Fail refusal must surface AlreadyExists, got {:?}: {err}",
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

/// `rename` on a flat namespace is Copy-Blob-then-delete, and its
/// `IfDestExists::Fail` rides the copy as `If-None-Match: *` — the canned
/// 412 `ConditionNotMet` refusal surfaces exactly `AlreadyExists` (the
/// documented `IfDestExists::Fail` contract; a native 409
/// `BlobAlreadyExists` maps there generically), and the source-delete
/// never happens.
async fn drive_rename_no_overwrite_existing(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer(
        "412 Precondition Failed",
        Some("ConditionNotMet"),
        ERROR_BODY,
    )
    .await;
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
            if server.hits() != verify_hits + 1 {
                return fail(
                    scenario,
                    "the refused rename must be exactly one Copy Blob RPC (no delete)".into(),
                );
            }
            let raw = server.requests();
            let copy = &raw[verify_hits];
            if !request_has_header(copy, "If-None-Match", "*")
                || !copy.to_ascii_lowercase().contains("x-ms-copy-source")
            {
                return fail(
                    scenario,
                    format!("the rename's copy must send If-None-Match: * on a Copy Blob: {copy}"),
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

/// `read` on a directory address refuses with the contract's
/// `InvalidArgument` on a hierarchical-namespace connection, where
/// `has_real_directories` is advertised. The scenario addresses the
/// directory in its slash-less spelling, so the verdict has to come from
/// the service: one canned `200 OK` carrying `x-ms-resource-type:
/// directory` serves the `create_directory` PUT (any 2xx commits) and the
/// read's kind preflight alike.
async fn drive_read_on_directory_mismatch(scenario: &Scenario) -> ScenarioReport {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::xml("200 OK", EMPTY_LIST_BODY)
            .with_header("x-ms-resource-type", "directory"),
    );
    let layer = empty_layer().await;
    let mut request = connection_request("assets", server.endpoint(), account_key_bundle());
    request
        .config
        .insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    add(&layer, request).await;
    if let Err(err) = layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: object_address("readdir/"),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
    {
        return fail(scenario, format!("setup create_directory failed: {err}"));
    }
    let outcome = layer
        .read(
            Request::new(ReadRequest {
                address: object_address("readdir"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await;
    // One canned response answers every request, so the error code alone
    // cannot tell a directory refusal from a setup that never reached the
    // wire. Pin the sequence the scenario is supposed to have driven.
    let requests = server.requests();
    let wire = |method: &str, needle: &str| {
        requests
            .iter()
            .any(|raw| raw.starts_with(method) && raw.contains(needle))
    };
    if !wire("GET", "comp=list") {
        return fail(scenario, format!("no verify List Blobs: {requests:?}"));
    }
    if !wire("PUT", "/assets/readdir?resource=directory") {
        return fail(
            scenario,
            format!("create_directory did not PUT: {requests:?}"),
        );
    }
    if !wire("HEAD", "/assets/readdir?action=getStatus") {
        return fail(
            scenario,
            format!("read did not preflight the directory kind: {requests:?}"),
        );
    }
    match outcome {
        // The message check is not decoration: `read` has three other
        // `InvalidArgument` exits before the kind preflight (the `if_match`
        // shape, the byte range, the address), so a bare code assertion would
        // stay green if the directory refusal were lost and some unrelated
        // rejection took its place.
        Err(err)
            if err.code() == ErrorCode::InvalidArgument && err.message().contains("list()") =>
        {
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected InvalidArgument with list() guidance on read of a directory, \
                 got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(_) => fail(
            scenario,
            "read of a directory address must refuse, not answer".into(),
        ),
    }
}

/// Capability self-gate: azure does not advertise
/// `supports_access_check`, and `check_access` refuses locally with a
/// typed `Unsupported` before the signed HEAD RPC it would otherwise issue.
async fn drive_gate_check_access(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer("200 OK", None, EMPTY_LIST_BODY).await;
    let outcome = layer
        .check_access(
            Request::new(CheckAccessRequest {
                address: object_address("obj.txt"),
                operations: AccessOps {
                    read: true,
                    ..AccessOps::default()
                },
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::Unsupported => {
            if server.hits() != verify_hits {
                return fail(
                    scenario,
                    "gated check_access must not reach the wire".into(),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!("expected Unsupported, got {:?}: {err}", err.code()),
        ),
        Ok(decision) => fail(
            scenario,
            format!("check_access unexpectedly returned a decision: {decision:?}"),
        ),
    }
}

/// Capability self-gate: without `change_feed_enabled=true` azure does
/// not advertise `supports_watch_directory`, and `watch_directory`
/// refuses locally with a typed `Unsupported` before any change-feed
/// RPC.
async fn drive_gate_watch_directory(scenario: &Scenario) -> ScenarioReport {
    let (layer, server, verify_hits) = credentialed_layer("200 OK", None, EMPTY_LIST_BODY).await;
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
            if server.hits() != verify_hits {
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

// === Registry sweep ===

#[tokio::test]
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
                drive_write_no_overwrite_refusal(scenario).await
            }
            "rename-no-overwrite-existing" => {
                driven.push(scenario.name);
                drive_rename_no_overwrite_existing(scenario).await
            }
            "copy-to-self-preserves-content" => runner.skip(
                scenario.name,
                "data preservation on a same-URL Copy Blob is service-enforced; a canned \
                 mock can only echo the test's own script, proving nothing about the \
                 provider",
            ),
            "capability-gate-watch-directory-unsupported" => {
                driven.push(scenario.name);
                drive_gate_watch_directory(scenario).await
            }
            "read-streamed-empty" => runner.skip(
                scenario.name,
                "azure read returns ReadResult::Redirect (a SAS/signed URL) only; the plugin \
                 never streams object bytes itself",
            ),
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion; expected_calls verification is \
                 test-backend-only",
            ),
            "delete-on-directory-type-mismatch"
            | "delete-directory-on-file-type-mismatch"
            | "list-on-file-type-mismatch" => runner.skip(
                scenario.name,
                "DirectoriesReal requires hierarchical_namespace=true and the backend defers \
                 kind checks to the service; the single-canned-response mock cannot script the \
                 create_directory + mismatched-op sequence with distinct responses",
            ),
            "read-on-directory-type-mismatch" => {
                driven.push(scenario.name);
                drive_read_on_directory_mismatch(scenario).await
            }
            "capability-gate-delete-unsupported"
            | "capability-gate-create-directory-unsupported"
            | "capability-gate-delete-directory-unsupported"
            | "capability-gate-list-versions-unsupported" => runner.skip(
                scenario.name,
                "azure always advertises this op; there is no unsupported configuration whose \
                 self-gate could be observed",
            ),
            "capability-gate-write-redirect-unsupported" => runner.skip(
                scenario.name,
                "an anonymous connection IS such a configuration — it withholds \
                 supports_write_redirect and answers Unsupported locally — but this harness \
                 drives a shared-key connection, so the gate is pinned by the unit test \
                 anonymous_withholds_only_the_bit_whose_slot_it_refuses instead",
            ),
            "capability-gate-update-metadata-unsupported" => runner.skip(
                scenario.name,
                "azure advertises supports_native_metadata_patch=true; update_metadata is a \
                 supported wire op with no self-gate to prove",
            ),
            "capability-gate-check-access-unsupported" => {
                driven.push(scenario.name);
                drive_gate_check_access(scenario).await
            }
            "readonly-connection-rejects-mutations" => runner.skip(
                scenario.name,
                "no read-only connection mode: an anonymous azure connection withholds only \
                 supports_write_redirect, and every other mutation is attempted unsigned over \
                 the wire for the service to refuse",
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
            "capability-gate-check-access-unsupported",
            "capability-gate-watch-directory-unsupported",
            "delete-existing-object",
            "list-one-level-vs-recursive",
            "read-on-directory-type-mismatch",
            "rename-no-overwrite-existing",
            "stat-basic-objectinfo",
            "stat-not-found",
            "write-done-inline",
            "write-no-overwrite-existing",
        ],
        "the driven scenario set changed; update the pin deliberately"
    );
}
