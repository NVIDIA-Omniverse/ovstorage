// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-as-spec conformance pass for the ABI-v2 anonymous HTTP layer
//! (RFC-0066): iterate every named scenario in
//! `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and either
//! DRIVE it against the layer (scripted local loopback origin, no real
//! network) or SKIP it with a concrete reason. Recorder-based
//! `expected_calls` verification is test-backend-only, so driven
//! scenarios assert the observable outcome (success shape or the exact
//! `failure_contract` error code) and push `ScenarioReport::passed`.
//!
//! Anonymous HTTP is read-only: `HttpBackend::capabilities()` is the
//! empty set and only `stat` + `read` are implemented. Applicability is
//! decided from the registry's own gating metadata — a scenario whose
//! `required_capabilities` or `required_profile` floor demands a
//! capability the plugin does not advertise SKIPs with the missing bit
//! named. The `capability-gate-*-unsupported` family DRIVES instead:
//! with every optional bit disabled, the typed `Unsupported` refusal is
//! the plugin's shipped contract, not a test configuration.

use std::collections::HashMap;

use ovstorage_plugin::{
    AccessOps, BackendFactory, Body, Capabilities, CheckAccessRequest, ConfigValue,
    ConnectionAuthState, ConnectionRequest, CreateDirectoryOptions, CreateDirectoryRequest,
    DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions, DeleteRequest, ErrorCode,
    LayerConfig, LayerConnectionRequest, LayerHandle, ListVersionsOptions, ListVersionsRequest,
    ObjectKind, ReadOptions, ReadRequest, ReadResult, Request, Result, SecretBundle, StatOptions,
    StatRequest, UpdateMetadataOptions, UpdateMetadataRequest, Url, WatchDirectoryOptions,
    WatchDirectoryRequest, WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_http::{HttpBackend, HttpBackendLayerFactory};
use ovstorage_plugin_test::{
    CAPABILITY_GATE_SCENARIOS, CannedHttpResponse, ConformanceReport, FailureContract, Scenario,
    ScenarioRegistry, ScenarioReport, ScenarioRunner, ScriptedHttpServer,
};

// === Layer / connection helpers ===

async fn empty_layer() -> LayerHandle {
    HttpBackendLayerFactory::default()
        .create_backend("http", &LayerConfig::new(), None)
        .await
        .unwrap()
}

/// Layer + one anonymous connection rooted at a fresh scripted origin.
/// `instantiate` probes the origin only when the connection carries a
/// credential, so an *anonymous* add leaves the wire untouched — drivers can
/// therefore count hits from 0. A credentialed add spends one HEAD before the
/// first driver request; `a_credentialed_add_probes_the_origin` below pins
/// both halves of that split.
async fn connected_layer(response: CannedHttpResponse) -> (LayerHandle, ScriptedHttpServer) {
    let server = ScriptedHttpServer::spawn(response);
    let layer = empty_layer().await;
    let mut config = HashMap::new();
    config.insert(
        "root_url".to_string(),
        ConfigValue::String(server.endpoint().into()),
    );
    let connection = layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "http".into(),
                connection: ConnectionRequest {
                    backend_kind: "http".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(connection.auth_state, ConnectionAuthState::Anonymous),
        "an HTTP connection with no credentials must connect Anonymous, got {:?}",
        connection.auth_state
    );
    assert_eq!(
        server.hits(),
        0,
        "an anonymous connection add must not reach the wire"
    );
    (layer, server)
}

fn object_address(server: &ScriptedHttpServer, key: &str) -> Url {
    address::parse(&format!("{}/{key}", server.endpoint())).unwrap()
}

fn pass(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn fail(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

// === Applicability gate (required_profile / required_capabilities) ===

/// Whether `caps` advertises the registry requirement named
/// `requirement`. Unknown names are conservatively unmet, so a future
/// registry capability produces a visible SKIP instead of a failure.
fn advertises(caps: &Capabilities, requirement: &str) -> bool {
    match requirement {
        "supports_if_match_write" => caps.supports_if_match_write,
        "supports_no_overwrite_write" => caps.supports_no_overwrite_write,
        "supports_native_metadata_patch" => caps.supports_native_metadata_patch,
        "supports_server_side_copy" => caps.supports_server_side_copy,
        "supports_server_side_rename" => caps.supports_server_side_rename,
        "supports_atomic_rename" => caps.supports_atomic_rename,
        "has_real_directories" => caps.has_real_directories,
        "supports_write" => caps.supports_write,
        "supports_write_stream" => caps.supports_write_stream,
        "supports_write_redirect" => caps.supports_write_redirect,
        "supports_delete" => caps.supports_delete,
        "supports_list" => caps.supports_list,
        "supports_recursive_list" => caps.supports_recursive_list,
        "supports_create_directory" => caps.supports_create_directory,
        "supports_delete_directory" => caps.supports_delete_directory,
        "supports_version_listing" => caps.supports_version_listing,
        "supports_access_check" => caps.supports_access_check,
        "supports_watch_directory" => caps.supports_watch_directory,
        _ => false,
    }
}

/// The capability bit a driven vtable slot needs. `stat` / `read` are
/// the ungated floor every layer implements.
fn slot_requirement(slot: &str) -> Option<&'static str> {
    match slot {
        "write" => Some("supports_write"),
        "write_stream" => Some("supports_write_stream"),
        "write_redirect" | "continue_write" => Some("supports_write_redirect"),
        "delete" => Some("supports_delete"),
        "list" => Some("supports_list"),
        "copy" => Some("supports_server_side_copy"),
        "rename" => Some("supports_server_side_rename"),
        "create_directory" => Some("supports_create_directory"),
        "delete_directory" => Some("supports_delete_directory"),
        "list_versions" => Some("supports_version_listing"),
        "update_metadata" => Some("supports_native_metadata_patch"),
        "check_access" => Some("supports_access_check"),
        "watch_directory" => Some("supports_watch_directory"),
        _ => None,
    }
}

/// The slot the scenario's failure contract expects to refuse with a
/// typed `Unsupported`. Such a slot is exercised by NOT supporting the
/// operation, so the gate must not demand its capability bit.
fn unsupported_refusal_slot(scenario: &Scenario) -> Option<&'static str> {
    match &scenario.failure_contract {
        FailureContract::Errors {
            method,
            code: ErrorCode::Unsupported,
        } => Some(method),
        _ => None,
    }
}

/// First registry requirement the plugin does not advertise, or `None`
/// when the scenario is applicable. Requirements come from
/// `required_capabilities` (explicit) and from `required_profile`: the
/// profile's capability set (`Profile::capabilities`) is demanded only
/// for the slots the scenario actually drives, so the `Minimal`
/// write/delete/list floor gates `write-done-inline` without gating
/// `stat-basic-objectinfo`.
fn unmet_requirement(scenario: &Scenario) -> Option<&'static str> {
    let advertised = HttpBackend::capabilities();
    for &requirement in scenario.required_capabilities {
        if !advertises(&advertised, requirement) {
            return Some(requirement);
        }
    }
    let profile_floor = scenario.required_profile.capabilities();
    for &slot in scenario.vtable_slots {
        if unsupported_refusal_slot(scenario) == Some(slot) {
            continue;
        }
        let Some(requirement) = slot_requirement(slot) else {
            continue;
        };
        if advertises(&profile_floor, requirement) && !advertises(&advertised, requirement) {
            return Some(requirement);
        }
    }
    None
}

// === Driven scenarios ===

/// stat → exactly one HEAD, materializing an ObjectInfo from the
/// origin's identity headers (etag unquoted, size from Content-Length).
async fn drive_stat_basic_objectinfo(scenario: &Scenario) -> ScenarioReport {
    let (layer, server) =
        connected_layer(CannedHttpResponse::new("200 OK", "hello").with_header("ETag", "\"abc\""))
            .await;
    let info = match layer
        .stat(
            Request::new(StatRequest {
                address: object_address(&server, "obj.txt"),
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
    if info.etag.as_deref() != Some("abc") {
        return fail(
            scenario,
            format!("expected the unquoted origin etag, got {:?}", info.etag),
        );
    }
    if info.size != Some(5) {
        return fail(
            scenario,
            format!("expected size 5 from Content-Length, got {:?}", info.size),
        );
    }
    if server.hits() != 1 {
        return fail(scenario, "stat must be exactly one HEAD request".into());
    }
    let raw = server.requests();
    if !raw[0].starts_with("HEAD ") {
        return fail(scenario, format!("stat must send HEAD: {}", raw[0]));
    }
    pass(scenario)
}

/// stat on a missing object surfaces exactly `NotFound` (HTTP 404).
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (layer, _server) = connected_layer(CannedHttpResponse::new("404 Not Found", "")).await;
    match layer
        .stat(
            Request::new(StatRequest {
                address: object_address(&_server, "missing.txt"),
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

/// Open-ended read returns `ReadResult::Stream` (the plugin streams the
/// origin body itself); an empty object drains to zero bytes in exactly
/// one GET.
async fn drive_read_streamed_empty(scenario: &Scenario) -> ScenarioReport {
    use futures::StreamExt;
    let (layer, server) = connected_layer(CannedHttpResponse::new("200 OK", "")).await;
    let result = match layer
        .read(
            Request::new(ReadRequest {
                address: object_address(&server, "empty.bin"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("read failed: {err}")),
    };
    let (mut stream, info) = match result {
        ReadResult::Stream { stream, info } => (stream, info),
        other => {
            return fail(
                scenario,
                format!("open-ended read must stream, got {other:?}"),
            );
        }
    };
    let mut drained = 0usize;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => drained += bytes.len(),
            Err(err) => return fail(scenario, format!("stream chunk failed: {err}")),
        }
    }
    if drained != 0 {
        return fail(scenario, format!("empty object drained {drained} bytes"));
    }
    if info.size != Some(0) {
        return fail(scenario, format!("expected size 0, got {:?}", info.size));
    }
    if server.hits() != 1 {
        return fail(scenario, "read must be exactly one GET request".into());
    }
    pass(scenario)
}

/// Shared driver for every scenario whose contract is a typed
/// `Unsupported` refusal (the `capability-gate-*` family, the read-only
/// mutation probe, and the stable v1 gate id): invoke the slot on a
/// live connection and require the refusal to surface before any wire
/// traffic.
async fn drive_unsupported_refusal(scenario: &Scenario, method: &str) -> ScenarioReport {
    let (layer, server) = connected_layer(CannedHttpResponse::new("200 OK", "")).await;
    match invoke_slot(&layer, &server, method).await {
        Err(err) if err.code() == ErrorCode::Unsupported => {
            if server.hits() != 0 {
                return fail(
                    scenario,
                    format!("refused {method} must not reach the wire"),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected Unsupported on {method}, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(()) => fail(scenario, format!("{method} unexpectedly succeeded")),
    }
}

/// Invoke one optional vtable slot with a minimal well-formed request,
/// discarding any success value.
async fn invoke_slot(layer: &LayerHandle, server: &ScriptedHttpServer, method: &str) -> Result<()> {
    let address = object_address(server, "gated.txt");
    let directory = object_address(server, "gated-dir/");
    match method {
        "write" => layer
            .write(
                Request::new(WriteRequest {
                    address,
                    body: Body::Bytes(Vec::new()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "write_redirect" => layer
            .write_redirect(
                Request::new(WriteRequest {
                    address,
                    body: Body::Bytes(Vec::new()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "delete" => {
            layer
                .delete(
                    Request::new(DeleteRequest {
                        address,
                        options: DeleteOptions::default(),
                    }),
                    None,
                )
                .await
        }
        "update_metadata" => layer
            .update_metadata(
                Request::new(UpdateMetadataRequest {
                    address,
                    options: UpdateMetadataOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "check_access" => layer
            .check_access(
                Request::new(CheckAccessRequest {
                    address,
                    operations: AccessOps {
                        read: true,
                        ..AccessOps::default()
                    },
                }),
                None,
            )
            .await
            .map(|_| ()),
        "create_directory" => layer
            .create_directory(
                Request::new(CreateDirectoryRequest {
                    address: directory,
                    options: CreateDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "delete_directory" => {
            layer
                .delete_directory(
                    Request::new(DeleteDirectoryRequest {
                        address: directory,
                        options: DeleteDirectoryOptions,
                    }),
                    None,
                )
                .await
        }
        "list_versions" => layer
            .list_versions(
                Request::new(ListVersionsRequest {
                    address,
                    options: ListVersionsOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "watch_directory" => layer
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: directory,
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        other => panic!("no slot invoker wired for `{other}`"),
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
        // Applicability gate first: any scenario demanding a capability
        // the read-only plugin does not advertise skips with the missing
        // bit named (visible in the rendered report below).
        if let Some(missing) = unmet_requirement(scenario) {
            report.push(runner.skip(
                scenario.name,
                format!("read-only anonymous HTTP does not advertise `{missing}`"),
            ));
            continue;
        }
        let gate_slot = CAPABILITY_GATE_SCENARIOS
            .iter()
            .find(|(name, _)| *name == scenario.name)
            .map(|&(_, slot)| slot);
        let entry = match scenario.name {
            "stat-basic-objectinfo" => {
                driven.push(scenario.name);
                drive_stat_basic_objectinfo(scenario).await
            }
            "stat-not-found" => {
                driven.push(scenario.name);
                drive_stat_not_found(scenario).await
            }
            "read-streamed-empty" => {
                driven.push(scenario.name);
                drive_read_streamed_empty(scenario).await
            }
            // Anonymous HTTP is read-only by construction; `write` is the
            // contract's probed mutation.
            "readonly-connection-rejects-mutations" => {
                driven.push(scenario.name);
                drive_unsupported_refusal(scenario, "write").await
            }
            // The stable gate id: `delete` is genuinely unsupported here,
            // so the layer's own capability refusal is observed directly.
            "compat-gates-v1-capability" => {
                driven.push(scenario.name);
                drive_unsupported_refusal(scenario, "delete").await
            }
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion; expected_calls verification is \
                 test-backend-only",
            ),
            _ => match gate_slot {
                // capability-gate-<op>-unsupported: the plugin ships with
                // every optional bit disabled, so the self-gate refusal is
                // its real contract rather than a test knob.
                Some(slot) => {
                    driven.push(scenario.name);
                    drive_unsupported_refusal(scenario, slot).await
                }
                None => runner.skip(
                    scenario.name,
                    "no provider driver wired; extend tests/conformance_scenarios.rs",
                ),
            },
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
    // Inapplicable scenarios must be visible skips, never silent
    // omissions: every non-pass is a rendered SKIP line with a reason.
    assert_eq!(report.passed() + report.skipped(), registry.len());
    assert!(
        report.render_human().contains("  SKIP  "),
        "skips must be visible in the rendered report"
    );

    // Pin the driven set so silently-lost coverage fails loudly.
    driven.sort_unstable();
    assert_eq!(
        driven,
        vec![
            "capability-gate-check-access-unsupported",
            "capability-gate-create-directory-unsupported",
            "capability-gate-delete-directory-unsupported",
            "capability-gate-delete-unsupported",
            "capability-gate-list-versions-unsupported",
            "capability-gate-update-metadata-unsupported",
            "capability-gate-watch-directory-unsupported",
            "capability-gate-write-redirect-unsupported",
            "compat-gates-v1-capability",
            "read-streamed-empty",
            "readonly-connection-rejects-mutations",
            "stat-basic-objectinfo",
            "stat-not-found",
        ],
        "the driven scenario set changed; update the pin deliberately"
    );
}

/// The other half of `connected_layer`'s hit-counting contract: a connection
/// that carries a credential *does* reach the wire once at add time, so a
/// driver counting from 0 must account for it.
#[tokio::test]
async fn a_credentialed_add_probes_the_origin_exactly_once() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let layer = empty_layer().await;
    let mut config = HashMap::new();
    config.insert(
        "root_url".to_string(),
        ConfigValue::String(server.endpoint().into()),
    );
    let mut credentials = SecretBundle::default();
    credentials.fields.insert(
        "bearer_token".to_string(),
        ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"tok".to_vec())),
    );

    let connection = layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "http".into(),
                connection: ConnectionRequest {
                    backend_kind: "http".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .unwrap();

    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "a probed credential must report Authenticated, got {:?}",
        connection.auth_state
    );
    assert_eq!(
        server.hits(),
        1,
        "a credentialed add spends exactly one probe: {:?}",
        server.requests()
    );
}
