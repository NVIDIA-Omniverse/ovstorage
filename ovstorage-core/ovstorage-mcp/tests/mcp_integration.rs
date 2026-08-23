// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use base64::Engine;
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation, ProtocolVersion,
};
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use tokio::process::Command;

fn server_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage-mcp"))
}

/// An empty plugin directory. The `file` backend is built into the Stack, so no
/// `file` cdylib is loaded; pointing the server at an empty dir keeps plugin
/// discovery a no-op
/// while native `file` handles the config's `backend_kind = "file"` connection.
fn empty_plugin_dir() -> PathBuf {
    tempfile::tempdir().expect("plugin temp dir").keep()
}

async fn connect_server(config: Option<&Path>) -> RunningService<rmcp::RoleClient, ()> {
    let mut cmd = Command::new(server_binary());
    cmd.env("OVSTORAGE_PLUGIN_DIR", empty_plugin_dir());
    match config {
        Some(path) => {
            cmd.env("OVSTORAGE_CONFIG", path);
            cmd.env_remove("OVSTORAGE_MCP_NO_CONFIG");
        }
        None => {
            cmd.env("OVSTORAGE_MCP_NO_CONFIG", "1");
            cmd.env_remove("OVSTORAGE_CONFIG");
        }
    }
    let transport = TokioChildProcess::new(cmd).expect("spawn server");
    ().serve(transport).await.expect("rmcp handshake")
}

fn write_file_config(root: &Path) -> tempfile::NamedTempFile {
    let config = tempfile::NamedTempFile::new().expect("config temp file");
    let root = root.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(
        config.path(),
        format!(
            r#"[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
        ),
    )
    .expect("write config");
    config
}

fn args(value: serde_json::Value) -> rmcp::model::JsonObject {
    rmcp::model::object(value)
}

async fn call_tool(
    client: &rmcp::Peer<rmcp::RoleClient>,
    name: &'static str,
    arguments: Option<serde_json::Value>,
) -> rmcp::model::CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    if let Some(arguments) = arguments {
        params = params.with_arguments(args(arguments));
    }
    client.call_tool(params).await.expect("tool call")
}

fn parse_envelope(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let value = serde_json::to_value(result).expect("serialize tool result");
    let text = value["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("envelope JSON")
}

#[tokio::test]
async fn lists_all_v0_tools() {
    let client = connect_server(None).await;
    let tools = client.list_all_tools().await.expect("list tools");
    let names: std::collections::BTreeSet<_> =
        tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names.len(), 16);
    for expected in [
        "ovstorage_doctor",
        "ovstorage_capabilities",
        "ovstorage_stat",
        "ovstorage_list",
        "ovstorage_read",
        "ovstorage_materialize",
        "ovstorage_release",
        "ovstorage_write",
        "ovstorage_update_metadata",
        "ovstorage_create_directory",
        "ovstorage_delete",
        "ovstorage_delete_directory",
        "ovstorage_copy",
        "ovstorage_move",
        "ovstorage_connections_list",
        "ovstorage_address_roots_list",
    ] {
        assert!(names.contains(expected), "missing tool {expected}");
    }
}

#[tokio::test]
async fn doctor_returns_envelope_with_doctor_result() {
    let client = connect_server(None).await;
    let result = call_tool(&client, "ovstorage_doctor", None).await;
    assert_eq!(result.is_error, Some(false));
    let env = parse_envelope(&result);
    assert_eq!(env["v"], "0.1");
    assert_eq!(env["ok"], true);
    assert_eq!(env["operation"], "ovstorage_doctor");
    assert!(env["result"].get("ovstorage_version").is_some());
    assert!(env["result"].get("backend_kinds").is_some());
}

#[tokio::test]
async fn discovery_tools_return_empty_lists_with_no_config() {
    let client = connect_server(None).await;
    let result = call_tool(&client, "ovstorage_connections_list", None).await;
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    assert!(env["result"]["connections"].as_array().unwrap().is_empty());

    let result = call_tool(&client, "ovstorage_address_roots_list", None).await;
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    assert!(
        env["result"]["address_roots"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn capabilities_returns_caps_for_file_scheme() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let prefix = format!("file://{}/", tmp.path().display());
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_capabilities",
        Some(serde_json::json!({ "prefix": prefix })),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    assert!(env["result"].get("supports_overwrite").is_some());
}

#[tokio::test]
async fn stat_missing_object_returns_envelope_error_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let missing = format!("file://{}/does-not-exist", tmp.path().display());
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_stat",
        Some(serde_json::json!({ "address": missing })),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], false);
    assert_eq!(env["error"]["code"], "NotFound");
}

#[tokio::test]
async fn read_under_max_bytes_returns_base64_data() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let path = tmp.path().join("a.bin");
    std::fs::write(&path, b"hello").unwrap();
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_read",
        Some(serde_json::json!({
            "address": format!("file://{}", path.display()),
            "max_bytes": 1024
        })),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    let data = base64::engine::general_purpose::STANDARD
        .decode(env["result"]["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data, b"hello");
}

#[tokio::test]
async fn read_over_max_bytes_returns_resource_exhausted() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let path = tmp.path().join("big.bin");
    std::fs::write(&path, vec![0u8; 4096]).unwrap();
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_read",
        Some(serde_json::json!({
            "address": format!("file://{}", path.display()),
            "max_bytes": 1024
        })),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], false);
    assert_eq!(env["error"]["code"], "ResourceExhausted");
    assert_eq!(env["error"]["retryable"], true);
}

#[tokio::test]
async fn write_then_stat_then_read_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let addr = format!("file://{}/rt.bin", tmp.path().display());
    let client = connect_server(Some(config.path())).await;
    let payload = b"roundtrip-data";
    let result = call_tool(
        &client,
        "ovstorage_write",
        Some(serde_json::json!({
            "address": addr,
            "data_base64": base64::engine::general_purpose::STANDARD.encode(payload),
            "if_dest": { "kind": "overwrite" }
        })),
    )
    .await;
    assert_eq!(result.is_error, Some(false));

    let result = call_tool(
        &client,
        "ovstorage_stat",
        Some(serde_json::json!({ "address": addr })),
    )
    .await;
    let env = parse_envelope(&result);
    assert_eq!(env["result"]["size"], payload.len() as u64);

    let result = call_tool(
        &client,
        "ovstorage_read",
        Some(serde_json::json!({ "address": addr, "max_bytes": 4096 })),
    )
    .await;
    let env = parse_envelope(&result);
    let data = base64::engine::general_purpose::STANDARD
        .decode(env["result"]["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data, payload);
}

#[tokio::test]
async fn delete_directory_dry_run_returns_plan_without_mutating() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let subdir = tmp.path().join("sub");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("a.bin"), b"a").unwrap();
    std::fs::write(subdir.join("b.bin"), b"b").unwrap();
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_delete_directory",
        Some(serde_json::json!({
            "address": format!("file://{}", subdir.display()),
            "recursive": true,
            "dry_run": true
        })),
    )
    .await;
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    assert_eq!(env["result"]["dry_run"], true);
    assert_eq!(env["result"]["would_delete_count"], 2);
    assert!(subdir.join("a.bin").exists());
    assert!(subdir.join("b.bin").exists());
}

#[tokio::test]
async fn materialize_returns_path_info_and_expires_at() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let file_path = tmp.path().join("mat.bin");
    std::fs::write(&file_path, b"hello-materialize").unwrap();
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({"address": format!("file://{}", file_path.display())})),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], true);
    let result = env.get("result").expect("result");
    let path = result["path"].as_str().expect("path string");
    assert!(
        std::path::Path::new(path).exists(),
        "materialized path must exist: {path}",
    );
    assert!(result["expires_at_unix_seconds"].is_i64());
    assert!(result["info"]["size"].as_u64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn release_succeeds_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let file_path = tmp.path().join("rel.bin");
    std::fs::write(&file_path, b"x").unwrap();
    let client = connect_server(Some(config.path())).await;
    let mat = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({"address": format!("file://{}", file_path.display())})),
    )
    .await;
    let env = parse_envelope(&mat);
    let path = env["result"]["path"].as_str().unwrap().to_string();

    let rel1 = call_tool(
        &client,
        "ovstorage_release",
        Some(serde_json::json!({"path": &path})),
    )
    .await;
    let env = parse_envelope(&rel1);
    assert_eq!(env["result"]["released"], true);
    assert_eq!(env["result"]["was_active"], true);

    let rel2 = call_tool(
        &client,
        "ovstorage_release",
        Some(serde_json::json!({"path": &path})),
    )
    .await;
    let env = parse_envelope(&rel2);
    assert_eq!(env["result"]["released"], true);
    assert_eq!(env["result"]["was_active"], false);
}

#[tokio::test]
async fn release_on_never_materialized_path_returns_was_active_false() {
    let client = connect_server(None).await;
    let result = call_tool(
        &client,
        "ovstorage_release",
        Some(serde_json::json!({"path": "/cache/never/materialized"})),
    )
    .await;
    let env = parse_envelope(&result);
    assert_eq!(env["result"]["released"], true);
    assert_eq!(env["result"]["was_active"], false);
}

#[tokio::test]
async fn materialize_with_zero_ttl_returns_invalid_argument() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let file_path = tmp.path().join("zero.bin");
    std::fs::write(&file_path, b"x").unwrap();
    let client = connect_server(Some(config.path())).await;
    let result = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({
            "address": format!("file://{}", file_path.display()),
            "ttl_seconds": 0
        })),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let env = parse_envelope(&result);
    assert_eq!(env["ok"], false);
    assert_eq!(env["error"]["code"], "InvalidArgument");
}

#[tokio::test]
async fn re_materialize_refreshes_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let file_path = tmp.path().join("refresh.bin");
    std::fs::write(&file_path, b"x").unwrap();
    let address = format!("file://{}", file_path.display());
    let client = connect_server(Some(config.path())).await;
    let r1 = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({"address": &address, "ttl_seconds": 60})),
    )
    .await;
    let exp1 = parse_envelope(&r1)["result"]["expires_at_unix_seconds"]
        .as_i64()
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let r2 = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({"address": &address, "ttl_seconds": 60})),
    )
    .await;
    let exp2 = parse_envelope(&r2)["result"]["expires_at_unix_seconds"]
        .as_i64()
        .unwrap();

    assert!(
        exp2 > exp1,
        "expires_at should advance with refresh (exp1={exp1}, exp2={exp2})",
    );
}

#[tokio::test]
async fn ttl_expiry_auto_releases() {
    let tmp = tempfile::tempdir().unwrap();
    let config = write_file_config(tmp.path());
    let file_path = tmp.path().join("ttl.bin");
    std::fs::write(&file_path, b"x").unwrap();
    let client = connect_server(Some(config.path())).await;
    let mat = call_tool(
        &client,
        "ovstorage_materialize",
        Some(serde_json::json!({
            "address": format!("file://{}", file_path.display()),
            "ttl_seconds": 1
        })),
    )
    .await;
    let env = parse_envelope(&mat);
    let path = env["result"]["path"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let rel = call_tool(
        &client,
        "ovstorage_release",
        Some(serde_json::json!({"path": path})),
    )
    .await;
    let env = parse_envelope(&rel);
    assert_eq!(
        env["result"]["was_active"], false,
        "lease should have expired before release",
    );
}

/// A version outside `KNOWN_VERSIONS`, built the only way one can be: the
/// tuple field is private, so it arrives through `Deserialize` exactly as a
/// real client's unrecognised version would.
fn unknown_version(raw: &str) -> ProtocolVersion {
    serde_json::from_value(serde_json::Value::String(raw.to_string()))
        .expect("any string deserializes to a ProtocolVersion")
}

/// Handshake as a client asking for `requested`, and report what was negotiated.
///
/// `connect_server` serves `()`, whose `ClientInfo` always carries the SDK's
/// own default, so it can only ever observe one version. Serving a
/// `ClientInfo` instead is what lets a test ask for a specific one.
async fn negotiated_version(requested: ProtocolVersion) -> ProtocolVersion {
    let mut cmd = Command::new(server_binary());
    cmd.env("OVSTORAGE_PLUGIN_DIR", empty_plugin_dir());
    cmd.env("OVSTORAGE_MCP_NO_CONFIG", "1");
    cmd.env_remove("OVSTORAGE_CONFIG");
    let transport = TokioChildProcess::new(cmd).expect("spawn server");
    let client = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("ovstorage-mcp-tests", env!("CARGO_PKG_VERSION")),
    )
    .with_protocol_version(requested)
    .serve(transport)
    .await
    .expect("rmcp handshake");
    let negotiated = client
        .peer_info()
        .expect("server answered initialize")
        .protocol_version
        .clone();
    client.cancel().await.ok();
    negotiated
}

#[tokio::test]
async fn default_client_negotiates_the_advertised_version() {
    assert_eq!(
        negotiated_version(ProtocolVersion::default()).await,
        ProtocolVersion::V_2025_11_25,
        "the release notes name this as the version the server advertises",
    );
}

#[tokio::test]
async fn a_client_pinned_to_an_older_version_keeps_it() {
    // The notes promise an existing client needs no change, which is a claim
    // about the server echoing rather than upgrading what it was asked for.
    for requested in [
        ProtocolVersion::V_2024_11_05,
        ProtocolVersion::V_2025_03_26,
        ProtocolVersion::V_2025_06_18,
    ] {
        assert_eq!(
            negotiated_version(requested.clone()).await,
            requested,
            "a pinned client must negotiate the version it asked for",
        );
    }
}

#[tokio::test]
async fn a_client_ahead_of_the_default_still_negotiates_its_version() {
    // `KNOWN_VERSIONS` reaches past the default and the server does not narrow
    // it, so the ceiling is not the default. Asserting this pins the
    // distinction the notes draw between what is advertised and what is served.
    assert_eq!(
        negotiated_version(ProtocolVersion::V_2026_07_28).await,
        ProtocolVersion::V_2026_07_28,
    );
}

#[tokio::test]
async fn an_unknown_version_falls_back_to_the_advertised_one() {
    assert_eq!(
        negotiated_version(unknown_version("1999-01-01")).await,
        ProtocolVersion::V_2025_11_25,
        "an unrecognised request is what the advertised default answers",
    );
}
