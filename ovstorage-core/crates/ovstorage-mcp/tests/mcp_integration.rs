// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use base64::Engine;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::TokioChildProcess;
use tokio::process::Command;

fn server_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage-mcp"))
}

fn file_plugin_dir() -> PathBuf {
    let _force_plugin_build = ovstorage_plugin_file::FileBackendFactory;
    let plugin_name = if cfg!(target_os = "windows") {
        "ovstorage_plugin_file.dll"
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_file.dylib"
    } else {
        "libovstorage_plugin_file.so"
    };
    let source = server_binary()
        .parent()
        .expect("binary has parent")
        .join("deps")
        .join(plugin_name);
    let dir = tempfile::tempdir().expect("plugin temp dir").keep();
    std::fs::copy(&source, dir.join(plugin_name)).expect("copy file plugin");
    dir
}

async fn connect_server(config: Option<&Path>) -> RunningService<rmcp::RoleClient, ()> {
    let mut cmd = Command::new(server_binary());
    cmd.env("OVSTORAGE_PLUGIN_DIR", file_plugin_dir());
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
    std::fs::write(
        config.path(),
        format!(
            r#"
[[connections]]
backend_kind = "file"
display_name = "test file"

[connections.config]
root = "{}"
prefix = "file://{}/"
"#,
            root.display(),
            root.display()
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
    let params = CallToolRequestParams {
        meta: None,
        name: name.into(),
        arguments: arguments.map(args),
        task: None,
    };
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
