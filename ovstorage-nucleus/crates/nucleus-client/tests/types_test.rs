// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use nucleus_client::types::*;

#[test]
fn test_status_type_serde() {
    let status = StatusType::OK;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, r#""OK""#);

    let parsed: StatusType = serde_json::from_str(r#""DENIED""#).unwrap();
    assert_eq!(parsed, StatusType::Denied);
}

#[test]
fn test_path_at_version_serde() {
    let pav = PathAtVersion {
        path: "/test/path".to_string(),
        branch: None,
        checkpoint: Some(42),
    };
    let json = serde_json::to_string(&pav).unwrap();
    assert!(!json.contains("branch"));
    assert!(json.contains("42"));
}

#[test]
fn test_path_type_serde() {
    let pt = PathType::Asset;
    let json = serde_json::to_string(&pt).unwrap();
    assert_eq!(json, r#""asset""#);
}

#[test]
fn test_stat2_result_deserialize() {
    let json = r#"{
        "status": "OK",
        "type": "asset",
        "uri": "/test.usd",
        "size": 12345,
        "etag": "abc123"
    }"#;
    let result: Stat2Result = serde_json::from_str(json).unwrap();
    assert_eq!(result.status, StatusType::OK);
    assert_eq!(result.size, Some(12345));
}

#[test]
fn test_auth_deserialize_rejects_missing_required_fields() {
    let json = r#"{"status": "DENIED"}"#;
    let err = serde_json::from_str::<Auth>(json).expect_err(
        "missing required username/token/connection_id/max_chunk_size must fail-closed",
    );
    let msg = err.to_string();
    assert!(msg.contains("missing field"), "unexpected error: {msg}");
}

#[test]
fn test_auth_deserialize_complete_denied_response() {
    let json = r#"{
        "status": "DENIED",
        "username": "",
        "token": "",
        "connection_id": "",
        "max_chunk_size": 0
    }"#;
    let result: Auth = serde_json::from_str(json).unwrap();
    assert_eq!(result.status, StatusType::Denied);
    assert!(result.username.is_empty());
    assert!(result.token.is_empty());
}

#[test]
fn test_list2_response_deserialize() {
    let json = r#"{
        "status": "OK",
        "entries": [
            {"path": "/foo", "path_type": "folder"},
            {"path": "/bar.usd", "path_type": "asset", "size": 100}
        ]
    }"#;
    let result: List2Response = serde_json::from_str(json).unwrap();
    assert_eq!(result.status, StatusType::OK);
    let entries = result.entries.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path_type, Some(PathType::Folder));
    assert_eq!(entries[1].size, Some(100));
}
