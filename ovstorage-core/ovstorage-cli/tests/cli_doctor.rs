// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ovstorage doctor`.

use std::process::Command;

fn ovstorage_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

#[test]
fn doctor_json_emits_v01_envelope_with_doctor_result() {
    let output = Command::new(ovstorage_binary())
        .args(["--no-config", "doctor", "--json"])
        .output()
        .expect("ovstorage doctor --json runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let env: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON on stdout");

    assert_eq!(env["v"], "0.1");
    assert_eq!(env["ok"], true);
    assert_eq!(env["operation"], "doctor");
    let result = env.get("result").expect("result present on ok envelope");
    assert!(result.get("ovstorage_version").is_some());
    assert!(result.get("backend_kinds").is_some());
    assert!(result.get("connections").is_some());
    assert!(result.get("address_roots").is_some());
    assert!(result.get("aliases").is_some());
    assert!(env.get("error").is_none());
}

#[test]
fn doctor_human_output_contains_section_headers() {
    let output = Command::new(ovstorage_binary())
        .args(["--no-config", "doctor"])
        .output()
        .expect("ovstorage doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("ovstorage doctor"));
    assert!(stdout.contains("Backend kinds"));
    assert!(stdout.contains("Connections"));
    assert!(stdout.contains("Address roots"));
    assert!(stdout.contains("Aliases"));
}
