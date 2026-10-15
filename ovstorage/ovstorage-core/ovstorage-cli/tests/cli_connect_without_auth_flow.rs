// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `connect` against a backend whose identity `add_connection` already
//! settled.
//!
//! `connect` drives `authenticate_connection` after `add_connection` and drops
//! the connection when the flow errors. `file` reports
//! `ConnectionAuthState::Anonymous`, so what this test pins is the *settled*
//! short-circuit: the flow is never entered, and `connect` does not fail for a
//! backend that has no credentials to establish.
//!
//! It deliberately does not reach the `AuthOutcome::NoFlowOffered` arm for a backend that offers
//! no flow at all — that needs an unsettled state, which only a credentialed
//! backend produces. `cli_connect_refused_credential.rs` covers it.
//!
//! `file` is used because it is the only backend the host serves natively, with
//! no cdylib to build.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

/// Empty: `file` is served natively, so plugin discovery must find nothing
/// rather than be pointed at the shared target dir.
fn prepare_empty_plugin_dir(dir: &Path) -> PathBuf {
    let plugin_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    plugin_dir
}

fn write_layer_only_config(dir: &Path) -> PathBuf {
    let config = dir.join("ovstorage.toml");
    std::fs::write(
        &config,
        r#"[ovstorage]
root = "file"

[ovstorage.layers.file]
"#,
    )
    .unwrap();
    config
}

#[test]
fn connect_succeeds_when_the_backend_has_no_authenticate_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = prepare_empty_plugin_dir(tmp.path());
    let config = write_layer_only_config(tmp.path());
    let root = tmp.path().join("data");
    std::fs::create_dir_all(&root).unwrap();

    // KIND plus a value for every required config field takes the
    // non-interactive path, so no TTY is needed.
    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("connect")
        .arg("file")
        .arg(root.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "connect must not fail because the backend has no auth flow.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("authenticate_connection"),
        "the Unsupported auth slot must not surface to the operator.\nstderr: {stderr}"
    );
}
