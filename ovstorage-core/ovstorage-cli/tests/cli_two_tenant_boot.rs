// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A stack with two backend layers of one kind still starts, and serves both.
//!
//! This is the two-tenant graph. Its connections have distinct prefixes, so
//! nothing collides and both must register — but the build-time connection
//! apply is what decides that, and a regression there takes the whole host
//! down rather than one connection.
//!
//! Driven through the binary and the staged cdylibs rather than in-process:
//! the router is a loaded plugin, so the ABI path is the one that has to
//! survive, and it is the path a host actually boots on.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

fn staged_plugin_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-plugins");
    assert!(
        dir.is_dir(),
        "run `make build-test-plugins` before this test"
    );
    dir
}

fn spawn_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        }
    });
    format!("{addr}")
}

#[test]
fn two_backend_layers_of_one_kind_both_serve_their_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = staged_plugin_dir();
    let authority = spawn_origin();
    let config = tmp.path().join("ovstorage.toml");
    std::fs::write(
        &config,
        format!(
            r#"[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["http_prod", "http_stage"]

[ovstorage.layers.http_prod]
kind = "http"

[ovstorage.layers.http_stage]
kind = "http"

[[ovstorage.connections]]
backend_kind = "http"
target = "http_prod"

[ovstorage.connections.config]
root_url = "http://{authority}/prod/"

[[ovstorage.connections]]
backend_kind = "http"
target = "http_stage"

[ovstorage.connections.config]
root_url = "http://{authority}/stage/"
"#
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("list-routes")
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a two-tenant graph must start.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // Both prefixes, so neither connection was dropped or shadowed. Asserting
    // only that the host booted would pass with one connection silently gone.
    assert!(
        stdout.contains(&format!("http://{authority}/prod/")),
        "the first tenant's route is missing.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!("http://{authority}/stage/")),
        "the second tenant's route is missing.\nstdout: {stdout}"
    );
}
