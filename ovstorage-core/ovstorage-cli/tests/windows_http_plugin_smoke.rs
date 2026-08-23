// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(windows)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

fn prepare_http_plugin_dir(dir: &Path) -> PathBuf {
    let plugin_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    let source = binary()
        .parent()
        .expect("ovstorage binary has a parent directory")
        .join("ovstorage_plugin_http.dll");
    assert!(
        source.exists(),
        "http plugin artifact does not exist at {}; build ovstorage-plugin-http before this test",
        source.display()
    );
    std::fs::copy(source, plugin_dir.join("ovstorage_plugin_http.dll")).unwrap();
    plugin_dir
}

fn spawn_http_fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0_u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let method = request.split_whitespace().next().unwrap_or("");
            let response = if method == "HEAD" {
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\nhello".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}/")
}

fn write_http_config(dir: &Path, root_url: &str) -> PathBuf {
    let config = dir.join("ovstorage.toml");
    std::fs::write(
        &config,
        format!(
            r#"[ovstorage]
root = "alias"

[ovstorage.layers.alias]
inner = "copy_rename_fallback"

[ovstorage.layers.copy_rename_fallback]
inner = "redirect_follower"

[ovstorage.layers.redirect_follower]
inner = "retry"

[ovstorage.layers.retry]
inner = "router"

[ovstorage.layers.router]
children = ["file", "http"]

[ovstorage.layers.file]

[ovstorage.layers.http]

[[ovstorage.connections]]
backend_kind = "http"

[ovstorage.connections.config]
root_url = "{root_url}"
"#
        ),
    )
    .unwrap();
    config
}

fn run_cli(config: &Path, plugin_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(binary());
    command
        .env("OVSTORAGE_PLUGIN_DIR", plugin_dir)
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::null());
    command.output().expect("run ovstorage")
}

#[test]
fn http_plugin_read_and_stat_child_processes_exit_zero_after_network_io() {
    let tmp = tempfile::tempdir().unwrap();
    let root_url = spawn_http_fixture();
    let config = write_http_config(tmp.path(), &root_url);
    let plugin_dir = prepare_http_plugin_dir(tmp.path());
    let address = format!("{root_url}object.txt");

    let read = run_cli(&config, &plugin_dir, &["read", &address]);
    assert!(
        read.status.success(),
        "read stderr: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&read.stdout), "hello");

    let stat = run_cli(&config, &plugin_dir, &["stat", &address]);
    assert!(
        stat.status.success(),
        "stat stderr: {}",
        String::from_utf8_lossy(&stat.stderr)
    );
}
