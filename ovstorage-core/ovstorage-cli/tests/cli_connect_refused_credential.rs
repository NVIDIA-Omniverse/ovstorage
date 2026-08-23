// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `connect` against an origin that refuses the credential it was given.
//!
//! `connect` skips `authenticate_connection` for a settled connection and
//! tolerates the `Unsupported` a backend with no interactive flow answers
//! with. `AuthFailed` is neither: it is the origin's definite refusal, so
//! reporting `Connected` and exiting 0 over it would tell the operator the
//! opposite of what happened — and would leave the route prefix taken, since
//! the CLI has no command that removes a connection.
//!
//! `http` is used because it is the one in-tree backend that decides
//! `AuthFailed` from a live answer (a `401` to its connect-time probe).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

/// The staged cdylib set, which includes `ovstorage_plugin_http`.
fn staged_plugin_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-plugins");
    assert!(
        dir.is_dir(),
        "run `make build-test-plugins` before this test"
    );
    dir
}

/// Answers `401` to everything, which is what an origin does when the
/// credential it was handed (here, none) is not one it accepts.
fn spawn_unauthorized_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 401 Unauthorized\r\n\
                  WWW-Authenticate: Basic realm=\"test\"\r\n\
                  Content-Length: 0\r\n\r\n",
            );
            let _ = stream.flush();
        }
    });
    // Userinfo, because `connect`'s non-interactive path takes config field
    // values on the command line and still prompts for a declared credential
    // at the TTY — there is no TTY here. Userinfo is the one credential
    // channel that rides in a config field, and it drives the same probe.
    // Loopback cleartext is exempt from the plaintext-credential refusal.
    format!("http://probe-user:probe-pass@{addr}/")
}

/// Answers `200` to everything, so the same credential is accepted.
fn spawn_accepting_origin() -> String {
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
    format!("http://probe-user:probe-pass@{addr}/")
}

fn write_http_config(dir: &Path) -> PathBuf {
    let config = dir.join("ovstorage.toml");
    std::fs::write(
        &config,
        r#"[ovstorage]
root = "http"

[ovstorage.layers.http]
"#,
    )
    .unwrap();
    config
}

#[test]
fn connect_fails_when_the_origin_refuses_the_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = staged_plugin_dir();
    let config = write_http_config(tmp.path());
    let root_url = spawn_unauthorized_origin();

    // KIND plus a value for every required config field takes the
    // non-interactive path, so no TTY is needed.
    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("connect")
        .arg("http")
        .arg(&root_url)
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a refused credential must not exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("Connected"),
        "a refused credential must not be reported as a connection.\nstdout: {stdout}"
    );
    // Pin the error's identity, or any failure to load the plugin, parse the
    // config or reach the non-interactive path would satisfy the assertions
    // above and this test would pass for the wrong reason.
    assert!(
        stderr.contains("401"),
        "the failure must be the origin's refusal, not some other error.\nstderr: {stderr}"
    );
    // The registration survives on purpose: the probe is a `HEAD` on the root,
    // and an origin that challenges its root while serving objects beneath it
    // is an ordinary shape, so `connect` reports the refusal without
    // discarding a configuration whose data path may work.
    assert!(
        stdout.contains("Registered, but not authenticated"),
        "the refused connection must still be reported as registered.\nstdout: {stdout}"
    );
}

/// The positive control for the assertions above: the same command against an
/// origin that accepts the credential must exit 0 and say `Connected`.
#[test]
fn connect_succeeds_when_the_origin_accepts_the_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = staged_plugin_dir();
    let config = write_http_config(tmp.path());
    let root_url = spawn_accepting_origin();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("connect")
        .arg("http")
        .arg(&root_url)
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "an accepted credential must exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // `Connected` is printed only for a settled identity. Asserting the
    // absence of the unconfirmed headline is what gives this teeth: without
    // it, a probe that quietly stopped proving anything would still print a
    // line containing "Connected" and exit 0.
    assert!(
        stdout.contains("Connected"),
        "an accepted credential must report a connection.\nstdout: {stdout}"
    );
    assert!(
        !stdout.contains("Registered, credential unconfirmed"),
        "the credential must be proven, not merely unrefuted.\nstdout: {stdout}"
    );
    assert!(
        !stderr.contains("was not confirmed"),
        "an accepted credential must carry no unconfirmed note.\nstderr: {stderr}"
    );
}
