// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prefix exclusivity holds across the WHOLE graph, not one layer instance.
//!
//! The sibling of `cli_two_tenant_boot`, which covers the case that must keep
//! working: two backend layers of one kind whose connections have distinct
//! prefixes both register and both serve. Here the two prefixes differ only in
//! userinfo, and a route prefix never carries userinfo — so they name ONE node
//! and only one of them can ever be routed.
//!
//! Each `http` layer instance enforces exclusivity over its own state and
//! cannot see its sibling's, so without a refusal at the aggregation boundary
//! both register, the route table prints the prefix twice, and one of the two
//! is registered, unroutable and silently unused. The Router refuses the
//! second, the build-time apply reports and skips it, and the host still boots
//! — one duplicated `[[connections]]` entry must not take an unrelated backend
//! down with it.
//!
//! The refusal is POST-COMMIT: the child accepts and probes before the Router
//! can see the collision, so the skipped connection's credential does reach the
//! origin once. What the refusal buys is that it is then rolled back off the
//! child rather than left registered forever.
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

/// Accepts every credential, so nothing but the collision decides the outcome:
/// a `401` here would strand a connection in `AuthFailed` and the test could
/// pass for the wrong reason.
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
fn two_backend_layers_cannot_both_claim_one_address_root() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = staged_plugin_dir();
    let authority = spawn_origin();
    let config = tmp.path().join("ovstorage.toml");
    // The two connections differ ONLY in userinfo. Loopback cleartext is
    // exempt from the plaintext-credential refusal, and userinfo is the one
    // credential channel that rides in a config field — so this is the
    // two-tenant shape an operator actually writes when two teams share an
    // origin under different accounts.
    std::fs::write(
        &config,
        format!(
            r#"[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["http_a", "http_b"]

[ovstorage.layers.http_a]
kind = "http"

[ovstorage.layers.http_b]
kind = "http"

[[ovstorage.connections]]
backend_kind = "http"
target = "http_a"

[ovstorage.connections.config]
root_url = "http://alice:alice-secret@{authority}/assets/"

[[ovstorage.connections]]
backend_kind = "http"
target = "http_b"

[ovstorage.connections.config]
root_url = "http://bob:bob-secret@{authority}/assets/"
"#
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        // The skip is a `warn`, and the CLI installs no subscriber unless a
        // filter is set.
        .env("OVSTORAGE_LOG", "warn")
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
        "a colliding connection must be skipped, not fatal: the rest of the \
         graph is unaffected.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The route prefix carries no userinfo, which is exactly why the two
    // connections collide — and why counting it is the whole assertion. Twice
    // is the bug: both registered, one unroutable.
    let prefix = format!("http://{authority}/assets/");
    let printed = stdout.lines().filter(|line| line.contains(&prefix)).count();
    assert_eq!(
        printed, 1,
        "exactly one of two colliding connections may hold the prefix; \
         {printed} routes printed it.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Pin the reason, or a graph that failed to load either connection would
    // satisfy the count above and this test would pass for the wrong reason.
    assert!(
        stderr.contains("skipping a declared connection whose route is already served"),
        "the operator must be told which declared connection was dropped.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("http_b"),
        "the skip must name the layer whose connection was refused — the first \
         one applied keeps the route.\nstderr: {stderr}"
    );
    // The refusal names the origin and nothing else: userinfo, a signed-URL
    // query and a capability path segment can each carry a secret.
    assert!(
        !stderr.contains("bob-secret") && !stderr.contains("alice-secret"),
        "a route-conflict refusal must not render the credential it collided \
         on.\nstderr: {stderr}"
    );
}

/// The same collision on a backend that cannot roll the refusal back, which is
/// where "the host still boots" is hardest to hold — and where it was lost.
///
/// `file` implements `add_connection` and leaves `remove_connection` to the
/// `Layer` default, so the Router's post-commit rollback answers `Unsupported`
/// and the refusal becomes `CommitAmbiguous`: the connection is registered, and
/// this Layer quarantines its roots so it cannot serve. That is a report, not a
/// reason to abort — the graph itself is fine, and a build that failed here
/// would take every unrelated backend down over one copy-pasted
/// `[[ovstorage.connections]]` entry, on the DEFAULT filesystem backend, and
/// loop a host that auto-restarts.
///
/// `file` rather than `http` on purpose: it is the only in-tree backend without
/// `remove_connection` (`s3`, `gcs`, `azure` and `opendal` all implement it), so
/// it is the one shape that reaches this arm.
#[test]
fn a_collision_the_child_cannot_roll_back_still_boots_the_host() {
    let plugin_dir = staged_plugin_dir();
    let tmp = tempfile::tempdir().unwrap();
    let shared = tmp.path().join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    let root = format!("file://{}/", shared.display());

    let config = tmp.path().join("ovstorage.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[ovstorage]
root = "r"

[ovstorage.layers.r]
kind = "router"
children = ["file_a", "file_b"]

[ovstorage.layers.file_a]
kind = "file"

[ovstorage.layers.file_b]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"
target = "file_a"

[ovstorage.connections.config]
root = "{root}"

[[ovstorage.connections]]
backend_kind = "file"
target = "file_b"

[ovstorage.connections.config]
root = "{root}"
"#
        ),
    )
    .unwrap();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .env("OVSTORAGE_LOG", "warn")
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
        "a duplicated connection on a backend that cannot undo the refusal must \
         not stop the host from starting.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let printed = stdout.lines().filter(|line| line.contains(&root)).count();
    assert_eq!(
        printed, 1,
        "exactly one of the two may hold the root; the quarantined one must not \
         route.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Pin the reason, so a graph that simply failed to apply either connection
    // cannot satisfy the count above.
    assert!(
        stderr.contains("could not confirm it"),
        "the operator must be told the connection was registered and why it is \
         not routing.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("file_b"),
        "and which layer holds the leftover to remove by hand.\nstderr: {stderr}"
    );
}
