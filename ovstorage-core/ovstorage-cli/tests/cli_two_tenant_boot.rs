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

/// The two-tenant config, with `display_name`s so a scripted session can name
/// one connection. A connection id is minted at runtime
/// (`routing::fresh_id` stamps the pid), so a script written in advance cannot
/// contain one — which is why `list-connections` prints the id first for a
/// human or a pipeline to pick up, and why the id selector is covered by unit
/// tests in `commands::connections` instead.
fn two_tenant_config(authority: &str) -> String {
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
display_name = "prod"

[ovstorage.connections.config]
root_url = "http://{authority}/prod/"

[[ovstorage.connections]]
backend_kind = "http"
target = "http_stage"
display_name = "stage"

[ovstorage.connections.config]
root_url = "http://{authority}/stage/"
"#
    )
}

/// Run a scripted REPL session against `config` and return `(stdout, stderr)`.
///
/// A REPL rather than one-shot invocations because the whole point is that the
/// commands share one process: a `disconnect` in its own process would exit
/// before anything could observe what it removed.
fn repl_session(
    config: &Path,
    plugin_dir: &Path,
    auth_dir: &Path,
    script: &str,
) -> (String, String) {
    let mut child = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", plugin_dir)
        .env("OVSTORAGE_AUTH_DIR", auth_dir)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ovstorage REPL");
    {
        let stdin = child.stdin.as_mut().expect("stdin handle");
        stdin
            .write_all(script.as_bytes())
            .expect("script the session");
        stdin.flush().expect("flush");
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait_with_output");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

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

/// `list-connections` shows both tenants — the inventory `list-routes` cannot
/// give, because it answers about addresses and says nothing about which
/// connection publishes them.
#[test]
fn list_connections_shows_every_tenant_with_a_usable_selector() {
    let tmp = tempfile::tempdir().unwrap();
    let authority = spawn_origin();
    let config = tmp.path().join("ovstorage.toml");
    std::fs::write(&config, two_tenant_config(&authority)).unwrap();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", staged_plugin_dir())
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("list-connections")
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "list-connections must succeed on a two-tenant graph.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let rows: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("\thttp\t"))
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "both tenants must be listed.\nstdout: {stdout}"
    );

    // The id leads because it is the selector; a row whose first column is
    // empty would list connections nothing could then address.
    let mut ids = Vec::new();
    for row in &rows {
        let mut columns = row.split('\t');
        let id = columns.next().expect("every row has a first column");
        assert!(!id.is_empty(), "a row must carry an id.\nrow: {row}");
        ids.push(id);
    }
    assert_ne!(
        ids[0], ids[1],
        "connection ids are unique.\nstdout: {stdout}"
    );

    for expected in ["prod", "stage"] {
        assert!(
            rows.iter()
                .any(|row| row.contains(&format!("\t{expected}\t"))),
            "the '{expected}' tenant is missing.\nstdout: {stdout}"
        );
    }
    // Both connections probe an origin that answers 200 without a challenge,
    // so both settle. Pinning the vocabulary keeps the column machine-readable.
    assert!(
        rows.iter()
            .all(|row| row.contains("\tanonymous\t") || row.contains("\tauthenticated\t")),
        "the auth-state column must use the compact vocabulary.\nstdout: {stdout}"
    );

    // **The target column is the other half of the selector.** An id is unique
    // only within the layer that owns it, so a row's id alone does not address
    // it -- and on this graph the two rows are the same `backend_kind`, so
    // nothing else here tells them apart either. Each row must name the layer
    // that holds it, and the two must differ. Driven through the binary and the
    // staged cdylibs, so this is the value that crossed the plugin ABI from the
    // http backend and back out through the loaded router's fan-out.
    let targets: Vec<&str> = rows
        .iter()
        .map(|row| {
            row.split('\t')
                .nth(1)
                .expect("every row has a target column")
        })
        .collect();
    let mut sorted = targets.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        ["http_prod", "http_stage"],
        "each row must name the layer instance that owns it.\nstdout: {stdout}"
    );
}

/// `disconnect` removes exactly one connection, and the graph keeps serving the
/// other.
#[test]
fn disconnect_removes_one_tenant_and_leaves_the_other_routing() {
    let tmp = tempfile::tempdir().unwrap();
    let authority = spawn_origin();
    let config = tmp.path().join("ovstorage.toml");
    std::fs::write(&config, two_tenant_config(&authority)).unwrap();

    // One process: a `disconnect` in its own would exit before `list-routes`
    // could observe what it removed, because connections are not persisted.
    let (stdout, stderr) = repl_session(
        &config,
        &staged_plugin_dir(),
        &tmp.path().join("auth"),
        "disconnect stage\nlist-routes\nquit\n",
    );

    assert!(
        stderr.contains("disconnected 'stage'"),
        "the removal must be reported.\nstderr: {stderr}"
    );
    // The owner scan had to cross a target boundary to get here: `stage`'s
    // connection lives on `http_stage`, and nothing in its snapshot said so.
    assert!(
        stderr.contains("http_stage"),
        "the scan must name the layer that owned it.\nstderr: {stderr}"
    );

    let routes: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with(&format!("http://{authority}/")))
        .collect();
    assert_eq!(
        routes.len(),
        1,
        "exactly one route may survive.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        routes[0].starts_with(&format!("http://{authority}/prod/")),
        "the tenant that was NOT disconnected must keep its route.\nstdout: {stdout}"
    );
}

/// `reauth` is reachable on a two-tenant graph.
///
/// It used to resolve the owning layer from `backend_kind`, which cannot name
/// one of two same-kind layers, so this graph answered `InvalidArgument` —
/// "kind is ambiguous" — and the command could not be run at all. The fix under
/// test is REACHABILITY, so the assertion is that the error changed: `http`
/// offers no interactive flow, so the run now reaches the backend and ends in
/// its `Unsupported`, which is the documented per-backend answer.
#[test]
fn reauth_reaches_the_backend_on_a_two_tenant_graph() {
    let tmp = tempfile::tempdir().unwrap();
    let authority = spawn_origin();
    let config = tmp.path().join("ovstorage.toml");
    std::fs::write(&config, two_tenant_config(&authority)).unwrap();

    let output = Command::new(binary())
        .env("OVSTORAGE_PLUGIN_DIR", staged_plugin_dir())
        .env("OVSTORAGE_AUTH_DIR", tmp.path().join("auth"))
        .arg("--config")
        .arg(&config)
        .arg("reauth")
        .arg("stage")
        .stdin(Stdio::null())
        .output()
        .expect("run ovstorage");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authenticating 'stage'"),
        "the connection must be found and addressed.\nstderr: {stderr}"
    );
    assert!(
        !stderr.contains("ambiguous"),
        "the owning layer must no longer be guessed from the backend kind.\n\
         stderr: {stderr}"
    );
    assert!(
        !stderr.contains("InvalidArgument"),
        "resolution must not fail before the backend is reached.\nstderr: {stderr}"
    );
    // `Unsupported` is exit 6 per the README's table: the run got all the way
    // to a backend that has no interactive flow, which is the answer `reauth`
    // documents for `http`.
    assert_eq!(
        output.status.code(),
        Some(6),
        "reauth must end in the backend's own `Unsupported`.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}
