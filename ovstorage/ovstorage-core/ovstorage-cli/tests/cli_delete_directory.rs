// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ovstorage delete-directory` recursive safety.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ovstorage"))
}

/// Create an empty plugin dir. The `file` backend is served natively in the
/// configured Stack, so no `file` cdylib is loaded;
/// `OVSTORAGE_PLUGIN_DIR` points here so `load_plugins_from_dir` is a no-op
/// while native `file` handles the config's `backend_kind = "file"` connection.
fn prepare_file_plugin_dir(dir: &Path) -> PathBuf {
    let plugin_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    plugin_dir
}

fn make_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.bin"), b"a").unwrap();
    std::fs::write(root.join("sub/b.bin"), b"b").unwrap();
    std::fs::write(root.join("sub/c.bin"), b"c").unwrap();
}

fn write_file_config(dir: &Path, root: &Path) -> PathBuf {
    let config = dir.join("ovstorage.toml");
    let root = root.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(
        &config,
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
    .unwrap();
    config
}

fn run_delete_directory(
    config: &Path,
    plugin_dir: &Path,
    address: &str,
    args: &[&str],
) -> std::process::Output {
    let mut command = Command::new(binary());
    command
        .env("OVSTORAGE_PLUGIN_DIR", plugin_dir)
        .arg("--config")
        .arg(config)
        .arg("delete-directory")
        .arg(address)
        .args(args)
        .stdin(Stdio::null());
    command.output().expect("run ovstorage delete-directory")
}

#[test]
fn dry_run_prints_plan_and_does_not_mutate() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    make_tree(&tree);
    let config = write_file_config(tmp.path(), tmp.path());
    let plugin_dir = prepare_file_plugin_dir(tmp.path());
    let addr = format!("file://{}", tree.display());

    let output = run_delete_directory(&config, &plugin_dir, &addr, &["--recursive", "--dry-run"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("Recursive delete plan"));
    assert!(stdout.contains("a.bin"));
    assert!(stdout.contains("b.bin"));
    assert!(stdout.contains("dry-run"));
    assert!(tree.join("a.bin").exists());
    assert!(tree.join("sub/b.bin").exists());
}

#[test]
fn recursive_with_yes_executes_without_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    make_tree(&tree);
    let config = write_file_config(tmp.path(), tmp.path());
    let plugin_dir = prepare_file_plugin_dir(tmp.path());
    let addr = format!("file://{}", tree.display());

    let output = run_delete_directory(&config, &plugin_dir, &addr, &["--recursive", "--yes"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!tree.exists());
}

#[test]
fn recursive_without_yes_in_noninteractive_mode_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    make_tree(&tree);
    let config = write_file_config(tmp.path(), tmp.path());
    let plugin_dir = prepare_file_plugin_dir(tmp.path());
    let addr = format!("file://{}", tree.display());

    let output = run_delete_directory(&config, &plugin_dir, &addr, &["--recursive"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--yes") || stderr.contains("--dry-run"));
    assert!(tree.join("a.bin").exists());
}

#[test]
fn nonrecursive_on_nonempty_directory_fails_loudly() {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    make_tree(&tree);
    let config = write_file_config(tmp.path(), tmp.path());
    let plugin_dir = prepare_file_plugin_dir(tmp.path());
    let addr = format!("file://{}", tree.display());

    let output = run_delete_directory(&config, &plugin_dir, &addr, &[]);
    assert!(!output.status.success());
    assert!(tree.join("a.bin").exists());
}
