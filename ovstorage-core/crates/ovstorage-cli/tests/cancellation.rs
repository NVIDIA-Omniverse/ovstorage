// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the CLI's Ctrl+C handling.
//!
//! Only a clean-exit smoke test runs here: spawn the binary in REPL
//! mode, close stdin, assert exit 0. The interrupt-decision timing and
//! next-or-cancel pumping have unit-test coverage in their respective
//! modules; SIGINT-during-command behavior is verified manually because
//! the test environment has no loadable backend plugins to produce a
//! long-running command.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

const OVSTORAGE_BIN: &str = env!("CARGO_BIN_EXE_ovstorage");

#[test]
fn repl_exits_cleanly_on_stdin_eof() {
    let mut child = Command::new(OVSTORAGE_BIN)
        .args(["--no-config"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ovstorage REPL");

    {
        let stdin = child.stdin.as_mut().expect("stdin handle");
        let _ = stdin.flush();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait_with_output");
    assert!(
        output.status.success(),
        "REPL did not exit cleanly; status={:?}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}
