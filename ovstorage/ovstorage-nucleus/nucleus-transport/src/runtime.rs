// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plugin-wide tokio runtime owned by `nucleus-transport`.
//!
//! `SowsTransport` and `ConnLibTransport` spawn long-lived `send_loop` /
//! `read_loop` / `stop_loop` tasks for every active connection. Spawning
//! those via plain `tokio::spawn` puts them on whatever runtime the caller
//! happens to be on — and if that caller's runtime drops (e.g. an auth-pump
//! runtime that completes once the handshake is done), tokio cancels every
//! task on it, killing the live socket.
//!
//! Anchor those tasks here instead. The runtime is built once on first use
//! and lives for the process lifetime; one worker thread (`ovs-nuc-io`)
//! drives every connection's I/O. Callers spawn via `io_runtime().spawn(...)`.

use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static IO_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Get a handle on the shared Nucleus I/O runtime, building it on first call.
/// The runtime is a single-worker multi-threaded executor — multi-thread (not
/// current-thread) so tasks make progress regardless of which thread called
/// `spawn`, single-worker because every task here is I/O-bound (websocket
/// read/write loops) and a second worker would just sit idle.
pub fn io_runtime() -> &'static Runtime {
    IO_RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("ovs-nuc-io")
            .build()
            .expect("failed to build nucleus IO runtime")
    })
}
