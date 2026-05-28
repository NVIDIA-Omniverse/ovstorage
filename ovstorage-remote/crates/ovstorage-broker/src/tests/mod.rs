// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use axum::body::Body as AxumBody;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ovstorage::{Body, ConfigValue, ReadOptions, StatOptions, WriteOptions};
use ovstorage_broker_protocol::PROTOCOL_V2;
use tower::ServiceExt;

// Broker tests dlopen four cdylibs, each statically linking its own
// rustls + `ring`. Production processes hold a single `Library` for
// process lifetime, so `ring`'s static initialization runs once and
// is consistent. Tests create+drop many `Library`s per process, which
// races the cross-cdylib `ring` state on cleanup; the symptom is an
// intermittent SIGSEGV in `tokio_rustls::common::Stream::handshake`
// inside `libovstorage_plugin_broker.so`'s plugin runtime
// worker. Forcing `--test-threads=1` for THIS test binary only
// (other -remote crates keep their parallelism) sidesteps the race
// without leaking the workaround into REST or broker unit
// tests where parallel coverage matters.
#[ctor::ctor]
fn pin_broker_tests_to_single_thread() {
    // SAFETY: ctor runs before main(), before libtest reads the env
    // var via `get_concurrency()`, and before any other thread
    // exists in the test binary.
    if std::env::var_os("RUST_TEST_THREADS").is_none() {
        unsafe {
            std::env::set_var("RUST_TEST_THREADS", "1");
        }
    }
}

use crate::test_utils::{
    BuilderTestExt, add_file_connection, add_test_connection, ensure_test_plugin_env,
    wait_until_test_counter_eq,
};

async fn build_default_broker_for_test() -> Broker {
    ensure_test_plugin_env();
    super::build_default_broker()
        .await
        .expect("build_default_broker")
}

async fn build_default_library_for_test() -> Arc<Library> {
    ensure_test_plugin_env();
    super::build_default_library()
        .await
        .expect("build_default_library")
}

mod attribution;
mod cache_redirect;
mod config;
mod core;
mod grpc;
mod grpc_streaming_seam;
mod helpers;
mod oauth_three_tier;
mod transport;
mod watch;

pub use helpers::*;
