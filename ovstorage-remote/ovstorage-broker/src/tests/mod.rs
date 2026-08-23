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
// rustls + `ring`. Production processes keep a single Stack and its loaded
// plugins for the process lifetime, so `ring`'s static initialization runs once
// and is consistent. Tests create and drop many Stacks per process, which
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
    BrokerClientStackOptions, BrokerStackFixture, broker_client_stack, broker_client_stack_with,
    empty_broker_stack, ensure_test_plugin_env, file_broker_stack,
};

async fn build_default_broker_for_test() -> Broker {
    ensure_test_plugin_env();
    super::build_default_broker()
        .await
        .expect("build_default_broker")
}

mod attribution;
mod bespoke_stack;
mod byte_cache_reuse;
mod cache_redirect;
mod config;
mod core;
mod grpc;
mod grpc_streaming_seam;
mod helpers;
mod memory_bounds;
mod oauth_three_tier;
mod plugin_auth;
mod principal_isolation;
mod redirect_disclosure;
mod transport;
mod watch;

pub use helpers::*;
