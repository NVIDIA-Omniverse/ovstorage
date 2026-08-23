// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A credentialed `[[ovstorage.connections]]` entry must never be able to stop
//! a host from starting.
//!
//! `instantiate` probes the origin when a credential is present, and a
//! declared connection is materialized during stack construction — `host.rs`
//! hands each one to `StackBuilder::connection` and propagates an
//! `add_connection` error out of `build_with_cancel`. So a probe that refused
//! the add would let one expired token ground a whole host, taking every
//! unrelated backend with it. The probe records what it learned instead.

use ovstorage::{
    ConnectionAuthState, ErrorCode, LoadedLayerFactory, StackConfig, StatOptions, ext::LayerExt,
};
use ovstorage_plugin::address;
use ovstorage_plugin_http::HttpBackendLayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

fn config_with_declared_connection(root_url: &str) -> StackConfig {
    let toml = format!(
        r#"
[ovstorage]
root = "http"

[ovstorage.layers.http]

[[ovstorage.connections]]
backend_kind = "http"

[ovstorage.connections.config]
root_url = "{root_url}"

[ovstorage.connections.credentials]
bearer_token = "expired-token"
"#
    );
    StackConfig::from_toml_str(&toml).expect("stack config parses")
}

#[tokio::test]
async fn a_refused_credential_in_config_still_starts_the_host() {
    let _ = ovstorage::init_auth_substrate(None);
    let origin = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
    let root_url = format!("{}/", origin.endpoint());

    let stack = ovstorage::host::build_stack_with_cancel(
        &config_with_declared_connection(&root_url),
        vec![LoadedLayerFactory::Backend(std::sync::Arc::new(
            HttpBackendLayerFactory::default(),
        ))],
        None,
    )
    .await
    .expect("a refused credential must not stop the host from starting");

    // The connection is registered, and says plainly that it was refused.
    let (snapshot, _updates) = ovstorage::Layer::list_connections(
        stack.as_ref(),
        &ovstorage_plugin::Extensions::new(),
        None,
    )
    .await
    .expect("list connections");
    let connection = snapshot
        .connections
        .iter()
        .find(|c| c.backend_kind == "http")
        .expect("the declared connection is registered");
    match &connection.auth_state {
        ConnectionAuthState::AuthFailed { error, attempts } => {
            assert_eq!(error.code(), ErrorCode::AuthRequired);
            assert_eq!(*attempts, 1);
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }

    // Reads still fail the way they did before the probe existed.
    let err = stack
        .stat(
            address::parse(&format!("{root_url}object.bin")).unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("the origin still refuses the credential");
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

/// A duplicate caller-facing prefix does **not** stop the host from starting.
///
/// Two declared connections whose prefixes are equal cannot both serve that
/// address — there is no rule for which credential a read should use, and the
/// route table answers with whichever claimed it first. That is true however
/// the host reacts, so refusing to build buys the shadowed connection nothing
/// while costing every unrelated backend in the graph: one duplicated
/// `[[connections]]` entry would ground the whole host, and a host that
/// auto-restarts turns that into a restart loop. It is the same failure this
/// backend already refuses to cause for a refused credential, reached through
/// a different door.
///
/// Stripping userinfo from the default prefix makes *more* pairs equal — two
/// connections to one origin that previously differed only in their userinfo
/// now collapse onto one prefix — so this is exactly the case that must
/// degrade rather than abort. The collision is reported on the tracing
/// channel and the shadowed connection is skipped; the runtime
/// `add_connection` path keeps its hard `RouteConflict`, where a caller is
/// present to read it and can free the prefix through `Layer::remove_connection`.
#[tokio::test]
async fn a_duplicate_declared_prefix_is_skipped_rather_than_grounding_the_host() {
    let _ = ovstorage::init_auth_substrate(None);
    let toml = r#"
[ovstorage]
root = "http"

[ovstorage.layers.http]

[[ovstorage.connections]]
backend_kind = "http"
display_name = "first"

[ovstorage.connections.config]
root_url = "https://cdn.example.invalid/assets/"

[[ovstorage.connections]]
backend_kind = "http"
display_name = "second"

[ovstorage.connections.config]
root_url = "https://bob:hunter2@cdn.example.invalid/assets/"
"#;
    // `.invalid` is guaranteed not to resolve (RFC 2606), so the credentialed
    // second connection's probe fails at DNS and no credential leaves the
    // machine. It still reaches `install`, which is what this pins.
    let config = StackConfig::from_toml_str(toml).expect("stack config parses");

    let stack = ovstorage::host::build_stack_with_cancel(
        &config,
        vec![LoadedLayerFactory::Backend(std::sync::Arc::new(
            HttpBackendLayerFactory::default(),
        ))],
        None,
    )
    .await
    .expect("a duplicate declared prefix must not stop the host from starting");

    // The first declaration owns the prefix; the second is skipped, not
    // registered alongside it as an unroutable duplicate.
    let (snapshot, _updates) = ovstorage::Layer::list_connections(
        stack.as_ref(),
        &ovstorage_plugin::Extensions::new(),
        None,
    )
    .await
    .expect("list connections");
    let http: Vec<_> = snapshot
        .connections
        .iter()
        .filter(|c| c.backend_kind == "http")
        .collect();
    assert_eq!(
        http.len(),
        1,
        "the shadowed connection must be skipped, not registered alongside \
         the one that owns the prefix: {http:?}"
    );
    // Named distinctly so this can say *which* survived. Asserting only the
    // count would pass just as well if `install` replaced the incumbent with
    // the newcomer, which is the opposite rule from the documented one.
    assert_eq!(
        http[0].display_name, "first",
        "the first declaration owns the prefix; the later one is the one skipped"
    );
}

/// The other half of the rule, without which the arm above could be widened
/// to swallow everything and every test here would still pass.
///
/// A connection error that is *not* a route conflict still stops the build —
/// a malformed `root_url` is the deterministic config error the fail-fast
/// precedent is built on, and nothing about it becomes serviceable by
/// starting anyway.
#[tokio::test]
async fn a_declared_connection_that_is_not_a_route_conflict_still_stops_the_build() {
    let _ = ovstorage::init_auth_substrate(None);
    let toml = r#"
[ovstorage]
root = "http"

[ovstorage.layers.http]

[[ovstorage.connections]]
backend_kind = "http"

[ovstorage.connections.config]
root_url = "not-a-url"
"#;
    let config = StackConfig::from_toml_str(toml).expect("stack config parses");
    let err = match ovstorage::host::build_stack_with_cancel(
        &config,
        vec![LoadedLayerFactory::Backend(std::sync::Arc::new(
            HttpBackendLayerFactory::default(),
        ))],
        None,
    )
    .await
    {
        Ok(_) => panic!("a malformed root_url must still stop the build"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}
