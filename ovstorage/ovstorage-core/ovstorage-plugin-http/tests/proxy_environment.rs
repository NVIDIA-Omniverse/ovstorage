// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-proxy characterization for the anonymous HTTP plugin. Parent tests
//! own the loopback proxy; one filtered child process owns each environment so
//! no `set_var` can race another Rust test's client construction.

use std::collections::HashMap;
use std::process::{Command, Output};

use ovstorage_plugin::{
    BackendFactory, ConfigValue, ConnectionRequest, LayerConfig, LayerConnectionRequest, Request,
    SecretBundle, StatOptions, StatRequest, address,
};
use ovstorage_plugin_http::HttpBackendLayerFactory;
use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

const CHILD_MODE: &str = "OVSTORAGE_HTTP_PROXY_TEST_CHILD";
/// Cleared in the child before it builds a client. `REQUEST_METHOD` is not a
/// proxy variable: hyper-util treats its mere presence as "running as a CGI
/// script" and then disables proxying entirely (the httpoxy mitigation), so an
/// ambient value would silently turn every assertion below into a no-proxy run.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];

fn child_command(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current integration test"));
    command
        .arg("proxy_environment_child")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode);
    for key in PROXY_ENV_KEYS {
        command.env_remove(key);
    }
    command
}

fn assert_child_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "proxy child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn proxy_environment_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    // The loopback mode points at a real loopback origin the parent owns, so
    // the child can prove the credentialed cleartext exemption never reaches
    // an ambient proxy.
    let loopback_root = std::env::var("OVSTORAGE_HTTP_PROXY_TEST_ORIGIN").ok();
    let scheme = if mode == "https" { "https" } else { "http" };
    let root = loopback_root
        .clone()
        .unwrap_or_else(|| format!("{scheme}://origin.invalid/"));
    let mut config = HashMap::new();
    config.insert("root_url".into(), ConfigValue::String(root.clone()));

    let mut credentials = SecretBundle::default();
    if loopback_root.is_some() {
        credentials.fields.insert(
            "bearer_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"tok".to_vec())),
        );
    }

    let layer = HttpBackendLayerFactory::default()
        .create_backend("http", &LayerConfig::new(), None)
        .await
        .unwrap();
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "http".into(),
                connection: ConnectionRequest {
                    backend_kind: "http".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .unwrap();

    let result = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse(&format!("{root}object")).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await;
    if mode == "https" {
        result.expect_err("the fixture closes after accepting CONNECT");
    } else {
        result.expect("the HTTP proxy supplies the origin response");
    }
}

/// A credentialed cleartext connection is only permitted because a loopback
/// destination never leaves the machine. reqwest honours `HTTP_PROXY` by
/// default, so without `no_proxy()` the request — `Authorization` and all —
/// would be sent in absolute form to a proxy that is not loopback.
#[test]
fn a_credentialed_loopback_connection_ignores_an_ambient_proxy() {
    let proxy = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let origin = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));

    let mut command = child_command("loopback");
    command.env("HTTP_PROXY", proxy.endpoint());
    command.env(
        "OVSTORAGE_HTTP_PROXY_TEST_ORIGIN",
        format!("{}/", origin.endpoint()),
    );
    let output = command.output().expect("run loopback proxy child");
    assert_child_succeeded(&output);

    assert_eq!(
        proxy.hits(),
        0,
        "the credential must not be disclosed to an ambient proxy: {:?}",
        proxy.requests()
    );
    // The probe at add plus the stat, both straight to the loopback origin.
    assert_eq!(origin.hits(), 2, "got {:?}", origin.requests());
    for request in origin.requests() {
        assert!(
            request_has_header(&request, "authorization", "Bearer tok"),
            "loopback origin request carried no credential: {request}"
        );
    }
}

#[test]
fn http_proxy_routes_plugin_requests_and_sends_basic_credentials() {
    let proxy = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let proxy_with_auth =
        proxy
            .endpoint()
            .replacen("http://", "http://proxy-user:proxy-secret@", 1);
    let mut command = child_command("http");
    command.env("HTTP_PROXY", proxy_with_auth);
    let output = command.output().expect("run HTTP proxy child");
    assert_child_succeeded(&output);

    assert_eq!(proxy.hits(), 1);
    let request = &proxy.requests()[0];
    assert!(
        request.starts_with("HEAD http://origin.invalid/object HTTP/1.1"),
        "forward proxy must receive an absolute-form URI: {request}"
    );
    assert!(request_has_header(
        request,
        "Proxy-Authorization",
        "Basic cHJveHktdXNlcjpwcm94eS1zZWNyZXQ="
    ));
}

#[test]
fn https_proxy_uses_connect_for_https_destinations() {
    let proxy = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
    let mut command = child_command("https");
    command.env("HTTPS_PROXY", proxy.endpoint());
    let output = command.output().expect("run HTTPS proxy child");
    assert_child_succeeded(&output);

    assert_eq!(proxy.hits(), 1);
    let request = &proxy.requests()[0];
    assert!(
        request.starts_with("CONNECT origin.invalid:443 HTTP/1.1"),
        "HTTPS proxy must receive a CONNECT tunnel request: {request}"
    );
}
