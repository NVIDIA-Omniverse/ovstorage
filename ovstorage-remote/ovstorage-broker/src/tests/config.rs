// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// A broker config that declares `[listener]`/`auth` but no
// `[ovstorage.layers]` must be refused (`require_configured_stack`, called both on
// the operator-config path in `main` and inside every build path), so the broker
// fails fast rather than serving an empty stack. Zero-config mode passes because
// it declares its own explicit forward graph — this guards against serving an
// empty stack.
#[test]
fn broker_config_empty_stack_refused_at_startup() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"
"#,
    )
    .unwrap();
    let error = ovstorage::host::require_configured_stack(&config.ovstorage)
        .expect_err("empty [ovstorage] must be refused");
    assert_eq!(error.code(), ErrorCode::NotConfigured);
    assert!(
        error.message().contains("empty stack"),
        "unexpected message: {}",
        error.message()
    );
}

// A config with `[[ovstorage.connections]]` but no `[ovstorage.layers]` is
// refused at build time: the build path rejects it exactly like the
// operator-file/REST guard — there is no silent default forward graph — so a
// connections-only config cannot bind a listener over an under-specified stack.
#[tokio::test]
async fn broker_config_connections_without_layers_refused_at_build() {
    ensure_test_plugin_env();
    let contents = r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "/tmp/ovstorage-refused"
"#;
    let err = build_broker_expecting_error(contents).await;
    assert_eq!(err.code(), ErrorCode::NotConfigured);
    assert!(
        err.message().contains("empty stack"),
        "unexpected message: {}",
        err.message()
    );
}

/// Drive `build_broker_from_config_str` expecting failure. `Broker` is not
/// `Debug`, so `Result::unwrap_err` can't be used directly.
async fn build_broker_expecting_error(contents: &str) -> Error {
    match build_broker_from_config_str(contents).await {
        Ok(_) => panic!("expected broker build to fail, but it succeeded"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn broker_config_registers_connections_through_library_api() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let root_string = root.to_string_lossy().replace('\\', "/");
    let config = format!(
        r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"
display_name = "configured file"

[ovstorage.connections.config]
root = "{}"
"#,
        root_string.replace('"', "\\\"")
    );

    let broker = build_broker_from_config_str(&config).await.unwrap();
    let roots = broker.list_address_roots(&default_context()).await.unwrap();

    assert_eq!(
        broker
            .list_connections(&default_context())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        roots
            .iter()
            .any(|address_root| address_root.address.as_str().starts_with("file:"))
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_config_without_listener_auth_fails_closed() {
    ensure_test_plugin_env();
    // No `auth` block ⇒ the build refuses (fail-closed), never a silent
    // allow-all.
    let contents = r#"
[listener]
bind = "127.0.0.1:0"
"#;
    let parsed = parse_broker_config(contents).unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&parsed)
            .unwrap_err()
            .code(),
        ErrorCode::NotConfigured
    );
    let err = build_broker_expecting_error(contents).await;
    assert_eq!(err.code(), ErrorCode::NotConfigured);
    assert!(
        err.message().contains("has no auth configured"),
        "unexpected message: {}",
        err.message()
    );
}

#[tokio::test]
async fn broker_config_anonymous_admits_unauthenticated_request() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let root_string = root.to_string_lossy().replace('\\', "/");
    let contents = format!(
        r#"
[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
        root_string.replace('"', "\\\"")
    );
    let broker = build_broker_from_config_str(&contents).await.unwrap();
    // Explicit anonymous allow-all: an unauthenticated caller is admitted.
    let roots = broker.list_address_roots(&default_context()).await.unwrap();
    assert!(
        roots
            .iter()
            .any(|address_root| address_root.address.as_str().starts_with("file:"))
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_config_gated_policy_denies_write_allows_read() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let root_string = root.to_string_lossy().replace('\\', "/");
    // A gated `builtin-auth` policy sourced entirely from `auth.config`: allow
    // read, deny write. Proves the config-sourced policy gates.
    let contents = format!(
        r#"
[listener]
bind = "127.0.0.1:0"

[listener.auth]
kind = "builtin-auth"

[listener.auth.config.policy]
plugin = "ovstorage-authz-toml"

[[listener.auth.config.policy.policy]]
id = "read-only"
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "*"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
        root_string.replace('"', "\\\"")
    );
    let broker = build_broker_from_config_str(&contents).await.unwrap();
    let context = default_context();
    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "note.txt").unwrap();

    let write_err = broker
        .write(
            &context,
            object.clone(),
            Body::Bytes(b"blocked".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(write_err.code(), ErrorCode::PermissionDenied);

    // A read op is allowed by the policy (the object is absent, so it surfaces
    // NotFound — not PermissionDenied, proving the gate admitted the read).
    let read_err = broker
        .read(&context, object, ReadOptions::default())
        .await
        .unwrap_err();
    assert_eq!(read_err.code(), ErrorCode::NotFound);

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_config_rejects_unknown_policy_plugin() {
    ensure_test_plugin_env();
    // The policy engine only supports the `ovstorage-authz-toml` rule set, so an
    // unknown `policy.plugin` name is `Unsupported` when parsed at build time.
    let contents = r#"
[listener]
bind = "127.0.0.1:0"

[listener.auth]
kind = "builtin-auth"

[listener.auth.config.policy]
plugin = "ovstorage-authz-this-does-not-exist"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#;
    let err = build_broker_expecting_error(contents).await;
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn broker_config_rejects_unknown_auth_kind() {
    ensure_test_plugin_env();
    let contents = r#"
[listener]
bind = "127.0.0.1:0"

[listener.auth]
kind = "entra"
"#;
    let err = build_broker_expecting_error(contents).await;
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("unknown auth kind 'entra'"),
        "message: {}",
        err.message()
    );
}

#[test]
fn broker_listener_plaintext_tcp_non_loopback_requires_trusted_proxy_constraints() {
    let public = parse_broker_config(
        r#"
[listener]
bind = "0.0.0.0:8787"
auth = "anonymous"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&public)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );

    let trusted_proxy = parse_broker_config(
        r#"
[listener]
bind = "0.0.0.0:8787"
trusted_proxy = true
trusted_peers = ["10.0.0.0/8"]
auth = "anonymous"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&trusted_proxy).unwrap();
}

#[test]
fn trusted_authn_modes_require_trusted_proxy_and_allowlist() {
    let missing_proxy = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_forwarded_headers"
"#,
    )
    .unwrap();
    let err = validate_broker_config_for_startup(&missing_proxy).unwrap_err();
    assert!(err.message().contains("trusted_proxy = true"));

    let configured = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"
trusted_proxy = true
trusted_peers = ["127.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_unsigned_jwt"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&configured).unwrap();
}

#[test]
fn mtls_authn_requires_tls_client_ca() {
    let without_ca = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"
[listener.tls]
cert_path = "/tmp/server.crt"
key_path = "/tmp/server.key"

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "mtls"
"#,
    )
    .unwrap();
    let err = validate_broker_config_for_startup(&without_ca).unwrap_err();
    assert!(err.message().contains("client_ca_path"));

    let with_ca = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"
[listener.tls]
cert_path = "/tmp/server.crt"
key_path = "/tmp/server.key"
client_ca_path = "/tmp/client-ca.crt"

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "mtls"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&with_ca).unwrap();
}

#[test]
fn zero_config_opts_the_listener_into_anonymous_auth() {
    let sandbox = unique_temp_dir();
    std::fs::create_dir_all(&sandbox).unwrap();
    #[cfg(unix)]
    let bind = sandbox
        .join("ovstorage-broker.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let bind = "pipe:ovstorage-broker-test".to_string();
    let config = build_zero_config_struct(bind, &sandbox);
    let listener = config.listener.as_ref().expect("zero-config has listener");
    let transport = listener.transport().unwrap();
    #[cfg(unix)]
    assert!(matches!(transport, BrokerTransport::UnixSocket(_)));
    #[cfg(windows)]
    assert!(matches!(transport, BrokerTransport::NamedPipe(_)));
    // Zero-config is the explicit unauthenticated allow-all opt-in.
    assert_eq!(
        listener.auth,
        Some(toml::Value::String("anonymous".into())),
        "zero-config must opt into anonymous auth"
    );
    validate_broker_config_for_startup(&config).unwrap();
    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn zero_config_rejects_transport_changing_listen_override() {
    // A zero-config broker serves anonymous allow-all on a local socket.
    // Retargeting it to TCP via `--listen` must be refused at startup:
    // otherwise the allow-all surface is exposed to the network.
    let err = check_listen_override(true, Some("/run/ovstorage-broker.sock"), "127.0.0.1:8787")
        .unwrap_err();
    assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("anonymous allow-all"),
        "message: {}",
        err.message()
    );
}

#[test]
fn zero_config_allows_local_listen_override() {
    // A local → local override (UDS path swap) keeps the anonymous surface local
    // and is allowed.
    check_listen_override(true, Some("/run/a.sock"), "/run/b.sock").unwrap();
}

#[test]
fn config_file_listen_override_to_tcp_is_allowed() {
    // With an explicit config file (not zero-config), the operator owns the auth
    // block; the override is re-validated by `validate_broker_config_for_startup`
    // rather than blanket-refused here.
    check_listen_override(false, Some("/run/a.sock"), "0.0.0.0:8787").unwrap();
}

#[test]
fn broker_config_builds_discovery_documents() {
    let config = parse_broker_config(
        r#"
[discovery]
name = "Acme Broker"

[[discovery.services]]
type = "ovstorage-broker"
endpoint = "grpc+tls://broker.acme.test:8443"

[[discovery.services]]
type = "ovstorage-rest"
endpoint = "https://rest.acme.test/v1"

[discovery.auth_config]
openid_configuration = "https://login.acme.test/.well-known/openid-configuration"

[discovery.auth_config.clients.default]
client_id = "ovstorage-cli"
scope = "openid email ovstorage:read ovstorage:write"
"#,
    )
    .unwrap();

    let services = config
        .discovery
        .services_document("http://127.0.0.1:8787")
        .unwrap();
    assert_eq!(services.name, "Acme Broker");
    assert_eq!(services.services.len(), 2);
    assert_eq!(services.services[0].service_type, "ovstorage-broker");

    let auth = config.discovery.auth_config_document().unwrap();
    assert_eq!(
        auth.clients
            .get("default")
            .map(|client| client.client_id.as_str()),
        Some("ovstorage-cli")
    );
}

#[test]
fn broker_discovery_defaults_to_local_broker_service() {
    let config = BrokerDiscoveryConfig::default();
    let document = config.services_document("http://127.0.0.1:8787").unwrap();
    assert_eq!(document.name, "ovstorage broker");
    assert_eq!(document.services.len(), 1);
    assert_eq!(document.services[0].service_type, "ovstorage-broker");
    assert_eq!(document.services[0].endpoint, "http://127.0.0.1:8787");
}

#[test]
fn broker_discovery_requires_broker_service() {
    let config = parse_broker_config(
        r#"
[[discovery.services]]
type = "ovstorage-rest"
endpoint = "https://rest.acme.test/v1"
"#,
    )
    .unwrap();
    assert_eq!(
        config
            .discovery
            .services_document("http://127.0.0.1:8787")
            .unwrap_err()
            .code(),
        ErrorCode::NotConfigured
    );
}

#[tokio::test]
async fn discovery_http_routes_serve_services_and_auth_config() {
    let config = parse_broker_config(
        r#"
[discovery]
name = "Test Broker"

[[discovery.services]]
type = "ovstorage-broker"
endpoint = "grpc+tls://broker.test:8443"

[discovery.auth_config]
openid_configuration = "https://login.test/.well-known/openid-configuration"

[discovery.auth_config.clients.default]
client_id = "ovstorage-cli"
"#,
    )
    .unwrap();
    let app = broker_discovery_app(BrokerDiscoveryState::new(
        config.discovery,
        "http://127.0.0.1:8787".into(),
    ));

    let services = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/services")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(services.status(), StatusCode::OK);
    let body = services.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "Test Broker");
    assert_eq!(json["services"][0]["type"], "ovstorage-broker");

    let auth = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth-config")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth.status(), StatusCode::OK);
    let body = auth.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["clients"]["default"]["client_id"], "ovstorage-cli");
}

const OAUTH_PROVIDER_TOML: &str = r#"
[oauth_providers.upstream-idp]
kind = "pkce"
backend_kind = "http"
client_id = "ovstorage-broker"
authorization_endpoint = "https://idp.example/authorize"
token_endpoint = "https://idp.example/token"
scope = "openid"
redirect_base = "http://127.0.0.1"
"#;

#[test]
fn validate_oauth_providers_pass_with_tcp_listener() {
    let raw = r#"
[listener]
bind = "127.0.0.1:0"
"#
    .to_string()
        + OAUTH_PROVIDER_TOML;
    let cfg = parse_broker_config(&raw).unwrap();
    validate_oauth_providers_against_listeners(&cfg).unwrap();
}

#[test]
fn validate_oauth_providers_rejects_unix_socket_listener() {
    let raw = r#"
[listener]
bind = "/tmp/ovstorage-broker.sock"
auth = "anonymous"

"#
    .to_string()
        + OAUTH_PROVIDER_TOML;
    let cfg = parse_broker_config(&raw).unwrap();
    let err = validate_oauth_providers_against_listeners(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("unix-socket") || err.message().contains("local-trust-scope"),
        "error must mention the local-trust-scope incompatibility, got: {}",
        err.message()
    );
}

#[test]
fn validate_oauth_providers_rejects_named_pipe_listener() {
    let raw = r#"
[listener]
bind = "pipe:ovstorage-broker"

"#
    .to_string()
        + OAUTH_PROVIDER_TOML;
    let cfg = parse_broker_config(&raw).unwrap();
    let err = validate_oauth_providers_against_listeners(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn validate_oauth_providers_passes_when_unix_listener_has_no_oauth_config() {
    let raw = r#"
[listener]
bind = "/tmp/ovstorage-broker.sock"

"#;
    let cfg = parse_broker_config(raw).unwrap();
    validate_oauth_providers_against_listeners(&cfg).unwrap();
}

#[test]
fn validate_oauth_providers_validator_runs_inside_startup_path() {
    // Misconfig must fire at startup, not at first OAuth request.
    let raw = r#"
[listener]
bind = "/tmp/ovstorage-broker.sock"
auth = "anonymous"

"#
    .to_string()
        + OAUTH_PROVIDER_TOML;
    let cfg = parse_broker_config(&raw).unwrap();
    let err = validate_broker_config_for_startup(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().contains("oauth_provider"));
}

#[test]
fn broker_oauth_routes_must_reference_known_provider() {
    let raw = r#"
[broker_oauth_routes]
"nucleus://prod/" = "ghost-provider"
"#;
    let cfg = parse_broker_config(raw).unwrap();
    let err = build_oauth_providers_from_config(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("ghost-provider"),
        "error must name the unknown provider, got: {}",
        err.message()
    );
}

/// An OAuth route key carrying a query or a fragment is refused at load.
///
/// A route key is a configuration address and is matched with
/// `is_ancestor_or_self`. The fragment used to vanish — `address::parse` strips
/// one, so the route silently covered a different scope than it spelled — and a
/// query pinned the route to one exact spelling. Both now fail loudly.
///
/// The refusal names the route by its byte length only, because the string is
/// operator-written and has not been parsed yet, so there is no structure to
/// redact. The `SECRET` assertion is what pins that.
///
/// The good input is asserted beside it: the same route without either
/// component loads and resolves to its provider.
///
/// Load-bearing line: the `refused_config_component` block in
/// `build_oauth_providers_from_config`.
#[test]
fn an_oauth_route_carrying_a_query_or_a_fragment_is_refused() {
    for (route, component) in [
        ("https://origin.invalid/team/#SECRET", "fragment"),
        ("https://origin.invalid/team/?v=SECRET", "query"),
    ] {
        let raw = format!(
            r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"{route}" = "upstream-idp"
"#
        );
        let cfg = parse_broker_config(&raw).unwrap();
        let err = build_oauth_providers_from_config(&cfg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{route}");
        assert!(
            err.message().contains(component),
            "{route}: the refusal must name what it refused: {}",
            err.message()
        );
        assert!(
            !err.message().contains("SECRET"),
            "{route}: the refusal echoed the route: {}",
            err.message()
        );
    }

    // The same route without either component loads.
    let raw = format!(
        r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"https://origin.invalid/team/" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    build_oauth_providers_from_config(&cfg).expect("the plain route loads");
}

/// The same refusal, for a route that carries a password — the easier of the
/// two refusals in that loop to reach, since it needs only a typo.
///
/// The password contains a comma on purpose. `Error`'s own redactor scrubs by
/// re-serializing a URL token it can tokenize, and its scan ends at
/// punctuation, so a comma-bearing password survives it verbatim and only the
/// `RedactedUrl(&url)` rendering removes it. Measured: with a plain password
/// this test passes against the raw interpolation and proves nothing.
#[test]
fn the_unknown_provider_refusal_does_not_echo_the_routes_credential() {
    let raw = r#"
[broker_oauth_routes]
"https://alice:hunt,er2@origin.invalid/team/" = "ghost-provider"
"#;
    let cfg = parse_broker_config(raw).unwrap();
    let err = build_oauth_providers_from_config(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("ghost-provider"),
        "the refusal must still name the provider, got: {}",
        err.message()
    );
    assert!(
        !err.message().contains("hunt,er2"),
        "the password must not survive into the startup error: {}",
        err.message()
    );
}

/// Two route keys that name one scope are refused at load.
///
/// The pair differs only in the trailing slash, which is not part of node
/// identity — so `node_key_owned` collapses them and one of the two providers
/// would be chosen by `HashMap` iteration order.
///
/// **A credential-bearing spelling against its credential-free twin cannot
/// reach this**, even though userinfo is dropped from the key too:
/// `an_oauth_route_carrying_credentials_is_refused` refuses either spelling
/// against the credential rule first, whichever the iteration reaches first.
/// The `RedactedUrl(&url)` rendering stays, because what a route key may carry
/// is decided by the guards ahead of this message and not by it.
///
/// Load-bearing line: the `RespelledScope` arm of `route_prefix_problem`.
/// Deleting it leaves the config loading with an order-dependent provider
/// choice — and reddens the programmatic ingress's
/// `a_programmatic_route_that_respells_a_bound_scope_is_not_bound_twice` in the
/// same run, which is the evidence that the two ingresses share one rule rather
/// than two copies that agree.
#[test]
fn two_spellings_of_one_scope_are_refused() {
    let raw = format!(
        r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"https://origin.invalid/team/" = "upstream-idp"
"https://origin.invalid/team" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    // The fixture must really hold two routes, or the refusal below could
    // never fire and the test would pass on an empty map.
    assert_eq!(cfg.broker_oauth_routes.len(), 2);
    let err = build_oauth_providers_from_config(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("names the same scope"),
        "the refusal must say what collided, got: {}",
        err.message()
    );
}

/// An OAuth route key carrying credentials is refused at load, and the refusal
/// does not publish them.
///
/// A route prefix SELECTS addresses, and `provider_for` selects with
/// `is_ancestor_or_self` — scheme, host, port and path, never the userinfo. So
/// a route written with a credential covers its path under every credential,
/// which is a silent widening of a live rule: on 0.2.0 the matcher compared
/// the whole serialization, so the credential had to be present to match. It
/// is the fourth adopter of the rule the authz `allow`, the alias `from` and a
/// `visible` visibility prefix already carry.
///
/// **A lone credential-bearing route is the case**, not a colliding pair: the
/// duplicate-scope refusal fires only when a second spelling of the same scope
/// is configured, so nothing else in this loop sees this one.
///
/// The password carries a comma on purpose — `Error`'s own redactor tokenizes
/// a URL and stops at punctuation, so a comma-bearing password survives it and
/// only the `RedactedUrl(&url)` rendering removes it.
///
/// The good input is asserted beside it, and asserted to ROUTE: the same
/// prefix without the credential loads and selects its own subtree.
#[test]
fn an_oauth_route_carrying_credentials_is_refused() {
    let raw = format!(
        r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"https://alice:hunt,er2@origin.invalid/team/" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    assert_eq!(cfg.broker_oauth_routes.len(), 1);
    let err = build_oauth_providers_from_config(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("must not carry credentials"),
        "the refusal must say what it refused, got: {}",
        err.message()
    );
    assert!(
        !err.message().contains("hunt,er2"),
        "the password must not survive into the startup error: {}",
        err.message()
    );

    let raw = format!(
        r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"https://origin.invalid/team/" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    let (_registry, bindings) =
        build_oauth_providers_from_config(&cfg).expect("the credential-free route loads");
    assert_eq!(
        bindings.provider_for(&url::Url::parse("https://origin.invalid/team/x").unwrap()),
        Some("upstream-idp"),
        "and it must still select its own subtree"
    );
}

/// A route key that does not parse is named by its length alone.
///
/// This is the only refusal in that loop with nothing but the raw string to
/// work with, and the shape that reaches it is the one `address::parse`'s own
/// documentation warns about: `s3:reader:hunter2@h/x` is authority-less, so
/// everything after the scheme is one opaque payload the redactor cannot
/// tokenize. `address::parse` goes to explicit trouble not to echo it, and
/// interpolating the raw prefix around its message would undo that at the call
/// site. Measured: reverting the format string to `prefix '{prefix}' is
/// invalid` turns this test red.
#[test]
fn the_unparseable_prefix_refusal_does_not_echo_the_route() {
    let raw = r#"
[broker_oauth_routes]
"s3:reader:hunter2@h/x" = "upstream-idp"
"#;
    let cfg = parse_broker_config(raw).unwrap();
    let err = build_oauth_providers_from_config(&cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        !err.message().contains("hunter2"),
        "the password must not survive into the startup error: {}",
        err.message()
    );
    // Still diagnosable: the operator has to be able to find the entry.
    assert!(
        err.message().contains("invalid prefix"),
        "the refusal must say what it refused: {}",
        err.message()
    );
}

#[test]
fn oauth_providers_config_round_trips() {
    let raw = format!(
        r#"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"https://assets.example/" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    assert_eq!(cfg.oauth_providers.len(), 1);
    let provider = cfg.oauth_providers.get("upstream-idp").unwrap();
    assert_eq!(provider.backend_kind, "http");
    assert_eq!(provider.client_id, "ovstorage-broker");
    assert_eq!(
        cfg.broker_oauth_routes
            .get("https://assets.example/")
            .unwrap(),
        "upstream-idp"
    );
    let (registry, bindings) = build_oauth_providers_from_config(&cfg).unwrap();
    assert!(registry.lookup("upstream-idp").is_some());
    assert!(!bindings.is_empty());
}

// The broker's --listen CLI override mutates
// config.listener after build_broker_from_config* validated the
// original. main.rs now re-runs validate_broker_config_for_startup
// after the override; this test mirrors that mutation and asserts the
// re-validation catches a UDS→public-plaintext promotion that would
// otherwise slip past startup.
#[test]
fn listen_override_revalidates_against_listener_invariants() {
    // UDS bind with auto-selected peer_cred — valid.
    let mut config = parse_broker_config(
        r#"
[listener]
bind = "/tmp/ovstorage-broker.sock"
auth = "anonymous"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&config).expect("UDS+peer_cred must validate");

    // Simulate `--listen 0.0.0.0:8787`: stamp the new bind exactly the
    // way main.rs does when the listener already exists. The new bind
    // is non-loopback plaintext TCP with no trusted_proxy — which the
    // shape rejects.
    config
        .listener
        .as_mut()
        .expect("listener present after parse")
        .bind = "0.0.0.0:8787".into();

    assert_eq!(
        validate_broker_config_for_startup(&config)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument,
    );
}

/// The follower's layer kind is spelled in `ovstorage::host` rather than
/// imported: the broker reaches every plugin through `dlopen`, so
/// `ovstorage-plugin-http` is a dev dependency at most and must not be linked
/// into production dispatch. Two spellings of one name is exactly the drift
/// that would make `stamp_redirect_disclosure` a silent no-op — it would find
/// no layer to stamp and, correctly for a graph with no follower, say nothing.
///
/// So the shipped graph is what pins the constant. If either side is renamed
/// alone, this fails.
#[test]
fn the_shipped_broker_graph_declares_a_layer_of_the_follower_kind() {
    use ovstorage::StackConfig;

    let shipped = include_str!("../../ovstorage-broker.toml");
    let config = StackConfig::from_toml_str(shipped).expect("shipped broker TOML parses");
    assert!(
        config.layers.iter().any(|(name, table)| {
            table.kind.as_deref().unwrap_or(name.as_str())
                == ovstorage::host::REDIRECT_FOLLOWER_LAYER_KIND
        }),
        "no layer in the shipped broker graph resolves to kind `{}`, so the operator's \
         `redirect_credential_disclosure` would reach no follower and the policy would \
         hold only at the broker's out-edge",
        ovstorage::host::REDIRECT_FOLLOWER_LAYER_KIND,
    );
}

/// The layer key is host-stamped, not operator-set. A graph that sets it by
/// hand is a startup error naming the top-level key, rather than two spellings
/// of one policy disagreeing where nobody can see it.
#[test]
fn a_graph_setting_the_follower_key_by_hand_is_refused() {
    use ovstorage::StackConfig;

    let config = StackConfig::from_toml_str(&format!(
        r#"
[ovstorage]
root = "redirect_follower"

[ovstorage.layers.redirect_follower]
kind = "redirect_follower"
inner = "router"
{} = true

[ovstorage.layers.router]
kind = "router"
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#,
        ovstorage::host::DISCLOSE_REDIRECT_CREDENTIALS_KEY
    ))
    .expect("the fixture graph parses");
    // The fixture must actually carry the key, or this asserts nothing.
    assert!(
        config.layers["redirect_follower"]
            .config
            .contains_key(ovstorage::host::DISCLOSE_REDIRECT_CREDENTIALS_KEY),
        "the fixture graph does not carry the layer key it is meant to be refused for"
    );

    let error = ovstorage::host::stamp_redirect_disclosure(config, false)
        .expect_err("a hand-set layer key must be refused, not silently overridden");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        error.to_string().contains("redirect_credential_disclosure"),
        "the refusal must name the key the operator should set instead, got: {error}"
    );
}

// The shipped default `ovstorage-broker.toml` declares the full
// broker graph as `[ovstorage]` config; it must parse through
// `StackConfig::from_toml_str` and `build_stack` to a real (non-`EmptyLayer`)
// Stack rooted at `alias`. The shipped file ships example absolute paths;
// point them at a tempdir so the byte cache opens and the `file` connection
// roots at a real directory — otherwise the graph is exactly as shipped.
#[tokio::test]
async fn shipped_default_config_ovstorage_builds_to_nonempty_stack() {
    use std::sync::Arc;

    use ovstorage::{LoadedLayerFactory, StackConfig};

    let shipped = include_str!("../../ovstorage-broker.toml");
    let base = unique_temp_dir();
    let data = base.join("data");
    let cache = base.join("cache");
    let state = base.join("state");
    for dir in [&data, &cache, &state] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let substituted = shipped
        .replace("/srv/ovstorage/data", &data.to_string_lossy())
        .replace(
            "/var/cache/ovstorage-broker/blobs",
            &cache.to_string_lossy(),
        )
        .replace(
            "/var/lib/ovstorage-broker/cache-state",
            &state.to_string_lossy(),
        );

    let config = StackConfig::from_toml_str(&substituted).unwrap();
    assert_eq!(config.root.as_deref(), Some("upstream_credential"));
    assert_eq!(
        config.layers["upstream_credential"].inner.as_deref(),
        Some("alias"),
        "the shipped broker-owned boundary wraps the alias-rooted operator graph"
    );
    // Attribution is a router branch, not the root: the shipped `file` branch
    // carries it, so the router's child is the wrapper and not the backend.
    assert_eq!(
        config.layers["router"].children,
        vec!["attribution_file".to_string()]
    );
    assert_eq!(
        config.layers["attribution_file"].inner.as_deref(),
        Some("file")
    );

    // `file` is the only generic built-in. Register the broker's private
    // wrappers (attribution + upstream_credential) and the rlib forms of every
    // public plugin layer named by the shipped graph.
    let factories: Vec<LoadedLayerFactory> = vec![
        LoadedLayerFactory::Wrapper(Arc::new(ovstorage_authz::AttributionWrapperFactory::new(
            ovstorage_authz::AttributionStrategy::UserMetadata,
        ))),
        LoadedLayerFactory::Router(Arc::new(ovstorage_plugin_core::RouterFactoryImpl)),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_core::AliasWrapperFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_core::CopyRenameFallbackWrapperFactory,
        )),
        LoadedLayerFactory::Wrapper(Arc::new(ovstorage_plugin_core::RetryWrapperFactory)),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_http::RedirectFollowerWrapperFactory,
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_cache::ByteCacheWrapperFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_plugin_cache::MetadataCacheWrapperFactory::default(),
        )),
        LoadedLayerFactory::Wrapper(Arc::new(UpstreamCredentialWrapperFactory::new(
            Arc::new(OAuthProviderRegistry::new()),
            BrokerOAuthRouteBindings::new(),
        ))),
    ];
    // The shipped graph must be a FIXED POINT of the branch-attribution
    // guarantee, which runs over every graph the host builds. If it changed this
    // one, the documented graph would not be the graph that runs, and the operator
    // guide's per-branch table would describe something the host quietly alters.
    let after = ovstorage_authz::ensure_branch_attribution(
        config.clone(),
        &ovstorage_authz::layer_types(&factories),
        &ovstorage_authz::UserMetadataKinds::from_factories(&factories),
    )
    .expect("the shipped graph is accepted");
    assert_eq!(config.root, after.root);
    assert_eq!(config.layers, after.layers);
    assert_eq!(config.connections, after.connections);

    let stack = ovstorage::host::build_stack(&config, factories)
        .await
        .expect("shipped ovstorage-broker.toml must build_stack");

    // A real graph, not the `EmptyLayer` fallback (which roots at `empty`).
    assert_eq!(stack.spec().root, "upstream_credential");
    assert!(
        stack.spec().layers.len() > 1,
        "expected the full broker graph, got {} layer(s)",
        stack.spec().layers.len()
    );

    std::fs::remove_dir_all(&base).ok();
}

// `attribution_strategy` is a TOP-LEVEL `BrokerConfig`
// field; the shipped template must place it above the first table header so it
// is not silently parsed as an ignored `listener.attribution_strategy`. Parse
// the whole shipped file through the real broker parser and assert a non-default
// value lands where the code reads it.
#[test]
fn shipped_broker_config_attribution_strategy_is_top_level() {
    let shipped = include_str!("../../ovstorage-broker.toml");
    let config = crate::parse_broker_config(shipped).expect("shipped config parses");
    assert_eq!(
        config.attribution_strategy,
        AttributionStrategyConfig::UserMetadata
    );

    let overridden = shipped.replace(
        "attribution_strategy = \"user_metadata\"",
        "attribution_strategy = \"passthrough\"",
    );
    let config = crate::parse_broker_config(&overridden).expect("overridden config parses");
    assert_eq!(
        config.attribution_strategy,
        AttributionStrategyConfig::Passthrough,
        "top-level attribution_strategy must reach BrokerConfig (A22 misplacement guard)"
    );
}

/// The operator-facing wire for `redirect_credential_disclosure`, end to end:
/// shipped TOML -> `BrokerConfig` -> `.discloses()`.
///
/// This whole chain was unverified. Every behavioural test injects the boolean
/// programmatically through the fixture, so nothing exercised the only path an
/// operator actually uses — and the operator surface is the entire point of the
/// key, since whether disclosure is permitted is a deployment property only
/// they can state.
///
/// The failure it guards is invisible in the shipped file, because the shipped
/// value is the default: an operator who writes `allow` below the first table
/// header, or a rename that desynchronizes the key from the serde field, leaves
/// the value at `Refuse` while their config says otherwise. Nothing errors and
/// their large brokered writes keep failing. Same hazard, and the same
/// substitute-and-reparse shape, as the sibling top-level key above.
#[test]
fn shipped_broker_config_redirect_disclosure_is_top_level_and_parses() {
    let shipped = include_str!("../../ovstorage-broker.toml");
    let config = crate::parse_broker_config(shipped).expect("shipped config parses");
    assert_eq!(
        config.redirect_credential_disclosure,
        RedirectDisclosureConfig::Refuse,
        "the shipped default must be `refuse`"
    );
    assert!(!config.redirect_credential_disclosure.discloses());

    let overridden = shipped.replace(
        "redirect_credential_disclosure = \"refuse\"",
        "redirect_credential_disclosure = \"allow\"",
    );
    assert_ne!(
        overridden, shipped,
        "the shipped file must carry the key for this substitution to mean anything"
    );
    let config = crate::parse_broker_config(&overridden).expect("overridden config parses");
    assert_eq!(
        config.redirect_credential_disclosure,
        RedirectDisclosureConfig::Allow,
        "a top-level redirect_credential_disclosure must reach BrokerConfig"
    );
    assert!(config.redirect_credential_disclosure.discloses());
}

/// A value the enum does not name is a startup error, not a silent fallback to
/// the default. `refuse` is the safe direction, so a typo silently landing
/// there would be quiet in the dangerous sense: the operator believes they
/// configured something and no one ever tells them otherwise.
#[test]
fn an_unknown_redirect_disclosure_value_is_a_startup_error() {
    let shipped = include_str!("../../ovstorage-broker.toml");
    let bad = shipped.replace(
        "redirect_credential_disclosure = \"refuse\"",
        "redirect_credential_disclosure = \"permit\"",
    );
    assert_ne!(bad, shipped, "the substitution must have applied");
    let error = crate::parse_broker_config(&bad)
        .expect_err("an unrecognised disclosure value must refuse to start");
    assert!(
        error.to_string().contains("redirect_credential_disclosure"),
        "the error must name the key the operator got wrong, got: {error}"
    );
}

// The trust-boundary attribution wrapper is a declared layer, not a
// composer-prepended one. A broker graph that omits it (an operator pasting the
// CLI's cache-only default, say) must still get one, matching how the
// per-listener auth layer is host-attached, so attribution is never silently
// dropped. Exercise the guarantee the broker actually calls — the same
// `ensure_branch_attribution` that `prepare_listener_inner_stack` applies — not
// the generic root helper, which no longer decides this.
#[test]
fn broker_stack_without_attribution_layer_gets_one_per_capable_branch() {
    let toml = r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["file", "http"]

[ovstorage.layers.file]
kind = "file"

[ovstorage.layers.http]
kind = "http"
"#;
    let config = ovstorage::StackConfig::from_toml_str(toml).unwrap();
    assert!(
        !config
            .layers
            .values()
            .any(|t| t.kind.as_deref() == Some("attribution")),
        "fixture must start without an attribution layer"
    );

    use std::sync::Arc;

    use ovstorage::LoadedLayerFactory;

    // Real factories, not an empty map. With an empty one every kind but core's
    // built-in `file` classifies as "not a backend", `placement` short-circuits
    // before it ever reads a kind's user-metadata declaration, and this test
    // passes whatever those declarations say — asserting a reason that is not
    // the one operating.
    let factories = vec![LoadedLayerFactory::Backend(Arc::new(
        ovstorage_plugin_http::HttpBackendLayerFactory::default(),
    ))];
    let ensured = ovstorage_authz::ensure_branch_attribution(
        config,
        &ovstorage_authz::layer_types(&factories),
        &ovstorage_authz::UserMetadataKinds::from_factories(&factories),
    )
    .expect("a graph declaring no attribution layer is accepted");
    assert_eq!(
        ensured.root.as_deref(),
        Some("router"),
        "the guarantee does not move the operator's root"
    );
    let mut children = ensured.layers["router"].children.clone();
    children.sort();
    assert_eq!(
        children,
        vec!["attribution_file".to_string(), "http".to_string()],
        "the file branch gains a wrapper; the http branch, which cannot carry \
         user metadata, must not"
    );
    assert_eq!(
        ensured.layers["attribution_file"].inner.as_deref(),
        Some("file")
    );

    // Idempotent: a graph already covered over its backend is unchanged.
    let already = ovstorage::StackConfig::from_toml_str(
        r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["attribution_file"]

[ovstorage.layers.attribution_file]
kind = "attribution"
inner = "file"

[ovstorage.layers.file]
kind = "file"
"#,
    )
    .unwrap();
    let count = |c: &ovstorage::StackConfig| c.layers.len();
    let before = count(&already);
    let ensured = ovstorage_authz::ensure_branch_attribution(
        already,
        &ovstorage_authz::layer_types(&factories),
        &ovstorage_authz::UserMetadataKinds::from_factories(&factories),
    )
    .expect("a graph already covered over its backend is accepted");
    assert_eq!(count(&ensured), before, "no extra layer injected");
    assert_eq!(
        ensured.layers["router"].children,
        vec!["attribution_file".to_string()]
    );
}

// The shipped `ovstorage-broker.toml`
// graph and the programmatic `broker_stack_config` twin must declare the same
// layer wiring. The twin is what the zero-config path and test fixtures compose
// from, so a shipped-TOML edit that is not mirrored in the twin (or vice versa)
// would silently ship a graph that behaves differently from the code path.
// Compares `root` and, per layer, its resolved kind / `inner` / `children`;
// ignores connection details and per-layer config (cache roots, caps) that
// legitimately differ (the twin injects caches as factories).
#[test]
fn shipped_toml_and_twin_have_identical_graph_wiring() {
    use std::collections::BTreeMap;

    use ovstorage::StackConfig;

    #[allow(clippy::type_complexity)]
    fn wiring(
        config: &StackConfig,
    ) -> (
        Option<String>,
        BTreeMap<String, String>,
        BTreeMap<String, Option<String>>,
        BTreeMap<String, Vec<String>>,
    ) {
        let kinds = config
            .layers
            .iter()
            .map(|(name, table)| {
                (
                    name.clone(),
                    table.kind.clone().unwrap_or_else(|| name.clone()),
                )
            })
            .collect();
        let inners = config
            .layers
            .iter()
            .map(|(name, table)| (name.clone(), table.inner.clone()))
            .collect();
        let children = config
            .layers
            .iter()
            .map(|(name, table)| {
                let mut c = table.children.clone();
                c.sort();
                (name.clone(), c)
            })
            .collect();
        (config.root.clone(), kinds, inners, children)
    }

    let shipped = include_str!("../../ovstorage-broker.toml");
    let parsed = StackConfig::from_toml_str(shipped).expect("shipped broker TOML parses");

    // The shipped broker.toml declares both caches and a 1 MiB follow/cache cap,
    // so the twin must be built with the matching graph options.
    let twin = crate::stack::broker_stack_config(
        parsed.connections.clone(),
        crate::stack::BrokerGraphOptions {
            byte_cache: true,
            metadata_cache: true,
            follow_cap: Some(1_048_576),
        },
        &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
    );

    assert_eq!(
        wiring(&parsed),
        wiring(&twin),
        "shipped ovstorage-broker.toml graph wiring diverged from broker_stack_config; \
         update both in lockstep"
    );
}

// The auth layer names a listener in its diagnostics (a permissive
// `trusted_unsigned_jwt` posture warns at build time) using an identity the host
// injects. Assert the broker actually injects it, and that it carries the
// operator's `bind` rather than a placeholder — an unattributable warning is the
// failure this guards against.
#[test]
fn listener_auth_config_carries_the_listener_bind_as_its_identity() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "0.0.0.0:8787"
trusted_proxy = true
trusted_peers = ["10.0.0.0/8"]

[listener.auth]
kind = "builtin-auth"
[listener.auth.config]
authn_mode = "trusted_unsigned_jwt"
"#,
    )
    .unwrap();
    let auth_config = crate::broker_listener_auth_preflight(config.listener.as_ref())
        .unwrap()
        .into_builtin_config()
        .unwrap();
    assert_eq!(
        auth_config.get("__host_listener_id"),
        Some(&ovstorage::ConfigValue::String("0.0.0.0:8787".to_string())),
    );
}

// `attributed_router_layers` resolves generated wrapper names against
// `HOST_GRAPH_LAYER_NAMES` so a connection kind cannot collide with a layer the
// host emits above the router. That list is hand-maintained in another crate, so
// a host adding a layer and not updating it would reintroduce the collision
// silently. Assert the coverage instead of trusting it: every layer the twin
// emits is either a connected backend kind, the router, or a reserved name.
#[test]
fn every_layer_the_broker_twin_emits_is_a_backend_kind_or_a_reserved_name() {
    let connections: Vec<ConnectionConfig> = ["file", "s3"]
        .into_iter()
        .map(|kind| {
            ConnectionConfig::from_request(ovstorage::ConnectionRequest {
                backend_kind: kind.into(),
                config: std::collections::HashMap::new(),
                credentials: ovstorage::SecretBundle::default(),
                persist: false,
                display_name: None,
            })
        })
        .collect();
    let twin = crate::stack::broker_stack_config(
        connections,
        crate::stack::BrokerGraphOptions {
            byte_cache: true,
            metadata_cache: true,
            follow_cap: Some(1_048_576),
        },
        &ovstorage_authz::UserMetadataKinds::from_factories(&[]).with("s3", true),
    );

    for name in twin.layers.keys() {
        let is_backend_kind = ["file", "s3"].contains(&name.as_str());
        let is_generated_wrapper = name.starts_with("attribution_");
        assert!(
            is_backend_kind
                || is_generated_wrapper
                || name == "router"
                || ovstorage_authz::is_reserved_host_layer_name(name),
            "the broker emits a layer named '{name}' that \
             `HOST_GRAPH_LAYER_NAMES` does not reserve; a connection whose \
             backend kind is '{name}' would collide with it"
        );
    }
}

// A zero-config broker must actually BUILD, not merely produce a valid config
// struct. Every other zero-config test stops at `build_zero_config_struct`,
// which never constructs the Stack — so the alias rules the host generates are
// never validated by any test in this suite, and the suite stayed green while
// the binary would not start.
//
// The refusal it catches is a duplicate alias `from`: the host emitted both
// `broker:/` and `broker:///`, which name one node once address identity stops
// reading the trailing-authority spelling, and `build_broker_from_config_with_aliases`
// builds the Stack eagerly, so the rejection is a startup failure rather than a
// deferred one.
#[tokio::test]
async fn zero_config_broker_builds_with_its_host_generated_aliases() {
    let sandbox = unique_temp_dir();
    std::fs::create_dir_all(&sandbox).unwrap();
    #[cfg(unix)]
    let bind = sandbox
        .join("ovstorage-broker.sock")
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let bind = "pipe:ovstorage-broker-test".to_string();
    let config = build_zero_config_struct(bind, &sandbox);
    let built = build_zero_config_broker(&config, &sandbox).await;
    let _ = std::fs::remove_dir_all(&sandbox);
    assert!(
        built.is_ok(),
        "zero-config broker must start with no configuration at all; got {:?}",
        built.err()
    );
}

/// One alias rule, and it serves both spellings a caller may write.
///
/// The build test above says the broker starts; this says the single rule that
/// replaced two still reaches everything the two reached. `broker:/x` and
/// `broker:///x` are distinct strings the parser preserves, so a reader cannot
/// assume one rule covers both — it does because `node_key` reads an absent
/// authority and an empty one alike, which is exactly the identity change that
/// made the two rules a duplicate in the first place.
#[test]
fn the_zero_config_alias_covers_both_spellings_of_the_broker_root() {
    let sandbox = unique_temp_dir();
    let aliases = zero_config_aliases(&sandbox).unwrap();
    assert_eq!(
        aliases.len(),
        1,
        "two rules for one node is a startup failure"
    );
    let (from, to) = &aliases[0];
    assert_eq!(from.as_str(), "broker:///");

    for (request, expected_suffix) in [
        ("broker:///x", "x"),
        ("broker:/x", "x"),
        ("broker:///a/b", "a/b"),
        ("broker:/a/b", "a/b"),
        ("broker:///", ""),
        ("broker:/", ""),
    ] {
        let addr = ovstorage_plugin::address::parse(request).unwrap();
        assert!(
            ovstorage_plugin::address::is_ancestor_or_self(from, &addr),
            "{request} must route through {from}"
        );
        assert_eq!(
            ovstorage_plugin::address::relative_suffix(&addr, from),
            Some(expected_suffix),
            "{request}"
        );
        let projected = ovstorage_plugin::address::replace_prefix(&addr, from, to).unwrap();
        assert!(
            projected.as_str().starts_with(to.as_str()),
            "{request} projects to {projected}, outside the sandbox {to}"
        );
    }
}

#[test]
fn plugin_listener_auth_preflight_is_explicitly_deferred() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"

[listener.auth]
kind = "corp-auth"
"#,
    )
    .unwrap();
    assert!(matches!(
        crate::broker_listener_auth_preflight(config.listener.as_ref()).unwrap(),
        crate::BrokerListenerAuthPreflight::NeedsPluginFactories
    ));
}

#[test]
fn plugin_listener_auth_rejects_invalid_trusted_peer_cidr_during_startup_validation() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:8787"
trusted_proxy = true
trusted_peers = ["not-a-cidr"]

[listener.auth]
kind = "corp-auth"
"#,
    )
    .unwrap();
    let error = validate_broker_config_for_startup(&config).unwrap_err();
    assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
    assert!(error.message().contains("not-a-cidr"));
}

// `[auth] state_root` is the operator's control over where credentials land.
// It sits ahead of `OVSTORAGE_AUTH_DIR` so a broker running as its own service
// user is not silently redirected by an inherited environment variable.
#[test]
fn auth_state_root_is_read_from_config() {
    let config = parse_broker_config(
        r#"
[auth]
state_root = "/srv/ovstorage/auth"

[ovstorage.layers.file]
kind = "file"
"#,
    )
    .expect("config with an auth state_root must parse");
    assert_eq!(
        config.auth.state_root.as_deref(),
        Some(std::path::Path::new("/srv/ovstorage/auth"))
    );
}

// Absent the key the broker resolves the shared per-user default, which is
// what makes a broker and a CLI running as one OS user share a credential.
#[test]
fn auth_state_root_is_absent_by_default() {
    let config = parse_broker_config(
        r#"
[ovstorage.layers.file]
kind = "file"
"#,
    )
    .expect("config without an auth block must parse");
    assert_eq!(config.auth.state_root, None);
}

// The block rejects unknown keys rather than ignoring them. A misspelled
// `state_roots` that parsed silently would leave the operator believing two
// deployments were isolated while both used the shared default.
#[test]
fn a_misspelled_auth_key_is_refused_rather_than_ignored() {
    let error = parse_broker_config(
        r#"
[auth]
state_roots = "/srv/ovstorage/auth"

[ovstorage.layers.file]
kind = "file"
"#,
    )
    .expect_err("a misspelled auth key must be refused");
    assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
}

// A relative auth root is resolved against the service's working directory,
// so it both moves with wherever the service is started and, on the way,
// narrows that directory to 0700 and creates `auth.sqlite` inside it.
#[test]
fn a_relative_auth_state_root_is_refused_at_startup() {
    for spelling in [".", "relative/auth", ""] {
        let error = validate_auth_state_root(Some(std::path::Path::new(spelling)))
            .expect_err("a relative auth.state_root must be refused");
        assert_eq!(
            error.code(),
            ovstorage::ErrorCode::InvalidArgument,
            "{spelling:?}"
        );
    }
}

#[test]
fn an_absolute_auth_state_root_is_accepted() {
    #[cfg(unix)]
    let root = std::path::Path::new("/srv/ovstorage/auth");
    #[cfg(windows)]
    let root = std::path::Path::new(r"C:\ProgramData\ovstorage\auth");
    validate_auth_state_root(Some(root)).expect("an absolute auth.state_root must be accepted");
}

#[test]
fn an_absent_auth_state_root_is_accepted() {
    validate_auth_state_root(None).expect("omitting the key resolves the shared default");
}
