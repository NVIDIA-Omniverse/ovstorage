// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn broker_config_registers_connections_through_library_api() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let root_string = root.to_string_lossy().replace('\\', "/");
    let config = format!(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[[authz.policy]]
id = "allow-test"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"

[[connections]]
backend_kind = "file"
display_name = "configured file"

[connections.config]
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
async fn broker_config_route_policy_drives_cache_threshold_redirects() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let root_string = root.to_string_lossy().replace('\\', "/");
    let prefix = address_for_path(&root);
    let redirect_target = root.join("redirect-read.txt");
    std::fs::write(&redirect_target, b"redirect").unwrap();
    let config = format!(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[[authz.policy]]
id = "allow-test"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"

[[connections]]
backend_kind = "file"
display_name = "configured file"

[connections.config]
root = "{}"

[[routes]]
prefix = "{}"

[routes.cache]
max_object_bytes = 4

[routes.redirect]
read_endpoint = "{}"
ttl_seconds = 30
"#,
        root_string.replace('"', "\\\""),
        prefix.as_str().replace('"', "\\\""),
        file_url(&redirect_target).replace('"', "\\\"")
    );

    let broker = build_broker_from_config_str(&config).await.unwrap();
    let context = default_context();
    let large = address::join_relative(&prefix, "large.txt").unwrap();
    broker
        .write(
            &context,
            large.clone(),
            Body::Bytes(b"large".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    match broker
        .read(&context, large, ReadOptions::default())
        .await
        .unwrap()
    {
        BrokerReadOutcome::Redirect(redirect) => {
            assert_eq!(redirect.request.method, "GET");
            assert_eq!(redirect.request.url, file_url(&redirect_target));
        }
        BrokerReadOutcome::Bytes { .. } => {
            panic!("configured over-threshold route should use redirect branch")
        }
        BrokerReadOutcome::Stream { .. } => {
            panic!("configured over-threshold route should use redirect branch")
        }
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn broker_config_rejects_unknown_authz_plugin() {
    ensure_test_plugin_env();
    // Shape-validator passes; rejection happens at dlopen time.
    let contents = r#"
[authz]
plugin = "ovstorage-authz-this-does-not-exist"
"#;
    let config = parse_broker_config(contents).unwrap();
    validate_broker_config_for_startup(&config).expect("shape is valid");

    let err = match build_broker_from_config_str(contents).await {
        Ok(_) => panic!("expected dlopen to fail for an unknown authz plugin name"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::NotConfigured);
}

#[test]
fn broker_config_requires_authz_block() {
    let config = parse_broker_config(
        r#"
[discovery]
name = "missing authz"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&config)
            .unwrap_err()
            .code(),
        ErrorCode::NotConfigured
    );
}

#[test]
fn broker_metadata_cache_config_preserves_notification_source_schema() {
    let config = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[metadata_cache]
max_entries = 16
ttl_seconds = 31

[[metadata_cache.notification_sources]]
prefix = "s3://bucket/"
kind = "s3_sqs"
queue_url = "https://sqs.example/queue"
region = "us-west-2"
"#,
    )
    .unwrap();
    let metadata_cache = config.library.metadata_cache.unwrap();

    assert_eq!(metadata_cache.max_entries, Some(16));
    assert_eq!(metadata_cache.ttl_seconds, Some(31));
    assert_eq!(metadata_cache.notification_sources.len(), 1);
    assert_eq!(
        metadata_cache.notification_sources[0].prefix,
        "s3://bucket/"
    );
    assert_eq!(
        metadata_cache.notification_sources[0].source,
        NotificationSourceKind::S3Sqs {
            queue_url: "https://sqs.example/queue".into(),
            region: "us-west-2".into(),
        }
    );
}

#[test]
fn broker_listener_authn_accepts_trusted_forwarded_headers_on_trusted_proxy() {
    let config = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "127.0.0.1:0"
trusted_proxy = true
trusted_peers = ["127.0.0.1/32"]

[listener.authn]
mode = "trusted_forwarded_headers"
identity_header = "x-forwarded-user"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&config).unwrap();
}

#[test]
fn broker_listener_authn_rejects_trusted_mode_on_public_listener() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"

[listener.authn]
mode = "trusted_unsigned_jwt"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&config)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn broker_listener_authn_mtls_is_reserved_for_0_5() {
    let config = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"

[listener.authn]
mode = "mtls"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&config)
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
}

#[test]
fn broker_listener_authn_peer_cred_requires_local_transport() {
    let public = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"

[listener.authn]
mode = "peer_cred"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&public)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );

    let local = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "pipe:ovstorage"

[listener.authn]
mode = "peer_cred"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&local).unwrap();
}

#[test]
fn broker_listener_plaintext_tcp_non_loopback_requires_trusted_proxy_constraints() {
    let public = parse_broker_config(
        r#"
[listener]
bind = "0.0.0.0:8787"
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
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "0.0.0.0:8787"
trusted_proxy = true
trusted_peers = ["10.0.0.0/8"]

[listener.authn]
mode = "trusted_forwarded_headers"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&trusted_proxy).unwrap();
}

#[test]
fn broker_listener_authn_jwt_verify_requires_issuer_audience_and_jwks() {
    let missing = parse_broker_config(
        r#"
[listener]
bind = "127.0.0.1:0"

[listener.authn]
mode = "jwt_verify"
"#,
    )
    .unwrap();
    assert_eq!(
        validate_broker_config_for_startup(&missing)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidArgument
    );

    let complete = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "127.0.0.1:0"

[listener.authn]
mode = "jwt_verify"
issuer = "https://issuer.example"
audience = "ovstorage"
jwks_url = "https://issuer.example/.well-known/jwks.json"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&complete).unwrap();
}

#[test]
fn zero_config_builds_a_validating_broker_config() {
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
    let resolved = listener.resolved_authn().unwrap();
    assert_eq!(resolved.mode, BrokerAuthnMode::PeerCred);
    let authz = config.authz.as_ref().expect("zero-config has authz");
    assert_eq!(authz.plugin, "ovstorage-authz-toml");
    validate_broker_config_for_startup(&config).unwrap();
    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn broker_listener_uds_auto_selects_peer_cred() {
    let config = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "/tmp/ovstorage-broker.sock"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&config).unwrap();
    let listener = config.listener.as_ref().unwrap();
    let resolved = listener.resolved_authn().unwrap();
    assert_eq!(resolved.mode, BrokerAuthnMode::PeerCred);
}

#[test]
fn broker_listener_pipe_auto_selects_peer_cred() {
    let config = parse_broker_config(
        r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "pipe:ovstorage-broker"
"#,
    )
    .unwrap();
    validate_broker_config_for_startup(&config).unwrap();
    let listener = config.listener.as_ref().unwrap();
    let resolved = listener.resolved_authn().unwrap();
    assert_eq!(resolved.mode, BrokerAuthnMode::PeerCred);
}

#[test]
fn broker_listener_tcp_auto_selects_jwt_verify() {
    let listener = BrokerListenerConfig {
        bind: "127.0.0.1:0".into(),
        tls: None,
        trusted_proxy: false,
        trusted_peers: Vec::new(),
        authn: None,
    };
    let resolved = listener.resolved_authn().unwrap();
    assert_eq!(resolved.mode, BrokerAuthnMode::JwtVerify);
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
backend_kind = "nucleus"
client_id = "ovstorage-broker"
authorization_endpoint = "https://idp.example/authorize"
token_endpoint = "https://idp.example/token"
scope = "openid"
redirect_base = "http://127.0.0.1"
"#;

#[test]
fn validate_oauth_providers_pass_with_tcp_listener() {
    let raw = r#"
[authz]
plugin = "ovstorage-authz-toml"

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
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "/tmp/ovstorage-broker.sock"

[listener.authn]
mode = "peer_cred"
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
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "pipe:ovstorage-broker"

[listener.authn]
mode = "peer_cred"
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
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "/tmp/ovstorage-broker.sock"

[listener.authn]
mode = "peer_cred"
"#;
    let cfg = parse_broker_config(raw).unwrap();
    validate_oauth_providers_against_listeners(&cfg).unwrap();
}

#[test]
fn validate_oauth_providers_validator_runs_inside_startup_path() {
    // Misconfig must fire at startup, not at first OAuth request.
    let raw = r#"
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "/tmp/ovstorage-broker.sock"

[listener.authn]
mode = "peer_cred"
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
[authz]
plugin = "ovstorage-authz-toml"

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

#[test]
fn oauth_providers_config_round_trips() {
    let raw = format!(
        r#"
[authz]
plugin = "ovstorage-authz-toml"
{OAUTH_PROVIDER_TOML}
[broker_oauth_routes]
"nucleus://prod/" = "upstream-idp"
"#
    );
    let cfg = parse_broker_config(&raw).unwrap();
    assert_eq!(cfg.oauth_providers.len(), 1);
    let provider = cfg.oauth_providers.get("upstream-idp").unwrap();
    assert_eq!(provider.backend_kind, "nucleus");
    assert_eq!(provider.client_id, "ovstorage-broker");
    assert_eq!(
        cfg.broker_oauth_routes.get("nucleus://prod/").unwrap(),
        "upstream-idp"
    );
    let (registry, bindings) = build_oauth_providers_from_config(&cfg).unwrap();
    assert!(registry.lookup("upstream-idp").is_some());
    assert!(!bindings.is_empty());
}

// Joe's review finding #4: the broker's --listen CLI override mutates
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
[authz]
plugin = "ovstorage-authz-toml"

[listener]
bind = "/tmp/ovstorage-broker.sock"
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
