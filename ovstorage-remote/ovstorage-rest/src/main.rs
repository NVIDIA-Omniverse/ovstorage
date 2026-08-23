// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST gateway binary.
//!
//! `[--config PATH] [--listen HOST:PORT]`. Config defaults to
//! `./ovstorage.toml`. Override precedence: CLI > env > config file > default.

use std::net::SocketAddr;
use std::path::Path;

use ovstorage::{Error, ErrorCode};
use ovstorage_rest::{GatewayStack, GatewayStackBuilder};
use serde::Deserialize;

/// Top-level shape of the REST gateway's `ovstorage.toml`.
#[derive(Debug, Default, Deserialize)]
struct RestConfig {
    /// The shared inner data-plane Stack, declared as `[ovstorage]` config
    /// (root + `[ovstorage.layers.*]` + `[[ovstorage.connections]]`). The gateway
    /// builds it verbatim through [`ovstorage::host::build_stack`]; the layer
    /// graph and follower follow policy are all layer config
    /// here, not host concerns. An empty `[ovstorage.layers]` is rejected at
    /// startup (`require_configured_stack`) — the gateway refuses to serve nothing.
    #[serde(default)]
    ovstorage: ovstorage::StackConfig,
    #[serde(default)]
    server: ServerConfig,
    /// Trust-boundary attribution strategy for `modified_by`. See the
    /// REST gateway operator guide. Default `user_metadata`.
    #[serde(default)]
    attribution_strategy: AttributionStrategyConfig,
    /// Whether a redirect carrying a credential broader than the redirected
    /// request may be handed to the client that asked for it.
    ///
    /// This is a property of the deployment, not of the credential, which is
    /// why it is an operator setting rather than a rule. A gateway is not always
    /// a credential boundary: it is sometimes a central configuration point for
    /// clients already inside the trust boundary — a pod of render agents in one
    /// datacenter behind one gateway — and handing those clients a credential
    /// discloses nothing they were not already entitled to, while refusing costs
    /// them the redirect path entirely.
    ///
    /// The broker spells this key the same way and means the same thing by it,
    /// and there it governs the read and the write path together. On the
    /// gateway it is a **read** setting in effect: REST surfaces no write
    /// redirect at all — a body-bearing `PUT` is followed server-side, and a
    /// `WriteStep::Redirects` reaching a handler is answered `Unsupported`. So
    /// there is no write disclosure here for it to govern.
    #[serde(default)]
    redirect_credential_disclosure: RedirectDisclosureConfig,
    /// Where the credential substrate lives on disk.
    ///
    /// ```toml
    /// [auth]
    /// state_root = "/srv/ovstorage/auth"
    /// ```
    #[serde(default)]
    auth: AuthStateConfig,
}

/// Operator control over the auth directory — `auth.sqlite`, its advisory
/// refresh locks, and the credential bytes.
///
/// Not to be confused with a byte-cache `state_root`: those are layer config
/// under `[ovstorage.layers.*]` and hold cache index state, which is safe to
/// delete. This directory is not.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthStateConfig {
    /// Absolute path to the auth directory. Takes precedence over
    /// `OVSTORAGE_AUTH_DIR`, which in turn takes precedence over the platform
    /// per-user data directory.
    #[serde(default)]
    state_root: Option<std::path::PathBuf>,
}

/// Whether redirects may carry a connection-wide credential to the client.
///
/// ```toml
/// redirect_credential_disclosure = "refuse"  # default; the gateway moves the bytes
/// # redirect_credential_disclosure = "allow" # clients are inside the trust boundary
/// ```
///
/// Redirects whose credential is scoped to the redirected request — an S3
/// presigned URL, an Azure service SAS the gateway minted, a GCS signed URL —
/// are surfaced as `307` under **both** settings. They are the reason redirects
/// exist and disclose nothing beyond the object being transferred.
#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RedirectDisclosureConfig {
    /// A redirect carrying a credential broader than the redirected request is
    /// not handed over; this host moves the bytes instead.
    #[default]
    Refuse,
    /// Any valid redirect may be handed to the client.
    Allow,
}

impl RedirectDisclosureConfig {
    fn discloses(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AttributionStrategyConfig {
    #[default]
    UserMetadata,
    Passthrough,
    ExternalDb,
}

impl From<AttributionStrategyConfig> for ovstorage_authz::AttributionStrategy {
    fn from(value: AttributionStrategyConfig) -> Self {
        match value {
            AttributionStrategyConfig::UserMetadata => Self::UserMetadata,
            AttributionStrategyConfig::Passthrough => Self::Passthrough,
            AttributionStrategyConfig::ExternalDb => Self::ExternalDb,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ServerConfig {
    /// Listen address as `HOST:PORT`.
    listen: Option<String>,
    /// Per-server auth block, resolved by
    /// [`ovstorage_authz_layer::resolve_listener_auth`] into the selected auth
    /// layer's kind + `LayerConfig`. Fail-closed: absent ⇒ the gateway refuses
    /// to build. `auth = "anonymous"` is the explicit unauthenticated allow-all
    /// opt-in; `[server.auth]` (a `{ kind, config }` table) carries the policy
    /// rule set plus optional OIDC `jwt_*` params and the `peer_dev_current_user`
    /// flag. Captured opaquely and handed to the resolver at
    /// build time — the host performs no authn.
    #[serde(default)]
    auth: Option<toml::Value>,
}

impl RestConfig {
    fn load_or_default(path: Option<&Path>) -> ovstorage::Result<Self> {
        use figment::{
            Figment,
            providers::{Env, Format, Toml},
        };
        let env = Env::prefixed("OVSTORAGE_REST__")
            .map(|key| {
                let lowered: String = key.as_str().to_lowercase().replace("__", ".");
                lowered.into()
            })
            .split(".");
        let mut figment = Figment::new();
        if let Some(p) = path {
            figment = figment.merge(Toml::file(p));
        }
        let config: Self = figment.merge(env).extract().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid REST config: {error}"),
            )
        })?;
        // Before anything opens or chmods the path. A relative auth root is
        // resolved against the working directory, so `state_root = "."` would
        // take the gateway's own working directory, narrow it to `0700` and
        // create `auth.sqlite` inside it.
        validate_auth_state_root(config.auth.state_root.as_deref())?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() {
    let _tracing = match ovstorage::init_tracing_from_env() {
        Ok(guard) => guard,
        Err(error) if error.code() == ErrorCode::AlreadyExists => ovstorage::TracingGuard::noop(),
        Err(error) => {
            eprintln!("{}: {}", error_code_name(error.code()), error.message());
            std::process::exit(exit_code(error.code()));
        }
    };
    if let Err(error) = run().await {
        eprintln!("{}: {}", error_code_name(error.code()), error.message());
        std::process::exit(exit_code(error.code()));
    }
}

async fn run() -> ovstorage::Result<()> {
    let Args {
        config_path,
        listen_override,
        dump_openapi,
    } = parse_args()?;

    if dump_openapi {
        let spec = ovstorage_rest::openapi_spec();
        let json = serde_json::to_string_pretty(&spec).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("serialize OpenAPI spec: {err}"),
            )
        })?;
        println!("{json}");
        return Ok(());
    }

    let resolved_config_path = resolve_config_path(config_path.as_deref());
    let cfg = RestConfig::load_or_default(resolved_config_path.as_deref())?;
    let gateway = build_gateway_stack_from_config(&cfg, cfg.attribution_strategy.into()).await?;

    let listen = resolve_listen(listen_override, cfg.server.listen.as_deref())?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to bind {listen}: {error}"),
            )
        })?;
    println!("serving REST on http://{listen}");
    tracing::info!(
        target: "ovstorage.rest.lifecycle",
        event = "startup",
        version = env!("CARGO_PKG_VERSION"),
        listen = %listen,
        "REST gateway started"
    );

    let router = ovstorage_rest::router(gateway);
    let result = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("REST server exited with error: {error}"),
        )
    });
    tracing::info!(
        target: "ovstorage.rest.lifecycle",
        event = "drain_complete",
        "REST gateway stopped"
    );
    result
}

/// Resolve the config file path: CLI flag, then `./ovstorage.toml`, then `None`.
fn resolve_config_path(cli: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(path) = cli {
        return Some(std::path::PathBuf::from(path));
    }
    let cwd_default = std::path::PathBuf::from("./ovstorage.toml");
    cwd_default.is_file().then_some(cwd_default)
}

/// Resolve the listen address (CLI > config (figment merges env) > default).
fn resolve_listen(
    cli_override: Option<SocketAddr>,
    config_value: Option<&str>,
) -> ovstorage::Result<SocketAddr> {
    if let Some(addr) = cli_override {
        return Ok(addr);
    }
    if let Some(value) = config_value {
        return value
            .parse()
            .map_err(|_| invalid("server.listen must be HOST:PORT"));
    }
    Ok(SocketAddr::from(([127, 0, 0, 1], 8080)))
}

struct Args {
    config_path: Option<String>,
    listen_override: Option<SocketAddr>,
    dump_openapi: bool,
}

fn parse_args() -> ovstorage::Result<Args> {
    let mut config_path = None;
    let mut listen_override = None;
    let mut dump_openapi = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = Some(
                    args.next()
                        .ok_or_else(|| invalid("missing path after --config"))?,
                );
            }
            "--listen" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid("missing address after --listen"))?;
                listen_override = Some(
                    value
                        .parse()
                        .map_err(|_| invalid("--listen must be HOST:PORT"))?,
                );
            }
            "--dump-openapi" => {
                dump_openapi = true;
            }
            "--help" | "-h" | "help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(invalid(format!("unknown argument '{other}'"))),
        }
    }
    Ok(Args {
        config_path,
        listen_override,
        dump_openapi,
    })
}

async fn build_gateway_stack_from_config(
    cfg: &RestConfig,
    attribution_strategy: ovstorage_authz::AttributionStrategy,
) -> ovstorage::Result<GatewayStack> {
    // The non-plugin preflight below preserves fail-fast validation before
    // plugin-directory lookup. Plugin kinds validate in GatewayStackBuilder
    // against the loaded auth-capable factory set before its configured-stack
    // guard, so an independent empty-stack error cannot mask an auth typo.
    let auth_plan =
        ovstorage_authz_layer::ListenerAuthBuildPlan::listener(cfg.server.auth.clone(), "rest");
    if auth_plan.preflight()?.is_some() {
        // Preserve the built-in/anonymous path's early configured-stack guard,
        // before plugin-directory resolution. The builder repeats this guard
        // for plugin auth after resolving its loaded factory kind.
        ovstorage::host::require_configured_stack(&cfg.ovstorage)?;
    }
    let plugin_dir = ovstorage::default_plugin_dir().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "could not resolve a default plugin directory; set OVSTORAGE_PLUGIN_DIR",
        )
    })?;
    let auth_root = rest_auth_state_root(cfg.auth.state_root.as_deref());
    // The declared `[ovstorage]` graph (layers + connections) is handed verbatim
    // to `build_stack`; the gateway carries only the host concerns config cannot
    // (attribution strategy + the resolved auth-layer config).
    let builder = GatewayStackBuilder::new()
        .plugin_dir(plugin_dir)
        .auth_dir(auth_root)
        .attribution_strategy(attribution_strategy)
        .redirect_disclosure(cfg.redirect_credential_disclosure.discloses())
        .stack_config(cfg.ovstorage.clone())
        .require_configured_stack()
        .listener_auth(cfg.server.auth.clone(), "rest");
    // SAFETY: dlopen runs platform loader hooks; the operator controls the plugin dir.
    unsafe { builder.build().await }
}

/// Refuse an auth root that is empty or relative.
///
/// Checked before anything opens or chmods the path, because both are
/// destructive against the wrong directory.
fn validate_auth_state_root(state_root: Option<&std::path::Path>) -> ovstorage::Result<()> {
    let Some(root) = state_root else {
        return Ok(());
    };
    if root.as_os_str().is_empty() || !root.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`auth.state_root` must be an absolute path, got {root:?}. A relative \
                 auth directory is resolved against the working directory, so it moves \
                 with wherever the service happens to be started",
            ),
        ));
    }
    Ok(())
}

/// `[auth] state_root` when the operator set one, else the shared resolver.
///
/// The config key sits ahead of `OVSTORAGE_AUTH_DIR` for the same reason it
/// does in the broker: a gateway running as its own service user is
/// configured by a file an operator owns, and an inherited environment
/// variable should not silently redirect where its credentials land.
fn rest_auth_state_root(configured_root: Option<&std::path::Path>) -> std::path::PathBuf {
    match configured_root {
        Some(path) => path.to_path_buf(),
        None => ovstorage::auth::default_state_root(),
    }
}

fn print_usage() {
    eprintln!(
        "usage: ovstorage-rest [--config PATH] [--listen HOST:PORT] [--dump-openapi]\n\
         \n\
         --dump-openapi prints the OpenAPI spec to stdout and exits;\n\
         no listener is bound, no config is required.\n\
         \n\
         Reads `./ovstorage.toml` if --config is omitted. The gateway\n\
         refuses to start without a declared `[ovstorage]` stack. TOML\n\
         schema is the shared `[ovstorage]` Stack (`root`,\n\
         `[ovstorage.layers.*]`, `[[ovstorage.connections]]`) plus a\n\
         REST-specific `[server]` section:\n\
         \n\
           [server]\n\
           listen = \"127.0.0.1:8080\"\n\
           # Fail-closed: `auth` is required. Explicit anonymous opt-in:\n\
           auth = \"anonymous\"\n\
         \n\
           # ...or a gated built-in auth layer:\n\
           # [server.auth]\n\
           # kind = \"builtin-auth\"\n\
           # [server.auth.config]\n\
           # policy = {{ plugin = \"ovstorage-authz-toml\", policy = [ ] }}\n\
           # jwt_issuer = \"https://issuer.example/\"\n\
           # jwt_audience = \"my-audience\"\n\
           # jwt_jwks_url = \"https://issuer.example/.well-known/jwks\"\n\
         \n\
         Override hierarchy: CLI flag > env var > config file > default.\n\
         Env-var convention: OVSTORAGE_REST__<FIELD>__<NESTED> (double\n\
         underscore = nesting). Example:\n\
           OVSTORAGE_REST__SERVER__LISTEN=0.0.0.0:8080"
    );
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotFound => "NotFound",
        ErrorCode::AlreadyExists => "AlreadyExists",
        ErrorCode::PermissionDenied => "PermissionDenied",
        ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
        ErrorCode::InvalidArgument => "InvalidArgument",
        ErrorCode::Unsupported => "Unsupported",
        ErrorCode::NoRoute => "NoRoute",
        ErrorCode::BrokerUnavailable => "BrokerUnavailable",
        _ => "Error",
    }
}

fn exit_code(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::NotFound => 2,
        ErrorCode::PermissionDenied => 3,
        ErrorCode::InvalidArgument => 7,
        ErrorCode::Unsupported => 6,
        ErrorCode::BrokerUnavailable => 13,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(contents: &str) -> RestConfig {
        toml::from_str(contents).expect("parse RestConfig")
    }

    /// The operator-facing wire for `redirect_credential_disclosure` on the
    /// gateway: shipped TOML -> `RestConfig` -> `.discloses()`.
    ///
    /// The companion of the broker's test of the same shape. Every behavioural
    /// test injects the boolean through `GatewayStackBuilder`, so without this
    /// the only path an operator uses is unexercised, and the failure is
    /// invisible in the shipped file because the shipped value is the default:
    /// a key written below the first table header nests under `[server]` and
    /// silently stays `Refuse`.
    #[test]
    fn shipped_rest_config_redirect_disclosure_is_top_level_and_parses() {
        let shipped = include_str!("../ovstorage-rest.toml");
        let cfg = parse(shipped);
        assert_eq!(
            cfg.redirect_credential_disclosure,
            RedirectDisclosureConfig::Refuse,
            "the shipped default must be `refuse`"
        );
        assert!(!cfg.redirect_credential_disclosure.discloses());

        let overridden = shipped.replace(
            "redirect_credential_disclosure = \"refuse\"",
            "redirect_credential_disclosure = \"allow\"",
        );
        assert_ne!(
            overridden, shipped,
            "the shipped file must carry the key for this substitution to mean anything"
        );
        let cfg = parse(&overridden);
        assert_eq!(
            cfg.redirect_credential_disclosure,
            RedirectDisclosureConfig::Allow,
            "a top-level redirect_credential_disclosure must reach RestConfig"
        );
        assert!(cfg.redirect_credential_disclosure.discloses());
    }

    /// A value the enum does not name is a parse error rather than a silent
    /// fallback to the safe default, which would leave an operator believing
    /// they had configured something.
    #[test]
    fn an_unknown_rest_redirect_disclosure_value_is_rejected() {
        let shipped = include_str!("../ovstorage-rest.toml");
        let bad = shipped.replace(
            "redirect_credential_disclosure = \"refuse\"",
            "redirect_credential_disclosure = \"permit\"",
        );
        assert_ne!(bad, shipped, "the substitution must have applied");
        let error = toml::from_str::<RestConfig>(&bad)
            .expect_err("an unrecognised disclosure value must be rejected");
        assert!(
            error.to_string().contains("redirect_credential_disclosure"),
            "the error must name the key the operator got wrong, got: {error}"
        );
    }

    #[tokio::test]
    async fn rest_config_without_server_auth_fails_closed() {
        // No `[server].auth` ⇒ the gateway refuses to build (fail-closed),
        // never a silent allow-all. The resolver runs
        // before any plugin load, so the error surfaces regardless of env.
        let cfg = parse(
            r#"
[server]
listen = "127.0.0.1:8080"
"#,
        );
        let error =
            match build_gateway_stack_from_config(&cfg, cfg.attribution_strategy.into()).await {
                Ok(_) => panic!("expected fail-closed build error"),
                Err(error) => error,
            };
        assert_eq!(error.code(), ErrorCode::NotConfigured);
        assert!(
            error.message().contains("has no auth configured"),
            "unexpected message: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn rest_config_connections_without_layers_refused_at_build() {
        // A32 (mirror of the broker's
        // `broker_config_connections_without_layers_refused_at_build`): a REST
        // config with `[[ovstorage.connections]]` but no `[ovstorage.layers]` must
        // be refused on the BUILD path — not only via the `run()` call — so a
        // future refactor that drops `run()`'s guard cannot bind a listener over an
        // `EmptyLayer` stack that answers every request with `Unsupported` (the
        // O-5.2 regression). Auth is present (`anonymous`) so the build clears the
        // fail-closed auth gate and reaches the empty-stack guard; that guard fires
        // before any plugin dir resolution, so no plugin env is required.
        let cfg = parse(
            r#"
[server]
listen = "127.0.0.1:8080"
auth = "anonymous"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "/tmp/ovstorage-rest-refused"
"#,
        );
        let error =
            match build_gateway_stack_from_config(&cfg, cfg.attribution_strategy.into()).await {
                Ok(_) => panic!("expected the empty-stack build guard to refuse"),
                Err(error) => error,
            };
        assert_eq!(error.code(), ErrorCode::NotConfigured);
        assert!(
            error.message().contains("empty stack"),
            "unexpected message: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn rest_config_gated_policy_denies_write_allows_read() {
        // End-to-end mirror of the broker's
        // `broker_config_gated_policy_denies_write_allows_read`: a REST config
        // whose `[server.auth.config.policy]` denies writes and allows reads must
        // gate through the REAL build path (`build_gateway_stack_from_config`),
        // proving the deny policy is sourced from `auth.config` — not a leftover
        // allow-all default anywhere in the stack (fail-closed single source).
        use axum::body::Body as AxumBody;
        use axum::http::{Method, Request, StatusCode};
        use http_body_util::BodyExt as _;
        use ovstorage::address;
        use ovstorage_rest::router;
        use tower::ServiceExt as _;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Pin the build-script fixture so the real build path discovers the
        // core and HTTP utility plugins required by the shipped graph, without
        // depending on an ambient installation.
        let plugin_dir = std::path::PathBuf::from(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR"));
        // SAFETY: set before the build; no other test in this binary reads
        // `OVSTORAGE_PLUGIN_DIR`, and neither of the sibling tests reaches plugin
        // resolution (one errors in `resolve_listener_auth`, one only parses).
        unsafe { std::env::set_var("OVSTORAGE_PLUGIN_DIR", &plugin_dir) };

        let root = std::env::temp_dir().join(format!(
            "ovstorage-rest-cfgtest-root-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root_string = root.to_string_lossy().replace('\\', "/");

        // The gating policy lives ENTIRELY in `[server.auth.config.policy]`: allow
        // read, deny write. No allow-all rule appears anywhere in the file.
        let contents = format!(
            r#"
[server]

[server.auth]
kind = "builtin-auth"

[server.auth.config.policy]
plugin = "ovstorage-authz-toml"

[[server.auth.config.policy.policy]]
id = "read-only"
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "*"

[ovstorage]
root = "alias"

[ovstorage.layers.alias]
inner = "copy_rename_fallback"

[ovstorage.layers.copy_rename_fallback]
inner = "redirect_follower"

[ovstorage.layers.redirect_follower]
inner = "router"
follow_reads = false

[ovstorage.layers.router]
children = ["attribution_file"]

# Declared explicitly rather than left to the host, so this fixture exercises an
# operator config that names its own attribution layer in the supported place.
[ovstorage.layers.attribution_file]
kind = "attribution"
inner = "file"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{}"
"#,
            root_string.replace('"', "\\\"")
        );
        let cfg = parse(&contents);
        let gateway = build_gateway_stack_from_config(&cfg, cfg.attribution_strategy.into())
            .await
            .expect("gateway builds from the gated auth config");

        // `file:`-prefixed address for the backend root, plus a leaf object.
        let mut prefix = root_string.clone();
        if !prefix.starts_with('/') {
            prefix.insert(0, '/');
        }
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let prefix = address::parse(&format!("file:{prefix}")).unwrap();
        let object = address::join_relative(&prefix, "note.txt").unwrap();

        let app = router(gateway);

        // Write is denied by the config-sourced policy → 403 PermissionDenied at
        // the auth layer, before any backend write.
        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/v1/objects?dest={object}"))
                    .body(AxumBody::from("blocked"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::FORBIDDEN);
        let put_body = put.into_body().collect().await.unwrap().to_bytes();
        let put_json: serde_json::Value = serde_json::from_slice(&put_body).unwrap();
        assert_eq!(put_json["error"]["code"], "PermissionDenied");

        // Read is admitted by the same config-sourced policy. Seed the object on
        // disk (the `file` backend maps the address to `root/note.txt`) and GET
        // it → 200 with the bytes, proving the read passed the gate (not 403).
        std::fs::write(root.join("note.txt"), b"visible").unwrap();
        let get = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/v1/objects?address={object}"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        let get_body = get.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&get_body[..], b"visible");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rest_config_parses_anonymous_and_gated_auth_blocks() {
        // The `auth` field is captured opaquely for the resolver.
        let anon = parse(
            r#"
[server]
auth = "anonymous"
"#,
        );
        assert_eq!(
            anon.server.auth,
            Some(toml::Value::String("anonymous".into()))
        );

        let gated = parse(
            r#"
[server]

[server.auth]
kind = "builtin-auth"

[server.auth.config.policy]
plugin = "ovstorage-authz-toml"
"#,
        );
        let auth = gated.server.auth.expect("auth table present");
        assert_eq!(
            auth.get("kind").and_then(toml::Value::as_str),
            Some("builtin-auth")
        );
    }

    #[test]
    fn rest_config_empty_stack_refused_at_startup() {
        // A config that declares `[server]` but no `[ovstorage.layers]` must be
        // rejected at startup: an empty stack builds the one-layer `EmptyLayer`
        // Stack (serves nothing), so the gateway fails fast rather than binding a
        // listener that answers every request with `Unsupported`.
        let cfg = parse(
            r#"
[server]
listen = "127.0.0.1:8080"
auth = "anonymous"
"#,
        );
        let error = ovstorage::host::require_configured_stack(&cfg.ovstorage)
            .expect_err("empty [ovstorage] must be refused");
        assert_eq!(error.code(), ErrorCode::NotConfigured);
        assert!(
            error.message().contains("empty stack"),
            "unexpected message: {}",
            error.message()
        );
    }

    // The shipped default `ovstorage-rest.toml` declares the full
    // gateway graph as `[ovstorage]` config; it must parse through
    // `StackConfig::from_toml_str` and `build_stack` to a real (non-`EmptyLayer`)
    // Stack rooted at `alias`. Point the `file` connection root at a tempdir
    // so it resolves a real directory; otherwise the graph is exactly as shipped.
    #[tokio::test]
    async fn shipped_default_config_ovstorage_builds_to_nonempty_stack() {
        use std::sync::Arc;

        use ovstorage::{LoadedLayerFactory, StackConfig};

        let shipped = include_str!("../ovstorage-rest.toml");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data = std::env::temp_dir().join(format!("ovstorage-rest-shipped-{stamp}"));
        std::fs::create_dir_all(&data).unwrap();
        let substituted = shipped.replace("/srv/ovstorage/data", &data.to_string_lossy());

        let config = StackConfig::from_toml_str(&substituted).unwrap();
        assert_eq!(config.root.as_deref(), Some("alias"));
        // Attribution is a router branch, not the root: the shipped `file`
        // branch carries it, so the router's child is the wrapper.
        assert_eq!(
            config.layers["router"].children,
            vec!["attribution_file".to_string()]
        );
        assert_eq!(
            config.layers["attribution_file"].inner.as_deref(),
            Some("file")
        );

        // REST-critical: the follower must NOT follow reads, so a backend read
        // redirect flows up unfollowed and the handler surfaces it as HTTP 307. A
        // future TOML edit that drops/flips this must fail here, not silently break
        // 307 surfacing.
        let follower = config
            .layers
            .get("redirect_follower")
            .expect("shipped config declares a redirect_follower layer");
        assert_eq!(
            follower.config.get("follow_reads"),
            Some(&toml::Value::Boolean(false)),
            "REST redirect_follower must set follow_reads=false for 307 surfacing",
        );

        // Load the public utility providers from the same build-script fixture
        // the REST integration tests use. The gateway's two private wrappers
        // remain in-process host concerns.
        let auth_root = rest_auth_state_root(None);
        ovstorage::init_auth_substrate(Some(&auth_root)).unwrap();
        let mut factories: Vec<LoadedLayerFactory> = unsafe {
            ovstorage::load_layer_plugins_from_dir(
                std::path::Path::new(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR")),
                true,
            )
            .unwrap()
        };
        factories.extend([LoadedLayerFactory::Wrapper(Arc::new(
            ovstorage_authz::AttributionWrapperFactory::new(
                ovstorage_authz::AttributionStrategy::UserMetadata,
            ),
        ))]);
        // The shipped graph must be a FIXED POINT of the branch-attribution
        // guarantee, which runs over every graph the host builds. If it changed
        // this one, the documented graph would not be the graph that runs.
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
            .expect("shipped ovstorage-rest.toml must build_stack");

        // A real graph, not the `EmptyLayer` fallback (which roots at `empty`).
        assert_eq!(stack.spec().root, "alias");
        assert!(
            stack.spec().layers.len() > 1,
            "expected the full gateway graph, got {} layer(s)",
            stack.spec().layers.len()
        );

        std::fs::remove_dir_all(&data).ok();
    }
}
