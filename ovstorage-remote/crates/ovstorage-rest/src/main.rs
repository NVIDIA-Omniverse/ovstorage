// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST gateway binary.
//!
//! `[--config PATH] [--listen HOST:PORT]`. Config defaults to
//! `./ovstorage.toml`. Override precedence: CLI > env > config file > default.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage::{Error, ErrorCode, Library, LibraryConfig, Storage as _};
use ovstorage_authz::AuthzPlugin;
use ovstorage_rest::JwtAuthenticator;
use serde::Deserialize;

/// Top-level shape of the REST gateway's `ovstorage.toml`.
#[derive(Debug, Default, Deserialize)]
struct RestConfig {
    #[serde(flatten)]
    library: LibraryConfig,
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    authz: Option<AuthzPluginConfig>,
    /// Trust-boundary attribution strategy for `modified_by`. See the
    /// REST gateway operator guide. Default `user_metadata`.
    #[serde(default)]
    attribution_strategy: AttributionStrategyConfig,
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

/// `[authz]` shape: `plugin` names the cdylib; remaining fields pass
/// opaquely to the plugin's `configure` step.
#[derive(Clone, Debug, Deserialize, PartialEq)]
struct AuthzPluginConfig {
    plugin: String,
    #[serde(flatten)]
    config: toml::Table,
}

#[derive(Debug, Default, Deserialize)]
struct ServerConfig {
    /// Listen address as `HOST:PORT`.
    listen: Option<String>,
    /// OIDC bearer-token validation; `None` runs dev-mode authn.
    oidc: Option<OidcConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct OidcConfig {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    audience: String,
    #[serde(default)]
    jwks_url: String,
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
        figment.merge(env).extract().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid REST config: {error}"),
            )
        })
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
    let library = build_library_from_config(&cfg.library).await?;
    let authenticator = build_authenticator(&cfg.server)?;
    let authz = build_authz_plugin(cfg.authz.as_ref()).await?;

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

    let router = ovstorage_rest::router_with_attribution(
        library,
        authenticator,
        authz,
        cfg.attribution_strategy.into(),
    )?;
    let result = axum::serve(listener, router).await.map_err(|error| {
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

/// dlopen the configured authz plugin and run its `configure` step;
/// returns `None` when no `[authz]` section is present (dev mode).
async fn build_authz_plugin(
    config: Option<&AuthzPluginConfig>,
) -> ovstorage::Result<Option<Arc<dyn AuthzPlugin>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if config.plugin.is_empty() {
        return Err(invalid("[authz] plugin field must not be empty"));
    }
    let dir = ovstorage::default_plugin_dir().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "could not resolve a plugin directory (set OVSTORAGE_PLUGIN_DIR)",
        )
    })?;
    // SAFETY: dlopen runs platform loader hooks; the operator controls the plugin dir.
    let plugin =
        unsafe { ovstorage_authz::loaded::load_authz_plugin_for_kind(&dir, &config.plugin)? };
    let mut config_map = HashMap::with_capacity(config.config.len());
    for (key, value) in &config.config {
        let cv = match value {
            toml::Value::String(s) => ovstorage::ConfigValue::String(s.clone()),
            toml::Value::Integer(n) => ovstorage::ConfigValue::Int(*n),
            toml::Value::Boolean(b) => ovstorage::ConfigValue::Bool(*b),
            toml::Value::Table(_) | toml::Value::Array(_) => {
                let mut wrapper = toml::value::Table::new();
                wrapper.insert(key.clone(), value.clone());
                let toml_str = toml::to_string(&toml::Value::Table(wrapper)).map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("[authz] field '{key}' could not be reserialized to TOML: {err}"),
                    )
                })?;
                ovstorage::ConfigValue::Toml(toml_str)
            }
            other => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "[authz] field '{key}' has unsupported type: {}",
                        other.type_str()
                    ),
                ));
            }
        };
        config_map.insert(key.clone(), cv);
    }
    plugin.configure(config_map, None).await?;
    Ok(Some(Arc::new(plugin)))
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

async fn build_library_from_config(cfg: &LibraryConfig) -> ovstorage::Result<Arc<Library>> {
    let plugin_dir = ovstorage::default_plugin_dir().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "could not resolve a default plugin directory; set OVSTORAGE_PLUGIN_DIR",
        )
    })?;
    let auth_root = rest_auth_state_root()?;
    let secret_store = Arc::new(SecretStore::new());
    let refresh_lock = Arc::new(AuthRefreshLock::open(&auth_root)?);

    let library = Library::builder()
        .with_credential_persistence(secret_store.clone(), refresh_lock)
        .open()?;
    // SAFETY: dlopen runs platform loader hooks; the operator controls the plugin dir.
    unsafe {
        library.load_plugins_from_dir(Some(&plugin_dir))?;
    }
    for connection in &cfg.connections {
        let request = connection.to_connection_request()?;
        library.add_connection(request, None).await?;
    }
    Ok(library)
}

fn rest_auth_state_root() -> ovstorage::Result<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(std::path::PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-rest-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        Error::new(
            ErrorCode::StateRootUnavailable,
            format!("failed to create REST auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}

/// Build a JWT authenticator from `[server.oidc]`. The figment overlay
/// already merged `OVSTORAGE_REST__SERVER__OIDC__*` env vars into the
/// config struct; this function only consumes what figment produced.
fn build_authenticator(server: &ServerConfig) -> ovstorage::Result<Option<Arc<JwtAuthenticator>>> {
    let Some(oidc) = server.oidc.as_ref() else {
        return Ok(None);
    };
    if oidc.issuer.is_empty() || oidc.audience.is_empty() || oidc.jwks_url.is_empty() {
        return Err(invalid(
            "[server.oidc] requires all of issuer/audience/jwks_url",
        ));
    }
    Ok(Some(Arc::new(JwtAuthenticator::new(
        oidc.issuer.clone(),
        oidc.audience.clone(),
        oidc.jwks_url.clone(),
    ))))
}

fn print_usage() {
    eprintln!(
        "usage: ovstorage-rest [--config PATH] [--listen HOST:PORT] [--dump-openapi]\n\
         \n\
         --dump-openapi prints the OpenAPI spec to stdout and exits;\n\
         no listener is bound, no config is required.\n\
         \n\
         Reads `./ovstorage.toml` if --config is omitted; falls back\n\
         to defaults if neither path exists. TOML schema embeds the\n\
         shared LibraryConfig (`[[connections]]`, `[[routes]]`,\n\
         `[state]`) plus a REST-specific `[server]` section:\n\
         \n\
           [server]\n\
           listen = \"127.0.0.1:8080\"\n\
         \n\
           [server.oidc]\n\
           issuer    = \"https://issuer.example/\"\n\
           audience  = \"my-audience\"\n\
           jwks_url  = \"https://issuer.example/.well-known/jwks\"\n\
         \n\
         Override hierarchy: CLI flag > env var > config file > default.\n\
         Env-var convention: OVSTORAGE_REST__<FIELD>__<NESTED> (double\n\
         underscore = nesting). Examples:\n\
           OVSTORAGE_REST__SERVER__LISTEN=0.0.0.0:8080\n\
           OVSTORAGE_REST__SERVER__OIDC__ISSUER=https://issuer.example"
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
