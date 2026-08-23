// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interactive backend setup. Picks a backend, walks only the visible
//! config fields (skipping `advanced` ones), then offers the backend's
//! credential methods (skipping `advanced` ones). After the connection
//! is registered, drives `authenticate_connection` to actually verify
//! the credentials and surfaces auth events live to the user.
//!
//! Positional KIND + required-field values skip the wizard end-to-end
//! (secrets for the chosen auth method are still prompted at the TTY).
//! `--advanced` re-exposes hidden config fields and falls back to walking
//! every credential field individually (the legacy per-field path);
//! wizard-only — incompatible with positional fields.
//!
//! `reauth <name>` (also in this module) drives the same auth flow for an
//! *existing* connection — used when a refresh token expired or the user
//! wants to log in again without rebuilding the connection config.

use std::collections::HashMap;
use std::time::SystemTime;

use inquire::{Password, PasswordDisplayMode, Select, Text};
use ovstorage::ext::LayerExt;
use ovstorage::{
    AuthEvent, AuthenticateRequest, CancellationToken, ConfigField, ConfigFieldKind, ConfigValue,
    Connection, ConnectionAuthState, ConnectionKey, CredentialField, CredentialMethod, EnumSource,
    Error, ErrorCode, LayerConnectionRequest, LayerType, Request, StackSpec,
    StorageBackendKindDescriptor, UpdateConnectionCredentialsRequest, config_value_to_toml,
};

use crate::commands::util::{Step, next_or_cancel};
use crate::session::{SessionConnection, SessionState};

pub struct Args {
    pub kind: Option<String>,
    pub fields: Vec<String>,
    pub auth: Option<String>,
    pub name: Option<String>,
    pub advanced: bool,
}

pub async fn run(
    state: &mut SessionState,
    args: Args,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let descriptors = state.stack.list_backend_kinds()?;
    if descriptors.is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "no backend kinds are registered",
        ));
    }

    if args.advanced && (!args.fields.is_empty() || args.auth.is_some()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "--advanced is wizard-only; cannot be combined with positional fields or --auth",
        ));
    }

    let descriptor = match &args.kind {
        Some(kind) => find_descriptor(descriptors, kind)?,
        None => pick_backend(descriptors)?,
    };
    println!(
        "Configuring {} ({})",
        descriptor.display_name, descriptor.kind
    );
    if let Some(desc) = &descriptor.description {
        println!("  {desc}");
    }

    let required_count = descriptor
        .config_schema
        .iter()
        .filter(|f| f.required)
        .count();
    let non_interactive = args.kind.is_some() && args.fields.len() == required_count;
    if !args.fields.is_empty() && !non_interactive {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "{} expects {} required field value(s) (got {}); supply all of them or none",
                descriptor.kind,
                required_count,
                args.fields.len(),
            ),
        ));
    }

    let (config_runtime, credentials, display_name) = if non_interactive {
        let config_runtime = build_config_from_positional(&descriptor, &args.fields)?;
        let credentials = pick_credentials_non_interactive(&descriptor, args.auth.as_deref())?;
        (config_runtime, credentials, args.name.clone())
    } else {
        let config_runtime = walk_config_schema(&descriptor, args.advanced)?;
        let credentials = gather_credentials(&descriptor, args.advanced)?;
        // Ask all interactive questions up front so the long-running authentication
        // step is the last thing the user waits on, not interrupted by a prompt.
        let display_name = match args.name.clone() {
            Some(n) => Some(n),
            None => prompt_display_name()?,
        };
        (config_runtime, credentials, display_name)
    };

    // Resolve the owning-layer target up front so it can be recorded on the
    // session connection for `write-config` round-tripping (renamed backend
    // layers) as well as used for addressing the connection-lifecycle calls.
    let target = resolve_backend_target(state.stack.spec(), &descriptor.kind)?;

    let session_conn = SessionConnection {
        backend_kind: descriptor.kind.clone(),
        target: Some(target.clone()),
        display_name: display_name.clone(),
        config: config_runtime
            .iter()
            .map(|(k, v)| (k.clone(), config_value_to_toml(v)))
            .collect(),
        credentials,
    };

    let request = session_conn.to_connection_request()?;
    // Connection-lifecycle calls are `Layer` primitives (no `LayerExt` verb);
    // UFCS avoids a trait-method collision with `LayerExt`'s data-plane verbs.
    let mut connection = ovstorage::Layer::add_connection(
        state.stack.as_ref(),
        Request::new(LayerConnectionRequest {
            target: target.clone(),
            connection: request,
        }),
        Some(cancel.clone()),
    )
    .await?;

    // When an authentication flow runs and fails, the half-registered
    // connection is dropped so the operator can retry `connect` — typically
    // with a different credential method — without hitting a route-prefix
    // conflict. A flow that was never offered, and a credential the origin
    // refused, both leave the registration in place; see below.
    let key = ConnectionKey {
        target: target.clone(),
        id: connection.id.clone(),
    };
    // `add_connection` may already have settled the identity — a backend with
    // static credentials or none at all reports `Anonymous` or
    // `Authenticated`. Driving an interactive flow over a settled connection
    // has nothing to do.
    //
    // Deciding on the reported state rather than on the error code keeps the
    // skip narrow: a connection that is genuinely parked or refused still
    // drives the flow, and a real authentication failure still propagates.
    let settled = matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. }
    );
    // Kept so the exit-status decision below can hand back the backend's own
    // explanation rather than inventing one.
    let mut no_flow_offered: Option<Error> = None;
    if !settled {
        match drive_authentication(state, key.clone(), cancel).await {
            Ok(AuthOutcome::Flowed(authenticated)) => connection = authenticated,
            // Nothing was ever offered to drive, so there is nothing to have
            // failed. Keep the connection: `add_connection` accepted it, and
            // where it publishes roots it serves reads. `print_success` reports
            // what the state is, and the exit status follows whether the
            // connection can serve anything at all.
            Ok(AuthOutcome::NoFlowOffered(err)) => no_flow_offered = Some(err),
            Err(err) => {
                let _ = ovstorage::Layer::remove_connection(
                    state.stack.as_ref(),
                    Request::new(key),
                    None,
                )
                .await;
                return Err(err);
            }
        }
    }

    state.connections.push(session_conn);
    print_success(&connection, display_name.as_deref());

    if state.interactive
        && state.pwd.is_none()
        && let [only] = connection.current_addresses.as_slice()
    {
        state.pwd = Some(only.clone());
        println!("(pwd set to {only})");
    }

    // A refusal is reported through the exit status, not only through the
    // warning `print_success` prints: a script sees the status and cannot see
    // stderr prose, so `Connected` plus exit 0 was the opposite of what
    // happened.
    //
    // The registration deliberately survives. The probe is a `HEAD` on the
    // root, and an origin that challenges its root while serving the objects
    // beneath it is an ordinary shape — so deleting the connection would
    // discard a configuration whose data path works, and the operator has no
    // flag to overrule it. Reporting the failure is recoverable in both
    // directions; deleting the operator's typed credential is not.
    if let ConnectionAuthState::AuthFailed { error, .. } = &connection.auth_state {
        return Err(error.clone());
    }
    // The same rule for a connection that cannot serve anything. Keeping the
    // registration and reporting success are independent decisions, and only
    // the first is about not destroying the operator's typed credential: a
    // connection that is neither settled nor routable answers `NoRoute` to
    // every operation, so exiting 0 tells a script the opposite of what
    // happened. A backend with no interactive flow reaches here through
    // `NoFlowOffered`, whose error explains itself better than anything this
    // module could invent, so it is what travels back.
    if is_unusable(&connection) {
        return Err(no_flow_offered.unwrap_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "connection registered but neither authenticated nor routable",
            )
        }));
    }
    Ok(())
}

/// Whether a registered connection can serve nothing at all.
///
/// A parked connection is not automatically useless: the cloud backends derive
/// their roots from config and publish them while parked, so they keep serving
/// reads on a credential the origin has not confirmed, and reporting that as a
/// failure would be wrong. A connection that is *also* routeless is different —
/// every operation answers `NoRoute` — and that is the shape a backend with no
/// interactive flow leaves behind when its credential is refused at bring-up,
/// because root discovery is skipped for a parked connection.
fn is_unusable(connection: &Connection) -> bool {
    let settled = matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. }
    );
    !settled && connection.current_addresses.is_empty()
}

fn find_descriptor(
    descriptors: Vec<StorageBackendKindDescriptor>,
    kind: &str,
) -> ovstorage::Result<StorageBackendKindDescriptor> {
    descriptors
        .into_iter()
        .find(|d| d.kind == kind)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                format!("no backend kind '{kind}' is registered"),
            )
        })
}

/// Resolve the Layer `target` that owns connections of `backend_kind` from the
/// live stack graph, so `add_connection` / `authenticate_connection` address a
/// real Layer even when a backend Layer is named differently from its kind
/// (e.g. layer `s3_prod` of kind `s3`).
///
/// The `Connection` snapshot carries no owning-layer target, so both the fresh
/// `connect` and `reauth` paths recover it here from `backend_kind`:
/// - exactly one backend Layer of that kind → its `name` (handles the renamed
///   `s3_prod`/`s3` case);
/// - none → fall back to `backend_kind` itself, the default-stack convention
///   (backend Layer named after its kind);
/// - several backend Layers of that kind → the target is genuinely ambiguous
///   (the snapshot cannot say which one owns the connection), so return an
///   error instead of synthesizing `backend_kind`, which names no Layer and
///   would make `add_connection` / `authenticate_connection` fail against a
///   nonexistent target.
fn resolve_backend_target(spec: &StackSpec, backend_kind: &str) -> ovstorage::Result<String> {
    let names: Vec<&str> = spec
        .layers
        .iter()
        .filter(|l| l.layer_type == LayerType::Backend && l.kind == backend_kind)
        .map(|l| l.name.as_str())
        .collect();
    match names.as_slice() {
        [name] => Ok(name.to_string()),
        [] => Ok(backend_kind.to_string()),
        several => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "kind '{backend_kind}' is ambiguous: {} backend layers share it ({}); \
                 target it by layer name",
                several.len(),
                several.join(", "),
            ),
        )),
    }
}

fn build_config_from_positional(
    descriptor: &StorageBackendKindDescriptor,
    values: &[String],
) -> ovstorage::Result<HashMap<String, ConfigValue>> {
    let required: Vec<&ConfigField> = descriptor
        .config_schema
        .iter()
        .filter(|f| f.required)
        .collect();
    debug_assert_eq!(required.len(), values.len());
    let mut out = HashMap::with_capacity(required.len());
    for (field, raw) in required.iter().zip(values.iter()) {
        out.insert(field.key.clone(), parse_config_value(field, raw)?);
    }
    Ok(out)
}

fn parse_config_value(field: &ConfigField, raw: &str) -> ovstorage::Result<ConfigValue> {
    match &field.kind {
        ConfigFieldKind::Url | ConfigFieldKind::Text | ConfigFieldKind::Path => {
            Ok(ConfigValue::String(raw.to_string()))
        }
        ConfigFieldKind::Integer => raw
            .parse::<i64>()
            .map(ConfigValue::Int)
            .map_err(|_| invalid_field(field, raw, "expected an integer")),
        ConfigFieldKind::Bool => match raw {
            "true" | "1" | "yes" | "y" => Ok(ConfigValue::Bool(true)),
            "false" | "0" | "no" | "n" => Ok(ConfigValue::Bool(false)),
            _ => Err(invalid_field(field, raw, "expected true/false")),
        },
        ConfigFieldKind::Enum {
            source: EnumSource::Static(variants),
        } => {
            if variants.iter().any(|v| v == raw) {
                Ok(ConfigValue::String(raw.to_string()))
            } else {
                Err(invalid_field(
                    field,
                    raw,
                    &format!("expected one of: {}", variants.join(", ")),
                ))
            }
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Discovered,
        } => Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "field '{}' uses runtime-discovered enum values, which are not yet supported in connect",
                field.display_name
            ),
        )),
    }
}

fn invalid_field(field: &ConfigField, raw: &str, why: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("invalid value '{raw}' for {}: {why}", field.display_name),
    )
}

fn pick_credentials_non_interactive(
    descriptor: &StorageBackendKindDescriptor,
    auth: Option<&str>,
) -> ovstorage::Result<HashMap<String, String>> {
    // No --auth (or `--auth none`) means an empty bundle: the plugin decides
    // what to do (anonymous for cloud, OAuth-via-AwaitingAuth for Nucleus,
    // no-op for filesystem-style backends).
    if auth.is_none() || auth == Some("none") {
        return Ok(HashMap::new());
    }
    if descriptor.credential_methods.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "backend '{}' has no credential methods; --auth not applicable",
                descriptor.kind
            ),
        ));
    }
    let id = auth.expect("checked above");
    let method = descriptor
        .credential_methods
        .iter()
        .find(|m| m.key == id)
        .ok_or_else(|| {
            let mut known: Vec<&str> = descriptor
                .credential_methods
                .iter()
                .map(|m| m.key.as_str())
                .collect();
            known.push("none");
            Error::new(
                ErrorCode::NotFound,
                format!(
                    "no credential method '{id}' on backend '{}'; known methods: {}",
                    descriptor.kind,
                    known.join(", "),
                ),
            )
        })?;
    populate_from_method(descriptor, method)
}

/// Build a credential map from a chosen method by prompting for each
/// referenced field.
fn populate_from_method(
    descriptor: &StorageBackendKindDescriptor,
    method: &CredentialMethod,
) -> ovstorage::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for key in &method.fields {
        let Some(field) = descriptor.credential_schema.iter().find(|f| f.key == *key) else {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "credential method '{}' references unknown field '{}'",
                    method.display_name, key
                ),
            ));
        };
        // Every field of a chosen method must be answered. Passing an empty
        // answer through to the backend instead would be silently unsafe for
        // the backends that treat empty as absent: S3 and Azure map an empty
        // secret to `None`, so an operator who explicitly picked a credential
        // method and pressed Enter would get an *anonymous* client, and
        // against a public bucket that reports success.
        //
        // HTTP Basic does have a legitimate empty half (an API key as the
        // user-id, RFC 7617). It is reachable through a declared
        // `[[ovstorage.connections]]` credentials table or a supplied bundle,
        // which is where a caller that wants it is; making the shared
        // interactive prompt permit it would trade a real cross-backend
        // hazard for that convenience.
        out.insert(field.key.clone(), prompt_credential_field_required(field)?);
    }
    Ok(out)
}

fn pick_backend(
    descriptors: Vec<StorageBackendKindDescriptor>,
) -> ovstorage::Result<StorageBackendKindDescriptor> {
    let labels: Vec<String> = descriptors
        .iter()
        .map(|d| {
            if d.display_name == d.kind {
                d.kind.clone()
            } else {
                format!("{}  ({})", d.display_name, d.kind)
            }
        })
        .collect();
    let chosen = Select::new("Backend?", labels.clone())
        .prompt()
        .map_err(map_inquire)?;
    let idx = labels.iter().position(|l| *l == chosen).expect("found");
    Ok(descriptors.into_iter().nth(idx).expect("found"))
}

fn walk_config_schema(
    descriptor: &StorageBackendKindDescriptor,
    advanced: bool,
) -> ovstorage::Result<HashMap<String, ConfigValue>> {
    let mut config = HashMap::new();
    for field in &descriptor.config_schema {
        if field.advanced && !advanced {
            continue;
        }
        if let Some(value) = prompt_config_field(field)? {
            config.insert(field.key.clone(), value);
        }
    }
    Ok(config)
}

fn prompt_config_field(field: &ConfigField) -> ovstorage::Result<Option<ConfigValue>> {
    let label = field_label(&field.display_name, field.required);
    match &field.kind {
        ConfigFieldKind::Url | ConfigFieldKind::Text | ConfigFieldKind::Path => {
            let text = text_prompt(&label, field, default_as_string(field))?;
            require_non_empty(field, text).map(|opt| opt.map(ConfigValue::String))
        }
        ConfigFieldKind::Integer => {
            if !field.required && !confirm_set_field(&field.display_name)? {
                return Ok(None);
            }
            let mut prompt = inquire::CustomType::<i64>::new(&label)
                .with_error_message("Please enter an integer.");
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            if let Some(ConfigValue::Int(n)) = field.default {
                prompt = prompt.with_default(n);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::Int(value)))
        }
        ConfigFieldKind::Bool => {
            let mut prompt = inquire::Confirm::new(&label);
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            if let Some(ConfigValue::Bool(b)) = field.default {
                prompt = prompt.with_default(b);
            } else {
                prompt = prompt.with_default(false);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::Bool(value)))
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Static(variants),
        } => {
            if !field.required && !confirm_set_field(&field.display_name)? {
                return Ok(None);
            }
            let mut prompt = Select::new(&label, variants.clone());
            if let Some(help) = &field.help {
                prompt = prompt.with_help_message(help);
            }
            let value = prompt.prompt().map_err(map_inquire)?;
            Ok(Some(ConfigValue::String(value)))
        }
        ConfigFieldKind::Enum {
            source: EnumSource::Discovered,
        } => Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "field '{}' uses runtime-discovered enum values, which are not yet supported in connect",
                field.display_name
            ),
        )),
    }
}

/// Pick a credential method (when the descriptor advertises any) and
/// prompt only that method's referenced fields. The picker always offers
/// a `None` entry that produces an empty bundle (the plugin decides what
/// to do — anonymous, OAuth, no-op). Falls back to the per-field walk
/// when `--advanced` was passed.
fn gather_credentials(
    descriptor: &StorageBackendKindDescriptor,
    advanced: bool,
) -> ovstorage::Result<HashMap<String, String>> {
    let visible_methods: Vec<&CredentialMethod> = descriptor
        .credential_methods
        .iter()
        .filter(|m| !m.advanced || advanced)
        .collect();
    if advanced {
        return walk_credential_schema(descriptor);
    }
    if visible_methods.is_empty() {
        // Backend declares no methods (e.g. filesystem): no picker, empty bundle.
        return Ok(HashMap::new());
    }
    let Some(method) = pick_credential_method(&visible_methods)? else {
        return Ok(HashMap::new());
    };
    populate_from_method(descriptor, method)
}

/// Returns `Ok(None)` when the user picked the synthetic `None` entry.
fn pick_credential_method<'a>(
    methods: &[&'a CredentialMethod],
) -> ovstorage::Result<Option<&'a CredentialMethod>> {
    const NONE_LABEL: &str = "None";
    let mut labels: Vec<String> = Vec::with_capacity(methods.len() + 1);
    labels.push(NONE_LABEL.into());
    labels.extend(methods.iter().map(|m| m.display_name.clone()));
    let chosen = Select::new("Credential method?", labels.clone())
        .with_help_message(
            "Pick how you want to authenticate (pick None for public buckets or interactive auth).",
        )
        .prompt()
        .map_err(map_inquire)?;
    if chosen == NONE_LABEL {
        return Ok(None);
    }
    let idx = labels
        .iter()
        .position(|l| *l == chosen)
        .expect("selection comes from this list");
    // labels[0] is None; methods[i] corresponds to labels[i+1]
    Ok(Some(methods[idx - 1]))
}

/// Legacy per-field walk: prompt every credential field individually.
/// Reachable via `--advanced` or when a backend's `credential_methods`
/// are empty.
fn walk_credential_schema(
    descriptor: &StorageBackendKindDescriptor,
) -> ovstorage::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for field in &descriptor.credential_schema {
        if let Some(cred) = prompt_credential_field(field)? {
            out.insert(field.key.clone(), cred);
        }
    }
    Ok(out)
}

/// Prompt for a credential field driven by a chosen credential method.
/// Method-referenced fields are mandatory (the user already opted in by
/// picking the method).
/// Prompt for one field of a chosen credential method. Every field of a
/// chosen method must be answered — see `populate_from_method`.
fn prompt_credential_field_required(field: &CredentialField) -> ovstorage::Result<String> {
    let label = field_label(&field.display_name, true);
    let mut prompt = Password::new(&label)
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation();
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    let value = prompt.prompt().map_err(map_inquire)?;
    if value.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is required", field.display_name),
        ));
    }
    Ok(value)
}

fn prompt_credential_field(field: &CredentialField) -> ovstorage::Result<Option<String>> {
    if !confirm_set_field(&field.display_name)? {
        return Ok(None);
    }
    let label = field_label(&field.display_name, false);
    let mut prompt = Password::new(&label)
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation();
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    let value = prompt.prompt().map_err(map_inquire)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

/// Drive interactive auth for an existing connection (looked up by
/// `display_name`). Used by the `reauth <name>` CLI subcommand when a
/// refresh token has expired or the user wants to re-authenticate
/// without rebuilding the connection config. Surfaces the same
/// `OpenBrowser` / `DeviceCode` / `Progress` events as `connect`.
pub async fn reauth(
    state: &SessionState,
    name: &str,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let connections = state.stack.list_connections(None).await?;
    let mut matches = connections
        .iter()
        .filter(|c| c.display_name == name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(Error::new(
            ErrorCode::NotFound,
            format!("no connection with display_name '{name}'"),
        ));
    }
    if matches.len() > 1 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "display_name '{name}' is ambiguous ({} connections); rename one to disambiguate",
                matches.len()
            ),
        ));
    }
    let connection = matches.remove(0);
    eprintln!("authenticating '{}'…", connection.display_name);
    let key = ConnectionKey {
        target: resolve_backend_target(state.stack.spec(), &connection.backend_kind)?,
        id: connection.id.clone(),
    };
    // `Ok(None)` is "the first `authenticate_connection` answered
    // `Unsupported`". That is usually the `Layer` leaf default, but not
    // always — an alias layer refuses a credentialless visibility-override
    // row with `Unsupported` too, and so does a remote service that does not
    // implement the RPC. Each says something different and more useful than
    // "this backend kind has no flow", so the backend's own error is what
    // `drive_authentication` hands back rather than one invented here.
    let connection = match drive_authentication(state, key, cancel).await? {
        AuthOutcome::Flowed(connection) => connection,
        AuthOutcome::NoFlowOffered(err) => return Err(err),
    };
    // Same rule as `connect`: a flow that ends with the credential still
    // refused is not an `ok`, and the exit status is the only part of that a
    // script can read.
    if let ConnectionAuthState::AuthFailed { error, .. } = &connection.auth_state {
        eprintln!("  the backend refused these credentials.");
        return Err(error.clone());
    }
    eprintln!("ok ({}).", connection.display_name);
    Ok(())
}

/// What driving `authenticate_connection` established.
#[allow(clippy::large_enum_variant)] // The common variant is the large one.
enum AuthOutcome {
    /// A flow ran to a terminal event, and this is the connection it left.
    Flowed(Connection),
    /// No flow was ever offered: the very first `authenticate_connection`
    /// answered `Unsupported`, carried here verbatim.
    ///
    /// That is usually the `Layer` leaf default, but not only — an alias
    /// layer refuses a credentialless visibility-override row the same way,
    /// and so does a remote service that has not implemented the RPC. Each
    /// explains itself better than any message this module could invent, so
    /// the error travels with the outcome instead of being discarded.
    NoFlowOffered(Error),
}

/// `NoFlowOffered` is a different fact from a flow that ran and then failed
/// with `Unsupported`, which `AuthEvent::Failed` and
/// `update_connection_credentials` can both raise. Only the first is a reason
/// to keep a connection the caller asked for; the second means the flow
/// genuinely failed, so it propagates like any other error.
async fn drive_authentication(
    state: &SessionState,
    key: ConnectionKey,
    cancel: &CancellationToken,
) -> ovstorage::Result<AuthOutcome> {
    let capability = ovstorage::auth::read_env_capability(&ovstorage::auth::StdEnv)
        .unwrap_or_else(|| ovstorage::auth::detect_default_capability(&ovstorage::auth::StdEnv));
    let mut stream = match ovstorage::Layer::authenticate_connection(
        state.stack.as_ref(),
        Request::new(AuthenticateRequest {
            key: key.clone(),
            capability,
            // The CLI opens the browser itself on the `OpenBrowser` event
            // (see below), so the backend must not auto-open it.
            auto_open_browser: false,
        }),
        Some(cancel.clone()),
    )
    .await
    {
        Ok(stream) => stream,
        Err(err) if err.code() == ErrorCode::Unsupported => {
            return Ok(AuthOutcome::NoFlowOffered(err));
        }
        Err(err) => return Err(err),
    };
    let mut final_connection: Option<Connection> = None;
    loop {
        match next_or_cancel(stream, cancel).await {
            Step::Event(returned, event) => {
                stream = returned;
                match event? {
                    AuthEvent::OpenBrowser { url, expires_at } => {
                        eprintln!();
                        eprintln!("Open this URL to authenticate:");
                        eprintln!("  {url}");
                        if let Some(message) = expires_message(expires_at) {
                            eprintln!("  ({message})");
                        }
                        let _ = webbrowser::open(&url);
                    }
                    AuthEvent::DeviceCode {
                        user_code,
                        verification_url,
                        expires_at,
                        ..
                    } => {
                        eprintln!();
                        eprintln!("Visit {verification_url} and enter code:");
                        eprintln!("  {user_code}");
                        if let Some(message) = expires_message(expires_at) {
                            eprintln!("  ({message})");
                        }
                    }
                    AuthEvent::Progress { message } => {
                        eprintln!("  {message}");
                    }
                    AuthEvent::Succeeded {
                        connection,
                        credentials,
                    } => {
                        // The OAuth/interactive flow surfaces tokens on
                        // `Succeeded`; the Layer forwards the event without
                        // installing it, so route the bundle to the backend via
                        // `update_connection_credentials` before finishing.
                        // Without this the connection stays unauthenticated and
                        // the next RPC runs with no tokens. `credentials: None`
                        // means the flow installed tokens itself (warm-continue)
                        // or uses static creds — nothing to apply.
                        final_connection = Some(match credentials {
                            Some(bundle) => {
                                ovstorage::Layer::update_connection_credentials(
                                    state.stack.as_ref(),
                                    Request::new(UpdateConnectionCredentialsRequest {
                                        key: key.clone(),
                                        credentials: bundle,
                                    }),
                                    Some(cancel.clone()),
                                )
                                .await?
                            }
                            None => *connection,
                        });
                    }
                    AuthEvent::Failed { error } => return Err(error),
                    AuthEvent::Cancelled => {
                        return Err(Error::new(ErrorCode::Cancelled, "authentication cancelled"));
                    }
                }
            }
            Step::Done(_) => break,
            Step::Cancelled => {
                return Err(Error::new(ErrorCode::Cancelled, "operation cancelled"));
            }
        }
    }
    final_connection.map(AuthOutcome::Flowed).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "authentication stream ended without a terminal event",
        )
    })
}

fn expires_message(expires_at: SystemTime) -> Option<String> {
    let remaining = expires_at.duration_since(SystemTime::now()).ok()?;
    let secs = remaining.as_secs();
    if secs == 0 {
        return None;
    }
    if secs >= 60 {
        Some(format!("expires in about {} minutes", secs / 60))
    } else {
        Some(format!("expires in {secs} seconds"))
    }
}

fn prompt_display_name() -> ovstorage::Result<Option<String>> {
    let value = Text::new("Display name (optional):")
        .with_help_message("Friendly label shown alongside this connection. Press Enter to skip.")
        .prompt_skippable()
        .map_err(map_inquire)?;
    Ok(value.and_then(non_empty_string))
}

fn print_success(connection: &Connection, display_name: Option<&str>) {
    println!();
    let label = display_name.filter(|s| !s.is_empty()).or({
        if connection.display_name.is_empty() {
            None
        } else {
            Some(connection.display_name.as_str())
        }
    });
    // A refused credential is still a registration — a backend records what
    // its probe learned rather than refusing the add — but it is not a
    // connection the operator can use, so it must not be announced as one.
    // Only a settled identity is announced as a connection. An unproven one
    // is registered and serves reads, but saying `Connected` over it is the
    // same over-claim as saying it over a refusal — the stderr note beneath
    // carries the detail, and the headline must not contradict it.
    let headline = match connection.auth_state {
        ConnectionAuthState::AuthFailed { .. } => "Registered, but not authenticated",
        ConnectionAuthState::AwaitingAuth { .. } => "Registered, credential unconfirmed",
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => "Connected",
    };
    match label {
        Some(name) => println!("{headline}: {name} ({}).", connection.id.0),
        None => println!("{headline} ({}).", connection.id.0),
    }
    // Say plainly when the identity is not settled, or a refused credential
    // reads as a clean success.
    match &connection.auth_state {
        ConnectionAuthState::AuthFailed { error, .. } => {
            eprintln!(
                "  warning: the backend refused these credentials: {}",
                error.message()
            );
        }
        ConnectionAuthState::AwaitingAuth { reason, .. } => {
            // Not a failure: the connection is registered and serves reads.
            // The credential simply was not established, so say why in the
            // backend's own words rather than printing the enum.
            let because = match reason {
                ovstorage::AuthReason::Unknown { details } => details.clone(),
                other => format!("{other:?}"),
            };
            eprintln!("  note: registered, but the credential was not confirmed ({because}).");
        }
        ConnectionAuthState::Anonymous | ConnectionAuthState::Authenticated { .. } => {}
    }
    if !connection.current_addresses.is_empty() {
        println!("Visible roots:");
        for addr in &connection.current_addresses {
            println!("  {addr}");
        }
    }
    println!();
    println!("Run `write-config <PATH>` to persist this connection to TOML.");
}

fn text_prompt(
    label: &str,
    field: &ConfigField,
    default: Option<String>,
) -> ovstorage::Result<String> {
    let mut prompt = Text::new(label);
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    if let Some(example) = &field.example {
        prompt = prompt.with_placeholder(example);
    }
    if let Some(d) = default.as_deref() {
        prompt = prompt.with_default(d);
    }
    prompt.prompt().map_err(map_inquire)
}

fn confirm_set_field(name: &str) -> ovstorage::Result<bool> {
    inquire::Confirm::new(&format!("Set optional field '{name}'?"))
        .with_default(false)
        .prompt()
        .map_err(map_inquire)
}

fn field_label(display_name: &str, required: bool) -> String {
    if required {
        format!("{display_name} *")
    } else {
        display_name.to_string()
    }
}

fn default_as_string(field: &ConfigField) -> Option<String> {
    match &field.default {
        Some(ConfigValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn non_empty_string(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

/// Required schema fields must be filled. The CLI's contract with
/// `descriptor.config_schema` is that `required = true` is honored before
/// the value reaches `add_connection`; otherwise the backend sees a
/// missing field and surfaces a less actionable error.
fn require_non_empty(field: &ConfigField, value: String) -> ovstorage::Result<Option<String>> {
    match (non_empty_string(value), field.required) {
        (Some(v), _) => Ok(Some(v)),
        (None, true) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is required", field.display_name),
        )),
        (None, false) => Ok(None),
    }
}

fn map_inquire(err: inquire::InquireError) -> Error {
    use inquire::InquireError::*;
    match err {
        OperationCanceled | OperationInterrupted => {
            Error::new(ErrorCode::Cancelled, "operation cancelled")
        }
        IO(io) => Error::new(ErrorCode::Internal, format!("input error: {io}")),
        InvalidConfiguration(msg) => Error::new(ErrorCode::InvalidArgument, msg),
        NotTTY => Error::new(
            ErrorCode::InvalidArgument,
            "interactive prompts require a terminal; run from a TTY",
        ),
        Custom(msg) => Error::new(ErrorCode::Internal, msg.to_string()),
    }
}

pub(crate) async fn list_routes(state: &SessionState) -> ovstorage::Result<()> {
    let stack = &state.stack;
    println!("prefix\tbackend\tvisibility");
    let roots = stack.list_address_roots(None).await?;
    for root in roots {
        println!("{}\t{}\t{:?}", root.root, root.layer_kind, root.visibility);
    }
    Ok(())
}

pub(crate) fn list_backends(state: &SessionState) -> ovstorage::Result<()> {
    let stack = &state.stack;
    println!("kind\tdisplay_name\truntime_add");
    for descriptor in stack.list_backend_kinds()? {
        println!(
            "{}\t{}\t{}",
            descriptor.kind, descriptor.display_name, descriptor.supports_runtime_add
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_unusable, resolve_backend_target};
    use ovstorage::{ErrorCode, LayerSpec, StackSpec};

    fn connection_with(
        auth_state: ovstorage::ConnectionAuthState,
        roots: &[&str],
    ) -> ovstorage::Connection {
        ovstorage::Connection {
            id: ovstorage::ConnectionId("c1".into()),
            backend_kind: "test".into(),
            display_name: "test".into(),
            source: ovstorage::ConnectionSource::Runtime { persisted: false },
            capabilities: ovstorage::Capabilities::empty(),
            current_addresses: roots
                .iter()
                .map(|r| ovstorage::address::parse(r).unwrap())
                .collect(),
            auth_state,
            last_probed: None,
            user_metadata: ovstorage::UserMetadata::new(),
        }
    }

    fn parked() -> ovstorage::ConnectionAuthState {
        ovstorage::ConnectionAuthState::AwaitingAuth {
            reason: ovstorage::AuthReason::NeverAuthenticated,
            last_attempt: None,
        }
    }

    /// The exit status turns on whether the connection can serve anything, not
    /// on whether its credential was confirmed. Both halves matter:
    ///
    /// - A parked connection that still publishes roots serves reads — the
    ///   cloud backends derive roots from config and publish them while parked
    ///   — so `connect` reports the state and exits 0.
    /// - A parked connection with no roots answers `NoRoute` to everything.
    ///   That is what a backend with no interactive flow leaves behind when its
    ///   credential is refused at bring-up, and exiting 0 over it tells a
    ///   script the opposite of what happened.
    #[test]
    fn only_a_parked_connection_with_no_roots_is_unusable() {
        assert!(
            is_unusable(&connection_with(parked(), &[])),
            "parked with no roots can serve nothing"
        );
        assert!(
            !is_unusable(&connection_with(parked(), &["azure://acct123/assets/"])),
            "parked but routable still serves reads"
        );
        assert!(
            !is_unusable(&connection_with(
                ovstorage::ConnectionAuthState::Anonymous,
                &[]
            )),
            "a settled connection is never unusable on this test, roots or not"
        );
        assert!(
            !is_unusable(&connection_with(
                ovstorage::ConnectionAuthState::Authenticated {
                    last_authenticated_at: std::time::SystemTime::now(),
                    expires_at: None,
                },
                &[],
            )),
            "an authenticated connection is settled"
        );
    }

    fn spec_with(layers: Vec<LayerSpec>) -> StackSpec {
        let mut spec = StackSpec::new("root");
        spec.layers = layers;
        spec
    }

    #[test]
    fn resolves_to_kind_when_backend_layer_is_named_after_its_kind() {
        // Default-stack convention: behavior is unchanged (target == kind).
        let spec = spec_with(vec![LayerSpec::backend("file", "file")]);
        assert_eq!(resolve_backend_target(&spec, "file").unwrap(), "file");
    }

    #[test]
    fn resolves_to_layer_name_when_named_differently_from_kind() {
        // Layer `s3_prod` of kind `s3` -> target is the Layer name.
        let spec = spec_with(vec![LayerSpec::backend("s3_prod", "s3")]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3_prod");
    }

    #[test]
    fn falls_back_to_kind_when_no_backend_layer_matches() {
        let spec = spec_with(vec![LayerSpec::backend("file", "file")]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3");
    }

    #[test]
    fn errors_when_several_backend_layers_match() {
        // Two backends of the same kind: the owning target is ambiguous, so the
        // kind cannot stand in for a real layer name. Resolution must reject the
        // ambiguity rather than synthesize `s3` (which names no layer and would
        // route `add_connection`/`authenticate_connection` at nothing).
        let spec = spec_with(vec![
            LayerSpec::backend("s3_a", "s3"),
            LayerSpec::backend("s3_b", "s3"),
        ]);
        let err = resolve_backend_target(&spec, "s3").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        // Both candidate layer names are surfaced so the operator can target one.
        assert!(err.message().contains("s3_a"));
        assert!(err.message().contains("s3_b"));
    }

    #[test]
    fn ignores_non_backend_layers_of_the_same_kind() {
        // A wrapper/router named like the kind must not be selected as target.
        let spec = spec_with(vec![
            LayerSpec::wrapper("s3", "s3", "s3_prod"),
            LayerSpec::backend("s3_prod", "s3"),
        ]);
        assert_eq!(resolve_backend_target(&spec, "s3").unwrap(), "s3_prod");
    }
}
