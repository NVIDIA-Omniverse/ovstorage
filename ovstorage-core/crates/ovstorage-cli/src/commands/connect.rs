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
use ovstorage::{
    AuthEvent, CancellationToken, ConfigField, ConfigFieldKind, ConfigValue, Connection,
    ConnectionId, CredentialField, CredentialMethod, EnumSource, Error, ErrorCode, Storage,
    StorageBackendKindDescriptor, config_value_to_toml,
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
    let descriptors = state.library.list_backend_kinds()?;
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

    let session_conn = SessionConnection {
        backend_kind: descriptor.kind.clone(),
        display_name: display_name.clone(),
        config: config_runtime
            .iter()
            .map(|(k, v)| (k.clone(), config_value_to_toml(v)))
            .collect(),
        credentials,
    };

    let request = session_conn.to_connection_request()?;
    let mut connection = state
        .library
        .add_connection(request, Some(cancel.clone()))
        .await?;

    // If authentication fails, drop the half-registered connection so the user can
    // retry `connect` (typically with a different credential method) without
    // hitting a route-prefix conflict.
    connection = match drive_authentication(state, &connection.id, cancel).await {
        Ok(c) => c,
        Err(err) => {
            let _ = state.library.remove_connection(&connection.id);
            return Err(err);
        }
    };

    state.connections.push(session_conn);
    print_success(&connection, display_name.as_deref());

    if state.interactive
        && state.pwd.is_none()
        && let [only] = connection.current_addresses.as_slice()
    {
        state.pwd = Some(only.clone());
        println!("(pwd set to {only})");
    }
    Ok(())
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
        if let Some(cred) = prompt_credential_field_required(field)? {
            out.insert(field.key.clone(), cred);
        }
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
fn prompt_credential_field_required(field: &CredentialField) -> ovstorage::Result<Option<String>> {
    let label = field_label(&field.display_name, true);
    let mut prompt = Password::new(&label)
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation();
    if let Some(help) = &field.help {
        prompt = prompt.with_help_message(help);
    }
    let value = prompt.prompt().map_err(map_inquire)?;
    let value = require_non_empty_secret(field, value)?;
    Ok(Some(value))
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
    let connections = state.library.list_connections()?;
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
    let connection = drive_authentication(state, &connection.id, cancel).await?;
    eprintln!("ok ({}).", connection.display_name);
    Ok(())
}

async fn drive_authentication(
    state: &SessionState,
    id: &ConnectionId,
    cancel: &CancellationToken,
) -> ovstorage::Result<Connection> {
    let mut stream = state
        .library
        .authenticate_connection(id, Some(cancel.clone()))
        .await?;
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
                    AuthEvent::Succeeded { connection, .. } => {
                        final_connection = Some(*connection);
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
    final_connection.ok_or_else(|| {
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
    match label {
        Some(name) => println!("Connected: {name} ({}).", connection.id.0),
        None => println!("Connected ({}).", connection.id.0),
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

fn require_non_empty_secret(field: &CredentialField, value: String) -> ovstorage::Result<String> {
    if value.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is required", field.display_name),
        ));
    }
    Ok(value)
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

pub(crate) fn list_routes(state: &SessionState) -> ovstorage::Result<()> {
    let lib = &state.library;
    println!("prefix\tbackend\tvisibility");
    for root in lib.list_address_roots()? {
        println!(
            "{}\t{}\t{:?}",
            root.address, root.backend_kind, root.visibility
        );
    }
    Ok(())
}

pub(crate) fn list_backends(state: &SessionState) -> ovstorage::Result<()> {
    let lib = &state.library;
    println!("kind\tdisplay_name\truntime_add");
    for descriptor in lib.list_backend_kinds()? {
        println!(
            "{}\t{}\t{}",
            descriptor.kind, descriptor.display_name, descriptor.supports_runtime_add
        );
    }
    Ok(())
}
