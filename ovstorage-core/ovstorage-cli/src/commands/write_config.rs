// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialize the running stack to a self-contained `[ovstorage]` TOML doc.
//!
//! The live layer graph (`state.stack.spec()`) becomes `[ovstorage.layers.*]`
//! tables and `SessionState.connections` (loaded + connect-pending, unified)
//! become `[[ovstorage.connections]]` entries, so the saved config runs
//! verbatim under any host. Each credential field becomes a plain string:
//!
//! - The value carries a `${IDENT}` reference the loader would substitute — it
//!   passes through verbatim, under any policy and whether or not a policy was
//!   supplied.
//! - Anything else is a literal, encoded per the `--secrets` policy
//!   (`plaintext` writes the value; `env` rewrites it as
//!   `${OVSTORAGE_<kind>_<slug>_<field>}` and tells the user which env vars
//!   to export).
//!
//! Provenance plays no part: a literal loaded from TOML is treated exactly
//! like one typed at `connect`, because the session records no origin for a
//! credential.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use clap::ValueEnum;
use ovstorage::{
    ConfigValue, ConnectionConfig, EMPTY_LAYER_KIND, Error, ErrorCode, LayerTable, StackConfig,
    StackSpec, config_value_to_toml, contains_env_ref,
};

use crate::session::{SessionConnection, SessionState};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum SecretsPolicy {
    /// Writes the literal value into the TOML; suitable for non-secret configs.
    Plaintext,
    /// Emit `${OVSTORAGE_...}` references; user must export the env vars before reusing the config.
    Env,
}

pub fn run(
    state: &SessionState,
    path: &Path,
    force: bool,
    secrets: Option<SecretsPolicy>,
) -> ovstorage::Result<()> {
    // Refuse to serialize the `EmptyLayer` fallback (the reserved `empty` root
    // that `host::build_stack` roots a stackless config at). Its spec emits
    // `root = "empty"` + `[ovstorage.layers.empty]`, which no host can reload
    // (`stack_config_to_spec` errors `unknown layer kind 'empty'`), so writing it
    // would produce an unloadable file. Detect the fallback by the root layer's
    // KIND, not its name: a legitimate graph may name a real-kind root layer
    // `empty` (e.g. `[ovstorage.layers.empty] kind = "file"`), and that must
    // remain write-config'able. Fail before touching the output path.
    let spec = state.stack.spec();
    let root_is_empty = spec
        .layers
        .iter()
        .find(|l| l.name == spec.root)
        .is_some_and(|l| l.kind == EMPTY_LAYER_KIND);
    if root_is_empty {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "cannot write-config an unconfigured (empty) stack; \
             supply a config that declares `[ovstorage.layers]` \
             (e.g. --config <file>, or copy the shipped ovstorage.toml; \
             see docs/public/configuration.md) and re-run",
        ));
    }

    let slugs = unique_slugs(&state.connections);

    if secrets.is_none() {
        let pending = pending_literal_fields(state);
        if !pending.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} literal credential(s) need a storage policy. \
                     Re-run with one of:\n  \
                     --secrets plaintext   (write the literal value into the TOML)\n  \
                     --secrets env         (export to env vars; ref in TOML)\n\
                     Affected fields: {}",
                    pending.len(),
                    pending.join(", ")
                ),
            ));
        }
    }

    let mut env_vars_to_export: Vec<String> = Vec::new();
    let mut emitted_plaintext = false;

    let mut connections = Vec::with_capacity(state.connections.len());
    for (idx, session_conn) in state.connections.iter().enumerate() {
        let slug = &slugs[idx];
        let mut credentials: HashMap<String, String> = HashMap::new();
        for (field, raw) in &session_conn.credentials {
            let value = plan_credential(
                raw,
                &session_conn.backend_kind,
                slug,
                field,
                secrets,
                &mut env_vars_to_export,
                &mut emitted_plaintext,
            );
            credentials.insert(field.clone(), value);
        }
        connections.push(ConnectionConfig {
            backend_kind: session_conn.backend_kind.clone(),
            // Preserve an explicit owning-layer target so a connection attached
            // to a renamed backend layer reloads against the right layer. Omit
            // it when it equals `backend_kind` (the build-time default), keeping
            // the common case terse.
            target: session_conn
                .target
                .clone()
                .filter(|t| *t != session_conn.backend_kind),
            display_name: session_conn.display_name.clone(),
            config: session_conn.config.clone(),
            credentials,
        });
    }

    // Emit the running stack made portable: the live layer graph from
    // `state.stack.spec()` plus the session connections, under `[ovstorage]`.
    let toml_str = spec_to_stack_config(state.stack.spec(), connections).to_toml_string()?;
    write_config_atomic(path, &toml_str, force, emitted_plaintext)?;

    println!("wrote {}", path.display());

    if !env_vars_to_export.is_empty() {
        eprintln!();
        eprintln!("Set these env vars before reusing this config:");
        for var in &env_vars_to_export {
            eprintln!("  export {var}=...");
        }
    }
    Ok(())
}

/// Convert the live [`StackSpec`] into a portable [`StackConfig`] — the running
/// stack graph made declarative, runnable verbatim under any host.
///
/// `kind` is omitted when it equals the layer name (the config default);
/// `inner`/`children` carry the structure; each layer config value is marshaled
/// back to TOML via [`config_value_to_toml`]. `connections` are passed through
/// (already credential-planned by the caller).
fn spec_to_stack_config(spec: &StackSpec, connections: Vec<ConnectionConfig>) -> StackConfig {
    let layers = spec
        .layers
        .iter()
        .map(|layer| {
            let table = LayerTable {
                kind: (layer.kind != layer.name).then(|| layer.kind.clone()),
                inner: layer.inner.clone(),
                children: layer.children.clone(),
                config: layer
                    .config
                    .iter()
                    .map(|(key, value)| (key.clone(), layer_config_value_to_toml(key, value)))
                    .collect(),
            };
            (layer.name.clone(), table)
        })
        .collect();
    StackConfig {
        root: Some(spec.root.clone()),
        layers,
        connections,
    }
}

/// Marshal one live layer-config value back to TOML for emit.
///
/// [`config_value_from_toml`](ovstorage::config_value_from_toml) wraps a nested
/// table/array config value under its own field key before storing it as a
/// [`ConfigValue::Toml`] fragment (so `toml::to_string` has a top-level table).
/// [`config_value_to_toml`] reparses that fragment but leaves the single-key
/// wrapper in place, so re-inserting it under the same field key would nest the
/// value twice (`aliases.aliases`) and fail to reload. Unwrap the wrapper here
/// so a nested layer-config value (e.g. an `alias` layer's `aliases` rules)
/// round-trips into the same shape it was authored in.
fn layer_config_value_to_toml(key: &str, value: &ConfigValue) -> toml::Value {
    let emitted = config_value_to_toml(value);
    if let toml::Value::Table(table) = &emitted
        && table.len() == 1
        && let Some(inner) = table.get(key)
    {
        return inner.clone();
    }
    emitted
}

/// Write `contents` to `path` with owner-only permissions on Unix.
///
/// Plaintext-config exposure is a real attack surface for a public-facing
/// gateway, so the path is opened with `O_CREAT|O_EXCL|0o600` and `rename`'d
/// into place. With `--force` we still create a fresh sibling file with
/// `0o600` and atomically replace the target rather than truncating it
/// in place, which would otherwise follow symlinks and preserve permissive
/// bits from the prior file.
fn write_config_atomic(
    path: &Path,
    contents: &str,
    force: bool,
    emitted_plaintext: bool,
) -> ovstorage::Result<()> {
    if !force && path.exists() {
        return Err(Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
        ));
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_dir = parent.unwrap_or_else(|| Path::new("."));
    let tmp_path = tmp_dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "ovstorage.toml".into()),
        std::process::id()
    ));

    let write_io = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    };

    if let Err(err) = write_io() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(Error::new(
            ErrorCode::Internal,
            format!("could not write {}: {err}", path.display()),
        ));
    }

    if emitted_plaintext {
        eprintln!(
            "warning: plaintext credentials were written to {} (mode 0600). Do NOT commit this file.",
            path.display()
        );
    }
    Ok(())
}

/// Map a session credential through the chosen `--secrets` policy.
/// A value carrying a `${IDENT}` reference the loader would substitute passes
/// through unchanged regardless of policy. Everything else is a literal and is
/// encoded per policy.
fn plan_credential(
    raw: &str,
    backend_kind: &str,
    slug: &str,
    field: &str,
    policy: Option<SecretsPolicy>,
    env_vars_to_export: &mut Vec<String>,
    emitted_plaintext: &mut bool,
) -> String {
    if looks_like_reference(raw) {
        return raw.to_string();
    }
    match policy.expect("policy required when literals exist") {
        SecretsPolicy::Plaintext => {
            *emitted_plaintext = true;
            raw.to_string()
        }
        SecretsPolicy::Env => {
            let var = env_var_name(backend_kind, slug, field);
            env_vars_to_export.push(var.clone());
            format!("${{{var}}}")
        }
    }
}

/// A credential counts as a reference only when it carries a `${IDENT}` the
/// loader would actually substitute. Deciding this by searching for `${` lets a
/// literal such as `secret${unterminated` take the reference path: no
/// `--secrets` demanded, no encoding applied, no plaintext warning, and the raw
/// value written into the TOML. The predicate is shared with the resolver so
/// the two cannot disagree about what a reference is.
fn looks_like_reference(raw: &str) -> bool {
    contains_env_ref(raw)
}

/// `<connection-slug>.<field>` for every literal credential in the
/// session. Gives the user a precise list when they forgot
/// `--secrets`.
fn pending_literal_fields(state: &SessionState) -> Vec<String> {
    let slugs = unique_slugs(&state.connections);
    let mut out = Vec::new();
    for (idx, conn) in state.connections.iter().enumerate() {
        let slug = &slugs[idx];
        for (field, raw) in &conn.credentials {
            if !looks_like_reference(raw) {
                out.push(format!("{slug}.{field}"));
            }
        }
    }
    out.sort();
    out
}

/// Compute one slug per connection, disambiguating duplicates of the
/// sanitized base by appending `-2`, `-3`, ... in connection order.
/// Slug stability matters: env-var names embed it, so two connections
/// that sanitize to the same base must NOT share a path.
pub(crate) fn unique_slugs(connections: &[SessionConnection]) -> Vec<String> {
    let mut out = Vec::with_capacity(connections.len());
    let mut used: HashSet<String> = HashSet::new();
    for (idx, conn) in connections.iter().enumerate() {
        let base = base_slug_for(conn, idx);
        let mut candidate = base.clone();
        let mut counter = 2u32;
        while used.contains(&candidate) {
            candidate = format!("{base}-{counter}");
            counter += 1;
        }
        used.insert(candidate.clone());
        out.push(candidate);
    }
    out
}

fn base_slug_for(conn: &SessionConnection, index: usize) -> String {
    if let Some(name) = &conn.display_name {
        let cleaned = sanitize(name);
        if !cleaned.is_empty() {
            return cleaned;
        }
    }
    format!("{}-{}", conn.backend_kind, index + 1)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn env_var_name(kind: &str, slug: &str, field: &str) -> String {
    format!("OVSTORAGE_{}_{}_{}", upper(kind), upper(slug), upper(field))
}

fn upper(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(kind: &str, display: Option<&str>) -> SessionConnection {
        SessionConnection {
            backend_kind: kind.into(),
            target: None,
            display_name: display.map(String::from),
            config: HashMap::new(),
            credentials: HashMap::new(),
        }
    }

    #[test]
    fn base_slug_uses_sanitized_display_name_when_present() {
        let c = conn("s3", Some("Prod Bucket #1"));
        assert_eq!(base_slug_for(&c, 0), "prod-bucket--1");
    }

    #[test]
    fn base_slug_falls_back_to_kind_plus_index() {
        let c = conn("s3", None);
        assert_eq!(base_slug_for(&c, 0), "s3-1");
        assert_eq!(base_slug_for(&c, 4), "s3-5");
    }

    #[test]
    fn env_var_name_uppercases_each_segment() {
        assert_eq!(
            env_var_name("s3", "prod-bucket", "aws_secret_access_key"),
            "OVSTORAGE_S3_PROD_BUCKET_AWS_SECRET_ACCESS_KEY"
        );
    }

    #[test]
    fn unique_slugs_disambiguates_identical_display_names() {
        let connections = vec![conn("s3", Some("Prod")), conn("s3", Some("Prod"))];
        let slugs = unique_slugs(&connections);
        assert_eq!(slugs, vec!["prod".to_string(), "prod-2".to_string()]);
    }

    #[test]
    fn unique_slugs_disambiguates_sanitized_collisions() {
        let connections = vec![
            conn("s3", Some("Prod!")),
            conn("s3", Some("Prod?")),
            conn("s3", Some("prod")),
        ];
        let slugs = unique_slugs(&connections);
        assert_eq!(
            slugs,
            vec![
                "prod".to_string(),
                "prod-2".to_string(),
                "prod-3".to_string()
            ]
        );
    }

    #[test]
    fn unique_slugs_fallback_does_not_collide_with_sanitized_match() {
        let connections = vec![conn("s3", Some("s3-2")), conn("s3", None)];
        let slugs = unique_slugs(&connections);
        assert_eq!(slugs, vec!["s3-2".to_string(), "s3-2-2".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn write_config_atomic_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ovstorage.toml");
        write_config_atomic(&path, "x = 1\n", false, false).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x = 1\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_config_atomic_force_replaces_permissive_file_with_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.toml");
        std::fs::write(&path, "old = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_config_atomic(&path, "new = 2\n", true, false).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 after --force, got {mode:o}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new = 2\n");
    }

    #[test]
    fn write_config_atomic_refuses_existing_file_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.toml");
        std::fs::write(&path, "old = 1\n").unwrap();
        let err = write_config_atomic(&path, "new = 2\n", false, false).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
    }

    /// End-to-end: build a session over a known stack, run `write-config`,
    /// then re-parse the emitted `[ovstorage]` doc and assert the live graph
    /// (`root` + each layer's `inner`/`children`) and the connections survive
    /// the round-trip — and that no legacy `[[routes]]`/`[state]` keys leak.
    #[tokio::test]
    async fn write_config_round_trips_the_live_stack() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_root = tmp.path().join("data");
        std::fs::create_dir_all(&backend_root).unwrap();
        let root_str = backend_root.to_string_lossy().replace('\\', "\\\\");

        // A known stack: alias -> router -> file backend, plus one connection.
        let toml = format!(
            r#"[ovstorage]
root = "alias"

[ovstorage.layers.alias]
inner = "router"

[ovstorage.layers.router]
children = ["file"]

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root_str}"
"#
        );
        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let live = stack.spec().clone();
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        run(&state, &out_path, false, None).unwrap();
        let emitted = std::fs::read_to_string(&out_path).unwrap();

        assert!(emitted.contains("[ovstorage]"), "missing [ovstorage] table");
        assert!(
            !emitted.contains("[[routes]]") && !emitted.contains("[state]"),
            "legacy keys leaked: {emitted}"
        );

        let reparsed = StackConfig::from_toml_str(&emitted).unwrap();

        // root matches.
        assert_eq!(reparsed.root.as_deref(), Some(live.root.as_str()));

        // Every live layer round-trips its name/inner/children.
        assert_eq!(reparsed.layers.len(), live.layers.len());
        for layer in &live.layers {
            let table = reparsed
                .layers
                .get(&layer.name)
                .unwrap_or_else(|| panic!("layer {} missing from output", layer.name));
            assert_eq!(
                table.inner, layer.inner,
                "inner mismatch for {}",
                layer.name
            );
            assert_eq!(
                table.children, layer.children,
                "children mismatch for {}",
                layer.name
            );
        }

        // Connections round-trip (backend_kind + config).
        assert_eq!(reparsed.connections.len(), state.connections.len());
        let conn = &reparsed.connections[0];
        assert_eq!(conn.backend_kind, "file");
        assert_eq!(
            conn.config.get("root").and_then(|v| v.as_str()),
            Some(backend_root.to_string_lossy().as_ref())
        );
    }

    /// A connection attached to a backend layer named differently from its
    /// kind (`prod` of kind `file`, `target = "prod"`) must round-trip its
    /// explicit `target`. Dropping it would default the reloaded target to
    /// `backend_kind` ("file"), which names no layer, so the emitted config
    /// would fail to rebuild.
    #[tokio::test]
    async fn write_config_round_trips_explicit_connection_target() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_root = tmp.path().join("data");
        std::fs::create_dir_all(&backend_root).unwrap();
        let root_str = backend_root.to_string_lossy().replace('\\', "\\\\");

        // Backend layer `prod` of kind `file`; the connection pins `target = "prod"`.
        let toml = format!(
            r#"[ovstorage]
root = "alias"

[ovstorage.layers.alias]
inner = "router"

[ovstorage.layers.router]
children = ["prod"]

[ovstorage.layers.prod]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"
target = "prod"

[ovstorage.connections.config]
root = "{root_str}"
"#
        );
        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();
        assert_eq!(
            state.connections[0].target.as_deref(),
            Some("prod"),
            "session must retain the loaded explicit target"
        );

        let out_path = tmp.path().join("out.toml");
        run(&state, &out_path, false, None).unwrap();
        let emitted = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            emitted.contains("target = \"prod\""),
            "explicit target must be emitted: {emitted}"
        );

        let reparsed = StackConfig::from_toml_str(&emitted).unwrap();
        assert_eq!(reparsed.connections[0].target.as_deref(), Some("prod"));
        // The emitted document must rebuild verbatim — proving the target names
        // a real layer rather than the defaulted, nonexistent `file`.
        ovstorage::host::build_stack(&reparsed, crate::commands::test_layer_factories())
            .await
            .expect("emitted config with explicit target must rebuild");
    }

    /// A layer whose config holds a nested array (the `alias` layer's `aliases`
    /// rules) must not double-nest on emit (`aliases.aliases`). The emitted
    /// config must rebuild and the alias rule must still resolve.
    #[tokio::test]
    async fn write_config_round_trips_nested_layer_config() {
        use ovstorage::ext::LayerExt;
        use ovstorage::{StackConfig, StatOptions, Url};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_dir = tmp.path().join("data");
        std::fs::create_dir_all(&backend_dir).unwrap();
        std::fs::write(backend_dir.join("hello.txt"), b"aliased").unwrap();
        let root = Url::from_directory_path(&backend_dir).unwrap();

        // An `alias` wrapper over `file`, rules authored as nested TOML.
        let toml = format!(
            r#"[ovstorage]
root = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "file"

[[ovstorage.layers.alias.aliases]]
from = "ov:///pub/"
to = "{root}"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
        );
        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        run(&state, &out_path, false, None).unwrap();
        let emitted = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            !emitted.contains("aliases.aliases"),
            "nested config double-nested on emit: {emitted}"
        );

        // The emitted config rebuilds and the alias rule still resolves onto the
        // physical target — proving the rules survived the round-trip intact.
        let reparsed = StackConfig::from_toml_str(&emitted).unwrap();
        let rebuilt =
            ovstorage::host::build_stack(&reparsed, crate::commands::test_layer_factories())
                .await
                .expect("emitted config with nested layer config must rebuild");
        let virt = Url::parse("ov:///pub/hello.txt").unwrap();
        let info = rebuilt
            .stat(virt, StatOptions::default(), None)
            .await
            .expect("alias rule must still resolve after round-trip");
        assert_eq!(info.size, Some(b"aliased".len() as u64));
    }

    /// `write-config` over an `EmptyLayer`-rooted stack (the no-config fallback)
    /// refuses with `NotConfigured` and writes no output file, rather than
    /// emitting a `root = "empty"` doc that fails to reload.
    #[tokio::test]
    async fn write_config_refuses_empty_stack_and_writes_no_file() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();

        // An empty StackConfig roots at `EmptyLayer` (`build_stack`'s fallback).
        let config = StackConfig::default();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        assert_eq!(stack.spec().root, "empty", "expected EmptyLayer fallback");
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        let err = run(&state, &out_path, false, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(
            !out_path.exists(),
            "no output file must be written for an empty stack"
        );
    }

    /// A legitimate graph whose root layer is *named* `empty` but is of a real
    /// kind (`kind = "file"`) must be write-config'able — the `EmptyLayer`
    /// fallback is detected by the root layer's KIND, not its name. The buggy
    /// name-only check (`spec().root == EMPTY_LAYER_KIND`) falsely refused this.
    #[tokio::test]
    async fn write_config_allows_stack_with_root_layer_named_empty() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_root = tmp.path().join("data");
        std::fs::create_dir_all(&backend_root).unwrap();
        let root_str = backend_root.to_string_lossy().replace('\\', "\\\\");

        // Root layer NAMED `empty` but of kind `file` — a real backend, not the
        // EmptyLayer fallback.
        let toml = format!(
            r#"[ovstorage]
root = "empty"

[ovstorage.layers.empty]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"
target = "empty"

[ovstorage.connections.config]
root = "{root_str}"
"#
        );
        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        assert_eq!(stack.spec().root, "empty", "root layer is named empty");
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        run(&state, &out_path, false, None)
            .expect("a real-kind root layer named `empty` must be write-config'able");
        assert!(out_path.exists(), "the config must have been written");
    }

    #[test]
    fn plan_credential_passes_through_reference_regardless_of_policy() {
        let mut env_vars = Vec::new();
        let mut emitted = false;
        let out = plan_credential(
            "${AWS_KEY}",
            "s3",
            "prod",
            "token",
            Some(SecretsPolicy::Env),
            &mut env_vars,
            &mut emitted,
        );
        assert_eq!(out, "${AWS_KEY}");
        assert!(env_vars.is_empty());
        assert!(!emitted);
    }

    #[test]
    fn plan_credential_env_policy_rewrites_literal() {
        let mut env_vars = Vec::new();
        let mut emitted = false;
        let out = plan_credential(
            "literal-secret",
            "s3",
            "prod",
            "token",
            Some(SecretsPolicy::Env),
            &mut env_vars,
            &mut emitted,
        );
        assert_eq!(out, "${OVSTORAGE_S3_PROD_TOKEN}");
        assert_eq!(env_vars, vec!["OVSTORAGE_S3_PROD_TOKEN"]);
        assert!(!emitted);
    }

    #[test]
    fn plan_credential_plaintext_policy_preserves_literal() {
        let mut env_vars = Vec::new();
        let mut emitted = false;
        let out = plan_credential(
            "literal-secret",
            "s3",
            "prod",
            "token",
            Some(SecretsPolicy::Plaintext),
            &mut env_vars,
            &mut emitted,
        );
        assert_eq!(out, "literal-secret");
        assert!(env_vars.is_empty());
        assert!(emitted);
    }

    /// A value containing `${` that is not a reference the loader would
    /// substitute is a LITERAL. Treating it as a reference hands a secret the
    /// pass-through path: no policy demanded, no encoding, no plaintext
    /// warning. Every case here must be encoded, not passed through.
    #[test]
    fn plan_credential_encodes_literals_that_merely_contain_dollar_brace() {
        for raw in [
            "secret${unterminated",
            "p${assw0rd",
            "${}",
            "${1BAD}",
            "${with-hyphen}",
            "$ {SPACED}",
            "${",
        ] {
            let mut env_vars = Vec::new();
            let mut emitted = false;
            let out = plan_credential(
                raw,
                "s3",
                "prod",
                "token",
                Some(SecretsPolicy::Env),
                &mut env_vars,
                &mut emitted,
            );
            assert_eq!(
                out, "${OVSTORAGE_S3_PROD_TOKEN}",
                "{raw:?} must be encoded as a literal, not passed through"
            );
            assert_eq!(env_vars, vec!["OVSTORAGE_S3_PROD_TOKEN"], "for {raw:?}");
            assert!(!emitted, "env policy emits no plaintext, for {raw:?}");

            // The plaintext arm is where these values must count as emitted
            // plaintext, because that is what raises the loud warning. Passing
            // them through would keep the value identical and skip the warning,
            // so asserting the value alone would not tell the two apart.
            let mut env_vars = Vec::new();
            let mut emitted = false;
            let out = plan_credential(
                raw,
                "s3",
                "prod",
                "token",
                Some(SecretsPolicy::Plaintext),
                &mut env_vars,
                &mut emitted,
            );
            assert_eq!(out, raw, "plaintext policy writes the literal, for {raw:?}");
            assert!(env_vars.is_empty(), "for {raw:?}");
            assert!(
                emitted,
                "{raw:?} is a literal: it must raise the plaintext warning"
            );
        }
    }

    /// The other half of the same gate: the forms the loader really does
    /// resolve must keep passing through untouched. A refusal that also
    /// refuses honest input has replaced a fail-open with a fail-closed and
    /// broken working configurations.
    #[test]
    fn plan_credential_still_passes_through_every_resolvable_reference_form() {
        for raw in [
            "${AWS_KEY}",
            "${_LEADING_UNDERSCORE}",
            "${MIXED_case_123}",
            // Embedded references are a supported form: `resolve_env_refs`
            // substitutes in place and keeps the surrounding text.
            "prefix-${VAR}-suffix",
            "${A}/${B}",
            "https://host/${BUCKET}/key",
        ] {
            for policy in [SecretsPolicy::Env, SecretsPolicy::Plaintext] {
                let mut env_vars = Vec::new();
                let mut emitted = false;
                let out = plan_credential(
                    raw,
                    "s3",
                    "prod",
                    "token",
                    Some(policy),
                    &mut env_vars,
                    &mut emitted,
                );
                assert_eq!(out, raw, "{raw:?} must pass through under {policy:?}");
                assert!(env_vars.is_empty(), "for {raw:?}");
                assert!(
                    !emitted,
                    "{raw:?} is a reference and must not count as emitted plaintext"
                );
            }
        }
    }

    /// End-to-end at the call site, not on the helper: a session credential
    /// that merely contains `${` must make `write-config` DEMAND `--secrets`.
    /// The helper being right proves nothing about `run`, which reaches the
    /// same predicate through `pending_literal_fields`.
    #[tokio::test]
    async fn run_demands_secrets_for_a_literal_that_merely_contains_dollar_brace() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_root = tmp.path().join("data");
        std::fs::create_dir_all(&backend_root).unwrap();
        let root_str = backend_root.to_string_lossy().replace('\\', "\\\\");

        let toml = format!(
            r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"
display_name = "leaky"

[ovstorage.connections.config]
root = "{root_str}"

[ovstorage.connections.credentials]
access_key = "secret${{unterminated"
"#
        );
        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        let err = run(&state, &out_path, false, None)
            .expect_err("a literal containing `${` must require a storage policy");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("leaky.access_key"),
            "the affected field must be named: {}",
            err.message()
        );
        assert!(
            !out_path.exists(),
            "no file may be written while a literal credential is unresolved"
        );

        // And under an explicit policy it is ENCODED, never emitted raw.
        run(&state, &out_path, false, Some(SecretsPolicy::Env)).unwrap();
        let emitted = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            !emitted.contains("secret${unterminated"),
            "the raw literal must not reach the TOML: {emitted}"
        );
        assert!(
            emitted.contains("${OVSTORAGE_FILE_LEAKY_ACCESS_KEY}"),
            "expected an env reference: {emitted}"
        );
    }

    /// The good-input half at the call site: a genuine reference, including an
    /// embedded one, still needs no `--secrets` and still round-trips whole.
    #[tokio::test]
    async fn run_passes_through_real_references_without_requiring_secrets() {
        use ovstorage::StackConfig;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let backend_root = tmp.path().join("data");
        std::fs::create_dir_all(&backend_root).unwrap();
        let root_str = backend_root.to_string_lossy().replace('\\', "\\\\");

        let toml = format!(
            r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"
display_name = "refs"

[ovstorage.connections.config]
root = "{root_str}"

[ovstorage.connections.credentials]
plain_ref = "${{OVSTORAGE_TEST_PLAIN_REF}}"
embedded = "prefix-${{OVSTORAGE_TEST_EMBEDDED}}-suffix"
"#
        );
        // `build_stack` resolves references, so the variables must exist for
        // the stack to build at all. That is the behaviour under test's
        // premise, not the behaviour under test.
        unsafe {
            std::env::set_var("OVSTORAGE_TEST_PLAIN_REF", "plain-value");
            std::env::set_var("OVSTORAGE_TEST_EMBEDDED", "embedded-value");
        }

        let config = StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&config, crate::commands::test_layer_factories())
            .await
            .unwrap();
        let state = SessionState::build(Arc::clone(&stack), config)
            .await
            .unwrap();

        let out_path = tmp.path().join("out.toml");
        run(&state, &out_path, false, None)
            .expect("references alone must not require a storage policy");
        let emitted = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            emitted.contains("${OVSTORAGE_TEST_PLAIN_REF}"),
            "plain reference must round-trip: {emitted}"
        );
        assert!(
            emitted.contains("prefix-${OVSTORAGE_TEST_EMBEDDED}-suffix"),
            "embedded reference must round-trip whole: {emitted}"
        );

        unsafe {
            std::env::remove_var("OVSTORAGE_TEST_PLAIN_REF");
            std::env::remove_var("OVSTORAGE_TEST_EMBEDDED");
        }
    }
}
