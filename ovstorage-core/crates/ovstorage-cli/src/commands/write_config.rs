// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialize the active library config to TOML.
//!
//! Iterates `SessionState.connections` (loaded + connect-pending, unified) and
//! emits one TOML `[[connections]]` block per entry. Each credential field
//! becomes a plain string:
//!
//! - The raw value pre-existed in the loaded TOML or was already a `${NAME}`
//!   reference — it passes through verbatim.
//! - The user typed a literal plaintext at `connect` — encoded per the
//!   `--secrets` policy (`plaintext` writes the value; `env` rewrites it as
//!   `${OVSTORAGE_<kind>_<slug>_<field>}` and tells the user which env vars
//!   to export).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use clap::ValueEnum;
use ovstorage::{ConnectionConfig, Error, ErrorCode, LibraryConfig};

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
            display_name: session_conn.display_name.clone(),
            config: session_conn.config.clone(),
            credentials,
        });
    }

    let output = LibraryConfig {
        state: state.state_config.clone(),
        routes: state.routes.clone(),
        connections,
        metadata_cache: None,
    };
    let toml_str = output.to_toml_string()?;
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
/// References (anything containing `${...}`) pass through unchanged
/// regardless of policy. Literal values are encoded per policy.
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

fn looks_like_reference(raw: &str) -> bool {
    raw.contains("${")
}

/// `<connection-slug>.<field>` for every literal credential in the
/// session. Used to give the user a precise list when they forgot
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
}
