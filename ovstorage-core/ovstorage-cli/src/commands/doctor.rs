// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Aggregate Stack diagnostic state for operators and agents.

use std::sync::Arc;

use ovstorage::ext::LayerExt;
use ovstorage::{ConfigValue, ConnectionAuthState, Error, ErrorCode, Stack, redact_message};
use serde::{Deserialize, Serialize};

const OPERATION: &str = "doctor";

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ovstorage_version: String,
    pub backend_kinds: Vec<BackendKindEntry>,
    pub connections: Vec<ConnectionEntry>,
    pub address_roots: Vec<AddressRootEntry>,
    pub aliases: Vec<AliasEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendKindEntry {
    pub kind: String,
    pub display_name: String,
    pub description: Option<String>,
    pub supports_runtime_add: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEntry {
    pub id: String,
    pub backend_kind: String,
    pub display_name: String,
    pub addresses: Vec<String>,
    pub auth_state_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddressRootEntry {
    pub address: String,
    pub backend_kind: String,
    pub display_name: Option<String>,
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasEntry {
    pub id: String,
    pub from: String,
    pub to: String,
    pub visibility: String,
}

pub async fn run(stack: Arc<Stack>, json: bool) -> ovstorage::Result<()> {
    let report = gather(stack.as_ref()).await?;
    if json {
        emit_json(&report)?;
    } else {
        emit_human(&report);
    }
    Ok(())
}

pub async fn gather(stack: &Stack) -> ovstorage::Result<DoctorReport> {
    Ok(DoctorReport {
        ovstorage_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_kinds: gather_backend_kinds(stack)?,
        connections: gather_connections(stack).await?,
        address_roots: gather_address_roots(stack).await?,
        aliases: gather_aliases(stack)?,
    })
}

pub fn gather_backend_kinds(stack: &Stack) -> ovstorage::Result<Vec<BackendKindEntry>> {
    Ok(stack
        .list_backend_kinds()?
        .into_iter()
        .map(|d| BackendKindEntry {
            kind: redact_message(&d.kind).into_owned(),
            display_name: redact_message(&d.display_name).into_owned(),
            description: d.description.map(|s| redact_message(&s).into_owned()),
            supports_runtime_add: d.supports_runtime_add,
        })
        .collect())
}

pub async fn gather_connections(stack: &Stack) -> ovstorage::Result<Vec<ConnectionEntry>> {
    let connections = stack.list_connections(None).await?;
    Ok(connections
        .into_iter()
        .map(|c| ConnectionEntry {
            id: c.id.0,
            backend_kind: redact_message(&c.backend_kind).into_owned(),
            display_name: redact_message(&c.display_name).into_owned(),
            addresses: c
                .current_addresses
                .into_iter()
                .map(|u| redact_message(u.as_str()).into_owned())
                .collect(),
            auth_state_kind: auth_state_kind(&c.auth_state).to_string(),
        })
        .collect())
}

pub async fn gather_address_roots(stack: &Stack) -> ovstorage::Result<Vec<AddressRootEntry>> {
    let roots = stack.list_address_roots(None).await?;
    Ok(roots
        .into_iter()
        .map(|r| AddressRootEntry {
            address: redact_message(r.root.as_str()).into_owned(),
            backend_kind: redact_message(&r.layer_kind).into_owned(),
            display_name: r.display_name.map(|s| redact_message(&s).into_owned()),
            visibility: format!("{:?}", r.visibility),
        })
        .collect())
}

/// Surface the operator-declared alias rewrite rules the stack was built with.
///
/// Post-O the `alias` layer's rules are config-declarable
/// (`[[ovstorage.layers.<name>.aliases]] from=… to=…`), so an empty list would
/// hide exactly the rewrite rules that explain why addresses resolve the way
/// they do. There is no runtime alias-introspection slot on the `Layer` API, so
/// the rules are read back from the built stack's spec — the same
/// `ConfigValue::Toml` fragment the alias factory parses. Each rule's reported
/// visibility is the longest-prefix match over the layer's `visibility`
/// overrides applied to its `from` prefix (default `Visible`), mirroring how the
/// alias layer advertises its synthesized roots.
pub fn gather_aliases(stack: &Stack) -> ovstorage::Result<Vec<AliasEntry>> {
    let mut entries = Vec::new();
    for layer in stack
        .spec()
        .layers
        .iter()
        .filter(|l| l.kind == ovstorage::layers::ALIAS_KIND)
    {
        let rules = parse_toml_config::<AliasRuleSet>(layer.config.get("aliases"))?;
        let visibility = parse_toml_config::<VisibilityRuleSet>(layer.config.get("visibility"))?;
        for (index, rule) in rules.aliases.into_iter().enumerate() {
            let vis = visibility_for(&rule.from, &visibility.visibility);
            entries.push(AliasEntry {
                id: format!("{}[{}]", layer.name, index),
                from: redact_message(&rule.from).into_owned(),
                to: redact_message(&rule.to).into_owned(),
                visibility: vis,
            });
        }
    }
    Ok(entries)
}

#[derive(Default, Deserialize)]
struct AliasRuleSet {
    #[serde(default, alias = "rule")]
    aliases: Vec<AliasRuleToml>,
}

#[derive(Deserialize)]
struct AliasRuleToml {
    from: String,
    to: String,
}

#[derive(Default, Deserialize)]
struct VisibilityRuleSet {
    #[serde(default, alias = "entry")]
    visibility: Vec<VisibilityRuleToml>,
}

#[derive(Deserialize)]
struct VisibilityRuleToml {
    address: String,
    visibility: String,
}

/// Parse an alias-layer `ConfigValue::Toml` config fragment into `T`. Absent or
/// non-Toml config yields the default (empty rule set) so a partially-configured
/// alias layer still reports whatever rules it does declare.
fn parse_toml_config<T: Default + serde::de::DeserializeOwned>(
    value: Option<&ConfigValue>,
) -> ovstorage::Result<T> {
    match value {
        Some(ConfigValue::Toml(text)) => toml::from_str(text).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("alias layer config could not be parsed: {err}"),
            )
        }),
        _ => Ok(T::default()),
    }
}

/// Longest-prefix visibility override covering `from` (default `Visible`).
fn visibility_for(from: &str, rules: &[VisibilityRuleToml]) -> String {
    let Ok(from_url) = ovstorage::address::parse(from) else {
        return "Visible".to_string();
    };
    let matched = rules
        .iter()
        .filter_map(|rule| {
            let prefix = ovstorage::address::parse(&rule.address).ok()?;
            ovstorage::address::is_ancestor_or_self(&prefix, &from_url)
                .then(|| (prefix.as_str().len(), rule.visibility.as_str()))
        })
        .max_by_key(|(len, _)| *len);
    match matched {
        Some((_, vis)) => normalize_visibility(vis),
        None => "Visible".to_string(),
    }
}

/// Render a snake_case config visibility value in the same casing the rest of
/// the doctor report uses for `AddressVisibility` (`Visible`/`Hidden`/
/// `Suppressed`), passing anything unrecognized through verbatim.
fn normalize_visibility(value: &str) -> String {
    match value {
        "visible" => "Visible".to_string(),
        "hidden" => "Hidden".to_string(),
        "suppressed" => "Suppressed".to_string(),
        other => other.to_string(),
    }
}

fn auth_state_kind(auth_state: &ConnectionAuthState) -> &'static str {
    match auth_state {
        ConnectionAuthState::Authenticated { .. } => "Authenticated",
        ConnectionAuthState::AwaitingAuth { .. } => "AwaitingAuth",
        ConnectionAuthState::AuthFailed { .. } => "AuthFailed",
        ConnectionAuthState::Anonymous => "Anonymous",
    }
}

fn emit_human(r: &DoctorReport) {
    println!("ovstorage doctor");
    println!("================");
    println!("Version: {}", r.ovstorage_version);
    println!();

    println!("Backend kinds loaded: {}", r.backend_kinds.len());
    for k in &r.backend_kinds {
        println!("  - {} ({})", k.display_name, k.kind);
        if let Some(desc) = &k.description {
            println!("    {desc}");
        }
    }
    println!();

    println!("Connections: {}", r.connections.len());
    for c in &r.connections {
        println!("  - {} [{}]", c.display_name, c.backend_kind);
        println!("    id={} auth={}", c.id, c.auth_state_kind);
        for a in &c.addresses {
            println!("    addr={a}");
        }
    }
    println!();

    println!("Address roots: {}", r.address_roots.len());
    for a in &r.address_roots {
        let name = a.display_name.as_deref().unwrap_or("(unnamed)");
        println!(
            "  - {} ({}) [{}] visibility={}",
            a.address, a.backend_kind, name, a.visibility
        );
    }
    println!();

    println!("Aliases: {}", r.aliases.len());
    for al in &r.aliases {
        println!(
            "  - {} -> {} (id={} visibility={})",
            al.from, al.to, al.id, al.visibility
        );
    }
}

fn emit_json(r: &DoctorReport) -> ovstorage::Result<()> {
    let env = ovstorage_envelope::Envelope::ok(OPERATION, r);
    let text = serde_json::to_string_pretty(&env).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("envelope serialization failed: {err}"),
        )
    })?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stack built from operator-declared `[[ovstorage.layers.alias.aliases]]`
    /// rules surfaces them through `gather_aliases` (regression for the
    /// always-empty stub, which hid config-declared rewrite rules).
    #[tokio::test]
    async fn gather_aliases_surfaces_operator_declared_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ovstorage::Url::from_directory_path(tmp.path()).unwrap();
        let toml = format!(
            r#"
[ovstorage]
root = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "file"

[[ovstorage.layers.alias.aliases]]
from = "ov:///pub/"
to = "{root}"

[[ovstorage.layers.alias.visibility]]
address = "{root}"
visibility = "suppressed"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
        );
        let cfg = ovstorage::StackConfig::from_toml_str(&toml).unwrap();
        let factories = vec![ovstorage::LoadedLayerFactory::Wrapper(std::sync::Arc::new(
            ovstorage_plugin_core::AliasWrapperFactory::default(),
        ))];
        let stack = ovstorage::host::build_stack(&cfg, factories).await.unwrap();

        let aliases = gather_aliases(&stack).unwrap();
        assert_eq!(
            aliases.len(),
            1,
            "expected the one declared rule: {aliases:?}"
        );
        assert_eq!(aliases[0].from, "ov:///pub/");
        assert!(
            aliases[0].to.starts_with("file:"),
            "rewrite target should be the physical root: {}",
            aliases[0].to
        );
        // The suppressed override targets the physical `to`, which does not
        // prefix the virtual `from`, so the advertised alias root is Visible.
        assert_eq!(aliases[0].visibility, "Visible");
    }

    #[test]
    fn visibility_for_uses_longest_prefix_match() {
        let rules = vec![
            VisibilityRuleToml {
                address: "ov:///a/".into(),
                visibility: "hidden".into(),
            },
            VisibilityRuleToml {
                address: "ov:///a/b/".into(),
                visibility: "suppressed".into(),
            },
        ];
        assert_eq!(visibility_for("ov:///a/b/c/", &rules), "Suppressed");
        assert_eq!(visibility_for("ov:///a/x/", &rules), "Hidden");
        assert_eq!(visibility_for("ov:///z/", &rules), "Visible");
    }
}
