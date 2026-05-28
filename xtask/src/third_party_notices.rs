// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cargo registry dependency table for `THIRD_PARTY_NOTICES.md`.
//!
//! The "Cargo Registry Dependencies" section is generated from
//! `cargo metadata --locked` across every active workspace. This module
//! produces that section and either writes it back ([`regenerate`]) or
//! compares it to the on-disk file ([`verify_clean`]) so CI catches
//! dependency drift before release.
//!
//! Earlier sections of the notices file (top-level prose, Copied Source,
//! Vendored Service/API Material) are hand-maintained and left untouched.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

const NOTICES_FILE: &str = "THIRD_PARTY_NOTICES.md";
const SECTION_HEADING: &str = "## Cargo Registry Dependencies";

// (display name in the table, manifest path relative to repo root)
const WORKSPACES: &[(&str, &str)] = &[
    ("xtask", "xtask/Cargo.toml"),
    ("ovstorage-cloud", "ovstorage-cloud/Cargo.toml"),
    ("ovstorage-core", "ovstorage-core/Cargo.toml"),
    ("ovstorage-nucleus", "ovstorage-nucleus/Cargo.toml"),
    ("ovstorage-remote", "ovstorage-remote/Cargo.toml"),
    (
        "ovstorage-services-client",
        "ovstorage-services-client/Cargo.toml",
    ),
];

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    license: Option<String>,
    repository: Option<String>,
    source: Option<String>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct DepKey {
    name: String,
    version: String,
}

#[derive(Default)]
struct DepEntry {
    license: String,
    repository: String,
    workspaces: BTreeSet<String>,
}

pub(crate) fn regenerate() -> Result<()> {
    let root = crate::repo_root()?;
    let table = build_section(&root)?;
    let notices_path = root.join(NOTICES_FILE);
    let current = std::fs::read_to_string(&notices_path)
        .with_context(|| format!("read {}", notices_path.display()))?;
    let updated = replace_section(&current, SECTION_HEADING, &table)?;
    if current == updated {
        println!("{NOTICES_FILE}: already up to date");
        return Ok(());
    }
    std::fs::write(&notices_path, &updated)
        .with_context(|| format!("write {}", notices_path.display()))?;
    println!("regenerated `{SECTION_HEADING}` in {NOTICES_FILE}");
    Ok(())
}

pub(crate) fn verify_clean() -> Result<()> {
    let root = crate::repo_root()?;
    let table = build_section(&root)?;
    let notices_path = root.join(NOTICES_FILE);
    let current = std::fs::read_to_string(&notices_path)
        .with_context(|| format!("read {}", notices_path.display()))?;
    let updated = replace_section(&current, SECTION_HEADING, &table)?;
    if current != updated {
        anyhow::bail!("{NOTICES_FILE} is stale; run `cargo xtask regenerate-third-party-notices`",);
    }
    println!("verified {NOTICES_FILE} is up to date");
    Ok(())
}

fn build_section(root: &Path) -> Result<String> {
    let deps = collect_external_deps(root)?;
    Ok(format_section(&deps))
}

fn collect_external_deps(root: &Path) -> Result<BTreeMap<DepKey, DepEntry>> {
    let mut map: BTreeMap<DepKey, DepEntry> = BTreeMap::new();
    for (name, manifest) in WORKSPACES {
        let metadata = run_cargo_metadata(root, manifest)?;
        for pkg in metadata.packages {
            let source = match pkg.source.as_deref() {
                Some(s) => s,
                None => continue, // workspace member (path source)
            };
            if !source.starts_with("registry+") {
                continue; // skip git/other; future-proof if any are added
            }
            let key = DepKey {
                name: pkg.name,
                version: pkg.version,
            };
            let entry = map.entry(key).or_default();
            entry.license = pkg.license.unwrap_or_default();
            entry.repository = pkg.repository.unwrap_or_default();
            entry.workspaces.insert((*name).to_string());
        }
    }
    Ok(map)
}

fn run_cargo_metadata(root: &Path, manifest: &str) -> Result<Metadata> {
    let manifest_path = root.join(manifest);
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--locked")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .context("invoke cargo metadata")?;
    if !output.status.success() {
        anyhow::bail!(
            "cargo metadata failed for {}: {}",
            manifest_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse cargo metadata for {}", manifest_path.display()))
}

fn format_section(deps: &BTreeMap<DepKey, DepEntry>) -> String {
    let mut out = String::new();
    out.push_str(SECTION_HEADING);
    out.push_str("\n\n");
    out.push_str("| Crate | Version | License expression | Workspaces | Repository |\n");
    out.push_str("|---|---:|---|---|---|\n");
    for (key, entry) in deps {
        let ws_list = entry
            .workspaces
            .iter()
            .map(|w| format!("`{w}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let repo = if entry.repository.is_empty() {
            "—".to_string()
        } else {
            format!("[{}]({})", entry.repository, entry.repository)
        };
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {} | {} |\n",
            key.name, key.version, entry.license, ws_list, repo
        ));
    }
    out
}

fn replace_section(content: &str, heading: &str, new_section: &str) -> Result<String> {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim_end() == heading)
        .ok_or_else(|| anyhow::anyhow!("heading `{heading}` not found in {NOTICES_FILE}"))?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.starts_with("## "))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let mut result = String::new();
    for line in &lines[..start] {
        result.push_str(line);
        result.push('\n');
    }
    result.push_str(new_section);
    if !new_section.ends_with('\n') {
        result.push('\n');
    }
    for line in &lines[end..] {
        result.push_str(line);
        result.push('\n');
    }
    if !content.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_section_replaces_target_only() {
        let content = "# Top\n\n## Keep\n\nA\n\n## Cargo Registry Dependencies\n\nold table\n\n## After\n\nB\n";
        let new = "## Cargo Registry Dependencies\n\nnew table\n";
        let updated = replace_section(content, "## Cargo Registry Dependencies", new).unwrap();
        assert!(updated.contains("## Keep"));
        assert!(updated.contains("new table"));
        assert!(!updated.contains("old table"));
        assert!(updated.contains("## After"));
        assert!(updated.contains("\nB\n"));
    }

    #[test]
    fn replace_section_handles_eof_terminator() {
        let content = "# Top\n\n## Cargo Registry Dependencies\n\nold\n";
        let new = "## Cargo Registry Dependencies\n\nnew\n";
        let updated = replace_section(content, "## Cargo Registry Dependencies", new).unwrap();
        assert!(updated.contains("new"));
        assert!(!updated.contains("old"));
    }

    #[test]
    fn replace_section_errors_when_heading_missing() {
        let content = "# Top\n";
        let err = replace_section(content, "## Cargo Registry Dependencies", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"));
    }

    #[test]
    fn format_section_emits_sorted_table() {
        let mut deps = BTreeMap::new();
        deps.insert(
            DepKey {
                name: "b".into(),
                version: "1.0.0".into(),
            },
            DepEntry {
                license: "MIT".into(),
                repository: "https://example.test/b".into(),
                workspaces: BTreeSet::from(["x".to_string()]),
            },
        );
        deps.insert(
            DepKey {
                name: "a".into(),
                version: "1.0.0".into(),
            },
            DepEntry {
                license: "Apache-2.0".into(),
                repository: "https://example.test/a".into(),
                workspaces: BTreeSet::from(["y".to_string()]),
            },
        );
        let table = format_section(&deps);
        let a_pos = table.find("| `a` |").unwrap();
        let b_pos = table.find("| `b` |").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn format_section_uses_dash_for_missing_repository() {
        let mut deps = BTreeMap::new();
        deps.insert(
            DepKey {
                name: "x".into(),
                version: "1.0.0".into(),
            },
            DepEntry {
                license: "MIT".into(),
                repository: String::new(),
                workspaces: BTreeSet::from(["w".to_string()]),
            },
        );
        let table = format_section(&deps);
        assert!(table.contains("| `x` | 1.0.0 | `MIT` | `w` | — |"));
    }

    #[test]
    fn format_section_joins_workspaces_alphabetically() {
        let mut deps = BTreeMap::new();
        deps.insert(
            DepKey {
                name: "x".into(),
                version: "1.0.0".into(),
            },
            DepEntry {
                license: "MIT".into(),
                repository: "https://example.test/x".into(),
                workspaces: BTreeSet::from(["c".to_string(), "a".to_string(), "b".to_string()]),
            },
        );
        let table = format_section(&deps);
        assert!(table.contains("`a`, `b`, `c`"));
    }
}
