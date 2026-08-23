// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Layering lint for ovstorage plugin crates.
//!
//! Walks every `ovstorage-plugin-*/Cargo.toml` under each configured root
//! (excluding the ABI crates themselves) and verifies that each
//! `ovstorage-`-prefixed key in
//! `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and
//! every `[target.<cfg>.<table>]` permutation appears in the matching
//! allowlist. The intent is to keep plugin crates layered on top of
//! `ovstorage-plugin` only, with a permissive starting allowlist that
//! tightens as plugins migrate.
//!
//! The lint is root-configured: `tools/check-plugin-deps/roots.toml` lists
//! the active first-party workspace directories, may extend the base
//! allowlist per root, and may grant per-crate `exceptions` when a single
//! crate needs a dependency that must stay forbidden for every other
//! plugin under the root.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const ABI_LAYER_CRATES: &[&str] = &["ovstorage-plugin", "ovstorage-plugin-macros"];

#[derive(Clone, Debug)]
pub struct AllowList {
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    pub build_dependencies: Vec<String>,
    /// Per-crate escape hatch: crate name -> extra dependency names allowed
    /// for that crate only (in any dependency table). Crates not listed here
    /// are unaffected.
    pub exceptions: BTreeMap<String, Vec<String>>,
}

impl AllowList {
    pub fn permissive_starting() -> Self {
        Self {
            dependencies: vec!["ovstorage-plugin".into()],
            dev_dependencies: vec!["ovstorage".into(), "ovstorage-cache".into()],
            build_dependencies: Vec::new(),
            exceptions: BTreeMap::new(),
        }
    }

    fn extended(
        &self,
        extra_deps: &[String],
        extra_dev_deps: &[String],
        extra_build_deps: &[String],
        exceptions: &BTreeMap<String, Vec<String>>,
    ) -> Self {
        let mut out = self.clone();
        out.dependencies.extend(extra_deps.iter().cloned());
        out.dev_dependencies.extend(extra_dev_deps.iter().cloned());
        out.build_dependencies
            .extend(extra_build_deps.iter().cloned());
        for (crate_name, deps) in exceptions {
            out.exceptions
                .entry(crate_name.clone())
                .or_default()
                .extend(deps.iter().cloned());
        }
        out
    }

    fn is_excepted(&self, crate_name: &str, dep_name: &str) -> bool {
        self.exceptions
            .get(crate_name)
            .is_some_and(|deps| deps.iter().any(|allowed| allowed == dep_name))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub crate_name: String,
    pub manifest_path: PathBuf,
    pub table: DependencyTable,
    pub table_label: String,
    pub offending_dep: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyTable {
    Dependencies,
    DevDependencies,
    BuildDependencies,
    Manifest,
}

#[derive(Clone, Debug)]
pub struct Root {
    pub label: String,
    pub crates_dir: PathBuf,
    pub extra_dependencies: Vec<String>,
    pub extra_dev_dependencies: Vec<String>,
    pub extra_build_dependencies: Vec<String>,
    pub exceptions: BTreeMap<String, Vec<String>>,
}

impl Root {
    pub fn allowlist(&self, base: &AllowList) -> AllowList {
        base.extended(
            &self.extra_dependencies,
            &self.extra_dev_dependencies,
            &self.extra_build_dependencies,
            &self.exceptions,
        )
    }
}

pub fn locate_crates_dir(start: &Path) -> Option<PathBuf> {
    let mut cursor = Some(start);
    while let Some(dir) = cursor {
        let candidate = dir.join("crates");
        if candidate.is_dir() {
            return Some(candidate);
        }
        cursor = dir.parent();
    }
    None
}

pub fn load_roots(roots_toml: &Path, base_dir: &Path) -> io::Result<Vec<Root>> {
    let raw = fs::read_to_string(roots_toml)?;
    let value: toml::Value = raw.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {}: {error}", roots_toml.display()),
        )
    })?;
    let entries = value
        .get("roots")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} missing [[roots]] array", roots_toml.display()),
            )
        })?;
    let mut roots = Vec::with_capacity(entries.len());
    for entry in entries {
        let table = entry.as_table().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: [[roots]] entry is not a table", roots_toml.display()),
            )
        })?;
        let label = table
            .get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: [[roots]] entry missing label", roots_toml.display()),
                )
            })?
            .to_string();
        let path_str = table.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: [[roots]] entry {label} missing path",
                    roots_toml.display()
                ),
            )
        })?;
        let crates_dir = base_dir.join(path_str);
        let crates_dir = match crates_dir.canonicalize() {
            Ok(path) => path,
            Err(_) => crates_dir,
        };
        let extra_dependencies = string_array(table, "extra_dependencies");
        let extra_dev_dependencies = string_array(table, "extra_dev_dependencies");
        let extra_build_dependencies = string_array(table, "extra_build_dependencies");
        let exceptions = exceptions_table(table, roots_toml, &label)?;
        roots.push(Root {
            label,
            crates_dir,
            extra_dependencies,
            extra_dev_dependencies,
            extra_build_dependencies,
            exceptions,
        });
    }
    Ok(roots)
}

fn exceptions_table(
    table: &toml::value::Table,
    roots_toml: &Path,
    label: &str,
) -> io::Result<BTreeMap<String, Vec<String>>> {
    let Some(value) = table.get("exceptions") else {
        return Ok(BTreeMap::new());
    };
    let exceptions = value.as_table().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: [[roots]] entry {label} has a non-table exceptions value",
                roots_toml.display()
            ),
        )
    })?;
    let mut out = BTreeMap::new();
    for (crate_name, deps) in exceptions {
        let deps = deps
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "{}: [[roots]] entry {label} exceptions.{crate_name} contains a non-string dependency",
                                    roots_toml.display()
                                ),
                            )
                        })
                    })
                    .collect::<io::Result<Vec<String>>>()
            })
            .unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: [[roots]] entry {label} exceptions.{crate_name} is not an array",
                        roots_toml.display()
                    ),
                ))
            })?;
        out.insert(crate_name.clone(), deps);
    }
    Ok(out)
}

fn string_array(table: &toml::value::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn lint_crates_dir(crates_dir: &Path, allowlist: &AllowList) -> io::Result<Vec<Violation>> {
    let (violations, _) = lint_crates_dir_with_visited(crates_dir, allowlist)?;
    Ok(violations)
}

pub fn lint_crates_dir_with_visited(
    crates_dir: &Path,
    allowlist: &AllowList,
) -> io::Result<(Vec<Violation>, Vec<String>)> {
    let mut violations = Vec::new();
    let mut visited = Vec::new();
    let entries = fs::read_dir(crates_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(crate_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !crate_name.starts_with("ovstorage-plugin-") {
            continue;
        }
        if ABI_LAYER_CRATES.contains(&crate_name) {
            continue;
        }
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        visited.push(crate_name.to_string());
        violations.extend(lint_manifest(&manifest_path, allowlist));
    }
    violations.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then_with(|| left.table_label.cmp(&right.table_label))
            .then_with(|| left.offending_dep.cmp(&right.offending_dep))
    });
    visited.sort();
    Ok((violations, visited))
}

struct TableSpec<'a> {
    key: &'a str,
    id: DependencyTable,
    allowed: &'a [String],
}

fn dependency_table_specs<'a>(allowlist: &'a AllowList) -> [TableSpec<'a>; 3] {
    [
        TableSpec {
            key: "dependencies",
            id: DependencyTable::Dependencies,
            allowed: &allowlist.dependencies,
        },
        TableSpec {
            key: "dev-dependencies",
            id: DependencyTable::DevDependencies,
            allowed: &allowlist.dev_dependencies,
        },
        TableSpec {
            key: "build-dependencies",
            id: DependencyTable::BuildDependencies,
            allowed: &allowlist.build_dependencies,
        },
    ]
}

fn lint_manifest(manifest_path: &Path, allowlist: &AllowList) -> Vec<Violation> {
    let mut violations = Vec::new();
    let raw = match fs::read_to_string(manifest_path) {
        Ok(raw) => raw,
        Err(error) => {
            violations.push(Violation {
                crate_name: crate_name_for(manifest_path),
                manifest_path: manifest_path.to_path_buf(),
                table: DependencyTable::Manifest,
                table_label: "Cargo.toml".into(),
                offending_dep: format!("<unreadable: {error}>"),
            });
            return violations;
        }
    };
    let value: toml::Value = match raw.parse() {
        Ok(value) => value,
        Err(error) => {
            violations.push(Violation {
                crate_name: crate_name_for(manifest_path),
                manifest_path: manifest_path.to_path_buf(),
                table: DependencyTable::Manifest,
                table_label: "Cargo.toml".into(),
                offending_dep: format!("<unparseable: {error}>"),
            });
            return violations;
        }
    };
    let crate_name = value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate_name_for(manifest_path));
    let specs = dependency_table_specs(allowlist);
    for spec in &specs {
        if let Some(table) = value.get(spec.key).and_then(|v| v.as_table()) {
            let label = format!("[{}]", spec.key);
            scan_table(
                table,
                &crate_name,
                manifest_path,
                spec.id,
                &label,
                spec.allowed,
                allowlist,
                &mut violations,
            );
        }
    }
    if let Some(target_table) = value.get("target").and_then(|v| v.as_table()) {
        for (cfg, cfg_value) in target_table {
            let Some(cfg_table) = cfg_value.as_table() else {
                continue;
            };
            let cfg_label = if cfg.starts_with('\'') || cfg.starts_with('"') {
                cfg.to_string()
            } else if cfg.starts_with("cfg(") {
                format!("'{cfg}'")
            } else {
                cfg.to_string()
            };
            for spec in &specs {
                let Some(table) = cfg_table.get(spec.key).and_then(|v| v.as_table()) else {
                    continue;
                };
                let label = format!("[target.{cfg_label}.{}]", spec.key);
                scan_table(
                    table,
                    &crate_name,
                    manifest_path,
                    spec.id,
                    &label,
                    spec.allowed,
                    allowlist,
                    &mut violations,
                );
            }
        }
    }
    violations
}

#[allow(clippy::too_many_arguments)]
fn scan_table(
    table: &toml::value::Table,
    crate_name: &str,
    manifest_path: &Path,
    table_id: DependencyTable,
    table_label: &str,
    allowed: &[String],
    allowlist: &AllowList,
    violations: &mut Vec<Violation>,
) {
    for (dep_name, _) in table {
        if !is_ovstorage_dep(dep_name) {
            continue;
        }
        if allowed.iter().any(|allowed_name| allowed_name == dep_name) {
            continue;
        }
        if allowlist.is_excepted(crate_name, dep_name) {
            continue;
        }
        violations.push(Violation {
            crate_name: crate_name.to_string(),
            manifest_path: manifest_path.to_path_buf(),
            table: table_id,
            table_label: table_label.to_string(),
            offending_dep: dep_name.clone(),
        });
    }
}

fn crate_name_for(manifest_path: &Path) -> String {
    manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string()
}

fn is_ovstorage_dep(name: &str) -> bool {
    name == "ovstorage" || name.starts_with("ovstorage-")
}

pub fn format_violations(violations: &[Violation]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "check-plugin-deps: {} layering violation(s) found:\n",
        violations.len()
    ));
    for violation in violations {
        out.push_str(&format!(
            "  - {} in {} ({}): {} is not in the allowlist\n",
            violation.crate_name,
            violation.manifest_path.display(),
            violation.table_label,
            violation.offending_dep,
        ));
    }
    out.push_str(
        "\nFix: drop the offending dependency, switch to ovstorage-plugin, or update the \
         allowlist in tools/check-plugin-deps/src/lib.rs (or extra_* / per-crate exceptions \
         in roots.toml) if the dependency is intentional. Tables checked: [dependencies], \
         [dev-dependencies], [build-dependencies], and every [target.<cfg>.<table>] variant.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_manifest(crates_dir: &Path, crate_name: &str, body: &str) {
        let crate_dir = crates_dir.join(crate_name);
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(crate_dir.join("Cargo.toml"), body).unwrap();
    }

    fn allowlist() -> AllowList {
        AllowList {
            dependencies: vec!["ovstorage-plugin".into()],
            dev_dependencies: vec!["ovstorage".into(), "ovstorage-plugin".into()],
            build_dependencies: Vec::new(),
            exceptions: BTreeMap::new(),
        }
    }

    #[test]
    fn permissive_starting_allowlist_admits_existing_core_plugin_deps() {
        let allowlist = AllowList::permissive_starting();
        assert!(
            allowlist
                .dependencies
                .iter()
                .any(|d| d == "ovstorage-plugin"),
            "dependencies allowlist missing ovstorage-plugin",
        );
        for name in ["ovstorage", "ovstorage-cache"] {
            assert!(
                allowlist.dev_dependencies.iter().any(|d| d == name),
                "dev_dependencies allowlist missing {name}",
            );
        }
    }

    #[test]
    fn permissive_starting_does_not_pad_with_unused_deps() {
        let allowlist = AllowList::permissive_starting();
        assert!(
            !allowlist
                .dependencies
                .iter()
                .any(|d| d == "ovstorage-broker-protocol"),
            "core dependencies allowlist over-permits ovstorage-broker-protocol: it is owned by the remote workspace and granted via roots.toml extra_dependencies",
        );
        assert!(
            !allowlist.dependencies.iter().any(|d| d == "ovstorage-core"),
            "dependencies allowlist over-permits ovstorage-core: that crate has been folded into ovstorage-plugin",
        );
        assert!(
            allowlist.build_dependencies.is_empty(),
            "build_dependencies allowlist starts empty until a real plugin needs an entry",
        );
    }

    #[test]
    fn allowed_dep_is_silent() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[dev-dependencies]
ovstorage = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations, Vec::new());
    }

    #[test]
    fn forbidden_dep_is_reported() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
ovstorage-cache = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].crate_name, "ovstorage-plugin-file");
        assert_eq!(violations[0].table, DependencyTable::Dependencies);
        assert_eq!(violations[0].table_label, "[dependencies]");
        assert_eq!(violations[0].offending_dep, "ovstorage-cache");
    }

    #[test]
    fn per_crate_exception_admits_only_the_named_crate() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        // The crate the exception is scoped to: its dependency passes.
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-test-abi",
            r#"
[package]
name = "ovstorage-plugin-test-abi"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
ovstorage-plugin-test = "0.4"
"#,
        );
        // Any other plugin crate taking the same dependency still fails.
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-http",
            r#"
[package]
name = "ovstorage-plugin-http"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
ovstorage-plugin-test = "0.4"
"#,
        );
        let mut allowlist = allowlist();
        allowlist.exceptions.insert(
            "ovstorage-plugin-test-abi".into(),
            vec!["ovstorage-plugin-test".into()],
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].crate_name, "ovstorage-plugin-http");
        assert_eq!(violations[0].table, DependencyTable::Dependencies);
        assert_eq!(violations[0].offending_dep, "ovstorage-plugin-test");
    }

    #[test]
    fn per_crate_exception_does_not_admit_other_deps_for_the_named_crate() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-test-abi",
            r#"
[package]
name = "ovstorage-plugin-test-abi"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
ovstorage-cache = "0.4"
"#,
        );
        let mut allowlist = allowlist();
        allowlist.exceptions.insert(
            "ovstorage-plugin-test-abi".into(),
            vec!["ovstorage-plugin-test".into()],
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].crate_name, "ovstorage-plugin-test-abi");
        assert_eq!(violations[0].offending_dep, "ovstorage-cache");
    }

    #[test]
    fn dev_dep_uses_dev_allowlist() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[dev-dependencies]
ovstorage-cache = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::DevDependencies);
        assert_eq!(violations[0].table_label, "[dev-dependencies]");
        assert_eq!(violations[0].offending_dep, "ovstorage-cache");
    }

    #[test]
    fn forbidden_build_dep_is_reported() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[build-dependencies]
ovstorage = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::BuildDependencies);
        assert_eq!(violations[0].table_label, "[build-dependencies]");
        assert_eq!(violations[0].offending_dep, "ovstorage");
    }

    #[test]
    fn target_specific_runtime_dep_is_reported() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[target.'cfg(unix)'.dependencies]
ovstorage-cache = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::Dependencies);
        assert_eq!(
            violations[0].table_label,
            "[target.'cfg(unix)'.dependencies]"
        );
        assert_eq!(violations[0].offending_dep, "ovstorage-cache");
    }

    #[test]
    fn target_specific_dev_dep_is_reported() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[target.'cfg(windows)'.dev-dependencies]
ovstorage-cache = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::DevDependencies);
        assert_eq!(
            violations[0].table_label,
            "[target.'cfg(windows)'.dev-dependencies]"
        );
        assert_eq!(violations[0].offending_dep, "ovstorage-cache");
    }

    #[test]
    fn target_specific_build_dep_is_reported() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[target.'cfg(unix)'.build-dependencies]
ovstorage = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::BuildDependencies);
        assert_eq!(
            violations[0].table_label,
            "[target.'cfg(unix)'.build-dependencies]"
        );
        assert_eq!(violations[0].offending_dep, "ovstorage");
    }

    #[test]
    fn allowed_target_specific_dep_is_silent() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"

[target.'cfg(unix)'.dependencies]
ovstorage-plugin = "0.4"

[target.'cfg(windows)'.dev-dependencies]
ovstorage = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations, Vec::new());
    }

    #[test]
    fn unparseable_manifest_is_reported_under_manifest_table() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(&crates_dir, "ovstorage-plugin-file", "not = valid = toml");
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].table, DependencyTable::Manifest);
        assert_eq!(violations[0].table_label, "Cargo.toml");
        assert!(violations[0].offending_dep.starts_with("<unparseable:"));
    }

    #[test]
    fn abi_layer_crates_are_skipped() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin",
            r#"
[package]
name = "ovstorage-plugin"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-core = "0.4"
ovstorage-plugin-macros = "0.4"
"#,
        );
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-macros",
            r#"
[package]
name = "ovstorage-plugin-macros"
version = "0.0.0"
edition = "2021"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations, Vec::new());
    }

    #[test]
    fn non_plugin_crates_are_skipped() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-cache",
            r#"
[package]
name = "ovstorage-cache"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-core = "0.4"
"#,
        );
        let violations = lint_crates_dir(&crates_dir, &allowlist()).unwrap();
        assert_eq!(violations, Vec::new());
    }

    #[test]
    fn missing_crates_dir_is_a_hard_error() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("does-not-exist");
        let result = lint_crates_dir(&missing, &allowlist());
        assert!(result.is_err());
    }

    #[test]
    fn locate_crates_dir_walks_up() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        let nested = crates_dir.join("ovstorage-plugin-file").join("src");
        fs::create_dir_all(&nested).unwrap();
        let found = locate_crates_dir(&nested).unwrap();
        assert_eq!(found, crates_dir);
    }

    #[test]
    fn lint_reports_visited_plugin_names() {
        let temp = TempDir::new().unwrap();
        let crates_dir = temp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-file",
            r#"
[package]
name = "ovstorage-plugin-file"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
"#,
        );
        write_manifest(
            &crates_dir,
            "ovstorage-plugin-http",
            r#"
[package]
name = "ovstorage-plugin-http"
version = "0.0.0"
edition = "2021"

[dependencies]
ovstorage-plugin = "0.4"
"#,
        );
        write_manifest(
            &crates_dir,
            "ovstorage-cache",
            r#"
[package]
name = "ovstorage-cache"
version = "0.0.0"
edition = "2021"
"#,
        );
        let (_, visited) = lint_crates_dir_with_visited(&crates_dir, &allowlist()).unwrap();
        assert_eq!(
            visited,
            vec!["ovstorage-plugin-file", "ovstorage-plugin-http"]
        );
    }

    #[test]
    fn load_roots_parses_extras_and_resolves_paths() {
        let temp = TempDir::new().unwrap();
        let base = temp.path();
        let crates_a = base.join("a/crates");
        let crates_b = base.join("b/crates");
        fs::create_dir_all(&crates_a).unwrap();
        fs::create_dir_all(&crates_b).unwrap();
        let roots_path = base.join("roots.toml");
        fs::write(
            &roots_path,
            r#"
[[roots]]
label = "a"
path = "a/crates"

[[roots]]
label = "b"
path = "b/crates"
extra_dependencies = ["ovstorage", "ovstorage-broker-protocol"]
extra_build_dependencies = ["ovstorage-plugin"]
"#,
        )
        .unwrap();
        let roots = load_roots(&roots_path, base).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].label, "a");
        assert!(roots[0].extra_dependencies.is_empty());
        assert_eq!(roots[1].label, "b");
        assert_eq!(
            roots[1].extra_dependencies,
            vec!["ovstorage", "ovstorage-broker-protocol"]
        );
        assert_eq!(roots[1].extra_build_dependencies, vec!["ovstorage-plugin"]);
        let extended = roots[1].allowlist(&AllowList::permissive_starting());
        assert!(extended.dependencies.contains(&"ovstorage".to_string()));
        assert!(
            extended
                .dependencies
                .contains(&"ovstorage-broker-protocol".to_string())
        );
        assert!(
            extended
                .build_dependencies
                .contains(&"ovstorage-plugin".to_string())
        );
    }

    #[test]
    fn load_roots_parses_per_crate_exceptions() {
        let temp = TempDir::new().unwrap();
        let base = temp.path();
        let crates = base.join("crates");
        fs::create_dir_all(&crates).unwrap();
        let roots_path = base.join("roots.toml");
        fs::write(
            &roots_path,
            r#"
[[roots]]
label = "core"
path = "crates"

[roots.exceptions]
"ovstorage-plugin-test-abi" = ["ovstorage-plugin-test"]
"#,
        )
        .unwrap();
        let roots = load_roots(&roots_path, base).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(
            roots[0].exceptions.get("ovstorage-plugin-test-abi"),
            Some(&vec!["ovstorage-plugin-test".to_string()])
        );
        let extended = roots[0].allowlist(&AllowList::permissive_starting());
        // The exception is per-crate: the blanket dependencies allowlist
        // must not pick up ovstorage-plugin-test.
        assert!(
            !extended
                .dependencies
                .contains(&"ovstorage-plugin-test".to_string())
        );
        assert!(extended.is_excepted("ovstorage-plugin-test-abi", "ovstorage-plugin-test"));
        assert!(!extended.is_excepted("ovstorage-plugin-http", "ovstorage-plugin-test"));
    }

    #[test]
    fn load_roots_rejects_malformed_exceptions() {
        let temp = TempDir::new().unwrap();
        let base = temp.path();
        let roots_path = base.join("roots.toml");
        fs::write(
            &roots_path,
            r#"
[[roots]]
label = "core"
path = "crates"
exceptions = ["ovstorage-plugin-test"]
"#,
        )
        .unwrap();
        assert!(load_roots(&roots_path, base).is_err());

        fs::write(
            &roots_path,
            r#"
[[roots]]
label = "core"
path = "crates"

[roots.exceptions]
"ovstorage-plugin-test-abi" = "ovstorage-plugin-test"
"#,
        )
        .unwrap();
        assert!(load_roots(&roots_path, base).is_err());
    }
}
