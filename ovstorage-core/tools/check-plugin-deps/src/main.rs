// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use check_plugin_deps::{
    AllowList, Root, format_violations, lint_crates_dir_with_visited, load_roots, locate_crates_dir,
};

fn main() -> ExitCode {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = match resolve_roots(&manifest_dir) {
        Ok(roots) => roots,
        Err(message) => {
            eprintln!("check-plugin-deps: {message}");
            return ExitCode::from(2);
        }
    };
    let base = AllowList::permissive_starting();
    let mut all_violations = Vec::new();
    let mut had_io_error = false;
    for root in &roots {
        let allowlist = root.allowlist(&base);
        match lint_crates_dir_with_visited(&root.crates_dir, &allowlist) {
            Ok((violations, visited)) => {
                println!(
                    "check-plugin-deps: {} ({}): scanned {} plugin(s)",
                    root.label,
                    root.crates_dir.display(),
                    visited.len()
                );
                all_violations.extend(violations);
            }
            Err(error) => {
                had_io_error = true;
                eprintln!(
                    "check-plugin-deps: failed to enumerate {} ({}): {error}",
                    root.label,
                    root.crates_dir.display(),
                );
            }
        }
    }
    if had_io_error {
        return ExitCode::from(2);
    }
    if all_violations.is_empty() {
        println!("check-plugin-deps: OK ({} root(s) scanned)", roots.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("{}", format_violations(&all_violations));
        ExitCode::FAILURE
    }
}

fn resolve_roots(manifest_dir: &Path) -> Result<Vec<Root>, String> {
    if let Some(arg) = env::args().nth(1) {
        let path = PathBuf::from(arg);
        if !path.is_dir() {
            return Err(format!("argument {} is not a directory", path.display()));
        }
        return Ok(vec![Root {
            label: "cli-arg".into(),
            crates_dir: path,
            extra_dependencies: Vec::new(),
            extra_dev_dependencies: Vec::new(),
            extra_build_dependencies: Vec::new(),
        }]);
    }
    let roots_toml = manifest_dir.join("roots.toml");
    if roots_toml.is_file() {
        return load_roots(&roots_toml, manifest_dir)
            .map_err(|error| format!("failed to load {}: {error}", roots_toml.display()));
    }
    let crates_dir = locate_crates_dir(manifest_dir).ok_or_else(|| {
        format!(
            "could not locate workspace crates/ directory starting from {}",
            manifest_dir.display()
        )
    })?;
    Ok(vec![Root {
        label: "default".into(),
        crates_dir,
        extra_dependencies: Vec::new(),
        extra_dev_dependencies: Vec::new(),
        extra_build_dependencies: Vec::new(),
    }])
}
