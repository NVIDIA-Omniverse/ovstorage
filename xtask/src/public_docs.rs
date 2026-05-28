// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lint for `docs/public/`: every markdown link target must resolve inside
//! `docs/public/`. The shipped distribution does not include the crate
//! sources, so out-of-tree links break in the user-facing surface.
//!
//! The rule is intentionally a substring check on the markdown link form
//! `](../../`: every public doc lives at depth 1
//! (`docs/public/<persona>/<file>.md`), so a single `../` stays inside
//! `docs/public/` and a double `../../` escapes. Bare prose mentioning
//! `../../` (e.g. inside inline code) is not matched — only link targets.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn validate() -> Result<()> {
    let root = crate::repo_root()?;
    let public = root.join("docs").join("public");
    validate_at(&public)
}

fn validate_at(public: &Path) -> Result<()> {
    if !public.exists() {
        println!("{}: not present, nothing to validate", public.display());
        return Ok(());
    }

    let mut files = Vec::new();
    collect_markdown(public, &mut files)?;
    files.sort();

    let mut errors = Vec::new();
    for path in &files {
        let body = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        for (idx, line) in body.lines().enumerate() {
            if line.contains("](../../") {
                errors.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
            }
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "docs/public/ has links that escape the public surface (use a single `../` or rephrase without a link):\n{}",
            errors.join("\n")
        );
    }
    println!("validated {} public doc(s)", files.len());
    Ok(())
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_markdown(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_double_dotdot_link() {
        let temp = temp_test_dir("flags");
        write_md(
            &temp,
            "library-rust/README.md",
            "see [the spi](../../../ovstorage-core/crates/ovstorage-plugin/README.md).\n",
        );
        let err = validate_at(&temp).unwrap_err().to_string();
        assert!(err.contains("library-rust/README.md"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn allows_single_dotdot_link() {
        let temp = temp_test_dir("allows");
        write_md(
            &temp,
            "library-rust/README.md",
            "see [glossary](../GLOSSARY.md) and [plugin-storage](../plugin-storage/README.md).\n",
        );
        validate_at(&temp).unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn allows_inline_code_with_double_dotdot() {
        let temp = temp_test_dir("inline");
        write_md(
            &temp,
            "library-rust/README.md",
            "the build script reads `../../path/to/whatever` from the workspace root.\n",
        );
        validate_at(&temp).unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn ignores_non_markdown_files() {
        let temp = temp_test_dir("non-md");
        write_md(&temp, "library-rust/README.md", "ok\n");
        fs::write(
            temp.join("library-rust").join("notes.txt"),
            "this has ](../../foo) but isn't a markdown file\n",
        )
        .unwrap();
        validate_at(&temp).unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    fn write_md(public_root: &Path, rel: &str, body: &str) {
        let path = public_root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let unique = format!(
            "ovstorage-xtask-public-docs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
