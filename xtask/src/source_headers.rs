// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Source-file notice gate for files that can carry comments. The approval
//! board requires NVIDIA-authored source files to carry a copyright notice
//! and SPDX short-form license identifier before distribution.
//!
//! Two validation modes:
//!
//! - **NVIDIA-authored (default).** The SPDX two-line header
//!   (`SPDX-FileCopyrightText` + `SPDX-License-Identifier: Apache-2.0`)
//!   must appear within the first [`NVIDIA_HEADER_WINDOW_LINES`] lines.
//!   The window is intentionally small: the header must sit at the top
//!   of the file. A larger window would let the header drift below
//!   unrelated leading comments without the lint noticing.
//! - **Vendored third-party** (e.g., the gRPC health.proto). OSRB does
//!   not allow the SPDX shortcut for non-NVIDIA-authored code — the
//!   full upstream Apache 2.0 boilerplate must be preserved verbatim
//!   within the first [`VENDORED_HEADER_WINDOW_LINES`] lines.

use anyhow::{Context, Result};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const NVIDIA_COPYRIGHT: &str = "SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.";
const APACHE_LICENSE: &str = "SPDX-License-Identifier: Apache-2.0";

/// Line window for the NVIDIA SPDX two-line header. Five lines is tight
/// enough that the header must sit at the very top of the file but loose
/// enough to permit a block-comment opener (e.g., `/*` on line 1 with the
/// SPDX text on lines 2–3) plus a blank separator line.
const NVIDIA_HEADER_WINDOW_LINES: usize = 5;

/// Line window for vendored third-party files. The canonical upstream
/// Apache 2.0 boilerplate is ~13 lines; 20 lines leaves room for a
/// brief vendoring annotation below the original notice.
const VENDORED_HEADER_WINDOW_LINES: usize = 20;

const GRPC_HEALTH_PROTO: &str =
    "ovstorage-remote/crates/ovstorage-broker-protocol/proto/grpc/health/v1/health.proto";

/// Anchors from the canonical upstream gRPC Apache 2.0 boilerplate. Both
/// must be present to confirm the file carries the verbatim third-party
/// notice rather than the SPDX shortcut (which OSRB does not permit for
/// non-NVIDIA code).
const GRPC_HEALTH_COPYRIGHT: &str = "Copyright 2015 The gRPC Authors";
const APACHE_LICENSE_FULL_PHRASE: &str = "Licensed under the Apache License, Version 2.0";

const GENERATED_WITH_EXTERNAL_DRIFT_CHECKS: &[&str] =
    &["ovstorage-remote/crates/ovstorage-rest/spec/openapi.yaml"];

pub(crate) fn validate() -> Result<()> {
    let root = crate::repo_root()?;
    let candidates = tracked_files(&root)?;
    let checked = validate_candidates(&root, candidates)?;
    println!("validated {checked} source header(s)");
    Ok(())
}

fn tracked_files(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .arg("ls-files")
        .current_dir(root)
        .output()
        .context("invoke git ls-files")?;
    if !output.status.success() {
        anyhow::bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(PathBuf::from)
        .collect())
}

fn validate_candidates<I>(root: &Path, candidates: I) -> Result<usize>
where
    I: IntoIterator<Item = PathBuf>,
{
    let mut checked = 0usize;
    let mut errors = Vec::new();
    for rel in candidates {
        if !is_linted_source(&rel) {
            continue;
        }
        if !root.join(&rel).exists() {
            continue;
        }
        checked += 1;
        if let Err(err) = validate_file(root, &rel) {
            errors.push(format!("{}: {err:#}", rel.display()));
        }
    }

    if !errors.is_empty() {
        anyhow::bail!("source-header validation failed:\n{}", errors.join("\n"));
    }
    Ok(checked)
}

fn validate_file(root: &Path, rel: &Path) -> Result<()> {
    let text = std::fs::read_to_string(root.join(rel))
        .with_context(|| format!("read {}", root.join(rel).display()))?;
    if path_key(rel) == GRPC_HEALTH_PROTO {
        let head = leading_lines(&text, VENDORED_HEADER_WINDOW_LINES);
        require(&head, GRPC_HEALTH_COPYRIGHT, VENDORED_HEADER_WINDOW_LINES)?;
        require(
            &head,
            APACHE_LICENSE_FULL_PHRASE,
            VENDORED_HEADER_WINDOW_LINES,
        )?;
        return Ok(());
    }
    let head = leading_lines(&text, NVIDIA_HEADER_WINDOW_LINES);
    require(&head, NVIDIA_COPYRIGHT, NVIDIA_HEADER_WINDOW_LINES)?;
    require(&head, APACHE_LICENSE, NVIDIA_HEADER_WINDOW_LINES)?;
    Ok(())
}

fn leading_lines(text: &str, n: usize) -> String {
    text.lines().take(n).collect::<Vec<_>>().join("\n")
}

fn require(head: &str, needle: &str, window: usize) -> Result<()> {
    if head.contains(needle) {
        Ok(())
    } else {
        anyhow::bail!("missing `{needle}` in the first {window} lines")
    }
}

fn is_linted_source(rel: &Path) -> bool {
    if is_excluded_area(rel) {
        return false;
    }
    let key = path_key(rel);
    if GENERATED_WITH_EXTERNAL_DRIFT_CHECKS.contains(&key.as_str()) {
        return false;
    }
    // File kinds whose comment syntax is supported by the SPDX header
    // format used by this lint. When introducing a new comment-bearing
    // source kind (e.g., `.sh`, `.nix`, Dockerfile, `.cmake`), add it
    // here and update `tests::skips_archives_services_and_generated_specs`.
    matches!(
        rel.extension().and_then(|ext| ext.to_str()),
        Some("c")
            | Some("cpp")
            | Some("h")
            | Some("hpp")
            | Some("html")
            | Some("ini")
            | Some("proto")
            | Some("py")
            | Some("pyi")
            | Some("rs")
            | Some("toml")
            | Some("ts")
            | Some("yaml")
            | Some("yml")
    ) || rel
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Makefile" || name == "CMakeLists.txt")
}

fn is_excluded_area(rel: &Path) -> bool {
    rel.components().any(|component| match component {
        Component::Normal(name) => {
            matches!(
                name.to_str(),
                Some(".git" | "dist" | "target" | "_archive" | "ovstorage-services")
            )
        }
        _ => false,
    })
}

fn path_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn accepts_nvidia_authored_source_header() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "crate/src/lib.rs",
            &format!("// {NVIDIA_COPYRIGHT}\n// {APACHE_LICENSE}\n\npub fn ok() {{}}\n"),
        );

        let checked = validate_candidates(temp.path(), [PathBuf::from("crate/src/lib.rs")])
            .expect("validate");

        assert_eq!(checked, 1);
    }

    #[test]
    fn rejects_missing_spdx_license() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "crate/src/lib.rs",
            &format!("// {NVIDIA_COPYRIGHT}\n\npub fn bad() {{}}\n"),
        );

        let err = validate_candidates(temp.path(), [PathBuf::from("crate/src/lib.rs")])
            .unwrap_err()
            .to_string();

        assert!(err.contains(APACHE_LICENSE));
    }

    #[test]
    fn rejects_header_buried_past_window() {
        // Header sits on lines 7–8, past the 5-line NVIDIA window.
        let temp = TempDir::new().expect("tempdir");
        let buried = format!(
            "// preamble line 1\n\
             // preamble line 2\n\
             // preamble line 3\n\
             // preamble line 4\n\
             // preamble line 5\n\
             // preamble line 6\n\
             // {NVIDIA_COPYRIGHT}\n\
             // {APACHE_LICENSE}\n\
             \npub fn buried() {{}}\n",
        );
        write(temp.path(), "crate/src/lib.rs", &buried);

        let err = validate_candidates(temp.path(), [PathBuf::from("crate/src/lib.rs")])
            .unwrap_err()
            .to_string();

        assert!(err.contains("first 5 lines"));
    }

    #[test]
    fn accepts_grpc_health_proto_full_apache_header() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            GRPC_HEALTH_PROTO,
            "// Copyright 2015 The gRPC Authors\n\
             //\n\
             // Licensed under the Apache License, Version 2.0 (the \"License\");\n\
             // you may not use this file except in compliance with the License.\n\
             // You may obtain a copy of the License at\n\
             //\n\
             //     http://www.apache.org/licenses/LICENSE-2.0\n\
             //\n\
             // Unless required by applicable law or agreed to in writing, software\n\
             // distributed under the License is distributed on an \"AS IS\" BASIS,\n\
             // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n\
             // See the License for the specific language governing permissions and\n\
             // limitations under the License.\n\
             \nsyntax = \"proto3\";\n",
        );

        let checked =
            validate_candidates(temp.path(), [PathBuf::from(GRPC_HEALTH_PROTO)]).expect("validate");

        assert_eq!(checked, 1);
    }

    #[test]
    fn rejects_grpc_health_proto_with_spdx_shortcut() {
        // OSRB does not permit the SPDX shortcut for non-NVIDIA code;
        // the verbatim upstream Apache 2.0 notice is required.
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            GRPC_HEALTH_PROTO,
            &format!(
                "// SPDX-FileCopyrightText: Copyright 2015 The gRPC Authors\n// {APACHE_LICENSE}\n\nsyntax = \"proto3\";\n"
            ),
        );

        let err = validate_candidates(temp.path(), [PathBuf::from(GRPC_HEALTH_PROTO)])
            .unwrap_err()
            .to_string();

        assert!(err.contains(APACHE_LICENSE_FULL_PHRASE));
    }

    #[test]
    fn skips_archives_services_and_generated_specs() {
        assert!(!is_linted_source(Path::new("_archive/old/src/lib.rs")));
        assert!(!is_linted_source(Path::new("ovstorage-services/foo.py")));
        assert!(!is_linted_source(Path::new(
            "ovstorage-remote/crates/ovstorage-rest/spec/openapi.yaml",
        )));
        assert!(is_linted_source(Path::new("ovstorage-core/src/lib.rs")));
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }
}
