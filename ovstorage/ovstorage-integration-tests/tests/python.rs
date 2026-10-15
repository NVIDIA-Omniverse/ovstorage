// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Drives the Python binding runner from `cargo test`.
//!
//! Runs `pytest` against `tests/python/` only when a Python interpreter loads
//! the NATIVE `ovstorage` extension built from THIS checkout (the `make` venv,
//! or the binding crate itself, which `maturin develop` installs as an editable
//! path). A globally installed wheel is deliberately rejected: it would run the
//! scenarios against whatever version happened to be on the machine and report
//! that as this checkout's binding coverage.
//!
//! ## Why the check is on the extension, not on the package
//!
//! `ovstorage/__init__.py` is a thin re-export of `ovstorage/ovstorage.abi3.so`
//! — the pure-Python file is a few dozen lines, the extension is the entire
//! binding and every line of Rust under test. Locating the package directory
//! therefore says nothing about what is actually loaded: with an editable
//! install the `.py` is a live view of the working tree while the `.so` beside
//! it is whatever `maturin develop` last produced, so a package that looks
//! current can be fronting a build from days ago. So this checks the loaded
//! extension's own path, and then its age.
//!
//! Self-skips — never fails — when that toolchain is absent or out of date,
//! because building the extension is heavy (maturin) and is owned by `make
//! test-integration-python`, which creates the venv, runs `maturin develop
//! --features test-probes`, and points `OVSTORAGE_PLUGIN_DIR` at the same
//! staged cdylibs this crate's Rust leg dlopens. A skip is the point: a stale
//! extension must not be reported as coverage of the current tree, and the CI
//! job that owns the Python leg runs pytest directly after building it, so
//! nothing is lost by declining here.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

/// Print the loaded NATIVE extension's path, and accept it only if it resolves
/// inside the workspace.
///
/// `importlib.import_module` rather than an attribute lookup on the package:
/// `ovstorage/__init__.py` does `from .ovstorage import *`, so the `ovstorage`
/// attribute of the package is not guaranteed to still be the submodule.
const IMPORT_CHECK: &str = r#"
import importlib
import os
import pathlib
import sys

import ovstorage
import pytest
import pytest_asyncio

native = importlib.import_module("ovstorage.ovstorage")
module_path = pathlib.Path(native.__file__).resolve()
print(module_path)

workspace = pathlib.Path(os.environ["OVSTORAGE_EXPECTED_WORKSPACE"]).resolve()
target = workspace / "target"
allowed_roots = [workspace / "ovstorage-core" / "ovstorage-python"]
if target.is_dir():
    allowed_roots.extend(
        path
        for path in target.iterdir()
        if path.is_dir() and path.name.startswith("python-test-venv-")
    )

if any(module_path.is_relative_to(root.resolve()) for root in allowed_roots):
    sys.exit(0)
print(module_path, file=sys.stderr)
sys.exit(1)
"#;

/// Extension suffixes CPython loads a native module from.
const NATIVE_SUFFIXES: &[&str] = &[".so", ".pyd", ".dylib"];

/// Candidate interpreters, most specific first: the venv `make` builds the
/// extension into, then whatever is on `PATH` (which is what an already-active
/// venv gives us).
fn candidate_interpreters(workspace_root: &Path) -> Vec<PathBuf> {
    let mut venvs = std::fs::read_dir(workspace_root.join("target"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let is_dir = entry.file_type().ok()?.is_dir();
            let is_test_venv = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("python-test-venv-"));
            (is_dir && is_test_venv).then(|| entry.path())
        })
        .collect::<Vec<_>>();
    venvs.sort();

    let mut interpreters = Vec::with_capacity(venvs.len() * 2 + 2);
    for venv in venvs {
        interpreters.push(venv.join("bin/python"));
        interpreters.push(venv.join("Scripts/python.exe"));
    }
    interpreters.push(PathBuf::from("python3"));
    interpreters.push(PathBuf::from("python"));
    interpreters
}

/// The first candidate interpreter that loads this checkout's native
/// extension, paired with the extension it loaded.
fn python_with_extension(workspace_root: &Path) -> Option<(PathBuf, PathBuf)> {
    candidate_interpreters(workspace_root)
        .into_iter()
        .find_map(|py| {
            let output = Command::new(&py)
                .args(["-c", IMPORT_CHECK])
                .env("OVSTORAGE_EXPECTED_WORKSPACE", workspace_root)
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let module = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
            Some((py, module))
        })
}

/// The newest modification time among the sources the extension is built from,
/// with the file that carries it.
///
/// `ovstorage-core/` is the whole input: the binding crate's only workspace
/// dependency is `ovstorage-core/ovstorage`, and the cloud plugins are
/// `dlopen`ed at run time rather than linked, so their sources cannot stale an
/// already-built extension.
///
/// Narrow on purpose — a false "stale" costs a rebuild nobody needed. Only
/// shipped code counts: `.rs` under a crate's `src/`, plus manifests. `target/`
/// is skipped (build output is always newer than its inputs), and so is
/// `tests/`, whose files cannot change what the extension does.
fn newest_source(workspace_root: &Path) -> Option<(PathBuf, SystemTime)> {
    fn is_input(path: &Path) -> bool {
        let name = path.file_name().unwrap_or_default();
        if name == "Cargo.toml" || name == "Cargo.lock" {
            return true;
        }
        path.extension().is_some_and(|e| e == "rs")
            && path.components().any(|c| c.as_os_str() == "src")
    }

    fn walk(dir: &Path, newest: &mut Option<(PathBuf, SystemTime)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if name == "target" || name == "tests" || name.to_string_lossy().starts_with('.') {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(&path, newest);
                continue;
            }
            if !is_input(&path) {
                continue;
            }
            let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            if newest.as_ref().is_none_or(|(_, seen)| mtime > *seen) {
                *newest = Some((path, mtime));
            }
        }
    }

    let mut newest = None;
    walk(&workspace_root.join("ovstorage-core"), &mut newest);
    newest
}

#[test]
fn python_runner() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest
        .parent()
        .expect("integration crate is under the workspace root");

    let Some((python, extension)) = python_with_extension(workspace_root) else {
        eprintln!(
            "⊘ SKIPPED python_runner: no interpreter loads this checkout's native `ovstorage` \
             extension (with pytest + pytest-asyncio). Run `make test-integration-python` (builds \
             the extension via maturin into target/python-test-venv-<version> and runs pytest). A globally \
             installed wheel is ignored to avoid reporting stale binding coverage as this \
             checkout's."
        );
        return;
    };

    // The package resolved to something that is not a compiled module at all —
    // a stub, a namespace shim, a leftover `ovstorage/ovstorage.py`. Loud,
    // because it means the binding under test was never built and the skip
    // above would have described the wrong problem.
    let name = extension.file_name().unwrap_or_default().to_string_lossy();
    assert!(
        NATIVE_SUFFIXES.iter().any(|s| name.ends_with(s)),
        "`ovstorage.ovstorage` resolved to {} , which is not a native extension module. The \
         Python leg would be exercising something other than this checkout's binding.",
        extension.display(),
    );

    // Freshness. Being inside the workspace only proves WHERE it came from, not
    // WHEN: `maturin develop` installs an editable path, so an extension built
    // before the Rust change under review keeps satisfying every path check
    // while reporting the old build's behavior as this run's coverage.
    let built = extension.metadata().and_then(|m| m.modified()).ok();
    if let (Some(built), Some((source, changed))) = (built, newest_source(workspace_root))
        && changed > built
    {
        eprintln!(
            "⊘ SKIPPED python_runner: the loaded extension {} is older than {}, so running the \
             scenarios against it would report a previous build's behavior as this tree's binding \
             coverage. Run `make test-integration-python` to rebuild it.",
            extension.display(),
            source.display(),
        );
        return;
    }

    // Same resolution order as the Rust leg's `plugin_dir()`, so both legs
    // dlopen the same staged cdylibs.
    let plugin_dir = std::env::var("OVSTORAGE_PLUGIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("OVSTORAGE_DEFAULT_PLUGIN_DIR")));

    eprintln!(
        "python_runner: {} loading {}",
        python.display(),
        extension.display()
    );
    // The guard env (`OVSTORAGE_REQUIRE_LIVE_BACKENDS` /
    // `OVSTORAGE_FORBID_LIVE_BACKENDS` / `OVSTORAGE_REQUIRE_TEST_PLUGINS`) is
    // inherited, so this leg honors exactly what the caller set for the Rust
    // one.
    let status = Command::new(&python)
        .args(["-m", "pytest", "-q"])
        .arg(manifest.join("tests/python"))
        .env("OVSTORAGE_PLUGIN_DIR", &plugin_dir)
        .status()
        .expect("invoke pytest");
    assert!(
        status.success(),
        "pytest failed: the Python binding scenarios did not pass"
    );
}

/// The freshness gate only ever fires in the negative on a working tree (a
/// current extension is the normal state), so its selection rules are pinned
/// here instead: what counts as an input, and what must not.
#[test]
fn newest_source_selects_shipped_code_only() {
    let root = std::env::temp_dir().join(format!(
        "ovstorage-it-newest-source-{}-{:?}",
        std::process::id(),
        std::thread::current().id(),
    ));
    let core = root.join("ovstorage-core/ovstorage/src");
    std::fs::create_dir_all(&core).expect("create crate src");
    std::fs::write(core.join("lib.rs"), "// old").expect("write lib.rs");

    let (found, base) = newest_source(&root).expect("a src/*.rs file is an input");
    assert_eq!(found, core.join("lib.rs"));

    // Build output and test sources are newer, and neither may win.
    for decoy in [
        root.join("ovstorage-core/ovstorage/target/debug/build.rs"),
        root.join("ovstorage-core/ovstorage/tests/some_test.rs"),
        root.join("ovstorage-core/ovstorage/src/notes.md"),
    ] {
        std::fs::create_dir_all(decoy.parent().expect("decoy has a parent")).expect("create dir");
        std::fs::write(&decoy, "// newer").expect("write decoy");
        let (found, mtime) = newest_source(&root).expect("still an input");
        assert_eq!(
            found,
            core.join("lib.rs"),
            "{} must not count",
            decoy.display()
        );
        assert_eq!(mtime, base);
    }

    // A manifest anywhere in the crate does count.
    let manifest = root.join("ovstorage-core/ovstorage/Cargo.toml");
    std::fs::write(&manifest, "[package]").expect("write manifest");
    let (found, mtime) = newest_source(&root).expect("manifest is an input");
    assert_eq!(found, manifest);
    assert!(mtime >= base);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn candidate_interpreters_follow_versioned_make_venvs() {
    let root = std::env::temp_dir().join(format!(
        "ovstorage-it-python-venvs-{}-{:?}",
        std::process::id(),
        std::thread::current().id(),
    ));
    let versioned = root.join("target/python-test-venv-3.13.2");
    let untagged = root.join("target/python-test-venv");
    std::fs::create_dir_all(versioned.join("bin")).expect("create versioned venv");
    std::fs::create_dir_all(untagged.join("bin")).expect("create untagged decoy");

    let candidates = candidate_interpreters(&root);
    assert!(candidates.contains(&versioned.join("bin/python")));
    assert!(!candidates.contains(&untagged.join("bin/python")));

    let _ = std::fs::remove_dir_all(&root);
}
