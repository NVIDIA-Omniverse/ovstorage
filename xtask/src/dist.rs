// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask dist` — build, then assemble a self-contained `dist/` at the
//! repo root: binaries adjacent to a `plugins/` directory the CLI's
//! `default_plugin_dir()` will find via `<exe-dir>/plugins/`.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use toml_edit::{DocumentMut, Item, value};

const BINARIES: &[(&str, &str)] = &[
    ("ovstorage-core", "ovstorage"),
    ("ovstorage-remote", "ovstorage-broker"),
    ("ovstorage-remote", "ovstorage-rest"),
];

// Storage and authz cdylibs ship side-by-side in `dist/plugins/`;
// the broker dlopens authz plugins from the same directory the host
// dlopens storage backends from (default_plugin_dir()), so the
// packaging layout doesn't distinguish them. Required-for-default-
// config items (`ovstorage-authz-toml`) belong here too — without
// them, a fresh release archive can't start the broker against the
// documented default `plugin = "ovstorage-authz-toml"`.
//
// `ovstorage-plugin-test` ships too even though it's `test_only =
// true`. `Library::load_plugins_from_dir` skips test_only plugins
// when `allow_test_plugins` is off, so bundling lets consumers opt
// in to the conformance fixture without changing the default-posture
// startup behavior of the broker / REST gateway.
const PLUGINS: &[(&str, &str)] = &[
    ("ovstorage-core", "ovstorage-plugin-file"),
    ("ovstorage-core", "ovstorage-plugin-http"),
    ("ovstorage-core", "ovstorage-plugin-test"),
    (
        "ovstorage-services-client",
        "ovstorage-plugin-services-client",
    ),
    ("ovstorage-cloud", "ovstorage-plugin-s3"),
    ("ovstorage-cloud", "ovstorage-plugin-gcs"),
    ("ovstorage-cloud", "ovstorage-plugin-azure"),
    ("ovstorage-cloud", "ovstorage-plugin-opendal"),
    ("ovstorage-nucleus", "ovstorage-plugin-nucleus"),
    ("ovstorage-remote", "ovstorage-plugin-broker"),
    ("ovstorage-remote", "ovstorage-authz-toml"),
];

// Cdylibs that aren't plugins but are part of the C/C++ consumer surface.
// The second tuple field is the cdylib's filename stem (set by
// `[lib] name` in the crate's Cargo.toml), not the cargo package name.
const LIBRARIES: &[(&str, &str)] = &[("ovstorage-core", "ovstorage")];

// C / C++ public headers consumer code includes.
const HEADERS: &[&str] = &[
    "ovstorage-core/crates/ovstorage-capi/include/ovstorage.h",
    "ovstorage-core/crates/ovstorage-capi/include/ovstorage.hpp",
    "ovstorage-core/crates/ovstorage-plugin/include/ovstorage_plugin.h",
];

// `docs/public/` is the user-facing tree (personas + agent reference +
// glossary). Its contents ship to dist/docs/ directly. Shipped root
// markdown and skills have their repo-relative `docs/public/...` links
// rewritten to the archive layout as they are copied.

const ROOT_DIST_FILES: &[&str] = &[
    "AGENTS.md",
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
];

// LICENSE / NOTICES files staged into the Python crate dir at wheel
// build time so maturin can include them in the wheel. Maturin can't
// reach above the pyproject.toml's parent for PEP 639 `license-files`
// or `[tool.maturin].include` entries, so they must live in the crate
// dir at packaging time. The crate's `.gitignore` keeps the staged
// copies out of source control.
const WHEEL_STAGED_FILES: &[&str] = &["LICENSE", "THIRD_PARTY_NOTICES.md"];
const PYTHON_CRATE_DIR: &str = "ovstorage-core/crates/ovstorage-python";

// Example consumer code. plugin-rust is in-tree dev-only and not shipped.
const EXAMPLES: &[&str] = &["plugin-c", "cpp-async"];

const SHIPPED_SKILL_PREFIXES: &[&str] = &["ovstorage-user-", "ovstorage-operator-"];

// CC BY 4.0 requires the license text and grant accompany the material.
// Skills declare `license: CC-BY-4.0` in their SKILL.md frontmatter and
// the release archive must carry the verbatim license + NVIDIA notice
// next to them. These are sibling files of the per-skill directories;
// the per-skill `copy_skill_dir` walks skill subtrees only.
const SHIPPED_SKILL_ROOT_FILES: &[&str] = &["LICENSE.txt", "NOTICE.txt", "README.md"];

// The services release surface is intentionally filtered. Ship API contracts,
// conformance/example material, deployment guidance, service skills, and the
// license/product-term files that govern them. Keep generated HTML/static docs
// with the API snapshots so archive readers do not need to rebuild Sphinx docs;
// continue excluding build/dependency caches.
const SERVICES_RELEASE_ROOT_FILES: &[&str] = &["README.md", "AGENTS.md"];

const SERVICES_RELEASE_FILES: &[&str] = &[
    "apis/README.md",
    "apis/storage-api/AGENTS.md",
    "apis/storage-api/CHANGELOG.md",
    "apis/storage-api/LICENSE.txt",
    "apis/storage-api/LICENSE_HEADER.txt",
    "apis/storage-api/PRODUCT_TERMS_OMNIVERSE.txt",
    "apis/storage-api/PROMPTS.md",
    "apis/storage-api/README.md",
    "apis/storage-api/SECURITY.md",
    "apis/storage-api/run_tests.sh",
    "apis/permissions-api/LICENSE.txt",
    "apis/permissions-api/LICENSE_HEADER.txt",
    "apis/permissions-api/PRODUCT_TERMS_OMNIVERSE.txt",
    "apis/permissions-api/README.md",
    "apis/permissions-api/SECURITY.md",
    "apis/notifications-api/README.md",
    "apis/notifications-api/aggregation/CHANGELOG.md",
    "apis/notifications-api/aggregation/LICENSE.txt",
    "apis/notifications-api/aggregation/OSS_LICENSE.txt",
    "apis/notifications-api/aggregation/PRODUCT_TERMS_OMNIVERSE.txt",
    "apis/notifications-api/aggregation/SECURITY.md",
    "apis/notifications-api/consumer/CHANGELOG.md",
    "apis/notifications-api/consumer/LICENSE.txt",
    "apis/notifications-api/consumer/OSS_LICENSE.txt",
    "apis/notifications-api/consumer/PRODUCT_TERMS_OMNIVERSE.txt",
    "apis/notifications-api/consumer/SECURITY.md",
];

const SERVICES_RELEASE_DIRS: &[&str] = &[
    "docs",
    "templates",
    "skills",
    "apis/storage-api/openapi",
    "apis/storage-api/proto",
    "apis/storage-api/docs",
    "apis/storage-api/conformance_tests",
    "apis/storage-api/filesystem_example",
    "apis/storage-api/templates",
    "apis/permissions-api/openapi",
    "apis/permissions-api/protos",
    "apis/permissions-api/docs",
    "apis/notifications-api/aggregation/openapi",
    "apis/notifications-api/aggregation/protos",
    "apis/notifications-api/aggregation/docs",
    "apis/notifications-api/consumer/openapi",
    "apis/notifications-api/consumer/protos",
    "apis/notifications-api/consumer/docs",
];

pub(crate) fn run(release: bool, wheel: bool) -> Result<()> {
    crate::build::run(release)?;
    let root = crate::repo_root()?;
    let dist = root.join("dist");
    assemble(&root, &dist, release, wheel)?;
    summarize(&dist, wheel);
    Ok(())
}

fn assemble(root: &Path, dist: &Path, release: bool, wheel: bool) -> Result<()> {
    if dist.exists() {
        fs::remove_dir_all(dist).with_context(|| format!("clean {}", dist.display()))?;
    }
    fs::create_dir_all(dist).with_context(|| format!("create {}", dist.display()))?;

    let profile = if release { "release" } else { "debug" };
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let dll_prefix = std::env::consts::DLL_PREFIX;
    let dll_suffix = std::env::consts::DLL_SUFFIX;

    for (workspace, binary) in BINARIES {
        let name = format!("{}{}", binary, exe_suffix);
        let src = target_path(root, workspace, profile, &name);
        let dst = dist.join(&name);
        copy_artifact(&src, &dst)?;
    }

    let plugins_dir = dist.join("plugins");
    fs::create_dir_all(&plugins_dir)?;
    for (workspace, plugin) in PLUGINS {
        let so = format!("{}{}{}", dll_prefix, plugin.replace('-', "_"), dll_suffix);
        let src = target_path(root, workspace, profile, &so);
        let dst = plugins_dir.join(&so);
        copy_artifact(&src, &dst)?;
    }

    let lib_dir = dist.join("lib");
    fs::create_dir_all(&lib_dir)?;
    for (workspace, lib) in LIBRARIES {
        let stem = lib.replace('-', "_");
        let so = format!("{}{}{}", dll_prefix, stem, dll_suffix);
        let src = target_path(root, workspace, profile, &so);
        let dst = lib_dir.join(&so);
        copy_artifact(&src, &dst)?;
        // Windows consumers need an import library to link the DLL.
        // MSVC emits `<stem>.dll.lib`; MinGW emits `lib<stem>.dll.a`.
        // Cargo writes whichever its toolchain produces; copy any
        // that's there.
        if cfg!(windows) {
            for candidate in [format!("{stem}.dll.lib"), format!("lib{stem}.dll.a")] {
                let src = target_path(root, workspace, profile, &candidate);
                if src.exists() {
                    let dst = lib_dir.join(&candidate);
                    copy_artifact(&src, &dst)?;
                }
            }
        }
    }

    let include_dir = dist.join("include");
    fs::create_dir_all(&include_dir)?;
    for header in HEADERS {
        let src = root.join(header);
        let name = src
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("no filename"))?;
        let dst = include_dir.join(name);
        copy_artifact(&src, &dst)?;
    }

    copy_public_docs(root, dist)?;

    copy_shipped_skills(root, dist)?;

    copy_ovstorage_services_release_surface(root, dist)?;

    let examples_dir = dist.join("examples");
    fs::create_dir_all(&examples_dir)?;
    for ex in EXAMPLES {
        copy_dir_recursive(
            &root.join("ovstorage-core/examples").join(ex),
            &examples_dir.join(ex),
        )?;
    }

    copy_root_dist_files(root, dist)?;

    // VERSION stamped from pyproject (source of truth).
    let version = read_pyproject_version(root)?;
    fs::write(dist.join("VERSION"), format!("{version}\n"))?;

    if wheel {
        build_wheel(root, dist, release)?;
    }
    Ok(())
}

fn summarize(dist: &Path, wheel: bool) {
    println!("dist/ assembled at {}", dist.display());
    println!("  binaries:  {} bin", BINARIES.len());
    println!("  plugins:   {} cdylib in plugins/", PLUGINS.len());
    println!("  libs:      {} cdylib in lib/", LIBRARIES.len());
    println!("  headers:   {} in include/", HEADERS.len());
    println!("  docs:      copied from docs/public/");
    println!("  services:  copied filtered ovstorage-services surface into services/");
    println!("  examples:  {} in examples/", EXAMPLES.len());
    if let Ok(count) = count_shipped_skills(dist) {
        println!("  skills:    {} in skills/", count);
    }
    if wheel {
        let wheels = dist.join("wheels");
        let count = count_wheels(&wheels).unwrap_or(0);
        println!("  wheels:    {} whl in wheels/", count);
    }
}

fn copy_shipped_skills(root: &Path, dist: &Path) -> Result<usize> {
    let skills_root = root.join("skills");
    if !skills_root.exists() {
        return Ok(0);
    }

    let dist_skills = dist.join("skills");
    let mut count = 0usize;
    for entry in
        fs::read_dir(&skills_root).with_context(|| format!("read_dir {}", skills_root.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !SHIPPED_SKILL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        if !entry.path().join("SKILL.md").exists() {
            continue;
        }
        copy_skill_dir(&entry.path(), &dist_skills.join(&name))?;
        count += 1;
    }

    // Only stage the CC BY 4.0 license + notice when at least one skill
    // shipped; otherwise dist/skills/ wouldn't exist and we'd be creating
    // a directory just to hold orphaned license files.
    if count > 0 {
        fs::create_dir_all(&dist_skills)
            .with_context(|| format!("create {}", dist_skills.display()))?;
        for file in SHIPPED_SKILL_ROOT_FILES {
            let src = skills_root.join(file);
            if !src.exists() {
                anyhow::bail!(
                    "skills ship under CC BY 4.0 but {} is missing — the release archive would \
                     omit the license text required by the license",
                    src.display()
                );
            }
            copy_artifact(&src, &dist_skills.join(file))?;
        }
    }
    Ok(count)
}

fn copy_public_docs(root: &Path, dist: &Path) -> Result<()> {
    let public_docs = root.join("docs/public");
    copy_dir_recursive(&public_docs, &dist.join("docs"))?;
    Ok(())
}

fn copy_ovstorage_services_release_surface(root: &Path, dist: &Path) -> Result<()> {
    let source_root = root.join("ovstorage-services");
    if !source_root.exists() {
        return Ok(());
    }

    let target_root = dist.join("services");
    fs::create_dir_all(&target_root)
        .with_context(|| format!("create {}", target_root.display()))?;

    for file in SERVICES_RELEASE_ROOT_FILES {
        copy_required_services_file(&source_root, &target_root, file)?;
    }
    for file in SERVICES_RELEASE_FILES {
        copy_required_services_file(&source_root, &target_root, file)?;
    }
    for dir in SERVICES_RELEASE_DIRS {
        let src = source_root.join(dir);
        if !src.exists() {
            anyhow::bail!(
                "ovstorage-services release surface requires missing directory {}",
                src.display()
            );
        }
        copy_dir_recursive(&src, &target_root.join(dir))?;
    }

    Ok(())
}

fn copy_required_services_file(source_root: &Path, target_root: &Path, file: &str) -> Result<()> {
    let src = source_root.join(file);
    if !src.exists() {
        anyhow::bail!(
            "ovstorage-services release surface requires missing file {}",
            src.display()
        );
    }
    let dst = target_root.join(file);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    copy_artifact(&src, &dst)
}

fn copy_root_dist_files(root: &Path, dist: &Path) -> Result<()> {
    fs::create_dir_all(dist).with_context(|| format!("create {}", dist.display()))?;
    for file in ROOT_DIST_FILES {
        let src = root.join(file);
        if !src.exists() {
            continue;
        }
        let dst = dist.join(file);
        if is_markdown_path(&src) {
            copy_markdown_with_dist_link_rewrites(&src, &dst)?;
        } else {
            copy_artifact(&src, &dst)?;
        }
    }
    Ok(())
}

fn copy_skill_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("read_dir {}", src.display()))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() && EXCLUDE_DIRS.iter().any(|e| *e == name_str) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        if kind.is_dir() {
            copy_skill_dir(&src_path, &dst_path)?;
        } else if kind.is_file() {
            if is_markdown_path(&src_path) {
                copy_markdown_with_dist_link_rewrites(&src_path, &dst_path)?;
            } else {
                copy_artifact(&src_path, &dst_path)?;
            }
        }
        // Skip symlinks deliberately; none in skills today.
    }
    Ok(())
}

fn copy_markdown_with_dist_link_rewrites(src: &Path, dst: &Path) -> Result<()> {
    let body = fs::read_to_string(src).with_context(|| format!("read {}", src.display()))?;
    let rewritten = rewrite_dist_doc_links(&body);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(dst, rewritten).with_context(|| format!("write {}", dst.display()))?;
    Ok(())
}

fn rewrite_dist_doc_links(markdown: &str) -> String {
    markdown.replace("docs/public/", "docs/")
}

fn is_markdown_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}

fn count_shipped_skills(dist: &Path) -> Result<usize> {
    let skills = dist.join("skills");
    if !skills.exists() {
        return Ok(0);
    }
    Ok(fs::read_dir(skills)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .count())
}

// Dev/build artifacts that must not ship in the release archive.
const EXCLUDE_DIRS: &[&str] = &["build", "target", "__pycache__", "node_modules", ".cache"];

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("read_dir {}", src.display()))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if kind.is_dir() && EXCLUDE_DIRS.iter().any(|e| *e == name_str) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        if kind.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if kind.is_file() {
            copy_artifact(&src_path, &dst_path)?;
        }
        // Skip symlinks deliberately; none in docs/examples today.
    }
    Ok(())
}

pub(crate) fn release_archive(release: bool, platform: &str) -> Result<()> {
    crate::build::run(release)?;
    let root = crate::repo_root()?;
    let version = read_pyproject_version(&root)?;
    let stem = format!("ovstorage-v{}-{}", version, platform);

    let dist = root.join("dist");
    let staging = dist.join(&stem);
    assemble(&root, &staging, release, true)?;
    summarize(&staging, true);

    let archive = if cfg!(windows) {
        dist.join(format!("{stem}.zip"))
    } else {
        dist.join(format!("{stem}.tar.gz"))
    };
    if archive.exists() {
        fs::remove_file(&archive)?;
    }

    let mut cmd = Command::new("tar");
    if cfg!(windows) {
        // bsdtar on Windows infers zip from -a + .zip extension.
        cmd.args(["-a", "-cf"]);
    } else {
        cmd.arg("-czf");
    }
    cmd.arg(&archive).arg("-C").arg(&dist).arg(&stem);
    let status = cmd
        .status()
        .context("spawn `tar` (required for release-archive)")?;
    if !status.success() {
        anyhow::bail!("tar failed building {}", archive.display());
    }

    println!("archive: {}", archive.display());
    Ok(())
}

pub(crate) fn wheel_only(release: bool) -> Result<()> {
    let root = crate::repo_root()?;
    let dist = root.join("dist");
    let wheels = dist.join("wheels");
    fs::create_dir_all(&wheels).with_context(|| format!("create {}", wheels.display()))?;
    build_wheel(&root, &dist, release)?;
    let count = count_wheels(&wheels)?;
    println!("{} wheel(s) at {}", count, wheels.display());
    Ok(())
}

fn build_wheel(root: &Path, dist: &Path, release: bool) -> Result<()> {
    let manifest_dir = root.join(PYTHON_CRATE_DIR);
    let pyproject = manifest_dir.join("pyproject.toml");
    let manifest = manifest_dir.join("Cargo.toml");
    let wheels = dist.join("wheels");
    fs::create_dir_all(&wheels).with_context(|| format!("create {}", wheels.display()))?;

    stage_wheel_files(root, &manifest_dir)?;

    let version = compute_wheel_version(root)?;
    let original =
        fs::read_to_string(&pyproject).with_context(|| format!("read {}", pyproject.display()))?;
    let stamped = stamp_version(&original, &version)?;
    fs::write(&pyproject, &stamped).with_context(|| format!("write {}", pyproject.display()))?;
    println!("stamped wheel version: {}", version);

    let result = run_maturin(&manifest, &wheels, release);

    // Restore pyproject.toml even on failure so a dev's tree is left clean.
    // Ctrl-C between stamp and restore leaves it modified; restore from VCS.
    fs::write(&pyproject, &original).with_context(|| format!("restore {}", pyproject.display()))?;
    result
}

fn stage_wheel_files(root: &Path, manifest_dir: &Path) -> Result<()> {
    for name in WHEEL_STAGED_FILES {
        let src = root.join(name);
        let dst = manifest_dir.join(name);
        fs::copy(&src, &dst)
            .with_context(|| format!("stage {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

fn run_maturin(manifest: &Path, wheels: &Path, release: bool) -> Result<()> {
    let mut cmd = Command::new("maturin");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--out")
        .arg(wheels);
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .context("spawn maturin (not on PATH? run `make install-tools`)")?;
    if !status.success() {
        anyhow::bail!("maturin build failed");
    }
    Ok(())
}

fn compute_wheel_version(root: &Path) -> Result<String> {
    let base = read_pyproject_version(root)?;
    if let Ok(release) = std::env::var("OVSTORAGE_RELEASE_VERSION") {
        let release = release.trim();
        if !release.is_empty() {
            return compute_wheel_version_value(&base, Some(release), None, "", false);
        }
    }
    match std::env::var("GITHUB_RUN_NUMBER") {
        Ok(run) if !run.is_empty() => {
            let sha = git_short_sha(root)?;
            compute_wheel_version_value(&base, None, Some(run.as_str()), &sha, false)
        }
        _ => compute_wheel_version_value(&base, None, None, "", false),
    }
}

fn compute_wheel_version_value(
    base: &str,
    release: Option<&str>,
    github_run: Option<&str>,
    sha: &str,
    dirty: bool,
) -> Result<String> {
    if let Some(release) = release {
        if release != base {
            anyhow::bail!(
                "OVSTORAGE_RELEASE_VERSION={} doesn't match pyproject version {}",
                release,
                base
            );
        }
        return Ok(release.to_string());
    }
    if let Some(run) = github_run.filter(|run| !run.is_empty()) {
        return Ok(format!("{}.dev{}+{}", base, run, sha));
    }
    let _ = (sha, dirty);
    Ok(base.to_string())
}

pub(crate) fn print_release_version() -> Result<()> {
    let root = crate::repo_root()?;
    let version = read_pyproject_version(&root)?;
    println!("{}", version);
    Ok(())
}

pub(crate) fn assert_release_open_version() -> Result<()> {
    let version = current_py_version()?;
    version.ensure_final()?;
    if version.patch != 0 {
        anyhow::bail!(
            "release-open requires main to be stamped as X.Y.0; current version is {}",
            version
        );
    }
    println!("{}", version);
    Ok(())
}

pub(crate) fn print_release_line_branch() -> Result<()> {
    let version = current_final_py_version()?;
    println!("{}", version.release_line_branch());
    Ok(())
}

pub(crate) fn print_next_minor_version() -> Result<()> {
    let version = current_final_py_version()?;
    println!("{}", version.bump_numeric(BumpKind::Minor));
    Ok(())
}

pub(crate) fn print_next_patch_version() -> Result<()> {
    let version = current_final_py_version()?;
    println!("{}", version.bump_numeric(BumpKind::Patch));
    Ok(())
}

pub(crate) fn print_final_release_tag() -> Result<()> {
    let version = current_final_py_version()?;
    println!("{}", version.final_tag());
    Ok(())
}

pub(crate) fn print_next_rc_number(tags: &[String]) -> Result<()> {
    let version = current_final_py_version()?;
    let refs = tags.iter().map(String::as_str).collect::<Vec<_>>();
    println!("{}", next_rc_number_for_version(version, &refs));
    Ok(())
}

pub(crate) fn assert_final_tag_absent(tags: &[String]) -> Result<()> {
    let version = current_final_py_version()?;
    let refs = tags.iter().map(String::as_str).collect::<Vec<_>>();
    if final_tag_exists(version, &refs) {
        anyhow::bail!("final tag {} already exists", version.final_tag());
    }
    println!("{} absent", version.final_tag());
    Ok(())
}

pub(crate) fn bump_release_version(kind: &str) -> Result<()> {
    let root = crate::repo_root()?;
    let pyproject = root.join("ovstorage-core/crates/ovstorage-python/pyproject.toml");
    let original =
        fs::read_to_string(&pyproject).with_context(|| format!("read {}", pyproject.display()))?;
    let current = parse_pyproject_version(&original)?;
    let next = bump(&current, kind)?;
    let rewritten = stamp_version(&original, &next)?;
    fs::write(&pyproject, &rewritten).with_context(|| format!("write {}", pyproject.display()))?;
    println!("{} -> {}", current, next);
    Ok(())
}

fn current_py_version() -> Result<PyVersion> {
    let root = crate::repo_root()?;
    let version = read_pyproject_version(&root)?;
    PyVersion::parse(&version)
}

fn current_final_py_version() -> Result<PyVersion> {
    let version = current_py_version()?;
    version.ensure_final()?;
    Ok(version)
}

fn read_pyproject_version(root: &Path) -> Result<String> {
    let pyproject = root.join("ovstorage-core/crates/ovstorage-python/pyproject.toml");
    let body =
        fs::read_to_string(&pyproject).with_context(|| format!("read {}", pyproject.display()))?;
    parse_pyproject_version(&body)
}

fn parse_pyproject(pyproject: &str) -> Result<DocumentMut> {
    pyproject
        .parse::<DocumentMut>()
        .context("parse pyproject.toml")
}

fn parse_pyproject_version(pyproject: &str) -> Result<String> {
    let doc = parse_pyproject(pyproject)?;
    project_version(&doc).map(ToString::to_string)
}

fn project_version(doc: &DocumentMut) -> Result<&str> {
    doc.get("project")
        .and_then(Item::as_table)
        .and_then(|project| project.get("version"))
        .and_then(Item::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing string `project.version` in pyproject.toml"))
}

fn bump(current: &str, kind: &str) -> Result<String> {
    if let Some(explicit) = kind.strip_prefix("to=") {
        return Ok(explicit.to_string());
    }
    let current = PyVersion::parse(current)?;
    let next = match kind {
        "alpha" => current.next_alpha().to_string(),
        "release" => current.final_release().to_string(),
        "patch" => current.bump_numeric(BumpKind::Patch).to_string(),
        "minor" => current.bump_numeric(BumpKind::Minor).to_string(),
        "major" => current.bump_numeric(BumpKind::Major).to_string(),
        other => anyhow::bail!(
            "unknown bump kind {} (want alpha|release|patch|minor|major|to=<v>)",
            other
        ),
    };
    Ok(next)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BumpKind {
    Patch,
    Minor,
    Major,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreKind {
    Alpha,
    Beta,
    Rc,
}

impl PreKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "a",
            Self::Beta => "b",
            Self::Rc => "rc",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreRelease {
    kind: PreKind,
    number: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PyVersion {
    major: u32,
    minor: u32,
    patch: u32,
    pre: Option<PreRelease>,
}

impl PyVersion {
    fn parse(version: &str) -> Result<Self> {
        let mut parts = version.split('.');
        let major = parse_number_part(parts.next(), "major", version)?;
        let minor = parse_number_part(parts.next(), "minor", version)?;
        let patch_and_pre = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("current version {} isn't X.Y.Z[preN]", version))?;
        if parts.next().is_some() {
            anyhow::bail!("current version {} isn't X.Y.Z[preN]", version);
        }

        let patch_len = patch_and_pre
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(patch_and_pre.len());
        if patch_len == 0 {
            anyhow::bail!("current version {} has an invalid patch component", version);
        }
        let patch = patch_and_pre[..patch_len].parse::<u32>()?;
        let suffix = &patch_and_pre[patch_len..];
        let pre = if suffix.is_empty() {
            None
        } else {
            Some(parse_pre_release(suffix, version)?)
        };

        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    fn next_alpha(self) -> Self {
        let number = match self.pre {
            Some(PreRelease {
                kind: PreKind::Alpha,
                number,
            }) => number + 1,
            _ => 1,
        };
        Self {
            pre: Some(PreRelease {
                kind: PreKind::Alpha,
                number,
            }),
            ..self
        }
    }

    fn final_release(self) -> Self {
        Self { pre: None, ..self }
    }

    fn ensure_final(self) -> Result<()> {
        if self.pre.is_some() {
            anyhow::bail!("release version must be final X.Y.Z, got {}", self);
        }
        Ok(())
    }

    fn release_line_branch(self) -> String {
        format!("release/v{}.{}", self.major, self.minor)
    }

    fn final_tag(self) -> String {
        format!("v{}", self)
    }

    fn bump_numeric(self, kind: BumpKind) -> Self {
        let (major, minor, patch) = match kind {
            BumpKind::Patch => (self.major, self.minor, self.patch + 1),
            BumpKind::Minor => (self.major, self.minor + 1, 0),
            BumpKind::Major => (self.major + 1, 0, 0),
        };
        // Conservative prerelease rule: numeric bumps start the new line at a1.
        let pre = self.pre.map(|_| PreRelease {
            kind: PreKind::Alpha,
            number: 1,
        });
        Self {
            major,
            minor,
            patch,
            pre,
        }
    }
}

fn next_rc_number_for_version(version: PyVersion, tags: &[&str]) -> u32 {
    let prefix = format!("{}-rc", version.final_tag());
    let max_seen = tags
        .iter()
        .filter_map(|tag| tag.strip_prefix(&prefix))
        .filter(|suffix| !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()))
        .filter_map(|suffix| suffix.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    max_seen + 1
}

fn final_tag_exists(version: PyVersion, tags: &[&str]) -> bool {
    let final_tag = version.final_tag();
    tags.iter().any(|tag| *tag == final_tag)
}

impl std::fmt::Display for PyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = self.pre {
            write!(f, "{}{}", pre.kind.as_str(), pre.number)?;
        }
        Ok(())
    }
}

fn parse_number_part(part: Option<&str>, label: &str, version: &str) -> Result<u32> {
    let part =
        part.ok_or_else(|| anyhow::anyhow!("current version {} is missing {label}", version))?;
    if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
        anyhow::bail!(
            "current version {} has an invalid {label} component",
            version
        );
    }
    Ok(part.parse()?)
}

fn parse_pre_release(suffix: &str, version: &str) -> Result<PreRelease> {
    let (kind, number) = if let Some(number) = suffix.strip_prefix("rc") {
        (PreKind::Rc, number)
    } else if let Some(number) = suffix.strip_prefix('a') {
        (PreKind::Alpha, number)
    } else if let Some(number) = suffix.strip_prefix('b') {
        (PreKind::Beta, number)
    } else {
        anyhow::bail!(
            "current version {} has an unsupported prerelease suffix",
            version
        );
    };
    if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
        anyhow::bail!(
            "current version {} has an invalid prerelease number",
            version
        );
    }
    Ok(PreRelease {
        kind,
        number: number.parse()?,
    })
}

fn git_short_sha(root: &Path) -> Result<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .context("run `git rev-parse`")?;
    if !out.status.success() {
        anyhow::bail!("`git rev-parse --short HEAD` failed");
    }
    Ok(String::from_utf8(out.stdout)
        .context("git short-sha not utf-8")?
        .trim()
        .to_string())
}

fn stamp_version(pyproject: &str, version: &str) -> Result<String> {
    let mut doc = parse_pyproject(pyproject)?;
    let project = doc
        .get_mut("project")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| anyhow::anyhow!("missing `[project]` table in pyproject.toml"))?;
    if project.get("version").and_then(Item::as_str).is_none() {
        anyhow::bail!("missing string `project.version` in pyproject.toml");
    }
    project.insert("version", value(version));
    Ok(doc.to_string())
}

fn count_wheels(wheels: &Path) -> Result<usize> {
    Ok(fs::read_dir(wheels)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "whl"))
        .count())
}

fn target_path(root: &Path, workspace: &str, profile: &str, name: &str) -> PathBuf {
    root.join(workspace).join("target").join(profile).join(name)
}

fn copy_artifact(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst)
        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PYPROJECT_CRLF: &str = concat!(
        "[build-system]\r\n",
        "requires = [\"maturin>=1,<2\"]\r\n",
        "build-backend = \"maturin\"\r\n",
        "\r\n",
        "[project]\r\n",
        "name = \"ovstorage\"\r\n",
        "version = \"0.1.0\"\r\n",
        "requires-python = \">=3.10\"\r\n",
    );

    const PYPROJECT_ALPHA: &str = concat!(
        "[project]\n",
        "name = \"ovstorage\"\n",
        "version = \"0.1.0a3\"\n",
    );

    // Joe's review finding #5: the authz cdylib must ship in the
    // release archive — broker configs default to
    // `plugin = "ovstorage-authz-toml"` and the broker dlopens that
    // cdylib at startup. Snapshot-style guard against silent removal.
    #[test]
    fn dist_includes_authz_toml_plugin() {
        assert!(
            PLUGINS
                .iter()
                .any(|(ws, plugin)| *ws == "ovstorage-remote" && *plugin == "ovstorage-authz-toml"),
            "PLUGINS must include the authz-toml cdylib so dist can start the broker against \
             the documented default config; current entries: {PLUGINS:?}",
        );
    }

    // The test plugin is the only `test_only = true` cdylib in the
    // archive — it lets consumers exercise their host against the
    // conformance fixture. Loading it requires the host to opt in via
    // `Builder::allow_test_plugins(true)`. Snapshot guard so an
    // ABI-cleanup commit doesn't silently drop it from `dist/`.
    #[test]
    fn dist_includes_test_plugin() {
        assert!(
            PLUGINS
                .iter()
                .any(|(ws, plugin)| *ws == "ovstorage-core" && *plugin == "ovstorage-plugin-test"),
            "PLUGINS must include the test plugin so consumers can drive their host through \
             conformance edge cases; current entries: {PLUGINS:?}",
        );
    }

    #[test]
    fn parses_project_version_with_crlf_line_endings() {
        assert_eq!(parse_pyproject_version(PYPROJECT_CRLF).unwrap(), "0.1.0");
    }

    #[test]
    fn parses_pep440_prerelease_project_versions() {
        assert_eq!(parse_pyproject_version(PYPROJECT_ALPHA).unwrap(), "0.1.0a3");
        assert_eq!(PyVersion::parse("0.1.0a3").unwrap().to_string(), "0.1.0a3");
        assert_eq!(PyVersion::parse("0.1.0b2").unwrap().to_string(), "0.1.0b2");
        assert_eq!(
            PyVersion::parse("0.1.0rc1").unwrap().to_string(),
            "0.1.0rc1"
        );
    }

    #[test]
    fn stamps_project_version_with_toml_parser() {
        let stamped = stamp_version(PYPROJECT_CRLF, "0.1.0.dev12+abcdef0").unwrap();
        assert_eq!(
            parse_pyproject_version(&stamped).unwrap(),
            "0.1.0.dev12+abcdef0"
        );
        assert!(stamped.contains("[project]"));
        assert!(stamped.contains("name = \"ovstorage\""));
    }

    #[test]
    fn wheel_version_preserves_prerelease_for_explicit_release() {
        assert_eq!(
            compute_wheel_version_value("0.1.0a3", Some("0.1.0a3"), None, "abcdef0", false)
                .unwrap(),
            "0.1.0a3"
        );
    }

    #[test]
    fn wheel_version_keeps_dev_suffix_for_ci_builds() {
        assert_eq!(
            compute_wheel_version_value("0.1.0a3", None, Some("42"), "abcdef0", false).unwrap(),
            "0.1.0a3.dev42+abcdef0"
        );
    }

    #[test]
    fn wheel_version_is_clean_for_local_builds() {
        assert_eq!(
            compute_wheel_version_value("0.1.0a3", None, None, "abcdef0", true).unwrap(),
            "0.1.0a3"
        );
    }

    #[test]
    fn dist_skill_copy_ships_user_and_operator_but_not_contributor() {
        let temp = temp_test_dir("dist-skills");
        let root = temp.join("root");
        let dist = temp.join("dist");
        fs::create_dir_all(root.join("skills/ovstorage-user-read-bytes")).unwrap();
        fs::create_dir_all(root.join("skills/ovstorage-operator-monitor-broker")).unwrap();
        fs::create_dir_all(root.join("skills/ovstorage-contributor-verify-before-merge")).unwrap();
        fs::write(
            root.join("skills/ovstorage-user-read-bytes/SKILL.md"),
            "user",
        )
        .unwrap();
        fs::write(
            root.join("skills/ovstorage-operator-monitor-broker/SKILL.md"),
            "operator",
        )
        .unwrap();
        fs::write(
            root.join("skills/ovstorage-contributor-verify-before-merge/SKILL.md"),
            "contributor",
        )
        .unwrap();
        fs::write(root.join("skills/LICENSE.txt"), "cc-by-4.0").unwrap();
        fs::write(root.join("skills/NOTICE.txt"), "nvidia notice").unwrap();
        fs::write(root.join("skills/README.md"), "skills index").unwrap();

        let count = copy_shipped_skills(&root, &dist).unwrap();

        assert_eq!(count, 2);
        assert!(
            dist.join("skills/ovstorage-user-read-bytes/SKILL.md")
                .exists()
        );
        assert!(
            dist.join("skills/ovstorage-operator-monitor-broker/SKILL.md")
                .exists()
        );
        assert!(
            !dist
                .join("skills/ovstorage-contributor-verify-before-merge/SKILL.md")
                .exists()
        );
        fs::remove_dir_all(temp).unwrap();
    }

    // CC BY 4.0 requires the license text accompany the material. The
    // dist tarball must therefore carry `skills/LICENSE.txt`,
    // `skills/NOTICE.txt`, and the skills index next to the shipped
    // ovstorage-user- / ovstorage-operator- skill directories.
    #[test]
    fn dist_skill_copy_stages_cc_by_license_next_to_skills() {
        let temp = temp_test_dir("dist-skill-license");
        let root = temp.join("root");
        let dist = temp.join("dist");
        fs::create_dir_all(root.join("skills/ovstorage-user-read-bytes")).unwrap();
        fs::write(
            root.join("skills/ovstorage-user-read-bytes/SKILL.md"),
            "user",
        )
        .unwrap();
        fs::write(root.join("skills/LICENSE.txt"), "cc-by-4.0 text").unwrap();
        fs::write(root.join("skills/NOTICE.txt"), "nvidia grant").unwrap();
        fs::write(root.join("skills/README.md"), "skills index").unwrap();

        copy_shipped_skills(&root, &dist).unwrap();

        assert_eq!(
            fs::read_to_string(dist.join("skills/LICENSE.txt")).unwrap(),
            "cc-by-4.0 text"
        );
        assert_eq!(
            fs::read_to_string(dist.join("skills/NOTICE.txt")).unwrap(),
            "nvidia grant"
        );
        assert_eq!(
            fs::read_to_string(dist.join("skills/README.md")).unwrap(),
            "skills index"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    // If required root skill files go missing while shipped skills exist,
    // the release archive would ship the material without the license or
    // directory-level context. Fail loudly rather than producing a quietly
    // incomplete tarball.
    #[test]
    fn dist_skill_copy_errors_if_cc_by_license_files_missing() {
        let temp = temp_test_dir("dist-skill-license-missing");
        let root = temp.join("root");
        let dist = temp.join("dist");
        fs::create_dir_all(root.join("skills/ovstorage-user-read-bytes")).unwrap();
        fs::write(
            root.join("skills/ovstorage-user-read-bytes/SKILL.md"),
            "user",
        )
        .unwrap();
        // Intentionally omit LICENSE.txt / NOTICE.txt.

        let err = copy_shipped_skills(&root, &dist).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("LICENSE.txt") || msg.contains("NOTICE.txt"),
            "expected error to name the missing license file, got: {msg}"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn public_docs_copy_uses_single_archive_docs_tree() {
        let temp = temp_test_dir("dist-docs");
        let root = temp.join("root");
        let dist = temp.join("dist");
        fs::create_dir_all(root.join("docs/public/agent")).unwrap();
        fs::write(root.join("docs/public/GLOSSARY.md"), "glossary").unwrap();
        fs::write(root.join("docs/public/agent/README.md"), "agent").unwrap();

        copy_public_docs(&root, &dist).unwrap();

        assert!(dist.join("docs/GLOSSARY.md").exists());
        assert!(dist.join("docs/agent/README.md").exists());
        assert!(!dist.join("docs/public/GLOSSARY.md").exists());
        assert!(!dist.join("docs/public/agent/README.md").exists());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn services_release_surface_copies_filtered_tree() {
        let temp = temp_test_dir("dist-services");
        let root = temp.join("root");
        let dist = temp.join("dist");
        let services = root.join("ovstorage-services");

        for file in SERVICES_RELEASE_ROOT_FILES
            .iter()
            .chain(SERVICES_RELEASE_FILES.iter())
        {
            let path = services.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("{file}\n")).unwrap();
        }
        for dir in SERVICES_RELEASE_DIRS {
            let path = services.join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("KEEP.txt"), format!("{dir}\n")).unwrap();
        }
        fs::create_dir_all(services.join("apis/storage-api/openapi/target")).unwrap();
        fs::write(
            services.join("apis/storage-api/openapi/target/should-not-ship.txt"),
            "build artifact",
        )
        .unwrap();
        fs::create_dir_all(services.join("apis/storage-api/docs/latest")).unwrap();
        fs::write(
            services.join("apis/storage-api/docs/latest/index.html"),
            "generated docs",
        )
        .unwrap();

        copy_ovstorage_services_release_surface(&root, &dist).unwrap();

        assert!(dist.join("services/README.md").exists());
        assert!(dist.join("services/AGENTS.md").exists());
        assert!(dist.join("services/apis/storage-api/LICENSE.txt").exists());
        assert!(
            dist.join("services/apis/storage-api/openapi/KEEP.txt")
                .exists()
        );
        assert!(
            dist.join("services/apis/storage-api/conformance_tests/KEEP.txt")
                .exists()
        );
        assert!(
            !dist
                .join("services/apis/storage-api/openapi/target/should-not-ship.txt")
                .exists()
        );
        assert!(
            dist.join("services/apis/storage-api/docs/latest/index.html")
                .exists()
        );
        assert!(!dist.join("ovstorage-services").exists());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn services_release_surface_requires_license_files() {
        let temp = temp_test_dir("dist-services-missing-license");
        let root = temp.join("root");
        let dist = temp.join("dist");
        let services = root.join("ovstorage-services");

        for file in SERVICES_RELEASE_ROOT_FILES {
            let path = services.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("{file}\n")).unwrap();
        }
        for file in SERVICES_RELEASE_FILES
            .iter()
            .filter(|file| **file != "apis/storage-api/LICENSE.txt")
        {
            let path = services.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("{file}\n")).unwrap();
        }
        for dir in SERVICES_RELEASE_DIRS {
            fs::create_dir_all(services.join(dir)).unwrap();
        }

        let err = copy_ovstorage_services_release_surface(&root, &dist).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("apis/storage-api/LICENSE.txt"),
            "expected missing storage-api LICENSE.txt in error, got: {msg}"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn shipped_markdown_links_are_rewritten_for_dist_docs_layout() {
        let input = concat!(
            "[agent](docs/public/agent/README.md)\n",
            "[mcp](../../docs/public/agent/mcp-tools.md)\n",
            "inline docs/public/GLOSSARY.md\n",
        );

        let rewritten = rewrite_dist_doc_links(input);

        assert!(rewritten.contains("[agent](docs/agent/README.md)"));
        assert!(rewritten.contains("[mcp](../../docs/agent/mcp-tools.md)"));
        assert!(rewritten.contains("inline docs/GLOSSARY.md"));
        assert!(!rewritten.contains("docs/public/"));
    }

    #[test]
    fn dist_copy_rewrites_root_markdown_and_skill_links() {
        let temp = temp_test_dir("dist-link-rewrites");
        let root = temp.join("root");
        let dist = temp.join("dist");
        fs::create_dir_all(root.join("skills/ovstorage-user-read-bytes")).unwrap();
        fs::write(
            root.join("README.md"),
            "[python](docs/public/library-python/README.md)",
        )
        .unwrap();
        fs::write(root.join("LICENSE"), "license docs/public/unchanged").unwrap();
        fs::write(
            root.join("skills/ovstorage-user-read-bytes/SKILL.md"),
            "[mcp](../../docs/public/agent/mcp-tools.md)",
        )
        .unwrap();
        fs::write(root.join("skills/LICENSE.txt"), "cc-by-4.0").unwrap();
        fs::write(root.join("skills/NOTICE.txt"), "nvidia notice").unwrap();
        fs::write(root.join("skills/README.md"), "skills index").unwrap();

        copy_root_dist_files(&root, &dist).unwrap();
        copy_shipped_skills(&root, &dist).unwrap();

        assert_eq!(
            fs::read_to_string(dist.join("README.md")).unwrap(),
            "[python](docs/library-python/README.md)"
        );
        assert_eq!(
            fs::read_to_string(dist.join("LICENSE")).unwrap(),
            "license docs/public/unchanged"
        );
        assert_eq!(
            fs::read_to_string(dist.join("skills/ovstorage-user-read-bytes/SKILL.md")).unwrap(),
            "[mcp](../../docs/agent/mcp-tools.md)"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn bumps_alpha_prerelease_to_next_alpha() {
        assert_eq!(bump("0.1.0a3", "alpha").unwrap(), "0.1.0a4");
    }

    #[test]
    fn release_bump_drops_prerelease_suffix() {
        assert_eq!(bump("0.1.0a3", "release").unwrap(), "0.1.0");
        assert_eq!(bump("0.1.0rc2", "release").unwrap(), "0.1.0");
    }

    #[test]
    fn numeric_bumps_on_prerelease_reset_to_alpha_one() {
        assert_eq!(bump("0.1.0a3", "patch").unwrap(), "0.1.1a1");
        assert_eq!(bump("0.1.0b2", "minor").unwrap(), "0.2.0a1");
        assert_eq!(bump("0.1.0rc1", "major").unwrap(), "1.0.0a1");
    }

    #[test]
    fn numeric_bumps_on_final_versions_stay_final() {
        assert_eq!(bump("0.1.0", "patch").unwrap(), "0.1.1");
        assert_eq!(bump("0.1.0", "minor").unwrap(), "0.2.0");
        assert_eq!(bump("0.1.0", "major").unwrap(), "1.0.0");
    }

    #[test]
    fn final_versions_derive_release_line_and_tags() {
        let version = PyVersion::parse("0.1.0").unwrap();
        assert_eq!(version.release_line_branch(), "release/v0.1");
        assert_eq!(version.final_tag(), "v0.1.0");
        assert_eq!(format!("{}-rc{}", version.final_tag(), 1), "v0.1.0-rc1");
    }

    #[test]
    fn release_open_requires_patch_zero_final_version() {
        let good = PyVersion::parse("0.1.0").unwrap();
        assert!(good.ensure_final().is_ok());
        assert_eq!(good.patch, 0);

        let patch = PyVersion::parse("0.1.1").unwrap();
        assert!(patch.ensure_final().is_ok());
        assert_ne!(patch.patch, 0);

        let prerelease = PyVersion::parse("0.1.0rc1").unwrap();
        assert!(prerelease.ensure_final().is_err());
    }

    #[test]
    fn rc_number_resets_per_patch_version() {
        let v010 = PyVersion::parse("0.1.0").unwrap();
        let v011 = PyVersion::parse("0.1.1").unwrap();
        let tags = ["v0.1.0-rc1", "v0.1.0-rc2", "v0.1.1-rc1"];

        assert_eq!(next_rc_number_for_version(v010, &tags), 3);
        assert_eq!(next_rc_number_for_version(v011, &tags), 2);
        assert_eq!(
            next_rc_number_for_version(PyVersion::parse("0.1.2").unwrap(), &tags),
            1
        );
    }

    #[test]
    fn final_tag_detection_ignores_rc_tags() {
        let version = PyVersion::parse("0.1.0").unwrap();
        assert!(!final_tag_exists(version, &["v0.1.0-rc1"]));
        assert!(final_tag_exists(version, &["v0.1.0"]));
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let unique = format!(
            "ovstorage-xtask-{label}-{}-{}",
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
