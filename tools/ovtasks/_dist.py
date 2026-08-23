# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ovtasks dist`` -- build, then assemble a self-contained ``dist/`` at the
repo root: binaries adjacent to a ``plugins/`` directory the CLI's
``default_plugin_dir()`` finds via ``<exe-dir>/plugins/``.

Also drives the Python wheel (maturin) and the per-platform release archive.
Artifacts come from the single workspace ``target/<profile>/``.

The C/C++ surface ships as exactly one thing: the standalone
``ovstorage-c-source/`` tree, copied wholesale to ``dist/c-source/``. Sources,
headers and example build files stay together there, which is the only layout
that can be built — the headers alone are not usable, because the archive
carries no compiled library to link them against.

That is why there is no flat ``dist/include/`` and no ``dist/lib/``. Both
described a consumption model the archive does not support: a prebuilt
``libovstorage`` to link and headers to include against it. Shipping headers
without their implementation would leave a directory that looks linkable and
is not, and duplicate every header already present under ``c-source/``."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import _release_platforms
import _version
from _repo import (
    TaskError,
    dll_filename,
    exe_filename,
    repo_root,
    require_tool,
    run,
)

# Binary names shipped at the dist root.
BINARIES = ("ovstorage", "ovstorage-broker", "ovstorage-rest")

# Default host config templates (RFC-0066). The hosts declare their Stack
# as data and refuse to start (broker/REST) or start empty (CLI/MCP) with no
# `[ovstorage.layers]`, so a fresh install needs a copyable starting stack.
# Each ships into `dist/config/` under its own name. Values are repo-relative
# source paths; the basename is preserved in the dist tree.
CONFIG_FILES = (
    "ovstorage-core/ovstorage-cli/ovstorage-cli.toml",
    "ovstorage-core/ovstorage-mcp/ovstorage-mcp.toml",
    "ovstorage-remote/ovstorage-broker/ovstorage-broker.toml",
    "ovstorage-remote/ovstorage-rest/ovstorage-rest.toml",
)

# Public Layer cdylibs ship in `dist/plugins/`; hosts dlopen backend, wrapper,
# and router factories from this directory. Authz is a private built-in Layer, not a
# separate cdylib. `ovstorage-plugin-test-abi` (the conformance backend's cdylib
# export) ships too (test_only) so consumers can opt in to the conformance
# fixture. Values are cargo package names; the cdylib filename replaces '-'
# with '_'.
PLUGINS = (
    "ovstorage-plugin-core-abi",
    "ovstorage-plugin-cache-abi",
    "ovstorage-plugin-http-abi",
    "ovstorage-plugin-test-abi",
    "ovstorage-plugin-services-client",
    "ovstorage-plugin-s3",
    "ovstorage-plugin-gcs",
    "ovstorage-plugin-azure",
    "ovstorage-plugin-opendal",
    "ovstorage-plugin-nucleus",
    "ovstorage-plugin-broker",
)

PLUGIN_ARTIFACT_STEMS = {
    "ovstorage-plugin-core-abi": "ovstorage_plugin_core",
    "ovstorage-plugin-cache-abi": "ovstorage_plugin_cache",
    "ovstorage-plugin-http-abi": "ovstorage_plugin_http",
}

# The conformance fixture is `test_only`: hosts refuse it unless a caller opts
# in, so it has no place in a public wheel. Everything else in `PLUGINS` is
# bundled by default -- dropping a plugin out is a decision made here, not an
# omission made by forgetting to add it.
WHEEL_PLUGIN_EXCLUDES = ("ovstorage-plugin-test-abi",)
WHEEL_PLUGINS = tuple(p for p in PLUGINS if p not in WHEEL_PLUGIN_EXCLUDES)
WHEEL_PLUGIN_INVENTORY = "inventory.json"

ROOT_DIST_FILES = ("AGENTS.md", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md")
ARCHIVE_MANIFEST_FILE = _release_platforms.MANIFEST_NAME
# `wheels` is deliberately absent: the wheel is built beside the staging tree
# and published as its own release asset, not carried inside the archive.
DIST_DIRECTORIES = (
    "plugins",
    "config",
    "docs",
    "skills",
    "services",
    "c-source",
)
VERSION_FILE = "VERSION"

# LICENSE / NOTICES staged into the Python crate dir at wheel-build time so
# maturin can include them (it can't reach above pyproject.toml's parent).
WHEEL_STAGED_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.md")
PYTHON_CRATE_DIR = "ovstorage-core/ovstorage-python"

# Example consumer code, as directory names under `ovstorage-core/examples`.
# C/C++ examples remain inside the standalone `c-source/` tree so their
# headers, sources, and build files stay together.
EXAMPLES = ("python",)

C_SOURCE_DIR = "ovstorage-c-source"

SHIPPED_SKILL_PREFIXES = ("ovstorage-user-", "ovstorage-operator-")
# CC BY 4.0 requires the license text + grant accompany the material.
SHIPPED_SKILL_ROOT_FILES = ("LICENSE.txt", "NOTICE.txt", "README.md")

SERVICES_RELEASE_ROOT_FILES = ("README.md", "AGENTS.md")
SERVICES_RELEASE_FILES = (
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
)
SERVICES_RELEASE_DIRS = (
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
)

# Dev/build artifacts that must not ship in the release archive.
EXCLUDE_DIRS = (
    "build",
    "target",
    "__pycache__",
    "node_modules",
    ".cache",
    ".claude",
)


# --- top-level commands -------------------------------------------------------


def run_dist(release: bool, wheel: bool) -> None:
    root = repo_root()
    _cargo_build(root, release)
    dist = root / "dist"
    _assemble(root, dist, release, wheel)
    _summarize(dist, wheel)


def release_archive(release: bool, platform: str) -> None:
    root = repo_root()
    if platform == "auto":
        platform = _release_platforms.detect_local(root)
    platform_record = _release_platforms.by_id(platform, root)
    _release_platforms.validate_host(platform_record)
    source_sha, source_dirty = _release_platforms.source_identity(
        root,
        ignored_input_paths=_release_input_paths(),
    )
    if source_dirty:
        raise TaskError(
            "release archive requires a clean tracked checkout; commit or stash "
            "the reported changes before packaging"
        )
    _cargo_build(root, release)
    version = _version.read_pyproject_version(root)
    stem = f"ovstorage-v{version}-{platform}"
    dist = root / "dist"
    staging = dist / stem
    # The wheel is built into `dist/wheels/`, a sibling of the staging tree
    # rather than a child of it, so the archive does not carry it. The archive
    # already ships every plugin under `plugins/`; a wheel that bundles the same
    # cdylibs would ship all of them a second time, and a `.whl` is already
    # deflated, so the archive would grow by the whole plugin payload. The wheel
    # is published as its own release asset instead.
    _assemble(root, staging, release, wheel=False)
    _build_wheel(root, dist, release)
    wheel = _resolve_single_wheel(dist / "wheels")
    _release_platforms.verify_staging(staging, platform_record)
    _release_platforms.verify_wheel(
        wheel,
        staging,
        platform_record,
        expected=wheel_plugin_filenames(),
        inventory_name=WHEEL_PLUGIN_INVENTORY,
    )
    _release_platforms.write_manifest(
        staging,
        version=version,
        platform_id=platform,
        source_sha=source_sha,
        source_dirty=source_dirty,
        root=root,
    )
    _summarize(staging, True, wheels_dir=dist / "wheels")
    print(f"wheel: {wheel}")

    if platform_record["archive_format"] == "zip":
        archive = dist / f"{stem}.zip"
        tar_args = ["tar", "-a", "-cf", str(archive), "-C", str(dist), stem]
    elif platform_record["archive_format"] == "tar.gz":
        archive = dist / f"{stem}.tar.gz"
        tar_args = ["tar", "-czf", str(archive), "-C", str(dist), stem]
    else:
        raise TaskError(
            f"unsupported archive format {platform_record['archive_format']!r}"
        )
    if archive.exists():
        archive.unlink()
    run(tar_args, label="tar (required for release-archive)")
    _release_platforms.verify_archive(
        archive,
        expected_version=version,
        expected_platform=platform,
        expected_source_sha=source_sha,
    )
    print(f"archive: {archive}")


def _release_input_paths() -> tuple[str, ...]:
    example_paths = tuple(
        f"ovstorage-core/examples/{example}" for example in EXAMPLES
    )
    return (*_release_platforms.DEFAULT_RELEASE_INPUT_PATHS, *example_paths)


def wheel_only(release: bool) -> None:
    root = repo_root()
    dist = root / "dist"
    wheels = dist / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    # The wheel bundles cdylibs out of `target/<profile>/`, so they have to
    # exist before it is packaged. `run_dist` builds the workspace already;
    # this entry point did not.
    _cargo_build(root, release)
    _build_wheel(root, dist, release)
    print(f"{_count_wheels(wheels)} wheel(s) at {wheels}")


# --- assembly -----------------------------------------------------------------


def _cargo_build(root: Path, release: bool) -> None:
    base = ["cargo", "build"]
    if release:
        base.append("--release")

    run(base + ["--workspace"], cwd=root, label="cargo build --workspace")


def _assemble(root: Path, dist: Path, release: bool, wheel: bool) -> None:
    if dist.exists():
        shutil.rmtree(dist)
    dist.mkdir(parents=True, exist_ok=True)
    for directory in DIST_DIRECTORIES:
        (dist / directory).mkdir(parents=True, exist_ok=True)

    profile = "release" if release else "debug"
    target = root / "target" / profile

    for binary in BINARIES:
        name = exe_filename(binary)
        _copy_artifact(target / name, dist / name)

    plugins_dir = dist / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    for plugin in PLUGINS:
        so = dll_filename(PLUGIN_ARTIFACT_STEMS.get(plugin, plugin.replace("-", "_")))
        _copy_artifact(target / so, plugins_dir / so)

    _copy_config_templates(root, dist)
    _copy_public_docs(root, dist)
    _copy_shipped_skills(root, dist)
    _copy_services_release_surface(root, dist)

    if EXAMPLES:
        examples_dir = dist / "examples"
        examples_dir.mkdir(parents=True, exist_ok=True)
        for ex in EXAMPLES:
            _copy_dir_recursive(root / "ovstorage-core/examples" / ex, examples_dir / ex)

    _copy_dir_recursive(root / C_SOURCE_DIR, dist / "c-source")

    _copy_root_dist_files(root, dist)

    version = _version.read_pyproject_version(root)
    (dist / VERSION_FILE).write_text(f"{version}\n", encoding="utf-8")

    if wheel:
        _build_wheel(root, dist, release)


def _summarize(dist: Path, wheel: bool, wheels_dir: Path | None = None) -> None:
    print(f"dist/ assembled at {dist}")
    print(f"  binaries:  {len(BINARIES)} bin")
    print(f"  plugins:   {len(PLUGINS)} cdylib in plugins/ ({len(WHEEL_PLUGINS)} in the wheel)")
    print(f"  config:    {len(CONFIG_FILES)} template(s) in config/")
    print("  docs:      copied from docs/public/")
    print("  services:  copied filtered ovstorage-services surface into services/")
    if EXAMPLES:
        print(f"  examples:  {len(EXAMPLES)} in examples/")
    print("  c-source:  copied wholesale into c-source/ (headers + sources)")
    print(f"  skills:    {_count_shipped_skills(dist)} in skills/")
    # `wheels_dir` is explicit because the release archive builds its wheel into
    # a sibling directory, not into the staging tree being summarized here.
    if wheel:
        wheels = dist / "wheels" if wheels_dir is None else wheels_dir
        print(f"  wheels:    {_count_wheels(wheels)} whl at {wheels}")


def _copy_config_templates(root: Path, dist: Path) -> None:
    config_dir = dist / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    for rel in CONFIG_FILES:
        src = root / rel
        if not src.exists():
            raise TaskError(
                f"dist requires missing default config template {src}"
            )
        _copy_artifact(src, config_dir / src.name)


def _copy_public_docs(root: Path, dist: Path) -> None:
    _copy_dir_recursive(root / "docs/public", dist / "docs")


def _copy_shipped_skills(root: Path, dist: Path) -> int:
    skills_root = root / "skills"
    if not skills_root.exists():
        return 0
    dist_skills = dist / "skills"
    count = 0
    for entry in sorted(skills_root.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        name = entry.name
        if not any(name.startswith(p) for p in SHIPPED_SKILL_PREFIXES):
            continue
        if not (entry / "SKILL.md").exists():
            continue
        _copy_skill_dir(entry, dist_skills / name)
        count += 1
    # Only stage the CC BY 4.0 license + notice when at least one skill shipped.
    if count > 0:
        dist_skills.mkdir(parents=True, exist_ok=True)
        for file in SHIPPED_SKILL_ROOT_FILES:
            src = skills_root / file
            if not src.exists():
                raise TaskError(
                    f"skills ship under CC BY 4.0 but {src} is missing — the release "
                    "archive would omit the license text required by the license"
                )
            _copy_artifact(src, dist_skills / file)
    return count


def _copy_services_release_surface(root: Path, dist: Path) -> None:
    source_root = root / "ovstorage-services"
    if not source_root.exists():
        return
    target_root = dist / "services"
    target_root.mkdir(parents=True, exist_ok=True)
    for file in (*SERVICES_RELEASE_ROOT_FILES, *SERVICES_RELEASE_FILES):
        _copy_required_services_file(source_root, target_root, file)
    for d in SERVICES_RELEASE_DIRS:
        src = source_root / d
        if not src.exists():
            raise TaskError(
                f"ovstorage-services release surface requires missing directory {src}"
            )
        _copy_dir_recursive(src, target_root / d)


def _copy_required_services_file(source_root: Path, target_root: Path, file: str) -> None:
    src = source_root / file
    if not src.exists():
        raise TaskError(
            f"ovstorage-services release surface requires missing file {src}"
        )
    dst = target_root / file
    dst.parent.mkdir(parents=True, exist_ok=True)
    _copy_artifact(src, dst)


def _copy_root_dist_files(root: Path, dist: Path) -> None:
    dist.mkdir(parents=True, exist_ok=True)
    for file in ROOT_DIST_FILES:
        src = root / file
        if not src.exists():
            continue
        dst = dist / file
        if _is_markdown(src):
            _copy_markdown_with_rewrites(src, dst)
        else:
            _copy_artifact(src, dst)


def _copy_skill_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in sorted(os.scandir(src), key=lambda e: e.name):
        name = entry.name
        if entry.is_dir(follow_symlinks=False) and name in EXCLUDE_DIRS:
            continue
        src_path = Path(entry.path)
        dst_path = dst / name
        if entry.is_dir(follow_symlinks=False):
            _copy_skill_dir(src_path, dst_path)
        elif entry.is_file(follow_symlinks=False):
            if _is_markdown(src_path):
                _copy_markdown_with_rewrites(src_path, dst_path)
            else:
                _copy_artifact(src_path, dst_path)
        # Skip symlinks deliberately; none in skills today.


def _copy_dir_recursive(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in sorted(os.scandir(src), key=lambda e: e.name):
        name = entry.name
        if entry.is_dir(follow_symlinks=False) and name in EXCLUDE_DIRS:
            continue
        src_path = Path(entry.path)
        dst_path = dst / name
        if entry.is_dir(follow_symlinks=False):
            _copy_dir_recursive(src_path, dst_path)
        elif entry.is_file(follow_symlinks=False):
            _copy_artifact(src_path, dst_path)
        # Skip symlinks deliberately; none in docs/examples today.


def _copy_markdown_with_rewrites(src: Path, dst: Path) -> None:
    body = src.read_text(encoding="utf-8")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(_rewrite_dist_doc_links(body), encoding="utf-8")


def _rewrite_dist_doc_links(markdown: str) -> str:
    return (
        markdown.replace("docs/public/", "docs/")
        .replace("ovstorage-core/examples/", "examples/")
        .replace("ovstorage-c-source/", "c-source/")
    )


def _is_markdown(path: Path) -> bool:
    return path.suffix.lower() == ".md"


def _copy_artifact(src: Path, dst: Path) -> None:
    try:
        shutil.copy2(src, dst)
    except OSError as err:
        raise TaskError(f"copy {src} -> {dst}: {err}") from err


def _count_shipped_skills(dist: Path) -> int:
    skills = dist / "skills"
    if not skills.exists():
        return 0
    return sum(1 for e in skills.iterdir() if e.is_dir())


def _count_wheels(wheels: Path) -> int:
    if not wheels.exists():
        return 0
    return sum(1 for e in wheels.iterdir() if e.suffix == ".whl")


def _resolve_single_wheel(wheels: Path) -> Path:
    found = sorted(wheels.glob("*.whl"))
    if len(found) != 1:
        raise TaskError(
            f"expected exactly one wheel in {wheels}, found {len(found)}"
        )
    return found[0]


# --- wheel --------------------------------------------------------------------


def _build_wheel(root: Path, dist: Path, release: bool) -> None:
    require_tool("maturin", "make install-tools")
    manifest_dir = root / PYTHON_CRATE_DIR
    pyproject = manifest_dir / "pyproject.toml"
    manifest = manifest_dir / "Cargo.toml"
    wheels = dist / "wheels"
    # Cleared, not just created: this directory is a sibling of the release
    # staging tree, so nothing else removes it between runs and maturin would
    # otherwise accumulate one wheel per version built here.
    if wheels.exists():
        shutil.rmtree(wheels)
    wheels.mkdir(parents=True, exist_ok=True)

    _stage_wheel_files(root, manifest_dir)

    # Resolved before staging so the inventory can record it, and before the
    # rewrite below because it reads the unstamped pyproject.toml.
    version = _version.compute_wheel_version(root)

    try:
        # Inside the guard, not before it: a staging run that fails partway --
        # a missing `target/<profile>` artifact after some libraries are already
        # copied -- would otherwise leave a partial directory with no
        # inventory, which a later hand-run `maturin build` would package.
        _stage_wheel_plugins(root, manifest_dir, release, version)
        original = pyproject.read_text(encoding="utf-8")
        # The guard opens before the stamping write, not after it: a write that
        # truncates and then fails, or anything raising between the write and
        # the build, would otherwise leave the tracked file stamped. A modified
        # pyproject.toml blocks the next `release_archive`, which requires a
        # clean tracked checkout.
        try:
            pyproject.write_text(
                _version.stamp_version(original, version), encoding="utf-8"
            )
            print(f"stamped wheel version: {version}")
            _run_maturin(manifest, wheels, release)
        finally:
            # Restore pyproject.toml even on failure so a dev's tree is left clean.
            pyproject.write_text(original, encoding="utf-8")
    finally:
        # Unstage in an outer block, and never let a failure here mask the
        # pyproject.toml restoration above: Windows refuses to unlink a DLL that
        # is still loaded, and a modified tracked file would block the next
        # `release_archive` run, which requires a clean tracked checkout.
        staged = manifest_dir / "ovstorage" / "plugins"
        # Guarded rather than blanket-ignored: a directory that was never
        # created is not a problem worth a warning, but a directory that
        # refuses to go away is.
        if staged.exists():
            try:
                shutil.rmtree(staged)
            except OSError as err:
                print(f"warning: could not unstage wheel plugins: {err}")


def _stage_wheel_files(root: Path, manifest_dir: Path) -> None:
    for name in WHEEL_STAGED_FILES:
        try:
            shutil.copy2(root / name, manifest_dir / name)
        except OSError as err:
            raise TaskError(f"stage {root / name} -> {manifest_dir / name}: {err}") from err


def wheel_plugin_filenames() -> tuple[str, ...]:
    """Library filenames the wheel bundles, for this host's platform.

    The package-name-to-stem mapping is not a plain hyphen substitution --
    `PLUGIN_ARTIFACT_STEMS` renames the three `-abi` crates -- so this is the
    one place that knows how to spell a bundled plugin's filename. Callers that
    re-derive names themselves get `libovstorage_plugin_core_abi.so`, which no
    build produces.
    """
    return tuple(
        dll_filename(PLUGIN_ARTIFACT_STEMS.get(plugin, plugin.replace("-", "_")))
        for plugin in WHEEL_PLUGINS
    )


def _stage_wheel_plugins(
    root: Path, manifest_dir: Path, release: bool, version: str
) -> None:
    """Copy the bundled cdylibs and an inventory into the Python package tree.

    Unlike `WHEEL_STAGED_FILES`, which persist after a build, these are removed
    again by `_build_wheel` -- they are build outputs, not source.
    """
    target = root / "target" / ("release" if release else "debug")
    staged = manifest_dir / "ovstorage" / "plugins"
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True, exist_ok=True)

    entries = []
    for name in wheel_plugin_filenames():
        _copy_artifact(target / name, staged / name)
        entries.append({"filename": name, "sha256": _sha256(staged / name)})

    inventory = {
        "schema_version": 1,
        "version": version,
        "plugins": entries,
    }
    (staged / WHEEL_PLUGIN_INVENTORY).write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_maturin(manifest: Path, wheels: Path, release: bool) -> None:
    args = ["maturin", "build", "--manifest-path", str(manifest), "--out", str(wheels)]
    if release:
        args.append("--release")
    completed = subprocess.run(args)
    if completed.returncode != 0:
        raise TaskError("maturin build failed")
