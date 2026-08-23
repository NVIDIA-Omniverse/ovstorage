# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that lock in the ``_version`` PEP 440 parsing/bumping rules the
release workflows depend on."""

from pathlib import Path

import pytest

import _version as v
from _repo import TaskError

PYPROJECT_CRLF = (
    "[build-system]\r\n"
    'requires = ["maturin>=1,<2"]\r\n'
    'build-backend = "maturin"\r\n'
    "\r\n"
    "[project]\r\n"
    'name = "ovstorage"\r\n'
    'version = "0.1.0"\r\n'
    'requires-python = ">=3.10"\r\n'
)

PYPROJECT_ALPHA = '[project]\nname = "ovstorage"\nversion = "0.1.0a3"\n'


def test_parses_project_version_with_crlf_line_endings():
    assert v.parse_pyproject_version(PYPROJECT_CRLF) == "0.1.0"


def test_parses_pep440_prerelease_project_versions():
    assert v.parse_pyproject_version(PYPROJECT_ALPHA) == "0.1.0a3"
    assert str(v.PyVersion.parse("0.1.0a3")) == "0.1.0a3"
    assert str(v.PyVersion.parse("0.1.0b2")) == "0.1.0b2"
    assert str(v.PyVersion.parse("0.1.0rc1")) == "0.1.0rc1"


def test_stamps_project_version_with_toml_parser():
    stamped = v.stamp_version(PYPROJECT_CRLF, "0.1.0.dev12+abcdef0")
    assert v.parse_pyproject_version(stamped) == "0.1.0.dev12+abcdef0"
    assert "[project]" in stamped
    assert 'name = "ovstorage"' in stamped


def test_wheel_version_preserves_prerelease_for_explicit_release():
    assert (
        v.compute_wheel_version_value("0.1.0a3", "0.1.0a3", None, "abcdef0", False)
        == "0.1.0a3"
    )


def test_wheel_version_keeps_dev_suffix_for_ci_builds():
    assert (
        v.compute_wheel_version_value("0.1.0a3", None, "42", "abcdef0", False)
        == "0.1.0a3.dev42+abcdef0"
    )


def test_wheel_version_is_clean_for_local_builds():
    assert (
        v.compute_wheel_version_value("0.1.0a3", None, None, "abcdef0", True) == "0.1.0a3"
    )


def test_wheel_version_release_mismatch_errors():
    with pytest.raises(TaskError):
        v.compute_wheel_version_value("0.1.0", "0.2.0", None, "", False)


def test_bumps_alpha_prerelease_to_next_alpha():
    assert v.bump("0.1.0a3", "alpha") == "0.1.0a4"


def test_release_bump_drops_prerelease_suffix():
    assert v.bump("0.1.0a3", "release") == "0.1.0"
    assert v.bump("0.1.0rc2", "release") == "0.1.0"


def test_numeric_bumps_on_prerelease_reset_to_alpha_one():
    assert v.bump("0.1.0a3", "patch") == "0.1.1a1"
    assert v.bump("0.1.0b2", "minor") == "0.2.0a1"
    assert v.bump("0.1.0rc1", "major") == "1.0.0a1"


def test_numeric_bumps_on_final_versions_stay_final():
    assert v.bump("0.1.0", "patch") == "0.1.1"
    assert v.bump("0.1.0", "minor") == "0.2.0"
    assert v.bump("0.1.0", "major") == "1.0.0"


def test_bump_to_explicit_override():
    assert v.bump("0.1.0", "to=9.9.9rc4") == "9.9.9rc4"


def test_unknown_bump_kind_errors():
    with pytest.raises(TaskError):
        v.bump("0.1.0", "nonsense")


def test_final_versions_derive_release_line_and_tags():
    ver = v.PyVersion.parse("0.1.0")
    assert ver.release_line_branch() == "release/v0.1"
    assert ver.final_tag() == "v0.1.0"
    assert f"{ver.final_tag()}-rc{1}" == "v0.1.0-rc1"


def test_ensure_final_accepts_any_patch_and_rejects_a_prerelease():
    v.PyVersion.parse("0.1.0").ensure_final()
    v.PyVersion.parse("0.1.1").ensure_final()

    with pytest.raises(TaskError):
        v.PyVersion.parse("0.1.0rc1").ensure_final()


def _stamped_root(root: Path, version: str) -> Path:
    """A tree carrying nothing but the pyproject the version is read from."""
    pyproject = v.pyproject_path(root)
    pyproject.parent.mkdir(parents=True)
    pyproject.write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    return root


def test_release_open_accepts_a_patch_version(tmp_path):
    """A release line opens from any final version, patch component included.

    `main` carries a patch version when a milestone is renumbered onto a line
    that already shipped. The load-bearing check is that no exception escapes;
    the two assertions below pin why a nonzero patch reaches nothing else.
    """
    pytest.importorskip("tomlkit")
    v.assert_release_open_version(_stamped_root(tmp_path, "0.2.1"))

    version = v.PyVersion.parse("0.2.1")
    assert version.release_line_branch() == "release/v0.2"
    assert str(version.bump_numeric("minor")) == "0.3.0"


def test_release_open_refuses_a_prerelease(tmp_path):
    """The patch component is 0 so only `ensure_final` can produce the refusal."""
    pytest.importorskip("tomlkit")
    with pytest.raises(TaskError, match="must be final"):
        v.assert_release_open_version(_stamped_root(tmp_path, "0.2.0rc1"))


def test_rc_number_resets_per_patch_version():
    v010 = v.PyVersion.parse("0.1.0")
    v011 = v.PyVersion.parse("0.1.1")
    tags = ["v0.1.0-rc1", "v0.1.0-rc2", "v0.1.1-rc1"]
    assert v.next_rc_number_for_version(v010, tags) == 3
    assert v.next_rc_number_for_version(v011, tags) == 2
    assert v.next_rc_number_for_version(v.PyVersion.parse("0.1.2"), tags) == 1


def test_final_tag_detection_ignores_rc_tags():
    ver = v.PyVersion.parse("0.1.0")
    assert not v.final_tag_exists(ver, ["v0.1.0-rc1"])
    assert v.final_tag_exists(ver, ["v0.1.0"])


def test_parse_rejects_too_many_components():
    with pytest.raises(TaskError):
        v.PyVersion.parse("0.1.0.0")


def test_parse_rejects_unsupported_prerelease():
    with pytest.raises(TaskError):
        v.PyVersion.parse("0.1.0dev1")


class TestModuleVersionStaysWithPackageVersion:
    """`ovstorage.__version__` is a literal in the PyO3 module init, so a bump
    that only touches pyproject leaves the extension naming a different release
    than the wheel that contains it. `test_stub_drift.py` catches the drift at
    test time; these pin the bump that causes it."""

    def test_repo_module_literal_matches_pyproject(self):
        assert v.parse_py_module_version(
            v.py_module_path().read_text(encoding="utf-8")
        ) == v.read_pyproject_version()

    def test_stamp_rewrites_the_literal(self):
        body = '    module.add("__version__", "0.2.0")?;\n'
        assert v.stamp_py_module_version(body, "0.3.0") == (
            '    module.add("__version__", "0.3.0")?;\n'
        )

    def test_stamp_without_the_literal_is_an_error(self):
        with pytest.raises(TaskError):
            v.stamp_py_module_version("no version literal here\n", "0.3.0")


def test_cargo_version_uses_numeric_core_for_python_prereleases():
    assert v.cargo_version_for("0.3.0a4") == "0.3.0"
    assert v.cargo_version_for("1.2.3rc2") == "1.2.3"


def test_cargo_release_line_uses_major_and_minor():
    assert v.cargo_release_line_for("0.3.0a4") == "0.3"
    assert v.cargo_release_line_for("1.2.3rc2") == "1.2"


def test_public_crate_requirements_follow_release_line(tmp_path: Path):
    docs = tmp_path / v.PUBLIC_DOCS_REL
    docs.mkdir(parents=True)
    guide = docs / "guide.md"
    guide.write_text(
        'ovstorage = "0.3"\n'
        'ovstorage-plugin = "0.3.0" # public plugin ABI\n'
        'unrelated = "0.3"\n',
        encoding="utf-8",
    )

    changes = v._public_crate_requirement_changes(tmp_path, "0.4.0")

    assert changes[guide] == (
        'ovstorage = "0.4"\n'
        'ovstorage-plugin = "0.4" # public plugin ABI\n'
        'unrelated = "0.3"\n'
    )


def test_stamp_openapi_version_uses_numeric_core():
    source = "openapi: 3.1.0\ninfo:\n  title: ovstorage\n  version: 0.1.0\npaths: {}\n"
    assert "version: 0.3.0" in v.stamp_openapi_version(source, "0.3.0rc2")


def test_stamp_cargo_versions_aligns_packages_and_path_pins(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["published", "fixture"]\n\n'
        '[workspace.package]\nversion = "0.1.0"\n\n'
        '[workspace.dependencies]\n'
        'fixture = { version = "0.1.0", path = "fixture" }\n',
        encoding="utf-8",
    )
    published = tmp_path / "published"
    published.mkdir()
    (published / "Cargo.toml").write_text(
        '[package]\nname = "published"\nversion = "0.1.0"\n\n'
        '[dependencies]\nfixture.workspace = true\n',
        encoding="utf-8",
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "Cargo.toml").write_text(
        '[package]\nname = "fixture"\nversion = "0.0.0"\npublish = false\n',
        encoding="utf-8",
    )

    assert v.stamp_cargo_versions(tmp_path, "0.3.0a1") == 3
    assert 'version = "0.3.0"' in (tmp_path / "Cargo.toml").read_text(
        encoding="utf-8"
    )
    assert (
        'fixture = { version = "0.3.0", path = "fixture" }'
        in (tmp_path / "Cargo.toml").read_text(encoding="utf-8")
    )
    published_text = (published / "Cargo.toml").read_text(encoding="utf-8")
    assert "version.workspace = true" in published_text
    assert "fixture.workspace = true" in published_text
    assert "version.workspace = true" in (fixture / "Cargo.toml").read_text(
        encoding="utf-8"
    )


def test_stamp_cargo_versions_handles_path_before_version_and_multiline(
    tmp_path: Path,
):
    crate = tmp_path / "crate"
    crate.mkdir()
    first = tmp_path / "first"
    first.mkdir()
    second = tmp_path / "second"
    second.mkdir()
    manifest = crate / "Cargo.toml"
    workspace_directories = {first.resolve(), second.resolve()}
    source = """
[dependencies]
first = { path = "../first", optional = true, version = "0.1.0" }

[dev-dependencies.second]
path = "../second"
features = ["test"]
version = "0.1.0"
"""
    stamped = v.stamp_path_dependency_versions(
        source, "0.3.0", manifest, workspace_directories
    )
    assert v.path_dependency_versions(
        stamped, manifest, workspace_directories
    ) == ["0.3.0", "0.3.0"]


def test_workspace_manifests_uses_members_not_default_members(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\ndefault-members = ["default"]\nmembers = ["actual"]\n',
        encoding="utf-8",
    )
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "Cargo.toml").write_text(
        '[package]\nname = "actual"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )

    assert v.workspace_manifests(tmp_path) == [
        tmp_path / "Cargo.toml",
        actual / "Cargo.toml",
    ]


def test_path_dependency_stamping_ignores_metadata_and_external_paths(
    tmp_path: Path,
):
    crate = tmp_path / "crate"
    crate.mkdir()
    member = tmp_path / "member"
    member.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    manifest = crate / "Cargo.toml"
    workspace_directories = {crate.resolve(), member.resolve()}
    source = """
[dependencies]
member = { path = "../member", version = "0.1.0" }
external = { path = "../external", version = "9.9.9" }

[package.metadata.release]
config = { path = "../member", version = "metadata-version" }
"""

    stamped = v.stamp_path_dependency_versions(
        source, "0.3.0", manifest, workspace_directories
    )

    assert 'member = { path = "../member", version = "0.3.0" }' in stamped
    assert 'external = { path = "../external", version = "9.9.9" }' in stamped
    assert (
        'config = { path = "../member", version = "metadata-version" }' in stamped
    )
    assert v.path_dependency_versions(
        stamped, manifest, workspace_directories
    ) == ["0.3.0"]


def test_workspace_manifests_ignore_unlisted_nested_checkout(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crate"]\n\n'
        '[workspace.package]\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    crate = tmp_path / "crate"
    crate.mkdir()
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "crate"\nversion.workspace = true\n',
        encoding="utf-8",
    )
    nested = tmp_path / ".worktrees/other"
    nested.mkdir(parents=True)
    nested_manifest = nested / "Cargo.toml"
    nested_manifest.write_text(
        '[package]\nname = "other"\nversion = "9.9.9"\n',
        encoding="utf-8",
    )

    assert v.workspace_manifests(tmp_path) == [
        tmp_path / "Cargo.toml",
        crate / "Cargo.toml",
    ]
    v.stamp_cargo_versions(tmp_path, "0.3.0")
    assert 'version = "9.9.9"' in nested_manifest.read_text(encoding="utf-8")


def test_stamp_cargo_versions_refreshes_real_lockfile(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crate"]\n\n'
        '[workspace.package]\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    crate = tmp_path / "crate"
    (crate / "src").mkdir(parents=True)
    (crate / "src/lib.rs").write_text("pub fn value() {}\n", encoding="utf-8")
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "crate"\nversion.workspace = true\nedition = "2024"\n',
        encoding="utf-8",
    )
    v.capture(["cargo", "generate-lockfile"], cwd=tmp_path)
    assert 'version = "0.1.0"' in (tmp_path / "Cargo.lock").read_text()

    v.stamp_cargo_versions(tmp_path, "0.3.0", refresh_lock=True)

    assert 'version = "0.3.0"' in (tmp_path / "Cargo.lock").read_text()
    assert 'version = "0.1.0"' not in (tmp_path / "Cargo.lock").read_text()


def test_version_transaction_restores_manifests_and_lock_on_failure(
    tmp_path: Path, monkeypatch
):
    manifest = tmp_path / "Cargo.toml"
    lock = tmp_path / "Cargo.lock"
    manifest.write_text("old manifest\n", encoding="utf-8")
    lock.write_text("old lock\n", encoding="utf-8")

    def fail_after_lock_write(*args, **kwargs):
        lock.write_text("partial lock\n", encoding="utf-8")
        raise TaskError("metadata failed")

    monkeypatch.setattr(v, "capture", fail_after_lock_write)
    with pytest.raises(TaskError, match="metadata failed"):
        v._apply_version_transaction(
            tmp_path,
            {manifest: "new manifest\n"},
            refresh_lock=True,
        )
    assert manifest.read_text(encoding="utf-8") == "old manifest\n"
    assert lock.read_text(encoding="utf-8") == "old lock\n"


def test_version_transaction_refreshes_lock_after_manifest_writes(
    tmp_path: Path, monkeypatch
):
    manifest = tmp_path / "Cargo.toml"
    lock = tmp_path / "Cargo.lock"
    manifest.write_text("old manifest\n", encoding="utf-8")
    lock.write_text("old lock\n", encoding="utf-8")

    def refresh(*args, **kwargs):
        assert manifest.read_text(encoding="utf-8") == "new manifest\n"
        lock.write_text("new lock\n", encoding="utf-8")
        return "{}"

    monkeypatch.setattr(v, "capture", refresh)
    v._apply_version_transaction(
        tmp_path,
        {manifest: "new manifest\n"},
        refresh_lock=True,
    )
    assert lock.read_text(encoding="utf-8") == "new lock\n"
