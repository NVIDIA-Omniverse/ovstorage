# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Release-version logic.

The single source of truth for the version is ``project.version`` in
``ovstorage-core/ovstorage-python/pyproject.toml``. ``tomlkit`` is used for
reads and the in-place version stamp so the file's formatting and comments
survive a bump. The PEP 440 parsing/bumping rules here must stay stable for the
release workflows; ``tests/test_version.py`` locks them in."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from _repo import TaskError, capture, repo_root, require_tool

# `tomlkit` is imported lazily inside the two functions that touch pyproject
# (parse + format-preserving stamp) so importing the ovtasks package — e.g. for
# the stdlib-only lint commands in `make verify` — never requires the dep.

PYPROJECT_REL = "ovstorage-core/ovstorage-python/pyproject.toml"

# The Python extension module reports `ovstorage.__version__` from a literal in
# its PyO3 module init. It cannot read pyproject at build time, and the crate's
# own Cargo version tracks the crate rather than the release, so a bump has to
# rewrite this literal too or the module disagrees with its package metadata.
PY_MODULE_REL = "ovstorage-core/ovstorage-python/src/lib.rs"
OPENAPI_REL = "ovstorage-remote/ovstorage-rest/spec/openapi.yaml"
PUBLIC_DOCS_REL = "docs/public"

# The Rust release version lives in `[workspace.package]`, and every
# intra-workspace dependency pin must name that same numeric version. Python
# prerelease suffixes stay on the wheel/module surfaces because Cargo versions
# use the numeric X.Y.Z core for this workspace.
CARGO_WORKSPACE_REL = "Cargo.toml"
_CARGO_WORKSPACE_VERSION_RE = re.compile(
    r'(\[workspace\.package\]\s*\nversion = ")([^"]*)(")'
)
_TOML_TABLE_RE = re.compile(
    r"(?m)^[ \t]*\[([^\]\n]+)\][ \t]*(?:#.*)?$"
)
_CARGO_WORKSPACE_MEMBERS_RE = re.compile(
    r"(?ms)^[ \t]*members[ \t]*=[ \t]*\[(.*?)\]"
)
_INLINE_TABLE_RE = re.compile(r"\{[^{}]*\}", re.S)
_PATH_FIELD_RE = re.compile(r'\bpath\s*=\s*"([^"]+)"')
_VERSION_FIELD_RE = re.compile(r'(\bversion\s*=\s*")([^"]*)(")')
_PACKAGE_SECTION_RE = re.compile(r'(^\[package\]\s*\n.*?)(?=^\[|\Z)', re.M | re.S)
_PACKAGE_VERSION_RE = re.compile(r'^version = "[^"]+"$', re.M)
_PY_MODULE_VERSION_RE = re.compile(r'(module\.add\(\s*"__version__"\s*,\s*")([^"]*)(")')
_OPENAPI_VERSION_RE = re.compile(r"(^info:\s*\n(?:^[ \t].*\n)*?^  version: )(\S+)", re.M)
_PUBLIC_CRATE_REQUIREMENT_RE = re.compile(
    r'(?m)^(?P<prefix>\s*(?P<crate>ovstorage(?:-[a-z0-9]+)*)\s*=\s*")'
    r"(?P<line>\d+\.\d+)(?:\.\d+)?"
    r'(?P<suffix>"\s*(?:#.*)?)$'
)

_PRE_KINDS = {"a": "a", "b": "b", "rc": "rc"}


@dataclass(frozen=True)
class PreRelease:
    kind: str  # "a", "b", or "rc"
    number: int


@dataclass(frozen=True)
class PyVersion:
    major: int
    minor: int
    patch: int
    pre: PreRelease | None

    @staticmethod
    def parse(version: str) -> "PyVersion":
        parts = version.split(".")
        major = _parse_number_part(parts[0] if len(parts) > 0 else None, "major", version)
        minor = _parse_number_part(parts[1] if len(parts) > 1 else None, "minor", version)
        if len(parts) < 3:
            raise TaskError(f"current version {version} isn't X.Y.Z[preN]")
        if len(parts) > 3:
            raise TaskError(f"current version {version} isn't X.Y.Z[preN]")
        patch_and_pre = parts[2]

        patch_len = len(patch_and_pre)
        for i, ch in enumerate(patch_and_pre):
            if ch not in "0123456789":
                patch_len = i
                break
        if patch_len == 0:
            raise TaskError(f"current version {version} has an invalid patch component")
        patch = int(patch_and_pre[:patch_len])
        suffix = patch_and_pre[patch_len:]
        pre = None if suffix == "" else _parse_pre_release(suffix, version)
        return PyVersion(major, minor, patch, pre)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre is not None:
            base += f"{self.pre.kind}{self.pre.number}"
        return base

    def next_alpha(self) -> "PyVersion":
        if self.pre is not None and self.pre.kind == "a":
            number = self.pre.number + 1
        else:
            number = 1
        return PyVersion(self.major, self.minor, self.patch, PreRelease("a", number))

    def final_release(self) -> "PyVersion":
        return PyVersion(self.major, self.minor, self.patch, None)

    def ensure_final(self) -> None:
        if self.pre is not None:
            raise TaskError(f"release version must be final X.Y.Z, got {self}")

    def release_line_branch(self) -> str:
        return f"release/v{self.major}.{self.minor}"

    def final_tag(self) -> str:
        return f"v{self}"

    def bump_numeric(self, kind: str) -> "PyVersion":
        if kind == "patch":
            major, minor, patch = self.major, self.minor, self.patch + 1
        elif kind == "minor":
            major, minor, patch = self.major, self.minor + 1, 0
        elif kind == "major":
            major, minor, patch = self.major + 1, 0, 0
        else:  # pragma: no cover - guarded by callers
            raise TaskError(f"unknown numeric bump {kind}")
        # Conservative prerelease rule: numeric bumps start the new line at a1.
        pre = PreRelease("a", 1) if self.pre is not None else None
        return PyVersion(major, minor, patch, pre)


def _parse_number_part(part: str | None, label: str, version: str) -> int:
    if part is None:
        raise TaskError(f"current version {version} is missing {label}")
    if part == "" or not all(ch in "0123456789" for ch in part):
        raise TaskError(f"current version {version} has an invalid {label} component")
    return int(part)


def _parse_pre_release(suffix: str, version: str) -> PreRelease:
    if suffix.startswith("rc"):
        kind, number = "rc", suffix[2:]
    elif suffix.startswith("a"):
        kind, number = "a", suffix[1:]
    elif suffix.startswith("b"):
        kind, number = "b", suffix[1:]
    else:
        raise TaskError(f"current version {version} has an unsupported prerelease suffix")
    if number == "" or not all(ch in "0123456789" for ch in number):
        raise TaskError(f"current version {version} has an invalid prerelease number")
    return PreRelease(kind, int(number))


def next_rc_number_for_version(version: PyVersion, tags: list[str]) -> int:
    prefix = f"{version.final_tag()}-rc"
    max_seen = 0
    for tag in tags:
        if not tag.startswith(prefix):
            continue
        suffix = tag[len(prefix):]
        if suffix == "" or not all(ch in "0123456789" for ch in suffix):
            continue
        max_seen = max(max_seen, int(suffix))
    return max_seen + 1


def final_tag_exists(version: PyVersion, tags: list[str]) -> bool:
    return any(tag == version.final_tag() for tag in tags)


def bump(current: str, kind: str) -> str:
    if kind.startswith("to="):
        return kind[3:]
    version = PyVersion.parse(current)
    if kind == "alpha":
        return str(version.next_alpha())
    if kind == "release":
        return str(version.final_release())
    if kind in ("patch", "minor", "major"):
        return str(version.bump_numeric(kind))
    raise TaskError(
        f"unknown bump kind {kind} (want alpha|release|patch|minor|major|to=<v>)"
    )


def compute_wheel_version_value(
    base: str,
    release: str | None,
    github_run: str | None,
    sha: str,
    dirty: bool,
) -> str:
    if release is not None:
        if release != base:
            raise TaskError(
                f"OVSTORAGE_RELEASE_VERSION={release} doesn't match pyproject version {base}"
            )
        return release
    if github_run is not None and github_run != "":
        return f"{base}.dev{github_run}+{sha}"
    _ = (sha, dirty)
    return base


# --- pyproject helpers --------------------------------------------------------


def pyproject_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / PYPROJECT_REL


def parse_pyproject_version(text: str) -> str:
    import tomlkit

    doc = tomlkit.parse(text)
    project = doc.get("project")
    version = project.get("version") if project is not None else None
    if not isinstance(version, str):
        raise TaskError("missing string `project.version` in pyproject.toml")
    return str(version)


def read_pyproject_version(root: Path | None = None) -> str:
    return parse_pyproject_version(pyproject_path(root).read_text(encoding="utf-8"))


def stamp_version(text: str, version: str) -> str:
    import tomlkit

    doc = tomlkit.parse(text)
    project = doc.get("project")
    if project is None:
        raise TaskError("missing `[project]` table in pyproject.toml")
    if not isinstance(project.get("version"), str):
        raise TaskError("missing string `project.version` in pyproject.toml")
    project["version"] = version
    return tomlkit.dumps(doc)


def git_short_sha(root: Path) -> str:
    return capture(
        ["git", "rev-parse", "--short", "HEAD"], cwd=root, label="git rev-parse"
    ).strip()


def compute_wheel_version(root: Path) -> str:
    import os

    base = read_pyproject_version(root)
    release = os.environ.get("OVSTORAGE_RELEASE_VERSION")
    if release is not None and release.strip() != "":
        return compute_wheel_version_value(base, release.strip(), None, "", False)
    run = os.environ.get("GITHUB_RUN_NUMBER")
    if run:
        sha = git_short_sha(root)
        return compute_wheel_version_value(base, None, run, sha, False)
    return compute_wheel_version_value(base, None, None, "", False)


# --- command entry points -----------------------------------------------------


def _current(root: Path | None = None) -> PyVersion:
    return PyVersion.parse(read_pyproject_version(root))


def _current_final() -> PyVersion:
    v = _current()
    v.ensure_final()
    return v


def print_release_version() -> None:
    print(read_pyproject_version())


def assert_release_open_version(root: Path | None = None) -> None:
    """Assert ``main`` carries a version a release line can be opened from.

    The version must be **final**. ``bump_numeric("minor")`` carries a
    prerelease across, so opening a line from ``0.2.1rc1`` would leave
    ``release-finalize`` stamping ``main`` with ``0.3.0a1``, which
    ``release-candidate`` would then refuse on the next cycle.

    **Any patch component is accepted.** ``X.Y`` alone names the release line
    (:meth:`PyVersion.release_line_branch`).  ``main`` carries a nonzero patch
    when a milestone is renumbered onto a line that has already shipped (e.g.
    ``0.2.1`` targets ``release/v0.2``); ``release-finalize`` zeroes the patch
    by advancing ``main`` to the next minor after publishing.

    On the advance path (``advance_existing_line=true``), the existing branch
    is a precondition rather than a refusal: ``release-open`` will merge
    ``main`` into it.  See the release runbook for Operation A vs B.
    """
    v = _current(root)
    v.ensure_final()
    print(v)


def print_release_line_branch() -> None:
    print(_current_final().release_line_branch())


def print_next_minor_version() -> None:
    print(_current_final().bump_numeric("minor"))


def print_next_patch_version() -> None:
    print(_current_final().bump_numeric("patch"))


def print_final_release_tag() -> None:
    print(_current_final().final_tag())


def print_next_rc_number(tags: list[str]) -> None:
    print(next_rc_number_for_version(_current_final(), tags))


def assert_final_tag_absent(tags: list[str]) -> None:
    v = _current_final()
    if final_tag_exists(v, tags):
        raise TaskError(f"final tag {v.final_tag()} already exists")
    print(f"{v.final_tag()} absent")


def py_module_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / PY_MODULE_REL


def parse_py_module_version(text: str) -> str:
    match = _PY_MODULE_VERSION_RE.search(text)
    if match is None:
        raise TaskError(f"missing `module.add(\"__version__\", ...)` literal in {PY_MODULE_REL}")
    return match.group(2)


def stamp_py_module_version(text: str, version: str) -> str:
    stamped, count = _PY_MODULE_VERSION_RE.subn(rf"\g<1>{version}\g<3>", text, count=1)
    if count != 1:
        raise TaskError(f"missing `module.add(\"__version__\", ...)` literal in {PY_MODULE_REL}")
    return stamped


def stamp_openapi_version(text: str, version: str) -> str:
    cargo_version = cargo_version_for(version)
    stamped, count = _OPENAPI_VERSION_RE.subn(
        rf"\g<1>{cargo_version}", text, count=1
    )
    if count != 1:
        raise TaskError(f"missing `info.version` in {OPENAPI_REL}")
    return stamped


def cargo_version_for(python_version: str) -> str:
    """Return the numeric Cargo spelling of a Python release version."""
    parsed = PyVersion.parse(python_version)
    return f"{parsed.major}.{parsed.minor}.{parsed.patch}"


def cargo_release_line_for(python_version: str) -> str:
    """Return the Cargo ``X.Y`` requirement for a Python release version."""
    parsed = PyVersion.parse(python_version)
    return f"{parsed.major}.{parsed.minor}"


def _public_crate_requirement_changes(
    root: Path, version: str
) -> dict[Path, str]:
    """Compute public Rust dependency rewrites without changing the checkout."""
    release_line = cargo_release_line_for(version)
    changes: dict[Path, str] = {}
    for document in sorted((root / PUBLIC_DOCS_REL).rglob("*.md")):
        original = document.read_text(encoding="utf-8")
        rewritten = _PUBLIC_CRATE_REQUIREMENT_RE.sub(
            lambda match: (
                f"{match.group('prefix')}{release_line}{match.group('suffix')}"
            ),
            original,
        )
        if rewritten != original:
            changes[document] = rewritten
    return changes


def workspace_manifests(root: Path) -> list[Path]:
    """Return exactly the manifests named by the root workspace."""
    workspace = root / CARGO_WORKSPACE_REL
    text = workspace.read_text(encoding="utf-8")
    tables = list(_TOML_TABLE_RE.finditer(text))
    workspace_table = next(
        (table for table in tables if table.group(1).strip() == "workspace"), None
    )
    if workspace_table is None:
        raise TaskError(f"no `[workspace] members` found in {CARGO_WORKSPACE_REL}")
    table_index = tables.index(workspace_table)
    table_end = (
        tables[table_index + 1].start()
        if table_index + 1 < len(tables)
        else len(text)
    )
    match = _CARGO_WORKSPACE_MEMBERS_RE.search(
        text, workspace_table.end(), table_end
    )
    if match is None:
        raise TaskError(f"no `[workspace] members` found in {CARGO_WORKSPACE_REL}")
    members = re.findall(r'"([^"]+)"', match.group(1))
    if not members:
        raise TaskError(f"`[workspace] members` is empty in {CARGO_WORKSPACE_REL}")
    manifests = [workspace]
    for member in members:
        if any(character in member for character in "*?["):
            raise TaskError(
                f"workspace member globs are unsupported by the version stamper: {member}"
            )
        manifest = root / member / "Cargo.toml"
        if not manifest.is_file():
            raise TaskError(f"workspace member has no manifest: {manifest}")
        manifests.append(manifest)
    return manifests


_DEPENDENCY_SECTION_NAMES = ("dependencies", "dev-dependencies", "build-dependencies")


def _dependency_table_kind(table: str) -> str | None:
    """Classify a Cargo dependency table as ``parent`` or ``detailed``."""
    table = table.strip()
    for section in _DEPENDENCY_SECTION_NAMES:
        for prefix in ("", "workspace."):
            base = f"{prefix}{section}"
            if table == base:
                return "parent"
            if table.startswith(f"{base}."):
                return "detailed"
        target_marker = f".{section}"
        if table.startswith("target.") and target_marker in table:
            suffix = table.rsplit(target_marker, 1)[1]
            if suffix == "":
                return "parent"
            if suffix.startswith("."):
                return "detailed"
    return None


def _dependency_spec_spans(text: str) -> list[tuple[int, int]]:
    """Return only inline and detailed Cargo dependency-spec spans."""
    tables = list(_TOML_TABLE_RE.finditer(text))
    spans: list[tuple[int, int]] = []
    for index, table in enumerate(tables):
        table_kind = _dependency_table_kind(table.group(1))
        if table_kind is None:
            continue
        body_start = table.end()
        body_end = tables[index + 1].start() if index + 1 < len(tables) else len(text)
        if table_kind == "detailed":
            spans.append((body_start, body_end))
            continue
        spans.extend(
            (match.start(), match.end())
            for match in _INLINE_TABLE_RE.finditer(text, body_start, body_end)
        )
    return spans


def _workspace_dependency_path(
    spec: str, manifest: Path, workspace_directories: set[Path]
) -> bool:
    path = _PATH_FIELD_RE.search(spec)
    return path is not None and (
        manifest.parent / path.group(1)
    ).resolve() in workspace_directories


def path_dependency_versions(
    text: str, manifest: Path, workspace_directories: set[Path]
) -> list[str]:
    """Return version pins for path dependencies to workspace members."""
    versions: list[str] = []
    for start, end in _dependency_spec_spans(text):
        spec = text[start:end]
        version = _VERSION_FIELD_RE.search(spec)
        if _workspace_dependency_path(spec, manifest, workspace_directories) and (
            version is not None
        ):
            versions.append(version.group(2))
    return versions


def stamp_path_dependency_versions(
    text: str, version: str, manifest: Path, workspace_directories: set[Path]
) -> str:
    """Stamp version pins for path dependencies to workspace members."""
    replacements: list[tuple[int, int]] = []
    for start, end in _dependency_spec_spans(text):
        spec = text[start:end]
        version_match = _VERSION_FIELD_RE.search(spec)
        if _workspace_dependency_path(spec, manifest, workspace_directories) and (
            version_match is not None
        ):
            replacements.append(
                (
                    start + version_match.start(2),
                    start + version_match.end(2),
                )
            )
    for start, end in reversed(replacements):
        text = f"{text[:start]}{version}{text[end:]}"
    return text


def package_uses_own_version(text: str) -> bool:
    package = _PACKAGE_SECTION_RE.search(text)
    return package is not None and _PACKAGE_VERSION_RE.search(package.group(1)) is not None


def _cargo_version_changes(root: Path, version: str) -> dict[Path, str]:
    """Compute every Cargo manifest rewrite without changing the checkout."""
    cargo_version = cargo_version_for(version)
    workspace = root / CARGO_WORKSPACE_REL
    text = workspace.read_text(encoding="utf-8")
    stamped, count = _CARGO_WORKSPACE_VERSION_RE.subn(
        lambda match: f"{match.group(1)}{cargo_version}{match.group(3)}",
        text,
        count=1,
    )
    if count != 1:
        raise TaskError(
            f"no `[workspace.package] version` found in {CARGO_WORKSPACE_REL}"
        )
    manifests = workspace_manifests(root)
    workspace_directories = {manifest.parent.resolve() for manifest in manifests}
    stamped = stamp_path_dependency_versions(
        stamped, cargo_version, workspace, workspace_directories
    )
    changes = {workspace: stamped}

    for manifest in manifests:
        if manifest == workspace:
            continue
        original = manifest.read_text(encoding="utf-8")
        rewritten = original
        package = _PACKAGE_SECTION_RE.search(rewritten)
        if package is not None and _PACKAGE_VERSION_RE.search(package.group(1)):
            updated_package = _PACKAGE_VERSION_RE.sub(
                "version.workspace = true", package.group(1), count=1
            )
            rewritten = (
                rewritten[: package.start(1)]
                + updated_package
                + rewritten[package.end(1) :]
            )
        rewritten = stamp_path_dependency_versions(
            rewritten, cargo_version, manifest, workspace_directories
        )
        if rewritten != original:
            changes[manifest] = rewritten
    return changes


def _write_atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    try:
        if path.exists():
            os.chmod(temporary, path.stat().st_mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_atomic(path: Path, text: str) -> None:
    _write_atomic_bytes(path, text.encode("utf-8"))


def _apply_version_transaction(
    root: Path,
    changes: dict[Path, str],
    *,
    refresh_lock: bool,
) -> None:
    """Apply precomputed contents and restore every file if any step fails."""
    lock = root / "Cargo.lock"
    tracked = set(changes)
    if refresh_lock:
        tracked.add(lock)
    originals = {
        path: (path.read_bytes(), path.stat().st_mode) if path.exists() else None
        for path in tracked
    }
    try:
        for path, text in changes.items():
            _write_atomic(path, text)
        if refresh_lock:
            require_tool(
                "cargo", "install the Rust toolchain from rust-toolchain.toml"
            )
            capture(
                ["cargo", "update", "--workspace", "--offline"],
                cwd=root,
                label="cargo update --workspace --offline",
            )
    except Exception:
        for path, state in originals.items():
            if state is None:
                path.unlink(missing_ok=True)
            else:
                original, mode = state
                _write_atomic_bytes(path, original)
                os.chmod(path, mode)
        raise


def stamp_cargo_versions(
    root: Path, version: str, *, refresh_lock: bool = False
) -> int:
    """Atomically stamp Cargo manifests and refresh ``Cargo.lock``."""
    changes = _cargo_version_changes(root, version)
    _apply_version_transaction(root, changes, refresh_lock=refresh_lock)
    return len(changes)


def bump_release_version(kind: str) -> None:
    root = repo_root()
    path = pyproject_path()
    original = path.read_text(encoding="utf-8")
    current = parse_pyproject_version(original)
    nxt = bump(current, kind)

    # Stamp every language surface from the same source version.
    module = py_module_path()
    module_original = module.read_text(encoding="utf-8")
    module_stamped = stamp_py_module_version(module_original, nxt)

    openapi = root / OPENAPI_REL
    changes = _cargo_version_changes(root, nxt)
    changes.update(_public_crate_requirement_changes(root, nxt))
    changes.update(
        {
            path: stamp_version(original, nxt),
            module: module_stamped,
            openapi: stamp_openapi_version(
                openapi.read_text(encoding="utf-8"), nxt
            ),
        }
    )
    _apply_version_transaction(root, changes, refresh_lock=True)
    manifests = sum(path.name == "Cargo.toml" for path in changes)
    print(
        f"{current} -> {nxt} "
        f"(Rust {cargo_version_for(nxt)}; {manifests} manifest(s))"
    )
