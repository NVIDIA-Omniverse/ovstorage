# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Canonical release platforms and self-verifying archive manifests."""

from __future__ import annotations

import ast
import hashlib
import json
import platform as host_platform
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO

from _repo import TaskError, capture, repo_root

REGISTRY = Path("tools/ovtasks/release_platforms.json")
PLATFORM_DOC = Path("docs/public/platform-support.md")
MANIFEST_NAME = "release-manifest.json"
MATRIX_BEGIN = "<!-- BEGIN GENERATED PLATFORM MATRIX -->"
MATRIX_END = "<!-- END GENERATED PLATFORM MATRIX -->"
DEFAULT_RELEASE_INPUT_PATHS = (
    "docs/public",
    "skills",
    "ovstorage-c-source",
    "ovstorage-services",
)


def load(root: Path | None = None) -> list[dict[str, str]]:
    root = repo_root() if root is None else root
    data = json.loads((root / REGISTRY).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise TaskError(f"{REGISTRY} must have schema_version 1")
    platforms = data.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise TaskError(f"{REGISTRY} must contain a non-empty platforms array")
    required = {
        "id",
        "os",
        "architecture",
        "runner",
        "archive_format",
        "wheel_tag",
        "runtime_floor",
    }
    ids: set[str] = set()
    for item in platforms:
        if not isinstance(item, dict) or required - item.keys():
            raise TaskError(f"{REGISTRY} has an incomplete platform entry")
        platform_id = item["id"]
        if platform_id in ids:
            raise TaskError(f"{REGISTRY} repeats platform {platform_id!r}")
        ids.add(platform_id)
    return platforms


def by_id(platform_id: str, root: Path | None = None) -> dict[str, str]:
    platforms = load(root)
    for platform in platforms:
        if platform["id"] == platform_id:
            return platform
    supported = ", ".join(item["id"] for item in platforms)
    raise TaskError(f"unsupported release platform {platform_id!r}; expected {supported}")


def _host_identity() -> tuple[str, str]:
    os_name = (
        "Windows"
        if sys.platform == "win32"
        else "Linux"
        if sys.platform.startswith("linux")
        else ""
    )
    machine = host_platform.machine().lower()
    architecture = (
        "x86_64"
        if machine in {"x86_64", "amd64"}
        else "ARM64 (aarch64)"
        if machine in {"aarch64", "arm64"}
        else ""
    )
    return os_name, architecture


def detect_local(root: Path | None = None) -> str:
    """Return the registry platform for the current OS and architecture."""
    identity = _host_identity()
    for item in load(root):
        if (item["os"], item["architecture"]) == identity:
            return item["id"]
    raise TaskError(
        f"the local host {sys.platform}/{host_platform.machine()} has no release platform"
    )


def validate_host(platform: dict[str, str]) -> None:
    """Reject packaging a platform whose binaries cannot match this host."""
    if (platform["os"], platform["architecture"]) != _host_identity():
        raise TaskError(
            f"release platform {platform['id']} does not match local host "
            f"{sys.platform}/{host_platform.machine()}"
        )


def render_matrix(platforms: list[dict[str, str]]) -> str:
    lines = [
        "| Platform | OS | Architecture | Archive | Wheel tag | Runtime floor |",
        "|---|---|---|---|---|---|",
    ]
    for item in platforms:
        lines.append(
            f"| `{item['id']}` | {item['os']} | {item['architecture']} | "
            f"`{item['archive_format']}` | `{item['wheel_tag']}` | "
            f"{item['runtime_floor']} |"
        )
    return "\n".join(lines)


def _matrix_body(text: str) -> str:
    if MATRIX_BEGIN not in text or MATRIX_END not in text:
        raise TaskError(f"{PLATFORM_DOC} is missing generated matrix markers")
    return text.split(MATRIX_BEGIN, 1)[1].split(MATRIX_END, 1)[0].strip()


def _workflow_matrix_sets(text: str) -> list[set[str]]:
    blocks = re.findall(
        r"matrix:\s*\n\s+name:\s*\n((?:\s+- [a-z0-9_-]+\s*\n)+)",
        text,
    )
    return [
        set(re.findall(r"^\s+- ([a-z0-9_-]+)\s*$", block, re.M))
        for block in blocks
    ]


def _workflow_runner_bindings(text: str) -> set[tuple[str, str]]:
    return set(
        re.findall(
            r"matrix\.name\s*==\s*'([^']+)'\s*&&\s*'([^']+)'",
            text,
        )
    )


def _kitmaker_platforms(text: str) -> tuple[str, ...]:
    tree = ast.parse(text)
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "DEFAULT_PLATFORMS"
                for target in node.targets
            )
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
                return value
    raise TaskError("tools/publish_wheels_to_kitmaker.py has no literal DEFAULT_PLATFORMS")


def verify_repository(root: Path | None = None) -> int:
    root = repo_root() if root is None else root
    platforms = load(root)
    expected_ids = {item["id"] for item in platforms}
    expected_tags = tuple(item["wheel_tag"] for item in platforms)

    doc = (root / PLATFORM_DOC).read_text(encoding="utf-8")
    if _matrix_body(doc) != render_matrix(platforms):
        raise TaskError(
            f"{PLATFORM_DOC}'s generated table differs from {REGISTRY}"
        )

    for rel in (
        Path(".github/workflows/verify.yml"),
        Path(".github/workflows/release-candidate.yml"),
    ):
        text = (root / rel).read_text(encoding="utf-8")
        if expected_ids not in _workflow_matrix_sets(text):
            raise TaskError(f"{rel} has no release matrix matching {REGISTRY}")
        bindings = _workflow_runner_bindings(text)
        for item in platforms:
            if (item["id"], item["runner"]) not in bindings:
                raise TaskError(
                    f"{rel} does not bind {item['id']} to {item['runner']}"
                )

    finalize = (root / ".github/workflows/release-finalize.yml").read_text(
        encoding="utf-8"
    )
    for item in platforms:
        filename = (
            f"ovstorage-v${{VERSION}}-{item['id']}."
            f"{item['archive_format']}"
        )
        if filename not in finalize:
            raise TaskError(f"release-finalize.yml does not require {filename}")

    # Both workflows hard-code the wheel filenames they require, so a wheel_tag
    # change here would otherwise stay green in this lint and fail at release
    # time instead. Note the tag is `ovstorage-${VERSION}-...`, with no `v`.
    #
    # `cp310-abi3` is not registry data: it follows from the dist matrix's
    # `setup-python: python-version: '3.10'`. Bumping CI's Python renames every
    # wheel, and this lint is where that surfaces -- pointing at the registry,
    # which is not where the cause lives.
    candidate = (root / ".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )
    for item in platforms:
        wheel = f"ovstorage-${{VERSION}}-cp310-abi3-{item['wheel_tag']}.whl"
        for rel, text in (
            (".github/workflows/release-candidate.yml", candidate),
            (".github/workflows/release-finalize.yml", finalize),
        ):
            if wheel not in text:
                raise TaskError(f"{rel} does not require {wheel}")

    kitmaker = (root / "tools/publish_wheels_to_kitmaker.py").read_text(
        encoding="utf-8"
    )
    if _kitmaker_platforms(kitmaker) != expected_tags:
        raise TaskError(
            "Kitmaker wheel tags differ from the release-platform registry"
        )

    print(
        "release platform registry matches docs, workflows, and wheel "
        f"publishing: {len(platforms)} platform(s)"
    )
    return len(platforms)


def source_identity(
    root: Path,
    *,
    ignored_input_paths: tuple[str, ...] = DEFAULT_RELEASE_INPUT_PATHS,
) -> tuple[str, bool]:
    source_sha = capture(
        ["git", "rev-parse", "HEAD"], cwd=root, label="git rev-parse"
    ).strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", source_sha) is None:
        raise TaskError(f"git rev-parse returned an invalid source SHA {source_sha!r}")
    status = capture(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        label="git status",
    ).strip()
    ignored_release_inputs = capture(
        [
            "git",
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *ignored_input_paths,
        ],
        cwd=root,
        label="git ignored release inputs",
    ).strip()
    dirty = bool(status or ignored_release_inputs)
    return source_sha, dirty


def _digest_file(path: Path) -> str:
    with path.open("rb") as stream:
        return _digest_stream(stream)


def _digest_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    staging: Path,
    *,
    version: str,
    platform_id: str,
    source_sha: str,
    source_dirty: bool,
    root: Path | None = None,
) -> Path:
    platform = by_id(platform_id, root)
    files = [
        {
            "path": path.relative_to(staging).as_posix(),
            "sha256": _digest_file(path),
        }
        for path in sorted(staging.rglob("*"))
        if path.is_file() and path != staging / MANIFEST_NAME
    ]
    public_platform = {
        field: platform[field]
        for field in (
            "id",
            "os",
            "architecture",
            "archive_format",
            "wheel_tag",
            "runtime_floor",
        )
    }
    manifest = {
        "schema_version": 1,
        "scope": "platform-archive",
        "version": version,
        "source_sha": source_sha,
        "source_dirty": source_dirty,
        "platform": public_platform,
        "files": files,
    }
    path = staging / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def _check_manifest(
    manifest: dict[str, object],
    files: dict[str, str],
    *,
    expected_version: str,
    expected_platform: str,
    expected_source_sha: str,
) -> None:
    if manifest.get("schema_version") != 1 or manifest.get("scope") != "platform-archive":
        raise TaskError("embedded release manifest has an unsupported schema or scope")
    platform = manifest.get("platform")
    if not isinstance(platform, dict) or platform.get("id") != expected_platform:
        raise TaskError("embedded release manifest names the wrong platform")
    if manifest.get("version") != expected_version:
        raise TaskError("embedded release manifest names the wrong version")
    if manifest.get("source_sha") != expected_source_sha:
        raise TaskError("embedded release manifest names the wrong source SHA")

    declared_items = manifest.get("files")
    if not isinstance(declared_items, list):
        raise TaskError("embedded release manifest has no file inventory")
    declared: dict[str, str] = {}
    for item in declared_items:
        if not isinstance(item, dict):
            raise TaskError("embedded release manifest has an invalid file entry")
        path = item.get("path")
        sha = item.get("sha256")
        if not isinstance(path, str) or not isinstance(sha, str) or path in declared:
            raise TaskError("embedded release manifest has an invalid file entry")
        declared[path] = sha
    if declared != files:
        missing = sorted(files.keys() - declared.keys())
        extra = sorted(declared.keys() - files.keys())
        changed = sorted(
            path
            for path in files.keys() & declared.keys()
            if files[path] != declared[path]
        )
        raise TaskError(
            "embedded release manifest does not match archive contents: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def verify_archive(
    archive: Path,
    *,
    expected_version: str,
    expected_platform: str,
    expected_source_sha: str,
) -> None:
    file_hashes: dict[str, str] = {}
    manifest_bytes: bytes | None = None
    roots: set[str] = set()

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise TaskError(
                        f"{archive} contains unsupported symlink {info.filename}"
                    )
                parts = Path(info.filename).parts
                if len(parts) < 2:
                    raise TaskError(f"{archive} contains a file outside its root")
                roots.add(parts[0])
                relative = Path(*parts[1:]).as_posix()
                if relative in file_hashes or (
                    relative == MANIFEST_NAME and manifest_bytes is not None
                ):
                    raise TaskError(f"{archive} repeats archive member {info.filename}")
                with bundle.open(info) as stream:
                    if relative == MANIFEST_NAME:
                        manifest_bytes = stream.read()
                    else:
                        file_hashes[relative] = _digest_stream(stream)
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            for info in bundle.getmembers():
                if info.isdir():
                    continue
                if not info.isfile():
                    raise TaskError(
                        f"{archive} contains unsupported non-file member {info.name}"
                    )
                parts = Path(info.name).parts
                if len(parts) < 2:
                    raise TaskError(f"{archive} contains a file outside its root")
                roots.add(parts[0])
                relative = Path(*parts[1:]).as_posix()
                if relative in file_hashes or (
                    relative == MANIFEST_NAME and manifest_bytes is not None
                ):
                    raise TaskError(f"{archive} repeats archive member {info.name}")
                stream = bundle.extractfile(info)
                if stream is None:
                    raise TaskError(f"cannot read {info.name} from {archive}")
                with stream:
                    if relative == MANIFEST_NAME:
                        manifest_bytes = stream.read()
                    else:
                        file_hashes[relative] = _digest_stream(stream)

    if len(roots) != 1 or manifest_bytes is None:
        raise TaskError(f"{archive} must contain one root and {MANIFEST_NAME}")
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise TaskError("embedded release manifest must be a JSON object")
    _check_manifest(
        manifest,
        file_hashes,
        expected_version=expected_version,
        expected_platform=expected_platform,
        expected_source_sha=expected_source_sha,
    )
    print(f"verified embedded release manifest in {archive}")


def _glibc_versions(data: bytes) -> set[tuple[int, int]]:
    """Read imported GLIBC symbol versions from one ELF image."""
    if not data.startswith(b"\x7fELF"):
        return set()
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(data)
        stream.flush()
        output = capture(
            ["readelf", "--version-info", stream.name],
            label="readelf --version-info",
        )
    return {
        (int(major), int(minor))
        for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)", output)
    }


def _glibc_versions_at(path: Path) -> set[tuple[int, int]]:
    output = capture(
        ["readelf", "--version-info", str(path)],
        label="readelf --version-info",
    )
    return {
        (int(major), int(minor))
        for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)", output)
    }


def _is_elf(path: Path) -> bool:
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def _needed_libraries(data: bytes) -> set[str]:
    """Read DT_NEEDED entries -- the shared libraries an ELF loads at runtime."""
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(data)
        stream.flush()
        output = capture(["readelf", "-d", stream.name], label="readelf -d")
    return set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", output))


def _symbol_version_nodes(data: bytes) -> set[tuple[str, str]]:
    """Read *required* versioned-symbol nodes, as (prefix, version) pairs.

    Only the `.gnu.version_r` ("Version needs") section is parsed. The symbols
    section that precedes it lists the same names, but scanning the whole
    output also picks up any version this library *defines*, which is not a
    dependency and must not be judged against another project's policy.

    Split on the first underscore, so `GLIBC_2.34` reads as
    `("GLIBC", "2.34")` and `GLIBCXX_3.4.32` as `("GLIBCXX", "3.4.32")` --
    the two prefixes share a leading substring, and conflating them would
    classify every C++ node as an impossibly new libc.

    The version part is deliberately not required to be numeric. Real nodes
    include `CXXABI_TM_1` and `CXXABI_FLOAT128`, which the policy permits, and
    `GLIBC_PRIVATE`, which it does not -- skipping non-numeric nodes would
    silently accept a dependency on glibc internals.
    """
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(data)
        stream.flush()
        output = capture(
            ["readelf", "--version-info", stream.name],
            label="readelf --version-info",
        )
    return parse_version_needs(output)


def parse_version_needs(output: str) -> set[tuple[str, str]]:
    """Parse `readelf --version-info` output into required (prefix, version)."""
    _, _, needs = output.partition("Version needs section")
    nodes = set()
    for name in re.findall(r"^\s*0x[0-9a-f]+:\s+Name:\s+(\S+)", needs, re.M):
        prefix, _, version = name.partition("_")
        if version:
            nodes.add((prefix, version))
    return nodes


def _glibc_limit(value: str) -> tuple[int, int]:
    parts = value.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise TaskError(f"invalid glibc compatibility version {value!r}")
    return int(parts[0]), int(parts[1])


def verify_staging(staging: Path, platform: dict[str, str]) -> None:
    """Verify the archive staging tree's imported-symbol compatibility.

    Wheel checks live in `verify_wheel`: the wheel is built beside the staging
    tree rather than inside it, so it is not reachable from here.
    """
    violations: list[str] = []
    archive_max = platform.get("archive_glibc_max")
    if archive_max is not None:
        archive_limit = _glibc_limit(archive_max)
        for path in staging.rglob("*"):
            if not path.is_file() or path.suffix == ".whl" or not _is_elf(path):
                continue
            name = path.relative_to(staging).as_posix()
            violations.extend(
                f"{name}: GLIBC_{major}.{minor} exceeds archive floor {archive_max}"
                for major, minor in _glibc_versions_at(path)
                if (major, minor) > archive_limit
            )
    if violations:
        raise TaskError(
            "release imports symbols newer than its declared glibc floor: "
            + ", ".join(sorted(violations))
        )


WHEEL_PLUGIN_DIR = "ovstorage/plugins"


def _verify_wheel_linkage(
    wheel: Path, members: dict[str, bytes], platform: dict[str, str]
) -> None:
    """Check bundled libraries against the wheel tag's manylinux policy.

    Two independent properties, neither of which backstops the other:

    * every `DT_NEEDED` library is one the policy guarantees is present, and
    * every versioned symbol node the library requires is one the policy
      permits.

    The second is not implied by the first. `libgcc_s.so.1` is always
    allowlisted, so a toolchain bump can introduce a `GCC_*` node the policy
    does not list without adding any new `DT_NEEDED` entry at all.

    Both lists are auditwheel's published `manylinux_2_34` policy, vendored per
    architecture into the platform registry. maturin does not audit `include`d
    files, so nothing else in the pipeline looks at these libraries.
    """
    allowlist = platform.get("wheel_lib_allowlist")
    permitted = platform.get("wheel_symbol_versions")
    if platform["os"] != "Linux":
        # No ELF, no manylinux policy. Windows has no equivalent gate.
        return
    if not allowlist or not permitted:
        # Keyed on the platform's OS rather than on the keys being present, so
        # that dropping or misspelling either one is an error instead of a
        # silently disabled check.
        raise TaskError(
            f"release platform {platform['id']} is missing wheel_lib_allowlist "
            "or wheel_symbol_versions; Linux platforms must declare a manylinux policy"
        )

    violations: list[str] = []
    for name in sorted(members):
        data = members[name]
        if not data.startswith(b"\x7fELF"):
            continue
        violations.extend(
            f"{name}: links {lib}, which is not guaranteed present on a "
            f"{platform['wheel_tag']} host"
            for lib in sorted(_needed_libraries(data) - set(allowlist))
        )
        for prefix, version in sorted(_symbol_version_nodes(data)):
            if prefix not in permitted:
                # An unrecognised prefix is a real dependency on something the
                # policy says nothing about, not a curiosity to skip over.
                violations.append(f"{name}: requires unknown symbol family {prefix}")
            elif version not in permitted[prefix]:
                violations.append(
                    f"{name}: requires {prefix}_{version}, which "
                    f"{platform['wheel_tag']} does not permit"
                )
    if violations:
        raise TaskError(
            f"wheel {wheel.name} bundles libraries incompatible with its tag: "
            + ", ".join(violations)
        )


WHEEL_INVENTORY_SCHEMA_VERSION = 1


def _read_inventory(data: bytes, wheel: Path, inventory_name: str) -> dict[str, str]:
    """Parse the wheel's plugin inventory into {filename: sha256}.

    Written by `_dist._stage_wheel_plugins`; the shape is::

        {"schema_version": 1, "version": "0.3.0",
         "plugins": [{"filename": "...", "sha256": "<64 hex chars>"}, ...]}

    Validated rather than trusted: this file is the only description of the
    bundle that reaches an installed wheel, where no packaging code exists to
    re-derive it.
    """
    try:
        inventory = json.loads(data)
    except json.JSONDecodeError as err:
        raise TaskError(f"{inventory_name} in {wheel.name} is not valid JSON: {err}") from err

    schema = inventory.get("schema_version")
    if schema != WHEEL_INVENTORY_SCHEMA_VERSION:
        raise TaskError(
            f"{inventory_name} in {wheel.name} has schema_version {schema!r}, "
            f"expected {WHEEL_INVENTORY_SCHEMA_VERSION}"
        )

    entries = inventory.get("plugins")
    if not isinstance(entries, list):
        raise TaskError(f"{inventory_name} in {wheel.name} has no plugins array")

    recorded: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise TaskError(f"{inventory_name} in {wheel.name} has a non-object entry")
        name, digest = entry.get("filename"), entry.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            raise TaskError(
                f"{inventory_name} in {wheel.name} has an entry missing filename/sha256"
            )
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            raise TaskError(
                f"{inventory_name} in {wheel.name}: {name} has a malformed sha256"
            )
        # Two entries for one filename would otherwise collapse, leaving the
        # last one to stand in for a contradiction.
        if name in recorded:
            raise TaskError(
                f"{inventory_name} in {wheel.name} lists {name} more than once"
            )
        recorded[name] = digest
    return recorded


def verify_wheel(
    wheel: Path,
    staging: Path,
    platform: dict[str, str],
    *,
    expected: tuple[str, ...],
    inventory_name: str,
) -> None:
    """Verify the wheel carries exactly the bundled plugins, unmodified.

    This is the gate against shipping a wheel that installs cleanly and has no
    backends -- the state 0.2.0 shipped in. `expected` is passed in rather than
    imported: `_dist` imports this module, so importing it back would be a
    cycle, and `_dist` owns the package-name-to-filename mapping anyway.
    """
    expected_tag = platform["wheel_tag"]
    if not wheel.name.endswith(f"-{expected_tag}.whl"):
        raise TaskError(f"wheel {wheel.name} does not carry registry tag {expected_tag}")

    prefix = f"{WHEEL_PLUGIN_DIR}/"
    with zipfile.ZipFile(wheel) as archive:
        plugin_infos = [
            info
            for info in archive.infolist()
            if not info.is_dir() and info.filename.startswith(prefix)
        ]
        # A zip may legally hold two members with the same path; building the
        # dict first would silently keep the last and hide the other.
        names = [info.filename for info in plugin_infos]
        if len(names) != len(set(names)):
            duplicated = sorted({n for n in names if names.count(n) > 1})
            raise TaskError(
                f"wheel {wheel.name} contains duplicate members: {', '.join(duplicated)}"
            )
        members = {
            info.filename[len(prefix) :]: archive.read(info) for info in plugin_infos
        }

        found = set(members) - {inventory_name}
        if found != set(expected):
            missing = ", ".join(sorted(set(expected) - found)) or "none"
            extra = ", ".join(sorted(found - set(expected))) or "none"
            raise TaskError(
                f"wheel {wheel.name} bundles the wrong plugin set under "
                f"{WHEEL_PLUGIN_DIR}/ (missing: {missing}; unexpected: {extra})"
            )

        if inventory_name not in members:
            raise TaskError(f"wheel {wheel.name} has no {prefix}{inventory_name}")
        recorded = _read_inventory(members[inventory_name], wheel, inventory_name)
        if set(recorded) != set(expected):
            raise TaskError(
                f"{inventory_name} in {wheel.name} does not list the bundled plugins"
            )

        violations: list[str] = []
        for name in sorted(expected):
            packaged = members[name]
            digest = hashlib.sha256(packaged).hexdigest()
            if digest != recorded[name]:
                violations.append(f"{name}: bytes do not match {inventory_name}")
            # The archive and the wheel must carry the same binary. Both are
            # copies of one `target/<profile>` artifact and zip deflate is
            # lossless, so a mismatch means a stale, debug, or wrong-architecture
            # library reached one of them.
            sibling = staging / "plugins" / name
            if not sibling.is_file():
                violations.append(f"{name}: not present in the archive's plugins/")
            elif _digest_file(sibling) != digest:
                violations.append(f"{name}: differs from the archive's copy")
        if violations:
            raise TaskError(
                f"wheel {wheel.name} plugin payload is inconsistent: "
                + ", ".join(violations)
            )

        _verify_wheel_linkage(wheel, members, platform)

        wheel_max = platform.get("wheel_glibc_max")
        if wheel_max is None:
            return
        wheel_limit = _glibc_limit(wheel_max)
        floor_violations = [
            f"{wheel.name}:{name}: GLIBC_{major}.{minor} exceeds wheel floor {wheel_max}"
            for name, data in members.items()
            if data.startswith(b"\x7fELF")
            for major, minor in _glibc_versions(data)
            if (major, minor) > wheel_limit
        ]
        for info in archive.infolist():
            if info.is_dir() or info.filename.startswith(prefix):
                continue
            data = archive.read(info)
            if not data.startswith(b"\x7fELF"):
                continue
            floor_violations.extend(
                f"{wheel.name}:{info.filename}: GLIBC_{major}.{minor} "
                f"exceeds wheel floor {wheel_max}"
                for major, minor in _glibc_versions(data)
                if (major, minor) > wheel_limit
            )
        if floor_violations:
            raise TaskError(
                "wheel imports symbols newer than its declared glibc floor: "
                + ", ".join(sorted(floor_violations))
            )
