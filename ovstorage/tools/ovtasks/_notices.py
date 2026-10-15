# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cargo registry dependency table for ``THIRD_PARTY_NOTICES.md``.

The "Cargo Registry Dependencies" section is generated from
``cargo metadata --locked`` over the single flat workspace. This module
produces that section and either writes it back (:func:`regenerate`) or
compares it to the on-disk file (:func:`verify_clean`) so CI catches
dependency drift before release.

Earlier sections of the notices file (top-level prose, Copied Source,
Vendored Service/API Material) are hand-maintained and left untouched.

The former per-workspace ``Workspaces`` column is gone: after the flatten
there is one workspace, so it carried no information."""

from __future__ import annotations

import json
from pathlib import Path

from _repo import TaskError, capture, repo_root

NOTICES_FILE = "THIRD_PARTY_NOTICES.md"
SECTION_HEADING = "## Cargo Registry Dependencies"


def regenerate() -> None:
    root = repo_root()
    updated = _rebuild(root)
    notices_path = root / NOTICES_FILE
    current = notices_path.read_text(encoding="utf-8")
    new_content = _replace_section(current, SECTION_HEADING, updated)
    if current == new_content:
        print(f"{NOTICES_FILE}: already up to date")
        return
    notices_path.write_text(new_content, encoding="utf-8")
    print(f"regenerated `{SECTION_HEADING}` in {NOTICES_FILE}")


def verify_clean() -> None:
    root = repo_root()
    updated = _rebuild(root)
    notices_path = root / NOTICES_FILE
    current = notices_path.read_text(encoding="utf-8")
    new_content = _replace_section(current, SECTION_HEADING, updated)
    if current != new_content:
        raise TaskError(
            f"{NOTICES_FILE} is stale; run `make regenerate-third-party-notices`"
        )
    print(f"verified {NOTICES_FILE} is up to date")


def _rebuild(root: Path) -> str:
    return _format_section(_collect_external_deps(root))


def _collect_external_deps(root: Path) -> dict[tuple[str, str], tuple[str, str]]:
    """Map ``(name, version)`` -> ``(license, repository)`` for every
    registry dependency in the workspace lock."""
    raw = capture(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        label="cargo metadata",
    )
    metadata = json.loads(raw)
    deps: dict[tuple[str, str], tuple[str, str]] = {}
    for pkg in metadata["packages"]:
        source = pkg.get("source")
        if source is None:
            continue  # workspace member (path source)
        if not source.startswith("registry+"):
            continue  # skip git/other; future-proof if any are added
        key = (pkg["name"], pkg["version"])
        deps[key] = (pkg.get("license") or "", pkg.get("repository") or "")
    return deps


def _format_section(deps: dict[tuple[str, str], tuple[str, str]]) -> str:
    out = [SECTION_HEADING, "", "| Crate | Version | License expression | Repository |", "|---|---:|---|---|"]
    for (name, version), (license_expr, repository) in sorted(deps.items()):
        repo = f"[{repository}]({repository})" if repository else "—"
        out.append(f"| `{name}` | {version} | `{license_expr}` | {repo} |")
    return "\n".join(out) + "\n"


def _replace_section(content: str, heading: str, new_section: str) -> str:
    lines = content.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.rstrip() == heading:
            start = idx
            break
    if start is None:
        raise TaskError(f"heading `{heading}` not found in {NOTICES_FILE}")

    end = len(lines)
    for idx in range(start + 1, len(lines)):
        if lines[idx].startswith("## "):
            end = idx
            break

    result = "".join(line + "\n" for line in lines[:start])
    result += new_section
    if not new_section.endswith("\n"):
        result += "\n"
    result += "".join(line + "\n" for line in lines[end:])
    if not content.endswith("\n") and result.endswith("\n"):
        result = result[:-1]
    return result
