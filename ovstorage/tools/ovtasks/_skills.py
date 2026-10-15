# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validation for repo-root agent skills.

The frontmatter parser is a deliberate line-based reader (not a general YAML
parser) so publication rules don't shift under a different YAML library."""

from __future__ import annotations

from pathlib import Path

from _repo import TaskError, repo_root

ALLOWED_PREFIXES = ("ovstorage-user-", "ovstorage-operator-", "ovstorage-contributor-")
SKILL_LICENSE = "CC-BY-4.0"
ALLOWED_TOOLS = ("Read", "Write", "Edit", "Bash", "Grep", "Glob", "Shell")
REQUIRED_FIELDS = (
    "name",
    "description",
    "license",
    "version",
    "author",
    "tags",
    "tools",
    "compatibility",
)


class _SkillError(Exception):
    """Per-skill validation failure, aggregated across all skills."""


def validate() -> None:
    _validate_at(repo_root())


def _validate_at(root: Path) -> None:
    skills = root / "skills"
    if not skills.exists():
        print("skills/: not present, nothing to validate")
        return

    checked = 0
    errors: list[str] = []
    for entry in sorted(skills.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        slug = entry.name
        skill_md = entry / "SKILL.md"
        if not skill_md.exists():
            continue
        checked += 1
        try:
            _validate_skill(slug, skill_md)
        except _SkillError as err:
            errors.append(f"{skill_md}: {err}")

    if errors:
        raise TaskError("skill validation failed:\n" + "\n".join(errors))
    print(f"validated {checked} skill(s)")


def _validate_skill(slug: str, skill_md: Path) -> None:
    if not any(slug.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise _SkillError(
            "skill directory slug must start with one of " + ", ".join(ALLOWED_PREFIXES)
        )

    body = skill_md.read_text(encoding="utf-8")
    frontmatter = _parse_frontmatter(body)

    name = frontmatter.get("name")
    if name is None:
        raise _SkillError("missing frontmatter `name:`")
    if name != slug:
        raise _SkillError(f'frontmatter `name:` is "{name}", expected "{slug}"')
    if not _is_valid_skill_slug(name):
        raise _SkillError("frontmatter `name:` must be lowercase kebab-case, 1-64 chars")

    description = frontmatter.get("description")
    if description is None:
        raise _SkillError("missing frontmatter `description:`")
    if description.strip() == "":
        raise _SkillError("frontmatter `description:` must be non-empty")
    if len(description) > 1024:
        raise _SkillError("frontmatter `description:` must be 1024 chars or shorter")

    for field in REQUIRED_FIELDS:
        value = frontmatter.get(field)
        if value is None:
            raise _SkillError(f"missing frontmatter `{field}:`")
        if value.strip() == "":
            raise _SkillError(f"frontmatter `{field}:` must be non-empty")

    if not _is_semver(frontmatter["version"]):
        raise _SkillError('frontmatter `version:` must be semver such as "0.1.0"')

    if frontmatter["license"] != SKILL_LICENSE:
        raise _SkillError(f"frontmatter `license:` must be {SKILL_LICENSE}")

    author = frontmatter["author"]
    if not author.startswith("NVIDIA ") or author.strip() == "NVIDIA":
        raise _SkillError("frontmatter `author:` must use `NVIDIA <team>` format")

    tags = _inline_list_entries(frontmatter["tags"])
    if tags is None:
        raise _SkillError("frontmatter `tags:` must be an inline YAML list")
    if not 1 <= len(tags) <= 5:
        raise _SkillError("frontmatter `tags:` must contain 1-5 entries")

    tools = _inline_list_entries(frontmatter["tools"])
    if tools is None:
        raise _SkillError("frontmatter `tools:` must be an inline YAML list")
    if not tools:
        raise _SkillError("frontmatter `tools:` must contain at least one entry")
    for tool in tools:
        if tool not in ALLOWED_TOOLS:
            raise _SkillError(
                f'unsupported frontmatter `tools:` entry "{tool}"; use one of '
                + ", ".join(ALLOWED_TOOLS)
            )

    if len(frontmatter["compatibility"]) > 500:
        raise _SkillError("frontmatter `compatibility:` must be 500 chars or shorter")


def _is_valid_skill_slug(value: str) -> bool:
    return (
        value != ""
        and len(value) <= 64
        and not value.startswith("-")
        and not value.endswith("-")
        and "--" not in value
        and all(ch.islower() and ch.isascii() or ch in "0123456789-" for ch in value)
    )


def _is_semver(value: str) -> bool:
    core = value.split("-", 1)[0]
    parts = core.split(".")
    if len(parts) != 3:
        return False
    return all(part != "" and all(ch in "0123456789" for ch in part) for part in parts)


def _inline_list_entries(value: str) -> list[str] | None:
    if not (value.startswith("[") and value.endswith("]")):
        return None
    inner = value[1:-1].strip()
    if inner == "":
        return []
    return [
        entry
        for entry in (_unquote_yaml_scalar(part.strip()) for part in inner.split(","))
        if entry != ""
    ]


def _parse_frontmatter(body: str) -> dict[str, str]:
    lines = body.splitlines()
    if not lines or lines[0] != "---":
        raise _SkillError("missing opening YAML frontmatter fence")

    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            return fields
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise _SkillError(f'frontmatter line is not `key: value`: "{line}"')
        key, value = line.split(":", 1)
        fields[key.strip()] = _unquote_yaml_scalar(value.strip())
    raise _SkillError("missing closing YAML frontmatter fence")


def _unquote_yaml_scalar(value: str) -> str:
    if len(value) >= 2:
        first, last = value[0], value[-1]
        if (first == '"' and last == '"') or (first == "'" and last == "'"):
            return value[1:-1]
    return value
