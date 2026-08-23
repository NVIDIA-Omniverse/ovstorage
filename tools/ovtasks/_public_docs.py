# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lint for ``docs/public/``: every markdown link target must resolve inside
``docs/public/``. The shipped distribution does not include the crate sources,
so out-of-tree links break in the user-facing surface.

The rule is intentionally a substring check on the markdown link form
``](../../``: every public doc lives at depth 1
(``docs/public/<persona>/<file>.md``), so a single ``../`` stays inside
``docs/public/`` and a double ``../../`` escapes. Bare prose mentioning
``../../`` (e.g. inside inline code) is not matched -- only link targets."""

from __future__ import annotations

from pathlib import Path

from _repo import TaskError, repo_root


def validate() -> None:
    public = repo_root() / "docs" / "public"
    _validate_at(public)


def _validate_at(public: Path) -> None:
    if not public.exists():
        print(f"{public}: not present, nothing to validate")
        return

    files = sorted(p for p in public.rglob("*.md") if p.is_file())

    errors: list[str] = []
    for path in files:
        body = path.read_text(encoding="utf-8")
        for idx, line in enumerate(body.splitlines(), start=1):
            if "](../../" in line:
                errors.append(f"{path}:{idx}: {line.strip()}")

    if errors:
        raise TaskError(
            "docs/public/ has links that escape the public surface "
            "(use a single `../` or rephrase without a link):\n"
            + "\n".join(errors)
        )
    print(f"validated {len(files)} public doc(s)")
