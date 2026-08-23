# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the ovtasks package: repo paths, subprocess wrappers,
target-dir resolution, and platform-specific binary/library affixes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence


class TaskError(Exception):
    """A task failed in a way that should print a message and exit non-zero.

    The command script catches this, prints the message to stderr, and exits 1.
    """


def repo_root() -> Path:
    """Repo root, derived from this file's location (``tools/ovtasks/_repo.py``).

    Robust regardless of the working directory.
    """
    return Path(__file__).resolve().parents[2]


def target_dir(release: bool) -> Path:
    """The single workspace ``target/<profile>`` directory at the repo root."""
    return repo_root() / "target" / ("release" if release else "debug")


def platform_affixes() -> tuple[str, str, str]:
    """``(exe_suffix, dll_prefix, dll_suffix)`` for the host platform.

    Mirrors Rust's ``std::env::consts::{EXE_SUFFIX, DLL_PREFIX, DLL_SUFFIX}``.
    """
    if sys.platform == "win32":
        return (".exe", "", ".dll")
    if sys.platform == "darwin":
        return ("", "lib", ".dylib")
    return ("", "lib", ".so")


def exe_filename(stem: str) -> str:
    exe_suffix, _, _ = platform_affixes()
    return f"{stem}{exe_suffix}"


def dll_filename(stem: str) -> str:
    """Platform cdylib filename for a crate's lib stem (e.g.
    ``ovstorage_plugin_file`` -> ``libovstorage_plugin_file.so``)."""
    _, dll_prefix, dll_suffix = platform_affixes()
    return f"{dll_prefix}{stem}{dll_suffix}"


def run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    label: str | None = None,
) -> None:
    """Run a command, raising :class:`TaskError` if it exits non-zero.

    ``env`` is merged over the current environment when provided."""
    full_env = None
    if env is not None:
        import os

        full_env = {**os.environ, **env}
    completed = subprocess.run(
        list(args),
        cwd=str(cwd) if cwd is not None else None,
        env=full_env,
    )
    if completed.returncode != 0:
        what = label or " ".join(args)
        where = f" in {cwd}" if cwd is not None else ""
        raise TaskError(f"{what} failed{where}")


def capture(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    label: str | None = None,
) -> str:
    """Run a command and return its stdout (decoded), raising on failure."""
    full_env = None
    if env is not None:
        import os

        full_env = {**os.environ, **env}
    completed = subprocess.run(
        list(args),
        cwd=str(cwd) if cwd is not None else None,
        env=full_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        what = label or " ".join(args)
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise TaskError(f"{what} failed: {stderr}")
    return completed.stdout.decode("utf-8", "replace")


def require_tool(binary: str, install_hint: str) -> None:
    """Fail with a focused install hint if ``binary`` is missing from PATH."""
    import shutil

    if shutil.which(binary) is None:
        raise TaskError(
            f"`{binary}` is not installed or not on PATH. Install with: {install_hint}"
        )


def git_tracked_files(root: Path) -> list[str]:
    """Repo-relative paths of every git-tracked file (``git ls-files``)."""
    out = capture(["git", "ls-files"], cwd=root, label="git ls-files")
    return [line for line in out.splitlines() if line]


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr)


def run_task(action) -> None:
    """Run a command script's action with the shared error convention: a
    :class:`TaskError` prints a clean ``error: <message>`` to stderr and exits
    with status 1. Every ``tools/ovtasks/<command>.py`` script wraps its call
    in this."""
    try:
        action()
    except TaskError as err:
        eprint(f"error: {err}")
        raise SystemExit(1)
