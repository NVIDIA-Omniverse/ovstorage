# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every command that runs the suite pins the auth root away from `$HOME`.

The auth substrate's default root is a real per-user platform directory. A
harness that resolves that default opens the credential database the developer
signed in with -- reading it, writing to it, and racing every other test
process against it.

Per-harness pinning is the isolation, but it cannot be the floor. Two of the
test suites shell out: the CLI and MCP integration tests spawn a binary whose
startup initialises the auth substrate, and the Python suite builds a Stack in
a shared fixture. A child process inherits an environment variable and cannot
inherit an in-process ``set_var``, so the only place that covers every
executable path is the command line that launches the suite.

That makes the pin a property of the *build files*, which is what this checks.
It is a source-level assertion because the failure it prevents is silent: a
recipe that stops naming the variable still runs, still passes, and starts
using the developer's real credentials. Nothing goes red at the moment the pin
is lost.

Scope note: this checks that the recipes name the variable, not that the
resolved directory is correct. The resolver has its own tests.
"""

from __future__ import annotations

import re
from pathlib import Path

from _repo import TaskError, repo_root

_MAKEFILE = "Makefile"

_PIN = "OVSTORAGE_AUTH_DIR"

# The variable the recipes are expected to pin to. Named here so a recipe that
# pins to something else -- `$(HOME)`, a literal, an empty value -- is caught
# rather than satisfying a bare substring test for the variable name.
_ROOT_VAR = "TEST_AUTH_ROOT"

# Recipe lines that run a test suite. Each must carry the pin. Matched on the
# runner rather than the target name so a renamed target does not silently
# leave the scan with nothing to check.
_RUNNERS = (
    ("cargo test --workspace", "the Rust suite"),
    ("$(PYTHON_TEST_PYTEST) tests", "the Python suite"),
)


def _assignment(text: str, name: str) -> str | None:
    """The right-hand side of ``name := ...``, joined across continuations."""
    match = re.search(rf"^{re.escape(name)}\s*:?=(.*?)(?<!\\)$", text, re.MULTILINE | re.DOTALL)
    if match is None:
        return None
    # A `\`-continued assignment runs until the first line with no trailing
    # backslash. Re-scan line by line rather than trusting the DOTALL match,
    # which would otherwise swallow the rest of the file.
    lines = text[match.start() :].splitlines()
    collected = []
    for line in lines:
        collected.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return "\n".join(collected)


def _is_prose(line: str) -> bool:
    """True when `line` talks about a runner rather than invoking one.

    ``make help`` echoes a description of every target, so the Makefile spells
    ``cargo test --workspace`` inside an ``@echo`` twice before the recipe that
    actually runs it. A comment does the same. Neither executes anything, so
    demanding a pin on them is a false positive -- and one that would push
    someone to "fix" it by adding an environment variable to a help string.
    """
    body = line.strip()
    return body.startswith("#") or body.startswith("@echo") or body.startswith("echo ")


def validate() -> None:
    root = repo_root()
    makefile = root / _MAKEFILE
    if not makefile.is_file():
        raise TaskError(f"{_MAKEFILE} is missing; this gate is looking at the wrong tree")

    text = makefile.read_text(encoding="utf-8")

    # Positive premise first: the pinned root must be defined at all. Without
    # this, every check below passes vacuously against a Makefile that names
    # `$(TEST_AUTH_ROOT)` and never sets it -- make expands an undefined
    # variable to the empty string without complaint, and `OVSTORAGE_AUTH_DIR=`
    # reads as unset, which is exactly the failure being prevented.
    definition = _assignment(text, _ROOT_VAR)
    if definition is None:
        raise TaskError(
            f"{_MAKEFILE} does not define `{_ROOT_VAR}`. The test recipes pin "
            f"`{_PIN}` to it so no suite resolves the real per-user auth "
            "directory; an undefined variable expands to the empty string, "
            "which make accepts and which reads as unset."
        )
    if "$(CURDIR)" not in definition:
        raise TaskError(
            f"{_MAKEFILE}'s `{_ROOT_VAR}` is not anchored under `$(CURDIR)`:\n"
            f"  {definition.strip()}\n"
            "It must resolve inside the build tree. A relative path moves with "
            "the working directory, and an unanchored one can land in $HOME."
        )

    offenders: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _is_prose(line):
            continue
        for runner, description in _RUNNERS:
            if runner not in line:
                continue
            if f"{_PIN}=" in line or f"$({_ROOT_VAR})" in line:
                continue
            # `make test` reaches the pin through `$(TEST_ENV)`; a recipe that
            # names neither that nor the variable directly is unpinned.
            if "$(TEST_ENV)" in line and f"{_PIN}=" in (_assignment(text, "TEST_ENV") or ""):
                continue
            offenders.append(f"{_MAKEFILE}:{lineno}: {description}: {line.strip()}")

    if not offenders:
        # An empty offender list is only meaningful if the scan found the
        # runners at all. A renamed recipe would otherwise report success
        # having inspected nothing.
        found = [runner for runner, _ in _RUNNERS if runner in text]
        missing = [runner for runner, _ in _RUNNERS if runner not in text]
        if missing:
            raise TaskError(
                f"{_MAKEFILE} no longer contains "
                + ", ".join(f"`{runner}`" for runner in missing)
                + "; this gate scanned for a test runner that has been renamed "
                "and therefore checked nothing. Update `_RUNNERS`."
            )
        if not found:
            raise TaskError(f"{_MAKEFILE} names no test runner; the gate is not scanning anything")
        return

    listing = "\n  ".join(offenders)
    raise TaskError(
        f"a test recipe does not pin `{_PIN}`:\n  {listing}\n"
        f"Add `{_PIN}=$({_ROOT_VAR})` to it. Without the pin these suites "
        "resolve the default auth root, which is a real per-user directory: "
        "the run then reads and writes the credentials the developer signed "
        "in with, and every test process races the same database. The "
        "spawned-binary suites (CLI, MCP) and the Python fixture cannot be "
        "covered any other way -- a child process inherits this variable and "
        "cannot inherit an in-process `set_var`."
    )
