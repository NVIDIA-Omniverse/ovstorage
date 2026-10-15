# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Header regeneration and copy gate.

Invokes the ``cbindgen`` CLI against each header-emitting crate's
``cbindgen.toml``, writes the result to the checked-in ``include/<header>.h``,
and (when ``verify_clean`` is true) fails if ``git diff --exit-code`` reports
any change.

Only ``ovstorage_plugin.h`` is generated. It has to be: plugins are prebuilt
cdylibs the host ``dlopen``s at runtime, so host and plugin are compiled
separately and must agree on struct layout, and the Rust crate is the single
definition both sides derive from. ``COPY_PAIRS`` byte-copies it into the
source distribution and the verify gate catches drift between the two.

``ovstorage.h`` is deliberately NOT a target. The C application API is
distributed as source -- consumers compile that header together with the
``ovstorage-c-source/src`` implementation it declares -- so there is no binary
boundary between them to freeze and no second definition to derive it from.
It is hand-maintained alongside that implementation, and the pure-C link
completeness gate (``_c_source_examples.verify_completeness_table``) is what
holds the two in agreement: every function the header declares must be
defined by the source set.

The hand-authored ``ovstorage.hpp`` and ``ovstorage_defaults.h`` are likewise
not copied.

The crates' own ``build.rs`` files perform the cbindgen work via the library as
a best-effort dev convenience. This is the strict version used by CI: any
cbindgen error is a hard failure."""

from __future__ import annotations

from collections import Counter
import shutil
import subprocess
from pathlib import Path

from _repo import TaskError, eprint, repo_root, require_tool

# (crate_path relative to repo root, header relative to the crate root)
TARGETS = (("ovstorage-core/ovstorage-plugin", "include/ovstorage_plugin.h"),)

# (canonical header path, byte-identical staged copy). One canonical source
# may feed multiple copies, so this is a tuple of pairs rather than a dict.
COPY_PAIRS = (
    (
        "ovstorage-core/ovstorage-plugin/include/ovstorage_plugin.h",
        "ovstorage-c-source/include/ovstorage_plugin.h",
    ),
)

_INSTALL_HINT = "cargo install cbindgen"


def run(verify_clean: bool) -> None:
    root = repo_root()
    require_tool("cbindgen", _INSTALL_HINT)
    for crate_path, header in TARGETS:
        crate_dir = root / crate_path
        if not crate_dir.exists():
            eprint(f"skipping missing header target {crate_path}")
            continue
        _regenerate_one(crate_dir, crate_path, header)
    if verify_clean:
        _verify_copies(root)
        _verify_no_diff(root)
    else:
        _refresh_copies(root)


# cbindgen diagnostics are treated as errors: any warning it prints fails header
# regeneration. Intentionally-unexported items carry a `/// cbindgen:ignore`
# annotation (with a reason) so they never warn; the only diagnostics allowed to
# survive are the exact, documented per-crate multisets below. Add an entry only
# for a warning that has no annotation site and is genuinely unavoidable — and
# say why.
# No target currently needs an entry: every intentionally-unexported item in
# `ovstorage-plugin` carries a `/// cbindgen:ignore` with a reason, so cbindgen
# runs silent and any diagnostic at all fails regeneration.
_EXPECTED_CBINDGEN_DIAGNOSTICS: dict[str, Counter[str]] = {}


def _diagnostic_mismatch(
    crate_path: str, stderr: bytes
) -> tuple[Counter[str], Counter[str]]:
    actual = Counter(
        line.strip()
        for line in stderr.decode("utf-8", "replace").splitlines()
        if line.strip()
    )
    expected = _EXPECTED_CBINDGEN_DIAGNOSTICS.get(crate_path, Counter())
    return actual - expected, expected - actual


def _regenerate_one(crate_dir: Path, crate_path: str, header: str) -> None:
    config = crate_dir / "cbindgen.toml"
    header_path = crate_dir / header
    header_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            "cbindgen",
            "--config",
            str(config),
            "--output",
            str(header_path),
            str(crate_dir),
        ],
        stderr=subprocess.PIPE,
    )
    stderr_lines = [
        line.strip()
        for line in completed.stderr.decode("utf-8", "replace").splitlines()
        if line.strip()
    ]
    if completed.returncode != 0:
        for line in stderr_lines:
            eprint(line)
        raise TaskError(f"cbindgen generate failed for {crate_dir}")

    unexpected, missing = _diagnostic_mismatch(crate_path, completed.stderr)
    if unexpected or missing:
        for line in unexpected.elements():
            eprint(line)
        for line, count in missing.items():
            eprint(f"missing expected cbindgen diagnostic ({count}): {line}")
        raise TaskError(
            f"cbindgen diagnostics for {crate_dir} did not match the documented "
            "per-crate multiset (cbindgen warnings are errors). Annotate the item "
            "with `/// cbindgen:ignore` plus a reason, or, if it has no annotation "
            "site and is unavoidable, add a documented entry to "
            "_EXPECTED_CBINDGEN_DIAGNOSTICS in _headers.py."
        )


def _refresh_copies(root: Path) -> None:
    for source, destination in COPY_PAIRS:
        source_path = root / source
        if not source_path.is_file():
            raise TaskError(f"canonical header is missing: {source}")
        destination_path = root / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)


def _verify_copies(root: Path) -> None:
    drifted: list[tuple[str, str]] = []
    for source, destination in COPY_PAIRS:
        source_path = root / source
        if not source_path.is_file():
            raise TaskError(f"canonical header is missing: {source}")
        destination_path = root / destination
        if (
            not destination_path.is_file()
            or source_path.read_bytes() != destination_path.read_bytes()
        ):
            drifted.append((source, destination))

    if drifted:
        eprint("--- copied header drift detected ---")
        for source, destination in drifted:
            eprint(f"{destination} differs from {source}")
        raise TaskError(
            "pure-C headers differ from their canonical copies. "
            "Run `make regenerate-headers` and commit the diff."
        )


def _verify_no_diff(root: Path) -> None:
    paths = [
        f"{crate_path}/{header}"
        for crate_path, header in TARGETS
        if (root / crate_path).exists()
    ]
    paths.extend(destination for _source, destination in COPY_PAIRS)
    completed = subprocess.run(
        ["git", "diff", "--exit-code", "--", *paths],
        cwd=str(root),
        stdout=subprocess.PIPE,
    )
    if completed.returncode != 0:
        eprint("--- header drift detected ---")
        eprint(completed.stdout.decode("utf-8", "replace"))
        raise TaskError(
            "checked-in C headers or pure-C copies differ from regenerated output. "
            "Run `make regenerate-headers` and commit the diff."
        )
