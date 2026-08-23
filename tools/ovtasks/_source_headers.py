# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Source-file notice gate for files that can carry comments. The approval
board requires NVIDIA-authored source files to carry a copyright notice and
SPDX short-form license identifier before distribution.

Two validation modes:

- **NVIDIA-authored (default).** The SPDX two-line header
  (``SPDX-FileCopyrightText`` + ``SPDX-License-Identifier: Apache-2.0``) must
  appear within the first ``NVIDIA_HEADER_WINDOW_LINES`` lines. The window is
  intentionally small: the header must sit at the top of the file.
- **Vendored third-party** (the gRPC ``health.proto``). OSRB does not allow
  the SPDX shortcut for non-NVIDIA-authored code -- the full upstream Apache
  2.0 boilerplate must be preserved verbatim within the first
  ``VENDORED_HEADER_WINDOW_LINES`` lines."""

from __future__ import annotations

from pathlib import PurePosixPath

from _repo import TaskError, git_tracked_files, repo_root

NVIDIA_COPYRIGHT = (
    "SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. "
    "All rights reserved."
)
APACHE_LICENSE = "SPDX-License-Identifier: Apache-2.0"

# Five lines is tight enough that the header must sit at the very top but
# loose enough to permit a block-comment opener plus a blank separator.
NVIDIA_HEADER_WINDOW_LINES = 5
# The canonical upstream Apache 2.0 boilerplate is ~13 lines; 20 leaves room
# for a brief vendoring annotation below the original notice.
VENDORED_HEADER_WINDOW_LINES = 20

GRPC_HEALTH_PROTO = (
    "ovstorage-remote/ovstorage-broker-protocol/proto/grpc/health/v1/health.proto"
)
GRPC_HEALTH_COPYRIGHT = "Copyright 2015 The gRPC Authors"
APACHE_LICENSE_FULL_PHRASE = "Licensed under the Apache License, Version 2.0"

GENERATED_WITH_EXTERNAL_DRIFT_CHECKS = (
    "ovstorage-remote/ovstorage-rest/spec/openapi.yaml",
)

_LINTED_EXTENSIONS = {
    "c",
    "cpp",
    "h",
    "hpp",
    "html",
    "ini",
    "proto",
    "py",
    "pyi",
    "rs",
    "toml",
    "ts",
    "yaml",
    "yml",
}
_LINTED_FILENAMES = {"Makefile", "CMakeLists.txt"}
_EXCLUDED_COMPONENTS = {".git", "dist", "target", "_archive", "ovstorage-services"}


def validate() -> None:
    root = repo_root()
    checked = 0
    errors: list[str] = []
    for rel in git_tracked_files(root):
        if not _is_linted_source(rel):
            continue
        if not (root / rel).exists():
            continue
        checked += 1
        err = _validate_file(rel, (root / rel).read_text(encoding="utf-8"))
        if err is not None:
            errors.append(f"{rel}: {err}")

    if errors:
        raise TaskError("source-header validation failed:\n" + "\n".join(errors))
    print(f"validated {checked} source header(s)")


def _validate_file(rel: str, text: str) -> str | None:
    if rel == GRPC_HEALTH_PROTO:
        head = _leading_lines(text, VENDORED_HEADER_WINDOW_LINES)
        return _require(head, GRPC_HEALTH_COPYRIGHT, VENDORED_HEADER_WINDOW_LINES) or _require(
            head, APACHE_LICENSE_FULL_PHRASE, VENDORED_HEADER_WINDOW_LINES
        )
    head = _leading_lines(text, NVIDIA_HEADER_WINDOW_LINES)
    return _require(head, NVIDIA_COPYRIGHT, NVIDIA_HEADER_WINDOW_LINES) or _require(
        head, APACHE_LICENSE, NVIDIA_HEADER_WINDOW_LINES
    )


def _leading_lines(text: str, n: int) -> str:
    return "\n".join(text.splitlines()[:n])


def _require(head: str, needle: str, window: int) -> str | None:
    if needle in head:
        return None
    return f"missing `{needle}` in the first {window} lines"


def _is_linted_source(rel: str) -> bool:
    path = PurePosixPath(rel)
    if any(part in _EXCLUDED_COMPONENTS for part in path.parts):
        return False
    if rel in GENERATED_WITH_EXTERNAL_DRIFT_CHECKS:
        return False
    ext = path.suffix[1:] if path.suffix else ""
    return ext in _LINTED_EXTENSIONS or path.name in _LINTED_FILENAMES
