# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bump the `[project] version` in the Python crate's pyproject.toml in place.

Bump kind: `release` (0.1.0rc1 -> 0.1.0), `patch`, `minor`, `major`, legacy
`alpha`, or `to=<version>` (explicit override).
"""

import argparse

import _version
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", help="release | patch | minor | major | alpha | to=<version>")
    args = parser.parse_args()
    run_task(lambda: _version.bump_release_version(args.kind))
