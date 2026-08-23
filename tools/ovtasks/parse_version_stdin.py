# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read a pyproject.toml from stdin and print its [project] version."""

import sys

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(lambda: print(_version.parse_pyproject_version(sys.stdin.read())))
