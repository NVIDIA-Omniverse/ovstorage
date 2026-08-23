# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print the current `[project] version` from the Python crate's pyproject.toml."""

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(_version.print_release_version)
