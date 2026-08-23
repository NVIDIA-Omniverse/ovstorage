# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print the release-line branch name for the current final version (release/vX.Y)."""

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(_version.print_release_line_branch)
