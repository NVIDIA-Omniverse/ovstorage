# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print the final release tag for the current version (vX.Y.Z)."""

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(_version.print_final_release_tag)
