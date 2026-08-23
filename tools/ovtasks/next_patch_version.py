# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print the next patch final version for a release branch after finalize."""

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(_version.print_next_patch_version)
