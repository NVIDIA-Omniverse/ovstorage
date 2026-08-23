# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assert the current release version is final (for opening a release line)."""

import _version
from _repo import run_task

if __name__ == "__main__":
    run_task(_version.assert_release_open_version)
