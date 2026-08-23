# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assert `main` can take the back-merge pull request as a merge commit."""

import _back_merge
from _repo import run_task

if __name__ == "__main__":
    run_task(_back_merge.assert_back_merge_mergeable)
