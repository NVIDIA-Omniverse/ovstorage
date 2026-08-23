# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print `true` when finalizing this release advances `main`, else `false`.

Takes the released version and `main`'s version as arguments, so the caller
supplies the pinned `main` it intends to act on rather than this reading a ref
of its own.
"""

import sys

import _back_merge
from _repo import TaskError, run_task


def main() -> None:
    if len(sys.argv) != 3:
        raise TaskError(
            "usage: back_merge_applies.py RELEASED_VERSION MAIN_VERSION"
        )
    _back_merge.report_back_merge_applies(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    run_task(main)
