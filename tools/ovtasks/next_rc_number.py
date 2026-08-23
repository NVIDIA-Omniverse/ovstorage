# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print the next RC number for the current final version from a tag list."""

import argparse

import _version
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tags", nargs="*", default=[])
    args = parser.parse_args()
    run_task(lambda: _version.print_next_rc_number(args.tags))
