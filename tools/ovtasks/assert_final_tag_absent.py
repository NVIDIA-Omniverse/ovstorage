# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if the current final version's tag is present in the given tag list."""

import argparse

import _version
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tags", nargs="*", default=[])
    args = parser.parse_args()
    run_task(lambda: _version.assert_final_tag_absent(args.tags))
