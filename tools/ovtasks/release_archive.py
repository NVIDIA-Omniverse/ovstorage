# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build a full release tarball/zip, including c-source/, under dist/."""

import argparse

import _dist
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", default="auto")
    parser.add_argument("--release", action="store_true", default=True)
    args = parser.parse_args()
    run_task(lambda: _dist.release_archive(args.release, args.platform))
