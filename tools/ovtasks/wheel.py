# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build only the Python wheel into dist/wheels/ via maturin."""

import argparse

import _dist
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    run_task(lambda: _dist.wheel_only(args.release))
