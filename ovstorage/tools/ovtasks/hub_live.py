#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run the live hub_cache test tier against a real Omniverse Hub."""

from __future__ import annotations

import argparse

from _hub_live import test
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("test",))
    parser.parse_args()
    run_task(test)
