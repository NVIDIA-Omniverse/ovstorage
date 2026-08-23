# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if an async slot completes outside the ABI mint chokepoint."""

import _abi_mint
from _repo import run_task

if __name__ == "__main__":
    run_task(_abi_mint.validate)
