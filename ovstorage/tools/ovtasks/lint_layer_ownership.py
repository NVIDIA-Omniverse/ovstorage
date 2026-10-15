# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail when Layer ownership documentation and implementation drift."""

import _layer_ownership
from _repo import run_task

if __name__ == "__main__":
    run_task(_layer_ownership.validate)
