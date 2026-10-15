# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if the Python bridge attaches to the interpreter outside its gate."""

import _bridge_gil
from _repo import run_task

if __name__ == "__main__":
    run_task(_bridge_gil.validate)
