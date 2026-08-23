# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build, run, and validate the standalone pure-C source examples."""

import _c_source_examples
from _repo import run_task

if __name__ == "__main__":
    run_task(_c_source_examples.run)
