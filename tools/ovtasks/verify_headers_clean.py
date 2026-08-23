# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regenerate C headers, then fail if generated files or byte copies drift."""

import _headers
from _repo import run_task

if __name__ == "__main__":
    run_task(lambda: _headers.run(verify_clean=True))
