# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate SPDX license/copyright notices in active source files."""

import _source_headers
from _repo import run_task

if __name__ == "__main__":
    run_task(_source_headers.validate)
