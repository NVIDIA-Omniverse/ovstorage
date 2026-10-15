# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if a code comment cites a GitHub issue number."""

import _comment_hygiene
from _repo import run_task

if __name__ == "__main__":
    run_task(_comment_hygiene.validate)
