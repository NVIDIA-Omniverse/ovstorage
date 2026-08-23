# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate publication frontmatter on the repo-root agent skills."""

import _skills
from _repo import run_task

if __name__ == "__main__":
    run_task(_skills.validate)
