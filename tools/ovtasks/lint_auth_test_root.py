# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if a test recipe stops pinning the auth root away from `$HOME`."""

import _auth_test_root
from _repo import run_task

if __name__ == "__main__":
    run_task(_auth_test_root.validate)
