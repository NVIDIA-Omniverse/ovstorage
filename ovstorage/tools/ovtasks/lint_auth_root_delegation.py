# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if a host resolves the auth directory outside the shared resolver."""

import _auth_root_delegation
from _repo import run_task

if __name__ == "__main__":
    run_task(_auth_root_delegation.validate)
