# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if the `keyring` crate returns to the dependency graph."""

import _auth_root_delegation
from _repo import run_task

if __name__ == "__main__":
    run_task(_auth_root_delegation.validate_no_keyring_dependency)
