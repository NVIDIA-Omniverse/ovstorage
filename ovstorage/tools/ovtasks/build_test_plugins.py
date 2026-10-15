# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build and stage the cdylib test plugins under target/test-plugins/."""

import _test_plugins
from _repo import run_task

if __name__ == "__main__":
    run_task(_test_plugins.run_cmd)
