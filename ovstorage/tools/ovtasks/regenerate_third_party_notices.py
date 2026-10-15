# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the Cargo dependency table in THIRD_PARTY_NOTICES.md."""

import _notices
from _repo import run_task

if __name__ == "__main__":
    run_task(_notices.regenerate)
