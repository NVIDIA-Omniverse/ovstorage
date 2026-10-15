# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if any markdown link in docs/public/ escapes the public surface."""

import _public_docs
from _repo import run_task

if __name__ == "__main__":
    run_task(_public_docs.validate)
