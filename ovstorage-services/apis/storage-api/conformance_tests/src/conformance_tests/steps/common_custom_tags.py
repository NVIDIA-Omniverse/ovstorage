# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import pytest


def pytest_bdd_apply_tag(tag, function):
    if tag == "skip":
        marker = pytest.mark.skip(reason="Test skipped")
        marker(function)
        return True
    elif tag == "optional":
        marker = pytest.mark.optional(reason="Optional test")
        marker(function)
        return True
    else:
        # Fall back to the default behavior of pytest-bdd
        return None
