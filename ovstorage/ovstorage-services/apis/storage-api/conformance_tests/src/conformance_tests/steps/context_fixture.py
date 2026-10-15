# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from typing import (
    Any,
    Optional,
)


class ContextFixture:
    def __init__(self, name: str):
        self.name = name
        self.value: Optional[Any] = None


class ListResultFixture:
    def __init__(self, name: str):
        self.name = name
        self.counter = 0
        self.value: Optional[Any] = None
