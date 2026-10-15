# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Mapping, Sequence

from .ovstorage import ConfigValue, LayerBase

__all__ = ["Router"]


class Router(LayerBase):
    def __new__(
        cls,
        name: str,
        children: Sequence[str],
        config: Mapping[str, ConfigValue] | None = None,
    ) -> Router: ...
