# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Mapping

from .ovstorage import ConfigValue, LayerBase

__all__ = ["PluginBackend"]


class PluginBackend(LayerBase):
    def __new__(
        cls,
        kind: str,
        name: str | None = None,
        config: Mapping[str, ConfigValue] | None = None,
    ) -> PluginBackend: ...
