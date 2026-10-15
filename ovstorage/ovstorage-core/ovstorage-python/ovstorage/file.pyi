# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Mapping

from .ovstorage import ConfigValue, LayerBase

__all__ = ["FileBackend"]


class FileBackend(LayerBase):
    def __new__(
        cls, name: str, config: Mapping[str, ConfigValue] | None = None
    ) -> FileBackend: ...
