# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable

async def _dispatch(start: Callable[[], Any]) -> Any: ...
async def _ready(value: Any) -> Any: ...
