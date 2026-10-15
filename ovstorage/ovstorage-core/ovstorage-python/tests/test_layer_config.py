# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Layer configuration reaches dynamically loaded factories."""

from __future__ import annotations

import asyncio
import pathlib
from types import MappingProxyType

import pytest

import conftest
import ovstorage

pytestmark = pytest.mark.asyncio


async def test_wrapper_config_is_forwarded_to_plugin_factory(
    tmp_path: pathlib.Path,
) -> None:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))

    composer = (
        ovstorage.Stack(root="retry")
        .with_registry(conftest.standard_registry())
        .wrapper(
            ovstorage.retry.Retry(
                "retry",
                "files",
                config=MappingProxyType(
                    {"max_attempts": ovstorage.ConfigValue.int_(0)}
                ),
            )
        )
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
    )

    with pytest.raises(
        ovstorage.InvalidArgumentError,
        match="max_attempts must be at least 1",
    ):
        await asyncio.wait_for(composer.build(), timeout=5)


async def test_layer_config_requires_typed_values() -> None:
    with pytest.raises(
        ovstorage.InvalidArgumentError,
        match="must be a ConfigValue",
    ):
        ovstorage.retry.Retry(
            "retry",
            "files",
            config={"max_attempts": 3},  # type: ignore[dict-item]
        )
