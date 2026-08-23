# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Composer graph validation is exposed through typed Python errors."""

from __future__ import annotations

import pytest

import conftest
import ovstorage

pytestmark = pytest.mark.asyncio


def _stack(root: str) -> ovstorage.Stack:
    return ovstorage.Stack(root=root).with_registry(conftest.standard_registry())


@pytest.mark.parametrize(
    ("composer", "message"),
    [
        (
            lambda: (
                _stack("retry")
                .wrapper(ovstorage.retry.Retry("retry", "routes"))
                .router(ovstorage.router.Router("routes", ["retry"]))
            ),
            "cycle",
        ),
        (
            lambda: _stack("routes").router(
                ovstorage.router.Router("routes", ["missing"])
            ),
            "referenced but not declared",
        ),
        (
            lambda: (
                _stack("files")
                .backend(ovstorage.file.FileBackend("files"))
                .backend(ovstorage.file.FileBackend("files"))
            ),
            "declared more than once",
        ),
        (
            lambda: (
                _stack("routes")
                .router(ovstorage.router.Router("routes", ["left", "right"]))
                .wrapper(ovstorage.retry.Retry("left", "files"))
                .wrapper(ovstorage.retry.Retry("right", "files"))
                .backend(ovstorage.file.FileBackend("files"))
            ),
            "referenced more than once",
        ),
        (
            lambda: _stack("unknown").backend(
                ovstorage.plugin.PluginBackend("unknown-kind", "unknown")
            ),
            "no factory registered",
        ),
        (
            lambda: _stack("wrong").backend(
                ovstorage.plugin.PluginBackend("router", "wrong")
            ),
            "mismatched layer_type",
        ),
    ],
    ids=("cycle", "dangling", "duplicate", "multiply-referenced", "unknown-kind", "layer-type-mismatch"),
)
async def test_invalid_compositions_raise_typed_errors(composer, message: str) -> None:
    expected = (
        ovstorage.NotConfiguredError if message == "no factory registered" else ovstorage.InvalidArgumentError
    )
    with pytest.raises(expected, match=message):
        await composer().build()
