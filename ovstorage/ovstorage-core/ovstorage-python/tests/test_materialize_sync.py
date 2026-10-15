# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Loop-independent LocalDelegate release behavior."""

from __future__ import annotations

import asyncio
import pathlib

import ovstorage
from conftest import standard_registry


async def _materialize(root: pathlib.Path, path: pathlib.Path) -> ovstorage.LocalDelegate:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    stack = await (
        ovstorage.Stack(root="routes")
        .with_registry(standard_registry())
        .router(ovstorage.router.Router("routes", ["files"]))
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )
    return await stack.materialize(path.as_uri())


def test_close_is_loop_independent_and_idempotent(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "sync-release.bin"
    path.write_bytes(b"sync")
    delegate = asyncio.run(_materialize(tmp_path, path))

    # asyncio.run has closed its loop. close() must remain a plain,
    # loop-independent cleanup operation and tolerate repeated host cleanup.
    delegate.close()
    delegate.close()

    assert delegate.closed is True


def test_sync_context_manager_releases_without_a_running_loop(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "sync-context.bin"
    path.write_bytes(b"context")
    delegate = asyncio.run(_materialize(tmp_path, path))

    with delegate:
        assert pathlib.Path(delegate).read_bytes() == b"context"

    assert delegate.closed is True
