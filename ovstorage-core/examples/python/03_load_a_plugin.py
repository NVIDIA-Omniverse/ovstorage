#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Load the core plugin explicitly and put its Router over file."""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

import ovstorage
from ovstorage.file import FileBackend
from ovstorage.router import Router

from _common import file_connection_request, plugin_registry


async def run(plugin_dir: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix="ovstorage-03-") as directory:
        root = Path(directory)

        # Unlike the built-in file backend, Router comes from the core plugin.
        # An explicit registry loads that shared library and makes its Layer
        # factories available while this Stack is built.
        registry = plugin_registry(plugin_dir, "core")

        # Requests enter `routes`, whose ordered children are the candidate
        # backends. The router compares each child's declared address roots and
        # sends this example's file:// URL to `files`.
        #
        #     routes (root/router)
        #       └── files (backend + connection)
        storage = await (
            ovstorage.Stack(root="routes")
            .with_registry(registry)
            .router(Router("routes", ["files"]))
            .backend(FileBackend("files"))
            .connection("files", file_connection_request(root, "local files"))
            .build()
        )

        # Callers use the same storage API regardless of how many routing or
        # wrapper Layers sit between the Stack root and the selected backend.
        address = (root / "routed.txt").as_uri()
        await storage.write(address, b"the core plugin routed this request\n")
        data, _info = await storage.read_bytes(address)
        print(data.decode().rstrip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-dir")
    args = parser.parse_args()
    asyncio.run(run(args.plugin_dir))


if __name__ == "__main__":
    main()
