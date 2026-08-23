#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Build the smallest useful Stack: one built-in file backend."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import ovstorage
from ovstorage.file import FileBackend


async def main() -> None:
    # A temporary root keeps the tutorial self-contained. A real application
    # normally points this connection at a durable directory instead.
    with tempfile.TemporaryDirectory(prefix="ovstorage-01-") as directory:
        root = Path(directory)

        # A backend describes how to perform operations; a connection supplies
        # one configured address scope. Here, the `root` setting restricts this
        # connection to file:// addresses beneath the temporary directory.
        request = ovstorage.ConnectionRequest("file")
        request.add_config("root", ovstorage.ConfigValue.string(str(root)))

        # Stack is an immutable graph builder. `root="files"` names the Layer
        # that receives each operation, and build() validates and instantiates
        # the complete graph before it can serve requests.
        storage = await (
            ovstorage.Stack(root="files")
            .backend(FileBackend("files"))
            .connection("files", request)
            .build()
        )

        # Applications pass storage URLs to every operation. The file backend
        # translates this URL to a native path only after matching it against
        # the connection declared above.
        address = (root / "hello.txt").as_uri()
        await storage.write(address, b"hello, ovstorage\n")

        # read_bytes collects a read stream into memory and returns both the
        # bytes and object metadata. Later examples use the metadata directly.
        data, _info = await storage.read_bytes(address)
        print(data.decode().rstrip())


if __name__ == "__main__":
    asyncio.run(main())
