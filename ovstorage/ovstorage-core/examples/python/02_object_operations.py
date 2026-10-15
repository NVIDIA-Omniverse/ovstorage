#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Use the common object operations and inspect their typed results."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from _common import build_file_stack


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ovstorage-02-") as directory:
        root = Path(directory)
        # Reuse the one-backend Stack from the first tutorial so this example
        # can focus on the object API rather than repeat graph construction.
        storage = await build_file_stack(root, "tutorial")
        address = (root / "notes.txt").as_uri()

        # Mutating operations return typed information about their result. The
        # returned address is canonicalized by the backend.
        written = await storage.write(address, b"stat, list, read, delete\n")
        print(f"wrote {written.size} bytes to {written.address}")

        # stat retrieves metadata without transferring the object's contents.
        stated = await storage.stat(address)
        print(f"stat: kind={stated.kind}, etag={stated.etag}")

        # list accepts a directory-like prefix and returns one page. Production
        # callers continue with page.next_page_token when it is not None.
        page = await storage.list(root.as_uri() + "/")
        for item in page.items:
            print(f"list: {item.kind:4} {item.address}")

        # Bound in-memory reads even when the expected object is small. The
        # operation fails instead of allocating beyond max_bytes.
        data, _info = await storage.read_bytes(address, max_bytes=1024)
        print(f"read: {data.decode().rstrip()}")

        # delete removes the object at this exact address, not the connection
        # root or every object sharing the prefix.
        await storage.delete(address)
        print("deleted")


if __name__ == "__main__":
    asyncio.run(main())
