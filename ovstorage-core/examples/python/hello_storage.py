#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Minimal local `ovstorage` Python example.

This example deliberately uses only the Python standard library plus
`ovstorage`. It creates a temporary local-file route, then writes, stats,
lists, reads, materializes, and deletes one object.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
from pathlib import Path

import ovstorage

from _common import build_file_stack


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory to load. Defaults to OVSTORAGE_PLUGIN_DIR.",
    )
    return parser.parse_args()


def _print_info(label: str, info: object) -> None:
    print(f"{label}:")
    print(f"  address: {getattr(info, 'address')}")
    print(f"  kind:    {getattr(info, 'kind')}")
    print(f"  size:    {getattr(info, 'size')}")
    print(f"  etag:    {getattr(info, 'etag')}")


async def _run(plugin_dir: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix="ovstorage-hello-") as tmp:
        root = Path(tmp).resolve()
        # `file` is the one built-in backend; --plugin-dir is accepted for
        # command-line compatibility but is not needed here.
        del plugin_dir
        storage = await build_file_stack(root, "hello-storage-local")

        address = (root / "hello.txt").as_uri()
        payload = b"hello from ovstorage\n"

        connection = (await storage.list_connections())[0]
        print(f"connected: {connection.id}")
        print(f"root:      {root}")
        print()

        written = await storage.write(address, payload)
        _print_info("write", written)
        print()

        stat = await storage.stat(address)
        _print_info("stat", stat)
        print()

        page = await storage.list(root.as_uri() + "/", max_results=20)
        print("list:")
        for item in page.items:
            print(f"  {item.kind:18} {item.size or '-':>8} {item.address}")
        print()

        data, info = await storage.read_bytes(address, max_bytes=1024)
        _print_info("read", info)
        print(f"  payload: {data.decode('utf-8').rstrip()}")
        print()

        async with await storage.materialize(address) as delegate:
            print("materialize:")
            print(f"  local path: {os.fspath(delegate)}")
            print(f"  bytes:      {Path(delegate).read_text(encoding='utf-8').rstrip()}")
        print()

        await storage.delete(address)
        print(f"delete: {address}")


async def _main() -> None:
    args = _parse_args()
    await _run(args.plugin_dir)


if __name__ == "__main__":
    asyncio.run(_main())
