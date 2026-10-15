#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Browse a small temporary file:// tree through `ovstorage`.

This example deliberately uses only the Python standard library plus
`ovstorage`. It creates a temporary local-file route, writes a few sample
objects, lists the route, and previews text-like files.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

import ovstorage

from _common import (
    build_file_stack,
    display_name,
    format_size,
    looks_text,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory to load. Defaults to OVSTORAGE_PLUGIN_DIR.",
    )
    parser.add_argument("--preview-bytes", type=int, default=4096)
    return parser.parse_args()


async def _seed(storage: ovstorage.LayerBase, root: Path) -> None:
    objects = {
        "README.txt": b"ovstorage file browser demo\n",
        "scene.usda": (
            b"#usda 1.0\n"
            b"(\n"
            b"    defaultPrim = \"World\"\n"
            b")\n\n"
            b"def Xform \"World\"\n"
            b"{\n"
            b"}\n"
        ),
        "metadata.json": b"{\n  \"source\": \"ovstorage demo\",\n  \"version\": 1\n}\n",
    }
    for name, data in objects.items():
        await storage.write((root / name).as_uri(), data)


async def _run(plugin_dir: str | None, preview_bytes: int) -> None:
    with tempfile.TemporaryDirectory(prefix="ovstorage-browser-") as tmp:
        root = Path(tmp).resolve()
        del plugin_dir
        storage = await build_file_stack(root, "file-browser-local")
        prefix = root.as_uri() + "/"

        await _seed(storage, root)

        print("ovstorage file browser")
        print(f"root: {root}")
        print()

        page = await storage.list(prefix, max_results=100)
        print("list:")
        for index, item in enumerate(page.items, start=1):
            address = getattr(item, "address")
            name = display_name(prefix, address)
            size = format_size(getattr(item, "size", None))
            print(f"  {index:2}. {getattr(item, 'kind'):18} {size:>10}  {name}")

        print()
        print("preview:")
        for item in page.items:
            address = getattr(item, "address")
            data, info = await storage.read_bytes(address, max_bytes=preview_bytes)
            if not looks_text(address, data):
                continue
            print(f"  {display_name(prefix, info.address)} ({len(data)} bytes)")
            for line in data.decode("utf-8", errors="replace").splitlines()[:5]:
                print(f"    {line}")


async def _main() -> None:
    args = _parse_args()
    await _run(args.plugin_dir, args.preview_bytes)


if __name__ == "__main__":
    asyncio.run(_main())
