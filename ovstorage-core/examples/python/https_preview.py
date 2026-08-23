#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read and preview one anonymous HTTPS object through `ovstorage`.

The HTTP plugin treats an HTTPS URL as a single object, not as a browsable
directory. This example creates a temporary runtime route for the URL's
origin, reads the exact URL passed on the command line, and prints a small
preview when the response appears to be text.
"""

from __future__ import annotations

import argparse
import asyncio
from urllib.parse import urlsplit

import ovstorage

from _common import (
    build_plugin_stack,
    format_size,
    http_connection_request,
    looks_text,
    origin_prefix,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Anonymous HTTPS object URL to read.")
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory to load. Defaults to OVSTORAGE_PLUGIN_DIR.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1024 * 1024,
        help="Maximum object size to read into memory.",
    )
    parser.add_argument("--preview-lines", type=int, default=12)
    return parser.parse_args()


def _require_https(url: str) -> None:
    if urlsplit(url).scheme != "https":
        raise SystemExit("pass an https:// URL")


def _print_info(info: object) -> None:
    print(f"address: {getattr(info, 'address')}")
    print(f"kind:    {getattr(info, 'kind')}")
    print(f"size:    {format_size(getattr(info, 'size', None))}")
    print(f"etag:    {getattr(info, 'etag')}")


async def _run(
    url: str,
    plugin_dir: str | None,
    max_bytes: int,
    preview_lines: int,
) -> None:
    _require_https(url)
    storage = await build_plugin_stack(
        plugin_dir,
        "http",
        "http",
        http_connection_request(origin_prefix(url), "anonymous-https-preview"),
    )
    data, info = await storage.read_bytes(url, max_bytes=max_bytes)
    print("read:")
    _print_info(info)
    print(f"bytes:   {len(data)}")
    print()

    print("preview:")
    if looks_text(url, data):
        for line in data.decode("utf-8", errors="replace").splitlines()[:preview_lines]:
            print(f"  {line}")
    else:
        print(f"  {data[:256].hex(' ')}")


async def _main() -> None:
    args = _parse_args()
    await _run(args.url, args.plugin_dir, args.max_bytes, args.preview_lines)


if __name__ == "__main__":
    asyncio.run(_main())
