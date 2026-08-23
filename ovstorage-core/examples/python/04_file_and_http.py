#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Route file and HTTP addresses, then compare their capabilities."""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

import ovstorage
from ovstorage.file import FileBackend
from ovstorage.plugin import PluginBackend
from ovstorage.redirect_follower import RedirectFollower
from ovstorage.router import Router

from _common import (
    file_connection_request,
    http_connection_request,
    origin_prefix,
    plugin_registry,
)


async def run(url: str, plugin_dir: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix="ovstorage-04-") as directory:
        root = Path(directory)

        # This graph gives one storage handle two address families. The router
        # chooses `files` for file:// and `web` for HTTP(S); the outer redirect
        # follower transparently continues reads when a backend returns a
        # redirect instead of bytes.
        #
        #     redirects (root/wrapper)
        #       └── routes (router)
        #           ├── files (built-in backend)
        #           └── web (HTTP plugin backend)
        storage = await (
            ovstorage.Stack(root="redirects")
            .with_registry(plugin_registry(plugin_dir, "core", "http"))
            .wrapper(RedirectFollower("redirects", "routes"))
            .router(Router("routes", ["files", "web"]))
            .backend(FileBackend("files"))
            .backend(PluginBackend("http", "web"))
            .connection("files", file_connection_request(root, "local files"))
            .connection("web", http_connection_request(origin_prefix(url), "public HTTP"))
            .build()
        )

        # Both URLs enter the same root Layer. Routing is a property of the
        # configured graph, so application code does not select a backend.
        local = (root / "local.txt").as_uri()
        await storage.write(local, b"local data\n")
        print("file read:", (await storage.read_bytes(local))[0].decode().rstrip())
        print("http read:", len((await storage.read_bytes(url, max_bytes=1024 * 1024))[0]), "bytes")

        # Backends advertise different capabilities. A filesystem has
        # directory listings; this HTTP backend models individual web objects
        # and reports Unsupported for list rather than emulating a directory.
        page = await storage.list(root.as_uri() + "/")
        print("file list:", [item.address for item in page.items])
        try:
            await storage.list(origin_prefix(url))
        except ovstorage.UnsupportedError as error:
            print(f"http list: {error.code} (HTTP addresses are objects, not directories)")
        else:
            raise SystemExit("expected the HTTP backend to reject list with Unsupported")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "url",
        nargs="?",
        default="https://raw.githubusercontent.com/NVIDIA-Omniverse/ovstorage/main/README.md",
    )
    parser.add_argument("--plugin-dir")
    args = parser.parse_args()
    asyncio.run(run(args.url, args.plugin_dir))


if __name__ == "__main__":
    main()
