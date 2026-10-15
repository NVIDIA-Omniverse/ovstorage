#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Add plugin-provided metadata and content caches to the routed Stack."""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

import ovstorage
from ovstorage.byte_cache import ByteCache
from ovstorage.file import FileBackend
from ovstorage.metadata_cache import MetadataCache
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
    with tempfile.TemporaryDirectory(prefix="ovstorage-05-") as directory:
        work = Path(directory)

        # Wrappers compose from the Stack root inward. ByteCache sees reads
        # first and stores content; MetadataCache independently stores stat-like
        # results; misses continue through redirect handling and routing.
        #
        #     content-cache (root/byte cache)
        #       └── metadata-cache
        #           └── redirects
        #               └── routes
        #                   ├── files
        #                   └── web
        storage = await (
            ovstorage.Stack(root="content-cache")
            .with_registry(plugin_registry(plugin_dir, "core", "cache", "http"))
            .wrapper(
                ByteCache(
                    "content-cache",
                    "metadata-cache",
                    {
                        "cache_root": ovstorage.ConfigValue.string(str(work / "content")),
                        "state_root": ovstorage.ConfigValue.string(str(work / "state")),
                    },
                )
            )
            .wrapper(
                MetadataCache(
                    "metadata-cache",
                    "redirects",
                    {"ttl_seconds": ovstorage.ConfigValue.int_(60)},
                )
            )
            .wrapper(RedirectFollower("redirects", "routes"))
            .router(Router("routes", ["files", "web"]))
            .backend(FileBackend("files"))
            .backend(PluginBackend("http", "web"))
            .connection("files", file_connection_request(work / "files", "local files"))
            .connection("web", http_connection_request(origin_prefix(url), "public HTTP"))
            .build()
        )

        # Repeating the same bounded read demonstrates that callers do not need
        # a cache-specific API. Cache lookup and fill happen inside the Layer.
        for attempt in (1, 2):
            data, _info = await storage.read_bytes(url, max_bytes=1024 * 1024)
            print(f"read {attempt}: {len(data)} bytes")

        # Metadata has its own policy and TTL, so repeated stat operations are
        # shown separately from content reads.
        for attempt in (1, 2):
            info = await storage.stat(url)
            print(f"stat {attempt}: size={info.size}, etag={info.etag}")

        # The content and state roots are application-owned locations. Keeping
        # them separate makes cached bytes distinct from SQLite bookkeeping.
        print("content cache:", work / "content")
        print("cache state:  ", work / "state")
        # Release the cache Layer and its SQLite state before TemporaryDirectory
        # removes the files. This ordering is required on Windows.
        del storage


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
