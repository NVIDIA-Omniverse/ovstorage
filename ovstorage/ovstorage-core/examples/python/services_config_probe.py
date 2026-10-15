#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Probe an Omniverse Storage Service connection from an ovstorage config file.

The standard ``[ovstorage]`` document declares the graph this probe needs: a
``redirect_follower`` root wrapping a router over an
``omniverse-storage-service`` backend, plus ``[[ovstorage.connections]]``.
``ovstorage write-config`` emits this same file shape, and ``${ENV}``
credential references resolve when the stack is built. See the adjacent
README's "Additional examples" section for a complete sample TOML document.

The script loads the core, HTTP, and services-client plugins, prints the
configured address roots, and optionally probes one address.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import ovstorage

from _common import display_name, format_size, looks_text, plugin_registry


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        required=True,
        help="Path to an ovstorage.toml that defines the service connection.",
    )
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory to load. Defaults to OVSTORAGE_PLUGIN_DIR.",
    )
    parser.add_argument(
        "--address",
        help="Optional address to probe after config loading.",
    )
    parser.add_argument(
        "--operation",
        choices=("stat", "list", "read"),
        default="stat",
        help="Probe operation to run when --address is provided.",
    )
    parser.add_argument("--max-results", type=int, default=25)
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--preview-lines", type=int, default=12)
    return parser.parse_args()


def _print_info(info: object) -> None:
    print(f"address: {getattr(info, 'address')}")
    print(f"kind:    {getattr(info, 'kind')}")
    print(f"size:    {format_size(getattr(info, 'size', None))}")
    print(f"etag:    {getattr(info, 'etag')}")


def _print_roots(roots: list[ovstorage.AddressRoot]) -> None:
    print("address roots:")
    if not roots:
        print("  none")
        return
    for root in roots:
        print(f"  {root.address}  ({root.backend_kind}, {root.visibility})")


async def _list_address(
    storage: ovstorage.LayerBase,
    address: str,
    max_results: int,
) -> None:
    page = await storage.list(address, max_results=max_results)
    print(f"list: {address}")
    if not page.items:
        print("  empty")
        return
    for index, item in enumerate(page.items, start=1):
        item_address = getattr(item, "address")
        name = display_name(address if address.endswith("/") else address + "/", item_address)
        size = format_size(getattr(item, "size", None))
        print(f"  {index:2}. {getattr(item, 'kind'):18} {size:>10}  {name}")
    if page.next_page_token:
        print("  next page available")


async def _read_address(
    storage: ovstorage.LayerBase,
    address: str,
    max_bytes: int,
    preview_lines: int,
) -> None:
    data, info = await storage.read_bytes(address, max_bytes=max_bytes)
    print("read:")
    _print_info(info)
    print(f"bytes:   {len(data)}")
    print()
    print("preview:")
    if looks_text(address, data):
        for line in data.decode("utf-8", errors="replace").splitlines()[:preview_lines]:
            print(f"  {line}")
    else:
        print(f"  {data[:256].hex(' ')}")


async def _run(args: argparse.Namespace) -> None:
    composer = ovstorage.Stack.from_config(path=args.config).with_registry(
        plugin_registry(args.plugin_dir, "core", "http", "services_client")
    )
    storage = await composer.build()
    connections = await storage.list_connections()
    roots = await storage.list_address_roots()

    if not connections and not roots:
        print(
            f"{args.config} declared no [ovstorage] stack; this example requires the\n"
            "standard [ovstorage] document shown in the README. Legacy top-level\n"
            "[[connections]] entries are ignored.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print("connections:")
    if not connections:
        print("  none")
    for connection in connections:
        print(
            f"  {connection.id}  "
            f"({connection.backend_kind}, {connection.auth_state_kind})"
        )
    print()

    _print_roots(roots)

    if not args.address:
        return

    print()
    if args.operation == "stat":
        info = await storage.stat(args.address)
        print("stat:")
        _print_info(info)
    elif args.operation == "list":
        await _list_address(storage, args.address, args.max_results)
    else:
        await _read_address(
            storage,
            args.address,
            args.max_bytes,
            args.preview_lines,
        )


async def _main() -> None:
    try:
        await _run(_parse_args())
    except ovstorage.Error as exc:
        print(f"ovstorage error: {exc}", file=sys.stderr)
        if getattr(exc, "next_action", None):
            print(f"next action: {exc.next_action}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    asyncio.run(_main())
