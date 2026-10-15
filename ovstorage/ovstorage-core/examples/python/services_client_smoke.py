#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Smoke-test the Omniverse Storage Service plugin through a composed Stack.

The connection, plugin registry, and OAuth token are declared before
``Stack.build()``. Interactive authentication completion is deferred from the
reduced M1 surface, so this example intentionally requires token credentials.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys
import time

import ovstorage as ov

from _common import build_plugin_stack


BACKEND_KIND = "omniverse-storage-service"
DEFAULT_OIDC_CLIENT_NAME = "client_library"
DEFAULT_MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-dir", help="Directory containing the services-client plugin.")
    parser.add_argument("--address", required=True)
    parser.add_argument("--oidc-client-name", default=DEFAULT_OIDC_CLIENT_NAME)
    parser.add_argument(
        "--auth",
        nargs="+",
        required=True,
        metavar="AUTH",
        help="token ACCESS_TOKEN [REFRESH_TOKEN] (interactive auth is deferred in M1)",
    )
    parser.add_argument("--stat", help="Optional object address to stat.")
    parser.add_argument(
        "--download",
        help="Optional object address to read, bounded by --max-download-bytes.",
    )
    parser.add_argument("--download-output", type=Path)
    parser.add_argument(
        "--max-download-bytes",
        type=int,
        default=DEFAULT_MAX_DOWNLOAD_BYTES,
        help=f"Maximum download size in bytes (default: {DEFAULT_MAX_DOWNLOAD_BYTES}).",
    )
    args = parser.parse_args()
    if args.auth[0] != "token" or len(args.auth) not in (2, 3):
        parser.error("--auth requires token ACCESS_TOKEN [REFRESH_TOKEN]")
    if args.max_download_bytes <= 0:
        parser.error("--max-download-bytes must be greater than zero")
    return args


def request_from_args(args: argparse.Namespace) -> ov.ConnectionRequest:
    request = ov.ConnectionRequest(BACKEND_KIND)
    request.add_config("address", ov.ConfigValue.string(args.address))
    request.add_config("oidc_client_name", ov.ConfigValue.string(args.oidc_client_name))
    request.set_display_name(f"{BACKEND_KIND}:{args.address}")
    access = args.auth[1].encode("utf-8")
    refresh = args.auth[2].encode("utf-8") if len(args.auth) == 3 else None
    request.add_credential("oauth", ov.SecretValue.oauth_token(access, refresh))
    return request


async def download_if_requested(storage: ov.LayerBase, args: argparse.Namespace) -> None:
    if not args.download:
        return
    started = time.perf_counter()
    data, info = await storage.read_bytes(
        args.download,
        max_bytes=args.max_download_bytes,
    )
    print(f"download: {args.download} (reported size: {info.size})")
    if args.download_output is not None:
        args.download_output.parent.mkdir(parents=True, exist_ok=True)
        args.download_output.write_bytes(data)
    elapsed = time.perf_counter() - started
    print(f"download ok: {len(data)} bytes in {elapsed:.3f}s")


async def main() -> None:
    args = parse_args()
    storage = await build_plugin_stack(
        args.plugin_dir,
        "services_client",
        BACKEND_KIND,
        request_from_args(args),
        interactive_auth_capability=ov.InteractiveAuthCapability.NONE,
    )
    for connection in await storage.list_connections():
        print(
            f"connection: id={connection.id} state={connection.auth_state_kind} "
            f"addresses={len(connection.addresses)}"
        )
    roots = await storage.list_address_roots()
    for root in roots:
        print(f"address root: {root.address} ({root.backend_kind}, {root.visibility})")
    if args.stat:
        info = await storage.stat(args.stat)
        print(f"stat ok: address={info.address} size={info.size} version={info.version}")
    await download_if_requested(storage, args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        raise SystemExit(130)
