#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Probe an Omniverse Storage Service connection from an ovstorage config file.

This example keeps service details outside the source tree. Provide an
`ovstorage.toml` prepared for the service instance you want to reach; the
script loads the services-client plugin, loads that config, prints the
configured address roots, and optionally probes one address.

Python 3.10 users need the ``tomli`` package; Python 3.11 and newer use the
standard-library ``tomllib`` module.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import re
import sys
from typing import Any, BinaryIO, Protocol, cast


class _TomlModule(Protocol):
    def load(self, fp: BinaryIO, /) -> dict[str, Any]: ...


if sys.version_info >= (3, 11):
    import tomllib as _tomllib
else:
    try:
        _tomllib = importlib.import_module("tomli")
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Python 3.10 requires 'tomli' for this example; "
            "install it with: python -m pip install tomli"
        ) from exc
tomllib = cast(_TomlModule, _tomllib)

import ovstorage
from ovstorage.plugin import PluginBackend
from ovstorage.redirect_follower import RedirectFollower
from ovstorage.router import Router

from _common import display_name, format_size, looks_text, plugin_registry


# Mirrors the Rust config's credential substitution: `${NAME}` (strict POSIX
# identifier) is replaced from the environment and a missing variable is an
# error; any other text — including `${VAR:-default}` — passes through
# literally. Keep this in sync with `resolve_env_refs` in ovstorage-layer.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve_env_refs(raw: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        try:
            return os.environ[name]
        except KeyError:
            raise ValueError(f"credential env var {name!r} is not set") from None

    return _ENV_REF.sub(_sub, raw)


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


async def _print_roots(storage: ovstorage.LayerBase) -> None:
    roots = await storage.list_address_roots()
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
    with open(args.config, "rb") as config_file:
        config = tomllib.load(config_file)
    declarations = config.get("connections", [])
    if not isinstance(declarations, list):
        raise ValueError("ovstorage.toml [[connections]] must be an array")

    # The services client answers reads with a redirect, so front the router
    # with a redirect follower or `read` probes fail with an internal error.
    composer = ovstorage.Stack(root="redirects").with_registry(
        plugin_registry(args.plugin_dir, "core", "http", "services_client")
    )
    composer.wrapper(RedirectFollower("redirects", "routes"))
    children: list[str] = []
    for index, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            raise ValueError("each [[connections]] entry must be a table")
        backend_kind = declaration.get("backend_kind")
        if not isinstance(backend_kind, str):
            raise ValueError("each connection needs a string backend_kind")
        name = f"backend-{index}"
        children.append(name)
        composer.backend(PluginBackend(backend_kind, name))
        request = ovstorage.ConnectionRequest(backend_kind)
        display = declaration.get("display_name")
        if display is not None:
            if not isinstance(display, str):
                raise ValueError("display_name must be a string")
            request.set_display_name(display)
        values = declaration.get("config", {})
        if not isinstance(values, dict):
            raise ValueError("connections.config must be a table")
        for key, value in values.items():
            if isinstance(value, str):
                request.add_config(key, ovstorage.ConfigValue.string(value))
            elif isinstance(value, bool):
                request.add_config(key, ovstorage.ConfigValue.bool_(value))
            elif isinstance(value, int):
                request.add_config(key, ovstorage.ConfigValue.int_(value))
            else:
                raise ValueError(f"connections.config.{key} must be a string, bool, or int")
        # Carry the connection's credentials too; dropping them would let a
        # valid service config build but fail authentication on the probe.
        secrets = declaration.get("credentials", {})
        if not isinstance(secrets, dict):
            raise ValueError("connections.credentials must be a table")
        for key, value in secrets.items():
            # `bool` is a subclass of `int`; both (and tables) are rejected
            # rather than silently coerced into a secret.
            if not isinstance(value, str) or isinstance(value, bool):
                raise ValueError(
                    f"connections.credentials.{key} must be a string; this example "
                    "cannot safely resolve non-string credential forms"
                )
            resolved = _resolve_env_refs(value)
            request.add_credential(key, ovstorage.SecretValue.bytes(resolved.encode("utf-8")))
        composer.connection(name, request)
    composer.router(Router("routes", children))
    storage = await composer.build()
    connections = await storage.list_connections()

    print("connections:")
    if not connections:
        print("  none")
    for connection in connections:
        print(
            f"  {connection.id}  "
            f"({connection.backend_kind}, {connection.auth_state_kind})"
        )
    print()

    await _print_roots(storage)

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
