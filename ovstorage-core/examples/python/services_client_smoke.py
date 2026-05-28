#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Smoke-test the Omniverse Storage Service plugin: auth, address-root refresh, and dispatch.

Examples:

  export OVSTORAGE_SERVICES_DISCOVERY_URL="<discovery-url>"
  export OVSTORAGE_SERVICES_STAT_ADDRESS="<object-address-to-stat>"
  export OVSTORAGE_SERVICES_DOWNLOAD_ADDRESS="<object-address-to-download>"

  python ovstorage-core/examples/python/services_client_smoke.py \
      --plugin-dir "${OVSTORAGE_PLUGIN_DIR}" \
      --discovery-url "${OVSTORAGE_SERVICES_DISCOVERY_URL}" \
      --print-tokens \
      --stat "${OVSTORAGE_SERVICES_STAT_ADDRESS}" \
      --download "${OVSTORAGE_SERVICES_DOWNLOAD_ADDRESS}"

  python ovstorage-core/examples/python/services_client_smoke.py \
      --auth token "${OVSTORAGE_SERVICES_ACCESS_TOKEN}" "${OVSTORAGE_SERVICES_REFRESH_TOKEN}" \
      --discovery-url "${OVSTORAGE_SERVICES_DISCOVERY_URL}" \
      --stat "${OVSTORAGE_SERVICES_STAT_ADDRESS}"
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import shlex
import sys
import time
import webbrowser

try:
    import ovstorage as ov
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Could not import the ovstorage Python module. Build/install "
        "ovstorage-python first, then rerun this script."
    ) from exc


DEFAULT_OIDC_CLIENT_NAME = "client_library"
ACCESS_TOKEN_EXPORT_ENV = "OVSTORAGE_SERVICES_ACCESS_TOKEN"
REFRESH_TOKEN_EXPORT_ENV = "OVSTORAGE_SERVICES_REFRESH_TOKEN"
BACKEND_KIND = "omniverse-storage-service"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exercise the services-client plugin Python auth and address-root routing."
    )
    parser.add_argument(
        "--plugin-dir",
        help="Directory containing ovstorage plugin .so files. Omit to use the library default.",
    )
    parser.add_argument(
        "--config",
        help="Optional TOML config to load instead of adding a services-client connection programmatically.",
    )
    parser.add_argument(
        "--discovery-url",
        help="Omniverse Storage Service discovery URL. Required unless --config is provided.",
    )
    parser.add_argument("--oidc-client-name", default=DEFAULT_OIDC_CLIENT_NAME)
    parser.add_argument(
        "--auth",
        nargs="+",
        default=["interactive"],
        metavar="AUTH",
        help=(
            "Use interactive auth, or token auth as: "
            "--auth token [access-token] [refresh-token]."
        ),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Request device-code auth instead of browser auth in interactive mode.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Print browser URLs but do not call webbrowser.open().",
    )
    parser.add_argument(
        "--print-tokens",
        action="store_true",
        help="Print shell export lines for tokens returned by interactive auth.",
    )
    parser.add_argument(
        "--stat",
        help="Optional object address to stat after roots are populated.",
    )
    parser.add_argument(
        "--download",
        help="Optional object address to stream after roots are populated.",
    )
    parser.add_argument(
        "--download-output",
        type=Path,
        help="Optional local path to write the downloaded bytes. Omit to discard after timing.",
    )
    args = parser.parse_args()
    return normalize_auth_args(parser, args)


def normalize_auth_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> argparse.Namespace:
    auth_parts = args.auth
    mode = auth_parts[0]
    if mode not in ("interactive", "token"):
        parser.error("--auth must be either 'interactive' or 'token'")
    if mode == "interactive" and len(auth_parts) > 1:
        parser.error("--auth interactive does not accept token arguments")
    if mode == "token" and len(auth_parts) > 3:
        parser.error("--auth token accepts at most access and refresh tokens")

    args.auth = mode
    args.access_token = auth_parts[1] if len(auth_parts) > 1 else None
    args.refresh_token = auth_parts[2] if len(auth_parts) > 2 else None
    return args


def make_library(args: argparse.Namespace) -> ov.Library:
    if args.auth == "token":
        capability = ov.InteractiveAuthCapability.NONE
    elif args.headless:
        capability = ov.InteractiveAuthCapability.HEADLESS
    else:
        capability = ov.InteractiveAuthCapability.BROWSER
    return ov.Library.open(interactive_auth_capability=capability)


async def load_plugins(lib: ov.Library, plugin_dir: str | None) -> None:
    print(f"loading plugins from: {plugin_dir or '<library default>'}")
    await lib.load_plugins_from_dir(plugin_dir)


async def get_connection(lib: ov.Library, args: argparse.Namespace) -> ov.Connection:
    if args.config:
        print(f"loading config: {args.config}")
        await lib.load_config(args.config)
    else:
        if not args.discovery_url:
            raise RuntimeError("--discovery-url is required unless --config is provided")
        request = ov.ConnectionRequest(BACKEND_KIND)
        request.add_config("discovery_url", ov.ConfigValue.string(args.discovery_url))
        request.add_config("oidc_client_name", ov.ConfigValue.string(args.oidc_client_name))
        request.set_display_name(f"{BACKEND_KIND}:{args.discovery_url}")
        print(f"adding {BACKEND_KIND} connection: {args.discovery_url}")
        await lib.add_connection(request)

    connections = await lib.list_connections()
    for conn in connections:
        if conn.backend_kind == BACKEND_KIND:
            print_connection("initial connection", conn)
            return conn
    raise RuntimeError(f"no {BACKEND_KIND} connection found")


def print_connection(label: str, conn: ov.Connection) -> None:
    print(
        f"{label}: id={conn.id} state={conn.auth_state_kind} "
        f"addresses={len(conn.addresses)}"
    )
    for address in conn.addresses:
        print(f"  conn.address: {address}")


def print_token_exports(event: ov.AuthEvent, args: argparse.Namespace) -> None:
    access = event.oauth_access_token
    if not args.print_tokens:
        return
    if access is None:
        print("auth succeeded without a returned OAuth bundle; no token env exports")
        return

    try:
        access_text = access.decode("utf-8")
        refresh_text = (
            event.oauth_refresh_token.decode("utf-8")
            if event.oauth_refresh_token is not None
            else None
        )
    except UnicodeDecodeError as exc:
        raise RuntimeError("OAuth token bytes were not valid UTF-8") from exc

    print("token env exports for a later --auth token run:")
    print(f"  export {ACCESS_TOKEN_EXPORT_ENV}={shlex.quote(access_text)}")
    if refresh_text is not None:
        print(f"  export {REFRESH_TOKEN_EXPORT_ENV}={shlex.quote(refresh_text)}")


async def authenticate_interactively(
    lib: ov.Library, conn: ov.Connection, args: argparse.Namespace
) -> ov.Connection:
    if conn.auth_state_kind in ("Authenticated", "Anonymous"):
        return conn

    print("starting interactive authentication")
    stream = await lib.authenticate_connection(conn.id)
    async for event in stream:
        print(f"auth event: {event.kind}")
        if event.kind == "OpenBrowser":
            if event.url:
                print(f"  url: {event.url}")
                if not args.no_browser:
                    webbrowser.open(event.url)
        elif event.kind == "DeviceCode":
            print(f"  user_code: {event.user_code}")
            print(f"  verification_url: {event.verification_url}")
        elif event.kind == "Progress":
            print(f"  {event.message}")
        elif event.kind == "Succeeded":
            if event.connection is None:
                raise RuntimeError("auth succeeded without a connection payload")
            print_token_exports(event, args)
            print_connection("authenticated connection", event.connection)
            return event.connection
        elif event.kind == "Failed":
            raise RuntimeError(f"auth failed: {event.error_code}: {event.message}")
        elif event.kind == "Cancelled":
            raise RuntimeError("auth cancelled")

    raise RuntimeError("authentication stream ended before success")


async def install_token_bundle(
    lib: ov.Library, conn: ov.Connection, args: argparse.Namespace
) -> ov.Connection:
    access_text = args.access_token
    refresh_text = args.refresh_token

    bundle = ov.SecretBundle()
    if access_text is None:
        print("installing empty bundle through update_connection_credentials")
    else:
        access = access_text.encode("utf-8")
        refresh = refresh_text.encode("utf-8") if refresh_text is not None else None
        bundle.add(
            "oauth",
            ov.SecretValue.oauth_token(access, refresh),
        )
        print("installing OAuth bundle through update_connection_credentials")
    updated = await lib.update_connection_credentials(conn.id, bundle)
    print_connection("updated connection", updated)
    return updated


async def ensure_address_roots(lib: ov.Library) -> None:
    roots = await lib.list_address_roots()
    if not roots:
        raise RuntimeError("no address roots were published after auth")


async def stat_if_requested(lib: ov.Library, address: str | None) -> None:
    if not address:
        return
    print(f"stat: {address}")
    info = await lib.stat(address)
    print(f"stat ok: address={info.address} size={info.size} version={info.version}")


async def download_if_requested(lib: ov.Library, args: argparse.Namespace) -> None:
    if not args.download:
        return

    output = args.download_output
    print(f"download: {args.download}")
    stream, info = await lib.read_stream(args.download)
    if info.size is not None:
        print(f"  reported size: {info.size} bytes")

    total = 0
    started = time.perf_counter()
    if output is None:
        async for chunk in stream:
            total += len(chunk)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("wb") as fh:
            async for chunk in stream:
                total += len(chunk)
                fh.write(chunk)

    elapsed = time.perf_counter() - started
    mb = total / 1_000_000
    mbps = mb / elapsed if elapsed > 0 else float("inf")
    destination = str(output) if output is not None else "<discarded>"
    print(
        f"download ok: {total} bytes to {destination} "
        f"in {elapsed:.3f}s ({mbps:.2f} MB/s)"
    )


async def main() -> None:
    args = parse_args()
    lib = make_library(args)
    await load_plugins(lib, args.plugin_dir)
    conn = await get_connection(lib, args)

    if args.auth == "token":
        conn = await install_token_bundle(lib, conn, args)
    else:
        conn = await authenticate_interactively(lib, conn, args)

    connections = await lib.list_connections()
    refreshed = next((candidate for candidate in connections if candidate.id == conn.id), conn)
    print_connection("post-auth list_connections view", refreshed)
    await ensure_address_roots(lib)
    await stat_if_requested(lib, args.stat)
    await download_if_requested(lib, args)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        raise SystemExit(130)
