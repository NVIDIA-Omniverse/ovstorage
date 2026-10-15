#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the Python examples."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

import ovstorage
from ovstorage.file import FileBackend
from ovstorage.plugin import PluginBackend
from ovstorage.redirect_follower import RedirectFollower
from ovstorage.router import Router


TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".mdl",
    ".py",
    ".txt",
    ".usd",
    ".usda",
    ".yaml",
    ".yml",
}


def plugin_path(plugin_dir: str | None, kind: str) -> Path:
    root = plugin_dir or os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if root is None:
        # A wheel installed from PyPI carries the first-party plugins, so the
        # examples run with no configuration at all. An explicit --plugin-dir
        # or OVSTORAGE_PLUGIN_DIR still wins, which is how a checkout points
        # them at `target/release` or an archive's `plugins/`.
        try:
            root = str(ovstorage.bundled_plugins_dir())
        except FileNotFoundError:
            raise SystemExit(
                "this build of ovstorage bundles no plugins, so set "
                "OVSTORAGE_PLUGIN_DIR or pass --plugin-dir so the example can "
                f"load the {kind!r} plugin"
            ) from None
    directory = Path(root)
    candidates = [
        directory / f"libovstorage_plugin_{kind}.so",
        directory / f"libovstorage_plugin_{kind}.dylib",
        directory / f"ovstorage_plugin_{kind}.dll",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit(f"could not find {kind!r} plugin in {directory}")


def plugin_registry(
    plugin_dir: str | None, *kinds: str
) -> ovstorage.PluginRegistry:
    """Load the requested plugin libraries into one explicit registry."""
    paths: list[str] = []
    for kind in dict.fromkeys(kinds):
        paths.append(str(plugin_path(plugin_dir, kind)))
    return ovstorage.PluginRegistry(paths)


def file_connection_request(root: Path, display_name: str) -> ovstorage.ConnectionRequest:
    root.mkdir(parents=True, exist_ok=True)
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    request.set_display_name(display_name)
    return request


def http_connection_request(root_url: str, display_name: str) -> ovstorage.ConnectionRequest:
    request = ovstorage.ConnectionRequest("http")
    request.add_config("root_url", ovstorage.ConfigValue.string(root_url))
    request.set_display_name(display_name)
    return request


async def build_file_stack(root: Path, display_name: str) -> ovstorage.LayerBase:
    """Build the built-in file backend with its connection declared up front."""
    return await (
        ovstorage.Stack(root="files")
        .backend(FileBackend("files"))
        .connection("files", file_connection_request(root, display_name))
        .build()
    )


async def build_plugin_stack(
    plugin_dir: str | None,
    plugin_kind: str,
    backend_kind: str,
    request: ovstorage.ConnectionRequest,
    *,
    interactive_auth_capability: int | None = None,
) -> ovstorage.LayerBase:
    """Build one plugin-backed route and declare its connection before build.

    A redirect follower fronts the router: plugin backends such as the
    services client answer reads with a ``ReadResult::Redirect``, which the
    ``read_bytes`` bridge only resolves when a ``RedirectFollower`` is present
    in the graph.
    """
    return await (
        ovstorage.Stack(
            root="redirects", interactive_auth_capability=interactive_auth_capability
        )
        .with_registry(
            plugin_registry(plugin_dir, "core", "http", plugin_kind)
        )
        .wrapper(RedirectFollower("redirects", "routes"))
        .router(Router("routes", ["backend"]))
        .backend(PluginBackend(backend_kind, "backend"))
        .connection("backend", request)
        .build()
    )


def origin_prefix(address: str) -> str:
    parts = urlsplit(address)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"expected an absolute URL, got {address!r}")
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def display_name(prefix: str, address: str) -> str:
    if address.startswith(prefix):
        name = address[len(prefix) :]
    else:
        name = address.rstrip("/").rsplit("/", 1)[-1]
    return unquote(name.rstrip("/") or ".")


def format_size(size: int | None) -> str:
    if size is None:
        return "-"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def looks_text(address: str, data: bytes) -> bool:
    suffix = Path(urlsplit(address).path).suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return True
    if b"\0" in data:
        return False
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
