#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the Python examples."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

import ovstorage


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
        raise SystemExit(
            "set OVSTORAGE_PLUGIN_DIR or pass --plugin-dir so the example can load "
            f"the {kind!r} plugin"
        )
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


async def load_plugin_kind(
    library: ovstorage.Library,
    plugin_dir: str | None,
    kind: str,
) -> None:
    # Examples load one known plugin explicitly. Applications that want every
    # available backend can use library.load_plugins_from_dir(...) instead.
    await library.load_plugin(str(plugin_path(plugin_dir, kind)))


async def add_file_connection(
    library: ovstorage.Library,
    root: Path,
    display_name: str,
) -> ovstorage.Connection:
    root.mkdir(parents=True, exist_ok=True)
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    request.set_display_name(display_name)
    return await library.add_connection(request)


async def add_http_connection(
    library: ovstorage.Library,
    root_url: str,
    display_name: str,
) -> ovstorage.Connection:
    request = ovstorage.ConnectionRequest("http")
    request.add_config("root_url", ovstorage.ConfigValue.string(root_url))
    request.set_display_name(display_name)
    return await library.add_connection(request)


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
