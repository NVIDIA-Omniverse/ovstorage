#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run a small local web browser for a file:// ovstorage route.

This example uses only the Python standard library plus `ovstorage`. It starts
an HTTP server for the UI, but all storage operations behind that UI go through
the ovstorage Python binding and the `file` plugin.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import ovstorage

from _common import (
    add_file_connection,
    display_name,
    format_size,
    load_plugin_kind,
    looks_text,
)


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ovstorage file browser</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #171a1f;
      --muted: #5a6472;
      --line: #d8dde6;
      --accent: #1b6f5f;
      --accent-soft: #e4f3ef;
      --code: #11151c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      padding: 16px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1 {
      margin: 0 0 6px;
      font-size: 20px;
      font-weight: 650;
    }
    .root {
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    main {
      display: grid;
      grid-template-columns: minmax(360px, 48%) minmax(360px, 1fr);
      gap: 16px;
      padding: 16px 24px 24px;
    }
    section {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      overflow: hidden;
    }
    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      min-height: 48px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }
    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 6px 10px;
      font: inherit;
      cursor: pointer;
    }
    button:hover { border-color: var(--accent); color: var(--accent); }
    .path {
      flex: 1;
      min-width: 0;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: middle;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }
    tr {
      cursor: pointer;
    }
    tr:hover td {
      background: var(--accent-soft);
    }
    td.size {
      width: 110px;
      color: var(--muted);
      text-align: right;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    td.kind {
      width: 110px;
      color: var(--muted);
    }
    .empty, .error {
      padding: 18px;
      color: var(--muted);
    }
    .error {
      color: #9b1c1c;
    }
    .details {
      padding: 14px;
    }
    .details h2 {
      margin: 0 0 8px;
      font-size: 16px;
    }
    .metadata {
      display: grid;
      grid-template-columns: 90px minmax(0, 1fr);
      gap: 6px 12px;
      margin: 0 0 14px;
      color: var(--muted);
    }
    .metadata dd, .metadata dt {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .metadata dd {
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    pre {
      margin: 0;
      padding: 12px;
      min-height: 260px;
      max-height: calc(100vh - 260px);
      overflow: auto;
      border-radius: 6px;
      background: var(--code);
      color: #f2f4f8;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space: pre-wrap;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; padding: 12px; }
      header { padding: 14px 12px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>ovstorage file browser</h1>
    <div class="root" id="root"></div>
  </header>
  <main>
    <section>
      <div class="toolbar">
        <button id="refresh" type="button">Refresh</button>
        <div class="path" id="path"></div>
      </div>
      <div id="listing"></div>
    </section>
    <section>
      <div class="toolbar">
        <div class="path" id="selected">Select an object</div>
      </div>
      <div class="details" id="details">
        <div class="empty">Click a file to preview it through ovstorage.</div>
      </div>
    </section>
  </main>
  <script>
    const state = { root: null, prefix: null, items: [] };

    async function api(path) {
      const response = await fetch(path);
      const data = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || response.statusText);
      }
      return data;
    }

    function escapeText(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }

    function shortName(item) {
      return item.name || item.address;
    }

    function isDirectory(item) {
      return item.kind === "directory" ||
        item.kind === "directory_marker" ||
        item.kind === "directory_inferred";
    }

    async function loadList(prefix) {
      state.prefix = prefix;
      document.getElementById("path").textContent = prefix;
      document.getElementById("listing").innerHTML = '<div class="empty">Loading...</div>';
      try {
        const data = await api(`/api/list?prefix=${encodeURIComponent(prefix)}`);
        state.items = data.items;
        renderList(data.items);
      } catch (error) {
        document.getElementById("listing").innerHTML =
          `<div class="error">${escapeText(error.message)}</div>`;
      }
    }

    function renderList(items) {
      if (!items.length) {
        document.getElementById("listing").innerHTML = '<div class="empty">No objects.</div>';
        return;
      }
      const rows = items.map((item, index) => `
        <tr data-index="${index}">
          <td>${isDirectory(item) ? "folder" : "file"} ${escapeText(shortName(item))}</td>
          <td class="kind">${escapeText(item.kind)}</td>
          <td class="size">${escapeText(item.size_display)}</td>
        </tr>
      `).join("");
      document.getElementById("listing").innerHTML = `
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Size</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
      document.querySelectorAll("tr[data-index]").forEach((row) => {
        row.addEventListener("click", () => {
          const item = state.items[Number(row.dataset.index)];
          if (isDirectory(item)) {
            loadList(item.address.endsWith("/") ? item.address : item.address + "/");
          } else {
            loadPreview(item);
          }
        });
      });
    }

    async function loadPreview(item) {
      document.getElementById("selected").textContent = item.address;
      document.getElementById("details").innerHTML = '<div class="empty">Loading preview...</div>';
      try {
        const data = await api(`/api/preview?address=${encodeURIComponent(item.address)}`);
        document.getElementById("details").innerHTML = `
          <h2>${escapeText(shortName(item))}</h2>
          <dl class="metadata">
            <dt>Address</dt><dd>${escapeText(data.info.address)}</dd>
            <dt>Kind</dt><dd>${escapeText(data.info.kind)}</dd>
            <dt>Size</dt><dd>${escapeText(data.info.size_display)}</dd>
            <dt>ETag</dt><dd>${escapeText(data.info.etag || "-")}</dd>
          </dl>
          <pre>${escapeText(data.preview)}</pre>
        `;
      } catch (error) {
        document.getElementById("details").innerHTML =
          `<div class="error">${escapeText(error.message)}</div>`;
      }
    }

    async function init() {
      const data = await api("/api/root");
      state.root = data.root;
      document.getElementById("root").textContent = data.root;
      document.getElementById("refresh").addEventListener("click", () => loadList(state.prefix));
      loadList(data.root);
    }

    init().catch((error) => {
      document.getElementById("listing").innerHTML =
        `<div class="error">${escapeText(error.message)}</div>`;
    });
  </script>
</body>
</html>
"""


class StorageApp:
    def __init__(self, plugin_dir: str | None, root: Path) -> None:
        self._plugin_dir = plugin_dir
        self._root = root
        self.library: ovstorage.Library | None = None
        self.connection: ovstorage.Connection | None = None
        self.root_address = root.as_uri() + "/"
        asyncio.run(self._setup())

    def run(self, coro: Any) -> Any:
        return asyncio.run(coro)

    async def _setup(self) -> None:
        library = ovstorage.Library.open()
        await load_plugin_kind(library, self._plugin_dir, "file")
        connection = await add_file_connection(library, self._root, "file-browser-web-local")
        self.library = library
        self.connection = connection

    async def close_async(self) -> None:
        if self.library is not None and self.connection is not None:
            await self.library.remove_connection(self.connection.id)

    def close(self) -> None:
        self.run(self.close_async())

    async def list(self, prefix: str) -> dict[str, Any]:
        if self.library is None:
            raise RuntimeError("storage not initialized")
        page = await self.library.list(prefix, max_results=200)
        items = []
        for item in page.items:
            address = getattr(item, "address")
            size = getattr(item, "size", None)
            items.append(
                {
                    "address": address,
                    "name": display_name(prefix, address),
                    "kind": getattr(item, "kind"),
                    "size": size,
                    "size_display": format_size(size),
                    "etag": getattr(item, "etag"),
                }
            )
        return {
            "prefix": prefix,
            "items": items,
            "next_page_token": page.next_page_token,
        }

    async def preview(self, address: str, max_bytes: int) -> dict[str, Any]:
        if self.library is None:
            raise RuntimeError("storage not initialized")
        data, info = await self.library.read_bytes(address, max_bytes=max_bytes)
        if looks_text(address, data):
            preview = data.decode("utf-8", errors="replace")
        else:
            preview = data[:256].hex(" ")
        return {
            "info": {
                "address": info.address,
                "kind": info.kind,
                "size": info.size,
                "size_display": format_size(info.size),
                "etag": info.etag,
            },
            "preview": preview,
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-dir",
        help="Plugin directory to load. Defaults to OVSTORAGE_PLUGIN_DIR.",
    )
    parser.add_argument(
        "--local-root",
        type=Path,
        help="Local directory to browse. Defaults to a temporary demo tree.",
    )
    parser.add_argument(
        "--seed-demo-data",
        action="store_true",
        help="Write a few small demo files before serving.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--open", action="store_true", help="Open the browser.")
    parser.add_argument("--preview-bytes", type=int, default=1024 * 1024)
    return parser.parse_args()


def _seed(root: Path) -> None:
    files = {
        "README.txt": "ovstorage web file browser demo\n",
        "metadata.json": '{\n  "source": "ovstorage demo",\n  "version": 1\n}\n',
        "scenes/world.usda": (
            "#usda 1.0\n"
            "(\n"
            "    defaultPrim = \"World\"\n"
            ")\n\n"
            "def Xform \"World\"\n"
            "{\n"
            "}\n"
        ),
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class BrowserHandler(BaseHTTPRequestHandler):
    storage: StorageApp
    preview_bytes: int

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_html(self) -> None:
        encoded = HTML_PAGE.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error_json(self, exc: BaseException) -> None:
        self._send_json({"error": f"{exc.__class__.__name__}: {exc}"}, HTTPStatus.BAD_REQUEST)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self._send_html()
            elif parsed.path == "/api/root":
                self._send_json({"root": self.storage.root_address})
            elif parsed.path == "/api/list":
                prefix = parse_qs(parsed.query).get("prefix", [self.storage.root_address])[0]
                self._send_json(self.storage.run(self.storage.list(prefix)))
            elif parsed.path == "/api/preview":
                values = parse_qs(parsed.query).get("address")
                if not values:
                    raise ValueError("missing address")
                self._send_json(
                    self.storage.run(self.storage.preview(values[0], self.preview_bytes))
                )
            else:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, ovstorage.Error, RuntimeError) as exc:
            self._send_error_json(exc)


def _serve(args: argparse.Namespace, root: Path) -> None:
    storage = StorageApp(args.plugin_dir, root)
    BrowserHandler.storage = storage
    BrowserHandler.preview_bytes = args.preview_bytes
    server = HTTPServer((args.host, args.port), BrowserHandler)
    url = f"http://{args.host}:{server.server_port}/"
    print(f"serving ovstorage file browser at {url}", flush=True)
    print(f"root: {storage.root_address}", flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
        storage.close()


def _main() -> None:
    args = _parse_args()
    if args.local_root is not None:
        root = args.local_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        if args.seed_demo_data:
            _seed(root)
        _serve(args, root)
        return

    with tempfile.TemporaryDirectory(prefix="ovstorage-web-browser-") as tmp:
        root = Path(tmp).resolve()
        _seed(root)
        _serve(args, root)


if __name__ == "__main__":
    _main()
