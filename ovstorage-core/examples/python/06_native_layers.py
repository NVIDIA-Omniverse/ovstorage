#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Mix plugin Layers with native Python logging and GitHub browsing Layers."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import NoReturn
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import ovstorage
from ovstorage.router import Router

from _common import plugin_registry

# The custom scheme is the public address space exposed by this backend. Storage
# URL parsing canonicalizes authorities to lowercase, so ROOT uses that form.
ROOT = "github://nvidia-omniverse/ovstorage/"
# API_ROOT is an implementation detail: callers see github:// addresses while
# the Layer translates operations to GitHub's HTTPS API.
API_ROOT = "https://api.github.com/repos/NVIDIA-Omniverse/ovstorage/contents/"


def _raise_http_error(error: HTTPError) -> NoReturn:
    """Translate transport-specific failures into ovstorage's error contract."""
    error.close()
    if error.code == 404:
        raise ovstorage.NotFoundError("GitHub path was not found") from error
    if error.code in {403, 429}:
        raise ovstorage.ResourceExhaustedError(
            "GitHub API rate limit was exhausted"
        ) from error
    if 500 <= error.code < 600:
        raise ovstorage.TransientError(
            f"GitHub returned HTTP {error.code}"
        ) from error
    raise ovstorage.InternalError(f"GitHub returned HTTP {error.code}") from error


def _fetch_json(path: str) -> object:
    """Perform the blocking GitHub request used by the async Layer below."""
    request = Request(
        API_ROOT + quote(path, safe="/"),
        headers={"Accept": "application/vnd.github+json"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        _raise_http_error(error)


def _redact_address(address: str) -> str:
    """Remove userinfo, query, and fragment before an address reaches a log."""
    parts = urlsplit(address)
    authority = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, authority, parts.path, "", ""))


def _info(item: dict[str, object]) -> SimpleNamespace:
    """Adapt one GitHub entry to the attributes expected from list items."""
    kind = "directory" if item["type"] == "dir" else "file"
    path = quote(str(item["path"]), safe="/")
    return SimpleNamespace(
        address=ROOT + path + ("/" if kind == "directory" else ""),
        kind=kind,
        size=item.get("size"),
        mtime_unix_nanos=None,
        etag=item.get("sha"),
        version=item.get("sha"),
        system_metadata={},
        user_metadata={},
    )


class GitHubRepository(ovstorage.LayerBase):
    """A small native Python backend for one read-only GitHub repository.

    LayerBase supplies default Unsupported behavior for operations this class
    does not implement, such as write and delete. A production backend can add
    those methods without changing callers or the surrounding graph.
    """

    async def list(
        self,
        prefix: str,
        recursive: bool = False,
        max_results: int | None = None,
        page_token: str | None = None,
        full_metadata: bool = False,
    ) -> SimpleNamespace:
        # Be explicit about this tutorial's capability boundary. Silently
        # ignoring an option would give callers a result with the wrong meaning.
        if recursive or full_metadata:
            raise ovstorage.UnsupportedError(
                "this tutorial backend supports only shallow, basic listings"
            )
        # Tokens are opaque to callers. This backend encodes a simple offset,
        # validates it here, and returns the next offset with the result page.
        try:
            offset = int(page_token) if page_token is not None else 0
        except ValueError:
            raise ovstorage.InvalidArgumentError(
                "GitHub page token is not valid"
            ) from None
        if offset < 0:
            raise ovstorage.InvalidArgumentError(
                "GitHub page token is not valid"
            )
        if max_results is not None and max_results <= 0:
            raise ovstorage.InvalidArgumentError(
                "max_results must be greater than zero"
            )
        # Translate the storage prefix to a repository-relative API path. urllib
        # is blocking, so to_thread keeps it off the asyncio event-loop thread.
        path = unquote(prefix.removeprefix(ROOT).rstrip("/"))
        payload = await asyncio.to_thread(_fetch_json, path)
        if not isinstance(payload, list):
            raise ovstorage.InvalidArgumentError("GitHub path is not a directory")
        end = len(payload) if max_results is None else offset + max_results
        next_page_token = str(end) if end < len(payload) else None
        return SimpleNamespace(
            items=[_info(item) for item in payload[offset:end]],
            next_page_token=next_page_token,
        )

    async def read(
        self,
        address: str,
        if_match: str | None = None,
        range_start: int | None = None,
        range_end_inclusive: int | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        # GitHub's contents endpoint supplies metadata and a download URL. The
        # storage address remains stable even though that transport URL may be
        # temporary or point at another host.
        path = unquote(address.removeprefix(ROOT))
        payload = await asyncio.to_thread(_fetch_json, path)
        if not isinstance(payload, dict) or not isinstance(payload.get("download_url"), str):
            raise ovstorage.InvalidArgumentError("GitHub path is not a file")
        # The Git blob SHA is this backend's object validator, so it implements
        # ovstorage's conditional-read contract for if_match. The read path
        # reports ObjectModified, not PreconditionFailed: a backend may only
        # detect the mismatch once bytes are moving, so the read side keeps one
        # code for both. Write-side preconditions are PreconditionFailed.
        if if_match is not None and payload.get("sha") != if_match:
            raise ovstorage.ObjectModifiedError(
                "GitHub object does not match if_match"
            )

        # Normalize the three bounding controls into one HTTP byte range.
        # HTTP's end is inclusive; requesting one extra byte for max_bytes lets
        # the client detect and reject a response that exceeds the caller's cap.
        start = 0 if range_start is None else range_start
        end = range_end_inclusive
        if end is not None and end < start:
            raise ovstorage.InvalidArgumentError(
                "range_end_inclusive must be greater than or equal to range_start"
            )
        if max_bytes is not None:
            bounded_end = start + max_bytes
            end = bounded_end if end is None else min(end, bounded_end)

        headers: dict[str, str] = {}
        if range_start is not None or range_end_inclusive is not None or max_bytes is not None:
            headers["Range"] = f"bytes={start}-{'' if end is None else end}"
        request = Request(payload["download_url"], headers=headers)

        def _download() -> bytes:
            try:
                with urlopen(request, timeout=30) as response:
                    data = response.read() if max_bytes is None else response.read(max_bytes + 1)
            except HTTPError as error:
                _raise_http_error(error)
            if max_bytes is not None and len(data) > max_bytes:
                raise ovstorage.ResourceExhaustedError(
                    f"GitHub read exceeds max_bytes={max_bytes}"
                )
            return data

        return await asyncio.to_thread(_download)


class RequestLogger(ovstorage.LayerBase):
    """A wrapper that observes selected operations and delegates downstream."""

    async def read(self, address: str, **kwargs: object) -> object:
        print(f"[native Python] read {_redact_address(address)}")
        # For a wrapper, LayerBase forwards super() calls to the configured
        # inner Layer. Returning its result preserves normal read semantics.
        return await super().read(address, **kwargs)

    async def list(self, prefix: str, **kwargs: object) -> object:
        print(f"[native Python] list {_redact_address(prefix)}")
        return await super().list(prefix, **kwargs)


async def main() -> None:
    # A native backend declares the roots it owns so Router can select it. A
    # native wrapper instead names the inner Layer to which it delegates.
    github = GitHubRepository(
        name="github",
        layer_type="backend",
        roots=[ROOT],
    )
    logger = RequestLogger(
        name="log",
        layer_type="wrapper",
        inner="routes",
    )
    # Native and plugin-provided Layers participate in the same graph:
    #
    #     log (native Python wrapper)
    #       └── routes (core-plugin router)
    #           └── github (native Python backend)
    storage = await (
        ovstorage.Stack(root="log")
        .with_registry(plugin_registry(None, "core"))
        .wrapper(logger)
        .router(Router("routes", ["github"]))
        .backend(github)
        .build()
    )

    # Both calls enter through `log`, so the wrapper prints each operation
    # before Router dispatches it to the native backend.
    page = await storage.list(ROOT)
    print("repository root:")
    for item in page.items[:8]:
        print(f"  {item.kind:9} {item.address}")
    readme, _info_result = await storage.read(ROOT + "README.md", max_bytes=128 * 1024)
    print("\nREADME preview:")
    print("\n".join(readme.decode().splitlines()[:6]))


if __name__ == "__main__":
    asyncio.run(main())
