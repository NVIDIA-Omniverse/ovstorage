# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Executable checks for the progressive Python examples."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from io import BytesIO
from types import ModuleType, SimpleNamespace
from urllib.error import HTTPError

import pytest

from conftest import standard_registry

pytestmark = pytest.mark.asyncio


def _load_example(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> ModuleType:
    examples = pathlib.Path(__file__).resolve().parents[2] / "examples" / "python"
    monkeypatch.syspath_prepend(str(examples))
    path = examples / filename
    module_name = "ovstorage_example_" + path.stem
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("filename", "expected_output"),
    [
        ("01_file.py", "hello, ovstorage"),
        ("02_object_operations.py", "deleted"),
    ],
)
async def test_offline_progressive_examples_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    filename: str,
    expected_output: str,
) -> None:
    example = _load_example(monkeypatch, filename)
    await example.main()
    assert expected_output in capsys.readouterr().out


async def test_services_probe_rejects_legacy_empty_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = _load_example(monkeypatch, "services_config_probe.py")
    registry = object()

    class _EmptyStorage:
        async def list_connections(self) -> list[object]:
            return []

        async def list_address_roots(self) -> list[object]:
            return []

    class _Composer:
        def with_registry(self, configured: object) -> _Composer:
            assert configured is registry
            return self

        async def build(self) -> _EmptyStorage:
            return _EmptyStorage()

    class _Stack:
        @staticmethod
        def from_config(*, path: str) -> _Composer:
            assert path == "legacy.toml"
            return _Composer()

    monkeypatch.setattr(example, "ovstorage", SimpleNamespace(Stack=_Stack))
    monkeypatch.setattr(
        example,
        "plugin_registry",
        lambda plugin_dir, *kinds: registry,
    )
    args = SimpleNamespace(
        config="legacy.toml",
        plugin_dir=None,
        address=None,
        operation="stat",
        max_results=25,
        max_bytes=1024,
        preview_lines=12,
    )

    with pytest.raises(SystemExit) as exc_info:
        await example._run(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "declared no [ovstorage] stack" in captured.err
    assert "Legacy top-level\n[[connections]] entries are ignored" in captured.err


async def test_native_github_backend_and_logger_compose(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = _load_example(monkeypatch, "06_native_layers.py")
    fetches: list[str] = []

    def _fetch_json(path: str) -> object:
        fetches.append(path)
        if path == "":
            return [
                {
                    "type": "file",
                    "path": "docs/read me%#.txt",
                    "size": 5,
                    "sha": "abc123",
                },
                {
                    "type": "dir",
                    "path": "guide",
                    "size": 0,
                    "sha": "def456",
                },
            ]
        assert path == "docs/read me%#.txt"
        return {
            "type": "file",
            "path": path,
            "size": 5,
            "sha": "abc123",
            "download_url": "https://download.example/object",
        }

    monkeypatch.setattr(example, "_fetch_json", _fetch_json)
    requests: list[object] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int = -1) -> bytes:
            data = b"hello"
            return data if limit < 0 else data[:limit]

    def _urlopen(request: object, *, timeout: int) -> _Response:
        assert timeout == 30
        requests.append(request)
        return _Response()

    monkeypatch.setattr(example, "urlopen", _urlopen)

    github = example.GitHubRepository(
        name="github",
        layer_type="backend",
        roots=[example.ROOT],
    )
    logger = example.RequestLogger(
        name="log",
        layer_type="wrapper",
        inner="routes",
    )
    storage = await (
        example.ovstorage.Stack(root="log")
        .with_registry(standard_registry())
        .wrapper(logger)
        .router(example.Router("routes", ["github"]))
        .backend(github)
        .build()
    )

    page = await storage.list(example.ROOT)
    assert [(item.address, item.kind) for item in page.items] == [
        (example.ROOT + "docs/read%20me%25%23.txt", "file"),
        (example.ROOT + "guide/", "directory"),
    ]
    address = page.items[0].address
    data, _info = await storage.read(
        address,
        if_match="abc123",
        max_bytes=8,
    )
    assert data == b"hello"
    assert fetches == ["", "docs/read me%#.txt"]
    assert requests[0].get_header("Range") == "bytes=0-8"

    output = capsys.readouterr().out
    assert f"[native Python] list {example.ROOT}" in output
    assert f"[native Python] read {address}" in output
    assert example._redact_address(
        "https://user:secret@example.com/object?X-Amz-Signature=secret#part"
    ) == "https://example.com/object"


async def test_native_github_backend_enforces_bounds_and_maps_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = _load_example(monkeypatch, "06_native_layers.py")
    monkeypatch.setattr(
        example,
        "_fetch_json",
        lambda _path: {
            "path": "README.md",
            "sha": "abc123",
            "download_url": "https://download.example/object",
        },
    )

    backend = example.GitHubRepository(
        name="github",
        layer_type="backend",
        roots=[example.ROOT],
    )

    class _LargeResponse:
        def __enter__(self) -> _LargeResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int = -1) -> bytes:
            assert limit == 5
            return b"abcde"

    monkeypatch.setattr(
        example,
        "urlopen",
        lambda _request, *, timeout: _LargeResponse(),
    )
    with pytest.raises(example.ovstorage.ResourceExhaustedError):
        await backend.read(example.ROOT + "README.md", max_bytes=4)
    with pytest.raises(example.ovstorage.ObjectModifiedError):
        await backend.read(example.ROOT + "README.md", if_match="stale")

    missing = HTTPError(
        "https://api.github.test/missing",
        404,
        "missing",
        {},
        BytesIO(),
    )
    with pytest.raises(example.ovstorage.NotFoundError):
        example._raise_http_error(missing)
