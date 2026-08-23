# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Native interactive-auth flows exposed through the Python binding."""

from __future__ import annotations

import asyncio
import gc

import pytest

import conftest
import ovstorage
from conftest import make_test_connection_request


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        conftest._TEST_PLUGIN is None or not conftest._TEST_PLUGIN.is_file(),
        reason="libovstorage_plugin_test_abi.so not built; run make build-test-plugins",
    ),
]


async def _build_auth_stack(stack_factory, flow: str):
    root = f"test://py-auth-{flow}/"
    stack = await stack_factory(
        request=make_test_connection_request(root, test_auth_flow=flow)
    )
    connection_id = (await stack.list_connections())[0].id
    return stack, connection_id


async def _drain(stream) -> list[ovstorage.AuthEvent]:
    return [event async for event in stream]


@pytest.mark.parametrize(
    ("flow", "expected_kinds"),
    [
        ("progress-then-succeed", ["Progress", "Succeeded"]),
        ("device-code-then-succeed", ["DeviceCode", "Succeeded"]),
        ("open-browser-then-succeed", ["OpenBrowser", "Succeeded"]),
        ("cancel", ["Cancelled"]),
        ("fail", ["Failed"]),
    ],
)
async def test_scripted_auth_flows(stack_factory, flow, expected_kinds) -> None:
    stack, connection_id = await _build_auth_stack(stack_factory, flow)

    stream = await stack.authenticate_connection("test", connection_id)
    events = await _drain(stream)

    assert [event.kind for event in events] == expected_kinds

    if flow == "progress-then-succeed":
        assert events[0].message
    elif flow == "device-code-then-succeed":
        device_code = events[0]
        assert device_code.user_code == "TEST-CODE"
        assert device_code.verification_url.startswith("https://")
        assert device_code.expires_at_unix_nanos > 0
        assert device_code.interval_seconds == 5.0
    elif flow == "open-browser-then-succeed":
        open_browser = events[0]
        assert open_browser.url
        assert open_browser.url.startswith("https://")
        assert open_browser.expires_at_unix_nanos > 0
    elif flow == "fail":
        failed = events[0]
        assert failed.error_code
        assert failed.message

    succeeded = next((event for event in events if event.kind == "Succeeded"), None)
    if succeeded is not None:
        assert isinstance(succeeded.connection, ovstorage.Connection)
        assert succeeded.oauth_access_token is None


async def test_authenticate_connection_rejects_unknown_connection(stack_factory) -> None:
    stack, _connection_id = await _build_auth_stack(stack_factory, "cancel")

    with pytest.raises(ovstorage.NotFoundError):
        await stack.authenticate_connection("test", "unknown-connection-id")


@pytest.mark.parametrize("invalid_capability", [99, 2**40, -(2**40), "HEADLESS"])
async def test_authenticate_connection_rejects_invalid_capability(
    stack_factory, invalid_capability
) -> None:
    stack, connection_id = await _build_auth_stack(stack_factory, "cancel")

    with pytest.raises(ovstorage.InvalidArgumentError):
        await stack.authenticate_connection(
            "test", connection_id, capability=invalid_capability
        )


async def test_authenticate_connection_accepts_headless_capability(stack_factory) -> None:
    stack, connection_id = await _build_auth_stack(stack_factory, "cancel")

    stream = await stack.authenticate_connection(
        "test",
        connection_id,
        capability=ovstorage.InteractiveAuthCapability.HEADLESS,
    )
    assert [event.kind for event in await _drain(stream)] == ["Cancelled"]


async def test_auth_stream_aclose_exhausts_stream(stack_factory) -> None:
    stack, connection_id = await _build_auth_stack(
        stack_factory, "device-code-then-succeed"
    )
    stream = await stack.authenticate_connection("test", connection_id)

    await stream.aclose()

    with pytest.raises(StopAsyncIteration):
        await stream.__anext__()


async def test_dropped_auth_stream_does_not_wedge_next_flow(stack_factory) -> None:
    stack, connection_id = await _build_auth_stack(
        stack_factory, "progress-then-succeed"
    )
    abandoned = await stack.authenticate_connection("test", connection_id)

    del abandoned
    gc.collect()
    await asyncio.sleep(0)

    stream = await asyncio.wait_for(
        stack.authenticate_connection("test", connection_id), timeout=5.0
    )
    events = await asyncio.wait_for(_drain(stream), timeout=5.0)
    assert [event.kind for event in events] == ["Progress", "Succeeded"]
