# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Connection declarations are resolved by the Stack composer."""

from __future__ import annotations

import pytest

import ovstorage
from conftest import make_test_connection_request

pytestmark = pytest.mark.asyncio


async def test_composed_connection_is_visible_to_stack_owner(stack_factory) -> None:
    stack = await stack_factory(request=make_test_connection_request("test://py-connection/"))
    connections = await stack.list_connections()
    assert len(connections) == 1
    connection = connections[0]
    assert connection.backend_kind == "test"
    assert connection.id
    assert "test://py-connection/" in connection.addresses
    assert connection.capabilities.supports_access_check is True
    assert connection.capabilities.supports_watch_directory is True


async def test_composed_connection_exposes_address_root_snapshot(stack_factory) -> None:
    stack = await stack_factory(request=make_test_connection_request("test://py-roots/"))
    roots = await stack.list_address_roots()
    assert any(root.address == "test://py-roots/" and root.backend_kind == "test" for root in roots)


async def test_connection_request_is_consumed_by_composer(stack_factory) -> None:
    request = make_test_connection_request("test://py-consumed/")
    stack = await stack_factory(request=request)
    assert (await stack.list_connections())[0].backend_kind == "test"
    with pytest.raises(ovstorage.Error, match="ConnectionRequest already consumed"):
        request.set_display_name("discarded")


async def test_config_value_classmethods() -> None:
    assert ovstorage.ConfigValue.string("foo").as_string == "foo"
    assert ovstorage.ConfigValue.int_(42).as_int == 42
    assert ovstorage.ConfigValue.bool_(True).as_bool is True
    assert "policy" in ovstorage.ConfigValue.toml("[[policy]]\nid = \"r1\"\n").as_toml
