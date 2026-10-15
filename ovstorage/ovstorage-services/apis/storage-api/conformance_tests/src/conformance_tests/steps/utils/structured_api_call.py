# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import json
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
)

import grpc
import pytest

from ..context_fixture import ListResultFixture
from .grpc_helpers import map_grpc_codes


def handle_grpc_response(grpc_call, status_code):
    if status_code == "OK":
        response = grpc_call()
        return response
    else:
        with pytest.raises(grpc.RpcError) as e_info:
            _ = grpc_call()
        exception_raised = e_info.value
        expected_code = map_grpc_codes(status_code)
        if exception_raised.code() != expected_code and exception_raised.code() == grpc.StatusCode.UNIMPLEMENTED:
            # We got an unexpected UNIMPLEMENTED, raise so the caller can handle it
            raise exception_raised
        assert exception_raised.code() == expected_code, f"Expected {map_grpc_codes(status_code)} but got {exception_raised.code()}"


def handle_rest_response(rest_call, status_code):
    response = rest_call()
    if response.status_code == 501 and int(status_code) != 501:
        # Call returned an unexpected 501 unimplemented error, raise this to let the caller handle it
        raise NotImplementedError(f"Got unexpected return code 501: unimplemented")
    assert response.status_code == int(status_code), f"Expected {status_code} but got {response.status_code}"
    return response


def structured_api_call(protocol, status_code=None, *, grpc_call, rest_call) -> Any:
    if protocol == "GRPC":
        if status_code is None:
            status_code = "OK"
        return handle_grpc_response(grpc_call, status_code)
    elif protocol == "REST":
        if status_code is None:
            status_code = "200"
        return handle_rest_response(rest_call, status_code)
    else:
        raise Exception(f"unknown protocol: {protocol}")


def structured_api_stream(
    protocol: str,
    status_code: Optional[str] = None,
    *,
    grpc_stream_call: Optional[Callable[[], Iterator]] = None,
    rest_call_factory: Optional[Callable[[Optional[Dict]], Any]] = None,
    fetch_first_page_only: bool = False,
    max_items: Optional[int] = None,
    # Result aggregation callback
    grpc_result_aggregator: Optional[Callable[[Any, ListResultFixture], bool]] = None,
    rest_result_aggregator: Optional[Callable[[Any, ListResultFixture], bool]] = None,
    # REST pagination config
    is_json_paginated=True,
    items_key: str = "items",
    continuation_key: str = "next_continuation_handle",
    continuation_param: str = "continuation_handle",
) -> ListResultFixture | None:
    """
    Handle streaming/paginated API calls with custom result aggregation

    Args:
        protocol: "GRPC" or "REST"
        status_code: Expected status code
        grpc_stream_call: Function returning gRPC stream iterator
        rest_call_factory: Function taking optional params dict for REST pagination
        fetch_first_page_only: Stop after first page/response
        max_items: Maximum items to collect
        grpc_result_aggregator: Callback(response, results_list) -> should_continue
                          Called for each response to aggregate results if protocol is GRPC.
                          Return False to stop iteration early.
        rest_result_aggregator: Callback(response, results_list) -> should_continue
                          Called for each response to aggregate results if protocol is REST.
                          Return False to stop iteration early.
        is_json_paginated: Toggles the use of continuation_key to determine if it needs to loop through result pages
        items_key: JSON key containing items array (REST only)
        continuation_key: JSON key for next page token (REST only)
        continuation_param: Parameter name for continuation token (REST only)

    Returns:
        ListResultFixture containing collected items (aggregated by result_aggregator if provided), or None
    """

    def default_grpc_aggregator(response, context_results):
        """Default aggregator for gRPC - assumes response.items"""
        if context_results.value is None:
            context_results.value = []
        if hasattr(response, "items"):
            context_results.value.extend(response.items)
        else:
            context_results.value.append(response)
        context_results.counter = len(context_results.value)
        return True  # Continue processing

    def default_rest_aggregator(response_data, context_results: ListResultFixture):
        """Default aggregator for REST - produces a list result in a ListResultFixture, extracts items_key"""
        if context_results.value is None:
            context_results.value = []
        if items_key in response_data:
            context_results.value.extend(response_data[items_key])
            context_results.counter = len(context_results.value)
        return True  # Continue processing

    if protocol == "GRPC":
        if status_code is None:
            status_code = "OK"

        if grpc_stream_call is None:
            raise ValueError("grpc_stream_call must be provided for GRPC protocol")

        if status_code == "OK":
            grpc_results = ListResultFixture(name="streaming_result")
            aggregator = grpc_result_aggregator or default_grpc_aggregator

            try:
                for response in grpc_stream_call():
                    should_continue = aggregator(response, grpc_results)

                    if fetch_first_page_only or not should_continue:
                        break
                    if max_items and grpc_results.counter >= max_items:
                        break

                return grpc_results
            except grpc.RpcError:
                raise
        else:
            # Expect an error
            with pytest.raises(grpc.RpcError) as e_info:
                list(grpc_stream_call())
            exception_raised = e_info.value
            assert exception_raised.code() == map_grpc_codes(
                status_code
            ), f"Expected {map_grpc_codes(status_code)} but got {exception_raised.code()}"
            return None

    elif protocol == "REST":
        if status_code is None:
            status_code = "200"

        if rest_call_factory is None:
            raise ValueError("rest_call_factory must be provided for REST protocol")

        # Make initial call
        response = rest_call_factory(None)
        if response.status_code != int(status_code):
            pytest.fail(f"Expected {status_code} but got {response.status_code}")

        rest_results = ListResultFixture(name="streaming_result")
        aggregator = rest_result_aggregator or default_rest_aggregator

        # Process initial response
        data = None
        if is_json_paginated:
            if response.content:
                data = json.loads(response.content)
                should_continue = aggregator(data, rest_results)
            else:
                should_continue = False
        else:
            # Use raw response (e.g. read call)
            should_continue = aggregator(response, rest_results)

        if fetch_first_page_only or not should_continue:
            return rest_results

        # Handle pagination
        if is_json_paginated and should_continue:
            if not data:
                raise RuntimeError("Logic error in pagination - should_continue should be false when no data is available")
            next_continuation = data.get(continuation_key)
            while next_continuation is not None and (max_items is None or rest_results.counter < max_items):

                # Prepare params for next page
                params = {continuation_param: next_continuation}

                # Make next page call
                response = rest_call_factory(params)
                if response.status_code != 200:
                    pytest.fail(f"Pagination call failed with status {response.status_code}")

                data = json.loads(response.content)
                should_continue = aggregator(data, rest_results)
                next_continuation = data.get(continuation_key)

                # Stop if aggregator says to stop, or we've reached max_items
                if not should_continue or (max_items and rest_results.counter >= max_items):
                    break

        return rest_results

    else:
        raise Exception(f"unknown protocol: {protocol}")
