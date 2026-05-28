# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from contextlib import contextmanager
from queue import Queue
from typing import (
    Any,
    Dict,
    Generator,
    Iterable,
    Iterator,
    Optional,
)
from unittest.mock import ANY
from urllib.parse import urlsplit

import grpc
import pytest
import requests
from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..common_fixtures import identity_from_fixture
from ..common_memory_steps import get_resource_address
from ..context_fixture import ContextFixture
from ..utils.rest_client import RestClient
from ..utils.structured_api_call import structured_api_call
from ..utils.upload_helpers import (
    perform_http_upload,
    split_into_chunks,
    upload_part_to_http_server,
)

_UPLOAD_OPTIONS_CACHE: Dict[tuple[str, str], list[dict[str, Any]]] = {}
_TOP_LEVEL_ADDRESSES_CACHE: Dict[str, list[str]] = {}


@pytest.fixture
def upload_headers() -> Generator[ContextFixture, None, None]:
    # This records the headers delivered by the last http upload operation
    yield ContextFixture("upload_headers")


@then(parsers.parse("calling '{protocol}' write on memorized '{memory_name}' with data returns '{return_code}'"))
@then(parsers.parse("calling '{protocol}' write on that address returns '{return_code}'"))
@when(parsers.parse("performing '{protocol}' write against that address with data succeeds"))
@when(parsers.parse("calling '{protocol}' write on that address with data returns a created response"))
@then(
    parsers.parse(
        "calling '{protocol}' write on that address with '{upload_preference}' upload preference using the memorized previous version '{memory}' returns '{return_code}'"
    )
)
@when(parsers.parse("calling '{protocol}' write on that address with '{upload_preference}' upload preference returns '{return_code}'"))
def step_write(
    protocol,
    scenario_state,
    blob,
    sapi_test_server_launch,
    return_code=None,
    memory_name=None,
    memory=None,
    upload_preference=None,
):
    last_stated_version = None
    if memory:
        last_stated_version = identity_from_fixture(scenario_state.memorized_responses[memory])
    if return_code is None:
        return_code = "OK" if protocol == "GRPC" else "201"
    response = _call_write(
        protocol=protocol,
        resource_address=get_resource_address(scenario_state, memory_name),
        blob=blob,
        scenario_state=scenario_state,
        return_value=return_code,
        upload_preference=upload_preference,
        previous_version=last_stated_version,
        continue_upload=True,
    )
    if return_code == 201 and (upload_preference is None or upload_preference == "body"):
        response_json = response.json()
        assert response_json["resource_identity"]
        assert response_json["metadata"]["data_object_size"] == len(blob)
    if protocol == "GRPC" and return_code == "OK" and (upload_preference is None or upload_preference == "body"):
        assert response.HasField("resource_info")
        assert response.resource_info.HasField("resource_identity")
        assert response.resource_info.HasField("metadata")
        assert response.resource_info.metadata.data_object_size == len(blob)
    scenario_state.last_response = response


@when(
    parsers.parse(
        "calling '{protocol}' write on that address with '{upload_preference}' upload preference using the memorized previous version '{memory}' returns '{return_code}'"
    )
)
@when(
    parsers.parse(
        "calling '{protocol}' write on that address with '{upload_preference}' upload preference the first roundtrip returns '{return_code}'"
    )
)
def step_write_only_first_roundtrip(
    protocol,
    scenario_state,
    blob,
    sapi_test_server_launch,
    return_code=None,
    memory_name=None,
    memory=None,
    upload_preference=None,
):
    last_stated_version = None
    if memory:
        last_stated_version = identity_from_fixture(scenario_state.memorized_responses[memory])
    if return_code is None:
        return_code = "OK" if protocol == "GRPC" else "201"
    response = _call_write(
        protocol=protocol,
        resource_address=get_resource_address(scenario_state, memory_name),
        blob=blob,
        scenario_state=scenario_state,
        return_value=return_code,
        upload_preference=upload_preference,
        previous_version=last_stated_version,
        continue_upload=False,
    )
    if return_code == 201 and (upload_preference is None or upload_preference == "body"):
        response_json = response.json()
        assert response_json["resource_identity"]
        assert response_json["metadata"]["data_object_size"] == len(blob)
    if protocol == "GRPC" and return_code == "OK" and (upload_preference is None or upload_preference == "body"):
        assert response.HasField("resource_info")
        assert response.resource_info.HasField("resource_identity")
        assert response.resource_info.HasField("metadata")
        assert response.resource_info.metadata.data_object_size == len(blob)
    scenario_state.last_response = response


@then(parsers.parse("aborting a multipart upload via '{protocol}' with that id returns '{return_value}'"))
def aborting_a_multipart_upload_with_that_id_returns(protocol, return_value, scenario_state, sapi_test_server_launch):
    def grpc_call():
        upload_id = scenario_state.last_response.multipart_upload.upload_id
        return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).AbortMultipartUpload(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).AbortMultipartUploadRequest(
                upload_id=upload_id, destination_resource_address=scenario_state.resource_address
            )
        )

    def rest_call():
        upload_id = scenario_state.last_response.json()["multipart"]["upload_id"]
        return scenario_state.sapi_test_client.rest_client().abort_multipart_upload(
            scenario_state.resource_address, upload_id, scenario_state.version_under_test["fileobject"]
        )

    scenario_state.last_response = structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)


@when(parsers.parse("calling '{protocol}' write on that address returns a redirect response"))
def calling_write_on_that_address_returns_redirect_response(protocol, blob, scenario_state, sapi_test_server_launch):
    return_value = "300" if protocol == "REST" else "OK"
    response = _call_write(protocol, return_value, scenario_state.resource_address, scenario_state, blob, continue_upload=False)
    if protocol == "REST":
        assert response.json() == {"redirect": ANY}
    elif protocol == "GRPC":
        assert response is not None and response.write_redirect

    scenario_state.last_response = response


@when(parsers.parse("calling '{protocol}' complete redirect upload returns '{return_value}'"))
def calling_complete_redirect_upload(protocol, return_value, scenario_state, sapi_test_server_launch, upload_headers):
    def grpc_call():
        return scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).CompleteRedirectUpload(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).CompleteRedirectUploadRequest(
                destination_resource_address=scenario_state.resource_address,
                additional_headers=[
                    scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"]).Header(
                        name=name, value=value
                    )
                    for name, value in (upload_headers.value or [])
                ],
            )
        )

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().complete_redirect_upload(
            address=scenario_state.resource_address,
            additional_headers=upload_headers.value if upload_headers.value is not None else [],
            write_version=scenario_state.version_under_test["fileobject"],
        )

    # Skip the test if the service reports UNIMPLEMENTED/501
    try:
        scenario_state.last_response = structured_api_call(protocol, status_code=return_value, grpc_call=grpc_call, rest_call=rest_call)
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.UNIMPLEMENTED:
            pytest.skip("CompleteRedirectUpload returned UNIMPLEMENTED, skipping test")
        else:
            raise e
    except NotImplementedError as e:
        pytest.skip(f"redirect/complete returned UNIMPLEMENTED, skipping test")


@when(parsers.parse("calling '{protocol}' write on that address returns a multipart upload handle"))
def calling_write_on_that_address_returns_multipart_upload_response(protocol, blob, scenario_state, sapi_test_server_launch):
    response = _call_write(
        protocol, "300" if protocol == "REST" else "OK", scenario_state.resource_address, scenario_state, blob, continue_upload=False
    )
    if protocol == "REST":
        assert response.json() == {"multipart": ANY}
    elif protocol == "GRPC":
        assert response is not None and response.HasField("multipart_upload")
    scenario_state.last_response = response


def _call_write(
    protocol,
    return_value,
    resource_address,
    scenario_state,
    blob,
    continue_upload=True,
    upload_preference: Optional[str] = None,
    previous_version: Optional[str] = None,
):
    def rest_call():
        headers: Dict[str, str] = {}
        params: Dict[str, Any] = {"data_object_size": len(blob)}
        if previous_version is not None:
            params["previous_version"] = previous_version
        if upload_preference is not None and upload_preference != "no":
            params["upload_preference"] = upload_preference
        data = (
            blob
            if _rest_write_should_send_inline_data(
                scenario_state=scenario_state,
                resource_address=resource_address,
                blob_size=len(blob),
                upload_preference=upload_preference,
            )
            else None
        )
        return scenario_state.sapi_test_client.rest_client().write_data_object(
            resource_address,
            write_version=scenario_state.version_under_test["fileobject"],
            data=data,
            headers=headers,
            params=params,
        )

    def grpc_call():
        return grpc_perform_write(
            scenario_state=scenario_state,
            resource_address=resource_address,
            data=blob,
            upload_preference=upload_preference,
            previous_version=previous_version,
            continue_upload=continue_upload,
        )

    try:
        return structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.UNIMPLEMENTED:
            pytest.skip("Skipping test because service returned unexpected UNIMPLEMENTED error during write")
        raise
    except NotImplementedError:
        pytest.skip("Skipping test because service returned unexpected NotImplementedError error during write")


def _rest_write_should_send_inline_data(
    scenario_state,
    resource_address: str,
    blob_size: int,
    upload_preference: Optional[str],
) -> bool:
    """Return whether REST write should include inline PUT body data.

    Uses `get_upload_options` and sends inline data only for sizes in the
    `body` interval (`blob_size < maximum_data_object_size`). Redirect and
    multipart preferences always omit the body. If upload options cannot be
    fetched or parsed, this falls back to sending inline data.
    """
    if upload_preference in {"redirect", "multipart"}:
        return False

    write_type_intervals = _get_cached_rest_write_type_intervals(scenario_state, resource_address)
    if write_type_intervals is None:
        return True

    for interval in write_type_intervals:
        if interval.get("preferred_upload_method") != "body":
            continue
        max_body_size = interval.get("maximum_data_object_size")
        if max_body_size is None:
            return True
        return blob_size < max_body_size

    return False


def _get_cached_rest_write_type_intervals(scenario_state, resource_address: str) -> Optional[list[dict[str, Any]]]:
    """Fetch and cache REST write type intervals by version and top-level address."""
    write_version = scenario_state.version_under_test["fileobject"]
    cache_key = (write_version, _resource_top_level_key(scenario_state, resource_address, write_version))
    if cache_key in _UPLOAD_OPTIONS_CACHE:
        return _UPLOAD_OPTIONS_CACHE[cache_key]

    upload_options_response = scenario_state.sapi_test_client.rest_client().get_upload_options(resource_address, write_version)
    if upload_options_response.status_code != 200:
        return None
    try:
        write_type_intervals = upload_options_response.json()["write_type_intervals"]
    except (ValueError, KeyError, TypeError):
        return None

    _UPLOAD_OPTIONS_CACHE[cache_key] = write_type_intervals
    return write_type_intervals


def _resource_top_level_key(scenario_state, resource_address: str, write_version: str) -> str:
    """Resolve cache key from ListTopLevelAddresses, with URI fallback."""
    top_level_addresses = _get_cached_top_level_addresses(scenario_state, write_version)
    if top_level_addresses:
        for top_level_address in sorted(top_level_addresses, key=len, reverse=True):
            if resource_address.startswith(top_level_address):
                return top_level_address

    # Fallback for tests that do not expose capabilities in this setup.
    parsed = urlsplit(resource_address)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return resource_address.split("/", 1)[0]


def _get_cached_top_level_addresses(scenario_state, write_version: str) -> Optional[list[str]]:
    """Fetch and cache top-level addresses from capabilities API."""
    capabilities_version = scenario_state.version_under_test.get("capabilities", write_version)
    if capabilities_version in _TOP_LEVEL_ADDRESSES_CACHE:
        return _TOP_LEVEL_ADDRESSES_CACHE[capabilities_version]

    top_level_addresses_response = scenario_state.sapi_test_client.rest_client().list_top_level_addresses(
        capabilities_version=capabilities_version
    )
    if top_level_addresses_response.status_code != 200:
        return None

    try:
        top_level_addresses = [
            item["top_level_address"] for item in top_level_addresses_response.json()["items"] if "top_level_address" in item
        ]
    except (ValueError, KeyError, TypeError):
        return None

    _TOP_LEVEL_ADDRESSES_CACHE[capabilities_version] = top_level_addresses
    return top_level_addresses


@then("uploading a file following a redirect succeeds")
def uploading_a_file_following_a_redirect_succeeds(blob, scenario_state, sapi_test_server_launch, upload_headers: ContextFixture):
    response = scenario_state.last_response
    if isinstance(response, requests.Response):
        response_json = response.json()
        upload_response = perform_http_upload(
            data=blob,
            method=response_json["redirect"]["method"].upper(),
            url=response_json["redirect"]["redirect_target_url"],
            headers=response_json["redirect"].get("additional_headers"),
        )
        desired_headers = set(response_json["redirect"]["completion_header_names"])
        upload_headers.value = [
            (header, upload_response.headers[header]) for header in desired_headers if header in upload_response.headers
        ]
    elif isinstance(
        response, scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).WriteResponse
    ):
        redirect = response.write_redirect
        upload_response = perform_http_upload(
            data=blob,
            method=map_request_method_to_str(
                scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]), redirect.method
            ),
            url=redirect.redirect_target_url,
            headers={h.name: h.value for h in redirect.additional_headers} if redirect.additional_headers else None,
        )
        desired_headers = set(redirect.completion_header_names)
        upload_headers.value = [
            (header, upload_response.headers[header]) for header in desired_headers if header in upload_response.headers
        ]
    else:
        raise ValueError(f"unexpected response type: {type(response)!r}")


@then("uploading a file following a redirect fails")
def uploading_a_file_following_a_redirect_fails(blob, scenario_state, sapi_test_server_launch):
    response = scenario_state.last_response
    if isinstance(response, requests.Response):
        response_json = response.json()
        upload_response = perform_http_upload(
            data=blob,
            method=response_json["redirect"]["method"].upper(),
            url=response_json["redirect"]["redirect_target_url"],
            headers=response_json["redirect"].get("additional_headers"),
        )
        assert upload_response.status_code >= 400, f"Expected failure but got status {upload_response.status_code}"
    elif isinstance(
        response, scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).WriteResponse
    ):
        redirect = response.write_redirect
        upload_response = perform_http_upload(
            data=blob,
            method=map_request_method_to_str(
                scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]), redirect.method
            ),
            url=redirect.redirect_target_url,
            headers={h.name: h.value for h in redirect.additional_headers} if redirect.additional_headers else None,
        )
        assert upload_response.status_code >= 400, f"Expected failure but got status {upload_response.status_code}"
    else:
        raise ValueError(f"unexpected response type: {type(response)!r}")


@then(parsers.parse("uploading a file with '{protocol}' in multiple parts returns '{return_code}' on completion"))
@then(
    parsers.parse(
        "uploading a file with '{protocol}' in multiple parts using the memorized write response '{write_response}' returns '{return_code}' on completion"
    )
)
def uploading_a_file_in_multiple_parts_succeeds(protocol, return_code, scenario_state, blob, sapi_test_server_launch, write_response=None):
    if write_response:
        last_response = scenario_state.memorized_responses[write_response]
    else:
        last_response = scenario_state.last_response

    def rest_call():
        multipart_json = last_response.json().get("multipart")
        return _rest_perform_multipart_upload(
            scenario_state=scenario_state,
            resource_address=scenario_state.resource_address,
            expected_completion_return_code=return_code,
            upload_id=multipart_json["upload_id"],
            data=blob,
            initial_redirect=multipart_json["first_part_write_redirect"],
            max_chunk_size=multipart_json["maximum_size_per_part"],
            min_chunk_size=multipart_json["minimum_size_per_part"],
            max_chunks=multipart_json.get("maximum_parts_number"),
        )

    def grpc_call():
        return _grpc_perform_multipart_upload(
            scenario_state=scenario_state,
            resource_address=scenario_state.resource_address,
            upload_id=last_response.multipart_upload.upload_id,
            data=blob,
            max_chunk_size=last_response.multipart_upload.maximum_size_per_part,
            min_chunk_size=last_response.multipart_upload.minimum_size_per_part,
            max_chunks=last_response.multipart_upload.maximum_parts_number,
            first_part_redirect=last_response.multipart_upload.first_part_write_redirect,
        )

    response = structured_api_call(protocol, return_code, grpc_call=grpc_call, rest_call=rest_call)
    if return_code == "OK" and protocol == "GRPC":
        assert response.resource_info.resource_identity.encoded_identity
    elif return_code == "200" and protocol == "REST":
        assert response.status_code == 200
        response_json = response.json()
        assert response_json["resource_identity"]


MAX_CHUNK_PAYLOAD_SIZE = 3 * (2**20)


def split_for_write(content: bytes) -> Iterable[bytes]:
    """Split contents of a data object into a series of chunks, of at most MAX_CHUNK_PAYLOAD_SIZE size."""

    if not content:
        yield b""
        return

    offset = 0
    while offset < len(content):
        last = min(offset + MAX_CHUNK_PAYLOAD_SIZE, len(content))
        yield content[offset:last]
        offset = last


def map_upload_preference(fileobject_service_pb2, upload_preference: str | None) -> Any:
    if upload_preference is None or upload_preference == "no":
        return None
    elif upload_preference == "body":
        return fileobject_service_pb2.UploadPreference.UPLOAD_PREFERENCE_BODY
    elif upload_preference == "redirect":
        return fileobject_service_pb2.UploadPreference.UPLOAD_PREFERENCE_REDIRECT
    elif upload_preference == "multipart":
        return fileobject_service_pb2.UploadPreference.UPLOAD_PREFERENCE_MULTIPART
    else:
        raise ValueError(f"unknown upload preference: {upload_preference}")


def grpc_perform_write(
    scenario_state,
    resource_address: str,
    data: bytes,
    upload_preference: Optional[str] = None,
    continue_upload=True,
    previous_version: Optional[str] = None,
):
    """Perform write based on the method selected by the storage service."""
    fileobject_pb2 = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"])
    fileobject_common_pb2 = scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"])
    preference = map_upload_preference(fileobject_pb2, upload_preference)

    with _write_message_queue() as (request_queue, request_iterator):
        if previous_version is not None:
            params = fileobject_pb2.WriteParameters(
                destination_resource_address=resource_address,
                data_object_size=len(data),
                previous_version=fileobject_common_pb2.ResourceIdentity(encoded_identity=previous_version),
            )
        else:
            params = fileobject_pb2.WriteParameters(
                destination_resource_address=resource_address,
                data_object_size=len(data),
            )
        if preference is not None:
            params.upload_preference = preference
        request_queue.put(fileobject_pb2.WriteRequest(params=params))

        responses: Iterator[Any] = scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).Write(request_iterator)

        response = next(responses)
        if response.HasField("write_chunks_accepted"):
            if continue_upload:
                return _grpc_continue_with_direct_write(fileobject_pb2, fileobject_common_pb2, responses, request_queue, data)
            else:
                return response

    # Can close write queue now, continue either with redirect or multipart upload
    if response.HasField("write_redirect"):
        if continue_upload:
            return _grpc_continue_with_redirect_upload(fileobject_pb2, response.write_redirect, data)
        else:
            return response

    if response.HasField("multipart_upload"):
        if continue_upload:
            return _grpc_continue_with_multipart_upload(scenario_state, resource_address, response.multipart_upload, data)
        else:
            return response

    pytest.fail("Unexpected message in the write response stream")


def _grpc_continue_with_direct_write(fileobject_pb2, fileobject_common_pb2, responses: Iterator, request_queue: Queue, data: bytes) -> Any:
    for blob in split_for_write(data):
        request_queue.put(fileobject_pb2.WriteRequest(chunk=fileobject_common_pb2.Chunk(chunk=blob)))

    # End chunk transmission.
    request_queue.put(None)

    # Expect a final response with the ResourceInfo message
    response = next(responses)
    assert response.HasField("resource_info"), "Resource info message is expected"
    return response


def _grpc_continue_with_redirect_upload(fileobject_pb2, properties, data: bytes) -> requests.Response:
    return perform_http_upload(
        data=data,
        method=map_request_method_to_str(fileobject_pb2, properties.method),
        url=properties.redirect_target_url,
        headers={header.name: header.value for header in properties.additional_headers or []},
    )


def _grpc_continue_with_multipart_upload(scenario_state, resource_address: str, properties, data: bytes):
    return _grpc_perform_multipart_upload(
        scenario_state,
        resource_address=resource_address,
        upload_id=properties.upload_id,
        data=data,
        max_chunk_size=properties.maximum_size_per_part,
        min_chunk_size=properties.minimum_size_per_part,
        max_chunks=properties.maximum_parts_number,
        first_part_redirect=properties.first_part_write_redirect,
    )


def map_request_method_to_str(fileobject_service_pb2, method) -> str:
    """Convert an upload method to a string."""
    if method == fileobject_service_pb2.UploadMethod.UPLOAD_METHOD_POST:
        return "POST"
    elif method == fileobject_service_pb2.UploadMethod.UPLOAD_METHOD_PUT:
        return "PUT"
    else:
        raise ValueError(f"Unexpected upload method {method!r}.")


def _grpc_multipart_part_upload(
    *,
    scenario_state,
    redirect_properties,
    resource_address: str,
    upload_id: str,
    part_number: int,
    data: bytes,
):
    """Upload a single data object part."""
    fileobject_pb2 = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"])
    fileobject_common_pb2 = scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"])
    if redirect_properties is None:
        upload_part_response = scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).UploadPart(
            fileobject_pb2.UploadPartRequest(
                upload_id=upload_id,
                destination_resource_address=resource_address,
                part_number=part_number,
            ),
        )
        redirect_properties = upload_part_response.part_write_redirects[0]

    upload_headers = upload_part_to_http_server(
        data=data,
        method=map_request_method_to_str(fileobject_pb2, redirect_properties.method),
        url=redirect_properties.redirect_target_url,
        header_names=[n for n in redirect_properties.completion_header_names],
        upload_headers={header.name: header.value for header in redirect_properties.additional_headers},
    )
    return fileobject_pb2.CompletedUploadPart(
        part_number=part_number,
        headers=[fileobject_common_pb2.Header(name=name, value=value) for name, value in upload_headers.items()],
    )


def _grpc_perform_multipart_upload(
    scenario_state,
    resource_address: str,
    upload_id: str,
    data: bytes,
    max_chunk_size: int | None,
    min_chunk_size: int | None,
    max_chunks: int | None,
    first_part_redirect,
):
    """Perform a multipart data object upload."""
    parts = [
        _grpc_multipart_part_upload(
            scenario_state=scenario_state,
            redirect_properties=first_part_redirect if part == 0 else None,
            resource_address=resource_address,
            upload_id=upload_id,
            part_number=part,
            data=chunk,
        )
        for part, chunk in enumerate(
            split_into_chunks(
                data=data,
                min_chunk_size=min_chunk_size,
                max_chunk_size=max_chunk_size,
                max_chunks=max_chunks,
            )
        )
    ]
    return _complete_multipart_upload_request("GRPC", upload_id, resource_address, parts, scenario_state, "OK")


def _complete_multipart_upload_request(protocol, upload_id, resource_address, parts, scenario_state, return_value) -> Any:
    def grpc_call():
        return scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).CompleteMultipartUpload(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).CompleteMultipartUploadRequest(
                upload_id=upload_id,
                destination_resource_address=resource_address,
                parts=parts,
            )
        )

    def rest_call():
        complete_multipart_request = {"upload_id": upload_id, "parts": parts}
        return scenario_state.sapi_test_client.rest_client().complete_multipart_upload(
            resource_address,
            multipart_version=scenario_state.version_under_test["fileobject"],
            json=complete_multipart_request,
        )

    return structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)


@contextmanager
def _write_message_queue():
    request_messages: Queue = Queue()

    def yield_request_messages():
        while True:
            if message := request_messages.get():
                yield message
            else:
                break

    try:
        yield request_messages, yield_request_messages()
    finally:
        request_messages.put_nowait(None)


def _rest_multipart_part_upload(
    client: RestClient, resource_address: str, upload_id: str, part: int, data: bytes, initial_redirect: dict, multipart_version: str
) -> dict:
    if part == 0:
        prepare_part_response_json = initial_redirect
    else:
        prepare_part_response = client.create_multipart_part_upload_request(
            resource_address,
            multipart_version=multipart_version,
            json={
                "upload_id": upload_id,
                "part_number": part,
            },
        )
        assert prepare_part_response.status_code == 200

        prepare_part_response_json = prepare_part_response.json()["part_write_redirects"][0]

    assert prepare_part_response_json["redirect_target_url"] is not None
    assert prepare_part_response_json["method"] in ["post", "put"]
    assert prepare_part_response_json["completion_header_names"] is not None
    assert prepare_part_response_json["additional_headers"] is not None

    response_headers: Dict = upload_part_to_http_server(
        data=data,
        method=prepare_part_response_json["method"],
        url=prepare_part_response_json["redirect_target_url"],
        header_names=prepare_part_response_json["completion_header_names"],
        upload_headers=dict([(h["name"], h["value"]) for h in prepare_part_response_json["additional_headers"]]),
    )
    return {
        "part_number": part,
        "additional_headers": [{"name": name, "value": value} for name, value in response_headers.items()],
    }


def _rest_perform_multipart_upload(
    scenario_state,
    resource_address: str,
    expected_completion_return_code: str,
    upload_id: str,
    data: bytes,
    initial_redirect: dict,
    max_chunk_size: int | None,
    min_chunk_size: int | None,
    max_chunks: int | None,
) -> Any:
    parts = [
        _rest_multipart_part_upload(
            client=scenario_state.sapi_test_client.rest_client(),
            resource_address=resource_address,
            upload_id=upload_id,
            part=part,
            data=chunk,
            initial_redirect=initial_redirect,
            multipart_version=scenario_state.version_under_test["fileobject"],
        )
        for part, chunk in enumerate(
            split_into_chunks(
                data=data,
                min_chunk_size=min_chunk_size,
                max_chunk_size=max_chunk_size,
                max_chunks=max_chunks,
            )
        )
    ]
    return _complete_multipart_upload_request("REST", upload_id, resource_address, parts, scenario_state, expected_completion_return_code)
