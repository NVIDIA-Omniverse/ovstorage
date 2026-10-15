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
import time
import uuid
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

import grpc
import pytest
import requests
from conformance_tests.storage_testdata_generator import AbstractTestDataGenerator
from pytest_bdd import (
    given,
    parsers,
    then,
    when,
)

from .common_fixtures import identity_from_fixture
from .utils.structured_api_call import structured_api_call


@given("a connection to the storage service")
def connection_to_storage(sapi_test_client):
    yield sapi_test_client.grpc_channel()


@given("an authenticated user")
def authenticated_user():
    return "some user"


@given(parsers.parse("the service speaks '{protocol}'"))
def given_the_service_understands_the_protocol(protocol: str, scenario_state):
    if not scenario_state.sapi_test_client.speaks_protocol(protocol):
        pytest.skip(f"skipping test because service does not speak the protocol '{protocol}'")


@given("an invalid resource address")
def invalid_address(scenario_state):
    scenario_state.resource_address = scenario_state.sapi_test_client.generator().make_invalid_resource_address()


@given("an invalid resource identity")
def invalid_identity(scenario_state):
    scenario_state.resource_identity = scenario_state.sapi_test_client.generator().make_invalid_resource_identity()


@given(parsers.parse("a new test namespace called '{namespace_name}'"))
def new_namespace(namespace_name, scenario_state):
    new_namespace = scenario_state.sapi_test_client.create_namespace(namespace_name)
    scenario_state.namespaces[namespace_name] = new_namespace
    scenario_state.current_namespace = namespace_name


@given(parsers.parse("a resource address for '{object_name}'"))
def a_resource_address(object_name, scenario_state):
    scenario_state.resource_address = scenario_state.sapi_test_client.generator(scenario_state.current_namespace).make_resource_address(
        scenario_state.namespaces[scenario_state.current_namespace], object_name
    )


@given(parsers.parse("a resource address '{object_name}' which is enumerable"))
def a_resource_address_which_is_enumerable(object_name, scenario_state):
    scenario_state.resource_address = scenario_state.sapi_test_client.generator().make_enumerable_resource_address(
        scenario_state.namespaces[scenario_state.current_namespace], object_name
    )


@given(parsers.parse("a new object address '{object_name}' within the given address"))
def a_new_subaddress(object_name, scenario_state):
    scenario_state.resource_address = scenario_state.resource_address.rstrip("/") + "/" + object_name.lstrip("/")


@given("a root resource address which has some content")
def a_root_resource_address(scenario_state):
    scenario_state.resource_address = scenario_state.sapi_test_client.generator().get_non_empty_root_address()


@given("no object exists at that address")
@when("no object exists at that address")
@then("no object exists at that address")
@when("the object referenced by that resource address is deleted")
def no_object_exists(scenario_state):
    scenario_state.sapi_test_client.generator().delete_if_exists(scenario_state.resource_address)


@when("the object referenced by that resource address is permanently deleted")
def obliterate_object(scenario_state):
    scenario_state.sapi_test_client.generator().obliterate(scenario_state.resource_address)


@given("a folder exists at that address")
def folder_exists_at_address(scenario_state):
    """Create a folder at the given address for idempotency testing."""
    # Delete any existing object first
    scenario_state.sapi_test_client.generator().delete_if_exists(scenario_state.resource_address)
    # Create the folder using the public method
    scenario_state.sapi_test_client.generator().create_folder(scenario_state.resource_address)


@given(parsers.cfparse("an object of size '{size:Number}' exists at that address and is readable", extra_types={"Number": int}))
@when(parsers.cfparse("an object of size '{size:Number}' exists at that address and is readable", extra_types={"Number": int}))
def an_object_of_given_size(size: int, scenario_state):
    scenario_state.sapi_test_client.generator().create_object_of_given_size(scenario_state.resource_address, size)


@given(parsers.parse("an object of size '{size:d}' exists at that address and is readable and has '{version_count:d}' versions"))
def an_object_with_many_versions(size: int, version_count: int, scenario_state):
    """Create an object with multiple versions, all of the same size.

    Note: For tests requiring many versions with distinct sizes (to detect ghost writes),
    use the step: "'{count}' versions with distinct sizes from '{start}' to '{end}' bytes exist at that address"
    """
    # Create the initial object
    scenario_state.sapi_test_client.generator().create_object_of_given_size(scenario_state.resource_address, size)

    # Create remaining versions sequentially
    for _ in range(version_count - 1):
        scenario_state.sapi_test_client.generator().add_version_object_of_given_size(scenario_state.resource_address, size)


@given(
    parsers.parse("'{version_count:d}' versions with distinct sizes from '{start_size:d}' to '{end_size:d}' bytes exist at that address")
)
def an_object_with_many_distinct_size_versions(version_count: int, start_size: int, end_size: int, scenario_state):
    """Create versions with distinct sizes for robust testing against ghost writes.

    Each version has a unique size, allowing verification that all expected versions are present
    and no ghost writes occurred (which would create duplicate or extra versions).

    Versions are created in parallel batches to stress-test the storage system's
    handling of concurrent writes.
    """
    # Calculate the step size to evenly distribute sizes
    step = (end_size - start_size) // (version_count - 1) if version_count > 1 else 0
    expected_sizes = [start_size + i * step for i in range(version_count)]

    # Store expected sizes in scenario_state for later verification
    scenario_state.expected_version_sizes = set(expected_sizes)

    # Create the first version
    scenario_state.sapi_test_client.generator().create_object_of_given_size(scenario_state.resource_address, expected_sizes[0])

    def add_version_with_size(size):
        scenario_state.sapi_test_client.generator().add_version_object_of_given_size(scenario_state.resource_address, size)

    remaining_sizes = expected_sizes[1:]

    # Create versions in parallel batches to stress-test concurrent writes
    with ThreadPoolExecutor() as executor:
        while remaining_sizes:
            batch = remaining_sizes[:50]
            remaining_sizes = remaining_sizes[50:]
            futures = [executor.submit(add_version_with_size, size) for size in batch]

            exceptions = []
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    exceptions.append(exc)

            if exceptions:
                if len(exceptions) == 1:
                    raise exceptions[0]
                else:
                    error_messages = [str(exc) for exc in exceptions]
                    raise RuntimeError(f"Multiple errors occurred during parallel version creation: {error_messages}")


@given(parsers.parse("an object of size '{size:d}' within that address which is named '{filename}'"))
def an_object_small(size: int, filename: str, scenario_state):
    sub_address = scenario_state.sapi_test_client.generator().make_resource_address(scenario_state.resource_address, filename)
    scenario_state.sapi_test_client.generator().create_object_of_given_size(sub_address, size)
    scenario_state.memorized_responses[filename] = sub_address


@given(parsers.parse("'{number:d}' objects within that address of size '{size:d}'"))
def many_objects_in_one_directory(number, size, scenario_state):
    for i in range(number):
        random_name = uuid.uuid4().hex + f".{i}"
        full_resource_address = scenario_state.sapi_test_client.generator().make_resource_address(
            scenario_state.resource_address, random_name
        )
        scenario_state.sapi_test_client.generator().create_object_of_given_size(full_resource_address, size)


@given(parsers.parse("a test object of size '{size:d}' with rand seed '{seed:d}' at that address"))
@when(parsers.parse("a test object of size '{size:d}' with rand seed '{seed:d}' at that address"))
def an_object_small_with_seed(size, seed, scenario_state):
    scenario_state.sapi_test_client.generator().create_object_of_given_size(scenario_state.resource_address, size, seed)


@given(parsers.parse("we add a version of size '{size:d}' with rand seed '{seed:d}' at that address"))
@when(parsers.parse("we add a version of size '{size:d}' with rand seed '{seed:d}' at that address"))
def add_version_to_address(size, seed, scenario_state):
    scenario_state.sapi_test_client.generator().add_version_object_of_given_size(scenario_state.resource_address, size, seed)
    # Track added size if we're verifying expected sizes
    if hasattr(scenario_state, "expected_version_sizes"):
        scenario_state.expected_version_sizes.add(size)


@given("an object exists at that address, but the user has no permissions")
def an_object_exists(scenario_state):
    try:
        scenario_state.sapi_test_client.generator().create_object_with_no_read_permission(scenario_state.resource_address)
    except NotImplementedError:
        pytest.skip("skipped because the test data generator can not create objects without read permissions - please adjust.")


@when("the user loses read permissions on that object")
def the_user_loses_read_permissions(scenario_state):
    resource_identity = identity_from_fixture(scenario_state.last_response)
    try:
        scenario_state.sapi_test_client.generator().remove_read_permission_via_identity(resource_identity)
    except NotImplementedError:
        pytest.skip("skipped because the test data generator can not remove read permissions via identity - please adjust.")


@when(parsers.parse("we wait for '{seconds:f}' seconds"))
def wait_time_step(seconds: float):
    time.sleep(seconds)


@given(parsers.parse("a blob of '{size}' bytes"), target_fixture="blob")
def a_blob_of_given_size(size):
    return AbstractTestDataGenerator.generate_random_bytes(int(size))


@when(parsers.parse("a '{blob_size}' blob according to the upload options for that address, using '{protocol}'"), target_fixture="blob")
@given(parsers.parse("a '{blob_size}' blob according to the upload options for that address, using '{protocol}'"), target_fixture="blob")
def a_blob_of_certain_size(blob_size, protocol, scenario_state, sapi_test_server_launch):
    if blob_size not in ["small", "medium", "large"]:
        pytest.fail(f"Unknown test blob size {blob_size}, use one of small, medium, large")
    if protocol == "REST":
        response = scenario_state.sapi_test_client.rest_client().get_upload_options(
            scenario_state.resource_address, scenario_state.version_under_test["fileobject"]
        )
        assert response.status_code == 200

        write_type_intervals = json.loads(response.content)["write_type_intervals"]
        # Find the write type interval to match the preferred upload method
        data_size = -1
        for interval in write_type_intervals:
            if (
                interval["preferred_upload_method"] == "body"
                and blob_size == "small"
                or interval["preferred_upload_method"] == "redirect"
                and blob_size == "medium"
                or interval["preferred_upload_method"] == "multipart"
                and blob_size == "large"
            ):
                data_size = interval["minimum_data_object_size"]
                break
        if data_size == -1:
            pytest.skip(reason="The storage service does not support the download method for this test")

    elif protocol == "GRPC":
        response = scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).FetchWriteTypeInfo(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).FetchWriteTypeInfoRequest(
                destination_resource_address=scenario_state.resource_address
            )
        )
        # Find the write type interval to match the preferred upload method
        data_size = -1
        for interval in response.write_type_intervals:
            if (
                interval.preferred_upload_method
                == scenario_state.sapi_test_client.fileobject_pb2(
                    scenario_state.version_under_test["fileobject"]
                ).UploadPreference.UPLOAD_PREFERENCE_BODY
                and blob_size == "small"
                or interval.preferred_upload_method
                == scenario_state.sapi_test_client.fileobject_pb2(
                    scenario_state.version_under_test["fileobject"]
                ).UploadPreference.UPLOAD_PREFERENCE_REDIRECT
                and blob_size == "medium"
                or interval.preferred_upload_method
                == scenario_state.sapi_test_client.fileobject_pb2(
                    scenario_state.version_under_test["fileobject"]
                ).UploadPreference.UPLOAD_PREFERENCE_MULTIPART
                and blob_size == "large"
            ):
                data_size = interval.minimum_data_object_size
                break
        if data_size == -1:
            pytest.skip(reason="The storage service does not support the download method for this test")
    else:
        pytest.fail(f"Unknown protocol {protocol}, must be one of REST, GRPC")
    return AbstractTestDataGenerator.generate_random_bytes(data_size)


@given(
    parsers.parse(
        "'{version_count:d}' versions with distinct sizes using '{upload_method}' upload exist at that address using '{protocol}'"
    )
)
def an_object_with_many_distinct_size_versions_for_upload_method(
    version_count: int, upload_method: str, protocol: str, scenario_state, sapi_test_server_launch
):
    """Create versions with distinct sizes that trigger a specific upload method.

    Queries the service for upload intervals and creates versions with sizes
    that fall within the range for the specified upload method (body, redirect, multipart).
    This tests ghost write detection for different upload paths.
    """
    if upload_method not in ["body", "redirect", "multipart"]:
        pytest.fail(f"Unknown upload method '{upload_method}', use one of: body, redirect, multipart")

    # Query the service for upload intervals
    if protocol == "REST":
        response = scenario_state.sapi_test_client.rest_client().get_upload_options(
            scenario_state.resource_address, scenario_state.version_under_test["fileobject"]
        )
        assert response.status_code == 200
        write_type_intervals = json.loads(response.content)["write_type_intervals"]

        # Find the interval for the specified upload method
        min_size, max_size = -1, -1
        for interval in write_type_intervals:
            if interval["preferred_upload_method"] == upload_method:
                min_size = interval["minimum_data_object_size"]
                max_size = interval["maximum_data_object_size"]
                break
    elif protocol == "GRPC":
        response = scenario_state.sapi_test_client.fileobject_grpc_client(
            scenario_state.version_under_test["fileobject"]
        ).FetchWriteTypeInfo(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).FetchWriteTypeInfoRequest(
                destination_resource_address=scenario_state.resource_address
            )
        )

        # Map upload method string to gRPC enum
        method_map = {
            "body": scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_BODY,
            "redirect": scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_REDIRECT,
            "multipart": scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_MULTIPART,
        }
        target_preference = method_map[upload_method]

        min_size, max_size = -1, -1
        for interval in response.write_type_intervals:
            if interval.preferred_upload_method == target_preference:
                min_size = interval.minimum_data_object_size
                max_size = interval.maximum_data_object_size
                break
    else:
        pytest.fail(f"Unknown protocol '{protocol}', must be one of: REST, GRPC")

    if min_size == -1:
        pytest.skip(f"The storage service does not support the '{upload_method}' upload method")

    # Limit max_size to avoid creating huge files (cap at 2MB for multipart tests)
    max_size = min(max_size, min_size + 2 * 1024 * 1024)

    # Calculate distinct sizes within the interval
    if version_count == 1:
        expected_sizes = [min_size]
    else:
        step = (max_size - min_size) // (version_count - 1) if version_count > 1 else 0
        # Ensure step is at least 1 to have distinct sizes
        step = max(step, 1)
        expected_sizes = [min_size + i * step for i in range(version_count)]

    # Store expected sizes for later verification
    scenario_state.expected_version_sizes = set(expected_sizes)

    # Create the first version
    scenario_state.sapi_test_client.generator().create_object_of_given_size(scenario_state.resource_address, expected_sizes[0])

    # Create remaining versions in parallel batches
    def add_version_with_size(size):
        scenario_state.sapi_test_client.generator().add_version_object_of_given_size(scenario_state.resource_address, size)

    remaining_sizes = expected_sizes[1:]

    with ThreadPoolExecutor() as executor:
        while remaining_sizes:
            batch = remaining_sizes[:50]
            remaining_sizes = remaining_sizes[50:]
            futures = [executor.submit(add_version_with_size, size) for size in batch]

            exceptions = []
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    exceptions.append(exc)

            if exceptions:
                if len(exceptions) == 1:
                    raise exceptions[0]
                else:
                    error_messages = [str(exc) for exc in exceptions]
                    raise RuntimeError(f"Multiple errors occurred during parallel version creation: {error_messages}")


@given("user has no permissions to write at that address")
def user_has_no_permissions_to_write_at_that_address(scenario_state):
    try:
        return scenario_state.sapi_test_client.generator().remove_write_permission_via_address(scenario_state.resource_address)
    except NotImplementedError:
        pytest.skip("skipped because the test data generator can not assert objects have no read permissions - please adjust.")


@given(parsers.parse("the '{protocol}' service supports the '{api_name}' API in version '{version}' for feature '{feature}'"))
def check_capability_step(protocol: str, api_name: str, version: str, feature: str, scenario_state, sapi_test_server_launch):
    # Call the capability API to check if the testee supports the appropriate API
    if protocol == "GRPC":
        for capabilities_version in ["v1alpha", "v1beta", "v1"]:
            try:
                services_supported = scenario_state.sapi_test_client.capabilities_grpc_client(capabilities_version).ListServices(
                    scenario_state.sapi_test_client.capabilities_pb2(capabilities_version).ListServicesRequest()
                )
                for service in services_supported.services:
                    if service.service_name == api_name:
                        for supported_version in service.service_versions:
                            if supported_version == version:
                                scenario_state.version_under_test[feature] = version
                                return True
                pytest.skip(f"'{api_name}' is not supported in version '{version}'")
            except grpc.RpcError as rpc_error:
                if rpc_error.code() == grpc.StatusCode.UNIMPLEMENTED:
                    pytest.skip(
                        f"Skipping test because GRPC returned UNIMPLEMENTED for api_name '{api_name}' version '{version}' feature '{feature}'"
                    )
                pytest.fail(f"Got RPC error calling the capabilities API: {rpc_error}")
    elif protocol == "REST":
        client = scenario_state.sapi_test_client.rest_client()
        service_response = client.list_services()
        assert service_response.status_code == 200
        data = json.loads(service_response.content)
        for service in data["services"]:
            if service["service_name"] == api_name:
                for supported_version in service["service_versions"]:
                    if supported_version == version:
                        scenario_state.version_under_test[feature] = version
                        return True
        pytest.skip(f"'{api_name}' is not supported in version '{version}'")
    else:
        raise ValueError(f"invalid protocol: {protocol!r}")


@given(parsers.parse("the '{protocol}' service reports having native folders '{predicate}' '{value}'"))
def service_reports_native_folders(protocol, predicate, value, scenario_state):
    if protocol == "GRPC":
        response = scenario_state.sapi_test_client.filefolder_grpc_client(scenario_state.version_under_test["filefolder"]).GetFolderMode(
            scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).GetFolderModeRequest(
                folder=scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).FolderAddress(
                    uri=scenario_state.namespaces[scenario_state.current_namespace]
                )
            )
        )
        if (
            response.folder_mode
            == scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).FolderMode.FOLDER_MODE_NATIVE
        ):
            detected_value = "native"
        elif (
            response.folder_mode
            == scenario_state.sapi_test_client.filefolder_pb2(
                scenario_state.version_under_test["filefolder"]
            ).FolderMode.FOLDER_MODE_NO_EMPTY
        ):
            detected_value = "no_empty"
        elif (
            response.folder_mode
            == scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).FolderMode.FOLDER_MODE_HYBRID
        ):
            detected_value = "hybrid"
        else:
            raise ValueError(f"Storage system specified unsupported FolderMode: {response.folder_mode}")
    elif protocol == "REST":
        client = scenario_state.sapi_test_client.rest_client()
        reply = client.get_folder_mode(
            scenario_state.namespaces[scenario_state.current_namespace], scenario_state.version_under_test["filefolder"]
        )
        assert reply.status_code == 200
        detected_value = reply.json()["folder_mode"]
    else:
        raise ValueError(f"invalid protocol: {protocol!r}")

    if predicate == "as":
        if value != detected_value:
            pytest.skip(f"Test only works for addresses with folder mode {value} but storage service reported {detected_value}")
    elif predicate == "not as":
        if value == detected_value:
            pytest.skip(f"Test only works for addresses with folder mode not being {value} but storage service reported {detected_value}")
    else:
        raise ValueError("Predicate must be 'as' or 'not as'")


@given("a blob of zero size", target_fixture="blob")
def a_blob_of_zero_size():
    return b""


@given(parsers.parse("the '{protocol}' service supports optimistic locking for '{operation}'"))
def determine_optimistic_locking_support(protocol: str, operation: str, scenario_state, sapi_test_server_launch):
    """Check if the server supports optimistic locking for the specified operation.

    This step checks if the server supports conditional execution (previous_version parameter)
    for the specified operation. If the GetOptimisticLockingSupport API is not available
    (e.g., on older servers), optimistic locking support is assumed (it was required behavior).
    The test is only skipped if the API is available and explicitly reports no support.

    Args:
        protocol: Either 'GRPC' or 'REST'
        operation: One of 'write', 'delete', 'copy', or 'move'
        scenario_state: Test state fixture
        sapi_test_server_launch: Server launch fixture
    """
    import urllib.parse

    operation = operation.lower()
    if operation not in ["write", "delete", "copy", "move"]:
        pytest.fail(f"Unknown operation '{operation}'. Must be one of: write, delete, copy, move")

    # Use the current namespace's resource address for the capability query
    resource_address = scenario_state.namespaces.get(scenario_state.current_namespace, "")

    def grpc_call():
        pb2 = scenario_state.sapi_test_client.fileobject_pb2("v1alpha")
        return scenario_state.sapi_test_client.fileobject_grpc_client("v1alpha").GetOptimisticLockingSupport(
            pb2.GetOptimisticLockingSupportRequest(resource_address=resource_address)
        )

    def rest_call():
        client = scenario_state.sapi_test_client.rest_client()
        encoded_address = urllib.parse.quote(resource_address, safe="")
        return requests.get(f"{client._base_url}/v1alpha/fileobject/optimistic-locking-support/{encoded_address}", timeout=30)

    try:
        response = structured_api_call(protocol, grpc_call=grpc_call, rest_call=rest_call)
    except (grpc.RpcError, NotImplementedError, AssertionError):
        # Old servers don't have GetOptimisticLockingSupport but DO support optimistic locking
        # (it was required behavior). Assume support is available for backward compatibility.
        return
    except Exception:
        # Same as above - assume optimistic locking is supported if we can't query
        return

    # Extract support flags from response
    if protocol == "GRPC":
        support = {
            "write": response.supports_write,
            "delete": response.supports_delete,
            "copy": response.supports_copy,
            "move": response.supports_move,
        }
    else:  # REST
        data = response.json()
        support = {
            "write": data.get("supports_write", False),
            "delete": data.get("supports_delete", False),
            "copy": data.get("supports_copy", False),
            "move": data.get("supports_move", False),
        }

    if not support.get(operation, False):
        pytest.skip(f"Server does not support optimistic locking for {operation} operations")
