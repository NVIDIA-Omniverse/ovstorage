# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import asyncio
import datetime
import os
import random
import string
import threading
from http.client import HTTPException
from math import ceil
from typing import (
    Generator,
    Optional,
    Tuple,
)

import grpc
import pytest
import requests
from conformance_tests.storage_testclient import ConformanceTestClient
from conformance_tests.storage_testdata_generator import AbstractTestDataGenerator
from nvidia.omniverse.storage.capabilities.v1alpha.capabilities_pb2 import (
    ListServicesRequest,
)
from nvidia.omniverse.storage.capabilities.v1alpha.capabilities_pb2_grpc import (
    CapabilitiesServiceStub,
)
from nvidia.omniverse.storage.filefolder.v1alpha.filefolder_service_pb2 import (
    CreateFolderRequest,
    FolderAddress,
)
from nvidia.omniverse.storage.filefolder.v1alpha.filefolder_service_pb2_grpc import (
    FileFolderServiceStub,
)
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_pb2 import (
    Chunk,
    Header,
)
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2 import (
    CompletedUploadPart,
    CompleteMultipartUploadRequest,
    CreateMultipartUploadResponse,
    DeleteRequest,
    UploadMethod,
    UploadPartRequest,
    UploadPartResponse,
    WriteParameters,
    WriteRedirectProperties,
    WriteRequest,
)
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2_grpc import (
    FileObjectServiceStub,
)


class StorageAPITestDataGenerator(AbstractTestDataGenerator):
    def __init__(self, resource_address_base: str, grpc_endpoint: str, rest_endpoint: str, **kwargs):
        self._resource_address_base = resource_address_base
        self._base_url = rest_endpoint
        self._endpoint = grpc_endpoint
        self._channel = grpc.insecure_channel(self._endpoint)
        self._fileobject_api = FileObjectServiceStub(self._channel)
        self._filefolder_api = FileFolderServiceStub(self._channel)
        self._capabilities_api = CapabilitiesServiceStub(self._channel)
        self._filefolder_v1alpha_supported = self._check_filefolder_v1alpha_support()

    def _check_filefolder_v1alpha_support(self) -> bool:
        """Check if the service supports filefolder API in v1alpha version."""
        try:
            services_supported = self._capabilities_api.ListServices(ListServicesRequest())
            for service in services_supported.services:
                if service.service_name == "filefolder":
                    for supported_version in service.service_versions:
                        if supported_version == "v1alpha":
                            return True
            return False
        except grpc.RpcError:
            # If capabilities API is not available, assume not supported
            return False

    def create_namespace(self, namespace) -> str:
        utcnow = datetime.datetime.now(datetime.timezone.utc)
        target = utcnow.strftime("%Y%m%d_%H%M%S_%f") + "_" + "".join(random.choices(string.ascii_lowercase, k=2))
        assert self._resource_address_base != "", "Empty resource address base"
        return f"{self._resource_address_base}/{target}/{namespace}"

    def make_resource_address(self, namespace_path, sub_address) -> str:
        if namespace_path.endswith("/"):
            namespace_path = namespace_path[:-1]
        return f"{namespace_path}/{sub_address}"

    def make_invalid_resource_address(self) -> str:
        return os.environ.get("TEST_INVALID_RESOURCE_ADDRESS", "c:d:e:\0")

    def make_invalid_resource_identity(self) -> str:
        return os.environ.get("TEST_INVALID_RESOURCE_IDENTITY", "c:d:e:\0")

    def make_enumerable_resource_address(self, namespace_path, object_name) -> str:
        return f"{namespace_path}/{object_name.lstrip('/')}"

    def get_non_empty_root_address(self) -> str:
        return self._resource_address_base

    def delete_if_exists(self, resource_address: str):
        try:
            self._fileobject_api.Delete(DeleteRequest(resource_address=resource_address))
        except grpc.RpcError as err:
            if err.code() == grpc.StatusCode.NOT_FOUND:
                # All good
                return
            raise err

    def obliterate(self, resource_address: str):
        pytest.skip("Storage API test data generator cannot obliterate, skipping test")

    def create_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None):
        content = AbstractTestDataGenerator.generate_random_bytes(size, seed)
        asyncio.run(self._write_file(resource_address, content, "create by test data generator"))

    def add_version_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None):
        content = AbstractTestDataGenerator.generate_random_bytes(size, seed)
        asyncio.run(self._write_file(resource_address, content, "create by test data generator"))

    def create_object_with_no_read_permission(self, resource_address: str):
        raise NotImplementedError("Can't create object which has no permission via the storage API")

    def remove_read_permission_via_identity(self, resource_identity: str):
        raise NotImplementedError("Can't remove object permissions on a resource identity via the storage API")

    def remove_write_permission_via_address(self, resource_address: str):
        raise NotImplementedError("Can't remove object permissions on a resource address via the storage API")

    def create_folder(self, resource_address: str):
        """Create a folder using the FileFolderService gRPC API."""
        if not self._filefolder_v1alpha_supported:
            raise NotImplementedError("CreateFolder service is not supported by the storage service under test, test should check first.")
        self._filefolder_api.CreateFolder(CreateFolderRequest(folder=FolderAddress(uri=resource_address)))

    async def _write_file(self, resource_address: str, content: bytes, comment: str) -> bool:
        content_length = len(content)

        # We launch a thread that creates the Write Chunk messages, so we can consume the server's replies
        # independently
        generator_initialized_event = threading.Event()
        send_chunks_event = threading.Event()
        send_chunks = False

        generator = None

        def __slice_content(chunk_size) -> Generator[bytes, None, None]:
            i = 0
            while i < len(content):
                yield content[i : i + chunk_size]
                i += chunk_size

        def __generate_write_requests() -> Generator[WriteRequest, None, None]:
            # Yield the initial WriteRequest
            yield WriteRequest(
                params=WriteParameters(
                    destination_resource_address=resource_address,
                    data_object_size=content_length,
                ),
            )
            send_chunks_event.wait()
            if send_chunks:
                for chunk in __slice_content(1024 * 1024):
                    yield WriteRequest(chunk=Chunk(chunk=bytes(chunk)))

        def __generator_thread_func():
            nonlocal generator
            generator = __generate_write_requests()
            generator_initialized_event.set()

        generator_thread = threading.Thread(target=__generator_thread_func)
        generator_thread.start()

        # Wait for thread startup
        generator_initialized_event.wait()

        try:
            write_responses = self._fileobject_api.Write(generator)
            flow_control_message = next(write_responses)
            if flow_control_message.HasField("write_chunks_accepted"):
                # Signal the generator to continue with the next chunks for direct upload
                send_chunks = True
                send_chunks_event.set()
                next_message = next(write_responses)
                if next_message.HasField("resource_info"):
                    return True
                else:
                    raise RuntimeError(f"Unexpected response from service: {flow_control_message}")
            elif flow_control_message.HasField("write_redirect"):
                send_chunks_event.set()  # Let the generator finish, no more chunk sending
                StorageAPITestDataGenerator._write_via_redirect(flow_control_message.write_redirect, content)
                return True
            elif flow_control_message.HasField("multipart_upload"):
                send_chunks_event.set()  # Let the generator finish, no more chunk sending
                return self._write_via_multipart(flow_control_message.multipart_upload, resource_address, content)

            raise Exception("Unexpected flow control message.")
        except grpc.RpcError as e:
            raise RuntimeError(f"Error calling Write: {str(e)}")

    @staticmethod
    def _write_via_redirect(parameters: WriteRedirectProperties, content) -> requests.Response:
        try:
            response: requests.Response = requests.request(
                url=parameters.redirect_target_url,
                method=_upload_method_to_string(parameters.method),
                headers={header.name: header.value for header in parameters.additional_headers},
                data=content,
            )
            response.raise_for_status()
            return response
        except HTTPException as e:
            raise RuntimeError(f"Failure to HTTP upload data to {parameters.redirect_target_url}: {str(e)}")

    def _write_via_multipart(self, parameters: CreateMultipartUploadResponse, resource_address: str, content):
        # Calculate the number of parts
        part_size = 1024 * 1024
        if parameters.HasField("minimum_size_per_part"):
            part_size = max(part_size, parameters.minimum_size_per_part)
        if parameters.HasField("maximum_size_per_part"):
            part_size = min(part_size, parameters.maximum_size_per_part)
        if part_size == 0:
            raise RuntimeError(f"Cannot upload multipart upload, allowed part_size calculated as 0")
        total_part_count = ceil(len(content) / part_size)
        if parameters.HasField("maximum_parts_number"):
            if total_part_count > parameters.maximum_parts_number:
                # TODO - we'd need to change the default buffer size of 1 MByte now...
                raise RuntimeError(
                    f"Cannot upload multipart upload, allowed part_number calculated as {total_part_count} exceeds maximum part number {parameters.maximum_parts_number}, need to change default buffer size"
                )

        try:
            # Build a list of redirect URLs to upload the parts to. The first we got from the CreateMultipartUploadResponse
            redirects = [parameters.first_part_write_redirect]
            if total_part_count > 1:
                # We need more than one part, generate the additional upload URLs via a server roundtrip
                response: UploadPartResponse = self._fileobject_api.UploadPart(
                    UploadPartRequest(
                        upload_id=parameters.upload_id,
                        destination_resource_address=resource_address,
                        part_number=1,  # Part number 0 has already been delivered by the first CreateMultipartUploadReponse
                        part_count=total_part_count - 1,
                    ),
                )
                redirects.extend(response.part_write_redirects)

            def part_generator() -> Generator[Tuple[int, bytes], None, None]:
                part_index = 0
                i = 0
                while i < len(content):
                    yield part_index, content[i : i + part_size]
                    part_index += 1
                    i += part_size

            completed_parts = []
            for part_index, part in part_generator():
                upload_response = StorageAPITestDataGenerator._write_via_redirect(redirects[part_index], part)
                if upload_response.status_code != 200:
                    raise RuntimeError(f"Got unexpected response from part upload: {upload_response.status_code}")
                return_headers = []
                for requested_header in redirects[part_index].completion_header_names:
                    if requested_header in upload_response.headers:
                        return_headers.append(Header(name=requested_header, value=upload_response.headers[requested_header]))
                    else:
                        raise RuntimeError(f"Part upload response missing required return header: '{requested_header}'")
                completed_parts.append(CompletedUploadPart(part_number=part_index, headers=return_headers))

            self._fileobject_api.CompleteMultipartUpload(
                CompleteMultipartUploadRequest(
                    upload_id=parameters.upload_id,
                    destination_resource_address=resource_address,
                    parts=completed_parts,
                ),
            )
        except grpc.RpcError as e:
            raise RuntimeError(f"Error calling MultipartUpload Write: {str(e)}")


def _upload_method_to_string(value: UploadMethod) -> str:
    if value == UploadMethod.UPLOAD_METHOD_POST:
        return "POST"
    elif value == UploadMethod.UPLOAD_METHOD_PUT:
        return "PUT"
    raise RuntimeError(f"Unsupported upload method {value!r}.")


@pytest.fixture(scope="session")
def sapi_test_client():
    rest_endpoint = os.getenv("TEST_STORAGE_API_REST_ENDPOINT", "http://localhost:8011")
    grpc_endpoint = os.getenv("TEST_STORAGE_API_GRPC_ENDPOINT", "localhost:50051")
    resource_base = os.getenv("TEST_STORAGE_API_RESOURCE_BASE", "file-storage://fileservice")
    test_data_generator = StorageAPITestDataGenerator(
        resource_address_base=resource_base, grpc_endpoint=grpc_endpoint, rest_endpoint=rest_endpoint
    )
    with grpc.insecure_channel(grpc_endpoint) as channel:
        yield ConformanceTestClient(
            grpc_port=50051, grpc_channel=channel, rest_endpoint=rest_endpoint, testdata_generator=test_data_generator
        )


@pytest.fixture(scope="session")
def sapi_test_server_launch():
    # No auto launching of the storage service implemented, the service needs to be launched before the tests are executed
    yield "No auto launching"
