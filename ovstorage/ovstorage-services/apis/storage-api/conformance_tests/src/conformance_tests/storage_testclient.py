# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from typing import (
    Dict,
    List,
    Optional,
)

import grpc
from conformance_tests.steps.utils.rest_client import RestClient
from conformance_tests.storage_testdata_generator import AbstractTestDataGenerator
from nvidia.omniverse.storage.capabilities.v1alpha import (
    capabilities_pb2 as capabilities_pb2_v1alpha,
)
from nvidia.omniverse.storage.capabilities.v1alpha import (
    capabilities_pb2_grpc as capabilities_pb2_grpc_v1alpha,
)
from nvidia.omniverse.storage.capabilities.v1beta import (
    capabilities_pb2 as capabilities_pb2_v1beta,
)
from nvidia.omniverse.storage.capabilities.v1beta import (
    capabilities_pb2_grpc as capabilities_pb2_grpc_v1beta,
)
from nvidia.omniverse.storage.filefolder.v1alpha import (
    filefolder_service_pb2 as filefolder_service_pb2_v1alpha,
)
from nvidia.omniverse.storage.filefolder.v1alpha import (
    filefolder_service_pb2_grpc as filefolder_service_pb2_grpc_v1alpha,
)
from nvidia.omniverse.storage.filefolder.v1beta import (
    filefolder_service_pb2 as filefolder_service_pb2_v1beta,
)
from nvidia.omniverse.storage.filefolder.v1beta import (
    filefolder_service_pb2_grpc as filefolder_service_pb2_grpc_v1beta,
)
from nvidia.omniverse.storage.fileobject.v1alpha import (
    fileobject_pb2 as fileobject_pb2_v1alpha,
)
from nvidia.omniverse.storage.fileobject.v1alpha import (
    fileobject_service_pb2 as fileobject_service_pb2_v1alpha,
)
from nvidia.omniverse.storage.fileobject.v1alpha import (
    fileobject_service_pb2_grpc as fileobject_service_pb2_grpc_v1alpha,
)
from nvidia.omniverse.storage.fileobject.v1beta import (
    fileobject_pb2 as fileobject_pb2_v1beta,
)
from nvidia.omniverse.storage.fileobject.v1beta import (
    fileobject_service_pb2 as fileobject_service_pb2_v1beta,
)
from nvidia.omniverse.storage.fileobject.v1beta import (
    fileobject_service_pb2_grpc as fileobject_service_pb2_grpc_v1beta,
)
from nvidia.omniverse.storage.metadata.v1alpha import (
    metadata_pb2 as metadata_pb2_v1alpha,
)
from nvidia.omniverse.storage.metadata.v1alpha import (
    metadata_pb2_grpc as metadata_pb2_grpc_v1alpha,
)
from nvidia.omniverse.storage.versioning.v1alpha import (
    versioning_pb2 as versioning_pb2_v1alpha,
)
from nvidia.omniverse.storage.versioning.v1alpha import (
    versioning_pb2_grpc as versioning_pb2_grpc_v1alpha,
)
from nvidia.omniverse.storage.versioning.v1beta import (
    versioning_pb2 as versioning_pb2_v1beta,
)
from nvidia.omniverse.storage.versioning.v1beta import (
    versioning_pb2_grpc as versioning_pb2_grpc_v1beta,
)


class ConformanceTestClient:
    def __init__(self, grpc_port, grpc_channel, rest_endpoint: str, testdata_generator):
        self._grpc_port = grpc_port
        self._grpc_channel = grpc_channel
        self._rest_endpoint = rest_endpoint
        self._testdata_generator = testdata_generator
        self._capabilities_service = {
            "v1alpha": capabilities_pb2_grpc_v1alpha.CapabilitiesServiceStub(self._grpc_channel),
            "v1beta": capabilities_pb2_grpc_v1beta.CapabilitiesServiceStub(self._grpc_channel),
        }
        self._capabilities_pb2 = {
            "v1alpha": capabilities_pb2_v1alpha,
            "v1beta": capabilities_pb2_v1beta,
        }
        self._fileobject_service = {
            "v1alpha": fileobject_service_pb2_grpc_v1alpha.FileObjectServiceStub(self._grpc_channel),
            "v1beta": fileobject_service_pb2_grpc_v1beta.FileObjectServiceStub(self._grpc_channel),
        }
        self._fileobject_service_pb2 = {
            "v1alpha": fileobject_service_pb2_v1alpha,
            "v1beta": fileobject_service_pb2_v1beta,
        }
        self._fileobject_pb2 = {
            "v1alpha": fileobject_pb2_v1alpha,
            "v1beta": fileobject_pb2_v1beta,
        }
        self._filefolder_service = {
            "v1alpha": filefolder_service_pb2_grpc_v1alpha.FileFolderServiceStub(self._grpc_channel),
            "v1beta": filefolder_service_pb2_grpc_v1beta.FileFolderServiceStub(self._grpc_channel),
        }
        self._filefolder_service_pb2 = {
            "v1alpha": filefolder_service_pb2_v1alpha,
            "v1beta": filefolder_service_pb2_v1beta,
        }
        self._versioning_service = {
            "v1alpha": versioning_pb2_grpc_v1alpha.VersioningServiceStub(self._grpc_channel),
            "v1beta": versioning_pb2_grpc_v1beta.VersioningServiceStub(self._grpc_channel),
        }
        self._versioning_pb2 = {
            "v1alpha": versioning_pb2_v1alpha,
            "v1beta": versioning_pb2_v1beta,
        }
        self._metadata_service = {"v1alpha": metadata_pb2_grpc_v1alpha.MetadataServiceStub(self._grpc_channel)}
        self._metadata_pb2 = {
            "v1alpha": metadata_pb2_v1alpha,
        }
        self._additional_testdata_generators: Dict[str, AbstractTestDataGenerator] = {}

    def grpc_port(self) -> int:
        return self._grpc_port

    def grpc_channel(self) -> grpc.Channel:
        return self._grpc_channel

    def capabilities_grpc_client(self, version):
        return self._capabilities_service[version]

    def capabilities_pb2(self, version):
        return self._capabilities_pb2[version]

    def fileobject_grpc_client(self, version):
        return self._fileobject_service[version]

    def fileobject_common_pb2(self, version):
        return self._fileobject_pb2[version]

    def fileobject_pb2(self, version):
        return self._fileobject_service_pb2[version]

    def filefolder_grpc_client(self, version):
        return self._filefolder_service[version]

    def filefolder_pb2(self, version):
        return self._filefolder_service_pb2[version]

    def versioning_grpc_client(self, version):
        return self._versioning_service[version]

    def versioning_pb2(self, version):
        return self._versioning_pb2[version]

    def metadata_grpc_client(self, version):
        return self._metadata_service[version]

    def metadata_pb2(self, version):
        return self._metadata_pb2[version]

    def speaks_protocol(self, protocol: str) -> bool:
        if protocol.lower() == "rest":
            return self._rest_endpoint is not None and self._rest_endpoint.lower() not in ["", "off"]
        elif protocol.lower() == "grpc":
            # TODO Currently assuming you always at least implement GRPC
            return True
        else:
            raise Exception(f"unknown protocol: {protocol}")

    def rest_base_url(self) -> str:
        return self._rest_endpoint

    def openapi_urls(self) -> List[str]:
        return [
            f"{self._rest_endpoint}/v1alpha/capabilities/openapi.json",
            f"{self._rest_endpoint}/v1beta/capabilities/openapi.json",
            f"{self._rest_endpoint}/v1alpha/fileobject/openapi.json",
            f"{self._rest_endpoint}/v1beta/fileobject/openapi.json",
            f"{self._rest_endpoint}/v1alpha/filefolder/openapi.json",
            f"{self._rest_endpoint}/v1beta/filefolder/openapi.json",
            f"{self._rest_endpoint}/v1alpha/versioning/openapi.json",
            f"{self._rest_endpoint}/v1beta/versioning/openapi.json",
        ]

    def create_namespace(self, name, generator: Optional[AbstractTestDataGenerator] = None):
        if generator is None:
            namespace = self._testdata_generator.create_namespace(name)
            self._additional_testdata_generators[name] = self._testdata_generator
        else:
            namespace = generator.create_namespace(name)
            self._additional_testdata_generators[name] = generator
        return namespace

    def generator(self, name=None) -> AbstractTestDataGenerator:
        if name is None:
            return self._testdata_generator
        else:
            return self._additional_testdata_generators[name]

    def rest_client(self) -> RestClient:
        if not self.speaks_protocol("REST"):
            raise Exception(
                "Rest endpoint is not defined, test should not run and needs a protocol guard in front using 'given the service speaks...'"
            )
        return RestClient(self.rest_base_url())
