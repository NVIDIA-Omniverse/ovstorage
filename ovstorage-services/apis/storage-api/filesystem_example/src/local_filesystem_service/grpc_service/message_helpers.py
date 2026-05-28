# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from google.protobuf.timestamp_pb2 import Timestamp
from local_filesystem_service.filesystem import (
    get_backend,
)


def resource_info(fileobject_version, resource_address: str):
    """Create a ResourceInfo protobuf message for a resource address.

    Constructs a complete ResourceInfo message containing both the resource
    identity (opaque identifier) and metadata (size, modification time) for
    the latest version at the given resource address.

    Args:
        fileobject_version: The fileobject protobuf module (v1alpha or v1beta)
                           containing ResourceInfo and related message types.
        resource_address: Storage API resource address (e.g., 'file-storage://server/path').

    Returns:
        A ResourceInfo protobuf message containing:
        - resource_identity: Opaque encoded identity for the latest version
        - metadata: File size and modification timestamp

    Note:
        This automatically resolves to the latest version of the resource.
    """
    backend = get_backend()
    resource_identity = fileobject_version.ResourceIdentity(
        encoded_identity=backend.create_identity_from_resource_address(resource_address)
    )
    # Use backend's stat method to get metadata
    version_info = backend.stat(resource_address)

    # Convert backend Metadata to protobuf Metadata
    modification_time_epoch = version_info.metadata.last_modified_timestamp.timestamp()
    modification_time_seconds = int(modification_time_epoch)
    nanos = int((modification_time_epoch - modification_time_seconds) * 1000000000)
    timestamp = Timestamp(seconds=modification_time_seconds, nanos=nanos)
    metadata = fileobject_version.Metadata(data_object_size=version_info.metadata.data_object_size, last_modified_timestamp=timestamp)

    return fileobject_version.ResourceInfo(resource_identity=resource_identity, metadata=metadata)
