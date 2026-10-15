# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import random
import threading
from abc import (
    ABC,
    abstractmethod,
)
from typing import (
    Optional,
)

# Thread-local storage for Random instances to ensure thread-safety
_thread_local = threading.local()


class AbstractTestDataGenerator(ABC):
    """
    This abstract class needs to be implemented for a specific Storage Service.

    Its role is to provide the test fixtures with the capability required to create test data and inspect and modify
    it as needed by the individual test steps.
    """

    @abstractmethod
    def create_namespace(self, namespace) -> str: ...

    """
    Given a human readable name of a namespace, return a top level resource address which is used to address this namespace.
    
    The resulting namespace_path will be stored in a table and used in calls to the other functions.
    It is expected the returned address is enumerable by Enumerate().
    """

    @abstractmethod
    def make_resource_address(self, namespace_path, sub_address) -> str: ...

    """
    Given a namespace path created by a prior call to create_space, return a full resource address given a sub_address. 
    """

    @abstractmethod
    def make_invalid_resource_address(self) -> str: ...

    """
    Create a resource address that is guaranteed to be invalid for the storage under test.
    """

    @abstractmethod
    def make_invalid_resource_identity(self) -> str: ...

    """
    Create a resource identity that is guaranteed to be invalid for the storage under test.
    """

    @abstractmethod
    def make_enumerable_resource_address(self, namespace_path, object_name) -> str: ...

    """
    Given a namespace path and an object name, create an enumerable sub resource address if possible on that storage.
    """

    @abstractmethod
    def get_non_empty_root_address(self) -> str: ...

    """
    Returns a resource address pointing at a root/top level address for that storage service which contains some data
    """

    @abstractmethod
    def delete_if_exists(self, resource_address: str): ...

    """
    Delete the data object addressed by the given resource_address.
    """

    @abstractmethod
    def obliterate(self, resource_address: str): ...

    """
    Delete the data object addressed by the given resource_address and all its versions, invalidating resource identities referencing these objects
    """

    @abstractmethod
    def create_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None): ...

    """
    Given a resource_address and a size in bytes, create an object of that size in bytes. This object will only have one version.
    
    If additionally a random seed is given, make sure to create a file that is re-creatable with the same seed at a later
    point in time.
    """

    @abstractmethod
    def add_version_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None): ...

    """
    Given a resource_address and a size in bytes, add a version to an object of that size in bytes.

    If additionally a random seed is given, make sure to create a file that is re-creatable with the same seed at a later
    point in time.
    """

    @abstractmethod
    def create_object_with_no_read_permission(self, resource_address: str): ...

    """
    Given the resource address create an object which will cause a permission error when accessed.
    """

    @abstractmethod
    def remove_read_permission_via_identity(self, resource_identity: str): ...

    """
    Given a resource identity remove read permission on the resource address referenced by the given resource identity.
    """

    @abstractmethod
    def remove_write_permission_via_address(self, resource_address: str): ...

    """
    Remove a write permission for an object given the address.
    """

    @abstractmethod
    def create_folder(self, resource_address: str): ...

    """
    Create a folder at the given resource address.
    """

    @staticmethod
    def generate_random_bytes(size: int, seed=None):
        # Use a thread-local Random instance to ensure thread-safety.
        # The global random module is not thread-safe, and concurrent calls
        # from multiple threads (e.g., pytest-xdist workers or ThreadPoolExecutor)
        # can corrupt the random state, causing unpredictable behavior.
        if not hasattr(_thread_local, "rng"):
            _thread_local.rng = random.Random()

        rng = _thread_local.rng
        if seed is not None:
            rng.seed(seed)
        else:
            rng.seed()
        return rng.randbytes(size)
