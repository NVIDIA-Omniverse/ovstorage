# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Implementing a provider that serves the local filesystem."""
import base64
import glob
import hashlib
import json
import logging
import os
import pathlib
import platform
import random
import re
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from datetime import (
    datetime,
    timezone,
)
from enum import Enum
from json import JSONDecodeError
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generator,
    List,
    Optional,
    Tuple,
)

from filelock import FileLock

if TYPE_CHECKING:
    from fastapi import FastAPI

from urllib.parse import urlparse

from local_filesystem_service.backends.storage_backend_interface import (
    EtagMismatchError,
    FolderMode,
    ListEntry,
    Metadata,
    MetadataKeyNotFoundError,
    OptimisticLockingSupport,
    RedirectUploadResult,
    StorageBackendInterface,
    VersionInfo,
    VersionsOrder,
)

VERSION_SUFFIX_PATTERN = re.compile(r".*;[0-9]+$")


class NoVersionFoundException(Exception):
    """Raised when no versions found for a resource address."""

    def __init__(self, resource_address: str):
        self.resource_address = resource_address
        super().__init__(f"No versions found for resource address: {resource_address}")


class FolderSimulationMode(Enum):
    NATIVE = 0
    NO_EMPTY = 1
    PLACEHOLDER_FILE = 2

    def __eq__(self, other):
        return self.value == other.value


class FileSystemProvider(StorageBackendInterface):
    # Example schema to use when creating resource identities, making them routable and connected to this instance
    # of the file system provider when using the same netloc as the base_uri
    IDENTITY_SCHEMA = "file-storage-id"

    def __init__(self, static_dir: str, base_uri: str, test_folder_mode: str) -> None:
        self._base_uri = base_uri
        self._static_dir = static_dir
        if not self._base_uri.endswith("/"):
            self._base_uri += "/"
        self._content_dir = os.path.join(static_dir, "content")
        if test_folder_mode == "native":
            self._test_folder_mode = FolderSimulationMode.NATIVE
        elif test_folder_mode == "no_empty":
            self._test_folder_mode = FolderSimulationMode.NO_EMPTY
        elif test_folder_mode == "hybrid":
            self._test_folder_mode = FolderSimulationMode.PLACEHOLDER_FILE
        else:
            raise ValueError(f"Got invalid value for test_folder_mode: {test_folder_mode}, use one of 'native', 'no_empty', 'hybrid'")
        os.makedirs(FileSystemProvider._to_extended_path(self._content_dir), exist_ok=True)
        self._versions_dir = os.path.join(static_dir, "versions")
        os.makedirs(FileSystemProvider._to_extended_path(self._versions_dir), exist_ok=True)
        self._metadata_dir = os.path.join(static_dir, "metadata")
        os.makedirs(FileSystemProvider._to_extended_path(self._metadata_dir), exist_ok=True)
        self._uploads_dir = os.path.join(static_dir, "uploads")
        os.makedirs(FileSystemProvider._to_extended_path(self._uploads_dir), exist_ok=True)
        # Lock for thread-safe version creation
        self._version_lock = threading.Lock()
        # Check if we can set permissions and remember that
        try:
            testpath = pathlib.Path(self._versions_dir) / f"test_permissions.{''.join(random.choices(string.ascii_lowercase, k=6))}"
            self._test_if_open_for_write_denied(testpath)
            self._respects_permissions = True
        except AssertionError:
            # That didn't work, need to remember this
            self._respects_permissions = False

    @property
    def base_uri(self) -> str:
        """Base URI for this storage backend instance."""
        return self._base_uri

    def folder_mode(self) -> FolderMode:
        """Get the folder mode for this storage backend.

        Maps the internal FolderSimulationMode to the interface's FolderMode.

        Returns:
            FolderMode enum from the interface.
        """
        if self._test_folder_mode == FolderSimulationMode.NATIVE:
            return FolderMode.NATIVE
        elif self._test_folder_mode == FolderSimulationMode.NO_EMPTY:
            return FolderMode.NO_EMPTY
        elif self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE:
            return FolderMode.HYBRID
        else:
            raise ValueError(f"Unknown folder simulation mode: {self._test_folder_mode}")

    def does_respect_permissions(self):
        # Return whether the constructor tested succesfully that this FileSystemProvider respects file permissions
        # If not, set_permissions doesn't make much sense. This can happen when run as root, or in a container.
        return self._respects_permissions

    def get_optimistic_locking_support(self) -> OptimisticLockingSupport:
        """FileSystemProvider supports optimistic locking for all operations."""
        return OptimisticLockingSupport(write=True, delete=True, copy=True, move=True)

    def check_read_permission_on_address(self, resource_address: str) -> bool:
        path = self.force_relative_path(resource_address)
        if self._is_versioned_address(resource_address):
            # Check permissions in versions directory for versioned addresses
            return FileSystemProvider.check_read_permission(FileSystemProvider._to_extended_path(os.path.join(self._versions_dir, path)))
        else:
            # Check permissions in content directory for regular addresses
            return FileSystemProvider.check_read_permission(FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path)))

    @staticmethod
    def check_read_permission(path: str) -> bool:
        """Test if the path can actually be read from."""
        if platform.system() == "Windows":
            # No easy way to check, fall through to read attempt
            pass
        else:
            # Check the read bit via stat
            if not FileSystemProvider._can_user_read(path):
                raise PermissionError
        with open(path, "rb") as f:
            if not f.readable():
                raise PermissionError
            else:
                # Try to provode another PermissionError by reading the first 10 bytes
                f.readline(10)
        return True

    def exists(self, resource_address: str) -> bool:
        if self._is_versioned_address(resource_address):
            return self._versioned_exists(resource_address)
        else:
            path = self.force_relative_path(resource_address)
            full_path = FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path))
            if self._test_folder_mode == FolderSimulationMode.NATIVE:
                return os.path.exists(full_path)
            else:
                if os.path.exists(full_path) and os.path.isdir(full_path):
                    # Special case - we report existence of non-native folders only if the directory is non-empty
                    return len(os.listdir(full_path)) > 0
                else:
                    return os.path.exists(full_path)

    def _is_versioned_address(self, resource_address: str) -> bool:
        """Check if the resource address has a version suffix (;version_number)."""
        # Parse the URI to extract only the path component
        parsed_address = urllib.parse.urlparse(resource_address)
        path = parsed_address.path
        return VERSION_SUFFIX_PATTERN.match(path) is not None

    def _versioned_exists(self, resource_address: str) -> bool:
        """Check if a versioned address exists in the "versions" directory."""
        if not self._is_versioned_address(resource_address):
            raise ValueError(f"{resource_address} is not a versioned address, but handed into _versioned_exists")
        path = self.force_relative_path(resource_address)
        return os.path.exists(FileSystemProvider._to_extended_path(os.path.join(self._versions_dir, path)))

    def _version_path_exists(self, path: str) -> bool:
        return os.path.exists(FileSystemProvider._to_extended_path(os.path.join(self._versions_dir, path)))

    def is_file(self, resource_address: str) -> bool:
        if self._is_versioned_address(resource_address):
            path = self.force_relative_path(resource_address)
            return self._versioned_exists(resource_address) and os.path.isfile(
                FileSystemProvider._to_extended_path(os.path.join(self._versions_dir, path))
            )
        else:
            path = self.force_relative_path(resource_address)
            return self.exists(resource_address) and os.path.isfile(
                FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path))
            )

    def is_dir(self, resource_address: str) -> bool:
        path = self.force_relative_path(resource_address)
        return self.exists(resource_address) and os.path.isdir(FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path)))

    def create_folder(self, resource_address: str) -> None:
        path = self.force_relative_path(resource_address)
        full_path = os.path.join(self._content_dir, path)
        extended_full_path = FileSystemProvider._to_extended_path(full_path)

        # Check if a file exists at this path
        if os.path.exists(extended_full_path) and os.path.isfile(extended_full_path):
            raise FileExistsError("A file exists at the requested folder path")

        # In no_empty mode, do not bother to create the folder. Uploads will do that as a side effect
        if self._test_folder_mode == FolderSimulationMode.NO_EMPTY:
            return

        # Create the folder (and parents if needed)
        pathlib.Path(extended_full_path).mkdir(parents=True, exist_ok=True)

        # If in PLACEHOLDER mode, create the .folder file that keeps the folder alive
        if self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE:
            placeholder = FileSystemProvider._to_extended_path(os.path.join(full_path, ".folder"))
            if not os.path.exists(placeholder):
                with open(placeholder, "wt"):
                    pass
                assert os.path.exists(placeholder)

    def create_identity_from_resource_address(self, resource_address: str) -> str:
        """Create an identity from a resource_address."""
        if self._is_versioned_address(resource_address):
            # If the address is already versioned, use it directly
            path = self.force_relative_path(resource_address)
            version_path = os.path.join(self._versions_dir, path)
            return self.create_identity_from_version_path(version_path)
        else:
            # For non-versioned addresses, find the latest version
            if self.is_dir(resource_address):
                raise ValueError("Program error: Cannot create identity for a folder: {resource_address}")
            return self.create_identity_from_version_path(self._latest_version_path(resource_address))

    @staticmethod
    def string_to_base64(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode()).decode()

    @staticmethod
    def base64_to_string(value: str) -> str:
        return base64.urlsafe_b64decode(value).decode()

    def _wrap_identity_in_url(self, identity: str) -> str:
        parsed = urllib.parse.urlparse(self._base_uri)
        return f"{FileSystemProvider.IDENTITY_SCHEMA}://{parsed.netloc}/{identity}"

    def create_identity_from_version_path(self, path: str) -> str:
        identity = FileSystemProvider.string_to_base64(json.dumps({"path": os.path.normpath(path)}))
        return self._wrap_identity_in_url(identity)

    @staticmethod
    def _identity_and_netloc_from_identity(resource_identity: str) -> Tuple[str, str]:
        parsed = urlparse(resource_identity)
        if parsed.scheme != FileSystemProvider.IDENTITY_SCHEMA:
            raise ValueError(f"Invalid resource identity, expected schema '{FileSystemProvider.IDENTITY_SCHEMA}': {resource_identity}")
        path = parsed.path
        if path.startswith("/"):
            path = path[1:]
        return path, parsed.netloc

    def address_from_identity(self, resource_identity: str) -> str:
        identity, netloc = FileSystemProvider._identity_and_netloc_from_identity(resource_identity)
        parsed_base = urllib.parse.urlparse(self._base_uri)
        if netloc != parsed_base.netloc:
            raise ValueError(
                f"Invalid resource identity, netloc is different from configured base URI '{self._base_uri}': {resource_identity}"
            )
        decoded = FileSystemProvider.base64_to_string(identity)
        json_identity = json.loads(decoded)
        full_path = json_identity["path"]
        rel_path = os.path.relpath(full_path, self._versions_dir)
        # Drop everything after the last semicolon
        parts = rel_path.split(";")[:-1]
        return self._base_uri + ";".join(parts)

    def url_from_identity(self, resource_identity: str) -> str:
        """Convert a resource identity to the full URL including version.

        Unlike address_from_identity(), this preserves the version suffix
        in the URL, which is needed for operations on specific versions (like copy).
        """
        identity, netloc = FileSystemProvider._identity_and_netloc_from_identity(resource_identity)
        parsed_base = urllib.parse.urlparse(self._base_uri)
        if netloc != parsed_base.netloc:
            raise ValueError(
                f"Invalid resource identity, netloc is different from configured base URI '{self._base_uri}': {resource_identity}"
            )
        decoded = FileSystemProvider.base64_to_string(identity)
        json_identity = json.loads(decoded)
        full_path = json_identity["path"]

        # Determine if path is in versions_dir or content_dir and compute relative path accordingly
        norm_full_path = os.path.normpath(full_path)
        norm_versions_dir = os.path.normpath(self._versions_dir)
        norm_content_dir = os.path.normpath(self._content_dir)

        if norm_full_path.startswith(norm_versions_dir + os.sep) or norm_full_path == norm_versions_dir:
            rel_path = os.path.relpath(full_path, self._versions_dir)
        elif norm_full_path.startswith(norm_content_dir + os.sep) or norm_full_path == norm_content_dir:
            rel_path = os.path.relpath(full_path, self._content_dir)
        else:
            # Fallback - shouldn't happen in normal usage
            rel_path = os.path.relpath(full_path, self._versions_dir)

        # Keep the version suffix (unlike address_from_identity which strips it)
        return self._base_uri + rel_path

    def create_identity_from_path(self, path: str) -> str:
        """Create an identity from a path."""
        if os.path.isdir(path):
            raise ValueError(f"Cannot create Identity for folder: {path}")
        identity = FileSystemProvider.string_to_base64(json.dumps({"path": os.path.normpath(path)}))
        return self._wrap_identity_in_url(identity)

    @staticmethod
    def get_path_from_identity(resource_identity: str) -> str:
        """Convert identity back to a path."""
        identity, realm = FileSystemProvider._identity_and_netloc_from_identity(resource_identity)
        decoded = FileSystemProvider.base64_to_string(identity)
        return json.loads(decoded)["path"]

    def get_full_path_from_address(self, resource_address: str) -> str:
        """Convert resource address to full file system path."""
        relative_path = self.force_relative_path(resource_address)
        if self._is_versioned_address(resource_address):
            return os.path.join(self._versions_dir, relative_path)
        else:
            return os.path.join(self._content_dir, relative_path)

    def enumerate(self, resource_address: str, start_index: int = 0, limit: Optional[int] = None) -> Generator[List[ListEntry], None, None]:
        """Enumerate is a recursive list with optional pagination support.

        Args:
            resource_address: The resource address to enumerate
            start_index: Index to start from (for pagination)
            limit: Maximum number of items to return (for early termination)
        """
        path = self.force_relative_path(resource_address)
        current_index = 0
        items_yielded = 0

        for root, dirs, files in os.walk(FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path))):
            # Strip extended path prefix from root for consistent path operations
            # os.walk returns extended paths when given extended input on Windows
            normalized_root = FileSystemProvider._strip_extended_prefix(root)

            entries: List[ListEntry] = []
            # Skip directories - enumerate only returns files per interface spec

            for name in files:
                if self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE and name == ".folder":
                    # Suppress outputting the magic file
                    continue

                # Check if we should process this item
                if current_index < start_index:
                    current_index += 1
                    continue
                if limit is not None and items_yielded >= limit:
                    if entries:
                        yield entries
                    return

                full_path = os.path.join(normalized_root, name)
                sub_address = os.path.relpath(full_path, self._content_dir)
                resource_address = self._base_uri + sub_address
                try:
                    stat_result = os.stat(FileSystemProvider._to_extended_path(full_path))
                    metadata = Metadata(
                        data_object_size=stat_result.st_size,
                        last_modified_timestamp=datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc),
                    )
                    entries.append(ListEntry(resource_address=resource_address, metadata=metadata))
                    current_index += 1
                    items_yielded += 1
                except (OSError, PermissionError):
                    # Skip files we can't stat
                    pass

            if entries:
                yield entries

    def _new_version_path(self, resource_address: str) -> str:
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot create new version for folder path: {resource_address}")
        all_versions, _ = self.enumerate_versions(resource_address)
        if len(all_versions) == 0:
            path = self.force_relative_path(resource_address)
            return os.path.join(self._versions_dir, path + ";0")
        # Parse out the version numbers, convert to int
        max_version = max(
            (
                int(v.sorting_key)
                if v.sorting_key is not None
                else int(FileSystemProvider.get_path_from_identity(v.resource_identity).split(";")[-1])
            )
            for v in all_versions
        )
        path = self.force_relative_path(resource_address)
        return os.path.join(self._versions_dir, path + ";" + str(max_version + 1))

    def _latest_version_path(self, resource_address: str) -> str:
        all_versions, _ = self.enumerate_versions(resource_address)
        if len(all_versions) == 0:
            raise NoVersionFoundException(resource_address)
        # Parse out the max version numbers, convert to int
        max_version = max(
            (
                int(v.sorting_key)
                if v.sorting_key is not None
                else int(FileSystemProvider.get_path_from_identity(v.resource_identity).split(";")[-1])
            )
            for v in all_versions
        )
        path = self.force_relative_path(resource_address)
        return os.path.join(self._versions_dir, path + ";" + str(max_version))

    def enumerate_versions(
        self, resource_address: str, start_index: int = 0, limit: Optional[int] = None
    ) -> Tuple[List[VersionInfo], VersionsOrder]:
        """
        Enumerate the versions of a file. Those are stored with ';<version>' suffix.

        Args:
            resource_address: The resource address to enumerate versions for
            start_index: Index to start from (for pagination)
            limit: Maximum number of versions to return

        Returns:
            Tuple[List[VersionInfo], VersionsOrder]:
                A tuple containing:
                - A list of VersionInfo objects representing each file version.
                - An enum representing the version ordering.
        """
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot enumerate versions of folder {resource_address}")
        path = self.force_relative_path(resource_address)
        versions = glob.glob(FileSystemProvider._to_extended_path(f"{os.path.join(self._versions_dir, path)}*"))

        # Strip extended path prefix from paths returned by glob
        # glob returns extended paths when given extended path input on Windows
        normalized_versions = [FileSystemProvider._strip_extended_prefix(v) for v in versions]

        # Filter to only versioned paths
        versioned_paths = [v for v in normalized_versions if VERSION_SUFFIX_PATTERN.match(v)]

        # Apply pagination
        end_index = start_index + limit if limit is not None else len(versioned_paths)
        paged_paths = versioned_paths[start_index:end_index]

        # Only process versions in the current page
        entries = []
        for version_path in paged_paths:
            version_number = int(version_path.split(";")[-1])
            stat_result = os.stat(FileSystemProvider._to_extended_path(version_path))
            resource_identity = self.create_identity_from_version_path(version_path)
            # Create version-specific resource address
            version_resource_address = f"{resource_address};{version_number}"

            entries.append(
                VersionInfo(
                    resource_identity=resource_identity,
                    metadata=Metadata(
                        data_object_size=stat_result.st_size,
                        last_modified_timestamp=datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc),
                    ),
                    sorting_key=f"{version_number:010d}",
                    resource_address=version_resource_address,
                )
            )
        return (
            entries,
            VersionsOrder.BY_KEY,
        )

    def stat(self, resource_address: str) -> VersionInfo:
        """Stat just checks a single file.

        For non-versioned addresses, returns the metadata of the latest version
        with the identity pointing to the versioned file in _versions_dir.
        This ensures the identity matches what write_version returns, which is
        required for optimistic locking to work correctly.
        """
        path = self.force_relative_path(resource_address)
        if self._is_versioned_address(resource_address):
            # For versioned addresses, look in the versions directory
            full_path = os.path.join(self._versions_dir, path)
            return self._stat(FileSystemProvider._to_extended_path(full_path))
        else:
            # For regular addresses, get metadata from content directory but
            # return identity from the latest version in versions directory
            content_path = os.path.join(self._content_dir, path)
            extended_content_path = FileSystemProvider._to_extended_path(content_path)

            if not os.path.exists(extended_content_path):
                raise FileNotFoundError(f"Resource not found: {resource_address}")
            if os.path.isdir(extended_content_path):
                raise IsADirectoryError(f"{resource_address} is a directory")

            FileSystemProvider.check_read_permission(extended_content_path)
            size = os.path.getsize(extended_content_path)
            modification_time = os.path.getmtime(extended_content_path)
            modification_dt = datetime.fromtimestamp(modification_time, tz=timezone.utc)

            # Get the identity from the latest version in _versions_dir
            try:
                latest_version_path = self._latest_version_path(resource_address)
                resource_identity = self.create_identity_from_version_path(latest_version_path)
            except NoVersionFoundException:
                # No versions exist yet - this shouldn't happen for a file that exists
                # Fall back to creating identity from content path
                resource_identity = self.create_identity_from_path(content_path)

            return VersionInfo(
                resource_identity=resource_identity,
                metadata=Metadata(data_object_size=size, last_modified_timestamp=modification_dt),
            )

    def stat_identity(self, resource_identity: str) -> VersionInfo:
        """Get metadata for a specific version by its identity.

        Unlike stat(), this method takes a resource_identity and returns metadata
        even if the address was deleted.
        """
        try:
            identity_path = FileSystemProvider.get_path_from_identity(resource_identity)
            return self._stat(identity_path)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid resource identity: {resource_identity}") from e

    def _stat(self, full_path: str) -> VersionInfo:
        """Stat just checks a single file."""
        extended_path = FileSystemProvider._to_extended_path(full_path)
        if os.path.exists(extended_path):
            if not os.path.isdir(extended_path):
                FileSystemProvider.check_read_permission(extended_path)
                size = os.path.getsize(extended_path)
                modification_time = os.path.getmtime(extended_path)
                modification_dt = datetime.fromtimestamp(modification_time, tz=timezone.utc)
                return VersionInfo(
                    resource_identity=self.create_identity_from_path(full_path),
                    metadata=Metadata(data_object_size=size, last_modified_timestamp=modification_dt),
                )
            else:
                raise IsADirectoryError(f"{full_path} is a directory")
        else:
            raise FileNotFoundError(f"Resource not found: {full_path}")

    def list_stat(self, resource_address: str, start_index: int = 0, limit: Optional[int] = None) -> tuple[list[str], list[ListEntry]]:
        """List files and directories in the specified resource address (non-recursively) with pagination support.

        Args:
            resource_address: The resource address to list
            start_index: Index to start from (for pagination)
            limit: Maximum number of items to return
        """
        path = self.force_relative_path(resource_address)
        full_path = os.path.join(self._content_dir, path)
        extended_full_path = FileSystemProvider._to_extended_path(full_path)

        # Get all directory entries first (we need to separate folders/files)
        all_entries = os.listdir(extended_full_path)
        folders = []
        files = []

        for name in all_entries:
            entry_path = os.path.join(full_path, name)
            extended_entry_path = FileSystemProvider._to_extended_path(entry_path)
            if os.path.isdir(extended_entry_path):
                folders.append(name)
            elif os.path.isfile(extended_entry_path):
                if self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE and name == ".folder":
                    continue
                files.append((name, entry_path))

        # Combine folders and files into single list with type tags for pagination
        all_items = [(name, True, None) for name in folders] + [(name, False, path) for name, path in files]

        # Apply pagination to unified list
        end_index = start_index + limit if limit is not None else len(all_items)
        paged_items = all_items[start_index:end_index]

        # Split back into folders and files
        paged_folders = [name for name, is_folder, _ in paged_items if is_folder]
        paged_file_items = [(name, entry_path) for name, is_folder, entry_path in paged_items if not is_folder]

        # Only stat files that are in the result page
        file_metadata = []
        for _, paged_entry_path in paged_file_items:
            try:
                if not paged_entry_path:
                    # Skip empty entry for mypy
                    continue
                extended_paged_entry_path = FileSystemProvider._to_extended_path(paged_entry_path)
                FileSystemProvider.check_read_permission(extended_paged_entry_path)
                size = os.path.getsize(extended_paged_entry_path)
                modification_time = os.path.getmtime(extended_paged_entry_path)
                modification_dt = datetime.fromtimestamp(modification_time, tz=timezone.utc)
                rel_path = os.path.relpath(paged_entry_path, full_path)
                file_metadata.append(
                    ListEntry(
                        resource_address=rel_path,
                        resource_identity=self.create_identity_from_path(paged_entry_path),
                        metadata=Metadata(
                            data_object_size=size,
                            last_modified_timestamp=modification_dt,
                        ),
                    )
                )
            except (PermissionError, OSError):
                # Skip files we can't read
                pass

        return paged_folders, file_metadata

    def list(self, resource_address: str) -> Tuple[List[str], List[str]]:
        """List immediate children of a folder, returning (subfolders, files)."""
        return self.list_(resource_address)

    def list_(self, resource_address: str):
        path = self.force_relative_path(resource_address)
        full_path = os.path.join(self._content_dir, path)
        extended_full_path = FileSystemProvider._to_extended_path(full_path)
        folders = []
        files = []

        if not os.path.exists(extended_full_path):
            raise FileNotFoundError(f"Resource address {resource_address} not found")

        for name in os.listdir(extended_full_path):
            sub_path = os.path.join(full_path, name)
            extended_sub_path = FileSystemProvider._to_extended_path(sub_path)
            if os.path.isdir(extended_sub_path):
                folders.append(name)
            elif os.path.isfile(extended_sub_path):
                if self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE and name == ".folder":
                    # Suppress outputting the magic file
                    continue
                files.append(name)

        return folders, files

    @staticmethod
    def read(identity_path: str) -> Generator[bytes, None, None]:
        """Read a file."""
        extended_path = FileSystemProvider._to_extended_path(identity_path)
        if os.path.exists(extended_path):
            with open(extended_path, "rb") as f:
                while chunk := f.read(1024):
                    yield chunk
        else:
            raise FileNotFoundError(f"Resource not found: {identity_path}")

    def read_from_address(self, resource_address: str) -> Generator[bytes, None, None]:
        """Read a file."""
        path = self.force_relative_path(resource_address)

        if self._is_versioned_address(resource_address):
            # Read from versions directory for versioned addresses
            full_path = os.path.join(self._versions_dir, path)
        elif self.is_dir(resource_address):
            raise ValueError("Cannot read from folder address: {resource_address}")
        else:
            # Read from content directory for regular addresses
            full_path = os.path.join(self._content_dir, path)

        extended_full_path = FileSystemProvider._to_extended_path(full_path)
        if os.path.exists(extended_full_path):
            with open(extended_full_path, "rb") as f:
                while chunk := f.read(1024):
                    yield chunk
        else:
            raise FileNotFoundError(f"Resource not found: {resource_address}")

    def read_from_identity(self, resource_identity: str) -> Generator[bytes, None, None]:
        """Read file content from a specific version by its identity."""
        try:
            identity_path = FileSystemProvider.get_path_from_identity(resource_identity)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid resource identity: {resource_identity}") from e

        # Use the static read method with the decoded path
        yield from FileSystemProvider.read(identity_path)

    def write_version(self, resource_address: str, content: bytes, previous_version: Optional[str] = None) -> str:
        # First write the latest file
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot write to folder addresses: {resource_address}")

        # Check optimistic concurrency control if previous_version is provided
        if previous_version is not None:
            try:
                current_latest_path = self._latest_version_path(resource_address)
                specified_latest_path = FileSystemProvider.get_path_from_identity(previous_version)
                if not FileSystemProvider.paths_eq(current_latest_path, specified_latest_path):
                    raise EtagMismatchError(
                        key=resource_address,
                        expected_etag=previous_version,
                        actual_etag=self.create_identity_from_version_path(current_latest_path),
                    )
            except NoVersionFoundException:
                # If no version exists and previous_version was provided, that's a mismatch
                raise EtagMismatchError(key=resource_address, expected_etag=previous_version, actual_etag="<no version exists>")

        path = self.force_relative_path(resource_address)
        latest_version_path = os.path.join(self._content_dir, path)
        if latest_version_path.endswith("/"):
            latest_version_path = latest_version_path[:-1]
        extended_latest_version_path = FileSystemProvider._to_extended_path(latest_version_path)

        # Write content to a unique temp file first to avoid race conditions
        # between multiple processes (pytest-xdist workers)
        pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(latest_version_path))).mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(extended_latest_version_path))
        try:
            os.write(temp_fd, content)
            os.close(temp_fd)

            # Use cross-process file locking to ensure only one process at a time
            # can determine the next version number and create the version file.
            # This prevents ghost writes when multiple pytest-xdist workers write concurrently.
            # Using filelock for cross-platform compatibility (Unix and Windows).
            lock_file_path = os.path.join(self._versions_dir, ".write_lock")
            pathlib.Path(os.path.dirname(lock_file_path)).mkdir(parents=True, exist_ok=True)

            with FileLock(lock_file_path):
                # Update the "latest" file
                shutil.copy(temp_path, extended_latest_version_path)

                # Get the next version path within the critical section
                version_path = self._new_version_path(resource_address)
                extended_version_path = FileSystemProvider._to_extended_path(version_path)
                pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(version_path))).mkdir(parents=True, exist_ok=True)
                shutil.copy(temp_path, extended_version_path)
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

        # Return the resource identity, not the relative path
        return self.create_identity_from_version_path(version_path)

    @staticmethod
    def _can_user_read(path):
        stat_result = os.stat(path)
        mode_string = stat.filemode(stat_result.st_mode)
        return "r" in mode_string

    @staticmethod
    def _test_if_open_for_write_denied(test_path: pathlib.Path):
        if sys.platform == "linux":
            import errno
            import stat

            # Make the file exist and remove all perms
            try:
                if not test_path.exists():
                    test_path.touch()
                os.chmod(test_path, 0o000)

                # Verify mode really is 000 (defense against umask / weird fs)
                st = test_path.stat()
                if stat.S_IMODE(st.st_mode) != 0:
                    raise AssertionError(f"chmod ineffective; mode is {oct(stat.S_IMODE(st.st_mode))}")

                # Now assert open-for-write fails
                try:
                    with open(test_path, "wb") as f:
                        f.write(b"x")  # if this works, we'll fail below
                    raise AssertionError(f"open('wb') unexpectedly succeeded (permissions not enforced)")
                except OSError as e:
                    if e.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                        raise AssertionError(f"open failed with unexpected errno {e.errno}: {e}") from e
            finally:
                if test_path.exists():
                    test_path.unlink()

    def set_permission(self, resource_address: str, can_read: bool):
        # First write the latest file
        path = self.force_relative_path(resource_address)
        latest_version_path = os.path.join(self._content_dir, path)
        extended_latest_version_path = FileSystemProvider._to_extended_path(latest_version_path)
        if not os.path.exists(extended_latest_version_path):
            raise Exception("Can't set permissions on a non-existent object")
        if platform.system() == "Windows":
            if can_read:
                # Reset file permissions to be those inherited from the folder
                subprocess.check_output(["icacls.exe", extended_latest_version_path, "/inheritance:e"], stderr=subprocess.STDOUT)
            else:
                # Remove the synchronization bit, disallowing reads on Windows
                user = os.environ.get("USERNAME")
                subprocess.check_output(["icacls.exe", extended_latest_version_path, "/deny", f"{user}:(S)"], stderr=subprocess.STDOUT)
        else:
            if can_read:
                # Set Read and Write bits
                subprocess.check_output(["chmod", "a+rw", extended_latest_version_path], stderr=subprocess.STDOUT)
            else:
                # Clear Read and Write bits
                subprocess.check_output(["chmod", "a-rw", extended_latest_version_path], stderr=subprocess.STDOUT)

    def copy(self, source_resource_address: str, destination_resource_address: str) -> str:
        """Copy a resource to a new address.

        Creates a new version at the destination address.
        """
        if self.is_dir(source_resource_address):
            raise ValueError("Cannot copy folder addresses")
        if not self.exists(source_resource_address):
            raise FileNotFoundError(f"Source resource not found: {source_resource_address}")

        # Get the source path from the address
        source_path = self.get_full_path_from_address(source_resource_address)

        # Read the content from source
        with FileSystemProvider.safe_open(source_path, "rb") as f:
            content = f.read()

        # Write to destination, creating a new version
        return self.write_version(destination_resource_address, content)

    def copy_and_create_version(self, source_path: str, resource_address: str) -> str:
        """Internal helper: Copy from a filesystem path to a resource address."""
        # First copy the source to the destination "latest"
        path = self.force_relative_path(resource_address)
        latest_version_path = os.path.join(self._content_dir, path)
        extended_latest_version_path = FileSystemProvider._to_extended_path(latest_version_path)
        extended_source_path = FileSystemProvider._to_extended_path(source_path)
        pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(latest_version_path))).mkdir(parents=True, exist_ok=True)

        # Use cross-process file locking to ensure only one process at a time
        # can determine the next version number and create the version file.
        # This prevents ghost writes when multiple pytest-xdist workers write concurrently.
        # Using filelock for cross-platform compatibility (Unix and Windows).
        lock_file_path = os.path.join(self._versions_dir, ".write_lock")
        pathlib.Path(os.path.dirname(lock_file_path)).mkdir(parents=True, exist_ok=True)

        with FileLock(lock_file_path):
            shutil.copy(extended_source_path, extended_latest_version_path)

            # Get the next version path within the critical section
            version_path = self._new_version_path(resource_address)
            extended_version_path = FileSystemProvider._to_extended_path(version_path)
            pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(version_path))).mkdir(parents=True, exist_ok=True)
            shutil.copy(extended_latest_version_path, extended_version_path)

        return version_path

    def remove_by_address(self, resource_address: str) -> None:
        # Only delete the current version, old versions still stay
        path = self.force_relative_path(resource_address)
        FileSystemProvider.remove_file_if_exists(
            FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path)), self._content_dir
        )

    def obliterate(self, resource_address: str) -> None:
        versions, _ = self.enumerate_versions(resource_address)
        for version in versions:
            version_path = FileSystemProvider.get_path_from_identity(version.resource_identity)
            FileSystemProvider.remove_file_if_exists(FileSystemProvider._to_extended_path(version_path), self._versions_dir)
        path = self.force_relative_path(resource_address)
        FileSystemProvider.remove_file_if_exists(
            FileSystemProvider._to_extended_path(os.path.join(self._content_dir, path)), self._content_dir
        )

    def move(self, source_resource_address: str, destination_resource_address: str) -> str:
        """Move/rename a resource to a new address.

        Creates a new version at the destination and removes the source.
        """
        if self.is_dir(source_resource_address):
            raise ValueError("Cannot move folder addresses")
        if not self.exists(source_resource_address):
            raise FileNotFoundError(f"Source resource not found: {source_resource_address}")

        # If source and destination are the same, this is a no-op
        if source_resource_address == destination_resource_address:
            # Just return the current identity without doing anything
            return self.create_identity_from_resource_address(source_resource_address)

        # Get the source path
        source_path = self.get_full_path_from_address(source_resource_address)

        # Copy to destination
        result_identity = self.copy(source_resource_address, destination_resource_address)

        # Remove source
        self.remove_by_address(source_resource_address)

        return result_identity

    def move_from_path(self, source_path: str, destination_resource_address: str) -> str:
        """Internal helper: Move from a filesystem path to a resource address."""
        destination_path = self.force_relative_path(destination_resource_address)
        destination_full_path = os.path.join(self._content_dir, destination_path)
        if source_path == destination_full_path:
            return source_path

        path = self.force_relative_path(destination_resource_address)
        latest_version_path = os.path.join(self._content_dir, path)
        extended_latest_version_path = FileSystemProvider._to_extended_path(latest_version_path)
        extended_source_path = FileSystemProvider._to_extended_path(source_path)
        pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(latest_version_path))).mkdir(parents=True, exist_ok=True)
        shutil.copy(extended_source_path, extended_latest_version_path)
        version_path = self._new_version_path(destination_resource_address)
        extended_version_path = FileSystemProvider._to_extended_path(version_path)
        pathlib.Path(FileSystemProvider._to_extended_path(os.path.dirname(version_path))).mkdir(parents=True, exist_ok=True)
        shutil.copy(extended_latest_version_path, extended_version_path)
        base_dir = self._versions_dir if VERSION_SUFFIX_PATTERN.match(source_path) else self._content_dir
        FileSystemProvider.remove_file_if_exists(extended_source_path, base_dir)
        return version_path

    def remove_empty_folder(self, resource_address: str) -> bool:
        path = self.force_relative_path(resource_address)
        folder_path = os.path.join(self._content_dir, path)
        extended_folder_path = FileSystemProvider._to_extended_path(folder_path)
        if not os.path.isdir(extended_folder_path):
            return False
        content = os.listdir(extended_folder_path)
        if self._test_folder_mode == FolderSimulationMode.PLACEHOLDER_FILE:
            FileSystemProvider.remove_file_if_exists(
                FileSystemProvider._to_extended_path(os.path.join(folder_path, ".folder")), self._content_dir
            )
        else:
            content = os.listdir(extended_folder_path)
            if len(content) != 0:
                return False
            FileSystemProvider.remove_file_if_exists(extended_folder_path, self._content_dir)
        return True

    @staticmethod
    def remove_file_if_exists(path: str, base_dir: Optional[str] = None):
        try:
            extended_path = FileSystemProvider._to_extended_path(path)
            if os.path.exists(extended_path):
                if base_dir is not None and not FileSystemProvider._is_sub_path(path, base_dir):
                    raise PermissionError(f"Refusing to delete path outside of allowed directory: {path}")
                if os.path.islink(extended_path) or os.path.isfile(extended_path):
                    os.unlink(extended_path)
                elif os.path.isdir(extended_path):
                    for file in os.listdir(extended_path):
                        FileSystemProvider.remove_file_if_exists(os.path.join(path, file), base_dir=base_dir)
                    os.rmdir(extended_path)
                else:
                    raise RuntimeError(f"Unknown file type: {path}")
            if os.path.exists(extended_path):
                raise RuntimeError(f"Failed to delete: {path}")
        except FileNotFoundError:
            pass

    @staticmethod
    def _strip_extended_prefix(path: str) -> str:
        """
        Strip Windows extended-length path prefix if present.

        This is used to normalize paths returned from os.walk() and glob.glob()
        which return extended paths when given extended input on Windows.

        Args:
            path: Path that may have extended prefix

        Returns:
            Path without extended prefix
        """
        # Define prefixes as string literals (each \\ becomes one backslash)
        extended_unc_prefix = "\\\\?\\UNC\\"
        extended_prefix = "\\\\?\\"

        if path.startswith(extended_unc_prefix):
            # \\?\UNC\server\share -> \\server\share
            return "\\\\" + path[len(extended_unc_prefix) :]
        elif path.startswith(extended_prefix):
            # \\?\C:\path -> C:\path
            return path[len(extended_prefix) :]
        else:
            # No prefix to strip
            return path

    @staticmethod
    def _to_extended_path(path: str) -> str:
        """
        Convert a path to Windows extended-length path format if needed.

        On Windows, paths longer than 260 characters can cause errors.
        This function prepends the '\\\\?\\' prefix for absolute paths on Windows
        to enable extended-length paths (up to ~32,767 characters).

        Args:
            path: The path to convert

        Returns:
            Extended-length path on Windows if applicable, original path otherwise
        """
        if platform.system() != "Windows":
            return path

        # Already an extended path
        if path.startswith("\\\\?\\"):
            return path

        # Convert to absolute path first
        abs_path = os.path.abspath(path)

        # UNC paths need special handling
        if abs_path.startswith("\\\\"):
            # UNC path: \\\\server\\share -> \\\\?\\UNC\\server\\share
            return "\\\\?\\UNC\\" + abs_path[2:]
        else:
            # Regular path: C:\\path -> \\\\?\\C:\\path
            return "\\\\?\\" + abs_path

    @staticmethod
    def _normalize_path(path: str) -> str:
        """
        Normalize a path using realpath and strip Windows extended-length prefix.

        On Windows, realpath can return paths with "\\?\" prefix which can cause
        issues with path comparisons. This function strips that prefix and
        normalizes case for consistent comparisons.
        """
        # First strip any existing extended-length prefix before normalization
        stripped_path = path
        if path.startswith("\\\\?\\"):
            if path.startswith("\\\\?\\UNC\\"):
                # \\\\?\\UNC\\server\\share -> \\\\server\\share
                stripped_path = "\\\\" + path[8:]
            else:
                # \\\\?\\C:\\path -> C:\\path
                stripped_path = path[4:]

        # Now normalize the stripped path
        normalized = os.path.realpath(stripped_path)

        # In case realpath added the prefix back, strip it again
        if normalized.startswith("\\\\?\\"):
            if normalized.startswith("\\\\?\\UNC\\"):
                normalized = "\\\\" + normalized[8:]
            else:
                normalized = normalized[4:]

        # Normalize case (on Windows this converts to lowercase, on Unix it's a no-op)
        normalized = os.path.normcase(normalized)
        return normalized

    @staticmethod
    def _is_sub_path(path: str, of_paths: str | List[str]):
        if isinstance(of_paths, str):
            of_paths = [of_paths]
        abs_path = FileSystemProvider._normalize_path(path)
        abs_base_paths = [FileSystemProvider._normalize_path(p) for p in of_paths]

        return any(os.path.commonpath([abs_path, base]) == base for base in abs_base_paths)

    def force_relative_path(self, resource_address: str) -> str:
        parsed_address = urllib.parse.urlparse(resource_address)
        base_address = urllib.parse.urlparse(self._base_uri)
        if parsed_address.scheme != base_address.scheme:
            raise ValueError(f"Unsupported scheme: {parsed_address.scheme}, service is configured for '{base_address.scheme}' scheme")
        if parsed_address.netloc != base_address.netloc:
            raise ValueError(f"Unsupported authority: {parsed_address.netloc}, service is configured for '{base_address.netloc}' authority")
        path = parsed_address.path
        # Check if the path is absolute
        if os.path.isabs(path):
            # Remove drive letter (if present)
            path_without_drive = os.path.splitdrive(path)[1]
            # Remove leading slashes or backslashes
            path = path_without_drive.lstrip("/\\")

        # Sanitize path to prevent directory traversal attacks
        return self._sanitize_path(path)

    def _sanitize_path(self, path: str) -> str:
        """Sanitize a path to prevent directory traversal attacks while supporting . and .. operations."""
        # Convert to use forward slashes for consistency
        normalized = path.replace("\\", "/")

        # Split into components and process them with a stack-based approach
        components: list[str] = []
        for component in normalized.split("/"):
            if component == "" or component == ".":
                # Skip empty components and current directory references
                continue
            elif component == "..":
                # Handle parent directory - only pop if we have components to pop
                if components:
                    components.pop()
                else:
                    # Attempting to go above the root - this is a path traversal attack
                    raise ValueError(f"Path traversal attempt detected: {path}")
            else:
                # Regular component - add it to the stack
                components.append(component)

        # Rejoin the safe components
        safe_path = "/".join(components)

        # Ensure the resulting path doesn't start with / (should be relative)
        return safe_path.lstrip("/")

    def construct_redirect_url(self, resource_address: str, redirect_host: str, redirect_port: int) -> str:
        """Construct a redirect URL for the given resource address.

        This method generates HTTP URLs for redirect-based uploads/downloads, simulating
        how cloud storage providers (like S3 or Azure) provide pre-signed URLs or SAS tokens.

        Note: This is specific to the local filesystem provider's implementation. Real cloud
        providers would generate their own signed URLs pointing to their infrastructure.

        Args:
            resource_address: The resource address to construct a URL for
            redirect_host: The host for the redirect URL (e.g., "http://localhost")
            redirect_port: The port for the redirect URL (e.g., 8011)

        Returns:
            A complete HTTP URL pointing to the local filesystem provider's upload/download endpoints
        """
        relative_path = self.force_relative_path(resource_address)
        # Replace backslashes with forward slashes and URL-encode
        encoded_path = urllib.parse.quote_plus(relative_path.replace("\\", "/"))

        if self._is_versioned_address(resource_address):
            # For versioned addresses, use the download-by-identity endpoint
            return f"{redirect_host}:{redirect_port}/download-by-identity/{encoded_path}"
        else:
            # For regular addresses, use the download endpoint
            return f"{redirect_host}:{redirect_port}/download/{encoded_path}"

    def is_address_valid(self, resource_address: str) -> bool:
        try:
            path = self.force_relative_path(resource_address)
            complete_path = os.path.join(self._content_dir, path)
            if FileSystemProvider.is_pathname_valid(complete_path):
                return FileSystemProvider._is_sub_path(complete_path, self._content_dir)
        except ValueError:
            # In this case we want to return False
            pass
        return False

    def is_version_address(self, resource_address: str) -> bool:
        """Check if the resource address is a specific version address (contains ;version)."""
        # Version addresses end with semicolon followed by one or more digits
        return bool(re.search(r";[0-9]+$", resource_address))

    @staticmethod
    def is_pathname_valid(pathname: str) -> bool:
        """Define function that tries to find out if a given path is valid on any filesystem in any OS.

        Details to be found in
        https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
        """
        import errno
        import os
        import sys

        # Sadly, Python fails to provide the following magic number for us.
        error_invalid_name = 123
        """
        Windows-specific error code indicating an invalid pathname.

        See Also
        ----------
        https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
            Official listing of all such codes.
        """

        """
        Define function that tries to find out if a given path is valid on any filesystem in any OS.

        `True` if the passed pathname is a valid pathname for the current OS;
        `False` otherwise.
        """
        # If this pathname is either not a string or is but is empty, this pathname
        # is invalid.
        try:
            if not isinstance(pathname, str) or not pathname:
                return False

            # Strip this pathname's Windows-specific drive specifier (e.g., `C:\`)
            # if any. Since Windows prohibits path components from containing `:`
            # characters, failing to strip this `:`-suffixed prefix would
            # erroneously invalidate all valid absolute Windows pathnames.
            _, pathname = os.path.splitdrive(pathname)

            # Directory guaranteed to exist. If the current OS is Windows, this is
            # the drive to which Windows was installed (e.g., the "%HOMEDRIVE%"
            # environment variable); else, the typical root directory.
            root_dirname = os.environ.get("HOMEDRIVE", "C:") if sys.platform == "win32" else os.path.sep

            # Append a path separator to this directory if needed.
            root_dirname = root_dirname.rstrip(os.path.sep) + os.path.sep

            # Test whether each path component split from this pathname is valid or
            # not, ignoring non-existent and non-readable path components.
            for pathname_part in pathname.split(os.path.sep):
                try:
                    os.lstat(root_dirname + pathname_part)
                # If an OS-specific exception is raised, its error code
                # indicates whether this pathname is valid or not. Unless this
                # is the case, this exception implies an ignorable kernel or
                # filesystem complaint (e.g., path not found or inaccessible).
                #
                # Only the following exceptions indicate invalid pathnames:
                #
                # * Instances of the Windows-specific "WindowsError" class
                #   defining the "winerror" attribute whose value is
                #   "ERROR_INVALID_NAME". Under Windows, "winerror" is more
                #   fine-grained and hence useful than the generic "errno"
                #   attribute. When a too-long pathname is passed, for example,
                #   "errno" is "ENOENT" (i.e., no such file or directory) rather
                #   than "ENAMETOOLONG" (i.e., file name too long).
                # * Instances of the cross-platform "OSError" class defining the
                #   generic "errno" attribute whose value is either:
                #   * Under most POSIX-compatible OSes, "ENAMETOOLONG".
                #   * Under some edge-case OSes (e.g., SunOS, *BSD), "ERANGE".
                except OSError as exc:
                    if hasattr(exc, "winerror"):
                        if exc.winerror == error_invalid_name:
                            return False
                    elif exc.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                        return False
        # If a "TypeError" exception was raised, it almost certainly has the
        # error message "embedded NUL character" indicating an invalid pathname.
        # In Linux this seems to throw a ValueError
        except (TypeError, ValueError):
            return False
        # If no exception was raised, all path components and hence this
        # pathname itself are valid. (Praise be to the curmudgeonly python.)
        else:
            return True
        # If any other exception was raised, this is an unrelated fatal issue
        # (e.g., a bug). Permit this exception to unwind the call stack.
        #
        # Did we mention this should be shipped with Python already?

    def _metadata_path_for_resource(self, metadata_uri: str) -> str:
        """Get the metadata file path for a metadata_uri.

        To handle very long paths, the encoded filename is split into chunks
        of 64 characters, creating a reproducible directory structure.
        """
        if self.is_address_valid(metadata_uri):
            # Optimization possible - this is a valid resource_address, we can shorten the id
            relative_path = self.force_relative_path(metadata_uri)
            encoded = self.string_to_base64(relative_path)
        else:
            # This will raise if this is not an identity, but that should have been checked beforehand
            full_path = FileSystemProvider.get_path_from_identity(metadata_uri)
            if FileSystemProvider._is_sub_path(full_path, self._versions_dir):
                rel_path = os.path.relpath(full_path, self._versions_dir)
                encoded = self.string_to_base64(rel_path)
            else:
                raise ValueError("Identity does not reference versions directory, invalid argument")

        # Split long encoded strings into directory structure to avoid filesystem limits
        # Most filesystems have a 255-byte filename limit
        # Use chunk_size - 1 to ensure the final filename is never empty and always
        # has at least one character before .json extension
        chunk_size = 63  # Use 63 characters per directory level (leaves room for at least 1 char in filename)
        max_filename_length = 200  # Start chunking well before filesystem limits

        if len(encoded) > max_filename_length:
            # Split into chunks and create a directory structure
            chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]
            # Last chunk gets the .json extension (guaranteed to be non-empty due to chunk_size < len(encoded))
            chunks[-1] = f"{chunks[-1]}.json"
            return os.path.join(self._metadata_dir, *chunks)
        else:
            return os.path.join(self._metadata_dir, f"{encoded}.json")

    def _load_metadata(self, metadata_uri: str) -> Dict[str, Dict]:
        """Load metadata for a given metadata_uri."""
        metadata_path = self._metadata_path_for_resource(metadata_uri)
        extended_metadata_path = FileSystemProvider._to_extended_path(metadata_path)
        if not os.path.exists(extended_metadata_path):
            return {}

        try:
            with open(extended_metadata_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning(f"Failed to load or parse metadata file '{metadata_path}': {e}")
            return {}

    def _save_metadata(self, metadata_uri: str, metadata: Dict[str, Dict]) -> None:
        """Save metadata for a metadata_uri."""
        metadata_path = self._metadata_path_for_resource(metadata_uri)
        extended_metadata_path = FileSystemProvider._to_extended_path(metadata_path)
        os.makedirs(FileSystemProvider._to_extended_path(os.path.dirname(metadata_path)), exist_ok=True)

        with open(extended_metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

    def _generate_etag(self, value: str) -> str:
        """Generate an ETag for a metadata value."""
        return hashlib.md5(value.encode("utf-8")).hexdigest()

    def _is_metadata_uri_valid(self, metadata_uri):
        if self.is_address_valid(metadata_uri):
            # Resource addresses are valid metadata_uris
            return True
        try:
            # Check if it can be parsed as an identity, then it is valid
            _ = self.address_from_identity(metadata_uri)
            return True
        except (ValueError, JSONDecodeError):
            # Generic strings not allowed, metadata_uris must be routable, so they need to be either
            # resource address or resource identity at the moment.
            return False

    def get_metadata(self, metadata_uri: str, keys: List[str]) -> Dict[str, Dict]:
        """Get metadata for a metadata_uri."""
        if not self._is_metadata_uri_valid(metadata_uri):
            raise ValueError(f"Invalid metadata id: {metadata_uri}")

        all_metadata = self._load_metadata(metadata_uri)

        # If requesting all keys with empty list
        if len(keys) == 0:
            return all_metadata

        # Return only requested keys
        result = {}
        for key in keys:
            if key in all_metadata:
                result[key] = all_metadata[key]

        return result

    def update_metadata(self, metadata_uri: str, key: str, value: str, expected_etag: Optional[str] = None) -> str:
        """Update metadata for a metadata_uri."""
        if not self._is_metadata_uri_valid(metadata_uri):
            raise ValueError(f"Invalid metadata id: {metadata_uri}")

        all_metadata = self._load_metadata(metadata_uri)

        if expected_etag is not None:
            if key not in all_metadata:
                raise MetadataKeyNotFoundError(key)
            current_etag = all_metadata[key].get("etag", "")
            if current_etag != expected_etag:
                raise EtagMismatchError(key, expected_etag, current_etag)

        new_etag = self._generate_etag(value)

        all_metadata[key] = {"value": value, "etag": new_etag}

        self._save_metadata(metadata_uri, all_metadata)
        return new_etag

    def delete_metadata(self, metadata_uri: str, key: str, expected_etag: Optional[str] = None) -> None:
        """Delete metadata for a metadata_uri."""
        if not self._is_metadata_uri_valid(metadata_uri):
            raise ValueError(f"Invalid metadata id: {metadata_uri}")

        all_metadata = self._load_metadata(metadata_uri)

        if key not in all_metadata:
            return

        if expected_etag is not None:
            current_etag = all_metadata[key].get("etag", "")
            if current_etag != expected_etag:
                raise EtagMismatchError(key, expected_etag, current_etag)

        del all_metadata[key]

        if all_metadata:
            self._save_metadata(metadata_uri, all_metadata)
        else:
            metadata_path = self._metadata_path_for_resource(metadata_uri)
            extended_metadata_path = FileSystemProvider._to_extended_path(metadata_path)
            if os.path.exists(extended_metadata_path):
                os.remove(extended_metadata_path)

    def encode_upload_id(self, upload_id: str, previous_version: str | None = None) -> str:
        """Encode an upload identifier."""

        if previous_version:
            return json.dumps({"upload_id": upload_id, "previous_version": previous_version})

        return json.dumps({"upload_id": upload_id})

    def decode_upload_id(self, value: str) -> tuple[str, str | None]:
        """Parse an upload identifier."""

        try:
            decoded = json.loads(value)
            if not isinstance(decoded, dict):
                raise ValueError("Upload identifier must be a JSON dictionary.")

            if not re.match(r"^[a-zA-Z0-9_-]+$", decoded["upload_id"]):
                raise ValueError("Invalid upload_id - must be alphanum with _ and - only!")
            return decoded["upload_id"], decoded.get("previous_version", None)
        except (KeyError, ValueError) as error:
            raise ValueError("Upload identifier is invalid.") from error

    @staticmethod
    def paths_eq(path1, path2) -> bool:
        # Convert to absolute paths for consistency
        p1 = os.path.abspath(path1)
        p2 = os.path.abspath(path2)

        # Normalize symbolic links, relative parts, \\?\ prefix, and case (on Windows)
        p1 = FileSystemProvider._normalize_path(p1)
        p2 = FileSystemProvider._normalize_path(p2)

        return p1 == p2

    # =============================================================================
    # Safe wrapper methods for OS operations with extended path support
    # =============================================================================
    # These methods ensure that all filesystem operations use extended path format
    # on Windows (\\?\ prefix) to support paths longer than 260 characters.
    # By centralizing these operations, we keep the max path complexity contained
    # in FileSystemProvider rather than leaking into the gRPC and REST service layers.

    @staticmethod
    def safe_makedirs(path: str, exist_ok: bool = False) -> None:
        """Create directories with extended path support.

        Args:
            path: Directory path to create
            exist_ok: If True, don't raise error if directory exists

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        os.makedirs(FileSystemProvider._to_extended_path(path), exist_ok=exist_ok)

    @staticmethod
    def safe_exists(path: str) -> bool:
        """Check if path exists with extended path support.

        Args:
            path: Path to check

        Returns:
            True if path exists, False otherwise

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return os.path.exists(FileSystemProvider._to_extended_path(path))

    @staticmethod
    def safe_isfile(path: str) -> bool:
        """Check if path is a file with extended path support.

        Args:
            path: Path to check

        Returns:
            True if path is a file, False otherwise

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return os.path.isfile(FileSystemProvider._to_extended_path(path))

    @staticmethod
    def safe_isdir(path: str) -> bool:
        """Check if path is a directory with extended path support.

        Args:
            path: Path to check

        Returns:
            True if path is a directory, False otherwise

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return os.path.isdir(FileSystemProvider._to_extended_path(path))

    @staticmethod
    def safe_open(path: str, mode: str, **kwargs):
        """Open file with extended path support.

        Args:
            path: File path to open
            mode: File open mode ('r', 'w', 'rb', 'wb', etc.)
            **kwargs: Additional arguments to pass to open()

        Returns:
            File object

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return open(FileSystemProvider._to_extended_path(path), mode, **kwargs)

    @staticmethod
    def safe_relpath(path: str, start: str) -> str:
        """Get relative path with extended path support.

        Args:
            path: Path to make relative
            start: Base path to compute relative path from

        Returns:
            Relative path from start to path (without extended prefix)

        Note:
            Both input and output paths are handled correctly for Windows
            extended path format. The result has extended prefix stripped.
        """
        extended_path = FileSystemProvider._to_extended_path(path)
        extended_start = FileSystemProvider._to_extended_path(start)
        result = os.path.relpath(extended_path, extended_start)
        return FileSystemProvider._strip_extended_prefix(result)

    @staticmethod
    def safe_getsize(path: str) -> int:
        """Get file size with extended path support.

        Args:
            path: File path to get size of

        Returns:
            File size in bytes

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return os.path.getsize(FileSystemProvider._to_extended_path(path))

    @staticmethod
    def safe_stat(path: str):
        """Get file statistics with extended path support.

        Args:
            path: File path to get statistics for

        Returns:
            os.stat_result object

        Note:
            Automatically handles Windows extended path format for paths > 260 chars.
        """
        return os.stat(FileSystemProvider._to_extended_path(path))

    @staticmethod
    def safe_dirname(path: str) -> str:
        """Get directory name with extended path support.

        Args:
            path: File path to get directory of

        Returns:
            Directory path (without extended prefix)

        Note:
            Result has extended prefix stripped for consistent path handling.
        """
        extended_path = FileSystemProvider._to_extended_path(path)
        result = os.path.dirname(extended_path)
        return FileSystemProvider._strip_extended_prefix(result)

    # =============================================================================
    # Capability Query Methods (implement interface)
    # =============================================================================

    def supports_redirect_download(self) -> bool:
        """FileSystemProvider supports redirect-based downloads."""
        return True

    def supports_redirect_upload(self) -> bool:
        """FileSystemProvider supports redirect-based uploads."""
        return True

    def supports_multipart_upload(self) -> bool:
        """FileSystemProvider supports multipart uploads."""
        return True

    # =============================================================================
    # HTTP Route Registration
    # =============================================================================

    def register_http_routes(self, app: "FastAPI") -> None:
        """Register filesystem-specific HTTP routes for redirect operations.

        This registers:
        - Static file mounts for download redirects (/download, /download-by-identity)
        - Upload endpoints for redirect-based uploads (/upload/{path})
        - Multipart upload endpoints (/upload_part/{upload_id}/{part_number}/{path})
        """
        from fastapi import (
            HTTPException,
            Path,
            Request,
        )
        from fastapi.staticfiles import StaticFiles
        from starlette.responses import JSONResponse

        # Mount static file directories for direct HTTP download redirects
        app.mount(
            "/download",
            StaticFiles(directory=self._content_dir, html=False),
            name="download-static",
        )
        app.mount(
            "/download-by-identity",
            StaticFiles(directory=self._versions_dir, html=False),
            name="download-by-identity-static",
        )

        # Capture self for use in closures
        backend = self

        @app.post("/upload/{resource_address:path}")
        async def upload_file(request: Request, resource_address: str = Path(...)):
            """Direct upload endpoint for redirect-based uploads."""
            resource_identity = backend.write_version(resource_address, await request.body())
            version_path = FileSystemProvider.get_path_from_identity(resource_identity)
            relative_version_path = os.path.relpath(version_path, backend._versions_dir)
            return JSONResponse(headers={"x-nvidia-storage-upload-location": relative_version_path}, content={})

        @app.post("/upload_part/{upload_id}/{part_number}/{resource_address:path}")
        async def upload_file_part(request: Request, upload_id: str, part_number: str, resource_address: str = Path(...)):
            """Upload a single part of a multipart upload."""
            if not part_number.isdigit() or int(part_number) < 0:
                raise HTTPException(400, "Invalid part_number")
            if "demo-multipart-upload" not in request.headers:
                raise HTTPException(400, "Client did not supply headers returned by multipart prepare part")

            upload_id_path = os.path.join(backend._uploads_dir, upload_id)
            path = os.path.join(upload_id_path, part_number, resource_address)

            if not FileSystemProvider.safe_exists(upload_id_path):
                # Pretend we're a third party server which doesn't know the upload has been aborted
                return JSONResponse(content={"filename": resource_address, "location": path}, headers={"local-file": path})

            FileSystemProvider.safe_makedirs(FileSystemProvider.safe_dirname(path), exist_ok=True)
            with FileSystemProvider.safe_open(path, "wb") as f:
                f.write(await request.body())
            return JSONResponse(content={"filename": resource_address, "location": path}, headers={"local-file": path})

    # =============================================================================
    # Redirect URL Construction for Identity-based Reads
    # =============================================================================

    def construct_redirect_url_for_identity(self, resource_identity: str, redirect_host: str, redirect_port: int) -> str:
        """Construct a redirect URL for reading a specific version by identity."""
        path = self.get_path_from_identity(resource_identity)
        relative_path = self.safe_relpath(path, self._versions_dir).replace("\\", "/")
        encoded_path = urllib.parse.quote_plus(relative_path)
        return f"{redirect_host}:{redirect_port}/download-by-identity/{encoded_path}"

    # =============================================================================
    # Redirect Upload Completion
    # =============================================================================

    def complete_redirect_upload(self, destination_resource_address: str, completion_headers: Dict[str, str]) -> RedirectUploadResult:
        """Complete a redirect-based upload using completion headers."""
        upload_location = completion_headers.get("x-nvidia-storage-upload-location")
        if not upload_location:
            raise ValueError("Missing x-nvidia-storage-upload-location header")

        if not self._version_path_exists(upload_location):
            raise FileNotFoundError(f"Invalid value for x-nvidia-storage-upload-location: {upload_location}")

        version_path = os.path.join(self._versions_dir, upload_location)
        info = self._stat(version_path)

        return RedirectUploadResult(
            resource_identity=info.resource_identity,
            metadata=info.metadata,
        )

    # =============================================================================
    # Multipart Upload Management
    # =============================================================================

    def create_upload_session(self, upload_id: str) -> None:
        """Create a new multipart upload session."""
        upload_id_path = os.path.join(self._uploads_dir, upload_id)
        self.safe_makedirs(upload_id_path, exist_ok=True)

    def get_upload_part_path(self, upload_id: str, part_number: int, resource_address: str) -> str:
        """Get the filesystem path where an upload part should be stored."""
        relative_path = self.force_relative_path(resource_address)
        return os.path.join(self._uploads_dir, upload_id, str(part_number), relative_path)

    def cleanup_upload_session(self, upload_id: str) -> None:
        """Clean up resources for a completed or aborted upload session."""
        upload_id_path = os.path.join(self._uploads_dir, upload_id)
        self.remove_file_if_exists(upload_id_path, self._uploads_dir)

    def upload_session_exists(self, upload_id: str) -> bool:
        """Check if an upload session exists."""
        upload_id_path = os.path.join(self._uploads_dir, upload_id)
        return self.safe_exists(upload_id_path)

    def construct_upload_part_redirect(
        self, upload_id: str, part_number: int, resource_address: str, redirect_host: str, redirect_port: int
    ) -> Dict[str, Any]:
        """Construct redirect properties for uploading a multipart part."""
        relative_path = self.force_relative_path(resource_address)
        url = f"{redirect_host}:{redirect_port}/upload_part/{upload_id}/{part_number}/" + urllib.parse.quote_plus(
            relative_path.replace("\\", "/")
        )
        return {
            "redirect_target_url": url,
            "method": "POST",
            "additional_headers": [("demo-multipart-upload", "1")],
            "completion_header_names": ["local-file"],
        }

    # =============================================================================
    # Metadata for Path (FileSystemProvider-specific)
    # =============================================================================

    def get_metadata_for_path(self, path: str) -> Metadata:
        """Get metadata for a filesystem path.

        This is a FileSystemProvider-specific helper for getting metadata
        from raw filesystem paths (used internally for redirect completion, etc.)

        Args:
            path: Filesystem path to get metadata for

        Returns:
            Metadata object with size and modification timestamp
        """
        size = self.safe_getsize(path)
        stat_result = self.safe_stat(path)
        modification_dt = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
        return Metadata(data_object_size=size, last_modified_timestamp=modification_dt)
