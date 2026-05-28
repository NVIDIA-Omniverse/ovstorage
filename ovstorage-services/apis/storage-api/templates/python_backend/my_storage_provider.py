# SPDX-FileCopyrightText: Copyright (c) 2025 YOUR_COMPANY
# SPDX-License-Identifier: YOUR_LICENSE
#
# Template for implementing a new storage backend for the Omniverse Storage API.
# Replace 'MyStorage' with your storage system name throughout this file.

"""
MyStorage Backend Implementation for Omniverse Storage API.

This module implements the StorageBackendInterface for [YOUR STORAGE SYSTEM].
Replace this docstring with a description of your storage system and any
important notes about the implementation.

Example:
    # Start the service with this backend
    local-filesystem-service mystorage --option1 value1

Configuration:
    - MYSTORAGE_OPTION1: Environment variable for option1
"""

import base64
import json
import logging
from datetime import (
    datetime,
    timezone,
)
from typing import (
    Any,
    Dict,
    Generator,
    List,
    Optional,
    Tuple,
)

from local_filesystem_service.backends.backend_factory import (
    BackendConfig,
    register_backend,
)
from local_filesystem_service.backends.storage_backend_interface import (
    EtagMismatchError,
    ListEntry,
    Metadata,
    MetadataKeyNotFoundError,
    OptimisticLockingSupport,
    RedirectUploadResult,
    StorageBackendInterface,
    VersionInfo,
    VersionsOrder,
)

logger = logging.getLogger(__name__)


# =============================================================================
# STEP 1: Register your backend factory
# =============================================================================


@register_backend("mystorage")  # <-- Change "mystorage" to your backend name
def create_my_storage_backend(config: BackendConfig) -> StorageBackendInterface:
    """Factory function to create MyStorage backend.

    This is called by the service when starting up with your backend type.

    Args:
        config: BackendConfig with base_uri and extra_config from CLI

    Returns:
        Configured instance of MyStorageBackend
    """
    # Extract your custom options from extra_config (set by CLI in __init__.py)
    option1 = config.extra_config.get("option1", "default_value")
    option2 = config.extra_config.get("option2", False)

    return MyStorageBackend(
        base_uri=config.base_uri,
        option1=option1,
        option2=option2,
    )


# =============================================================================
# STEP 2: Implement your backend class
# =============================================================================


class MyStorageBackend(StorageBackendInterface):
    """Storage backend for [YOUR STORAGE SYSTEM].

    This class implements all methods required by StorageBackendInterface.
    See the interface docstrings for detailed requirements.

    Resource Address Format:
        mystorage://authority/path/to/resource

    Resource Identity Format:
        mystorage-id://authority/<base64-encoded-version-info>
    """

    # Schema for resource identities (must be different from address schema)
    IDENTITY_SCHEMA = "mystorage-id"  # <-- Change to your identity schema

    def __init__(
        self,
        base_uri: str,
        option1: str,
        option2: bool,
    ) -> None:
        """Initialize the MyStorage backend.

        Args:
            base_uri: Base URI for resource addresses (e.g., "mystorage://bucket")
            option1: Your custom option
            option2: Another custom option
        """
        self._base_uri = base_uri
        if not self._base_uri.endswith("/"):
            self._base_uri += "/"

        self._option1 = option1
        self._option2 = option2

        # TODO: Initialize your storage client here
        # Example for S3:
        # import boto3
        # self._client = boto3.client('s3')

        logger.info(f"Initialized MyStorage backend with base_uri={base_uri}")

    # =========================================================================
    # Configuration Properties
    # =========================================================================

    @property
    def base_uri(self) -> str:
        """Base URI for this storage backend instance."""
        return self._base_uri

    # =========================================================================
    # Resource Address Validation and Conversion
    # =========================================================================

    def is_address_valid(self, resource_address: str) -> bool:
        """Check if a resource address is valid for this backend.

        A valid address should:
        - Have the correct scheme (matching base_uri)
        - Have the correct authority/netloc
        - Have a valid path structure
        - Not contain invalid characters

        Returns:
            True if valid, False otherwise
        """
        try:
            from urllib.parse import urlparse

            parsed = urlparse(resource_address)
            base_parsed = urlparse(self._base_uri)

            if parsed.scheme != base_parsed.scheme:
                return False
            if parsed.netloc != base_parsed.netloc:
                return False

            # TODO: Add your storage-specific validation
            # Example: Check for invalid characters, path length, etc.

            return True
        except Exception:
            return False

    def is_version_address(self, resource_address: str) -> bool:
        """Check if address refers to a specific version.

        Version addresses have format: resource_address;version_number
        Example: mystorage://bucket/file.usd;3

        Returns:
            True if address contains version suffix
        """
        # Standard pattern: address ends with ;digit(s)
        import re
        from urllib.parse import urlparse

        parsed = urlparse(resource_address)
        return bool(re.search(r";[0-9]+$", parsed.path))

    def create_identity_from_resource_address(self, resource_address: str) -> str:
        """Create a resource identity from a resource address.

        For non-versioned addresses, returns identity for the latest version.
        For versioned addresses, returns identity for that specific version.

        Returns:
            Opaque identity string

        Raises:
            ValueError: If address points to a folder or is invalid
        """
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot create identity for folder: {resource_address}")

        # TODO: Implement identity creation
        # This should encode everything needed to retrieve the specific version

        # Example implementation:
        path = self._extract_path(resource_address)
        version_id = self._get_latest_version_id(path)  # <-- You implement this

        identity_data = {
            "path": path,
            "version": version_id,
            # Add any other storage-specific identifiers
        }

        encoded = base64.urlsafe_b64encode(json.dumps(identity_data).encode()).decode()

        from urllib.parse import urlparse

        parsed = urlparse(self._base_uri)
        return f"{self.IDENTITY_SCHEMA}://{parsed.netloc}/{encoded}"

    def address_from_identity(self, resource_identity: str) -> str:
        """Convert identity back to resource address (without version suffix).

        Returns:
            Resource address for the latest version at that location

        Raises:
            ValueError: If identity is invalid
        """
        identity_data = self._decode_identity(resource_identity)
        path = identity_data["path"]
        return self._base_uri + path

    def url_from_identity(self, resource_identity: str) -> str:
        """Convert identity to URL including version suffix.

        Unlike address_from_identity(), this preserves version info.

        Returns:
            Full URL including version suffix if applicable
        """
        identity_data = self._decode_identity(resource_identity)
        path = identity_data["path"]
        version = identity_data.get("version")

        if version is not None:
            return f"{self._base_uri}{path};{version}"
        return self._base_uri + path

    def get_optimistic_locking_support(self) -> OptimisticLockingSupport:
        """Return which operations support optimistic locking.

        Optimistic locking allows clients to pass previous_version to ensure
        no concurrent modifications occurred.

        Returns:
            OptimisticLockingSupport indicating supported operations
        """
        # TODO: Set to True for operations your backend can support
        return OptimisticLockingSupport(
            write=False,  # True if you can check version before writing
            delete=False,  # True if you can check version before deleting
            copy=False,  # True if you can check version before copying
            move=False,  # True if you can check version before moving
        )

    # =========================================================================
    # File Existence and Type Checking
    # =========================================================================

    def exists(self, resource_address: str) -> bool:
        """Check if a resource exists.

        Returns True for both files and directories.
        """
        # TODO: Implement existence check
        raise NotImplementedError("Implement exists()")

    def is_file(self, resource_address: str) -> bool:
        """Check if address points to a file (not a directory)."""
        # TODO: Implement file check
        raise NotImplementedError("Implement is_file()")

    def is_dir(self, resource_address: str) -> bool:
        """Check if address points to a directory."""
        # TODO: Implement directory check
        raise NotImplementedError("Implement is_dir()")

    # =========================================================================
    # File Operations
    # =========================================================================

    def read_from_address(self, resource_address: str) -> Generator[bytes, None, None]:
        """Read file content from an address (yields chunks).

        For versioned addresses, reads that specific version.
        For non-versioned addresses, reads the latest version.

        Yields:
            Byte chunks of file content

        Raises:
            FileNotFoundError: If resource doesn't exist
            ValueError: If address points to a folder
        """
        if not self.exists(resource_address):
            raise FileNotFoundError(f"Resource not found: {resource_address}")
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot read from folder: {resource_address}")

        # TODO: Implement reading
        # Should yield chunks of bytes for streaming
        raise NotImplementedError("Implement read_from_address()")

    def read_from_identity(self, resource_identity: str) -> Generator[bytes, None, None]:
        """Read file content from a specific version by identity.

        Yields:
            Byte chunks of file content

        Raises:
            FileNotFoundError: If version doesn't exist
            ValueError: If identity is invalid
        """
        try:
            identity_data = self._decode_identity(resource_identity)
        except Exception as e:
            raise ValueError(f"Invalid identity: {resource_identity}") from e

        # TODO: Implement reading specific version
        raise NotImplementedError("Implement read_from_identity()")

    def write_version(
        self,
        resource_address: str,
        content: bytes,
        previous_version: Optional[str] = None,
    ) -> str:
        """Write content, creating a new version.

        Args:
            resource_address: Where to write
            content: File content to write
            previous_version: Optional identity of expected current version
                             (for optimistic locking)

        Returns:
            Resource identity of the newly created version

        Raises:
            ValueError: If address points to a folder
            EtagMismatchError: If previous_version doesn't match current
        """
        if self.is_dir(resource_address):
            raise ValueError(f"Cannot write to folder: {resource_address}")

        # Check optimistic locking if previous_version provided
        if previous_version is not None:
            if not self.is_version_latest(resource_address, previous_version):
                current = self.stat(resource_address)
                raise EtagMismatchError(
                    key=resource_address,
                    expected_etag=previous_version,
                    actual_etag=current.resource_identity,
                )

        # TODO: Implement writing and version creation
        raise NotImplementedError("Implement write_version()")

    def stat(self, resource_address: str) -> VersionInfo:
        """Get metadata for a resource address (latest version).

        Returns:
            VersionInfo with identity and metadata

        Raises:
            FileNotFoundError: If resource doesn't exist
            IsADirectoryError: If address points to a directory
        """
        if not self.exists(resource_address):
            raise FileNotFoundError(f"Resource not found: {resource_address}")
        if self.is_dir(resource_address):
            raise IsADirectoryError(f"{resource_address} is a directory")

        # TODO: Implement stat
        # Should return VersionInfo with:
        # - resource_identity: Identity for the current version
        # - metadata: Metadata with size and timestamp
        raise NotImplementedError("Implement stat()")

    def stat_identity(self, resource_identity: str) -> VersionInfo:
        """Get metadata for a specific version by identity.

        Unlike stat(), this works even if the address was deleted.

        Returns:
            VersionInfo with same identity and metadata

        Raises:
            FileNotFoundError: If version doesn't exist
            ValueError: If identity is invalid
        """
        try:
            identity_data = self._decode_identity(resource_identity)
        except Exception as e:
            raise ValueError(f"Invalid identity: {resource_identity}") from e

        # TODO: Implement stat for specific version
        raise NotImplementedError("Implement stat_identity()")

    def remove_by_address(self, resource_address: str) -> None:
        """Remove the current version (historical versions remain).

        Raises:
            FileNotFoundError: If resource doesn't exist
        """
        if not self.exists(resource_address):
            raise FileNotFoundError(f"Resource not found: {resource_address}")

        # TODO: Implement soft delete (keep versions)
        raise NotImplementedError("Implement remove_by_address()")

    def obliterate(self, resource_address: str) -> None:
        """Permanently delete resource and ALL versions.

        Raises:
            FileNotFoundError: If resource doesn't exist
        """
        # TODO: Implement hard delete (remove everything)
        raise NotImplementedError("Implement obliterate()")

    # =========================================================================
    # Folder Operations
    # =========================================================================

    def create_folder(self, resource_address: str) -> None:
        """Create a folder.

        Raises:
            FileExistsError: If a file exists at this path
        """
        # TODO: Implement folder creation
        # Note: Some storage systems don't have real folders
        raise NotImplementedError("Implement create_folder()")

    def list(self, resource_address: str) -> Tuple[List[str], List[str]]:
        """List immediate children of a folder.

        Returns:
            Tuple of (subfolder_names, file_names)

        Raises:
            FileNotFoundError: If folder doesn't exist
            ValueError: If address points to a file
        """
        if not self.exists(resource_address):
            raise FileNotFoundError(f"Folder not found: {resource_address}")
        if self.is_file(resource_address):
            raise ValueError(f"Not a folder: {resource_address}")

        # TODO: Implement listing
        raise NotImplementedError("Implement list()")

    def list_stat(
        self,
        resource_address: str,
        start_index: int = 0,
        limit: Optional[int] = None,
    ) -> Tuple[List[str], List[ListEntry]]:
        """List folder contents with metadata (paginated).

        Returns:
            Tuple of (subfolder_names, file_entries_with_metadata)
        """
        # TODO: Implement listing with metadata
        raise NotImplementedError("Implement list_stat()")

    def enumerate(
        self,
        resource_address: str,
        start_index: int = 0,
        limit: Optional[int] = None,
    ) -> Generator[List[ListEntry], None, None]:
        """Recursively enumerate all files under a directory.

        Yields:
            Batches of ListEntry objects for files
        """
        # TODO: Implement recursive enumeration
        raise NotImplementedError("Implement enumerate()")

    def remove_empty_folder(self, resource_address: str) -> bool:
        """Remove an empty folder.

        Returns:
            True if removed, False if not empty
        """
        # TODO: Implement folder removal
        raise NotImplementedError("Implement remove_empty_folder()")

    # =========================================================================
    # Versioning Operations
    # =========================================================================

    def enumerate_versions(
        self,
        resource_address: str,
        start_index: int = 0,
        limit: Optional[int] = None,
    ) -> Tuple[List[VersionInfo], VersionsOrder]:
        """Enumerate all versions of a resource.

        Returns:
            Tuple of (version_list, ordering)
        """
        # TODO: Implement version enumeration
        raise NotImplementedError("Implement enumerate_versions()")

    # =========================================================================
    # Metadata Operations (User-defined key-value pairs)
    # =========================================================================

    def get_metadata(
        self,
        metadata_uri: str,
        keys: List[str],
    ) -> Dict[str, Dict[str, Any]]:
        """Get user-defined metadata.

        Args:
            metadata_uri: Resource address or identity
            keys: Keys to retrieve (empty list = all keys)

        Returns:
            Dict mapping keys to {value, etag}
        """
        # TODO: Implement metadata retrieval
        return {}

    def update_metadata(
        self,
        metadata_uri: str,
        key: str,
        value: str,
        expected_etag: Optional[str] = None,
    ) -> str:
        """Update metadata (with optional optimistic locking).

        Returns:
            New etag for the updated value
        """
        # TODO: Implement metadata update
        raise NotImplementedError("Implement update_metadata()")

    def delete_metadata(
        self,
        metadata_uri: str,
        key: str,
        expected_etag: Optional[str] = None,
    ) -> None:
        """Delete metadata key."""
        # TODO: Implement metadata deletion
        raise NotImplementedError("Implement delete_metadata()")

    # =========================================================================
    # Permission Checking
    # =========================================================================

    def check_read_permission_on_address(self, resource_address: str) -> bool:
        """Check if resource can be read.

        Raises:
            PermissionError: If access is denied
        """
        # TODO: Implement permission check
        return True

    # =========================================================================
    # Upload/Download Support
    # =========================================================================

    def construct_redirect_url(
        self,
        resource_address: str,
        redirect_host: str,
        redirect_port: int,
    ) -> str:
        """Construct redirect URL for upload/download.

        Used for presigned URL-based operations.
        """
        # TODO: Implement redirect URL construction (e.g., presigned URL)
        raise NotImplementedError("Redirect not supported")

    def supports_redirect_download(self) -> bool:
        """Return True if presigned download URLs are supported."""
        return False

    def supports_redirect_upload(self) -> bool:
        """Return True if presigned upload URLs are supported."""
        return False

    def supports_multipart_upload(self) -> bool:
        """Return True if multipart uploads are supported."""
        return False

    # =========================================================================
    # Copy/Move Operations
    # =========================================================================

    def copy(
        self,
        source_resource_address: str,
        destination_resource_address: str,
    ) -> str:
        """Copy resource to new address.

        Returns:
            Identity of newly created version at destination
        """
        # TODO: Implement copy
        raise NotImplementedError("Implement copy()")

    def move(
        self,
        source_resource_address: str,
        destination_resource_address: str,
    ) -> str:
        """Move/rename resource.

        Returns:
            Identity of newly created version at destination
        """
        # TODO: Implement move
        raise NotImplementedError("Implement move()")

    # =========================================================================
    # Upload ID Encoding (for multipart uploads)
    # =========================================================================

    def encode_upload_id(
        self,
        upload_id: str,
        previous_version: Optional[str] = None,
    ) -> str:
        """Encode upload identifier for multipart uploads."""
        data = {"upload_id": upload_id}
        if previous_version:
            data["previous_version"] = previous_version
        return json.dumps(data)

    def decode_upload_id(self, value: str) -> Tuple[str, Optional[str]]:
        """Decode upload identifier."""
        try:
            data = json.loads(value)
            return data["upload_id"], data.get("previous_version")
        except (KeyError, json.JSONDecodeError) as e:
            raise ValueError("Invalid upload_id") from e

    # =========================================================================
    # Helper Methods (Add your own below)
    # =========================================================================

    def _extract_path(self, resource_address: str) -> str:
        """Extract relative path from resource address."""
        from urllib.parse import urlparse

        parsed = urlparse(resource_address)
        path = parsed.path
        if path.startswith("/"):
            path = path[1:]
        # Remove version suffix if present
        if ";" in path:
            path = path.rsplit(";", 1)[0]
        return path

    def _decode_identity(self, resource_identity: str) -> Dict[str, Any]:
        """Decode base64 identity to dict."""
        from urllib.parse import urlparse

        parsed = urlparse(resource_identity)
        if parsed.scheme != self.IDENTITY_SCHEMA:
            raise ValueError(f"Invalid identity schema: {parsed.scheme}")

        encoded = parsed.path
        if encoded.startswith("/"):
            encoded = encoded[1:]

        decoded = base64.urlsafe_b64decode(encoded).decode()
        return json.loads(decoded)

    def _get_latest_version_id(self, path: str) -> str:
        """Get the version ID of the latest version."""
        # TODO: Implement this based on your storage system
        raise NotImplementedError("Implement _get_latest_version_id()")
