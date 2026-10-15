# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Filesystem module - provides storage backend access and configuration.

This module maintains a global storage backend instance (STORAGE_BACKEND) that
can be initialized with different backend implementations (filesystem, git, s3, etc.).

The backend is initialized by calling init_backend() with the appropriate configuration,
typically done from the CLI entry points in __main__.py files.
"""

import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

import typer
from local_filesystem_service.backends import (
    BackendConfig,
    StorageBackendInterface,
    create_backend,
    register_backend,
    register_backend_cli,
)
from local_filesystem_service.filesystem.file_system_provider import (
    FileSystemProvider,
)
from typing_extensions import Annotated

logger = logging.getLogger(__name__)

# Filesystem backend option names/defaults (shared by Typer + fallback startup path)
FILESERVICE_SERVER_BASE_URI_ENV = "FILESERVICE_SERVER_BASE_URI"
FILESERVICE_SERVER_BASE_URI_DEFAULT = "file-storage://fileservice"
FILESERVICE_STATIC_DIR_ENV = "FILESERVICE_STATIC_DIR"
FILESERVICE_TEST_FOLDER_MODE_ENV = "FILESERVICE_TEST_FOLDER_MODE"
FILESERVICE_TEST_FOLDER_MODE_DEFAULT = "native"
REDIRECT_HOST_ENV = "REDIRECT_HOST"
REDIRECT_HOST_DEFAULT = "http://localhost"
REDIRECT_PORT_ENV = "REDIRECT_PORT"
REDIRECT_PORT_DEFAULT = 8011


@dataclass
class FilesystemConfig(BackendConfig):
    """Configuration for the local filesystem storage backend.

    Extends BackendConfig with filesystem-specific options.

    Attributes:
        backend_type: Type/name of backend (always "filesystem")
        base_uri: Base URI for resource addresses (e.g., "file-storage://fileservice")
        static_dir: Directory for file storage
        folder_mode: Folder simulation mode: "native", "no_empty", or "placeholder"
        redirect_host: Host for redirect URLs (e.g., "http://localhost")
        redirect_port: Port for redirect URLs (e.g., 8011)
        extra_config: Additional configuration options
    """

    static_dir: Optional[str] = None
    folder_mode: str = "native"
    redirect_host: str = "http://localhost"
    redirect_port: int = 8011


# Note: FILE_SYSTEM_PROVIDER is dynamically set and may not be a FileSystemProvider instance
# It will be whatever backend type is initialized via init_backend()
__all__ = [
    "init_backend",
    "get_backend",
    "FILE_SYSTEM_PROVIDER",
    "FileSystemProvider",
    "FilesystemConfig",
    "STATIC_DIR",
    "REDIRECT_HOST",
    "REDIRECT_PORT",
    "SERVER_BASE_URI",
]

# =============================================================================
# Global Configuration (from environment variables, for backward compatibility)
# =============================================================================

# Default directory for storing files (used if FILESERVICE_STATIC_DIR not set)
default_tmpdir = os.path.join(tempfile.gettempdir(), "storage_api_test")

# Root directory where all files and metadata will be stored
# Structure:
#   STATIC_DIR/
#     content/     - Current versions of files by resource address
#     metadata/    - User-defined metadata key-value pairs
#     versions/    - Immutable version history by resource identity
#     uploads/     - Temporary storage for multipart uploads
STATIC_DIR = os.environ.get(FILESERVICE_STATIC_DIR_ENV, default_tmpdir)
os.makedirs(STATIC_DIR, exist_ok=True)

# Host and port for redirect URLs (when clients should upload/download via alternate endpoint)
REDIRECT_HOST = os.getenv(REDIRECT_HOST_ENV, REDIRECT_HOST_DEFAULT)
REDIRECT_PORT = int(os.getenv(REDIRECT_PORT_ENV, str(REDIRECT_PORT_DEFAULT)))

# Base URI that will be prepended to all resource addresses
# Example: "file-storage://fileservice" + "/path/to/file" = "file-storage://fileservice/path/to/file"
# Note that these are plus quoted when used in the REST endpoints
SERVER_BASE_URI = os.environ.get(FILESERVICE_SERVER_BASE_URI_ENV, FILESERVICE_SERVER_BASE_URI_DEFAULT)

# =============================================================================
# Global Storage Backend Instance
# =============================================================================

# Global storage backend instance (initialized by init_backend())
# This is set by the CLI entry points and used by the service layer
_storage_backend: Optional[StorageBackendInterface] = None

# Legacy FILE_SYSTEM_PROVIDER reference that will always point to the current backend
FILE_SYSTEM_PROVIDER: Optional[StorageBackendInterface] = None


def init_backend(config: BackendConfig) -> StorageBackendInterface:
    """Initialize the global storage backend instance.

    This should be called once at application startup with the desired backend
    configuration. Subsequent calls will replace the existing backend.

    Args:
        config: Configuration for the storage backend (e.g., FilesystemConfig)

    Returns:
        The created storage backend instance

    Example:
        config = FilesystemConfig(
            backend_type="filesystem",
            base_uri="file-storage://fileservice",
            static_dir="/tmp/storage"
        )
        backend = init_backend(config)
    """
    global _storage_backend, FILE_SYSTEM_PROVIDER
    _storage_backend = create_backend(config)
    # Update FILE_SYSTEM_PROVIDER to point to the new backend for backward compatibility
    FILE_SYSTEM_PROVIDER = _storage_backend
    logger.info(f"Initialized storage backend: {config.backend_type}")
    return _storage_backend


def get_backend() -> StorageBackendInterface:
    """Get the global storage backend instance.

    Returns:
        The current storage backend

    Raises:
        RuntimeError: If backend has not been initialized
    """
    if _storage_backend is None:
        raise RuntimeError(
            "Storage backend not initialized. Call init_backend() first "
            "or use the legacy FILE_SYSTEM_PROVIDER for backward compatibility."
        )
    return _storage_backend


# =============================================================================
# Legacy Support (Backward Compatibility)
# =============================================================================

# Initialize default backend using environment variables for backward compatibility
_default_backend = FileSystemProvider(
    STATIC_DIR,
    SERVER_BASE_URI,
    os.environ.get(FILESERVICE_TEST_FOLDER_MODE_ENV, FILESERVICE_TEST_FOLDER_MODE_DEFAULT),
)
_storage_backend = _default_backend
FILE_SYSTEM_PROVIDER = _default_backend
logger.info("Initialized default filesystem backend from environment variables")


# Import and register built-in backends
def _register_builtin_backends():
    """Register built-in storage backends and their CLI commands."""

    @register_backend("filesystem")
    def create_filesystem_backend(config: FilesystemConfig) -> StorageBackendInterface:
        """Create a local filesystem storage backend.

        This backend stores files in a local directory structure with support
        for versioning, metadata, and multipart uploads.

        Args:
            config: FilesystemConfig with filesystem-specific options
        """
        # Use provided static_dir or create default
        static_dir = config.static_dir
        if not static_dir:
            static_dir = default_tmpdir

        os.makedirs(static_dir, exist_ok=True)

        return FileSystemProvider(static_dir=static_dir, base_uri=config.base_uri, test_folder_mode=config.folder_mode)

    @register_backend_cli("filesystem", "Start service with local filesystem storage")
    def filesystem_cli_command(
        base_uri: Annotated[
            str,
            typer.Option(
                "--base-uri",
                help="Base URI for resource addresses",
                envvar=FILESERVICE_SERVER_BASE_URI_ENV,
            ),
        ] = FILESERVICE_SERVER_BASE_URI_DEFAULT,
        static_dir: Annotated[
            Optional[str],
            typer.Option(
                "--static-dir",
                help="Directory for file storage",
                envvar=FILESERVICE_STATIC_DIR_ENV,
            ),
        ] = None,
        folder_mode: Annotated[
            str,
            typer.Option(
                "--folder-mode",
                help="Folder simulation mode: native, no_empty, or placeholder",
                envvar=FILESERVICE_TEST_FOLDER_MODE_ENV,
            ),
        ] = FILESERVICE_TEST_FOLDER_MODE_DEFAULT,
        redirect_host: Annotated[
            str,
            typer.Option(
                "--redirect-host",
                help="Host for redirect URLs",
                envvar=REDIRECT_HOST_ENV,
            ),
        ] = REDIRECT_HOST_DEFAULT,
        redirect_port: Annotated[
            int,
            typer.Option(
                "--redirect-port",
                help="Port for redirect URLs",
                envvar=REDIRECT_PORT_ENV,
            ),
        ] = REDIRECT_PORT_DEFAULT,
    ) -> FilesystemConfig:
        """Configure local filesystem backend.

        The filesystem backend stores files in a local directory with support for:
        - Multiple folder simulation modes (native, no_empty, placeholder)
        - Versioning and metadata
        - Redirect-based uploads/downloads

        Examples:
            # Use default temporary directory
            ... filesystem

            # Specify custom storage directory
            ... filesystem --static-dir /data/storage

            # S3-like folder behavior (no empty folders)
            ... filesystem --folder-mode no_empty

            # Custom redirect endpoint
            ... filesystem --redirect-host http://cdn.example.com --redirect-port 9000
        """
        return FilesystemConfig(
            backend_type="filesystem",
            base_uri=base_uri,
            static_dir=static_dir,
            folder_mode=folder_mode,
            redirect_host=redirect_host,
            redirect_port=redirect_port,
        )


# Register built-in backends on module import
_register_builtin_backends()
