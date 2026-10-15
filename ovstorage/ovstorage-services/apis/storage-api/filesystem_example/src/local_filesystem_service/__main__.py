# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""NVIDIA Omniverse Storage API - Combined gRPC and REST Service

This module provides the main entry point for running both gRPC and REST services
together. Each storage backend has its own subcommand with backend-specific parameters.

Example Usage:
    # Start with filesystem backend
    python -m local_filesystem_service filesystem --static-dir /data/storage

    # Start with custom ports
    python -m local_filesystem_service --grpc-port 50052 --http-port 8012 filesystem

    # Start only REST server
    python -m local_filesystem_service --no-grpc filesystem

    # See all available backends
    python -m local_filesystem_service --help

    # See backend-specific options
    python -m local_filesystem_service filesystem --help
"""
from __future__ import annotations

import inspect
import logging
import os
import signal
import threading
import time

import local_filesystem_service.filesystem as fs_module
import typer
from local_filesystem_service.backends import (
    BackendConfig,
    get_backend_cli_commands,
    list_backends,
)
from local_filesystem_service.filesystem import (
    FILESERVICE_SERVER_BASE_URI_DEFAULT,
    FILESERVICE_SERVER_BASE_URI_ENV,
    FILESERVICE_STATIC_DIR_ENV,
    FILESERVICE_TEST_FOLDER_MODE_DEFAULT,
    FILESERVICE_TEST_FOLDER_MODE_ENV,
    REDIRECT_HOST_DEFAULT,
    REDIRECT_HOST_ENV,
    REDIRECT_PORT_DEFAULT,
    REDIRECT_PORT_ENV,
    get_backend,
    init_backend,
)
from typing_extensions import Annotated

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("FileSystemService")

# Create Typer app
cli_app = typer.Typer(
    name="local-filesystem-service",
    help="NVIDIA Omniverse Storage API - Combined gRPC and REST Service",
    add_completion=False,
)

# Global variables for server management
exiting = False
grpc_server = None
static_server = None
fastapi_thread = None


def handle_sigint(signum, frame):
    """Handle SIGINT to gracefully shut down servers."""
    global exiting, grpc_server, static_server
    logger.info("Received SIGINT, shutting down!")
    exiting = True
    if grpc_server:
        grpc_server.stop(0)  # Immediate shutdown
    if static_server:
        static_server.should_exit = True  # Signal exit


def _run_services(backend_config: BackendConfig, backend_name: str, grpc_port: int, http_port: int, enable_grpc: bool, enable_rest: bool):
    """Shared logic to initialize backend and run servers."""
    global exiting, grpc_server, static_server, fastapi_thread
    from local_filesystem_service.grpc_service.server import (
        createStaticServer,
        run_static_server,
        startGRPCserver,
    )
    from local_filesystem_service.rest_service import app

    # Update global configuration for redirect endpoints
    if hasattr(backend_config, "redirect_host"):
        fs_module.REDIRECT_HOST = backend_config.redirect_host
    if hasattr(backend_config, "redirect_port"):
        fs_module.REDIRECT_PORT = backend_config.redirect_port

    # Initialize storage backend
    try:
        init_backend(backend_config)
        logger.info(f"Initialized {backend_name} storage backend")
        logger.info(f"  Base URI: {backend_config.base_uri}")
    except ValueError as e:
        logger.error(f"Failed to initialize backend: {e}")
        raise typer.Exit(1)

    # Register backend-specific HTTP routes AFTER backend is initialized
    backend = get_backend()
    backend.register_http_routes(app)
    logger.info("Registered backend HTTP routes")

    # Start servers
    if enable_grpc:
        logger.info(f"Starting gRPC server on port {grpc_port}")
        grpc_server = startGRPCserver(grpc_port, http_port)
        logger.info(f"  gRPC endpoint: localhost:{grpc_port}")

    if enable_rest:
        logger.info(f"Starting HTTP/REST server on port {http_port}")
        static_server = createStaticServer(app, http_port)
        fastapi_thread = threading.Thread(target=run_static_server, args=(static_server,))
        fastapi_thread.start()
        logger.info(f"  REST endpoint: http://localhost:{http_port}")
        logger.info(f"  OpenAPI docs: http://localhost:{http_port}/docs")

    if not enable_grpc and not enable_rest:
        logger.warning("Both gRPC and REST servers are disabled. Exiting.")
        return

    # Set up signal handling and run
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)
    logger.info("Services started successfully")

    try:
        while not exiting:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, forcing shutdown...")
        exiting = True
        if grpc_server:
            grpc_server.stop(0)
        if static_server:
            static_server.should_exit = True

    logger.debug("Waiting for servers to terminate...")
    if fastapi_thread and fastapi_thread.is_alive():
        fastapi_thread.join(5)
    logger.info("Server shut down successfully.")


# Context class to pass common options to subcommands
class ServiceContext:
    def __init__(self):
        self.grpc_port = 50051
        self.http_port = 8011
        self.enable_grpc = True
        self.enable_rest = True


def _build_default_filesystem_config() -> BackendConfig:
    """Build filesystem backend config from environment defaults.

    This keeps no-subcommand startup behavior aligned with Typer envvar parsing
    used by the explicit `filesystem` subcommand.
    """
    backend_commands = get_backend_cli_commands()
    filesystem_cli = backend_commands.get("filesystem")
    if filesystem_cli is None:
        logger.error("Default filesystem backend not found")
        raise typer.Exit(1)

    redirect_port_value = os.getenv(REDIRECT_PORT_ENV, str(REDIRECT_PORT_DEFAULT))
    try:
        redirect_port = int(redirect_port_value)
    except ValueError:
        logger.error(f"Invalid {REDIRECT_PORT_ENV} value: {redirect_port_value!r}")
        raise typer.Exit(1)

    return filesystem_cli(
        base_uri=os.getenv(FILESERVICE_SERVER_BASE_URI_ENV, FILESERVICE_SERVER_BASE_URI_DEFAULT),
        static_dir=os.getenv(FILESERVICE_STATIC_DIR_ENV),
        folder_mode=os.getenv(FILESERVICE_TEST_FOLDER_MODE_ENV, FILESERVICE_TEST_FOLDER_MODE_DEFAULT),
        redirect_host=os.getenv(REDIRECT_HOST_ENV, REDIRECT_HOST_DEFAULT),
        redirect_port=redirect_port,
    )


@cli_app.callback(invoke_without_command=True)
def common_options(
    ctx: typer.Context,
    grpc_port: Annotated[
        int,
        typer.Option(
            "--grpc-port",
            help="Port for gRPC server",
            envvar="GRPC_SERVER_PORT",
        ),
    ] = 50051,
    http_port: Annotated[
        int,
        typer.Option(
            "--http-port",
            help="Port for HTTP/REST server",
            envvar="HTTP_SERVER_PORT",
        ),
    ] = 8011,
    enable_grpc: Annotated[
        bool,
        typer.Option(
            "--grpc/--no-grpc",
            help="Enable gRPC server",
        ),
    ] = True,
    enable_rest: Annotated[
        bool,
        typer.Option(
            "--rest/--no-rest",
            help="Enable REST server",
        ),
    ] = True,
):
    """NVIDIA Omniverse Storage API - Combined gRPC and REST Service.

    Provides both gRPC and REST interfaces for the Storage API. Choose a backend
    subcommand to start the service with that storage backend, or omit the backend
    to use the default filesystem backend.

    Common options apply to all backends and control server ports.
    """
    # Store common options in context for subcommands to access
    ctx.obj = ServiceContext()
    ctx.obj.grpc_port = grpc_port
    ctx.obj.http_port = http_port
    ctx.obj.enable_grpc = enable_grpc
    ctx.obj.enable_rest = enable_rest

    # If no subcommand was invoked, use filesystem backend with defaults
    if ctx.invoked_subcommand is None:
        logger.info("No backend specified, using default filesystem backend")
        backend_config = _build_default_filesystem_config()
        _run_services(backend_config, "filesystem", grpc_port, http_port, enable_grpc, enable_rest)


@cli_app.command(name="list-backends")
def list_backends_command():
    """List all available storage backends."""
    available_backends = list_backends()
    typer.echo("Available storage backends:")
    for backend_name in available_backends:
        typer.echo(f"  {backend_name}")
    typer.echo("\nUse 'python -m local_filesystem_service BACKEND --help' for backend-specific options.")


def create_backend_command(backend_name: str, backend_cli_func):
    """Create a command function for a specific backend.

    This wraps the backend's CLI function to initialize the backend and start services.
    """

    def backend_command_wrapper(ctx: typer.Context, **backend_kwargs):
        """Start service with the specified backend."""
        backend_config: BackendConfig = backend_cli_func(**backend_kwargs)
        _run_services(
            backend_config,
            backend_name,
            ctx.obj.grpc_port,
            ctx.obj.http_port,
            ctx.obj.enable_grpc,
            ctx.obj.enable_rest,
        )

    # Create a merged signature: ctx + all backend parameters
    backend_sig = inspect.signature(backend_cli_func)
    ctx_param = inspect.Parameter("ctx", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=typer.Context)
    new_params = [ctx_param] + list(backend_sig.parameters.values())
    backend_command_wrapper.__signature__ = inspect.Signature(new_params)  # type: ignore[attr-defined]
    backend_command_wrapper.__annotations__ = {"ctx": typer.Context, **backend_cli_func.__annotations__}  # type: ignore[attr-defined]
    backend_command_wrapper.__doc__ = backend_cli_func.__doc__

    return backend_command_wrapper


# Dynamically register all backend CLI commands as subcommands
for backend_name, backend_cli_func in get_backend_cli_commands().items():
    command_func = create_backend_command(backend_name, backend_cli_func)
    cli_app.command(name=backend_name)(command_func)


def main():
    """Entry point for the local-filesystem-service console script."""
    cli_app()


if __name__ == "__main__":
    main()
