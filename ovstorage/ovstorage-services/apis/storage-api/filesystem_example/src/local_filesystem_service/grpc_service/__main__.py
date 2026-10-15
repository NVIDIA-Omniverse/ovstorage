# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""NVIDIA Omniverse Storage API - gRPC Service Only

This module runs only the gRPC service with minimal HTTP endpoints for redirect-based
operations. Each storage backend has its own subcommand with backend-specific parameters.

Example Usage:
    # Start with filesystem backend
    python -m local_filesystem_service.grpc_service filesystem --static-dir /data/storage

    # Start with custom ports
    python -m local_filesystem_service.grpc_service --grpc-port 50052 filesystem

    # See all available backends
    python -m local_filesystem_service.grpc_service --help

    # See backend-specific options
    python -m local_filesystem_service.grpc_service filesystem --help
"""

import inspect
import signal
import threading
import time

import typer
from fastapi import FastAPI
from local_filesystem_service.backends import (
    BackendConfig,
    get_backend_cli_commands,
    list_backends,
)
from local_filesystem_service.filesystem import (
    get_backend,
    init_backend,
)
from typing_extensions import Annotated

from .server import (
    createStaticServer,
    logger,
    run_static_server,
    startGRPCserver,
)

# Create the FastAPI app at module level
# HTTP routes will be registered lazily after backend initialization
app = FastAPI()

# Create Typer app
cli_app = typer.Typer(
    name="local-filesystem-service-grpc",
    help="NVIDIA Omniverse Storage API - gRPC Service Only",
    add_completion=False,
)

# Global variables for server management
exiting = False
grpc_server = None
static_server = None
fastapi_thread = None


# Context class to pass common options to subcommands
class ServiceContext:
    def __init__(self):
        self.grpc_port = 50051
        self.http_port = 8011


@cli_app.callback()
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
            help="Port for minimal HTTP server (redirect endpoints only)",
            envvar="HTTP_SERVER_PORT",
        ),
    ] = 8011,
):
    """NVIDIA Omniverse Storage API - gRPC Service Only.

    Provides gRPC interface with minimal HTTP endpoints for redirect-based operations.
    The HTTP server only serves redirect endpoints, not the full REST API.

    Common options apply to all backends and control server ports.
    """
    # Store common options in context for subcommands to access
    ctx.obj = ServiceContext()
    ctx.obj.grpc_port = grpc_port
    ctx.obj.http_port = http_port


@cli_app.command(name="list-backends")
def list_backends_command():
    """List all available storage backends."""
    available_backends = list_backends()
    typer.echo("Available storage backends:")
    for backend_name in available_backends:
        typer.echo(f"  {backend_name}")
    typer.echo("\nUse 'python -m local_filesystem_service.grpc_service BACKEND --help' for backend-specific options.")


def create_backend_command(backend_name: str, backend_cli_func):
    """Create a command function for a specific backend.

    This wraps the backend's CLI function to initialize the backend and start services.
    """

    def backend_command_wrapper(ctx: typer.Context, **backend_kwargs):
        """Start gRPC service with the specified backend."""
        global exiting, grpc_server, static_server, fastapi_thread

        # Get backend configuration from the backend's CLI function
        backend_config: BackendConfig = backend_cli_func(**backend_kwargs)

        # Get common options from context
        grpc_port = ctx.obj.grpc_port
        http_port = ctx.obj.http_port

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
        logger.info(f"Starting gRPC server on port {grpc_port}")
        logger.info(f"Starting minimal HTTP server on port {http_port} (redirect endpoints only)")

        grpc_server = startGRPCserver(grpc_port, http_port)
        static_server = createStaticServer(app, http_port)
        fastapi_thread = threading.Thread(target=run_static_server, args=(static_server,))
        fastapi_thread.start()

        exiting = False

        def handle_sigint(signum, frame):
            """Handle SIGINT to gracefully shut down servers."""
            global exiting, grpc_server, static_server
            logger.info("Received SIGINT, shutting down!")
            exiting = True
            if grpc_server:
                grpc_server.stop(0)
            if static_server:
                static_server.should_exit = True

        # Set up signal handling
        signal.signal(signal.SIGINT, handle_sigint)

        logger.info("Services started successfully")
        logger.info(f"  gRPC endpoint: localhost:{grpc_port}")
        logger.info(f"  HTTP redirect endpoints: http://localhost:{http_port}")

        try:
            # Keep the loop running until SIGINT is received
            while not exiting:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt, forcing shutdown...")
            exiting = True
            grpc_server.stop(0)
            static_server.should_exit = True

        logger.debug("Waiting for static server thread to terminate...")
        fastapi_thread.join(5)
        logger.info("Server shut down successfully.")

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
    """Entry point for the local-filesystem-grpc console script."""
    cli_app()


if __name__ == "__main__":
    main()
