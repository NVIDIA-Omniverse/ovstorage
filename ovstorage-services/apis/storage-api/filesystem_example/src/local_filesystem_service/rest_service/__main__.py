# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""NVIDIA Omniverse Storage API - REST Service Only

This module runs only the REST/HTTP server with the full Storage API.
Each storage backend has its own subcommand with backend-specific parameters.

Example Usage:
    # Start with filesystem backend
    python -m local_filesystem_service.rest_service filesystem --static-dir /data/storage

    # Start with custom port
    python -m local_filesystem_service.rest_service --http-port 9000 filesystem

    # Enable auto-reload for development
    python -m local_filesystem_service.rest_service --reload filesystem

    # See all available backends
    python -m local_filesystem_service.rest_service --help

    # See backend-specific options
    python -m local_filesystem_service.rest_service filesystem --help
"""

import inspect
import logging

import typer
import uvicorn
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

# Import app to register all routes
from .routes import app

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("RESTService")

# Create Typer app
cli_app = typer.Typer(
    name="local-filesystem-service-rest",
    help="NVIDIA Omniverse Storage API - REST Service Only",
    add_completion=False,
)


# Context class to pass common options to subcommands
class ServiceContext:
    def __init__(self):
        self.http_port = 8011
        self.reload = False


@cli_app.callback()
def common_options(
    ctx: typer.Context,
    http_port: Annotated[
        int,
        typer.Option(
            "--http-port",
            help="Port for HTTP/REST server",
            envvar="HTTP_SERVER_PORT",
        ),
    ] = 8011,
    reload: Annotated[
        bool,
        typer.Option(
            "--reload",
            help="Enable auto-reload for development",
        ),
    ] = False,
):
    """NVIDIA Omniverse Storage API - REST Service Only.

    Provides complete HTTP REST API for the Storage API, including all file operations,
    folder operations, versioning, and metadata.

    Common options apply to all backends and control server behavior.
    """
    # Store common options in context for subcommands to access
    ctx.obj = ServiceContext()
    ctx.obj.http_port = http_port
    ctx.obj.reload = reload


@cli_app.command(name="list-backends")
def list_backends_command():
    """List all available storage backends."""
    available_backends = list_backends()
    typer.echo("Available storage backends:")
    for backend_name in available_backends:
        typer.echo(f"  {backend_name}")
    typer.echo("\nUse 'python -m local_filesystem_service.rest_service BACKEND --help' for backend-specific options.")


def create_backend_command(backend_name: str, backend_cli_func):
    """Create a command function for a specific backend.

    This wraps the backend's CLI function to initialize the backend and start the service.
    """

    def backend_command_wrapper(ctx: typer.Context, **backend_kwargs):
        """Start REST service with the specified backend."""
        # Get backend configuration from the backend's CLI function
        backend_config: BackendConfig = backend_cli_func(**backend_kwargs)

        # Get common options from context
        http_port = ctx.obj.http_port
        reload_flag = ctx.obj.reload

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

        # Start server
        logger.info(f"Starting REST server on port {http_port}")
        logger.info(f"  REST endpoint: http://localhost:{http_port}")
        logger.info(f"  OpenAPI docs: http://localhost:{http_port}/docs")

        if reload_flag:
            logger.info("  Auto-reload: ENABLED")

        uvicorn.run(
            "local_filesystem_service.rest_service:app",
            host="0.0.0.0",
            port=http_port,
            reload=reload_flag,
            log_level="info",
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
    """Entry point for the local-filesystem-rest console script."""
    cli_app()


if __name__ == "__main__":
    main()
