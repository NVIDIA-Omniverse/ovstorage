# Omniverse Filesystem Storage Service

A reference Python implementation of a storage service that serves files from a local filesystem using a content and a version tree
to store old versions of files. This service provides both REST and gRPC interfaces for file operations, and serves as a reference implementation
of the USD Storage API specification.

## Features

- File operations: stat, read, write, enumerate, delete
- Multipart upload support for large files
- Directory operations: list, create, delete
- Versioning support: enumerate versions, read old versions
- Generic metadata store

## Installation

### Prerequisites

- **Python** 3.10, 3.11, or 3.12
- **Poetry** package manager

```bash
# Create virtual environment for poetry
python -m venv .poetry_venv

# Install poetry 
.poetry_venv/bin/pip install poetry
```

### Build from source

```bash
# Install dependencies
.poetry_venv/bin/poetry install 

# Run the installed entrypoint via poetry
.poetry_venv/bin/poetry run local-filesystem-service
```
The results should look similar to this:
```bash
2025-11-18 11:28:00,263 - INFO - gRPC Server launched on port 50051
2025-11-18 11:28:00,264 - INFO - Starting static server...
2025-11-18 11:28:00,272 - INFO - Started server process [362059]
2025-11-18 11:28:00,272 - INFO - Waiting for application startup.
2025-11-18 11:28:00,272 - INFO - Application startup complete.
2025-11-18 11:28:00,272 - INFO - Uvicorn running on http://0.0.0.0:8011 (Press CTRL+C to quit)
```

### Optional: advanced poetry setup

You can also put the poetry command into your PATH and/or activate the virtual environment poetry as created for you to omit   
the path specifications or to run the `local-filesystem-service` command directly without poetry.

To find where poetry created the environment, you run the following command, and will see an output similar to:

```bash
$ .poetry_venv/bin/poetry env info
Virtualenv
Python:         3.10.12
Implementation: CPython
Path:           /home/username/storage-api/filesystem_example/.venv
Executable:     /home/username/storage-api/filesystem_example/.venv/bin/python
Valid:          True

Base
Platform:   linux
OS:         posix
Python:     3.10.12
Path:       /usr
Executable: /usr/bin/python3.10
```

In this example, the environment can be activated via

```bash
source /home/username/storage-api/filesystem_example/.venv/bin/activate
```

Then you can run the service just with 

```bash
local-filesystem-service
```

## Usage

### Quick Start

```bash
# Get help first!
local-filesystem-service --help

# Start with filesystem backend (default settings)
local-filesystem-service

# Help for the specific parameters setting up the local filesystem 
local-filesystem-service filesystem --help

# Start with custom configuration
local-filesystem-service filesystem --static-dir /data/storage

# The service is started as a python module, so this is equivalent:
python -m local_filesystem_service filesystem --static-dir /data/storage
```

### Service Modes

**Combined Service (gRPC + REST):**
```bash
local-filesystem-service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

with BACKEND being `filesystem` as the only option in this version.

**gRPC Only:**
```bash
# via script
local-filesystem-grpc [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]

# via module
python -m local_filesystem_service.grpc_service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS] 
```

**REST Only:**
```bash
# via script
local-filesystem-rest [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]

# via module
python -m local_filesystem_service.rest_service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

**Note**: Each backend (e.g., `filesystem`) has its own subcommand with specific options.

### CLI Structure

**Common Options** (apply to all backends):
- `--grpc-port`: Port for gRPC server (default: 50051)
- `--http-port`: Port for HTTP/REST server (default: 8011)
- `--reload`: Enable auto-reload for development (REST service only)

**Backend Subcommands**:
Each backend has its own subcommand. For example, the `filesystem` backend:
- `--base-uri`: Base URI for resource addresses (default: `file-storage://fileservice`)
- `--static-dir`: Directory for file storage (default: system temp directory)
- `--folder-mode`: Folder simulation mode: `native`, `no_empty`, or `placeholder` (default: `native`)
- `--redirect-host`: Host for redirect URLs (default: `http://localhost`)
- `--redirect-port`: Port for redirect URLs (default: 8011)

**Example**:
```bash
python -m local_filesystem_service --grpc-port 50052 filesystem --static-dir /data
```

### Environment Variables

All CLI options can also be set via environment variables:

- `FILESERVICE_STATIC_DIR`: Directory where files will be stored
- `FILESERVICE_SERVER_BASE_URI`: Base URI for the service, default is "file-storage://fileservice"
- `FILESERVICE_TEST_FOLDER_MODE`: Folder simulation mode, default is "native"
- `GRPC_SERVER_PORT`: Port for the gRPC server
- `HTTP_SERVER_PORT`: Port for the HTTP server
- `REDIRECT_HOST`: Host for redirect URLs
- `REDIRECT_PORT`: Port for redirect URLs

CLI options take precedence over environment variables.

## Testing the Service

Once started, test the service:

```bash
# Test REST API
curl http://localhost:8011/v1beta/capabilities/services

# View OpenAPI documentation for a specific endpoint
open http://localhost:8011/v1beta/fileobject/docs
# or for the filefolder API
open http://localhost:8011/v1beta/filefolder/docs

# Test file upload, size hint is a required parameter
curl -X PUT "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt?data_object_size=64" \
  -H "Content-Type: application/octet-stream" \
  -d "Hello World"

# Test file download
curl http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt
```

# Building a Docker container

## Building a wheel

Using poetry, you can easily make it create deployable version of the service using 

```bash
.poetry_venv/bin/poetry build
```

This places a wheel file which can easily be installed via Python's `pip` command into the `dist` subdirectory by default.

## Building the container

With the wheel created in the `dist` folder, you can use the provided Dockerfile to create a container image using 

```bash
docker build -f Dockerfile -t local-filesystem-service .
```

and the containerized service can be run as a detached daemon while exposing the REST port at 8011 on your localhost.
For persistent storage, mount a host directory (or PVC in Kubernetes) and set `FILESERVICE_STATIC_DIR` to the mount path:

```bash
docker run -d \
  -p=8011:8011 \
  -e FILESERVICE_STATIC_DIR=/data \
  -v "$(pwd)/storage-data:/data" \
  local-filesystem-service
```

The image default command includes the backend subcommand (`filesystem`) so backend env vars are applied.
If you override the container command/args, include `filesystem` explicitly.

You can see it running with 

```bash
docker ps
CONTAINER ID   IMAGE                      COMMAND                  CREATED         STATUS         PORTS                                         NAMES
52109ddea784   local-filesystem-service   "local-filesystem-se…"   3 seconds ago   Up 2 seconds   0.0.0.0:8011->8011/tcp, [::]:8011->8011/tcp   festive_albattani
```

Verify it is running again with CURL:

```bash
curl http://localhost:8011/v1beta/capabilities/services
{"services":[{"service_name":"capabilities","service_versions":["v1beta"]},
{"service_name":"fileobject","service_versions":["v1beta"]},
{"service_name":"filefolder","service_versions":["v1beta"]},
{"service_name":"versioning","service_versions":["v1beta"]}]}
```

To see the "v1alpha" version services by querying the alpha version of the "capabilities" endpoint:

```bash
curl http://localhost:8011/v1alpha/capabilities/services/capabilities/services
{"services":[{"service_name":"capabilities","service_versions":["v1alpha","v1beta"]},
{"service_name":"fileobject","service_versions":["v1alpha","v1beta"]},
{"service_name":"filefolder","service_versions":["v1alpha","v1beta"]},
{"service_name":"versioning","service_versions":["v1alpha","v1beta"]},
{"service_name":"metadata","service_versions":["v1alpha"]}]}
```
