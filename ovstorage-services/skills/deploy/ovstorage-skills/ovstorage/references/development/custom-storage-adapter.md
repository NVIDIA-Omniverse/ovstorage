# Custom Storage Adapter Development

## Overview

The Omniverse Storage API provides gRPC and REST API specifications for the data access layer within the Omniverse platform. Using the Storage API, you can overlay a **Storage Adapter** on top of your existing storage system and interface directly with Omniverse.

This guide covers how to:

- Download the Storage API specifications and reference implementation from NGC
- Understand key concepts (Resource Address vs Resource Identity)
- Build a Storage Adapter service (REST and gRPC)
- Write client code that consumes a Storage Adapter
- Run the conformance test suite to validate your implementation

### Downloading from NGC

The Storage API package is available on the NGC registry:

```
nvidia/omniverse/storage-api:{version}
```

Download from: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/storage-api

The package includes proto files, OpenAPI specs, a reference filesystem implementation, and the conformance test suite.

> **Full collection** (all services, charts, and API specs): https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/collections/storage_apis

---

## Package Contents

The downloaded Storage API package contains:

- **Proto files** -- gRPC service definitions under `proto/nvidia/omniverse/storage/fileobject/v1beta/` (and `v1alpha`)
- **OpenAPI specs** -- REST API specifications for the fileobject, filefolder, capabilities, and versioning services
- **`filesystem_example/`** -- A full reference implementation serving versioned files from a local filesystem
- **`conformance_tests/`** -- A runnable test suite that validates any Storage API implementation for spec conformance

---

## Key Concepts

### Resource Address vs Resource Identity

These two concepts are fundamental to the Storage API.

#### Resource Address: Locating Data

A **Resource Address** is a string that acts as a locator for objects within a storage system -- like a file path or URL.

- **Storage-specific semantics** -- format varies by backend (e.g., `s3://bucket/path/to/file.ext` or `my_custom_database://17A56A6F8734E`)
- **Identifies location** -- specifies *where* a data object is; specific storage systems may support query-based addresses (e.g., `s3://bucket/path/to/file.ext?etag=a64be1231acd`)
- **Potentially mutable content** -- content at a given address can change over time
- **Hierarchical organization** -- follows RFC3986 for file-system-like structures, allowing clients to construct new addresses by appending relative paths
- **Routable** -- a storage service should be able to identify its own Resource Addresses to support multi-service deployments

#### Resource Identity: Identifying Specific Data Object Instances

A **Resource Identity** is a string that identifies **a particular version or instance of a data object**.

- **Opaque and storage-service-specific** -- clients should treat it as an opaque string
- **Immutable content guarantee** -- always retrieves the *same content* every time `Read` is called (if available)
- **Durable** -- survives service redeployments; lifetime is tied to the data, not the service
- **Shareable** -- can be shared between users with appropriate permissions
- **Routable** -- a storage service should be able to identify its own Resource Identities

#### Usage Summary

| Concept | Role | Key Guarantees | Used in API Functions |
|---------|------|----------------|----------------------|
| **Resource Address** | Locates data within the storage. Points to a mutable storage location. | Semantics are storage-specific. Content at the address can change over time. | Enumerate, Stat, ReadFromAddress, Write, Delete, Copy |
| **Resource Identity** | Identifies a specific, immutable instance of a data object. | Always retrieves the same content (if available). Durable and shareable. Opaque format. | Stat, EnumerateVersions, Read, Write (as return value), RestoreVersion, Copy (as source) |

---

## Reference Implementation: Filesystem Storage Service

A reference Python implementation is provided in the `filesystem_example` directory. It serves files from a local filesystem using content and version trees to store old versions.

### Features

- File operations: stat, read, write, enumerate, delete
- Multipart upload support for large files
- Directory operations: list, create, delete
- Versioning support: enumerate versions, read old versions
- Generic metadata store

### Installation

**Prerequisites:**
- Python 3.10, 3.11, or 3.12
- Poetry package manager

```bash
# Create virtual environment for poetry
python -m venv .poetry_venv

# Install poetry
.poetry_venv/bin/pip install poetry

# Install dependencies
.poetry_venv/bin/poetry install

# Run the installed entrypoint via poetry
.poetry_venv/bin/poetry run local-filesystem-service
```

Expected output:

```
2025-11-18 11:28:00,263 - INFO - gRPC Server launched on port 50051
2025-11-18 11:28:00,264 - INFO - Starting static server...
2025-11-18 11:28:00,272 - INFO - Started server process [362059]
2025-11-18 11:28:00,272 - INFO - Waiting for application startup.
2025-11-18 11:28:00,272 - INFO - Application startup complete.
2025-11-18 11:28:00,272 - INFO - Uvicorn running on http://0.0.0.0:8011 (Press CTRL+C to quit)
```

### Service Modes

**Combined Service (gRPC + REST):**

```bash
local-filesystem-service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

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

### CLI Options

**Common Options** (apply to all backends):

- `--grpc-port`: Port for gRPC server (default: 50051)
- `--http-port`: Port for HTTP/REST server (default: 8011)
- `--reload`: Enable auto-reload for development (REST service only)

**Filesystem Backend Options:**

- `--base-uri`: Base URI for resource addresses (default: `file-storage://fileservice`)
- `--static-dir`: Directory for file storage (default: system temp directory)
- `--folder-mode`: Folder simulation mode: `native`, `no_empty`, or `placeholder` (default: `native`)
- `--redirect-host`: Host for redirect URLs (default: `http://localhost`)
- `--redirect-port`: Port for redirect URLs (default: 8011)

Example:

```bash
python -m local_filesystem_service --grpc-port 50052 filesystem --static-dir /data
```

### Environment Variables

All CLI options can also be set via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `FILESERVICE_STATIC_DIR` | Directory where files will be stored | system temp |
| `FILESERVICE_SERVER_BASE_URI` | Base URI for the service | `file-storage://fileservice` |
| `FILESERVICE_TEST_FOLDER_MODE` | Folder simulation mode | `native` |
| `GRPC_SERVER_PORT` | Port for the gRPC server | `50051` |
| `HTTP_SERVER_PORT` | Port for the HTTP server | `8011` |
| `REDIRECT_HOST` | Host for redirect URLs | `http://localhost` |
| `REDIRECT_PORT` | Port for redirect URLs | `8011` |

CLI options take precedence over environment variables.

### Capabilities Endpoint

Test the service and check available capabilities:

```bash
# Test REST API
curl http://localhost:8011/v1beta/capabilities/services

# Response:
{"services":[{"service_name":"capabilities","service_versions":["v1beta"]},
{"service_name":"fileobject","service_versions":["v1beta"]},
{"service_name":"filefolder","service_versions":["v1beta"]},
{"service_name":"versioning","service_versions":["v1beta"]}]}
```

```bash
# View OpenAPI documentation for a specific endpoint
open http://localhost:8011/v1beta/fileobject/docs
# or for the filefolder API
open http://localhost:8011/v1beta/filefolder/docs
```

### Docker Containerization

**Building a wheel:**

```bash
.poetry_venv/bin/poetry build
```

This places a wheel file in the `dist` subdirectory.

**Building the container:**

```bash
docker build -f Dockerfile -t local-filesystem-service .
```

**Running the container:**

```bash
docker run -d -p=8011:8011 local-filesystem-service
```

Verify it is running:

```bash
docker ps
curl http://localhost:8011/v1beta/capabilities/services
```

---

## REST Service Example

The Storage API allows data exposure from non-standard storage backends. This section demonstrates building a simple REST service using Python and FastAPI.

### Implementing Stat

Install dependencies:

```
pip install fastapi pydantic uvicorn asyncio
```

Implement the stat endpoint, serving content of a local disk directory via the Storage API:

```python
@app.head("/fileobject/by-address/{resource_address:path}")
async def stat_api(resource_address: str):
    path = os.path.join(STATIC_DIR, resource_address)
    if os.path.exists(path):
        size = os.path.getsize(path)
        modification_time = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat()
        metadata = Metadata(data_object_size=size, last_modified_timestamp=modification_time)
        return JSONResponse(
            status_code=204,
            content=None,
            headers={
                "x-nvidia-omniverse-storage-metadata": metadata.model_dump_json(),
                "x-nvidia-omniverse-storage-resource-identity": create_identity(resource_address, modification_time),
            },
        )
    else:
        raise HTTPException(status_code=404, detail=f"{path} not found on disk")
```

Pydantic model for metadata:

```python
class Metadata(BaseModel):
    data_object_size: int
    last_modified_timestamp: Optional[str] = None
```

### Identity Encoding

The resource identity combines the address and modification date as a base64-encoded JSON package. This emphasizes that the identity format is storage-service-specific and clients should make no assumptions about its content:

```python
def create_identity(relative_path: str, modification_time: str) -> str:
    return binascii.b2a_base64(json.dumps({"p": relative_path, "t": modification_time}).encode("utf-8")).decode("utf-8").strip()
```

### Testing the Stat Endpoint

Place a file `hello.txt` in the `STATIC_DIR` being served:

```
> curl --head localhost:8011/object-store/by-address/hello.txt
HTTP/1.1 204 No Content
date: Fri, 28 Jun 2024 13:17:37 GMT
server: uvicorn
x-nvidia-omniverse-storage-metadata: {"resource_address":"hello.txt","resource_identity":"eyJwIjogImhlbGxvLnR4dCIsIC
J0IjogIjIwMjQtMDYtMjhUMTM6MTI6MzUuNzY3MTM4KzAwOjAwIn0=",
"metadata":{"data_object_size":12,"last_modified_timestamp":"2024-06-28T13:12:35.767138+00:00"}}
content-type: application/json
```

### Read with Streaming

The read operation streams the file back via the HTTP response body:

```python
@app.get("/fileobject/by-identity/{resource_identity:path}")
async def read(resource_identity: str, download_preference: Optional[str] = None):
    relative_path = path_from_identity(urllib.parse.unquote_plus(resource_identity))
    path = os.path.join(STATIC_DIR, relative_path)
    if os.path.exists(path):

        def load_file():
            with open(path, "rb") as f:
                while chunk := f.read(1024):
                    yield chunk

        return StreamingResponse(load_file(), media_type="application/octet-stream")
    else:
        raise HTTPException(status_code=404, detail=f"{path} not found on disk")
```

Download using the identity from the stat response:

```
curl --get localhost:8011/object-store/by-identity/eyJwIjogImhlbGxvLnR4dCIsICJ0IjogIjIwMjQtMDYtMjhUMTM6MTI6MzUuNzY3MTM4KzAwOjAwIn0= -v
*   Trying [::1]:8011...
*   Trying 127.0.0.1:8011...
* Connected to localhost (127.0.0.1) port 8011
> GET /object-store/by-identity/eyJwIjogImhlbGxvLnR4dCIsICJ0IjogIjIwMjQtMDYtMjhUMTM6MTI6MzUuNzY3MTM4KzAwOjAwIn0= HTTP/1.1
> Host: localhost:8011
> User-Agent: curl/8.4.0
> Accept: */*
>
< HTTP/1.1 200 OK
< date: Fri, 28 Jun 2024 13:32:37 GMT
< server: uvicorn
< content-type: application/octet-stream
< transfer-encoding: chunked
<
Hello from your demo server, this is the content of the file hello.txt!
* Connection #0 to host localhost left intact
```

---

## gRPC Service Example

For the gRPC service, generate Python language bindings from the proto files (see proto compilation in the gRPC Client section below).

### FileObjectServiceServicer Subclass

Implement the service by subclassing the generated base class:

```python
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2_grpc import (
    FileObjectServiceServicer,
    add_FileObjectServiceServicer_to_server,
)
from service_utils import (
    STATIC_DIR,
    args,
    create_identity,
)


class FileSystemServiceServicer(FileObjectServiceServicer):
    def Stat(self, request, context):
        path = os.path.join(STATIC_DIR, request.resource_address)
        if os.path.exists(path):
            # First build the ResourceIdentity from resource address and modification time
            modification_time = os.path.getmtime(path)
            modification_time_iso = datetime.fromtimestamp(modification_time, tz=timezone.utc).isoformat()
            resource_identity = fileobject_pb2.ResourceIdentity(
                encoded_identity=create_identity(request.resource_address, modification_time_iso)
            )
            # Then create the Metadata info using google Timestamp
            stat_result = os.stat(path)
            modification_time_seconds = int(stat_result.st_mtime)
            nanos = int((stat_result.st_mtime - modification_time_seconds) * 1e9)
            timestamp = timestamp_pb2.Timestamp(seconds=int(stat_result.st_mtime), nanos=nanos)
            metadata = fileobject_pb2.Metadata(data_object_size=stat_result.st_size, last_modified_timestamp=timestamp)

            # Now return the result
            return fileobject_service_pb2.StatResponse(
                resource_info=fileobject_pb2.ResourceInfo(resource_identity=resource_identity, metadata=metadata)
            )
        else:
            context.abort(grpc.StatusCode.NOT_FOUND, f"file not found: {path}")
```

### Server Setup

```python
    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
    add_FileObjectServiceServicer_to_server(FileSystemServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print(f"GRPC Server listening on port 50051 serving directory '{STATIC_DIR}'")
    server.wait_for_termination()
```

### gRPC Reflection

Enable reflection to simplify `grpcurl` commands:

```
pip install grpcio-reflection
```

Modify the server launch to include reflection:

```python
    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
    add_FileObjectServiceServicer_to_server(FileSystemServiceServicer(), server)

    # Enable reflection
    from grpc_reflection.v1alpha import reflection

    SERVICE_NAMES = (
        nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2.DESCRIPTOR.services_by_name["FileObjectService"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print(f"GRPC Server listening on port 50051 serving directory '{STATIC_DIR}'")
    server.wait_for_termination()
```

### Testing with grpcurl

List enabled services:

```
> grpcurl -plaintext localhost:50051 list
grpc.reflection.v1beta.ServerReflection
nvidia.omniverse.storage.fileobject.v1beta.FileObjectService
```

Describe the service:

```
> grpcurl -plaintext localhost:50051 describe nvidia.omniverse.storage.fileobject.v1beta.FileObjectService
nvidia.omniverse.storage.fileobject.v1beta.FileObjectService is a service:
service FileObjectService {
  rpc Stat ( .nvidia.omniverse.storage.fileobject.v1beta.StatRequest ) returns ( .nvidia.omniverse.storage.fileobject.v1beta.StatResponse );
}
```

Call Stat without proto imports (using reflection):

```
> grpcurl -plaintext -d "{\"resource_address\": \"hello.txt\"}" localhost:50051 nvidia.omniverse.storage.fileobject.v1beta.FileObjectService.Stat
```

Call Stat with proto imports (without reflection):

```
grpcurl -plaintext -d "{\"resource_address\": \"hello.txt\"}" -import-path proto/nvidia/omniverse/storage/fileobject/v1beta -import-path proto -proto fileobject_service.proto localhost:50051 nvidia.omniverse.storage.fileobject.v1beta.FileObjectService.Stat
```

Expected reply:

```json
{
  "resourceInfo": {
    "resourceIdentity": {
      "encodedIdentity": "eyJwIjogImhlbGxvLnR4dCIsICJ0IjogIjIwMjQtMDYtMjhUMTM6MTI6MzUuNzY3MTM4KzAwOjAwIn0="
    },
    "metadata": {
      "dataObjectSize": "12",
      "lastModifiedTimestamp": "2024-06-28T13:12:35.767138242Z"
    }
  }
}
```

---

## REST Client Examples

Python is an excellent choice for writing a client that consumes the Storage API.

### Client Library Setup

```
pip install requests
```

The Storage API endpoint is not auto-discovered. You need the endpoint address. Example:
- REST endpoint on localhost: `http://127.0.0.1:8011/fileobject`
- gRPC connection string: `127.0.0.1:50051`

> **Port distinction:** The Python reference filesystem example uses gRPC port **50051** and REST port **8011**. The NVIDIA production adapter uses gRPC port **8011** and REST port **8012**.

### Stat (HEAD)

```python
def stat(example_server_address: str, resource_address: str):
    api_url = example_server_address + f"/by-address/{urllib.parse.quote_plus(resource_address)}"
    response = requests.head(api_url)
    if response.status_code == 204:
        result = json.loads(response.headers["x-nvidia-omniverse-storage-metadata"])
        print(result)
    else:
        print(f"Error calling stat, result code is {response.status_code}")
```

A successful stat returns HTTP 204 with metadata in the `x-nvidia-omniverse-storage-metadata` response header.

### Download (Body)

Stream data directly via the HTTP response body:

```python
def download_via_body(example_server_address: str, resource_address: str, destination_file_name: str):
    api_url = example_server_address + f"/by-address/{urllib.parse.quote_plus(resource_address)}?download_preference=body"
    response = requests.get(api_url, stream=True)
    if response.status_code == 200:
        with open(destination_file_name, "wb") as downloaded_file:
            for chunk in response.iter_content(chunk_size=None):
                downloaded_file.write(chunk)
        print(f"finished writing to file {destination_file_name}")
    else:
        print(f"Error downloading {resource_address}, result code is {response.status_code}")
```

### Download (Redirect)

For scalable environments, the service may return a redirect:

```python
def download_via_redirect(example_server_address: str, resource_address: str, destination_file_name: str):
    api_url = example_server_address + f"/by-address/{urllib.parse.quote_plus(resource_address)}?download_preference=redirect"
    response = requests.get(api_url, stream=True)
    if response.status_code == 300:
        redirection_properties = json.loads(response.content)
        redirected_response = requests.get(
            redirection_properties["redirect_target_url"], headers=redirection_properties["additional_headers"], stream=True
        )
        if redirected_response.status_code == 200:
            with open(destination_file_name, "wb") as downloaded_file:
                for chunk in redirected_response.iter_content(chunk_size=None):
                    downloaded_file.write(chunk)
            print(f"finished writing to file {destination_file_name}")
        else:
            print(f"Error downloading {resource_address} after redirection, result code is {redirected_response.status_code}")
    else:
        print(f"Error downloading {resource_address}, result code is {response.status_code}")
```

### Combined Download Client

A complete flexible download client handling both body and redirect responses:

```python
def download(example_server_address: str, resource_address: str, destination_file_name: str):
    api_url = example_server_address + f"/by-address/{urllib.parse.quote_plus(resource_address)}"
    response = requests.get(api_url, stream=True)
    if response.status_code == 200:
        with open(destination_file_name, "wb") as downloaded_file:
            for chunk in response.iter_content(chunk_size=None):
                downloaded_file.write(chunk)
        print(f"finished writing to file {destination_file_name}")
    elif response.status_code == 300:
        redirection_properties = json.loads(response.content)
        if redirection_properties["method"] == "get":
            redirected_response = requests.get(redirection_properties["redirect_target_url"], stream=True)
        elif redirection_properties["method"] == "post":
            redirected_response = requests.post(redirection_properties["redirect_target_url"], stream=True)
        else:
            raise RuntimeError(f"Download verb {redirection_properties['method']} not implemented")

        if redirected_response.status_code == 200:
            with open(destination_file_name, "wb") as downloaded_file:
                for chunk in redirected_response.iter_content(chunk_size=None):
                    downloaded_file.write(chunk)
            print(f"finished writing to file {destination_file_name}")
        else:
            print(f"Error downloading {resource_address} after redirection, result code is {redirected_response.status_code}")
    else:
        print(f"Error downloading {resource_address}, result code is {response.status_code}")
```

### Upload (Body + Redirect + Multipart)

To write a file object, call `PUT /fileobject/by-address/<address>` providing the contents and specifying the length in the `data_object_size` query parameter. The service responds with HTTP 201 (direct write success) or HTTP 300 (redirect/multipart instructions):

```python
def upload(address: str, upload_preference: str | None, content: IO[bytes]):
    """Upload a file object at the specified address using REST interface."""

    content_length = get_content_length(content)
    if not upload_preference:
        upload_preference = _get_upload_preference(address, content_length)

    write_response = requests.put(
        f"{BASE_URL}/fileobject/by-address/{quote_plus(address)}",
        data=content,
        headers={
            "Expect": "100-continue",
        },
        params={
            key: value
            for key, value in (
                ("data_object_size", content_length),
                ("upload_preference", upload_preference),
            )
            if value is not None
        },
    )
    write_response.raise_for_status()

    if write_response.status_code == 201:
        return

    if write_response.status_code == 300:
        content.seek(0)

        write_response_json: WriteResponse = write_response.json()
        if (redirect := write_response_json.get("redirect")) is not None:
            return _write_via_redirect(address, redirect, content)
        if (multipart := write_response_json.get("multipart")) is not None:
            return _write_via_multipart(address, multipart, content)

    raise Exception("PUT write got unexpected response.")
```

**Redirect write:**

```python
def _write_via_redirect(address: str, params: WriteRedirectParams, content: IO[bytes]):
    response = requests.request(
        url=params["redirect_target_url"],
        method=params["method"].upper(),
        headers={h["name"]: h["value"] for h in params["additional_headers"]},
        data=content,
    )
    response.raise_for_status()

    # Optionally, obtain the resource information of the just uploaded file object
    requested_headers = {name.lower() for name in params["completion_header_names"]}
    completion = requests.post(
        f"{BASE_URL}/fileobject/by-address/{quote_plus(address)}/redirect/complete",
        json={
            "additional_headers": [
                {"name": response_key, "value": response.headers[response_key]}
                for response_key in response.headers
                if response_key.lower() in requested_headers
            ]
        },
    )
    completion.raise_for_status()
```

**Multipart upload with prepare/complete:**

```python
def _write_via_multipart(address: str, params: MultipartUploadParams, content: IO[bytes]):
    # Build a list of redirect URLs to upload the parts to
    redirects = [params["first_part_write_redirect"]]

    # Calculate the number of parts, and retrieve the pre-signed URLs
    total_part_count, part_size, content_length = part_count_for_multipart_upload(
        content, params["minimum_size_per_part"], params["maximum_size_per_part"]
    )
    if total_part_count > 1:
        response = requests.post(
            f"{BASE_URL}/fileobject/by-address/{quote_plus(address)}/multipart/prepare",
            json={
                "upload_id": params["upload_id"],
                "part_number": 1,
                "part_count": total_part_count - 1,
            },
        )
        if response.status_code != 200:
            print(response)
            raise Exception("POST multipart prepare got unexpected response.")

        redirects.extend(response.json()["part_write_redirects"])

    response = requests.post(
        f"{BASE_URL}/fileobject/by-address/{quote_plus(address)}/multipart/complete",
        json={
            "upload_id": params["upload_id"],
            "parts": [
                _write_part(part_number, redirects[part_number], part)
                for part_number, part in enumerate(
                    split_contents_for_multipart_upload(
                        content,
                        max_part_size=params.get("maximum_size_per_part"),
                        min_part_size=params.get("minimum_size_per_part"),
                        max_parts=params.get("maximum_parts_number"),
                    ),
                )
            ],
        },
    )
    if response.status_code != 200:
        raise Exception("Post multipart complete got unexpected response.")


def _write_part(part_number: int, redirect, content: SupportsRead) -> CompletedUploadPart:
    return {
        "part_number": part_number,
        "additional_headers": [
            {
                "name": name,
                "value": value,
            }
            for name, value in upload_part(
                redirect["redirect_target_url"],
                redirect["method"],
                content,
                upload_headers=dict([(h["name"], h["value"]) for h in redirect["additional_headers"]]),
                return_headers=redirect["completion_header_names"],
            )
        ],
    }
```

**Upload preference selection:**

```python
def _get_upload_preference(address: str, size: int) -> str | None:
    response = requests.get(f"{BASE_URL}/fileobject/upload-options/by-address/{quote_plus(address)}")
    response.raise_for_status()

    for interval in response.json()["write_type_intervals"]:
        min_size = interval.get("minimum_data_object_size")
        max_size = interval.get("maximum_data_object_size")
        if min_size and min_size > size:
            continue

        if max_size and max_size < size:
            continue

        return interval["preferred_upload_method"]

    return None
```

### Listing (List + ListStat with Pagination)

REST exposes token-based pagination "list" and "list with stat" endpoints:

```python
def list_file_folders(resource_address: str, stat: bool = False, max_page_size: int | None = None):
    with Session() as session:
        if stat:
            for list_stat_response in list_stat_file_folders_paginated(session, resource_address, max_page_size):
                handle_list_stat_file_folders_response(list_stat_response)
        else:
            for list_response in list_file_folders_paginated(session, resource_address, max_page_size):
                handle_list_file_folders_response(list_response)


def fetch_paginated(session: Session, url: str, max_page_size: int | None) -> Iterable[dict]:
    query_params = {}
    if max_page_size:
        query_params["max_page_size"] = max_page_size

    while True:
        response = session.get(url, params=query_params)
        response.raise_for_status()

        response_json = response.json()
        yield response_json

        if continuation_handle := response_json.get("next_continuation_handle"):
            query_params["continuation_handle"] = continuation_handle
        else:
            break


def list_file_folders_paginated(
    session: Session,
    address: str,
    max_page_size: int | None,
) -> Iterable[ListFileFoldersResponse]:
    return fetch_paginated(
        session,
        f"{REST_SERVICE_ADDRESS}/filefolder/list/{quote_plus(address)}",
        max_page_size,
    )


def list_stat_file_folders_paginated(
    session: Session,
    address: str,
    max_page_size: int | None,
) -> Iterable[ListStatFileFoldersResponse]:
    return fetch_paginated(
        session,
        f"{REST_SERVICE_ADDRESS}/filefolder/liststat/{quote_plus(address)}",
        max_page_size,
    )
```

### Delete

```python
def delete(
    example_server_address: str,
    resource_address: str,
):
    api_url = example_server_address + f"/by-address/{urllib.parse.quote_plus(resource_address)}"
    response = requests.delete(api_url)
    if response.status_code == 204:
        print(f"Done deleting via rest, file {resource_address}!")
    else:
        print(f"Error deleting {resource_address}, result code is {response.status_code}")
        print(response.json())
        raise Exception("Could not delete")
```

The DELETE endpoint always returns a 204 status code, regardless of whether the object exists.

---

## gRPC Client Examples

### Proto Compilation

Install the gRPC tools:

```
pip install grpcio grpcio-tools
```

Generate Python language bindings from the proto files:

```
python -m grpc_tools.protoc --python_out=. --pyi_out=. --grpc_python_out=. --proto_path=proto proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject.proto proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto proto/nvidia/omniverse/storage/capabilities/v1beta/capabilities.proto proto/nvidia/omniverse/storage/filefolder/v1beta/filefolder_service.proto
```

This creates the required Python files in the `nvidia` subdirectory. Adjust paths and number of files to match the version of the storage API definitions.

### Stat

```python
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2_grpc import (
    FileObjectServiceStub,
)


def stat(grpc_address: str, resource_address: str):
    with grpc.insecure_channel(grpc_address) as channel:
        storage_api_server = FileObjectServiceStub(channel)
        try:
            response = storage_api_server.Stat(StatRequest(resource_address=resource_address))
            print(f"{resource_address}: size {response.resource_info.metadata.data_object_size}")
        except grpc.RpcError as e:
            print(f"Failure to stat {resource_address}: {str(e)}")
```

### ReadFromAddress (Streaming)

Download data by iterating over the streaming response:

```python
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2_grpc import (
    FileObjectServiceStub,
)


def download(
    grpc_address: str,
    resource_address: str,
    destination_file_name: str,
    download_preference: DownloadPreference,
):
    with grpc.insecure_channel(grpc_address) as channel:
        storage_api_server = FileObjectServiceStub(channel)
        try:
            with open(destination_file_name, "wb") as destination_file:
                for reply in storage_api_server.ReadFromAddress(
                    ReadFromAddressRequest(resource_address=resource_address, download_preference=download_preference)
                ):
                    if reply.HasField("resource_info"):
                        print(f"Found {resource_address}, downloading {reply.resource_info.metadata.data_object_size} bytes")
                    elif reply.HasField("chunk"):
                        destination_file.write(reply.chunk.chunk)
                    elif reply.HasField("redirect"):
                        redirected_response = requests.get(reply.redirect.redirect_target_url, stream=True)
                        if redirected_response.ok:
                            for chunk in redirected_response.iter_content(chunk_size=None):
                                destination_file.write(chunk)
                            print(f"Done downloading from webserver file {destination_file_name} written!")
                            return
                        else:
                            raise Exception(f"{reply.redirect.redirect_target_url} failed to download")
                    else:
                        raise Exception(f"Unexpected reply {reply}")
                print(f"Done downloading via grpc, file {destination_file_name} written!")
        except grpc.RpcError as e:
            print(f"Failure to download {resource_address}: {str(e)}")
```

The response stream returns first the metadata, then either a stream of chunks or redirection data.

### Write (Bidirectional Streaming)

Write is initiated by sending a `WriteRequest` with `resource_address` and `data_object_size`. The service responds with a flow control message: `WriteChunksAccepted` (stream chunks), `WriteRedirect` (redirect write), or `CreateMultipartUploadResponse` (multipart write):

```python
def upload(channel: Channel, address: str, upload_preference: str | None, content: IO[bytes]):
    """Upload the contents of a file object at the specified address."""

    content_length = get_content_length(content)
    if upload_preference:
        chosen_upload_preference = _string_to_upload_preference(upload_preference)
    else:
        chosen_upload_preference = _get_upload_preference(channel, address, content_length)

    service = FileObjectServiceStub(channel)
    with _write_message_queue() as (requests, request_iterator):
        requests.put(
            WriteRequest(
                params=WriteParameters(
                    destination_resource_address=address,
                    data_object_size=content_length,
                    upload_preference=chosen_upload_preference,
                ),
            ),
        )

        write_responses: Iterator[WriteResponse] = service.Write(request_iterator)

        flow_control_message = next(write_responses)

        # A service may immediately respond with a "resource info" message for 0-byte writes
        if flow_control_message.HasField("resource_info"):
            return

        # If we receive a "write chunks accepted" message, stream the chunks
        if flow_control_message.HasField("write_chunks_accepted"):
            for chunk in _slice_content(content):
                requests.put(WriteRequest(chunk=chunk))

            # End chunk transmission
            requests.put(None)

            resource_info_response = next(write_responses)
            if resource_info_response.HasField("resource_info"):
                return

            raise Exception("Resource info message is expected.")

    # Write redirect and multipart upload close the write stream first
    if flow_control_message.HasField("write_redirect"):
        _write_via_redirect(service, address, flow_control_message.write_redirect, content)
        return

    if flow_control_message.HasField("multipart_upload"):
        _write_via_multipart(service, address, flow_control_message.multipart_upload, content)
        return

    raise Exception("Unexpected flow control message.")
```

**gRPC redirect write:**

```python
def _write_via_redirect(service: FileObjectServiceStub, address: str, parameters: WriteRedirectProperties, content: IO[bytes]):
    response = requests.request(
        url=parameters.redirect_target_url,
        method=_upload_method_to_string(parameters.method),
        headers={header.name: header.value for header in parameters.additional_headers},
        data=content,
    )
    response.raise_for_status()

    requested_headers = set(parameters.completion_header_names)
    response_headers_lower = {key.lower(): key for key in response.headers}

    service.CompleteRedirectUpload(
        CompleteRedirectUploadRequest(
            destination_resource_address=address,
            additional_headers=[
                Header(name=x, value=response.headers[response_headers_lower[x.lower()]])
                for x in requested_headers
                if x.lower() in response_headers_lower
            ],
        )
    )
```

**gRPC multipart write:**

```python
def _write_via_multipart(service: FileObjectServiceStub, address: str, parameters: CreateMultipartUploadResponse, content: IO[bytes]):
    redirects = [parameters.first_part_write_redirect]

    total_part_count, part_size, content_length = part_count_for_multipart_upload(
        content, parameters.minimum_size_per_part, parameters.maximum_size_per_part
    )
    if total_part_count > 1:
        response: UploadPartResponse = service.UploadPart(
            UploadPartRequest(
                upload_id=parameters.upload_id,
                destination_resource_address=address,
                part_number=1,
                part_count=total_part_count - 1,
            ),
        )
        redirects.extend(response.part_write_redirects)

    completed_parts = []
    for part_number, part in enumerate(
        split_contents_for_multipart_upload(
            content,
            min_part_size=parameters.minimum_size_per_part,
            max_part_size=parameters.maximum_size_per_part,
            max_parts=parameters.maximum_parts_number,
        )
    ):
        completed_parts.append(_write_part(redirects[part_number], part_number, part))

    service.CompleteMultipartUpload(
        CompleteMultipartUploadRequest(
            upload_id=parameters.upload_id,
            destination_resource_address=address,
            parts=completed_parts,
        ),
    )


def _write_part(redirect: WriteRedirectProperties, part: int, content: SupportsRead) -> CompletedUploadPart:
    return CompletedUploadPart(
        part_number=part,
        headers=[
            Header(name=name, value=value)
            for name, value in upload_part(
                url=redirect.redirect_target_url,
                method=_upload_method_to_string(redirect.method),
                upload_headers=dict([(header.name, header.value) for header in redirect.additional_headers]),
                return_headers=[name for name in redirect.completion_header_names],
                content=content,
            )
        ],
    )
```

### FetchWriteTypeInfo

Determine the preferred upload method before writing:

```python
def _get_upload_preference(channel: Channel, resource_address: str, size: int) -> UploadPreference:
    client = FileObjectServiceStub(channel)
    response = client.FetchWriteTypeInfo(FetchWriteTypeInfoRequest(destination_resource_address=resource_address))

    for interval in response.write_type_intervals:
        if interval.minimum_data_object_size and interval.minimum_data_object_size > size:
            continue

        if interval.maximum_data_object_size and interval.maximum_data_object_size < size:
            continue

        return interval.preferred_upload_method

    return UploadPreference.UPLOAD_PREFERENCE_UNSPECIFIED
```

**Opportunistic writes:** For small uploads, clients can stream `Chunk` messages without waiting for `WriteChunksAccepted`. For larger files, call `FetchWriteTypeInfo` first to avoid traffic congestion from rejected chunks.

### List

Use the `List` or `ListStat` operation from `FileFolderService`:

```python
def list_file_folders(channel: Channel, resource_address: str, stat: bool = False):
    client = FileFolderServiceStub(channel)

    if stat:
        for list_stat_message in client.ListStat(ListStatRequest(folder=FolderAddress(uri=resource_address))):
            handle_list_stat_message(list_stat_message)
    else:
        for list_message in client.List(ListRequest(folder=FolderAddress(uri=resource_address))):
            handle_list_message(list_message)
```

`ListStat` might be significantly slower than `List` depending on the storage backend.

### Delete

```python
from nvidia.omniverse.storage.fileobject.v1alpha.fileobject_service_pb2_grpc import (
    FileObjectServiceStub,
)


def delete(
    grpc_address: str,
    resource_address: str,
):
    with grpc.insecure_channel(grpc_address) as channel:
        storage_api_server = FileObjectServiceStub(channel)
        try:
            reply = storage_api_server.Delete(DeleteRequest(resource_address=resource_address))
            print(f"Done deleting via grpc, file {resource_address}!")
        except grpc.RpcError as e:
            print(f"Failure to delete {resource_address}: {str(e)}")
```

The Delete operation is idempotent and returns OK even if the file does not exist.

---

## Conformance Test Suite

The conformance test suite verifies that a Storage API implementation behaves in a way that generic client software can reliably depend on. Tests are written in Gherkin specification language and executed via `pytest-bdd`.

This is **not** a comprehensive quality or performance benchmark. It ensures that different Storage API implementations expose a consistent contract so clients can interact with them uniformly.

### Installation

**Prerequisites:**
- Python 3.10, 3.11, or 3.12
- Poetry package manager

```bash
# Run these commands within the conformance tests subdirectory
cd conformance_tests

# Create virtual environment for poetry
python -m venv .poetry_venv

# Install poetry
.poetry_venv/bin/pip install poetry

# Install dependencies
.poetry_venv/bin/poetry install

# Activate the poetry-created virtual environment
source .venv/bin/activate
```

### Running Tests

Start a Storage API implementation first:

```bash
# Start the service with default ports
local-filesystem-service filesystem --static-dir /tmp/storage
```

Default endpoints:
- REST endpoint: `http://localhost:8011`
- gRPC endpoint: `localhost:50051`
- Resource address base: `file-storage://fileservice`

Run the conformance tests:

```bash
# After successfully running `poetry install` above, activate the environment:
source .venv/bin/activate

# Run the test suite:
run-conformance-tests
```

This command uses `pytest` under the hood, loads the default test data generator plugin (`conformance_tests.example_fixtures.storageapi_testdata_generator`), and executes the full Gherkin-based conformance suite.

Extra arguments are forwarded to pytest:

```bash
run-conformance-tests -k "stat" -vv
```

### Environment Variables

#### Core Storage API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_STORAGE_API_REST_ENDPOINT` | `http://localhost:8011` | Base URL of the Storage API REST endpoint |
| `TEST_STORAGE_API_GRPC_ENDPOINT` | `localhost:50051` | Host and port of the gRPC endpoint |
| `TEST_STORAGE_API_RESOURCE_BASE` | `file-storage://fileservice` | Base resource address prefix for test namespaces |
| `STORAGEAPI_TEST_HTTP_TIMEOUT` | `60` seconds | Global timeout for REST client HTTP calls |

#### Error Condition Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_INVALID_RESOURCE_ADDRESS` | `c:d:e:\0` | Intentionally invalid resource address for negative tests |
| `TEST_INVALID_RESOURCE_IDENTITY` | `c:d:e:\0` | Intentionally invalid resource identity for negative tests |

These values should not correspond to valid addresses or identities in your implementation.

#### OpenAPI Verification

| Variable | Required | Description |
|----------|----------|-------------|
| `OASDIFF_EXECUTABLE` | Required for OpenAPI tests | Path to the `oasdiff` binary used to compare schemas |
| `TEST_EXACT_OPENAPI_MATCH` | No (default: `false`) | When `true`, enables strict OpenAPI schema comparison tests |

#### S3/Boto3 Test Data Generator

An alternative test data generator is provided in `conformance_tests.example_fixtures.boto3_testdata_generator` for S3-compatible backends. Set the pytest plugin via `PYTEST_PLUGINS`.

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | -- | Standard AWS credentials |
| `AWS_SECRET_ACCESS_KEY` | -- | Standard AWS credentials |
| `AWS_REGION` | `us-east-1` | AWS region |
| `TEST_STORAGE_API_BOTO3_CONNECT_TIMEOUT` | `5.0` seconds | Connection timeout for S3 client |
| `TEST_STORAGE_API_BOTO3_MAX_POOL_CONNECTIONS` | `20` | Maximum pooled HTTP connections for S3 client |
| `TEST_STORAGE_API_BOTO3_BUCKET_NAME` | `sapiv` | Name of the bucket for test objects |
| `CREATE_FOLDER` | `false` | When `true`, creates zero-byte objects for folders; when `false`, folders are inferred |

#### Test Execution Control

| Variable | Description |
|----------|-------------|
| `PYTEST_PLUGINS` | When unset, defaults to `conformance_tests.example_fixtures.storageapi_testdata_generator`. Set to another plugin (e.g., the boto3 generator or your own `AbstractTestDataGenerator` subclass) to change test data creation. |

### Reporting

The conformance tests write standard output, logging, and pytest reports to the current working directory.

---

## Testing Against a Deployment

To run conformance tests or client code against a Storage API service running in a Kubernetes cluster, use port-forwarding:

```bash
# Forward the REST and gRPC ports from the storage service pod
kubectl port-forward svc/storage-service 8011:8011 50051:50051 -n <namespace>
```

Then configure the conformance test environment variables to point to the forwarded ports:

```bash
export TEST_STORAGE_API_REST_ENDPOINT=http://localhost:8011
export TEST_STORAGE_API_GRPC_ENDPOINT=localhost:50051
export TEST_STORAGE_API_RESOURCE_BASE=<your-service-resource-base>

run-conformance-tests
```

Replace `<namespace>` with your deployment namespace (e.g., `storage-apis-dev` for local or `storage-apis` for full deployments) and `<your-service-resource-base>` with the appropriate resource address prefix for your storage adapter.
