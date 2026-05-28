# AI Agent Guide for NVIDIA Omniverse Storage API Implementation

This document provides guidance for AI coding agents (such as Cursor, GitHub Copilot, Codex, etc.) to help developers rapidly implement new storage service backends for the Omniverse Storage API.

## 📋 Project Overview

This package contains:
- **API Specifications**: gRPC (`.proto`) and REST (OpenAPI `.yaml`) interface definitions
- **Reference Implementation**: A Python service serving files from a local filesystem
- **Conformance Tests**: BDD-style tests to validate any new implementation

## 🎯 Two Implementation Paths

### Path A: Quick Prototype (Python Backend Plugin)
**Best for**: Rapid prototyping, proof-of-concepts, Python-native storage systems

Reuse the existing Python service framework by implementing a new storage backend that plugs into the existing gRPC/REST service layer.

### Path B: Production Implementation (Any Language)
**Best for**: Production deployments, performance-critical systems, teams with Go/Java/Rust expertise

Implement the full gRPC and/or REST APIs from scratch in your preferred language.

---

## 📁 Key Files Reference

### API Specifications (MUST READ for any implementation)

| File | Purpose |
|------|---------|
| `proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto` | Core file operations: read, write, delete, stat, enumerate |
| `proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject.proto` | Shared message types and enums |
| `proto/nvidia/omniverse/storage/filefolder/v1beta/filefolder_service.proto` | Folder operations: list, create, delete |
| `proto/nvidia/omniverse/storage/capabilities/v1beta/capabilities.proto` | Service discovery and capabilities |
| `proto/nvidia/omniverse/storage/versioning/v1beta/versioning.proto` | Version enumeration |
| `openapi/fileobject/v1beta/fileobject-api.yaml` | REST API specification for file operations |
| `openapi/filefolder/v1beta/filefolder-api.yaml` | REST API specification for folder operations |
| `openapi/capabilities/v1beta/capabilities-api.yaml` | REST API for capabilities |
| `openapi/versioning/v1beta/versioning-api.yaml` | REST API for versioning |

### Reference Implementation (Path A - Python Backend)

| File | Purpose |
|------|---------|
| `filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py` | **THE KEY INTERFACE** - Abstract base class all backends must implement |
| `filesystem_example/src/local_filesystem_service/backends/backend_factory.py` | Backend registration system with `@register_backend` decorator |
| `filesystem_example/src/local_filesystem_service/backends/cli_registry.py` | CLI argument registration for backends |
| `filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py` | Complete reference implementation |
| `filesystem_example/src/local_filesystem_service/grpc_service/` | gRPC service layer (reusable) |
| `filesystem_example/src/local_filesystem_service/rest_service/` | REST service layer (reusable) |

### Conformance Tests

| File | Purpose |
|------|---------|
| `conformance_tests/README.md` | How to run conformance tests |
| `conformance_tests/src/conformance_tests/features/` | Gherkin feature files defining expected behavior |

---

## 🔧 Path A: Implementing a Python Backend Plugin

### Step 1: Understand the Interface

Read `filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py`. This defines ~40 methods organized into categories:

```
Configuration:
  - base_uri (property)

Resource Address Handling:
  - is_address_valid()
  - is_version_address()
  - create_identity_from_resource_address()
  - address_from_identity()

File Operations:
  - exists()
  - is_file()
  - is_dir()
  - read_from_address()
  - read_from_identity()
  - write_version()
  - stat()
  - stat_identity()
  - remove_by_address()
  - obliterate()
  - copy()
  - move()

Folder Operations:
  - create_folder()
  - list()
  - list_stat()
  - enumerate()
  - remove_empty_folder()

Versioning:
  - enumerate_versions()

Metadata:
  - get_metadata()
  - update_metadata()
  - delete_metadata()

Upload Support:
  - supports_redirect_download()
  - supports_redirect_upload()
  - supports_multipart_upload()
  - construct_redirect_url()
  - encode_upload_id()
  - decode_upload_id()
```

### Step 2: Create Your Backend

Create a new file, e.g., `filesystem_example/src/local_filesystem_service/s3/s3_provider.py`:

```python
from local_filesystem_service.backends.storage_backend_interface import (
    StorageBackendInterface,
    ListEntry,
    Metadata,
    VersionInfo,
    VersionsOrder,
)
from local_filesystem_service.backends.backend_factory import (
    register_backend,
    BackendConfig,
)

@register_backend("s3")
def create_s3_backend(config: BackendConfig) -> StorageBackendInterface:
    """Factory function to create S3 backend."""
    bucket = config.extra_config.get("bucket", "default-bucket")
    return S3StorageBackend(config.base_uri, bucket)

class S3StorageBackend(StorageBackendInterface):
    def __init__(self, base_uri: str, bucket: str):
        self._base_uri = base_uri
        self._bucket = bucket
        # Initialize your S3 client here
    
    @property
    def base_uri(self) -> str:
        return self._base_uri
    
    # Implement all abstract methods...
```

### Step 3: Register CLI Arguments

Create `filesystem_example/src/local_filesystem_service/s3/__init__.py`:

```python
from local_filesystem_service.backends.cli_registry import register_backend_cli
import click

@register_backend_cli("s3")
@click.option("--bucket", default="my-bucket", help="S3 bucket name")
@click.option("--region", default="us-east-1", help="AWS region")
def s3_cli(bucket: str, region: str):
    """S3 storage backend configuration."""
    return {"bucket": bucket, "region": region}
```

### Step 4: Ensure Import

Add import to `filesystem_example/src/local_filesystem_service/backends/__init__.py`:

```python
# Import to trigger registration
from local_filesystem_service.s3 import s3_provider
```

### Step 5: Run Conformance Tests

```bash
# Use the test runner script (handles service lifecycle automatically)
./run_tests.sh

# Or run specific tests during development
./run_tests.sh -k "stat" --no-parallel --verbose
```

For manual testing:
```bash
# Terminal 1: Start your service
cd filesystem_example
poetry install
source .venv/bin/activate
local-filesystem-service s3 --bucket my-test-bucket

# Terminal 2: Run tests
cd conformance_tests
source .venv/bin/activate
./run_tests.sh --test-only
```

---

## 🔧 Path B: Production Implementation from Scratch

### Language-Specific Setup

#### Go
```bash
# Generate Go code from proto files
protoc --go_out=. --go-grpc_out=. proto/nvidia/omniverse/storage/**/*.proto
```

#### Java
```bash
# Use protoc with Java plugin, or use buf.build
protoc --java_out=. --grpc-java_out=. proto/nvidia/omniverse/storage/**/*.proto
```

#### Rust
```bash
# Use tonic for gRPC
# Add to Cargo.toml: tonic-build as build dependency
# In build.rs: tonic_build::compile_protos("proto/...")
```

### Implementation Checklist

#### Core Services to Implement

1. **FileObjectService** (Required)
   - [ ] `Enumerate` - List files recursively
   - [ ] `Stat` - Get file metadata
   - [ ] `Read` - Read file by identity
   - [ ] `ReadFromAddress` - Read file by address
   - [ ] `FetchWriteTypeInfo` - Get upload preferences
   - [ ] `Write` - Upload file (streaming)
   - [ ] `Delete` - Remove file
   - [ ] `CompleteRedirectUpload` - Finalize redirect upload
   - [ ] `UploadPart` - Multipart upload part
   - [ ] `CompleteMultipartUpload` - Finalize multipart
   - [ ] `AbortMultipartUpload` - Cancel multipart

2. **FileFolderService** (Required)
   - [ ] `List` - List folder contents
   - [ ] `CreateFolder` - Create directory
   - [ ] `DeleteFolder` - Remove empty directory

3. **CapabilitiesService** (Required)
   - [ ] `ListServices` - Enumerate available APIs
   - [ ] `ListTopLevelAddresses` - Get root addresses

4. **VersioningService** (Optional but recommended)
   - [ ] `EnumerateVersions` - List file versions

#### REST API Endpoints (if implementing REST)

Map the OpenAPI specifications to HTTP routes:
- `HEAD /v1beta/fileobject/by-address/{resource_address}` → Stat
- `GET /v1beta/fileobject/by-address/{resource_address}` → ReadFromAddress
- `PUT /v1beta/fileobject/by-address/{resource_address}` → Write
- `DELETE /v1beta/fileobject/by-address/{resource_address}` → Delete
- `GET /v1beta/fileobject/data-objects/{resource_address}` → Enumerate
- etc.

### Key Concepts to Understand

#### Resource Address vs Resource Identity

- **Resource Address**: A URI pointing to a *mutable* location (like a file path)
  - Example: `s3-storage://my-bucket/path/to/file.usd`
  - Points to "latest version" at that location

- **Resource Identity**: An opaque, *immutable* identifier for a specific version
  - Example: `s3-storage-id://my-bucket/base64encodedversioninfo`
  - Always refers to the exact same bytes

#### Version Model

Every write creates a new immutable version. The address points to the latest version, but old versions remain accessible via their identities.

#### Error Handling

Use standard gRPC status codes / HTTP status codes:
- `NOT_FOUND` / `404` - Resource doesn't exist
- `PERMISSION_DENIED` / `403` - Access denied
- `INVALID_ARGUMENT` / `400` - Bad request parameters
- `ALREADY_EXISTS` / `409` - Resource already exists (for folders)

---

## 🧪 Testing Your Implementation

### Quick Test Run (Recommended for AI Agents)

The easiest way to test your implementation is using the provided `run_tests.sh` script:

```bash
# Run all tests with parallel execution (fastest)
./run_tests.sh

# Run specific tests (e.g., only stat-related tests)
./run_tests.sh -k "stat"

# Run tests serially with verbose output (for debugging)
./run_tests.sh --no-parallel --verbose -k "stat"

# Force restart if service is already running
./run_tests.sh --force

# Start service only (for manual API exploration)
./run_tests.sh --service-only

# Run tests against already-running service
./run_tests.sh --test-only
```

### Script Options

| Option | Description |
|--------|-------------|
| `--help` | Show usage information |
| `--force` | Kill any existing service on the ports before starting |
| `-k, --keyword PATTERN` | Run only tests matching pattern (pytest -k) |
| `--no-parallel` | Run tests serially (slower but clearer output) |
| `--parallel N` | Number of parallel workers (default: 8) |
| `--verbose` | Extra test output |
| `--service-only` | Start service and wait (don't run tests) |
| `--test-only` | Run tests without starting service |

### Troubleshooting

**Port already in use:**
```bash
# Option 1: Force kill existing service
./run_tests.sh --force

# Option 2: Manually kill and restart
pkill -f "local-filesystem-service"
./run_tests.sh
```

**Service won't start:**
```bash
# Check what's using the ports
lsof -i :8011 -i :50051

# Run service manually to see errors
local-filesystem-service filesystem --static-dir /tmp/test-storage
```

### Manual Testing (Advanced)

If you need more control, you can run tests manually:

```bash
cd conformance_tests
poetry install
source .venv/bin/activate

# Set environment variables for your service
export TEST_STORAGE_API_REST_ENDPOINT=http://localhost:8011
export TEST_STORAGE_API_GRPC_ENDPOINT=localhost:50051
export TEST_STORAGE_API_RESOURCE_BASE=your-scheme://your-authority

# Run tests
run-conformance-tests

# Run specific tests
run-conformance-tests -k "stat" -vv
run-conformance-tests -k "write" -vv
```

### Test Incrementally

Recommended order:
1. Capabilities (service discovery)
2. Stat (basic file metadata)
3. Write + Read (basic I/O)
4. Enumerate (listing)
5. Delete
6. Folder operations
7. Versioning
8. Multipart uploads

---

## 💡 Common Implementation Patterns

### Encoding Resource Identities

Resource identities must be:
- Opaque strings (clients should not parse them)
- URL-safe (use base64url encoding)
- Contain enough info to locate the exact version

Example pattern:
```python
import base64
import json

def create_identity(bucket: str, key: str, version_id: str) -> str:
    data = {"bucket": bucket, "key": key, "version": version_id}
    return "s3-storage-id://bucket/" + base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).decode()

def parse_identity(identity: str) -> dict:
    # Extract base64 part and decode
    ...
```

### Handling Large Files

For files larger than ~10MB, implement redirect-based uploads:
1. Client calls `Write` with size hint
2. Service returns `WriteRedirectProperties` with presigned URL
3. Client uploads directly to storage (S3, Azure Blob, etc.)
4. Client calls `CompleteRedirectUpload` to finalize

### Streaming Responses

For `Enumerate` and `Read`, use streaming:
- Send data in batches/chunks
- Allow client to process incrementally
- Handle backpressure appropriately

---

## 📚 Additional Resources

- **Documentation**: `docs/latest/index.html` (open in browser)
- **Changelog**: `CHANGELOG.md`
- **Feature files**: `conformance_tests/src/conformance_tests/features/` - BDD specs showing expected behavior
- **OpenAPI docs**: Start the reference service and visit `http://localhost:8011/v1beta/fileobject/docs`

---

## 🤖 Prompts for AI Agents

See `PROMPTS.md` for copy-paste prompts to help AI agents assist with common implementation tasks.
