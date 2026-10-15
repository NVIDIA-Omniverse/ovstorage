# NVIDIA Omniverse Storage API

The Omniverse Storage API provides gRPC and REST interface specifications for implementing storage services compatible with the NVIDIA Omniverse platform.

## What's Included

| Directory | Description                                               |
|-----------|-----------------------------------------------------------|
| `proto/` | gRPC Protocol Buffer definitions                          |
| `openapi/` | REST API OpenAPI specifications                           |
| `filesystem_example/` | Python reference implementation                           |
| `conformance_tests/` | Test suite to validate implementations                    |
| `docs/` | Documentation (open `docs/latest/index.html` in browser)  |
| `templates/` | Starter templates for new services using the example code |

## Quick Start: Testing

After implementing your storage backend:

```bash
# Install dependencies
cd filesystem_example && poetry install && source .venv/bin/activate
cd ../conformance_tests && poetry install

# Run all tests with the default filesystem backend
./run_tests.sh

# Run specific tests during development
./run_tests.sh -k "stat" --verbose
```

### Testing Custom Backends

For non-filesystem backends, you must provide two environment variables:

| Variable | Description |
|----------|-------------|
| `TEST_STORAGE_API_RESOURCE_BASE` | **Required.** The resource base URL that your backend uses. This is implementation-dependent and must match what your backend's capabilities endpoint returns. |
| `BACKEND_ARGS` | Backend-specific command line arguments passed to the service. |

**Example: Testing a hypothetical Azurite backend**

```bash
# Ensure Azurite emulator is running first
# docker run -p 10000:10000 mcr.microsoft.com/azure-storage/azurite

# Run conformance tests against the azurite backend
TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://azurite" \
BACKEND_ARGS="--connection-string 'DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=...;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1' --container conformance-tests" \
./run_tests.sh azurite
```

**Finding your resource base:** The resource base URL is determined by your backend implementation. Check your backend's `CapabilitiesService.ListTopLevelAddresses` response or look at how your backend constructs resource addresses.

**Additional test runner options:**

```bash
# Run tests against an already-running service
TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://azurite" \
./run_tests.sh --test-only azurite

# Start the service only (for manual API exploration)  
TEST_STORAGE_API_RESOURCE_BASE="azurite-storage://azurite" \
BACKEND_ARGS="--connection-string '...' --container test" \
./run_tests.sh --service-only azurite

# Run specific test categories
./run_tests.sh -m "grpc"     # gRPC tests only
./run_tests.sh -m "rest"     # REST tests only
./run_tests.sh -k "stat"     # Tests matching "stat"

# Debug mode: serial execution with verbose output
./run_tests.sh --no-parallel --verbose -k "failing_test"
```

Run `./run_tests.sh --help` for all available options.

## Implementing Your Own Storage Service

We provide two paths for implementing a new storage service:

### Path A: Python Backend Plugin (Quick Prototype)
Best for rapid prototyping. Reuse the existing Python gRPC/REST framework.

```bash
# Start from the template
cp -r templates/python_backend filesystem_example/src/local_filesystem_service/mybackend
# Edit the template files to implement your storage system
```

### Path B: Production Implementation (Any Language)
Best for production deployments. Implement from scratch in Go, Rust, Java, etc.

```bash
# Generate code from protos (example for Go)
protoc --go_out=. --go-grpc_out=. proto/nvidia/omniverse/storage/**/*.proto
```

See `templates/production_impl/README.md` for detailed guidance.

## 🤖 AI-Assisted Development

This package is designed to work well with AI coding assistants like Cursor, GitHub Copilot, and others.

| Document | Purpose |
|----------|---------|
| `AGENTS.md` | Comprehensive guide for AI agents |
| `PROMPTS.md` | Ready-to-use prompts for common tasks |
| `.cursorrules` | Auto-loaded context for Cursor IDE |

### Example AI Prompt

```
I want to create a new storage backend for AWS S3.
Please read @AGENTS.md and @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py
then create the implementation.
```

or more elaborate prompting techniques, writing a plan first. See @PROMPTS.md for some ideas.

## API Overview

### FileObjectService (File Operations)
- `Enumerate` - Recursively list files
- `Stat` - Get file metadata  
- `Read` / `ReadFromAddress` - Download files
- `Write` - Upload files (with streaming and redirect support)
- `Delete` - Remove files

### FileFolderService (Directory Operations)
- `List` - List directory contents
- `CreateFolder` / `DeleteFolder` - Manage directories

### CapabilitiesService (Discovery)
- `ListServices` - Available API versions
- `ListTopLevelAddresses` - Root locations

### VersioningService (Version History)
- `EnumerateVersions` - List all versions of a file

## Key Concepts

### Resource Address
A URL pointing to a mutable storage location.
```
s3://my-bucket/path/to/file.usd
```

### Resource Identity  
An opaque, routable, immutable identifier for a specific version. Routable meaning if we have multiple storage
services running, it should be clear which one will allow to Read the data identified here:
```
s3-storage-id://my-bucket/eyJwYXRoIjogIi4uLiIsICJ2ZXJzaW9uIjogIjEyMyJ9
```

### Versioning
Every write creates a new immutable version. The address points to the latest version, while identities always refer to specific versions.

## Documentation

Open `docs/latest/index.html` in your browser for the full developer guide.

## Support

- Read the conformance test feature files in `conformance_tests/src/conformance_tests/features/` - they document expected behavior in plain English
- Check the reference implementation in `filesystem_example/` for correct patterns
- Use the AI guides (`AGENTS.md`, `PROMPTS.md`) with your preferred AI coding assistant

## License

See `LICENSE.txt` and `PRODUCT_TERMS_OMNIVERSE.txt` for license information.
