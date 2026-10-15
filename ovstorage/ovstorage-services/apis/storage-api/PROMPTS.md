# AI Agent Prompts for Storage API Implementation

This document contains ready-to-use prompts for AI coding agents to help implement NVIDIA Omniverse Storage API backends. Copy and paste these prompts, adjusting the specifics (storage system name, language, etc.) for your needs.

---

## 🚀 Quick Start Prompts

### Orientation Prompt
Use this first to help the AI understand the project:

```
I'm working with the NVIDIA Omniverse Storage API package. Please read:
1. @AGENTS.md - the AI guide for this project
2. @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py - the interface I need to implement

Give me a summary of what I need to implement and the key concepts (resource address vs identity, versioning model, etc.)
```

---

## 📦 Path A: Python Backend Plugin Prompts

### Create New Backend Structure

```
I want to create a new storage backend for [STORAGE_SYSTEM] (e.g., AWS S3, Azure Blob, Google Cloud Storage, Dropbox, etc.) as a Python plugin.

Please:
1. Read @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py
2. Read @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py for reference
3. Create a new backend module at filesystem_example/src/local_filesystem_service/[name]/
4. Implement the StorageBackendInterface with appropriate SDK calls
5. Register it with @register_backend decorator
6. Add CLI options for configuration (bucket name, credentials, etc.)

Focus on implementing these core methods first:
- base_uri property
- is_address_valid()
- exists(), is_file(), is_dir()
- stat(), stat_identity()
- read_from_address(), read_from_identity()
- write_version()
- list(), enumerate()
```

### Implement Specific Method

```
I'm implementing a [STORAGE_SYSTEM] backend. Help me implement the [METHOD_NAME] method.

Context:
- Read @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py for the interface contract
- Read @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py to see how the filesystem backend implements it
- My backend class is at @[PATH_TO_YOUR_BACKEND]

Requirements from the interface:
[Copy the docstring from storage_backend_interface.py for that method]

Please implement this method for [STORAGE_SYSTEM], handling all edge cases and error conditions.
```

### Debug Conformance Test Failure

```
My [STORAGE_SYSTEM] backend is failing conformance tests. Here's the output:

[PASTE TEST OUTPUT]

Please:
1. Read the relevant feature file at @conformance_tests/src/conformance_tests/features/[path]
2. Read my implementation at @[PATH_TO_YOUR_BACKEND]
3. Identify why the test is failing
4. Suggest the fix
```

### Add Multipart Upload Support

```
I need to add multipart upload support to my [STORAGE_SYSTEM] backend.

Please:
1. Read how multipart uploads work in @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py (the multipart methods)
2. Read the reference implementation in @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py
3. Read how the gRPC service uses these methods in @filesystem_example/src/local_filesystem_service/grpc_service/fileobject.py

Implement these methods for [STORAGE_SYSTEM]:
- supports_multipart_upload()
- create_upload_session()
- get_upload_part_path()
- construct_upload_part_redirect()
- cleanup_upload_session()
- upload_session_exists()
```

---

## 🏗️ Path B: Production Implementation Prompts

### Go Implementation

```
I want to implement the Omniverse Storage API FileObjectService in Go for [STORAGE_SYSTEM].

Please:
1. Read @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto
2. Read @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject.proto
3. Create a Go implementation structure using standard gRPC patterns
4. Implement the Stat RPC method as an example, with proper error handling

Use these Go idioms:
- Context for cancellation
- Standard error wrapping
- Proper status code mapping (codes.NotFound, codes.InvalidArgument, etc.)
```

### Java Implementation

```
I want to implement the Omniverse Storage API in Java using Spring Boot and gRPC.

Please:
1. Read @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto
2. Read @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject.proto
3. Create a project structure with:
   - gRPC service implementation
   - Spring Boot configuration
   - Storage backend interface (similar pattern to Python)
4. Implement the FileObjectService.Stat method as an example
```

### Rust Implementation

```
I want to implement the Omniverse Storage API in Rust using Tonic.

Please:
1. Read @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto
2. Create a Cargo.toml with tonic and tonic-build dependencies
3. Set up build.rs for proto compilation
4. Create trait-based storage backend abstraction
5. Implement FileObjectService with the Stat method as an example

Use Rust idioms: Result types, async/await, proper error types.
```

### REST-Only Implementation

```
I want to implement just the REST API (no gRPC) for [STORAGE_SYSTEM] in [LANGUAGE].

Please:
1. Read @openapi/fileobject/v1beta/fileobject-api.yaml
2. Read @openapi/filefolder/v1beta/filefolder-api.yaml
3. Read @openapi/capabilities/v1beta/capabilities-api.yaml
4. Create a REST server implementation with all endpoints
5. Ensure response formats match the OpenAPI spec exactly

Pay special attention to:
- HTTP status codes (204 for stat, 201 for write, etc.)
- Custom headers (x-nvidia-omniverse-storage-*)
- The 300 redirect response for large files
```

---

## 🧪 Testing Prompts

### Understand a Conformance Test

```
Help me understand what this conformance test is checking.

Read @conformance_tests/src/conformance_tests/features/[path/to/feature.feature]

Explain:
1. What scenario is being tested
2. What the expected behavior is for each protocol (gRPC, REST)
3. What status codes/responses are expected
4. What my implementation needs to do to pass this test
```

### Create Integration Test

```
Create an integration test for my [STORAGE_SYSTEM] backend that:
1. Uploads a file
2. Stats it to verify it exists
3. Reads it back and verifies content
4. Creates a new version
5. Lists versions
6. Deletes the file

Use pytest and the patterns from @conformance_tests/
```

### Debug Specific Test Scenario

```
I'm implementing [STORAGE_SYSTEM] and failing this test scenario:

Feature: [NAME]
Scenario: [DESCRIPTION]
[PASTE THE SCENARIO]

My implementation returns [ACTUAL_RESULT] but the test expects [EXPECTED_RESULT].

Please:
1. Analyze the scenario
2. Check my implementation at @[PATH]
3. Identify the bug
4. Provide the fix
```

### Run Tests with Script

```
I've implemented some methods in my storage backend. Help me test them:

1. Run `./run_tests.sh -k "stat" --verbose` to test stat functionality
2. Analyze any failures and help me fix them
3. Then run `./run_tests.sh -k "write"` to test write functionality

My backend is at @[PATH_TO_BACKEND]
```

### Debug Test Failure with Script

```
I ran `./run_tests.sh -k "enumerate" --no-parallel --verbose` and got this error:

[PASTE ERROR OUTPUT]

Please:
1. Read the relevant feature file
2. Check my implementation at @[PATH]
3. Suggest the fix
```

### Quick Verification Run

```
I think my implementation is complete. Run a full verification:
./run_tests.sh

This will run all tests in parallel. If any fail, help me debug them.
```

---

## 🔧 Specific Feature Prompts

### Implement Resource Identity Encoding

```
I need to implement resource identity encoding/decoding for [STORAGE_SYSTEM].

Requirements:
- Must be URL-safe (can appear in URLs)
- Must encode: bucket/container, object key, version ID
- Must be decodable back to components
- Should be opaque to clients

Reference: See how @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py does it with base64 + JSON

Create identity encoding for [STORAGE_SYSTEM] that encodes:
- [LIST YOUR STORAGE-SPECIFIC IDENTIFIERS]
```

### Implement Redirect Downloads

```
I want to implement redirect-based downloads for [STORAGE_SYSTEM] using presigned URLs.

Please:
1. Read how redirects work in @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py
2. Read the ReadRedirectProperties message in @proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject.proto
3. Implement:
   - supports_redirect_download() → True
   - construct_redirect_url() → presigned URL for [STORAGE_SYSTEM]
   - construct_redirect_url_for_identity() → presigned URL for specific version

For [STORAGE_SYSTEM], use [SDK/API] to generate presigned URLs.
```

### Implement Optimistic Locking

```
I need to implement optimistic locking for write/delete operations.

Read how it works:
1. @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py - OptimisticLockingSupport and is_version_latest()
2. @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py - how write_version checks previous_version

Implement for [STORAGE_SYSTEM]:
- get_optimistic_locking_support() 
- is_version_latest()
- Check previous_version in write_version() before writing

[STORAGE_SYSTEM] supports versioning via [DESCRIBE YOUR STORAGE'S VERSIONING]
```

### Add Metadata Support

```
I need to implement user-defined metadata (key-value pairs) for [STORAGE_SYSTEM].

Read the interface:
1. @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py - get_metadata, update_metadata, delete_metadata
2. @filesystem_example/src/local_filesystem_service/filesystem/file_system_provider.py - reference implementation

For [STORAGE_SYSTEM], metadata should be stored in [DESCRIBE WHERE - object metadata, separate store, etc.]

Implement with:
- ETag-based optimistic concurrency
- Support for both resource addresses and resource identities
```

---

## 📝 Documentation Prompts

### Generate Backend Documentation

```
Generate README.md documentation for my [STORAGE_SYSTEM] backend.

Read my implementation at @[PATH_TO_BACKEND]

Include:
1. Overview and supported features
2. Prerequisites (SDK, credentials, etc.)
3. Configuration options (all CLI flags)
4. Quick start example
5. Environment variables
6. Known limitations
7. Troubleshooting common issues
```

### Create Architecture Diagram

```
Create a text-based architecture diagram (using ASCII or Mermaid) showing how my [STORAGE_SYSTEM] backend integrates with:
1. The gRPC service layer (@filesystem_example/src/local_filesystem_service/grpc_service/)
2. The REST service layer (@filesystem_example/src/local_filesystem_service/rest_service/)
3. The [STORAGE_SYSTEM] cloud service

Show the data flow for a Read operation and a Write operation.
```

---

## 🐛 Troubleshooting Prompts

### General Debug

```
My [STORAGE_SYSTEM] backend has an issue:
[DESCRIBE THE PROBLEM]

Here's my implementation: @[PATH]
Here's the error/unexpected behavior:
[PASTE ERROR OR DESCRIBE BEHAVIOR]

Please diagnose and fix.
```

### Protocol Mismatch

```
My REST implementation passes but gRPC fails (or vice versa).

REST result: [DESCRIBE]
gRPC result: [DESCRIBE]

The test is: @conformance_tests/src/conformance_tests/features/[path]

Help me find the inconsistency between my REST and gRPC implementations.
```

### Performance Issue

```
My [STORAGE_SYSTEM] backend is slow for [OPERATION].

Current implementation: @[PATH]

Please analyze and suggest optimizations for:
1. Reducing API calls to [STORAGE_SYSTEM]
2. Better batching/streaming
3. Caching opportunities
4. Connection pooling
```

---

## 🎯 Completion Checklist Prompt

```
Review my [STORAGE_SYSTEM] backend implementation for completeness.

My implementation: @[PATH_TO_BACKEND_DIRECTORY]

Check against @filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py:

1. Are all abstract methods implemented?
2. Are all error cases handled correctly?
3. Is the factory function registered with @register_backend?
4. Are CLI options registered with @register_backend_cli?
5. Are the imports added to __init__.py?
6. Does it handle:
   - Versioned addresses (with ;version suffix)?
   - Large files (redirect uploads)?
   - Concurrent access (thread safety)?
   - Optimistic locking (previous_version parameter)?

List any missing pieces.
```

---

## 💡 Tips for Using These Prompts

1. **Always reference the interface**: Include `@filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py` for any implementation question.

2. **Show your current code**: Point to your implementation file with `@your/path/here.py` so the AI can see what you have.

3. **Be specific about your storage system**: Different storage systems (S3, Azure, GCS, etc.) have different SDKs and patterns.

4. **Iterate incrementally**: Implement and test one method at a time rather than trying to do everything at once.

5. **Use conformance tests early**: Run tests after implementing each method to catch issues early.
