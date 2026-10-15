# Production Implementation Guide

This guide helps you implement the Omniverse Storage API from scratch in Go, Rust, Java, or any other language.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Omniverse Clients                        │
└──────────────┬────────────────────────────┬─────────────────┘
               │                            │
               ▼                            ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│      gRPC Interface       │   │      REST Interface          │
│   (fileobject_service)    │   │   (OpenAPI endpoints)        │
└──────────────┬────────────┘   └──────────────┬───────────────┘
               │                               │
               └───────────────┬───────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Storage Backend Abstraction                     │
│  (interface similar to StorageBackendInterface)              │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Your Storage System                          │
│            (S3, Azure, GCS, Custom, etc.)                   │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Checklist

### 1. Project Setup

- [ ] Set up gRPC code generation from proto files
- [ ] Set up OpenAPI code generation (optional, for REST)
- [ ] Configure build system (Make, Cargo, Gradle, etc.)
- [ ] Create storage abstraction interface

### 2. gRPC Services (Required)

#### FileObjectService (`proto/nvidia/omniverse/storage/fileobject/v1beta/`)
- [ ] `Enumerate` - Recursive file listing (streaming)
- [ ] `Stat` - File metadata
- [ ] `Read` - Read by identity (streaming)
- [ ] `ReadFromAddress` - Read by address (streaming)
- [ ] `FetchWriteTypeInfo` - Upload method preferences
- [ ] `Write` - Upload file (bidirectional streaming)
- [ ] `CompleteRedirectUpload` - Finalize presigned upload
- [ ] `UploadPart` - Multipart part URL
- [ ] `CompleteMultipartUpload` - Finalize multipart
- [ ] `AbortMultipartUpload` - Cancel multipart
- [ ] `Delete` - Remove file

#### FileFolderService (`proto/nvidia/omniverse/storage/filefolder/v1beta/`)
- [ ] `List` - Directory listing
- [ ] `CreateFolder` - Create directory
- [ ] `DeleteFolder` - Remove empty directory

#### CapabilitiesService (`proto/nvidia/omniverse/storage/capabilities/v1beta/`)
- [ ] `ListServices` - Available API versions
- [ ] `ListTopLevelAddresses` - Root addresses

#### VersioningService (`proto/nvidia/omniverse/storage/versioning/v1beta/`)
- [ ] `EnumerateVersions` - List file versions

### 3. REST API (Optional but Recommended)

Map OpenAPI specs to HTTP endpoints. See `openapi/` directory.

### 4. Error Handling

Map storage errors to gRPC/HTTP status codes:

| Error Condition | gRPC Code | HTTP Status |
|-----------------|-----------|-------------|
| Resource not found | `NOT_FOUND` | 404 |
| Permission denied | `PERMISSION_DENIED` | 403 |
| Invalid argument | `INVALID_ARGUMENT` | 400 |
| Already exists | `ALREADY_EXISTS` | 409 |
| Internal error | `INTERNAL` | 500 |

---

## Go Implementation

### Setup

```bash
# Create project
mkdir mystorage-service && cd mystorage-service
go mod init github.com/yourorg/mystorage-service

# Install dependencies
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate from protos
protoc \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  proto/nvidia/omniverse/storage/**/*.proto
```

### Project Structure

```
mystorage-service/
├── cmd/
│   └── server/
│       └── main.go          # Entry point
├── internal/
│   ├── service/
│   │   ├── fileobject.go    # FileObjectService implementation
│   │   ├── filefolder.go    # FileFolderService implementation
│   │   ├── capabilities.go  # CapabilitiesService implementation
│   │   └── versioning.go    # VersioningService implementation
│   └── storage/
│       ├── interface.go     # Storage backend interface
│       └── s3/
│           └── s3.go        # S3 implementation
├── pb/                      # Generated protobuf code
├── proto/                   # Original proto files (copy from package)
├── go.mod
└── go.sum
```

### Example Interface (Go)

```go
// internal/storage/interface.go
package storage

import (
    "context"
    "io"
    "time"
)

type Metadata struct {
    Size         int64
    LastModified time.Time
}

type VersionInfo struct {
    Identity string
    Metadata Metadata
}

type ListEntry struct {
    Address  string
    Identity string
    Metadata *Metadata // nil for folders
}

type Backend interface {
    BaseURI() string
    
    // Existence
    Exists(ctx context.Context, address string) (bool, error)
    IsFile(ctx context.Context, address string) (bool, error)
    IsDir(ctx context.Context, address string) (bool, error)
    
    // File operations
    Stat(ctx context.Context, address string) (*VersionInfo, error)
    Read(ctx context.Context, identity string) (io.ReadCloser, error)
    Write(ctx context.Context, address string, content io.Reader, size int64) (*VersionInfo, error)
    Delete(ctx context.Context, address string) error
    
    // Folder operations
    List(ctx context.Context, address string) ([]string, []ListEntry, error)
    CreateFolder(ctx context.Context, address string) error
    DeleteFolder(ctx context.Context, address string) error
    
    // Versioning
    EnumerateVersions(ctx context.Context, address string) ([]VersionInfo, error)
    
    // Identity conversion
    AddressFromIdentity(identity string) (string, error)
    IdentityFromAddress(address string) (string, error)
}
```

---

## Rust Implementation

### Setup

```toml
# Cargo.toml
[package]
name = "mystorage-service"
version = "0.1.0"
edition = "2021"

[dependencies]
tonic = "0.10"
prost = "0.12"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"

[build-dependencies]
tonic-build = "0.10"
```

```rust
// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &[
                "proto/nvidia/omniverse/storage/fileobject/v1beta/fileobject_service.proto",
                "proto/nvidia/omniverse/storage/filefolder/v1beta/filefolder_service.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
```

### Project Structure

```
mystorage-service/
├── src/
│   ├── main.rs
│   ├── service/
│   │   ├── mod.rs
│   │   ├── fileobject.rs
│   │   └── filefolder.rs
│   └── storage/
│       ├── mod.rs
│       ├── backend.rs       # Trait definition
│       └── s3.rs           # S3 implementation
├── proto/                   # Proto files
├── Cargo.toml
└── build.rs
```

### Example Trait (Rust)

```rust
// src/storage/backend.rs
use async_trait::async_trait;
use std::io::Read;

pub struct Metadata {
    pub size: u64,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

pub struct VersionInfo {
    pub identity: String,
    pub metadata: Metadata,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    fn base_uri(&self) -> &str;
    
    async fn exists(&self, address: &str) -> Result<bool, StorageError>;
    async fn is_file(&self, address: &str) -> Result<bool, StorageError>;
    async fn is_dir(&self, address: &str) -> Result<bool, StorageError>;
    
    async fn stat(&self, address: &str) -> Result<VersionInfo, StorageError>;
    async fn read(&self, identity: &str) -> Result<Box<dyn Read + Send>, StorageError>;
    async fn write(&self, address: &str, content: &[u8]) -> Result<VersionInfo, StorageError>;
    async fn delete(&self, address: &str) -> Result<(), StorageError>;
    
    // ... more methods
}
```

---

## Java Implementation

### Setup (Gradle)

```gradle
// build.gradle
plugins {
    id 'java'
    id 'com.google.protobuf' version '0.9.4'
}

dependencies {
    implementation 'io.grpc:grpc-netty-shaded:1.59.0'
    implementation 'io.grpc:grpc-protobuf:1.59.0'
    implementation 'io.grpc:grpc-stub:1.59.0'
    implementation 'com.google.protobuf:protobuf-java:3.24.0'
}

protobuf {
    protoc {
        artifact = 'com.google.protobuf:protoc:3.24.0'
    }
    plugins {
        grpc {
            artifact = 'io.grpc:protoc-gen-grpc-java:1.59.0'
        }
    }
    generateProtoTasks {
        all()*.plugins {
            grpc {}
        }
    }
}
```

### Project Structure

```
mystorage-service/
├── src/main/java/com/yourorg/storage/
│   ├── Application.java
│   ├── service/
│   │   ├── FileObjectServiceImpl.java
│   │   └── FileFolderServiceImpl.java
│   └── backend/
│       ├── StorageBackend.java      # Interface
│       └── S3StorageBackend.java    # Implementation
├── src/main/proto/                   # Proto files
├── build.gradle
└── settings.gradle
```

### Example Interface (Java)

```java
// src/main/java/com/yourorg/storage/backend/StorageBackend.java
package com.yourorg.storage.backend;

import java.io.InputStream;
import java.util.List;

public interface StorageBackend {
    String getBaseUri();
    
    boolean exists(String address);
    boolean isFile(String address);
    boolean isDirectory(String address);
    
    VersionInfo stat(String address) throws NotFoundException;
    InputStream read(String identity) throws NotFoundException;
    VersionInfo write(String address, byte[] content);
    void delete(String address) throws NotFoundException;
    
    List<String> listFolders(String address);
    List<ListEntry> listFiles(String address);
    void createFolder(String address);
    void deleteFolder(String address);
    
    List<VersionInfo> enumerateVersions(String address);
    
    String addressFromIdentity(String identity);
    String identityFromAddress(String address);
}
```

---

## Key Implementation Notes

### Resource Identity Design

Resource identities should be:
1. **Opaque**: Clients should not parse them
2. **Stable**: Same version = same identity
3. **Self-contained**: Contain all info needed to retrieve
4. **URL-safe**: Use base64url encoding

Example structure (encoded as JSON then base64url):
```json
{
  "bucket": "my-bucket",
  "key": "path/to/file.usd",
  "version": "abc123",
  "storage": "s3"
}
```

### Streaming Best Practices

For `Enumerate` and `Read`:
- Use reasonable chunk sizes (64KB - 1MB)
- Handle backpressure (don't overwhelm client)
- Support cancellation via context

For `Write` (bidirectional streaming):
1. Client sends `WriteParameters` first
2. Server responds with `WriteChunksAccepted` or `WriteRedirect`
3. If accepted, client sends `Chunk` messages
4. Server sends `ResourceInfo` on completion

### Versioning Without Native Support

If your storage doesn't support versioning:

Option 1: Version suffix in key
```
object.usd.v1
object.usd.v2
object.usd.v3
```

Option 2: Separate metadata store
```
versions/
  object.usd/
    metadata.json  # {"latest": 3, "versions": [1,2,3]}
    v1
    v2
    v3
```

Option 3: Return single version
- `enumerate_versions` returns only current version
- Identity and address effectively equivalent

### Testing Your Implementation

1. Start your service
2. Configure conformance tests:
   ```bash
   export TEST_STORAGE_API_REST_ENDPOINT=http://localhost:8011
   export TEST_STORAGE_API_GRPC_ENDPOINT=localhost:50051
   export TEST_STORAGE_API_RESOURCE_BASE=yourscheme://yourauthority
   ```
3. Run tests:
   ```bash
   cd conformance_tests
   poetry install
   source .venv/bin/activate
   run-conformance-tests
   ```

---

## Need Help?

1. **Read the protos**: Start with `fileobject_service.proto` - it has detailed comments
2. **Check the reference**: `filesystem_example/` shows correct behavior
3. **Run specific tests**: `run-conformance-tests -k "stat" -vv` to debug one feature
4. **Read feature files**: `conformance_tests/src/conformance_tests/features/` shows expected behavior in plain English
