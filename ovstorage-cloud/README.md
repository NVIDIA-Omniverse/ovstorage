# ovstorage-cloud

First-party cloud storage plugins for `ovstorage`. Each crate is a cdylib
that the `ovstorage` library (or `ovstorage-broker`) loads at runtime
through the C ABI declared by [`ovstorage-plugin`](../ovstorage-core/crates/ovstorage-plugin/README.md).

See the [repo-root README](../README.md) for the cross-workspace layout
and dependency graph.

## Crates

- [`ovstorage-plugin-s3`](crates/ovstorage-plugin-s3/README.md) — AWS S3 + S3-compatible (MinIO, Cloudflare R2, Backblaze B2, custom). Hand-rolled SigV4 signer, native multipart uploads, presigned-URL redirects.
- [`ovstorage-plugin-gcs`](crates/ovstorage-plugin-gcs/README.md) — Google Cloud Storage. OAuth bearer tokens, V4 query-signing for service accounts, resumable uploads.
- [`ovstorage-plugin-azure`](crates/ovstorage-plugin-azure/README.md) — Azure Blob and ADLS Gen2 (HNS-aware). Shared Access Signatures, shared-key signing, lease-based atomic writes.
- [`ovstorage-plugin-opendal`](crates/ovstorage-plugin-opendal/README.md) — long-tail backends fronted by Apache OpenDAL. Driver-specific capabilities mapped to ovstorage's capability matrix. The descriptor's `service` enum advertises only the OpenDAL services the workspace actually compiles in (`fs`, `s3`, `webdav`); additional services require enabling their `services-*` feature on the workspace's `opendal` dep and adding a matching `DriverSpec`.

Plugin authors writing additional cloud-flavored backends should start at
the [`plugin-storage` persona](../docs/public/plugin-storage/README.md)
and the shared [plugin-development foundation](../docs/public/plugin-development/README.md).
