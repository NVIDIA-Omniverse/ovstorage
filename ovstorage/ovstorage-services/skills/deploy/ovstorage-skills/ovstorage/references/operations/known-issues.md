# Known Issues

## v1.0.0 GA Release

- `FILESERVICE_STATIC_DIR` environment variable is injected but **not consumed** by the service entrypoint in Docker and Kubernetes deployments. Files are written to ephemeral storage and lost on pod restart.
  - **Workaround:** Pass the backend subcommand explicitly in your container args:
    ```yaml
    args: ["filesystem", "--static-dir", "/data/storage"]
    ```
    Or when running directly: `python -m local_filesystem_service filesystem --static-dir /data/storage`

- IRSA Web Identity Tokens are not consumed on EKS. The Helm chart injects AWS credentials but the Storage Service does not consume them, causing pod-level S3 access to fail or fall back to instance metadata credentials.
  - **Workaround:** Inject credentials explicitly via Kubernetes secret and reference them in Helm values using `extraEnvs`.

## 1.0.0-beta Initial Release

- When using Notification Services, if you upload or write data outside the Storage Service path, update events will not be received and the storage service and client application will not represent the changes in a known timeframe. It is recommended that you use the Storage APIs for both read and write operations to get expected consistency results.

- For Kit app streaming, the authentication token may expire and disconnect the user from the Storage API deployment even though the streaming app is still active. This is planned to be fixed in the next release.
  - **Workaround:** Start a new streaming session.

- Within Kit and Client Library, Copy, Move, Rename, and Create Folder are not currently implemented for the Storage APIs. This is planned to be fixed in the next release.
  - **Workaround:** Use Storage Navigator to perform these operations.

- When using multiple Storage Service replicas with caches enabled, clients may see stale reads for non-version-specific objects until the cache TTL expires. See `references/operations/scalability.md` for cache configuration guidance.

- Storage Navigator cannot download files into default system directories (Documents, Downloads, etc.). You must create a dedicated folder for downloads.
