---
name: ovstorage-user-choose-a-backend
description: Use when selecting the right ovstorage backend plugin for a task or deciding which route to configure.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, routing, backend]
tools: [Read]
compatibility: Requires ovstorage MCP tools or equivalent library calls. Backend-specific plugins and credentials are user-supplied.
---

# Choose a Backend

## Goal

Pick a backend kind whose address shape, capabilities, and credential model
match the storage task.

## Available backends

| Backend | Use when | Address shape | Notes |
|---|---|---|---|
| `file` | Data is on a local or mounted filesystem visible to this process | `file:///absolute/path` | Best for local smoke tests, dev fixtures, and direct POSIX semantics. |
| `http` | Data is read from an HTTP(S) endpoint | `https://host/path` | Read-oriented and URL-shaped; confirm write/list support before depending on it. |
| `omniverse-storage-service` | Targeting a deployed Omniverse Storage Service | gRPC; configured via `discovery_url` | Needs `discovery_url` (host of `/api/v1/services` and `/api/v1/auth-config`) and OIDC credentials. See per-backend section below. |
| `s3` | AWS S3 or S3-compatible object stores (MinIO, R2, B2, custom endpoint) | `s3://<bucket>/<key>` | `aws_access_key_id` + `aws_secret_access_key` (+ optional `aws_session_token`); env vars and `~/.aws/credentials` honoured. |
| `gcs` | Google Cloud Storage | `gs://<bucket>/<object>` | `service_account_key` (JSON blob) or ADC `file_path`; no IMDS, no impersonation. |
| `azure` | Azure Blob and ADLS Gen2 (HNS-aware accounts) | `azure://<account>/<container>/<path>` | One of `account_key`, `sas_token`, service principal, or workload identity. |
| `opendal` | Long-tail backends fronted by OpenDAL (services compiled in: `fs`, `s3`, `webdav`) | `opendal://<service>/<path>` (configurable prefix) | Driver-specific; `s3` uses bare `access_key_id` / `secret_access_key`, `webdav` uses `password`. |
| `nucleus` | NVIDIA Omniverse Nucleus content-collaboration server | `omniverse://server[:port]/path` (with optional `?<branch>&<checkpoint>` selector) | Three credential methods (`sso`, `userpass`, `api_token`); refresh token persisted in OS keyring for warm-continue. |
| `broker` | Routing traffic through an upstream `ovstorage-broker` daemon (per-call authz, broker-side caching, credential isolation) | No scheme of its own — address roots are published by the upstream broker (typically `s3://`, `gs://`, `azure://`, `omniverse://`, `file://`) | Single config key `address` (HTTPS discovery, direct gRPC, UDS, or named pipe). One credential method: `client_credentials` (OIDC client ID + secret) for headless deployments; interactive PKCE / device flow drives via `Factory::authenticate`. |

## Backend-specific notes

### `omniverse-storage-service`

A Omniverse Storage Service deployment, accessed over gRPC with
OIDC bearer-token auth. Configure with:

- `discovery_url` — HTTP root that serves `/api/v1/services` and
  `/api/v1/auth-config`. The plugin discovers the gRPC endpoint and
  OIDC client from there.
- `oidc_client_name` (optional, default `"default"`) — picks an entry
  from `auth-config.clients`.

Credentials arrive via OAuth (PKCE for browser, device flow for
headless). See
[`ovstorage-user-authenticate-to-backend`](../ovstorage-user-authenticate-to-backend/SKILL.md)
for the auth flow.

Pick this backend when you have an existing Omniverse Storage Service deployment;
otherwise pick a cloud or file backend.

This backend is the client-side adapter for reaching an existing service
deployment. It is not the service deployment workflow itself; service-stack
deployment and operations use the `ovstorage-services` routing in a source
checkout.

### `s3`

AWS S3 and S3-compatible object stores. Addresses are
`s3://<bucket>/<key>`; the configured `bucket` is authoritative, so
the prefix lives in the address, not the connection config. Config
keys:

- `bucket` (**required**) and `region` (**required**).
- `endpoint` — optional; required for `minio`, `b2`, and `custom`
  compatibility profiles.
- `compatibility_profile` — enum (`aws`, `minio`, `r2`, `b2`,
  `custom`; defaults to `aws`, or `custom` when `endpoint` is set).
  Selects addressing style and signing region per the matrix in
  [`plugin-s3.md`](../../docs/public/plugin-storage/plugin-s3.md);
  this is the knob to flip for R2 (`auto` signing region) or B2
  (path-style + `auto`).
- `force_path_style` (bool), `force_request_payer` (bool),
  `profile` (named entry in the AWS shared credentials file).
- `sqs_queue_url` / `sqs_max_messages` / `sqs_wait_seconds` /
  `sqs_visibility_timeout` for `watch_directory`.

Credentials (`aws_access_key_id`, `aws_secret_access_key`,
`aws_session_token`) are all optional; absent fields fall through
the chain (env vars, then the AWS shared credentials file). IMDS,
AWS SSO, and STS role assumption are **not** implemented — operators
materialise a static-key profile out-of-band.

### `gcs`

Google Cloud Storage. Addresses are `gs://<bucket>/<object>`. Config
keys:

- `bucket` (**required**).
- `project_id` — optional; surfaced for operator clarity only.
- `service_account` — optional; named entry in the credential chain.
- `endpoint` — optional; for GCS-compatible deployments (e.g.
  `fake-gcs-server`).
- `pubsub_subscription` /  `pubsub_pull_max` for `watch_directory`.

Credentials are `service_account_key` (the JSON blob from Google's
IAM console, accepting either `type: service_account` or
`type: authorized_user`) or `file_path` (ADC JSON file on disk;
defaults to `~/.config/gcloud/application_default_credentials.json`).
Authorized-user creds cannot mint V4 signed URLs, so reads under
that credential type pull bytes through the JSON download endpoint
instead. GCE/GKE metadata server, workload-identity federation, and
service-account impersonation are not implemented in-process.

### `azure`

Azure Blob and Azure Data Lake Storage Gen2 (HNS-aware). Addresses
are `azure://<account>/<container>/<path>`. The Azure plugin
**rejects unknown config keys** (`CONFIG_KEYS` is a strict
whitelist), so don't add a `prefix` field. Config keys:

- `account` (**required**) and `container` (**required**).
- `endpoint_suffix` — optional; default `core.windows.net` (override
  for sovereign clouds).
- `hierarchical_namespace` — bool; set to `true` for ADLS Gen2 HNS
  accounts. `instantiate` checks this matches the account's actual
  mode.
- `change_feed_enabled` / `change_feed_segment_lag_seconds` /
  `change_feed_poll_interval_seconds` for `watch_directory` (flat
  Blob accounts only).

Credentials are picked from four distinct methods, in this
resolution order: `account_key` (Shared Key signing) → `sas_token`
(appended verbatim) → workload identity (`federated_token_file` +
`client_id` + `tenant_id`) → service principal (`client_id` +
`client_secret` + `tenant_id`). Managed Identity / IMDS, Azure CLI
session reuse, and the rest of the `DefaultAzureCredential` chain
are not implemented in-process.

### `opendal`

Long-tail backends fronted by Apache OpenDAL. Pick a `service` —
the descriptor's enum advertises **only** the services this workspace
compiles in, namely `fs`, `s3`, and `webdav`. Other OpenDAL services
(http, sftp, hdfs, etc.) are not enabled and will be rejected at
`instantiate`. Config keys:

- `service` (**required** enum: `fs` | `s3` | `webdav`).
- `endpoint` — optional; passed through to the chosen driver.
- `config_json` — optional flat JSON string-map of driver knobs
  (`bucket`, `region`, `root`, `username`, ...).
- `prefix` — optional URL; route prefix shown to callers (defaults
  to `opendal://<service>/`).

Credentials are a fixed shared set: `access_key_id` +
`secret_access_key` (for the OpenDAL `s3` driver), `password` (for
WebDAV), and `private_key`. Note that the OpenDAL `s3` driver uses
the **bare** `access_key_id` / `secret_access_key` names — not the
`aws_*`-prefixed names that the first-party `s3` plugin uses — so
the credential shapes are not interchangeable. For S3-shaped
storage that needs the full conditional-write / version-listing
capability set, prefer the first-party `s3` plugin.

### `nucleus`

NVIDIA Omniverse Nucleus is the content-collaboration server for
the Omniverse platform. Pick this backend when:

- You have an Omniverse Nucleus server deployed (`omniverse://`
  URLs).
- You need checkpoint-based versioning (Nucleus tracks per-path
  checkpoint history; `list_versions` enumerates them newest-first
  and an `?&<checkpoint>` URL selector pins reads to a specific
  checkpoint).
- You need ACL-aware permissions on `stat`
  (`populates_effective_permissions_on_stat = true`).

Configuration is minimal: `server` (the `host[:port]` of the
Nucleus server) is the only required key. `endpoint` overrides
SOWS discovery for production session establishment; `prefix`
scopes which paths the backend instance serves (default `/`);
`use_lft` (default `true`) gates the LFT redirect path for bulk
bytes.

`if_match` on this backend is an opaque etag string — Nucleus's
mutating omni1 method that carries a conditional (`update_asset`)
accepts only an etag. Pass `if_match: Some(etag_string)`. The
checkpoint selector lives in the URL (`?&<N>`), not in `if_match`.

See [`ovstorage-user-authenticate-to-backend`](../ovstorage-user-authenticate-to-backend/SKILL.md)
for the three credential methods (`sso`, `userpass`, `api_token`)
and the keyring-backed refresh-token warm-continue.

### `broker`

Routes traffic through an upstream `ovstorage-broker` daemon. The
broker holds long-lived cloud credentials, enforces per-call
authorization, runs broker-side metadata + byte caching, and keeps
credentials off the calling host. Pick this backend when:

- You want a credential boundary: the calling process holds only
  short-lived broker bearers, not S3 / GCS / Azure keys.
- You want per-call authorization (allow / deny / audit) against a
  configured `AuthzPlugin` policy.
- You're running zero-trust fleets, workload-identity-federated
  deployments, or want a shared metadata cache in front of the
  cloud.

Configuration is minimal: `address` (broker discovery URL or direct
gRPC endpoint) is the only required key. Accepted shapes:

- `https://broker.example.com` — HTTPS discovery (fetches
  `/api/v1/services` for the broker endpoint).
- `http://localhost` — plaintext-HTTP discovery (honored only for
  `localhost`, IP literals, and `.local` hosts).
- `grpc+tls://host:port` / `grpc+tcp://host:port` — direct gRPC,
  skipping discovery.
- `/path/to/socket` — Unix domain socket.
- `pipe:NAME` — Windows named pipe.

Optional `oidc_client_name` (default `"default"`) selects an entry
from the broker's published `auth-config.clients.<name>` when the
deployment publishes auth-config under a non-default key.

Address roots come from the broker on `ListAddressRoots` after
`instantiate`. The library merges them into the routing table; the
per-route capability profile mirrors the upstream plugin's profile
field-by-field (so a brokered `s3://corp-prod/` route advertises
the same `supports_recursive_list`, `supports_version_listing`,
`version_list_order`, `watch_directory_kinds`,
`redirect_size_threshold`, etc. it would in Direct mode).

See [`ovstorage-user-authenticate-to-backend`](../ovstorage-user-authenticate-to-backend/SKILL.md)
for the `client_credentials` credential method and the
broker-driven interactive PKCE / device flow.

## Recipe

1. Run [`ovstorage-user-getting-started`](../ovstorage-user-getting-started/SKILL.md) and confirm
   the backend kind exists in `backend_kinds`.
2. Match the address root you need to the backend's URL scheme and configured
   `address_roots`.
3. Check capabilities before relying on writes, recursive list, directory
   delete, watches, materialize, or optimistic concurrency.
4. Follow [`ovstorage-user-authenticate-to-backend`](../ovstorage-user-authenticate-to-backend/SKILL.md)
   before first use if the descriptor has credential fields.

## References

- [`docs/public/library-rust/README.md`](../../docs/public/library-rust/README.md) for route
  and connection setup.
- [`docs/public/plugin-storage/README.md`](../../docs/public/plugin-storage/README.md) for
  plugin capability vocabulary.
- [`plugin-file`](../../docs/public/plugin-storage/plugin-file.md)
  and [`plugin-http`](../../docs/public/plugin-storage/plugin-http.md)
  for backend-specific semantics.
- [`plugin-services-client`](../../docs/public/plugin-storage/plugin-services-client.md)
  for the `omniverse-storage-service` backend.
- [`plugin-s3.md`](../../docs/public/plugin-storage/plugin-s3.md) for
  AWS S3 and S3-compatible object stores.
- [`plugin-gcs.md`](../../docs/public/plugin-storage/plugin-gcs.md)
  for Google Cloud Storage.
- [`plugin-azure.md`](../../docs/public/plugin-storage/plugin-azure.md)
  for Azure Blob and ADLS Gen2.
- [`plugin-opendal.md`](../../docs/public/plugin-storage/plugin-opendal.md)
  for OpenDAL-fronted long-tail backends.
- [`plugin-nucleus.md`](../../docs/public/plugin-storage/plugin-nucleus.md)
  for the Omniverse Nucleus content-collaboration server.
- [`plugin-broker.md`](../../docs/public/plugin-storage/plugin-broker.md)
  for the broker-client cdylib.
