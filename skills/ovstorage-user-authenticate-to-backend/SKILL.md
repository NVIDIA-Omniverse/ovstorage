---
name: ovstorage-user-authenticate-to-backend
description: Use when configuring credentials or driving interactive authentication for a direct ovstorage backend connection.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, authentication, credentials]
tools: [Read]
compatibility: Requires ovstorage MCP tools or equivalent library calls. Backend credentials, browser/device auth, network access, and service URLs are user-supplied when needed.
---

# Authenticate to a Backend

## Goal

Create or refresh credentials for a backend connection without leaking secrets
into logs, route metadata, or tool output.

## When to use this

Use this when adding a new direct-mode connection (`file`, `http`,
`omniverse-storage-service`, `s3`, `gcs`, `azure`, `opendal`, or any
other backend kind), or when an existing connection reports
`AuthRequired`, `CredentialExpired`, or an inactive `auth_state_kind`
in `ovstorage_doctor`.

## Recipe

1. Inspect available backend kinds and configured connections with
   [`ovstorage-user-getting-started`](../ovstorage-user-getting-started/SKILL.md).
2. Read the backend descriptor and credential schema before prompting for
   anything secret. Library callers get this from
   `Storage::list_backend_kinds`; CLI users can use the `connect` wizard.
3. For `file`, no external credential is normally required. Register the root
   path and keep credentials empty.
4. For `http`, prefer public or pre-authorized URLs. If an HTTP route
   needs credentials, pass them through the connection credential schema or a
   host-provided credential callback, not through the address string.
5. If `authenticate_connection` returns an auth event stream, surface
   `OpenBrowser`, `DeviceCode`, `Progress`, `Succeeded`, `Failed`, and
   `Cancelled` events to the user exactly as events, then stop on a terminal
   event.

## Backend-specific auth

### `omniverse-storage-service`

The `omniverse-storage-service` backend authenticates over OIDC. The plugin reads
`/api/v1/auth-config` from the configured `discovery_url` to learn the
OIDC issuer and client; the standard OIDC discovery doc supplies the
auth / token / device endpoints.

Two interactive flows:

- **Browser** (`InteractiveAuthCapability::Browser`): PKCE with a
  loopback redirect. The plugin opens the user's browser to the
  authorization endpoint, captures the code at a transient localhost
  callback, and exchanges it for the token bundle.
- **Headless** (`InteractiveAuthCapability::Headless`): RFC 8628
  device flow. The plugin requests a device code, surfaces a
  user-code + verification URL via `AuthEvent`, and polls the token
  endpoint until the user completes the flow on a separate device.

In both cases the resulting `OAuthToken` lands as the connection's
`oauth` credential bundle. The plugin proactively refreshes the access
token in a background task at ~90% of the token's TTL using the
refresh-token grant (or the client-credentials grant if that's the
configured method). No intervention required for long-running processes.

To pre-seed credentials (e.g. for CI), populate `oauth` with a long-lived
refresh token; the plugin will exchange it for an access token on first
use.

### `s3`

The descriptor exposes three credential methods:

- `static_key` — long-lived IAM user key. Populate
  `aws_access_key_id` + `aws_secret_access_key`.
- `session` — short-lived STS / SSO credentials. Populate
  `aws_access_key_id` + `aws_secret_access_key` +
  `aws_session_token`.
- `aws_credentials_file` — read from an INI section. Populate
  `file_path` (defaults to `~/.aws/credentials`) and `profile`
  (defaults to `default`); the per-connection `profile` config key
  picks the section.

Each credential field's descriptor default is the matching `${AWS_*}`
env-var placeholder (e.g. `${AWS_ACCESS_KEY_ID}`); the host's
bundle-resolution layer expands these before the bundle reaches the
plugin. From the plugin's point of view the resolution chain is
bundle fields → env vars (via placeholder expansion) → shared
credentials file. IMDS, AWS SSO, web-identity tokens, and STS role
assumption are not implemented in-process; operators that need them
run their session helper (`aws sso login`, etc.) to materialise a
static-key profile.

### `gcs`

The descriptor exposes two credential methods:

- `service_account_key` — paste a service-account JSON keyfile into
  the `service_account_key` field. The plugin auto-detects the JSON
  `type`: `service_account` triggers JWT-bearer exchange (and is
  the only path that can mint V4-signed read URLs); `authorized_user`
  triggers an OAuth2 refresh-token exchange (reads stream through
  `alt=media` under the cached bearer because authorized-user creds
  cannot V4-sign).
- `gcloud_adc_file` — populate `file_path` with the path to an
  ADC JSON file written by `gcloud auth application-default login`
  (defaults to `~/.config/gcloud/application_default_credentials.json`,
  with `~` expanded against `HOME` / `USERPROFILE` + `HOMEDRIVE`).

The plugin does **not** consult `GOOGLE_APPLICATION_CREDENTIALS` or
any other env var; if you need env-var expansion, do it in the host's
bundle-resolution layer before handing the bundle to the plugin.
GCE/GKE metadata, workload-identity federation
(`external_account`), and service-account impersonation
(`impersonated_service_account`) are not implemented in-process.

### `azure`

The descriptor exposes four distinct credential methods. The plugin
resolves them in this order:

- `account_key` — Shared Key signing. Populate `account_key`.
- `sas_token` — pre-issued shared-access signature appended verbatim
  to request URLs. Populate `sas_token`.
- `workload_identity` — Entra OAuth2 federated workload identity.
  Populate `federated_token_file` + `client_id` + `tenant_id`.
- `service_principal` — Entra OAuth2 client-credentials. Populate
  `client_id` + `client_secret` + `tenant_id`.

Each credential field's descriptor default is the matching
`${AZURE_*}` env-var placeholder
(`${AZURE_STORAGE_ACCOUNT_KEY}`, `${AZURE_STORAGE_SAS_TOKEN}`,
`${AZURE_TENANT_ID}`, `${AZURE_CLIENT_ID}`, `${AZURE_CLIENT_SECRET}`,
`${AZURE_FEDERATED_TOKEN_FILE}`); the host's bundle-resolution layer
expands these before the bundle reaches the plugin. The plugin
itself never reads `AZURE_*` env vars at runtime. Managed Identity
(IMDS), `az login`, VS Code, and PowerShell credential sources from
`DefaultAzureCredential` are not implemented in-process.

### `opendal`

Auth depends on the chosen `service` (one of `fs`, `s3`, `webdav` —
the only services compiled in). `fs` requires no credentials.
The OpenDAL `s3` driver wants `access_key_id` + `secret_access_key`
(**bare names**, not `aws_*`-prefixed — these are NOT
interchangeable with the first-party `s3` plugin's credential
shape). `webdav` uses HTTP Basic credentials (`password`, plus
`username` passed through `config_json`). The adapter accepts only
`SecretValue::Bytes`, `SecretValue::OAuthToken`, and
`SecretValue::File` for these fields; `SecretValue::SystemIdentity`
and `SecretValue::MtlsCertPair` are rejected as `Unsupported`.
Ambient-identity flows (Kerberos ticket cache, etc.) are not
threaded through. See
[`plugin-opendal.md`](../../docs/public/plugin-storage/plugin-opendal.md)
for per-driver detail.

### `nucleus`

Omniverse Nucleus's auth shape predates the unified OAuth pattern
used by the Omniverse Storage Service and the cloud backends.
The descriptor exposes three user-selectable credential methods:

- **`sso`** — single sign-on (browser). Recommended. Binds no
  credential fields. The plugin (`establish_interactive_auth`)
  calls `Tokens::subscribe` to register a one-shot login intent,
  receives a server-generated `nonce`, and surfaces
  `AuthEvent::OpenBrowser` with the Nucleus login URL annotated
  with `?nonce=<nonce>`. The host UI opens the URL; once the user
  completes the form, the second response on the same subscription
  carries the authentication result. The plugin never touches raw
  passwords or 2FA challenges on this path.
- **`userpass`** — username and password. Binds `username` and
  `password`; drives Nucleus's `Credentials::auth` flow. For
  service accounts and headless deployments.
- **`api_token`** — API token. Binds a single `api_token`
  credential. Drives `Tokens::auth_with_api_token`; takes
  precedence over `username` / `password`. The `Auth` envelope's
  `username` is recorded as the authenticated principal. The
  recommended automation path.

Successful authentication via `sso` produces a refresh token that
the plugin persists in the OS keyring keyed by the *server
hostname* (not the host-minted, unstable `ConnectionId`). On
subsequent connects, warm-continuation reads `refresh_token` from
the keyring, rediscovers `tokens_url`, and exchanges the refresh
token without re-prompting; on a service-call `Expired` /
`InvalidToken`, the plugin invokes `Tokens::refresh` once per
token-generation epoch (concurrent callers share a single refresh
under a per-shared mutex). `AuthRequired` / `AuthExpired` /
`PermissionDenied` clear the keyring entry; `Transient` preserves
it for retry. SSO (`SSO::*`) and DeviceFlow (`DeviceFlow::*`) are
declared as target / deferred flows; they are not wired today.

### `broker`

The `broker` plugin authenticates to an upstream `ovstorage-broker`
daemon; the broker itself holds the long-lived cloud credentials and
runs its own authn substrate against whatever listener-authn mode
operators configured. From the calling host's perspective the
client-side credential surface is intentionally minimal:

- **`client_credentials`** — OIDC client credentials grant. Binds
  `client_id` + `client_secret`. Only valid when the configured
  `address` is a discovery URL (not a direct gRPC endpoint): the
  plugin fetches `/api/v1/auth-config`, follows the published
  `openid_configuration` URL to the IdP's standard OIDC discovery
  doc, and drives a non-interactive client-credentials grant. Suited
  for service accounts and headless deployments.

Interactive flows (PKCE loopback for `Browser`, RFC 8628 device flow
for `Headless`) are driven by `Factory::authenticate` against the
same broker-published `auth-config`. The host signals which mode is
available through the gRPC `x-ov-iauth: browser|headless|none`
metadata header attached by the broker-client SDK on every RPC; the
broker reads this on its streaming `Auth` RPC, threads the parsed
`InteractiveAuthCapability` into the upstream-OAuth flow, and emits
`AuthEvent::OpenBrowser` / `DeviceCode` / `Progress` / `Succeeded`
back to the host. `None` mode causes the broker to emit a terminal
`Failed { AuthRequired }` envelope without opening a browser tab or
device prompt — the fail-fast shape render workers and CI hosts
need.

**Three-tier OAuth, broker-held.** Successful interactive auth lands
a refresh token *on the broker* via the unary `RegisterCredential`
round-trip; the broker persists it through its `OAuthCredentialProvider`
+ `secret_tokens` row + `SecretStore` (per-`(BackendId, PrincipalView)`
slot). The host process holds only the short-lived broker bearer —
never the upstream cloud credentials. Workers and a coordinator that
share a `PrincipalView` at the broker hit the same cache slot, which
covers the multi-tenant SaaS and render-worker shapes without any
host-side coordination.

The broker daemon's listener authn mode (`jwt_verify`,
`trusted_unsigned_jwt`, `trusted_forwarded_headers`, `peer_cred`, or
the reserved `mtls`) decides how the host's bearer is validated —
that's operator-owned config and is not part of the
`broker-client`-side credential schema. See
[`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
for the daemon side.

## References

- [`docs/public/library-rust/README.md`](../../docs/public/library-rust/README.md) for
  `add_connection`, credential persistence, and `authenticate_connection`.
- [`plugin-file`](../../docs/public/plugin-storage/plugin-file.md)
  for local filesystem configuration.
- [`plugin-http`](../../docs/public/plugin-storage/plugin-http.md)
  for HTTP route behavior.
- [`plugin-services-client`](../../docs/public/plugin-storage/plugin-services-client.md)
  for the `omniverse-storage-service` OIDC flow.
- [`plugin-nucleus`](../../docs/public/plugin-storage/plugin-nucleus.md)
  for the Omniverse Nucleus auth flows.
- [`plugin-broker`](../../docs/public/plugin-storage/plugin-broker.md)
  for the broker-client SPI surface, discovery URL normalization,
  and the broker-held three-tier OAuth model.
- [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
  for the daemon-side listener authn modes a broker operator
  configures.
- [`ovstorage-user-handle-errors`](../ovstorage-user-handle-errors/SKILL.md) for interpreting
  auth and permission failures.
