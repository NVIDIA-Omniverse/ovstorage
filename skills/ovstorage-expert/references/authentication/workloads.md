Up: [authentication](README.md)

# Unattended workloads

Render farms, CI jobs, simulation workers, and services have nobody to finish a sign-in. Build their Stack with capability `NONE`, so a missing credential fails at once with `AuthRequired` instead of waiting on a prompt nobody will answer.

## Give the workload its own identity

Prefer an identity the platform issues to the workload over anything copied from a person:

- **Federated workload identity.** The workload presents a token its platform issues (a CI OIDC token or a Kubernetes service account token) and exchanges it for storage access. Backends that support it take the token from a file the platform keeps current. Examples are Azure's `workload_identity` method and a GCS `external_account` configuration.
- **Client credentials.** A non-interactive OAuth grant for a service account, where the backend offers one. The broker client takes one against a discovery address.
- **Short-lived session credentials.** Produced by the platform's own helper and passed in through `${VAR}` references. Rotate them before they expire.
- **Static keys.** The simplest option, and long-lived. Scope them narrowly.

Don't reuse a person's refresh token or saved sign-in for a workload: when that person leaves or rotates it, the workload breaks with them. When a child process needs delegated access for one task, pass it a current, short-lived access token instead.

Federation proves the workload's identity. The workload still needs its own access grant from whoever owns the content. Request it separately from the identity setup.

Per-backend fields and limits: [authenticate to a backend](../../../../ovstorage/skills/ovstorage-user-authenticate-to-backend/SKILL.md) and [credential providers](../../../../ovstorage/docs/public/plugin-storage/credential-providers.md).

## Centralize credentials with the broker

When many workers share backends, run `ovstorage-broker`. It holds the backend credentials, and each worker holds only a credential for the broker, which the broker's listener auth mode validates. Workers that share a principal at the broker share its credential cache. Setup: [storage/deploy.md](../storage/deploy.md).

## Rotate and verify

- Rotate injected tokens with `update_connection_credentials` (in Python, `set_credential` pushes into the Stack's cache), or restart with fresh environment values.
- Before scaling out, check in the real worker environment: `list-connections`, a list, a pinned input read, and a scratch output write with read-back. Stop at the first failure and report the step that failed.
