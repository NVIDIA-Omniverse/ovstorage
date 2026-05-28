# Skill: ovstorage-services/auth-secrets

Use this skill for service-side credentials, cloud identity, Kubernetes secret
boundaries, token exchange boundaries, and agent-safe handling of operational
auth material.

This repo does not include secret material or internal auth bootstrapping flows.
Keep environment-specific auth instructions in the owning deployment or auth
repo.

## Rules

- Never print bearer tokens, refresh tokens, cloud keys, kubeconfigs, presigned
  URLs, or secret values.
- Describe secret ownership and rotation responsibilities without embedding
  values.
- Distinguish client-to-service credentials from service-to-storage provider
  credentials.
- Prefer capability checks and redacted error summaries over raw logs.
- If a task requires an auth flow that is not documented here, route to the
  owning auth/deployment repo rather than adding ad hoc instructions here.

Do not route ordinary library users here. Library users should start at
[`../../AGENTS.md`](../../AGENTS.md).
