# Skill: ovstorage-services/operator

Use this skill for deployment review, day-2 operations, observability,
rollbacks, and environment triage for services that implement ovstorage APIs.

This repo does not contain Helm charts, operators, or production deployment
assets. Use this skill to inspect deployment docs, validate assumptions, and
produce safe operator-facing checklists.

## Start Here

1. Read [`../docs/deployment.md`](../docs/deployment.md).
2. Read [`../docs/running-services.md`](../docs/running-services.md).
3. Check API support declarations with [`../docs/api-support.md`](../docs/api-support.md).
4. For deployment-specific agent workflows, load the imported bundle through
   [`deploy/README.md`](deploy/README.md).
5. Use [`service-debug.md`](service-debug.md) for incident triage.

## Operator Checks

- Identify the service endpoint, discovery endpoint, and advertised API
  versions.
- Confirm auth and cloud credentials are configured outside repo examples and
  logs.
- Confirm health/readiness/capability endpoints are reachable.
- Confirm the deployment has passed the relevant API conformance suite.
- Confirm rollback compatibility with the previous API support declaration.
- Never print bearer tokens, cloud keys, presigned URLs, or secret values.
