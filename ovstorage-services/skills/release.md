# Skill: ovstorage-services/release

Use this skill for service/API compatibility and release readiness checks.

## Release Checks

- Confirm the service's `api-support.yaml` matches the API versions it actually
  advertises.
- Confirm the relevant conformance suite passed for every advertised API
  version.
- Confirm the `ovstorage` library service adapter supports the API routes the
  service expects clients to use.
- Confirm deployment release notes identify image/chart versions in the owning
  deployment repo.
- Confirm rollback compatibility with the previous service release.
- Confirm no credentials, internal endpoints, or environment-specific secrets
  are committed to this repo.

## Related Material

- API support declaration: [`../docs/api-support.md`](../docs/api-support.md)
- Conformance guide: [`../docs/conformance.md`](../docs/conformance.md)
- API contribution route: [`api-contribute/AGENTS.md`](api-contribute/AGENTS.md)
