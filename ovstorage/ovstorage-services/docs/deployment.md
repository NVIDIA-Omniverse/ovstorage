# Deployment Guidance

This repo does not ship Helm charts, operators, or service source code.
Deployment assets live in service/deployment repositories outside this repo.

The purpose of this document is to define what deployment documentation should
answer for an ovstorage-compatible service stack.

## Minimum Deployment Information

- Service endpoint and discovery endpoint shape.
- Required cloud credentials and secret ownership.
- Supported API versions and `api-support.yaml` location.
- Health, readiness, and capability-check routes.
- Required storage backends and provider permissions.
- Upgrade, rollback, and compatibility policy.
- Conformance and smoke-test gates before promotion.

## Boundary With This Repo

This repo provides:

- API specs and conformance tests under [`../apis/`](../apis/);
- service/operator skills under [`../skills/`](../skills/);
- the imported deploy skill bundle under [`../skills/deploy/`](../skills/deploy/);
- the `api-support.yaml` template under [`../templates/`](../templates/).

This repo does not provide:

- service implementation source;
- Helm charts;
- Kubernetes operators;
- production environment configuration;
- secrets or auth bootstrapping flows.

## Release Archive Posture

Release archives should include this subtree as the service/API support
surface: specs, conformance material, deployment guidance, templates, and
agent skills. They should not imply that this repo contains a production-ready
deployment bundle.

The imported skills and reference material are useful for service teams and
agents, but any actual deployment package remains owned by the corresponding
service/deployment repository. If a future release intentionally includes
charts, operators, environment overlays, or auth bootstrapping material, that
release must name the owning repository and license/product terms explicitly.

## Related Material

- Running services: [`running-services.md`](running-services.md)
- API support: [`api-support.md`](api-support.md)
- Operator skill: [`../skills/operator.md`](../skills/operator.md)
