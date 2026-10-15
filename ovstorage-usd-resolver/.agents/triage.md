# Triage

Start with:

1. [`docs/cli-reference.md`](../docs/cli-reference.md)
2. [`docs/configuration.md`](../docs/configuration.md)
3. [`docs/test-strategy.md`](../docs/test-strategy.md)

Classify failures by owner:

- OpenUSD: plugin discovery, resolver selection, package resolver behavior,
  composition errors;
- resolver: identifier normalization, relative joins, package identifier
  preservation, bridge-lease materialization, Resolve-existence metadata
  caching, diagnostics;
- ovstorage: backend route selection, read/stat/range behavior, auth,
  provider errors;
- storage backend: object not found, permissions, region, redirects, service
  availability.

Always capture:

- input identifier;
- normalized identifier;
- base asset/context if relevant;
- operation type;
- ovstorage status;
- whether the failure occurs for local file, HTTPS, native `s3://`, or package
  paths.
