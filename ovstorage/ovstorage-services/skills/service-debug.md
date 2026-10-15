# Skill: ovstorage-services/service-debug

Use this skill to triage a running ovstorage-compatible service deployment.

## Debug Order

1. Confirm which API/version the failing call targets.
2. Check service discovery and capability output.
3. Reproduce through the `ovstorage` Python API or CLI with the smallest
   operation that fails.
4. Compare behavior against the relevant API conformance scenario.
5. Check auth, permission, redirect, multipart, metadata, and range-read
   behavior only after basic discovery and capability checks pass.

## Evidence To Capture

- Endpoint hostnames, not tokens or secret values.
- API/version and operation name.
- Request shape with credentials redacted.
- Response status, typed error body, and relevant headers.
- Library command or Python snippet used to reproduce.
- Whether the behavior is unsupported, non-conformant, or deployment-specific.

## Related Material

- Running services: [`../docs/running-services.md`](../docs/running-services.md)
- API conformance: [`../docs/conformance.md`](../docs/conformance.md)
