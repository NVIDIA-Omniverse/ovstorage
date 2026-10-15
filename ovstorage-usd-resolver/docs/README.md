# ovstorage USD Resolver Docs

This directory holds the architecture, verification guides, and
compatibility reference for `ovstorage-usd-resolver`.

## Build and install

- [building.md](building.md): build the resolver for the host SDK, configure
  schemes/providers and verify integration. No resolver wheels are distributed
  for this release.
- [native-package.md](native-package.md): optional local CMake installation.
- [python-wheels.md](python-wheels.md): optional locally built Python package
  and bootstrap API, restricted to the pinned SDK.

## Reference

- [`../examples/embed_resolver/`](../examples/embed_resolver/): runnable
  source-consumer integration from ovstorage stack construction through
  `UsdStage::Open`.
- [architecture.md](architecture.md): library boundaries, resolver
  registration posture, and integration with ovstorage.
- [api-stability.md](api-stability.md): public-header inventory and the exact
  source, ABI, CLI, trace, and packaging compatibility commitments.
- [configuration.md](configuration.md): standalone and embedded
  configuration contract.
- [compatibility-matrix.md](compatibility-matrix.md): OpenUSD, ovstorage,
  platform, and ABI targets.
- [cli-reference.md](cli-reference.md): CLI command set, JSON schema, and exit-code
  policy.
- [decisions/README.md](decisions/README.md): release-blocking decision
  summary.
- [test-strategy.md](test-strategy.md): unit, integration, and optional
  live-smoke coverage expectations.
- [local-verification.md](local-verification.md): reproducible NVIDIA Kit
  OpenUSD acquisition and ovstorage SDK-backed checks.
- [legacy-behavior-ledger.md](legacy-behavior-ledger.md): per-behavior
  status table for legacy resolver parity and deferrals.

## Scope Guardrails

The resolver:

- routes build-advertised non-local schemes through configured ovstorage
  providers, including the default `https://`, `s3://`, and `hf://` profile as
  well as provider-backed schemes selected by downstream builds;
- allows local USD files to continue working without ovstorage installed;
- avoids hidden omniclient dependencies;
- exposes clear diagnostics when ovstorage is unavailable, misconfigured, or
  unable to access a remote asset;
- supports package and USDZ resolution paths required by OpenUSD composition.

In 0.1, the resolver does not:

- implement provider transports or service-specific workflow APIs; these
  belong to ovstorage and the consuming application;
- copy source code from the legacy resolver;
- own non-USD asset IO for downstream consumers. This resolver owns USD
  resolution and USD asset materialization.

## Implementation status

The identifier module, URI resolver plugin (advertised schemes set at
build time via `OVS_USD_RESOLVER_URI_SCHEMES`; shipping default
`s3;http;https;hf`), concrete scheme-agnostic ovstorage bridge (including
0.1-tested graphs composed from file, HTTP, S3, and read-only Hugging Face
providers), lease-based
materialization (the bridge owns
the on-disk lease), and diagnostic CLI all ship. Composed OpenUSD
stage smokes cover HTTP end-to-end (loopback fixture), USDZ through
the concrete bridge, and deterministic cross-scheme composition from a remote
package. Native `s3://` release qualification covers AWS S3 and is gated by
the env-var-controlled `live_s3_stage` smoke. Other S3-compatible profiles are
inherited from ovstorage and are not resolver-qualified in 0.1. A pinned public NVIDIA
Hugging Face fixture is covered by the opt-in `live_hf_stage` smoke.

The [legacy behavior ledger](legacy-behavior-ledger.md) lists each
resolver behavior with its current coverage status.
