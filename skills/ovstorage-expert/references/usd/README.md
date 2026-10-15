Up: [ovstorage-expert](../../SKILL.md)

# USD workflows and data access

Use this for basic USD questions as they relate to fetching content. For call-by-call detail see [data-flow.md](data-flow.md). For diagrams see [sequence-diagrams.md](sequence-diagrams.md). To share the full explanation with a person, link the published page [How USD content flows](../../../../docs/usd-data-flow.md).

## USD concepts that drive I/O

- **Stage and layers.** A `UsdStage` composes a root layer and every layer it pulls in. Each layer is a file (`.usd`, `.usda`, `.usdc`, or a `.usdz` package) that OpenUSD must find and open.
- **Composition arcs load files.** Sublayers, references, and payloads each name an asset path that OpenUSD resolves and opens. Variants and other arcs only select from content that is already loaded. Payloads can be deferred (`UsdStage::Open(..., UsdStage::LoadNone)`, then `Load()`), which is the main lever for fetching less.
- **Asset paths come in three forms:**
  - An *absolute URI* in a claimed scheme, such as `s3://bucket/scene/root.usd`, goes to this resolver.
  - A *relative path* inside a remote layer anchors to that layer's URI and also goes to this resolver.
  - A *bare path or a local file* stays with OpenUSD's default filesystem resolver, so no remote lookup happens.
- **Asset resolver (`Ar`).** OpenUSD asks a resolver to create an identifier, resolve it, open it, and report timestamps and asset info. This resolver is a URI resolver for the schemes advertised at build time (default `s3;http;https;hf`). Local paths stay with OpenUSD's filesystem resolver. Additional remote schemes, including `omni` and `omniverse`, can be advertised when the host supplies matching ovstorage routes and avoids competing resolver registrations.
- **Resolver context.** OpenUSD calls reach ovstorage only while a context naming a runtime is bound. In Python that is `Runtime(config).bind()`. In C++ it is `ScopedDefaultContext`, or `ArResolverContextBinder` with `makeOpenUsdResolverContext`. Bindings are per thread, so each worker thread binds its own ([embed](../resolver/embed.md)).
- **Layer reuse.** OpenUSD keeps opened layers in its own registry. Reopening a stage in the same process may fetch nothing. Reload decisions use the modification timestamp the resolver reports from `stat`.

## Who does what

| Concern | Owner |
| --- | --- |
| Composition, layer parsing, package (USDZ) internals | OpenUSD |
| Which identifiers are remote, anchoring relative paths, the scheme gate, local file leases for `ArAsset` | Resolver |
| Routing, credentials, retries, redirects, caching, the provider protocol | ovstorage Stack, as configured in `ovstorage.toml` |

The resolver caches no bytes. Repeat reads get faster only through Layers declared in the Stack (`byte_cache`, `metadata_cache`, `hub_cache`) or through the caches in [related experts](../related-experts.md).

## Common questions

- **Do local stages need ovstorage?** No. Local paths never touch it.
- **Why does a texture or MDL file fail when the layer opens fine?** The resolver handles USD layers and packages. Other consumers in a host need their own integration for remote schemes ([resolver configuration](../../../../ovstorage-usd-resolver/docs/configuration.md)).
- **Is there partial or range loading?** OpenUSD opens assets through a materialized local file. Range reads exist for direct `StorageBridge::read` callers, not for `UsdStage::Open`.
- **Can I save back?** Yes, on write-capable routes, as whole-object uploads. The shipped HTTP provider is read-only. See [data-flow.md](data-flow.md#write).
- **How do I see what happened?** Run `ovstorage-usd-resolver trace <uri> --stack-config ovstorage.toml --json` ([validate](../resolver/validate.md)).
