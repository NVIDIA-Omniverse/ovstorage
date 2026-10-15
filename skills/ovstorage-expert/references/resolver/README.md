Up: [ovstorage-expert](../../SKILL.md)

# The ovstorage USD resolver

`ovstorage-usd-resolver` (version in [VERSION](../../../../ovstorage-usd-resolver/VERSION)) is an OpenUSD `ArResolver` plugin. It claims only the URI schemes advertised at build time — default `s3;http;https;hf` — and leaves local paths, bare asset paths, and unadvertised schemes to OpenUSD's default or other resolvers. Remote bytes flow through ovstorage; the resolver never calls a provider SDK or omniclient. Authoritative reference: [architecture.md](../../../../ovstorage-usd-resolver/docs/architecture.md).

## How a remote stage opens

1. `_CreateIdentifier` normalizes the URI (`src/identifier.cpp`); `_Resolve` claims it only if its scheme is advertised and the runtime has a usable bridge (`src/openusd/resolver.cpp`).
2. `_OpenAsset` asks the runtime to **materialize** the object through the `StorageBridge` (`include/ovstorage_usd_resolver/storage_bridge.hpp`). The concrete bridge (`src/ovstorage_stack_bridge.cpp`) uses ovstorage's `LayerHandle::read_local_file`, or reads into a bridge-owned temp file when a backend has no local materialization.
3. The asset holds a lease on that local file; dropping the asset releases it. The resolver keeps **no byte cache**, and ovstorage owns on-disk bytes and their GC.
4. Sublayers, references, payloads, and USDZ inner paths resolve relative to the remote layer and route back through the resolver.
5. Writes (`UsdStage::Save`, `OpenAssetForWrite`) stage locally, then perform one whole-object write with a precondition on routes that can write (`src/openusd/writable_asset.cpp`).

## Who owns what

- The **host** owns the ovstorage configuration and Stack (or hands the resolver a config path), and must configure the resolver before OpenUSD first selects a resolver.
- The **resolver** owns identifier, context, and asset behavior.
- **ovstorage** owns provider I/O, credentials, and materialized bytes.

`resolveVerifiesExistence` adds a bounded, metadata-only existence cache for hosts that treat `Resolve()` as proof of existence; it is off by default.

## Files in this reference

| File | Read it when |
| --- | --- |
| [build.md](build.md) | Building from this checkout, with or without the OpenUSD plugin |
| [configure.md](configure.md) | Choosing schemes, registering the plugin, runtime options, the CLI |
| [embed.md](embed.md) | Wiring the resolver into a C++ host, an optional local Python package, or a local native CMake install |
| [validate.md](validate.md) | Proving it works, running tests, diagnosing failures |
| [modify.md](modify.md) | Changing resolver behavior and what must change with it |
| [openusd-version.md](openusd-version.md) | Targeting a different OpenUSD SDK |

Resolver task guides for agents live in `ovstorage-usd-resolver/.agents/` and are routed from its [agent entry](../../../../ovstorage-usd-resolver/AGENTS.md). It requires reading `architecture.md`, `api-stability.md`, and `test-strategy.md` before implementation work.
