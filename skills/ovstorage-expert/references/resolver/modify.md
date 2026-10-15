Up: [ovstorage-expert](../../SKILL.md)

# Change resolver behavior

Before editing, read [architecture.md](../../../../ovstorage-usd-resolver/docs/architecture.md), [api-stability.md](../../../../ovstorage-usd-resolver/docs/api-stability.md), and [test-strategy.md](../../../../ovstorage-usd-resolver/docs/test-strategy.md), as the resolver's agent entry requires. Implementation rules are in `ovstorage-usd-resolver/.agents/develop-resolver.md`: keep OpenUSD integration in C++, keep the `StorageBridge` narrow, keep materialization lease-owned, add no resolver-side byte cache, redact credentials in traces, and copy no code from earlier NVIDIA resolvers.

## Where changes go

| Change | Edit | Tests to extend |
| --- | --- | --- |
| Claim another URI scheme | Build flag only: `OVS_USD_RESOLVER_URI_SCHEMES` ([configure.md](configure.md)) | Plugin-registration smoke; add a routed smoke if behavior differs |
| Identifier parsing, normalization, packages, SDF args | `src/identifier.cpp` | `tests/unit/identifier_tests.cpp` |
| Resolve, open, write gates | `src/openusd/resolver.cpp`, `src/openusd/writable_asset.cpp` | `tests/openusd/*_smoke.cpp` |
| Runtime options and validation | `include/ovstorage_usd_resolver/configuration.hpp`, `src/configuration.cpp` | `tests/unit/configuration_tests.cpp` |
| Existence cache, tracing | `src/runtime.cpp` | `tests/unit/runtime_tests.cpp` |
| How ovstorage is called | `src/ovstorage_stack_bridge.cpp`; the contract is `include/ovstorage_usd_resolver/storage_bridge.hpp` | Bridge unit tests plus SDK-backed bridge smokes |
| CLI output or errors | `tools/ovstorage_usd_resolver_cli.cpp` and [cli-reference.md](../../../../ovstorage-usd-resolver/docs/cli-reference.md) | `tests/no_sdk/` CLI scripts |

New storage *backends* are not a resolver change. They belong to ovstorage providers: route plugin development to the [plugin contract](../../../../ovstorage/docs/public/plugin-development/README.md). Storage API services and their adapters are developed outside this checkout ([related experts](../related-experts.md)).

## What must change with it

- Public headers and CLI JSON are governed by `api-stability.md`. Changing them requires a `CHANGELOG.md` entry, focused tests, and updated reference docs.
- Behavior that a release decision settles (registration mode, `Resolve()` existence semantics, write scope, cache versus lease, scheme source of truth, USD flavour) is recorded in [decisions](../../../../ovstorage-usd-resolver/docs/decisions/README.md). Changing one means revisiting that decision, not just the code.
- Legacy-resolver behavior differences are tracked in [legacy-behavior-ledger.md](../../../../ovstorage-usd-resolver/docs/legacy-behavior-ledger.md).
- Run all three build levels' tests after the change ([validate.md](validate.md)). Storage-side changes also need storage's `make verify` and `make test`.
