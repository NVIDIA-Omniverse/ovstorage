# API Stability

Version 0.1 is a source-consumed preview; no resolver wheels are published
for this release. It gives applications a supported way to
build and evaluate the resolver, but it does not freeze the C++ source or
binary interface before the project has real downstream integration history.

## Compatibility Commitments

| Surface | Version 0.1 commitment |
| --- | --- |
| Public C++ headers | Preview. Declarations, types, and ownership shapes may change in a later 0.x release. Source compatibility is not guaranteed unless a later release says otherwise. |
| C++ binary ABI | Not supported. Consumers compile the resolver against ovstorage 0.3.x and the exact OpenUSD SDK used by their host, within the current [Kit 25.11 nopy monolithic SDK restrictions](building.md#select-the-host-sdk). |
| OpenUSD plugin binary | Bound to the OpenUSD distribution used to build it. `PXR_VERSION` equality alone does not establish ABI compatibility. |
| Installed package | Build locally from source. The opt-in native CMake install/export surface is preview and exact-version-only; see [native installation](native-package.md). No resolver wheels are distributed for this release. Local packaging does not establish a native archive or Conan publication commitment. |
| CLI JSON | `schema_version: "1"`, required envelope fields, documented error codes/categories, and exit-code meanings are stable within the `0.1.x` line. Compatible fields may be added. |
| Human-readable CLI text | Diagnostic preview output. Do not parse it as a stable interface. |
| Resolver trace vocabulary | Diagnostic preview data. Event names and payload detail are not stable unless a later policy explicitly promotes an event family. Trace identifiers and URI-shaped message tokens are credential-redacted before callbacks. |
| URI scheme build setting | `OVS_USD_RESOLVER_URI_SCHEMES` is a supported source-build setting. A runtime may narrow the compiled set. The shipping default may expand when another ovstorage provider has release evidence. |

An incompatible CLI JSON change does not land silently in `0.1.x`. It requires
a later minor release and either a new schema version or a documented
transition that lets existing consumers continue to distinguish the old
shape. The complete version-1 error contract is in
[the CLI reference](cli-reference.md#stable-error-contract).

The preview C++ posture does not make behavior changes invisible. Changes to
public declarations or ownership rules are called out in `CHANGELOG.md`, and
source consumers should review those notes before moving between revisions.

## Public Header Inventory

Every header under `include/ovstorage_usd_resolver/` is part of the preview
source API. The inventory describes the current source revision: the version
0.1 headers plus `host.hpp` and `openusd_host.hpp`, which `CHANGELOG.md` lists
under Unreleased and no 0.1.0 preview candidate contains.

| Header | Consumer role |
| --- | --- |
| `configuration.hpp` | Configure a resolver runtime, provide a storage-bridge factory, and receive diagnostic trace events. |
| `identifier.hpp` | Apply the same URI, package, SDF-argument, normalization, provider-target, and diagnostic-redaction rules as the resolver. |
| `materialization_cache.hpp` | Own `MaterializedAsset` and `MaterializationResult` lease values returned by the runtime. The resolver exposes no materialized-byte cache despite the filename. |
| `runtime.hpp` | Create and call a context-local `ResolverRuntime` for stat, materialize, write, capability, and trace operations. |
| `storage_bridge.hpp` | Implement or consume the resolver-facing storage abstraction, status vocabulary, metadata, leases, and whole-object writes. |
| `ovstorage_stack_bridge.hpp` | Construct the optional concrete ovstorage adapter from a `LayerHandle` or ovstorage StackConfig. Its SDK-on shape depends on the pinned ovstorage C++ headers. |
| `openusd_context.hpp` | Bind a runtime into OpenUSD resolver contexts. It is available only in an OpenUSD plugin build and inherits that SDK's ABI constraint. |
| `host.hpp` | Adopt a host-built ovstorage stack: a same-copy `OvStorage_LayerHandle*`, or an `OvStoragePlugin_LayerHandle` exported by another copy of ovstorage's C runtime. The header is C++17; the `ovstorage::usd_resolver_host` library behind it contains the concrete bridge, so building it needs that bridge's C++20 compiler floor (GCC 13+, Clang 17+ or MSVC 19.40+). Available only in a build with the ovstorage SDK, which also supplies the `ovstorage.h` it includes. |
| `openusd_host.hpp` | Register the resolver plugin before first OpenUSD use with late-registration and duplicate-scheme diagnostics, verify dispatch, and make a runtime's `ArResolverContext`. Header-only and C++17; available only in an OpenUSD plugin build. |

No header in this inventory is classified as implementation-only. Some types
are primarily adapter or extension seams rather than the shortest consumer
path, but source hosts and test doubles legitimately use them. Their presence
in the table is not a promise that their current signatures survive future
0.x releases.

## Internal Surface

Files outside the public include directory are not C++ API merely because they
are present in the source archive. In particular:

- `src/file_root.hpp` and `src/openusd/writable_asset.hpp` are implementation
  headers;
- the configured `ovstorage_usd_resolver/build_config.hpp` is generated for
  this build and is not a consumer contract;
- test-support headers, examples, CMake internals, and plugin metadata
  templates are validation or integration material, not library API.

Consumers should include only headers from the inventory above. The optional local Python package does not establish a stable native C++ package ABI.

## Review Rule

Any pull request that changes a public header, a documented build contract, or
an agent-facing CLI contract must:

1. describe the consumer-visible effect in `CHANGELOG.md`;
2. update this document when the compatibility posture or public inventory
   changes;
3. update focused tests and the relevant reference documentation; and
4. verify the prospective public source projection rather than only the
   internal repository tree.

Release review compares the public headers and CLI contract against the
selected candidate commit. A release can still be rejected when a
preview API change is undocumented or when the public documentation implies a
stronger source, ABI, or packaging guarantee than this policy provides.

The Python `Runtime`, scoped binding, registration, and CLI locator are preview
0.1 APIs. The ctypes C entrypoints are private implementation details versioned
as a unit with the Python package. The checked `createOvStorageBridge(options,
status)` overload exposes eager setup diagnostics without changing the existing
factory overload or its deferred-error behavior.

The optional locally built wheel distribution name is flavour-specific (`ovstorage-usd-resolver-kit-25-11`).
`Runtime` accepts `usd_sdk_root` for early exact-SDK validation and registration;
reusing the same selected SDK is permitted, replacing a loaded SDK is not.
