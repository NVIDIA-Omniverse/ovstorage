# ovstorage documentation

Start here for the ovstorage library and the ovstorage USD resolver. The
[repository overview](../README.md) explains the product and the
[version record](../VERSION.md) identifies the selected component versions.
The same guides can also be built as a [documentation site](documentation-site.md).

## Choose a workflow

| Goal | Guide |
| --- | --- |
| Get started | [Getting started](getting-started.md) |
| Use the storage library | [Storage documentation](../ovstorage/docs/public/README.md) |
| Use Python | [Python guide](../ovstorage/docs/public/library-python/README.md) and [tutorial](../ovstorage/ovstorage-core/examples/python/README.md) |
| Use C or C++ | [C/C++ guide](../ovstorage/docs/public/library-cpp/README.md) and [tutorial](../ovstorage/ovstorage-c-source/examples/tutorial/README.md) |
| Use Rust | [Rust guide](../ovstorage/docs/public/library-rust/README.md) |
| Configure storage backends | [Stack configuration](../ovstorage/docs/public/configuration.md) and [backend guides](../ovstorage/docs/public/plugin-storage/README.md) |
| Use storage through MCP | [MCP and result envelope](../ovstorage/docs/public/agent/README.md) |
| Develop a storage plugin | [Plugin contract and ABI](../ovstorage/docs/public/plugin-development/README.md) |
| Use the USD resolver | [Resolver overview](../ovstorage-usd-resolver/README.md) and [documentation index](../ovstorage-usd-resolver/docs/README.md) |
| Understand how USD content is resolved and materialized | [How USD content flows](usd-data-flow.md) |
| Configure USD resolution | [Resolver configuration](../ovstorage-usd-resolver/docs/configuration.md) |
| Embed the resolver in an OpenUSD host | [Runnable embedding example](../ovstorage-usd-resolver/examples/embed_resolver/) |
| Diagnose USD resolution | [Resolver CLI reference](../ovstorage-usd-resolver/docs/cli-reference.md) |
| Build both components together | [Combined source build](building.md) |
| Check binary compatibility | [Storage platforms](../ovstorage/docs/public/platform-support.md) and [resolver compatibility](../ovstorage-usd-resolver/docs/compatibility-matrix.md) |
| Work with an agent | [Agent entry](../AGENTS.md) and [skills catalog](../skills/README.md) |

## Distribution

The ovstorage library publishes wheels and native archives. The resolver is
built from source for the consuming host; no resolver wheels are published for
this release. An [optional Python package](../ovstorage-usd-resolver/docs/python-wheels.md)
can be built locally.

## Repository

- [Component layout and path migration](../MIGRATION.md).
- [Exact component versions](../VERSION.md) and [source provenance](../SOURCE_PROVENANCE.json).
- [Licensing](../LICENSE), [notices](../THIRD_PARTY_NOTICES.md), and [security reporting](../SECURITY.md).

Storage configuration supplies providers and credentials; resolver configuration
controls how an OpenUSD host uses them. Run component-specific commands from
that component's directory unless a guide explicitly starts at the public root.
