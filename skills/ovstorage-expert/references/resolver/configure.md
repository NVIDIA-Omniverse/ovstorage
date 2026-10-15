Up: [ovstorage-expert](../../SKILL.md)

# Configure the resolver

The resolver has no configuration file of its own. Behavior comes from three places. Contract: [configuration.md](../../../../ovstorage-usd-resolver/docs/configuration.md).

## 1. Build time: which schemes it claims

`OVS_USD_RESOLVER_URI_SCHEMES` (default `s3;http;https;hf`) is the single source of truth for both `plugInfo.json` and the compiled claim check. `file` is rejected. To claim another scheme, for example `-DOVS_USD_RESOLVER_URI_SCHEMES="s3;http;https;hf;az"`, rebuild and make sure the ovstorage configuration routes that scheme. A stage URI must be both advertised by the build and routed by the Stack. One resolver should own each scheme per process; don't advertise `http`/`https` alongside another resolver that claims them.

## 2. Registration: how OpenUSD finds the plugin

- Source builds: set `PXR_PLUGINPATH_NAME` to the build tree's `resources/` directory (or the installed plugin directory) before OpenUSD starts.
- Optional locally built Python package (no published resolver wheel): call `ovstorage_usd_resolver.register_plugin(usd_sdk_root=…)` before any resolver use ([embed.md](embed.md)).
- `plugInfo.json` is generated from `resources/plugInfo.json.in`; its library, resource, and root paths come from the `OVS_USD_RESOLVER_*_PATH` and `OVS_USD_RESOLVER_PLUGIN_ROOT` cache variables.

## 3. Runtime: storage and options

- **Storage:** an `ovstorage.toml` Stack ([storage/configure.md](../storage/configure.md)) plus a trusted provider directory (`OVSTORAGE_PLUGIN_DIR`, or the `pluginDirectory` option). Embedding hosts may instead pass a pre-built `LayerHandle`.
- **`ResolverOptions`** (`include/ovstorage_usd_resolver/configuration.hpp`): `remoteUriSchemes` (may only narrow the build list), `isolationKey`, `storageBridgeFactory`, `traceSink` (identifiers are redacted first), `resolveVerifiesExistence` with its TTL and size settings.

## CLI

`ovstorage-usd-resolver` (built at the build-tree root) has `doctor`, `resolve`, `materialize`, `trace`, `put`, and `benchmark`. Every command takes `--json` (`schema_version` `"1"`) and uses stable error categories and exit codes. Reference: [cli-reference.md](../../../../ovstorage-usd-resolver/docs/cli-reference.md).

```sh
export OVSTORAGE_PLUGIN_DIR="$PWD/../ovstorage/plugins"
./build-openusd-ovstorage/ovstorage-usd-resolver doctor --stack-config ovstorage.toml --json
./build-openusd-ovstorage/ovstorage-usd-resolver materialize <uri> --out /tmp/asset --stack-config ovstorage.toml
```

Read-only Hugging Face and other worked configuration examples are in the configuration contract.
