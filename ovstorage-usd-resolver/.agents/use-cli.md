# Use CLI

Start with [`docs/cli-reference.md`](../docs/cli-reference.md).

The CLI is for diagnostics and inspection. It should not become the resolver
runtime API.

Current commands:

- `doctor`: validate CLI setup, supported remote schemes, ovstorage
  bridge build availability, `ovstorage_stack_config` bridge
  construction from `--stack-config <ovstorage.toml>`, and an optional
  provider-backed URI stat probe. `doctor --json` returns a stable
  schema and categorized `errors[]`.
- `resolve`: show identifier normalization and resolver selection.
- `materialize`: fetch one provider-backed asset to a local output path when
  the binary is built with an ovstorage SDK/dist. Accepts
  `--stack-config <ovstorage.toml>`.
- `trace`: run the resolver against a stage URI and dump every trace-sink
  event as JSON. When the CLI is built with the OpenUSD plugin (SDK-on +
  plugin), `trace` drives a full `UsdStage::Open(uri, context)` and surfaces
  `create_identifier.begin/end`, `resolve.begin/end`, and paired
  `open_asset.begin/end` events for every layer OpenUSD composes. Without
  the OpenUSD plugin (no-SDK CI, resolver-only SDK builds) `trace` falls
  back to a single `runtime->materialize` and reports only the paired
  `open_asset.begin/end` events. Accepts `--stack-config
  <ovstorage.toml>`.
- `put`: upload a local file to a remote URL claimed by this resolver
  through the same runtime and storage bridge that `materialize` uses
  in reverse. Flags: `--overwrite`, `--if-none-match`, `--stack-config
  <ovstorage.toml>`. Requires the ovstorage bridge build.
- `benchmark`: repeatedly exercise the configured URI and report per-run wall
  time plus percentile stats. OpenUSD-enabled builds open the complete stage;
  bridge-only builds materialize the addressed object. Flags
  include `--runs N`, `--warmup N`, `--base`, `--stack-config
  <ovstorage.toml>`, and `--json`. Requires the ovstorage bridge
  build.

Agent-facing CLI work should keep `--json` output stable and documented.
For the `0.1.x` line, `schema_version: "1"`, required envelope fields,
error codes/categories, and exit-code meanings are compatibility commitments;
fields may be added compatibly. The exact contract and classification
precedence are in
[`docs/cli-reference.md`](../docs/cli-reference.md#stable-error-contract).

Treat identifiers as potentially credential-bearing. Passive commands and
errors redact URI userinfo, query/fragment values, and SDF format arguments;
do not bypass that policy or add a raw-output default. `resolve` intentionally
returns exact functional identifiers, so do not place its output in logs or
support bundles without applying the public diagnostic-redaction helper.

## One-command usable-bridge check

Fresh agents should run this before touching a real address, so they can
distinguish a resolver setup problem from a route/plugin problem:

```bash
export OVSTORAGE_PLUGIN_DIR=/path/to/ovstorage/plugins
./build-ovstorage/ovstorage-usd-resolver doctor \
  --stack-config /path/to/ovstorage.toml \
  --json
```

`--stack-config <ovstorage.toml>` is the CLI's bridge-config knob. It
maps to `OvStorageBridgeOptions::configPath`; ovstorage loads the
stack from the referenced TOML file and owns provider composition
(file mounts, HTTP roots, S3 buckets, credentials profiles, etc.).
`file` is built in. For every other layer kind, the CLI loads generic
`libovstorage_plugin_*.so` libraries from the explicitly trusted
`OVSTORAGE_PLUGIN_DIR` and keeps them alive with the built stack. If
`--stack-config` is omitted, provider-backed commands use ovstorage's
documented default-path search (`./ovstorage.toml`, then the XDG user config
path). See the ovstorage documentation for the stack-config schema.

The output includes:

- `checks[].name = ovstorage_bridge_build` — whether the binary was built
  with the ovstorage bridge at all.
- `checks[].name = ovstorage_stack_config` — the result of constructing
  the bridge from `--stack-config`. `ok` if it initialized, `error` if
  the file failed to load, a plugin failed to load, or a route was
  unwireable.
- `errors[].category` on any failure. See the error taxonomy below.

## Error categories

Every entry in `errors[]` now carries a `category` alongside `code` and
`message`, so callers can route failures without parsing message text:

| category        | when it fires                                                         |
| --------------- | --------------------------------------------------------------------- |
| `resolver`      | Invalid CLI input or resolver-side option problems.                   |
| `configuration` | Unclaimed scheme, unavailable bridge, or unusable stack config.       |
| `plugin`        | `Plugin::load` / `Registry::add_plugin` failed (ABI, missing `.so`).  |
| `route`         | No factory or no route for the identifier's scheme.                   |
| `backend`       | Reached the backend and it returned an error (404, permission, ...). |

Text output prints `error[<category>/<code>]: <message>`.

Current resolve smoke:

```bash
./build/ovstorage-usd-resolver doctor --json

./build/ovstorage-usd-resolver resolve \
  ./textures/a.png \
  --base https://example.com/scene/root.usd \
  --json
```

When the binary is built with the ovstorage bridge, materialize one
provider-backed asset for inspection. `--stack-config` gives ovstorage
the provider composition:

```bash
./build-ovstorage/ovstorage-usd-resolver materialize \
  https://example.com/scene/root.usda \
  --stack-config /path/to/ovstorage.toml \
  --out /tmp/root.usda \
  --json
```

To inspect what the resolver does under the hood without writing an output
file, use `trace`. It accepts the same `--stack-config` flag as
`materialize`. When the CLI is built with the OpenUSD plugin, `trace`
drives a full `UsdStage::Open(uri, context)` and prints one record per
trace-sink event (`create_identifier.begin/end`, `resolve.begin/end`,
`open_asset.begin/end` for every composed layer):

```bash
./build-ovstorage/ovstorage-usd-resolver trace \
  s3://bucket/path/root.usd \
  --stack-config /path/to/ovstorage.toml \
  --json
```

Use `doctor --uri ... --stack-config ... --json` before deeper OpenUSD
debugging when you need to separate route/setup failures from
composition failures. Use `--overwrite` on `materialize` only when
replacing an existing output file is intentional.
