# CLI Reference

The concrete bridge preserves error remediation through the existing CLI
taxonomy. Object `NotFound` requires ovstorage's explicit fine-grained identity;
missing configuration, no route, and rejected plugins map to `unsupported`.
Permission/auth failures map to `permission_denied`, transient and resource
exhaustion failures to `timeout`, and incompatible types to `abi_mismatch`.
Write precondition failures map to `conflict`. Partial completion, cancellation,
unknown statuses, and ambiguous coarse `NotFound` map to `backend_error` and
must not be interpreted as missing objects or blindly retried. The provider
message remains available subject to diagnostic credential redaction. These
are intentional coarsenings into the version-1 CLI taxonomy, not new error codes.

> **Bridge configuration:** the CLI has one user-facing bridge-config
> knob — `--stack-config <ovstorage.toml>` — which maps to
> `OvStorageBridgeOptions::configPath`. Library callers may instead
> hand the resolver a pre-built ovstorage `LayerHandle` via
> `OvStorageBridgeOptions::layerHandle`; the CLI cannot receive a
> live handle from a shell process, so the config-file path is the
> shell-facing seam. `OVSTORAGE_PLUGIN_DIR` supplies an explicitly
> trusted provider-plugin directory when the graph uses non-file kinds.
> Bridge composition is ovstorage's job.

The resolver ships a small standalone CLI for diagnostics and asset
inspection. It gives a fast way to separate resolver setup problems from
ovstorage provider problems and OpenUSD composition problems.

The CLI is a support tool, not the public runtime API. Runtime applications
call OpenUSD and ovstorage directly.

## Sensitive identifier output

Resolver-owned passive diagnostic surfaces redact URI credentials by default.
`doctor`, `materialize`, `trace`, `put`, and `benchmark`, plus text/JSON errors,
remove URI userinfo and replace query values, fragment values, and SDF format
arguments with `<redacted>`. Package identifiers retain their non-sensitive
outer and inner structure. Provider and OpenUSD error messages receive the
same URI-shaped-token redaction before the CLI stores or formats them. There
is no raw-diagnostic opt-in.

Redaction affects display only. Provider operations still receive the exact
identifier. `materialize` reports redacted remote fields and the exact local
output and lease paths.

Successful `resolve` output is the deliberate exception: computing and
returning the exact identifier is that command's function, so its successful
text and JSON fields are not redacted. Treat successful `resolve` output as
sensitive when the input or base contains credentials. Invalid-input errors,
including rejected extra arguments, use the same redacting diagnostic formatter
as the other commands. With JSON mode selected, parser failures return the
schema-1 error envelope on stdout, exit `2`, and `invalid_input` / `resolver`;
text-mode errors are redacted on stderr. The library likewise preserves exact
operation results; `ResolverTraceEvent` is the safe diagnostic surface for host
logging.

## Command

The binary name is:

```text
ovstorage-usd-resolver
```

No short alias ships in the first release.

## Commands

### `doctor`

Validates local setup.

Checks emitted (each surfaces in the `checks[]` array with a status of
`ok`, `warning`, `error`, or `skipped`):

- `cli_binary` — the CLI binary is runnable.
- `supported_remote_schemes` — the build-advertised URI scheme list
  (`OVS_USD_RESOLVER_URI_SCHEMES`; shipping default `s3;http;https;hf`).
- `openusd_plugin_discovery` — when built with the OpenUSD plugin,
  reports the URI schemes OpenUSD sees the resolver claim through
  `plugInfo.json`. Reports `skipped` in builds without the OpenUSD
  plugin.
- `ovstorage_bridge_build` — whether this binary was built with the
  ovstorage bridge (`OVS_OVSTORAGE_SDK_ROOT`). Emitted as `warning`
  when it was not, since provider-backed probes and `materialize`
  need the bridge.
- `ovstorage_stack_config` — emitted only when `--stack-config <path>`
  is passed. Reports whether the bridge built from that stack
  configuration reports usable capabilities.

When `--uri <identifier>` is passed, `doctor` runs a `doctor_probe`
operation against that URI (stat probe through the constructed bridge)
and reports it in `operations[]`.

Useful forms:

```text
ovstorage-usd-resolver doctor
ovstorage-usd-resolver doctor --json
ovstorage-usd-resolver doctor --stack-config /path/to/ovstorage.toml --json
ovstorage-usd-resolver doctor --uri https://example.com/scene/root.usd \
    --stack-config /path/to/ovstorage.toml --json
```

`doctor` includes a bridge-construction probe. When `--stack-config` is
passed, it constructs the ovstorage bridge from the supplied stack
configuration and reports plugin-load, ABI, and route-wiring problems
up front. When `--uri` is also passed, it stat-probes the URI through
the constructed bridge.

When `--stack-config` is omitted, provider-backed commands select
ovstorage's default-path search (`./ovstorage.toml`, then the XDG user config
path). StackConfig itself never discovers plugins: `OVSTORAGE_PLUGIN_DIR`
names the trusted directory whose generic `libovstorage_plugin_*.so` files
the bridge registers and pins. A file-only graph needs no plugin directory.

`--stack-config <ovstorage.toml>` is the CLI's bridge-config knob and
maps to `OvStorageBridgeOptions::configPath`. Under it, ovstorage owns
provider composition: native `s3://`, HTTP(S), `hf://`, and file mounts are
all described in the ovstorage stack configuration. Native `s3://`
read/composition is release-qualified against AWS S3, while native `hf://` is
release-tested against a pinned public repository revision via their
live-conformance smokes. Non-AWS S3-compatible endpoint profiles are inherited
ovstorage capabilities, not resolver-qualified platforms in 0.1.

### `resolve`

Shows how an identifier normalizes and resolves.

Useful forms:

```text
ovstorage-usd-resolver resolve https://example.com/scene/root.usd
ovstorage-usd-resolver resolve ./textures/a.png --base https://example.com/scene/root.usd
ovstorage-usd-resolver resolve 'https://example.com/pkg.usdz[scene.usd]' --json
```

The `operations[0]` record contains:

- input identifier;
- optional base identifier;
- normalized identifier;
- package outer asset;
- package inner path;
- SDF format arguments;
- URI scheme; and
- owner (`ovstorage` for a claimed remote URI, otherwise `default`).

### `materialize`

Fetches a remote USD asset or package to a local path for inspection.

Useful forms:

```text
ovstorage-usd-resolver materialize https://example.com/scene/root.usd \
    --stack-config /path/to/ovstorage.toml --out /tmp/root.usd
ovstorage-usd-resolver materialize https://example.com/pkg.usdz \
    --stack-config /path/to/ovstorage.toml --out /tmp/pkg.usdz
```

`materialize` fetches exactly one addressed provider-backed asset to the
requested output path. It does not recursively copy stage dependencies; use
`trace` to inspect composition through OpenUSD.

### `trace`

Opens a root USD asset and reports resolver activity.

Useful forms:

```text
ovstorage-usd-resolver trace https://example.com/scene/root.usd \
    --stack-config /path/to/ovstorage.toml
ovstorage-usd-resolver trace s3://bucket/scene/root.usd \
    --stack-config /path/to/ovstorage.toml --json
```

Each trace event reports:

- a monotonic event index;
- operation name;
- identifier;
- resolver storage status code; and
- an optional diagnostic message.

Identifiers and URI-shaped tokens in status/detail messages use the sensitive
identifier policy above before they reach the trace callback or CLI record.
Trace output cannot be replayed as a provider request.

The enclosing operation also reports the input, optional base, normalized and
storage identifiers, and URI scheme. In an OpenUSD-enabled build the events
cover each layer composed by `UsdStage::Open`; otherwise they cover one direct
materialization.

### `put`

Uploads a local file to a remote URL through the same runtime and storage
bridge that `materialize` uses in reverse. Requires the ovstorage bridge
build.

Useful forms:

```text
ovstorage-usd-resolver put ./scene.usda s3://bucket/scene/scene.usda \
    --stack-config /path/to/ovstorage.toml --overwrite --json

ovstorage-usd-resolver put ./scene.usda s3://bucket/scene/scene.usda \
    --stack-config /path/to/ovstorage.toml --if-none-match  # strict create-only
```

Positional arguments: `<local-path>` (source file) and
`<remote-identifier>` (URL in a scheme claimed by this resolver — one of the
schemes advertised by `OVS_USD_RESOLVER_URI_SCHEMES`; shipping default
`s3;http;https;hf`).

`put` replaces one whole provider object. SDF format arguments are removed
before route selection and upload because they do not name a distinct backing
object. Package-member identifiers are rejected; replace a USDZ package only
by naming its outer identifier directly.

Writability is a property of the configured ovstorage route, not a hardcoded
resolver scheme list. In the default provider set, native `s3://` routes can
advertise writes; the shipped HTTP and Hugging Face providers are read-only.
An `https://` or `hf://` `put` against a route with no configured
write-capable backend fails with
`category: configuration, code: not_writable` and exit `3`. Sites
that need HTTPS writes can build a service-specific ovstorage layer
and insert it into the stack.

Flags:

- `--if-none-match` — strict create-only PUT. Fails with
  `category: backend, code: conflict` when the object already exists.
  Requires the backend to advertise `supports_no_overwrite_write`;
  otherwise fails with `code: capability_unavailable, category: configuration`.
- `--overwrite` — explicit LWW (last-writer-wins). Equivalent to
  omitting all conditional flags; documented so scripted callers can
  express intent explicitly.
- `--stack-config <ovstorage.toml>` — shared bridge configuration
  (matches `doctor` / `materialize` / `trace` / `benchmark`).

Exit codes follow the standard CLI taxonomy:

- `0` — write succeeded.
- `1` — backend attempted the write and refused (conflict, permission
  denied, not-found on parent, quota, network).
- `2` — invalid CLI input (missing file, conflicting flags).
- `3` — environment error (no ovstorage bridge in build, or configured
  route lacks write capability).
- `4` — URL scheme not claimed by this resolver.

### `benchmark`

Repeatedly exercises a URI through the configured stack and reports per-run
wall time plus aggregate percentile statistics. In an OpenUSD-enabled build it
uses `UsdStage::Open` and `TraverseAll`; a resolver-only ovstorage build
measures direct materialization and reports a prim count of zero. The command
is intended for local cold/warm comparisons, bridge-config comparisons, and
resolver regression checks.

Useful forms:

```text
ovstorage-usd-resolver benchmark https://host/scene.usda \
    --stack-config /path/to/ovstorage.toml --runs 10 --warmup 1 --json

ovstorage-usd-resolver benchmark s3://bucket/scene.usda \
    --stack-config /path/to/ovstorage.toml --runs 20
```

Positional argument: `<identifier>` (URI claimed by this resolver — a
scheme from the build-advertised list `OVS_USD_RESOLVER_URI_SCHEMES`,
whose shipping default is `s3;http;https;hf`; or a URI routable via
`--base`).

Flags:

- `--runs N` — number of measured opens per process. Default 10.
  Must be `>= 1`.
- `--warmup N` — number of untimed opens before the measured runs.
  Default 0. Untimed opens exercise plugin registration, ovstorage
  Stack build, and TCP/TLS setup so the first *measured* run is not
  the very first Open.
- `--base` — identifier joined against the positional identifier
  before opening.
- `--stack-config <ovstorage.toml>` — shared bridge configuration
  (matches `doctor` / `materialize` / `trace` / `put`).
- `--json` — JSON envelope (default is human-readable text).

JSON envelope: `operations[]` contains a single record with:

```jsonc
{
  "operation": "benchmark",
  "input": "<identifier as given>",
  "normalized": "<after --base joining>",
  "storage_identifier": "<what ovstorage saw>",
  "runs_requested": 10,
  "warmup": 0,
  "runs": [
    {"run": 0, "cold": true,  "wall_ms": 935.2, "prims": 3335, "trace_events": 2626, "ok": true},
    {"run": 1, "cold": false, "wall_ms": 366.1, "prims": 3335, "trace_events": 2626, "ok": true}
    // ...
  ],
  "stats": {
    "n": 10, "min_ms": 366.1, "p50_ms": 372.4, "p95_ms": 935.2,
    "max_ms": 935.2, "mean_ms": 429.7, "stdev_ms": 168.9
  }
}
```

`run 0` is flagged `"cold": true` only when `--warmup 0` was
requested. If `--warmup N > 0` was passed, the process has already
run N untimed opens before the first measured one, so run 0 has
warm SdfLayer / HTTP-pool state and `"cold"` is `false` for every
measured run. `stats` aggregates only runs where `ok == true`;
if every run failed, `stats.n` is 0 and per-run `wall_ms` values
remain in the array for inspection.

Exit codes follow the standard CLI taxonomy:

- `0` — command produced a report (individual runs may have failed;
  callers should inspect `runs[].ok` and `stats.n`).
- `2` — invalid CLI input (missing URL, `--runs 0`, unknown flag).
- `3` — environment error (no ovstorage bridge in this build, or
  runtime construction failed).
- `4` — identifier's URI scheme is not claimed by this resolver build.

## Stable Error Contract

Every command supports:

- human-readable text output;
- `--json` output for agents and CI;
- non-zero exit codes for actionable failures;
- stable error categories.

For the `0.1.x` line, JSON `schema_version: "1"`, the required envelope
fields, error `code` / `category` meanings, and exit-code meanings are stable.
Compatible releases may add fields. Callers should ignore fields they do not
recognize. This is the agent-facing exception to the broader preview posture
defined in the [API stability policy](api-stability.md).

For `doctor`, `materialize`, `trace`, `put`, and `benchmark` parsing errors,
`--json` selects a JSON error envelope on stdout regardless of its position after
the command name, including after an invalid argument. These errors exit `2` with `invalid_input` / `resolver` and no text
error on stderr. A token consumed as an option value (for example, the base in
`--base --json`) remains a value; use a separate `--json` flag to select JSON.

Exit codes have one meaning across commands:

- `0` — success or, for `doctor --uri` with an unclaimed scheme, an explicit
  skipped probe because this resolver is not the owner;
- `1` — an operation reached the resolver, OpenUSD, or ovstorage and failed;
- `2` — invalid command line or malformed input;
- `3` — the requested operation is in scope but the build or configured
  environment cannot provide it;
- `4` — the command or URI scheme is outside this build's claimed surface.

The following user-actionable code/category pairs are pinned:

- `scheme_not_owned` / `configuration` — `materialize`, `trace`, `put`, or
  `benchmark` received a URI scheme outside
  `OVS_USD_RESOLVER_URI_SCHEMES`; local `put` destinations use the same pair
  and direct the caller to OpenUSD's default resolver. These failures exit
  `4`, even in a no-SDK build, because ownership is checked before optional
  bridge availability.
- `ovstorage_unavailable` / `configuration` — the identifier is claimed, but
  the binary was built without the ovstorage bridge. This exits `3`, including
  `put` in a no-SDK build.
- `unsupported` / `route` — ovstorage accepted the configured stack but its
  authoritative router found no route for an otherwise claimed identifier.
  A `doctor --uri` probe exits `1` for this operation failure.

Other emitted codes are operation-specific (`invalid_input`,
`materialize_failed`, `openusd_composition_failed`, `not_writable`, and
`capability_unavailable`) or come directly from the resolver storage status
vocabulary (`unavailable`, `not_found`, `permission_denied`, `unsupported`,
`timeout`, `invalid_argument`, `backend_error`, `abi_mismatch`, and
`conflict`). The category remains the stable routing signal when the same
storage code can arise at different layers.

## Error Category Field

Every entry in `errors[]` carries a `category` alongside `code` and
`message`. The category groups error kinds so callers can route failures
without parsing message text:

| category        | when it fires                                                        |
| --------------- | -------------------------------------------------------------------- |
| `resolver`      | Invalid CLI input or resolver-side option problems.                  |
| `configuration` | Unclaimed scheme, unavailable bridge, or unusable stack configuration. |
| `plugin`        | `Plugin::load` / `Registry::add_plugin` failed (ABI, missing `.so`). |
| `route`         | No factory or no route for the identifier's scheme.                  |
| `backend`       | Reached the backend and it returned an error (404, permission, ...). |

Text output prints `error[<category>/<code>]: <message>`.

## JSON Shape

Every JSON result has these top-level fields: `schema_version`, `command`,
`status`, `checks`, `operations`, and `errors`. Command-specific data lives in
`checks[]` or `operations[]`; failures carry `code`, `category`, and `message`
in `errors[]`.

A successful `resolve` result has this shape:

```json
{
  "schema_version": "1",
  "command": "resolve",
  "status": "ok",
  "checks": [],
  "operations": [
    {
      "operation": "resolve",
      "input": "https://example.com/scene/root.usd",
      "base": null,
      "normalized": "https://example.com/scene/root.usd",
      "resolved": "https://example.com/scene/root.usd",
      "scheme": "https",
      "owner": "ovstorage",
      "package_outer": null,
      "package_inner": null,
      "sdf_format_args": null
    }
  ],
  "errors": []
}
```

## Build-Dependent Behavior

The CLI ships `doctor`, `resolve`, `materialize`, `trace`,
`put`, and `benchmark`.
`doctor` reports CLI readiness, supported remote schemes,
ovstorage bridge build availability, actual bridge construction from
StackConfig, explicit config/plugin path checks, and an optional URI stat probe
when the binary is built with `OVS_OVSTORAGE_SDK_ROOT`. Builds without the ovstorage bridge still return a
useful `doctor --json` setup report, and URI probes report
`ovstorage_unavailable` clearly. Every failure in `errors[]` carries a
`category` field so callers can route without parsing message text.

`trace` runs the resolver against a stage URI and dumps every
trace-sink event as JSON. When the CLI is built with the OpenUSD
plugin (SDK-on + `OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN`), `trace`
drives a full `UsdStage::Open(uri, context)` and surfaces
`create_identifier.begin/end`, `resolve.begin/end`, and paired
`open_asset.begin/end` events for every layer OpenUSD composes.
Without the OpenUSD plugin `trace` falls back to a single
`runtime->materialize` and reports only the paired
`open_asset.begin/end` events. Accepts `--stack-config <ovstorage.toml>` for
bridge construction.

`materialize`, `put`, `trace`, and `benchmark` require a binary built with
`OVS_OVSTORAGE_SDK_ROOT`; otherwise they report `ovstorage_unavailable`.
`doctor` includes an OpenUSD plugin discovery check in every build and reports
it as `skipped` when OpenUSD is not linked.

Exit code policy:

- `0`: success;
- `1`: resolver, OpenUSD, or ovstorage operation failed;
- `2`: invalid command line or invalid input;
- `3`: environment/configuration problem;
- `4`: command or URI scheme outside this build's claimed surface.

## Verification

`tests/no_sdk/cli_error_taxonomy.cmake` is the machine-verified copy of the
no-SDK code/category/exit contract and runs under both default-scheme and
non-default-scheme CI legs. The SDK-on `cli_stack_config_doctor` smoke pins the
claimed-but-unrouted `unsupported` / `route` shape and the successful `trace`
JSON envelope. CLI tests use local fixtures and do not require GPUs, private
endpoints, or deployed services.
