# Test Strategy

The resolver is infrastructure for OpenUSD remote composition. Its required
test suite proves correctness without GPUs, private endpoints, or deployed
services.

## Principles

- Required CI tests must be deterministic.
- Cloud behavior should be tested with fakes or local compatible services
  before optional live smoke tests.
- Test names should describe user-visible behavior, not implementation trivia.
- Failure cases are as important as success cases because resolver failures
  otherwise look like generic USD composition errors.
- Optional live smokes should never block ordinary development unless a release
  manager opts in.

## Unit Tests

Identifier tests should cover:

- local absolute and relative paths;
- `file://` URLs;
- `http://` and `https://` URLs;
- `s3://` URLs;
- `hf://` URLs;
- a non-default configured scheme to prove scheme-agnostic handling;
- relative reference joins from remote assets;
- bare asset paths staying with OpenUSD's default resolver (the ovstorage
  resolver does not claim them);
- SDF format arguments;
- package identifiers;
- nested package identifiers;
- MDL module names, remote MDL paths, MDL-in-package paths, and relative MDL
  references from remote USD assets;
- invalid package syntax;
- extension extraction from package paths;
- canonicalization of known S3 HTTPS host forms.

Bridge tests should cover:

- capability reporting;
- read success;
- whole-object and range-read requests;
- stat success;
- materialization success;
- missing object;
- auth failure;
- unsupported operation;
- timeout or provider failure;
- ABI/version mismatch;
- ovstorage unavailable.

Runtime tests cover configured bridge-factory construction,
lease-based materialization (the resolver holds no byte cache; every `materialize`
call routes through the bridge and returns a `MaterializedAsset` whose
`LocalLeaseHandle` keeps the local file alive), trace emission, and clear
failure when the default runtime has no ovstorage bridge.
CLI parser tests run in every build and verify identical JSON error envelopes
with `--json` before and after invalid arguments in `doctor`, `materialize`,
`trace`, `put`, and `benchmark`.
They cover invalid numeric values, extra arguments, missing arguments/values,
conflicting flags, text-mode errors, and literal `--json` option values.
CLI tests also cover `doctor` setup JSON in all builds, a real ovstorage-backed
loopback HTTP URI probe when SDK artifacts are configured, and an explicit
unavailable diagnostic when a URI probe requires ovstorage bridge support.
They also cover `materialize` against that HTTP route and its explicit
unavailable diagnostic when no bridge is built. A structural no-SDK test
parses each JSON envelope and pins schema version, exact exit/code/category tuples, and one
identifying message fragment for unclaimed schemes, local writes, and missing
bridge support in both URI-scheme matrix legs. The SDK-on HTTP doctor smoke
pins the claimed-but-unrouted operation as `unsupported` / `route` with exit
`1`, plus successful materialize and trace envelopes.

`resolve` parser-error tests run with and without the SDKs and check redacted
JSON and text errors for extra credential-bearing URI arguments, signed URL
fields, package paths, and SDF format arguments. They also cover missing input
and option values, and preserve exact functional identifiers on success.

Configuration tests should cover:

- default scheme set (the build-advertised list, shipping default
  `s3;http;https;hf`);
- case-insensitive scheme lookup;
- rejection of `file` as a remote scheme;
- rejection of a runtime scheme not in the build-advertised list (widening
  is not allowed; narrowing is);
- required storage bridge factory validation;
- default unavailable bridge factory behavior;
- host-provided bridge factory behavior;
- isolation key handling in `ResolverOptions`;
- trace sink defaults.

## Resolver Tests

Resolver tests should cover:

- plugin metadata shape before an OpenUSD SDK is required;
- plugin discovery through `plugInfo.json`;
- default local-file behavior;
- remote identifier resolution;
- context binding and unbinding;
- `OpenAsset`;
- `Read`;
- `GetBuffer`;
- `GetFileUnsafe` through materialization;
- modification timestamp and asset-info behavior;
- write behavior for routes whose configured ovstorage backend advertises
  write support, and clear failure for routes that do not;
- SDF-decorated writes use one normalized provider target for capability
  lookup, Update materialization, PUT, trace events, and existence-cache
  invalidation;
- package-inner write identifiers are rejected before materialization or PUT
  and cannot create a bracket-bearing provider key or overwrite the outer USDZ;
- direct `OpenAssetForWrite` calls reject read-only routes without relying on
  the caller to invoke `CanWriteAssetToPath` first;
- `Update` range writes preserve untouched prefixes, gaps, and tails across
  disjoint and overlapping writes;
- `Update` creates a missing object with a create-only close, and refuses a
  concurrent creator with `Conflict`;
- `Replace` remains whole-object replacement, while existing-target `Update`
  retains conditional-write conflict detection;
- producer-level OpenUSD coverage proves that existing USDC
  `SdfLayer::Save` selects conditional `Update`, preserves an opaque region
  outside its writes, and fails closed on a competing writer, while
  `UsdStage::Export` selects whole-object `Replace` for missing and existing
  destinations;
- parity between direct ovstorage routing and the resolver bridge for canonical
  URL spellings (including percent-encoded dot segments), with no resolver-side
  operational preflight;
- per-address write/ownership queries through ovstorage's authoritative route
  lookup, while root discovery remains aggregate and advisory.

The OpenUSD SDK smoke registers the URI resolver and proves
that `OpenAsset` fails closed without a bound resolver context and can read
bytes through a context-bound fake bridge-backed runtime. A separate optional
ovstorage SDK smoke exercises the ovstorage bridge against the built-in
`file` backend: compose a file-only bridge; `stat`/`read`/`materialize`
through the real ovstorage `file` provider; accept `configPath` as the
stack-configuration seam (`OvStorageBridgeOptions::configPath`, exposed on
the CLI as `--stack-config <ovstorage.toml>`); and tolerate repeated bridge
creation/destruction on the calling thread. The deterministic
`openusd_ovstorage_bridge_http` smoke composes sublayer, reference, and payload
arcs across two HTTP authorities. It requires exact prim and remote-layer sets,
a successful resolver open for every layer, no failed trace events, and no
composition errors; a one-root negative control proves that a non-null partial
stage does not pass. The SDK-backed `host_s3_routed_stack` smoke constructs the
native-S3-plus-HTTPS graph without provider IO, proves that the core, HTTP, and
S3 plugins remain pinned after the registry/build scope ends, and verifies
authoritative route ownership through the surviving layer handle. Every
deterministic stage-opening smoke applies the same exact-signature contract,
including default-context and USDZ/package paths.

The host-owned stack smokes compile at C++17 against `host.hpp` and
`openusd_host.hpp`. `host_api_stack` and `host_api_openusd` are built only
on Linux, in a build with the ovstorage C sources; `host_api_openusd` also
needs the provider plugin directory and `http` among the build's schemes.
The `host_api_registration_*` scenarios run in every OpenUSD plugin build,
including Windows. `host_api_stack` adopts a same-copy stack and a stack
exported by a second, separately compiled copy of the ovstorage C runtime in a
hidden-visibility test library. A counting layer in the host's stack proves the
resolver's traffic reaches it, and each runtime outlives the host's handle and
releases the stack exactly once. It also requires that a host-supplied bridge
factory is ignored and that null, undersized-vtable and ABI-mismatched exports
get ovstorage's documented disposal: an undersized vtable, like options that
fail validation, is `InvalidArgument` and leaves the export untouched, while
an ABI mismatch drops it once. `host_api_openusd` registers the plugin with
the dispatch check deferred, adopts a two-origin HTTP stack from the second
copy, captures the bound context on one thread and composes the exact stage
signature on a worker. The `host_api_registration_*` scenarios each run in
their own process. `host_api_registration_diagnostics` requires `Unavailable`,
naming the schemes, for a registration after the first `ArGetResolver()`,
and `Conflict` when another resolver claims one of the schemes. It also
requires `InvalidArgument`, never success, for a directory that does not hold
the registered plugin: an empty one, one holding a second copy that OpenUSD
ignores, and a path that is not valid UTF-8. `host_api_registration_competitor`
registers a competing resolver for one of the schemes between registration
and `verifyResolverDispatch()` and requires `Conflict`, because OpenUSD still
lists that scheme as dispatched. `host_api_registration_unloadable` registers
the resolver's plugInfo with a missing library and requires `Unavailable`
from the dispatch check rather than a failure on the first resolve.
`host_api_registration_impostor` registers a directory whose plugin has the
resolver's name but declares no types, while another plugin declares the
resolver type, and requires `InvalidArgument`.

When `OVS_USD_RESOLVER_BUILD_EXAMPLES=ON`, `embed_example` launches the public
consumer binary as a subprocess against a loopback HTTP stage. It requires a
successful process exit, the logical remote root identifier, the expected prim
count, a nonzero resolver-open signal, and an observed request at the
ovstorage HTTP fixture.
Negative default-context controls use an identifier that was not populated in
OpenUSD's layer registry, so cached layer state cannot produce a false pass.
The live HTTP/S3/Hugging Face, default-context, write-reopen, and two-runtime
smokes load provider plugins from an explicitly trusted directory, pin them
for each bridge lifetime, and apply scene-signature floors. The Hugging Face
smoke fixes the public repository and immutable revision in source, requires
known composed layers, and checks that resolver-visible identifiers stay
`hf://`. The credentialed live-write smoke requires an explicitly selected
disposable S3 object, proves that the route advertises write support, performs
the provider PUT, and reopens the authored stage through OpenUSD. Multi-runtime
stage opens pass their resolver context explicitly so dependency composition
remains attached to the intended runtime.
The 0.1 native-S3 read/composition qualification runs against AWS S3. MinIO,
Cloudflare R2, Backblaze B2, and custom-endpoint runs are optional ovstorage
provider-compatibility investigations; a targeted write-path check does not
qualify a provider for complete stage composition. Endpoint, profile, and
credential configuration remains owned by the test host and ovstorage.
Checked-in CI keeps the fake bridge as its deterministic baseline. For each
release candidate, a maintainer runs the SDK-backed matrix manually from the
exact candidate SHA with the selected ovstorage revision and pinned OpenUSD
SDK, then records that evidence with the candidate. A development dependency
revision is provisional evidence only; final promotion requires repeating
qualification against released ovstorage 0.3.0.

Materialization tests should cover (the resolver holds no byte cache, so
these exercise the lease-based `MaterializedAsset` contract against a
fake bridge):

- bridge-native materialization when the concrete bridge supports it;
- coherent bridge-native metadata from the same local delegate that owns the
  materialized bytes, with no post-materialization stat;
- whole-object read fallback when native materialization is unsupported
  (concrete ovstorage bridge falls back to a `TempFileLease` when the
  Layer surface reports `Unsupported` for `read_local_file`);
- lease lifetime — the returned local path stays valid until the
  `MaterializedAsset` drops, at which point the bridge-supplied
  deleter runs and the file goes away;
- concurrent-read-vs-write invariance — a held lease's bytes must
  survive a subsequent write to the same URL;
- concurrent same-URL materialize — parallel `materialize` calls
  return independent leases pointing at distinct temp paths, with no
  resolver-side global mutex;
- runtime contract enforcement — a bridge that returns
  `status.ok() == true` with an empty local path or a null lease is
  converted to `BackendError`;
- storage error propagation.

Writable-update tests should also prove that an If-Match-capable route refuses
to open for `Update` when coherent materialization metadata has no ETag or an
empty ETag, while the same materialization remains valid for read-only callers.
A route without If-Match support uses overwrite even with an ETag, regardless of
aggregate bridge capabilities. Refused conditional writes must not retry as
overwrite. The SDK-backed writable-asset smoke covers this capability/validator
matrix, untouched-byte preservation, and single-attempt close behavior.

## Package and USDZ Tests

USDZ is in 0.1 scope. Tests include:

- a small synthetic USDZ fixture; covered by the generated OpenUSD package
  smoke;
- a package with an inner layer reference; covered by the generated OpenUSD
  package smoke;
- a package-internal layer with an absolute reference under a second advertised
  scheme; covered by the deterministic `cross_scheme_usdz` smoke, which pins
  the exact composed prim, used-layer, and successful-open sets;
- a package with an internal non-layer asset such as a texture; covered by the
  generated OpenUSD package smoke;
- a package path with SDF format arguments;
- an error case for a missing inner asset; covered by the generated OpenUSD
  package smoke;
- a materialization cleanup check.

If public sample content is used for manual testing, it should be documented as
optional and should not be required by CI.

## Integration Tests

Required integration tests should run without credentials:

- local composed USD through the normal resolver path;
- HTTP fixture through a local HTTP server;
- fake ovstorage-backed remote object fixture;
- real ovstorage `file://` bridge fixture when an ovstorage SDK/dist is
  available;
- real ovstorage `http://` OpenUSD fixture against two local loopback servers
  when both OpenUSD and ovstorage SDKs are available, including relative
  sublayer, cross-root reference and payload arcs, and a missing-route control;
- real ovstorage Hugging Face StackConfig construction and native `hf://`
  route ownership without provider IO when the plugin artifacts are available;
- cross-scheme USDZ composition through deterministic fixtures.

Optional integration tests may cover:

- public S3 sample assets through
  `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL`;
- live AWS S3 native `s3://` stage composition through
  `OVS_USD_RESOLVER_LIVE_S3_STAGE_URL`, with optional HTTPS dependency roots
  supplied through `OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS`;
- non-AWS S3-compatible provider investigations using the same smoke harness,
  reported separately from the resolver 0.1 compatibility claim;
- pinned public NVIDIA Hugging Face USD composition through native `hf://`
  when `OVS_USD_RESOLVER_RUN_LIVE_HF=1`;
- additional configured providers when their ovstorage plugins are available;
- OpenUSD application integration.

## CI Matrix

The checked-in `.github/workflows/ci.yml` runs no-SDK Release builds and CTest
on Linux x86_64, Linux aarch64, Windows x86_64, and macOS arm64. Each platform
runs the default and az-only scheme configurations. Platform jobs have stable
explicit IDs; Windows uses MSVC with Ninja so plugin metadata and executable
paths use the same single-configuration layout as the other platforms. The core
DLL exports the functions used by the separate CLI and unit-test executables.

These jobs test the core, CLI and SDK-layout fixtures. They do not qualify the
concrete bridge, an OpenUSD binary ABI, providers, or a wheel on those platforms.
Maintainer source validation exports and audits the exact projected archive and
builds that projection both without SDKs and against the pinned OpenUSD SDK.
The maintainer `wheel-build` workflow builds the concrete combined stack and runs deterministic
provider-backed tests on all three binary targets. It also installs the prepared
wheel with normal pip dependency resolution and tests outside the source tree.
The public ovstorage v0.3.0 tag and package are prerequisites; a skipped or
unavailable dependency is not qualification. Live-provider release gates remain
separate and must retain evidence for the selected candidate.

`ci.yml` is the only resolver workflow included in the public source. The maintainer
`release-shape`, `sdk-plugin` and `wheel-build` workflows and their artifacts
are not shipped there. Consumers reproduce the applicable
[source/provider tests](building.md#build-and-test) locally; those three
workflow names are maintainer context, not public commands or evidence links.
The `sdk-plugin` fixtures alone do not qualify matched providers.

The maintainer `release-shape` workflow validates the source export. Wheel-build retains
useful package-content, runtime and installed-consumer tests, but no resolver
wheels are published for this release and wheel publication is not a release
gate. Local native installation and any future package distribution require
their own consumer and runtime-closure evidence.

## Shipping criteria

Do not consider the resolver ready to ship until:

- a clean checkout builds the plugin;
- the projected public source builds against the pinned OpenUSD SDK and the
  exact selected ovstorage 0.3.x tag;
- a clean checkout runs required tests without private infrastructure;
- an agent can run the same tests from `AGENTS.md`;
- an agent can run `doctor` and get actionable setup output;
- local USD behavior is proven to work without ovstorage;
- remote USD behavior is proven to require and use ovstorage;
- package/USDZ behavior is covered;
- the native AWS S3 and pinned native Hugging Face composition gates pass;
- the exported tree passes its public-content audit;
- failures are clear enough to route to the right component owner.

The no-SDK `platform` test exercises exclusive temporary-file creation, binary
bytes, Unicode parent paths, collision preservation, concurrent leases and
cleanup, plus native provider filename recognition. POSIX additionally checks
owner-only permissions and rejection of pre-existing symlinks. These helper
tests do not replace SDK-backed materialization or provider-load tests.

The `sdk-plugin` workflow builds and tests the pinned Kit USD plugin on Linux
x86_64, Linux aarch64, and Windows x86_64. This suite exercises OpenUSD against
deterministic bridge fixtures. Concrete ovstorage provider qualification needs
the additional SDK-backed bridge tests and a matching provider bundle.
Windows uses CMake 3.22+ for test DLL search paths and the SDK's separate `bin`
and `lib` directories. Only Release SDK binaries are pinned.

The Linux ARM SDK also names the X11/SM/ICE/Xext development linker interfaces;
install `libsm-dev libice-dev libx11-dev libxext-dev` alongside OpenGL on Ubuntu.
The `support_platform` no-SDK test launches a child with spaces, quotes, empty
arguments and shell metacharacters, verifies its exit status and captured output,
and sends a real request to the loopback HTTP fixture. SDK-backed CLI/example
smokes use the same direct subprocess helper; no shell quoting is involved.

Windows concrete-provider fixtures create symbolic links, including a dangling
non-provider library entry. Local Windows runs require Developer Mode or the
Create symbolic links privilege (hosted CI supplies it). The POSIX subprocess
helper relies on the enclosing CTest timeout; invoke these smokes through CTest
when a child may hang. The Windows helper also terminates a child after 60 s.
