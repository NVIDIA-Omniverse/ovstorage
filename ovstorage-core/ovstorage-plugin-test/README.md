# ovstorage-plugin-test

> The Cargo crate name `ovstorage-plugin-test` is the canonical name. The crate's design doc was titled "plugin-conformance"; that name describes the harness's role (an in-tree controllable backend used by the workspace's conformance harness, not a third-party plugin-author TCK or a production backend). Real backend plugins prove that ovstorage works against real systems; this crate is the deterministic input that lets the host conformance suites drive ABI shapes real services cannot produce reliably on demand.

## Purpose

`plugin-conformance` is a controllable backend plugin used by the workspace's conformance harness. The harness loads it when a test needs the host to observe a very specific plugin behavior: a streamed read that fails after two chunks, a redirect whose response carries exactly the headers listed in `ResultCapture`, a multipart write whose final `continue_write` returns `Done`, a change stream that emits `Lapsed` before resuming, or an authentication flow that opens a browser and then gets cancelled.

That is different from first-party backend conformance:

- `file`, `s3`, `gcs`, `azure`, `http`, `opendal`, `broker-client`, and `nucleus` prove the public contracts against realistic backends and provider APIs.
- `plugin-conformance` proves that the host (`ovstorage`, `ovstorage-broker`, and `broker-protocol`) consumes every legal storage SPI shape correctly.

The plugin is intentionally small, scripted, and boring. It does not model S3, GCS, Azure, Nucleus, POSIX filesystems, or provider-specific metadata. It emits named scenarios from a fixed registry and records the host calls it observed. If a behavior can be exercised cheaply against a real backend, the real-backend test remains the primary test and the conformance scenario is only a host-edge supplement.

**Name choice.** The doc title `plugin-conformance` matches the "conformance suite" vocabulary in the per-crate `Conformance tests` sections; the Cargo crate is `ovstorage-plugin-test`. The two names refer to the same crate.

## Public surface

The manifest carries `test_only: bool`; the host loader refuses any
`test_only = true` cdylib unless the host configuration enables test
plugins. Refusal surfaces as `ErrorCode::PluginRejected`. The
`ovstorage-plugin-test` crate's
`Cargo.toml` carries `publish = false` and builds as an rlib only. The
`ovstorage_layer_plugin!(backend, TestLayerFactory::default, test_only)`
macro invocation (the function-like macro from
[ovstorage-plugin-macros](../ovstorage-plugin-macros/README.md); the
optional trailing `, test_only` flips the manifest's `test_only` bit)
lives in the sibling
[`ovstorage-plugin-test-abi`](../ovstorage-plugin-test-abi/) cdylib
crate, which emits the manifest with that flag set — the macro stamps
fixed-name `#[no_mangle]` entry-point symbols into every crate type
(including rlibs), so keeping it out of this crate lets other plugins
link the harness into their own test binaries. There is no
`#[ovstorage_plugin(test_only)]` attribute macro; the function-like
form is the only spelling.

The implemented address scheme is `test:` (`ADDRESS_SCHEME = "test"`
in `src/config.rs`). The `conformance:` scheme name is reserved (see
`CONFORMANCE_ADDRESS_SCHEME` in `src/scenarios.rs`) for the future
scenario-authority-driven dispatch pattern documented under "URL format
(target design)" below; no plugin code routes on `conformance:` today.

- **Scheme**: `test:` (current); `conformance:` is reserved (target design).
- **Manifest**: `name = "ovstorage-plugin-test-abi"` (the macro pulls it from the exporting crate's `CARGO_PKG_NAME`, and the `ovstorage_layer_plugin!` export lives in the [`ovstorage-plugin-test-abi`](../ovstorage-plugin-test-abi/) cdylib crate), `version = "0.1.0"`, `test_only = true`. There is **no** `plugin_kind` or `schemes` field on `PluginManifestV1` — see [ovstorage-plugin § C-ABI surface](../ovstorage-plugin/README.md#c-abi-surface).
- **Descriptor**: `supports_runtime_add = true`; tests can instantiate scenario backends through `add_connection`, not only from static startup config.
- **Package policy**: workspace member, `publish = false`, `crate-type = ["rlib"]` (no FFI export symbols). The cdylib that ships in the release archive's `plugins/` directory is built from the sibling [`ovstorage-plugin-test-abi`](../ovstorage-plugin-test-abi/) crate (artifact `libovstorage_plugin_test_abi.so` / `.dylib` / `ovstorage_plugin_test_abi.dll`) so downstream host authors can drive their host through the conformance fixture; the host-level `allow_test_plugins` gate carries the safety story (bundle exclusion is intentionally not a layer — see Threat model below).
- **Credential keys**: none. The plugin never accepts long-lived credentials, cloud keys, OAuth refresh tokens, or bearer tokens.
- **Host gate**: the library and broker load the plugin only when the host opts in via `allow_test_plugins = true`. Direct loading returns `PluginRejected` when the host has not opted in. Directory discovery skips the plugin at debug-log level, so a default-posture deployment can scan a `plugins/` directory containing the bundled cdylib without failing startup.

### Modules and types in place

The `ovstorage_plugin_test::scenarios` module exposes the `Scenario`
/ `Profile` / `ExpectedCall` / `FailureContract` /
`ScenarioRegistry` types with `Profile::capabilities()` mapping each
profile to its advertised `Capabilities`.
`ScenarioRegistry::with_defaults()` seeds 8 named scenarios covering
the Stat / Read / Write / Delete / List boundary contracts. The
`ovstorage_plugin_test::recorder` module exposes the `Recorder` +
`ObservedCall` types and is wired through every SPI method on
`TestBackend` via `enter_recorded`. `__test_meta/calls.json` surfaces
the structured log alongside the `__test_meta/method_calls.json`
counter map. `ovstorage_plugin_test::responder` ships a loopback-only
HTTP responder (`Responder::start`) with `Route`, `ScriptedResponse`,
and `CapturedRequest` for redirect-scenario verification.
`ovstorage_plugin_test::runner` ships `ScenarioRunner`,
`ConformanceReport`, `ScenarioReport`, and `ScenarioOutcome` with
JSON / human report rendering.

### Surface boundary under test

`plugin-conformance` tests the host/plugin boundary, not the current spelling of the public `Stack` helpers. Scenario groups are therefore classified by the boundary they exercise:

- **`Layer` object SPI**: configured Layer calls such as `stat`, `read`, `write`, `continue_write`, `delete`, `list`, version operations, copy/rename, directory operations, metadata patch, access checks, and watches.
- **`Layer` introspection SPI**: `root_info_for`, `list_address_roots`, and root-scoped `Capabilities`.
- **`Layer` connection/lifecycle SPI**: connection creation, credential update, authentication, stream/delegate destruction, cancellation, and teardown.
- **Factory SPI**: kind descriptors and `BackendFactory::create_backend`.
- **Host-only APIs**: connection management, alias management, visibility overrides, cache policy, redirect following, public `read_*` helper selection, broker authorization, and public bindings. The plugin can provide stimuli and recorder assertions for these paths, but it does not define their public API.

This avoids the trap where an "eight-method" or other public-surface shorthand accidentally becomes the plugin ABI. Conformance names the SPI method it expects the host to call, and host-suite tests name the public API entry point that led there.

### Config keys

The plugin is configured per backend instance. Capabilities are a property of the configured instance, not of individual URLs, so capability-sensitive tests create separate backend instances with separate route prefixes.

#### Implemented keys (current)

The implemented config keys (parsed in `src/config.rs`) are
knob-shaped per-aspect toggles:

`test_root`, `test_caps`, `test_caps_versioning`, `test_caps_server_copy`, `test_caps_server_rename`, `test_caps_copy`, `test_caps_rename`, `test_caps_watch`, `test_redirect_url`, `test_multipart_parts`, `test_continue_write_loops`, `test_redirect_ttl_seconds`, `test_write_returns_unsupported`, `test_write_stream_returns_unsupported`, `test_write_redirect_returns_unsupported`, `test_auth_flow`, `test_auth_drives_host_callbacks`, `test_watch_event_count`, `test_watch_lapsed_at`, `test_watch_keep_alive`, `test_watch_event_kind`, `test_inject_error_on`, `test_inject_error_code`, `test_inject_error_count`, `test_check_access_decision`, `test_read_delay_ms`, `test_panic_on_read_key`.

`test_caps` selects from the `CapsPreset` enum's 4 variants
(`Minimal`, `Full`, `ReadOnly`, `RedirectHeavy`) and the four
`test_caps_*` boolean overrides flip individual bits on top of the
preset. `test_redirect_url` is the loopback redirect endpoint a
scenario expects (the responder helper
`start_responder_with_redirect` returns a matching
`("test_redirect_url", ...)` config pair).

#### Target keys (design — not implemented)

| Key | Type | Required | Meaning |
|---|---:|---:|---|
| `profile` | enum | yes | Capability profile advertised by this backend instance. See "Capability profiles". |
| `scenario_set` | enum | no | Restricts which scenarios this instance may run. Default `all`. |
| `scratch_dir` | path | no | Directory for `LocalDelegate` files, temporary object bytes, and redirect-responder fixtures. Required by scenarios that return local files unless the harness supplies an implicit temp dir. |
| `redirect_base_url` | URL | no | Loopback HTTP(S) endpoint started by the harness. Required by redirect scenarios. (Today's `test_redirect_url` is the closest implemented surface, but loopback enforcement and responder coupling are not wired.) |
| `seed` | integer | no | Deterministic seed for generated payloads and randomized property-test cases. Default `0`. |
| `stream_chunk_bytes` | integer | no | Chunk size used by streamed read/write scenarios. Default `8192`. |
| `clock` | enum | no | `deterministic` or `real`. Default `deterministic`; real time is allowed only for explicit timeout/backoff tests. |
| `required_host` | enum | no | `library`, `broker`, or `any`. Default `any`. Used by host-mode rejection scenarios to verify `Host::is_broker` handling without baking broker-only branches into object I/O. |

Free-form scenario scripts are not accepted in config. If a test needs a new behavior, the behavior is added to the scenario registry with a stable name and a short contract. That keeps reports searchable and prevents one-off test code from quietly creating a second ABI.

### Capability profiles (design)

> Implemented: 4 `CapsPreset` variants (`Minimal`, `Full`, `ReadOnly`, `RedirectHeavy`) in `src/config.rs:107-113`, plus 6 boolean overrides (`test_caps_versioning`, `test_caps_server_copy`, `test_caps_server_rename`, `test_caps_copy`, `test_caps_rename`, `test_caps_watch`) — the availability knobs are independent of the server-side ones so a scenario can express available-but-not-server-side. The `Profile` enum in `src/scenarios.rs` adds 10 named scenario profiles (`Minimal`, `ConditionalWrites`, `MetadataNative`, `VersionsNewest`, `DirectoriesReal`, `AtomicRename`, `WatchDirectoryResumable`, `AddressRootsDynamic`, `Redirects`, `LocalDelegate`) with `Profile::capabilities()` mapping each to a `Capabilities` value; ~10 of the ~20 design profiles below are unimplemented (e.g., `metadata_rewrite_only`, `metadata_unsupported`, `versions_oldest`/`versions_unordered`, `permissions_on_stat`, `access_check`, `watch_directory_non_resumable`, `directories_flat`, `server_side_copy`, `server_side_rename`). Per-instance capability immutability is partly enforced (`TestBackend::capabilities` snapshots at instantiate, `src/lib.rs:152`); profile-level scenario gating in the runner is implemented but not driven from the `TestConfig` knob layer.

Each profile maps to a fixed `Capabilities` value. Tests choose profiles to verify that the host honors capability gating before plugin dispatch.

| Profile | Purpose |
|---|---|
| `minimal` | Only `stat`, read, write, delete, and one-level list. No metadata patch, access check, version listing, directories, or watch_directory. |
| `conditional_writes` | Sets `supports_if_match_write` and `supports_no_overwrite_write`; write precondition scenarios expect the plugin to reject mismatches before bytes are committed. |
| `metadata_native` | Advertises `supports_native_metadata_patch = true`; `update_metadata` mutates `UserMetadata` without rewriting bytes. |
| `metadata_rewrite_only` | Advertises `supports_metadata_rewrite_emulation = true` and native patch false; verifies `allow_rewrite_emulation`. |
| `metadata_unsupported` | Advertises neither metadata-patch bit; `update_metadata` must not be called by a host path that first checked capabilities. |
| `versions_newest`, `versions_oldest`, `versions_unordered` | Exercise `list_versions` ordering and caller-side sorting rules. |
| `permissions_on_stat` | Advertises `populates_effective_permissions_on_stat = true`; `stat` and full-metadata list scenarios populate `ObjectInfo.effective_permissions`. |
| `access_check` | Advertises `supports_access_check = true` and returns scripted `AccessDecision` values. |
| `watch_directory_resumable` | Advertises resumable watch_directory streams and a bounded `watch_directory_max_lag`. |
| `watch_directory_non_resumable` | Supports watch_directory but emits `Lapsed` when opened with `since`. |
| `dynamic_roots` | Sets `address_roots_are_dynamic = true` and drives `watch_address_roots` `Snapshot` / `Added` / `Removed` events. |
| `directories_real` | Reports `has_real_directories = true` and uses real-directory semantics inside the in-memory store. |
| `directories_flat` | Reports flat-backend marker semantics for directory tests. |
| `server_side_copy` | Advertises `supports_server_side_copy = true`; copy scenarios expect a single `Layer::copy` call instead of host read/write fallback. |
| `server_side_rename` | Advertises `supports_server_side_rename = true`; rename scenarios expect a single `Layer::rename` call. |
| `atomic_rename` | Advertises both `supports_server_side_rename = true` and `supports_atomic_rename = true`; rename scenarios expect all-or-nothing behavior. |

The default profile is deliberately absent. Tests must name the profile they rely on, so a capability skip can cite exactly which capability was missing.

### URL format

#### Current

The implemented scheme is `test:` (`ADDRESS_SCHEME = "test"` in `src/config.rs`). Keys after the address root are addressed verbatim into the in-memory `BTreeMap`. The only carved-out path namespace is `__test_meta/` (`META_PREFIX` in `src/lib.rs`); two introspection sub-keys are surfaced (`method_calls.json` for the `MethodCounters` map and `calls.json` for the structured `ObservedCall` log), plus a `redirect_expired` toggle. **Scenario behavior is selected by per-connection config knobs, not by URL**.

#### Target design — not implemented

The `conformance:` scheme is reserved (`CONFORMANCE_ADDRESS_SCHEME` constant in `src/scenarios.rs`) for the URL-based scenario authority described below; no plugin code routes on it today.

Scenario selection is URL-based:

```text
conformance://<scenario>/<object-key>
```

The authority is the scenario name. The path is the object key and is preserved byte-for-byte after normal `ObjectAddress` canonicalization. Query parameters are scenario-specific but must be declared in the registry; unknown query keys fail `InvalidArgument`.

Examples:

```text
conformance://read-streamed-midstream-error/assets/a.bin
conformance://write-multipart-three-batches/assets/out.bin
conformance://watch-directory-lapsed-then-resume/team/
conformance://list-versions-preserve-query/foo.bin?response-content-type=text/plain
```

The harness normally mounts each profile on a distinct route prefix, for example:

```toml
[[backend]]
id = "cf-redirects"
plugin = "conformance"
profile = "minimal"
scenario_set = "redirects"
redirect_base_url = "http://127.0.0.1:49152"

[[route]]
prefix = "conformance://"
backend = "cf-redirects"
```

## Internals (design)

> The crate has 7 source files: `lib.rs` (TestFactory + TestBackend + `start_responder_with_redirect` helper), `config.rs` (knob parser + `CapsPreset`), `store.rs` (in-memory BTreeMap + `MethodCounters`), `scenarios.rs` (`Scenario` / `Profile` / `ScenarioRegistry`), `recorder.rs` (`Recorder` + `ObservedCall` log), `responder.rs` (loopback HTTP responder for redirect-scenario verification), and `runner.rs` (`ScenarioRunner` + `ConformanceReport`). The harness, responder, scenario registry, and `ObservedCall` log all exist. The responder→backend wiring is exposed via `start_responder_with_redirect` (returns the `Responder` plus the matching `("test_redirect_url", ConfigValue::String(loopback))` pair so a single `add_connection` call carries both). Missing from the design below: a `scratch_dir` namespace (no per-instance scratch directory), and richer `Route` modeling that mirrors the SPI's `BodySource` / `ResponseParsing` / `ResultCapture` descriptors so responder routes can declare exact byte-level expectations (the captures already record what the host sent; the routes do not describe what the host *should* send beyond method+path).

### Two pieces: plugin and harness support

The crate owns two test-only pieces:

1. **The backend plugin** loaded through [ovstorage-plugin](../ovstorage-plugin/README.md). It implements the manifest, `BackendFactory`, and `Layer`.
2. **Harness support** linked only into tests. It starts the loopback redirect responder, creates scratch directories, exposes scenario assertions, captures observed calls, and generates the scenario report under `tests/conformance/reports/`.

The plugin binary does not start listeners or spawn background services by itself. Redirect scenarios require the harness to pass `redirect_base_url`; without it, the plugin rejects the scenario at config/probe time.

The boundary between those two pieces is strict. The plugin may read only its config, input bodies, deterministic store, scratch subdirectory, and responder URL. It may record observed SPI calls through the recorder handle the harness supplied. It must not call back into the host `Stack`, inspect the routing table, read the cache database, mutate broker policy, sleep on real time in deterministic mode, or start its own redirect/auth services. If a test needs host-side setup, the harness does it and passes the resulting handles through explicit config.

### Scripted object store (partial)

> Implemented as `BTreeMap<String, Vec<StoredObject>>` in `src/store.rs`. `StoredObject` carries `bytes`, `mtime`, `user_metadata` only — the design's `identity`, `system_metadata`, and `version_log` are not separate fields (etag is derived from `bytes.len()`, version is `None`, no version log). `if_match` is checked but `seed`-derived stable ETags are not implemented.

The plugin keeps a deterministic in-memory object store per backend instance:

```text
struct ScenarioObject {
    bytes: Bytes,
    etag: String,
    version: Option<String>,
    system_metadata: SystemMetadata,
    user_metadata: UserMetadata,
    version_log: Vec<VersionRecord>,
}
```

Keys are the resolved `ObjectAddress` the plugin receives. Writes increment a monotonically increasing version counter and derive stable ETags from `(seed, key, version, bytes)`. This store is not a cloud simulator; it exists so `stat`, `list`, `list_versions`, preconditions, and metadata operations can produce stable answers while the host behavior under test changes around them.

Preconditions follow the project contract: the etag is the opaque token the plugin compares against the SPI's `if_match` / `if_source` / `IfDestExists::MatchEtag` payloads. The plugin can be configured by scenario to fail the precondition before bytes flow, or to return a response etag that causes the host to detect a post-response mismatch.

### Redirect responder (design)

> A loopback HTTP responder is implemented in `src/responder.rs` (`Responder::start` binds `127.0.0.1` on an ephemeral port; `Route` + `ScriptedResponse` declare matches; `CapturedRequest` records what the host actually sent). The crate-level `start_responder_with_redirect(routes)` helper returns the `Responder` plus a `("test_redirect_url", ConfigValue::String(<loopback>))` pair callers add to `ConnectionRequest.config`, so a single `add_connection` move points the plugin's redirect emission at the responder's loopback URL and the host's redirect follower fetches scripted responses end-to-end. The `read_redirect_points_at_loopback_responder` self-test in `lib.rs` pins this contract. The responder's body verification, status mapping, and loopback-only enforcement are wired; `BodySource` (`Empty` / `UserBytes` / `Inline`), `ResponseParsing`, and `ResultCapture` descriptors are not modeled in the responder's `Route` struct (a route can match on method + path-prefix and emit a scripted response, but cannot declare "the host MUST send these exact bytes" inline). The plugin honors `test_redirect_ttl_seconds = 0` to mint already-expired redirects.

Redirect scenarios use a loopback HTTP responder owned by the harness. The plugin emits `ReadResult::Redirect` or `WriteStep::Redirects` pointing at that responder. Each redirect carries:

- the exact method, URL, headers, and `expires_at` required by the scenario;
- one `BodySource` variant (`Empty`, `UserBytes { offset, len }`, or `Inline(Bytes)`);
- a `ResponseParsing` descriptor;
- a `ResultCapture` descriptor for write redirects.

The responder validates that the host sent the expected method, headers, and body bytes. It returns the scripted status, headers, and body, including malformed or surplus data when the scenario is about rejection or truncation. This keeps provider-specific HTTP out of the host while still testing a real HTTP follower.

### Call recorder (design)

> Implemented: `MethodCounters` (`src/store.rs:121`) — 19 `u64` fields, one per method, exposed as JSON via `__test_meta/method_calls.json`. A structured `ObservedCall` enum (`src/recorder.rs`) records each SPI call with the resolved-address target (and `byte_len` for `Write`, `recursive` for `List`, `src`/`dest` pairs for `Copy`/`Rename`); the log is exposed as JSON via `__test_meta/calls.json` and as a typed `Recorder` snapshot via `TestFactory::recorder_for(root)`. Variants do **not** carry the SPI options struct (`opts`) or a `body_shape` summary — additional context the design below specifies (`opts: ReadOptions`, `body_shape: BodyShape`, `since: Option<WatchDirectoryCursor>`, `ops: AccessOps`) is not modeled. URL/header redaction is not implemented; the recorder stores raw `Url`s as-is.

Every SPI method records a compact event into a harness-owned recorder:

```text
enum ObservedCall {
    Stat { target: ResolvedTarget },
    Read { target: ResolvedTarget, opts: ReadOptions },
    Write { target: ResolvedTarget, opts: WriteOptions, body_shape: BodyShape },
    ContinueWrite { state_len: usize, response_count: usize },
    UpdateMetadata { target: ResolvedTarget },
    List { prefix: ResolvedTarget, opts: ListOptions },
    CheckAccess { target: ResolvedTarget, ops: AccessOps },
    WatchDirectory { prefix: ResolvedTarget, since: Option<WatchDirectoryCursor> },
}
```

Tests use the recorder to assert negative behavior that cannot be seen from the public result alone. For example, a route whose profile lacks `supports_native_metadata_patch` and `supports_metadata_rewrite_emulation` must not receive `UpdateMetadata`; a multipart write must receive one `RedirectResponse` per redirect in the same order the plugin emitted; a host retry test must not cause plugin-internal retry sleeps.

Recorder assertions are allowed only for contract-critical negative checks of this kind — "host must not call unsupported method" or "wrong-cardinality redirect result fails." Ordinary behavior is asserted through public API results, never through the recorder; otherwise the recorder would lock in implementation details the public API hides. The line is enforced at review.

Observed calls redact URLs and headers with the same rules as normal tracing. The recorder stores scenario names, target hashes, and safe request summaries, not signed query strings or credential-shaped bytes.

### Registry entry shape (design)

> The canonical reference for **Registry entry shape** (the per-scenario fields `name`, `vtable_slots`, `required_profile`, `required_capabilities`, `required_config`, `allowed_hosts`, `expected_calls`, `failure_contract`, `report_tags`, plus the append-only rule) lives in [`docs/public/plugin-development/README.md` § Registry entry shape](../../docs/public/plugin-development/README.md#registry-entry-shape).

### What the plugin does not fake

`ReadResult::Pending` is not a backend-plugin behavior in the SPI. It is produced by the cache/herd-collapse layer in front of the plugin. Pending-read coverage belongs to an `ovstorage-cache` harness fixture that races multiple callers against this plugin or a fake fetch gate. `plugin-conformance` does not return `Pending` directly.

Likewise, host authorization decisions are not made by backend plugins. Host
authorization scenarios configure the built-in auth Layer;
`plugin-conformance` supplies only the backend behavior dispatched after the
policy allows the call.

`plugin-conformance` also does not fake provider SDKs, IAM systems, eventual consistency, object-store billing behavior, clock skew between cloud regions, or native filesystem watcher quirks. Those belong to first-party backend tests and integration tests. This plugin provides legal SPI shapes and controlled edge cases so the host can prove it consumes them correctly.

### What conformance must not over-specify

The harness should stay precise about ovstorage contracts and loose about backend implementation choices:

- Do not require exact retry counts, sleep durations, HTTP connection reuse, thread counts, or task scheduling. Tests may assert "no plugin-internal retry sleep" when retry ownership is the host contract, but not the host's private backoff implementation.
- Do not require a provider-specific metadata spelling unless the scenario is explicitly about `ResponseParsing` or normalized `SystemMetadata` mapping. Real plugins decide which vendor headers are useful.
- Do not require list or version order except through `version_list_order` and explicit paging contracts. Streams must be complete and duplicate-free; their natural ordering remains backend-defined unless the capability says otherwise.
- Do not require byte-for-byte public error messages. Assert typed errors, stable reason codes, and redaction of sensitive values.
- Do not require a specific cache file layout, SQLite schema, redirect batch executor, broker wire framing, or binding-level wrapper shape. Those are tested in their owning crates.
- Do not turn this plugin into a third-party TCK. A future plugin-author TCK may reuse scenarios, but it needs a separate packaging story, clearer compatibility promises, and tests that run against arbitrary plugin binaries rather than this in-tree fake.

The harness ships **stable named scenarios only**, never a free-form scripting language. A scripting language would become a second plugin ABI: every breaking change to it would force every plugin author to update tests. New behavior requires a registry addition and a doc update, not a script.

**Scenario fidelity to real backends.** Every scenario in the registry carries a `modeled_after` note — for example `s3 multipart`, `file local delegate`, `GCS generation precondition`, `generic HTTP 503` — and, where feasible, a matching real-backend test that exercises the same broad shape. A fake that drifts away from its referent is a regression detectable both against the registry note and the parallel real-backend run. CI reports "host ABI conformance" and "real backend conformance" as separate gates; release gates require both where the feature claims real-provider support. Passing this crate is therefore a sufficiency check for the host-ABI contract, not a guarantee that a plugin works against real backends.

## Scenario registry (design)

> 8 of the ~80 scenario names below exist as `ScenarioRegistry::with_defaults()` entries (see "Registry entry shape" above): `stat-basic-objectinfo`, `stat-not-found`, `read-streamed-empty`, `write-done-inline`, `write-no-overwrite-existing`, `delete-existing-object`, `list-one-level-vs-recursive`, `metadata-unsupported-not-called`. The remaining ~70 are design-only. `../ovstorage-plugin-test-abi/tests/loaded.rs` (the dlopen coverage moved with the cdylib export to the `-abi` crate) has 5 hand-written `#[tokio::test]` functions that approximate a few scenarios (`dlopen_round_trip_through_in_memory_store` ≈ stat-basic-objectinfo + write-done-inline + read-streamed-empty subset; `dlopen_read_emits_redirect_when_url_configured` ≈ read-redirect-basic, driving the loopback `Responder` end-to-end via `start_responder_with_redirect` and asserting captured request bytes; `dlopen_multipart_write_runs_continue_write_loop` ≈ write-multipart-three-batches, wired through the loopback responder so the host's redirect follower completes the multi-stage write deterministically; `dlopen_introspection_returns_method_call_counter_after_injected_retries` exercises retry budget; `dlopen_internal_error_in_plugin_method_surfaces_to_host` ≈ abi-panic-or-exception-contained — it drives an `Err(Internal)` return through the FFI path rather than a live panic (a genuine in-method panic on the dlopen path would also surface as `Internal`, caught by the thunk's `catch_unwind` wall), proving a plugin error surfaces cleanly and the library stays usable), plus a `#[test]` `dlopen_test_plugin_is_rejected_without_allow_flag` that pins the production-host rejection. `tests/conformance.rs` runs the runner against 6 registered scenarios + 1 skip and snapshots the report.

Scenario names are stable test identifiers. A conformance report cites them as:

```text
plugin-conformance scenario `read-streamed-midstream-error`
```

### Factory, ABI, and lifecycle

| Scenario | Contract |
|---|---|
| `factory-descriptor-schema-roundtrip` | `BackendFactory::descriptor` exposes config and credential schema; host renders it, validates exact keys, and creates a Layer from matching config. |
| `factory-invalid-config` | Missing, unknown, or wrong-typed config keys fail with the documented error before a `Layer` is installed. |
| `factory-host-mode-accepted` | `required_host = any`, `library`, or `broker` accepts the matching host and records the captured `Host::is_broker` value. |
| `factory-host-mode-rejected` | `required_host` deliberately conflicts with the host; `instantiate` fails with a typed error and no route is installed. |
| `abi-struct-size-rejection` | A deliberately undersized options struct is rejected by the callee with `InvalidArgument`; the host reports the error without reading past the declared size. |
| `abi-owned-handle-destroy-once` | Plugin-created stream/error/backend handles are destroyed exactly once, after all in-flight users drop them. |
| `abi-panic-or-exception-contained` | A Rust panic or foreign exception at an exported entry point becomes a typed failure or process abort per ABI policy; it never unwinds across FFI. |
| `backend-concurrent-calls` | Multiple simultaneous `&self` calls observe isolated request state; plugin-global state is internally synchronized. |
| `backend-drop-waits-for-streams` | Backend teardown waits until returned streams/delegates are dropped or cancels them with a typed error; no use-after-free is observable. |

### Stat and identity

| Scenario | Contract |
|---|---|
| `stat-basic-objectinfo` | Returns stable `ObjectInfo` with identity, system metadata, and user metadata populated from the scripted store. |
| `stat-not-found` | Missing key returns `NotFound`; host does not synthesize an empty object or directory. |
| `stat-effective-permissions` | `permissions_on_stat` profile populates `effective_permissions`; profiles without the capability leave the field `None`. |
| `stat-identity-field-subset` | Scenario omits selected identity fields; host preserves absence rather than inventing `size`, `mtime`, `etag`, or `version`. |
| `stat-redacts-sensitive-system-metadata` | Signed-looking values in metadata are redacted in traces and reports while returned typed data remains intact. |

### Reads

| Scenario | Contract |
|---|---|
| `read-streamed-empty` | Returns `ReadResult::Stream` with zero chunks and a valid `ObjectInfo`. |
| `read-streamed-exact-boundary` | Emits bytes exactly equal to `stream_chunk_bytes` and verifies the host neither drops nor duplicates the boundary chunk. |
| `read-streamed-threshold-plus-one` | Emits `stream_chunk_bytes + 1` bytes to catch off-by-one materialization and cache tee bugs. |
| `read-streamed-midstream-error` | Emits two successful chunks, then a typed `Transient`; host must not surface a truncated success or commit a cache entry. |
| `read-local-delegate` | Writes bytes to `scratch_dir`, returns `LocalDelegate`, and verifies the broker promotes broker-side paths to byte streams. |
| `read-local-delegate-lease-lifetime` | Returned path remains valid while the delegate is alive and may be removed only after the lease is dropped. |
| `read-redirect-basic` | Emits a valid redirect whose response headers populate `ObjectInfo` (etag, version, size, mtime) through `ResponseParsing`. |
| `read-redirect-response-parsing-all-fields` | Exercises etag, version, size, mtime format, checksum, and normalized system-metadata header parsing in one response. |
| `read-redirect-expired` | Emits `expires_at` in the past; host must reject before sending the HTTP request. |
| `read-redirect-status-mismatch` | Responder returns a status outside the parsing descriptor; host maps it to the expected typed error. |
| `read-redirect-checksum-mismatch` | Responder returns bytes that do not match `content_checksum_header`; host returns `ContentChecksumMismatch`. |
| `read-post-response-if-match-mismatch` | `if_match` etag matches at request issue but the response carries a different etag (concurrent overwrite); host returns `ObjectModified`. |
| `read-cancelled-stream` | Caller drops the stream early; plugin observes cancellation, releases resources, and host does not log it as a backend failure. |
| `read-redirect-sensitive-url-redaction` | Signed-looking query strings and headers are redacted in recorder output and traces. |

### Writes

| Scenario | Contract |
|---|---|
| `write-done-inline` | `Layer::write` consumes the body and returns `WriteStep::Done` directly. |
| `write-stream-source-midstream-error` | Caller body stream fails mid-write; host aborts the operation and plugin does not return a successful `WriteResult`. |
| `write-single-redirect-put` | One `WriteStep::Redirects` batch with one `UserBytes { offset: 0, len }` redirect, then `Done`. |
| `write-body-source-empty` | Redirect uses `BodySource::Empty`; responder rejects any request body. |
| `write-body-source-sliced-user-bytes` | Redirect uses non-zero `offset` and partial `len`; responder verifies the exact slice. |
| `write-body-source-inline` | Redirect uses plugin-supplied `Inline(Bytes)`; responder verifies those bytes, not caller bytes. |
| `write-result-capture-header-whitelist` | Responder sends requested and surplus headers; plugin receives only the requested ones. |
| `write-result-capture-body-limit` | Responder sends a larger body than `body_max_bytes`; plugin receives the truncated capture. |
| `write-multipart-three-batches` | Initiate batch, N independent part redirects, Complete batch, then `Done`. |
| `write-multipart-part-failure` | One part redirect fails; host surfaces the error and does not call `continue_write` as if all parts succeeded. |
| `write-empty-redirect-batch` | Plugin emits an empty redirect batch as "wait for client"; host handles it without spinning or corrupting state. |
| `write-non-idempotent-complete-dropped` | Final Complete response is dropped; host returns `Transient` without retrying the non-idempotent redirect. |
| `write-if-match-success` | `conditional_writes` profile accepts a matching `IfDestExists::MatchEtag(etag)` and commits exactly one new version. |
| `write-if-match-mismatch` | `conditional_writes` profile rejects a mismatched `IfDestExists::MatchEtag(etag)` before committing bytes. |
| `write-no-overwrite-existing` | `conditional_writes` profile rejects `IfDestExists::Fail` when the key already exists. |
| `write-continue-response-cardinality-mismatch` | Host or broker provides a response vector whose count differs from the redirect batch; write fails typed and the plugin does not commit. |
| `write-continue-state-corrupt` | Opaque continuation state altered by a test host fails typed; plugin never treats malformed state as a valid upload. |

### Object mutation, listings, directories, and versions

| Scenario | Contract |
|---|---|
| `delete-existing-object` | Deletes an existing object and invalidates relevant host cache entries. |
| `delete-not-found` | Missing key returns the documented not-found behavior; host does not treat it as successful unless the public API explicitly says idempotent delete. |
| `copy-same-backend-spi` | `server_side_copy` profile causes host to dispatch same-backend copy to `Layer::copy`; plugin returns a `WriteResult` without the host round-tripping bytes. |
| `copy-fallback-read-write` | When plugin returns `Unsupported`, host fallback reads source then writes destination, preserving identity and cache semantics. |
| `rename-server-side-spi` | `server_side_rename` profile receives one `Layer::rename` call; non-atomic backends must report the partial-success risk through the documented error path. |
| `rename-atomic-spi` | `atomic_rename` profile receives one `Layer::rename` call and either fully moves the object or returns an error without partial state. |
| `rename-fallback-copy-delete` | Non-atomic profile exercises host copy/delete fallback; failure after copy is surfaced as partial-success risk according to the owning host contract. |
| `list-differential-rewrite` | Plugin returns relative keys; host composes caller-facing `ObjectAddress` values after route rewrite. |
| `list-one-level-vs-recursive` | One-level listings return direct objects plus `Subdirectory`; recursive listings return object entries only. |
| `directory-address-trailing-slash-equivalence` | **Documented, not registered — this row describes a scenario the registry does not contain.** The contract it names is real: the host calls `create_directory`, `delete_directory` and `list` with and without the trailing slash, the plugin observes **the spelling the caller wrote** because the host does not rewrite it, and it must reach the same node for both by deriving its own directory key. Host-side coverage lives in the routing, authorization and backend suites; a plugin-side scenario does not exist yet. |
| `stat-input-guided-slash-order` | With list-backed stat disabled or ineligible, bare public `stat("foo")` dispatches exact object stat (`foo`) and falls back to slash-form directory stat (`foo/`) only after exact-object `NotFound`; public `stat("foo/")` dispatches only slash-form directory stat and never exact object stat. |
| `stat-list-backed-object-hit` | Unversioned `stat("dir/a")` under a route with `supports_list = true` and `wants_list_backed_stat = true` is satisfied from one parent `Layer::list("dir/")` object entry; a following `stat("dir/b")` reuses the cached list without another backend call. |
| `stat-list-backed-provider-opt-out` | A route with `supports_list = true` and `wants_list_backed_stat = false` dispatches exact `Layer::stat` and never probes the parent list for public `stat`; this pins the `file` plugin's cheap-native-stat behavior. |
| `stat-list-backed-version-selector-bypass` | `stat("dir/a?versionId=1")`, Nucleus-style `stat("dir/a.usd?&3")`, and any other query/fragment-selected address bypass the parent-list cache and dispatch exact `Layer::stat`, because versioned object URLs do not appear in unversioned list entries. |
| `stat-list-backed-list-miss-fallback` | If the parent list succeeds but does not contain the requested object, the host falls back to exact `Layer::stat` rather than treating the list miss as authoritative `NotFound`. |
| `stat-list-backed-parent-dirty` | Successful write, delete, copy destination, rename source/destination, and metadata update invalidate the whole immediate parent folder list cache before the next sibling stat. |
| `stat-list-backed-notification-dirtying` | Change events for any child dirty the parent list cache as a unit. Self-notifications are not filtered out; event order and timestamps are treated as hints, not as authority to resurrect an older cached entry. |
| `list-marker-folding-flat` | Flat-directory marker object folds into the `Subdirectory` entry and does not appear as a separate object. |
| `stat-directory-real` | Real-directory profile returns directory `ObjectInfo`; flat profile returns marker info, inferred directory info when an authorized bounded prefix probe finds descendants, or `NotFound` when a successful probe finds neither marker nor descendants. |
| `stat-directory-flat-inferred-list-denied` | Flat profile has no marker but would need a bounded prefix probe to infer descendants; when that probe is denied, the plugin returns `PermissionDenied` rather than synthesizing `NotFound` or an inferred directory. |
| `create-directory-real` | Real-directory profile creates a directory entry independent of contained objects. |
| `create-directory-flat-marker` | Flat profile creates the backend's marker object and reports marker metadata on subsequent one-level list. |
| `delete-directory-real-nonempty` | Real-directory profile rejects deletion of a non-empty directory with `DirectoryNotEmpty`. |
| `delete-directory-flat-marker-only` | Flat profile removes only the marker; contained objects remain and may still make the prefix appear in listings. |
| `list-versions-preserve-query` | Existing query parameters survive when version selectors are appended. |
| `list-versions-pinned-filter` | A version-pinned base URL returns at most the pinned version. |
| `list-paging-boundary` | Repeated `(max_results, page_token)` calls produce the same sequence as unpaged streaming, without duplicates or gaps. |

### Metadata, permissions, and capabilities

| Scenario | Contract |
|---|---|
| `metadata-native-patch` | `update_metadata` applies `metadata set/remove options` in place and returns a new `ObjectInfo`. |
| `metadata-rewrite-required` | With rewrite emulation allowed, host drives rewrite path; without it, host returns `Unsupported`. |
| `metadata-unsupported-not-called` | A profile advertising no patch capability must not receive `Layer::update_metadata`. |
| `capabilities-immutable` | The `RootInfo.capabilities` value stays constant for the connection lifetime, even after writes, auth refresh, or scenario changes. |
| `capability-skip-reported` | A skipped host test records the exact absent capability and profile; generic "backend does not support it" skips fail the harness. |
| `effective-permissions-flags` | Emits `effective_permissions` values: full set, `READ` only, `EffectivePermissions::empty()`, and `None`; host treats each per the SPI contract. |
| `check-access-subset` | Returns exactly the allowed subset of requested ops; unrequested ops do not appear. |
| `check-access-unsupported` | Profile without `supports_access_check` returns `Unsupported` without a synthesized answer. |

### WatchDirectory and address roots

| Scenario | Contract |
|---|---|
| `watch-directory-basic-events` | Emits `Created`, `Modified`, `Deleted`, and `MetadataChanged` under one prefix. |
| `watch-directory-lapsed-then-resume` | Emits `Lapsed`, then resumes with a fresh cursor; host forwards both. |
| `watch-directory-resume-from-cursor` | Resumable profile replays events from `since` rather than starting from "now". |
| `watch-directory-nonresumable-since` | Non-resumable profile emits `Lapsed` first when opened with `since`. |
| `watch-directory-one-level-filter` | `recursive = false` suppresses nested-key events; `recursive = true` includes them. |
| `watch-directory-option-superset` | Recursive watches retain all non-recursive events, and metadata-inclusive watches retain all object events while adding metadata changes. |
| `address-roots-absolute` | `address_roots` returns absolute `ObjectAddress` values; host does not prepend route prefixes. |
| `watch-address-roots-default-snapshot` | Profile without `address_roots_are_dynamic` gets the default single `Snapshot` behavior and no synthetic deltas. |
| `watch-address-roots-snapshot` | Emits a `Snapshot` followed by `Added` and `Removed`; host mutates routes under a single route-epoch bump per change batch. |

### Authentication and connection management

| Scenario | Contract |
|---|---|
| `auth-anonymous-noop` | Factory `authenticate` returns an empty `SecretBundle` and no events. |
| `auth-pkce-open-browser-success` | Emits `AuthEvent::OpenBrowser`, then `Succeeded` with a refreshed connection. |
| `auth-device-code-success` | Emits `DeviceCode`, honors polling interval, then succeeds. |
| `auth-cancelled` | Stops when the application drops the stream; plugin observes cancellation and emits `Cancelled`. |
| `auth-failed` | Emits `Failed` with a typed `ConnectionError`. |
| `probe-success` | `probe` succeeds after instantiate and records no extra object I/O calls. |
| `probe-failure-variants` | `probe` returns each documented `ConnectionError` variant under a named query case. |
| `update-credentials-reinstantiate` | Returns `ReinstantiateRequired`; host rebuilds the backend while preserving `ConnectionId`. |
| `update-credentials-in-place` | Plugin accepts a new `SecretBundle`, refreshes internal state, and keeps the same backend instance. |
| `connection-secret-redaction` | Configured fake secrets are redacted in descriptors, recorder output, debug logs, and reports. |

### Broker-specific host paths

| Scenario | Contract |
|---|---|
| `broker-read-redirect-over-threshold` | Broker forwards a read redirect for an object above `cache.max_object_bytes`. |
| `broker-read-stream-under-threshold` | Broker fetches, caches, and streams an under-threshold object. |
| `broker-local-delegate-promotion` | Broker converts plugin-local paths to byte-stream responses; client never receives broker filesystem paths. |
| `broker-write-accept-upload-threshold` | With `size_hint <= threshold`, broker accepts inline upload and caches on success. |
| `broker-write-redirect-unknown-size` | With unknown size, broker prefers redirect branch when the plugin can mint redirects. |
| `broker-multipart-result-pairing` | Out-of-order or wrong-cardinality `RedirectResultBatch` fails as a typed error, not a corrupted upload. |

## Dependencies

In-workspace:

- [ovstorage-plugin](../ovstorage-plugin/README.md) for the Layer SPI, manifest, redirect vocabulary, factory traits, and `AuthEvent` surface.
- [ovstorage-plugin](../ovstorage-plugin/README.md) § "Type vocabulary" for `ObjectAddress`, `ResolvedTarget`, `ObjectInfo`, `ObjectKind`, `IfDestExists`, `Capabilities`, errors, connection types, and metadata maps.
- [ovstorage-cache](../ovstorage-cache/README.md) as a dev-dependency only for `ReadResult::Pending` and herd-collapse companion fixtures.

External dependencies stay test-oriented: `bytes`, `futures-core`, `tokio`, `tempfile`, `serde`, and a small loopback HTTP server stack such as `hyper` or `axum` for redirect scenarios. No cloud SDKs, no keyring dependency, no filesystem watcher dependency, and no provider-specific auth libraries belong in this crate.

## Threat model (design)

> Of the defense-in-depth claims below, the implemented layers are: the manifest carries `test_only: true` through `ovstorage_layer_plugin!(backend, TestLayerFactory::default, test_only)`, the host gates loading behind `allow_test_plugins`, directory discovery skips the cdylib when the host has not opted in, and `Cargo.toml` carries `publish = false`. The responder enforces loopback-only binds at `Responder::start`. Bundle exclusion is not a defense layer — the cdylib ships in the release archive so downstream host authors can opt in to it. **Unimplemented:** `scratch_dir` namespace (no per-instance scratch directory plumbing); responder-side body verification against `BodySource` / `ResponseParsing` / `ResultCapture` descriptors.

This plugin is hostile to production by design. It can forge identities, emit arbitrary redirects, synthesize auth events, and return bytes unrelated to any real backend. The defense relies on the host gate:

- The manifest carries `test_only = true`.
- Direct loading returns `PluginRejected` when the host has not enabled test plugins.
- Directory discovery skips the cdylib at debug-log level when the host has not opted in, so a default-posture broker / REST gateway can sweep a `plugins/` directory containing the bundled cdylib without failing startup or surfacing a backend that responds to `test://` URLs.
- The broker reads `OVSTORAGE_ALLOW_TEST_PLUGINS=1` to flip `allow_test_plugins`; production deployments leave the env unset, in which case the bundled cdylib is silently ignored.

The plugin never accepts credentials. Auth scenarios use fake `SecretBundle` values that are shaped like credentials but contain deterministic non-secret bytes. Redirect scenarios may include signed-looking query strings to verify redaction, but those strings are generated by the harness and are not valid credentials.

`scratch_dir` is treated as disposable test state. The plugin writes only under that directory, rejects symlink escapes when creating `LocalDelegate` files, and removes its scratch subdirectory on normal teardown. Crash cleanup is the harness's responsibility.

The redirect responder binds only loopback addresses supplied by the harness. A `redirect_base_url` with a non-loopback host fails config validation so a test cannot accidentally send scripted request bodies to the network.

## Conformance tests (design)

> Implemented self-tests: 5 `#[tokio::test]` functions in `../ovstorage-plugin-test-abi/tests/loaded.rs` (round-trip, redirect-emission, multipart `continue_write`, bounded-injection retry, internal-error surfacing), 1 `#[test]` in the same file pinning the production-host rejection of `test_only` plugins (`dlopen_test_plugin_is_rejected_without_allow_flag`), one `#[tokio::test]` runner-driven smoke in `tests/conformance.rs` snapshotting `tests/conformance/reports/runner_smoke.json`, plus unit tests in `src/config.rs`, `src/store.rs`, `src/scenarios.rs`, `src/recorder.rs`, `src/responder.rs`, `src/runner.rs`. The `tests/conformance/` directory exists; the runner emits both a `render_human()` summary and a stable `render_json()` report; a skip protocol (`ScenarioOutcome::Skipped { reason }`) is implemented and verified by the runner integration test. **Missing:** the determinism oracle (no fixed-seed end-to-end byte-equality test across runs) and the release-package CI gate (no grep on the released tarball for the test-plugin cdylib). The `struct_size`-rejection assertion lives in `ovstorage-plugin` as a unit test (`marshal::tests::read_options_undersized_struct_size_is_rejected` exercises the rejection path through `ffi::validate_struct_size` + `read_options_from_ffi`); the helper is wired into the `ReadOptions` from-FFI converter, so a thunk passed an undersized struct surfaces `InvalidArgument` before reading any tail field. A full conformance scenario (`abi-struct-size-rejection`) that drives the same path through the loaded-plugin runner is the residual gap.

This crate is mostly an input to other conformance suites, but it has its own self-tests:

**Loader and packaging**
- Direct loading of the test cdylib returns `PluginRejected` when `allow_test_plugins` is off.
- Directory discovery skips the test cdylib at debug-log level when `allow_test_plugins` is off; the scan succeeds and other plugins in the directory load normally.
- A host that opts in via `allow_test_plugins(true)` accepts the cdylib and records the loaded manifest.
- The cdylib ships in the release archive's `plugins/` directory; there is no bundle-exclusion check.

**Scenario registry**
- Every scenario in this document has a registry entry, a stable string name, and at least one harness test.
- Every registry entry declares `vtable_slots`, `required_profile`, `required_capabilities`, `required_config`, `allowed_hosts`, `expected_calls`, and `failure_contract`.
- Unknown scenario names and unknown scenario query keys fail `InvalidArgument`.
- Each scenario declares required config keys; missing `scratch_dir` or `redirect_base_url` fails before dispatch.
- Scenario reports include the scenario name, profile, seed, route prefix, and the crate test that consumed it.

**Capability skip policy**
- A host conformance test may skip a scenario only when the scenario's declared `required_capabilities` are absent, the scenario's declared `allowed_hosts` excludes the current host, or a required harness fixture such as `redirect_base_url` is intentionally not started for that suite.
- Every skip record includes the absent capability or host/fixture reason. Free-form skip messages are test failures.
- A present capability turns the scenario into a requirement. The plugin must produce the advertised behavior, and the host must not silently downgrade to a fallback path unless that fallback is the documented behavior under test.
- Negative capability scenarios assert non-dispatch through the call recorder. For example, `metadata-unsupported-not-called` fails if the host calls `Layer::update_metadata` and then translates `Unsupported`; the contract is that the capability check happens before dispatch on host paths that can check it.
- Capability profiles are per backend instance. Tests that need two capability sets instantiate two backends instead of changing a profile at runtime.

**Determinism**
- Given the same `profile`, `scenario`, `seed`, and input bytes, the plugin emits byte-for-byte identical streams, identities, version logs, and observed-call records.
- `clock = deterministic` tests do not sleep on wall clock; retry and backoff tests use fake time unless explicitly marked real-time.

**Capability gating**
- For every profile, `RootInfo.capabilities` matches the documented bits and does not change for the connection lifetime.
- Negative recorder assertions verify that hosts do not call unsupported SPI methods after checking capabilities.
- Capability-dependent public helpers are tested through host suites, not by adding new plugin methods. Example: a public `materialize` test may use `read-local-delegate`, but the plugin still only implements `Layer::read`.

**Redirect responder**
- Body source slicing is property-tested over offsets and lengths.
- Captured response headers are exactly the whitelist requested by `ResultCapture`.
- Captured response body is bounded by `body_max_bytes`.
- Expired redirects are rejected before the responder observes a request.

**Lifetime and ABI**
- Opaque handles created by the plugin are destroyed exactly once and only after all dependent streams/delegates/futures have completed or been cancelled.
- Borrowed buffers passed over the ABI are not retained by either side after the call that borrowed them.
- Panic/exception containment tests run through the same ABI codecs production plugins use.

**Brokered path parity**
- A direct-mode redirect response and the brokered `RedirectResult` carrying the same responder output translate to byte-for-byte equivalent plugin-facing `RedirectResponse` values.
- Brokered `LocalDelegate` scenarios never expose broker-local paths to the client process.
- Broker-specific scenarios assert broker behavior at the broker boundary, not inside the plugin. The plugin records the same Layer calls it would in Direct mode unless the scenario is explicitly about `Host::is_broker` admissibility.

## Streaming seams

> The canonical reference for **Streaming seams** (the per-seam inventory, the `streaming_invariant` test contract, and the per-seam recorder shapes) lives in [`docs/public/plugin-development/README.md` § Streaming seams](../../docs/public/plugin-development/README.md#streaming-seams).

## Risks

### Production loading of a test plugin

**Status:** defensive-depth

**Concern.** Test plugins exist specifically to inject failures, simulate adversarial responses, and bypass normal authentication paths. A test plugin loaded into a production broker would let any caller who can name it trigger arbitrary failure modes, fabricate bytes, or pose as an authenticated principal — privilege escalation and data-integrity failure rolled into one.

**Why this mitigation is sound.** The plugin's manifest carries a `test_only: true` flag set by `ovstorage_layer_plugin!(backend, TestLayerFactory::default, test_only)`. The host's `allow_test_plugins` setting is false by default; direct loading returns `ErrorCode::PluginRejected`, and directory discovery silently skips the cdylib. The cdylib ships in the release archive so consumer-side host authors can opt in; bundle exclusion is intentionally not a separate defense layer because the host gate makes a default-posture host treat the bundled cdylib as unloadable while preserving downstream conformance testing.

**Alternatives considered and rejected.**

- **Trust operator discipline (no manifest gate).** A single misconfigured deployment is one slip from compromise; a build-time gate is the only honest defense.
- **Rename the test plugin to look obviously test-y (`fake_*`).** Naming convention is not a security boundary; an attacker who can configure plugin paths can name anything.
- **Sign production plugins with a project key.** Adds a key-management problem the project doesn't otherwise have; the manifest flag is the same defense without the operational tail.
- **Run conformance tests in a separate process with no broker access.** Solves part of the problem but doesn't prevent an operator from accidentally loading the test plugin into the real broker; the gate must live at the host load path.

**What this mitigation does NOT cover.**

- A malicious build pipeline that strips the `test_only` flag from the manifest before loading: build-time tampering is outside scope; mitigation is supply-chain hygiene (signed builds, reproducible artifacts), which is the deployment's responsibility.
- A production plugin with a similar name to a test plugin: the project doesn't claim to defend against typo-squatting in plugin paths; operators control the plugin search path.

**Implementor checklist.**

- The function-like macro's optional `, test_only` flag (`ovstorage_layer_plugin!(backend, MyFactory::default, test_only)`) sets `manifest.test_only = true`; the flag is absent by default.
- Production hosts check `manifest.test_only` at every plugin load. Direct loading rejects with `ErrorCode::PluginRejected`; directory discovery skips the cdylib at debug-log level.
- Operators that want the test plugin loaded set `OVSTORAGE_ALLOW_TEST_PLUGINS=1` for the broker; the default-unset path treats the cdylib as silently absent.

**Verification.**

- `dlopen_test_plugin_is_rejected_without_allow_flag` (`../ovstorage-plugin-test-abi/tests/loaded.rs`): direct `load_plugin` against the test cdylib with `allow_test_plugins` off returns `PluginRejected`.
- `bulk_load_skips_test_plugin_without_allow_flag` (`../ovstorage-plugin-test-abi/tests/loaded.rs`): default-posture library builds, copies the test cdylib into a tempdir, and confirms `load_plugins_from_dir` returns `Ok(())` while the direct path on the same file still surfaces `PluginRejected`.
- Conformance test `test_only_flag_compile_time_validated`: a plugin author who tries to set `test_only = false` while still using conformance-only SPI calls fails to compile.
