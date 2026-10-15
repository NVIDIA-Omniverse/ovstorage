Up: [ovstorage-expert](../../SKILL.md)

# Validate the resolver

Report which level a result came from. A no-SDK pass says nothing about the OpenUSD plugin, a loopback HTTP pass is not live-provider evidence, and a skipped CTest is not a pass. Evidence rules: `ovstorage-usd-resolver/.agents/verify-empirically.md`; full steps: [local-verification.md](../../../../ovstorage-usd-resolver/docs/local-verification.md).

## Is it working?

1. **Bridge and configuration:**
   `ovstorage-usd-resolver doctor --stack-config ovstorage.toml --json` should report `ovstorage_bridge_build` and `ovstorage_stack_config` as `ok`. Add `--uri <remote-uri>` to probe one object.
2. **One asset end to end:** `materialize <uri> --out <file> --stack-config ovstorage.toml`, then inspect the file.
3. **Composition:** `trace <uri> --stack-config ovstorage.toml` on a plugin build opens a stage and reports resolver opens and failures.
4. **Tests:** `ctest --test-dir <build> --output-on-failure` at the level you built ([build.md](build.md)). The OpenUSD build runs plugin registration, USDZ, write, embedding-example, and loopback-HTTP stage smokes.

Opt-in live smokes need real endpoints and are enabled by environment variables, for example `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL`, `OVS_USD_RESOLVER_LIVE_S3_STAGE_URL` with `…_REGION`, `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL`, and `OVS_USD_RESOLVER_RUN_LIVE_HF=1`. Select one with `ctest -R live_s3_stage`.

## Diagnose

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ovstorage_bridge_build` is `warning`; exit 3 `ovstorage_unavailable` | Built without the bridge | Reconfigure with `OVS_OVSTORAGE_REQUIRED=ON` and `OVS_OVSTORAGE_SDK_ROOT` |
| `ovstorage_stack_config` error, category `plugin` | Provider library missing or from another storage version | Point `OVSTORAGE_PLUGIN_DIR` at providers built from the pinned storage source |
| Category `route` | The Stack doesn't route that scheme or address | Fix `ovstorage.toml`; check with `ovstorage list-routes` |
| Exit 4 `scheme_not_owned` | Scheme isn't in `OVS_USD_RESOLVER_URI_SCHEMES` | Rebuild with the scheme advertised ([configure.md](configure.md)) |
| Remote paths fall through to the default resolver | Plugin not registered | Set `PXR_PLUGINPATH_NAME`, or call `register_plugin` before OpenUSD starts |
| Undefined USD symbols or crashes at load | Host USD differs from the build SDK | Rebuild against the host's exact SDK ([openusd-version.md](openusd-version.md)) |
| Configure fails on compiler floor | Compiler too old for the C++20 bridge | Use GCC 13+, Clang 17+, or MSVC 19.40+ |
| Windows DLL load failure | SDK directories not on `PATH` | Prepend SDK `lib`, `bin`, `plugin/usd` |

Storage-side failures (auth, NoRoute) are diagnosed with [storage/validate.md](../storage/validate.md). Triage routes: `ovstorage-usd-resolver/.agents/triage.md`.
