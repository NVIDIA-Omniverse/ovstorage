Up: [ovstorage-expert](../../SKILL.md)

# Build ovstorage

The storage component is one Cargo workspace under `ovstorage/`, pinned to Rust 1.96.0 by [rust-toolchain.toml](../../../../ovstorage/rust-toolchain.toml). Run `make` targets from `ovstorage/`, or with `make -C ovstorage <target>` from the checkout root ([path migration guide](../../../../MIGRATION.md)). `make help` lists every target.

| Target | Produces or proves |
| --- | --- |
| `make dist` | `ovstorage/dist/`: `ovstorage`, `ovstorage-broker`, `ovstorage-rest` binaries; provider plugins in `dist/plugins/`; the C/C++ source tree in `dist/c-source/` |
| `make dist-wheel` | Release `dist` plus the Python wheel in `dist/wheels/` |
| `make build` | `cargo build --workspace` |
| `make verify` | Non-test gate: formatting, clippy, docs, skills, headers, notices, dependency policy |
| `make test` | Workspace tests, with test plugins staged |
| `make test-python` | Builds the extension into an isolated venv; pytest plus stubtest |
| `make test-integration` | Hermetic application-level suite across bindings |

- The MCP server is not in `dist/`; build it with `cargo build --release -p ovstorage-mcp`.
- C and C++ consumers don't link a prebuilt library: they compile `ovstorage-c-source/` into their own build ([C source README](../../../../ovstorage/ovstorage-c-source/README.md)). `make c-source-examples` builds and runs the tutorials.
- For CLI iteration, `cargo run -p ovstorage-cli` from `ovstorage/ovstorage-core/` with `OVSTORAGE_PLUGIN_DIR` pointing at the already-built `dist/plugins/`.
- Contributors changing storage code follow the [verify-before-merge skill](../../../../ovstorage/skills/ovstorage-contributor-verify-before-merge/SKILL.md): `make verify` after each change, `make test` before merge.

## Feeding the resolver

The resolver compiles against this source: set `OVS_OVSTORAGE_SDK_ROOT=$PWD/ovstorage` from the checkout root, build providers with `make -C ovstorage dist`, then run the resolver's `tools/dependencies/stage_ovstorage_providers.py` helper as shown in the resolver build guide. Prebuilt providers must come from the exact storage version this snapshot pins (see [VERSION.md](../../../../VERSION.md)), because the plugin ABI must match the bundled source. Continue with [resolver/build.md](../resolver/build.md).

Platforms and prebuilt availability: [platform-support.md](../../../../ovstorage/docs/public/platform-support.md). There are no macOS prebuilts; build from source there.
