Up: [ovstorage-expert](../../SKILL.md)

# Link against a different OpenUSD SDK

The resolver binary is bound to one exact SDK build. Today that is NVIDIA Kit OpenUSD nopy monolithic `0.25.11.kit.4-gl.21081`. `PXR_VERSION 2511` alone does not identify it, and another 25.11 build (including `usd-core`) is not ABI interchangeable. Any other SDK is **unqualified** until it passes the full validation below ([compatibility matrix](../../../../ovstorage-usd-resolver/docs/compatibility-matrix.md)).

## First, classify the target

| Target | Effort |
| --- | --- |
| Another Kit OpenUSD **monolithic** build of 25.11 | Re-pin the acquisition and receipts (steps 1, 4–6) |
| A Kit monolithic build of **another USD release** | All steps below |
| Stock or non-monolithic OpenUSD (your own build, `usd-core`) | A new CMake integration: `cmake/NvidiaKitUsd.cmake` assumes the Kit layout (`usd_m` target, `ov_<ver>usd_ms` library, SDK-supplied TBB, Alembic, draco, OpenSubdiv, Imath). Treat it as resolver development ([modify.md](modify.md)) and revisit the USD-flavour decision |

These are development changes, not a supported SDK-path override. Current
CMake hardcodes Kit 25.11 monolithic discovery and dependencies; changing only
the version checks can leave linking or runtime behavior broken. Without
`.ovs-openusd-sdk.json`, a plugin build warns that provenance is not recorded;
the optional local wheel build refuses outright. No resolver wheels are
published for this release.

## Every place the version is pinned

1. **Acquisition** — `tools/dependencies/acquire_openusd_sdk.py`: `PACKAGE_VERSION`, the per-platform `PACKAGES` SHA-256 values, the download URL pattern, and `_validate_sdk()`'s expected files.
2. **Library name** — `ov_25.11usd_ms` appears in `cmake/NvidiaKitUsd.cmake`, `python/ovstorage_usd_resolver/__init__.py`, `tests/python/test_installed.py`, and `tools/dependencies/tests/test_acquire_openusd_sdk.py`.
3. **Configure checks** — `cmake/NvidiaKitUsd.cmake`: the `PXR_VERSION` equality check (`2511`) and the required `usd_m` target.
4. **Wheel receipt** — `cmake/InstallWheel.cmake`: the accepted receipt `version` and package-name pattern.
5. **Wheel identity** — `pyproject.toml`: distribution name `ovstorage-usd-resolver-kit-25-11` and description. Rename it for a new flavour, since different flavours must not co-install.
6. **Defaults and docs** — the `OVS_USD_SDK_ROOT` description in `CMakeLists.txt`; `.deps/openusd/<version>` paths in [local-verification.md](../../../../ovstorage-usd-resolver/docs/local-verification.md), [python-wheels.md](../../../../ovstorage-usd-resolver/docs/python-wheels.md), the embedding example README, the resolver README, `CHANGELOG.md`, and the compatibility matrix tables.

The native package records the built USD library hash automatically, but its
exported SDK discovery and consumer checks must also work with the new layout.
Do not assume it needs no changes for another SDK family.

Search for leftovers before testing:

```sh
cd ovstorage-usd-resolver && rg -n '25\.11|25-11|2511|kit\.4-gl' .
```

## Prove it

1. Acquire the new SDK, then configure the OpenUSD build level ([build.md](build.md)) and run `ctest --output-on-failure`. Every OpenUSD smoke must run and pass, not skip.
2. Run the embedding example and `trace` against a real remote stage ([validate.md](validate.md)).
3. If exercising the optional local Python package, build and install it into a clean environment and run `tests/python/test_installed.py` against the new SDK.
4. Repeat on each platform you claim, and update the compatibility matrix with the evidence. Without that evidence, describe the result as unqualified.

Mismatches show up as configure errors from `NvidiaKitUsd.cmake`, undefined `pxr` or TBB symbols at load time, or crashes inside OpenUSD. All of them mean the host and build SDKs differ.
