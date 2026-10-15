# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ovtasks build-test-plugins`` -- pre-build the cdylib plugins that the
``ovstorage`` test build.rs files would otherwise produce via nested cargo,
and stage the example plugin under ``target/test-plugins/``. Tests pick it up
via ``OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE``.

Goal: avoid the two-level nested-cargo trees that exhaust a hosted CI runner.
Locally, the same path means ``make dist`` + ``make test`` share the plugin
compile instead of doing it twice. With the flattened workspace this is a
single ``cargo build -p ...`` against the one ``target/`` dir."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from _repo import TaskError, dll_filename, eprint, repo_root, run

# Package names to pre-build. All live in the single flat workspace now.
# The ABI-v2 mini Layer cdylib is staged too so the dlopen-backed mixed-layer and
# Stack plugin tests find it in the profile dir; with OVSTORAGE_REQUIRE_TEST_PLUGINS
# set, its absence is a hard error rather than a silent skip.
PLUGINS = (
    # ABI-v2 cdylib export of the conformance backend (the harness crate
    # itself is rlib-only so other plugins' test binaries can link it).
    "ovstorage-plugin-test-abi",
    # Same conformance backend over an instrumented `#[global_allocator]`,
    # dlopened by its own cross-allocator test. `cargo test` builds the test
    # binary but not the cdylib it loads, so it has to be pre-built here.
    "ovstorage-plugin-test-abi-alloc",
    "ovstorage-plugin-test-incompatible-abi",
    "ovstorage-plugin-test-layer",
    "ovstorage-example-plugin-rust",
    # Staged so the Stack plugin tests exercise the real ABI-v2 cdylibs
    # (manifest / thunks / loader / connection bridge), not just an
    # in-process Stack, via OVSTORAGE_HTTP_PLUGIN_SO_OVERRIDE /
    # OVSTORAGE_S3_PLUGIN_SO_OVERRIDE.
    "ovstorage-plugin-core-abi",
    "ovstorage-plugin-cache-abi",
    "ovstorage-plugin-hub-cache-abi",
    "ovstorage-plugin-http-abi",
    "ovstorage-plugin-s3",
    "ovstorage-plugin-azure",
    "ovstorage-plugin-gcs",
    "ovstorage-plugin-huggingface",
    "ovstorage-plugin-opendal",
    "ovstorage-plugin-nucleus",
)

# ABI-v2 cdylibs copied verbatim into the staging dir (lib stem = package name
# with '-'→'_', unlike the example plugin's custom stem).
STAGED_V2_STEMS = (
    "ovstorage_plugin_core",
    "ovstorage_plugin_cache",
    "ovstorage_plugin_hub_cache",
    "ovstorage_plugin_http",
    "ovstorage_plugin_s3",
    "ovstorage_plugin_azure",
    "ovstorage_plugin_gcs",
    "ovstorage_plugin_huggingface",
    "ovstorage_plugin_opendal",
    "ovstorage_plugin_nucleus",
)

EXAMPLE_PLUGIN_PACKAGE = "ovstorage-example-plugin-rust"
EXAMPLE_PLUGIN_STEM = "ovstorage_plugin_example_rust"
STAGING_SUBDIR = "target/test-plugins"

# Manifest of this task's own classification of the workspace's plugin
# cdylibs, written into the staging dir for `plugin_loading.rs` to read. The
# ABI sweep can only judge what reaches `target/debug`, and that is decided
# here -- so the set the sweep is held to has to come from here too, rather
# than being derived independently and drifting.
STAGED_MANIFEST_NAME = "staged-plugins.json"

# Lib stems of every plugin this task builds and uplifts into `target/debug`.
#
# `ovstorage-example-plugin-rust` sets a custom `[lib] name`, so its stem is
# NOT its package name with '-'->'_'; deriving it that way names an artifact
# that never exists.
ABI_PACKAGE_STEMS = {
    "ovstorage-plugin-core-abi": "ovstorage_plugin_core",
    "ovstorage-plugin-cache-abi": "ovstorage_plugin_cache",
    "ovstorage-plugin-hub-cache-abi": "ovstorage_plugin_hub_cache",
    "ovstorage-plugin-http-abi": "ovstorage_plugin_http",
}

BUILT_PLUGIN_STEMS = {
    ABI_PACKAGE_STEMS.get(package, package.replace("-", "_"))
    for package in PLUGINS
    if package != EXAMPLE_PLUGIN_PACKAGE
} | {EXAMPLE_PLUGIN_STEM}

# Workspace `libovstorage_plugin_*` cdylibs this task deliberately does NOT
# stage, and which therefore never reach `target/debug` on the test path.
#
# `cargo build` uplifts a cdylib to the profile root; `cargo test` leaves it in
# `target/debug/deps/` and uplifts nothing. These two are built by nobody here,
# so under `make test-ci` they exist only in `deps/`, where the ABI sweep does
# not look. They are exempt from the sweep's completeness requirement for that
# reason -- not because they are less important.
#
# Also the prune keep-set: pruning must not delete a live artifact left by a
# developer's own `cargo build --workspace`. That cuts both ways -- see
# `_prune_stale_plugin_artifacts` -- because it means a genuinely retired crate
# whose stem is still listed here keeps a stale `.so` alive forever.
OTHER_WORKSPACE_PLUGIN_STEMS = {
    "ovstorage_plugin_broker",
    "ovstorage_plugin_services_client",
}

# A genuine C driver, cc-compiled into a standalone `.so`
# that links nothing from the ovstorage runtime (only `#include`s the ABI-v2
# header). The Python->C matrix leg (test_handoff_matrix.py) `ctypes`-loads it
# `RTLD_LOCAL` and hands it a Python-exported handle.
C_DRIVER_SRC = "ovstorage-core/ovstorage-python/tests/csrc/handoff_c_driver.c"
C_DRIVER_STEM = "ovsx_handoff_c_driver"
PLUGIN_INCLUDE_DIR = "ovstorage-core/ovstorage-plugin/include"

# The FULL pure-C source distribution plus a producer TU
# (`create_exported_stack`), cc-compiled directly (no cargo) into a standalone
# `.so`. Two legs `dlopen`/`ctypes`-load it `RTLD_LOCAL`: the C->Rust test
# (`ovstorage/tests/handoff_c_source.rs`) and the C->Python smoke leg
# (test_handoff_matrix.py). Deliberately not built by the
# `ovstorage-c-source-cc-test` crate: that crate links the pure-C archive,
# and linking it and `ovstorage-plugin`'s rlib into one binary would collide
# on their shared `ovstorage_plugin_*` symbol names.
C_SOURCE_DIR = "ovstorage-c-source"
C_SOURCE_PRODUCER_SRC = "ovstorage-core/ovstorage/tests/csrc/handoff_c_source_producer.c"
C_SOURCE_FIXTURE_STEM = "ovsx_c_source_handoff_fixture"

# The C++ leg of the app-level integration suite: the same FULL pure-C source
# distribution plus `cloud_driver.cpp` (C++20, over `ovstorage.hpp`) in ONE
# standalone `.so`. `ovstorage-integration-tests/tests/cpp.rs` `dlopen`s it
# `RTLD_LOCAL` and hands it a handle exported from the real routed Rust Stack
# -- the Rust->C++ direction of the same handoff the fixture above runs
# C->Rust, and subject to the same "never link this next to
# `ovstorage-plugin`'s rlib" rule.
#
# Built through its own CMakeLists rather than a bare `cc` line like the two
# fixtures above: it has a C99 half and a C++20 half with different flags, and
# it needs the same `check_cxx_source_compiles` floor probe the shipped
# `ovstorage-c-source/CMakeLists.txt.example` uses. One build definition,
# reused by anyone building the driver by hand.
#
# UNIX-ONLY, and deliberately so rather than by oversight: `cloud_driver.cpp`
# exports `ovsx_cloud_driver_run` with no `__declspec(dllexport)`/.def file,
# the CMake target pins the Unix `lib<stem>.so` / `.dylib` artifact name, and
# `tests/cpp.rs` looks for exactly those two names. Windows support means
# changing all three together; until then `_stage_cpp_driver` states the
# absence in as many words (see CPP_DRIVER_WINDOWS_MESSAGE).
CPP_DRIVER_DIR = "ovstorage-integration-tests/tests/cpp"
CPP_DRIVER_STEM = "ovsx_cloud_cpp_driver"
# Reused across runs -- never wiped between invocations, so `make
# build-test-plugins` does not re-run cmake configure + a full C compile of the
# pure-C source set every time it is called (and it gates every test target).
# The CMakeLists is written to suit that: its C++20 probe refuses to cache a
# failure, so a fixed toolchain recovers without anyone deleting this by hand.
CPP_DRIVER_BUILD_SUBDIR = "target/test-plugins-build/cpp-cloud-driver"

# Turns "no cmake / no C++20 compiler / the wrapper stopped compiling" from a
# reported skip into a hard failure. `OVSTORAGE_REQUIRE_CPP20` is the same
# switch `_c_source_examples.py` uses for the shipped C++ example and CI
# already sets it; `OVSTORAGE_REQUIRE_TEST_PLUGINS` is this suite's own
# "the staged artifacts are mandatory" gate, honored by `tests/cpp.rs` too.
REQUIRE_CPP20_ENV = "OVSTORAGE_REQUIRE_CPP20"
REQUIRE_TEST_PLUGINS_ENV = "OVSTORAGE_REQUIRE_TEST_PLUGINS"

# Said out loud on Windows, where the driver is not built at all. Spelling out
# the three coupled reasons matters more than brevity here: without it a
# Windows developer meets this as `tests/cpp.rs` failing to find an artifact
# nothing ever claimed to produce. The "NO coverage" clause is equally
# deliberate -- a leg that does not run on a platform must not be readable as
# a leg that passes there.
CPP_DRIVER_WINDOWS_MESSAGE = (
    "the C++ integration driver is not built on Windows, so the C++ leg of "
    "ovstorage-integration-tests does NOT run there and its cases must not be "
    "read as Windows coverage. Three things are Unix-only and would have to "
    "change together: tests/cpp/cloud_driver.cpp does not export "
    "`ovsx_cloud_driver_run` from an MSVC DLL, tests/cpp/CMakeLists.txt pins "
    "the Unix `lib*.so`/`.dylib` artifact name, and tests/cpp.rs looks for "
    "only those two names"
)


def staged_example_so(root: Path | None = None) -> Path:
    """Resolve the staged path without building (callers may plumb the env
    var before the artifact exists)."""
    root = root or repo_root()
    return root / STAGING_SUBDIR / dll_filename(EXAMPLE_PLUGIN_STEM)


def staged_c_driver_so(root: Path | None = None) -> Path:
    """Resolve the staged path of the C driver `.so`."""
    root = root or repo_root()
    return root / STAGING_SUBDIR / dll_filename(C_DRIVER_STEM)


def staged_c_source_fixture_so(root: Path | None = None) -> Path:
    """Resolve the staged path of the pure-C handoff fixture `.so`."""
    root = root or repo_root()
    return root / STAGING_SUBDIR / dll_filename(C_SOURCE_FIXTURE_STEM)


def staged_cpp_driver_so(root: Path | None = None) -> Path:
    """Resolve the staged path of the C++ integration driver `.so`."""
    root = root or repo_root()
    return root / STAGING_SUBDIR / dll_filename(CPP_DRIVER_STEM)


def _stage_c_driver(root: Path, staging: Path) -> None:
    """Compile the C driver TU into the staging dir with the C compiler.

    Header-only: no runtime linkage, so a bare `cc -fPIC -shared` against the
    ABI-v2 plugin header suffices. `$CC` overrides the compiler for CI images."""
    cc = os.environ.get("CC", "cc")
    dest = staged_c_driver_so(root)
    run(
        [
            cc,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-shared",
            "-I",
            str(root / PLUGIN_INCLUDE_DIR),
            str(root / C_DRIVER_SRC),
            "-o",
            str(dest),
            "-lpthread",
        ],
        cwd=root,
        label="cc (handoff C driver)",
    )
    if not dest.exists():
        raise TaskError(f"expected compiled C driver missing: {dest}")


def _stage_c_source_fixture(root: Path, staging: Path) -> None:
    """Compile the pure-C handoff fixture into the staging dir.

    Links the FULL `ovstorage-c-source/src/*.c` set plus the producer TU into
    one shared object with a bare `cc -fPIC -shared` invocation (mirrors
    `Makefile.example` / the `_c_source_examples.py` embedded-suite build,
    generalized from an executable to a shared library) -- deliberately not
    routed through cargo/`ovstorage-c-source-cc-test`, whose crate links the
    pure-C archive together with `ovstorage-plugin`'s rlib (symbol
    collision)."""
    cc = os.environ.get("CC", "cc")
    source_root = root / C_SOURCE_DIR
    sources = sorted((source_root / "src").glob("*.c"))
    if not sources:
        raise TaskError(f"pure-C source set is empty: {source_root / 'src'}")
    dest = staged_c_source_fixture_so(root)
    run(
        [
            cc,
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-shared",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_XOPEN_SOURCE=700",
            "-D_FILE_OFFSET_BITS=64",
            "-I",
            str(source_root / "include"),
            *[str(path) for path in sources],
            str(root / C_SOURCE_PRODUCER_SRC),
            "-o",
            str(dest),
            "-lpthread",
            "-ldl",
        ],
        cwd=root,
        label="cc (pure-C handoff fixture)",
    )
    if not dest.exists():
        raise TaskError(f"expected compiled pure-C handoff fixture missing: {dest}")


def _cpp_driver_required() -> str | None:
    """The env var demanding the C++ driver, or ``None`` if none is set."""
    for name in (REQUIRE_CPP20_ENV, REQUIRE_TEST_PLUGINS_ENV):
        if os.environ.get(name) == "1":
            return name
    return None


def _stage_cpp_driver(root: Path, staging: Path) -> None:
    """Build the C++ integration driver into the staging dir via CMake.

    Unlike the two fixtures above there is no `cc` line here: the build
    definition lives in `ovstorage-integration-tests/tests/cpp/CMakeLists.txt`
    and this only drives it, so the flags a consumer building the driver by
    hand uses are the flags CI uses.

    A missing `cmake`, a C++ compiler below the documented C++20 floor, a
    wrapper that stopped compiling, or a Windows host (where the driver is not
    built at all) all land in the same place: the artifact is absent, and this
    reports that LOUDLY and keeps going, because `build-test-plugins` gates
    every other test target and hard-failing here would take the Rust and
    Python legs down over a C++ toolchain. Absence is not silent on either
    side -- `tests/cpp.rs` prints a skip line per case -- and either gate in
    `_cpp_driver_required` turns it into a hard error for a runner that is
    known to clear the floor.

    Each cause names ITSELF. A Windows host is not a toolchain problem and is
    not fixed by installing anything, so it does not get to hide behind the
    C++20-floor message."""
    required = _cpp_driver_required()
    dest = staged_cpp_driver_so(root)
    if sys.platform == "win32":
        # Reached rather than skipped by the caller's platform guard, so that
        # the require-gates still bite here: a Windows CI asking for the C++
        # leg gets told the leg does not exist on Windows, at the step that
        # would have built it, instead of an unexplained missing artifact
        # later in `tests/cpp.rs`.
        if required is not None:
            raise TaskError(
                f"{required}=1 but {CPP_DRIVER_WINDOWS_MESSAGE}. Either leave "
                f"{required} unset on Windows runners or implement the DLL "
                "export, staging and lookup together"
            )
        eprint(f"NOTE: {CPP_DRIVER_WINDOWS_MESSAGE}")
        return
    if shutil.which("cmake") is None:
        message = (
            "cmake is not installed or not on PATH, so the C++ leg of "
            "ovstorage-integration-tests will skip. Install with: "
            "sudo apt-get install cmake"
        )
        if required is not None:
            raise TaskError(f"{required}=1 but {message}")
        eprint(f"NOTE: {message}")
        return

    build_dir = root / CPP_DRIVER_BUILD_SUBDIR
    build_dir.mkdir(parents=True, exist_ok=True)
    configure_and_build = (
        [
            "cmake",
            "-S",
            str(root / CPP_DRIVER_DIR),
            "-B",
            str(build_dir),
            f"-DOVSTORAGE_DRIVER_OUTPUT_DIR={staging}",
        ],
        ["cmake", "--build", str(build_dir)],
    )
    try:
        for args in configure_and_build:
            run(args, cwd=root, label="cmake (C++ integration driver)")
    except TaskError as error:
        if required is not None:
            raise
        eprint(f"NOTE: {error}; the C++ leg of ovstorage-integration-tests will skip")
        return

    if not dest.exists():
        # CMake succeeded but emitted no target: the C++20 wrapper probe in
        # the CMakeLists failed, which it reports as a configure-time WARNING
        # rather than an error so the rest of staging survives.
        message = (
            f"expected C++ integration driver missing: {dest}. The C++20 wrapper "
            "probe most likely failed -- the wrapper needs GCC 13+, Clang 17+ or "
            f"MSVC 19.40+; see {build_dir}/CMakeFiles/CMakeError.log. The probe "
            "does not cache a failure, so installing a newer compiler (or fixing "
            "the header) and re-running this is enough to bring the driver back; "
            f"`rm -rf {build_dir}` is the escape hatch for everything else, since "
            "that directory is otherwise reused across runs"
        )
        if required is not None:
            raise TaskError(f"{required}=1 but {message}")
        eprint(f"NOTE: {message}")


def _prune_stale_plugin_artifacts(root: Path) -> None:
    """Remove profile cdylibs left behind by renamed or deleted plugins.

    The keep-set is every workspace `libovstorage_plugin_*` cdylib -- the ones
    this task pre-builds plus the broker / services-client plugins built by
    their own crates into the shared `target/debug` -- so pruning only reaches
    genuinely retired stems, never a live sibling artifact."""
    profile_dir = root / "target" / "debug"
    keep_filenames = {
        dll_filename(stem)
        for stem in BUILT_PLUGIN_STEMS | OTHER_WORKSPACE_PLUGIN_STEMS
    }
    plugin_prefix = "ovstorage_plugin_" if sys.platform == "win32" else "libovstorage_plugin_"
    for artifact in profile_dir.iterdir():
        if not artifact.is_file() or artifact.name in keep_filenames:
            continue
        if artifact.name.startswith(plugin_prefix) and artifact.suffix in {
            ".dll",
            ".dylib",
            ".so",
        }:
            artifact.unlink()


def _write_staged_manifest(staging: Path) -> None:
    """Record which workspace plugin cdylibs this task stages, and which it
    deliberately does not.

    `plugin_loading.rs` reads this to decide what its ABI sweep must have
    covered. Emitting it rather than letting the test hardcode a list keeps a
    newly added plugin covered by default: a stem absent from BOTH lists is
    classified by nobody, and the test says so instead of quietly not
    requiring it."""

    manifest = {
        "staged": sorted(BUILT_PLUGIN_STEMS),
        "unstaged_by_design": sorted(OTHER_WORKSPACE_PLUGIN_STEMS),
    }
    (staging / STAGED_MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def stage() -> Path:
    root = repo_root()
    # One cargo invocation builds every plugin; deps resolve once and the
    # single workspace target/ holds the artifacts.
    args = ["cargo", "build"]
    for pkg in PLUGINS:
        args += ["-p", pkg]
    run(args, cwd=root, label="cargo build (test plugins)")
    _prune_stale_plugin_artifacts(root)

    # (Re)create the staging dir so a renamed plugin doesn't leave a stale .so.
    staging = root / STAGING_SUBDIR
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    _write_staged_manifest(staging)

    example_src = root / "target" / "debug" / dll_filename(EXAMPLE_PLUGIN_STEM)
    dest = staged_example_so(root)
    if not example_src.exists():
        raise TaskError(f"expected built plugin missing: {example_src}")
    shutil.copy2(example_src, dest)
    # Stage the ABI-v2 cdylibs so the Stack plugin tests can dlopen the real
    # plugins via their OVSTORAGE_*_PLUGIN_SO_OVERRIDE env vars.
    for stem in STAGED_V2_STEMS:
        so_name = dll_filename(stem)
        src = root / "target" / "debug" / so_name
        if not src.exists():
            raise TaskError(f"expected built plugin missing: {src}")
        shutil.copy2(src, staging / so_name)
    # The two C fixtures below shell out to `cc` with POSIX-only sources
    # (`pthread.h`, `RTLD_LOCAL` consumers), so skip them on Windows the same
    # way their unix-only handoff-test consumers already do (`#[cfg(unix)]`,
    # pytest skip fixtures). Everything the Windows-capable tests need was
    # already built by the cargo step above; hard-failing here would abort
    # `make build-test-plugins` (and every target depending on it) on Windows.
    if sys.platform != "win32":
        # Compile the C driver into the staging dir (header-only, no
        # runtime linkage); the Python->C matrix leg ctypes-loads it.
        _stage_c_driver(root, staging)
        # Compile the pure-C handoff fixture (full src set + producer
        # TU); the C->Rust and C->Python matrix legs dlopen/ctypes-load it.
        _stage_c_source_fixture(root, staging)
    # Build the C++ integration driver (full src set + cloud_driver.cpp over
    # the C++20 wrapper); the C++ leg of ovstorage-integration-tests dlopens it
    # and hands it a Rust-exported Stack handle.
    #
    # Called on Windows too, outside the guard above, even though it cannot
    # build there. Its consumers are not `#[cfg(unix)]` -- `tests/cpp.rs` runs
    # on every platform and just fails to find the artifact -- so unlike the
    # two fixtures, dropping this one on the floor silently would leave a
    # Windows developer with an unexplained missing `.so` and CI's require
    # gates quietly satisfied. It states the platform limit itself instead.
    _stage_cpp_driver(root, staging)
    return dest


def run_cmd() -> None:
    dest = stage()
    print(f"OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE={dest}")
