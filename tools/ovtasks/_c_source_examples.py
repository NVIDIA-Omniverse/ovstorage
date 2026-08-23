# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks shared by the pure-C source-distribution example gate."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from _repo import (
    TaskError,
    exe_filename,
    repo_root,
    require_tool,
    run as run_command,
)

_C_SOURCE_DIR = Path("ovstorage-c-source")
_HEADER = Path("ovstorage-c-source/include/ovstorage.h")
_PLUGIN_HEADER = Path("ovstorage-c-source/include/ovstorage_plugin.h")
# The defaults header ships the request-release entry points a declining slot
# calls. It is hand-authored rather than cbindgen-generated, so nothing else
# pins its symbols: without this table a declaration could lose its definition
# and only a third-party author would find out, at link time.
_DEFAULTS_HEADER = Path("ovstorage-c-source/include/ovstorage_defaults.h")
_COMPLETENESS_TU = Path(
    "ovstorage-core/ovstorage-c-source-cc-test/completeness.c"
)
_CODE_DIRECTORIES = ("src", "include", "examples")
_EXAMPLE_BUILD_FILES = ("Makefile.example", "CMakeLists.txt.example")
_C_EXAMPLE_BINARIES = ("c_roundtrip",)
# Built only where the toolchain clears the documented C++20 floor; both
# shipped build files skip it below that, so this gate must too.
_CXX_EXAMPLE_BINARIES = (
    "cpp20_roundtrip",
    "tutorial_01_file",
    "tutorial_02_object_operations",
    "tutorial_06_native_layer",
)
# Set in CI, where the toolchain is known to clear the floor. Turns the skip
# into a hard failure so the C++ leg cannot silently self-disable when a
# runner image changes or the wrapper stops compiling.
_REQUIRE_CPP20_ENV = "OVSTORAGE_REQUIRE_CPP20"
# Multi-config CMake generators (Visual Studio, Xcode) place binaries in a
# per-configuration subdirectory of the build tree.
_CMAKE_BUILD_CONFIG = "Release"

# Include the library name and its conventional C header/API prefix.  In
# particular, ``#include <curl/curl.h>`` must trip the libcurl guard even
# though the literal string "libcurl" is absent.  This is intentionally a
# grep-style substring check so linker flags such as ``-lcurl`` also fail.
_FORBIDDEN_DEPENDENCY = re.compile(
    r"(?:tokio|(?:lib)?curl|openssl|hyper)",
    re.IGNORECASE,
)

# cbindgen emits every public declaration with its return type and function
# name on the first line, at column zero even inside its `extern "C"`
# cpp_compat guards.  Anchoring at column zero excludes API names in comments
# and the negative lookahead excludes callback typedefs.
_HEADER_FUNCTION = re.compile(
    r"^(?!typedef\b)[A-Za-z_][A-Za-z0-9_ \t*]*\b"
    r"(ovstorage_[A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)

# The plugin header's host-facing helpers all share the ovstorage_plugin_
# prefix, which keeps them disjoint from the ovstorage.h application API
# (ovstorage.h's own ovstorage_plugin_destroy stays in the first table).
_PLUGIN_HEADER_FUNCTION = re.compile(
    r"^(?!typedef\b)[A-Za-z_][A-Za-z0-9_ \t*]*\b"
    r"(ovstorage_plugin_[A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)

# Count only entries in the mechanically maintained tables.  In particular,
# do not count API names in the explanatory comments or macro definitions.
_COMPLETENESS_REFERENCE = re.compile(
    r"^\s*OVSTORAGE_API_REF\((ovstorage_[A-Za-z0-9_]+)\),\s*$",
    re.MULTILINE,
)

_PLUGIN_COMPLETENESS_REFERENCE = re.compile(
    r"^\s*OVSTORAGE_PLUGIN_API_REF\((ovstorage_plugin_[A-Za-z0-9_]+)\),\s*$",
    re.MULTILINE,
)

_DEFAULTS_COMPLETENESS_REFERENCE = re.compile(
    r"^\s*OVSTORAGE_DEFAULTS_API_REF\((ovstorage_plugin_[A-Za-z0-9_]+)\),\s*$",
    re.MULTILINE,
)


def _read(path: Path, description: str) -> str:
    if not path.is_file():
        raise TaskError(f"{description} is missing: {path}")
    return path.read_text(encoding="utf-8")


def _duplicates(symbols: list[str]) -> list[str]:
    return sorted(symbol for symbol, count in Counter(symbols).items() if count > 1)


def _format_symbols(label: str, symbols: list[str]) -> str:
    if not symbols:
        return ""
    return f" {label}: {', '.join(symbols)}."


def _verify_one_completeness_table(
    completeness_text: str,
    header: Path,
    header_text: str,
    header_function: re.Pattern[str],
    table_reference: re.Pattern[str],
    surface: str,
) -> int:
    header_symbols = header_function.findall(header_text)
    referenced_symbols = table_reference.findall(completeness_text)

    header_duplicates = _duplicates(header_symbols)
    reference_duplicates = _duplicates(referenced_symbols)
    missing = sorted(set(header_symbols) - set(referenced_symbols))
    extra = sorted(set(referenced_symbols) - set(header_symbols))

    if (
        len(header_symbols) != len(referenced_symbols)
        or header_duplicates
        or reference_duplicates
        or missing
        or extra
    ):
        details = "".join(
            (
                _format_symbols("missing references", missing),
                _format_symbols("extra references", extra),
                _format_symbols("duplicate header declarations", header_duplicates),
                _format_symbols("duplicate table references", reference_duplicates),
            )
        )
        raise TaskError(
            f"pure-C {surface} link-completeness table is stale: "
            f"{header} declares {len(header_symbols)} functions, but "
            f"{_COMPLETENESS_TU} references {len(referenced_symbols)}."
            f"{details} Regenerate {_COMPLETENESS_TU} from {header} and "
            "rerun the C source examples gate."
        )

    print(
        f"pure-C {surface} link-completeness table is current: "
        f"{len(header_symbols)} functions",
        flush=True,
    )
    return len(header_symbols)


def verify_completeness_table(root: Path | None = None) -> int:
    """Verify that ``completeness.c`` references every frozen C API symbol.

    Both distribution surfaces are checked: the ovstorage.h application API
    (the ``OVSTORAGE_API_REF`` table) and the ovstorage_plugin.h host-facing
    helper API (the ``OVSTORAGE_PLUGIN_API_REF`` table, implemented by
    ``src/plugin_values.c``).  Returns the total checked symbol count for
    callers that want to report it.
    """

    root = repo_root() if root is None else root
    completeness_text = _read(
        root / _COMPLETENESS_TU, "C API link-completeness translation unit"
    )
    application_count = _verify_one_completeness_table(
        completeness_text,
        _HEADER,
        _read(root / _HEADER, "copied ovstorage C header"),
        _HEADER_FUNCTION,
        _COMPLETENESS_REFERENCE,
        "API",
    )
    plugin_count = _verify_one_completeness_table(
        completeness_text,
        _PLUGIN_HEADER,
        _read(root / _PLUGIN_HEADER, "copied ovstorage plugin C header"),
        _PLUGIN_HEADER_FUNCTION,
        _PLUGIN_COMPLETENESS_REFERENCE,
        "plugin API",
    )
    defaults_count = _verify_one_completeness_table(
        completeness_text,
        _DEFAULTS_HEADER,
        _read(root / _DEFAULTS_HEADER, "copied ovstorage defaults C header"),
        _PLUGIN_HEADER_FUNCTION,
        _DEFAULTS_COMPLETENESS_REFERENCE,
        "defaults API",
    )
    return application_count + plugin_count + defaults_count


def _dependency_guard_paths(root: Path) -> list[Path]:
    source_root = root / _C_SOURCE_DIR
    paths: list[Path] = []

    for directory_name in _CODE_DIRECTORIES:
        directory = source_root / directory_name
        if not directory.is_dir():
            raise TaskError(f"pure-C source directory is missing: {directory}")
        paths.extend(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix.lower() != ".md"
        )

    paths.extend(source_root / name for name in _EXAMPLE_BUILD_FILES)
    return sorted(paths)


def verify_dependency_purity(root: Path | None = None) -> int:
    """Reject heavyweight runtime/network dependencies in source inputs.

    Markdown is deliberately outside the scanned file set so the public
    README can document the dependency policy without failing the policy.
    Returns the number of checked files for focused tests and reporting.
    """

    root = repo_root() if root is None else root
    paths = _dependency_guard_paths(root)
    findings: list[str] = []

    for path in paths:
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(
            _read(path, "pure-C source or example build input").splitlines(),
            start=1,
        ):
            for match in _FORBIDDEN_DEPENDENCY.finditer(line):
                token = match.group(0).lower()
                dependency = "libcurl" if token in {"curl", "libcurl"} else token
                findings.append(f"{relative}:{line_number}: {dependency}")

    if findings:
        raise TaskError(
            "pure-C dependency guard found forbidden references:\n"
            + "\n".join(findings)
        )

    print(
        f"pure-C dependency guard passed: {len(paths)} source/build files",
        flush=True,
    )
    return len(paths)


def _find_built_binary(build_dir: Path, stem: str) -> Path | None:
    """Probe the build root and the multi-config subdirectory for a binary."""

    for candidate_dir in (build_dir, build_dir / _CMAKE_BUILD_CONFIG):
        candidate = candidate_dir / exe_filename(stem)
        if candidate.is_file():
            return candidate
    return None


def _cxx20_probe_error(source_root: Path, temporary_root: Path) -> str | None:
    """Compile `#include "ovstorage.hpp"` and return diagnostics on failure.

    The same probe both shipped build files run, for the same reason: a
    narrower coroutine check passes on compilers that then reject the header.
    Running it here lets this gate tell "the toolchain is below the floor,
    and both build systems correctly skipped the C++ example" apart from
    "the C++ example failed to build", which are the same missing file.
    """

    probe_source = temporary_root / "cxx20_probe.cpp"
    probe_source.write_text('#include "ovstorage.hpp"\n', encoding="utf-8")
    if sys.platform == "win32":
        command = [
            os.environ.get("CXX", "cl"),
            "/nologo",
            "/std:c++20",
            "/EHsc",
            f"/I{source_root / 'include'}",
            "/c",
            str(probe_source),
            f"/Fo{temporary_root / 'cxx20_probe.obj'}",
        ]
    else:
        command = [
            os.environ.get("CXX", "c++"),
            "-std=c++20",
            f"-I{source_root / 'include'}",
            "-c",
            str(probe_source),
            "-o",
            str(temporary_root / "cxx20_probe.o"),
        ]
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
    )
    if completed.returncode == 0:
        return None
    return completed.stderr.decode("utf-8", "replace").strip() or "(no output)"


def _expected_example_binaries(cxx20_error: str | None) -> tuple[str, ...]:
    if cxx20_error is None:
        return (*_C_EXAMPLE_BINARIES, *_CXX_EXAMPLE_BINARIES)
    if os.environ.get(_REQUIRE_CPP20_ENV) == "1":
        raise TaskError(
            f"{_REQUIRE_CPP20_ENV}=1 but this toolchain cannot compile the "
            "shipped C++20 wrapper `ovstorage.hpp` (floor: GCC 13+, "
            f"Clang 17+, MSVC 19.40+):\n{cxx20_error}"
        )
    print(
        "skipping the C++ example: this toolchain cannot compile "
        f"include/ovstorage.hpp (floor: GCC 13+, Clang 17+, MSVC 19.40+):\n"
        f"{cxx20_error}",
        flush=True,
    )
    return _C_EXAMPLE_BINARIES


def _run_example_binaries(
    build_dir: Path, build_system: str, expected: tuple[str, ...]
) -> None:
    for stem in expected:
        executable = _find_built_binary(build_dir, stem)
        if executable is None:
            raise TaskError(
                f"{build_system} did not produce expected example: "
                f"{build_dir / exe_filename(stem)}"
            )
        run_command(
            [str(executable)],
            cwd=executable.parent,
            label=f"{build_system} {stem} example",
        )


def _build_with_make(
    source_root: Path, temporary_root: Path, expected: tuple[str, ...]
) -> None:
    # A build directory whose name contains a SPACE, deliberately.
    #
    # Makefile.example carries a three-way escaping scheme for this --
    # `BUILD_DIR_ESC` for rule heads, individually-quoted word lists for
    # recipes, and link rules that name their inputs explicitly because `$^`
    # would be ambiguous -- and none of it was exercised by any gate. It
    # rests on non-obvious GNU make behaviour, so an unspaced build dir
    # leaves a scheme nobody checks, and a consumer under
    # `C:\Users\Some Name\` or `~/My Projects/` is the one who finds out.
    #
    # Before the escaping landed this same path failed with
    # `[: ...: unexpected operator` and `mixed implicit and normal rules`.
    build_dir = temporary_root / "make build"
    print(
        f"building pure-C examples with Makefile.example in {build_dir}",
        flush=True,
    )
    run_command(
        [
            "make",
            "-f",
            "Makefile.example",
            f"BUILD_DIR={build_dir}",
            "examples",
        ],
        cwd=source_root,
        label="Makefile.example build",
    )
    _run_example_binaries(build_dir, "Makefile.example", expected)


def _stage_cmake_source(source_root: Path, temporary_root: Path) -> Path:
    """Stage the alternate-name CMake example as a conventional source tree."""

    staged_source = temporary_root / "cmake-source"
    staged_source.mkdir()
    for directory_name in _CODE_DIRECTORIES:
        source_directory = source_root / directory_name
        if not source_directory.is_dir():
            raise TaskError(f"pure-C source directory is missing: {source_directory}")
        shutil.copytree(source_directory, staged_source / directory_name)

    example = source_root / "CMakeLists.txt.example"
    if not example.is_file():
        raise TaskError(f"CMake example is missing: {example}")
    shutil.copyfile(example, staged_source / "CMakeLists.txt")
    return staged_source


def _build_with_cmake(
    source_root: Path, temporary_root: Path, expected: tuple[str, ...]
) -> None:
    staged_source = _stage_cmake_source(source_root, temporary_root)
    build_dir = temporary_root / "cmake-build"
    print(
        f"building pure-C examples with CMakeLists.txt.example in {build_dir}",
        flush=True,
    )
    run_command(
        ["cmake", "-S", str(staged_source), "-B", str(build_dir)],
        label="CMakeLists.txt.example configure",
    )
    run_command(
        [
            "cmake",
            "--build",
            str(build_dir),
            "--parallel",
            # Single-config generators ignore --config; multi-config
            # generators (Visual Studio, Xcode) require it to match the
            # per-configuration directory probed by _find_built_binary.
            "--config",
            _CMAKE_BUILD_CONFIG,
        ],
        label="CMakeLists.txt.example build",
    )
    _run_example_binaries(build_dir, "CMakeLists.txt.example", expected)


def build_and_run_examples(root: Path | None = None) -> None:
    """Build the source set twice and execute every example from each build.

    On win32 only the CMake leg runs because Makefile.example uses GNU make,
    a POSIX shell, and cc-style flags.
    """

    root = repo_root() if root is None else root
    source_root = root / _C_SOURCE_DIR
    require_tool("cmake", "sudo apt-get install cmake")
    if sys.platform != "win32":
        require_tool("make", "sudo apt-get install make")

    with tempfile.TemporaryDirectory(
        prefix="ovstorage-c-source-examples-"
    ) as temporary:
        temporary_root = Path(temporary)
        expected = _expected_example_binaries(
            _cxx20_probe_error(source_root, temporary_root)
        )
        if sys.platform == "win32":
            print(
                "skipping the POSIX-only Makefile.example build on win32",
                flush=True,
            )
        else:
            _build_with_make(source_root, temporary_root, expected)
        _build_with_cmake(source_root, temporary_root, expected)


# Every embedded *_TEST_MAIN suite compiled by the gate, in source order.
_EMBEDDED_SUITE_MODULES = (
    "dispatch",
    "streams",
    "stack",
    "runtime",
    "registry",
    "host_callbacks",
    "file_backend",
    "values_conn",
    "temp_dir",
)

# Some *_TEST_MAIN blocks define their own stub of a production symbol so
# the suite can observe calls into it; the translation unit shipping the
# production definition must then stay out of that suite's link.
_EMBEDDED_SUITE_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    # stack.c's suite stubs ovstorage_c_register_builtin_kinds, whose
    # production definition lives in file_backend.c.
    "stack": ("file_backend.c",),
    # registry.c's suite stubs ovstorage_c_register_builtin_kinds too.
    "registry": ("file_backend.c",),
    # file_backend.c's suite stubs ovc_registry_register_builtin_kinds's
    # host half and deliberately links no registry, Stack builder, or
    # dispatcher (registry.c owns ovc_registry_register_builtin_kind, and
    # stack.c/dispatch.c would then reference the excluded registry).
    "file_backend": ("registry.c", "stack.c", "dispatch.c"),
}


def build_and_run_embedded_suites(root: Path | None = None) -> None:
    """Build and run every platform-applicable per-module ``*_TEST_MAIN`` suite.

    Each suite compiles the whole ``src/`` set with ``-DOVC_<M>_TEST_MAIN``
    minus that suite's exclusions, links it as an executable, and runs it.
    Assertions stay enabled (never pass ``-DNDEBUG``); the suites' own
    ``#error`` guards reject an NDEBUG build.
    """

    root = repo_root() if root is None else root
    source_root = root / _C_SOURCE_DIR
    compiler = "cl" if sys.platform == "win32" else "cc"
    require_tool(compiler, f"install a C toolchain providing {compiler}")
    sources = sorted((source_root / "src").glob("*.c"))
    if not sources:
        raise TaskError(f"pure-C source set is empty: {source_root / 'src'}")

    with tempfile.TemporaryDirectory(
        prefix="ovstorage-c-source-test-mains-"
    ) as temporary:
        temporary_root = Path(temporary)
        suites_run = 0
        for module in _EMBEDDED_SUITE_MODULES:
            excluded = set(_EMBEDDED_SUITE_EXCLUSIONS.get(module, ()))
            suite_sources = [
                str(path) for path in sources if path.name not in excluded
            ]
            executable = temporary_root / exe_filename(f"{module}_test_main")
            print(
                f"building the {module} *_TEST_MAIN suite in {executable}",
                flush=True,
            )
            if sys.platform == "win32":
                command = [
                    compiler,
                    "/nologo",
                    "/std:c11",
                    "/W4",
                    "/WX",
                    f"/I{source_root / 'include'}",
                    f"/DOVC_{module.upper()}_TEST_MAIN",
                    *suite_sources,
                    f"/Fe:{executable}",
                ]
            else:
                command = [
                    compiler,
                    "-std=c99",
                    f"-I{source_root / 'include'}",
                    f"-DOVC_{module.upper()}_TEST_MAIN",
                    *suite_sources,
                    "-o",
                    str(executable),
                    "-lpthread",
                    "-ldl",
                ]
            run_command(
                command,
                # cl writes objects relative to the working directory, so build
                # from the scratch tree rather than wherever the gate was run.
                cwd=temporary_root,
                label=f"{module} *_TEST_MAIN build",
            )
            run_command(
                [str(executable)],
                cwd=temporary_root,
                label=f"{module} *_TEST_MAIN suite",
            )
            suites_run += 1
    print(
        f"embedded *_TEST_MAIN suites passed: {suites_run}",
        flush=True,
    )


# Inputs of the sanitizer contract leg.  The driver TU provides main() and
# calls the contract entry points defined by the cc-test's streams and
# handoff TUs; it deliberately lives at the crate root next to
# completeness.c so build.rs never compiles it into the Rust test binary.
_LEAK_CONTRACT_DRIVER = Path(
    "ovstorage-core/ovstorage-c-source-cc-test/leak_contracts_main.c"
)
_LEAK_CONTRACT_TUS = (
    Path("ovstorage-core/ovstorage-c-source-cc-test/tests/cc/streams_c.c"),
    Path("ovstorage-core/ovstorage-c-source-cc-test/tests/cc/handoff_c.c"),
    Path("ovstorage-core/ovstorage-c-source-cc-test/tests/cc/declined_release_c.c"),
)
_LEAK_SANITIZER_FLAGS = ("-fsanitize=address,leak", "-fno-omit-frame-pointer")
_CRT_LEAK_PROBE = Path(
    "ovstorage-core/ovstorage-c-source-cc-test/tests/cc/crt_leak_probe.c"
)
_CRT_DEBUG_FLAGS = ("/MDd", "/Zi")


# A leak LeakSanitizer cannot miss.
#
# The hard part is REACHABILITY, not liveness. LSan scans globals, registers
# and thread stacks as roots (`use_globals=1`), so a block still pointed at by
# any of them is correctly not a leak. A self-check that parks the pointer in a
# global — the obvious way to stop the optimiser eliding the allocation —
# therefore reports "LeakSanitizer is broken" on a perfectly good toolchain,
# because LSan is right and the check asked the wrong question. `volatile`
# addresses only the optimiser; it says nothing about reachability.
#
# So: allocate in a function that has RETURNED by scan time, hide each
# pointer's value from the optimiser with a barrier rather than by storing it
# somewhere scannable, drop the reference, and overwrite the frame that held it.
#
# MANY blocks rather than one, which is load-bearing and is the calibration
# this probe has already got wrong twice. A stale copy of the most recent
# pointer routinely survives in a callee-saved register or an unscrubbed stack
# slot, and LSan is then RIGHT to call that block reachable. With a single
# allocation that one stale root hides the whole leak, and this probe disables
# the entire leak-contracts leg on a host where LSan works perfectly.
#
# The probe as shipped leaks LEAK_BLOCKS x LEAK_BLOCK_BYTES = 64 blocks of
# 1 KiB. The superseded version leaked one 64 KiB block; measured on x86-64
# Linux with gcc 11.4 and gcc 12.3, that one block reports nothing and exits 0,
# two report exactly one of the two, and 64 report all 64. Whether the same
# holds on other compilers or platforms is untested -- the point is only that
# block count, not total bytes, is what moved this probe from silent to
# reporting on every toolchain measured.
#
# Kept in step with the cc-test crate's copy of this self-check
# (`ovstorage-core/ovstorage-c-source-cc-test/build.rs`, LEAK_SELF_CHECK_SOURCE):
# the two drivers are separate programs, so each carries its own. A
# recalibration here -- which the maintainer note below actively invites -- is
# a recalibration there too, or the two silently diverge on how hard they try
# to make a leak visible.
#
# Maintainer note: if a future toolchain reports nothing here, raise
# `LEAK_BLOCKS` before suspecting the sanitizer — more blocks means more that
# cannot all be pinned by the handful of stale roots a return path leaves
# behind. `LEAK_BLOCK_BYTES` is incidental (any size a stale register can point
# at will do); `scratch[4096]` need only exceed the frame `leak_blocks` used,
# so it too has slack. Only after raising the count and still seeing silence is
# "this LeakSanitizer does not work" the right conclusion.
# Interpolated into the source below rather than written inline, so the
# diagnostic can quote the real count instead of a copy that drifts the moment
# anyone raises it.
_LEAK_SELF_CHECK_BLOCKS = 64
_LEAK_SELF_CHECK_BLOCK_BYTES = 1024

_LEAK_SELF_CHECK_BODY = """\
#include <stddef.h>
#include <stdlib.h>

__attribute__((noinline)) static void leak_blocks(void)
{
    int index;

    for (index = 0; index < LEAK_BLOCKS; ++index) {
        void *block = malloc(LEAK_BLOCK_BYTES);
        if (block == NULL) {
            abort();
        }
        /* Touch it, and hide its value, so the allocation cannot be elided or
           demoted to a stack object. Neither keeps it reachable. */
        *(volatile char *)block = 1;
        __asm__ volatile("" : : "r"(block) : "memory");
        block = NULL;
        (void)block;
    }
}

/* Overwrite the frame `leak_blocks` used, so no stale copy of a pointer
   survives in stack memory LeakSanitizer scans as a root. */
__attribute__((noinline)) static void scrub_stack(void)
{
    volatile unsigned char scratch[4096];
    size_t index;

    for (index = 0; index < sizeof scratch; ++index) {
        scratch[index] = 0;
    }
}

int main(void)
{
    leak_blocks();
    scrub_stack();
    return 0;
}
"""

# The `#define`s are prepended rather than written into the body so the
# diagnostic below can quote the real count instead of a copy that drifts the
# moment anyone raises it.
_LEAK_SELF_CHECK_SOURCE = (
    f"#define LEAK_BLOCKS {_LEAK_SELF_CHECK_BLOCKS}\n"
    f"#define LEAK_BLOCK_BYTES {_LEAK_SELF_CHECK_BLOCK_BYTES}\n"
    + _LEAK_SELF_CHECK_BODY
)

# Exit code the self-check demands from a working LeakSanitizer. Any value
# ASan will exit with does; 23 is simply outside the range the probe program
# can produce itself (it returns 0 or calls `abort`).
_LEAK_SELF_CHECK_EXIT = 23

# The stderr a leak report contains, and an unrelated fatal does not.
#
# Matching `LeakSanitizer` alone is too weak: 23 is also ASan's generic
# `common_flags()->exitcode`, which any post-parse fatal uses -- including
# `detect_leaks is not supported on this platform`, whose text does not contain
# this phrase. Requiring the report headline means only an actual leak report
# reads as success.
_LEAK_SELF_CHECK_REPORT = "detected memory leaks"


def _leak_sanitizer_link_error(temporary_root: Path) -> str | None:
    """Probe whether cc can compile AND link the sanitizer runtime.

    Returns None when it links, else the probe's diagnostics.
    """

    probe_source = temporary_root / "leak_probe.c"
    probe_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    completed = subprocess.run(
        [
            "cc",
            *_LEAK_SANITIZER_FLAGS,
            str(probe_source),
            "-o",
            str(temporary_root / exe_filename("leak_probe")),
        ],
        capture_output=True,
        check=False,
    )
    if completed.returncode == 0:
        return None
    diagnostics = completed.stderr.decode("utf-8", "replace").strip()
    return "cc cannot link -fsanitize=address,leak:\n" + (diagnostics or "(no output)")


def _leak_sanitizer_detection_error(temporary_root: Path) -> str | None:
    """Probe whether LeakSanitizer actually REPORTS a leak it is handed.

    Linking the runtime is not the same as it working. A runtime that
    initialises but reports nothing leaves every leak assertion in this leg
    passing while observing nothing, which is indistinguishable from passing
    because the code is leak-clean.

    So the sanitizer has to demonstrate itself before it is allowed to certify
    anything — the same stance as ``OVSTORAGE_REQUIRE_TSAN`` on the
    ``sync_wait`` regression. Returns None when the leak is reported.

    The probe is only as good as its calibration: see
    ``_LEAK_SELF_CHECK_SOURCE`` for why it leaks many blocks rather than one,
    and what to raise first if a future toolchain reports nothing.
    """

    source = temporary_root / "leak_self_check.c"
    source.write_text(_LEAK_SELF_CHECK_SOURCE, encoding="utf-8")
    executable = temporary_root / exe_filename("leak_self_check")
    built = subprocess.run(
        ["cc", *_LEAK_SANITIZER_FLAGS, str(source), "-o", str(executable)],
        capture_output=True,
        check=False,
    )
    if built.returncode != 0:
        diagnostics = built.stderr.decode("utf-8", "replace").strip()
        return "the LeakSanitizer self-check did not build:\n" + (
            diagnostics or "(no output)"
        )
    completed = subprocess.run(
        [str(executable)],
        env={
            **os.environ,
            "ASAN_OPTIONS": f"detect_leaks=1:exitcode={_LEAK_SELF_CHECK_EXIT}",
            # Consulted after ASAN_OPTIONS for leak settings, so a stale
            # `detect_leaks=0` in the caller's environment would otherwise
            # answer "LeakSanitizer is broken" on a host where it works.
            "LSAN_OPTIONS": "",
        },
        capture_output=True,
        check=False,
        cwd=temporary_root,
    )
    diagnostics = completed.stderr.decode("utf-8", "replace").strip()
    # BOTH signals, not either. The exit code alone is ambiguous because 23 is
    # also ASan's generic fatal `exitcode`; the report headline is what makes
    # this an observation of LeakSanitizer specifically.
    if (
        completed.returncode == _LEAK_SELF_CHECK_EXIT
        and _LEAK_SELF_CHECK_REPORT in diagnostics
    ):
        return None
    return (
        f"LeakSanitizer did not report {_LEAK_SELF_CHECK_BLOCKS} deliberately "
        "leaked blocks (exit "
        f"{completed.returncode}, wanted {_LEAK_SELF_CHECK_EXIT} with "
        f"{_LEAK_SELF_CHECK_REPORT!r} on stderr). It links here but detects "
        "nothing, so every leak assertion in this leg would pass without "
        "observing anything. Raise the self-check's block count before "
        "concluding the toolchain is at fault: a lone stale root can pin a "
        "small leak, and this probe has been miscalibrated that way before.\n"
        f"self-check stderr: {diagnostics or '(silent)'}"
    )


def _leak_sanitizer_unusable_reason(temporary_root: Path) -> str | None:
    """Why this toolchain's LeakSanitizer cannot be trusted, or None."""

    return _leak_sanitizer_link_error(temporary_root) or _leak_sanitizer_detection_error(
        temporary_root
    )


def _crt_leak_detection_error(temporary_root: Path, root: Path) -> str | None:
    """Probe whether the MSVC debug CRT reports a deliberate leak.

    Returns None when the leaky probe exits 23 and the clean probe exits 0.
    """

    probe_source = root / _CRT_LEAK_PROBE
    if not probe_source.is_file():
        return f"the CRT leak self-check source is missing: {probe_source}"

    for probe_value, expected_exit, label in (
        (1, _LEAK_SELF_CHECK_EXIT, "leaky"),
        (0, 0, "clean"),
    ):
        executable = temporary_root / exe_filename(f"crt_leak_{label}")
        built = subprocess.run(
            [
                "cl",
                "/nologo",
                "/std:c11",
                *_CRT_DEBUG_FLAGS,
                f"/DOVC_CRT_LEAK_PROBE={probe_value}",
                str(probe_source),
                f"/Fe:{executable}",
            ],
            capture_output=True,
            check=False,
            cwd=temporary_root,
        )
        if built.returncode != 0:
            diagnostics = built.stderr.decode("utf-8", "replace").strip()
            return (
                f"the CRT leak self-check ({label}) did not build:\n"
                + (diagnostics or "(no output)")
            )
        completed = subprocess.run(
            [str(executable)],
            capture_output=True,
            check=False,
            cwd=temporary_root,
        )
        if completed.returncode != expected_exit:
            diagnostics = completed.stderr.decode("utf-8", "replace").strip()
            return (
                f"the CRT leak self-check ({label}) exited "
                f"{completed.returncode}, wanted {expected_exit}.\n"
                f"stderr: {diagnostics or '(silent)'}"
            )
    return None


def _crt_leak_unusable_reason(temporary_root: Path, root: Path) -> str | None:
    """Why this toolchain's CRT leak reporter cannot be trusted, or None."""

    return _crt_leak_detection_error(temporary_root, root)


def _build_and_run_crt_leak_contracts(
    root: Path,
    source_root: Path,
    sources: list[Path],
    driver: Path,
    contract_tus: list[Path],
    temporary_root: Path,
) -> None:
    executable = temporary_root / exe_filename("leak_contracts")
    run_command(
        [
            "cl",
            "/nologo",
            "/std:c11",
            "/W4",
            "/WX",
            # Route ovc_abi_alloc/free through the CRT allocator for this
            # binary only. The process heap is invisible to the CRT leak
            # reporter, so without this every ABI value the contracts
            # allocate escapes the gate.
            "/DOVC_ABI_ALLOC_VIA_CRT",
            # Count queued plus executing process-global runtime tasks so the
            # driver can establish a bounded quiescent point before asking
            # the CRT for outstanding allocation identities.
            "/DOVC_RUNTIME_TEST_QUIESCENCE",
            # The connection ownership contract arms a thread-local one-shot
            # trap in the driver and ovc_abi_alloc consults it here.
            "/DOVC_ABI_ALLOC_FAILURE_TEST",
            *_CRT_DEBUG_FLAGS,
            f"/I{source_root / 'include'}",
            *[str(path) for path in sources],
            *[str(path) for path in contract_tus],
            str(driver),
            f"/Fe:{executable}",
        ],
        cwd=temporary_root,
        label="CRT leak contracts build",
    )
    run_command(
        [str(executable)],
        cwd=temporary_root,
        label="CRT leak contracts",
    )
    print("CRT leak contracts passed leak-clean", flush=True)


def build_and_run_leak_contracts(root: Path | None = None) -> None:
    """Run the stream cancel/error contracts under ASan+LeakSanitizer.

    The cancel-races-Failed contract requires the dispatcher to *release*
    the producer's error while reporting Cancelled — a behavior observable
    only as a leak, and the handoff contract's import-failure disposal is
    equally leak-shaped.  This leg builds the distribution sources plus the
    cc-test contract TUs with the sanitizers and runs the contracts, so a
    regression that stops freeing a plugin-minted error (or leaks any
    stream/pump/exported-proxy state) fails the gate instead of passing
    silently.
    On win32 the same contracts run under the MSVC debug CRT leak reporter.
    Skipped on toolchains where the chosen leak detector either does not
    link or does not work — which it must DEMONSTRATE, by reporting a
    deliberate leak, before it is allowed to certify anything.
    Both skips become hard failures under OVSTORAGE_REQUIRE_SANITIZERS=1 (set
    in CI's c-source job), so the leg cannot silently self-disable when a
    runner image changes.
    """

    root = repo_root() if root is None else root
    source_root = root / _C_SOURCE_DIR
    sources = sorted((source_root / "src").glob("*.c"))
    if not sources:
        raise TaskError(f"pure-C source set is empty: {source_root / 'src'}")
    driver = root / _LEAK_CONTRACT_DRIVER
    contract_tus = [root / relative for relative in _LEAK_CONTRACT_TUS]
    for path in (driver, *contract_tus):
        if not path.is_file():
            raise TaskError(f"sanitizer contract input is missing: {path}")

    with tempfile.TemporaryDirectory(
        prefix="ovstorage-c-source-leak-contracts-"
    ) as temporary:
        temporary_root = Path(temporary)

        if sys.platform == "win32":
            require_tool("cl", "install MSVC (cl) for CRT leak contracts")
            unusable = _crt_leak_unusable_reason(temporary_root, root)
            if unusable is not None:
                if os.environ.get("OVSTORAGE_REQUIRE_SANITIZERS") == "1":
                    raise TaskError(
                        "OVSTORAGE_REQUIRE_SANITIZERS=1 but the CRT leak "
                        "reporter is not usable on this toolchain:\n"
                        + unusable
                    )
                print(
                    f"skipping the CRT leak contracts: {unusable}",
                    flush=True,
                )
                return
            _build_and_run_crt_leak_contracts(
                root,
                source_root,
                sources,
                driver,
                contract_tus,
                temporary_root,
            )
            return

        require_tool("cc", "install a C99 toolchain providing cc")
        unusable = _leak_sanitizer_unusable_reason(temporary_root)
        if unusable is not None:
            if os.environ.get("OVSTORAGE_REQUIRE_SANITIZERS") == "1":
                raise TaskError(
                    "OVSTORAGE_REQUIRE_SANITIZERS=1 but LeakSanitizer is not "
                    "usable on this toolchain:\n" + unusable
                )
            print(
                f"skipping the sanitizer contracts: {unusable}",
                flush=True,
            )
            return
        executable = temporary_root / exe_filename("leak_contracts")
        run_command(
            [
                "cc",
                "-std=c99",
                "-g",
                *_LEAK_SANITIZER_FLAGS,
                "-DOVC_ABI_ALLOC_FAILURE_TEST",
                f"-I{source_root / 'include'}",
                *[str(path) for path in sources],
                *[str(path) for path in contract_tus],
                str(driver),
                "-o",
                str(executable),
                "-lpthread",
                "-ldl",
            ],
            label="sanitizer contracts build",
        )
        run_command(
            # detect_leaks defaults on for Linux ASan; pass it explicitly so
            # the gate's intent survives toolchain default changes. LSAN_OPTIONS
            # is cleared because it is consulted after ASAN_OPTIONS for leak
            # settings, so a stale `detect_leaks=0` in the caller's environment
            # would otherwise switch leak detection back off.
            ["env", "ASAN_OPTIONS=detect_leaks=1", "LSAN_OPTIONS=", str(executable)],
            cwd=temporary_root,
            label="sanitizer contracts (ASan+LSan)",
        )
    print("sanitizer contracts passed leak-clean", flush=True)


# The driver TU lives at the crate root next to leak_contracts_main.c so
# build.rs never compiles it into the Rust test binary.
_SECRET_WIPE_SEAM_DRIVER = Path(
    "ovstorage-core/ovstorage-c-source-cc-test/secret_wipe_seam_main.c"
)
def build_and_run_secret_wipe_seam(root: Path | None = None) -> None:
    """Observe the secret wipe at every SecretValue and auth-bearer site.

    tests/cc/secret_wipe_c.c covers the wipe PRIMITIVE. The wiring is
    `static` below the public SecretBundle and AuthCredential free functions,
    so the compile-time OVC_ABI_FREE seam watches each release before
    forwarding to the real allocator. Dropping any clear call fails here.
    """

    root = repo_root() if root is None else root
    source_root = root / _C_SOURCE_DIR
    compiler = "cl" if sys.platform == "win32" else "cc"
    require_tool(compiler, f"install a C toolchain providing {compiler}")
    sources = sorted((source_root / "src").glob("*.c"))
    if not sources:
        raise TaskError(f"pure-C source set is empty: {source_root / 'src'}")
    driver = root / _SECRET_WIPE_SEAM_DRIVER
    if not driver.is_file():
        raise TaskError(f"secret-wipe seam driver is missing: {driver}")

    with tempfile.TemporaryDirectory(
        prefix="ovstorage-c-source-secret-wipe-seam-"
    ) as temporary:
        temporary_root = Path(temporary)
        executable = temporary_root / exe_filename("secret_wipe_seam")
        if sys.platform == "win32":
            command = [
                compiler,
                "/nologo",
                "/std:c11",
                "/W4",
                "/WX",
                f"/I{source_root / 'include'}",
                "/DOVC_ABI_FREE=ovc_test_abi_free",
                *[str(path) for path in sources],
                str(driver),
                f"/Fe:{executable}",
            ]
        else:
            command = [
                compiler,
                "-std=c99",
                "-Wall",
                "-Wextra",
                f"-I{source_root / 'include'}",
                "-DOVC_ABI_FREE=ovc_test_abi_free",
                *[str(path) for path in sources],
                str(driver),
                "-o",
                str(executable),
                "-lpthread",
                "-ldl",
            ]
        run_command(
            command,
            cwd=temporary_root,
            label="secret-wipe compile-time seam build",
        )
        run_command(
            [str(executable)],
            cwd=temporary_root,
            label="secret-wipe compile-time seam",
        )


def run() -> None:
    """Run the pure-C source completeness, purity, and example-build gate."""

    root = repo_root()
    verify_completeness_table(root)
    verify_dependency_purity(root)
    build_and_run_examples(root)
    build_and_run_embedded_suites(root)
    build_and_run_secret_wipe_seam(root)
    build_and_run_leak_contracts(root)
    print("pure-C source example gate passed", flush=True)
