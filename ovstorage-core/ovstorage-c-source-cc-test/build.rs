// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds and links the standalone C source distribution into the test harness.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Shipped C headers, each compiled as a standalone C99 TU and a standalone
/// C++17 TU so a header regression fails this crate instead of the first
/// downstream consumer. The C++ wrapper `ovstorage.hpp` is C++-only, needs
/// C++20, and has its own list below.
const HEADER_CONFORMANCE_C: &[&str] = &[
    "tests/cc/header_ovstorage_c.c",
    "tests/cc/header_defaults_c.c",
    "tests/cc/header_plugin_c.c",
    // Exposes the shipped EffectivePermissions constants so roundtrip.rs
    // can compare them against ovstorage-layer's Rust bit values.
    "tests/cc/permissions_probe_c.c",
];

const HEADER_CONFORMANCE_CPP17: &[&str] = &[
    "tests/cc/header_ovstorage_cpp17.cpp",
    "tests/cc/header_defaults_cpp17.cpp",
    "tests/cc/header_plugin_cpp17.cpp",
    // Expands the __cplusplus arm of the EffectivePermissions macros —
    // macros are only checked when expanded, so the C++ arm needs its own
    // probe alongside the C one.
    "tests/cc/permissions_probe_cpp17.cpp",
];

/// The shipped C++ wrapper is async-only and needs `<coroutine>`, so its
/// conformance TU compiles at C++20. It is gated on [`probe_cpp20`].
const HEADER_CONFORMANCE_CPP20: &[&str] = &["tests/cc/header_hpp_cpp20.cpp"];

/// Set in CI, where the toolchain is known to clear the documented C++20
/// floor. Turns an unsupported-compiler skip into a hard build failure, so
/// the C++20 coverage cannot silently self-disable when a runner image
/// changes or the wrapper stops compiling.
const REQUIRE_CPP20_ENV: &str = "OVSTORAGE_REQUIRE_CPP20";

/// Set in CI, where ThreadSanitizer is expected to work. Without TSan the
/// `sync_wait` regression still builds and runs, but it can only catch a
/// wrong outcome or a hang — both of which the unfixed, stack-owned
/// rendezvous passes. Requiring it keeps that leg from self-disabling.
const REQUIRE_TSAN_ENV: &str = "OVSTORAGE_REQUIRE_TSAN";

/// Whether the *target* is MSVC.
///
/// One spelling, deliberately. This was written two ways in this file — the
/// literal `CARGO_CFG_TARGET_ENV` comparison and `cc::Tool::is_like_msvc()` —
/// and the two disagree under clang-cl, which targets MSVC while the tool is
/// clang. A build that picked one predicate for its flags and the other for
/// its command construction would emit a mismatched mixture.
///
/// Use this for anything keyed on the TARGET ABI (flag spellings, feature
/// tests). Use `tool.is_like_msvc()` only where the question is genuinely
/// about the driver being invoked.
fn target_is_msvc() -> bool {
    std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
}

fn configure_common(build: &mut cc::Build, include_dir: &Path) {
    build.include(include_dir);
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("unix") {
        build
            .define("_POSIX_C_SOURCE", Some("200809L"))
            .define("_XOPEN_SOURCE", Some("700"))
            .define("_FILE_OFFSET_BITS", Some("64"));
    }
    if target_is_msvc() {
        build.flag("/W4");
    } else {
        build
            .flag_if_supported("-Wall")
            .flag_if_supported("-Wextra");
    }
    build
        .warnings(true)
        // A warning in the shipped sources (or in this crate's gate TUs)
        // must fail the build here rather than surface in a downstream
        // consumer's -Werror build of the vendored tree.
        .warnings_into_errors(true);
}

fn c_build(include_dir: &Path) -> cc::Build {
    let mut build = cc::Build::new();
    configure_common(&mut build, include_dir);
    if target_is_msvc() {
        build.std("c11");
    } else {
        build.std("c99");
    }
    build
}

fn cpp17_build(include_dir: &Path) -> cc::Build {
    let mut build = cc::Build::new();
    configure_common(&mut build, include_dir);
    build.cpp(true).std("c++17");
    if target_is_msvc() {
        build.flag("/EHsc");
    }
    build
}

fn cpp20_build(include_dir: &Path) -> cc::Build {
    let mut build = cc::Build::new();
    configure_common(&mut build, include_dir);
    build.cpp(true).std("c++20");
    if target_is_msvc() {
        build.flag("/EHsc");
    }
    build
}

/// Capability probe for the shipped C++ wrapper: compile a translation unit
/// whose entire content is `#include "ovstorage.hpp"` at `-std=c++20`.
///
/// This is a capability check, not a version comparison, because the version
/// numbers in the documented floor (GCC 13+, Clang 17+, MSVC 19.40+) are not
/// what a compiler reports about itself in a way `cc` can compare portably —
/// and because a narrower probe is not equivalent. A two-line `co_await`
/// translation unit compiles under GCC 11, which then rejects `ovstorage.hpp`
/// ("no suspend point info for `co_await`" in `Stack::build`, whose awaiter is
/// a class local to the coroutine body). Compiling the header itself is the
/// only probe that answers the question actually being asked.
///
/// Returns the compiler diagnostics on failure. Warnings stay off here: this
/// asks "can this toolchain build the wrapper at all", and the real
/// conformance TU below re-compiles it under `-Wall -Wextra -Werror`.
fn probe_cpp20(include_dir: &Path) -> Result<(), String> {
    let probe_dir = out_dir().join("cpp20_probe");
    fs::create_dir_all(&probe_dir)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", probe_dir.display()));
    let source = probe_dir.join("cpp20_probe.cpp");
    fs::write(&source, "#include \"ovstorage.hpp\"\n")
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", source.display()));

    let mut build = cc::Build::new();
    build
        .include(include_dir)
        .cpp(true)
        .std("c++20")
        .file(&source)
        .out_dir(&probe_dir)
        // The probe archive is never linked, so it must not emit link flags.
        .cargo_metadata(false)
        .warnings(false);
    if target_is_msvc() {
        build.flag("/EHsc");
    }
    build
        .try_compile("ovstorage_c_source_cpp20_probe")
        .map_err(|error| error.to_string())
}

fn c_source_files(source_dir: &Path) -> Vec<PathBuf> {
    let entries = fs::read_dir(source_dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source_dir.display()));
    let mut files = entries
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to read an entry in {}: {error}",
                        source_dir.display()
                    )
                })
                .path()
        })
        .filter(|path| path.extension() == Some(OsStr::new("c")))
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "standalone C source set is empty: {}",
        source_dir.display()
    );
    files
}

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    // This crate is at ovstorage-core/ovstorage-c-source-cc-test, exactly two
    // levels below the repository root.
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("walk two levels from the crate to the repository root");
    let source_root = repo_root.join("ovstorage-c-source");
    let source_dir = source_root.join("src");
    let include_dir = source_root.join("include");
    let roundtrip_c = manifest_dir.join("tests/cc/roundtrip_c.c");
    let roundtrip_cpp20 = manifest_dir.join("tests/cc/roundtrip_cpp20.cpp");
    let streams_c = manifest_dir.join("tests/cc/streams_c.c");
    let declined_release_c = manifest_dir.join("tests/cc/declined_release_c.c");
    let handoff_c = manifest_dir.join("tests/cc/handoff_c.c");
    let stack_async_c = manifest_dir.join("tests/cc/stack_async_c.c");
    let stack_build_parked_c = manifest_dir.join("tests/cc/stack_build_parked_c.c");
    let stack_build_parked_cpp = manifest_dir.join("tests/cc/stack_build_parked_cpp.cpp");
    let auth_event_stub_c = manifest_dir.join("tests/cc/auth_event_stub_c.c");
    let auth_decoder_plugin_fixture = manifest_dir.join("tests/cc/auth_decoder_plugin_fixture.c");
    let auth_decoder_plugin_host = manifest_dir.join("tests/cc/auth_decoder_plugin_host.c");
    let auth_credential_ownership = manifest_dir.join("tests/cc/auth_credential_ownership_main.c");
    let sync_wait_race = manifest_dir.join("tests/cc/sync_wait_destroy_race.cpp");
    let callback_boundaries = manifest_dir.join("tests/cc/callback_boundaries_cpp20.cpp");
    let secret_wipe_c = manifest_dir.join("tests/cc/secret_wipe_c.c");
    let stack_build_abandon_repro = manifest_dir.join("tests/cc/stack_build_abandon_repro.c");
    let abandon_inner_fixture = manifest_dir.join("tests/cc/abandon_inner_fixture.c");
    let completeness = manifest_dir.join("completeness.c");
    let header_conformance_c = HEADER_CONFORMANCE_C
        .iter()
        .map(|relative| manifest_dir.join(relative))
        .collect::<Vec<_>>();
    let header_conformance_cpp17 = HEADER_CONFORMANCE_CPP17
        .iter()
        .map(|relative| manifest_dir.join(relative))
        .collect::<Vec<_>>();
    let header_conformance_cpp20 = HEADER_CONFORMANCE_CPP20
        .iter()
        .map(|relative| manifest_dir.join(relative))
        .collect::<Vec<_>>();
    let source_files = c_source_files(&source_dir);
    // The `task<T>` regressions are standalone executables like the abandon
    // repro and the sync_wait race, and need watching for the same reason: the
    // nested compile is opaque to cargo, so without this an edit to one leaves
    // the stale binary in `OUT_DIR` and the test keeps certifying the old code.
    let task_drop_sources = TASK_DROP_REPROS
        .iter()
        .map(|(source_name, ..)| manifest_dir.join("tests/cc").join(source_name))
        .collect::<Vec<_>>();
    let target_is_unix = std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("unix");

    for path in source_files
        .iter()
        .chain([
            &roundtrip_c,
            &roundtrip_cpp20,
            &streams_c,
            &declined_release_c,
            &handoff_c,
            &stack_async_c,
            &stack_build_parked_c,
            &stack_build_parked_cpp,
            &auth_event_stub_c,
            &auth_decoder_plugin_fixture,
            &auth_decoder_plugin_host,
            &auth_credential_ownership,
            &sync_wait_race,
            &callback_boundaries,
            &stack_build_abandon_repro,
            &abandon_inner_fixture,
            &completeness,
        ])
        .chain(task_drop_sources.iter())
        .chain(header_conformance_c.iter())
        .chain(header_conformance_cpp17.iter())
        .chain(header_conformance_cpp20.iter())
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-env-changed={REQUIRE_CPP20_ENV}");
    println!("cargo:rerun-if-env-changed={REQUIRE_TSAN_ENV}");
    // Declared unconditionally so `--cfg ovstorage_cpp20` is a known cfg even
    // on the skip path, where it is never emitted.
    println!("cargo::rustc-check-cfg=cfg(ovstorage_cpp20)");
    println!("cargo:rerun-if-changed={}", source_dir.display());
    println!("cargo:rerun-if-changed={}", secret_wipe_c.display());
    println!("cargo:rerun-if-changed={}", include_dir.display());
    // Every gate input under tests/cc, by directory rather than by name.
    //
    // Emitting any rerun-if-changed replaces Cargo's default "rerun when the
    // package changes", so a gate input this script never names is one Cargo
    // never watches: an edit to it leaves the compiled archives stale while a
    // passing `cargo test` certifies the previous mechanism. The named list
    // above has silently lost inputs three times (the `task_drop_*.cpp`
    // sources, `file_url.h`, `windows_posix_compat.h`), so the directory is
    // registered instead — it covers headers, which are inputs no `.file()`
    // call ever mentions, and it covers translation units added later.
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("tests/cc").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("internal.h").display()
    );

    // Emit the C++ archives first so their C ABI and ovstorage API references
    // are resolved by the C archives that follow them on linkers with ordered
    // static archive resolution. -pedantic-errors: see the C conformance pass.
    cpp17_build(&include_dir)
        .flag_if_supported("-pedantic-errors")
        .files(&header_conformance_cpp17)
        .compile("ovstorage_c_source_header_conformance_cpp17");

    // Tri-state C++20 gate, matching this crate's policy elsewhere: `built`
    // compiles and runs the C++20 coverage, `unsupported` skips it on a
    // toolchain below the documented floor, and anything else is a hard
    // failure. Only the capability probe can produce a skip — once it passes,
    // a compile error in any C++20 translation unit below fails the build, so
    // a broken wrapper cannot quietly delete its own coverage.
    let cpp20 = match probe_cpp20(&include_dir) {
        Ok(()) => true,
        Err(diagnostics) => {
            assert!(
                std::env::var(REQUIRE_CPP20_ENV).as_deref() != Ok("1"),
                "{REQUIRE_CPP20_ENV}=1 but this toolchain cannot compile the shipped C++20 \
                 wrapper `ovstorage.hpp` (floor: GCC 13+, Clang 17+, MSVC 19.40+):\n{diagnostics}"
            );
            println!(
                "cargo:warning=this toolchain cannot compile the shipped C++20 wrapper \
                 `ovstorage.hpp` (floor: GCC 13+, Clang 17+, MSVC 19.40+); skipping the C++20 \
                 conformance and round-trip coverage"
            );
            false
        }
    };
    if cpp20 {
        println!("cargo:rustc-cfg=ovstorage_cpp20");
        cpp20_build(&include_dir)
            .flag_if_supported("-pedantic-errors")
            .files(&header_conformance_cpp20)
            .compile("ovstorage_c_source_header_conformance_cpp20");
    }

    if cpp20 {
        cpp20_build(&include_dir)
            .file(&roundtrip_cpp20)
            .compile("ovstorage_c_source_roundtrip_cpp20");

        c_build(&include_dir)
            .file(&auth_event_stub_c)
            .compile("ovstorage_c_source_auth_event_stub_c");
    }

    c_build(&include_dir)
        .file(&roundtrip_c)
        .compile("ovstorage_c_source_roundtrip_c");

    c_build(&include_dir)
        .file(&auth_decoder_plugin_host)
        .compile("ovstorage_c_source_auth_decoder_plugin_host");

    build_auth_credential_ownership(&auth_credential_ownership, &include_dir, &source_dir);

    c_build(&include_dir)
        .file(&stack_async_c)
        .compile("ovstorage_c_source_stack_async_c");

    c_build(&include_dir)
        .file(&streams_c)
        .file(&declined_release_c)
        .compile("ovstorage_c_source_streams_c");

    c_build(&include_dir)
        .file(&handoff_c)
        .compile("ovstorage_c_source_handoff_c");

    if cpp20 {
        build_task_drop_repros(&manifest_dir, &include_dir);
    }

    // Parked-discovery and plugin-inspect need a dynamically loaded fixture.
    // Their drivers call `dlopen`/`dlsym` directly rather than going through
    // the shipped loader in plat.c; on Windows `windows_posix_compat.h`
    // defines those names over LoadLibraryW / GetProcAddress. So the dlopen
    // spelling in these TUs is a portable shim, not a POSIX-only contract,
    // and they are not gated on `target_is_unix`.
    if cpp20 {
        // The parked-discovery driver links the C ABI directly, exactly
        // like its C sibling, so it drives the shipped wrapper over the
        // shipped C sources. It needs no dlopen of a host library — only
        // of the Rust parking fixture, whose path roundtrip.rs supplies.
        cpp20_build(&include_dir)
            .file(&stack_build_parked_cpp)
            .compile("ovstorage_c_source_stack_build_parked_cpp");
    }

    c_build(&include_dir)
        .file(&stack_build_parked_c)
        .compile("ovstorage_c_source_stack_build_parked_c");

    if target_is_unix {
        build_abandon_repro(&manifest_dir, &include_dir, &source_files);
        if cpp20 {
            // Before the sync_wait regression, because its verdict decides how
            // that one is built: a toolchain that races every coroutine frame
            // makes any TSan report from an awaiting coroutine ambiguous.
            let coro_frames = build_coroutine_frame_probe(&manifest_dir);
            build_sync_wait_race(&manifest_dir, &include_dir, coro_frames);
        }
    }

    {
        let fixture_name = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            "libovstorage_c_source_inspect_fixture.dylib"
        } else if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            "ovstorage_c_source_inspect_fixture.dll"
        } else {
            "libovstorage_c_source_inspect_fixture.so"
        };
        let fixture = out_dir().join(fixture_name);
        compile_inspect_fixture(&include_dir, &streams_c, &fixture);
        println!(
            "cargo:rustc-env=OVSTORAGE_C_SOURCE_INSPECT_FIXTURE={}",
            fixture.display()
        );
    }

    {
        let fixture_name = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            "libovstorage_plugin_c_auth_decoder_fixture.dylib"
        } else if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            "ovstorage_plugin_c_auth_decoder_fixture.dll"
        } else {
            "libovstorage_plugin_c_auth_decoder_fixture.so"
        };
        let fixture = out_dir().join(fixture_name);
        compile_auth_decoder_plugin_fixture(
            &include_dir,
            &auth_decoder_plugin_fixture,
            &source_dir,
            &fixture,
        );
        println!(
            "cargo:rustc-env=OVSTORAGE_C_AUTH_DECODER_PLUGIN_FIXTURE={}",
            fixture.display()
        );
    }

    // The conformance TUs additionally compile under -pedantic-errors: the
    // EffectivePermissions empty-initializer regression this gate pins is a
    // -Wpedantic-only diagnostic, invisible to plain -Wall -Wextra -Werror.
    c_build(&include_dir)
        .flag_if_supported("-pedantic-errors")
        .files(&header_conformance_c)
        .compile("ovstorage_c_source_header_conformance_c");

    // completeness.c is an executable-style TU. Rename its main function and
    // call it from Rust so the linker must retain all frozen API relocations.
    // Portable: the wipe primitive needs no Stack, runtime, or filesystem.
    c_build(&include_dir)
        .file(&secret_wipe_c)
        .compile("ovstorage_c_source_secret_wipe_c");

    c_build(&include_dir)
        .define("main", Some("ovstorage_c_source_completeness"))
        .file(&completeness)
        .compile("ovstorage_c_source_completeness");

    c_build(&include_dir)
        .files(source_files)
        .compile("ovstorage_c_source");

    // Emitted last: it links the archive the call above just produced.
    if target_is_unix && cpp20 {
        build_callback_boundaries(&callback_boundaries, &include_dir);
    }

    if target_is_unix {
        // Keep these explicit, matching Makefile.example on systems where
        // pthread and the dynamic loader are not part of libc.
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
    }
}

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
}

/// Build the pure-C AuthCredential codec with an accounting allocator.
///
/// This is a standalone executable because the regular round-trip archive also
/// contains the production ABI allocator. Keeping the accounting allocator in
/// its own process lets the test prove exact balance for every nested decoder
/// allocation without interposing on unrelated, concurrently running tests.
fn build_auth_credential_ownership(source: &Path, include_dir: &Path, source_dir: &Path) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_STATUS=skipped");
        return;
    }

    let output_dir = out_dir();
    let binary = output_dir.join(
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            "auth_credential_ownership.exe"
        } else {
            "auth_credential_ownership"
        },
    );
    let codec = source_dir.join("auth_credential.c");
    let utf8 = source_dir.join("utf8.c");
    let plugin_values = source_dir.join("plugin_values.c");
    let tool = c_build(include_dir).get_compiler();
    let mut command = tool.to_command();

    if target_is_msvc() {
        command
            .current_dir(&output_dir)
            .arg("/std:c11")
            .arg("/W4")
            .arg("/WX")
            .arg(format!("/I{}", include_dir.display()))
            .arg(&codec)
            .arg(&utf8)
            .arg(&plugin_values)
            .arg(source)
            .arg(format!("/Fe:{}", binary.display()));
    } else {
        command
            .arg("-std=c99")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(format!("-I{}", include_dir.display()))
            .arg(&codec)
            .arg(&utf8)
            .arg(&plugin_values)
            .arg(source)
            .arg("-o")
            .arg(&binary);
    }

    match command.status() {
        Ok(status) if status.success() => {
            println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_STATUS=built");
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_BIN={}",
                binary.display()
            );
        }
        result => println!(
            "cargo:rustc-env=OVSTORAGE_C_SOURCE_AUTH_OWNERSHIP_STATUS=failed:\
             AuthCredential ownership driver did not build ({result:?})"
        ),
    }
}

/// Build the build-abandon regression as a standalone executable in `OUT_DIR`,
/// with AddressSanitizer when the toolchain supports it, and hand its path plus
/// whether ASan is active to the Rust tests via `rustc-env`.
///
/// It is an executable rather than another linked-in TU because the behaviour
/// it pins is "the build thread gets out of a slot a Layer never completes":
/// the failure mode is a hang, so the harness runs it under a timeout in its
/// own process. ASan matters because the completion state behind that slot is
/// reference-counted across two threads that may release it in either order.
///
/// It needs a companion plugin cdylib, built here too: only a genuinely loaded
/// plugin has a registration whose release is observable, which is what pins
/// that an abandoned subtree keeps every plugin behind it alive.
///
/// `..._STATUS` is always emitted and decides what the Rust test does. Only a
/// non-native build reports `skipped`; a compile or link failure reports
/// `failed`, which the test turns into a panic, so a broken fixture cannot
/// quietly remove the whole regression.
fn build_abandon_repro(manifest_dir: &Path, include_dir: &Path, source_files: &[PathBuf]) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS=skipped");
        return;
    }
    let out_dir = out_dir();
    let source = manifest_dir.join("tests/cc/stack_build_abandon_repro.c");
    let fixture_source = manifest_dir.join("tests/cc/abandon_inner_fixture.c");
    let binary = out_dir.join("stack_build_abandon_repro");
    let fixture = out_dir.join(
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            "libovstorage_c_source_abandon_inner.dylib"
        } else {
            "libovstorage_c_source_abandon_inner.so"
        },
    );
    let tool = c_build(include_dir).get_compiler();
    let asan = probe_asan(&tool, &out_dir, "asan_c");
    // ASan linking and ASan's LEAK half reporting are different questions, and
    // the repro asserts on both a use-after-free and a leak. Only the first is
    // a build-time fact; the self-check below is built here and RUN by the
    // test, so a cached build cannot answer a question about the current host.
    let leak_self_check = asan
        .then(|| build_leak_self_check(&tool, &out_dir, "abandon_repro"))
        .flatten();

    let common = |command: &mut std::process::Command| {
        command
            .arg("-std=c99")
            .arg("-O1")
            .arg("-g")
            .arg("-D_POSIX_C_SOURCE=200809L")
            .arg("-D_XOPEN_SOURCE=700")
            .arg("-D_FILE_OFFSET_BITS=64")
            .arg(format!("-I{}", include_dir.display()));
        if asan {
            command
                .arg("-fsanitize=address")
                .arg("-fno-omit-frame-pointer");
        }
    };

    // The companion plugin needs the default Layer vtable it copies, and
    // everything that vtable reaches: `vtables.c` for the table itself,
    // and `plugin_values.c` for the request releases its declining slots call.
    //
    // `plat.c` deliberately does NOT come along: it defines the plugin-ABI
    // allocator pair, and overriding that pair is the fixture's whole
    // mechanism -- allocations made through a released request have to come
    // back to ITS allocator for the leak account to mean anything. The fixture
    // supplies the one other symbol plat.c would have provided.
    const FIXTURE_SOURCES: [&str; 2] = ["vtables.c", "plugin_values.c"];
    let mut fixture_sources = Vec::new();
    for name in FIXTURE_SOURCES {
        let Some(path) = source_files
            .iter()
            .find(|path| path.file_name() == Some(OsStr::new(name)))
        else {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS=failed:\
                 {name} missing from the pure-C source set"
            );
            return;
        };
        fixture_sources.push(path);
    }
    let mut fixture_command = tool.to_command();
    common(&mut fixture_command);
    fixture_command
        .arg("-fPIC")
        .arg("-shared")
        .arg(&fixture_source)
        .args(&fixture_sources)
        // No `-Wl,--no-undefined` here, deliberately. It would turn a missing
        // source into a link error rather than a `dlopen` failure, which reads
        // better -- but this is a `-shared` link that also carries
        // `-fsanitize=address` whenever the ASan probe succeeds, and clang does
        // not link the ASan runtime into shared objects. The `__asan_*`
        // references are legitimately unresolved until the host loads this, so
        // the flag fails the link on clang, and therefore on macOS where it is
        // the only compiler. gcc happens to pass only because it links
        // `libasan.so` and satisfies them from there.
        //
        // The failure it would have improved on is already loud: `dlopen`
        // names the undefined symbol and the test turns that into a panic.
        .arg("-o")
        .arg(&fixture);
    match fixture_command.status() {
        Ok(status) if status.success() => {}
        result => {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS=failed:\
                 abandon_inner_fixture.c did not build ({result:?})"
            );
            return;
        }
    }

    let mut command = tool.to_command();
    common(&mut command);
    command.arg("-pthread").arg(&source).args(source_files);
    command.arg("-o").arg(&binary).arg("-ldl");
    match command.status() {
        Ok(status) if status.success() => {
            println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS=built");
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_BIN={}",
                binary.display()
            );
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_FIXTURE={}",
                fixture.display()
            );
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_ASAN={}",
                if asan { "1" } else { "0" }
            );
            // Absent when ASan is unavailable or the probe would not compile;
            // the test treats absence as "cannot demonstrate leak detection".
            if let Some(probe) = &leak_self_check {
                println!(
                    "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_LEAK_PROBE={}",
                    probe.display()
                );
            }
        }
        result => {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_ABANDON_REPRO_STATUS=failed:\
                 stack_build_abandon_repro.c did not build ({result:?})"
            );
        }
    }
}

/// Build the two `task<T>` lifetime regressions as standalone executables in
/// `OUT_DIR`, with AddressSanitizer when the toolchain supports it, and hand
/// each path plus whether ASan is active to the Rust tests via `rustc-env`.
///
/// They are executables rather than linked-in TUs because both failure modes
/// are a hang or a sanitizer abort: the harness runs them under a timeout in
/// their own process. They exercise only the header-only parts of
/// `ovstorage.hpp` — `task<T>`, its promise/`final_awaiter` abandon state
/// machine, and `detail::awaiter_base` — with their own awaiters standing in
/// for the C ABI's `on_complete`, so they need no runtime and reference no
/// `ovstorage_*` symbol.
///
/// `..._STATUS` is always emitted and decides what the Rust test does. Only a
/// non-native build reports `skipped`; a compile or link failure reports
/// `failed`, which the test turns into a panic. A toolchain that cannot build
/// the wrapper at all never reaches here — [`probe_cpp20`] gates the call —
/// so an internal compiler error in either regression is a hard failure
/// rather than a silent loss of both.
fn build_task_drop_repros(manifest_dir: &Path, include_dir: &Path) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    let out_dir = out_dir();

    for (source_name, binary_name, status_env, binary_env, asan_env) in TASK_DROP_REPROS {
        if host.is_empty() || host != target {
            println!("cargo:rustc-env={status_env}=skipped");
            continue;
        }
        let tool = cpp20_build(include_dir).get_compiler();
        let source = manifest_dir.join("tests/cc").join(source_name);
        let binary = out_dir.join(if cfg!(windows) {
            format!("{binary_name}.exe")
        } else {
            binary_name.to_string()
        });
        let mut command = tool.to_command();
        if tool.is_like_msvc() {
            // cl writes its object and debug-info files relative to the
            // working directory unless /Fo and /Fd say otherwise, so both are
            // pinned into OUT_DIR alongside the binary.
            //
            // These regressions need BOTH halves, and on MSVC they come from
            // two different tools. MSVC's AddressSanitizer has no leak
            // detector, so the debug CRT (/MDd + _CrtDumpMemoryLeaks) supplies
            // the unreclaimed-frame half; /fsanitize=address supplies the
            // freed-frame-access and double-free half, which the CRT heap
            // cannot see at all because those leave no outstanding
            // allocation. Reporting `crt` alone as "sanitized" claimed
            // coverage this build never had.
            //
            // Verified on cl.exe 14.44.35207 that the two compose: /MDd with
            // /fsanitize=address builds, runs, and reports
            // `heap-use-after-free`.
            let msvc_asan = probe_asan(&tool, &out_dir, "asan_cpp_msvc");
            command
                .current_dir(&out_dir)
                // `get_compiler()` does not carry `cpp20_build`'s `.std()`,
                // so the standard has to be restated here exactly as the
                // non-MSVC branch below restates `-std=c++20`. Without it
                // cl.exe defaults below C++20 and both drivers fail on
                // `std::suspend_never` — verified: C2039 without the flag,
                // clean with it.
                .arg("/std:c++20")
                .arg("/O1")
                .arg("/MDd")
                .arg("/Zi");
            if msvc_asan {
                command.arg("/fsanitize=address");
            }
            command
                .arg(format!(
                    "/Fo{}",
                    out_dir.join(format!("{binary_name}.obj")).display()
                ))
                .arg(format!(
                    "/Fd{}",
                    out_dir.join(format!("{binary_name}.pdb")).display()
                ))
                .arg(format!("/I{}", include_dir.display()))
                .arg(&source)
                .arg(format!("/Fe:{}", binary.display()));
            match command.status() {
                Ok(status) if status.success() => {
                    println!("cargo:rustc-env={status_env}=built");
                    println!("cargo:rustc-env={binary_env}={}", binary.display());
                    // `crt` means leaks only; `crt+asan` means the
                    // freed-frame half is covered too. The runner refuses
                    // the former under OVSTORAGE_REQUIRE_SANITIZERS.
                    println!(
                        "cargo:rustc-env={asan_env}={}",
                        if msvc_asan { "crt+asan" } else { "crt" }
                    );
                }
                result => {
                    println!(
                        "cargo:rustc-env={status_env}=failed:{source_name} did not build ({result:?})"
                    );
                }
            }
            continue;
        }
        let asan = probe_asan(&tool, &out_dir, "asan_cpp");
        command
            .arg("-std=c++20")
            .arg("-O1")
            .arg("-g")
            .arg(format!("-I{}", include_dir.display()))
            .arg("-pthread");
        if asan {
            command
                .arg("-fsanitize=address")
                .arg("-fno-omit-frame-pointer");
        }
        command.arg(&source).arg("-o").arg(&binary);
        match command.status() {
            Ok(status) if status.success() => {
                println!("cargo:rustc-env={status_env}=built");
                println!("cargo:rustc-env={binary_env}={}", binary.display());
                println!(
                    "cargo:rustc-env={asan_env}={}",
                    if asan { "1" } else { "0" }
                );
            }
            result => {
                println!(
                    "cargo:rustc-env={status_env}=failed:{source_name} did not build ({result:?})"
                );
            }
        }
    }
}

/// What running the coroutine-frame probe said about THIS toolchain.
///
/// Returned rather than only exported, because the answer changes how the
/// `sync_wait` regression is built: a toolchain that races its own coroutine
/// frames cannot give a meaningful TSan verdict on anything that awaits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CoroFrames {
    /// The probe ran both loops to completion with no TSan report.
    RaceFree,
    /// The probe halted on a report from the loop that publishes its handle
    /// inside `await_suspend`.
    Racy,
    /// No verdict: TSan is unavailable, the probe did not build, it did not
    /// run natively, it timed out, or it failed its own self-check.
    Unknown,
}

impl CoroFrames {
    fn as_str(self) -> &'static str {
        match self {
            CoroFrames::RaceFree => "race-free",
            CoroFrames::Racy => "racy",
            CoroFrames::Unknown => "unknown",
        }
    }
}

/// Build AND RUN the ovstorage-free coroutine-frame probe, and report whether
/// this compiler emits coroutine frames that can be resumed from another thread
/// without racing the frame's own bookkeeping.
///
/// GCC 15 gives every coroutine frame a 16-bit `_Coro_frame_refcount` and
/// manipulates it non-atomically from
/// both the ramp and the actor, so any coroutine that publishes its handle from
/// inside `await_suspend` — the only conforming place for a callback-driven
/// awaiter — races it. TSan reports that as a data race *inside the awaiting
/// coroutine*, which reads exactly like a defect in `ovstorage.hpp`. It is not;
/// the same report comes out of a standalone program that includes no ovstorage
/// header at all, which is precisely what `coroutine_frame_refcount_race.cpp`
/// is. Establishing that separately keeps the compiler verdict out of the
/// `sync_wait` leg.
///
/// The verdict is derived by RUNNING the probe, as `probe_sanitizer` already
/// runs its trivial binary: whether the codegen races is not a question the
/// build script can answer by inspecting flags or version strings. The probe's
/// exit code is the whole contract — 0 race-free, 1 a TSan report, 2 its own
/// self-check failed — so its output is discarded rather than inherited, which
/// also keeps a chatty child from writing anything into this script's stdout,
/// where Cargo reads `cargo:` directives.
///
/// Without TSan there is nothing to detect, so the verdict is `unknown` and the
/// probe is still built and exported: it then catches a wrong resumption count
/// or a hang, which is worth keeping even though it is not the interesting half.
///
/// Unlike its siblings this compile deliberately does NOT pass `-I` for the
/// shipped headers. The probe's entire value is that its verdict cannot be
/// about `ovstorage.hpp`, and an include path that lets it grow an include
/// later would quietly destroy that.
///
/// Concretely: `configure_common` calls `build.include(include_dir)`, and
/// `cc::Build::get_compiler()` propagates every include directory into the
/// returned `Tool`'s args.  Bypassing `configure_common` (and `cpp20_build`)
/// keeps that path out of `tool.to_command()` entirely.
fn build_coroutine_frame_probe(manifest_dir: &Path) -> CoroFrames {
    let export = |status: &str, verdict: CoroFrames| {
        println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_STATUS={status}");
        println!(
            "cargo:rustc-env=OVSTORAGE_C_SOURCE_TOOLCHAIN_CORO_FRAMES={}",
            verdict.as_str()
        );
        verdict
    };

    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        return export("skipped", CoroFrames::Unknown);
    }
    let out_dir = out_dir();
    // Build with warnings as errors but without `configure_common`'s
    // `.include()`: calling `cpp20_build` would carry `include_dir` into
    // `tool.to_command()` via `get_compiler()`, defeating the invariant above.
    let tool = {
        let mut build = cc::Build::new();
        build
            .cpp(true)
            .std("c++20")
            .warnings(true)
            .warnings_into_errors(true);
        build.get_compiler()
    };

    // The compiler identification travels with the verdict: every diagnostic
    // this feeds names a toolchain defect, and "which toolchain" is the first
    // thing a reader of that message needs.
    println!(
        "cargo:rustc-env=OVSTORAGE_C_SOURCE_CORO_FRAME_COMPILER={}",
        compiler_version_line(&tool)
    );

    let tsan = probe_sanitizer(&tool, &out_dir, "tsan_cpp", "-fsanitize=thread");
    let source = manifest_dir.join("tests/cc/coroutine_frame_refcount_race.cpp");
    let binary = out_dir.join("coroutine_frame_refcount_race");

    let mut command = tool.to_command();
    command
        .arg("-std=c++20")
        .arg("-O1")
        .arg("-g")
        .arg("-pthread");
    if tsan {
        command
            .arg("-fsanitize=thread")
            .arg("-fno-omit-frame-pointer");
    }
    command.arg(&source).arg("-o").arg(&binary);
    match command.status() {
        Ok(status) if status.success() => {}
        result => {
            return export(
                &format!("failed:coroutine_frame_refcount_race.cpp did not build ({result:?})"),
                CoroFrames::Unknown,
            );
        }
    }
    println!(
        "cargo:rustc-env=OVSTORAGE_C_SOURCE_CORO_FRAME_PROBE_BIN={}",
        binary.display()
    );
    if !tsan {
        return export("built-without-tsan", CoroFrames::Unknown);
    }

    let run = run_with_timeout(&binary, std::time::Duration::from_secs(180));
    let verdict = match run.as_ref().map(|run| run.code) {
        Some(Some(0)) => CoroFrames::RaceFree,
        // Exit 1 alone is NOT the verdict — see `probe_reported_its_own_race`.
        Some(Some(1)) if run.as_ref().is_some_and(probe_reported_its_own_race) => CoroFrames::Racy,
        // A self-check failure, a signal, a timeout, or a report that is not
        // this probe's says the probe did not work — NOT that the toolchain is
        // fine, and not that it is affected either. Warn rather than fold it
        // into either verdict, so a probe that quietly stopped probing is
        // visible.
        other => {
            println!(
                "cargo:warning=the coroutine-frame toolchain probe did not produce a \
                 verdict ({other:?}{}); this build cannot say whether this compiler's \
                 coroutine frames are race-free",
                run.as_ref().map(probe_failure_hint).unwrap_or_default()
            );
            CoroFrames::Unknown
        }
    };
    export("built", verdict)
}

/// Did the probe report the race it exists to detect, or merely *a* race?
///
/// `exitcode=1` is what ThreadSanitizer exits with for ANY report or runtime
/// failure — a race inside libstdc++, a startup failure such as "unexpected
/// memory mapping", a report provoked by the control loop. Mapping a bare 1 to
/// `Racy` would let any of those switch ThreadSanitizer off for the sync_wait
/// regression and print a confident, wrong diagnosis naming the compiler. That
/// is the same species of mistake this probe was written to correct, so the
/// exit code is checked against what the process actually said.
///
/// Two conditions, both necessary:
///
/// * the control loop printed its completion marker, so whatever TSan halted on
///   happened AFTER the control finished and is not the control's own; and
/// * the report is a `data race` naming the racy loop's coroutine, on a
///   two-byte access — the frame's refcount width.
///
/// The markers are the driver's, and its `OUTPUT CONTRACT` comment
/// (`tests/cc/coroutine_frame_refcount_race.cpp`) is where they are defined.
/// `tests/roundtrip.rs` repeats this check for its own re-run; all three move
/// together. Matching sanitizer output by literal follows `LEAK_PROBE_REPORT`
/// in that file.
fn probe_reported_its_own_race(run: &ProbeRun) -> bool {
    const CONTROL_OK: &str = "coroutine_frame_refcount_race: control (publish after the ramp) ok";
    const RACY_FUNCTION: &str = "publishes_during_the_ramp";
    // The frame is a heap block; that line survives an unsymbolized report,
    // where the function name does not (no llvm-symbolizer/addr2line on the
    // host prints `<null> (binary+0xNNNN)` instead).
    const RACY_FRAME_BLOCK: &str = "Location is heap block";

    run.stdout.contains(CONTROL_OK)
        && run.stderr.contains("data race")
        && run.stderr.contains("of size 2")
        && (run.stderr.contains(RACY_FUNCTION) || run.stderr.contains(RACY_FRAME_BLOCK))
}

/// A one-line excerpt of what the probe said, for the `cargo:warning` above.
///
/// `cargo:warning` is a single line, so this picks the sanitizer's own summary
/// when there is one and truncates. Without it "did not produce a verdict" is
/// unactionable: the whole point of the check that rejected this run is that
/// something else was reported, and a developer cannot chase what they cannot
/// see.
fn probe_failure_hint(run: &ProbeRun) -> String {
    let line = run
        .stderr
        .lines()
        .find(|line| line.starts_with("SUMMARY:"))
        .or_else(|| run.stderr.lines().find(|line| !line.trim().is_empty()));
    match line {
        Some(line) => format!(
            ", it said: {}",
            line.trim().chars().take(200).collect::<String>()
        ),
        None => String::new(),
    }
}

/// First line of the compiler's `--version`, or `unknown`.
///
/// `tool.path()` rather than `tool.to_command()`: the latter carries the flags
/// `cc` has accumulated, and a `--version` run is not the place to find out one
/// of them is rejected.
fn compiler_version_line(tool: &cc::Tool) -> String {
    std::process::Command::new(tool.path())
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// What the probe did and what it printed.
struct ProbeRun {
    /// `None` when a signal killed it.
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `binary` under TSan's halt-on-first-report settings and return what it
/// did, or `None` if it did not exit within `timeout`.
///
/// The streams are collected rather than discarded because the exit code alone
/// does not identify WHICH report a sanitizer exit stands for; see
/// [`probe_reported_its_own_race`]. Piping also keeps a chatty child out of
/// this script's stdout, where Cargo reads `cargo:` directives — the reason
/// they were nulled before. Reading after exit is safe here for the same
/// reason it is in the test harness: under `halt_on_error=1` the probe prints
/// one report, far below the pipe buffer that would deadlock the read.
///
/// A build script that runs a program with a spin-wait in it needs a bound. The
/// probe hands handles between two threads and waits for counts to advance, so
/// a toolchain that mis-schedules it would hang this build forever rather than
/// report `unknown`, and a hung build gives a developer far less to go on than
/// a skipped verdict does.
///
/// `abort_on_error=0` because sanitizer_common defaults it to 1 on Darwin: a
/// report there raises `SIGABRT`, `code()` is `None` for a signalled child, and
/// this would record `Unknown` for a detection that plainly worked — building
/// the sync_wait regression WITH TSan on an affected compiler and restoring the
/// exact misdirection this probe exists to remove. It must stay in step with
/// `run_driver` in `tests/roundtrip.rs`, which reads the same contract.
fn run_with_timeout(binary: &Path, timeout: std::time::Duration) -> Option<ProbeRun> {
    let mut child = std::process::Command::new(binary)
        .env(
            "TSAN_OPTIONS",
            "halt_on_error=1:exitcode=1:abort_on_error=0",
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    Some(ProbeRun {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Why the `sync_wait` regression is being built without ThreadSanitizer.
///
/// Two different facts about the host produce the same degraded build, and they
/// must not share a message: one is "this machine cannot run TSan", the other is
/// "this compiler's own codegen races, so TSan's answer would not be about
/// `ovstorage.hpp`". Telling a developer the first when the second is true is
/// exactly the misdirection this whole change set exists to undo.
enum SyncWaitDegradation {
    /// TSan did not compile, link or start here.
    NoTsanRuntime,
    /// The toolchain races its own coroutine frames — see
    /// [`build_coroutine_frame_probe`].
    RacyCoroutineFrames,
}

/// Build the `sync_wait` destruction-race regression.
///
/// It needs ThreadSanitizer, not AddressSanitizer. The defect it pins is the
/// completing thread touching the waiter's condition variable after the
/// waiter destroyed it, and the touch happens inside `pthread_cond_broadcast`
/// — uninstrumented libc as far as ASan is concerned, so ASan sees nothing.
/// TSan intercepts the condvar calls and reports the destroy/broadcast pair
/// directly.
///
/// TSan is probed by compiling, linking AND running a trivial program,
/// because it fails at startup on some hosts ("unexpected memory mapping").
/// Without it the driver still builds and runs — it catches a wrong outcome
/// or a hang — and reports `built-without-tsan` so the test says which
/// coverage it actually got. That degraded mode CANNOT detect the condvar
/// destruction race itself, so CI sets `OVSTORAGE_REQUIRE_TSAN=1` and a
/// missing TSan runtime becomes a hard failure there rather than a leg that
/// silently stops checking the thing it exists to check.
///
/// A toolchain whose coroutine frames are not race-free takes that SAME
/// degraded path, for a different reason. This driver awaits, so every
/// iteration builds a coroutine frame; on GCC 15 the frame's non-atomic
/// refcount races whenever the body is resumed from the completing thread, and
/// TSan halts on that instead of on the condvar. The result is a `sync_wait`
/// test failing for a defect that is not in `sync_wait`. Building without
/// TSan here keeps the outcome/hang coverage, and the compiler defect gets
/// reported by the test that actually pins it
/// (`cpp20_toolchain_coroutine_frames_are_race_free`) rather than by this one.
/// `OVSTORAGE_REQUIRE_TSAN=1` still fails hard, so CI cannot lose the condvar
/// coverage without saying so if a runner image moves to an affected compiler.
fn build_sync_wait_race(manifest_dir: &Path, include_dir: &Path, coro_frames: CoroFrames) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS=skipped");
        return;
    }
    let out_dir = out_dir();
    let tool = cpp20_build(include_dir).get_compiler();
    // A racy verdict already implies TSan works — the probe cannot reach one
    // otherwise — so the order here only decides which message wins in a case
    // that cannot occur, and the missing runtime is the more basic fact.
    let degradation = if !probe_sanitizer(&tool, &out_dir, "tsan_cpp", "-fsanitize=thread") {
        Some(SyncWaitDegradation::NoTsanRuntime)
    } else if coro_frames == CoroFrames::Racy {
        Some(SyncWaitDegradation::RacyCoroutineFrames)
    } else {
        None
    };
    let tsan = degradation.is_none();
    if std::env::var(REQUIRE_TSAN_ENV).as_deref() == Ok("1") {
        match degradation {
            None => {}
            Some(SyncWaitDegradation::NoTsanRuntime) => panic!(
                "{REQUIRE_TSAN_ENV}=1 but this toolchain cannot compile, link and run a \
                 ThreadSanitizer binary. Without TSan the sync_wait regression cannot \
                 observe the condvar destruction race it exists to pin."
            ),
            Some(SyncWaitDegradation::RacyCoroutineFrames) => panic!(
                "{REQUIRE_TSAN_ENV}=1 but this compiler ({}) does not emit race-free \
                 coroutine frames, so a TSan build of the sync_wait regression reports \
                 the COMPILER's race and never reaches the condvar race it exists to \
                 pin.\n\nThis is a defect in the compiler, not in ovstorage.hpp: it \
                 gives every coroutine frame a non-atomic refcount that the ramp and \
                 the resuming thread decrement concurrently. Coroutine code that can \
                 resume on another thread before its ramp returns is affected, whoever \
                 wrote it. The standalone probe \
                 `cpp20_toolchain_coroutine_frames_are_race_free` pins it with no \
                 ovstorage header involved.\n\nBuild the C++ wrapper with GCC 13/14 or \
                 Clang 17+ to keep the condvar coverage. Unsetting \
                 {REQUIRE_TSAN_ENV} instead keeps this leg running WITHOUT TSan, \
                 where it still catches a wrong outcome or a hang but cannot see the \
                 destruction race.",
                compiler_version_line(&tool)
            ),
        }
    }
    let source = manifest_dir.join("tests/cc/sync_wait_destroy_race.cpp");
    let binary = out_dir.join("sync_wait_destroy_race");

    let mut command = tool.to_command();
    command
        .arg("-std=c++20")
        .arg("-O1")
        .arg("-g")
        .arg(format!("-I{}", include_dir.display()))
        .arg("-pthread");
    if tsan {
        command
            .arg("-fsanitize=thread")
            .arg("-fno-omit-frame-pointer");
    } else {
        // Override any -fsanitize=thread inherited from CXXFLAGS: tool.to_command()
        // carries the full environment, and CXXFLAGS=-fsanitize=thread would
        // otherwise enable TSan despite the degradation path intending a plain build.
        command.arg("-fno-sanitize=thread");
    }
    command.arg(&source).arg("-o").arg(&binary);
    match command.status() {
        Ok(status) if status.success() => {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS={}",
                match degradation {
                    None => "built",
                    Some(SyncWaitDegradation::NoTsanRuntime) => "built-without-tsan",
                    Some(SyncWaitDegradation::RacyCoroutineFrames) =>
                        "built-without-tsan-racy-coroutine-frames",
                }
            );
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_BIN={}",
                binary.display()
            );
        }
        result => {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_SYNC_WAIT_RACE_STATUS=failed:\
                 sync_wait_destroy_race.cpp did not build ({result:?})"
            );
        }
    }
}

/// Build the C-callback allocation-failure driver as a standalone executable
/// in `OUT_DIR`, linking the C archive `main` has already produced.
///
/// An executable rather than another linked-in TU for three reasons. It
/// replaces the global `operator new` and interposes `free`, which must not
/// reach the rest of the test binary. Two of the failure modes it pins are
/// process-wide — a boundary that never resumes its coroutine hangs, and one
/// that lets an exception escape a `noexcept` thunk calls `std::terminate` —
/// so the harness runs it under a timeout in its own process. And the `free`
/// interposition is incompatible with AddressSanitizer's allocator, so this
/// driver deliberately builds without sanitizers; its assertions are exact and
/// need no leak checker.
///
/// `..._STATUS` is always emitted and decides what the Rust test does. A
/// non-native build reports `skipped`, and a toolchain outside the driver's
/// two library assumptions reports `unsupported-c-library` or
/// `unsupported-cxx-library`; a compile or link failure reports `failed`,
/// which the test turns into a panic, so a driver that stops building cannot
/// quietly delete the coverage.
fn build_callback_boundaries(source: &Path, include_dir: &Path) {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS=skipped");
        return;
    }
    // The driver's leak assertion interposes `free` and forwards to
    // `__libc_free`, which only exists on glibc. Everywhere else the driver
    // would fail to LINK, and a link failure is supposed to mean a real
    // regression — so screen the C library out here instead.
    let glibc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    if !glibc {
        println!(
            "cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS=unsupported-c-library"
        );
        return;
    }
    let out_dir = out_dir();
    let binary = out_dir.join("callback_boundaries");
    let tool = cpp20_build(include_dir).get_compiler();

    // And the C++ standard library, which the C-library screen above does not
    // imply: a linux-gnu target built with `-stdlib=libc++` links and runs.
    if !probe_libstdcxx(&tool, &out_dir) {
        println!(
            "cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS=unsupported-cxx-library"
        );
        return;
    }

    let mut command = tool.to_command();
    command
        .arg("-std=c++20")
        .arg("-O1")
        .arg("-g")
        .arg("-Wall")
        .arg("-Wextra")
        .arg(format!("-I{}", include_dir.display()))
        .arg("-pthread")
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .arg(format!("-L{}", out_dir.display()))
        .arg("-lovstorage_c_source")
        .arg("-ldl");
    match command.status() {
        Ok(status) if status.success() => {
            println!("cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS=built");
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_BIN={}",
                binary.display()
            );
        }
        result => {
            println!(
                "cargo:rustc-env=OVSTORAGE_C_SOURCE_CALLBACK_BOUNDARIES_STATUS=failed:\
                 callback_boundaries_cpp20.cpp did not build ({result:?})"
            );
        }
    }
}

/// (source, binary, status env, binary env, ASan env) for each regression.
const TASK_DROP_REPROS: [(&str, &str, &str, &str, &str); 2] = [
    (
        "task_drop_before_await.cpp",
        "task_drop_before_await",
        "OVSTORAGE_C_SOURCE_TASK_DROP_STATUS",
        "OVSTORAGE_C_SOURCE_TASK_DROP_BIN",
        "OVSTORAGE_C_SOURCE_TASK_DROP_ASAN",
    ),
    (
        "task_drop_after_worker_park.cpp",
        "task_drop_after_worker_park",
        "OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_STATUS",
        "OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_BIN",
        "OVSTORAGE_C_SOURCE_TASK_WORKER_PARK_ASAN",
    ),
];

/// Return true only if `tool` compiles against libstdc++.
///
/// The allocation-failure driver arms its trap on an EXACT byte count, and
/// those counts are libstdc++'s: `len + 1` for a `std::string` copy of a
/// `len >= 16` C string, `n` for a range insert of `n` bytes into an empty
/// `std::vector`. Under a standard library that sizes differently the trap
/// arms a size that never occurs, and the driver's own "the injection never
/// fired" guard turns that into a hard failure.
///
/// That failure is right for a SUPPORTED toolchain whose allocation behaviour
/// changed — a real regression in an assumption the driver depends on — and
/// wrong for a toolchain the driver simply does not cover, where the answer is
/// a skip. Only a screen can tell those two apart, so the screen lives here
/// and the trap keeps its exact match.
///
/// The probe compiles with `tool`, which carries the crate's configured
/// compiler and the environment's `CXXFLAGS`, so a `-stdlib=libc++` build is
/// screened by the flags it actually builds with rather than by a guess from
/// the target triple (which does not encode the C++ standard library at all).
fn probe_libstdcxx(tool: &cc::Tool, out_dir: &Path) -> bool {
    let probe_source = out_dir.join("libstdcxx_probe.cpp");
    let probe_body = "#include <string>\n\
                      #if !defined(__GLIBCXX__)\n\
                      #error \"not libstdc++\"\n\
                      #endif\n\
                      int main() { return 0; }\n";
    if fs::write(&probe_source, probe_body).is_err() {
        return false;
    }
    tool.to_command()
        .arg("-std=c++20")
        .arg("-fsyntax-only")
        .arg(&probe_source)
        // The `#error` is the expected negative result, not build noise.
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Return true only if `tool` can both compile+link AND run a trivial
/// `-fsanitize=address` program: a link that succeeds but whose runtime is
/// absent would otherwise fail at test time. Only reached on a native build
/// (`HOST == TARGET`), so executing the probe here is safe.
///
/// `stem` names the probe's source and binary so the C and C++ drivers —
/// which can differ in sanitizer support — get independent answers without
/// colliding in `OUT_DIR`. One probe body serves both: it is valid C and
/// valid C++, and `g++` compiles a `.c` input as C++.
fn probe_asan(tool: &cc::Tool, out_dir: &Path, stem: &str) -> bool {
    probe_sanitizer(tool, out_dir, stem, "-fsanitize=address")
}

/// A leak LeakSanitizer cannot miss.
///
/// The verdict this source feeds is taken in `roundtrip.rs` at test time, not
/// here — see [`build_leak_self_check`] — so the exit code and stderr the
/// probe must produce are named there.
///
/// The hard part is REACHABILITY, not liveness. LSan scans globals, registers
/// and thread stacks as roots, so a block still pointed at by any of them is
/// correctly not a leak — parking the pointer in a global to stop the
/// optimiser eliding the allocation would make this report "LSan is broken" on
/// a working toolchain. So: allocate in a function that has RETURNED by scan
/// time, hide each pointer's value behind a barrier rather than by storing it
/// somewhere scannable, drop the reference, and overwrite the frame that held
/// it.
///
/// MANY blocks rather than one, which is load-bearing and is the calibration
/// this probe has already got wrong twice. A stale copy of the most recent
/// pointer routinely survives in a callee-saved register or an unscrubbed
/// stack slot, and LSan is then RIGHT to call that block reachable. With a
/// single allocation that one stale root hides the whole leak and the probe
/// concludes the toolchain is broken.
///
/// The probe as shipped leaks `LEAK_BLOCKS` × `LEAK_BLOCK_BYTES` = 64 blocks
/// of 1 KiB. The superseded version leaked one 64 KiB block; measured on
/// x86-64 Linux with gcc 11.4 and gcc 12.3, that one block reports nothing and
/// exits 0, two report exactly one of the two, and 64 report all 64. Whether
/// the same holds on other compilers or platforms is untested — the point is
/// only that block count, not total bytes, is what moved this probe from
/// silent to reporting on every toolchain measured.
///
/// Maintainer note: if a future toolchain reports nothing here, raise
/// `LEAK_BLOCKS` before suspecting the sanitizer — more blocks means more
/// that cannot all be pinned by the handful of stale roots a return path
/// leaves behind. `LEAK_BLOCK_BYTES` is incidental (any size a stale register
/// can point at will do); `scratch[4096]` need only exceed the frame
/// `leak_blocks` used, so it too has slack. Only after raising the count and
/// still seeing silence is "this LSan does not work" the right conclusion.
///
/// Kept in step with the pure-C examples gate's self-check
/// (`tools/ovtasks/_c_source_examples.py`, `_LEAK_SELF_CHECK_SOURCE`, which
/// carries the reciprocal note); the two drivers are separate
/// programs, so each carries its own copy.
const LEAK_SELF_CHECK_SOURCE: &str = r#"#include <stddef.h>
#include <stdlib.h>

#define LEAK_BLOCKS 64
#define LEAK_BLOCK_BYTES 1024

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
"#;

/// Compile — but do not run — the LeakSanitizer self-check.
///
/// Whether the ASan runtime LINKS is a build-time fact and is settled here.
/// Whether its leak half REPORTS is a property of the machine the test runs
/// on, so the verdict is deliberately NOT taken here: `cargo:rustc-env` values
/// are baked into the test binary, and a build and a run are not guaranteed to
/// share a machine or a toolchain. A developer's `OUT_DIR` survives a
/// toolchain upgrade untouched, and a compiled test binary can be executed
/// somewhere other than where it was built. Either way a verdict recorded here
/// would answer for a host it never saw, and the test would certify
/// leak-cleanliness while observing nothing — under the very flag meant to
/// prevent that. (CI is not the motivating case: `Swatinem/rust-cache` drops
/// workspace-member `build/` and `.fingerprint/` entries before saving, so a
/// member build script re-runs each job.) So the build stage
/// only produces the probe; `roundtrip.rs` executes it each run.
///
/// Returns the probe's path, or `None` if it could not be built.
fn build_leak_self_check(tool: &cc::Tool, out_dir: &Path, stem: &str) -> Option<PathBuf> {
    let source = out_dir.join(format!("{stem}_leak_self_check.c"));
    fs::write(&source, LEAK_SELF_CHECK_SOURCE).ok()?;
    let binary = out_dir.join(format!("{stem}_leak_self_check"));
    let compiled = tool
        .to_command()
        .arg("-fsanitize=address")
        .arg("-fno-omit-frame-pointer")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    compiled.then_some(binary)
}

/// As [`probe_asan`], for an arbitrary `-fsanitize=` selection.
fn probe_sanitizer(tool: &cc::Tool, out_dir: &Path, stem: &str, flag: &str) -> bool {
    let probe_source = out_dir.join(format!("{stem}_probe.c"));
    if fs::write(&probe_source, "int main(void) { return 0; }\n").is_err() {
        return false;
    }
    let probe_binary = out_dir.join(if tool.is_like_msvc() {
        format!("{stem}_probe.exe")
    } else {
        format!("{stem}_probe")
    });
    let mut command = tool.to_command();
    if tool.is_like_msvc() {
        let msvc_flag = match flag {
            "-fsanitize=address" => "/fsanitize=address",
            _ => return false,
        };
        // As in build_task_drop_repros: without /Fo, cl drops the probe object
        // in the working directory, which for a build script is the crate root.
        command
            .current_dir(out_dir)
            .arg(msvc_flag)
            .arg(&probe_source)
            .arg(format!(
                "/Fo{}",
                out_dir.join(format!("{stem}_probe.obj")).display()
            ))
            .arg(format!("/Fe:{}", probe_binary.display()));
    } else {
        command
            .arg(flag)
            .arg(&probe_source)
            .arg("-o")
            .arg(&probe_binary);
    }
    let compiled = command
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !compiled {
        return false;
    }
    std::process::Command::new(&probe_binary)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn compile_inspect_fixture(include_dir: &Path, source: &Path, output: &Path) {
    let compiler = c_build(include_dir).get_compiler();
    let mut command = compiler.to_command();
    let out_dir = out_dir();

    if compiler.is_like_msvc() {
        // /LD builds a DLL; /Fo keeps the object out of the crate root.
        command
            .current_dir(&out_dir)
            .arg("/nologo")
            .arg("/std:c11")
            .arg("/LD")
            .arg("/DOVC_INSPECT_FIXTURE")
            .arg(format!("/I{}", include_dir.display()))
            .arg(source)
            .arg(format!(
                "/Fo{}",
                out_dir
                    .join("ovstorage_c_source_inspect_fixture.obj")
                    .display()
            ))
            .arg(format!("/Fe:{}", output.display()));
    } else {
        command
            .arg("-std=c99")
            .arg("-fPIC")
            .arg("-shared")
            .arg("-DOVC_INSPECT_FIXTURE")
            .arg(format!("-I{}", include_dir.display()))
            .arg(source)
            .arg("-o")
            .arg(output);
    }
    let result = command
        .output()
        .unwrap_or_else(|error| panic!("failed to invoke {}: {error}", compiler.path().display()));
    assert!(
        result.status.success(),
        "failed to build inspect fixture with {}:\n{}\n{}",
        compiler.path().display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

/// Build a genuine auth-capable C plugin whose decoder helpers are linked into
/// the plugin image. The undefined-symbol check is load-bearing: it prevents
/// this fixture from passing by resolving the SDK helpers from its Rust test
/// host at `dlopen` time.
fn compile_auth_decoder_plugin_fixture(
    include_dir: &Path,
    fixture_source: &Path,
    source_dir: &Path,
    output: &Path,
) {
    const SDK_SOURCES: [&str; 4] = ["auth_credential.c", "plugin_values.c", "plat.c", "utf8.c"];
    let compiler = c_build(include_dir).get_compiler();
    let mut command = compiler.to_command();
    let out_dir = out_dir();
    let sdk_sources = SDK_SOURCES.map(|name| source_dir.join(name));

    if compiler.is_like_msvc() {
        // /LD fails on unresolved externals by default. `current_dir` keeps
        // each source's object out of the crate root; a single `/Fo<file>` is
        // invalid when cl compiles this multi-source link. The fixture source
        // exports only the plugin handshake plus its test probe.
        command
            .current_dir(&out_dir)
            .arg("/nologo")
            .arg("/std:c11")
            .arg("/LD")
            .arg("/W4")
            .arg("/WX")
            .arg(format!("/I{}", include_dir.display()))
            .arg(fixture_source)
            .args(&sdk_sources)
            .arg(format!("/Fe:{}", output.display()));
    } else {
        command
            .arg("-std=c99")
            .arg("-fPIC")
            .arg("-shared")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg("-D_POSIX_C_SOURCE=200809L")
            .arg("-D_XOPEN_SOURCE=700")
            .arg("-D_FILE_OFFSET_BITS=64")
            .arg(format!("-I{}", include_dir.display()))
            .arg(fixture_source)
            .args(&sdk_sources);
        let target_os = std::env::var("CARGO_CFG_TARGET_OS");
        if target_os.as_deref() == Ok("macos") {
            command.arg("-Wl,-undefined,error");
        } else {
            command.arg("-Wl,--no-undefined");
        }
        command.arg("-o").arg(output).arg("-pthread");
        if target_os.as_deref() != Ok("macos") {
            command.arg("-ldl");
        }
    }
    let result = command
        .output()
        .unwrap_or_else(|error| panic!("failed to invoke {}: {error}", compiler.path().display()));
    assert!(
        result.status.success(),
        "failed to build bundled C auth decoder plugin with {}:\n{}\n{}",
        compiler.path().display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
