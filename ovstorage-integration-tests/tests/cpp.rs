// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C++ binding runner. Expands the shared scenario contract into one test per
//! `(backend, scenario)`, driven through the shipped C++20 wrapper
//! (`ovstorage-c-source/include/ovstorage.hpp`) over a Rust -> C++ live
//! handoff.
//!
//! ## Why a handoff, and not a Stack composed in C++
//!
//! The shipped C++ surface uses the pure-C source distribution in
//! `ovstorage-c-source/`, and that runtime is FILE-BACKEND-ONLY BY DESIGN:
//! no HTTP client, no TLS, no redirect follower. Azure and S3 answer every
//! read with `ReadResult::Redirect`, which its dispatcher rejects outright, so
//! a Stack composed inside pure C cannot read a cloud object at all.
//!
//! So this leg composes the SAME `AppState`/`Stack` the Rust leg uses — one
//! `ovstorage_integration_tests::app()` per process, over
//! the explicit `alias → redirect_follower → retry → router` Layer chain,
//! with the follower that makes cloud reads work — mints one owned handle over
//! its root with [`ovstorage::export_handle`], and hands that to the C++
//! driver. The driver imports it with `ovstorage_import_handle` and drives the
//! scenario against the C++ RAII types. That is the path a real C++ consumer
//! takes: embed the Rust runtime, hand C++ a handle.
//!
//! Reusing `app()` is deliberate. A second, C++-only Stack would be a second
//! composition to keep in step with the first, and the moment it drifted this
//! leg would be reporting coverage of a stack no other leg runs.
//!
//! ## Linkage
//!
//! The driver `.so` (`target/test-plugins/libovsx_cloud_cpp_driver.so`, staged
//! by `tools/ovtasks/_test_plugins.py` from `tests/cpp/CMakeLists.txt`) bundles
//! the FULL pure-C source distribution and is `dlopen`ed `RTLD_LOCAL`. It must
//! NEVER be linked against `ovstorage-plugin`'s rlib — which this test binary
//! *does* link — because both export `ovstorage_plugin_*` symbols and that is
//! a hard collision. Same constraint, same reason as
//! `ovstorage-core/ovstorage/tests/handoff_c_source.rs`, which runs the same
//! mechanism in the opposite direction.
//!
//! ## Where each gate lives
//!
//! Target *selection* happens here, exactly as in `src/scenarios.rs`: the
//! `(backend, access)` lookup, and the capability predicates the directory
//! scenarios select on. Capability *gating within* a scenario happens in the
//! driver, against the root's real advertised `RootInfo` capabilities read back
//! over the bridge — the read-family cases gate there on `supports_list` /
//! `supports_write` / `supports_version_listing` directly. The write-family
//! arms still gate host-side through `HostCap` even though
//! `OvStorage_Capabilities` carries those flags. TODO: fold the `HostCap`
//! gates into the driver when the stale write-family arms are rebuilt.
//!
//! `OVSTORAGE_REQUIRE_LIVE_BACKENDS` / `OVSTORAGE_FORBID_LIVE_BACKENDS` are
//! enforced by `app()` at construction time, so this leg inherits them rather
//! than reimplementing them.

use std::ffi::{CStr, CString};
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

// `ovstorage::Layer` is deliberately NOT imported, for the same reason
// `src/scenarios.rs` avoids it: `LayerExt` shadows eleven `Layer` primitive
// names, so importing both makes every ergonomic call ambiguous. This leg needs
// no `Layer`-only primitive — the version-aware cleanup that did lives in
// `reclaim_object`.
use ovstorage::ext::LayerExt as _;
use ovstorage::{Capabilities, ListOptions, ObjectKind, Url, ffi};
use ovstorage_integration_tests::{
    Access, AppState, Backend, Target, app, block_on, reclaim_directory, reclaim_object, skip,
};

/// 0 pass, 77 a visible skip, anything else a failure. Mirrors the contract
/// documented on `ovsx_cloud_driver_run` in `tests/cpp/cloud_driver.cpp`.
const DRIVER_SKIP: c_int = 77;

/// Size of the buffer the driver writes its skip reason / failure message
/// into. Messages quote addresses and backend error text, so it is generous;
/// the driver truncates rather than overflowing.
const ERR_LEN: usize = 2048;

/// `int ovsx_cloud_driver_run(OvStoragePlugin_LayerHandle handle,
///                            const char* scenario, const char* root_url,
///                            const char* prefix, char* err, size_t err_len)`
///
/// `handle` is passed BY VALUE and is consumed by the call (the driver feeds it
/// straight to `ovstorage_import_handle`). Moving it into the call is what
/// stops this side's `ffi::LayerHandle` destructor — which would invoke the
/// vtable `drop` slot — from also running.
type DriverRunFn = unsafe extern "C" fn(
    ffi::LayerHandle,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_char,
    usize,
) -> c_int;

/// A live `dlopen` of the C++ driver plus its entry point.
///
/// The mapping is pinned for the process lifetime: the driver owns the pure-C
/// implementation's detached, process-lifetime worker pool (`ovc_runtime_ensure`
/// runs on the first import), and `dlclose` would unmap code those workers may
/// still execute during test-process teardown.
struct Driver {
    #[allow(dead_code)]
    library: ManuallyDrop<libloading::Library>,
    run: DriverRunFn,
}

/// Locate the driver staged by `_test_plugins.py` under `target/test-plugins/`
/// — a fixed, deterministic location. Like the pure-C handoff fixture, this
/// artifact is never built by `cargo` (only by the staging script's own cmake
/// invocation), so there is no per-artifact `OVSTORAGE_*_OVERRIDE` env to
/// plumb.
fn driver_so() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // <target>/<profile>/deps/<test-binary> -> <target>/<profile>/deps ->
    // <target>/<profile> -> <target>
    let target_dir = exe.parent()?.parent()?.parent()?;
    let file = if cfg!(target_os = "macos") {
        "libovsx_cloud_cpp_driver.dylib"
    } else {
        "libovsx_cloud_cpp_driver.so"
    };
    let path = target_dir.join("test-plugins").join(file);
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
        "C++ cloud driver not found at {} but OVSTORAGE_REQUIRE_TEST_PLUGINS is set: run \
         `make build-test-plugins` (it needs cmake ≥3.16 and a C++20 toolchain — GCC 13+, \
         Clang 17+)",
        path.display(),
    );
    None
}

fn driver() -> Option<&'static Driver> {
    static DRIVER: OnceLock<Option<Driver>> = OnceLock::new();
    DRIVER
        .get_or_init(|| {
            let so = driver_so()?;
            // SAFETY: our own workspace-staged driver, built from the vendored
            // pure-C sources plus `cloud_driver.cpp`, with no runtime linkage
            // beyond libc/libstdc++/pthread/dl.
            let library =
                unsafe { libloading::Library::new(&so) }.expect("dlopen the C++ cloud driver");
            // SAFETY: `cloud_driver.cpp` exports this exact symbol and
            // signature under `extern "C"`.
            let run = *unsafe {
                library
                    .get::<DriverRunFn>(b"ovsx_cloud_driver_run\0")
                    .expect("resolve ovsx_cloud_driver_run")
            };
            Some(Driver {
                library: ManuallyDrop::new(library),
                run,
            })
        })
        .as_ref()
}

// === per-scenario target selection + host-side capability gates ===

/// How a scenario picks its [`Target`], mirroring `src/scenarios.rs`.
#[derive(Copy, Clone)]
enum Selector {
    /// `app.target(backend, access)`.
    Access(Access),
    /// A backend with real directory inodes (file = native, Azure = ADLS Gen2
    /// HNS).
    RealDirectories,
    /// A flat object store whose directories are marker objects.
    FlatDirectories,
}

/// A capability gate the write-family arms apply host-side.
/// `OvStorage_Capabilities` carries these flags too; the read-family cases
/// already gate on them inside the driver, and the module doc's TODO covers
/// folding these host-side gates in with the write-family rebuild.
#[derive(Copy, Clone)]
enum HostCap {
    Write,
    Delete,
}

impl HostCap {
    fn satisfied(self, caps: &Capabilities) -> bool {
        match self {
            HostCap::Write => caps.supports_write,
            HostCap::Delete => caps.supports_delete,
        }
    }

    fn name(self) -> &'static str {
        match self {
            HostCap::Write => "supports_write",
            HostCap::Delete => "supports_delete",
        }
    }
}

/// A scenario the C++ API cannot express, and the condition under which that
/// is true.
///
/// Distinct from a skip ON PURPOSE. `skip` means "this backend did not offer
/// the behavior", and the coverage baseline in `src/lib.rs` turns that into a
/// failure on a required target. An ABI limit is the opposite claim — the
/// backend offers it and THIS BINDING cannot ask — so routing it through `skip`
/// would either fail a run for a gap that is not the backend's, or (worse)
/// force the baseline to be loosened until it no longer catches the C++ leg
/// quietly running less.
struct AbiLimit {
    /// Why the scenario cannot run, in the same voice as the driver's own
    /// message. Printed verbatim.
    reason: &'static str,
    /// When it bites. `|_| true` for a verb the C ABI simply does not have;
    /// a capability predicate for one that is only reachable on backends whose
    /// richer path the ABI does carry.
    applies: fn(&Capabilities) -> bool,
}

struct Case {
    selector: Selector,
    host_caps: &'static [HostCap],
    abi_limits: &'static [AbiLimit],
}

/// The C ABI has no entry point at all for this verb.
const ALWAYS: fn(&Capabilities) -> bool = |_| true;

/// The per-scenario contract, kept beside the Rust leg's own gates so the two
/// can be read against each other.
///
/// The scenarios the C++ API cannot express declare no host-side capability
/// gate: they carry an [`AbiLimit`] instead, which states the ABI's own reason
/// rather than blaming a backend for a verb it does provide. This list is the
/// reviewable statement of how much less the C++ leg covers than the Rust one —
/// everything NOT listed here is expected to run, and the coverage baseline
/// fails the run if it does not.
fn case_for(scenario: &str) -> Case {
    let (selector, host_caps, abi_limits): (Selector, &'static [HostCap], &'static [AbiLimit]) =
        match scenario {
            "write_stat_read" => (Selector::Access(Access::Default), &[HostCap::Write], &[]),
            "delete" => (
                Selector::Access(Access::Default),
                &[HostCap::Write, HostCap::Delete],
                &[],
            ),
            "list_prefix_delimiter" => (Selector::Access(Access::Default), &[HostCap::Write], &[]),
            "list_recursive_and_pagination" => {
                (Selector::Access(Access::Default), &[HostCap::Write], &[])
            }
            "copy" => (Selector::Access(Access::Default), &[HostCap::Write], &[]),
            "rename" => (
                Selector::Access(Access::Default),
                &[HostCap::Write, HostCap::Delete],
                &[],
            ),
            "update_metadata" => (
                Selector::Access(Access::Default),
                &[HostCap::Write],
                // Reachable wherever the backend has a real metadata patch
                // (Azure, GCS, file); on a rewrite-emulation backend (S3) it is
                // not, because `OvStorage_UpdateMetadataOptions` has no
                // `allow_rewrite_emulation` flag and the dispatcher
                // zero-initializes the plugin request.
                &[AbiLimit {
                    reason: "the C ABI's OvStorage_UpdateMetadataOptions has no \
                             allow_rewrite_emulation flag, and this backend can only emulate the \
                             patch by rewriting the object",
                    applies: |caps| !caps.supports_native_metadata_patch,
                }],
            ),
            "attribution_round_trip" => (
                Selector::Access(Access::Default),
                &[HostCap::Write],
                // The C ABI carries no request extensions, so this leg cannot
                // present a principal to an attribution layer. The driver
                // mirrors the portable half instead — the reserved key stored
                // and read back under its exact spelling through
                // `update_metadata` — which reaches only a native metadata
                // patch, for the same reason as `update_metadata` above.
                &[AbiLimit {
                    reason: "the C ABI's OvStorage_UpdateMetadataOptions has no \
                             allow_rewrite_emulation flag, and this backend can only emulate the \
                             patch by rewriting the object",
                    applies: |caps| !caps.supports_native_metadata_patch,
                }],
            ),
            "message_annotation" => (
                Selector::Access(Access::Default),
                &[],
                // The Rust scenario stashes a per-operation `message` through
                // `WriteOptions` and `UpdateMetadataOptions`. Neither
                // `OvStorage_WriteOptions` nor the opaque
                // `OvStorage_UpdateMetadataOptions` (create/destroy/set/remove)
                // carries one, so this leg has no way to ask a backend to
                // record the annotation at all.
                &[AbiLimit {
                    reason: "the C ABI carries no per-operation message: OvStorage_WriteOptions \
                             has no message field and OvStorage_UpdateMetadataOptions has only \
                             set/remove, so this leg cannot ask a backend to stash the annotation",
                    applies: ALWAYS,
                }],
            ),
            "check_access" => (Selector::Access(Access::Default), &[], &[]),
            "error_path_not_found" => (Selector::Access(Access::Default), &[], &[]),
            "read_stream_and_materialize" => {
                (Selector::Access(Access::Default), &[HostCap::Write], &[])
            }
            "conditional_write" => (
                Selector::Access(Access::Default),
                &[HostCap::Write],
                // The driver runs only the create-only half, so a backend
                // offering ONLY if-match has nothing the current case can
                // drive. TODO: rebuild the etag-CAS half against
                // `WriteOptions::if_match_etag`.
                &[AbiLimit {
                    reason: "the C++ conditional_write case drives only the create-only half \
                             (its etag-CAS half is not yet rebuilt against \
                             WriteOptions::if_match_etag — issue #614), and this backend offers \
                             no create-only write",
                    applies: |caps| !caps.supports_no_overwrite_write,
                }],
            ),
            "directory_ops" => (Selector::RealDirectories, &[], &[]),
            "directory_marker_ops" => (Selector::FlatDirectories, &[], &[]),
            "list_versions" => (Selector::Access(Access::Versioned), &[HostCap::Write], &[]),
            "range_read" => (
                Selector::Access(Access::Default),
                &[],
                &[AbiLimit {
                    reason: "the C++ range_read case is not yet rebuilt against ovstorage.hpp's \
                             ranged read_bytes(address, options) overload, which \
                             read_only_range_read drives (issue #614)",
                    applies: ALWAYS,
                }],
            ),
            "key_encoding" => (
                Selector::Access(Access::Default),
                &[],
                &[AbiLimit {
                    reason: "no address-composition entry point on the C ABI (Rust's \
                             address::join_relative has no C/C++ equivalent), so there is no \
                             reserved-character encoding behavior to exercise",
                    applies: ALWAYS,
                }],
            ),
            "write_stream" => (
                Selector::Access(Access::Default),
                &[],
                &[AbiLimit {
                    reason: "the C++ write_stream case is not yet rebuilt against \
                             ovstorage.hpp's write_stream entry point (issue #614)",
                    applies: ALWAYS,
                }],
            ),
            "get_latest_version" => (
                Selector::Access(Access::Versioned),
                &[],
                &[AbiLimit {
                    reason: "the C++ get_latest_version case is not yet rebuilt against \
                             ovstorage.hpp's get_latest_version entry point, which \
                             read_only_version_pinning drives (issue #614)",
                    applies: ALWAYS,
                }],
            ),
            // The read family gates entirely in the driver: supports_list,
            // !supports_write, and (for the version scenario)
            // supports_version_listing are all carried by
            // OvStorage_Capabilities.
            "read_only_list_stat_read" | "read_only_range_read" | "read_only_version_pinning" => {
                (Selector::Access(Access::Default), &[], &[])
            }
            other => panic!(
                "no C++ case for scenario {other:?}: the shared scenario contract grew and \
                 tests/cpp.rs was not updated"
            ),
        };
    Case {
        selector,
        host_caps,
        abi_limits,
    }
}

/// Resolve the target, or the visible skip line that explains its absence.
fn resolve<'a>(
    app: &'a AppState,
    backend: Backend,
    case: &Case,
) -> Result<&'a Target, (Access, &'static str)> {
    match case.selector {
        Selector::Access(access) => app
            .target(backend, access)
            .ok_or((access, "target not configured")),
        Selector::RealDirectories => app
            .target_where(backend, |c| {
                c.has_real_directories && c.supports_create_directory && c.supports_delete_directory
            })
            .ok_or((Access::Default, "no real-directory target")),
        Selector::FlatDirectories => app
            .target_where(backend, |c| {
                !c.has_real_directories
                    && c.supports_create_directory
                    && c.supports_delete_directory
            })
            .ok_or((Access::Default, "no flat directory-marker target")),
    }
}

// === driving one case ===

/// Every address a driver scenario can mutate, derived before crossing the
/// FFI boundary. The driver tries to delete its own fixture on success, but an
/// unpinned delete retains history on version-enabled storage. Reclaiming this
/// ledger after every return therefore matters even when the driver reports a
/// pass and a recursive prefix listing is empty.
#[derive(Default)]
struct TouchedAddresses {
    objects: Vec<Url>,
    directories: Vec<Url>,
}

fn touched_addresses(scenario: &str, prefix: &Url) -> TouchedAddresses {
    let (objects, directories): (&[&str], &[&str]) = match scenario {
        "write_stat_read" => (&["obj.bin"], &[]),
        "delete" => (&["gone.bin"], &[]),
        "list_prefix_delimiter" | "list_recursive_and_pagination" => {
            (&["a.txt", "b.txt", "sub/c.txt"], &[])
        }
        "copy" => (&["src.bin", "dst.bin"], &[]),
        "rename" => (&["from.bin", "to.bin"], &[]),
        "update_metadata" => (&["meta.bin"], &[]),
        "attribution_round_trip" => (&["attributed.bin"], &[]),
        "read_stream_and_materialize" => (&["stream-read.bin"], &[]),
        "conditional_write" => (&["cas.bin"], &[]),
        "directory_ops" | "directory_marker_ops" => (&[], &["adir"]),
        "list_versions" => (&["versioned.bin"], &[]),
        // These cases are read-only or are rejected as ABI-limited before the
        // driver is invoked. Naming every contract entry here makes that
        // absence deliberate and keeps additions from inheriting no cleanup.
        "check_access"
        | "error_path_not_found"
        | "range_read"
        | "key_encoding"
        | "message_annotation"
        | "write_stream"
        | "get_latest_version"
        | "read_only_list_stat_read"
        | "read_only_range_read"
        | "read_only_version_pinning" => (&[], &[]),
        other => panic!(
            "no touched-address ledger for scenario {other:?}: update cleanup before running it"
        ),
    };
    let join = |suffix: &&str| {
        prefix
            .join(suffix)
            .unwrap_or_else(|error| panic!("append {suffix:?} to {prefix}: {error:?}"))
    };
    TouchedAddresses {
        objects: objects.iter().map(join).collect(),
        directories: directories.iter().map(join).collect(),
    }
}

async fn reclaim_touched(target: &Target, touched: TouchedAddresses) {
    for address in touched.objects {
        reclaim_object(target, address).await;
    }
    for address in touched.directories {
        reclaim_directory(target, address).await;
    }
}

fn run_case(backend: Backend, scenario: &str) {
    let Some(driver) = driver() else {
        eprintln!(
            "⊘ SKIPPED [{}] {scenario}: C++ cloud driver not staged. Run \
             `make build-test-plugins` (needs cmake ≥3.16 and a C++20 toolchain).",
            backend.label(),
        );
        return;
    };

    block_on(async move {
        let app = app().await;
        let case = case_for(scenario);
        let target = match resolve(app, backend, &case) {
            Ok(target) => target,
            Err((access, why)) => return skip(backend, access, scenario, why),
        };
        if let Some(why) = ovstorage_integration_tests::scenario_exclusion(target, scenario) {
            return skip(target.backend, target.access, scenario, why);
        }
        // Before the host-capability gates and before the driver call: what the
        // binding cannot ask for is not something the backend failed to
        // provide, and it costs a live round trip to discover in the driver.
        for limit in case.abi_limits {
            if (limit.applies)(&target.caps) {
                eprintln!(
                    "⊘ ABI-LIMITED [{}:{}] {scenario}: {}",
                    target.backend.label(),
                    target.access.label(),
                    limit.reason,
                );
                return;
            }
        }
        for cap in case.host_caps {
            if !cap.satisfied(&target.caps) {
                return skip(
                    target.backend,
                    target.access,
                    scenario,
                    &format!(
                        "missing capability {} (gated host-side until the write-family \
                         arms are rebuilt against the current C ABI — issue #614)",
                        cap.name()
                    ),
                );
            }
        }

        // Run-unique, so parallel cases and prior runs never collide, and so
        // the sweep below can reclaim exactly what this case created.
        let prefix = target.addr(&ovstorage_integration_tests::unique_prefix(scenario));
        // Resolve the complete cleanup set before handing execution to the
        // driver. A failure or panic in that thread cannot hide an address the
        // host did not learn until afterwards.
        let touched = touched_addresses(scenario, &prefix);
        // Mint ONE owned handle over the routed Stack root for this call. The
        // driver consumes it; the producer (this process, plus the plugin
        // runtime driving the Stack) outlives it because `AppState` lives in a
        // process-wide `OnceCell`.
        let layer: Arc<dyn ovstorage::Layer> = app.stack.clone();
        let handle = ovstorage::export_handle(layer);

        let result = invoke(driver.run, handle, scenario, target.root.as_str(), &prefix).await;

        // Always reclaim the known addresses, including version history left
        // by the driver's own successful deletes. Do this before inspecting
        // the join result so a driver-thread failure cannot bypass cleanup.
        reclaim_touched(target, touched).await;
        // Keep the recursive sweep as a backstop for a driver implementation
        // that accidentally creates something outside its declared ledger.
        sweep(target, &prefix).await;

        let (code, message) =
            result.unwrap_or_else(|e| panic!("the C++ driver thread panicked: {e}"));

        match code {
            0 => {}
            DRIVER_SKIP => skip(target.backend, target.access, scenario, &message),
            _ => panic!(
                "C++ [{}:{}] {scenario} failed (code {code}): {message}",
                target.backend.label(),
                target.access.label(),
            ),
        }
    });
}

/// Cross into the driver on a blocking thread.
///
/// The call parks until the scenario completes. It does not deadlock the
/// suite's runtime — the exported handle's vtable thunks spawn onto
/// `ovstorage-plugin`'s own process-wide runtime, not this one — but it would
/// hold a worker thread for the duration of live cloud I/O, so it goes to the
/// blocking pool instead.
async fn invoke(
    run: DriverRunFn,
    handle: ffi::LayerHandle,
    scenario: &str,
    root: &str,
    prefix: &Url,
) -> Result<(c_int, String), tokio::task::JoinError> {
    let scenario = CString::new(scenario).expect("scenario name has no interior NUL");
    let root = CString::new(root).expect("address root has no interior NUL");
    let prefix = CString::new(prefix.as_str()).expect("address prefix has no interior NUL");
    tokio::task::spawn_blocking(move || {
        let mut err = vec![0u8; ERR_LEN];
        // SAFETY: every pointer is valid for the call and outlives it; `err`
        // is writable for `ERR_LEN` bytes; `handle` is a live, freshly
        // exported ABI pair whose ownership transfers to the callee.
        let code = unsafe {
            run(
                handle,
                scenario.as_ptr(),
                root.as_ptr(),
                prefix.as_ptr(),
                err.as_mut_ptr().cast::<c_char>(),
                err.len(),
            )
        };
        let message = CStr::from_bytes_until_nul(&err)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        (code, message)
    })
    .await
}

/// Recursively reclaim anything left under `prefix`.
///
/// Delegates to [`reclaim_object`], which decides pinned-vs-unpinned from the
/// ROOT's capabilities rather than from `Access::Versioned`. The distinction
/// matters: the default Azure target is pointed at a version-enabled container
/// too, so keying on the access label left every default-target object's
/// version history behind on every run.
///
/// Objects the driver deleted itself are reclaimed from the explicit ledger
/// before this backstop runs. They cannot be rediscovered here: unpinned
/// deletes retain history on a version-enabled root, while `list_page` returns
/// only live objects and `list_versions` is per-object.
async fn sweep(target: &Target, prefix: &Url) {
    let Ok(page) = target
        .stack()
        .list_page(
            prefix.clone(),
            ListOptions {
                recursive: true,
                ..Default::default()
            },
            None,
        )
        .await
    else {
        return;
    };
    // Files first, then directories: a recursive listing has no defined order,
    // and `delete_directory` on a directory whose children are still there
    // fails with DirectoryNotEmpty. Directories also need the directory verb —
    // `delete` on a real directory is an error, which is why this partitions
    // rather than reclaiming every entry the same way.
    let (dirs, files): (Vec<_>, Vec<_>) = page
        .items
        .into_iter()
        .partition(|entry| entry.kind != ObjectKind::File);
    for entry in files {
        reclaim_object(target, entry.address).await;
    }
    for entry in dirs {
        reclaim_directory(target, entry.address).await;
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn touched_ledger_names_objects_deleted_by_the_driver() {
        let prefix = Url::parse("test://fixture/run/").unwrap();

        let copy = touched_addresses("copy", &prefix);
        assert_eq!(
            copy.objects,
            [
                Url::parse("test://fixture/run/src.bin").unwrap(),
                Url::parse("test://fixture/run/dst.bin").unwrap(),
            ]
        );
        assert!(copy.directories.is_empty());

        let deleted = touched_addresses("delete", &prefix);
        assert_eq!(
            deleted.objects,
            [Url::parse("test://fixture/run/gone.bin").unwrap()]
        );
    }

    #[test]
    fn touched_ledger_distinguishes_directories() {
        let prefix = Url::parse("test://fixture/run/").unwrap();

        let touched = touched_addresses("directory_marker_ops", &prefix);

        assert!(touched.objects.is_empty());
        assert_eq!(
            touched.directories,
            [Url::parse("test://fixture/run/adir").unwrap()]
        );
    }
}

/// Expand the shared scenario contract into one `#[test]` per
/// `(backend, scenario)` — the same shape `app_suite!` gives the Rust leg, so
/// the two runners' output lines up case for case.
macro_rules! cpp_suite {
    (backends: [$($backend:ident),* $(,)?], scenarios: $scenarios:tt $(,)?) => {
        $( cpp_suite!(@backend $backend, $scenarios); )*
        cpp_suite!(@contract_test $scenarios);
    };
    (@backend $backend:ident, [$($scenario:ident),* $(,)?]) => {
        #[allow(non_snake_case)]
        mod $backend {
            $(
                #[test]
                fn $scenario() {
                    crate::run_case(
                        ovstorage_integration_tests::Backend::$backend,
                        stringify!($scenario),
                    );
                }
            )*
        }
    };
    (@contract_test [$($scenario:ident),* $(,)?]) => {
        #[test]
        fn scenario_invocation_matches_coverage_baseline() {
            ovstorage_integration_tests::assert_scenario_contract(
                &[$(stringify!($scenario)),*],
            );
        }
    };
}

cpp_suite! {
    backends: [File, Azure, S3, Gcs, Huggingface],
    scenarios: [
        write_stat_read,
        delete,
        list_prefix_delimiter,
        list_recursive_and_pagination,
        copy,
        rename,
        update_metadata,
        attribution_round_trip,
        message_annotation,
        check_access,
        error_path_not_found,
        range_read,
        read_stream_and_materialize,
        key_encoding,
        conditional_write,
        write_stream,
        directory_ops,
        directory_marker_ops,
        list_versions,
        get_latest_version,
        read_only_list_stat_read,
        read_only_range_read,
        read_only_version_pinning,
    ],
}
