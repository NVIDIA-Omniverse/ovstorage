// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storage-plugin loading contracts.
//!
//! - every first-party plugin cdylib next to the test binary loads through
//!   the current Layer ABI loader, and
//! - a dylib whose filename looks like a plugin but which has no plugin
//!   manifest symbol is skipped by bulk discovery without aborting startup.
//!
//! The sweep enumerates `libovstorage_plugin_*` artifacts rather than
//! hardcoding the first-party list, so any incompatible plugin artifact fails
//! this gate loudly. `make test` / `make test-ci` set
//! `OVSTORAGE_REQUIRE_TEST_PLUGINS` after `build-test-plugins` stages the
//! cdylibs, which turns an incomplete sweep into a hard error instead of
//! vacuous green.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ovstorage::{ErrorCode, LoadedLayerFactory};

const INCOMPATIBLE_ABI_STEM: &str = "ovstorage_plugin_test_incompatible_abi";

/// Matches a plugin cdylib by lib-name convention, the same way the on-disk
/// sweep does.
const PLUGIN_STEM_PREFIX: &str = "ovstorage_plugin_";

/// Loadable by filename but not a storage plugin: a proc-macro crate. Only
/// the on-disk sweep needs to exclude it; it is a `proc-macro` target and so
/// never appears among the workspace's cdylibs.
const PROC_MACRO_STEM: &str = "ovstorage_plugin_macros";

/// Written by `build-test-plugins` into the staging dir; see
/// `tools/ovtasks/_test_plugins.py`.
const STAGED_MANIFEST_NAME: &str = "staged-plugins.json";

/// An `OVSTORAGE_REQUIRE_*` switch is on only when set to exactly `1`.
///
/// Presence alone would make `...=0` turn the requirement ON, which is the
/// opposite of what anyone typing it means. `1` is the spelling the Makefile,
/// the workflows and the Python gates all use.
fn require_env(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("1")
}

/// The test binary's target profile dir (`target/<profile>/`), where
/// workspace builds and `build-test-plugins` leave the plugin cdylibs.
fn profile_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // .../target/<profile>/deps/<test-bin>  ->  .../target/<profile>
    exe.parent()
        .and_then(Path::parent)
        .expect("test binary has a target profile dir")
        .to_path_buf()
}

/// Platform-normalized plugin stem for a candidate artifact
/// (`libovstorage_plugin_foo.so` -> `ovstorage_plugin_foo`), or `None` if
/// the file isn't a plugin cdylib by name.
fn plugin_stem(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = if cfg!(target_os = "windows") {
        name.strip_suffix(".dll")?
    } else if cfg!(target_os = "macos") {
        name.strip_prefix("lib")?.strip_suffix(".dylib")?
    } else {
        name.strip_prefix("lib")?.strip_suffix(".so")?
    };
    stem.starts_with("ovstorage_plugin_")
        .then(|| stem.to_string())
}

fn plugin_artifacts() -> Vec<(String, PathBuf)> {
    let dir = profile_dir();
    let mut artifacts: Vec<(String, PathBuf)> = std::fs::read_dir(&dir)
        .expect("read profile dir")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if !path.is_file() {
                return None;
            }
            let stem = plugin_stem(&path)?;
            Some((stem, path))
        })
        .collect();
    artifacts.sort();
    artifacts
}

/// Lib stems of every cdylib target in the CURRENT workspace.
///
/// This is provenance, not an allowlist. The sweep still enumerates whatever
/// is on disk, so a newly added first-party plugin is covered by the ABI gate
/// the moment it exists — the property the glob is there for. What this adds
/// is the ability to tell a plugin *this checkout* can produce from an
/// artifact left behind by a different one.
///
/// The reachable case is branch-switching in a single checkout: build a branch
/// carrying plugin X, switch to one that lacks it, and
/// `libovstorage_plugin_x.so` persists in `target/<profile>/` with no crate in
/// the tree. Nothing else notices — a stale artifact can be perfectly fresh by
/// mtime, because there are no sources left to compare it against. Worktrees
/// are not affected: no `target-dir` is configured and `CARGO_TARGET_DIR` is
/// unset, so each gets its own `target/`.
///
/// `target.name` already carries the lib name, so the stem needs no derivation
/// from the package name — which matters because they differ
/// (`ovstorage-example-plugin-rust` builds `ovstorage_plugin_example_rust`).
///
/// `None` when the workspace cannot be interrogated — no `cargo` on PATH, or a
/// metadata failure. Provenance only ever *adds* discrimination, so losing it
/// degrades to the historical behaviour rather than failing the sweep.
fn workspace_cdylib_stems() -> Option<BTreeSet<String>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let packages = metadata.get("packages")?.as_array()?;
    let mut stems = BTreeSet::new();
    for package in packages {
        let Some(targets) = package.get("targets").and_then(|t| t.as_array()) else {
            continue;
        };
        for target in targets {
            let is_cdylib = target
                .get("kind")
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("cdylib")));
            if !is_cdylib {
                continue;
            }
            if let Some(name) = target.get("name").and_then(|n| n.as_str()) {
                stems.insert(name.replace('-', "_"));
            }
        }
    }
    (!stems.is_empty()).then_some(stems)
}

/// `build-test-plugins`' classification of the workspace's plugin cdylibs.
struct StagedManifest {
    /// Built and uplifted into `target/debug`, so the sweep must cover them.
    staged: BTreeSet<String>,
    /// Workspace plugins the staging step deliberately leaves alone; they
    /// never reach the profile root on the test path, so the sweep cannot see
    /// them and is not held to them.
    unstaged_by_design: BTreeSet<String>,
}

/// Read the staging manifest from the dir `build-test-plugins` writes.
///
/// Located relative to the profile dir rather than through an env var: the
/// staging dir is a fixed sibling of it, and one fewer knob is one fewer thing
/// to set inconsistently between `make test` and CI.
fn staged_plugin_manifest() -> Option<StagedManifest> {
    let path = profile_dir()
        .parent()?
        .join("test-plugins")
        .join(STAGED_MANIFEST_NAME);
    let raw = std::fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let list = |key: &str| -> BTreeSet<String> {
        json.get(key)
            .and_then(|v| v.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(StagedManifest {
        staged: list("staged"),
        unstaged_by_design: list("unstaged_by_design"),
    })
}

/// Proc-macro crates are loadable dylibs but are not storage plugins. Cargo
/// writes them under `target/<profile>/deps` with a metadata hash in the file
/// name, making `ovstorage-plugin-macros` a stable missing-manifest fixture
/// without requiring the `ovstorage` crate itself to produce a cdylib.
fn proc_macro_artifacts() -> Vec<PathBuf> {
    let prefix = if cfg!(target_os = "windows") {
        "ovstorage_plugin_macros-"
    } else {
        "libovstorage_plugin_macros-"
    };
    let suffix = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    let mut artifacts: Vec<PathBuf> = std::fs::read_dir(profile_dir().join("deps"))
        .expect("read profile deps dir")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            (path.is_file() && name.starts_with(prefix) && name.ends_with(suffix)).then_some(path)
        })
        .collect();
    artifacts.sort();
    artifacts
}

#[tokio::test]
async fn first_party_plugins_load_current_layer_abi() {
    ovstorage::init_auth_substrate(None).expect("init auth substrate");

    let require_plugins = require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS");
    let workspace_stems = workspace_cdylib_stems();
    if workspace_stems.is_none() {
        // Deliberate: strict mode is entered only from `make test` / `make
        // test-ci`, which run cargo already, so requiring `cargo metadata` to
        // be invokable from inside this test process costs nothing there. It
        // does make the strict leg depend on a nested cargo invocation, which
        // a bare `cargo test` run of the binary would not have -- that path is
        // never strict, and reverts to judging everything on disk.
        assert!(
            !require_plugins,
            "OVSTORAGE_REQUIRE_TEST_PLUGINS is set but `cargo metadata` could not be \
             read, so the sweep cannot tell this checkout's plugins from artifacts \
             left by another branch, nor assert that every one of them was covered"
        );
        eprintln!(
            "provenance unavailable (no readable `cargo metadata`): every artifact on \
             disk will be swept, including any left by another branch"
        );
    }

    let mut loaded_plugins = Vec::new();
    for (stem, path) in plugin_artifacts() {
        // The procedural-macro implementation crate matches the plugin
        // filename prefix but is a `proc-macro` target, not a cdylib. It is
        // the ONLY stem skipped before provenance: it can never appear among
        // the workspace's cdylibs, so checking it there would always fail.
        if stem == PROC_MACRO_STEM {
            continue;
        }
        // An artifact no crate in this checkout can produce is not judged
        // against this branch's ABI policy: loading it fails toward red naming
        // a crate the developer cannot find, or — if it happens to load —
        // toward green, on coverage the run did not earn.
        //
        // Skipping it is right for a developer whose `target/` carries
        // leftovers from another branch. It is NOT right in strict mode: CI
        // builds the workspace into a `target/` restored from this repo's own
        // cache, so an unrecognised plugin artifact there means a plugin left
        // the build without leaving the directory — a crate that dropped
        // `cdylib` from `crate-type`, or left the workspace — and the ABI
        // coverage it used to get would vanish behind a printed notice in a
        // passing run. Neither the sweep nor the completeness check below can
        // see that on its own: both are derived from the workspace, and the
        // workspace is what shrank.
        if let Some(known) = &workspace_stems
            && !known.contains(&stem)
        {
            let notice = format!(
                "{stem}: {} is not from this checkout. No cdylib crate in the current \
                 workspace produces this artifact. Either a branch that carried the \
                 plugin left it in target/, or a crate here stopped declaring \
                 `crate-type = [\"cdylib\"]` and silently left the ABI sweep. Note that \
                 rebuilding will NOT clear it if its stem is in \
                 OTHER_WORKSPACE_PLUGIN_STEMS (tools/ovtasks/_test_plugins.py): that \
                 set is the prune keep-set, so a retired crate still listed there keeps \
                 its stale artifact alive. Drop the stem from that set, or remove the \
                 artifact by hand.",
                path.display()
            );
            assert!(!require_plugins, "{notice}");
            eprintln!("skipping — {notice}");
            continue;
        }
        // Provenance has now vouched for the incompatible-ABI fixture, so it
        // is recorded as observed and excused only from the positive load —
        // its whole job is to be REJECTED by the loader, which the sibling
        // test drives directly. Excusing it any earlier would leave the one
        // artifact that exists to be rejected as the only one exempt from the
        // stale-artifact guard, and that sibling would then happily "reject" a
        // binary this checkout cannot produce.
        if stem == INCOMPATIBLE_ABI_STEM {
            loaded_plugins.push(stem);
            continue;
        }
        // `allow_test_plugins = true`: the sweep judges the ABI policy
        // only, so `test_only` fixtures must not confound the rejection.
        let result = unsafe { ovstorage::load_layer_plugin(&path, true) };
        let factories: Vec<LoadedLayerFactory> = result.unwrap_or_else(|e| {
            panic!(
                "{stem}: first-party plugin must load through the current \
                 Layer ABI loader; load failed: {e}"
            )
        });
        assert!(
            !factories.is_empty(),
            "{stem}: loaded but advertised no Layer kinds"
        );
        let kinds = factories
            .iter()
            .map(|factory| factory.descriptor().kind)
            .collect::<BTreeSet<_>>();
        match stem.as_str() {
            "ovstorage_plugin_core" => assert_eq!(
                kinds,
                ["alias", "copy_rename_fallback", "retry", "router"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            ),
            "ovstorage_plugin_cache" => assert_eq!(
                kinds,
                ["byte_cache", "metadata_cache"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            ),
            "ovstorage_plugin_http" => {
                assert_eq!(
                    kinds,
                    ["http", "redirect_follower"]
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                );
                // Advertising the kinds is not enough: the credential
                // declaration is what a host walks to offer an auth method,
                // and it crosses the C ABI as marshalled arrays. An in-crate
                // test on the native descriptor cannot see a marshalling gap.
                let http = factories
                    .iter()
                    .map(|factory| factory.descriptor())
                    .find(|descriptor| descriptor.kind == "http")
                    .expect("the http kind is advertised");
                assert_eq!(
                    http.credential_schema
                        .iter()
                        .map(|field| field.key.as_str())
                        .collect::<Vec<_>>(),
                    [
                        "bearer_token",
                        "username",
                        "password",
                        "signed_query",
                        "secret_headers",
                    ],
                    "the http credential schema did not survive dlopen"
                );
                assert_eq!(
                    http.credential_methods
                        .iter()
                        .map(|method| (
                            method.key.as_str(),
                            method.fields.iter().map(String::as_str).collect::<Vec<_>>()
                        ))
                        .collect::<Vec<_>>(),
                    [
                        ("bearer", vec!["bearer_token"]),
                        ("basic", vec!["username", "password"]),
                        ("signed_query", vec!["signed_query"]),
                        ("secret_headers", vec!["secret_headers"]),
                    ],
                    "the http credential methods did not survive dlopen"
                );
            }
            _ => {}
        }
        loaded_plugins.push(stem);
    }

    // Completeness, held to what `build-test-plugins` says it stages.
    //
    // Filtering alone can only ever observe LESS, and silently: a plugin that
    // stops being staged simply stops appearing, and nothing notices it left
    // the gate. So the sweep is required to have covered every staged plugin.
    //
    // The required set comes from the staging tool's own manifest rather than
    // from `cargo metadata`, because the ABI sweep reads only the profile root
    // and `cargo test` puts a cdylib in `target/debug/deps/` without uplifting
    // it there. `ovstorage-plugin-broker` and `ovstorage-plugin-services-client`
    // are built by nobody on the test path, so a workspace-derived requirement
    // demands two artifacts that cannot exist and names `make test-ci` — the
    // command that just failed — as the remedy.
    //
    // A newly added plugin stays covered by default because the manifest also
    // carries what it deliberately does NOT stage: a stem in neither list is
    // classified by nobody, and the cross-check below fails rather than
    // quietly dropping it from the requirement.
    if require_plugins {
        let known = workspace_stems.expect("checked above under require_plugins");
        let manifest = staged_plugin_manifest().unwrap_or_else(|| {
            panic!(
                "OVSTORAGE_REQUIRE_TEST_PLUGINS is set but {} is missing from the \
                 staging dir: run `make build-test-plugins` (every `make test` target \
                 depends on it)",
                STAGED_MANIFEST_NAME
            )
        });

        // The incompatible-ABI fixture is NOT exempt from either loop. It is a
        // workspace cdylib like any other, and the sibling rejection test is
        // only meaningful against an artifact this checkout can still produce.
        for stem in &known {
            if !stem.starts_with(PLUGIN_STEM_PREFIX) {
                continue;
            }
            assert!(
                manifest.staged.contains(stem) || manifest.unstaged_by_design.contains(stem),
                "the workspace declares a plugin cdylib `{stem}` that \
                 tools/ovtasks/_test_plugins.py classifies neither as staged (PLUGINS) \
                 nor as deliberately unstaged (OTHER_WORKSPACE_PLUGIN_STEMS), so nothing \
                 requires it to pass the ABI sweep. Add it to one of them."
            );
        }

        for stem in &manifest.staged {
            assert!(
                loaded_plugins.contains(stem),
                "`{stem}` is staged by build-test-plugins but the sweep never observed \
                 it, and OVSTORAGE_REQUIRE_TEST_PLUGINS is set: re-run \
                 `make build-test-plugins`, which uplifts each staged plugin into \
                 target/debug where this sweep looks."
            );
        }
    }
}

#[tokio::test]
async fn core_plugin_composes_router_over_builtin_file() {
    let Some(path) = plugin_artifacts()
        .into_iter()
        .find_map(|(stem, path)| (stem == "ovstorage_plugin_core").then_some(path))
    else {
        eprintln!("skipping core plugin composition: plugin cdylib not built");
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let factories = unsafe { ovstorage::load_layer_plugin(path, false) }.expect("load core plugin");
    let mut builder =
        ovstorage::layers::register_default_layer_factories(ovstorage::Stack::builder("routes"));
    for factory in factories {
        builder = match factory {
            LoadedLayerFactory::Backend(factory) => builder.backend_factory(factory),
            LoadedLayerFactory::Wrapper(factory) => builder.wrapper_factory(factory),
            LoadedLayerFactory::Router(factory) => builder.router_factory(factory),
        };
    }
    let build = builder
        .layer(ovstorage::LayerSpec::router(
            "routes",
            "router",
            vec!["files".into()],
        ))
        .layer(ovstorage::LayerSpec::backend("files", "file"))
        .build();
    tokio::time::timeout(std::time::Duration::from_secs(5), build)
        .await
        .expect("core plugin router build timed out")
        .expect("build router over file");
}

/// A plugin that explicitly advertises a retired ABI is rejected when loaded
/// directly, but skipped during discovery so valid neighbors remain usable.
#[tokio::test]
async fn incompatible_abi_is_rejected_directly_and_skipped_by_bulk_discovery() {
    let artifacts = plugin_artifacts();
    let find = |stem: &str| {
        artifacts
            .iter()
            .find(|(candidate, _)| candidate == stem)
            .map(|(_, path)| path.clone())
    };
    let (Some(incompatible), Some(current)) = (
        find(INCOMPATIBLE_ABI_STEM),
        find("ovstorage_plugin_test_layer"),
    ) else {
        assert!(
            !require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS"),
            "ABI test cdylibs not staged but OVSTORAGE_REQUIRE_TEST_PLUGINS is set"
        );
        eprintln!("skipping incompatible-ABI gate: test cdylibs not built");
        return;
    };

    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let error = match unsafe { ovstorage::load_layer_plugin(&incompatible, true) } {
        Ok(_) => panic!("direct loading must report the incompatible ABI"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::IncompatibleType);
    assert_eq!(
        error.message(),
        "manifest abi_version is not the supported Layer ABI"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    for artifact in [&incompatible, &current] {
        std::fs::copy(
            artifact,
            dir.path().join(artifact.file_name().expect("file name")),
        )
        .expect("stage ABI fixture");
    }
    let factories = unsafe { ovstorage::load_layer_plugins_from_dir(dir.path(), true) }
        .expect("bulk discovery must skip only the incompatible ABI fixture");
    let kinds: Vec<String> = factories.iter().map(|f| f.descriptor().kind).collect();
    assert_eq!(
        kinds,
        ["mini-v2", "mini-wrapper", "mini-auth", "mini-router"]
    );
}

/// Bulk dir discovery skips a loadable dylib that has no plugin manifest
/// symbol, while still loading a neighboring ABI-v2 plugin.
#[tokio::test]
async fn bulk_dir_scan_skips_non_plugin_dylib_and_loads_v2_neighbor() {
    let artifacts = plugin_artifacts();
    let find = |stem: &str| {
        artifacts
            .iter()
            .find(|(s, _)| s == stem)
            .map(|(_, p)| p.clone())
    };
    let Some(v2_so) = find("ovstorage_plugin_test_layer") else {
        assert!(
            !require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS"),
            "test cdylibs not staged but OVSTORAGE_REQUIRE_TEST_PLUGINS is set"
        );
        eprintln!("skipping bulk-scan gate: test cdylibs not built (run `make test-ci`)");
        return;
    };

    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let dir = tempfile::tempdir().expect("tempdir");
    let non_plugins = proc_macro_artifacts();
    let non_plugin = non_plugins
        .iter()
        .find(|path| {
            matches!(
                unsafe { ovstorage::load_layer_plugin(path, true) },
                Err(error)
                    if error.code() == ErrorCode::InvalidArgument
                        && error.message().starts_with("plugin manifest symbol is missing")
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "no loadable ovstorage-plugin-macros dylib found in profile deps; candidates: {non_plugins:?}"
            )
        });
    let fake_name = if cfg!(target_os = "windows") {
        "ovstorage_plugin_not_a_plugin.dll"
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_not_a_plugin.dylib"
    } else {
        "libovstorage_plugin_not_a_plugin.so"
    };
    std::fs::copy(non_plugin, dir.path().join(fake_name)).expect("stage non-plugin dylib");
    std::fs::copy(
        &v2_so,
        dir.path().join(v2_so.file_name().expect("file name")),
    )
    .expect("stage plugin into scan dir");

    let factories = unsafe { ovstorage::load_layer_plugins_from_dir(dir.path(), true) }
        .expect("bulk scan must skip the missing-manifest dylib, not abort");
    let kinds: Vec<String> = factories.iter().map(|f| f.descriptor().kind).collect();
    assert!(
        kinds.iter().any(|k| k == "mini-v2"),
        "v2 neighbor must load from the scanned dir, got kinds {kinds:?}"
    );
}

/// Two plugin libraries cannot claim the same kind: selecting one by directory
/// order would make the active implementation depend on filenames.
#[tokio::test]
async fn bulk_dir_scan_rejects_duplicate_kinds_across_plugins() {
    let Some((_, plugin)) = plugin_artifacts()
        .into_iter()
        .find(|(stem, _)| stem == "ovstorage_plugin_test_layer")
    else {
        assert!(
            !require_env("OVSTORAGE_REQUIRE_TEST_PLUGINS"),
            "test cdylibs not staged but OVSTORAGE_REQUIRE_TEST_PLUGINS is set"
        );
        eprintln!("skipping duplicate-kind gate: test cdylib not built");
        return;
    };

    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let dir = tempfile::tempdir().expect("tempdir");
    for suffix in ["duplicate_a", "duplicate_b"] {
        let filename = if cfg!(target_os = "windows") {
            format!("ovstorage_plugin_{suffix}.dll")
        } else if cfg!(target_os = "macos") {
            format!("libovstorage_plugin_{suffix}.dylib")
        } else {
            format!("libovstorage_plugin_{suffix}.so")
        };
        std::fs::copy(&plugin, dir.path().join(filename)).expect("stage duplicate plugin");
    }

    let error = match unsafe { ovstorage::load_layer_plugins_from_dir(dir.path(), true) } {
        Ok(_) => panic!("bulk discovery must reject duplicate advertised kinds"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        error.message(),
        "more than one plugin advertises Layer kind 'mini-v2'"
    );
}

/// Directory discovery is the shared definition of "point a host at a plugin
/// directory" (native `load_layer_plugins_from_dir`, Python `PluginRegistry`),
/// so it is pinned on names alone — no cdylib is opened here.
mod discovery {
    use std::path::{Path, PathBuf};

    use ovstorage::{ErrorCode, discover_plugin_libraries};

    /// Platform-correct plugin filename for a stem suffix.
    fn plugin_name(suffix: &str) -> String {
        if cfg!(target_os = "windows") {
            format!("ovstorage_plugin_{suffix}.dll")
        } else if cfg!(target_os = "macos") {
            format!("libovstorage_plugin_{suffix}.dylib")
        } else {
            format!("libovstorage_plugin_{suffix}.so")
        }
    }

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"not a real cdylib").expect("write candidate");
        path
    }

    /// A directory holding one plugin yields exactly that plugin.
    #[test]
    fn single_plugin_directory_yields_that_plugin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let only = touch(dir.path(), &plugin_name("solo"));
        assert_eq!(
            discover_plugin_libraries(dir.path()).expect("discover"),
            vec![only]
        );
    }

    /// The scan order must not depend on the filesystem's directory order:
    /// two hosts (or two runs on one host) otherwise register plugin kinds in
    /// different orders.
    ///
    /// The candidates are created in DESCENDING name order, which is the part
    /// that makes this able to fail. Creating them ascending would make
    /// creation order and lexicographic order the same sequence, so on any
    /// filesystem that enumerates in creation order -- tmpfs, i.e. the usual
    /// `/tmp` on Linux CI, which is where `tempdir()` lands -- `read_dir`
    /// would already return them sorted and the assertion would pass whether
    /// or not the implementation sorts anything.
    #[test]
    fn several_plugins_are_returned_in_sorted_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut expected: Vec<PathBuf> = (0..10)
            .rev()
            .map(|index| touch(dir.path(), &plugin_name(&format!("scan{index}"))))
            .collect();
        expected.sort();

        let raw: Vec<PathBuf> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|entry| entry.expect("entry").path())
            .collect();
        if raw == expected {
            // Control: on a filesystem that already enumerates in sorted
            // order this assertion cannot tell a sorting implementation from
            // an unsorted one. Say so rather than claiming a green run proved
            // the guarantee.
            eprintln!(
                "note: this filesystem enumerates {} in sorted order; the assertion below \
                 cannot discriminate on this host",
                dir.path().display()
            );
        }

        assert_eq!(
            discover_plugin_libraries(dir.path()).expect("discover"),
            expected,
            "discovery must be sorted, not filesystem order {raw:?}"
        );
    }

    /// Files that are not plugin libraries — by extension, by missing `lib`
    /// prefix, by unrelated name, or by carrying a versioned suffix — are not
    /// candidates. `dlopen`ing something that merely sits in the directory
    /// would run its initializers in this process.
    #[test]
    fn non_library_files_are_not_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plugin = touch(dir.path(), &plugin_name("real"));
        for name in [
            "README.md",
            "plugins.json",
            "libssl.so",
            "ovstorage_plugin_unprefixed.so",
            "libovstorage_plugin_versioned.so.1",
        ] {
            touch(dir.path(), name);
        }
        assert_eq!(
            discover_plugin_libraries(dir.path()).expect("discover"),
            vec![plugin]
        );
    }

    /// Nested directories are not descended: a plugin directory inside a
    /// release tree sits beside unrelated shared objects.
    #[test]
    fn nested_directories_are_not_descended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).expect("create nested");
        touch(&nested, &plugin_name("buried"));
        // A directory whose own name matches the pattern is not a candidate
        // either (e.g. a bundle).
        std::fs::create_dir(dir.path().join(plugin_name("bundle"))).expect("create bundle dir");
        assert!(
            discover_plugin_libraries(dir.path())
                .expect("discover")
                .is_empty()
        );
    }

    /// An empty directory is not an error at this level: the caller decides
    /// whether "nothing here" is fatal (the Python `PluginRegistry` rejects
    /// it; the exe-adjacent auto-scan tolerates it).
    #[test]
    fn empty_directory_yields_no_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            discover_plugin_libraries(dir.path())
                .expect("discover")
                .is_empty()
        );
    }

    /// A path that does not exist, or that is a file rather than a directory,
    /// is reported instead of being silently treated as empty.
    #[test]
    fn missing_or_non_directory_path_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-dir");
        let error = discover_plugin_libraries(&missing).expect_err("missing dir must be an error");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("is not a directory"),
            "message must name the problem, got {:?}",
            error.message()
        );

        let file = touch(dir.path(), &plugin_name("file"));
        let error = discover_plugin_libraries(&file).expect_err("file must be an error");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
}
